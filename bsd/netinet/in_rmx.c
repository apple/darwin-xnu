/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * Copyright 1994, 1995 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * This code does two things necessary for the enhanced TCP metrics to
 * function in a useful manner:
 *  1) It marks all non-host routes as `cloning', thus ensuring that
 *     every actual reference to such a route actually gets turned
 *     into a reference to a host route to the specific destination
 *     requested.
 *  2) When such routes lose all their references, it arranges for them
 *     to be deleted in some random collection of circumstances, so that
 *     a large quantity of stale routing data is not kept in kernel memory
 *     indefinitely.  See in_rtqtimo() below for the exact mechanism.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/syslog.h>
#include <sys/mcache.h>
#include <kern/locks.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_arp.h>

extern int tvtohz(struct timeval *);

static int in_rtqtimo_run;		/* in_rtqtimo is scheduled to run */
static void in_rtqtimo(void *);
static void in_sched_rtqtimo(struct timeval *);

static struct radix_node *in_addroute(void *, void *, struct radix_node_head *,
    struct radix_node *);
static struct radix_node *in_deleteroute(void *, void *,
    struct radix_node_head *);
static struct radix_node *in_matroute(void *, struct radix_node_head *);
static struct radix_node *in_matroute_args(void *, struct radix_node_head *,
    rn_matchf_t *f, void *);
static void in_clsroute(struct radix_node *, struct radix_node_head *);
static int in_rtqkill(struct radix_node *, void *);

static int in_ifadownkill(struct radix_node *, void *);

/*
 * Do what we need to do when inserting a route.
 */
static struct radix_node *
in_addroute(void *v_arg, void *n_arg, struct radix_node_head *head,
    struct radix_node *treenodes)
{
	struct rtentry *rt = (struct rtentry *)treenodes;
	struct sockaddr_in *sin = (struct sockaddr_in *)(void *)rt_key(rt);
	struct radix_node *ret;
	char dbuf[MAX_IPv4_STR_LEN], gbuf[MAX_IPv4_STR_LEN];
	uint32_t flags = rt->rt_flags;
	boolean_t verbose = (rt_verbose > 1);

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	if (verbose)
		rt_str(rt, dbuf, sizeof (dbuf), gbuf, sizeof (gbuf));

	/*
	 * For IP, all unicast non-host routes are automatically cloning.
	 */
	if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
		rt->rt_flags |= RTF_MULTICAST;

	if (!(rt->rt_flags & (RTF_HOST | RTF_CLONING | RTF_MULTICAST)))
		rt->rt_flags |= RTF_PRCLONING;

	/*
	 * A little bit of help for both IP output and input:
	 *   For host routes, we make sure that RTF_BROADCAST
	 *   is set for anything that looks like a broadcast address.
	 *   This way, we can avoid an expensive call to in_broadcast()
	 *   in ip_output() most of the time (because the route passed
	 *   to ip_output() is almost always a host route).
	 *
	 *   We also do the same for local addresses, with the thought
	 *   that this might one day be used to speed up ip_input().
	 *
	 * We also mark routes to multicast addresses as such, because
	 * it's easy to do and might be useful (but this is much more
	 * dubious since it's so easy to inspect the address).  (This
	 * is done above.)
	 */
	if (rt->rt_flags & RTF_HOST) {
		if (in_broadcast(sin->sin_addr, rt->rt_ifp)) {
			rt->rt_flags |= RTF_BROADCAST;
		} else {
			/* Become a regular mutex */
			RT_CONVERT_LOCK(rt);
			IFA_LOCK_SPIN(rt->rt_ifa);
			if (satosin(rt->rt_ifa->ifa_addr)->sin_addr.s_addr ==
			    sin->sin_addr.s_addr)
				rt->rt_flags |= RTF_LOCAL;
			IFA_UNLOCK(rt->rt_ifa);
		}
	}

	if (!rt->rt_rmx.rmx_mtu && !(rt->rt_rmx.rmx_locks & RTV_MTU) &&
	    rt->rt_ifp)
		rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu;

	ret = rn_addroute(v_arg, n_arg, head, treenodes);
	if (ret == NULL && (rt->rt_flags & RTF_HOST)) {
		struct rtentry *rt2;
		/*
		 * We are trying to add a host route, but can't.
		 * Find out if it is because of an
		 * ARP entry and delete it if so.
		 */
		rt2 = rtalloc1_scoped_locked(rt_key(rt), 0,
		    RTF_CLONING | RTF_PRCLONING, sin_get_ifscope(rt_key(rt)));
		if (rt2 != NULL) {
			char dbufc[MAX_IPv4_STR_LEN];

			RT_LOCK(rt2);
			if (verbose)
				rt_str(rt2, dbufc, sizeof (dbufc), NULL, 0);

			if ((rt2->rt_flags & RTF_LLINFO) &&
			    (rt2->rt_flags & RTF_HOST) &&
			    rt2->rt_gateway != NULL &&
			    rt2->rt_gateway->sa_family == AF_LINK) {
				if (verbose) {
					log(LOG_DEBUG, "%s: unable to insert "
					    "route to %s;%s, flags=%b, due to "
					    "existing ARP route %s->%s "
					    "flags=%b, attempting to delete\n",
					    __func__, dbuf,
					    (rt->rt_ifp != NULL) ?
					    rt->rt_ifp->if_xname : "",
					    rt->rt_flags, RTF_BITS, dbufc,
					    (rt2->rt_ifp != NULL) ?
					    rt2->rt_ifp->if_xname : "",
					    rt2->rt_flags, RTF_BITS);
				}
				/*
				 * Safe to drop rt_lock and use rt_key,
				 * rt_gateway, since holding rnh_lock here
				 * prevents another thread from calling
				 * rt_setgate() on this route.
				 */
				RT_UNLOCK(rt2);
				(void) rtrequest_locked(RTM_DELETE, rt_key(rt2),
				    rt2->rt_gateway, rt_mask(rt2),
				    rt2->rt_flags, NULL);
				ret = rn_addroute(v_arg, n_arg, head,
				    treenodes);
			} else {
				RT_UNLOCK(rt2);
			}
			rtfree_locked(rt2);
		}
	}

	if (!verbose)
		goto done;

	if (ret != NULL) {
		if (flags != rt->rt_flags) {
			log(LOG_DEBUG, "%s: route to %s->%s->%s inserted, "
			    "oflags=%b, flags=%b\n", __func__,
			    dbuf, gbuf, (rt->rt_ifp != NULL) ?
			    rt->rt_ifp->if_xname : "", flags, RTF_BITS,
			    rt->rt_flags, RTF_BITS);
		} else {
			log(LOG_DEBUG, "%s: route to %s->%s->%s inserted, "
			    "flags=%b\n", __func__, dbuf, gbuf,
			    (rt->rt_ifp != NULL) ? rt->rt_ifp->if_xname : "",
			    rt->rt_flags, RTF_BITS);
		}
	} else {
		log(LOG_DEBUG, "%s: unable to insert route to %s->%s->%s, "
		    "flags=%b, already exists\n", __func__, dbuf, gbuf,
		    (rt->rt_ifp != NULL) ? rt->rt_ifp->if_xname : "",
		    rt->rt_flags, RTF_BITS);
	}
done:
	return (ret);
}

static struct radix_node *
in_deleteroute(void *v_arg, void *netmask_arg, struct radix_node_head *head)
{
	struct radix_node *rn;

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);

	rn = rn_delete(v_arg, netmask_arg, head);
	if (rt_verbose > 1 && rn != NULL) {
		char dbuf[MAX_IPv4_STR_LEN], gbuf[MAX_IPv4_STR_LEN];
		struct rtentry *rt = (struct rtentry *)rn;

		RT_LOCK(rt);
		rt_str(rt, dbuf, sizeof (dbuf), gbuf, sizeof (gbuf));
		log(LOG_DEBUG, "%s: route to %s->%s->%s deleted, "
		    "flags=%b\n", __func__, dbuf, gbuf, (rt->rt_ifp != NULL) ?
		    rt->rt_ifp->if_xname : "", rt->rt_flags, RTF_BITS);
		RT_UNLOCK(rt);
	}
	return (rn);
}

/*
 * Validate (unexpire) an expiring AF_INET route.
 */
struct radix_node *
in_validate(struct radix_node *rn)
{
	struct rtentry *rt = (struct rtentry *)rn;

	RT_LOCK_ASSERT_HELD(rt);

	/* This is first reference? */
	if (rt->rt_refcnt == 0) {
		if (rt_verbose > 2) {
			char dbuf[MAX_IPv4_STR_LEN], gbuf[MAX_IPv4_STR_LEN];

			rt_str(rt, dbuf, sizeof (dbuf), gbuf, sizeof (gbuf));
			log(LOG_DEBUG, "%s: route to %s->%s->%s validated, "
			    "flags=%b\n", __func__, dbuf, gbuf,
			    (rt->rt_ifp != NULL) ? rt->rt_ifp->if_xname : "",
			    rt->rt_flags, RTF_BITS);
		}

		/*
		 * It's one of ours; unexpire it.  If the timer is already
		 * scheduled, let it run later as it won't re-arm itself
		 * if there's nothing to do.
		 */
		if (rt->rt_flags & RTPRF_OURS) {
			rt->rt_flags &= ~RTPRF_OURS;
			rt_setexpire(rt, 0);
		}
	}
	return (rn);
}

/*
 * Similar to in_matroute_args except without the leaf-matching parameters.
 */
static struct radix_node *
in_matroute(void *v_arg, struct radix_node_head *head)
{
	return (in_matroute_args(v_arg, head, NULL, NULL));
}

/*
 * This code is the inverse of in_clsroute: on first reference, if we
 * were managing the route, stop doing so and set the expiration timer
 * back off again.
 */
static struct radix_node *
in_matroute_args(void *v_arg, struct radix_node_head *head,
    rn_matchf_t *f, void *w)
{
	struct radix_node *rn = rn_match_args(v_arg, head, f, w);

	if (rn != NULL) {
		RT_LOCK_SPIN((struct rtentry *)rn);
		in_validate(rn);
		RT_UNLOCK((struct rtentry *)rn);
	}
	return (rn);
}

/* one hour is ``really old'' */
static uint32_t rtq_reallyold = 60*60;
SYSCTL_UINT(_net_inet_ip, IPCTL_RTEXPIRE, rtexpire,
	CTLFLAG_RW | CTLFLAG_LOCKED, &rtq_reallyold, 0,
	"Default expiration time on dynamically learned routes");

/* never automatically crank down to less */
static uint32_t rtq_minreallyold = 10;
SYSCTL_UINT(_net_inet_ip, IPCTL_RTMINEXPIRE, rtminexpire,
	CTLFLAG_RW | CTLFLAG_LOCKED, &rtq_minreallyold, 0,
	"Minimum time to attempt to hold onto dynamically learned routes");

/* 128 cached routes is ``too many'' */
static uint32_t rtq_toomany = 128;
SYSCTL_UINT(_net_inet_ip, IPCTL_RTMAXCACHE, rtmaxcache,
	CTLFLAG_RW | CTLFLAG_LOCKED, &rtq_toomany, 0,
	"Upper limit on dynamically learned routes");

/*
 * On last reference drop, mark the route as belong to us so that it can be
 * timed out.
 */
static void
in_clsroute(struct radix_node *rn, struct radix_node_head *head)
{
#pragma unused(head)
	char dbuf[MAX_IPv4_STR_LEN], gbuf[MAX_IPv4_STR_LEN];
	struct rtentry *rt = (struct rtentry *)rn;
	boolean_t verbose = (rt_verbose > 1);

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	if (!(rt->rt_flags & RTF_UP))
		return;         /* prophylactic measures */

	if ((rt->rt_flags & (RTF_LLINFO | RTF_HOST)) != RTF_HOST)
		return;

	if (rt->rt_flags & RTPRF_OURS)
		return;

	if (!(rt->rt_flags & (RTF_WASCLONED | RTF_DYNAMIC)))
		return;

	if (verbose)
		rt_str(rt, dbuf, sizeof (dbuf), gbuf, sizeof (gbuf));

	/*
	 * Delete the route immediately if RTF_DELCLONE is set or
	 * if route caching is disabled (rtq_reallyold set to 0).
	 * Otherwise, let it expire and be deleted by in_rtqkill().
	 */
	if ((rt->rt_flags & RTF_DELCLONE) || rtq_reallyold == 0) {
		int err;

		if (verbose) {
			log(LOG_DEBUG, "%s: deleting route to %s->%s->%s, "
			    "flags=%b\n", __func__, dbuf, gbuf,
			    (rt->rt_ifp != NULL) ? rt->rt_ifp->if_xname : "",
			    rt->rt_flags, RTF_BITS);
		}
		/*
		 * Delete the route from the radix tree but since we are
		 * called when the route's reference count is 0, don't
		 * deallocate it until we return from this routine by
		 * telling rtrequest that we're interested in it.
		 * Safe to drop rt_lock and use rt_key, rt_gateway since
		 * holding rnh_lock here prevents another thread from
		 * calling rt_setgate() on this route.
		 */
		RT_UNLOCK(rt);
		err = rtrequest_locked(RTM_DELETE, rt_key(rt),
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, &rt);
		if (err == 0) {
			/* Now let the caller free it */
			RT_LOCK(rt);
			RT_REMREF_LOCKED(rt);
		} else {
			RT_LOCK(rt);
			if (!verbose)
				rt_str(rt, dbuf, sizeof (dbuf),
				    gbuf, sizeof (gbuf));
			log(LOG_ERR, "%s: error deleting route to "
			    "%s->%s->%s, flags=%b, err=%d\n", __func__,
			    dbuf, gbuf, (rt->rt_ifp != NULL) ?
			    rt->rt_ifp->if_xname : "", rt->rt_flags,
			    RTF_BITS, err);
		}
	} else {
		uint64_t timenow;

		timenow = net_uptime();
		rt->rt_flags |= RTPRF_OURS;
		rt_setexpire(rt, timenow + rtq_reallyold);

		if (verbose) {
			log(LOG_DEBUG, "%s: route to %s->%s->%s invalidated, "
			    "flags=%b, expire=T+%u\n", __func__, dbuf, gbuf,
			    (rt->rt_ifp != NULL) ? rt->rt_ifp->if_xname : "",
			    rt->rt_flags, RTF_BITS, rt->rt_expire - timenow);
		}

		/* We have at least one entry; arm the timer if not already */
		in_sched_rtqtimo(NULL);
	}
}

struct rtqk_arg {
	struct radix_node_head *rnh;
	int updating;
	int draining;
	uint32_t killed;
	uint32_t found;
	uint64_t nextstop;
};

/*
 * Get rid of old routes.  When draining, this deletes everything, even when
 * the timeout is not expired yet.  When updating, this makes sure that
 * nothing has a timeout longer than the current value of rtq_reallyold.
 */
static int
in_rtqkill(struct radix_node *rn, void *rock)
{
	struct rtqk_arg *ap = rock;
	struct rtentry *rt = (struct rtentry *)rn;
	boolean_t verbose = (rt_verbose > 1);
	uint64_t timenow;
	int err;

	timenow = net_uptime();
	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);

	RT_LOCK(rt);
	if (rt->rt_flags & RTPRF_OURS) {
		char dbuf[MAX_IPv4_STR_LEN], gbuf[MAX_IPv4_STR_LEN];

		if (verbose)
			rt_str(rt, dbuf, sizeof (dbuf), gbuf, sizeof (gbuf));

		ap->found++;
		VERIFY(rt->rt_expire == 0 || rt->rt_rmx.rmx_expire != 0);
		VERIFY(rt->rt_expire != 0 || rt->rt_rmx.rmx_expire == 0);
		if (ap->draining || rt->rt_expire <= timenow) {
			if (rt->rt_refcnt > 0) {
				panic("%s: route %p marked with RTPRF_OURS "
				    "with non-zero refcnt (%u)", __func__,
				    rt, rt->rt_refcnt);
				/* NOTREACHED */
			}

			if (verbose) {
				log(LOG_DEBUG, "%s: deleting route to "
				    "%s->%s->%s, flags=%b, draining=%d\n",
				    __func__, dbuf, gbuf, (rt->rt_ifp != NULL) ?
				    rt->rt_ifp->if_xname : "", rt->rt_flags,
				    RTF_BITS, ap->draining);
			}
			RT_ADDREF_LOCKED(rt);	/* for us to free below */
			/*
			 * Delete this route since we're done with it;
			 * the route may be freed afterwards, so we
			 * can no longer refer to 'rt' upon returning
			 * from rtrequest().  Safe to drop rt_lock and
			 * use rt_key, rt_gateway since holding rnh_lock
			 * here prevents another thread from calling
			 * rt_setgate() on this route.
			 */
			RT_UNLOCK(rt);
			err = rtrequest_locked(RTM_DELETE, rt_key(rt),
			    rt->rt_gateway, rt_mask(rt), rt->rt_flags, NULL);
			if (err != 0) {
				RT_LOCK(rt);
				if (!verbose)
					rt_str(rt, dbuf, sizeof (dbuf),
					    gbuf, sizeof (gbuf));
				log(LOG_ERR, "%s: error deleting route to "
				    "%s->%s->%s, flags=%b, err=%d\n", __func__,
				    dbuf, gbuf, (rt->rt_ifp != NULL) ?
				    rt->rt_ifp->if_xname : "", rt->rt_flags,
				    RTF_BITS, err);
				RT_UNLOCK(rt);
			} else {
				ap->killed++;
			}
			rtfree_locked(rt);
		} else {
			uint64_t expire = (rt->rt_expire - timenow);

			if (ap->updating && expire > rtq_reallyold) {
				rt_setexpire(rt, timenow + rtq_reallyold);
				if (verbose) {
					log(LOG_DEBUG, "%s: route to "
					    "%s->%s->%s, flags=%b, adjusted "
					    "expire=T+%u (was T+%u)\n",
					    __func__, dbuf, gbuf,
					    (rt->rt_ifp != NULL) ?
					    rt->rt_ifp->if_xname : "",
					    rt->rt_flags, RTF_BITS,
					    (rt->rt_expire - timenow), expire);
				}
			}
			ap->nextstop = lmin(ap->nextstop, rt->rt_expire);
			RT_UNLOCK(rt);
		}
	} else {
		RT_UNLOCK(rt);
	}

	return (0);
}

#define	RTQ_TIMEOUT	60*10	/* run no less than once every ten minutes */
static int rtq_timeout = RTQ_TIMEOUT;

static void
in_rtqtimo(void *targ)
{
#pragma unused(targ)
	struct radix_node_head *rnh;
	struct rtqk_arg arg;
	struct timeval atv;
	static uint64_t last_adjusted_timeout = 0;
	boolean_t verbose = (rt_verbose > 1);
	uint64_t timenow;
	uint32_t ours;

	lck_mtx_lock(rnh_lock);
	rnh = rt_tables[AF_INET];
	VERIFY(rnh != NULL);

	/* Get the timestamp after we acquire the lock for better accuracy */
	timenow = net_uptime();
	if (verbose) {
		log(LOG_DEBUG, "%s: initial nextstop is T+%u seconds\n",
		    __func__, rtq_timeout);
	}
	bzero(&arg, sizeof (arg));
	arg.rnh = rnh;
	arg.nextstop = timenow + rtq_timeout;
	rnh->rnh_walktree(rnh, in_rtqkill, &arg);
	if (verbose) {
		log(LOG_DEBUG, "%s: found %u, killed %u\n", __func__,
		    arg.found, arg.killed);
	}
	/*
	 * Attempt to be somewhat dynamic about this:
	 * If there are ``too many'' routes sitting around taking up space,
	 * then crank down the timeout, and see if we can't make some more
	 * go away.  However, we make sure that we will never adjust more
	 * than once in rtq_timeout seconds, to keep from cranking down too
	 * hard.
	 */
	ours = (arg.found - arg.killed);
	if (ours > rtq_toomany &&
	    ((timenow - last_adjusted_timeout) >= (uint64_t)rtq_timeout) &&
	    rtq_reallyold > rtq_minreallyold) {
		rtq_reallyold = 2 * rtq_reallyold / 3;
		if (rtq_reallyold < rtq_minreallyold)
			rtq_reallyold = rtq_minreallyold;

		last_adjusted_timeout = timenow;
		if (verbose) {
			log(LOG_DEBUG, "%s: adjusted rtq_reallyold to %d "
			    "seconds\n", __func__, rtq_reallyold);
		}
		arg.found = arg.killed = 0;
		arg.updating = 1;
		rnh->rnh_walktree(rnh, in_rtqkill, &arg);
	}

	atv.tv_usec = 0;
	atv.tv_sec = arg.nextstop - timenow;
	/* re-arm the timer only if there's work to do */
	in_rtqtimo_run = 0;
	if (ours > 0)
		in_sched_rtqtimo(&atv);
	else if (verbose)
		log(LOG_DEBUG, "%s: not rescheduling timer\n", __func__);
	lck_mtx_unlock(rnh_lock);
}

static void
in_sched_rtqtimo(struct timeval *atv)
{
	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);

	if (!in_rtqtimo_run) {
		struct timeval tv;

		if (atv == NULL) {
			tv.tv_usec = 0;
			tv.tv_sec = MAX(rtq_timeout / 10, 1);
			atv = &tv;
		}
		if (rt_verbose > 1) {
			log(LOG_DEBUG, "%s: timer scheduled in "
			    "T+%llus.%lluu\n", __func__,
			    (uint64_t)atv->tv_sec, (uint64_t)atv->tv_usec);
		}
		in_rtqtimo_run = 1;
		timeout(in_rtqtimo, NULL, tvtohz(atv));
	}
}

void
in_rtqdrain(void)
{
	struct radix_node_head *rnh;
	struct rtqk_arg arg;

	if (rt_verbose > 1)
		log(LOG_DEBUG, "%s: draining routes\n", __func__);

	lck_mtx_lock(rnh_lock);
	rnh = rt_tables[AF_INET];
	VERIFY(rnh != NULL);
	bzero(&arg, sizeof (arg));
	arg.rnh = rnh;
	arg.draining = 1;
	rnh->rnh_walktree(rnh, in_rtqkill, &arg);
	lck_mtx_unlock(rnh_lock);
}

/*
 * Initialize our routing tree.
 */
int
in_inithead(void **head, int off)
{
	struct radix_node_head *rnh;

	/* If called from route_init(), make sure it is exactly once */
	VERIFY(head != (void **)&rt_tables[AF_INET] || *head == NULL);

	if (!rn_inithead(head, off))
		return (0);

	/*
	 * We can get here from nfs_subs.c as well, in which case this
	 * won't be for the real routing table and thus we're done;
	 * this also takes care of the case when we're called more than
	 * once from anywhere but route_init().
	 */
	if (head != (void **)&rt_tables[AF_INET])
		return (1);	/* only do this for the real routing table */

	rnh = *head;
	rnh->rnh_addaddr = in_addroute;
	rnh->rnh_deladdr = in_deleteroute;
	rnh->rnh_matchaddr = in_matroute;
	rnh->rnh_matchaddr_args = in_matroute_args;
	rnh->rnh_close = in_clsroute;
	return (1);
}

/*
 * This zaps old routes when the interface goes down or interface
 * address is deleted.  In the latter case, it deletes static routes
 * that point to this address.  If we don't do this, we may end up
 * using the old address in the future.  The ones we always want to
 * get rid of are things like ARP entries, since the user might down
 * the interface, walk over to a completely different network, and
 * plug back in.
 */
struct in_ifadown_arg {
	struct radix_node_head *rnh;
	struct ifaddr *ifa;
	int del;
};

static int
in_ifadownkill(struct radix_node *rn, void *xap)
{
	char dbuf[MAX_IPv4_STR_LEN], gbuf[MAX_IPv4_STR_LEN];
	struct in_ifadown_arg *ap = xap;
	struct rtentry *rt = (struct rtentry *)rn;
	boolean_t verbose = (rt_verbose != 0);
	int err;

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);

	RT_LOCK(rt);
	if (rt->rt_ifa == ap->ifa &&
	    (ap->del || !(rt->rt_flags & RTF_STATIC))) {
		rt_str(rt, dbuf, sizeof (dbuf), gbuf, sizeof (gbuf));
		if (verbose) {
			log(LOG_DEBUG, "%s: deleting route to %s->%s->%s, "
			    "flags=%b\n", __func__, dbuf, gbuf,
			    (rt->rt_ifp != NULL) ? rt->rt_ifp->if_xname : "",
			    rt->rt_flags, RTF_BITS);
		}
		RT_ADDREF_LOCKED(rt);	/* for us to free below */
		/*
		 * We need to disable the automatic prune that happens
		 * in this case in rtrequest() because it will blow
		 * away the pointers that rn_walktree() needs in order
		 * continue our descent.  We will end up deleting all
		 * the routes that rtrequest() would have in any case,
		 * so that behavior is not needed there.  Safe to drop
		 * rt_lock and use rt_key, rt_gateway, since holding
		 * rnh_lock here prevents another thread from calling
		 * rt_setgate() on this route.
		 */
		rt->rt_flags &= ~(RTF_CLONING | RTF_PRCLONING);
		RT_UNLOCK(rt);
		err = rtrequest_locked(RTM_DELETE, rt_key(rt),
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, NULL);
		if (err != 0) {
			RT_LOCK(rt);
			if (!verbose)
				rt_str(rt, dbuf, sizeof (dbuf),
				    gbuf, sizeof (gbuf));
			log(LOG_ERR, "%s: error deleting route to "
			    "%s->%s->%s, flags=%b, err=%d\n", __func__,
			    dbuf, gbuf, (rt->rt_ifp != NULL) ?
			    rt->rt_ifp->if_xname : "", rt->rt_flags,
			    RTF_BITS, err);
			RT_UNLOCK(rt);
		}
		rtfree_locked(rt);
	} else {
		RT_UNLOCK(rt);
	}
	return (0);
}

int
in_ifadown(struct ifaddr *ifa, int delete)
{
	struct in_ifadown_arg arg;
	struct radix_node_head *rnh;

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Holding rnh_lock here prevents the possibility of
	 * ifa from changing (e.g. in_ifinit), so it is safe
	 * to access its ifa_addr without locking.
	 */
	if (ifa->ifa_addr->sa_family != AF_INET)
		return (1);

	/* trigger route cache reevaluation */
	routegenid_inet_update();

	arg.rnh = rnh = rt_tables[AF_INET];
	arg.ifa = ifa;
	arg.del = delete;
	rnh->rnh_walktree(rnh, in_ifadownkill, &arg);
	IFA_LOCK_SPIN(ifa);
	ifa->ifa_flags &= ~IFA_ROUTE;
	IFA_UNLOCK(ifa);
	return (0);
}
