/*
 * Copyright (c) 2003-2016 Apple Inc. All rights reserved.
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
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
 *     indefinitely.  See in6_rtqtimo() below for the exact mechanism.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <kern/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <sys/mcache.h>
#include <kern/locks.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>

#include <netinet/icmp6.h>

#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>

extern int      tvtohz(struct timeval *);

static int in6_rtqtimo_run;             /* in6_rtqtimo is scheduled to run */
static void in6_rtqtimo(void *);
static void in6_sched_rtqtimo(struct timeval *);

static struct radix_node *in6_addroute(void *, void *, struct radix_node_head *,
    struct radix_node *);
static struct radix_node *in6_deleteroute(void *, void *,
    struct radix_node_head *);
static struct radix_node *in6_matroute(void *, struct radix_node_head *);
static struct radix_node *in6_matroute_args(void *, struct radix_node_head *,
    rn_matchf_t *, void *);
static void in6_clsroute(struct radix_node *, struct radix_node_head *);
static int in6_rtqkill(struct radix_node *, void *);

/*
 * Accessed by in6_addroute(), in6_deleteroute() and in6_rtqkill(), during
 * which the routing lock (rnh_lock) is held and thus protects the variable.
 */
static int in6dynroutes;

/*
 * Do what we need to do when inserting a route.
 */
static struct radix_node *
in6_addroute(void *v_arg, void *n_arg, struct radix_node_head *head,
    struct radix_node *treenodes)
{
	struct rtentry *rt = (struct rtentry *)treenodes;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)rt_key(rt);
	struct radix_node *ret;
	char dbuf[MAX_IPv6_STR_LEN], gbuf[MAX_IPv6_STR_LEN];
	uint32_t flags = rt->rt_flags;
	boolean_t verbose = (rt_verbose > 1);

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	if (verbose) {
		rt_str(rt, dbuf, sizeof(dbuf), gbuf, sizeof(gbuf));
	}

	/*
	 * If this is a dynamic route (which is created via Redirect) and
	 * we already have the maximum acceptable number of such route entries,
	 * reject creating a new one.  We could initiate garbage collection to
	 * make available space right now, but the benefit would probably not
	 * be worth the cleaning overhead; we only have to endure a slightly
	 * suboptimal path even without the redirected route.
	 */
	if ((rt->rt_flags & RTF_DYNAMIC) &&
	    ip6_maxdynroutes >= 0 && in6dynroutes >= ip6_maxdynroutes) {
		return NULL;
	}

	/*
	 * For IPv6, all unicast non-host routes are automatically cloning.
	 */
	if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
		rt->rt_flags |= RTF_MULTICAST;
	}

	if (!(rt->rt_flags & (RTF_HOST | RTF_CLONING | RTF_MULTICAST))) {
		rt->rt_flags |= RTF_PRCLONING;
	}

	/*
	 * A little bit of help for both IPv6 output and input:
	 *   For local addresses, we make sure that RTF_LOCAL is set,
	 *   with the thought that this might one day be used to speed up
	 *   ip_input().
	 *
	 * We also mark routes to multicast addresses as such, because
	 * it's easy to do and might be useful (but this is much more
	 * dubious since it's so easy to inspect the address).  (This
	 * is done above.)
	 *
	 * XXX
	 * should elaborate the code.
	 */
	if (rt->rt_flags & RTF_HOST) {
		IFA_LOCK_SPIN(rt->rt_ifa);
		if (IN6_ARE_ADDR_EQUAL(&satosin6(rt->rt_ifa->ifa_addr)->
		    sin6_addr, &sin6->sin6_addr)) {
			rt->rt_flags |= RTF_LOCAL;
		}
		IFA_UNLOCK(rt->rt_ifa);
	}

	if (!rt->rt_rmx.rmx_mtu && !(rt->rt_rmx.rmx_locks & RTV_MTU) &&
	    rt->rt_ifp) {
		rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu;
	}

	ret = rn_addroute(v_arg, n_arg, head, treenodes);
	if (ret == NULL && (rt->rt_flags & RTF_HOST)) {
		struct rtentry *rt2;
		/*
		 * We are trying to add a host route, but can't.
		 * Find out if it is because of an
		 * ND6 entry and delete it if so.
		 */
		rt2 = rtalloc1_scoped_locked((struct sockaddr *)sin6, 0,
		    RTF_CLONING | RTF_PRCLONING, sin6_get_ifscope(rt_key(rt)));
		if (rt2 != NULL) {
			char dbufc[MAX_IPv6_STR_LEN];

			RT_LOCK(rt2);
			if (verbose) {
				rt_str(rt2, dbufc, sizeof(dbufc), NULL, 0);
			}

			if ((rt2->rt_flags & RTF_LLINFO) &&
			    (rt2->rt_flags & RTF_HOST) &&
			    rt2->rt_gateway != NULL &&
			    rt2->rt_gateway->sa_family == AF_LINK) {
				if (verbose) {
					log(LOG_DEBUG, "%s: unable to insert "
					    "route to %s:%s, flags=%b, due to "
					    "existing ND6 route %s->%s "
					    "flags=%b, attempting to delete\n",
					    __func__, dbuf,
					    (rt->rt_ifp != NULL) ?
					    rt->rt_ifp->if_xname : "",
					    rt->rt_flags, RTF_BITS,
					    dbufc, (rt2->rt_ifp != NULL) ?
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
	} else if (ret == NULL && (rt->rt_flags & RTF_CLONING)) {
		struct rtentry *rt2;
		/*
		 * We are trying to add a net route, but can't.
		 * The following case should be allowed, so we'll make a
		 * special check for this:
		 *	Two IPv6 addresses with the same prefix is assigned
		 *	to a single interrface.
		 *	# ifconfig if0 inet6 3ffe:0501::1 prefix 64 alias (*1)
		 *	# ifconfig if0 inet6 3ffe:0501::2 prefix 64 alias (*2)
		 *	In this case, (*1) and (*2) want to add the same
		 *	net route entry, 3ffe:0501:: -> if0.
		 *	This case should not raise an error.
		 */
		rt2 = rtalloc1_scoped_locked((struct sockaddr *)sin6, 0,
		    RTF_CLONING | RTF_PRCLONING, sin6_get_ifscope(rt_key(rt)));
		if (rt2 != NULL) {
			RT_LOCK(rt2);
			if ((rt2->rt_flags & (RTF_CLONING | RTF_HOST |
			    RTF_GATEWAY)) == RTF_CLONING &&
			    rt2->rt_gateway &&
			    rt2->rt_gateway->sa_family == AF_LINK &&
			    rt2->rt_ifp == rt->rt_ifp) {
				ret = rt2->rt_nodes;
			}
			RT_UNLOCK(rt2);
			rtfree_locked(rt2);
		}
	}

	if (ret != NULL && (rt->rt_flags & RTF_DYNAMIC)) {
		in6dynroutes++;
	}

	if (!verbose) {
		goto done;
	}

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
	return ret;
}

static struct radix_node *
in6_deleteroute(void *v_arg, void *netmask_arg, struct radix_node_head *head)
{
	struct radix_node *rn;

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);

	rn = rn_delete(v_arg, netmask_arg, head);
	if (rn != NULL) {
		struct rtentry *rt = (struct rtentry *)rn;

		RT_LOCK(rt);
		if (rt->rt_flags & RTF_DYNAMIC) {
			in6dynroutes--;
		}
		if (rt_verbose > 1) {
			char dbuf[MAX_IPv6_STR_LEN], gbuf[MAX_IPv6_STR_LEN];

			rt_str(rt, dbuf, sizeof(dbuf), gbuf, sizeof(gbuf));
			log(LOG_DEBUG, "%s: route to %s->%s->%s deleted, "
			    "flags=%b\n", __func__, dbuf, gbuf,
			    (rt->rt_ifp != NULL) ? rt->rt_ifp->if_xname : "",
			    rt->rt_flags, RTF_BITS);
		}
		RT_UNLOCK(rt);
	}
	return rn;
}

/*
 * Validate (unexpire) an expiring AF_INET6 route.
 */
struct radix_node *
in6_validate(struct radix_node *rn)
{
	struct rtentry *rt = (struct rtentry *)rn;

	RT_LOCK_ASSERT_HELD(rt);

	/* This is first reference? */
	if (rt->rt_refcnt == 0) {
		if (rt_verbose > 2) {
			char dbuf[MAX_IPv6_STR_LEN], gbuf[MAX_IPv6_STR_LEN];

			rt_str(rt, dbuf, sizeof(dbuf), gbuf, sizeof(gbuf));
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
	return rn;
}

/*
 * Similar to in6_matroute_args except without the leaf-matching parameters.
 */
static struct radix_node *
in6_matroute(void *v_arg, struct radix_node_head *head)
{
	return in6_matroute_args(v_arg, head, NULL, NULL);
}

/*
 * This code is the inverse of in6_clsroute: on first reference, if we
 * were managing the route, stop doing so and set the expiration timer
 * back off again.
 */
static struct radix_node *
in6_matroute_args(void *v_arg, struct radix_node_head *head,
    rn_matchf_t *f, void *w)
{
	struct radix_node *rn = rn_match_args(v_arg, head, f, w);

	if (rn != NULL) {
		RT_LOCK_SPIN((struct rtentry *)rn);
		in6_validate(rn);
		RT_UNLOCK((struct rtentry *)rn);
	}
	return rn;
}

SYSCTL_DECL(_net_inet6_ip6);

/* one hour is ``really old'' */
static uint32_t rtq_reallyold = 60 * 60;
SYSCTL_UINT(_net_inet6_ip6, IPV6CTL_RTEXPIRE, rtexpire,
    CTLFLAG_RW | CTLFLAG_LOCKED, &rtq_reallyold, 0, "");

/* never automatically crank down to less */
static uint32_t rtq_minreallyold = 10;
SYSCTL_UINT(_net_inet6_ip6, IPV6CTL_RTMINEXPIRE, rtminexpire,
    CTLFLAG_RW | CTLFLAG_LOCKED, &rtq_minreallyold, 0, "");

/* 128 cached routes is ``too many'' */
static uint32_t rtq_toomany = 128;
SYSCTL_UINT(_net_inet6_ip6, IPV6CTL_RTMAXCACHE, rtmaxcache,
    CTLFLAG_RW | CTLFLAG_LOCKED, &rtq_toomany, 0, "");

/*
 * On last reference drop, mark the route as belong to us so that it can be
 * timed out.
 */
static void
in6_clsroute(struct radix_node *rn, struct radix_node_head *head)
{
#pragma unused(head)
	char dbuf[MAX_IPv6_STR_LEN], gbuf[MAX_IPv6_STR_LEN];
	struct rtentry *rt = (struct rtentry *)rn;
	boolean_t verbose = (rt_verbose > 1);

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	if (!(rt->rt_flags & RTF_UP)) {
		return;         /* prophylactic measures */
	}
	if ((rt->rt_flags & (RTF_LLINFO | RTF_HOST)) != RTF_HOST) {
		return;
	}

	if (rt->rt_flags & RTPRF_OURS) {
		return;
	}

	if (!(rt->rt_flags & (RTF_WASCLONED | RTF_DYNAMIC))) {
		return;
	}

	if (verbose) {
		rt_str(rt, dbuf, sizeof(dbuf), gbuf, sizeof(gbuf));
	}

	/*
	 * Delete the route immediately if RTF_DELCLONE is set or
	 * if route caching is disabled (rtq_reallyold set to 0).
	 * Otherwise, let it expire and be deleted by in6_rtqkill().
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
		 * Safe to drop rt_lock and use rt_key, rt_gateway,
		 * since holding rnh_lock here prevents another thread
		 * from calling rt_setgate() on this route.
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
			if (!verbose) {
				rt_str(rt, dbuf, sizeof(dbuf),
				    gbuf, sizeof(gbuf));
			}
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
		in6_sched_rtqtimo(NULL);
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
 * the timeout is not expired yet.  This also applies if the route is dynamic
 * and there are sufficiently large number of such routes (more than a half of
 * maximum).  When updating, this makes sure that nothing has a timeout longer
 * than the current value of rtq_reallyold.
 */
static int
in6_rtqkill(struct radix_node *rn, void *rock)
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
		char dbuf[MAX_IPv6_STR_LEN], gbuf[MAX_IPv6_STR_LEN];

		if (verbose) {
			rt_str(rt, dbuf, sizeof(dbuf), gbuf, sizeof(gbuf));
		}

		ap->found++;
		VERIFY(rt->rt_expire == 0 || rt->rt_rmx.rmx_expire != 0);
		VERIFY(rt->rt_expire != 0 || rt->rt_rmx.rmx_expire == 0);
		if (ap->draining || rt->rt_expire <= timenow ||
		    ((rt->rt_flags & RTF_DYNAMIC) && ip6_maxdynroutes >= 0 &&
		    in6dynroutes > ip6_maxdynroutes / 2)) {
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
			RT_ADDREF_LOCKED(rt);   /* for us to free below */
			/*
			 * Delete this route since we're done with it;
			 * the route may be freed afterwards, so we
			 * can no longer refer to 'rt' upon returning
			 * from rtrequest().  Safe to drop rt_lock and
			 * use rt_key, rt_gateway, since holding rnh_lock
			 * here prevents another thread from calling
			 * rt_setgate() on this route.
			 */
			RT_UNLOCK(rt);
			err = rtrequest_locked(RTM_DELETE, rt_key(rt),
			    rt->rt_gateway, rt_mask(rt), rt->rt_flags, NULL);
			if (err != 0) {
				RT_LOCK(rt);
				if (!verbose) {
					rt_str(rt, dbuf, sizeof(dbuf),
					    gbuf, sizeof(gbuf));
				}
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

	return 0;
}

#define RTQ_TIMEOUT     60*10   /* run no less than once every ten minutes */
static int rtq_timeout = RTQ_TIMEOUT;

static void
in6_rtqtimo(void *targ)
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
	rnh = rt_tables[AF_INET6];
	VERIFY(rnh != NULL);

	/* Get the timestamp after we acquire the lock for better accuracy */
	timenow = net_uptime();
	if (verbose) {
		log(LOG_DEBUG, "%s: initial nextstop is T+%u seconds\n",
		    __func__, rtq_timeout);
	}
	bzero(&arg, sizeof(arg));
	arg.rnh = rnh;
	arg.nextstop = timenow + rtq_timeout;
	rnh->rnh_walktree(rnh, in6_rtqkill, &arg);
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
		if (rtq_reallyold < rtq_minreallyold) {
			rtq_reallyold = rtq_minreallyold;
		}

		last_adjusted_timeout = timenow;
		if (verbose) {
			log(LOG_DEBUG, "%s: adjusted rtq_reallyold to %d "
			    "seconds\n", __func__, rtq_reallyold);
		}
		arg.found = arg.killed = 0;
		arg.updating = 1;
		rnh->rnh_walktree(rnh, in6_rtqkill, &arg);
	}

	atv.tv_usec = 0;
	atv.tv_sec = arg.nextstop - timenow;
	/* re-arm the timer only if there's work to do */
	in6_rtqtimo_run = 0;
	if (ours > 0) {
		in6_sched_rtqtimo(&atv);
	} else if (verbose) {
		log(LOG_DEBUG, "%s: not rescheduling timer\n", __func__);
	}
	lck_mtx_unlock(rnh_lock);
}

static void
in6_sched_rtqtimo(struct timeval *atv)
{
	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);

	if (!in6_rtqtimo_run) {
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
		in6_rtqtimo_run = 1;
		timeout(in6_rtqtimo, NULL, tvtohz(atv));
	}
}

void
in6_rtqdrain(void)
{
	struct radix_node_head *rnh;
	struct rtqk_arg arg;

	if (rt_verbose > 1) {
		log(LOG_DEBUG, "%s: draining routes\n", __func__);
	}

	lck_mtx_lock(rnh_lock);
	rnh = rt_tables[AF_INET6];
	VERIFY(rnh != NULL);
	bzero(&arg, sizeof(arg));
	arg.rnh = rnh;
	arg.draining = 1;
	rnh->rnh_walktree(rnh, in6_rtqkill, &arg);
	lck_mtx_unlock(rnh_lock);
}

/*
 * Initialize our routing tree.
 */
int
in6_inithead(void **head, int off)
{
	struct radix_node_head *rnh;

	/* If called from route_init(), make sure it is exactly once */
	VERIFY(head != (void **)&rt_tables[AF_INET6] || *head == NULL);

	if (!rn_inithead(head, off)) {
		return 0;
	}

	/*
	 * We can get here from nfs_subs.c as well, in which case this
	 * won't be for the real routing table and thus we're done;
	 * this also takes care of the case when we're called more than
	 * once from anywhere but route_init().
	 */
	if (head != (void **)&rt_tables[AF_INET6]) {
		return 1;     /* only do this for the real routing table */
	}
	rnh = *head;
	rnh->rnh_addaddr = in6_addroute;
	rnh->rnh_deladdr = in6_deleteroute;
	rnh->rnh_matchaddr = in6_matroute;
	rnh->rnh_matchaddr_args = in6_matroute_args;
	rnh->rnh_close = in6_clsroute;
	return 1;
}
