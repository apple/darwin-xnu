/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
 * $FreeBSD: src/sys/netinet/in_rmx.c,v 1.37.2.1 2001/05/14 08:23:49 ru Exp $
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
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>

extern int	in_inithead __P((void **head, int off));

#ifdef __APPLE__
static void in_rtqtimo(void *rock);
#endif

#define RTPRF_OURS		RTF_PROTO3	/* set on routes we manage */

/*
 * Do what we need to do when inserting a route.
 */
static struct radix_node *
in_addroute(void *v_arg, void *n_arg, struct radix_node_head *head,
	    struct radix_node *treenodes)
{
	struct rtentry *rt = (struct rtentry *)treenodes;
	struct sockaddr_in *sin = (struct sockaddr_in *)rt_key(rt);
	struct radix_node *ret;

	/*
	 * For IP, all unicast non-host routes are automatically cloning.
	 */
	if(IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
		rt->rt_flags |= RTF_MULTICAST;

	if(!(rt->rt_flags & (RTF_HOST | RTF_CLONING | RTF_MULTICAST))) {
		rt->rt_flags |= RTF_PRCLONING;
	}

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
#define satosin(sa) ((struct sockaddr_in *)sa)
			if (satosin(rt->rt_ifa->ifa_addr)->sin_addr.s_addr
			    == sin->sin_addr.s_addr)
				rt->rt_flags |= RTF_LOCAL;
#undef satosin
		}
	}

	if (!rt->rt_rmx.rmx_mtu && !(rt->rt_rmx.rmx_locks & RTV_MTU) 
	    && rt->rt_ifp)
		rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu;

	ret = rn_addroute(v_arg, n_arg, head, treenodes);
	if (ret == NULL && rt->rt_flags & RTF_HOST) {
		struct rtentry *rt2;
		/*
		 * We are trying to add a host route, but can't.
		 * Find out if it is because of an
		 * ARP entry and delete it if so.
		 */
		rt2 = rtalloc1((struct sockaddr *)sin, 0,
				RTF_CLONING | RTF_PRCLONING);
		if (rt2) {
			if (rt2->rt_flags & RTF_LLINFO &&
				rt2->rt_flags & RTF_HOST &&
				rt2->rt_gateway &&
				rt2->rt_gateway->sa_family == AF_LINK) {
				rtrequest(RTM_DELETE,
					  (struct sockaddr *)rt_key(rt2),
					  rt2->rt_gateway,
					  rt_mask(rt2), rt2->rt_flags, 0);
				ret = rn_addroute(v_arg, n_arg, head,
					treenodes);
			}
			rtfree(rt2);
		}
	}
	return ret;
}

/*
 * This code is the inverse of in_clsroute: on first reference, if we
 * were managing the route, stop doing so and set the expiration timer
 * back off again.
 */
static struct radix_node *
in_matroute(void *v_arg, struct radix_node_head *head)
{
	struct radix_node *rn = rn_match(v_arg, head);
	struct rtentry *rt = (struct rtentry *)rn;

	if(rt && rt->rt_refcnt == 0) { /* this is first reference */
		if(rt->rt_flags & RTPRF_OURS) {
			rt->rt_flags &= ~RTPRF_OURS;
			rt->rt_rmx.rmx_expire = 0;
		}
	}
	return rn;
}

static int rtq_reallyold = 60*60;
	/* one hour is ``really old'' */
SYSCTL_INT(_net_inet_ip, IPCTL_RTEXPIRE, rtexpire, CTLFLAG_RW, 
    &rtq_reallyold , 0, 
    "Default expiration time on dynamically learned routes");
				   
static int rtq_minreallyold = 10;
	/* never automatically crank down to less */
SYSCTL_INT(_net_inet_ip, IPCTL_RTMINEXPIRE, rtminexpire, CTLFLAG_RW, 
    &rtq_minreallyold , 0, 
    "Minimum time to attempt to hold onto dynamically learned routes");
				   
static int rtq_toomany = 128;
	/* 128 cached routes is ``too many'' */
SYSCTL_INT(_net_inet_ip, IPCTL_RTMAXCACHE, rtmaxcache, CTLFLAG_RW, 
    &rtq_toomany , 0, "Upper limit on dynamically learned routes");

#ifdef __APPLE__
/* XXX LD11JUL02 Special case for AOL 5.1.2 connectivity issue to AirPort BS (Radar 2969954)
 * AOL is adding a circular route ("10.0.1.1/32 10.0.1.1") when establishing its ppp tunnel
 * to the AP BaseStation by removing the default gateway and replacing it with their tunnel entry point.
 * There is no apparent reason to add this route as there is a valid 10.0.1.1/24 route to the BS.
 * That circular route was ignored on previous version of MacOS X because of a routing bug
 * corrected with the merge to FreeBSD4.4 (a route generated from an RTF_CLONING route had the RTF_WASCLONED
 * flag set but did not have a reference to the parent route) and that entry was left in the RT. This workaround is
 * made in order to provide binary compatibility with AOL. 
 * If we catch a process adding a circular route with a /32 from the routing socket, we error it out instead of
 * confusing the routing table with a wrong route to the previous default gateway
 * If for some reason a circular route is needed, turn this sysctl (net.inet.ip.check_route_selfref) to zero.
 */
int check_routeselfref = 1;
SYSCTL_INT(_net_inet_ip, OID_AUTO, check_route_selfref, CTLFLAG_RW, 
    &check_routeselfref , 0, "");
#endif

__private_extern__ int use_routegenid = 1;
SYSCTL_INT(_net_inet_ip, OID_AUTO, use_route_genid, CTLFLAG_RW, 
    &use_routegenid , 0, "");

/*
 * On last reference drop, mark the route as belong to us so that it can be
 * timed out.
 */
static void
in_clsroute(struct radix_node *rn, struct radix_node_head *head)
{
	struct rtentry *rt = (struct rtentry *)rn;

	if(!(rt->rt_flags & RTF_UP))
		return;		/* prophylactic measures */

	if((rt->rt_flags & (RTF_LLINFO | RTF_HOST)) != RTF_HOST)
		return;

	if((rt->rt_flags & (RTF_WASCLONED | RTPRF_OURS))
	   != RTF_WASCLONED)
		return;

	/*
	 * As requested by David Greenman:
	 * If rtq_reallyold is 0, just delete the route without
	 * waiting for a timeout cycle to kill it.
	 */
	if(rtq_reallyold != 0) {
		rt->rt_flags |= RTPRF_OURS;
		rt->rt_rmx.rmx_expire = time_second + rtq_reallyold;
	} else {
		rtrequest(RTM_DELETE,
			  (struct sockaddr *)rt_key(rt),
			  rt->rt_gateway, rt_mask(rt),
			  rt->rt_flags, 0);
	}
}

struct rtqk_arg {
	struct radix_node_head *rnh;
	int draining;
	int killed;
	int found;
	int updating;
	time_t nextstop;
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
	int err;

	if(rt->rt_flags & RTPRF_OURS) {
		ap->found++;

		if(ap->draining || rt->rt_rmx.rmx_expire <= time_second) {
			if(rt->rt_refcnt > 0)
				panic("rtqkill route really not free");

			err = rtrequest(RTM_DELETE,
					(struct sockaddr *)rt_key(rt),
					rt->rt_gateway, rt_mask(rt),
					rt->rt_flags, 0);
			if(err) {
				log(LOG_WARNING, "in_rtqkill: error %d\n", err);
			} else {
				ap->killed++;
			}
		} else {
			if(ap->updating
			   && (rt->rt_rmx.rmx_expire - time_second
			       > rtq_reallyold)) {
				rt->rt_rmx.rmx_expire = time_second
					+ rtq_reallyold;
			}
			ap->nextstop = lmin(ap->nextstop,
					    rt->rt_rmx.rmx_expire);
		}
	}

	return 0;
}

static void
in_rtqtimo_funnel(void *rock)
{
	boolean_t 	funnel_state;

	funnel_state = thread_funnel_set(network_flock, TRUE);
        in_rtqtimo(rock);
	(void) thread_funnel_set(network_flock, FALSE);

}
#define RTQ_TIMEOUT	60*10	/* run no less than once every ten minutes */
static int rtq_timeout = RTQ_TIMEOUT;

static void
in_rtqtimo(void *rock)
{
	struct radix_node_head *rnh = rock;
	struct rtqk_arg arg;
	struct timeval atv;
	static time_t last_adjusted_timeout = 0;
	int s;

	arg.found = arg.killed = 0;
	arg.rnh = rnh;
	arg.nextstop = time_second + rtq_timeout;
	arg.draining = arg.updating = 0;
	s = splnet();
	rnh->rnh_walktree(rnh, in_rtqkill, &arg);
	splx(s);

	/*
	 * Attempt to be somewhat dynamic about this:
	 * If there are ``too many'' routes sitting around taking up space,
	 * then crank down the timeout, and see if we can't make some more
	 * go away.  However, we make sure that we will never adjust more
	 * than once in rtq_timeout seconds, to keep from cranking down too
	 * hard.
	 */
	if((arg.found - arg.killed > rtq_toomany)
	   && (time_second - last_adjusted_timeout >= rtq_timeout)
	   && rtq_reallyold > rtq_minreallyold) {
		rtq_reallyold = 2*rtq_reallyold / 3;
		if(rtq_reallyold < rtq_minreallyold) {
			rtq_reallyold = rtq_minreallyold;
		}

		last_adjusted_timeout = time_second;
#if DIAGNOSTIC
		log(LOG_DEBUG, "in_rtqtimo: adjusted rtq_reallyold to %d\n",
		    rtq_reallyold);
#endif
		arg.found = arg.killed = 0;
		arg.updating = 1;
		s = splnet();
		rnh->rnh_walktree(rnh, in_rtqkill, &arg);
		splx(s);
	}

	atv.tv_usec = 0;
	atv.tv_sec = arg.nextstop - time_second;
	timeout(in_rtqtimo_funnel, rock, tvtohz(&atv));
}

void
in_rtqdrain(void)
{
	struct radix_node_head *rnh = rt_tables[AF_INET];
	struct rtqk_arg arg;
	int s;
	arg.found = arg.killed = 0;
	arg.rnh = rnh;
	arg.nextstop = 0;
	arg.draining = 1;
	arg.updating = 0;
	s = splnet();
	rnh->rnh_walktree(rnh, in_rtqkill, &arg);
	splx(s);
}

/*
 * Initialize our routing tree.
 */
int
in_inithead(void **head, int off)
{
	struct radix_node_head *rnh;

#ifdef __APPLE__
	if (*head)
		return 1;
#endif

	if(!rn_inithead(head, off))
		return 0;

	if(head != (void **)&rt_tables[AF_INET]) /* BOGUS! */
		return 1;	/* only do this for the real routing table */

	rnh = *head;
	rnh->rnh_addaddr = in_addroute;
	rnh->rnh_matchaddr = in_matroute;
	rnh->rnh_close = in_clsroute;
	in_rtqtimo(rnh);	/* kick off timeout first time */
	return 1;
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
	struct in_ifadown_arg *ap = xap;
	struct rtentry *rt = (struct rtentry *)rn;
	int err;

	if (rt->rt_ifa == ap->ifa &&
	    (ap->del || !(rt->rt_flags & RTF_STATIC))) {
		/*
		 * We need to disable the automatic prune that happens
		 * in this case in rtrequest() because it will blow
		 * away the pointers that rn_walktree() needs in order
		 * continue our descent.  We will end up deleting all
		 * the routes that rtrequest() would have in any case,
		 * so that behavior is not needed there.
		 */
		rt->rt_flags &= ~(RTF_CLONING | RTF_PRCLONING);
		err = rtrequest(RTM_DELETE, (struct sockaddr *)rt_key(rt),
				rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0);
		if (err) {
			log(LOG_WARNING, "in_ifadownkill: error %d\n", err);
		}
	}
	return 0;
}

int
in_ifadown(struct ifaddr *ifa, int delete)
{
	struct in_ifadown_arg arg;
	struct radix_node_head *rnh;

	if (ifa->ifa_addr->sa_family != AF_INET)
		return 1;

	arg.rnh = rnh = rt_tables[AF_INET];
	arg.ifa = ifa;
	arg.del = delete;
	rnh->rnh_walktree(rnh, in_ifadownkill, &arg);
	ifa->ifa_flags &= ~IFA_ROUTE;
	return 0;
}
