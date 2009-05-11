/*
 * Copyright (c) 2003-2008 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/in6_rmx.c,v 1.1.2.2 2001/07/03 11:01:52 ume Exp $	*/
/*	$KAME: in6_rmx.c,v 1.10 2001/05/24 05:44:58 itojun Exp $	*/

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
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <kern/lock.h>

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

extern int	in6_inithead(void **head, int off);
static void	in6_rtqtimo(void *rock);
static void in6_mtutimo(void *rock);
extern int tvtohz(struct timeval *);

static struct radix_node *in6_matroute_args(void *, struct radix_node_head *,
    rn_matchf_t *, void *);

#define RTPRF_OURS		RTF_PROTO3	/* set on routes we manage */

/*
 * Do what we need to do when inserting a route.
 */
static struct radix_node *
in6_addroute(void *v_arg, void *n_arg, struct radix_node_head *head,
	    struct radix_node *treenodes)
{
	struct rtentry *rt = (struct rtentry *)treenodes;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)rt_key(rt);
	struct radix_node *ret;

	/*
	 * For IPv6, all unicast non-host routes are automatically cloning.
	 */
	if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
		rt->rt_flags |= RTF_MULTICAST;

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
		if (IN6_ARE_ADDR_EQUAL(&satosin6(rt->rt_ifa->ifa_addr)
					->sin6_addr,
				       &sin6->sin6_addr)) {
			rt->rt_flags |= RTF_LOCAL;
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
		rt2 = rtalloc1_locked((struct sockaddr *)sin6, 0,
				RTF_CLONING | RTF_PRCLONING);
		if (rt2) {
			if (rt2->rt_flags & RTF_LLINFO &&
				rt2->rt_flags & RTF_HOST &&
				rt2->rt_gateway &&
				rt2->rt_gateway->sa_family == AF_LINK) {
				rtrequest_locked(RTM_DELETE,
					  (struct sockaddr *)rt_key(rt2),
					  rt2->rt_gateway,
					  rt_mask(rt2), rt2->rt_flags, 0);
				ret = rn_addroute(v_arg, n_arg, head,
					treenodes);
			}
			rtfree_locked(rt2);
		}
	} else if (ret == NULL && rt->rt_flags & RTF_CLONING) {
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
		rt2 = rtalloc1_locked((struct sockaddr *)sin6, 0,
				RTF_CLONING | RTF_PRCLONING);
		if (rt2) {
			if ((rt2->rt_flags & (RTF_CLONING|RTF_HOST|RTF_GATEWAY))
					== RTF_CLONING
			 && rt2->rt_gateway
			 && rt2->rt_gateway->sa_family == AF_LINK
			 && rt2->rt_ifp == rt->rt_ifp) {
				ret = rt2->rt_nodes;
			}
			rtfree_locked(rt2);
		}
	}
	return ret;
}

/*
 * Similar to in6_matroute_args except without the leaf-matching parameters.
 */
static struct radix_node *
in6_matroute(void *v_arg, struct radix_node_head *head)
{
	return (in6_matroute_args(v_arg, head, NULL, NULL));
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
	struct rtentry *rt = (struct rtentry *)rn;

	if (rt && rt->rt_refcnt == 0) { /* this is first reference */
		if (rt->rt_flags & RTPRF_OURS) {
			rt->rt_flags &= ~RTPRF_OURS;
			rt->rt_rmx.rmx_expire = 0;
		}
	}
	return (rn);
}

SYSCTL_DECL(_net_inet6_ip6);

static int rtq_reallyold = 60*60;
	/* one hour is ``really old'' */
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_RTEXPIRE, rtexpire,
	CTLFLAG_RW, &rtq_reallyold , 0, "");
				
static int rtq_minreallyold = 10;
	/* never automatically crank down to less */
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_RTMINEXPIRE, rtminexpire,
	CTLFLAG_RW, &rtq_minreallyold , 0, "");
				
static int rtq_toomany = 128;
	/* 128 cached routes is ``too many'' */
SYSCTL_INT(_net_inet6_ip6, IPV6CTL_RTMAXCACHE, rtmaxcache,
	CTLFLAG_RW, &rtq_toomany , 0, "");
				

/*
 * On last reference drop, mark the route as belong to us so that it can be
 * timed out.
 */
static void
in6_clsroute(struct radix_node *rn, __unused struct radix_node_head *head)
{
	struct rtentry *rt = (struct rtentry *)rn;

	if (!(rt->rt_flags & RTF_UP))
		return;		/* prophylactic measures */

	if ((rt->rt_flags & (RTF_LLINFO | RTF_HOST)) != RTF_HOST)
		return;

	if ((rt->rt_flags & (RTF_WASCLONED | RTPRF_OURS)) != RTF_WASCLONED)
		return;

	/*
	 * Delete the route immediately if RTF_DELCLONE is set or
	 * if route caching is disabled (rtq_reallyold set to 0).
	 * Otherwise, let it expire and be deleted by in6_rtqkill().
	 */
	if ((rt->rt_flags & RTF_DELCLONE) || rtq_reallyold == 0) {
		/*
		 * Delete the route from the radix tree but since we are
		 * called when the route's reference count is 0, don't
		 * deallocate it until we return from this routine by
		 * telling rtrequest that we're interested in it.
		 */
		if (rtrequest_locked(RTM_DELETE, (struct sockaddr *)rt_key(rt),
		    rt->rt_gateway, rt_mask(rt), rt->rt_flags, &rt) == 0) {
			/* Now let the caller free it */
			rtunref(rt);
		}
	} else {
		struct timeval timenow;

		getmicrotime(&timenow);
		rt->rt_flags |= RTPRF_OURS;
		rt->rt_rmx.rmx_expire = timenow.tv_sec + rtq_reallyold;
	}
}

struct rtqk_arg {
	struct radix_node_head *rnh;
	int mode;
	int updating;
	int draining;
	int killed;
	int found;
	time_t nextstop;
};

/*
 * Get rid of old routes.  When draining, this deletes everything, even when
 * the timeout is not expired yet.  When updating, this makes sure that
 * nothing has a timeout longer than the current value of rtq_reallyold.
 */
static int
in6_rtqkill(struct radix_node *rn, void *rock)
{
	struct rtqk_arg *ap = rock;
	struct rtentry *rt = (struct rtentry *)rn;
	int err;
	struct timeval timenow;

	getmicrotime(&timenow);
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (rt->rt_flags & RTPRF_OURS) {
		ap->found++;

		if (ap->draining || rt->rt_rmx.rmx_expire <= timenow.tv_sec) {
			if (rt->rt_refcnt > 0)
				panic("rtqkill route really not free");

			err = rtrequest_locked(RTM_DELETE,
					(struct sockaddr *)rt_key(rt),
					rt->rt_gateway, rt_mask(rt),
					rt->rt_flags, 0);
			if (err) {
				log(LOG_WARNING, "in6_rtqkill: error %d", err);
			} else {
				ap->killed++;
			}
		} else {
			if (ap->updating
			   && (rt->rt_rmx.rmx_expire - timenow.tv_sec
			       > rtq_reallyold)) {
				rt->rt_rmx.rmx_expire = timenow.tv_sec
					+ rtq_reallyold;
			}
			ap->nextstop = lmin(ap->nextstop,
					    rt->rt_rmx.rmx_expire);
		}
	}

	return 0;
}

#define RTQ_TIMEOUT	60*10	/* run no less than once every ten minutes */
static int rtq_timeout = RTQ_TIMEOUT;

static void
in6_rtqtimo(void *rock)
{
	struct radix_node_head *rnh = rock;
	struct rtqk_arg arg;
	struct timeval atv;
	static time_t last_adjusted_timeout = 0;
	struct timeval timenow;

	lck_mtx_lock(rt_mtx);
	/* Get the timestamp after we acquire the lock for better accuracy */
	getmicrotime(&timenow);

	arg.found = arg.killed = 0;
	arg.rnh = rnh;
	arg.nextstop = timenow.tv_sec + rtq_timeout;
	arg.draining = arg.updating = 0;
	rnh->rnh_walktree(rnh, in6_rtqkill, &arg);

	/*
	 * Attempt to be somewhat dynamic about this:
	 * If there are ``too many'' routes sitting around taking up space,
	 * then crank down the timeout, and see if we can't make some more
	 * go away.  However, we make sure that we will never adjust more
	 * than once in rtq_timeout seconds, to keep from cranking down too
	 * hard.
	 */
	if ((arg.found - arg.killed > rtq_toomany)
	   && (timenow.tv_sec - last_adjusted_timeout >= rtq_timeout)
	   && rtq_reallyold > rtq_minreallyold) {
		rtq_reallyold = 2*rtq_reallyold / 3;
		if (rtq_reallyold < rtq_minreallyold) {
			rtq_reallyold = rtq_minreallyold;
		}

		last_adjusted_timeout = timenow.tv_sec;
#if DIAGNOSTIC
		log(LOG_DEBUG, "in6_rtqtimo: adjusted rtq_reallyold to %d",
		    rtq_reallyold);
#endif
		arg.found = arg.killed = 0;
		arg.updating = 1;
		rnh->rnh_walktree(rnh, in6_rtqkill, &arg);
	}

	atv.tv_usec = 0;
	atv.tv_sec = arg.nextstop - timenow.tv_sec;
	lck_mtx_unlock(rt_mtx);
	timeout(in6_rtqtimo, rock, tvtohz(&atv));
}

/*
 * Age old PMTUs.
 */
struct mtuex_arg {
	struct radix_node_head *rnh;
	time_t nextstop;
};

static int
in6_mtuexpire(struct radix_node *rn, void *rock)
{
	struct rtentry *rt = (struct rtentry *)rn;
	struct mtuex_arg *ap = rock;
	struct timeval timenow;

	getmicrotime(&timenow);

	/* sanity */
	if (!rt)
		panic("rt == NULL in in6_mtuexpire");

	if (rt->rt_rmx.rmx_expire && !(rt->rt_flags & RTF_PROBEMTU)) {
		if (rt->rt_rmx.rmx_expire <= timenow.tv_sec) {
			rt->rt_flags |= RTF_PROBEMTU;
		} else {
			ap->nextstop = lmin(ap->nextstop,
					rt->rt_rmx.rmx_expire);
		}
	}

	return 0;
}

#define	MTUTIMO_DEFAULT	(60*1)

static void
in6_mtutimo(void *rock)
{
	struct radix_node_head *rnh = rock;
	struct mtuex_arg arg;
	struct timeval atv;
	struct timeval timenow;

	getmicrotime(&timenow);

	arg.rnh = rnh;
	arg.nextstop = timenow.tv_sec + MTUTIMO_DEFAULT;
	lck_mtx_lock(rt_mtx);
	rnh->rnh_walktree(rnh, in6_mtuexpire, &arg);

	atv.tv_usec = 0;
	atv.tv_sec = arg.nextstop;
	if (atv.tv_sec < timenow.tv_sec) {
#if DIAGNOSTIC
		log(LOG_DEBUG, "IPv6: invalid mtu expiration time on routing table\n");
#endif
		arg.nextstop = timenow.tv_sec + 30;	/*last resort*/
	}
	atv.tv_sec -= timenow.tv_sec;
	lck_mtx_unlock(rt_mtx);
	timeout(in6_mtutimo, rock, tvtohz(&atv));
}

#if 0
void
in6_rtqdrain()
{
	struct radix_node_head *rnh = rt_tables[AF_INET6];
	struct rtqk_arg arg;
	int s;
	arg.found = arg.killed = 0;
	arg.rnh = rnh;
	arg.nextstop = 0;
	arg.draining = 1;
	arg.updating = 0;
	s = splnet();
	rnh->rnh_walktree(rnh, in6_rtqkill, &arg);
	splx(s);
}
#endif

/*
 * Initialize our routing tree.
 */
int
in6_inithead(void **head, int off)
{
	struct radix_node_head *rnh;

	if (!rn_inithead(head, off))
		return 0;

	if (head != (void **)&rt_tables[AF_INET6]) /* BOGUS! */
		return 1;	/* only do this for the real routing table */

	rnh = *head;
	rnh->rnh_addaddr = in6_addroute;
	rnh->rnh_matchaddr = in6_matroute;
	rnh->rnh_matchaddr_args = in6_matroute_args;
	rnh->rnh_close = in6_clsroute;
	in6_rtqtimo(rnh);	/* kick off timeout first time */
	in6_mtutimo(rnh);	/* kick off timeout first time */
	return 1;
}
