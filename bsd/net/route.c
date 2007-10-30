/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1980, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)route.c	8.2 (Berkeley) 11/15/93
 * $FreeBSD: src/sys/net/route.c,v 1.59.2.3 2001/07/29 19:18:02 ume Exp $
 */
 
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#include <kern/lock.h>
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip_mroute.h>

#include <net/if_dl.h>

#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>

#include <pexpert/pexpert.h>

#define	equal(a1, a2) (bcmp((caddr_t)(a1), (caddr_t)(a2), (a1)->sa_len) == 0)
#define	SA(p) ((struct sockaddr *)(p))

extern void kdp_set_gateway_mac (void *gatewaymac);

extern struct domain routedomain;
struct route_cb route_cb;
__private_extern__ struct rtstat rtstat  = { 0, 0, 0, 0, 0 };
struct radix_node_head *rt_tables[AF_MAX+1];

lck_mtx_t 	*rt_mtx;	/*### global routing tables mutex for now */
lck_attr_t 	*rt_mtx_attr;
lck_grp_t 	*rt_mtx_grp;
lck_grp_attr_t 	*rt_mtx_grp_attr;

lck_mtx_t 	*route_domain_mtx;	/*### global routing tables mutex for now */
int rttrash = 0;		/* routes not in table but not freed */

static unsigned int rte_debug;

/* Possible flags for rte_debug */
#define	RTD_DEBUG	0x1	/* enable or disable rtentry debug facility */
#define	RTD_TRACE	0x2	/* trace alloc, free and refcnt */
#define	RTD_NO_FREE	0x4	/* don't free (good to catch corruptions) */

static struct zone *rte_zone;			/* special zone for rtentry */
#define	RTE_ZONE_MAX		65536		/* maximum elements in zone */
#define	RTE_ZONE_NAME		"rtentry"	/* name of rtentry zone */

#define	RTD_INUSE		0xFEEDFACE	/* entry is in use */
#define	RTD_FREED		0xDEADBEEF	/* entry is freed */

#define	RTD_TRSTACK_SIZE	8		/* depth of stack trace */
#define	RTD_REFHIST_SIZE	4		/* refcnt history size */

/*
 * Debug variant of rtentry structure.
 */
struct rtentry_dbg {
	struct rtentry	rtd_entry;			/* rtentry */
	struct rtentry	rtd_entry_saved;		/* saved rtentry */
	u_int32_t	rtd_inuse;			/* in use pattern */
	u_int16_t	rtd_refhold_cnt;		/* # of rtref */
	u_int16_t	rtd_refrele_cnt;		/* # of rtunref */
	/*
	 * Thread and PC stack trace up to RTD_TRSTACK_SIZE
	 * deep during alloc and free.
	 */
	struct thread	*rtd_alloc_thread;
	void		*rtd_alloc_stk_pc[RTD_TRSTACK_SIZE];
	struct thread	*rtd_free_thread;
	void		*rtd_free_stk_pc[RTD_TRSTACK_SIZE];
	/*
	 * Circular lists of rtref and rtunref callers.
	 */
	u_int16_t	rtd_refhold_next;
	u_int16_t	rtd_refrele_next;
	struct {
		struct thread *th;
		void *pc[RTD_TRSTACK_SIZE];
	} rtd_refhold[RTD_REFHIST_SIZE];
	struct {
		struct thread *th;
		void *pc[RTD_TRSTACK_SIZE];
	} rtd_refrele[RTD_REFHIST_SIZE];
	/*
	 * Trash list linkage
	 */
	TAILQ_ENTRY(rtentry_dbg) rtd_trash_link;
};

/* List of trash route entries protected by rt_mtx */
static TAILQ_HEAD(, rtentry_dbg) rttrash_head;

static inline struct rtentry *rte_alloc_debug(void);
static inline void rte_free_debug(struct rtentry *);
static void rt_maskedcopy(struct sockaddr *,
	    struct sockaddr *, struct sockaddr *);
static void rtable_init(void **);
static inline void rtref_audit(struct rtentry_dbg *);
static inline void rtunref_audit(struct rtentry_dbg *);

__private_extern__ u_long route_generation = 0;
extern int use_routegenid;


static void
rtable_init(void **table)
{
	struct domain *dom;
	for (dom = domains; dom; dom = dom->dom_next)
		if (dom->dom_rtattach)
			dom->dom_rtattach(&table[dom->dom_family],
			    dom->dom_rtoffset);
}

void
route_init(void)
{
	int size;

	PE_parse_boot_arg("rte_debug", &rte_debug);
	if (rte_debug != 0)
		rte_debug |= RTD_DEBUG;

	rt_mtx_grp_attr = lck_grp_attr_alloc_init();

	rt_mtx_grp = lck_grp_alloc_init("route", rt_mtx_grp_attr);

	rt_mtx_attr = lck_attr_alloc_init();

	if ((rt_mtx = lck_mtx_alloc_init(rt_mtx_grp, rt_mtx_attr)) == NULL) {
		printf("route_init: can't alloc rt_mtx\n");
		return;
	}

	lck_mtx_lock(rt_mtx);
	rn_init();	/* initialize all zeroes, all ones, mask table */
	lck_mtx_unlock(rt_mtx);
	rtable_init((void **)rt_tables);
	route_domain_mtx = routedomain.dom_mtx;

	if (rte_debug & RTD_DEBUG)
		size = sizeof (struct rtentry_dbg);
	else
		size = sizeof (struct rtentry);

	rte_zone = zinit(size, RTE_ZONE_MAX * size, 0, RTE_ZONE_NAME);
	if (rte_zone == NULL)
		panic("route_init: failed allocating rte_zone");

	zone_change(rte_zone, Z_EXPAND, TRUE);

	TAILQ_INIT(&rttrash_head);
}

/*
 * Packet routing routines.
 */
void
rtalloc(struct route *ro)
{
	rtalloc_ign(ro, 0UL);
}

void
rtalloc_ign_locked(struct route *ro, u_long ignore)
{
	struct rtentry *rt;

	if ((rt = ro->ro_rt) != NULL) {
		if (rt->rt_ifp != NULL && rt->rt_flags & RTF_UP)
			return;
		/* XXX - We are probably always at splnet here already. */
		rtfree_locked(rt);
		ro->ro_rt = NULL;
	}
	ro->ro_rt = rtalloc1_locked(&ro->ro_dst, 1, ignore);
	if (ro->ro_rt)
		ro->ro_rt->generation_id = route_generation;
}
void
rtalloc_ign(struct route *ro, u_long ignore)
{
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rt_mtx);
	rtalloc_ign_locked(ro, ignore);
	lck_mtx_unlock(rt_mtx);
}

/*
 * Look up the route that matches the address given
 * Or, at least try.. Create a cloned route if needed.
 */
struct rtentry *
rtalloc1_locked(struct sockaddr *dst, int report, u_long ignflags)
{
	struct radix_node_head *rnh = rt_tables[dst->sa_family];
	struct rtentry *rt;
	struct radix_node *rn;
	struct rtentry *newrt = 0;
	struct rt_addrinfo info;
	u_long nflags;
	int  err = 0, msgtype = RTM_MISS;
	/*
	 * Look up the address in the table for that Address Family
	 */
	if (rnh && (rn = rnh->rnh_matchaddr((caddr_t)dst, rnh)) &&
	    ((rn->rn_flags & RNF_ROOT) == 0)) {
		/*
		 * If we find it and it's not the root node, then
		 * get a refernce on the rtentry associated.
		 */
		newrt = rt = (struct rtentry *)rn;
		nflags = rt->rt_flags & ~ignflags;
		if (report && (nflags & (RTF_CLONING | RTF_PRCLONING))) {
			/*
			 * We are apparently adding (report = 0 in delete).
			 * If it requires that it be cloned, do so.
			 * (This implies it wasn't a HOST route.)
			 */
			err = rtrequest_locked(RTM_RESOLVE, dst, SA(0),
					      SA(0), 0, &newrt);
			if (err) {
				/*
				 * If the cloning didn't succeed, maybe
				 * what we have will do. Return that.
				 */
				newrt = rt;
				rtref(rt);
				goto miss;
			}
			if ((rt = newrt) && (rt->rt_flags & RTF_XRESOLVE)) {
				/*
				 * If the new route specifies it be
				 * externally resolved, then go do that.
				 */
				msgtype = RTM_RESOLVE;
				goto miss;
			}
		} else
			rtref(rt);
	} else {
		/*
		 * Either we hit the root or couldn't find any match,
		 * Which basically means
		 * "caint get there frm here"
		 */
		rtstat.rts_unreach++;
	miss:	if (report) {
			/*
			 * If required, report the failure to the supervising
			 * Authorities.
			 * For a delete, this is not an error. (report == 0)
			 */
			bzero((caddr_t)&info, sizeof(info));
			info.rti_info[RTAX_DST] = dst;
			rt_missmsg(msgtype, &info, 0, err);
		}
	}
	return (newrt);
}

struct rtentry *
rtalloc1(struct sockaddr *dst, int report, u_long ignflags)
{
	struct rtentry * entry;
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rt_mtx);
	entry = rtalloc1_locked(dst, report, ignflags);
	lck_mtx_unlock(rt_mtx);
	return (entry);
}

/*
 * Remove a reference count from an rtentry.
 * If the count gets low enough, take it out of the routing table
 */
void
rtfree_locked(struct rtentry *rt)
{
	/*
	 * find the tree for that address family
	 * Note: in the case of igmp packets, there might not be an rnh
	 */
	struct radix_node_head *rnh;

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	/* See 3582620 - We hit this during the transition from funnels to locks */
	if (rt == 0) {
		printf("rtfree - rt is NULL\n");
		return;
	}
	
	rnh = rt_tables[rt_key(rt)->sa_family];

	/*
	 * decrement the reference count by one and if it reaches 0,
	 * and there is a close function defined, call the close function
	 */
	rtunref(rt);
	if (rt->rt_refcnt > 0)
		return;

	if ((rt->rt_flags & RTF_TRACKREFS) != 0)
		printf("%s rt(%p)->rt_refcnt(%d), caller=%p\n", __FUNCTION__,
			rt, rt->rt_refcnt, __builtin_return_address(0));
	
	/*
	 * On last reference give the "close method" a chance to cleanup
	 * private state.  This also permits (for IPv4 and IPv6) a chance
	 * to decide if the routing table entry should be purged immediately
	 * or at a later time.  When an immediate purge is to happen the
	 * close routine typically issues RTM_DELETE which clears the RTF_UP
	 * flag on the entry so that the code below reclaims the storage.
	 */
	if (rnh->rnh_close && rt->rt_refcnt == 0)
		rnh->rnh_close((struct radix_node *)rt, rnh);

	/*
	 * If we are no longer "up" (and ref == 0)
	 * then we can free the resources associated
	 * with the route.
	 */
	if (!(rt->rt_flags & RTF_UP)) {
		if (rt->rt_nodes->rn_flags & (RNF_ACTIVE | RNF_ROOT))
			panic ("rtfree 2");
		/*
		 * the rtentry must have been removed from the routing table
		 * so it is represented in rttrash.. remove that now.
		 */
		(void) OSDecrementAtomic((SInt32 *)&rttrash);
		if (rte_debug & RTD_DEBUG) {
			TAILQ_REMOVE(&rttrash_head, (struct rtentry_dbg *)rt,
			    rtd_trash_link);
		}

#ifdef	DIAGNOSTIC
		if (rt->rt_refcnt < 0) {
			printf("rtfree: %p not freed (neg refs) cnt=%d\n",
			    rt, rt->rt_refcnt);
			return;
		}
#endif

		/*
		 * release references on items we hold them on..
		 * e.g other routes and ifaddrs.
		 */
		if (rt->rt_parent)
			rtfree_locked(rt->rt_parent);

		if(rt->rt_ifa) {
			ifafree(rt->rt_ifa);
			rt->rt_ifa = NULL;
		}

		/*
		 * The key is separatly alloc'd so free it (see rt_setgate()).
		 * This also frees the gateway, as they are always malloc'd
		 * together.
		 */
		R_Free(rt_key(rt));

		/*
		 * and the rtentry itself of course
		 */
		rte_free(rt);
	}
}

void
rtfree(struct rtentry *rt)
{
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rt_mtx);	
	rtfree_locked(rt);
	lck_mtx_unlock(rt_mtx);
}

/*
 * Decrements the refcount but does not free the route when
 * the refcount reaches zero. Unless you have really good reason,
 * use rtfree not rtunref.
 */
void
rtunref(struct rtentry *p)
{
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (p->rt_refcnt <= 0)
		panic("rtunref: bad refcnt %d for rt=%p\n", p->rt_refcnt, p);

	if (rte_debug & RTD_DEBUG)
		rtunref_audit((struct rtentry_dbg *)p);

	p->rt_refcnt--;
}

static inline void
rtunref_audit(struct rtentry_dbg *rte)
{
	if (rte->rtd_inuse != RTD_INUSE)
		panic("rtunref: on freed rte=%p\n", rte);

	rte->rtd_refrele_cnt++;

	if (rte_debug & RTD_TRACE) {
		rte->rtd_refrele[rte->rtd_refrele_next].th = current_thread();
		bzero(rte->rtd_refrele[rte->rtd_refrele_next].pc,
		    sizeof (rte->rtd_refrele[rte->rtd_refrele_next].pc));
		(void) OSBacktrace(rte->rtd_refrele[rte->rtd_refrele_next].pc,
		    RTD_TRSTACK_SIZE);

		rte->rtd_refrele_next =
		    (rte->rtd_refrele_next + 1) % RTD_REFHIST_SIZE;
	}
}

/*
 * Add a reference count from an rtentry.
 */
void
rtref(struct rtentry *p)
{
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (p->rt_refcnt < 0)
		panic("rtref: bad refcnt %d for rt=%p\n", p->rt_refcnt, p);

	if (rte_debug & RTD_DEBUG)
		rtref_audit((struct rtentry_dbg *)p);

	p->rt_refcnt++;
	
	if ((p->rt_flags & RTF_TRACKREFS) != 0)
		printf("%s rt(%p)->rt_refcnt(%d), caller=%p\n", __FUNCTION__,
			p, p->rt_refcnt, __builtin_return_address(0));
}

static inline void
rtref_audit(struct rtentry_dbg *rte)
{
	if (rte->rtd_inuse != RTD_INUSE)
		panic("rtref_audit: on freed rte=%p\n", rte);

	rte->rtd_refhold_cnt++;

	if (rte_debug & RTD_TRACE) {
		rte->rtd_refhold[rte->rtd_refhold_next].th = current_thread();
		bzero(rte->rtd_refhold[rte->rtd_refhold_next].pc,
		    sizeof (rte->rtd_refhold[rte->rtd_refhold_next].pc));
		(void) OSBacktrace(rte->rtd_refhold[rte->rtd_refhold_next].pc,
		    RTD_TRSTACK_SIZE);

		rte->rtd_refhold_next =
		    (rte->rtd_refhold_next + 1) % RTD_REFHIST_SIZE;
	}
}

void
rtsetifa(struct rtentry *rt, struct ifaddr* ifa)
{
	if (rt == NULL)
		panic("rtsetifa");

	if (rt->rt_ifa == ifa)
		return;

	/* Release the old ifa */
	if (rt->rt_ifa)
		ifafree(rt->rt_ifa);

	/* Set rt_ifa */
	rt->rt_ifa = ifa;

	/* Take a reference to the ifa */
	if (rt->rt_ifa)
		ifaref(rt->rt_ifa);
}

void
ifafree(struct ifaddr *ifa)
{
	int oldval;

	if (ifa == NULL)
		panic("ifafree");

	oldval = OSAddAtomic(-1, (SInt32 *)&ifa->ifa_refcnt);

	if (oldval == 0) {
		if  ((ifa->ifa_debug & IFA_ATTACHED) != 0) {
			panic("ifa attached to ifp is being freed\n");
		}
		FREE(ifa, M_IFADDR);
	}
}

void
ifaref(struct ifaddr *ifa)
{
	if (ifa == NULL)
		panic("ifaref");

	if (OSAddAtomic(1, (SInt32 *)&ifa->ifa_refcnt) == 0xffffffff)
		panic("ifaref - reference count rolled over!");
}

/*
 * Force a routing table entry to the specified
 * destination to go through the given gateway.
 * Normally called as a result of a routing redirect
 * message from the network layer.
 *
 * N.B.: must be called at splnet
 *
 */
void
rtredirect(struct sockaddr *dst, struct sockaddr *gateway,
	   struct sockaddr *netmask, int flags, struct sockaddr *src,
	   struct rtentry **rtp)
{
	struct rtentry *rt;
	int error = 0;
	short *stat = 0;
	struct rt_addrinfo info;
	struct ifaddr *ifa = NULL;

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rt_mtx);

	/* verify the gateway is directly reachable */
	if ((ifa = ifa_ifwithnet(gateway)) == 0) {
		error = ENETUNREACH;
		goto out;
	}

	rt = rtalloc1_locked(dst, 0, RTF_CLONING | RTF_PRCLONING);
	/*
	 * If the redirect isn't from our current router for this dst,
	 * it's either old or wrong.  If it redirects us to ourselves,
	 * we have a routing loop, perhaps as a result of an interface
	 * going down recently.
	 */
	if (!(flags & RTF_DONE) && rt &&
	     (!equal(src, rt->rt_gateway) || !equal(rt->rt_ifa->ifa_addr,
	     ifa->ifa_addr))) {
		error = EINVAL;
	} else {
		ifafree(ifa);
		if ((ifa = ifa_ifwithaddr(gateway))) {
			ifafree(ifa);
			ifa = NULL;
			error = EHOSTUNREACH;
		}
	}
	
	if (ifa) {
		ifafree(ifa);
		ifa = NULL;
	}
	
	if (error)
		goto done;
	/*
	 * Create a new entry if we just got back a wildcard entry
	 * or the the lookup failed.  This is necessary for hosts
	 * which use routing redirects generated by smart gateways
	 * to dynamically build the routing tables.
	 */
	if ((rt == 0) || (rt_mask(rt) && rt_mask(rt)->sa_len < 2))
		goto create;
	/*
	 * Don't listen to the redirect if it's
	 * for a route to an interface.
	 */
	if (rt->rt_flags & RTF_GATEWAY) {
		if (((rt->rt_flags & RTF_HOST) == 0) && (flags & RTF_HOST)) {
			/*
			 * Changing from route to net => route to host.
			 * Create new route, rather than smashing route to net.
			 */
		create:
			flags |=  RTF_GATEWAY | RTF_DYNAMIC;
			error = rtrequest_locked((int)RTM_ADD, dst, gateway,
				    netmask, flags,
				    (struct rtentry **)0);
			stat = &rtstat.rts_dynamic;
		} else {
			/*
			 * Smash the current notion of the gateway to
			 * this destination.  Should check about netmask!!!
			 */
			rt->rt_flags |= RTF_MODIFIED;
			flags |= RTF_MODIFIED;
			stat = &rtstat.rts_newgateway;
			/*
			 * add the key and gateway (in one malloc'd chunk).
			 */
			rt_setgate(rt, rt_key(rt), gateway);
		}
	} else
		error = EHOSTUNREACH;
done:
	if (rt) {
		if (rtp && !error)
			*rtp = rt;
		else
			rtfree_locked(rt);
	}
out:
	if (error)
		rtstat.rts_badredirect++;
	else if (stat != NULL)
		(*stat)++;
	bzero((caddr_t)&info, sizeof(info));
	info.rti_info[RTAX_DST] = dst;
	info.rti_info[RTAX_GATEWAY] = gateway;
	info.rti_info[RTAX_NETMASK] = netmask;
	info.rti_info[RTAX_AUTHOR] = src;
	rt_missmsg(RTM_REDIRECT, &info, flags, error);
	lck_mtx_unlock(rt_mtx);
}

/*
* Routing table ioctl interface.
*/
int
rtioctl(int req, caddr_t data, struct proc *p)
{
#pragma unused(p)
#if INET && MROUTING
	return mrt_ioctl(req, data);
#else
	return ENXIO;
#endif
}

struct ifaddr *
ifa_ifwithroute(
	int flags,
	const struct sockaddr	*dst,
	const struct sockaddr *gateway)
{
	struct ifaddr *ifa;

	lck_mtx_lock(rt_mtx);
	ifa = ifa_ifwithroute_locked(flags, dst, gateway);
	lck_mtx_unlock(rt_mtx);

	return (ifa);
}

struct ifaddr *
ifa_ifwithroute_locked(
	int flags,
	const struct sockaddr *dst,
	const struct sockaddr *gateway)
{
	struct ifaddr *ifa = NULL;
	struct rtentry *rt = NULL;

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (!(flags & RTF_GATEWAY)) {
		/*
		 * If we are adding a route to an interface,
		 * and the interface is a pt to pt link
		 * we should search for the destination
		 * as our clue to the interface.  Otherwise
		 * we can use the local address.
		 */
		if (flags & RTF_HOST) {
			ifa = ifa_ifwithdstaddr(dst);
		}
		if (ifa == NULL)
			ifa = ifa_ifwithaddr(gateway);
	} else {
		/*
		 * If we are adding a route to a remote net
		 * or host, the gateway may still be on the
		 * other end of a pt to pt link.
		 */
		ifa = ifa_ifwithdstaddr(gateway);
	}
	if (ifa == NULL)
		ifa = ifa_ifwithnet(gateway);
	if (ifa == NULL) {
		/* Workaround to avoid gcc warning regarding const variable */
		rt = rtalloc1_locked((struct sockaddr *)(size_t)dst, 0, 0UL);
		if (rt != NULL) {
			ifa = rt->rt_ifa;
			if (ifa != NULL)
				ifaref(ifa);
			rtunref(rt);
			rt = NULL;
		}
	}
	if (ifa != NULL && ifa->ifa_addr->sa_family != dst->sa_family) {
		struct ifaddr *newifa;
		/* Callee adds reference to newifa upon success */
		newifa = ifaof_ifpforaddr(dst, ifa->ifa_ifp);
		if (newifa != NULL) {
			ifafree(ifa);
			ifa = newifa;
		}
	}
	/*
	 * If we are adding a gateway, it is quite possible that the
	 * routing table has a static entry in place for the gateway,
	 * that may not agree with info garnered from the interfaces.
	 * The routing table should carry more precedence than the
	 * interfaces in this matter.  Must be careful not to stomp
	 * on new entries from rtinit, hence (ifa->ifa_addr != gateway).
	 */
	if ((ifa == NULL ||
	    !equal(ifa->ifa_addr, (struct sockaddr *)(size_t)gateway)) &&
	    (rt = rtalloc1_locked((struct sockaddr *)(size_t)gateway,
	    0, 0UL)) != NULL) {
		if (ifa != NULL)
			ifafree(ifa);
		ifa = rt->rt_ifa;
		if (ifa != NULL)
			ifaref(ifa);
		rtunref(rt);
	}
	return (ifa);
}

#define ROUNDUP(a) (a>0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static int rt_fixdelete __P((struct radix_node *, void *));
static int rt_fixchange __P((struct radix_node *, void *));

struct rtfc_arg {
	struct rtentry *rt0;
	struct radix_node_head *rnh;
};

/*
 * Do appropriate manipulations of a routing tree given
 * all the bits of info needed
 */
int
rtrequest_locked(
	int req,
	struct sockaddr *dst,
	struct sockaddr *gateway,
	struct sockaddr *netmask,
	int flags,
	struct rtentry **ret_nrt)
{
	int error = 0;
	struct rtentry *rt;
	struct radix_node *rn;
	struct radix_node_head *rnh;
	struct ifaddr *ifa = NULL;
	struct sockaddr *ndst;
#define senderr(x) { error = x ; goto bad; }

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);
	/*
	 * Find the correct routing tree to use for this Address Family
	 */
	if ((rnh = rt_tables[dst->sa_family]) == 0)
		senderr(ESRCH);
	/*
	 * If we are adding a host route then we don't want to put
	 * a netmask in the tree
	 */
	if (flags & RTF_HOST)
		netmask = 0;
	switch (req) {
	case RTM_DELETE:
		/*
		 * Remove the item from the tree and return it.
		 * Complain if it is not there and do no more processing.
		 */
		if ((rn = rnh->rnh_deladdr(dst, netmask, rnh)) == 0)
			senderr(ESRCH);
		if (rn->rn_flags & (RNF_ACTIVE | RNF_ROOT))
			panic ("rtrequest delete");
		rt = (struct rtentry *)rn;

		/*
		 * Take an extra reference to handle the deletion of a route
		 * entry whose reference count is already 0; e.g. an expiring
		 * cloned route entry or an entry that was added to the table
		 * with 0 reference. If the caller is interested in this route,
		 * we will return it with the reference intact. Otherwise we
		 * will decrement the reference via rtfree_locked() and then
		 * possibly deallocate it.
		 */
		rtref(rt);
		rt->rt_flags &= ~RTF_UP;

		/*
		 * Now search what's left of the subtree for any cloned
		 * routes which might have been formed from this node.
		 */
		if ((rt->rt_flags & (RTF_CLONING | RTF_PRCLONING)) &&
		    rt_mask(rt)) {
			rnh->rnh_walktree_from(rnh, dst, rt_mask(rt),
					       rt_fixdelete, rt);
		}

		/*
		 * Remove any external references we may have.
		 * This might result in another rtentry being freed if
		 * we held its last reference.
		 */
		if (rt->rt_gwroute) {
			rt = rt->rt_gwroute;
			rtfree_locked(rt);
			(rt = (struct rtentry *)rn)->rt_gwroute = 0;
		}

		/*
		 * give the protocol a chance to keep things in sync.
		 */
		if ((ifa = rt->rt_ifa) && ifa->ifa_rtrequest)
			ifa->ifa_rtrequest(RTM_DELETE, rt, SA(0));
		ifa = NULL;

		/*
		 * one more rtentry floating around that is not
		 * linked to the routing table.
		 */
		(void) OSIncrementAtomic((SInt32 *)&rttrash);
		if (rte_debug & RTD_DEBUG) {
			TAILQ_INSERT_TAIL(&rttrash_head,
			    (struct rtentry_dbg *)rt, rtd_trash_link);
		}

		/*
		 * If the caller wants it, then it can have it,
		 * but it's up to it to free the rtentry as we won't be
		 * doing it.
		 */
		if (ret_nrt != NULL) {
			/* Return the route to caller with reference intact */
			*ret_nrt = rt;
		} else {
			/* Dereference or deallocate the route */
			rtfree_locked(rt);
		}
		break;

	case RTM_RESOLVE:
		if (ret_nrt == 0 || (rt = *ret_nrt) == 0)
			senderr(EINVAL);
		ifa = rt->rt_ifa;
		ifaref(ifa);
		flags = rt->rt_flags &
		    ~(RTF_CLONING | RTF_PRCLONING | RTF_STATIC);
		flags |= RTF_WASCLONED;
		gateway = rt->rt_gateway;
		if ((netmask = rt->rt_genmask) == 0)
			flags |= RTF_HOST;
		goto makeroute;

	case RTM_ADD:
		if ((flags & RTF_GATEWAY) && !gateway)
			panic("rtrequest: GATEWAY but no gateway");

		if ((ifa = ifa_ifwithroute_locked(flags, dst, gateway)) == 0)
			senderr(ENETUNREACH);

	makeroute:
		if ((rt = rte_alloc()) == NULL)
			senderr(ENOBUFS);
		Bzero(rt, sizeof(*rt));
		rt->rt_flags = RTF_UP | flags;
		/*
		 * Add the gateway. Possibly re-malloc-ing the storage for it
		 * also add the rt_gwroute if possible.
		 */
		if ((error = rt_setgate(rt, dst, gateway)) != 0) {
			rte_free(rt);
			senderr(error);
		}

		/*
		 * point to the (possibly newly malloc'd) dest address.
		 */
		ndst = rt_key(rt);

		/*
		 * make sure it contains the value we want (masked if needed).
		 */
		if (netmask) {
			rt_maskedcopy(dst, ndst, netmask);
		} else
			Bcopy(dst, ndst, dst->sa_len);

		/*
		 * Note that we now have a reference to the ifa.
		 * This moved from below so that rnh->rnh_addaddr() can
		 * examine the ifa and  ifa->ifa_ifp if it so desires.
		 */
		rtsetifa(rt, ifa);
		rt->rt_ifp = rt->rt_ifa->ifa_ifp;

		/* XXX mtu manipulation will be done in rnh_addaddr -- itojun */

		rn = rnh->rnh_addaddr((caddr_t)ndst, (caddr_t)netmask,
					rnh, rt->rt_nodes);
		if (rn == 0) {
			struct rtentry *rt2;
			/*
			 * Uh-oh, we already have one of these in the tree.
			 * We do a special hack: if the route that's already
			 * there was generated by the protocol-cloning
			 * mechanism, then we just blow it away and retry
			 * the insertion of the new one.
			 */
			rt2 = rtalloc1_locked(dst, 0,
			    RTF_CLONING | RTF_PRCLONING);
			if (rt2 && rt2->rt_parent) {
				rtrequest_locked(RTM_DELETE,
					  (struct sockaddr *)rt_key(rt2),
					  rt2->rt_gateway,
					  rt_mask(rt2), rt2->rt_flags, 0);
				rtfree_locked(rt2);
				rn = rnh->rnh_addaddr((caddr_t)ndst,
						      (caddr_t)netmask,
						      rnh, rt->rt_nodes);
			} else if (rt2) {
				/* undo the extra ref we got */
				rtfree_locked(rt2);
			}
		}

		/*
		 * If it still failed to go into the tree,
		 * then un-make it (this should be a function)
		 */
		if (rn == 0) {
			if (rt->rt_gwroute)
				rtfree_locked(rt->rt_gwroute);
			if (rt->rt_ifa) {
				ifafree(rt->rt_ifa);
			}
			R_Free(rt_key(rt));
			rte_free(rt);
			senderr(EEXIST);
		}

		rt->rt_parent = 0;

		/*
		 * If we got here from RESOLVE, then we are cloning
		 * so clone the rest, and note that we
		 * are a clone (and increment the parent's references)
		 */
		if (req == RTM_RESOLVE) {
			rt->rt_rmx = (*ret_nrt)->rt_rmx; /* copy metrics */
			if ((*ret_nrt)->rt_flags & (RTF_CLONING | RTF_PRCLONING)) {
				rt->rt_parent = (*ret_nrt);
				rtref(*ret_nrt);
			}
		}

		/*
		 * if this protocol has something to add to this then
		 * allow it to do that as well.
		 */
		if (ifa->ifa_rtrequest)
			ifa->ifa_rtrequest(req, rt, SA(ret_nrt ? *ret_nrt : 0));
		ifafree(ifa);
		ifa = 0;

		/*
		 * We repeat the same procedure from rt_setgate() here because
		 * it doesn't fire when we call it there because the node
		 * hasn't been added to the tree yet.
		 */
		if (!(rt->rt_flags & RTF_HOST) && rt_mask(rt) != 0) {
			struct rtfc_arg arg;
			arg.rnh = rnh;
			arg.rt0 = rt;
			rnh->rnh_walktree_from(rnh, rt_key(rt), rt_mask(rt),
					       rt_fixchange, &arg);
		}

		/*
		 * actually return a resultant rtentry and
		 * give the caller a single reference.
		 */
		if (ret_nrt) {
			*ret_nrt = rt;
			rtref(rt);
		}
		break;
	}
bad:
	if (ifa)
		ifafree(ifa);
	return (error);
}

int
rtrequest(
	int req,
	struct sockaddr *dst,
	struct sockaddr *gateway,
	struct sockaddr *netmask,
	int flags,
	struct rtentry **ret_nrt)
{
	int error;
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rt_mtx);
	error = rtrequest_locked(req, dst, gateway, netmask, flags, ret_nrt);
	lck_mtx_unlock(rt_mtx);
	return (error);
}
/*
 * Called from rtrequest(RTM_DELETE, ...) to fix up the route's ``family''
 * (i.e., the routes related to it by the operation of cloning).  This
 * routine is iterated over all potential former-child-routes by way of
 * rnh->rnh_walktree_from() above, and those that actually are children of
 * the late parent (passed in as VP here) are themselves deleted.
 */
static int
rt_fixdelete(struct radix_node *rn, void *vp)
{
	struct rtentry *rt = (struct rtentry *)rn;
	struct rtentry *rt0 = vp;

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (rt->rt_parent == rt0 &&
	    !(rt->rt_flags & (RTF_PINNED | RTF_CLONING | RTF_PRCLONING))) {
		return rtrequest_locked(RTM_DELETE, rt_key(rt),
				 (struct sockaddr *)0, rt_mask(rt),
				 rt->rt_flags, (struct rtentry **)0);
	}
	return 0;
}

/*
 * This routine is called from rt_setgate() to do the analogous thing for
 * adds and changes.  There is the added complication in this case of a
 * middle insert; i.e., insertion of a new network route between an older
 * network route and (cloned) host routes.  For this reason, a simple check
 * of rt->rt_parent is insufficient; each candidate route must be tested
 * against the (mask, value) of the new route (passed as before in vp)
 * to see if the new route matches it.
 *
 * XXX - it may be possible to do fixdelete() for changes and reserve this
 * routine just for adds.  I'm not sure why I thought it was necessary to do
 * changes this way.
 */
#ifdef DEBUG
static int rtfcdebug = 0;
#endif

static int
rt_fixchange(struct radix_node *rn, void *vp)
{
	struct rtentry *rt = (struct rtentry *)rn;
	struct rtfc_arg *ap = vp;
	struct rtentry *rt0 = ap->rt0;
	struct radix_node_head *rnh = ap->rnh;
	u_char *xk1, *xm1, *xk2, *xmp;
	int i, len, mlen;

#ifdef DEBUG
	if (rtfcdebug)
		printf("rt_fixchange: rt %p, rt0 %p\n", rt, rt0);
#endif

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (!rt->rt_parent ||
	    (rt->rt_flags & (RTF_PINNED | RTF_CLONING | RTF_PRCLONING))) {
#ifdef DEBUG
		if(rtfcdebug) printf("no parent or pinned\n");
#endif
		return 0;
	}

	if (rt->rt_parent == rt0) {
#ifdef DEBUG
		if(rtfcdebug) printf("parent match\n");
#endif
		return rtrequest_locked(RTM_DELETE, rt_key(rt),
				 (struct sockaddr *)0, rt_mask(rt),
				 rt->rt_flags, (struct rtentry **)0);
	}

	/*
	 * There probably is a function somewhere which does this...
	 * if not, there should be.
	 */
	len = imin(((struct sockaddr *)rt_key(rt0))->sa_len,
		   ((struct sockaddr *)rt_key(rt))->sa_len);

	xk1 = (u_char *)rt_key(rt0);
	xm1 = (u_char *)rt_mask(rt0);
	xk2 = (u_char *)rt_key(rt);

	/* avoid applying a less specific route */
	xmp = (u_char *)rt_mask(rt->rt_parent);
	mlen = ((struct sockaddr *)rt_key(rt->rt_parent))->sa_len;
	if (mlen > ((struct sockaddr *)rt_key(rt0))->sa_len) {
#if DEBUG
		if (rtfcdebug)
			printf("rt_fixchange: inserting a less "
			       "specific route\n");
#endif
		return 0;
	}
	for (i = rnh->rnh_treetop->rn_offset; i < mlen; i++) {
		if ((xmp[i] & ~(xmp[i] ^ xm1[i])) != xmp[i]) {
#if DEBUG
			if (rtfcdebug)
				printf("rt_fixchange: inserting a less "
				       "specific route\n");
#endif
			return 0;
		}
	}

	for (i = rnh->rnh_treetop->rn_offset; i < len; i++) {
		if ((xk2[i] & xm1[i]) != xk1[i]) {
#ifdef DEBUG
			if(rtfcdebug) printf("no match\n");
#endif
			return 0;
		}
	}

	/*
	 * OK, this node is a clone, and matches the node currently being
	 * changed/added under the node's mask.  So, get rid of it.
	 */
#ifdef DEBUG
	if(rtfcdebug) printf("deleting\n");
#endif
	return rtrequest_locked(RTM_DELETE, rt_key(rt), (struct sockaddr *)0,
			 rt_mask(rt), rt->rt_flags, (struct rtentry **)0);
}

int
rt_setgate(struct rtentry *rt0, struct sockaddr *dst, struct sockaddr *gate)
{
	caddr_t new, old;
	int dlen = ROUNDUP(dst->sa_len), glen = ROUNDUP(gate->sa_len);
	struct rtentry *rt = rt0;
	struct radix_node_head *rnh = rt_tables[dst->sa_family];
	/*
	 * A host route with the destination equal to the gateway
	 * will interfere with keeping LLINFO in the routing
	 * table, so disallow it.
	 */
	
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (((rt0->rt_flags & (RTF_HOST|RTF_GATEWAY|RTF_LLINFO)) ==
					(RTF_HOST|RTF_GATEWAY)) &&
	    (dst->sa_len == gate->sa_len) &&
	    (bcmp(dst, gate, dst->sa_len) == 0)) {
		/*
		 * The route might already exist if this is an RTM_CHANGE
		 * or a routing redirect, so try to delete it.
		 */
		if (rt_key(rt0))
			rtrequest_locked(RTM_DELETE, (struct sockaddr *)rt_key(rt0),
			    rt0->rt_gateway, rt_mask(rt0), rt0->rt_flags, 0);
		return EADDRNOTAVAIL;
	}

	/*
	 * Both dst and gateway are stored in the same malloc'd chunk
	 * (If I ever get my hands on....)
	 * if we need to malloc a new chunk, then keep the old one around
	 * till we don't need it any more.
	 */
	if (rt->rt_gateway == 0 || glen > ROUNDUP(rt->rt_gateway->sa_len)) {
		old = (caddr_t)rt_key(rt);
		R_Malloc(new, caddr_t, dlen + glen);
		if (new == 0)
			return ENOBUFS;
		rt->rt_nodes->rn_key = new;
	} else {
		/*
		 * otherwise just overwrite the old one
		 */
		new = rt->rt_nodes->rn_key;
		old = 0;
	}

	/*
	 * copy the new gateway value into the memory chunk
	 */
	Bcopy(gate, (rt->rt_gateway = (struct sockaddr *)(new + dlen)), glen);

	/*
	 * if we are replacing the chunk (or it's new) we need to
	 * replace the dst as well
	 */
	if (old) {
		Bcopy(dst, new, dlen);
		R_Free(old);
	}

	/*
	 * If there is already a gwroute, it's now almost definitly wrong
	 * so drop it.
	 */
	if (rt->rt_gwroute) {
		rt = rt->rt_gwroute; rtfree_locked(rt);
		rt = rt0; rt->rt_gwroute = 0;
	}
	/*
	 * Cloning loop avoidance:
	 * In the presence of protocol-cloning and bad configuration,
	 * it is possible to get stuck in bottomless mutual recursion
	 * (rtrequest rt_setgate rtalloc1).  We avoid this by not allowing
	 * protocol-cloning to operate for gateways (which is probably the
	 * correct choice anyway), and avoid the resulting reference loops
	 * by disallowing any route to run through itself as a gateway.
	 * This is obviously mandatory when we get rt->rt_output().
	 */
	if (rt->rt_flags & RTF_GATEWAY) {
		rt->rt_gwroute = rtalloc1_locked(gate, 1, RTF_PRCLONING);
		if (rt->rt_gwroute == rt) {
			rtfree_locked(rt->rt_gwroute);
			rt->rt_gwroute = 0;
			return EDQUOT; /* failure */
		}
		/* Tell the kernel debugger about the new default gateway */
		if ((AF_INET == rt->rt_gateway->sa_family) && 
		    rt->rt_gwroute && rt->rt_gwroute->rt_gateway && 
		    (AF_LINK == rt->rt_gwroute->rt_gateway->sa_family)) {
		  kdp_set_gateway_mac(((struct sockaddr_dl *)rt0->rt_gwroute->rt_gateway)->sdl_data);
		}
	}

	/*
	 * This isn't going to do anything useful for host routes, so
	 * don't bother.  Also make sure we have a reasonable mask
	 * (we don't yet have one during adds).
	 */
	if (!(rt->rt_flags & RTF_HOST) && rt_mask(rt) != 0) {
		struct rtfc_arg arg;
		arg.rnh = rnh;
		arg.rt0 = rt;
		rnh->rnh_walktree_from(rnh, rt_key(rt), rt_mask(rt),
				       rt_fixchange, &arg);
	}

	return 0;
}

static void
rt_maskedcopy(struct sockaddr *src, struct sockaddr *dst,
	      struct sockaddr *netmask)
{
	u_char *cp1 = (u_char *)src;
	u_char *cp2 = (u_char *)dst;
	u_char *cp3 = (u_char *)netmask;
	u_char *cplim = cp2 + *cp3;
	u_char *cplim2 = cp2 + *cp1;

	*cp2++ = *cp1++; *cp2++ = *cp1++; /* copies sa_len & sa_family */
	cp3 += 2;
	if (cplim > cplim2)
		cplim = cplim2;
	while (cp2 < cplim)
		*cp2++ = *cp1++ & *cp3++;
	if (cp2 < cplim2)
		bzero((caddr_t)cp2, (unsigned)(cplim2 - cp2));
}

/*
 * Set up a routing table entry, normally
 * for an interface.
 */
int
rtinit(struct ifaddr *ifa, int cmd, int flags)
{
	int error;
	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rt_mtx);
	error = rtinit_locked(ifa, cmd, flags);
	lck_mtx_unlock(rt_mtx);
	return (error);
}

int
rtinit_locked(struct ifaddr *ifa, int cmd, int flags)
{
	struct rtentry *rt;
	struct sockaddr *dst;
	struct sockaddr *deldst;
	struct mbuf *m = 0;
	struct rtentry *nrt = 0;
	int error;

	dst = flags & RTF_HOST ? ifa->ifa_dstaddr : ifa->ifa_addr;
	/*
	 * If it's a delete, check that if it exists, it's on the correct
	 * interface or we might scrub a route to another ifa which would
	 * be confusing at best and possibly worse.
	 */
	if (cmd == RTM_DELETE) {
		/*
		 * It's a delete, so it should already exist..
		 * If it's a net, mask off the host bits
		 * (Assuming we have a mask)
		 */
		if ((flags & RTF_HOST) == 0 && ifa->ifa_netmask) {
			m = m_get(M_DONTWAIT, MT_SONAME);
			if (m == NULL) {
				return(ENOBUFS);
			}
			deldst = mtod(m, struct sockaddr *);
			rt_maskedcopy(dst, deldst, ifa->ifa_netmask);
			dst = deldst;
		}
		/*
		 * Get an rtentry that is in the routing tree and
		 * contains the correct info. (if this fails, can't get there).
		 * We set "report" to FALSE so that if it doesn't exist,
		 * it doesn't report an error or clone a route, etc. etc.
		 */
		rt = rtalloc1_locked(dst, 0, 0UL);
		if (rt) {
			/*
			 * Ok so we found the rtentry. it has an extra reference
			 * for us at this stage. we won't need that so
			 * lop that off now.
			 */
			rtunref(rt);
			if (rt->rt_ifa != ifa) {
				/*
				 * If the interface in the rtentry doesn't match
				 * the interface we are using, then we don't
				 * want to delete it, so return an error.
				 * This seems to be the only point of
				 * this whole RTM_DELETE clause.
				 */
				if (m)
					(void) m_free(m);
				return (flags & RTF_HOST ? EHOSTUNREACH
							: ENETUNREACH);
			}
		}
		/* XXX */
#if 0
		else {
			/*
			 * One would think that as we are deleting, and we know
			 * it doesn't exist, we could just return at this point
			 * with an "ELSE" clause, but apparently not..
			 */
			lck_mtx_unlock(rt_mtx);
			return (flags & RTF_HOST ? EHOSTUNREACH
							: ENETUNREACH);
		}
#endif
	}
	/*
	 * Do the actual request
	 */
	error = rtrequest_locked(cmd, dst, ifa->ifa_addr, ifa->ifa_netmask,
			flags | ifa->ifa_flags, &nrt);
	if (m)
		(void) m_free(m);
	/*
	 * If we are deleting, and we found an entry, then
	 * it's been removed from the tree.. now throw it away.
	 */
	if (cmd == RTM_DELETE && error == 0 && (rt = nrt)) {
		/*
		 * notify any listenning routing agents of the change
		 */
		rt_newaddrmsg(cmd, ifa, error, nrt);
		if (use_routegenid)
			route_generation++;
		rtfree_locked(rt);
	}

	/*
	 * We are adding, and we have a returned routing entry.
	 * We need to sanity check the result.
	 */
	if (cmd == RTM_ADD && error == 0 && (rt = nrt)) {
		/*
		 * If it came back with an unexpected interface, then it must
		 * have already existed or something. (XXX)
		 */
		if (rt->rt_ifa != ifa) {
			if (!(rt->rt_ifa->ifa_ifp->if_flags &
			    (IFF_POINTOPOINT|IFF_LOOPBACK)))
				printf("rtinit: wrong ifa (%p) was (%p)\n",
				    ifa, rt->rt_ifa);
			/*
			 * Ask that the protocol in question
			 * remove anything it has associated with
			 * this route and ifaddr.
			 */
			if (rt->rt_ifa->ifa_rtrequest)
			    rt->rt_ifa->ifa_rtrequest(RTM_DELETE, rt, SA(0));
			/*
			 * Set the route's ifa.
			 */
			rtsetifa(rt, ifa);
			/*
			 * And substitute in references to the ifaddr
			 * we are adding.
			 */
			rt->rt_ifp = ifa->ifa_ifp;
			rt->rt_rmx.rmx_mtu = ifa->ifa_ifp->if_mtu;	/*XXX*/
			/*
			 * Now ask the protocol to check if it needs
			 * any special processing in its new form.
			 */
			if (ifa->ifa_rtrequest)
			    ifa->ifa_rtrequest(RTM_ADD, rt, SA(0));
		}
		/*
		 * notify any listenning routing agents of the change
		 */
		rt_newaddrmsg(cmd, ifa, error, nrt);
		if (use_routegenid)
			route_generation++;
		/*
		 * We just wanted to add it; we don't actually need a
		 * reference.  This will result in a route that's added
		 * to the routing table without a reference count.  The
		 * RTM_DELETE code will do the necessary step to adjust
		 * the reference count at deletion time.
		 */
		rtunref(rt);
	}
	return (error);
}

struct rtentry *
rte_alloc(void)
{
	if (rte_debug & RTD_DEBUG)
		return (rte_alloc_debug());

	return ((struct rtentry *)zalloc(rte_zone));
}

void
rte_free(struct rtentry *p)
{
	if (rte_debug & RTD_DEBUG) {
		rte_free_debug(p);
		return;
	}

	if (p->rt_refcnt != 0)
		panic("rte_free: rte=%p refcnt=%d non-zero\n", p, p->rt_refcnt);

	zfree(rte_zone, p);
}

static inline struct rtentry *
rte_alloc_debug(void)
{
	struct rtentry_dbg *rte;

	rte = ((struct rtentry_dbg *)zalloc(rte_zone));
	if (rte != NULL) {
		bzero(rte, sizeof (*rte));
		if (rte_debug & RTD_TRACE) {
			rte->rtd_alloc_thread = current_thread();
			(void) OSBacktrace(rte->rtd_alloc_stk_pc,
			    RTD_TRSTACK_SIZE);
		}
		rte->rtd_inuse = RTD_INUSE;
	}
	return ((struct rtentry *)rte);
}

static inline void
rte_free_debug(struct rtentry *p)
{
	struct rtentry_dbg *rte = (struct rtentry_dbg *)p;

	if (p->rt_refcnt != 0)
		panic("rte_free: rte=%p refcnt=%d\n", p, p->rt_refcnt);

	if (rte->rtd_inuse == RTD_FREED)
		panic("rte_free: double free rte=%p\n", rte);
	else if (rte->rtd_inuse != RTD_INUSE)
		panic("rte_free: corrupted rte=%p\n", rte);

	bcopy((caddr_t)p, (caddr_t)&rte->rtd_entry_saved, sizeof (*p));
	bzero((caddr_t)p, sizeof (*p));

	rte->rtd_inuse = RTD_FREED;

	if (rte_debug & RTD_TRACE) {
		rte->rtd_free_thread = current_thread();
		(void) OSBacktrace(rte->rtd_free_stk_pc, RTD_TRSTACK_SIZE);
	}

	if (!(rte_debug & RTD_NO_FREE))
		zfree(rte_zone, p);
}
