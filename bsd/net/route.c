/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#include <netinet/in_var.h>
#include <netinet/ip_mroute.h>
#include <netinet/ip_var.h>

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
static struct rtentry *rtalloc1_common_locked(struct sockaddr *, int, u_long,
    unsigned int);
static int rtrequest_common_locked(int, struct sockaddr *,
    struct sockaddr *, struct sockaddr *, int, struct rtentry **,
    unsigned int);
static void rtalloc_ign_common_locked(struct route *, u_long, unsigned int);
static inline void sa_set_ifscope(struct sockaddr *, unsigned int);
static struct sockaddr *sin_copy(struct sockaddr_in *, struct sockaddr_in *,
    unsigned int);
static struct sockaddr *mask_copy(struct sockaddr *, struct sockaddr_in *,
    unsigned int);
static struct radix_node *node_lookup(struct sockaddr *, struct sockaddr *,
    unsigned int);
static struct radix_node *node_lookup_default(void);
static int rn_match_ifscope(struct radix_node *, void *);
static struct ifaddr *ifa_ifwithroute_common_locked(int,
    const struct sockaddr *, const struct sockaddr *, unsigned int);

__private_extern__ u_long route_generation = 0;
extern int use_routegenid;

/*
 * sockaddr_in with embedded interface scope; this is used internally
 * to keep track of scoped route entries in the routing table.  The
 * fact that such a scope is embedded in the structure is an artifact
 * of the current implementation which could change in future.
 */
struct sockaddr_inifscope {
	__uint8_t	sin_len;
	sa_family_t	sin_family;
	in_port_t	sin_port;
	struct	in_addr sin_addr;
	/*
	 * To avoid possible conflict with an overlaid sockaddr_inarp
	 * having sin_other set to SIN_PROXY, we use the first 4-bytes
	 * of sin_zero since sin_srcaddr is one of the unused fields
	 * in sockaddr_inarp.
	 */
	union {
		char	sin_zero[8];
		struct {
			__uint32_t	ifscope;
		} _in_index;
	} un;
#define	sin_ifscope	un._in_index.ifscope
};

#define	SIN(sa)		((struct sockaddr_in *)(size_t)(sa))
#define	SINIFSCOPE(sa)	((struct sockaddr_inifscope *)(size_t)(sa))

#define	ASSERT_SINIFSCOPE(sa) {						\
	if ((sa)->sa_family != AF_INET ||				\
	    (sa)->sa_len < sizeof (struct sockaddr_in))			\
		panic("%s: bad sockaddr_in %p\n", __func__, sa);	\
}

/*
 * Argument to leaf-matching routine; at present it is scoped routing
 * specific but can be expanded in future to include other search filters.
 */
struct matchleaf_arg {
	unsigned int	ifscope;	/* interface scope */
};

/*
 * For looking up the non-scoped default route (sockaddr instead
 * of sockaddr_in for convenience).
 */
static struct sockaddr sin_def = {
	sizeof (struct sockaddr_in), AF_INET, { 0, }
};

/*
 * Interface index (scope) of the primary interface; determined at
 * the time when the default, non-scoped route gets added, changed
 * or deleted.  Protected by rt_mtx.
 */
static unsigned int primary_ifscope = IFSCOPE_NONE;

#define	INET_DEFAULT(dst)	\
	((dst)->sa_family == AF_INET && SIN(dst)->sin_addr.s_addr == 0)

#define	RT(r)		((struct rtentry *)r)
#define	RT_HOST(r)	(RT(r)->rt_flags & RTF_HOST)

/*
 * Given a route, determine whether or not it is the non-scoped default
 * route; dst typically comes from rt_key(rt) but may be coming from
 * a separate place when rt is in the process of being created.
 */
boolean_t
rt_inet_default(struct rtentry *rt, struct sockaddr *dst)
{
	return (INET_DEFAULT(dst) && !(rt->rt_flags & RTF_IFSCOPE));
}

/*
 * Set the ifscope of the primary interface; caller holds rt_mtx.
 */
void
set_primary_ifscope(unsigned int ifscope)
{
	primary_ifscope = ifscope;
}

/*
 * Return the ifscope of the primary interface; caller holds rt_mtx.
 */
unsigned int
get_primary_ifscope(void)
{
	return (primary_ifscope);
}

/*
 * Embed ifscope into a given a sockaddr_in.
 */
static inline void
sa_set_ifscope(struct sockaddr *sa, unsigned int ifscope)
{
	/* Caller must pass in sockaddr_in */
	ASSERT_SINIFSCOPE(sa);

	SINIFSCOPE(sa)->sin_ifscope = ifscope;
}

/*
 * Given a sockaddr_in, return the embedded ifscope to the caller.
 */
unsigned int
sa_get_ifscope(struct sockaddr *sa)
{
	/* Caller must pass in sockaddr_in */
	ASSERT_SINIFSCOPE(sa);

	return (SINIFSCOPE(sa)->sin_ifscope);
}

/*
 * Copy a sockaddr_in src to dst and embed ifscope into dst.
 */
static struct sockaddr *
sin_copy(struct sockaddr_in *src, struct sockaddr_in *dst, unsigned int ifscope)
{
	*dst = *src;
	sa_set_ifscope(SA(dst), ifscope);

	return (SA(dst));
}

/*
 * Copy a mask from src to a sockaddr_in dst and embed ifscope into dst.
 */
static struct sockaddr *
mask_copy(struct sockaddr *src, struct sockaddr_in *dst, unsigned int ifscope)
{
	/* We know dst is at least the size of sockaddr{_in} */
	bzero(dst, sizeof (*dst));
	rt_maskedcopy(src, SA(dst), src);

	/*
	 * The length of the mask sockaddr would need to be adjusted
	 * to cover the additional sin_ifscope field; when ifscope is
	 * IFSCOPE_NONE, we'd end up clearing the embedded ifscope on
	 * the destination mask in addition to extending the length
	 * of the sockaddr, as a side effect.  This is okay, as any
	 * trailing zeroes would be skipped by rn_addmask prior to
	 * inserting or looking up the mask in the mask tree.
	 */
	SINIFSCOPE(dst)->sin_ifscope = ifscope;
	SINIFSCOPE(dst)->sin_len =
	    offsetof(struct sockaddr_inifscope, sin_ifscope) +
	    sizeof (SINIFSCOPE(dst)->sin_ifscope);

	return (SA(dst));
}

/*
 * Callback leaf-matching routine for rn_matchaddr_args used
 * for looking up an exact match for a scoped route entry.
 */
static int
rn_match_ifscope(struct radix_node *rn, void *arg)
{
	struct rtentry *rt = (struct rtentry *)rn;
	struct matchleaf_arg *ma = arg;

	if (!(rt->rt_flags & RTF_IFSCOPE) || rt_key(rt)->sa_family != AF_INET)
		return (0);

	return (SINIFSCOPE(rt_key(rt))->sin_ifscope == ma->ifscope);
}

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

	PE_parse_boot_argn("rte_debug", &rte_debug, sizeof (rte_debug));
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
	return (rtalloc_ign_common_locked(ro, ignore, IFSCOPE_NONE));
}

void
rtalloc_scoped_ign_locked(struct route *ro, u_long ignore, unsigned int ifscope)
{
	return (rtalloc_ign_common_locked(ro, ignore, ifscope));
}

static void
rtalloc_ign_common_locked(struct route *ro, u_long ignore,
    unsigned int ifscope)
{
	struct rtentry *rt;

	if ((rt = ro->ro_rt) != NULL) {
		if (rt->rt_ifp != NULL && rt->rt_flags & RTF_UP)
			return;
		rtfree_locked(rt);
		ro->ro_rt = NULL;
	}
	ro->ro_rt = rtalloc1_common_locked(&ro->ro_dst, 1, ignore, ifscope);
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

struct rtentry *
rtalloc1_locked(struct sockaddr *dst, int report, u_long ignflags)
{
	return (rtalloc1_common_locked(dst, report, ignflags, IFSCOPE_NONE));
}

struct rtentry *
rtalloc1_scoped_locked(struct sockaddr *dst, int report, u_long ignflags,
    unsigned int ifscope)
{
	return (rtalloc1_common_locked(dst, report, ignflags, ifscope));
}

/*
 * Look up the route that matches the address given
 * Or, at least try.. Create a cloned route if needed.
 */
static struct rtentry *
rtalloc1_common_locked(struct sockaddr *dst, int report, u_long ignflags,
    unsigned int ifscope)
{
	struct radix_node_head *rnh = rt_tables[dst->sa_family];
	struct rtentry *rt, *newrt = NULL;
	struct rt_addrinfo info;
	u_long nflags;
	int  err = 0, msgtype = RTM_MISS;

	if (rnh == NULL)
		goto unreachable;

	/*
	 * Find the longest prefix or exact (in the scoped case) address match;
	 * callee adds a reference to entry and checks for root node as well
	 */
	rt = rt_lookup(FALSE, dst, NULL, rnh, ifscope);
	if (rt == NULL)
		goto unreachable;

	newrt = rt;
	nflags = rt->rt_flags & ~ignflags;
	if (report && (nflags & (RTF_CLONING | RTF_PRCLONING))) {
		/*
		 * We are apparently adding (report = 0 in delete).
		 * If it requires that it be cloned, do so.
		 * (This implies it wasn't a HOST route.)
		 */
		err = rtrequest_locked(RTM_RESOLVE, dst, NULL, NULL, 0, &newrt);
		if (err) {
			/*
			 * If the cloning didn't succeed, maybe what we
			 * have from lookup above will do.  Return that;
			 * no need to hold another reference since it's
			 * already done.
			 */
			newrt = rt;
			goto miss;
		}

		/*
		 * We cloned it; drop the original route found during lookup.
		 * The resulted cloned route (newrt) would now have an extra
		 * reference held during rtrequest.
		 */
		rtfree_locked(rt);
		if ((rt = newrt) && (rt->rt_flags & RTF_XRESOLVE)) {
			/*
			 * If the new route specifies it be
			 * externally resolved, then go do that.
			 */
			msgtype = RTM_RESOLVE;
			goto miss;
		}
	}
	goto done;

unreachable:
	/*
	 * Either we hit the root or couldn't find any match,
	 * Which basically means "cant get there from here"
	 */
	rtstat.rts_unreach++;
miss:
	if (report) {
		/*
		 * If required, report the failure to the supervising
		 * Authorities.
		 * For a delete, this is not an error. (report == 0)
		 */
		bzero((caddr_t)&info, sizeof(info));
		info.rti_info[RTAX_DST] = dst;
		rt_missmsg(msgtype, &info, 0, err);
	}
done:
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

	/*
	 * On last reference give the "close method" a chance to cleanup
	 * private state.  This also permits (for IPv4 and IPv6) a chance
	 * to decide if the routing table entry should be purged immediately
	 * or at a later time.  When an immediate purge is to happen the
	 * close routine typically issues RTM_DELETE which clears the RTF_UP
	 * flag on the entry so that the code below reclaims the storage.
	 */
	if (rnh && rnh->rnh_close && rt->rt_refcnt == 0)
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
 */
void
rtredirect(struct ifnet *ifp, struct sockaddr *dst, struct sockaddr *gateway,
   struct sockaddr *netmask, int flags, struct sockaddr *src,
   struct rtentry **rtp)
{
	struct rtentry *rt = NULL;
	int error = 0;
	short *stat = 0;
	struct rt_addrinfo info;
	struct ifaddr *ifa = NULL;
	unsigned int ifscope = (ifp != NULL) ? ifp->if_index : IFSCOPE_NONE;
	struct sockaddr_in sin;

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rt_mtx);

	/*
	 * Verify the gateway is directly reachable; if scoped routing
	 * is enabled, verify that it is reachable from the interface
	 * where the ICMP redirect arrived on.
	 */
	if ((ifa = ifa_ifwithnet_scoped(gateway, ifscope)) == NULL) {
		error = ENETUNREACH;
		goto out;
	}

	/* Lookup route to the destination (from the original IP header) */
	rt = rtalloc1_scoped_locked(dst, 0, RTF_CLONING|RTF_PRCLONING, ifscope);

	/* Embed scope in src for comparison against rt_gateway below */
	if (ip_doscopedroute && src->sa_family == AF_INET)
		src = sin_copy(SIN(src), &sin, ifscope);

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
			 * Create new route, rather than smashing route
			 * to net; similar to cloned routes, the newly
			 * created host route is scoped as well.
			 */
		create:
			flags |=  RTF_GATEWAY | RTF_DYNAMIC;
			error = rtrequest_scoped_locked(RTM_ADD, dst,
			    gateway, netmask, flags, NULL, ifscope);
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
			error = rt_setgate(rt, rt_key(rt), gateway);
		}
	} else {
		error = EHOSTUNREACH;
	}
done:
	if (rt) {
		if (rtp && !error)
			*rtp = rt;
		else
			rtfree_locked(rt);
	}
out:
	if (error) {
		rtstat.rts_badredirect++;
	} else {
		if (stat != NULL)
			(*stat)++;
		if (use_routegenid)
			route_generation++;
	}
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
ifa_ifwithroute_locked(int flags, const struct sockaddr *dst,
    const struct sockaddr *gateway)
{
	return (ifa_ifwithroute_common_locked((flags & ~RTF_IFSCOPE), dst,
	    gateway, IFSCOPE_NONE));
}

struct ifaddr *
ifa_ifwithroute_scoped_locked(int flags, const struct sockaddr *dst,
    const struct sockaddr *gateway, unsigned int ifscope)
{
	if (ifscope != IFSCOPE_NONE)
		flags |= RTF_IFSCOPE;
	else
		flags &= ~RTF_IFSCOPE;

	return (ifa_ifwithroute_common_locked(flags, dst, gateway, ifscope));
}

static struct ifaddr *
ifa_ifwithroute_common_locked(int flags, const struct sockaddr *dst,
    const struct sockaddr *gateway, unsigned int ifscope)
{
	struct ifaddr *ifa = NULL;
	struct rtentry *rt = NULL;
	struct sockaddr_in dst_in, gw_in;

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (ip_doscopedroute) {
		/*
		 * Just in case the sockaddr passed in by the caller
		 * contains embedded scope, make sure to clear it since
		 * IPv4 interface addresses aren't scoped.
		 */
		if (dst != NULL && dst->sa_family == AF_INET)
			dst = sin_copy(SIN(dst), &dst_in, IFSCOPE_NONE);
		if (gateway != NULL && gateway->sa_family == AF_INET)
			gateway = sin_copy(SIN(gateway), &gw_in, IFSCOPE_NONE);
	}

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
			ifa = ifa_ifwithaddr_scoped(gateway, ifscope);
	} else {
		/*
		 * If we are adding a route to a remote net
		 * or host, the gateway may still be on the
		 * other end of a pt to pt link.
		 */
		ifa = ifa_ifwithdstaddr(gateway);
	}
	if (ifa == NULL)
		ifa = ifa_ifwithnet_scoped(gateway, ifscope);
	if (ifa == NULL) {
		/* Workaround to avoid gcc warning regarding const variable */
		rt = rtalloc1_scoped_locked((struct sockaddr *)(size_t)dst,
		    0, 0UL, ifscope);
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
	    (rt = rtalloc1_scoped_locked((struct sockaddr *)(size_t)gateway,
	    0, 0UL, ifscope)) != NULL) {
		if (ifa != NULL)
			ifafree(ifa);
		ifa = rt->rt_ifa;
		if (ifa != NULL)
			ifaref(ifa);
		rtunref(rt);
	}
	/*
	 * If an interface scope was specified, the interface index of
	 * the found ifaddr must be equivalent to that of the scope;
	 * otherwise there is no match.
	 */
	if ((flags & RTF_IFSCOPE) &&
	    ifa != NULL && ifa->ifa_ifp->if_index != ifscope) {
		ifafree(ifa);
		ifa = NULL;
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

int
rtrequest_locked(int req, struct sockaddr *dst, struct sockaddr *gateway,
    struct sockaddr *netmask, int flags, struct rtentry **ret_nrt)
{
	return (rtrequest_common_locked(req, dst, gateway, netmask,
	    (flags & ~RTF_IFSCOPE), ret_nrt, IFSCOPE_NONE));
}

int
rtrequest_scoped_locked(int req, struct sockaddr *dst,
    struct sockaddr *gateway, struct sockaddr *netmask, int flags,
    struct rtentry **ret_nrt, unsigned int ifscope)
{
	if (ifscope != IFSCOPE_NONE)
		flags |= RTF_IFSCOPE;
	else
		flags &= ~RTF_IFSCOPE;

	return (rtrequest_common_locked(req, dst, gateway, netmask,
	    flags, ret_nrt, ifscope));
}

/*
 * Do appropriate manipulations of a routing tree given all the bits of
 * info needed.
 *
 * Embedding the scope in the radix key is an internal job that should be
 * left to routines in this module.  Callers should specify the scope value
 * to the "scoped" variants of route routines instead of manipulating the
 * key itself.  This is typically done when creating a scoped route, e.g.
 * rtrequest(RTM_ADD).  Once such a route is created and marked with the
 * RTF_IFSCOPE flag, callers can simply use its rt_key(rt) to clone it
 * (RTM_RESOLVE) or to remove it (RTM_DELETE).  An exception to this is
 * during certain routing socket operations where the search key might be
 * derived from the routing message itself, in which case the caller must
 * specify the destination address and scope value for RTM_ADD/RTM_DELETE.
 */
static int
rtrequest_common_locked(int req, struct sockaddr *dst0,
    struct sockaddr *gateway, struct sockaddr *netmask, int flags,
    struct rtentry **ret_nrt, unsigned int ifscope)
{
	int error = 0;
	struct rtentry *rt;
	struct radix_node *rn;
	struct radix_node_head *rnh;
	struct ifaddr *ifa = NULL;
	struct sockaddr *ndst, *dst = dst0;
	struct sockaddr_in sin, mask;
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

	/*
	 * If RTF_IFSCOPE is specified, use a local copy of the destination
	 * address to embed the scope into.  This logic is repeated below
	 * in the RTM_RESOLVE handler since the caller does not normally
	 * specify such a flag during a resolve; instead it passes in the
	 * route used for cloning for which the scope info is derived from.
	 * Note also that in the case of RTM_DELETE, the address passed in
	 * by the caller might already contain the embedded scope info when
	 * it is the key itself, thus making RTF_IFSCOPE unnecessary; one
	 * instance where it is explicitly set is inside route_output()
	 * as part of handling a routing socket request.
	 */
	if (req != RTM_RESOLVE && (flags & RTF_IFSCOPE)) {
		/* Scoped routing is for AF_INET only */
		if (dst->sa_family != AF_INET ||
		    (req == RTM_ADD && !ip_doscopedroute))
			senderr(EINVAL);

		if (ifscope == IFSCOPE_NONE) {
			flags &= ~RTF_IFSCOPE;
		} else {
			/* Embed ifscope into the key (local copy) */
			dst = sin_copy(SIN(dst), &sin, ifscope);

			/* Embed ifscope into netmask (local copy) */
			if (netmask != NULL)
				netmask = mask_copy(netmask, &mask, ifscope);
		}
	}

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
		 * If this is the (non-scoped) default route, clear
		 * the interface index used for the primary ifscope.
		 */
		if (rt_inet_default(rt, rt_key(rt)))
			set_primary_ifscope(IFSCOPE_NONE);

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

		if (!ip_doscopedroute || dst->sa_family != AF_INET)
			goto makeroute;
		/*
		 * When scoped routing is enabled, cloned entries are
		 * always scoped according to the interface portion of
		 * the parent route.  The exception to this are IPv4
		 * link local addresses.
		 */
		if (!IN_LINKLOCAL(ntohl(SIN(dst)->sin_addr.s_addr))) {
			if (flags & RTF_IFSCOPE) {
				ifscope = sa_get_ifscope(rt_key(rt));
			} else {
				ifscope = rt->rt_ifp->if_index;
				flags |= RTF_IFSCOPE;
			}
		} else {
			ifscope = IFSCOPE_NONE;
			flags &= ~RTF_IFSCOPE;
		}

		/* Embed or clear ifscope into/from the key (local copy) */
		dst = sin_copy(SIN(dst), &sin, ifscope);

		/* Embed or clear ifscope into/from netmask (local copy) */
		if (netmask != NULL)
			netmask = mask_copy(netmask, &mask, ifscope);

		goto makeroute;

	case RTM_ADD:
		if ((flags & RTF_GATEWAY) && !gateway)
			panic("rtrequest: RTF_GATEWAY but no gateway");

		if (flags & RTF_IFSCOPE) {
			ifa = ifa_ifwithroute_scoped_locked(flags, dst0,
			    gateway, ifscope);
		} else {
			ifa = ifa_ifwithroute_locked(flags, dst0, gateway);
		}
		if (ifa == NULL)
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
		if (netmask)
			rt_maskedcopy(dst, ndst, netmask);
		else
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
			if (flags & RTF_IFSCOPE) {
				rt2 = rtalloc1_scoped_locked(dst0, 0,
				    RTF_CLONING | RTF_PRCLONING, ifscope);
			} else {
				rt2 = rtalloc1_locked(dst, 0,
				    RTF_CLONING | RTF_PRCLONING);
			}
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
		 * If this is the (non-scoped) default route, record
		 * the interface index used for the primary ifscope.
		 */
		if (rt_inet_default(rt, rt_key(rt)))
			set_primary_ifscope(rt->rt_ifp->if_index);

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
static int
rt_fixchange(struct radix_node *rn, void *vp)
{
	struct rtentry *rt = (struct rtentry *)rn;
	struct rtfc_arg *ap = vp;
	struct rtentry *rt0 = ap->rt0;
	struct radix_node_head *rnh = ap->rnh;
	u_char *xk1, *xm1, *xk2, *xmp;
	int i, len, mlen;

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (!rt->rt_parent ||
	    (rt->rt_flags & (RTF_PINNED | RTF_CLONING | RTF_PRCLONING)))
		return (0);

	if (rt->rt_parent == rt0)
		goto delete_rt;

	/*
	 * There probably is a function somewhere which does this...
	 * if not, there should be.
	 */
	len = imin(rt_key(rt0)->sa_len, rt_key(rt)->sa_len);

	xk1 = (u_char *)rt_key(rt0);
	xm1 = (u_char *)rt_mask(rt0);
	xk2 = (u_char *)rt_key(rt);

	/* avoid applying a less specific route */
	xmp = (u_char *)rt_mask(rt->rt_parent);
	mlen = rt_key(rt->rt_parent)->sa_len;
	if (mlen > rt_key(rt0)->sa_len)
		return (0);

	for (i = rnh->rnh_treetop->rn_offset; i < mlen; i++) {
		if ((xmp[i] & ~(xmp[i] ^ xm1[i])) != xmp[i])
			return (0);
	}

	for (i = rnh->rnh_treetop->rn_offset; i < len; i++) {
		if ((xk2[i] & xm1[i]) != xk1[i])
			return (0);
	}

	/*
	 * OK, this node is a clone, and matches the node currently being
	 * changed/added under the node's mask.  So, get rid of it.
	 */
delete_rt:
	return (rtrequest_locked(RTM_DELETE, rt_key(rt), NULL,
	    rt_mask(rt), rt->rt_flags, NULL));
}

int
rt_setgate(struct rtentry *rt, struct sockaddr *dst, struct sockaddr *gate)
{
	int dlen = ROUNDUP(dst->sa_len), glen = ROUNDUP(gate->sa_len);
	struct radix_node_head *rnh = rt_tables[dst->sa_family];

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	/*
	 * A host route with the destination equal to the gateway
	 * will interfere with keeping LLINFO in the routing
	 * table, so disallow it.
	 */
	if (((rt->rt_flags & (RTF_HOST|RTF_GATEWAY|RTF_LLINFO)) ==
	    (RTF_HOST|RTF_GATEWAY)) && (dst->sa_len == gate->sa_len) &&
	    (bcmp(dst, gate, dst->sa_len) == 0)) {
		/*
		 * The route might already exist if this is an RTM_CHANGE
		 * or a routing redirect, so try to delete it.
		 */
		if (rt_key(rt))
			rtrequest_locked(RTM_DELETE, rt_key(rt),
			    rt->rt_gateway, rt_mask(rt), rt->rt_flags, NULL);
		return (EADDRNOTAVAIL);
	}

	/*
	 * The destination is not directly reachable.  Get a route
	 * to the next-hop gateway and store it in rt_gwroute.
	 */
	if (rt->rt_flags & RTF_GATEWAY) {
		struct rtentry *gwrt;
		unsigned int ifscope;

		ifscope = (dst->sa_family == AF_INET) ?
		    sa_get_ifscope(dst) : IFSCOPE_NONE;

		gwrt = rtalloc1_scoped_locked(gate, 1, RTF_PRCLONING, ifscope);

		/*
		 * Cloning loop avoidance:
		 *
		 * In the presence of protocol-cloning and bad configuration,
		 * it is possible to get stuck in bottomless mutual recursion
		 * (rtrequest rt_setgate rtalloc1).  We avoid this by not
		 * allowing protocol-cloning to operate for gateways (which
		 * is probably the correct choice anyway), and avoid the
		 * resulting reference loops by disallowing any route to run
		 * through itself as a gateway.  This is obviously mandatory
		 * when we get rt->rt_output().  It implies that a route to
		 * the gateway must already be present in the system in order
		 * for the gateway to be referred to by another route.
		 */
		if (gwrt == rt) {
			rtunref(gwrt);
			return (EADDRINUSE); /* failure */
		}

		/* If scoped, the gateway route must use the same interface */
		if (ifscope != IFSCOPE_NONE && (rt->rt_flags & RTF_IFSCOPE) &&
		    gwrt != NULL && gwrt->rt_ifp != NULL &&
		    gwrt->rt_ifp->if_index != ifscope) {
			rtfree_locked(gwrt);
			return ((rt->rt_flags & RTF_HOST) ?
			    EHOSTUNREACH : ENETUNREACH);
		}

		if (rt->rt_gwroute != NULL)
			rtfree_locked(rt->rt_gwroute);
		rt->rt_gwroute = gwrt;

		/*
		 * In case the (non-scoped) default route gets modified via
		 * an ICMP redirect, record the interface index used for the
		 * primary ifscope.  Also done in rt_setif() to take care
		 * of the non-redirect cases.
		 */
		if (rt_inet_default(rt, dst) && rt->rt_ifp != NULL)
			set_primary_ifscope(rt->rt_ifp->if_index);

		/*
		 * Tell the kernel debugger about the new default gateway
		 * if the gateway route uses the primary interface, or
		 * if we are in a transient state before the non-scoped
		 * default gateway is installed (similar to how the system
		 * was behaving in the past).  In future, it would be good
		 * to do all this only when KDP is enabled.
		 */
		if ((dst->sa_family == AF_INET) &&
		    gwrt != NULL && gwrt->rt_gateway->sa_family == AF_LINK &&
		    (gwrt->rt_ifp->if_index == get_primary_ifscope() ||
		    get_primary_ifscope() == IFSCOPE_NONE))
			kdp_set_gateway_mac(SDL(gwrt->rt_gateway)->sdl_data);
	}

	/*
	 * Prepare to store the gateway in rt_gateway.  Both dst and gateway
	 * are stored one after the other in the same malloc'd chunk.  If we
	 * have room, reuse the old buffer since rt_gateway already points
	 * to the right place.  Otherwise, malloc a new block and update
	 * the 'dst' address and point rt_gateway to the right place.
	 */
	if (rt->rt_gateway == NULL || glen > ROUNDUP(rt->rt_gateway->sa_len)) {
		caddr_t new;

		/* The underlying allocation is done with M_WAITOK set */
		R_Malloc(new, caddr_t, dlen + glen);
		if (new == NULL) {
			if (rt->rt_gwroute != NULL)
				rtfree_locked(rt->rt_gwroute);
			rt->rt_gwroute = NULL;
			return (ENOBUFS);
		}

		/*
		 * Copy from 'dst' and not rt_key(rt) because we can get
		 * here to initialize a newly allocated route entry, in
		 * which case rt_key(rt) is NULL (and so does rt_gateway).
		 */
		Bcopy(dst, new, dlen);
		R_Free(rt_key(rt));	/* free old block; NULL is okay */
		rt->rt_nodes->rn_key = new;
		rt->rt_gateway = (struct sockaddr *)(new + dlen);
	}

	/*
	 * Copy the new gateway value into the memory chunk.
	 */
	Bcopy(gate, rt->rt_gateway, glen);

	/*
	 * For consistency between rt_gateway and rt_key(gwrt).
	 */
	if ((rt->rt_flags & RTF_GATEWAY) && rt->rt_gwroute != NULL &&
	    (rt->rt_gwroute->rt_flags & RTF_IFSCOPE) &&
	    rt->rt_gateway->sa_family == AF_INET &&
	    rt_key(rt->rt_gwroute)->sa_family == AF_INET) {
		sa_set_ifscope(rt->rt_gateway,
		    sa_get_ifscope(rt_key(rt->rt_gwroute)));
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

	return (0);
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
 * Lookup an AF_INET scoped or non-scoped route depending on the ifscope
 * value passed in by the caller (IFSCOPE_NONE implies non-scoped).
 */
static struct radix_node *
node_lookup(struct sockaddr *dst, struct sockaddr *netmask,
    unsigned int ifscope)
{
	struct radix_node_head *rnh = rt_tables[AF_INET];
	struct radix_node *rn;
	struct sockaddr_in sin, mask;
	struct matchleaf_arg ma = { ifscope };
	rn_matchf_t *f = rn_match_ifscope;
	void *w = &ma;

	if (dst->sa_family != AF_INET)
		return (NULL);

	/*
	 * Embed ifscope into the search key; for a non-scoped
	 * search this will clear out any embedded scope value.
	 */
	dst = sin_copy(SIN(dst), &sin, ifscope);

	/* Embed (or clear) ifscope into netmask */
	if (netmask != NULL)
		netmask = mask_copy(netmask, &mask, ifscope);

	if (ifscope == IFSCOPE_NONE)
		f = w = NULL;

	rn = rnh->rnh_lookup_args(dst, netmask, rnh, f, w);
	if (rn != NULL && (rn->rn_flags & RNF_ROOT))
		rn = NULL;

	return (rn);
}

/*
 * Lookup the AF_INET non-scoped default route.
 */
static struct radix_node *
node_lookup_default(void)
{
	struct radix_node_head *rnh = rt_tables[AF_INET];
	return (rnh->rnh_lookup(&sin_def, NULL, rnh));
}

/*
 * Common routine to lookup/match a route.  It invokes the lookup/matchaddr
 * callback which could be address family-specific.  The main difference
 * between the two (at least for AF_INET/AF_INET6) is that a lookup does
 * not alter the expiring state of a route, whereas a match would unexpire
 * or revalidate the route.
 *
 * The optional scope or interface index property of a route allows for a
 * per-interface route instance.  This permits multiple route entries having
 * the same destination (but not necessarily the same gateway) to exist in
 * the routing table; each of these entries is specific to the corresponding
 * interface.  This is made possible by embedding the scope value into the
 * radix key, thus making each route entry unique.  These scoped entries
 * exist along with the regular, non-scoped entries in the same radix tree
 * for a given address family (currently AF_INET only); the scope logically
 * partitions it into multiple per-interface sub-trees.
 *
 * When a scoped route lookup is performed, the routing table is searched for
 * the best match that would result in a route using the same interface as the
 * one associated with the scope (the exception to this are routes that point
 * to the loopback interface).  The search rule follows the longest matching
 * prefix with the additional interface constraint.
 */
struct rtentry *
rt_lookup(boolean_t lookup_only, struct sockaddr *dst, struct sockaddr *netmask,
    struct radix_node_head *rnh, unsigned int ifscope)
{
	struct radix_node *rn0, *rn;
	boolean_t dontcare = (ifscope == IFSCOPE_NONE);

	lck_mtx_assert(rt_mtx, LCK_MTX_ASSERT_OWNED);

	if (!lookup_only)
		netmask = NULL;

	/*
	 * Non-scoped route lookup.
	 */
	if (!ip_doscopedroute || dst->sa_family != AF_INET) {
		if (lookup_only)
			rn = rnh->rnh_lookup(dst, netmask, rnh);
		else
			rn = rnh->rnh_matchaddr(dst, rnh);
		goto done;
	}

	/*
	 * Scoped route lookup:
	 *
	 * We first perform a non-scoped lookup for the original result.
	 * Afterwards, depending on whether or not the caller has specified
	 * a scope, we perform a more specific scoped search and fallback
	 * to this original result upon failure.
	 */
	rn0 = rn = node_lookup(dst, netmask, IFSCOPE_NONE);

	/*
	 * If the caller did not specify a scope, use the primary scope
	 * derived from the system's non-scoped default route.  If, for
	 * any reason, there is no primary interface, return what we have.
	 */
	if (dontcare && (ifscope = get_primary_ifscope()) == IFSCOPE_NONE)
		goto validate;

	/*
	 * Keep the original result if either of the following is true:
	 *
	 *   1) The interface portion of the route has the same interface
	 *	index as the scope value and it is marked with RTF_IFSCOPE.
	 *   2) The route uses the loopback interface, in which case the
	 *	destination (host/net) is local/loopback.
	 *
	 * Otherwise, do a more specified search using the scope.
	 */
	if (rn != NULL) {
		struct rtentry *rt = RT(rn);
		if (rt->rt_ifp != lo_ifp) {
			if (rt->rt_ifp->if_index != ifscope) {
				/*
				 * Wrong interface; keep the original result
				 * only if the caller did not specify a scope,
				 * and do a more specific scoped search using
				 * the scope of the found route.  Otherwise,
				 * start again from scratch.
				 */
				rn = NULL;
				if (dontcare)
					ifscope = rt->rt_ifp->if_index;
				else
					rn0 = NULL;
			} else if (!(rt->rt_flags & RTF_IFSCOPE)) {
				/*
				 * Right interface, except that this route
				 * isn't marked with RTF_IFSCOPE.  Do a more
				 * specific scoped search.  Keep the original
				 * result and return it it in case the scoped
				 * search fails.
				 */
				rn = NULL;
			}
		}
	}

	/*
	 * Scoped search.  Find the most specific entry having the same
	 * interface scope as the one requested.  The following will result
	 * in searching for the longest prefix scoped match.
	 */
	if (rn == NULL)
		rn = node_lookup(dst, netmask, ifscope);

	/*
	 * Use the original result if either of the following is true:
	 *
	 *   1) The scoped search did not yield any result.
	 *   2) The result from the scoped search is a scoped default route,
	 *	and the original (non-scoped) result is not a default route,
	 *	i.e. the original result is a more specific host/net route.
	 *   3)	The scoped search yielded a net route but the original
	 *	result is a host route, i.e. the original result is treated
	 *	as a more specific route.
	 */
	if (rn == NULL || (rn0 != NULL &&
	    ((INET_DEFAULT(rt_key(RT(rn))) && !INET_DEFAULT(rt_key(RT(rn0)))) ||
	    (!RT_HOST(rn) && RT_HOST(rn0)))))
		rn = rn0;

	/*
	 * If we still don't have a route, use the non-scoped default
	 * route as long as the interface portion satistifes the scope.
	 */
	if (rn == NULL && (rn = node_lookup_default()) != NULL &&
	    RT(rn)->rt_ifp->if_index != ifscope)
		rn = NULL;

validate:
	if (rn != NULL && !lookup_only)
		(void) in_validate(rn);

done:
	if (rn != NULL && (rn->rn_flags & RNF_ROOT))
		rn = NULL;
	else if (rn != NULL)
		rtref(RT(rn));

	return (RT(rn));
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
