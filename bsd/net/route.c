/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#include <sys/mcache.h>
#include <sys/protosw.h>
#include <kern/lock.h>
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/route.h>
#include <net/ntstat.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_mroute.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>

#if INET6
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#endif /* INET6 */

#include <net/if_dl.h>

#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>

#include <pexpert/pexpert.h>

/*
 * Synchronization notes:
 *
 * Routing entries fall under two locking domains: the global routing table
 * lock (rnh_lock) and the per-entry lock (rt_lock); the latter is a mutex that
 * resides (statically defined) in the rtentry structure.
 *
 * The locking domains for routing are defined as follows:
 *
 * The global routing lock is used to serialize all accesses to the radix
 * trees defined by rt_tables[], as well as the tree of masks.  This includes
 * lookups, insertions and removals of nodes to/from the respective tree.
 * It is also used to protect certain fields in the route entry that aren't
 * often modified and/or require global serialization (more details below.)
 *
 * The per-route entry lock is used to serialize accesses to several routing
 * entry fields (more details below.)  Acquiring and releasing this lock is
 * done via RT_LOCK() and RT_UNLOCK() routines.
 *
 * In cases where both rnh_lock and rt_lock must be held, the former must be
 * acquired first in order to maintain lock ordering.  It is not a requirement
 * that rnh_lock be acquired first before rt_lock, but in case both must be
 * acquired in succession, the correct lock ordering must be followed.
 *
 * The fields of the rtentry structure are protected in the following way:
 *
 * rt_nodes[]
 *
 *	- Routing table lock (rnh_lock).
 *
 * rt_parent, rt_mask, rt_llinfo_free
 *
 *	- Set once during creation and never changes; no locks to read.
 *
 * rt_flags, rt_genmask, rt_llinfo, rt_rmx, rt_refcnt, rt_gwroute
 *
 *	- Routing entry lock (rt_lock) for read/write access.
 *
 *	- Some values of rt_flags are either set once at creation time,
 *	  or aren't currently used, and thus checking against them can
 *	  be done without rt_lock: RTF_GATEWAY, RTF_HOST, RTF_DYNAMIC,
 *	  RTF_DONE,  RTF_XRESOLVE, RTF_STATIC, RTF_BLACKHOLE, RTF_ANNOUNCE,
 *	  RTF_USETRAILERS, RTF_WASCLONED, RTF_PINNED, RTF_LOCAL,
 *	  RTF_BROADCAST, RTF_MULTICAST, RTF_IFSCOPE, RTF_IFREF.
 *
 * rt_key, rt_gateway, rt_ifp, rt_ifa
 *
 *	- Always written/modified with both rnh_lock and rt_lock held.
 *
 *	- May be read freely with rnh_lock held, else must hold rt_lock
 *	  for read access; holding both locks for read is also okay.
 *
 *	- In the event rnh_lock is not acquired, or is not possible to be
 *	  acquired across the operation, setting RTF_CONDEMNED on a route
 *	  entry will prevent its rt_key, rt_gateway, rt_ifp and rt_ifa
 *	  from being modified.  This is typically done on a route that
 *	  has been chosen for a removal (from the tree) prior to dropping
 *	  the rt_lock, so that those values will remain the same until
 *	  the route is freed.
 *
 *	  When rnh_lock is held rt_setgate(), rt_setif(), and rtsetifa() are
 *	  single-threaded, thus exclusive.  This flag will also prevent the
 *	  route from being looked up via rt_lookup().
 *
 * generation_id
 *
 *	- Assumes that 32-bit writes are atomic; no locks.
 *
 * rt_dlt, rt_output
 *
 *	- Currently unused; no locks.
 *
 * Operations on a route entry can be described as follows:
 *
 * CREATE an entry with reference count set to 0 as part of RTM_ADD/RESOLVE.
 *
 * INSERTION of an entry into the radix tree holds the rnh_lock, checks
 * for duplicates and then adds the entry.  rtrequest returns the entry
 * after bumping up the reference count to 1 (for the caller).
 *
 * LOOKUP of an entry holds the rnh_lock and bumps up the reference count
 * before returning; it is valid to also bump up the reference count using
 * RT_ADDREF after the lookup has returned an entry.
 *
 * REMOVAL of an entry from the radix tree holds the rnh_lock, removes the
 * entry but does not decrement the reference count.  Removal happens when
 * the route is explicitly deleted (RTM_DELETE) or when it is in the cached
 * state and it expires.  The route is said to be "down" when it is no
 * longer present in the tree.  Freeing the entry will happen on the last
 * reference release of such a "down" route.
 *
 * RT_ADDREF/RT_REMREF operates on the routing entry which increments/
 * decrements the reference count, rt_refcnt, atomically on the rtentry.
 * rt_refcnt is modified only using this routine.  The general rule is to
 * do RT_ADDREF in the function that is passing the entry as an argument,
 * in order to prevent the entry from being freed by the callee.
 */

#define	equal(a1, a2) (bcmp((caddr_t)(a1), (caddr_t)(a2), (a1)->sa_len) == 0)

extern void kdp_set_gateway_mac (void *gatewaymac);

extern struct domain routedomain;
struct route_cb route_cb;
__private_extern__ struct rtstat rtstat  = { 0, 0, 0, 0, 0 };
struct radix_node_head *rt_tables[AF_MAX+1];

decl_lck_mtx_data(,rnh_lock_data);	/* global routing tables mutex */
lck_mtx_t		*rnh_lock = &rnh_lock_data;
static lck_attr_t	*rnh_lock_attr;
static lck_grp_t	*rnh_lock_grp;
static lck_grp_attr_t	*rnh_lock_grp_attr;

/* Lock group and attribute for routing entry locks */
static lck_attr_t	*rte_mtx_attr;
static lck_grp_t	*rte_mtx_grp;
static lck_grp_attr_t	*rte_mtx_grp_attr;

int rttrash = 0;		/* routes not in table but not freed */

unsigned int rte_debug;

/* Possible flags for rte_debug */
#define	RTD_DEBUG	0x1	/* enable or disable rtentry debug facility */
#define	RTD_TRACE	0x2	/* trace alloc, free, refcnt and lock */
#define	RTD_NO_FREE	0x4	/* don't free (good to catch corruptions) */

#define	RTE_NAME		"rtentry"	/* name for zone and rt_lock */

static struct zone *rte_zone;			/* special zone for rtentry */
#define	RTE_ZONE_MAX		65536		/* maximum elements in zone */
#define	RTE_ZONE_NAME		RTE_NAME	/* name of rtentry zone */

#define	RTD_INUSE		0xFEEDFACE	/* entry is in use */
#define	RTD_FREED		0xDEADBEEF	/* entry is freed */

/* For gdb */
__private_extern__ unsigned int ctrace_stack_size = CTRACE_STACK_SIZE;
__private_extern__ unsigned int ctrace_hist_size = CTRACE_HIST_SIZE;

/*
 * Debug variant of rtentry structure.
 */
struct rtentry_dbg {
	struct rtentry	rtd_entry;			/* rtentry */
	struct rtentry	rtd_entry_saved;		/* saved rtentry */
	uint32_t	rtd_inuse;			/* in use pattern */
	uint16_t	rtd_refhold_cnt;		/* # of rtref */
	uint16_t	rtd_refrele_cnt;		/* # of rtunref */
	uint32_t	rtd_lock_cnt;			/* # of locks */
	uint32_t	rtd_unlock_cnt;			/* # of unlocks */
	/*
	 * Alloc and free callers.
	 */
	ctrace_t	rtd_alloc;
	ctrace_t	rtd_free;
	/*
	 * Circular lists of rtref and rtunref callers.
	 */
	ctrace_t	rtd_refhold[CTRACE_HIST_SIZE];
	ctrace_t	rtd_refrele[CTRACE_HIST_SIZE];
	/*
	 * Circular lists of locks and unlocks.
	 */
	ctrace_t	rtd_lock[CTRACE_HIST_SIZE];
	ctrace_t	rtd_unlock[CTRACE_HIST_SIZE];
	/*
	 * Trash list linkage
	 */
	TAILQ_ENTRY(rtentry_dbg) rtd_trash_link;
};

/* List of trash route entries protected by rnh_lock */
static TAILQ_HEAD(, rtentry_dbg) rttrash_head;

static void rte_lock_init(struct rtentry *);
static void rte_lock_destroy(struct rtentry *);
static inline struct rtentry *rte_alloc_debug(void);
static inline void rte_free_debug(struct rtentry *);
static inline void rte_lock_debug(struct rtentry_dbg *);
static inline void rte_unlock_debug(struct rtentry_dbg *);
static void rt_maskedcopy(struct sockaddr *,
	    struct sockaddr *, struct sockaddr *);
static void rtable_init(void **);
static inline void rtref_audit(struct rtentry_dbg *);
static inline void rtunref_audit(struct rtentry_dbg *);
static struct rtentry *rtalloc1_common_locked(struct sockaddr *, int, uint32_t,
    unsigned int);
static int rtrequest_common_locked(int, struct sockaddr *,
    struct sockaddr *, struct sockaddr *, int, struct rtentry **,
    unsigned int);
static struct rtentry *rtalloc1_locked(struct sockaddr *, int, uint32_t);
static void rtalloc_ign_common_locked(struct route *, uint32_t, unsigned int);
static inline void sin6_set_ifscope(struct sockaddr *, unsigned int);
static inline void sin6_set_embedded_ifscope(struct sockaddr *, unsigned int);
static inline unsigned int sin6_get_embedded_ifscope(struct sockaddr *);
static struct sockaddr *sa_copy(struct sockaddr *, struct sockaddr_storage *,
    unsigned int *);
static struct sockaddr *ma_copy(int, struct sockaddr *,
    struct sockaddr_storage *, unsigned int);
static struct sockaddr *sa_trim(struct sockaddr *, int);
static struct radix_node *node_lookup(struct sockaddr *, struct sockaddr *,
    unsigned int);
static struct radix_node *node_lookup_default(int);
static int rn_match_ifscope(struct radix_node *, void *);
static struct ifaddr *ifa_ifwithroute_common_locked(int,
    const struct sockaddr *, const struct sockaddr *, unsigned int);
static struct rtentry *rte_alloc(void);
static void rte_free(struct rtentry *);
static void rtfree_common(struct rtentry *, boolean_t);
static void rte_if_ref(struct ifnet *, int);

uint32_t route_generation = 0;

/*
 * sockaddr_in with scope ID field; this is used internally to keep
 * track of scoped route entries in the routing table.  The fact that
 * such a value is embedded in the structure is an artifact of the
 * current implementation which could change in future.
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
#define	sin_scope_id	un._in_index.ifscope
};

#define	SINIFSCOPE(sa)	((struct sockaddr_inifscope *)(size_t)(sa))
#define	SIN6IFSCOPE(sa)	SIN6(sa)

#define	ASSERT_SINIFSCOPE(sa) {						\
	if ((sa)->sa_family != AF_INET ||				\
	    (sa)->sa_len < sizeof (struct sockaddr_in))			\
		panic("%s: bad sockaddr_in %p\n", __func__, sa);	\
}

#define	ASSERT_SIN6IFSCOPE(sa) {					\
	if ((sa)->sa_family != AF_INET6 ||				\
	    (sa)->sa_len < sizeof (struct sockaddr_in6))		\
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

static struct sockaddr_in6 sin6_def = {
	sizeof (struct sockaddr_in6), AF_INET6, 0, 0, IN6ADDR_ANY_INIT, 0
};

/*
 * Interface index (scope) of the primary interface; determined at
 * the time when the default, non-scoped route gets added, changed
 * or deleted.  Protected by rnh_lock.
 */
static unsigned int primary_ifscope = IFSCOPE_NONE;
static unsigned int primary6_ifscope = IFSCOPE_NONE;

#define	INET_DEFAULT(sa)	\
	((sa)->sa_family == AF_INET && SIN(sa)->sin_addr.s_addr == 0)

#define	INET6_DEFAULT(sa)						\
	((sa)->sa_family == AF_INET6 &&					\
	IN6_IS_ADDR_UNSPECIFIED(&SIN6(sa)->sin6_addr))

#define	SA_DEFAULT(sa)	(INET_DEFAULT(sa) || INET6_DEFAULT(sa))
#define	RT(r)		((struct rtentry *)r)
#define	RN(r)		((struct radix_node *)r)
#define	RT_HOST(r)	(RT(r)->rt_flags & RTF_HOST)

SYSCTL_DECL(_net_idle_route);

static int rt_if_idle_expire_timeout = RT_IF_IDLE_EXPIRE_TIMEOUT;
SYSCTL_INT(_net_idle_route, OID_AUTO, expire_timeout, CTLFLAG_RW|CTLFLAG_LOCKED,
    &rt_if_idle_expire_timeout, 0, "Default expiration time on routes for "
    "interface idle reference counting");

/*
 * Given a route, determine whether or not it is the non-scoped default
 * route; dst typically comes from rt_key(rt) but may be coming from
 * a separate place when rt is in the process of being created.
 */
boolean_t
rt_primary_default(struct rtentry *rt, struct sockaddr *dst)
{
	return (SA_DEFAULT(dst) && !(rt->rt_flags & RTF_IFSCOPE));
}

/*
 * Set the ifscope of the primary interface; caller holds rnh_lock.
 */
void
set_primary_ifscope(int af, unsigned int ifscope)
{
	if (af == AF_INET)
		primary_ifscope = ifscope;
	else
		primary6_ifscope = ifscope;
}

/*
 * Return the ifscope of the primary interface; caller holds rnh_lock.
 */
unsigned int
get_primary_ifscope(int af)
{
	return (af == AF_INET ? primary_ifscope : primary6_ifscope);
}

/*
 * Set the scope ID of a given a sockaddr_in.
 */
void
sin_set_ifscope(struct sockaddr *sa, unsigned int ifscope)
{
	/* Caller must pass in sockaddr_in */
	ASSERT_SINIFSCOPE(sa);

	SINIFSCOPE(sa)->sin_scope_id = ifscope;
}

/*
 * Set the scope ID of given a sockaddr_in6.
 */
static inline void
sin6_set_ifscope(struct sockaddr *sa, unsigned int ifscope)
{
	/* Caller must pass in sockaddr_in6 */
	ASSERT_SIN6IFSCOPE(sa);

	SIN6IFSCOPE(sa)->sin6_scope_id = ifscope;
}

/*
 * Given a sockaddr_in, return the scope ID to the caller.
 */
unsigned int
sin_get_ifscope(struct sockaddr *sa)
{
	/* Caller must pass in sockaddr_in */
	ASSERT_SINIFSCOPE(sa);

	return (SINIFSCOPE(sa)->sin_scope_id);
}

/*
 * Given a sockaddr_in6, return the scope ID to the caller.
 */
unsigned int
sin6_get_ifscope(struct sockaddr *sa)
{
	/* Caller must pass in sockaddr_in6 */
	ASSERT_SIN6IFSCOPE(sa);

	return (SIN6IFSCOPE(sa)->sin6_scope_id);
}

static inline void
sin6_set_embedded_ifscope(struct sockaddr *sa, unsigned int ifscope)
{
	/* Caller must pass in sockaddr_in6 */
	ASSERT_SIN6IFSCOPE(sa);
	VERIFY(IN6_IS_SCOPE_EMBED(&(SIN6(sa)->sin6_addr)));

	SIN6(sa)->sin6_addr.s6_addr16[1] = htons(ifscope);
}

static inline unsigned int
sin6_get_embedded_ifscope(struct sockaddr *sa)
{
	/* Caller must pass in sockaddr_in6 */
	ASSERT_SIN6IFSCOPE(sa);

	return (ntohs(SIN6(sa)->sin6_addr.s6_addr16[1]));
}

/*
 * Copy a sockaddr_{in,in6} src to a dst storage and set scope ID into dst.
 *
 * To clear the scope ID, pass is a NULL pifscope.  To set the scope ID, pass
 * in a non-NULL pifscope with non-zero ifscope.  Otherwise if pifscope is
 * non-NULL and ifscope is IFSCOPE_NONE, the existing scope ID is left intact.
 * In any case, the effective scope ID value is returned to the caller via
 * pifscope, if it is non-NULL.
 */
static struct sockaddr *
sa_copy(struct sockaddr *src, struct sockaddr_storage *dst,
    unsigned int *pifscope)
{
	int af = src->sa_family;
	unsigned int ifscope = (pifscope != NULL) ? *pifscope : IFSCOPE_NONE;

	VERIFY(af == AF_INET || af == AF_INET6);

	bzero(dst, sizeof (*dst));

	if (af == AF_INET) {
		bcopy(src, dst, sizeof (struct sockaddr_in));
		if (pifscope == NULL || ifscope != IFSCOPE_NONE)
			sin_set_ifscope(SA(dst), ifscope);
	} else {
		bcopy(src, dst, sizeof (struct sockaddr_in6));
		if (pifscope != NULL &&
		    IN6_IS_SCOPE_EMBED(&SIN6(dst)->sin6_addr)) {
			unsigned int eifscope;
			/*
			 * If the address contains the embedded scope ID,
			 * use that as the value for sin6_scope_id as long
			 * the caller doesn't insist on clearing it (by
			 * passing NULL) or setting it.
			 */
			eifscope = sin6_get_embedded_ifscope(SA(dst));
			if (eifscope != IFSCOPE_NONE && ifscope == IFSCOPE_NONE)
				ifscope = eifscope;
			sin6_set_ifscope(SA(dst), ifscope);
			/*
			 * If sin6_scope_id is set but the address doesn't
			 * contain the equivalent embedded value, set it.
			 */
			if (ifscope != IFSCOPE_NONE && eifscope != ifscope)
				sin6_set_embedded_ifscope(SA(dst), ifscope);
		} else if (pifscope == NULL || ifscope != IFSCOPE_NONE) {
			sin6_set_ifscope(SA(dst), ifscope);
		}
	}

	if (pifscope != NULL) {
		*pifscope = (af == AF_INET) ? sin_get_ifscope(SA(dst)) :
		    sin6_get_ifscope(SA(dst));
	}

	return (SA(dst));
}

/*
 * Copy a mask from src to a dst storage and set scope ID into dst.
 */
static struct sockaddr *
ma_copy(int af, struct sockaddr *src, struct sockaddr_storage *dst,
    unsigned int ifscope)
{
	VERIFY(af == AF_INET || af == AF_INET6);

	bzero(dst, sizeof (*dst));
	rt_maskedcopy(src, SA(dst), src);

	/*
	 * The length of the mask sockaddr would need to be adjusted
	 * to cover the additional {sin,sin6}_ifscope field; when ifscope
	 * is IFSCOPE_NONE, we'd end up clearing the scope ID field on
	 * the destination mask in addition to extending the length
	 * of the sockaddr, as a side effect.  This is okay, as any
	 * trailing zeroes would be skipped by rn_addmask prior to
	 * inserting or looking up the mask in the mask tree.
	 */
	if (af == AF_INET) {
		SINIFSCOPE(dst)->sin_scope_id = ifscope;
		SINIFSCOPE(dst)->sin_len =
		    offsetof(struct sockaddr_inifscope, sin_scope_id) +
		    sizeof (SINIFSCOPE(dst)->sin_scope_id);
	} else {
		SIN6IFSCOPE(dst)->sin6_scope_id = ifscope;
		SIN6IFSCOPE(dst)->sin6_len =
		    offsetof(struct sockaddr_in6, sin6_scope_id) +
		    sizeof (SIN6IFSCOPE(dst)->sin6_scope_id);
	}

	return (SA(dst));
}

/*
 * Trim trailing zeroes on a sockaddr and update its length.
 */
static struct sockaddr *
sa_trim(struct sockaddr *sa, int skip)
{
	caddr_t cp, base = (caddr_t)sa + skip;

	if (sa->sa_len <= skip)
		return (sa);

	for (cp = base + (sa->sa_len - skip); cp > base && cp[-1] == 0;)
		cp--;

	sa->sa_len = (cp - base) + skip;
	if (sa->sa_len < skip) {
		/* Must not happen, and if so, panic */
		panic("%s: broken logic (sa_len %d < skip %d )", __func__,
		    sa->sa_len, skip);
		/* NOTREACHED */
	} else if (sa->sa_len == skip) {
		/* If we end up with all zeroes, then there's no mask */
		sa->sa_len = 0;
	}

	return (sa);
}

/*
 * Called by rtm_msg{1,2} routines to "scrub" the scope ID field away from
 * the socket address structure, so that clients of the routing socket will
 * not be confused by the presence of the information, or the side effect of
 * the increased length due to that.  The source sockaddr is not modified;
 * instead, the scrubbing happens on the destination sockaddr storage that
 * is passed in by the caller.
 */
struct sockaddr *
rtm_scrub_ifscope(int type, int idx, struct sockaddr *hint, struct sockaddr *sa,
    struct sockaddr_storage *ss)
{
	struct sockaddr *ret = sa;

	switch (idx) {
	case RTAX_DST:
		/*
		 * If this is for an AF_INET/AF_INET6 destination address,
		 * call sa_copy() to clear the scope ID field.
		 */
		if (sa->sa_family == AF_INET &&
		    SINIFSCOPE(sa)->sin_scope_id != IFSCOPE_NONE) {
			ret = sa_copy(sa, ss, NULL);
		} else if (sa->sa_family == AF_INET6 &&
		    SIN6IFSCOPE(sa)->sin6_scope_id != IFSCOPE_NONE) {
			ret = sa_copy(sa, ss, NULL);
		}
		break;

	case RTAX_NETMASK: {
		int skip, af;
		/*
		 * If this is for a mask, we can't tell whether or not there
		 * is an valid scope ID value, as the span of bytes between
		 * sa_len and the beginning of the mask (offset of sin_addr in
		 * the case of AF_INET, or sin6_addr for AF_INET6) may be
		 * filled with all-ones by rn_addmask(), and hence we cannot
		 * rely on sa_family.  Because of this, we use the sa_family
		 * of the hint sockaddr (RTAX_{DST,IFA}) as indicator as to
		 * whether or not the mask is to be treated as one for AF_INET
		 * or AF_INET6.  Clearing the scope ID field involves setting
		 * it to IFSCOPE_NONE followed by calling sa_trim() to trim
		 * trailing zeroes from the storage sockaddr, which reverses
		 * what was done earlier by ma_copy() on the source sockaddr.
		 */
		if (hint == NULL ||
		    ((af = hint->sa_family) != AF_INET && af != AF_INET6))
			break;	/* nothing to do */

		skip = (af == AF_INET) ?
		    offsetof(struct sockaddr_in, sin_addr) :
		    offsetof(struct sockaddr_in6, sin6_addr);

		if (sa->sa_len > skip && sa->sa_len <= sizeof (*ss)) {
			bzero(ss, sizeof (*ss));
			bcopy(sa, ss, sa->sa_len);
			/*
			 * Don't use {sin,sin6}_set_ifscope() as sa_family
			 * and sa_len for the netmask might not be set to
			 * the corresponding expected values of the hint.
			 */
			if (hint->sa_family == AF_INET)
				SINIFSCOPE(ss)->sin_scope_id = IFSCOPE_NONE;
			else
				SIN6IFSCOPE(ss)->sin6_scope_id = IFSCOPE_NONE;
			ret = sa_trim(SA(ss), skip);

			/*
			 * For AF_INET6 mask, set sa_len appropriately unless
			 * this is requested via systl_dumpentry(), in which
			 * case we return the raw value.
			 */
			if (hint->sa_family == AF_INET6 &&
			    type != RTM_GET && type != RTM_GET2)
				SA(ret)->sa_len = sizeof (struct sockaddr_in6);
		}
		break;
	}
	default:
		break;
	}

	return (ret);
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
	int af = rt_key(rt)->sa_family;

	if (!(rt->rt_flags & RTF_IFSCOPE) || (af != AF_INET && af != AF_INET6))
		return (0);

	return (af == AF_INET ?
	    (SINIFSCOPE(rt_key(rt))->sin_scope_id == ma->ifscope) :
	    (SIN6IFSCOPE(rt_key(rt))->sin6_scope_id == ma->ifscope));
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

	rnh_lock_grp_attr = lck_grp_attr_alloc_init();
	rnh_lock_grp = lck_grp_alloc_init("route", rnh_lock_grp_attr);
	rnh_lock_attr = lck_attr_alloc_init();
	lck_mtx_init(rnh_lock, rnh_lock_grp, rnh_lock_attr);

	rte_mtx_grp_attr = lck_grp_attr_alloc_init();
	rte_mtx_grp = lck_grp_alloc_init(RTE_NAME, rte_mtx_grp_attr);
	rte_mtx_attr = lck_attr_alloc_init();

	lck_mtx_lock(rnh_lock);
	rn_init();	/* initialize all zeroes, all ones, mask table */
	lck_mtx_unlock(rnh_lock);
	rtable_init((void **)rt_tables);

	if (rte_debug & RTD_DEBUG)
		size = sizeof (struct rtentry_dbg);
	else
		size = sizeof (struct rtentry);

	rte_zone = zinit(size, RTE_ZONE_MAX * size, 0, RTE_ZONE_NAME);
	if (rte_zone == NULL)
		panic("route_init: failed allocating rte_zone");

	zone_change(rte_zone, Z_EXPAND, TRUE);
	zone_change(rte_zone, Z_CALLERACCT, FALSE);
	zone_change(rte_zone, Z_NOENCRYPT, TRUE);

	TAILQ_INIT(&rttrash_head);
}

/*
 * Atomically increment route generation counter
 */
void
routegenid_update(void)
{
	(void) atomic_add_32_ov(&route_generation, 1);
}

/*
 * Packet routing routines.
 */
void
rtalloc(struct route *ro)
{
	rtalloc_ign(ro, 0);
}

void
rtalloc_scoped(struct route *ro, unsigned int ifscope)
{
	rtalloc_scoped_ign(ro, 0, ifscope);
}

static void
rtalloc_ign_common_locked(struct route *ro, uint32_t ignore,
    unsigned int ifscope)
{
	struct rtentry *rt;

	if ((rt = ro->ro_rt) != NULL) {
		RT_LOCK_SPIN(rt);
		if (rt->rt_ifp != NULL && (rt->rt_flags & RTF_UP) &&
		    rt->generation_id == route_generation) {
			RT_UNLOCK(rt);
			return;
		}
		RT_UNLOCK(rt);
		rtfree_locked(rt);
		ro->ro_rt = NULL;
	}
	ro->ro_rt = rtalloc1_common_locked(&ro->ro_dst, 1, ignore, ifscope);
	if (ro->ro_rt != NULL) {
		ro->ro_rt->generation_id = route_generation;
		RT_LOCK_ASSERT_NOTHELD(ro->ro_rt);
	}
}

void
rtalloc_ign(struct route *ro, uint32_t ignore)
{
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);
	rtalloc_ign_common_locked(ro, ignore, IFSCOPE_NONE);
	lck_mtx_unlock(rnh_lock);
}

void
rtalloc_scoped_ign(struct route *ro, uint32_t ignore, unsigned int ifscope)
{
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);
	rtalloc_ign_common_locked(ro, ignore, ifscope);
	lck_mtx_unlock(rnh_lock);
}

static struct rtentry *
rtalloc1_locked(struct sockaddr *dst, int report, uint32_t ignflags)
{
	return (rtalloc1_common_locked(dst, report, ignflags, IFSCOPE_NONE));
}

struct rtentry *
rtalloc1_scoped_locked(struct sockaddr *dst, int report, uint32_t ignflags,
    unsigned int ifscope)
{
	return (rtalloc1_common_locked(dst, report, ignflags, ifscope));
}

/*
 * Look up the route that matches the address given
 * Or, at least try.. Create a cloned route if needed.
 */
static struct rtentry *
rtalloc1_common_locked(struct sockaddr *dst, int report, uint32_t ignflags,
    unsigned int ifscope)
{
	struct radix_node_head *rnh = rt_tables[dst->sa_family];
	struct rtentry *rt, *newrt = NULL;
	struct rt_addrinfo info;
	uint32_t nflags;
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

	RT_LOCK_SPIN(rt);
	newrt = rt;
	nflags = rt->rt_flags & ~ignflags;
	RT_UNLOCK(rt);
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
rtalloc1(struct sockaddr *dst, int report, uint32_t ignflags)
{
	struct rtentry * entry;
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);
	entry = rtalloc1_locked(dst, report, ignflags);
	lck_mtx_unlock(rnh_lock);
	return (entry);
}

struct rtentry *
rtalloc1_scoped(struct sockaddr *dst, int report, uint32_t ignflags,
    unsigned int ifscope)
{
	struct rtentry * entry;
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);
	entry = rtalloc1_scoped_locked(dst, report, ignflags, ifscope);
	lck_mtx_unlock(rnh_lock);
	return (entry);
}

/*
 * Remove a reference count from an rtentry.
 * If the count gets low enough, take it out of the routing table
 */
void
rtfree_locked(struct rtentry *rt)
{
	rtfree_common(rt, TRUE);
}

static void
rtfree_common(struct rtentry *rt, boolean_t locked)
{
	struct radix_node_head *rnh;

	/*
	 * Atomically decrement the reference count and if it reaches 0,
	 * and there is a close function defined, call the close function.
	 */
	RT_LOCK_SPIN(rt);
	if (rtunref(rt) > 0) {
		RT_UNLOCK(rt);
		return;
	}

	/*
	 * To avoid violating lock ordering, we must drop rt_lock before
	 * trying to acquire the global rnh_lock.  If we are called with
	 * rnh_lock held, then we already have exclusive access; otherwise
	 * we do the lock dance.
	 */
	if (!locked) {
		/*
		* Note that we check it again below after grabbing rnh_lock,
		* since it is possible that another thread doing a lookup wins
		* the race, grabs the rnh_lock first, and bumps up the reference
		* count in which case the route should be left alone as it is
		* still in use.  It's also possible that another thread frees
		* the route after we drop rt_lock; to prevent the route from
		* being freed, we hold an extra reference.
		*/
		RT_ADDREF_LOCKED(rt);
		RT_UNLOCK(rt);
		lck_mtx_lock(rnh_lock);
		RT_LOCK_SPIN(rt);
		RT_REMREF_LOCKED(rt);
		if (rt->rt_refcnt > 0) {
			/* We've lost the race, so abort */
			RT_UNLOCK(rt);
			goto done;
		}
	}

	/*
	 * We may be blocked on other lock(s) as part of freeing
	 * the entry below, so convert from spin to full mutex.
	 */
	RT_CONVERT_LOCK(rt);

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	/* Negative refcnt must never happen */
	if (rt->rt_refcnt != 0)
		panic("rt %p invalid refcnt %d", rt, rt->rt_refcnt);

	/*
	 * find the tree for that address family
	 * Note: in the case of igmp packets, there might not be an rnh
	 */
	rnh = rt_tables[rt_key(rt)->sa_family];

	/*
	 * On last reference give the "close method" a chance to cleanup
	 * private state.  This also permits (for IPv4 and IPv6) a chance
	 * to decide if the routing table entry should be purged immediately
	 * or at a later time.  When an immediate purge is to happen the
	 * close routine typically issues RTM_DELETE which clears the RTF_UP
	 * flag on the entry so that the code below reclaims the storage.
	 */
	if (rnh != NULL && rnh->rnh_close != NULL)
		rnh->rnh_close((struct radix_node *)rt, rnh);

	/*
	 * If we are no longer "up" (and ref == 0) then we can free the
	 * resources associated with the route.
	 */
	if (!(rt->rt_flags & RTF_UP)) {
		struct rtentry *rt_parent;
		struct ifaddr *rt_ifa;

		if (rt->rt_nodes->rn_flags & (RNF_ACTIVE | RNF_ROOT))
			panic("rt %p freed while in radix tree\n", rt);
		/*
		 * the rtentry must have been removed from the routing table
		 * so it is represented in rttrash; remove that now.
		 */
		(void) OSDecrementAtomic(&rttrash);
		if (rte_debug & RTD_DEBUG) {
			TAILQ_REMOVE(&rttrash_head, (struct rtentry_dbg *)rt,
			    rtd_trash_link);
		}

		/*
		 * release references on items we hold them on..
		 * e.g other routes and ifaddrs.
		 */
		if ((rt_parent = rt->rt_parent) != NULL)
			rt->rt_parent = NULL;

		if ((rt_ifa = rt->rt_ifa) != NULL)
			rt->rt_ifa = NULL;

		/*
		 * Now free any attached link-layer info.
		 */
		if (rt->rt_llinfo != NULL) {
			if (rt->rt_llinfo_free != NULL)
				(*rt->rt_llinfo_free)(rt->rt_llinfo);
			else
				R_Free(rt->rt_llinfo);
			rt->rt_llinfo = NULL;
		}

		/*
		 * Route is no longer in the tree and refcnt is 0;
		 * we have exclusive access, so destroy it.
		 */
		RT_UNLOCK(rt);

		if (rt_parent != NULL)
			rtfree_locked(rt_parent);

		if (rt_ifa != NULL)
			IFA_REMREF(rt_ifa);

		/*
		 * The key is separately alloc'd so free it (see rt_setgate()).
		 * This also frees the gateway, as they are always malloc'd
		 * together.
		 */
		R_Free(rt_key(rt));

		/*
		 * Free any statistics that may have been allocated
		 */
		nstat_route_detach(rt);

		/*
		 * and the rtentry itself of course
		 */
		rte_lock_destroy(rt);
		rte_free(rt);
	} else {
		/*
		 * The "close method" has been called, but the route is
		 * still in the radix tree with zero refcnt, i.e. "up"
		 * and in the cached state.
		 */
		RT_UNLOCK(rt);
	}
done:
	if (!locked)
		lck_mtx_unlock(rnh_lock);
}

void
rtfree(struct rtentry *rt)
{
	rtfree_common(rt, FALSE);
}

/*
 * Decrements the refcount but does not free the route when
 * the refcount reaches zero. Unless you have really good reason,
 * use rtfree not rtunref.
 */
int
rtunref(struct rtentry *p)
{
	RT_LOCK_ASSERT_HELD(p);

	if (p->rt_refcnt == 0)
		panic("%s(%p) bad refcnt\n", __func__, p);

	--p->rt_refcnt;

	if (rte_debug & RTD_DEBUG)
		rtunref_audit((struct rtentry_dbg *)p);

	/* Return new value */
	return (p->rt_refcnt);
}

static inline void
rtunref_audit(struct rtentry_dbg *rte)
{
	uint16_t idx;

	if (rte->rtd_inuse != RTD_INUSE)
		panic("rtunref: on freed rte=%p\n", rte);

	idx = atomic_add_16_ov(&rte->rtd_refrele_cnt, 1) % CTRACE_HIST_SIZE;
	if (rte_debug & RTD_TRACE)
		ctrace_record(&rte->rtd_refrele[idx]);
}

/*
 * Add a reference count from an rtentry.
 */
void
rtref(struct rtentry *p)
{
	RT_LOCK_ASSERT_HELD(p);

	if (++p->rt_refcnt == 0)
		panic("%s(%p) bad refcnt\n", __func__, p);

	if (rte_debug & RTD_DEBUG)
		rtref_audit((struct rtentry_dbg *)p);
}

static inline void
rtref_audit(struct rtentry_dbg *rte)
{
	uint16_t idx;

	if (rte->rtd_inuse != RTD_INUSE)
		panic("rtref_audit: on freed rte=%p\n", rte);

	idx = atomic_add_16_ov(&rte->rtd_refhold_cnt, 1) % CTRACE_HIST_SIZE;
	if (rte_debug & RTD_TRACE)
		ctrace_record(&rte->rtd_refhold[idx]);
}

void
rtsetifa(struct rtentry *rt, struct ifaddr* ifa)
{
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	RT_LOCK_ASSERT_HELD(rt);

	if (rt->rt_ifa == ifa)
		return;

	/* Become a regular mutex, just in case */
	RT_CONVERT_LOCK(rt);

	/* Release the old ifa */
	if (rt->rt_ifa)
		IFA_REMREF(rt->rt_ifa);

	/* Set rt_ifa */
	rt->rt_ifa = ifa;

	/* Take a reference to the ifa */
	if (rt->rt_ifa)
		IFA_ADDREF(rt->rt_ifa);
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
	struct sockaddr_storage ss;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);

	/*
	 * Transform src into the internal routing table form for
	 * comparison against rt_gateway below.
	 */
#if INET6
	if ((src->sa_family == AF_INET && ip_doscopedroute) ||
	    (src->sa_family == AF_INET6 && ip6_doscopedroute))
#else
	if (src->sa_family == AF_INET && ip_doscopedroute)
#endif /* !INET6 */
		src = sa_copy(src, &ss, &ifscope);

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
	if (rt != NULL)
		RT_LOCK(rt);

	/*
	 * If the redirect isn't from our current router for this dst,
	 * it's either old or wrong.  If it redirects us to ourselves,
	 * we have a routing loop, perhaps as a result of an interface
	 * going down recently.  Holding rnh_lock here prevents the
	 * possibility of rt_ifa/ifa's ifa_addr from changing (e.g.
	 * in_ifinit), so okay to access ifa_addr without locking.
	 */
	if (!(flags & RTF_DONE) && rt != NULL &&
	     (!equal(src, rt->rt_gateway) || !equal(rt->rt_ifa->ifa_addr,
	     ifa->ifa_addr))) {
		error = EINVAL;
	} else {
		IFA_REMREF(ifa);
		if ((ifa = ifa_ifwithaddr(gateway))) {
			IFA_REMREF(ifa);
			ifa = NULL;
			error = EHOSTUNREACH;
		}
	}

	if (ifa) {
		IFA_REMREF(ifa);
		ifa = NULL;
	}

	if (error) {
		if (rt != NULL)
			RT_UNLOCK(rt);
		goto done;
	}

	/*
	 * Create a new entry if we just got back a wildcard entry
	 * or the the lookup failed.  This is necessary for hosts
	 * which use routing redirects generated by smart gateways
	 * to dynamically build the routing tables.
	 */
	if ((rt == NULL) || (rt_mask(rt) != NULL && rt_mask(rt)->sa_len < 2))
		goto create;
	/*
	 * Don't listen to the redirect if it's
	 * for a route to an interface.
	 */
	RT_LOCK_ASSERT_HELD(rt);
	if (rt->rt_flags & RTF_GATEWAY) {
		if (((rt->rt_flags & RTF_HOST) == 0) && (flags & RTF_HOST)) {
			/*
			 * Changing from route to net => route to host.
			 * Create new route, rather than smashing route
			 * to net; similar to cloned routes, the newly
			 * created host route is scoped as well.
			 */
create:
			if (rt != NULL)
				RT_UNLOCK(rt);
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
			RT_UNLOCK(rt);
		}
	} else {
		RT_UNLOCK(rt);
		error = EHOSTUNREACH;
	}
done:
	if (rt != NULL) {
		RT_LOCK_ASSERT_NOTHELD(rt);
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
			routegenid_update();
	}
	lck_mtx_unlock(rnh_lock);
	bzero((caddr_t)&info, sizeof(info));
	info.rti_info[RTAX_DST] = dst;
	info.rti_info[RTAX_GATEWAY] = gateway;
	info.rti_info[RTAX_NETMASK] = netmask;
	info.rti_info[RTAX_AUTHOR] = src;
	rt_missmsg(RTM_REDIRECT, &info, flags, error);
}

/*
* Routing table ioctl interface.
*/
int
rtioctl(unsigned long req, caddr_t data, struct proc *p)
{
#pragma unused(p)
#if INET && MROUTING
	return mrt_ioctl(req, data);
#else
#pragma unused(req)
#pragma unused(data)
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

	lck_mtx_lock(rnh_lock);
	ifa = ifa_ifwithroute_locked(flags, dst, gateway);
	lck_mtx_unlock(rnh_lock);

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
    const struct sockaddr *gw, unsigned int ifscope)
{
	struct ifaddr *ifa = NULL;
	struct rtentry *rt = NULL;
	struct sockaddr_storage dst_ss, gw_ss;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Just in case the sockaddr passed in by the caller
	 * contains a scope ID, make sure to clear it since
	 * interface addresses aren't scoped.
	 */
#if INET6
	if (dst != NULL &&
	    ((dst->sa_family == AF_INET && ip_doscopedroute) ||
	    (dst->sa_family == AF_INET6 && ip6_doscopedroute)))
#else
	if (dst != NULL && dst->sa_family == AF_INET && ip_doscopedroute)
#endif /* !INET6 */
		dst = sa_copy(SA((uintptr_t)dst), &dst_ss, NULL);

#if INET6
	if (gw != NULL &&
	    ((gw->sa_family == AF_INET && ip_doscopedroute) ||
	    (gw->sa_family == AF_INET6 && ip6_doscopedroute)))
#else
	if (gw != NULL && gw->sa_family == AF_INET && ip_doscopedroute)
#endif /* !INET6 */
		gw = sa_copy(SA((uintptr_t)gw), &gw_ss, NULL);

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
			ifa = ifa_ifwithaddr_scoped(gw, ifscope);
	} else {
		/*
		 * If we are adding a route to a remote net
		 * or host, the gateway may still be on the
		 * other end of a pt to pt link.
		 */
		ifa = ifa_ifwithdstaddr(gw);
	}
	if (ifa == NULL)
		ifa = ifa_ifwithnet_scoped(gw, ifscope);
	if (ifa == NULL) {
		/* Workaround to avoid gcc warning regarding const variable */
		rt = rtalloc1_scoped_locked((struct sockaddr *)(size_t)dst,
		    0, 0, ifscope);
		if (rt != NULL) {
			RT_LOCK_SPIN(rt);
			ifa = rt->rt_ifa;
			if (ifa != NULL) {
				/* Become a regular mutex */
				RT_CONVERT_LOCK(rt);
				IFA_ADDREF(ifa);
			}
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			rt = NULL;
		}
	}
	/*
	 * Holding rnh_lock here prevents the possibility of ifa from
	 * changing (e.g. in_ifinit), so it is safe to access its
	 * ifa_addr (here and down below) without locking.
	 */
	if (ifa != NULL && ifa->ifa_addr->sa_family != dst->sa_family) {
		struct ifaddr *newifa;
		/* Callee adds reference to newifa upon success */
		newifa = ifaof_ifpforaddr(dst, ifa->ifa_ifp);
		if (newifa != NULL) {
			IFA_REMREF(ifa);
			ifa = newifa;
		}
	}
	/*
	 * If we are adding a gateway, it is quite possible that the
	 * routing table has a static entry in place for the gateway,
	 * that may not agree with info garnered from the interfaces.
	 * The routing table should carry more precedence than the
	 * interfaces in this matter.  Must be careful not to stomp
	 * on new entries from rtinit, hence (ifa->ifa_addr != gw).
	 */
	if ((ifa == NULL ||
	    !equal(ifa->ifa_addr, (struct sockaddr *)(size_t)gw)) &&
	    (rt = rtalloc1_scoped_locked((struct sockaddr *)(size_t)gw,
	    0, 0, ifscope)) != NULL) {
		if (ifa != NULL)
			IFA_REMREF(ifa);
		RT_LOCK_SPIN(rt);
		ifa = rt->rt_ifa;
		if (ifa != NULL) {
			/* Become a regular mutex */
			RT_CONVERT_LOCK(rt);
			IFA_ADDREF(ifa);
		}
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
	}
	/*
	 * If an interface scope was specified, the interface index of
	 * the found ifaddr must be equivalent to that of the scope;
	 * otherwise there is no match.
	 */
	if ((flags & RTF_IFSCOPE) &&
	    ifa != NULL && ifa->ifa_ifp->if_index != ifscope) {
		IFA_REMREF(ifa);
		ifa = NULL;
	}

	return (ifa);
}

static int rt_fixdelete(struct radix_node *, void *);
static int rt_fixchange(struct radix_node *, void *);

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
 * Storing the scope ID in the radix key is an internal job that should be
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
	struct sockaddr_storage ss, mask;
	struct timeval curr_calendartime;
	int af = dst->sa_family;
	void (*ifa_rtrequest)(int, struct rtentry *, struct sockaddr *);

#define senderr(x) { error = x ; goto bad; }

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	/*
	 * Find the correct routing tree to use for this Address Family
	 */
	if ((rnh = rt_tables[af]) == NULL)
		senderr(ESRCH);
	/*
	 * If we are adding a host route then we don't want to put
	 * a netmask in the tree
	 */
	if (flags & RTF_HOST)
		netmask = NULL;

	/*
	 * If Scoped Routing is enabled, use a local copy of the destination
	 * address to store the scope ID into.  This logic is repeated below
	 * in the RTM_RESOLVE handler since the caller does not normally
	 * specify such a flag during a resolve, as well as for the handling
	 * of IPv4 link-local address; instead, it passes in the route used for
	 * cloning for which the scope info is derived from.  Note also that
	 * in the case of RTM_DELETE, the address passed in by the caller
	 * might already contain the scope ID info when it is the key itself,
	 * thus making RTF_IFSCOPE unnecessary; one instance where it is
	 * explicitly set is inside route_output() as part of handling a
	 * routing socket request.
	 */
#if INET6
	if (req != RTM_RESOLVE &&
	    ((af == AF_INET && ip_doscopedroute) ||
	    (af == AF_INET6 && ip6_doscopedroute))) {
#else
	if (req != RTM_RESOLVE && af == AF_INET && ip_doscopedroute) {
#endif /* !INET6 */
		/* Transform dst into the internal routing table form */
		dst = sa_copy(dst, &ss, &ifscope);

		/* Transform netmask into the internal routing table form */
		if (netmask != NULL)
			netmask = ma_copy(af, netmask, &mask, ifscope);

		if (ifscope != IFSCOPE_NONE)
			flags |= RTF_IFSCOPE;
	} else {
		if ((flags & RTF_IFSCOPE) && (af != AF_INET && af != AF_INET6))
			senderr(EINVAL);

#if INET6
		if ((af == AF_INET && !ip_doscopedroute) ||
		    (af == AF_INET6 && !ip6_doscopedroute))
#else
		if (af == AF_INET && !ip_doscopedroute)
#endif /* !INET6 */
			ifscope = IFSCOPE_NONE;
	}

	if (ifscope == IFSCOPE_NONE)
		flags &= ~RTF_IFSCOPE;

	switch (req) {
	case RTM_DELETE: {
		struct rtentry *gwrt = NULL;
		/*
		 * Remove the item from the tree and return it.
		 * Complain if it is not there and do no more processing.
		 */
		if ((rn = rnh->rnh_deladdr(dst, netmask, rnh)) == NULL)
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
		RT_LOCK(rt);
		RT_ADDREF_LOCKED(rt);
		rt->rt_flags &= ~RTF_UP;

		/*
		 * For consistency, in case the caller didn't set the flag.
		 */
		rt->rt_flags |= RTF_CONDEMNED;

		/*
		 * Clear RTF_ROUTER if it's set.
		 */
		if (rt->rt_flags & RTF_ROUTER) {
			VERIFY(rt->rt_flags & RTF_HOST);
			rt->rt_flags &= ~RTF_ROUTER;
		}

		/*
		 * Now search what's left of the subtree for any cloned
		 * routes which might have been formed from this node.
		 */
		if ((rt->rt_flags & (RTF_CLONING | RTF_PRCLONING)) &&
		    rt_mask(rt)) {
			RT_UNLOCK(rt);
			rnh->rnh_walktree_from(rnh, dst, rt_mask(rt),
					       rt_fixdelete, rt);
			RT_LOCK(rt);
		}

		/*
		 * Remove any external references we may have.
		 */
		if ((gwrt = rt->rt_gwroute) != NULL)
			rt->rt_gwroute = NULL;

		/*
		 * give the protocol a chance to keep things in sync.
		 */
		if ((ifa = rt->rt_ifa) != NULL) {
			IFA_LOCK_SPIN(ifa);
			ifa_rtrequest = ifa->ifa_rtrequest;
			IFA_UNLOCK(ifa);
			if (ifa_rtrequest != NULL)
				ifa_rtrequest(RTM_DELETE, rt, NULL);
			/* keep reference on rt_ifa */
			ifa = NULL;
		}

		/*
		 * one more rtentry floating around that is not
		 * linked to the routing table.
		 */
		(void) OSIncrementAtomic(&rttrash);
		if (rte_debug & RTD_DEBUG) {
			TAILQ_INSERT_TAIL(&rttrash_head,
			    (struct rtentry_dbg *)rt, rtd_trash_link);
		}

		/*
		 * If this is the (non-scoped) default route, clear
		 * the interface index used for the primary ifscope.
		 */
		if (rt_primary_default(rt, rt_key(rt))) {
			set_primary_ifscope(rt_key(rt)->sa_family,
			    IFSCOPE_NONE);
		}
		rt_clear_idleref(rt);

		RT_UNLOCK(rt);

		/*
		 * This might result in another rtentry being freed if
		 * we held its last reference.  Do this after the rtentry
		 * lock is dropped above, as it could lead to the same
		 * lock being acquired if gwrt is a clone of rt.
		 */
		if (gwrt != NULL)
			rtfree_locked(gwrt);

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
	}
	case RTM_RESOLVE:
		if (ret_nrt == NULL || (rt = *ret_nrt) == NULL)
			senderr(EINVAL);
		/*
		 * If cloning, we have the parent route given by the caller
		 * and will use its rt_gateway, rt_rmx as part of the cloning
		 * process below.  Since rnh_lock is held at this point, the
		 * parent's rt_ifa and rt_gateway will not change, and its
		 * relevant rt_flags will not change as well.  The only thing
		 * that could change are the metrics, and thus we hold the
		 * parent route's rt_lock later on during the actual copying
		 * of rt_rmx.
		 */
		ifa = rt->rt_ifa;
		IFA_ADDREF(ifa);
		flags = rt->rt_flags &
		    ~(RTF_CLONING | RTF_PRCLONING | RTF_STATIC);
		flags |= RTF_WASCLONED;
		gateway = rt->rt_gateway;
		if ((netmask = rt->rt_genmask) == NULL)
			flags |= RTF_HOST;

#if INET6
		if ((af != AF_INET && af != AF_INET6) ||
		    (af == AF_INET && !ip_doscopedroute) ||
		    (af == AF_INET6 && !ip6_doscopedroute))
#else
		if (af != AF_INET || !ip_doscopedroute)
#endif /* !INET6 */
			goto makeroute;

		/*
		 * When scoped routing is enabled, cloned entries are
		 * always scoped according to the interface portion of
		 * the parent route.  The exception to this are IPv4
		 * link local addresses, or those routes that are cloned
		 * from a RTF_PROXY route.  For the latter, the clone
		 * gets to keep the RTF_PROXY flag.
		 */
		if ((af == AF_INET &&
		    IN_LINKLOCAL(ntohl(SIN(dst)->sin_addr.s_addr))) ||
		    (rt->rt_flags & RTF_PROXY)) {
			ifscope = IFSCOPE_NONE;
			flags &= ~RTF_IFSCOPE;
		} else {
			if (flags & RTF_IFSCOPE) {
				ifscope = (af == AF_INET) ?
				    sin_get_ifscope(rt_key(rt)) :
				    sin6_get_ifscope(rt_key(rt));
			} else {
				ifscope = rt->rt_ifp->if_index;
				flags |= RTF_IFSCOPE;
			}
			VERIFY(ifscope != IFSCOPE_NONE);
		}

		/*
		 * Transform dst into the internal routing table form,
		 * clearing out the scope ID field if ifscope isn't set.
		 */
		dst = sa_copy(dst, &ss, (ifscope == IFSCOPE_NONE) ?
		    NULL : &ifscope);

		/* Transform netmask into the internal routing table form */
		if (netmask != NULL)
			netmask = ma_copy(af, netmask, &mask, ifscope);

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
		getmicrotime(&curr_calendartime);
		if ((rt = rte_alloc()) == NULL)
			senderr(ENOBUFS);
		Bzero(rt, sizeof(*rt));
		rte_lock_init(rt);
                rt->base_calendartime = curr_calendartime.tv_sec;
		rt->base_uptime = net_uptime();
		RT_LOCK(rt);
		rt->rt_flags = RTF_UP | flags;

		/*
		 * Add the gateway. Possibly re-malloc-ing the storage for it
		 * also add the rt_gwroute if possible.
		 */
		if ((error = rt_setgate(rt, dst, gateway)) != 0) {
			int tmp = error;
			RT_UNLOCK(rt);
			nstat_route_detach(rt);
			rte_lock_destroy(rt);
			rte_free(rt);
			senderr(tmp);
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
				/*
				 * rnh_lock is held here, so rt_key and
				 * rt_gateway of rt2 will not change.
				 */
				(void) rtrequest_locked(RTM_DELETE, rt_key(rt2),
				    rt2->rt_gateway, rt_mask(rt2),
				    rt2->rt_flags, 0);
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
		if (rn == NULL) {
			/* Clear gateway route */
			rt_set_gwroute(rt, rt_key(rt), NULL);
			if (rt->rt_ifa) {
				IFA_REMREF(rt->rt_ifa);
				rt->rt_ifa = NULL;
			}
			R_Free(rt_key(rt));
			RT_UNLOCK(rt);
			nstat_route_detach(rt);
			rte_lock_destroy(rt);
			rte_free(rt);
			senderr(EEXIST);
		}

		rt->rt_parent = NULL;

		/*
		 * If we got here from RESOLVE, then we are cloning so clone
		 * the rest, and note that we are a clone (and increment the
		 * parent's references).  rnh_lock is still held, which prevents
		 * a lookup from returning the newly-created route.  Hence
		 * holding and releasing the parent's rt_lock while still
		 * holding the route's rt_lock is safe since the new route
		 * is not yet externally visible.
		 */
		if (req == RTM_RESOLVE) {
			RT_LOCK_SPIN(*ret_nrt);
			VERIFY((*ret_nrt)->rt_expire == 0 ||
			    (*ret_nrt)->rt_rmx.rmx_expire != 0);
			VERIFY((*ret_nrt)->rt_expire != 0 ||
			    (*ret_nrt)->rt_rmx.rmx_expire == 0);
			rt->rt_rmx = (*ret_nrt)->rt_rmx;
			rt_setexpire(rt, (*ret_nrt)->rt_expire);
			if ((*ret_nrt)->rt_flags & (RTF_CLONING | RTF_PRCLONING)) {
				rt->rt_parent = (*ret_nrt);
				RT_ADDREF_LOCKED(*ret_nrt);
			}
			RT_UNLOCK(*ret_nrt);

			/*
			 * Enable interface reference counting for unicast
			 * cloned routes and bump up the reference count.
			 */
			if (rt->rt_parent != NULL &&
			    !(rt->rt_flags & (RTF_BROADCAST | RTF_MULTICAST))) {
				rt_set_idleref(rt);
			}
		}

		/*
		 * if this protocol has something to add to this then
		 * allow it to do that as well.
		 */
		IFA_LOCK_SPIN(ifa);
		ifa_rtrequest = ifa->ifa_rtrequest;
		IFA_UNLOCK(ifa);
		if (ifa_rtrequest != NULL)
			ifa_rtrequest(req, rt, SA(ret_nrt ? *ret_nrt : NULL));
		IFA_REMREF(ifa);
		ifa = NULL;

		/*
		 * If this is the (non-scoped) default route, record
		 * the interface index used for the primary ifscope.
		 */
		if (rt_primary_default(rt, rt_key(rt))) {
			set_primary_ifscope(rt_key(rt)->sa_family,
			    rt->rt_ifp->if_index);
		}

		/*
		 * actually return a resultant rtentry and
		 * give the caller a single reference.
		 */
		if (ret_nrt) {
			*ret_nrt = rt;
			RT_ADDREF_LOCKED(rt);
		}

		/*
		 * We repeat the same procedures from rt_setgate() here
		 * because they weren't completed when we called it earlier,
		 * since the node was embryonic.
		 */
		if ((rt->rt_flags & RTF_GATEWAY) && rt->rt_gwroute != NULL)
			rt_set_gwroute(rt, rt_key(rt), rt->rt_gwroute);

		if (req == RTM_ADD &&
		    !(rt->rt_flags & RTF_HOST) && rt_mask(rt) != NULL) {
			struct rtfc_arg arg;
			arg.rnh = rnh;
			arg.rt0 = rt;
			RT_UNLOCK(rt);
			rnh->rnh_walktree_from(rnh, rt_key(rt), rt_mask(rt),
					       rt_fixchange, &arg);
		} else {
			RT_UNLOCK(rt);
		}

		nstat_route_new_entry(rt);
		break;
	}
bad:
	if (ifa)
		IFA_REMREF(ifa);
	return (error);
}
#undef senderr

int
rtrequest(int req, struct sockaddr *dst, struct sockaddr *gateway,
    struct sockaddr *netmask, int flags, struct rtentry **ret_nrt)
{
	int error;
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);
	error = rtrequest_locked(req, dst, gateway, netmask, flags, ret_nrt);
	lck_mtx_unlock(rnh_lock);
	return (error);
}

int
rtrequest_scoped(int req, struct sockaddr *dst, struct sockaddr *gateway,
    struct sockaddr *netmask, int flags, struct rtentry **ret_nrt,
    unsigned int ifscope)
{
	int error;
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);
	error = rtrequest_scoped_locked(req, dst, gateway, netmask, flags,
	    ret_nrt, ifscope);
	lck_mtx_unlock(rnh_lock);
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

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	RT_LOCK(rt);
	if (rt->rt_parent == rt0 &&
	    !(rt->rt_flags & (RTF_PINNED | RTF_CLONING | RTF_PRCLONING))) {
		/*
		 * Safe to drop rt_lock and use rt_key, since holding
		 * rnh_lock here prevents another thread from calling
		 * rt_setgate() on this route.
		 */
		RT_UNLOCK(rt);
		return (rtrequest_locked(RTM_DELETE, rt_key(rt), NULL,
		    rt_mask(rt), rt->rt_flags, NULL));
	}
	RT_UNLOCK(rt);
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
	int i, len;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	RT_LOCK(rt);

	if (!rt->rt_parent ||
	    (rt->rt_flags & (RTF_PINNED | RTF_CLONING | RTF_PRCLONING))) {
		RT_UNLOCK(rt);
		return (0);
	}

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

	/*
	 * Avoid applying a less specific route; do this only if the parent
	 * route (rt->rt_parent) is a network route, since otherwise its mask
	 * will be NULL if it is a cloning host route.
	 */
	if ((xmp = (u_char *)rt_mask(rt->rt_parent)) != NULL) {
		int mlen = rt_mask(rt->rt_parent)->sa_len;
		if (mlen > rt_mask(rt0)->sa_len) {
			RT_UNLOCK(rt);
			return (0);
		}

		for (i = rnh->rnh_treetop->rn_offset; i < mlen; i++) {
			if ((xmp[i] & ~(xmp[i] ^ xm1[i])) != xmp[i]) {
				RT_UNLOCK(rt);
				return (0);
			}
		}
	}

	for (i = rnh->rnh_treetop->rn_offset; i < len; i++) {
		if ((xk2[i] & xm1[i]) != xk1[i]) {
			RT_UNLOCK(rt);
			return (0);
		}
	}

	/*
	 * OK, this node is a clone, and matches the node currently being
	 * changed/added under the node's mask.  So, get rid of it.
	 */
delete_rt:
	/*
	 * Safe to drop rt_lock and use rt_key, since holding rnh_lock here
	 * prevents another thread from calling rt_setgate() on this route.
	 */
	RT_UNLOCK(rt);
	return (rtrequest_locked(RTM_DELETE, rt_key(rt), NULL,
	    rt_mask(rt), rt->rt_flags, NULL));
}

/*
 * Round up sockaddr len to multiples of 32-bytes.  This will reduce
 * or even eliminate the need to re-allocate the chunk of memory used
 * for rt_key and rt_gateway in the event the gateway portion changes.
 * Certain code paths (e.g. IPSec) are notorious for caching the address
 * of rt_gateway; this rounding-up would help ensure that the gateway
 * portion never gets deallocated (though it may change contents) and
 * thus greatly simplifies things.
 */
#define	SA_SIZE(x) (-(-((uintptr_t)(x)) & -(32)))

/*
 * Sets the gateway and/or gateway route portion of a route; may be
 * called on an existing route to modify the gateway portion.  Both
 * rt_key and rt_gateway are allocated out of the same memory chunk.
 * Route entry lock must be held by caller; this routine will return
 * with the lock held.
 */
int
rt_setgate(struct rtentry *rt, struct sockaddr *dst, struct sockaddr *gate)
{
	int dlen = SA_SIZE(dst->sa_len), glen = SA_SIZE(gate->sa_len);
	struct radix_node_head *rnh = rt_tables[dst->sa_family];
	boolean_t loop = FALSE;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	/*
	 * If this is for a route that is on its way of being removed,
	 * or is temporarily frozen, reject the modification request.
	 */
	if (rt->rt_flags & RTF_CONDEMNED)
		return (EBUSY);

	/* Add an extra ref for ourselves */
	RT_ADDREF_LOCKED(rt);

	if (rt->rt_flags & RTF_GATEWAY) {
		if ((dst->sa_len == gate->sa_len) &&
		    (dst->sa_family == AF_INET || dst->sa_family == AF_INET6)) {
			struct sockaddr_storage dst_ss, gate_ss;

			(void) sa_copy(dst, &dst_ss, NULL);
			(void) sa_copy(gate, &gate_ss, NULL);

			loop = equal(SA(&dst_ss), SA(&gate_ss));
		} else {
			loop = (dst->sa_len == gate->sa_len &&
			    equal(dst, gate));
		}
	}

	/*
	 * A (cloning) network route with the destination equal to the gateway
	 * will create an endless loop (see notes below), so disallow it.
	 */
	if (((rt->rt_flags & (RTF_HOST|RTF_GATEWAY|RTF_LLINFO)) ==
	    RTF_GATEWAY) && loop) {
		/* Release extra ref */
		RT_REMREF_LOCKED(rt);
		return (EADDRNOTAVAIL);
	}

	/*
	 * A host route with the destination equal to the gateway
	 * will interfere with keeping LLINFO in the routing
	 * table, so disallow it.
	 */
	if (((rt->rt_flags & (RTF_HOST|RTF_GATEWAY|RTF_LLINFO)) ==
	    (RTF_HOST|RTF_GATEWAY)) && loop) {
		/*
		 * The route might already exist if this is an RTM_CHANGE
		 * or a routing redirect, so try to delete it.
		 */
		if (rt_key(rt) != NULL) {
			/*
			 * Safe to drop rt_lock and use rt_key, rt_gateway,
			 * since holding rnh_lock here prevents another thread
			 * from calling rt_setgate() on this route.
			 */
			RT_UNLOCK(rt);
			(void) rtrequest_locked(RTM_DELETE, rt_key(rt),
			    rt->rt_gateway, rt_mask(rt), rt->rt_flags, NULL);
			RT_LOCK(rt);
		}
		/* Release extra ref */
		RT_REMREF_LOCKED(rt);
		return (EADDRNOTAVAIL);
	}

	/*
	 * The destination is not directly reachable.  Get a route
	 * to the next-hop gateway and store it in rt_gwroute.
	 */
	if (rt->rt_flags & RTF_GATEWAY) {
		struct rtentry *gwrt;
		unsigned int ifscope;

		if (dst->sa_family == AF_INET)
			ifscope = sin_get_ifscope(dst);
		else if (dst->sa_family == AF_INET6)
			ifscope = sin6_get_ifscope(dst);
		else
			ifscope = IFSCOPE_NONE;

		RT_UNLOCK(rt);
		/*
		 * Don't ignore RTF_CLONING, since we prefer that rt_gwroute
		 * points to a clone rather than a cloning route; see above
		 * check for cloning loop avoidance (dst == gate).
		 */
		gwrt = rtalloc1_scoped_locked(gate, 1, RTF_PRCLONING, ifscope);
		if (gwrt != NULL)
			RT_LOCK_ASSERT_NOTHELD(gwrt);
		RT_LOCK(rt);

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
			RT_REMREF_LOCKED(gwrt);
			/* Release extra ref */
			RT_REMREF_LOCKED(rt);
			return (EADDRINUSE); /* failure */
		}

		/*
		 * If scoped, the gateway route must use the same interface;
		 * we're holding rnh_lock now, so rt_gateway and rt_ifp of gwrt
		 * should not change and are freely accessible.
		 */
		if (ifscope != IFSCOPE_NONE && (rt->rt_flags & RTF_IFSCOPE) &&
		    gwrt != NULL && gwrt->rt_ifp != NULL &&
		    gwrt->rt_ifp->if_index != ifscope) {
			rtfree_locked(gwrt);	/* rt != gwrt, no deadlock */
			/* Release extra ref */
			RT_REMREF_LOCKED(rt);
			return ((rt->rt_flags & RTF_HOST) ?
			    EHOSTUNREACH : ENETUNREACH);
		}

		/* Check again since we dropped the lock above */
		if (rt->rt_flags & RTF_CONDEMNED) {
			if (gwrt != NULL)
				rtfree_locked(gwrt);
			/* Release extra ref */
			RT_REMREF_LOCKED(rt);
			return (EBUSY);
		}

		/* Set gateway route; callee adds ref to gwrt if non-NULL */
		rt_set_gwroute(rt, dst, gwrt);

		/*
		 * In case the (non-scoped) default route gets modified via
		 * an ICMP redirect, record the interface index used for the
		 * primary ifscope.  Also done in rt_setif() to take care
		 * of the non-redirect cases.
		 */
		if (rt_primary_default(rt, dst) && rt->rt_ifp != NULL) {
			set_primary_ifscope(dst->sa_family,
			    rt->rt_ifp->if_index);
		}

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
		    (gwrt->rt_ifp->if_index == get_primary_ifscope(AF_INET) ||
		    get_primary_ifscope(AF_INET) == IFSCOPE_NONE)) {
			kdp_set_gateway_mac(SDL((void *)gwrt->rt_gateway)->
			    sdl_data);
		}

		/* Release extra ref from rtalloc1() */
		if (gwrt != NULL)
			RT_REMREF(gwrt);
	}

	/*
	 * Prepare to store the gateway in rt_gateway.  Both dst and gateway
	 * are stored one after the other in the same malloc'd chunk.  If we
	 * have room, reuse the old buffer since rt_gateway already points
	 * to the right place.  Otherwise, malloc a new block and update
	 * the 'dst' address and point rt_gateway to the right place.
	 */
	if (rt->rt_gateway == NULL || glen > SA_SIZE(rt->rt_gateway->sa_len)) {
		caddr_t new;

		/* The underlying allocation is done with M_WAITOK set */
		R_Malloc(new, caddr_t, dlen + glen);
		if (new == NULL) {
			/* Clear gateway route */
			rt_set_gwroute(rt, dst, NULL);
			/* Release extra ref */
			RT_REMREF_LOCKED(rt);
			return (ENOBUFS);
		}

		/*
		 * Copy from 'dst' and not rt_key(rt) because we can get
		 * here to initialize a newly allocated route entry, in
		 * which case rt_key(rt) is NULL (and so does rt_gateway).
		 */
		bzero(new, dlen + glen);
		Bcopy(dst, new, dst->sa_len);
		R_Free(rt_key(rt));	/* free old block; NULL is okay */
		rt->rt_nodes->rn_key = new;
		rt->rt_gateway = (struct sockaddr *)(new + dlen);
	}

	/*
	 * Copy the new gateway value into the memory chunk.
	 */
	Bcopy(gate, rt->rt_gateway, gate->sa_len);

	/*
	 * For consistency between rt_gateway and rt_key(gwrt).
	 */
	if ((rt->rt_flags & RTF_GATEWAY) && rt->rt_gwroute != NULL &&
	    (rt->rt_gwroute->rt_flags & RTF_IFSCOPE)) {
		if (rt->rt_gateway->sa_family == AF_INET &&
		    rt_key(rt->rt_gwroute)->sa_family == AF_INET) {
			sin_set_ifscope(rt->rt_gateway,
			    sin_get_ifscope(rt_key(rt->rt_gwroute)));
		} else if (rt->rt_gateway->sa_family == AF_INET6 &&
		    rt_key(rt->rt_gwroute)->sa_family == AF_INET6) {
			sin6_set_ifscope(rt->rt_gateway,
			    sin6_get_ifscope(rt_key(rt->rt_gwroute)));
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
		RT_UNLOCK(rt);
		rnh->rnh_walktree_from(rnh, rt_key(rt), rt_mask(rt),
		    rt_fixchange, &arg);
		RT_LOCK(rt);
	}

	/* Release extra ref */
	RT_REMREF_LOCKED(rt);
	return (0);
}

#undef SA_SIZE

void
rt_set_gwroute(struct rtentry *rt, struct sockaddr *dst, struct rtentry *gwrt)
{
	boolean_t gwrt_isrouter;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	if (gwrt != NULL)
		RT_ADDREF(gwrt);	/* for this routine */

	/*
	 * Get rid of existing gateway route; if rt_gwroute is already
	 * set to gwrt, this is slightly redundant (though safe since
	 * we held an extra ref above) but makes the code simpler.
	 */
	if (rt->rt_gwroute != NULL) {
		struct rtentry *ogwrt = rt->rt_gwroute;

		VERIFY(rt != ogwrt);	/* sanity check */
		rt->rt_gwroute = NULL;
		RT_UNLOCK(rt);
		rtfree_locked(ogwrt);
		RT_LOCK(rt);
		VERIFY(rt->rt_gwroute == NULL);
	}

	/*
	 * And associate the new gateway route.
	 */
	if ((rt->rt_gwroute = gwrt) != NULL) {
		RT_ADDREF(gwrt);	/* for rt */

		if (rt->rt_flags & RTF_WASCLONED) {
			/* rt_parent might be NULL if rt is embryonic */
			gwrt_isrouter = (rt->rt_parent != NULL &&
			    SA_DEFAULT(rt_key(rt->rt_parent)) &&
			    !RT_HOST(rt->rt_parent));
		} else {
			gwrt_isrouter = (SA_DEFAULT(dst) && !RT_HOST(rt));
		}

		/* If gwrt points to a default router, mark it accordingly */
		if (gwrt_isrouter && RT_HOST(gwrt) &&
		    !(gwrt->rt_flags & RTF_ROUTER)) {
			RT_LOCK(gwrt);
			gwrt->rt_flags |= RTF_ROUTER;
			RT_UNLOCK(gwrt);
		}

		RT_REMREF(gwrt);	/* for this routine */
	}
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
 * Lookup an AF_INET/AF_INET6 scoped or non-scoped route depending on the
 * ifscope value passed in by the caller (IFSCOPE_NONE implies non-scoped).
 */
static struct radix_node *
node_lookup(struct sockaddr *dst, struct sockaddr *netmask,
    unsigned int ifscope)
{
	struct radix_node_head *rnh;
	struct radix_node *rn;
	struct sockaddr_storage ss, mask;
	int af = dst->sa_family;
	struct matchleaf_arg ma = { ifscope };
	rn_matchf_t *f = rn_match_ifscope;
	void *w = &ma;

	if (af != AF_INET && af != AF_INET6)
		return (NULL);

	rnh = rt_tables[af];

	/*
	 * Transform dst into the internal routing table form,
	 * clearing out the scope ID field if ifscope isn't set.
	 */
	dst = sa_copy(dst, &ss, (ifscope == IFSCOPE_NONE) ? NULL : &ifscope);

	/* Transform netmask into the internal routing table form */
	if (netmask != NULL)
		netmask = ma_copy(af, netmask, &mask, ifscope);

	if (ifscope == IFSCOPE_NONE)
		f = w = NULL;

	rn = rnh->rnh_lookup_args(dst, netmask, rnh, f, w);
	if (rn != NULL && (rn->rn_flags & RNF_ROOT))
		rn = NULL;

	return (rn);
}

/*
 * Lookup the AF_INET/AF_INET6 non-scoped default route.
 */
static struct radix_node *
node_lookup_default(int af)
{
	struct radix_node_head *rnh;

	VERIFY(af == AF_INET || af == AF_INET6);
	rnh = rt_tables[af];

	return (af == AF_INET ? rnh->rnh_lookup(&sin_def, NULL, rnh) :
	    rnh->rnh_lookup(&sin6_def, NULL, rnh));
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
 * interface.  This is made possible by storing the scope ID value into the
 * radix key, thus making each route entry unique.  These scoped entries
 * exist along with the regular, non-scoped entries in the same radix tree
 * for a given address family (AF_INET/AF_INET6); the scope logically
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
	boolean_t dontcare;
	int af = dst->sa_family;
	struct sockaddr_storage dst_ss, mask_ss;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	if (!lookup_only)
		netmask = NULL;

	/*
	 * Non-scoped route lookup.
	 */
#if INET6
	if ((af != AF_INET && af != AF_INET6) ||
	    (af == AF_INET && !ip_doscopedroute) ||
	    (af == AF_INET6 && !ip6_doscopedroute)) {
#else
	if (af != AF_INET || !ip_doscopedroute) {
#endif /* !INET6 */
		rn = rnh->rnh_matchaddr(dst, rnh);

		/*
		 * Don't return a root node; also, rnh_matchaddr callback
		 * would have done the necessary work to clear RTPRF_OURS
		 * for certain protocol families.
		 */
		if (rn != NULL && (rn->rn_flags & RNF_ROOT))
			rn = NULL;
		if (rn != NULL) {
			RT_LOCK_SPIN(RT(rn));
			if (!(RT(rn)->rt_flags & RTF_CONDEMNED)) {
				RT_ADDREF_LOCKED(RT(rn));
				RT_UNLOCK(RT(rn));
			} else {
				RT_UNLOCK(RT(rn));
				rn = NULL;
			}
		}
		return (RT(rn));
	}

	/* Transform dst/netmask into the internal routing table form */
	dst = sa_copy(dst, &dst_ss, &ifscope);
	if (netmask != NULL)
		netmask = ma_copy(af, netmask, &mask_ss, ifscope);
	dontcare = (ifscope == IFSCOPE_NONE);

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
	 * any reason, there is no primary interface, ifscope will be
	 * set to IFSCOPE_NONE; if the above lookup resulted in a route,
	 * we'll do a more-specific search below, scoped to the interface
	 * of that route.
	 */
	if (dontcare)
		ifscope = get_primary_ifscope(af);

	/*
	 * Keep the original result if either of the following is true:
	 *
	 *   1) The interface portion of the route has the same interface
	 *	index as the scope value and it is marked with RTF_IFSCOPE.
	 *   2) The route uses the loopback interface, in which case the
	 *	destination (host/net) is local/loopback.
	 *
	 * Otherwise, do a more specified search using the scope;
	 * we're holding rnh_lock now, so rt_ifp should not change.
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
	    ((SA_DEFAULT(rt_key(RT(rn))) && !SA_DEFAULT(rt_key(RT(rn0)))) ||
	    (!RT_HOST(rn) && RT_HOST(rn0)))))
		rn = rn0;

	/*
	 * If we still don't have a route, use the non-scoped default
	 * route as long as the interface portion satistifes the scope.
	 */
	if (rn == NULL && (rn = node_lookup_default(af)) != NULL &&
	    RT(rn)->rt_ifp->if_index != ifscope)
		rn = NULL;

	if (rn != NULL) {
		/*
		 * Manually clear RTPRF_OURS using rt_validate() and
		 * bump up the reference count after, and not before;
		 * we only get here for AF_INET/AF_INET6.  node_lookup()
		 * has done the check against RNF_ROOT, so we can be sure
		 * that we're not returning a root node here.
		 */
		RT_LOCK_SPIN(RT(rn));
		if (rt_validate(RT(rn))) {
			RT_ADDREF_LOCKED(RT(rn));
			RT_UNLOCK(RT(rn));
		} else {
			RT_UNLOCK(RT(rn));
			rn = NULL;
		}
	}

	return (RT(rn));
}

boolean_t
rt_validate(struct rtentry *rt)
{
	RT_LOCK_ASSERT_HELD(rt);

	if ((rt->rt_flags & (RTF_UP | RTF_CONDEMNED)) == RTF_UP) {
		int af = rt_key(rt)->sa_family;

		if (af == AF_INET)
			(void) in_validate(RN(rt));
		else if (af == AF_INET6)
			(void) in6_validate(RN(rt));
	} else {
		rt = NULL;
	}

	return (rt != NULL);
}

/*
 * Set up a routing table entry, normally
 * for an interface.
 */
int
rtinit(struct ifaddr *ifa, int cmd, int flags)
{
	int error;
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);
	error = rtinit_locked(ifa, cmd, flags);
	lck_mtx_unlock(rnh_lock);
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
	u_int32_t ifa_flags;
	int error;

	/*
	 * Holding rnh_lock here prevents the possibility of ifa from
	 * changing (e.g. in_ifinit), so it is safe to access its
	 * ifa_{dst}addr (here and down below) without locking.
	 */
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
		rt = rtalloc1_locked(dst, 0, 0);
		if (rt) {
			/*
			 * Ok so we found the rtentry. it has an extra reference
			 * for us at this stage. we won't need that so
			 * lop that off now.
			 */
			RT_LOCK_SPIN(rt);
			if (rt->rt_ifa != ifa) {
				RT_REMREF_LOCKED(rt);
				RT_UNLOCK(rt);
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
			} else {
				RT_REMREF_LOCKED(rt);
				RT_UNLOCK(rt);
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
			lck_mtx_unlock(rnh_lock);
			return (flags & RTF_HOST ? EHOSTUNREACH
							: ENETUNREACH);
		}
#endif
	}
	/*
	 * Do the actual request
	 */
	IFA_LOCK_SPIN(ifa);
	ifa_flags = ifa->ifa_flags;
	IFA_UNLOCK(ifa);
	error = rtrequest_locked(cmd, dst, ifa->ifa_addr, ifa->ifa_netmask,
			flags | ifa_flags, &nrt);
	if (m)
		(void) m_free(m);
	/*
	 * If we are deleting, and we found an entry, then
	 * it's been removed from the tree.. now throw it away.
	 */
	if (cmd == RTM_DELETE && error == 0 && (rt = nrt)) {
		/*
		 * notify any listening routing agents of the change
		 */
		RT_LOCK(rt);
		rt_newaddrmsg(cmd, ifa, error, nrt);
		if (use_routegenid)
			routegenid_update();
		RT_UNLOCK(rt);
		rtfree_locked(rt);
	}

	/*
	 * We are adding, and we have a returned routing entry.
	 * We need to sanity check the result.
	 */
	if (cmd == RTM_ADD && error == 0 && (rt = nrt)) {
		RT_LOCK(rt);
		/*
		 * If it came back with an unexpected interface, then it must
		 * have already existed or something. (XXX)
		 */
		if (rt->rt_ifa != ifa) {
			void (*ifa_rtrequest)
			    (int, struct rtentry *, struct sockaddr *);

			if (!(rt->rt_ifa->ifa_ifp->if_flags &
			    (IFF_POINTOPOINT|IFF_LOOPBACK)))
				printf("rtinit: wrong ifa (%p) was (%p)\n",
				    ifa, rt->rt_ifa);
			/*
			 * Ask that the protocol in question
			 * remove anything it has associated with
			 * this route and ifaddr.
			 */
			IFA_LOCK_SPIN(rt->rt_ifa);
			ifa_rtrequest = rt->rt_ifa->ifa_rtrequest;
			IFA_UNLOCK(rt->rt_ifa);
			if (ifa_rtrequest != NULL)
				ifa_rtrequest(RTM_DELETE, rt, SA(0));
			/*
			 * Set the route's ifa.
			 */
			rtsetifa(rt, ifa);

			if (rt->rt_ifp != ifa->ifa_ifp) {
				/*
				 * Purge any link-layer info caching.
				 */
				if (rt->rt_llinfo_purge != NULL)
					rt->rt_llinfo_purge(rt);
				/*
				 * Adjust route ref count for the interfaces.
				 */
				if (rt->rt_if_ref_fn != NULL) {
					rt->rt_if_ref_fn(ifa->ifa_ifp, 1);
					rt->rt_if_ref_fn(rt->rt_ifp, -1);
				}
			}

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
			IFA_LOCK_SPIN(ifa);
			ifa_rtrequest = ifa->ifa_rtrequest;
			IFA_UNLOCK(ifa);
			if (ifa_rtrequest != NULL)
				ifa_rtrequest(RTM_ADD, rt, SA(0));
		}
		/*
		 * notify any listenning routing agents of the change
		 */
		rt_newaddrmsg(cmd, ifa, error, nrt);
		if (use_routegenid)
			routegenid_update();
		/*
		 * We just wanted to add it; we don't actually need a
		 * reference.  This will result in a route that's added
		 * to the routing table without a reference count.  The
		 * RTM_DELETE code will do the necessary step to adjust
		 * the reference count at deletion time.
		 */
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
	}
	return (error);
}

u_int64_t
rt_expiry(struct rtentry *rt, u_int64_t base, u_int32_t delta)
{
	u_int64_t retval;

	/*
	 * If the interface of the route doesn't demand aggressive draining,
	 * return the expiration time based on the caller-supplied delta.
	 * Otherwise use the more aggressive route expiration delta (or
	 * the caller-supplied delta, whichever is less.)
	 */
	if (rt->rt_ifp == NULL || rt->rt_ifp->if_want_aggressive_drain == 0)
		retval = base + delta;
	else
		retval = base + MIN(rt_if_idle_expire_timeout, delta);

	return (retval);
}

void
rt_set_idleref(struct rtentry *rt)
{
	RT_LOCK_ASSERT_HELD(rt);

	rt_clear_idleref(rt);
	rt->rt_if_ref_fn = rte_if_ref;
	rt->rt_if_ref_fn(rt->rt_ifp, 1);
	rt->rt_flags |= RTF_IFREF;
}

void
rt_clear_idleref(struct rtentry *rt)
{
	RT_LOCK_ASSERT_HELD(rt);

	if (rt->rt_if_ref_fn != NULL) {
		rt->rt_if_ref_fn(rt->rt_ifp, -1);
		rt->rt_flags &= ~RTF_IFREF;
		rt->rt_if_ref_fn = NULL;
	}
}

void
rt_set_proxy(struct rtentry *rt, boolean_t set)
{
	lck_mtx_lock(rnh_lock);
	RT_LOCK(rt);
	/*
	 * Search for any cloned routes which might have
	 * been formed from this node, and delete them.
	 */
	if (rt->rt_flags & (RTF_CLONING | RTF_PRCLONING)) {
		struct radix_node_head *rnh = rt_tables[rt_key(rt)->sa_family];

		if (set)
			rt->rt_flags |= RTF_PROXY;
		else
			rt->rt_flags &= ~RTF_PROXY;

		RT_UNLOCK(rt);
		if (rnh != NULL && rt_mask(rt)) {
			rnh->rnh_walktree_from(rnh, rt_key(rt), rt_mask(rt),
			    rt_fixdelete, rt);
		}
	} else {
		RT_UNLOCK(rt);
	}
	lck_mtx_unlock(rnh_lock);
}

static void
rte_lock_init(struct rtentry *rt)
{
	lck_mtx_init(&rt->rt_lock, rte_mtx_grp, rte_mtx_attr);
}

static void
rte_lock_destroy(struct rtentry *rt)
{
	RT_LOCK_ASSERT_NOTHELD(rt);
	lck_mtx_destroy(&rt->rt_lock, rte_mtx_grp);
}

void
rt_lock(struct rtentry *rt, boolean_t spin)
{
	RT_LOCK_ASSERT_NOTHELD(rt);
	if (spin)
		lck_mtx_lock_spin(&rt->rt_lock);
	else
		lck_mtx_lock(&rt->rt_lock);
	if (rte_debug & RTD_DEBUG)
		rte_lock_debug((struct rtentry_dbg *)rt);
}

void
rt_unlock(struct rtentry *rt)
{
	RT_LOCK_ASSERT_HELD(rt);
	if (rte_debug & RTD_DEBUG)
		rte_unlock_debug((struct rtentry_dbg *)rt);
	lck_mtx_unlock(&rt->rt_lock);

}

static inline void
rte_lock_debug(struct rtentry_dbg *rte)
{
	uint32_t idx;

	idx = atomic_add_32_ov(&rte->rtd_lock_cnt, 1) % CTRACE_HIST_SIZE;
	if (rte_debug & RTD_TRACE)
		ctrace_record(&rte->rtd_lock[idx]);
}

static inline void
rte_unlock_debug(struct rtentry_dbg *rte)
{
	uint32_t idx;

	idx = atomic_add_32_ov(&rte->rtd_unlock_cnt, 1) % CTRACE_HIST_SIZE;
	if (rte_debug & RTD_TRACE)
		ctrace_record(&rte->rtd_unlock[idx]);
}

static struct rtentry *
rte_alloc(void)
{
	if (rte_debug & RTD_DEBUG)
		return (rte_alloc_debug());

	return ((struct rtentry *)zalloc(rte_zone));
}

static void
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

static void
rte_if_ref(struct ifnet *ifp, int cnt)
{
	struct kev_msg ev_msg;
	struct net_event_data ev_data;
	uint32_t old;

	/* Force cnt to 1 increment/decrement */
	if (cnt < -1 || cnt > 1)
		panic("%s: invalid count argument (%d)", __func__, cnt);

	old = atomic_add_32_ov(&ifp->if_route_refcnt, cnt);
	if (cnt < 0 && old == 0)
		panic("%s: ifp=%p negative route refcnt!", __func__, ifp);

	/*
	 * The following is done without first holding the ifnet lock,
	 * for performance reasons.  The relevant ifnet fields, with
	 * the exception of the if_idle_flags, are never changed
	 * during the lifetime of the ifnet.  The if_idle_flags
	 * may possibly be modified, so in the event that the value
	 * is stale because IFRF_IDLE_NOTIFY was cleared, we'd end up
	 * sending the event anyway.  This is harmless as it is just
	 * a notification to the monitoring agent in user space, and
	 * it is expected to check via SIOCGIFGETRTREFCNT again anyway.
	 */
	if ((ifp->if_idle_flags & IFRF_IDLE_NOTIFY) && cnt < 0 && old == 1) {
		bzero(&ev_msg, sizeof (ev_msg));
		bzero(&ev_data, sizeof (ev_data));

		ev_msg.vendor_code	= KEV_VENDOR_APPLE;
		ev_msg.kev_class	= KEV_NETWORK_CLASS;
		ev_msg.kev_subclass	= KEV_DL_SUBCLASS;
		ev_msg.event_code	= KEV_DL_IF_IDLE_ROUTE_REFCNT;

		strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);

		ev_data.if_family	= ifp->if_family;
		ev_data.if_unit		= ifp->if_unit;
		ev_msg.dv[0].data_length = sizeof (struct net_event_data);
		ev_msg.dv[0].data_ptr	= &ev_data;

		kev_post_msg(&ev_msg);
	}
}

static inline struct rtentry *
rte_alloc_debug(void)
{
	struct rtentry_dbg *rte;

	rte = ((struct rtentry_dbg *)zalloc(rte_zone));
	if (rte != NULL) {
		bzero(rte, sizeof (*rte));
		if (rte_debug & RTD_TRACE)
			ctrace_record(&rte->rtd_alloc);
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
	/* Preserve rt_lock to help catch use-after-free cases */
	bzero((caddr_t)p, offsetof(struct rtentry, rt_lock));

	rte->rtd_inuse = RTD_FREED;

	if (rte_debug & RTD_TRACE)
		ctrace_record(&rte->rtd_free);

	if (!(rte_debug & RTD_NO_FREE))
		zfree(rte_zone, p);
}

void
ctrace_record(ctrace_t *tr)
{
	tr->th = current_thread();
	bzero(tr->pc, sizeof (tr->pc));
	(void) OSBacktrace(tr->pc, CTRACE_STACK_SIZE);
}

__private_extern__ void
route_copyout(
	struct route *dst,
	const struct route *src,
	size_t length)
{
	/* Copy everything (rt, dst, flags) from ifnet */
	bcopy(src, dst, length);

	/* Hold one reference for the local copy of struct route */
	if (dst->ro_rt != NULL)
		RT_ADDREF(dst->ro_rt);
}

__private_extern__ void
route_copyin(
	struct route *src,
	struct route *dst,
	size_t length)
{
	/* No cached route in the ifnet? */
	if (dst->ro_rt == NULL) {
		/*
		 * Copy everything (rt, dst, flags) from ip_forward();
		 * the reference to the route was held at the time
		 * it was allocated and is kept intact.
		 */
		bcopy(src, dst, length);
	} else if (src->ro_rt != NULL) {
		/*
		 * If the same, update just the ro_flags and ditch the one
		 * in the local copy.  Else ditch the one that is currently
		 * cached, and cache the new route.
		 */
		if (dst->ro_rt == src->ro_rt) {
			dst->ro_flags = src->ro_flags;
			rtfree(src->ro_rt);
		} else {
			rtfree(dst->ro_rt);
			bcopy(src, dst, length);
		}
	}

	/* This function consumes the reference */
	src->ro_rt = NULL;
}

/*
 * route_to_gwroute will find the gateway route for a given route.
 *
 * If the route is down, look the route up again.
 * If the route goes through a gateway, get the route to the gateway.
 * If the gateway route is down, look it up again.
 * If the route is set to reject, verify it hasn't expired.
 *
 * If the returned route is non-NULL, the caller is responsible for
 * releasing the reference and unlocking the route.
 */
#define senderr(e) { error = (e); goto bad; }
errno_t
route_to_gwroute(const struct sockaddr *net_dest, struct rtentry *hint0,
     struct rtentry **out_route)
{
	uint64_t timenow;
	struct rtentry *rt = hint0, *hint = hint0;
	errno_t error = 0;
	unsigned int ifindex;
	boolean_t gwroute;

	*out_route = NULL;

	if (rt == NULL)
		return (0);

	/*
	 * Next hop determination.  Because we may involve the gateway route
	 * in addition to the original route, locking is rather complicated.
	 * The general concept is that regardless of whether the route points
	 * to the original route or to the gateway route, this routine takes
	 * an extra reference on such a route.  This extra reference will be
	 * released at the end.
	 *
	 * Care must be taken to ensure that the "hint0" route never gets freed
	 * via rtfree(), since the caller may have stored it inside a struct
	 * route with a reference held for that placeholder.
	 */
	RT_LOCK_SPIN(rt);
	ifindex = rt->rt_ifp->if_index;
	RT_ADDREF_LOCKED(rt);
	if (!(rt->rt_flags & RTF_UP)) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		/* route is down, find a new one */
		hint = rt = rtalloc1_scoped((struct sockaddr *)
		    (size_t)net_dest, 1, 0, ifindex);
		if (hint != NULL) {
			RT_LOCK_SPIN(rt);
			ifindex = rt->rt_ifp->if_index;
		} else {
			senderr(EHOSTUNREACH);
		}
	}

	/*
	 * We have a reference to "rt" by now; it will either
	 * be released or freed at the end of this routine.
	 */
	RT_LOCK_ASSERT_HELD(rt);
	if ((gwroute = (rt->rt_flags & RTF_GATEWAY))) {
		struct rtentry *gwrt = rt->rt_gwroute;
		struct sockaddr_storage ss;
		struct sockaddr *gw = (struct sockaddr *)&ss;

		VERIFY(rt == hint);
		RT_ADDREF_LOCKED(hint);

		/* If there's no gateway rt, look it up */
		if (gwrt == NULL) {
			bcopy(rt->rt_gateway, gw, MIN(sizeof (ss),
			    rt->rt_gateway->sa_len));
			RT_UNLOCK(rt);
			goto lookup;
		}
		/* Become a regular mutex */
		RT_CONVERT_LOCK(rt);

		/*
		 * Take gwrt's lock while holding route's lock;
		 * this is okay since gwrt never points back
		 * to "rt", so no lock ordering issues.
		 */
		RT_LOCK_SPIN(gwrt);
		if (!(gwrt->rt_flags & RTF_UP)) {
			rt->rt_gwroute = NULL;
			RT_UNLOCK(gwrt);
			bcopy(rt->rt_gateway, gw, MIN(sizeof (ss),
			    rt->rt_gateway->sa_len));
			RT_UNLOCK(rt);
			rtfree(gwrt);
lookup:
			lck_mtx_lock(rnh_lock);
			gwrt = rtalloc1_scoped_locked(gw, 1, 0, ifindex);

			RT_LOCK(rt);
			/*
			 * Bail out if the route is down, no route
			 * to gateway, circular route, or if the
			 * gateway portion of "rt" has changed.
			 */
			if (!(rt->rt_flags & RTF_UP) || gwrt == NULL ||
			    gwrt == rt || !equal(gw, rt->rt_gateway)) {
				if (gwrt == rt) {
					RT_REMREF_LOCKED(gwrt);
					gwrt = NULL;
				}
				VERIFY(rt == hint);
				RT_REMREF_LOCKED(hint);
				hint = NULL;
				RT_UNLOCK(rt);
				if (gwrt != NULL)
					rtfree_locked(gwrt);
				lck_mtx_unlock(rnh_lock);
				senderr(EHOSTUNREACH);
			}
			VERIFY(gwrt != NULL);
			/*
			 * Set gateway route; callee adds ref to gwrt;
			 * gwrt has an extra ref from rtalloc1() for
			 * this routine.
			 */
			rt_set_gwroute(rt, rt_key(rt), gwrt);
			VERIFY(rt == hint);
			RT_REMREF_LOCKED(rt);	/* hint still holds a refcnt */
			RT_UNLOCK(rt);
			lck_mtx_unlock(rnh_lock);
			rt = gwrt;
		} else {
			RT_ADDREF_LOCKED(gwrt);
			RT_UNLOCK(gwrt);
			VERIFY(rt == hint);
			RT_REMREF_LOCKED(rt);	/* hint still holds a refcnt */
			RT_UNLOCK(rt);
			rt = gwrt;
		}
		VERIFY(rt == gwrt && rt != hint);

		/*
		 * This is an opportunity to revalidate the parent route's
		 * rt_gwroute, in case it now points to a dead route entry.
		 * Parent route won't go away since the clone (hint) holds
		 * a reference to it.  rt == gwrt.
		 */
		RT_LOCK_SPIN(hint);
		if ((hint->rt_flags & (RTF_WASCLONED | RTF_UP)) ==
		    (RTF_WASCLONED | RTF_UP)) {
			struct rtentry *prt = hint->rt_parent;
			VERIFY(prt != NULL);

			RT_CONVERT_LOCK(hint);
			RT_ADDREF(prt);
			RT_UNLOCK(hint);
			rt_revalidate_gwroute(prt, rt);
			RT_REMREF(prt);
		} else {
			RT_UNLOCK(hint);
		}

		/* Clean up "hint" now; see notes above regarding hint0 */
		if (hint == hint0)
			RT_REMREF(hint);
		else
			rtfree(hint);
		hint = NULL;

		/* rt == gwrt; if it is now down, give up */
		RT_LOCK_SPIN(rt);
		if (!(rt->rt_flags & RTF_UP)) {
			RT_UNLOCK(rt);
			senderr(EHOSTUNREACH);
		}
	}

	if (rt->rt_flags & RTF_REJECT) {
		VERIFY(rt->rt_expire == 0 || rt->rt_rmx.rmx_expire != 0);
		VERIFY(rt->rt_expire != 0 || rt->rt_rmx.rmx_expire == 0);
		timenow = net_uptime();
		if (rt->rt_expire == 0 || timenow < rt->rt_expire) {
			RT_UNLOCK(rt);
			senderr(!gwroute ? EHOSTDOWN : EHOSTUNREACH);
		}
	}

	/* Become a regular mutex */
	RT_CONVERT_LOCK(rt);

	/* Caller is responsible for cleaning up "rt" */
	*out_route = rt;
	return (0);

bad:
	/* Clean up route (either it is "rt" or "gwrt") */
	if (rt != NULL) {
		RT_LOCK_SPIN(rt);
		if (rt == hint0) {
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
		} else {
			RT_UNLOCK(rt);
			rtfree(rt);
		}
	}
	return (error);
}
#undef senderr

void
rt_revalidate_gwroute(struct rtentry *rt, struct rtentry *gwrt)
{
	VERIFY(rt->rt_flags & (RTF_CLONING | RTF_PRCLONING));
	VERIFY(gwrt != NULL);

	RT_LOCK_SPIN(rt);
	if ((rt->rt_flags & (RTF_GATEWAY | RTF_UP)) == (RTF_GATEWAY | RTF_UP) &&
	    rt->rt_ifp == gwrt->rt_ifp && rt->rt_gateway->sa_family ==
	    rt_key(gwrt)->sa_family && (rt->rt_gwroute == NULL ||
	    !(rt->rt_gwroute->rt_flags & RTF_UP))) {
		boolean_t isequal;

		if (rt->rt_gateway->sa_family == AF_INET ||
		    rt->rt_gateway->sa_family == AF_INET6) {
			struct sockaddr_storage key_ss, gw_ss;
			/*
			 * We need to compare rt_key and rt_gateway; create
			 * local copies to get rid of any ifscope association.
			 */
			(void) sa_copy(rt_key(gwrt), &key_ss, NULL);
			(void) sa_copy(rt->rt_gateway, &gw_ss, NULL);

			isequal = equal(SA(&key_ss), SA(&gw_ss));
		} else {
			isequal = equal(rt_key(gwrt), rt->rt_gateway);
		}

		/* If they are the same, update gwrt */
		if (isequal) {
			RT_UNLOCK(rt);
			lck_mtx_lock(rnh_lock);
			RT_LOCK(rt);
			rt_set_gwroute(rt, rt_key(rt), gwrt);
			RT_UNLOCK(rt);
			lck_mtx_unlock(rnh_lock);
		} else {
			RT_UNLOCK(rt);
		}
	} else {
		RT_UNLOCK(rt);
	}
}
