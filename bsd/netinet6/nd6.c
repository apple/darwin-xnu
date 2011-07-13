/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/nd6.c,v 1.20 2002/08/02 20:49:14 rwatson Exp $	*/
/*	$KAME: nd6.c,v 1.144 2001/05/24 07:44:00 itojun Exp $	*/

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
 * XXX
 * KAME 970409 note:
 * BSD/OS version heavily modifies this code, related to llinfo.
 * Since we don't have BSD/OS version of net/route.c in our hand,
 * I left the code mostly as it was in 970310.  -- itojun
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/proc.h>
#include <sys/mcache.h>

#include <kern/queue.h>
#include <kern/zalloc.h>

#define DONT_WARN_OBSOLETE
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llreach.h>
#include <net/route.h>
#include <net/dlil.h>
#include <net/ntstat.h>

#include <netinet/in.h>
#include <netinet/in_arp.h>
#include <netinet/if_ether.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>
#include <netinet/icmp6.h>

#include "loop.h"

#include <net/net_osdep.h>

#define ND6_SLOWTIMER_INTERVAL (60 * 60) /* 1 hour */
#define ND6_RECALC_REACHTM_INTERVAL (60 * 120) /* 2 hours */

#define	SA(p) ((struct sockaddr *)(p))
#define SIN6(s) ((struct sockaddr_in6 *)s)
#define SDL(s) ((struct sockaddr_dl *)s)
#define	equal(a1, a2) (bcmp((caddr_t)(a1), (caddr_t)(a2), (a1)->sa_len) == 0)

/* timer values */
int	nd6_prune	= 1;	/* walk list every 1 seconds */
int	nd6_delay	= 5;	/* delay first probe time 5 second */
int	nd6_umaxtries	= 3;	/* maximum unicast query */
int	nd6_mmaxtries	= 3;	/* maximum multicast query */
int	nd6_useloopback = 1;	/* use loopback interface for local traffic */
int	nd6_gctimer	= (60 * 60 * 24); /* 1 day: garbage collection timer */

/* preventing too many loops in ND option parsing */
int nd6_maxndopt = 10;	/* max # of ND options allowed */

int nd6_maxnudhint = 0;	/* max # of subsequent upper layer hints */
int nd6_maxqueuelen = 1; /* max # of packets cached in unresolved ND entries */

#if ND6_DEBUG
int nd6_debug = 1;
#else
int nd6_debug = 0;
#endif

static int nd6_is_new_addr_neighbor (struct sockaddr_in6 *, struct ifnet *);

/* for debugging? */
static int nd6_inuse, nd6_allocated;

/*
 * Synchronization notes:
 *
 * The global list of ND entries are stored in llinfo_nd6; an entry
 * gets inserted into the list when the route is created and gets
 * removed from the list when it is deleted; this is done as part
 * of RTM_ADD/RTM_RESOLVE/RTM_DELETE in nd6_rtrequest().
 *
 * Because rnh_lock and rt_lock for the entry are held during those
 * operations, the same locks (and thus lock ordering) must be used
 * elsewhere to access the relevant data structure fields:
 *
 * ln_next, ln_prev, ln_rt
 *
 *	- Routing lock (rnh_lock)
 *
 * ln_hold, ln_asked, ln_expire, ln_state, ln_router, ln_byhint, ln_flags,
 * ln_llreach, ln_lastused
 *
 *	- Routing entry lock (rt_lock)
 *
 * Due to the dependency on rt_lock, llinfo_nd6 has the same lifetime
 * as the route entry itself.  When a route is deleted (RTM_DELETE),
 * it is simply removed from the global list but the memory is not
 * freed until the route itself is freed.
 */
struct llinfo_nd6 llinfo_nd6 = {
	&llinfo_nd6, &llinfo_nd6, NULL, NULL, 0, 0, 0, 0, 0, 0, NULL, 0
};

/* Protected by nd_if_rwlock */
size_t nd_ifinfo_indexlim = 32; /* increased for 5589193 */
struct nd_ifinfo *nd_ifinfo = NULL;

static lck_grp_attr_t	*nd_if_rwlock_grp_attr;
static lck_grp_t	*nd_if_rwlock_grp;
static lck_attr_t	*nd_if_rwlock_attr;
lck_rw_t		*nd_if_rwlock;

/* Protected by nd6_mutex */
struct nd_drhead nd_defrouter;
struct nd_prhead nd_prefix = { 0 };

/* Serialization variables for nd6_drain() */
static boolean_t nd6_drain_busy;
static void *nd6_drain_waitchan = &nd6_drain_busy;
static int nd6_drain_waiters = 0;

int nd6_recalc_reachtm_interval = ND6_RECALC_REACHTM_INTERVAL;
static struct sockaddr_in6 all1_sa;

static int regen_tmpaddr(struct in6_ifaddr *);
extern lck_mtx_t *nd6_mutex;

static void nd6_slowtimo(void *ignored_arg);
static struct llinfo_nd6 *nd6_llinfo_alloc(void);
static void nd6_llinfo_free(void *);
static void nd6_llinfo_purge(struct rtentry *);
static void nd6_llinfo_get_ri(struct rtentry *, struct rt_reach_info *);

static void nd6_siocgdrlst(void *, int);
static void nd6_siocgprlst(void *, int);

/*
 * Insertion and removal from llinfo_nd6 must be done with rnh_lock held.
 */
#define LN_DEQUEUE(_ln) do {						\
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);			\
	RT_LOCK_ASSERT_HELD((_ln)->ln_rt);				\
	(_ln)->ln_next->ln_prev = (_ln)->ln_prev;			\
	(_ln)->ln_prev->ln_next = (_ln)->ln_next;			\
	(_ln)->ln_prev = (_ln)->ln_next = NULL;				\
	(_ln)->ln_flags &= ~ND6_LNF_IN_USE;				\
} while (0)

#define LN_INSERTHEAD(_ln) do {						\
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);			\
	RT_LOCK_ASSERT_HELD((_ln)->ln_rt);				\
	(_ln)->ln_next = llinfo_nd6.ln_next;				\
	llinfo_nd6.ln_next = (_ln);					\
	(_ln)->ln_prev = &llinfo_nd6;					\
	(_ln)->ln_next->ln_prev = (_ln);				\
	(_ln)->ln_flags |= ND6_LNF_IN_USE;				\
} while (0)

static struct zone *llinfo_nd6_zone;
#define	LLINFO_ND6_ZONE_MAX	256		/* maximum elements in zone */
#define	LLINFO_ND6_ZONE_NAME	"llinfo_nd6"	/* name for zone */

void
nd6_init()
{
	static int nd6_init_done = 0;
	int i;

	if (nd6_init_done) {
		log(LOG_NOTICE, "nd6_init called more than once (ignored)\n");
		return;
	}

	all1_sa.sin6_family = AF_INET6;
	all1_sa.sin6_len = sizeof(struct sockaddr_in6);
	for (i = 0; i < sizeof(all1_sa.sin6_addr); i++)
		all1_sa.sin6_addr.s6_addr[i] = 0xff;

	/* initialization of the default router list */
	TAILQ_INIT(&nd_defrouter);

	nd_if_rwlock_grp_attr = lck_grp_attr_alloc_init();
	nd_if_rwlock_grp = lck_grp_alloc_init("nd_if_rwlock",
	    nd_if_rwlock_grp_attr);
	nd_if_rwlock_attr = lck_attr_alloc_init();
	nd_if_rwlock = lck_rw_alloc_init(nd_if_rwlock_grp, nd_if_rwlock_attr);

	llinfo_nd6_zone = zinit(sizeof (struct llinfo_nd6),
	    LLINFO_ND6_ZONE_MAX * sizeof (struct llinfo_nd6), 0,
	    LLINFO_ND6_ZONE_NAME);
	if (llinfo_nd6_zone == NULL)
		panic("%s: failed allocating llinfo_nd6_zone", __func__);

	zone_change(llinfo_nd6_zone, Z_EXPAND, TRUE);
	zone_change(llinfo_nd6_zone, Z_CALLERACCT, FALSE);

	nd6_nbr_init();
	nd6_rtr_init();

	nd6_init_done = 1;

	/* start timer */
	timeout(nd6_slowtimo, (caddr_t)0, ND6_SLOWTIMER_INTERVAL * hz);
}

static struct llinfo_nd6 *
nd6_llinfo_alloc(void)
{
	return (zalloc(llinfo_nd6_zone));
}

static void
nd6_llinfo_free(void *arg)
{
	struct llinfo_nd6 *ln = arg;

	if (ln->ln_next != NULL || ln->ln_prev != NULL) {
		panic("%s: trying to free %p when it is in use", __func__, ln);
		/* NOTREACHED */
	}

	/* Just in case there's anything there, free it */
	if (ln->ln_hold != NULL) {
		m_freem(ln->ln_hold);
		ln->ln_hold = NULL;
	}

	/* Purge any link-layer info caching */
	VERIFY(ln->ln_rt->rt_llinfo == ln);
	if (ln->ln_rt->rt_llinfo_purge != NULL)
		ln->ln_rt->rt_llinfo_purge(ln->ln_rt);

	zfree(llinfo_nd6_zone, ln);
}

static void
nd6_llinfo_purge(struct rtentry *rt)
{
	struct llinfo_nd6 *ln = rt->rt_llinfo;

	RT_LOCK_ASSERT_HELD(rt);
	VERIFY(rt->rt_llinfo_purge == nd6_llinfo_purge && ln != NULL);

	if (ln->ln_llreach != NULL) {
		RT_CONVERT_LOCK(rt);
		ifnet_llreach_free(ln->ln_llreach);
		ln->ln_llreach = NULL;
	}
	ln->ln_lastused = 0;
}

static void
nd6_llinfo_get_ri(struct rtentry *rt, struct rt_reach_info *ri)
{
	struct llinfo_nd6 *ln = rt->rt_llinfo;
	struct if_llreach *lr = ln->ln_llreach;

	if (lr == NULL) {
		bzero(ri, sizeof (*ri));
	} else {
		IFLR_LOCK(lr);
		/* Export to rt_reach_info structure */
		ifnet_lr2ri(lr, ri);
		/* Export ND6 send expiration time */
		ri->ri_snd_expire = ifnet_llreach_up2cal(lr, ln->ln_lastused);
		IFLR_UNLOCK(lr);
	}
}

int
nd6_ifattach(struct ifnet *ifp)
{

	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 */
	lck_rw_lock_exclusive(nd_if_rwlock);
	if (nd_ifinfo == NULL || if_index >= nd_ifinfo_indexlim) {
		size_t n;
		caddr_t q;
		size_t newlim = nd_ifinfo_indexlim;

		while (if_index >= newlim)
			newlim <<= 1;

		/* grow nd_ifinfo */
		n = newlim * sizeof(struct nd_ifinfo);
		q = (caddr_t)_MALLOC(n, M_IP6NDP, M_WAITOK);
		if (q == NULL) {
			lck_rw_done(nd_if_rwlock);
			return ENOBUFS;
		}
		bzero(q, n);
		nd_ifinfo_indexlim = newlim;
		if (nd_ifinfo) {
			bcopy((caddr_t)nd_ifinfo, q, n/2);
			/*
			 * We might want to pattern fill the old
			 * array to catch use-after-free cases.
			 */
			FREE((caddr_t)nd_ifinfo, M_IP6NDP);
		}
		nd_ifinfo = (struct nd_ifinfo *)q;
	}
	lck_rw_done(nd_if_rwlock);

#define ND nd_ifinfo[ifp->if_index]

	/*
	 * Don't initialize if called twice.
	 * XXX: to detect this, we should choose a member that is never set
	 * before initialization of the ND structure itself.  We formaly used
	 * the linkmtu member, which was not suitable because it could be 
	 * initialized via "ifconfig mtu".
	 */
	lck_rw_lock_shared(nd_if_rwlock);
	if (ND.basereachable) {
		lck_rw_done(nd_if_rwlock);
		return 0;
	}
	ND.linkmtu = ifp->if_mtu;
	ND.chlim = IPV6_DEFHLIM;
	ND.basereachable = REACHABLE_TIME;
	ND.reachable = ND_COMPUTE_RTIME(ND.basereachable);
	ND.retrans = RETRANS_TIMER;
	ND.flags = ND6_IFF_PERFORMNUD;
	lck_rw_done(nd_if_rwlock);
	nd6_setmtu(ifp);
#undef ND
	
	return 0;
}

/*
 * Reset ND level link MTU. This function is called when the physical MTU
 * changes, which means we might have to adjust the ND level MTU.
 */
void
nd6_setmtu(struct ifnet *ifp)
{
	struct nd_ifinfo *ndi;
	u_int32_t oldmaxmtu, maxmtu;

	/*
	 * Make sure IPv6 is enabled for the interface first, 
	 * because this can be called directly from SIOCSIFMTU for IPv4
	 */
	lck_rw_lock_shared(nd_if_rwlock);
	if (ifp->if_index >= nd_ifinfo_indexlim) {
		lck_rw_done(nd_if_rwlock);
		return; /* we're  out of bound for nd_ifinfo */
	}

	ndi = &nd_ifinfo[ifp->if_index];
	oldmaxmtu = ndi->maxmtu;

	/*
	 * The ND level maxmtu is somewhat redundant to the interface MTU
	 * and is an implementation artifact of KAME.  Instead of hard-
	 * limiting the maxmtu based on the interface type here, we simply
	 * take the if_mtu value since SIOCSIFMTU would have taken care of
	 * the sanity checks related to the maximum MTU allowed for the
	 * interface (a value that is known only by the interface layer),
	 * by sending the request down via ifnet_ioctl().  The use of the
	 * ND level maxmtu and linkmtu are done via IN6_LINKMTU() which
	 * does further checking against if_mtu.
	 */
	maxmtu = ndi->maxmtu = ifp->if_mtu;

	/*
	* Decreasing the interface MTU under IPV6 minimum MTU may cause
	* undesirable situation.  We thus notify the operator of the change
	* explicitly.  The check for oldmaxmtu is necessary to restrict the
	* log to the case of changing the MTU, not initializing it.
	*/
	if (oldmaxmtu >= IPV6_MMTU && ndi->maxmtu < IPV6_MMTU) {
		log(LOG_NOTICE, "nd6_setmtu: "
		    "new link MTU on %s%d (%u) is too small for IPv6\n",
		    ifp->if_name, ifp->if_unit, (uint32_t)ndi->maxmtu);
	}
	ndi->linkmtu = ifp->if_mtu;
	lck_rw_done(nd_if_rwlock);

	/* also adjust in6_maxmtu if necessary. */
	if (maxmtu > in6_maxmtu)
		in6_setmaxmtu();
}

void
nd6_option_init(
	void *opt,
	int icmp6len,
	union nd_opts *ndopts)
{
	bzero(ndopts, sizeof(*ndopts));
	ndopts->nd_opts_search = (struct nd_opt_hdr *)opt;
	ndopts->nd_opts_last
		= (struct nd_opt_hdr *)(((u_char *)opt) + icmp6len);

	if (icmp6len == 0) {
		ndopts->nd_opts_done = 1;
		ndopts->nd_opts_search = NULL;
	}
}

/*
 * Take one ND option.
 */
struct nd_opt_hdr *
nd6_option(
	union nd_opts *ndopts)
{
	struct nd_opt_hdr *nd_opt;
	int olen;

	if (!ndopts)
		panic("ndopts == NULL in nd6_option\n");
	if (!ndopts->nd_opts_last)
		panic("uninitialized ndopts in nd6_option\n");
	if (!ndopts->nd_opts_search)
		return NULL;
	if (ndopts->nd_opts_done)
		return NULL;

	nd_opt = ndopts->nd_opts_search;

	/* make sure nd_opt_len is inside the buffer */
	if ((caddr_t)&nd_opt->nd_opt_len >= (caddr_t)ndopts->nd_opts_last) {
		bzero(ndopts, sizeof(*ndopts));
		return NULL;
	}

	olen = nd_opt->nd_opt_len << 3;
	if (olen == 0) {
		/*
		 * Message validation requires that all included
		 * options have a length that is greater than zero.
		 */
		bzero(ndopts, sizeof(*ndopts));
		return NULL;
	}

	ndopts->nd_opts_search = (struct nd_opt_hdr *)((caddr_t)nd_opt + olen);
	if (ndopts->nd_opts_search > ndopts->nd_opts_last) {
		/* option overruns the end of buffer, invalid */
		bzero(ndopts, sizeof(*ndopts));
		return NULL;
	} else if (ndopts->nd_opts_search == ndopts->nd_opts_last) {
		/* reached the end of options chain */
		ndopts->nd_opts_done = 1;
		ndopts->nd_opts_search = NULL;
	}
	return nd_opt;
}

/*
 * Parse multiple ND options.
 * This function is much easier to use, for ND routines that do not need
 * multiple options of the same type.
 */
int
nd6_options(
	union nd_opts *ndopts)
{
	struct nd_opt_hdr *nd_opt;
	int i = 0;

	if (ndopts == NULL)
		panic("ndopts == NULL in nd6_options");
	if (ndopts->nd_opts_last == NULL)
		panic("uninitialized ndopts in nd6_options");
	if (ndopts->nd_opts_search == NULL)
		return 0;

	while (1) {
		nd_opt = nd6_option(ndopts);
		if (nd_opt == NULL && ndopts->nd_opts_last == NULL) {
			/*
			 * Message validation requires that all included
			 * options have a length that is greater than zero.
			 */
			icmp6stat.icp6s_nd_badopt++;
			bzero(ndopts, sizeof(*ndopts));
			return -1;
		}

		if (nd_opt == NULL)
			goto skip1;

		switch (nd_opt->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
		case ND_OPT_TARGET_LINKADDR:
		case ND_OPT_MTU:
		case ND_OPT_REDIRECTED_HEADER:
			if (ndopts->nd_opt_array[nd_opt->nd_opt_type]) {
				nd6log((LOG_INFO,
				    "duplicated ND6 option found (type=%d)\n",
				    nd_opt->nd_opt_type));
				/* XXX bark? */
			} else {
				ndopts->nd_opt_array[nd_opt->nd_opt_type]
					= nd_opt;
			}
			break;
		case ND_OPT_PREFIX_INFORMATION:
			if (ndopts->nd_opt_array[nd_opt->nd_opt_type] == 0) {
				ndopts->nd_opt_array[nd_opt->nd_opt_type]
					= nd_opt;
			}
			ndopts->nd_opts_pi_end =
				(struct nd_opt_prefix_info *)nd_opt;
			break;
		case ND_OPT_RDNSS:
		    	/* ignore */
		    	break;
		default:
			/*
			 * Unknown options must be silently ignored,
			 * to accomodate future extension to the protocol.
			 */
			nd6log((LOG_DEBUG,
			    "nd6_options: unsupported option %d - "
			    "option ignored\n", nd_opt->nd_opt_type));
		}

skip1:
		i++;
		if (i > nd6_maxndopt) {
			icmp6stat.icp6s_nd_toomanyopt++;
			nd6log((LOG_INFO, "too many loop in nd opt\n"));
			break;
		}

		if (ndopts->nd_opts_done)
			break;
	}

	return 0;
}

void
nd6_drain(__unused void	*ignored_arg)
{
	struct llinfo_nd6 *ln;
	struct nd_defrouter *dr;
	struct nd_prefix *pr;
	struct ifnet *ifp = NULL;
	struct in6_ifaddr *ia6, *nia6;
	struct in6_addrlifetime *lt6;
	struct timeval timenow;

	getmicrotime(&timenow);
again:
	/*
	 * The global list llinfo_nd6 is modified by nd6_request() and is
	 * therefore protected by rnh_lock.  For obvious reasons, we cannot
	 * hold rnh_lock across calls that might lead to code paths which
	 * attempt to acquire rnh_lock, else we deadlock.  Hence for such
	 * cases we drop rt_lock and rnh_lock, make the calls, and repeat the
	 * loop.  To ensure that we don't process the same entry more than
	 * once in a single timeout, we mark the "already-seen" entries with
	 * ND6_LNF_TIMER_SKIP flag.  At the end of the loop, we do a second
	 * pass thru the entries and clear the flag so they can be processed
	 * during the next timeout.
	 */
	lck_mtx_lock(rnh_lock);
	ln = llinfo_nd6.ln_next;
	while (ln != NULL && ln != &llinfo_nd6) {
		struct rtentry *rt;
		struct sockaddr_in6 *dst;
		struct llinfo_nd6 *next;

		/* ln_next/prev/rt is protected by rnh_lock */
		next = ln->ln_next;
		rt = ln->ln_rt;
		RT_LOCK(rt);

		/* We've seen this already; skip it */
		if (ln->ln_flags & ND6_LNF_TIMER_SKIP) {
			RT_UNLOCK(rt);
			ln = next;
			continue;
		}

		/* rt->rt_ifp should never be NULL */
		if ((ifp = rt->rt_ifp) == NULL) {
			panic("%s: ln(%p) rt(%p) rt_ifp == NULL", __func__,
			    ln, rt);
			/* NOTREACHED */
		}

		/* rt_llinfo must always be equal to ln */
		if ((struct llinfo_nd6 *)rt->rt_llinfo != ln) {
			panic("%s: rt_llinfo(%p) is not equal to ln(%p)",
			      __func__, rt->rt_llinfo, ln);
			/* NOTREACHED */
		}

		/* rt_key should never be NULL */
		dst = (struct sockaddr_in6 *)rt_key(rt);
		if (dst == NULL) {
			panic("%s: rt(%p) key is NULL ln(%p)", __func__,
			    rt, ln);
			/* NOTREACHED */
		}

		/* Set the flag in case we jump to "again" */
		ln->ln_flags |= ND6_LNF_TIMER_SKIP;

		if (ln->ln_expire > timenow.tv_sec) {
			RT_UNLOCK(rt);
			ln = next;
			continue;
		}

		/* Make a copy (we're using it read-only anyway) */
		lck_rw_lock_shared(nd_if_rwlock);
		if (ifp->if_index >= nd_ifinfo_indexlim) {
			lck_rw_done(nd_if_rwlock);
			RT_UNLOCK(rt);
			ln = next;
			continue;
		}
		lck_rw_done(nd_if_rwlock);

		RT_LOCK_ASSERT_HELD(rt);

		switch (ln->ln_state) {
		case ND6_LLINFO_INCOMPLETE:
			if (ln->ln_asked < nd6_mmaxtries) {
				ln->ln_asked++;
				lck_rw_lock_shared(nd_if_rwlock);
				ln->ln_expire = timenow.tv_sec +
				    nd_ifinfo[ifp->if_index].retrans / 1000;
				lck_rw_done(nd_if_rwlock);
				RT_ADDREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_ns_output(ifp, NULL, &dst->sin6_addr,
					ln, 0);
				RT_REMREF(rt);
			} else {
				struct mbuf *m = ln->ln_hold;
				ln->ln_hold = NULL;
				if (m != NULL) {
					/*
					 * Fake rcvif to make ICMP error
					 * more helpful in diagnosing
					 * for the receiver.
					 * XXX: should we consider
					 * older rcvif?
					 */
					m->m_pkthdr.rcvif = ifp;
					RT_UNLOCK(rt);
					lck_mtx_unlock(rnh_lock);
					icmp6_error(m, ICMP6_DST_UNREACH,
						    ICMP6_DST_UNREACH_ADDR, 0);
				} else {
					RT_UNLOCK(rt);
					lck_mtx_unlock(rnh_lock);
				}
				nd6_free(rt);
			}
			lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
			goto again;

		case ND6_LLINFO_REACHABLE:
			if (ln->ln_expire) {
				ln->ln_state = ND6_LLINFO_STALE;
				ln->ln_expire = rt_expiry(rt, timenow.tv_sec,
				    nd6_gctimer);
			}
			RT_UNLOCK(rt);
			break;

		case ND6_LLINFO_STALE:
		case ND6_LLINFO_PURGE:
			/* Garbage Collection(RFC 2461 5.3) */
			if (ln->ln_expire) {
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_free(rt);
				lck_mtx_assert(rnh_lock,
				    LCK_MTX_ASSERT_NOTOWNED);
				goto again;
			} else {
				RT_UNLOCK(rt);
			}
			break;

		case ND6_LLINFO_DELAY:
			lck_rw_lock_shared(nd_if_rwlock);
			if ((nd_ifinfo[ifp->if_index].flags &
			    ND6_IFF_PERFORMNUD) != 0) {
				/* We need NUD */
				ln->ln_asked = 1;
				ln->ln_state = ND6_LLINFO_PROBE;
				ln->ln_expire = timenow.tv_sec +
				    nd_ifinfo[ifp->if_index].retrans / 1000;
				lck_rw_done(nd_if_rwlock);
				RT_ADDREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_ns_output(ifp, &dst->sin6_addr,
				    &dst->sin6_addr, ln, 0);
				lck_mtx_assert(rnh_lock,
				    LCK_MTX_ASSERT_NOTOWNED);
				RT_REMREF(rt);
				goto again;
			}
			lck_rw_done(nd_if_rwlock);
			ln->ln_state = ND6_LLINFO_STALE; /* XXX */
			ln->ln_expire = rt_expiry(rt, timenow.tv_sec,
			    nd6_gctimer);
			RT_UNLOCK(rt);
			break;

		case ND6_LLINFO_PROBE:
			if (ln->ln_asked < nd6_umaxtries) {
				ln->ln_asked++;
				lck_rw_lock_shared(nd_if_rwlock);
				ln->ln_expire = timenow.tv_sec +
				    nd_ifinfo[ifp->if_index].retrans / 1000;
				lck_rw_done(nd_if_rwlock);
				RT_ADDREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_ns_output(ifp, &dst->sin6_addr,
				    &dst->sin6_addr, ln, 0);
				RT_REMREF(rt);
			} else {
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_free(rt);
			}
			lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
			goto again;

		default:
			RT_UNLOCK(rt);
			break;
		}
		ln = next;
	}
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	/* Now clear the flag from all entries */
	ln = llinfo_nd6.ln_next;
	while (ln != NULL && ln != &llinfo_nd6) {
		struct rtentry *rt = ln->ln_rt;
		struct llinfo_nd6 *next = ln->ln_next;

		RT_LOCK_SPIN(rt);
		if (ln->ln_flags & ND6_LNF_TIMER_SKIP)
			ln->ln_flags &= ~ND6_LNF_TIMER_SKIP;
		RT_UNLOCK(rt);
		ln = next;
	}
	lck_mtx_unlock(rnh_lock);

	/* expire default router list */
	lck_mtx_lock(nd6_mutex);
	dr = TAILQ_FIRST(&nd_defrouter);
	while (dr) {
		if (dr->expire && dr->expire < timenow.tv_sec) {
			struct nd_defrouter *t;
			t = TAILQ_NEXT(dr, dr_entry);
			defrtrlist_del(dr);
			dr = t;
		} else {
			dr = TAILQ_NEXT(dr, dr_entry);
		}
	}
	lck_mtx_unlock(nd6_mutex);

	/*
	 * expire interface addresses.
	 * in the past the loop was inside prefix expiry processing.
	 * However, from a stricter speci-confrmance standpoint, we should
	 * rather separate address lifetimes and prefix lifetimes.
	 */
addrloop:
	lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
	for (ia6 = in6_ifaddrs; ia6; ia6 = nia6) {
		nia6 = ia6->ia_next;
		IFA_LOCK(&ia6->ia_ifa);
		/*
		 * Extra reference for ourselves; it's no-op if
		 * we don't have to regenerate temporary address,
		 * otherwise it protects the address from going
		 * away since we drop in6_ifaddr_rwlock below.
		 */
		IFA_ADDREF_LOCKED(&ia6->ia_ifa);
		/* check address lifetime */
		lt6 = &ia6->ia6_lifetime;
		if (IFA6_IS_INVALID(ia6)) {
			/*
			 * If the expiring address is temporary, try
			 * regenerating a new one.  This would be useful when
			 * we suspended a laptop PC, then turned it on after a
			 * period that could invalidate all temporary
			 * addresses.  Although we may have to restart the
			 * loop (see below), it must be after purging the
			 * address.  Otherwise, we'd see an infinite loop of
			 * regeneration. 
			 */
			if (ip6_use_tempaddr &&
			    (ia6->ia6_flags & IN6_IFF_TEMPORARY) != 0) {
				/* NOTE: We have to drop the lock here because 
				 * regen_tmpaddr() eventually calls in6_update_ifa(),  
				 * which must take the lock and would otherwise cause a 
				 * hang. This is safe because the goto addrloop 
				 * leads to a reevaluation of the in6_ifaddrs list
				 */
				IFA_UNLOCK(&ia6->ia_ifa);
				lck_rw_done(&in6_ifaddr_rwlock);
				(void) regen_tmpaddr(ia6);
			} else {
				IFA_UNLOCK(&ia6->ia_ifa);
				lck_rw_done(&in6_ifaddr_rwlock);
			}

			/*
			 * Purging the address would have caused
			 * in6_ifaddr_rwlock to be dropped and reacquired;
			 * therefore search again from the beginning
			 * of in6_ifaddrs list.
			 */
			in6_purgeaddr(&ia6->ia_ifa);

			/* Release extra reference taken above */
			IFA_REMREF(&ia6->ia_ifa);
			goto addrloop;
		}
		IFA_LOCK_ASSERT_HELD(&ia6->ia_ifa);
		if (IFA6_IS_DEPRECATED(ia6)) {
			int oldflags = ia6->ia6_flags;

			ia6->ia6_flags |= IN6_IFF_DEPRECATED;

			/*
			 * If a temporary address has just become deprecated,
			 * regenerate a new one if possible.
			 */
			if (ip6_use_tempaddr &&
			    (ia6->ia6_flags & IN6_IFF_TEMPORARY) != 0 &&
			    (oldflags & IN6_IFF_DEPRECATED) == 0) {

				/* see NOTE above */
				IFA_UNLOCK(&ia6->ia_ifa);
				lck_rw_done(&in6_ifaddr_rwlock);
				if (regen_tmpaddr(ia6) == 0) {
					/*
					 * A new temporary address is
					 * generated.
					 * XXX: this means the address chain
					 * has changed while we are still in
					 * the loop.  Although the change
					 * would not cause disaster (because
					 * it's not a deletion, but an
					 * addition,) we'd rather restart the
					 * loop just for safety.  Or does this 
					 * significantly reduce performance??
					 */
					/* Release extra reference */
					IFA_REMREF(&ia6->ia_ifa);
					goto addrloop;
				}
				lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
			} else {
				IFA_UNLOCK(&ia6->ia_ifa);
			}
		} else {
			/*
			 * A new RA might have made a deprecated address
			 * preferred.
			 */
			ia6->ia6_flags &= ~IN6_IFF_DEPRECATED;
			IFA_UNLOCK(&ia6->ia_ifa);
		}
		lck_rw_assert(&in6_ifaddr_rwlock, LCK_RW_ASSERT_EXCLUSIVE);
		/* Release extra reference taken above */
		IFA_REMREF(&ia6->ia_ifa);
	}
	lck_rw_done(&in6_ifaddr_rwlock);

	lck_mtx_lock(nd6_mutex);
	/*
	 * Since we drop the nd6_mutex in prelist_remove, we want to run this
	 * section single threaded.
	 */
	while (nd6_drain_busy) {
		nd6_drain_waiters++;
		msleep(nd6_drain_waitchan, nd6_mutex, (PZERO-1),
		    __func__, NULL);
		lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	}
	nd6_drain_busy = TRUE;

	/* expire prefix list */
	pr = nd_prefix.lh_first;
	while (pr) {
		/*
		 * check prefix lifetime.
		 * since pltime is just for autoconf, pltime processing for
		 * prefix is not necessary.
		 */
		NDPR_LOCK(pr);
		if (pr->ndpr_stateflags & NDPRF_PROCESSED) {
			NDPR_UNLOCK(pr);
			pr = pr->ndpr_next;
			continue;
		}
		if (pr->ndpr_expire && pr->ndpr_expire < timenow.tv_sec) {
			/*
			 * address expiration and prefix expiration are
			 * separate.  NEVER perform in6_purgeaddr here.
			 */
			pr->ndpr_stateflags |= NDPRF_PROCESSED;
			NDPR_ADDREF_LOCKED(pr);
			prelist_remove(pr);
			NDPR_UNLOCK(pr);
			NDPR_REMREF(pr);
			pr = nd_prefix.lh_first;
		} else {
			pr->ndpr_stateflags |= NDPRF_PROCESSED;
			NDPR_UNLOCK(pr);
			pr = pr->ndpr_next;
		}
	}
	LIST_FOREACH(pr, &nd_prefix, ndpr_entry) {
		NDPR_LOCK(pr);
		pr->ndpr_stateflags &= ~NDPRF_PROCESSED;
		NDPR_UNLOCK(pr);
	}
	nd6_drain_busy = FALSE;
	if (nd6_drain_waiters > 0) {
		nd6_drain_waiters = 0;
		wakeup(nd6_drain_waitchan);
	}
	lck_mtx_unlock(nd6_mutex);
}

/*
 * ND6 timer routine to expire default route list and prefix list
 */
void
nd6_timer(__unused void	*ignored_arg)
{
	nd6_drain(NULL);
	timeout(nd6_timer, (caddr_t)0, nd6_prune * hz);
}

static int
regen_tmpaddr(
	struct in6_ifaddr *ia6) /* deprecated/invalidated temporary address */
{
	struct ifaddr *ifa;
	struct ifnet *ifp;
	struct in6_ifaddr *public_ifa6 = NULL;
	struct timeval timenow;

	getmicrotime(&timenow);

	ifp = ia6->ia_ifa.ifa_ifp;
	ifnet_lock_shared(ifp);
	for (ifa = ifp->if_addrlist.tqh_first; ifa;
	     ifa = ifa->ifa_list.tqe_next)
	{
		struct in6_ifaddr *it6;

		IFA_LOCK(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			IFA_UNLOCK(ifa);
			continue;
		}
		it6 = (struct in6_ifaddr *)ifa;

		/* ignore no autoconf addresses. */
		if ((it6->ia6_flags & IN6_IFF_AUTOCONF) == 0) {
			IFA_UNLOCK(ifa);
			continue;
		}
		/* ignore autoconf addresses with different prefixes. */
		if (it6->ia6_ndpr == NULL || it6->ia6_ndpr != ia6->ia6_ndpr) {
			IFA_UNLOCK(ifa);
			continue;
		}
		/*
		 * Now we are looking at an autoconf address with the same
		 * prefix as ours.  If the address is temporary and is still
		 * preferred, do not create another one.  It would be rare, but
		 * could happen, for example, when we resume a laptop PC after
		 * a long period.
		 */
		if ((it6->ia6_flags & IN6_IFF_TEMPORARY) != 0 &&
		    !IFA6_IS_DEPRECATED(it6)) {
			IFA_UNLOCK(ifa);
			if (public_ifa6 != NULL)
				IFA_REMREF(&public_ifa6->ia_ifa);
			public_ifa6 = NULL;
			break;
		}

		/*
		 * This is a public autoconf address that has the same prefix
		 * as ours.  If it is preferred, keep it.  We can't break the
		 * loop here, because there may be a still-preferred temporary
		 * address with the prefix.
		 */
		if (!IFA6_IS_DEPRECATED(it6)) {
			IFA_ADDREF_LOCKED(ifa);	/* for public_ifa6 */
			IFA_UNLOCK(ifa);
			if (public_ifa6 != NULL)
				IFA_REMREF(&public_ifa6->ia_ifa);
			public_ifa6 = it6;
		} else {
			IFA_UNLOCK(ifa);
		}
	}
	ifnet_lock_done(ifp);

	if (public_ifa6 != NULL) {
		int e;

		if ((e = in6_tmpifadd(public_ifa6, 0, M_WAITOK)) != 0) {
			log(LOG_NOTICE, "regen_tmpaddr: failed to create a new"
			    " tmp addr,errno=%d\n", e);
			IFA_REMREF(&public_ifa6->ia_ifa);
			return(-1);
		}
		IFA_REMREF(&public_ifa6->ia_ifa);
		return(0);
	}

	return(-1);
}

/*
 * Nuke neighbor cache/prefix/default router management table, right before
 * ifp goes away.
 */
void
nd6_purge(
	struct ifnet *ifp)
{
	struct llinfo_nd6 *ln;
	struct nd_defrouter *dr, *ndr;
	struct nd_prefix *pr, *npr;

	/* Nuke default router list entries toward ifp */
	lck_mtx_lock(nd6_mutex);
	if ((dr = TAILQ_FIRST(&nd_defrouter)) != NULL) {
		/*
		 * The first entry of the list may be stored in
		 * the routing table, so we'll delete it later.
		 */
		for (dr = TAILQ_NEXT(dr, dr_entry); dr; dr = ndr) {
			ndr = TAILQ_NEXT(dr, dr_entry);
			if (dr->stateflags & NDDRF_INSTALLED)
				continue;
			if (dr->ifp == ifp)
				defrtrlist_del(dr);
		}
		dr = TAILQ_FIRST(&nd_defrouter);
		if (dr->ifp == ifp)
			defrtrlist_del(dr);
	}

	for (dr = TAILQ_FIRST(&nd_defrouter); dr; dr = ndr) {
		ndr = TAILQ_NEXT(dr, dr_entry);
		if (!(dr->stateflags & NDDRF_INSTALLED))
			continue;

		if (dr->ifp == ifp)
			defrtrlist_del(dr);
	}

	/* Nuke prefix list entries toward ifp */
	for (pr = nd_prefix.lh_first; pr; pr = npr) {
		npr = pr->ndpr_next;
		NDPR_LOCK(pr);
		if (pr->ndpr_ifp == ifp) {
			/*
			 * Because if_detach() does *not* release prefixes
			 * while purging addresses the reference count will
			 * still be above zero. We therefore reset it to
			 * make sure that the prefix really gets purged.
			 */
			pr->ndpr_addrcnt = 0;

			/*
			 * Previously, pr->ndpr_addr is removed as well,
			 * but I strongly believe we don't have to do it.
			 * nd6_purge() is only called from in6_ifdetach(),
			 * which removes all the associated interface addresses
			 * by itself.
			 * (jinmei@kame.net 20010129)
			 */
			NDPR_ADDREF_LOCKED(pr);
			prelist_remove(pr);
			NDPR_UNLOCK(pr);
			NDPR_REMREF(pr);
		} else {
			NDPR_UNLOCK(pr);
		}
	}
	lck_mtx_unlock(nd6_mutex);

	/* cancel default outgoing interface setting */
	if (nd6_defifindex == ifp->if_index) {
		nd6_setdefaultiface(0);
	}

	if (!ip6_forwarding && (ip6_accept_rtadv || (ifp->if_eflags & IFEF_ACCEPT_RTADVD))) { 
		lck_mtx_lock(nd6_mutex);
		/* refresh default router list */
		defrouter_reset();
		defrouter_select(ifp);
		lck_mtx_unlock(nd6_mutex);
	}

	/*
	 * Nuke neighbor cache entries for the ifp.
	 * Note that rt->rt_ifp may not be the same as ifp,
	 * due to KAME goto ours hack.  See RTM_RESOLVE case in
	 * nd6_rtrequest(), and ip6_input().
	 */
again:
	lck_mtx_lock(rnh_lock);
	ln = llinfo_nd6.ln_next;
	while (ln != NULL && ln != &llinfo_nd6) {
		struct rtentry *rt;
		struct llinfo_nd6 *nln;

		nln = ln->ln_next;
		rt = ln->ln_rt;
		RT_LOCK(rt);
		if (rt->rt_gateway != NULL &&
		    rt->rt_gateway->sa_family == AF_LINK &&
		    SDL(rt->rt_gateway)->sdl_index == ifp->if_index) {
			RT_UNLOCK(rt);
			lck_mtx_unlock(rnh_lock);
			/*
			 * See comments on nd6_timer() for reasons why
			 * this loop is repeated; we bite the costs of
			 * going thru the same llinfo_nd6 more than once
			 * here, since this purge happens during detach,
			 * and that unlike the timer case, it's possible
			 * there's more than one purges happening at the
			 * same time (thus a flag wouldn't buy anything).
			 */
			nd6_free(rt);
			lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
			goto again;
		} else {
			RT_UNLOCK(rt);
		}
		ln = nln;
	}
	lck_mtx_unlock(rnh_lock);
}

/*
 * Upon success, the returned route will be locked and the caller is
 * responsible for releasing the reference and doing RT_UNLOCK(rt).
 * This routine does not require rnh_lock to be held by the caller,
 * although it needs to be indicated of such a case in order to call
 * the correct variant of the relevant routing routines.
 */
struct rtentry *
nd6_lookup(
	struct in6_addr *addr6,
	int create,
	struct ifnet *ifp,
	int rt_locked)
{
	struct rtentry *rt;
	struct sockaddr_in6 sin6;
	unsigned int ifscope;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *addr6;

	ifscope = (ifp != NULL) ? ifp->if_index : IFSCOPE_NONE;
	if (rt_locked) {
		lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
		rt = rtalloc1_scoped_locked((struct sockaddr *)&sin6,
		    create, 0, ifscope);
	} else {
		rt = rtalloc1_scoped((struct sockaddr *)&sin6,
		    create, 0, ifscope);
	}

	if (rt != NULL) {
		RT_LOCK(rt);
		if ((rt->rt_flags & RTF_LLINFO) == 0) {
			/*
			 * This is the case for the default route.
			 * If we want to create a neighbor cache for the
			 * address, we should free the route for the
			 * destination and allocate an interface route.
			 */
			if (create) {
				RT_UNLOCK(rt);
				if (rt_locked)
					rtfree_locked(rt);
				else
					rtfree(rt);
				rt = NULL;
			}
		}
	}
	if (rt == NULL) {
		if (create && ifp) {
			struct ifaddr *ifa;
			u_int32_t ifa_flags;
			int e;

			/*
			 * If no route is available and create is set,
			 * we allocate a host route for the destination
			 * and treat it like an interface route.
			 * This hack is necessary for a neighbor which can't
			 * be covered by our own prefix.
			 */
			ifa = ifaof_ifpforaddr((struct sockaddr *)&sin6, ifp);
			if (ifa == NULL)
				return(NULL);

			/*
			 * Create a new route.  RTF_LLINFO is necessary
			 * to create a Neighbor Cache entry for the
			 * destination in nd6_rtrequest which will be
			 * called in rtrequest via ifa->ifa_rtrequest.
			 */
			if (!rt_locked)
				lck_mtx_lock(rnh_lock);
			IFA_LOCK_SPIN(ifa);
			ifa_flags = ifa->ifa_flags;
			IFA_UNLOCK(ifa);
			if ((e = rtrequest_scoped_locked(RTM_ADD,
			    (struct sockaddr *)&sin6, ifa->ifa_addr,
			    (struct sockaddr *)&all1_sa,
			    (ifa_flags | RTF_HOST | RTF_LLINFO) &
			    ~RTF_CLONING, &rt, ifscope)) != 0) {
				if (e != EEXIST)
					log(LOG_ERR, "%s: failed to add route "
					    "for a neighbor(%s), errno=%d\n",
					    __func__, ip6_sprintf(addr6), e);
			}
			if (!rt_locked)
				lck_mtx_unlock(rnh_lock);
			IFA_REMREF(ifa);
			if (rt == NULL)
				return(NULL);

			RT_LOCK(rt);
			if (rt->rt_llinfo) {
				struct llinfo_nd6 *ln = rt->rt_llinfo;
				ln->ln_state = ND6_LLINFO_NOSTATE;
			}
		} else {
			return(NULL);
		}
	}
	RT_LOCK_ASSERT_HELD(rt);
	/*
	 * Validation for the entry.
	 * Note that the check for rt_llinfo is necessary because a cloned
	 * route from a parent route that has the L flag (e.g. the default
	 * route to a p2p interface) may have the flag, too, while the
	 * destination is not actually a neighbor.
	 * XXX: we can't use rt->rt_ifp to check for the interface, since
	 *      it might be the loopback interface if the entry is for our
	 *      own address on a non-loopback interface. Instead, we should
	 *      use rt->rt_ifa->ifa_ifp, which would specify the REAL
	 *	interface.
	 * Note also that ifa_ifp and ifp may differ when we connect two
	 * interfaces to a same link, install a link prefix to an interface,
	 * and try to install a neighbor cache on an interface that does not
	 * have a route to the prefix.
	 */
	if (ifp == NULL || 
	    (rt->rt_flags & RTF_GATEWAY) || (rt->rt_flags & RTF_LLINFO) == 0 ||
	    rt->rt_gateway->sa_family != AF_LINK ||  rt->rt_llinfo == NULL ||
	    (ifp && rt->rt_ifa->ifa_ifp != ifp)) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		if (create) {
			log(LOG_DEBUG, "%s: failed to lookup %s "
			    "(if = %s)\n", __func__, ip6_sprintf(addr6),
			    ifp ? if_name(ifp) : "unspec");
			/* xxx more logs... kazu */
		}
		return(NULL);
	}
	/*
	 * Caller needs to release reference and call RT_UNLOCK(rt).
	 */
	return(rt);
}

/*
 * Test whether a given IPv6 address is a neighbor or not, ignoring
 * the actual neighbor cache.  The neighbor cache is ignored in order
 * to not reenter the routing code from within itself.
 */
static int
nd6_is_new_addr_neighbor(
	struct sockaddr_in6 *addr,
	struct ifnet *ifp)
{
	struct nd_prefix *pr;
	struct ifaddr *dstaddr;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	/*
	 * A link-local address is always a neighbor.
	 * XXX: a link does not necessarily specify a single interface.
	 */
	if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
		struct sockaddr_in6 sin6_copy;
		u_int32_t zone;

		/*
		 * We need sin6_copy since sa6_recoverscope() may modify the
		 * content (XXX).
		 */
		sin6_copy = *addr;
		if (sa6_recoverscope(&sin6_copy))
			return (0); /* XXX: should be impossible */
		if (in6_setscope(&sin6_copy.sin6_addr, ifp, &zone))
			return (0);
		if (sin6_copy.sin6_scope_id == zone)
			return (1);
		else
			return (0);
	}

	/*
	 * If the address matches one of our addresses,
	 * it should be a neighbor.
	 * If the address matches one of our on-link prefixes, it should be a
	 * neighbor.
	 */
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		NDPR_LOCK(pr);
		if (pr->ndpr_ifp != ifp) {
			NDPR_UNLOCK(pr);
			continue;
		}
		if (!(pr->ndpr_stateflags & NDPRF_ONLINK)) {
			NDPR_UNLOCK(pr);
			continue;
		}
		if (IN6_ARE_MASKED_ADDR_EQUAL(&pr->ndpr_prefix.sin6_addr,
		    &addr->sin6_addr, &pr->ndpr_mask)) {
			NDPR_UNLOCK(pr);
			return (1);
		}
		NDPR_UNLOCK(pr);
	}

	/*
	 * If the address is assigned on the node of the other side of
	 * a p2p interface, the address should be a neighbor.
	 */
	dstaddr = ifa_ifwithdstaddr((struct sockaddr *)addr);
	if (dstaddr != NULL) {
		if (dstaddr->ifa_ifp == ifp) {
			IFA_REMREF(dstaddr);
			return (1);
		}
		IFA_REMREF(dstaddr);
		dstaddr = NULL;
	}

	/*
	 * If the default router list is empty, all addresses are regarded
	 * as on-link, and thus, as a neighbor.
	 * XXX: we restrict the condition to hosts, because routers usually do
	 * not have the "default router list".
	 */
	if (!ip6_forwarding && TAILQ_FIRST(&nd_defrouter) == NULL &&
	    nd6_defifindex == ifp->if_index) {
		return (1);
	}

	return (0);
}


/*
 * Detect if a given IPv6 address identifies a neighbor on a given link.
 * XXX: should take care of the destination of a p2p link?
 */
int
nd6_is_addr_neighbor(struct sockaddr_in6 *addr, struct ifnet *ifp, int rt_locked)
{
	struct rtentry *rt;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(nd6_mutex);
	if (nd6_is_new_addr_neighbor(addr, ifp)) {
		lck_mtx_unlock(nd6_mutex);
		return (1);
	}
	lck_mtx_unlock(nd6_mutex);

	/*
	 * Even if the address matches none of our addresses, it might be
	 * in the neighbor cache.
	 */
	if ((rt = nd6_lookup(&addr->sin6_addr, 0, ifp, rt_locked)) != NULL) {
		RT_LOCK_ASSERT_HELD(rt);
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		return (1);
	}

	return (0);
}

/*
 * Free an nd6 llinfo entry.
 * Since the function would cause significant changes in the kernel, DO NOT
 * make it global, unless you have a strong reason for the change, and are sure
 * that the change is safe.
 */
void
nd6_free(
	struct rtentry *rt)
{
	struct llinfo_nd6 *ln;
	struct in6_addr in6;
	struct nd_defrouter *dr;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	RT_LOCK_ASSERT_NOTHELD(rt);
	lck_mtx_lock(nd6_mutex);

	RT_LOCK(rt);
	RT_ADDREF_LOCKED(rt);	/* Extra ref */
	ln = rt->rt_llinfo;
	in6 = ((struct sockaddr_in6 *)rt_key(rt))->sin6_addr;

	/*
	 * Prevent another thread from modifying rt_key, rt_gateway
	 * via rt_setgate() after the rt_lock is dropped by marking
	 * the route as defunct.
	 */
	rt->rt_flags |= RTF_CONDEMNED;

	/*
	 * we used to have pfctlinput(PRC_HOSTDEAD) here. 
	 * even though it is not harmful, it was not really necessary.
	 */

	if (!ip6_forwarding && (ip6_accept_rtadv ||
	    (rt->rt_ifp->if_eflags & IFEF_ACCEPT_RTADVD))) {
		dr = defrouter_lookup(&((struct sockaddr_in6 *)rt_key(rt))->
		    sin6_addr, rt->rt_ifp);

		if ((ln && ln->ln_router) || dr) {
			/*
			 * rt6_flush must be called whether or not the neighbor
			 * is in the Default Router List.
			 * See a corresponding comment in nd6_na_input().
			 */
			RT_UNLOCK(rt);
			lck_mtx_unlock(nd6_mutex);
			rt6_flush(&in6, rt->rt_ifp);
			lck_mtx_lock(nd6_mutex);
		} else {
			RT_UNLOCK(rt);
		}

		if (dr) {
			NDDR_REMREF(dr);
			/*
			 * Unreachablity of a router might affect the default
			 * router selection and on-link detection of advertised
			 * prefixes.
			 */

			/*
			 * Temporarily fake the state to choose a new default
			 * router and to perform on-link determination of
			 * prefixes correctly.
			 * Below the state will be set correctly,
			 * or the entry itself will be deleted.
			 */
			RT_LOCK_SPIN(rt);
			ln->ln_state = ND6_LLINFO_INCOMPLETE;

			/*
			 * Since defrouter_select() does not affect the
			 * on-link determination and MIP6 needs the check
			 * before the default router selection, we perform
			 * the check now.
			 */
			RT_UNLOCK(rt);
			pfxlist_onlink_check();

			/*
			 * refresh default router list
			 */
			defrouter_select(rt->rt_ifp);
		}
		RT_LOCK_ASSERT_NOTHELD(rt);
	} else {
		RT_UNLOCK(rt);
	}

	lck_mtx_unlock(nd6_mutex);
	/*
	 * Detach the route from the routing tree and the list of neighbor
	 * caches, and disable the route entry not to be used in already
	 * cached routes.
	 */
	(void) rtrequest(RTM_DELETE, rt_key(rt), (struct sockaddr *)0,
		  rt_mask(rt), 0, (struct rtentry **)0);

	/* Extra ref held above; now free it */
	rtfree(rt);
}

/*
 * Upper-layer reachability hint for Neighbor Unreachability Detection.
 *
 * XXX cost-effective methods?
 */
void
nd6_nud_hint(
	struct rtentry *rt,
	struct in6_addr *dst6,
	int force)
{
	struct llinfo_nd6 *ln;
	struct timeval timenow;

	getmicrotime(&timenow);

	/*
	 * If the caller specified "rt", use that.  Otherwise, resolve the
	 * routing table by supplied "dst6".
	 */
	if (!rt) {
		if (!dst6)
			return;
		/* Callee returns a locked route upon success */
		if ((rt = nd6_lookup(dst6, 0, NULL, 0)) == NULL)
			return;
		RT_LOCK_ASSERT_HELD(rt);
	} else {
		RT_LOCK(rt);
		RT_ADDREF_LOCKED(rt);
	}

	if ((rt->rt_flags & RTF_GATEWAY) != 0 ||
	    (rt->rt_flags & RTF_LLINFO) == 0 ||
	    !rt->rt_llinfo || !rt->rt_gateway ||
	    rt->rt_gateway->sa_family != AF_LINK) {
		/* This is not a host route. */
		goto done;
	}

	ln = rt->rt_llinfo;
	if (ln->ln_state < ND6_LLINFO_REACHABLE)
		goto done;

	/*
	 * if we get upper-layer reachability confirmation many times,
	 * it is possible we have false information.
	 */
	if (!force) {
		ln->ln_byhint++;
		if (ln->ln_byhint > nd6_maxnudhint)
			goto done;
	}

	ln->ln_state = ND6_LLINFO_REACHABLE;
	if (ln->ln_expire) {
		lck_rw_lock_shared(nd_if_rwlock);
		ln->ln_expire = timenow.tv_sec +
			nd_ifinfo[rt->rt_ifp->if_index].reachable;
		lck_rw_done(nd_if_rwlock);
	}
done:
	RT_REMREF_LOCKED(rt);
	RT_UNLOCK(rt);
}

void
nd6_rtrequest(
	int	req,
	struct rtentry *rt,
	__unused struct sockaddr *sa)
{
	struct sockaddr *gate = rt->rt_gateway;
	struct llinfo_nd6 *ln = rt->rt_llinfo;
	static struct sockaddr_dl null_sdl = {sizeof(null_sdl), AF_LINK, 0, 0, 0, 0, 0, 
											{0,0,0,0,0,0,0,0,0,0,0,0,} };
	struct ifnet *ifp = rt->rt_ifp;
	struct ifaddr *ifa;
	struct timeval timenow;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	if ((rt->rt_flags & RTF_GATEWAY))
		return;

	if (nd6_need_cache(ifp) == 0 && (rt->rt_flags & RTF_HOST) == 0) {
		/*
		 * This is probably an interface direct route for a link
		 * which does not need neighbor caches (e.g. fe80::%lo0/64).
		 * We do not need special treatment below for such a route.
		 * Moreover, the RTF_LLINFO flag which would be set below
		 * would annoy the ndp(8) command.
		 */
		return;
	}

	if (req == RTM_RESOLVE) {
		int no_nd_cache;

		if (!nd6_need_cache(ifp)) {	/* stf case */
			no_nd_cache = 1;
		} else {
			struct sockaddr_in6 sin6;

			rtkey_to_sa6(rt, &sin6);
			/*
			 * nd6_is_addr_neighbor() may call nd6_lookup(),
			 * therefore we drop rt_lock to avoid deadlock
			 * during the lookup.
			 */
			RT_ADDREF_LOCKED(rt);
			RT_UNLOCK(rt);
			no_nd_cache = !nd6_is_addr_neighbor(&sin6, ifp, 1);
			RT_LOCK(rt);
			RT_REMREF_LOCKED(rt);
		}

		/*
		 * FreeBSD and BSD/OS often make a cloned host route based
		 * on a less-specific route (e.g. the default route).
		 * If the less specific route does not have a "gateway"
		 * (this is the case when the route just goes to a p2p or an
		 * stf interface), we'll mistakenly make a neighbor cache for
		 * the host route, and will see strange neighbor solicitation
		 * for the corresponding destination.  In order to avoid the
		 * confusion, we check if the destination of the route is
		 * a neighbor in terms of neighbor discovery, and stop the
		 * process if not.  Additionally, we remove the LLINFO flag
		 * so that ndp(8) will not try to get the neighbor information
		 * of the destination.
		 */
		if (no_nd_cache) {
			rt->rt_flags &= ~RTF_LLINFO;
			return;
		}
	}

	getmicrotime(&timenow);
	switch (req) {
	case RTM_ADD:
		/*
		 * There is no backward compatibility :)
		 *
		 * if ((rt->rt_flags & RTF_HOST) == 0 &&
		 *     SIN(rt_mask(rt))->sin_addr.s_addr != 0xffffffff)
		 *	   rt->rt_flags |= RTF_CLONING;
		 */
		if ((rt->rt_flags & RTF_CLONING) ||
		    ((rt->rt_flags & RTF_LLINFO) && ln == NULL)) {
			/*
			 * Case 1: This route should come from a route to
			 * interface (RTF_CLONING case) or the route should be
			 * treated as on-link but is currently not
			 * (RTF_LLINFO && ln == NULL case).
			 */
			if (rt_setgate(rt, rt_key(rt),
			    (struct sockaddr *)&null_sdl) == 0) {
				gate = rt->rt_gateway;
				SDL(gate)->sdl_type = ifp->if_type;
				SDL(gate)->sdl_index = ifp->if_index;
				/*
				 * In case we're called before 1.0 sec.
				 * has elapsed.
				 */
				if (ln != NULL)
					ln->ln_expire = MAX(timenow.tv_sec, 1);
			}
			if ((rt->rt_flags & RTF_CLONING))
				break;
		}
		/*
		 * In IPv4 code, we try to annonuce new RTF_ANNOUNCE entry here.
		 * We don't do that here since llinfo is not ready yet.
		 *
		 * There are also couple of other things to be discussed:
		 * - unsolicited NA code needs improvement beforehand
		 * - RFC2461 says we MAY send multicast unsolicited NA
		 *   (7.2.6 paragraph 4), however, it also says that we
		 *   SHOULD provide a mechanism to prevent multicast NA storm.
		 *   we don't have anything like it right now.
		 *   note that the mechanism needs a mutual agreement
		 *   between proxies, which means that we need to implement
		 *   a new protocol, or a new kludge.
		 * - from RFC2461 6.2.4, host MUST NOT send an unsolicited NA.
		 *   we need to check ip6forwarding before sending it.
		 *   (or should we allow proxy ND configuration only for
		 *   routers?  there's no mention about proxy ND from hosts)
		 */
		/* FALLTHROUGH */
	case RTM_RESOLVE:
		if ((ifp->if_flags & (IFF_POINTOPOINT | IFF_LOOPBACK)) == 0) {
			/*
			 * Address resolution isn't necessary for a point to
			 * point link, so we can skip this test for a p2p link.
			 */
			if (gate->sa_family != AF_LINK ||
			    gate->sa_len < sizeof(null_sdl)) {
				/* Don't complain in case of RTM_ADD */
				if (req == RTM_RESOLVE) {
					log(LOG_DEBUG,
					    "nd6_rtrequest: bad gateway "
					        "value: %s\n", if_name(ifp));
				}
				break;
			}
			SDL(gate)->sdl_type = ifp->if_type;
			SDL(gate)->sdl_index = ifp->if_index;
		}
		if (ln != NULL)
			break;	/* This happens on a route change */
		/*
		 * Case 2: This route may come from cloning, or a manual route
		 * add with a LL address.
		 */
		rt->rt_llinfo = ln = nd6_llinfo_alloc();
		if (ln == NULL) {
			log(LOG_DEBUG, "nd6_rtrequest: malloc failed\n");
			break;
		}
		rt->rt_llinfo_get_ri = nd6_llinfo_get_ri;
		rt->rt_llinfo_purge = nd6_llinfo_purge;
		rt->rt_llinfo_free = nd6_llinfo_free;

		nd6_inuse++;
		nd6_allocated++;
		Bzero(ln, sizeof(*ln));
		ln->ln_rt = rt;
		/* this is required for "ndp" command. - shin */
		if (req == RTM_ADD) {
		        /*
			 * gate should have some valid AF_LINK entry,
			 * and ln->ln_expire should have some lifetime
			 * which is specified by ndp command.
			 */
			ln->ln_state = ND6_LLINFO_REACHABLE;
			ln->ln_byhint = 0;
		} else {
		        /*
			 * When req == RTM_RESOLVE, rt is created and
			 * initialized in rtrequest(), so rt_expire is 0.
			 */
			ln->ln_state = ND6_LLINFO_NOSTATE;
			/* In case we're called before 1.0 sec. has elapsed */
			ln->ln_expire = MAX(timenow.tv_sec, 1);
		}
		rt->rt_flags |= RTF_LLINFO;
		LN_INSERTHEAD(ln);

		/*
		 * If we have too many cache entries, initiate immediate
		 * purging for some "less recently used" entries.  Note that
		 * we cannot directly call nd6_free() here because it would
		 * cause re-entering rtable related routines triggering an LOR
		 * problem.
		 */
		if (ip6_neighborgcthresh >= 0 &&
		    nd6_inuse >= ip6_neighborgcthresh) {
			int i;

			for (i = 0; i < 10 && llinfo_nd6.ln_prev != ln; i++) {
				struct llinfo_nd6 *ln_end = llinfo_nd6.ln_prev;
				struct rtentry *rt_end = ln_end->ln_rt;

				/* Move this entry to the head */
				RT_LOCK(rt_end);
				LN_DEQUEUE(ln_end);
				LN_INSERTHEAD(ln_end);

				if (ln_end->ln_expire == 0) {
					RT_UNLOCK(rt_end);
					continue;
				}
				if (ln_end->ln_state > ND6_LLINFO_INCOMPLETE)
					ln_end->ln_state = ND6_LLINFO_STALE;
				else
					ln_end->ln_state = ND6_LLINFO_PURGE;
				ln_end->ln_expire = timenow.tv_sec;
				RT_UNLOCK(rt_end);
			}
		}

		/*
		 * check if rt_key(rt) is one of my address assigned
		 * to the interface.
		 */
		ifa = (struct ifaddr *)in6ifa_ifpwithaddr(rt->rt_ifp,
					  &SIN6(rt_key(rt))->sin6_addr);
		if (ifa) {
			caddr_t macp = nd6_ifptomac(ifp);
			ln->ln_expire = 0;
			ln->ln_state = ND6_LLINFO_REACHABLE;
			ln->ln_byhint = 0;
			if (macp) {
				Bcopy(macp, LLADDR(SDL(gate)), ifp->if_addrlen);
				SDL(gate)->sdl_alen = ifp->if_addrlen;
			}
			if (nd6_useloopback) {
				if (rt->rt_ifp != lo_ifp) {
					/*
					 * Purge any link-layer info caching.
					 */
					if (rt->rt_llinfo_purge != NULL)
						rt->rt_llinfo_purge(rt);

					/*
					 * Adjust route ref count for the
					 * interfaces.
					 */
					if (rt->rt_if_ref_fn != NULL) {
						rt->rt_if_ref_fn(lo_ifp, 1);
						rt->rt_if_ref_fn(rt->rt_ifp, -1);
					}
				}
				rt->rt_ifp = lo_ifp;	/* XXX */
				/*
				 * Make sure rt_ifa be equal to the ifaddr
				 * corresponding to the address.
				 * We need this because when we refer
				 * rt_ifa->ia6_flags in ip6_input, we assume
				 * that the rt_ifa points to the address instead
				 * of the loopback address.
				 */
				if (ifa != rt->rt_ifa) {
					rtsetifa(rt, ifa);
				}
			}
			IFA_REMREF(ifa);
		} else if (rt->rt_flags & RTF_ANNOUNCE) {
			ln->ln_expire = 0;
			ln->ln_state = ND6_LLINFO_REACHABLE;
			ln->ln_byhint = 0;

			/* join solicited node multicast for proxy ND */
			if (ifp->if_flags & IFF_MULTICAST) {
				struct in6_addr llsol;
				struct in6_multi *in6m;
				int error;

				llsol = SIN6(rt_key(rt))->sin6_addr;
				llsol.s6_addr32[0] = IPV6_ADDR_INT32_MLL;
				llsol.s6_addr32[1] = 0;
				llsol.s6_addr32[2] = htonl(1);
				llsol.s6_addr8[12] = 0xff;
				if (in6_setscope(&llsol, ifp, NULL))
					break;
				error = in6_mc_join(ifp, &llsol, NULL, &in6m, 0);
				if (error) {
					nd6log((LOG_ERR, "%s: failed to join "
					    "%s (errno=%d)\n", if_name(ifp),
					    ip6_sprintf(&llsol), error));
				} else {
					IN6M_REMREF(in6m);
				}
			}
		}
		break;

	case RTM_DELETE:
		if (ln == NULL)
			break;
		/* leave from solicited node multicast for proxy ND */
		if ((rt->rt_flags & RTF_ANNOUNCE) != 0 &&
		    (ifp->if_flags & IFF_MULTICAST) != 0) {
			struct in6_addr llsol;
			struct in6_multi *in6m;

			llsol = SIN6(rt_key(rt))->sin6_addr;
			llsol.s6_addr32[0] = IPV6_ADDR_INT32_MLL;
			llsol.s6_addr32[1] = 0;
			llsol.s6_addr32[2] = htonl(1);
			llsol.s6_addr8[12] = 0xff;
			if (in6_setscope(&llsol, ifp, NULL) == 0) {
				in6_multihead_lock_shared();
				IN6_LOOKUP_MULTI(&llsol, ifp, in6m);
				in6_multihead_lock_done();
				if (in6m != NULL) {
					in6_mc_leave(in6m, NULL);
					IN6M_REMREF(in6m);
				}
			}
		}
		nd6_inuse--;
		/*
		 * Unchain it but defer the actual freeing until the route
		 * itself is to be freed.  rt->rt_llinfo still points to
		 * llinfo_nd6, and likewise, ln->ln_rt stil points to this
		 * route entry, except that RTF_LLINFO is now cleared.
		 */
		if (ln->ln_flags & ND6_LNF_IN_USE)
			LN_DEQUEUE(ln);

		/*
		 * Purge any link-layer info caching.
		 */
		if (rt->rt_llinfo_purge != NULL)
			rt->rt_llinfo_purge(rt);

		rt->rt_flags &= ~RTF_LLINFO;
		if (ln->ln_hold != NULL) {
			m_freem(ln->ln_hold);
			ln->ln_hold = NULL;
		}
	}
}

static void
nd6_siocgdrlst(void *data, int data_is_64)
{
	struct in6_drlist_64 *drl_64 = (struct in6_drlist_64 *)data;
	struct in6_drlist_32 *drl_32 = (struct in6_drlist_32 *)data;
	struct nd_defrouter *dr;
	int i = 0;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	bzero(data, data_is_64 ? sizeof (*drl_64) : sizeof (*drl_32));
	dr = TAILQ_FIRST(&nd_defrouter);
	if (data_is_64) {
		/* For 64-bit process */
		while (dr && i < DRLSTSIZ) {
			drl_64->defrouter[i].rtaddr = dr->rtaddr;
			if (IN6_IS_ADDR_LINKLOCAL(&drl_64->defrouter[i].rtaddr)) {
				/* XXX: need to this hack for KAME stack */
				drl_64->defrouter[i].rtaddr.s6_addr16[1] = 0;
			} else {
				log(LOG_ERR,
				    "default router list contains a "
				    "non-linklocal address(%s)\n",
				    ip6_sprintf(&drl_64->defrouter[i].rtaddr));
			}
			drl_64->defrouter[i].flags = dr->flags;
			drl_64->defrouter[i].rtlifetime = dr->rtlifetime;
			drl_64->defrouter[i].expire = dr->expire;
			drl_64->defrouter[i].if_index = dr->ifp->if_index;
			i++;
			dr = TAILQ_NEXT(dr, dr_entry);
		}
		return;
	}
	/* For 32-bit process */
	while (dr && i < DRLSTSIZ) {
		drl_32->defrouter[i].rtaddr = dr->rtaddr;
		if (IN6_IS_ADDR_LINKLOCAL(&drl_32->defrouter[i].rtaddr)) {
			/* XXX: need to this hack for KAME stack */
			drl_32->defrouter[i].rtaddr.s6_addr16[1] = 0;
		} else {
			log(LOG_ERR,
			    "default router list contains a "
			    "non-linklocal address(%s)\n",
			    ip6_sprintf(&drl_32->defrouter[i].rtaddr));
		}
		drl_32->defrouter[i].flags = dr->flags;
		drl_32->defrouter[i].rtlifetime = dr->rtlifetime;
		drl_32->defrouter[i].expire = dr->expire;
		drl_32->defrouter[i].if_index = dr->ifp->if_index;
		i++;
		dr = TAILQ_NEXT(dr, dr_entry);
	}
}

static void
nd6_siocgprlst(void *data, int data_is_64)
{
	struct in6_prlist_64 *prl_64 = (struct in6_prlist_64 *)data;
	struct in6_prlist_32 *prl_32 = (struct in6_prlist_32 *)data;
	struct nd_prefix *pr;
	int i = 0;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	/*
	 * XXX meaning of fields, especialy "raflags", is very
	 * differnet between RA prefix list and RR/static prefix list.
	 * how about separating ioctls into two?
	 */
	bzero(data, data_is_64 ? sizeof (*prl_64) : sizeof (*prl_32));
	pr = nd_prefix.lh_first;
	if (data_is_64) {
		/* For 64-bit process */
		while (pr && i < PRLSTSIZ) {
			struct nd_pfxrouter *pfr;
			int j;

			NDPR_LOCK(pr);
			(void) in6_embedscope(&prl_64->prefix[i].prefix,
			    &pr->ndpr_prefix, NULL, NULL, NULL);
			prl_64->prefix[i].raflags = pr->ndpr_raf;
			prl_64->prefix[i].prefixlen = pr->ndpr_plen;
			prl_64->prefix[i].vltime = pr->ndpr_vltime;
			prl_64->prefix[i].pltime = pr->ndpr_pltime;
			prl_64->prefix[i].if_index = pr->ndpr_ifp->if_index;
			prl_64->prefix[i].expire = pr->ndpr_expire;

			pfr = pr->ndpr_advrtrs.lh_first;
			j = 0;
			while (pfr) {
				if (j < DRLSTSIZ) {
#define RTRADDR prl_64->prefix[i].advrtr[j]
					RTRADDR = pfr->router->rtaddr;
					if (IN6_IS_ADDR_LINKLOCAL(&RTRADDR)) {
						/* XXX: hack for KAME */
						RTRADDR.s6_addr16[1] = 0;
					} else {
						log(LOG_ERR,
						    "a router(%s) advertises "
						    "a prefix with "
						    "non-link local address\n",
						    ip6_sprintf(&RTRADDR));
					}
#undef RTRADDR
				}
				j++;
				pfr = pfr->pfr_next;
			}
			prl_64->prefix[i].advrtrs = j;
			prl_64->prefix[i].origin = PR_ORIG_RA;
			NDPR_UNLOCK(pr);

			i++;
			pr = pr->ndpr_next;
		}

		return;
	}
	/* For 32-bit process */
	while (pr && i < PRLSTSIZ) {
		struct nd_pfxrouter *pfr;
		int j;

		NDPR_LOCK(pr);
		(void) in6_embedscope(&prl_32->prefix[i].prefix,
		    &pr->ndpr_prefix, NULL, NULL, NULL);
		prl_32->prefix[i].raflags = pr->ndpr_raf;
		prl_32->prefix[i].prefixlen = pr->ndpr_plen;
		prl_32->prefix[i].vltime = pr->ndpr_vltime;
		prl_32->prefix[i].pltime = pr->ndpr_pltime;
		prl_32->prefix[i].if_index = pr->ndpr_ifp->if_index;
		prl_32->prefix[i].expire = pr->ndpr_expire;

		pfr = pr->ndpr_advrtrs.lh_first;
		j = 0;
		while (pfr) {
			if (j < DRLSTSIZ) {
#define RTRADDR prl_32->prefix[i].advrtr[j]
				RTRADDR = pfr->router->rtaddr;
				if (IN6_IS_ADDR_LINKLOCAL(&RTRADDR)) {
					/* XXX: hack for KAME */
					RTRADDR.s6_addr16[1] = 0;
				} else {
					log(LOG_ERR,
					    "a router(%s) advertises "
					    "a prefix with "
					    "non-link local address\n",
					    ip6_sprintf(&RTRADDR));
				}
#undef RTRADDR
			}
			j++;
			pfr = pfr->pfr_next;
		}
		prl_32->prefix[i].advrtrs = j;
		prl_32->prefix[i].origin = PR_ORIG_RA;
		NDPR_UNLOCK(pr);

		i++;
		pr = pr->ndpr_next;
	}
}

int
nd6_ioctl(u_long cmd, caddr_t data, struct ifnet *ifp)
{
	struct in6_ndireq *ndi = (struct in6_ndireq *)data;
	struct in6_ondireq *ondi = (struct in6_ondireq *)data;
	struct nd_defrouter *dr;
	struct nd_prefix *pr;
	struct rtentry *rt;
	int i = ifp->if_index, error = 0;

	switch (cmd) {
	case SIOCGDRLST_IN6_32:
	case SIOCGDRLST_IN6_64:
		/*
		 * obsolete API, use sysctl under net.inet6.icmp6
		 */
		lck_mtx_lock(nd6_mutex);
		nd6_siocgdrlst(data, cmd == SIOCGDRLST_IN6_64);
		lck_mtx_unlock(nd6_mutex);
		break;

	case SIOCGPRLST_IN6_32:
	case SIOCGPRLST_IN6_64:
		/*
		 * obsolete API, use sysctl under net.inet6.icmp6
		 */
		lck_mtx_lock(nd6_mutex);
		nd6_siocgprlst(data, cmd == SIOCGPRLST_IN6_64);
		lck_mtx_unlock(nd6_mutex);
		break;

	case OSIOCGIFINFO_IN6:
	case SIOCGIFINFO_IN6:
		/*
		 * SIOCGIFINFO_IN6 ioctl is encoded with in6_ondireq
		 * instead of in6_ndireq, so we treat it as such.
		 */
		lck_rw_lock_shared(nd_if_rwlock);
		if (!nd_ifinfo || i >= nd_ifinfo_indexlim) {
			lck_rw_done(nd_if_rwlock);
			error = EINVAL;
			break;
		}
		ondi->ndi.linkmtu = IN6_LINKMTU(ifp);
		ondi->ndi.maxmtu = nd_ifinfo[i].maxmtu;
		ondi->ndi.basereachable = nd_ifinfo[i].basereachable;
		ondi->ndi.reachable = nd_ifinfo[i].reachable;
		ondi->ndi.retrans = nd_ifinfo[i].retrans;
		ondi->ndi.flags = nd_ifinfo[i].flags;
		ondi->ndi.recalctm = nd_ifinfo[i].recalctm;
		ondi->ndi.chlim = nd_ifinfo[i].chlim;
		lck_rw_done(nd_if_rwlock);
		break;

	case SIOCSIFINFO_FLAGS:
		/* XXX: almost all other fields of ndi->ndi is unused */
		lck_rw_lock_shared(nd_if_rwlock);
		if (!nd_ifinfo || i >= nd_ifinfo_indexlim) {
			lck_rw_done(nd_if_rwlock);
			error = EINVAL;
			break;
		}
		nd_ifinfo[i].flags = ndi->ndi.flags;
		lck_rw_done(nd_if_rwlock);
		break;

	case SIOCSNDFLUSH_IN6:	/* XXX: the ioctl name is confusing... */
		/* flush default router list */
		/*
		 * xxx sumikawa: should not delete route if default
		 * route equals to the top of default router list
		 */
		lck_mtx_lock(nd6_mutex);
		defrouter_reset();
		defrouter_select(ifp);
		lck_mtx_unlock(nd6_mutex);
		/* xxx sumikawa: flush prefix list */
		break;

	case SIOCSPFXFLUSH_IN6: {
		/* flush all the prefix advertised by routers */
		struct nd_prefix *next;

		lck_mtx_lock(nd6_mutex);
		for (pr = nd_prefix.lh_first; pr; pr = next) {
			struct in6_ifaddr *ia;

			next = pr->ndpr_next;

			NDPR_LOCK(pr);
			if (IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_prefix.sin6_addr)) {
				NDPR_UNLOCK(pr);
				continue; /* XXX */
			}
			if (ifp != lo_ifp && pr->ndpr_ifp != ifp) {
				NDPR_UNLOCK(pr);
				continue;
			}
			/* do we really have to remove addresses as well? */
			NDPR_ADDREF_LOCKED(pr);
			NDPR_UNLOCK(pr);
			lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
			ia = in6_ifaddrs;
			while (ia != NULL) {
				IFA_LOCK(&ia->ia_ifa);
				if ((ia->ia6_flags & IN6_IFF_AUTOCONF) == 0) {
					IFA_UNLOCK(&ia->ia_ifa);
					ia = ia->ia_next;
					continue;
				}

				if (ia->ia6_ndpr == pr) {
					IFA_ADDREF_LOCKED(&ia->ia_ifa);
					IFA_UNLOCK(&ia->ia_ifa);
					lck_rw_done(&in6_ifaddr_rwlock);
					lck_mtx_unlock(nd6_mutex);
					in6_purgeaddr(&ia->ia_ifa);
					lck_mtx_lock(nd6_mutex);
					lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
					IFA_REMREF(&ia->ia_ifa);
					/*
					 * Purging the address caused
					 * in6_ifaddr_rwlock to be
					 * dropped and
					 * reacquired; therefore search again
					 * from the beginning of in6_ifaddrs.
					 * The same applies for the prefix list.
					 */
					ia = in6_ifaddrs;
					next = nd_prefix.lh_first;
					continue;

				}
				IFA_UNLOCK(&ia->ia_ifa);
				ia = ia->ia_next;
			}
			lck_rw_done(&in6_ifaddr_rwlock);
			NDPR_LOCK(pr);
			prelist_remove(pr);
			NDPR_UNLOCK(pr);
			/*
			 * If we were trying to restart this loop
			 * above by changing the value of 'next', we might
			 * end up freeing the only element on the list
			 * when we call NDPR_REMREF().
			 * When this happens, we also have get out of this
			 * loop because we have nothing else to do.
			 */
			if (pr == next)
				next = NULL;
			NDPR_REMREF(pr);
		}
		lck_mtx_unlock(nd6_mutex);
		break;
	}

	case SIOCSRTRFLUSH_IN6: {
		/* flush all the default routers */
		struct nd_defrouter *next;

		lck_mtx_lock(nd6_mutex);
		if ((dr = TAILQ_FIRST(&nd_defrouter)) != NULL) {
			/*
			 * The first entry of the list may be stored in
			 * the routing table, so we'll delete it later.
			 */
			for (dr = TAILQ_NEXT(dr, dr_entry); dr; dr = next) {
				next = TAILQ_NEXT(dr, dr_entry);
				if (ifp == lo_ifp || dr->ifp == ifp)
					defrtrlist_del(dr);
			}
			if (ifp == lo_ifp ||
			    TAILQ_FIRST(&nd_defrouter)->ifp == ifp)
				defrtrlist_del(TAILQ_FIRST(&nd_defrouter));
		}
		lck_mtx_unlock(nd6_mutex);
		break;
	}

	case SIOCGNBRINFO_IN6_32: {
		struct llinfo_nd6 *ln;
		struct in6_nbrinfo_32 *nbi_32 = (struct in6_nbrinfo_32 *)data;
		/* make local for safety */
		struct in6_addr nb_addr = nbi_32->addr;

		/*
		 * XXX: KAME specific hack for scoped addresses
		 *      XXXX: for other scopes than link-local?
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&nbi_32->addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&nbi_32->addr)) {
			u_int16_t *idp = (u_int16_t *)&nb_addr.s6_addr[2];

			if (*idp == 0)
				*idp = htons(ifp->if_index);
		}

		/* Callee returns a locked route upon success */
		if ((rt = nd6_lookup(&nb_addr, 0, ifp, 0)) == NULL) {
			error = EINVAL;
			break;
		}
		RT_LOCK_ASSERT_HELD(rt);
		ln = rt->rt_llinfo;
		nbi_32->state = ln->ln_state;
		nbi_32->asked = ln->ln_asked;
		nbi_32->isrouter = ln->ln_router;
		nbi_32->expire = ln->ln_expire;
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		break;
	}

	case SIOCGNBRINFO_IN6_64: {
		struct llinfo_nd6 *ln;
		struct in6_nbrinfo_64 *nbi_64 = (struct in6_nbrinfo_64 *)data;
		/* make local for safety */
		struct in6_addr nb_addr = nbi_64->addr;

		/*
		 * XXX: KAME specific hack for scoped addresses
		 *      XXXX: for other scopes than link-local?
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&nbi_64->addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&nbi_64->addr)) {
			u_int16_t *idp = (u_int16_t *)&nb_addr.s6_addr[2];

			if (*idp == 0)
				*idp = htons(ifp->if_index);
		}

		/* Callee returns a locked route upon success */
		if ((rt = nd6_lookup(&nb_addr, 0, ifp, 0)) == NULL) {
			error = EINVAL;
			break;
		}
		RT_LOCK_ASSERT_HELD(rt);
		ln = rt->rt_llinfo;
		nbi_64->state = ln->ln_state;
		nbi_64->asked = ln->ln_asked;
		nbi_64->isrouter = ln->ln_router;
		nbi_64->expire = ln->ln_expire;
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		break;
	}

	case SIOCGDEFIFACE_IN6_32: /* XXX: should be implemented as a sysctl? */
	case SIOCGDEFIFACE_IN6_64: {
		struct in6_ndifreq_64 *ndif_64 = (struct in6_ndifreq_64 *)data;
		struct in6_ndifreq_32 *ndif_32 = (struct in6_ndifreq_32 *)data;

		if (cmd == SIOCGDEFIFACE_IN6_64)
			ndif_64->ifindex = nd6_defifindex;
		else
			ndif_32->ifindex = nd6_defifindex;
		break;
	}

	case SIOCSDEFIFACE_IN6_32: /* XXX: should be implemented as a sysctl? */
	case SIOCSDEFIFACE_IN6_64: {
		struct in6_ndifreq_64 *ndif_64 = (struct in6_ndifreq_64 *)data;
		struct in6_ndifreq_32 *ndif_32 = (struct in6_ndifreq_32 *)data;

		error = nd6_setdefaultiface(cmd == SIOCSDEFIFACE_IN6_64 ?
		    ndif_64->ifindex : ndif_32->ifindex);
		return (error);
		/* NOTREACHED */
	}
	}
	return (error);
}

/*
 * Create neighbor cache entry and cache link-layer address,
 * on reception of inbound ND6 packets. (RS/RA/NS/redirect)
 */
void
nd6_cache_lladdr(
	struct ifnet *ifp,
	struct in6_addr *from,
	char *lladdr,
	__unused int lladdrlen,
	int type,	/* ICMP6 type */
	int code)	/* type dependent information */
{
	struct rtentry *rt = NULL;
	struct llinfo_nd6 *ln = NULL;
	int is_newentry;
	struct sockaddr_dl *sdl = NULL;
	int do_update;
	int olladdr;
	int llchange;
	int newstate = 0;
	struct timeval timenow;

	if (ifp == NULL)
		panic("ifp == NULL in nd6_cache_lladdr");
	if (from == NULL)
		panic("from == NULL in nd6_cache_lladdr");

	/* nothing must be updated for unspecified address */
	if (IN6_IS_ADDR_UNSPECIFIED(from))
		return;

	/*
	 * Validation about ifp->if_addrlen and lladdrlen must be done in
	 * the caller.
	 *
	 * XXX If the link does not have link-layer adderss, what should
	 * we do? (ifp->if_addrlen == 0)
	 * Spec says nothing in sections for RA, RS and NA.  There's small
	 * description on it in NS section (RFC 2461 7.2.3).
	 */
	getmicrotime(&timenow);

	rt = nd6_lookup(from, 0, ifp, 0);
	if (rt == NULL) {
		if ((rt = nd6_lookup(from, 1, ifp, 0)) == NULL)
			return;
		RT_LOCK_ASSERT_HELD(rt);
		is_newentry = 1;
	} else {
		RT_LOCK_ASSERT_HELD(rt);
		/* do nothing if static ndp is set */
		if (rt->rt_flags & RTF_STATIC) {
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			return;
		}
		is_newentry = 0;
	}

	if (rt == NULL)
		return;
	if ((rt->rt_flags & (RTF_GATEWAY | RTF_LLINFO)) != RTF_LLINFO) {
fail:
		RT_UNLOCK(rt);
		nd6_free(rt);
		rtfree(rt);
		return;
	}
	ln = (struct llinfo_nd6 *)rt->rt_llinfo;
	if (ln == NULL)
		goto fail;
	if (rt->rt_gateway == NULL)
		goto fail;
	if (rt->rt_gateway->sa_family != AF_LINK)
		goto fail;
	sdl = SDL(rt->rt_gateway);

	olladdr = (sdl->sdl_alen) ? 1 : 0;
	if (olladdr && lladdr) {
		if (bcmp(lladdr, LLADDR(sdl), ifp->if_addrlen))
			llchange = 1;
		else
			llchange = 0;
	} else
		llchange = 0;

	/*
	 * newentry olladdr  lladdr  llchange	(*=record)
	 *	0	n	n	--	(1)
	 *	0	y	n	--	(2)
	 *	0	n	y	--	(3) * STALE
	 *	0	y	y	n	(4) *
	 *	0	y	y	y	(5) * STALE
	 *	1	--	n	--	(6)   NOSTATE(= PASSIVE)
	 *	1	--	y	--	(7) * STALE
	 */

	if (lladdr) {		/* (3-5) and (7) */
		/*
		 * Record source link-layer address
		 * XXX is it dependent to ifp->if_type?
		 */
		sdl->sdl_alen = ifp->if_addrlen;
		bcopy(lladdr, LLADDR(sdl), ifp->if_addrlen);

		/* cache the gateway (sender HW) address */
		nd6_llreach_alloc(rt, ifp, LLADDR(sdl), sdl->sdl_alen, FALSE);
	}

	if (!is_newentry) {
		if ((!olladdr && lladdr != NULL) ||	/* (3) */
		    (olladdr && lladdr != NULL && llchange)) {	/* (5) */
			do_update = 1;
			newstate = ND6_LLINFO_STALE;
		} else					/* (1-2,4) */
			do_update = 0;
	} else {
		do_update = 1;
		if (lladdr == NULL)			/* (6) */
			newstate = ND6_LLINFO_NOSTATE;
		else					/* (7) */
			newstate = ND6_LLINFO_STALE;
	}

	if (do_update) {
		/*
		 * Update the state of the neighbor cache.
		 */
		ln->ln_state = newstate;

		if (ln->ln_state == ND6_LLINFO_STALE) {
			struct mbuf *m = ln->ln_hold;
			/*
			 * XXX: since nd6_output() below will cause
			 * state tansition to DELAY and reset the timer,
			 * we must set the timer now, although it is actually
			 * meaningless.
			 */
			ln->ln_expire = timenow.tv_sec + nd6_gctimer;
			ln->ln_hold = NULL;

			if (m != NULL) {
				struct sockaddr_in6 sin6;

				rtkey_to_sa6(rt, &sin6);
				/*
				 * we assume ifp is not a p2p here, so just
				 * set the 2nd argument as the 1st one.
				 */
				RT_UNLOCK(rt);
				nd6_output(ifp, ifp, m, &sin6, rt);
				RT_LOCK(rt);
			}
		} else if (ln->ln_state == ND6_LLINFO_INCOMPLETE) {
			/* probe right away */
			ln->ln_expire = timenow.tv_sec;
		}
	}

	/*
	 * ICMP6 type dependent behavior.
	 *
	 * NS: clear IsRouter if new entry
	 * RS: clear IsRouter
	 * RA: set IsRouter if there's lladdr
	 * redir: clear IsRouter if new entry
	 *
	 * RA case, (1):
	 * The spec says that we must set IsRouter in the following cases:
	 * - If lladdr exist, set IsRouter.  This means (1-5).
	 * - If it is old entry (!newentry), set IsRouter.  This means (7).
	 * So, based on the spec, in (1-5) and (7) cases we must set IsRouter.
	 * A quetion arises for (1) case.  (1) case has no lladdr in the
	 * neighbor cache, this is similar to (6).
	 * This case is rare but we figured that we MUST NOT set IsRouter.
	 *
	 * newentry olladdr  lladdr  llchange	    NS  RS  RA	redir
	 *							D R
	 *	0	n	n	--	(1)	c   ?     s
	 *	0	y	n	--	(2)	c   s     s
	 *	0	n	y	--	(3)	c   s     s
	 *	0	y	y	n	(4)	c   s     s
	 *	0	y	y	y	(5)	c   s     s
	 *	1	--	n	--	(6) c	c	c s
	 *	1	--	y	--	(7) c	c   s	c s
	 *
	 *					(c=clear s=set)
	 */
	switch (type & 0xff) {
	case ND_NEIGHBOR_SOLICIT:
		/*
		 * New entry must have is_router flag cleared.
		 */
		if (is_newentry)	/* (6-7) */
			ln->ln_router = 0;
		break;
	case ND_REDIRECT:
		/*
		 * If the icmp is a redirect to a better router, always set the
		 * is_router flag.  Otherwise, if the entry is newly created,
		 * clear the flag.  [RFC 2461, sec 8.3]
		 */
		if (code == ND_REDIRECT_ROUTER)
			ln->ln_router = 1;
		else if (is_newentry) /* (6-7) */
			ln->ln_router = 0;
		break;
	case ND_ROUTER_SOLICIT:
		/*
		 * is_router flag must always be cleared.
		 */
		ln->ln_router = 0;
		break;
	case ND_ROUTER_ADVERT:
		/*
		 * Mark an entry with lladdr as a router.
		 */
		if ((!is_newentry && (olladdr || lladdr)) ||	/* (2-5) */
		    (is_newentry && lladdr)) {			/* (7) */
			ln->ln_router = 1;
		}
		break;
	}

	/*
	 * When the link-layer address of a router changes, select the
	 * best router again.  In particular, when the neighbor entry is newly
	 * created, it might affect the selection policy.
	 * Question: can we restrict the first condition to the "is_newentry"
	 * case?
	 * XXX: when we hear an RA from a new router with the link-layer
	 * address option, defrouter_select() is called twice, since
	 * defrtrlist_update called the function as well.  However, I believe
	 * we can compromise the overhead, since it only happens the first
	 * time.
	 * XXX: although defrouter_select() should not have a bad effect
	 * for those are not autoconfigured hosts, we explicitly avoid such
	 * cases for safety.
	 */
	if (do_update && ln->ln_router && !ip6_forwarding &&
	    (ip6_accept_rtadv || (ifp->if_eflags & IFEF_ACCEPT_RTADVD))) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		lck_mtx_lock(nd6_mutex);
		defrouter_select(ifp);
		lck_mtx_unlock(nd6_mutex);
	} else {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
	}
}

static void
nd6_slowtimo(
    __unused void *ignored_arg)
{
	int i;
	struct nd_ifinfo *nd6if;

	lck_rw_lock_shared(nd_if_rwlock);
	for (i = 1; i < if_index + 1; i++) {
		if (!nd_ifinfo || i >= nd_ifinfo_indexlim)
			break;
		nd6if = &nd_ifinfo[i];
		if (nd6if->basereachable && /* already initialized */
		    (nd6if->recalctm -= ND6_SLOWTIMER_INTERVAL) <= 0) {
			/*
			 * Since reachable time rarely changes by router
			 * advertisements, we SHOULD insure that a new random
			 * value gets recomputed at least once every few hours.
			 * (RFC 2461, 6.3.4)
			 */
			nd6if->recalctm = nd6_recalc_reachtm_interval;
			nd6if->reachable = ND_COMPUTE_RTIME(nd6if->basereachable);
		}
	}
	lck_rw_done(nd_if_rwlock);
	timeout(nd6_slowtimo, (caddr_t)0, ND6_SLOWTIMER_INTERVAL * hz);
}

#define senderr(e) { error = (e); goto bad;}
int
nd6_output(struct ifnet *ifp, struct ifnet *origifp, struct mbuf *m0,
    struct sockaddr_in6 *dst, struct rtentry *hint0)
{
	struct mbuf *m = m0;
	struct rtentry *rt = hint0, *hint = hint0;
	struct llinfo_nd6 *ln = NULL;
	int error = 0;
	struct timeval timenow;
	struct rtentry *rtrele = NULL;

	if (rt != NULL) {
		RT_LOCK_SPIN(rt);
		RT_ADDREF_LOCKED(rt);
	}

	if (IN6_IS_ADDR_MULTICAST(&dst->sin6_addr) || !nd6_need_cache(ifp)) {
		if (rt != NULL)
			RT_UNLOCK(rt);
		goto sendpkt;
	}

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
	 *
	 * This logic is similar to, though not exactly the same as the one
	 * used by arp_route_to_gateway_route().
	 */
	if (rt != NULL) {
		/*
		 * We have a reference to "rt" by now (or below via rtalloc1),
		 * which will either be released or freed at the end of this
		 * routine.
		 */
		RT_LOCK_ASSERT_HELD(rt);
		if (!(rt->rt_flags & RTF_UP)) {
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			if ((hint = rt = rtalloc1_scoped((struct sockaddr *)dst,
			    1, 0, ifp->if_index)) != NULL) {
				RT_LOCK_SPIN(rt);
				if (rt->rt_ifp != ifp) {
					/* XXX: loop care? */
					RT_UNLOCK(rt);
					error = nd6_output(ifp, origifp, m0,
					    dst, rt);
					rtfree(rt);
					return (error);
				}
			} else {
				senderr(EHOSTUNREACH);
			}
		}

		if (rt->rt_flags & RTF_GATEWAY) {
			struct rtentry *gwrt;
			struct in6_ifaddr *ia6 = NULL;
			struct sockaddr_in6 gw6;

			rtgw_to_sa6(rt, &gw6);
			/*
			 * Must drop rt_lock since nd6_is_addr_neighbor()
			 * calls nd6_lookup() and acquires rnh_lock.
			 */
			RT_UNLOCK(rt);

			/*
			 * We skip link-layer address resolution and NUD
			 * if the gateway is not a neighbor from ND point
			 * of view, regardless of the value of nd_ifinfo.flags.
			 * The second condition is a bit tricky; we skip
			 * if the gateway is our own address, which is
			 * sometimes used to install a route to a p2p link.
			 */
			if (!nd6_is_addr_neighbor(&gw6, ifp, 0) ||
			    (ia6 = in6ifa_ifpwithaddr(ifp, &gw6.sin6_addr))) {
				/*
				 * We allow this kind of tricky route only
				 * when the outgoing interface is p2p.
				 * XXX: we may need a more generic rule here.
				 */
				if (ia6 != NULL)
					IFA_REMREF(&ia6->ia_ifa);
				if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
					senderr(EHOSTUNREACH);
				goto sendpkt;
			}

			RT_LOCK_SPIN(rt);
			gw6 = *((struct sockaddr_in6 *)rt->rt_gateway);

			/* If hint is now down, give up */
			if (!(rt->rt_flags & RTF_UP)) {
				RT_UNLOCK(rt);
				senderr(EHOSTUNREACH);
			}

			/* If there's no gateway route, look it up */
			if ((gwrt = rt->rt_gwroute) == NULL) {
				RT_UNLOCK(rt);
				goto lookup;
			}
			/* Become a regular mutex */
			RT_CONVERT_LOCK(rt);

			/*
			 * Take gwrt's lock while holding route's lock;
			 * this is okay since gwrt never points back
			 * to rt, so no lock ordering issues.
			 */
			RT_LOCK_SPIN(gwrt);
			if (!(gwrt->rt_flags & RTF_UP)) {
				struct rtentry *ogwrt;

				rt->rt_gwroute = NULL;
				RT_UNLOCK(gwrt);
				RT_UNLOCK(rt);
				rtfree(gwrt);
lookup:
				gwrt = rtalloc1_scoped((struct sockaddr *)&gw6,
				    1, 0, ifp->if_index);

				RT_LOCK(rt);
				/*
				 * Bail out if the route is down, no route
				 * to gateway, circular route, or if the
				 * gateway portion of "rt" has changed.
				 */
				if (!(rt->rt_flags & RTF_UP) ||
				    gwrt == NULL || gwrt == rt ||
				    !equal(SA(&gw6), rt->rt_gateway)) {
					if (gwrt == rt) {
						RT_REMREF_LOCKED(gwrt);
						gwrt = NULL;
					}
					RT_UNLOCK(rt);
					if (gwrt != NULL)
						rtfree(gwrt);
					senderr(EHOSTUNREACH);
				}

				/* Remove any existing gwrt */
				ogwrt = rt->rt_gwroute;
				if ((rt->rt_gwroute = gwrt) != NULL)
					RT_ADDREF(gwrt);

				RT_UNLOCK(rt);
				/* Now free the replaced gwrt */
				if (ogwrt != NULL)
					rtfree(ogwrt);
				/* If still no route to gateway, bail out */
				if (gwrt == NULL)
					senderr(EHOSTUNREACH);
				/* Remember to release/free "rt" at the end */
				rtrele = rt;
				rt = gwrt;
				RT_LOCK_SPIN(rt);
				/* If gwrt is now down, give up */
				if (!(rt->rt_flags & RTF_UP)) {
					RT_UNLOCK(rt);
					rtfree(rt);
					rt = NULL;
					/* "rtrele" == original "rt" */
					senderr(EHOSTUNREACH);
				}
			} else {
				RT_ADDREF_LOCKED(gwrt);
				RT_UNLOCK(gwrt);
				RT_UNLOCK(rt);
				RT_LOCK_SPIN(gwrt);
				/* If gwrt is now down, give up */
				if (!(gwrt->rt_flags & RTF_UP)) {
					RT_UNLOCK(gwrt);
					rtfree(gwrt);
					senderr(EHOSTUNREACH);
				}
				/* Remember to release/free "rt" at the end */
				rtrele = rt;
				rt = gwrt;
			}
		}
		/* Become a regular mutex */
		RT_CONVERT_LOCK(rt);
	}

	if (rt != NULL)
		RT_LOCK_ASSERT_HELD(rt);

	/*
	 * Address resolution or Neighbor Unreachability Detection
	 * for the next hop.
	 * At this point, the destination of the packet must be a unicast
	 * or an anycast address(i.e. not a multicast).
	 */

	/* Look up the neighbor cache for the nexthop */
	if (rt && (rt->rt_flags & RTF_LLINFO) != 0) {
		ln = rt->rt_llinfo;
	} else {
		struct sockaddr_in6 sin6;
		/*
		 * Clear out Scope ID field in case it is set.
		 */
		sin6 = *dst;
		sin6.sin6_scope_id = 0;
		/*
		 * Since nd6_is_addr_neighbor() internally calls nd6_lookup(),
		 * the condition below is not very efficient.  But we believe
		 * it is tolerable, because this should be a rare case.
		 * Must drop rt_lock since nd6_is_addr_neighbor() calls
		 * nd6_lookup() and acquires rnh_lock.
		 */
		if (rt != NULL)
			RT_UNLOCK(rt);
		if (nd6_is_addr_neighbor(&sin6, ifp, 0)) {
			/* "rtrele" may have been used, so clean up "rt" now */
			if (rt != NULL) {
				/* Don't free "hint0" */
				if (rt == hint0)
					RT_REMREF(rt);
				else
					rtfree(rt);
			}
			/* Callee returns a locked route upon success */
			rt = nd6_lookup(&dst->sin6_addr, 1, ifp, 0);
			if (rt != NULL) {
				RT_LOCK_ASSERT_HELD(rt);
				ln = rt->rt_llinfo;
			}
		} else if (rt != NULL) {
			RT_LOCK(rt);
		}
	}

	if (!ln || !rt) {
		if (rt != NULL)
			RT_UNLOCK(rt);
		lck_rw_lock_shared(nd_if_rwlock);
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0 &&
		    !(nd_ifinfo[ifp->if_index].flags & ND6_IFF_PERFORMNUD)) {
			lck_rw_done(nd_if_rwlock);
			log(LOG_DEBUG,
			    "nd6_output: can't allocate llinfo for %s "
			    "(ln=%p, rt=%p)\n",
			    ip6_sprintf(&dst->sin6_addr), ln, rt);
			senderr(EIO);	/* XXX: good error? */
		}
		lck_rw_done(nd_if_rwlock);

		goto sendpkt;	/* send anyway */
	}

	getmicrotime(&timenow);

	/* We don't have to do link-layer address resolution on a p2p link. */
	if ((ifp->if_flags & IFF_POINTOPOINT) != 0 &&
	    ln->ln_state < ND6_LLINFO_REACHABLE) {
		ln->ln_state = ND6_LLINFO_STALE;
		ln->ln_expire = rt_expiry(rt, timenow.tv_sec, nd6_gctimer);
	}

	/*
	 * The first time we send a packet to a neighbor whose entry is
	 * STALE, we have to change the state to DELAY and a sets a timer to
	 * expire in DELAY_FIRST_PROBE_TIME seconds to ensure do
	 * neighbor unreachability detection on expiration.
	 * (RFC 2461 7.3.3)
	 */
	if (ln->ln_state == ND6_LLINFO_STALE) {
		ln->ln_asked = 0;
		ln->ln_state = ND6_LLINFO_DELAY;
		ln->ln_expire = rt_expiry(rt, timenow.tv_sec, nd6_delay);
	}

	/*
	 * If the neighbor cache entry has a state other than INCOMPLETE
	 * (i.e. its link-layer address is already resolved), just
	 * send the packet.
	 */
	if (ln->ln_state > ND6_LLINFO_INCOMPLETE) {
		RT_UNLOCK(rt);
		/*
		 * Move this entry to the head of the queue so that it is
		 * less likely for this entry to be a target of forced
		 * garbage collection (see nd6_rtrequest()).
		 */
		lck_mtx_lock(rnh_lock);
		RT_LOCK_SPIN(rt);
		if (ln->ln_flags & ND6_LNF_IN_USE) {
			LN_DEQUEUE(ln);
			LN_INSERTHEAD(ln);
		}
		RT_UNLOCK(rt);
		lck_mtx_unlock(rnh_lock);
		goto sendpkt;
	}

	/*
	 * There is a neighbor cache entry, but no ethernet address
	 * response yet.  Replace the held mbuf (if any) with this
	 * latest one.
	 *
	 * This code conforms to the rate-limiting rule described in Section
	 * 7.2.2 of RFC 2461, because the timer is set correctly after sending
	 * an NS below.
	 */
	if (ln->ln_state == ND6_LLINFO_NOSTATE)
		ln->ln_state = ND6_LLINFO_INCOMPLETE;
	if (ln->ln_hold)
		m_freem(ln->ln_hold);
	ln->ln_hold = m;
	if (ln->ln_expire && ln->ln_asked < nd6_mmaxtries &&
	    ln->ln_expire < timenow.tv_sec) {
		ln->ln_asked++;
		lck_rw_lock_shared(nd_if_rwlock);
		ln->ln_expire = timenow.tv_sec +
			nd_ifinfo[ifp->if_index].retrans / 1000;
		lck_rw_done(nd_if_rwlock);
		RT_UNLOCK(rt);
		/* We still have a reference on rt (for ln) */
		nd6_ns_output(ifp, NULL, &dst->sin6_addr, ln, 0);
	} else {
		RT_UNLOCK(rt);
	}
	/*
	 * Move this entry to the head of the queue so that it is
	 * less likely for this entry to be a target of forced
	 * garbage collection (see nd6_rtrequest()).
	 */
	lck_mtx_lock(rnh_lock);
	RT_LOCK_SPIN(rt);
	if (ln->ln_flags & ND6_LNF_IN_USE) {
		LN_DEQUEUE(ln);
		LN_INSERTHEAD(ln);
	}
	/* Clean up "rt" now while we can */
	if (rt == hint0) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
	} else {
		RT_UNLOCK(rt);
		rtfree_locked(rt);
	}
	rt = NULL;	/* "rt" has been taken care of */
	lck_mtx_unlock(rnh_lock);

	error = 0;
	goto release;

sendpkt:
	if (rt != NULL)
		RT_LOCK_ASSERT_NOTHELD(rt);

	/* discard the packet if IPv6 operation is disabled on the interface */
	lck_rw_lock_shared(nd_if_rwlock);
	if ((nd_ifinfo[ifp->if_index].flags & ND6_IFF_IFDISABLED)) {
		lck_rw_done(nd_if_rwlock);
		error = ENETDOWN; /* better error? */
		goto bad;
	}
	lck_rw_done(nd_if_rwlock);

	if ((ifp->if_flags & IFF_LOOPBACK) != 0) {
		/* forwarding rules require the original scope_id */
		m->m_pkthdr.rcvif = origifp;
		error = dlil_output(origifp, PF_INET6, m, (caddr_t)rt,
		    (struct sockaddr *)dst, 0);
		goto release;
	} else {
		/* Do not allow loopback address to wind up on a wire */
		struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);

		if ((IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src) ||
			IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst))) {
			ip6stat.ip6s_badscope++;
			/*
			 * Do not simply drop the packet just like a
			 * firewall -- we want the the application to feel
			 * the pain.  Return ENETUNREACH like ip6_output
			 * does in some similar cases.  This can startle
			 * the otherwise clueless process that specifies
			 * loopback as the source address.
			 */
			error = ENETUNREACH;
			goto bad;
		}
	}

	if (rt != NULL) {
		RT_LOCK_SPIN(rt);
		/* Mark use timestamp */
		if (rt->rt_llinfo != NULL)
			nd6_llreach_use(rt->rt_llinfo);
		RT_UNLOCK(rt);
	}

	if (hint && nstat_collect)
		nstat_route_tx(hint, 1, m->m_pkthdr.len, 0);

	m->m_pkthdr.rcvif = NULL;
	error = dlil_output(ifp, PF_INET6, m, (caddr_t)rt,
	    (struct sockaddr *)dst, 0);
	goto release;

bad:
	if (m != NULL)
		m_freem(m);

release:
	/* Clean up "rt" unless it's already been done */
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
	/* And now clean up "rtrele" if there is any */
	if (rtrele != NULL) {
		RT_LOCK_SPIN(rtrele);
		if (rtrele == hint0) {
			RT_REMREF_LOCKED(rtrele);
			RT_UNLOCK(rtrele);
		} else {
			RT_UNLOCK(rtrele);
			rtfree(rtrele);
		}
	}
	return (error);
}
#undef senderr

int
nd6_need_cache(
	struct ifnet *ifp)
{
	/*
	 * XXX: we currently do not make neighbor cache on any interface
	 * other than ARCnet, Ethernet, FDDI and GIF.
	 *
	 * RFC2893 says:
	 * - unidirectional tunnels needs no ND
	 */
	switch (ifp->if_type) {
	case IFT_ARCNET:
	case IFT_ETHER:
	case IFT_FDDI:
	case IFT_IEEE1394:
	case IFT_L2VLAN:
	case IFT_IEEE8023ADLAG:
#if IFT_IEEE80211
	case IFT_IEEE80211:
#endif
	case IFT_GIF:		/* XXX need more cases? */
	case IFT_PPP:
#if IFT_TUNNEL
	case IFT_TUNNEL:
#endif
	case IFT_BRIDGE:
	case IFT_CELLULAR:
		return(1);
	default:
		return(0);
	}
}

int
nd6_storelladdr(
	struct ifnet *ifp,
	struct rtentry *rt,
	struct mbuf *m,
	struct sockaddr *dst,
	u_char *desten)
{
	int i;
	struct sockaddr_dl *sdl;

	if (m->m_flags & M_MCAST) {
		switch (ifp->if_type) {
		case IFT_ETHER:
		case IFT_FDDI:
		case IFT_L2VLAN:
		case IFT_IEEE8023ADLAG:
#if IFT_IEEE80211
		case IFT_IEEE80211:
#endif
		case IFT_BRIDGE:
			ETHER_MAP_IPV6_MULTICAST(&SIN6(dst)->sin6_addr,
						 desten);
			return(1);
		case IFT_IEEE1394:
			for (i = 0; i < ifp->if_addrlen; i++)
				desten[i] = ~0;
			return(1);
		case IFT_ARCNET:
			*desten = 0;
			return(1);
		default:
			return(0); /* caller will free mbuf */
		}
	}

	if (rt == NULL) {
		/* this could happen, if we could not allocate memory */
		return(0); /* caller will free mbuf */
	}
	RT_LOCK(rt);
	if (rt->rt_gateway->sa_family != AF_LINK) {
		printf("nd6_storelladdr: something odd happens\n");
		RT_UNLOCK(rt);
		return(0); /* caller will free mbuf */
	}
	sdl = SDL(rt->rt_gateway);
	if (sdl->sdl_alen == 0) {
		/* this should be impossible, but we bark here for debugging */
		printf("nd6_storelladdr: sdl_alen == 0\n");
		RT_UNLOCK(rt);
		return(0); /* caller will free mbuf */
	}

	bcopy(LLADDR(sdl), desten, sdl->sdl_alen);
	RT_UNLOCK(rt);
	return(1);
}

/*
 * This is the ND pre-output routine; care must be taken to ensure that
 * the "hint" route never gets freed via rtfree(), since the caller may
 * have stored it inside a struct route with a reference held for that
 * placeholder.
 */
errno_t
nd6_lookup_ipv6(ifnet_t	 ifp, const struct sockaddr_in6	*ip6_dest,
    struct sockaddr_dl *ll_dest, size_t	ll_dest_len, route_t hint,
    mbuf_t packet)
{
	route_t	route = hint;
	errno_t	result = 0;
	struct sockaddr_dl *sdl = NULL;
	size_t	copy_len;

	if (ip6_dest->sin6_family != AF_INET6)
		return (EAFNOSUPPORT);

	if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) != (IFF_UP|IFF_RUNNING))
		return (ENETDOWN);

	if (hint != NULL) {
		/*
		 * Callee holds a reference on the route and returns
		 * with the route entry locked, upon success.
		 */
		result = arp_route_to_gateway_route(
		    (const struct sockaddr*)ip6_dest, hint, &route);
		if (result != 0)
			return (result);
		if (route != NULL)
			RT_LOCK_ASSERT_HELD(route);
	}

	if ((packet->m_flags & M_MCAST) != 0) {
		if (route != NULL)
			RT_UNLOCK(route);
		result = dlil_resolve_multi(ifp,
		    (const struct sockaddr*)ip6_dest,
		    (struct sockaddr *)ll_dest, ll_dest_len);
		if (route != NULL)
			RT_LOCK(route);
		goto release;
	}

	if (route == NULL) {
		/*
		 * This could happen, if we could not allocate memory or
		 * if arp_route_to_gateway_route() didn't return a route.
		 */
		result = ENOBUFS;
		goto release;
	}

	if (route->rt_gateway->sa_family != AF_LINK) {
		printf("nd6_lookup_ipv6: gateway address not AF_LINK\n");
		result = EADDRNOTAVAIL;
		goto release;
	}

	sdl = SDL(route->rt_gateway);
	if (sdl->sdl_alen == 0) {
		/* this should be impossible, but we bark here for debugging */
		printf("nd6_lookup_ipv6: sdl_alen == 0\n");
		result = EHOSTUNREACH;
		goto release;
	}

	copy_len = sdl->sdl_len <= ll_dest_len ? sdl->sdl_len : ll_dest_len;
	bcopy(sdl, ll_dest, copy_len);

release:
	if (route != NULL) {
		if (route == hint) {
			RT_REMREF_LOCKED(route);
			RT_UNLOCK(route);
		} else {
			RT_UNLOCK(route);
			rtfree(route);
		}
	}
	return (result);
}

SYSCTL_DECL(_net_inet6_icmp6);

static int
nd6_sysctl_drlist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;
	char buf[1024];
	struct nd_defrouter *dr;
	int p64 = proc_is64bit(req->p);

	if (req->newptr)
		return (EPERM);

	lck_mtx_lock(nd6_mutex);
	if (p64) {
		struct in6_defrouter_64 *d, *de;

		for (dr = TAILQ_FIRST(&nd_defrouter);
		     dr;
		     dr = TAILQ_NEXT(dr, dr_entry)) {
			d = (struct in6_defrouter_64 *)buf;
			de = (struct in6_defrouter_64 *)(buf + sizeof (buf));

			if (d + 1 <= de) {
				bzero(d, sizeof (*d));
				d->rtaddr.sin6_family = AF_INET6;
				d->rtaddr.sin6_len = sizeof (d->rtaddr);
				if (in6_recoverscope(&d->rtaddr, &dr->rtaddr,
				    dr->ifp) != 0)
					log(LOG_ERR,
					    "scope error in "
					    "default router list (%s)\n",
					    ip6_sprintf(&dr->rtaddr));
				d->flags = dr->flags;
				d->stateflags = dr->stateflags;
				d->stateflags &= ~NDDRF_PROCESSED;
				d->rtlifetime = dr->rtlifetime;
				d->expire = dr->expire;
				d->if_index = dr->ifp->if_index;
			} else {
				panic("buffer too short");
			}
			error = SYSCTL_OUT(req, buf, sizeof (*d));
			if (error)
				break;
		}
	} else {
		struct in6_defrouter_32 *d_32, *de_32;

		for (dr = TAILQ_FIRST(&nd_defrouter);
		     dr;
		     dr = TAILQ_NEXT(dr, dr_entry)) {
			d_32 = (struct in6_defrouter_32 *)buf;
			de_32 = (struct in6_defrouter_32 *)(buf + sizeof (buf));

			if (d_32 + 1 <= de_32) {
				bzero(d_32, sizeof (*d_32));
				d_32->rtaddr.sin6_family = AF_INET6;
				d_32->rtaddr.sin6_len = sizeof (d_32->rtaddr);
				if (in6_recoverscope(&d_32->rtaddr, &dr->rtaddr,
				    dr->ifp) != 0)
					log(LOG_ERR,
					    "scope error in "
					    "default router list (%s)\n",
					    ip6_sprintf(&dr->rtaddr));
				d_32->flags = dr->flags;
				d_32->stateflags = dr->stateflags;
				d_32->stateflags &= ~NDDRF_PROCESSED;
				d_32->rtlifetime = dr->rtlifetime;
				d_32->expire = dr->expire;
				d_32->if_index = dr->ifp->if_index;
			} else {
				panic("buffer too short");
			}
			error = SYSCTL_OUT(req, buf, sizeof (*d_32));
			if (error)
				break;
		}
	}
	lck_mtx_unlock(nd6_mutex);
	return (error);
}

static int
nd6_sysctl_prlist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;
	char buf[1024];
	struct nd_prefix *pr;
	int p64 = proc_is64bit(req->p);

	if (req->newptr)
		return (EPERM);

	lck_mtx_lock(nd6_mutex);
	if (p64) {
		struct in6_prefix_64 *p, *pe;

		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			u_short advrtrs = 0;
			size_t advance;
			struct sockaddr_in6 *sin6, *s6;
			struct nd_pfxrouter *pfr;

			p = (struct in6_prefix_64 *)buf;
			pe = (struct in6_prefix_64 *)(buf + sizeof (buf));

			if (p + 1 <= pe) {
				bzero(p, sizeof (*p));
				sin6 = (struct sockaddr_in6 *)(p + 1);

				NDPR_LOCK(pr);
				p->prefix = pr->ndpr_prefix;
				if (in6_recoverscope(&p->prefix,
				    &p->prefix.sin6_addr, pr->ndpr_ifp) != 0)
					log(LOG_ERR,
					    "scope error in prefix list (%s)\n",
					    ip6_sprintf(&p->prefix.sin6_addr));
				p->raflags = pr->ndpr_raf;
				p->prefixlen = pr->ndpr_plen;
				p->vltime = pr->ndpr_vltime;
				p->pltime = pr->ndpr_pltime;
				p->if_index = pr->ndpr_ifp->if_index;
				p->expire = pr->ndpr_expire;
				p->refcnt = pr->ndpr_addrcnt;
				p->flags = pr->ndpr_stateflags;
				p->origin = PR_ORIG_RA;
				advrtrs = 0;
				for (pfr = pr->ndpr_advrtrs.lh_first;
				     pfr;
				     pfr = pfr->pfr_next) {
					if ((void *)&sin6[advrtrs + 1] >
					    (void *)pe) {
						advrtrs++;
						continue;
					}
					s6 = &sin6[advrtrs];
					bzero(s6, sizeof (*s6));
					s6->sin6_family = AF_INET6;
					s6->sin6_len = sizeof (*sin6);
					if (in6_recoverscope(s6,
					    &pfr->router->rtaddr,
					    pfr->router->ifp) != 0)
						log(LOG_ERR, "scope error in "
						    "prefix list (%s)\n",
						    ip6_sprintf(&pfr->router->
						    rtaddr));
					advrtrs++;
				}
				p->advrtrs = advrtrs;
				NDPR_UNLOCK(pr);
			} else {
				panic("buffer too short");
			}
			advance = sizeof (*p) + sizeof (*sin6) * advrtrs;
			error = SYSCTL_OUT(req, buf, advance);
			if (error)
				break;
		}
	} else {
		struct in6_prefix_32 *p_32, *pe_32;

		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			u_short advrtrs = 0;
			size_t advance;
			struct sockaddr_in6 *sin6, *s6;
			struct nd_pfxrouter *pfr;

			p_32 = (struct in6_prefix_32 *)buf;
			pe_32 = (struct in6_prefix_32 *)(buf + sizeof (buf));

			if (p_32 + 1 <= pe_32) {
				bzero(p_32, sizeof (*p_32));
				sin6 = (struct sockaddr_in6 *)(p_32 + 1);

				NDPR_LOCK(pr);
				p_32->prefix = pr->ndpr_prefix;
				if (in6_recoverscope(&p_32->prefix,
				    &p_32->prefix.sin6_addr, pr->ndpr_ifp) != 0)
					log(LOG_ERR, "scope error in prefix "
					    "list (%s)\n", ip6_sprintf(&p_32->
					    prefix.sin6_addr));
				p_32->raflags = pr->ndpr_raf;
				p_32->prefixlen = pr->ndpr_plen;
				p_32->vltime = pr->ndpr_vltime;
				p_32->pltime = pr->ndpr_pltime;
				p_32->if_index = pr->ndpr_ifp->if_index;
				p_32->expire = pr->ndpr_expire;
				p_32->refcnt = pr->ndpr_addrcnt;
				p_32->flags = pr->ndpr_stateflags;
				p_32->origin = PR_ORIG_RA;
				advrtrs = 0;
				for (pfr = pr->ndpr_advrtrs.lh_first;
				     pfr;
				     pfr = pfr->pfr_next) {
					if ((void *)&sin6[advrtrs + 1] >
					    (void *)pe_32) {
						advrtrs++;
						continue;
					}
					s6 = &sin6[advrtrs];
					bzero(s6, sizeof (*s6));
					s6->sin6_family = AF_INET6;
					s6->sin6_len = sizeof (*sin6);
					if (in6_recoverscope(s6,
					    &pfr->router->rtaddr,
					    pfr->router->ifp) != 0)
						log(LOG_ERR, "scope error in "
						    "prefix list (%s)\n",
						    ip6_sprintf(&pfr->router->
						    rtaddr));
					advrtrs++;
				}
				p_32->advrtrs = advrtrs;
				NDPR_UNLOCK(pr);
			} else {
				panic("buffer too short");
			}
			advance = sizeof (*p_32) + sizeof (*sin6) * advrtrs;
			error = SYSCTL_OUT(req, buf, advance);
			if (error)
				break;
		}
	}
	lck_mtx_unlock(nd6_mutex);
	return (error);
}
SYSCTL_PROC(_net_inet6_icmp6, ICMPV6CTL_ND6_DRLIST, nd6_drlist,
	CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, nd6_sysctl_drlist, "S,in6_defrouter","");
SYSCTL_PROC(_net_inet6_icmp6, ICMPV6CTL_ND6_PRLIST, nd6_prlist,
	CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, nd6_sysctl_prlist, "S,in6_defrouter","");

