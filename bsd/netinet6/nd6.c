/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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

#include <dev/random/randomdev.h>

#include <kern/queue.h>
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_llreach.h>
#include <net/route.h>
#include <net/dlil.h>
#include <net/ntstat.h>
#include <net/net_osdep.h>

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

#define	ND6_SLOWTIMER_INTERVAL		(60 * 60)	/* 1 hour */
#define	ND6_RECALC_REACHTM_INTERVAL	(60 * 120)	/* 2 hours */

#define	equal(a1, a2) (bcmp((caddr_t)(a1), (caddr_t)(a2), (a1)->sa_len) == 0)

/* timer values */
int	nd6_prune	= 1;	/* walk list every 1 seconds */
int	nd6_prune_lazy	= 5;	/* lazily walk list every 5 seconds */
int	nd6_delay	= 5;	/* delay first probe time 5 second */
int	nd6_umaxtries	= 3;	/* maximum unicast query */
int	nd6_mmaxtries	= 3;	/* maximum multicast query */
int	nd6_useloopback = 1;	/* use loopback interface for local traffic */
int	nd6_gctimer	= (60 * 60 * 24); /* 1 day: garbage collection timer */

/* preventing too many loops in ND option parsing */
int nd6_maxndopt = 10;	/* max # of ND options allowed */

int nd6_maxqueuelen = 1; /* max # of packets cached in unresolved ND entries */

#if ND6_DEBUG
int nd6_debug = 1;
#else
int nd6_debug = 0;
#endif

int nd6_optimistic_dad =
	(ND6_OPTIMISTIC_DAD_LINKLOCAL|ND6_OPTIMISTIC_DAD_AUTOCONF|
	ND6_OPTIMISTIC_DAD_TEMPORARY|ND6_OPTIMISTIC_DAD_DYNAMIC|
	ND6_OPTIMISTIC_DAD_SECURED|ND6_OPTIMISTIC_DAD_MANUAL);

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
 * ln_hold, ln_asked, ln_expire, ln_state, ln_router, ln_flags,
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
	.ln_next = &llinfo_nd6,
	.ln_prev = &llinfo_nd6,
};

/* Protected by nd_if_rwlock */
size_t nd_ifinfo_indexlim = 32; /* increased for 5589193 */
struct nd_ifinfo *nd_ifinfo = NULL;

static lck_grp_attr_t	*nd_if_lock_grp_attr;
static lck_grp_t	*nd_if_lock_grp;
static lck_attr_t	*nd_if_lock_attr;
decl_lck_rw_data(, nd_if_rwlock_data);
lck_rw_t		*nd_if_rwlock = &nd_if_rwlock_data;

/* Protected by nd6_mutex */
struct nd_drhead nd_defrouter;
struct nd_prhead nd_prefix = { 0 };

/*
 * nd6_timeout() is scheduled on a demand basis.  nd6_timeout_run is used
 * to indicate whether or not a timeout has been scheduled.  The rnh_lock
 * mutex is used to protect this scheduling; it is a natural choice given
 * the work done in the timer callback.  Unfortunately, there are cases
 * when nd6_timeout() needs to be scheduled while rnh_lock cannot be easily
 * held, due to lock ordering.  In those cases, we utilize a "demand" counter
 * nd6_sched_timeout_want which can be atomically incremented without
 * having to hold rnh_lock.  On places where we acquire rnh_lock, such as
 * nd6_rtrequest(), we check this counter and schedule the timer if it is
 * non-zero.  The increment happens on various places when we allocate
 * new ND entries, default routers, prefixes and addresses.
 */
static int nd6_timeout_run;		/* nd6_timeout is scheduled to run */
static void nd6_timeout(void *);
int nd6_sched_timeout_want;		/* demand count for timer to be sched */
static boolean_t nd6_fast_timer_on = FALSE;

/* Serialization variables for nd6_service(), protected by rnh_lock */
static boolean_t nd6_service_busy;
static void *nd6_service_wc = &nd6_service_busy;
static int nd6_service_waiters = 0;

int nd6_recalc_reachtm_interval = ND6_RECALC_REACHTM_INTERVAL;
static struct sockaddr_in6 all1_sa;

static int regen_tmpaddr(struct in6_ifaddr *);
extern lck_mtx_t *nd6_mutex;

static struct llinfo_nd6 *nd6_llinfo_alloc(int);
static void nd6_llinfo_free(void *);
static void nd6_llinfo_purge(struct rtentry *);
static void nd6_llinfo_get_ri(struct rtentry *, struct rt_reach_info *);
static void nd6_llinfo_get_iflri(struct rtentry *, struct ifnet_llreach_info *);
static uint64_t ln_getexpire(struct llinfo_nd6 *);

static void nd6_service(void *);
static void nd6_slowtimo(void *);
static int nd6_is_new_addr_neighbor(struct sockaddr_in6 *, struct ifnet *);
static int nd6_siocgdrlst(void *, int);
static int nd6_siocgprlst(void *, int);

static int nd6_sysctl_drlist SYSCTL_HANDLER_ARGS;
static int nd6_sysctl_prlist SYSCTL_HANDLER_ARGS;

/*
 * Insertion and removal from llinfo_nd6 must be done with rnh_lock held.
 */
#define	LN_DEQUEUE(_ln) do {						\
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);			\
	RT_LOCK_ASSERT_HELD((_ln)->ln_rt);				\
	(_ln)->ln_next->ln_prev = (_ln)->ln_prev;			\
	(_ln)->ln_prev->ln_next = (_ln)->ln_next;			\
	(_ln)->ln_prev = (_ln)->ln_next = NULL;				\
	(_ln)->ln_flags &= ~ND6_LNF_IN_USE;				\
} while (0)

#define	LN_INSERTHEAD(_ln) do {						\
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

extern int tvtohz(struct timeval *);

static int nd6_init_done;

SYSCTL_DECL(_net_inet6_icmp6);

SYSCTL_PROC(_net_inet6_icmp6, ICMPV6CTL_ND6_DRLIST, nd6_drlist,
	CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
	nd6_sysctl_drlist, "S,in6_defrouter", "");

SYSCTL_PROC(_net_inet6_icmp6, ICMPV6CTL_ND6_PRLIST, nd6_prlist,
	CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
	nd6_sysctl_prlist, "S,in6_defrouter", "");

void
nd6_init(void)
{
	int i;

	VERIFY(!nd6_init_done);

	all1_sa.sin6_family = AF_INET6;
	all1_sa.sin6_len = sizeof (struct sockaddr_in6);
	for (i = 0; i < sizeof (all1_sa.sin6_addr); i++)
		all1_sa.sin6_addr.s6_addr[i] = 0xff;

	/* initialization of the default router list */
	TAILQ_INIT(&nd_defrouter);

	nd_if_lock_grp_attr = lck_grp_attr_alloc_init();
	nd_if_lock_grp = lck_grp_alloc_init("nd_if_lock", nd_if_lock_grp_attr);
	nd_if_lock_attr = lck_attr_alloc_init();
	lck_rw_init(nd_if_rwlock, nd_if_lock_grp, nd_if_lock_attr);

	llinfo_nd6_zone = zinit(sizeof (struct llinfo_nd6),
	    LLINFO_ND6_ZONE_MAX * sizeof (struct llinfo_nd6), 0,
	    LLINFO_ND6_ZONE_NAME);
	if (llinfo_nd6_zone == NULL)
		panic("%s: failed allocating llinfo_nd6_zone", __func__);

	zone_change(llinfo_nd6_zone, Z_EXPAND, TRUE);
	zone_change(llinfo_nd6_zone, Z_CALLERACCT, FALSE);

	nd6_nbr_init();
	nd6_rtr_init();
	nd6_prproxy_init();

	nd6_init_done = 1;

	/* start timer */
	timeout(nd6_slowtimo, NULL, ND6_SLOWTIMER_INTERVAL * hz);
}

static struct llinfo_nd6 *
nd6_llinfo_alloc(int how)
{
	struct llinfo_nd6 *ln;

	ln = (how == M_WAITOK) ? zalloc(llinfo_nd6_zone) :
	    zalloc_noblock(llinfo_nd6_zone);
	if (ln != NULL)
		bzero(ln, sizeof (*ln));

	return (ln);
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
		ri->ri_rssi = IFNET_RSSI_UNKNOWN;
		ri->ri_lqm = IFNET_LQM_THRESH_OFF;
		ri->ri_npm = IFNET_NPM_THRESH_UNKNOWN;
	} else {
		IFLR_LOCK(lr);
		/* Export to rt_reach_info structure */
		ifnet_lr2ri(lr, ri);
		/* Export ND6 send expiration (calendar) time */
		ri->ri_snd_expire =
		    ifnet_llreach_up2calexp(lr, ln->ln_lastused);
		IFLR_UNLOCK(lr);
	}
}

static void
nd6_llinfo_get_iflri(struct rtentry *rt, struct ifnet_llreach_info *iflri)
{
	struct llinfo_nd6 *ln = rt->rt_llinfo;
	struct if_llreach *lr = ln->ln_llreach;

	if (lr == NULL) {
		bzero(iflri, sizeof (*iflri));
		iflri->iflri_rssi = IFNET_RSSI_UNKNOWN;
		iflri->iflri_lqm = IFNET_LQM_THRESH_OFF;
		iflri->iflri_npm = IFNET_NPM_THRESH_UNKNOWN;
	} else {
		IFLR_LOCK(lr);
		/* Export to ifnet_llreach_info structure */
		ifnet_lr2iflri(lr, iflri);
		/* Export ND6 send expiration (uptime) time */
		iflri->iflri_snd_expire =
		    ifnet_llreach_up2upexp(lr, ln->ln_lastused);
		IFLR_UNLOCK(lr);
	}
}

void
ln_setexpire(struct llinfo_nd6 *ln, uint64_t expiry)
{
	ln->ln_expire = expiry;
}

static uint64_t
ln_getexpire(struct llinfo_nd6 *ln)
{
	struct timeval caltime;
	uint64_t expiry;

	if (ln->ln_expire != 0) {
		struct rtentry *rt = ln->ln_rt;

		VERIFY(rt != NULL);
		/* account for system time change */
		getmicrotime(&caltime);

		rt->base_calendartime +=
		    NET_CALCULATE_CLOCKSKEW(caltime,
		    rt->base_calendartime, net_uptime(), rt->base_uptime);

		expiry = rt->base_calendartime +
		    ln->ln_expire - rt->base_uptime;
	} else {
		expiry = 0;
	}
	return (expiry);
}

void
nd6_ifreset(struct ifnet *ifp)
{
	struct nd_ifinfo *ndi;

	lck_rw_assert(nd_if_rwlock, LCK_RW_ASSERT_HELD);
	VERIFY(ifp != NULL && ifp->if_index < nd_ifinfo_indexlim);
	ndi = &nd_ifinfo[ifp->if_index];

	VERIFY(ndi->initialized);
	lck_mtx_assert(&ndi->lock, LCK_MTX_ASSERT_OWNED);
	ndi->linkmtu = ifp->if_mtu;
	ndi->chlim = IPV6_DEFHLIM;
	ndi->basereachable = REACHABLE_TIME;
	ndi->reachable = ND_COMPUTE_RTIME(ndi->basereachable);
	ndi->retrans = RETRANS_TIMER;
}

int
nd6_ifattach(struct ifnet *ifp)
{
	size_t newlim;
	struct nd_ifinfo *ndi;

	/*
	 * We have some arrays that should be indexed by if_index.
	 * since if_index will grow dynamically, they should grow too.
	 */
	lck_rw_lock_shared(nd_if_rwlock);
	newlim = nd_ifinfo_indexlim;
	if (nd_ifinfo == NULL || if_index >= newlim) {
		if (!lck_rw_lock_shared_to_exclusive(nd_if_rwlock))
			lck_rw_lock_exclusive(nd_if_rwlock);
		lck_rw_assert(nd_if_rwlock, LCK_RW_ASSERT_EXCLUSIVE);

		newlim = nd_ifinfo_indexlim;
		if (nd_ifinfo == NULL || if_index >= newlim) {
			size_t n;
			caddr_t q;

			while (if_index >= newlim)
				newlim <<= 1;

			/* grow nd_ifinfo */
			n = newlim * sizeof (struct nd_ifinfo);
			q = (caddr_t)_MALLOC(n, M_IP6NDP, M_WAITOK);
			if (q == NULL) {
				lck_rw_done(nd_if_rwlock);
				return (ENOBUFS);
			}
			bzero(q, n);
			if (nd_ifinfo != NULL) {
				bcopy((caddr_t)nd_ifinfo, q, n/2);
				/*
				 * We might want to pattern fill the old
				 * array to catch use-after-free cases.
				 */
				FREE((caddr_t)nd_ifinfo, M_IP6NDP);
			}
			nd_ifinfo = (struct nd_ifinfo *)(void *)q;
			nd_ifinfo_indexlim = newlim;
		}
	}

	VERIFY(ifp != NULL);
	ndi = &nd_ifinfo[ifp->if_index];
	if (!ndi->initialized) {
		lck_mtx_init(&ndi->lock, nd_if_lock_grp, nd_if_lock_attr);
		ndi->flags = ND6_IFF_PERFORMNUD;
		ndi->initialized = TRUE;
	}

	lck_mtx_lock(&ndi->lock);

	if (!(ifp->if_flags & IFF_MULTICAST))
		ndi->flags |= ND6_IFF_IFDISABLED;

	nd6_ifreset(ifp);
	lck_mtx_unlock(&ndi->lock);

	lck_rw_done(nd_if_rwlock);

	nd6_setmtu(ifp);

	return (0);
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
	if (ifp->if_index >= nd_ifinfo_indexlim ||
	    !nd_ifinfo[ifp->if_index].initialized) {
		lck_rw_done(nd_if_rwlock);
		return; /* nd_ifinfo out of bound, or not yet initialized */
	}

	ndi = &nd_ifinfo[ifp->if_index];
	VERIFY(ndi->initialized);
	lck_mtx_lock(&ndi->lock);
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
		    "new link MTU on %s (%u) is too small for IPv6\n",
		    if_name(ifp), (uint32_t)ndi->maxmtu);
	}
	ndi->linkmtu = ifp->if_mtu;
	lck_mtx_unlock(&ndi->lock);
	lck_rw_done(nd_if_rwlock);

	/* also adjust in6_maxmtu if necessary. */
	if (maxmtu > in6_maxmtu)
		in6_setmaxmtu();
}

void
nd6_option_init(void *opt, int icmp6len, union nd_opts *ndopts)
{
	bzero(ndopts, sizeof (*ndopts));
	ndopts->nd_opts_search = (struct nd_opt_hdr *)opt;
	ndopts->nd_opts_last =
	    (struct nd_opt_hdr *)(((u_char *)opt) + icmp6len);

	if (icmp6len == 0) {
		ndopts->nd_opts_done = 1;
		ndopts->nd_opts_search = NULL;
	}
}

/*
 * Take one ND option.
 */
struct nd_opt_hdr *
nd6_option(union nd_opts *ndopts)
{
	struct nd_opt_hdr *nd_opt;
	int olen;

	if (!ndopts)
		panic("ndopts == NULL in nd6_option\n");
	if (!ndopts->nd_opts_last)
		panic("uninitialized ndopts in nd6_option\n");
	if (!ndopts->nd_opts_search)
		return (NULL);
	if (ndopts->nd_opts_done)
		return (NULL);

	nd_opt = ndopts->nd_opts_search;

	/* make sure nd_opt_len is inside the buffer */
	if ((caddr_t)&nd_opt->nd_opt_len >= (caddr_t)ndopts->nd_opts_last) {
		bzero(ndopts, sizeof (*ndopts));
		return (NULL);
	}

	olen = nd_opt->nd_opt_len << 3;
	if (olen == 0) {
		/*
		 * Message validation requires that all included
		 * options have a length that is greater than zero.
		 */
		bzero(ndopts, sizeof (*ndopts));
		return (NULL);
	}

	ndopts->nd_opts_search = (struct nd_opt_hdr *)((caddr_t)nd_opt + olen);
	if (ndopts->nd_opts_search > ndopts->nd_opts_last) {
		/* option overruns the end of buffer, invalid */
		bzero(ndopts, sizeof (*ndopts));
		return (NULL);
	} else if (ndopts->nd_opts_search == ndopts->nd_opts_last) {
		/* reached the end of options chain */
		ndopts->nd_opts_done = 1;
		ndopts->nd_opts_search = NULL;
	}
	return (nd_opt);
}

/*
 * Parse multiple ND options.
 * This function is much easier to use, for ND routines that do not need
 * multiple options of the same type.
 */
int
nd6_options(union nd_opts *ndopts)
{
	struct nd_opt_hdr *nd_opt;
	int i = 0;

	if (ndopts == NULL)
		panic("ndopts == NULL in nd6_options");
	if (ndopts->nd_opts_last == NULL)
		panic("uninitialized ndopts in nd6_options");
	if (ndopts->nd_opts_search == NULL)
		return (0);

	while (1) {
		nd_opt = nd6_option(ndopts);
		if (nd_opt == NULL && ndopts->nd_opts_last == NULL) {
			/*
			 * Message validation requires that all included
			 * options have a length that is greater than zero.
			 */
			icmp6stat.icp6s_nd_badopt++;
			bzero(ndopts, sizeof (*ndopts));
			return (-1);
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
				ndopts->nd_opt_array[nd_opt->nd_opt_type] =
				    nd_opt;
			}
			break;
		case ND_OPT_PREFIX_INFORMATION:
			if (ndopts->nd_opt_array[nd_opt->nd_opt_type] == 0) {
				ndopts->nd_opt_array[nd_opt->nd_opt_type] =
				    nd_opt;
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

	return (0);
}

struct nd6svc_arg {
	int draining;
	uint32_t killed;
	uint32_t aging_lazy;
	uint32_t aging;
	uint32_t sticky;
	uint32_t found;
};

/*
 * ND6 service routine to expire default route list and prefix list
 */
static void
nd6_service(void *arg)
{
	struct nd6svc_arg *ap = arg;
	struct llinfo_nd6 *ln;
	struct nd_defrouter *dr;
	struct nd_prefix *pr;
	struct ifnet *ifp = NULL;
	struct in6_ifaddr *ia6, *nia6;
	uint64_t timenow;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	/*
	 * Since we may drop rnh_lock and nd6_mutex below, we want
	 * to run this entire operation single threaded.
	 */
	while (nd6_service_busy) {
		nd6log2((LOG_DEBUG, "%s: %s is blocked by %d waiters\n",
		    __func__, ap->draining ? "drainer" : "timer",
		    nd6_service_waiters));
		nd6_service_waiters++;
		(void) msleep(nd6_service_wc, rnh_lock, (PZERO-1),
		    __func__, NULL);
		lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	}

	/* We are busy now; tell everyone else to go away */
	nd6_service_busy = TRUE;

	net_update_uptime();
	timenow = net_uptime();
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
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	ln = llinfo_nd6.ln_next;
	while (ln != NULL && ln != &llinfo_nd6) {
		struct rtentry *rt;
		struct sockaddr_in6 *dst;
		struct llinfo_nd6 *next;
		u_int32_t retrans, flags;

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
		ap->found++;

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
		dst = SIN6(rt_key(rt));
		if (dst == NULL) {
			panic("%s: rt(%p) key is NULL ln(%p)", __func__,
			    rt, ln);
			/* NOTREACHED */
		}

		/* Set the flag in case we jump to "again" */
		ln->ln_flags |= ND6_LNF_TIMER_SKIP;

		if (ln->ln_expire == 0 || (rt->rt_flags & RTF_STATIC)) {
			ap->sticky++;
		} else if (ap->draining && (rt->rt_refcnt == 0)) {
			/*
			 * If we are draining, immediately purge non-static
			 * entries without oustanding route refcnt.
			 */
			if (ln->ln_state > ND6_LLINFO_INCOMPLETE)
				ln->ln_state = ND6_LLINFO_STALE;
			else
				ln->ln_state = ND6_LLINFO_PURGE;
			ln_setexpire(ln, timenow);
		}

		/*
		 * If the entry has not expired, skip it.  Take note on the
		 * state, as entries that are in the STALE state are simply
		 * waiting to be garbage collected, in which case we can
		 * relax the callout scheduling (use nd6_prune_lazy).
		 */
		if (ln->ln_expire > timenow) {
			switch (ln->ln_state) {
			case ND6_LLINFO_STALE:
				ap->aging_lazy++;
				break;
			default:
				ap->aging++;
				break;
			}
			RT_UNLOCK(rt);
			ln = next;
			continue;
		}

		lck_rw_lock_shared(nd_if_rwlock);
		if (ifp->if_index >= nd_ifinfo_indexlim) {
			/*
			 * In the event the nd_ifinfo[] array is not in synch
			 * by now, we don't want to hold on to the llinfo entry
			 * forever; just purge it rather than have it consume
			 * resources.  That's better than transmitting out of
			 * the interface as the rest of the layers may not be
			 * ready as well.
			 *
			 * We can retire this logic once we get rid of the
			 * separate array and utilize a per-ifnet structure.
			 */
			retrans = RETRANS_TIMER;
			flags = ND6_IFF_PERFORMNUD;
			if (ln->ln_expire != 0) {
				ln->ln_state = ND6_LLINFO_PURGE;
				log (LOG_ERR, "%s: purging rt(0x%llx) "
				    "ln(0x%llx) dst %s, if_index %d >= %d\n",
				    __func__, (uint64_t)VM_KERNEL_ADDRPERM(rt),
				    (uint64_t)VM_KERNEL_ADDRPERM(ln),
				    ip6_sprintf(&dst->sin6_addr), ifp->if_index,
				    nd_ifinfo_indexlim);
			}
		} else {
			struct nd_ifinfo *ndi = ND_IFINFO(ifp);
			VERIFY(ndi->initialized);
			retrans = ndi->retrans;
			flags = ndi->flags;
		}
		lck_rw_done(nd_if_rwlock);

		RT_LOCK_ASSERT_HELD(rt);

		switch (ln->ln_state) {
		case ND6_LLINFO_INCOMPLETE:
			if (ln->ln_asked < nd6_mmaxtries) {
				struct ifnet *exclifp = ln->ln_exclifp;
				ln->ln_asked++;
				ln_setexpire(ln, timenow + retrans / 1000);
				RT_ADDREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				if (ip6_forwarding) {
					nd6_prproxy_ns_output(ifp, exclifp,
					    NULL, &dst->sin6_addr, ln);
				} else {
					nd6_ns_output(ifp, NULL,
					    &dst->sin6_addr, ln, 0);
				}
				RT_REMREF(rt);
				ap->aging++;
				lck_mtx_lock(rnh_lock);
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
					RT_ADDREF_LOCKED(rt);
					RT_UNLOCK(rt);
					lck_mtx_unlock(rnh_lock);
					icmp6_error(m, ICMP6_DST_UNREACH,
					    ICMP6_DST_UNREACH_ADDR, 0);
				} else {
					RT_ADDREF_LOCKED(rt);
					RT_UNLOCK(rt);
					lck_mtx_unlock(rnh_lock);
				}
				nd6_free(rt);
				ap->killed++;
				lck_mtx_lock(rnh_lock);
				rtfree_locked(rt);
			}
			lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
			goto again;

		case ND6_LLINFO_REACHABLE:
			if (ln->ln_expire != 0) {
				ln->ln_state = ND6_LLINFO_STALE;
				ln_setexpire(ln, timenow + nd6_gctimer);
				ap->aging_lazy++;
			}
			RT_UNLOCK(rt);
			break;

		case ND6_LLINFO_STALE:
		case ND6_LLINFO_PURGE:
			/* Garbage Collection(RFC 4861 5.3) */
			if (ln->ln_expire != 0) {
				RT_ADDREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_free(rt);
				ap->killed++;
				lck_mtx_lock(rnh_lock);
				rtfree_locked(rt);
				goto again;
			} else {
				RT_UNLOCK(rt);
			}
			break;

		case ND6_LLINFO_DELAY:
			if ((flags & ND6_IFF_PERFORMNUD) != 0) {
				/* We need NUD */
				ln->ln_asked = 1;
				ln->ln_state = ND6_LLINFO_PROBE;
				ln_setexpire(ln, timenow + retrans / 1000);
				RT_ADDREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_ns_output(ifp, &dst->sin6_addr,
				    &dst->sin6_addr, ln, 0);
				RT_REMREF(rt);
				ap->aging++;
				lck_mtx_lock(rnh_lock);
				goto again;
			}
			ln->ln_state = ND6_LLINFO_STALE; /* XXX */
			ln_setexpire(ln, timenow + nd6_gctimer);
			RT_UNLOCK(rt);
			ap->aging_lazy++;
			break;

		case ND6_LLINFO_PROBE:
			if (ln->ln_asked < nd6_umaxtries) {
				ln->ln_asked++;
				ln_setexpire(ln, timenow + retrans / 1000);
				RT_ADDREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_ns_output(ifp, &dst->sin6_addr,
				    &dst->sin6_addr, ln, 0);
				RT_REMREF(rt);
				ap->aging++;
				lck_mtx_lock(rnh_lock);
			} else {
				RT_ADDREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				nd6_free(rt);
				ap->killed++;
				lck_mtx_lock(rnh_lock);
				rtfree_locked(rt);
			}
			lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
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
		ap->found++;
		if (dr->expire != 0 && dr->expire < timenow) {
			struct nd_defrouter *t;
			t = TAILQ_NEXT(dr, dr_entry);
			defrtrlist_del(dr);
			dr = t;
			ap->killed++;
		} else {
			if (dr->expire == 0 || (dr->stateflags & NDDRF_STATIC))
				ap->sticky++;
			else
				ap->aging_lazy++;
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
		ap->found++;
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
		if (IFA6_IS_INVALID(ia6, timenow)) {
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
				/*
				 * NOTE: We have to drop the lock here
				 * because regen_tmpaddr() eventually calls
				 * in6_update_ifa(), which must take the lock
				 * and would otherwise cause a hang.  This is
				 * safe because the goto addrloop leads to a
				 * re-evaluation of the in6_ifaddrs list
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
			ap->killed++;

			/* Release extra reference taken above */
			IFA_REMREF(&ia6->ia_ifa);
			goto addrloop;
		}
		/*
		 * The lazy timer runs every nd6_prune_lazy seconds with at
		 * most "2 * nd6_prune_lazy - 1" leeway. We consider the worst
		 * case here and make sure we schedule the regular timer if an
		 * interface address is about to expire.
		 */
		if (IFA6_IS_INVALID(ia6, timenow + 3 * nd6_prune_lazy))
			ap->aging++;
		else
			ap->aging_lazy++;
		IFA_LOCK_ASSERT_HELD(&ia6->ia_ifa);
		if (IFA6_IS_DEPRECATED(ia6, timenow)) {
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
	/* expire prefix list */
	pr = nd_prefix.lh_first;
	while (pr != NULL) {
		ap->found++;
		/*
		 * check prefix lifetime.
		 * since pltime is just for autoconf, pltime processing for
		 * prefix is not necessary.
		 */
		NDPR_LOCK(pr);
		if (pr->ndpr_stateflags & NDPRF_PROCESSED_SERVICE ||
		    pr->ndpr_stateflags & NDPRF_DEFUNCT) {
			pr->ndpr_stateflags |= NDPRF_PROCESSED_SERVICE;
			NDPR_UNLOCK(pr);
			pr = pr->ndpr_next;
			continue;
		}
		if (pr->ndpr_expire != 0 && pr->ndpr_expire < timenow) {
			/*
			 * address expiration and prefix expiration are
			 * separate.  NEVER perform in6_purgeaddr here.
			 */
			pr->ndpr_stateflags |= NDPRF_PROCESSED_SERVICE;
			NDPR_ADDREF_LOCKED(pr);
			prelist_remove(pr);
			NDPR_UNLOCK(pr);
			NDPR_REMREF(pr);
			pfxlist_onlink_check();
			pr = nd_prefix.lh_first;
			ap->killed++;
		} else {
			if (pr->ndpr_expire == 0 ||
			    (pr->ndpr_stateflags & NDPRF_STATIC))
				ap->sticky++;
			else
				ap->aging_lazy++;
			pr->ndpr_stateflags |= NDPRF_PROCESSED_SERVICE;
			NDPR_UNLOCK(pr);
			pr = pr->ndpr_next;
		}
	}
	LIST_FOREACH(pr, &nd_prefix, ndpr_entry) {
		NDPR_LOCK(pr);
		pr->ndpr_stateflags &= ~NDPRF_PROCESSED_SERVICE;
		NDPR_UNLOCK(pr);
	}
	lck_mtx_unlock(nd6_mutex);

	lck_mtx_lock(rnh_lock);
	/* We're done; let others enter */
	nd6_service_busy = FALSE;
	if (nd6_service_waiters > 0) {
		nd6_service_waiters = 0;
		wakeup(nd6_service_wc);
	}
}

void
nd6_drain(void *arg)
{
#pragma unused(arg)
	struct nd6svc_arg sarg;

	nd6log2((LOG_DEBUG, "%s: draining ND6 entries\n", __func__));

	lck_mtx_lock(rnh_lock);
	bzero(&sarg, sizeof (sarg));
	sarg.draining = 1;
	nd6_service(&sarg);
	nd6log2((LOG_DEBUG, "%s: found %u, aging_lazy %u, aging %u, "
	    "sticky %u, killed %u\n", __func__, sarg.found, sarg.aging_lazy,
	    sarg.aging, sarg.sticky, sarg.killed));
	lck_mtx_unlock(rnh_lock);
}

/*
 * We use the ``arg'' variable to decide whether or not the timer we're
 * running is the fast timer. We do this to reset the nd6_fast_timer_on
 * variable so that later we don't end up ignoring a ``fast timer'' 
 * request if the 5 second timer is running (see nd6_sched_timeout).
 */
static void
nd6_timeout(void *arg)
{
	struct nd6svc_arg sarg;
	uint32_t buf;

	lck_mtx_lock(rnh_lock);
	bzero(&sarg, sizeof (sarg));
	nd6_service(&sarg);
	nd6log2((LOG_DEBUG, "%s: found %u, aging_lazy %u, aging %u, "
	    "sticky %u, killed %u\n", __func__, sarg.found, sarg.aging_lazy,
	    sarg.aging, sarg.sticky, sarg.killed));
	/* re-arm the timer if there's work to do */
	nd6_timeout_run--;
	VERIFY(nd6_timeout_run >= 0 && nd6_timeout_run < 2);
	if (arg == &nd6_fast_timer_on)
		nd6_fast_timer_on = FALSE;
	if (sarg.aging_lazy > 0 || sarg.aging > 0 || nd6_sched_timeout_want) {
		struct timeval atv, ltv, *leeway;
		int lazy = nd6_prune_lazy;

		if (sarg.aging > 0 || lazy < 1) {
			atv.tv_usec = 0;
			atv.tv_sec = nd6_prune;
			leeway = NULL;
		} else {
			VERIFY(lazy >= 1);
			atv.tv_usec = 0;
			atv.tv_sec = MAX(nd6_prune, lazy);
			ltv.tv_usec = 0;
			read_frandom(&buf, sizeof(buf));
			ltv.tv_sec = MAX(buf % lazy, 1) * 2;
			leeway = &ltv;
		}
		nd6_sched_timeout(&atv, leeway);
	} else if (nd6_debug) {
		nd6log2((LOG_DEBUG, "%s: not rescheduling timer\n", __func__));
	}
	lck_mtx_unlock(rnh_lock);
}

void
nd6_sched_timeout(struct timeval *atv, struct timeval *ltv)
{
	struct timeval tv;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	if (atv == NULL) {
		tv.tv_usec = 0;
		tv.tv_sec = MAX(nd6_prune, 1);
		atv = &tv;
		ltv = NULL;	/* ignore leeway */
	}
	/* see comments on top of this file */
	if (nd6_timeout_run == 0) {
		if (ltv == NULL) {
			nd6log2((LOG_DEBUG, "%s: timer scheduled in "
			    "T+%llus.%lluu (demand %d)\n", __func__,
			    (uint64_t)atv->tv_sec, (uint64_t)atv->tv_usec,
			    nd6_sched_timeout_want));
			nd6_fast_timer_on = TRUE;
			timeout(nd6_timeout, &nd6_fast_timer_on, tvtohz(atv));
		} else {
			nd6log2((LOG_DEBUG, "%s: timer scheduled in "
			    "T+%llus.%lluu with %llus.%lluu leeway "
			    "(demand %d)\n", __func__, (uint64_t)atv->tv_sec,
			    (uint64_t)atv->tv_usec, (uint64_t)ltv->tv_sec,
			    (uint64_t)ltv->tv_usec, nd6_sched_timeout_want));
			nd6_fast_timer_on = FALSE;
			timeout_with_leeway(nd6_timeout, NULL,
			    tvtohz(atv), tvtohz(ltv));
		}
		nd6_timeout_run++;
		nd6_sched_timeout_want = 0;
	} else if (nd6_timeout_run == 1 && ltv == NULL && 
	    nd6_fast_timer_on == FALSE) {
		nd6log2((LOG_DEBUG, "%s: fast timer scheduled in "
		    "T+%llus.%lluu (demand %d)\n", __func__,
		    (uint64_t)atv->tv_sec, (uint64_t)atv->tv_usec,
		    nd6_sched_timeout_want));
		nd6_fast_timer_on = TRUE;
		nd6_sched_timeout_want = 0;
		nd6_timeout_run++;
		timeout(nd6_timeout, &nd6_fast_timer_on, tvtohz(atv));
	} else {
		if (ltv == NULL) {
			nd6log2((LOG_DEBUG, "%s: not scheduling timer: "
			    "timers %d, fast_timer %d, T+%llus.%lluu\n",
			    __func__, nd6_timeout_run, nd6_fast_timer_on,
			    (uint64_t)atv->tv_sec, (uint64_t)atv->tv_usec));
		} else {
			nd6log2((LOG_DEBUG, "%s: not scheduling timer: "
			    "timers %d, fast_timer %d, T+%llus.%lluu "
			    "with %llus.%lluu leeway\n", __func__,
			    nd6_timeout_run, nd6_fast_timer_on,
			    (uint64_t)atv->tv_sec, (uint64_t)atv->tv_usec,
			    (uint64_t)ltv->tv_sec, (uint64_t)ltv->tv_usec));
		}
	}
}

/*
 * ND6 router advertisement kernel notification
 */
void
nd6_post_msg(u_int32_t code, struct nd_prefix_list *prefix_list,
    u_int32_t list_length, u_int32_t mtu, char *dl_addr, u_int32_t dl_addr_len)
{
	struct kev_msg ev_msg;
	struct kev_nd6_ra_data nd6_ra_msg_data;
	struct nd_prefix_list *itr = prefix_list;

	bzero(&ev_msg, sizeof (struct kev_msg));
	ev_msg.vendor_code	= KEV_VENDOR_APPLE;
	ev_msg.kev_class	= KEV_NETWORK_CLASS;
	ev_msg.kev_subclass	= KEV_ND6_SUBCLASS;
	ev_msg.event_code	= code;

	bzero(&nd6_ra_msg_data, sizeof (nd6_ra_msg_data));
	nd6_ra_msg_data.lladdrlen = (dl_addr_len <= ND6_ROUTER_LL_SIZE) ?
	    dl_addr_len : ND6_ROUTER_LL_SIZE;
	bcopy(dl_addr, &nd6_ra_msg_data.lladdr, nd6_ra_msg_data.lladdrlen);

	if (mtu > 0 && mtu >= IPV6_MMTU) {
		nd6_ra_msg_data.mtu = mtu;
		nd6_ra_msg_data.flags |= KEV_ND6_DATA_VALID_MTU;
	}

	if (list_length > 0 && prefix_list != NULL) {
		nd6_ra_msg_data.list_length = list_length;
		nd6_ra_msg_data.flags |= KEV_ND6_DATA_VALID_PREFIX;
	}

	while (itr != NULL && nd6_ra_msg_data.list_index < list_length) {
		bcopy(&itr->pr.ndpr_prefix, &nd6_ra_msg_data.prefix.prefix,
		    sizeof (nd6_ra_msg_data.prefix.prefix));
		nd6_ra_msg_data.prefix.raflags = itr->pr.ndpr_raf;
		nd6_ra_msg_data.prefix.prefixlen = itr->pr.ndpr_plen;
		nd6_ra_msg_data.prefix.origin = PR_ORIG_RA;
		nd6_ra_msg_data.prefix.vltime = itr->pr.ndpr_vltime;
		nd6_ra_msg_data.prefix.pltime = itr->pr.ndpr_pltime;
		nd6_ra_msg_data.prefix.expire = ndpr_getexpire(&itr->pr);
		nd6_ra_msg_data.prefix.flags = itr->pr.ndpr_stateflags;
		nd6_ra_msg_data.prefix.refcnt = itr->pr.ndpr_addrcnt;
		nd6_ra_msg_data.prefix.if_index = itr->pr.ndpr_ifp->if_index;

		/* send the message up */
		ev_msg.dv[0].data_ptr		= &nd6_ra_msg_data;
		ev_msg.dv[0].data_length	= sizeof (nd6_ra_msg_data);
		ev_msg.dv[1].data_length	= 0;
		kev_post_msg(&ev_msg);

		/* clean up for the next prefix */
		bzero(&nd6_ra_msg_data.prefix, sizeof (nd6_ra_msg_data.prefix));
		itr = itr->next;
		nd6_ra_msg_data.list_index++;
	}
}

/*
 * Regenerate deprecated/invalidated temporary address
 */
static int
regen_tmpaddr(struct in6_ifaddr *ia6)
{
	struct ifaddr *ifa;
	struct ifnet *ifp;
	struct in6_ifaddr *public_ifa6 = NULL;
	uint64_t timenow = net_uptime();

	ifp = ia6->ia_ifa.ifa_ifp;
	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
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
		    !IFA6_IS_DEPRECATED(it6, timenow)) {
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
		if (!IFA6_IS_DEPRECATED(it6, timenow)) {
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

		if ((e = in6_tmpifadd(public_ifa6, 0)) != 0) {
			log(LOG_NOTICE, "regen_tmpaddr: failed to create a new"
			    " tmp addr,errno=%d\n", e);
			IFA_REMREF(&public_ifa6->ia_ifa);
			return (-1);
		}
		IFA_REMREF(&public_ifa6->ia_ifa);
		return (0);
	}

	return (-1);
}

/*
 * Nuke neighbor cache/prefix/default router management table, right before
 * ifp goes away.
 */
void
nd6_purge(struct ifnet *ifp)
{
	struct llinfo_nd6 *ln;
	struct nd_defrouter *dr, *ndr;
	struct nd_prefix *pr, *npr;
	boolean_t removed;

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
	removed = FALSE;
	for (pr = nd_prefix.lh_first; pr; pr = npr) {
		NDPR_LOCK(pr);
		npr = pr->ndpr_next;
		if (pr->ndpr_ifp == ifp && 
		    !(pr->ndpr_stateflags & NDPRF_DEFUNCT)) {
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
			removed = TRUE;
			npr = nd_prefix.lh_first;
		} else {
			NDPR_UNLOCK(pr);
		}
	}
	if (removed)
		pfxlist_onlink_check();
	lck_mtx_unlock(nd6_mutex);

	/* cancel default outgoing interface setting */
	if (nd6_defifindex == ifp->if_index) {
		nd6_setdefaultiface(0);
	}

	/*
	 * Perform default router selection even when we are a router,
	 * if Scoped Routing is enabled.
	 */
	if (ip6_doscopedroute || !ip6_forwarding) {
		lck_mtx_lock(nd6_mutex);
		/* refresh default router list */
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
			RT_ADDREF_LOCKED(rt);
			RT_UNLOCK(rt);
			lck_mtx_unlock(rnh_lock);
			/*
			 * See comments on nd6_service() for reasons why
			 * this loop is repeated; we bite the costs of
			 * going thru the same llinfo_nd6 more than once
			 * here, since this purge happens during detach,
			 * and that unlike the timer case, it's possible
			 * there's more than one purges happening at the
			 * same time (thus a flag wouldn't buy anything).
			 */
			nd6_free(rt);
			RT_REMREF(rt);
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
nd6_lookup(struct in6_addr *addr6, int create, struct ifnet *ifp, int rt_locked)
{
	struct rtentry *rt;
	struct sockaddr_in6 sin6;
	unsigned int ifscope;

	bzero(&sin6, sizeof (sin6));
	sin6.sin6_len = sizeof (struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = *addr6;

	ifscope = (ifp != NULL) ? ifp->if_index : IFSCOPE_NONE;
	if (rt_locked) {
		lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
		rt = rtalloc1_scoped_locked(SA(&sin6), create, 0, ifscope);
	} else {
		rt = rtalloc1_scoped(SA(&sin6), create, 0, ifscope);
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
			ifa = ifaof_ifpforaddr(SA(&sin6), ifp);
			if (ifa == NULL)
				return (NULL);

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
			    SA(&sin6), ifa->ifa_addr, SA(&all1_sa),
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
				return (NULL);

			RT_LOCK(rt);
			if (rt->rt_llinfo) {
				struct llinfo_nd6 *ln = rt->rt_llinfo;
				ln->ln_state = ND6_LLINFO_NOSTATE;
			}
		} else {
			return (NULL);
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
	 *	it might be the loopback interface if the entry is for our
	 *	own address on a non-loopback interface. Instead, we should
	 *	use rt->rt_ifa->ifa_ifp, which would specify the REAL
	 *	interface.
	 * Note also that ifa_ifp and ifp may differ when we connect two
	 * interfaces to a same link, install a link prefix to an interface,
	 * and try to install a neighbor cache on an interface that does not
	 * have a route to the prefix.
	 *
	 * If the address is from a proxied prefix, the ifa_ifp and ifp might
	 * not match, because nd6_na_input() could have modified the ifp
	 * of the route to point to the interface where the NA arrived on,
	 * hence the test for RTF_PROXY.
	 */
	if ((rt->rt_flags & RTF_GATEWAY) || (rt->rt_flags & RTF_LLINFO) == 0 ||
	    rt->rt_gateway->sa_family != AF_LINK || rt->rt_llinfo == NULL ||
	    (ifp && rt->rt_ifa->ifa_ifp != ifp &&
	    !(rt->rt_flags & RTF_PROXY))) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		if (create) {
			log(LOG_DEBUG, "%s: failed to lookup %s "
			    "(if = %s)\n", __func__, ip6_sprintf(addr6),
			    ifp ? if_name(ifp) : "unspec");
			/* xxx more logs... kazu */
		}
		return (NULL);
	}
	/*
	 * Caller needs to release reference and call RT_UNLOCK(rt).
	 */
	return (rt);
}

/*
 * Test whether a given IPv6 address is a neighbor or not, ignoring
 * the actual neighbor cache.  The neighbor cache is ignored in order
 * to not reenter the routing code from within itself.
 */
static int
nd6_is_new_addr_neighbor(struct sockaddr_in6 *addr, struct ifnet *ifp)
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
		if (sa6_recoverscope(&sin6_copy, FALSE))
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
	dstaddr = ifa_ifwithdstaddr(SA(addr));
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
	 * XXX: this block should eventually be removed (it is disabled when
	 * Scoped Routing is in effect); treating all destinations as on-link
	 * in the absence of a router is rather harmful.
	 */
	if (!ip6_doscopedroute && !ip6_forwarding &&
	    TAILQ_FIRST(&nd_defrouter) == NULL &&
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
nd6_is_addr_neighbor(struct sockaddr_in6 *addr, struct ifnet *ifp,
    int rt_locked)
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
nd6_free(struct rtentry *rt)
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
	in6 = SIN6(rt_key(rt))->sin6_addr;

	/*
	 * Prevent another thread from modifying rt_key, rt_gateway
	 * via rt_setgate() after the rt_lock is dropped by marking
	 * the route as defunct.
	 */
	rt->rt_flags |= RTF_CONDEMNED;

	/*
	 * We used to have pfctlinput(PRC_HOSTDEAD) here.  Even though it is
	 * not harmful, it was not really necessary.  Perform default router
	 * selection even when we are a router, if Scoped Routing is enabled.
	 */
	if (ip6_doscopedroute || !ip6_forwarding) {
		dr = defrouter_lookup(&SIN6(rt_key(rt))->sin6_addr, rt->rt_ifp);

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
	(void) rtrequest(RTM_DELETE, rt_key(rt), NULL, rt_mask(rt), 0, NULL);

	/* Extra ref held above; now free it */
	rtfree(rt);
}

void
nd6_rtrequest(int req, struct rtentry *rt, struct sockaddr *sa)
{
#pragma unused(sa)
	struct sockaddr *gate = rt->rt_gateway;
	struct llinfo_nd6 *ln = rt->rt_llinfo;
	static struct sockaddr_dl null_sdl =
	    { .sdl_len = sizeof (null_sdl), .sdl_family = AF_LINK };
	struct ifnet *ifp = rt->rt_ifp;
	struct ifaddr *ifa;
	uint64_t timenow;
	char buf[MAX_IPv6_STR_LEN];

	VERIFY(nd6_init_done);
	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	/*
	 * We have rnh_lock held, see if we need to schedule the timer;
	 * we might do this again below during RTM_RESOLVE, but doing it
	 * now handles all other cases.
	 */
	if (nd6_sched_timeout_want)
		nd6_sched_timeout(NULL, NULL);

	if (rt->rt_flags & RTF_GATEWAY)
		return;

	if (!nd6_need_cache(ifp) && !(rt->rt_flags & RTF_HOST)) {
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

	timenow = net_uptime();

	switch (req) {
	case RTM_ADD:
		/*
		 * There is no backward compatibility :)
		 *
		 * if ((rt->rt_flags & RTF_HOST) == 0 &&
		 * 	SIN(rt_mask(rt))->sin_addr.s_addr != 0xffffffff)
		 * 		rt->rt_flags |= RTF_CLONING;
		 */
		if ((rt->rt_flags & RTF_CLONING) ||
		    ((rt->rt_flags & RTF_LLINFO) && ln == NULL)) {
			/*
			 * Case 1: This route should come from a route to
			 * interface (RTF_CLONING case) or the route should be
			 * treated as on-link but is currently not
			 * (RTF_LLINFO && ln == NULL case).
			 */
			if (rt_setgate(rt, rt_key(rt), SA(&null_sdl)) == 0) {
				gate = rt->rt_gateway;
				SDL(gate)->sdl_type = ifp->if_type;
				SDL(gate)->sdl_index = ifp->if_index;
				/*
				 * In case we're called before 1.0 sec.
				 * has elapsed.
				 */
				if (ln != NULL) {
					ln_setexpire(ln,
					    (ifp->if_eflags & IFEF_IPV6_ND6ALT)
					    ? 0 : MAX(timenow, 1));
				}
			}
			if (rt->rt_flags & RTF_CLONING)
				break;
		}
		/*
		 * In IPv4 code, we try to annonuce new RTF_ANNOUNCE entry here.
		 * We don't do that here since llinfo is not ready yet.
		 *
		 * There are also couple of other things to be discussed:
		 * - unsolicited NA code needs improvement beforehand
		 * - RFC4861 says we MAY send multicast unsolicited NA
		 *   (7.2.6 paragraph 4), however, it also says that we
		 *   SHOULD provide a mechanism to prevent multicast NA storm.
		 *   we don't have anything like it right now.
		 *   note that the mechanism needs a mutual agreement
		 *   between proxies, which means that we need to implement
		 *   a new protocol, or a new kludge.
		 * - from RFC4861 6.2.4, host MUST NOT send an unsolicited RA.
		 *   we need to check ip6forwarding before sending it.
		 *   (or should we allow proxy ND configuration only for
		 *   routers?  there's no mention about proxy ND from hosts)
		 */
		/* FALLTHROUGH */
	case RTM_RESOLVE:
		if (!(ifp->if_flags & (IFF_POINTOPOINT | IFF_LOOPBACK))) {
			/*
			 * Address resolution isn't necessary for a point to
			 * point link, so we can skip this test for a p2p link.
			 */
			if (gate->sa_family != AF_LINK ||
			    gate->sa_len < sizeof (null_sdl)) {
				/* Don't complain in case of RTM_ADD */
				if (req == RTM_RESOLVE) {
					log(LOG_ERR, "%s: route to %s has bad "
					    "gateway address (sa_family %u "
					    "sa_len %u) on %s\n", __func__,
					    inet_ntop(AF_INET6,
					    &SIN6(rt_key(rt))->sin6_addr, buf,
					    sizeof (buf)), gate->sa_family,
					    gate->sa_len, if_name(ifp));
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
		rt->rt_llinfo = ln = nd6_llinfo_alloc(M_WAITOK);
		if (ln == NULL)
			break;

		nd6_allocated++;
		rt->rt_llinfo_get_ri	= nd6_llinfo_get_ri;
		rt->rt_llinfo_get_iflri	= nd6_llinfo_get_iflri;
		rt->rt_llinfo_purge	= nd6_llinfo_purge;
		rt->rt_llinfo_free	= nd6_llinfo_free;
		rt->rt_flags |= RTF_LLINFO;
		ln->ln_rt = rt;
		/* this is required for "ndp" command. - shin */
		if (req == RTM_ADD) {
			/*
			 * gate should have some valid AF_LINK entry,
			 * and ln->ln_expire should have some lifetime
			 * which is specified by ndp command.
			 */
			ln->ln_state = ND6_LLINFO_REACHABLE;
		} else {
			/*
			 * When req == RTM_RESOLVE, rt is created and
			 * initialized in rtrequest(), so rt_expire is 0.
			 */
			ln->ln_state = ND6_LLINFO_NOSTATE;

			/* In case we're called before 1.0 sec. has elapsed */
			ln_setexpire(ln, (ifp->if_eflags & IFEF_IPV6_ND6ALT) ?
			    0 : MAX(timenow, 1));
		}
		LN_INSERTHEAD(ln);
		nd6_inuse++;

		/* We have at least one entry; arm the timer if not already */
		nd6_sched_timeout(NULL, NULL);

		/*
		 * If we have too many cache entries, initiate immediate
		 * purging for some "less recently used" entries.  Note that
		 * we cannot directly call nd6_free() here because it would
		 * cause re-entering rtable related routines triggering an LOR
		 * problem.
		 */
		if (ip6_neighborgcthresh > 0 &&
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
				ln_setexpire(ln_end, timenow);
				RT_UNLOCK(rt_end);
			}
		}

		/*
		 * check if rt_key(rt) is one of my address assigned
		 * to the interface.
		 */
		ifa = (struct ifaddr *)in6ifa_ifpwithaddr(rt->rt_ifp,
		    &SIN6(rt_key(rt))->sin6_addr);
		if (ifa != NULL) {
			caddr_t macp = nd6_ifptomac(ifp);
			ln_setexpire(ln, 0);
			ln->ln_state = ND6_LLINFO_REACHABLE;
			if (macp != NULL) {
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
						rt->rt_if_ref_fn(rt->rt_ifp,
						    -1);
					}
				}
				rt->rt_ifp = lo_ifp;
				/*
				 * If rmx_mtu is not locked, update it
				 * to the MTU used by the new interface.
				 */
				if (!(rt->rt_rmx.rmx_locks & RTV_MTU))
					rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu;
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
			ln_setexpire(ln, 0);
			ln->ln_state = ND6_LLINFO_REACHABLE;

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
				error = in6_mc_join(ifp, &llsol,
				    NULL, &in6m, 0);
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
		if ((rt->rt_flags & RTF_ANNOUNCE) &&
		    (ifp->if_flags & IFF_MULTICAST)) {
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

static int
nd6_siocgdrlst(void *data, int data_is_64)
{
	struct in6_drlist_32 *drl_32;
	struct nd_defrouter *dr;
	int i = 0;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	dr = TAILQ_FIRST(&nd_defrouter);

	/* For 64-bit process */
	if (data_is_64) {
		struct in6_drlist_64 *drl_64;

		drl_64 = _MALLOC(sizeof (*drl_64), M_TEMP, M_WAITOK|M_ZERO);
		if (drl_64 == NULL)
			return (ENOMEM);

		/* preserve the interface name */
		bcopy(data, drl_64, sizeof (drl_64->ifname));

		while (dr && i < DRLSTSIZ) {
			drl_64->defrouter[i].rtaddr = dr->rtaddr;
			if (IN6_IS_ADDR_LINKLOCAL(
			    &drl_64->defrouter[i].rtaddr)) {
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
			drl_64->defrouter[i].expire = nddr_getexpire(dr);
			drl_64->defrouter[i].if_index = dr->ifp->if_index;
			i++;
			dr = TAILQ_NEXT(dr, dr_entry);
		}
		bcopy(drl_64, data, sizeof (*drl_64));
		_FREE(drl_64, M_TEMP);
		return (0);
	}

	/* For 32-bit process */
	drl_32 = _MALLOC(sizeof (*drl_32), M_TEMP, M_WAITOK|M_ZERO);
	if (drl_32 == NULL)
		return (ENOMEM);

	/* preserve the interface name */
	bcopy(data, drl_32, sizeof (drl_32->ifname));

	while (dr != NULL && i < DRLSTSIZ) {
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
		drl_32->defrouter[i].expire = nddr_getexpire(dr);
		drl_32->defrouter[i].if_index = dr->ifp->if_index;
		i++;
		dr = TAILQ_NEXT(dr, dr_entry);
	}
	bcopy(drl_32, data, sizeof (*drl_32));
	_FREE(drl_32, M_TEMP);
	return (0);
}

/*
 * XXX meaning of fields, especialy "raflags", is very
 * differnet between RA prefix list and RR/static prefix list.
 * how about separating ioctls into two?
 */
static int
nd6_siocgprlst(void *data, int data_is_64)
{
	struct in6_prlist_32 *prl_32;
	struct nd_prefix *pr;
	int i = 0;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	pr = nd_prefix.lh_first;

	/* For 64-bit process */
	if (data_is_64) {
		struct in6_prlist_64 *prl_64;

		prl_64 = _MALLOC(sizeof (*prl_64), M_TEMP, M_WAITOK|M_ZERO);
		if (prl_64 == NULL)
			return (ENOMEM);

		/* preserve the interface name */
		bcopy(data, prl_64, sizeof (prl_64->ifname));

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
			prl_64->prefix[i].expire = ndpr_getexpire(pr);

			pfr = pr->ndpr_advrtrs.lh_first;
			j = 0;
			while (pfr) {
				if (j < DRLSTSIZ) {
#define	RTRADDR prl_64->prefix[i].advrtr[j]
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
		bcopy(prl_64, data, sizeof (*prl_64));
		_FREE(prl_64, M_TEMP);
		return (0);
	}

	/* For 32-bit process */
	prl_32 = _MALLOC(sizeof (*prl_32), M_TEMP, M_WAITOK|M_ZERO);
	if (prl_32 == NULL)
		return (ENOMEM);

	/* preserve the interface name */
	bcopy(data, prl_32, sizeof (prl_32->ifname));

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
		prl_32->prefix[i].expire = ndpr_getexpire(pr);

		pfr = pr->ndpr_advrtrs.lh_first;
		j = 0;
		while (pfr) {
			if (j < DRLSTSIZ) {
#define	RTRADDR prl_32->prefix[i].advrtr[j]
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
	bcopy(prl_32, data, sizeof (*prl_32));
	_FREE(prl_32, M_TEMP);
	return (0);
}

int
nd6_ioctl(u_long cmd, caddr_t data, struct ifnet *ifp)
{
	struct nd_defrouter *dr;
	struct nd_prefix *pr;
	struct rtentry *rt;
	int i, error = 0;

	VERIFY(ifp != NULL);
	i = ifp->if_index;

	switch (cmd) {
	case SIOCGDRLST_IN6_32:		/* struct in6_drlist_32 */
	case SIOCGDRLST_IN6_64:		/* struct in6_drlist_64 */
		/*
		 * obsolete API, use sysctl under net.inet6.icmp6
		 */
		lck_mtx_lock(nd6_mutex);
		error = nd6_siocgdrlst(data, cmd == SIOCGDRLST_IN6_64);
		lck_mtx_unlock(nd6_mutex);
		break;

	case SIOCGPRLST_IN6_32:		/* struct in6_prlist_32 */
	case SIOCGPRLST_IN6_64:		/* struct in6_prlist_64 */
		/*
		 * obsolete API, use sysctl under net.inet6.icmp6
		 */
		lck_mtx_lock(nd6_mutex);
		error = nd6_siocgprlst(data, cmd == SIOCGPRLST_IN6_64);
		lck_mtx_unlock(nd6_mutex);
		break;

	case OSIOCGIFINFO_IN6:		/* struct in6_ondireq */
	case SIOCGIFINFO_IN6: {		/* struct in6_ondireq */
		u_int32_t linkmtu;
		struct in6_ondireq *ondi = (struct in6_ondireq *)(void *)data;
		struct nd_ifinfo *ndi;
		/*
		 * SIOCGIFINFO_IN6 ioctl is encoded with in6_ondireq
		 * instead of in6_ndireq, so we treat it as such.
		 */
		lck_rw_lock_shared(nd_if_rwlock);
		ndi = ND_IFINFO(ifp);
		if (!nd_ifinfo || i >= nd_ifinfo_indexlim ||
		    !ndi->initialized) {
			lck_rw_done(nd_if_rwlock);
			error = EINVAL;
			break;
		}
		lck_mtx_lock(&ndi->lock);
		linkmtu = IN6_LINKMTU(ifp);
		bcopy(&linkmtu, &ondi->ndi.linkmtu, sizeof (linkmtu));
		bcopy(&nd_ifinfo[i].maxmtu, &ondi->ndi.maxmtu,
		    sizeof (u_int32_t));
		bcopy(&nd_ifinfo[i].basereachable, &ondi->ndi.basereachable,
		    sizeof (u_int32_t));
		bcopy(&nd_ifinfo[i].reachable, &ondi->ndi.reachable,
		    sizeof (u_int32_t));
		bcopy(&nd_ifinfo[i].retrans, &ondi->ndi.retrans,
		    sizeof (u_int32_t));
		bcopy(&nd_ifinfo[i].flags, &ondi->ndi.flags,
		    sizeof (u_int32_t));
		bcopy(&nd_ifinfo[i].recalctm, &ondi->ndi.recalctm,
		    sizeof (int));
		ondi->ndi.chlim = nd_ifinfo[i].chlim;
		ondi->ndi.receivedra = 0;
		lck_mtx_unlock(&ndi->lock);
		lck_rw_done(nd_if_rwlock);
		break;
	}

	case SIOCSIFINFO_FLAGS:	{	/* struct in6_ndireq */
		struct in6_ndireq *cndi = (struct in6_ndireq *)(void *)data;
		u_int32_t oflags, flags;
		struct nd_ifinfo *ndi;

		/* XXX: almost all other fields of cndi->ndi is unused */
		lck_rw_lock_shared(nd_if_rwlock);
		ndi = ND_IFINFO(ifp);
		if (!nd_ifinfo || i >= nd_ifinfo_indexlim ||
		    !ndi->initialized) {
			lck_rw_done(nd_if_rwlock);
			error = EINVAL;
			break;
		}
		lck_mtx_lock(&ndi->lock);
		oflags = nd_ifinfo[i].flags;
		bcopy(&cndi->ndi.flags, &nd_ifinfo[i].flags, sizeof (flags));
		flags = nd_ifinfo[i].flags;
		lck_mtx_unlock(&ndi->lock);
		lck_rw_done(nd_if_rwlock);

		if (oflags == flags)
			break;

		error = nd6_setifinfo(ifp, oflags, flags);
		break;
	}

	case SIOCSNDFLUSH_IN6:		/* struct in6_ifreq */
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

	case SIOCSPFXFLUSH_IN6: {	/* struct in6_ifreq */
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
					IFA_REMREF(&ia->ia_ifa);
					lck_mtx_lock(nd6_mutex);
					lck_rw_lock_exclusive(
					    &in6_ifaddr_rwlock);
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
			pfxlist_onlink_check();
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

	case SIOCSRTRFLUSH_IN6: {	/* struct in6_ifreq */
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

	case SIOCGNBRINFO_IN6_32: {	/* struct in6_nbrinfo_32 */
		struct llinfo_nd6 *ln;
		struct in6_nbrinfo_32 nbi_32;
		struct in6_addr nb_addr; /* make local for safety */

		bcopy(data, &nbi_32, sizeof (nbi_32));
		nb_addr = nbi_32.addr;
		/*
		 * XXX: KAME specific hack for scoped addresses
		 * 	XXXX: for other scopes than link-local?
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&nbi_32.addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&nbi_32.addr)) {
			u_int16_t *idp =
			    (u_int16_t *)(void *)&nb_addr.s6_addr[2];

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
		nbi_32.state = ln->ln_state;
		nbi_32.asked = ln->ln_asked;
		nbi_32.isrouter = ln->ln_router;
		nbi_32.expire = ln_getexpire(ln);
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		bcopy(&nbi_32, data, sizeof (nbi_32));
		break;
	}

	case SIOCGNBRINFO_IN6_64: {	/* struct in6_nbrinfo_64 */
		struct llinfo_nd6 *ln;
		struct in6_nbrinfo_64 nbi_64;
		struct in6_addr nb_addr; /* make local for safety */

		bcopy(data, &nbi_64, sizeof (nbi_64));
		nb_addr = nbi_64.addr;
		/*
		 * XXX: KAME specific hack for scoped addresses
		 * 	XXXX: for other scopes than link-local?
		 */
		if (IN6_IS_ADDR_LINKLOCAL(&nbi_64.addr) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(&nbi_64.addr)) {
			u_int16_t *idp =
			    (u_int16_t *)(void *)&nb_addr.s6_addr[2];

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
		nbi_64.state = ln->ln_state;
		nbi_64.asked = ln->ln_asked;
		nbi_64.isrouter = ln->ln_router;
		nbi_64.expire = ln_getexpire(ln);
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		bcopy(&nbi_64, data, sizeof (nbi_64));
		break;
	}

	case SIOCGDEFIFACE_IN6_32:	/* struct in6_ndifreq_32 */
	case SIOCGDEFIFACE_IN6_64: {	/* struct in6_ndifreq_64 */
		struct in6_ndifreq_64 *ndif_64 =
		    (struct in6_ndifreq_64 *)(void *)data;
		struct in6_ndifreq_32 *ndif_32 =
		    (struct in6_ndifreq_32 *)(void *)data;

		if (cmd == SIOCGDEFIFACE_IN6_64) {
			u_int64_t j = nd6_defifindex;
			bcopy(&j, &ndif_64->ifindex, sizeof (j));
		} else {
			bcopy(&nd6_defifindex, &ndif_32->ifindex,
			    sizeof (u_int32_t));
		}
		break;
	}

	case SIOCSDEFIFACE_IN6_32:	/* struct in6_ndifreq_32 */
	case SIOCSDEFIFACE_IN6_64: {	/* struct in6_ndifreq_64 */
		struct in6_ndifreq_64 *ndif_64 =
		    (struct in6_ndifreq_64 *)(void *)data;
		struct in6_ndifreq_32 *ndif_32 =
		    (struct in6_ndifreq_32 *)(void *)data;
		u_int32_t idx;

		if (cmd == SIOCSDEFIFACE_IN6_64) {
			u_int64_t j;
			bcopy(&ndif_64->ifindex, &j, sizeof (j));
			idx = (u_int32_t)j;
		} else {
			bcopy(&ndif_32->ifindex, &idx, sizeof (idx));
		}

		error = nd6_setdefaultiface(idx);
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
nd6_cache_lladdr(struct ifnet *ifp, struct in6_addr *from, char *lladdr,
    int lladdrlen, int type, int code)
{
#pragma unused(lladdrlen)
	struct rtentry *rt = NULL;
	struct llinfo_nd6 *ln = NULL;
	int is_newentry;
	struct sockaddr_dl *sdl = NULL;
	int do_update;
	int olladdr;
	int llchange;
	int newstate = 0;
	uint64_t timenow;
	boolean_t sched_timeout = FALSE;

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
	 */
	timenow = net_uptime();

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
			ln_setexpire(ln, timenow + nd6_gctimer);
			ln->ln_hold = NULL;

			if (m != NULL) {
				struct sockaddr_in6 sin6;

				rtkey_to_sa6(rt, &sin6);
				/*
				 * we assume ifp is not a p2p here, so just
				 * set the 2nd argument as the 1st one.
				 */
				RT_UNLOCK(rt);
				nd6_output(ifp, ifp, m, &sin6, rt, NULL);
				RT_LOCK(rt);
			}
		} else if (ln->ln_state == ND6_LLINFO_INCOMPLETE) {
			/* probe right away */
			ln_setexpire(ln, timenow);
			sched_timeout = TRUE;
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
	 * newentry olladdr  lladdr  llchange	    NS  RS	RA	redir
	 *								D R
	 *	0	n	n	--	(1)	c	?	s
	 *	0	y	n	--	(2)	c	s	s
	 *	0	n	y	--	(3)	c	s	s
	 *	0	y	y	n	(4)	c	s	s
	 *	0	y	y	y	(5)	c	s	s
	 *	1	--	n	--	(6) c	c		c s
	 *	1	--	y	--	(7) c	c	s	c s
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
		 * If the ICMP message is a Redirect to a better router, always
		 * set the is_router flag.  Otherwise, if the entry is newly
		 * created, then clear the flag.  [RFC 4861, sec 8.3]
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
	 *
	 * Note: Perform default router selection even when we are a router,
	 * if Scoped Routing is enabled.
	 */
	if (do_update && ln->ln_router &&
	    (ip6_doscopedroute || !ip6_forwarding)) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		lck_mtx_lock(nd6_mutex);
		defrouter_select(ifp);
		lck_mtx_unlock(nd6_mutex);
	} else {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
	}
	if (sched_timeout) {
		lck_mtx_lock(rnh_lock);
		nd6_sched_timeout(NULL, NULL);
		lck_mtx_unlock(rnh_lock);
	}
}

static void
nd6_slowtimo(void *arg)
{
#pragma unused(arg)
	int i;
	struct nd_ifinfo *nd6if;

	lck_rw_lock_shared(nd_if_rwlock);
	for (i = 1; i < if_index + 1; i++) {
		if (!nd_ifinfo || i >= nd_ifinfo_indexlim)
			break;
		nd6if = &nd_ifinfo[i];
		if (!nd6if->initialized)
			break;
		lck_mtx_lock(&nd6if->lock);
		if (nd6if->basereachable && /* already initialized */
		    (nd6if->recalctm -= ND6_SLOWTIMER_INTERVAL) <= 0) {
			/*
			 * Since reachable time rarely changes by router
			 * advertisements, we SHOULD insure that a new random
			 * value gets recomputed at least once every few hours.
			 * (RFC 4861, 6.3.4)
			 */
			nd6if->recalctm = nd6_recalc_reachtm_interval;
			nd6if->reachable =
			    ND_COMPUTE_RTIME(nd6if->basereachable);
		}
		lck_mtx_unlock(&nd6if->lock);
	}
	lck_rw_done(nd_if_rwlock);
	timeout(nd6_slowtimo, NULL, ND6_SLOWTIMER_INTERVAL * hz);
}

#define	senderr(e) { error = (e); goto bad; }
int
nd6_output(struct ifnet *ifp, struct ifnet *origifp, struct mbuf *m0,
    struct sockaddr_in6 *dst, struct rtentry *hint0, struct flowadv *adv)
{
	struct mbuf *m = m0;
	struct rtentry *rt = hint0, *hint = hint0;
	struct llinfo_nd6 *ln = NULL;
	int error = 0;
	uint64_t timenow;
	struct rtentry *rtrele = NULL;
	struct nd_ifinfo *ndi;

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
	 * used by route_to_gwroute().
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
			if ((hint = rt = rtalloc1_scoped(SA(dst), 1, 0,
			    ifp->if_index)) != NULL) {
				RT_LOCK_SPIN(rt);
				if (rt->rt_ifp != ifp) {
					/* XXX: loop care? */
					RT_UNLOCK(rt);
					error = nd6_output(ifp, origifp, m0,
					    dst, rt, adv);
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
			gw6 = *(SIN6(rt->rt_gateway));

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
				rt->rt_gwroute = NULL;
				RT_UNLOCK(gwrt);
				RT_UNLOCK(rt);
				rtfree(gwrt);
lookup:
				lck_mtx_lock(rnh_lock);
				gwrt = rtalloc1_scoped_locked(SA(&gw6), 1, 0,
				    ifp->if_index);

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
				RT_UNLOCK(rt);
				lck_mtx_unlock(rnh_lock);
				/* Remember to release/free "rt" at the end */
				rtrele = rt;
				rt = gwrt;
			} else {
				RT_ADDREF_LOCKED(gwrt);
				RT_UNLOCK(gwrt);
				RT_UNLOCK(rt);
				/* Remember to release/free "rt" at the end */
				rtrele = rt;
				rt = gwrt;
			}
			VERIFY(rt == gwrt);

			/*
			 * This is an opportunity to revalidate the parent
			 * route's gwroute, in case it now points to a dead
			 * route entry.  Parent route won't go away since the
			 * clone (hint) holds a reference to it.  rt == gwrt.
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

			RT_LOCK_SPIN(rt);
			/* rt == gwrt; if it is now down, give up */
			if (!(rt->rt_flags & RTF_UP)) {
				RT_UNLOCK(rt);
				rtfree(rt);
				rt = NULL;
				/* "rtrele" == original "rt" */
				senderr(EHOSTUNREACH);
			}
		}

		/* Become a regular mutex */
		RT_CONVERT_LOCK(rt);
	}

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
		ndi = ND_IFINFO(ifp);
		VERIFY(ndi != NULL && ndi->initialized);
		lck_mtx_lock(&ndi->lock);
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0 &&
		    !(ndi->flags & ND6_IFF_PERFORMNUD)) {
			lck_mtx_unlock(&ndi->lock);
			lck_rw_done(nd_if_rwlock);
			log(LOG_DEBUG,
			    "nd6_output: can't allocate llinfo for %s "
			    "(ln=0x%llx, rt=0x%llx)\n",
			    ip6_sprintf(&dst->sin6_addr),
			    (uint64_t)VM_KERNEL_ADDRPERM(ln),
			    (uint64_t)VM_KERNEL_ADDRPERM(rt));
			senderr(EIO);	/* XXX: good error? */
		}
		lck_mtx_unlock(&ndi->lock);
		lck_rw_done(nd_if_rwlock);

		goto sendpkt;	/* send anyway */
	}

	net_update_uptime();
	timenow = net_uptime();

	/* We don't have to do link-layer address resolution on a p2p link. */
	if ((ifp->if_flags & IFF_POINTOPOINT) != 0 &&
	    ln->ln_state < ND6_LLINFO_REACHABLE) {
		ln->ln_state = ND6_LLINFO_STALE;
		ln_setexpire(ln, timenow + nd6_gctimer);
	}

	/*
	 * The first time we send a packet to a neighbor whose entry is
	 * STALE, we have to change the state to DELAY and a sets a timer to
	 * expire in DELAY_FIRST_PROBE_TIME seconds to ensure do
	 * neighbor unreachability detection on expiration.
	 * (RFC 4861 7.3.3)
	 */
	if (ln->ln_state == ND6_LLINFO_STALE) {
		ln->ln_asked = 0;
		ln->ln_state = ND6_LLINFO_DELAY;
		ln_setexpire(ln, timenow + nd6_delay);
		/* N.B.: we will re-arm the timer below. */
		_CASSERT(ND6_LLINFO_DELAY > ND6_LLINFO_INCOMPLETE);
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
		 * garbage collection (see nd6_rtrequest()).  Do this only
		 * if the entry is non-permanent (as permanent ones will
		 * never be purged), and if the number of active entries
		 * is at least half of the threshold.
		 */
		if (ln->ln_state == ND6_LLINFO_DELAY ||
		    (ln->ln_expire != 0 && ip6_neighborgcthresh > 0 &&
		    nd6_inuse >= (ip6_neighborgcthresh >> 1))) {
			lck_mtx_lock(rnh_lock);
			if (ln->ln_state == ND6_LLINFO_DELAY)
				nd6_sched_timeout(NULL, NULL);
			if (ln->ln_expire != 0 && ip6_neighborgcthresh > 0 &&
			    nd6_inuse >= (ip6_neighborgcthresh >> 1)) {
				RT_LOCK_SPIN(rt);
				if (ln->ln_flags & ND6_LNF_IN_USE) {
					LN_DEQUEUE(ln);
					LN_INSERTHEAD(ln);
				}
				RT_UNLOCK(rt);
			}
			lck_mtx_unlock(rnh_lock);
		}
		goto sendpkt;
	}

	/*
	 * If this is a prefix proxy route, record the inbound interface
	 * so that it can be excluded from the list of interfaces eligible
	 * for forwarding the proxied NS in nd6_prproxy_ns_output().
	 */
	if (rt->rt_flags & RTF_PROXY)
		ln->ln_exclifp = ((origifp == ifp) ? NULL : origifp);

	/*
	 * There is a neighbor cache entry, but no ethernet address
	 * response yet.  Replace the held mbuf (if any) with this
	 * latest one.
	 *
	 * This code conforms to the rate-limiting rule described in Section
	 * 7.2.2 of RFC 4861, because the timer is set correctly after sending
	 * an NS below.
	 */
	if (ln->ln_state == ND6_LLINFO_NOSTATE)
		ln->ln_state = ND6_LLINFO_INCOMPLETE;
	if (ln->ln_hold)
		m_freem(ln->ln_hold);
	ln->ln_hold = m;
	if (ln->ln_expire != 0 && ln->ln_asked < nd6_mmaxtries &&
	    ln->ln_expire <= timenow) {
		ln->ln_asked++;
		lck_rw_lock_shared(nd_if_rwlock);
		ndi = ND_IFINFO(ifp);
		VERIFY(ndi != NULL && ndi->initialized);
		lck_mtx_lock(&ndi->lock);
		ln_setexpire(ln, timenow + ndi->retrans / 1000);
		lck_mtx_unlock(&ndi->lock);
		lck_rw_done(nd_if_rwlock);
		RT_UNLOCK(rt);
		/* We still have a reference on rt (for ln) */
		if (ip6_forwarding)
			nd6_prproxy_ns_output(ifp, origifp, NULL,
			    &dst->sin6_addr, ln);
		else
			nd6_ns_output(ifp, NULL, &dst->sin6_addr, ln, 0);
		lck_mtx_lock(rnh_lock);
		nd6_sched_timeout(NULL, NULL);
		lck_mtx_unlock(rnh_lock);
	} else {
		RT_UNLOCK(rt);
	}
	/*
	 * Move this entry to the head of the queue so that it is
	 * less likely for this entry to be a target of forced
	 * garbage collection (see nd6_rtrequest()).  Do this only
	 * if the entry is non-permanent (as permanent ones will
	 * never be purged), and if the number of active entries
	 * is at least half of the threshold.
	 */
	if (ln->ln_expire != 0 && ip6_neighborgcthresh > 0 &&
	    nd6_inuse >= (ip6_neighborgcthresh >> 1)) {
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
	}
	error = 0;
	goto release;

sendpkt:
	if (rt != NULL)
		RT_LOCK_ASSERT_NOTHELD(rt);

	/* discard the packet if IPv6 operation is disabled on the interface */
	if (ifp->if_eflags & IFEF_IPV6_DISABLED) {
		error = ENETDOWN; /* better error? */
		goto bad;
	}

	if (ifp->if_flags & IFF_LOOPBACK) {
		/* forwarding rules require the original scope_id */
		m->m_pkthdr.rcvif = origifp;
		error = dlil_output(origifp, PF_INET6, m, (caddr_t)rt,
		    SA(dst), 0, adv);
		goto release;
	} else {
		/* Do not allow loopback address to wind up on a wire */
		struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);

		if ((IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src) ||
		    IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst))) {
			ip6stat.ip6s_badscope++;
			error = EADDRNOTAVAIL;
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

	if (hint != NULL && nstat_collect) {
		int scnt;

		if ((m->m_pkthdr.csum_flags & CSUM_TSO_IPV6) &&
		    (m->m_pkthdr.tso_segsz > 0))
			scnt = m->m_pkthdr.len / m->m_pkthdr.tso_segsz;
		else
			scnt = 1;

		nstat_route_tx(hint, scnt, m->m_pkthdr.len, 0);
	}

	m->m_pkthdr.rcvif = NULL;
	error = dlil_output(ifp, PF_INET6, m, (caddr_t)rt, SA(dst), 0, adv);
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
nd6_need_cache(struct ifnet *ifp)
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
		return (1);
	default:
		return (0);
	}
}

int
nd6_storelladdr(struct ifnet *ifp, struct rtentry *rt, struct mbuf *m,
    struct sockaddr *dst, u_char *desten)
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
			ETHER_MAP_IPV6_MULTICAST(&SIN6(dst)->sin6_addr, desten);
			return (1);
		case IFT_IEEE1394:
			for (i = 0; i < ifp->if_addrlen; i++)
				desten[i] = ~0;
			return (1);
		case IFT_ARCNET:
			*desten = 0;
			return (1);
		default:
			return (0); /* caller will free mbuf */
		}
	}

	if (rt == NULL) {
		/* this could happen, if we could not allocate memory */
		return (0); /* caller will free mbuf */
	}
	RT_LOCK(rt);
	if (rt->rt_gateway->sa_family != AF_LINK) {
		printf("nd6_storelladdr: something odd happens\n");
		RT_UNLOCK(rt);
		return (0); /* caller will free mbuf */
	}
	sdl = SDL(rt->rt_gateway);
	if (sdl->sdl_alen == 0) {
		/* this should be impossible, but we bark here for debugging */
		printf("nd6_storelladdr: sdl_alen == 0\n");
		RT_UNLOCK(rt);
		return (0); /* caller will free mbuf */
	}

	bcopy(LLADDR(sdl), desten, sdl->sdl_alen);
	RT_UNLOCK(rt);
	return (1);
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
		result = route_to_gwroute((const struct sockaddr *)ip6_dest,
		    hint, &route);
		if (result != 0)
			return (result);
		if (route != NULL)
			RT_LOCK_ASSERT_HELD(route);
	}

	if ((packet->m_flags & M_MCAST) != 0) {
		if (route != NULL)
			RT_UNLOCK(route);
		result = dlil_resolve_multi(ifp,
		    (const struct sockaddr *)ip6_dest,
		    SA(ll_dest), ll_dest_len);
		if (route != NULL)
			RT_LOCK(route);
		goto release;
	}

	if (route == NULL) {
		/*
		 * This could happen, if we could not allocate memory or
		 * if route_to_gwroute() didn't return a route.
		 */
		result = ENOBUFS;
		goto release;
	}

	if (route->rt_gateway->sa_family != AF_LINK) {
		printf("%s: route %s on %s%d gateway address not AF_LINK\n",
		    __func__, ip6_sprintf(&ip6_dest->sin6_addr),
		    route->rt_ifp->if_name, route->rt_ifp->if_unit);
		result = EADDRNOTAVAIL;
		goto release;
	}

	sdl = SDL(route->rt_gateway);
	if (sdl->sdl_alen == 0) {
		/* this should be impossible, but we bark here for debugging */
		printf("%s: route %s on %s%d sdl_alen == 0\n", __func__,
		    ip6_sprintf(&ip6_dest->sin6_addr), route->rt_ifp->if_name,
		    route->rt_ifp->if_unit);
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

int
nd6_setifinfo(struct ifnet *ifp, u_int32_t before, u_int32_t after)
{
	uint32_t b, a;
	int err = 0;

	/*
	 * Handle ND6_IFF_IFDISABLED
	 */
	if ((before & ND6_IFF_IFDISABLED) ||
	    (after & ND6_IFF_IFDISABLED)) {
		b = (before & ND6_IFF_IFDISABLED);
		a = (after & ND6_IFF_IFDISABLED);

		if (b != a && (err = nd6_if_disable(ifp,
		     ((int32_t)(a - b) > 0))) != 0)
			goto done;
	}

	/*
	 * Handle ND6_IFF_PROXY_PREFIXES
	 */
	if ((before & ND6_IFF_PROXY_PREFIXES) ||
	    (after & ND6_IFF_PROXY_PREFIXES)) {
		b = (before & ND6_IFF_PROXY_PREFIXES);
		a = (after & ND6_IFF_PROXY_PREFIXES);

		if (b != a && (err = nd6_if_prproxy(ifp,
		     ((int32_t)(a - b) > 0))) != 0)
			goto done;
	}
done:
	return (err);
}

/*
 * Enable/disable IPv6 on an interface, called as part of
 * setting/clearing ND6_IFF_IFDISABLED, or during DAD failure.
 */
int
nd6_if_disable(struct ifnet *ifp, boolean_t enable)
{
	ifnet_lock_shared(ifp);
	if (enable)
		ifp->if_eflags |= IFEF_IPV6_DISABLED;
	else
		ifp->if_eflags &= ~IFEF_IPV6_DISABLED;
	ifnet_lock_done(ifp);

	return (0);
}

static int
nd6_sysctl_drlist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	char pbuf[MAX_IPv6_STR_LEN];
	struct nd_defrouter *dr;
	int error = 0;

	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	lck_mtx_lock(nd6_mutex);
	if (proc_is64bit(req->p)) {
		struct in6_defrouter_64 d;

		bzero(&d, sizeof (d));
		d.rtaddr.sin6_family = AF_INET6;
		d.rtaddr.sin6_len = sizeof (d.rtaddr);

		TAILQ_FOREACH(dr, &nd_defrouter, dr_entry) {
			d.rtaddr.sin6_addr = dr->rtaddr;
			if (in6_recoverscope(&d.rtaddr,
			    &dr->rtaddr, dr->ifp) != 0)
				log(LOG_ERR, "scope error in default router "
				    "list (%s)\n", inet_ntop(AF_INET6,
				    &dr->rtaddr, pbuf, sizeof (pbuf)));
			d.flags = dr->flags;
			d.stateflags = dr->stateflags;
			d.stateflags &= ~NDDRF_PROCESSED;
			d.rtlifetime = dr->rtlifetime;
			d.expire = nddr_getexpire(dr);
			d.if_index = dr->ifp->if_index;
			error = SYSCTL_OUT(req, &d, sizeof (d));
			if (error != 0)
				break;
		}
	} else {
		struct in6_defrouter_32 d;

		bzero(&d, sizeof (d));
		d.rtaddr.sin6_family = AF_INET6;
		d.rtaddr.sin6_len = sizeof (d.rtaddr);

		TAILQ_FOREACH(dr, &nd_defrouter, dr_entry) {
			d.rtaddr.sin6_addr = dr->rtaddr;
			if (in6_recoverscope(&d.rtaddr,
			    &dr->rtaddr, dr->ifp) != 0)
				log(LOG_ERR, "scope error in default router "
				    "list (%s)\n", inet_ntop(AF_INET6,
				    &dr->rtaddr, pbuf, sizeof (pbuf)));
			d.flags = dr->flags;
			d.stateflags = dr->stateflags;
			d.stateflags &= ~NDDRF_PROCESSED;
			d.rtlifetime = dr->rtlifetime;
			d.expire = nddr_getexpire(dr);
			d.if_index = dr->ifp->if_index;
			error = SYSCTL_OUT(req, &d, sizeof (d));
			if (error != 0)
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
	char pbuf[MAX_IPv6_STR_LEN];
	struct nd_pfxrouter *pfr;
	struct sockaddr_in6 s6;
	struct nd_prefix *pr;
	int error = 0;

	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	bzero(&s6, sizeof (s6));
	s6.sin6_family = AF_INET6;
	s6.sin6_len = sizeof (s6);

	lck_mtx_lock(nd6_mutex);
	if (proc_is64bit(req->p)) {
		struct in6_prefix_64 p;

		bzero(&p, sizeof (p));
		p.origin = PR_ORIG_RA;

		LIST_FOREACH(pr, &nd_prefix, ndpr_entry) {
			NDPR_LOCK(pr);
			p.prefix = pr->ndpr_prefix;
			if (in6_recoverscope(&p.prefix,
			    &pr->ndpr_prefix.sin6_addr, pr->ndpr_ifp) != 0)
				log(LOG_ERR, "scope error in "
				    "prefix list (%s)\n", inet_ntop(AF_INET6,
				    &p.prefix.sin6_addr, pbuf, sizeof (pbuf)));
			p.raflags = pr->ndpr_raf;
			p.prefixlen = pr->ndpr_plen;
			p.vltime = pr->ndpr_vltime;
			p.pltime = pr->ndpr_pltime;
			p.if_index = pr->ndpr_ifp->if_index;
			p.expire = ndpr_getexpire(pr);
			p.refcnt = pr->ndpr_addrcnt;
			p.flags = pr->ndpr_stateflags;
			p.advrtrs = 0;
			LIST_FOREACH(pfr, &pr->ndpr_advrtrs, pfr_entry)
				p.advrtrs++;
			error = SYSCTL_OUT(req, &p, sizeof (p));
			if (error != 0) {
				NDPR_UNLOCK(pr);
				break;
			}
			LIST_FOREACH(pfr, &pr->ndpr_advrtrs, pfr_entry) {
				s6.sin6_addr = pfr->router->rtaddr;
				if (in6_recoverscope(&s6, &pfr->router->rtaddr,
				    pfr->router->ifp) != 0)
					log(LOG_ERR,
					    "scope error in prefix list (%s)\n",
					    inet_ntop(AF_INET6, &s6.sin6_addr,
					    pbuf, sizeof (pbuf)));
				error = SYSCTL_OUT(req, &s6, sizeof (s6));
				if (error != 0)
					break;
			}
			NDPR_UNLOCK(pr);
			if (error != 0)
				break;
		}
	} else {
		struct in6_prefix_32 p;

		bzero(&p, sizeof (p));
		p.origin = PR_ORIG_RA;

		LIST_FOREACH(pr, &nd_prefix, ndpr_entry) {
			NDPR_LOCK(pr);
			p.prefix = pr->ndpr_prefix;
			if (in6_recoverscope(&p.prefix,
			    &pr->ndpr_prefix.sin6_addr, pr->ndpr_ifp) != 0)
				log(LOG_ERR,
				    "scope error in prefix list (%s)\n",
				    inet_ntop(AF_INET6, &p.prefix.sin6_addr,
				    pbuf, sizeof (pbuf)));
			p.raflags = pr->ndpr_raf;
			p.prefixlen = pr->ndpr_plen;
			p.vltime = pr->ndpr_vltime;
			p.pltime = pr->ndpr_pltime;
			p.if_index = pr->ndpr_ifp->if_index;
			p.expire = ndpr_getexpire(pr);
			p.refcnt = pr->ndpr_addrcnt;
			p.flags = pr->ndpr_stateflags;
			p.advrtrs = 0;
			LIST_FOREACH(pfr, &pr->ndpr_advrtrs, pfr_entry)
				p.advrtrs++;
			error = SYSCTL_OUT(req, &p, sizeof (p));
			if (error != 0) {
				NDPR_UNLOCK(pr);
				break;
			}
			LIST_FOREACH(pfr, &pr->ndpr_advrtrs, pfr_entry) {
				s6.sin6_addr = pfr->router->rtaddr;
				if (in6_recoverscope(&s6, &pfr->router->rtaddr,
				    pfr->router->ifp) != 0)
					log(LOG_ERR,
					    "scope error in prefix list (%s)\n",
					    inet_ntop(AF_INET6, &s6.sin6_addr,
					    pbuf, sizeof (pbuf)));
				error = SYSCTL_OUT(req, &s6, sizeof (s6));
				if (error != 0)
					break;
			}
			NDPR_UNLOCK(pr);
			if (error != 0)
				break;
		}
	}
	lck_mtx_unlock(nd6_mutex);

	return (error);
}
