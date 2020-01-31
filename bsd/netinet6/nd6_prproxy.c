/*
 * Copyright (c) 2011-2016 Apple Inc. All rights reserved.
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
 * Prefix-based Neighbor Discovery Proxy
 *
 * When an interface is marked with the ND6_IFF_PROXY_PREFIXES flag, all
 * of current and future non-scoped on-link prefixes configured on the
 * interface will be shared with the scoped variant of such prefixes on
 * other interfaces.  This allows for one or more prefixes to be shared
 * across multiple links, with full support for Duplicate Addres Detection,
 * Address Resolution and Neighbor Unreachability Detection.
 *
 * A non-scoped prefix may be configured statically, or dynamically via
 * Router Advertisement.  An interface is said to be an "upstream" interface
 * when it is marked with ND6_IFF_PROXY_PREFIXES and has at least one prefix
 * that is non-scoped (global, not scoped.)  Such prefixes are marked with
 * the NDPRF_PRPROXY flag.
 *
 * A scoped prefix typically gets configured by way of adding an address
 * to a "downstream" interface, when the added address is part of an existing
 * prefix that is allowed to be shared (i.e. NDPRF_PRPROXY prefixes.)  Unlike
 * non-scoped prefixes, however, scoped prefixes will never be marked with
 * the NDPRF_PRPROXY flag.
 *
 * The setting of NDPRF_PRPROXY depends on whether the prefix is on-link;
 * an off-link prefix on an interface marked with ND6_IFF_PROXY_PREFIXES
 * will not cause NDPRF_PRPROXY to be set (it will only happen when that
 * prefix goes on-link.)  Likewise, a previously on-link prefix that has
 * transitioned to off-link will cause its NDPRF_PRPROXY flag to be cleared.
 *
 * Prefix proxying relies on IPv6 Scoped Routing to be in effect, as it would
 * otherwise be impossible to install scoped prefix route entries in the
 * routing table.  By default, such cloning prefix routes will generate cloned
 * routes that are scoped according to their interfaces.  Because prefix
 * proxying is essentially creating a larger network comprised of multiple
 * links sharing a prefix, we need to treat the cloned routes as if they
 * weren't scoped route entries.  This requires marking such cloning prefix
 * routes with the RTF_PROXY flag, which serves as an indication that the
 * route entry (and its clones) are part of a proxied prefix, and that the
 * entries are non-scoped.
 *
 * In order to handle solicited-node destined ND packets (Address Resolution,
 * Neighbor Unreachability Detection), prefix proxying also requires that the
 * "upstream" and "downstream" interfaces be configured for all-multicast mode.
 *
 * The setting and clearing of RTF_PROXY flag, as well as the entering and
 * exiting of all-multicast mode on those interfaces happen when a prefix
 * transitions between on-link and off-link (vice versa.)
 *
 * Note that this is not a strict implementation of RFC 4389, but rather a
 * derivative based on similar concept.  In particular, we only proxy NS and
 * NA packets; RA packets are never proxied.  Care should be taken to enable
 * prefix proxying only on non-looping network topology.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/mcache.h>
#include <sys/protosw.h>

#include <kern/queue.h>
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>

struct nd6_prproxy_prelist {
	SLIST_ENTRY(nd6_prproxy_prelist) ndprl_le;
	struct nd_prefix *ndprl_pr;             /* prefix */
	struct nd_prefix *ndprl_up;             /* non-NULL for upstream */
	struct ifnet    *ndprl_fwd_ifp;         /* outgoing interface */
	boolean_t       ndprl_sol;              /* unicast solicitor? */
	struct in6_addr ndprl_sol_saddr;        /* solicitor's address */
};

/*
 * Soliciting node (source) record.
 */
struct nd6_prproxy_solsrc {
	TAILQ_ENTRY(nd6_prproxy_solsrc) solsrc_tqe;
	struct in6_addr solsrc_saddr;           /* soliciting (src) address */
	struct ifnet    *solsrc_ifp;            /* iface where NS arrived on */
};

/*
 * Solicited node (target) record.
 */
struct nd6_prproxy_soltgt {
	RB_ENTRY(nd6_prproxy_soltgt) soltgt_link; /* RB tree links */
	struct soltgt_key_s {
		struct in6_addr taddr;          /* solicited (tgt) address */
	} soltgt_key;
	u_int64_t       soltgt_expire;          /* expiration time */
	u_int32_t       soltgt_cnt;             /* total # of solicitors */
	TAILQ_HEAD(, nd6_prproxy_solsrc) soltgt_q;
};

SLIST_HEAD(nd6_prproxy_prelist_head, nd6_prproxy_prelist);

static void nd6_prproxy_prelist_setroute(boolean_t enable,
    struct nd6_prproxy_prelist_head *, struct nd6_prproxy_prelist_head *);
static struct nd6_prproxy_prelist *nd6_ndprl_alloc(int);
static void nd6_ndprl_free(struct nd6_prproxy_prelist *);
static struct nd6_prproxy_solsrc *nd6_solsrc_alloc(int);
static void nd6_solsrc_free(struct nd6_prproxy_solsrc *);
static boolean_t nd6_solsrc_enq(struct nd_prefix *, struct ifnet *,
    struct in6_addr *, struct in6_addr *);
static boolean_t nd6_solsrc_deq(struct nd_prefix *, struct in6_addr *,
    struct in6_addr *, struct ifnet **);
static struct nd6_prproxy_soltgt *nd6_soltgt_alloc(int);
static void nd6_soltgt_free(struct nd6_prproxy_soltgt *);
static void nd6_soltgt_prune(struct nd6_prproxy_soltgt *, u_int32_t);
static __inline int soltgt_cmp(const struct nd6_prproxy_soltgt *,
    const struct nd6_prproxy_soltgt *);
static void nd6_prproxy_sols_purge(struct nd_prefix *, u_int64_t);

RB_PROTOTYPE_SC_PREV(__private_extern__, prproxy_sols_tree, nd6_prproxy_soltgt,
    soltgt_link, soltgt_cmp);

/*
 * Time (in seconds) before a target record expires (is idle).
 */
#define ND6_TGT_SOLS_EXPIRE                     5

/*
 * Maximum number of queued soliciting (source) records per target.
 */
#define ND6_MAX_SRC_SOLS_DEFAULT                4

/*
 * Maximum number of queued solicited (target) records per prefix.
 */
#define ND6_MAX_TGT_SOLS_DEFAULT                8

static u_int32_t nd6_max_tgt_sols = ND6_MAX_TGT_SOLS_DEFAULT;
static u_int32_t nd6_max_src_sols = ND6_MAX_SRC_SOLS_DEFAULT;

static unsigned int ndprl_size;                 /* size of zone element */
static struct zone *ndprl_zone;                 /* nd6_prproxy_prelist zone */

#define NDPRL_ZONE_MAX  256                     /* maximum elements in zone */
#define NDPRL_ZONE_NAME "nd6_prproxy_prelist"   /* name for zone */

static unsigned int solsrc_size;                /* size of zone element */
static struct zone *solsrc_zone;                /* nd6_prproxy_solsrc zone */

#define SOLSRC_ZONE_MAX  256                    /* maximum elements in zone */
#define SOLSRC_ZONE_NAME "nd6_prproxy_solsrc"   /* name for zone */

static unsigned int soltgt_size;                /* size of zone element */
static struct zone *soltgt_zone;                /* nd6_prproxy_soltgt zone */

#define SOLTGT_ZONE_MAX  256                    /* maximum elements in zone */
#define SOLTGT_ZONE_NAME "nd6_prproxy_soltgt"   /* name for zone */

/* The following is protected by ndpr_lock */
RB_GENERATE_PREV(prproxy_sols_tree, nd6_prproxy_soltgt,
    soltgt_link, soltgt_cmp);

/* The following is protected by proxy6_lock (for updates) */
u_int32_t nd6_prproxy;

extern lck_mtx_t *nd6_mutex;

SYSCTL_DECL(_net_inet6_icmp6);

SYSCTL_UINT(_net_inet6_icmp6, OID_AUTO, nd6_maxsolstgt,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_max_tgt_sols, ND6_MAX_TGT_SOLS_DEFAULT,
    "maximum number of outstanding solicited targets per prefix");

SYSCTL_UINT(_net_inet6_icmp6, OID_AUTO, nd6_maxproxiedsol,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_max_src_sols, ND6_MAX_SRC_SOLS_DEFAULT,
    "maximum number of outstanding solicitations per target");

SYSCTL_UINT(_net_inet6_icmp6, OID_AUTO, prproxy_cnt,
    CTLFLAG_RD | CTLFLAG_LOCKED, &nd6_prproxy, 0,
    "total number of proxied prefixes");

/*
 * Called by nd6_init() during initialization time.
 */
void
nd6_prproxy_init(void)
{
	ndprl_size = sizeof(struct nd6_prproxy_prelist);
	ndprl_zone = zinit(ndprl_size, NDPRL_ZONE_MAX * ndprl_size, 0,
	    NDPRL_ZONE_NAME);
	if (ndprl_zone == NULL) {
		panic("%s: failed allocating ndprl_zone", __func__);
	}

	zone_change(ndprl_zone, Z_EXPAND, TRUE);
	zone_change(ndprl_zone, Z_CALLERACCT, FALSE);

	solsrc_size = sizeof(struct nd6_prproxy_solsrc);
	solsrc_zone = zinit(solsrc_size, SOLSRC_ZONE_MAX * solsrc_size, 0,
	    SOLSRC_ZONE_NAME);
	if (solsrc_zone == NULL) {
		panic("%s: failed allocating solsrc_zone", __func__);
	}

	zone_change(solsrc_zone, Z_EXPAND, TRUE);
	zone_change(solsrc_zone, Z_CALLERACCT, FALSE);

	soltgt_size = sizeof(struct nd6_prproxy_soltgt);
	soltgt_zone = zinit(soltgt_size, SOLTGT_ZONE_MAX * soltgt_size, 0,
	    SOLTGT_ZONE_NAME);
	if (soltgt_zone == NULL) {
		panic("%s: failed allocating soltgt_zone", __func__);
	}

	zone_change(soltgt_zone, Z_EXPAND, TRUE);
	zone_change(soltgt_zone, Z_CALLERACCT, FALSE);
}

static struct nd6_prproxy_prelist *
nd6_ndprl_alloc(int how)
{
	struct nd6_prproxy_prelist *ndprl;

	ndprl = (how == M_WAITOK) ? zalloc(ndprl_zone) :
	    zalloc_noblock(ndprl_zone);
	if (ndprl != NULL) {
		bzero(ndprl, ndprl_size);
	}

	return ndprl;
}

static void
nd6_ndprl_free(struct nd6_prproxy_prelist *ndprl)
{
	zfree(ndprl_zone, ndprl);
}

/*
 * Apply routing function on the affected upstream and downstream prefixes,
 * i.e. either set or clear RTF_PROXY on the cloning prefix route; all route
 * entries that were cloned off these prefixes will be blown away.  Caller
 * must have acquried proxy6_lock and must not be holding nd6_mutex.
 */
static void
nd6_prproxy_prelist_setroute(boolean_t enable,
    struct nd6_prproxy_prelist_head *up_head,
    struct nd6_prproxy_prelist_head *down_head)
{
	struct nd6_prproxy_prelist *up, *down, *ndprl_tmp;
	struct nd_prefix *pr;

	LCK_MTX_ASSERT(&proxy6_lock, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	SLIST_FOREACH_SAFE(up, up_head, ndprl_le, ndprl_tmp) {
		struct rtentry *rt;
		boolean_t prproxy, set_allmulti = FALSE;
		int allmulti_sw = FALSE;
		struct ifnet *ifp = NULL;

		SLIST_REMOVE(up_head, up, nd6_prproxy_prelist, ndprl_le);
		pr = up->ndprl_pr;
		VERIFY(up->ndprl_up == NULL);

		NDPR_LOCK(pr);
		ifp = pr->ndpr_ifp;
		prproxy = (pr->ndpr_stateflags & NDPRF_PRPROXY);
		VERIFY(!prproxy || ((pr->ndpr_stateflags & NDPRF_ONLINK) &&
		    !(pr->ndpr_stateflags & NDPRF_IFSCOPE)));

		nd6_prproxy_sols_reap(pr);
		VERIFY(pr->ndpr_prproxy_sols_cnt == 0);
		VERIFY(RB_EMPTY(&pr->ndpr_prproxy_sols));

		if (enable && pr->ndpr_allmulti_cnt == 0) {
			nd6_prproxy++;
			pr->ndpr_allmulti_cnt++;
			set_allmulti = TRUE;
			allmulti_sw = TRUE;
		} else if (!enable && pr->ndpr_allmulti_cnt > 0) {
			nd6_prproxy--;
			pr->ndpr_allmulti_cnt--;
			set_allmulti = TRUE;
			allmulti_sw = FALSE;
		}

		if ((rt = pr->ndpr_rt) != NULL) {
			if ((enable && prproxy) || (!enable && !prproxy)) {
				RT_ADDREF(rt);
			} else {
				rt = NULL;
			}
			NDPR_UNLOCK(pr);
		} else {
			NDPR_UNLOCK(pr);
		}

		/* Call the following ioctl after releasing NDPR lock */
		if (set_allmulti && ifp != NULL) {
			if_allmulti(ifp, allmulti_sw);
		}


		NDPR_REMREF(pr);
		if (rt != NULL) {
			rt_set_proxy(rt, enable);
			rtfree(rt);
		}
		nd6_ndprl_free(up);
	}

	SLIST_FOREACH_SAFE(down, down_head, ndprl_le, ndprl_tmp) {
		struct nd_prefix *pr_up;
		struct rtentry *rt;
		boolean_t prproxy, set_allmulti = FALSE;
		int allmulti_sw = FALSE;
		struct ifnet *ifp = NULL;

		SLIST_REMOVE(down_head, down, nd6_prproxy_prelist, ndprl_le);
		pr = down->ndprl_pr;
		pr_up = down->ndprl_up;
		VERIFY(pr_up != NULL);

		NDPR_LOCK(pr_up);
		ifp = pr->ndpr_ifp;
		prproxy = (pr_up->ndpr_stateflags & NDPRF_PRPROXY);
		VERIFY(!prproxy || ((pr_up->ndpr_stateflags & NDPRF_ONLINK) &&
		    !(pr_up->ndpr_stateflags & NDPRF_IFSCOPE)));
		NDPR_UNLOCK(pr_up);

		NDPR_LOCK(pr);
		if (enable && pr->ndpr_allmulti_cnt == 0) {
			pr->ndpr_allmulti_cnt++;
			set_allmulti = TRUE;
			allmulti_sw = TRUE;
		} else if (!enable && pr->ndpr_allmulti_cnt > 0) {
			pr->ndpr_allmulti_cnt--;
			set_allmulti = TRUE;
			allmulti_sw = FALSE;
		}

		if ((rt = pr->ndpr_rt) != NULL) {
			if ((enable && prproxy) || (!enable && !prproxy)) {
				RT_ADDREF(rt);
			} else {
				rt = NULL;
			}
			NDPR_UNLOCK(pr);
		} else {
			NDPR_UNLOCK(pr);
		}
		if (set_allmulti && ifp != NULL) {
			if_allmulti(ifp, allmulti_sw);
		}

		NDPR_REMREF(pr);
		NDPR_REMREF(pr_up);
		if (rt != NULL) {
			rt_set_proxy(rt, enable);
			rtfree(rt);
		}
		nd6_ndprl_free(down);
	}
}

/*
 * Enable/disable prefix proxying on an interface; typically called
 * as part of handling SIOCSIFINFO_FLAGS[IFEF_IPV6_ROUTER].
 */
int
nd6_if_prproxy(struct ifnet *ifp, boolean_t enable)
{
	SLIST_HEAD(, nd6_prproxy_prelist) up_head;
	SLIST_HEAD(, nd6_prproxy_prelist) down_head;
	struct nd6_prproxy_prelist *up, *down;
	struct nd_prefix *pr;

	/* Can't be enabled if we are an advertising router on the interface */
	ifnet_lock_shared(ifp);
	if (enable && (ifp->if_eflags & IFEF_IPV6_ROUTER)) {
		ifnet_lock_done(ifp);
		return EBUSY;
	}
	ifnet_lock_done(ifp);

	SLIST_INIT(&up_head);
	SLIST_INIT(&down_head);

	/*
	 * Serialize the clearing/setting of NDPRF_PRPROXY.
	 */
	lck_mtx_lock(&proxy6_lock);

	/*
	 * First build a list of upstream prefixes on this interface for
	 * which we need to enable/disable prefix proxy functionality.
	 */
	lck_mtx_lock(nd6_mutex);
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		NDPR_LOCK(pr);
		if (IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_prefix.sin6_addr) ||
		    (!enable && !(pr->ndpr_stateflags & NDPRF_PRPROXY)) ||
		    (enable && (pr->ndpr_stateflags & NDPRF_PRPROXY)) ||
		    (pr->ndpr_stateflags & NDPRF_IFSCOPE) ||
		    pr->ndpr_ifp != ifp) {
			NDPR_UNLOCK(pr);
			continue;
		}

		/*
		 * At present, in order for the prefix to be eligible
		 * as a proxying/proxied prefix, we require that the
		 * prefix route entry be marked as a cloning route with
		 * RTF_PROXY; i.e. nd6_need_cache() needs to return
		 * true for the interface type.
		 */
		if (enable && (pr->ndpr_stateflags & NDPRF_ONLINK) &&
		    nd6_need_cache(ifp)) {
			pr->ndpr_stateflags |= NDPRF_PRPROXY;
			NDPR_ADDREF_LOCKED(pr);
			NDPR_UNLOCK(pr);
		} else if (!enable) {
			pr->ndpr_stateflags &= ~NDPRF_PRPROXY;
			NDPR_ADDREF_LOCKED(pr);
			NDPR_UNLOCK(pr);
		} else {
			NDPR_UNLOCK(pr);
			pr = NULL;      /* don't go further */
		}

		if (pr == NULL) {
			break;
		}

		up = nd6_ndprl_alloc(M_WAITOK);
		if (up == NULL) {
			NDPR_REMREF(pr);
			continue;
		}

		up->ndprl_pr = pr;      /* keep reference from above */
		SLIST_INSERT_HEAD(&up_head, up, ndprl_le);
	}

	/*
	 * Now build a list of matching (scoped) downstream prefixes on other
	 * interfaces which need to be enabled/disabled accordingly.  Note that
	 * the NDPRF_PRPROXY is never set/cleared on the downstream prefixes.
	 */
	SLIST_FOREACH(up, &up_head, ndprl_le) {
		struct nd_prefix *fwd;
		struct in6_addr pr_addr;
		u_char pr_len;

		pr = up->ndprl_pr;

		NDPR_LOCK(pr);
		bcopy(&pr->ndpr_prefix.sin6_addr, &pr_addr, sizeof(pr_addr));
		pr_len = pr->ndpr_plen;
		NDPR_UNLOCK(pr);

		for (fwd = nd_prefix.lh_first; fwd; fwd = fwd->ndpr_next) {
			NDPR_LOCK(fwd);
			if (!(fwd->ndpr_stateflags & NDPRF_ONLINK) ||
			    !(fwd->ndpr_stateflags & NDPRF_IFSCOPE) ||
			    fwd->ndpr_plen != pr_len ||
			    !in6_are_prefix_equal(&fwd->ndpr_prefix.sin6_addr,
			    &pr_addr, pr_len)) {
				NDPR_UNLOCK(fwd);
				continue;
			}
			NDPR_UNLOCK(fwd);

			down = nd6_ndprl_alloc(M_WAITOK);
			if (down == NULL) {
				continue;
			}

			NDPR_ADDREF(fwd);
			down->ndprl_pr = fwd;
			NDPR_ADDREF(pr);
			down->ndprl_up = pr;
			SLIST_INSERT_HEAD(&down_head, down, ndprl_le);
		}
	}
	lck_mtx_unlock(nd6_mutex);

	/*
	 * Apply routing function on prefixes; callee will free resources.
	 */
	nd6_prproxy_prelist_setroute(enable,
	    (struct nd6_prproxy_prelist_head *)&up_head,
	    (struct nd6_prproxy_prelist_head *)&down_head);

	VERIFY(SLIST_EMPTY(&up_head));
	VERIFY(SLIST_EMPTY(&down_head));

	lck_mtx_unlock(&proxy6_lock);

	return 0;
}

/*
 * Called from the input path to determine whether the packet is destined
 * to a proxied node; if so, mark the mbuf with PKTFF_PROXY_DST so that
 * icmp6_input() knows that this is not to be delivered to socket(s).
 */
boolean_t
nd6_prproxy_isours(struct mbuf *m, struct ip6_hdr *ip6, struct route_in6 *ro6,
    unsigned int ifscope)
{
	struct rtentry *rt;
	boolean_t ours = FALSE;

	if (ip6->ip6_hlim != IPV6_MAXHLIM || ip6->ip6_nxt != IPPROTO_ICMPV6) {
		goto done;
	}

	if (IN6_IS_ADDR_MC_NODELOCAL(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&ip6->ip6_dst)) {
		VERIFY(ro6 == NULL);
		ours = TRUE;
		goto done;
	} else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		goto done;
	}

	if (ro6 == NULL) {
		goto done;
	}

	if ((rt = ro6->ro_rt) != NULL) {
		RT_LOCK(rt);
	}

	if (ROUTE_UNUSABLE(ro6)) {
		if (rt != NULL) {
			RT_UNLOCK(rt);
		}

		ROUTE_RELEASE(ro6);

		/* Caller must have ensured this condition (not srcrt) */
		VERIFY(IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
		    &ro6->ro_dst.sin6_addr));

		rtalloc_scoped_ign((struct route *)ro6, RTF_PRCLONING, ifscope);
		if ((rt = ro6->ro_rt) == NULL) {
			goto done;
		}

		RT_LOCK(rt);
	}

	ours = (rt->rt_flags & RTF_PROXY) ? TRUE : FALSE;
	RT_UNLOCK(rt);

done:
	if (ours) {
		m->m_pkthdr.pkt_flags |= PKTF_PROXY_DST;
	}

	return ours;
}

/*
 * Called from the input path to determine whether or not the proxy
 * route entry is pointing to the correct interface, and to perform
 * the necessary route fixups otherwise.
 */
void
nd6_proxy_find_fwdroute(struct ifnet *ifp, struct route_in6 *ro6)
{
	struct in6_addr *dst6 = &ro6->ro_dst.sin6_addr;
	struct ifnet *fwd_ifp = NULL;
	struct nd_prefix *pr;
	struct rtentry *rt;

	if ((rt = ro6->ro_rt) != NULL) {
		RT_LOCK(rt);
		if (!(rt->rt_flags & RTF_PROXY) || rt->rt_ifp == ifp) {
			nd6log2((LOG_DEBUG, "%s: found incorrect prefix "
			    "proxy route for dst %s on %s\n", if_name(ifp),
			    ip6_sprintf(dst6),
			    if_name(rt->rt_ifp)));
			RT_UNLOCK(rt);
			/* look it up below */
		} else {
			RT_UNLOCK(rt);
			/*
			 * The route is already marked with RTF_PRPROXY and
			 * it isn't pointing back to the inbound interface;
			 * optimistically return (see notes below).
			 */
			return;
		}
	}

	/*
	 * Find out where we should forward this packet to, by searching
	 * for another interface that is proxying for the prefix.  Our
	 * current implementation assumes that the proxied prefix is shared
	 * to no more than one downstream interfaces (typically a bridge
	 * interface).
	 */
	lck_mtx_lock(nd6_mutex);
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		struct in6_addr pr_addr;
		struct nd_prefix *fwd;
		u_char pr_len;

		NDPR_LOCK(pr);
		if (!(pr->ndpr_stateflags & NDPRF_ONLINK) ||
		    !(pr->ndpr_stateflags & NDPRF_PRPROXY) ||
		    !IN6_ARE_MASKED_ADDR_EQUAL(&pr->ndpr_prefix.sin6_addr,
		    dst6, &pr->ndpr_mask)) {
			NDPR_UNLOCK(pr);
			continue;
		}

		VERIFY(!(pr->ndpr_stateflags & NDPRF_IFSCOPE));
		bcopy(&pr->ndpr_prefix.sin6_addr, &pr_addr, sizeof(pr_addr));
		pr_len = pr->ndpr_plen;
		NDPR_UNLOCK(pr);

		for (fwd = nd_prefix.lh_first; fwd; fwd = fwd->ndpr_next) {
			NDPR_LOCK(fwd);
			if (!(fwd->ndpr_stateflags & NDPRF_ONLINK) ||
			    fwd->ndpr_ifp == ifp ||
			    fwd->ndpr_plen != pr_len ||
			    !in6_are_prefix_equal(&fwd->ndpr_prefix.sin6_addr,
			    &pr_addr, pr_len)) {
				NDPR_UNLOCK(fwd);
				continue;
			}

			fwd_ifp = fwd->ndpr_ifp;
			NDPR_UNLOCK(fwd);
			break;
		}
		break;
	}
	lck_mtx_unlock(nd6_mutex);

	lck_mtx_lock(rnh_lock);
	ROUTE_RELEASE_LOCKED(ro6);

	/*
	 * Lookup a forwarding route; delete the route if it's incorrect,
	 * or return to caller if the correct one got created prior to
	 * our acquiring the rnh_lock.
	 */
	if ((rt = rtalloc1_scoped_locked(SA(&ro6->ro_dst), 0,
	    RTF_CLONING | RTF_PRCLONING, IFSCOPE_NONE)) != NULL) {
		RT_LOCK(rt);
		if (rt->rt_ifp != fwd_ifp || !(rt->rt_flags & RTF_PROXY)) {
			rt->rt_flags |= RTF_CONDEMNED;
			RT_UNLOCK(rt);
			(void) rtrequest_locked(RTM_DELETE, rt_key(rt),
			    rt->rt_gateway, rt_mask(rt), rt->rt_flags, NULL);
			rtfree_locked(rt);
			rt = NULL;
		} else {
			nd6log2((LOG_DEBUG, "%s: found prefix proxy route "
			    "for dst %s\n", if_name(rt->rt_ifp),
			    ip6_sprintf(dst6)));
			RT_UNLOCK(rt);
			ro6->ro_rt = rt;        /* refcnt held by rtalloc1 */
			lck_mtx_unlock(rnh_lock);
			return;
		}
	}
	VERIFY(rt == NULL && ro6->ro_rt == NULL);

	/*
	 * Clone a route from the correct parent prefix route and return it.
	 */
	if (fwd_ifp != NULL && (rt = rtalloc1_scoped_locked(SA(&ro6->ro_dst), 1,
	    RTF_PRCLONING, fwd_ifp->if_index)) != NULL) {
		RT_LOCK(rt);
		if (!(rt->rt_flags & RTF_PROXY)) {
			RT_UNLOCK(rt);
			rtfree_locked(rt);
			rt = NULL;
		} else {
			nd6log2((LOG_DEBUG, "%s: allocated prefix proxy "
			    "route for dst %s\n", if_name(rt->rt_ifp),
			    ip6_sprintf(dst6)));
			RT_UNLOCK(rt);
			ro6->ro_rt = rt;        /* refcnt held by rtalloc1 */
		}
	}
	VERIFY(rt != NULL || ro6->ro_rt == NULL);

	if (fwd_ifp == NULL || rt == NULL) {
		nd6log2((LOG_ERR, "%s: failed to find forwarding prefix "
		    "proxy entry for dst %s\n", if_name(ifp),
		    ip6_sprintf(dst6)));
	}
	lck_mtx_unlock(rnh_lock);
}

/*
 * Called when a prefix transitions between on-link and off-link.  Perform
 * routing (RTF_PROXY) and interface (all-multicast) related operations on
 * the affected prefixes.
 */
void
nd6_prproxy_prelist_update(struct nd_prefix *pr_cur, struct nd_prefix *pr_up)
{
	SLIST_HEAD(, nd6_prproxy_prelist) up_head;
	SLIST_HEAD(, nd6_prproxy_prelist) down_head;
	struct nd6_prproxy_prelist *up, *down;
	struct nd_prefix *pr;
	struct in6_addr pr_addr;
	boolean_t enable;
	u_char pr_len;

	SLIST_INIT(&up_head);
	SLIST_INIT(&down_head);
	VERIFY(pr_cur != NULL);

	LCK_MTX_ASSERT(&proxy6_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Upstream prefix.  If caller did not specify one, search for one
	 * based on the information in current prefix.  Caller is expected
	 * to have held an extra reference for the passed-in prefixes.
	 */
	lck_mtx_lock(nd6_mutex);
	if (pr_up == NULL) {
		NDPR_LOCK(pr_cur);
		bcopy(&pr_cur->ndpr_prefix.sin6_addr, &pr_addr,
		    sizeof(pr_addr));
		pr_len = pr_cur->ndpr_plen;
		NDPR_UNLOCK(pr_cur);

		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			NDPR_LOCK(pr);
			if (!(pr->ndpr_stateflags & NDPRF_ONLINK) ||
			    !(pr->ndpr_stateflags & NDPRF_PRPROXY) ||
			    pr->ndpr_plen != pr_len ||
			    !in6_are_prefix_equal(&pr->ndpr_prefix.sin6_addr,
			    &pr_addr, pr_len)) {
				NDPR_UNLOCK(pr);
				continue;
			}
			NDPR_UNLOCK(pr);
			break;
		}

		if ((pr_up = pr) == NULL) {
			lck_mtx_unlock(nd6_mutex);
			goto done;
		}
		NDPR_LOCK(pr_up);
	} else {
		NDPR_LOCK(pr_up);
		bcopy(&pr_up->ndpr_prefix.sin6_addr, &pr_addr,
		    sizeof(pr_addr));
		pr_len = pr_up->ndpr_plen;
	}
	NDPR_LOCK_ASSERT_HELD(pr_up);
	/*
	 * Upstream prefix could be offlink by now; therefore we cannot
	 * assert that NDPRF_PRPROXY is set; however, we can insist that
	 * it must not be a scoped prefix.
	 */
	VERIFY(!(pr_up->ndpr_stateflags & NDPRF_IFSCOPE));
	enable = (pr_up->ndpr_stateflags & NDPRF_PRPROXY);
	NDPR_UNLOCK(pr_up);

	up = nd6_ndprl_alloc(M_WAITOK);
	if (up == NULL) {
		lck_mtx_unlock(nd6_mutex);
		goto done;
	}

	NDPR_ADDREF(pr_up);
	up->ndprl_pr = pr_up;
	SLIST_INSERT_HEAD(&up_head, up, ndprl_le);

	/*
	 * Now build a list of matching (scoped) downstream prefixes on other
	 * interfaces which need to be enabled/disabled accordingly.  Note that
	 * the NDPRF_PRPROXY is never set/cleared on the downstream prefixes.
	 */
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		NDPR_LOCK(pr);
		if (!(pr->ndpr_stateflags & NDPRF_ONLINK) ||
		    !(pr->ndpr_stateflags & NDPRF_IFSCOPE) ||
		    pr->ndpr_plen != pr_len ||
		    !in6_are_prefix_equal(&pr->ndpr_prefix.sin6_addr,
		    &pr_addr, pr_len)) {
			NDPR_UNLOCK(pr);
			continue;
		}
		NDPR_UNLOCK(pr);

		down = nd6_ndprl_alloc(M_WAITOK);
		if (down == NULL) {
			continue;
		}

		NDPR_ADDREF(pr);
		down->ndprl_pr = pr;
		NDPR_ADDREF(pr_up);
		down->ndprl_up = pr_up;
		SLIST_INSERT_HEAD(&down_head, down, ndprl_le);
	}
	lck_mtx_unlock(nd6_mutex);

	/*
	 * Apply routing function on prefixes; callee will free resources.
	 */
	nd6_prproxy_prelist_setroute(enable,
	    (struct nd6_prproxy_prelist_head *)&up_head,
	    (struct nd6_prproxy_prelist_head *)&down_head);

done:
	VERIFY(SLIST_EMPTY(&up_head));
	VERIFY(SLIST_EMPTY(&down_head));
}

/*
 * Given an interface address, determine whether or not the address
 * is part of of a proxied prefix.
 */
boolean_t
nd6_prproxy_ifaddr(struct in6_ifaddr *ia)
{
	struct nd_prefix *pr;
	struct in6_addr addr, pr_mask;
	u_int32_t pr_len;
	boolean_t proxied = FALSE;

	LCK_MTX_ASSERT(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	IFA_LOCK(&ia->ia_ifa);
	bcopy(&ia->ia_addr.sin6_addr, &addr, sizeof(addr));
	bcopy(&ia->ia_prefixmask.sin6_addr, &pr_mask, sizeof(pr_mask));
	pr_len = ia->ia_plen;
	IFA_UNLOCK(&ia->ia_ifa);

	lck_mtx_lock(nd6_mutex);
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		NDPR_LOCK(pr);
		if ((pr->ndpr_stateflags & NDPRF_ONLINK) &&
		    (pr->ndpr_stateflags & NDPRF_PRPROXY) &&
		    in6_are_prefix_equal(&pr->ndpr_prefix.sin6_addr,
		    &addr, pr_len)) {
			NDPR_UNLOCK(pr);
			proxied = TRUE;
			break;
		}
		NDPR_UNLOCK(pr);
	}
	lck_mtx_unlock(nd6_mutex);

	return proxied;
}

/*
 * Perform automatic proxy function with NS output.
 *
 * If the target address matches a global prefix obtained from a router
 * advertisement received on an interface with the ND6_IFF_PROXY_PREFIXES
 * flag set, then we send solicitations for the target address to all other
 * interfaces where a matching prefix is currently on-link, in addition to
 * the original interface.
 */
void
nd6_prproxy_ns_output(struct ifnet *ifp, struct ifnet *exclifp,
    struct in6_addr *daddr, struct in6_addr *taddr, struct llinfo_nd6 *ln)
{
	SLIST_HEAD(, nd6_prproxy_prelist) ndprl_head;
	struct nd6_prproxy_prelist *ndprl, *ndprl_tmp;
	struct nd_prefix *pr, *fwd;
	struct ifnet *fwd_ifp;
	struct in6_addr pr_addr;
	u_char pr_len;

	/*
	 * Ignore excluded interface if it's the same as the original;
	 * we always send a NS on the original interface down below.
	 */
	if (exclifp != NULL && exclifp == ifp) {
		exclifp = NULL;
	}

	if (exclifp == NULL) {
		nd6log2((LOG_DEBUG, "%s: sending NS who has %s on ALL\n",
		    if_name(ifp), ip6_sprintf(taddr)));
	} else {
		nd6log2((LOG_DEBUG, "%s: sending NS who has %s on ALL "
		    "(except %s)\n", if_name(ifp),
		    ip6_sprintf(taddr), if_name(exclifp)));
	}

	SLIST_INIT(&ndprl_head);

	lck_mtx_lock(nd6_mutex);

	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		NDPR_LOCK(pr);
		if (!(pr->ndpr_stateflags & NDPRF_ONLINK) ||
		    !(pr->ndpr_stateflags & NDPRF_PRPROXY) ||
		    !IN6_ARE_MASKED_ADDR_EQUAL(&pr->ndpr_prefix.sin6_addr,
		    taddr, &pr->ndpr_mask)) {
			NDPR_UNLOCK(pr);
			continue;
		}

		VERIFY(!(pr->ndpr_stateflags & NDPRF_IFSCOPE));
		bcopy(&pr->ndpr_prefix.sin6_addr, &pr_addr, sizeof(pr_addr));
		pr_len = pr->ndpr_plen;
		NDPR_UNLOCK(pr);

		for (fwd = nd_prefix.lh_first; fwd; fwd = fwd->ndpr_next) {
			NDPR_LOCK(fwd);
			if (!(fwd->ndpr_stateflags & NDPRF_ONLINK) ||
			    fwd->ndpr_ifp == ifp || fwd->ndpr_ifp == exclifp ||
			    fwd->ndpr_plen != pr_len ||
			    !in6_are_prefix_equal(&fwd->ndpr_prefix.sin6_addr,
			    &pr_addr, pr_len)) {
				NDPR_UNLOCK(fwd);
				continue;
			}

			fwd_ifp = fwd->ndpr_ifp;
			NDPR_UNLOCK(fwd);

			ndprl = nd6_ndprl_alloc(M_WAITOK);
			if (ndprl == NULL) {
				continue;
			}

			NDPR_ADDREF(fwd);
			ndprl->ndprl_pr = fwd;
			ndprl->ndprl_fwd_ifp = fwd_ifp;

			SLIST_INSERT_HEAD(&ndprl_head, ndprl, ndprl_le);
		}
		break;
	}

	lck_mtx_unlock(nd6_mutex);

	SLIST_FOREACH_SAFE(ndprl, &ndprl_head, ndprl_le, ndprl_tmp) {
		SLIST_REMOVE(&ndprl_head, ndprl, nd6_prproxy_prelist, ndprl_le);

		pr = ndprl->ndprl_pr;
		fwd_ifp = ndprl->ndprl_fwd_ifp;

		if ((fwd_ifp->if_eflags & IFEF_IPV6_ND6ALT) != 0) {
			NDPR_REMREF(pr);
			nd6_ndprl_free(ndprl);
			continue;
		}

		NDPR_LOCK(pr);
		if (pr->ndpr_stateflags & NDPRF_ONLINK) {
			NDPR_UNLOCK(pr);
			nd6log2((LOG_DEBUG,
			    "%s: Sending cloned NS who has %s, originally "
			    "on %s\n", if_name(fwd_ifp),
			    ip6_sprintf(taddr), if_name(ifp)));

			nd6_ns_output(fwd_ifp, daddr, taddr, NULL, NULL);
		} else {
			NDPR_UNLOCK(pr);
		}
		NDPR_REMREF(pr);

		nd6_ndprl_free(ndprl);
	}
	VERIFY(SLIST_EMPTY(&ndprl_head));

	nd6_ns_output(ifp, daddr, taddr, ln, NULL);
}

/*
 * Perform automatic proxy function with NS input.
 *
 * If the target address matches a global prefix obtained from a router
 * advertisement received on an interface with the ND6_IFF_PROXY_PREFIXES
 * flag set, then we send solicitations for the target address to all other
 * interfaces where a matching prefix is currently on-link.
 */
void
nd6_prproxy_ns_input(struct ifnet *ifp, struct in6_addr *saddr,
    char *lladdr, int lladdrlen, struct in6_addr *daddr,
    struct in6_addr *taddr, uint8_t *nonce)
{
	SLIST_HEAD(, nd6_prproxy_prelist) ndprl_head;
	struct nd6_prproxy_prelist *ndprl, *ndprl_tmp;
	struct nd_prefix *pr, *fwd;
	struct ifnet *fwd_ifp;
	struct in6_addr pr_addr;
	u_char pr_len;
	boolean_t solrec = FALSE;

	SLIST_INIT(&ndprl_head);

	lck_mtx_lock(nd6_mutex);

	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		NDPR_LOCK(pr);
		if (!(pr->ndpr_stateflags & NDPRF_ONLINK) ||
		    !(pr->ndpr_stateflags & NDPRF_PRPROXY) ||
		    !IN6_ARE_MASKED_ADDR_EQUAL(&pr->ndpr_prefix.sin6_addr,
		    taddr, &pr->ndpr_mask)) {
			NDPR_UNLOCK(pr);
			continue;
		}

		VERIFY(!(pr->ndpr_stateflags & NDPRF_IFSCOPE));
		bcopy(&pr->ndpr_prefix.sin6_addr, &pr_addr, sizeof(pr_addr));
		pr_len = pr->ndpr_plen;

		/*
		 * If this is a NS for NUD/AR, record it so that we know
		 * how to forward the NA reply later on (if/when it arrives.)
		 * Give up if we fail to save the NS info.
		 */
		if ((solrec = !IN6_IS_ADDR_UNSPECIFIED(saddr)) &&
		    !nd6_solsrc_enq(pr, ifp, saddr, taddr)) {
			NDPR_UNLOCK(pr);
			solrec = FALSE;
			break;                  /* bail out */
		} else {
			NDPR_UNLOCK(pr);
		}

		for (fwd = nd_prefix.lh_first; fwd; fwd = fwd->ndpr_next) {
			NDPR_LOCK(fwd);
			if (!(fwd->ndpr_stateflags & NDPRF_ONLINK) ||
			    fwd->ndpr_ifp == ifp ||
			    fwd->ndpr_plen != pr_len ||
			    !in6_are_prefix_equal(&fwd->ndpr_prefix.sin6_addr,
			    &pr_addr, pr_len)) {
				NDPR_UNLOCK(fwd);
				continue;
			}

			fwd_ifp = fwd->ndpr_ifp;
			NDPR_UNLOCK(fwd);

			ndprl = nd6_ndprl_alloc(M_WAITOK);
			if (ndprl == NULL) {
				continue;
			}

			NDPR_ADDREF(fwd);
			ndprl->ndprl_pr = fwd;
			ndprl->ndprl_fwd_ifp = fwd_ifp;
			ndprl->ndprl_sol = solrec;

			SLIST_INSERT_HEAD(&ndprl_head, ndprl, ndprl_le);
		}
		break;
	}

	lck_mtx_unlock(nd6_mutex);

	/*
	 * If this is a recorded solicitation (NS for NUD/AR), create
	 * or update the neighbor cache entry for the soliciting node.
	 * Later on, when the NA reply arrives, we will need this cache
	 * entry in order to send the NA back to the original solicitor.
	 * Without a neighbor cache entry, we'd end up with an endless
	 * cycle of NS ping-pong between the us (the proxy) and the node
	 * which is soliciting for the address.
	 */
	if (solrec) {
		VERIFY(!IN6_IS_ADDR_UNSPECIFIED(saddr));
		nd6_cache_lladdr(ifp, saddr, lladdr, lladdrlen,
		    ND_NEIGHBOR_SOLICIT, 0);
	}

	SLIST_FOREACH_SAFE(ndprl, &ndprl_head, ndprl_le, ndprl_tmp) {
		SLIST_REMOVE(&ndprl_head, ndprl, nd6_prproxy_prelist, ndprl_le);

		pr = ndprl->ndprl_pr;
		fwd_ifp = ndprl->ndprl_fwd_ifp;

		if ((fwd_ifp->if_eflags & IFEF_IPV6_ND6ALT) != 0) {
			NDPR_REMREF(pr);
			nd6_ndprl_free(ndprl);
			continue;
		}

		NDPR_LOCK(pr);
		if (pr->ndpr_stateflags & NDPRF_ONLINK) {
			NDPR_UNLOCK(pr);
			nd6log2((LOG_DEBUG,
			    "%s: Forwarding NS (%s) from %s to %s who "
			    "has %s, originally on %s\n", if_name(fwd_ifp),
			    ndprl->ndprl_sol ? "NUD/AR" :
			    "DAD", ip6_sprintf(saddr), ip6_sprintf(daddr),
			    ip6_sprintf(taddr), if_name(ifp)));

			nd6_ns_output(fwd_ifp, ndprl->ndprl_sol ? taddr : NULL,
			    taddr, NULL, nonce);
		} else {
			NDPR_UNLOCK(pr);
		}
		NDPR_REMREF(pr);

		nd6_ndprl_free(ndprl);
	}
	VERIFY(SLIST_EMPTY(&ndprl_head));
}

/*
 * Perform automatic proxy function with NA input.
 *
 * If the target address matches a global prefix obtained from a router
 * advertisement received on an interface with the ND6_IFF_PROXY_PREFIXES flag
 * set, then we send neighbor advertisements for the target address on all
 * other interfaces where a matching prefix is currently on link.
 */
void
nd6_prproxy_na_input(struct ifnet *ifp, struct in6_addr *saddr,
    struct in6_addr *daddr0, struct in6_addr *taddr, int flags)
{
	SLIST_HEAD(, nd6_prproxy_prelist) ndprl_head;
	struct nd6_prproxy_prelist *ndprl, *ndprl_tmp;
	struct nd_prefix *pr;
	struct ifnet *fwd_ifp;
	struct in6_addr daddr;

	SLIST_INIT(&ndprl_head);


	lck_mtx_lock(nd6_mutex);

	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		NDPR_LOCK(pr);
		if (!(pr->ndpr_stateflags & NDPRF_ONLINK) ||
		    !(pr->ndpr_stateflags & NDPRF_PRPROXY) ||
		    !IN6_ARE_MASKED_ADDR_EQUAL(&pr->ndpr_prefix.sin6_addr,
		    taddr, &pr->ndpr_mask)) {
			NDPR_UNLOCK(pr);
			continue;
		}

		VERIFY(!(pr->ndpr_stateflags & NDPRF_IFSCOPE));
		/*
		 * If this is a NA for NUD, see if there is a record created
		 * for the corresponding NS; upon success, we get back the
		 * interface where the NS originally arrived on, as well as
		 * the soliciting node's address.  Give up if we can't find it.
		 */
		if (!IN6_IS_ADDR_MULTICAST(daddr0)) {
			fwd_ifp = NULL;
			bzero(&daddr, sizeof(daddr));
			if (!nd6_solsrc_deq(pr, taddr, &daddr, &fwd_ifp)) {
				NDPR_UNLOCK(pr);
				break;          /* bail out */
			}
			VERIFY(!IN6_IS_ADDR_UNSPECIFIED(&daddr) && fwd_ifp);
			NDPR_UNLOCK(pr);

			ndprl = nd6_ndprl_alloc(M_WAITOK);
			if (ndprl == NULL) {
				break;          /* bail out */
			}
			ndprl->ndprl_fwd_ifp = fwd_ifp;
			ndprl->ndprl_sol = TRUE;
			ndprl->ndprl_sol_saddr = *(&daddr);

			SLIST_INSERT_HEAD(&ndprl_head, ndprl, ndprl_le);
		} else {
			struct nd_prefix *fwd;
			struct in6_addr pr_addr;
			u_char pr_len;

			bcopy(&pr->ndpr_prefix.sin6_addr, &pr_addr,
			    sizeof(pr_addr));
			pr_len = pr->ndpr_plen;
			NDPR_UNLOCK(pr);

			for (fwd = nd_prefix.lh_first; fwd;
			    fwd = fwd->ndpr_next) {
				NDPR_LOCK(fwd);
				if (!(fwd->ndpr_stateflags & NDPRF_ONLINK) ||
				    fwd->ndpr_ifp == ifp ||
				    fwd->ndpr_plen != pr_len ||
				    !in6_are_prefix_equal(
					    &fwd->ndpr_prefix.sin6_addr,
					    &pr_addr, pr_len)) {
					NDPR_UNLOCK(fwd);
					continue;
				}

				fwd_ifp = fwd->ndpr_ifp;
				NDPR_UNLOCK(fwd);

				ndprl = nd6_ndprl_alloc(M_WAITOK);
				if (ndprl == NULL) {
					continue;
				}

				NDPR_ADDREF(fwd);
				ndprl->ndprl_pr = fwd;
				ndprl->ndprl_fwd_ifp = fwd_ifp;

				SLIST_INSERT_HEAD(&ndprl_head, ndprl, ndprl_le);
			}
		}
		break;
	}

	lck_mtx_unlock(nd6_mutex);

	SLIST_FOREACH_SAFE(ndprl, &ndprl_head, ndprl_le, ndprl_tmp) {
		boolean_t send_na;

		SLIST_REMOVE(&ndprl_head, ndprl, nd6_prproxy_prelist, ndprl_le);

		pr = ndprl->ndprl_pr;
		fwd_ifp = ndprl->ndprl_fwd_ifp;

		if (ndprl->ndprl_sol) {
			VERIFY(pr == NULL);
			daddr = *(&ndprl->ndprl_sol_saddr);
			VERIFY(!IN6_IS_ADDR_UNSPECIFIED(&daddr));
			send_na = (in6_setscope(&daddr, fwd_ifp, NULL) == 0);
		} else {
			VERIFY(pr != NULL);
			daddr = *daddr0;
			NDPR_LOCK(pr);
			send_na = ((pr->ndpr_stateflags & NDPRF_ONLINK) &&
			    in6_setscope(&daddr, fwd_ifp, NULL) == 0);
			NDPR_UNLOCK(pr);
		}

		if (send_na) {
			if (!ndprl->ndprl_sol) {
				nd6log2((LOG_DEBUG,
				    "%s: Forwarding NA (DAD) from %s to %s "
				    "tgt is %s, originally on %s\n",
				    if_name(fwd_ifp),
				    ip6_sprintf(saddr), ip6_sprintf(&daddr),
				    ip6_sprintf(taddr), if_name(ifp)));
			} else {
				nd6log2((LOG_DEBUG,
				    "%s: Forwarding NA (NUD/AR) from %s to "
				    "%s (was %s) tgt is %s, originally on "
				    "%s\n", if_name(fwd_ifp),
				    ip6_sprintf(saddr),
				    ip6_sprintf(&daddr), ip6_sprintf(daddr0),
				    ip6_sprintf(taddr), if_name(ifp)));
			}

			nd6_na_output(fwd_ifp, &daddr, taddr, flags, 1, NULL);
		}

		if (pr != NULL) {
			NDPR_REMREF(pr);
		}

		nd6_ndprl_free(ndprl);
	}
	VERIFY(SLIST_EMPTY(&ndprl_head));
}

static struct nd6_prproxy_solsrc *
nd6_solsrc_alloc(int how)
{
	struct nd6_prproxy_solsrc *ssrc;

	ssrc = (how == M_WAITOK) ? zalloc(solsrc_zone) :
	    zalloc_noblock(solsrc_zone);
	if (ssrc != NULL) {
		bzero(ssrc, solsrc_size);
	}

	return ssrc;
}

static void
nd6_solsrc_free(struct nd6_prproxy_solsrc *ssrc)
{
	zfree(solsrc_zone, ssrc);
}

static void
nd6_prproxy_sols_purge(struct nd_prefix *pr, u_int64_t max_stgt)
{
	struct nd6_prproxy_soltgt *soltgt, *tmp;
	u_int64_t expire = (max_stgt > 0) ? net_uptime() : 0;

	NDPR_LOCK_ASSERT_HELD(pr);

	/* Either trim all or those that have expired or are idle */
	RB_FOREACH_SAFE(soltgt, prproxy_sols_tree,
	    &pr->ndpr_prproxy_sols, tmp) {
		VERIFY(pr->ndpr_prproxy_sols_cnt > 0);
		if (expire == 0 || soltgt->soltgt_expire <= expire ||
		    soltgt->soltgt_cnt == 0) {
			pr->ndpr_prproxy_sols_cnt--;
			RB_REMOVE(prproxy_sols_tree,
			    &pr->ndpr_prproxy_sols, soltgt);
			nd6_soltgt_free(soltgt);
		}
	}

	if (max_stgt == 0 || pr->ndpr_prproxy_sols_cnt < max_stgt) {
		VERIFY(max_stgt != 0 || (pr->ndpr_prproxy_sols_cnt == 0 &&
		    RB_EMPTY(&pr->ndpr_prproxy_sols)));
		return;
	}

	/* Brute force; mercilessly evict entries until we are under limit */
	RB_FOREACH_SAFE(soltgt, prproxy_sols_tree,
	    &pr->ndpr_prproxy_sols, tmp) {
		VERIFY(pr->ndpr_prproxy_sols_cnt > 0);
		pr->ndpr_prproxy_sols_cnt--;
		RB_REMOVE(prproxy_sols_tree, &pr->ndpr_prproxy_sols, soltgt);
		nd6_soltgt_free(soltgt);
		if (pr->ndpr_prproxy_sols_cnt < max_stgt) {
			break;
		}
	}
}

/*
 * Purges all solicitation records on a given prefix.
 * Caller is responsible for holding prefix lock.
 */
void
nd6_prproxy_sols_reap(struct nd_prefix *pr)
{
	nd6_prproxy_sols_purge(pr, 0);
}

/*
 * Purges expired or idle solicitation records on a given prefix.
 * Caller is responsible for holding prefix lock.
 */
void
nd6_prproxy_sols_prune(struct nd_prefix *pr, u_int32_t max_stgt)
{
	nd6_prproxy_sols_purge(pr, max_stgt);
}

/*
 * Enqueue a soliciation record in the target record of a prefix.
 */
static boolean_t
nd6_solsrc_enq(struct nd_prefix *pr, struct ifnet *ifp,
    struct in6_addr *saddr, struct in6_addr *taddr)
{
	struct nd6_prproxy_soltgt find, *soltgt;
	struct nd6_prproxy_solsrc *ssrc;
	u_int32_t max_stgt = nd6_max_tgt_sols;
	u_int32_t max_ssrc = nd6_max_src_sols;

	NDPR_LOCK_ASSERT_HELD(pr);
	VERIFY(!(pr->ndpr_stateflags & NDPRF_IFSCOPE));
	VERIFY((pr->ndpr_stateflags & (NDPRF_ONLINK | NDPRF_PRPROXY)) ==
	    (NDPRF_ONLINK | NDPRF_PRPROXY));
	VERIFY(!IN6_IS_ADDR_UNSPECIFIED(saddr));

	ssrc = nd6_solsrc_alloc(M_WAITOK);
	if (ssrc == NULL) {
		return FALSE;
	}

	ssrc->solsrc_saddr = *saddr;
	ssrc->solsrc_ifp = ifp;

	find.soltgt_key.taddr = *taddr;         /* search key */

	soltgt = RB_FIND(prproxy_sols_tree, &pr->ndpr_prproxy_sols, &find);
	if (soltgt == NULL) {
		if (max_stgt != 0 && pr->ndpr_prproxy_sols_cnt >= max_stgt) {
			VERIFY(!RB_EMPTY(&pr->ndpr_prproxy_sols));
			nd6_prproxy_sols_prune(pr, max_stgt);
			VERIFY(pr->ndpr_prproxy_sols_cnt < max_stgt);
		}

		soltgt = nd6_soltgt_alloc(M_WAITOK);
		if (soltgt == NULL) {
			nd6_solsrc_free(ssrc);
			return FALSE;
		}

		soltgt->soltgt_key.taddr = *taddr;
		VERIFY(soltgt->soltgt_cnt == 0);
		VERIFY(TAILQ_EMPTY(&soltgt->soltgt_q));

		pr->ndpr_prproxy_sols_cnt++;
		VERIFY(pr->ndpr_prproxy_sols_cnt != 0);
		RB_INSERT(prproxy_sols_tree, &pr->ndpr_prproxy_sols, soltgt);
	}

	if (max_ssrc != 0 && soltgt->soltgt_cnt >= max_ssrc) {
		VERIFY(!TAILQ_EMPTY(&soltgt->soltgt_q));
		nd6_soltgt_prune(soltgt, max_ssrc);
		VERIFY(soltgt->soltgt_cnt < max_ssrc);
	}

	soltgt->soltgt_cnt++;
	VERIFY(soltgt->soltgt_cnt != 0);
	TAILQ_INSERT_TAIL(&soltgt->soltgt_q, ssrc, solsrc_tqe);
	if (soltgt->soltgt_cnt == 1) {
		soltgt->soltgt_expire = net_uptime() + ND6_TGT_SOLS_EXPIRE;
	}

	return TRUE;
}

/*
 * Dequeue a solicitation record from a target record of a prefix.
 */
static boolean_t
nd6_solsrc_deq(struct nd_prefix *pr, struct in6_addr *taddr,
    struct in6_addr *daddr, struct ifnet **ifp)
{
	struct nd6_prproxy_soltgt find, *soltgt;
	struct nd6_prproxy_solsrc *ssrc;

	NDPR_LOCK_ASSERT_HELD(pr);
	VERIFY(!(pr->ndpr_stateflags & NDPRF_IFSCOPE));
	VERIFY((pr->ndpr_stateflags & (NDPRF_ONLINK | NDPRF_PRPROXY)) ==
	    (NDPRF_ONLINK | NDPRF_PRPROXY));

	bzero(daddr, sizeof(*daddr));
	*ifp = NULL;

	find.soltgt_key.taddr = *taddr;         /* search key */

	soltgt = RB_FIND(prproxy_sols_tree, &pr->ndpr_prproxy_sols, &find);
	if (soltgt == NULL || soltgt->soltgt_cnt == 0) {
		VERIFY(soltgt == NULL || TAILQ_EMPTY(&soltgt->soltgt_q));
		return FALSE;
	}

	VERIFY(soltgt->soltgt_cnt != 0);
	--soltgt->soltgt_cnt;
	ssrc = TAILQ_FIRST(&soltgt->soltgt_q);
	VERIFY(ssrc != NULL);
	TAILQ_REMOVE(&soltgt->soltgt_q, ssrc, solsrc_tqe);
	*daddr = *(&ssrc->solsrc_saddr);
	*ifp = ssrc->solsrc_ifp;
	nd6_solsrc_free(ssrc);

	return TRUE;
}

static struct nd6_prproxy_soltgt *
nd6_soltgt_alloc(int how)
{
	struct nd6_prproxy_soltgt *soltgt;

	soltgt = (how == M_WAITOK) ? zalloc(soltgt_zone) :
	    zalloc_noblock(soltgt_zone);
	if (soltgt != NULL) {
		bzero(soltgt, soltgt_size);
		TAILQ_INIT(&soltgt->soltgt_q);
	}
	return soltgt;
}

static void
nd6_soltgt_free(struct nd6_prproxy_soltgt *soltgt)
{
	struct nd6_prproxy_solsrc *ssrc, *tssrc;

	TAILQ_FOREACH_SAFE(ssrc, &soltgt->soltgt_q, solsrc_tqe, tssrc) {
		VERIFY(soltgt->soltgt_cnt > 0);
		soltgt->soltgt_cnt--;
		TAILQ_REMOVE(&soltgt->soltgt_q, ssrc, solsrc_tqe);
		nd6_solsrc_free(ssrc);
	}

	VERIFY(soltgt->soltgt_cnt == 0);
	VERIFY(TAILQ_EMPTY(&soltgt->soltgt_q));

	zfree(soltgt_zone, soltgt);
}

static void
nd6_soltgt_prune(struct nd6_prproxy_soltgt *soltgt, u_int32_t max_ssrc)
{
	while (soltgt->soltgt_cnt >= max_ssrc) {
		struct nd6_prproxy_solsrc *ssrc;

		VERIFY(soltgt->soltgt_cnt != 0);
		--soltgt->soltgt_cnt;
		ssrc = TAILQ_FIRST(&soltgt->soltgt_q);
		VERIFY(ssrc != NULL);
		TAILQ_REMOVE(&soltgt->soltgt_q, ssrc, solsrc_tqe);
		nd6_solsrc_free(ssrc);
	}
}

/*
 * Solicited target tree comparison function.
 *
 * An ordered predicate is necessary; bcmp() is not documented to return
 * an indication of order, memcmp() is, and is an ISO C99 requirement.
 */
static __inline int
soltgt_cmp(const struct nd6_prproxy_soltgt *a,
    const struct nd6_prproxy_soltgt *b)
{
	return memcmp(&a->soltgt_key, &b->soltgt_key, sizeof(a->soltgt_key));
}
