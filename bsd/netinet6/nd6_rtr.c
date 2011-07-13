/*
 * Copyright (c) 2003-2011 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/nd6_rtr.c,v 1.11 2002/04/19 04:46:23 suz Exp $	*/
/*	$KAME: nd6_rtr.c,v 1.111 2001/04/27 01:37:15 jinmei Exp $	*/

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


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#include <sys/mcache.h>

#include <kern/lock.h>
#include <kern/zalloc.h>
#include <machine/machine_routines.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/radix.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_ifattach.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/icmp6.h>
#include <netinet6/scope6_var.h>

#include <net/net_osdep.h>

#define SDL(s)	((struct sockaddr_dl *)s)

static struct nd_defrouter *defrtrlist_update_common(struct nd_defrouter *,
    boolean_t);
static struct nd_defrouter *defrtrlist_update(struct nd_defrouter *);

static struct in6_ifaddr *in6_ifadd(struct nd_prefix *, int);
static void defrtrlist_sync(struct ifnet *);

static void defrouter_select_common(struct ifnet *, int);

static struct nd_pfxrouter *pfxrtr_lookup(struct nd_prefix *,
	struct nd_defrouter *);
static void pfxrtr_add(struct nd_prefix *, struct nd_defrouter *);
static void pfxrtr_del(struct nd_pfxrouter *);
static struct nd_pfxrouter *find_pfxlist_reachable_router(struct nd_prefix *);
static void nd6_rtmsg(int, struct rtentry *);

static int nd6_prefix_onlink_common(struct nd_prefix *, boolean_t,
    unsigned int);
static struct nd_prefix *nd6_prefix_equal_lookup(struct nd_prefix *, boolean_t);
static void nd6_prefix_sync(struct ifnet *);

static void in6_init_address_ltimes(struct nd_prefix *,
    struct in6_addrlifetime *, boolean_t);

static int rt6_deleteroute(struct radix_node *, void *);

static struct nd_defrouter *nddr_alloc(int);
static void nddr_free(struct nd_defrouter *);
static void nddr_trace(struct nd_defrouter *, int);

static struct nd_prefix *ndpr_alloc(int);
static void ndpr_free(struct nd_prefix *);
static void ndpr_trace(struct nd_prefix *, int);

extern int nd6_recalc_reachtm_interval;

static struct ifnet *nd6_defifp;
int nd6_defifindex;
static unsigned int nd6_defrouter_genid;

int ip6_use_tempaddr = 1; /* use temp addr by default for testing now */

int nd6_accept_6to4 = 1;

int ip6_desync_factor;
u_int32_t ip6_temp_preferred_lifetime = DEF_TEMP_PREFERRED_LIFETIME;
u_int32_t ip6_temp_valid_lifetime = DEF_TEMP_VALID_LIFETIME;
/*
 * shorter lifetimes for debugging purposes.
u_int32_t ip6_temp_preferred_lifetime = 800;
static u_int32_t ip6_temp_valid_lifetime = 1800;
*/
int ip6_temp_regen_advance = TEMPADDR_REGEN_ADVANCE;

extern lck_mtx_t *nd6_mutex;

/* Serialization variables for single thread access to nd_prefix */
static boolean_t nd_prefix_busy;
static void *nd_prefix_waitchan = &nd_prefix_busy;
static int nd_prefix_waiters = 0;

/* Serialization variables for single thread access to nd_defrouter */
static boolean_t nd_defrouter_busy;
static void *nd_defrouter_waitchan = &nd_defrouter_busy;
static int nd_defrouter_waiters = 0;

/* RTPREF_MEDIUM has to be 0! */
#define RTPREF_HIGH	1
#define RTPREF_MEDIUM	0
#define RTPREF_LOW	(-1)
#define RTPREF_RESERVED	(-2)
#define RTPREF_INVALID	(-3)	/* internal */

#define	NDPR_TRACE_HIST_SIZE	32		/* size of trace history */

/* For gdb */
__private_extern__ unsigned int ndpr_trace_hist_size = NDPR_TRACE_HIST_SIZE;

struct nd_prefix_dbg {
	struct nd_prefix	ndpr_pr;		/* nd_prefix */
	u_int16_t		ndpr_refhold_cnt;	/* # of ref */
	u_int16_t		ndpr_refrele_cnt;	/* # of rele */
	/*
	 * Circular lists of ndpr_addref and ndpr_remref callers.
	 */
	ctrace_t		ndpr_refhold[NDPR_TRACE_HIST_SIZE];
	ctrace_t		ndpr_refrele[NDPR_TRACE_HIST_SIZE];
};

static unsigned int ndpr_debug;			/* debug flags */
static unsigned int ndpr_size;			/* size of zone element */
static struct zone *ndpr_zone;			/* zone for nd_prefix */

#define	NDPR_ZONE_MAX	64			/* maximum elements in zone */
#define	NDPR_ZONE_NAME	"nd6_prefix"		/* zone name */

#define	NDDR_TRACE_HIST_SIZE	32              /* size of trace history */

/* For gdb */
__private_extern__ unsigned int nddr_trace_hist_size = NDDR_TRACE_HIST_SIZE;

struct nd_defrouter_dbg {
	struct nd_defrouter	nddr_dr;		/* nd_defrouter */
	uint16_t		nddr_refhold_cnt;	/* # of ref */
	uint16_t		nddr_refrele_cnt;	/* # of rele */
	/*
	 * Circular lists of ndpr_addref and ndpr_remref callers.
	 */
	ctrace_t		nddr_refhold[NDDR_TRACE_HIST_SIZE];
	ctrace_t		nddr_refrele[NDDR_TRACE_HIST_SIZE];
};

static unsigned int nddr_debug;			/* debug flags */
static unsigned int nddr_size;			/* size of zone element */
static struct zone *nddr_zone;			/* zone for nd_defrouter */

#define	NDDR_ZONE_MAX	64			/* maximum elements in zone */
#define	NDDR_ZONE_NAME	"nd6_defrouter"		/* zone name */

static unsigned int ndprtr_size;		/* size of zone element */
static struct zone *ndprtr_zone;		/* zone for nd_pfxrouter */

#define	NDPRTR_ZONE_MAX	64			/* maximum elements in zone */
#define	NDPRTR_ZONE_NAME "nd6_pfxrouter"	/* zone name */

void
nd6_rtr_init(void)
{
	PE_parse_boot_argn("ifa_debug", &ndpr_debug, sizeof (ndpr_debug));
	PE_parse_boot_argn("ifa_debug", &nddr_debug, sizeof (nddr_debug));

	ndpr_size = (ndpr_debug == 0) ? sizeof (struct nd_prefix) :
	    sizeof (struct nd_prefix_dbg);
	ndpr_zone = zinit(ndpr_size, NDPR_ZONE_MAX * ndpr_size, 0,
	    NDPR_ZONE_NAME);
	if (ndpr_zone == NULL) {
		panic("%s: failed allocating %s", __func__, NDPR_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(ndpr_zone, Z_EXPAND, TRUE);
	zone_change(ndpr_zone, Z_CALLERACCT, FALSE);

	nddr_size = (nddr_debug == 0) ? sizeof (struct nd_defrouter) :
	    sizeof (struct nd_defrouter_dbg);
	nddr_zone = zinit(nddr_size, NDDR_ZONE_MAX * nddr_size, 0,
	    NDDR_ZONE_NAME);
	if (nddr_zone == NULL) {
		panic("%s: failed allocating %s", __func__, NDDR_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(nddr_zone, Z_EXPAND, TRUE);
	zone_change(nddr_zone, Z_CALLERACCT, FALSE);

	ndprtr_size = sizeof (struct nd_pfxrouter);
	ndprtr_zone = zinit(ndprtr_size, NDPRTR_ZONE_MAX * ndprtr_size, 0,
	    NDPRTR_ZONE_NAME);
	if (ndprtr_zone == NULL) {
		panic("%s: failed allocating %s", __func__, NDPRTR_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(ndprtr_zone, Z_EXPAND, TRUE);
	zone_change(ndprtr_zone, Z_CALLERACCT, FALSE);
}

/*
 * Receive Router Solicitation Message - just for routers.
 * Router solicitation/advertisement is mostly managed by userland program
 * (rtadvd) so here we have no function like nd6_ra_output().
 *
 * Based on RFC 2461
 */
void
nd6_rs_input(
	struct	mbuf *m,
	int off,
	int icmp6len)
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_router_solicit *nd_rs;
	struct in6_addr saddr6 = ip6->ip6_src;
	char *lladdr = NULL;
	int lladdrlen = 0;
	union nd_opts ndopts;

	/* If I'm not a router, ignore it. */
	if (ip6_accept_rtadv != 0 || (ifp->if_eflags & IFEF_ACCEPT_RTADVD) || ip6_forwarding != 1)
		goto freeit;

	/* Sanity checks */
	if (ip6->ip6_hlim != 255) {
		nd6log((LOG_ERR,
		    "nd6_rs_input: invalid hlim (%d) from %s to %s on %s\n",
		    ip6->ip6_hlim, ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst), if_name(ifp)));
		goto bad;
	}

	/*
	 * Don't update the neighbor cache, if src = :: or a non-neighbor.
	 * The former case indicates that the src has no IP address assigned
	 * yet.  See nd6_ns_input() for the latter case.
 	 */
 	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src))
		goto freeit;
	else {
		struct sockaddr_in6 src_sa6;

		bzero(&src_sa6, sizeof(src_sa6));
		src_sa6.sin6_family = AF_INET6;
		src_sa6.sin6_len = sizeof(src_sa6);
		src_sa6.sin6_addr = ip6->ip6_src;
		if (!nd6_is_addr_neighbor(&src_sa6, ifp, 0)) {
			nd6log((LOG_INFO, "nd6_rs_input: "
				"RS packet from non-neighbor\n"));
			goto freeit;
		}
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len, return);
	nd_rs = (struct nd_router_solicit *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(nd_rs, struct nd_router_solicit *, m, off, icmp6len);
	if (nd_rs == NULL) {
		icmp6stat.icp6s_tooshort++;
		return;
	}
#endif

	icmp6len -= sizeof(*nd_rs);
	nd6_option_init(nd_rs + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log((LOG_INFO,
		    "nd6_rs_input: invalid ND option, ignored\n"));
		/* nd6_options have incremented stats */
		goto freeit;
	}

	if (ndopts.nd_opts_src_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_src_lladdr + 1);
		lladdrlen = ndopts.nd_opts_src_lladdr->nd_opt_len << 3;
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log((LOG_INFO,
		    "nd6_rs_input: lladdrlen mismatch for %s "
		    "(if %d, RS packet %d)\n",
			ip6_sprintf(&saddr6), ifp->if_addrlen, lladdrlen - 2));
		goto bad;
	}

	nd6_cache_lladdr(ifp, &saddr6, lladdr, lladdrlen, ND_ROUTER_SOLICIT, 0);

 freeit:
	m_freem(m);
	return;

 bad:
	icmp6stat.icp6s_badrs++;
	m_freem(m);
}

/*
 * Receive Router Advertisement Message.
 *
 * Based on RFC 2461
 * TODO: on-link bit on prefix information
 * TODO: ND_RA_FLAG_{OTHER,MANAGED} processing
 */
void
nd6_ra_input(
	struct	mbuf *m,
	int off, 
	int icmp6len)
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct nd_ifinfo *ndi = NULL;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_router_advert *nd_ra;
	struct in6_addr saddr6 = ip6->ip6_src;
	int mcast = 0;
	union nd_opts ndopts;
	struct nd_defrouter *dr = NULL;
	struct timeval timenow;

	getmicrotime(&timenow);

	if (ip6_accept_rtadv == 0 && ((ifp->if_eflags & IFEF_ACCEPT_RTADVD) == 0))
		goto freeit;

	if (ip6->ip6_hlim != 255) {
		nd6log((LOG_ERR,
		    "nd6_ra_input: invalid hlim (%d) from %s to %s on %s\n",
		    ip6->ip6_hlim, ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst), if_name(ifp)));
		goto bad;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&saddr6)) {
		nd6log((LOG_ERR,
		    "nd6_ra_input: src %s is not link-local\n",
		    ip6_sprintf(&saddr6)));
		goto bad;
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len, return);
	nd_ra = (struct nd_router_advert *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(nd_ra, struct nd_router_advert *, m, off, icmp6len);
	if (nd_ra == NULL) {
		icmp6stat.icp6s_tooshort++;
		return;
	}
#endif

	icmp6len -= sizeof(*nd_ra);
	nd6_option_init(nd_ra + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log((LOG_INFO,
		    "nd6_ra_input: invalid ND option, ignored\n"));
		/* nd6_options have incremented stats */
		goto freeit;
	}

    {
	struct nd_defrouter dr0;
	u_int32_t advreachable = nd_ra->nd_ra_reachable;

	/* remember if this is a multicasted advertisement */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
		mcast = 1;

	lck_rw_lock_shared(nd_if_rwlock);
	if (ifp->if_index >= nd_ifinfo_indexlim) {
		lck_rw_done(nd_if_rwlock);
		goto freeit;
	}
	ndi = &nd_ifinfo[ifp->if_index];
	bzero(&dr0, sizeof (dr0));
	dr0.rtaddr = saddr6;
	dr0.flags  = nd_ra->nd_ra_flags_reserved;
	dr0.rtlifetime = ntohs(nd_ra->nd_ra_router_lifetime);
	dr0.expire = timenow.tv_sec + dr0.rtlifetime;
	dr0.ifp = ifp;
	/* unspecified or not? (RFC 2461 6.3.4) */
	if (advreachable) {
		advreachable = ntohl(advreachable);
		if (advreachable <= MAX_REACHABLE_TIME &&
		    ndi->basereachable != advreachable) {
			ndi->basereachable = advreachable;
			ndi->reachable = ND_COMPUTE_RTIME(ndi->basereachable);
			ndi->recalctm = nd6_recalc_reachtm_interval; /* reset */
		}
	}
	if (nd_ra->nd_ra_retransmit)
		ndi->retrans = ntohl(nd_ra->nd_ra_retransmit);
	if (nd_ra->nd_ra_curhoplimit)
		ndi->chlim = nd_ra->nd_ra_curhoplimit;
	lck_rw_done(nd_if_rwlock);
	ndi = NULL;
	lck_mtx_lock(nd6_mutex);
	dr = defrtrlist_update(&dr0);
	lck_mtx_unlock(nd6_mutex);
    }

	/*
	 * prefix
	 */
	if (ndopts.nd_opts_pi) {
		struct nd_opt_hdr *pt;
		struct nd_opt_prefix_info *pi = NULL;
		struct nd_prefix pr;

		for (pt = (struct nd_opt_hdr *)ndopts.nd_opts_pi;
		     pt <= (struct nd_opt_hdr *)ndopts.nd_opts_pi_end;
		     pt = (struct nd_opt_hdr *)((caddr_t)pt +
						(pt->nd_opt_len << 3))) {
			if (pt->nd_opt_type != ND_OPT_PREFIX_INFORMATION)
				continue;
			pi = (struct nd_opt_prefix_info *)pt;

			if (pi->nd_opt_pi_len != 4) {
				nd6log((LOG_INFO,
				    "nd6_ra_input: invalid option "
				    "len %d for prefix information option, "
				    "ignored\n", pi->nd_opt_pi_len));
				continue;
			}

			if (128 < pi->nd_opt_pi_prefix_len) {
				nd6log((LOG_INFO,
				    "nd6_ra_input: invalid prefix "
				    "len %d for prefix information option, "
				    "ignored\n", pi->nd_opt_pi_prefix_len));
				continue;
			}

			if (IN6_IS_ADDR_MULTICAST(&pi->nd_opt_pi_prefix)
			 || IN6_IS_ADDR_LINKLOCAL(&pi->nd_opt_pi_prefix)) {
				nd6log((LOG_INFO,
				    "nd6_ra_input: invalid prefix "
				    "%s, ignored\n",
				    ip6_sprintf(&pi->nd_opt_pi_prefix)));
				continue;
			}

			bzero(&pr, sizeof(pr));
			lck_mtx_init(&pr.ndpr_lock, ifa_mtx_grp, ifa_mtx_attr);
			NDPR_LOCK(&pr);
			pr.ndpr_prefix.sin6_family = AF_INET6;
			pr.ndpr_prefix.sin6_len = sizeof(pr.ndpr_prefix);
			pr.ndpr_prefix.sin6_addr = pi->nd_opt_pi_prefix;
			pr.ndpr_ifp = m->m_pkthdr.rcvif;

			pr.ndpr_raf_onlink = (pi->nd_opt_pi_flags_reserved &
					      ND_OPT_PI_FLAG_ONLINK) ? 1 : 0;
			pr.ndpr_raf_auto = (pi->nd_opt_pi_flags_reserved &
					    ND_OPT_PI_FLAG_AUTO) ? 1 : 0;
			pr.ndpr_plen = pi->nd_opt_pi_prefix_len;
			pr.ndpr_vltime = ntohl(pi->nd_opt_pi_valid_time);
			pr.ndpr_pltime =
				ntohl(pi->nd_opt_pi_preferred_time);

			/*
			 * Exceptions to stateless autoconfiguration processing:
			 * + nd6_accept_6to4 == 0 && address has 6to4 prefix
			 * + ip6_only_allow_rfc4193_prefix != 0 && address not RFC 4193
			 */
			if (ip6_only_allow_rfc4193_prefix &&
			    !IN6_IS_ADDR_UNIQUE_LOCAL(&pi->nd_opt_pi_prefix)) {
				nd6log((LOG_INFO,
				    "nd6_ra_input: no SLAAC on prefix %s [not RFC 4193]\n",
				    ip6_sprintf(&pi->nd_opt_pi_prefix)));
				pr.ndpr_raf_auto = 0;
			}
			else if (!nd6_accept_6to4 &&
				     IN6_IS_ADDR_6TO4(&pi->nd_opt_pi_prefix)) {
				nd6log((LOG_INFO,
				    "nd6_ra_input: no SLAAC on prefix %s [6to4]\n",
				    ip6_sprintf(&pi->nd_opt_pi_prefix)));
				pr.ndpr_raf_auto = 0;
			}

			if (in6_init_prefix_ltimes(&pr)) {
				NDPR_UNLOCK(&pr);
				lck_mtx_destroy(&pr.ndpr_lock, ifa_mtx_grp);
				continue; /* prefix lifetime init failed */
			} else {
				NDPR_UNLOCK(&pr);
			}
			(void)prelist_update(&pr, dr, m, mcast);
			lck_mtx_destroy(&pr.ndpr_lock, ifa_mtx_grp);
		}
	}

	/*
	 * MTU
	 */
	if (ndopts.nd_opts_mtu && ndopts.nd_opts_mtu->nd_opt_mtu_len == 1) {
		u_int32_t mtu = ntohl(ndopts.nd_opts_mtu->nd_opt_mtu_mtu);

		/* lower bound */
		if (mtu < IPV6_MMTU) {
			nd6log((LOG_INFO, "nd6_ra_input: bogus mtu option "
			    "mtu=%d sent from %s, ignoring\n",
			    mtu, ip6_sprintf(&ip6->ip6_src)));
			goto skip;
		}

		lck_rw_lock_shared(nd_if_rwlock);
		if (ifp->if_index >= nd_ifinfo_indexlim) {
			lck_rw_done(nd_if_rwlock);
			goto freeit;
		}
		ndi = &nd_ifinfo[ifp->if_index];
		/* upper bound */
		if (ndi->maxmtu) {
			if (mtu <= ndi->maxmtu) {
				int change = (ndi->linkmtu != mtu);

				ndi->linkmtu = mtu;
				lck_rw_done(nd_if_rwlock);
				if (change) /* in6_maxmtu may change */
					in6_setmaxmtu();
			} else {
				nd6log((LOG_INFO, "nd6_ra_input: bogus mtu "
				    "mtu=%d sent from %s; "
				    "exceeds maxmtu %d, ignoring\n",
				    mtu, ip6_sprintf(&ip6->ip6_src),
				    ndi->maxmtu));
				lck_rw_done(nd_if_rwlock);
			}
		} else {
			lck_rw_done(nd_if_rwlock);
			nd6log((LOG_INFO, "nd6_ra_input: mtu option "
			    "mtu=%d sent from %s; maxmtu unknown, "
			    "ignoring\n",
			    mtu, ip6_sprintf(&ip6->ip6_src)));
		}
		ndi = NULL;
	}

 skip:
	
	/*
	 * Source link layer address
	 */
    {
	char *lladdr = NULL;
	int lladdrlen = 0;
	
	if (ndopts.nd_opts_src_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_src_lladdr + 1);
		lladdrlen = ndopts.nd_opts_src_lladdr->nd_opt_len << 3;
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log((LOG_INFO,
		    "nd6_ra_input: lladdrlen mismatch for %s "
		    "(if %d, RA packet %d)\n",
			ip6_sprintf(&saddr6), ifp->if_addrlen, lladdrlen - 2));
		goto bad;
	}

	nd6_cache_lladdr(ifp, &saddr6, lladdr, lladdrlen, ND_ROUTER_ADVERT, 0);

	/*
	 * Installing a link-layer address might change the state of the
	 * router's neighbor cache, which might also affect our on-link
	 * detection of adveritsed prefixes.
	 */
	lck_mtx_lock(nd6_mutex);
	pfxlist_onlink_check();
	lck_mtx_unlock(nd6_mutex);
    }

 freeit:
	m_freem(m);
	if (dr)
		NDDR_REMREF(dr);
	return;

 bad:
	icmp6stat.icp6s_badra++;
	goto freeit;
}

/*
 * default router list proccessing sub routines
 */

/* tell the change to user processes watching the routing socket. */
static void
nd6_rtmsg(cmd, rt)
	int cmd;
	struct rtentry *rt;
{
	struct rt_addrinfo info;
	struct ifnet *ifp = rt->rt_ifp;

	RT_LOCK_ASSERT_HELD(rt);

	bzero((caddr_t)&info, sizeof(info));
	/* Lock ifp for if_lladdr */
	ifnet_lock_shared(ifp);
	info.rti_info[RTAX_DST] = rt_key(rt);
	info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
	info.rti_info[RTAX_NETMASK] = rt_mask(rt);
	/*
	 * ifa_addr pointers for both should always be valid
	 * in this context; no need to hold locks.
	 */
	info.rti_info[RTAX_IFP] = ifp->if_lladdr->ifa_addr;
	info.rti_info[RTAX_IFA] = rt->rt_ifa->ifa_addr;

	rt_missmsg(cmd, &info, rt->rt_flags, 0);
	ifnet_lock_done(ifp);
}

void
defrouter_addreq(struct nd_defrouter *new, boolean_t scoped)
{
	struct sockaddr_in6 def, mask, gate;
	struct rtentry *newrt = NULL;
	unsigned int ifscope;
	int err;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	if (new->stateflags & NDDRF_INSTALLED)
		return;

	nd6log2((LOG_INFO, "%s: adding default router %s, scoped=%d, "
	    "static=%d\n", if_name(new->ifp), ip6_sprintf(&new->rtaddr),
	    scoped, (new->stateflags & NDDRF_STATIC) ? 1 : 0));

	Bzero(&def, sizeof(def));
	Bzero(&mask, sizeof(mask));
	Bzero(&gate, sizeof(gate));

	def.sin6_len = mask.sin6_len = gate.sin6_len
		= sizeof(struct sockaddr_in6);
	def.sin6_family = mask.sin6_family = gate.sin6_family = AF_INET6;
	gate.sin6_addr = new->rtaddr;

	ifscope = scoped ? new->ifp->if_index : IFSCOPE_NONE;

	err = rtrequest_scoped(RTM_ADD, (struct sockaddr *)&def,
	    (struct sockaddr *)&gate, (struct sockaddr *)&mask,
	    RTF_GATEWAY, &newrt, ifscope);

	if (newrt) {
		RT_LOCK(newrt);
		nd6_rtmsg(RTM_ADD, newrt); /* tell user process */
		RT_REMREF_LOCKED(newrt);
		RT_UNLOCK(newrt);
		new->stateflags |= NDDRF_INSTALLED;
		if (ifscope != IFSCOPE_NONE)
			new->stateflags |= NDDRF_IFSCOPE;
		new->genid = nd6_defrouter_genid;
	} else {
		nd6log((LOG_ERR, "%s: failed to add default router "
		    "%s on %s scoped %d (errno = %d)\n", __func__,
		    ip6_sprintf(&gate.sin6_addr), if_name(new->ifp),
		    (ifscope != IFSCOPE_NONE), err));
	}
	new->err = err;
}

struct nd_defrouter *
defrouter_lookup(
	struct in6_addr *addr,
	struct ifnet *ifp)
{
	struct nd_defrouter *dr;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	for (dr = TAILQ_FIRST(&nd_defrouter); dr;
	     dr = TAILQ_NEXT(dr, dr_entry)) {
		NDDR_LOCK(dr);
		if (dr->ifp == ifp && IN6_ARE_ADDR_EQUAL(addr, &dr->rtaddr)) {
			NDDR_ADDREF_LOCKED(dr);
			NDDR_UNLOCK(dr);
			return(dr);
		}
		NDDR_UNLOCK(dr);
	}

	return (NULL);		/* search failed */
}

/*
 * Remove the default route for a given router.
 * This is just a subroutine function for defrouter_select(), and should
 * not be called from anywhere else.
 */
void
defrouter_delreq(struct nd_defrouter *dr)
{
	struct sockaddr_in6 def, mask, gate;
	struct rtentry *oldrt = NULL;
	unsigned int ifscope;
	int err;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	/* ifp would be NULL for the "drany" case */
	if (dr->ifp != NULL && !(dr->stateflags & NDDRF_INSTALLED))
		return;

	NDDR_LOCK_ASSERT_HELD(dr);

	nd6log2((LOG_INFO, "%s: removing default router %s, scoped=%d, "
	    "static=%d\n", dr->ifp != NULL ? if_name(dr->ifp) : "ANY",
	    ip6_sprintf(&dr->rtaddr), (dr->stateflags & NDDRF_IFSCOPE) ? 1 : 0,
	    (dr->stateflags & NDDRF_STATIC) ? 1 : 0));

	Bzero(&def, sizeof(def));
	Bzero(&mask, sizeof(mask));
	Bzero(&gate, sizeof(gate));

	def.sin6_len = mask.sin6_len = gate.sin6_len
		= sizeof(struct sockaddr_in6);
	def.sin6_family = mask.sin6_family = gate.sin6_family = AF_INET6;
	gate.sin6_addr = dr->rtaddr;

	if (dr->ifp != NULL) {
		ifscope = (dr->stateflags & NDDRF_IFSCOPE) ?
		    dr->ifp->if_index : IFSCOPE_NONE;
	} else {
		ifscope = IFSCOPE_NONE;
	}
	err = rtrequest_scoped(RTM_DELETE,
	    (struct sockaddr *)&def, (struct sockaddr *)&gate,
	    (struct sockaddr *)&mask, RTF_GATEWAY, &oldrt, ifscope);

	if (oldrt) {
		RT_LOCK(oldrt);
		nd6_rtmsg(RTM_DELETE, oldrt);
		RT_UNLOCK(oldrt);
		rtfree(oldrt);
	} else if (err != ESRCH) {
		nd6log((LOG_ERR, "%s: failed to delete default router "
		    "%s on %s scoped %d (errno = %d)\n", __func__,
		    ip6_sprintf(&gate.sin6_addr), dr->ifp != NULL ?
		    if_name(dr->ifp) : "ANY", (ifscope != IFSCOPE_NONE), err));
	}
	/* ESRCH means it's no longer in the routing table; ignore it */
	if (oldrt != NULL || err == ESRCH) {
		dr->stateflags &= ~NDDRF_INSTALLED;
		if (ifscope != IFSCOPE_NONE)
			dr->stateflags &= ~NDDRF_IFSCOPE;
	}
	dr->err = 0;
}


/*
 * remove all default routes from default router list
 */
void
defrouter_reset(void)
{
	struct nd_defrouter *dr, drany;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	dr = TAILQ_FIRST(&nd_defrouter);
	while (dr) {
		NDDR_LOCK(dr);
		if (dr->stateflags & NDDRF_INSTALLED) {
			NDDR_ADDREF_LOCKED(dr);
			NDDR_UNLOCK(dr);
			lck_mtx_unlock(nd6_mutex);
			NDDR_LOCK(dr);
			defrouter_delreq(dr);
			NDDR_UNLOCK(dr);
			lck_mtx_lock(nd6_mutex);
			NDDR_REMREF(dr);
			dr = TAILQ_FIRST(&nd_defrouter);
		} else {
			NDDR_UNLOCK(dr);
			dr = TAILQ_NEXT(dr, dr_entry);
		}
	}

	/* Nuke primary (non-scoped) default router */
	if (ip6_doscopedroute) {
		bzero(&drany, sizeof (drany));
		lck_mtx_init(&drany.nddr_lock, ifa_mtx_grp, ifa_mtx_attr);
		lck_mtx_unlock(nd6_mutex);
		NDDR_LOCK(&drany);
		defrouter_delreq(&drany);
		NDDR_UNLOCK(&drany);
		lck_mtx_destroy(&drany.nddr_lock, ifa_mtx_grp);
		lck_mtx_lock(nd6_mutex);
	}

}

int
defrtrlist_ioctl(u_long cmd, caddr_t data)
{
	struct in6_defrouter_32 *r_32 = (struct in6_defrouter_32 *)data;
	struct in6_defrouter_64 *r_64 = (struct in6_defrouter_64 *)data;
	struct nd_defrouter dr0;
	unsigned int ifindex;
	struct ifnet *dr_ifp;
	int error = 0, add = 0;

	switch (cmd) {
	case SIOCDRADD_IN6_32:
	case SIOCDRADD_IN6_64:
		++add;
		/* FALLTHRU */
	case SIOCDRDEL_IN6_32:
	case SIOCDRDEL_IN6_64:
		bzero(&dr0, sizeof (dr0));
		if (cmd == SIOCDRADD_IN6_64 || cmd == SIOCDRDEL_IN6_64) {
			dr0.rtaddr = r_64->rtaddr.sin6_addr;
			dr0.flags = r_64->flags;
			ifindex = r_64->if_index;
		} else {
			dr0.rtaddr = r_32->rtaddr.sin6_addr;
			dr0.flags = r_32->flags;
			ifindex = r_32->if_index;
		}
		ifnet_head_lock_shared();
		/* Don't need to check is ifindex is < 0 since it's unsigned */
		if (if_index < ifindex ||
		    (dr_ifp = ifindex2ifnet[ifindex]) == NULL) {
			ifnet_head_done();
			error = EINVAL;
			break;
		}
		dr0.ifp = dr_ifp;
		ifnet_head_done();

		if (IN6_IS_SCOPE_EMBED(&dr0.rtaddr)) {
			uint16_t *scope = &dr0.rtaddr.s6_addr16[1];

			if (*scope == 0) {
				*scope = htons(dr_ifp->if_index);
			} else if (*scope != htons(dr_ifp->if_index)) {
				error = EINVAL;
				break;
			}
		}

		if (add)
			error = defrtrlist_add_static(&dr0);
		if (!add || error != 0) {
			int err = defrtrlist_del_static(&dr0);
			if (!add)
				error = err;
		}
		break;

	default:
		error = EOPNOTSUPP; /* check for safety */
		break;
	}

	return (error);
}

void
defrtrlist_del(struct nd_defrouter *dr)
{
	struct nd_defrouter *deldr = NULL;
	struct nd_prefix *pr;
	struct ifnet *ifp = dr->ifp;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	/*
	 * Flush all the routing table entries that use the router
	 * as a next hop.
	 */
	if (!ip6_forwarding &&
	    (ip6_accept_rtadv || (ifp->if_eflags & IFEF_ACCEPT_RTADVD))) {
		/* above is a good condition? */
		NDDR_ADDREF(dr);
		lck_mtx_unlock(nd6_mutex);
		rt6_flush(&dr->rtaddr, ifp);
		lck_mtx_lock(nd6_mutex);
		NDDR_REMREF(dr);
	}

	if (dr == TAILQ_FIRST(&nd_defrouter))
		deldr = dr;	/* The router is primary. */

	TAILQ_REMOVE(&nd_defrouter, dr, dr_entry);
	++nd6_defrouter_genid;

	nd6log2((LOG_INFO, "%s: freeing defrouter %s\n", if_name(dr->ifp),
	    ip6_sprintf(&dr->rtaddr)));

	/*
	 * Delete it from the routing table.
	 */
	NDDR_ADDREF(dr);
	lck_mtx_unlock(nd6_mutex);
	NDDR_LOCK(dr);
	defrouter_delreq(dr);
	NDDR_UNLOCK(dr);
	lck_mtx_lock(nd6_mutex);
	NDDR_REMREF(dr);

	/*
	 * Also delete all the pointers to the router in each prefix lists.
	 */
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		struct nd_pfxrouter *pfxrtr;

		NDPR_LOCK(pr);
		if ((pfxrtr = pfxrtr_lookup(pr, dr)) != NULL)
			pfxrtr_del(pfxrtr);
		NDPR_UNLOCK(pr);
	}

	pfxlist_onlink_check();

	/*
	 * If the router is the primary one, choose a new one.  If Scoped
	 * Routing is enabled, always try to pick another eligible router
	 * on this interface.
	 */
	if ((deldr || ip6_doscopedroute) && !ip6_forwarding &&
	    (ip6_accept_rtadv || (ifp->if_eflags & IFEF_ACCEPT_RTADVD)))
		defrouter_select(ifp);

	lck_rw_lock_shared(nd_if_rwlock);
	if (ifp->if_index < nd_ifinfo_indexlim) {
		struct nd_ifinfo *ndi = &nd_ifinfo[ifp->if_index];
		atomic_add_32(&ndi->ndefrouters, -1);
		if (ndi->ndefrouters < 0) {
			log(LOG_WARNING, "defrtrlist_del: negative "
			    "count on %s\n", if_name(ifp));
		}
	}
	lck_rw_done(nd_if_rwlock);

	NDDR_REMREF(dr);	/* remove list reference */
}

int
defrtrlist_add_static(struct nd_defrouter *new)
{
	struct nd_defrouter *dr;
	int err = 0;

	new->rtlifetime = -1;
	new->stateflags |= NDDRF_STATIC;

	/* we only want the preference level */
	new->flags &= ND_RA_FLAG_RTPREF_MASK;

	lck_mtx_lock(nd6_mutex);
	dr = defrouter_lookup(&new->rtaddr, new->ifp);
	if (dr != NULL && !(dr->stateflags & NDDRF_STATIC)) {
		err = EINVAL;
	} else {
		if (dr != NULL)
			NDDR_REMREF(dr);
		dr = defrtrlist_update(new);
		if (dr != NULL)
			err = dr->err;
		else
			err = ENOMEM;
	}
	if (dr != NULL)
		NDDR_REMREF(dr);
	lck_mtx_unlock(nd6_mutex);

	return (err);
}

int
defrtrlist_del_static(struct nd_defrouter *new)
{
	struct nd_defrouter *dr;

	lck_mtx_lock(nd6_mutex);
	dr = defrouter_lookup(&new->rtaddr, new->ifp);
	if (dr == NULL || !(dr->stateflags & NDDRF_STATIC)) {
		if (dr != NULL)
			NDDR_REMREF(dr);
		dr = NULL;
	} else {
		defrtrlist_del(dr);
		NDDR_REMREF(dr);
	}
	lck_mtx_unlock(nd6_mutex);

	return (dr != NULL ? 0 : EINVAL);
}

/*
 * for default router selection
 * regards router-preference field as a 2-bit signed integer
 */
static int
rtpref(struct nd_defrouter *dr)
{
	switch (dr->flags & ND_RA_FLAG_RTPREF_MASK) {
	case ND_RA_FLAG_RTPREF_HIGH:
		return (RTPREF_HIGH);
	case ND_RA_FLAG_RTPREF_MEDIUM:
	case ND_RA_FLAG_RTPREF_RSV:
		return (RTPREF_MEDIUM);
	case ND_RA_FLAG_RTPREF_LOW:
		return (RTPREF_LOW);
	default:
		/*
		 * This case should never happen.  If it did, it would mean a
		 * serious bug of kernel internal.  We thus always bark here.
		 * Or, can we even panic?
		 */
		log(LOG_ERR, "rtpref: impossible RA flag %x\n", dr->flags);
		return (RTPREF_INVALID);
	}
	/* NOTREACHED */
}

/*
 * Default Router Selection according to Section 6.3.6 of RFC 2461 and
 * draft-ietf-ipngwg-router-selection:
 *
 * 1) Routers that are reachable or probably reachable should be preferred.
 *    If we have more than one (probably) reachable router, prefer ones
 *    with the highest router preference.
 * 2) When no routers on the list are known to be reachable or
 *    probably reachable, routers SHOULD be selected in a round-robin
 *    fashion, regardless of router preference values.
 * 3) If the Default Router List is empty, assume that all
 *    destinations are on-link.
 *
 * When Scoped Routing is enabled, the selection logic is amended as follows:
 *
 * a) When a default interface is specified, the primary/non-scoped default
 *    router will be set to the reachable router on that link (if any) with
 *    the highest router preference.
 * b) When there are more than one routers on the same link, the one with
 *    the highest router preference will be installed, either as scoped or
 *    non-scoped route entry.  If they all share the same preference value,
 *    the one installed will be the static or the first encountered reachable
 *    router, i.e. static one wins over dynamic.
 * c) When no routers on the list are known to be reachable, or probably
 *    reachable, no round-robin selection will take place when the default
 *    interface is set.
 *
 * We assume nd_defrouter is sorted by router preference value.
 * Since the code below covers both with and without router preference cases,
 * we do not need to classify the cases by ifdef.
 */
static void
defrouter_select_common(struct ifnet *ifp, int ignore)
{
	struct nd_defrouter *dr, *selected_dr = NULL, *installed_dr = NULL;
	struct nd_defrouter *installed_dr0 = NULL;
	struct rtentry *rt = NULL;
	struct llinfo_nd6 *ln = NULL;
	int  update = 0;
	boolean_t found_installedrt = FALSE;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	/*
	 * This function should be called only when acting as an autoconfigured
	 * host.  Although the remaining part of this function is not effective
	 * if the node is not an autoconfigured host, we explicitly exclude
	 * such cases here for safety.
	 */
	if (ip6_forwarding || (!ignore && !ip6_accept_rtadv &&
	    !(ifp->if_eflags & IFEF_ACCEPT_RTADVD))) {
		nd6log((LOG_WARNING,
		    "defrouter_select: called unexpectedly (forwarding=%d, "
		    "accept_rtadv=%d)\n", ip6_forwarding, ip6_accept_rtadv));
		return;
	}

	/*
	 * Let's handle easy case (3) first:
	 * If default router list is empty, there's nothing to be done.
	 */
	if (!TAILQ_FIRST(&nd_defrouter))
		return;

	/*
	 * Due to the number of times we drop nd6_mutex, we need to
	 * serialize this function.
	 */
	while (nd_defrouter_busy) {
		nd_defrouter_waiters++;
		msleep(nd_defrouter_waitchan, nd6_mutex, (PZERO-1),
		    __func__, NULL);
		lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	}
	nd_defrouter_busy = TRUE;

	/*
	 * Search for a (probably) reachable router from the list.
	 * We just pick up the first reachable one (if any), assuming that
	 * the ordering rule of the list described in defrtrlist_update().
	 *
	 * For all intents and purposes of Scoped Routing:
	 *	selected_dr	= candidate for primary router
	 *	installed_dr	= currently installed primary router
	 */
	for (dr = TAILQ_FIRST(&nd_defrouter); dr;
	     dr = TAILQ_NEXT(dr, dr_entry)) {
		boolean_t reachable;

		/* Callee returns a locked route upon success */
		reachable = FALSE;
		NDDR_ADDREF(dr);	/* for this for loop */
		lck_mtx_unlock(nd6_mutex);
		if ((rt = nd6_lookup(&dr->rtaddr, 0, dr->ifp, 0)) != NULL) {
			RT_LOCK_ASSERT_HELD(rt);
			if ((ln = rt->rt_llinfo) != NULL &&
			    ND6_IS_LLINFO_PROBREACH(ln)) {
				reachable = TRUE;
				if (selected_dr == NULL &&
				    (!ip6_doscopedroute ||
				    dr->ifp == nd6_defifp)) {
					selected_dr = dr;
					NDDR_ADDREF(selected_dr);
				}
			}
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			rt = NULL;
		}
		lck_mtx_lock(nd6_mutex);

		/* Handle case (b) */
		if (ip6_doscopedroute && dr->ifp == nd6_defifp &&
		    (selected_dr == NULL || rtpref(dr) > rtpref(selected_dr) ||
		    (rtpref(dr) == rtpref(selected_dr) &&
		    (dr->stateflags & NDDRF_STATIC) &&
		    !(selected_dr->stateflags & NDDRF_STATIC)))) {
			if (selected_dr)
				NDDR_REMREF(selected_dr);
			selected_dr = dr;
			NDDR_ADDREF(selected_dr);
		}

		if (!(dr->stateflags & NDDRF_INSTALLED)) {
			/*
			 * If the router hasn't been installed and it is
			 * reachable, try to install it later on below.
			 * If it's static, try to install it anyway.
			 */
			if (reachable || (dr->stateflags & NDDRF_STATIC)) {
				dr->genid = -1;
				++update;
				nd6log2((LOG_INFO, "%s: possible router %s, "
				    "scoped=%d, static=%d\n", if_name(dr->ifp),
				    ip6_sprintf(&dr->rtaddr),
				    (dr->stateflags & NDDRF_IFSCOPE) ? 1 : 0,
				    (dr->stateflags & NDDRF_STATIC) ? 1 : 0));
			}
			NDDR_REMREF(dr);	/* for this for loop */
			continue;
		}

		/* Record the currently installed primary/non-scoped router */
		if (!ip6_doscopedroute || !(dr->stateflags & NDDRF_IFSCOPE)) {
			if (installed_dr == NULL) {
				installed_dr = dr;
				NDDR_ADDREF(installed_dr);
			} else {
				/* this should not happen; warn for diagnosis */
				log(LOG_ERR, "defrouter_select: more than one "
				    "%s default router is installed\n",
				    ip6_doscopedroute ? "non-scoped" : "");
			}
		}
		NDDR_REMREF(dr);	/* for this for loop */
	}

	/* If none was selected, use the currently installed one */
	if (ip6_doscopedroute && selected_dr == NULL && installed_dr != NULL) {
		selected_dr = installed_dr;
		NDDR_ADDREF(selected_dr);
	}

	/*
	 * Install the unreachable one(s) if necesssary.
	 */
	for (dr = TAILQ_FIRST(&nd_defrouter); dr;
	     dr = TAILQ_NEXT(dr, dr_entry)) {
		struct nd_defrouter *_dr;

		if (!ip6_doscopedroute)
			break;

		NDDR_LOCK(dr);

		/* If already (or will be) installed, skip */
		if ((dr->stateflags & NDDRF_INSTALLED) || dr->genid == -1) {
			NDDR_UNLOCK(dr);
			continue;
		}

		/* See if there is already a default router for the link */
		for (_dr = TAILQ_FIRST(&nd_defrouter); _dr;
		     _dr = TAILQ_NEXT(_dr, dr_entry)) {
			if (_dr != dr)
				NDDR_LOCK(_dr);
			if (_dr == dr || _dr->ifp != dr->ifp) {
				if (_dr != dr)
					NDDR_UNLOCK(_dr);
				continue;
			}

			if ((_dr->stateflags & NDDRF_INSTALLED) ||
			    _dr->genid == -1) {
				if (_dr != dr)
					NDDR_UNLOCK(_dr);
				break;
			}
			if (_dr != dr)
				NDDR_UNLOCK(_dr);
		}

		/* If none so far, schedule it to be installed below */
		if (_dr == NULL) {
			dr->genid = -1;
			++update;
			nd6log2((LOG_INFO, "%s: possible router %s, "
			    "static=%d (unreachable)\n", if_name(dr->ifp),
			    ip6_sprintf(&dr->rtaddr),
			    (dr->stateflags & NDDRF_STATIC) ? 1 : 0));
		}
		NDDR_UNLOCK(dr);
	}

	dr = selected_dr;
	if (dr != NULL) {
		nd6log2((LOG_INFO, "%s: considering primary default router %s, "
		    "static=%d [round 1]\n", if_name(dr->ifp),
		    ip6_sprintf(&dr->rtaddr),
		    (dr->stateflags & NDDRF_STATIC) ? 1 : 0));
	}

	/*
	 * If none of the default routers was found to be reachable,
	 * round-robin the list regardless of preference, except when
	 * Scoped Routing is enabled per case (c).
	 *
	 * Otherwise, if we have an installed router, check if the selected
	 * (reachable) router should really be preferred to the installed one.
	 * We only prefer the new router when the old one is not reachable
	 * or when the new one has a really higher preference value.
	 */
	if (!ip6_doscopedroute && selected_dr == NULL) {
		if (installed_dr == NULL ||
		    !TAILQ_NEXT(installed_dr, dr_entry)) {
			selected_dr = TAILQ_FIRST(&nd_defrouter);
			if (selected_dr)
				NDDR_ADDREF(selected_dr);
		} else {
			selected_dr = TAILQ_NEXT(installed_dr, dr_entry);
			if (selected_dr)
				NDDR_ADDREF(selected_dr);
		}
	} else if (selected_dr != NULL && installed_dr != NULL) {
		lck_mtx_unlock(nd6_mutex);
		rt = nd6_lookup(&installed_dr->rtaddr, 0, installed_dr->ifp, 0);
		if (rt) {
			RT_LOCK_ASSERT_HELD(rt);
			if ((ln = (struct llinfo_nd6 *)rt->rt_llinfo) &&
			    ND6_IS_LLINFO_PROBREACH(ln) &&
			    (!ip6_doscopedroute ||
				installed_dr->ifp == nd6_defifp) &&
			    rtpref(selected_dr) <= rtpref(installed_dr)) {
				NDDR_REMREF(selected_dr);
				selected_dr = installed_dr;
				NDDR_ADDREF(selected_dr);
			}
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			rt = NULL;
			found_installedrt = TRUE;
		}
		lck_mtx_lock(nd6_mutex);
	}

	if (ip6_doscopedroute) {
		/*
		 * If the installed primary router is not on the current
		 * IPv6 default interface, demote it to a scoped entry.
		 */
		if (installed_dr != NULL && installed_dr->ifp != nd6_defifp &&
		    !(installed_dr->stateflags & NDDRF_IFSCOPE)) {
			if (selected_dr != NULL &&
			    selected_dr->ifp != nd6_defifp) {
				NDDR_REMREF(selected_dr);
				selected_dr = NULL;
			}
			++update;
		}

		/*
		 * If the selected router is currently scoped, make sure
		 * we update (it needs to be promoted to primary.)
		 */
		if (selected_dr != NULL &&
		    (selected_dr->stateflags & NDDRF_IFSCOPE))
			++update;

		/*
		 * If the installed router is no longe reachable, remove
		 * it and install the selected router instead.
		 */
		if (installed_dr != NULL && selected_dr != NULL &&
		    installed_dr != selected_dr && found_installedrt == FALSE) {
			installed_dr0 = installed_dr;	/* skip it below */
			/* NB: we previousled referenced installed_dr */
			installed_dr = NULL;
			selected_dr->genid = -1;
			++update;
		}
	}

	/*
	 * If Scoped Routing is enabled and there's nothing to update,
	 * just return.  Otherwise, if Scoped Routing is disabled and if
	 * the selected router is different than the installed one,
	 * remove the installed router and install the selected one.
	 */
	dr = selected_dr;
	VERIFY(dr != NULL || ip6_doscopedroute);
	if (!ip6_doscopedroute || !update) {
		if (dr == NULL)
			goto out;

		if (dr != installed_dr) {
			nd6log2((LOG_INFO, "%s: no update, selected router %s, "
			    "installed router %s\n", if_name(dr->ifp),
			    ip6_sprintf(&dr->rtaddr), installed_dr != NULL ?
			    ip6_sprintf(&installed_dr->rtaddr) : "NONE"));
		} else {
			nd6log2((LOG_INFO, "%s: no update, router is %s\n",
			    if_name(dr->ifp), ip6_sprintf(&dr->rtaddr)));
		}
		if (!ip6_doscopedroute && installed_dr != dr) {
			/* 
			 * No need to ADDREF dr because at this point
			 * dr points to selected_dr, which already holds
			 * a reference.
			 */
			lck_mtx_unlock(nd6_mutex);
			if (installed_dr) {
				NDDR_LOCK(installed_dr);
				defrouter_delreq(installed_dr);
				NDDR_UNLOCK(installed_dr);
			}
			NDDR_LOCK(dr);
			defrouter_addreq(dr, FALSE);
			NDDR_UNLOCK(dr);
			lck_mtx_lock(nd6_mutex);
		}
		goto out;
	}

	/*
	 * Scoped Routing is enabled and we need to update.  The selected
	 * router needs to be installed as primary/non-scoped entry.  If
	 * there is any existing entry that is non-scoped, remove it from
	 * the routing table and reinstall it as scoped entry.
	 */
	if (dr != NULL) {
		nd6log2((LOG_INFO, "%s: considering primary default router %s, "
		    "static=%d [round 2]\n", if_name(dr->ifp),
		    ip6_sprintf(&dr->rtaddr),
		    (dr->stateflags & NDDRF_STATIC) ? 1 : 0));
	}

	/*
	 * On the following while loops we use two flags:
	 *   dr->genid
	 *   NDDRF_PROCESSED
	 *
	 * genid is used to skip entries that are not to be added/removed on the
	 * second while loop.
	 * NDDRF_PROCESSED is used to skip entries that were already processed.
	 * This is necessary because we drop the nd6_mutex and start the while
	 * loop again.
	 */
	TAILQ_FOREACH(dr, &nd_defrouter, dr_entry) {
		NDDR_LOCK(dr);
		VERIFY((dr->stateflags & NDDRF_PROCESSED) == 0);
		NDDR_UNLOCK(dr);
	}
	/* Remove conflicting entries */
	dr = TAILQ_FIRST(&nd_defrouter);
	while (dr) {
		NDDR_LOCK(dr);
		if (!(dr->stateflags & NDDRF_INSTALLED) ||
		    dr->stateflags & NDDRF_PROCESSED) {
			NDDR_UNLOCK(dr);
			dr = TAILQ_NEXT(dr, dr_entry);
			continue;
		}
		dr->stateflags |= NDDRF_PROCESSED;

		/* A NULL selected_dr will remove primary default route */
		if ((dr == selected_dr && (dr->stateflags & NDDRF_IFSCOPE)) ||
		    (dr != selected_dr && !(dr->stateflags & NDDRF_IFSCOPE))) {
			NDDR_ADDREF_LOCKED(dr);
			NDDR_UNLOCK(dr);
			lck_mtx_unlock(nd6_mutex);
			NDDR_LOCK(dr);
			defrouter_delreq(dr);
			NDDR_UNLOCK(dr);
			lck_mtx_lock(nd6_mutex);
			NDDR_LOCK(dr);
			if (dr && dr != installed_dr0)
				dr->genid = -1;
			NDDR_UNLOCK(dr);
			NDDR_REMREF(dr);
			/*
			 * Since we lost nd6_mutex, we have to start over.
			 */
			dr = TAILQ_FIRST(&nd_defrouter);
			continue;
		}
		NDDR_UNLOCK(dr);
		dr = TAILQ_NEXT(dr, dr_entry);
	}

	/* -1 is a special number, make sure we don't use it for genid */
	if (++nd6_defrouter_genid == -1)
		nd6_defrouter_genid = 1;

	TAILQ_FOREACH(dr, &nd_defrouter, dr_entry) {
		NDDR_LOCK(dr);
		dr->stateflags &= ~NDDRF_PROCESSED;
		NDDR_UNLOCK(dr);
	}
	/* Add the entries back */
	dr = TAILQ_FIRST(&nd_defrouter);
	while (dr) {
		struct nd_defrouter *_dr;

		NDDR_LOCK(dr);
		if (dr->stateflags & NDDRF_PROCESSED ||
		    dr->genid != -1) {
			NDDR_UNLOCK(dr);
			dr = TAILQ_NEXT(dr, dr_entry);
			continue;
		}
		dr->stateflags |= NDDRF_PROCESSED;

		/* Handle case (b) */
		for (_dr = TAILQ_FIRST(&nd_defrouter); _dr;
		     _dr = TAILQ_NEXT(_dr, dr_entry)) {
			if (_dr == dr)
				continue;
			/*
			 * This is safe because we previously checked if
			 * _dr == dr.
			 */
			NDDR_LOCK(_dr);
			if (_dr->ifp == dr->ifp && rtpref(_dr) >= rtpref(dr) &&
			    (_dr->stateflags & NDDRF_INSTALLED)) {
				NDDR_ADDREF_LOCKED(_dr);
				NDDR_UNLOCK(_dr);
				break;
			}
			NDDR_UNLOCK(_dr);
		}

		/* If same preference and i/f, static entry takes precedence */
		if (_dr != NULL && rtpref(_dr) == rtpref(dr) &&
		    !(_dr->stateflags & NDDRF_STATIC) &&
		    (dr->stateflags & NDDRF_STATIC)) {
			lck_mtx_unlock(nd6_mutex);
			NDDR_LOCK(_dr);
			defrouter_delreq(_dr);
			NDDR_UNLOCK(_dr);
			lck_mtx_lock(nd6_mutex);
			NDDR_REMREF(_dr);
			_dr = NULL;
		}

		if (_dr == NULL && !(dr->stateflags & NDDRF_INSTALLED)) {
			NDDR_ADDREF_LOCKED(dr);
			NDDR_UNLOCK(dr);
			lck_mtx_unlock(nd6_mutex);
			NDDR_LOCK(dr);
			defrouter_addreq(dr, (selected_dr == NULL ||
			    dr->ifp != selected_dr->ifp));
			dr->genid = nd6_defrouter_genid;
			NDDR_UNLOCK(dr);
			lck_mtx_lock(nd6_mutex);
			NDDR_REMREF(dr);
			/*
			 * Since we lost nd6_mutex, we have to start over.
			 */
			dr = TAILQ_FIRST(&nd_defrouter);
			continue;
		}
		NDDR_UNLOCK(dr);
		dr = TAILQ_NEXT(dr, dr_entry);
	}
out:
	TAILQ_FOREACH(dr, &nd_defrouter, dr_entry) {
		NDDR_LOCK(dr);
		dr->stateflags &= ~NDDRF_PROCESSED;
		NDDR_UNLOCK(dr);
	}
	if (selected_dr)
		NDDR_REMREF(selected_dr);
	if (installed_dr)
		NDDR_REMREF(installed_dr);
	if (installed_dr0)
		NDDR_REMREF(installed_dr0);
	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	VERIFY(nd_defrouter_busy);
	nd_defrouter_busy = FALSE;
	if (nd_defrouter_waiters > 0) {
		nd_defrouter_waiters = 0;
		wakeup(nd_defrouter_waitchan);
	}
}

void
defrouter_select(struct ifnet *ifp)
{
	return (defrouter_select_common(ifp, 0));
}

static struct nd_defrouter *
defrtrlist_update_common(struct nd_defrouter *new, boolean_t scoped)
{
	struct nd_defrouter *dr, *n;
	struct ifnet *ifp = new->ifp;
	struct nd_ifinfo *ndi;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	if ((dr = defrouter_lookup(&new->rtaddr, ifp)) != NULL) {
		/* entry exists */
		if (new->rtlifetime == 0) {
			defrtrlist_del(dr);
			NDDR_REMREF(dr);
			dr = NULL;
		} else {
			int oldpref = rtpref(dr);

			/* override */
			dr->flags = new->flags; /* xxx flag check */
			dr->rtlifetime = new->rtlifetime;
			dr->expire = new->expire;

			/*
			 * If the preference does not change, there's no need
			 * to sort the entries.  If Scoped Routing is enabled,
			 * put the primary/non-scoped router at the top of the
			 * list of routers in the same preference band, unless
			 * it's already at that position.
			 */
			if (ip6_doscopedroute) {
				struct nd_defrouter *p = NULL;

				/* same preference and scoped; just return */
				if (rtpref(new) == oldpref && scoped)
					return (dr);

				n = TAILQ_FIRST(&nd_defrouter);
				while (n != NULL) {
					/* preference changed; sort it */
					if (rtpref(new) != oldpref)
						break;

					/* not at the top of band; sort it */
					if (n != dr && rtpref(n) == oldpref &&
					    (!p || rtpref(p) > rtpref(n)))
						break;

					p = n;
					n = TAILQ_NEXT(n, dr_entry);
				}

				/* nothing has changed, just return */
				if (n == NULL && (scoped ||
				    !(dr->stateflags & NDDRF_IFSCOPE)))
					return (dr);
			} else if (rtpref(new) == oldpref) {
				return (dr);
			}

			/*
			 * preferred router may be changed, so relocate
			 * this router.
			 * XXX: calling TAILQ_REMOVE directly is a bad manner.
			 * However, since defrtrlist_del() has many side
			 * effects, we intentionally do so here.
			 * defrouter_select() below will handle routing
			 * changes later.
			 */
			TAILQ_REMOVE(&nd_defrouter, dr, dr_entry);
			new->stateflags = dr->stateflags;
			new->stateflags &= ~NDDRF_PROCESSED;

			lck_rw_lock_shared(nd_if_rwlock);
			VERIFY(ifp->if_index < nd_ifinfo_indexlim);
			ndi = &nd_ifinfo[ifp->if_index];
			lck_rw_done(nd_if_rwlock);
			n = dr;
			goto insert;
		}
		return (dr);
	}

	VERIFY(dr == NULL);

	/* entry does not exist */
	if (new->rtlifetime == 0) {
		return(NULL);
	}

	n = nddr_alloc(M_WAITOK);
	if (n == NULL) {
		return(NULL);
	}

	lck_rw_lock_shared(nd_if_rwlock);
	ndi = &nd_ifinfo[ifp->if_index];
	if (ifp->if_index >= nd_ifinfo_indexlim)
		goto freeit;
	if (ip6_maxifdefrouters >= 0 &&
	    ndi->ndefrouters >= ip6_maxifdefrouters) {
freeit:
		lck_rw_done(nd_if_rwlock);
		nddr_free(n);
		return (NULL);
	}

	NDDR_ADDREF(n);	/* for the nd_defrouter list */
	NDDR_ADDREF(n);	/* for the caller */

	++nd6_defrouter_genid;
	atomic_add_32(&ndi->ndefrouters, 1);
	lck_rw_done(nd_if_rwlock);

	nd6log2((LOG_INFO, "%s: allocating defrouter %s\n", if_name(ifp),
	    ip6_sprintf(&new->rtaddr)));

	NDDR_LOCK(n);
	memcpy(&n->rtaddr, &new->rtaddr, sizeof(n->rtaddr));
	n->flags = new->flags;
	n->stateflags = new->stateflags;
	n->stateflags &= ~NDDRF_PROCESSED;
	n->rtlifetime = new->rtlifetime;
	n->expire = new->expire;
	n->ifp = new->ifp;
	n->genid = new->genid;
	n->err = new->err;
	NDDR_UNLOCK(n);
insert:

	/*
	 * Insert the new router in the Default Router List;
	 * The Default Router List should be in the descending order
	 * of router-preferece.  When Scoped Routing is disabled, routers
	 * with the same preference are sorted in the arriving time order;
	 * otherwise, the first entry in the list of routers having the same
	 * preference is the primary default router, when the interface used
	 * by the entry is the default interface.
	 */

	/* insert at the end of the group */
	for (dr = TAILQ_FIRST(&nd_defrouter); dr;
	     dr = TAILQ_NEXT(dr, dr_entry)) {
		if (rtpref(n) > rtpref(dr) ||
		    (ip6_doscopedroute && !scoped && rtpref(n) == rtpref(dr)))
			break;
	}
	if (dr)
		TAILQ_INSERT_BEFORE(dr, n, dr_entry);
	else
		TAILQ_INSERT_TAIL(&nd_defrouter, n, dr_entry);

	/* Ignore auto-configuration checks for static route entries */
	defrouter_select_common(ifp, (n->stateflags & NDDRF_STATIC));

	return (n);
}

static struct nd_defrouter *
defrtrlist_update(struct nd_defrouter *new)
{
	struct nd_defrouter *dr;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	dr = defrtrlist_update_common(new,
	    (nd6_defifp != NULL && new->ifp != nd6_defifp));

	return (dr);
}

static void
defrtrlist_sync(struct ifnet *ifp)
{
	struct nd_defrouter *dr, new;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	if (!ip6_doscopedroute) {
		defrouter_select(ifp);
		return;
	}

	for (dr = TAILQ_FIRST(&nd_defrouter); dr;
	     dr = TAILQ_NEXT(dr, dr_entry)) {
		NDDR_LOCK(dr);
		if (dr->ifp == ifp && (dr->stateflags & NDDRF_INSTALLED))
			break;
		NDDR_UNLOCK(dr);
	}

	if (dr == NULL) {
		/*
		 * Set ignore flag; the chosen default interface might
		 * not be configured to accept RAs.
		 */
		defrouter_select_common(ifp, 1);
	} else {
		memcpy(&new.rtaddr, &dr->rtaddr, sizeof(new.rtaddr));
		new.flags = dr->flags;
		new.stateflags = dr->stateflags;
		new.stateflags &= ~NDDRF_PROCESSED;
		new.rtlifetime = dr->rtlifetime;
		new.expire = dr->expire;
		new.ifp = dr->ifp;
		new.genid = dr->genid;
		new.err = dr->err;
		NDDR_UNLOCK(dr);
		dr = defrtrlist_update_common(&new, FALSE);
		if (dr)
			NDDR_REMREF(dr);
	}
}

static struct nd_pfxrouter *
pfxrtr_lookup(struct nd_prefix *pr, struct nd_defrouter *dr)
{
	struct nd_pfxrouter *search;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	NDPR_LOCK_ASSERT_HELD(pr);

	for (search = pr->ndpr_advrtrs.lh_first; search;
	    search = search->pfr_next) {
		if (search->router == dr)
			break;
	}

	return(search);
}

static void
pfxrtr_add(struct nd_prefix *pr, struct nd_defrouter *dr)
{
	struct nd_pfxrouter *new;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	NDPR_LOCK_ASSERT_NOTHELD(pr);

	new = zalloc(ndprtr_zone);
	if (new == NULL)
		return;
	bzero(new, sizeof(*new));
	new->router = dr;

	NDPR_LOCK(pr);
	LIST_INSERT_HEAD(&pr->ndpr_advrtrs, new, pfr_entry);
	NDPR_UNLOCK(pr);
	
	pfxlist_onlink_check();
}

static void
pfxrtr_del(
	struct nd_pfxrouter *pfr)
{
	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	LIST_REMOVE(pfr, pfr_entry);
	zfree(ndprtr_zone, pfr);
}

struct nd_prefix *
nd6_prefix_lookup(struct nd_prefix *pr)
{
	struct nd_prefix *search;

	lck_mtx_lock(nd6_mutex);
	for (search = nd_prefix.lh_first; search; search = search->ndpr_next) {
		NDPR_LOCK(search);
		if (pr->ndpr_ifp == search->ndpr_ifp &&
		    pr->ndpr_plen == search->ndpr_plen &&
		    in6_are_prefix_equal(&pr->ndpr_prefix.sin6_addr,
		    &search->ndpr_prefix.sin6_addr, pr->ndpr_plen)) {
			NDPR_ADDREF_LOCKED(search);
			NDPR_UNLOCK(search);
			break;
		}
		NDPR_UNLOCK(search);
	}
	lck_mtx_unlock(nd6_mutex);

	return(search);
}

static void
purge_detached(struct ifnet *ifp)
{
	struct nd_prefix *pr, *pr_next;
	struct in6_ifaddr *ia;
	struct ifaddr *ifa, *ifa_next;

	lck_mtx_lock(nd6_mutex);

	pr = nd_prefix.lh_first;
repeat:
	while (pr) {
		pr_next = pr->ndpr_next;
		NDPR_LOCK(pr);
		if (pr->ndpr_ifp != ifp ||
		    IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_prefix.sin6_addr) ||
		    ((pr->ndpr_stateflags & NDPRF_DETACHED) == 0 &&
		    !LIST_EMPTY(&pr->ndpr_advrtrs))) {
			NDPR_UNLOCK(pr);
			pr = pr_next;
			continue;
		}
		NDPR_UNLOCK(pr);
		ifnet_lock_shared(ifp);
		for (ifa = ifp->if_addrlist.tqh_first; ifa; ifa = ifa_next) {
			ifa_next = ifa->ifa_list.tqe_next;
			IFA_LOCK(ifa);
			if (ifa->ifa_addr->sa_family != AF_INET6) {
				IFA_UNLOCK(ifa);
				continue;
			}
			ia = (struct in6_ifaddr *)ifa;
			if ((ia->ia6_flags & IN6_IFF_AUTOCONF) ==
			    IN6_IFF_AUTOCONF && ia->ia6_ndpr == pr) {
				IFA_ADDREF_LOCKED(ifa);	/* for us */
				IFA_UNLOCK(ifa);
				/*
				 * Purging the address requires writer access
				 * to the address list, so drop the ifnet lock
				 * now and repeat from beginning.
				 */
				ifnet_lock_done(ifp);
				lck_mtx_unlock(nd6_mutex);
				in6_purgeaddr(ifa);
				lck_mtx_lock(nd6_mutex);
				IFA_REMREF(ifa); /* drop ours */
				pr = nd_prefix.lh_first;
				goto repeat;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
		NDPR_LOCK(pr);
		if (pr->ndpr_addrcnt == 0) {
			NDPR_ADDREF_LOCKED(pr);
			prelist_remove(pr);
			NDPR_UNLOCK(pr);
			NDPR_REMREF(pr);
		} else {
			NDPR_UNLOCK(pr);
		}
		pr = pr_next;
	}

	lck_mtx_unlock(nd6_mutex);
}

int
nd6_prelist_add(struct nd_prefix *pr, struct nd_defrouter *dr,
    struct nd_prefix **newp, boolean_t force_scoped)
{
	struct nd_prefix *new = NULL;
	struct ifnet *ifp = pr->ndpr_ifp;
	struct nd_ifinfo *ndi = NULL;
	int i, error;
	struct timeval timenow;

	getmicrotime(&timenow);

	if (ip6_maxifprefixes >= 0) {
		lck_rw_lock_shared(nd_if_rwlock);
		if (ifp->if_index >= nd_ifinfo_indexlim) {
			lck_rw_done(nd_if_rwlock);
			return (EINVAL);
		}
		ndi = &nd_ifinfo[ifp->if_index];
		if (ndi->nprefixes >= ip6_maxifprefixes / 2) {
			lck_rw_done(nd_if_rwlock);
			purge_detached(ifp);
			lck_rw_lock_shared(nd_if_rwlock);
			/*
			 * Refresh pointer since nd_ifinfo[] may have grown;
			 * repeating the bounds check against nd_ifinfo_indexlim
			 * isn't necessary since the array never shrinks.
			 */
			ndi = &nd_ifinfo[ifp->if_index];
		}
		if (ndi->nprefixes >= ip6_maxifprefixes) {
			lck_rw_done(nd_if_rwlock);
			return(ENOMEM);
		}
		lck_rw_done(nd_if_rwlock);
	}

	new = ndpr_alloc(M_WAITOK);
	if (new == NULL)
		return ENOMEM;

	NDPR_LOCK(new);
	NDPR_LOCK(pr);
	new->ndpr_ifp = pr->ndpr_ifp;
	new->ndpr_prefix = pr->ndpr_prefix;
	new->ndpr_plen = pr->ndpr_plen;
	new->ndpr_vltime = pr->ndpr_vltime;
	new->ndpr_pltime = pr->ndpr_pltime;
	new->ndpr_flags = pr->ndpr_flags;
	if (pr->ndpr_stateflags & NDPRF_STATIC)
		new->ndpr_stateflags |= NDPRF_STATIC;
	NDPR_UNLOCK(pr);
	if ((error = in6_init_prefix_ltimes(new)) != 0) {
		NDPR_UNLOCK(new);
		ndpr_free(new);
		return(error);
	}
	new->ndpr_lastupdate = timenow.tv_sec;
	if (newp != NULL) {
		*newp = new;
		NDPR_ADDREF_LOCKED(new);	/* for caller */
	}
	/* initialization */
	LIST_INIT(&new->ndpr_advrtrs);
	in6_prefixlen2mask(&new->ndpr_mask, new->ndpr_plen);
	/* make prefix in the canonical form */
	for (i = 0; i < 4; i++)
		new->ndpr_prefix.sin6_addr.s6_addr32[i] &=
			new->ndpr_mask.s6_addr32[i];

	NDPR_UNLOCK(new);

	lck_mtx_lock(nd6_mutex);
	/* link ndpr_entry to nd_prefix list */
	LIST_INSERT_HEAD(&nd_prefix, new, ndpr_entry);
	new->ndpr_debug |= IFD_ATTACHED;
	NDPR_ADDREF(new);	/* for nd_prefix list */

	/* ND_OPT_PI_FLAG_ONLINK processing */
	if (new->ndpr_raf_onlink) {
		int e;

		if ((e = nd6_prefix_onlink_common(new, force_scoped,
		    new->ndpr_ifp->if_index)) != 0) {
			nd6log((LOG_ERR, "nd6_prelist_add: failed to make "
			    "the prefix %s/%d on-link %s on %s (errno=%d)\n",
			    ip6_sprintf(&new->ndpr_prefix.sin6_addr),
			    new->ndpr_plen, force_scoped ? "scoped" :
			    "non-scoped", if_name(ifp), e));
			/* proceed anyway. XXX: is it correct? */
		}
	}

	if (dr) {
		pfxrtr_add(new, dr);
	}

	lck_rw_lock_shared(nd_if_rwlock);
	/*
	 * Refresh pointer since nd_ifinfo[] may have grown;
	 * repeating the bounds check against nd_ifinfo_indexlim
	 * isn't necessary since the array never shrinks.
	 */
	ndi = &nd_ifinfo[ifp->if_index];
	atomic_add_32(&ndi->nprefixes, 1);
	lck_rw_done(nd_if_rwlock);

	lck_mtx_unlock(nd6_mutex);

	return 0;
}

/*
 * Caller must have held an extra reference on nd_prefix.
 */
void
prelist_remove(struct nd_prefix *pr)
{
	struct nd_pfxrouter *pfr, *next;
	struct ifnet *ifp = pr->ndpr_ifp;
	int e;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	NDPR_LOCK_ASSERT_HELD(pr);

	/* make sure to invalidate the prefix until it is really freed. */
	pr->ndpr_vltime = 0;
	pr->ndpr_pltime = 0;

	/*
	 * Though these flags are now meaningless, we'd rather keep the value
	 * of pr->ndpr_raf_onlink and pr->ndpr_raf_auto not to confuse users
	 * when executing "ndp -p".
	 */

	if ((pr->ndpr_stateflags & NDPRF_ONLINK)) {
		NDPR_ADDREF_LOCKED(pr);
		NDPR_UNLOCK(pr);
		lck_mtx_unlock(nd6_mutex);
		if ((e = nd6_prefix_offlink(pr)) != 0) {
			nd6log((LOG_ERR, "prelist_remove: failed to make "
			    "%s/%d offlink on %s, errno=%d\n",
			    ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
			    pr->ndpr_plen, if_name(ifp), e));
			/* what should we do? */
		}
		lck_mtx_lock(nd6_mutex);
		NDPR_LOCK(pr);
		if (NDPR_REMREF_LOCKED(pr) == NULL)
			return;
	}

	if (pr->ndpr_addrcnt > 0)
		return;	/* notice here? */

	/* unlink ndpr_entry from nd_prefix list */
	LIST_REMOVE(pr, ndpr_entry);
	pr->ndpr_debug &= ~IFD_ATTACHED;

	/* free list of routers that adversed the prefix */
	for (pfr = pr->ndpr_advrtrs.lh_first; pfr; pfr = next) {
		next = pfr->pfr_next;
		pfxrtr_del(pfr);
	}

	lck_rw_lock_shared(nd_if_rwlock);
	if (ifp->if_index < nd_ifinfo_indexlim) {
		struct nd_ifinfo *ndi = &nd_ifinfo[ifp->if_index];
		atomic_add_32(&ndi->nprefixes, -1);
		if (ndi->nprefixes < 0) {
			log(LOG_WARNING, "prelist_remove: negative "
			    "count on %s\n", if_name(ifp));
		}
	}
	lck_rw_done(nd_if_rwlock);

	/* This must not be the last reference to the nd_prefix */
	if (NDPR_REMREF_LOCKED(pr) == NULL) {
		panic("%s: unexpected (missing) refcnt ndpr=%p", __func__, pr);
		/* NOTREACHED */
	}

	pfxlist_onlink_check();
}

int
prelist_update(
	struct nd_prefix *new,
	struct nd_defrouter *dr, /* may be NULL */
	struct mbuf *m,
	int mcast)
{
	struct in6_ifaddr *ia6 = NULL, *ia6_match = NULL;
	struct ifaddr *ifa;
	struct ifnet *ifp = new->ndpr_ifp;
	struct nd_prefix *pr;
	int error = 0;
	int newprefix = 0;
	int auth;
	struct in6_addrlifetime lt6_tmp;
	struct timeval timenow;

	/* no need to lock "new" here, as it is local to the caller */
	NDPR_LOCK_ASSERT_NOTHELD(new);

	auth = 0;
	if (m) {
		/*
		 * Authenticity for NA consists authentication for
		 * both IP header and IP datagrams, doesn't it ?
		 */
#if defined(M_AUTHIPHDR) && defined(M_AUTHIPDGM)
		auth = (m->m_flags & M_AUTHIPHDR
		     && m->m_flags & M_AUTHIPDGM) ? 1 : 0;
#endif
	}


	if ((pr = nd6_prefix_lookup(new)) != NULL) {
		/*
		 * nd6_prefix_lookup() ensures that pr and new have the same
		 * prefix on a same interface.
		 */

		/*
		 * Update prefix information.  Note that the on-link (L) bit
		 * and the autonomous (A) bit should NOT be changed from 1
		 * to 0.
		 */
		lck_mtx_lock(nd6_mutex);
		NDPR_LOCK(pr);
		if (new->ndpr_raf_onlink == 1)
			pr->ndpr_raf_onlink = 1;
		if (new->ndpr_raf_auto == 1)
			pr->ndpr_raf_auto = 1;
		if (new->ndpr_raf_onlink) {
			pr->ndpr_vltime = new->ndpr_vltime;
			pr->ndpr_pltime = new->ndpr_pltime;
			pr->ndpr_preferred = new->ndpr_preferred;
			pr->ndpr_expire = new->ndpr_expire;
		}

		if (new->ndpr_raf_onlink &&
		    (pr->ndpr_stateflags & NDPRF_ONLINK) == 0) {
			int e;

			NDPR_UNLOCK(pr);
			if ((e = nd6_prefix_onlink(pr)) != 0) {
				nd6log((LOG_ERR,
				    "prelist_update: failed to make "
				    "the prefix %s/%d on-link on %s "
				    "(errno=%d)\n",
				    ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
				    pr->ndpr_plen, if_name(pr->ndpr_ifp), e));
				/* proceed anyway. XXX: is it correct? */
			}
			NDPR_LOCK(pr);
		}

		if (dr && pfxrtr_lookup(pr, dr) == NULL) {
			NDPR_UNLOCK(pr);
			pfxrtr_add(pr, dr);
		} else {
			NDPR_UNLOCK(pr);
		}
		lck_mtx_unlock(nd6_mutex);
	} else {
		struct nd_prefix *newpr = NULL;

		newprefix = 1;

		if (new->ndpr_vltime == 0)
			goto end;
		if (new->ndpr_raf_onlink == 0 && new->ndpr_raf_auto == 0)
			goto end;

		bzero(&new->ndpr_addr, sizeof(struct in6_addr));

		error = nd6_prelist_add(new, dr, &newpr, FALSE);
		if (error != 0 || newpr == NULL) {
			nd6log((LOG_NOTICE, "prelist_update: "
			    "nd6_prelist_add failed for %s/%d on %s "
			    "errno=%d, returnpr=%p\n",
			    ip6_sprintf(&new->ndpr_prefix.sin6_addr),
					new->ndpr_plen, if_name(new->ndpr_ifp),
					error, newpr));
			goto end; /* we should just give up in this case. */
		}

		/*
		 * XXX: from the ND point of view, we can ignore a prefix
		 * with the on-link bit being zero.  However, we need a
		 * prefix structure for references from autoconfigured
		 * addresses.  Thus, we explicitly make sure that the prefix
		 * itself expires now.
		 */
		NDPR_LOCK(newpr);
		if (newpr->ndpr_raf_onlink == 0) {
			newpr->ndpr_vltime = 0;
			newpr->ndpr_pltime = 0;
			in6_init_prefix_ltimes(newpr);
		}

		pr = newpr;
		NDPR_UNLOCK(newpr);
	}

	/*
	 * Address autoconfiguration based on Section 5.5.3 of RFC 2462.
	 * Note that pr must be non NULL at this point.
	 */

	/* 5.5.3 (a). Ignore the prefix without the A bit set. */
	if (!new->ndpr_raf_auto)
		goto afteraddrconf;

	/*
	 * 5.5.3 (b). the link-local prefix should have been ignored in
	 * nd6_ra_input.
	 */

	/* 5.5.3 (c). Consistency check on lifetimes: pltime <= vltime. */
	if (new->ndpr_pltime > new->ndpr_vltime) {
		error = EINVAL;	/* XXX: won't be used */
		goto end;
	}

	/*
	 * 5.5.3 (d).  If the prefix advertised is not equal to the prefix of
	 * an address configured by stateless autoconfiguration already in the
	 * list of addresses associated with the interface, and the Valid
	 * Lifetime is not 0, form an address.  We first check if we have
	 * a matching prefix.
	 * Note: we apply a clarification in rfc2462bis-02 here.  We only
	 * consider autoconfigured addresses while RFC2462 simply said
	 * "address".
	 */

 	getmicrotime(&timenow);

	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
	{
		struct in6_ifaddr *ifa6;
		u_int32_t remaininglifetime;

		IFA_LOCK(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			IFA_UNLOCK(ifa);
			continue;
		}
		ifa6 = (struct in6_ifaddr *)ifa;

		/*
		 * We only consider autoconfigured addresses as per rfc2462bis.
		 */
		if (!(ifa6->ia6_flags & IN6_IFF_AUTOCONF)) {
			IFA_UNLOCK(ifa);
			continue;
		}
		/*
		 * Spec is not clear here, but I believe we should concentrate
		 * on unicast (i.e. not anycast) addresses.
		 * XXX: other ia6_flags? detached or duplicated?
		 */
		if ((ifa6->ia6_flags & IN6_IFF_ANYCAST) != 0) {
			IFA_UNLOCK(ifa);
			continue;
		}
		/*
		 * Ignore the address if it is not associated with a prefix
		 * or is associated with a prefix that is different from this
		 * one.  (pr is never NULL here)
		 */
		if (ifa6->ia6_ndpr != pr) {
			IFA_UNLOCK(ifa);
			continue;
		}

		if (ia6_match == NULL) { /* remember the first one */
			ia6_match = ifa6;
			IFA_ADDREF_LOCKED(ifa);	/* for ia6_match */
		}

		/*
		 * An already autoconfigured address matched.  Now that we
		 * are sure there is at least one matched address, we can
		 * proceed to 5.5.3. (e): update the lifetimes according to the
		 * "two hours" rule and the privacy extension.
		 * We apply some clarifications in rfc2462bis:
		 * - use remaininglifetime instead of storedlifetime as a
		 *   variable name
		 * - remove the dead code in the "two-hour" rule
		 */
#define TWOHOUR		(120*60)
		lt6_tmp = ifa6->ia6_lifetime;

		if (lt6_tmp.ia6t_vltime == ND6_INFINITE_LIFETIME)
			remaininglifetime = ND6_INFINITE_LIFETIME;
		else if (timenow.tv_sec - ifa6->ia6_updatetime >
			 lt6_tmp.ia6t_vltime) {
			/*
			 * The case of "invalid" address.  We should usually
			 * not see this case.
			 */
			remaininglifetime = 0;
		} else
			remaininglifetime = lt6_tmp.ia6t_vltime -
			    (timenow.tv_sec - ifa6->ia6_updatetime);

		/* when not updating, keep the current stored lifetime. */
		lt6_tmp.ia6t_vltime = remaininglifetime;

		if (TWOHOUR < new->ndpr_vltime ||
		    remaininglifetime < new->ndpr_vltime) {
			lt6_tmp.ia6t_vltime = new->ndpr_vltime;
		} else if (remaininglifetime <= TWOHOUR) {
			if (auth) {
				lt6_tmp.ia6t_vltime = new->ndpr_vltime;
			}
		} else {
			/*
			 * new->ndpr_vltime <= TWOHOUR &&
			 * TWOHOUR < remaininglifetime
			 */
			lt6_tmp.ia6t_vltime = TWOHOUR;
		}

		/* The 2 hour rule is not imposed for preferred lifetime. */
		lt6_tmp.ia6t_pltime = new->ndpr_pltime;

		/* Special handling for lifetimes of temporary addresses. */
		if ((ifa6->ia6_flags & IN6_IFF_TEMPORARY) != 0) {
			u_int32_t maxvltime, maxpltime;
			
			/* Constrain lifetimes to system limits. */
			if (lt6_tmp.ia6t_vltime > ip6_temp_valid_lifetime)
				lt6_tmp.ia6t_vltime = ip6_temp_valid_lifetime;
			if (lt6_tmp.ia6t_pltime > ip6_temp_preferred_lifetime)
				lt6_tmp.ia6t_pltime =
				    ip6_temp_preferred_lifetime -
				    ip6_desync_factor;

			/*
			 * According to RFC 4941, section 3.3 (1), we only
			 * update the lifetimes when they are in the maximum
			 * intervals.
			 */
			if (ip6_temp_valid_lifetime >
			    (u_int32_t)((timenow.tv_sec - ifa6->ia6_createtime) +
			    ip6_desync_factor)) {
				maxvltime = ip6_temp_valid_lifetime -
				    (timenow.tv_sec - ifa6->ia6_createtime) -
				    ip6_desync_factor;
			} else
				maxvltime = 0;
			if (ip6_temp_preferred_lifetime >
			    (u_int32_t)((timenow.tv_sec - ifa6->ia6_createtime) +
			    ip6_desync_factor)) {
				maxpltime = ip6_temp_preferred_lifetime -
				    (timenow.tv_sec - ifa6->ia6_createtime) -
				    ip6_desync_factor;
			} else
				maxpltime = 0;

			if (lt6_tmp.ia6t_vltime > maxvltime)
				lt6_tmp.ia6t_vltime = maxvltime;
			if (lt6_tmp.ia6t_pltime > maxpltime)
				lt6_tmp.ia6t_pltime = maxpltime;
		}

		in6_init_address_ltimes(pr, &lt6_tmp,
		    !!(ifa6->ia6_flags & IN6_IFF_TEMPORARY));
		
		ifa6->ia6_lifetime = lt6_tmp;
		ifa6->ia6_updatetime = timenow.tv_sec;
		IFA_UNLOCK(ifa);
	}
	ifnet_lock_done(ifp);
	if (ia6_match == NULL && new->ndpr_vltime) {
		int ifidlen;

		/*
		 * 5.5.3 (d) (continued)
		 * No address matched and the valid lifetime is non-zero.
		 * Create a new address.
		 */

		/*
		 * Prefix Length check:
		 * If the sum of the prefix length and interface identifier
		 * length does not equal 128 bits, the Prefix Information
		 * option MUST be ignored.  The length of the interface
		 * identifier is defined in a separate link-type specific
		 * document.
		 */
		ifidlen = in6_if2idlen(ifp);
		if (ifidlen < 0) {
			/* this should not happen, so we always log it. */
			log(LOG_ERR, "prelist_update: IFID undefined (%s)\n",
			    if_name(ifp));
			goto end;
		}
		NDPR_LOCK(pr);
		if (ifidlen + pr->ndpr_plen != 128) {
			nd6log((LOG_INFO,
			    "prelist_update: invalid prefixlen "
			    "%d for %s, ignored\n",
			    pr->ndpr_plen, if_name(ifp)));
			NDPR_UNLOCK(pr);
			goto end;
		}
		NDPR_UNLOCK(pr);

		if ((ia6 = in6_ifadd(new, mcast)) != NULL) {
			/*
			 * note that we should use pr (not new) for reference.
			 */
			IFA_LOCK(&ia6->ia_ifa);
			NDPR_LOCK(pr);
			ia6->ia6_ndpr = pr;
			NDPR_ADDREF_LOCKED(pr);	/* for addr reference */
			pr->ndpr_addrcnt++;
			VERIFY(pr->ndpr_addrcnt != 0);
			NDPR_UNLOCK(pr);
			IFA_UNLOCK(&ia6->ia_ifa);

			/*
			 * RFC 4941 3.3 (2).
			 * When a new public address is created as described
			 * in RFC2462, also create a new temporary address.
			 *
			 * RFC 4941 3.5.
			 * When an interface connects to a new link, a new
			 * randomized interface identifier should be generated
			 * immediately together with a new set of temporary
			 * addresses.  Thus, we specifiy 1 as the 2nd arg of
			 * in6_tmpifadd().
			 */
			if (ip6_use_tempaddr) {
				int e;
				if ((e = in6_tmpifadd(ia6, 1, M_WAITOK)) != 0) {
					nd6log((LOG_NOTICE, "prelist_update: "
					    "failed to create a temporary "
					    "address, errno=%d\n",
					    e));
				}
			}
			IFA_REMREF(&ia6->ia_ifa);
			ia6 = NULL;

			/*
			 * A newly added address might affect the status
			 * of other addresses, so we check and update it.
			 * XXX: what if address duplication happens?
			 */
			lck_mtx_lock(nd6_mutex);
			pfxlist_onlink_check();
			lck_mtx_unlock(nd6_mutex);
		} else {
			/* just set an error. do not bark here. */
			error = EADDRNOTAVAIL; /* XXX: might be unused. */
		}
	}

afteraddrconf:

end:
	if (pr != NULL)
		NDPR_REMREF(pr);
	if (ia6_match != NULL)
		IFA_REMREF(&ia6_match->ia_ifa);
	return error;
}

/*
 * Neighbor Discover Default Router structure reference counting routines.
 */
static struct nd_defrouter *
nddr_alloc(int how)
{
	struct nd_defrouter *dr;

	dr = (how == M_WAITOK) ? zalloc(nddr_zone) : zalloc_noblock(nddr_zone);
	if (dr != NULL) {
		bzero(dr, nddr_size);
		lck_mtx_init(&dr->nddr_lock, ifa_mtx_grp, ifa_mtx_attr);
		dr->nddr_debug |= IFD_ALLOC;
		if (nddr_debug != 0) {
			dr->nddr_debug |= IFD_DEBUG;
			dr->nddr_trace = nddr_trace;
		}
	}
	return (dr);
}

static void
nddr_free(struct nd_defrouter *dr)
{
	NDDR_LOCK(dr);
	if (dr->nddr_debug & IFD_ATTACHED) {
		panic("%s: attached nddr %p is being freed", __func__, dr);
		/* NOTREACHED */
	} else if (!(dr->nddr_debug & IFD_ALLOC)) {
		panic("%s: nddr %p cannot be freed", __func__, dr);
		/* NOTREACHED */
	}
	dr->nddr_debug &= ~IFD_ALLOC;
	NDDR_UNLOCK(dr);

	lck_mtx_destroy(&dr->nddr_lock, ifa_mtx_grp);
	zfree(nddr_zone, dr);
}

static void
nddr_trace(struct nd_defrouter *dr, int refhold)
{
	struct nd_defrouter_dbg *dr_dbg = (struct nd_defrouter_dbg *)dr;
	ctrace_t *tr;
	uint32_t idx;
	uint16_t *cnt;

	if (!(dr->nddr_debug & IFD_DEBUG)) {
		panic("%s: nddr %p has no debug structure", __func__, dr);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &dr_dbg->nddr_refhold_cnt;
		tr = dr_dbg->nddr_refhold;
	} else {
		cnt = &dr_dbg->nddr_refrele_cnt;
		tr = dr_dbg->nddr_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % NDDR_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

void
nddr_addref(struct nd_defrouter *nddr, int locked)
{

	if (!locked)
		NDDR_LOCK_SPIN(nddr);
	else
		NDDR_LOCK_ASSERT_HELD(nddr);

	if (++nddr->nddr_refcount == 0) {
		panic("%s: nddr %p wraparound refcnt\n", __func__, nddr);
		/* NOTREACHED */
	} else if (nddr->nddr_trace != NULL) {
		(*nddr->nddr_trace)(nddr, TRUE);
	}

	if (!locked)
		NDDR_UNLOCK(nddr);
}

struct nd_defrouter *
nddr_remref(struct nd_defrouter *nddr, int locked)
{

	if (!locked)
		NDDR_LOCK_SPIN(nddr);
	else
		NDDR_LOCK_ASSERT_HELD(nddr);

	if (nddr->nddr_refcount == 0) {
		panic("%s: nddr %p negative refcnt\n", __func__, nddr);
		/* NOTREACHED */
	} else if (nddr->nddr_trace != NULL) {
		(*nddr->nddr_trace)(nddr, FALSE);
	}

	if (--nddr->nddr_refcount == 0) {
		NDDR_UNLOCK(nddr);
		nddr_free(nddr);
		nddr = NULL;
	}

	if (!locked && nddr != NULL)
		NDDR_UNLOCK(nddr);

	return (nddr);
}

/*
 * Neighbor Discover Prefix structure reference counting routines.
 */
static struct nd_prefix *
ndpr_alloc(int how)
{
	struct nd_prefix *pr;

	pr = (how == M_WAITOK) ? zalloc(ndpr_zone) : zalloc_noblock(ndpr_zone);
	if (pr != NULL) {
		bzero(pr, ndpr_size);
		lck_mtx_init(&pr->ndpr_lock, ifa_mtx_grp, ifa_mtx_attr);
		pr->ndpr_debug |= IFD_ALLOC;
		if (ndpr_debug != 0) {
			pr->ndpr_debug |= IFD_DEBUG;
			pr->ndpr_trace = ndpr_trace;
		}
	}
	return (pr);
}

static void
ndpr_free(struct nd_prefix *pr)
{
	NDPR_LOCK(pr);
	if (pr->ndpr_debug & IFD_ATTACHED) {
		panic("%s: attached ndpr %p is being freed", __func__, pr);
		/* NOTREACHED */
	} else if (!(pr->ndpr_debug & IFD_ALLOC)) {
		panic("%s: ndpr %p cannot be freed", __func__, pr);
		/* NOTREACHED */
	}
	pr->ndpr_debug &= ~IFD_ALLOC;
	NDPR_UNLOCK(pr);

	lck_mtx_destroy(&pr->ndpr_lock, ifa_mtx_grp);
	zfree(ndpr_zone, pr);
}

static void
ndpr_trace(struct nd_prefix *pr, int refhold)
{
	struct nd_prefix_dbg *pr_dbg = (struct nd_prefix_dbg *)pr;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(pr->ndpr_debug & IFD_DEBUG)) {
		panic("%s: ndpr %p has no debug structure", __func__, pr);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &pr_dbg->ndpr_refhold_cnt;
		tr = pr_dbg->ndpr_refhold;
	} else {
		cnt = &pr_dbg->ndpr_refrele_cnt;
		tr = pr_dbg->ndpr_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % NDPR_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

void
ndpr_addref(struct nd_prefix *ndpr, int locked)
{
	if (!locked)
		NDPR_LOCK_SPIN(ndpr);
	else
		NDPR_LOCK_ASSERT_HELD(ndpr);

	if (++ndpr->ndpr_refcount == 0) {
		panic("%s: ndpr %p wraparound refcnt\n", __func__, ndpr);
		/* NOTREACHED */
	} else if (ndpr->ndpr_trace != NULL) {
		(*ndpr->ndpr_trace)(ndpr, TRUE);
	}

	if (!locked)
		NDPR_UNLOCK(ndpr);
}

struct nd_prefix *
ndpr_remref(struct nd_prefix *ndpr, int locked)
{
	if (!locked)
		NDPR_LOCK_SPIN(ndpr);
	else
		NDPR_LOCK_ASSERT_HELD(ndpr);

	if (ndpr->ndpr_refcount == 0) {
		panic("%s: ndpr %p negative refcnt\n", __func__, ndpr);
		/* NOTREACHED */
	} else if (ndpr->ndpr_trace != NULL) {
		(*ndpr->ndpr_trace)(ndpr, FALSE);
	}

	if (--ndpr->ndpr_refcount == 0) {
		if (ndpr->ndpr_addrcnt != 0) {
			panic("%s: freeing ndpr %p with outstanding address "
			    "reference (%d)", __func__, ndpr,
			    ndpr->ndpr_addrcnt);
			/* NOTREACHED */
		}
		NDPR_UNLOCK(ndpr);
		ndpr_free(ndpr);
		ndpr = NULL;
	}

	if (!locked && ndpr != NULL)
		NDPR_UNLOCK(ndpr);

	return (ndpr);
}

/*
 * A supplement function used in the on-link detection below;
 * detect if a given prefix has a (probably) reachable advertising router.
 * XXX: lengthy function name...
 */
static struct nd_pfxrouter *
find_pfxlist_reachable_router(struct nd_prefix *pr)
{
	struct nd_pfxrouter *pfxrtr;
	struct rtentry *rt;
	struct llinfo_nd6 *ln;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	NDPR_LOCK_ASSERT_HELD(pr);

	for (pfxrtr = LIST_FIRST(&pr->ndpr_advrtrs); pfxrtr;
	     pfxrtr = LIST_NEXT(pfxrtr, pfr_entry)) {
		NDPR_UNLOCK(pr);
		lck_mtx_unlock(nd6_mutex);
		/* Callee returns a locked route upon success */
		if ((rt = nd6_lookup(&pfxrtr->router->rtaddr, 0,
		    pfxrtr->router->ifp, 0)) != NULL) {
			RT_LOCK_ASSERT_HELD(rt);
			if ((ln = rt->rt_llinfo) != NULL &&
			    ND6_IS_LLINFO_PROBREACH(ln)) {
				RT_REMREF_LOCKED(rt);
				RT_UNLOCK(rt);
				lck_mtx_lock(nd6_mutex);
				NDPR_LOCK(pr);
				break;	/* found */
			}
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
		}
		lck_mtx_lock(nd6_mutex);
		NDPR_LOCK(pr);
	}
	NDPR_LOCK_ASSERT_HELD(pr);

	return (pfxrtr);

}

/*
 * Check if each prefix in the prefix list has at least one available router
 * that advertised the prefix (a router is "available" if its neighbor cache
 * entry is reachable or probably reachable).
 * If the check fails, the prefix may be off-link, because, for example,
 * we have moved from the network but the lifetime of the prefix has not
 * expired yet.  So we should not use the prefix if there is another prefix
 * that has an available router.
 * But, if there is no prefix that has an available router, we still regards
 * all the prefixes as on-link.  This is because we can't tell if all the
 * routers are simply dead or if we really moved from the network and there
 * is no router around us.
 */
void
pfxlist_onlink_check(void)
{
	struct nd_prefix *pr, *prclear;
	struct in6_ifaddr *ifa;
	struct nd_defrouter *dr;
	struct nd_pfxrouter *pfxrtr = NULL;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	while (nd_prefix_busy) {
		nd_prefix_waiters++;
		msleep(nd_prefix_waitchan, nd6_mutex, (PZERO-1),
		    __func__, NULL);
		lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	}
	nd_prefix_busy = TRUE;

	/*
	 * Check if there is a prefix that has a reachable advertising
	 * router.
	 */
	pr = nd_prefix.lh_first;
	while (pr) {
		NDPR_LOCK(pr);
		if (pr->ndpr_stateflags & NDPRF_PROCESSED) {
			NDPR_UNLOCK(pr);
			pr = pr->ndpr_next;
			continue;
		}
		NDPR_ADDREF_LOCKED(pr);
		if (pr->ndpr_raf_onlink && find_pfxlist_reachable_router(pr) &&
		    (pr->ndpr_debug & IFD_ATTACHED)) {
			NDPR_UNLOCK(pr);
			NDPR_REMREF(pr);
			break;
		}
		pr->ndpr_stateflags |= NDPRF_PROCESSED;
		NDPR_UNLOCK(pr);
		NDPR_REMREF(pr);
		/*
		 * Since find_pfxlist_reachable_router() drops the nd6_mutex, we
		 * have to start over, but the NDPRF_PROCESSED flag will stop
		 * us from checking the same prefix twice.
		 */
		pr = nd_prefix.lh_first;
	}
	LIST_FOREACH(prclear, &nd_prefix, ndpr_entry) {
		NDPR_LOCK(prclear);
		prclear->ndpr_stateflags &= ~NDPRF_PROCESSED;
		NDPR_UNLOCK(prclear);
	}

	/*
	 * If we have no such prefix, check whether we still have a router
	 * that does not advertise any prefixes.
	 */
	if (pr == NULL) {
		for (dr = TAILQ_FIRST(&nd_defrouter); dr;
		    dr = TAILQ_NEXT(dr, dr_entry)) {
			struct nd_prefix *pr0;

			for (pr0 = nd_prefix.lh_first; pr0;
			    pr0 = pr0->ndpr_next) {
				NDPR_LOCK(pr0);
				if ((pfxrtr = pfxrtr_lookup(pr0, dr)) != NULL) {
					NDPR_UNLOCK(pr0);
					break;
				}
				NDPR_UNLOCK(pr0);
			}
			if (pfxrtr != NULL)
				break;
		}
	}
	if (pr != NULL || (TAILQ_FIRST(&nd_defrouter) && pfxrtr == NULL)) {
		/*
		 * There is at least one prefix that has a reachable router,
		 * or at least a router which probably does not advertise
		 * any prefixes.  The latter would be the case when we move
		 * to a new link where we have a router that does not provide
		 * prefixes and we configure an address by hand.
		 * Detach prefixes which have no reachable advertising
		 * router, and attach other prefixes.
		 */
		pr = nd_prefix.lh_first;
		while (pr) {
			NDPR_LOCK(pr);
			/*
			 * We aren't interested prefixes already processed,
			 * nor in prefixes without the L bit
			 * set nor in static prefixes
			 */
			if (pr->ndpr_raf_onlink == 0 ||
			    pr->ndpr_stateflags & NDPRF_PROCESSED ||
			    pr->ndpr_stateflags & NDPRF_STATIC) {
				NDPR_UNLOCK(pr);
				pr = pr->ndpr_next;
				continue;
			}
			NDPR_ADDREF_LOCKED(pr);
			if ((pr->ndpr_stateflags & NDPRF_DETACHED) == 0 &&
			    find_pfxlist_reachable_router(pr) == NULL &&
			    (pr->ndpr_debug & IFD_ATTACHED))
				pr->ndpr_stateflags |= NDPRF_DETACHED;
			if ((pr->ndpr_stateflags & NDPRF_DETACHED) != 0 &&
			    find_pfxlist_reachable_router(pr) != NULL &&
			    (pr->ndpr_debug & IFD_ATTACHED))
				pr->ndpr_stateflags &= ~NDPRF_DETACHED;
			pr->ndpr_stateflags |= NDPRF_PROCESSED;
			NDPR_UNLOCK(pr);
			NDPR_REMREF(pr);
			/*
			 * Since find_pfxlist_reachable_router() drops the
			 * nd6_mutex, we have to start over, but the
			 * NDPRF_PROCESSED flag will stop us from checking
			 * the same prefix twice.
			 */
			pr = nd_prefix.lh_first;
		}
	} else {
		/* there is no prefix that has a reachable router */
		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			NDPR_LOCK(pr);
			if (pr->ndpr_raf_onlink == 0 ||
			    pr->ndpr_stateflags & NDPRF_STATIC) {
				NDPR_UNLOCK(pr);
				continue;
			}
			if ((pr->ndpr_stateflags & NDPRF_DETACHED) != 0)
				pr->ndpr_stateflags &= ~NDPRF_DETACHED;
			NDPR_UNLOCK(pr);
		}
	}
	LIST_FOREACH(prclear, &nd_prefix, ndpr_entry) {
		NDPR_LOCK(prclear);
		prclear->ndpr_stateflags &= ~NDPRF_PROCESSED;
		NDPR_UNLOCK(prclear);
	}
	VERIFY(nd_prefix_busy);
	nd_prefix_busy = FALSE;
	if (nd_prefix_waiters > 0) {
		nd_prefix_waiters = 0;
		wakeup(nd_prefix_waitchan);
	}

	/*
	 * Remove each interface route associated with a (just) detached
	 * prefix, and reinstall the interface route for a (just) attached
	 * prefix.  Note that all attempt of reinstallation does not
	 * necessarily success, when a same prefix is shared among multiple
	 * interfaces.  Such cases will be handled in nd6_prefix_onlink,
	 * so we don't have to care about them.
	 */
	pr = nd_prefix.lh_first;
	while (pr) {
		int e;

		NDPR_LOCK(pr);
		if (pr->ndpr_raf_onlink == 0 ||
		    pr->ndpr_stateflags & NDPRF_STATIC) {
			NDPR_UNLOCK(pr);
			pr = pr->ndpr_next;
			continue;
		}
		if ((pr->ndpr_stateflags & NDPRF_DETACHED) != 0 &&
		    (pr->ndpr_stateflags & NDPRF_ONLINK) != 0) {
			NDPR_UNLOCK(pr);
			lck_mtx_unlock(nd6_mutex);
			if ((e = nd6_prefix_offlink(pr)) != 0) {
				nd6log((LOG_ERR,
				    "pfxlist_onlink_check: failed to "
				    "make %s/%d offlink, errno=%d\n",
				    ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
				    pr->ndpr_plen, e));
			}
			lck_mtx_lock(nd6_mutex);
			pr = nd_prefix.lh_first;
			continue;
		}
		if ((pr->ndpr_stateflags & NDPRF_DETACHED) == 0 &&
		    (pr->ndpr_stateflags & NDPRF_ONLINK) == 0 &&
		    pr->ndpr_raf_onlink) {
			NDPR_UNLOCK(pr);
			if ((e = nd6_prefix_onlink(pr)) != 0) {
				nd6log((LOG_ERR,
				    "pfxlist_onlink_check: failed to "
				    "make %s/%d offlink, errno=%d\n",
				    ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
				    pr->ndpr_plen, e));
			}
		} else {
			NDPR_UNLOCK(pr);
		}
		pr = pr->ndpr_next;
	}

	/*
	 * Changes on the prefix status might affect address status as well.
	 * Make sure that all addresses derived from an attached prefix are
	 * attached, and that all addresses derived from a detached prefix are
	 * detached.  Note, however, that a manually configured address should
	 * always be attached.
	 * The precise detection logic is same as the one for prefixes.
	 */
	lck_rw_lock_shared(&in6_ifaddr_rwlock);
	for (ifa = in6_ifaddrs; ifa; ifa = ifa->ia_next) {
		struct nd_prefix *ndpr;

		IFA_LOCK(&ifa->ia_ifa);
		if ((ifa->ia6_flags & IN6_IFF_AUTOCONF) == 0) {
			IFA_UNLOCK(&ifa->ia_ifa);
			continue;
		}
		if ((ndpr = ifa->ia6_ndpr) == NULL) {
			/*
			 * This can happen when we first configure the address
			 * (i.e. the address exists, but the prefix does not).
			 * XXX: complicated relationships...
			 */
			IFA_UNLOCK(&ifa->ia_ifa);
			continue;
		}
		NDPR_ADDREF(ndpr);
		IFA_UNLOCK(&ifa->ia_ifa);

		NDPR_LOCK(ndpr);
		if (find_pfxlist_reachable_router(ndpr)) {
			NDPR_UNLOCK(ndpr);
			NDPR_REMREF(ndpr);
			break;
		}
		NDPR_UNLOCK(ndpr);
		NDPR_REMREF(ndpr);
	}
	if (ifa) {
		for (ifa = in6_ifaddrs; ifa; ifa = ifa->ia_next) {
			struct nd_prefix *ndpr;

			IFA_LOCK(&ifa->ia_ifa);
			if ((ifa->ia6_flags & IN6_IFF_AUTOCONF) == 0) {
				IFA_UNLOCK(&ifa->ia_ifa);
				continue;
			}
			if ((ndpr = ifa->ia6_ndpr) == NULL) {
				/* XXX: see above. */
				IFA_UNLOCK(&ifa->ia_ifa);
				continue;
			}
			NDPR_ADDREF(ndpr);
			IFA_UNLOCK(&ifa->ia_ifa);
			NDPR_LOCK(ndpr);
			if (find_pfxlist_reachable_router(ndpr)) {
				NDPR_UNLOCK(ndpr);
				IFA_LOCK(&ifa->ia_ifa);
				if (ifa->ia6_flags & IN6_IFF_DETACHED) {
					ifa->ia6_flags &= ~IN6_IFF_DETACHED;
					ifa->ia6_flags |= IN6_IFF_TENTATIVE;
					IFA_UNLOCK(&ifa->ia_ifa);
					nd6_dad_start((struct ifaddr *)ifa, 0);
				} else {
					IFA_UNLOCK(&ifa->ia_ifa);
				}
			} else {
				NDPR_UNLOCK(ndpr);
				IFA_LOCK(&ifa->ia_ifa);
				ifa->ia6_flags |= IN6_IFF_DETACHED;
				IFA_UNLOCK(&ifa->ia_ifa);
			}
			NDPR_REMREF(ndpr);
		}
	}
	else {
		for (ifa = in6_ifaddrs; ifa; ifa = ifa->ia_next) {
			IFA_LOCK(&ifa->ia_ifa);
			if ((ifa->ia6_flags & IN6_IFF_AUTOCONF) == 0) {
				IFA_UNLOCK(&ifa->ia_ifa);
				continue;
			}
			if (ifa->ia6_flags & IN6_IFF_DETACHED) {
				ifa->ia6_flags &= ~IN6_IFF_DETACHED;
				ifa->ia6_flags |= IN6_IFF_TENTATIVE;
				IFA_UNLOCK(&ifa->ia_ifa);
				/* Do we need a delay in this case? */
				nd6_dad_start((struct ifaddr *)ifa, 0);
			} else {
				IFA_UNLOCK(&ifa->ia_ifa);
			}
		}
	}
	lck_rw_done(&in6_ifaddr_rwlock);
}

static struct nd_prefix *
nd6_prefix_equal_lookup(struct nd_prefix *pr, boolean_t primary_only)
{
	struct nd_prefix *opr;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	for (opr = nd_prefix.lh_first; opr; opr = opr->ndpr_next) {
		if (opr == pr)
			continue;

		NDPR_LOCK(opr);
		if ((opr->ndpr_stateflags & NDPRF_ONLINK) == 0) {
			NDPR_UNLOCK(opr);
			continue;
		}
		if (opr->ndpr_plen == pr->ndpr_plen &&
		    in6_are_prefix_equal(&pr->ndpr_prefix.sin6_addr,
		    &opr->ndpr_prefix.sin6_addr, pr->ndpr_plen) &&
		    (!primary_only ||
		    !(opr->ndpr_stateflags & NDPRF_IFSCOPE))) {
			NDPR_ADDREF_LOCKED(opr);
			NDPR_UNLOCK(opr);
			return (opr);
		}
		NDPR_UNLOCK(opr);
	}
	return (NULL);
}

/*
 * Synchronize the interface routes of similar prefixes on different
 * interfaces; the one using the default interface would be (re)installed
 * as a primary/non-scoped entry, and the rest as scoped entri(es).
 */
static void
nd6_prefix_sync(struct ifnet *ifp)
{
	struct nd_prefix *pr, *opr;
	int err = 0;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	if (!ip6_doscopedroute || ifp == NULL)
		return;

	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		NDPR_LOCK(pr);
		if (!(pr->ndpr_stateflags & NDPRF_ONLINK)) {
			NDPR_UNLOCK(pr);
			continue;
		}
		if (pr->ndpr_ifp == ifp &&
		    (pr->ndpr_stateflags & NDPRF_IFSCOPE) &&
		    !IN6_IS_ADDR_LINKLOCAL(&pr->ndpr_prefix.sin6_addr)) {
			NDPR_UNLOCK(pr);
			break;
		}
		NDPR_UNLOCK(pr);
	}

	if (pr == NULL)
		return;

	/* Remove conflicting entries */
	opr = nd6_prefix_equal_lookup(pr, TRUE);
	if (opr != NULL) {
		lck_mtx_unlock(nd6_mutex);
		err = nd6_prefix_offlink(opr);
		lck_mtx_lock(nd6_mutex);
		if (err != 0) {
			nd6log((LOG_ERR,
			    "%s: failed to make %s/%d offlink on %s, "
			    "errno=%d\n", __func__,
			    ip6_sprintf(&opr->ndpr_prefix.sin6_addr),
			    opr->ndpr_plen, if_name(opr->ndpr_ifp), err));
		}
	} else {
		nd6log((LOG_ERR,
		    "%s: scoped %s/%d on %s has no matching unscoped prefix\n",
		    __func__, ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
		    pr->ndpr_plen, if_name(pr->ndpr_ifp)));
	}

	lck_mtx_unlock(nd6_mutex);
	err = nd6_prefix_offlink(pr);
	lck_mtx_lock(nd6_mutex);
	if (err != 0) {
		nd6log((LOG_ERR,
		    "%s: failed to make %s/%d offlink on %s, errno=%d\n",
		    __func__, ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
		    pr->ndpr_plen, if_name(pr->ndpr_ifp), err));
	}

	/* Add the entries back */
	if (opr != NULL) {
		err = nd6_prefix_onlink_scoped(opr, opr->ndpr_ifp->if_index);
		if (err != 0) {
			nd6log((LOG_ERR,
			    "%s: failed to make %s/%d scoped onlink on %s, "
			    "errno=%d\n", __func__,
			    ip6_sprintf(&opr->ndpr_prefix.sin6_addr),
			    opr->ndpr_plen, if_name(opr->ndpr_ifp), err));
		}
	}

	err = nd6_prefix_onlink_scoped(pr, IFSCOPE_NONE);
	if (err != 0) {
		nd6log((LOG_ERR,
		    "%s: failed to make %s/%d onlink on %s, errno=%d\n",
		    __func__, ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
		    pr->ndpr_plen, if_name(pr->ndpr_ifp), err));
	}

	if (err != 0) {
		nd6log((LOG_ERR,
		    "%s: error promoting %s/%d to %s from %s\n",
		    __func__, ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
		    pr->ndpr_plen, if_name(pr->ndpr_ifp),
		    (opr != NULL) ? if_name(opr->ndpr_ifp) : "NONE"));
	} else {
		nd6log2((LOG_INFO,
		    "%s: %s/%d promoted, previously on %s\n",
		    if_name(pr->ndpr_ifp),
		    ip6_sprintf(&pr->ndpr_prefix.sin6_addr), pr->ndpr_plen,
		    (opr != NULL) ? if_name(opr->ndpr_ifp) : "NONE"));
	}

	if (opr != NULL)
		NDPR_REMREF(opr);
}

static int
nd6_prefix_onlink_common(struct nd_prefix *pr, boolean_t force_scoped,
    unsigned int ifscope)
{
	struct ifaddr *ifa;
	struct ifnet *ifp = pr->ndpr_ifp;
	struct sockaddr_in6 mask6, prefix;
	struct nd_prefix *opr;
	u_int32_t rtflags;
	int error = 0;
	struct rtentry *rt = NULL;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	/* sanity check */
	NDPR_LOCK(pr);
	if ((pr->ndpr_stateflags & NDPRF_ONLINK) != 0) {
		nd6log((LOG_ERR,
		    "nd6_prefix_onlink: %s/%d on %s scoped=%d is already "
		     "on-link\n", ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
		     pr->ndpr_plen, if_name(pr->ndpr_ifp),
		     (pr->ndpr_stateflags & NDPRF_IFSCOPE) ? 1 : 0);
		NDPR_UNLOCK(pr);
		return (EEXIST));
	}
	NDPR_UNLOCK(pr);

	/*
	 * Add the interface route associated with the prefix.  Before
	 * installing the route, check if there's the same prefix on another
	 * interface, and the prefix has already installed the interface route.
	 */
	opr = nd6_prefix_equal_lookup(pr, FALSE);
	if (opr != NULL)
		NDPR_REMREF(opr);

	if (!ip6_doscopedroute) {
		/* if an interface route already exists, just return */
		if (opr != NULL)
			return (0);
		ifscope = IFSCOPE_NONE;
	} else if (!force_scoped) {
		/*
		 * If a primary/non-scoped interface route already exists,
		 * install the new one as a scoped entry.  If the existing
		 * interface route is scoped, install new as non-scoped.
		 */
		ifscope = (opr != NULL) ? ifp->if_index : IFSCOPE_NONE;
		opr = nd6_prefix_equal_lookup(pr, TRUE);
		if (opr != NULL)
			NDPR_REMREF(opr);
		else if (ifscope != IFSCOPE_NONE)
			ifscope = IFSCOPE_NONE;
	}

	/*
	 * We prefer link-local addresses as the associated interface address.
	 */
	/* search for a link-local addr */
	ifa = (struct ifaddr *)in6ifa_ifpforlinklocal(ifp,
						      IN6_IFF_NOTREADY|
						      IN6_IFF_ANYCAST);
	if (ifa == NULL) {
		struct in6_ifaddr *ia6;
		ifnet_lock_shared(ifp);
		IFP_TO_IA6(ifp, ia6);
		ifnet_lock_done(ifp);
		if (ia6 != NULL)
			ifa = &ia6->ia_ifa;
		/* should we care about ia6_flags? */
	}
	NDPR_LOCK(pr);
	if (ifa == NULL) {
		/*
		 * This can still happen, when, for example, we receive an RA
		 * containing a prefix with the L bit set and the A bit clear,
		 * after removing all IPv6 addresses on the receiving
		 * interface.  This should, of course, be rare though.
		 */
		nd6log((LOG_NOTICE,
		    "nd6_prefix_onlink: failed to find any ifaddr"
		    " to add route for a prefix(%s/%d) on %s\n",
		    ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
		    pr->ndpr_plen, if_name(ifp)));
		NDPR_UNLOCK(pr);
		return (0);
	}

	/*
	 * in6_ifinit() sets nd6_rtrequest to ifa_rtrequest for all ifaddrs.
	 * ifa->ifa_rtrequest = nd6_rtrequest;
	 */
	bzero(&mask6, sizeof(mask6));
	mask6.sin6_len = sizeof(mask6);
	mask6.sin6_addr = pr->ndpr_mask;
	prefix = pr->ndpr_prefix;
	NDPR_UNLOCK(pr);

	IFA_LOCK_SPIN(ifa);
	rtflags = ifa->ifa_flags | RTF_CLONING | RTF_UP;
	IFA_UNLOCK(ifa);
	if (nd6_need_cache(ifp)) {
		/* explicitly set in case ifa_flags does not set the flag. */
		rtflags |= RTF_CLONING;
	} else {
		/*
		 * explicitly clear the cloning bit in case ifa_flags sets it.
		 */
		rtflags &= ~RTF_CLONING;
	}

	lck_mtx_unlock(nd6_mutex);

	error = rtrequest_scoped(RTM_ADD, (struct sockaddr *)&prefix,
	    ifa->ifa_addr, (struct sockaddr *)&mask6, rtflags, &rt,
	    ifscope);

	if (rt != NULL) {
		RT_LOCK(rt);
		nd6_rtmsg(RTM_ADD, rt);
		RT_UNLOCK(rt);
		RT_REMREF(rt);
	} else {
		NDPR_LOCK(pr);
		nd6log((LOG_ERR, "nd6_prefix_onlink: failed to add route for a"
		    " prefix (%s/%d) on %s, gw=%s, mask=%s, flags=%lx,"
		    " scoped=%d, errno = %d\n",
		    ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
		    pr->ndpr_plen, if_name(ifp),
		    ip6_sprintf(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr),
		    ip6_sprintf(&mask6.sin6_addr), rtflags,
		    (ifscope != IFSCOPE_NONE), error));
		NDPR_UNLOCK(pr);
	}

	lck_mtx_lock(nd6_mutex);

	NDPR_LOCK(pr);
	pr->ndpr_stateflags &= ~NDPRF_IFSCOPE;
	if (rt != NULL || error == EEXIST) {
		pr->ndpr_stateflags |= NDPRF_ONLINK;
		if (ifscope != IFSCOPE_NONE)
			pr->ndpr_stateflags |= NDPRF_IFSCOPE;
	}
	NDPR_UNLOCK(pr);

	IFA_REMREF(ifa);

	return (error);
}

int
nd6_prefix_onlink(struct nd_prefix *pr)
{
	return (nd6_prefix_onlink_common(pr, FALSE, IFSCOPE_NONE));
}

int
nd6_prefix_onlink_scoped(struct nd_prefix *pr, unsigned int ifscope)
{
	return (nd6_prefix_onlink_common(pr, TRUE, ifscope));
}

int
nd6_prefix_offlink(struct nd_prefix *pr)
{
	int plen, error = 0;
	struct ifnet *ifp = pr->ndpr_ifp;
	struct nd_prefix *opr;
	struct sockaddr_in6 sa6, mask6, prefix;
	struct rtentry *rt = NULL;
	unsigned int ifscope;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	/* sanity check */
	NDPR_LOCK(pr);
	if ((pr->ndpr_stateflags & NDPRF_ONLINK) == 0) {
		nd6log((LOG_ERR,
		    "nd6_prefix_offlink: %s/%d on %s scoped=%d is already "
		    "off-link\n", ip6_sprintf(&pr->ndpr_prefix.sin6_addr),
		    pr->ndpr_plen, if_name(pr->ndpr_ifp),
		    (pr->ndpr_stateflags & NDPRF_IFSCOPE) ? 1 : 0));
		NDPR_UNLOCK(pr);
		return (EEXIST);
	}

	bzero(&sa6, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(sa6);
	bcopy(&pr->ndpr_prefix.sin6_addr, &sa6.sin6_addr,
	      sizeof(struct in6_addr));
	bzero(&mask6, sizeof(mask6));
	mask6.sin6_family = AF_INET6;
	mask6.sin6_len = sizeof(sa6);
	bcopy(&pr->ndpr_mask, &mask6.sin6_addr, sizeof(struct in6_addr));
	prefix = pr->ndpr_prefix;
	plen = pr->ndpr_plen;
	NDPR_UNLOCK(pr);

	ifscope = (pr->ndpr_stateflags & NDPRF_IFSCOPE) ?
	    ifp->if_index : IFSCOPE_NONE;

	error = rtrequest_scoped(RTM_DELETE, (struct sockaddr *)&sa6,
	    NULL, (struct sockaddr *)&mask6, 0, &rt, ifscope);

	if (rt != NULL) {
		/* report the route deletion to the routing socket. */
		RT_LOCK(rt);
		nd6_rtmsg(RTM_DELETE, rt);
		RT_UNLOCK(rt);
		rtfree(rt);

		/*
		 * The following check takes place only when Scoped Routing
		 * is not enabled.  There might be the same prefix on another
		 * interface, the prefix which could not be on-link just
		 * because we have the interface route (see comments in
		 * nd6_prefix_onlink).  If there's one, try to make the prefix
		 * on-link on the interface.
		 */
		lck_mtx_lock(nd6_mutex);
		opr = nd_prefix.lh_first;
		while (opr) {
			/* does not apply in the Scoped Routing case */
			if (ip6_doscopedroute)
				break;

			if (opr == pr) {
				opr = opr->ndpr_next;
				continue;
			}

			NDPR_LOCK(opr);
			if ((opr->ndpr_stateflags & NDPRF_ONLINK) != 0) {
				NDPR_UNLOCK(opr);
				opr = opr->ndpr_next;
				continue;
			}
			/*
			 * KAME specific: detached prefixes should not be
			 * on-link.
			 */
			if ((opr->ndpr_stateflags & NDPRF_DETACHED) != 0) {
				NDPR_UNLOCK(opr);
				opr = opr->ndpr_next;
				continue;
			}
			if (opr->ndpr_plen == plen &&
			    in6_are_prefix_equal(&prefix.sin6_addr,
		            &opr->ndpr_prefix.sin6_addr, plen)) {
				int e;

				NDPR_UNLOCK(opr);
				lck_mtx_unlock(nd6_mutex);
				if ((e = nd6_prefix_onlink(opr)) != 0) {
					nd6log((LOG_ERR,
					    "nd6_prefix_offlink: failed to "
					    "recover a prefix %s/%d from %s "
					    "to %s (errno = %d)\n",
					    ip6_sprintf(&opr->ndpr_prefix.sin6_addr),
					    opr->ndpr_plen, if_name(ifp),
					    if_name(opr->ndpr_ifp), e));
				}
				lck_mtx_lock(nd6_mutex);
				opr = nd_prefix.lh_first;
			} else {
				NDPR_UNLOCK(opr);
				opr = opr->ndpr_next;
			}
		}
		lck_mtx_unlock(nd6_mutex);
	} else {
		nd6log((LOG_ERR,
		    "nd6_prefix_offlink: failed to delete route: "
		    "%s/%d on %s, scoped %d, (errno = %d)\n",
		    ip6_sprintf(&sa6.sin6_addr), plen, if_name(ifp),
		    (ifscope != IFSCOPE_NONE), error));
	}

	NDPR_LOCK(pr);
	pr->ndpr_stateflags &= ~(NDPRF_ONLINK | NDPRF_IFSCOPE);
	NDPR_UNLOCK(pr);

	return (error);
}

static struct in6_ifaddr *
in6_ifadd(
	struct nd_prefix *pr,
	int mcast)
{
	struct ifnet *ifp = pr->ndpr_ifp;
	struct in6_aliasreq ifra;
	struct in6_ifaddr *ia, *ib;
	int error, plen0;
	int updateflags;
	struct in6_addr mask;
	int prefixlen;

	/*
	 * find a link-local address (will be interface ID).
	 * Is it really mandatory? Theoretically, a global or a site-local
	 * address can be configured without a link-local address, if we
	 * have a unique interface identifier...
	 *
	 * it is not mandatory to have a link-local address, we can generate
	 * interface identifier on the fly.  we do this because:
	 * (1) it should be the easiest way to find interface identifier.
	 * (2) RFC2462 5.4 suggesting the use of the same interface identifier
	 * for multiple addresses on a single interface, and possible shortcut
	 * of DAD.  we omitted DAD for this reason in the past.
	 * (3) a user can prevent autoconfiguration of global address
	 * by removing link-local address by hand (this is partly because we
	 * don't have other way to control the use of IPv6 on an interface.
	 * this has been our design choice - cf. NRL's "ifconfig auto").
	 * (4) it is easier to manage when an interface has addresses
	 * with the same interface identifier, than to have multiple addresses
	 * with different interface identifiers.
	 */
	ib = in6ifa_ifpforlinklocal(ifp, 0);/* 0 is OK? */
	if (ib == NULL)
		return (NULL);

	IFA_LOCK(&ib->ia_ifa);
	NDPR_LOCK(pr);
	prefixlen = pr->ndpr_plen;
	in6_len2mask(&mask, prefixlen);
	plen0 = in6_mask2len(&ib->ia_prefixmask.sin6_addr, NULL);
	/* prefixlen + ifidlen must be equal to 128 */
	if (prefixlen != plen0) {
		nd6log((LOG_INFO, "in6_ifadd: wrong prefixlen for %s "
		    "(prefix=%d ifid=%d)\n",
		    if_name(ifp), prefixlen, 128 - plen0));
		NDPR_UNLOCK(pr);
		IFA_UNLOCK(&ib->ia_ifa);
		IFA_REMREF(&ib->ia_ifa);
		return (NULL);
	}

	/* make ifaddr */

	bzero(&ifra, sizeof(ifra));
	/*
	 * in6_update_ifa() does not use ifra_name, but we accurately set it
	 * for safety.
	 */
	strncpy(ifra.ifra_name, if_name(ifp), sizeof(ifra.ifra_name));
	ifra.ifra_addr.sin6_family = AF_INET6;
	ifra.ifra_addr.sin6_len = sizeof(struct sockaddr_in6);
	/* prefix */
	bcopy(&pr->ndpr_prefix.sin6_addr, &ifra.ifra_addr.sin6_addr,
	      sizeof(ifra.ifra_addr.sin6_addr));
	ifra.ifra_addr.sin6_addr.s6_addr32[0] &= mask.s6_addr32[0];
	ifra.ifra_addr.sin6_addr.s6_addr32[1] &= mask.s6_addr32[1];
	ifra.ifra_addr.sin6_addr.s6_addr32[2] &= mask.s6_addr32[2];
	ifra.ifra_addr.sin6_addr.s6_addr32[3] &= mask.s6_addr32[3];

	/* interface ID */
	ifra.ifra_addr.sin6_addr.s6_addr32[0] |=
	    (ib->ia_addr.sin6_addr.s6_addr32[0] & ~mask.s6_addr32[0]);
	ifra.ifra_addr.sin6_addr.s6_addr32[1] |=
	    (ib->ia_addr.sin6_addr.s6_addr32[1] & ~mask.s6_addr32[1]);
	ifra.ifra_addr.sin6_addr.s6_addr32[2] |=
	    (ib->ia_addr.sin6_addr.s6_addr32[2] & ~mask.s6_addr32[2]);
	ifra.ifra_addr.sin6_addr.s6_addr32[3] |=
	    (ib->ia_addr.sin6_addr.s6_addr32[3] & ~mask.s6_addr32[3]);

	/* new prefix mask. */
	ifra.ifra_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ifra.ifra_prefixmask.sin6_family = AF_INET6;
	bcopy(&mask, &ifra.ifra_prefixmask.sin6_addr,
	      sizeof(ifra.ifra_prefixmask.sin6_addr));

	/* lifetimes. */
	ifra.ifra_lifetime.ia6t_vltime = pr->ndpr_vltime;
	ifra.ifra_lifetime.ia6t_pltime = pr->ndpr_pltime;

	/* XXX: scope zone ID? */

	ifra.ifra_flags |= IN6_IFF_AUTOCONF; /* obey autoconf */

	NDPR_UNLOCK(pr);
	IFA_UNLOCK(&ib->ia_ifa);
	IFA_REMREF(&ib->ia_ifa);

	/*
	 * Make sure that we do not have this address already.  This should
	 * usually not happen, but we can still see this case, e.g., if we
	 * have manually configured the exact address to be configured.
	 */
	if ((ib = in6ifa_ifpwithaddr(ifp, &ifra.ifra_addr.sin6_addr)) != NULL) {
		IFA_REMREF(&ib->ia_ifa);
		/* this should be rare enough to make an explicit log */
		log(LOG_INFO, "in6_ifadd: %s is already configured\n",
		    ip6_sprintf(&ifra.ifra_addr.sin6_addr));
		return (NULL);
	}

	/*
	 * Allocate ifaddr structure, link into chain, etc.
	 * If we are going to create a new address upon receiving a multicasted
	 * RA, we need to impose a random delay before starting DAD.
	 * [draft-ietf-ipv6-rfc2462bis-02.txt, Section 5.4.2]
	 */
	updateflags = 0;
	if (mcast)
		updateflags |= IN6_IFAUPDATE_DADDELAY;
	error = in6_update_ifa(ifp, &ifra, NULL, updateflags, M_WAITOK);
	if (error != 0) {
		nd6log((LOG_ERR,
		    "in6_ifadd: failed to make ifaddr %s on %s (errno=%d)\n",
		    ip6_sprintf(&ifra.ifra_addr.sin6_addr), if_name(ifp),
		    error));
		return(NULL);	/* ifaddr must not have been allocated. */
	}

	ia = in6ifa_ifpwithaddr(ifp, &ifra.ifra_addr.sin6_addr);

	in6_post_msg(ifp, KEV_INET6_NEW_RTADV_ADDR, ia); 

	return(ia);		/* this must NOT be NULL. */
}

#define	IA6_NONCONST(i) ((struct in6_ifaddr *)(uintptr_t)(i))

int
in6_tmpifadd(
	const struct in6_ifaddr *ia0, /* corresponding public address */
	int forcegen,
	int how)
{
	struct ifnet *ifp = ia0->ia_ifa.ifa_ifp;
	struct in6_ifaddr *ia, *newia;
	struct in6_aliasreq ifra;
	int i, error;
	int trylimit = 3;	/* XXX: adhoc value */
	int updateflags;
	u_int32_t randid[2];
	time_t vltime0, pltime0;
	struct timeval timenow;
	struct in6_addr addr;
	struct nd_prefix *ndpr;

	getmicrotime(&timenow);

	bzero(&ifra, sizeof(ifra));
	strncpy(ifra.ifra_name, if_name(ifp), sizeof(ifra.ifra_name));
	IFA_LOCK(&IA6_NONCONST(ia0)->ia_ifa);
	ifra.ifra_addr = ia0->ia_addr;
	/* copy prefix mask */
	ifra.ifra_prefixmask = ia0->ia_prefixmask;
	/* clear the old IFID */
	for (i = 0; i < 4; i++) {
		ifra.ifra_addr.sin6_addr.s6_addr32[i]
			&= ifra.ifra_prefixmask.sin6_addr.s6_addr32[i];
	}
	addr = ia0->ia_addr.sin6_addr;
	IFA_UNLOCK(&IA6_NONCONST(ia0)->ia_ifa);

again:
	in6_get_tmpifid(ifp, (u_int8_t *)randid,
	    (const u_int8_t *)&addr.s6_addr[8], forcegen);

	ifra.ifra_addr.sin6_addr.s6_addr32[2] |=
	    (randid[0] & ~(ifra.ifra_prefixmask.sin6_addr.s6_addr32[2]));
	ifra.ifra_addr.sin6_addr.s6_addr32[3] |=
	    (randid[1] & ~(ifra.ifra_prefixmask.sin6_addr.s6_addr32[3]));

	/*
	 * in6_get_tmpifid() quite likely provided a unique interface ID.
	 * However, we may still have a chance to see collision, because
	 * there may be a time lag between generation of the ID and generation
	 * of the address.  So, we'll do one more sanity check.
	 */
	if ((ia = in6ifa_ifpwithaddr(ifp, &ifra.ifra_addr.sin6_addr)) != NULL) {
		IFA_REMREF(&ia->ia_ifa);
		if (trylimit-- == 0) {
			nd6log((LOG_NOTICE, "in6_tmpifadd: failed to find "
			    "a unique random IFID\n"));
			return(EEXIST);
		}
		forcegen = 1;
		goto again;
	}

	/*
	 * The Valid Lifetime is the lower of the Valid Lifetime of the
         * public address or TEMP_VALID_LIFETIME.
	 * The Preferred Lifetime is the lower of the Preferred Lifetime
         * of the public address or TEMP_PREFERRED_LIFETIME -
         * DESYNC_FACTOR.
	 */
	IFA_LOCK(&IA6_NONCONST(ia0)->ia_ifa);
	vltime0 = IFA6_IS_INVALID(ia0)
	    ? 0
	    : (ia0->ia6_lifetime.ia6t_vltime -
	      (timenow.tv_sec - ia0->ia6_updatetime));
	if (vltime0 > ip6_temp_valid_lifetime)
		vltime0 = ip6_temp_valid_lifetime;
	pltime0 = IFA6_IS_DEPRECATED(ia0)
	    ? 0
	    : (ia0->ia6_lifetime.ia6t_pltime -
	      (timenow.tv_sec - ia0->ia6_updatetime));
	if (pltime0 > ip6_temp_preferred_lifetime - ip6_desync_factor)
		pltime0 = ip6_temp_preferred_lifetime - ip6_desync_factor;
	ifra.ifra_lifetime.ia6t_vltime = vltime0;
	ifra.ifra_lifetime.ia6t_pltime = pltime0;
	IFA_UNLOCK(&IA6_NONCONST(ia0)->ia_ifa);
	/*
	 * A temporary address is created only if this calculated Preferred
	 * Lifetime is greater than REGEN_ADVANCE time units.
	 */
	if (ifra.ifra_lifetime.ia6t_pltime <= ip6_temp_regen_advance)
		return(0);

	/* XXX: scope zone ID? */

	ifra.ifra_flags |= (IN6_IFF_AUTOCONF|IN6_IFF_TEMPORARY);

	/* allocate ifaddr structure, link into chain, etc. */
	updateflags = 0;

	if (how)
		updateflags |= IN6_IFAUPDATE_DADDELAY;

	if ((error = in6_update_ifa(ifp, &ifra, NULL, updateflags, how)) != 0)
		return (error);

	newia = in6ifa_ifpwithaddr(ifp, &ifra.ifra_addr.sin6_addr);
	if (newia == NULL) {	/* XXX: can it happen? */
		nd6log((LOG_ERR,
		    "in6_tmpifadd: ifa update succeeded, but we got "
		    "no ifaddr\n"));
		return(EINVAL); /* XXX */
	}
	IFA_LOCK(&IA6_NONCONST(ia0)->ia_ifa);
	ndpr = ia0->ia6_ndpr;
	if (ndpr == NULL) {
		/*
		 * We lost the race with another thread that has purged
		 * ia0 address; in this case, purge the tmp addr as well.
		 */
		nd6log((LOG_ERR, "in6_tmpifadd: no public address\n"));
		VERIFY(!(ia0->ia6_flags & IN6_IFF_AUTOCONF));
		IFA_UNLOCK(&IA6_NONCONST(ia0)->ia_ifa);
		in6_purgeaddr(&newia->ia_ifa);
		IFA_REMREF(&newia->ia_ifa);
		return (EADDRNOTAVAIL);
	}
	NDPR_ADDREF(ndpr);	/* for us */
	IFA_UNLOCK(&IA6_NONCONST(ia0)->ia_ifa);
	IFA_LOCK(&newia->ia_ifa);
	if (newia->ia6_ndpr != NULL) {
		NDPR_LOCK(newia->ia6_ndpr);
		VERIFY(newia->ia6_ndpr->ndpr_addrcnt != 0);
		newia->ia6_ndpr->ndpr_addrcnt--;
		NDPR_UNLOCK(newia->ia6_ndpr);
		NDPR_REMREF(newia->ia6_ndpr);	/* release addr reference */
	}
	newia->ia6_ndpr = ndpr;
	NDPR_LOCK(newia->ia6_ndpr);
	newia->ia6_ndpr->ndpr_addrcnt++;
	VERIFY(newia->ia6_ndpr->ndpr_addrcnt != 0);
	NDPR_ADDREF_LOCKED(newia->ia6_ndpr);	/* for addr reference */
	NDPR_UNLOCK(newia->ia6_ndpr);
	IFA_UNLOCK(&newia->ia_ifa);
	/*
	 * A newly added address might affect the status of other addresses.
	 * XXX: when the temporary address is generated with a new public
	 * address, the onlink check is redundant.  However, it would be safe
	 * to do the check explicitly everywhere a new address is generated,
	 * and, in fact, we surely need the check when we create a new
	 * temporary address due to deprecation of an old temporary address.
	 */
	lck_mtx_lock(nd6_mutex);
	pfxlist_onlink_check();
	lck_mtx_unlock(nd6_mutex);
	IFA_REMREF(&newia->ia_ifa);

	/* remove our reference */
	NDPR_REMREF(ndpr);

	return(0);
}
#undef IA6_NONCONST

int
in6_init_prefix_ltimes(struct nd_prefix *ndpr)
{
	struct timeval timenow;

	NDPR_LOCK_ASSERT_HELD(ndpr);

	getmicrotime(&timenow);
	/* check if preferred lifetime > valid lifetime.  RFC2462 5.5.3 (c) */
	if (ndpr->ndpr_pltime > ndpr->ndpr_vltime) {
		nd6log((LOG_INFO, "in6_init_prefix_ltimes: preferred lifetime"
		    "(%d) is greater than valid lifetime(%d)\n",
		    (u_int)ndpr->ndpr_pltime, (u_int)ndpr->ndpr_vltime));
		return (EINVAL);
	}
	if (ndpr->ndpr_pltime == ND6_INFINITE_LIFETIME)
		ndpr->ndpr_preferred = 0;
	else
		ndpr->ndpr_preferred = timenow.tv_sec + ndpr->ndpr_pltime;
	if (ndpr->ndpr_vltime == ND6_INFINITE_LIFETIME)
		ndpr->ndpr_expire = 0;
	else
		ndpr->ndpr_expire = timenow.tv_sec + ndpr->ndpr_vltime;

	return 0;
}

static void
in6_init_address_ltimes(__unused struct nd_prefix *new,
    struct in6_addrlifetime *lt6, boolean_t is_temporary)
{
	struct timeval timenow;

	getmicrotime(&timenow);
	/* Valid lifetime must not be updated unless explicitly specified. */
	/* init ia6t_expire */
	if (!is_temporary && lt6->ia6t_vltime == ND6_INFINITE_LIFETIME)
		lt6->ia6t_expire = 0;
	else {
		lt6->ia6t_expire = timenow.tv_sec;
		lt6->ia6t_expire += lt6->ia6t_vltime;
	}

	/* init ia6t_preferred */
	if (!is_temporary && lt6->ia6t_pltime == ND6_INFINITE_LIFETIME)
		lt6->ia6t_preferred = 0;
	else {
		lt6->ia6t_preferred = timenow.tv_sec;
		lt6->ia6t_preferred += lt6->ia6t_pltime;
	}
}

/*
 * Delete all the routing table entries that use the specified gateway.
 * XXX: this function causes search through all entries of routing table, so
 * it shouldn't be called when acting as a router.
 */
void
rt6_flush(
	struct in6_addr *gateway,
	struct ifnet *ifp)
{
	struct radix_node_head *rnh = rt_tables[AF_INET6];

	/* We'll care only link-local addresses */
	if (!IN6_IS_ADDR_LINKLOCAL(gateway)) {
		return;
	}
	lck_mtx_lock(rnh_lock);
	/* XXX: hack for KAME's link-local address kludge */
	gateway->s6_addr16[1] = htons(ifp->if_index);

	rnh->rnh_walktree(rnh, rt6_deleteroute, (void *)gateway);
	lck_mtx_unlock(rnh_lock);
}

static int
rt6_deleteroute(
	struct radix_node *rn,
	void *arg)
{
#define SIN6(s)	((struct sockaddr_in6 *)s)
	struct rtentry *rt = (struct rtentry *)rn;
	struct in6_addr *gate = (struct in6_addr *)arg;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	RT_LOCK(rt);
	if (rt->rt_gateway == NULL || rt->rt_gateway->sa_family != AF_INET6) {
		RT_UNLOCK(rt);
		return(0);
	}

	if (!IN6_ARE_ADDR_EQUAL(gate, &SIN6(rt->rt_gateway)->sin6_addr)) {
		RT_UNLOCK(rt);
		return(0);
	}
	/*
	 * Do not delete a static route.
	 * XXX: this seems to be a bit ad-hoc. Should we consider the
	 * 'cloned' bit instead?
	 */
	if ((rt->rt_flags & RTF_STATIC) != 0) {
		RT_UNLOCK(rt);
		return(0);
	}
	/*
	 * We delete only host route. This means, in particular, we don't
	 * delete default route.
	 */
	if ((rt->rt_flags & RTF_HOST) == 0) {
		RT_UNLOCK(rt);
		return(0);
	}

	/*
	 * Safe to drop rt_lock and use rt_key, rt_gateway, since holding
	 * rnh_lock here prevents another thread from calling rt_setgate()
	 * on this route.
	 */
	RT_UNLOCK(rt);
	return (rtrequest_locked(RTM_DELETE, rt_key(rt), rt->rt_gateway,
	    rt_mask(rt), rt->rt_flags, 0));
#undef SIN6
}

int
nd6_setdefaultiface(
	int ifindex)
{
	int error = 0;
	ifnet_t def_ifp = NULL;
	
	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	ifnet_head_lock_shared();
	if (ifindex < 0 || if_index < ifindex) {
		ifnet_head_done();
		return(EINVAL);
	}
	def_ifp = ifindex2ifnet[ifindex];
	ifnet_head_done();

	lck_mtx_lock(nd6_mutex);
	if (nd6_defifindex != ifindex) {
		struct ifnet *odef_ifp = nd6_defifp;

		nd6_defifindex = ifindex;
		if (nd6_defifindex > 0)
			nd6_defifp = def_ifp;
		else
			nd6_defifp = NULL;

		if (nd6_defifp != NULL)
			nd6log((LOG_INFO, "%s: is now the default "
			    "interface (was %s)\n", if_name(nd6_defifp),
			    odef_ifp != NULL ? if_name(odef_ifp) : "NONE"));
		else
			nd6log((LOG_INFO, "No default interface set\n"));

		/*
		 * If the Default Router List is empty, install a route
		 * to the specified interface as default or remove the default
		 * route when the default interface becomes canceled.
		 * The check for the queue is actually redundant, but
		 * we do this here to avoid re-install the default route
		 * if the list is NOT empty.
		 */
		if (ip6_doscopedroute || TAILQ_FIRST(&nd_defrouter) == NULL) {
			defrtrlist_sync(nd6_defifp);
			nd6_prefix_sync(nd6_defifp);
		}

		/*
		 * Our current implementation assumes one-to-one maping between
		 * interfaces and links, so it would be natural to use the
		 * default interface as the default link.
		 */
		scope6_setdefault(nd6_defifp);
	}
	lck_mtx_unlock(nd6_mutex);

	return(error);
}
