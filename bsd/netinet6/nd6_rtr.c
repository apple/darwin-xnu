/*	$KAME: nd6_rtr.c,v 1.30 2000/03/21 11:37:31 itojun Exp $	*/

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
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3)
#include <sys/ioctl.h>
#endif
#include <sys/syslog.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/radix.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/icmp6.h>

#if MIP6
#include <netinet6/mip6.h>
#endif

#include <net/net_osdep.h>

#define SDL(s)	((struct sockaddr_dl *)s)

static struct nd_defrouter *defrtrlist_update __P((struct nd_defrouter *));
static int prelist_add __P((struct nd_prefix *, struct nd_defrouter *));
/* static struct nd_prefix *prefix_lookup __P((struct nd_prefix *)); XXXYYY */
static struct in6_ifaddr *in6_ifadd __P((struct ifnet *, struct in6_addr *,
			  struct in6_addr *, int));
/*static struct nd_pfxrouter *pfxrtr_lookup __P((struct nd_prefix *,
  struct nd_defrouter *)); XXXYYYY */
static void pfxrtr_add __P((struct nd_prefix *, struct nd_defrouter *));
static void pfxrtr_del __P((struct nd_pfxrouter *));
/*static struct nd_pfxrouter *find_pfxlist_reachable_router __P((struct nd_prefix *));  XXXYYY */
static void nd6_detach_prefix __P((struct nd_prefix *));
static void nd6_attach_prefix __P((struct nd_prefix *));
/* static void defrouter_addifreq __P((struct ifnet *)); XXXYYY */

static void in6_init_address_ltimes __P((struct nd_prefix *ndpr,
					 struct in6_addrlifetime *lt6,
					 int update_vltime));

static int rt6_deleteroute __P((struct radix_node *, void *));

extern int nd6_recalc_reachtm_interval;

struct ifnet *nd6_defifp;
int nd6_defifindex;


#if MIP6
void (*mip6_select_defrtr_hook)(void) = NULL;
struct nd_prefix * (*mip6_get_home_prefix_hook)(void) = NULL;
void (*mip6_prelist_update_hook)(struct nd_prefix *pr,
				 struct nd_defrouter *dr) = NULL;
void (*mip6_probe_pfxrtrs_hook)(void) = NULL;
void (*mip6_store_advint_hook)(struct nd_opt_advint *ai,
			       struct nd_defrouter *dr) = NULL;
int (*mip6_get_md_state_hook)(void) = 0;
void (*mip6_minus_a_case_hook)(struct nd_prefix *) = NULL;
#endif /* MIP6 */

/*
 * Receive Router Solicitation Message - just for routers.
 * Router solicitation/advertisement is mostly managed by userland program
 * (rtadvd) so here we have no function like nd6_ra_output().
 *
 * Based on RFC 2461
 */
void
nd6_rs_input(m, off, icmp6len)
	struct	mbuf *m;
	int off, icmp6len;
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_router_solicit *nd_rs;
	struct in6_addr saddr6 = ip6->ip6_src;
#if 0
	struct in6_addr daddr6 = ip6->ip6_dst;
#endif
	char *lladdr = NULL;
	int lladdrlen = 0;
#if 0
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)NULL;
	struct llinfo_nd6 *ln = (struct llinfo_nd6 *)NULL;
	struct rtentry *rt = NULL;
	int is_newentry;
#endif
	union nd_opts ndopts;

	/* If I'm not a router, ignore it. */
	if (ip6_accept_rtadv != 0 || ip6_forwarding != 1)
		goto freeit;

	/* Sanity checks */
	if (ip6->ip6_hlim != 255) {
		log(LOG_ERR,
		    "nd6_rs_input: invalid hlim %d\n", ip6->ip6_hlim);
		goto freeit;
	}

	/*
	 * Don't update the neighbor cache, if src = ::.
	 * This indicates that the src has no IP address assigned yet.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&saddr6))
		goto freeit;

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len,);
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
		log(LOG_INFO, "nd6_rs_input: invalid ND option, ignored\n");
		goto freeit;
	}

	if (ndopts.nd_opts_src_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_src_lladdr + 1);
		lladdrlen = ndopts.nd_opts_src_lladdr->nd_opt_len << 3;
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		log(LOG_INFO,
		    "nd6_rs_input: lladdrlen mismatch for %s "
		    "(if %d, RS packet %d)\n",
			ip6_sprintf(&saddr6), ifp->if_addrlen, lladdrlen - 2);
	}

	nd6_cache_lladdr(ifp, &saddr6, lladdr, lladdrlen, ND_ROUTER_SOLICIT, 0);

 freeit:
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
nd6_ra_input(m, off, icmp6len)
	struct	mbuf *m;
	int off, icmp6len;
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct nd_ifinfo *ndi = &nd_ifinfo[ifp->if_index];
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_router_advert *nd_ra;
	struct in6_addr saddr6 = ip6->ip6_src;
#if 0
	struct in6_addr daddr6 = ip6->ip6_dst;
	int flags; /* = nd_ra->nd_ra_flags_reserved; */
	int is_managed = ((flags & ND_RA_FLAG_MANAGED) != 0);
	int is_other = ((flags & ND_RA_FLAG_OTHER) != 0);
#endif
	union nd_opts ndopts;
	struct nd_defrouter *dr;

	if (ip6_accept_rtadv == 0)
		goto freeit;

	if (ip6->ip6_hlim != 255) {
		log(LOG_ERR,
		    "nd6_ra_input: invalid hlim %d\n", ip6->ip6_hlim);
		goto freeit;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&saddr6)) {
		log(LOG_ERR,
		    "nd6_ra_input: src %s is not link-local\n",
		    ip6_sprintf(&saddr6));
		goto freeit;
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len,);
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
		log(LOG_INFO, "nd6_ra_input: invalid ND option, ignored\n");
		goto freeit;
	}

    {
	struct nd_defrouter dr0;
	u_int32_t advreachable = nd_ra->nd_ra_reachable;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	dr0.rtaddr = saddr6;
	dr0.flags  = nd_ra->nd_ra_flags_reserved;
	dr0.rtlifetime = ntohs(nd_ra->nd_ra_router_lifetime);
	dr0.expire = time_second + dr0.rtlifetime;
	dr0.ifp = ifp;
	dr0.advint = 0;		/* Mobile IPv6 */
	dr0.advint_expire = 0;	/* Mobile IPv6 */
	dr0.advints_lost = 0;	/* Mobile IPv6 */
	/* unspecified or not? (RFC 2461 6.3.4) */
	if (advreachable) {
		NTOHL(advreachable);
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
	dr = defrtrlist_update(&dr0);
    }

	/*
	 * prefix
	 */
	if (ndopts.nd_opts_pi) {
		struct nd_opt_hdr *pt;
		struct nd_opt_prefix_info *pi;
		struct nd_prefix pr;

		for (pt = (struct nd_opt_hdr *)ndopts.nd_opts_pi;
		     pt <= (struct nd_opt_hdr *)ndopts.nd_opts_pi_end;
		     pt = (struct nd_opt_hdr *)((caddr_t)pt +
						(pt->nd_opt_len << 3))) {
			if (pt->nd_opt_type != ND_OPT_PREFIX_INFORMATION)
				continue;
			pi = (struct nd_opt_prefix_info *)pt;

			if (pi->nd_opt_pi_len != 4) {
				log(LOG_INFO, "nd6_ra_input: invalid option "
					"len %d for prefix information option, "
					"ignored\n", pi->nd_opt_pi_len);
				continue;
			}

			if (128 < pi->nd_opt_pi_prefix_len) {
				log(LOG_INFO, "nd6_ra_input: invalid prefix "
					"len %d for prefix information option, "
					"ignored\n", pi->nd_opt_pi_prefix_len);
				continue;
			}

			if (IN6_IS_ADDR_MULTICAST(&pi->nd_opt_pi_prefix)
			 || IN6_IS_ADDR_LINKLOCAL(&pi->nd_opt_pi_prefix)) {
				log(LOG_INFO, "nd6_ra_input: invalid prefix "
					"%s, ignored\n",
					ip6_sprintf(&pi->nd_opt_pi_prefix));
				continue;
			}

			/* aggregatable unicast address, rfc2374 */
			if ((pi->nd_opt_pi_prefix.s6_addr8[0] & 0xe0) == 0x20
			 && pi->nd_opt_pi_prefix_len != 64) {
				log(LOG_INFO, "nd6_ra_input: invalid prefixlen "
					"%d for rfc2374 prefix %s, ignored\n",
					pi->nd_opt_pi_prefix_len,
					ip6_sprintf(&pi->nd_opt_pi_prefix));
				continue;
			}

			bzero(&pr, sizeof(pr));
			pr.ndpr_prefix.sin6_family = AF_INET6;
			pr.ndpr_prefix.sin6_len = sizeof(pr.ndpr_prefix);
			pr.ndpr_prefix.sin6_addr = pi->nd_opt_pi_prefix;
			pr.ndpr_ifp = (struct ifnet *)m->m_pkthdr.rcvif;

			pr.ndpr_raf_onlink = (pi->nd_opt_pi_flags_reserved &
					      ND_OPT_PI_FLAG_ONLINK) ? 1 : 0;
			pr.ndpr_raf_auto = (pi->nd_opt_pi_flags_reserved &
					    ND_OPT_PI_FLAG_AUTO) ? 1 : 0;
			pr.ndpr_plen = pi->nd_opt_pi_prefix_len;
			pr.ndpr_vltime = ntohl(pi->nd_opt_pi_valid_time);
			pr.ndpr_pltime =
				ntohl(pi->nd_opt_pi_preferred_time);

			if (in6_init_prefix_ltimes(&pr))
				continue; /* prefix lifetime init failed */

			(void)prelist_update(&pr, dr, m);
		}
	}

	/*
	 * MTU
	 */
	if (ndopts.nd_opts_mtu && ndopts.nd_opts_mtu->nd_opt_mtu_len == 1) {
		u_int32_t mtu = ntohl(ndopts.nd_opts_mtu->nd_opt_mtu_mtu);

		/* lower bound */
		if (mtu < IPV6_MMTU) {
			log(LOG_INFO, "nd6_ra_input: bogus mtu option "
			    "mtu=%d sent from %s, ignoring\n",
			    mtu, ip6_sprintf(&ip6->ip6_src));
			goto skip;
		}

		/* upper bound */
		if (ndi->maxmtu) {
			if (mtu <= ndi->maxmtu) {
				int change = (ndi->linkmtu != mtu);

				ndi->linkmtu = mtu;
				if (change) /* in6_maxmtu may change */
					in6_setmaxmtu();
			} else {
				log(LOG_INFO, "nd6_ra_input: bogus mtu "
				    "mtu=%d sent from %s; "
				    "exceeds maxmtu %d, ignoring\n",
				    mtu, ip6_sprintf(&ip6->ip6_src),
				    ndi->maxmtu);
			}
		} else {
			log(LOG_INFO, "nd6_ra_input: mtu option "
			    "mtu=%d sent from %s; maxmtu unknown, "
			    "ignoring\n",
			    mtu, ip6_sprintf(&ip6->ip6_src));
		}
	}

 skip:
	
	/*
	 * Src linkaddress
	 */
    {
	char *lladdr = NULL;
	int lladdrlen = 0;
	
	if (ndopts.nd_opts_src_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_src_lladdr + 1);
		lladdrlen = ndopts.nd_opts_src_lladdr->nd_opt_len << 3;
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		log(LOG_INFO,
		    "nd6_ra_input: lladdrlen mismatch for %s "
		    "(if %d, RA packet %d)\n",
			ip6_sprintf(&saddr6), ifp->if_addrlen, lladdrlen - 2);
	}

	nd6_cache_lladdr(ifp, &saddr6, lladdr, lladdrlen, ND_ROUTER_ADVERT, 0);

	/*
	 * Installing a link-layer address might change the state of the
	 * router's neighbor cache, which might also affect our on-link
	 * detection of adveritsed prefixes.
	 */
	pfxlist_onlink_check();
    }

#if MIP6
	if (mip6_store_advint_hook) {
		if (ndopts.nd_opts_adv)
			(*mip6_store_advint_hook)(ndopts.nd_opts_adv, dr);
	}
#endif

freeit:
	m_freem(m);
}

/*
 * default router list proccessing sub routines
 */
void
defrouter_addreq(new)
	struct nd_defrouter *new;
{
	struct sockaddr_in6 def, mask, gate;
	int s;

	Bzero(&def, sizeof(def));
	Bzero(&mask, sizeof(mask));
	Bzero(&gate, sizeof(gate));

	def.sin6_len = mask.sin6_len = gate.sin6_len
		= sizeof(struct sockaddr_in6);
	def.sin6_family = mask.sin6_family = gate.sin6_family = AF_INET6;
	gate.sin6_addr = new->rtaddr;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	(void)rtrequest(RTM_ADD, (struct sockaddr *)&def,
		(struct sockaddr *)&gate, (struct sockaddr *)&mask,
		RTF_GATEWAY, NULL);
	splx(s);
	return;
}

/* Add a route to a given interface as default */
void
defrouter_addifreq(ifp)
	struct ifnet *ifp;
{
	struct sockaddr_in6 def, mask;
	struct ifaddr *ifa;
	int error, flags;

	bzero(&def, sizeof(def));
	bzero(&mask, sizeof(mask));

	def.sin6_len = mask.sin6_len = sizeof(struct sockaddr_in6);
	def.sin6_family = mask.sin6_family = AF_INET6;

	/*
	 * Search for an ifaddr beloging to the specified interface.
	 * XXX: An IPv6 address are required to be assigned on the interface.
	 */
	if ((ifa = ifaof_ifpforaddr((struct sockaddr *)&def, ifp)) == NULL) {
		log(LOG_ERR,	/* better error? */
		    "defrouter_addifreq: failed to find an ifaddr "
		    "to install a route to interface %s\n",
		    if_name(ifp));
		return;
	}

	flags = ifa->ifa_flags;
	if ((ifp->if_flags & IFF_POINTOPOINT) != 0)
		flags &= ~RTF_CLONING;
	if ((error = rtrequest(RTM_ADD, (struct sockaddr *)&def,
			       ifa->ifa_addr, (struct sockaddr *)&mask,
			       flags, NULL)) != 0) {
		log(LOG_ERR,
		    "defrouter_addifreq: failed to install a route to "
		    "interface %s (errno = %d)\n",
		    if_name(ifp), error);
	}
}

struct nd_defrouter *
defrouter_lookup(addr, ifp)
	struct in6_addr *addr;
	struct ifnet *ifp;
{
	struct nd_defrouter *dr;

	for (dr = TAILQ_FIRST(&nd_defrouter); dr;
	     dr = TAILQ_NEXT(dr, dr_entry)) {
		if (dr->ifp == ifp && IN6_ARE_ADDR_EQUAL(addr, &dr->rtaddr))
			return(dr);
	}

	return(NULL);		/* search failed */
}

void
defrouter_delreq(dr, dofree)
	struct nd_defrouter *dr;
	int dofree;
{
	struct sockaddr_in6 def, mask, gate;

	Bzero(&def, sizeof(def));
	Bzero(&mask, sizeof(mask));
	Bzero(&gate, sizeof(gate));

	def.sin6_len = mask.sin6_len = gate.sin6_len
		= sizeof(struct sockaddr_in6);
	def.sin6_family = mask.sin6_family = gate.sin6_family = AF_INET6;
	gate.sin6_addr = dr->rtaddr;

	rtrequest(RTM_DELETE, (struct sockaddr *)&def,
		  (struct sockaddr *)&gate,
		  (struct sockaddr *)&mask,
		  RTF_GATEWAY, (struct rtentry **)0);

	if (dofree)		/* XXX: necessary? */
		_FREE(dr, M_IP6NDP);
}

void
defrtrlist_del(dr)
	struct nd_defrouter *dr;
{
	struct nd_defrouter *deldr = NULL;
	struct nd_prefix *pr;

	/*
	 * Flush all the routing table entries that use the router
	 * as a next hop.
	 */
	if (!ip6_forwarding && ip6_accept_rtadv) {
		/* above is a good condition? */
		rt6_flush(&dr->rtaddr, dr->ifp);
	}

	if (dr == TAILQ_FIRST(&nd_defrouter))
		deldr = dr;	/* The router is primary. */

	TAILQ_REMOVE(&nd_defrouter, dr, dr_entry);

	/*
	 * Also delete all the pointers to the router in each prefix lists.
	 */
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		struct nd_pfxrouter *pfxrtr;
		if ((pfxrtr = pfxrtr_lookup(pr, dr)) != NULL)
			pfxrtr_del(pfxrtr);
	}
	pfxlist_onlink_check();

	/*
	 * If the router is the primary one, choose a new one.
	 * Note that defrouter_select() will remove the current gateway
	 * from the routing table.
	 */
	if (deldr)
		defrouter_select();

	_FREE(dr, M_IP6NDP);
}

/*
 * Default Router Selection according to Section 6.3.6 of RFC 2461:
 * 1) Routers that are reachable or probably reachable should be
 *    preferred.
 * 2) When no routers on the list are known to be reachable or
 *    probably reachable, routers SHOULD be selected in a round-robin
 *    fashion.
 * 3) If the Default Router List is empty, assume that all
 *    destinations are on-link.
 */
void
defrouter_select()
{
#ifdef __NetBSD__
	int s = splsoftnet();
#else
	int s = splnet();
#endif
	struct nd_defrouter *dr, anydr;
	struct rtentry *rt = NULL;
	struct llinfo_nd6 *ln = NULL;

#if MIP6
	/* Mobile IPv6 alternative routine */
	if (mip6_select_defrtr_hook) {
		(*mip6_select_defrtr_hook)();    /* XXXYYY Temporary? */
		splx(s);
		return;
	}
	/* End of Mobile IPv6 */
#endif /* MIP6 */

	/*
	 * Search for a (probably) reachable router from the list.
	 */
	for (dr = TAILQ_FIRST(&nd_defrouter); dr;
	     dr = TAILQ_NEXT(dr, dr_entry)) {
		if ((rt = nd6_lookup(&dr->rtaddr, 0, dr->ifp)) &&
		    (ln = (struct llinfo_nd6 *)rt->rt_llinfo) &&
		    ND6_IS_LLINFO_PROBREACH(ln)) {
			/* Got it, and move it to the head */
			TAILQ_REMOVE(&nd_defrouter, dr, dr_entry);
			TAILQ_INSERT_HEAD(&nd_defrouter, dr, dr_entry);
			break;
		}
	}

	if ((dr = TAILQ_FIRST(&nd_defrouter))) {
		/*
		 * De-install the previous default gateway and install
		 * a new one.
		 * Note that if there is no reachable router in the list,
		 * the head entry will be used anyway.
		 * XXX: do we have to check the current routing table entry?
		 */
		bzero(&anydr, sizeof(anydr));
		defrouter_delreq(&anydr, 0);
		defrouter_addreq(dr);
	}
	else {
		/*
		 * The Default Router List is empty, so install the default
		 * route to an inteface.
		 * XXX: The specification does not say this mechanism should
		 * be restricted to hosts, but this would be not useful
		 * (even harmful) for routers.
		 */
		if (!ip6_forwarding) {
			/*
			 * De-install the current default route
			 * in advance.
			 */
			bzero(&anydr, sizeof(anydr));
			defrouter_delreq(&anydr, 0);
			if (nd6_defifp) {
				/*
				 * Install a route to the default interface
				 * as default route.
				 */
				defrouter_addifreq(nd6_defifp);
			}
#if ND6_DEBUG
			else	/* noisy log? */
				log(LOG_INFO, "defrouter_select: "
				    "there's no default router and no default"
				    " interface\n");
#endif
		}
	}

	splx(s);
	return;
}

static struct nd_defrouter *
defrtrlist_update(new)
	struct nd_defrouter *new;
{
	struct nd_defrouter *dr, *n;
#ifdef __NetBSD__
	int s = splsoftnet();
#else
	int s = splnet();
#endif

	if ((dr = defrouter_lookup(&new->rtaddr, new->ifp)) != NULL) {
		/* entry exists */
		if (new->rtlifetime == 0) {
			defrtrlist_del(dr);
			dr = NULL;
		} else {
			/* override */
			dr->flags = new->flags; /* xxx flag check */
			dr->rtlifetime = new->rtlifetime;
			dr->expire = new->expire;
		}
		splx(s);
		return(dr);
	}

	/* entry does not exist */
	if (new->rtlifetime == 0) {
		splx(s);
		return(NULL);
	}

	n = (struct nd_defrouter *)_MALLOC(sizeof(*n), M_IP6NDP, M_NOWAIT);
	if (n == NULL) {
		splx(s);
		return(NULL);
	}
	bzero(n, sizeof(*n));
	*n = *new;

	/*
	 * Insert the new router at the end of the Default Router List.
	 * If there is no other router, install it anyway. Otherwise,
	 * just continue to use the current default router.
	 */
	TAILQ_INSERT_TAIL(&nd_defrouter, n, dr_entry);
	if (TAILQ_FIRST(&nd_defrouter) == n)
		defrouter_select();
	splx(s);
		
	return(n);
}

struct nd_pfxrouter *
pfxrtr_lookup(pr, dr)
	struct nd_prefix *pr;
	struct nd_defrouter *dr;
{
	struct nd_pfxrouter *search;
	
	for (search = pr->ndpr_advrtrs.lh_first; search; search = search->pfr_next) {
		if (search->router == dr)
			break;
	}

	return(search);
}

static void
pfxrtr_add(pr, dr)
	struct nd_prefix *pr;
	struct nd_defrouter *dr;
{
	struct nd_pfxrouter *new;

	new = (struct nd_pfxrouter *)_MALLOC(sizeof(*new), M_IP6NDP, M_NOWAIT);
	if (new == NULL)
		return;
	bzero(new, sizeof(*new));
	new->router = dr;

	LIST_INSERT_HEAD(&pr->ndpr_advrtrs, new, pfr_entry);

	pfxlist_onlink_check();
}

static void
pfxrtr_del(pfr)
	struct nd_pfxrouter *pfr;
{
	LIST_REMOVE(pfr, pfr_entry);
	_FREE(pfr, M_IP6NDP);
}

struct nd_prefix *
prefix_lookup(pr)
	struct nd_prefix *pr;
{
	struct nd_prefix *search;

	for (search = nd_prefix.lh_first; search; search = search->ndpr_next) {
		if (pr->ndpr_ifp == search->ndpr_ifp &&
		    pr->ndpr_plen == search->ndpr_plen &&
		    in6_are_prefix_equal(&pr->ndpr_prefix.sin6_addr,
					 &search->ndpr_prefix.sin6_addr,
					 pr->ndpr_plen)
		    ) {
			break;
		}
	}

	return(search);
}

static int
prelist_add(pr, dr)
	struct nd_prefix *pr;
	struct nd_defrouter *dr;
{
	struct nd_prefix *new;
	int i, s;

	new = (struct nd_prefix *)_MALLOC(sizeof(*new), M_IP6NDP, M_NOWAIT);
	if (new == NULL)
		return ENOMEM;
	bzero(new, sizeof(*new));
	*new = *pr;

	/* initilization */
	new->ndpr_statef_onlink = pr->ndpr_statef_onlink;
	LIST_INIT(&new->ndpr_advrtrs);
	in6_prefixlen2mask(&new->ndpr_mask, new->ndpr_plen);
	/* make prefix in the canonical form */
	for (i = 0; i < 4; i++)
		new->ndpr_prefix.sin6_addr.s6_addr32[i] &=
			new->ndpr_mask.s6_addr32[i];

	/* xxx ND_OPT_PI_FLAG_ONLINK processing */

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	/* link ndpr_entry to nd_prefix list */
	LIST_INSERT_HEAD(&nd_prefix, new, ndpr_entry);
	splx(s);

	if (dr) {
		pfxrtr_add(new, dr);
#if MIP6
		if (mip6_get_md_state_hook) {
			/*
			 * If we are in UNDEFINED state and a router appears,
			 * select that router and change state.
			 * This case takes care of transitions from UNDEFINED
			 * to FOREIGN when the prefix is not known from before.
			 */
			if ((*mip6_get_md_state_hook)() == MIP6_MD_UNDEFINED) {
				if (mip6_select_defrtr_hook)
					(*mip6_select_defrtr_hook)();
			}
		}
#endif /* MIP6 */
	}

	return 0;
}

void
prelist_remove(pr)
	struct nd_prefix *pr;
{
	struct nd_pfxrouter *pfr, *next;
	int s;

#ifdef __NetBSD__
	s = splsoftnet();
#else
	s = splnet();
#endif
	/* unlink ndpr_entry from nd_prefix list */
	LIST_REMOVE(pr, ndpr_entry);
	splx(s);

	/* free list of routers that adversed the prefix */
	for (pfr = pr->ndpr_advrtrs.lh_first; pfr; pfr = next) {
		next = pfr->pfr_next;

		_FREE(pfr, M_IP6NDP);
	}
	_FREE(pr, M_IP6NDP);

	pfxlist_onlink_check();
}

/*
 * NOTE: We set address lifetime to keep
 *	address lifetime <= prefix lifetime
 * invariant.  This is to simplify on-link determination code.
 * If onlink determination is udated, this routine may have to be updated too.
 */
int
prelist_update(new, dr, m)
	struct nd_prefix *new;
	struct nd_defrouter *dr; /* may be NULL */
	struct mbuf *m;
{
	struct in6_ifaddr *ia6 = NULL;
	struct nd_prefix *pr;
#ifdef __NetBSD__
	int s = splsoftnet();
#else
	int s = splnet();
#endif
	int error = 0;
	int auth;
	struct in6_addrlifetime *lt6;
	u_char onlink;	/* Mobile IPv6 */

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

	if ((pr = prefix_lookup(new)) != NULL) {
		if (pr->ndpr_ifp != new->ndpr_ifp) {
			error = EADDRNOTAVAIL;
			goto end;
		}

#if MIP6
		if (mip6_get_home_prefix_hook) {
			/*
			 * The home prefix should be kept away from updates.
			 * XXXYYY Tunneled RA? New Home Prefix? Unless
			 * configured, the code below will be executed.
			 */
			if (pr == (*mip6_get_home_prefix_hook)())
				goto noautoconf1;
		}
#endif /* MIP6 */

		/* update prefix information */
		pr->ndpr_flags = new->ndpr_flags;
		pr->ndpr_vltime = new->ndpr_vltime;
		pr->ndpr_pltime = new->ndpr_pltime;
		pr->ndpr_preferred = new->ndpr_preferred;
		pr->ndpr_expire = new->ndpr_expire;

		/*
		 * RFC 2462 5.5.3 (d) or (e)
		 * We got a prefix which we have seen in the past.
		 */
		if (!new->ndpr_raf_auto)
			goto noautoconf1;

		if (IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr))
			ia6 = NULL;
		else
			ia6 = in6ifa_ifpwithaddr(pr->ndpr_ifp, &pr->ndpr_addr);

		if (ia6 == NULL) {
			/*
			 * Special case:
			 * (1) We have seen the prefix advertised before, but
			 * we have never performed autoconfig for this prefix.
			 * This is because Autonomous bit was 0 previously, or
			 * autoconfig failed due to some other reasons.
			 * (2) We have seen the prefix advertised before and
			 * we have performed autoconfig in the past, but
			 * we seem to have no interface address right now.
			 * This is because the interface address have expired.
			 *
			 * This prefix is fresh, with respect to autoconfig
			 * process.
			 *
			 * Add an address based on RFC 2462 5.5.3 (d).
			 */
			ia6 = in6_ifadd(pr->ndpr_ifp,
				&pr->ndpr_prefix.sin6_addr, &pr->ndpr_addr,
				new->ndpr_plen);
			if (!ia6) {
				error = EADDRNOTAVAIL;
				log(LOG_ERR, "prelist_update: failed to add a "
				    "new address\n");
				goto noautoconf1;
			}

			lt6 = &ia6->ia6_lifetime;

			/* address lifetime <= prefix lifetime */
			lt6->ia6t_vltime = new->ndpr_vltime;
			lt6->ia6t_pltime = new->ndpr_pltime;
			in6_init_address_ltimes(new, lt6, 1);
		} else {
#define TWOHOUR		(120*60)
			/*
			 * We have seen the prefix before, and we have added
			 * interface address in the past.  We still have
			 * the interface address assigned.
			 *
			 * update address lifetime based on RFC 2462
			 * 5.5.3 (e).
			 */
			int update = 0;

			lt6 = &ia6->ia6_lifetime;

#if 0	/* RFC 2462 5.5.3 (e) */
			lt6->ia6t_pltime = new->ndpr_pltime;
			if (TWOHOUR < new->ndpr_vltime
			 || lt6pr->nd < new->ndpr_vltime) {
				lt6->ia6t_vltime = new->ndpr_vltime;
				update++;
			} else if (auth
				&& lt6->ia6t_vltime <= TWOHOUR0
				&& new->ndpr_vltime <= lt6->ia6t_vltime) {
				lt6->ia6t_vltime = new->ndpr_vltime;
				update++;
			} else {
				lt6->ia6t_vltime = TWOHOUR;
				update++;
			}

			/* 2 hour rule is not imposed for pref lifetime */
			new->ndpr_apltime = new->ndpr_pltime;
			lt6->ia6t_pltime = new->ndpr_pltime;
#else	/* update from Jim Bound, (ipng 6712) */
			if (TWOHOUR < new->ndpr_vltime
			 || lt6->ia6t_vltime < new->ndpr_vltime) {
				lt6->ia6t_vltime = new->ndpr_vltime;
				update++;
			} else if (auth) {
				lt6->ia6t_vltime = new->ndpr_vltime;
				update++;
			}

			/* jim bound rule is not imposed for pref lifetime */
			lt6->ia6t_pltime = new->ndpr_pltime;
#endif
			in6_init_address_ltimes(new, lt6, update);
		}

 noautoconf1:

#if 0
		/* address lifetime expire processing, RFC 2462 5.5.4. */
		if (pr->ndpr_preferred && pr->ndpr_preferred < time_second) {
			struct in6_ifaddr *ia6;

			ia6 = in6ifa_ifpwithaddr(pr->ndpr_ifp, &pr->ndpr_addr);
			if (ia6)
				ia6->ia6_flags &= ~IN6_IFF_DEPRECATED;
		}
#endif

		onlink = pr->ndpr_statef_onlink;     /* Mobile IPv6 */

		if (dr && pfxrtr_lookup(pr, dr) == NULL)
			pfxrtr_add(pr, dr);

#if MIP6
		if (mip6_prelist_update_hook) {
			/*
			 * Check for home prefix. It can't be a fresh prefix
			 * (since it's static), so check here.
			 */
			(*mip6_prelist_update_hook)(pr, dr);
		}

		if (mip6_probe_pfxrtrs_hook) {
			/*
			 * If this prefix previously was detached, maybe we
			 * have moved.
			 */
			if (!onlink)
				(*mip6_probe_pfxrtrs_hook)();
		}
#endif /* MIP6 */

	} else {
		int error_tmp;

		if (new->ndpr_vltime == 0) goto end;

		bzero(&new->ndpr_addr, sizeof(struct in6_addr));

		/*
		 * RFC 2462 5.5.3 (d)
		 * We got a fresh prefix.  Perform some sanity checks
		 * and add an interface address by appending interface ID
		 * to the advertised prefix.
		 */
		if (!new->ndpr_raf_auto)
			goto noautoconf2;

		ia6 = in6_ifadd(new->ndpr_ifp, &new->ndpr_prefix.sin6_addr,
			  &new->ndpr_addr, new->ndpr_plen);
		if (!ia6) {
			error = EADDRNOTAVAIL;
			log(LOG_ERR, "prelist_update: "
				"failed to add a new address\n");
			goto noautoconf2;
		}
		/* set onlink bit if an interface route is configured */
		new->ndpr_statef_onlink = (ia6->ia_flags & IFA_ROUTE) ? 1 : 0;

		lt6 = &ia6->ia6_lifetime;

		/* address lifetime <= prefix lifetime */
		lt6->ia6t_vltime = new->ndpr_vltime;
		lt6->ia6t_pltime = new->ndpr_pltime;
		in6_init_address_ltimes(new, lt6, 1);

 noautoconf2:
		error_tmp = prelist_add(new, dr);
		error = error_tmp ? error_tmp : error;

#if MIP6
		if (mip6_probe_pfxrtrs_hook) {
			/* This is a new prefix, maybe we have moved. */
			(*mip6_probe_pfxrtrs_hook)();
		}

		if (mip6_minus_a_case_hook) {
			/*
			 * If we are still looking for an autoconfigured home
			 * address when we are in "minus a" case, here's a new
			 * prefix and hopefully we can use the address derived
			 *from that.
			 */
			if (ia6)
				(*mip6_minus_a_case_hook)(new);
		}
#endif /* MIP6 */

	}

 end:
	splx(s);
	return error;
}

/*
 * A supplement function used in the on-link detection below;
 * detect if a given prefix has a (probably) reachable advertising router.
 * XXX: lengthy function name...
 */
struct nd_pfxrouter *
find_pfxlist_reachable_router(pr)
	struct nd_prefix *pr;
{
	struct nd_pfxrouter *pfxrtr;
	struct rtentry *rt;
	struct llinfo_nd6 *ln;

	for (pfxrtr = LIST_FIRST(&pr->ndpr_advrtrs); pfxrtr;
	     pfxrtr = LIST_NEXT(pfxrtr, pfr_entry)) {
		if ((rt = nd6_lookup(&pfxrtr->router->rtaddr, 0,
				     pfxrtr->router->ifp)) &&
		    (ln = (struct llinfo_nd6 *)rt->rt_llinfo) &&
		    ND6_IS_LLINFO_PROBREACH(ln))
			break;	/* found */
	}

	return(pfxrtr);

}

/*
 * Check if each prefix in the prefix list has at least one available router
 * that advertised the prefix (A router is "available" if its neighbor cache
 * entry has reachable or probably reachable).
 * If the check fails, the prefix may be off-link, because, for example,
 * we have moved from the network but the lifetime of the prefix has not
 * been expired yet. So we should not use the prefix if there is another
 * prefix that has an available router.
 * But if there is no prefix that has an available router, we still regards
 * all the prefixes as on-link. This is because we can't tell if all the
 * routers are simply dead or if we really moved from the network and there
 * is no router around us.
 */
void
pfxlist_onlink_check()
{
	struct nd_prefix *pr;

	/*
	 * Check if there is a prefix that has a reachable advertising
	 * router.
	 */
	for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
		if (find_pfxlist_reachable_router(pr))
			break;
	}

	if (pr) {
		/*
		 * There is at least one prefix that has a reachable router.
		 * First, detach prefixes which has no reachable advertising
		 * router and then attach other prefixes.
		 * The order is important since an attached prefix and a
		 * detached prefix may have a same interface route.
		 */
		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			if (find_pfxlist_reachable_router(pr) == NULL &&
			    pr->ndpr_statef_onlink) {
				pr->ndpr_statef_onlink = 0;
				nd6_detach_prefix(pr);
			}
		}
		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next) {
			if (find_pfxlist_reachable_router(pr) &&
			    pr->ndpr_statef_onlink == 0)
				nd6_attach_prefix(pr);
		}
	}
	else {
		/* there is no prefix that has a reachable router */
		for (pr = nd_prefix.lh_first; pr; pr = pr->ndpr_next)
			if (pr->ndpr_statef_onlink == 0)
				nd6_attach_prefix(pr);
	}
}

static void
nd6_detach_prefix(pr)
	struct nd_prefix *pr;
{
	struct in6_ifaddr *ia6;
	struct sockaddr_in6 sa6, mask6;

	/*
	 * Delete the interface route associated with the prefix.
	 */
	bzero(&sa6, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	sa6.sin6_len = sizeof(sa6);
	bcopy(&pr->ndpr_prefix.sin6_addr, &sa6.sin6_addr,
	      sizeof(struct in6_addr));
	bzero(&mask6, sizeof(mask6));
	mask6.sin6_family = AF_INET6;
	mask6.sin6_len = sizeof(sa6);
	bcopy(&pr->ndpr_mask, &mask6.sin6_addr, sizeof(struct in6_addr));
	{
		int e;

		e = rtrequest(RTM_DELETE, (struct sockaddr *)&sa6, NULL,
			      (struct sockaddr *)&mask6, 0, NULL);
		if (e) {
			log(LOG_ERR,
			    "nd6_detach_prefix: failed to delete route: "
			    "%s/%d (errno = %d)\n",
			    ip6_sprintf(&sa6.sin6_addr),
			    pr->ndpr_plen,
			    e);
		}
	}

	/*
	 * Mark the address derived from the prefix detached so that
	 * it won't be used as a source address for a new connection.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr))
		ia6 = NULL;
	else
		ia6 = in6ifa_ifpwithaddr(pr->ndpr_ifp, &pr->ndpr_addr);
	if (ia6)
#if MIP6
		if (mip6_get_home_prefix_hook)
			if (pr != (*mip6_get_home_prefix_hook)())
				ia6->ia6_flags |= IN6_IFF_DETACHED;
#else
		ia6->ia6_flags |= IN6_IFF_DETACHED;
#endif
}

static void
nd6_attach_prefix(pr)
	struct nd_prefix *pr;
{
	struct ifaddr *ifa;
	struct in6_ifaddr *ia6;

	/*
	 * Add the interface route associated with the prefix(if necessary)
	 * Should we consider if the L bit is set in pr->ndpr_flags?
	 */
	ifa = ifaof_ifpforaddr((struct sockaddr *)&pr->ndpr_prefix,
			       pr->ndpr_ifp);
	if (ifa == NULL) {
		log(LOG_ERR,
		    "nd6_attach_prefix: failed to find any ifaddr"
		    " to add route for a prefix(%s/%d)\n",
		    ip6_sprintf(&pr->ndpr_addr), pr->ndpr_plen);
	}
	else {
		int e;
		struct sockaddr_in6 mask6;

		bzero(&mask6, sizeof(mask6));
		mask6.sin6_family = AF_INET6;
		mask6.sin6_len = sizeof(mask6);
		mask6.sin6_addr = pr->ndpr_mask;
		e = rtrequest(RTM_ADD, (struct sockaddr *)&pr->ndpr_prefix,
			      ifa->ifa_addr, (struct sockaddr *)&mask6,
			      ifa->ifa_flags, NULL);
		if (e == 0)
			pr->ndpr_statef_onlink = 1;
		else {
			log(LOG_ERR,
			    "nd6_attach_prefix: failed to add route for"
			    " a prefix(%s/%d), errno = %d\n",
			    ip6_sprintf(&pr->ndpr_addr), pr->ndpr_plen, e);
		}
	}

	/*
	 * Now the address derived from the prefix can be used as a source
	 * for a new connection, so clear the detached flag.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr))
		ia6 = NULL;
	else
		ia6 = in6ifa_ifpwithaddr(pr->ndpr_ifp, &pr->ndpr_addr);
	if (ia6) {
		ia6->ia6_flags &= ~IN6_IFF_DETACHED;
		if (pr->ndpr_statef_onlink)
			ia6->ia_flags |= IFA_ROUTE;
	}
}

static struct in6_ifaddr *
in6_ifadd(ifp, in6, addr, prefixlen)
	struct ifnet *ifp;
	struct in6_addr *in6;
	struct in6_addr *addr;
	int prefixlen;	/* prefix len of the new prefix in "in6" */
{
	struct ifaddr *ifa;
	struct in6_ifaddr *ia, *ib, *oia;
	int s, error;
	struct in6_addr mask;

	in6_len2mask(&mask, prefixlen);

	/* find link-local address (will be interface ID) */
	ifa = (struct ifaddr *)in6ifa_ifpforlinklocal(ifp, 0);/* 0 is OK? */
	if (ifa)
		ib = (struct in6_ifaddr *)ifa;
	else
		return NULL;

#if 0 /* don't care link local addr state, and always do DAD */
	/* if link-local address is not eligible, do not autoconfigure. */
	if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_NOTREADY) {
		printf("in6_ifadd: link-local address not ready\n");
		return NULL;
	}
#endif

	/* prefixlen + ifidlen must be equal to 128 */
	if (prefixlen != in6_mask2len(&ib->ia_prefixmask.sin6_addr)) {
		log(LOG_ERR, "in6_ifadd: wrong prefixlen for %s"
			"(prefix=%d ifid=%d)\n", if_name(ifp),
			prefixlen,
			128 - in6_mask2len(&ib->ia_prefixmask.sin6_addr));
		return NULL;
	}

	/* make ifaddr */
	ia = (struct in6_ifaddr *)_MALLOC(sizeof(*ia), M_IFADDR, M_DONTWAIT);
	if (ia == NULL) {
		printf("ENOBUFS in in6_ifadd %d\n", __LINE__);
		return NULL;
	}

	bzero((caddr_t)ia, sizeof(*ia));
	ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	if (ifp->if_flags & IFF_POINTOPOINT)
		ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
	else
		ia->ia_ifa.ifa_dstaddr = NULL;
	ia->ia_ifa.ifa_netmask = (struct sockaddr *)&ia->ia_prefixmask;
	ia->ia_ifp = ifp;

	/* link to in6_ifaddr */
	if ((oia = in6_ifaddr) != NULL) {
		for( ; oia->ia_next; oia = oia->ia_next)
			continue;
		oia->ia_next = ia;
	} else
		in6_ifaddr = ia;
	ia->ia_ifa.ifa_refcnt++;

	/* link to if_addrlist */
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	if ((ifa = ifp->if_addrlist) != NULL) {
		for ( ; ifa->ifa_next; ifa = ifa->ifa_next)
			continue;
		ifa->ifa_next = (struct ifaddr *)ia;
	}
#else
	if (ifp->if_addrlist.tqh_first != NULL) {
		TAILQ_INSERT_TAIL(&ifp->if_addrlist, (struct ifaddr *)ia,
			ifa_list);
		ia->ia_ifa.ifa_refcnt++;
	}
#endif
#if 0
	else {
		/*
		 * this should not be the case because there is at least one
		 * link-local address(see the beginning of the function).
		 */
		TAILQ_INIT(&ifp->if_addrlist);
	}
#endif

	/* new address */
	ia->ia_addr.sin6_len = sizeof(struct sockaddr_in6);
	ia->ia_addr.sin6_family = AF_INET6;
	/* prefix */
	bcopy(in6, &ia->ia_addr.sin6_addr, sizeof(ia->ia_addr.sin6_addr));
	ia->ia_addr.sin6_addr.s6_addr32[0] &= mask.s6_addr32[0];
	ia->ia_addr.sin6_addr.s6_addr32[1] &= mask.s6_addr32[1];
	ia->ia_addr.sin6_addr.s6_addr32[2] &= mask.s6_addr32[2];
	ia->ia_addr.sin6_addr.s6_addr32[3] &= mask.s6_addr32[3];
	/* interface ID */
	ia->ia_addr.sin6_addr.s6_addr32[0]
		|= (ib->ia_addr.sin6_addr.s6_addr32[0] & ~mask.s6_addr32[0]);
	ia->ia_addr.sin6_addr.s6_addr32[1]
		|= (ib->ia_addr.sin6_addr.s6_addr32[1] & ~mask.s6_addr32[1]);
	ia->ia_addr.sin6_addr.s6_addr32[2]
		|= (ib->ia_addr.sin6_addr.s6_addr32[2] & ~mask.s6_addr32[2]);
	ia->ia_addr.sin6_addr.s6_addr32[3]
		|= (ib->ia_addr.sin6_addr.s6_addr32[3] & ~mask.s6_addr32[3]);

	/* new prefix */
	ia->ia_prefixmask.sin6_len = sizeof(struct sockaddr_in6);
	ia->ia_prefixmask.sin6_family = AF_INET6;
	bcopy(&mask, &ia->ia_prefixmask.sin6_addr,
		sizeof(ia->ia_prefixmask.sin6_addr));

	/* same routine */
	ia->ia_ifa.ifa_rtrequest =
		(ifp->if_type == IFT_PPP) ? nd6_p2p_rtrequest : nd6_rtrequest;
	ia->ia_ifa.ifa_flags |= RTF_CLONING;
	ia->ia_ifa.ifa_metric = ifp->if_metric;

	/* add interface route */
	if ((error = rtinit(&(ia->ia_ifa), (int)RTM_ADD, RTF_UP|RTF_CLONING))) {
		log(LOG_NOTICE, "in6_ifadd: failed to add an interface route "
		    "for %s/%d on %s, errno = %d\n",
		    ip6_sprintf(&ia->ia_addr.sin6_addr), prefixlen,
		    if_name(ifp), error);
	}
	else
		ia->ia_flags |= IFA_ROUTE;

	*addr = ia->ia_addr.sin6_addr;

	if (ifp->if_flags & IFF_MULTICAST) {
		int error;	/* not used */
		struct in6_addr sol6;

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined (__APPLE__)
		/* Restore saved multicast addresses(if any). */
		in6_restoremkludge(ia, ifp);
#endif

		/* join solicited node multicast address */
		bzero(&sol6, sizeof(sol6));
		sol6.s6_addr16[0] = htons(0xff02);
		sol6.s6_addr16[1] = htons(ifp->if_index);
		sol6.s6_addr32[1] = 0;
		sol6.s6_addr32[2] = htonl(1);
		sol6.s6_addr32[3] = ia->ia_addr.sin6_addr.s6_addr32[3];
		sol6.s6_addr8[12] = 0xff;
		(void)in6_addmulti(&sol6, ifp, &error);
	}

	ia->ia6_flags |= IN6_IFF_TENTATIVE;

	/*
	 * To make the interface up. Only AF_INET6 in ia is used...
	 */
	s = splimp();
	error = dlil_ioctl(PF_INET6, ifp, SIOCSIFADDR, (caddr_t)ia);
	if (error == EOPNOTSUPP)
		error = 0;
	if (error) {

		splx(s);
		return NULL;
	}
	splx(s);

	/* Perform DAD, if needed. */
	nd6_dad_start((struct ifaddr *)ia, NULL);

	return ia;
}

int
in6_ifdel(ifp, in6)
	struct ifnet *ifp;
	struct in6_addr *in6;
{
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	struct ifaddr *ifa;
#endif
	struct in6_ifaddr *ia = (struct in6_ifaddr *)NULL;
	struct in6_ifaddr *oia = (struct in6_ifaddr *)NULL;

	if (!ifp)
		return -1;

	ia = in6ifa_ifpwithaddr(ifp, in6);
	if (!ia)
		return -1;

	if (ifp->if_flags & IFF_MULTICAST) {
		/*
		 * delete solicited multicast addr for deleting host id
		 */
		struct in6_multi *in6m;
		struct in6_addr llsol;
		bzero(&llsol, sizeof(struct in6_addr));
		llsol.s6_addr16[0] = htons(0xff02);
		llsol.s6_addr16[1] = htons(ifp->if_index);
		llsol.s6_addr32[1] = 0;
		llsol.s6_addr32[2] = htonl(1);
		llsol.s6_addr32[3] =
				ia->ia_addr.sin6_addr.s6_addr32[3];
		llsol.s6_addr8[12] = 0xff;

		IN6_LOOKUP_MULTI(llsol, ifp, in6m);
		if (in6m)
			in6_delmulti(in6m);
	}

	if (ia->ia_flags & IFA_ROUTE) {
		rtinit(&(ia->ia_ifa), (int)RTM_DELETE, 0);
		ia->ia_flags &= ~IFA_ROUTE;
	}

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	if ((ifa = ifp->if_addrlist) == (struct ifaddr *)ia) {
		ifp->if_addrlist = ifa->ifa_next;
	} else {
		while (ifa->ifa_next &&
		      (ifa->ifa_next != (struct ifaddr *)ia))
			ifa = ifa->ifa_next;
		if (ifa->ifa_next)
			ifa->ifa_next = ((struct ifaddr *)ia)->ifa_next;
		else
			return -1;
	}
#else
	TAILQ_REMOVE(&ifp->if_addrlist, (struct ifaddr *)ia, ifa_list);
#endif
	IFAFREE(&ia->ia_ifa);

	/* lladdr is never deleted */
	oia = ia;
	if (oia == (ia = in6_ifaddr))
		in6_ifaddr = ia->ia_next;
	else {
		while (ia->ia_next && (ia->ia_next != oia))
			ia = ia->ia_next;
		if (ia->ia_next)
			ia->ia_next = oia->ia_next;
		else
			return -1;
	}

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined (__APPLE__)
	in6_savemkludge(oia);
#endif
	IFAFREE((&oia->ia_ifa));
/* xxx
	rtrequest(RTM_DELETE,
		  (struct sockaddr *)&ia->ia_addr,
		  (struct sockaddr *)0
		  (struct sockaddr *)&ia->ia_prefixmask,
		  RTF_UP|RTF_CLONING,
		  (struct rtentry **)0);
*/
	return 0;
}

int
in6_init_prefix_ltimes(struct nd_prefix *ndpr)
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	/* check if preferred lifetime > valid lifetime */
	if (ndpr->ndpr_pltime > ndpr->ndpr_vltime) {
		log(LOG_INFO, "in6_init_prefix_ltimes: preferred lifetime"
		    "(%d) is greater than valid lifetime(%d)\n",
		    (u_int)ndpr->ndpr_pltime, (u_int)ndpr->ndpr_vltime);
		return (EINVAL);
	}
	if (ndpr->ndpr_pltime == ND6_INFINITE_LIFETIME)
		ndpr->ndpr_preferred = 0;
	else
		ndpr->ndpr_preferred = time_second + ndpr->ndpr_pltime;
	if (ndpr->ndpr_vltime == ND6_INFINITE_LIFETIME)
		ndpr->ndpr_expire = 0;
	else
		ndpr->ndpr_expire = time_second + ndpr->ndpr_vltime;

	return 0;
}

static void
in6_init_address_ltimes(struct nd_prefix *new,
			struct in6_addrlifetime *lt6,
			int update_vltime)
{
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined (__APPLE__)
	long time_second = time.tv_sec;
#endif

	/* Valid lifetime must not be updated unless explicitly specified. */
	if (update_vltime) {
		/* init ia6t_expire */
		if (lt6->ia6t_vltime == ND6_INFINITE_LIFETIME)
			lt6->ia6t_expire = 0;
		else {
			lt6->ia6t_expire = time_second;
			lt6->ia6t_expire += lt6->ia6t_vltime;
		}
		/* Ensure addr lifetime <= prefix lifetime. */
		if (new->ndpr_expire && lt6->ia6t_expire &&
		    new->ndpr_expire < lt6->ia6t_expire)
			lt6->ia6t_expire = new->ndpr_expire;
	}

	/* init ia6t_preferred */
	if (lt6->ia6t_pltime == ND6_INFINITE_LIFETIME)
		lt6->ia6t_preferred = 0;
	else {
		lt6->ia6t_preferred = time_second;
		lt6->ia6t_preferred += lt6->ia6t_pltime;
	}
	 /* Ensure addr lifetime <= prefix lifetime. */
	if (new->ndpr_preferred && lt6->ia6t_preferred
	    && new->ndpr_preferred < lt6->ia6t_preferred)
		lt6->ia6t_preferred = new->ndpr_preferred;
}

/*
 * Delete all the routing table entries that use the specified gateway.
 * XXX: this function causes search through all entries of routing table, so
 * it shouldn't be called when acting as a router.
 */
void
rt6_flush(gateway, ifp)
    struct in6_addr *gateway;
    struct ifnet *ifp;
{
	struct radix_node_head *rnh = rt_tables[AF_INET6];
#ifdef __NetBSD__
	int s = splsoftnet();
#else
	int s = splnet();
#endif

	/* We'll care only link-local addresses */
	if (!IN6_IS_ADDR_LINKLOCAL(gateway)) {
		splx(s);
		return;
	}
	/* XXX: hack for KAME's link-local address kludge */
	gateway->s6_addr16[1] = htons(ifp->if_index);

	rnh->rnh_walktree(rnh, rt6_deleteroute, (void *)gateway);
	splx(s);
}

static int
rt6_deleteroute(rn, arg)
	struct radix_node *rn;
	void *arg;
{
#define SIN6(s)	((struct sockaddr_in6 *)s)
	struct rtentry *rt = (struct rtentry *)rn;
	struct in6_addr *gate = (struct in6_addr *)arg;

	if (rt->rt_gateway == NULL || rt->rt_gateway->sa_family != AF_INET6)
		return(0);

	if (!IN6_ARE_ADDR_EQUAL(gate, &SIN6(rt->rt_gateway)->sin6_addr))
		return(0);

	/*
	 * We delete only host route. This means, in particular, we don't
	 * delete default route.
	 */
	if ((rt->rt_flags & RTF_HOST) == 0)
		return(0);

	return(rtrequest(RTM_DELETE, rt_key(rt),
			 rt->rt_gateway, rt_mask(rt), rt->rt_flags, 0));
#undef SIN6
}

int
nd6_setdefaultiface(ifindex)
	int ifindex;
{
	int error = 0;

	if (ifindex < 0 || if_index < ifindex)
		return(EINVAL);

	if (nd6_defifindex != ifindex) {
		nd6_defifindex = ifindex;
		if (nd6_defifindex > 0)
			nd6_defifp = ifindex2ifnet[nd6_defifindex];
		else
			nd6_defifp = NULL;

		/*
		 * If the Default Router List is empty, install a route
		 * to the specified interface as default or remove the default
		 * route when the default interface becomes canceled.
		 * The check for the queue is actually redundant, but
		 * we do this here to avoid re-install the default route
		 * if the list is NOT empty.
		 */
		if (TAILQ_FIRST(&nd_defrouter) == NULL)
			defrouter_select();
	}

	return(error);
}
