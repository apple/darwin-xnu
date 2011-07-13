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
/*	$FreeBSD: src/sys/netinet6/nd6_nbr.c,v 1.4.2.4 2001/07/06 05:32:25 sumikawa Exp $	*/
/*	$KAME: nd6_nbr.c,v 1.64 2001/05/17 03:48:30 itojun Exp $	*/

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
#include <sys/sysctl.h>
#include <sys/mcache.h>
#include <sys/protosw.h>
#include <kern/queue.h>

#include <kern/locks.h>
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_llreach.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>
#include <netinet/icmp6.h>

#if IPSEC
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
extern int ipsec_bypass;
#endif

#include <net/net_osdep.h>

#define SDL(s) ((struct sockaddr_dl *)s)

struct dadq;
static struct dadq *nd6_dad_find(struct ifaddr *);
void nd6_dad_stoptimer(struct ifaddr *);
static void nd6_dad_timer(struct ifaddr *);
static void nd6_dad_ns_output(struct dadq *, struct ifaddr *);
static void nd6_dad_ns_input(struct ifaddr *);
static void nd6_dad_na_input(struct ifaddr *, caddr_t, int);
static void dad_addref(struct dadq *, int);
static void dad_remref(struct dadq *);
static struct dadq *nd6_dad_attach(struct dadq *, struct ifaddr *);
static void nd6_dad_detach(struct dadq *, struct ifaddr *);

static int dad_ignore_ns = 0;	/* ignore NS in DAD - specwise incorrect*/
static int dad_maxtry = 15;	/* max # of *tries* to transmit DAD packet */

static unsigned int dad_size;			/* size of zone element */
static struct zone *dad_zone;			/* zone for dadq */

#define	DAD_ZONE_MAX	64			/* maximum elements in zone */
#define	DAD_ZONE_NAME	"nd6_dad"		/* zone name */

#define	DAD_LOCK_ASSERT_HELD(_dp)					\
	lck_mtx_assert(&(_dp)->dad_lock, LCK_MTX_ASSERT_OWNED)

#define	DAD_LOCK_ASSERT_NOTHELD(_dp)					\
	lck_mtx_assert(&(_dp)->dad_lock, LCK_MTX_ASSERT_NOTOWNED)

#define	DAD_LOCK(_dp)							\
	lck_mtx_lock(&(_dp)->dad_lock)

#define	DAD_LOCK_SPIN(_dp)						\
	lck_mtx_lock_spin(&(_dp)->dad_lock)

#define	DAD_CONVERT_LOCK(_dp) do {					\
	DAD_LOCK_ASSERT_HELD(_dp);					\
	lck_mtx_convert_spin(&(_dp)->dad_lock);				\
} while (0)

#define	DAD_UNLOCK(_dp)							\
	lck_mtx_unlock(&(_dp)->dad_lock)

#define	DAD_ADDREF(_dp)							\
	dad_addref(_dp, 0)

#define	DAD_ADDREF_LOCKED(_dp)						\
	dad_addref(_dp, 1)

#define	DAD_REMREF(_dp)							\
	dad_remref(_dp)

extern lck_mtx_t *dad6_mutex;
extern lck_mtx_t *nd6_mutex;
extern int in6_get_hw_ifid(struct ifnet *, struct in6_addr *);

static int nd6_llreach_base = (LL_BASE_REACHABLE / 1000); /* seconds */

SYSCTL_DECL(_net_inet6_icmp6);

SYSCTL_INT(_net_inet6_icmp6, OID_AUTO, nd6_llreach_base,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_llreach_base, LL_BASE_REACHABLE,
    "default ND6 link-layer reachability max lifetime (in seconds)");

#define SIN6(s)	((struct sockaddr_in6 *)s)

/*
 * Obtain a link-layer source cache entry for the sender.
 *
 * NOTE: This is currently only for ND6/Ethernet.
 */
void
nd6_llreach_alloc(struct rtentry *rt, struct ifnet *ifp, void *addr,
    unsigned int alen, boolean_t solicited)
{
	struct llinfo_nd6 *ln = rt->rt_llinfo;

	if (nd6_llreach_base != 0 &&
	    ln->ln_expire != 0 && rt->rt_ifp != lo_ifp &&
	    ifp->if_addrlen == IF_LLREACH_MAXLEN &&	/* Ethernet */
	    alen == ifp->if_addrlen) {
		struct if_llreach *lr;
		const char *why = NULL, *type = "";

		/* Become a regular mutex, just in case */
		RT_CONVERT_LOCK(rt);

		if ((lr = ln->ln_llreach) != NULL) {
			type = (solicited ? "ND6 advertisement" :
			    "ND6 unsolicited announcement");
			/*
			 * If target has changed, create a new record;
			 * otherwise keep existing record.
			 */
			IFLR_LOCK(lr);
			if (bcmp(addr, lr->lr_key.addr, alen) != 0) {
				IFLR_UNLOCK(lr);
				/* Purge any link-layer info caching */
				VERIFY(rt->rt_llinfo_purge != NULL);
				rt->rt_llinfo_purge(rt);
				lr = NULL;
				why = " for different target HW address; "
				    "using new llreach record";
			} else {
				lr->lr_probes = 0;	/* reset probe count */
				IFLR_UNLOCK(lr);
				if (solicited) {
					why = " for same target HW address; "
					    "keeping existing llreach record";
				}
			}
		}

		if (lr == NULL) {
			lr = ln->ln_llreach = ifnet_llreach_alloc(ifp,
			    ETHERTYPE_IPV6, addr, alen, nd6_llreach_base);
			if (lr != NULL) {
				lr->lr_probes = 0;	/* reset probe count */
				if (why == NULL)
					why = "creating new llreach record";
			}
		}

		if (nd6_debug && lr != NULL && why != NULL) {
			char tmp[MAX_IPv6_STR_LEN];

			nd6log((LOG_DEBUG, "%s%d: %s%s for %s\n", ifp->if_name,
			    ifp->if_unit, type, why, inet_ntop(AF_INET6,
			    &SIN6(rt_key(rt))->sin6_addr, tmp, sizeof (tmp))));
		}
	}
}

void
nd6_llreach_use(struct llinfo_nd6 *ln)
{
	if (ln->ln_llreach != NULL)
		ln->ln_lastused = net_uptime();
}

/*
 * Input a Neighbor Solicitation Message.
 *
 * Based on RFC 2461
 * Based on RFC 2462 (duplicate address detection)
 */
void
nd6_ns_input(
	struct mbuf *m,
	int off,
	int icmp6len)
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_neighbor_solicit *nd_ns;
	struct in6_addr saddr6 = ip6->ip6_src;
	struct in6_addr daddr6 = ip6->ip6_dst;
	struct in6_addr taddr6;
	struct in6_addr myaddr6;
	char *lladdr = NULL;
	struct ifaddr *ifa = NULL;
	int lladdrlen = 0;
	int anycast = 0, proxy = 0, tentative = 0;
	int tlladdr;
	union nd_opts ndopts;
	struct sockaddr_dl proxydl;

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len, return);
	nd_ns = (struct nd_neighbor_solicit *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(nd_ns, struct nd_neighbor_solicit *, m, off, icmp6len);
	if (nd_ns == NULL) {
		icmp6stat.icp6s_tooshort++;
		return;
	}
#endif
	ip6 = mtod(m, struct ip6_hdr *); /* adjust pointer for safety */
	taddr6 = nd_ns->nd_ns_target;
	if (in6_setscope(&taddr6, ifp, NULL) != 0)
		goto bad;

	if (ip6->ip6_hlim != 255) {
		nd6log((LOG_ERR,
		    "nd6_ns_input: invalid hlim (%d) from %s to %s on %s\n",
		    ip6->ip6_hlim, ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst), if_name(ifp)));
		goto bad;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&saddr6)) {
		/* dst has to be a solicited node multicast address. */
		if (daddr6.s6_addr16[0] == IPV6_ADDR_INT16_MLL &&
		    /* don't check ifindex portion */
		    daddr6.s6_addr32[1] == 0 &&
		    daddr6.s6_addr32[2] == IPV6_ADDR_INT32_ONE &&
		    daddr6.s6_addr8[12] == 0xff) {
			; /* good */
		} else {
			nd6log((LOG_INFO, "nd6_ns_input: bad DAD packet "
				"(wrong ip6 dst)\n"));
			goto bad;
		}
	} else if (!nd6_onlink_ns_rfc4861) {
		struct sockaddr_in6 src_sa6;

		/*
		 * According to recent IETF discussions, it is not a good idea
		 * to accept a NS from an address which would not be deemed
		 * to be a neighbor otherwise.  This point is expected to be
		 * clarified in future revisions of the specification.
		 */
		bzero(&src_sa6, sizeof(src_sa6));
		src_sa6.sin6_family = AF_INET6;
		src_sa6.sin6_len = sizeof(src_sa6);
		src_sa6.sin6_addr = saddr6;
		if (!nd6_is_addr_neighbor(&src_sa6, ifp, 0)) {
			nd6log((LOG_INFO, "nd6_ns_input: "
				"NS packet from non-neighbor\n"));
			goto bad;
		}
	}

	if (IN6_IS_ADDR_MULTICAST(&taddr6)) {
		nd6log((LOG_INFO, "nd6_ns_input: bad NS target (multicast)\n"));
		goto bad;
	}

	icmp6len -= sizeof(*nd_ns);
	nd6_option_init(nd_ns + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log((LOG_INFO,
		    "nd6_ns_input: invalid ND option, ignored\n"));
		/* nd6_options have incremented stats */
		goto freeit;
	}

	if (ndopts.nd_opts_src_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_src_lladdr + 1);
		lladdrlen = ndopts.nd_opts_src_lladdr->nd_opt_len << 3;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) && lladdr) {
		nd6log((LOG_INFO, "nd6_ns_input: bad DAD packet "
		    "(link-layer address option)\n"));
		goto bad;
	}

	/*
	 * Attaching target link-layer address to the NA?
	 * (RFC 2461 7.2.4)
	 *
	 * NS IP dst is unicast/anycast			MUST NOT add
	 * NS IP dst is solicited-node multicast	MUST add
	 *
	 * In implementation, we add target link-layer address by default.
	 * We do not add one in MUST NOT cases.
	 */
	if (!IN6_IS_ADDR_MULTICAST(&daddr6))
		tlladdr = 0;
	else
		tlladdr = 1;

	/*
	 * Target address (taddr6) must be either:
	 * (1) Valid unicast/anycast address for my receiving interface,
	 * (2) Unicast address for which I'm offering proxy service, or
	 * (3) "tentative" address on which DAD is being performed.
	 */
	/* (1) and (3) check. */
	ifa = (struct ifaddr *)in6ifa_ifpwithaddr(ifp, &taddr6);

	/* (2) check. */
	if (ifa == NULL) {
		struct rtentry *rt;
		struct sockaddr_in6 tsin6;

		bzero(&tsin6, sizeof tsin6);
		tsin6.sin6_len = sizeof(struct sockaddr_in6);
		tsin6.sin6_family = AF_INET6;
		tsin6.sin6_addr = taddr6;

		rt = rtalloc1_scoped((struct sockaddr *)&tsin6, 0, 0,
		    ifp->if_index);

		if (rt != NULL) {
			RT_LOCK(rt);
			if ((rt->rt_flags & RTF_ANNOUNCE) != 0 &&
			    rt->rt_gateway->sa_family == AF_LINK) {
				/*
				 * proxy NDP for single entry
				 */
				ifa = (struct ifaddr *)in6ifa_ifpforlinklocal(
				    ifp, IN6_IFF_NOTREADY|IN6_IFF_ANYCAST);
				if (ifa) {
					proxy = 1;
					proxydl = *SDL(rt->rt_gateway);
				}
			}
			RT_UNLOCK(rt);
			rtfree(rt);
		}
	}
	if (ifa == NULL) {
		/*
		 * We've got an NS packet, and we don't have that adddress
		 * assigned for us.  We MUST silently ignore it.
		 * See RFC2461 7.2.3.
		 */
		goto freeit;
	}
	IFA_LOCK(ifa);
	myaddr6 = *IFA_IN6(ifa);
	anycast = ((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_ANYCAST;
	tentative = ((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_TENTATIVE;
	if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DUPLICATED) {
		IFA_UNLOCK(ifa);
		goto freeit;
	}
	IFA_UNLOCK(ifa);

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log((LOG_INFO,
		    "nd6_ns_input: lladdrlen mismatch for %s "
		    "(if %d, NS packet %d)\n",
			ip6_sprintf(&taddr6), ifp->if_addrlen, lladdrlen - 2));
		goto bad;
	}

	if (IN6_ARE_ADDR_EQUAL(&myaddr6, &saddr6)) {
		nd6log((LOG_INFO,
			"nd6_ns_input: duplicate IP6 address %s\n",
			ip6_sprintf(&saddr6)));
		goto freeit;
	}

	/*
	 * We have neighbor solicitation packet, with target address equals to
	 * one of my tentative address.
	 *
	 * src addr	how to process?
	 * ---		---
	 * multicast	of course, invalid (rejected in ip6_input)
	 * unicast	somebody is doing address resolution -> ignore
	 * unspec	dup address detection
	 *
	 * The processing is defined in RFC 2462.
	 */
	if (tentative) {
		/*
		 * If source address is unspecified address, it is for
		 * duplicate address detection.
		 *
		 * If not, the packet is for addess resolution;
		 * silently ignore it.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&saddr6))
			nd6_dad_ns_input(ifa);

		goto freeit;
	}

	/*
	 * If the source address is unspecified address, entries must not
	 * be created or updated.
	 * It looks that sender is performing DAD.  Output NA toward
	 * all-node multicast address, to tell the sender that I'm using
	 * the address.
	 * S bit ("solicited") must be zero.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&saddr6)) {
		saddr6 = in6addr_linklocal_allnodes;
		if (in6_setscope(&saddr6, ifp, NULL) != 0)
			goto bad;
		nd6_na_output(ifp, &saddr6, &taddr6,
			      ((anycast || proxy || !tlladdr)
				      ? 0 : ND_NA_FLAG_OVERRIDE)
			      	| (ip6_forwarding ? ND_NA_FLAG_ROUTER : 0),
		      tlladdr, proxy ? (struct sockaddr *)&proxydl : NULL);
		goto freeit;
	}

	nd6_cache_lladdr(ifp, &saddr6, lladdr, lladdrlen, ND_NEIGHBOR_SOLICIT, 0);

	nd6_na_output(ifp, &saddr6, &taddr6,
		      ((anycast || proxy || !tlladdr) ? 0 : ND_NA_FLAG_OVERRIDE)
			| (ip6_forwarding ? ND_NA_FLAG_ROUTER : 0)
			| ND_NA_FLAG_SOLICITED,
		      tlladdr, proxy ? (struct sockaddr *)&proxydl : NULL);
 freeit:
	m_freem(m);
	if (ifa != NULL)
		IFA_REMREF(ifa);
	return;

 bad:
	nd6log((LOG_ERR, "nd6_ns_input: src=%s\n", ip6_sprintf(&saddr6)));
	nd6log((LOG_ERR, "nd6_ns_input: dst=%s\n", ip6_sprintf(&daddr6)));
	nd6log((LOG_ERR, "nd6_ns_input: tgt=%s\n", ip6_sprintf(&taddr6)));
	icmp6stat.icp6s_badns++;
	m_freem(m);
	if (ifa != NULL)
		IFA_REMREF(ifa);
}

/*
 * Output a Neighbor Solicitation Message. Caller specifies:
 *	- ICMP6 header source IP6 address
 *	- ND6 header target IP6 address
 *	- ND6 header source datalink address
 *
 * Based on RFC 2461
 * Based on RFC 2462 (duplicate address detection)
 *
 * Caller must bump up ln->ln_rt refcnt to make sure 'ln' doesn't go
 * away if there is a llinfo_nd6 passed in.
 */
void
nd6_ns_output(
	struct ifnet *ifp,
	const struct in6_addr *daddr6,
	const struct in6_addr *taddr6,
	struct llinfo_nd6 *ln,	/* for source address determination */
	int dad)	/* duplicated address detection */
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct nd_neighbor_solicit *nd_ns;
	struct in6_ifaddr *ia = NULL;
	struct in6_addr *src, src_in, src_storage;
	struct ip6_moptions *im6o = NULL;
        struct ifnet *outif = NULL;
	int icmp6len;
	int maxlen;
	int flags;
	caddr_t mac;
	struct route_in6 ro;
	struct ip6_out_args ip6oa = { IFSCOPE_NONE, 0 };

	bzero(&ro, sizeof(ro));

	if (IN6_IS_ADDR_MULTICAST(taddr6))
		return;

	ip6oa.ip6oa_boundif = ifp->if_index;

	/* estimate the size of message */
	maxlen = sizeof(*ip6) + sizeof(*nd_ns);
	maxlen += (sizeof(struct nd_opt_hdr) + ifp->if_addrlen + 7) & ~7;
	if (max_linkhdr + maxlen >= MCLBYTES) {
#if DIAGNOSTIC
		printf("nd6_ns_output: max_linkhdr + maxlen >= MCLBYTES "
		    "(%d + %d > %d)\n", max_linkhdr, maxlen, MCLBYTES);
#endif
		return;
	}

	MGETHDR(m, M_DONTWAIT, MT_DATA);	/* XXXMAC: mac_create_mbuf_linklayer() probably */
	if (m && max_linkhdr + maxlen >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return;
	m->m_pkthdr.rcvif = NULL;

	if (daddr6 == NULL || IN6_IS_ADDR_MULTICAST(daddr6)) {
		m->m_flags |= M_MCAST;

		im6o = ip6_allocmoptions(M_DONTWAIT);
		if (im6o == NULL) {
			m_freem(m);
			return;
		}

		im6o->im6o_multicast_ifp = ifp;
		im6o->im6o_multicast_hlim = 255;
		im6o->im6o_multicast_loop = 0;
	}

	icmp6len = sizeof(*nd_ns);
	m->m_pkthdr.len = m->m_len = sizeof(*ip6) + icmp6len;
	m->m_data += max_linkhdr;	/* or MH_ALIGN() equivalent? */

	/* fill neighbor solicitation packet */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	if (daddr6)
		ip6->ip6_dst = *daddr6;
	else {
		ip6->ip6_dst.s6_addr16[0] = IPV6_ADDR_INT16_MLL;
		ip6->ip6_dst.s6_addr16[1] = 0;
		ip6->ip6_dst.s6_addr32[1] = 0;
		ip6->ip6_dst.s6_addr32[2] = IPV6_ADDR_INT32_ONE;
		ip6->ip6_dst.s6_addr32[3] = taddr6->s6_addr32[3];
		ip6->ip6_dst.s6_addr8[12] = 0xff;
		if (in6_setscope(&ip6->ip6_dst, ifp, NULL) != 0)
			goto bad;
	}
	if (!dad) {
		/*
		 * RFC2461 7.2.2:
		 * "If the source address of the packet prompting the
		 * solicitation is the same as one of the addresses assigned
		 * to the outgoing interface, that address SHOULD be placed
		 * in the IP Source Address of the outgoing solicitation.
		 * Otherwise, any one of the addresses assigned to the
		 * interface should be used."
		 *
		 * We use the source address for the prompting packet
		 * (saddr6), if:
		 * - saddr6 is given from the caller (by giving "ln"), and
		 * - saddr6 belongs to the outgoing interface.
		 * Otherwise, we perform the source address selection as usual.
		 */
		struct ip6_hdr *hip6;		/* hold ip6 */
		struct in6_addr *hsrc = NULL;

		/* Caller holds ref on this route */
		if (ln != NULL) {
			RT_LOCK(ln->ln_rt);
			/*
			 * assuming every packet in ln_hold has the same IP
			 * header
			 */
			if (ln->ln_hold != NULL) {
				hip6 = mtod(ln->ln_hold, struct ip6_hdr *);
				/* XXX pullup? */
				if (sizeof (*hip6) < ln->ln_hold->m_len)
					hsrc = &hip6->ip6_src;
				else
					hsrc = NULL;
			}
			/* Update probe count, if applicable */
			if (ln->ln_llreach != NULL) {
				IFLR_LOCK_SPIN(ln->ln_llreach);
				ln->ln_llreach->lr_probes++;
				IFLR_UNLOCK(ln->ln_llreach);
			}
			RT_UNLOCK(ln->ln_rt);

		}
		if (ia != NULL) {
			IFA_REMREF(&ia->ia_ifa);
			ia = NULL;
		}
		if (hsrc != NULL && (ia = in6ifa_ifpwithaddr(ifp, hsrc))) {
			src = hsrc;
			IFA_REMREF(&ia->ia_ifa);
			ia = NULL;
		} else {
			int error;
			struct sockaddr_in6 dst_sa;

			bzero(&dst_sa, sizeof(dst_sa));
			dst_sa.sin6_family = AF_INET6;
			dst_sa.sin6_len = sizeof(dst_sa);
			dst_sa.sin6_addr = ip6->ip6_dst;

			src = in6_selectsrc(&dst_sa, NULL,
			    NULL, &ro, NULL, &src_storage, ip6oa.ip6oa_boundif,
			    &error);
			if (src == NULL) {
				nd6log((LOG_DEBUG,
				    "nd6_ns_output: source can't be "
				    "determined: dst=%s, error=%d\n",
				    ip6_sprintf(&dst_sa.sin6_addr),
				    error));
				goto bad;
			}
		}
	} else {
		/*
		 * Source address for DAD packet must always be IPv6
		 * unspecified address. (0::0)
		 * We actually don't have to 0-clear the address (we did it
		 * above), but we do so here explicitly to make the intention
		 * clearer.
		 */
		bzero(&src_in, sizeof(src_in));
		src = &src_in;
	}
	ip6->ip6_src = *src;
	nd_ns = (struct nd_neighbor_solicit *)(ip6 + 1);
	nd_ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
	nd_ns->nd_ns_code = 0;
	nd_ns->nd_ns_reserved = 0;
	nd_ns->nd_ns_target = *taddr6;
	in6_clearscope(&nd_ns->nd_ns_target); /* XXX */

	/*
	 * Add source link-layer address option.
	 *
	 *				spec		implementation
	 *				---		---
	 * DAD packet			MUST NOT	do not add the option
	 * there's no link layer address:
	 *				impossible	do not add the option
	 * there's link layer address:
	 *	Multicast NS		MUST add one	add the option
	 *	Unicast NS		SHOULD add one	add the option
	 */
	if (!dad && (mac = nd6_ifptomac(ifp))) {
		int optlen = sizeof(struct nd_opt_hdr) + ifp->if_addrlen;
		struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(nd_ns + 1);
		/* 8 byte alignments... */
		optlen = (optlen + 7) & ~7;
		
		m->m_pkthdr.len += optlen;
		m->m_len += optlen;
		icmp6len += optlen;
		bzero((caddr_t)nd_opt, optlen);
		nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		nd_opt->nd_opt_len = optlen >> 3;
		bcopy(mac, (caddr_t)(nd_opt + 1), ifp->if_addrlen);
	}

	ip6->ip6_plen = htons((u_short)icmp6len);
	nd_ns->nd_ns_cksum = 0;
	nd_ns->nd_ns_cksum
		= in6_cksum(m, IPPROTO_ICMPV6, sizeof(*ip6), icmp6len);

#if IPSEC
	/* Don't lookup socket */
	if (ipsec_bypass == 0)
		(void)ipsec_setsocket(m, NULL);
#endif
	flags = dad ? IPV6_UNSPECSRC : 0;
	flags |= IPV6_OUTARGS;

	ip6_output(m, NULL, NULL, flags, im6o, &outif, &ip6oa);
	if (outif) {
		icmp6_ifstat_inc(outif, ifs6_out_msg);
		icmp6_ifstat_inc(outif, ifs6_out_neighborsolicit);
		ifnet_release(outif);
	}
	icmp6stat.icp6s_outhist[ND_NEIGHBOR_SOLICIT]++;

	if (im6o != NULL)
		IM6O_REMREF(im6o);
	if (ro.ro_rt) {		/* we don't cache this route. */
		rtfree(ro.ro_rt);
	}
	if (ia != NULL)
		IFA_REMREF(&ia->ia_ifa);
	return;

bad:
	if (im6o != NULL)
		IM6O_REMREF(im6o);
	if (ro.ro_rt) {
		rtfree(ro.ro_rt);
	}
	m_freem(m);
	if (ia != NULL)
		IFA_REMREF(&ia->ia_ifa);
	return;
}

/*
 * Neighbor advertisement input handling.
 *
 * Based on RFC 2461
 * Based on RFC 2462 (duplicate address detection)
 *
 * the following items are not implemented yet:
 * - proxy advertisement delay rule (RFC2461 7.2.8, last paragraph, SHOULD)
 * - anycast advertisement delay rule (RFC2461 7.2.7, SHOULD)
 */
void
nd6_na_input(
	struct mbuf *m,
	int off, 
	int icmp6len)
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_neighbor_advert *nd_na;
	struct in6_addr daddr6 = ip6->ip6_dst;
	struct in6_addr taddr6;
	int flags;
	int is_router;
	int is_solicited;
	int is_override;
	char *lladdr = NULL;
	int lladdrlen = 0;
	struct ifaddr *ifa = NULL;
	struct llinfo_nd6 *ln;
	struct rtentry *rt;
	struct sockaddr_dl *sdl;
	union nd_opts ndopts;
	struct timeval timenow;

	if (ip6->ip6_hlim != 255) {
		nd6log((LOG_ERR,
		    "nd6_na_input: invalid hlim (%d) from %s to %s on %s\n",
		    ip6->ip6_hlim, ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst), if_name(ifp)));
		goto bad;
	}

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, icmp6len, return);
	nd_na = (struct nd_neighbor_advert *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(nd_na, struct nd_neighbor_advert *, m, off, icmp6len);
	if (nd_na == NULL) {
		icmp6stat.icp6s_tooshort++;
		return;
	}
#endif

	flags = nd_na->nd_na_flags_reserved;
	is_router = ((flags & ND_NA_FLAG_ROUTER) != 0);
	is_solicited = ((flags & ND_NA_FLAG_SOLICITED) != 0);
	is_override = ((flags & ND_NA_FLAG_OVERRIDE) != 0);

	taddr6 = nd_na->nd_na_target;
	if (in6_setscope(&taddr6, ifp, NULL))
		goto bad;	/* XXX: impossible */

	if (IN6_IS_ADDR_MULTICAST(&taddr6)) {
		nd6log((LOG_ERR,
		    "nd6_na_input: invalid target address %s\n",
		    ip6_sprintf(&taddr6)));
		goto bad;
	}
	if (IN6_IS_ADDR_MULTICAST(&daddr6))
		if (is_solicited) {
			nd6log((LOG_ERR,
			    "nd6_na_input: a solicited adv is multicasted\n"));
			goto bad;
		}

	icmp6len -= sizeof(*nd_na);
	nd6_option_init(nd_na + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log((LOG_INFO,
		    "nd6_na_input: invalid ND option, ignored\n"));
		/* nd6_options have incremented stats */
		goto freeit;
	}

	if (ndopts.nd_opts_tgt_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_tgt_lladdr + 1);
		lladdrlen = ndopts.nd_opts_tgt_lladdr->nd_opt_len << 3;
	}

	ifa = (struct ifaddr *)in6ifa_ifpwithaddr(ifp, &taddr6);

	/*
	 * Target address matches one of my interface address.
	 *
	 * If my address is tentative, this means that there's somebody
	 * already using the same address as mine.  This indicates DAD failure.
	 * This is defined in RFC 2462.
	 *
	 * Otherwise, process as defined in RFC 2461.
	 */
	if (ifa != NULL) {
		IFA_LOCK(ifa);
		if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_TENTATIVE) {
			IFA_UNLOCK(ifa);
			nd6_dad_na_input(ifa, lladdr, lladdrlen);
			goto freeit;
		}
		IFA_UNLOCK(ifa);
	}

	/* Just for safety, maybe unnecessary. */
	if (ifa) {
		log(LOG_ERR,
		    "nd6_na_input: duplicate IP6 address %s\n",
		    ip6_sprintf(&taddr6));
		goto freeit;
	}

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log((LOG_INFO,
		    "nd6_na_input: lladdrlen mismatch for %s "
		    "(if %d, NA packet %d)\n",
			ip6_sprintf(&taddr6), ifp->if_addrlen, lladdrlen - 2));
		goto bad;
	}

	/*
	 * If no neighbor cache entry is found, NA SHOULD silently be
	 * discarded.
	 */
	if ((rt = nd6_lookup(&taddr6, 0, ifp, 0)) == NULL)
		goto freeit;

	RT_LOCK_ASSERT_HELD(rt);
	if ((ln = rt->rt_llinfo) == NULL ||
	    (sdl = SDL(rt->rt_gateway)) == NULL) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		goto freeit;
	}

	getmicrotime(&timenow);
	if (ln->ln_state == ND6_LLINFO_INCOMPLETE) {
		/*
		 * If the link-layer has address, and no lladdr option came,
		 * discard the packet.
		 */
		if (ifp->if_addrlen && !lladdr) {
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			goto freeit;
		}

		/*
		 * Record link-layer address, and update the state.
		 */
		sdl->sdl_alen = ifp->if_addrlen;
		bcopy(lladdr, LLADDR(sdl), ifp->if_addrlen);
		if (is_solicited) {
			ln->ln_state = ND6_LLINFO_REACHABLE;
			ln->ln_byhint = 0;
			if (ln->ln_expire) {
				lck_rw_lock_shared(nd_if_rwlock);
				ln->ln_expire = rt_expiry(rt, timenow.tv_sec,
				    nd_ifinfo[rt->rt_ifp->if_index].reachable);
				lck_rw_done(nd_if_rwlock);
			}
		} else {
			ln->ln_state = ND6_LLINFO_STALE;
			ln->ln_expire = rt_expiry(rt, timenow.tv_sec,
			    nd6_gctimer);
		}
		if ((ln->ln_router = is_router) != 0) {
			/*
			 * This means a router's state has changed from
			 * non-reachable to probably reachable, and might
			 * affect the status of associated prefixes..
			 */
			RT_UNLOCK(rt);
			lck_mtx_lock(nd6_mutex);
			pfxlist_onlink_check();
			lck_mtx_unlock(nd6_mutex);
			RT_LOCK(rt);
		}
	} else {
		int llchange;

		/*
		 * Check if the link-layer address has changed or not.
		 */
		if (!lladdr)
			llchange = 0;
		else {
			if (sdl->sdl_alen) {
				if (bcmp(lladdr, LLADDR(sdl), ifp->if_addrlen))
					llchange = 1;
				else
					llchange = 0;
			} else
				llchange = 1;
		}

		/*
		 * This is VERY complex.  Look at it with care.
		 *
		 * override solicit lladdr llchange	action
		 *					(L: record lladdr)
		 *
		 *	0	0	n	--	(2c)
		 *	0	0	y	n	(2b) L
		 *	0	0	y	y	(1)    REACHABLE->STALE
		 *	0	1	n	--	(2c)   *->REACHABLE
		 *	0	1	y	n	(2b) L *->REACHABLE
		 *	0	1	y	y	(1)    REACHABLE->STALE
		 *	1	0	n	--	(2a)
		 *	1	0	y	n	(2a) L
		 *	1	0	y	y	(2a) L *->STALE
		 *	1	1	n	--	(2a)   *->REACHABLE
		 *	1	1	y	n	(2a) L *->REACHABLE
		 *	1	1	y	y	(2a) L *->REACHABLE
		 */
		if (!is_override && (lladdr != NULL && llchange)) {  /* (1) */
			/*
			 * If state is REACHABLE, make it STALE.
			 * no other updates should be done.
			 */
			if (ln->ln_state == ND6_LLINFO_REACHABLE) {
				ln->ln_state = ND6_LLINFO_STALE;
				ln->ln_expire = rt_expiry(rt, timenow.tv_sec,
				    nd6_gctimer);
			}
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			goto freeit;
		} else if (is_override				   /* (2a) */
			|| (!is_override && (lladdr && !llchange)) /* (2b) */
			|| !lladdr) {				   /* (2c) */
			/*
			 * Update link-local address, if any.
			 */
			if (lladdr) {
				sdl->sdl_alen = ifp->if_addrlen;
				bcopy(lladdr, LLADDR(sdl), ifp->if_addrlen);
			}

			/*
			 * If solicited, make the state REACHABLE.
			 * If not solicited and the link-layer address was
			 * changed, make it STALE.
			 */
			if (is_solicited) {
				ln->ln_state = ND6_LLINFO_REACHABLE;
				ln->ln_byhint = 0;
				if (ln->ln_expire) {
					lck_rw_lock_shared(nd_if_rwlock);
					ln->ln_expire =
					    rt_expiry(rt, timenow.tv_sec,
					    nd_ifinfo[ifp->if_index].reachable);
					lck_rw_done(nd_if_rwlock);
				}
			} else {
				if (lladdr && llchange) {
					ln->ln_state = ND6_LLINFO_STALE;
					ln->ln_expire = rt_expiry(rt,
					    timenow.tv_sec, nd6_gctimer);
				}
			}
		}

		if (ln->ln_router && !is_router) {
			/*
			 * The peer dropped the router flag.
			 * Remove the sender from the Default Router List and
			 * update the Destination Cache entries.
			 */
			struct nd_defrouter *dr;
			struct in6_addr *in6;
			struct ifnet *rt_ifp = rt->rt_ifp;

			in6 = &((struct sockaddr_in6 *)rt_key(rt))->sin6_addr;

			/*
			 * Lock to protect the default router list.
			 * XXX: this might be unnecessary, since this function
			 * is only called under the network software interrupt
			 * context.  However, we keep it just for safety.
			 */
			RT_UNLOCK(rt);
			lck_mtx_lock(nd6_mutex);
			dr = defrouter_lookup(in6, rt_ifp);
			if (dr) {
				defrtrlist_del(dr);
				NDDR_REMREF(dr);
				lck_mtx_unlock(nd6_mutex);
			}
			else {
				lck_mtx_unlock(nd6_mutex);
				if (!ip6_forwarding && (ip6_accept_rtadv || (rt_ifp->if_eflags & IFEF_ACCEPT_RTADVD))) {
					/*
				 	 * Even if the neighbor is not in the default
					 * router list, the neighbor may be used
					 * as a next hop for some destinations
					 * (e.g. redirect case). So we must
					 * call rt6_flush explicitly.
					 */
					rt6_flush(&ip6->ip6_src, rt_ifp);
				}
			}
			RT_LOCK(rt);
		}
		ln->ln_router = is_router;
	}
	RT_LOCK_ASSERT_HELD(rt);
	rt->rt_flags &= ~RTF_REJECT;

	/* cache the gateway (sender HW) address */
	nd6_llreach_alloc(rt, ifp, LLADDR(sdl), sdl->sdl_alen, TRUE);

	/* update the llinfo, send a queued packet if there is one */
	ln->ln_asked = 0;
	if (ln->ln_hold != NULL) {
		struct mbuf *m_hold, *m_hold_next;
		struct sockaddr_in6 sin6;

		rtkey_to_sa6(rt, &sin6);
		/*
		 * reset the ln_hold in advance, to explicitly
		 * prevent a ln_hold lookup in nd6_output()
		 * (wouldn't happen, though...)
		 */
		for (m_hold = ln->ln_hold;
		    m_hold; m_hold = m_hold_next) {
			m_hold_next = m_hold->m_nextpkt;
			m_hold->m_nextpkt = NULL;
			/*
			 * we assume ifp is not a loopback here, so just set
			 * the 2nd argument as the 1st one.
			 */
			RT_UNLOCK(rt);
			nd6_output(ifp, ifp, m_hold, &sin6, rt);
			RT_LOCK_SPIN(rt);
		}
		ln->ln_hold = NULL;

	}
	RT_REMREF_LOCKED(rt);
	RT_UNLOCK(rt);

freeit:
	m_freem(m);
	if (ifa != NULL)
		IFA_REMREF(ifa);
	return;

bad:
	icmp6stat.icp6s_badna++;
	m_freem(m);
	if (ifa != NULL)
		IFA_REMREF(ifa);
}

/*
 * Neighbor advertisement output handling.
 *
 * Based on RFC 2461
 *
 * the following items are not implemented yet:
 * - proxy advertisement delay rule (RFC2461 7.2.8, last paragraph, SHOULD)
 * - anycast advertisement delay rule (RFC2461 7.2.7, SHOULD)
 *
 * tlladdr - 1 if include target link-layer address
 * sdl0 - sockaddr_dl (= proxy NA) or NULL
 */
void
nd6_na_output(
	struct ifnet *ifp,
	const struct in6_addr *daddr6_0,
	const struct in6_addr *taddr6,
	uint32_t flags,
	int tlladdr,		/* 1 if include target link-layer address */
	struct sockaddr *sdl0)	/* sockaddr_dl (= proxy NA) or NULL */
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct nd_neighbor_advert *nd_na;
	struct ip6_moptions *im6o = NULL;
	caddr_t mac = NULL;
	struct route_in6 ro;
	struct in6_addr *src, src_storage, daddr6;
	struct sockaddr_in6 dst_sa;
	int icmp6len, maxlen, error;
        struct ifnet *outif = NULL;
	struct ip6_out_args ip6oa = { IFSCOPE_NONE, 0 };

	bzero(&ro, sizeof(ro));

	daddr6 = *daddr6_0;	/* make a local copy for modification */

	ip6oa.ip6oa_boundif = ifp->if_index;

	/* estimate the size of message */
	maxlen = sizeof(*ip6) + sizeof(*nd_na);
	maxlen += (sizeof(struct nd_opt_hdr) + ifp->if_addrlen + 7) & ~7;
	if (max_linkhdr + maxlen >= MCLBYTES) {
#if DIAGNOSTIC
		printf("nd6_na_output: max_linkhdr + maxlen >= MCLBYTES "
		    "(%d + %d > %d)\n", max_linkhdr, maxlen, MCLBYTES);
#endif
		return;
	}

	MGETHDR(m, M_DONTWAIT, MT_DATA);	/* XXXMAC: mac_create_mbuf_linklayer() probably */
	if (m && max_linkhdr + maxlen >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return;
	m->m_pkthdr.rcvif = NULL;

	if (IN6_IS_ADDR_MULTICAST(&daddr6)) {
		m->m_flags |= M_MCAST;

		im6o = ip6_allocmoptions(M_DONTWAIT);
		if (im6o == NULL) {
			m_freem(m);
			return;
		}

		im6o->im6o_multicast_ifp = ifp;
		im6o->im6o_multicast_hlim = 255;
		im6o->im6o_multicast_loop = 0;
	}

	icmp6len = sizeof(*nd_na);
	m->m_pkthdr.len = m->m_len = sizeof(struct ip6_hdr) + icmp6len;
	m->m_data += max_linkhdr;	/* or MH_ALIGN() equivalent? */

	/* fill neighbor advertisement packet */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	if (IN6_IS_ADDR_UNSPECIFIED(&daddr6)) {
		/* reply to DAD */
		daddr6.s6_addr16[0] = IPV6_ADDR_INT16_MLL;
		daddr6.s6_addr16[1] = 0;
		daddr6.s6_addr32[1] = 0;
		daddr6.s6_addr32[2] = 0;
		daddr6.s6_addr32[3] = IPV6_ADDR_INT32_ONE;
		if (in6_setscope(&daddr6, ifp, NULL))
			goto bad;

		flags &= ~ND_NA_FLAG_SOLICITED;
	} else
		ip6->ip6_dst = daddr6;

	bzero(&dst_sa, sizeof(struct sockaddr_in6));
	dst_sa.sin6_family = AF_INET6;
	dst_sa.sin6_len = sizeof(struct sockaddr_in6);
	dst_sa.sin6_addr = daddr6;

	/*
	 * Select a source whose scope is the same as that of the dest.
	 */
	bcopy(&dst_sa, &ro.ro_dst, sizeof(dst_sa));
	src = in6_selectsrc(&dst_sa, NULL, NULL, &ro, NULL, &src_storage,
	    ip6oa.ip6oa_boundif, &error);
	if (src == NULL) {
		nd6log((LOG_DEBUG, "nd6_na_output: source can't be "
		    "determined: dst=%s, error=%d\n",
		    ip6_sprintf(&dst_sa.sin6_addr), error));
		goto bad;
	}
	ip6->ip6_src = *src;

	nd_na = (struct nd_neighbor_advert *)(ip6 + 1);
	nd_na->nd_na_type = ND_NEIGHBOR_ADVERT;
	nd_na->nd_na_code = 0;
	nd_na->nd_na_target = *taddr6;
	in6_clearscope(&nd_na->nd_na_target); /* XXX */

	/*
	 * "tlladdr" indicates NS's condition for adding tlladdr or not.
	 * see nd6_ns_input() for details.
	 * Basically, if NS packet is sent to unicast/anycast addr,
	 * target lladdr option SHOULD NOT be included.
	 */
	if (tlladdr) {
		/*
		 * sdl0 != NULL indicates proxy NA.  If we do proxy, use
		 * lladdr in sdl0.  If we are not proxying (sending NA for
		 * my address) use lladdr configured for the interface.
		 */
		if (sdl0 == NULL)
			mac = nd6_ifptomac(ifp);
		else if (sdl0->sa_family == AF_LINK) {
			struct sockaddr_dl *sdl;
			sdl = (struct sockaddr_dl *)sdl0;
			if (sdl->sdl_alen == ifp->if_addrlen)
				mac = LLADDR(sdl);
		}
	}
	if (tlladdr && mac) {
		int optlen = sizeof(struct nd_opt_hdr) + ifp->if_addrlen;
		struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(nd_na + 1);

		/* roundup to 8 bytes alignment! */
		optlen = (optlen + 7) & ~7;

		m->m_pkthdr.len += optlen;
		m->m_len += optlen;
		icmp6len += optlen;
		bzero((caddr_t)nd_opt, optlen);
		nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		nd_opt->nd_opt_len = optlen >> 3;
		bcopy(mac, (caddr_t)(nd_opt + 1), ifp->if_addrlen);
	} else
		flags &= ~ND_NA_FLAG_OVERRIDE;

	ip6->ip6_plen = htons((u_short)icmp6len);
	nd_na->nd_na_flags_reserved = flags;
	nd_na->nd_na_cksum = 0;
	nd_na->nd_na_cksum =
		in6_cksum(m, IPPROTO_ICMPV6, sizeof(struct ip6_hdr), icmp6len);

#if IPSEC
	/* Don't lookup socket */
	if (ipsec_bypass == 0)
		(void)ipsec_setsocket(m, NULL);
#endif
	ip6_output(m, NULL, NULL, IPV6_OUTARGS, im6o, &outif, &ip6oa);
	if (outif) {
		icmp6_ifstat_inc(outif, ifs6_out_msg);
		icmp6_ifstat_inc(outif, ifs6_out_neighboradvert);
		ifnet_release(outif);
	}
	icmp6stat.icp6s_outhist[ND_NEIGHBOR_ADVERT]++;

	if (im6o != NULL)
		IM6O_REMREF(im6o);
	if (ro.ro_rt) {
		rtfree(ro.ro_rt);
	}
	return;

bad:
	if (im6o != NULL)
		IM6O_REMREF(im6o);
	if (ro.ro_rt) {
		rtfree(ro.ro_rt);
	}
	m_freem(m);
	return;
}

caddr_t
nd6_ifptomac(
	struct ifnet *ifp)
{
	switch (ifp->if_type) {
	case IFT_ARCNET:
	case IFT_ETHER:
	case IFT_IEEE8023ADLAG:
	case IFT_FDDI:
	case IFT_IEEE1394:
#ifdef IFT_L2VLAN
	case IFT_L2VLAN:
#endif
#ifdef IFT_IEEE80211
	case IFT_IEEE80211:
#endif
#ifdef IFT_CARP
	case IFT_CARP:
#endif
	case IFT_BRIDGE:
	case IFT_ISO88025:
		return ((caddr_t)ifnet_lladdr(ifp));
	default:
		return NULL;
	}
}

TAILQ_HEAD(dadq_head, dadq);
struct dadq {
	decl_lck_mtx_data(, dad_lock);
	u_int32_t dad_refcount;	/* reference count */
	int dad_attached;
	TAILQ_ENTRY(dadq) dad_list;
	struct ifaddr *dad_ifa;
	int dad_count;		/* max NS to send */
	int dad_ns_tcount;	/* # of trials to send NS */
	int dad_ns_ocount;	/* NS sent so far */
	int dad_ns_icount;
	int dad_na_icount;
	int dad_na_ixcount;	/* Count of IFDISABLED eligible NA rx'd */
};

static struct dadq_head dadq;

void
nd6_nbr_init(void)
{
	TAILQ_INIT(&dadq);

	dad_size = sizeof (struct dadq);
	dad_zone = zinit(dad_size, DAD_ZONE_MAX * dad_size, 0, DAD_ZONE_NAME);
	if (dad_zone == NULL) {
		panic("%s: failed allocating %s", __func__, DAD_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dad_zone, Z_EXPAND, TRUE);
	zone_change(dad_zone, Z_CALLERACCT, FALSE);
}

static struct dadq *
nd6_dad_find(struct ifaddr *ifa)
{
	struct dadq *dp;

	lck_mtx_lock(dad6_mutex);
	for (dp = dadq.tqh_first; dp; dp = dp->dad_list.tqe_next) {
		DAD_LOCK_SPIN(dp);
		if (dp->dad_ifa == ifa) {
			DAD_ADDREF_LOCKED(dp);
			DAD_UNLOCK(dp);
			lck_mtx_unlock(dad6_mutex);
			return (dp);
		}
		DAD_UNLOCK(dp);
	}
	lck_mtx_unlock(dad6_mutex);
	return (NULL);
}

void
nd6_dad_stoptimer(
	struct ifaddr *ifa)
{

	untimeout((void (*)(void *))nd6_dad_timer, (void *)ifa);
}

/*
 * Start Duplicate Address Detection (DAD) for specified interface address.
 */
void
nd6_dad_start(
	struct ifaddr *ifa,
	int *tick_delay)	/* minimum delay ticks for IFF_UP event */
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct dadq *dp;

	/*
	 * If we don't need DAD, don't do it.
	 * There are several cases:
	 * - DAD is disabled (ip6_dad_count == 0)
	 * - the interface address is anycast
	 */
	IFA_LOCK(&ia->ia_ifa);
	if (!(ia->ia6_flags & IN6_IFF_TENTATIVE)) {
		log(LOG_DEBUG,
			"nd6_dad_start: called with non-tentative address "
			"%s(%s)\n",
			ip6_sprintf(&ia->ia_addr.sin6_addr),
			ifa->ifa_ifp ? if_name(ifa->ifa_ifp) : "???");
		IFA_UNLOCK(&ia->ia_ifa);
		return;
	}
	if (ia->ia6_flags & IN6_IFF_ANYCAST) {
		ia->ia6_flags &= ~IN6_IFF_TENTATIVE;
		IFA_UNLOCK(&ia->ia_ifa);
		return;
	}
	if (!ip6_dad_count) {
		ia->ia6_flags &= ~IN6_IFF_TENTATIVE;
		IFA_UNLOCK(&ia->ia_ifa);
		return;
	}
	IFA_UNLOCK(&ia->ia_ifa);
	if (ifa->ifa_ifp == NULL)
		panic("nd6_dad_start: ifa->ifa_ifp == NULL");
	if (!(ifa->ifa_ifp->if_flags & IFF_UP)) {
		return;
	}
	if ((dp = nd6_dad_find(ifa)) != NULL) {
		DAD_REMREF(dp);
		/* DAD already in progress */
		return;
	}

	dp = zalloc(dad_zone);
	if (dp == NULL) {
		log(LOG_ERR, "nd6_dad_start: memory allocation failed for "
			"%s(%s)\n",
			ip6_sprintf(&ia->ia_addr.sin6_addr),
			ifa->ifa_ifp ? if_name(ifa->ifa_ifp) : "???");
		return;
	}
	bzero(dp, dad_size);
	lck_mtx_init(&dp->dad_lock, ifa_mtx_grp, ifa_mtx_attr);

	/* Callee adds one reference for us */
	dp = nd6_dad_attach(dp, ifa);

	nd6log((LOG_DEBUG, "%s: starting DAD for %s\n", if_name(ifa->ifa_ifp),
	    ip6_sprintf(&ia->ia_addr.sin6_addr)));

	/*
	 * Send NS packet for DAD, ip6_dad_count times.
	 * Note that we must delay the first transmission, if this is the
	 * first packet to be sent from the interface after interface
	 * (re)initialization.
	 */
	if (tick_delay == NULL) {
		u_int32_t retrans;
		nd6_dad_ns_output(dp, ifa);
		lck_rw_lock_shared(nd_if_rwlock);
		retrans = nd_ifinfo[ifa->ifa_ifp->if_index].retrans * hz / 1000;
		lck_rw_done(nd_if_rwlock);
		timeout((void (*)(void *))nd6_dad_timer, (void *)ifa, retrans);
	} else {
		int ntick;

		if (*tick_delay == 0)
			ntick = random() % (MAX_RTR_SOLICITATION_DELAY * hz);
		else
			ntick = *tick_delay + random() % (hz / 2);
		*tick_delay = ntick;
		timeout((void (*)(void *))nd6_dad_timer, (void *)ifa,
			ntick);
	}

	DAD_REMREF(dp);		/* drop our reference */
}

static struct dadq *
nd6_dad_attach(struct dadq *dp, struct ifaddr *ifa)
{
	lck_mtx_lock(dad6_mutex);
	DAD_LOCK(dp);
	dp->dad_ifa = ifa;
	IFA_ADDREF(ifa);	/* for dad_ifa */
	dp->dad_count = ip6_dad_count;
	dp->dad_ns_icount = dp->dad_na_icount = 0;
	dp->dad_ns_ocount = dp->dad_ns_tcount = 0;
	dp->dad_na_ixcount = 0;
	VERIFY(!dp->dad_attached);
	dp->dad_attached = 1;
	DAD_ADDREF_LOCKED(dp);	/* for caller */
	DAD_ADDREF_LOCKED(dp);	/* for dadq_head list */
	TAILQ_INSERT_TAIL(&dadq, (struct dadq *)dp, dad_list);
	DAD_UNLOCK(dp);
	lck_mtx_unlock(dad6_mutex);

	return (dp);
}

static void
nd6_dad_detach(struct dadq *dp, struct ifaddr *ifa)
{
	int detached;

	lck_mtx_lock(dad6_mutex);
	DAD_LOCK(dp);
	if ((detached = dp->dad_attached)) {
		VERIFY(dp->dad_ifa == ifa);
		TAILQ_REMOVE(&dadq, (struct dadq *)dp, dad_list);
		dp->dad_list.tqe_next = NULL;
		dp->dad_list.tqe_prev = NULL;
		dp->dad_attached = 0;
	}
	DAD_UNLOCK(dp);
	lck_mtx_unlock(dad6_mutex);
	if (detached) {
		DAD_REMREF(dp);		/* drop dadq_head reference */
	}
}

/*
 * terminate DAD unconditionally.  used for address removals.
 */
void
nd6_dad_stop(struct ifaddr *ifa)
{
	struct dadq *dp;

	dp = nd6_dad_find(ifa);
	if (!dp) {
		/* DAD wasn't started yet */
		return;
	}

	untimeout((void (*)(void *))nd6_dad_timer, (void *)ifa);

	nd6_dad_detach(dp, ifa);
	DAD_REMREF(dp);		/* drop our reference */
}


static void
nd6_unsol_na_output(struct ifaddr *ifa)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct ifnet *ifp = ifa->ifa_ifp;
	struct in6_addr saddr6, taddr6;

	if ((ifp->if_flags & IFF_UP) == 0 ||
	    (ifp->if_flags & IFF_RUNNING) == 0)
		return;

	IFA_LOCK_SPIN(&ia->ia_ifa);
	taddr6 = ia->ia_addr.sin6_addr;
	IFA_UNLOCK(&ia->ia_ifa);
	if (in6_setscope(&taddr6, ifp, NULL) != 0)
		return;
	saddr6 = in6addr_linklocal_allnodes;
	if (in6_setscope(&saddr6, ifp, NULL) != 0)
		return;

	nd6log((LOG_INFO, "%s: sending unsolicited NA\n",
	    if_name(ifa->ifa_ifp)));

	nd6_na_output(ifp, &saddr6, &taddr6, ND_NA_FLAG_OVERRIDE, 1, NULL);
}

static void
nd6_dad_timer(struct ifaddr *ifa)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct dadq *dp = NULL;

	/* Sanity check */
	if (ia == NULL) {
		log(LOG_ERR, "nd6_dad_timer: called with null parameter\n");
		goto done;
	}
	dp = nd6_dad_find(ifa);
	if (dp == NULL) {
		log(LOG_ERR, "nd6_dad_timer: DAD structure not found\n");
		goto done;
	}
	IFA_LOCK(&ia->ia_ifa);
	if (ia->ia6_flags & IN6_IFF_DUPLICATED) {
		log(LOG_ERR, "nd6_dad_timer: called with duplicated address "
			"%s(%s)\n",
			ip6_sprintf(&ia->ia_addr.sin6_addr),
			ifa->ifa_ifp ? if_name(ifa->ifa_ifp) : "???");
		IFA_UNLOCK(&ia->ia_ifa);
		goto done;
	}
	if ((ia->ia6_flags & IN6_IFF_TENTATIVE) == 0) {
		log(LOG_ERR, "nd6_dad_timer: called with non-tentative address "
			"%s(%s)\n",
			ip6_sprintf(&ia->ia_addr.sin6_addr),
			ifa->ifa_ifp ? if_name(ifa->ifa_ifp) : "???");
		IFA_UNLOCK(&ia->ia_ifa);
		goto done;
	}
	IFA_UNLOCK(&ia->ia_ifa);

	/* timeouted with IFF_{RUNNING,UP} check */
	DAD_LOCK(dp);
	if (dp->dad_ns_tcount > dad_maxtry) {
		DAD_UNLOCK(dp);
		nd6log((LOG_INFO, "%s: could not run DAD, driver problem?\n",
			if_name(ifa->ifa_ifp)));

		nd6_dad_detach(dp, ifa);
		goto done;
	}

	/* Need more checks? */
	if (dp->dad_ns_ocount < dp->dad_count) {
		u_int32_t retrans;
		DAD_UNLOCK(dp);
		/*
		 * We have more NS to go.  Send NS packet for DAD.
		 */
		nd6_dad_ns_output(dp, ifa);
		lck_rw_lock_shared(nd_if_rwlock);
		retrans = nd_ifinfo[ifa->ifa_ifp->if_index].retrans * hz / 1000;
		lck_rw_done(nd_if_rwlock);
		timeout((void (*)(void *))nd6_dad_timer, (void *)ifa, retrans);
	} else {
		/*
		 * We have transmitted sufficient number of DAD packets.
		 * See what we've got.
		 */
		int duplicate;

		duplicate = 0;

		if (dp->dad_na_icount) {
			/*
			 * the check is in nd6_dad_na_input(),
			 * but just in case
			 */
			duplicate++;
		}

		if (dp->dad_ns_icount) {
			/* We've seen NS, means DAD has failed. */
			duplicate++;
		}
		DAD_UNLOCK(dp);

		if (duplicate) {
			/* (*dp) will be freed in nd6_dad_duplicated() */
			nd6_dad_duplicated(ifa, TRUE);
		} else {
			/*
			 * We are done with DAD.  No NA came, no NS came.
			 * No duplicate address found.
			 */
			IFA_LOCK_SPIN(&ia->ia_ifa);
			ia->ia6_flags &= ~IN6_IFF_TENTATIVE;
			IFA_UNLOCK(&ia->ia_ifa);

			nd6log((LOG_DEBUG,
			    "%s: DAD complete for %s - no duplicates found\n",
			    if_name(ifa->ifa_ifp),
			    ip6_sprintf(&ia->ia_addr.sin6_addr)));
			/*
			 * Send an Unsolicited Neighbor Advertisement so that
			 * other machines on the network are aware of us
			 * (important when we are waking from sleep).
			 */
			nd6_unsol_na_output(ifa);
			in6_post_msg(ia->ia_ifp, KEV_INET6_NEW_USER_ADDR, ia);
			nd6_dad_detach(dp, ifa);
		}
	}

done:
	if (dp != NULL)
		DAD_REMREF(dp);		/* drop our reference */
}

void
nd6_dad_duplicated(struct ifaddr *ifa, boolean_t dontignhwdup)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct dadq *dp;
	struct ifnet *ifp = ifa->ifa_ifp;
	int hwdupposs;

	dp = nd6_dad_find(ifa);
	if (dp == NULL) {
		log(LOG_ERR, "nd6_dad_duplicated: DAD structure not found\n");
		return;
	}

	hwdupposs = 0;
	IFA_LOCK(&ia->ia_ifa);
	DAD_LOCK(dp);
	log(LOG_ERR, "%s: DAD detected duplicate IPv6 address %s: "
	    "NS in/out=%d/%d, NA in=%d inx=%d\n",
	    if_name(ifp), ip6_sprintf(&ia->ia_addr.sin6_addr),
	    dp->dad_ns_icount, dp->dad_ns_ocount, dp->dad_na_icount,
	    dp->dad_na_ixcount);
	hwdupposs = dp->dad_na_ixcount;
	DAD_UNLOCK(dp);
	ia->ia6_flags &= ~IN6_IFF_TENTATIVE;
	ia->ia6_flags |= IN6_IFF_DUPLICATED;
	IFA_UNLOCK(&ia->ia_ifa);

	/* We are done with DAD, with duplicated address found. (failure) */
	untimeout((void (*)(void *))nd6_dad_timer, (void *)ifa);

	IFA_LOCK(&ia->ia_ifa);
	log(LOG_ERR, "%s: DAD complete for %s - duplicate found\n",
	    if_name(ifp), ip6_sprintf(&ia->ia_addr.sin6_addr));
	log(LOG_ERR, "%s: manual intervention required\n",
	    if_name(ifp));
	IFA_UNLOCK(&ia->ia_ifa);
	
	if (hwdupposs ||
	    (dontignhwdup && IN6_IS_ADDR_LINKLOCAL(&ia->ia_addr.sin6_addr))) {
		log(LOG_ERR, "%s: possible hardware address duplication "
		    "detected, disable IPv6\n", if_name(ifp));
		
		lck_rw_lock_shared(nd_if_rwlock);
		nd_ifinfo[ifp->if_index].flags |=
		    ND6_IFF_IFDISABLED;
		lck_rw_done(nd_if_rwlock);
	}
	
	/* Send an event to the configuration agent so that the
	 * duplicate address will be notified to the user and will
	 * be removed.
	 */
	in6_post_msg(ifp, KEV_INET6_NEW_USER_ADDR, ia);
	nd6_dad_detach(dp, ifa);
	DAD_REMREF(dp);		/* drop our reference */
}

static void
nd6_dad_ns_output(struct dadq *dp, struct ifaddr *ifa)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct ifnet *ifp = ifa->ifa_ifp;
	struct in6_addr taddr6;

	DAD_LOCK(dp);
	dp->dad_ns_tcount++;
	if ((ifp->if_flags & IFF_UP) == 0) {
		DAD_UNLOCK(dp);
		return;
	}
	if ((ifp->if_flags & IFF_RUNNING) == 0) {
		DAD_UNLOCK(dp);
		return;
	}

	dp->dad_ns_ocount++;
	DAD_UNLOCK(dp);
	IFA_LOCK_SPIN(&ia->ia_ifa);
	taddr6 = ia->ia_addr.sin6_addr;
	IFA_UNLOCK(&ia->ia_ifa);
	nd6_ns_output(ifp, NULL, &taddr6, NULL, 1);
}

static void
nd6_dad_ns_input(struct ifaddr *ifa)
{
	struct dadq *dp;
	int duplicate;
	struct ifnet *ifp;

	if (ifa == NULL)
		panic("ifa == NULL in nd6_dad_ns_input");

	ifp = ifa->ifa_ifp;
	duplicate = 0;
	dp = nd6_dad_find(ifa);

	/* Quickhack - completely ignore DAD NS packets */
	if (dad_ignore_ns) {
		struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
		IFA_LOCK(&ia->ia_ifa);
		nd6log((LOG_INFO,
		    "nd6_dad_ns_input: ignoring DAD NS packet for "
		    "address %s(%s)\n", ip6_sprintf(&ia->ia_addr.sin6_addr),
		    if_name(ifa->ifa_ifp)));
		IFA_UNLOCK(&ia->ia_ifa);
		return;
	}

	/*
	 * if I'm yet to start DAD, someone else started using this address
	 * first.  I have a duplicate and you win.
	 */
	if (dp != NULL)
		DAD_LOCK(dp);
	if (dp == NULL || dp->dad_ns_ocount == 0)
		duplicate++;

	/* XXX more checks for loopback situation - see nd6_dad_timer too */

	if (duplicate) {
		if (dp != NULL) {
			DAD_UNLOCK(dp);
			DAD_REMREF(dp);
			dp = NULL;
		}
		nd6_dad_duplicated(ifa, TRUE);
	} else if (dp != NULL) {
		/*
		 * not sure if I got a duplicate.
		 * increment ns count and see what happens.
		 */
		dp->dad_ns_icount++;
		DAD_UNLOCK(dp);
		DAD_REMREF(dp);
	}
}

static void
nd6_dad_na_input(struct ifaddr *ifa, caddr_t lladdr, int lladdrlen)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct dadq *dp;
	int hwdupposs;

	if (ifa == NULL)
		panic("ifa == NULL in nd6_dad_na_input");

	dp = nd6_dad_find(ifa);
	if (dp == NULL) {
		log(LOG_ERR, "nd6_dad_na_input: DAD structure not found\n");
		return;
	}
	
	/*
	 * If the address is a link-local address formed from an interface
	 * identifier based on the hardware address which is supposed to be
	 * uniquely assigned (e.g., EUI-64 for an Ethernet interface), IP
	 * operation on the interface SHOULD be disabled according to RFC 4862,
	 * section 5.4.5, but here we decide not to disable if the target
	 * hardware address is not also ours, which is a transitory possibility
	 * in the presence of network-resident sleep proxies on the local link.
	 */
	hwdupposs = 0;
	IFA_LOCK(ifa);
	if (IN6_IS_ADDR_LINKLOCAL(&ia->ia_addr.sin6_addr)) {
		struct ifnet *ifp;
		struct in6_addr in6;
		
		IFA_UNLOCK(ifa);
		ifp = ifa->ifa_ifp;
		
		/*
		 * To avoid over-reaction, we only apply this logic when we are
		 * very sure that hardware addresses are supposed to be unique.
		 */
		switch (ifp->if_type) {
		case IFT_BRIDGE:
		case IFT_ETHER:
		case IFT_FDDI:
		case IFT_ATM:
		case IFT_IEEE1394:
#ifdef IFT_IEEE80211
		case IFT_IEEE80211:
#endif
			/* Check if our hardware address matches the target */
			if (lladdr != NULL && lladdrlen > 0) {
				struct ifaddr *llifa;
				struct sockaddr_dl *sdl;
				
				llifa = ifp->if_lladdr;
				IFA_LOCK(llifa);
				sdl = (struct sockaddr_dl *)llifa->ifa_addr;
				if (lladdrlen == sdl->sdl_alen ||
				    bcmp(lladdr, LLADDR(sdl), lladdrlen) == 0)
					hwdupposs = 1;
				IFA_UNLOCK(llifa);
			}
			in6 = ia->ia_addr.sin6_addr;
			if (in6_get_hw_ifid(ifp, &in6) != 0)
				break;
			/*
			 * Apply this logic only to the EUI-64 form of
			 * link-local interface identifiers.
			 */
			IFA_LOCK(ifa);
			if (hwdupposs &&
			    !IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr, &in6)) {
				hwdupposs = 0;
			} else if (lladdr == NULL &&
			    IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr, &in6)) {
				/*
				 * We received a NA with no target link-layer
				 * address option. This means that someone else
				 * has our address. Mark it as a hardware
				 * duplicate so we disable IPv6 later on.
				 */
				hwdupposs = 1;
			}
			IFA_UNLOCK(ifa);
			break;
		default:
			break;
		}
	} else {
		IFA_UNLOCK(ifa);
	}
	
	DAD_LOCK_SPIN(dp);
	dp->dad_na_icount++;
	if (hwdupposs)
		dp->dad_na_ixcount++;
	DAD_UNLOCK(dp);
	DAD_REMREF(dp);
	
	/* remove the address. */
	nd6_dad_duplicated(ifa, FALSE);
}

static void
dad_addref(struct dadq *dp, int locked)
{
	if (!locked)
		DAD_LOCK_SPIN(dp);
	else
		DAD_LOCK_ASSERT_HELD(dp);

	if (++dp->dad_refcount == 0) {
		panic("%s: dad %p wraparound refcnt\n", __func__, dp);
		/* NOTREACHED */
	}
	if (!locked)
		DAD_UNLOCK(dp);
}

static void
dad_remref(struct dadq *dp)
{
	struct ifaddr *ifa;

	DAD_LOCK_SPIN(dp);
	if (dp->dad_refcount == 0)
		panic("%s: dad %p negative refcnt\n", __func__, dp);
	--dp->dad_refcount;
	if (dp->dad_refcount > 0) {
		DAD_UNLOCK(dp);
		return;
	}
	DAD_UNLOCK(dp);

	if (dp->dad_attached ||
	    dp->dad_list.tqe_next != NULL || dp->dad_list.tqe_prev != NULL) {
		panic("%s: attached dad=%p is being freed", __func__, dp);
		/* NOTREACHED */
	}

	if ((ifa = dp->dad_ifa) != NULL) {
		IFA_REMREF(ifa);	/* drop dad_ifa reference */
		dp->dad_ifa = NULL;
	}

	lck_mtx_destroy(&dp->dad_lock, ifa_mtx_grp);
	zfree(dad_zone, dp);
}

void
nd6_llreach_set_reachable(struct ifnet *ifp, void *addr, unsigned int alen)
{
	/* Nothing more to do if it's disabled */
	if (nd6_llreach_base == 0)
		return;

	ifnet_llreach_set_reachable(ifp, ETHERTYPE_IPV6, addr, alen);
}
