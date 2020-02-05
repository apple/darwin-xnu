/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
#include <dev/random/randomdev.h>

#include <kern/locks.h>
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_llreach.h>
#include <net/route.h>
#include <net/dlil.h>
#include <net/nwk_wq.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_ifattach.h>
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
#endif

struct dadq;
static struct dadq *nd6_dad_find(struct ifaddr *, struct nd_opt_nonce *);
void nd6_dad_stoptimer(struct ifaddr *);
static void nd6_dad_timer(struct ifaddr *);
static void nd6_dad_ns_output(struct dadq *, struct ifaddr *);
static void nd6_dad_ns_input(struct ifaddr *, char *, int, struct nd_opt_nonce *);
static struct mbuf *nd6_dad_na_input(struct mbuf *, struct ifnet *,
    struct in6_addr *, caddr_t, int);
static void dad_addref(struct dadq *, int);
static void dad_remref(struct dadq *);
static struct dadq *nd6_dad_attach(struct dadq *, struct ifaddr *);
static void nd6_dad_detach(struct dadq *, struct ifaddr *);

static int dad_maxtry = 15;     /* max # of *tries* to transmit DAD packet */

static unsigned int dad_size;                   /* size of zone element */
static struct zone *dad_zone;                   /* zone for dadq */

#define DAD_ZONE_MAX    64                      /* maximum elements in zone */
#define DAD_ZONE_NAME   "nd6_dad"               /* zone name */

#define DAD_LOCK_ASSERT_HELD(_dp)                                       \
	LCK_MTX_ASSERT(&(_dp)->dad_lock, LCK_MTX_ASSERT_OWNED)

#define DAD_LOCK_ASSERT_NOTHELD(_dp)                                    \
	LCK_MTX_ASSERT(&(_dp)->dad_lock, LCK_MTX_ASSERT_NOTOWNED)

#define DAD_LOCK(_dp)                                                   \
	lck_mtx_lock(&(_dp)->dad_lock)

#define DAD_LOCK_SPIN(_dp)                                              \
	lck_mtx_lock_spin(&(_dp)->dad_lock)

#define DAD_CONVERT_LOCK(_dp) do {                                      \
	DAD_LOCK_ASSERT_HELD(_dp);                                      \
	lck_mtx_convert_spin(&(_dp)->dad_lock);                         \
} while (0)

#define DAD_UNLOCK(_dp)                                                 \
	lck_mtx_unlock(&(_dp)->dad_lock)

#define DAD_ADDREF(_dp)                                                 \
	dad_addref(_dp, 0)

#define DAD_ADDREF_LOCKED(_dp)                                          \
	dad_addref(_dp, 1)

#define DAD_REMREF(_dp)                                                 \
	dad_remref(_dp)

extern lck_mtx_t *dad6_mutex;
extern lck_mtx_t *nd6_mutex;

static int nd6_llreach_base = 30;        /* seconds */

static struct sockaddr_in6 hostrtmask;

SYSCTL_DECL(_net_inet6_icmp6);
SYSCTL_INT(_net_inet6_icmp6, OID_AUTO, nd6_llreach_base,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nd6_llreach_base, 0,
    "default ND6 link-layer reachability max lifetime (in seconds)");

int dad_enhanced = 1;
SYSCTL_DECL(_net_inet6_ip6);
SYSCTL_INT(_net_inet6_ip6, OID_AUTO, dad_enhanced, CTLFLAG_RW | CTLFLAG_LOCKED,
    &dad_enhanced, 0,
    "Enable Enhanced DAD, which adds a random nonce to NS messages for DAD.");

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
	    (ln->ln_expire != 0 || (ifp->if_eflags & IFEF_IPV6_ND6ALT) != 0) &&
	    !(rt->rt_ifp->if_flags & IFF_LOOPBACK) &&
	    ifp->if_addrlen == IF_LLREACH_MAXLEN &&     /* Ethernet */
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
				lr->lr_probes = 0;      /* reset probe count */
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
				lr->lr_probes = 0;      /* reset probe count */
				if (why == NULL) {
					why = "creating new llreach record";
				}
			}
		}

		if (nd6_debug && lr != NULL && why != NULL) {
			char tmp[MAX_IPv6_STR_LEN];

			nd6log(debug, "%s: %s%s for %s\n", if_name(ifp),
			    type, why, inet_ntop(AF_INET6,
			    &SIN6(rt_key(rt))->sin6_addr, tmp, sizeof(tmp)));
		}
	}
}

void
nd6_llreach_use(struct llinfo_nd6 *ln)
{
	if (ln->ln_llreach != NULL) {
		ln->ln_lastused = net_uptime();
	}
}

/*
 * Input a Neighbor Solicitation Message.
 *
 * Based on RFC 4861
 * Based on RFC 4862 (duplicate address detection)
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
	int anycast = 0, proxy = 0, dadprogress = 0;
	int tlladdr;
	union nd_opts ndopts;
	struct sockaddr_dl proxydl;
	boolean_t advrouter;
	boolean_t is_dad_probe;
	int oflgclr = 0;

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	IP6_EXTHDR_CHECK(m, off, icmp6len, return );
	nd_ns = (struct nd_neighbor_solicit *)((caddr_t)ip6 + off);
	m->m_pkthdr.pkt_flags |= PKTF_INET6_RESOLVE;

	ip6 = mtod(m, struct ip6_hdr *); /* adjust pointer for safety */
	taddr6 = nd_ns->nd_ns_target;
	if (in6_setscope(&taddr6, ifp, NULL) != 0) {
		goto bad;
	}

	if (ip6->ip6_hlim != IPV6_MAXHLIM) {
		nd6log(error,
		    "nd6_ns_input: invalid hlim (%d) from %s to %s on %s\n",
		    ip6->ip6_hlim, ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst), if_name(ifp));
		goto bad;
	}

	is_dad_probe = IN6_IS_ADDR_UNSPECIFIED(&saddr6);
	if (is_dad_probe) {
		/* dst has to be a solicited node multicast address. */
		if (daddr6.s6_addr16[0] == IPV6_ADDR_INT16_MLL &&
		    /* don't check ifindex portion */
		    daddr6.s6_addr32[1] == 0 &&
		    daddr6.s6_addr32[2] == IPV6_ADDR_INT32_ONE &&
		    daddr6.s6_addr8[12] == 0xff) {
			; /* good */
		} else {
			nd6log(info, "nd6_ns_input: bad DAD packet "
			    "(wrong ip6 dst)\n");
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
			nd6log(info, "nd6_ns_input: "
			    "NS packet from non-neighbor\n");
			goto bad;
		}
	}

	if (IN6_IS_ADDR_MULTICAST(&taddr6)) {
		nd6log(info, "nd6_ns_input: bad NS target (multicast)\n");
		goto bad;
	}

	icmp6len -= sizeof(*nd_ns);
	nd6_option_init(nd_ns + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log(info,
		    "nd6_ns_input: invalid ND option, ignored\n");
		/* nd6_options have incremented stats */
		goto freeit;
	}

	if (ndopts.nd_opts_src_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_src_lladdr + 1);
		lladdrlen = ndopts.nd_opts_src_lladdr->nd_opt_len << 3;
	}

	if (is_dad_probe && lladdr) {
		nd6log(info, "nd6_ns_input: bad DAD packet "
		    "(link-layer address option)\n");
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
	if (!IN6_IS_ADDR_MULTICAST(&daddr6)) {
		tlladdr = 0;
	} else {
		tlladdr = 1;
	}

	/*
	 * Target address (taddr6) must be either:
	 * (1) Valid unicast/anycast address for my receiving interface,
	 * (2) Unicast address for which I'm offering proxy service, or
	 * (3) "tentative" or "optimistic" address [DAD is in progress].
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
					ifp, IN6_IFF_NOTREADY | IN6_IFF_ANYCAST);
				if (ifa) {
					proxy = 1;
					proxydl = *SDL(rt->rt_gateway);
				}
			}
			RT_UNLOCK(rt);
			rtfree(rt);
		}
	}
	if (ifa == NULL && ip6_forwarding && nd6_prproxy) {
		/*
		 * Is the target address part of the prefix that is being
		 * proxied and installed on another interface?
		 */
		ifa = (struct ifaddr *)in6ifa_prproxyaddr(&taddr6);
	}
	if (ifa == NULL) {
		/*
		 * We've got an NS packet, and we don't have that address
		 * assigned for us.  We MUST silently ignore it on this
		 * interface, c.f. RFC 4861 7.2.3.
		 *
		 * Forwarding associated with NDPRF_PRPROXY may apply.
		 */
		if (ip6_forwarding && nd6_prproxy) {
			nd6_prproxy_ns_input(ifp, &saddr6, lladdr,
			    lladdrlen, &daddr6, &taddr6,
			    (ndopts.nd_opts_nonce == NULL) ? NULL :
			    ndopts.nd_opts_nonce->nd_opt_nonce);
		}
		goto freeit;
	}
	IFA_LOCK(ifa);
	myaddr6 = *IFA_IN6(ifa);
	anycast = ((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_ANYCAST;
	dadprogress =
	    ((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DADPROGRESS;
	if (((struct in6_ifaddr *)ifa)->ia6_flags & IN6_IFF_DUPLICATED) {
		IFA_UNLOCK(ifa);
		goto freeit;
	}
	IFA_UNLOCK(ifa);

	if (lladdr && ((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
		nd6log(info,
		    "nd6_ns_input: lladdrlen mismatch for %s "
		    "(if %d, NS packet %d)\n",
		    ip6_sprintf(&taddr6), ifp->if_addrlen, lladdrlen - 2);
		goto bad;
	}

	if (IN6_ARE_ADDR_EQUAL(&myaddr6, &saddr6)) {
		nd6log(info,
		    "nd6_ns_input: duplicate IP6 address %s\n",
		    ip6_sprintf(&saddr6));
		goto freeit;
	}

	/*
	 * We have neighbor solicitation packet, with target address equals to
	 * one of my DAD in-progress addresses.
	 *
	 * src addr	how to process?
	 * ---		---
	 * multicast	of course, invalid (rejected in ip6_input)
	 * unicast	somebody is doing address resolution
	 * unspec	dup address detection
	 *
	 * The processing is defined in the "draft standard" RFC 4862 (and by
	 * RFC 4429, which is a "proposed standard" update to its obsolete
	 * predecessor, RFC 2462)  The reason optimistic DAD is not included
	 * in RFC 4862 is entirely due to IETF procedural considerations.
	 */
	if (dadprogress) {
		/*
		 * If source address is unspecified address, it is for
		 * duplicate address detection.
		 *
		 * If not, the packet is for addess resolution;
		 * silently ignore it when not optimistic
		 *
		 * Per RFC 4429 the reply for an optimistic address must
		 * have the Override flag cleared
		 */
		if (!is_dad_probe && (dadprogress & IN6_IFF_OPTIMISTIC) != 0) {
			oflgclr = 1;
		} else {
			if (is_dad_probe) {
				nd6_dad_ns_input(ifa, lladdr, lladdrlen, ndopts.nd_opts_nonce);
			}

			goto freeit;
		}
	}

	/* Are we an advertising router on this interface? */
	advrouter = (ifp->if_eflags & IFEF_IPV6_ROUTER);

	/*
	 * If the source address is unspecified address, entries must not
	 * be created or updated.
	 * It looks that sender is performing DAD.  If I'm using the address,
	 * and it's a "preferred" address, i.e. not optimistic, then output NA
	 * toward all-node multicast address, to tell the sender that I'm using
	 * the address.
	 * S bit ("solicited") must be zero.
	 */
	if (is_dad_probe) {
		saddr6 = in6addr_linklocal_allnodes;
		if (in6_setscope(&saddr6, ifp, NULL) != 0) {
			goto bad;
		}
		if ((dadprogress & IN6_IFF_OPTIMISTIC) == 0) {
			nd6_na_output(ifp, &saddr6, &taddr6,
			    ((anycast || proxy || !tlladdr) ? 0 :
			    ND_NA_FLAG_OVERRIDE) | (advrouter ?
			    ND_NA_FLAG_ROUTER : 0), tlladdr, proxy ?
			    (struct sockaddr *)&proxydl : NULL);
		}
		goto freeit;
	}

	nd6_cache_lladdr(ifp, &saddr6, lladdr, lladdrlen,
	    ND_NEIGHBOR_SOLICIT, 0);

	nd6_na_output(ifp, &saddr6, &taddr6,
	    ((anycast || proxy || !tlladdr || oflgclr) ? 0 : ND_NA_FLAG_OVERRIDE) |
	    (advrouter ? ND_NA_FLAG_ROUTER : 0) | ND_NA_FLAG_SOLICITED,
	    tlladdr, proxy ? (struct sockaddr *)&proxydl : NULL);
freeit:
	m_freem(m);
	if (ifa != NULL) {
		IFA_REMREF(ifa);
	}
	return;

bad:
	nd6log(error, "nd6_ns_input: src=%s\n", ip6_sprintf(&saddr6));
	nd6log(error, "nd6_ns_input: dst=%s\n", ip6_sprintf(&daddr6));
	nd6log(error, "nd6_ns_input: tgt=%s\n", ip6_sprintf(&taddr6));
	icmp6stat.icp6s_badns++;
	m_freem(m);
	if (ifa != NULL) {
		IFA_REMREF(ifa);
	}
}

/*
 * Output a Neighbor Solicitation Message. Caller specifies:
 *	- ICMP6 header source IP6 address
 *	- ND6 header target IP6 address
 *	- ND6 header source datalink address
 *
 * Based on RFC 4861
 * Based on RFC 4862 (duplicate address detection)
 * Based on RFC 4429 (optimistic duplicate address detection)
 *
 * Caller must bump up ln->ln_rt refcnt to make sure 'ln' doesn't go
 * away if there is a llinfo_nd6 passed in.
 */
void
nd6_ns_output(
	struct ifnet *ifp,
	const struct in6_addr *daddr6,
	const struct in6_addr *taddr6,
	struct llinfo_nd6 *ln,  /* for source address determination */
	uint8_t *nonce) /* duplicated address detection */
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
	struct ip6_out_args ip6oa;
	u_int32_t rtflags = 0;

	if ((ifp->if_eflags & IFEF_IPV6_ND6ALT) || IN6_IS_ADDR_MULTICAST(taddr6)) {
		return;
	}

	bzero(&ro, sizeof(ro));
	bzero(&ip6oa, sizeof(ip6oa));
	ip6oa.ip6oa_boundif = ifp->if_index;
	ip6oa.ip6oa_flags = IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR |
	    IP6OAF_AWDL_UNRESTRICTED | IP6OAF_INTCOPROC_ALLOWED;
	ip6oa.ip6oa_sotc = SO_TC_UNSPEC;
	ip6oa.ip6oa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

	ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;

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

	MGETHDR(m, M_DONTWAIT, MT_DATA);        /* XXXMAC: mac_create_mbuf_linklayer() probably */
	if (m && max_linkhdr + maxlen >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL) {
		return;
	}
	m->m_pkthdr.rcvif = NULL;

	if (daddr6 == NULL || IN6_IS_ADDR_MULTICAST(daddr6)) {
		m->m_flags |= M_MCAST;

		im6o = ip6_allocmoptions(M_DONTWAIT);
		if (im6o == NULL) {
			m_freem(m);
			return;
		}

		im6o->im6o_multicast_ifp = ifp;
		im6o->im6o_multicast_hlim = IPV6_MAXHLIM;
		im6o->im6o_multicast_loop = 0;
	}

	icmp6len = sizeof(*nd_ns);
	m->m_pkthdr.len = m->m_len = sizeof(*ip6) + icmp6len;
	m->m_data += max_linkhdr;       /* or MH_ALIGN() equivalent? */

	/* fill neighbor solicitation packet */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	/* ip6->ip6_plen will be set later */
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = IPV6_MAXHLIM;
	if (daddr6) {
		ip6->ip6_dst = *daddr6;
	} else {
		ip6->ip6_dst.s6_addr16[0] = IPV6_ADDR_INT16_MLL;
		ip6->ip6_dst.s6_addr16[1] = 0;
		ip6->ip6_dst.s6_addr32[1] = 0;
		ip6->ip6_dst.s6_addr32[2] = IPV6_ADDR_INT32_ONE;
		ip6->ip6_dst.s6_addr32[3] = taddr6->s6_addr32[3];
		ip6->ip6_dst.s6_addr8[12] = 0xff;
		if (in6_setscope(&ip6->ip6_dst, ifp, NULL) != 0) {
			goto bad;
		}
	}
	if (nonce == NULL) {
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
		struct ip6_hdr *hip6;           /* hold ip6 */
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
				if (sizeof(*hip6) < ln->ln_hold->m_len) {
					hsrc = &hip6->ip6_src;
				} else {
					hsrc = NULL;
				}
			}
			/* Update probe count, if applicable */
			if (ln->ln_llreach != NULL) {
				IFLR_LOCK_SPIN(ln->ln_llreach);
				ln->ln_llreach->lr_probes++;
				IFLR_UNLOCK(ln->ln_llreach);
			}
			rtflags = ln->ln_rt->rt_flags;
			RT_UNLOCK(ln->ln_rt);
		}
		if (hsrc != NULL && (ia = in6ifa_ifpwithaddr(ifp, hsrc)) &&
		    (ia->ia6_flags & IN6_IFF_OPTIMISTIC) == 0) {
			src = hsrc;
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
				nd6log(debug,
				    "nd6_ns_output: source can't be "
				    "determined: dst=%s, error=%d\n",
				    ip6_sprintf(&dst_sa.sin6_addr),
				    error);
				goto bad;
			}

			if (ia != NULL) {
				IFA_REMREF(&ia->ia_ifa);
				ia = NULL;
			}
			/*
			 * RFC 4429 section 3.2:
			 * When a node has a unicast packet to send
			 * from an Optimistic Address to a neighbor,
			 * but does not know the neighbor's link-layer
			 * address, it MUST NOT perform Address
			 * Resolution.
			 */
			ia = in6ifa_ifpwithaddr(ifp, src);
			if (!ia || (ia->ia6_flags & IN6_IFF_OPTIMISTIC)) {
				nd6log(debug,
				    "nd6_ns_output: no preferred source "
				    "available: dst=%s\n",
				    ip6_sprintf(&dst_sa.sin6_addr));
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
		ip6oa.ip6oa_flags &= ~IP6OAF_BOUND_SRCADDR;
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
	if (nonce == NULL && (mac = nd6_ifptomac(ifp))) {
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
	/*
	 * Add a Nonce option (RFC 3971) to detect looped back NS messages.
	 * This behavior is documented as Enhanced Duplicate Address
	 * Detection in draft-ietf-6man-enhanced-dad-13.
	 * net.inet6.ip6.dad_enhanced=0 disables this.
	 */
	if (dad_enhanced != 0 && nonce != NULL && !(ifp->if_flags & IFF_POINTOPOINT)) {
		int optlen = sizeof(struct nd_opt_hdr) + ND_OPT_NONCE_LEN;
		struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(nd_ns + 1);
		/* 8-byte alignment is required. */
		optlen = (optlen + 7) & ~7;

		m->m_pkthdr.len += optlen;
		m->m_len += optlen;
		icmp6len += optlen;
		bzero((caddr_t)nd_opt, optlen);
		nd_opt->nd_opt_type = ND_OPT_NONCE;
		nd_opt->nd_opt_len = optlen >> 3;
		bcopy(nonce, (caddr_t)(nd_opt + 1), ND_OPT_NONCE_LEN);
	}
	ip6->ip6_plen = htons((u_short)icmp6len);
	nd_ns->nd_ns_cksum = 0;
	nd_ns->nd_ns_cksum
	        = in6_cksum(m, IPPROTO_ICMPV6, sizeof(*ip6), icmp6len);

	flags = nonce ? IPV6_UNSPECSRC : 0;
	flags |= IPV6_OUTARGS;

	/*
	 * PKTF_{INET,INET6}_RESOLVE_RTR are mutually exclusive, so make
	 * sure only one of them is set (just in case.)
	 */
	m->m_pkthdr.pkt_flags &= ~(PKTF_INET_RESOLVE | PKTF_RESOLVE_RTR);
	m->m_pkthdr.pkt_flags |= PKTF_INET6_RESOLVE;
	/*
	 * If this is a NS for resolving the (default) router, mark
	 * the packet accordingly so that the driver can find out,
	 * in case it needs to perform driver-specific action(s).
	 */
	if (rtflags & RTF_ROUTER) {
		m->m_pkthdr.pkt_flags |= PKTF_RESOLVE_RTR;
	}

	if (ifp->if_eflags & IFEF_TXSTART) {
		/*
		 * Use control service class if the interface
		 * supports transmit-start model
		 */
		(void) m_set_service_class(m, MBUF_SC_CTL);
	}

	ip6oa.ip6oa_flags |= IP6OAF_SKIP_PF;
	ip6_output(m, NULL, NULL, flags, im6o, &outif, &ip6oa);
	if (outif) {
		icmp6_ifstat_inc(outif, ifs6_out_msg);
		icmp6_ifstat_inc(outif, ifs6_out_neighborsolicit);
		ifnet_release(outif);
	}
	icmp6stat.icp6s_outhist[ND_NEIGHBOR_SOLICIT]++;

exit:
	if (im6o != NULL) {
		IM6O_REMREF(im6o);
	}

	ROUTE_RELEASE(&ro);     /* we don't cache this route. */

	if (ia != NULL) {
		IFA_REMREF(&ia->ia_ifa);
	}
	return;

bad:
	m_freem(m);
	goto exit;
}

/*
 * Neighbor advertisement input handling.
 *
 * Based on RFC 4861
 * Based on RFC 4862 (duplicate address detection)
 *
 * the following items are not implemented yet:
 * - anycast advertisement delay rule (RFC 4861 7.2.7, SHOULD)
 * - proxy advertisement delay rule (RFC 4861 7.2.8, last paragraph, "should")
 */
void
nd6_na_input(struct mbuf *m, int off, int icmp6len)
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct nd_neighbor_advert *nd_na;
	struct in6_addr saddr6 = ip6->ip6_src;
	struct in6_addr daddr6 = ip6->ip6_dst;
	struct in6_addr taddr6;
	int flags;
	int is_router;
	int is_solicited;
	int is_override;
	char *lladdr = NULL;
	int lladdrlen = 0;
	struct llinfo_nd6 *ln;
	struct rtentry *rt;
	struct sockaddr_dl *sdl;
	union nd_opts ndopts;
	uint64_t timenow;
	bool send_nc_alive_kev = false;

	if ((ifp->if_eflags & IFEF_IPV6_ND6ALT) != 0) {
		nd6log(info, "nd6_na_input: on ND6ALT interface!\n");
		goto freeit;
	}

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	if (ip6->ip6_hlim != IPV6_MAXHLIM) {
		nd6log(error,
		    "nd6_na_input: invalid hlim (%d) from %s to %s on %s\n",
		    ip6->ip6_hlim, ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst), if_name(ifp));
		goto bad;
	}

	IP6_EXTHDR_CHECK(m, off, icmp6len, return );
	nd_na = (struct nd_neighbor_advert *)((caddr_t)ip6 + off);
	m->m_pkthdr.pkt_flags |= PKTF_INET6_RESOLVE;

	flags = nd_na->nd_na_flags_reserved;
	is_router = ((flags & ND_NA_FLAG_ROUTER) != 0);
	is_solicited = ((flags & ND_NA_FLAG_SOLICITED) != 0);
	is_override = ((flags & ND_NA_FLAG_OVERRIDE) != 0);

	taddr6 = nd_na->nd_na_target;
	if (in6_setscope(&taddr6, ifp, NULL)) {
		goto bad;       /* XXX: impossible */
	}
	if (IN6_IS_ADDR_MULTICAST(&taddr6)) {
		nd6log(error,
		    "nd6_na_input: invalid target address %s\n",
		    ip6_sprintf(&taddr6));
		goto bad;
	}
	if (IN6_IS_ADDR_MULTICAST(&daddr6)) {
		if (is_solicited) {
			nd6log(error,
			    "nd6_na_input: a solicited adv is multicasted\n");
			goto bad;
		}
	}

	icmp6len -= sizeof(*nd_na);
	nd6_option_init(nd_na + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		nd6log(info,
		    "nd6_na_input: invalid ND option, ignored\n");
		/* nd6_options have incremented stats */
		goto freeit;
	}

	if (ndopts.nd_opts_tgt_lladdr) {
		lladdr = (char *)(ndopts.nd_opts_tgt_lladdr + 1);
		lladdrlen = ndopts.nd_opts_tgt_lladdr->nd_opt_len << 3;

		if (((ifp->if_addrlen + 2 + 7) & ~7) != lladdrlen) {
			nd6log(info,
			    "nd6_na_input: lladdrlen mismatch for %s "
			    "(if %d, NA packet %d)\n",
			    ip6_sprintf(&taddr6), ifp->if_addrlen,
			    lladdrlen - 2);
			goto bad;
		}
	}

	m = nd6_dad_na_input(m, ifp, &taddr6, lladdr, lladdrlen);
	if (m == NULL) {
		return;
	}

	/* Forwarding associated with NDPRF_PRPROXY may apply. */
	if (ip6_forwarding && nd6_prproxy) {
		nd6_prproxy_na_input(ifp, &saddr6, &daddr6, &taddr6, flags);
	}

	/*
	 * If no neighbor cache entry is found, NA SHOULD silently be
	 * discarded.  If we are forwarding (and Scoped Routing is in
	 * effect), try to see if there is a neighbor cache entry on
	 * another interface (in case we are doing prefix proxying.)
	 */
	if ((rt = nd6_lookup(&taddr6, 0, ifp, 0)) == NULL) {
		if (!ip6_forwarding || !nd6_prproxy) {
			goto freeit;
		}

		if ((rt = nd6_lookup(&taddr6, 0, NULL, 0)) == NULL) {
			goto freeit;
		}

		RT_LOCK_ASSERT_HELD(rt);
		if (rt->rt_ifp != ifp) {
			/*
			 * Purge any link-layer info caching.
			 */
			if (rt->rt_llinfo_purge != NULL) {
				rt->rt_llinfo_purge(rt);
			}

			/* Adjust route ref count for the interfaces */
			if (rt->rt_if_ref_fn != NULL) {
				rt->rt_if_ref_fn(ifp, 1);
				rt->rt_if_ref_fn(rt->rt_ifp, -1);
			}

			/* Change the interface when the existing route is on */
			rt->rt_ifp = ifp;

			/*
			 * If rmx_mtu is not locked, update it
			 * to the MTU used by the new interface.
			 */
			if (!(rt->rt_rmx.rmx_locks & RTV_MTU)) {
				rt->rt_rmx.rmx_mtu = rt->rt_ifp->if_mtu;
			}
		}
	}

	RT_LOCK_ASSERT_HELD(rt);
	if ((ln = rt->rt_llinfo) == NULL ||
	    (sdl = SDL(rt->rt_gateway)) == NULL) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		goto freeit;
	}

	timenow = net_uptime();

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
			send_nc_alive_kev = (rt->rt_flags & RTF_ROUTER) ? true : false;
			ND6_CACHE_STATE_TRANSITION(ln, ND6_LLINFO_REACHABLE);
			if (ln->ln_expire != 0) {
				struct nd_ifinfo *ndi = NULL;

				ndi = ND_IFINFO(rt->rt_ifp);
				VERIFY(ndi != NULL && ndi->initialized);
				lck_mtx_lock(&ndi->lock);
				ln_setexpire(ln, timenow + ndi->reachable);
				lck_mtx_unlock(&ndi->lock);
				RT_UNLOCK(rt);
				lck_mtx_lock(rnh_lock);
				nd6_sched_timeout(NULL, NULL);
				lck_mtx_unlock(rnh_lock);
				RT_LOCK(rt);
			}
		} else {
			ND6_CACHE_STATE_TRANSITION(ln, ND6_LLINFO_STALE);
			ln_setexpire(ln, timenow + nd6_gctimer);
		}


		/*
		 * Enqueue work item to invoke callback for this
		 * route entry
		 */
		route_event_enqueue_nwk_wq_entry(rt, NULL,
		    ROUTE_LLENTRY_RESOLVED, NULL, TRUE);

		if ((ln->ln_router = is_router) != 0) {
			struct radix_node_head  *rnh = NULL;
			struct route_event rt_ev;
			route_event_init(&rt_ev, rt, NULL, ROUTE_LLENTRY_RESOLVED);
			/*
			 * This means a router's state has changed from
			 * non-reachable to probably reachable, and might
			 * affect the status of associated prefixes..
			 * We already have a reference on rt. Don't need to
			 * take one for the unlock/lock.
			 */
			RT_UNLOCK(rt);
			lck_mtx_lock(rnh_lock);
			rnh = rt_tables[AF_INET6];

			if (rnh != NULL) {
				(void) rnh->rnh_walktree(rnh, route_event_walktree,
				    (void *)&rt_ev);
			}
			lck_mtx_unlock(rnh_lock);
			lck_mtx_lock(nd6_mutex);
			pfxlist_onlink_check();
			lck_mtx_unlock(nd6_mutex);
			RT_LOCK(rt);
		}
	} else {
		int llchange = 0;

		/*
		 * Check if the link-layer address has changed or not.
		 */
		if (lladdr == NULL) {
			llchange = 0;
		} else {
			if (sdl->sdl_alen) {
				if (bcmp(lladdr, LLADDR(sdl), ifp->if_addrlen)) {
					llchange = 1;
				} else {
					llchange = 0;
				}
			} else {
				llchange = 1;
			}
		}

		/*
		 * This is VERY complex. Look at it with care.
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
				ND6_CACHE_STATE_TRANSITION(ln, ND6_LLINFO_STALE);
				ln_setexpire(ln, timenow + nd6_gctimer);
			}
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			goto freeit;
		} else if (is_override                             /* (2a) */
		    || (!is_override && (lladdr && !llchange))     /* (2b) */
		    || !lladdr) {                                  /* (2c) */
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
				ND6_CACHE_STATE_TRANSITION(ln, ND6_LLINFO_REACHABLE);
				if (ln->ln_expire != 0) {
					struct nd_ifinfo *ndi = NULL;

					ndi = ND_IFINFO(ifp);
					VERIFY(ndi != NULL && ndi->initialized);
					lck_mtx_lock(&ndi->lock);
					ln_setexpire(ln,
					    timenow + ndi->reachable);
					lck_mtx_unlock(&ndi->lock);
					RT_UNLOCK(rt);
					lck_mtx_lock(rnh_lock);
					nd6_sched_timeout(NULL, NULL);
					lck_mtx_unlock(rnh_lock);
					RT_LOCK(rt);
				}
			} else {
				if (lladdr && llchange) {
					ND6_CACHE_STATE_TRANSITION(ln, ND6_LLINFO_STALE);
					ln_setexpire(ln, timenow + nd6_gctimer);
				}
			}

			/*
			 * XXX
			 * The above is somewhat convoluted, for now just
			 * issue a callback for LLENTRY changed.
			 */
			/* Enqueue work item to invoke callback for this route entry */
			if (llchange) {
				route_event_enqueue_nwk_wq_entry(rt, NULL,
				    ROUTE_LLENTRY_CHANGED, NULL, TRUE);
			}

			/*
			 * If the router's link-layer address has changed,
			 * notify routes using this as gateway so they can
			 * update any cached information.
			 */
			if (ln->ln_router && is_router && llchange) {
				struct radix_node_head  *rnh = NULL;
				struct route_event rt_ev;
				route_event_init(&rt_ev, rt, NULL, ROUTE_LLENTRY_CHANGED);
				/*
				 * This means a router's state has changed from
				 * non-reachable to probably reachable, and might
				 * affect the status of associated prefixes..
				 *
				 * We already have a valid rt reference here.
				 * We don't need to take another one for unlock/lock.
				 */
				RT_UNLOCK(rt);
				lck_mtx_lock(rnh_lock);
				rnh = rt_tables[AF_INET6];

				if (rnh != NULL) {
					(void) rnh->rnh_walktree(rnh, route_event_walktree,
					    (void *)&rt_ev);
				}
				lck_mtx_unlock(rnh_lock);
				RT_LOCK(rt);
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

			in6 = &((struct sockaddr_in6 *)
			    (void *)rt_key(rt))->sin6_addr;

			RT_UNLOCK(rt);
			lck_mtx_lock(nd6_mutex);
			dr = defrouter_lookup(in6, rt_ifp);
			if (dr) {
				TAILQ_REMOVE(&nd_defrouter, dr, dr_entry);
				defrtrlist_del(dr);
				NDDR_REMREF(dr);        /* remove list reference */
				NDDR_REMREF(dr);
				lck_mtx_unlock(nd6_mutex);
			} else {
				lck_mtx_unlock(nd6_mutex);
				/*
				 * Even if the neighbor is not in the
				 * default router list, the neighbor
				 * may be used as a next hop for some
				 * destinations (e.g. redirect case).
				 * So we must call rt6_flush explicitly.
				 */
				rt6_flush(&ip6->ip6_src, rt_ifp);
			}
			RT_LOCK(rt);
		}
		ln->ln_router = is_router;
	}

	if (send_nc_alive_kev && (ifp->if_addrlen == IF_LLREACH_MAXLEN)) {
		struct kev_msg ev_msg;
		struct kev_nd6_ndalive nd6_ndalive;
		bzero(&ev_msg, sizeof(ev_msg));
		bzero(&nd6_ndalive, sizeof(nd6_ndalive));
		ev_msg.vendor_code      = KEV_VENDOR_APPLE;
		ev_msg.kev_class        = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass     = KEV_ND6_SUBCLASS;
		ev_msg.event_code       = KEV_ND6_NDALIVE;

		nd6_ndalive.link_data.if_family = ifp->if_family;
		nd6_ndalive.link_data.if_unit = ifp->if_unit;
		strlcpy(nd6_ndalive.link_data.if_name,
		    ifp->if_name,
		    sizeof(nd6_ndalive.link_data.if_name));
		ev_msg.dv[0].data_ptr = &nd6_ndalive;
		ev_msg.dv[0].data_length =
		    sizeof(nd6_ndalive);
		dlil_post_complete_msg(NULL, &ev_msg);
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
		m_hold = ln->ln_hold;
		ln->ln_hold = NULL;
		for (; m_hold; m_hold = m_hold_next) {
			m_hold_next = m_hold->m_nextpkt;
			m_hold->m_nextpkt = NULL;
			/*
			 * we assume ifp is not a loopback here, so just set
			 * the 2nd argument as the 1st one.
			 */
			RT_UNLOCK(rt);
			nd6_output(ifp, ifp, m_hold, &sin6, rt, NULL);
			RT_LOCK_SPIN(rt);
		}
	}
	RT_REMREF_LOCKED(rt);
	RT_UNLOCK(rt);
	m_freem(m);
	return;

bad:
	icmp6stat.icp6s_badna++;
	/* fall through */
freeit:
	m_freem(m);
	return;
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
	int tlladdr,            /* 1 if include target link-layer address */
	struct sockaddr *sdl0)  /* sockaddr_dl (= proxy NA) or NULL */
{
	struct mbuf *m;
	struct ip6_hdr *ip6;
	struct nd_neighbor_advert *nd_na;
	struct ip6_moptions *im6o = NULL;
	caddr_t mac = NULL;
	struct route_in6 ro;
	struct in6_addr *src, src_storage, daddr6;
	struct in6_ifaddr *ia;
	struct sockaddr_in6 dst_sa;
	int icmp6len, maxlen, error;
	struct ifnet *outif = NULL;

	struct ip6_out_args ip6oa;
	bzero(&ro, sizeof(ro));

	daddr6 = *daddr6_0;     /* make a local copy for modification */

	bzero(&ip6oa, sizeof(ip6oa));
	ip6oa.ip6oa_boundif = ifp->if_index;
	ip6oa.ip6oa_flags = IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR |
	    IP6OAF_AWDL_UNRESTRICTED | IP6OAF_INTCOPROC_ALLOWED;
	ip6oa.ip6oa_sotc = SO_TC_UNSPEC;
	ip6oa.ip6oa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

	ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;

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

	MGETHDR(m, M_DONTWAIT, MT_DATA);        /* XXXMAC: mac_create_mbuf_linklayer() probably */
	if (m && max_linkhdr + maxlen >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL) {
		return;
	}
	m->m_pkthdr.rcvif = NULL;

	if (IN6_IS_ADDR_MULTICAST(&daddr6)) {
		m->m_flags |= M_MCAST;

		im6o = ip6_allocmoptions(M_DONTWAIT);
		if (im6o == NULL) {
			m_freem(m);
			return;
		}

		im6o->im6o_multicast_ifp = ifp;
		im6o->im6o_multicast_hlim = IPV6_MAXHLIM;
		im6o->im6o_multicast_loop = 0;
	}

	icmp6len = sizeof(*nd_na);
	m->m_pkthdr.len = m->m_len = sizeof(struct ip6_hdr) + icmp6len;
	m->m_data += max_linkhdr;       /* or MH_ALIGN() equivalent? */

	/* fill neighbor advertisement packet */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = IPV6_MAXHLIM;
	if (IN6_IS_ADDR_UNSPECIFIED(&daddr6)) {
		/* reply to DAD */
		daddr6.s6_addr16[0] = IPV6_ADDR_INT16_MLL;
		daddr6.s6_addr16[1] = 0;
		daddr6.s6_addr32[1] = 0;
		daddr6.s6_addr32[2] = 0;
		daddr6.s6_addr32[3] = IPV6_ADDR_INT32_ONE;
		if (in6_setscope(&daddr6, ifp, NULL)) {
			goto bad;
		}

		flags &= ~ND_NA_FLAG_SOLICITED;
	} else {
		ip6->ip6_dst = daddr6;
	}

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
		nd6log(debug, "nd6_na_output: source can't be "
		    "determined: dst=%s, error=%d\n",
		    ip6_sprintf(&dst_sa.sin6_addr), error);
		goto bad;
	}
	ip6->ip6_src = *src;

	/*
	 * RFC 4429 requires not setting "override" flag on NA packets sent
	 * from optimistic addresses.
	 */
	ia = in6ifa_ifpwithaddr(ifp, src);
	if (ia != NULL) {
		if (ia->ia6_flags & IN6_IFF_OPTIMISTIC) {
			flags &= ~ND_NA_FLAG_OVERRIDE;
		}
		IFA_REMREF(&ia->ia_ifa);
	}

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
		if (sdl0 == NULL) {
			mac = nd6_ifptomac(ifp);
		} else if (sdl0->sa_family == AF_LINK) {
			struct sockaddr_dl *sdl;
			sdl = (struct sockaddr_dl *)(void *)sdl0;
			if (sdl->sdl_alen == ifp->if_addrlen) {
				mac = LLADDR(sdl);
			}
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
	} else {
		flags &= ~ND_NA_FLAG_OVERRIDE;
	}

	ip6->ip6_plen = htons((u_short)icmp6len);
	nd_na->nd_na_flags_reserved = flags;
	nd_na->nd_na_cksum = 0;
	nd_na->nd_na_cksum =
	    in6_cksum(m, IPPROTO_ICMPV6, sizeof(struct ip6_hdr), icmp6len);

	m->m_pkthdr.pkt_flags |= PKTF_INET6_RESOLVE;

	if (ifp->if_eflags & IFEF_TXSTART) {
		/* Use control service class if the interface supports
		 * transmit-start model.
		 */
		(void) m_set_service_class(m, MBUF_SC_CTL);
	}

	ip6oa.ip6oa_flags |= IP6OAF_SKIP_PF;
	ip6_output(m, NULL, NULL, IPV6_OUTARGS, im6o, &outif, &ip6oa);
	if (outif) {
		icmp6_ifstat_inc(outif, ifs6_out_msg);
		icmp6_ifstat_inc(outif, ifs6_out_neighboradvert);
		ifnet_release(outif);
	}
	icmp6stat.icp6s_outhist[ND_NEIGHBOR_ADVERT]++;

exit:
	if (im6o != NULL) {
		IM6O_REMREF(im6o);
	}

	ROUTE_RELEASE(&ro);
	return;

bad:
	m_freem(m);
	goto exit;
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
	case IFT_6LOWPAN:
		return (caddr_t)IF_LLADDR(ifp);
	default:
		return NULL;
	}
}

TAILQ_HEAD(dadq_head, dadq);
struct dadq {
	decl_lck_mtx_data(, dad_lock);
	u_int32_t dad_refcount; /* reference count */
	int dad_attached;
	TAILQ_ENTRY(dadq) dad_list;
	struct ifaddr *dad_ifa;
	int dad_count;          /* max NS to send */
	int dad_ns_tcount;      /* # of trials to send NS */
	int dad_ns_ocount;      /* NS sent so far */
	int dad_ns_icount;
	int dad_na_icount;
	int dad_ns_lcount;      /* looped back NS */
	int dad_loopbackprobe;  /* probing state for loopback detection */
	uint8_t dad_lladdr[ETHER_ADDR_LEN];
	uint8_t dad_lladdrlen;
#define ND_OPT_NONCE_LEN32 \
    ((ND_OPT_NONCE_LEN + sizeof(uint32_t) - 1)/sizeof(uint32_t))
	uint32_t dad_nonce[ND_OPT_NONCE_LEN32];
};

static struct dadq_head dadq;

void
nd6_nbr_init(void)
{
	int i;

	TAILQ_INIT(&dadq);

	dad_size = sizeof(struct dadq);
	dad_zone = zinit(dad_size, DAD_ZONE_MAX * dad_size, 0, DAD_ZONE_NAME);
	if (dad_zone == NULL) {
		panic("%s: failed allocating %s", __func__, DAD_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(dad_zone, Z_EXPAND, TRUE);
	zone_change(dad_zone, Z_CALLERACCT, FALSE);

	bzero(&hostrtmask, sizeof hostrtmask);
	hostrtmask.sin6_family = AF_INET6;
	hostrtmask.sin6_len = sizeof hostrtmask;
	for (i = 0; i < sizeof hostrtmask.sin6_addr; ++i) {
		hostrtmask.sin6_addr.s6_addr[i] = 0xff;
	}
}

static struct dadq *
nd6_dad_find(struct ifaddr *ifa, struct nd_opt_nonce *nonce)
{
	struct dadq *dp;

	lck_mtx_lock(dad6_mutex);
	for (dp = dadq.tqh_first; dp; dp = dp->dad_list.tqe_next) {
		DAD_LOCK_SPIN(dp);
		if (dp->dad_ifa != ifa) {
			DAD_UNLOCK(dp);
			continue;
		}

		/*
		 * Skip if the nonce matches the received one.
		 * +2 in the length is required because of type and
		 * length fields are included in a header.
		 */
		if (nonce != NULL &&
		    nonce->nd_opt_nonce_len == (ND_OPT_NONCE_LEN + 2) / 8 &&
		    memcmp(&nonce->nd_opt_nonce[0], &dp->dad_nonce[0],
		    ND_OPT_NONCE_LEN) == 0) {
			nd6log(error, "%s: a looped back NS message is "
			    "detected during DAD for %s. Ignoring.\n",
			    if_name(ifa->ifa_ifp),
			    ip6_sprintf(IFA_IN6(ifa)));
			dp->dad_ns_lcount++;
			++ip6stat.ip6s_dad_loopcount;
			DAD_UNLOCK(dp);
			continue;
		}

		DAD_ADDREF_LOCKED(dp);
		DAD_UNLOCK(dp);
		break;
	}
	lck_mtx_unlock(dad6_mutex);
	return dp;
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
	int *tick_delay)        /* minimum delay ticks for IFF_UP event */
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct dadq *dp;

	nd6log2(debug, "%s - %s ifp %s ia6_flags 0x%x\n",
	    __func__,
	    ip6_sprintf(&ia->ia_addr.sin6_addr),
	    if_name(ia->ia_ifp),
	    ia->ia6_flags);

	/*
	 * If we don't need DAD, don't do it.
	 * There are several cases:
	 * - DAD is disabled (ip6_dad_count == 0)
	 * - the interface address is anycast
	 */
	IFA_LOCK(&ia->ia_ifa);
	if (!(ia->ia6_flags & IN6_IFF_DADPROGRESS)) {
		nd6log0(debug,
		    "nd6_dad_start: not a tentative or optimistic address "
		    "%s(%s)\n",
		    ip6_sprintf(&ia->ia_addr.sin6_addr),
		    ifa->ifa_ifp ? if_name(ifa->ifa_ifp) : "???");
		IFA_UNLOCK(&ia->ia_ifa);
		return;
	}
	if (!ip6_dad_count || (ia->ia6_flags & IN6_IFF_ANYCAST) != 0) {
		ia->ia6_flags &= ~IN6_IFF_DADPROGRESS;
		IFA_UNLOCK(&ia->ia_ifa);
		return;
	}
	IFA_UNLOCK(&ia->ia_ifa);
	if (ifa->ifa_ifp == NULL) {
		panic("nd6_dad_start: ifa->ifa_ifp == NULL");
	}
	if (!(ifa->ifa_ifp->if_flags & IFF_UP) ||
	    (ifa->ifa_ifp->if_eflags & IFEF_IPV6_ND6ALT)) {
		return;
	}
	if ((dp = nd6_dad_find(ifa, NULL)) != NULL) {
		DAD_REMREF(dp);
		/* DAD already in progress */
		return;
	}

	dp = zalloc(dad_zone);
	if (dp == NULL) {
		nd6log0(error, "nd6_dad_start: memory allocation failed for %s(%s)\n",
		    ip6_sprintf(&ia->ia_addr.sin6_addr),
		    ifa->ifa_ifp ? if_name(ifa->ifa_ifp) : "???");
		return;
	}
	bzero(dp, dad_size);
	lck_mtx_init(&dp->dad_lock, ifa_mtx_grp, ifa_mtx_attr);

	/* Callee adds one reference for us */
	dp = nd6_dad_attach(dp, ifa);

	nd6log0(debug, "%s: starting %sDAD %sfor %s\n",
	    if_name(ifa->ifa_ifp),
	    (ia->ia6_flags & IN6_IFF_OPTIMISTIC) ? "optimistic " : "",
	    (tick_delay == NULL) ? "immediately " : "",
	    ip6_sprintf(&ia->ia_addr.sin6_addr));

	/*
	 * Send NS packet for DAD, ip6_dad_count times.
	 * Note that we must delay the first transmission, if this is the
	 * first packet to be sent from the interface after interface
	 * (re)initialization.
	 */
	if (tick_delay == NULL) {
		u_int32_t retrans;
		struct nd_ifinfo *ndi = NULL;

		nd6_dad_ns_output(dp, ifa);
		ndi = ND_IFINFO(ifa->ifa_ifp);
		VERIFY(ndi != NULL && ndi->initialized);
		lck_mtx_lock(&ndi->lock);
		retrans = ndi->retrans * hz / 1000;
		lck_mtx_unlock(&ndi->lock);
		timeout((void (*)(void *))nd6_dad_timer, (void *)ifa, retrans);
	} else {
		int ntick;

		if (*tick_delay == 0) {
			ntick = random() % (MAX_RTR_SOLICITATION_DELAY * hz);
		} else {
			ntick = *tick_delay + random() % (hz / 2);
		}
		*tick_delay = ntick;
		timeout((void (*)(void *))nd6_dad_timer, (void *)ifa,
		    ntick);
	}

	DAD_REMREF(dp);         /* drop our reference */
}

static struct dadq *
nd6_dad_attach(struct dadq *dp, struct ifaddr *ifa)
{
	lck_mtx_lock(dad6_mutex);
	DAD_LOCK(dp);
	dp->dad_ifa = ifa;
	IFA_ADDREF(ifa);        /* for dad_ifa */
	dp->dad_count = ip6_dad_count;
	dp->dad_ns_icount = dp->dad_na_icount = 0;
	dp->dad_ns_ocount = dp->dad_ns_tcount = 0;
	dp->dad_ns_lcount = dp->dad_loopbackprobe = 0;
	VERIFY(!dp->dad_attached);
	dp->dad_attached = 1;
	dp->dad_lladdrlen = 0;
	DAD_ADDREF_LOCKED(dp);  /* for caller */
	DAD_ADDREF_LOCKED(dp);  /* for dadq_head list */
	TAILQ_INSERT_TAIL(&dadq, (struct dadq *)dp, dad_list);
	DAD_UNLOCK(dp);
	lck_mtx_unlock(dad6_mutex);

	return dp;
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
		DAD_REMREF(dp);         /* drop dadq_head reference */
	}
}

/*
 * terminate DAD unconditionally.  used for address removals.
 */
void
nd6_dad_stop(struct ifaddr *ifa)
{
	struct dadq *dp;

	dp = nd6_dad_find(ifa, NULL);
	if (!dp) {
		/* DAD wasn't started yet */
		return;
	}

	untimeout((void (*)(void *))nd6_dad_timer, (void *)ifa);

	nd6_dad_detach(dp, ifa);
	DAD_REMREF(dp);         /* drop our reference */
}

static void
nd6_unsol_na_output(struct ifaddr *ifa)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct ifnet *ifp = ifa->ifa_ifp;
	struct in6_addr saddr6, taddr6;

	if ((ifp->if_flags & IFF_UP) == 0 ||
	    (ifp->if_flags & IFF_RUNNING) == 0 ||
	    (ifp->if_eflags & IFEF_IPV6_ND6ALT) != 0) {
		return;
	}

	IFA_LOCK_SPIN(&ia->ia_ifa);
	taddr6 = ia->ia_addr.sin6_addr;
	IFA_UNLOCK(&ia->ia_ifa);
	if (in6_setscope(&taddr6, ifp, NULL) != 0) {
		return;
	}
	saddr6 = in6addr_linklocal_allnodes;
	if (in6_setscope(&saddr6, ifp, NULL) != 0) {
		return;
	}

	nd6log(info, "%s: sending unsolicited NA\n",
	    if_name(ifa->ifa_ifp));

	nd6_na_output(ifp, &saddr6, &taddr6, ND_NA_FLAG_OVERRIDE, 1, NULL);
}

static void
nd6_dad_timer(struct ifaddr *ifa)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct dadq *dp = NULL;
	struct nd_ifinfo *ndi = NULL;
	u_int32_t retrans;

	/* Sanity check */
	if (ia == NULL) {
		nd6log0(error, "nd6_dad_timer: called with null parameter\n");
		goto done;
	}

	nd6log2(debug, "%s - %s ifp %s ia6_flags 0x%x\n",
	    __func__,
	    ip6_sprintf(&ia->ia_addr.sin6_addr),
	    if_name(ia->ia_ifp),
	    ia->ia6_flags);

	dp = nd6_dad_find(ifa, NULL);
	if (dp == NULL) {
		nd6log0(error, "nd6_dad_timer: DAD structure not found\n");
		goto done;
	}
	IFA_LOCK(&ia->ia_ifa);
	if (ia->ia6_flags & IN6_IFF_DUPLICATED) {
		nd6log0(error, "nd6_dad_timer: called with duplicated address "
		    "%s(%s)\n",
		    ip6_sprintf(&ia->ia_addr.sin6_addr),
		    ifa->ifa_ifp ? if_name(ifa->ifa_ifp) : "???");
		IFA_UNLOCK(&ia->ia_ifa);
		goto done;
	}
	if ((ia->ia6_flags & IN6_IFF_DADPROGRESS) == 0) {
		nd6log0(error, "nd6_dad_timer: not a tentative or optimistic "
		    "address %s(%s)\n",
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
		nd6log0(info, "%s: could not run DAD, driver problem?\n",
		    if_name(ifa->ifa_ifp));

		nd6_dad_detach(dp, ifa);
		goto done;
	}

	/* Need more checks? */
	if (dp->dad_ns_ocount < dp->dad_count) {
		DAD_UNLOCK(dp);
		/*
		 * We have more NS to go.  Send NS packet for DAD.
		 */
		nd6_dad_ns_output(dp, ifa);
		ndi = ND_IFINFO(ifa->ifa_ifp);
		VERIFY(ndi != NULL && ndi->initialized);
		lck_mtx_lock(&ndi->lock);
		retrans = ndi->retrans * hz / 1000;
		lck_mtx_unlock(&ndi->lock);
		timeout((void (*)(void *))nd6_dad_timer, (void *)ifa, retrans);
	} else {
		/*
		 * We have transmitted sufficient number of DAD packets.
		 * See what we've got.
		 */
		if (dp->dad_na_icount > 0 || dp->dad_ns_icount) {
			/* We've seen NS or NA, means DAD has failed. */
			DAD_UNLOCK(dp);
			nd6log0(info,
			    "%s: duplicate IPv6 address %s if:%s [timer]\n",
			    __func__, ip6_sprintf(&ia->ia_addr.sin6_addr),
			    if_name(ia->ia_ifp));
			nd6_dad_duplicated(ifa);
			/* (*dp) will be freed in nd6_dad_duplicated() */
		} else if (dad_enhanced != 0 &&
		    dp->dad_ns_lcount > 0 &&
		    dp->dad_ns_lcount > dp->dad_loopbackprobe) {
			dp->dad_loopbackprobe = dp->dad_ns_lcount;
			dp->dad_count =
			    dp->dad_ns_ocount + dad_maxtry - 1;
			DAD_UNLOCK(dp);
			ndi = ND_IFINFO(ifa->ifa_ifp);
			VERIFY(ndi != NULL && ndi->initialized);
			lck_mtx_lock(&ndi->lock);
			retrans = ndi->retrans * hz / 1000;
			lck_mtx_unlock(&ndi->lock);

			/*
			 * Sec. 4.1 in RFC 7527 requires transmission of
			 * additional probes until the loopback condition
			 * becomes clear when a looped back probe is detected.
			 */
			nd6log0(info,
			    "%s: a looped back NS message is detected during DAD for %s. Another DAD probe is being sent on interface %s.\n",
			    __func__, ip6_sprintf(&ia->ia_addr.sin6_addr),
			    if_name(ia->ia_ifp));
			/*
			 * Send an NS immediately and increase dad_count by
			 * nd6_mmaxtries - 1.
			 */
			nd6_dad_ns_output(dp, ifa);
			timeout((void (*)(void *))nd6_dad_timer, (void *)ifa, retrans);
			goto done;
		} else {
			boolean_t txunsolna;
			DAD_UNLOCK(dp);
			/*
			 * We are done with DAD.  No NA came, no NS came.
			 * No duplicate address found.
			 */
			IFA_LOCK_SPIN(&ia->ia_ifa);
			ia->ia6_flags &= ~IN6_IFF_DADPROGRESS;
			IFA_UNLOCK(&ia->ia_ifa);

			ndi = ND_IFINFO(ifa->ifa_ifp);
			VERIFY(ndi != NULL && ndi->initialized);
			lck_mtx_lock(&ndi->lock);
			txunsolna = (ndi->flags & ND6_IFF_REPLICATED) != 0;
			lck_mtx_unlock(&ndi->lock);

			if (txunsolna) {
				nd6_unsol_na_output(ifa);
			}

			nd6log0(debug,
			    "%s: DAD complete for %s - no duplicates found %s\n",
			    if_name(ifa->ifa_ifp),
			    ip6_sprintf(&ia->ia_addr.sin6_addr),
			    txunsolna ? ", tx unsolicited NA with O=1" : ".");

			if (dp->dad_ns_lcount > 0) {
				nd6log0(debug,
				    "%s: DAD completed while "
				    "a looped back NS message is detected "
				    "during DAD for %s om interface %s\n",
				    __func__,
				    ip6_sprintf(&ia->ia_addr.sin6_addr),
				    if_name(ia->ia_ifp));
			}

			in6_post_msg(ia->ia_ifp, KEV_INET6_NEW_USER_ADDR, ia,
			    dp->dad_lladdr);
			nd6_dad_detach(dp, ifa);
		}
	}

done:
	if (dp != NULL) {
		DAD_REMREF(dp);         /* drop our reference */
	}
}

void
nd6_dad_duplicated(struct ifaddr *ifa)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct dadq *dp;
	struct ifnet *ifp = ifa->ifa_ifp;
	boolean_t candisable;

	dp = nd6_dad_find(ifa, NULL);
	if (dp == NULL) {
		log(LOG_ERR, "%s: DAD structure not found.\n", __func__);
		return;
	}
	IFA_LOCK(&ia->ia_ifa);
	DAD_LOCK(dp);
	nd6log(error, "%s: NS in/out/loopback=%d/%d/%d, NA in=%d\n",
	    __func__, dp->dad_ns_icount, dp->dad_ns_ocount, dp->dad_ns_lcount,
	    dp->dad_na_icount);
	candisable = FALSE;

	if (IN6_IS_ADDR_LINKLOCAL(&ia->ia_addr.sin6_addr) &&
	    !(ia->ia6_flags & IN6_IFF_SECURED)) {
		struct in6_addr in6;
		struct ifaddr *llifa = NULL;
		struct sockaddr_dl *sdl = NULL;
		uint8_t *lladdr = dp->dad_lladdr;
		uint8_t lladdrlen = dp->dad_lladdrlen;

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
			/*
			 * Check if our hardware address matches the
			 * link layer information received in the
			 * NS/NA
			 */
			llifa = ifp->if_lladdr;
			IFA_LOCK(llifa);
			sdl = (struct sockaddr_dl *)(void *)
			    llifa->ifa_addr;
			if (lladdrlen == sdl->sdl_alen &&
			    bcmp(lladdr, LLADDR(sdl), lladdrlen) == 0) {
				candisable = TRUE;
			}
			IFA_UNLOCK(llifa);

			in6 = ia->ia_addr.sin6_addr;
			if (in6_iid_from_hw(ifp, &in6) != 0) {
				break;
			}

			/* Refine decision about whether IPv6 can be disabled */
			if (candisable &&
			    !IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr, &in6)) {
				/*
				 * Apply this logic only to the embedded MAC
				 * address form of link-local IPv6 address.
				 */
				candisable = FALSE;
			} else if (lladdr == NULL &&
			    IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr, &in6)) {
				/*
				 * We received a NA with no target link-layer
				 * address option. This means that someone else
				 * has our address. Mark it as a hardware
				 * duplicate so we disable IPv6 later on.
				 */
				candisable = TRUE;
			}
			break;
		default:
			break;
		}
	}
	DAD_UNLOCK(dp);

	ia->ia6_flags &= ~IN6_IFF_DADPROGRESS;
	ia->ia6_flags |= IN6_IFF_DUPLICATED;
	in6_event_enqueue_nwk_wq_entry(IN6_ADDR_MARKED_DUPLICATED,
	    ia->ia_ifa.ifa_ifp, &ia->ia_addr.sin6_addr,
	    0);
	IFA_UNLOCK(&ia->ia_ifa);

	/* increment DAD collision counter */
	++ip6stat.ip6s_dad_collide;

	/* We are done with DAD, with duplicated address found. (failure) */
	untimeout((void (*)(void *))nd6_dad_timer, (void *)ifa);

	IFA_LOCK(&ia->ia_ifa);
	log(LOG_ERR, "%s: DAD complete for %s - duplicate found.\n",
	    if_name(ifp), ip6_sprintf(&ia->ia_addr.sin6_addr));
	IFA_UNLOCK(&ia->ia_ifa);

	if (candisable) {
		struct nd_ifinfo *ndi =  ND_IFINFO(ifp);
		log(LOG_ERR, "%s: possible hardware address duplication "
		    "detected, disabling IPv6 for interface.\n", if_name(ifp));

		VERIFY((NULL != ndi) && (TRUE == ndi->initialized));
		ndi->flags |= ND6_IFF_IFDISABLED;
		/* Make sure to set IFEF_IPV6_DISABLED too */
		nd6_if_disable(ifp, TRUE);
	}

	log(LOG_ERR, "%s: manual intervention required!\n", if_name(ifp));

	/* Send an event to the configuration agent so that the
	 * duplicate address will be notified to the user and will
	 * be removed.
	 */
	in6_post_msg(ifp, KEV_INET6_NEW_USER_ADDR, ia, dp->dad_lladdr);
	nd6_dad_detach(dp, ifa);
	DAD_REMREF(dp);         /* drop our reference */
}

static void
nd6_dad_ns_output(struct dadq *dp, struct ifaddr *ifa)
{
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct ifnet *ifp = ifa->ifa_ifp;
	int i = 0;
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
	if (dad_enhanced != 0 && !(ifp->if_flags & IFF_POINTOPOINT)) {
		for (i = 0; i < ND_OPT_NONCE_LEN32; i++) {
			dp->dad_nonce[i] = RandomULong();
		}
		/*
		 * XXXHRS: Note that in the case that
		 * DupAddrDetectTransmits > 1, multiple NS messages with
		 * different nonces can be looped back in an unexpected
		 * order.  The current implementation recognizes only
		 * the latest nonce on the sender side.  Practically it
		 * should work well in almost all cases.
		 */
	}
	nd6_ns_output(ifp, NULL, &taddr6, NULL,
	    (uint8_t *)&dp->dad_nonce[0]);
}

/*
 * @brief       Called to process DAD NS
 *
 * @param       ifa is the pointer to the interface's address
 * @param       lladdr is source link layer information
 * @param       lladdrlen is source's linklayer length
 *
 * @return      void
 */
static void
nd6_dad_ns_input(struct ifaddr *ifa, char *lladdr,
    int lladdrlen, struct nd_opt_nonce *ndopt_nonce)
{
	struct dadq *dp;
	VERIFY(ifa != NULL);

	/* Ignore Nonce option when Enhanced DAD is disabled. */
	if (dad_enhanced == 0) {
		ndopt_nonce = NULL;
	}

	dp = nd6_dad_find(ifa, ndopt_nonce);
	if (dp == NULL) {
		return;
	}

	DAD_LOCK(dp);
	++dp->dad_ns_icount;
	if (lladdr && lladdrlen >= ETHER_ADDR_LEN) {
		memcpy(dp->dad_lladdr, lladdr, ETHER_ADDR_LEN);
		dp->dad_lladdrlen = lladdrlen;
	}
	DAD_UNLOCK(dp);
	DAD_REMREF(dp);
}

/*
 * @brief	Called to process received NA for DAD
 *
 * @param	m is the pointer to the packet's mbuf
 * @param	ifp is the pointer to the interface on which packet
 *              was receicved.
 * @param	taddr is pointer to target's IPv6 address
 * @param	lladdr is target's link layer information
 * @param	lladdrlen is target's linklayer length
 *
 * @return	NULL if the packet is consumed by DAD processing, else
 *              pointer to the mbuf.
 */
static struct mbuf *
nd6_dad_na_input(struct mbuf *m, struct ifnet *ifp, struct in6_addr *taddr,
    caddr_t lladdr, int lladdrlen)
{
	struct ifaddr *ifa = NULL;
	struct in6_ifaddr *ia = NULL;
	struct dadq *dp = NULL;
	struct nd_ifinfo *ndi = NULL;
	boolean_t replicated;

	ifa = (struct ifaddr *) in6ifa_ifpwithaddr(ifp, taddr);
	if (ifa == NULL) {
		return m;
	}

	replicated = FALSE;

	/* Get the ND6_IFF_REPLICATED flag. */
	ndi = ND_IFINFO(ifp);
	if (ndi != NULL && ndi->initialized) {
		lck_mtx_lock(&ndi->lock);
		replicated = !!(ndi->flags & ND6_IFF_REPLICATED);
		lck_mtx_unlock(&ndi->lock);
	}

	if (replicated) {
		nd6log(info, "%s: ignoring duplicate NA on "
		    "replicated interface %s\n", __func__, if_name(ifp));
		goto done;
	}

	/* Lock the interface address until done (see label below). */
	IFA_LOCK(ifa);
	ia = (struct in6_ifaddr *) ifa;

	if (!(ia->ia6_flags & IN6_IFF_DADPROGRESS)) {
		IFA_UNLOCK(ifa);
		nd6log(info, "%s: ignoring duplicate NA on "
		    "%s [DAD not in progress]\n", __func__,
		    if_name(ifp));
		goto done;
	}

	/* Some sleep proxies improperly send the client's Ethernet address in
	 * the target link-layer address option, so detect this by comparing
	 * the L2-header source address, if we have seen it, with the target
	 * address, and ignoring the NA if they don't match.
	 */
	if (lladdr != NULL && lladdrlen >= ETHER_ADDR_LEN) {
		struct ip6aux *ip6a = ip6_findaux(m);
		if (ip6a && (ip6a->ip6a_flags & IP6A_HASEEN) != 0 &&
		    bcmp(ip6a->ip6a_ehsrc, lladdr, ETHER_ADDR_LEN) != 0) {
			IFA_UNLOCK(ifa);
			nd6log(error, "%s: ignoring duplicate NA on %s "
			    "[eh_src != tgtlladdr]\n", __func__, if_name(ifp));
			goto done;
		}
	}

	IFA_UNLOCK(ifa);

	dp = nd6_dad_find(ifa, NULL);
	if (dp == NULL) {
		nd6log(info, "%s: no DAD structure for %s on %s.\n",
		    __func__, ip6_sprintf(taddr), if_name(ifp));
		goto done;
	}

	DAD_LOCK_SPIN(dp);
	if (lladdr != NULL && lladdrlen >= ETHER_ADDR_LEN) {
		memcpy(dp->dad_lladdr, lladdr, ETHER_ADDR_LEN);
		dp->dad_lladdrlen = lladdrlen;
	}
	dp->dad_na_icount++;
	DAD_UNLOCK(dp);
	DAD_REMREF(dp);

	/* remove the address. */
	nd6log(info,
	    "%s: duplicate IPv6 address %s [processing NA on %s]\n", __func__,
	    ip6_sprintf(taddr), if_name(ifp));
done:
	IFA_LOCK_ASSERT_NOTHELD(ifa);
	IFA_REMREF(ifa);
	m_freem(m);
	return NULL;
}

static void
dad_addref(struct dadq *dp, int locked)
{
	if (!locked) {
		DAD_LOCK_SPIN(dp);
	} else {
		DAD_LOCK_ASSERT_HELD(dp);
	}

	if (++dp->dad_refcount == 0) {
		panic("%s: dad %p wraparound refcnt\n", __func__, dp);
		/* NOTREACHED */
	}
	if (!locked) {
		DAD_UNLOCK(dp);
	}
}

static void
dad_remref(struct dadq *dp)
{
	struct ifaddr *ifa;

	DAD_LOCK_SPIN(dp);
	if (dp->dad_refcount == 0) {
		panic("%s: dad %p negative refcnt\n", __func__, dp);
	}
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
		IFA_REMREF(ifa);        /* drop dad_ifa reference */
		dp->dad_ifa = NULL;
	}

	lck_mtx_destroy(&dp->dad_lock, ifa_mtx_grp);
	zfree(dad_zone, dp);
}

void
nd6_llreach_set_reachable(struct ifnet *ifp, void *addr, unsigned int alen)
{
	/* Nothing more to do if it's disabled */
	if (nd6_llreach_base == 0) {
		return;
	}

	ifnet_llreach_set_reachable(ifp, ETHERTYPE_IPV6, addr, alen);
}

void
nd6_alt_node_addr_decompose(struct ifnet *ifp, struct sockaddr *sa,
    struct sockaddr_dl* sdl, struct sockaddr_in6 *sin6)
{
	static const size_t EUI64_LENGTH = 8;

	VERIFY(nd6_need_cache(ifp));
	VERIFY(sa);
	VERIFY(sdl && (void *)sa != (void *)sdl);
	VERIFY(sin6 && (void *)sa != (void *)sin6);

	bzero(sin6, sizeof(*sin6));
	sin6->sin6_len = sizeof *sin6;
	sin6->sin6_family = AF_INET6;

	bzero(sdl, sizeof(*sdl));
	sdl->sdl_len = sizeof *sdl;
	sdl->sdl_family = AF_LINK;
	sdl->sdl_type = ifp->if_type;
	sdl->sdl_index = ifp->if_index;

	switch (sa->sa_family) {
	case AF_INET6: {
		struct sockaddr_in6 *sin6a = (struct sockaddr_in6 *)(void *)sa;
		struct in6_addr *in6 = &sin6a->sin6_addr;

		VERIFY(sa->sa_len == sizeof *sin6);

		sdl->sdl_nlen = strlen(ifp->if_name);
		bcopy(ifp->if_name, sdl->sdl_data, sdl->sdl_nlen);
		if (in6->s6_addr[11] == 0xff && in6->s6_addr[12] == 0xfe) {
			sdl->sdl_alen = ETHER_ADDR_LEN;
			LLADDR(sdl)[0] = (in6->s6_addr[8] ^ ND6_EUI64_UBIT);
			LLADDR(sdl)[1] = in6->s6_addr[9];
			LLADDR(sdl)[2] = in6->s6_addr[10];
			LLADDR(sdl)[3] = in6->s6_addr[13];
			LLADDR(sdl)[4] = in6->s6_addr[14];
			LLADDR(sdl)[5] = in6->s6_addr[15];
		} else {
			sdl->sdl_alen = EUI64_LENGTH;
			bcopy(&in6->s6_addr[8], LLADDR(sdl), EUI64_LENGTH);
		}

		sdl->sdl_slen = 0;
		break;
	}
	case AF_LINK: {
		struct sockaddr_dl *sdla = (struct sockaddr_dl *)(void *)sa;
		struct in6_addr *in6 = &sin6->sin6_addr;
		caddr_t lla = LLADDR(sdla);

		VERIFY(sa->sa_len <= sizeof(*sdl));
		bcopy(sa, sdl, sa->sa_len);

		sin6->sin6_scope_id = sdla->sdl_index;
		if (sin6->sin6_scope_id == 0) {
			sin6->sin6_scope_id = ifp->if_index;
		}
		in6->s6_addr[0] = 0xfe;
		in6->s6_addr[1] = 0x80;
		if (sdla->sdl_alen == EUI64_LENGTH) {
			bcopy(lla, &in6->s6_addr[8], EUI64_LENGTH);
		} else {
			VERIFY(sdla->sdl_alen == ETHER_ADDR_LEN);

			in6->s6_addr[8] = ((uint8_t) lla[0] ^ ND6_EUI64_UBIT);
			in6->s6_addr[9] = (uint8_t) lla[1];
			in6->s6_addr[10] = (uint8_t) lla[2];
			in6->s6_addr[11] = 0xff;
			in6->s6_addr[12] = 0xfe;
			in6->s6_addr[13] = (uint8_t) lla[3];
			in6->s6_addr[14] = (uint8_t) lla[4];
			in6->s6_addr[15] = (uint8_t) lla[5];
		}

		break;
	}
	default:
		VERIFY(false);
		break;
	}
}

int
nd6_alt_node_present(struct ifnet *ifp, struct sockaddr_in6 *sin6,
    struct sockaddr_dl *sdl, int32_t rssi, int lqm, int npm)
{
	struct rtentry *rt;
	struct llinfo_nd6 *ln;
	struct  if_llreach *lr = NULL;
	const uint16_t temp_embedded_id = sin6->sin6_addr.s6_addr16[1];

	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr) &&
	    (temp_embedded_id == 0)) {
		sin6->sin6_addr.s6_addr16[1] = htons(ifp->if_index);
	}

	nd6_cache_lladdr(ifp, &sin6->sin6_addr, LLADDR(sdl), sdl->sdl_alen,
	    ND_NEIGHBOR_ADVERT, 0);

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);

	rt = rtalloc1_scoped_locked((struct sockaddr *)sin6, 1, 0,
	    ifp->if_index);

	/* Restore the address that was passed to us */
	if (temp_embedded_id == 0) {
		sin6->sin6_addr.s6_addr16[1] = 0;
	}

	if (rt != NULL) {
		RT_LOCK(rt);
		VERIFY(rt->rt_flags & RTF_LLINFO);
		VERIFY(rt->rt_llinfo);

		ln = rt->rt_llinfo;
		ND6_CACHE_STATE_TRANSITION(ln, ND6_LLINFO_REACHABLE);
		ln_setexpire(ln, 0);

		lr = ln->ln_llreach;
		if (lr) {
			IFLR_LOCK(lr);
			lr->lr_rssi = rssi;
			lr->lr_lqm = (int32_t) lqm;
			lr->lr_npm = (int32_t) npm;
			IFLR_UNLOCK(lr);
		}

		RT_UNLOCK(rt);
		RT_REMREF(rt);
	}

	lck_mtx_unlock(rnh_lock);

	if (rt == NULL) {
		log(LOG_ERR, "%s: failed to add/update host route to %s.\n",
		    __func__, ip6_sprintf(&sin6->sin6_addr));
		return EHOSTUNREACH;
	} else {
		nd6log(debug, "%s: host route to %s [lr=0x%llx]\n",
		    __func__, ip6_sprintf(&sin6->sin6_addr),
		    (uint64_t)VM_KERNEL_ADDRPERM(lr));
		return 0;
	}
}

void
nd6_alt_node_absent(struct ifnet *ifp, struct sockaddr_in6 *sin6, struct sockaddr_dl *sdl)
{
	struct rtentry *rt;
	const uint16_t temp_embedded_id = sin6->sin6_addr.s6_addr16[1];

	nd6log(debug, "%s: host route to %s\n", __func__,
	    ip6_sprintf(&sin6->sin6_addr));

	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr) &&
	    (temp_embedded_id == 0)) {
		sin6->sin6_addr.s6_addr16[1] = htons(ifp->if_index);
	}

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(rnh_lock);

	rt = rtalloc1_scoped_locked((struct sockaddr *)sin6, 0, 0,
	    ifp->if_index);

	/* Restore the address that was passed to us */
	if (temp_embedded_id == 0) {
		sin6->sin6_addr.s6_addr16[1] = 0;
	}

	if (rt != NULL) {
		RT_LOCK(rt);

		if (!(rt->rt_flags & (RTF_CLONING | RTF_PRCLONING)) &&
		    (rt->rt_flags & (RTF_HOST | RTF_LLINFO | RTF_WASCLONED)) ==
		    (RTF_HOST | RTF_LLINFO | RTF_WASCLONED)) {
			/*
			 * Copy the link layer information in SDL when present
			 * as it later gets used to issue the kernel event for
			 * node absence.
			 */
			if (sdl != NULL && rt->rt_gateway != NULL &&
			    rt->rt_gateway->sa_family == AF_LINK &&
			    SDL(rt->rt_gateway)->sdl_len <= sizeof(*sdl)) {
				bcopy(rt->rt_gateway, sdl, SDL(rt->rt_gateway)->sdl_len);
			}

			rt->rt_flags |= RTF_CONDEMNED;
			RT_UNLOCK(rt);

			(void) rtrequest_locked(RTM_DELETE, rt_key(rt),
			    (struct sockaddr *)NULL, rt_mask(rt), 0,
			    (struct rtentry **)NULL);

			rtfree_locked(rt);
		} else {
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
		}
	}

	lck_mtx_unlock(rnh_lock);
}
