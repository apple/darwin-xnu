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

/*	$FreeBSD: src/sys/netinet6/ip6_output.c,v 1.43 2002/10/31 19:45:48 ume Exp $	*/
/*	$KAME: ip6_output.c,v 1.279 2002/01/26 06:12:30 jinmei Exp $	*/

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
 * Copyright (c) 1982, 1986, 1988, 1990, 1993
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
 *	@(#)ip_output.c	8.3 (Berkeley) 1/21/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/mcache.h>
#include <sys/sysctl.h>
#include <kern/zalloc.h>

#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/route.h>
#include <net/dlil.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6protosw.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_var.h>
#include <netinet/in_pcb.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>
#include <mach/sdt.h>

#if IPSEC
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netkey/key.h>
extern int ipsec_bypass;
#endif /* IPSEC */

#if CONFIG_MACF_NET
#include <security/mac.h>
#endif /* MAC_NET */

#include <netinet6/ip6_fw.h>

#include <net/net_osdep.h>

#include <netinet/kpi_ipfilter_var.h>

#if PF
#include <net/pfvar.h>
#endif /* PF */

#ifndef __APPLE__
static MALLOC_DEFINE(M_IPMOPTS, "ip6_moptions", "internet multicast options");
#endif

struct ip6_exthdrs {
	struct mbuf *ip6e_ip6;
	struct mbuf *ip6e_hbh;
	struct mbuf *ip6e_dest1;
	struct mbuf *ip6e_rthdr;
	struct mbuf *ip6e_dest2;
};

int ip6_raw_ctloutput(struct socket *so, struct sockopt *sopt);
static int ip6_pcbopts(struct ip6_pktopts **, struct mbuf *,
			    struct socket *, struct sockopt *sopt);
static int ip6_pcbopt(int optname, u_char *buf, int len, struct ip6_pktopts **pktopt, int uproto);
static int ip6_getpcbopt(struct ip6_pktopts *pktopt, int optname, struct sockopt *sopt);
static int ip6_setpktopt(int optname, u_char *buf, int len, struct ip6_pktopts *opt, int sticky, int cmsg, int uproto);
static void im6o_trace(struct ip6_moptions *, int);
static int ip6_copyexthdr(struct mbuf **, caddr_t, int);
static int ip6_insertfraghdr(struct mbuf *, struct mbuf *, int,
				  struct ip6_frag **);
static int ip6_insert_jumboopt(struct ip6_exthdrs *, u_int32_t);
static int ip6_splithdr(struct mbuf *, struct ip6_exthdrs *);
static int ip6_getpmtu (struct route_in6 *, struct route_in6 *,
	struct ifnet *, struct in6_addr *, u_int32_t *, int *);

#define	IM6O_TRACE_HIST_SIZE	32	/* size of trace history */

/* For gdb */
__private_extern__ unsigned int im6o_trace_hist_size = IM6O_TRACE_HIST_SIZE;

struct ip6_moptions_dbg {
	struct ip6_moptions	im6o;			/* ip6_moptions */
	u_int16_t		im6o_refhold_cnt;	/* # of IM6O_ADDREF */
	u_int16_t		im6o_refrele_cnt;	/* # of IM6O_REMREF */
	/*
	 * Alloc and free callers.
	 */
	ctrace_t		im6o_alloc;
	ctrace_t		im6o_free;
	/*
	 * Circular lists of IM6O_ADDREF and IM6O_REMREF callers.
	 */
	ctrace_t		im6o_refhold[IM6O_TRACE_HIST_SIZE];
	ctrace_t		im6o_refrele[IM6O_TRACE_HIST_SIZE];
};

#if DEBUG
static unsigned int im6o_debug = 1;	/* debugging (enabled) */
#else
static unsigned int im6o_debug;		/* debugging (disabled) */
#endif /* !DEBUG */

static unsigned int im6o_size;		/* size of zone element */
static struct zone *im6o_zone;		/* zone for ip6_moptions */

#define	IM6O_ZONE_MAX		64		/* maximum elements in zone */
#define	IM6O_ZONE_NAME		"ip6_moptions"	/* zone name */


/*
 * IP6 output. The packet in mbuf chain m contains a skeletal IP6
 * header (with pri, len, nxt, hlim, src, dst).
 * This function may modify ver and hlim only.
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 *
 * type of "mtu": rt_rmx.rmx_mtu is u_int32_t, ifnet.ifr_mtu is int, and
 * nd_ifinfo.linkmtu is u_int32_t.  so we use u_int32_t to hold largest one,
 * which is rt_rmx.rmx_mtu.
 */
int
ip6_output(
	struct mbuf *m0,
	struct ip6_pktopts *opt,
	struct route_in6 *ro,
	int flags,
	struct ip6_moptions *im6o,
	struct ifnet **ifpp,	/* XXX: just for statistics */
	struct ip6_out_args *ip6oa)
{
	struct ip6_hdr *ip6, *mhip6;
	struct ifnet *ifp = NULL, *origifp = NULL;
	struct mbuf *m = m0;
	int hlen, tlen, len, off;
	struct route_in6 ip6route;
	struct rtentry *rt = NULL;
	struct sockaddr_in6 *dst, src_sa, dst_sa;
	int error = 0;
	struct in6_ifaddr *ia = NULL;
	u_int32_t mtu;
	int alwaysfrag = 0, dontfrag = 0;
	u_int32_t optlen = 0, plen = 0, unfragpartlen = 0;
	struct ip6_exthdrs exthdrs;
	struct in6_addr finaldst, src0, dst0;
	u_int32_t zone;
	struct route_in6 *ro_pmtu = NULL;
	int hdrsplit = 0;
	int needipsec = 0;
	ipfilter_t inject_filter_ref;
	int tso;
	unsigned int ifscope;
	unsigned int nocell;
	boolean_t select_srcif;
	struct ipf_pktopts *ippo = NULL, ipf_pktopts;
	u_int32_t ifmtu;

#if IPSEC
	int needipsectun = 0;
	struct socket *so = NULL;
	struct secpolicy *sp = NULL;
	struct route_in6 *ipsec_saved_route = NULL;
	struct ipsec_output_state ipsec_state;

	bzero(&ipsec_state, sizeof(ipsec_state));
		
	/* for AH processing. stupid to have "socket" variable in IP layer... */
	if (ipsec_bypass == 0)
	{
		so = ipsec_getsocket(m);
		(void)ipsec_setsocket(m, NULL);
	}
#endif /* IPSEC */

	bzero(&ipf_pktopts, sizeof(struct ipf_pktopts));
	ippo = &ipf_pktopts;

	ip6 = mtod(m, struct ip6_hdr *);
	inject_filter_ref = ipf_get_inject_filter(m);
	
	finaldst = ip6->ip6_dst;

	if (ip6_doscopedroute && (flags & IPV6_OUTARGS)) {
		select_srcif = !(flags & (IPV6_FORWARDING | IPV6_UNSPECSRC | IPV6_FLAG_NOSRCIFSEL));
		ifscope = ip6oa->ip6oa_boundif;
		ipf_pktopts.ippo_flags = IPPOF_BOUND_IF;
		ipf_pktopts.ippo_flags |= (ifscope << IPPOF_SHIFT_IFSCOPE);
	} else {
		select_srcif = FALSE;
		ifscope = IFSCOPE_NONE;
	}

	if (flags & IPV6_OUTARGS) {
		nocell = ip6oa->ip6oa_nocell;
		if (nocell)
			ipf_pktopts.ippo_flags |= IPPOF_NO_IFT_CELLULAR;
	} else {
		nocell = 0;
	}

#define MAKE_EXTHDR(hp, mp)						\
    do {								\
	if (hp) {							\
		struct ip6_ext *eh = (struct ip6_ext *)(hp);		\
		error = ip6_copyexthdr((mp), (caddr_t)(hp), 		\
				       ((eh)->ip6e_len + 1) << 3);	\
		if (error)						\
			goto freehdrs;					\
	}								\
    } while (0)
	
	bzero(&exthdrs, sizeof(exthdrs));
	
	if (opt) {
		/* Hop-by-Hop options header */
		MAKE_EXTHDR(opt->ip6po_hbh, &exthdrs.ip6e_hbh);
		/* Destination options header(1st part) */
		if (opt->ip6po_rthdr) {
			/*
			 * Destination options header(1st part)
			 * This only makes sense with a routing header.
			 * See Section 9.2 of RFC 3542.
			 * Disabling this part just for MIP6 convenience is
			 * a bad idea.  We need to think carefully about a
			 * way to make the advanced API coexist with MIP6
			 * options, which might automatically be inserted in
			 * the kernel.
			 */
			MAKE_EXTHDR(opt->ip6po_dest1, &exthdrs.ip6e_dest1);
		}
		/* Routing header */
		MAKE_EXTHDR(opt->ip6po_rthdr, &exthdrs.ip6e_rthdr);
		/* Destination options header(2nd part) */
		MAKE_EXTHDR(opt->ip6po_dest2, &exthdrs.ip6e_dest2);
	}

#if IPSEC
	if (ipsec_bypass != 0)
		goto skip_ipsec;
	
	/* get a security policy for this packet */
	if (so == NULL)
		sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_OUTBOUND, 0, &error);
	else
		sp = ipsec6_getpolicybysock(m, IPSEC_DIR_OUTBOUND, so, &error);

	if (sp == NULL) {
		IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
		goto freehdrs;
	}

	error = 0;

	/* check policy */
	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_GENERATE:
		/*
		 * This packet is just discarded.
		 */
		IPSEC_STAT_INCREMENT(ipsec6stat.out_polvio);
		goto freehdrs;

	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_NONE:
		/* no need to do IPsec. */
		needipsec = 0;
		break;
	
	case IPSEC_POLICY_IPSEC:
		if (sp->req == NULL) {
			/* acquire a policy */
			error = key_spdacquire(sp);
			goto freehdrs;
		}
		needipsec = 1;
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		printf("ip6_output: Invalid policy found. %d\n", sp->policy);
	}
	skip_ipsec:
#endif /* IPSEC */

	/*
	 * Calculate the total length of the extension header chain.
	 * Keep the length of the unfragmentable part for fragmentation.
	 */
	optlen = 0;
	if (exthdrs.ip6e_hbh)
		optlen += exthdrs.ip6e_hbh->m_len;
	if (exthdrs.ip6e_dest1)
		optlen += exthdrs.ip6e_dest1->m_len;
	if (exthdrs.ip6e_rthdr)
		optlen += exthdrs.ip6e_rthdr->m_len;
	unfragpartlen = optlen + sizeof(struct ip6_hdr);

	/* NOTE: we don't add AH/ESP length here. do that later. */
	if (exthdrs.ip6e_dest2)
		optlen += exthdrs.ip6e_dest2->m_len;


	if (needipsec &&
	    (m->m_pkthdr.csum_flags & CSUM_DELAY_IPV6_DATA) != 0) {
		in6_delayed_cksum(m, sizeof(struct ip6_hdr) + optlen);
		m->m_pkthdr.csum_flags &= ~CSUM_DELAY_IPV6_DATA;
	}

	/*
	 * If we need IPsec, or there is at least one extension header,
	 * separate IP6 header from the payload.
	 */
	if ((needipsec || optlen) && !hdrsplit) {
		if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
			m = NULL;
			goto freehdrs;
		}
		m = exthdrs.ip6e_ip6;
		hdrsplit++;
	}

	/* adjust pointer */
	ip6 = mtod(m, struct ip6_hdr *);

	/* adjust mbuf packet header length */
	m->m_pkthdr.len += optlen;
	plen = m->m_pkthdr.len - sizeof(*ip6);

	/* If this is a jumbo payload, insert a jumbo payload option. */
	if (plen > IPV6_MAXPACKET) {
		if (!hdrsplit) {
			if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
				m = NULL;
				goto freehdrs;
			}
			m = exthdrs.ip6e_ip6;
			hdrsplit++;
		}
		/* adjust pointer */
		ip6 = mtod(m, struct ip6_hdr *);
		if ((error = ip6_insert_jumboopt(&exthdrs, plen)) != 0)
			goto freehdrs;
		ip6->ip6_plen = 0;
	} else
		ip6->ip6_plen = htons(plen);

	/*
	 * Concatenate headers and fill in next header fields.
	 * Here we have, on "m"
	 *	IPv6 payload
	 * and we insert headers accordingly.  Finally, we should be getting:
	 *	IPv6 hbh dest1 rthdr ah* [esp* dest2 payload]
	 *
	 * during the header composing process, "m" points to IPv6 header.
	 * "mprev" points to an extension header prior to esp.
	 */
	{
		u_char *nexthdrp = &ip6->ip6_nxt;
		struct mbuf *mprev = m;

		/*
		 * we treat dest2 specially.  this makes IPsec processing
		 * much easier.  the goal here is to make mprev point the
		 * mbuf prior to dest2.
		 *
		 * result: IPv6 dest2 payload
		 * m and mprev will point to IPv6 header.
		 */
		if (exthdrs.ip6e_dest2) {
			if (!hdrsplit)
				panic("assumption failed: hdr not split");
			exthdrs.ip6e_dest2->m_next = m->m_next;
			m->m_next = exthdrs.ip6e_dest2;
			*mtod(exthdrs.ip6e_dest2, u_char *) = ip6->ip6_nxt;
			ip6->ip6_nxt = IPPROTO_DSTOPTS;
		}

#define MAKE_CHAIN(m, mp, p, i)\
    do {\
	if (m) {\
		if (!hdrsplit) \
			panic("assumption failed: hdr not split"); \
		*mtod((m), u_char *) = *(p);\
		*(p) = (i);\
		p = mtod((m), u_char *);\
		(m)->m_next = (mp)->m_next;\
		(mp)->m_next = (m);\
		(mp) = (m);\
	}\
    } while (0)
		/*
		 * result: IPv6 hbh dest1 rthdr dest2 payload
		 * m will point to IPv6 header.  mprev will point to the
		 * extension header prior to dest2 (rthdr in the above case).
		 */
		MAKE_CHAIN(exthdrs.ip6e_hbh, mprev,
			   nexthdrp, IPPROTO_HOPOPTS);
		MAKE_CHAIN(exthdrs.ip6e_dest1, mprev,
			   nexthdrp, IPPROTO_DSTOPTS);
		MAKE_CHAIN(exthdrs.ip6e_rthdr, mprev,
			   nexthdrp, IPPROTO_ROUTING);

		if (!TAILQ_EMPTY(&ipv6_filters)) {
			struct ipfilter	*filter;
			int seen = (inject_filter_ref == 0);
			int	fixscope = 0;

			if (im6o != NULL && IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
				ippo->ippo_flags |= IPPOF_MCAST_OPTS;
				IM6O_LOCK(im6o);
				ippo->ippo_mcast_ifnet = im6o->im6o_multicast_ifp;
				ippo->ippo_mcast_ttl = im6o->im6o_multicast_hlim;
				ippo->ippo_mcast_loop = im6o->im6o_multicast_loop;
				IM6O_UNLOCK(im6o);
			}

			/* Hack: embed the scope_id in the destination */
			if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst) &&
				(ip6->ip6_dst.s6_addr16[1] == 0) && (ro != NULL)) {
				fixscope = 1;
				ip6->ip6_dst.s6_addr16[1] = htons(ro->ro_dst.sin6_scope_id);
			}
			{
				ipf_ref();
				TAILQ_FOREACH(filter, &ipv6_filters, ipf_link) {
					/*
					 * No need to proccess packet twice if we've 
					 * already seen it
					 */
					if (seen == 0) {
						if ((struct ipfilter *)inject_filter_ref == filter)
							seen = 1;
					} else if (filter->ipf_filter.ipf_output) {
						errno_t result;
						
						result = filter->ipf_filter.ipf_output(filter->ipf_filter.cookie, (mbuf_t*)&m, ippo);
						if (result == EJUSTRETURN) {
							ipf_unref();
							goto done;
						}
						if (result != 0) {
							ipf_unref();
							goto bad;
						}
					}
				}
				ipf_unref();
			}
			ip6 = mtod(m, struct ip6_hdr *);
			/* Hack: cleanup embedded scope_id if we put it there */
			if (fixscope)
				ip6->ip6_dst.s6_addr16[1] = 0;
		}

#if IPSEC
		if (!needipsec)
			goto skip_ipsec2;

		/*
		 * pointers after IPsec headers are not valid any more.
		 * other pointers need a great care too.
		 * (IPsec routines should not mangle mbufs prior to AH/ESP)
		 */
		exthdrs.ip6e_dest2 = NULL;

	    {
		struct ip6_rthdr *rh = NULL;
		int segleft_org = 0;

		if (exthdrs.ip6e_rthdr) {
			rh = mtod(exthdrs.ip6e_rthdr, struct ip6_rthdr *);
			segleft_org = rh->ip6r_segleft;
			rh->ip6r_segleft = 0;
		}

		ipsec_state.m = m;
		error = ipsec6_output_trans(&ipsec_state, nexthdrp, mprev, sp, flags,
			&needipsectun);
		m = ipsec_state.m;
		if (error) {
			/* mbuf is already reclaimed in ipsec6_output_trans. */
			m = NULL;
			switch (error) {
			case EHOSTUNREACH:
			case ENETUNREACH:
			case EMSGSIZE:
			case ENOBUFS:
			case ENOMEM:
				break;
			default:
				printf("ip6_output (ipsec): error code %d\n", error);
				/* fall through */
			case ENOENT:
				/* don't show these error codes to the user */
				error = 0;
				break;
			}
			goto bad;
		}
		if (exthdrs.ip6e_rthdr) {
			/* ah6_output doesn't modify mbuf chain */
			rh->ip6r_segleft = segleft_org;
		}
	  }
	}
skip_ipsec2:
#endif

	/*
	 * If there is a routing header, replace the destination address field
	 * with the first hop of the routing header.
	 */
	if (exthdrs.ip6e_rthdr) {
		struct ip6_rthdr *rh =
			(struct ip6_rthdr *)(mtod(exthdrs.ip6e_rthdr,
						  struct ip6_rthdr *));
		struct ip6_rthdr0 *rh0;
		struct in6_addr *addr;
		struct sockaddr_in6 sa;

		switch (rh->ip6r_type) {
		case IPV6_RTHDR_TYPE_0:
			 rh0 = (struct ip6_rthdr0 *)rh;
			 addr = (struct in6_addr *)(rh0 + 1);

			 /*
			  * construct a sockaddr_in6 form of
			  * the first hop.
			  *
			  * XXX: we may not have enough
			  * information about its scope zone;
			  * there is no standard API to pass
			  * the information from the
			  * application.
			  */
			 bzero(&sa, sizeof(sa));
			 sa.sin6_family = AF_INET6;
			 sa.sin6_len = sizeof(sa);
			 sa.sin6_addr = addr[0];
			 if ((error = sa6_embedscope(&sa,
			     ip6_use_defzone)) != 0) {
				 goto bad;
			 }
			 ip6->ip6_dst = sa.sin6_addr;
			 bcopy(&addr[1], &addr[0], sizeof(struct in6_addr)
			     * (rh0->ip6r0_segleft - 1));
			 addr[rh0->ip6r0_segleft - 1] = finaldst;
			 /* XXX */
			 in6_clearscope(addr + rh0->ip6r0_segleft - 1);
			 break;
		default:	/* is it possible? */
			 error = EINVAL;
			 goto bad;
		}
	}

	/* Source address validation */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) &&
	    (flags & IPV6_UNSPECSRC) == 0) {
		error = EOPNOTSUPP;
		ip6stat.ip6s_badscope++;
		goto bad;
	}
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src)) {
		error = EOPNOTSUPP;
		ip6stat.ip6s_badscope++;
		goto bad;
	}

	ip6stat.ip6s_localout++;

	/*
	 * Route packet.
	 */
	if (ro == 0) {
		ro = &ip6route;
		bzero((caddr_t)ro, sizeof(*ro));
	}
	ro_pmtu = ro;
	if (opt && opt->ip6po_rthdr)
		ro = &opt->ip6po_route;
	dst = (struct sockaddr_in6 *)&ro->ro_dst;

	if (ro && ro->ro_rt)
		RT_LOCK_ASSERT_NOTHELD(ro->ro_rt);
	/*
	 * if specified, try to fill in the traffic class field.
	 * do not override if a non-zero value is already set.
	 * we check the diffserv field and the ecn field separately.
	 */
	if (opt && opt->ip6po_tclass >= 0) {
		int mask = 0;

		if ((ip6->ip6_flow & htonl(0xfc << 20)) == 0)
			mask |= 0xfc;
		if ((ip6->ip6_flow & htonl(0x03 << 20)) == 0)
			mask |= 0x03;
		if (mask != 0)
			ip6->ip6_flow |= htonl((opt->ip6po_tclass & mask) << 20);
	}

	/* fill in or override the hop limit field, if necessary. */
	if (opt && opt->ip6po_hlim != -1)
		ip6->ip6_hlim = opt->ip6po_hlim & 0xff;
	else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		if (im6o != NULL) {
			IM6O_LOCK(im6o);
			ip6->ip6_hlim = im6o->im6o_multicast_hlim;
			IM6O_UNLOCK(im6o);
		} else {
			ip6->ip6_hlim = ip6_defmcasthlim;
		}
	}

	/*
	 * If there is a cached route, check that it is to the same
	 * destination and is still up. If not, free it and try again.
	 * Test rt_flags without holding rt_lock for performance reasons;
	 * if the route is down it will hopefully be caught by the layer
	 * below (since it uses this route as a hint) or during the
	 * next transmit.
	 */
	if (ro->ro_rt != NULL && (!(ro->ro_rt->rt_flags & RTF_UP) ||
	    dst->sin6_family != AF_INET6 ||
	    !IN6_ARE_ADDR_EQUAL(&dst->sin6_addr, &ip6->ip6_dst) ||
	    ro->ro_rt->generation_id != route_generation)) {
		rtfree(ro->ro_rt);
		ro->ro_rt = NULL;
	}
	if (ro->ro_rt == NULL) {
		bzero(dst, sizeof(*dst));
		dst->sin6_family = AF_INET6;
		dst->sin6_len = sizeof(struct sockaddr_in6);
		dst->sin6_addr = ip6->ip6_dst;
	}

#if IPSEC
	if (needipsec && needipsectun) {
#if CONFIG_DTRACE
		struct ifnet *trace_ifp = (ifpp != NULL) ? (*ifpp) : NULL;
#endif /* CONFIG_DTRACE */
		/*
		 * All the extension headers will become inaccessible
		 * (since they can be encrypted).
		 * Don't panic, we need no more updates to extension headers
		 * on inner IPv6 packet (since they are now encapsulated).
		 *
		 * IPv6 [ESP|AH] IPv6 [extension headers] payload
		 */
		bzero(&exthdrs, sizeof(exthdrs));
		exthdrs.ip6e_ip6 = m;

		ipsec_state.m = m;
		route_copyout(&ipsec_state.ro, (struct route *)ro, sizeof(ipsec_state.ro));
		ipsec_state.dst = (struct sockaddr *)dst;

		/* Added a trace here so that we can see packets inside a tunnel */
		DTRACE_IP6(send, struct mbuf *, m, struct inpcb *, NULL,
			struct ip6_hdr *, ip6, struct ifnet *, trace_ifp,
			struct ip *, NULL, struct ip6_hdr *, ip6); 

		error = ipsec6_output_tunnel(&ipsec_state, sp, flags);
		if (ipsec_state.tunneled == 4)	/* tunneled in IPv4 - packet is gone */
			goto done;
		m = ipsec_state.m;
		ipsec_saved_route = ro;
		ro = (struct route_in6 *)&ipsec_state.ro;
		dst = (struct sockaddr_in6 *)ipsec_state.dst;
		if (error) {
			/* mbuf is already reclaimed in ipsec6_output_tunnel. */
			m0 = m = NULL;
			m = NULL;
			switch (error) {
			case EHOSTUNREACH:
			case ENETUNREACH:
			case EMSGSIZE:
			case ENOBUFS:
			case ENOMEM:
				break;
			default:
				printf("ip6_output (ipsec): error code %d\n", error);
				/* fall through */
			case ENOENT:
				/* don't show these error codes to the user */
				error = 0;
				break;
			}
			goto bad;
		}
		/* 
		 * The packet has been encapsulated so the ifscope is no longer valid
		 * since it does not apply to the outer address: ignore the ifscope.
		 */
		ifscope = IFSCOPE_NONE;
		if (opt != NULL && opt->ip6po_pktinfo != NULL) {
			if (opt->ip6po_pktinfo->ipi6_ifindex != IFSCOPE_NONE)
				opt->ip6po_pktinfo->ipi6_ifindex = IFSCOPE_NONE;
		}
		exthdrs.ip6e_ip6 = m;
	}
#endif /* IPSEC */

	/* for safety */
	if (ifp != NULL) {
		ifnet_release(ifp);
		ifp = NULL;
	}

	/* adjust pointer */
	ip6 = mtod(m, struct ip6_hdr *);

	if (select_srcif) {
		bzero(&src_sa, sizeof(src_sa));
		src_sa.sin6_family = AF_INET6;
		src_sa.sin6_len = sizeof(src_sa);
		src_sa.sin6_addr = ip6->ip6_src;
	}
	bzero(&dst_sa, sizeof(dst_sa));
	dst_sa.sin6_family = AF_INET6;
	dst_sa.sin6_len = sizeof(dst_sa);
	dst_sa.sin6_addr = ip6->ip6_dst;

	if ((error = in6_selectroute(select_srcif ? &src_sa : NULL,
	    &dst_sa, opt, im6o, ro, &ifp, &rt, 0, ifscope, nocell)) != 0) {
		switch (error) {
		case EHOSTUNREACH:
			ip6stat.ip6s_noroute++;
			break;
		case EADDRNOTAVAIL:
		default:
			break; /* XXX statistics? */
		}
		if (ifp != NULL)
			in6_ifstat_inc(ifp, ifs6_out_discard);
		goto bad;
	}
	if (rt == NULL) {
		/*
		 * If in6_selectroute() does not return a route entry,
		 * dst may not have been updated.
		 */
		*dst = dst_sa;	/* XXX */
	}

	/*
	 * then rt (for unicast) and ifp must be non-NULL valid values.
	 */
	if ((flags & IPV6_FORWARDING) == 0) {
		/* XXX: the FORWARDING flag can be set for mrouting. */
		in6_ifstat_inc(ifp, ifs6_out_request);
	}
	if (rt != NULL) {
		RT_LOCK(rt);
		ia = (struct in6_ifaddr *)(rt->rt_ifa);
		if (ia != NULL)
			IFA_ADDREF(&ia->ia_ifa);
		rt->rt_use++;
		RT_UNLOCK(rt);
	}

	/*
	 * The outgoing interface must be in the zone of source and
	 * destination addresses.  We should use ia_ifp to support the
	 * case of sending packets to an address of our own.
	 */
	if (ia != NULL && ia->ia_ifp) {
		ifnet_reference(ia->ia_ifp);
		if (origifp != NULL)
			ifnet_release(origifp);
		origifp = ia->ia_ifp;
	} else {
		if (ifp != NULL)
			ifnet_reference(ifp);
		if (origifp != NULL)
			ifnet_release(origifp);
		origifp = ifp;
	}
	src0 = ip6->ip6_src;
	if (in6_setscope(&src0, origifp, &zone))
		goto badscope;
	bzero(&src_sa, sizeof(src_sa));
	src_sa.sin6_family = AF_INET6;
	src_sa.sin6_len = sizeof(src_sa);
	src_sa.sin6_addr = ip6->ip6_src;
	if (sa6_recoverscope(&src_sa) || zone != src_sa.sin6_scope_id)
		goto badscope;

	dst0 = ip6->ip6_dst;
	if (in6_setscope(&dst0, origifp, &zone))
		goto badscope;
	/* re-initialize to be sure */
	bzero(&dst_sa, sizeof(dst_sa));
	dst_sa.sin6_family = AF_INET6;
	dst_sa.sin6_len = sizeof(dst_sa);
	dst_sa.sin6_addr = ip6->ip6_dst;
	if (sa6_recoverscope(&dst_sa) || zone != dst_sa.sin6_scope_id) {
		goto badscope;
	}

	/* scope check is done. */
	goto routefound;

  badscope:
	ip6stat.ip6s_badscope++;
	in6_ifstat_inc(origifp, ifs6_out_discard);
	if (error == 0)
		error = EHOSTUNREACH; /* XXX */
	goto bad;

  routefound:
	if (rt && !IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		if (opt && opt->ip6po_nextroute.ro_rt) {
			/*
			 * The nexthop is explicitly specified by the
			 * application.  We assume the next hop is an IPv6
			 * address.
			 */
			dst = (struct sockaddr_in6 *)opt->ip6po_nexthop;
		}
		else if ((rt->rt_flags & RTF_GATEWAY))
			dst = (struct sockaddr_in6 *)rt->rt_gateway;
	}

	if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		m->m_flags &= ~(M_BCAST | M_MCAST); /* just in case */
	} else {
		struct	in6_multi *in6m;

		m->m_flags = (m->m_flags & ~M_BCAST) | M_MCAST;

		in6_ifstat_inc(ifp, ifs6_out_mcast);

		/*
		 * Confirm that the outgoing interface supports multicast.
		 */
		if ((ifp->if_flags & IFF_MULTICAST) == 0) {
			ip6stat.ip6s_noroute++;
			in6_ifstat_inc(ifp, ifs6_out_discard);
			error = ENETUNREACH;
			goto bad;
		}
		in6_multihead_lock_shared();
		IN6_LOOKUP_MULTI(&ip6->ip6_dst, ifp, in6m);
		in6_multihead_lock_done();
		if (im6o != NULL)
			IM6O_LOCK(im6o);
		if (in6m != NULL &&
		   (im6o == NULL || im6o->im6o_multicast_loop)) {
			if (im6o != NULL)
				IM6O_UNLOCK(im6o);
			/*
			 * If we belong to the destination multicast group
			 * on the outgoing interface, and the caller did not
			 * forbid loopback, loop back a copy.
			 */
			ip6_mloopback(ifp, m, dst);
		} else {
			if (im6o != NULL)
				IM6O_UNLOCK(im6o);
			/*
			 * If we are acting as a multicast router, perform
			 * multicast forwarding as if the packet had just
			 * arrived on the interface to which we are about
			 * to send.  The multicast forwarding function
			 * recursively calls this function, using the
			 * IPV6_FORWARDING flag to prevent infinite recursion.
			 *
			 * Multicasts that are looped back by ip6_mloopback(),
			 * above, will be forwarded by the ip6_input() routine,
			 * if necessary.
			 */
#if MROUTING
			if (ip6_mrouter && (flags & IPV6_FORWARDING) == 0) {
				/*
				 * XXX: ip6_mforward expects that rcvif is NULL
				 * when it is called from the originating path.
				 * However, it is not always the case, since
				 * some versions of MGETHDR() does not
				 * initialize the field.
				 */
				m->m_pkthdr.rcvif = NULL;
				if (ip6_mforward(ip6, ifp, m) != 0) {
					m_freem(m);
					if (in6m != NULL)
						IN6M_REMREF(in6m);
					goto done;
				}
			}
#endif
		}
		if (in6m != NULL)
			IN6M_REMREF(in6m);
		/*
		 * Multicasts with a hoplimit of zero may be looped back,
		 * above, but must not be transmitted on a network.
		 * Also, multicasts addressed to the loopback interface
		 * are not sent -- the above call to ip6_mloopback() will
		 * loop back a copy if this host actually belongs to the
		 * destination group on the loopback interface.
		 */
		if (ip6->ip6_hlim == 0 || (ifp->if_flags & IFF_LOOPBACK) ||
		    IN6_IS_ADDR_MC_INTFACELOCAL(&ip6->ip6_dst)) {
			m_freem(m);
			goto done;
		}
	}

	/*
	 * Fill the outgoing inteface to tell the upper layer
	 * to increment per-interface statistics.
	 */
	if (ifpp != NULL) {
		ifnet_reference(ifp);	/* for caller */
		if (*ifpp != NULL)
			ifnet_release(*ifpp);
		*ifpp = ifp;
	}

	/* Determine path MTU. */
	if ((error = ip6_getpmtu(ro_pmtu, ro, ifp, &finaldst, &mtu,
	    &alwaysfrag)) != 0)
		goto bad;

	/*
	 * The caller of this function may specify to use the minimum MTU
	 * in some cases.
	 * An advanced API option (IPV6_USE_MIN_MTU) can also override MTU
	 * setting.  The logic is a bit complicated; by default, unicast
	 * packets will follow path MTU while multicast packets will be sent at
	 * the minimum MTU.  If IP6PO_MINMTU_ALL is specified, all packets
	 * including unicast ones will be sent at the minimum MTU.  Multicast
	 * packets will always be sent at the minimum MTU unless
	 * IP6PO_MINMTU_DISABLE is explicitly specified.
	 * See RFC 3542 for more details.
	 */
	if (mtu > IPV6_MMTU) {
		if ((flags & IPV6_MINMTU))
			mtu = IPV6_MMTU;
		else if (opt && opt->ip6po_minmtu == IP6PO_MINMTU_ALL)
			mtu = IPV6_MMTU;
		else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) &&
			 (opt == NULL ||
			  opt->ip6po_minmtu != IP6PO_MINMTU_DISABLE)) {
			mtu = IPV6_MMTU;
		}
	}

	/*
	 * clear embedded scope identifiers if necessary.
	 * in6_clearscope will touch the addresses only when necessary.
	 */
	in6_clearscope(&ip6->ip6_src);
	in6_clearscope(&ip6->ip6_dst);

#if IPFW2
	/*
	 * Check with the firewall...
	 */
        if (ip6_fw_enable && ip6_fw_chk_ptr) {
		u_short port = 0;
		m->m_pkthdr.rcvif = NULL;	/* XXX */
		/* If ipfw says divert, we have to just drop packet */
		if (ip6_fw_chk_ptr(&ip6, ifp, &port, &m)) {
			m_freem(m);
			goto done;
		}
		if (!m) {
			error = EACCES;
			goto done;
		}
	}
#endif

	/*
	 * If the outgoing packet contains a hop-by-hop options header,
	 * it must be examined and processed even by the source node.
	 * (RFC 2460, section 4.)
	 */
	if (exthdrs.ip6e_hbh) {
		struct ip6_hbh *hbh = mtod(exthdrs.ip6e_hbh, struct ip6_hbh *);
		u_int32_t dummy; /* XXX unused */

#if DIAGNOSTIC
		if ((hbh->ip6h_len + 1) << 3 > exthdrs.ip6e_hbh->m_len)
			panic("ip6e_hbh is not continuous");
#endif
		/*
		 *  XXX: if we have to send an ICMPv6 error to the sender,
		 *       we need the M_LOOP flag since icmp6_error() expects
		 *       the IPv6 and the hop-by-hop options header are
		 *       continuous unless the flag is set.
		 */
		m->m_flags |= M_LOOP;
		m->m_pkthdr.rcvif = ifp;
		if (ip6_process_hopopts(m, (u_int8_t *)(hbh + 1),
		    ((hbh->ip6h_len + 1) << 3) - sizeof(struct ip6_hbh),
		    &dummy, &plen) < 0) {
			/* m was already freed at this point */
			error = EINVAL;/* better error? */
			goto done;
		}
		m->m_flags &= ~M_LOOP; /* XXX */
		m->m_pkthdr.rcvif = NULL;
	}

#if PF
	if (PF_IS_ENABLED) {
		/* Invoke outbound packet filter */
		error = pf_af_hook(ifp, NULL, &m, AF_INET6, FALSE);

		if (error) {
			if (m != NULL) {
				panic("%s: unexpected packet %p\n", __func__, m);
				/* NOTREACHED */
			}
			/* Already freed by callee */
			goto done;
		}
		ip6 = mtod(m, struct ip6_hdr *);
	}
#endif /* PF */

	/*
	 * Send the packet to the outgoing interface.
	 * If necessary, do IPv6 fragmentation before sending.
	 *
	 * the logic here is rather complex:
	 * 1: normal case (dontfrag == 0, alwaysfrag == 0)
	 * 1-a:	send as is if tlen <= path mtu
	 * 1-b:	fragment if tlen > path mtu
	 *
	 * 2: if user asks us not to fragment (dontfrag == 1)
	 * 2-a:	send as is if tlen <= interface mtu
	 * 2-b:	error if tlen > interface mtu
	 *
	 * 3: if we always need to attach fragment header (alwaysfrag == 1)
	 *	always fragment
	 *
	 * 4: if dontfrag == 1 && alwaysfrag == 1
	 *	error, as we cannot handle this conflicting request
	 */
	tlen = m->m_pkthdr.len;

	if (opt && (opt->ip6po_flags & IP6PO_DONTFRAG))
		dontfrag = 1;
	else
		dontfrag = 0;
	if (dontfrag && alwaysfrag) {	/* case 4 */
		/* conflicting request - can't transmit */
		error = EMSGSIZE;
		goto bad;
	}

	lck_rw_lock_shared(nd_if_rwlock);
	ifmtu = IN6_LINKMTU(ifp);
	lck_rw_done(nd_if_rwlock);

	if (dontfrag && tlen > ifmtu) {	/* case 2-b */
		/*
		 * Even if the DONTFRAG option is specified, we cannot send the
		 * packet when the data length is larger than the MTU of the
		 * outgoing interface.
		 * Notify the error by sending IPV6_PATHMTU ancillary data as
		 * well as returning an error code (the latter is not described
		 * in the API spec.)
		 */
		u_int32_t mtu32;
		struct ip6ctlparam ip6cp;

		mtu32 = (u_int32_t)mtu;
		bzero(&ip6cp, sizeof(ip6cp));
		ip6cp.ip6c_cmdarg = (void *)&mtu32;
		pfctlinput2(PRC_MSGSIZE, (struct sockaddr *)&ro_pmtu->ro_dst,
		    (void *)&ip6cp);

		error = EMSGSIZE;
		goto bad;
	}

	/*
	 * transmit packet without fragmentation
	 */
	tso = (ifp->if_hwassist & IFNET_TSO_IPV6) &&
	    (m->m_pkthdr.csum_flags & CSUM_TSO_IPV6);
	if (dontfrag || (!alwaysfrag &&		/* case 1-a and 2-a */
	    (tlen <= mtu || tso || (ifp->if_hwassist & CSUM_FRAGMENT_IPV6)))) {
		int sw_csum;

		ip6 = mtod(m, struct ip6_hdr *);
#ifdef IPSEC
		/* clean ipsec history once it goes out of the node */
		ipsec_delaux(m);
#endif

		if (apple_hwcksum_tx == 0) /* Do not let HW handle cksum */
			sw_csum = m->m_pkthdr.csum_flags;
		else
			sw_csum = m->m_pkthdr.csum_flags &
			    ~IF_HWASSIST_CSUM_FLAGS(ifp->if_hwassist);

		if ((sw_csum & CSUM_DELAY_IPV6_DATA) != 0) {
			in6_delayed_cksum(m, sizeof(struct ip6_hdr) + optlen);
			m->m_pkthdr.csum_flags &= ~CSUM_DELAY_IPV6_DATA;
		}
		if (ro->ro_rt)
			RT_LOCK_ASSERT_NOTHELD(ro->ro_rt);
		error = nd6_output(ifp, origifp, m, dst, ro->ro_rt);
		goto done;
	}

	/*
	 * try to fragment the packet.  case 1-b and 3
	 */
	if (mtu < IPV6_MMTU) {
		/* path MTU cannot be less than IPV6_MMTU */
		error = EMSGSIZE;
		in6_ifstat_inc(ifp, ifs6_out_fragfail);
		goto bad;
	} else if (ip6->ip6_plen == 0) {
		/* jumbo payload cannot be fragmented */
		error = EMSGSIZE;
		in6_ifstat_inc(ifp, ifs6_out_fragfail);
		goto bad;
	} else {
		struct mbuf **mnext, *m_frgpart;
		struct ip6_frag *ip6f;
		u_int32_t id = htonl(ip6_randomid());
		u_char nextproto;

		/*
		 * Too large for the destination or interface;
		 * fragment if possible.
		 * Must be able to put at least 8 bytes per fragment.
		 */
		hlen = unfragpartlen;
		if (mtu > IPV6_MAXPACKET)
			mtu = IPV6_MAXPACKET;

		len = (mtu - hlen - sizeof(struct ip6_frag)) & ~7;
		if (len < 8) {
			error = EMSGSIZE;
			in6_ifstat_inc(ifp, ifs6_out_fragfail);
			goto bad;
		}

		mnext = &m->m_nextpkt;

		/*
		 * Change the next header field of the last header in the
		 * unfragmentable part.
		 */
		if (exthdrs.ip6e_rthdr) {
			nextproto = *mtod(exthdrs.ip6e_rthdr, u_char *);
			*mtod(exthdrs.ip6e_rthdr, u_char *) = IPPROTO_FRAGMENT;
		} else if (exthdrs.ip6e_dest1) {
			nextproto = *mtod(exthdrs.ip6e_dest1, u_char *);
			*mtod(exthdrs.ip6e_dest1, u_char *) = IPPROTO_FRAGMENT;
		} else if (exthdrs.ip6e_hbh) {
			nextproto = *mtod(exthdrs.ip6e_hbh, u_char *);
			*mtod(exthdrs.ip6e_hbh, u_char *) = IPPROTO_FRAGMENT;
		} else {
			nextproto = ip6->ip6_nxt;
			ip6->ip6_nxt = IPPROTO_FRAGMENT;
		}

		if ((m->m_pkthdr.csum_flags & CSUM_DELAY_IPV6_DATA) != 0) {
			in6_delayed_cksum(m, sizeof(struct ip6_hdr) + optlen);
			m->m_pkthdr.csum_flags &= ~CSUM_DELAY_IPV6_DATA;
		}

		/*
		 * Loop through length of segment after first fragment,
		 * make new header and copy data of each part and link onto
		 * chain.
		 */
		m0 = m;
		for (off = hlen; off < tlen; off += len) {
			MGETHDR(m, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
			if (!m) {
				error = ENOBUFS;
				ip6stat.ip6s_odropped++;
				goto sendorfree;
			}
			m->m_pkthdr.rcvif = NULL;
			m->m_flags = m0->m_flags & M_COPYFLAGS;
			*mnext = m;
			mnext = &m->m_nextpkt;
			m->m_data += max_linkhdr;
			mhip6 = mtod(m, struct ip6_hdr *);
			*mhip6 = *ip6;
			m->m_len = sizeof(*mhip6);
 			error = ip6_insertfraghdr(m0, m, hlen, &ip6f);
 			if (error) {
				ip6stat.ip6s_odropped++;
				goto sendorfree;
			}
			ip6f->ip6f_offlg = htons((u_short)((off - hlen) & ~7));
			if (off + len >= tlen)
				len = tlen - off;
			else
				ip6f->ip6f_offlg |= IP6F_MORE_FRAG;
			mhip6->ip6_plen = htons((u_short)(len + hlen +
							  sizeof(*ip6f) -
							  sizeof(struct ip6_hdr)));
			if ((m_frgpart = m_copy(m0, off, len)) == 0) {
				error = ENOBUFS;
				ip6stat.ip6s_odropped++;
				goto sendorfree;
			}
			m_cat(m, m_frgpart);
			m->m_pkthdr.len = len + hlen + sizeof(*ip6f);
			m->m_pkthdr.rcvif = 0;
			m->m_pkthdr.socket_id = m0->m_pkthdr.socket_id;
#ifdef __darwin8_notyet
#if CONFIG_MACF_NET
			mac_create_fragment(m0, m);
#endif
#endif
			ip6f->ip6f_reserved = 0;
			ip6f->ip6f_ident = id;
			ip6f->ip6f_nxt = nextproto;
			ip6stat.ip6s_ofragments++;
			in6_ifstat_inc(ifp, ifs6_out_fragcreat);
		}

		in6_ifstat_inc(ifp, ifs6_out_fragok);
	}

	/*
	 * Remove leading garbages.
	 */
sendorfree:
	m = m0->m_nextpkt;
	m0->m_nextpkt = 0;
	m_freem(m0);
	for (m0 = m; m; m = m0) {
		m0 = m->m_nextpkt;
		m->m_nextpkt = 0;
		if (error == 0) {
 			/* Record statistics for this interface address. */
 			if (ia) {
#ifndef __APPLE__
 				ia->ia_ifa.if_opackets++;
 				ia->ia_ifa.if_obytes += m->m_pkthdr.len;
#endif
 			}
#if IPSEC
			/* clean ipsec history once it goes out of the node */
			ipsec_delaux(m);
#endif
			error = nd6_output(ifp, origifp, m, dst, ro->ro_rt);

		} else
			m_freem(m);
	}

	if (error == 0)
		ip6stat.ip6s_fragmented++;

done:
#if IPSEC
	if (ipsec_saved_route) {
		ro = ipsec_saved_route;
		if (ipsec_state.ro.ro_rt) { 
			rtfree(ipsec_state.ro.ro_rt);
		}
	}
#endif /* IPSEC */
	if (ro == &ip6route && ro->ro_rt) { /* brace necessary for rtfree */
		rtfree(ro->ro_rt);
	} else if (ro_pmtu == &ip6route && ro_pmtu->ro_rt) {
		rtfree(ro_pmtu->ro_rt);
	}

#if IPSEC
	if (sp != NULL)
		key_freesp(sp, KEY_SADB_UNLOCKED);
#endif /* IPSEC */

	if (ia != NULL)
		IFA_REMREF(&ia->ia_ifa);
	if (ifp != NULL)
		ifnet_release(ifp);
	if (origifp != NULL)
		ifnet_release(origifp);
	return (error);

freehdrs:
	m_freem(exthdrs.ip6e_hbh);	/* m_freem will check if mbuf is 0 */
	m_freem(exthdrs.ip6e_dest1);
	m_freem(exthdrs.ip6e_rthdr);
	m_freem(exthdrs.ip6e_dest2);
	/* fall through */
bad:
	m_freem(m);
	goto done;
}

static int
ip6_copyexthdr(mp, hdr, hlen)
	struct mbuf **mp;
	caddr_t hdr;
	int hlen;
{
	struct mbuf *m;

	if (hlen > MCLBYTES)
		return(ENOBUFS); /* XXX */

	MGET(m, M_DONTWAIT, MT_DATA);
	if (!m)
		return(ENOBUFS);

	if (hlen > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return (ENOBUFS);
		}
	}
	m->m_len = hlen;
	if (hdr)
		bcopy(hdr, mtod(m, caddr_t), hlen);

	*mp = m;
	return (0);
}

/*
 * Process a delayed payload checksum calculation.
 */
void
in6_delayed_cksum(struct mbuf *m, uint16_t offset)
{
	uint16_t csum;

	csum = in6_cksum(m, 0, offset, m->m_pkthdr.len - offset);
	if (csum == 0 && (m->m_pkthdr.csum_flags & CSUM_UDPIPV6) != 0) {
		csum = 0xffff;
	}

	offset += (m->m_pkthdr.csum_data & 0xffff);
	if ((offset + sizeof(csum)) > m->m_len) {
		m_copyback(m, offset, sizeof(csum), &csum);
	} else {
		*(uint16_t *)(mtod(m, char *) + offset) = csum;
	}
}
/*
 * Insert jumbo payload option.
 */
static int
ip6_insert_jumboopt(exthdrs, plen)
	struct ip6_exthdrs *exthdrs;
	u_int32_t plen;
{
	struct mbuf *mopt;
	u_char *optbuf;
	u_int32_t v;

#define JUMBOOPTLEN	8	/* length of jumbo payload option and padding */

	/*
	 * If there is no hop-by-hop options header, allocate new one.
	 * If there is one but it doesn't have enough space to store the
	 * jumbo payload option, allocate a cluster to store the whole options.
	 * Otherwise, use it to store the options.
	 */
	if (exthdrs->ip6e_hbh == 0) {
		MGET(mopt, M_DONTWAIT, MT_DATA);
		if (mopt == 0)
			return (ENOBUFS);
		mopt->m_len = JUMBOOPTLEN;
		optbuf = mtod(mopt, u_char *);
		optbuf[1] = 0;	/* = ((JUMBOOPTLEN) >> 3) - 1 */
		exthdrs->ip6e_hbh = mopt;
	} else {
		struct ip6_hbh *hbh;

		mopt = exthdrs->ip6e_hbh;
		if (M_TRAILINGSPACE(mopt) < JUMBOOPTLEN) {
			/*
			 * XXX assumption:
			 * - exthdrs->ip6e_hbh is not referenced from places
			 *   other than exthdrs.
			 * - exthdrs->ip6e_hbh is not an mbuf chain.
			 */
			u_int32_t oldoptlen = mopt->m_len;
			struct mbuf *n;

			/*
			 * XXX: give up if the whole (new) hbh header does
			 * not fit even in an mbuf cluster.
			 */
			if (oldoptlen + JUMBOOPTLEN > MCLBYTES)
				return (ENOBUFS);

			/*
			 * As a consequence, we must always prepare a cluster
			 * at this point.
			 */
			MGET(n, M_DONTWAIT, MT_DATA);
			if (n) {
				MCLGET(n, M_DONTWAIT);
				if ((n->m_flags & M_EXT) == 0) {
					m_freem(n);
					n = NULL;
				}
			}
			if (!n)
				return (ENOBUFS);
			n->m_len = oldoptlen + JUMBOOPTLEN;
			bcopy(mtod(mopt, caddr_t), mtod(n, caddr_t),
			    oldoptlen);
			optbuf = mtod(n, u_char *) + oldoptlen;
			m_freem(mopt);
			mopt = exthdrs->ip6e_hbh = n;
		} else {
			optbuf = mtod(mopt, u_char *) + mopt->m_len;
			mopt->m_len += JUMBOOPTLEN;
		}
		optbuf[0] = IP6OPT_PADN;
		optbuf[1] = 1;

		/*
		 * Adjust the header length according to the pad and
		 * the jumbo payload option.
		 */
		hbh = mtod(mopt, struct ip6_hbh *);
		hbh->ip6h_len += (JUMBOOPTLEN >> 3);
	}

	/* fill in the option. */
	optbuf[2] = IP6OPT_JUMBO;
	optbuf[3] = 4;
	v = (u_int32_t)htonl(plen + JUMBOOPTLEN);
	bcopy(&v, &optbuf[4], sizeof(u_int32_t));

	/* finally, adjust the packet header length */
	exthdrs->ip6e_ip6->m_pkthdr.len += JUMBOOPTLEN;

	return (0);
#undef JUMBOOPTLEN
}

/*
 * Insert fragment header and copy unfragmentable header portions.
 */
static int
ip6_insertfraghdr(m0, m, hlen, frghdrp)
	struct mbuf *m0, *m;
	int hlen;
	struct ip6_frag **frghdrp;
{
	struct mbuf *n, *mlast;

	if (hlen > sizeof(struct ip6_hdr)) {
		n = m_copym(m0, sizeof(struct ip6_hdr),
		    hlen - sizeof(struct ip6_hdr), M_DONTWAIT);
		if (n == 0)
			return (ENOBUFS);
		m->m_next = n;
	} else
		n = m;

	/* Search for the last mbuf of unfragmentable part. */
	for (mlast = n; mlast->m_next; mlast = mlast->m_next)
		;

	if ((mlast->m_flags & M_EXT) == 0 &&
	    M_TRAILINGSPACE(mlast) >= sizeof(struct ip6_frag)) {
		/* use the trailing space of the last mbuf for the fragment hdr */
		*frghdrp = (struct ip6_frag *)(mtod(mlast, caddr_t) +
		    mlast->m_len);
		mlast->m_len += sizeof(struct ip6_frag);
		m->m_pkthdr.len += sizeof(struct ip6_frag);
	} else {
		/* allocate a new mbuf for the fragment header */
		struct mbuf *mfrg;

		MGET(mfrg, M_DONTWAIT, MT_DATA);
		if (mfrg == 0)
			return (ENOBUFS);
		mfrg->m_len = sizeof(struct ip6_frag);
		*frghdrp = mtod(mfrg, struct ip6_frag *);
		mlast->m_next = mfrg;
	}

	return (0);
}

extern int load_ipfw(void);
static int
ip6_getpmtu(struct route_in6 *ro_pmtu, struct route_in6 *ro,
    struct ifnet *ifp, struct in6_addr *dst, u_int32_t *mtup,
    int *alwaysfragp)
{
	u_int32_t mtu = 0;
	int alwaysfrag = 0;
	int error = 0;

	if (ro_pmtu != ro) {
		/* The first hop and the final destination may differ. */
		struct sockaddr_in6 *sa6_dst =
		    (struct sockaddr_in6 *)&ro_pmtu->ro_dst;
		if (ro_pmtu->ro_rt &&
		    ((ro_pmtu->ro_rt->rt_flags & RTF_UP) == 0 ||
		     ro_pmtu->ro_rt->generation_id != route_generation ||
		     !IN6_ARE_ADDR_EQUAL(&sa6_dst->sin6_addr, dst))) {
			rtfree(ro_pmtu->ro_rt);
			ro_pmtu->ro_rt = (struct rtentry *)NULL;
		}
		if (ro_pmtu->ro_rt == NULL) {
			bzero(sa6_dst, sizeof(*sa6_dst));
			sa6_dst->sin6_family = AF_INET6;
			sa6_dst->sin6_len = sizeof(struct sockaddr_in6);
			sa6_dst->sin6_addr = *dst;

			rtalloc_scoped((struct route *)ro_pmtu,
			    ifp != NULL ? ifp->if_index : IFSCOPE_NONE);
		}
	}


	if (ro_pmtu->ro_rt != NULL) {
		u_int32_t ifmtu;

		lck_rw_lock_shared(nd_if_rwlock);
		ifmtu = IN6_LINKMTU(ifp);
		lck_rw_done(nd_if_rwlock);

		RT_LOCK_SPIN(ro_pmtu->ro_rt);
		mtu = ro_pmtu->ro_rt->rt_rmx.rmx_mtu;
		if (mtu > ifmtu || mtu == 0) {
			/*
			 * The MTU on the route is larger than the MTU on
			 * the interface!  This shouldn't happen, unless the
			 * MTU of the interface has been changed after the
			 * interface was brought up.  Change the MTU in the
			 * route to match the interface MTU (as long as the
			 * field isn't locked).
			 *
			 * if MTU on the route is 0, we need to fix the MTU.
			 * this case happens with path MTU discovery timeouts.
			 */
			 mtu = ifmtu;
			 if ((ro_pmtu->ro_rt->rt_rmx.rmx_locks & RTV_MTU) == 0)
				 ro_pmtu->ro_rt->rt_rmx.rmx_mtu = mtu; /* XXX */
		}
		else if (mtu < IPV6_MMTU) {
			/*
			 * RFC2460 section 5, last paragraph:
			 * if we record ICMPv6 too big message with
			 * mtu < IPV6_MMTU, transmit packets sized IPV6_MMTU
			 * or smaller, with framgent header attached.
			 * (fragment header is needed regardless from the
			 * packet size, for translators to identify packets)
			 */
			alwaysfrag = 1;
			mtu = IPV6_MMTU;
		} 
		RT_UNLOCK(ro_pmtu->ro_rt);
	} else {
		if (ifp) {
			lck_rw_lock_shared(nd_if_rwlock);
			mtu = IN6_LINKMTU(ifp);
			lck_rw_done(nd_if_rwlock);
		} else
			error = EHOSTUNREACH; /* XXX */
	}

	*mtup = mtu;
	if (alwaysfragp)
		*alwaysfragp = alwaysfrag;
	return (error);
}

/*
 * IP6 socket option processing.
 */
int
ip6_ctloutput(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int optdatalen, uproto;
	void *optdata;
	int privileged;
	struct inpcb *in6p = sotoinpcb(so);
	int error = 0, optval = 0;
	int level, op = -1, optname = 0;
	int optlen = 0;
	struct proc *p;

	if (sopt == NULL) {
		panic("ip6_ctloutput: arg soopt is NULL");
		/* NOTREACHED */
	}
	level = sopt->sopt_level;
	op = sopt->sopt_dir;
	optname = sopt->sopt_name;
	optlen = sopt->sopt_valsize;
	p = sopt->sopt_p;
	uproto = (int)so->so_proto->pr_protocol;

	privileged = (proc_suser(p) == 0);

	if (level == IPPROTO_IPV6) {
		switch (op) {

		case SOPT_SET:
			switch (optname) {
			case IPV6_2292PKTOPTIONS:
			{
				struct mbuf *m;

				error = soopt_getm(sopt, &m); /* XXX */
				if (error != 0)
					break;
				error = soopt_mcopyin(sopt, m); /* XXX */
				if (error != 0)
					break;
				error = ip6_pcbopts(&in6p->in6p_outputopts,
						    m, so, sopt);
				m_freem(m); /* XXX */
				break;
			}

			/*
			 * Use of some Hop-by-Hop options or some
			 * Destination options, might require special
			 * privilege.  That is, normal applications
			 * (without special privilege) might be forbidden
			 * from setting certain options in outgoing packets,
			 * and might never see certain options in received
			 * packets. [RFC 2292 Section 6]
			 * KAME specific note:
			 *  KAME prevents non-privileged users from sending or
			 *  receiving ANY hbh/dst options in order to avoid
			 *  overhead of parsing options in the kernel.
			 */
			case IPV6_RECVHOPOPTS:
			case IPV6_RECVDSTOPTS:
			case IPV6_RECVRTHDRDSTOPTS:
					if (!privileged)
						break;
				/* FALLTHROUGH */
			case IPV6_UNICAST_HOPS:
			case IPV6_HOPLIMIT:
			case IPV6_FAITH:

			case IPV6_RECVPKTINFO:
			case IPV6_RECVHOPLIMIT:
			case IPV6_RECVRTHDR:
			case IPV6_RECVPATHMTU:
			case IPV6_RECVTCLASS:
			case IPV6_V6ONLY:
			case IPV6_AUTOFLOWLABEL:
				if (optlen != sizeof(int)) {
					error = EINVAL;
					break;
				}
				error = sooptcopyin(sopt, &optval,
					sizeof optval, sizeof optval);
				if (error)
					break;
				switch (optname) {

				case IPV6_UNICAST_HOPS:
					if (optval < -1 || optval >= 256)
						error = EINVAL;
					else {
						/* -1 = kernel default */
						in6p->in6p_hops = optval;
						if ((in6p->inp_vflag &
						     INP_IPV4) != 0)
							in6p->inp_ip_ttl = optval;
					}
					break;
#define OPTSET(bit) \
do { \
	if (optval) \
		in6p->inp_flags |= (bit); \
	else \
		in6p->inp_flags &= ~(bit); \
} while (/*CONSTCOND*/ 0)
#define OPTSET2292(bit) \
do { \
	in6p->inp_flags |= IN6P_RFC2292; \
	if (optval) \
		in6p->inp_flags |= (bit); \
	else \
		in6p->inp_flags &= ~(bit); \
} while (/*CONSTCOND*/ 0)
#define OPTBIT(bit) (in6p->inp_flags & (bit) ? 1 : 0)

				case IPV6_RECVPKTINFO:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_PKTINFO);
					break;

				case IPV6_HOPLIMIT:
				{
					struct ip6_pktopts **optp;

					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					optp = &in6p->in6p_outputopts;
					error = ip6_pcbopt(IPV6_HOPLIMIT,
					    (u_char *)&optval, sizeof(optval),
					    optp, uproto);
					break;
				}

				case IPV6_RECVHOPLIMIT:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_HOPLIMIT);
					break;

				case IPV6_RECVHOPOPTS:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_HOPOPTS);
					break;

				case IPV6_RECVDSTOPTS:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_DSTOPTS);
					break;

				case IPV6_RECVRTHDRDSTOPTS:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_RTHDRDSTOPTS);
					break;

				case IPV6_RECVRTHDR:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_RTHDR);
					break;

				case IPV6_FAITH:
					OPTSET(INP_FAITH);
					break;

				case IPV6_RECVPATHMTU:
					/*
					 * We ignore this option for TCP
					 * sockets.
					 * (RFC3542 leaves this case
					 * unspecified.)
					 */
					if (uproto != IPPROTO_TCP)
						OPTSET(IN6P_MTU);
					break;

				case IPV6_V6ONLY:
					/*
					 * make setsockopt(IPV6_V6ONLY)
					 * available only prior to bind(2).
					 * see ipng mailing list, Jun 22 2001.
					 */
					if (in6p->inp_lport ||
					    !IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_IPV6_V6ONLY);
					if (optval)
						in6p->inp_vflag &= ~INP_IPV4;
					else
						in6p->inp_vflag |= INP_IPV4;
					break;
				case IPV6_RECVTCLASS:
					/* we can mix with RFC2292 */
					OPTSET(IN6P_TCLASS);
					break;
				case IPV6_AUTOFLOWLABEL:
					OPTSET(IN6P_AUTOFLOWLABEL);
					break;

				}
				break;

			case IPV6_TCLASS:
			case IPV6_DONTFRAG:
			case IPV6_USE_MIN_MTU:
			case IPV6_PREFER_TEMPADDR:
				if (optlen != sizeof(optval)) {
					error = EINVAL;
					break;
				}
				error = sooptcopyin(sopt, &optval,
					sizeof optval, sizeof optval);
				if (error)
					break;
				{
					struct ip6_pktopts **optp;
					optp = &in6p->in6p_outputopts;
					error = ip6_pcbopt(optname,
					    (u_char *)&optval, sizeof(optval),
					    optp, uproto);
					break;
				}

			case IPV6_2292PKTINFO:
			case IPV6_2292HOPLIMIT:
			case IPV6_2292HOPOPTS:
			case IPV6_2292DSTOPTS:
			case IPV6_2292RTHDR:
				/* RFC 2292 */
				if (optlen != sizeof(int)) {
					error = EINVAL;
					break;
				}
				error = sooptcopyin(sopt, &optval,
					sizeof optval, sizeof optval);
				if (error)
					break;
				switch (optname) {
				case IPV6_2292PKTINFO:
					OPTSET2292(IN6P_PKTINFO);
					break;
				case IPV6_2292HOPLIMIT:
					OPTSET2292(IN6P_HOPLIMIT);
					break;
				case IPV6_2292HOPOPTS:
					/*
					 * Check super-user privilege.
					 * See comments for IPV6_RECVHOPOPTS.
					 */
					if (!privileged)
						return(EPERM);
					OPTSET2292(IN6P_HOPOPTS);
					break;
				case IPV6_2292DSTOPTS:
					if (!privileged)
						return(EPERM);
					OPTSET2292(IN6P_DSTOPTS|IN6P_RTHDRDSTOPTS); /* XXX */
					break;
				case IPV6_2292RTHDR:
					OPTSET2292(IN6P_RTHDR);
					break;
				}
				break;
			case IPV6_3542PKTINFO:
			case IPV6_3542HOPOPTS:
			case IPV6_3542RTHDR:
			case IPV6_3542DSTOPTS:
			case IPV6_RTHDRDSTOPTS:
			case IPV6_3542NEXTHOP:
			{
				/* new advanced API (RFC3542) */
				struct mbuf *m;

				/* cannot mix with RFC2292 */
				if (OPTBIT(IN6P_RFC2292)) {
					error = EINVAL;
					break;
				}
				error = soopt_getm(sopt, &m);
				if (error != 0)
					break;
				error = soopt_mcopyin(sopt, m);
				if (error) {
					m_freem(m);
					break;
				}
				error = ip6_pcbopt(optname, mtod(m, u_char *), 
					m->m_len, &in6p->in6p_outputopts, uproto);
				m_freem(m);
				break;
			}
#undef OPTSET

			case IPV6_MULTICAST_IF:
			case IPV6_MULTICAST_HOPS:
			case IPV6_MULTICAST_LOOP:
			case IPV6_JOIN_GROUP:
			case IPV6_LEAVE_GROUP:
			case IPV6_MSFILTER:
			case MCAST_BLOCK_SOURCE:
			case MCAST_UNBLOCK_SOURCE:
			case MCAST_JOIN_GROUP:
			case MCAST_LEAVE_GROUP:
			case MCAST_JOIN_SOURCE_GROUP:
			case MCAST_LEAVE_SOURCE_GROUP:
				error = ip6_setmoptions(in6p, sopt);
				break;

			case IPV6_PORTRANGE:
				error = sooptcopyin(sopt, &optval,
				    sizeof optval, sizeof optval);
				if (error)
					break;

				switch (optval) {
				case IPV6_PORTRANGE_DEFAULT:
					in6p->inp_flags &= ~(INP_LOWPORT);
					in6p->inp_flags &= ~(INP_HIGHPORT);
					break;

				case IPV6_PORTRANGE_HIGH:
					in6p->inp_flags &= ~(INP_LOWPORT);
					in6p->inp_flags |= INP_HIGHPORT;
					break;

				case IPV6_PORTRANGE_LOW:
					in6p->inp_flags &= ~(INP_HIGHPORT);
					in6p->inp_flags |= INP_LOWPORT;
					break;

				default:
					error = EINVAL;
					break;
				}
				break;

#if IPSEC
			case IPV6_IPSEC_POLICY:
			    {
				caddr_t req = NULL;
				size_t len = 0;
				struct mbuf *m;

				if ((error = soopt_getm(sopt, &m)) != 0) /* XXX */
					break;
				if ((error = soopt_mcopyin(sopt, m)) != 0) /* XXX */
					break;
				if (m) {
					req = mtod(m, caddr_t);
					len = m->m_len;
				}
				error = ipsec6_set_policy(in6p, optname, req,
				                          len, privileged);
				m_freem(m);
			    }
				break;
#endif /* KAME IPSEC */

#if IPFIREWALL
			case IPV6_FW_ADD:
			case IPV6_FW_DEL:
			case IPV6_FW_FLUSH:
			case IPV6_FW_ZERO:
				{
				if (ip6_fw_ctl_ptr == NULL)
					load_ip6fw();
				if (ip6_fw_ctl_ptr != NULL)
					error = (*ip6_fw_ctl_ptr)(sopt);
				else
					return ENOPROTOOPT;
				}
				break;
#endif /* IPFIREWALL */

			/*
			 * IPv6 variant of IP_BOUND_IF; for details see
			 * comments on IP_BOUND_IF in ip_ctloutput().
			 */
			case IPV6_BOUND_IF:
				/* This option is settable only on IPv6 */
				if (!(in6p->inp_vflag & INP_IPV6)) {
					error = EINVAL;
					break;
				}

				error = sooptcopyin(sopt, &optval,
				    sizeof (optval), sizeof (optval));

				if (error)
					break;

				inp_bindif(in6p, optval);
				break;

			case IPV6_NO_IFT_CELLULAR:
				/* This option is settable only for IPv6 */
				if (!(in6p->inp_vflag & INP_IPV6)) {
					error = EINVAL;
					break;
				}

				error = sooptcopyin(sopt, &optval,
				    sizeof (optval), sizeof (optval));

				if (error)
					break;

				error = inp_nocellular(in6p, optval);
				break;

			case IPV6_OUT_IF:
				/* This option is not settable */
				error = EINVAL;
				break;

			default:
				error = ENOPROTOOPT;
				break;
			}
			break;

		case SOPT_GET:
			switch (optname) {

			case IPV6_2292PKTOPTIONS:
				/*
				 * RFC3542 (effectively) deprecated the
				 * semantics of the 2292-style pktoptions.
				 * Since it was not reliable in nature (i.e.,
				 * applications had to expect the lack of some
				 * information after all), it would make sense
				 * to simplify this part by always returning
				 * empty data.
				 */
				sopt->sopt_valsize = 0;
				break;

			case IPV6_RECVHOPOPTS:
			case IPV6_RECVDSTOPTS:
			case IPV6_RECVRTHDRDSTOPTS:
			case IPV6_UNICAST_HOPS:
			case IPV6_RECVPKTINFO:
			case IPV6_RECVHOPLIMIT:
			case IPV6_RECVRTHDR:
			case IPV6_RECVPATHMTU:

			case IPV6_FAITH:
			case IPV6_V6ONLY:
			case IPV6_PORTRANGE:
			case IPV6_RECVTCLASS:
			case IPV6_AUTOFLOWLABEL:
				switch (optname) {

				case IPV6_RECVHOPOPTS:
					optval = OPTBIT(IN6P_HOPOPTS);
					break;

				case IPV6_RECVDSTOPTS:
					optval = OPTBIT(IN6P_DSTOPTS);
					break;

				case IPV6_RECVRTHDRDSTOPTS:
					optval = OPTBIT(IN6P_RTHDRDSTOPTS);
					break;

				case IPV6_UNICAST_HOPS:
					optval = in6p->in6p_hops;
					break;

				case IPV6_RECVPKTINFO:
					optval = OPTBIT(IN6P_PKTINFO);
					break;

				case IPV6_RECVHOPLIMIT:
					optval = OPTBIT(IN6P_HOPLIMIT);
					break;

				case IPV6_RECVRTHDR:
					optval = OPTBIT(IN6P_RTHDR);
					break;

				case IPV6_RECVPATHMTU:
					optval = OPTBIT(IN6P_MTU);
					break;

				case IPV6_FAITH:
					optval = OPTBIT(INP_FAITH);
					break;

				case IPV6_V6ONLY:
					optval = OPTBIT(IN6P_IPV6_V6ONLY);
					break;

				case IPV6_PORTRANGE:
				    {
					int flags;
					flags = in6p->inp_flags;
					if (flags & INP_HIGHPORT)
						optval = IPV6_PORTRANGE_HIGH;
					else if (flags & INP_LOWPORT)
						optval = IPV6_PORTRANGE_LOW;
					else
						optval = 0;
					break;
				    }
				case IPV6_RECVTCLASS:
					optval = OPTBIT(IN6P_TCLASS);
					break;

				case IPV6_AUTOFLOWLABEL:
					optval = OPTBIT(IN6P_AUTOFLOWLABEL);
					break;
				}
				if (error)
					break;
				error = sooptcopyout(sopt, &optval,
					sizeof optval);
				break;

			case IPV6_PATHMTU:
			{
				u_int32_t pmtu = 0;
				struct ip6_mtuinfo mtuinfo;
				struct route_in6 sro;

				bzero(&sro, sizeof(sro));

				if (!(so->so_state & SS_ISCONNECTED))
					return (ENOTCONN);
				/*
				 * XXX: we dot not consider the case of source
				 * routing, or optional information to specify
				 * the outgoing interface.
				 */
				error = ip6_getpmtu(&sro, NULL, NULL,
				    &in6p->in6p_faddr, &pmtu, NULL);
				if (sro.ro_rt)
					rtfree(sro.ro_rt);
				if (error)
					break;
				if (pmtu > IPV6_MAXPACKET)
					pmtu = IPV6_MAXPACKET;

				bzero(&mtuinfo, sizeof(mtuinfo));
				mtuinfo.ip6m_mtu = (u_int32_t)pmtu;
				optdata = (void *)&mtuinfo;
				optdatalen = sizeof(mtuinfo);
				error = sooptcopyout(sopt, optdata,
				    optdatalen);
				break;
			}

			case IPV6_2292PKTINFO:
			case IPV6_2292HOPLIMIT:
			case IPV6_2292HOPOPTS:
			case IPV6_2292RTHDR:
			case IPV6_2292DSTOPTS:
				switch (optname) {
				case IPV6_2292PKTINFO:
					optval = OPTBIT(IN6P_PKTINFO);
					break;
				case IPV6_2292HOPLIMIT:
					optval = OPTBIT(IN6P_HOPLIMIT);
					break;
				case IPV6_2292HOPOPTS:
					optval = OPTBIT(IN6P_HOPOPTS);
					break;
				case IPV6_2292RTHDR:
					optval = OPTBIT(IN6P_RTHDR);
					break;
				case IPV6_2292DSTOPTS:
					optval = OPTBIT(IN6P_DSTOPTS|IN6P_RTHDRDSTOPTS);
					break;
				}
				error = sooptcopyout(sopt, &optval,
				    sizeof optval);
				break;
			case IPV6_PKTINFO:
			case IPV6_HOPOPTS:
			case IPV6_RTHDR:
			case IPV6_DSTOPTS:
			case IPV6_RTHDRDSTOPTS:
			case IPV6_NEXTHOP:
			case IPV6_TCLASS:
			case IPV6_DONTFRAG:
			case IPV6_USE_MIN_MTU:
			case IPV6_PREFER_TEMPADDR:
				error = ip6_getpcbopt(in6p->in6p_outputopts,
				    optname, sopt);
				break;

			case IPV6_MULTICAST_IF:
			case IPV6_MULTICAST_HOPS:
			case IPV6_MULTICAST_LOOP:
			case IPV6_MSFILTER:
				error = ip6_getmoptions(in6p, sopt);
				break;

#if IPSEC
			case IPV6_IPSEC_POLICY:
			  {
				caddr_t req = NULL;
				size_t len = 0;
				struct mbuf *m = NULL;
				struct mbuf **mp = &m;

				error = soopt_getm(sopt, &m); /* XXX */
				if (error != 0)
					break;
				error = soopt_mcopyin(sopt, m); /* XXX */
				if (error != 0)
					break;
				if (m) {
					req = mtod(m, caddr_t);
					len = m->m_len;
				}
				error = ipsec6_get_policy(in6p, req, len, mp);
				if (error == 0)
					error = soopt_mcopyout(sopt, m); /*XXX*/
				if (error == 0 && m)
					m_freem(m);
				break;
			  }
#endif /* KAME IPSEC */

#if IPFIREWALL
			case IPV6_FW_GET:
				{
				if (ip6_fw_ctl_ptr == NULL)
					load_ip6fw();
				if (ip6_fw_ctl_ptr != NULL)
					error = (*ip6_fw_ctl_ptr)(sopt);
				else
					return ENOPROTOOPT;
				}
				break;
#endif /* IPFIREWALL */

			case IPV6_BOUND_IF:
				if (in6p->inp_flags & INP_BOUND_IF)
					optval = in6p->inp_boundif;
				error = sooptcopyout(sopt, &optval,
				    sizeof (optval));
				break;

			case IPV6_NO_IFT_CELLULAR:
				optval = (in6p->inp_flags & INP_NO_IFT_CELLULAR)
				    ? 1 : 0;
				error = sooptcopyout(sopt, &optval,
				    sizeof (optval));
				break;

			case IPV6_OUT_IF:
				optval = in6p->in6p_last_outif;
				error = sooptcopyout(sopt, &optval,
				    sizeof (optval));
				break;

			default:
				error = ENOPROTOOPT;
				break;
			}
			break;
		}
	} else {
		error = EINVAL;
	}
	return(error);
}

int
ip6_raw_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int error = 0, optval, optlen;
	const int icmp6off = offsetof(struct icmp6_hdr, icmp6_cksum);
	struct inpcb *in6p = sotoinpcb(so);
	int level, op, optname;

	level = sopt->sopt_level;
	op = sopt->sopt_dir;
	optname = sopt->sopt_name;
	optlen = sopt->sopt_valsize;

	if (level != IPPROTO_IPV6) {
		return (EINVAL);
	}

	switch (optname) {
	case IPV6_CHECKSUM:
		/*
		 * For ICMPv6 sockets, no modification allowed for checksum
		 * offset, permit "no change" values to help existing apps.
		 *
		 * RFC3542 says: "An attempt to set IPV6_CHECKSUM
		 * for an ICMPv6 socket will fail."
		 * The current behavior does not meet RFC3542.
		 */
		switch (op) {
		case SOPT_SET:
			if (optlen != sizeof(int)) {
				error = EINVAL;
				break;
			}
			error = sooptcopyin(sopt, &optval, sizeof(optval),
					    sizeof(optval));
			if (error)
				break;
			if ((optval % 2) != 0) {
				/* the API assumes even offset values */
				error = EINVAL;
			} else if (so->so_proto->pr_protocol ==
			    IPPROTO_ICMPV6) {
				if (optval != icmp6off)
					error = EINVAL;
			} else
				in6p->in6p_cksum = optval;
			break;

		case SOPT_GET:
			if (so->so_proto->pr_protocol == IPPROTO_ICMPV6)
				optval = icmp6off;
			else
				optval = in6p->in6p_cksum;

			error = sooptcopyout(sopt, &optval, sizeof(optval));
			break;

		default:
			error = EINVAL;
			break;
		}
		break;

	default:
		error = ENOPROTOOPT;
		break;
	}

	return (error);
}

/*
 * Set up IP6 options in pcb for insertion in output packets or
 * specifying behavior of outgoing packets.
 */
static int
ip6_pcbopts(
	struct ip6_pktopts **pktopt,
	struct mbuf *m,
	__unused struct socket *so,
	__unused struct sockopt *sopt)
{
	struct ip6_pktopts *opt = *pktopt;
	int error = 0;

	/* turn off any old options. */
	if (opt) {
#if DIAGNOSTIC
		if (opt->ip6po_pktinfo || opt->ip6po_nexthop ||
		    opt->ip6po_hbh || opt->ip6po_dest1 || opt->ip6po_dest2 ||
		    opt->ip6po_rhinfo.ip6po_rhi_rthdr)
			printf("ip6_pcbopts: all specified options are cleared.\n");
#endif
		ip6_clearpktopts(opt, -1);
	} else {
		opt = _MALLOC(sizeof(*opt), M_IP6OPT, M_WAITOK);
		if (opt == NULL)
			return ENOBUFS;
	}
	*pktopt = NULL;

	if (!m || m->m_len == 0) {
		/*
		 * Only turning off any previous options, regardless of
		 * whether the opt is just created or given.
		 */
		if (opt)
			FREE(opt, M_IP6OPT);
		return(0);
	}

	/*  set options specified by user. */
	if ((error = ip6_setpktopts(m, opt, NULL, so->so_proto->pr_protocol)) != 0) {
		ip6_clearpktopts(opt, -1); /* XXX: discard all options */
		FREE(opt, M_IP6OPT);
		return(error);
	}
	*pktopt = opt;
	return(0);
}

/*
 * initialize ip6_pktopts.  beware that there are non-zero default values in
 * the struct.
 */
void
ip6_initpktopts(struct ip6_pktopts *opt)
{

	bzero(opt, sizeof(*opt));
	opt->ip6po_hlim = -1;	/* -1 means default hop limit */
	opt->ip6po_tclass = -1;	/* -1 means default traffic class */
	opt->ip6po_minmtu = IP6PO_MINMTU_MCASTONLY;
	opt->ip6po_prefer_tempaddr = IP6PO_TEMPADDR_SYSTEM;
}

static int
ip6_pcbopt(int optname, u_char *buf, int len, struct ip6_pktopts **pktopt, int uproto)
{
	struct ip6_pktopts *opt;

	opt = *pktopt;
	if (opt == NULL) {
		opt = _MALLOC(sizeof(*opt), M_IP6OPT, M_WAITOK);
		if (opt == NULL)
			return(ENOBUFS);
		ip6_initpktopts(opt);
		*pktopt = opt;
	}

	return (ip6_setpktopt(optname, buf, len, opt, 1, 0, uproto));
}

static int
ip6_getpcbopt(struct ip6_pktopts *pktopt, int optname, struct sockopt *sopt)
{
	void *optdata = NULL;
	int optdatalen = 0;
	struct ip6_ext *ip6e;
	int error = 0;
	struct in6_pktinfo null_pktinfo;
	int deftclass = 0, on;
	int defminmtu = IP6PO_MINMTU_MCASTONLY;
	int defpreftemp = IP6PO_TEMPADDR_SYSTEM;

	switch (optname) {
	case IPV6_PKTINFO:
		if (pktopt && pktopt->ip6po_pktinfo)
			optdata = (void *)pktopt->ip6po_pktinfo;
		else {
			/* XXX: we don't have to do this every time... */
			bzero(&null_pktinfo, sizeof(null_pktinfo));
			optdata = (void *)&null_pktinfo;
		}
		optdatalen = sizeof(struct in6_pktinfo);
		break;
	case IPV6_TCLASS:
		if (pktopt && pktopt->ip6po_tclass >= 0)
			optdata = (void *)&pktopt->ip6po_tclass;
		else
			optdata = (void *)&deftclass;
		optdatalen = sizeof(int);
		break;
	case IPV6_HOPOPTS:
		if (pktopt && pktopt->ip6po_hbh) {
			optdata = (void *)pktopt->ip6po_hbh;
			ip6e = (struct ip6_ext *)pktopt->ip6po_hbh;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_RTHDR:
		if (pktopt && pktopt->ip6po_rthdr) {
			optdata = (void *)pktopt->ip6po_rthdr;
			ip6e = (struct ip6_ext *)pktopt->ip6po_rthdr;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_RTHDRDSTOPTS:
		if (pktopt && pktopt->ip6po_dest1) {
			optdata = (void *)pktopt->ip6po_dest1;
			ip6e = (struct ip6_ext *)pktopt->ip6po_dest1;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_DSTOPTS:
		if (pktopt && pktopt->ip6po_dest2) {
			optdata = (void *)pktopt->ip6po_dest2;
			ip6e = (struct ip6_ext *)pktopt->ip6po_dest2;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;
	case IPV6_NEXTHOP:
		if (pktopt && pktopt->ip6po_nexthop) {
			optdata = (void *)pktopt->ip6po_nexthop;
			optdatalen = pktopt->ip6po_nexthop->sa_len;
		}
		break;
	case IPV6_USE_MIN_MTU:
		if (pktopt)
			optdata = (void *)&pktopt->ip6po_minmtu;
		else
			optdata = (void *)&defminmtu;
		optdatalen = sizeof(int);
		break;
	case IPV6_DONTFRAG:
		if (pktopt && ((pktopt->ip6po_flags) & IP6PO_DONTFRAG))
			on = 1;
		else
			on = 0;
		optdata = (void *)&on;
		optdatalen = sizeof(on);
		break;
	case IPV6_PREFER_TEMPADDR:
		if (pktopt)
			optdata = (void *)&pktopt->ip6po_prefer_tempaddr;
		else
			optdata = (void *)&defpreftemp;
		optdatalen = sizeof(int);
		break;
	default:		/* should not happen */
#ifdef DIAGNOSTIC
		panic("ip6_getpcbopt: unexpected option\n");
#endif
		return (ENOPROTOOPT);
	}

	error = sooptcopyout(sopt, optdata, optdatalen);

	return (error);
}

void
ip6_clearpktopts(pktopt, optname)
	struct ip6_pktopts *pktopt;
	int optname;
{
	if (pktopt == NULL)
		return;

	if (optname == -1 || optname == IPV6_PKTINFO) {
		if (pktopt->ip6po_pktinfo)
			FREE(pktopt->ip6po_pktinfo, M_IP6OPT);
		pktopt->ip6po_pktinfo = NULL;
	}
	if (optname == -1 || optname == IPV6_HOPLIMIT)
		pktopt->ip6po_hlim = -1;
	if (optname == -1 || optname == IPV6_TCLASS)
		pktopt->ip6po_tclass = -1;
	if (optname == -1 || optname == IPV6_NEXTHOP) {
		if (pktopt->ip6po_nextroute.ro_rt) {
			rtfree(pktopt->ip6po_nextroute.ro_rt);
			pktopt->ip6po_nextroute.ro_rt = NULL;
		}
		if (pktopt->ip6po_nexthop)
			FREE(pktopt->ip6po_nexthop, M_IP6OPT);
		pktopt->ip6po_nexthop = NULL;
	}
	if (optname == -1 || optname == IPV6_HOPOPTS) {
		if (pktopt->ip6po_hbh)
			FREE(pktopt->ip6po_hbh, M_IP6OPT);
		pktopt->ip6po_hbh = NULL;
	}
	if (optname == -1 || optname == IPV6_RTHDRDSTOPTS) {
		if (pktopt->ip6po_dest1)
			FREE(pktopt->ip6po_dest1, M_IP6OPT);
		pktopt->ip6po_dest1 = NULL;
	}
	if (optname == -1 || optname == IPV6_RTHDR) {
		if (pktopt->ip6po_rhinfo.ip6po_rhi_rthdr)
			FREE(pktopt->ip6po_rhinfo.ip6po_rhi_rthdr, M_IP6OPT);
		pktopt->ip6po_rhinfo.ip6po_rhi_rthdr = NULL;
		if (pktopt->ip6po_route.ro_rt) {
			rtfree(pktopt->ip6po_route.ro_rt);
			pktopt->ip6po_route.ro_rt = NULL;
		}
	}
	if (optname == -1 || optname == IPV6_DSTOPTS) {
		if (pktopt->ip6po_dest2)
			FREE(pktopt->ip6po_dest2, M_IP6OPT);
		pktopt->ip6po_dest2 = NULL;
	}
}

#define PKTOPT_EXTHDRCPY(type) \
do {\
	if (src->type) {\
		int hlen =\
			(((struct ip6_ext *)src->type)->ip6e_len + 1) << 3;\
		dst->type = _MALLOC(hlen, M_IP6OPT, canwait);\
		if (dst->type == NULL && canwait == M_NOWAIT)\
			goto bad;\
		bcopy(src->type, dst->type, hlen);\
	}\
} while (0)

static int
copypktopts(struct ip6_pktopts *dst, struct ip6_pktopts *src, int canwait)
{
	if (dst == NULL || src == NULL)  {
		printf("ip6_clearpktopts: invalid argument\n");
		return (EINVAL);
	}

	dst->ip6po_hlim = src->ip6po_hlim;
	dst->ip6po_tclass = src->ip6po_tclass;
	dst->ip6po_flags = src->ip6po_flags;
	if (src->ip6po_pktinfo) {
		dst->ip6po_pktinfo = _MALLOC(sizeof(*dst->ip6po_pktinfo),
					    M_IP6OPT, canwait);
		if (dst->ip6po_pktinfo == NULL && canwait == M_NOWAIT)
			goto bad;
		*dst->ip6po_pktinfo = *src->ip6po_pktinfo;
	}
	if (src->ip6po_nexthop) {
		dst->ip6po_nexthop = _MALLOC(src->ip6po_nexthop->sa_len,
					    M_IP6OPT, canwait);
		if (dst->ip6po_nexthop == NULL && canwait == M_NOWAIT)
			goto bad;
		bcopy(src->ip6po_nexthop, dst->ip6po_nexthop,
		      src->ip6po_nexthop->sa_len);
	}
	PKTOPT_EXTHDRCPY(ip6po_hbh);
	PKTOPT_EXTHDRCPY(ip6po_dest1);
	PKTOPT_EXTHDRCPY(ip6po_dest2);
	PKTOPT_EXTHDRCPY(ip6po_rthdr); /* not copy the cached route */
	return (0);

  bad:
	ip6_clearpktopts(dst, -1);
	return (ENOBUFS);
}
#undef PKTOPT_EXTHDRCPY

struct ip6_pktopts *
ip6_copypktopts(struct ip6_pktopts *src, int canwait)
{
	int error;
	struct ip6_pktopts *dst;

	dst = _MALLOC(sizeof(*dst), M_IP6OPT, canwait);
	if (dst == NULL)
		return (NULL);
	ip6_initpktopts(dst);

	if ((error = copypktopts(dst, src, canwait)) != 0) {
		FREE(dst, M_IP6OPT);
		return (NULL);
	}

	return (dst);
}

void
ip6_freepcbopts(pktopt)
	struct ip6_pktopts *pktopt;
{
	if (pktopt == NULL)
		return;

	ip6_clearpktopts(pktopt, -1);

	FREE(pktopt, M_IP6OPT);
}

void
ip6_moptions_init(void)
{
	PE_parse_boot_argn("ifa_debug", &im6o_debug, sizeof (im6o_debug));

	im6o_size = (im6o_debug == 0) ? sizeof (struct ip6_moptions) :
	    sizeof (struct ip6_moptions_dbg);

	im6o_zone = zinit(im6o_size, IM6O_ZONE_MAX * im6o_size, 0,
	    IM6O_ZONE_NAME);
	if (im6o_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IM6O_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(im6o_zone, Z_EXPAND, TRUE);
}

void
im6o_addref(struct ip6_moptions *im6o, int locked)
{
	if (!locked)
		IM6O_LOCK(im6o);
	else
		IM6O_LOCK_ASSERT_HELD(im6o);

	if (++im6o->im6o_refcnt == 0) {
		panic("%s: im6o %p wraparound refcnt\n", __func__, im6o);
		/* NOTREACHED */
	} else if (im6o->im6o_trace != NULL) {
		(*im6o->im6o_trace)(im6o, TRUE);
	}

	if (!locked)
		IM6O_UNLOCK(im6o);
}

void
im6o_remref(struct ip6_moptions *im6o)
{
	int i;

	IM6O_LOCK(im6o);
	if (im6o->im6o_refcnt == 0) {
		panic("%s: im6o %p negative refcnt", __func__, im6o);
		/* NOTREACHED */
	} else if (im6o->im6o_trace != NULL) {
		(*im6o->im6o_trace)(im6o, FALSE);
	}

	--im6o->im6o_refcnt;
	if (im6o->im6o_refcnt > 0) {
		IM6O_UNLOCK(im6o);
		return;
	}

	for (i = 0; i < im6o->im6o_num_memberships; ++i) {
		struct in6_mfilter *imf;

		imf = im6o->im6o_mfilters ? &im6o->im6o_mfilters[i] : NULL;
		if (imf != NULL)
			im6f_leave(imf);

		(void) in6_mc_leave(im6o->im6o_membership[i], imf);

		if (imf != NULL)
			im6f_purge(imf);

		IN6M_REMREF(im6o->im6o_membership[i]);
		im6o->im6o_membership[i] = NULL;
	}
	im6o->im6o_num_memberships = 0;
	if (im6o->im6o_mfilters != NULL) {
		FREE(im6o->im6o_mfilters, M_IN6MFILTER);
		im6o->im6o_mfilters = NULL;
	}
	if (im6o->im6o_membership != NULL) {
		FREE(im6o->im6o_membership, M_IP6MOPTS);
		im6o->im6o_membership = NULL;
	}
	IM6O_UNLOCK(im6o);

	lck_mtx_destroy(&im6o->im6o_lock, ifa_mtx_grp);

	if (!(im6o->im6o_debug & IFD_ALLOC)) {
		panic("%s: im6o %p cannot be freed", __func__, im6o);
		/* NOTREACHED */
	}
	zfree(im6o_zone, im6o);
}

static void
im6o_trace(struct ip6_moptions *im6o, int refhold)
{
	struct ip6_moptions_dbg *im6o_dbg = (struct ip6_moptions_dbg *)im6o;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(im6o->im6o_debug & IFD_DEBUG)) {
		panic("%s: im6o %p has no debug structure", __func__, im6o);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &im6o_dbg->im6o_refhold_cnt;
		tr = im6o_dbg->im6o_refhold;
	} else {
		cnt = &im6o_dbg->im6o_refrele_cnt;
		tr = im6o_dbg->im6o_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % IM6O_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

struct ip6_moptions *
ip6_allocmoptions(int how)
{
	struct ip6_moptions *im6o;

	im6o = (how == M_WAITOK) ?
	    zalloc(im6o_zone) : zalloc_noblock(im6o_zone);
	if (im6o != NULL) {
		bzero(im6o, im6o_size);
		lck_mtx_init(&im6o->im6o_lock, ifa_mtx_grp, ifa_mtx_attr);
		im6o->im6o_debug |= IFD_ALLOC;
		if (im6o_debug != 0) {
			im6o->im6o_debug |= IFD_DEBUG;
			im6o->im6o_trace = im6o_trace;
		}
		IM6O_ADDREF(im6o);
	}

	return (im6o);
}

/*
 * Set IPv6 outgoing packet options based on advanced API.
 */
int
ip6_setpktopts(struct mbuf *control, struct ip6_pktopts *opt,
    struct ip6_pktopts *stickyopt, int uproto)
{
	struct cmsghdr *cm = 0;

	if (control == NULL || opt == NULL)
		return (EINVAL);

	ip6_initpktopts(opt);
	if (stickyopt) {
		int error;

		/*
		 * If stickyopt is provided, make a local copy of the options
		 * for this particular packet, then override them by ancillary
		 * objects.
		 * XXX: copypktopts() does not copy the cached route to a next
		 * hop (if any).  This is not very good in terms of efficiency,
		 * but we can allow this since this option should be rarely
		 * used.
		 */
		if ((error = copypktopts(opt, stickyopt, M_NOWAIT)) != 0)
			return (error);
	}

	/*
	 * XXX: Currently, we assume all the optional information is stored
	 * in a single mbuf.
	 */
	if (control->m_next)
		return (EINVAL);

	if (control->m_len < CMSG_LEN(0))
		return (EINVAL);

	for (cm = M_FIRST_CMSGHDR(control); cm; cm = M_NXT_CMSGHDR(control, cm)) {
		int error;

		if (cm->cmsg_len < sizeof(struct cmsghdr) || cm->cmsg_len > control->m_len)
			return (EINVAL);
		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;

		error = ip6_setpktopt(cm->cmsg_type, CMSG_DATA(cm),
		    cm->cmsg_len - CMSG_LEN(0), opt, 0, 1, uproto);
		if (error)
			return (error);
	}

	return (0);
}
/*
 * Set a particular packet option, as a sticky option or an ancillary data
 * item.  "len" can be 0 only when it's a sticky option.
 * We have 4 cases of combination of "sticky" and "cmsg":
 * "sticky=0, cmsg=0": impossible
 * "sticky=0, cmsg=1": RFC2292 or RFC3542 ancillary data
 * "sticky=1, cmsg=0": RFC3542 socket option
 * "sticky=1, cmsg=1": RFC2292 socket option
 */
static int
ip6_setpktopt(int optname, u_char *buf, int len, struct ip6_pktopts *opt,
    int sticky, int cmsg, int uproto)
{
	int minmtupolicy, preftemp;
	int error;

	if (!sticky && !cmsg) {
#ifdef DIAGNOSTIC
		printf("ip6_setpktopt: impossible case\n");
#endif
		return (EINVAL);
	}

	/*
	 * IPV6_2292xxx is for backward compatibility to RFC2292, and should
	 * not be specified in the context of RFC3542.  Conversely,
	 * RFC3542 types should not be specified in the context of RFC2292.
	 */
	if (!cmsg) {
		switch (optname) {
		case IPV6_2292PKTINFO:
		case IPV6_2292HOPLIMIT:
		case IPV6_2292NEXTHOP:
		case IPV6_2292HOPOPTS:
		case IPV6_2292DSTOPTS:
		case IPV6_2292RTHDR:
		case IPV6_2292PKTOPTIONS:
			return (ENOPROTOOPT);
		}
	}
	if (sticky && cmsg) {
		switch (optname) {
		case IPV6_PKTINFO:
		case IPV6_HOPLIMIT:
		case IPV6_NEXTHOP:
		case IPV6_HOPOPTS:
		case IPV6_DSTOPTS:
		case IPV6_RTHDRDSTOPTS:
		case IPV6_RTHDR:
		case IPV6_USE_MIN_MTU:
		case IPV6_DONTFRAG:
		case IPV6_TCLASS:
		case IPV6_PREFER_TEMPADDR: /* XXX: not an RFC3542 option */
			return (ENOPROTOOPT);
		}
	}

	switch (optname) {
	case IPV6_2292PKTINFO:
	case IPV6_PKTINFO:
	{
		struct ifnet *ifp = NULL;
		struct in6_pktinfo *pktinfo;

		if (len != sizeof(struct in6_pktinfo))
			return (EINVAL);

		pktinfo = (struct in6_pktinfo *)buf;

		/*
		 * An application can clear any sticky IPV6_PKTINFO option by
		 * doing a "regular" setsockopt with ipi6_addr being
		 * in6addr_any and ipi6_ifindex being zero.
		 * [RFC 3542, Section 6]
		 */
		if (optname == IPV6_PKTINFO && opt->ip6po_pktinfo &&
		    pktinfo->ipi6_ifindex == 0 &&
		    IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
			ip6_clearpktopts(opt, optname);
			break;
		}

		if (uproto == IPPROTO_TCP && optname == IPV6_PKTINFO &&
		    sticky && !IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
			return (EINVAL);
		}

		/* validate the interface index if specified. */
		ifnet_head_lock_shared();

		if (pktinfo->ipi6_ifindex > if_index) {
			ifnet_head_done();
			return (ENXIO);
		}
		
		if (pktinfo->ipi6_ifindex) {
			ifp = ifindex2ifnet[pktinfo->ipi6_ifindex];
			if (ifp == NULL) {
				ifnet_head_done();
				return (ENXIO);
			}
		}
		
		ifnet_head_done();

		/*
		 * We store the address anyway, and let in6_selectsrc()
		 * validate the specified address.  This is because ipi6_addr
		 * may not have enough information about its scope zone, and
		 * we may need additional information (such as outgoing
		 * interface or the scope zone of a destination address) to
		 * disambiguate the scope.
		 * XXX: the delay of the validation may confuse the
		 * application when it is used as a sticky option.
		 */
		if (opt->ip6po_pktinfo == NULL) {
			opt->ip6po_pktinfo = _MALLOC(sizeof(*pktinfo),
			    M_IP6OPT, M_NOWAIT);
			if (opt->ip6po_pktinfo == NULL)
				return (ENOBUFS);
		}
		bcopy(pktinfo, opt->ip6po_pktinfo, sizeof(*pktinfo));
		break;
	}

	case IPV6_2292HOPLIMIT:
	case IPV6_HOPLIMIT:
	{
		int *hlimp;

		/*
		 * RFC 3542 deprecated the usage of sticky IPV6_HOPLIMIT
		 * to simplify the ordering among hoplimit options.
		 */
		if (optname == IPV6_HOPLIMIT && sticky)
			return (ENOPROTOOPT);

		if (len != sizeof(int))
			return (EINVAL);
		hlimp = (int *)buf;
		if (*hlimp < -1 || *hlimp > 255)
			return (EINVAL);

		opt->ip6po_hlim = *hlimp;
		break;
	}

	case IPV6_TCLASS:
	{
		int tclass;

		if (len != sizeof(int))
			return (EINVAL);
		tclass = *(int *)buf;
		if (tclass < -1 || tclass > 255)
			return (EINVAL);

		opt->ip6po_tclass = tclass;
		break;
	}

	case IPV6_2292NEXTHOP:
	case IPV6_NEXTHOP:
		error = suser(kauth_cred_get(), 0);
		if (error)
			return (EACCES);

		if (len == 0) {	/* just remove the option */
			ip6_clearpktopts(opt, IPV6_NEXTHOP);
			break;
		}

		/* check if cmsg_len is large enough for sa_len */
		if (len < sizeof(struct sockaddr) || len < *buf)
			return (EINVAL);

		switch (((struct sockaddr *)buf)->sa_family) {
		case AF_INET6:
		{
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)buf;

			if (sa6->sin6_len != sizeof(struct sockaddr_in6))
				return (EINVAL);

			if (IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr) ||
			    IN6_IS_ADDR_MULTICAST(&sa6->sin6_addr)) {
				return (EINVAL);
			}
			if ((error = sa6_embedscope(sa6, ip6_use_defzone))
			    != 0) {
				return (error);
			}
			break;
		}
		case AF_LINK:	/* should eventually be supported */
		default:
			return (EAFNOSUPPORT);
		}

		/* turn off the previous option, then set the new option. */
		ip6_clearpktopts(opt, IPV6_NEXTHOP);
		opt->ip6po_nexthop = _MALLOC(*buf, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_nexthop == NULL)
			return (ENOBUFS);
		bcopy(buf, opt->ip6po_nexthop, *buf);
		break;

	case IPV6_2292HOPOPTS:
	case IPV6_HOPOPTS:
	{
		struct ip6_hbh *hbh;
		int hbhlen;

		/*
		 * XXX: We don't allow a non-privileged user to set ANY HbH
		 * options, since per-option restriction has too much
		 * overhead.
		 */
		error = suser(kauth_cred_get(), 0);
		if (error)
			return (EACCES);

		if (len == 0) {
			ip6_clearpktopts(opt, IPV6_HOPOPTS);
			break;	/* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_hbh))
			return (EINVAL);
		hbh = (struct ip6_hbh *)buf;
		hbhlen = (hbh->ip6h_len + 1) << 3;
		if (len != hbhlen)
			return (EINVAL);

		/* turn off the previous option, then set the new option. */
		ip6_clearpktopts(opt, IPV6_HOPOPTS);
		opt->ip6po_hbh = _MALLOC(hbhlen, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_hbh == NULL)
			return (ENOBUFS);
		bcopy(hbh, opt->ip6po_hbh, hbhlen);

		break;
	}

	case IPV6_2292DSTOPTS:
	case IPV6_DSTOPTS:
	case IPV6_RTHDRDSTOPTS:
	{
		struct ip6_dest *dest, **newdest = NULL;
		int destlen;

		error = suser(kauth_cred_get(), 0);
		if (error)
			return (EACCES);

		if (len == 0) {
			ip6_clearpktopts(opt, optname);
			break;	/* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_dest))
			return (EINVAL);
		dest = (struct ip6_dest *)buf;
		destlen = (dest->ip6d_len + 1) << 3;
		if (len != destlen)
			return (EINVAL);

		/*
		 * Determine the position that the destination options header
		 * should be inserted; before or after the routing header.
		 */
		switch (optname) {
		case IPV6_2292DSTOPTS:
			/*
			 * The old advacned API is ambiguous on this point.
			 * Our approach is to determine the position based
			 * according to the existence of a routing header.
			 * Note, however, that this depends on the order of the
			 * extension headers in the ancillary data; the 1st
			 * part of the destination options header must appear
			 * before the routing header in the ancillary data,
			 * too.
			 * RFC3542 solved the ambiguity by introducing
			 * separate ancillary data or option types.
			 */
			if (opt->ip6po_rthdr == NULL)
				newdest = &opt->ip6po_dest1;
			else
				newdest = &opt->ip6po_dest2;
			break;
		case IPV6_RTHDRDSTOPTS:
			newdest = &opt->ip6po_dest1;
			break;
		case IPV6_DSTOPTS:
			newdest = &opt->ip6po_dest2;
			break;
		}

		/* turn off the previous option, then set the new option. */
		ip6_clearpktopts(opt, optname);
		*newdest = _MALLOC(destlen, M_IP6OPT, M_NOWAIT);
		if (*newdest == NULL)
			return (ENOBUFS);
		bcopy(dest, *newdest, destlen);

		break;
	}

	case IPV6_2292RTHDR:
	case IPV6_RTHDR:
	{
		struct ip6_rthdr *rth;
		int rthlen;

		if (len == 0) {
			ip6_clearpktopts(opt, IPV6_RTHDR);
			break;	/* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_rthdr))
			return (EINVAL);
		rth = (struct ip6_rthdr *)buf;
		rthlen = (rth->ip6r_len + 1) << 3;
		if (len != rthlen)
			return (EINVAL);

		switch (rth->ip6r_type) {
		case IPV6_RTHDR_TYPE_0:
			if (rth->ip6r_len == 0)	/* must contain one addr */
				return (EINVAL);
			if (rth->ip6r_len % 2) /* length must be even */
				return (EINVAL);
			if (rth->ip6r_len / 2 != rth->ip6r_segleft)
				return (EINVAL);
			break;
		default:
			return (EINVAL);	/* not supported */
		}

		/* turn off the previous option */
		ip6_clearpktopts(opt, IPV6_RTHDR);
		opt->ip6po_rthdr = _MALLOC(rthlen, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_rthdr == NULL)
			return (ENOBUFS);
		bcopy(rth, opt->ip6po_rthdr, rthlen);

		break;
	}

	case IPV6_USE_MIN_MTU:
		if (len != sizeof(int))
			return (EINVAL);
		minmtupolicy = *(int *)buf;
		if (minmtupolicy != IP6PO_MINMTU_MCASTONLY &&
		    minmtupolicy != IP6PO_MINMTU_DISABLE &&
		    minmtupolicy != IP6PO_MINMTU_ALL) {
			return (EINVAL);
		}
		opt->ip6po_minmtu = minmtupolicy;
		break;

	case IPV6_DONTFRAG:
		if (len != sizeof(int))
			return (EINVAL);

		if (uproto == IPPROTO_TCP || *(int *)buf == 0) {
			/*
			 * we ignore this option for TCP sockets.
			 * (RFC3542 leaves this case unspecified.)
			 */
			opt->ip6po_flags &= ~IP6PO_DONTFRAG;
		} else
			opt->ip6po_flags |= IP6PO_DONTFRAG;
		break;

	case IPV6_PREFER_TEMPADDR:
		if (len != sizeof(int))
			return (EINVAL);
		preftemp = *(int *)buf;
		if (preftemp != IP6PO_TEMPADDR_SYSTEM &&
		    preftemp != IP6PO_TEMPADDR_NOTPREFER &&
		    preftemp != IP6PO_TEMPADDR_PREFER) {
			return (EINVAL);
		}
		opt->ip6po_prefer_tempaddr = preftemp;
		break;

	default:
		return (ENOPROTOOPT);
	} /* end of switch */

	return (0);
}

/*
 * Routine called from ip6_output() to loop back a copy of an IP6 multicast
 * packet to the input queue of a specified interface.  Note that this
 * calls the output routine of the loopback "driver", but with an interface
 * pointer that might NOT be &loif -- easier than replicating that code here.
 */
void
ip6_mloopback(
	struct ifnet *ifp,
	struct mbuf *m,
	struct sockaddr_in6 *dst)
{
	struct mbuf *copym;
	struct ip6_hdr *ip6;

	copym = m_copy(m, 0, M_COPYALL);
	if (copym == NULL)
		return;

	/*
	 * Make sure to deep-copy IPv6 header portion in case the data
	 * is in an mbuf cluster, so that we can safely override the IPv6
	 * header portion later.
	 */
	if ((copym->m_flags & M_EXT) != 0 ||
	    copym->m_len < sizeof(struct ip6_hdr)) {
		copym = m_pullup(copym, sizeof(struct ip6_hdr));
		if (copym == NULL)
			return;
	}

#if DIAGNOSTIC
	if (copym->m_len < sizeof(*ip6)) {
		m_freem(copym);
		return;
	}
#endif

	ip6 = mtod(copym, struct ip6_hdr *);
	/*
	 * clear embedded scope identifiers if necessary.
	 * in6_clearscope will touch the addresses only when necessary.
	 */
	in6_clearscope(&ip6->ip6_src);
	in6_clearscope(&ip6->ip6_dst);

#ifdef __APPLE__

	/* Makes sure the HW checksum flags are cleaned before sending the packet */

	if ((copym->m_pkthdr.csum_flags & CSUM_DELAY_IPV6_DATA) != 0) {
		in6_delayed_cksum(copym, sizeof(struct ip6_hdr));
		copym->m_pkthdr.csum_flags &= ~CSUM_DELAY_IPV6_DATA;
	}
	copym->m_pkthdr.rcvif = 0;
	copym->m_pkthdr.csum_data = 0;
	copym->m_pkthdr.csum_flags = 0;

	if (lo_ifp) {
		copym->m_pkthdr.rcvif = ifp;
		dlil_output(lo_ifp, PF_INET6, copym, 0, (struct sockaddr *)dst, 0);
	} else
		m_free(copym);
#else
	(void)if_simloop(ifp, copym, dst->sin6_family, NULL);
#endif
}

/*
 * Chop IPv6 header off from the payload.
 */
static int
ip6_splithdr(m, exthdrs)
	struct mbuf *m;
	struct ip6_exthdrs *exthdrs;
{
	struct mbuf *mh;
	struct ip6_hdr *ip6;

	ip6 = mtod(m, struct ip6_hdr *);
	if (m->m_len > sizeof(*ip6)) {
		MGETHDR(mh, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
		if (mh == 0) {
			m_freem(m);
			return ENOBUFS;
		}
		M_COPY_PKTHDR(mh, m);
		MH_ALIGN(mh, sizeof(*ip6));
		m->m_flags &= ~M_PKTHDR;
		m->m_len -= sizeof(*ip6);
		m->m_data += sizeof(*ip6);
		mh->m_next = m;
		m = mh;
		m->m_len = sizeof(*ip6);
		bcopy((caddr_t)ip6, mtod(m, caddr_t), sizeof(*ip6));
	}
	exthdrs->ip6e_ip6 = m;
	return 0;
}

/*
 * Compute IPv6 extension header length.
 */
int
ip6_optlen(in6p)
	struct in6pcb *in6p;
{
	int len;

	if (!in6p->in6p_outputopts)
		return 0;

	len = 0;
#define elen(x) \
	(((struct ip6_ext *)(x)) ? (((struct ip6_ext *)(x))->ip6e_len + 1) << 3 : 0)

	len += elen(in6p->in6p_outputopts->ip6po_hbh);
	if (in6p->in6p_outputopts->ip6po_rthdr)
		/* dest1 is valid with rthdr only */
		len += elen(in6p->in6p_outputopts->ip6po_dest1);
	len += elen(in6p->in6p_outputopts->ip6po_rthdr);
	len += elen(in6p->in6p_outputopts->ip6po_dest2);
	return len;
#undef elen
}
