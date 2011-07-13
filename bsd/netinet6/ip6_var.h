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

/*	$FreeBSD: src/sys/netinet6/ip6_var.h,v 1.2.2.2 2001/07/03 11:01:54 ume Exp $	*/
/*	$KAME: ip6_var.h,v 1.62 2001/05/03 14:51:48 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)ip_var.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET6_IP6_VAR_H_
#define _NETINET6_IP6_VAR_H_
#include <sys/appleapiopts.h>

#ifdef XNU_KERNEL_PRIVATE
/*
 * IP6 reassembly queue structure.  Each fragment
 * being reassembled is attached to one of these structures.
 */
struct	ip6q {
	struct ip6asfrag *ip6q_down;
	struct ip6asfrag *ip6q_up;
	u_int32_t	ip6q_ident;
	u_int8_t	ip6q_nxt;
	u_int8_t	ip6q_ecn;
	u_int8_t	ip6q_ttl;
	struct in6_addr ip6q_src, ip6q_dst;
	struct ip6q	*ip6q_next;
	struct ip6q	*ip6q_prev;
	int		ip6q_unfrglen;	/* len of unfragmentable part */
#if notyet
	u_char	*ip6q_nxtp;
#endif
	int		ip6q_nfrag;	/* # of fragments */
};

struct	ip6asfrag {
	struct ip6asfrag *ip6af_down;
	struct ip6asfrag *ip6af_up;
	struct mbuf	*ip6af_m;
	int		ip6af_offset;	/* offset in ip6af_m to next header */
	int		ip6af_frglen;	/* fragmentable part length */
	int		ip6af_off;	/* fragment offset */
	u_int16_t	ip6af_mff;	/* more fragment bit in frag off */
};

#define IP6_REASS_MBUF(ip6af) (*(struct mbuf **)&((ip6af)->ip6af_m))

struct	ip6_moptions {
	decl_lck_mtx_data(, im6o_lock);
	uint32_t im6o_refcnt;		/* ref count */
	uint32_t im6o_debug;		/* see ifa_debug flags */
	struct	ifnet *im6o_multicast_ifp; /* ifp for outgoing multicasts */
	u_char	im6o_multicast_hlim;	/* hoplimit for outgoing multicasts */
	u_char	im6o_multicast_loop;	/* 1 >= hear sends if a member */
	u_short	im6o_num_memberships;	/* no. memberships this socket */
	u_short	im6o_max_memberships;	/* max memberships this socket */
	struct	in6_multi **im6o_membership;	/* group memberships */
	struct	in6_mfilter *im6o_mfilters;	/* source filters */
	void (*im6o_trace)		/* callback fn for tracing refs */
	    (struct ip6_moptions *, int);
};

#define	IM6O_LOCK_ASSERT_HELD(_im6o)					\
	lck_mtx_assert(&(_im6o)->im6o_lock, LCK_MTX_ASSERT_OWNED)

#define	IM6O_LOCK_ASSERT_NOTHELD(_im6o)					\
	lck_mtx_assert(&(_im6o)->im6o_lock, LCK_MTX_ASSERT_NOTOWNED)

#define	IM6O_LOCK(_im6o)						\
	lck_mtx_lock(&(_im6o)->im6o_lock)

#define	IM6O_LOCK_SPIN(_im6o)						\
	lck_mtx_lock_spin(&(_im6o)->im6o_lock)

#define	IM6O_CONVERT_LOCK(_im6o) do {					\
	IM6O_LOCK_ASSERT_HELD(_im6o);					\
	lck_mtx_convert_spin(&(_im6o)->im6o_lock);			\
} while (0)

#define	IM6O_UNLOCK(_im6o)						\
	lck_mtx_unlock(&(_im6o)->im6o_lock)

#define	IM6O_ADDREF(_im6o)						\
	im6o_addref(_im6o, 0)

#define	IM6O_ADDREF_LOCKED(_im6o)					\
	im6o_addref(_im6o, 1)

#define	IM6O_REMREF(_im6o)						\
	im6o_remref(_im6o)

/*
 * Control options for outgoing packets
 */

/* Routing header related info */
struct	ip6po_rhinfo {
	struct	ip6_rthdr *ip6po_rhi_rthdr; /* Routing header */
	struct	route_in6 ip6po_rhi_route; /* Route to the 1st hop */
};
#define ip6po_rthdr	ip6po_rhinfo.ip6po_rhi_rthdr
#define ip6po_route	ip6po_rhinfo.ip6po_rhi_route

/* Nexthop related info */
struct	ip6po_nhinfo {
	struct	sockaddr *ip6po_nhi_nexthop;
	struct	route_in6 ip6po_nhi_route; /* Route to the nexthop */
};
#define ip6po_nexthop	ip6po_nhinfo.ip6po_nhi_nexthop
#define ip6po_nextroute	ip6po_nhinfo.ip6po_nhi_route

struct	ip6_pktopts {
	struct	mbuf *ip6po_m;	/* Pointer to mbuf storing the data */
	int	ip6po_hlim;	/* Hoplimit for outgoing packets */

	/* Outgoing IF/address information */
	struct	in6_pktinfo *ip6po_pktinfo;

	/* Next-hop address information */
	struct	ip6po_nhinfo ip6po_nhinfo;

	struct	ip6_hbh *ip6po_hbh; /* Hop-by-Hop options header */

	/* Destination options header (before a routing header) */
	struct	ip6_dest *ip6po_dest1;

	/* Routing header related info. */
	struct	ip6po_rhinfo ip6po_rhinfo;

	/* Destination options header (after a routing header) */
	struct	ip6_dest *ip6po_dest2;

	int	ip6po_tclass;	/* traffic class */

	int	ip6po_minmtu;  /* fragment vs PMTU discovery policy */
#define IP6PO_MINMTU_MCASTONLY	-1 /* default; send at min MTU for multicast*/
#define IP6PO_MINMTU_DISABLE	 0 /* always perform pmtu disc */
#define IP6PO_MINMTU_ALL	 1 /* always send at min MTU */

	int	ip6po_prefer_tempaddr;  /* whether temporary addresses are
					   preferred as source address */
#define IP6PO_TEMPADDR_SYSTEM	-1 /* follow the system default */
#define IP6PO_TEMPADDR_NOTPREFER 0 /* not prefer temporary address */
#define IP6PO_TEMPADDR_PREFER	 1 /* prefer temporary address */

	int ip6po_flags;
#if 0	/* parameters in this block is obsolete. do not reuse the values. */
#define IP6PO_REACHCONF	0x01	/* upper-layer reachability confirmation. */
#define IP6PO_MINMTU	0x02	/* use minimum MTU (IPV6_USE_MIN_MTU) */
#endif
#define IP6PO_DONTFRAG	0x04	/* disable fragmentation (IPV6_DONTFRAG) */
#define IP6PO_USECOA	0x08	/* use care of address */
};

/*
 * Control options for incoming packets
 */
#endif /* XNU_KERNEL_PRIVATE */

struct	ip6stat {
	u_quad_t ip6s_total;		/* total packets received */
	u_quad_t ip6s_tooshort;		/* packet too short */
	u_quad_t ip6s_toosmall;		/* not enough data */
	u_quad_t ip6s_fragments;	/* fragments received */
	u_quad_t ip6s_fragdropped;	/* frags dropped(dups, out of space) */
	u_quad_t ip6s_fragtimeout;	/* fragments timed out */
	u_quad_t ip6s_fragoverflow;	/* fragments that exceeded limit */
	u_quad_t ip6s_forward;		/* packets forwarded */
	u_quad_t ip6s_cantforward;	/* packets rcvd for unreachable dest */
	u_quad_t ip6s_redirectsent;	/* packets forwarded on same net */
	u_quad_t ip6s_delivered;	/* datagrams delivered to upper level*/
	u_quad_t ip6s_localout;		/* total ip packets generated here */
	u_quad_t ip6s_odropped;		/* lost packets due to nobufs, etc. */
	u_quad_t ip6s_reassembled;	/* total packets reassembled ok */
	u_quad_t ip6s_fragmented;	/* datagrams successfully fragmented */
	u_quad_t ip6s_ofragments;	/* output fragments created */
	u_quad_t ip6s_cantfrag;		/* don't fragment flag was set, etc. */
	u_quad_t ip6s_badoptions;	/* error in option processing */
	u_quad_t ip6s_noroute;		/* packets discarded due to no route */
	u_quad_t ip6s_badvers;		/* ip6 version != 6 */
	u_quad_t ip6s_rawout;		/* total raw ip packets generated */
	u_quad_t ip6s_badscope;		/* scope error */
	u_quad_t ip6s_notmember;	/* don't join this multicast group */
	u_quad_t ip6s_nxthist[256];	/* next header history */
	u_quad_t ip6s_m1;		/* one mbuf */
	u_quad_t ip6s_m2m[32];		/* two or more mbuf */
	u_quad_t ip6s_mext1;		/* one ext mbuf */
	u_quad_t ip6s_mext2m;		/* two or more ext mbuf */
	u_quad_t ip6s_exthdrtoolong;	/* ext hdr are not continuous */
	u_quad_t ip6s_nogif;		/* no match gif found */
	u_quad_t ip6s_toomanyhdr;	/* discarded due to too many headers */

	/*
	 * statistics for improvement of the source address selection
	 * algorithm:
	 * XXX: hardcoded 16 = # of ip6 multicast scope types + 1
	 */
	/* number of times that address selection fails */
	u_quad_t ip6s_sources_none;
	/* number of times that an address on the outgoing I/F is chosen */
	u_quad_t ip6s_sources_sameif[16];
	/* number of times that an address on a non-outgoing I/F is chosen */
	u_quad_t ip6s_sources_otherif[16];
	/*
	 * number of times that an address that has the same scope
	 * from the destination is chosen.
	 */
	u_quad_t ip6s_sources_samescope[16];
	/*
	 * number of times that an address that has a different scope
	 * from the destination is chosen.
	 */
	u_quad_t ip6s_sources_otherscope[16];
	/* number of times that a deprecated address is chosen */
	u_quad_t ip6s_sources_deprecated[16];

	u_quad_t ip6s_forward_cachehit;
	u_quad_t ip6s_forward_cachemiss;

	/* number of times that each rule of source selection is applied. */
	u_quad_t ip6s_sources_rule[16];
#ifdef PRIVATE
	u_quad_t ip6s_pktdropcntrl;	/* pkt dropped, no mbufs for control data */
#endif /* PRIVATE */
};

#ifdef KERNEL_PRIVATE
#ifdef KERNEL
/*
 * IPv6 onion peeling state.
 * it will be initialized when we come into ip6_input().
 * XXX do not make it a kitchen sink!
 */
struct ip6aux {
	u_int32_t ip6a_flags;
#define IP6A_SWAP	0x01		/* swapped home/care-of on packet */
#define IP6A_HASEEN	0x02		/* HA was present */
#define IP6A_BRUID	0x04		/* BR Unique Identifier was present */
#define IP6A_RTALERTSEEN 0x08		/* rtalert present */

	/* ip6.ip6_src */
	struct in6_addr ip6a_careof;	/* care-of address of the peer */
	struct in6_addr ip6a_home;	/* home address of the peer */
	u_int16_t	ip6a_bruid;	/* BR unique identifier */

	/* ip6.ip6_dst */
	struct in6_ifaddr *ip6a_dstia6;	/* my ifaddr that matches ip6_dst */

	/* rtalert */
	u_int16_t ip6a_rtalert;		/* rtalert option value */

	/*
	 * decapsulation history will be here.
	 * with IPsec it may not be accurate.
	 */
};

/* flags passed to ip6_output as last parameter */
#define	IPV6_UNSPECSRC		0x01	/* allow :: as the source address */
#define	IPV6_FORWARDING		0x02	/* most of IPv6 header exists */
#define	IPV6_MINMTU		0x04	/* use minimum MTU (IPV6_USE_MIN_MTU) */
#define	IPV6_FLAG_NOSRCIFSEL	0x80	/* bypas source address selection */
#define	IPV6_OUTARGS		0x100	/* has ancillary output info */

#ifdef __NO_STRICT_ALIGNMENT
#define IP6_HDR_ALIGNED_P(ip)	1
#else
#define IP6_HDR_ALIGNED_P(ip)	((((intptr_t) (ip)) & 3) == 0)
#endif

/*
 * Extra information passed to ip6_output when IP6_OUTARGS is set.
 */
struct ip6_out_args {
	unsigned int	ip6oa_boundif;	/* bound outgoing interface */
	unsigned int	ip6oa_nocell;	/* don't use IFT_CELLULAR */
};

extern struct	ip6stat ip6stat;	/* statistics */
extern u_int32_t ip6_id; 		/* fragment identifier */
extern int	ip6_defhlim;		/* default hop limit */
extern int	ip6_defmcasthlim;	/* default multicast hop limit */
extern int	ip6_forwarding;		/* act as router? */
extern int	ip6_forward_srcrt;	/* forward src-routed? */
extern int	ip6_gif_hlim;		/* Hop limit for gif encap packet */
extern int	ip6_use_deprecated;	/* allow deprecated addr as source */
extern int	ip6_rr_prune;		/* router renumbering prefix
					 * walk list every 5 sec.    */
extern int	ip6_mcast_pmtu;		/* enable pMTU discovery for multicast? */
#define ip6_mapped_addr_on      (!ip6_v6only)
extern int	ip6_v6only;

extern int	ip6_neighborgcthresh;	/* Threshold # of NDP entries for GC */
extern int	ip6_maxifprefixes;	/* Max acceptable prefixes via RA per IF */
extern int	ip6_maxifdefrouters;	/* Max acceptable def routers via RA */
extern int	ip6_maxdynroutes;	/* Max # of routes created via redirect */
#if MROUTING
extern struct socket *ip6_mrouter; 	/* multicast routing daemon */
#endif
extern int	ip6_sendredirects;	/* send IP redirects when forwarding? */
extern int	ip6_maxfragpackets; /* Maximum packets in reassembly queue */
extern int	ip6_maxfrags;	/* Maximum fragments in reassembly queue */
extern int	ip6_sourcecheck;	/* Verify source interface */
extern int	ip6_sourcecheck_interval; /* Interval between log messages */
extern int	ip6_accept_rtadv;	/* Acts as a host not a router */
extern int	ip6_keepfaith;		/* Firewall Aided Internet Translator */
extern int	ip6_log_interval;
extern time_t	ip6_log_time;
extern int	ip6_hdrnestlimit; /* upper limit of # of extension headers */
extern int	ip6_dad_count;		/* DupAddrDetectionTransmits */
extern int	ip6_only_allow_rfc4193_prefix;	/* RFC4193 Unique Local Unicast Prefixes only */

extern u_int32_t ip6_flow_seq;
extern int ip6_auto_flowlabel;
extern int ip6_auto_linklocal;

extern int   ip6_anonportmin;		/* minimum ephemeral port */
extern int   ip6_anonportmax;		/* maximum ephemeral port */
extern int   ip6_lowportmin;		/* minimum reserved port */
extern int   ip6_lowportmax;		/* maximum reserved port */

extern int	ip6_use_tempaddr; /* whether to use temporary addresses. */
extern int	ip6_prefer_tempaddr; /* whether to prefer temporary addresses
					in the source address selection */
extern int	ip6_use_defzone; /* whether to use the default scope zone
				    when unspecified */

extern struct	pr_usrreqs rip6_usrreqs;
extern struct   pr_usrreqs icmp6_dgram_usrreqs;

extern int	ip6_doscopedroute;

struct sockopt;

struct inpcb;

int	icmp6_ctloutput(struct socket *, struct sockopt *);
int	icmp6_dgram_ctloutput(struct socket *, struct sockopt *);
int 	icmp6_dgram_send(struct socket *, int , struct mbuf *, struct sockaddr *, struct mbuf *, struct proc *);
int 	icmp6_dgram_attach(struct socket *, int , struct proc *);


struct in6_ifaddr;
void	ip6_init(void);
void ip6_fin(void);
void	ip6_input(struct mbuf *);
struct in6_ifaddr *ip6_getdstifaddr(struct mbuf *);
void	ip6_freepcbopts(struct ip6_pktopts *);
int	ip6_unknown_opt(u_int8_t *, struct mbuf *, int);
char *	ip6_get_prevhdr(struct mbuf *, int);
int	ip6_nexthdr(struct mbuf *, int, int, int *);
int	ip6_lasthdr(struct mbuf *, int, int, int *);

extern void ip6_moptions_init(void);
extern struct ip6_moptions *ip6_allocmoptions(int);
extern void im6o_addref(struct ip6_moptions *, int);
extern void im6o_remref(struct ip6_moptions *);

struct ip6aux *ip6_addaux(struct mbuf *);
struct ip6aux *ip6_findaux(struct mbuf *);
void	ip6_delaux(struct mbuf *);
extern void ip6_destroyaux(struct ip6aux *);
extern void ip6_copyaux(struct ip6aux *, struct ip6aux *);

int	ip6_mforward(struct ip6_hdr *, struct ifnet *, struct mbuf *);
int	ip6_process_hopopts(struct mbuf *, u_int8_t *, int, u_int32_t *,
				 u_int32_t *);
struct mbuf	**ip6_savecontrol_v4(struct inpcb *, struct mbuf *,
	    struct mbuf **, int *);
int	ip6_savecontrol(struct inpcb *, struct mbuf *, struct mbuf **);
void	ip6_forward(struct mbuf *, struct route_in6 *, int);
void	ip6_notify_pmtu __P((struct inpcb *, struct sockaddr_in6 *,
			     u_int32_t *));
void	ip6_mloopback(struct ifnet *, struct mbuf *, struct sockaddr_in6 *);
int	ip6_output(struct mbuf *, struct ip6_pktopts *, struct route_in6 *,
	    int, struct ip6_moptions *, struct ifnet **,
	    struct ip6_out_args *);
int	ip6_ctloutput(struct socket *, struct sockopt *sopt);
void	ip6_initpktopts(struct ip6_pktopts *);
int	ip6_setpktoptions(struct mbuf *, struct ip6_pktopts *, int, int);
void	ip6_clearpktopts(struct ip6_pktopts *, int);
struct ip6_pktopts *ip6_copypktopts(struct ip6_pktopts *, int);
int	ip6_optlen(struct inpcb *);

int	route6_input(struct mbuf **, int *, int);

void	frag6_init(void);
int	frag6_input(struct mbuf **, int *, int);
void	frag6_slowtimo(void);
void	frag6_drain(void);

int	rip6_input(struct mbuf **, int *, int);
void	rip6_ctlinput(int, struct sockaddr *, void *);
int	rip6_ctloutput(struct socket *so, struct sockopt *sopt);
int	rip6_output(struct mbuf *, struct socket *, struct sockaddr_in6 *, struct mbuf *, int);

int	dest6_input(struct mbuf **, int *, int);
extern struct in6_addr *in6_selectsrc(struct sockaddr_in6 *,
	    struct ip6_pktopts *, struct inpcb *, struct route_in6 *,
	    struct ifnet **, struct in6_addr *, unsigned int, int *);
extern struct in6_addrpolicy *
	in6_addrsel_lookup_policy(struct sockaddr_in6 *);
int in6_selectroute(struct sockaddr_in6 *, struct sockaddr_in6 *,
	struct ip6_pktopts *, struct ip6_moptions *, struct route_in6 *,
	struct ifnet **, struct rtentry **, int, unsigned int, unsigned int);
int ip6_setpktopts(struct mbuf *control, struct ip6_pktopts *opt, struct ip6_pktopts *stickyopt, int uproto);
u_int32_t ip6_randomid(void);
u_int32_t ip6_randomflowlabel(void);

#endif /* KERNEL */
#endif /* KERNEL_PRIVATE */

#endif /* !_NETINET6_IP6_VAR_H_ */
