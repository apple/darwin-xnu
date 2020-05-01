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
#include <libkern/OSByteOrder.h>

#include <pexpert/pexpert.h>
#include <mach/sdt.h>

#include <net/if.h>
#include <net/route.h>
#include <net/dlil.h>
#include <net/net_api_stats.h>
#include <net/net_osdep.h>
#include <net/net_perf.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet/kpi_ipfilter_var.h>
#include <netinet/in_tclass.h>

#include <netinet6/ip6protosw.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_var.h>
#include <netinet/in_pcb.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>
#if IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/ipsec6.h>
#include <netkey/key.h>
extern int ipsec_bypass;
#endif /* IPSEC */

#if NECP
#include <net/necp.h>
#endif /* NECP */

#if CONFIG_MACF_NET
#include <security/mac.h>
#endif /* CONFIG_MACF_NET */

#if DUMMYNET
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#endif /* DUMMYNET */

#if PF
#include <net/pfvar.h>
#endif /* PF */

static int sysctl_reset_ip6_output_stats SYSCTL_HANDLER_ARGS;
static int sysctl_ip6_output_measure_bins SYSCTL_HANDLER_ARGS;
static int sysctl_ip6_output_getperf SYSCTL_HANDLER_ARGS;
static int ip6_copyexthdr(struct mbuf **, caddr_t, int);
static void ip6_out_cksum_stats(int, u_int32_t);
static int ip6_insert_jumboopt(struct ip6_exthdrs *, u_int32_t);
static int ip6_insertfraghdr(struct mbuf *, struct mbuf *, int,
    struct ip6_frag **);
static int ip6_getpmtu(struct route_in6 *, struct route_in6 *,
    struct ifnet *, struct in6_addr *, u_int32_t *);
static int ip6_pcbopts(struct ip6_pktopts **, struct mbuf *, struct socket *,
    struct sockopt *sopt);
static int ip6_pcbopt(int, u_char *, int, struct ip6_pktopts **, int);
static int ip6_getpcbopt(struct ip6_pktopts *, int, struct sockopt *);
static int copypktopts(struct ip6_pktopts *, struct ip6_pktopts *, int);
static void im6o_trace(struct ip6_moptions *, int);
static int ip6_setpktopt(int, u_char *, int, struct ip6_pktopts *, int,
    int, int);
static int ip6_splithdr(struct mbuf *, struct ip6_exthdrs *);
static void ip6_output_checksum(struct ifnet *, uint32_t, struct mbuf *,
    int, uint32_t, uint32_t);
extern int udp_ctloutput(struct socket *, struct sockopt *);
static int ip6_fragment_packet(struct mbuf **m,
    struct ip6_pktopts *opt, struct ip6_exthdrs *exthdrsp, struct ifnet *ifp,
    uint32_t mtu, uint32_t unfragpartlen,
    struct route_in6 *ro_pmtu, int nxt0, uint32_t optlen);

SYSCTL_DECL(_net_inet6_ip6);

static int ip6_output_measure = 0;
SYSCTL_PROC(_net_inet6_ip6, OID_AUTO, output_perf,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip6_output_measure, 0, sysctl_reset_ip6_output_stats, "I", "Do time measurement");

static uint64_t ip6_output_measure_bins = 0;
SYSCTL_PROC(_net_inet6_ip6, OID_AUTO, output_perf_bins,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_output_measure_bins, 0,
    sysctl_ip6_output_measure_bins, "I",
    "bins for chaining performance data histogram");

static net_perf_t net_perf;
SYSCTL_PROC(_net_inet6_ip6, OID_AUTO, output_perf_data,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, sysctl_ip6_output_getperf, "S,net_perf",
    "IP6 output performance data (struct net_perf, net/net_perf.h)");

#define IM6O_TRACE_HIST_SIZE    32      /* size of trace history */

/* For gdb */
__private_extern__ unsigned int im6o_trace_hist_size = IM6O_TRACE_HIST_SIZE;

struct ip6_moptions_dbg {
	struct ip6_moptions     im6o;                   /* ip6_moptions */
	u_int16_t               im6o_refhold_cnt;       /* # of IM6O_ADDREF */
	u_int16_t               im6o_refrele_cnt;       /* # of IM6O_REMREF */
	/*
	 * Alloc and free callers.
	 */
	ctrace_t                im6o_alloc;
	ctrace_t                im6o_free;
	/*
	 * Circular lists of IM6O_ADDREF and IM6O_REMREF callers.
	 */
	ctrace_t                im6o_refhold[IM6O_TRACE_HIST_SIZE];
	ctrace_t                im6o_refrele[IM6O_TRACE_HIST_SIZE];
};

#if DEBUG
static unsigned int im6o_debug = 1;     /* debugging (enabled) */
#else
static unsigned int im6o_debug;         /* debugging (disabled) */
#endif /* !DEBUG */

static unsigned int im6o_size;          /* size of zone element */
static struct zone *im6o_zone;          /* zone for ip6_moptions */

#define IM6O_ZONE_MAX           64              /* maximum elements in zone */
#define IM6O_ZONE_NAME          "ip6_moptions"  /* zone name */

/*
 * ip6_output() calls ip6_output_list() to do the work
 */
int
ip6_output(struct mbuf *m0, struct ip6_pktopts *opt,
    struct route_in6 *ro, int flags, struct ip6_moptions *im6o,
    struct ifnet **ifpp, struct ip6_out_args *ip6oa)
{
	return ip6_output_list(m0, 0, opt, ro, flags, im6o, ifpp, ip6oa);
}

/*
 * IP6 output. Each packet in mbuf chain m contains a skeletal IP6
 * header (with pri, len, nxt, hlim, src, dst).
 * This function may modify ver and hlim only.
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 *
 * If ro is non-NULL and has valid ro->ro_rt, route lookup would be
 * skipped and ro->ro_rt would be used.  Otherwise the result of route
 * lookup is stored in ro->ro_rt.
 *
 * type of "mtu": rt_rmx.rmx_mtu is u_int32_t, ifnet.ifr_mtu is int, and
 * nd_ifinfo.linkmtu is u_int32_t.  so we use u_int32_t to hold largest one,
 * which is rt_rmx.rmx_mtu.
 */
int
ip6_output_list(struct mbuf *m0, int packetchain, struct ip6_pktopts *opt,
    struct route_in6 *ro, int flags, struct ip6_moptions *im6o,
    struct ifnet **ifpp, struct ip6_out_args *ip6oa)
{
	struct ip6_hdr *ip6;
	u_char *nexthdrp;
	struct ifnet *ifp = NULL, *origifp = NULL;      /* refcnt'd */
	struct ifnet **ifpp_save = ifpp;
	struct mbuf *m, *mprev;
	struct mbuf *sendchain = NULL, *sendchain_last = NULL;
	struct mbuf *inputchain = NULL;
	int nxt0 = 0;
	struct route_in6 *ro_pmtu = NULL;
	struct rtentry *rt = NULL;
	struct sockaddr_in6 *dst = NULL, src_sa, dst_sa;
	int error = 0;
	struct in6_ifaddr *ia = NULL, *src_ia = NULL;
	u_int32_t mtu = 0;
	u_int32_t optlen = 0, plen = 0, unfragpartlen = 0;
	struct ip6_rthdr *rh;
	struct in6_addr finaldst;
	ipfilter_t inject_filter_ref;
	struct ipf_pktopts *ippo = NULL;
	struct flowadv *adv = NULL;
	uint32_t pktcnt = 0;
	uint32_t packets_processed = 0;
	struct timeval start_tv;
#if PF
	boolean_t skip_pf = (ip6oa != NULL) &&
	    (ip6oa->ip6oa_flags & IP6OAF_SKIP_PF);
#endif

#if DUMMYNET
	struct m_tag *tag;
	struct ip6_out_args saved_ip6oa;
	struct sockaddr_in6 dst_buf;
#endif /* DUMMYNET */
#if IPSEC
	struct socket *so = NULL;
	struct secpolicy *sp = NULL;
	struct route_in6 *ipsec_saved_route = NULL;
	boolean_t needipsectun = FALSE;
#endif /* IPSEC */
#if NECP
	necp_kernel_policy_result necp_result = 0;
	necp_kernel_policy_result_parameter necp_result_parameter;
	necp_kernel_policy_id necp_matched_policy_id = 0;
#endif /* NECP */
	struct {
		struct ipf_pktopts ipf_pktopts;
		struct ip6_exthdrs exthdrs;
		struct route_in6 ip6route;
#if IPSEC
		struct ipsec_output_state ipsec_state;
#endif /* IPSEC */
#if NECP
		struct route_in6 necp_route;
#endif /* NECP */
#if DUMMYNET
		struct route_in6 saved_route;
		struct route_in6 saved_ro_pmtu;
		struct ip_fw_args args;
#endif /* DUMMYNET */
	} ip6obz;
#define ipf_pktopts     ip6obz.ipf_pktopts
#define exthdrs         ip6obz.exthdrs
#define ip6route        ip6obz.ip6route
#define ipsec_state     ip6obz.ipsec_state
#define necp_route      ip6obz.necp_route
#define saved_route     ip6obz.saved_route
#define saved_ro_pmtu   ip6obz.saved_ro_pmtu
#define args            ip6obz.args
	union {
		struct {
			boolean_t select_srcif : 1;
			boolean_t hdrsplit : 1;
			boolean_t route_selected : 1;
			boolean_t dontfrag : 1;
#if IPSEC
			boolean_t needipsec : 1;
			boolean_t noipsec : 1;
#endif /* IPSEC */
		};
		uint32_t raw;
	} ip6obf = { .raw = 0 };

	if (ip6_output_measure) {
		net_perf_start_time(&net_perf, &start_tv);
	}

	VERIFY(m0->m_flags & M_PKTHDR);

	/* zero out {saved_route, saved_ro_pmtu, ip6route, exthdrs, args} */
	bzero(&ip6obz, sizeof(ip6obz));

#if DUMMYNET
	if (SLIST_EMPTY(&m0->m_pkthdr.tags)) {
		goto tags_done;
	}

	/* Grab info from mtags prepended to the chain */
	if ((tag = m_tag_locate(m0, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_DUMMYNET, NULL)) != NULL) {
		struct dn_pkt_tag       *dn_tag;

		/*
		 * ip6_output_list() cannot handle chains of packets reinjected
		 * by dummynet. The same restriction applies to
		 * ip_output_list().
		 */
		VERIFY(0 == packetchain);

		dn_tag = (struct dn_pkt_tag *)(tag + 1);
		args.fwa_pf_rule = dn_tag->dn_pf_rule;

		bcopy(&dn_tag->dn_dst6, &dst_buf, sizeof(dst_buf));
		dst = &dst_buf;
		ifp = dn_tag->dn_ifp;
		if (ifp != NULL) {
			ifnet_reference(ifp);
		}
		flags = dn_tag->dn_flags;
		if (dn_tag->dn_flags & IPV6_OUTARGS) {
			saved_ip6oa = dn_tag->dn_ip6oa;
			ip6oa = &saved_ip6oa;
		}

		saved_route = dn_tag->dn_ro6;
		ro = &saved_route;
		saved_ro_pmtu = dn_tag->dn_ro6_pmtu;
		ro_pmtu = &saved_ro_pmtu;
		origifp = dn_tag->dn_origifp;
		if (origifp != NULL) {
			ifnet_reference(origifp);
		}
		mtu = dn_tag->dn_mtu;
		unfragpartlen = dn_tag->dn_unfragpartlen;

		bcopy(&dn_tag->dn_exthdrs, &exthdrs, sizeof(exthdrs));

		m_tag_delete(m0, tag);
	}

tags_done:
#endif /* DUMMYNET */

	m = m0;

#if IPSEC
	if (ipsec_bypass == 0) {
		so = ipsec_getsocket(m);
		if (so != NULL) {
			(void) ipsec_setsocket(m, NULL);
		}
		/* If packet is bound to an interface, check bound policies */
		if ((flags & IPV6_OUTARGS) &&
		    (ip6oa->ip6oa_flags & IP6OAF_BOUND_IF) &&
		    ip6oa->ip6oa_boundif != IFSCOPE_NONE) {
			/* ip6obf.noipsec is a bitfield, use temp integer */
			int noipsec = 0;

			if (ipsec6_getpolicybyinterface(m, IPSEC_DIR_OUTBOUND,
			    flags, ip6oa, &noipsec, &sp) != 0) {
				goto bad;
			}

			ip6obf.noipsec = (noipsec != 0);
		}
	}
#endif /* IPSEC */

	ippo = &ipf_pktopts;

	if (flags & IPV6_OUTARGS) {
		/*
		 * In the forwarding case, only the ifscope value is used,
		 * as source interface selection doesn't take place.
		 */
		if ((ip6obf.select_srcif = (!(flags & (IPV6_FORWARDING |
		    IPV6_UNSPECSRC | IPV6_FLAG_NOSRCIFSEL)) &&
		    (ip6oa->ip6oa_flags & IP6OAF_SELECT_SRCIF)))) {
			ipf_pktopts.ippo_flags |= IPPOF_SELECT_SRCIF;
		}

		if ((ip6oa->ip6oa_flags & IP6OAF_BOUND_IF) &&
		    ip6oa->ip6oa_boundif != IFSCOPE_NONE) {
			ipf_pktopts.ippo_flags |= (IPPOF_BOUND_IF |
			    (ip6oa->ip6oa_boundif << IPPOF_SHIFT_IFSCOPE));
		}

		if (ip6oa->ip6oa_flags & IP6OAF_BOUND_SRCADDR) {
			ipf_pktopts.ippo_flags |= IPPOF_BOUND_SRCADDR;
		}
	} else {
		ip6obf.select_srcif = FALSE;
		if (flags & IPV6_OUTARGS) {
			ip6oa->ip6oa_boundif = IFSCOPE_NONE;
			ip6oa->ip6oa_flags &= ~(IP6OAF_SELECT_SRCIF |
			    IP6OAF_BOUND_IF | IP6OAF_BOUND_SRCADDR);
		}
	}

	if (flags & IPV6_OUTARGS) {
		if (ip6oa->ip6oa_flags & IP6OAF_NO_CELLULAR) {
			ipf_pktopts.ippo_flags |= IPPOF_NO_IFT_CELLULAR;
		}
		if (ip6oa->ip6oa_flags & IP6OAF_NO_EXPENSIVE) {
			ipf_pktopts.ippo_flags |= IPPOF_NO_IFF_EXPENSIVE;
		}
		if (ip6oa->ip6oa_flags & IP6OAF_NO_CONSTRAINED) {
			ipf_pktopts.ippo_flags |= IPPOF_NO_IFF_CONSTRAINED;
		}
		adv = &ip6oa->ip6oa_flowadv;
		adv->code = FADV_SUCCESS;
		ip6oa->ip6oa_retflags = 0;
	}

	/*
	 * Clear out ifpp to be filled in after determining route. ifpp_save is
	 * used to keep old value to release reference properly and dtrace
	 * ipsec tunnel traffic properly.
	 */
	if (ifpp != NULL && *ifpp != NULL) {
		*ifpp = NULL;
	}

#if DUMMYNET
	if (args.fwa_pf_rule) {
		ip6 = mtod(m, struct ip6_hdr *);
		VERIFY(ro != NULL);     /* ro == saved_route */
		goto check_with_pf;
	}
#endif /* DUMMYNET */

#if NECP
	/*
	 * Since all packets are assumed to come from same socket, necp lookup
	 * only needs to happen once per function entry.
	 */
	necp_matched_policy_id = necp_ip6_output_find_policy_match(m, flags,
	    (flags & IPV6_OUTARGS) ? ip6oa : NULL, ro ? ro->ro_rt : NULL, &necp_result,
	    &necp_result_parameter);
#endif /* NECP */

	/*
	 * If a chain was passed in, prepare for ther first iteration. For all
	 * other iterations, this work will be done at evaluateloop: label.
	 */
	if (packetchain) {
		/*
		 * Remove m from the chain during processing to avoid
		 * accidental frees on entire list.
		 */
		inputchain = m->m_nextpkt;
		m->m_nextpkt = NULL;
	}

loopit:
	packets_processed++;
	m->m_pkthdr.pkt_flags &= ~(PKTF_LOOP | PKTF_IFAINFO);
	ip6 = mtod(m, struct ip6_hdr *);
	nxt0 = ip6->ip6_nxt;
	finaldst = ip6->ip6_dst;
	ip6obf.hdrsplit = FALSE;
	ro_pmtu = NULL;

	if (!SLIST_EMPTY(&m->m_pkthdr.tags)) {
		inject_filter_ref = ipf_get_inject_filter(m);
	} else {
		inject_filter_ref = NULL;
	}

#define MAKE_EXTHDR(hp, mp) do {                                        \
	if (hp != NULL) {                                               \
	        struct ip6_ext *eh = (struct ip6_ext *)(hp);            \
	        error = ip6_copyexthdr((mp), (caddr_t)(hp),             \
	            ((eh)->ip6e_len + 1) << 3);                         \
	        if (error)                                              \
	                goto freehdrs;                                  \
	}                                                               \
} while (0)

	if (opt != NULL) {
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

#undef MAKE_EXTHDR

#if NECP
	if (necp_matched_policy_id) {
		necp_mark_packet_from_ip(m, necp_matched_policy_id);

		switch (necp_result) {
		case NECP_KERNEL_POLICY_RESULT_PASS:
			if (necp_result_parameter.pass_flags & NECP_KERNEL_POLICY_PASS_NO_SKIP_IPSEC) {
				break;
			}
			goto skip_ipsec;
		case NECP_KERNEL_POLICY_RESULT_DROP:
			error = EHOSTUNREACH;
			ip6stat.ip6s_necp_policy_drop++;
			goto freehdrs;
		case NECP_KERNEL_POLICY_RESULT_SOCKET_DIVERT:
			/*
			 * Flow divert packets should be blocked at the IP
			 * layer.
			 */
			error = EHOSTUNREACH;
			ip6stat.ip6s_necp_policy_drop++;
			goto freehdrs;
		case NECP_KERNEL_POLICY_RESULT_IP_TUNNEL: {
			/*
			 * Verify that the packet is being routed to the tunnel
			 */
			struct ifnet *policy_ifp =
			    necp_get_ifnet_from_result_parameter(
				&necp_result_parameter);

			if (policy_ifp == ifp) {
				goto skip_ipsec;
			} else {
				if (necp_packet_can_rebind_to_ifnet(m,
				    policy_ifp, (struct route *)&necp_route,
				    AF_INET6)) {
					/*
					 * Set scoped index to the tunnel
					 * interface, since it is compatible
					 * with the packet. This will only work
					 * for callers who pass IPV6_OUTARGS,
					 * but that covers all of the clients
					 * we care about today.
					 */
					if (flags & IPV6_OUTARGS) {
						ip6oa->ip6oa_boundif =
						    policy_ifp->if_index;
						ip6oa->ip6oa_flags |=
						    IP6OAF_BOUND_IF;
					}
					if (opt != NULL
					    && opt->ip6po_pktinfo != NULL) {
						opt->ip6po_pktinfo->
						ipi6_ifindex =
						    policy_ifp->if_index;
					}
					ro = &necp_route;
					goto skip_ipsec;
				} else {
					error = ENETUNREACH;
					ip6stat.ip6s_necp_policy_drop++;
					goto freehdrs;
				}
			}
		}
		default:
			break;
		}
	}
#endif /* NECP */

#if IPSEC
	if (ipsec_bypass != 0 || ip6obf.noipsec) {
		goto skip_ipsec;
	}

	if (sp == NULL) {
		/* get a security policy for this packet */
		if (so != NULL) {
			sp = ipsec6_getpolicybysock(m, IPSEC_DIR_OUTBOUND,
			    so, &error);
		} else {
			sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_OUTBOUND,
			    0, &error);
		}
		if (sp == NULL) {
			IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
			goto freehdrs;
		}
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
		ip6obf.needipsec = FALSE;
		break;

	case IPSEC_POLICY_IPSEC:
		if (sp->req == NULL) {
			/* acquire a policy */
			error = key_spdacquire(sp);
			goto freehdrs;
		}
		if (sp->ipsec_if) {
			goto skip_ipsec;
		} else {
			ip6obf.needipsec = TRUE;
		}
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		printf("%s: Invalid policy found: %d\n", __func__, sp->policy);
		break;
	}
skip_ipsec:
#endif /* IPSEC */

	/*
	 * Calculate the total length of the extension header chain.
	 * Keep the length of the unfragmentable part for fragmentation.
	 */
	optlen = 0;
	if (exthdrs.ip6e_hbh != NULL) {
		optlen += exthdrs.ip6e_hbh->m_len;
	}
	if (exthdrs.ip6e_dest1 != NULL) {
		optlen += exthdrs.ip6e_dest1->m_len;
	}
	if (exthdrs.ip6e_rthdr != NULL) {
		optlen += exthdrs.ip6e_rthdr->m_len;
	}
	unfragpartlen = optlen + sizeof(struct ip6_hdr);

	/* NOTE: we don't add AH/ESP length here. do that later. */
	if (exthdrs.ip6e_dest2 != NULL) {
		optlen += exthdrs.ip6e_dest2->m_len;
	}

	/*
	 * If we need IPsec, or there is at least one extension header,
	 * separate IP6 header from the payload.
	 */
	if ((
#if IPSEC
		    ip6obf.needipsec ||
#endif /* IPSEC */
		    optlen) && !ip6obf.hdrsplit) {
		if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
			m = NULL;
			goto freehdrs;
		}
		m = exthdrs.ip6e_ip6;
		ip6obf.hdrsplit = TRUE;
	}

	/* adjust pointer */
	ip6 = mtod(m, struct ip6_hdr *);

	/* adjust mbuf packet header length */
	m->m_pkthdr.len += optlen;
	plen = m->m_pkthdr.len - sizeof(*ip6);

	/* If this is a jumbo payload, insert a jumbo payload option. */
	if (plen > IPV6_MAXPACKET) {
		if (!ip6obf.hdrsplit) {
			if ((error = ip6_splithdr(m, &exthdrs)) != 0) {
				m = NULL;
				goto freehdrs;
			}
			m = exthdrs.ip6e_ip6;
			ip6obf.hdrsplit = TRUE;
		}
		/* adjust pointer */
		ip6 = mtod(m, struct ip6_hdr *);
		if ((error = ip6_insert_jumboopt(&exthdrs, plen)) != 0) {
			goto freehdrs;
		}
		ip6->ip6_plen = 0;
	} else {
		ip6->ip6_plen = htons(plen);
	}
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
	nexthdrp = &ip6->ip6_nxt;
	mprev = m;

	/*
	 * we treat dest2 specially.  this makes IPsec processing
	 * much easier.  the goal here is to make mprev point the
	 * mbuf prior to dest2.
	 *
	 * result: IPv6 dest2 payload
	 * m and mprev will point to IPv6 header.
	 */
	if (exthdrs.ip6e_dest2 != NULL) {
		if (!ip6obf.hdrsplit) {
			panic("assumption failed: hdr not split");
			/* NOTREACHED */
		}
		exthdrs.ip6e_dest2->m_next = m->m_next;
		m->m_next = exthdrs.ip6e_dest2;
		*mtod(exthdrs.ip6e_dest2, u_char *) = ip6->ip6_nxt;
		ip6->ip6_nxt = IPPROTO_DSTOPTS;
	}

#define MAKE_CHAIN(m, mp, p, i) do {                                    \
	if (m != NULL) {                                                \
	        if (!ip6obf.hdrsplit) {                                 \
	                panic("assumption failed: hdr not split");      \
	/* NOTREACHED */                                \
	        }                                                       \
	        *mtod((m), u_char *) = *(p);                            \
	        *(p) = (i);                                             \
	        p = mtod((m), u_char *);                                \
	        (m)->m_next = (mp)->m_next;                             \
	        (mp)->m_next = (m);                                     \
	        (mp) = (m);                                             \
	}                                                               \
} while (0)
	/*
	 * result: IPv6 hbh dest1 rthdr dest2 payload
	 * m will point to IPv6 header.  mprev will point to the
	 * extension header prior to dest2 (rthdr in the above case).
	 */
	MAKE_CHAIN(exthdrs.ip6e_hbh, mprev, nexthdrp, IPPROTO_HOPOPTS);
	MAKE_CHAIN(exthdrs.ip6e_dest1, mprev, nexthdrp, IPPROTO_DSTOPTS);
	MAKE_CHAIN(exthdrs.ip6e_rthdr, mprev, nexthdrp, IPPROTO_ROUTING);

	/* It is no longer safe to free the pointers in exthdrs. */
	exthdrs.merged = TRUE;

#undef MAKE_CHAIN

#if IPSEC
	if (ip6obf.needipsec && (m->m_pkthdr.csum_flags & CSUM_DELAY_IPV6_DATA)) {
		in6_delayed_cksum_offset(m, 0, optlen, nxt0);
	}
#endif /* IPSEC */

	if (!TAILQ_EMPTY(&ipv6_filters) &&
	    !((flags & IPV6_OUTARGS) &&
	    (ip6oa->ip6oa_flags & IP6OAF_INTCOPROC_ALLOWED)
#if NECP
	    && !necp_packet_should_skip_filters(m)
#endif // NECP
	    )) {
		struct ipfilter *filter;
		int seen = (inject_filter_ref == NULL);
		int fixscope = 0;

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
			ip6->ip6_dst.s6_addr16[1] =
			    htons(ro->ro_dst.sin6_scope_id);
		}

		ipf_ref();
		TAILQ_FOREACH(filter, &ipv6_filters, ipf_link) {
			/*
			 * Don't process packet twice if we've already seen it.
			 */
			if (seen == 0) {
				if ((struct ipfilter *)inject_filter_ref ==
				    filter) {
					seen = 1;
				}
			} else if (filter->ipf_filter.ipf_output != NULL) {
				errno_t result;

				result = filter->ipf_filter.ipf_output(
					filter->ipf_filter.cookie,
					(mbuf_t *)&m, ippo);
				if (result == EJUSTRETURN) {
					ipf_unref();
					m = NULL;
					goto evaluateloop;
				}
				if (result != 0) {
					ipf_unref();
					goto bad;
				}
			}
		}
		ipf_unref();

		ip6 = mtod(m, struct ip6_hdr *);
		/* Hack: cleanup embedded scope_id if we put it there */
		if (fixscope) {
			ip6->ip6_dst.s6_addr16[1] = 0;
		}
	}

#if IPSEC
	if (ip6obf.needipsec) {
		int segleft_org;

		/*
		 * pointers after IPsec headers are not valid any more.
		 * other pointers need a great care too.
		 * (IPsec routines should not mangle mbufs prior to AH/ESP)
		 */
		exthdrs.ip6e_dest2 = NULL;

		if (exthdrs.ip6e_rthdr != NULL) {
			rh = mtod(exthdrs.ip6e_rthdr, struct ip6_rthdr *);
			segleft_org = rh->ip6r_segleft;
			rh->ip6r_segleft = 0;
		} else {
			rh = NULL;
			segleft_org = 0;
		}

		ipsec_state.m = m;
		error = ipsec6_output_trans(&ipsec_state, nexthdrp, mprev,
		    sp, flags, &needipsectun);
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
				printf("ip6_output (ipsec): error code %d\n",
				    error);
			/* FALLTHRU */
			case ENOENT:
				/* don't show these error codes to the user */
				error = 0;
				break;
			}
			goto bad;
		}
		if (exthdrs.ip6e_rthdr != NULL) {
			/* ah6_output doesn't modify mbuf chain */
			rh->ip6r_segleft = segleft_org;
		}
	}
#endif /* IPSEC */

	/* If there is a routing header, discard the packet. */
	if (exthdrs.ip6e_rthdr != NULL) {
		error = EINVAL;
		goto bad;
	}

	/* Source address validation */
	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) &&
	    !(flags & IPV6_UNSPECSRC)) {
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
	if (ro == NULL) {
		ro = &ip6route;
		bzero((caddr_t)ro, sizeof(*ro));
	}
	ro_pmtu = ro;
	if (opt != NULL && opt->ip6po_rthdr) {
		ro = &opt->ip6po_route;
	}
	dst = SIN6(&ro->ro_dst);

	if (ro->ro_rt != NULL) {
		RT_LOCK_ASSERT_NOTHELD(ro->ro_rt);
	}
	/*
	 * if specified, try to fill in the traffic class field.
	 * do not override if a non-zero value is already set.
	 * we check the diffserv field and the ecn field separately.
	 */
	if (opt != NULL && opt->ip6po_tclass >= 0) {
		int mask = 0;

		if ((ip6->ip6_flow & htonl(0xfc << 20)) == 0) {
			mask |= 0xfc;
		}
		if ((ip6->ip6_flow & htonl(0x03 << 20)) == 0) {
			mask |= 0x03;
		}
		if (mask != 0) {
			ip6->ip6_flow |=
			    htonl((opt->ip6po_tclass & mask) << 20);
		}
	}

	/* fill in or override the hop limit field, if necessary. */
	if (opt && opt->ip6po_hlim != -1) {
		ip6->ip6_hlim = opt->ip6po_hlim & 0xff;
	} else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
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
	if (ROUTE_UNUSABLE(ro) || dst->sin6_family != AF_INET6 ||
	    !IN6_ARE_ADDR_EQUAL(&dst->sin6_addr, &ip6->ip6_dst)) {
		ROUTE_RELEASE(ro);
	}

	if (ro->ro_rt == NULL) {
		bzero(dst, sizeof(*dst));
		dst->sin6_family = AF_INET6;
		dst->sin6_len = sizeof(struct sockaddr_in6);
		dst->sin6_addr = ip6->ip6_dst;
	}
#if IPSEC
	if (ip6obf.needipsec && needipsectun) {
#if CONFIG_DTRACE
		struct ifnet *trace_ifp = (ifpp_save != NULL) ? (*ifpp_save) : NULL;
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
		route_copyout((struct route *)&ipsec_state.ro, (struct route *)ro,
		    sizeof(struct route_in6));
		ipsec_state.dst = SA(dst);

		/* So that we can see packets inside the tunnel */
		DTRACE_IP6(send, struct mbuf *, m, struct inpcb *, NULL,
		    struct ip6_hdr *, ip6, struct ifnet *, trace_ifp,
		    struct ip *, NULL, struct ip6_hdr *, ip6);

		error = ipsec6_output_tunnel(&ipsec_state, sp, flags);
		/* tunneled in IPv4? packet is gone */
		if (ipsec_state.tunneled == 4) {
			m = NULL;
			goto evaluateloop;
		}
		m = ipsec_state.m;
		ipsec_saved_route = ro;
		ro = (struct route_in6 *)&ipsec_state.ro;
		dst = SIN6(ipsec_state.dst);
		if (error) {
			/* mbuf is already reclaimed in ipsec6_output_tunnel. */
			m = NULL;
			switch (error) {
			case EHOSTUNREACH:
			case ENETUNREACH:
			case EMSGSIZE:
			case ENOBUFS:
			case ENOMEM:
				break;
			default:
				printf("ip6_output (ipsec): error code %d\n",
				    error);
			/* FALLTHRU */
			case ENOENT:
				/* don't show these error codes to the user */
				error = 0;
				break;
			}
			goto bad;
		}
		/*
		 * The packet has been encapsulated so the ifscope
		 * is no longer valid since it does not apply to the
		 * outer address: ignore the ifscope.
		 */
		if (flags & IPV6_OUTARGS) {
			ip6oa->ip6oa_boundif = IFSCOPE_NONE;
			ip6oa->ip6oa_flags &= ~IP6OAF_BOUND_IF;
		}
		if (opt != NULL && opt->ip6po_pktinfo != NULL) {
			if (opt->ip6po_pktinfo->ipi6_ifindex != IFSCOPE_NONE) {
				opt->ip6po_pktinfo->ipi6_ifindex = IFSCOPE_NONE;
			}
		}
		exthdrs.ip6e_ip6 = m;
	}
#endif /* IPSEC */

	/*
	 * ifp should only be filled in for dummy net packets which will jump
	 * to check_with_pf label.
	 */
	if (ifp != NULL) {
		VERIFY(ip6obf.route_selected);
	}

	/* adjust pointer */
	ip6 = mtod(m, struct ip6_hdr *);

	if (ip6obf.select_srcif) {
		bzero(&src_sa, sizeof(src_sa));
		src_sa.sin6_family = AF_INET6;
		src_sa.sin6_len = sizeof(src_sa);
		src_sa.sin6_addr = ip6->ip6_src;
	}
	bzero(&dst_sa, sizeof(dst_sa));
	dst_sa.sin6_family = AF_INET6;
	dst_sa.sin6_len = sizeof(dst_sa);
	dst_sa.sin6_addr = ip6->ip6_dst;

	/*
	 * Only call in6_selectroute() on first iteration to avoid taking
	 * multiple references on ifp and rt.
	 *
	 * in6_selectroute() might return an ifp with its reference held
	 * even in the error case, so make sure to release its reference.
	 * ip6oa may be NULL if IPV6_OUTARGS isn't set.
	 */
	if (!ip6obf.route_selected) {
		error = in6_selectroute( ip6obf.select_srcif ? &src_sa : NULL,
		    &dst_sa, opt, im6o, &src_ia, ro, &ifp, &rt, 0, ip6oa);

		if (error != 0) {
			switch (error) {
			case EHOSTUNREACH:
				ip6stat.ip6s_noroute++;
				break;
			case EADDRNOTAVAIL:
			default:
				break; /* XXX statistics? */
			}
			if (ifp != NULL) {
				in6_ifstat_inc(ifp, ifs6_out_discard);
			}
			/* ifp (if non-NULL) will be released at the end */
			goto bad;
		}
		ip6obf.route_selected = TRUE;
	}
	if (rt == NULL) {
		/*
		 * If in6_selectroute() does not return a route entry,
		 * dst may not have been updated.
		 */
		*dst = dst_sa;  /* XXX */
	}

#if NECP
	/* Catch-all to check if the interface is allowed */
	if (!necp_packet_is_allowed_over_interface(m, ifp)) {
		error = EHOSTUNREACH;
		ip6stat.ip6s_necp_policy_drop++;
		goto bad;
	}
#endif /* NECP */

	/*
	 * then rt (for unicast) and ifp must be non-NULL valid values.
	 */
	if (!(flags & IPV6_FORWARDING)) {
		in6_ifstat_inc_na(ifp, ifs6_out_request);
	}
	if (rt != NULL) {
		RT_LOCK(rt);
		if (ia == NULL) {
			ia = (struct in6_ifaddr *)(rt->rt_ifa);
			if (ia != NULL) {
				IFA_ADDREF(&ia->ia_ifa);
			}
		}
		rt->rt_use++;
		RT_UNLOCK(rt);
	}

	/*
	 * The outgoing interface must be in the zone of source and
	 * destination addresses (except local/loopback).  We should
	 * use ia_ifp to support the case of sending packets to an
	 * address of our own.
	 */
	if (ia != NULL && ia->ia_ifp) {
		ifnet_reference(ia->ia_ifp);    /* for origifp */
		if (origifp != NULL) {
			ifnet_release(origifp);
		}
		origifp = ia->ia_ifp;
	} else {
		if (ifp != NULL) {
			ifnet_reference(ifp);   /* for origifp */
		}
		if (origifp != NULL) {
			ifnet_release(origifp);
		}
		origifp = ifp;
	}

	/* skip scope enforcements for local/loopback route */
	if (rt == NULL || !(rt->rt_ifp->if_flags & IFF_LOOPBACK)) {
		struct in6_addr src0, dst0;
		u_int32_t zone;

		src0 = ip6->ip6_src;
		if (in6_setscope(&src0, origifp, &zone)) {
			goto badscope;
		}
		bzero(&src_sa, sizeof(src_sa));
		src_sa.sin6_family = AF_INET6;
		src_sa.sin6_len = sizeof(src_sa);
		src_sa.sin6_addr = ip6->ip6_src;
		if ((sa6_recoverscope(&src_sa, TRUE) ||
		    zone != src_sa.sin6_scope_id)) {
			goto badscope;
		}

		dst0 = ip6->ip6_dst;
		if ((in6_setscope(&dst0, origifp, &zone))) {
			goto badscope;
		}
		/* re-initialize to be sure */
		bzero(&dst_sa, sizeof(dst_sa));
		dst_sa.sin6_family = AF_INET6;
		dst_sa.sin6_len = sizeof(dst_sa);
		dst_sa.sin6_addr = ip6->ip6_dst;
		if ((sa6_recoverscope(&dst_sa, TRUE) ||
		    zone != dst_sa.sin6_scope_id)) {
			goto badscope;
		}

		/* scope check is done. */
		goto routefound;

badscope:
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(origifp, ifs6_out_discard);
		if (error == 0) {
			error = EHOSTUNREACH; /* XXX */
		}
		goto bad;
	}

routefound:
	if (rt != NULL && !IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		if (opt != NULL && opt->ip6po_nextroute.ro_rt) {
			/*
			 * The nexthop is explicitly specified by the
			 * application.  We assume the next hop is an IPv6
			 * address.
			 */
			dst = SIN6(opt->ip6po_nexthop);
		} else if ((rt->rt_flags & RTF_GATEWAY)) {
			dst = SIN6(rt->rt_gateway);
		}
		/*
		 * For packets destined to local/loopback, record the
		 * source the source interface (which owns the source
		 * address), as well as the output interface.  This is
		 * needed to reconstruct the embedded zone for the
		 * link-local address case in ip6_input().
		 */
		if (ia != NULL && (ifp->if_flags & IFF_LOOPBACK)) {
			uint32_t srcidx;

			if (src_ia != NULL) {
				srcidx = src_ia->ia_ifp->if_index;
			} else if (ro->ro_srcia != NULL) {
				srcidx = ro->ro_srcia->ifa_ifp->if_index;
			} else {
				srcidx = 0;
			}

			ip6_setsrcifaddr_info(m, srcidx, NULL);
			ip6_setdstifaddr_info(m, 0, ia);
		}
	}

	if (!IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		m->m_flags &= ~(M_BCAST | M_MCAST); /* just in case */
	} else {
		struct  in6_multi *in6m;

		m->m_flags = (m->m_flags & ~M_BCAST) | M_MCAST;
		in6_ifstat_inc_na(ifp, ifs6_out_mcast);

		/*
		 * Confirm that the outgoing interface supports multicast.
		 */
		if (!(ifp->if_flags & IFF_MULTICAST)) {
			ip6stat.ip6s_noroute++;
			in6_ifstat_inc(ifp, ifs6_out_discard);
			error = ENETUNREACH;
			goto bad;
		}
		in6_multihead_lock_shared();
		IN6_LOOKUP_MULTI(&ip6->ip6_dst, ifp, in6m);
		in6_multihead_lock_done();
		if (im6o != NULL) {
			IM6O_LOCK(im6o);
		}
		if (in6m != NULL &&
		    (im6o == NULL || im6o->im6o_multicast_loop)) {
			if (im6o != NULL) {
				IM6O_UNLOCK(im6o);
			}
			/*
			 * If we belong to the destination multicast group
			 * on the outgoing interface, and the caller did not
			 * forbid loopback, loop back a copy.
			 */
			ip6_mloopback(NULL, ifp, m, dst, optlen, nxt0);
		} else if (im6o != NULL) {
			IM6O_UNLOCK(im6o);
		}
		if (in6m != NULL) {
			IN6M_REMREF(in6m);
		}
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
			/* remove m from the packetchain and continue looping */
			if (m != NULL) {
				m_freem(m);
			}
			m = NULL;
			goto evaluateloop;
		}
	}

	/*
	 * Fill the outgoing inteface to tell the upper layer
	 * to increment per-interface statistics.
	 */
	if (ifpp != NULL && *ifpp == NULL) {
		ifnet_reference(ifp);   /* for caller */
		*ifpp = ifp;
	}

	/* Determine path MTU. */
	if ((error = ip6_getpmtu(ro_pmtu, ro, ifp, &finaldst, &mtu)) != 0) {
		goto bad;
	}

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
		if ((flags & IPV6_MINMTU)) {
			mtu = IPV6_MMTU;
		} else if (opt && opt->ip6po_minmtu == IP6PO_MINMTU_ALL) {
			mtu = IPV6_MMTU;
		} else if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) &&
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
	/*
	 * If the outgoing packet contains a hop-by-hop options header,
	 * it must be examined and processed even by the source node.
	 * (RFC 2460, section 4.)
	 */
	if (exthdrs.ip6e_hbh != NULL) {
		struct ip6_hbh *hbh = mtod(exthdrs.ip6e_hbh, struct ip6_hbh *);
		u_int32_t dummy; /* XXX unused */
		uint32_t oplen = 0; /* for ip6_process_hopopts() */
#if DIAGNOSTIC
		if ((hbh->ip6h_len + 1) << 3 > exthdrs.ip6e_hbh->m_len) {
			panic("ip6e_hbh is not continuous");
		}
#endif
		/*
		 * XXX: If we have to send an ICMPv6 error to the sender,
		 * we need the M_LOOP flag since icmp6_error() expects
		 * the IPv6 and the hop-by-hop options header are
		 * continuous unless the flag is set.
		 */
		m->m_flags |= M_LOOP;
		m->m_pkthdr.rcvif = ifp;
		if (ip6_process_hopopts(m, (u_int8_t *)(hbh + 1),
		    ((hbh->ip6h_len + 1) << 3) - sizeof(struct ip6_hbh),
		    &dummy, &oplen) < 0) {
			/*
			 * m was already freed at this point. Set to NULL so it
			 * is not re-freed at end of ip6_output_list.
			 */
			m = NULL;
			error = EINVAL; /* better error? */
			goto bad;
		}
		m->m_flags &= ~M_LOOP; /* XXX */
		m->m_pkthdr.rcvif = NULL;
	}

#if DUMMYNET
check_with_pf:
#endif /* DUMMYNET */
#if PF
	if (PF_IS_ENABLED && !skip_pf) {
#if DUMMYNET

		/*
		 * TODO: Need to save opt->ip6po_flags for reinjection
		 * rdar://10434993
		 */
		args.fwa_m = m;
		args.fwa_oif = ifp;
		args.fwa_oflags = flags;
		if (flags & IPV6_OUTARGS) {
			args.fwa_ip6oa = ip6oa;
		}
		args.fwa_ro6 = ro;
		args.fwa_dst6 = dst;
		args.fwa_ro6_pmtu = ro_pmtu;
		args.fwa_origifp = origifp;
		args.fwa_mtu = mtu;
		args.fwa_unfragpartlen = unfragpartlen;
		args.fwa_exthdrs = &exthdrs;
		/* Invoke outbound packet filter */
		error = pf_af_hook(ifp, NULL, &m, AF_INET6, FALSE, &args);
#else /* !DUMMYNET */
		error = pf_af_hook(ifp, NULL, &m, AF_INET6, FALSE, NULL);
#endif /* !DUMMYNET */

		if (error != 0 || m == NULL) {
			if (m != NULL) {
				panic("%s: unexpected packet %p\n",
				    __func__, m);
				/* NOTREACHED */
			}
			/* m was already freed by callee and is now NULL.  */
			goto evaluateloop;
		}
		ip6 = mtod(m, struct ip6_hdr *);
	}
#endif /* PF */

#ifdef IPSEC
	/* clean ipsec history before fragmentation */
	ipsec_delaux(m);
#endif /* IPSEC */

	if (ip6oa != NULL) {
		u_int8_t dscp;

		dscp = (ntohl(ip6->ip6_flow) & IP6FLOW_DSCP_MASK) >> IP6FLOW_DSCP_SHIFT;

		error = set_packet_qos(m, ifp,
		    ip6oa->ip6oa_flags & IP6OAF_QOSMARKING_ALLOWED ? TRUE : FALSE,
		    ip6oa->ip6oa_sotc, ip6oa->ip6oa_netsvctype, &dscp);
		if (error == 0) {
			ip6->ip6_flow &= ~htonl(IP6FLOW_DSCP_MASK);
			ip6->ip6_flow |= htonl((u_int32_t)dscp << IP6FLOW_DSCP_SHIFT);
		} else {
			printf("%s if_dscp_for_mbuf() error %d\n", __func__, error);
			error = 0;
		}
	}
	/*
	 * Determine whether fragmentation is necessary. If so, m is passed
	 * back as a chain of packets and original mbuf is freed. Otherwise, m
	 * is unchanged.
	 */
	error = ip6_fragment_packet(&m, opt,
	    &exthdrs, ifp, mtu, unfragpartlen, ro_pmtu, nxt0,
	    optlen);

	if (error) {
		goto bad;
	}

/*
 * The evaluateloop label is where we decide whether to continue looping over
 * packets or call into nd code to send.
 */
evaluateloop:

	/*
	 * m may be NULL when we jump to the evaluateloop label from PF or
	 * other code that can drop packets.
	 */
	if (m != NULL) {
		/*
		 * If we already have a chain to send, tack m onto the end.
		 * Otherwise make m the start and end of the to-be-sent chain.
		 */
		if (sendchain != NULL) {
			sendchain_last->m_nextpkt = m;
		} else {
			sendchain = m;
		}

		/* Fragmentation may mean m is a chain. Find the last packet. */
		while (m->m_nextpkt) {
			m = m->m_nextpkt;
		}
		sendchain_last = m;
		pktcnt++;
	}

	/* Fill in next m from inputchain as appropriate. */
	m = inputchain;
	if (m != NULL) {
		/* Isolate m from rest of input chain. */
		inputchain = m->m_nextpkt;
		m->m_nextpkt = NULL;

		/*
		 * Clear exthdrs and ipsec_state so stale contents are not
		 * reused. Note this also clears the exthdrs.merged flag.
		 */
		bzero(&exthdrs, sizeof(exthdrs));
		bzero(&ipsec_state, sizeof(ipsec_state));

		/* Continue looping. */
		goto loopit;
	}

	/*
	 * If we get here, there's no more mbufs in inputchain, so send the
	 * sendchain if there is one.
	 */
	if (pktcnt > 0) {
		error = nd6_output_list(ifp, origifp, sendchain, dst,
		    ro->ro_rt, adv);
		/*
		 * Fall through to done label even in error case because
		 * nd6_output_list frees packetchain in both success and
		 * failure cases.
		 */
	}

done:
	if (ifpp_save != NULL && *ifpp_save != NULL) {
		ifnet_release(*ifpp_save);
		*ifpp_save = NULL;
	}
	ROUTE_RELEASE(&ip6route);
#if IPSEC
	ROUTE_RELEASE(&ipsec_state.ro);
	if (sp != NULL) {
		key_freesp(sp, KEY_SADB_UNLOCKED);
	}
#endif /* IPSEC */
#if NECP
	ROUTE_RELEASE(&necp_route);
#endif /* NECP */
#if DUMMYNET
	ROUTE_RELEASE(&saved_route);
	ROUTE_RELEASE(&saved_ro_pmtu);
#endif /* DUMMYNET */

	if (ia != NULL) {
		IFA_REMREF(&ia->ia_ifa);
	}
	if (src_ia != NULL) {
		IFA_REMREF(&src_ia->ia_ifa);
	}
	if (ifp != NULL) {
		ifnet_release(ifp);
	}
	if (origifp != NULL) {
		ifnet_release(origifp);
	}
	if (ip6_output_measure) {
		net_perf_measure_time(&net_perf, &start_tv, packets_processed);
		net_perf_histogram(&net_perf, packets_processed);
	}
	return error;

freehdrs:
	if (exthdrs.ip6e_hbh != NULL) {
		if (exthdrs.merged) {
			panic("Double free of ip6e_hbh");
		}
		m_freem(exthdrs.ip6e_hbh);
	}
	if (exthdrs.ip6e_dest1 != NULL) {
		if (exthdrs.merged) {
			panic("Double free of ip6e_dest1");
		}
		m_freem(exthdrs.ip6e_dest1);
	}
	if (exthdrs.ip6e_rthdr != NULL) {
		if (exthdrs.merged) {
			panic("Double free of ip6e_rthdr");
		}
		m_freem(exthdrs.ip6e_rthdr);
	}
	if (exthdrs.ip6e_dest2 != NULL) {
		if (exthdrs.merged) {
			panic("Double free of ip6e_dest2");
		}
		m_freem(exthdrs.ip6e_dest2);
	}
	/* FALLTHRU */
bad:
	if (inputchain != NULL) {
		m_freem_list(inputchain);
	}
	if (sendchain != NULL) {
		m_freem_list(sendchain);
	}
	if (m != NULL) {
		m_freem(m);
	}

	goto done;

#undef ipf_pktopts
#undef exthdrs
#undef ip6route
#undef ipsec_state
#undef saved_route
#undef saved_ro_pmtu
#undef args
}

/* ip6_fragment_packet
 *
 * The fragmentation logic is rather complex:
 * 1: normal case (dontfrag == 0)
 * 1-a:	send as is if tlen <= path mtu
 * 1-b:	fragment if tlen > path mtu
 *
 * 2: if user asks us not to fragment (dontfrag == 1)
 * 2-a:	send as is if tlen <= interface mtu
 * 2-b:	error if tlen > interface mtu
 */

static int
ip6_fragment_packet(struct mbuf **mptr, struct ip6_pktopts *opt,
    struct ip6_exthdrs *exthdrsp, struct ifnet *ifp, uint32_t mtu,
    uint32_t unfragpartlen, struct route_in6 *ro_pmtu,
    int nxt0, uint32_t optlen)
{
	VERIFY(NULL != mptr);
	struct mbuf *m = *mptr;
	int error = 0;
	size_t tlen = m->m_pkthdr.len;
	boolean_t dontfrag = (opt != NULL && (opt->ip6po_flags & IP6PO_DONTFRAG));

	if (m->m_pkthdr.pkt_flags & PKTF_FORWARDED) {
		dontfrag = TRUE;
		/*
		 * Discard partial sum information if this packet originated
		 * from another interface; the packet would already have the
		 * final checksum and we shouldn't recompute it.
		 */
		if ((m->m_pkthdr.csum_flags & (CSUM_DATA_VALID | CSUM_PARTIAL)) ==
		    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
			m->m_pkthdr.csum_flags &= ~CSUM_TX_FLAGS;
			m->m_pkthdr.csum_data = 0;
		}
	}

	/* Access without acquiring nd_ifinfo lock for performance */
	if (dontfrag && tlen > IN6_LINKMTU(ifp)) {      /* case 2-b */
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
		pfctlinput2(PRC_MSGSIZE, SA(&ro_pmtu->ro_dst), (void *)&ip6cp);
		return EMSGSIZE;
	}

	/*
	 * transmit packet without fragmentation
	 */
	if (dontfrag ||
	    (tlen <= mtu || TSO_IPV6_OK(ifp, m) ||
	    (ifp->if_hwassist & CSUM_FRAGMENT_IPV6))) {
		/*
		 * mppn not updated in this case because no new chain is formed
		 * and inserted
		 */
		ip6_output_checksum(ifp, mtu, m, nxt0, tlen, optlen);
	} else {
		/*
		 * time to fragment - cases 1-b is handled inside
		 * ip6_do_fragmentation().
		 * mppn is passed down to be updated to point at fragment chain.
		 */
		u_int8_t *lexthdrsp;

		if (exthdrsp->ip6e_rthdr != NULL) {
			lexthdrsp = mtod(exthdrsp->ip6e_rthdr, uint8_t *);
		} else if (exthdrsp->ip6e_dest1 != NULL) {
			lexthdrsp = mtod(exthdrsp->ip6e_dest1, uint8_t *);
		} else if (exthdrsp->ip6e_hbh != NULL) {
			lexthdrsp = mtod(exthdrsp->ip6e_hbh, uint8_t *);
		} else {
			lexthdrsp = NULL;
		}
		error = ip6_do_fragmentation(mptr, optlen, ifp,
		    unfragpartlen, mtod(m, struct ip6_hdr *), lexthdrsp, mtu,
		    nxt0, htonl(ip6_randomid()));
	}

	return error;
}

/*
 * ip6_do_fragmentation() is called by ip6_fragment_packet() after determining
 * the packet needs to be fragmented. on success, morig is freed and a chain
 * of fragments is linked into the packet chain where morig existed. Otherwise,
 * an errno is returned.
 * optlen:        total length of all extension headers (excludes the IPv6 header).
 * unfragpartlen: length of the per-fragment headers which consist of the IPv6
 *                header plus any extension headers that must be processed by nodes
 *                en route to the destination.
 * lexthdrsp:     pointer to the last extension header in the unfragmentable part
 *                or NULL.
 * nxt0:          upper-layer protocol number.
 * id:            Identification value to be used in the fragment header.
 */
int
ip6_do_fragmentation(struct mbuf **mptr, uint32_t optlen, struct ifnet *ifp,
    uint32_t unfragpartlen, struct ip6_hdr *ip6, uint8_t *lexthdrsp,
    uint32_t mtu, int nxt0, uint32_t id)
{
	VERIFY(NULL != mptr);
	int error = 0;

	struct mbuf *morig = *mptr;
	struct mbuf *first_mbufp = NULL;
	struct mbuf *last_mbufp = NULL;

	size_t tlen = morig->m_pkthdr.len;

	/* try to fragment the packet. case 1-b */
	if ((morig->m_pkthdr.csum_flags & CSUM_TSO_IPV6)) {
		/* TSO and fragment aren't compatible */
		in6_ifstat_inc(ifp, ifs6_out_fragfail);
		return EMSGSIZE;
	} else if (mtu < IPV6_MMTU) {
		/* path MTU cannot be less than IPV6_MMTU */
		in6_ifstat_inc(ifp, ifs6_out_fragfail);
		return EMSGSIZE;
	} else if (ip6->ip6_plen == 0) {
		/* jumbo payload cannot be fragmented */
		in6_ifstat_inc(ifp, ifs6_out_fragfail);
		return EMSGSIZE;
	} else {
		size_t hlen, len, off;
		struct mbuf **mnext = NULL;
		struct ip6_frag *ip6f;
		u_char nextproto;

		/*
		 * Too large for the destination or interface;
		 * fragment if possible.
		 * Must be able to put at least 8 bytes per fragment.
		 */
		hlen = unfragpartlen;
		if (mtu > IPV6_MAXPACKET) {
			mtu = IPV6_MAXPACKET;
		}

		len = (mtu - hlen - sizeof(struct ip6_frag)) & ~7;
		if (len < 8) {
			in6_ifstat_inc(ifp, ifs6_out_fragfail);
			return EMSGSIZE;
		}

		/*
		 * Change the next header field of the last header in the
		 * unfragmentable part.
		 */
		if (lexthdrsp != NULL) {
			nextproto = *lexthdrsp;
			*lexthdrsp = IPPROTO_FRAGMENT;
		} else {
			nextproto = ip6->ip6_nxt;
			ip6->ip6_nxt = IPPROTO_FRAGMENT;
		}

		if (morig->m_pkthdr.csum_flags & CSUM_DELAY_IPV6_DATA) {
			in6_delayed_cksum_offset(morig, 0, optlen, nxt0);
		}

		/*
		 * Loop through length of segment after first fragment,
		 * make new header and copy data of each part and link onto
		 * chain.
		 */
		for (off = hlen; off < tlen; off += len) {
			struct ip6_hdr *new_mhip6;
			struct mbuf *new_m;
			struct mbuf *m_frgpart;

			MGETHDR(new_m, M_DONTWAIT, MT_HEADER);  /* MAC-OK */
			if (new_m == NULL) {
				error = ENOBUFS;
				ip6stat.ip6s_odropped++;
				break;
			}
			new_m->m_pkthdr.rcvif = NULL;
			new_m->m_flags = morig->m_flags & M_COPYFLAGS;

			if (first_mbufp != NULL) {
				/* Every pass through loop but first */
				*mnext = new_m;
				last_mbufp = new_m;
			} else {
				/* This is the first element of the fragment chain */
				first_mbufp = new_m;
				last_mbufp = new_m;
			}
			mnext = &new_m->m_nextpkt;

			new_m->m_data += max_linkhdr;
			new_mhip6 = mtod(new_m, struct ip6_hdr *);
			*new_mhip6 = *ip6;
			new_m->m_len = sizeof(*new_mhip6);

			error = ip6_insertfraghdr(morig, new_m, hlen, &ip6f);
			if (error) {
				ip6stat.ip6s_odropped++;
				break;
			}

			ip6f->ip6f_offlg = htons((u_short)((off - hlen) & ~7));
			if (off + len >= tlen) {
				len = tlen - off;
			} else {
				ip6f->ip6f_offlg |= IP6F_MORE_FRAG;
			}
			new_mhip6->ip6_plen = htons((u_short)(len + hlen +
			    sizeof(*ip6f) - sizeof(struct ip6_hdr)));

			if ((m_frgpart = m_copy(morig, off, len)) == NULL) {
				error = ENOBUFS;
				ip6stat.ip6s_odropped++;
				break;
			}
			m_cat(new_m, m_frgpart);
			new_m->m_pkthdr.len = len + hlen + sizeof(*ip6f);
			new_m->m_pkthdr.rcvif = NULL;

			M_COPY_CLASSIFIER(new_m, morig);
			M_COPY_PFTAG(new_m, morig);

#ifdef notyet
#if CONFIG_MACF_NET
			mac_create_fragment(morig, new_m);
#endif /* CONFIG_MACF_NET */
#endif /* notyet */

			ip6f->ip6f_reserved = 0;
			ip6f->ip6f_ident = id;
			ip6f->ip6f_nxt = nextproto;
			ip6stat.ip6s_ofragments++;
			in6_ifstat_inc(ifp, ifs6_out_fragcreat);
		}

		if (error) {
			/* free all the fragments created */
			if (first_mbufp != NULL) {
				m_freem_list(first_mbufp);
				first_mbufp = NULL;
			}
			last_mbufp = NULL;
		} else {
			/* successful fragmenting */
			m_freem(morig);
			*mptr = first_mbufp;
			last_mbufp->m_nextpkt = NULL;
			ip6stat.ip6s_fragmented++;
			in6_ifstat_inc(ifp, ifs6_out_fragok);
		}
	}
	return error;
}

static int
ip6_copyexthdr(struct mbuf **mp, caddr_t hdr, int hlen)
{
	struct mbuf *m;

	if (hlen > MCLBYTES) {
		return ENOBUFS; /* XXX */
	}
	MGET(m, M_DONTWAIT, MT_DATA);
	if (m == NULL) {
		return ENOBUFS;
	}

	if (hlen > MLEN) {
		MCLGET(m, M_DONTWAIT);
		if (!(m->m_flags & M_EXT)) {
			m_free(m);
			return ENOBUFS;
		}
	}
	m->m_len = hlen;
	if (hdr != NULL) {
		bcopy(hdr, mtod(m, caddr_t), hlen);
	}

	*mp = m;
	return 0;
}

static void
ip6_out_cksum_stats(int proto, u_int32_t len)
{
	switch (proto) {
	case IPPROTO_TCP:
		tcp_out6_cksum_stats(len);
		break;
	case IPPROTO_UDP:
		udp_out6_cksum_stats(len);
		break;
	default:
		/* keep only TCP or UDP stats for now */
		break;
	}
}

/*
 * Process a delayed payload checksum calculation (outbound path.)
 *
 * hoff is the number of bytes beyond the mbuf data pointer which
 * points to the IPv6 header.  optlen is the number of bytes, if any,
 * between the end of IPv6 header and the beginning of the ULP payload
 * header, which represents the extension headers.  If optlen is less
 * than zero, this routine will bail when it detects extension headers.
 *
 * Returns a bitmask representing all the work done in software.
 */
uint32_t
in6_finalize_cksum(struct mbuf *m, uint32_t hoff, int32_t optlen,
    int32_t nxt0, uint32_t csum_flags)
{
	unsigned char buf[sizeof(struct ip6_hdr)] __attribute__((aligned(8)));
	struct ip6_hdr *ip6;
	uint32_t offset, mlen, hlen, olen, sw_csum;
	uint16_t csum, ulpoff, plen;
	uint8_t nxt;

	_CASSERT(sizeof(csum) == sizeof(uint16_t));
	VERIFY(m->m_flags & M_PKTHDR);

	sw_csum = (csum_flags & m->m_pkthdr.csum_flags);

	if ((sw_csum &= CSUM_DELAY_IPV6_DATA) == 0) {
		goto done;
	}

	mlen = m->m_pkthdr.len;                         /* total mbuf len */
	hlen = sizeof(*ip6);                            /* IPv6 header len */

	/* sanity check (need at least IPv6 header) */
	if (mlen < (hoff + hlen)) {
		panic("%s: mbuf %p pkt len (%u) < hoff+ip6_hdr "
		    "(%u+%u)\n", __func__, m, mlen, hoff, hlen);
		/* NOTREACHED */
	}

	/*
	 * In case the IPv6 header is not contiguous, or not 32-bit
	 * aligned, copy it to a local buffer.
	 */
	if ((hoff + hlen) > m->m_len ||
	    !IP6_HDR_ALIGNED_P(mtod(m, caddr_t) + hoff)) {
		m_copydata(m, hoff, hlen, (caddr_t)buf);
		ip6 = (struct ip6_hdr *)(void *)buf;
	} else {
		ip6 = (struct ip6_hdr *)(void *)(m->m_data + hoff);
	}

	nxt = ip6->ip6_nxt;
	plen = ntohs(ip6->ip6_plen);
	if (plen != (mlen - (hoff + hlen))) {
		plen = OSSwapInt16(plen);
		if (plen != (mlen - (hoff + hlen))) {
			/* Don't complain for jumbograms */
			if (plen != 0 || nxt != IPPROTO_HOPOPTS) {
				printf("%s: mbuf 0x%llx proto %d IPv6 "
				    "plen %d (%x) [swapped %d (%x)] doesn't "
				    "match actual packet length; %d is used "
				    "instead\n", __func__,
				    (uint64_t)VM_KERNEL_ADDRPERM(m), nxt,
				    ip6->ip6_plen, ip6->ip6_plen, plen, plen,
				    (mlen - (hoff + hlen)));
			}
			plen = mlen - (hoff + hlen);
		}
	}

	if (optlen < 0) {
		/* next header isn't TCP/UDP and we don't know optlen, bail */
		if (nxt != IPPROTO_TCP && nxt != IPPROTO_UDP) {
			sw_csum = 0;
			goto done;
		}
		olen = 0;
	} else {
		/* caller supplied the original transport number; use it */
		if (nxt0 >= 0) {
			nxt = nxt0;
		}
		olen = optlen;
	}

	offset = hoff + hlen + olen;                    /* ULP header */

	/* sanity check */
	if (mlen < offset) {
		panic("%s: mbuf %p pkt len (%u) < hoff+ip6_hdr+ext_hdr "
		    "(%u+%u+%u)\n", __func__, m, mlen, hoff, hlen, olen);
		/* NOTREACHED */
	}

	/*
	 * offset is added to the lower 16-bit value of csum_data,
	 * which is expected to contain the ULP offset; therefore
	 * CSUM_PARTIAL offset adjustment must be undone.
	 */
	if ((m->m_pkthdr.csum_flags & (CSUM_PARTIAL | CSUM_DATA_VALID)) ==
	    (CSUM_PARTIAL | CSUM_DATA_VALID)) {
		/*
		 * Get back the original ULP offset (this will
		 * undo the CSUM_PARTIAL logic in ip6_output.)
		 */
		m->m_pkthdr.csum_data = (m->m_pkthdr.csum_tx_stuff -
		    m->m_pkthdr.csum_tx_start);
	}

	ulpoff = (m->m_pkthdr.csum_data & 0xffff);      /* ULP csum offset */

	if (mlen < (ulpoff + sizeof(csum))) {
		panic("%s: mbuf %p pkt len (%u) proto %d invalid ULP "
		    "cksum offset (%u) cksum flags 0x%x\n", __func__,
		    m, mlen, nxt, ulpoff, m->m_pkthdr.csum_flags);
		/* NOTREACHED */
	}

	csum = inet6_cksum(m, 0, offset, plen - olen);

	/* Update stats */
	ip6_out_cksum_stats(nxt, plen - olen);

	/* RFC1122 4.1.3.4 */
	if (csum == 0 &&
	    (m->m_pkthdr.csum_flags & (CSUM_UDPIPV6 | CSUM_ZERO_INVERT))) {
		csum = 0xffff;
	}

	/* Insert the checksum in the ULP csum field */
	offset += ulpoff;
	if ((offset + sizeof(csum)) > m->m_len) {
		m_copyback(m, offset, sizeof(csum), &csum);
	} else if (IP6_HDR_ALIGNED_P(mtod(m, char *) + hoff)) {
		*(uint16_t *)(void *)(mtod(m, char *) + offset) = csum;
	} else {
		bcopy(&csum, (mtod(m, char *) + offset), sizeof(csum));
	}
	m->m_pkthdr.csum_flags &= ~(CSUM_DELAY_IPV6_DATA | CSUM_DATA_VALID |
	    CSUM_PARTIAL | CSUM_ZERO_INVERT);

done:
	return sw_csum;
}

/*
 * Insert jumbo payload option.
 */
static int
ip6_insert_jumboopt(struct ip6_exthdrs *exthdrs, u_int32_t plen)
{
	struct mbuf *mopt;
	u_char *optbuf;
	u_int32_t v;

#define JUMBOOPTLEN     8       /* length of jumbo payload option and padding */

	/*
	 * If there is no hop-by-hop options header, allocate new one.
	 * If there is one but it doesn't have enough space to store the
	 * jumbo payload option, allocate a cluster to store the whole options.
	 * Otherwise, use it to store the options.
	 */
	if (exthdrs->ip6e_hbh == NULL) {
		MGET(mopt, M_DONTWAIT, MT_DATA);
		if (mopt == NULL) {
			return ENOBUFS;
		}
		mopt->m_len = JUMBOOPTLEN;
		optbuf = mtod(mopt, u_char *);
		optbuf[1] = 0;  /* = ((JUMBOOPTLEN) >> 3) - 1 */
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
			if (oldoptlen + JUMBOOPTLEN > MCLBYTES) {
				return ENOBUFS;
			}

			/*
			 * As a consequence, we must always prepare a cluster
			 * at this point.
			 */
			MGET(n, M_DONTWAIT, MT_DATA);
			if (n != NULL) {
				MCLGET(n, M_DONTWAIT);
				if (!(n->m_flags & M_EXT)) {
					m_freem(n);
					n = NULL;
				}
			}
			if (n == NULL) {
				return ENOBUFS;
			}
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

	return 0;
#undef JUMBOOPTLEN
}

/*
 * Insert fragment header and copy unfragmentable header portions.
 */
static int
ip6_insertfraghdr(struct mbuf *m0, struct mbuf *m, int hlen,
    struct ip6_frag **frghdrp)
{
	struct mbuf *n, *mlast;

	if (hlen > sizeof(struct ip6_hdr)) {
		n = m_copym(m0, sizeof(struct ip6_hdr),
		    hlen - sizeof(struct ip6_hdr), M_DONTWAIT);
		if (n == NULL) {
			return ENOBUFS;
		}
		m->m_next = n;
	} else {
		n = m;
	}

	/* Search for the last mbuf of unfragmentable part. */
	for (mlast = n; mlast->m_next; mlast = mlast->m_next) {
		;
	}

	if (!(mlast->m_flags & M_EXT) &&
	    M_TRAILINGSPACE(mlast) >= sizeof(struct ip6_frag)) {
		/* use the trailing space of the last mbuf for the frag hdr */
		*frghdrp = (struct ip6_frag *)(mtod(mlast, caddr_t) +
		    mlast->m_len);
		mlast->m_len += sizeof(struct ip6_frag);
		m->m_pkthdr.len += sizeof(struct ip6_frag);
	} else {
		/* allocate a new mbuf for the fragment header */
		struct mbuf *mfrg;

		MGET(mfrg, M_DONTWAIT, MT_DATA);
		if (mfrg == NULL) {
			return ENOBUFS;
		}
		mfrg->m_len = sizeof(struct ip6_frag);
		*frghdrp = mtod(mfrg, struct ip6_frag *);
		mlast->m_next = mfrg;
	}

	return 0;
}

static int
ip6_getpmtu(struct route_in6 *ro_pmtu, struct route_in6 *ro,
    struct ifnet *ifp, struct in6_addr *dst, u_int32_t *mtup)
{
	u_int32_t mtu = 0;
	int error = 0;


	if (ro_pmtu != ro) {
		/* The first hop and the final destination may differ. */
		struct sockaddr_in6 *sa6_dst = SIN6(&ro_pmtu->ro_dst);
		if (ROUTE_UNUSABLE(ro_pmtu) ||
		    !IN6_ARE_ADDR_EQUAL(&sa6_dst->sin6_addr, dst)) {
			ROUTE_RELEASE(ro_pmtu);
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

		if (ifp == NULL) {
			ifp = ro_pmtu->ro_rt->rt_ifp;
		}
		/* Access without acquiring nd_ifinfo lock for performance */
		ifmtu = IN6_LINKMTU(ifp);

		/*
		 * Access rmx_mtu without holding the route entry lock,
		 * for performance; this isn't something that changes
		 * often, so optimize.
		 */
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
			if (!(ro_pmtu->ro_rt->rt_rmx.rmx_locks & RTV_MTU)) {
				ro_pmtu->ro_rt->rt_rmx.rmx_mtu = mtu; /* XXX */
			}
		}
	} else {
		if (ifp) {
			/* Don't hold nd_ifinfo lock for performance */
			mtu = IN6_LINKMTU(ifp);
		} else {
			error = EHOSTUNREACH; /* XXX */
		}
	}

	*mtup = mtu;
	return error;
}

/*
 * IP6 socket option processing.
 */
int
ip6_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int optdatalen, uproto;
	void *optdata;
	int privileged;
	struct inpcb *in6p = sotoinpcb(so);
	int error = 0, optval = 0;
	int level, op = -1, optname = 0;
	int optlen = 0;
	struct proc *p;
	lck_mtx_t *mutex_held = NULL;

	VERIFY(sopt != NULL);

	level = sopt->sopt_level;
	op = sopt->sopt_dir;
	optname = sopt->sopt_name;
	optlen = sopt->sopt_valsize;
	p = sopt->sopt_p;
	uproto = (int)SOCK_PROTO(so);

	privileged = (proc_suser(p) == 0);

	if (level == IPPROTO_IPV6) {
		boolean_t capture_exthdrstat_in = FALSE;
		switch (op) {
		case SOPT_SET:
			mutex_held = socket_getlock(so, PR_F_WILLUNLOCK);
			/*
			 * Wait if we are in the middle of ip6_output
			 * as we unlocked the socket there and don't
			 * want to overwrite the IP options
			 */
			if (in6p->inp_sndinprog_cnt > 0) {
				in6p->inp_sndingprog_waiters++;

				while (in6p->inp_sndinprog_cnt > 0) {
					msleep(&in6p->inp_sndinprog_cnt, mutex_held,
					    PSOCK | PCATCH, "inp_sndinprog_cnt",
					    NULL);
				}
				in6p->inp_sndingprog_waiters--;
			}
			switch (optname) {
			case IPV6_2292PKTOPTIONS: {
				struct mbuf *m;

				error = soopt_getm(sopt, &m);
				if (error != 0) {
					break;
				}
				error = soopt_mcopyin(sopt, m);
				if (error != 0) {
					break;
				}
				error = ip6_pcbopts(&in6p->in6p_outputopts,
				    m, so, sopt);
				m_freem(m);
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
				if (!privileged) {
					break;
				}
			/* FALLTHROUGH */
			case IPV6_UNICAST_HOPS:
			case IPV6_HOPLIMIT:
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
				    sizeof(optval), sizeof(optval));
				if (error) {
					break;
				}

				switch (optname) {
				case IPV6_UNICAST_HOPS:
					if (optval < -1 || optval >= 256) {
						error = EINVAL;
					} else {
						/* -1 = kernel default */
						in6p->in6p_hops = optval;
						if (in6p->inp_vflag &
						    INP_IPV4) {
							in6p->inp_ip_ttl =
							    optval;
						}
					}
					break;
#define OPTSET(bit) do {                                                \
	if (optval)                                                     \
	        in6p->inp_flags |= (bit);                               \
	else                                                            \
	        in6p->inp_flags &= ~(bit);                              \
} while (0)

#define OPTSET2292(bit) do {                                            \
	in6p->inp_flags |= IN6P_RFC2292;                                \
	if (optval)                                                     \
	        in6p->inp_flags |= (bit);                               \
	else                                                            \
	        in6p->inp_flags &= ~(bit);                              \
} while (0)

#define OPTBIT(bit) (in6p->inp_flags & (bit) ? 1 : 0)

				case IPV6_RECVPKTINFO:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_PKTINFO);
					break;

				case IPV6_HOPLIMIT: {
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
					capture_exthdrstat_in = TRUE;
					break;

				case IPV6_RECVDSTOPTS:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_DSTOPTS);
					capture_exthdrstat_in = TRUE;
					break;

				case IPV6_RECVRTHDRDSTOPTS:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_RTHDRDSTOPTS);
					capture_exthdrstat_in = TRUE;
					break;

				case IPV6_RECVRTHDR:
					/* cannot mix with RFC2292 */
					if (OPTBIT(IN6P_RFC2292)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_RTHDR);
					capture_exthdrstat_in = TRUE;
					break;

				case IPV6_RECVPATHMTU:
					/*
					 * We ignore this option for TCP
					 * sockets.
					 * (RFC3542 leaves this case
					 * unspecified.)
					 */
					if (uproto != IPPROTO_TCP) {
						OPTSET(IN6P_MTU);
					}
					break;

				case IPV6_V6ONLY:
					/*
					 * make setsockopt(IPV6_V6ONLY)
					 * available only prior to bind(2).
					 * see ipng mailing list, Jun 22 2001.
					 */
					if (in6p->inp_lport ||
					    !IN6_IS_ADDR_UNSPECIFIED(
						    &in6p->in6p_laddr)) {
						error = EINVAL;
						break;
					}
					OPTSET(IN6P_IPV6_V6ONLY);
					if (optval) {
						in6p->inp_vflag &= ~INP_IPV4;
					} else {
						in6p->inp_vflag |= INP_IPV4;
					}
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
			case IPV6_PREFER_TEMPADDR: {
				struct ip6_pktopts **optp;

				if (optlen != sizeof(optval)) {
					error = EINVAL;
					break;
				}
				error = sooptcopyin(sopt, &optval,
				    sizeof(optval), sizeof(optval));
				if (error) {
					break;
				}

				optp = &in6p->in6p_outputopts;
				error = ip6_pcbopt(optname, (u_char *)&optval,
				    sizeof(optval), optp, uproto);

				if (optname == IPV6_TCLASS) {
					// Add in the ECN flags
					u_int8_t tos = (in6p->inp_ip_tos & ~IPTOS_ECN_MASK);
					u_int8_t ecn = optval & IPTOS_ECN_MASK;
					in6p->inp_ip_tos = tos | ecn;
				}
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
				    sizeof(optval), sizeof(optval));
				if (error) {
					break;
				}
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
					if (!privileged) {
						return EPERM;
					}
					OPTSET2292(IN6P_HOPOPTS);
					capture_exthdrstat_in = TRUE;
					break;
				case IPV6_2292DSTOPTS:
					if (!privileged) {
						return EPERM;
					}
					OPTSET2292(IN6P_DSTOPTS |
					    IN6P_RTHDRDSTOPTS); /* XXX */
					capture_exthdrstat_in = TRUE;
					break;
				case IPV6_2292RTHDR:
					OPTSET2292(IN6P_RTHDR);
					capture_exthdrstat_in = TRUE;
					break;
				}
				break;

			case IPV6_3542PKTINFO:
			case IPV6_3542HOPOPTS:
			case IPV6_3542RTHDR:
			case IPV6_3542DSTOPTS:
			case IPV6_RTHDRDSTOPTS:
			case IPV6_3542NEXTHOP: {
				struct ip6_pktopts **optp;
				/* new advanced API (RFC3542) */
				struct mbuf *m;

				/* cannot mix with RFC2292 */
				if (OPTBIT(IN6P_RFC2292)) {
					error = EINVAL;
					break;
				}
				error = soopt_getm(sopt, &m);
				if (error != 0) {
					break;
				}
				error = soopt_mcopyin(sopt, m);
				if (error != 0) {
					break;
				}

				optp = &in6p->in6p_outputopts;
				error = ip6_pcbopt(optname, mtod(m, u_char *),
				    m->m_len, optp, uproto);
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
				    sizeof(optval), sizeof(optval));
				if (error) {
					break;
				}

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
			case IPV6_IPSEC_POLICY: {
				caddr_t req = NULL;
				size_t len = 0;
				struct mbuf *m;

				if ((error = soopt_getm(sopt, &m)) != 0) {
					break;
				}
				if ((error = soopt_mcopyin(sopt, m)) != 0) {
					break;
				}

				req = mtod(m, caddr_t);
				len = m->m_len;
				error = ipsec6_set_policy(in6p, optname, req,
				    len, privileged);
				m_freem(m);
				break;
			}
#endif /* IPSEC */
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
				    sizeof(optval), sizeof(optval));

				if (error) {
					break;
				}

				error = inp_bindif(in6p, optval, NULL);
				break;

			case IPV6_NO_IFT_CELLULAR:
				/* This option is settable only for IPv6 */
				if (!(in6p->inp_vflag & INP_IPV6)) {
					error = EINVAL;
					break;
				}

				error = sooptcopyin(sopt, &optval,
				    sizeof(optval), sizeof(optval));

				if (error) {
					break;
				}

				/* once set, it cannot be unset */
				if (!optval && INP_NO_CELLULAR(in6p)) {
					error = EINVAL;
					break;
				}

				error = so_set_restrictions(so,
				    SO_RESTRICT_DENY_CELLULAR);
				break;

			case IPV6_OUT_IF:
				/* This option is not settable */
				error = EINVAL;
				break;

			default:
				error = ENOPROTOOPT;
				break;
			}
			if (capture_exthdrstat_in) {
				if (uproto == IPPROTO_TCP) {
					INC_ATOMIC_INT64_LIM(net_api_stats.nas_sock_inet6_stream_exthdr_in);
				} else if (uproto == IPPROTO_UDP) {
					INC_ATOMIC_INT64_LIM(net_api_stats.nas_sock_inet6_dgram_exthdr_in);
				}
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

				case IPV6_V6ONLY:
					optval = OPTBIT(IN6P_IPV6_V6ONLY);
					break;

				case IPV6_PORTRANGE: {
					int flags;
					flags = in6p->inp_flags;
					if (flags & INP_HIGHPORT) {
						optval = IPV6_PORTRANGE_HIGH;
					} else if (flags & INP_LOWPORT) {
						optval = IPV6_PORTRANGE_LOW;
					} else {
						optval = 0;
					}
					break;
				}
				case IPV6_RECVTCLASS:
					optval = OPTBIT(IN6P_TCLASS);
					break;

				case IPV6_AUTOFLOWLABEL:
					optval = OPTBIT(IN6P_AUTOFLOWLABEL);
					break;
				}
				if (error) {
					break;
				}
				error = sooptcopyout(sopt, &optval,
				    sizeof(optval));
				break;

			case IPV6_PATHMTU: {
				u_int32_t pmtu = 0;
				struct ip6_mtuinfo mtuinfo;
				struct route_in6 sro;

				bzero(&sro, sizeof(sro));

				if (!(so->so_state & SS_ISCONNECTED)) {
					return ENOTCONN;
				}
				/*
				 * XXX: we dot not consider the case of source
				 * routing, or optional information to specify
				 * the outgoing interface.
				 */
				error = ip6_getpmtu(&sro, NULL, NULL,
				    &in6p->in6p_faddr, &pmtu);
				ROUTE_RELEASE(&sro);
				if (error) {
					break;
				}
				if (pmtu > IPV6_MAXPACKET) {
					pmtu = IPV6_MAXPACKET;
				}

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
					optval = OPTBIT(IN6P_DSTOPTS |
					    IN6P_RTHDRDSTOPTS);
					break;
				}
				error = sooptcopyout(sopt, &optval,
				    sizeof(optval));
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
			case IPV6_IPSEC_POLICY: {
				error = 0; /* This option is no longer supported */
				break;
			}
#endif /* IPSEC */
			case IPV6_BOUND_IF:
				if (in6p->inp_flags & INP_BOUND_IF) {
					optval = in6p->inp_boundifp->if_index;
				}
				error = sooptcopyout(sopt, &optval,
				    sizeof(optval));
				break;

			case IPV6_NO_IFT_CELLULAR:
				optval = INP_NO_CELLULAR(in6p) ? 1 : 0;
				error = sooptcopyout(sopt, &optval,
				    sizeof(optval));
				break;

			case IPV6_OUT_IF:
				optval = (in6p->in6p_last_outifp != NULL) ?
				    in6p->in6p_last_outifp->if_index : 0;
				error = sooptcopyout(sopt, &optval,
				    sizeof(optval));
				break;

			default:
				error = ENOPROTOOPT;
				break;
			}
			break;
		}
	} else if (level == IPPROTO_UDP) {
		error = udp_ctloutput(so, sopt);
	} else {
		error = EINVAL;
	}
	return error;
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
		return EINVAL;
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
			if (error) {
				break;
			}
			if ((optval % 2) != 0) {
				/* the API assumes even offset values */
				error = EINVAL;
			} else if (SOCK_PROTO(so) == IPPROTO_ICMPV6) {
				if (optval != icmp6off) {
					error = EINVAL;
				}
			} else {
				in6p->in6p_cksum = optval;
			}
			break;

		case SOPT_GET:
			if (SOCK_PROTO(so) == IPPROTO_ICMPV6) {
				optval = icmp6off;
			} else {
				optval = in6p->in6p_cksum;
			}

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

	return error;
}

/*
 * Set up IP6 options in pcb for insertion in output packets or
 * specifying behavior of outgoing packets.
 */
static int
ip6_pcbopts(struct ip6_pktopts **pktopt, struct mbuf *m, struct socket *so,
    struct sockopt *sopt)
{
#pragma unused(sopt)
	struct ip6_pktopts *opt = *pktopt;
	int error = 0;

	/* turn off any old options. */
	if (opt != NULL) {
#if DIAGNOSTIC
		if (opt->ip6po_pktinfo || opt->ip6po_nexthop ||
		    opt->ip6po_hbh || opt->ip6po_dest1 || opt->ip6po_dest2 ||
		    opt->ip6po_rhinfo.ip6po_rhi_rthdr) {
			printf("%s: all specified options are cleared.\n",
			    __func__);
		}
#endif
		ip6_clearpktopts(opt, -1);
	} else {
		opt = _MALLOC(sizeof(*opt), M_IP6OPT, M_WAITOK);
		if (opt == NULL) {
			return ENOBUFS;
		}
	}
	*pktopt = NULL;

	if (m == NULL || m->m_len == 0) {
		/*
		 * Only turning off any previous options, regardless of
		 * whether the opt is just created or given.
		 */
		if (opt != NULL) {
			FREE(opt, M_IP6OPT);
		}
		return 0;
	}

	/*  set options specified by user. */
	if ((error = ip6_setpktopts(m, opt, NULL, SOCK_PROTO(so))) != 0) {
		ip6_clearpktopts(opt, -1); /* XXX: discard all options */
		FREE(opt, M_IP6OPT);
		return error;
	}
	*pktopt = opt;
	return 0;
}

/*
 * initialize ip6_pktopts.  beware that there are non-zero default values in
 * the struct.
 */
void
ip6_initpktopts(struct ip6_pktopts *opt)
{
	bzero(opt, sizeof(*opt));
	opt->ip6po_hlim = -1;   /* -1 means default hop limit */
	opt->ip6po_tclass = -1; /* -1 means default traffic class */
	opt->ip6po_minmtu = IP6PO_MINMTU_MCASTONLY;
	opt->ip6po_prefer_tempaddr = IP6PO_TEMPADDR_SYSTEM;
}

static int
ip6_pcbopt(int optname, u_char *buf, int len, struct ip6_pktopts **pktopt,
    int uproto)
{
	struct ip6_pktopts *opt;

	opt = *pktopt;
	if (opt == NULL) {
		opt = _MALLOC(sizeof(*opt), M_IP6OPT, M_WAITOK);
		if (opt == NULL) {
			return ENOBUFS;
		}
		ip6_initpktopts(opt);
		*pktopt = opt;
	}

	return ip6_setpktopt(optname, buf, len, opt, 1, 0, uproto);
}

static int
ip6_getpcbopt(struct ip6_pktopts *pktopt, int optname, struct sockopt *sopt)
{
	void *optdata = NULL;
	int optdatalen = 0;
	struct ip6_ext *ip6e;
	struct in6_pktinfo null_pktinfo;
	int deftclass = 0, on;
	int defminmtu = IP6PO_MINMTU_MCASTONLY;
	int defpreftemp = IP6PO_TEMPADDR_SYSTEM;


	switch (optname) {
	case IPV6_PKTINFO:
		if (pktopt && pktopt->ip6po_pktinfo) {
			optdata = (void *)pktopt->ip6po_pktinfo;
		} else {
			/* XXX: we don't have to do this every time... */
			bzero(&null_pktinfo, sizeof(null_pktinfo));
			optdata = (void *)&null_pktinfo;
		}
		optdatalen = sizeof(struct in6_pktinfo);
		break;

	case IPV6_TCLASS:
		if (pktopt && pktopt->ip6po_tclass >= 0) {
			optdata = (void *)&pktopt->ip6po_tclass;
		} else {
			optdata = (void *)&deftclass;
		}
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
		if (pktopt) {
			optdata = (void *)&pktopt->ip6po_minmtu;
		} else {
			optdata = (void *)&defminmtu;
		}
		optdatalen = sizeof(int);
		break;

	case IPV6_DONTFRAG:
		if (pktopt && ((pktopt->ip6po_flags) & IP6PO_DONTFRAG)) {
			on = 1;
		} else {
			on = 0;
		}
		optdata = (void *)&on;
		optdatalen = sizeof(on);
		break;

	case IPV6_PREFER_TEMPADDR:
		if (pktopt) {
			optdata = (void *)&pktopt->ip6po_prefer_tempaddr;
		} else {
			optdata = (void *)&defpreftemp;
		}
		optdatalen = sizeof(int);
		break;

	default:                /* should not happen */
#ifdef DIAGNOSTIC
		panic("ip6_getpcbopt: unexpected option\n");
#endif
		return ENOPROTOOPT;
	}

	return sooptcopyout(sopt, optdata, optdatalen);
}

void
ip6_clearpktopts(struct ip6_pktopts *pktopt, int optname)
{
	if (pktopt == NULL) {
		return;
	}

	if (optname == -1 || optname == IPV6_PKTINFO) {
		if (pktopt->ip6po_pktinfo) {
			FREE(pktopt->ip6po_pktinfo, M_IP6OPT);
		}
		pktopt->ip6po_pktinfo = NULL;
	}
	if (optname == -1 || optname == IPV6_HOPLIMIT) {
		pktopt->ip6po_hlim = -1;
	}
	if (optname == -1 || optname == IPV6_TCLASS) {
		pktopt->ip6po_tclass = -1;
	}
	if (optname == -1 || optname == IPV6_NEXTHOP) {
		ROUTE_RELEASE(&pktopt->ip6po_nextroute);
		if (pktopt->ip6po_nexthop) {
			FREE(pktopt->ip6po_nexthop, M_IP6OPT);
		}
		pktopt->ip6po_nexthop = NULL;
	}
	if (optname == -1 || optname == IPV6_HOPOPTS) {
		if (pktopt->ip6po_hbh) {
			FREE(pktopt->ip6po_hbh, M_IP6OPT);
		}
		pktopt->ip6po_hbh = NULL;
	}
	if (optname == -1 || optname == IPV6_RTHDRDSTOPTS) {
		if (pktopt->ip6po_dest1) {
			FREE(pktopt->ip6po_dest1, M_IP6OPT);
		}
		pktopt->ip6po_dest1 = NULL;
	}
	if (optname == -1 || optname == IPV6_RTHDR) {
		if (pktopt->ip6po_rhinfo.ip6po_rhi_rthdr) {
			FREE(pktopt->ip6po_rhinfo.ip6po_rhi_rthdr, M_IP6OPT);
		}
		pktopt->ip6po_rhinfo.ip6po_rhi_rthdr = NULL;
		ROUTE_RELEASE(&pktopt->ip6po_route);
	}
	if (optname == -1 || optname == IPV6_DSTOPTS) {
		if (pktopt->ip6po_dest2) {
			FREE(pktopt->ip6po_dest2, M_IP6OPT);
		}
		pktopt->ip6po_dest2 = NULL;
	}
}

#define PKTOPT_EXTHDRCPY(type) do {                                     \
	if (src->type) {                                                \
	        int hlen =                                              \
	            (((struct ip6_ext *)src->type)->ip6e_len + 1) << 3; \
	        dst->type = _MALLOC(hlen, M_IP6OPT, canwait);           \
	        if (dst->type == NULL && canwait == M_NOWAIT)           \
	                goto bad;                                       \
	        bcopy(src->type, dst->type, hlen);                      \
	}                                                               \
} while (0)

static int
copypktopts(struct ip6_pktopts *dst, struct ip6_pktopts *src, int canwait)
{
	if (dst == NULL || src == NULL) {
		printf("copypktopts: invalid argument\n");
		return EINVAL;
	}

	dst->ip6po_hlim = src->ip6po_hlim;
	dst->ip6po_tclass = src->ip6po_tclass;
	dst->ip6po_flags = src->ip6po_flags;
	if (src->ip6po_pktinfo) {
		dst->ip6po_pktinfo = _MALLOC(sizeof(*dst->ip6po_pktinfo),
		    M_IP6OPT, canwait);
		if (dst->ip6po_pktinfo == NULL && canwait == M_NOWAIT) {
			goto bad;
		}
		*dst->ip6po_pktinfo = *src->ip6po_pktinfo;
	}
	if (src->ip6po_nexthop) {
		dst->ip6po_nexthop = _MALLOC(src->ip6po_nexthop->sa_len,
		    M_IP6OPT, canwait);
		if (dst->ip6po_nexthop == NULL && canwait == M_NOWAIT) {
			goto bad;
		}
		bcopy(src->ip6po_nexthop, dst->ip6po_nexthop,
		    src->ip6po_nexthop->sa_len);
	}
	PKTOPT_EXTHDRCPY(ip6po_hbh);
	PKTOPT_EXTHDRCPY(ip6po_dest1);
	PKTOPT_EXTHDRCPY(ip6po_dest2);
	PKTOPT_EXTHDRCPY(ip6po_rthdr); /* not copy the cached route */
	return 0;

bad:
	ip6_clearpktopts(dst, -1);
	return ENOBUFS;
}
#undef PKTOPT_EXTHDRCPY

struct ip6_pktopts *
ip6_copypktopts(struct ip6_pktopts *src, int canwait)
{
	int error;
	struct ip6_pktopts *dst;

	dst = _MALLOC(sizeof(*dst), M_IP6OPT, canwait);
	if (dst == NULL) {
		return NULL;
	}
	ip6_initpktopts(dst);

	if ((error = copypktopts(dst, src, canwait)) != 0) {
		FREE(dst, M_IP6OPT);
		return NULL;
	}

	return dst;
}

void
ip6_freepcbopts(struct ip6_pktopts *pktopt)
{
	if (pktopt == NULL) {
		return;
	}

	ip6_clearpktopts(pktopt, -1);

	FREE(pktopt, M_IP6OPT);
}

void
ip6_moptions_init(void)
{
	PE_parse_boot_argn("ifa_debug", &im6o_debug, sizeof(im6o_debug));

	im6o_size = (im6o_debug == 0) ? sizeof(struct ip6_moptions) :
	    sizeof(struct ip6_moptions_dbg);

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
	if (!locked) {
		IM6O_LOCK(im6o);
	} else {
		IM6O_LOCK_ASSERT_HELD(im6o);
	}

	if (++im6o->im6o_refcnt == 0) {
		panic("%s: im6o %p wraparound refcnt\n", __func__, im6o);
		/* NOTREACHED */
	} else if (im6o->im6o_trace != NULL) {
		(*im6o->im6o_trace)(im6o, TRUE);
	}

	if (!locked) {
		IM6O_UNLOCK(im6o);
	}
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
		if (imf != NULL) {
			im6f_leave(imf);
		}

		(void) in6_mc_leave(im6o->im6o_membership[i], imf);

		if (imf != NULL) {
			im6f_purge(imf);
		}

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

	return im6o;
}

/*
 * Set IPv6 outgoing packet options based on advanced API.
 */
int
ip6_setpktopts(struct mbuf *control, struct ip6_pktopts *opt,
    struct ip6_pktopts *stickyopt, int uproto)
{
	struct cmsghdr *cm = NULL;

	if (control == NULL || opt == NULL) {
		return EINVAL;
	}

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
		if ((error = copypktopts(opt, stickyopt, M_NOWAIT)) != 0) {
			return error;
		}
	}

	/*
	 * XXX: Currently, we assume all the optional information is stored
	 * in a single mbuf.
	 */
	if (control->m_next) {
		return EINVAL;
	}

	if (control->m_len < CMSG_LEN(0)) {
		return EINVAL;
	}

	for (cm = M_FIRST_CMSGHDR(control);
	    is_cmsg_valid(control, cm);
	    cm = M_NXT_CMSGHDR(control, cm)) {
		int error;

		if (cm->cmsg_level != IPPROTO_IPV6) {
			continue;
		}

		error = ip6_setpktopt(cm->cmsg_type, CMSG_DATA(cm),
		    cm->cmsg_len - CMSG_LEN(0), opt, 0, 1, uproto);
		if (error) {
			return error;
		}
	}

	return 0;
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
	boolean_t capture_exthdrstat_out = FALSE;

	if (!sticky && !cmsg) {
#ifdef DIAGNOSTIC
		printf("ip6_setpktopt: impossible case\n");
#endif
		return EINVAL;
	}

	/*
	 * Caller must have ensured that the buffer is at least
	 * aligned on 32-bit boundary.
	 */
	VERIFY(IS_P2ALIGNED(buf, sizeof(u_int32_t)));

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
			return ENOPROTOOPT;
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
			return ENOPROTOOPT;
		}
	}

	switch (optname) {
	case IPV6_2292PKTINFO:
	case IPV6_PKTINFO: {
		struct ifnet *ifp = NULL;
		struct in6_pktinfo *pktinfo;

		if (len != sizeof(struct in6_pktinfo)) {
			return EINVAL;
		}

		pktinfo = (struct in6_pktinfo *)(void *)buf;

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
			return EINVAL;
		}

		/* validate the interface index if specified. */
		ifnet_head_lock_shared();

		if (pktinfo->ipi6_ifindex > if_index) {
			ifnet_head_done();
			return ENXIO;
		}

		if (pktinfo->ipi6_ifindex) {
			ifp = ifindex2ifnet[pktinfo->ipi6_ifindex];
			if (ifp == NULL) {
				ifnet_head_done();
				return ENXIO;
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
			if (opt->ip6po_pktinfo == NULL) {
				return ENOBUFS;
			}
		}
		bcopy(pktinfo, opt->ip6po_pktinfo, sizeof(*pktinfo));
		break;
	}

	case IPV6_2292HOPLIMIT:
	case IPV6_HOPLIMIT: {
		int *hlimp;

		/*
		 * RFC 3542 deprecated the usage of sticky IPV6_HOPLIMIT
		 * to simplify the ordering among hoplimit options.
		 */
		if (optname == IPV6_HOPLIMIT && sticky) {
			return ENOPROTOOPT;
		}

		if (len != sizeof(int)) {
			return EINVAL;
		}
		hlimp = (int *)(void *)buf;
		if (*hlimp < -1 || *hlimp > IPV6_MAXHLIM) {
			return EINVAL;
		}

		opt->ip6po_hlim = *hlimp;
		break;
	}

	case IPV6_TCLASS: {
		int tclass;

		if (len != sizeof(int)) {
			return EINVAL;
		}
		tclass = *(int *)(void *)buf;
		if (tclass < -1 || tclass > 255) {
			return EINVAL;
		}

		opt->ip6po_tclass = tclass;
		break;
	}

	case IPV6_2292NEXTHOP:
	case IPV6_NEXTHOP:
		error = suser(kauth_cred_get(), 0);
		if (error) {
			return EACCES;
		}

		if (len == 0) { /* just remove the option */
			ip6_clearpktopts(opt, IPV6_NEXTHOP);
			break;
		}

		/* check if cmsg_len is large enough for sa_len */
		if (len < sizeof(struct sockaddr) || len < *buf) {
			return EINVAL;
		}

		switch (SA(buf)->sa_family) {
		case AF_INET6: {
			struct sockaddr_in6 *sa6 = SIN6(buf);

			if (sa6->sin6_len != sizeof(struct sockaddr_in6)) {
				return EINVAL;
			}

			if (IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr) ||
			    IN6_IS_ADDR_MULTICAST(&sa6->sin6_addr)) {
				return EINVAL;
			}
			if ((error = sa6_embedscope(sa6, ip6_use_defzone))
			    != 0) {
				return error;
			}
			break;
		}
		case AF_LINK:   /* should eventually be supported */
		default:
			return EAFNOSUPPORT;
		}

		/* turn off the previous option, then set the new option. */
		ip6_clearpktopts(opt, IPV6_NEXTHOP);
		opt->ip6po_nexthop = _MALLOC(*buf, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_nexthop == NULL) {
			return ENOBUFS;
		}
		bcopy(buf, opt->ip6po_nexthop, *buf);
		break;

	case IPV6_2292HOPOPTS:
	case IPV6_HOPOPTS: {
		struct ip6_hbh *hbh;
		int hbhlen;

		/*
		 * XXX: We don't allow a non-privileged user to set ANY HbH
		 * options, since per-option restriction has too much
		 * overhead.
		 */
		error = suser(kauth_cred_get(), 0);
		if (error) {
			return EACCES;
		}

		if (len == 0) {
			ip6_clearpktopts(opt, IPV6_HOPOPTS);
			break;  /* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_hbh)) {
			return EINVAL;
		}
		hbh = (struct ip6_hbh *)(void *)buf;
		hbhlen = (hbh->ip6h_len + 1) << 3;
		if (len != hbhlen) {
			return EINVAL;
		}

		/* turn off the previous option, then set the new option. */
		ip6_clearpktopts(opt, IPV6_HOPOPTS);
		opt->ip6po_hbh = _MALLOC(hbhlen, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_hbh == NULL) {
			return ENOBUFS;
		}
		bcopy(hbh, opt->ip6po_hbh, hbhlen);
		capture_exthdrstat_out = TRUE;
		break;
	}

	case IPV6_2292DSTOPTS:
	case IPV6_DSTOPTS:
	case IPV6_RTHDRDSTOPTS: {
		struct ip6_dest *dest, **newdest = NULL;
		int destlen;

		error = suser(kauth_cred_get(), 0);
		if (error) {
			return EACCES;
		}

		if (len == 0) {
			ip6_clearpktopts(opt, optname);
			break;  /* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_dest)) {
			return EINVAL;
		}
		dest = (struct ip6_dest *)(void *)buf;
		destlen = (dest->ip6d_len + 1) << 3;
		if (len != destlen) {
			return EINVAL;
		}

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
			if (opt->ip6po_rthdr == NULL) {
				newdest = &opt->ip6po_dest1;
			} else {
				newdest = &opt->ip6po_dest2;
			}
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
		if (*newdest == NULL) {
			return ENOBUFS;
		}
		bcopy(dest, *newdest, destlen);
		capture_exthdrstat_out = TRUE;
		break;
	}

	case IPV6_2292RTHDR:
	case IPV6_RTHDR: {
		struct ip6_rthdr *rth;
		int rthlen;

		if (len == 0) {
			ip6_clearpktopts(opt, IPV6_RTHDR);
			break;  /* just remove the option */
		}

		/* message length validation */
		if (len < sizeof(struct ip6_rthdr)) {
			return EINVAL;
		}
		rth = (struct ip6_rthdr *)(void *)buf;
		rthlen = (rth->ip6r_len + 1) << 3;
		if (len != rthlen) {
			return EINVAL;
		}

		switch (rth->ip6r_type) {
		case IPV6_RTHDR_TYPE_0:
			if (rth->ip6r_len == 0) { /* must contain one addr */
				return EINVAL;
			}
			if (rth->ip6r_len % 2) { /* length must be even */
				return EINVAL;
			}
			if (rth->ip6r_len / 2 != rth->ip6r_segleft) {
				return EINVAL;
			}
			break;
		default:
			return EINVAL;        /* not supported */
		}

		/* turn off the previous option */
		ip6_clearpktopts(opt, IPV6_RTHDR);
		opt->ip6po_rthdr = _MALLOC(rthlen, M_IP6OPT, M_NOWAIT);
		if (opt->ip6po_rthdr == NULL) {
			return ENOBUFS;
		}
		bcopy(rth, opt->ip6po_rthdr, rthlen);
		capture_exthdrstat_out = TRUE;
		break;
	}

	case IPV6_USE_MIN_MTU:
		if (len != sizeof(int)) {
			return EINVAL;
		}
		minmtupolicy = *(int *)(void *)buf;
		if (minmtupolicy != IP6PO_MINMTU_MCASTONLY &&
		    minmtupolicy != IP6PO_MINMTU_DISABLE &&
		    minmtupolicy != IP6PO_MINMTU_ALL) {
			return EINVAL;
		}
		opt->ip6po_minmtu = minmtupolicy;
		break;

	case IPV6_DONTFRAG:
		if (len != sizeof(int)) {
			return EINVAL;
		}

		if (uproto == IPPROTO_TCP || *(int *)(void *)buf == 0) {
			/*
			 * we ignore this option for TCP sockets.
			 * (RFC3542 leaves this case unspecified.)
			 */
			opt->ip6po_flags &= ~IP6PO_DONTFRAG;
		} else {
			opt->ip6po_flags |= IP6PO_DONTFRAG;
		}
		break;

	case IPV6_PREFER_TEMPADDR:
		if (len != sizeof(int)) {
			return EINVAL;
		}
		preftemp = *(int *)(void *)buf;
		if (preftemp != IP6PO_TEMPADDR_SYSTEM &&
		    preftemp != IP6PO_TEMPADDR_NOTPREFER &&
		    preftemp != IP6PO_TEMPADDR_PREFER) {
			return EINVAL;
		}
		opt->ip6po_prefer_tempaddr = preftemp;
		break;

	default:
		return ENOPROTOOPT;
	} /* end of switch */

	if (capture_exthdrstat_out) {
		if (uproto == IPPROTO_TCP) {
			INC_ATOMIC_INT64_LIM(net_api_stats.nas_sock_inet6_stream_exthdr_out);
		} else if (uproto == IPPROTO_UDP) {
			INC_ATOMIC_INT64_LIM(net_api_stats.nas_sock_inet6_dgram_exthdr_out);
		}
	}

	return 0;
}

/*
 * Routine called from ip6_output() to loop back a copy of an IP6 multicast
 * packet to the input queue of a specified interface.  Note that this
 * calls the output routine of the loopback "driver", but with an interface
 * pointer that might NOT be &loif -- easier than replicating that code here.
 */
void
ip6_mloopback(struct ifnet *srcifp, struct ifnet *origifp, struct mbuf *m,
    struct sockaddr_in6 *dst, uint32_t optlen, int32_t nxt0)
{
	struct mbuf *copym;
	struct ip6_hdr *ip6;
	struct in6_addr src;

	if (lo_ifp == NULL) {
		return;
	}

	/*
	 * Copy the packet header as it's needed for the checksum.
	 * Make sure to deep-copy IPv6 header portion in case the data
	 * is in an mbuf cluster, so that we can safely override the IPv6
	 * header portion later.
	 */
	copym = m_copym_mode(m, 0, M_COPYALL, M_DONTWAIT, M_COPYM_COPY_HDR);
	if (copym != NULL && ((copym->m_flags & M_EXT) ||
	    copym->m_len < sizeof(struct ip6_hdr))) {
		copym = m_pullup(copym, sizeof(struct ip6_hdr));
	}

	if (copym == NULL) {
		return;
	}

	ip6 = mtod(copym, struct ip6_hdr *);
	src = ip6->ip6_src;
	/*
	 * clear embedded scope identifiers if necessary.
	 * in6_clearscope will touch the addresses only when necessary.
	 */
	in6_clearscope(&ip6->ip6_src);
	in6_clearscope(&ip6->ip6_dst);

	if (copym->m_pkthdr.csum_flags & CSUM_DELAY_IPV6_DATA) {
		in6_delayed_cksum_offset(copym, 0, optlen, nxt0);
	}

	/*
	 * Stuff the 'real' ifp into the pkthdr, to be used in matching
	 * in ip6_input(); we need the loopback ifp/dl_tag passed as args
	 * to make the loopback driver compliant with the data link
	 * requirements.
	 */
	copym->m_pkthdr.rcvif = origifp;

	/*
	 * Also record the source interface (which owns the source address).
	 * This is basically a stripped down version of ifa_foraddr6().
	 */
	if (srcifp == NULL) {
		struct in6_ifaddr *ia;

		lck_rw_lock_shared(&in6_ifaddr_rwlock);
		for (ia = in6_ifaddrs; ia != NULL; ia = ia->ia_next) {
			IFA_LOCK_SPIN(&ia->ia_ifa);
			/* compare against src addr with embedded scope */
			if (IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr, &src)) {
				srcifp = ia->ia_ifp;
				IFA_UNLOCK(&ia->ia_ifa);
				break;
			}
			IFA_UNLOCK(&ia->ia_ifa);
		}
		lck_rw_done(&in6_ifaddr_rwlock);
	}
	if (srcifp != NULL) {
		ip6_setsrcifaddr_info(copym, srcifp->if_index, NULL);
	}
	ip6_setdstifaddr_info(copym, origifp->if_index, NULL);

	dlil_output(lo_ifp, PF_INET6, copym, NULL, SA(dst), 0, NULL);
}

/*
 * Chop IPv6 header off from the payload.
 */
static int
ip6_splithdr(struct mbuf *m, struct ip6_exthdrs *exthdrs)
{
	struct mbuf *mh;
	struct ip6_hdr *ip6;

	ip6 = mtod(m, struct ip6_hdr *);
	if (m->m_len > sizeof(*ip6)) {
		MGETHDR(mh, M_DONTWAIT, MT_HEADER);     /* MAC-OK */
		if (mh == NULL) {
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

static void
ip6_output_checksum(struct ifnet *ifp, uint32_t mtu, struct mbuf *m,
    int nxt0, uint32_t tlen, uint32_t optlen)
{
	uint32_t sw_csum, hwcap = ifp->if_hwassist;
	int tso = TSO_IPV6_OK(ifp, m);

	if (!hwcksum_tx) {
		/* do all in software; checksum offload is disabled */
		sw_csum = CSUM_DELAY_IPV6_DATA & m->m_pkthdr.csum_flags;
	} else {
		/* do in software what the hardware cannot */
		sw_csum = m->m_pkthdr.csum_flags &
		    ~IF_HWASSIST_CSUM_FLAGS(hwcap);
	}

	if (optlen != 0) {
		sw_csum |= (CSUM_DELAY_IPV6_DATA &
		    m->m_pkthdr.csum_flags);
	} else if (!(sw_csum & CSUM_DELAY_IPV6_DATA) &&
	    (hwcap & CSUM_PARTIAL)) {
		/*
		 * Partial checksum offload, ere), if no extension headers,
		 * and TCP only (no UDP support, as the hardware may not be
		 * able to convert +0 to -0 (0xffff) per RFC1122 4.1.3.4.
		 * unless the interface supports "invert zero" capability.)
		 */
		if (hwcksum_tx && !tso &&
		    ((m->m_pkthdr.csum_flags & CSUM_TCPIPV6) ||
		    ((hwcap & CSUM_ZERO_INVERT) &&
		    (m->m_pkthdr.csum_flags & CSUM_ZERO_INVERT))) &&
		    tlen <= mtu) {
			uint16_t start = sizeof(struct ip6_hdr);
			uint16_t ulpoff =
			    m->m_pkthdr.csum_data & 0xffff;
			m->m_pkthdr.csum_flags |=
			    (CSUM_DATA_VALID | CSUM_PARTIAL);
			m->m_pkthdr.csum_tx_stuff = (ulpoff + start);
			m->m_pkthdr.csum_tx_start = start;
			sw_csum = 0;
		} else {
			sw_csum |= (CSUM_DELAY_IPV6_DATA &
			    m->m_pkthdr.csum_flags);
		}
	}

	if (sw_csum & CSUM_DELAY_IPV6_DATA) {
		in6_delayed_cksum_offset(m, 0, optlen, nxt0);
		sw_csum &= ~CSUM_DELAY_IPV6_DATA;
	}

	if (hwcksum_tx) {
		/*
		 * Drop off bits that aren't supported by hardware;
		 * also make sure to preserve non-checksum related bits.
		 */
		m->m_pkthdr.csum_flags =
		    ((m->m_pkthdr.csum_flags &
		    (IF_HWASSIST_CSUM_FLAGS(hwcap) | CSUM_DATA_VALID)) |
		    (m->m_pkthdr.csum_flags & ~IF_HWASSIST_CSUM_MASK));
	} else {
		/* drop all bits; checksum offload is disabled */
		m->m_pkthdr.csum_flags = 0;
	}
}

/*
 * Compute IPv6 extension header length.
 */
int
ip6_optlen(struct in6pcb *in6p)
{
	int len;

	if (!in6p->in6p_outputopts) {
		return 0;
	}

	len = 0;
#define elen(x)                                                         \
	(((struct ip6_ext *)(x)) ?                                      \
	(((struct ip6_ext *)(x))->ip6e_len + 1) << 3 : 0)

	len += elen(in6p->in6p_outputopts->ip6po_hbh);
	if (in6p->in6p_outputopts->ip6po_rthdr) {
		/* dest1 is valid with rthdr only */
		len += elen(in6p->in6p_outputopts->ip6po_dest1);
	}
	len += elen(in6p->in6p_outputopts->ip6po_rthdr);
	len += elen(in6p->in6p_outputopts->ip6po_dest2);
	return len;
#undef elen
}

static int
sysctl_reset_ip6_output_stats SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, i;

	i = ip6_output_measure;
	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || req->newptr == USER_ADDR_NULL) {
		goto done;
	}
	/* impose bounds */
	if (i < 0 || i > 1) {
		error = EINVAL;
		goto done;
	}
	if (ip6_output_measure != i && i == 1) {
		net_perf_initialize(&net_perf, ip6_output_measure_bins);
	}
	ip6_output_measure = i;
done:
	return error;
}

static int
sysctl_ip6_output_measure_bins SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	uint64_t i;

	i = ip6_output_measure_bins;
	error = sysctl_handle_quad(oidp, &i, 0, req);
	if (error || req->newptr == USER_ADDR_NULL) {
		goto done;
	}
	/* validate data */
	if (!net_perf_validate_bins(i)) {
		error = EINVAL;
		goto done;
	}
	ip6_output_measure_bins = i;
done:
	return error;
}

static int
sysctl_ip6_output_getperf SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldlen = (size_t)sizeof(struct ipstat);
	}

	return SYSCTL_OUT(req, &net_perf, MIN(sizeof(net_perf), req->oldlen));
}
