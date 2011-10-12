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
 * $FreeBSD: src/sys/netinet/ip_output.c,v 1.99.2.16 2001/07/19 06:37:26 kris Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#define _IP_VHL

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <kern/locks.h>
#include <sys/sysctl.h>
#include <sys/mcache.h>

#include <machine/endian.h>
#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/ntstat.h>
#include <net/net_osdep.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>

#include <netinet/kpi_ipfilter_var.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#include "faith.h"

#include <net/dlil.h>
#include <sys/kdebug.h>
#include <libkern/OSAtomic.h>

#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETIP, 1)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETIP, 3)
#define DBG_FNC_IP_OUTPUT	NETDBG_CODE(DBG_NETIP, (1 << 8) | 1)
#define DBG_FNC_IPSEC4_OUTPUT	NETDBG_CODE(DBG_NETIP, (2 << 8) | 1)

#define	SWAP16(v) ((((v) & 0xff) << 8) | ((v) >> 8))

#if IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#if IPSEC_DEBUG
#include <netkey/key_debug.h>
#else
#define	KEYDEBUG(lev,arg)
#endif
#endif /*IPSEC*/

#include <netinet/ip_fw.h>
#include <netinet/ip_divert.h>
#include <mach/sdt.h>

#if DUMMYNET
#include <netinet/ip_dummynet.h>
#endif

#if PF
#include <net/pfvar.h>
#endif /* PF */

#if IPFIREWALL_FORWARD_DEBUG
#define print_ip(a)	 printf("%ld.%ld.%ld.%ld",(ntohl(a.s_addr)>>24)&0xFF,\
				 		  (ntohl(a.s_addr)>>16)&0xFF,\
						  (ntohl(a.s_addr)>>8)&0xFF,\
						  (ntohl(a.s_addr))&0xFF);
#endif


u_short ip_id;

static struct mbuf *ip_insertoptions(struct mbuf *, struct mbuf *, int *);
static void	ip_mloopback(struct ifnet *, struct mbuf *,
	struct sockaddr_in *, int);
static int	ip_pcbopts(int, struct mbuf **, struct mbuf *);
static void	imo_trace(struct ip_moptions *, int);

static void ip_out_cksum_stats(int, u_int32_t);
static struct ifaddr *in_selectsrcif(struct ip *, struct route *, unsigned int);

int	ip_optcopy(struct ip *, struct ip *);
void in_delayed_cksum_offset(struct mbuf *, int );
void in_cksum_offset(struct mbuf* , size_t );

extern int (*fr_checkp)(struct ip *, int, struct ifnet *, int, struct mbuf **);

extern	struct protosw inetsw[];

extern struct ip_linklocal_stat ip_linklocal_stat;
extern lck_mtx_t *ip_mutex;

/* temporary: for testing */
#if IPSEC
extern int ipsec_bypass;
#endif

static int	ip_maxchainsent = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, maxchainsent, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip_maxchainsent, 0, "use dlil_output_list");
#if DEBUG
static int forge_ce = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, forge_ce, CTLFLAG_RW | CTLFLAG_LOCKED,
    &forge_ce, 0, "Forge ECN CE");
#endif /* DEBUG */

static int ip_select_srcif_debug = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, select_srcif_debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip_select_srcif_debug, 0, "log source interface selection debug info");

#define	IMO_TRACE_HIST_SIZE	32	/* size of trace history */

/* For gdb */
__private_extern__ unsigned int imo_trace_hist_size = IMO_TRACE_HIST_SIZE;

struct ip_moptions_dbg {
	struct ip_moptions	imo;			/* ip_moptions */
	u_int16_t		imo_refhold_cnt;	/* # of IMO_ADDREF */
	u_int16_t		imo_refrele_cnt;	/* # of IMO_REMREF */
	/*
	 * Alloc and free callers.
	 */
	ctrace_t		imo_alloc;
	ctrace_t		imo_free;
	/*
	 * Circular lists of IMO_ADDREF and IMO_REMREF callers.
	 */
	ctrace_t		imo_refhold[IMO_TRACE_HIST_SIZE];
	ctrace_t		imo_refrele[IMO_TRACE_HIST_SIZE];
};

#if DEBUG
static unsigned int imo_debug = 1;	/* debugging (enabled) */
#else
static unsigned int imo_debug;		/* debugging (disabled) */
#endif /* !DEBUG */
static unsigned int imo_size;		/* size of zone element */
static struct zone *imo_zone;		/* zone for ip_moptions */

#define	IMO_ZONE_MAX		64		/* maximum elements in zone */
#define	IMO_ZONE_NAME		"ip_moptions"	/* zone name */

/*
 * IP output.  The packet in mbuf chain m contains a skeletal IP
 * header (with len, off, ttl, proto, tos, src, dst).
 * The mbuf chain containing the packet will be freed.
 * The mbuf opt, if present, will not be freed.
 */
int
ip_output(
	struct mbuf *m0,
	struct mbuf *opt,
	struct route *ro,
	int flags,
	struct ip_moptions *imo,
	struct ip_out_args *ipoa)
{
	int error;
	error = ip_output_list(m0, 0, opt, ro, flags, imo, ipoa);
	return error;
}

/*
 * Returns:	0			Success
 *		ENOMEM
 *		EADDRNOTAVAIL
 *		ENETUNREACH
 *		EHOSTUNREACH
 *		EACCES
 *		EMSGSIZE
 *		ENOBUFS
 *	ipsec4_getpolicybyaddr:???	[IPSEC 4th argument, contents modified]
 *	ipsec4_getpolicybysock:???	[IPSEC 4th argument, contents modified]
 *	key_spdacquire:???		[IPSEC]
 *	ipsec4_output:???		[IPSEC]
 *	<fr_checkp>:???			[firewall]
 *	ip_dn_io_ptr:???		[dummynet]
 *	dlil_output:???			[DLIL]
 *	dlil_output_list:???		[DLIL]
 *
 * Notes:	The ipsec4_getpolicyby{addr|sock} function error returns are
 *		only used as the error return from this function where one of
 *		these functions fails to return a policy.
 */
int
ip_output_list(
	struct mbuf *m0,
	int packetchain,
	struct mbuf *opt,
	struct route *ro,
	int flags,
	struct ip_moptions *imo,
	struct ip_out_args *ipoa
	)
{
	struct ip *ip;
	struct ifnet *ifp = NULL;
	struct mbuf *m = m0, **mppn = NULL;
	int hlen = sizeof (struct ip);
	int len = 0, error = 0;
	struct sockaddr_in *dst = NULL;
	struct in_ifaddr *ia = NULL, *src_ia = NULL;
	int isbroadcast, sw_csum;
	struct in_addr pkt_dst;
	struct ipf_pktopts *ippo = NULL, ipf_pktopts;
#if IPSEC
	struct ipsec_output_state ipsec_state;
	struct route *ipsec_saved_route = NULL;
	struct socket *so = NULL;
	struct secpolicy *sp = NULL;
#endif
#if IPFIREWALL_FORWARD
	int fwd_rewrite_src = 0;
#endif
#if IPFIREWALL
	int off;
	struct ip_fw_args args;
	struct m_tag	*tag;
	struct sockaddr_in *next_hop_from_ipfwd_tag = NULL;
#endif
	int didfilter = 0;
	ipfilter_t inject_filter_ref = 0;
#if DUMMYNET
	struct route	saved_route;
	struct ip_out_args saved_ipoa;
	struct sockaddr_in dst_buf;
#endif /* DUMMYNET */
	struct mbuf * packetlist;
	int pktcnt = 0, tso = 0;
	u_int32_t	bytecnt = 0;
	unsigned int ifscope;
	unsigned int nocell;
	boolean_t select_srcif;
	KERNEL_DEBUG(DBG_FNC_IP_OUTPUT | DBG_FUNC_START, 0,0,0,0,0);

#if IPSEC
	bzero(&ipsec_state, sizeof(ipsec_state));
#endif /* IPSEC */

	packetlist = m0;
#if IPFIREWALL
	args.next_hop = NULL;
	args.eh = NULL;
	args.rule = NULL;
	args.divert_rule = 0;			/* divert cookie */
	args.ipoa = NULL;

	if (SLIST_EMPTY(&m0->m_pkthdr.tags))
		goto ipfw_tags_done;

	/* Grab info from mtags prepended to the chain */
#if DUMMYNET
	if ((tag = m_tag_locate(m0, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_DUMMYNET, NULL)) != NULL) {
		struct dn_pkt_tag	*dn_tag;

		dn_tag = (struct dn_pkt_tag *)(tag+1);
		args.rule = dn_tag->rule;
		opt = NULL;
		saved_route = dn_tag->ro;
		ro = &saved_route;

		imo = NULL;
		bcopy(&dn_tag->dn_dst, &dst_buf, sizeof(dst_buf));
		dst = &dst_buf;
		ifp = dn_tag->ifp;
		flags = dn_tag->flags;
		saved_ipoa = dn_tag->ipoa;
		ipoa = &saved_ipoa;

		m_tag_delete(m0, tag);
	}
#endif /* DUMMYNET */

#if IPDIVERT
	if ((tag = m_tag_locate(m0, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_DIVERT, NULL)) != NULL) {
		struct divert_tag	*div_tag;

		div_tag = (struct divert_tag *)(tag+1);
		args.divert_rule = div_tag->cookie;

		m_tag_delete(m0, tag);
	}
#endif /* IPDIVERT */

	if ((tag = m_tag_locate(m0, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_IPFORWARD, NULL)) != NULL) {
		struct ip_fwd_tag	*ipfwd_tag;

		ipfwd_tag = (struct ip_fwd_tag *)(tag+1);
		next_hop_from_ipfwd_tag = ipfwd_tag->next_hop;
		
		m_tag_delete(m0, tag);
	}
ipfw_tags_done:
#endif /* IPFIREWALL */

	m = m0;

#if	DIAGNOSTIC
	if ( !m || (m->m_flags & M_PKTHDR) != 0)
		panic("ip_output no HDR");
	if (!ro)
		panic("ip_output no route, proto = %d",
		      mtod(m, struct ip *)->ip_p);
#endif

	bzero(&ipf_pktopts, sizeof(struct ipf_pktopts));
	ippo = &ipf_pktopts;

	/*
	 * At present the IP_OUTARGS flag implies a request for IP to
	 * perform source interface selection.  In the forwarding case,
	 * only the ifscope value is used, as source interface selection
	 * doesn't take place.
	 */
	if (ip_doscopedroute && (flags & IP_OUTARGS)) {
		select_srcif = !(flags & IP_FORWARDING);
		ifscope = ipoa->ipoa_boundif;
		ipf_pktopts.ippo_flags = IPPOF_BOUND_IF;
		ipf_pktopts.ippo_flags |= (ifscope << IPPOF_SHIFT_IFSCOPE);
	} else {
		select_srcif = FALSE;
		ifscope = IFSCOPE_NONE;
	}

	if (flags & IP_OUTARGS) {
		nocell = ipoa->ipoa_nocell;
		if (nocell)
			ipf_pktopts.ippo_flags |= IPPOF_NO_IFT_CELLULAR;
	} else {
		nocell = 0;
	}

#if IPFIREWALL
	if (args.rule != NULL) {	/* dummynet already saw us */
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2 ;
		if (ro->ro_rt != NULL) {
			RT_LOCK_SPIN(ro->ro_rt);
			ia = (struct in_ifaddr *)ro->ro_rt->rt_ifa;
			if (ia) {
				/* Become a regular mutex */
				RT_CONVERT_LOCK(ro->ro_rt);
				IFA_ADDREF(&ia->ia_ifa);
			}
			RT_UNLOCK(ro->ro_rt);
		}
#if IPSEC
		if (ipsec_bypass == 0 && (flags & IP_NOIPSEC) == 0) {
			so = ipsec_getsocket(m);
			(void)ipsec_setsocket(m, NULL);
		}
#endif
		goto sendit;
	}
#endif /* IPFIREWALL */

#if IPSEC
	if (ipsec_bypass == 0 && (flags & IP_NOIPSEC) == 0) {
		so = ipsec_getsocket(m);
		(void)ipsec_setsocket(m, NULL);
	}
#endif
loopit:	
	/*
	 * No need to proccess packet twice if we've 
	 * already seen it
	 */
	if (!SLIST_EMPTY(&m->m_pkthdr.tags))
		inject_filter_ref = ipf_get_inject_filter(m);
	else
		inject_filter_ref = 0;

	if (opt) {
		m = ip_insertoptions(m, opt, &len);
		hlen = len;
	}
	ip = mtod(m, struct ip *);
#if IPFIREWALL
	/*
	 * rdar://8542331
	 *
	 * When dealing with a packet chain, we need to reset "next_hop" because 
	 * "dst" may have been changed to the gateway address below for the previous
	 * packet of the chain. This could cause the route to be inavertandly changed 
	 * to the route to the gateway address (instead of the route to the destination).
	 */
	args.next_hop = next_hop_from_ipfwd_tag;
	pkt_dst = args.next_hop ? args.next_hop->sin_addr : ip->ip_dst;
#else
	pkt_dst = ip->ip_dst;
#endif

	/*
	 * We must not send if the packet is destined to network zero.
	 * RFC1122 3.2.1.3 (a) and (b).
	 */
	if (IN_ZERONET(ntohl(pkt_dst.s_addr))) {
		error = EHOSTUNREACH;
		goto bad;
	}

	/*
	 * Fill in IP header.
	 */
	if ((flags & (IP_FORWARDING|IP_RAWOUTPUT)) == 0) {
		ip->ip_vhl = IP_MAKE_VHL(IPVERSION, hlen >> 2);
		ip->ip_off &= IP_DF;
#if RANDOM_IP_ID
		ip->ip_id = ip_randomid();
#else
		ip->ip_id = htons(ip_id++);
#endif
		OSAddAtomic(1, &ipstat.ips_localout);
	} else {
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	}
	
#if DEBUG
	/* For debugging, we let the stack forge congestion */
	if (forge_ce != 0 &&
		((ip->ip_tos & IPTOS_ECN_MASK) == IPTOS_ECN_ECT1 ||
		 (ip->ip_tos & IPTOS_ECN_MASK) == IPTOS_ECN_ECT0)) {
		ip->ip_tos = (ip->ip_tos & ~IPTOS_ECN_MASK) | IPTOS_ECN_CE;
		forge_ce--;
	}
#endif /* DEBUG */

	KERNEL_DEBUG(DBG_LAYER_BEG, ip->ip_dst.s_addr, 
		     ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);
	
	dst = (struct sockaddr_in *)&ro->ro_dst;

	/*
	 * If there is a cached route,
	 * check that it is to the same destination
	 * and is still up.  If not, free it and try again.
	 * The address family should also be checked in case of sharing the
	 * cache with IPv6.
	 */

	if (ro->ro_rt != NULL) {
		if (ro->ro_rt->generation_id != route_generation &&
		    ((flags & (IP_ROUTETOIF | IP_FORWARDING)) == 0) &&
		    (ip->ip_src.s_addr != INADDR_ANY)) {
			src_ia = ifa_foraddr(ip->ip_src.s_addr);
			if (src_ia == NULL) {
				error = EADDRNOTAVAIL;
				goto bad;
			}
			IFA_REMREF(&src_ia->ia_ifa);
		}
		/*
		 * Test rt_flags without holding rt_lock for performance
		 * reasons; if the route is down it will hopefully be
		 * caught by the layer below (since it uses this route
		 * as a hint) or during the next transmit.
		 */
		if ((ro->ro_rt->rt_flags & RTF_UP) == 0 ||
		    dst->sin_family != AF_INET ||
		    dst->sin_addr.s_addr != pkt_dst.s_addr) {
			rtfree(ro->ro_rt);
			ro->ro_rt = NULL;
		}
		/*
		 * If we're doing source interface selection, we may not
		 * want to use this route; only synch up the generation
		 * count otherwise.
		 */
		if (!select_srcif && ro->ro_rt != NULL &&
		    ro->ro_rt->generation_id != route_generation)
			ro->ro_rt->generation_id = route_generation;
	}
	if (ro->ro_rt == NULL) {
		bzero(dst, sizeof(*dst));
		dst->sin_family = AF_INET;
		dst->sin_len = sizeof(*dst);
		dst->sin_addr = pkt_dst;
	}
	/*
	 * If routing to interface only,
	 * short circuit routing lookup.
	 */
#define ifatoia(ifa)	((struct in_ifaddr *)(ifa))
#define sintosa(sin)	((struct sockaddr *)(sin))
	if (flags & IP_ROUTETOIF) {
		if (ia)
			IFA_REMREF(&ia->ia_ifa);
		if ((ia = ifatoia(ifa_ifwithdstaddr(sintosa(dst)))) == 0) {
			if ((ia = ifatoia(ifa_ifwithnet(sintosa(dst)))) == 0) {
				OSAddAtomic(1, &ipstat.ips_noroute);
				error = ENETUNREACH;
				goto bad;
			}
		}
		ifp = ia->ia_ifp;
		ip->ip_ttl = 1;
		isbroadcast = in_broadcast(dst->sin_addr, ifp);
	} else if (IN_MULTICAST(ntohl(pkt_dst.s_addr)) &&
	    imo != NULL && (ifp = imo->imo_multicast_ifp) != NULL) {
		/*
		 * Bypass the normal routing lookup for multicast
		 * packets if the interface is specified.
		 */
		isbroadcast = 0;
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);

		/* Macro takes reference on ia */
		IFP_TO_IA(ifp, ia);
	} else {
		boolean_t cloneok = FALSE;
		/*
		 * Perform source interface selection; the source IP address
		 * must belong to one of the addresses of the interface used
		 * by the route.  For performance reasons, do this only if
		 * there is no route, or if the routing table has changed,
		 * or if we haven't done source interface selection on this
		 * route (for this PCB instance) before.
		 */
		if (select_srcif && ip->ip_src.s_addr != INADDR_ANY &&
		    (ro->ro_rt == NULL || !(ro->ro_rt->rt_flags & RTF_UP) ||
		    ro->ro_rt->generation_id != route_generation ||
		    !(ro->ro_flags & ROF_SRCIF_SELECTED))) {
			struct ifaddr *ifa;

			/* Find the source interface */
			ifa = in_selectsrcif(ip, ro, ifscope);

			/*
			 * If the source address belongs to a cellular interface
			 * and the caller forbids our using interfaces of such
			 * type, pretend that there is no source address.
			 */
			if (nocell && ifa != NULL &&
			    ifa->ifa_ifp->if_type == IFT_CELLULAR) {
				IFA_REMREF(ifa);
				error = EADDRNOTAVAIL;
				goto bad;
			}

			/*
			 * If the source address is spoofed (in the case
			 * of IP_RAWOUTPUT), or if this is destined for
			 * local/loopback, just let it go out using the
			 * interface of the route.  Otherwise, there's no
			 * interface having such an address, so bail out.
			 */
			if (ifa == NULL && !(flags & IP_RAWOUTPUT) &&
			    ifscope != lo_ifp->if_index) {
				error = EADDRNOTAVAIL;
				goto bad;
			}

			/*
			 * If the caller didn't explicitly specify the scope,
			 * pick it up from the source interface.  If the cached
			 * route was wrong and was blown away as part of source
			 * interface selection, don't mask out RTF_PRCLONING
			 * since that route may have been allocated by the ULP,
			 * unless the IP header was created by the caller or
			 * the destination is IPv4 LLA.  The check for the
			 * latter is needed because IPv4 LLAs are never scoped
			 * in the current implementation, and we don't want to
			 * replace the resolved IPv4 LLA route with one whose
			 * gateway points to that of the default gateway on
			 * the primary interface of the system.
			 */
			if (ifa != NULL) {
				if (ifscope == IFSCOPE_NONE)
					ifscope = ifa->ifa_ifp->if_index;
				IFA_REMREF(ifa);
				cloneok = (!(flags & IP_RAWOUTPUT) &&
				    !(IN_LINKLOCAL(ntohl(ip->ip_dst.s_addr))));
			}
		}

		/*
		 * If this is the case, we probably don't want to allocate
		 * a protocol-cloned route since we didn't get one from the
		 * ULP.  This lets TCP do its thing, while not burdening
		 * forwarding or ICMP with the overhead of cloning a route.
		 * Of course, we still want to do any cloning requested by
		 * the link layer, as this is probably required in all cases
		 * for correct operation (as it is for ARP).
		 */
		if (ro->ro_rt == NULL) {
			unsigned long ign = RTF_PRCLONING;
			/*
			 * We make an exception here: if the destination
			 * address is INADDR_BROADCAST, allocate a protocol-
			 * cloned host route so that we end up with a route
			 * marked with the RTF_BROADCAST flag.  Otherwise,
			 * we would end up referring to the default route,
			 * instead of creating a cloned host route entry.
			 * That would introduce inconsistencies between ULPs
			 * that allocate a route and those that don't.  The
			 * RTF_BROADCAST route is important since we'd want
			 * to send out undirected IP broadcast packets using
			 * link-level broadcast address. Another exception
			 * is for ULP-created routes that got blown away by
			 * source interface selection (see above).
			 *
			 * These exceptions will no longer be necessary when
			 * the RTF_PRCLONING scheme is no longer present.
			 */
			if (cloneok || dst->sin_addr.s_addr == INADDR_BROADCAST)
				ign &= ~RTF_PRCLONING;

			/*
			 * Loosen the route lookup criteria if the ifscope
			 * corresponds to the loopback interface; this is
			 * needed to support Application Layer Gateways
			 * listening on loopback, in conjunction with packet
			 * filter redirection rules.  The final source IP
			 * address will be rewritten by the packet filter
			 * prior to the RFC1122 loopback check below.
			 */
			if (ifscope == lo_ifp->if_index)
				rtalloc_ign(ro, ign);
			else
				rtalloc_scoped_ign(ro, ign, ifscope);

			/*
			 * If the route points to a cellular interface and the
			 * caller forbids our using interfaces of such type,
			 * pretend that there is no route.
			 */
			if (nocell && ro->ro_rt != NULL) {
				RT_LOCK_SPIN(ro->ro_rt);
				if (ro->ro_rt->rt_ifp->if_type ==
				    IFT_CELLULAR) {
					RT_UNLOCK(ro->ro_rt);
					rtfree(ro->ro_rt);
					ro->ro_rt = NULL;
				} else {
					RT_UNLOCK(ro->ro_rt);
				}
			}
		}

		if (ro->ro_rt == NULL) {
			OSAddAtomic(1, &ipstat.ips_noroute);
			error = EHOSTUNREACH;
			goto bad;
		}

		if (ia)
			IFA_REMREF(&ia->ia_ifa);
		RT_LOCK_SPIN(ro->ro_rt);
		ia = ifatoia(ro->ro_rt->rt_ifa);
		if (ia) {
			/* Become a regular mutex */
			RT_CONVERT_LOCK(ro->ro_rt);
			IFA_ADDREF(&ia->ia_ifa);
		}
		ifp = ro->ro_rt->rt_ifp;
		ro->ro_rt->rt_use++;
		if (ro->ro_rt->rt_flags & RTF_GATEWAY)
			dst = (struct sockaddr_in *)ro->ro_rt->rt_gateway;
		if (ro->ro_rt->rt_flags & RTF_HOST) {
			isbroadcast = (ro->ro_rt->rt_flags & RTF_BROADCAST);
		} else {
			/* Become a regular mutex */
			RT_CONVERT_LOCK(ro->ro_rt);
			isbroadcast = in_broadcast(dst->sin_addr, ifp);
		}
		RT_UNLOCK(ro->ro_rt);
	}

	if (IN_MULTICAST(ntohl(pkt_dst.s_addr))) {
		struct in_multi *inm;
		u_int32_t vif;
		u_int8_t ttl = IP_DEFAULT_MULTICAST_TTL;
		u_int8_t loop = IP_DEFAULT_MULTICAST_LOOP;

		m->m_flags |= M_MCAST;
		/*
		 * IP destination address is multicast.  Make sure "dst"
		 * still points to the address in "ro".  (It may have been
		 * changed to point to a gateway address, above.)
		 */
		dst = (struct sockaddr_in *)&ro->ro_dst;
		/*
		 * See if the caller provided any multicast options
		 */
		if (imo != NULL) {
			IMO_LOCK(imo);
			vif = imo->imo_multicast_vif;
			ttl = imo->imo_multicast_ttl;
			loop = imo->imo_multicast_loop;
			if ((flags & IP_RAWOUTPUT) == 0)
				ip->ip_ttl = ttl;
			if (imo->imo_multicast_ifp != NULL)
				ifp = imo->imo_multicast_ifp;
			IMO_UNLOCK(imo);
#if MROUTING
			if (vif != -1 && ((flags & IP_RAWOUTPUT) == 0 ||
			    ip->ip_src.s_addr == INADDR_ANY))
				ip->ip_src.s_addr = ip_mcast_src(vif);
#endif /* MROUTING */
		} else if ((flags & IP_RAWOUTPUT) == 0) {
			vif = -1;
			ip->ip_ttl = ttl;
		}
		/*
		 * Confirm that the outgoing interface supports multicast.
		 */
		if (imo == NULL || vif == -1) {
			if ((ifp->if_flags & IFF_MULTICAST) == 0) {
				OSAddAtomic(1, &ipstat.ips_noroute);
				error = ENETUNREACH;
				goto bad;
			}
		}
		/*
		 * If source address not specified yet, use address
		 * of outgoing interface.
		 */
		if (ip->ip_src.s_addr == INADDR_ANY) {
			struct in_ifaddr *ia1;
			lck_rw_lock_shared(in_ifaddr_rwlock);
			TAILQ_FOREACH(ia1, &in_ifaddrhead, ia_link) {
				IFA_LOCK_SPIN(&ia1->ia_ifa);
				if (ia1->ia_ifp == ifp) {
					ip->ip_src = IA_SIN(ia1)->sin_addr;
					IFA_UNLOCK(&ia1->ia_ifa);
					break;
				}
				IFA_UNLOCK(&ia1->ia_ifa);
			}
			lck_rw_done(in_ifaddr_rwlock);
			if (ip->ip_src.s_addr == INADDR_ANY) {
				error = ENETUNREACH;
				goto bad;
			}
		}

		in_multihead_lock_shared();
		IN_LOOKUP_MULTI(&pkt_dst, ifp, inm);
		in_multihead_lock_done();
		if (inm != NULL && (imo == NULL || loop)) {
			/*
			 * If we belong to the destination multicast group
			 * on the outgoing interface, and the caller did not
			 * forbid loopback, loop back a copy.
			 */
			if (!TAILQ_EMPTY(&ipv4_filters)) {
				struct ipfilter	*filter;
				int seen = (inject_filter_ref == 0);

				if (imo != NULL) {
					ipf_pktopts.ippo_flags |= IPPOF_MCAST_OPTS;
					ipf_pktopts.ippo_mcast_ifnet = ifp;
					ipf_pktopts.ippo_mcast_ttl = ttl;
					ipf_pktopts.ippo_mcast_loop = loop;
				}

				ipf_ref();

				/* 4135317 - always pass network byte order to filter */

#if BYTE_ORDER != BIG_ENDIAN
				HTONS(ip->ip_len);
				HTONS(ip->ip_off);
#endif

				TAILQ_FOREACH(filter, &ipv4_filters, ipf_link) {
					if (seen == 0) {
						if ((struct ipfilter *)inject_filter_ref == filter)
							seen = 1;
					} else if (filter->ipf_filter.ipf_output) {
						errno_t result;
						result = filter->ipf_filter.ipf_output(filter->ipf_filter.cookie, (mbuf_t*)&m, ippo);
						if (result == EJUSTRETURN) {
							ipf_unref();
							INM_REMREF(inm);
							goto done;
						}
						if (result != 0) {
							ipf_unref();
							INM_REMREF(inm);
							goto bad;
						}
					}
				}

				/* set back to host byte order */
				ip = mtod(m, struct ip *);

#if BYTE_ORDER != BIG_ENDIAN
				NTOHS(ip->ip_len);
				NTOHS(ip->ip_off);
#endif

				ipf_unref();
				didfilter = 1;
			}
			ip_mloopback(ifp, m, dst, hlen);
		}
#if MROUTING
		else {
			/*
			 * If we are acting as a multicast router, perform
			 * multicast forwarding as if the packet had just
			 * arrived on the interface to which we are about
			 * to send.  The multicast forwarding function
			 * recursively calls this function, using the
			 * IP_FORWARDING flag to prevent infinite recursion.
			 *
			 * Multicasts that are looped back by ip_mloopback(),
			 * above, will be forwarded by the ip_input() routine,
			 * if necessary.
			 */
			if (ip_mrouter && (flags & IP_FORWARDING) == 0) {
				/*
				 * Check if rsvp daemon is running. If not, don't
				 * set ip_moptions. This ensures that the packet
				 * is multicast and not just sent down one link
				 * as prescribed by rsvpd.
				 */
				if (!rsvp_on)
					imo = NULL;
				if (ip_mforward(ip, ifp, m, imo) != 0) {
					m_freem(m);
					if (inm != NULL)
						INM_REMREF(inm);
					goto done;
				}
			}
		}
#endif /* MROUTING */
		if (inm != NULL)
			INM_REMREF(inm);
		/*
		 * Multicasts with a time-to-live of zero may be looped-
		 * back, above, but must not be transmitted on a network.
		 * Also, multicasts addressed to the loopback interface
		 * are not sent -- the above call to ip_mloopback() will
		 * loop back a copy if this host actually belongs to the
		 * destination group on the loopback interface.
		 */
		if (ip->ip_ttl == 0 || ifp->if_flags & IFF_LOOPBACK) {
			m_freem(m);
			goto done;
		}

		goto sendit;
	}
#ifndef notdef
	/*
	 * If source address not specified yet, use address
	 * of outgoing interface.
	 */
	if (ip->ip_src.s_addr == INADDR_ANY) {
		IFA_LOCK_SPIN(&ia->ia_ifa);
		ip->ip_src = IA_SIN(ia)->sin_addr;
		IFA_UNLOCK(&ia->ia_ifa);
#if IPFIREWALL_FORWARD
		/* Keep note that we did this - if the firewall changes
		 * the next-hop, our interface may change, changing the
		 * default source IP. It's a shame so much effort happens
		 * twice. Oh well. 
		 */
		fwd_rewrite_src++;
#endif /* IPFIREWALL_FORWARD */
	}
#endif /* notdef */

	/*
	 * Look for broadcast address and
	 * and verify user is allowed to send
	 * such a packet.
	 */
	if (isbroadcast) {
		if ((ifp->if_flags & IFF_BROADCAST) == 0) {
			error = EADDRNOTAVAIL;
			goto bad;
		}
		if ((flags & IP_ALLOWBROADCAST) == 0) {
			error = EACCES;
			goto bad;
		}
		/* don't allow broadcast messages to be fragmented */
		if ((u_short)ip->ip_len > ifp->if_mtu) {
			error = EMSGSIZE;
			goto bad;
		}
		m->m_flags |= M_BCAST;
	} else {
		m->m_flags &= ~M_BCAST;
	}

sendit:
#if PF
	/* Invoke outbound packet filter */
	if ( PF_IS_ENABLED) {
		int rc;
		rc = pf_af_hook(ifp, mppn, &m, AF_INET, FALSE);
		if (rc != 0) {
			if (packetlist == m0) {
				packetlist = m;
				mppn = NULL;
			}
			if (m != NULL) {
				m0 = m;
				/* Next packet in the chain */
				goto loopit;
			} else if (packetlist != NULL) {
				/* No more packet; send down the chain */
				goto sendchain;
			}
			/* Nothing left; we're done */
			goto done;
		}
		m0 = m;
		ip = mtod(m, struct ip *);
		pkt_dst = ip->ip_dst;
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	}
#endif /* PF */
        /*
         * Force IP TTL to 255 following draft-ietf-zeroconf-ipv4-linklocal.txt
         */
        if (IN_LINKLOCAL(ntohl(ip->ip_src.s_addr)) || IN_LINKLOCAL(ntohl(ip->ip_dst.s_addr))) {
		ip_linklocal_stat.iplls_out_total++;
		if (ip->ip_ttl != MAXTTL) {
			ip_linklocal_stat.iplls_out_badttl++;
                	ip->ip_ttl = MAXTTL;
		}
        }

	if (!didfilter && !TAILQ_EMPTY(&ipv4_filters)) {
		struct ipfilter	*filter;
		int seen = (inject_filter_ref == 0);
		ipf_pktopts.ippo_flags &= ~IPPOF_MCAST_OPTS;

		/* Check that a TSO frame isn't passed to a filter.
		 * This could happen if a filter is inserted while
		 * TCP is sending the TSO packet.
		 */
		if (m->m_pkthdr.csum_flags & CSUM_TSO_IPV4) {
			error = EMSGSIZE;
			goto bad;
		}

		ipf_ref();
		
		/* 4135317 - always pass network byte order to filter */

#if BYTE_ORDER != BIG_ENDIAN
		HTONS(ip->ip_len);
		HTONS(ip->ip_off);
#endif

		TAILQ_FOREACH(filter, &ipv4_filters, ipf_link) {
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
		
		/* set back to host byte order */
		ip = mtod(m, struct ip *);

#if BYTE_ORDER != BIG_ENDIAN
		NTOHS(ip->ip_len);
		NTOHS(ip->ip_off);
#endif

		ipf_unref();
	}

#if IPSEC
	/* temporary for testing only: bypass ipsec alltogether */

	if (ipsec_bypass != 0 || (flags & IP_NOIPSEC) != 0)
		goto skip_ipsec;

	KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_START, 0,0,0,0,0);


	/* get SP for this packet */
	if (so == NULL)
		sp = ipsec4_getpolicybyaddr(m, IPSEC_DIR_OUTBOUND, flags, &error);
	else
		sp = ipsec4_getpolicybysock(m, IPSEC_DIR_OUTBOUND, so, &error);

	if (sp == NULL) {
		IPSEC_STAT_INCREMENT(ipsecstat.out_inval);		
		KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
		goto bad;
	}

	error = 0;

	/* check policy */
	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
	case IPSEC_POLICY_GENERATE:
		/*
		 * This packet is just discarded.
		 */
		IPSEC_STAT_INCREMENT(ipsecstat.out_polvio);
		KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_END, 1,0,0,0,0);
		goto bad;

	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_NONE:
		/* no need to do IPsec. */
		KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_END, 2,0,0,0,0);
		goto skip_ipsec;
	
	case IPSEC_POLICY_IPSEC:
		if (sp->req == NULL) {
			/* acquire a policy */
			error = key_spdacquire(sp);
			KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_END, 3,0,0,0,0);
			goto bad;
		}
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		printf("ip_output: Invalid policy found. %d\n", sp->policy);
	}
    {
	ipsec_state.m = m;
	if (flags & IP_ROUTETOIF) {
		bzero(&ipsec_state.ro, sizeof(ipsec_state.ro));
	} else
		route_copyout(&ipsec_state.ro, ro, sizeof(ipsec_state.ro));
	ipsec_state.dst = (struct sockaddr *)dst;

	ip->ip_sum = 0;

	/*
	 * XXX
	 * delayed checksums are not currently compatible with IPsec
	 */
	if (m->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
		in_delayed_cksum(m);
		m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
	}


#if BYTE_ORDER != BIG_ENDIAN
	HTONS(ip->ip_len);
	HTONS(ip->ip_off);
#endif

	DTRACE_IP6(send, struct mbuf *, m, struct inpcb *, NULL,
		struct ip *, ip, struct ifnet *, ifp,
		struct ip *, ip, struct ip6_hdr *, NULL);

	error = ipsec4_output(&ipsec_state, sp, flags);
    
	m0 = m = ipsec_state.m;
	
	if (flags & IP_ROUTETOIF) {
		/*
		 * if we have tunnel mode SA, we may need to ignore
		 * IP_ROUTETOIF.
		 */
		if (ipsec_state.tunneled) {
			flags &= ~IP_ROUTETOIF;
			ipsec_saved_route = ro;
			ro = &ipsec_state.ro;
		}
	} else {
		ipsec_saved_route = ro;
		ro = &ipsec_state.ro;
	}
	dst = (struct sockaddr_in *)ipsec_state.dst;
	if (error) {
		/* mbuf is already reclaimed in ipsec4_output. */
		m0 = NULL;
		switch (error) {
		case EHOSTUNREACH:
		case ENETUNREACH:
		case EMSGSIZE:
		case ENOBUFS:
		case ENOMEM:
			break;
		default:
			printf("ip4_output (ipsec): error code %d\n", error);
			/*fall through*/
		case ENOENT:
			/* don't show these error codes to the user */
			error = 0;
			break;
		}
		KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_END, 4,0,0,0,0);
		goto bad;
	}
    }

	/* be sure to update variables that are affected by ipsec4_output() */
	ip = mtod(m, struct ip *);
	
#ifdef _IP_VHL
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif
	/* Check that there wasn't a route change and src is still valid */
	if (ro->ro_rt != NULL && ro->ro_rt->generation_id != route_generation) {
		if ((src_ia = ifa_foraddr(ip->ip_src.s_addr)) == NULL &&
		    ((flags & (IP_ROUTETOIF | IP_FORWARDING)) == 0)) {
			error = EADDRNOTAVAIL;
			KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_END,
			    5,0,0,0,0);
			goto bad;
		}
		rtfree(ro->ro_rt);
		ro->ro_rt = NULL;
		if (src_ia != NULL)
			IFA_REMREF(&src_ia->ia_ifa);
	}

	if (ro->ro_rt == NULL) {
		if ((flags & IP_ROUTETOIF) == 0) {
			printf("ip_output: can't update route after "
			    "IPsec processing\n");
			error = EHOSTUNREACH;	/*XXX*/
			KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_END,
			    6,0,0,0,0);
			goto bad;
		}
	} else {
		if (ia)
			IFA_REMREF(&ia->ia_ifa);
		RT_LOCK_SPIN(ro->ro_rt);
		ia = ifatoia(ro->ro_rt->rt_ifa);
		if (ia) {
			/* Become a regular mutex */
			RT_CONVERT_LOCK(ro->ro_rt);
			IFA_ADDREF(&ia->ia_ifa);
		}
		ifp = ro->ro_rt->rt_ifp;
		RT_UNLOCK(ro->ro_rt);
	}

	/* make it flipped, again. */

#if BYTE_ORDER != BIG_ENDIAN
	NTOHS(ip->ip_len);
	NTOHS(ip->ip_off);
#endif
	
	KERNEL_DEBUG(DBG_FNC_IPSEC4_OUTPUT | DBG_FUNC_END, 7,0xff,0xff,0xff,0xff);
	
	/* Pass to filters again */
	if (!TAILQ_EMPTY(&ipv4_filters)) {
		struct ipfilter	*filter;
		
		ipf_pktopts.ippo_flags &= ~IPPOF_MCAST_OPTS;

		/* Check that a TSO frame isn't passed to a filter.
		 * This could happen if a filter is inserted while
		 * TCP is sending the TSO packet.
		 */
		if (m->m_pkthdr.csum_flags & CSUM_TSO_IPV4) {
			error = EMSGSIZE;
			goto bad;
		}

		ipf_ref();
		
		/* 4135317 - always pass network byte order to filter */

#if BYTE_ORDER != BIG_ENDIAN
		HTONS(ip->ip_len);
		HTONS(ip->ip_off);
#endif

		TAILQ_FOREACH(filter, &ipv4_filters, ipf_link) {
			if (filter->ipf_filter.ipf_output) {
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
		
		/* set back to host byte order */
		ip = mtod(m, struct ip *);

#if BYTE_ORDER != BIG_ENDIAN
		NTOHS(ip->ip_len);
		NTOHS(ip->ip_off);
#endif

		ipf_unref();
	}
skip_ipsec:
#endif /*IPSEC*/

#if IPFIREWALL
	/*
	 * IpHack's section.
	 * - Xlate: translate packet's addr/port (NAT).
	 * - Firewall: deny/allow/etc.
	 * - Wrap: fake packet's addr/port <unimpl.>
	 * - Encapsulate: put it in another IP and send out. <unimp.>
	 */ 
	if (fr_checkp) {
		struct  mbuf    *m1 = m;

		if ((error = (*fr_checkp)(ip, hlen, ifp, 1, &m1)) || !m1) {
			goto done;
		}
		ip = mtod(m0 = m = m1, struct ip *);
	}

	/*
	 * Check with the firewall...
	 * but not if we are already being fwd'd from a firewall.
	 */
	if (fw_enable && IPFW_LOADED && !args.next_hop) {
		struct sockaddr_in *old = dst;

		args.m = m;
		args.next_hop = dst;
		args.oif = ifp;
		off = ip_fw_chk_ptr(&args);
		m = args.m;
		dst = args.next_hop;

                /*
                 * On return we must do the following:
                 * IP_FW_PORT_DENY_FLAG		-> drop the pkt (XXX new)
                 * 1<=off<= 0xffff   -> DIVERT
                 * (off & IP_FW_PORT_DYNT_FLAG)	-> send to a DUMMYNET pipe
                 * (off & IP_FW_PORT_TEE_FLAG)	-> TEE the packet
                 * dst != old        -> IPFIREWALL_FORWARD
                 * off==0, dst==old  -> accept
                 * If some of the above modules is not compiled in, then
                 * we should't have to check the corresponding condition
                 * (because the ipfw control socket should not accept
                 * unsupported rules), but better play safe and drop
                 * packets in case of doubt.
                 */
		m0 = m;
		if ( (off & IP_FW_PORT_DENY_FLAG) || m == NULL) {
			if (m)
				m_freem(m);
			error = EACCES ;
			goto done ;
		}
		ip = mtod(m, struct ip *);
		
		if (off == 0 && dst == old) {/* common case */
			goto pass ;
		}
#if DUMMYNET
                if (DUMMYNET_LOADED && (off & IP_FW_PORT_DYNT_FLAG) != 0) {
			/*
			 * pass the pkt to dummynet. Need to include
			 * pipe number, m, ifp, ro, dst because these are
			 * not recomputed in the next pass.
			 * All other parameters have been already used and
			 * so they are not needed anymore.
			 * XXX note: if the ifp or ro entry are deleted
			 * while a pkt is in dummynet, we are in trouble!
			 */
			args.ro = ro;
			args.dst = dst;
			args.flags = flags;
			if (flags & IP_OUTARGS)
				args.ipoa = ipoa;

			error = ip_dn_io_ptr(m, off & 0xffff, DN_TO_IP_OUT,
			    &args);
			goto done;
		}
#endif /* DUMMYNET */
#if IPDIVERT
		if (off != 0 && (off & IP_FW_PORT_DYNT_FLAG) == 0) {
			struct mbuf *clone = NULL;

			/* Clone packet if we're doing a 'tee' */
			if ((off & IP_FW_PORT_TEE_FLAG) != 0)
				clone = m_dup(m, M_DONTWAIT);
			/*
			 * XXX
			 * delayed checksums are not currently compatible
			 * with divert sockets.
			 */
			if (m->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
				in_delayed_cksum(m);
				m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
			}

			/* Restore packet header fields to original values */

#if BYTE_ORDER != BIG_ENDIAN
			HTONS(ip->ip_len);
			HTONS(ip->ip_off);
#endif

			/* Deliver packet to divert input routine */
			divert_packet(m, 0, off & 0xffff, args.divert_rule);

			/* If 'tee', continue with original packet */
			if (clone != NULL) {
				m0 = m = clone;
				ip = mtod(m, struct ip *);
				goto pass;
			}
			goto done;
		}
#endif

#if IPFIREWALL_FORWARD
		/* Here we check dst to make sure it's directly reachable on the
		 * interface we previously thought it was.
		 * If it isn't (which may be likely in some situations) we have
		 * to re-route it (ie, find a route for the next-hop and the
		 * associated interface) and set them here. This is nested
		 * forwarding which in most cases is undesirable, except where
		 * such control is nigh impossible. So we do it here.
		 * And I'm babbling.
		 */
		if (off == 0 && old != dst) {
			struct in_ifaddr *ia_fw;

			/* It's changed... */
			/* There must be a better way to do this next line... */
			static struct route sro_fwd, *ro_fwd = &sro_fwd;
#if IPFIREWALL_FORWARD_DEBUG
			printf("IPFIREWALL_FORWARD: New dst ip: ");
			print_ip(dst->sin_addr);
			printf("\n");
#endif
			/*
			 * We need to figure out if we have been forwarded
			 * to a local socket. If so then we should somehow 
			 * "loop back" to ip_input, and get directed to the
			 * PCB as if we had received this packet. This is
			 * because it may be dificult to identify the packets
			 * you want to forward until they are being output
			 * and have selected an interface. (e.g. locally
			 * initiated packets) If we used the loopback inteface,
			 * we would not be able to control what happens 
			 * as the packet runs through ip_input() as
			 * it is done through a ISR.
			 */
			lck_rw_lock_shared(in_ifaddr_rwlock);
			TAILQ_FOREACH(ia_fw, &in_ifaddrhead, ia_link) {
				/*
				 * If the addr to forward to is one
				 * of ours, we pretend to
				 * be the destination for this packet.
				 */
				IFA_LOCK_SPIN(&ia_fw->ia_ifa);
				if (IA_SIN(ia_fw)->sin_addr.s_addr ==
				    dst->sin_addr.s_addr) {
					IFA_UNLOCK(&ia_fw->ia_ifa);
					break;
				}
				IFA_UNLOCK(&ia_fw->ia_ifa);
			}
			lck_rw_done(in_ifaddr_rwlock);
			if (ia_fw) {
				/* tell ip_input "dont filter" */
				struct m_tag 		*fwd_tag;
				struct ip_fwd_tag	*ipfwd_tag;

				fwd_tag = m_tag_create(KERNEL_MODULE_TAG_ID,
				    KERNEL_TAG_TYPE_IPFORWARD,
				    sizeof (*ipfwd_tag), M_NOWAIT, m);
				if (fwd_tag == NULL) {
					error = ENOBUFS;
					goto bad;
				}

				ipfwd_tag = (struct ip_fwd_tag *)(fwd_tag+1);
				ipfwd_tag->next_hop = args.next_hop;

				m_tag_prepend(m, fwd_tag);

				if (m->m_pkthdr.rcvif == NULL)
					m->m_pkthdr.rcvif = lo_ifp;
				if ((~IF_HWASSIST_CSUM_FLAGS(m->m_pkthdr.rcvif->if_hwassist) & 
						m->m_pkthdr.csum_flags) == 0) {
					if (m->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
						m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
						m->m_pkthdr.csum_flags |=
							CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
						m->m_pkthdr.csum_data = 0xffff;
					}
					m->m_pkthdr.csum_flags |=
						CSUM_IP_CHECKED | CSUM_IP_VALID;
				}
				else if (m->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
					in_delayed_cksum(m);
					m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
					ip->ip_sum = in_cksum(m, hlen);
				}

#if BYTE_ORDER != BIG_ENDIAN
				HTONS(ip->ip_len);
				HTONS(ip->ip_off);
#endif				
				
				/*  we need to call dlil_output to run filters
				 *	and resync to avoid recursion loops.
				 */
				if (lo_ifp) {
					dlil_output(lo_ifp, PF_INET, m, 0, (struct sockaddr *)dst, 0);
				}
				else {
					printf("ip_output: no loopback ifp for forwarding!!!\n");
				}
				goto done;
			}
			/* Some of the logic for this was
			 * nicked from above.
			 *
			 * This rewrites the cached route in a local PCB.
			 * Is this what we want to do?
			 */
			bcopy(dst, &ro_fwd->ro_dst, sizeof(*dst));

			ro_fwd->ro_rt = NULL;
			rtalloc_ign(ro_fwd, RTF_PRCLONING);

			if (ro_fwd->ro_rt == NULL) {
				OSAddAtomic(1, &ipstat.ips_noroute);
				error = EHOSTUNREACH;
				goto bad;
			}

			RT_LOCK_SPIN(ro_fwd->ro_rt);
			ia_fw = ifatoia(ro_fwd->ro_rt->rt_ifa);
			if (ia_fw != NULL) {
				/* Become a regular mutex */
				RT_CONVERT_LOCK(ro_fwd->ro_rt);
				IFA_ADDREF(&ia_fw->ia_ifa);
			}
			ifp = ro_fwd->ro_rt->rt_ifp;
			ro_fwd->ro_rt->rt_use++;
			if (ro_fwd->ro_rt->rt_flags & RTF_GATEWAY)
				dst = (struct sockaddr_in *)ro_fwd->ro_rt->rt_gateway;
			if (ro_fwd->ro_rt->rt_flags & RTF_HOST) {
				isbroadcast =
				    (ro_fwd->ro_rt->rt_flags & RTF_BROADCAST);
			} else {
				/* Become a regular mutex */
				RT_CONVERT_LOCK(ro_fwd->ro_rt);
				isbroadcast = in_broadcast(dst->sin_addr, ifp);
			}
			RT_UNLOCK(ro_fwd->ro_rt);
			rtfree(ro->ro_rt);
			ro->ro_rt = ro_fwd->ro_rt;
			dst = (struct sockaddr_in *)&ro_fwd->ro_dst;

			/*
			 * If we added a default src ip earlier,
			 * which would have been gotten from the-then
			 * interface, do it again, from the new one.
			 */
			if (ia_fw != NULL) {
				if (fwd_rewrite_src) {
					IFA_LOCK_SPIN(&ia_fw->ia_ifa);
					ip->ip_src = IA_SIN(ia_fw)->sin_addr;
					IFA_UNLOCK(&ia_fw->ia_ifa);
				}
				IFA_REMREF(&ia_fw->ia_ifa);
			}
			goto pass ;
		}
#endif /* IPFIREWALL_FORWARD */
                /*
                 * if we get here, none of the above matches, and 
                 * we have to drop the pkt
                 */
		m_freem(m);
		error = EACCES; /* not sure this is the right error msg */
		goto done;
	}

pass:
#endif /* IPFIREWALL */
#if __APPLE__
	/* Do not allow loopback address to wind up on a wire */
	if ((ifp->if_flags & IFF_LOOPBACK) == 0 &&
		 ((ntohl(ip->ip_src.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
		  (ntohl(ip->ip_dst.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET)) {
		OSAddAtomic(1, &ipstat.ips_badaddr);
		m_freem(m);
		/* 
		 * Do not simply drop the packet just like a firewall -- we want the 
		 * the application to feel the pain.
		 * Return ENETUNREACH like ip6_output does in some similar cases. 
		 * This can startle the otherwise clueless process that specifies
		 * loopback as the source address.
		 */
		error = ENETUNREACH;
		goto done;
	}
#endif
	m->m_pkthdr.csum_flags |= CSUM_IP;
	tso =  (ifp->if_hwassist & IFNET_TSO_IPV4) && (m->m_pkthdr.csum_flags & CSUM_TSO_IPV4);
		     
	sw_csum = m->m_pkthdr.csum_flags 
		& ~IF_HWASSIST_CSUM_FLAGS(ifp->if_hwassist);

	if ((ifp->if_hwassist & CSUM_TCP_SUM16) != 0) {
		/*
		 * Special case code for GMACE
		 * frames that can be checksumed by GMACE SUM16 HW:
		 * frame >64, no fragments, no UDP
		 */
		if (apple_hwcksum_tx && (m->m_pkthdr.csum_flags & CSUM_TCP)
			&& (ip->ip_len > 50) && (ip->ip_len <= ifp->if_mtu)) {
			/* Apple GMAC HW, expects STUFF_OFFSET << 16  | START_OFFSET */
			u_short offset = (IP_VHL_HL(ip->ip_vhl) << 2) +14 ; /* IP+Enet header length */
			u_short csumprev= m->m_pkthdr.csum_data & 0xFFFF;
	       		m->m_pkthdr.csum_flags = CSUM_DATA_VALID | CSUM_TCP_SUM16; /* for GMAC */
			m->m_pkthdr.csum_data = (csumprev + offset)  << 16 ;
			m->m_pkthdr.csum_data += offset; 
       		sw_csum = CSUM_DELAY_IP; /* do IP hdr chksum in software */
		}
		else {
			/* let the software handle any UDP or TCP checksums */
			sw_csum |= (CSUM_DELAY_DATA & m->m_pkthdr.csum_flags);
		}
	} else if (apple_hwcksum_tx == 0) {
		sw_csum |= (CSUM_DELAY_DATA | CSUM_DELAY_IP) &
		    m->m_pkthdr.csum_flags;
	}
	
	if (sw_csum & CSUM_DELAY_DATA) {
		in_delayed_cksum(m);
		sw_csum &= ~CSUM_DELAY_DATA;
		m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
	}

	if (apple_hwcksum_tx != 0) {
		m->m_pkthdr.csum_flags &=
		    IF_HWASSIST_CSUM_FLAGS(ifp->if_hwassist);
	} else {
		m->m_pkthdr.csum_flags = 0;
	}

	/*
	 * If small enough for interface, or the interface will take
	 * care of the fragmentation for us, can just send directly.
	 */
	if ((u_short)ip->ip_len <= ifp->if_mtu || tso ||
	    ifp->if_hwassist & CSUM_FRAGMENT) {
		if (tso) 
			m->m_pkthdr.csum_flags |= CSUM_TSO_IPV4;
			

#if BYTE_ORDER != BIG_ENDIAN
		HTONS(ip->ip_len);
		HTONS(ip->ip_off);
#endif
		
		ip->ip_sum = 0;
		if (sw_csum & CSUM_DELAY_IP) {
			ip->ip_sum = in_cksum(m, hlen);
		}
		
#ifndef __APPLE__
		/* Record statistics for this interface address. */
		if (!(flags & IP_FORWARDING) && ia != NULL) {
			ia->ia_ifa.if_opackets++;
			ia->ia_ifa.if_obytes += m->m_pkthdr.len;
		}
#endif

#if IPSEC
		/* clean ipsec history once it goes out of the node */
		if (ipsec_bypass == 0 && (flags & IP_NOIPSEC) == 0)
			ipsec_delaux(m);
#endif
		if (packetchain == 0) {
			if (ro->ro_rt && nstat_collect)
				nstat_route_tx(ro->ro_rt, 1, m->m_pkthdr.len, 0);
			error = ifnet_output(ifp, PF_INET, m, ro->ro_rt,
			    (struct sockaddr *)dst);
			goto done;
		}
		else { /* packet chaining allows us to reuse the route for all packets */
			bytecnt += m->m_pkthdr.len;
			mppn = &m->m_nextpkt;
			m = m->m_nextpkt;
			if (m == NULL) {
#if PF
sendchain:
#endif /* PF */
				if (pktcnt > ip_maxchainsent)
					ip_maxchainsent = pktcnt;
				if (ro->ro_rt && nstat_collect)
					nstat_route_tx(ro->ro_rt, pktcnt, bytecnt, 0);
				//send
				error = ifnet_output(ifp, PF_INET, packetlist,
				    ro->ro_rt, (struct sockaddr *)dst);
				pktcnt = 0;
				bytecnt = 0;
				goto done;
	
			}
			m0 = m;
			pktcnt++;
			goto loopit;
		}
	}
	/*
	 * Too large for interface; fragment if possible.
	 * Must be able to put at least 8 bytes per fragment.
	 */

	if (ip->ip_off & IP_DF  || (m->m_pkthdr.csum_flags & CSUM_TSO_IPV4) ||
		pktcnt > 0) {
		error = EMSGSIZE;
		/*
		 * This case can happen if the user changed the MTU
		 * of an interface after enabling IP on it.  Because
		 * most netifs don't keep track of routes pointing to
		 * them, there is no way for one to update all its
		 * routes when the MTU is changed.
		 */
		if (ro->ro_rt) {
			RT_LOCK_SPIN(ro->ro_rt);
			if ((ro->ro_rt->rt_flags & (RTF_UP | RTF_HOST))
			    && !(ro->ro_rt->rt_rmx.rmx_locks & RTV_MTU)
			    && (ro->ro_rt->rt_rmx.rmx_mtu > ifp->if_mtu)) {
				ro->ro_rt->rt_rmx.rmx_mtu = ifp->if_mtu;
			}
			RT_UNLOCK(ro->ro_rt);
		}
		if (pktcnt > 0) {
			m0 = packetlist;
		}
		OSAddAtomic(1, &ipstat.ips_cantfrag);
		goto bad;
	}

	error = ip_fragment(m, ifp, ifp->if_mtu, sw_csum);
	if (error != 0) {
		m0 = m = NULL;
		goto bad;
	}

	KERNEL_DEBUG(DBG_LAYER_END, ip->ip_dst.s_addr, 
		     ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);

	for (m = m0; m; m = m0) {
		m0 = m->m_nextpkt;
		m->m_nextpkt = 0;
#if IPSEC
		/* clean ipsec history once it goes out of the node */
		if (ipsec_bypass == 0 && (flags & IP_NOIPSEC) == 0)
			ipsec_delaux(m);
#endif
		if (error == 0) {
#ifndef __APPLE__
			/* Record statistics for this interface address. */
			if (ia != NULL) {
				ia->ia_ifa.if_opackets++;
				ia->ia_ifa.if_obytes += m->m_pkthdr.len;
			}
#endif
			if ((packetchain != 0)  && (pktcnt > 0))
				panic("ip_output: mix of packet in packetlist is wrong=%p", packetlist);
			if (ro->ro_rt && nstat_collect)
				nstat_route_tx(ro->ro_rt, 1, m->m_pkthdr.len, 0);
			error = ifnet_output(ifp, PF_INET, m, ro->ro_rt,
			    (struct sockaddr *)dst);
		} else
			m_freem(m);
	}

	if (error == 0)
		OSAddAtomic(1, &ipstat.ips_fragmented);

done:
	if (ia) {
		IFA_REMREF(&ia->ia_ifa);
		ia = NULL;
	}
#if IPSEC
	if (ipsec_bypass == 0 && (flags & IP_NOIPSEC) == 0) {
		if (ipsec_state.ro.ro_rt)
			rtfree(ipsec_state.ro.ro_rt);
	if (sp != NULL) {
		KEYDEBUG(KEYDEBUG_IPSEC_STAMP,
			printf("DP ip_output call free SP:%x\n", sp));
		key_freesp(sp, KEY_SADB_UNLOCKED);
	}
	}
#endif /* IPSEC */

	KERNEL_DEBUG(DBG_FNC_IP_OUTPUT | DBG_FUNC_END, error,0,0,0,0);
	return (error);
bad:
	m_freem(m0);
	goto done;
}

int
ip_fragment(struct mbuf *m, struct ifnet *ifp, unsigned long mtu, int sw_csum)
{
	struct ip *ip, *mhip;
	int len, hlen, mhlen, firstlen, off, error = 0;
	struct mbuf **mnext = &m->m_nextpkt, *m0;
	int nfrags = 1;

	ip = mtod(m, struct ip *);
#ifdef _IP_VHL
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif

	firstlen = len = (mtu - hlen) &~ 7;
	if (len < 8) {
		m_freem(m);
		return (EMSGSIZE);
	}

	/*
	 * if the interface will not calculate checksums on
	 * fragmented packets, then do it here.
	 */
	if (m->m_pkthdr.csum_flags & CSUM_DELAY_DATA &&
	    (ifp->if_hwassist & CSUM_IP_FRAGS) == 0) {
		in_delayed_cksum(m);
		m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
	}

	/*
	 * Loop through length of segment after first fragment,
	 * make new header and copy data of each part and link onto chain.
	 */
	m0 = m;
	mhlen = sizeof (struct ip);
	for (off = hlen + len; off < (u_short)ip->ip_len; off += len) {
		MGETHDR(m, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
		if (m == 0) {
			error = ENOBUFS;
			OSAddAtomic(1, &ipstat.ips_odropped);
			goto sendorfree;
		}
		m->m_flags |= (m0->m_flags & M_MCAST) | M_FRAG;
		m->m_data += max_linkhdr;
		mhip = mtod(m, struct ip *);
		*mhip = *ip;
		if (hlen > sizeof (struct ip)) {
			mhlen = ip_optcopy(ip, mhip) + sizeof (struct ip);
			mhip->ip_vhl = IP_MAKE_VHL(IPVERSION, mhlen >> 2);
		}
		m->m_len = mhlen;
		mhip->ip_off = ((off - hlen) >> 3) + (ip->ip_off & ~IP_MF);
		if (ip->ip_off & IP_MF)
			mhip->ip_off |= IP_MF;
		if (off + len >= (u_short)ip->ip_len)
			len = (u_short)ip->ip_len - off;
		else
			mhip->ip_off |= IP_MF;
		mhip->ip_len = htons((u_short)(len + mhlen));
		m->m_next = m_copy(m0, off, len);
		if (m->m_next == 0) {
			(void) m_free(m);
			error = ENOBUFS;	/* ??? */
			OSAddAtomic(1, &ipstat.ips_odropped);
			goto sendorfree;
		}
		m->m_pkthdr.len = mhlen + len;
		m->m_pkthdr.rcvif = 0;
		m->m_pkthdr.csum_flags = m0->m_pkthdr.csum_flags;
		m->m_pkthdr.socket_id = m0->m_pkthdr.socket_id;
#if CONFIG_MACF_NET
		mac_netinet_fragment(m0, m);
#endif

#if BYTE_ORDER != BIG_ENDIAN
		HTONS(mhip->ip_off);
#endif

		mhip->ip_sum = 0;
		if (sw_csum & CSUM_DELAY_IP) {
			mhip->ip_sum = in_cksum(m, mhlen);
		}
		*mnext = m;
		mnext = &m->m_nextpkt;
		nfrags++;
	}
	OSAddAtomic(nfrags, &ipstat.ips_ofragments);

	/* set first/last markers for fragment chain */
	m->m_flags |= M_LASTFRAG;
	m0->m_flags |= M_FIRSTFRAG | M_FRAG;
	m0->m_pkthdr.csum_data = nfrags;

	/*
	 * Update first fragment by trimming what's been copied out
	 * and updating header, then send each fragment (in order).
	 */
	m = m0;
	m_adj(m, hlen + firstlen - (u_short)ip->ip_len);
	m->m_pkthdr.len = hlen + firstlen;
	ip->ip_len = htons((u_short)m->m_pkthdr.len);
	ip->ip_off |= IP_MF;

#if BYTE_ORDER != BIG_ENDIAN
	HTONS(ip->ip_off);
#endif
	
	ip->ip_sum = 0;
	if (sw_csum & CSUM_DELAY_IP) {
		ip->ip_sum = in_cksum(m, hlen);
	}
sendorfree:
	if (error)
		m_freem_list(m0);

	return (error);
}

static void
ip_out_cksum_stats(int proto, u_int32_t len)
{
	switch (proto) {
	case IPPROTO_TCP:
		tcp_out_cksum_stats(len);
		break;
	case IPPROTO_UDP:
		udp_out_cksum_stats(len);
		break;
	default:
		/* keep only TCP or UDP stats for now */
		break;
	}
}

void
in_delayed_cksum_offset(struct mbuf *m0, int ip_offset)
{
	struct ip *ip;
	unsigned char buf[sizeof(struct ip)];
	u_short csum, offset, ip_len;

        /* Save copy of first mbuf pointer and the ip_offset before modifying */
        struct mbuf *m = m0;
        int ip_offset_copy = ip_offset;

	while (ip_offset >= m->m_len) {
		ip_offset -= m->m_len;
		m = m->m_next;
		if (m == NULL) {
			printf("in_delayed_cksum_withoffset failed - ip_offset wasn't in the packet\n");
			return;
		}
	}
	
	/* Sometimes the IP header is not contiguous, yes this can happen! */
	if (ip_offset + sizeof(struct ip) > m->m_len) {
#if DEBUG		
		printf("delayed m_pullup, m->len: %d  off: %d\n",
			m->m_len, ip_offset);
#endif
		m_copydata(m, ip_offset, sizeof(struct ip), (caddr_t) buf);
		
		ip = (struct ip *)buf;
	} else {
		ip = (struct ip*)(m->m_data + ip_offset);
	}
	
	/* Gross */
	if (ip_offset) {
		m->m_len -= ip_offset;
		m->m_data += ip_offset;
	}
	
	offset = IP_VHL_HL(ip->ip_vhl) << 2 ;

	/*
	 * We could be in the context of an IP or interface filter; in the
	 * former case, ip_len would be in host (correct) order while for
	 * the latter it would be in network order.  Because of this, we
	 * attempt to interpret the length field by comparing it against
	 * the actual packet length.  If the comparison fails, byte swap
	 * the length and check again.  If it still fails, then the packet
	 * is bogus and we give up.
	 */
	ip_len = ip->ip_len;
	if (ip_len != (m0->m_pkthdr.len - ip_offset_copy)) {
		ip_len = SWAP16(ip_len);
		if (ip_len != (m0->m_pkthdr.len - ip_offset_copy)) {
			printf("in_delayed_cksum_offset: ip_len %d (%d) "
			    "doesn't match actual length %d\n", ip->ip_len,
			    ip_len, (m0->m_pkthdr.len - ip_offset_copy));
			return;
		}
	}

	csum = in_cksum_skip(m, ip_len, offset);

	/* Update stats */
	ip_out_cksum_stats(ip->ip_p, ip_len - offset);

	if (m0->m_pkthdr.csum_flags & CSUM_UDP && csum == 0)
		csum = 0xffff;
	offset += m0->m_pkthdr.csum_data & 0xFFFF;        /* checksum offset */

	/* Gross */
	if (ip_offset) {
		if (M_LEADINGSPACE(m) < ip_offset)
			panic("in_delayed_cksum_offset - chain modified!\n");
		m->m_len += ip_offset;
		m->m_data -= ip_offset;
	}

	if (offset > ip_len) /* bogus offset */
		return;

	/* Insert the checksum in the existing chain */
	if (offset + ip_offset + sizeof(u_short) > m->m_len) {
		char tmp[2];
		
#if DEBUG
		printf("delayed m_copyback, m->len: %d  off: %d  p: %d\n",
		    m->m_len, offset + ip_offset, ip->ip_p);
#endif
		*(u_short *)tmp = csum;
		m_copyback(m, offset + ip_offset, 2, tmp);
	} else
		*(u_short *)(m->m_data + offset + ip_offset) = csum;
}

void
in_delayed_cksum(struct mbuf *m)
{
	in_delayed_cksum_offset(m, 0);
}

void
in_cksum_offset(struct mbuf* m, size_t ip_offset)
{
	struct ip* ip = NULL;
	int hlen = 0;
	unsigned char buf[sizeof(struct ip)];
	int swapped = 0;

        /* Save copy of first mbuf pointer and the ip_offset before modifying */
        struct mbuf* m0 = m;
        size_t ip_offset_copy = ip_offset;
	
	while (ip_offset >= m->m_len) {
		ip_offset -= m->m_len;
		m = m->m_next;
		if (m == NULL) {
			printf("in_cksum_offset failed - ip_offset wasn't in the packet\n");
			return;
		}
	}
	
	/* Sometimes the IP header is not contiguous, yes this can happen! */
	if (ip_offset + sizeof(struct ip) > m->m_len) {

#if DEBUG
		printf("in_cksum_offset - delayed m_pullup, m->len: %d  off: %lu\n",
			m->m_len, ip_offset);
#endif	
		m_copydata(m, ip_offset, sizeof(struct ip), (caddr_t) buf);

		ip = (struct ip *)buf;
		ip->ip_sum = 0;
		m_copyback(m, ip_offset + offsetof(struct ip, ip_sum), 2, (caddr_t)&ip->ip_sum);
	} else {
		ip = (struct ip*)(m->m_data + ip_offset);
		ip->ip_sum = 0;
	}
	
	/* Gross */
	if (ip_offset) {
		m->m_len -= ip_offset;
		m->m_data += ip_offset;
	}

#ifdef _IP_VHL
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
	hlen = ip->ip_hl << 2;
#endif
	/*
	 * We could be in the context of an IP or interface filter; in the
	 * former case, ip_len would be in host order while for the latter
	 * it would be in network (correct) order.  Because of this, we
	 * attempt to interpret the length field by comparing it against
	 * the actual packet length.  If the comparison fails, byte swap
	 * the length and check again.  If it still fails, then the packet
	 * is bogus and we give up.
	 */
	if (ntohs(ip->ip_len) != (m0->m_pkthdr.len - ip_offset_copy)) {
		ip->ip_len = SWAP16(ip->ip_len);
		swapped = 1;
		if (ntohs(ip->ip_len) != (m0->m_pkthdr.len - ip_offset_copy)) {
			ip->ip_len = SWAP16(ip->ip_len);
			printf("in_cksum_offset: ip_len %d (%d) "
			    "doesn't match actual length %lu\n",
			    ip->ip_len, SWAP16(ip->ip_len),
			    (m0->m_pkthdr.len - ip_offset_copy));
			return;
		}
	}

	ip->ip_sum = 0;
	ip->ip_sum = in_cksum(m, hlen);
	if (swapped)
		ip->ip_len = SWAP16(ip->ip_len);

	/* Gross */
	if (ip_offset) {
		if (M_LEADINGSPACE(m) < ip_offset)
			panic("in_cksum_offset - chain modified!\n");
		m->m_len += ip_offset;
		m->m_data -= ip_offset;
	}

	/* Insert the checksum in the existing chain if IP header not contiguous */
	if (ip_offset + sizeof(struct ip) > m->m_len) {
		char tmp[2];

#if DEBUG
		printf("in_cksum_offset m_copyback, m->len: %u  off: %lu  p: %d\n",
		    m->m_len, ip_offset + offsetof(struct ip, ip_sum), ip->ip_p);
#endif
		*(u_short *)tmp = ip->ip_sum;
		m_copyback(m, ip_offset + offsetof(struct ip, ip_sum), 2, tmp);
	}
}

/*
 * Insert IP options into preformed packet.
 * Adjust IP destination as required for IP source routing,
 * as indicated by a non-zero in_addr at the start of the options.
 *
 * XXX This routine assumes that the packet has no options in place.
 */
static struct mbuf *
ip_insertoptions(m, opt, phlen)
	register struct mbuf *m;
	struct mbuf *opt;
	int *phlen;
{
	register struct ipoption *p = mtod(opt, struct ipoption *);
	struct mbuf *n;
	register struct ip *ip = mtod(m, struct ip *);
	unsigned optlen;

	optlen = opt->m_len - sizeof(p->ipopt_dst);
	if (optlen + (u_short)ip->ip_len > IP_MAXPACKET)
		return (m);		/* XXX should fail */
	if (p->ipopt_dst.s_addr)
		ip->ip_dst = p->ipopt_dst;
	if (m->m_flags & M_EXT || m->m_data - optlen < m->m_pktdat) {
		MGETHDR(n, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
		if (n == 0)
			return (m);
		n->m_pkthdr.rcvif = 0;
#if CONFIG_MACF_NET
		mac_mbuf_label_copy(m, n);
#endif
		n->m_pkthdr.len = m->m_pkthdr.len + optlen;
		m->m_len -= sizeof(struct ip);
		m->m_data += sizeof(struct ip);
		n->m_next = m;
		m = n;
		m->m_len = optlen + sizeof(struct ip);
		m->m_data += max_linkhdr;
		(void)memcpy(mtod(m, void *), ip, sizeof(struct ip));
	} else {
		m->m_data -= optlen;
		m->m_len += optlen;
		m->m_pkthdr.len += optlen;
		ovbcopy((caddr_t)ip, mtod(m, caddr_t), sizeof(struct ip));
	}
	ip = mtod(m, struct ip *);
	bcopy(p->ipopt_list, ip + 1, optlen);
	*phlen = sizeof(struct ip) + optlen;
	ip->ip_vhl = IP_MAKE_VHL(IPVERSION, *phlen >> 2);
	ip->ip_len += optlen;
	return (m);
}

/*
 * Copy options from ip to jp,
 * omitting those not copied during fragmentation.
 */
int
ip_optcopy(ip, jp)
	struct ip *ip, *jp;
{
	register u_char *cp, *dp;
	int opt, optlen, cnt;

	cp = (u_char *)(ip + 1);
	dp = (u_char *)(jp + 1);
	cnt = (IP_VHL_HL(ip->ip_vhl) << 2) - sizeof (struct ip);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP) {
			/* Preserve for IP mcast tunnel's LSRR alignment. */
			*dp++ = IPOPT_NOP;
			optlen = 1;
			continue;
		}
#if DIAGNOSTIC
		if (cnt < IPOPT_OLEN + sizeof(*cp))
			panic("malformed IPv4 option passed to ip_optcopy");
#endif
		optlen = cp[IPOPT_OLEN];
#if DIAGNOSTIC
		if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt)
			panic("malformed IPv4 option passed to ip_optcopy");
#endif
		/* bogus lengths should have been caught by ip_dooptions */
		if (optlen > cnt)
			optlen = cnt;
		if (IPOPT_COPIED(opt)) {
			bcopy(cp, dp, optlen);
			dp += optlen;
		}
	}
	for (optlen = dp - (u_char *)(jp+1); optlen & 0x3; optlen++)
		*dp++ = IPOPT_EOL;
	return (optlen);
}

/*
 * IP socket option processing.
 */
int
ip_ctloutput(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	struct	inpcb *inp = sotoinpcb(so);
	int	error, optval;

	error = optval = 0;
	if (sopt->sopt_level != IPPROTO_IP) {
		return (EINVAL);
	}

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case IP_OPTIONS:
#ifdef notyet
		case IP_RETOPTS:
#endif
		{
			struct mbuf *m;
			if (sopt->sopt_valsize > MLEN) {
				error = EMSGSIZE;
				break;
			}
			MGET(m, sopt->sopt_p != kernproc ? M_WAIT : M_DONTWAIT,
			    MT_HEADER);
			if (m == 0) {
				error = ENOBUFS;
				break;
			}
			m->m_len = sopt->sopt_valsize;
			error = sooptcopyin(sopt, mtod(m, char *), m->m_len,
					    m->m_len);
			if (error)
				break;
			
			return (ip_pcbopts(sopt->sopt_name, &inp->inp_options,
					   m));
		}

		case IP_TOS:
		case IP_TTL:
		case IP_RECVOPTS:
		case IP_RECVRETOPTS:
		case IP_RECVDSTADDR:
		case IP_RECVIF:
		case IP_RECVTTL:
#if defined(NFAITH) && NFAITH > 0
		case IP_FAITH:
#endif
		case IP_RECVPKTINFO:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;

			switch (sopt->sopt_name) {
			case IP_TOS:
				inp->inp_ip_tos = optval;
				break;

			case IP_TTL:
				inp->inp_ip_ttl = optval;
				break;
#define	OPTSET(bit) \
	if (optval) \
		inp->inp_flags |= bit; \
	else \
		inp->inp_flags &= ~bit;

			case IP_RECVOPTS:
				OPTSET(INP_RECVOPTS);
				break;

			case IP_RECVRETOPTS:
				OPTSET(INP_RECVRETOPTS);
				break;

			case IP_RECVDSTADDR:
				OPTSET(INP_RECVDSTADDR);
				break;

			case IP_RECVIF:
				OPTSET(INP_RECVIF);
				break;

			case IP_RECVTTL:
				OPTSET(INP_RECVTTL);
				break;

#if defined(NFAITH) && NFAITH > 0
			case IP_FAITH:
				OPTSET(INP_FAITH);
				break;
#endif
			case IP_RECVPKTINFO:
				OPTSET(INP_PKTINFO);
				break;
			}
			break;
#undef OPTSET

#if CONFIG_FORCE_OUT_IFP
		/*
		 * Apple private interface, similar to IP_BOUND_IF, except
		 * that the parameter is a NULL-terminated string containing
		 * the name of the network interface; an emptry string means
		 * unbind.  Applications are encouraged to use IP_BOUND_IF
		 * instead, as that is the current "official" API.
		 */
		case IP_FORCE_OUT_IFP: {
			char ifname[IFNAMSIZ];
			unsigned int ifscope;

			/* This option is settable only for IPv4 */
			if (!(inp->inp_vflag & INP_IPV4)) {
				error = EINVAL;
				break;
			}

			/* Verify interface name parameter is sane */
			if (sopt->sopt_valsize > sizeof(ifname)) {
				error = EINVAL;
				break;
			}

			/* Copy the interface name */
			if (sopt->sopt_valsize != 0) {
				error = sooptcopyin(sopt, ifname,
				    sizeof (ifname), sopt->sopt_valsize);
				if (error)
					break;
			}

			if (sopt->sopt_valsize == 0 || ifname[0] == '\0') {
				/* Unbind this socket from any interface */
				ifscope = IFSCOPE_NONE;
			} else {
				ifnet_t	ifp;

				/* Verify name is NULL terminated */
				if (ifname[sopt->sopt_valsize - 1] != '\0') {
					error = EINVAL;
					break;
				}

				/* Bail out if given bogus interface name */
				if (ifnet_find_by_name(ifname, &ifp) != 0) {
					error = ENXIO;
					break;
				}

				/* Bind this socket to this interface */
				ifscope = ifp->if_index;

				/*
				 * Won't actually free; since we don't release
				 * this later, we should do it now.
				 */
				ifnet_release(ifp);
			}
			inp_bindif(inp, ifscope);
		}
		break;
#endif
		/*
		 * Multicast socket options are processed by the in_mcast
		 * module.
		 */
		case IP_MULTICAST_IF:
		case IP_MULTICAST_IFINDEX:
		case IP_MULTICAST_VIF:
		case IP_MULTICAST_TTL:
		case IP_MULTICAST_LOOP:
		case IP_ADD_MEMBERSHIP:
		case IP_DROP_MEMBERSHIP:
		case IP_ADD_SOURCE_MEMBERSHIP:
		case IP_DROP_SOURCE_MEMBERSHIP:
		case IP_BLOCK_SOURCE:
		case IP_UNBLOCK_SOURCE:
		case IP_MSFILTER:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
			error = inp_setmoptions(inp, sopt);
			break;

		case IP_PORTRANGE:
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
			if (error)
				break;

			switch (optval) {
			case IP_PORTRANGE_DEFAULT:
				inp->inp_flags &= ~(INP_LOWPORT);
				inp->inp_flags &= ~(INP_HIGHPORT);
				break;

			case IP_PORTRANGE_HIGH:
				inp->inp_flags &= ~(INP_LOWPORT);
				inp->inp_flags |= INP_HIGHPORT;
				break;

			case IP_PORTRANGE_LOW:
				inp->inp_flags &= ~(INP_HIGHPORT);
				inp->inp_flags |= INP_LOWPORT;
				break;

			default:
				error = EINVAL;
				break;
			}
			break;

#if IPSEC
		case IP_IPSEC_POLICY:
		{
			caddr_t req = NULL;
			size_t len = 0;
			int priv;
			struct mbuf *m;
			int optname;

			if ((error = soopt_getm(sopt, &m)) != 0) /* XXX */
				break;
			if ((error = soopt_mcopyin(sopt, m)) != 0) /* XXX */
				break;
			priv = (proc_suser(sopt->sopt_p) == 0);
			if (m) {
				req = mtod(m, caddr_t);
				len = m->m_len;
			}
			optname = sopt->sopt_name;
			error = ipsec4_set_policy(inp, optname, req, len, priv);
			m_freem(m);
			break;
		}
#endif /*IPSEC*/

#if TRAFFIC_MGT
		case IP_TRAFFIC_MGT_BACKGROUND:
		{
			unsigned	background = 0;
			error = sooptcopyin(sopt, &background, sizeof(background), sizeof(background));
			if (error) 
				break;

			if (background) {
				socket_set_traffic_mgt_flags_locked(so,
				    TRAFFIC_MGT_SO_BACKGROUND);
			} else {
				socket_clear_traffic_mgt_flags_locked(so,
				    TRAFFIC_MGT_SO_BACKGROUND);
			}

			break;
		}
#endif /* TRAFFIC_MGT */

		/*
		 * On a multihomed system, scoped routing can be used to
		 * restrict the source interface used for sending packets.
		 * The socket option IP_BOUND_IF binds a particular AF_INET
		 * socket to an interface such that data sent on the socket
		 * is restricted to that interface.  This is unlike the
		 * SO_DONTROUTE option where the routing table is bypassed;
		 * therefore it allows for a greater flexibility and control
		 * over the system behavior, and does not place any restriction
		 * on the destination address type (e.g.  unicast, multicast,
		 * or broadcast if applicable) or whether or not the host is
		 * directly reachable.  Note that in the multicast transmit
		 * case, IP_MULTICAST_{IF,IFINDEX} takes precedence over
		 * IP_BOUND_IF, since the former practically bypasses the
		 * routing table; in this case, IP_BOUND_IF sets the default
		 * interface used for sending multicast packets in the absence
		 * of an explicit multicast transmit interface.
		 */
		case IP_BOUND_IF:
			/* This option is settable only for IPv4 */
			if (!(inp->inp_vflag & INP_IPV4)) {
				error = EINVAL;
				break;
			}

			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));

			if (error)
				break;

			inp_bindif(inp, optval);
			break;

		case IP_NO_IFT_CELLULAR:
			/* This option is settable only for IPv4 */
			if (!(inp->inp_vflag & INP_IPV4)) {
				error = EINVAL;
				break;
			}

			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));

			if (error)
				break;

			error = inp_nocellular(inp, optval);
			break;

		case IP_OUT_IF:
			/* This option is not settable */
			error = EINVAL;
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;

	case SOPT_GET:
		switch (sopt->sopt_name) {
		case IP_OPTIONS:
		case IP_RETOPTS:
			if (inp->inp_options)
				error = sooptcopyout(sopt, 
						     mtod(inp->inp_options,
							  char *),
						     inp->inp_options->m_len);
			else
				sopt->sopt_valsize = 0;
			break;

		case IP_TOS:
		case IP_TTL:
		case IP_RECVOPTS:
		case IP_RECVRETOPTS:
		case IP_RECVDSTADDR:
		case IP_RECVIF:
		case IP_RECVTTL:
		case IP_PORTRANGE:
#if defined(NFAITH) && NFAITH > 0
		case IP_FAITH:
#endif
		case IP_RECVPKTINFO:
			switch (sopt->sopt_name) {

			case IP_TOS:
				optval = inp->inp_ip_tos;
				break;

			case IP_TTL:
				optval = inp->inp_ip_ttl;
				break;

#define	OPTBIT(bit)	(inp->inp_flags & bit ? 1 : 0)

			case IP_RECVOPTS:
				optval = OPTBIT(INP_RECVOPTS);
				break;

			case IP_RECVRETOPTS:
				optval = OPTBIT(INP_RECVRETOPTS);
				break;

			case IP_RECVDSTADDR:
				optval = OPTBIT(INP_RECVDSTADDR);
				break;

			case IP_RECVIF:
				optval = OPTBIT(INP_RECVIF);
				break;

			case IP_RECVTTL:
				optval = OPTBIT(INP_RECVTTL);
				break;

			case IP_PORTRANGE:
				if (inp->inp_flags & INP_HIGHPORT)
					optval = IP_PORTRANGE_HIGH;
				else if (inp->inp_flags & INP_LOWPORT)
					optval = IP_PORTRANGE_LOW;
				else
					optval = 0;
				break;

#if defined(NFAITH) && NFAITH > 0
			case IP_FAITH:
				optval = OPTBIT(INP_FAITH);
				break;
#endif
			case IP_RECVPKTINFO:
				optval = OPTBIT(INP_PKTINFO);
				break;
			}
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;

		case IP_MULTICAST_IF:
		case IP_MULTICAST_IFINDEX:
		case IP_MULTICAST_VIF:
		case IP_MULTICAST_TTL:
		case IP_MULTICAST_LOOP:
		case IP_MSFILTER:
			error = inp_getmoptions(inp, sopt);
			break;

#if IPSEC
		case IP_IPSEC_POLICY:
		{
			struct mbuf *m = NULL;
			caddr_t req = NULL;
			size_t len = 0;

			if (m != 0) {
				req = mtod(m, caddr_t);
				len = m->m_len;
			}
			error = ipsec4_get_policy(sotoinpcb(so), req, len, &m);
			if (error == 0)
				error = soopt_mcopyout(sopt, m); /* XXX */
			if (error == 0)
				m_freem(m);
			break;
		}
#endif /*IPSEC*/

#if TRAFFIC_MGT
		case IP_TRAFFIC_MGT_BACKGROUND:
		{
			unsigned	background = (so->so_traffic_mgt_flags &  TRAFFIC_MGT_SO_BACKGROUND);
			return (sooptcopyout(sopt, &background, sizeof(background)));
			break;
		}
#endif /* TRAFFIC_MGT */

		case IP_BOUND_IF:
			if (inp->inp_flags & INP_BOUND_IF)
				optval = inp->inp_boundif;
			error = sooptcopyout(sopt, &optval, sizeof (optval));
			break;

		case IP_NO_IFT_CELLULAR:
			optval = (inp->inp_flags & INP_NO_IFT_CELLULAR) ? 1 : 0;
			error = sooptcopyout(sopt, &optval, sizeof (optval));
			break;

		case IP_OUT_IF:
			optval = inp->inp_last_outif;
			error = sooptcopyout(sopt, &optval, sizeof (optval));
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;
	}
	return (error);
}

/*
 * Set up IP options in pcb for insertion in output packets.
 * Store in mbuf with pointer in pcbopt, adding pseudo-option
 * with destination address if source routed.
 */
static int
ip_pcbopts(
	__unused int optname,
	struct mbuf **pcbopt,
	register struct mbuf *m)
{
	register int cnt, optlen;
	register u_char *cp;
	u_char opt;

	/* turn off any old options */
	if (*pcbopt)
		(void)m_free(*pcbopt);
	*pcbopt = 0;
	if (m == (struct mbuf *)0 || m->m_len == 0) {
		/*
		 * Only turning off any previous options.
		 */
		if (m)
			(void)m_free(m);
		return (0);
	}

#ifndef	vax
	if (m->m_len % sizeof(int32_t))
		goto bad;
#endif
	/*
	 * IP first-hop destination address will be stored before
	 * actual options; move other options back
	 * and clear it when none present.
	 */
	if (m->m_data + m->m_len + sizeof(struct in_addr) >= &m->m_dat[MLEN])
		goto bad;
	cnt = m->m_len;
	m->m_len += sizeof(struct in_addr);
	cp = mtod(m, u_char *) + sizeof(struct in_addr);
	ovbcopy(mtod(m, caddr_t), (caddr_t)cp, (unsigned)cnt);
	bzero(mtod(m, caddr_t), sizeof(struct in_addr));

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < IPOPT_OLEN + sizeof(*cp))
				goto bad;
			optlen = cp[IPOPT_OLEN];
			if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt)
				goto bad;
		}
		switch (opt) {

		default:
			break;

		case IPOPT_LSRR:
		case IPOPT_SSRR:
			/*
			 * user process specifies route as:
			 *	->A->B->C->D
			 * D must be our final destination (but we can't
			 * check that since we may not have connected yet).
			 * A is first hop destination, which doesn't appear in
			 * actual IP option, but is stored before the options.
			 */
			if (optlen < IPOPT_MINOFF - 1 + sizeof(struct in_addr))
				goto bad;
			m->m_len -= sizeof(struct in_addr);
			cnt -= sizeof(struct in_addr);
			optlen -= sizeof(struct in_addr);
			cp[IPOPT_OLEN] = optlen;
			/*
			 * Move first hop before start of options.
			 */
			bcopy((caddr_t)&cp[IPOPT_OFFSET+1], mtod(m, caddr_t),
			    sizeof(struct in_addr));
			/*
			 * Then copy rest of options back
			 * to close up the deleted entry.
			 */
			ovbcopy((caddr_t)(&cp[IPOPT_OFFSET+1] +
			    sizeof(struct in_addr)),
			    (caddr_t)&cp[IPOPT_OFFSET+1],
			    (unsigned)cnt + sizeof(struct in_addr));
			break;
		}
	}
	if (m->m_len > MAX_IPOPTLEN + sizeof(struct in_addr))
		goto bad;
	*pcbopt = m;
	return (0);

bad:
	(void)m_free(m);
	return (EINVAL);
}

void
ip_moptions_init(void)
{
	PE_parse_boot_argn("ifa_debug", &imo_debug, sizeof (imo_debug));

	imo_size = (imo_debug == 0) ? sizeof (struct ip_moptions) :
	    sizeof (struct ip_moptions_dbg);

	imo_zone = zinit(imo_size, IMO_ZONE_MAX * imo_size, 0,
	    IMO_ZONE_NAME);
	if (imo_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IMO_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(imo_zone, Z_EXPAND, TRUE);
}

void
imo_addref(struct ip_moptions *imo, int locked)
{
	if (!locked)
		IMO_LOCK(imo);
	else
		IMO_LOCK_ASSERT_HELD(imo);

	if (++imo->imo_refcnt == 0) {
		panic("%s: imo %p wraparound refcnt\n", __func__, imo);
		/* NOTREACHED */
	} else if (imo->imo_trace != NULL) {
		(*imo->imo_trace)(imo, TRUE);
	}

	if (!locked)
		IMO_UNLOCK(imo);
}

void
imo_remref(struct ip_moptions *imo)
{
	int i;

	IMO_LOCK(imo);
	if (imo->imo_refcnt == 0) {
		panic("%s: imo %p negative refcnt", __func__, imo);
		/* NOTREACHED */
	} else if (imo->imo_trace != NULL) {
		(*imo->imo_trace)(imo, FALSE);
	}

	--imo->imo_refcnt;
	if (imo->imo_refcnt > 0) {
		IMO_UNLOCK(imo);
		return;
	}

	for (i = 0; i < imo->imo_num_memberships; ++i) {
		struct in_mfilter *imf;

		imf = imo->imo_mfilters ? &imo->imo_mfilters[i] : NULL;
		if (imf != NULL)
			imf_leave(imf);

		(void) in_leavegroup(imo->imo_membership[i], imf);

		if (imf != NULL)
			imf_purge(imf);

		INM_REMREF(imo->imo_membership[i]);
		imo->imo_membership[i] = NULL;
	}
	imo->imo_num_memberships = 0;
	if (imo->imo_mfilters != NULL) {
		FREE(imo->imo_mfilters, M_INMFILTER);
		imo->imo_mfilters = NULL;
	}
	if (imo->imo_membership != NULL) {
		FREE(imo->imo_membership, M_IPMOPTS);
		imo->imo_membership = NULL;
	}
	IMO_UNLOCK(imo);

	lck_mtx_destroy(&imo->imo_lock, ifa_mtx_grp);

	if (!(imo->imo_debug & IFD_ALLOC)) {
		panic("%s: imo %p cannot be freed", __func__, imo);
		/* NOTREACHED */
	}
	zfree(imo_zone, imo);
}

static void
imo_trace(struct ip_moptions *imo, int refhold)
{
	struct ip_moptions_dbg *imo_dbg = (struct ip_moptions_dbg *)imo;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(imo->imo_debug & IFD_DEBUG)) {
		panic("%s: imo %p has no debug structure", __func__, imo);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &imo_dbg->imo_refhold_cnt;
		tr = imo_dbg->imo_refhold;
	} else {
		cnt = &imo_dbg->imo_refrele_cnt;
		tr = imo_dbg->imo_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % IMO_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

struct ip_moptions *
ip_allocmoptions(int how)
{
	struct ip_moptions *imo;

	imo = (how == M_WAITOK) ? zalloc(imo_zone) : zalloc_noblock(imo_zone);
	if (imo != NULL) {
		bzero(imo, imo_size);
		lck_mtx_init(&imo->imo_lock, ifa_mtx_grp, ifa_mtx_attr);
		imo->imo_debug |= IFD_ALLOC;
		if (imo_debug != 0) {
			imo->imo_debug |= IFD_DEBUG;
			imo->imo_trace = imo_trace;
		}
		IMO_ADDREF(imo);
	}

	return (imo);
}

/*
 * Routine called from ip_output() to loop back a copy of an IP multicast
 * packet to the input queue of a specified interface.  Note that this
 * calls the output routine of the loopback "driver", but with an interface
 * pointer that might NOT be a loopback interface -- evil, but easier than
 * replicating that code here.
 */
static void
ip_mloopback(ifp, m, dst, hlen)
	struct ifnet *ifp;
	register struct mbuf *m;
	register struct sockaddr_in *dst;
	int hlen;
{
	register struct ip *ip;
	struct mbuf *copym;
	int sw_csum = (apple_hwcksum_tx == 0);

	copym = m_copy(m, 0, M_COPYALL);
	if (copym != NULL && (copym->m_flags & M_EXT || copym->m_len < hlen))
		copym = m_pullup(copym, hlen);

	if (copym == NULL)
		return;

	/*
	 * We don't bother to fragment if the IP length is greater
	 * than the interface's MTU.  Can this possibly matter?
	 */
	ip = mtod(copym, struct ip *);

#if BYTE_ORDER != BIG_ENDIAN
	HTONS(ip->ip_len);
	HTONS(ip->ip_off);
#endif
	
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum(copym, hlen);
	/*
	 * NB:
	 * It's not clear whether there are any lingering
	 * reentrancy problems in other areas which might
	 * be exposed by using ip_input directly (in
	 * particular, everything which modifies the packet
	 * in-place).  Yet another option is using the
	 * protosw directly to deliver the looped back
	 * packet.  For the moment, we'll err on the side
	 * of safety by using if_simloop().
	 */
#if 1 /* XXX */
	if (dst->sin_family != AF_INET) {
		printf("ip_mloopback: bad address family %d\n",
					dst->sin_family);
		dst->sin_family = AF_INET;
	}
#endif

        /*
         * Mark checksum as valid or calculate checksum for loopback.
         *
         * This is done this way because we have to embed the ifp of
         * the interface we will send the original copy of the packet
         * out on in the mbuf. ip_input will check if_hwassist of the
         * embedded ifp and ignore all csum_flags if if_hwassist is 0.
         * The UDP checksum has not been calculated yet.
         */
        if (sw_csum || (copym->m_pkthdr.csum_flags & CSUM_DELAY_DATA)) {
		if (!sw_csum && IF_HWASSIST_CSUM_FLAGS(ifp->if_hwassist)) {
			copym->m_pkthdr.csum_flags |=
			    CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
			    CSUM_IP_CHECKED | CSUM_IP_VALID;
			copym->m_pkthdr.csum_data = 0xffff;
		} else {

#if BYTE_ORDER != BIG_ENDIAN
			NTOHS(ip->ip_len);
#endif
			
			in_delayed_cksum(copym);

#if BYTE_ORDER != BIG_ENDIAN
			HTONS(ip->ip_len);
#endif
		
		}
        }

	/*
	 * TedW: 
	 * We need to send all loopback traffic down to dlil in case 
	 * a filter has tapped-in.
	 */

	/*
	 * Stuff the 'real' ifp into the pkthdr, to be used in matching
	 *  in ip_input(); we need the loopback ifp/dl_tag passed as args
	 *  to make the loopback driver compliant with the data link
	 *  requirements.
	 */
	if (lo_ifp) {
		copym->m_pkthdr.rcvif = ifp;
		dlil_output(lo_ifp, PF_INET, copym, 0,
		    (struct sockaddr *) dst, 0);
	} else {
		printf("Warning: ip_output call to dlil_find_dltag failed!\n");
		m_freem(copym);
	}
}

/*
 * Given a source IP address (and route, if available), determine the best
 * interface to send the packet from.  Checking for (and updating) the
 * ROF_SRCIF_SELECTED flag in the pcb-supplied route placeholder is done
 * without any locks based on the assumption that ip_output() is single-
 * threaded per-pcb, i.e. for any given pcb there can only be one thread
 * performing output at the IP layer.
 *
 * This routine is analogous to in6_selectroute() for IPv6.
 */
static struct ifaddr *
in_selectsrcif(struct ip *ip, struct route *ro, unsigned int ifscope)
{
	struct ifaddr *ifa = NULL;
	struct in_addr src = ip->ip_src;
	struct in_addr dst = ip->ip_dst;
	struct ifnet *rt_ifp;
	char s_src[MAX_IPv4_STR_LEN], s_dst[MAX_IPv4_STR_LEN];

	if (ip_select_srcif_debug) {
		(void) inet_ntop(AF_INET, &src.s_addr, s_src, sizeof (s_src));
		(void) inet_ntop(AF_INET, &dst.s_addr, s_dst, sizeof (s_dst));
	}

	if (ro->ro_rt != NULL)
		RT_LOCK(ro->ro_rt);

	rt_ifp = (ro->ro_rt != NULL) ? ro->ro_rt->rt_ifp : NULL;

	/*
	 * Given the source IP address, find a suitable source interface
	 * to use for transmission; if the caller has specified a scope,
	 * optimize the search by looking at the addresses only for that
	 * interface.  This is still suboptimal, however, as we need to
	 * traverse the per-interface list.
	 */
	if (ifscope != IFSCOPE_NONE || ro->ro_rt != NULL) {
		unsigned int scope = ifscope;

		/*
		 * If no scope is specified and the route is stale (pointing
		 * to a defunct interface) use the current primary interface;
		 * this happens when switching between interfaces configured
		 * with the same IP address.  Otherwise pick up the scope
		 * information from the route; the ULP may have looked up a
		 * correct route and we just need to verify it here and mark
		 * it with the ROF_SRCIF_SELECTED flag below.
		 */
		if (scope == IFSCOPE_NONE) {
			scope = rt_ifp->if_index;
			if (scope != get_primary_ifscope(AF_INET) &&
			    ro->ro_rt->generation_id != route_generation)
				scope = get_primary_ifscope(AF_INET);
		}

		ifa = (struct ifaddr *)ifa_foraddr_scoped(src.s_addr, scope);

		if (ifa == NULL && ip->ip_p != IPPROTO_UDP &&
		    ip->ip_p != IPPROTO_TCP && ipforwarding) {
			/*
			 * If forwarding is enabled, and if the packet isn't
			 * TCP or UDP, check if the source address belongs
			 * to one of our own interfaces; if so, demote the
			 * interface scope and do a route lookup right below.
			 */
			ifa = (struct ifaddr *)ifa_foraddr(src.s_addr);
			if (ifa != NULL) {
				IFA_REMREF(ifa);
				ifa = NULL;
				ifscope = IFSCOPE_NONE;
			}
		}

		if (ip_select_srcif_debug && ifa != NULL) {
			if (ro->ro_rt != NULL) {
				printf("%s->%s ifscope %d->%d ifa_if %s "
				    "ro_if %s\n", s_src, s_dst, ifscope,
				    scope, if_name(ifa->ifa_ifp),
				    if_name(rt_ifp));
			} else {
				printf("%s->%s ifscope %d->%d ifa_if %s\n",
				    s_src, s_dst, ifscope, scope,
				    if_name(ifa->ifa_ifp));
			}
		}
	}

	/*
	 * Slow path; search for an interface having the corresponding source
	 * IP address if the scope was not specified by the caller, and:
	 *
	 *   1) There currently isn't any route, or,
	 *   2) The interface used by the route does not own that source
	 *	IP address; in this case, the route will get blown away
	 *	and we'll do a more specific scoped search using the newly
	 *	found interface.
	 */
	if (ifa == NULL && ifscope == IFSCOPE_NONE) {
		ifa = (struct ifaddr *)ifa_foraddr(src.s_addr);

		/*
		 * If we have the IP address, but not the route, we don't
		 * really know whether or not it belongs to the correct
		 * interface (it could be shared across multiple interfaces.)
		 * The only way to find out is to do a route lookup.
		 */
		if (ifa != NULL && ro->ro_rt == NULL) {
			struct rtentry *rt;
			struct sockaddr_in sin;
			struct ifaddr *oifa = NULL;

			bzero(&sin, sizeof (sin));
			sin.sin_family = AF_INET;
			sin.sin_len = sizeof (sin);
			sin.sin_addr = dst;

			lck_mtx_lock(rnh_lock);
			if ((rt = rt_lookup(TRUE, (struct sockaddr *)&sin, NULL,
			    rt_tables[AF_INET], IFSCOPE_NONE)) != NULL) {
				RT_LOCK(rt);
				/*
				 * If the route uses a different interface,
				 * use that one instead.  The IP address of
				 * the ifaddr that we pick up here is not
				 * relevant.
				 */
				if (ifa->ifa_ifp != rt->rt_ifp) {
					oifa = ifa;
					ifa = rt->rt_ifa;
					IFA_ADDREF(ifa);
					RT_UNLOCK(rt);
				} else {
					RT_UNLOCK(rt);
				}
				rtfree_locked(rt);
			}
			lck_mtx_unlock(rnh_lock);

			if (oifa != NULL) {
				struct ifaddr *iifa;

				/*
				 * See if the interface pointed to by the
				 * route is configured with the source IP
				 * address of the packet.
				 */
				iifa = (struct ifaddr *)ifa_foraddr_scoped(
				    src.s_addr, ifa->ifa_ifp->if_index);

				if (iifa != NULL) {
					/*
					 * Found it; drop the original one
					 * as well as the route interface
					 * address, and use this instead.
					 */
					IFA_REMREF(oifa);
					IFA_REMREF(ifa);
					ifa = iifa;
				} else if (!ipforwarding ||
				    (rt->rt_flags & RTF_GATEWAY)) {
					/*
					 * This interface doesn't have that
					 * source IP address; drop the route
					 * interface address and just use the
					 * original one, and let the caller
					 * do a scoped route lookup.
					 */
					IFA_REMREF(ifa);
					ifa = oifa;
				} else {
					/*
					 * Forwarding is enabled and the source
					 * address belongs to one of our own
					 * interfaces which isn't the outgoing
					 * interface, and we have a route, and
					 * the destination is on a network that
					 * is directly attached (onlink); drop
					 * the original one and use the route
					 * interface address instead.
					 */
					IFA_REMREF(oifa);
				}
			}
		} else if (ifa != NULL && ro->ro_rt != NULL &&
		    !(ro->ro_rt->rt_flags & RTF_GATEWAY) &&
		    ifa->ifa_ifp != ro->ro_rt->rt_ifp && ipforwarding) {
			/*
			 * Forwarding is enabled and the source address belongs
			 * to one of our own interfaces which isn't the same
			 * as the interface used by the known route; drop the
			 * original one and use the route interface address.
			 */
			IFA_REMREF(ifa);
			ifa = ro->ro_rt->rt_ifa;
			IFA_ADDREF(ifa);
		}

		if (ip_select_srcif_debug && ifa != NULL) {
			printf("%s->%s ifscope %d ifa_if %s\n",
			    s_src, s_dst, ifscope, if_name(ifa->ifa_ifp));
		}
	}

	if (ro->ro_rt != NULL)
		RT_LOCK_ASSERT_HELD(ro->ro_rt);
	/*
	 * If there is a non-loopback route with the wrong interface, or if
	 * there is no interface configured with such an address, blow it
	 * away.  Except for local/loopback, we look for one with a matching
	 * interface scope/index.
	 */
	if (ro->ro_rt != NULL &&
	    (ifa == NULL || (ifa->ifa_ifp != rt_ifp && rt_ifp != lo_ifp) ||
	    !(ro->ro_rt->rt_flags & RTF_UP))) {
		if (ip_select_srcif_debug) {
			if (ifa != NULL) {
				printf("%s->%s ifscope %d ro_if %s != "
				    "ifa_if %s (cached route cleared)\n",
				    s_src, s_dst, ifscope, if_name(rt_ifp),
				    if_name(ifa->ifa_ifp));
			} else {
				printf("%s->%s ifscope %d ro_if %s "
				    "(no ifa_if found)\n",
				    s_src, s_dst, ifscope, if_name(rt_ifp));
			}
		}

		RT_UNLOCK(ro->ro_rt);
		rtfree(ro->ro_rt);
		ro->ro_rt = NULL;
		ro->ro_flags &= ~ROF_SRCIF_SELECTED;

		/*
		 * If the destination is IPv4 LLA and the route's interface
		 * doesn't match the source interface, then the source IP
		 * address is wrong; it most likely belongs to the primary
		 * interface associated with the IPv4 LL subnet.  Drop the
		 * packet rather than letting it go out and return an error
		 * to the ULP.  This actually applies not only to IPv4 LL
		 * but other shared subnets; for now we explicitly test only
		 * for the former case and save the latter for future.
		 */
		if (IN_LINKLOCAL(ntohl(dst.s_addr)) &&
		    !IN_LINKLOCAL(ntohl(src.s_addr)) && ifa != NULL) {
			IFA_REMREF(ifa);
			ifa = NULL;
		}
	}

	if (ip_select_srcif_debug && ifa == NULL) {
		printf("%s->%s ifscope %d (neither ro_if/ifa_if found)\n",
		    s_src, s_dst, ifscope);
	}

	/*
	 * If there is a route, mark it accordingly.  If there isn't one,
	 * we'll get here again during the next transmit (possibly with a
	 * route) and the flag will get set at that point.  For IPv4 LLA
	 * destination, mark it only if the route has been fully resolved;
	 * otherwise we want to come back here again when the route points
	 * to the interface over which the ARP reply arrives on.
	 */
	if (ro->ro_rt != NULL && (!IN_LINKLOCAL(ntohl(dst.s_addr)) ||
	    (ro->ro_rt->rt_gateway->sa_family == AF_LINK &&
	    SDL(ro->ro_rt->rt_gateway)->sdl_alen != 0))) {
		ro->ro_flags |= ROF_SRCIF_SELECTED;
		ro->ro_rt->generation_id = route_generation;
	}

	if (ro->ro_rt != NULL)
		RT_UNLOCK(ro->ro_rt);

	return (ifa);
}
