/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1993 Daniel Boulet
 * Copyright (c) 1994 Ugen J.S.Antsilevich
 * Copyright (c) 1996 Alex Nash
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 */

/*
 * Implement IP packet firewall
 */
#if !IPFIREWALL_KEXT
#if ISFB31
#if !defined(KLD_MODULE) && !defined(IPFIREWALL_MODULE)
#include "opt_ipfw.h"
#include "opt_ipdn.h"
#include "opt_ipdivert.h"
#include "opt_inet.h"
#endif
#endif
#ifndef INET
#error IPFIREWALL requires INET.
#endif /* INET */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_fw.h>
#if DUMMYNET
#include <net/route.h>
#include <netinet/ip_dummynet.h>
#endif
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/tcpip.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <netinet/if_ether.h> /* XXX ethertype_ip */

static int fw_debug = 1;
#if IPFIREWALL_VERBOSE
static int fw_verbose = 1;
#else
static int fw_verbose = 0;
#endif
static int fw_one_pass = 0; /* XXX */
#if IPFIREWALL_VERBOSE_LIMIT
static int fw_verbose_limit = IPFIREWALL_VERBOSE_LIMIT;
#else
static int fw_verbose_limit = 0;
#endif

#define	IPFW_DEFAULT_RULE	((u_int)(u_short)~0)

LIST_HEAD (ip_fw_head, ip_fw_chain) ip_fw_chain;

MALLOC_DEFINE(M_IPFW, "IpFw/IpAcct", "IpFw/IpAcct chain's");

SYSCTL_DECL(_net_inet_ip);
SYSCTL_NODE(_net_inet_ip, OID_AUTO, fw, CTLFLAG_RW, 0, "Firewall");
SYSCTL_INT(_net_inet_ip_fw, OID_AUTO, debug, CTLFLAG_RW, &fw_debug, 0, "");
SYSCTL_INT(_net_inet_ip_fw, OID_AUTO,one_pass,CTLFLAG_RW, &fw_one_pass, 0, "");
SYSCTL_INT(_net_inet_ip_fw, OID_AUTO, verbose, CTLFLAG_RW, &fw_verbose, 0, "");
SYSCTL_INT(_net_inet_ip_fw, OID_AUTO, verbose_limit, CTLFLAG_RW, &fw_verbose_limit, 0, "");

#define dprintf(a)	if (!fw_debug); else printf a

#define print_ip(a)	printf("%d.%d.%d.%d",				\
			    (int)(ntohl(a.s_addr) >> 24) & 0xFF,	\
			    (int)(ntohl(a.s_addr) >> 16) & 0xFF,	\
			    (int)(ntohl(a.s_addr) >> 8) & 0xFF,		\
			    (int)(ntohl(a.s_addr)) & 0xFF);

#define dprint_ip(a)	if (!fw_debug); else print_ip(a)

static int	add_entry __P((struct ip_fw_head *chainptr, struct ip_fw *frwl));
static int	del_entry __P((struct ip_fw_head *chainptr, u_short number));
static int	zero_entry __P((struct ip_fw *));
static int	check_ipfw_struct __P((struct ip_fw *m));
static __inline int
		iface_match __P((struct ifnet *ifp, union ip_fw_if *ifu,
				 int byname));
static int	ipopts_match __P((struct ip *ip, struct ip_fw *f));
static __inline int
		port_match __P((u_short *portptr, int nports, u_short port,
				int range_flag));
static int	tcpflg_match __P((struct tcphdr *tcp, struct ip_fw *f));
static int	icmptype_match __P((struct icmp *  icmp, struct ip_fw * f));
static void	ipfw_report __P((struct ip_fw *f, struct ip *ip,
				struct ifnet *rif, struct ifnet *oif));

static void flush_rule_ptrs(void);

static int	ip_fw_chk __P((struct ip **pip, int hlen,
			struct ifnet *oif, u_int16_t *cookie, struct mbuf **m,
			struct ip_fw_chain **flow_id,
			struct sockaddr_in **next_hop));
static int	ip_fw_ctl __P((struct sockopt *sopt));

static char err_prefix[] = "ip_fw_ctl:";

/*
 * Returns 1 if the port is matched by the vector, 0 otherwise
 */
static __inline int 
port_match(u_short *portptr, int nports, u_short port, int range_flag)
{
	if (!nports)
		return 1;
	if (range_flag) {
		if (portptr[0] <= port && port <= portptr[1]) {
			return 1;
		}
		nports -= 2;
		portptr += 2;
	}
	while (nports-- > 0) {
		if (*portptr++ == port) {
			return 1;
		}
	}
	return 0;
}

static int
tcpflg_match(struct tcphdr *tcp, struct ip_fw *f)
{
	u_char		flg_set, flg_clr;
	
	if ((f->fw_tcpf & IP_FW_TCPF_ESTAB) &&
	    (tcp->th_flags & (IP_FW_TCPF_RST | IP_FW_TCPF_ACK)))
		return 1;

	flg_set = tcp->th_flags & f->fw_tcpf;
	flg_clr = tcp->th_flags & f->fw_tcpnf;

	if (flg_set != f->fw_tcpf)
		return 0;
	if (flg_clr)
		return 0;

	return 1;
}

static int
icmptype_match(struct icmp *icmp, struct ip_fw *f)
{
	int type;

	if (!(f->fw_flg & IP_FW_F_ICMPBIT))
		return(1);

	type = icmp->icmp_type;

	/* check for matching type in the bitmap */
	if (type < IP_FW_ICMPTYPES_MAX &&
		(f->fw_uar.fw_icmptypes[type / (sizeof(unsigned) * 8)] & 
		(1U << (type % (8 * sizeof(unsigned))))))
		return(1);

	return(0); /* no match */
}

static int
is_icmp_query(struct ip *ip)
{
	const struct icmp *icmp;
	int icmp_type;

	icmp = (struct icmp *)((u_int32_t *)ip + ip->ip_hl);
	icmp_type = icmp->icmp_type;

	if (icmp_type == ICMP_ECHO || icmp_type == ICMP_ROUTERSOLICIT ||
	    icmp_type == ICMP_TSTAMP || icmp_type == ICMP_IREQ ||
	    icmp_type == ICMP_MASKREQ)
		return(1);

	return(0);
}

static int
ipopts_match(struct ip *ip, struct ip_fw *f)
{
	register u_char *cp;
	int opt, optlen, cnt;
	u_char	opts, nopts, nopts_sve;

	cp = (u_char *)(ip + 1);
	cnt = (ip->ip_hl << 2) - sizeof (struct ip);
	opts = f->fw_ipopt;
	nopts = nopts_sve = f->fw_ipnopt;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			optlen = cp[IPOPT_OLEN];
			if (optlen <= 0 || optlen > cnt) {
				return 0; /*XXX*/
			}
		}
		switch (opt) {

		default:
			break;

		case IPOPT_LSRR:
			opts &= ~IP_FW_IPOPT_LSRR;
			nopts &= ~IP_FW_IPOPT_LSRR;
			break;

		case IPOPT_SSRR:
			opts &= ~IP_FW_IPOPT_SSRR;
			nopts &= ~IP_FW_IPOPT_SSRR;
			break;

		case IPOPT_RR:
			opts &= ~IP_FW_IPOPT_RR;
			nopts &= ~IP_FW_IPOPT_RR;
			break;
		case IPOPT_TS:
			opts &= ~IP_FW_IPOPT_TS;
			nopts &= ~IP_FW_IPOPT_TS;
			break;
		}
		if (opts == nopts)
			break;
	}
	if (opts == 0 && nopts == nopts_sve)
		return 1;
	else
		return 0;
}

static __inline int
iface_match(struct ifnet *ifp, union ip_fw_if *ifu, int byname)
{
	/* Check by name or by IP address */
	if (byname) {
		/* Check unit number (-1 is wildcard) */
		if (ifu->fu_via_if.unit != -1
		    && ifp->if_unit != ifu->fu_via_if.unit)
			return(0);
		/* Check name */
		if (strncmp(ifp->if_name, ifu->fu_via_if.name, FW_IFNLEN))
			return(0);
		return(1);
	} else if (ifu->fu_via_ip.s_addr != 0) {	/* Zero == wildcard */
		struct ifaddr *ia;

		for (ia = ifp->if_addrhead.tqh_first;
		    ia != NULL; ia = ia->ifa_link.tqe_next) {
			if (ia->ifa_addr == NULL)
				continue;
			if (ia->ifa_addr->sa_family != AF_INET)
				continue;
			if (ifu->fu_via_ip.s_addr != ((struct sockaddr_in *)
			    (ia->ifa_addr))->sin_addr.s_addr)
				continue;
			return(1);
		}
		return(0);
	}
	return(1);
}

static void
ipfw_report(struct ip_fw *f, struct ip *ip,
	struct ifnet *rif, struct ifnet *oif)
{
    if (ip) {
	static u_int64_t counter;
	struct tcphdr *const tcp = (struct tcphdr *) ((u_int32_t *) ip+ ip->ip_hl);
	struct udphdr *const udp = (struct udphdr *) ((u_int32_t *) ip+ ip->ip_hl);
	struct icmp *const icmp = (struct icmp *) ((u_int32_t *) ip + ip->ip_hl);
	int count;

	count = f ? f->fw_pcnt : ++counter;
	if (fw_verbose_limit != 0 && count > fw_verbose_limit)
		return;

	/* Print command name */
	printf("ipfw: %d ", f ? f->fw_number : -1);
	if (!f)
		printf("Refuse");
	else
		switch (f->fw_flg & IP_FW_F_COMMAND) {
		case IP_FW_F_DENY:
			printf("Deny");
			break;
		case IP_FW_F_REJECT:
			if (f->fw_reject_code == IP_FW_REJECT_RST)
				printf("Reset");
			else
				printf("Unreach");
			break;
		case IP_FW_F_ACCEPT:
			printf("Accept");
			break;
		case IP_FW_F_COUNT:
			printf("Count");
			break;
		case IP_FW_F_DIVERT:
			printf("Divert %d", f->fw_divert_port);
			break;
		case IP_FW_F_TEE:
			printf("Tee %d", f->fw_divert_port);
			break;
		case IP_FW_F_SKIPTO:
			printf("SkipTo %d", f->fw_skipto_rule);
			break;
#if DUMMYNET
		case IP_FW_F_PIPE:
			printf("Pipe %d", f->fw_skipto_rule);
			break;
#endif
#if IPFIREWALL_FORWARD
		case IP_FW_F_FWD:
			printf("Forward to ");
			print_ip(f->fw_fwd_ip.sin_addr);
			if (f->fw_fwd_ip.sin_port)
				printf(":%d", f->fw_fwd_ip.sin_port);
			break;
#endif
		default:	
			printf("UNKNOWN");
			break;
		}
	printf(" ");

	switch (ip->ip_p) {
	case IPPROTO_TCP:
		printf("TCP ");
		print_ip(ip->ip_src);
		if ((ip->ip_off & IP_OFFMASK) == 0)
			printf(":%d ", ntohs(tcp->th_sport));
		else
			printf(" ");
		print_ip(ip->ip_dst);
		if ((ip->ip_off & IP_OFFMASK) == 0)
			printf(":%d", ntohs(tcp->th_dport));
		break;
	case IPPROTO_UDP:
		printf("UDP ");
		print_ip(ip->ip_src);
		if ((ip->ip_off & IP_OFFMASK) == 0)
			printf(":%d ", ntohs(udp->uh_sport));
		else
			printf(" ");
		print_ip(ip->ip_dst);
		if ((ip->ip_off & IP_OFFMASK) == 0)
			printf(":%d", ntohs(udp->uh_dport));
		break;
	case IPPROTO_ICMP:
		if ((ip->ip_off & IP_OFFMASK) == 0)
			printf("ICMP:%u.%u ", icmp->icmp_type, icmp->icmp_code);
		else
			printf("ICMP ");
		print_ip(ip->ip_src);
		printf(" ");
		print_ip(ip->ip_dst);
		break;
	default:
		printf("P:%d ", ip->ip_p);
		print_ip(ip->ip_src);
		printf(" ");
		print_ip(ip->ip_dst);
		break;
	}
	if (oif)
		printf(" out via %s%d", oif->if_name, oif->if_unit);
	else if (rif)
		printf(" in via %s%d", rif->if_name, rif->if_unit);
	if ((ip->ip_off & IP_OFFMASK)) 
		printf(" Fragment = %d",ip->ip_off & IP_OFFMASK);
	printf("\n");
	if (fw_verbose_limit != 0 && count == fw_verbose_limit)
		printf("ipfw: limit reached on rule #%d\n",
		f ? f->fw_number : -1);
    }
}

/*
 * given an ip_fw_chain *, lookup_next_rule will return a pointer
 * of the same type to the next one. This can be either the jump
 * target (for skipto instructions) or the next one in the chain (in
 * all other cases including a missing jump target).
 * Backward jumps are not allowed, so start looking from the next
 * rule...
 */ 
static struct ip_fw_chain * lookup_next_rule(struct ip_fw_chain *me);

static struct ip_fw_chain *
lookup_next_rule(struct ip_fw_chain *me)
{
    struct ip_fw_chain *chain ;
    int rule = me->rule->fw_skipto_rule ; /* guess... */

    if ( (me->rule->fw_flg & IP_FW_F_COMMAND) == IP_FW_F_SKIPTO )
	for (chain = me->chain.le_next; chain ; chain = chain->chain.le_next )
	    if (chain->rule->fw_number >= rule)
                return chain ;
    return me->chain.le_next ; /* failure or not a skipto */
}

/*
 * Parameters:
 *
 *	pip	Pointer to packet header (struct ip **)
 *      bridge_ipfw extension: pip = NULL means a complete ethernet packet
 *      including ethernet header in the mbuf. Other fields
 *      are ignored/invalid.
 *
 *	hlen	Packet header length
 *	oif	Outgoing interface, or NULL if packet is incoming
 *	*cookie Skip up to the first rule past this rule number;
 *	*m	The packet; we set to NULL when/if we nuke it.
 *	*flow_id pointer to the last matching rule (in/out)
 *	*next_hop socket we are forwarding to (in/out).
 *
 * Return value:
 *
 *	0	The packet is to be accepted and routed normally OR
 *      	the packet was denied/rejected and has been dropped;
 *		in the latter case, *m is equal to NULL upon return.
 *	port	Divert the packet to port.
 */

static int 
ip_fw_chk(struct ip **pip, int hlen,
	struct ifnet *oif, u_int16_t *cookie, struct mbuf **m,
	struct ip_fw_chain **flow_id,
        struct sockaddr_in **next_hop)
{
	struct ip_fw_chain *chain;
	struct ip_fw *rule = NULL;
	struct ip *ip = NULL ;
	struct ifnet *const rif = (*m)->m_pkthdr.rcvif;
	u_short offset = 0 ;
	u_short src_port, dst_port;
	u_int16_t skipto = *cookie;

	if (pip) { /* normal ip packet */
	    ip = *pip;
	    offset = (ip->ip_off & IP_OFFMASK);
	} else { /* bridged or non-ip packet */
	    struct ether_header *eh = mtod(*m, struct ether_header *);
	    switch (ntohs(eh->ether_type)) {
	    case ETHERTYPE_IP :
		if ((*m)->m_len<sizeof(struct ether_header) + sizeof(struct ip))
		    goto non_ip ;
		ip = (struct ip *)(eh + 1 );
		if (ip->ip_v != IPVERSION)
		    goto non_ip ;
		hlen = ip->ip_hl << 2;
		if (hlen < sizeof(struct ip)) /* minimum header length */
		    goto non_ip ;
		if ((*m)->m_len < 14 + hlen + 14) {
		    printf("-- m_len %d, need more...\n", (*m)->m_len);
		    goto non_ip ;
		}
		offset = (ip->ip_off & IP_OFFMASK);
		break ;
	    default :
non_ip:         ip = NULL ;
		break ;
	    }
	}

	if (*flow_id) {
	    if (fw_one_pass)
		return 0 ; /* accept if passed first test */
	    /*
	     * pkt has already been tagged. Look for the next rule
	     * to restart processing
	     */
	    chain = LIST_NEXT( *flow_id, chain);

	    if ( (chain = (*flow_id)->rule->next_rule_ptr) == NULL )
		chain = (*flow_id)->rule->next_rule_ptr =
			lookup_next_rule(*flow_id) ;
		if (! chain) goto dropit;
	} else {
	/*
	 * Go down the chain, looking for enlightment
	 * If we've been asked to start at a given rule immediatly, do so.
	 */
	chain = LIST_FIRST(&ip_fw_chain);
	if ( skipto ) {
		if (skipto >= IPFW_DEFAULT_RULE)
			goto dropit;
		while (chain && (chain->rule->fw_number <= skipto)) {
			chain = LIST_NEXT(chain, chain);
		}
		if (! chain) goto dropit;
	}
	}
	*cookie = 0;
	for (; chain; chain = LIST_NEXT(chain, chain)) {
		register struct ip_fw * f ;
again:
		f = chain->rule;

		if (oif) {
			/* Check direction outbound */
			if (!(f->fw_flg & IP_FW_F_OUT))
				continue;
		} else {
			/* Check direction inbound */
			if (!(f->fw_flg & IP_FW_F_IN))
				continue;
		}
		if (ip == NULL ) {
		    /*
		     * do relevant checks for non-ip packets:
		     * after this, only goto got_match or continue
		     */
		    struct ether_header *eh = mtod(*m, struct ether_header *);

		    /*
		     * make default rule always match or we have a panic
		     */
		    if (f->fw_number == IPFW_DEFAULT_RULE)
			goto got_match ;
		    /*
		     * temporary hack: 
		     *   udp from 0.0.0.0 means this rule applies.
		     *   1 src port is match ether type
		     *   2 src ports (interval) is match ether type
		     *   3 src ports is match ether address
		     */
		    if ( f->fw_src.s_addr != 0 || f->fw_prot != IPPROTO_UDP
			|| f->fw_smsk.s_addr != 0xffffffff )
			continue;
		    switch (IP_FW_GETNSRCP(f)) {
		    case 1: /* match one type */
			if (  /* ( (f->fw_flg & IP_FW_F_INVSRC) != 0) ^ */
				( f->fw_uar.fw_pts[0] == ntohs(eh->ether_type) )  ) {
			    goto got_match ;
			}
			break ;
		    default:
			break ;
		    }
		    continue ;
		}

		/* Fragments */
		if ((f->fw_flg & IP_FW_F_FRAG) && offset == 0 )
			continue;

		/* If src-addr doesn't match, not this rule. */
		if (((f->fw_flg & IP_FW_F_INVSRC) != 0) ^ ((ip->ip_src.s_addr
		    & f->fw_smsk.s_addr) != f->fw_src.s_addr))
			continue;

		/* If dest-addr doesn't match, not this rule. */
		if (((f->fw_flg & IP_FW_F_INVDST) != 0) ^ ((ip->ip_dst.s_addr
		    & f->fw_dmsk.s_addr) != f->fw_dst.s_addr))
			continue;

		/* Interface check */
		if ((f->fw_flg & IF_FW_F_VIAHACK) == IF_FW_F_VIAHACK) {
			struct ifnet *const iface = oif ? oif : rif;

			/* Backwards compatibility hack for "via" */
			if (!iface || !iface_match(iface,
			    &f->fw_in_if, f->fw_flg & IP_FW_F_OIFNAME))
				continue;
		} else {
			/* Check receive interface */
			if ((f->fw_flg & IP_FW_F_IIFACE)
			    && (!rif || !iface_match(rif,
			      &f->fw_in_if, f->fw_flg & IP_FW_F_IIFNAME)))
				continue;
			/* Check outgoing interface */
			if ((f->fw_flg & IP_FW_F_OIFACE)
			    && (!oif || !iface_match(oif,
			      &f->fw_out_if, f->fw_flg & IP_FW_F_OIFNAME)))
				continue;
		}

		/* Check IP options */
		if (f->fw_ipopt != f->fw_ipnopt && !ipopts_match(ip, f))
			continue;

		/* Check protocol; if wildcard, match */
		if (f->fw_prot == IPPROTO_IP)
			goto got_match;

		/* If different, don't match */
		if (ip->ip_p != f->fw_prot) 
			continue;

/*
 * here, pip==NULL for bridged pkts -- they include the ethernet
 * header so i have to adjust lengths accordingly
 */
#define PULLUP_TO(l)	do {                                            \
			    int len = (pip ? l : l + 14 ) ;             \
			    if ((*m)->m_len < (len) ) {                 \
				if ( (*m = m_pullup(*m, (len))) == 0)   \
				    goto bogusfrag;                     \
				ip = mtod(*m, struct ip *);             \
				if (pip)                                \
				    *pip = ip ;                         \
				else                                    \
				    ip = (struct ip *)((int)ip + 14);   \
				offset = (ip->ip_off & IP_OFFMASK);     \
			    }                                           \
			} while (0)

		/* Protocol specific checks */
		switch (ip->ip_p) {
		case IPPROTO_TCP:
		    {
			struct tcphdr *tcp;

			if (offset == 1)	/* cf. RFC 1858 */
				goto bogusfrag;
			if (offset != 0) {
				/*
				 * TCP flags and ports aren't available in this
				 * packet -- if this rule specified either one,
				 * we consider the rule a non-match.
				 */
				if (f->fw_nports != 0 ||
				    f->fw_tcpf != f->fw_tcpnf)
					continue;

				break;
			}
			PULLUP_TO(hlen + 14);
			tcp = (struct tcphdr *) ((u_int32_t *)ip + ip->ip_hl);
			if (f->fw_tcpf != f->fw_tcpnf && !tcpflg_match(tcp, f))
				continue;
			src_port = ntohs(tcp->th_sport);
			dst_port = ntohs(tcp->th_dport);
			goto check_ports;
		    }

		case IPPROTO_UDP:
		    {
			struct udphdr *udp;

			if (offset != 0) {
				/*
				 * Port specification is unavailable -- if this
				 * rule specifies a port, we consider the rule
				 * a non-match.
				 */
				if (f->fw_nports != 0)
					continue;

				break;
			}
			PULLUP_TO(hlen + 4);
			udp = (struct udphdr *) ((u_int32_t *)ip + ip->ip_hl);
			src_port = ntohs(udp->uh_sport);
			dst_port = ntohs(udp->uh_dport);
check_ports:
			if (!port_match(&f->fw_uar.fw_pts[0],
			    IP_FW_GETNSRCP(f), src_port,
			    f->fw_flg & IP_FW_F_SRNG))
				continue;
			if (!port_match(&f->fw_uar.fw_pts[IP_FW_GETNSRCP(f)],
			    IP_FW_GETNDSTP(f), dst_port,
			    f->fw_flg & IP_FW_F_DRNG)) 
				continue;
			break;
		    }

		case IPPROTO_ICMP:
		    {
			struct icmp *icmp;

			if (offset != 0)	/* Type isn't valid */
				break;
			PULLUP_TO(hlen + 2);
			icmp = (struct icmp *) ((u_int32_t *)ip + ip->ip_hl);
			if (!icmptype_match(icmp, f))
				continue;
			break;
		    }
#undef PULLUP_TO

bogusfrag:
			if (fw_verbose)
				ipfw_report(NULL, ip, rif, oif);
			goto dropit;
		}

got_match:
		*flow_id = chain ; /* XXX set flow id */
		/* Update statistics */
		f->fw_pcnt += 1;
		if (ip) {
		    f->fw_bcnt += ip->ip_len;
		}
		f->timestamp = time_second;

		/* Log to console if desired */
		if ((f->fw_flg & IP_FW_F_PRN) && fw_verbose)
			ipfw_report(f, ip, rif, oif);

		/* Take appropriate action */
		switch (f->fw_flg & IP_FW_F_COMMAND) {
		case IP_FW_F_ACCEPT:
			return(0);
		case IP_FW_F_COUNT:
			continue;
#if IPDIVERT
		case IP_FW_F_DIVERT:
			*cookie = f->fw_number;
			return(f->fw_divert_port);
#endif
		case IP_FW_F_TEE:
			/*
			 * XXX someday tee packet here, but beware that you
			 * can't use m_copym() or m_copypacket() because
			 * the divert input routine modifies the mbuf
			 * (and these routines only increment reference
			 * counts in the case of mbuf clusters), so need
			 * to write custom routine.
			 */
			continue;
		case IP_FW_F_SKIPTO: /* XXX check */
			if ( f->next_rule_ptr )
			    chain = f->next_rule_ptr ;
			else
			    chain = lookup_next_rule(chain) ;
			if (! chain) goto dropit;
			goto again ;
#if DUMMYNET
		case IP_FW_F_PIPE:
			return(f->fw_pipe_nr | 0x10000 );
#endif
#if IPFIREWALL_FORWARD
		case IP_FW_F_FWD:
			/* Change the next-hop address for this packet.
			 * Initially we'll only worry about directly
			 * reachable next-hop's, but ultimately
			 * we will work out for next-hops that aren't
			 * direct the route we would take for it. We
			 * [cs]ould leave this latter problem to
			 * ip_output.c. We hope to high [name the abode of
			 * your favourite deity] that ip_output doesn't modify
			 * the new value of next_hop (which is dst there)
			 */
			if (next_hop != NULL) /* Make sure, first... */
				*next_hop = &(f->fw_fwd_ip);
			return(0); /* Allow the packet */
#endif
		}

		/* Deny/reject this packet using this rule */
		rule = f;
		break;

	}

#if DIAGNOSTIC
	/* Rule IPFW_DEFAULT_RULE should always be there and should always match */
	if (!chain)
		panic("ip_fw: chain");
#endif

	/*
	 * At this point, we're going to drop the packet.
	 * Send a reject notice if all of the following are true:
	 *
	 * - The packet matched a reject rule
	 * - The packet is not an ICMP packet, or is an ICMP query packet
	 * - The packet is not a multicast or broadcast packet
	 */
	if ((rule->fw_flg & IP_FW_F_COMMAND) == IP_FW_F_REJECT
	    && ip
	    && (ip->ip_p != IPPROTO_ICMP || is_icmp_query(ip))
	    && !((*m)->m_flags & (M_BCAST|M_MCAST))
	    && !IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
		switch (rule->fw_reject_code) {
		case IP_FW_REJECT_RST:
		  {
			struct tcphdr *const tcp =
				(struct tcphdr *) ((u_int32_t *)ip + ip->ip_hl);
			struct tcpiphdr ti, *const tip = (struct tcpiphdr *) ip;

			if (offset != 0 || (tcp->th_flags & TH_RST))
				break;
			ti.ti_i = *((struct ipovly *) ip);
			ti.ti_t = *tcp;
			bcopy(&ti, ip, sizeof(ti));
			NTOHL(tip->ti_seq);
			NTOHL(tip->ti_ack);
			tip->ti_len = ip->ip_len - hlen - (tip->ti_off << 2);
			if (tcp->th_flags & TH_ACK) {
				tcp_respond(NULL, (void *)tip, &tip->ti_t, *m,
				    (tcp_seq)0, ntohl(tcp->th_ack), TH_RST, 0);
			} else {
				if (tcp->th_flags & TH_SYN)
					tip->ti_len++;
				tcp_respond(NULL, (void *)tip, &tip->ti_t, *m,
					    tip->ti_seq + tip->ti_len,
					    (tcp_seq)0, TH_RST|TH_ACK, 0);
			}
			*m = NULL;
			break;
		  }
		default:	/* Send an ICMP unreachable using code */
			icmp_error(*m, ICMP_UNREACH,
			    rule->fw_reject_code, 0L, 0);
			*m = NULL;
			break;
		}
	}

dropit:
	/*
	 * Finally, drop the packet.
	 */
	/* *cookie = 0; */ /* XXX is this necessary ? */
	if (*m) {
		m_freem(*m);
		*m = NULL;
	}
	return(0);
}

/*
 * when a rule is added/deleted, zero the direct pointers within
 * all firewall rules. These will be reconstructed on the fly
 * as packets are matched.
 * Must be called at splnet().
 */
static void
flush_rule_ptrs()
{
    struct ip_fw_chain *fcp ;

    for (fcp = ip_fw_chain.lh_first; fcp; fcp = fcp->chain.le_next) {
	fcp->rule->next_rule_ptr = NULL ;
    }
}

static int
add_entry(struct ip_fw_head *chainptr, struct ip_fw *frwl)
{
	struct ip_fw *ftmp = 0;
	struct ip_fw_chain *fwc = 0, *fcp, *fcpl = 0;
	u_short nbr = 0;
	int s;

	fwc = _MALLOC(sizeof *fwc, M_IPFW, M_NOWAIT);
	ftmp = _MALLOC(sizeof *ftmp, M_IPFW, M_NOWAIT);
	if (!fwc || !ftmp) {
		dprintf(("%s MALLOC said no\n", err_prefix));
		if (fwc)  FREE(fwc, M_IPFW);
		if (ftmp) FREE(ftmp, M_IPFW);
		return (ENOSPC);
	}

	bcopy(frwl, ftmp, sizeof(struct ip_fw));
	ftmp->fw_in_if.fu_via_if.name[FW_IFNLEN - 1] = '\0';
	ftmp->fw_pcnt = 0L;
	ftmp->fw_bcnt = 0L;
	ftmp->next_rule_ptr = NULL ;
	ftmp->pipe_ptr = NULL ;
	fwc->rule = ftmp;
	
	s = splnet();

	if (chainptr->lh_first == 0) {
		LIST_INSERT_HEAD(chainptr, fwc, chain);
		splx(s);
		return(0);
        }

	/* If entry number is 0, find highest numbered rule and add 100 */
	if (ftmp->fw_number == 0) {
		for (fcp = LIST_FIRST(chainptr); fcp; fcp = LIST_NEXT(fcp, chain)) {
			if (fcp->rule->fw_number != (u_short)-1)
				nbr = fcp->rule->fw_number;
			else
				break;
		}
		if (nbr < IPFW_DEFAULT_RULE - 100)
			nbr += 100;
		ftmp->fw_number = nbr;
	}

	/* Got a valid number; now insert it, keeping the list ordered */
	for (fcp = LIST_FIRST(chainptr); fcp; fcp = LIST_NEXT(fcp, chain)) {
		if (fcp->rule->fw_number > ftmp->fw_number) {
			if (fcpl) {
				LIST_INSERT_AFTER(fcpl, fwc, chain);
			} else {
				LIST_INSERT_HEAD(chainptr, fwc, chain);
			}
			break;
		} else {
			fcpl = fcp;
		}
	}
	flush_rule_ptrs();

	splx(s);
	return (0);
}

static int
del_entry(struct ip_fw_head *chainptr, u_short number)
{
	struct ip_fw_chain *fcp;

	fcp = LIST_FIRST(chainptr);
	if (number != (u_short)-1) {
		for (; fcp; fcp = LIST_NEXT(fcp, chain)) {
			if (fcp->rule->fw_number == number) {
				int s;

				/* prevent access to rules while removing them */
				s = splnet();
				while (fcp && fcp->rule->fw_number == number) {
					struct ip_fw_chain *next;

					next = LIST_NEXT(fcp, chain);
					LIST_REMOVE(fcp, chain);
#if DUMMYNET
					dn_rule_delete(fcp) ;
#endif
					flush_rule_ptrs();
					FREE(fcp->rule, M_IPFW);
					FREE(fcp, M_IPFW);
					fcp = next;
				}
				splx(s);
				return 0;
			}
		}
	}

	return (EINVAL);
}

static int
zero_entry(struct ip_fw *frwl)
{
	struct ip_fw_chain *fcp;
	int s, cleared;

	if (frwl == 0) {
		s = splnet();
		for (fcp = LIST_FIRST(&ip_fw_chain); fcp; fcp = LIST_NEXT(fcp, chain)) {
			fcp->rule->fw_bcnt = fcp->rule->fw_pcnt = 0;
			fcp->rule->timestamp = 0;
		}
		splx(s);
	}
	else {
		cleared = 0;

		/*
		 *	It's possible to insert multiple chain entries with the
		 *	same number, so we don't stop after finding the first
		 *	match if zeroing a specific entry.
		 */
		for (fcp = LIST_FIRST(&ip_fw_chain); fcp; fcp = LIST_NEXT(fcp, chain))
			if (frwl->fw_number == fcp->rule->fw_number) {
				s = splnet();
				while (fcp && frwl->fw_number == fcp->rule->fw_number) {
					fcp->rule->fw_bcnt = fcp->rule->fw_pcnt = 0;
					fcp->rule->timestamp = 0;
					fcp = LIST_NEXT(fcp, chain);
				}
				splx(s);
				cleared = 1;
				break;
			}
		if (!cleared)	/* we didn't find any matching rules */
			return (EINVAL);
	}

	if (fw_verbose) {
		if (frwl)
			printf("ipfw: Entry %d cleared.\n", frwl->fw_number);
		else
			printf("ipfw: Accounting cleared.\n");
	}

	return (0);
}

static int
check_ipfw_struct(struct ip_fw *frwl)
{
	/* Check for invalid flag bits */
	if ((frwl->fw_flg & ~IP_FW_F_MASK) != 0) {
		dprintf(("%s undefined flag bits set (flags=%x)\n",
		    err_prefix, frwl->fw_flg));
		return (EINVAL);
	}
	/* Must apply to incoming or outgoing (or both) */
	if (!(frwl->fw_flg & (IP_FW_F_IN | IP_FW_F_OUT))) {
		dprintf(("%s neither in nor out\n", err_prefix));
		return (EINVAL);
	}
	/* Empty interface name is no good */
	if (((frwl->fw_flg & IP_FW_F_IIFNAME)
	      && !*frwl->fw_in_if.fu_via_if.name)
	    || ((frwl->fw_flg & IP_FW_F_OIFNAME)
	      && !*frwl->fw_out_if.fu_via_if.name)) {
		dprintf(("%s empty interface name\n", err_prefix));
		return (EINVAL);
	}
	/* Sanity check interface matching */
	if ((frwl->fw_flg & IF_FW_F_VIAHACK) == IF_FW_F_VIAHACK) {
		;		/* allow "via" backwards compatibility */
	} else if ((frwl->fw_flg & IP_FW_F_IN)
	    && (frwl->fw_flg & IP_FW_F_OIFACE)) {
		dprintf(("%s outgoing interface check on incoming\n",
		    err_prefix));
		return (EINVAL);
	}
	/* Sanity check port ranges */
	if ((frwl->fw_flg & IP_FW_F_SRNG) && IP_FW_GETNSRCP(frwl) < 2) {
		dprintf(("%s src range set but n_src_p=%d\n",
		    err_prefix, IP_FW_GETNSRCP(frwl)));
		return (EINVAL);
	}
	if ((frwl->fw_flg & IP_FW_F_DRNG) && IP_FW_GETNDSTP(frwl) < 2) {
		dprintf(("%s dst range set but n_dst_p=%d\n",
		    err_prefix, IP_FW_GETNDSTP(frwl)));
		return (EINVAL);
	}
	if (IP_FW_GETNSRCP(frwl) + IP_FW_GETNDSTP(frwl) > IP_FW_MAX_PORTS) {
		dprintf(("%s too many ports (%d+%d)\n",
		    err_prefix, IP_FW_GETNSRCP(frwl), IP_FW_GETNDSTP(frwl)));
		return (EINVAL);
	}
	/*
	 *	Protocols other than TCP/UDP don't use port range
	 */
	if ((frwl->fw_prot != IPPROTO_TCP) &&
	    (frwl->fw_prot != IPPROTO_UDP) &&
	    (IP_FW_GETNSRCP(frwl) || IP_FW_GETNDSTP(frwl))) {
		dprintf(("%s port(s) specified for non TCP/UDP rule\n",
		    err_prefix));
		return (EINVAL);
	}

	/*
	 *	Rather than modify the entry to make such entries work, 
	 *	we reject this rule and require user level utilities
	 *	to enforce whatever policy they deem appropriate.
	 */
	if ((frwl->fw_src.s_addr & (~frwl->fw_smsk.s_addr)) || 
		(frwl->fw_dst.s_addr & (~frwl->fw_dmsk.s_addr))) {
		dprintf(("%s rule never matches\n", err_prefix));
		return (EINVAL);
	}

	if ((frwl->fw_flg & IP_FW_F_FRAG) &&
		(frwl->fw_prot == IPPROTO_UDP || frwl->fw_prot == IPPROTO_TCP)) {
		if (frwl->fw_nports) {
			dprintf(("%s cannot mix 'frag' and ports\n", err_prefix));
			return (EINVAL);
		}
		if (frwl->fw_prot == IPPROTO_TCP &&
			frwl->fw_tcpf != frwl->fw_tcpnf) {
			dprintf(("%s cannot mix 'frag' and TCP flags\n", err_prefix));
			return (EINVAL);
		}
	}

	/* Check command specific stuff */
	switch (frwl->fw_flg & IP_FW_F_COMMAND)
	{
	case IP_FW_F_REJECT:
		if (frwl->fw_reject_code >= 0x100
		    && !(frwl->fw_prot == IPPROTO_TCP
		      && frwl->fw_reject_code == IP_FW_REJECT_RST)) {
			dprintf(("%s unknown reject code\n", err_prefix));
			return (EINVAL);
		}
		break;
	case IP_FW_F_DIVERT:		/* Diverting to port zero is invalid */
	case IP_FW_F_PIPE:              /* piping through 0 is invalid */
	case IP_FW_F_TEE:
		if (frwl->fw_divert_port == 0) {
			dprintf(("%s can't divert to port 0\n", err_prefix));
			return (EINVAL);
		}
		break;
	case IP_FW_F_DENY:
	case IP_FW_F_ACCEPT:
	case IP_FW_F_COUNT:
	case IP_FW_F_SKIPTO:
#if IPFIREWALL_FORWARD
	case IP_FW_F_FWD:
#endif
		break;
	default:
		dprintf(("%s invalid command\n", err_prefix));
		return (EINVAL);
	}

	return 0;
}

static int
ip_fw_ctl(struct sockopt *sopt)
{
	int error, s;
	size_t size;
	char *buf, *bp;
	struct ip_fw_chain *fcp;
	struct ip_fw frwl;

	/* Disallow sets in really-really secure mode. */
	if (sopt->sopt_dir == SOPT_SET && securelevel >= 3)
			return (EPERM);
	error = 0;

	switch (sopt->sopt_name) {
	case IP_FW_GET:
		for (fcp = LIST_FIRST(&ip_fw_chain), size = 0; fcp;
		     fcp = LIST_NEXT(fcp, chain))
			size += sizeof *fcp->rule;
		buf = _MALLOC(size, M_TEMP, M_WAITOK);
		if (buf == 0) {
			error = ENOBUFS;
			break;
		}

		for (fcp = LIST_FIRST(&ip_fw_chain), bp = buf; fcp;
		     fcp = LIST_NEXT(fcp, chain)) {
			bcopy(fcp->rule, bp, sizeof *fcp->rule);
			bp += sizeof *fcp->rule;
		}
		error = sooptcopyout(sopt, buf, size);
		FREE(buf, M_TEMP);
		break;

	case IP_FW_FLUSH:
		for (fcp = ip_fw_chain.lh_first; 
		     fcp != 0 && fcp->rule->fw_number != IPFW_DEFAULT_RULE;
		     fcp = ip_fw_chain.lh_first) {
			s = splnet();
			LIST_REMOVE(fcp, chain);
			FREE(fcp->rule, M_IPFW);
			FREE(fcp, M_IPFW);
			splx(s);
		}
		break;

	case IP_FW_ZERO:
		if (sopt->sopt_val != 0) {
			error = sooptcopyin(sopt, &frwl, sizeof frwl,
					    sizeof frwl);
			if (error || (error = zero_entry(&frwl)))
				break;
		} else {
			error = zero_entry(0);
		}
		break;

	case IP_FW_ADD:
		error = sooptcopyin(sopt, &frwl, sizeof frwl, sizeof frwl);
		if (error || (error = check_ipfw_struct(&frwl)))
			break;

		if (frwl.fw_number == IPFW_DEFAULT_RULE) {
			dprintf(("%s can't add rule %u\n", err_prefix,
				 (unsigned)IPFW_DEFAULT_RULE));
			error = EINVAL;
		} else {
			error = add_entry(&ip_fw_chain, &frwl);
		}
		break;

	case IP_FW_DEL:
		error = sooptcopyin(sopt, &frwl, sizeof frwl, sizeof frwl);
		if (error)
			break;

		if (frwl.fw_number == IPFW_DEFAULT_RULE) {
			dprintf(("%s can't delete rule %u\n", err_prefix,
				 (unsigned)IPFW_DEFAULT_RULE));
			error = EINVAL;
		} else {
			error = del_entry(&ip_fw_chain, frwl.fw_number);
		}
		break;

	default:
		printf("ip_fw_ctl invalid option %d\n", sopt->sopt_name);
		error = EINVAL ;
	}

	return (error);
}

struct ip_fw_chain *ip_fw_default_rule ;

void
ip_fw_init(void)
{
	struct ip_fw default_rule;

	ip_fw_chk_ptr = ip_fw_chk;
	ip_fw_ctl_ptr = ip_fw_ctl;
	LIST_INIT(&ip_fw_chain);

	bzero(&default_rule, sizeof default_rule);
	default_rule.fw_prot = IPPROTO_IP;
	default_rule.fw_number = IPFW_DEFAULT_RULE;
#if IPFIREWALL_DEFAULT_TO_ACCEPT
	default_rule.fw_flg |= IP_FW_F_ACCEPT;
#else
	default_rule.fw_flg |= IP_FW_F_DENY;
#endif
	default_rule.fw_flg |= IP_FW_F_IN | IP_FW_F_OUT;
	if (check_ipfw_struct(&default_rule) != 0 ||
	    add_entry(&ip_fw_chain, &default_rule))
		panic("ip_fw_init");

	ip_fw_default_rule = ip_fw_chain.lh_first ;
	printf("IP packet filtering initialized, "
#if IPDIVERT
		"divert enabled, ");
#else
		"divert disabled, ");
#endif
#if IPFIREWALL_FORWARD
	printf("rule-based forwarding enabled, ");
#else
	printf("rule-based forwarding disabled, ");
#endif
#if IPFIREWALL_DEFAULT_TO_ACCEPT
	printf("default to accept, ");
#endif
#ifndef IPFIREWALL_VERBOSE
	printf("logging disabled\n");
#else
	if (fw_verbose_limit == 0)
		printf("unlimited logging\n");
	else
		printf("logging limited to %d packets/entry\n",
		    fw_verbose_limit);
#endif
}

#if ISFB31

/*
 * ### LD 08/04/99: This is used if IPFIREWALL is a FreeBSD "KLD" module
 *     Right now, we're linked to the kernel all the time
 *     will be fixed with the use of an NKE?
 *
 * Note: ip_fw_init is called from div_init() in xnu
 */ 

static ip_fw_chk_t *old_chk_ptr;
static ip_fw_ctl_t *old_ctl_ptr;

#if defined(IPFIREWALL_MODULE) && !defined(KLD_MODULE)

#include <sys/exec.h>
#include <sys/sysent.h>
#include <sys/lkm.h>

MOD_MISC(ipfw);

static int
ipfw_load(struct lkm_table *lkmtp, int cmd)
{
	int s=splnet();

	old_chk_ptr = ip_fw_chk_ptr;
	old_ctl_ptr = ip_fw_ctl_ptr;

	ip_fw_init();
	splx(s);
	return 0;
}

static int
ipfw_unload(struct lkm_table *lkmtp, int cmd)
{
	int s=splnet();

	ip_fw_chk_ptr =  old_chk_ptr;
	ip_fw_ctl_ptr =  old_ctl_ptr;

	while (LIST_FIRST(&ip_fw_chain) != NULL) {
		struct ip_fw_chain *fcp = LIST_FIRST(&ip_fw_chain);
		LIST_REMOVE(LIST_FIRST(&ip_fw_chain), chain);
		FREE(fcp->rule, M_IPFW);
		FREE(fcp, M_IPFW);
	}
	
	splx(s);
	printf("IP firewall unloaded\n");
	return 0;
}

int
ipfw_mod(struct lkm_table *lkmtp, int cmd, int ver)
{
	MOD_DISPATCH(ipfw, lkmtp, cmd, ver,
		ipfw_load, ipfw_unload, lkm_nullcmd);
}
#else
static int
ipfw_modevent(module_t mod, int type, void *unused)
{
	int s;
	
	switch (type) {
	case MOD_LOAD:
		s = splnet();

		old_chk_ptr = ip_fw_chk_ptr;
		old_ctl_ptr = ip_fw_ctl_ptr;

		ip_fw_init();
		splx(s);
		return 0;
	case MOD_UNLOAD:
		s = splnet();

		ip_fw_chk_ptr =  old_chk_ptr;
		ip_fw_ctl_ptr =  old_ctl_ptr;

		while (LIST_FIRST(&ip_fw_chain) != NULL) {
			struct ip_fw_chain *fcp = LIST_FIRST(&ip_fw_chain);
			LIST_REMOVE(LIST_FIRST(&ip_fw_chain), chain);
			FREE(fcp->rule, M_IPFW);
			FREE(fcp, M_IPFW);
		}
	
		splx(s);
		printf("IP firewall unloaded\n");
		return 0;
	default:
		break;
	}
	return 0;
}

static moduledata_t ipfwmod = {
	"ipfw",
	ipfw_modevent,
	0
};
DECLARE_MODULE(ipfw, ipfwmod, SI_SUB_PSEUDO, SI_ORDER_ANY);
#endif
#endif /* ISFB31 */
#endif /* IPFIREWALL_KEXT */

