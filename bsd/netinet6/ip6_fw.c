/*	$KAME: ip6_fw.c,v 1.11 2000/03/10 04:22:18 k-sugyou Exp $	*/

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
 *	$Id: ip6_fw.c,v 1.3 2001/05/01 21:52:50 lindak Exp $
 */

/*
 * Implement IPv6 packet firewall
 */

#ifdef __FreeBSD__
#include "opt_ip6fw.h"
#if __FreeBSD__ >= 3
#include "opt_inet.h"
#endif
#endif

#if IP6DIVERT
#error "NOT SUPPORTED IPV6 DIVERT"
#endif
#if IP6FW_DIVERT_RESTART
#error "NOT SUPPORTED IPV6 DIVERT"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <kern/queue.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
#include <sys/socketvar.h>
#endif
#include <sys/time.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#include <netinet/icmp6.h>

#include <netinet/in_pcb.h>

#include <netinet6/ip6_fw.h>
#if TCP6
#include <netinet6/tcp6.h>
#include <netinet6/tcp6_timer.h>
#include <netinet6/tcp6_var.h>
#endif
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <vm/vm.h>
#endif
#if __FreeBSD__ || defined (__APPLE__)
#include <sys/sysctl.h>
#endif

#include <net/net_osdep.h>

#if defined(__FreeBSD__) && __FreeBSD__ >= 3
MALLOC_DEFINE(M_IP6FW, "Ip6Fw/Ip6Acct", "Ip6Fw/Ip6Acct chain's");
#else
#ifndef M_IP6FW
#define M_IP6FW	M_TEMP
#endif
#endif

static int fw6_debug = 1;
#if IPV6FIREWALL_VERBOSE
static int fw6_verbose = 1;
#else
static int fw6_verbose = 0;
#endif
#if IPV6FIREWALL_VERBOSE_LIMIT
static int fw6_verbose_limit = IPV6FIREWALL_VERBOSE_LIMIT;
#else
static int fw6_verbose_limit = 0;
#endif

LIST_HEAD (ip6_fw_head, ip6_fw_chain) ip6_fw_chain;

SYSCTL_DECL(_net_inet6_ip6);
SYSCTL_NODE(_net_inet6_ip6, OID_AUTO, fw, CTLFLAG_RW, 0, "Firewall");
SYSCTL_INT(_net_inet6_ip6_fw, IP6FWCTL_DEBUG, debug, CTLFLAG_RW, &fw6_debug, 0, "");
SYSCTL_INT(_net_inet6_ip6_fw, IP6FWCTL_VERBOSE, verbose, CTLFLAG_RW, &fw6_verbose, 0, "");
SYSCTL_INT(_net_inet6_ip6_fw, IP6FWCTL_VERBLIMIT, verbose_limit, CTLFLAG_RW, &fw6_verbose_limit, 0, "");

#define dprintf(a)	if (!fw6_debug); else printf a

#define print_ip6(a)	printf("[%s]", ip6_sprintf(a))

#define dprint_ip6(a)	if (!fw6_debug); else print_ip6(a)

static int	add_entry6 __P((struct ip6_fw_head *chainptr, struct ip6_fw *frwl));
static int	del_entry6 __P((struct ip6_fw_head *chainptr, u_short number));
static int	zero_entry6 __P((struct mbuf *m));
static struct ip6_fw *check_ip6fw_struct __P((struct ip6_fw *m));
static struct ip6_fw *check_ip6fw_mbuf __P((struct mbuf *fw));
static int	ip6opts_match __P((struct ip6_hdr **ip6, struct ip6_fw *f,
				   struct mbuf **m,
				   int *off, int *nxt, u_short *offset));
static int	port_match6 __P((u_short *portptr, int nports, u_short port,
				int range_flag));
static int	tcp6flg_match __P((struct tcphdr *tcp6, struct ip6_fw *f));
static int	icmp6type_match __P((struct icmp6_hdr *  icmp, struct ip6_fw * f));
static void	ip6fw_report __P((struct ip6_fw *f, struct ip6_hdr *ip6,
				struct ifnet *rif, struct ifnet *oif, int off, int nxt));

static int	ip6_fw_chk __P((struct ip6_hdr **pip6,
			struct ifnet *oif, u_int16_t *cookie, struct mbuf **m));
static int	ip6_fw_ctl __P((int stage, struct mbuf **mm));

static char err_prefix[] = "ip6_fw_ctl:";

/*
 * Returns 1 if the port is matched by the vector, 0 otherwise
 */
static
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
__inline
#else
inline
#endif
int
port_match6(u_short *portptr, int nports, u_short port, int range_flag)
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
tcp6flg_match(struct tcphdr *tcp6, struct ip6_fw *f)
{
	u_char		flg_set, flg_clr;
	
	if ((f->fw_tcpf & IPV6_FW_TCPF_ESTAB) &&
	    (tcp6->th_flags & (IPV6_FW_TCPF_RST | IPV6_FW_TCPF_ACK)))
		return 1;

	flg_set = tcp6->th_flags & f->fw_tcpf;
	flg_clr = tcp6->th_flags & f->fw_tcpnf;

	if (flg_set != f->fw_tcpf)
		return 0;
	if (flg_clr)
		return 0;

	return 1;
}

static int
icmp6type_match(struct icmp6_hdr *icmp6, struct ip6_fw *f)
{
	int type;

	if (!(f->fw_flg & IPV6_FW_F_ICMPBIT))
		return(1);

	type = icmp6->icmp6_type;

	/* check for matching type in the bitmap */
	if (type < IPV6_FW_ICMPTYPES_DIM * sizeof(unsigned) * 8 &&
		(f->fw_icmp6types[type / (sizeof(unsigned) * 8)] &
		(1U << (type % (8 * sizeof(unsigned))))))
		return(1);

	return(0); /* no match */
}

static int
is_icmp6_query(struct ip6_hdr *ip6, int off)
{
	const struct icmp6_hdr *icmp6;
	int icmp6_type;

	icmp6 = (struct icmp6_hdr *)((caddr_t)ip6 + off);
	icmp6_type = icmp6->icmp6_type;

	if (icmp6_type == ICMP6_ECHO_REQUEST ||
	    icmp6_type == ICMP6_MEMBERSHIP_QUERY ||
	    icmp6_type == ICMP6_WRUREQUEST ||
	    icmp6_type == ICMP6_FQDN_QUERY ||
	    icmp6_type == ICMP6_NI_QUERY)
		return(1);

	return(0);
}

static int
ip6opts_match(struct ip6_hdr **pip6, struct ip6_fw *f, struct mbuf **m,
	      int *off, int *nxt, u_short *offset)
{
	int len;
	struct ip6_hdr *ip6 = *pip6;
	struct ip6_ext *ip6e;
	u_char	opts, nopts, nopts_sve;

	opts = f->fw_ip6opt;
	nopts = nopts_sve = f->fw_ip6nopt;

	*nxt = ip6->ip6_nxt;
	*off = sizeof(struct ip6_hdr);
	len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
	while (*off < len) {
		ip6e = (struct ip6_ext *)((caddr_t) ip6 + *off);
		if ((*m)->m_len < *off + sizeof(*ip6e))
			goto opts_check;	/* XXX */

		switch(*nxt) {
		case IPPROTO_FRAGMENT:
			if ((*m)->m_len < *off + sizeof(struct ip6_frag)) {
				struct ip6_frag *ip6f;

				ip6f = (struct ip6_frag *) ((caddr_t)ip6 + *off);
				*offset = ip6f->ip6f_offlg | IP6F_OFF_MASK;
			}
			opts &= ~IPV6_FW_IP6OPT_FRAG;
			nopts &= ~IPV6_FW_IP6OPT_FRAG;
			*off += sizeof(struct ip6_frag);
			break;
		case IPPROTO_AH:
			opts &= ~IPV6_FW_IP6OPT_AH;
			nopts &= ~IPV6_FW_IP6OPT_AH;
			*off += (ip6e->ip6e_len + 2) << 2;
			break;
		default:
			switch (*nxt) {
			case IPPROTO_HOPOPTS:
				opts &= ~IPV6_FW_IP6OPT_HOPOPT;
				nopts &= ~IPV6_FW_IP6OPT_HOPOPT;
				break;
			case IPPROTO_ROUTING:
				opts &= ~IPV6_FW_IP6OPT_ROUTE;
				nopts &= ~IPV6_FW_IP6OPT_ROUTE;
				break;
			case IPPROTO_ESP:
				opts &= ~IPV6_FW_IP6OPT_ESP;
				nopts &= ~IPV6_FW_IP6OPT_ESP;
				break;
			case IPPROTO_NONE:
				opts &= ~IPV6_FW_IP6OPT_NONXT;
				nopts &= ~IPV6_FW_IP6OPT_NONXT;
				goto opts_check;
				break;
			case IPPROTO_DSTOPTS:
				opts &= ~IPV6_FW_IP6OPT_OPTS;
				nopts &= ~IPV6_FW_IP6OPT_OPTS;
				break;
			default:
				goto opts_check;
				break;
			}
			*off += (ip6e->ip6e_len + 1) << 3;
			break;
		}
		*nxt = ip6e->ip6e_nxt;

	}
 opts_check:
	if (f->fw_ip6opt == f->fw_ip6nopt)	/* XXX */
		return 1;

	if (opts == 0 && nopts == nopts_sve)
		return 1;
	else
		return 0;
}

static
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
__inline
#else
inline
#endif
int
iface_match(struct ifnet *ifp, union ip6_fw_if *ifu, int byname)
{
	/* Check by name or by IP address */
	if (byname) {
#if __NetBSD__
	    {
		char xname[IFNAMSIZ];
		snprintf(xname, sizeof(xname), "%s%d", ifu->fu_via_if.name,
			ifu->fu_via_if.unit);
		if (strcmp(ifp->if_xname, xname))
			return(0);
	    }
#else
		/* Check unit number (-1 is wildcard) */
		if (ifu->fu_via_if.unit != -1
		    && ifp->if_unit != ifu->fu_via_if.unit)
			return(0);
		/* Check name */
		if (strncmp(ifp->if_name, ifu->fu_via_if.name, FW_IFNLEN))
			return(0);
#endif
		return(1);
	} else if (!IN6_IS_ADDR_UNSPECIFIED(&ifu->fu_via_ip6)) {	/* Zero == wildcard */
		struct ifaddr *ia;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
		for (ia = ifp->if_addrlist; ia; ia = ia->ifa_next)
#else
		for (ia = ifp->if_addrlist.tqh_first; ia; ia = ia->ifa_list.tqe_next)
#endif
		{

			if (ia->ifa_addr == NULL)
				continue;
			if (ia->ifa_addr->sa_family != AF_INET6)
				continue;
			if (!IN6_ARE_ADDR_EQUAL(&ifu->fu_via_ip6,
			    &(((struct sockaddr_in6 *)
			    (ia->ifa_addr))->sin6_addr)))
				continue;
			return(1);
		}
		return(0);
	}
	return(1);
}

static void
ip6fw_report(struct ip6_fw *f, struct ip6_hdr *ip6,
	struct ifnet *rif, struct ifnet *oif, int off, int nxt)
{
	static int counter;
	struct tcphdr *const tcp6 = (struct tcphdr *) ((caddr_t) ip6+ off);
	struct udphdr *const udp = (struct udphdr *) ((caddr_t) ip6+ off);
	struct icmp6_hdr *const icmp6 = (struct icmp6_hdr *) ((caddr_t) ip6+ off);
	int count;

	count = f ? f->fw_pcnt : ++counter;
	if (fw6_verbose_limit != 0 && count > fw6_verbose_limit)
		return;

	/* Print command name */
	printf("ip6fw: %d ", f ? f->fw_number : -1);
	if (!f)
		printf("Refuse");
	else
		switch (f->fw_flg & IPV6_FW_F_COMMAND) {
		case IPV6_FW_F_DENY:
			printf("Deny");
			break;
		case IPV6_FW_F_REJECT:
			if (f->fw_reject_code == IPV6_FW_REJECT_RST)
				printf("Reset");
			else
				printf("Unreach");
			break;
		case IPV6_FW_F_ACCEPT:
			printf("Accept");
			break;
		case IPV6_FW_F_COUNT:
			printf("Count");
			break;
		case IPV6_FW_F_DIVERT:
			printf("Divert %d", f->fw_divert_port);
			break;
		case IPV6_FW_F_TEE:
			printf("Tee %d", f->fw_divert_port);
			break;
		case IPV6_FW_F_SKIPTO:
			printf("SkipTo %d", f->fw_skipto_rule);
			break;
		default:	
			printf("UNKNOWN");
			break;
		}
	printf(" ");

	switch (nxt) {
	case IPPROTO_TCP:
		printf("TCP ");
		print_ip6(&ip6->ip6_src);
		if (off > 0)
			printf(":%d ", ntohs(tcp6->th_sport));
		else
			printf(" ");
		print_ip6(&ip6->ip6_dst);
		if (off > 0)
			printf(":%d", ntohs(tcp6->th_dport));
		break;
	case IPPROTO_UDP:
		printf("UDP ");
		print_ip6(&ip6->ip6_src);
		if (off > 0)
			printf(":%d ", ntohs(udp->uh_sport));
		else
			printf(" ");
		print_ip6(&ip6->ip6_dst);
		if (off > 0)
			printf(":%d", ntohs(udp->uh_dport));
		break;
	case IPPROTO_ICMPV6:
		if (off > 0)
			printf("IPV6-ICMP:%u.%u ", icmp6->icmp6_type, icmp6->icmp6_code);
		else
			printf("IPV6-ICMP ");
		print_ip6(&ip6->ip6_src);
		printf(" ");
		print_ip6(&ip6->ip6_dst);
		break;
	default:
		printf("P:%d ", nxt);
		print_ip6(&ip6->ip6_src);
		printf(" ");
		print_ip6(&ip6->ip6_dst);
		break;
	}
	if (oif)
		printf(" out via %s", if_name(oif));
	else if (rif)
		printf(" in via %s", if_name(rif));
	printf("\n");
	if (fw6_verbose_limit != 0 && count == fw6_verbose_limit)
		printf("ip6fw: limit reached on rule #%d\n",
		f ? f->fw_number : -1);
}

/*
 * Parameters:
 *
 *	ip	Pointer to packet header (struct ip6_hdr *)
 *	hlen	Packet header length
 *	oif	Outgoing interface, or NULL if packet is incoming
 * #ifndef IP6FW_DIVERT_RESTART
 *	*cookie	Ignore all divert/tee rules to this port (if non-zero)
 * #else
 *	*cookie Skip up to the first rule past this rule number;
 * #endif
 *	*m	The packet; we set to NULL when/if we nuke it.
 *
 * Return value:
 *
 *	0	The packet is to be accepted and routed normally OR
 *      	the packet was denied/rejected and has been dropped;
 *		in the latter case, *m is equal to NULL upon return.
 *	port	Divert the packet to port.
 */

static int
ip6_fw_chk(struct ip6_hdr **pip6,
	struct ifnet *oif, u_int16_t *cookie, struct mbuf **m)
{
	struct ip6_fw_chain *chain;
	struct ip6_fw *rule = NULL;
	struct ip6_hdr *ip6 = *pip6;
	struct ifnet *const rif = (*m)->m_pkthdr.rcvif;
	u_short offset = 0;
	int off = sizeof(struct ip6_hdr), nxt = ip6->ip6_nxt;
	u_short src_port, dst_port;
#if	IP6FW_DIVERT_RESTART
	u_int16_t skipto = *cookie;
#else
	u_int16_t ignport = ntohs(*cookie);
#endif

	*cookie = 0;
	/*
	 * Go down the chain, looking for enlightment
	 * #if IP6FW_DIVERT_RESTART
	 * If we've been asked to start at a given rule immediatly, do so.
	 * #endif
	 */
	chain = LIST_FIRST(&ip6_fw_chain);
#if IP6FW_DIVERT_RESTART
	if (skipto) {
		if (skipto >= 65535)
			goto dropit;
		while (chain && (chain->rule->fw_number <= skipto)) {
			chain = LIST_NEXT(chain, chain);
		}
		if (! chain) goto dropit;
	}
#endif /* IP6FW_DIVERT_RESTART */
	for (; chain; chain = LIST_NEXT(chain, chain)) {
		register struct ip6_fw *const f = chain->rule;

		if (oif) {
			/* Check direction outbound */
			if (!(f->fw_flg & IPV6_FW_F_OUT))
				continue;
		} else {
			/* Check direction inbound */
			if (!(f->fw_flg & IPV6_FW_F_IN))
				continue;
		}

#define IN6_ARE_ADDR_MASKEQUAL(x,y,z) (\
	(((x)->s6_addr32[0] & (y)->s6_addr32[0]) == (z)->s6_addr32[0]) && \
	(((x)->s6_addr32[1] & (y)->s6_addr32[1]) == (z)->s6_addr32[1]) && \
	(((x)->s6_addr32[2] & (y)->s6_addr32[2]) == (z)->s6_addr32[2]) && \
	(((x)->s6_addr32[3] & (y)->s6_addr32[3]) == (z)->s6_addr32[3]))

		/* If src-addr doesn't match, not this rule. */
		if (((f->fw_flg & IPV6_FW_F_INVSRC) != 0) ^
			(!IN6_ARE_ADDR_MASKEQUAL(&ip6->ip6_src,&f->fw_smsk,&f->fw_src)))
			continue;

		/* If dest-addr doesn't match, not this rule. */
		if (((f->fw_flg & IPV6_FW_F_INVDST) != 0) ^
			(!IN6_ARE_ADDR_MASKEQUAL(&ip6->ip6_dst,&f->fw_dmsk,&f->fw_dst)))
			continue;

#undef IN6_ARE_ADDR_MASKEQUAL
		/* Interface check */
		if ((f->fw_flg & IF6_FW_F_VIAHACK) == IF6_FW_F_VIAHACK) {
			struct ifnet *const iface = oif ? oif : rif;

			/* Backwards compatibility hack for "via" */
			if (!iface || !iface_match(iface,
			    &f->fw_in_if, f->fw_flg & IPV6_FW_F_OIFNAME))
				continue;
		} else {
			/* Check receive interface */
			if ((f->fw_flg & IPV6_FW_F_IIFACE)
			    && (!rif || !iface_match(rif,
			      &f->fw_in_if, f->fw_flg & IPV6_FW_F_IIFNAME)))
				continue;
			/* Check outgoing interface */
			if ((f->fw_flg & IPV6_FW_F_OIFACE)
			    && (!oif || !iface_match(oif,
			      &f->fw_out_if, f->fw_flg & IPV6_FW_F_OIFNAME)))
				continue;
		}

		/* Check IP options */
		if (!ip6opts_match(&ip6, f, m, &off, &nxt, &offset))
			continue;

		/* Fragments */
		if ((f->fw_flg & IPV6_FW_F_FRAG) && !offset)
			continue;

		/* Check protocol; if wildcard, match */
		if (f->fw_prot == IPPROTO_IPV6)
			goto got_match;

		/* If different, don't match */
		if (nxt != f->fw_prot)
			continue;

#define PULLUP_TO(len)	do {						\
			    if ((*m)->m_len < (len)			\
				&& (*m = m_pullup(*m, (len))) == 0) {	\
				    goto dropit;			\
			    }						\
			    *pip6 = ip6 = mtod(*m, struct ip6_hdr *);	\
			} while (0)

		/* Protocol specific checks */
		switch (nxt) {
		case IPPROTO_TCP:
		    {
			struct tcphdr *tcp6;

			if (offset == 1) {	/* cf. RFC 1858 */
				PULLUP_TO(off + 4); /* XXX ? */
				goto bogusfrag;
			}
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
			PULLUP_TO(off + 14);
			tcp6 = (struct tcphdr *) ((caddr_t)ip6 + off);
			if (f->fw_tcpf != f->fw_tcpnf && !tcp6flg_match(tcp6, f))
				continue;
			src_port = ntohs(tcp6->th_sport);
			dst_port = ntohs(tcp6->th_dport);
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
			PULLUP_TO(off + 4);
			udp = (struct udphdr *) ((caddr_t)ip6 + off);
			src_port = ntohs(udp->uh_sport);
			dst_port = ntohs(udp->uh_dport);
check_ports:
			if (!port_match6(&f->fw_pts[0],
			    IPV6_FW_GETNSRCP(f), src_port,
			    f->fw_flg & IPV6_FW_F_SRNG))
				continue;
			if (!port_match6(&f->fw_pts[IPV6_FW_GETNSRCP(f)],
			    IPV6_FW_GETNDSTP(f), dst_port,
			    f->fw_flg & IPV6_FW_F_DRNG))
				continue;
			break;
		    }

		case IPPROTO_ICMPV6:
		    {
			struct icmp6_hdr *icmp;

			if (offset != 0)	/* Type isn't valid */
				break;
			PULLUP_TO(off + 2);
			icmp = (struct icmp6_hdr *) ((caddr_t)ip6 + off);
			if (!icmp6type_match(icmp, f))
				continue;
			break;
		    }
#undef PULLUP_TO

bogusfrag:
			if (fw6_verbose)
				ip6fw_report(NULL, ip6, rif, oif, off, nxt);
			goto dropit;
		}

got_match:
#ifndef IP6FW_DIVERT_RESTART
		/* Ignore divert/tee rule if socket port is "ignport" */
		switch (f->fw_flg & IPV6_FW_F_COMMAND) {
		case IPV6_FW_F_DIVERT:
		case IPV6_FW_F_TEE:
			if (f->fw_divert_port == ignport)
				continue;       /* ignore this rule */
			break;
		}

#endif /* IP6FW_DIVERT_RESTART */
		/* Update statistics */
		f->fw_pcnt += 1;
		f->fw_bcnt += ntohs(ip6->ip6_plen);
#if defined(__FreeBSD__) && __FreeBSD__ >= 3
		f->timestamp = time_second;
#else
		f->timestamp = time.tv_sec;
#endif

		/* Log to console if desired */
		if ((f->fw_flg & IPV6_FW_F_PRN) && fw6_verbose)
			ip6fw_report(f, ip6, rif, oif, off, nxt);

		/* Take appropriate action */
		switch (f->fw_flg & IPV6_FW_F_COMMAND) {
		case IPV6_FW_F_ACCEPT:
			return(0);
		case IPV6_FW_F_COUNT:
			continue;
		case IPV6_FW_F_DIVERT:
#if IP6FW_DIVERT_RESTART
			*cookie = f->fw_number;
#else
			*cookie = htons(f->fw_divert_port);
#endif /* IP6FW_DIVERT_RESTART */
			return(f->fw_divert_port);
		case IPV6_FW_F_TEE:
			/*
			 * XXX someday tee packet here, but beware that you
			 * can't use m_copym() or m_copypacket() because
			 * the divert input routine modifies the mbuf
			 * (and these routines only increment reference
			 * counts in the case of mbuf clusters), so need
			 * to write custom routine.
			 */
			continue;
		case IPV6_FW_F_SKIPTO:
#if DIAGNOSTIC
			while (chain->chain.le_next
			    && chain->chain.le_next->rule->fw_number
				< f->fw_skipto_rule)
#else
			while (chain->chain.le_next->rule->fw_number
			    < f->fw_skipto_rule)
#endif
				chain = chain->chain.le_next;
			continue;
		}

		/* Deny/reject this packet using this rule */
		rule = f;
		break;
	}

#if DIAGNOSTIC
	/* Rule 65535 should always be there and should always match */
	if (!chain)
		panic("ip6_fw: chain");
#endif

	/*
	 * At this point, we're going to drop the packet.
	 * Send a reject notice if all of the following are true:
	 *
	 * - The packet matched a reject rule
	 * - The packet is not an ICMP packet, or is an ICMP query packet
	 * - The packet is not a multicast or broadcast packet
	 */
	if ((rule->fw_flg & IPV6_FW_F_COMMAND) == IPV6_FW_F_REJECT
	    && (nxt != IPPROTO_ICMPV6 || is_icmp6_query(ip6, off))
	    && !((*m)->m_flags & (M_BCAST|M_MCAST))
	    && !IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		switch (rule->fw_reject_code) {
		case IPV6_FW_REJECT_RST:
#if 1	/*not tested*/
		  {
			struct tcphdr *const tcp =
				(struct tcphdr *) ((caddr_t)ip6 + off);
			struct {
				struct ip6_hdr ip6;
				struct tcphdr th;
			} ti;
			tcp_seq ack, seq;
			int flags;

			if (offset != 0 || (tcp->th_flags & TH_RST))
				break;

			ti.ip6 = *ip6;
			ti.th = *tcp;
			NTOHL(ti.th.th_seq);
			NTOHL(ti.th.th_ack);
			ti.ip6.ip6_nxt = IPPROTO_TCP;
			if (ti.th.th_flags & TH_ACK) {
				ack = 0;
				seq = ti.th.th_ack;
				flags = TH_RST;
			} else {
				ack = ti.th.th_seq;
				if (((*m)->m_flags & M_PKTHDR) != 0) {
					ack += (*m)->m_pkthdr.len - off
						- (ti.th.th_off << 2);
				} else if (ip6->ip6_plen) {
					ack += ntohs(ip6->ip6_plen) + sizeof(*ip6)
						- off - (ti.th.th_off << 2);
				} else {
					m_freem(*m);
					*m = 0;
					break;
				}
				seq = 0;
				flags = TH_RST|TH_ACK;
			}
			bcopy(&ti, ip6, sizeof(ti));
#if TCP6
			tcp6_respond(NULL, ip6, (struct tcp6hdr *)(ip6 + 1),
				*m, ack, seq, flags);
#elif defined(__NetBSD__)
			tcp_respond(NULL, NULL, *m, (struct tcphdr *)(ip6 + 1),
				ack, seq, flags);
#elif defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
			tcp_respond(NULL, ip6, (struct tcphdr *)(ip6 + 1),
				*m, ack, seq, flags, 1);
#else
			m_freem(*m);
#endif
			*m = NULL;
			break;
		  }
#endif
		default:	/* Send an ICMP unreachable using code */
			if (oif)
				(*m)->m_pkthdr.rcvif = oif;
			icmp6_error(*m, ICMP6_DST_UNREACH,
			    rule->fw_reject_code, 0);
			*m = NULL;
			break;
		}
	}

dropit:
	/*
	 * Finally, drop the packet.
	 */
	if (*m) {
		m_freem(*m);
		*m = NULL;
	}
	return(0);
}

static int
add_entry6(struct ip6_fw_head *chainptr, struct ip6_fw *frwl)
{
	struct ip6_fw *ftmp = 0;
	struct ip6_fw_chain *fwc = 0, *fcp, *fcpl = 0;
	u_short nbr = 0;
	int s;

	fwc = _MALLOC(sizeof *fwc, M_IP6FW, M_NOWAIT);
	ftmp = _MALLOC(sizeof *ftmp, M_IP6FW, M_NOWAIT);
	if (!fwc || !ftmp) {
		dprintf(("%s malloc said no\n", err_prefix));
		if (fwc)  _FREE(fwc, M_IP6FW);
		if (ftmp) _FREE(ftmp, M_IP6FW);
		return (ENOSPC);
	}

	bcopy(frwl, ftmp, sizeof(struct ip6_fw));
	ftmp->fw_in_if.fu_via_if.name[FW_IFNLEN - 1] = '\0';
	ftmp->fw_pcnt = 0L;
	ftmp->fw_bcnt = 0L;
	fwc->rule = ftmp;
	
	s = splnet();

	if (!chainptr->lh_first) {
		LIST_INSERT_HEAD(chainptr, fwc, chain);
		splx(s);
		return(0);
        } else if (ftmp->fw_number == (u_short)-1) {
		if (fwc)  _FREE(fwc, M_IP6FW);
		if (ftmp) _FREE(ftmp, M_IP6FW);
		splx(s);
		dprintf(("%s bad rule number\n", err_prefix));
		return (EINVAL);
        }

	/* If entry number is 0, find highest numbered rule and add 100 */
	if (ftmp->fw_number == 0) {
		for (fcp = chainptr->lh_first; fcp; fcp = fcp->chain.le_next) {
			if (fcp->rule->fw_number != (u_short)-1)
				nbr = fcp->rule->fw_number;
			else
				break;
		}
		if (nbr < (u_short)-1 - 100)
			nbr += 100;
		ftmp->fw_number = nbr;
	}

	/* Got a valid number; now insert it, keeping the list ordered */
	for (fcp = chainptr->lh_first; fcp; fcp = fcp->chain.le_next) {
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

	splx(s);
	return (0);
}

static int
del_entry6(struct ip6_fw_head *chainptr, u_short number)
{
	struct ip6_fw_chain *fcp;
	int s;

	s = splnet();

	fcp = chainptr->lh_first;
	if (number != (u_short)-1) {
		for (; fcp; fcp = fcp->chain.le_next) {
			if (fcp->rule->fw_number == number) {
				LIST_REMOVE(fcp, chain);
				splx(s);
				_FREE(fcp->rule, M_IP6FW);
				_FREE(fcp, M_IP6FW);
				return 0;
			}
		}
	}

	splx(s);
	return (EINVAL);
}

static int
zero_entry6(struct mbuf *m)
{
	struct ip6_fw *frwl;
	struct ip6_fw_chain *fcp;
	int s;

	if (m) {
		if (m->m_len != sizeof(struct ip6_fw))
			return(EINVAL);
		frwl = mtod(m, struct ip6_fw *);
	}
	else
		frwl = NULL;

	/*
	 *	It's possible to insert multiple chain entries with the
	 *	same number, so we don't stop after finding the first
	 *	match if zeroing a specific entry.
	 */
	s = splnet();
	for (fcp = ip6_fw_chain.lh_first; fcp; fcp = fcp->chain.le_next)
		if (!frwl || frwl->fw_number == fcp->rule->fw_number) {
			fcp->rule->fw_bcnt = fcp->rule->fw_pcnt = 0;
			fcp->rule->timestamp = 0;
		}
	splx(s);

	if (fw6_verbose) {
		if (frwl)
			printf("ip6fw: Entry %d cleared.\n", frwl->fw_number);
		else
			printf("ip6fw: Accounting cleared.\n");
	}

	return(0);
}

static struct ip6_fw *
check_ip6fw_mbuf(struct mbuf *m)
{
	/* Check length */
	if (m->m_len != sizeof(struct ip6_fw)) {
		dprintf(("%s len=%d, want %d\n", err_prefix, m->m_len,
		    sizeof(struct ip6_fw)));
		return (NULL);
	}
	return(check_ip6fw_struct(mtod(m, struct ip6_fw *)));
}

static struct ip6_fw *
check_ip6fw_struct(struct ip6_fw *frwl)
{
	/* Check for invalid flag bits */
	if ((frwl->fw_flg & ~IPV6_FW_F_MASK) != 0) {
		dprintf(("%s undefined flag bits set (flags=%x)\n",
		    err_prefix, frwl->fw_flg));
		return (NULL);
	}
	/* Must apply to incoming or outgoing (or both) */
	if (!(frwl->fw_flg & (IPV6_FW_F_IN | IPV6_FW_F_OUT))) {
		dprintf(("%s neither in nor out\n", err_prefix));
		return (NULL);
	}
	/* Empty interface name is no good */
	if (((frwl->fw_flg & IPV6_FW_F_IIFNAME)
	      && !*frwl->fw_in_if.fu_via_if.name)
	    || ((frwl->fw_flg & IPV6_FW_F_OIFNAME)
	      && !*frwl->fw_out_if.fu_via_if.name)) {
		dprintf(("%s empty interface name\n", err_prefix));
		return (NULL);
	}
	/* Sanity check interface matching */
	if ((frwl->fw_flg & IF6_FW_F_VIAHACK) == IF6_FW_F_VIAHACK) {
		;		/* allow "via" backwards compatibility */
	} else if ((frwl->fw_flg & IPV6_FW_F_IN)
	    && (frwl->fw_flg & IPV6_FW_F_OIFACE)) {
		dprintf(("%s outgoing interface check on incoming\n",
		    err_prefix));
		return (NULL);
	}
	/* Sanity check port ranges */
	if ((frwl->fw_flg & IPV6_FW_F_SRNG) && IPV6_FW_GETNSRCP(frwl) < 2) {
		dprintf(("%s src range set but n_src_p=%d\n",
		    err_prefix, IPV6_FW_GETNSRCP(frwl)));
		return (NULL);
	}
	if ((frwl->fw_flg & IPV6_FW_F_DRNG) && IPV6_FW_GETNDSTP(frwl) < 2) {
		dprintf(("%s dst range set but n_dst_p=%d\n",
		    err_prefix, IPV6_FW_GETNDSTP(frwl)));
		return (NULL);
	}
	if (IPV6_FW_GETNSRCP(frwl) + IPV6_FW_GETNDSTP(frwl) > IPV6_FW_MAX_PORTS) {
		dprintf(("%s too many ports (%d+%d)\n",
		    err_prefix, IPV6_FW_GETNSRCP(frwl), IPV6_FW_GETNDSTP(frwl)));
		return (NULL);
	}
	/*
	 *	Protocols other than TCP/UDP don't use port range
	 */
	if ((frwl->fw_prot != IPPROTO_TCP) &&
	    (frwl->fw_prot != IPPROTO_UDP) &&
	    (IPV6_FW_GETNSRCP(frwl) || IPV6_FW_GETNDSTP(frwl))) {
		dprintf(("%s port(s) specified for non TCP/UDP rule\n",
		    err_prefix));
		return(NULL);
	}

	/*
	 *	Rather than modify the entry to make such entries work,
	 *	we reject this rule and require user level utilities
	 *	to enforce whatever policy they deem appropriate.
	 */
	if ((frwl->fw_src.s6_addr32[0] & (~frwl->fw_smsk.s6_addr32[0])) ||
		(frwl->fw_src.s6_addr32[1] & (~frwl->fw_smsk.s6_addr32[1])) ||
		(frwl->fw_src.s6_addr32[2] & (~frwl->fw_smsk.s6_addr32[2])) ||
		(frwl->fw_src.s6_addr32[3] & (~frwl->fw_smsk.s6_addr32[3])) ||
		(frwl->fw_dst.s6_addr32[0] & (~frwl->fw_dmsk.s6_addr32[0])) ||
		(frwl->fw_dst.s6_addr32[1] & (~frwl->fw_dmsk.s6_addr32[1])) ||
		(frwl->fw_dst.s6_addr32[2] & (~frwl->fw_dmsk.s6_addr32[2])) ||
		(frwl->fw_dst.s6_addr32[3] & (~frwl->fw_dmsk.s6_addr32[3]))) {
		dprintf(("%s rule never matches\n", err_prefix));
		return(NULL);
	}

	if ((frwl->fw_flg & IPV6_FW_F_FRAG) &&
		(frwl->fw_prot == IPPROTO_UDP || frwl->fw_prot == IPPROTO_TCP)) {
		if (frwl->fw_nports) {
			dprintf(("%s cannot mix 'frag' and ports\n", err_prefix));
			return(NULL);
		}
		if (frwl->fw_prot == IPPROTO_TCP &&
			frwl->fw_tcpf != frwl->fw_tcpnf) {
			dprintf(("%s cannot mix 'frag' with TCP flags\n", err_prefix));
			return(NULL);
		}
	}

	/* Check command specific stuff */
	switch (frwl->fw_flg & IPV6_FW_F_COMMAND)
	{
	case IPV6_FW_F_REJECT:
		if (frwl->fw_reject_code >= 0x100
		    && !(frwl->fw_prot == IPPROTO_TCP
		      && frwl->fw_reject_code == IPV6_FW_REJECT_RST)) {
			dprintf(("%s unknown reject code\n", err_prefix));
			return(NULL);
		}
		break;
	case IPV6_FW_F_DIVERT:		/* Diverting to port zero is invalid */
	case IPV6_FW_F_TEE:
		if (frwl->fw_divert_port == 0) {
			dprintf(("%s can't divert to port 0\n", err_prefix));
			return (NULL);
		}
		break;
	case IPV6_FW_F_DENY:
	case IPV6_FW_F_ACCEPT:
	case IPV6_FW_F_COUNT:
	case IPV6_FW_F_SKIPTO:
		break;
	default:
		dprintf(("%s invalid command\n", err_prefix));
		return(NULL);
	}

	return frwl;
}

static int
ip6_fw_ctl(int stage, struct mbuf **mm)
{
	int error;
	struct mbuf *m;

	if (stage == IPV6_FW_GET) {
		struct ip6_fw_chain *fcp = ip6_fw_chain.lh_first;
#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
		*mm = m = m_get(M_WAIT, MT_DATA); /* XXX */
#else
		*mm = m = m_get(M_WAIT, MT_SOOPTS);
#endif
		if (!m)
			return(ENOBUFS);
		if (sizeof *(fcp->rule) > MLEN) {
			MCLGET(m, M_WAIT);
			if ((m->m_flags & M_EXT) == 0) {
				m_free(m);
				return(ENOBUFS);
			}
		}
		for (; fcp; fcp = fcp->chain.le_next) {
			memcpy(m->m_data, fcp->rule, sizeof *(fcp->rule));
			m->m_len = sizeof *(fcp->rule);
#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined (__APPLE__)
			m->m_next = m_get(M_WAIT, MT_DATA); /* XXX */
#else
			m->m_next = m_get(M_WAIT, MT_SOOPTS);
#endif
			if (!m->m_next) {
				m_freem(*mm);
				return(ENOBUFS);
			}
			m = m->m_next;
			if (sizeof *(fcp->rule) > MLEN) {
				MCLGET(m, M_WAIT);
				if ((m->m_flags & M_EXT) == 0) {
					m_freem(*mm);
					return(ENOBUFS);
				}
			}
			m->m_len = 0;
		}
		return (0);
	}
	m = *mm;
	/* only allow get calls if secure mode > 2 */
	if (securelevel > 2) {
		if (m) {
			(void)m_freem(m);
			*mm = 0;
		}
		return(EPERM);
	}
	if (stage == IPV6_FW_FLUSH) {
		while (ip6_fw_chain.lh_first != NULL && 
		    ip6_fw_chain.lh_first->rule->fw_number != (u_short)-1) {
			struct ip6_fw_chain *fcp = ip6_fw_chain.lh_first;
			int s = splnet();
			LIST_REMOVE(ip6_fw_chain.lh_first, chain);
			splx(s);
			_FREE(fcp->rule, M_IP6FW);
			_FREE(fcp, M_IP6FW);
		}
		if (m) {
			(void)m_freem(m);
			*mm = 0;
		}
		return (0);
	}
	if (stage == IPV6_FW_ZERO) {
		error = zero_entry6(m);
		if (m) {
			(void)m_freem(m);
			*mm = 0;
		}
		return (error);
	}
	if (m == NULL) {
		printf("%s NULL mbuf ptr\n", err_prefix);
		return (EINVAL);
	}

	if (stage == IPV6_FW_ADD) {
		struct ip6_fw *frwl = check_ip6fw_mbuf(m);

		if (!frwl)
			error = EINVAL;
		else
			error = add_entry6(&ip6_fw_chain, frwl);
		if (m) {
			(void)m_freem(m);
			*mm = 0;
		}
		return error;
	}
	if (stage == IPV6_FW_DEL) {
		if (m->m_len != sizeof(struct ip6_fw)) {
			dprintf(("%s len=%d, want %d\n", err_prefix, m->m_len,
			    sizeof(struct ip6_fw)));
			error = EINVAL;
		} else if (mtod(m, struct ip6_fw *)->fw_number == (u_short)-1) {
			dprintf(("%s can't delete rule 65535\n", err_prefix));
			error = EINVAL;
		} else
			error = del_entry6(&ip6_fw_chain,
			    mtod(m, struct ip6_fw *)->fw_number);
		if (m) {
			(void)m_freem(m);
			*mm = 0;
		}
		return error;
	}

	dprintf(("%s unknown request %d\n", err_prefix, stage));
	if (m) {
		(void)m_freem(m);
		*mm = 0;
	}
	return (EINVAL);
}

void
ip6_fw_init(void)
{
	struct ip6_fw default_rule;

	ip6_fw_chk_ptr = ip6_fw_chk;
	ip6_fw_ctl_ptr = ip6_fw_ctl;
	LIST_INIT(&ip6_fw_chain);

	bzero(&default_rule, sizeof default_rule);
	default_rule.fw_prot = IPPROTO_IPV6;
	default_rule.fw_number = (u_short)-1;
#if IPV6FIREWALL_DEFAULT_TO_ACCEPT
	default_rule.fw_flg |= IPV6_FW_F_ACCEPT;
#else
	default_rule.fw_flg |= IPV6_FW_F_DENY;
#endif
	default_rule.fw_flg |= IPV6_FW_F_IN | IPV6_FW_F_OUT;
	if (check_ip6fw_struct(&default_rule) == NULL ||
		add_entry6(&ip6_fw_chain, &default_rule))
		panic(__FUNCTION__);

#if 1	/* NOT SUPPORTED IPV6 DIVERT */
	printf("IPv6 packet filtering initialized, ");
#else
	printf("IPv6 packet filtering initialized, "
#if IP6DIVERT
		"divert enabled, ");
#else
		"divert disabled, ");
#endif
#endif
#if IPV6FIREWALL_DEFAULT_TO_ACCEPT
	printf("default to accept, ");
#endif
#ifndef IPV6FIREWALL_VERBOSE
	printf("logging disabled\n");
#else
	if (fw6_verbose_limit == 0)
		printf("unlimited logging\n");
	else
		printf("logging limited to %d packets/entry\n",
		    fw6_verbose_limit);
#endif
}
