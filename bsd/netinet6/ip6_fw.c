/*
 * Copyright (c) 2003-2012 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/ip6_fw.c,v 1.2.2.9 2002/04/28 05:40:27 suz Exp $	*/
/*	$KAME: ip6_fw.c,v 1.21 2001/01/24 01:25:32 itojun Exp $	*/

/*
 * Copyright (C) 1998, 1999, 2000 and 2001 WIDE Project.
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
 */

/*
 * Implement IPv6 packet firewall
 */


#ifdef IP6DIVERT
#error "NOT SUPPORTED IPV6 DIVERT"
#endif
#ifdef IP6FW_DIVERT_RESTART
#error "NOT SUPPORTED IPV6 DIVERT"
#endif

#include <string.h>
#include <machine/spl.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/lock.h>
#include <sys/time.h>
#include <sys/kern_event.h>

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
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>

#include <sys/sysctl.h>

#include <net/net_osdep.h>

MALLOC_DEFINE(M_IP6FW, "Ip6Fw/Ip6Acct", "Ip6Fw/Ip6Acct chain's");

static int fw6_debug = 0;
#ifdef IPV6FIREWALL_VERBOSE
static int fw6_verbose = 1;
#else
static int fw6_verbose = 0;
#endif
#ifdef IPV6FIREWALL_VERBOSE_LIMIT
static int fw6_verbose_limit = IPV6FIREWALL_VERBOSE_LIMIT;
#else
static int fw6_verbose_limit = 0;
#endif

LIST_HEAD (ip6_fw_head, ip6_fw_chain) ip6_fw_chain;

static void ip6fw_kev_post_msg(u_int32_t );

#ifdef SYSCTL_NODE
static int ip6fw_sysctl SYSCTL_HANDLER_ARGS;

SYSCTL_DECL(_net_inet6_ip6);
SYSCTL_NODE(_net_inet6_ip6, OID_AUTO, fw, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Firewall");
SYSCTL_PROC(_net_inet6_ip6_fw, OID_AUTO, enable, 
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip6_fw_enable, 0, ip6fw_sysctl, "I", "Enable ip6fw");
SYSCTL_INT(_net_inet6_ip6_fw, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED, &fw6_debug, 0, "");
SYSCTL_INT(_net_inet6_ip6_fw, OID_AUTO, verbose, CTLFLAG_RW | CTLFLAG_LOCKED, &fw6_verbose, 0, "");
SYSCTL_INT(_net_inet6_ip6_fw, OID_AUTO, verbose_limit, CTLFLAG_RW | CTLFLAG_LOCKED, &fw6_verbose_limit, 0, "");

static int
ip6fw_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	
	error = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	if (error || !req->newptr)
		return (error);
	
	ip6fw_kev_post_msg(KEV_IP6FW_ENABLE);
	
	return error;
}

#endif

#define dprintf(a)	do {						\
				if (fw6_debug)				\
					printf a;			\
			} while (0)
#define SNPARGS(buf, len) buf + len, sizeof(buf) > len ? sizeof(buf) - len : 0

static int	add_entry6 __P((struct ip6_fw_head *chainptr, struct ip6_fw *frwl));
static int	del_entry6 __P((struct ip6_fw_head *chainptr, u_short number));
static int	zero_entry6 __P((struct ip6_fw *frwl));
static struct ip6_fw *check_ip6fw_struct __P((struct ip6_fw *m));
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
static int	ip6_fw_ctl __P((struct sockopt *));
static void cp_to_user_64( struct ip6_fw_64 *userrule_64, struct ip6_fw *rule);
static void cp_from_user_64( struct ip6_fw_64 *userrule_64, struct ip6_fw *rule);
static void cp_to_user_32( struct ip6_fw_32 *userrule_32, struct ip6_fw *rule);
static void cp_from_user_32( struct ip6_fw_32 *userrule_32, struct ip6_fw *rule);

static char err_prefix[] = "ip6_fw_ctl:";

/*
 * Returns 1 if the port is matched by the vector, 0 otherwise
 */
static
__inline int
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
	
	/*
	 * If an established connection is required, reject packets that
	 * have only SYN of RST|ACK|SYN set.  Otherwise, fall through to
	 * other flag requirements.
	 */
	if ((f->fw_ipflg & IPV6_FW_IF_TCPEST) &&
	    ((tcp6->th_flags & (IPV6_FW_TCPF_RST | IPV6_FW_TCPF_ACK |
	    IPV6_FW_TCPF_SYN)) == IPV6_FW_TCPF_SYN))
		return 0;

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
			if ((*m)->m_len >= *off + sizeof(struct ip6_frag)) {
				struct ip6_frag *ip6f;

				ip6f = (struct ip6_frag *) ((caddr_t)ip6 + *off);
				*offset = ip6f->ip6f_offlg & IP6F_OFF_MASK;
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
__inline int
iface_match(struct ifnet *ifp, union ip6_fw_if *ifu, int byname)
{
	/* Check by name or by IP address */
	if (byname) {
		/* Check unit number (-1 is wildcard) */
		if (ifu->fu_via_if.unit != -1
		    && ifp->if_unit != ifu->fu_via_if.unit)
			return(0);
		/* Check name */
		if (strncmp(ifp->if_name, ifu->fu_via_if.name, IP6FW_IFNLEN))
			return(0);
		return(1);
	} else if (!IN6_IS_ADDR_UNSPECIFIED(&ifu->fu_via_ip6)) {	/* Zero == wildcard */
		struct ifaddr *ia;

		ifnet_lock_shared(ifp);
		for (ia = ifp->if_addrlist.tqh_first; ia;
		    ia = ia->ifa_list.tqe_next)
		{
			IFA_LOCK_SPIN(ia);
			if (ia->ifa_addr->sa_family != AF_INET6) {
				IFA_UNLOCK(ia);
				continue;
			}
			if (!IN6_ARE_ADDR_EQUAL(&ifu->fu_via_ip6,
			    &(((struct sockaddr_in6 *)
			    (ia->ifa_addr))->sin6_addr))) {
				IFA_UNLOCK(ia);
				continue;
			}
			IFA_UNLOCK(ia);
			ifnet_lock_done(ifp);
			return(1);
		}
		ifnet_lock_done(ifp);
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
	const char *action;
	char action2[32], proto[102], name[18];
	int len;

	count = f ? f->fw_pcnt : ++counter;
	if (fw6_verbose_limit != 0 && count > fw6_verbose_limit)
		return;

	/* Print command name */
	snprintf(SNPARGS(name, 0), "ip6fw: %d", f ? f->fw_number : -1);

	action = action2;
	if (!f)
		action = "Refuse";
	else {
		switch (f->fw_flg & IPV6_FW_F_COMMAND) {
		case IPV6_FW_F_DENY:
			action = "Deny";
			break;
		case IPV6_FW_F_REJECT:
			if (f->fw_reject_code == IPV6_FW_REJECT_RST)
				action = "Reset";
			else
				action = "Unreach";
			break;
		case IPV6_FW_F_ACCEPT:
			action = "Accept";
			break;
		case IPV6_FW_F_COUNT:
			action = "Count";
			break;
		case IPV6_FW_F_DIVERT:
			snprintf(SNPARGS(action2, 0), "Divert %d",
			    f->fw_divert_port);
			break;
		case IPV6_FW_F_TEE:
			snprintf(SNPARGS(action2, 0), "Tee %d",
			    f->fw_divert_port);
			break;
		case IPV6_FW_F_SKIPTO:
			snprintf(SNPARGS(action2, 0), "SkipTo %d",
			    f->fw_skipto_rule);
			break;
		default:	
			action = "UNKNOWN";
			break;
		}
	}

	switch (nxt) {
	case IPPROTO_TCP:
		len = snprintf(SNPARGS(proto, 0), "TCP [%s]",
		    ip6_sprintf(&ip6->ip6_src));
		if (off > 0)
			len += snprintf(SNPARGS(proto, len), ":%d ",
			    ntohs(tcp6->th_sport));
		else
			len += snprintf(SNPARGS(proto, len), " ");
		len += snprintf(SNPARGS(proto, len), "[%s]",
		    ip6_sprintf(&ip6->ip6_dst));
		if (off > 0)
			snprintf(SNPARGS(proto, len), ":%d",
			    ntohs(tcp6->th_dport));
		break;
	case IPPROTO_UDP:
		len = snprintf(SNPARGS(proto, 0), "UDP [%s]",
		    ip6_sprintf(&ip6->ip6_src));
		if (off > 0)
			len += snprintf(SNPARGS(proto, len), ":%d ",
			    ntohs(udp->uh_sport));
		else
		    len += snprintf(SNPARGS(proto, len), " ");
		len += snprintf(SNPARGS(proto, len), "[%s]",
		    ip6_sprintf(&ip6->ip6_dst));
		if (off > 0)
			snprintf(SNPARGS(proto, len), ":%d",
			    ntohs(udp->uh_dport));
		break;
	case IPPROTO_ICMPV6:
		if (off > 0)
			len = snprintf(SNPARGS(proto, 0), "IPV6-ICMP:%u.%u ",
			    icmp6->icmp6_type, icmp6->icmp6_code);
		else
			len = snprintf(SNPARGS(proto, 0), "IPV6-ICMP ");
		len += snprintf(SNPARGS(proto, len), "[%s]",
		    ip6_sprintf(&ip6->ip6_src));
		snprintf(SNPARGS(proto, len), " [%s]",
		    ip6_sprintf(&ip6->ip6_dst));
		break;
	default:
		len = snprintf(SNPARGS(proto, 0), "P:%d [%s]", nxt,
		    ip6_sprintf(&ip6->ip6_src));
		snprintf(SNPARGS(proto, len), " [%s]",
		    ip6_sprintf(&ip6->ip6_dst));
		break;
	}

	if (oif)
		log(LOG_AUTHPRIV | LOG_INFO, "%s %s %s out via %s\n",
		    name, action, proto, if_name(oif));
	else if (rif)
		log(LOG_AUTHPRIV | LOG_INFO, "%s %s %s in via %s\n",
		    name, action, proto, if_name(rif));
	else
		log(LOG_AUTHPRIV | LOG_INFO, "%s %s %s",
		    name, action, proto);
	if (fw6_verbose_limit != 0 && count == fw6_verbose_limit)
	    log(LOG_AUTHPRIV | LOG_INFO, "ip6fw: limit reached on entry %d\n",
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
	struct ifnet *const rif = ((*m)->m_flags & M_LOOP) ? lo_ifp : (*m)->m_pkthdr.rcvif;
	u_short offset = 0;
	int off = sizeof(struct ip6_hdr), nxt = ip6->ip6_nxt;
	u_short src_port, dst_port;
#ifdef	IP6FW_DIVERT_RESTART
	u_int16_t skipto = *cookie;
#else
	u_int16_t ignport = ntohs(*cookie);
#endif
	struct timeval timenow;

	getmicrotime(&timenow);

	*cookie = 0;
	/*
	 * Go down the chain, looking for enlightment
	 * #ifdef IP6FW_DIVERT_RESTART
	 * If we've been asked to start at a given rule immediatly, do so.
	 * #endif
	 */
	chain = LIST_FIRST(&ip6_fw_chain);
#ifdef IP6FW_DIVERT_RESTART
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
		struct ip6_fw *const f = chain->rule;

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
			if (((f->fw_tcpf != f->fw_tcpnf) ||
			   (f->fw_ipflg & IPV6_FW_IF_TCPEST))  &&
			   !tcp6flg_match(tcp6, f))
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
		f->timestamp = timenow.tv_sec;

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
#ifdef IP6FW_DIVERT_RESTART
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
#ifdef DIAGNOSTIC
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

#ifdef DIAGNOSTIC
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
			ti.th.th_seq = ntohl(ti.th.th_seq);
			ti.th.th_ack = ntohl(ti.th.th_ack);
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
			tcp_respond(NULL, ip6, (struct tcphdr *)(ip6 + 1),
				*m, ack, seq, flags, IFSCOPE_NONE, 0);
			*m = NULL;
			break;
		  }
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

	fwc = _MALLOC(sizeof *fwc, M_IP6FW, M_WAITOK);
	ftmp = _MALLOC(sizeof *ftmp, M_IP6FW, M_WAITOK);
	if (!fwc || !ftmp) {
		dprintf(("%s malloc said no\n", err_prefix));
		if (fwc)  FREE(fwc, M_IP6FW);
		if (ftmp) FREE(ftmp, M_IP6FW);
		return (ENOSPC);
	}

	bcopy(frwl, ftmp, sizeof(struct ip6_fw));
	ftmp->fw_in_if.fu_via_if.name[IP6FW_IFNLEN - 1] = '\0';
	ftmp->fw_pcnt = 0L;
	ftmp->fw_bcnt = 0L;
	fwc->rule = ftmp;
	
	s = splnet();

	if (!chainptr->lh_first) {
		LIST_INSERT_HEAD(chainptr, fwc, chain);
		splx(s);
		return(0);
        } else if (ftmp->fw_number == (u_short)-1) {
		if (fwc)  FREE(fwc, M_IP6FW);
		if (ftmp) FREE(ftmp, M_IP6FW);
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

	bcopy(ftmp, frwl, sizeof(struct ip6_fw));
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
				FREE(fcp->rule, M_IP6FW);
				FREE(fcp, M_IP6FW);
				return 0;
			}
		}
	}

	splx(s);
	return (EINVAL);
}

static int
zero_entry6(struct ip6_fw *frwl)
{
	struct ip6_fw_chain *fcp;
	int s;

	/*
	 *	It's possible to insert multiple chain entries with the
	 *	same number, so we don't stop after finding the first
	 *	match if zeroing a specific entry.
	 */
	s = splnet();
	for (fcp = ip6_fw_chain.lh_first; fcp; fcp = fcp->chain.le_next)
		if (!frwl || frwl->fw_number == 0 || frwl->fw_number == fcp->rule->fw_number) {
			fcp->rule->fw_bcnt = fcp->rule->fw_pcnt = 0;
			fcp->rule->timestamp = 0;
		}
	splx(s);

	if (fw6_verbose) {
		if (frwl)
			log(LOG_AUTHPRIV | LOG_NOTICE,
			    "ip6fw: Entry %d cleared.\n", frwl->fw_number);
		else
			log(LOG_AUTHPRIV | LOG_NOTICE,
			    "ip6fw: Accounting cleared.\n");
	}

	return(0);
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

static void
ip6fw_kev_post_msg(u_int32_t event_code)
{
	struct kev_msg		ev_msg;

	bzero(&ev_msg, sizeof(struct kev_msg));
	
	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_FIREWALL_CLASS;
	ev_msg.kev_subclass = KEV_IP6FW_SUBCLASS;
	ev_msg.event_code = event_code;

	kev_post_msg(&ev_msg);

}


static void
cp_to_user_64( struct ip6_fw_64 *userrule_64, struct ip6_fw *rule)
{
	userrule_64->version = rule->version;
	userrule_64->context = CAST_USER_ADDR_T(rule->context);
	userrule_64->fw_pcnt = rule->fw_pcnt;
	userrule_64->fw_bcnt = rule->fw_bcnt;
	userrule_64->fw_src = rule->fw_src;
	userrule_64->fw_dst = rule->fw_dst;
	userrule_64->fw_smsk = rule->fw_smsk;
	userrule_64->fw_dmsk = rule->fw_dmsk;
	userrule_64->fw_number = rule->fw_number;
	userrule_64->fw_flg = rule->fw_flg;
	userrule_64->fw_ipflg = rule->fw_ipflg;
	bcopy( rule->fw_pts, userrule_64->fw_pts, IPV6_FW_MAX_PORTS);
	userrule_64->fw_ip6opt= rule->fw_ip6opt;
	userrule_64->fw_ip6nopt = rule->fw_ip6nopt;
	userrule_64->fw_tcpf = rule->fw_tcpf;
	userrule_64->fw_tcpnf = rule->fw_tcpnf;
	bcopy( rule->fw_icmp6types, userrule_64->fw_icmp6types, sizeof(userrule_64->fw_icmp6types));
	userrule_64->fw_in_if = rule->fw_in_if;
	userrule_64->fw_out_if = rule->fw_out_if;
	userrule_64->timestamp = rule->timestamp;
	userrule_64->fw_un.fu_divert_port = rule->fw_un.fu_divert_port;
	userrule_64->fw_prot = rule->fw_prot;
	userrule_64->fw_nports = rule->fw_nports;
}


static void
cp_from_user_64( struct ip6_fw_64 *userrule_64, struct ip6_fw *rule)
{
	rule->version = userrule_64->version;
	rule->context = CAST_DOWN(void *, userrule_64->context);
	rule->fw_pcnt = userrule_64->fw_pcnt;
	rule->fw_bcnt = userrule_64->fw_bcnt;
	rule->fw_src = userrule_64->fw_src;
	rule->fw_dst = userrule_64->fw_dst;
	rule->fw_smsk = userrule_64->fw_smsk;
	rule->fw_dmsk = userrule_64->fw_dmsk;
	rule->fw_number = userrule_64->fw_number;
	rule->fw_flg = userrule_64->fw_flg;
	rule->fw_ipflg = userrule_64->fw_ipflg;
	bcopy( userrule_64->fw_pts, rule->fw_pts, IPV6_FW_MAX_PORTS);
	rule->fw_ip6opt  = userrule_64->fw_ip6opt;
	rule->fw_ip6nopt = userrule_64->fw_ip6nopt;
	rule->fw_tcpf = userrule_64->fw_tcpf;
	rule->fw_tcpnf = userrule_64->fw_tcpnf;
	bcopy( userrule_64->fw_icmp6types, rule->fw_icmp6types, sizeof(userrule_64->fw_icmp6types));
	rule->fw_in_if = userrule_64->fw_in_if;
	rule->fw_out_if = userrule_64->fw_out_if;
	rule->timestamp = CAST_DOWN( long, userrule_64->timestamp);
	rule->fw_un.fu_divert_port = userrule_64->fw_un.fu_divert_port;
	rule->fw_prot = userrule_64->fw_prot;
	rule->fw_nports = userrule_64->fw_nports;
}


static void
cp_to_user_32( struct ip6_fw_32 *userrule_32, struct ip6_fw *rule)
{
	userrule_32->version = rule->version;
	userrule_32->context = CAST_DOWN_EXPLICIT( user32_addr_t, rule->context);
	userrule_32->fw_pcnt = rule->fw_pcnt;
	userrule_32->fw_bcnt = rule->fw_bcnt;
	userrule_32->fw_src = rule->fw_src;
	userrule_32->fw_dst = rule->fw_dst;
	userrule_32->fw_smsk = rule->fw_smsk;
	userrule_32->fw_dmsk = rule->fw_dmsk;
	userrule_32->fw_number = rule->fw_number;
	userrule_32->fw_flg = rule->fw_flg;
	userrule_32->fw_ipflg = rule->fw_ipflg;
	bcopy( rule->fw_pts, userrule_32->fw_pts, IPV6_FW_MAX_PORTS);
	userrule_32->fw_ip6opt = rule->fw_ip6opt ;
	userrule_32->fw_ip6nopt = rule->fw_ip6nopt;
	userrule_32->fw_tcpf = rule->fw_tcpf;
	userrule_32->fw_tcpnf = rule->fw_tcpnf;
	bcopy( rule->fw_icmp6types, userrule_32->fw_icmp6types, sizeof(rule->fw_icmp6types));
	userrule_32->fw_in_if = rule->fw_in_if;
	userrule_32->fw_out_if = rule->fw_out_if;
	userrule_32->timestamp = rule->timestamp;
	userrule_32->fw_un.fu_divert_port = rule->fw_un.fu_divert_port;
	userrule_32->fw_prot = rule->fw_prot;
	userrule_32->fw_nports = rule->fw_nports;
}


static void
cp_from_user_32( struct ip6_fw_32 *userrule_32, struct ip6_fw *rule)
{
	rule->version = userrule_32->version;
	rule->context = CAST_DOWN(void *, userrule_32->context);
	rule->fw_pcnt = userrule_32->fw_pcnt;
	rule->fw_bcnt = userrule_32->fw_bcnt;
	rule->fw_src = userrule_32->fw_src;
	rule->fw_dst = userrule_32->fw_dst;
	rule->fw_smsk = userrule_32->fw_smsk;
	rule->fw_dmsk = userrule_32->fw_dmsk;
	rule->fw_number = userrule_32->fw_number;
	rule->fw_flg = userrule_32->fw_flg;
	rule->fw_ipflg = userrule_32->fw_ipflg;
	bcopy( userrule_32->fw_pts, rule->fw_pts, IPV6_FW_MAX_PORTS);
	rule->fw_ip6opt  = userrule_32->fw_ip6opt;
	rule->fw_ip6nopt = userrule_32->fw_ip6nopt;
	rule->fw_tcpf = userrule_32->fw_tcpf;
	rule->fw_tcpnf = userrule_32->fw_tcpnf;
	bcopy( userrule_32->fw_icmp6types, rule->fw_icmp6types, sizeof(userrule_32->fw_icmp6types));
	rule->fw_in_if = userrule_32->fw_in_if;
	rule->fw_out_if = userrule_32->fw_out_if;
	rule->timestamp = CAST_DOWN(long, userrule_32->timestamp);
	rule->fw_un.fu_divert_port = userrule_32->fw_un.fu_divert_port;
	rule->fw_prot = userrule_32->fw_prot;
	rule->fw_nports = userrule_32->fw_nports;
}

static int
ip6_fw_ctl(struct sockopt *sopt)
{
	int error = 0;
	int spl;
	int valsize;
	struct ip6_fw rule;
	int is64user=0;
	size_t	userrulesize;

	if (securelevel >= 3 &&
		(sopt->sopt_dir != SOPT_GET || sopt->sopt_name != IPV6_FW_GET))
		return (EPERM);

	if ( proc_is64bit(sopt->sopt_p) ){
		is64user = 1;
		userrulesize = sizeof( struct ip6_fw_64 );
	} else
		userrulesize = sizeof( struct ip6_fw_32 );
	
	/* We ALWAYS expect the client to pass in a rule structure so that we can
	 * check the version of the API that they are using.  In the case of a
	 * IPV6_FW_GET operation, the first rule of the output buffer passed to us
	 * must have the version set. */
	if (!sopt->sopt_val || sopt->sopt_valsize < userrulesize) return EINVAL;

	/* save sopt->sopt_valsize */
	valsize = sopt->sopt_valsize;
	
	if (is64user){
		struct ip6_fw_64 userrule_64;
		
		if ((error = sooptcopyin(sopt, &userrule_64, userrulesize, userrulesize)))
			return error;
		
		cp_from_user_64( &userrule_64, &rule );
	}
	else {
		struct ip6_fw_32 userrule_32;
		
		if ((error = sooptcopyin(sopt, &userrule_32, userrulesize, userrulesize)))
			return error;
		
		cp_from_user_32( &userrule_32, &rule );
	}
	
	if (rule.version != IPV6_FW_CURRENT_API_VERSION) return EINVAL;
	rule.version = 0xFFFFFFFF;	/* version is meaningless once rules "make it in the door". */

	switch (sopt->sopt_name)
	{
		case IPV6_FW_GET:
		{
			struct ip6_fw_chain *fcp;
			struct ip6_fw *buf;
			size_t size = 0;
			size_t rulesize = 0;

			spl = splnet();
			
			if ( is64user )
				rulesize = sizeof(struct ip6_fw_64 );
			else
				rulesize = sizeof(struct ip6_fw_32 );
			
			LIST_FOREACH(fcp, &ip6_fw_chain, chain)
				size += rulesize;

			buf = _MALLOC(size, M_TEMP, M_WAITOK);
			if (!buf) error = ENOBUFS;
			else
			{
				//struct ip6_fw *bp = buf;
				caddr_t bp = (caddr_t)buf;
				
				LIST_FOREACH(fcp, &ip6_fw_chain, chain)
				{
					//bcopy(fcp->rule, bp, sizeof *bp);
					if ( is64user ){
						cp_to_user_64( (struct ip6_fw_64*)bp, fcp->rule);
					}
					else {
						cp_to_user_32( (struct ip6_fw_32*)bp, fcp->rule);
					}

					( (struct ip6_fw*)bp)->version = IPV6_FW_CURRENT_API_VERSION;
					//bp++;
					bp += rulesize;
				}
			}

			splx(spl);
			if (buf)
			{
				sopt->sopt_valsize = valsize;
				error = sooptcopyout(sopt, buf, size);
				FREE(buf, M_TEMP);
			}

			break;
		}

		case IPV6_FW_FLUSH:
			spl = splnet();
			while (ip6_fw_chain.lh_first &&
				ip6_fw_chain.lh_first->rule->fw_number != (u_short)-1)
			{
				struct ip6_fw_chain *fcp = ip6_fw_chain.lh_first;
				LIST_REMOVE(ip6_fw_chain.lh_first, chain);
				FREE(fcp->rule, M_IP6FW);
				FREE(fcp, M_IP6FW);
			}
			splx(spl);
			ip6fw_kev_post_msg(KEV_IP6FW_FLUSH);
			break;

		case IPV6_FW_ZERO:
			error = zero_entry6(&rule);
			break;

		case IPV6_FW_ADD:
			if (check_ip6fw_struct(&rule)) {
				error = add_entry6(&ip6_fw_chain, &rule);

				ip6fw_kev_post_msg(KEV_IP6FW_ADD);
			} else
				error = EINVAL;

			if (is64user){
				struct ip6_fw_64 userrule_64;
				cp_to_user_64( &userrule_64, &rule);
				error = sooptcopyout(sopt, &userrule_64, userrulesize);
			}
			else {
				struct ip6_fw_32 userrule_32;
				cp_to_user_32( &userrule_32, &rule);
				error = sooptcopyout(sopt, &userrule_32, userrulesize);
			}
			break;

		case IPV6_FW_DEL:
			if (rule.fw_number == (u_short)-1)
			{
				dprintf(("%s can't delete rule 65535\n", err_prefix));
				error = EINVAL;
			}
			else {
				error = del_entry6(&ip6_fw_chain, rule.fw_number);

				ip6fw_kev_post_msg(KEV_IP6FW_DEL);
			}
			break;

		default:
			dprintf(("%s invalid option %d\n", err_prefix, sopt->sopt_name));
			error = EINVAL;
	}

	return error;
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
#ifdef IPV6FIREWALL_DEFAULT_TO_ACCEPT
	default_rule.fw_flg |= IPV6_FW_F_ACCEPT;
#else
	default_rule.fw_flg |= IPV6_FW_F_DENY;
#endif
	default_rule.fw_flg |= IPV6_FW_F_IN | IPV6_FW_F_OUT;
	if (check_ip6fw_struct(&default_rule) == NULL ||
		add_entry6(&ip6_fw_chain, &default_rule))
		panic("%s", __FUNCTION__);

	printf("IPv6 packet filtering initialized, ");
#ifdef IPV6FIREWALL_DEFAULT_TO_ACCEPT
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

