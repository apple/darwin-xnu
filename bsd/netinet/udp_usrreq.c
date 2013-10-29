/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
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
 *	@(#)udp_usrreq.c	8.6 (Berkeley) 5/23/95
 * $FreeBSD: src/sys/netinet/udp_usrreq.c,v 1.64.2.13 2001/08/08 18:59:54 ghelmer Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/mcache.h>
#include <net/ntstat.h>

#include <kern/zalloc.h>
#include <mach/boolean.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/dlil.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif /* INET6 */
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#if INET6
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/udp6_var.h>
#endif /* INET6 */
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <sys/kdebug.h>

#if IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/esp.h>
extern int ipsec_bypass;
extern int esp_udp_encap_port;
#endif /* IPSEC */

#define	DBG_LAYER_IN_BEG	NETDBG_CODE(DBG_NETUDP, 0)
#define	DBG_LAYER_IN_END	NETDBG_CODE(DBG_NETUDP, 2)
#define	DBG_LAYER_OUT_BEG	NETDBG_CODE(DBG_NETUDP, 1)
#define	DBG_LAYER_OUT_END	NETDBG_CODE(DBG_NETUDP, 3)
#define	DBG_FNC_UDP_INPUT	NETDBG_CODE(DBG_NETUDP, (5 << 8))
#define	DBG_FNC_UDP_OUTPUT	NETDBG_CODE(DBG_NETUDP, (6 << 8) | 1)

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */
#ifndef	COMPAT_42
static int udpcksum = 1;
#else
static int udpcksum = 0;		/* XXX */
#endif
SYSCTL_INT(_net_inet_udp, UDPCTL_CHECKSUM, checksum,
    CTLFLAG_RW | CTLFLAG_LOCKED, &udpcksum, 0, "");

int udp_log_in_vain = 0;
SYSCTL_INT(_net_inet_udp, OID_AUTO, log_in_vain, CTLFLAG_RW | CTLFLAG_LOCKED,
    &udp_log_in_vain, 0, "Log all incoming UDP packets");

static int blackhole = 0;
SYSCTL_INT(_net_inet_udp, OID_AUTO, blackhole, CTLFLAG_RW | CTLFLAG_LOCKED,
    &blackhole, 0, "Do not send port unreachables for refused connects");

struct inpcbhead udb;		/* from udp_var.h */
#define	udb6	udb  /* for KAME src sync over BSD*'s */
struct inpcbinfo udbinfo;

#ifndef UDBHASHSIZE
#define UDBHASHSIZE 16
#endif

/* Garbage collection performed during most recent udp_gc() run */
static boolean_t udp_gc_done = FALSE;

#if IPFIREWALL
extern int fw_verbose;
extern void ipfwsyslog( int level, const char *format,...);
extern void ipfw_stealth_stats_incr_udp(void);

/* Apple logging, log to ipfw.log */
#define log_in_vain_log(a) {						\
	if ((udp_log_in_vain == 3) && (fw_verbose == 2)) {		\
		ipfwsyslog a;						\
	} else if ((udp_log_in_vain == 4) && (fw_verbose == 2)) {       \
	        ipfw_stealth_stats_incr_udp();				\
	} else {							\
		log a;							\
	}								\
}
#else /* !IPFIREWALL */
#define log_in_vain_log( a ) { log a; }
#endif /* !IPFIREWALL */

static int udp_getstat SYSCTL_HANDLER_ARGS;
struct	udpstat udpstat;	/* from udp_var.h */
SYSCTL_PROC(_net_inet_udp, UDPCTL_STATS, stats, CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, udp_getstat, "S,udpstat",
    "UDP statistics (struct udpstat, netinet/udp_var.h)");

SYSCTL_INT(_net_inet_udp, OID_AUTO, pcbcount,
    CTLFLAG_RD | CTLFLAG_LOCKED, &udbinfo.ipi_count, 0,
    "Number of active PCBs");

__private_extern__ int udp_use_randomport = 1;
SYSCTL_INT(_net_inet_udp, OID_AUTO, randomize_ports,
    CTLFLAG_RW | CTLFLAG_LOCKED, &udp_use_randomport, 0,
    "Randomize UDP port numbers");

#if INET6
struct udp_in6 {
	struct sockaddr_in6	uin6_sin;
	u_char			uin6_init_done : 1;
};
struct udp_ip6 {
	struct ip6_hdr		uip6_ip6;
	u_char			uip6_init_done : 1;
};

static int udp_abort(struct socket *);
static int udp_attach(struct socket *, int, struct proc *);
static int udp_bind(struct socket *, struct sockaddr *, struct proc *);
static int udp_connect(struct socket *, struct sockaddr *, struct proc *);
static int udp_connectx(struct socket *, struct sockaddr_list **,
    struct sockaddr_list **, struct proc *, uint32_t, associd_t, connid_t *,
    uint32_t, void *, uint32_t);
static int udp_detach(struct socket *);
static int udp_disconnect(struct socket *);
static int udp_disconnectx(struct socket *, associd_t, connid_t);
static int udp_send(struct socket *, int, struct mbuf *, struct sockaddr *,
    struct mbuf *, struct proc *);
static void udp_append(struct inpcb *, struct ip *, struct mbuf *, int,
    struct sockaddr_in *, struct udp_in6 *, struct udp_ip6 *, struct ifnet *);
#else /* !INET6 */
static void udp_append(struct inpcb *, struct ip *, struct mbuf *, int,
    struct sockaddr_in *, struct ifnet *);
#endif /* !INET6 */
static int udp_input_checksum(struct mbuf *, struct udphdr *, int, int);
static int udp_output(struct inpcb *, struct mbuf *, struct sockaddr *,
    struct mbuf *, struct proc *);
static void ip_2_ip6_hdr(struct ip6_hdr *ip6, struct ip *ip);
static void udp_gc(struct inpcbinfo *);

struct pr_usrreqs udp_usrreqs = {
	.pru_abort =		udp_abort,
	.pru_attach =		udp_attach,
	.pru_bind =		udp_bind,
	.pru_connect =		udp_connect,
	.pru_connectx =		udp_connectx,
	.pru_control =		in_control,
	.pru_detach =		udp_detach,
	.pru_disconnect =	udp_disconnect,
	.pru_disconnectx =	udp_disconnectx,
	.pru_peeraddr =		in_getpeeraddr,
	.pru_send =		udp_send,
	.pru_shutdown =		udp_shutdown,
	.pru_sockaddr =		in_getsockaddr,
	.pru_sosend =		sosend,
	.pru_soreceive =	soreceive,
};

void
udp_init(struct protosw *pp, struct domain *dp)
{
#pragma unused(dp)
	static int udp_initialized = 0;
	vm_size_t		str_size;
	struct inpcbinfo	*pcbinfo;

	VERIFY((pp->pr_flags & (PR_INITIALIZED|PR_ATTACHED)) == PR_ATTACHED);

	if (udp_initialized)
		return;
	udp_initialized = 1;

	LIST_INIT(&udb);
	udbinfo.ipi_listhead = &udb;
	udbinfo.ipi_hashbase = hashinit(UDBHASHSIZE, M_PCB,
	    &udbinfo.ipi_hashmask);
	udbinfo.ipi_porthashbase = hashinit(UDBHASHSIZE, M_PCB,
	    &udbinfo.ipi_porthashmask);
	str_size = (vm_size_t) sizeof (struct inpcb);
	udbinfo.ipi_zone = zinit(str_size, 80000*str_size, 8192, "udpcb");

	pcbinfo = &udbinfo;
	/*
	 * allocate lock group attribute and group for udp pcb mutexes
	 */
	pcbinfo->ipi_lock_grp_attr = lck_grp_attr_alloc_init();
	pcbinfo->ipi_lock_grp = lck_grp_alloc_init("udppcb",
	    pcbinfo->ipi_lock_grp_attr);
	pcbinfo->ipi_lock_attr = lck_attr_alloc_init();
	if ((pcbinfo->ipi_lock = lck_rw_alloc_init(pcbinfo->ipi_lock_grp,
	    pcbinfo->ipi_lock_attr)) == NULL) {
		panic("%s: unable to allocate PCB lock\n", __func__);
		/* NOTREACHED */
	}

	udbinfo.ipi_gc = udp_gc;
	in_pcbinfo_attach(&udbinfo);
}

void
udp_input(struct mbuf *m, int iphlen)
{
	struct ip *ip;
	struct udphdr *uh;
	struct inpcb *inp;
	struct mbuf *opts = NULL;
	int len, isbroadcast;
	struct ip save_ip;
	struct sockaddr *append_sa;
	struct inpcbinfo *pcbinfo = &udbinfo;
	struct sockaddr_in udp_in;
	struct ip_moptions *imo = NULL;
	int foundmembership = 0, ret = 0;
#if INET6
	struct udp_in6 udp_in6;
	struct udp_ip6 udp_ip6;
#endif /* INET6 */
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	boolean_t cell = IFNET_IS_CELLULAR(ifp);
	boolean_t wifi = (!cell && IFNET_IS_WIFI(ifp));

	bzero(&udp_in, sizeof (udp_in));
	udp_in.sin_len = sizeof (struct sockaddr_in);
	udp_in.sin_family = AF_INET;
#if INET6
	bzero(&udp_in6, sizeof (udp_in6));
	udp_in6.uin6_sin.sin6_len = sizeof (struct sockaddr_in6);
	udp_in6.uin6_sin.sin6_family = AF_INET6;
#endif /* INET6 */

	udpstat.udps_ipackets++;

	KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_START, 0,0,0,0,0);

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	/*
	 * Strip IP options, if any; should skip this,
	 * make available to user, and use on returned packets,
	 * but we don't yet have a way to check the checksum
	 * with options still present.
	 */
	if (iphlen > sizeof (struct ip)) {
		ip_stripoptions(m, (struct mbuf *)0);
		iphlen = sizeof (struct ip);
	}

	/*
	 * Get IP and UDP header together in first mbuf.
	 */
	ip = mtod(m, struct ip *);
	if (m->m_len < iphlen + sizeof (struct udphdr)) {
		m = m_pullup(m, iphlen + sizeof (struct udphdr));
		if (m == NULL) {
			udpstat.udps_hdrops++;
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END,
			    0,0,0,0,0);
			return;
		}
		ip = mtod(m, struct ip *);
	}
	uh = (struct udphdr *)(void *)((caddr_t)ip + iphlen);

	/* destination port of 0 is illegal, based on RFC768. */
	if (uh->uh_dport == 0) {
		IF_UDP_STATINC(ifp, port0);
		goto bad;
	}

	KERNEL_DEBUG(DBG_LAYER_IN_BEG, uh->uh_dport, uh->uh_sport,
	    ip->ip_src.s_addr, ip->ip_dst.s_addr, uh->uh_ulen);

	/*
	 * Make mbuf data length reflect UDP length.
	 * If not enough data to reflect UDP length, drop.
	 */
	len = ntohs((u_short)uh->uh_ulen);
	if (ip->ip_len != len) {
		if (len > ip->ip_len || len < sizeof (struct udphdr)) {
			udpstat.udps_badlen++;
			IF_UDP_STATINC(ifp, badlength);
			goto bad;
		}
		m_adj(m, len - ip->ip_len);
		/* ip->ip_len = len; */
	}
	/*
	 * Save a copy of the IP header in case we want restore it
	 * for sending an ICMP error message in response.
	 */
	save_ip = *ip;

	/*
	 * Checksum extended UDP header and data.
	 */
	if (udp_input_checksum(m, uh, iphlen, len))
		goto bad;

	isbroadcast = in_broadcast(ip->ip_dst, ifp);

	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)) || isbroadcast) {
		int reuse_sock = 0, mcast_delivered = 0;

		lck_rw_lock_shared(pcbinfo->ipi_lock);
		/*
		 * Deliver a multicast or broadcast datagram to *all* sockets
		 * for which the local and remote addresses and ports match
		 * those of the incoming datagram.  This allows more than
		 * one process to receive multi/broadcasts on the same port.
		 * (This really ought to be done for unicast datagrams as
		 * well, but that would cause problems with existing
		 * applications that open both address-specific sockets and
		 * a wildcard socket listening to the same port -- they would
		 * end up receiving duplicates of every unicast datagram.
		 * Those applications open the multiple sockets to overcome an
		 * inadequacy of the UDP socket interface, but for backwards
		 * compatibility we avoid the problem here rather than
		 * fixing the interface.  Maybe 4.5BSD will remedy this?)
		 */

		/*
		 * Construct sockaddr format source address.
		 */
		udp_in.sin_port = uh->uh_sport;
		udp_in.sin_addr = ip->ip_src;
		/*
		 * Locate pcb(s) for datagram.
		 * (Algorithm copied from raw_intr().)
		 */
#if INET6
		udp_in6.uin6_init_done = udp_ip6.uip6_init_done = 0;
#endif /* INET6 */
		LIST_FOREACH(inp, &udb, inp_list) {
#if IPSEC
			int skipit;
#endif /* IPSEC */

			if (inp->inp_socket == NULL)
				continue;
			if (inp != sotoinpcb(inp->inp_socket)) {
				panic("%s: bad so back ptr inp=%p\n",
				    __func__, inp);
				/* NOTREACHED */
			}
#if INET6
                        if ((inp->inp_vflag & INP_IPV4) == 0)
                                continue;
#endif /* INET6 */
			if (inp_restricted(inp, ifp))
				continue;

			if (IFNET_IS_CELLULAR(ifp) &&
			    (inp->inp_flags & INP_NO_IFT_CELLULAR))
				continue;

			if ((inp->inp_moptions == NULL) &&
			    (ntohl(ip->ip_dst.s_addr) !=
			    INADDR_ALLHOSTS_GROUP) && (isbroadcast == 0))
				continue;

			if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) ==
			    WNT_STOPUSING)
				continue;

			udp_lock(inp->inp_socket, 1, 0);

			if (in_pcb_checkstate(inp, WNT_RELEASE, 1) ==
			    WNT_STOPUSING) {
				udp_unlock(inp->inp_socket, 1, 0);
				continue;
			}

			if (inp->inp_lport != uh->uh_dport) {
				udp_unlock(inp->inp_socket, 1, 0);
				continue;
			}
			if (inp->inp_laddr.s_addr != INADDR_ANY) {
				if (inp->inp_laddr.s_addr !=
				    ip->ip_dst.s_addr) {
					udp_unlock(inp->inp_socket, 1, 0);
					continue;
				}
			}
			if (inp->inp_faddr.s_addr != INADDR_ANY) {
				if (inp->inp_faddr.s_addr !=
				    ip->ip_src.s_addr ||
				    inp->inp_fport != uh->uh_sport) {
					udp_unlock(inp->inp_socket, 1, 0);
					continue;
				}
			}

			if (isbroadcast == 0 && (ntohl(ip->ip_dst.s_addr) !=
			    INADDR_ALLHOSTS_GROUP)) {
				struct sockaddr_in group;
				int blocked;

				if ((imo = inp->inp_moptions) == NULL) {
					udp_unlock(inp->inp_socket, 1, 0);
					continue;
				}
				IMO_LOCK(imo);

				bzero(&group, sizeof (struct sockaddr_in));
				group.sin_len = sizeof (struct sockaddr_in);
				group.sin_family = AF_INET;
				group.sin_addr = ip->ip_dst;

				blocked = imo_multi_filter(imo, ifp,
				    (struct sockaddr *)&group,
				    (struct sockaddr *)&udp_in);
				if (blocked == MCAST_PASS)
					foundmembership = 1;

				IMO_UNLOCK(imo);
				if (!foundmembership) {
					udp_unlock(inp->inp_socket, 1, 0);
					if (blocked == MCAST_NOTSMEMBER ||
					    blocked == MCAST_MUTED)
						udpstat.udps_filtermcast++;
					continue;
				}
				foundmembership = 0;
			}

			reuse_sock = (inp->inp_socket->so_options &
			    (SO_REUSEPORT|SO_REUSEADDR));

#if IPSEC
			skipit = 0;
			/* check AH/ESP integrity. */
			if (ipsec_bypass == 0 &&
			    ipsec4_in_reject_so(m, inp->inp_socket)) {
				IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
				/* do not inject data to pcb */
				skipit = 1;
			}
			if (skipit == 0)
#endif /*IPSEC*/
			{
				struct mbuf *n = NULL;

				if (reuse_sock)
					n = m_copy(m, 0, M_COPYALL);
#if INET6
				udp_append(inp, ip, m,
				    iphlen + sizeof (struct udphdr),
				    &udp_in, &udp_in6, &udp_ip6, ifp);
#else /* !INET6 */
				udp_append(inp, ip, m,
				    iphlen + sizeof (struct udphdr),
				    &udp_in, ifp);
#endif /* !INET6 */
				mcast_delivered++;

				m = n;
			}
			udp_unlock(inp->inp_socket, 1, 0);

			/*
			 * Don't look for additional matches if this one does
			 * not have either the SO_REUSEPORT or SO_REUSEADDR
			 * socket options set.  This heuristic avoids searching
			 * through all pcbs in the common case of a non-shared
			 * port.  It assumes that an application will never
			 * clear these options after setting them.
			 */
			if (reuse_sock == 0 || m == NULL)
				break;

			/*
			 * Expect 32-bit aligned data pointer on strict-align
			 * platforms.
			 */
			MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);
			/*
			 * Recompute IP and UDP header pointers for new mbuf
			 */
			ip = mtod(m, struct ip *);
			uh = (struct udphdr *)(void *)((caddr_t)ip + iphlen);
		}
		lck_rw_done(pcbinfo->ipi_lock);

		if (mcast_delivered == 0) {
			/*
			 * No matching pcb found; discard datagram.
			 * (No need to send an ICMP Port Unreachable
			 * for a broadcast or multicast datgram.)
			 */
			udpstat.udps_noportbcast++;
			IF_UDP_STATINC(ifp, port_unreach);
			goto bad;
		}

		/* free the extra copy of mbuf or skipped by IPSec */
		if (m != NULL)
			m_freem(m);
		KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
		return;
	}

#if IPSEC
	/*
	 * UDP to port 4500 with a payload where the first four bytes are
	 * not zero is a UDP encapsulated IPSec packet. Packets where
	 * the payload is one byte and that byte is 0xFF are NAT keepalive
	 * packets. Decapsulate the ESP packet and carry on with IPSec input
	 * or discard the NAT keep-alive.
	 */
	if (ipsec_bypass == 0 && (esp_udp_encap_port & 0xFFFF) != 0 &&
	    uh->uh_dport == ntohs((u_short)esp_udp_encap_port)) {
		int payload_len = len - sizeof (struct udphdr) > 4 ? 4 :
		    len - sizeof (struct udphdr);

		if (m->m_len < iphlen + sizeof (struct udphdr) + payload_len) {
			if ((m = m_pullup(m, iphlen + sizeof (struct udphdr) +
			    payload_len)) == NULL) {
				udpstat.udps_hdrops++;
				KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END,
				    0,0,0,0,0);
				return;
			}
			/*
			 * Expect 32-bit aligned data pointer on strict-align
			 * platforms.
			 */
			MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

			ip = mtod(m, struct ip *);
			uh = (struct udphdr *)(void *)((caddr_t)ip + iphlen);
		}
		/* Check for NAT keepalive packet */
		if (payload_len == 1 && *(u_int8_t*)
		    ((caddr_t)uh + sizeof (struct udphdr)) == 0xFF) {
			m_freem(m);
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END,
			    0,0,0,0,0);
			return;
		} else if (payload_len == 4 && *(u_int32_t*)(void *)
		    ((caddr_t)uh + sizeof (struct udphdr)) != 0) {
			/* UDP encapsulated IPSec packet to pass through NAT */
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END,
			    0,0,0,0,0);
			/* preserve the udp header */
			esp4_input(m, iphlen + sizeof (struct udphdr));
			return;
		}
	}
#endif /* IPSEC */

	/*
	 * Locate pcb for datagram.
	 */
	inp = in_pcblookup_hash(&udbinfo, ip->ip_src, uh->uh_sport,
	    ip->ip_dst, uh->uh_dport, 1, ifp);
	if (inp == NULL) {
		IF_UDP_STATINC(ifp, port_unreach);

		if (udp_log_in_vain) {
			char buf[MAX_IPv4_STR_LEN];
			char buf2[MAX_IPv4_STR_LEN];

			/* check src and dst address */
			if (udp_log_in_vain < 3) {
				log(LOG_INFO, "Connection attempt to "
				    "UDP %s:%d from %s:%d\n", inet_ntop(AF_INET,
				        &ip->ip_dst, buf, sizeof (buf)),
					ntohs(uh->uh_dport), inet_ntop(AF_INET,
					&ip->ip_src, buf2, sizeof (buf2)),
					ntohs(uh->uh_sport));
			} else if (!(m->m_flags & (M_BCAST | M_MCAST)) &&
			    ip->ip_dst.s_addr != ip->ip_src.s_addr) {
				log_in_vain_log((LOG_INFO,
				    "Stealth Mode connection attempt to "
				    "UDP %s:%d from %s:%d\n", inet_ntop(AF_INET,
				    &ip->ip_dst, buf, sizeof (buf)),
				    ntohs(uh->uh_dport), inet_ntop(AF_INET,
				    &ip->ip_src, buf2, sizeof (buf2)),
				    ntohs(uh->uh_sport)))
			}
		}
		udpstat.udps_noport++;
		if (m->m_flags & (M_BCAST | M_MCAST)) {
			udpstat.udps_noportbcast++;
			goto bad;
		}
#if ICMP_BANDLIM
		if (badport_bandlim(BANDLIM_ICMP_UNREACH) < 0)
			goto bad;
#endif /* ICMP_BANDLIM */
		if (blackhole)
			if (ifp && ifp->if_type != IFT_LOOP)
				goto bad;
		*ip = save_ip;
		ip->ip_len += iphlen;
		icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0);
		KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
		return;
	}
	udp_lock(inp->inp_socket, 1, 0);

	if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
		udp_unlock(inp->inp_socket, 1, 0);
		IF_UDP_STATINC(ifp, cleanup);
		goto bad;
	}
#if IPSEC
	if (ipsec_bypass == 0 && inp != NULL) {
		if (ipsec4_in_reject_so(m, inp->inp_socket)) {
			IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
			udp_unlock(inp->inp_socket, 1, 0);
			IF_UDP_STATINC(ifp, badipsec);
			goto bad;
		}
	}
#endif /* IPSEC */

	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	udp_in.sin_port = uh->uh_sport;
	udp_in.sin_addr = ip->ip_src;
	if ((inp->inp_flags & INP_CONTROLOPTS) != 0 ||
	    (inp->inp_socket->so_options & SO_TIMESTAMP) != 0 ||
	    (inp->inp_socket->so_options & SO_TIMESTAMP_MONOTONIC) != 0) {
#if INET6
		if (inp->inp_vflag & INP_IPV6) {
			int savedflags;

			ip_2_ip6_hdr(&udp_ip6.uip6_ip6, ip);
			savedflags = inp->inp_flags;
			inp->inp_flags &= ~INP_UNMAPPABLEOPTS;
			ret = ip6_savecontrol(inp, m, &opts);
			inp->inp_flags = savedflags;
		} else
#endif /* INET6 */
		{
			ret = ip_savecontrol(inp, &opts, ip, m);
		}
		if (ret != 0) {
			udp_unlock(inp->inp_socket, 1, 0);
			goto bad;
		}
	}
	m_adj(m, iphlen + sizeof (struct udphdr));

	KERNEL_DEBUG(DBG_LAYER_IN_END, uh->uh_dport, uh->uh_sport,
	    save_ip.ip_src.s_addr, save_ip.ip_dst.s_addr, uh->uh_ulen);

#if INET6
	if (inp->inp_vflag & INP_IPV6) {
		in6_sin_2_v4mapsin6(&udp_in, &udp_in6.uin6_sin);
		append_sa = (struct sockaddr *)&udp_in6.uin6_sin;
	} else
#endif /* INET6 */
	{
		append_sa = (struct sockaddr *)&udp_in;
	}
	if (nstat_collect) {
		INP_ADD_STAT(inp, cell, wifi, rxpackets, 1);
		INP_ADD_STAT(inp, cell, wifi, rxbytes, m->m_pkthdr.len);
	}
	so_recv_data_stat(inp->inp_socket, m, 0);
	if (sbappendaddr(&inp->inp_socket->so_rcv, append_sa,
	    m, opts, NULL) == 0) {
		udpstat.udps_fullsock++;
	} else {
		sorwakeup(inp->inp_socket);
	}
	udp_unlock(inp->inp_socket, 1, 0);
	KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
	return;
bad:
	m_freem(m);
	if (opts)
		m_freem(opts);
	KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
}

#if INET6
static void
ip_2_ip6_hdr(struct ip6_hdr *ip6, struct ip *ip)
{
	bzero(ip6, sizeof (*ip6));

	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = ip->ip_len;
	ip6->ip6_nxt = ip->ip_p;
	ip6->ip6_hlim = ip->ip_ttl;
	if (ip->ip_src.s_addr) {
		ip6->ip6_src.s6_addr32[2] = IPV6_ADDR_INT32_SMP;
		ip6->ip6_src.s6_addr32[3] = ip->ip_src.s_addr;
	}
	if (ip->ip_dst.s_addr) {
		ip6->ip6_dst.s6_addr32[2] = IPV6_ADDR_INT32_SMP;
		ip6->ip6_dst.s6_addr32[3] = ip->ip_dst.s_addr;
	}
}
#endif /* INET6 */

/*
 * subroutine of udp_input(), mainly for source code readability.
 */
static void
#if INET6
udp_append(struct inpcb *last, struct ip *ip, struct mbuf *n, int off,
    struct sockaddr_in *pudp_in, struct udp_in6 *pudp_in6,
    struct udp_ip6 *pudp_ip6, struct ifnet *ifp)
#else /* !INET6 */
udp_append(struct inpcb *last, struct ip *ip, struct mbuf *n, int off,
    struct sockaddr_in *pudp_in, struct ifnet *ifp)
#endif /* !INET6 */
{
	struct sockaddr *append_sa;
	struct mbuf *opts = 0;
	boolean_t cell = IFNET_IS_CELLULAR(ifp);
	boolean_t wifi = (!cell && IFNET_IS_WIFI(ifp));
	int ret = 0;

#if CONFIG_MACF_NET
	if (mac_inpcb_check_deliver(last, n, AF_INET, SOCK_DGRAM) != 0) {
		m_freem(n);
		return;
	}
#endif /* CONFIG_MACF_NET */
	if ((last->inp_flags & INP_CONTROLOPTS) != 0 ||
	    (last->inp_socket->so_options & SO_TIMESTAMP) != 0 ||
	    (last->inp_socket->so_options & SO_TIMESTAMP_MONOTONIC) != 0) {
#if INET6
		if (last->inp_vflag & INP_IPV6) {
			int savedflags;

			if (pudp_ip6->uip6_init_done == 0) {
				ip_2_ip6_hdr(&pudp_ip6->uip6_ip6, ip);
				pudp_ip6->uip6_init_done = 1;
			}
			savedflags = last->inp_flags;
			last->inp_flags &= ~INP_UNMAPPABLEOPTS;
			ret = ip6_savecontrol(last, n, &opts);
			if (ret != 0) {
				last->inp_flags = savedflags;
				goto error;
			}
			last->inp_flags = savedflags;
		} else
#endif /* INET6 */
		{
			ret = ip_savecontrol(last, &opts, ip, n);
			if (ret != 0) {
				goto error;
			}
		}
	}
#if INET6
	if (last->inp_vflag & INP_IPV6) {
		if (pudp_in6->uin6_init_done == 0) {
			in6_sin_2_v4mapsin6(pudp_in, &pudp_in6->uin6_sin);
			pudp_in6->uin6_init_done = 1;
		}
		append_sa = (struct sockaddr *)&pudp_in6->uin6_sin;
	} else
#endif /* INET6 */
	append_sa = (struct sockaddr *)pudp_in;
	if (nstat_collect) {
		INP_ADD_STAT(last, cell, wifi, rxpackets, 1);
		INP_ADD_STAT(last, cell, wifi, rxbytes, n->m_pkthdr.len);
	}
	so_recv_data_stat(last->inp_socket, n, 0);
	m_adj(n, off);
	if (sbappendaddr(&last->inp_socket->so_rcv, append_sa,
	    n, opts, NULL) == 0) {
		udpstat.udps_fullsock++;
	} else {
		sorwakeup(last->inp_socket);
	}
	return;
error:
	m_freem(n);
	m_freem(opts);
	return;
}

/*
 * Notify a udp user of an asynchronous error;
 * just wake up so that he can collect error status.
 */
void
udp_notify(struct inpcb *inp, int errno)
{
	inp->inp_socket->so_error = errno;
	sorwakeup(inp->inp_socket);
	sowwakeup(inp->inp_socket);
}

void
udp_ctlinput(int cmd, struct sockaddr *sa, void *vip)
{
	struct ip *ip = vip;
	void (*notify)(struct inpcb *, int) = udp_notify;
        struct in_addr faddr;
	struct inpcb *inp;

	faddr = ((struct sockaddr_in *)(void *)sa)->sin_addr;
	if (sa->sa_family != AF_INET || faddr.s_addr == INADDR_ANY)
		return;

	if (PRC_IS_REDIRECT(cmd)) {
		ip = 0;
		notify = in_rtchange;
	} else if (cmd == PRC_HOSTDEAD) {
		ip = 0;
	} else if ((unsigned)cmd >= PRC_NCMDS || inetctlerrmap[cmd] == 0) {
		return;
	}
	if (ip) {
		struct udphdr uh;

		bcopy(((caddr_t)ip + (ip->ip_hl << 2)), &uh, sizeof (uh));
		inp = in_pcblookup_hash(&udbinfo, faddr, uh.uh_dport,
                    ip->ip_src, uh.uh_sport, 0, NULL);
		if (inp != NULL && inp->inp_socket != NULL) {
			udp_lock(inp->inp_socket, 1, 0);
			if (in_pcb_checkstate(inp, WNT_RELEASE, 1) ==
			    WNT_STOPUSING)  {
				udp_unlock(inp->inp_socket, 1, 0);
				return;
			}
			(*notify)(inp, inetctlerrmap[cmd]);
			udp_unlock(inp->inp_socket, 1, 0);
		}
	} else {
		in_pcbnotifyall(&udbinfo, faddr, inetctlerrmap[cmd], notify);
	}
}

int
udp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int	error, optval;
	struct	inpcb *inp;

	/* Allow <SOL_SOCKET,SO_FLUSH> at this level */
	if (sopt->sopt_level != IPPROTO_UDP &&
	    !(sopt->sopt_level == SOL_SOCKET && sopt->sopt_name == SO_FLUSH))
		return (ip_ctloutput(so, sopt));

	error = 0;
	inp = sotoinpcb(so);

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case UDP_NOCKSUM:
			/* This option is settable only for UDP over IPv4 */
			if (!(inp->inp_vflag & INP_IPV4)) {
				error = EINVAL;
				break;
			}

			if ((error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval))) != 0)
				break;

			if (optval != 0)
				inp->inp_flags |= INP_UDP_NOCKSUM;
			else
				inp->inp_flags &= ~INP_UDP_NOCKSUM;
			break;

		case SO_FLUSH:
			if ((error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval))) != 0)
				break;

			error = inp_flush(inp, optval);
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		break;

	case SOPT_GET:
		switch (sopt->sopt_name) {
		case UDP_NOCKSUM:
			optval = inp->inp_flags & INP_UDP_NOCKSUM;
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (error == 0)
			error = sooptcopyout(sopt, &optval, sizeof (optval));
		break;
	}
	return (error);
}

static int
udp_pcblist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error, i, n;
	struct inpcb *inp, **inp_list;
	inp_gen_t gencnt;
	struct xinpgen xig;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	lck_rw_lock_exclusive(udbinfo.ipi_lock);
	if (req->oldptr == USER_ADDR_NULL) {
		n = udbinfo.ipi_count;
		req->oldidx = 2 * (sizeof (xig))
			+ (n + n/8) * sizeof (struct xinpcb);
		lck_rw_done(udbinfo.ipi_lock);
		return (0);
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(udbinfo.ipi_lock);
		return (EPERM);
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = udbinfo.ipi_gencnt;
	n = udbinfo.ipi_count;

	bzero(&xig, sizeof (xig));
	xig.xig_len = sizeof (xig);
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof (xig));
	if (error) {
		lck_rw_done(udbinfo.ipi_lock);
		return (error);
	}
	/*
	 * We are done if there is no pcb
	 */
	if (n == 0) {
		lck_rw_done(udbinfo.ipi_lock);
		return (0);
	}

	inp_list = _MALLOC(n * sizeof (*inp_list), M_TEMP, M_WAITOK);
	if (inp_list == 0) {
		lck_rw_done(udbinfo.ipi_lock);
		return (ENOMEM);
	}

	for (inp = LIST_FIRST(udbinfo.ipi_listhead), i = 0; inp && i < n;
	     inp = LIST_NEXT(inp, inp_list)) {
		if (inp->inp_gencnt <= gencnt &&
		    inp->inp_state != INPCB_STATE_DEAD)
			inp_list[i++] = inp;
	}
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		if (inp->inp_gencnt <= gencnt &&
		    inp->inp_state != INPCB_STATE_DEAD) {
			struct xinpcb xi;

			bzero(&xi, sizeof (xi));
			xi.xi_len = sizeof (xi);
			/* XXX should avoid extra copy */
			inpcb_to_compat(inp, &xi.xi_inp);
			if (inp->inp_socket)
				sotoxsocket(inp->inp_socket, &xi.xi_socket);
			error = SYSCTL_OUT(req, &xi, sizeof (xi));
		}
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		bzero(&xig, sizeof (xig));
		xig.xig_len = sizeof (xig);
		xig.xig_gen = udbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = udbinfo.ipi_count;
		error = SYSCTL_OUT(req, &xig, sizeof (xig));
	}
	FREE(inp_list, M_TEMP);
	lck_rw_done(udbinfo.ipi_lock);
	return (error);
}

SYSCTL_PROC(_net_inet_udp, UDPCTL_PCBLIST, pcblist,
    CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, udp_pcblist,
    "S,xinpcb", "List of active UDP sockets");


static int
udp_pcblist64 SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
        int error, i, n;
        struct inpcb *inp, **inp_list;
        inp_gen_t gencnt;
        struct xinpgen xig;

        /*
         * The process of preparing the TCB list is too time-consuming and
         * resource-intensive to repeat twice on every request.
         */
        lck_rw_lock_shared(udbinfo.ipi_lock);
        if (req->oldptr == USER_ADDR_NULL) {
                n = udbinfo.ipi_count;
                req->oldidx =
		    2 * (sizeof (xig)) + (n + n/8) * sizeof (struct xinpcb64);
                lck_rw_done(udbinfo.ipi_lock);
                return (0);
        }

        if (req->newptr != USER_ADDR_NULL) {
                lck_rw_done(udbinfo.ipi_lock);
                return (EPERM);
        }

        /*
         * OK, now we're committed to doing something.
         */
        gencnt = udbinfo.ipi_gencnt;
        n = udbinfo.ipi_count;

        bzero(&xig, sizeof (xig));
        xig.xig_len = sizeof (xig);
        xig.xig_count = n;
        xig.xig_gen = gencnt;
        xig.xig_sogen = so_gencnt;
        error = SYSCTL_OUT(req, &xig, sizeof (xig));
        if (error) {
                lck_rw_done(udbinfo.ipi_lock);
                return (error);
        }
	/*
	 * We are done if there is no pcb
	 */
	if (n == 0) {
		lck_rw_done(udbinfo.ipi_lock);
		return (0);
	}

        inp_list = _MALLOC(n * sizeof (*inp_list), M_TEMP, M_WAITOK);
        if (inp_list == 0) {
                lck_rw_done(udbinfo.ipi_lock);
                return (ENOMEM);
        }

        for (inp = LIST_FIRST(udbinfo.ipi_listhead), i = 0; inp && i < n;
             inp = LIST_NEXT(inp, inp_list)) {
                if (inp->inp_gencnt <= gencnt &&
		    inp->inp_state != INPCB_STATE_DEAD)
                        inp_list[i++] = inp;
        }
        n = i;

        error = 0;
        for (i = 0; i < n; i++) {
                inp = inp_list[i];
                if (inp->inp_gencnt <= gencnt &&
		    inp->inp_state != INPCB_STATE_DEAD) {
                        struct xinpcb64 xi;

                        bzero(&xi, sizeof (xi));
                        xi.xi_len = sizeof (xi);
                        inpcb_to_xinpcb64(inp, &xi);
                        if (inp->inp_socket)
                                sotoxsocket64(inp->inp_socket, &xi.xi_socket);
                        error = SYSCTL_OUT(req, &xi, sizeof (xi));
                }
        }
        if (!error) {
                /*
                 * Give the user an updated idea of our state.
                 * If the generation differs from what we told
                 * her before, she knows that something happened
                 * while we were processing this request, and it
                 * might be necessary to retry.
                 */
                bzero(&xig, sizeof (xig));
                xig.xig_len = sizeof (xig);
                xig.xig_gen = udbinfo.ipi_gencnt;
                xig.xig_sogen = so_gencnt;
                xig.xig_count = udbinfo.ipi_count;
                error = SYSCTL_OUT(req, &xig, sizeof (xig));
        }
        FREE(inp_list, M_TEMP);
        lck_rw_done(udbinfo.ipi_lock);
        return (error);
}

SYSCTL_PROC(_net_inet_udp, OID_AUTO, pcblist64,
    CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, udp_pcblist64,
    "S,xinpcb64", "List of active UDP sockets");


static int
udp_pcblist_n SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	return (get_pcblist_n(IPPROTO_UDP, req, &udbinfo));
}

SYSCTL_PROC(_net_inet_udp, OID_AUTO, pcblist_n,
    CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, udp_pcblist_n,
    "S,xinpcb_n", "List of active UDP sockets");

__private_extern__ void
udp_get_ports_used(uint32_t ifindex, int protocol, uint32_t wildcardok,
    bitstr_t *bitfield)
{
	inpcb_get_ports_used(ifindex, protocol, wildcardok, bitfield, &udbinfo);
}

__private_extern__ uint32_t
udp_count_opportunistic(unsigned int ifindex, u_int32_t flags)
{
	return (inpcb_count_opportunistic(ifindex, &udbinfo, flags));
}

__private_extern__ uint32_t
udp_find_anypcb_byaddr(struct ifaddr *ifa)
{
	return (inpcb_find_anypcb_byaddr(ifa, &udbinfo));
}

static int
udp_check_pktinfo(struct mbuf *control, struct ifnet **outif,
    struct in_addr *laddr)
{
	struct cmsghdr *cm = 0;
	struct in_pktinfo *pktinfo;
	struct ifnet *ifp;

	if (outif != NULL)
		*outif = NULL;

	/*
	 * XXX: Currently, we assume all the optional information is stored
	 * in a single mbuf.
	 */
	if (control->m_next)
		return (EINVAL);

	if (control->m_len < CMSG_LEN(0))
		return (EINVAL);

	for (cm = M_FIRST_CMSGHDR(control); cm;
	    cm = M_NXT_CMSGHDR(control, cm)) {
		if (cm->cmsg_len < sizeof (struct cmsghdr) ||
		    cm->cmsg_len > control->m_len)
			return (EINVAL);

		if (cm->cmsg_level != IPPROTO_IP || cm->cmsg_type != IP_PKTINFO)
			continue;

		if (cm->cmsg_len != CMSG_LEN(sizeof (struct in_pktinfo)))
			return (EINVAL);

		pktinfo =  (struct in_pktinfo *)(void *)CMSG_DATA(cm);

		/* Check for a valid ifindex in pktinfo */
		ifnet_head_lock_shared();

		if (pktinfo->ipi_ifindex > if_index) {
			ifnet_head_done();
			return (ENXIO);
		}

		/*
		 * If ipi_ifindex is specified it takes precedence
		 * over ipi_spec_dst.
		 */
		if (pktinfo->ipi_ifindex) {
			ifp = ifindex2ifnet[pktinfo->ipi_ifindex];
			if (ifp == NULL) {
				ifnet_head_done();
				return (ENXIO);
			}
			if (outif != NULL) {
				ifnet_reference(ifp);
				*outif = ifp;
			}
			ifnet_head_done();
			laddr->s_addr = INADDR_ANY;
			break;
		}

		ifnet_head_done();

		/*
		 * Use the provided ipi_spec_dst address for temp
		 * source address.
		 */
		*laddr = pktinfo->ipi_spec_dst;
		break;
	}
	return (0);
}

static int
udp_output(struct inpcb *inp, struct mbuf *m, struct sockaddr *addr,
    struct mbuf *control, struct proc *p)
{
	struct udpiphdr *ui;
	int len = m->m_pkthdr.len;
	struct sockaddr_in *sin;
	struct in_addr origladdr, laddr, faddr, pi_laddr;
	u_short lport, fport;
	int error = 0, udp_dodisconnect = 0, pktinfo = 0;
	struct socket *so = inp->inp_socket;
	int soopts = 0;
	struct mbuf *inpopts;
	struct ip_moptions *mopts;
	struct route ro;
	struct ip_out_args ipoa =
	    { IFSCOPE_NONE, { 0 }, IPOAF_SELECT_SRCIF, 0 };
	struct ifnet *outif = NULL;
	struct flowadv *adv = &ipoa.ipoa_flowadv;
	mbuf_svc_class_t msc = MBUF_SC_UNSPEC;
	struct ifnet *origoutifp;
	int flowadv = 0;

	/* Enable flow advisory only when connected */
	flowadv = (so->so_state & SS_ISCONNECTED) ? 1 : 0;
	pi_laddr.s_addr = INADDR_ANY;

	KERNEL_DEBUG(DBG_FNC_UDP_OUTPUT | DBG_FUNC_START, 0,0,0,0,0);

	lck_mtx_assert(&inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
	if (control != NULL) {
		msc = mbuf_service_class_from_control(control);
		VERIFY(outif == NULL);
		error = udp_check_pktinfo(control, &outif, &pi_laddr);
		m_freem(control);
		control = NULL;
		if (error)
			goto release;
		pktinfo++;
		if (outif != NULL)
			ipoa.ipoa_boundif = outif->if_index;
	}

	KERNEL_DEBUG(DBG_LAYER_OUT_BEG, inp->inp_fport, inp->inp_lport,
	    inp->inp_laddr.s_addr, inp->inp_faddr.s_addr,
	    (htons((u_short)len + sizeof (struct udphdr))));

	if (len + sizeof (struct udpiphdr) > IP_MAXPACKET) {
		error = EMSGSIZE;
		goto release;
	}

	if (flowadv && INP_WAIT_FOR_IF_FEEDBACK(inp)) {
		/*
		 * The socket is flow-controlled, drop the packets
		 * until the inp is not flow controlled
		 */
		error = ENOBUFS;
		goto release;
	}
	/*
	 * If socket was bound to an ifindex, tell ip_output about it.
	 * If the ancillary IP_PKTINFO option contains an interface index,
	 * it takes precedence over the one specified by IP_BOUND_IF.
	 */
	if (ipoa.ipoa_boundif == IFSCOPE_NONE &&
	    (inp->inp_flags & INP_BOUND_IF)) {
		VERIFY(inp->inp_boundifp != NULL);
		ifnet_reference(inp->inp_boundifp);	/* for this routine */
		if (outif != NULL)
			ifnet_release(outif);
		outif = inp->inp_boundifp;
		ipoa.ipoa_boundif = outif->if_index;
	}
	if (inp->inp_flags & INP_NO_IFT_CELLULAR)
		ipoa.ipoa_flags |=  IPOAF_NO_CELLULAR;
	soopts |= IP_OUTARGS;

	/*
	 * If there was a routing change, discard cached route and check
	 * that we have a valid source address.  Reacquire a new source
	 * address if INADDR_ANY was specified.
	 */
	if (ROUTE_UNUSABLE(&inp->inp_route)) {
		struct in_ifaddr *ia = NULL;

		ROUTE_RELEASE(&inp->inp_route);

		/* src address is gone? */
		if (inp->inp_laddr.s_addr != INADDR_ANY &&
		    (ia = ifa_foraddr(inp->inp_laddr.s_addr)) == NULL) {
			if (!(inp->inp_flags & INP_INADDR_ANY) ||
			    (so->so_state & SS_ISCONNECTED)) {
				/*
				 * Rdar://5448998
				 * If the source address is gone, return an
				 * error if:
				 * - the source was specified
				 * - the socket was already connected
				 */
				soevent(so, (SO_FILT_HINT_LOCKED |
				    SO_FILT_HINT_NOSRCADDR));
				error = EADDRNOTAVAIL;
				goto release;
			} else {
				/* new src will be set later */
				inp->inp_laddr.s_addr = INADDR_ANY;
				inp->inp_last_outifp = NULL;
			}
		}
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);
	}

	origoutifp = inp->inp_last_outifp;

	/*
	 * IP_PKTINFO option check.  If a temporary scope or src address
	 * is provided, use it for this packet only and make sure we forget
	 * it after sending this datagram.
	 */
	if (pi_laddr.s_addr != INADDR_ANY ||
	    (ipoa.ipoa_boundif != IFSCOPE_NONE && pktinfo)) {
		/* temp src address for this datagram only */
		laddr = pi_laddr;
		origladdr.s_addr = INADDR_ANY;
		/* we don't want to keep the laddr or route */
		udp_dodisconnect = 1;
		/* remember we don't care about src addr.*/
		inp->inp_flags |= INP_INADDR_ANY;
	} else {
		origladdr = laddr = inp->inp_laddr;
	}

	origoutifp = inp->inp_last_outifp;
	faddr = inp->inp_faddr;
	lport = inp->inp_lport;
	fport = inp->inp_fport;

	if (addr) {
		sin = (struct sockaddr_in *)(void *)addr;
		if (faddr.s_addr != INADDR_ANY) {
			error = EISCONN;
			goto release;
		}
		if (lport == 0) {
			/*
			 * In case we don't have a local port set, go through
			 * the full connect.  We don't have a local port yet
			 * (i.e., we can't be looked up), so it's not an issue
			 * if the input runs at the same time we do this.
			 */
			/* if we have a source address specified, use that */
			if (pi_laddr.s_addr != INADDR_ANY)
				inp->inp_laddr = pi_laddr;
			/*
			 * If a scope is specified, use it.  Scope from
			 * IP_PKTINFO takes precendence over the the scope
			 * set via INP_BOUND_IF.
			 */
			error = in_pcbconnect(inp, addr, p, ipoa.ipoa_boundif,
			    &outif);
			if (error)
				goto release;

			laddr = inp->inp_laddr;
			lport = inp->inp_lport;
			faddr = inp->inp_faddr;
			fport = inp->inp_fport;
			udp_dodisconnect = 1;

			/* synch up in case in_pcbladdr() overrides */
			if (outif != NULL && ipoa.ipoa_boundif != IFSCOPE_NONE)
				ipoa.ipoa_boundif = outif->if_index;
		}
		else {
			/*
			 * Fast path case
			 *
			 * We have a full address and a local port; use those
			 * info to build the packet without changing the pcb
			 * and interfering with the input path. See 3851370.
			 *
			 * Scope from IP_PKTINFO takes precendence over the
			 * the scope set via INP_BOUND_IF.
			 */
			if (laddr.s_addr == INADDR_ANY) {
				if ((error = in_pcbladdr(inp, addr, &laddr,
				    ipoa.ipoa_boundif, &outif)) != 0)
					goto release;
				/*
				 * from pcbconnect: remember we don't
				 * care about src addr.
				 */
				inp->inp_flags |= INP_INADDR_ANY;

				/* synch up in case in_pcbladdr() overrides */
				if (outif != NULL &&
				    ipoa.ipoa_boundif != IFSCOPE_NONE)
					ipoa.ipoa_boundif = outif->if_index;
			}

			faddr = sin->sin_addr;
			fport = sin->sin_port;
		}
	} else {
		if (faddr.s_addr == INADDR_ANY) {
			error = ENOTCONN;
			goto release;
		}
	}

#if CONFIG_MACF_NET
	mac_mbuf_label_associate_inpcb(inp, m);
#endif /* CONFIG_MACF_NET */

	if (inp->inp_flowhash == 0)
		inp->inp_flowhash = inp_calc_flowhash(inp);

	/*
	 * Calculate data length and get a mbuf
	 * for UDP and IP headers.
	 */
	M_PREPEND(m, sizeof (struct udpiphdr), M_DONTWAIT);
	if (m == 0) {
		error = ENOBUFS;
		goto abort;
	}

	/*
	 * Fill in mbuf with extended UDP header
	 * and addresses and length put into network format.
	 */
	ui = mtod(m, struct udpiphdr *);
	bzero(ui->ui_x1, sizeof (ui->ui_x1));	/* XXX still needed? */
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_src = laddr;
	ui->ui_dst = faddr;
	ui->ui_sport = lport;
	ui->ui_dport = fport;
	ui->ui_ulen = htons((u_short)len + sizeof (struct udphdr));

	/*
	 * Set up checksum and output datagram.
	 */
	if (udpcksum && !(inp->inp_flags & INP_UDP_NOCKSUM)) {
		ui->ui_sum = in_pseudo(ui->ui_src.s_addr, ui->ui_dst.s_addr,
		    htons((u_short)len + sizeof (struct udphdr) + IPPROTO_UDP));
		m->m_pkthdr.csum_flags = CSUM_UDP;
		m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
	} else {
		ui->ui_sum = 0;
	}
	((struct ip *)ui)->ip_len = sizeof (struct udpiphdr) + len;
	((struct ip *)ui)->ip_ttl = inp->inp_ip_ttl;	/* XXX */
	((struct ip *)ui)->ip_tos = inp->inp_ip_tos;	/* XXX */
	udpstat.udps_opackets++;

	KERNEL_DEBUG(DBG_LAYER_OUT_END, ui->ui_dport, ui->ui_sport,
		     ui->ui_src.s_addr, ui->ui_dst.s_addr, ui->ui_ulen);

#if IPSEC
	if (ipsec_bypass == 0 && ipsec_setsocket(m, inp->inp_socket) != 0) {
		error = ENOBUFS;
		goto abort;
	}
#endif /* IPSEC */

	inpopts = inp->inp_options;
	soopts |= (inp->inp_socket->so_options & (SO_DONTROUTE | SO_BROADCAST));
	mopts = inp->inp_moptions;
	if (mopts != NULL) {
		IMO_LOCK(mopts);
		IMO_ADDREF_LOCKED(mopts);
		if (IN_MULTICAST(ntohl(ui->ui_dst.s_addr)) &&
		    mopts->imo_multicast_ifp != NULL) {
			/* no reference needed */
			inp->inp_last_outifp = mopts->imo_multicast_ifp;
		}
		IMO_UNLOCK(mopts);
	}

	/* Copy the cached route and take an extra reference */
	inp_route_copyout(inp, &ro);

	set_packet_service_class(m, so, msc, 0);
	m->m_pkthdr.pkt_flowsrc = FLOWSRC_INPCB;
	m->m_pkthdr.pkt_flowid = inp->inp_flowhash;
	m->m_pkthdr.pkt_proto = IPPROTO_UDP;
	m->m_pkthdr.pkt_flags |= (PKTF_FLOW_ID | PKTF_FLOW_LOCALSRC);
	if (flowadv)
		m->m_pkthdr.pkt_flags |= PKTF_FLOW_ADV;

	if (ipoa.ipoa_boundif != IFSCOPE_NONE)
		ipoa.ipoa_flags |= IPOAF_BOUND_IF;

	if (laddr.s_addr != INADDR_ANY)
		ipoa.ipoa_flags |= IPOAF_BOUND_SRCADDR;

	inp->inp_sndinprog_cnt++;

	socket_unlock(so, 0);
	error = ip_output(m, inpopts, &ro, soopts, mopts, &ipoa);
	m = NULL;
	socket_lock(so, 0);
	if (mopts != NULL)
		IMO_REMREF(mopts);

	if (error == 0 && nstat_collect) {
		boolean_t cell, wifi;

		if (ro.ro_rt != NULL) {
			cell = IFNET_IS_CELLULAR(ro.ro_rt->rt_ifp);
			wifi = (!cell && IFNET_IS_WIFI(ro.ro_rt->rt_ifp));
		} else {
			cell = wifi = FALSE;
		}
		INP_ADD_STAT(inp, cell, wifi, txpackets, 1);
		INP_ADD_STAT(inp, cell, wifi, txbytes, len);
	}

	if (flowadv && (adv->code == FADV_FLOW_CONTROLLED ||
	    adv->code == FADV_SUSPENDED)) {
		/* return a hint to the application that 
		 * the packet has been dropped
		 */
		error = ENOBUFS;
		inp_set_fc_state(inp, adv->code);
	}

	VERIFY(inp->inp_sndinprog_cnt > 0);
	if ( --inp->inp_sndinprog_cnt == 0)
		inp->inp_flags &= ~(INP_FC_FEEDBACK);

	/* Synchronize PCB cached route */
	inp_route_copyin(inp, &ro);

abort:
	if (udp_dodisconnect) {
		/* Always discard the cached route for unconnected socket */
		ROUTE_RELEASE(&inp->inp_route);
		in_pcbdisconnect(inp);
		inp->inp_laddr = origladdr;	/* XXX rehash? */
		/* no reference needed */
		inp->inp_last_outifp = origoutifp;
	} else if (inp->inp_route.ro_rt != NULL) {
		struct rtentry *rt = inp->inp_route.ro_rt;
		struct ifnet *outifp;

		if (rt->rt_flags & (RTF_MULTICAST|RTF_BROADCAST))
			rt = NULL;	/* unusable */
		/*
		 * Always discard if it is a multicast or broadcast route.
		 */
		if (rt == NULL)
			ROUTE_RELEASE(&inp->inp_route);

		/*
		 * If the destination route is unicast, update outifp with
		 * that of the route interface used by IP.
		 */
		if (rt != NULL && (outifp = rt->rt_ifp) != inp->inp_last_outifp)
			inp->inp_last_outifp = outifp;	/* no reference needed */
	} else {
		ROUTE_RELEASE(&inp->inp_route);
	}

	/*
	 * If output interface was cellular, and this socket is denied
	 * access to it, generate an event.
	 */
	if (error != 0 && (ipoa.ipoa_retflags & IPOARF_IFDENIED) &&
	    (inp->inp_flags & INP_NO_IFT_CELLULAR))
		soevent(so, (SO_FILT_HINT_LOCKED|SO_FILT_HINT_IFDENIED));

release:
	KERNEL_DEBUG(DBG_FNC_UDP_OUTPUT | DBG_FUNC_END, error, 0, 0, 0, 0);

	if (m != NULL)
		m_freem(m);

	if (outif != NULL)
		ifnet_release(outif);

	return (error);
}

u_int32_t	udp_sendspace = 9216;		/* really max datagram size */
/* 187 1K datagrams (approx 192 KB) */
u_int32_t	udp_recvspace = 187 * (1024 +
#if INET6
		    sizeof (struct sockaddr_in6)
#else /* !INET6 */
		    sizeof (struct sockaddr_in)
#endif /* !INET6 */
		);

/* Check that the values of udp send and recv space do not exceed sb_max */
static int
sysctl_udp_sospace(struct sysctl_oid *oidp, void *arg1, int arg2,
    struct sysctl_req *req)
{
#pragma unused(arg1, arg2)
	u_int32_t new_value = 0, *space_p = NULL;
	int changed = 0, error = 0;
	u_quad_t sb_effective_max = (sb_max/(MSIZE+MCLBYTES)) * MCLBYTES;

	switch (oidp->oid_number) {
	case UDPCTL_RECVSPACE:
		space_p = &udp_recvspace;
		break;
	case UDPCTL_MAXDGRAM:
		space_p = &udp_sendspace;
		break;
	default:
		return EINVAL;
	}
        error = sysctl_io_number(req, *space_p, sizeof (u_int32_t),
	    &new_value, &changed);
        if (changed) {
                if (new_value > 0 && new_value <= sb_effective_max)
                        *space_p = new_value;
                else
                        error = ERANGE;
        }
        return (error);
}

SYSCTL_PROC(_net_inet_udp, UDPCTL_RECVSPACE, recvspace,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &udp_recvspace, 0,
    &sysctl_udp_sospace, "IU", "Maximum incoming UDP datagram size");

SYSCTL_PROC(_net_inet_udp, UDPCTL_MAXDGRAM, maxdgram,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &udp_sendspace, 0,
    &sysctl_udp_sospace, "IU", "Maximum outgoing UDP datagram size");

static int
udp_abort(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		panic("%s: so=%p null inp\n", __func__, so);
		/* NOTREACHED */
	}
	soisdisconnected(so);
	in_pcbdetach(inp);
	return (0);
}

static int
udp_attach(struct socket *so, int proto, struct proc *p)
{
#pragma unused(proto)
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	if (inp != NULL) {
		panic ("%s so=%p inp=%p\n", __func__, so, inp);
		/* NOTREACHED */
	}
	error = in_pcballoc(so, &udbinfo, p);
	if (error != 0)
		return (error);
	error = soreserve(so, udp_sendspace, udp_recvspace);
	if (error != 0)
		return (error);
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_ttl = ip_defttl;
	if (nstat_collect)
		nstat_udp_new_pcb(inp);
	return (0);
}

static int
udp_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int error;

	if (nam->sa_family != 0 && nam->sa_family != AF_INET &&
	    nam->sa_family != AF_INET6)
		return (EAFNOSUPPORT);

	inp = sotoinpcb(so);
	if (inp == NULL || (inp->inp_flags2 & INP2_WANT_FLOW_DIVERT))
		return (inp == NULL ? EINVAL : EPROTOTYPE);
	error = in_pcbbind(inp, nam, p);
	return (error);
}

static int
udp_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	if (inp == NULL || (inp->inp_flags2 & INP2_WANT_FLOW_DIVERT))
		return (inp == NULL ? EINVAL : EPROTOTYPE);
	if (inp->inp_faddr.s_addr != INADDR_ANY)
		return (EISCONN);
	error = in_pcbconnect(inp, nam, p, IFSCOPE_NONE, NULL);
	if (error == 0) {
		soisconnected(so);
		if (inp->inp_flowhash == 0)
			inp->inp_flowhash = inp_calc_flowhash(inp);
	}
	return (error);
}

int
udp_connectx_common(struct socket *so, int af,
    struct sockaddr_list **src_sl, struct sockaddr_list **dst_sl,
    struct proc *p, uint32_t ifscope, associd_t aid, connid_t *pcid,
    uint32_t flags, void *arg, uint32_t arglen)
{
#pragma unused(aid, flags, arg, arglen)
	struct sockaddr_entry *src_se = NULL, *dst_se = NULL;
	struct inpcb *inp = sotoinpcb(so);
	int error;

	if (inp == NULL)
		return (EINVAL);

	VERIFY(dst_sl != NULL);

	/* select source (if specified) and destination addresses */
	error = in_selectaddrs(af, src_sl, &src_se, dst_sl, &dst_se);
	if (error != 0)
		return (error);

	VERIFY(*dst_sl != NULL && dst_se != NULL);
	VERIFY(src_se == NULL || *src_sl != NULL);
	VERIFY(dst_se->se_addr->sa_family == af);
	VERIFY(src_se == NULL || src_se->se_addr->sa_family == af);

	/* bind socket to the specified interface, if requested */
	if (ifscope != IFSCOPE_NONE &&
	    (error = inp_bindif(inp, ifscope, NULL)) != 0)
		return (error);

	/* if source address and/or port is specified, bind to it */
	if (src_se != NULL) {
		struct sockaddr *sa = src_se->se_addr;
		error = sobindlock(so, sa, 0);	/* already locked */
		if (error != 0)
			return (error);
	}

	switch (af) {
	case AF_INET:
		error = udp_connect(so, dst_se->se_addr, p);
		break;
#if INET6
	case AF_INET6:
		error = udp6_connect(so, dst_se->se_addr, p);
		break;
#endif /* INET6 */
	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	if (error == 0 && pcid != NULL)
		*pcid = 1;	/* there is only 1 connection for a UDP */

	return (error);
}

static int
udp_connectx(struct socket *so, struct sockaddr_list **src_sl,
    struct sockaddr_list **dst_sl, struct proc *p, uint32_t ifscope,
    associd_t aid, connid_t *pcid, uint32_t flags, void *arg,
    uint32_t arglen)
{
	return (udp_connectx_common(so, AF_INET, src_sl, dst_sl,
	    p, ifscope, aid, pcid, flags, arg, arglen));
}

static int
udp_detach(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		panic("%s: so=%p null inp\n", __func__, so);
		/* NOTREACHED */
	}
	in_pcbdetach(inp);
	inp->inp_state = INPCB_STATE_DEAD;
	return (0);
}

static int
udp_disconnect(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL || (inp->inp_flags2 & INP2_WANT_FLOW_DIVERT))
		return (inp == NULL ? EINVAL : EPROTOTYPE);
	if (inp->inp_faddr.s_addr == INADDR_ANY)
		return (ENOTCONN);

	in_pcbdisconnect(inp);

	/* reset flow controlled state, just in case */
	inp_reset_fc_state(inp);

	inp->inp_laddr.s_addr = INADDR_ANY;
	so->so_state &= ~SS_ISCONNECTED;		/* XXX */
	inp->inp_last_outifp = NULL;
	return (0);
}

static int
udp_disconnectx(struct socket *so, associd_t aid, connid_t cid)
{
#pragma unused(cid)
	if (aid != ASSOCID_ANY && aid != ASSOCID_ALL)
		return (EINVAL);

	return (udp_disconnect(so));
}

static int
udp_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *addr, struct mbuf *control, struct proc *p)
{
#pragma unused(flags)
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL || (inp->inp_flags2 & INP2_WANT_FLOW_DIVERT)) {
		if (m != NULL)
			m_freem(m);
		if (control != NULL)
			m_freem(control);
		return (inp == NULL ? EINVAL : EPROTOTYPE);
	}

	return (udp_output(inp, m, addr, control, p));
}

int
udp_shutdown(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL)
		return (EINVAL);
	socantsendmore(so);
	return (0);
}

int
udp_lock(struct socket *so, int refcount, void *debug)
{
	void *lr_saved;

	if (debug == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = debug;

	if (so->so_pcb != NULL) {
		lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx,
		    LCK_MTX_ASSERT_NOTOWNED);
		lck_mtx_lock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
	} else {
		panic("%s: so=%p NO PCB! lr=%p lrh= %s\n", __func__,
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	}
	if (refcount)
		so->so_usecount++;

	so->lock_lr[so->next_lock_lr] = lr_saved;
	so->next_lock_lr = (so->next_lock_lr+1) % SO_LCKDBG_MAX;
	return (0);
}

int
udp_unlock(struct socket *so, int refcount, void *debug)
{
	void *lr_saved;

	if (debug == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = debug;

	if (refcount)
		so->so_usecount--;

	if (so->so_pcb == NULL) {
		panic("%s: so=%p NO PCB! lr=%p lrh= %s\n", __func__,
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	} else {
		lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx,
		    LCK_MTX_ASSERT_OWNED);
		so->unlock_lr[so->next_unlock_lr] = lr_saved;
		so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;
		lck_mtx_unlock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
	}
	return (0);
}

lck_mtx_t *
udp_getlock(struct socket *so, int locktype)
{
#pragma unused(locktype)
	struct inpcb *inp = sotoinpcb(so);

	if (so->so_pcb == NULL) {
		panic("%s: so=%p NULL so_pcb lrh= %s\n", __func__,
		    so, solockhistory_nr(so));
		/* NOTREACHED */
	}
	return (&inp->inpcb_mtx);
}

/*
 * UDP garbage collector callback (inpcb_timer_func_t).
 *
 * Returns > 0 to keep timer active.
 */
static void
udp_gc(struct inpcbinfo *ipi)
{
	struct inpcb *inp, *inpnxt;
	struct socket *so;

	if (lck_rw_try_lock_exclusive(ipi->ipi_lock) == FALSE) {
		if (udp_gc_done == TRUE) {
			udp_gc_done = FALSE;
			/* couldn't get the lock, must lock next time */
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
			return;
		}
		lck_rw_lock_exclusive(ipi->ipi_lock);
	}

	udp_gc_done = TRUE;

	for (inp = udb.lh_first; inp != NULL; inp = inpnxt) {
		inpnxt = inp->inp_list.le_next;

		/*
		 * Skip unless it's STOPUSING; garbage collector will
		 * be triggered by in_pcb_checkstate() upon setting
		 * wantcnt to that value.  If the PCB is already dead,
		 * keep gc active to anticipate wantcnt changing.
		 */
		if (inp->inp_wantcnt != WNT_STOPUSING)
			continue;

		/*
		 * Skip if busy, no hurry for cleanup.  Keep gc active
		 * and try the lock again during next round.
		 */
		if (!lck_mtx_try_lock(&inp->inpcb_mtx)) {
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
			continue;
		}

		/*
		 * Keep gc active unless usecount is 0.
		 */
		so = inp->inp_socket;
		if (so->so_usecount == 0) {
			if (inp->inp_state != INPCB_STATE_DEAD) {
#if INET6
				if (SOCK_CHECK_DOM(so, PF_INET6))
					in6_pcbdetach(inp);
				else
#endif /* INET6 */
					in_pcbdetach(inp);
			}
			in_pcbdispose(inp);
		} else {
			lck_mtx_unlock(&inp->inpcb_mtx);
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
		}
	}
	lck_rw_done(ipi->ipi_lock);

	return;
}

static int
udp_getstat SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (req->oldptr == USER_ADDR_NULL)
		req->oldlen = (size_t)sizeof (struct udpstat);

	return (SYSCTL_OUT(req, &udpstat, MIN(sizeof (udpstat), req->oldlen)));
}

void
udp_in_cksum_stats(u_int32_t len)
{
	udpstat.udps_rcv_swcsum++;
	udpstat.udps_rcv_swcsum_bytes += len;
}

void
udp_out_cksum_stats(u_int32_t len)
{
	udpstat.udps_snd_swcsum++;
	udpstat.udps_snd_swcsum_bytes += len;
}

#if INET6
void
udp_in6_cksum_stats(u_int32_t len)
{
	udpstat.udps_rcv6_swcsum++;
	udpstat.udps_rcv6_swcsum_bytes += len;
}

void
udp_out6_cksum_stats(u_int32_t len)
{
	udpstat.udps_snd6_swcsum++;
	udpstat.udps_snd6_swcsum_bytes += len;
}
#endif /* INET6 */

/*
 * Checksum extended UDP header and data.
 */
static int
udp_input_checksum(struct mbuf *m, struct udphdr *uh, int off, int ulen)
{
	struct ifnet *ifp = m->m_pkthdr.rcvif;
	struct ip *ip = mtod(m, struct ip *);
	struct ipovly *ipov = (struct ipovly *)ip;

	if (uh->uh_sum == 0) {
		udpstat.udps_nosum++;
		return (0);
	}

	if ((hwcksum_rx || (ifp->if_flags & IFF_LOOPBACK) ||
	    (m->m_pkthdr.pkt_flags & PKTF_LOOP)) &&
	    (m->m_pkthdr.csum_flags & CSUM_DATA_VALID)) {
		if (m->m_pkthdr.csum_flags & CSUM_PSEUDO_HDR) {
			uh->uh_sum = m->m_pkthdr.csum_rx_val;
		} else {
			uint16_t sum = m->m_pkthdr.csum_rx_val;
			uint16_t start = m->m_pkthdr.csum_rx_start;

			/*
			 * Perform 1's complement adjustment of octets
			 * that got included/excluded in the hardware-
			 * calculated checksum value.  Ignore cases
			 * where the value includes or excludes the
			 * IP header span, as the sum for those octets
			 * would already be 0xffff and thus no-op.
			 */
			if ((m->m_pkthdr.csum_flags & CSUM_PARTIAL) &&
			    start != 0 && (off - start) != off) {
#if BYTE_ORDER != BIG_ENDIAN
				if (start < off) {
					HTONS(ip->ip_len);
					HTONS(ip->ip_off);
				}
#endif /* BYTE_ORDER != BIG_ENDIAN */
				/* callee folds in sum */
				sum = m_adj_sum16(m, start, off, sum);
#if BYTE_ORDER != BIG_ENDIAN
				if (start < off) {
					NTOHS(ip->ip_off);
					NTOHS(ip->ip_len);
				}
#endif /* BYTE_ORDER != BIG_ENDIAN */
			}

			/* callee folds in sum */
			uh->uh_sum = in_pseudo(ip->ip_src.s_addr,
			    ip->ip_dst.s_addr, sum + htonl(ulen + IPPROTO_UDP));
		}
		uh->uh_sum ^= 0xffff;
	} else {
		uint16_t ip_sum;
		char b[9];

		bcopy(ipov->ih_x1, b, sizeof (ipov->ih_x1));
		bzero(ipov->ih_x1, sizeof (ipov->ih_x1));
		ip_sum = ipov->ih_len;
		ipov->ih_len = uh->uh_ulen;
		uh->uh_sum = in_cksum(m, ulen + sizeof (struct ip));
		bcopy(b, ipov->ih_x1, sizeof (ipov->ih_x1));
		ipov->ih_len = ip_sum;

		udp_in_cksum_stats(ulen);
	}

	if (uh->uh_sum != 0) {
		udpstat.udps_badsum++;
		IF_UDP_STATINC(ifp, badchksum);
		return (-1);
	}

	return (0);
}
