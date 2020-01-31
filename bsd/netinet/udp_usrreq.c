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
#include <net/net_api_stats.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_tclass.h>
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

#if NECP
#include <net/necp.h>
#endif /* NECP */

#if FLOW_DIVERT
#include <netinet/flow_divert.h>
#endif /* FLOW_DIVERT */

#if CONTENT_FILTER
#include <net/content_filter.h>
#endif /* CONTENT_FILTER */

#define DBG_LAYER_IN_BEG        NETDBG_CODE(DBG_NETUDP, 0)
#define DBG_LAYER_IN_END        NETDBG_CODE(DBG_NETUDP, 2)
#define DBG_LAYER_OUT_BEG       NETDBG_CODE(DBG_NETUDP, 1)
#define DBG_LAYER_OUT_END       NETDBG_CODE(DBG_NETUDP, 3)
#define DBG_FNC_UDP_INPUT       NETDBG_CODE(DBG_NETUDP, (5 << 8))
#define DBG_FNC_UDP_OUTPUT      NETDBG_CODE(DBG_NETUDP, (6 << 8) | 1)

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */
#ifndef COMPAT_42
static int udpcksum = 1;
#else
static int udpcksum = 0;                /* XXX */
#endif
SYSCTL_INT(_net_inet_udp, UDPCTL_CHECKSUM, checksum,
    CTLFLAG_RW | CTLFLAG_LOCKED, &udpcksum, 0, "");

int udp_log_in_vain = 0;
SYSCTL_INT(_net_inet_udp, OID_AUTO, log_in_vain, CTLFLAG_RW | CTLFLAG_LOCKED,
    &udp_log_in_vain, 0, "Log all incoming UDP packets");

static int blackhole = 0;
SYSCTL_INT(_net_inet_udp, OID_AUTO, blackhole, CTLFLAG_RW | CTLFLAG_LOCKED,
    &blackhole, 0, "Do not send port unreachables for refused connects");

struct inpcbhead udb;           /* from udp_var.h */
#define udb6    udb  /* for KAME src sync over BSD*'s */
struct inpcbinfo udbinfo;

#ifndef UDBHASHSIZE
#define UDBHASHSIZE 16
#endif

/* Garbage collection performed during most recent udp_gc() run */
static boolean_t udp_gc_done = FALSE;

#if IPFIREWALL
extern int fw_verbose;
extern void ipfwsyslog(int level, const char *format, ...);
extern void ipfw_stealth_stats_incr_udp(void);

/* Apple logging, log to ipfw.log */
#define log_in_vain_log(a) {                                            \
	if ((udp_log_in_vain == 3) && (fw_verbose == 2)) {              \
	        ipfwsyslog a;                                           \
	} else if ((udp_log_in_vain == 4) && (fw_verbose == 2)) {       \
	        ipfw_stealth_stats_incr_udp();                          \
	} else {                                                        \
	        log a;                                                  \
	}                                                               \
}
#else /* !IPFIREWALL */
#define log_in_vain_log(a) { log a; }
#endif /* !IPFIREWALL */

static int udp_getstat SYSCTL_HANDLER_ARGS;
struct  udpstat udpstat;        /* from udp_var.h */
SYSCTL_PROC(_net_inet_udp, UDPCTL_STATS, stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
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
	struct sockaddr_in6     uin6_sin;
	u_char                  uin6_init_done : 1;
};
struct udp_ip6 {
	struct ip6_hdr          uip6_ip6;
	u_char                  uip6_init_done : 1;
};

int udp_abort(struct socket *);
int udp_attach(struct socket *, int, struct proc *);
int udp_bind(struct socket *, struct sockaddr *, struct proc *);
int udp_connect(struct socket *, struct sockaddr *, struct proc *);
int udp_connectx(struct socket *, struct sockaddr *,
    struct sockaddr *, struct proc *, uint32_t, sae_associd_t,
    sae_connid_t *, uint32_t, void *, uint32_t, struct uio *, user_ssize_t *);
int udp_detach(struct socket *);
int udp_disconnect(struct socket *);
int udp_disconnectx(struct socket *, sae_associd_t, sae_connid_t);
int udp_send(struct socket *, int, struct mbuf *, struct sockaddr *,
    struct mbuf *, struct proc *);
static void udp_append(struct inpcb *, struct ip *, struct mbuf *, int,
    struct sockaddr_in *, struct udp_in6 *, struct udp_ip6 *, struct ifnet *);
#else /* !INET6 */
static void udp_append(struct inpcb *, struct ip *, struct mbuf *, int,
    struct sockaddr_in *, struct ifnet *);
#endif /* !INET6 */
static int udp_input_checksum(struct mbuf *, struct udphdr *, int, int);
int udp_output(struct inpcb *, struct mbuf *, struct sockaddr *,
    struct mbuf *, struct proc *);
static void ip_2_ip6_hdr(struct ip6_hdr *ip6, struct ip *ip);
static void udp_gc(struct inpcbinfo *);

struct pr_usrreqs udp_usrreqs = {
	.pru_abort =            udp_abort,
	.pru_attach =           udp_attach,
	.pru_bind =             udp_bind,
	.pru_connect =          udp_connect,
	.pru_connectx =         udp_connectx,
	.pru_control =          in_control,
	.pru_detach =           udp_detach,
	.pru_disconnect =       udp_disconnect,
	.pru_disconnectx =      udp_disconnectx,
	.pru_peeraddr =         in_getpeeraddr,
	.pru_send =             udp_send,
	.pru_shutdown =         udp_shutdown,
	.pru_sockaddr =         in_getsockaddr,
	.pru_sosend =           sosend,
	.pru_soreceive =        soreceive,
	.pru_soreceive_list =   soreceive_list,
};

void
udp_init(struct protosw *pp, struct domain *dp)
{
#pragma unused(dp)
	static int udp_initialized = 0;
	vm_size_t               str_size;
	struct inpcbinfo        *pcbinfo;

	VERIFY((pp->pr_flags & (PR_INITIALIZED | PR_ATTACHED)) == PR_ATTACHED);

	if (udp_initialized) {
		return;
	}
	udp_initialized = 1;
	uint32_t pool_size = (nmbclusters << MCLSHIFT) >> MBSHIFT;
	if (pool_size >= 96) {
		/* Improves 10GbE UDP performance. */
		udp_recvspace = 786896;
	}
	LIST_INIT(&udb);
	udbinfo.ipi_listhead = &udb;
	udbinfo.ipi_hashbase = hashinit(UDBHASHSIZE, M_PCB,
	    &udbinfo.ipi_hashmask);
	udbinfo.ipi_porthashbase = hashinit(UDBHASHSIZE, M_PCB,
	    &udbinfo.ipi_porthashmask);
	str_size = (vm_size_t) sizeof(struct inpcb);
	udbinfo.ipi_zone = zinit(str_size, 80000 * str_size, 8192, "udpcb");

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
	boolean_t wired = (!wifi && IFNET_IS_WIRED(ifp));

	bzero(&udp_in, sizeof(udp_in));
	udp_in.sin_len = sizeof(struct sockaddr_in);
	udp_in.sin_family = AF_INET;
#if INET6
	bzero(&udp_in6, sizeof(udp_in6));
	udp_in6.uin6_sin.sin6_len = sizeof(struct sockaddr_in6);
	udp_in6.uin6_sin.sin6_family = AF_INET6;
#endif /* INET6 */

	udpstat.udps_ipackets++;

	KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_START, 0, 0, 0, 0, 0);

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	/*
	 * Strip IP options, if any; should skip this,
	 * make available to user, and use on returned packets,
	 * but we don't yet have a way to check the checksum
	 * with options still present.
	 */
	if (iphlen > sizeof(struct ip)) {
		ip_stripoptions(m);
		iphlen = sizeof(struct ip);
	}

	/*
	 * Get IP and UDP header together in first mbuf.
	 */
	ip = mtod(m, struct ip *);
	if (m->m_len < iphlen + sizeof(struct udphdr)) {
		m = m_pullup(m, iphlen + sizeof(struct udphdr));
		if (m == NULL) {
			udpstat.udps_hdrops++;
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END,
			    0, 0, 0, 0, 0);
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
		if (len > ip->ip_len || len < sizeof(struct udphdr)) {
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
	if (udp_input_checksum(m, uh, iphlen, len)) {
		goto bad;
	}

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

			if (inp->inp_socket == NULL) {
				continue;
			}
			if (inp != sotoinpcb(inp->inp_socket)) {
				panic("%s: bad so back ptr inp=%p\n",
				    __func__, inp);
				/* NOTREACHED */
			}
#if INET6
			if ((inp->inp_vflag & INP_IPV4) == 0) {
				continue;
			}
#endif /* INET6 */
			if (inp_restricted_recv(inp, ifp)) {
				continue;
			}

			if ((inp->inp_moptions == NULL) &&
			    (ntohl(ip->ip_dst.s_addr) !=
			    INADDR_ALLHOSTS_GROUP) && (isbroadcast == 0)) {
				continue;
			}

			if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) ==
			    WNT_STOPUSING) {
				continue;
			}

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

				bzero(&group, sizeof(struct sockaddr_in));
				group.sin_len = sizeof(struct sockaddr_in);
				group.sin_family = AF_INET;
				group.sin_addr = ip->ip_dst;

				blocked = imo_multi_filter(imo, ifp,
				    &group, &udp_in);
				if (blocked == MCAST_PASS) {
					foundmembership = 1;
				}

				IMO_UNLOCK(imo);
				if (!foundmembership) {
					udp_unlock(inp->inp_socket, 1, 0);
					if (blocked == MCAST_NOTSMEMBER ||
					    blocked == MCAST_MUTED) {
						udpstat.udps_filtermcast++;
					}
					continue;
				}
				foundmembership = 0;
			}

			reuse_sock = (inp->inp_socket->so_options &
			    (SO_REUSEPORT | SO_REUSEADDR));

#if NECP
			skipit = 0;
			if (!necp_socket_is_allowed_to_send_recv_v4(inp,
			    uh->uh_dport, uh->uh_sport, &ip->ip_dst,
			    &ip->ip_src, ifp, NULL, NULL, NULL)) {
				/* do not inject data to pcb */
				skipit = 1;
			}
			if (skipit == 0)
#endif /* NECP */
			{
				struct mbuf *n = NULL;

				if (reuse_sock) {
					n = m_copy(m, 0, M_COPYALL);
				}
#if INET6
				udp_append(inp, ip, m,
				    iphlen + sizeof(struct udphdr),
				    &udp_in, &udp_in6, &udp_ip6, ifp);
#else /* !INET6 */
				udp_append(inp, ip, m,
				    iphlen + sizeof(struct udphdr),
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
			if (reuse_sock == 0 || m == NULL) {
				break;
			}

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
		if (m != NULL) {
			m_freem(m);
		}
		KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
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
		int payload_len = len - sizeof(struct udphdr) > 4 ? 4 :
		    len - sizeof(struct udphdr);

		if (m->m_len < iphlen + sizeof(struct udphdr) + payload_len) {
			if ((m = m_pullup(m, iphlen + sizeof(struct udphdr) +
			    payload_len)) == NULL) {
				udpstat.udps_hdrops++;
				KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END,
				    0, 0, 0, 0, 0);
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
		if (payload_len == 1 && *(u_int8_t *)
		    ((caddr_t)uh + sizeof(struct udphdr)) == 0xFF) {
			m_freem(m);
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END,
			    0, 0, 0, 0, 0);
			return;
		} else if (payload_len == 4 && *(u_int32_t *)(void *)
		    ((caddr_t)uh + sizeof(struct udphdr)) != 0) {
			/* UDP encapsulated IPSec packet to pass through NAT */
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END,
			    0, 0, 0, 0, 0);
			/* preserve the udp header */
			esp4_input(m, iphlen + sizeof(struct udphdr));
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
				    &ip->ip_dst, buf, sizeof(buf)),
				    ntohs(uh->uh_dport), inet_ntop(AF_INET,
				    &ip->ip_src, buf2, sizeof(buf2)),
				    ntohs(uh->uh_sport));
			} else if (!(m->m_flags & (M_BCAST | M_MCAST)) &&
			    ip->ip_dst.s_addr != ip->ip_src.s_addr) {
				log_in_vain_log((LOG_INFO,
				    "Stealth Mode connection attempt to "
				    "UDP %s:%d from %s:%d\n", inet_ntop(AF_INET,
				    &ip->ip_dst, buf, sizeof(buf)),
				    ntohs(uh->uh_dport), inet_ntop(AF_INET,
				    &ip->ip_src, buf2, sizeof(buf2)),
				    ntohs(uh->uh_sport)))
			}
		}
		udpstat.udps_noport++;
		if (m->m_flags & (M_BCAST | M_MCAST)) {
			udpstat.udps_noportbcast++;
			goto bad;
		}
#if ICMP_BANDLIM
		if (badport_bandlim(BANDLIM_ICMP_UNREACH) < 0) {
			goto bad;
		}
#endif /* ICMP_BANDLIM */
		if (blackhole) {
			if (ifp && ifp->if_type != IFT_LOOP) {
				goto bad;
			}
		}
		*ip = save_ip;
		ip->ip_len += iphlen;
		icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0);
		KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
		return;
	}
	udp_lock(inp->inp_socket, 1, 0);

	if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
		udp_unlock(inp->inp_socket, 1, 0);
		IF_UDP_STATINC(ifp, cleanup);
		goto bad;
	}
#if NECP
	if (!necp_socket_is_allowed_to_send_recv_v4(inp, uh->uh_dport,
	    uh->uh_sport, &ip->ip_dst, &ip->ip_src, ifp, NULL, NULL, NULL)) {
		udp_unlock(inp->inp_socket, 1, 0);
		IF_UDP_STATINC(ifp, badipsec);
		goto bad;
	}
#endif /* NECP */

	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	udp_in.sin_port = uh->uh_sport;
	udp_in.sin_addr = ip->ip_src;
	if ((inp->inp_flags & INP_CONTROLOPTS) != 0 ||
	    (inp->inp_socket->so_options & SO_TIMESTAMP) != 0 ||
	    (inp->inp_socket->so_options & SO_TIMESTAMP_MONOTONIC) != 0 ||
	    (inp->inp_socket->so_options & SO_TIMESTAMP_CONTINUOUS) != 0) {
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
	m_adj(m, iphlen + sizeof(struct udphdr));

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
		INP_ADD_STAT(inp, cell, wifi, wired, rxpackets, 1);
		INP_ADD_STAT(inp, cell, wifi, wired, rxbytes, m->m_pkthdr.len);
		inp_set_activity_bitmap(inp);
	}
	so_recv_data_stat(inp->inp_socket, m, 0);
	if (sbappendaddr(&inp->inp_socket->so_rcv, append_sa,
	    m, opts, NULL) == 0) {
		udpstat.udps_fullsock++;
	} else {
		sorwakeup(inp->inp_socket);
	}
	udp_unlock(inp->inp_socket, 1, 0);
	KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
	return;
bad:
	m_freem(m);
	if (opts) {
		m_freem(opts);
	}
	KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

#if INET6
static void
ip_2_ip6_hdr(struct ip6_hdr *ip6, struct ip *ip)
{
	bzero(ip6, sizeof(*ip6));

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
	boolean_t wired = (!wifi && IFNET_IS_WIRED(ifp));
	int ret = 0;

#if CONFIG_MACF_NET
	if (mac_inpcb_check_deliver(last, n, AF_INET, SOCK_DGRAM) != 0) {
		m_freem(n);
		return;
	}
#endif /* CONFIG_MACF_NET */
	if ((last->inp_flags & INP_CONTROLOPTS) != 0 ||
	    (last->inp_socket->so_options & SO_TIMESTAMP) != 0 ||
	    (last->inp_socket->so_options & SO_TIMESTAMP_MONOTONIC) != 0 ||
	    (last->inp_socket->so_options & SO_TIMESTAMP_CONTINUOUS) != 0) {
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
		INP_ADD_STAT(last, cell, wifi, wired, rxpackets, 1);
		INP_ADD_STAT(last, cell, wifi, wired, rxbytes,
		    n->m_pkthdr.len);
		inp_set_activity_bitmap(last);
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
udp_ctlinput(int cmd, struct sockaddr *sa, void *vip, __unused struct ifnet * ifp)
{
	struct ip *ip = vip;
	void (*notify)(struct inpcb *, int) = udp_notify;
	struct in_addr faddr;
	struct inpcb *inp = NULL;

	faddr = ((struct sockaddr_in *)(void *)sa)->sin_addr;
	if (sa->sa_family != AF_INET || faddr.s_addr == INADDR_ANY) {
		return;
	}

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

		bcopy(((caddr_t)ip + (ip->ip_hl << 2)), &uh, sizeof(uh));
		inp = in_pcblookup_hash(&udbinfo, faddr, uh.uh_dport,
		    ip->ip_src, uh.uh_sport, 0, NULL);
		if (inp != NULL && inp->inp_socket != NULL) {
			udp_lock(inp->inp_socket, 1, 0);
			if (in_pcb_checkstate(inp, WNT_RELEASE, 1) ==
			    WNT_STOPUSING) {
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
	int     error = 0, optval = 0;
	struct  inpcb *inp;

	/* Allow <SOL_SOCKET,SO_FLUSH> at this level */
	if (sopt->sopt_level != IPPROTO_UDP &&
	    !(sopt->sopt_level == SOL_SOCKET && sopt->sopt_name == SO_FLUSH)) {
		return ip_ctloutput(so, sopt);
	}

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

			if ((error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval))) != 0) {
				break;
			}

			if (optval != 0) {
				inp->inp_flags |= INP_UDP_NOCKSUM;
			} else {
				inp->inp_flags &= ~INP_UDP_NOCKSUM;
			}
			break;
		case UDP_KEEPALIVE_OFFLOAD:
		{
			struct udp_keepalive_offload ka;
			/*
			 * If the socket is not connected, the stack will
			 * not know the destination address to put in the
			 * keepalive datagram. Return an error now instead
			 * of failing later.
			 */
			if (!(so->so_state & SS_ISCONNECTED)) {
				error = EINVAL;
				break;
			}
			if (sopt->sopt_valsize != sizeof(ka)) {
				error = EINVAL;
				break;
			}
			if ((error = sooptcopyin(sopt, &ka, sizeof(ka),
			    sizeof(ka))) != 0) {
				break;
			}

			/* application should specify the type */
			if (ka.ka_type == 0) {
				return EINVAL;
			}

			if (ka.ka_interval == 0) {
				/*
				 * if interval is 0, disable the offload
				 * mechanism
				 */
				if (inp->inp_keepalive_data != NULL) {
					FREE(inp->inp_keepalive_data,
					    M_TEMP);
				}
				inp->inp_keepalive_data = NULL;
				inp->inp_keepalive_datalen = 0;
				inp->inp_keepalive_interval = 0;
				inp->inp_keepalive_type = 0;
				inp->inp_flags2 &= ~INP2_KEEPALIVE_OFFLOAD;
			} else {
				if (inp->inp_keepalive_data != NULL) {
					FREE(inp->inp_keepalive_data,
					    M_TEMP);
					inp->inp_keepalive_data = NULL;
				}

				inp->inp_keepalive_datalen = min(
					ka.ka_data_len,
					UDP_KEEPALIVE_OFFLOAD_DATA_SIZE);
				if (inp->inp_keepalive_datalen > 0) {
					MALLOC(inp->inp_keepalive_data,
					    u_int8_t *,
					    inp->inp_keepalive_datalen,
					    M_TEMP, M_WAITOK);
					if (inp->inp_keepalive_data == NULL) {
						inp->inp_keepalive_datalen = 0;
						error = ENOMEM;
						break;
					}
					bcopy(ka.ka_data,
					    inp->inp_keepalive_data,
					    inp->inp_keepalive_datalen);
				} else {
					inp->inp_keepalive_datalen = 0;
				}
				inp->inp_keepalive_interval =
				    min(UDP_KEEPALIVE_INTERVAL_MAX_SECONDS,
				    ka.ka_interval);
				inp->inp_keepalive_type = ka.ka_type;
				inp->inp_flags2 |= INP2_KEEPALIVE_OFFLOAD;
			}
			break;
		}
		case SO_FLUSH:
			if ((error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval))) != 0) {
				break;
			}

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
		if (error == 0) {
			error = sooptcopyout(sopt, &optval, sizeof(optval));
		}
		break;
	}
	return error;
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
		req->oldidx = 2 * (sizeof(xig))
		    + (n + n / 8) * sizeof(struct xinpcb);
		lck_rw_done(udbinfo.ipi_lock);
		return 0;
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(udbinfo.ipi_lock);
		return EPERM;
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = udbinfo.ipi_gencnt;
	n = udbinfo.ipi_count;

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof(xig);
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof(xig));
	if (error) {
		lck_rw_done(udbinfo.ipi_lock);
		return error;
	}
	/*
	 * We are done if there is no pcb
	 */
	if (n == 0) {
		lck_rw_done(udbinfo.ipi_lock);
		return 0;
	}

	inp_list = _MALLOC(n * sizeof(*inp_list), M_TEMP, M_WAITOK);
	if (inp_list == 0) {
		lck_rw_done(udbinfo.ipi_lock);
		return ENOMEM;
	}

	for (inp = LIST_FIRST(udbinfo.ipi_listhead), i = 0; inp && i < n;
	    inp = LIST_NEXT(inp, inp_list)) {
		if (inp->inp_gencnt <= gencnt &&
		    inp->inp_state != INPCB_STATE_DEAD) {
			inp_list[i++] = inp;
		}
	}
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		struct xinpcb xi;

		inp = inp_list[i];

		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING) {
			continue;
		}
		udp_lock(inp->inp_socket, 1, 0);
		if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
			udp_unlock(inp->inp_socket, 1, 0);
			continue;
		}
		if (inp->inp_gencnt > gencnt) {
			udp_unlock(inp->inp_socket, 1, 0);
			continue;
		}

		bzero(&xi, sizeof(xi));
		xi.xi_len = sizeof(xi);
		/* XXX should avoid extra copy */
		inpcb_to_compat(inp, &xi.xi_inp);
		if (inp->inp_socket) {
			sotoxsocket(inp->inp_socket, &xi.xi_socket);
		}

		udp_unlock(inp->inp_socket, 1, 0);

		error = SYSCTL_OUT(req, &xi, sizeof(xi));
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		bzero(&xig, sizeof(xig));
		xig.xig_len = sizeof(xig);
		xig.xig_gen = udbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = udbinfo.ipi_count;
		error = SYSCTL_OUT(req, &xig, sizeof(xig));
	}
	FREE(inp_list, M_TEMP);
	lck_rw_done(udbinfo.ipi_lock);
	return error;
}

SYSCTL_PROC(_net_inet_udp, UDPCTL_PCBLIST, pcblist,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, udp_pcblist,
    "S,xinpcb", "List of active UDP sockets");

#if !CONFIG_EMBEDDED

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
		    2 * (sizeof(xig)) + (n + n / 8) * sizeof(struct xinpcb64);
		lck_rw_done(udbinfo.ipi_lock);
		return 0;
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(udbinfo.ipi_lock);
		return EPERM;
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = udbinfo.ipi_gencnt;
	n = udbinfo.ipi_count;

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof(xig);
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof(xig));
	if (error) {
		lck_rw_done(udbinfo.ipi_lock);
		return error;
	}
	/*
	 * We are done if there is no pcb
	 */
	if (n == 0) {
		lck_rw_done(udbinfo.ipi_lock);
		return 0;
	}

	inp_list = _MALLOC(n * sizeof(*inp_list), M_TEMP, M_WAITOK);
	if (inp_list == 0) {
		lck_rw_done(udbinfo.ipi_lock);
		return ENOMEM;
	}

	for (inp = LIST_FIRST(udbinfo.ipi_listhead), i = 0; inp && i < n;
	    inp = LIST_NEXT(inp, inp_list)) {
		if (inp->inp_gencnt <= gencnt &&
		    inp->inp_state != INPCB_STATE_DEAD) {
			inp_list[i++] = inp;
		}
	}
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		struct xinpcb64 xi;

		inp = inp_list[i];

		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING) {
			continue;
		}
		udp_lock(inp->inp_socket, 1, 0);
		if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
			udp_unlock(inp->inp_socket, 1, 0);
			continue;
		}
		if (inp->inp_gencnt > gencnt) {
			udp_unlock(inp->inp_socket, 1, 0);
			continue;
		}

		bzero(&xi, sizeof(xi));
		xi.xi_len = sizeof(xi);
		inpcb_to_xinpcb64(inp, &xi);
		if (inp->inp_socket) {
			sotoxsocket64(inp->inp_socket, &xi.xi_socket);
		}

		udp_unlock(inp->inp_socket, 1, 0);

		error = SYSCTL_OUT(req, &xi, sizeof(xi));
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		bzero(&xig, sizeof(xig));
		xig.xig_len = sizeof(xig);
		xig.xig_gen = udbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = udbinfo.ipi_count;
		error = SYSCTL_OUT(req, &xig, sizeof(xig));
	}
	FREE(inp_list, M_TEMP);
	lck_rw_done(udbinfo.ipi_lock);
	return error;
}

SYSCTL_PROC(_net_inet_udp, OID_AUTO, pcblist64,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, udp_pcblist64,
    "S,xinpcb64", "List of active UDP sockets");

#endif /* !CONFIG_EMBEDDED */

static int
udp_pcblist_n SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	return get_pcblist_n(IPPROTO_UDP, req, &udbinfo);
}

SYSCTL_PROC(_net_inet_udp, OID_AUTO, pcblist_n,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0, udp_pcblist_n,
    "S,xinpcb_n", "List of active UDP sockets");

__private_extern__ void
udp_get_ports_used(uint32_t ifindex, int protocol, uint32_t flags,
    bitstr_t *bitfield)
{
	inpcb_get_ports_used(ifindex, protocol, flags, bitfield,
	    &udbinfo);
}

__private_extern__ uint32_t
udp_count_opportunistic(unsigned int ifindex, u_int32_t flags)
{
	return inpcb_count_opportunistic(ifindex, &udbinfo, flags);
}

__private_extern__ uint32_t
udp_find_anypcb_byaddr(struct ifaddr *ifa)
{
	return inpcb_find_anypcb_byaddr(ifa, &udbinfo);
}

static int
udp_check_pktinfo(struct mbuf *control, struct ifnet **outif,
    struct in_addr *laddr)
{
	struct cmsghdr *cm = 0;
	struct in_pktinfo *pktinfo;
	struct ifnet *ifp;

	if (outif != NULL) {
		*outif = NULL;
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
		if (cm->cmsg_level != IPPROTO_IP ||
		    cm->cmsg_type != IP_PKTINFO) {
			continue;
		}

		if (cm->cmsg_len != CMSG_LEN(sizeof(struct in_pktinfo))) {
			return EINVAL;
		}

		pktinfo =  (struct in_pktinfo *)(void *)CMSG_DATA(cm);

		/* Check for a valid ifindex in pktinfo */
		ifnet_head_lock_shared();

		if (pktinfo->ipi_ifindex > if_index) {
			ifnet_head_done();
			return ENXIO;
		}

		/*
		 * If ipi_ifindex is specified it takes precedence
		 * over ipi_spec_dst.
		 */
		if (pktinfo->ipi_ifindex) {
			ifp = ifindex2ifnet[pktinfo->ipi_ifindex];
			if (ifp == NULL) {
				ifnet_head_done();
				return ENXIO;
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
	return 0;
}

int
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
	struct ip_out_args ipoa;
#if CONTENT_FILTER
	struct m_tag *cfil_tag = NULL;
	bool cfil_faddr_use = false;
	uint32_t cfil_so_state_change_cnt = 0;
	short cfil_so_options = 0;
	struct sockaddr *cfil_faddr = NULL;
#endif

	bzero(&ipoa, sizeof(ipoa));
	ipoa.ipoa_boundif = IFSCOPE_NONE;
	ipoa.ipoa_flags = IPOAF_SELECT_SRCIF;

	struct ifnet *outif = NULL;
	struct flowadv *adv = &ipoa.ipoa_flowadv;
	int sotc = SO_TC_UNSPEC;
	int netsvctype = _NET_SERVICE_TYPE_UNSPEC;
	struct ifnet *origoutifp = NULL;
	int flowadv = 0;

	/* Enable flow advisory only when connected */
	flowadv = (so->so_state & SS_ISCONNECTED) ? 1 : 0;
	pi_laddr.s_addr = INADDR_ANY;

	KERNEL_DEBUG(DBG_FNC_UDP_OUTPUT | DBG_FUNC_START, 0, 0, 0, 0, 0);

	socket_lock_assert_owned(so);

#if CONTENT_FILTER
	/*
	 * If socket is subject to UDP Content Filter and no addr is passed in,
	 * retrieve CFIL saved state from mbuf and use it if necessary.
	 */
	if (so->so_cfil_db && !addr) {
		cfil_tag = cfil_udp_get_socket_state(m, &cfil_so_state_change_cnt, &cfil_so_options, &cfil_faddr);
		if (cfil_tag) {
			sin = (struct sockaddr_in *)(void *)cfil_faddr;
			if (inp && inp->inp_faddr.s_addr == INADDR_ANY) {
				/*
				 * Socket is unconnected, simply use the saved faddr as 'addr' to go through
				 * the connect/disconnect logic.
				 */
				addr = (struct sockaddr *)cfil_faddr;
			} else if ((so->so_state_change_cnt != cfil_so_state_change_cnt) &&
			    (inp->inp_fport != sin->sin_port ||
			    inp->inp_faddr.s_addr != sin->sin_addr.s_addr)) {
				/*
				 * Socket is connected but socket state and dest addr/port changed.
				 * We need to use the saved faddr info.
				 */
				cfil_faddr_use = true;
			}
		}
	}
#endif

	if (control != NULL) {
		sotc = so_tc_from_control(control, &netsvctype);
		VERIFY(outif == NULL);
		error = udp_check_pktinfo(control, &outif, &pi_laddr);
		m_freem(control);
		control = NULL;
		if (error) {
			goto release;
		}
		pktinfo++;
		if (outif != NULL) {
			ipoa.ipoa_boundif = outif->if_index;
		}
	}
	if (sotc == SO_TC_UNSPEC) {
		sotc = so->so_traffic_class;
		netsvctype = so->so_netsvctype;
	}

	KERNEL_DEBUG(DBG_LAYER_OUT_BEG, inp->inp_fport, inp->inp_lport,
	    inp->inp_laddr.s_addr, inp->inp_faddr.s_addr,
	    (htons((u_short)len + sizeof(struct udphdr))));

	if (len + sizeof(struct udpiphdr) > IP_MAXPACKET) {
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
		ifnet_reference(inp->inp_boundifp);     /* for this routine */
		if (outif != NULL) {
			ifnet_release(outif);
		}
		outif = inp->inp_boundifp;
		ipoa.ipoa_boundif = outif->if_index;
	}
	if (INP_NO_CELLULAR(inp)) {
		ipoa.ipoa_flags |=  IPOAF_NO_CELLULAR;
	}
	if (INP_NO_EXPENSIVE(inp)) {
		ipoa.ipoa_flags |=  IPOAF_NO_EXPENSIVE;
	}
	if (INP_AWDL_UNRESTRICTED(inp)) {
		ipoa.ipoa_flags |=  IPOAF_AWDL_UNRESTRICTED;
	}
	ipoa.ipoa_sotc = sotc;
	ipoa.ipoa_netsvctype = netsvctype;
	soopts |= IP_OUTARGS;

	/*
	 * If there was a routing change, discard cached route and check
	 * that we have a valid source address.  Reacquire a new source
	 * address if INADDR_ANY was specified.
	 *
	 * If we are using cfil saved state, go through this cache cleanup
	 * so that we can get a new route.
	 */
	if (ROUTE_UNUSABLE(&inp->inp_route)
#if CONTENT_FILTER
	    || cfil_faddr_use
#endif
	    ) {
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
		if (ia != NULL) {
			IFA_REMREF(&ia->ia_ifa);
		}
	}

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
		/* remember we don't care about src addr */
		inp->inp_flags |= INP_INADDR_ANY;
	} else {
		origladdr = laddr = inp->inp_laddr;
	}

	origoutifp = inp->inp_last_outifp;
	faddr = inp->inp_faddr;
	lport = inp->inp_lport;
	fport = inp->inp_fport;

#if CONTENT_FILTER
	if (cfil_faddr_use) {
		faddr = ((struct sockaddr_in *)(void *)cfil_faddr)->sin_addr;
		fport = ((struct sockaddr_in *)(void *)cfil_faddr)->sin_port;
	}
#endif

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
			if (pi_laddr.s_addr != INADDR_ANY) {
				inp->inp_laddr = pi_laddr;
			}
			/*
			 * If a scope is specified, use it.  Scope from
			 * IP_PKTINFO takes precendence over the the scope
			 * set via INP_BOUND_IF.
			 */
			error = in_pcbconnect(inp, addr, p, ipoa.ipoa_boundif,
			    &outif);
			if (error) {
				goto release;
			}

			laddr = inp->inp_laddr;
			lport = inp->inp_lport;
			faddr = inp->inp_faddr;
			fport = inp->inp_fport;
			udp_dodisconnect = 1;

			/* synch up in case in_pcbladdr() overrides */
			if (outif != NULL && ipoa.ipoa_boundif != IFSCOPE_NONE) {
				ipoa.ipoa_boundif = outif->if_index;
			}
		} else {
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
				    ipoa.ipoa_boundif, &outif, 0)) != 0) {
					goto release;
				}
				/*
				 * from pcbconnect: remember we don't
				 * care about src addr.
				 */
				inp->inp_flags |= INP_INADDR_ANY;

				/* synch up in case in_pcbladdr() overrides */
				if (outif != NULL &&
				    ipoa.ipoa_boundif != IFSCOPE_NONE) {
					ipoa.ipoa_boundif = outif->if_index;
				}
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

	if (inp->inp_flowhash == 0) {
		inp->inp_flowhash = inp_calc_flowhash(inp);
	}

	if (fport == htons(53) && !(so->so_flags1 & SOF1_DNS_COUNTED)) {
		so->so_flags1 |= SOF1_DNS_COUNTED;
		INC_ATOMIC_INT64_LIM(net_api_stats.nas_socket_inet_dgram_dns);
	}

	/*
	 * Calculate data length and get a mbuf
	 * for UDP and IP headers.
	 */
	M_PREPEND(m, sizeof(struct udpiphdr), M_DONTWAIT, 1);
	if (m == 0) {
		error = ENOBUFS;
		goto abort;
	}

	/*
	 * Fill in mbuf with extended UDP header
	 * and addresses and length put into network format.
	 */
	ui = mtod(m, struct udpiphdr *);
	bzero(ui->ui_x1, sizeof(ui->ui_x1));    /* XXX still needed? */
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_src = laddr;
	ui->ui_dst = faddr;
	ui->ui_sport = lport;
	ui->ui_dport = fport;
	ui->ui_ulen = htons((u_short)len + sizeof(struct udphdr));

	/*
	 * Set up checksum to pseudo header checksum and output datagram.
	 *
	 * Treat flows to be CLAT46'd as IPv6 flow and compute checksum
	 * no matter what, as IPv6 mandates checksum for UDP.
	 *
	 * Here we only compute the one's complement sum of the pseudo header.
	 * The payload computation and final complement is delayed to much later
	 * in IP processing to decide if remaining computation needs to be done
	 * through offload.
	 *
	 * That is communicated by setting CSUM_UDP in csum_flags.
	 * The offset of checksum from the start of ULP header is communicated
	 * through csum_data.
	 *
	 * Note since this already contains the pseudo checksum header, any
	 * later operation at IP layer that modify the values used here must
	 * update the checksum as well (for example NAT etc).
	 */
	if ((inp->inp_flags2 & INP2_CLAT46_FLOW) ||
	    (udpcksum && !(inp->inp_flags & INP_UDP_NOCKSUM))) {
		ui->ui_sum = in_pseudo(ui->ui_src.s_addr, ui->ui_dst.s_addr,
		    htons((u_short)len + sizeof(struct udphdr) + IPPROTO_UDP));
		m->m_pkthdr.csum_flags = (CSUM_UDP | CSUM_ZERO_INVERT);
		m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
	} else {
		ui->ui_sum = 0;
	}
	((struct ip *)ui)->ip_len = sizeof(struct udpiphdr) + len;
	((struct ip *)ui)->ip_ttl = inp->inp_ip_ttl;    /* XXX */
	((struct ip *)ui)->ip_tos = inp->inp_ip_tos;    /* XXX */
	udpstat.udps_opackets++;

	KERNEL_DEBUG(DBG_LAYER_OUT_END, ui->ui_dport, ui->ui_sport,
	    ui->ui_src.s_addr, ui->ui_dst.s_addr, ui->ui_ulen);

#if NECP
	{
		necp_kernel_policy_id policy_id;
		necp_kernel_policy_id skip_policy_id;
		u_int32_t route_rule_id;

		/*
		 * We need a route to perform NECP route rule checks
		 */
		if (net_qos_policy_restricted != 0 &&
		    ROUTE_UNUSABLE(&inp->inp_route)) {
			struct sockaddr_in to;
			struct sockaddr_in from;

			ROUTE_RELEASE(&inp->inp_route);

			bzero(&from, sizeof(struct sockaddr_in));
			from.sin_family = AF_INET;
			from.sin_len = sizeof(struct sockaddr_in);
			from.sin_addr = laddr;

			bzero(&to, sizeof(struct sockaddr_in));
			to.sin_family = AF_INET;
			to.sin_len = sizeof(struct sockaddr_in);
			to.sin_addr = faddr;

			inp->inp_route.ro_dst.sa_family = AF_INET;
			inp->inp_route.ro_dst.sa_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *)(void *)&inp->inp_route.ro_dst)->sin_addr =
			    faddr;

			rtalloc_scoped(&inp->inp_route, ipoa.ipoa_boundif);

			inp_update_necp_policy(inp, (struct sockaddr *)&from,
			    (struct sockaddr *)&to, ipoa.ipoa_boundif);
			inp->inp_policyresult.results.qos_marking_gencount = 0;
		}

		if (!necp_socket_is_allowed_to_send_recv_v4(inp, lport, fport,
		    &laddr, &faddr, NULL, &policy_id, &route_rule_id, &skip_policy_id)) {
			error = EHOSTUNREACH;
			goto abort;
		}

		necp_mark_packet_from_socket(m, inp, policy_id, route_rule_id, skip_policy_id);

		if (net_qos_policy_restricted != 0) {
			necp_socket_update_qos_marking(inp,
			    inp->inp_route.ro_rt, NULL, route_rule_id);
		}
	}
#endif /* NECP */
	if ((so->so_flags1 & SOF1_QOSMARKING_ALLOWED)) {
		ipoa.ipoa_flags |= IPOAF_QOSMARKING_ALLOWED;
	}

#if IPSEC
	if (inp->inp_sp != NULL && ipsec_setsocket(m, inp->inp_socket) != 0) {
		error = ENOBUFS;
		goto abort;
	}
#endif /* IPSEC */

	inpopts = inp->inp_options;
#if CONTENT_FILTER
	if (cfil_tag && (inp->inp_socket->so_options != cfil_so_options)) {
		soopts |= (cfil_so_options & (SO_DONTROUTE | SO_BROADCAST));
	} else
#endif
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

	set_packet_service_class(m, so, sotc, 0);
	m->m_pkthdr.pkt_flowsrc = FLOWSRC_INPCB;
	m->m_pkthdr.pkt_flowid = inp->inp_flowhash;
	m->m_pkthdr.pkt_proto = IPPROTO_UDP;
	m->m_pkthdr.pkt_flags |= (PKTF_FLOW_ID | PKTF_FLOW_LOCALSRC);
	if (flowadv) {
		m->m_pkthdr.pkt_flags |= PKTF_FLOW_ADV;
	}
	m->m_pkthdr.tx_udp_pid = so->last_pid;
	if (so->so_flags & SOF_DELEGATED) {
		m->m_pkthdr.tx_udp_e_pid = so->e_pid;
	} else {
		m->m_pkthdr.tx_udp_e_pid = 0;
	}

	if (ipoa.ipoa_boundif != IFSCOPE_NONE) {
		ipoa.ipoa_flags |= IPOAF_BOUND_IF;
	}

	if (laddr.s_addr != INADDR_ANY) {
		ipoa.ipoa_flags |= IPOAF_BOUND_SRCADDR;
	}

	inp->inp_sndinprog_cnt++;

	socket_unlock(so, 0);
	error = ip_output(m, inpopts, &ro, soopts, mopts, &ipoa);
	m = NULL;
	socket_lock(so, 0);
	if (mopts != NULL) {
		IMO_REMREF(mopts);
	}

	if (error == 0 && nstat_collect) {
		boolean_t cell, wifi, wired;

		if (ro.ro_rt != NULL) {
			cell = IFNET_IS_CELLULAR(ro.ro_rt->rt_ifp);
			wifi = (!cell && IFNET_IS_WIFI(ro.ro_rt->rt_ifp));
			wired = (!wifi && IFNET_IS_WIRED(ro.ro_rt->rt_ifp));
		} else {
			cell = wifi = wired = FALSE;
		}
		INP_ADD_STAT(inp, cell, wifi, wired, txpackets, 1);
		INP_ADD_STAT(inp, cell, wifi, wired, txbytes, len);
		inp_set_activity_bitmap(inp);
	}

	if (flowadv && (adv->code == FADV_FLOW_CONTROLLED ||
	    adv->code == FADV_SUSPENDED)) {
		/*
		 * return a hint to the application that
		 * the packet has been dropped
		 */
		error = ENOBUFS;
		inp_set_fc_state(inp, adv->code);
	}

	VERIFY(inp->inp_sndinprog_cnt > 0);
	if (--inp->inp_sndinprog_cnt == 0) {
		inp->inp_flags &= ~(INP_FC_FEEDBACK);
	}

	/* Synchronize PCB cached route */
	inp_route_copyin(inp, &ro);

abort:
	if (udp_dodisconnect) {
		/* Always discard the cached route for unconnected socket */
		ROUTE_RELEASE(&inp->inp_route);
		in_pcbdisconnect(inp);
		inp->inp_laddr = origladdr;     /* XXX rehash? */
		/* no reference needed */
		inp->inp_last_outifp = origoutifp;
	} else if (inp->inp_route.ro_rt != NULL) {
		struct rtentry *rt = inp->inp_route.ro_rt;
		struct ifnet *outifp;

		if (rt->rt_flags & (RTF_MULTICAST | RTF_BROADCAST)) {
			rt = NULL;      /* unusable */
		}
#if CONTENT_FILTER
		/*
		 * Discard temporary route for cfil case
		 */
		if (cfil_faddr_use) {
			rt = NULL;      /* unusable */
		}
#endif

		/*
		 * Always discard if it is a multicast or broadcast route.
		 */
		if (rt == NULL) {
			ROUTE_RELEASE(&inp->inp_route);
		}

		/*
		 * If the destination route is unicast, update outifp with
		 * that of the route interface used by IP.
		 */
		if (rt != NULL &&
		    (outifp = rt->rt_ifp) != inp->inp_last_outifp) {
			inp->inp_last_outifp = outifp; /* no reference needed */

			so->so_pktheadroom = P2ROUNDUP(
				sizeof(struct udphdr) +
				sizeof(struct ip) +
				ifnet_hdrlen(outifp) +
				ifnet_mbuf_packetpreamblelen(outifp),
				sizeof(u_int32_t));
		}
	} else {
		ROUTE_RELEASE(&inp->inp_route);
	}

	/*
	 * If output interface was cellular/expensive, and this socket is
	 * denied access to it, generate an event.
	 */
	if (error != 0 && (ipoa.ipoa_retflags & IPOARF_IFDENIED) &&
	    (INP_NO_CELLULAR(inp) || INP_NO_EXPENSIVE(inp))) {
		soevent(so, (SO_FILT_HINT_LOCKED | SO_FILT_HINT_IFDENIED));
	}

release:
	KERNEL_DEBUG(DBG_FNC_UDP_OUTPUT | DBG_FUNC_END, error, 0, 0, 0, 0);

	if (m != NULL) {
		m_freem(m);
	}

	if (outif != NULL) {
		ifnet_release(outif);
	}

#if CONTENT_FILTER
	if (cfil_tag) {
		m_tag_free(cfil_tag);
	}
#endif

	return error;
}

u_int32_t       udp_sendspace = 9216;           /* really max datagram size */
/* 187 1K datagrams (approx 192 KB) */
u_int32_t       udp_recvspace = 187 * (1024 +
#if INET6
    sizeof(struct sockaddr_in6)
#else /* !INET6 */
    sizeof(struct sockaddr_in)
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
	u_quad_t sb_effective_max = (sb_max / (MSIZE + MCLBYTES)) * MCLBYTES;

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
	error = sysctl_io_number(req, *space_p, sizeof(u_int32_t),
	    &new_value, &changed);
	if (changed) {
		if (new_value > 0 && new_value <= sb_effective_max) {
			*space_p = new_value;
		} else {
			error = ERANGE;
		}
	}
	return error;
}

SYSCTL_PROC(_net_inet_udp, UDPCTL_RECVSPACE, recvspace,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &udp_recvspace, 0,
    &sysctl_udp_sospace, "IU", "Maximum incoming UDP datagram size");

SYSCTL_PROC(_net_inet_udp, UDPCTL_MAXDGRAM, maxdgram,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &udp_sendspace, 0,
    &sysctl_udp_sospace, "IU", "Maximum outgoing UDP datagram size");

int
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
	return 0;
}

int
udp_attach(struct socket *so, int proto, struct proc *p)
{
#pragma unused(proto)
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	if (inp != NULL) {
		panic("%s so=%p inp=%p\n", __func__, so, inp);
		/* NOTREACHED */
	}
	error = in_pcballoc(so, &udbinfo, p);
	if (error != 0) {
		return error;
	}
	error = soreserve(so, udp_sendspace, udp_recvspace);
	if (error != 0) {
		return error;
	}
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_ttl = ip_defttl;
	if (nstat_collect) {
		nstat_udp_new_pcb(inp);
	}
	return 0;
}

int
udp_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int error;

	if (nam->sa_family != 0 && nam->sa_family != AF_INET &&
	    nam->sa_family != AF_INET6) {
		return EAFNOSUPPORT;
	}

	inp = sotoinpcb(so);
	if (inp == NULL) {
		return EINVAL;
	}
	error = in_pcbbind(inp, nam, p);

#if NECP
	/* Update NECP client with bind result if not in middle of connect */
	if (error == 0 &&
	    (inp->inp_flags2 & INP2_CONNECT_IN_PROGRESS) &&
	    !uuid_is_null(inp->necp_client_uuid)) {
		socket_unlock(so, 0);
		necp_client_assign_from_socket(so->last_pid, inp->necp_client_uuid, inp);
		socket_lock(so, 0);
	}
#endif /* NECP */

	return error;
}

int
udp_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		return EINVAL;
	}
	if (inp->inp_faddr.s_addr != INADDR_ANY) {
		return EISCONN;
	}

	if (!(so->so_flags1 & SOF1_CONNECT_COUNTED)) {
		so->so_flags1 |= SOF1_CONNECT_COUNTED;
		INC_ATOMIC_INT64_LIM(net_api_stats.nas_socket_inet_dgram_connected);
	}

#if NECP
#if FLOW_DIVERT
	if (necp_socket_should_use_flow_divert(inp)) {
		uint32_t fd_ctl_unit =
		    necp_socket_get_flow_divert_control_unit(inp);
		if (fd_ctl_unit > 0) {
			error = flow_divert_pcb_init(so, fd_ctl_unit);
			if (error == 0) {
				error = flow_divert_connect_out(so, nam, p);
			}
		} else {
			error = ENETDOWN;
		}
		return error;
	}
#endif /* FLOW_DIVERT */
#endif /* NECP */

	error = in_pcbconnect(inp, nam, p, IFSCOPE_NONE, NULL);
	if (error == 0) {
#if NECP
		/* Update NECP client with connected five-tuple */
		if (!uuid_is_null(inp->necp_client_uuid)) {
			socket_unlock(so, 0);
			necp_client_assign_from_socket(so->last_pid, inp->necp_client_uuid, inp);
			socket_lock(so, 0);
		}
#endif /* NECP */

		soisconnected(so);
		if (inp->inp_flowhash == 0) {
			inp->inp_flowhash = inp_calc_flowhash(inp);
		}
	}
	return error;
}

int
udp_connectx_common(struct socket *so, int af, struct sockaddr *src, struct sockaddr *dst,
    struct proc *p, uint32_t ifscope, sae_associd_t aid, sae_connid_t *pcid,
    uint32_t flags, void *arg, uint32_t arglen,
    struct uio *uio, user_ssize_t *bytes_written)
{
#pragma unused(aid, flags, arg, arglen)
	struct inpcb *inp = sotoinpcb(so);
	int error = 0;
	user_ssize_t datalen = 0;

	if (inp == NULL) {
		return EINVAL;
	}

	VERIFY(dst != NULL);

	ASSERT(!(inp->inp_flags2 & INP2_CONNECT_IN_PROGRESS));
	inp->inp_flags2 |= INP2_CONNECT_IN_PROGRESS;

#if NECP
	inp_update_necp_policy(inp, src, dst, ifscope);
#endif /* NECP */

	/* bind socket to the specified interface, if requested */
	if (ifscope != IFSCOPE_NONE &&
	    (error = inp_bindif(inp, ifscope, NULL)) != 0) {
		goto done;
	}

	/* if source address and/or port is specified, bind to it */
	if (src != NULL) {
		error = sobindlock(so, src, 0); /* already locked */
		if (error != 0) {
			goto done;
		}
	}

	switch (af) {
	case AF_INET:
		error = udp_connect(so, dst, p);
		break;
#if INET6
	case AF_INET6:
		error = udp6_connect(so, dst, p);
		break;
#endif /* INET6 */
	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	if (error != 0) {
		goto done;
	}

	/*
	 * If there is data, copy it. DATA_IDEMPOTENT is ignored.
	 * CONNECT_RESUME_ON_READ_WRITE is ignored.
	 */
	if (uio != NULL) {
		socket_unlock(so, 0);

		VERIFY(bytes_written != NULL);

		datalen = uio_resid(uio);
		error = so->so_proto->pr_usrreqs->pru_sosend(so, NULL,
		    (uio_t)uio, NULL, NULL, 0);
		socket_lock(so, 0);

		/* If error returned is EMSGSIZE, for example, disconnect */
		if (error == 0 || error == EWOULDBLOCK) {
			*bytes_written = datalen - uio_resid(uio);
		} else {
			(void) so->so_proto->pr_usrreqs->pru_disconnectx(so,
			    SAE_ASSOCID_ANY, SAE_CONNID_ANY);
		}
		/*
		 * mask the EWOULDBLOCK error so that the caller
		 * knows that atleast the connect was successful.
		 */
		if (error == EWOULDBLOCK) {
			error = 0;
		}
	}

	if (error == 0 && pcid != NULL) {
		*pcid = 1;      /* there is only 1 connection for UDP */
	}
done:
	inp->inp_flags2 &= ~INP2_CONNECT_IN_PROGRESS;
	return error;
}

int
udp_connectx(struct socket *so, struct sockaddr *src,
    struct sockaddr *dst, struct proc *p, uint32_t ifscope,
    sae_associd_t aid, sae_connid_t *pcid, uint32_t flags, void *arg,
    uint32_t arglen, struct uio *uio, user_ssize_t *bytes_written)
{
	return udp_connectx_common(so, AF_INET, src, dst,
	           p, ifscope, aid, pcid, flags, arg, arglen, uio, bytes_written);
}

int
udp_detach(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		panic("%s: so=%p null inp\n", __func__, so);
		/* NOTREACHED */
	}

	/*
	 * If this is a socket that does not want to wakeup the device
	 * for it's traffic, the application might be waiting for
	 * close to complete before going to sleep. Send a notification
	 * for this kind of sockets
	 */
	if (so->so_options & SO_NOWAKEFROMSLEEP) {
		socket_post_kev_msg_closed(so);
	}

	in_pcbdetach(inp);
	inp->inp_state = INPCB_STATE_DEAD;
	return 0;
}

int
udp_disconnect(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL
#if NECP
	    || (necp_socket_should_use_flow_divert(inp))
#endif /* NECP */
	    ) {
		return inp == NULL ? EINVAL : EPROTOTYPE;
	}
	if (inp->inp_faddr.s_addr == INADDR_ANY) {
		return ENOTCONN;
	}

	in_pcbdisconnect(inp);

	/* reset flow controlled state, just in case */
	inp_reset_fc_state(inp);

	inp->inp_laddr.s_addr = INADDR_ANY;
	so->so_state &= ~SS_ISCONNECTED;                /* XXX */
	inp->inp_last_outifp = NULL;

	return 0;
}

int
udp_disconnectx(struct socket *so, sae_associd_t aid, sae_connid_t cid)
{
#pragma unused(cid)
	if (aid != SAE_ASSOCID_ANY && aid != SAE_ASSOCID_ALL) {
		return EINVAL;
	}

	return udp_disconnect(so);
}

int
udp_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *addr, struct mbuf *control, struct proc *p)
{
#ifndef FLOW_DIVERT
#pragma unused(flags)
#endif /* !(FLOW_DIVERT) */
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		if (m != NULL) {
			m_freem(m);
		}
		if (control != NULL) {
			m_freem(control);
		}
		return EINVAL;
	}

#if NECP
#if FLOW_DIVERT
	if (necp_socket_should_use_flow_divert(inp)) {
		/* Implicit connect */
		return flow_divert_implicit_data_out(so, flags, m, addr,
		           control, p);
	}
#endif /* FLOW_DIVERT */
#endif /* NECP */

	return udp_output(inp, m, addr, control, p);
}

int
udp_shutdown(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == NULL) {
		return EINVAL;
	}
	socantsendmore(so);
	return 0;
}

int
udp_lock(struct socket *so, int refcount, void *debug)
{
	void *lr_saved;

	if (debug == NULL) {
		lr_saved = __builtin_return_address(0);
	} else {
		lr_saved = debug;
	}

	if (so->so_pcb != NULL) {
		LCK_MTX_ASSERT(&((struct inpcb *)so->so_pcb)->inpcb_mtx,
		    LCK_MTX_ASSERT_NOTOWNED);
		lck_mtx_lock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
	} else {
		panic("%s: so=%p NO PCB! lr=%p lrh= %s\n", __func__,
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	}
	if (refcount) {
		so->so_usecount++;
	}

	so->lock_lr[so->next_lock_lr] = lr_saved;
	so->next_lock_lr = (so->next_lock_lr + 1) % SO_LCKDBG_MAX;
	return 0;
}

int
udp_unlock(struct socket *so, int refcount, void *debug)
{
	void *lr_saved;

	if (debug == NULL) {
		lr_saved = __builtin_return_address(0);
	} else {
		lr_saved = debug;
	}

	if (refcount) {
		VERIFY(so->so_usecount > 0);
		so->so_usecount--;
	}
	if (so->so_pcb == NULL) {
		panic("%s: so=%p NO PCB! lr=%p lrh= %s\n", __func__,
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	} else {
		LCK_MTX_ASSERT(&((struct inpcb *)so->so_pcb)->inpcb_mtx,
		    LCK_MTX_ASSERT_OWNED);
		so->unlock_lr[so->next_unlock_lr] = lr_saved;
		so->next_unlock_lr = (so->next_unlock_lr + 1) % SO_LCKDBG_MAX;
		lck_mtx_unlock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
	}
	return 0;
}

lck_mtx_t *
udp_getlock(struct socket *so, int flags)
{
#pragma unused(flags)
	struct inpcb *inp = sotoinpcb(so);

	if (so->so_pcb == NULL) {
		panic("%s: so=%p NULL so_pcb lrh= %s\n", __func__,
		    so, solockhistory_nr(so));
		/* NOTREACHED */
	}
	return &inp->inpcb_mtx;
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
		if (inp->inp_wantcnt != WNT_STOPUSING) {
			continue;
		}

		/*
		 * Skip if busy, no hurry for cleanup.  Keep gc active
		 * and try the lock again during next round.
		 */
		if (!socket_try_lock(inp->inp_socket)) {
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
				if (SOCK_CHECK_DOM(so, PF_INET6)) {
					in6_pcbdetach(inp);
				} else
#endif /* INET6 */
				in_pcbdetach(inp);
			}
			in_pcbdispose(inp);
		} else {
			socket_unlock(so, 0);
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
		}
	}
	lck_rw_done(ipi->ipi_lock);
}

static int
udp_getstat SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldlen = (size_t)sizeof(struct udpstat);
	}

	return SYSCTL_OUT(req, &udpstat, MIN(sizeof(udpstat), req->oldlen));
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
		return 0;
	}

	/* ip_stripoptions() must have been called before we get here */
	ASSERT((ip->ip_hl << 2) == sizeof(*ip));

	if ((hwcksum_rx || (ifp->if_flags & IFF_LOOPBACK) ||
	    (m->m_pkthdr.pkt_flags & PKTF_LOOP)) &&
	    (m->m_pkthdr.csum_flags & CSUM_DATA_VALID)) {
		if (m->m_pkthdr.csum_flags & CSUM_PSEUDO_HDR) {
			uh->uh_sum = m->m_pkthdr.csum_rx_val;
		} else {
			uint32_t sum = m->m_pkthdr.csum_rx_val;
			uint32_t start = m->m_pkthdr.csum_rx_start;
			int32_t trailer = (m_pktlen(m) - (off + ulen));

			/*
			 * Perform 1's complement adjustment of octets
			 * that got included/excluded in the hardware-
			 * calculated checksum value.  Ignore cases
			 * where the value already includes the entire
			 * IP header span, as the sum for those octets
			 * would already be 0 by the time we get here;
			 * IP has already performed its header checksum
			 * checks.  If we do need to adjust, restore
			 * the original fields in the IP header when
			 * computing the adjustment value.  Also take
			 * care of any trailing bytes and subtract out
			 * their partial sum.
			 */
			ASSERT(trailer >= 0);
			if ((m->m_pkthdr.csum_flags & CSUM_PARTIAL) &&
			    ((start != 0 && start != off) || trailer != 0)) {
				uint32_t swbytes = (uint32_t)trailer;

				if (start < off) {
					ip->ip_len += sizeof(*ip);
#if BYTE_ORDER != BIG_ENDIAN
					HTONS(ip->ip_len);
					HTONS(ip->ip_off);
#endif /* BYTE_ORDER != BIG_ENDIAN */
				}
				/* callee folds in sum */
				sum = m_adj_sum16(m, start, off, ulen, sum);
				if (off > start) {
					swbytes += (off - start);
				} else {
					swbytes += (start - off);
				}

				if (start < off) {
#if BYTE_ORDER != BIG_ENDIAN
					NTOHS(ip->ip_off);
					NTOHS(ip->ip_len);
#endif /* BYTE_ORDER != BIG_ENDIAN */
					ip->ip_len -= sizeof(*ip);
				}

				if (swbytes != 0) {
					udp_in_cksum_stats(swbytes);
				}
				if (trailer != 0) {
					m_adj(m, -trailer);
				}
			}

			/* callee folds in sum */
			uh->uh_sum = in_pseudo(ip->ip_src.s_addr,
			    ip->ip_dst.s_addr, sum + htonl(ulen + IPPROTO_UDP));
		}
		uh->uh_sum ^= 0xffff;
	} else {
		uint16_t ip_sum;
		char b[9];

		bcopy(ipov->ih_x1, b, sizeof(ipov->ih_x1));
		bzero(ipov->ih_x1, sizeof(ipov->ih_x1));
		ip_sum = ipov->ih_len;
		ipov->ih_len = uh->uh_ulen;
		uh->uh_sum = in_cksum(m, ulen + sizeof(struct ip));
		bcopy(b, ipov->ih_x1, sizeof(ipov->ih_x1));
		ipov->ih_len = ip_sum;

		udp_in_cksum_stats(ulen);
	}

	if (uh->uh_sum != 0) {
		udpstat.udps_badsum++;
		IF_UDP_STATINC(ifp, badchksum);
		return -1;
	}

	return 0;
}

void
udp_fill_keepalive_offload_frames(ifnet_t ifp,
    struct ifnet_keepalive_offload_frame *frames_array,
    u_int32_t frames_array_count, size_t frame_data_offset,
    u_int32_t *used_frames_count)
{
	struct inpcb *inp;
	inp_gen_t gencnt;
	u_int32_t frame_index = *used_frames_count;

	if (ifp == NULL || frames_array == NULL ||
	    frames_array_count == 0 ||
	    frame_index >= frames_array_count ||
	    frame_data_offset >= IFNET_KEEPALIVE_OFFLOAD_FRAME_DATA_SIZE) {
		return;
	}

	lck_rw_lock_shared(udbinfo.ipi_lock);
	gencnt = udbinfo.ipi_gencnt;
	LIST_FOREACH(inp, udbinfo.ipi_listhead, inp_list) {
		struct socket *so;
		u_int8_t *data;
		struct ifnet_keepalive_offload_frame *frame;
		struct mbuf *m = NULL;

		if (frame_index >= frames_array_count) {
			break;
		}

		if (inp->inp_gencnt > gencnt ||
		    inp->inp_state == INPCB_STATE_DEAD) {
			continue;
		}

		if ((so = inp->inp_socket) == NULL ||
		    (so->so_state & SS_DEFUNCT)) {
			continue;
		}
		/*
		 * check for keepalive offload flag without socket
		 * lock to avoid a deadlock
		 */
		if (!(inp->inp_flags2 & INP2_KEEPALIVE_OFFLOAD)) {
			continue;
		}

		udp_lock(so, 1, 0);
		if (!(inp->inp_vflag & (INP_IPV4 | INP_IPV6))) {
			udp_unlock(so, 1, 0);
			continue;
		}
		if ((inp->inp_vflag & INP_IPV4) &&
		    (inp->inp_laddr.s_addr == INADDR_ANY ||
		    inp->inp_faddr.s_addr == INADDR_ANY)) {
			udp_unlock(so, 1, 0);
			continue;
		}
		if ((inp->inp_vflag & INP_IPV6) &&
		    (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr) ||
		    IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr))) {
			udp_unlock(so, 1, 0);
			continue;
		}
		if (inp->inp_lport == 0 || inp->inp_fport == 0) {
			udp_unlock(so, 1, 0);
			continue;
		}
		if (inp->inp_last_outifp == NULL ||
		    inp->inp_last_outifp->if_index != ifp->if_index) {
			udp_unlock(so, 1, 0);
			continue;
		}
		if ((inp->inp_vflag & INP_IPV4)) {
			if ((frame_data_offset + sizeof(struct udpiphdr) +
			    inp->inp_keepalive_datalen) >
			    IFNET_KEEPALIVE_OFFLOAD_FRAME_DATA_SIZE) {
				udp_unlock(so, 1, 0);
				continue;
			}
			if ((sizeof(struct udpiphdr) +
			    inp->inp_keepalive_datalen) > _MHLEN) {
				udp_unlock(so, 1, 0);
				continue;
			}
		} else {
			if ((frame_data_offset + sizeof(struct ip6_hdr) +
			    sizeof(struct udphdr) +
			    inp->inp_keepalive_datalen) >
			    IFNET_KEEPALIVE_OFFLOAD_FRAME_DATA_SIZE) {
				udp_unlock(so, 1, 0);
				continue;
			}
			if ((sizeof(struct ip6_hdr) + sizeof(struct udphdr) +
			    inp->inp_keepalive_datalen) > _MHLEN) {
				udp_unlock(so, 1, 0);
				continue;
			}
		}
		MGETHDR(m, M_WAIT, MT_HEADER);
		if (m == NULL) {
			udp_unlock(so, 1, 0);
			continue;
		}
		/*
		 * This inp has all the information that is needed to
		 * generate an offload frame.
		 */
		if (inp->inp_vflag & INP_IPV4) {
			struct ip *ip;
			struct udphdr *udp;

			frame = &frames_array[frame_index];
			frame->length = frame_data_offset +
			    sizeof(struct udpiphdr) +
			    inp->inp_keepalive_datalen;
			frame->ether_type =
			    IFNET_KEEPALIVE_OFFLOAD_FRAME_ETHERTYPE_IPV4;
			frame->interval = inp->inp_keepalive_interval;
			switch (inp->inp_keepalive_type) {
			case UDP_KEEPALIVE_OFFLOAD_TYPE_AIRPLAY:
				frame->type =
				    IFNET_KEEPALIVE_OFFLOAD_FRAME_AIRPLAY;
				break;
			default:
				break;
			}
			data = mtod(m, u_int8_t *);
			bzero(data, sizeof(struct udpiphdr));
			ip = (__typeof__(ip))(void *)data;
			udp = (__typeof__(udp))(void *) (data +
			    sizeof(struct ip));
			m->m_len = sizeof(struct udpiphdr);
			data = data + sizeof(struct udpiphdr);
			if (inp->inp_keepalive_datalen > 0 &&
			    inp->inp_keepalive_data != NULL) {
				bcopy(inp->inp_keepalive_data, data,
				    inp->inp_keepalive_datalen);
				m->m_len += inp->inp_keepalive_datalen;
			}
			m->m_pkthdr.len = m->m_len;

			ip->ip_v = IPVERSION;
			ip->ip_hl = (sizeof(struct ip) >> 2);
			ip->ip_p = IPPROTO_UDP;
			ip->ip_len = htons(sizeof(struct udpiphdr) +
			    (u_short)inp->inp_keepalive_datalen);
			ip->ip_ttl = inp->inp_ip_ttl;
			ip->ip_tos |= (inp->inp_ip_tos & ~IPTOS_ECN_MASK);
			ip->ip_src = inp->inp_laddr;
			ip->ip_dst = inp->inp_faddr;
			ip->ip_sum = in_cksum_hdr_opt(ip);

			udp->uh_sport = inp->inp_lport;
			udp->uh_dport = inp->inp_fport;
			udp->uh_ulen = htons(sizeof(struct udphdr) +
			    (u_short)inp->inp_keepalive_datalen);

			if (!(inp->inp_flags & INP_UDP_NOCKSUM)) {
				udp->uh_sum = in_pseudo(ip->ip_src.s_addr,
				    ip->ip_dst.s_addr,
				    htons(sizeof(struct udphdr) +
				    (u_short)inp->inp_keepalive_datalen +
				    IPPROTO_UDP));
				m->m_pkthdr.csum_flags =
				    (CSUM_UDP | CSUM_ZERO_INVERT);
				m->m_pkthdr.csum_data = offsetof(struct udphdr,
				    uh_sum);
			}
			m->m_pkthdr.pkt_proto = IPPROTO_UDP;
			in_delayed_cksum(m);
			bcopy(m->m_data, frame->data + frame_data_offset,
			    m->m_len);
		} else {
			struct ip6_hdr *ip6;
			struct udphdr *udp6;

			VERIFY(inp->inp_vflag & INP_IPV6);
			frame = &frames_array[frame_index];
			frame->length = frame_data_offset +
			    sizeof(struct ip6_hdr) +
			    sizeof(struct udphdr) +
			    inp->inp_keepalive_datalen;
			frame->ether_type =
			    IFNET_KEEPALIVE_OFFLOAD_FRAME_ETHERTYPE_IPV6;
			frame->interval = inp->inp_keepalive_interval;
			switch (inp->inp_keepalive_type) {
			case UDP_KEEPALIVE_OFFLOAD_TYPE_AIRPLAY:
				frame->type =
				    IFNET_KEEPALIVE_OFFLOAD_FRAME_AIRPLAY;
				break;
			default:
				break;
			}
			data = mtod(m, u_int8_t *);
			bzero(data, sizeof(struct ip6_hdr) + sizeof(struct udphdr));
			ip6 = (__typeof__(ip6))(void *)data;
			udp6 = (__typeof__(udp6))(void *)(data +
			    sizeof(struct ip6_hdr));
			m->m_len = sizeof(struct ip6_hdr) +
			    sizeof(struct udphdr);
			data = data + (sizeof(struct ip6_hdr) +
			    sizeof(struct udphdr));
			if (inp->inp_keepalive_datalen > 0 &&
			    inp->inp_keepalive_data != NULL) {
				bcopy(inp->inp_keepalive_data, data,
				    inp->inp_keepalive_datalen);
				m->m_len += inp->inp_keepalive_datalen;
			}
			m->m_pkthdr.len = m->m_len;
			ip6->ip6_flow = inp->inp_flow & IPV6_FLOWINFO_MASK;
			ip6->ip6_flow = ip6->ip6_flow & ~IPV6_FLOW_ECN_MASK;
			ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
			ip6->ip6_vfc |= IPV6_VERSION;
			ip6->ip6_nxt = IPPROTO_UDP;
			ip6->ip6_hlim = ip6_defhlim;
			ip6->ip6_plen = htons(sizeof(struct udphdr) +
			    (u_short)inp->inp_keepalive_datalen);
			ip6->ip6_src = inp->in6p_laddr;
			if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src)) {
				ip6->ip6_src.s6_addr16[1] = 0;
			}

			ip6->ip6_dst = inp->in6p_faddr;
			if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst)) {
				ip6->ip6_dst.s6_addr16[1] = 0;
			}

			udp6->uh_sport = inp->in6p_lport;
			udp6->uh_dport = inp->in6p_fport;
			udp6->uh_ulen = htons(sizeof(struct udphdr) +
			    (u_short)inp->inp_keepalive_datalen);
			if (!(inp->inp_flags & INP_UDP_NOCKSUM)) {
				udp6->uh_sum = in6_pseudo(&ip6->ip6_src,
				    &ip6->ip6_dst,
				    htonl(sizeof(struct udphdr) +
				    (u_short)inp->inp_keepalive_datalen +
				    IPPROTO_UDP));
				m->m_pkthdr.csum_flags =
				    (CSUM_UDPIPV6 | CSUM_ZERO_INVERT);
				m->m_pkthdr.csum_data = offsetof(struct udphdr,
				    uh_sum);
			}
			m->m_pkthdr.pkt_proto = IPPROTO_UDP;
			in6_delayed_cksum(m);
			bcopy(m->m_data, frame->data + frame_data_offset,
			    m->m_len);
		}
		if (m != NULL) {
			m_freem(m);
			m = NULL;
		}
		frame_index++;
		udp_unlock(so, 1, 0);
	}
	lck_rw_done(udbinfo.ipi_lock);
	*used_frames_count = frame_index;
}
