/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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

#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#if INET6
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <sys/kdebug.h>

#if IPSEC
#include <netinet6/ipsec.h>
#include <netinet6/esp.h>
extern int ipsec_bypass;
#endif /*IPSEC*/


#define DBG_LAYER_IN_BEG	NETDBG_CODE(DBG_NETUDP, 0)
#define DBG_LAYER_IN_END	NETDBG_CODE(DBG_NETUDP, 2)
#define DBG_LAYER_OUT_BEG	NETDBG_CODE(DBG_NETUDP, 1)
#define DBG_LAYER_OUT_END	NETDBG_CODE(DBG_NETUDP, 3)
#define DBG_FNC_UDP_INPUT	NETDBG_CODE(DBG_NETUDP, (5 << 8))
#define DBG_FNC_UDP_OUTPUT	NETDBG_CODE(DBG_NETUDP, (6 << 8) | 1)

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */
#ifndef	COMPAT_42
static int	udpcksum = 1;
#else
static int	udpcksum = 0;		/* XXX */
#endif
SYSCTL_INT(_net_inet_udp, UDPCTL_CHECKSUM, checksum, CTLFLAG_RW,
		&udpcksum, 0, "");

static u_int32_t udps_in_sw_cksum;
SYSCTL_UINT(_net_inet_udp, OID_AUTO, in_sw_cksum, CTLFLAG_RD,
    &udps_in_sw_cksum, 0,
    "Number of received packets checksummed in software");

static u_int64_t udps_in_sw_cksum_bytes;
SYSCTL_QUAD(_net_inet_udp, OID_AUTO, in_sw_cksum_bytes, CTLFLAG_RD,
    &udps_in_sw_cksum_bytes,
    "Amount of received data checksummed in software");

static u_int32_t udps_out_sw_cksum;
SYSCTL_UINT(_net_inet_udp, OID_AUTO, out_sw_cksum, CTLFLAG_RD,
    &udps_out_sw_cksum, 0,
    "Number of transmitted packets checksummed in software");

static u_int64_t udps_out_sw_cksum_bytes;
SYSCTL_QUAD(_net_inet_udp, OID_AUTO, out_sw_cksum_bytes, CTLFLAG_RD,
    &udps_out_sw_cksum_bytes,
    "Amount of transmitted data checksummed in software");

int	log_in_vain = 0;
SYSCTL_INT(_net_inet_udp, OID_AUTO, log_in_vain, CTLFLAG_RW, 
    &log_in_vain, 0, "Log all incoming UDP packets");

static int	blackhole = 0;
SYSCTL_INT(_net_inet_udp, OID_AUTO, blackhole, CTLFLAG_RW,
	&blackhole, 0, "Do not send port unreachables for refused connects");

struct	inpcbhead udb;		/* from udp_var.h */
#define	udb6	udb  /* for KAME src sync over BSD*'s */
struct	inpcbinfo udbinfo;

#ifndef UDBHASHSIZE
#define UDBHASHSIZE 16
#endif

extern	int	esp_udp_encap_port;

extern  void    ipfwsyslog( int level, const char *format,...);
 
extern int fw_verbose;
static int udp_gc_done = FALSE; /* Garbage collection performed last slowtimo */

#if IPFIREWALL
#define log_in_vain_log( a ) {            \
        if ( (log_in_vain == 3 ) && (fw_verbose == 2)) {        /* Apple logging, log to ipfw.log */ \
                ipfwsyslog a ;  \
        }                       \
        else log a ;            \
}
#else
#define log_in_vain_log( a ) { log a; }
#endif

struct	udpstat udpstat;	/* from udp_var.h */
SYSCTL_STRUCT(_net_inet_udp, UDPCTL_STATS, stats, CTLFLAG_RD,
    &udpstat, udpstat, "UDP statistics (struct udpstat, netinet/udp_var.h)");
SYSCTL_INT(_net_inet_udp, OID_AUTO, pcbcount, CTLFLAG_RD, 
    &udbinfo.ipi_count, 0, "Number of active PCBs");

__private_extern__ int udp_use_randomport = 1;
SYSCTL_INT(_net_inet_udp, OID_AUTO, randomize_ports, CTLFLAG_RW,
    &udp_use_randomport, 0, "Randomize UDP port numbers");

#if INET6
struct udp_in6 {
	struct sockaddr_in6	uin6_sin;
	u_char			uin6_init_done : 1;
};
struct udp_ip6 {
	struct ip6_hdr		uip6_ip6;
	u_char			uip6_init_done : 1;
};
static void ip_2_ip6_hdr(struct ip6_hdr *ip6, struct ip *ip);
static void udp_append(struct inpcb *last, struct ip *ip,
    struct mbuf *n, int off, struct sockaddr_in *pudp_in,
    struct udp_in6 *pudp_in6, struct udp_ip6 *pudp_ip6);
#else
static void udp_append(struct inpcb *last, struct ip *ip,
    struct mbuf *n, int off, struct sockaddr_in *pudp_in);
#endif

static int udp_detach(struct socket *so);
static	int udp_output(struct inpcb *, struct mbuf *, struct sockaddr *,
			    struct mbuf *, struct proc *);
extern int ChkAddressOK( __uint32_t dstaddr, __uint32_t srcaddr );

void
udp_init()
{
    	vm_size_t			str_size;
    	struct inpcbinfo 	*pcbinfo;
	

	LIST_INIT(&udb);
	udbinfo.listhead = &udb;
	udbinfo.hashbase = hashinit(UDBHASHSIZE, M_PCB, &udbinfo.hashmask);
	udbinfo.porthashbase = hashinit(UDBHASHSIZE, M_PCB,
					&udbinfo.porthashmask);
#ifdef __APPLE__
	str_size = (vm_size_t) sizeof(struct inpcb);
	udbinfo.ipi_zone = (void *) zinit(str_size, 80000*str_size, 8192, "udpcb");

    	pcbinfo = &udbinfo;
	/*
	 * allocate lock group attribute and group for udp pcb mutexes
	 */
	pcbinfo->mtx_grp_attr = lck_grp_attr_alloc_init();

	pcbinfo->mtx_grp = lck_grp_alloc_init("udppcb", pcbinfo->mtx_grp_attr);
		
	pcbinfo->mtx_attr = lck_attr_alloc_init();

	if ((pcbinfo->mtx = lck_rw_alloc_init(pcbinfo->mtx_grp, pcbinfo->mtx_attr)) == NULL)
		return;	/* pretty much dead if this fails... */
#else
	udbinfo.ipi_zone = zinit("udpcb", sizeof(struct inpcb), maxsockets,
				 ZONE_INTERRUPT, 0);
#endif
}

void
udp_input(m, iphlen)
	register struct mbuf *m;
	int iphlen;
{
	register struct ip *ip;
	register struct udphdr *uh;
	register struct inpcb *inp;
	struct mbuf *opts = 0;
	int len;
	struct ip save_ip;
	struct sockaddr *append_sa;
	struct inpcbinfo *pcbinfo = &udbinfo;
	struct sockaddr_in udp_in = {
		sizeof (udp_in), AF_INET, 0, { 0 }, { 0, 0, 0, 0, 0, 0, 0, 0 }
	};
#if INET6
	struct udp_in6 udp_in6 = {
		{ sizeof (udp_in6.uin6_sin), AF_INET6, 0, 0,
		    IN6ADDR_ANY_INIT, 0 },
		0
	};
	struct udp_ip6 udp_ip6;
#endif /* INET6 */

	udpstat.udps_ipackets++;

	KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_START, 0,0,0,0,0);
	if (m->m_pkthdr.csum_flags & CSUM_TCP_SUM16)
		m->m_pkthdr.csum_flags = 0; /* invalidate hwcksum for UDP */

	/*
	 * Strip IP options, if any; should skip this,
	 * make available to user, and use on returned packets,
	 * but we don't yet have a way to check the checksum
	 * with options still present.
	 */
	if (iphlen > sizeof (struct ip)) {
		ip_stripoptions(m, (struct mbuf *)0);
		iphlen = sizeof(struct ip);
	}

	/*
	 * Get IP and UDP header together in first mbuf.
	 */
	ip = mtod(m, struct ip *);
	if (m->m_len < iphlen + sizeof(struct udphdr)) {
		if ((m = m_pullup(m, iphlen + sizeof(struct udphdr))) == 0) {
			udpstat.udps_hdrops++;
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
			return;
		}
		ip = mtod(m, struct ip *);
	}
	uh = (struct udphdr *)((caddr_t)ip + iphlen);

	/* destination port of 0 is illegal, based on RFC768. */
	if (uh->uh_dport == 0)
		goto bad;

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
	if (uh->uh_sum) {
		if (m->m_pkthdr.csum_flags & CSUM_DATA_VALID) {
			if (m->m_pkthdr.csum_flags & CSUM_PSEUDO_HDR)
				uh->uh_sum = m->m_pkthdr.csum_data;
			else
				goto doudpcksum;
			uh->uh_sum ^= 0xffff;
		} else {
			char b[9];
doudpcksum:
			*(uint32_t*)&b[0] = *(uint32_t*)&((struct ipovly *)ip)->ih_x1[0];
			*(uint32_t*)&b[4] = *(uint32_t*)&((struct ipovly *)ip)->ih_x1[4];
			*(uint8_t*)&b[8] = *(uint8_t*)&((struct ipovly *)ip)->ih_x1[8];
			
			bzero(((struct ipovly *)ip)->ih_x1, 9);
			((struct ipovly *)ip)->ih_len = uh->uh_ulen;
			uh->uh_sum = in_cksum(m, len + sizeof (struct ip));
			
			*(uint32_t*)&((struct ipovly *)ip)->ih_x1[0] = *(uint32_t*)&b[0];
			*(uint32_t*)&((struct ipovly *)ip)->ih_x1[4] = *(uint32_t*)&b[4];
			*(uint8_t*)&((struct ipovly *)ip)->ih_x1[8] = *(uint8_t*)&b[8];
			udp_in_cksum_stats(len);
		}
		if (uh->uh_sum) {
			udpstat.udps_badsum++;
			m_freem(m);
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
			return;
		}
	}
#ifndef __APPLE__
	 else
		udpstat.udps_nosum++;
#endif

	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)) ||
	    in_broadcast(ip->ip_dst, m->m_pkthdr.rcvif)) {

		int reuse_sock = 0, mcast_delivered = 0;

		lck_rw_lock_shared(pcbinfo->mtx);
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
#endif
		LIST_FOREACH(inp, &udb, inp_list) {
			if (inp->inp_socket == NULL) 
				continue;
			if (inp != sotoinpcb(inp->inp_socket))
				panic("udp_input: bad so back ptr inp=%p\n", inp);
#if INET6
                        if ((inp->inp_vflag & INP_IPV4) == 0)
                                continue;
#endif

			if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING) {
				continue;
			}
			
			udp_lock(inp->inp_socket, 1, 0);	

			if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
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

			reuse_sock = inp->inp_socket->so_options& (SO_REUSEPORT|SO_REUSEADDR);
			{
#if IPSEC
				int skipit = 0;
				/* check AH/ESP integrity. */
				if (ipsec_bypass == 0) {
					if (ipsec4_in_reject_so(m, inp->inp_socket)) {
						IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
						/* do not inject data to pcb */
						skipit = 1;
					}
				}
				if (skipit == 0) 
#endif /*IPSEC*/
				{
					struct mbuf *n = NULL;
					
					if (reuse_sock) 
						n = m_copy(m, 0, M_COPYALL);
#if INET6
					udp_append(inp, ip, m,
					    iphlen + sizeof(struct udphdr),
					    &udp_in, &udp_in6, &udp_ip6);
#else
					udp_append(inp, ip, m,
					    iphlen + sizeof(struct udphdr),
					    &udp_in);
#endif /* INET6 */
					mcast_delivered++;

					m = n;
				}
				udp_unlock(inp->inp_socket, 1, 0);
			}
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
			 * Recompute IP and UDP header pointers for new mbuf
			 */
			ip = mtod(m, struct ip *);
			uh = (struct udphdr *)((caddr_t)ip + iphlen);
		}
		lck_rw_done(pcbinfo->mtx);

		if (mcast_delivered == 0) {
			/*
			 * No matching pcb found; discard datagram.
			 * (No need to send an ICMP Port Unreachable
			 * for a broadcast or multicast datgram.)
			 */
			udpstat.udps_noportbcast++;
			goto bad;
		}

		if (m != NULL)	/* free the extra copy of mbuf or skipped by IPSec */
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
		int	payload_len = len - sizeof(struct udphdr) > 4 ? 4 : len - sizeof(struct udphdr);
		if (m->m_len < iphlen + sizeof(struct udphdr) + payload_len) {
			if ((m = m_pullup(m, iphlen + sizeof(struct udphdr) + payload_len)) == 0) {
				udpstat.udps_hdrops++;
				KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
				return;
			}
			ip = mtod(m, struct ip *);
			uh = (struct udphdr *)((caddr_t)ip + iphlen);
		}
		/* Check for NAT keepalive packet */
		if (payload_len == 1 && *(u_int8_t*)((caddr_t)uh + sizeof(struct udphdr)) == 0xFF) {
			m_freem(m);
			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
			return;
		}
		else if (payload_len == 4 && *(u_int32_t*)((caddr_t)uh + sizeof(struct udphdr)) != 0) {
			/* UDP encapsulated IPSec packet to pass through NAT */
			size_t stripsiz;

			stripsiz = sizeof(struct udphdr);

			ip = mtod(m, struct ip *);
			ovbcopy((caddr_t)ip, (caddr_t)(((u_char *)ip) + stripsiz), iphlen);
			m->m_data += stripsiz;
			m->m_len -= stripsiz;
			m->m_pkthdr.len -= stripsiz;
			ip = mtod(m, struct ip *);
			ip->ip_len = ip->ip_len - stripsiz;
			ip->ip_p = IPPROTO_ESP;

			KERNEL_DEBUG(DBG_FNC_UDP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
			esp4_input(m, iphlen);
			return;
		}
	}
#endif

	/*
	 * Locate pcb for datagram.
	 */
	inp = in_pcblookup_hash(&udbinfo, ip->ip_src, uh->uh_sport,
	    ip->ip_dst, uh->uh_dport, 1, m->m_pkthdr.rcvif);
	if (inp == NULL) {
		if (log_in_vain) {
			char buf[MAX_IPv4_STR_LEN];
			char buf2[MAX_IPv4_STR_LEN];

			/* check src and dst address */
			if (log_in_vain != 3)
				log(LOG_INFO,
					"Connection attempt to UDP %s:%d from %s:%d\n",
					inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf)),
					ntohs(uh->uh_dport),
					inet_ntop(AF_INET, &ip->ip_src, buf2, sizeof(buf2)),
					ntohs(uh->uh_sport));
			else if (!(m->m_flags & (M_BCAST | M_MCAST)) &&
					 ip->ip_dst.s_addr != ip->ip_src.s_addr)
				log_in_vain_log((LOG_INFO,
					"Stealth Mode connection attempt to UDP %s:%d from %s:%d\n",
					inet_ntop(AF_INET, &ip->ip_dst, buf, sizeof(buf)),
					ntohs(uh->uh_dport),
					inet_ntop(AF_INET, &ip->ip_src, buf2, sizeof(buf2)),
					ntohs(uh->uh_sport)))
		}
		udpstat.udps_noport++;
		if (m->m_flags & (M_BCAST | M_MCAST)) {
			udpstat.udps_noportbcast++;
			goto bad;
		}
#if ICMP_BANDLIM
		if (badport_bandlim(BANDLIM_ICMP_UNREACH) < 0)
			goto bad;
#endif
		if (blackhole)
			if (m->m_pkthdr.rcvif && m->m_pkthdr.rcvif->if_type != IFT_LOOP)
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
		goto bad;
	}
#if IPSEC
	if (ipsec_bypass == 0 && inp != NULL) {
		if (ipsec4_in_reject_so(m, inp->inp_socket)) {
			IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
			udp_unlock(inp->inp_socket, 1, 0);
			goto bad;
	        }
	}
#endif /*IPSEC*/

	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	udp_in.sin_port = uh->uh_sport;
	udp_in.sin_addr = ip->ip_src;
	if (inp->inp_flags & INP_CONTROLOPTS
	    || inp->inp_socket->so_options & SO_TIMESTAMP) {
#if INET6
		if (inp->inp_vflag & INP_IPV6) {
			int savedflags;

			ip_2_ip6_hdr(&udp_ip6.uip6_ip6, ip);
			savedflags = inp->inp_flags;
			inp->inp_flags &= ~INP_UNMAPPABLEOPTS;
			ip6_savecontrol(inp, &opts, &udp_ip6.uip6_ip6, m);
			inp->inp_flags = savedflags;
		} else
#endif
		ip_savecontrol(inp, &opts, ip, m);
	}
 	m_adj(m, iphlen + sizeof(struct udphdr));

	KERNEL_DEBUG(DBG_LAYER_IN_END, uh->uh_dport, uh->uh_sport,
		     save_ip.ip_src.s_addr, save_ip.ip_dst.s_addr, uh->uh_ulen);

#if INET6
	if (inp->inp_vflag & INP_IPV6) {
		in6_sin_2_v4mapsin6(&udp_in, &udp_in6.uin6_sin);
		append_sa = (struct sockaddr *)&udp_in6.uin6_sin;
	} else
#endif
	append_sa = (struct sockaddr *)&udp_in;
	if (sbappendaddr(&inp->inp_socket->so_rcv, append_sa, m, opts, NULL) == 0) {
		udpstat.udps_fullsock++;
	}
	else {
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
	return;
}

#if INET6
static void
ip_2_ip6_hdr(ip6, ip)
	struct ip6_hdr *ip6;
	struct ip *ip;
{
	bzero(ip6, sizeof(*ip6));

	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = ip->ip_len;
	ip6->ip6_nxt = ip->ip_p;
	ip6->ip6_hlim = ip->ip_ttl;
	ip6->ip6_src.s6_addr32[2] = ip6->ip6_dst.s6_addr32[2] =
		IPV6_ADDR_INT32_SMP;
	ip6->ip6_src.s6_addr32[3] = ip->ip_src.s_addr;
	ip6->ip6_dst.s6_addr32[3] = ip->ip_dst.s_addr;
}
#endif

/*
 * subroutine of udp_input(), mainly for source code readability.
 */
static void
#if INET6
udp_append(struct inpcb *last, struct ip *ip, struct mbuf *n, int off,
    struct sockaddr_in *pudp_in, struct udp_in6 *pudp_in6,
    struct udp_ip6 *pudp_ip6)
#else
udp_append(struct inpcb *last, struct ip *ip, struct mbuf *n, int off,
    struct sockaddr_in *pudp_in)
#endif
{
	struct sockaddr *append_sa;
	struct mbuf *opts = 0;

#if CONFIG_MACF_NET
	if (mac_inpcb_check_deliver(last, n, AF_INET, SOCK_DGRAM) != 0) {
		m_freem(n);
		return;
	}
#endif
	if (last->inp_flags & INP_CONTROLOPTS ||
	    last->inp_socket->so_options & SO_TIMESTAMP) {
#if INET6
		if (last->inp_vflag & INP_IPV6) {
			int savedflags;

			if (pudp_ip6->uip6_init_done == 0) {
				ip_2_ip6_hdr(&pudp_ip6->uip6_ip6, ip);
				pudp_ip6->uip6_init_done = 1;
			}
			savedflags = last->inp_flags;
			last->inp_flags &= ~INP_UNMAPPABLEOPTS;
			ip6_savecontrol(last, &opts, &pudp_ip6->uip6_ip6, n);
			last->inp_flags = savedflags;
		} else
#endif
		ip_savecontrol(last, &opts, ip, n);
	}
#if INET6
	if (last->inp_vflag & INP_IPV6) {
		if (pudp_in6->uin6_init_done == 0) {
			in6_sin_2_v4mapsin6(pudp_in, &pudp_in6->uin6_sin);
			pudp_in6->uin6_init_done = 1;
		}
		append_sa = (struct sockaddr *)&pudp_in6->uin6_sin;
	} else
#endif
	append_sa = (struct sockaddr *)pudp_in;
	m_adj(n, off);
	if (sbappendaddr(&last->inp_socket->so_rcv, append_sa, n, opts, NULL) == 0) {
		udpstat.udps_fullsock++;
	} else
		sorwakeup(last->inp_socket);
}

/*
 * Notify a udp user of an asynchronous error;
 * just wake up so that he can collect error status.
 */
void
udp_notify(inp, errno)
	register struct inpcb *inp;
	int errno;
{
	inp->inp_socket->so_error = errno;
	sorwakeup(inp->inp_socket);
	sowwakeup(inp->inp_socket);
}

void
udp_ctlinput(cmd, sa, vip)
	int cmd;
	struct sockaddr *sa;
	void *vip;
{
	struct ip *ip = vip;
	struct udphdr *uh;
	void (*notify)(struct inpcb *, int) = udp_notify;
        struct in_addr faddr;
	struct inpcb *inp;

	faddr = ((struct sockaddr_in *)sa)->sin_addr;
	if (sa->sa_family != AF_INET || faddr.s_addr == INADDR_ANY)
        	return;

	if (PRC_IS_REDIRECT(cmd)) {
		ip = 0;
		notify = in_rtchange;
	} else if (cmd == PRC_HOSTDEAD)
		ip = 0;
	else if ((unsigned)cmd >= PRC_NCMDS || inetctlerrmap[cmd] == 0)
		return;
	if (ip) {
		uh = (struct udphdr *)((caddr_t)ip + (ip->ip_hl << 2));
		inp = in_pcblookup_hash(&udbinfo, faddr, uh->uh_dport,
                    ip->ip_src, uh->uh_sport, 0, NULL);
		if (inp != NULL && inp->inp_socket != NULL) {
			udp_lock(inp->inp_socket, 1, 0);
			if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING)  {
				udp_unlock(inp->inp_socket, 1, 0);
				return;
			}
			(*notify)(inp, inetctlerrmap[cmd]);
			udp_unlock(inp->inp_socket, 1, 0);
		}
	} else
		in_pcbnotifyall(&udbinfo, faddr, inetctlerrmap[cmd], notify);
}

int
udp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int	error, optval;
	struct	inpcb *inp;

	if (sopt->sopt_level != IPPROTO_UDP)
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
	lck_rw_lock_exclusive(udbinfo.mtx);
	if (req->oldptr == USER_ADDR_NULL) {
		n = udbinfo.ipi_count;
		req->oldidx = 2 * (sizeof xig)
			+ (n + n/8) * sizeof(struct xinpcb);
		lck_rw_done(udbinfo.mtx);
		return 0;
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(udbinfo.mtx);
		return EPERM;
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = udbinfo.ipi_gencnt;
	n = udbinfo.ipi_count;

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof xig;
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error) {
		lck_rw_done(udbinfo.mtx);
		return error;
	}
    /*
     * We are done if there is no pcb
     */
    if (n == 0) {
	lck_rw_done(udbinfo.mtx);
        return 0; 
    }

	inp_list = _MALLOC(n * sizeof *inp_list, M_TEMP, M_WAITOK);
	if (inp_list == 0) {
		lck_rw_done(udbinfo.mtx);
		return ENOMEM;
	}
	
	for (inp = LIST_FIRST(udbinfo.listhead), i = 0; inp && i < n;
	     inp = LIST_NEXT(inp, inp_list)) {
		if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD)
			inp_list[i++] = inp;
	}
	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD) {
			struct xinpcb xi;

			bzero(&xi, sizeof(xi));
			xi.xi_len = sizeof xi;
			/* XXX should avoid extra copy */
			inpcb_to_compat(inp, &xi.xi_inp);
			if (inp->inp_socket)
				sotoxsocket(inp->inp_socket, &xi.xi_socket);
			error = SYSCTL_OUT(req, &xi, sizeof xi);
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
		bzero(&xig, sizeof(xig));
		xig.xig_len = sizeof xig;
		xig.xig_gen = udbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = udbinfo.ipi_count;
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	FREE(inp_list, M_TEMP);
	lck_rw_done(udbinfo.mtx);
	return error;
}

SYSCTL_PROC(_net_inet_udp, UDPCTL_PCBLIST, pcblist, CTLFLAG_RD, 0, 0,
	    udp_pcblist, "S,xinpcb", "List of active UDP sockets");

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
        lck_rw_lock_shared(udbinfo.mtx);
        if (req->oldptr == USER_ADDR_NULL) {
                n = udbinfo.ipi_count;
                req->oldidx = 2 * (sizeof xig)
                        + (n + n/8) * sizeof(struct xinpcb64);
                lck_rw_done(udbinfo.mtx);
                return 0;
        }

        if (req->newptr != USER_ADDR_NULL) {
                lck_rw_done(udbinfo.mtx);
                return EPERM;
        }

        /*
         * OK, now we're committed to doing something.
         */
        gencnt = udbinfo.ipi_gencnt;
        n = udbinfo.ipi_count;

        bzero(&xig, sizeof(xig));
        xig.xig_len = sizeof xig;
        xig.xig_count = n;
        xig.xig_gen = gencnt;
        xig.xig_sogen = so_gencnt;
        error = SYSCTL_OUT(req, &xig, sizeof xig);
        if (error) {
                lck_rw_done(udbinfo.mtx);
                return error;
        }
    /*
     * We are done if there is no pcb
     */
    if (n == 0) {
        lck_rw_done(udbinfo.mtx);
        return 0;
    }

        inp_list = _MALLOC(n * sizeof *inp_list, M_TEMP, M_WAITOK);
        if (inp_list == 0) {
                lck_rw_done(udbinfo.mtx);
                return ENOMEM;
        }

        for (inp = LIST_FIRST(udbinfo.listhead), i = 0; inp && i < n;
             inp = LIST_NEXT(inp, inp_list)) {
                if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD)
                        inp_list[i++] = inp;
        }
        n = i;

        error = 0;
        for (i = 0; i < n; i++) {
                inp = inp_list[i];
                if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD) {
                        struct xinpcb64 xi;

                        bzero(&xi, sizeof(xi));
                        xi.xi_len = sizeof xi;
                        inpcb_to_xinpcb64(inp, &xi);
                        if (inp->inp_socket)
                                sotoxsocket64(inp->inp_socket, &xi.xi_socket);
                        error = SYSCTL_OUT(req, &xi, sizeof xi);
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
                bzero(&xig, sizeof(xig));
                xig.xig_len = sizeof xig;
                xig.xig_gen = udbinfo.ipi_gencnt;
                xig.xig_sogen = so_gencnt;
                xig.xig_count = udbinfo.ipi_count;
                error = SYSCTL_OUT(req, &xig, sizeof xig);
        }
        FREE(inp_list, M_TEMP);
        lck_rw_done(udbinfo.mtx);
        return error;
}

SYSCTL_PROC(_net_inet_udp, OID_AUTO, pcblist64, CTLFLAG_RD, 0, 0,
            udp_pcblist64, "S,xinpcb64", "List of active UDP sockets");

#endif /* !CONFIG_EMBEDDED */

static __inline__ u_int16_t
get_socket_id(struct socket * s)
{
	u_int16_t 		val;

	if (s == NULL) {
	    return (0);
	}
	val = (u_int16_t)(((uintptr_t)s) / sizeof(struct socket));
	if (val == 0) {
		val = 0xffff;
	}
	return (val);
}

static int
udp_output(inp, m, addr, control, p)
	register struct inpcb *inp;
	struct mbuf *m;
	struct sockaddr *addr;
	struct mbuf *control;
	struct proc *p;
{
	register struct udpiphdr *ui;
	register int len = m->m_pkthdr.len;
	struct sockaddr_in *sin;
	struct in_addr origladdr, laddr, faddr;
	u_short lport, fport;
	struct sockaddr_in *ifaddr;
	int error = 0, udp_dodisconnect = 0;
	struct socket *so = inp->inp_socket;
	int soopts = 0;
	struct mbuf *inpopts;
	struct ip_moptions *mopts;
	struct route ro;
	struct ip_out_args ipoa;

	KERNEL_DEBUG(DBG_FNC_UDP_OUTPUT | DBG_FUNC_START, 0,0,0,0,0);

	if (control)
		m_freem(control);		/* XXX */

	KERNEL_DEBUG(DBG_LAYER_OUT_BEG, inp->inp_fport, inp->inp_lport,
		     inp->inp_laddr.s_addr, inp->inp_faddr.s_addr,
		     (htons((u_short)len + sizeof (struct udphdr))));

	if (len + sizeof(struct udpiphdr) > IP_MAXPACKET) {
		error = EMSGSIZE;
		goto release;
	}

        lck_mtx_assert(inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	/* If socket was bound to an ifindex, tell ip_output about it */
	ipoa.ipoa_ifscope = (inp->inp_flags & INP_BOUND_IF) ?
	    inp->inp_boundif : IFSCOPE_NONE;
	soopts |= IP_OUTARGS;

	/* If there was a routing change, discard cached route and check
	 * that we have a valid source address. 
	 * Reacquire a new source address if INADDR_ANY was specified
	 */
	if (inp->inp_route.ro_rt != NULL &&
	    inp->inp_route.ro_rt->generation_id != route_generation) {
		struct in_ifaddr *ia;

		/* src address is gone? */
		if ((ia = ifa_foraddr(inp->inp_laddr.s_addr)) == NULL) {
			if (inp->inp_flags & INP_INADDR_ANY) {
				/* new src will be set later */
				inp->inp_laddr.s_addr = INADDR_ANY;
			} else {
				error = EADDRNOTAVAIL;
				goto release;
			}
		}
		if (ia != NULL)
			ifafree(&ia->ia_ifa);
		if (inp->inp_route.ro_rt != NULL)
			rtfree(inp->inp_route.ro_rt);
		inp->inp_route.ro_rt = NULL;
	}

	origladdr= laddr = inp->inp_laddr;
	faddr = inp->inp_faddr;
	lport = inp->inp_lport;
	fport = inp->inp_fport;

	if (addr) {
		sin = (struct sockaddr_in *)addr;
		if (faddr.s_addr != INADDR_ANY) {
			error = EISCONN;
			goto release;
		}
		if (lport == 0) {
			/*
			 * In case we don't have a local port set, go through the full connect.
			 * We don't have a local port yet (ie, we can't be looked up),
			 * so it's not an issue if the input runs at the same time we do this.
		 	 */
			error = in_pcbconnect(inp, addr, p);
			if (error) {
				goto release;
			}
			laddr = inp->inp_laddr;
			lport = inp->inp_lport;
			faddr = inp->inp_faddr;
			fport = inp->inp_fport;
			udp_dodisconnect = 1;
		}
		else {	
			/* Fast path case
			 * we have a full address and a local port.
			 * use those info to build the packet without changing the pcb
			 * and interfering with the input path. See 3851370
			 */
			if (laddr.s_addr == INADDR_ANY) {
			   if ((error = in_pcbladdr(inp, addr, &ifaddr)) != 0)
				   goto release;
			   laddr = ifaddr->sin_addr;
			   inp->inp_flags |= INP_INADDR_ANY; /* from pcbconnect: remember we don't care about src addr.*/
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
#endif

	/*
	 * Calculate data length and get a mbuf
	 * for UDP and IP headers.
	 */
	M_PREPEND(m, sizeof(struct udpiphdr), M_DONTWAIT);
	if (m == 0) {
		error = ENOBUFS;
		goto abort;
	}

	/*
	 * Fill in mbuf with extended UDP header
	 * and addresses and length put into network format.
	 */
	ui = mtod(m, struct udpiphdr *);
	bzero(ui->ui_x1, sizeof(ui->ui_x1));	/* XXX still needed? */
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_src = laddr;
	ui->ui_dst = faddr;
	ui->ui_sport = lport;
	ui->ui_dport = fport;
	ui->ui_ulen = htons((u_short)len + sizeof(struct udphdr));

	/*
	 * Set up checksum and output datagram.
	 */
	if (udpcksum && !(inp->inp_flags & INP_UDP_NOCKSUM)) {
        	ui->ui_sum = in_pseudo(ui->ui_src.s_addr, ui->ui_dst.s_addr,
		    htons((u_short)len + sizeof(struct udphdr) + IPPROTO_UDP));
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
#endif /*IPSEC*/
	m->m_pkthdr.socket_id = get_socket_id(inp->inp_socket);

	inpopts = inp->inp_options;
	soopts |= (inp->inp_socket->so_options & (SO_DONTROUTE | SO_BROADCAST));
	mopts = inp->inp_moptions;

	/* Copy the cached route and take an extra reference */
	inp_route_copyout(inp, &ro);

	socket_unlock(so, 0);
	/* XXX jgraessley please look at XXX */
	error = ip_output_list(m, 0, inpopts, &ro, soopts, mopts, &ipoa);
	socket_lock(so, 0);

	/* Synchronize PCB cached route */
	inp_route_copyin(inp, &ro);

	if (udp_dodisconnect) {
		in_pcbdisconnect(inp);
		inp->inp_laddr = origladdr;	/* XXX rehash? */
	}
	KERNEL_DEBUG(DBG_FNC_UDP_OUTPUT | DBG_FUNC_END, error, 0,0,0,0);
	return (error);

abort:
        if (udp_dodisconnect) {
                in_pcbdisconnect(inp);
                inp->inp_laddr = origladdr; /* XXX rehash? */
        }

release:
	m_freem(m);
	KERNEL_DEBUG(DBG_FNC_UDP_OUTPUT | DBG_FUNC_END, error, 0,0,0,0);
	return (error);
}

u_int32_t	udp_sendspace = 9216;		/* really max datagram size */
/* 40 1K datagrams */
u_int32_t	udp_recvspace = 40 * (1024 +
#if INET6
				      sizeof(struct sockaddr_in6)
#else
				      sizeof(struct sockaddr_in)
#endif
				      );

/* Check that the values of udp send and recv space do not exceed sb_max */
static int
sysctl_udp_sospace(struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, struct sysctl_req *req) {
	u_int32_t new_value = 0, *space_p = NULL;
	int changed = 0, error = 0;
	u_quad_t sb_effective_max = (sb_max/ (MSIZE+MCLBYTES)) * MCLBYTES;

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

SYSCTL_PROC(_net_inet_udp, UDPCTL_RECVSPACE, recvspace, CTLTYPE_INT | CTLFLAG_RW,
    &udp_recvspace, 0, &sysctl_udp_sospace, "IU", "Maximum incoming UDP datagram size");

SYSCTL_PROC(_net_inet_udp, UDPCTL_MAXDGRAM, maxdgram, CTLTYPE_INT | CTLFLAG_RW,
    &udp_sendspace, 0, &sysctl_udp_sospace, "IU", "Maximum outgoing UDP datagram size");

static int
udp_abort(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == 0)
		panic("udp_abort: so=%p null inp\n", so);	/* ??? possible? panic instead? */
	soisdisconnected(so);
	in_pcbdetach(inp);
	return 0;
}

static int
udp_attach(struct socket *so, __unused int proto, struct proc *p)
{
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	if (inp != 0)
		panic ("udp_attach so=%p inp=%p\n", so, inp);

	error = in_pcballoc(so, &udbinfo, p);
	if (error)
		return error;
	error = soreserve(so, udp_sendspace, udp_recvspace);
	if (error) 
		return error;
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_ttl = ip_defttl;
	return 0;
}

static int
udp_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int error;

	if (nam->sa_family != 0 && nam->sa_family != AF_INET
	    && nam->sa_family != AF_INET6) {
		return EAFNOSUPPORT;
	}
	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;
	error = in_pcbbind(inp, nam, p);
	return error;
}

static int
udp_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int error;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;
	if (inp->inp_faddr.s_addr != INADDR_ANY)
		return EISCONN;
	error = in_pcbconnect(inp, nam, p);
	if (error == 0) 
		soisconnected(so);
	return error;
}

static int
udp_detach(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == 0)
		panic("udp_detach: so=%p null inp\n", so);	/* ??? possible? panic instead? */
	in_pcbdetach(inp);
	inp->inp_state = INPCB_STATE_DEAD;
	return 0;
}

static int
udp_disconnect(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;
	if (inp->inp_faddr.s_addr == INADDR_ANY)
		return ENOTCONN;

	in_pcbdisconnect(inp);
	inp->inp_laddr.s_addr = INADDR_ANY;
	so->so_state &= ~SS_ISCONNECTED;		/* XXX */
	return 0;
}

static int
udp_send(struct socket *so, __unused int flags, struct mbuf *m, struct sockaddr *addr,
	    struct mbuf *control, struct proc *p)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == 0) {
		m_freem(m);
		return EINVAL;
	}
	
	return udp_output(inp, m, addr, control, p);
}

int
udp_shutdown(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;
	socantsendmore(so);
	return 0;
}

struct pr_usrreqs udp_usrreqs = {
	udp_abort, pru_accept_notsupp, udp_attach, udp_bind, udp_connect, 
	pru_connect2_notsupp, in_control, udp_detach, udp_disconnect, 
	pru_listen_notsupp, in_setpeeraddr, pru_rcvd_notsupp, 
	pru_rcvoob_notsupp, udp_send, pru_sense_null, udp_shutdown,
	in_setsockaddr, sosend, soreceive, pru_sopoll_notsupp
};


int
udp_lock(struct socket *so, int refcount, void *debug)
{
	void *lr_saved;

	if (debug == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = debug;

	if (so->so_pcb) {
		lck_mtx_assert(((struct inpcb *)so->so_pcb)->inpcb_mtx,
		    LCK_MTX_ASSERT_NOTOWNED);
		lck_mtx_lock(((struct inpcb *)so->so_pcb)->inpcb_mtx);
	} else {
		panic("udp_lock: so=%p NO PCB! lr=%p lrh= %s\n", 
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
		panic("udp_unlock: so=%p NO PCB! lr=%p lrh= %s\n", 
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	} else {
		lck_mtx_assert(((struct inpcb *)so->so_pcb)->inpcb_mtx,
		    LCK_MTX_ASSERT_OWNED);
		so->unlock_lr[so->next_unlock_lr] = lr_saved;
		so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;
		lck_mtx_unlock(((struct inpcb *)so->so_pcb)->inpcb_mtx);
	}


	return (0);
}

lck_mtx_t *
udp_getlock(struct socket *so, __unused int locktype)
{
	struct inpcb *inp = sotoinpcb(so);


	if (so->so_pcb)
		return(inp->inpcb_mtx);
	else {
		panic("udp_getlock: so=%p NULL so_pcb lrh= %s\n", 
			so, solockhistory_nr(so));
		return (so->so_proto->pr_domain->dom_mtx);
	}
}

void
udp_slowtimo()
{
	struct inpcb *inp, *inpnxt;
	struct socket *so;
    	struct inpcbinfo *pcbinfo	= &udbinfo;

	if (lck_rw_try_lock_exclusive(pcbinfo->mtx) == FALSE) {
		if (udp_gc_done == TRUE) {
			udp_gc_done = FALSE;
			return; /* couldn't get the lock, better lock next time */
		}
		lck_rw_lock_exclusive(pcbinfo->mtx);
	}

	udp_gc_done = TRUE;

	for (inp = udb.lh_first; inp != NULL; inp = inpnxt) {
		inpnxt = inp->inp_list.le_next;

		if (inp->inp_wantcnt != WNT_STOPUSING) 
			continue;

		so = inp->inp_socket;
		if (!lck_mtx_try_lock(inp->inpcb_mtx))	/* skip if busy, no hurry for cleanup... */
			continue;

		if (so->so_usecount == 0) {
			if (inp->inp_state != INPCB_STATE_DEAD) {
#if INET6
				if (INP_CHECK_SOCKAF(so, AF_INET6))
					in6_pcbdetach(inp);
				else
#endif /* INET6 */
				in_pcbdetach(inp);
			}
			in_pcbdispose(inp);
		} else {
			lck_mtx_unlock(inp->inpcb_mtx);
		}
	}
	lck_rw_done(pcbinfo->mtx);
}

int
ChkAddressOK( __uint32_t dstaddr, __uint32_t srcaddr )
{
        if ( dstaddr == srcaddr ){
                return 0;
        }
        return 1;
}

void
udp_in_cksum_stats(u_int32_t len)
{
	udps_in_sw_cksum++;
	udps_in_sw_cksum_bytes += len;
}

void
udp_out_cksum_stats(u_int32_t len)
{
	udps_out_sw_cksum++;
	udps_out_sw_cksum_bytes += len;
}
