/*	$KAME: natpt_trans.c,v 1.12 2000/03/25 07:23:56 sumikawa Exp $	*/

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

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#ifdef __FreeBSD__
# include <sys/kernel.h>
#endif

#include <net/if.h>
#ifdef __bsdi__
#include <net/route.h>
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#if defined(__bsdi__) || defined(__NetBSD__)
#include <net/route.h>		/* netinet/in_pcb.h line 71 make happy.		*/
#include <netinet/in_pcb.h>
#endif

#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#if !defined(__NetBSD__) && (!defined(__FreeBSD__) || (__FreeBSD__ < 3)) && !defined(__APPLE__)
#include <netinet6/tcp6.h>
#endif

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_list.h>
#include <netinet6/natpt_var.h>


#define	recalculateTCP4Checksum		1
#define	recalculateTCP6Checksum		1


/*
 *
 */

int		 errno;
int		 natpt_initialized;
int		 ip6_protocol_tr;

extern	struct in6_addr	 natpt_prefix;
extern	struct in6_addr	 natpt_prefixmask;

struct mbuf	*translatingTCPUDPv4To4		__P((struct _cv *, struct pAddr *, struct _cv *));

void		 tr_icmp4EchoReply		__P((struct _cv *, struct _cv *));
void		 tr_icmp4Unreach		__P((struct _cv *, struct _cv *, struct pAddr *));
void		 tr_icmp4Echo			__P((struct _cv *, struct _cv *));
void		 tr_icmp4Timxceed		__P((struct _cv *, struct _cv *, struct pAddr *));
void		 tr_icmp4Paramprob		__P((struct _cv *, struct _cv *));
void		 tr_icmp4MimicPayload		__P((struct _cv *, struct _cv *, struct pAddr *));

void		 tr_icmp6DstUnreach		__P((struct _cv *, struct _cv *));
void		 tr_icmp6PacketTooBig		__P((struct _cv *, struct _cv *));
void		 tr_icmp6TimeExceed		__P((struct _cv *, struct _cv *));
void		 tr_icmp6ParamProb		__P((struct _cv *, struct _cv *));
void		 tr_icmp6EchoRequest		__P((struct _cv *, struct _cv *));
void		 tr_icmp6EchoReply		__P((struct _cv *, struct _cv *));

static	void	 _recalculateTCP4Checksum	__P((struct _cv *));

static	int	 updateTcpStatus		__P((struct _cv *));
static	int	 _natpt_tcpfsm			__P((int, int, u_short, u_char));
static	int	 _natpt_tcpfsmSessOut		__P((int, short, u_char));
static	int	 _natpt_tcpfsmSessIn		__P((int, short, u_char));

static	void	 adjustUpperLayerChecksum	__P((int, int, struct _cv *, struct _cv *));
static	int	 adjustChecksum			__P((int, u_char *, int, u_char *, int));


#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static	MALLOC_DEFINE(M_NATPT, "NATPT", "Network Address Translation - Protocol Translation");
#endif


#ifdef NATPT_NAT
/*
 *	Translating From IPv4 to IPv4
 */

struct mbuf *
translatingIPv4To4(struct _cv *cv4, struct pAddr *pad)
{
    struct timeval	 atv;
    struct mbuf		*m4 = NULL;

    if (isDump(D_TRANSLATINGIPV4))
	natpt_logIp4(LOG_DEBUG, cv4->_ip._ip4);

    microtime(&atv);
    cv4->ats->tstamp = atv.tv_sec;

    switch (cv4->ip_payload)
    {
      case IPPROTO_ICMP:
	m4 = translatingICMPv4To4(cv4, pad);
	break;

      case IPPROTO_TCP:
	m4 = translatingTCPv4To4(cv4, pad);
	break;

      case IPPROTO_UDP:
	m4 = translatingUDPv4To4(cv4, pad);
	break;
    }

    if (m4)
    {
	struct ip	*ip4;

	ip4 = mtod(m4, struct ip *);
	ip4->ip_sum = 0;			/* Header checksum	*/
	ip4->ip_sum = in_cksum(m4, sizeof(struct ip));
	m4->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;
	
	m4->m_pkthdr.len = cv4->m->m_pkthdr.len;
    }

    return (m4);
}


struct mbuf *
translatingICMPv4To4(struct _cv *cv4from, struct pAddr *pad)
{
    struct _cv		 cv4to;
    struct mbuf		*m4;
    struct ip		*ip4from, *ip4to;
    struct icmp		*icmp4from;

    ip4from = mtod(cv4from->m, struct ip *);
    icmp4from = cv4from->_payload._icmp4;

    m4 = m_copym(cv4from->m,0, M_COPYALL, M_NOWAIT);
    ReturnEnobufs(m4);

    bzero(&cv4to, sizeof(struct _cv));
    cv4to.m = m4;
    cv4to._ip._ip4 = ip4to = mtod(m4, struct ip *);
    cv4to._payload._caddr = (caddr_t)cv4to._ip._ip4 + (ip4from->ip_hl << 2);

    ip4to->ip_src = pad->in4src;	/* source address		*/
    ip4to->ip_dst = pad->in4dst;	/* destination address		*/

    switch (icmp4from->icmp_type)
    {
      case ICMP_ECHOREPLY:
      case ICMP_ECHO:
	break;

      default:
	m_freem(m4);
	return (NULL);
    }

    m4->m_len = cv4from->m->m_len;
    return (m4);
}


struct mbuf *
translatingTCPv4To4(struct _cv *cv4from, struct pAddr *pad)
{
    struct _cv		 cv4to;
    struct mbuf		*m4;

    bzero(&cv4to, sizeof(struct _cv));
    m4 = translatingTCPUDPv4To4(cv4from, pad, &cv4to);
    cv4to.ip_p = cv4to.ip_payload = IPPROTO_TCP;

    updateTcpStatus(&cv4to);
    adjustUpperLayerChecksum(IPPROTO_IPV4, IPPROTO_TCP, cv4from, &cv4to);

#ifdef recalculateTCP4Checksum
    _recalculateTCP4Checksum(&cv4to);
#endif

    return (m4);
}


struct mbuf *
translatingUDPv4To4(struct _cv *cv4from, struct pAddr *pad)
{
    struct _cv		 cv4to;
    struct mbuf		*m4;

    bzero(&cv4to, sizeof(struct _cv));
    m4 = translatingTCPUDPv4To4(cv4from, pad, &cv4to);
    cv4to.ip_p = cv4to.ip_payload = IPPROTO_UDP;

    adjustUpperLayerChecksum(IPPROTO_IPV4, IPPROTO_UDP, cv4from, &cv4to);

    return (m4);
}


struct mbuf *
translatingTCPUDPv4To4(struct _cv *cv4from, struct pAddr *pad, struct _cv *cv4to)
{
    struct mbuf		*m4;
    struct ip		*ip4to;
    struct tcphdr	*tcp4to;

    m4 = m_copym(cv4from->m,0, M_COPYALL, M_NOWAIT);
    ReturnEnobufs(m4);

    ip4to = mtod(m4, struct ip *);

    ip4to->ip_src = pad->in4src;
    ip4to->ip_dst = pad->in4dst;

    tcp4to = (struct tcphdr *)((caddr_t)ip4to + (ip4to->ip_hl << 2));
    tcp4to->th_sport = pad->_sport;
    tcp4to->th_dport = pad->_dport;

    cv4to->m = m4;
    cv4to->_ip._ip4 = ip4to;
    cv4to->_payload._tcp4 = tcp4to;
    cv4to->ats = cv4from->ats;

    return (m4);
}

#endif	/* ifdef NATPT_NAT	*/


/*
 *	Translating From IPv4 To IPv6
 */

struct mbuf *
translatingIPv4To6(struct _cv *cv4, struct pAddr *pad)
{
    struct timeval	 atv;
    struct mbuf		*m6 = NULL;

    if (isDump(D_TRANSLATINGIPV4))
	natpt_logIp4(LOG_DEBUG, cv4->_ip._ip4);

    microtime(&atv);
    cv4->ats->tstamp = atv.tv_sec;

    switch (cv4->ip_payload)
    {
      case IPPROTO_ICMP:
	m6 = translatingICMPv4To6(cv4, pad);
	break;

      case IPPROTO_TCP:
	m6 = translatingTCPv4To6(cv4, pad);
	break;

      case IPPROTO_UDP:
	m6 = translatingUDPv4To6(cv4, pad);
	break;
    }

    if (m6)
	m6->m_pkthdr.rcvif = cv4->m->m_pkthdr.rcvif;

    return (m6);
}


struct mbuf *
translatingICMPv4To6(struct _cv *cv4, struct pAddr *pad)
{
    struct _cv		 cv6;
    struct mbuf		*m6;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;
    struct icmp		*icmp4;
    struct icmp6_hdr	*icmp6;

    ip4 = mtod(cv4->m, struct ip *);
    icmp4 = cv4->_payload._icmp4;

    {
	caddr_t		 icmp4end;
	int		 icmp4len;

	icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	icmp4len = icmp4end - (caddr_t)cv4->_payload._icmp4;

	MGETHDR(m6, M_NOWAIT, MT_HEADER);
	if (m6 == NULL)
	{
	    errno = ENOBUFS;
	    return (NULL);
	}
	if (MHLEN < (sizeof(struct ip6_hdr) + icmp4len))
	    MCLGET(m6, M_NOWAIT);
    }

    cv6.m = m6;
    cv6._ip._ip6 = mtod(m6, struct ip6_hdr *);
    cv6._payload._caddr = (caddr_t)cv6._ip._ip6 + sizeof(struct ip6_hdr);

    ip6 = mtod(cv6.m,  struct ip6_hdr *);
    icmp6 = cv6._payload._icmp6;;

    ip6->ip6_flow = 0;
    ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
    ip6->ip6_vfc |=  IPV6_VERSION;
    ip6->ip6_plen = 0;						/* XXX */
    ip6->ip6_nxt  = IPPROTO_ICMPV6;
    ip6->ip6_hlim = ip4->ip_ttl -1;
    ip6->ip6_dst  = pad->in6dst;
    ip6->ip6_src  = pad->in6src;
    if (natpt_prefix.s6_addr32[0] != 0)
    {
	ip6->ip6_src.s6_addr32[0] = natpt_prefix.s6_addr32[0];
	ip6->ip6_src.s6_addr32[1] = natpt_prefix.s6_addr32[1];
	ip6->ip6_src.s6_addr32[2] = natpt_prefix.s6_addr32[2];
    }
    else
    {
	ip6->ip6_src.s6_addr32[0] = 0;
	ip6->ip6_src.s6_addr32[1] = 0;
	ip6->ip6_src.s6_addr32[2] = 0;
    }
    ip6->ip6_src.s6_addr32[3] = ip4->ip_src.s_addr;

    switch (icmp4->icmp_type)
    {
      case ICMP_ECHOREPLY:
	tr_icmp4EchoReply(cv4, &cv6);
	break;

      case ICMP_UNREACH:
	tr_icmp4Unreach(cv4, &cv6, pad);
	break;

      case ICMP_ECHO:
	tr_icmp4Echo(cv4, &cv6);
	break;

      case ICMP_TIMXCEED:
	tr_icmp4Timxceed(cv4, &cv6, pad);
	break;

      case ICMP_PARAMPROB:
	tr_icmp4Paramprob(cv4, &cv6);
	break;

      case ICMP_REDIRECT:
      case ICMP_ROUTERADVERT:
      case ICMP_ROUTERSOLICIT:
	m_freem(m6);		/* Single hop message.	Silently drop.	*/
	return (NULL);

      case ICMP_SOURCEQUENCH:
      case ICMP_TSTAMP:
      case ICMP_TSTAMPREPLY:
      case ICMP_IREQ:
      case ICMP_IREQREPLY:
      case ICMP_MASKREQ:
      case ICMP_MASKREPLY:
	m_freem(m6);		/* Obsoleted in ICMPv6.	 Silently drop.	*/
	return (NULL);

      default:
	m_freem(m6);		/* Silently drop.			*/
	return (NULL);
    }

    icmp6->icmp6_cksum = 0;
    icmp6->icmp6_cksum = in6_cksum(cv6.m, IPPROTO_ICMPV6,
				   sizeof(struct ip6_hdr), ntohs(ip6->ip6_plen));

    return (m6);
}


void
tr_icmp4EchoReply(struct _cv *cv4, struct _cv *cv6)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp6->icmp6_type = ICMP6_ECHO_REPLY;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id   = icmp4->icmp_id;
    icmp6->icmp6_seq  = icmp4->icmp_seq;

    {
	int		 dlen;
	struct ip	*ip4 = cv4->_ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;
	caddr_t		 icmp4off, icmp6off;
	caddr_t		 icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	int		 icmp4len = icmp4end - (caddr_t)cv4->_payload._icmp4;

	dlen = icmp4len - ICMP_MINLEN;
	icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
	icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
	bcopy(icmp4off, icmp6off, dlen);

	ip6->ip6_plen = ntohs(sizeof(struct icmp6_hdr) + dlen);
	cv6->m->m_pkthdr.len
	  = cv6->m->m_len
	  = sizeof(struct ip6_hdr) + htons(ip6->ip6_plen);
    }
}


void
tr_icmp4Unreach(struct _cv *cv4, struct _cv *cv6, struct pAddr *pad)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp6->icmp6_type = ICMP6_DST_UNREACH;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id   = icmp4->icmp_id;
    icmp6->icmp6_seq  = icmp4->icmp_seq;

    switch (icmp4->icmp_code)
    {
      case ICMP_UNREACH_NET:
      case ICMP_UNREACH_HOST:
	icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
	break;

      case ICMP_UNREACH_PROTOCOL:					/* do more	*/
	icmp6->icmp6_type = ICMP6_PARAM_PROB;
	icmp6->icmp6_code = ICMP6_PARAMPROB_NEXTHEADER;			/* xxx		*/
	break;

      case ICMP_UNREACH_PORT:
	icmp6->icmp6_code = ICMP6_DST_UNREACH_NOPORT;
	break;

      case ICMP_UNREACH_NEEDFRAG:					/* do more	*/
	icmp6->icmp6_type = ICMP6_PACKET_TOO_BIG;
	icmp6->icmp6_code = ICMP6_PARAMPROB_HEADER;
	break;

      case ICMP_UNREACH_SRCFAIL:
	icmp6->icmp6_code = ICMP6_DST_UNREACH_NOTNEIGHBOR;
	break;

      case ICMP_UNREACH_NET_UNKNOWN:
      case ICMP_UNREACH_HOST_UNKNOWN:
	icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
	break;

      case ICMP_UNREACH_ISOLATED:
	icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
	break;

      case ICMP_UNREACH_NET_PROHIB:
      case ICMP_UNREACH_HOST_PROHIB:
	icmp6->icmp6_code = ICMP6_DST_UNREACH_ADMIN;
	break;

      case ICMP_UNREACH_TOSNET:
      case ICMP_UNREACH_TOSHOST:
	icmp6->icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
	break;

      default:
	break;
    }

    tr_icmp4MimicPayload(cv4, cv6, pad);
}


void
tr_icmp4Echo(struct _cv *cv4, struct _cv *cv6)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id   = icmp4->icmp_id;
    icmp6->icmp6_seq  = icmp4->icmp_seq;

    {
	int		 dlen;
	struct ip	*ip4 = cv4->_ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;
	caddr_t		 icmp4off, icmp6off;
	caddr_t		 icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
	int		 icmp4len = icmp4end - (caddr_t)cv4->_payload._icmp4;

	dlen = icmp4len - ICMP_MINLEN;
	icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
	icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
	bcopy(icmp4off, icmp6off, dlen);

	ip6->ip6_plen = ntohs(sizeof(struct icmp6_hdr) + dlen);
	cv6->m->m_pkthdr.len
	  = cv6->m->m_len
	  = sizeof(struct ip6_hdr) + htons(ip6->ip6_plen);
    }
}


void
tr_icmp4Timxceed(struct _cv *cv4, struct _cv *cv6, struct pAddr *pad)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp6->icmp6_type = ICMP6_TIME_EXCEEDED;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id   = icmp4->icmp_id;
    icmp6->icmp6_seq  = icmp4->icmp_seq;

    tr_icmp4MimicPayload(cv4, cv6, pad);
}


void
tr_icmp4Paramprob(struct _cv *cv4, struct _cv *cv6)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp6->icmp6_type = ICMP6_PARAM_PROB;
    icmp6->icmp6_code = 0;
    icmp6->icmp6_id   = icmp4->icmp_id;
    icmp6->icmp6_seq  = icmp4->icmp_seq;
}


void
tr_icmp4MimicPayload(struct _cv *cv4, struct _cv *cv6, struct pAddr *pad)
{
    int			 dgramlen;
    int			 icmp6dlen, icmp6rest;
    struct ip		*ip4 = cv6->_ip._ip4;
    struct ip6_hdr	*ip6 = cv6->_ip._ip6;
    struct ip6_hdr	*icmpip6;
    caddr_t		 icmp4off, icmp4dgramoff;
    caddr_t		 icmp6off, icmp6dgramoff;
    caddr_t		 icmp4end = (caddr_t)ip4 + cv4->m->m_pkthdr.len;
    int			 icmp4len = icmp4end - (caddr_t)cv4->_payload._icmp4;

    icmp6rest = MHLEN - sizeof(struct ip6_hdr) * 2 - sizeof(struct icmp6_hdr);
    dgramlen  = icmp4len - ICMP_MINLEN - sizeof(struct ip);
    dgramlen  = min(icmp6rest, dgramlen);

    icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
    icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
    icmp4dgramoff = icmp4off + sizeof(struct ip);
    icmp6dgramoff = icmp6off + sizeof(struct ip6_hdr);

    icmpip6 = (struct ip6_hdr *)icmp6off;
    bzero(icmpip6, sizeof(struct ip6_hdr));
    bcopy(icmp4dgramoff, icmp6dgramoff, dgramlen);

    icmpip6->ip6_flow = 0;
    icmpip6->ip6_vfc &= ~IPV6_VERSION_MASK;
    icmpip6->ip6_vfc |=	 IPV6_VERSION;
    icmpip6->ip6_plen = 0;
    icmpip6->ip6_nxt  = IPPROTO_UDP;
    icmpip6->ip6_hlim = 0;
    icmpip6->ip6_src  = pad->in6dst;
    icmpip6->ip6_dst  = pad->in6src;

    icmp6dlen = sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + dgramlen;
    ip6->ip6_plen = ntohs(icmp6dlen);
    cv6->m->m_pkthdr.len
      = cv6->m->m_len
      = sizeof(struct ip6_hdr) + htons(ip6->ip6_plen);

    if (cv4->flags & NATPT_TRACEROUTE)
    {
	struct udphdr	*icmpudp6;

	icmpudp6 = (struct udphdr *)((caddr_t)icmpip6 + sizeof(struct ip6_hdr));
	icmpudp6->uh_sport = cv4->ats->local._dport;
	icmpudp6->uh_dport = cv4->ats->local._sport;
    }
}


struct mbuf *
translatingTCPv4To6(struct _cv *cv4, struct pAddr *pad)
{
    int			 cksumOrg;
    struct _cv		 cv6;
    struct mbuf		*m6;

    bzero(&cv6, sizeof(struct _cv));
    m6 = translatingTCPUDPv4To6(cv4, pad, &cv6);
    cv6.ip_p = cv6.ip_payload = IPPROTO_TCP;
    cksumOrg = ntohs(cv4->_payload._tcp4->th_sum);

    updateTcpStatus(cv4);
    adjustUpperLayerChecksum(IPPROTO_IPV4, IPPROTO_TCP, &cv6, cv4);

#ifdef recalculateTCP6Checksum
    {
	int		 cksumAdj, cksumCks;
	struct tcp6hdr	*th;

	cksumAdj = cv6._payload._tcp6->th_sum;

	th = cv6._payload._tcp6;
	th->th_sum = 0;
	th->th_sum = in6_cksum(cv6.m, IPPROTO_TCP, sizeof(struct ip6_hdr),
			       cv6.m->m_pkthdr.len - sizeof(struct ip6_hdr));

	cksumCks = th->th_sum;
#if	0
	printf("translatingTCPv4To6: TCP4->TCP6: %04x, %04x, %04x %d\n",
	       cksumOrg, cksumAdj, cksumCks, cv6.m->m_pkthdr.len);
#endif
    }
#endif

    return (m6);
}


struct mbuf *
translatingUDPv4To6(struct _cv *cv4, struct pAddr *pad)
{
    struct _cv		 cv6;
    struct mbuf		*m6;

    bzero(&cv6, sizeof(struct _cv));
    m6 = translatingTCPUDPv4To6(cv4, pad, &cv6);
    cv6.ip_p = cv6.ip_payload = IPPROTO_UDP;

    return (m6);
}


struct mbuf *
translatingTCPUDPv4To6(struct _cv *cv4, struct pAddr *pad, struct _cv *cv6)
{
    struct mbuf		*m6;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;
    struct tcp6hdr	*tcp6;

    if (cv4->m->m_flags & M_EXT)
    {
	if (cv4->plen + sizeof(struct ip6_hdr) > MHLEN)
	{
	    struct mbuf	*m6next;

	    m6next = m_copym(cv4->m, 0, M_COPYALL, M_NOWAIT);
	    ReturnEnobufs(m6next);

	    m6next->m_data += cv4->poff;
	    m6next->m_len  -= cv4->poff;

	    MGETHDR(m6, M_NOWAIT, MT_HEADER);
	    ReturnEnobufs(m6);

	    m6->m_next	= m6next;
	    m6->m_data += (MHLEN - sizeof(struct ip6_hdr));
	    m6->m_len	= sizeof(struct ip6_hdr);
	    m6->m_pkthdr.len = sizeof(struct ip6_hdr) + cv4->plen;
	    ip6 = mtod(m6, struct ip6_hdr *);

	    cv6->m = m6;
	    cv6->_ip._ip6 = mtod(m6, struct ip6_hdr *);
	    cv6->_payload._caddr = m6next->m_data;
	    cv6->plen = cv4->plen;
	    cv6->poff = 0;
	}
	else	/* (sizeof(struct ip6_hdr) + cv4->plen <= MHLEN)	*/
	{
	    caddr_t	tcp4;
	    caddr_t	tcp6;

	    MGETHDR(m6, M_NOWAIT, MT_HEADER);
	    if (m6 == NULL)
	    {
		errno = ENOBUFS;
		return (NULL);
	    }

	    ip6 = mtod(m6, struct ip6_hdr *);
	    tcp4 = (caddr_t)cv4->_payload._tcp4;
	    tcp6 = (caddr_t)ip6 + sizeof(struct ip6_hdr);
	    bcopy(tcp4, tcp6, cv4->plen);

	    m6->m_pkthdr.len
		= m6->m_len
		= sizeof(struct ip6_hdr) + cv4->plen;

	    cv6->m = m6;
	    cv6->_ip._ip6 = mtod(m6, struct ip6_hdr *);
	    cv6->_payload._caddr = (caddr_t)cv6->_ip._ip6 + sizeof(struct ip6_hdr);
	    cv6->plen = cv4->plen;
	    cv6->poff = cv6->_payload._caddr - (caddr_t)cv6->_ip._ip6;
	}
    }
    else if (cv4->plen + sizeof(struct ip6_hdr) > MHLEN)
    {
	caddr_t	tcp4;
	caddr_t	tcp6;

	MGETHDR(m6, M_NOWAIT, MT_HEADER);
	ReturnEnobufs(m6);
	MCLGET(m6, M_NOWAIT);

	m6->m_data += 128;	/* make struct ether_header{} space. -- too many?	*/
	m6->m_pkthdr.len = m6->m_len   = sizeof(struct ip6_hdr) + cv4->plen;
	ip6 = mtod(m6, struct ip6_hdr *);

	tcp4 = (caddr_t)cv4->_payload._tcp4;
	tcp6 = (caddr_t)ip6 + sizeof(struct ip6_hdr);
	bcopy(tcp4, tcp6, cv4->plen);

	cv6->m = m6;
	cv6->_ip._ip6 = mtod(m6, struct ip6_hdr *);
	cv6->_payload._caddr = tcp6;
	cv6->plen = cv4->plen;
	cv6->poff = cv6->_payload._caddr - (caddr_t)cv6->_ip._ip6;
    }
    else
    {
	caddr_t	tcp4;
	caddr_t	tcp6;

	MGETHDR(m6, M_NOWAIT, MT_HEADER);
	if (m6 == NULL)
	{
	    errno = ENOBUFS;
	    return (NULL);
	}

	cv6->m = m6;
	ip6 = mtod(m6, struct ip6_hdr *);
	tcp4 = (caddr_t)cv4->_payload._tcp4;
	tcp6 = (caddr_t)ip6 + sizeof(struct ip6_hdr);
	bcopy(tcp4, tcp6, cv4->plen);

	m6->m_pkthdr.len
	    = m6->m_len
	    = sizeof(struct ip6_hdr) + cv4->plen;

	cv6->_ip._ip6 = mtod(m6, struct ip6_hdr *);
	cv6->_payload._caddr = (caddr_t)cv6->_ip._ip6 + sizeof(struct ip6_hdr);
	cv6->plen = cv4->plen;
	cv6->poff = cv6->_payload._caddr - (caddr_t)cv6->_ip._ip6;
    }

    cv6->ats = cv4->ats;

    ip4 = mtod(cv4->m, struct ip *);
    ip6->ip6_flow = 0;
    ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
    ip6->ip6_vfc |=  IPV6_VERSION;
    ip6->ip6_plen = htons(cv4->plen);
    ip6->ip6_nxt  = IPPROTO_TCP;
    ip6->ip6_hlim = ip4->ip_ttl -1;
    ip6->ip6_src  = pad->in6src;
    ip6->ip6_dst  = pad->in6dst;

    tcp6 = cv6->_payload._tcp6;
    tcp6->th_sport = pad->_sport;
    tcp6->th_dport = pad->_dport;

    return (m6);
}


/*
 *	Translating Form IPv6 To IPv4
 */

struct mbuf *
translatingIPv6To4(struct _cv *cv6, struct pAddr *pad)
{
    struct timeval	 atv;
    struct mbuf		*m4 = NULL;

    if (isDump(D_TRANSLATINGIPV6))
	natpt_logIp6(LOG_DEBUG, cv6->_ip._ip6);

    microtime(&atv);
    cv6->ats->tstamp = atv.tv_sec;

    switch (cv6->ip_payload)
    {
      case IPPROTO_ICMP:
	m4 = translatingICMPv6To4(cv6, pad);
	break;

      case IPPROTO_TCP:
	m4 = translatingTCPv6To4(cv6, pad);
	break;

      case IPPROTO_UDP:
	m4 = translatingUDPv6To4(cv6, pad);
	break;
    }

    if (m4)
    {
	int		 mlen;
	struct mbuf	*mm;
	struct ip	*ip4;

	ip4 = mtod(m4, struct ip *);
	ip4->ip_sum = 0;			/* Header checksum		*/
	ip4->ip_sum = in_cksum(m4, sizeof(struct ip));
	m4->m_pkthdr.rcvif = cv6->m->m_pkthdr.rcvif;

	for (mlen = 0, mm = m4; mm; mm = mm->m_next)
	{
	    mlen += mm->m_len;
	}

	m4->m_pkthdr.len = mlen;

	if (isDump(D_TRANSLATEDIPV4))
	    natpt_logIp4(LOG_DEBUG, ip4);
    }

    return (m4);
}


struct mbuf *
translatingICMPv6To4(struct _cv *cv6, struct pAddr *pad)
{
    struct _cv		 cv4;
    struct mbuf		*m4;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;
    struct icmp		*icmp4;
    struct icmp6_hdr	*icmp6;

    ip6 = mtod(cv6->m, struct ip6_hdr *);
    icmp6 = cv6->_payload._icmp6;

    {
	caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 icmp6len = icmp6end - (caddr_t)cv6->_payload._icmp6;

	MGETHDR(m4, M_NOWAIT, MT_HEADER);
	if (m4 == NULL)
	{
	    errno = ENOBUFS;
	    return (NULL);
	}
	if (MHLEN < (sizeof(struct ip) + icmp6len))
	    MCLGET(m4, M_NOWAIT);
    }

    cv4.m = m4;
    cv4._ip._ip4 = mtod(m4, struct ip *);
    cv4._payload._caddr = (caddr_t)cv4._ip._ip4 + sizeof(struct ip);

    ip4 = mtod(cv4.m,  struct ip *);
    icmp4 = cv4._payload._icmp4;

    ip4->ip_v	= IPVERSION;		/* IP version				*/
    ip4->ip_hl	= 5;			/* header length (no IPv4 option)	*/
    ip4->ip_tos = 0;			/* Type Of Service			*/
    ip4->ip_len = htons(ip6->ip6_plen);	/* Payload length			*/
    ip4->ip_id	= 0;			/* Identification			*/
    ip4->ip_off = 0;			/* flag and fragment offset		*/
    ip4->ip_ttl = ip6->ip6_hlim - 1;	/* Time To Live				*/
    ip4->ip_p	= cv6->ip_payload;	/* Final Payload			*/
    ip4->ip_src = pad->in4src;		/* source addresss			*/
    ip4->ip_dst = pad->in4dst;		/* destination address			*/

    switch (icmp6->icmp6_type)
    {
      case ICMP6_DST_UNREACH:
	tr_icmp6DstUnreach(cv6, &cv4);
	break;

      case ICMP6_PACKET_TOO_BIG:
	tr_icmp6PacketTooBig(cv6, &cv4);
	break;

      case ICMP6_TIME_EXCEEDED:
	tr_icmp6TimeExceed(cv6, &cv4);
	break;

      case ICMP6_PARAM_PROB:
	tr_icmp6ParamProb(cv6, &cv4);
	break;

      case ICMP6_ECHO_REQUEST:
	tr_icmp6EchoRequest(cv6, &cv4);
	break;

      case ICMP6_ECHO_REPLY:
	tr_icmp6EchoReply(cv6, &cv4);
	break;

      case MLD6_LISTENER_QUERY:
      case MLD6_LISTENER_REPORT:
      case MLD6_LISTENER_DONE:
	m_freem(m4);		/* Single hop message.	Silently drop.	*/
	return (NULL);

      default:
	m_freem(m4);		/* Silently drop.			*/
	return (NULL);
    }

    {
	int		 hlen;
	struct mbuf	*m4  = cv4.m;
	struct ip	*ip4 = cv4._ip._ip4;

	hlen = ip4->ip_hl << 2;
	m4->m_data += hlen;
	m4->m_len  -= hlen;
	icmp4->icmp_cksum = 0;
	icmp4->icmp_cksum = in_cksum(cv4.m, ip4->ip_len - hlen);
	m4->m_data -= hlen;
	m4->m_len  += hlen;
    }

    return (m4);
}


void
tr_icmp6DstUnreach(struct _cv *cv6, struct _cv *cv4)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp4->icmp_type = ICMP_UNREACH;
    icmp4->icmp_code = 0;
    icmp4->icmp_id   = icmp6->icmp6_id;
    icmp4->icmp_seq  = icmp6->icmp6_seq;

    switch (icmp6->icmp6_code)
    {
      case ICMP6_DST_UNREACH_NOROUTE:
	icmp4->icmp_code = ICMP_UNREACH_HOST;
	break;

      case ICMP6_DST_UNREACH_ADMIN:
	icmp4->icmp_code = ICMP_UNREACH_HOST_PROHIB;
	break;

      case ICMP6_DST_UNREACH_NOTNEIGHBOR:
	icmp4->icmp_code = ICMP_UNREACH_SRCFAIL;
	break;

      case ICMP6_DST_UNREACH_ADDR:
	icmp4->icmp_code = ICMP_UNREACH_HOST;
	break;

      case ICMP6_DST_UNREACH_NOPORT:
	icmp4->icmp_code = ICMP_UNREACH_PORT;
	break;
    }
}


void
tr_icmp6PacketTooBig(struct _cv *cv6, struct _cv *cv4)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp4->icmp_type = ICMP_UNREACH;
    icmp4->icmp_code = ICMP_UNREACH_NEEDFRAG;				/* do more	*/
    icmp4->icmp_id   = icmp6->icmp6_id;
    icmp4->icmp_seq  = icmp6->icmp6_seq;
}


void
tr_icmp6TimeExceed(struct _cv *cv6, struct _cv *cv4)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp4->icmp_type = ICMP_TIMXCEED;
    icmp4->icmp_code = icmp6->icmp6_code;		/* code unchanged.	*/
    icmp4->icmp_id   = icmp6->icmp6_id;
    icmp4->icmp_seq  = icmp6->icmp6_seq;
}


void
tr_icmp6ParamProb(struct _cv *cv6, struct _cv *cv4)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp4->icmp_type = ICMP_PARAMPROB;					/* do more	*/
    icmp4->icmp_code = 0;
    icmp4->icmp_id   = icmp6->icmp6_id;
    icmp4->icmp_seq  = icmp6->icmp6_seq;

    if (icmp6->icmp6_code == ICMP6_PARAMPROB_NEXTHEADER)
    {
	icmp4->icmp_type = ICMP_UNREACH;
	icmp4->icmp_code = ICMP_UNREACH_PROTOCOL;
    }
}


void
tr_icmp6EchoRequest(struct _cv *cv6, struct _cv *cv4)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp4->icmp_type = ICMP_ECHO;
    icmp4->icmp_code = 0;
    icmp4->icmp_id   = icmp6->icmp6_id;
    icmp4->icmp_seq  = icmp6->icmp6_seq;

    {
	int	dlen;
	struct ip	*ip4 = cv4->_ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;
	caddr_t		 icmp6off, icmp4off;
	caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 icmp6len = icmp6end - (caddr_t)cv6->_payload._icmp6;

	dlen = icmp6len - sizeof(struct icmp6_hdr);
	icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
	icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
	bcopy(icmp6off, icmp4off, dlen);

	ip4->ip_len = cv4->m->m_len = sizeof(struct ip) + ICMP_MINLEN + dlen;
    }
}


void
tr_icmp6EchoReply(struct _cv *cv6, struct _cv *cv4)
{
    struct icmp		*icmp4 = cv4->_payload._icmp4;
    struct icmp6_hdr	*icmp6 = cv6->_payload._icmp6;

    icmp4->icmp_type = ICMP_ECHOREPLY;
    icmp4->icmp_code = 0;
    icmp4->icmp_id   = icmp6->icmp6_id;
    icmp4->icmp_seq  = icmp6->icmp6_seq;

    {
	int	dlen;
	struct ip	*ip4 = cv4->_ip._ip4;
	struct ip6_hdr	*ip6 = cv6->_ip._ip6;
	caddr_t		 icmp6off, icmp4off;
	caddr_t		 icmp6end = (caddr_t)ip6 + cv6->m->m_pkthdr.len;
	int		 icmp6len = icmp6end - (caddr_t)cv6->_payload._icmp6;

	dlen = icmp6len - sizeof(struct icmp6_hdr);
	icmp6off = (caddr_t)(cv6->_payload._icmp6) + sizeof(struct icmp6_hdr);
	icmp4off = (caddr_t)(cv4->_payload._icmp4) + ICMP_MINLEN;
	bcopy(icmp6off, icmp4off, dlen);

	ip4->ip_len = cv4->m->m_len = sizeof(struct ip) + ICMP_MINLEN + dlen;
    }
}


struct mbuf *
translatingTCPv6To4(struct _cv *cv6, struct pAddr *pad)
{
    int			 cksumOrg;
    struct _cv		 cv4;
    struct mbuf		*m4;

    bzero(&cv4, sizeof(struct _cv));
    m4 = translatingTCPUDPv6To4(cv6, pad, &cv4);
    cv4.ip_p = cv4.ip_payload = IPPROTO_TCP;
    cksumOrg = ntohs(cv6->_payload._tcp6->th_sum);

    updateTcpStatus(cv6);
    adjustUpperLayerChecksum(IPPROTO_IPV6, IPPROTO_TCP, cv6, &cv4);

#ifdef recalculateTCP4Checksum
    _recalculateTCP4Checksum(&cv4);
#endif

    return (m4);
}


struct mbuf *
translatingUDPv6To4(struct _cv *cv6, struct pAddr *pad)
{
    struct _cv		 cv4;
    struct mbuf		*m4;

    bzero(&cv4, sizeof(struct _cv));
    m4 = translatingTCPUDPv6To4(cv6, pad, &cv4);
    cv4.ip_p = cv4.ip_payload = IPPROTO_UDP;

    adjustUpperLayerChecksum(IPPROTO_IPV6, IPPROTO_UDP, cv6, &cv4);

#if	1
    {
	int		 cksumAdj, cksumCks;
	int		 iphlen;
	struct ip	*ip4 = cv4._ip._ip4;
	struct ip	 save_ip;
	struct udpiphdr	*ui;

	cksumAdj = cv4._payload._tcp4->th_sum;

	ui = mtod(cv4.m, struct udpiphdr *);
	iphlen = ip4->ip_hl << 2;

	save_ip = *cv4._ip._ip4;
	bzero(ui, sizeof(struct udpiphdr));
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_len = htons(cv4.m->m_pkthdr.len - iphlen);
	ui->ui_src = save_ip.ip_src;
	ui->ui_dst = save_ip.ip_dst;

	ui->ui_sum = 0;
	ui->ui_sum = in_cksum(cv4.m, cv4.m->m_pkthdr.len);
	*cv4._ip._ip4 = save_ip;

	cksumCks = ui->ui_sum;
#if	0
	printf("translatingUDPv6To4: UDP6->UDP4: %04x, %04x %d\n",
	       cksumAdj, cksumCks, cv4.m->m_pkthdr.len);
#endif
    }
#endif

    return (m4);
}


struct mbuf *
translatingTCPUDPv6To4(struct _cv *cv6, struct pAddr *pad, struct _cv *cv4)
{
    struct mbuf		*m4;
    struct ip		*ip4;
    struct ip6_hdr	*ip6;
    struct tcphdr	*th;

    m4 = m_copym(cv6->m, 0, M_COPYALL, M_NOWAIT);
    ReturnEnobufs(m4);

    m4->m_data += sizeof(struct ip6_hdr) - sizeof(struct ip);
    m4->m_pkthdr.len = m4->m_len = sizeof(struct ip) + cv6->plen;

    cv4->m = m4;
    cv4->plen = cv6->plen;
    cv4->poff = sizeof(struct ip);
    cv4->_ip._ip4 = mtod(m4, struct ip *);
    cv4->_payload._caddr = (caddr_t)cv4->_ip._ip4 + sizeof(struct ip);

    cv4->ats = cv6->ats;

    ip4 = mtod(m4, struct ip *);
    ip6 = mtod(cv6->m, struct ip6_hdr *);
    ip4->ip_v	= IPVERSION;		/* IP version				*/
    ip4->ip_hl	= 5;			/* header length (no IPv4 option)	*/
    ip4->ip_tos = 0;			/* Type Of Service			*/
    ip4->ip_len = sizeof(struct ip) + ntohs(ip6->ip6_plen);
					/* Payload length			*/
    ip4->ip_id	= 0;			/* Identification			*/
    ip4->ip_off = 0;			/* flag and fragment offset		*/
    ip4->ip_ttl = ip6->ip6_hlim;	/* Time To Live				*/
    ip4->ip_p	= cv6->ip_payload;	/* Final Payload			*/
    ip4->ip_src = pad->in4src;		/* source addresss			*/
    ip4->ip_dst = pad->in4dst;		/* destination address			*/

    th = (struct tcphdr *)(ip4 + 1);
    th->th_sport = pad->_sport;
    th->th_dport = pad->_dport;

    return (m4);
}


/*
 * Itojun said 'code fragment in "#ifdef recalculateTCP4Checksum"
 * does not make sense to me'.  I agree, but
 * adjustUpperLayerChecksum() cause checksum error sometime but
 * not always, so I left its code.  After I fixed it, this code
 * will become vanish.
 */

static void
_recalculateTCP4Checksum(struct _cv *cv4)
{
    int			 cksumAdj, cksumCks;
    int			 iphlen;
    struct ip		*ip4 = cv4->_ip._ip4;
    struct ip		 save_ip;
    struct tcpiphdr	*ti;

    cksumAdj = cv4->_payload._tcp4->th_sum;

    ti = mtod(cv4->m, struct tcpiphdr *);
    iphlen = ip4->ip_hl << 2;

    save_ip = *cv4->_ip._ip4;
#ifdef ti_next
    ti->ti_next = ti->ti_prev = 0;
    ti->ti_x1 = 0;
#else
    bzero(ti->ti_x1, 9);
#endif
    ti->ti_pr = IPPROTO_TCP;
    ti->ti_len = htons(cv4->m->m_pkthdr.len - iphlen);
    ti->ti_src = save_ip.ip_src;
    ti->ti_dst = save_ip.ip_dst;

    ti->ti_sum = 0;
    ti->ti_sum = in_cksum(cv4->m, cv4->m->m_pkthdr.len);
    *cv4->_ip._ip4 = save_ip;

    cksumCks = ti->ti_sum;
#if	0
    printf("translatingTCPv6To4: TCP6->TCP4: %04x, %04x, %04x %d\n",
	   cksumOrg, cksumAdj, cksumCks, cv4->m->m_pkthdr.len);
#endif
}


/*
 *
 */

static int
updateTcpStatus(struct _cv *cv)
{
    struct _tSlot	*ats = cv->ats;
    struct _tcpstate	*ts;

    if (ats->ip_payload != IPPROTO_TCP)
	return (0);							/* XXX	*/

    if ((ts = ats->suit.tcp) == NULL)
    {
	MALLOC(ts, struct _tcpstate *, sizeof(struct _tcpstate), M_NATPT, M_NOWAIT);
	if (ts == NULL)
	{
	    return (0);							/* XXX	*/
	}

	bzero(ts, sizeof(struct _tcpstate));
	
	ts->_state = TCPS_CLOSED;
	ats->suit.tcp = ts;
    }

    ts->_state
	= _natpt_tcpfsm(ats->session, cv->inout, ts->_state, cv->_payload._tcp4->th_flags);

    return (0);
}


static	int
_natpt_tcpfsm(int session, int inout, u_short state, u_char flags)
{
    int		rv;

    if (flags & TH_RST)
	return (TCPS_CLOSED);

    if (session == NATPT_OUTBOUND)
	rv = _natpt_tcpfsmSessOut(inout, state, flags);
    else
	rv = _natpt_tcpfsmSessIn (inout, state, flags);

    return (rv);
}


/*
//##
//#------------------------------------------------------------------------
//#	_natpt_tcpfsmSessOut

	delta(start,		eps)			-> CLOSED
	delta(CLOSED,		TH_SYN & !TH_ACK)	-> SYN_SENT
	delta(SYN_SENT,	     in	TH_SYN &  TH_ACK)	-> SYN_RCVD
	delta(SYN_RCVD,		TH_ACK)			-> ESTABLISHED
	delta(ESTABLISHED,	TH_FIN)			-> FIN_WAIT_1
	delta(FIN_WAIT_1,    in	TH_FIN | TH_ACK)	-> TIME_WAIT
	delta(FIN_WAIT_1,    in	TH_ACK)			-> FIN_WAIT_2
	delta(FIN_WAIT_1,    in	TH_FIN)			-> CLOSING
	delta(FIN_WAIT_2,    in	TH_FIN)			-> TIME_WAIT
	delta(CLOSING,		TH_ACK)			-> TIME_WAIT
	delta(TIME_WAIT,	eps)			-> CLOSED

//#------------------------------------------------------------------------
*/

static	int
_natpt_tcpfsmSessOut(int inout, short state, u_char flags)
{
    int	    rv = state;

    switch (state)
    {
      case TCPS_CLOSED:
	if ((inout == NATPT_OUTBOUND)
	    && (((flags & TH_SYN) != 0)
		&& (flags & TH_ACK) == 0))
	    rv = TCPS_SYN_SENT;
	break;

      case TCPS_SYN_SENT:
	if ((inout == NATPT_INBOUND)
	    && (flags & (TH_SYN | TH_ACK)))
	    rv = TCPS_SYN_RECEIVED;
	break;

      case TCPS_SYN_RECEIVED:
	if ((inout == NATPT_OUTBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_ESTABLISHED;
	break;

      case TCPS_ESTABLISHED:
	if ((inout == NATPT_OUTBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_FIN_WAIT_1;
	break;

      case TCPS_FIN_WAIT_1:
	if (inout == NATPT_INBOUND)
	{
	    if (flags & (TH_FIN | TH_ACK))	rv = TCPS_TIME_WAIT;
	    else if (flags & TH_ACK)		rv = TCPS_FIN_WAIT_2;
	    else if (flags & TH_FIN)		rv = TCPS_CLOSING;
	}
	break;

      case TCPS_CLOSING:
	if ((inout == NATPT_OUTBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_TIME_WAIT;
	break;

      case TCPS_FIN_WAIT_2:
	if ((inout == NATPT_INBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_TIME_WAIT;
	break;
    }

    return (rv);
}


/*
//##
//#------------------------------------------------------------------------
//#	_natpt_tcpfsmSessIn

	delta(start,		eps)			-> CLOSED
	delta(CLOSED,		TH_SYN & !TH_ACK)	-> SYN_RCVD
	delta(SYN_RCVD,		TH_ACK)			-> ESTABLISHED
	delta(ESTABLISHED,   in	TH_FIN)			-> CLOSE_WAIT
	delta(ESTABLISHED,  out	TH_FIN)			-> FIN_WAIT_1
	delta(CLOSE_WAIT,   out	TH_FIN)			-> LAST_ACK
	delta(FIN_WAIT_1,	TH_FIN & TH_ACK)	-> TIME_WAIT
	delta(FIN_WAIT_1,	TH_FIN)			-> CLOSING
	delta(FIN_WAIT_1,	TH_ACK)			-> FIN_WAIT_2
	delta(CLOSING,		TH_ACK)			-> TIME_WAIT
	delta(LAST_ACK),	TH_ACK)			-> CLOSED
	delta(FIN_WAIT_2,	TH_FIN)			-> TIME_WAIT
	delta(TIME_WAIT,	eps)			-> CLOSED

//#------------------------------------------------------------------------
*/

static	int
_natpt_tcpfsmSessIn(int inout, short state, u_char flags)
{
    int		rv = state;

    switch (state)
    {
      case TCPS_CLOSED:
	if ((inout == NATPT_INBOUND)
	    && (((flags & TH_SYN) != 0)
		&& (flags & TH_ACK) == 0))
	    rv = TCPS_SYN_RECEIVED;
	break;

      case TCPS_SYN_RECEIVED:
	if ((inout == NATPT_INBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_ESTABLISHED;
	break;

      case TCPS_ESTABLISHED:
	if ((inout == NATPT_INBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_CLOSE_WAIT;
	if ((inout == NATPT_OUTBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_FIN_WAIT_1;
	break;

      case TCPS_CLOSE_WAIT:
	if ((inout == NATPT_OUTBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_LAST_ACK;
	break;

      case TCPS_FIN_WAIT_1:
	if (inout == NATPT_INBOUND)
	{
	    if (flags & (TH_FIN | TH_ACK))	rv = TCPS_TIME_WAIT;
	    else if (flags & TH_FIN)		rv = TCPS_CLOSING;
	    else if (flags & TH_ACK)		rv = TCPS_FIN_WAIT_2;
	}
	break;

      case TCPS_CLOSING:
	if ((inout == NATPT_INBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_TIME_WAIT;
	break;

      case TCPS_LAST_ACK:
	if ((inout == NATPT_INBOUND)
	    && (flags & TH_ACK))
	    rv = TCPS_CLOSED;
	break;

      case TCPS_FIN_WAIT_2:
	if ((inout == NATPT_INBOUND)
	    && (flags & TH_FIN))
	    rv = TCPS_TIME_WAIT;
	break;
    }

    return (rv);
}


/*
 *
 */

static void
adjustUpperLayerChecksum(int header, int proto, struct _cv *cv6, struct _cv *cv4)
{
    u_short		cksum;
    struct ipovly	ip4;
    struct ulc
    {
	struct in6_addr	ulc_src;
	struct in6_addr	ulc_dst;
	u_long		ulc_len;
	u_char		ulc_zero[3];
	u_char		ulc_nxt;
    }			ulc;

    bzero(&ulc, sizeof(struct ulc));
    bzero(&ip4, sizeof(struct ipovly));

    ulc.ulc_src = cv6->_ip._ip6->ip6_src;
    ulc.ulc_dst = cv6->_ip._ip6->ip6_dst;
    ulc.ulc_len = htonl(cv6->plen);
    ulc.ulc_nxt = cv6->ip_p;

    ip4.ih_src = cv4->_ip._ip4->ip_src;
    ip4.ih_dst = cv4->_ip._ip4->ip_dst;
    ip4.ih_len = htons(cv4->plen);
    ip4.ih_pr  = cv4->ip_p;

    switch (proto)
    {
      case IPPROTO_TCP:
	if (header == IPPROTO_IPV6)
	{
	    cksum = adjustChecksum(ntohs(cv6->_payload._tcp6->th_sum),
				   (u_char *)&ulc, sizeof(struct ulc),
				   (u_char *)&ip4, sizeof(struct ipovly));
	    cv4->_payload._tcp4->th_sum = htons(cksum);
	}
	else
	{
	    cksum = adjustChecksum(ntohs(cv4->_payload._tcp4->th_sum),
				   (u_char *)&ip4, sizeof(struct ipovly),
				   (u_char *)&ulc, sizeof(struct ulc));
	    cv6->_payload._tcp6->th_sum = htons(cksum);
	}
	break;

      case IPPROTO_UDP:
	if (header == IPPROTO_IPV6)
	{
	    cksum = adjustChecksum(ntohs(cv6->_payload._udp->uh_sum),
				   (u_char *)&ulc, sizeof(struct ulc),
				   (u_char *)&ip4, sizeof(struct ipovly));
	    cv4->_payload._udp->uh_sum = htons(cksum);
	}
	else
	{
	    cksum = adjustChecksum(ntohs(cv4->_payload._udp->uh_sum),
				   (u_char *)&ip4, sizeof(struct ipovly),
				   (u_char *)&ulc, sizeof(struct ulc));
	    cv6->_payload._udp->uh_sum = htons(cksum);
	}
	break;

      default:
    }
}


static int
adjustChecksum(int cksum, u_char *optr, int olen, u_char *nptr, int nlen)
{
    long	x, old, new;

    x = ~cksum & 0xffff;

    while (olen)
    {
	if (olen == 1)
	{
	    old = optr[0] * 256 + optr[1];
	    x -= old & 0xff00;
	    if ( x <= 0 ) { x--; x &= 0xffff; }
	    break;
	}	
	else
	{
	    old = optr[0] * 256 + optr[1];
	    x -= old & 0xffff;
	    if ( x <= 0 ) { x--; x &= 0xffff; }
	    optr += 2;
	    olen -= 2;
	}
    }

    while (nlen)
    {
	if (nlen == 1)	
	{
	    new = nptr[0] * 256 + nptr[1];
	    x += new & 0xff00;
	    if (x & 0x10000) { x++; x &= 0xffff; }
	    break;
	}
	else
	{
	    new = nptr[0] * 256 + nptr[1];
	    x += new & 0xffff;
	    if (x & 0x10000) { x++; x &= 0xffff; }
	    nptr += 2;
	    nlen -= 2;
	}
    }

    return (~x & 0xffff);
}
