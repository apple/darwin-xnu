/*	$KAME: natpt_dispatch.c,v 1.9 2000/03/25 07:23:54 sumikawa Exp $	*/

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
#include <net/net_osdep.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_list.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

u_int		natpt_debug;
u_int		natpt_dump;

static	struct _cell	*ifBox;

struct ifnet	*natpt_ip6src;

struct in6_addr	 faith_prefix
			= {{{0x00000000, 0x00000000, 0x00000000, 0x00000000}}};
struct in6_addr	 faith_prefixmask
			= {{{0x00000000, 0x00000000, 0x00000000, 0x00000000}}};
struct in6_addr	 natpt_prefix
			= {{{0x00000000, 0x00000000, 0x00000000, 0x00000000}}};
struct in6_addr	 natpt_prefixmask
			= {{{0x00000000, 0x00000000, 0x00000000, 0x00000000}}};

int		 natpt_in4			__P((struct mbuf *, struct mbuf **));
int		 natpt_in6			__P((struct mbuf *, struct mbuf **));
int		 natpt_out4			__P((struct mbuf *, struct mbuf **));
int		 natpt_out6			__P((struct mbuf *, struct mbuf **));
int		 natpt_incomingIPv4		__P((int, struct mbuf *, struct mbuf **));
int		 natpt_outgoingIPv4		__P((int, struct mbuf *, struct mbuf **));
int		 natpt_incomingIPv6		__P((int, struct mbuf *, struct mbuf **));
int		 natpt_outgoingIPv6		__P((int, struct mbuf *, struct mbuf **));

int		 configCv4			__P((int, struct mbuf *, struct _cv *));
int		 configCv6			__P((int, struct mbuf *, struct _cv *));
caddr_t		 foundFinalPayload		__P((struct mbuf *, int *, int *));
int		 sanityCheckIn4			__P((struct _cv *));
int		 sanityCheckOut6		__P((struct _cv *));
int		 checkMTU			__P((struct _cv *));


#if defined(__FreeBSD__) && __FreeBSD__ >= 3
static	MALLOC_DEFINE(M_NATPT, "NATPT", "Network Address Translation - Protocol Translation");
#endif


/*
 *
 */

int
natpt_in4(struct mbuf *m4, struct mbuf **m6)
{
    Cell	    *p;
    struct ifnet    *ifnet;
    struct ifBox    *ifb;
    int		     rv = IPPROTO_IP;

    if (natpt_initialized == 0)
	return (IPPROTO_IP);			/* goto ours		*/

    if (isDump(D_DIVEIN4))
	natpt_logMBuf(LOG_DEBUG, m4, "dive into natpt_in4.");

    ifnet = m4->m_pkthdr.rcvif;
    for (p = ifBox; p; p = CDR(p))
    {
	ifb = (struct ifBox *)CAR(p);
	if (ifb->ifnet == ifnet)
	{
	    if (ifb->side == outSide)
		rv = natpt_incomingIPv4(NATPT_INBOUND,	m4, m6);
	    else
		rv = natpt_outgoingIPv4(NATPT_OUTBOUND, m4, m6);
	    goto    exit;
	}
    }

  exit:;
    return (rv);
}


int
natpt_in6(struct mbuf *m6, struct mbuf **m4)
{
    Cell	    *p;
    struct ifnet    *ifnet;
    struct ifBox    *ifb;
    struct ip6_hdr  *ip6;
    struct in6_addr  cand;
    int		     rv = IPPROTO_IP;

    if (natpt_initialized == 0)
	return (IPPROTO_IP);			/* goto mcastcheck	*/

    if (isDump(D_DIVEIN6))
	natpt_logMBuf(LOG_DEBUG, m6, "dive into natpt_in6.");

    ip6 = mtod(m6, struct ip6_hdr *);

    cand.s6_addr32[0] = ip6->ip6_dst.s6_addr32[0] & natpt_prefixmask.s6_addr32[0];
    cand.s6_addr32[1] = ip6->ip6_dst.s6_addr32[1] & natpt_prefixmask.s6_addr32[1];
    cand.s6_addr32[2] = ip6->ip6_dst.s6_addr32[2] & natpt_prefixmask.s6_addr32[2];
    cand.s6_addr32[3] = ip6->ip6_dst.s6_addr32[3] & natpt_prefixmask.s6_addr32[3];

    if ((cand.s6_addr32[0] != natpt_prefix.s6_addr32[0])
	|| (cand.s6_addr32[1] != natpt_prefix.s6_addr32[1])
	|| (cand.s6_addr32[2] != natpt_prefix.s6_addr32[2])
	|| (cand.s6_addr32[3] != natpt_prefix.s6_addr32[3]))
    {
	if (isDump(D_IN6REJECT))
	    natpt_logMBuf(LOG_DEBUG, m6, "v6 translation rejected.");

	return (IPPROTO_IP);			/* goto mcastcheck	*/
    }

    if (isDump(D_IN6ACCEPT))
	natpt_logMBuf(LOG_DEBUG, m6, "v6 translation start.");

    ifnet = m6->m_pkthdr.rcvif;
    for (p = ifBox; p; p = CDR(p))
    {
	ifb = (struct ifBox *)CAR(p);
	if (ifb->ifnet == ifnet)
	{
	    if (ifb->side == outSide)
		rv = natpt_incomingIPv6(NATPT_INBOUND,	m6, m4);
	    else
		rv = natpt_outgoingIPv6(NATPT_OUTBOUND, m6, m4);
	    goto    exit;
	}
    }

  exit:;
    return (rv);
}


int
natpt_out4(struct mbuf *m4, struct mbuf **m6)
{
    Cell	    *p;
    struct ifnet    *ifnet;
    struct ifBox    *ifb;
    int		     rv = IPPROTO_IP;

    ifnet = m4->m_pkthdr.rcvif;
    for (p = ifBox; p; p = CDR(p))
    {
	ifb = (struct ifBox *)CAR(p);
	if (ifb->ifnet == ifnet)
	{
	    if (ifb->side == outSide)
		rv = natpt_outgoingIPv4(NATPT_OUTBOUND, m4, m6);
	    else
		rv = natpt_incomingIPv4(NATPT_INBOUND,	m4, m6);
	    goto    exit;
	}
    }

  exit:;
    return (rv);
}



int
natpt_out6(struct mbuf *m6, struct mbuf **m4)
{
    Cell	    *p;
    struct ifnet    *ifnet;
    struct ifBox    *ifb;
    int		     rv = IPPROTO_IP;

    ifnet = m6->m_pkthdr.rcvif;
    for (p = ifBox; p; p = CDR(p))
    {
	ifb = (struct ifBox *)CAR(p);
	if (ifb->ifnet == ifnet)
	{
	    if (ifb->side == outSide)
		rv = natpt_outgoingIPv6(NATPT_OUTBOUND, m6, m4);
	    else
		rv = natpt_incomingIPv6(NATPT_INBOUND,	m6, m4);
	    goto    exit;
	}
    }

  exit:;
    return (rv);
}


int
natpt_incomingIPv4(int sess, struct mbuf *m4, struct mbuf **m6)
{
    int			 rv;
    struct _cv		 cv;
    struct _cSlot	*acs;
    struct _tSlot	*ats;

    if ((rv = configCv4(sess, m4, &cv)) == IPPROTO_MAX)
	return (IPPROTO_MAX);				/* discard this packet	*/

    if ((rv = sanityCheckIn4(&cv)) != IPPROTO_IPV4)
	return (IPPROTO_DONE);		/* discard this packet without free	*/

    cv.ats = lookingForIncomingV4Hash(&cv);
    if ((ats = checkTraceroute6Return(&cv)) != NULL)
	cv.ats = ats;

    if (cv.ats == NULL)
    {
	if ((acs = lookingForIncomingV4Rule(&cv)) == NULL)
	    return (IPPROTO_IP);			/* goto ours		*/

	if ((cv.ats = internIncomingV4Hash(sess, acs, &cv)) == NULL)
	    return (IPPROTO_IP);			/* goto ours		*/
    }

    if (checkMTU(&cv) != IPPROTO_IPV4)
	return (IPPROTO_DONE);		/* discard this packet without free	*/

#ifdef NATPT_NAT
    if (cv.ats->local.sa_family == AF_INET)
    {
	if ((*m6 = translatingIPv4To4(&cv, &cv.ats->local)) != NULL)
	    return (IPPROTO_IPV4);
    }
    else
#endif
    {
	if ((*m6 = translatingIPv4To6(&cv, &cv.ats->local)) != NULL)
	    return (IPPROTO_IPV6);
    }

    return (IPPROTO_MAX);				/* discard this packet	*/
}


int
natpt_outgoingIPv4(int sess, struct mbuf *m4, struct mbuf **m6)
{
    int			 rv;
    struct _cv		 cv;
    struct _cSlot	*acs;
    struct ip		*ip4;

    if ((rv = configCv4(sess, m4, &cv)) == IPPROTO_MAX)
	return (IPPROTO_MAX);				/* discard this packet	*/

    if ((cv.ats = lookingForOutgoingV4Hash(&cv)) == NULL)
    {
	if ((acs = lookingForOutgoingV4Rule(&cv)) == NULL)
	    return (IPPROTO_IP);			/* goto ours		*/

	ip4 = mtod(m4, struct ip *);
	if (ip4->ip_ttl <= IPTTLDEC)
	{
	    n_long	dest = 0;

	    icmp_error(m4, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
	    return (IPPROTO_MAX);			/* discard this packet	*/
	}
	
	if ((cv.ats = internOutgoingV4Hash(sess, acs, &cv)) == NULL)
	    return (IPPROTO_IP);			/* goto ours		*/
    }

#ifdef NATPT_NAT
    if (cv.ats->remote.sa_family == AF_INET)
    {
	if ((*m6 = translatingIPv4To4(&cv, &cv.ats->remote)) != NULL)
	    return (IPPROTO_IPV4);
    }
    else
#endif
    {
	if ((*m6 = translatingIPv4To6(&cv, &cv.ats->remote)) != NULL)
	    return (IPPROTO_IPV6);
    }

    return (IPPROTO_MAX);				/* discard this packet	*/
}


int
natpt_incomingIPv6(int sess, struct mbuf *m6, struct mbuf **m4)
{
    int			 rv;
    struct _cv		 cv;
    struct _cSlot	*acs;
    struct ip6_hdr	*ip6;

    rv = configCv6(sess, m6, &cv);
    if ((rv == IPPROTO_IP) || (rv == IPPROTO_MAX) || (rv == IPPROTO_DONE))
	return (rv);

    if ((cv.ats = lookingForIncomingV6Hash(&cv)) == NULL)
    {
	if ((acs = lookingForIncomingV6Rule(&cv)) == NULL)
	    return (IPPROTO_IP);			/* goto mcastcheck	*/

	ip6 = mtod(m6, struct ip6_hdr *);
	if (ip6->ip6_hlim <= IPV6_HLIMDEC)
	{
	    icmp6_error(m6, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
	    return (IPPROTO_MAX);			/* discard this packet	*/
	}

	if ((cv.ats = internIncomingV6Hash(sess, acs, &cv)) == NULL)
	    return (IPPROTO_IP);			/* goto mcastcheck	*/
    }

    if ((*m4 = translatingIPv6To4(&cv, &cv.ats->local)) != NULL)
	return (IPPROTO_IPV4);

    return (IPPROTO_MAX);				/* discard this packet	*/
}


int
natpt_outgoingIPv6(int sess, struct mbuf *m6, struct mbuf **m4)
{
    int			 rv;
    struct _cv		 cv6;
    struct _cSlot	*acs;

    rv = configCv6(sess, m6, &cv6);
    if ((rv == IPPROTO_IP) || (rv == IPPROTO_MAX) || (rv == IPPROTO_DONE))
	return (rv);

    if ((rv = sanityCheckOut6(&cv6)) != IPPROTO_IPV6)
	return (IPPROTO_DONE);				/* discard this packet	*/

    if (isDump(D_PEEKOUTGOINGV6))
	natpt_logIp6(LOG_DEBUG, cv6._ip._ip6);

    if ((cv6.ats = lookingForOutgoingV6Hash(&cv6)) == NULL)
    {
	if ((acs = lookingForOutgoingV6Rule(&cv6)) == NULL)
	    return (IPPROTO_IP);			/* goto mcastcheck	*/

	if ((cv6.ats = internOutgoingV6Hash(sess, acs, &cv6)) == NULL)
	    return (IPPROTO_IP);			/* goto mcastcheck	*/
    }

    if ((*m4 = translatingIPv6To4(&cv6, &cv6.ats->remote)) != NULL)
	return (IPPROTO_IPV4);

    return (IPPROTO_MAX);				/* discard this packet	*/
}


int
configCv4(int sess, struct mbuf *m, struct _cv *cv)
{
    struct ip	*ip = mtod(m, struct ip *);

    bzero(cv, sizeof(struct _cv));
    cv->ip_p = ip->ip_p;
    cv->m = m;
    cv->_ip._ip4 = ip;
    cv->inout  = sess;

    switch (ip->ip_p)
    {
      case IPPROTO_ICMP:
      case IPPROTO_TCP:
      case IPPROTO_UDP:
	cv->ip_payload = ip->ip_p;
	cv->_payload._caddr = (caddr_t)((u_long *)ip + ip->ip_hl);
	cv->poff = cv->_payload._caddr - (caddr_t)cv->_ip._ip4;
	cv->plen = (caddr_t)m->m_data + m->m_len - cv->_payload._caddr;
	return (ip->ip_p);
    }

    return (IPPROTO_MAX);
}


int
configCv6(int sess, struct mbuf *m, struct _cv *cv)
{
    int			 proto;
    int			 offset;
    caddr_t		 tcpudp;

    bzero(cv, sizeof(struct _cv));
    cv->m = m;
    cv->_ip._ip6 = mtod(m, struct ip6_hdr *);
    cv->inout  = sess;

    if ((tcpudp = foundFinalPayload(m, &proto, &offset)))
    {
	switch (proto)
	{
	  case IPPROTO_ICMP:
	  case IPPROTO_ICMPV6:
	  case IPPROTO_TCP:
	  case IPPROTO_UDP:
	    cv->ip_p = proto;
	    cv->ip_payload = proto;
	    if (proto == IPPROTO_ICMPV6)
		cv->ip_payload = IPPROTO_ICMP;
	    cv->_payload._caddr = tcpudp;	
	    cv->poff = offset;
	    cv->plen = (caddr_t)m->m_data + m->m_len - cv->_payload._caddr;
	    return (proto);
	}
    }

    return (proto);
}


caddr_t
foundFinalPayload(struct mbuf *m, int *proto, int *offset)
{
    int			 nxt;
    int			 off;
    struct ip6_hdr	*ip6;
    struct ip6_ext	*ip6ext;

    ip6 = mtod(m, struct ip6_hdr *);
    nxt = ip6->ip6_nxt;
    off = sizeof(struct ip6_hdr);
    ip6ext = (struct ip6_ext *)((struct ip6_hdr *)(ip6 + 1));
    while (nxt != IPPROTO_NONE && off + sizeof(*ip6ext) < m->m_len)
    {
	switch (nxt)
	{
	  case IPPROTO_HOPOPTS:
	  case IPPROTO_ROUTING:
#if 0
	  case IPPROTO_FRAGMENT:
#endif
	  case IPPROTO_DSTOPTS:
	    nxt = ip6ext->ip6e_nxt;
	    off += ip6ext->ip6e_len;
	    ip6ext = (struct ip6_ext *)(((caddr_t)ip6ext) + ip6ext->ip6e_len);
	    break;

	  case IPPROTO_ICMPV6:
	  case IPPROTO_TCP:
	  case IPPROTO_UDP:
	    *proto = nxt;
	    *offset = off;
	    return ((caddr_t)ip6ext);

	  default:
	    *proto = IPPROTO_IP;			/* goto mcastcheck	*/
	    *offset = off;
	    return (NULL);
	}
    }

    *proto = IPPROTO_IP;				/* goto mcastcheck	*/
    *offset = off;
    return (NULL);
}


int
sanityCheckIn4(struct _cv *cv4)
{
    struct mbuf	*m4  = cv4->m;
    struct ip	*ip4 = mtod(m4, struct ip *);

    if (ip4->ip_ttl <= IPTTLDEC)
    {
	n_long	dest = 0;

	icmp_error(m4, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
	return (IPPROTO_DONE);		/* discard this packet without free	*/
    }

    return (IPPROTO_IPV4);
}


int
sanityCheckOut6(struct _cv *cv6)
{
    struct mbuf		*m6 = cv6->m;
    struct ip6_hdr	*ip6 = mtod(m6, struct ip6_hdr *);

    if (ip6->ip6_hlim <= IPV6_HLIMDEC)
    {
	icmp6_error(m6, ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT, 0);
	return (IPPROTO_DONE);			/* discard this packet	*/
    }

    return (IPPROTO_IPV6);
}


int
checkMTU(struct _cv *cv4)
{
    int		 mmtu;
    struct mbuf	*m4  = cv4->m;
    struct ip	*ip4 = mtod(m4, struct ip *);

    mmtu = IPV6_MMTU - sizeof(struct ip6_hdr) - sizeof(struct ip6_frag);
						/* This should be 1232[byte]	*/

    if ((m4->m_flags & M_PKTHDR)
	&& (m4->m_pkthdr.len >= mmtu))
    {
	if (ip4->ip_off & IP_DF)
	{
	    n_long		dest = 0;
	    struct ifnet	destif;

	    bzero(&destif, sizeof(struct ifnet));
	    destif.if_mtu = mmtu;

#ifdef fixSuMiReICMPBug
	    ip4->ip_dst.s_addr = IPDST;					/* XXX	*/
#endif

	    icmp_error(m4, ICMP_UNREACH, ICMP_UNREACH_NEEDFRAG, dest, &destif);
	    return (IPPROTO_DONE);	/* discard this packet without free	*/
	}
	
	cv4->flags |= NATPT_NEEDFRAGMENT;	/* fragment, then translate	*/
    }

    return (IPPROTO_IPV4);
}


/*
 *
 */


struct ifBox *
natpt_asIfBox(char *ifName)
{
    Cell	*p;

    for (p = ifBox; p; p = CDR(p))
    {
      if (strcmp(ifName, ((struct ifBox *)CAR(p))->ifName) == SAME)
	return ((struct ifBox *)CAR(p));
    }

    return (NULL);
}


struct ifBox *
natpt_setIfBox(char *ifName)
{
    struct ifnet	*p;
    struct ifBox	*q;
    char		 Wow[IFNAMSIZ];

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
    for (p = ifnet; p; p = p->if_next)
#else
    for (p = TAILQ_FIRST(&ifnet); p; p = TAILQ_NEXT(p, if_list))
#endif
    {
#ifdef __NetBSD__
	sprintf(Wow, "%s%c",  p->if_xname, '\0');
#else
	sprintf(Wow, "%s%d%c", p->if_name, p->if_unit, '\0');
#endif
	if (strcmp(ifName, Wow) != SAME)
	    continue;

	natpt_ip6src = p;

	MALLOC(q, struct ifBox *, sizeof(struct ifBox), M_NATPT, M_WAITOK);
	bzero(q, sizeof(struct ifBox));

	q->ifnet = p;
#ifdef __NetBSD__
	sprintf(q->ifName, "%s%c",  p->if_xname, '\0');
#else
	sprintf(q->ifName, "%s%d%c", p->if_name, p->if_unit, '\0');
#endif

	LST_hookup_list((Cell**)&ifBox, q);
	return (q);
    }
    return (NULL);
}


/*
 *
 */

void
natpt_debugProbe()
{
    printf("DebugProbe");
}


void
natpt_assert(const char *file, int line, const char *failedexpr)
{
    (void)printf("natpt assertion \"%s\" failed: file \"%s\", line %d\n",
		 failedexpr, file, line);
    panic("natpt assertion");
    /* NOTREACHED */
}


/*
 *
 */

void
natpt_initialize()
{
    struct ifnet	*ifn;
    struct ifaddr	*ifa;
    struct ifBox	*ibox;

    if (natpt_initialized)
	return;

    natpt_initialized = 1;

#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
    for (ifn = ifnet; ifn; ifn = ifn->if_next)
#else
    for (ifn = TAILQ_FIRST(&ifnet); ifn; ifn = TAILQ_NEXT(ifn, if_list))
#endif
    {
#if defined(__bsdi__) || (defined(__FreeBSD__) && __FreeBSD__ < 3)
	for (ifa = ifn->if_addrlist; ifa; ifa = ifa->ifa_next)
#else
	for (ifa = ifn->if_addrlist.tqh_first; ifa;
	     ifa = ifa->ifa_list.tqe_next)
#endif
	{
	    if (((ifa->ifa_addr->sa_family) == AF_INET)
		|| ((ifa->ifa_addr->sa_family) == AF_INET6))
	    {
		MALLOC(ibox, struct ifBox *, sizeof(struct ifBox), M_TEMP, M_WAITOK);
#ifdef __NetBSD__
		sprintf(ibox->ifName, "%s",  ifn->if_xname);
#else
		sprintf(ibox->ifName, "%s%d", ifn->if_name, ifn->if_unit);
#endif
		ibox->ifnet = ifn;
		ibox->side = NULL;
		LST_hookup_list(&ifBox, ibox);
		goto nextif;
	    }
	}
      nextif:
    }
}
