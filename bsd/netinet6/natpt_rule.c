/*	$KAME: natpt_rule.c,v 1.9 2000/03/25 07:23:56 sumikawa Exp $	*/

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

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <netinet/ip6.h>
#if (defined(__FreeBSD__) && __FreeBSD__ < 3) || defined(__bsdi__)
#include <netinet6/tcp6.h>
#endif

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_list.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_soctl.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

Cell		*natptStatic;		/* list of struct _cSlot	*/
Cell		*natptDynamic;		/* list of struct _cSlot	*/
Cell		*natptFaith;		/* list of struct _cSlot	*/

int		 matchIn4addr		__P((struct _cv *, struct pAddr *));
int		 matchIn6addr		__P((struct _cv *, struct pAddr *));
static void	 _flushPtrRules		__P((struct _cell **));


extern	struct in6_addr	 faith_prefix;
extern	struct in6_addr	 faith_prefixmask;
extern	struct in6_addr	 natpt_prefix;
extern	struct in6_addr	 natpt_prefixmask;

extern	void	in4_len2mask __P((struct in_addr *, int));
extern	void	in6_len2mask __P((struct in6_addr *, int));


/*
 *
 */

struct _cSlot	*
lookingForIncomingV4Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = natptStatic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if ((acs->dir == NATPT_INBOUND)
	    && ((acs->proto == 0)
		|| (acs->proto == cv->ip_payload))
	    && (matchIn4addr(cv, &acs->remote) != 0))
	    return (acs);
    }

    for (p = natptDynamic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if ((acs->dir == NATPT_INBOUND)
	    && ((acs->proto == 0)
		|| (acs->proto == cv->ip_payload))
	    && (matchIn4addr(cv, &acs->remote) != 0))
	    return (acs);
    }

    return (NULL);
}


struct _cSlot	*
lookingForOutgoingV4Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = natptStatic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);

	if ((acs->dir == NATPT_OUTBOUND)
	    && (matchIn4addr(cv, &acs->local) != 0))
	    return (acs);
    }

    for (p = natptDynamic; p; p = CDR(p))
    {
	acs = (struct _cSlot *)CAR(p);
	if ((acs->dir == NATPT_OUTBOUND)
	    && (matchIn4addr(cv, &acs->local) != 0))
	    return (acs);
    }

    return (NULL);
}


struct _cSlot	*
lookingForIncomingV6Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = natptStatic; p; p = CDR(p))
    {	
	acs = (struct _cSlot *)CAR(p);
	if ((acs->dir == NATPT_INBOUND)
	    && (matchIn6addr(cv, &acs->remote)) != 0)
	    return (acs);
    }

    for (p = natptDynamic; p; p = CDR(p))
    {	
	acs = (struct _cSlot *)CAR(p);
	if ((acs->dir == NATPT_INBOUND)
	    && (matchIn6addr(cv, &acs->remote)) != 0)
	    return (acs);
    }

    return (NULL);
}


struct _cSlot	*
lookingForOutgoingV6Rule(struct _cv *cv)
{
    Cell		*p;
    struct _cSlot	*acs;

    for (p = natptStatic; p; p = CDR(p))
    {	
	acs = (struct _cSlot *)CAR(p);
	if ((acs->dir == NATPT_OUTBOUND)
	    && ((acs->proto == 0)
		|| (acs->proto == cv->ip_payload))
	    && (matchIn6addr(cv, &acs->local)) != 0)
	    return (acs);
    }

    for (p = natptDynamic; p; p = CDR(p))
    {	
	acs = (struct _cSlot *)CAR(p);
	if ((acs->dir == NATPT_OUTBOUND)
	    && ((acs->proto == 0)
		|| (acs->proto == cv->ip_payload))
	    && (matchIn6addr(cv, &acs->local)) != 0)
	    return (acs);
    }

    for (p = natptFaith; p; p = CDR(p))
    {	
	acs = (struct _cSlot *)CAR(p);
	if ((acs->dir == NATPT_OUTBOUND)
	    && ((acs->proto == 0)
		|| (acs->proto == cv->ip_payload))
	    && (matchIn6addr(cv, &acs->local)) != 0)
	    return (acs);
    }

    return (NULL);
}


int
matchIn4addr(struct _cv *cv4, struct pAddr *from)
{
    struct in_addr	in4from = cv4->_ip._ip4->ip_src;
    struct in_addr	in4masked;

    if (from->sa_family != AF_INET)
	return (0);

    switch (from->ad.type)
    {
      case ADDR_ANY:						goto port;

      case ADDR_SINGLE:
	if (in4from.s_addr == from->in4Addr.s_addr)		goto port;
	return (0);

      case ADDR_MASK:
	in4masked.s_addr = in4from.s_addr & from->in4Mask.s_addr;
	if (in4masked.s_addr == from->in4Addr.s_addr)		goto port;
	return (0);

      case ADDR_RANGE:
	if ((in4from.s_addr >= from->in4RangeStart.s_addr)
	    && (in4from.s_addr <= from->in4RangeEnd.s_addr))	goto port;
	return (0);

      default:
	return (0);
    }

port:;
    if ((cv4->ip_payload != IPPROTO_UDP)
	&& (cv4->ip_payload != IPPROTO_TCP))			return (1);

    if (from->_port0 == 0)					return (1);

    if (from->_port1 == 0)
    {
	if ((cv4->_payload._tcp4->th_dport == from->_port0))	return (1);
    }
    else
    {
	u_short	dport = ntohs(cv4->_payload._tcp4->th_dport);
	u_short	port0 = ntohs(from->_port0);
	u_short	port1 = ntohs(from->_port1);

	if ((dport >= port0)
	    && (dport <= port1))				return (1);
    }

    return (0);
}


int
matchIn6addr(struct _cv *cv6, struct pAddr *from)
{
    struct in6_addr		*in6from = &cv6->_ip._ip6->ip6_src;
    struct in6_addr		 in6masked;

    if (from->sa_family != AF_INET6)
	return (0);

    switch (from->ad.type)
    {
      case ADDR_ANY:						goto port;

      case ADDR_SINGLE:
	if (IN6_ARE_ADDR_EQUAL(in6from, &from->in6Addr))	goto port;
	return (0);

      case ADDR_MASK:
	in6masked.s6_addr32[0] = in6from->s6_addr32[0] & from->in6Mask.s6_addr32[0];
	in6masked.s6_addr32[1] = in6from->s6_addr32[1] & from->in6Mask.s6_addr32[1];
	in6masked.s6_addr32[2] = in6from->s6_addr32[2] & from->in6Mask.s6_addr32[2];
	in6masked.s6_addr32[3] = in6from->s6_addr32[3] & from->in6Mask.s6_addr32[3];
	
	if (IN6_ARE_ADDR_EQUAL(&in6masked, &from->in6Addr))	goto port;
	return (0);

      default:
	return (0);
    }

port:;
    if ((cv6->ip_payload != IPPROTO_UDP)
	&& (cv6->ip_payload != IPPROTO_TCP))			return (1);

    if (from->_port0 == 0)					return (1);

    if (from->_port1 == 0)
    {
	if (cv6->_payload._tcp6->th_dport == from->_port0)	return (1);
    }
    else
    {
	u_short	dport = ntohs(cv6->_payload._tcp6->th_dport);
#ifdef UnusedVariable
	u_short	port0 = ntohs(from->_port0);
	u_short	port1 = ntohs(from->_port1);
#endif

	if ((dport >= from->_port0)
	    && (dport <= from->_port1))				return (1);
    }


    return (0);
}
/*
 *
 */

int
_natptEnableTrans(caddr_t addr)
{
    char	Wow[64];

    sprintf(Wow, "map enable");
    natpt_logMsg(LOG_INFO, Wow, strlen(Wow));

    ip6_protocol_tr = 1;
    return (0);
}


int
_natptDisableTrans(caddr_t addr)
{
    char	Wow[64];

    sprintf(Wow, "map disable");
    natpt_logMsg(LOG_INFO, Wow, strlen(Wow));

    ip6_protocol_tr = 0;
    return (0);
}


int
_natptSetRule(caddr_t addr)
{
    struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;
    struct _cSlot	*cst;
    Cell		**anchor;

#if	0
    if (((ifb = natpt_asIfBox(mbx->m_ifName)) == NULL)
      && ((ifb = natpt_setIfBox(mbx->m_ifName)) == NULL))
     return (ENXIO);
#endif

    if (mbx->flags == NATPT_FAITH)
	return (_natptSetFaithRule(addr));

    MALLOC(cst, struct _cSlot *, sizeof(struct _cSlot), M_TEMP, M_WAITOK);
    copyin(mbx->freight, cst, sizeof(struct _cSlot));

    {
	struct pAddr	*from;

	from = &cst->local;
	if (cst->dir == NATPT_INBOUND)
	    from = &cst->remote;

	if (from->sa_family == AF_INET)
	{
	    in4_len2mask(&from->in4Mask, cst->prefix);
	    from->in4Addr.s_addr &= from->in4Mask.s_addr;
	}
	else
	{
	    in6_len2mask(&from->in6Mask, cst->prefix);
	    from->in6Addr.s6_addr32[0]
		= from->in6Addr.s6_addr32[0] & from->in6Mask.s6_addr32[0];
	    from->in6Addr.s6_addr32[1]
		= from->in6Addr.s6_addr32[1] & from->in6Mask.s6_addr32[1];
	    from->in6Addr.s6_addr32[2]
		= from->in6Addr.s6_addr32[2] & from->in6Mask.s6_addr32[2];
	    from->in6Addr.s6_addr32[3]
		= from->in6Addr.s6_addr32[3] & from->in6Mask.s6_addr32[3];
	}
    }

    natpt_log(LOG_CSLOT, LOG_DEBUG, (void *)cst, sizeof(struct _cSlot));

    anchor = &natptStatic;
    if (cst->flags == NATPT_DYNAMIC)
	anchor = &natptDynamic;

    LST_hookup_list(anchor, cst);

    return (0);
}


int
_natptSetFaithRule(caddr_t addr)
{
    struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;
    struct _cSlot	*cst;

    MALLOC(cst, struct _cSlot *, sizeof(struct _cSlot), M_TEMP, M_WAITOK);
    copyin(mbx->freight, cst, sizeof(struct _cSlot));

    LST_hookup_list(&natptFaith, cst);

    return (0);
}


int
_natptFlushRule(caddr_t addr)
{
    struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;

    if (mbx->flags & FLUSH_STATIC)
	_flushPtrRules(&natptStatic);

    if (mbx->flags & FLUSH_DYNAMIC)
	_flushPtrRules(&natptDynamic);

    return (0);
}


int
_natptSetPrefix(caddr_t addr)
{
    struct natpt_msgBox	*mbx = (struct natpt_msgBox *)addr;
    struct pAddr	*load;

    MALLOC(load, struct pAddr *, sizeof(struct pAddr), M_TEMP, M_WAITOK);
    copyin(mbx->freight, load, SZSIN6 * 2);

    if (mbx->flags & PREFIX_FAITH)
    {
	faith_prefix	 =  load->addr[0].in6;
	faith_prefixmask =  load->addr[1].in6;
	
	natpt_logIN6addr(LOG_INFO, "FAITH prefix: ", &faith_prefix);
	natpt_logIN6addr(LOG_INFO, "FAITH prefixmask: ", &faith_prefixmask);
    }
    else if (mbx->flags & PREFIX_NATPT)
    {
	natpt_prefix	 =  load->addr[0].in6;
	natpt_prefixmask =  load->addr[1].in6;

	natpt_logIN6addr(LOG_INFO, "NATPT prefix: ", &natpt_prefix);
	natpt_logIN6addr(LOG_INFO, "NATPT prefixmask: ", &natpt_prefixmask);
    }

    FREE(load, M_TEMP);
    return (0);
}


int
_natptBreak()
{
    printf("break");

    return (0);
}


/*
 *
 */

static void
_flushPtrRules(struct _cell **anchor)
{
    struct _cell	*p0, *p1;
    struct _cSlot	*cslt;

    p0 = *anchor;
    while (p0)
    {
	p1 = p0;
	p0 = CDR(p0);

	cslt = (struct _cSlot *)CAR(p1);
	FREE(cslt, M_TEMP);
	LST_free(p1);
    }

    *anchor = NULL;
}
