/*	$KAME: natpt_log.c,v 1.6 2000/03/25 07:23:55 sumikawa Exp $	*/

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
 *
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/systm.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <netinet/ip6.h>

#include <netinet6/natpt_defs.h>
#include <netinet6/natpt_log.h>
#include <netinet6/natpt_var.h>


/*
 *
 */

static struct sockaddr	_natpt_dst = {2, PF_INET};
static struct sockaddr	_natpt_src = {2, PF_INET};


struct mbuf	*natpt_lbuf	__P((int type, int priorities, size_t size));


/*
 *
 */

void
natpt_logMsg(int priorities, void *item, size_t size)
{
    natpt_log(LOG_MSG, priorities, item, size);
}


void
natpt_logMBuf(int priorities, struct mbuf *m, char *msg)
{
    if (msg)
	natpt_log(LOG_MSG,  priorities, (void *)msg, strlen(msg)+1);
    natpt_log(LOG_MBUF, priorities, (void *)m->m_data, min(m->m_len, LBFSZ));
}


void
natpt_logIp4(int priorities, struct ip *ip4)
{
    natpt_log(LOG_IP4, priorities, (void *)ip4, sizeof(struct ip)+8);
}


void
natpt_logIp6(int priorities, struct ip6_hdr *ip6)
{
    natpt_log(LOG_IP6, priorities, (void *)ip6, sizeof(struct ip6_hdr)+8);
}


int
natpt_log(int type, int priorities, void *item, size_t size)
{
    struct sockproto	 proto;
    struct	mbuf	*m;
    struct	lbuf	*p;

    if ((m = natpt_lbuf(type, priorities, size)) == NULL)
	return (ENOBUFS);

    p = (struct lbuf *)m->m_data;
    m_copyback(m, sizeof(struct l_hdr), p->l_hdr.lh_size, (caddr_t)item);

    proto.sp_family = AF_INET;
    proto.sp_protocol = IPPROTO_AHIP;
    natpt_input(m, &proto, &_natpt_src, &_natpt_dst);

    return (0);
}


int
natpt_logIN6addr(int priorities, char *msg, struct in6_addr *sin6addr)
{
    int		size, msgsz;
    struct	mbuf	*m;
    struct	lbuf	*p;

    msgsz = strlen(msg)+1;
    size = sizeof(struct l_hdr) + IN6ADDRSZ + msgsz;

    m = natpt_lbuf(LOG_IN6ADDR, priorities, size);
    if (m == NULL)
	return (ENOBUFS);

    {
	struct sockproto	proto;

	p = (struct lbuf *)m->m_pktdat;
	bcopy(sin6addr, p->l_addr.in6addr, sizeof(struct in6_addr));
	strncpy(p->l_msg, msg, min(msgsz, MSGSZ-1));
	p->l_msg[MSGSZ-1] = '\0';

	proto.sp_family = AF_INET;
	proto.sp_protocol = IPPROTO_AHIP;
	natpt_input(m, &proto, &_natpt_src, &_natpt_dst);
    }

    return (0);
}


struct mbuf *
natpt_lbuf(int type, int priorities, size_t size)
{
    struct	mbuf	*m;
    struct	lbuf	*p;

    MGETHDR(m, M_NOWAIT, MT_DATA);
    if (m == NULL)
	return (NULL);

    m->m_pkthdr.len = m->m_len = MHLEN;
    m->m_pkthdr.rcvif = NULL;

    p = (struct lbuf *)m->m_data;
    p->l_hdr.lh_type = type;
    p->l_hdr.lh_pri  = priorities;
    p->l_hdr.lh_size = size;
    microtime((struct timeval *)&p->l_hdr.lh_sec);

    return (m);
}
