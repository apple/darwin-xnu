/*	$KAME: natpt_var.h,v 1.6 2000/03/25 07:23:57 sumikawa Exp $	*/

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


extern int		 natpt_initialized;
extern int		 ip6_protocol_tr;
extern u_int		 natpt_debug;
extern u_int		 natpt_dump;

extern struct ifnet	*natpt_ip6src;

/*	natpt_log.c		*/
void		 natpt_logMsg			__P((int, void *, size_t));
void		 natpt_logMBuf			__P((int, struct mbuf *, char *));
void		 natpt_logIp4			__P((int, struct ip *));
void		 natpt_logIp6			__P((int, struct ip6_hdr *));
int		 natpt_log			__P((int, int, void *, size_t));
int		 natpt_logIN6addr		__P((int, char *, struct in6_addr *));

void		 natpt_debugProbe		__P((void));
void		 natpt_assert			__P((const char *, int, const char *));
void		 natpt_initialize		__P((void));


/*	natpt_rule.c		*/
struct _cSlot	*lookingForIncomingV4Rule	__P((struct _cv *));
struct _cSlot	*lookingForOutgoingV4Rule	__P((struct _cv *));
struct _cSlot	*lookingForIncomingV6Rule	__P((struct _cv *));
struct _cSlot	*lookingForOutgoingV6Rule	__P((struct _cv *));
int		 _natptEnableTrans		__P((caddr_t));
int		 _natptDisableTrans		__P((caddr_t));
int		 _natptSetRule			__P((caddr_t));
int		 _natptSetFaithRule		__P((caddr_t));
int		 _natptFlushRule		__P((caddr_t));
int		 _natptSetPrefix		__P((caddr_t));

int		 _natptBreak			__P((void));


struct ifBox	*natpt_asIfBox			__P((char *));
struct ifBox	*natpt_setIfBox			__P((char *));


/*	natpt_trans.c		*/
#ifdef NATPT_NAT
struct mbuf	*translatingIPv4To4		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingICMPv4To4		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingTCPv4To4		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingUDPv4To4		__P((struct _cv *, struct pAddr *));
#endif

struct mbuf	*translatingIPv4To6		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingICMPv4To6		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingTCPv4To6		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingUDPv4To6		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingTCPUDPv4To6		__P((struct _cv *, struct pAddr *, struct _cv *));

struct mbuf	*translatingIPv6To4		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingICMPv6To4		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingTCPv6To4		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingUDPv6To4		__P((struct _cv *, struct pAddr *));
struct mbuf	*translatingTCPUDPv6To4		__P((struct _cv *, struct pAddr *, struct _cv *));


/*	natpt_tslot.c		*/
struct _tSlot	*lookingForOutgoingV4Hash	__P((struct _cv *));
struct _tSlot	*lookingForIncomingV4Hash	__P((struct _cv *));
struct _tSlot	*lookingForOutgoingV6Hash	__P((struct _cv *));
struct _tSlot	*lookingForIncomingV6Hash	__P((struct _cv *));
struct _tSlot	*internIncomingV4Hash		__P((int, struct _cSlot *, struct _cv *));
struct _tSlot	*internOutgoingV4Hash		__P((int, struct _cSlot *, struct _cv *));
struct _tSlot	*internIncomingV6Hash		__P((int, struct _cSlot *, struct _cv *));
struct _tSlot	*internOutgoingV6Hash		__P((int, struct _cSlot *, struct _cv *));

struct _tSlot	*checkTraceroute6Return		__P((struct _cv *));

void		 init_hash			__P((void));
void		 init_tslot			__P((void));


/*	natpt_usrreq.c		*/
void		 natpt_input	__P((struct mbuf *, struct sockproto *,
				     struct sockaddr *src, struct sockaddr *dst));

