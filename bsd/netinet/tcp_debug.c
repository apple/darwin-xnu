/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)tcp_debug.c	8.1 (Berkeley) 6/10/93
 */

#if ISFB31
#include "opt_inet.h"
#include "opt_tcpdebug.h"
#endif

#ifndef INET
#error The option TCPDEBUG requires option INET.
#endif

#if TCPDEBUG
/* load symbolic names */
#define PRUREQUESTS
#define TCPSTATES
#define	TCPTIMERS
#define	TANAMES
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/protosw.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>

#if TCPDEBUG
static int	tcpconsdebug = 0;
#endif

static struct tcp_debug tcp_debug[TCP_NDEBUG];
static int	tcp_debx;

/*
 * Tcp debug routines
 */
void
tcp_trace(act, ostate, tp, ip, th, req)
	short act, ostate;
	struct tcpcb *tp;
#if INET6
	void *ip;
#else
	struct ip *ip;
#endif
	struct tcphdr *th;
	int req;
{
#if INET6
	int isipv6 = (ip != NULL && ((struct ip *)ip)->ip_v == 6) ? 1 : 0;
#endif /* INET6 */
	tcp_seq seq, ack;
	int len, flags;
	struct tcp_debug *td = &tcp_debug[tcp_debx++];

	if (tcp_debx == TCP_NDEBUG)
		tcp_debx = 0;
	td->td_time = iptime();
	td->td_act = act;
	td->td_ostate = ostate;
	td->td_tcb = (caddr_t)tp;
	if (tp)
		td->td_cb = *tp;
	else
		bzero((caddr_t)&td->td_cb, sizeof (*tp));
	if (ip) {
#if INET6
		if (isipv6)
			td->td_ip6 = *(struct ip6_hdr *)ip;
		else
			td->td_ip = *(struct ip *)ip;
#else /* INET6 */
		td->td_ip = *ip;
#endif /* INET6 */
	} else
#if INET6
		bzero((caddr_t)&td->_td_ipx, sizeof (td->_td_ipx));
#else /* INET6 */
		bzero((caddr_t)&td->td_ip, sizeof (*ip));
#endif /* INET6 */
	if (th)
		td->td_th = *th;

	td->td_req = req;
#if TCPDEBUG
	if (tcpconsdebug == 0)
		return;
	if (tp)
		printf("%p %s:", tp, tcpstates[ostate]);
	else
		printf("???????? ");
	printf("%s ", tanames[act]);
	switch (act) {

	case TA_INPUT:
	case TA_OUTPUT:
	case TA_DROP:
		if (ip == 0)
			break;
#if INET6
		if (isipv6) {
			len = ((struct ip6_hdr *)ip)->ip6_plen;
		} else {
			len = ((struct ip *)ip)->ip_len;
		}
#else /* INET6 */
		len = ip->ip_len;
#endif /* INET6 */
		seq = th->th_seq;
		ack = th->th_ack;
		if (act == TA_OUTPUT) {
			seq = ntohl(seq);
			ack = ntohl(ack);
			len = ntohs((u_short)len);
		}
		if (act == TA_OUTPUT)
			len -= sizeof (struct tcphdr);
		if (len)
			printf("[%x..%x)", seq, seq+len);
		else
			printf("%x", seq);
		printf("@%x, urp=%x", ack, th->th_urp);
		flags = th->th_flags;
		if (flags) {
			char *cp = "<";
#define pf(f) {					\
	if (th->th_flags & TH_##f) {		\
		printf("%s%s", cp, #f);		\
		cp = ",";			\
	}					\
}
			pf(SYN); pf(ACK); pf(FIN); pf(RST); pf(PUSH); pf(URG);
			printf(">");
		}
		break;

	case TA_USER:
		printf("%s", prurequests[req&0xff]);
		if ((req & 0xff) == PRU_SLOWTIMO)
			printf("<%s>", tcptimers[req>>8]);
		break;
	}
	if (tp)
		printf(" -> %s", tcpstates[tp->t_state]);
	/* print out internal state of tp !?! */
	printf("\n");
	if (tp == 0)
		return;
	printf(
	"\trcv_(nxt,wnd,up) (%lx,%lx,%lx) snd_(una,nxt,max) (%lx,%lx,%lx)\n",
	    (u_long)tp->rcv_nxt, tp->rcv_wnd, (u_long)tp->rcv_up,
	    (u_long)tp->snd_una, (u_long)tp->snd_nxt, (u_long)tp->snd_max);
	printf("\tsnd_(wl1,wl2,wnd) (%lx,%lx,%lx)\n",
	    (u_long)tp->snd_wl1, (u_long)tp->snd_wl2, tp->snd_wnd);
#endif /* TCPDEBUG */
}
