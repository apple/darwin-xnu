/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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
 * $FreeBSD: src/sys/netinet/tcp_debug.c,v 1.16.2.1 2000/07/15 07:14:31 kris Exp $
 */


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
#include <sys/sysctl.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_debug.h>

#if TCPDEBUG
__private_extern__ int	tcpconsdebug = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tcpconsdebug, CTLFLAG_RW, 
    &tcpconsdebug, 0, "Turn tcp debugging on or off");
#endif

static struct tcp_debug tcp_debug[TCP_NDEBUG];
static int	tcp_debx;

/*
 * Tcp debug routines
 */
void
tcp_trace(act, ostate, tp, ipgen, th, req)
	short act, ostate;
	struct tcpcb *tp;
	void *ipgen;
	struct tcphdr *th;
	int req;
{
#if INET6
	int isipv6;
#endif /* INET6 */
	tcp_seq seq, ack;
	int len, flags;
	struct tcp_debug *td = &tcp_debug[tcp_debx++];

#if INET6
	isipv6 = (ipgen != NULL && ((struct ip *)ipgen)->ip_v == 6) ? 1 : 0;
#endif /* INET6 */
	td->td_family =
#if INET6
		(isipv6 != 0) ? AF_INET6 :
#endif
		AF_INET;
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
	if (ipgen) {
		switch (td->td_family) {
		case AF_INET:
			bcopy((caddr_t)ipgen, (caddr_t)&td->td_ti.ti_i,
			      sizeof(td->td_ti.ti_i));
			bzero((caddr_t)td->td_ip6buf, sizeof(td->td_ip6buf));
			break;
#if INET6
		case AF_INET6:
			bcopy((caddr_t)ipgen, (caddr_t)td->td_ip6buf,
			      sizeof(td->td_ip6buf));
			bzero((caddr_t)&td->td_ti.ti_i,
			      sizeof(td->td_ti.ti_i));
			break;
#endif
		default:
			bzero((caddr_t)td->td_ip6buf, sizeof(td->td_ip6buf));
			bzero((caddr_t)&td->td_ti.ti_i,
			      sizeof(td->td_ti.ti_i));
			break;
		}
	} else {
		bzero((caddr_t)&td->td_ti.ti_i, sizeof(td->td_ti.ti_i));
		bzero((caddr_t)td->td_ip6buf, sizeof(td->td_ip6buf));
	}
	if (th) {
		switch (td->td_family) {
		case AF_INET:
			td->td_ti.ti_t = *th;
			bzero((caddr_t)&td->td_ti6.th, sizeof(td->td_ti6.th));
			break;
#if INET6
		case AF_INET6:
			td->td_ti6.th = *th;
			bzero((caddr_t)&td->td_ti.ti_t,
			      sizeof(td->td_ti.ti_t));
			break;
#endif
		default:
			bzero((caddr_t)&td->td_ti.ti_t,
			      sizeof(td->td_ti.ti_t));
			bzero((caddr_t)&td->td_ti6.th, sizeof(td->td_ti6.th));
			break;
		}
	} else {
		bzero((caddr_t)&td->td_ti.ti_t, sizeof(td->td_ti.ti_t));
		bzero((caddr_t)&td->td_ti6.th, sizeof(td->td_ti6.th));
	}
	td->td_req = req;
#if TCPDEBUG
	if (tcpconsdebug == 0)
		return;
	if (tp)
		printf("%x %s:", tp, tcpstates[ostate]);
	else
		printf("???????? ");
	printf("%s ", tanames[act]);
	switch (act) {

	case TA_INPUT:
	case TA_OUTPUT:
	case TA_DROP:
		if (ipgen == NULL || th == NULL)
			break;
		seq = th->th_seq;
		ack = th->th_ack;
		len =
#if INET6
			isipv6 ? ((struct ip6_hdr *)ipgen)->ip6_plen :
#endif
			((struct ip *)ipgen)->ip_len;
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
