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
/*-
 * Copyright (c) 1991, 1993
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
 *	@(#)tp_trace.c	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */
/* 
 * ARGO TP
 *
 * The whole protocol trace module.
 * We keep a circular buffer of trace structures, which are big
 * unions of different structures we might want to see.
 * Unfortunately this gets too big pretty easily. Pcbs were removed
 * from the tracing when the kernel got too big to boot.
 */

#define TP_TRACEFILE

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netiso/tp_param.h>
#include <netiso/tp_timer.h>
#include <netiso/tp_stat.h>
#include <netiso/tp_param.h>
#include <netiso/tp_ip.h>
#include <netiso/tp_pcb.h>
#include <netiso/tp_tpdu.h>
#include <netiso/argo_debug.h>
#include <netiso/tp_trace.h>

#ifdef TPPT
static tp_seq = 0;
u_char tp_traceflags[128];

/*
 * The argument tpcb is the obvious.
 * event here is just the type of trace event - TPPTmisc, etc.
 * The rest of the arguments have different uses depending
 * on the type of trace event.
 */
/*ARGSUSED*/
/*VARARGS*/

void
tpTrace(tpcb, event, arg, src, len, arg4, arg5)
	struct tp_pcb	*tpcb;
	u_int 			event, arg;
	u_int	 		src;
	u_int	 		len; 
	u_int	 		arg4;
	u_int	 		arg5;
{
	register struct tp_Trace *tp;

	tp = &tp_Trace[tp_Tracen++];
	tp_Tracen %= TPTRACEN;

	tp->tpt_event = event;
	tp->tpt_tseq = tp_seq++;
	tp->tpt_arg = arg;
	if(tpcb)
		tp->tpt_arg2 = tpcb->tp_lref;
	bcopy( (caddr_t)&time, (caddr_t)&tp->tpt_time, sizeof(struct timeval) );

	switch(event) {

	case TPPTertpdu:
		bcopy((caddr_t)src, (caddr_t)&tp->tpt_ertpdu,
			(unsigned)MIN((int)len, sizeof(struct tp_Trace)));
		break;

	case TPPTusrreq:
	case TPPTmisc:

		/* arg is a string */
		bcopy((caddr_t)arg, (caddr_t)tp->tpt_str, 
			(unsigned)MIN(1+strlen((caddr_t) arg), TPTRACE_STRLEN));
		tp->tpt_m2 = src; 
		tp->tpt_m3 = len;
		tp->tpt_m4 = arg4;
		tp->tpt_m1 = arg5;
		break;

	case TPPTgotXack: 
	case TPPTXack: 
	case TPPTsendack: 
	case TPPTgotack: 
	case TPPTack: 
	case TPPTindicate: 
	default:
	case TPPTdriver: 
		tp->tpt_m2 = arg; 
		tp->tpt_m3 = src;
		tp->tpt_m4 = len;
		tp->tpt_m5 = arg4;
		tp->tpt_m1 = arg5; 
		break;
	case TPPTparam:
		bcopy((caddr_t)src, (caddr_t)&tp->tpt_param, sizeof(struct tp_param));
		break;
	case TPPTref:
		bcopy((caddr_t)src, (caddr_t)&tp->tpt_ref, sizeof(struct tp_ref));
		break;

	case TPPTtpduin:
	case TPPTtpduout:
		tp->tpt_arg2 = arg4;
		bcopy((caddr_t)src, (caddr_t)&tp->tpt_tpdu,
		      (unsigned)MIN((int)len, sizeof(struct tp_Trace)));
		break;
	}
}
#endif /* TPPT */
