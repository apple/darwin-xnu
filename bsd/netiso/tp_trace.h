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
 *	@(#)tp_trace.h	8.1 (Berkeley) 6/10/93
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
 * Definitions needed for the protocol trace mechanism.
 */

#ifndef __TP_TRACE__
#define __TP_TRACE__


#define TPPTsendack	1
#define TPPTgotack	2
#define TPPTXack	3
#define TPPTgotXack	4
#define TPPTack		5
#define TPPTindicate	6
#define TPPTusrreq	7
#define TPPTmisc	8
#define TPPTpcb		9
#define TPPTref		10
#define TPPTtpduin	11
#define TPPTparam	12
#define TPPTertpdu	13
#define TPPTdriver	14
#define TPPTtpduout	15

#include <netiso/tp_pcb.h>

/* this #if is to avoid lint */

#if  defined(TP_TRACEFILE)||!defined(KERNEL)

#include <netiso/tp_tpdu.h>

#define TPTRACE_STRLEN 50


/* for packet tracing */
struct tp_timeval {
	SeqNum	tptv_seq;
	u_int tptv_kind;
	u_int tptv_window;
	u_int tptv_size;
};

struct	tp_Trace {
	u_int	tpt_event;
	u_int	tpt_arg;
	u_int 	tpt_arg2;
	int	tpt_tseq;
	struct timeval	tpt_time;
	union {
		struct inpcb	tpt_Inpcb; /* protocol control block */
		struct tp_ref 	tpt_Ref; /* ref part of pcb */
		struct tpdu 	tpt_Tpdu; /* header*/
		struct tp_refinfo tpt_Param; /* ?? bytes, make sure < 128??*/
		struct tp_timeval tpt_Time;
		struct {
			u_int tptm_2;
			u_int tptm_3;
			u_int tptm_4;
			u_int tptm_5;
			char tpt_Str[TPTRACE_STRLEN];
			u_int tptm_1;
		} tptmisc;
		u_char 			tpt_Ertpdu; /* use rest of structure */
	} tpt_stuff;
};
#define tpt_inpcb tpt_stuff.tpt_Inpcb
#define tpt_pcb tpt_stuff.tpt_Pcb
#define tpt_ref tpt_stuff.tpt_Ref
#define tpt_tpdu tpt_stuff.tpt_Tpdu
#define tpt_param tpt_stuff.tpt_Param
#define tpt_ertpdu tpt_stuff.tpt_Ertpdu
#define tpt_str tpt_stuff.tptmisc.tpt_Str
#define tpt_m1 tpt_stuff.tptmisc.tptm_1
#define tpt_m2 tpt_stuff.tptmisc.tptm_2
#define tpt_m3 tpt_stuff.tptmisc.tptm_3
#define tpt_m4 tpt_stuff.tptmisc.tptm_4
#define tpt_m5 tpt_stuff.tptmisc.tptm_5

#define tpt_seq tpt_stuff.tpt_Time.tptv_seq
#define tpt_kind tpt_stuff.tpt_Time.tptv_kind
#define tpt_window tpt_stuff.tpt_Time.tptv_window
#define tpt_size tpt_stuff.tpt_Time.tptv_size

#endif /* defined(TP_TRACEFILE)||!defined(KERNEL) */


#ifdef TPPT

#define TPTRACEN 300

#define tptrace(A,B,C,D,E,F) \
	tpTrace((struct tp_pcb *)0,\
	(u_int)(A),(u_int)(B),(u_int)(C),(u_int)(D),(u_int)(E),(u_int)(F))

#define tptraceTPCB(A,B,C,D,E,F) \
	tpTrace(tpcb,\
	(u_int)(A),(u_int)(B),(u_int)(C),(u_int)(D),(u_int)(E),(u_int)(F))

extern void tpTrace();
extern struct tp_Trace tp_Trace[];
extern u_char	tp_traceflags[];
int tp_Tracen = 0;

#define IFTRACE(ascii)\
	if(tp_traceflags[ascii]) {
/* 
 * for some reason lint complains about tp_param being undefined no
 * matter where or how many times I define it.
 */
#define ENDTRACE  }


#else  /* TPPT */

/***********************************************
 * NO TPPT TRACE STUFF
 **********************************************/
#define TPTRACEN 1

#define tptrace(A,B,C,D,E,F) 0
#define tptraceTPCB(A,B,C,D,E,F) 0

#define IFTRACE(ascii)	 if (0) {
#define ENDTRACE	 }

#endif /* TPPT */



#endif /* __TP_TRACE__ */
