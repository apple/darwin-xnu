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
 *	@(#)argo_debug.h	8.1 (Berkeley) 6/10/93
 */

/*****************************************************************
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

#ifndef __ARGO_DEBUG__
#define __ARGO_DEBUG__

#define dump_buf(a, b) Dump_buf((caddr_t)(a), (int)(b))

/***********************************************
 * Lint stuff
 **********************************************/
#if	defined(lint)
/* 
 * lint can't handle the flaky vacuous definitions 
 * of IFDEBUG, ENDDEBUG, etc.
 */
#endif	/* defined(lint) */

/***********************************************
 * DEBUG ON:
 **********************************************/
#ifndef ARGO_DEBUG
#define ARGO_DEBUG
#endif /* ARGO_DEBUG */


#ifdef ARGO_DEBUG
#if 0
    #ifndef TPPT
    #define TPPT
    #endif /* TPPT */

    #ifndef TP_PERF_MEAS
    #define TP_PERF_MEAS
    #endif /* TP_PERF_MEAS */
#endif /* 0 */

unsigned char	argo_debug[128];

#define IFDEBUG(ascii) \
	if(argo_debug[ascii]) { 
#define ENDDEBUG  ; }

#else  /* ARGO_DEBUG */

/***********************************************
 * DEBUG OFF:
 **********************************************/

#ifndef STAR
#define STAR *
#endif	/* STAR */
#define IFDEBUG(ascii)	 //*beginning of comment*/STAR
#define ENDDEBUG	 STAR/*end of comment*//

#endif /* ARGO_DEBUG */

/***********************************************
 * ASSERT 
 **********************************************/
#ifdef ARGO_DEBUG

#ifndef lint
#define ASSERT(phrase) \
if( !(phrase) ) printf("ASSERTION NOT VALID at line %d file %s\n",__LINE__,__FILE__)
#else /* lint */
#define ASSERT(phrase) /* phrase */
#endif /* lint */

#else /* ARGO_DEBUG */

#define ASSERT(phrase) /* phrase */

#endif /* ARGO_DEBUG */


/***********************************************
 * CLNP DEBUG OPTIONS
 **********************************************/
#define	D_INPUT			'\1'
/* clnp input */
#define	D_OUTPUT		'\2'
/* clnp output */
#define	D_ROUTE			'\3'
/* clnp routing */
#define	D_CTLINPUT		'\4'
/* clnp control input */
#define	D_CTLOUTPUT		'\5'
/* clnp control output */
#define D_OPTIONS		'\6'
/* clnp options */
#define	D_IOCTL			'\7'
/* iso ioctls */
#define D_ETHER			'\10'
/* clnp over ethernet */
#define D_TOKEN			'\11'
/* clnp over token ring */
#define D_ADCOM			'\12'
/* clnp over the adcom */
#define D_ISO			'\13'	
/* iso address family */
#define	D_FORWARD		'\14'
/* clnp forwarding */
#define	D_DUMPOUT		'\15'
/* dump clnp outgoing packets */
#define	D_DUMPIN		'\16'	
/* dump clnp input packets */
#define D_DISCARD		'\17'	
/* debug clnp packet discard/er function */
#define D_FRAG			'\20'	
/* clnp fragmentation */
#define	D_REASS			'\21'	
/* clnp reassembly */

char *clnp_iso_addrp();

/***********************************************
 * ESIS DEBUG OPTIONS
 **********************************************/
#define	D_ESISOUTPUT	'\30'
#define	D_ESISINPUT		'\31'
#define D_SNPA			'\32'

/***********************************************
 * ISIS DEBUG OPTIONS
 **********************************************/
#define D_ISISOUTPUT	'\40'
#define D_ISISINPUT		'\41'

/***********************************************
 * EON DEBUG OPTION
 **********************************************/
#define	D_EON			'\57'

/***********************************************
 * CONS DEBUG OPTIONS
 **********************************************/

#define D_ECNWORK		'\60'
#define D_ECNOUT		'\61'
#define D_ECNFIN		'\62'
#define D_ECNDWN		'\63'
#define D_ECNUTIL		'\64'

#define D_INCOMING		'\70'
#define D_CDATA			'\71'
#define D_CFIND			'\72'
#define D_CDUMP_REQ		'\73'
#define D_CADDR			'\74'
#define D_CCONS			'\75'
#define D_CCONN			'\76'


/***********************************************
 * TP DEBUG OPTIONS
 **********************************************/

#define D_SETPARAMS		'\137'
#define D_RTT 			'\140'

#define D_ACKRECV 		'\141'
#define D_ACKSEND 		'\142'
#define D_CONN 			'\143'
#define D_CREDIT 		'\144'
#define D_DATA 			'\145'
#define D_DRIVER 		'\146'

#define D_EMIT 			'\147'
#define D_ERROR_EMIT 	'\150'
#define D_TPINPUT 		'\151'
#define D_INDICATION 	'\152'
#define D_CHKSUM 		'\153'

#define D_RENEG 		'\154'
#define D_PERF_MEAS 	'\155'
#define D_MBUF_MEAS 	'\156'
#define D_RTC 			'\157'
#define D_SB 			'\160'

#define D_DISASTER_CHECK '\161'
#define D_REQUEST 		'\162'
#define D_STASH 		'\163'
#define D_NEWSOCK 		'\164'
#define D_TIMER 		'\165'

#define D_TPIOCTL 		'\166'
#define D_SIZE_CHECK 	'\167'
#define D_2ER 			'\170'
#define D_DISASTER_CHECK_W '\171'

#define D_XPD 			'\172'
#define D_SYSCALL 		'\173'
#define D_DROP 			'\174'
#define D_ZDREF 		'\175'
#define D_TPISO			'\176'
#define D_QUENCH		'\177'

void dump_mbuf();

/***********************************************
 * New mbuf types for debugging w/ netstat -m
 * This messes up 4.4 malloc for now. need bigger
 * mbtypes array for now.
 **********************************************/
#ifdef notdef

#define 	TPMT_DATA	0x21
#define 	TPMT_RCVRTC	0x42
#define 	TPMT_SNDRTC	0x41
#define 	TPMT_TPHDR	0x22
#define 	TPMT_IPHDR	0x32
#define 	TPMT_SONAME	0x28
#define 	TPMT_EOT	0x40
#define 	TPMT_XPD	0x44
#define 	TPMT_PCB	0x23
#define 	TPMT_PERF	0x45

#else /* ARGO_DEBUG */

#define 	TPMT_DATA	MT_DATA
#define 	TPMT_RCVRTC	MT_DATA
#define 	TPMT_SNDRTC	MT_DATA
#define 	TPMT_IPHDR	MT_HEADER
#define 	TPMT_TPHDR	MT_HEADER
#define 	TPMT_SONAME	MT_SONAME
/* MT_EOT and MT_XPD are defined in tp_param.h */
#define 	TPMT_XPD	MT_OOBDATA
#define 	TPMT_PCB	MT_PCB
#define 	TPMT_PERF	MT_PCB

#endif /* ARGO_DEBUG */

#endif /* __ARGO_DEBUG__ */
