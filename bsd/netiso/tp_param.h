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
 *	@(#)tp_param.h	8.1 (Berkeley) 6/10/93
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
 */

#ifndef __TP_PARAM__
#define __TP_PARAM__


/******************************************************
 * compile time parameters that can be changed
 *****************************************************/

#define 	TP_CLASSES_IMPLEMENTED 0x11 /* zero and 4 */

#define		TP_DECBIT_CLEAR_COUNT	3

/*#define 	N_TPREF				100 */
#ifdef KERNEL
extern int N_TPREF;
#endif

#define 	TP_SOCKBUFSIZE		((u_long)4096)
#define 	TP0_SOCKBUFSIZE		((u_long)512)
#define		MAX_TSAP_SEL_LEN	64

/* maximum tpdu size we'll accept: */
#define 	TP_TPDUSIZE			0xc		/* 4096 octets for classes 1-4*/
#define 	TP0_TPDUSIZE		0xb		/* 2048 octets for class 0 */
#define 	TP_DFL_TPDUSIZE		0x7		/* 128 octets default */
	/* NOTE: don't ever negotiate 8192 because could get 
	 * wraparound in checksumming
	 * (No mtu is likely to be larger than 4K anyway...)
	 */
#define		TP_NRETRANS			12		/* TCP_MAXRXTSHIFT + 1 */
#define		TP_MAXRXTSHIFT		6		/* factor of 64 */
#define		TP_MAXPORT			0xefff

/* ALPHA: to be used in the context: gain= 1/(2**alpha), or 
 * put another way, gaintimes(x) (x)>>alpha (forgetting the case alpha==0) 
 */
#define 	TP_RTT_ALPHA		3 
#define 	TP_RTV_ALPHA		2
#define		TP_REXMTVAL(tpcb)\
	((tp_rttadd + (tpcb)->tp_rtt + ((tpcb)->tp_rtv) << 2) / tp_rttdiv)
#define		TP_RANGESET(tv, value, min, max) \
	((tv = value) > (max) ? (tv = max) : (tv < min ? tv = min : tv))

/*
 * not sure how to treat data on disconnect 
 */
#define 	T_CONN_DATA			0x1
#define 	T_DISCONNECT		0x2
#define 	T_DISC_DATA			0x4
#define 	T_XDATA				0x8

#define ISO_CLNS	 0
#define IN_CLNS	 	 1
#define ISO_CONS	 2
#define ISO_COSNS	 3
#define TP_MAX_NETSERVICES 3

/* Indices into tp stats ackreason[i] */
#define _ACK_DONT_ 0
#define _ACK_STRAT_EACH_ 0x1
#define _ACK_STRAT_FULLWIN_ 0x2
#define _ACK_DUP_ 0x3
#define _ACK_EOT_ 0x4
#define _ACK_REORDER_ 0x5
#define _ACK_USRRCV_ 0x6
#define _ACK_FCC_ 0x7
#define _ACK_NUM_REASONS_ 0x8

/* masks for use in tp_stash() */
#define ACK_DONT 			0
#define ACK_STRAT_EACH		(1<< _ACK_STRAT_EACH_)
#define ACK_STRAT_FULLWIN	(1<< _ACK_STRAT_FULLWIN_)
#define ACK_DUP 			(1<< _ACK_DUP_)
#define ACK_EOT				(1<< _ACK_EOT_)
#define ACK_REORDER			(1<< _ACK_REORDER_)

/******************************************************
 * constants used in the protocol 
 *****************************************************/

#define		TP_VERSION 			0x1

#define 	TP_MAX_HEADER_LEN	256

#define 	TP_MIN_TPDUSIZE		0x7		/* 128 octets */
#define 	TP_MAX_TPDUSIZE		0xd		/* 8192 octets */

#define		TP_MAX_XPD_DATA		0x10	/* 16 octets */
#define		TP_MAX_CC_DATA		0x20	/* 32 octets */
#define		TP_MAX_CR_DATA		TP_MAX_CC_DATA
#define		TP_MAX_DR_DATA		0x40	/* 64 octets */

#define		TP_XTD_FMT_BIT 	0x80000000
#define		TP_XTD_FMT_MASK	0x7fffffff
#define		TP_NML_FMT_BIT 	0x80
#define		TP_NML_FMT_MASK	0x7f

/*  
 * values for the tpdu_type field, 2nd byte in a tpdu 
 */

#define TP_MIN_TPDUTYPE 0x1

#define XPD_TPDU_type	0x1
#define XAK_TPDU_type	0x2
#define GR_TPDU_type	0x3	
#define AK_TPDU_type	0x6
#define ER_TPDU_type	0x7
#define DR_TPDU_type	0x8
#define DC_TPDU_type	0xc
#define CC_TPDU_type	0xd
#define CR_TPDU_type	0xe
#define DT_TPDU_type	0xf

#define TP_MAX_TPDUTYPE 0xf

/*
 * identifiers for the variable-length options in tpdus 
 */

#define		TPP_acktime			0x85
#define		TPP_residER			0x86
#define		TPP_priority		0x87
#define		TPP_transdelay		0x88
#define		TPP_throughput		0x89
#define		TPP_subseq			0x8a
#define		TPP_flow_cntl_conf	0x8c	/* not implemented */
#define		TPP_addl_info		0xe0
#define		TPP_tpdu_size		0xc0
#define		TPP_calling_sufx	0xc1
#define		TPP_invalid_tpdu	0xc1	/* the bozos used a value twice */
#define		TPP_called_sufx		0xc2
#define		TPP_checksum		0xc3
#define		TPP_vers			0xc4
#define		TPP_security		0xc5
#define		TPP_addl_opt		0xc6
#define		TPP_alt_class		0xc7
#define		TPP_perf_meas		0xc8	/* local item : perf meas on, svp */
#define		TPP_ptpdu_size		0xf0	/* preferred TPDU size */
#define		TPP_inact_time		0xf2	/* inactivity time exchanged */


/******************************************************
 * Some fundamental data types
 *****************************************************/
#ifndef		TRUE
#define		TRUE				1
#endif		/* TRUE */

#ifndef		FALSE
#define		FALSE				0
#endif		/* FALSE */

#define		TP_LOCAL				22
#define		TP_FOREIGN				33

#ifndef 	EOK
#define 	EOK 	0
#endif  	/* EOK */

#define 	TP_CLASS_0 	(1<<0)
#define 	TP_CLASS_1 	(1<<1)
#define 	TP_CLASS_2 	(1<<2)
#define 	TP_CLASS_3 	(1<<3)
#define 	TP_CLASS_4 	(1<<4)

#define 	TP_FORCE 	0x1
#define 	TP_STRICT 	0x2

#ifndef 	MNULL
#define 	MNULL				(struct mbuf *)0
#endif 	/* MNULL */
	/* if ../sys/mbuf.h gets MT_types up to 0x40, these will 
	 * have to be changed:
	 */
#define 	MT_XPD 				0x44	
#define 	MT_EOT 				0x40

#define		TP_ENOREF			0x80000000

typedef 	unsigned int	SeqNum;
typedef		unsigned short	RefNum;
typedef		int				ProtoHook;

/******************************************************
 * Macro used all over, for driver
 *****************************************************/

#define  DoEvent(x) \
  ((E.ev_number=(x)),(tp_driver(tpcb,&E)))

/******************************************************
 * Some macros used all over, for timestamping
 *****************************************************/

#define GET_CUR_TIME(tvalp) ((*tvalp) = time)

#define GET_TIME_SINCE(oldtvalp, diffp) {\
	(diffp)->tv_sec = time.tv_sec - (oldtvalp)->tv_sec;\
	(diffp)->tv_usec = time.tv_usec - (oldtvalp)->tv_usec;\
	if( (diffp)->tv_usec <0 ) {\
		(diffp)->tv_sec --;\
		(diffp)->tv_usec = 1000000 - (diffp)->tv_usec;\
	}\
}
			
/******************************************************
 * Some macros used for address families
 *****************************************************/

#define satosiso(ADDR) ((struct sockaddr_iso *)(ADDR))
#define satosin(ADDR) ((struct sockaddr_in *)(ADDR))

/******************************************************
 * Macro used for changing types of mbufs
 *****************************************************/

#define CHANGE_MTYPE(m, TYPE)\
	if((m)->m_type != TYPE) { \
		mbstat.m_mtypes[(m)->m_type]--; mbstat.m_mtypes[TYPE]++; \
		(m)->m_type = TYPE; \
	}

/******************************************************
 * Macros used for adding options to a tpdu header and for
 * parsing the headers.
 * Options are variable-length and must be bcopy-d because on the
 * RT your assignments must be N-word aligned for objects of length
 * N.  Such a drag.
 *****************************************************/

struct tp_vbp {
	u_char	tpv_code;
	char 	tpv_len;
	char	tpv_val;
};
#define vbptr(x) ((struct tp_vbp *)(x))
#define vbval(x,type) (*((type *)&(((struct tp_vbp *)(x))->tpv_val)))
#define vbcode(x) (vbptr(x)->tpv_code)
#define vblen(x) (vbptr(x)->tpv_len)

#define vb_putval(dst,type,src)\
	bcopy((caddr_t)&(src),(caddr_t)&(((struct tp_vbp *)(dst))->tpv_val),\
	sizeof(type))

#define vb_getval(src,type,dst)\
bcopy((caddr_t)&(((struct tp_vbp *)(src))->tpv_val),(caddr_t)&(dst),sizeof(type))

#define ADDOPTION(type, DU, len, src)\
{	register caddr_t P;\
	P = (caddr_t)(DU) + (int)((DU)->tpdu_li);\
	vbptr(P)->tpv_code = type;\
	vbptr(P)->tpv_len = len;\
	bcopy((caddr_t)&src, (caddr_t)&(vbptr(P)->tpv_val), (unsigned)len);\
	DU->tpdu_li += len+2;/* 1 for code, 1 for length */\
}
/******************************************************
 * Macro for the local credit:
 * uses max transmission unit for the ll
 * (as modified by the max TPDU size negotiated) 
 *****************************************************/

#if defined(ARGO_DEBUG)&&!defined(LOCAL_CREDIT_EXPAND)
#define LOCAL_CREDIT(tpcb) tp_local_credit(tpcb)
#else
#define LOCAL_CREDIT(tpcb) { if (tpcb->tp_rsycnt == 0) {\
    register struct sockbuf *xxsb = &((tpcb)->tp_sock->so_rcv);\
    register int xxi = sbspace(xxsb);\
    xxi = (xxi<0) ? 0 : ((xxi) / (tpcb)->tp_l_tpdusize);\
    xxi = min(xxi, (tpcb)->tp_maxlcredit); \
    if (!(tpcb->tp_cebit_off)) { \
        (tpcb)->tp_lcredit = ROUND((tpcb)->tp_win_recv); \
        if (xxi < (tpcb)->tp_lcredit) { \
            (tpcb)->tp_lcredit = xxi; \
        } \
    } else \
        (tpcb)->tp_lcredit = xxi; \
} }
#endif /* ARGO_DEBUG */

#ifdef KERNEL
extern int tp_rttadd, tp_rttdiv;
#include <sys/syslog.h>
#define printf logpri(LOG_DEBUG),addlog

#ifndef  tp_NSTATES 

#include <netiso/tp_states.h>
#include <netiso/tp_events.h>
#if defined(__STDC__) || defined(__cplusplus)
#undef ATTR
#define ATTR(X) ev_union.EV_ ## X
#endif /* defined(__STDC__) || defined(__cplusplus) */

#endif  /* tp_NSTATES  */
#endif /* KERNEL */

#endif /* __TP_PARAM__ */
