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
 *	@(#)iso_errno.h	8.1 (Berkeley) 6/10/93
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

#ifndef __ISO_ERRNO__
#define __ISO_ERRNO__

#define ISO_ERROR_MASK 	0x8000
#define BSD_ERROR_MASK 	0x0000
#define	TP_ERROR_MASK	0x8800	/* transport layer */
#define	CONL_ERROR_MASK	0x8400	/* co network layer */ 
#define	CLNL_ERROR_MASK	0x8200	/* cl network layer */
#define TP_ERROR_SNDC	0x10000	/* kludge to force DC's on certain errors */

#define E_CO_NOERROR	(CONL_ERROR_MASK | 0x0)	/* no add'l info */

/******************************************************************************/
/*                                                                            */
/*                                                                            */
/*                          Transport Layer                                   */
/*                                                                            */
/*                                                                            */
/******************************************************************************/

#define E_TP_DR_NO_REAS	(TP_ERROR_MASK | 0x0)	 /* dr reason not specified*/
#define E_TP_CONGEST	(TP_ERROR_MASK | 0x1)	 /* dr reason congestion */
#define E_TP_NO_SESSION	(TP_ERROR_MASK | 0x2)	 /* dr reason no sess ent */
#define E_TP_ADDR_UNK	(TP_ERROR_MASK | 0x3)	 /* dr reason addr unknown */

#define E_TP_ER_NO_REAS (TP_ERROR_MASK | 0x40) /* er reas not specified */
#define E_TP_INV_PCODE	(TP_ERROR_MASK | 0x41)	 /* er reas invalid parm code */
#define E_TP_INV_TPDU	(TP_ERROR_MASK | 0x42)	 /* er reas invalid tpdu type */
#define E_TP_INV_PVAL	(TP_ERROR_MASK | 0x43)	 /* er reas invalid parm value*/

#define E_TP_NORMAL_DISC (TP_ERROR_MASK | 0x80)	 /* dr reas normal disc */
#define E_TP_CONGEST_2	(TP_ERROR_MASK | 0x81)	 /* dr reason congestion */
#define E_TP_NEGOT_FAILED (TP_ERROR_MASK | 0x82)	 /* dr negotiation failed */
#define E_TP_DUPL_SRCREF (TP_ERROR_MASK | 0x83)	 /* dr duplicate src ref */
#define E_TP_MISM_REFS 	(TP_ERROR_MASK | 0x84)	 /* dr mismatched references*/
#define E_TP_PROTO_ERR 	(TP_ERROR_MASK | 0x85)	 /* dr protocol error*/
/* 0x86 not used */
#define E_TP_REF_OVERFLOW (TP_ERROR_MASK | 0x87)	 /* dr reference overflow */
#define E_TP_NO_CR_ON_NC (TP_ERROR_MASK | 0x88)	 /* dr cr refused on this nc */
/* 0x89 not used */
#define E_TP_LENGTH_INVAL (TP_ERROR_MASK | 0x8a)	 /* dr inval length in hdr*/

/******************************************************************************/
/*                                                                            */
/*                                                                            */
/*                   Connection Less Network Layer                            */
/*                                                                            */
/*                                                                            */
/******************************************************************************/
#ifdef notdef		/* Doesn't look like legal C and is causing 
			 * compiler problems 	*/
#define E_CLNL_???	(CLNL_ERROR_MASK | 0x1)	 /* explanation */
#endif

/******************************************************************************/
/*                                                                            */
/*                                                                            */
/*               Connection Oriented Network Layer                            */
/*                                                                            */
/*                                                                            */
/******************************************************************************/
	/* see p. 149 of ISO 8208 */
#define E_CO_NOERROR	(CONL_ERROR_MASK | 0x0)	/* no add'l info */
#define E_CO_INV_PS		(CONL_ERROR_MASK | 0x1)	/* invalid p(s) */
#define E_CO_INV_PR		(CONL_ERROR_MASK | 0x2)	/* invalid p(r) */
	/* dot dot dot */
#define E_CO_INV_PKT_TYPE	(CONL_ERROR_MASK | 0x10)	/* packet type invalid*/
#define E_CO_INV_PKT_R1		(CONL_ERROR_MASK | 0x11)	/* for state r1 */
#define E_CO_INV_PKT_R2		(CONL_ERROR_MASK | 0x12)	/* for state r2 */
#define E_CO_INV_PKT_R3		(CONL_ERROR_MASK | 0x13)	/* for state r3 */
#define E_CO_INV_PKT_P1		(CONL_ERROR_MASK | 0x14)	/* for state p1 */
#define E_CO_INV_PKT_P2		(CONL_ERROR_MASK | 0x15)	/* for state p2 */
#define E_CO_INV_PKT_P3		(CONL_ERROR_MASK | 0x16)	/* for state p3 */
#define E_CO_INV_PKT_P4		(CONL_ERROR_MASK | 0x17)	/* for state p4 */
#define E_CO_INV_PKT_P5		(CONL_ERROR_MASK | 0x18)	/* for state p5 */
#define E_CO_INV_PKT_P6		(CONL_ERROR_MASK | 0x19)	/* for state p6 */
#define E_CO_INV_PKT_P7		(CONL_ERROR_MASK | 0x1a)	/* for state p7 */
#define E_CO_INV_PKT_D1		(CONL_ERROR_MASK | 0x1b)	/* for state d1 */
#define E_CO_INV_PKT_D2		(CONL_ERROR_MASK | 0x1c)	/* for state d2 */
#define E_CO_INV_PKT_D3		(CONL_ERROR_MASK | 0x1d)	/* for state d3 */
	/* dot dot dot */
#define E_CO_PKT_NOT_ALWD	(CONL_ERROR_MASK | 0x20) /* packet not allowed */
#define E_CO_PNA_UNIDENT	(CONL_ERROR_MASK | 0x21) /* unidentifiable pkt */
#define E_CO_PNA_ONEWAY		(CONL_ERROR_MASK | 0x22) /* call on 1-way lc */
#define E_CO_PNA_PVC		(CONL_ERROR_MASK | 0x23) /* inv pkt type on a pvc */
#define E_CO_PNA_UNASSLC	(CONL_ERROR_MASK | 0x24) /* pkt on unassigned lc */
#define E_CO_PNA_REJECT		(CONL_ERROR_MASK | 0x25) /* REJ not subscribed to*/
#define E_CO_PNA_SHORT		(CONL_ERROR_MASK | 0x26) /* pkt too short */
#define E_CO_PNA_LONG		(CONL_ERROR_MASK | 0x27) /* pkt too long */
#define E_CO_PNA_INVGFI		(CONL_ERROR_MASK | 0x28) /* inv gen format id */
#define E_CO_PNA_NZLCI		(CONL_ERROR_MASK | 0x29) \
	/* restart or reg pkt with nonzero logical channel identifier */
#define E_CO_PNA_FACIL		(CONL_ERROR_MASK | 0x2a) \
	/* pkt type not compat with facility */
#define E_CO_PNA_UINTCON	(CONL_ERROR_MASK | 0x2b)	/* unauthor intrpt conf */
#define E_CO_PNA_UINTRPT	(CONL_ERROR_MASK | 0x2c) /* unauthorized intrpt	*/
#define E_CO_PNA_UREJECT	(CONL_ERROR_MASK | 0x2d) /* unauthorized reject  */

#define E_CO_TMR_EXP		(CONL_ERROR_MASK | 0x30) /* timer expired */
#define E_CO_TMR_CALR		(CONL_ERROR_MASK | 0x31) /* inc. call or call req */
#define E_CO_TMR_CLRI		(CONL_ERROR_MASK | 0x32) /* clear indication */
#define E_CO_TMR_RSTI		(CONL_ERROR_MASK | 0x33) /* reset indication */
#define E_CO_TMR_RRTI		(CONL_ERROR_MASK | 0x34) /* restart indication */

#define E_CO_REG_PROB		(CONL_ERROR_MASK | 0x40)\
	/* call setup, clear, or registration problem  */
#define E_CO_REG_CODE		(CONL_ERROR_MASK | 0x41) /* code not allowed */
#define E_CO_REG_PARM		(CONL_ERROR_MASK | 0x42) /* parameter not allowed */
#define E_CO_REG_ICDA		(CONL_ERROR_MASK | 0x43) /* invalid called addr */
#define E_CO_REG_ICGA		(CONL_ERROR_MASK | 0x44) /* invalid calling addr */
#define E_CO_REG_ILEN		(CONL_ERROR_MASK | 0x45) /* invalid facil length */
#define E_CO_REG_IBAR		(CONL_ERROR_MASK | 0x46) /* incoming call barred */
#define E_CO_REG_NOLC		(CONL_ERROR_MASK | 0x47) /* no logical chan avail*/
#define E_CO_REG_COLL		(CONL_ERROR_MASK | 0x48) /* call collision */
#define E_CO_REG_DUPF		(CONL_ERROR_MASK | 0x49) /* dupl facil requested */
#define E_CO_REG_NZAL		(CONL_ERROR_MASK | 0x4a) /* non-zero addr length */
#define E_CO_REG_NZFL		(CONL_ERROR_MASK | 0x4b) /* non-zero facil length */
#define E_CO_REG_EFNP		(CONL_ERROR_MASK | 0x4c) \
	/* expected facil not provided */
#define E_CO_REG_ICCITT		(CONL_ERROR_MASK | 0x4d) \
	/* invalid CCITT-specified  DTE facil */

#define E_CO_MISC			(CONL_ERROR_MASK | 0x50) /* miscellaneous */
#define E_CO_MISC_CAUSE		(CONL_ERROR_MASK | 0x51) /* improper cause code */
#define E_CO_MISC_ALIGN		(CONL_ERROR_MASK | 0x52) /* not octet-aligned */
#define E_CO_MISC_IQBS		(CONL_ERROR_MASK | 0x53) \
	/* inconsistent Q bit settings */

#define E_CO_INTL			(CONL_ERROR_MASK | 0x70) /* international problem */
#define E_CO_IREMNWK		(CONL_ERROR_MASK | 0x71) /* remote network problem */
#define E_CO_INPROTO		(CONL_ERROR_MASK | 0x72) /* int'l protocol problem */
#define E_CO_ILINKDWN		(CONL_ERROR_MASK | 0x73) /* int'l link down */
#define E_CO_ILINKBSY		(CONL_ERROR_MASK | 0x74) /* int'l link busy */
#define E_CO_IXNETFAC		(CONL_ERROR_MASK | 0x75) /* transit netwk facil */
#define E_CO_IRNETFAC		(CONL_ERROR_MASK | 0x76) /* remote netwk facil */
#define E_CO_IROUTING		(CONL_ERROR_MASK | 0x77) /* int'l routing prob */
#define E_CO_ITMPRTG		(CONL_ERROR_MASK | 0x78) /* temporary routing prob */
#define E_CO_IUNKDNIC		(CONL_ERROR_MASK | 0x79) /* unknown called DNIC */
#define E_CO_IMAINT			(CONL_ERROR_MASK | 0x7a)	/* maintenance action */

#define E_CO_TIMO			(CONL_ERROR_MASK | 0x90)	\
	/* timer expired or retransmission count surpassed */
#define E_CO_TIM_INTRP		(CONL_ERROR_MASK | 0x91)	/* for interrupt */
#define E_CO_TIM_DATA		(CONL_ERROR_MASK | 0x92)	/*  for data */
#define E_CO_TIM_REJ		(CONL_ERROR_MASK | 0x93)	/*  for reject */

#define E_CO_DTE_SPEC		(CONL_ERROR_MASK | 0xa0)	/* DTE-specific */
#define E_CO_DTE_OK			(CONL_ERROR_MASK | 0xa1)	/* DTE operational */
#define E_CO_DTE_NOK		(CONL_ERROR_MASK | 0xa2)	/* DTE not operational */
#define E_CO_DTE_RSRC		(CONL_ERROR_MASK | 0xa3)	/* DTE resource constraint*/
#define E_CO_DTE_FSLCT		(CONL_ERROR_MASK | 0xa4)	/* fast select not subsc */
#define E_CO_DTE_PFPKT		(CONL_ERROR_MASK | 0xa5)	/* partially full pkt */
#define E_CO_DTE_DBIT		(CONL_ERROR_MASK | 0xa6)	/* D-bit proc not supp */
#define E_CO_DTE_RCCON		(CONL_ERROR_MASK | 0xa7)	/* reg/canell confirmed */

#define E_CO_OSI_NSP		(CONL_ERROR_MASK | 0xe0)	/* OSI net svc problem */
#define E_CO_OSI_DISCT		(CONL_ERROR_MASK | 0xe1)	/* disconnect transient */
#define E_CO_OSI_DISCP		(CONL_ERROR_MASK | 0xe2)	/* disconnect permanent */
#define E_CO_OSI_REJT		(CONL_ERROR_MASK | 0xe3)	/* reject transient */
#define E_CO_OSI_REJP		(CONL_ERROR_MASK | 0xe4)	/* reject permanent */
#define E_CO_OSI_QOST		(CONL_ERROR_MASK | 0xe5)	/* reject QOS transient */
#define E_CO_OSI_QOSP		(CONL_ERROR_MASK | 0xe6)	/* reject QOS permanent */
#define E_CO_OSI_NSAPT		(CONL_ERROR_MASK | 0xe7)	/* NSAP unreach transient */
#define E_CO_OSI_NSAPP		(CONL_ERROR_MASK | 0xe8)	/* NSAP unreach permanent */
#define E_CO_OSI_RESET		(CONL_ERROR_MASK | 0xe9)	/* reset no reason */
#define E_CO_OSI_CONGEST	(CONL_ERROR_MASK | 0xea)	/* reset congestion */
#define E_CO_OSI_UNSAP		(CONL_ERROR_MASK | 0xeb)	/* unknown NSAP permanent */

#define E_CO_HLI_INIT		(CONL_ERROR_MASK | 0xf0)	/* higher level initiated*/
#define E_CO_HLI_DISCN		(CONL_ERROR_MASK | 0xf1)	/* disconnect normal */
#define E_CO_HLI_DISCA		(CONL_ERROR_MASK | 0xf2)	/* disconnect abnormal */
#define E_CO_HLI_DISCI		(CONL_ERROR_MASK | 0xf3)	/* disconnect incompatible*/
#define E_CO_HLI_REJT		(CONL_ERROR_MASK | 0xf4)	/* reject transient */
#define E_CO_HLI_REJP		(CONL_ERROR_MASK | 0xf5)	/* reject permanent */
#define E_CO_HLI_QOST		(CONL_ERROR_MASK | 0xf6)	/* reject QOS transient */
#define E_CO_HLI_QOSP		(CONL_ERROR_MASK | 0xf7)	/* reject QOS permanent */
#define E_CO_HLI_REJI		(CONL_ERROR_MASK | 0xf8)	/* reject incompatible  */
#define E_CO_HLI_PROTOID	(CONL_ERROR_MASK | 0xf9)	/* unrecog proto id  */
#define E_CO_HLI_RESYNC		(CONL_ERROR_MASK | 0xfa)	/* reset - user resync */

/* Cause on 8208 CLEAR field */
#define E_CO_NUMBERBUSY		(CONL_ERROR_MASK | 0x101) /* Number busy */
#define E_CO_INVFACREQ		(CONL_ERROR_MASK | 0x103)  /* invalid facil req */
#define E_CO_NETCONGEST		(CONL_ERROR_MASK | 0x105)  /* Network congestion */
#define E_CO_OUTOFORDER		(CONL_ERROR_MASK | 0x109) /* Out of order */
#define E_CO_ACCESSBAR		(CONL_ERROR_MASK | 0x10b)  /* access barred */
#define E_CO_NOTOBTAIN		(CONL_ERROR_MASK | 0x10d)  /* not obtainable */
#define E_CO_REMPROCERR		(CONL_ERROR_MASK | 0x111) /* Remote procedure err */
#define E_CO_LOCPROCERR		(CONL_ERROR_MASK | 0x113)  /* Local procedure err */
#define E_CO_RPOAOOO		(CONL_ERROR_MASK | 0x115)  /* RPOA out of order */
#define E_CO_NOREVCHG		(CONL_ERROR_MASK | 0x119) /* Revs chg not accepted*/
#define E_CO_INCOMPAT		(CONL_ERROR_MASK | 0x121) /* Incompatible dest */
#define E_CO_NOFASTSEL		(CONL_ERROR_MASK | 0x129) 
	/* Fast select accpt not subscribed */
#define E_CO_NOSHIP			(CONL_ERROR_MASK | 0x139)  /* ship absent */
#define E_CO_GWPROCERR		(CONL_ERROR_MASK | 0x1c1)  /* Gateway-detected err*/
#define E_CO_GWCONGEST		(CONL_ERROR_MASK | 0x1c3)  /* Gateway congestion*/

/* ARGO only */
#define E_CO_QFULL 	(CONL_ERROR_MASK | 0x100)	/* dropped packet - queue full*/
#define E_CO_AIWP 	(CONL_ERROR_MASK | 0x102)   /* addr incompat w/proto */
#define E_CO_CHAN 	(CONL_ERROR_MASK | 0x104)	/* bad channel number */

/* ARGO only; driver specific */
#define E_CO_NORESOURCES 	(CONL_ERROR_MASK | 0x1b0)	/* eicon clogged  */
#define E_CO_PDNDOWN		(CONL_ERROR_MASK | 0x1b1)	/* physical net down */
#define E_CO_DRVRCLRESET	(CONL_ERROR_MASK | 0x1b2)	/* driver clear/reset */
#define E_CO_PDNCLRESET		(CONL_ERROR_MASK | 0x1b3)	/* PDN clear/reset */
#define E_CO_DTECLRESET		(CONL_ERROR_MASK | 0x1b4)	/* board clear/reset */
#define E_CO_UNKCLRESET		(CONL_ERROR_MASK | 0x1b5)	/* unexpected clr/rst */

#define CONL_ERROR_MAX 0x1c3

#endif /* __ISO_ERRNO__ */
