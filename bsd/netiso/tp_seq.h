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
 *	@(#)tp_seq.h	8.1 (Berkeley) 6/10/93
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
 * These macros perform sequence number arithmetic modulo (2**7 or 2**31).
 * The relevant fields in the tpcb are:
 *  	tp_seqmask : the mask of bits that define the sequence space.
 *  	tp_seqbit  : 1 + tp_seqmask
 *  	tp_seqhalf : tp_seqbit / 2 or half the sequence space (rounded up)
 * Not exactly fast, but at least it's maintainable.
 */

#ifndef __TP_SEQ__
#define __TP_SEQ__

#define SEQ(tpcb,x) \
	((x) & (tpcb)->tp_seqmask)

#define SEQ_GT(tpcb, seq, operand ) \
( ((int)((seq)-(operand)) > 0)\
? ((int)((seq)-(operand)) < (int)(tpcb)->tp_seqhalf)\
: !(-((int)(seq)-(operand)) < (int)(tpcb)->tp_seqhalf))

#define SEQ_GEQ(tpcb, seq, operand ) \
( ((int)((seq)-(operand)) >= 0)\
? ((int)((seq)-(operand)) < (int)(tpcb)->tp_seqhalf)\
: !((-((int)(seq)-(operand))) < (int)(tpcb)->tp_seqhalf))

#define SEQ_LEQ(tpcb, seq, operand ) \
( ((int)((seq)-(operand)) <= 0)\
? ((-(int)((seq)-(operand))) < (int)(tpcb)->tp_seqhalf)\
: !(((int)(seq)-(operand)) < (int)(tpcb)->tp_seqhalf))

#define SEQ_LT(tpcb, seq, operand ) \
( ((int)((seq)-(operand)) < 0)\
? ((-(int)((seq)-(operand))) < (int)(tpcb)->tp_seqhalf)\
: !(((int)(seq)-(operand)) < (int)(tpcb)->tp_seqhalf))
	
#define SEQ_MIN(tpcb, a, b) ( SEQ_GT(tpcb, a, b) ? b : a)

#define SEQ_MAX(tpcb, a, b) ( SEQ_GT(tpcb, a, b) ? a : b)

#define SEQ_INC(tpcb, Seq) ((++Seq), ((Seq) &= (tpcb)->tp_seqmask))

#define SEQ_DEC(tpcb, Seq)\
	((Seq) = (((Seq)+(unsigned)((int)(tpcb)->tp_seqbit - 1))&(tpcb)->tp_seqmask))

/* (amt) had better be less than the seq bit ! */

#define SEQ_SUB(tpcb, Seq, amt)\
	(((Seq) + (unsigned)((int)(tpcb)->tp_seqbit - amt)) & (tpcb)->tp_seqmask)
#define SEQ_ADD(tpcb, Seq, amt) (((Seq) + (unsigned)amt) & (tpcb)->tp_seqmask)


#define IN_RWINDOW(tpcb, seq, lwe, uwe)\
	( SEQ_GEQ(tpcb, seq, lwe) && SEQ_LT(tpcb, seq, uwe) )

#define IN_SWINDOW(tpcb, seq, lwe, uwe)\
	( SEQ_GT(tpcb, seq, lwe) && SEQ_LEQ(tpcb, seq, uwe) )

#endif /* __TP_SEQ__ */
