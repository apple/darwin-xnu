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
 *	@(#)tp_astring.c	8.1 (Berkeley) 6/10/93
 */

char *tp_sstring[] = {
"ST_ERROR(0x0)",
"TP_CLOSED(0x1)",
"TP_CRSENT(0x2)",
"TP_AKWAIT(0x3)",
"TP_OPEN(0x4)",
"TP_CLOSING(0x5)",
"TP_REFWAIT(0x6)",
"TP_LISTENING(0x7)",
"TP_CONFIRMING(0x8)",
};

char *tp_estring[] = {
"TM_inact(0x0)",
"TM_retrans(0x1)",
"TM_sendack(0x2)",
"TM_notused(0x3)",
"TM_reference(0x4)",
"TM_data_retrans(0x5)",
"ER_TPDU(0x6)",
"CR_TPDU(0x7)",
"DR_TPDU(0x8)",
"DC_TPDU(0x9)",
"CC_TPDU(0xa)",
"AK_TPDU(0xb)",
"DT_TPDU(0xc)",
"XPD_TPDU(0xd)",
"XAK_TPDU(0xe)",
"T_CONN_req(0xf)",
"T_DISC_req(0x10)",
"T_LISTEN_req(0x11)",
"T_DATA_req(0x12)",
"T_XPD_req(0x13)",
"T_USR_rcvd(0x14)",
"T_USR_Xrcvd(0x15)",
"T_DETACH(0x16)",
"T_NETRESET(0x17)",
"T_ACPT_req(0x18)",
};
