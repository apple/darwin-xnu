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
 * Copyright (C) Dirk Husemann, Computer Science Department IV, 
 * 		 University of Erlangen-Nuremberg, Germany, 1990, 1991, 1992
 * Copyright (c) 1992, 1993
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
 *	@(#)dll.h	8.1 (Berkeley) 6/10/93
 */

/* 
 * We define the additional PRC_* codes in here
 */
#ifdef KERNEL
#ifndef PRC_IFUP
#define PRC_IFUP		   3
#endif
#define PRC_CONNECT_INDICATION     8
#define PRC_CONNECT_REQUEST        9
#define PRC_DISCONNECT_REQUEST     10
#define PRC_DISCONNECT_INDICATION  11
#define PRC_RESET_REQUEST          12
#endif

/*
 * Data link layer configuration --- basically a copy of the relevant parts
 * of x25config, implemented to become a little bit more network
 * layer independent. (Probably only used for casting et al.)
 */
struct dllconfig {
       u_short dllcfg_unused0:4,
               dllcfg_unused1:4,
               dllcfg_trace:1,     /* link level tracing flag */
               dllcfg_window:7;    /* link level window size */
       u_short dllcfg_xchxid:1,    /* exchange XID (not yet) */
               dllcfg_unused2:7;   /* here be dragons */
};

struct dll_ctlinfo {
	union {
		struct {
			struct	dllconfig *dctli_up_cfg;
			u_char	dctli_up_lsap;
		} CTLI_UP;
		struct {
			caddr_t dctli_down_pcb;
			struct rtentry *dctli_down_rt;
			struct dllconfig *dctli_down_llconf;
		} CTLI_DOWN;
	} CTLIun;
};
#define dlcti_cfg  CTLIun.CTLI_UP.dctli_up_cfg
#define dlcti_lsap CTLIun.CTLI_UP.dctli_up_lsap
#define dlcti_pcb  CTLIun.CTLI_DOWN.dctli_down_pcb
#define dlcti_rt   CTLIun.CTLI_DOWN.dctli_down_rt
#define dlcti_conf CTLIun.CTLI_DOWN.dctli_down_llconf
