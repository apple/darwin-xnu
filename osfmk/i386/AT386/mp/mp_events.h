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
#ifndef __AT386_MP_EVENTS__
#define	__AT386_MP_EVENTS__

/* Interrupt types */

#define MP_TLB_FLUSH	0x00
#define MP_CLOCK	0x01
#define	MP_KDB		0x02
#define	MP_AST		0x03
#define MP_SOFTCLOCK	0x04
#define MP_INT_AVAIL	0x05
#define MP_AST_URGENT	0x06
#define	MP_TLB_RELOAD	0x07

#ifndef ASSEMBLER
extern void	i386_signal_cpus(int event);
#endif

#endif
