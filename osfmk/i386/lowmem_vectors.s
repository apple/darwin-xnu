/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <platforms.h>
#include <mach_kdb.h>
#include <mach_kdp.h>

#include <i386/asm.h>
#include <i386/proc_reg.h>
#include <i386/postcode.h>
#include <assym.s>


/* on x86 the low mem vectors live here and get mapped to 0x2000 at
 * system startup time
 */

	.text
	.align	12
	
	.globl	EXT(lowGlo)
EXT(lowGlo):

	.ascii "Catfish "		/* 0x2000 System verification code */
	.long   0			/* 0x2008 Double constant 0 */
	.long   0
	.long	0			/* 0x2010 Reserved */
	.long	0			/* 0x2014 Zero */
	.long	0			/* 0x2018 Reserved */
	.long	EXT(version)		/* 0x201C Pointer to kernel version string */
	.fill	280, 4, 0		/* 0x2020 Reserved */
	.long	EXT(kmod)		/* 0x2480 Pointer to kmod, debugging aid */
#if MACH_KDP
	.long	EXT(kdp_trans_off)	/* 0x2484 Pointer to kdp_trans_off, debugging aid */
	.long	EXT(kdp_read_io)	/* 0x2488 Pointer to kdp_read_io, debugging aid */
#else
	.long	0			/* 0x2484 Reserved */
	.long	0			/* 0x2488 Reserved */
#endif
	.long	0			/* 0x248C Reserved for developer use */
	.long	0			/* 0x2490 Reserved for developer use */
	.long	EXT(osversion)		/* 0x2494 Pointer to osversion string */
#if MACH_KDP
	.long	EXT(flag_kdp_trigger_reboot) /* 0x2498 Pointer to debugger reboot trigger */
#else
	.long	0			/* 0x2498 Reserved */
#endif
	.fill	729, 4, 0
