/*
 * Copyright (c) 2000-2011 Apple Computer, Inc. All rights reserved.
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
#include <mach_kdp.h>
#include <mach/vm_param.h>
#include <x86_64/lowglobals.h>

/* 
 * on x86_64 the low mem vectors live here and get mapped to 0xffffff8000002000 at
 * system startup time
 */

extern void	*version;
extern void	*kmod;
extern void	*kdp_trans_off;
extern void	*kdp_read_io;
extern void	*osversion;
extern void	*flag_kdp_trigger_reboot;
extern void	*manual_pkt;

lowglo lowGlo __attribute__ ((aligned(PAGE_SIZE))) = {

	.lgVerCode		= { 'C','a','t','f','i','s','h',' ' },

	.lgCHUDXNUfnStart	= 0,

	.lgVersion		= (uint64_t) &version,

	.lgKmodptr		= (uint64_t) &kmod,

#if MACH_KDP
	.lgTransOff		= (uint64_t) &kdp_trans_off,
	.lgReadIO		= (uint64_t) &kdp_read_io,
#else
	.lgTransOff		= 0,
	.lgReadIO		= 0,
#endif

	.lgDevSlot1		= 0,
	.lgDevSlot2		= 0,

	.lgOSVersion		= (uint64_t) &osversion,

#if MACH_KDP
	.lgRebootFlag		= (uint64_t) &flag_kdp_trigger_reboot,
	.lgManualPktAddr	= (uint64_t) &manual_pkt,
#else
	.lgRebootFlag		= 0,
	.lgManualPktAddr	= 0,
#endif	
};
