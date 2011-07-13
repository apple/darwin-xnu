/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
/* CMU_ENDHIST */
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
/*
 */

/*
 * Global descriptor table.
 */
#include <i386/seg.h>

struct real_descriptor master_gdt[GDTSZ] __attribute__ ((section("__INITGDT,__data")))= {
	[SEL_TO_INDEX(KERNEL32_CS)] = MAKE_REAL_DESCRIPTOR(	/* kernel 32-bit code */ 
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_K|ACC_CODE_R
	),
	[SEL_TO_INDEX(KERNEL_DS)] = MAKE_REAL_DESCRIPTOR(	/* kernel data */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_K|ACC_DATA_W
	),
	[SEL_TO_INDEX(KERNEL64_CS)] = MAKE_REAL_DESCRIPTOR(	/* kernel 64-bit code */ 
		0,
		0xfffff,
		SZ_64|SZ_G,
		ACC_P|ACC_PL_K|ACC_CODE_R
	),
	[SEL_TO_INDEX(KERNEL64_SS)] = MAKE_REAL_DESCRIPTOR(	/* kernel 64-bit syscall stack */ 
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_K|ACC_DATA_W
	),
#ifdef __x86_64__
	[SEL_TO_INDEX(USER_CS)] = MAKE_REAL_DESCRIPTOR(	/* 32-bit user code segment */
		0,
		0xfffff,
 		SZ_32|SZ_G,
		ACC_P|ACC_PL_U|ACC_CODE_R
	),
	[SEL_TO_INDEX(USER_DS)] = MAKE_REAL_DESCRIPTOR(	/* 32-bit user data segment */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_U|ACC_DATA_W
	),
	[SEL_TO_INDEX(USER64_CS)] = MAKE_REAL_DESCRIPTOR(	/* user 64-bit code segment */
		0,
		0xfffff,
		SZ_64|SZ_G,
		ACC_P|ACC_PL_U|ACC_CODE_R
	),
#endif
};
