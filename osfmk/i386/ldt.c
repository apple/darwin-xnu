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
/*
 */

/*
 * "Local" descriptor table.  At the moment, all tasks use the
 * same LDT.
 */
#include <i386/seg.h>
#include <i386/pmap.h>
#include <mach/i386/vm_types.h>
#include <mach/i386/vm_param.h>


struct fake_descriptor	master_ldt[LDTSZ] __attribute__ ((aligned (4096))) = {
	[SEL_TO_INDEX(SYSENTER_CS)] {	/* kernel code (sysenter) */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_K|ACC_CODE_R
	},
	[SEL_TO_INDEX(SYSENTER_DS)] {	/* kernel data (sysenter) */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_K|ACC_DATA_W
	},
	[SEL_TO_INDEX(USER_CS)] {	/* user code segment */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_U|ACC_CODE_R
	},
	[SEL_TO_INDEX(USER_DS)] {	/* user data segment */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_U|ACC_DATA_W
	},
	[SEL_TO_INDEX(USER64_CS)] {	/* user 64-bit code segment */
		0,
		0xfffff,
		SZ_64|SZ_G,
		ACC_P|ACC_PL_U|ACC_CODE_R
	},
	[SEL_TO_INDEX(USER_CTHREAD)] {	/* user cthread segment */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_U|ACC_DATA_W
	},
};
