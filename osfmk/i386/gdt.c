/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <mach/machine.h>
#include <mach/i386/vm_param.h>
#include <kern/thread.h>
#include <i386/cpu_data.h>
#include <i386/mp_desc.h>

struct fake_descriptor master_gdt[GDTSZ] __attribute__ ((aligned (4096))) = {
	[SEL_TO_INDEX(KERNEL_CS)] {	/* kernel code */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_K|ACC_CODE_R,
	},
	[SEL_TO_INDEX(KERNEL_DS)] {	/* kernel data */
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_K|ACC_DATA_W
	},
	[SEL_TO_INDEX(KERNEL_LDT)] {	/* local descriptor table */
		(uint32_t) &master_ldt,
		LDTSZ_MIN*sizeof(struct fake_descriptor)-1,
		0,
		ACC_P|ACC_PL_K|ACC_LDT
	},				/* The slot KERNEL_LDT_2 is reserved. */
	[SEL_TO_INDEX(KERNEL_TSS)] {	/* TSS for this processor */
		(uint32_t) &master_ktss,
		sizeof(struct i386_tss)-1,
		0,
		ACC_P|ACC_PL_K|ACC_TSS
	},				/* The slot KERNEL_TSS_2 is reserved. */
	[SEL_TO_INDEX(CPU_DATA_GS)] {	/* per-CPU current thread address */
		(uint32_t) &cpu_data_master,
		sizeof(cpu_data_t)-1,
		SZ_32,
		ACC_P|ACC_PL_K|ACC_DATA_W
	},
	[SEL_TO_INDEX(USER_LDT)] {	/* user local descriptor table */
		(uint32_t) &master_ldt,
		LDTSZ_MIN*sizeof(struct fake_descriptor)-1,
		0,
		ACC_P|ACC_PL_K|ACC_LDT
	},
	[SEL_TO_INDEX(KERNEL64_CS)] {	/* kernel 64-bit code */ 
		0,
		0xfffff,
		SZ_64|SZ_G,
		ACC_P|ACC_PL_K|ACC_CODE_R
	},
	[SEL_TO_INDEX(KERNEL64_SS)] {	/* kernel 64-bit syscall stack */ 
		0,
		0xfffff,
		SZ_32|SZ_G,
		ACC_P|ACC_PL_K|ACC_DATA_W
	},
#if	MACH_KDB
	[SEL_TO_INDEX(DEBUG_TSS)] {	/* TSS for this processor */
		(uint32_t)&master_dbtss,
		sizeof(struct i386_tss)-1,
		0,
		ACC_P|ACC_PL_K|ACC_TSS
	},
#endif	/* MACH_KDB */
};
