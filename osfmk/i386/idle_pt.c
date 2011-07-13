/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
#include <i386/pmap.h>

#define PML4_PROT (INTEL_PTE_VALID | INTEL_PTE_WRITE)
pml4_entry_t	IdlePML4[PTE_PER_PAGE] __attribute__((section("__INITPT, __data"))) = {
#ifdef __x86_64__
		[  0]
			= ((uint64_t)(INITPT_SEG_BASE + PAGE_SIZE) | PML4_PROT),
#if KERNEL_PML4_INDEX != 0
		[KERNEL_PML4_INDEX]
			= ((uint64_t)(INITPT_SEG_BASE + PAGE_SIZE) | PML4_PROT),
#endif
#endif
	};

#if defined(__x86_64__)
#define PDPT_PROT (INTEL_PTE_VALID | INTEL_PTE_WRITE)
#elif defined(__i386__)
#define PDPT_PROT (INTEL_PTE_VALID)
#endif
pdpt_entry_t	IdlePDPT[PTE_PER_PAGE] __attribute__((section("__INITPT, __data"))) = {
		[0] = ((uint64_t)(INITPT_SEG_BASE + 2*PAGE_SIZE) | PDPT_PROT), 
		[1] = ((uint64_t)(INITPT_SEG_BASE + 3*PAGE_SIZE) | PDPT_PROT), 
		[2] = ((uint64_t)(INITPT_SEG_BASE + 4*PAGE_SIZE) | PDPT_PROT), 
		[3] = ((uint64_t)(INITPT_SEG_BASE + 5*PAGE_SIZE) | PDPT_PROT), 
	};

#if NPGPTD != 4
#error Please update idle_pt.c to reflect the new value of NPGPTD
#endif

#if MACHINE_BOOTSTRAPPTD

#define ID_MAP_2MEG(x) [(x)] = ((((uint64_t)(x)) << 21) | (INTEL_PTE_PS | INTEL_PTE_VALID | INTEL_PTE_WRITE)),

#define L0(x,n) x(n)
#define L1(x,n) L0(x,n-1)   L0(x,n)
#define L2(x,n) L1(x,n-2)   L1(x,n)
#define L3(x,n) L2(x,n-4)   L2(x,n)
#define L4(x,n) L3(x,n-8)   L3(x,n)
#define L5(x,n) L4(x,n-16)  L4(x,n)
#define L6(x,n) L5(x,n-32)  L5(x,n)
#define L7(x,n) L6(x,n-64)  L6(x,n)
#define L8(x,n) L7(x,n-128) L7(x,n)
#define L9(x,n) L8(x,n-256) L8(x,n)
#define L10(x,n) L9(x,n-512) L9(x,n)
#define L11(x,n) L10(x,n-1024) L10(x,n)

#define FOR_0_TO_2047(x) L11(x,2047)

pd_entry_t		BootstrapPTD[2048] __attribute__((section("__INITPT, __data"))) = {
	FOR_0_TO_2047(ID_MAP_2MEG)
};
#endif /* MACHINE_BOOTSTRAPPTD */
