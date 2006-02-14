/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
 *	File:	mach/vm_param.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Machine independent virtual memory parameters.
 *
 */

#ifndef	_MACH_VM_PARAM_H_
#define _MACH_VM_PARAM_H_

#include <mach/machine/vm_param.h>

#ifdef	KERNEL

#ifndef	ASSEMBLER
#include <mach/vm_types.h>
#endif	/* ASSEMBLER */

/*
 *	The machine independent pages are refered to as PAGES.  A page
 *	is some number of hardware pages, depending on the target machine.
 */

#ifndef	ASSEMBLER

#define PAGE_SIZE_64 (unsigned long long)PAGE_SIZE		/* pagesize in addr units */
#define PAGE_MASK_64 (unsigned long long)PAGE_MASK		/* mask for off in page */

/*
 *	Convert addresses to pages and vice versa.  No rounding is used.
 *      The atop_32 and ptoa_32 macros should not be use on 64 bit types.
 *      The round_page_64 and trunc_page_64 macros should be used instead.
 */

#define atop_32(x) ((uint32_t)(x) >> PAGE_SHIFT)
#define ptoa_32(x) ((uint32_t)(x) << PAGE_SHIFT)
#define atop_64(x) ((uint64_t)(x) >> PAGE_SHIFT)
#define ptoa_64(x) ((uint64_t)(x) << PAGE_SHIFT)

/*
 *      While the following block is enabled, the legacy atop and ptoa
 *      macros will behave correctly.  If not, they will generate
 *      invalid lvalue errors.
 */

#if 1
#define atop(x)	((uint32_t)(x) >> PAGE_SHIFT)
#define ptoa(x)	((uint32_t)(x) << PAGE_SHIFT)
#else
#define atop(x) (0UL = 0)
#define ptoa(x) (0UL = 0)
#endif

/*
 *	Page-size rounding macros for the Public fixed-width VM types.
 */
#define mach_vm_round_page(x) (((mach_vm_offset_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define mach_vm_trunc_page(x) ((mach_vm_offset_t)(x) & ~((signed)PAGE_MASK))

#define memory_object_round_page(x) (((memory_object_offset_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define memory_object_trunc_page(x) ((memory_object_offset_t)(x) & ~((signed)PAGE_MASK))

/*
 *	Rounding macros for the legacy (scalable with the current task's
 *	address space size) VM types.
 */

#define round_page(x) (((vm_offset_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define trunc_page(x) ((vm_offset_t)(x) & ~((signed)PAGE_MASK))

/*
 *	Round off or truncate to the nearest page.  These will work
 *	for either addresses or counts.  (i.e. 1 byte rounds to 1 page
 *	bytes.  The round_page_32 and trunc_page_32 macros should not be
 *      use on 64 bit types.  The round_page_64 and trunc_page_64 macros
 *      should be used instead.
 *
 *	These should only be used in the rare case the size of the address
 *	or length is hard-coded as 32 or 64 bit.  Otherwise, the macros
 *	associated with the specific VM type should be used.
 */

#define round_page_32(x) (((uint32_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define trunc_page_32(x) ((uint32_t)(x) & ~((signed)PAGE_MASK))
#define round_page_64(x) (((uint64_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define trunc_page_64(x) ((uint64_t)(x) & ~((signed)PAGE_MASK))


/*
 *      Enable the following block to find uses of xxx_32 macros that should
 *      be xxx_64.  These macros only work in C code, not C++.  The resulting
 *      binaries are not functional.  Look for invalid lvalue errors in
 *      the compiler output.
 *
 *      Enabling the following block will also find use of the xxx_64 macros
 *      that have been passed pointers.  The parameters should be case to an
 *      unsigned long type first.  Look for invalid operands to binary + error
 *      in the compiler output.
 */

#if 0
#undef atop_32
#undef ptoa_32
#undef round_page_32
#undef trunc_page_32
#undef atop_64
#undef ptoa_64
#undef round_page_64
#undef trunc_page_64

#ifndef __cplusplus

#define atop_32(x) \
    (__builtin_choose_expr (sizeof(x) != sizeof(uint64_t), \
        (*(long *)0), \
        (0UL)) = 0)

#define ptoa_32(x) \
    (__builtin_choose_expr (sizeof(x) != sizeof(uint64_t), \
        (*(long *)0), \
        (0UL)) = 0)

#define round_page_32(x) \
    (__builtin_choose_expr (sizeof(x) != sizeof(uint64_t), \
        (*(long *)0), \
        (0UL)) = 0)

#define trunc_page_32(x) \
    (__builtin_choose_expr (sizeof(x) != sizeof(uint64_t), \
        (*(long *)0), \
        (0UL)) = 0)
#else

#define atop_32(x) (0)
#define ptoa_32(x) (0)
#define round_page_32(x) (0)
#define trunc_page_32(x) (0)

#endif /* ! __cplusplus */

#define atop_64(x) ((uint64_t)((x) + (uint8_t *)0))
#define ptoa_64(x) ((uint64_t)((x) + (uint8_t *)0))
#define round_page_64(x) ((uint64_t)((x) + (uint8_t *)0))
#define trunc_page_64(x) ((uint64_t)((x) + (uint8_t *)0))

#endif

/*
 *	Determine whether an address is page-aligned, or a count is
 *	an exact page multiple.
 */

#define	page_aligned(x)	((((vm_object_offset_t) (x)) & PAGE_MASK) == 0)

extern vm_size_t	mem_size;		/* 32-bit size of memory - limited by maxmem - deprecated */
extern uint64_t		max_mem;		/* 64-bit size of memory - limited by maxmem */

#ifdef	XNU_KERNEL_PRIVATE

extern uint64_t		mem_actual;		/* 64-bit size of memory - not limited by maxmem */
extern uint64_t		sane_size;		/* Memory size to use for defaults calculations */
extern addr64_t 	vm_last_addr;	/* Highest kernel virtual address known to the VM system */

#endif	/* XNU_KERNEL_PRIVATE */

extern vm_size_t	page_size;
extern vm_size_t	page_mask;
extern int			page_shift;

/* We need a way to get rid of compiler warnings when we cast from   */
/* a 64 bit value to an address that is 32 bits.                     */
/* We know at this point the cast is harmless but sometime in        */
/* the future it may not be.                                         */
/* When size of an int is no longer equal to size of uintptr_t then  */
/* the compile will fail and we know we need to fix our cast.		 */
#include <stdint.h>
#ifndef __CAST_DOWN_CHECK
#define __CAST_DOWN_CHECK
typedef char __NEED_TO_CHANGE_CAST_DOWN[ sizeof(uintptr_t) == sizeof(int) ? 0 : -1 ];
#define CAST_DOWN( type, addr )  ( ((type)((uintptr_t) (addr))) ) 
#endif /* __CAST_DOWN_CHECK */

#endif	/* ASSEMBLER */

#endif	/* KERNEL */

#endif	/* _MACH_VM_PARAM_H_ */
