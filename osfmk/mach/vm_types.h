/*
 * Copyright (c) 2002,2000 Apple Computer, Inc. All rights reserved.
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
 * 
 */
#ifndef	MACH_VM_TYPES_H_
#define MACH_VM_TYPES_H_

#include <stdint.h>
#include <sys/appleapiopts.h>

#include <mach/port.h>
#include <mach/machine/vm_types.h>

typedef vm_offset_t     	pointer_t;
typedef vm_offset_t     	vm_address_t;
typedef uint64_t		vm_object_offset_t;

/*
 * We use addr64_t for 64-bit addresses that are used on both
 * 32 and 64-bit machines.  On PPC, they are passed and returned as
 * two adjacent 32-bit GPRs.  We use addr64_t in places where
 * common code must be useable both on 32 and 64-bit machines.
 */
typedef uint64_t addr64_t;		/* Basic effective address */

/*
 * We use reg64_t for addresses that are 32 bits on a 32-bit
 * machine, and 64 bits on a 64-bit machine, but are always
 * passed and returned in a single GPR on PPC.  This type
 * cannot be used in generic 32-bit c, since on a 64-bit
 * machine the upper half of the register will be ignored
 * by the c compiler in 32-bit mode.  In c, we can only use the
 * type in prototypes of functions that are written in and called
 * from assembly language.  This type is basically a comment.
 */
typedef	uint32_t	reg64_t;

/*
 * To minimize the use of 64-bit fields, we keep some physical
 * addresses (that are page aligned) as 32-bit page numbers. 
 * This limits the physical address space to 16TB of RAM.
 */
typedef uint32_t ppnum_t;		/* Physical page number */
#define PPNUM_MAX UINT32_MAX

#ifdef KERNEL_PRIVATE

#if !defined(__APPLE_API_PRIVATE) || !defined(MACH_KERNEL_PRIVATE)

/*
 * Use specifically typed null structures for these in
 * other parts of the kernel to enable compiler warnings
 * about type mismatches, etc...  Otherwise, these would
 * be void*.
 */
struct vm_map ;
struct vm_object ;

#endif /* !__APPLE_API_PRIVATE || !MACH_KERNEL_PRIVATE */

typedef struct vm_map		*vm_map_t;
typedef struct vm_object 	*vm_object_t;
#define VM_OBJECT_NULL		((vm_object_t) 0)

#else   /* KERNEL_PRIVATE */

typedef mach_port_t		vm_map_t;

#endif  /* KERNEL_PRIVATE */

#define VM_MAP_NULL		((vm_map_t) 0)


#ifdef  __APPLE_API_EVOLVING

#ifdef  KERNEL_PRIVATE

#ifndef MACH_KERNEL_PRIVATE
struct upl ;
struct vm_map_copy ;
struct vm_named_entry ;
#endif /* !MACH_KERNEL_PRIVATE */

typedef struct upl		*upl_t;
typedef struct vm_map_copy	*vm_map_copy_t;
typedef struct vm_named_entry	*vm_named_entry_t;

#define VM_MAP_COPY_NULL	((vm_map_copy_t) 0)

#else  /* !KERNEL_PRIVATE */

typedef mach_port_t		upl_t;
typedef mach_port_t		vm_named_entry_t;

#endif /* !KERNEL_PRIVATE */

#define UPL_NULL		((upl_t) 0)
#define VM_NAMED_ENTRY_NULL	((vm_named_entry_t) 0)

#endif	/* __APPLE_API_EVOLVING */

#endif	/* MACH_VM_TYPES_H_ */


