/*
 * Copyright (c) 2002,2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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


