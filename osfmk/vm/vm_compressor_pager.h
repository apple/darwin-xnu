/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#ifdef	XNU_KERNEL_PRIVATE

#ifndef _VM_VM_COMPRESSOR_PAGER_H_
#define _VM_VM_COMPRESSOR_PAGER_H_

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <vm/vm_external.h>

extern kern_return_t vm_compressor_pager_put(
	memory_object_t			mem_obj,
	memory_object_offset_t		offset,
	ppnum_t				ppnum,
	void				**current_chead,
	char				*scratch_buf);
extern kern_return_t vm_compressor_pager_get(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	ppnum_t			ppnum,
	int			*my_fault_type,
	int			flags);

#define	C_DONT_BLOCK		0x01
#define C_KEEP			0x02

extern void vm_compressor_pager_state_clr(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset);
extern vm_external_state_t vm_compressor_pager_state_get(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset);

#define VM_COMPRESSOR_PAGER_STATE_GET(object, offset)			\
	(((COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) && \
	  (object)->internal &&						\
	  (object)->pager != NULL &&					\
	  !(object)->terminating &&					\
	  (object)->alive)						\
	 ? vm_compressor_pager_state_get((object)->pager,		\
					 (offset) + (object)->paging_offset) \
	 : VM_EXTERNAL_STATE_UNKNOWN)

#define VM_COMPRESSOR_PAGER_STATE_CLR(object, offset)		\
	MACRO_BEGIN						\
	if ((COMPRESSED_PAGER_IS_ACTIVE || DEFAULT_FREEZER_COMPRESSED_PAGER_IS_ACTIVE) &&	\
	    (object)->internal &&				\
	    (object)->pager != NULL &&				\
	    !(object)->terminating &&				\
	    (object)->alive) {					\
		vm_compressor_pager_state_clr(			\
			(object)->pager,			\
			(offset) + (object)->paging_offset);	\
	}							\
	MACRO_END

extern void vm_compressor_init(void);
extern int vm_compressor_put(ppnum_t pn, int *slot, void **current_chead, char *scratch_buf);
extern int vm_compressor_get(ppnum_t pn, int *slot, int flags);
extern void vm_compressor_free(int *slot);

#endif	/* _VM_VM_COMPRESSOR_PAGER_H_ */

#endif	/* XNU_KERNEL_PRIVATE */
