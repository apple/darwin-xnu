/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

#ifndef _KDP_X86_COMMON_H_
#define _KDP_X86_COMMON_H_

#include <libsa/types.h>
#include <mach/machine/vm_types.h>
#include <i386/pmap.h>

/*
 * Attempt to discover all virtually contiguous ranges in a pmap
 * that have valid mappings to DRAM (not MMIO device memory for example).
 * Results are returned via a callback. If the callback returns an error,
 * traversal is aborted.
 */
typedef int (*pmap_traverse_callback)(vm_map_offset_t start,
									  vm_map_offset_t end,
									  void *context);

extern int pmap_traverse_present_mappings(pmap_t pmap,
										  vm_map_offset_t start,
										  vm_map_offset_t end,
										  pmap_traverse_callback callback,
										  void *context);


extern int kern_dump(void);
extern size_t kern_collectth_state_size(void);
extern void kern_collectth_state(thread_t thread, void *buffer, size_t size);

#endif /* _KDP_X86_COMMON_H_ */
