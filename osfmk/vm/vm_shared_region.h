/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 *
 *	File: vm/vm_shared_region.h
 *
 * 	protos and struct definitions for shared region
 */

#ifndef _VM_SHARED_REGION_H_
#define _VM_SHARED_REGION_H_

#ifdef	KERNEL_PRIVATE

#include <mach/vm_prot.h>
#include <mach/mach_types.h>
#include <mach/shared_region.h>

#include <kern/kern_types.h>
#include <kern/macro_help.h>

#include <vm/vm_map.h>

extern int shared_region_version;
extern int shared_region_persistence;

#if DEBUG
extern int shared_region_debug;
#define SHARED_REGION_DEBUG(args)		\
	MACRO_BEGIN				\
	if (shared_region_debug) {		\
		kprintf args;			\
	}					\
	MACRO_END
#else /* DEBUG */
#define SHARED_REGION_DEBUG(args)
#endif /* DEBUG */

extern int shared_region_trace_level;
#define SHARED_REGION_TRACE_NONE_LVL		0 /* no trace */
#define SHARED_REGION_TRACE_ERROR_LVL		1 /* trace abnormal events */
#define SHARED_REGION_TRACE_INFO_LVL		2 /* trace all events */
#define SHARED_REGION_TRACE_DEBUG_LVL		3 /* extra traces for debug */
#define SHARED_REGION_TRACE(level, args)		\
	MACRO_BEGIN					\
	if (shared_region_trace_level >= level) {	\
		printf args;				\
	}						\
	MACRO_END
#define SHARED_REGION_TRACE_NONE(args)
#define SHARED_REGION_TRACE_ERROR(args)				\
	MACRO_BEGIN						\
	SHARED_REGION_TRACE(SHARED_REGION_TRACE_ERROR_LVL,	\
			    args);				\
	MACRO_END
#define SHARED_REGION_TRACE_INFO(args)				\
	MACRO_BEGIN						\
	SHARED_REGION_TRACE(SHARED_REGION_TRACE_INFO_LVL,	\
			    args);				\
	MACRO_END
#define SHARED_REGION_TRACE_DEBUG(args)				\
	MACRO_BEGIN						\
	SHARED_REGION_TRACE(SHARED_REGION_TRACE_DEBUG_LVL,	\
			    args);				\
	MACRO_END

typedef struct vm_shared_region *vm_shared_region_t;

#ifdef MACH_KERNEL_PRIVATE

#include <kern/queue.h>
#include <vm/vm_object.h>
#include <vm/memory_object.h>

/* address space shared region descriptor */
struct vm_shared_region {
	uint32_t		sr_ref_count;
	queue_chain_t		sr_q;
	void			*sr_root_dir;
	cpu_type_t		sr_cpu_type;
	boolean_t		sr_64bit;
	boolean_t		sr_mapping_in_progress;
	boolean_t		sr_persists;
	ipc_port_t		sr_mem_entry;
	mach_vm_offset_t	sr_first_mapping;
	mach_vm_offset_t	sr_base_address;
	mach_vm_size_t		sr_size;
	mach_vm_offset_t	sr_pmap_nesting_start;
	mach_vm_size_t		sr_pmap_nesting_size;
	thread_call_t		sr_timer_call;
};

#else  /* !MACH_KERNEL_PRIVATE */

struct vm_shared_region;

#endif /* MACH_KERNEL_PRIVATE */

extern void vm_shared_region_init(void);
extern kern_return_t vm_shared_region_enter(
	struct _vm_map		*map,
	struct task		*task,
	void			*fsroot,
	cpu_type_t		cpu);
extern kern_return_t vm_shared_region_remove(
	struct _vm_map		*map,
	struct task		*task);
extern vm_shared_region_t vm_shared_region_get(
	struct task		*task);
extern void vm_shared_region_deallocate(
	struct vm_shared_region	*shared_region);
extern mach_vm_offset_t vm_shared_region_base_address(
	struct vm_shared_region	*shared_region);
extern mach_vm_size_t vm_shared_region_size(
	struct vm_shared_region	*shared_region);
extern ipc_port_t vm_shared_region_mem_entry(
	struct vm_shared_region	*shared_region);
extern void vm_shared_region_set(
	struct task		*task,
	struct vm_shared_region	*new_shared_region);
extern vm_shared_region_t vm_shared_region_lookup(
	void			*root_dir,
	cpu_type_t		cpu,
	boolean_t		is_64bit);
extern kern_return_t vm_shared_region_start_address(
	struct vm_shared_region	*shared_region,
	mach_vm_offset_t	*start_address);
extern kern_return_t vm_shared_region_map_file(
	struct vm_shared_region	*shared_region,
	unsigned int		mappings_count,
	struct shared_file_mapping_np *mappings,
	memory_object_control_t	file_control,
	memory_object_size_t	file_size,
	void			*root_dir);

extern void vm_commpage_init(void);
extern kern_return_t vm_commpage_enter(
	struct _vm_map		*map,
	struct task		*task);
extern kern_return_t vm_commpage_remove(
	struct _vm_map		*map,
	struct task		*task);

#endif /* KERNEL_PRIVATE */

#endif	/* _VM_SHARED_REGION_H_ */
