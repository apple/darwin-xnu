/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 *
 *	File: vm/vm_shared_memory_server.h
 *
 * 	protos and struct definitions for shared library
 *	server and interface
 */

#ifndef _VM_SHARED_MEMORY_SERVER_H_
#define _VM_SHARED_MEMORY_SERVER_H_

#ifdef	KERNEL_PRIVATE

#include <mach/vm_prot.h>
#include <mach/mach_types.h>
#include <mach/shared_memory_server.h>

#include <kern/kern_types.h>
#include <kern/macro_help.h>

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
#define SHARED_REGION_TRACE_NONE	0	/* no trace */
#define SHARED_REGION_TRACE_ERROR	1	/* trace abnormal events */
#define SHARED_REGION_TRACE_CONFLICT	2	/* trace library conflicts */
#define SHARED_REGION_TRACE_INFO	3	/* trace all events */
#define SHARED_REGION_TRACE(level, args)		\
	MACRO_BEGIN					\
	if (level <= shared_region_trace_level) {	\
		printf args;				\
	}						\
	MACRO_END

struct shared_region_task_mappings {
	mach_port_t		text_region;
	vm_size_t		text_size;
	mach_port_t		data_region;
	vm_size_t		data_size;
	vm_offset_t		region_mappings;
	vm_offset_t		client_base;
	vm_offset_t		alternate_base;
	vm_offset_t		alternate_next;
	unsigned int		fs_base;
	unsigned int		system;
	int			flags;
	vm_offset_t		self;
};

#define SHARED_REGION_SYSTEM	0x1 // Default env for system and fs_root
#define SHARED_REGION_FULL	0x2 // Shared regions are full
#define SHARED_REGION_STALE 	0x4 // Indicates no longer in default list
#define SHARED_REGION_STANDALONE 0x10 // Shared region is not shared !


/* defines for default environment, and co-resident systems */

#define ENV_DEFAULT_ROOT	0

typedef	struct shared_region_task_mappings *shared_region_task_mappings_t;
typedef struct shared_region_mapping *shared_region_mapping_t;

#ifdef MACH_KERNEL_PRIVATE

#include <kern/queue.h>
#include <vm/vm_object.h>
#include <vm/memory_object.h>

extern vm_offset_t     shared_file_mapping_array;

struct loaded_mapping {
	vm_offset_t	mapping_offset;
	vm_size_t	size;
	vm_offset_t	file_offset;
	vm_prot_t	protection;  /* read/write/execute/COW/ZF */
	
	struct loaded_mapping *next;
};

typedef struct loaded_mapping loaded_mapping_t;

struct load_struct {
	queue_chain_t   	links;  
	shared_region_mapping_t	regions_instance;
	int			depth;
	int			file_object;
	vm_offset_t		base_address;
	int			mapping_cnt;
	loaded_mapping_t	*mappings;
        vm_offset_t             file_offset; // start of file we mapped in
};

typedef struct load_struct load_struct_t;
typedef struct load_struct *load_struct_ptr_t;

struct load_file_ele {
	union {
		sf_mapping_t	mapping;
		load_struct_t	element;
	} u;
};

struct shared_file_info {
	mutex_t	    	lock;   /* lock for the structure */
	queue_head_t	*hash;  /* for later perf enhance */
	int		hash_size;
	boolean_t	hash_init;
};

typedef struct shared_file_info shared_file_info_t;

struct shared_region_object_chain {
	shared_region_mapping_t	object_chain_region;
	int			depth;
	struct shared_region_object_chain *next;
};
typedef struct shared_region_object_chain *shared_region_object_chain_t;

/* address space shared region descriptor */
struct shared_region_mapping {
        decl_mutex_data(,       Lock)   /* Synchronization */
	unsigned int		ref_count;
	unsigned int		fs_base;
	unsigned int		system;
	mach_port_t		text_region;
	vm_size_t		text_size;
	mach_port_t		data_region;
	vm_size_t		data_size;
	vm_offset_t		region_mappings;
	vm_offset_t		client_base;
	vm_offset_t		alternate_base;
	vm_offset_t		alternate_next;
	int			flags;
	int			depth;
	shared_region_mapping_t default_env_list;
	shared_region_object_chain_t object_chain;
	shared_region_mapping_t self;
	shared_region_mapping_t next;
};

#define shared_region_mapping_lock_init(object)   \
			mutex_init(&(object)->Lock, 0)
#define shared_region_mapping_lock(object)        mutex_lock(&(object)->Lock)
#define shared_region_mapping_unlock(object)      mutex_unlock(&(object)->Lock)

#else  /* !MACH_KERNEL_PRIVATE */

struct shared_region_mapping ;

#endif /* MACH_KERNEL_PRIVATE */

#define load_file_hash(file_object, size) \
		((((natural_t)file_object) & 0xffffff) % size)

extern kern_return_t map_shared_file(
	int 				map_cnt,
	struct shared_file_mapping_np 	*mappings,
	memory_object_control_t		file_control,
	memory_object_size_t		file_size,
	shared_region_task_mappings_t	sm_info,
	mach_vm_offset_t		base_offset,
	mach_vm_offset_t		*slide_p);

extern kern_return_t shared_region_cleanup(
	unsigned int			range_count,
	struct shared_region_range_np	*ranges,
	shared_region_task_mappings_t	sm_info);

extern kern_return_t shared_region_mapping_info(
				shared_region_mapping_t	shared_region,
				mach_port_t		*text_region,
				vm_size_t		*text_size,
				mach_port_t		*data_region,
				vm_size_t		*data_size,
				vm_offset_t		*region_mappings,
				vm_offset_t		*client_base,
				vm_offset_t		*alternate_base,
				vm_offset_t		*alternate_next,
				unsigned int		*fs_base,
				unsigned int		*system,
				int			*flags,
				shared_region_mapping_t	*next);

extern kern_return_t shared_region_mapping_create(
				mach_port_t		text_region,
				vm_size_t		text_size,
				mach_port_t		data_region,
				vm_size_t		data_size,
				vm_offset_t		region_mappings,
				vm_offset_t		client_base,
				shared_region_mapping_t	*shared_region,
				vm_offset_t		alt_base,
				vm_offset_t		alt_next,
				int			fs_base,
				int			system);

extern kern_return_t shared_region_mapping_ref(
				shared_region_mapping_t	shared_region);

extern kern_return_t shared_region_mapping_dealloc(
				shared_region_mapping_t	shared_region);

extern kern_return_t shared_region_object_chain_attach(
				shared_region_mapping_t	target_region,
				shared_region_mapping_t	object_chain);

extern void shared_region_object_chain_detached(
	shared_region_mapping_t	target_region);

extern kern_return_t vm_get_shared_region(
				task_t	task,
				shared_region_mapping_t	*shared_region);

extern kern_return_t vm_set_shared_region(
				task_t	task,
				shared_region_mapping_t	shared_region);

extern shared_region_mapping_t update_default_shared_region(
				shared_region_mapping_t new_system_region);

extern shared_region_mapping_t lookup_default_shared_region(
				unsigned int fs_base,
				unsigned int system);

extern void remove_default_shared_region(
				shared_region_mapping_t system_region);

__private_extern__ void remove_default_shared_region_lock(
				shared_region_mapping_t system_region,
				int need_sfh_lock,
				int need_drl_lock);

__private_extern__ struct load_struct *lsf_remove_regions_mappings_lock(
				shared_region_mapping_t	region,
				shared_region_task_mappings_t	sm_info,
				int need_lock);

extern unsigned int lsf_mapping_pool_gauge(void);

extern kern_return_t shared_file_create_system_region(
	shared_region_mapping_t	*shared_region,
	int			fs_base,
	int			system);

extern void remove_all_shared_regions(void);

extern void shared_file_boot_time_init(
		unsigned int fs_base, 
		unsigned int system);

extern struct load_struct *lsf_remove_regions_mappings(
	shared_region_mapping_t	region,
	shared_region_task_mappings_t	sm_info);

extern void mach_memory_entry_port_release(ipc_port_t port);
extern void mach_destroy_memory_entry(ipc_port_t port);

extern kern_return_t mach_memory_entry_purgable_control(
	ipc_port_t	entry_port,
	vm_purgable_t	control,
	int		*state);

extern kern_return_t mach_memory_entry_page_op(
	ipc_port_t		entry_port,
	vm_object_offset_t	offset,
	int			ops,
	ppnum_t			*phys_entry,
	int			*flags);

extern kern_return_t mach_memory_entry_range_op(
	ipc_port_t		entry_port,
	vm_object_offset_t	offset_beg,
	vm_object_offset_t	offset_end,
	int                     ops,
	int                     *range);

#endif /* KERNEL_PRIVATE */

#endif	/* _VM_SHARED_MEMORY_SERVER_H_ */
