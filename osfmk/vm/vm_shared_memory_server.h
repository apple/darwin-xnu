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
 *
 *	File: vm/vm_shared_memory_server.h
 *
 * 	protos and struct definitions for shared library
 *	server and interface
 */

#ifndef _VM_SHARED_MEMORY_SERVER_H_
#define _VM_SHARED_MEMORY_SERVER_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE

#include <mach/vm_prot.h>
#include <mach/mach_types.h>
#include <mach/shared_memory_server.h>

#include <kern/kern_types.h>

extern mach_port_t      shared_text_region_handle;
extern mach_port_t      shared_data_region_handle;

struct shared_region_task_mappings {
	mach_port_t		text_region;
	vm_size_t		text_size;
	mach_port_t		data_region;
	vm_size_t		data_size;
	vm_offset_t		region_mappings;
	vm_offset_t		client_base;
	vm_offset_t		alternate_base;
	vm_offset_t		alternate_next;
	int			flags;
	vm_offset_t		self;
};

#define SHARED_REGION_SYSTEM	0x1
#define SHARED_REGION_FULL	0x2

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
	int			ref_count;
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
	shared_region_object_chain_t object_chain;
	shared_region_mapping_t self;
	shared_region_mapping_t next;
};

#define shared_region_mapping_lock_init(object)   \
			mutex_init(&(object)->Lock, ETAP_VM_OBJ)
#define shared_region_mapping_lock(object)        mutex_lock(&(object)->Lock)
#define shared_region_mapping_unlock(object)      mutex_unlock(&(object)->Lock)

#else  /* !MACH_KERNEL_PRIVATE */

struct shared_region_mapping ;

#endif /* MACH_KERNEL_PRIVATE */

extern kern_return_t copyin_shared_file(
				vm_offset_t     	mapped_file,
				vm_size_t       	mapped_file_size,
				vm_offset_t     	*base_address,
				int             	map_cnt,
				sf_mapping_t    	*mappings,
				memory_object_control_t		file_control,
				shared_region_task_mappings_t	shared_region,
				int             	*flags);

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
				vm_offset_t		alt_next);

extern kern_return_t shared_region_mapping_ref(
				shared_region_mapping_t	shared_region);

extern kern_return_t shared_region_mapping_dealloc(
				shared_region_mapping_t	shared_region);

extern kern_return_t shared_region_object_chain_attach(
				shared_region_mapping_t	target_region,
				shared_region_mapping_t	object_chain);

extern kern_return_t vm_get_shared_region(
				task_t	task,
				shared_region_mapping_t	*shared_region);

extern kern_return_t vm_set_shared_region(
				task_t	task,
				shared_region_mapping_t	shared_region);

extern unsigned int lsf_mapping_pool_gauge();

#endif /* __APPLE_API_PRIVATE */

#endif /* _VM_SHARED_MEMORY_SERVER_H_ */
