/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *	File: kern/shared_memory_server.h
 *
 * 	protos and struct definitions for shared library
 *	server and interface
 */
#ifndef _SHARED_MEMORY_SERVER_H_
#define _SHARED_MEMORY_SERVER_H_

#define		SHARED_TEXT_REGION_SIZE 0x10000000
#define		SHARED_DATA_REGION_SIZE 0x10000000
/* 
 *  Note: the two masks below are useful because the assumption is 
 *  made that these shared regions will always be mapped on natural boundaries 
 *  i.e. if the size is 0x10000000 the object can be mapped at 
 *  0x20000000, or 0x30000000, but not 0x1000000
 */
#define		SHARED_TEXT_REGION_MASK 0xFFFFFFF
#define		SHARED_DATA_REGION_MASK 0xFFFFFFF

#define		SHARED_ALTERNATE_LOAD_BASE 0x9000000

#include <mach/vm_prot.h>
#ifndef MACH_KERNEL
#include <mach/mach.h>
#else
#include <vm/vm_map.h>
#endif

#ifdef MACH_KERNEL_PRIVATE

#include <kern/queue.h>
#include <vm/vm_object.h>

extern ipc_port_t      shared_text_region_handle;
extern ipc_port_t      shared_data_region_handle;
#else /* MACH_KERNEL_PRIVATE */

#ifdef KERNEL_PRIVATE
extern mach_port_t      shared_text_region_handle;
extern mach_port_t      shared_data_region_handle;
#endif
#endif /* MACH_KERNEL_PRIVATE*/

#ifdef KERNEL_PRIVATE

extern vm_offset_t     shared_file_mapping_array;


struct shared_region_task_mappings {
	ipc_port_t		text_region;
	vm_size_t		text_size;
	ipc_port_t		data_region;
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
#endif /* KERNEL_PRIVATE */


#define SHARED_LIB_ALIAS  0x10


/* flags field aliases for copyin_shared_file and load_shared_file */

/* IN */
#define ALTERNATE_LOAD_SITE 0x1
#define NEW_LOCAL_SHARED_REGIONS 0x2

/* OUT */
#define SF_PREV_LOADED    0x1


#define load_file_hash(file_object, size) \
		((((natural_t)file_object) & 0xffffff) % size)

#define VM_PROT_COW  0x8  /* must not interfere with normal prot assignments */
#define VM_PROT_ZF  0x10  /* must not interfere with normal prot assignments */

struct sf_mapping {
	vm_offset_t	mapping_offset;
	vm_size_t	size;
	vm_offset_t	file_offset;
	vm_prot_t	protection;  /* read/write/execute/COW/ZF */
	vm_offset_t	cksum;
};

typedef struct sf_mapping sf_mapping_t;


#ifdef MACH_KERNEL_PRIVATE

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

#endif /* MACH_KERNEL_PRIVATE */

typedef struct load_struct load_struct_t;
typedef struct load_struct *load_struct_ptr_t;

#ifdef MACH_KERNEL_PRIVATE

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

extern kern_return_t                                   
copyin_shared_file(
        vm_offset_t     mapped_file,
        vm_size_t       mapped_file_size,
        vm_offset_t     *base_address,
        int             map_cnt,
        sf_mapping_t    *mappings,
        vm_object_t     file_object,
	shared_region_task_mappings_t	shared_region,
        int             *flags);

extern kern_return_t           
shared_file_init(               
        ipc_port_t      *shared_text_region_handle,
        vm_size_t       text_region_size,
        ipc_port_t      *shared_data_region_handle,
        vm_size_t       data_region_size, 
        vm_offset_t     *shared_file_mapping_array);

extern load_struct_t  *
lsf_hash_lookup(   
        queue_head_t    		*hash_table,
        void    			*file_object,  
        int     			size,
	boolean_t			alternate,
	shared_region_task_mappings_t	sm_info);

extern load_struct_t *
lsf_hash_delete(
        void            		*file_object,
	vm_offset_t			base_offset,
	shared_region_task_mappings_t	sm_info);

extern void    
lsf_hash_insert(
        load_struct_t   *entry,
	shared_region_task_mappings_t	sm_info);

extern kern_return_t                   
lsf_load(
        vm_offset_t		 	mapped_file,
        vm_size_t      			mapped_file_size,
        vm_offset_t    			*base_address,
        sf_mapping_t   			*mappings,
        int            			map_cnt,
        void           			*file_object,
        int           			flags,
	shared_region_task_mappings_t	sm_info);

extern void
lsf_unload(
        void     			*file_object,
	vm_offset_t			base_offset,
	shared_region_task_mappings_t	sm_info);

#endif /* MACH_KERNEL_PRIVATE */
#endif /* _SHARED_MEMORY_SERVER_H_ */
