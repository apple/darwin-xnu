/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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

#ifndef	_DEFAULT_FREEZER_H_
#define _DEFAULT_FREEZER_H_

#if CONFIG_FREEZE

#ifdef MACH_KERNEL

#include <default_pager/default_pager_internal.h>
#include <default_pager/default_pager_object_server.h>
#include <mach/memory_object_default_server.h>
#include <mach/memory_object_control.h>
#include <mach/memory_object_types.h>
#include <mach/memory_object_server.h>
#include <mach/upl.h>
#include <mach/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h> 
#include <vm/vm_map.h>


/*
 * Begin declaration for default_freezer_ops.
*/
extern void   df_memory_object_reference(memory_object_t);
extern void   df_memory_object_deallocate(memory_object_t);
extern kern_return_t   df_memory_object_init(memory_object_t,
					     memory_object_control_t,
					     memory_object_cluster_size_t);
extern	kern_return_t df_memory_object_terminate(memory_object_t);
extern	kern_return_t   df_memory_object_data_request(memory_object_t, 
						      memory_object_offset_t,
						      memory_object_cluster_size_t,
						      vm_prot_t,
						      memory_object_fault_info_t);
extern kern_return_t df_memory_object_data_return(memory_object_t,
						    memory_object_offset_t,
						    memory_object_cluster_size_t,
						    memory_object_offset_t *,
						    int *,
						    boolean_t,
						    boolean_t,
						    int);
extern kern_return_t df_memory_object_data_initialize(memory_object_t,
						      memory_object_offset_t,
						      memory_object_cluster_size_t);
extern kern_return_t df_memory_object_data_unlock(memory_object_t,
						  memory_object_offset_t,
						  memory_object_size_t,
						  vm_prot_t);
extern kern_return_t df_memory_object_synchronize(memory_object_t,
						  memory_object_offset_t,
						  memory_object_size_t,
						  vm_sync_t);
extern kern_return_t df_memory_object_map(memory_object_t,
					  vm_prot_t);
extern kern_return_t df_memory_object_last_unmap(memory_object_t);

extern kern_return_t df_memory_object_data_reclaim( memory_object_t,
						    boolean_t);
/*
 * End declaration for default_freezer_ops.
*/

const struct memory_object_pager_ops default_freezer_ops = {
	df_memory_object_reference,
	df_memory_object_deallocate,
	df_memory_object_init,
	df_memory_object_terminate,
	df_memory_object_data_request,
	df_memory_object_data_return,
	df_memory_object_data_initialize,
	df_memory_object_data_unlock,
	df_memory_object_synchronize,
	df_memory_object_map,
	df_memory_object_last_unmap,
	df_memory_object_data_reclaim,
	"default freezer"
};

#define MAX_FREEZE_TABLE_ENTRIES 128
 
struct default_freezer_mapping_table_entry {
	memory_object_t memory_object; /* memory object will lead us to the most current VM object */
	memory_object_offset_t offset;
};
typedef struct default_freezer_mapping_table *default_freezer_mapping_table_t;

struct default_freezer_mapping_table {
	struct default_freezer_mapping_table *next;
	vm_object_t object; /* packed object */
	vm_object_offset_t offset;
	unsigned int index;
	struct default_freezer_mapping_table_entry entry[MAX_FREEZE_TABLE_ENTRIES];
};
typedef struct default_freezer_mapping_table_entry *default_freezer_mapping_table_entry_t;

struct default_freezer_handle {
	lck_rw_t				dfh_lck;
	uint32_t				dfh_ref_count;
	default_freezer_mapping_table_t		dfh_table;
	vm_object_t				dfh_compact_object;
	vm_object_offset_t			dfh_compact_offset;
};
typedef struct default_freezer_handle	*default_freezer_handle_t;

struct default_freezer_memory_object{
	struct ipc_object_header	fo_pager_header;	/* fake ip_kotype() */
	memory_object_pager_ops_t	fo_pager_ops; 		/* == &default_freezer_ops */
	memory_object_control_t		fo_pager_control;
	default_freezer_handle_t	fo_df_handle;
};
typedef struct default_freezer_memory_object *default_freezer_memory_object_t;


__private_extern__ void	default_freezer_handle_lock(default_freezer_handle_t);
__private_extern__ void	default_freezer_handle_unlock(default_freezer_handle_t);

extern lck_grp_attr_t	default_freezer_handle_lck_grp_attr;	
extern lck_grp_t	default_freezer_handle_lck_grp;

__private_extern__ default_freezer_mapping_table_t	default_freezer_mapping_create(vm_object_t, vm_offset_t);

__private_extern__ void		default_freezer_mapping_free(default_freezer_mapping_table_t *table_p, boolean_t all);

__private_extern__  kern_return_t	default_freezer_mapping_store( default_freezer_mapping_table_t ,
									memory_object_offset_t,
									memory_object_t,
									memory_object_offset_t );

__private_extern__ kern_return_t	default_freezer_mapping_update( default_freezer_mapping_table_t, 
									memory_object_t,
									memory_object_offset_t,
									memory_object_offset_t *,
									boolean_t );

__private_extern__ void	default_freezer_handle_reference_locked(default_freezer_handle_t);

__private_extern__ boolean_t	default_freezer_handle_deallocate_locked(default_freezer_handle_t);

__private_extern__ void	default_freezer_memory_object_create(vm_object_t, default_freezer_handle_t);

#endif /* MACH_KERNEL */
#endif /* CONFIG_FREEZE */
#endif /* DEFAULT_FREEZER_H */
