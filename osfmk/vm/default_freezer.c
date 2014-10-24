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

#if CONFIG_FREEZE

#ifndef CONFIG_MEMORYSTATUS
#error "CONFIG_FREEZE defined without matching CONFIG_MEMORYSTATUS"
#endif

#include <vm/default_freezer.h>

/*
 * Indicates that a page has been faulted back in.
 */
#define FREEZER_OFFSET_ABSENT ((vm_object_offset_t)(-1))

lck_grp_attr_t	default_freezer_handle_lck_grp_attr;	
lck_grp_t	default_freezer_handle_lck_grp;

void
default_freezer_init(void)
{
	lck_grp_attr_setdefault(&default_freezer_handle_lck_grp_attr);
	lck_grp_init(&default_freezer_handle_lck_grp, "default_freezer_handle",
		     &default_freezer_handle_lck_grp_attr);

}


/*
 * Create the mapping table that will
 * tell us the object/offset pair that
 * corresponds to the page being sent
 * out or being brought back in.
 */

default_freezer_mapping_table_t
default_freezer_mapping_create(vm_object_t object, vm_offset_t offset)
{
	default_freezer_mapping_table_t table;
	
	table = kalloc(sizeof(struct default_freezer_mapping_table));
	if (table) {
		memset(table, 0, sizeof(*table));
	} else {
		panic("Could not allocate mapping table\n");
	}
	
	table->object = object;
	table->offset = offset;
	
	return table;
}

/*
 * Table modifications/lookup are done behind
 * the compact_object lock.
 */

void
default_freezer_mapping_free(default_freezer_mapping_table_t *table_p, boolean_t all)
{	
	default_freezer_mapping_table_t freezer_table = *table_p;
	assert(freezer_table);
	
	if (all) {
		do { 
			default_freezer_mapping_table_t next = freezer_table->next;
			kfree(freezer_table, sizeof(*freezer_table));
			freezer_table = next;	
		} while (freezer_table);
	} else {
		kfree(freezer_table, sizeof(*freezer_table));
	}
}
 
kern_return_t
default_freezer_mapping_store(
		default_freezer_mapping_table_t table,
		memory_object_offset_t table_offset,
		memory_object_t memory_object,
		memory_object_offset_t offset)
{
	default_freezer_mapping_table_entry_t entry;
	uint32_t index;

	assert(table);

	while (table->next) {
		table = table->next;
	}

	if (table->index >= MAX_FREEZE_TABLE_ENTRIES) {
		vm_object_t compact_object = table->object;
		default_freezer_mapping_table_t next;
		
		next = default_freezer_mapping_create(compact_object, table_offset);
		if (!next) {
			return KERN_FAILURE;
		}
		table->next = next;
	}

	index = (table)->index++;
	entry = &(table)->entry[index];

	entry->memory_object = memory_object;
	entry->offset = offset;
	
	return KERN_SUCCESS;
}

kern_return_t
default_freezer_mapping_update(
		default_freezer_mapping_table_t table, 
		memory_object_t memory_object,
		memory_object_offset_t offset,
		memory_object_offset_t *table_offset, /*OUT: contains the offset into the compact object*/
		boolean_t remove_entry)
{

	kern_return_t kr = KERN_SUCCESS;
	vm_object_offset_t compact_offset;
	default_freezer_mapping_table_entry_t entry;
	uint32_t index = 0;
	
	if (table == NULL){
		return KERN_FAILURE;
	}

	compact_offset = table->offset;

	while (1) {	
		if (index >= table->index) {
			if (table->next) {
				table = table->next;
				index = 0;
			} else {
				/* End of tables and we didn't find our candidate entry */
				kr = KERN_FAILURE;
				break;
			}
		}

		entry = &table->entry[index];

		if (memory_object == entry->memory_object && offset == entry->offset) {
			if (remove_entry == TRUE) {
				/*
				 * Mark the page absent whilst retaining the object 
				 * for cleanup during thaw.
				 */
				entry->offset = FREEZER_OFFSET_ABSENT;
			}
			if (table_offset != NULL) {
				*table_offset = compact_offset;
			}
			break;
		}
	
		index++;
		compact_offset += PAGE_SIZE;
	}
	return kr;
}



/*
 * Create a freezer memory object for this
 * vm object. This will be one of the vm
 * objects that will pack the compact object.
 */
void
default_freezer_memory_object_create(
			vm_object_t	object,
			default_freezer_handle_t df_handle)
{

	default_freezer_memory_object_t fo = NULL;
	
	fo = kalloc(sizeof(struct default_freezer_memory_object));

	if (fo) {
		memory_object_control_t control = NULL;

		memset(fo, 0, sizeof(*fo));
		
		control = memory_object_control_allocate(object);
		assert (control != MEMORY_OBJECT_CONTROL_NULL);

		df_memory_object_init((memory_object_t)fo, control, 0);		
		fo->fo_df_handle = df_handle;

		default_freezer_handle_reference_locked(fo->fo_df_handle);
	
		object->pager = (memory_object_t)fo;
		object->pager_created = TRUE;
		object->pager_initialized = TRUE;
		object->pager_ready = TRUE;
		object->pager_trusted = TRUE;
		object->pager_control = control;
	} else {
		panic(" Could not allocate freezer object\n");
	}
}

kern_return_t
default_freezer_pack(
	unsigned int	*purgeable_count,
	unsigned int	*wired_count,
	unsigned int	*clean_count,
	unsigned int	*dirty_count,
	unsigned int	dirty_budget,
	boolean_t	*shared,
	vm_object_t	src_object,
	default_freezer_handle_t df_handle)
{
	kern_return_t			kr = KERN_SUCCESS;

	if (df_handle) {
		default_freezer_handle_lock(df_handle);
	}

	kr = vm_object_pack(purgeable_count, wired_count, clean_count, dirty_count, dirty_budget, shared, src_object, df_handle);
	
	if (df_handle) {
		default_freezer_handle_unlock(df_handle);
	}

	return kr;
}

/* 
 * Called with freezer_handle locked.
 * default_freezer_pack locks the handle, calls
 * vm_object_pack which, in turn, will call
 * default_freezer_pack_page().
 */
void
default_freezer_pack_page(
		vm_page_t p, 
		default_freezer_handle_t df_handle)
{

	default_freezer_mapping_table_t freeze_table = NULL;
	memory_object_t 		memory_object = NULL;
	vm_object_t			compact_object =  VM_OBJECT_NULL;

	assert(df_handle);

	compact_object = df_handle->dfh_compact_object;

	assert(compact_object);

	freeze_table =  df_handle->dfh_table;
	memory_object = p->object->pager;

	if (memory_object == NULL) {
		default_freezer_memory_object_create(p->object, df_handle);
		memory_object = p->object->pager;
	} else {
		assert(df_handle == ((default_freezer_memory_object_t)memory_object)->fo_df_handle);
	}

	vm_object_lock(compact_object);
	default_freezer_mapping_store(freeze_table, df_handle->dfh_compact_offset, memory_object, p->offset + p->object->paging_offset);
	vm_page_rename(p, compact_object, df_handle->dfh_compact_offset, FALSE);
	vm_object_unlock(compact_object);
	
	df_handle->dfh_compact_offset += PAGE_SIZE;
}


kern_return_t
default_freezer_unpack(
		 default_freezer_handle_t df_handle)
{
	
	vm_page_t 				compact_page = VM_PAGE_NULL, src_page = VM_PAGE_NULL;
	uint32_t 				index = 0;
	vm_object_t 				src_object = VM_OBJECT_NULL;
	vm_object_t				compact_object = VM_OBJECT_NULL;
	memory_object_t				src_mem_object = MEMORY_OBJECT_NULL;
	memory_object_offset_t			src_offset = 0;
	vm_object_offset_t			compact_offset = 0;
	default_freezer_memory_object_t		fo = NULL;
	default_freezer_mapping_table_t 	freeze_table = NULL;
	boolean_t				should_unlock_handle = FALSE;
	kern_return_t				kr;

	assert(df_handle);

	default_freezer_handle_lock(df_handle);
	should_unlock_handle = TRUE;

	freeze_table = df_handle->dfh_table;	
	compact_object = df_handle->dfh_compact_object;

	assert(compact_object);
	assert(compact_object->alive);
	assert(!compact_object->terminating);
	assert(compact_object->pager_ready);
	
	/* Bring the pages back in */
	if ((kr = vm_object_pagein(compact_object)) != KERN_SUCCESS) {
		if (should_unlock_handle) {
			default_freezer_handle_unlock(df_handle);
		}
        	return (kr);
	}

	vm_object_lock(compact_object);
	
	for (index = 0, compact_offset = 0; ; index++, compact_offset += PAGE_SIZE){
		if (index >= freeze_table->index) {
			default_freezer_mapping_table_t table_next;
			
			table_next = freeze_table->next; 
			
			/* Free the tables as we go along */
			default_freezer_mapping_free(&freeze_table, FALSE);
		
			if (table_next == NULL){
				break;
			}
			
			freeze_table = table_next;
			index = 0;
		}

		/* 
		 * Skip slots that represent deallocated memory objects.
		 */
		src_mem_object = freeze_table->entry[index].memory_object;
		if (src_mem_object == MEMORY_OBJECT_NULL)
			continue;

		/* 
		 * Skip slots that represent faulted pages.
		 */
		src_offset = freeze_table->entry[index].offset;
		if (src_offset != FREEZER_OFFSET_ABSENT) {
			
			compact_page = vm_page_lookup(compact_object, compact_offset);
			assert(compact_page);

			fo = (default_freezer_memory_object_t)src_mem_object;
		
			src_object = memory_object_control_to_vm_object(fo->fo_pager_control); 
	
			/* Move back over from the freeze object to the original */
			vm_object_lock(src_object);
			src_page = vm_page_lookup(src_object, src_offset - src_object->paging_offset);
			if (src_page != VM_PAGE_NULL){
				/*
				 * We might be racing with a VM fault. 
				 * So handle that gracefully.
				 */
				assert(src_page->absent == TRUE);
				VM_PAGE_FREE(src_page);
			}
			vm_page_rename(compact_page, src_object, src_offset - src_object->paging_offset, FALSE);
			vm_object_unlock(src_object);
		}
		
	}
	
	vm_object_unlock(compact_object);
	
	vm_object_deallocate(compact_object);
	
	if (should_unlock_handle) {
		df_handle->dfh_table = NULL;
		df_handle->dfh_compact_object = VM_OBJECT_NULL;
		df_handle->dfh_compact_offset = 0;
		default_freezer_handle_unlock(df_handle);
	}
	return (KERN_SUCCESS);
}

void
df_memory_object_reference(__unused memory_object_t mem_obj)
{

	/* No-op */
}

void
df_memory_object_deallocate(memory_object_t mem_obj)
{

	default_freezer_memory_object_t	fo = (default_freezer_memory_object_t)mem_obj;

	assert(fo);
	
	if (fo->fo_df_handle != NULL) {
		
		default_freezer_mapping_table_t table = NULL;
		default_freezer_mapping_table_entry_t entry;
		boolean_t found = FALSE;
		uint32_t index = 0;
		vm_object_t compact_object = VM_OBJECT_NULL;
		
		default_freezer_handle_lock(fo->fo_df_handle);

		compact_object =  fo->fo_df_handle->dfh_compact_object;
		table = fo->fo_df_handle->dfh_table;

		if (compact_object == VM_OBJECT_NULL || table == NULL) {
			/*Nothing to do. A thaw must have cleared it all out.*/
		} else {
			vm_object_lock(compact_object);
		
			/* Remove from table */
			while (1) {	
				if (index >= table->index) {
					if (table->next) {
						table = table->next;
						index = 0;
					} else {
						/* End of tables */
						break;
					}
				}

				entry = &table->entry[index];
				if (mem_obj == entry->memory_object) {
					/* It matches, so clear the entry */
					if (!found) {
						found = TRUE;
					} 
					entry->memory_object = MEMORY_OBJECT_NULL;
					entry->offset = 0;
				} else if (MEMORY_OBJECT_NULL != entry->memory_object) {
					/* We have a different valid object; we're done */
					if (found) {
						break;
					}
				}
			
				index++;
			}
		
			vm_object_unlock(compact_object);
		}

		if (default_freezer_handle_deallocate_locked(fo->fo_df_handle)) {
			default_freezer_handle_unlock(fo->fo_df_handle);
		}	
	}

	kfree(fo, sizeof(*fo));
}

kern_return_t
df_memory_object_init(
		memory_object_t mem_obj,
		memory_object_control_t control,
		__unused memory_object_cluster_size_t pager_page_size)
{

	default_freezer_memory_object_t	fo = (default_freezer_memory_object_t)mem_obj;
	assert(fo);

	fo->fo_pager_ops = &default_freezer_ops;
	fo->fo_pager_header.io_bits = IKOT_MEMORY_OBJECT;
	fo->fo_pager_control = control;
	
	return KERN_SUCCESS;
}

kern_return_t
df_memory_object_terminate(memory_object_t mem_obj)
{

	default_freezer_memory_object_t	fo = (default_freezer_memory_object_t)mem_obj;
	assert(fo);
	memory_object_control_deallocate(fo->fo_pager_control);
	return KERN_SUCCESS;
}


kern_return_t
df_memory_object_data_request(
		memory_object_t mem_obj, 
		memory_object_offset_t offset,
		memory_object_cluster_size_t length,
		vm_prot_t protection_required,
		memory_object_fault_info_t fault_info)
{

	vm_object_t	src_object = VM_OBJECT_NULL, compact_object = VM_OBJECT_NULL;
	memory_object_offset_t	compact_offset = 0;
	memory_object_t pager = NULL;
	kern_return_t kr = KERN_SUCCESS;
	boolean_t	drop_object_ref = FALSE;
	vm_page_t compact_page, dst_page;

	default_freezer_memory_object_t fo = (default_freezer_memory_object_t)mem_obj;
	default_freezer_handle_t	df_handle = NULL;

	df_handle = fo->fo_df_handle;

	if (df_handle == NULL) {
		kr = KERN_FAILURE;
	} else {
		default_freezer_handle_lock(df_handle);
		
		src_object = memory_object_control_to_vm_object(fo->fo_pager_control);
		compact_object = fo->fo_df_handle->dfh_compact_object;
	
		if (compact_object == NULL) {
			kr = KERN_FAILURE;
		} else {	
			vm_object_lock(compact_object);
			vm_object_reference_locked(compact_object);
			drop_object_ref = TRUE;

			kr = default_freezer_mapping_update(fo->fo_df_handle->dfh_table,
								mem_obj,
								offset,
								&compact_offset,
								FALSE);
			vm_object_unlock(compact_object);
		}
		default_freezer_handle_unlock(df_handle);
	}
	

	if (length == 0){
		/*Caller is just querying to see if we have the page*/
		if (drop_object_ref) {
			vm_object_deallocate(compact_object);
		}
		return kr;
	}

	if (kr != KERN_SUCCESS){

		unsigned int request_flags;
		upl_t        upl;
		unsigned int page_list_count = 0;

		request_flags = UPL_NO_SYNC | UPL_RET_ONLY_ABSENT | UPL_SET_LITE | UPL_SET_INTERNAL;
		/*
		 * Should we decide to activate USE_PRECIOUS (from default_pager_internal.h)
		 * here, then the request_flags will need to add these to the ones above:
		 *
		 * request_flags |= UPL_PRECIOUS | UPL_CLEAN_IN_PLACE
		 */
		request_flags |= UPL_REQUEST_SET_DIRTY;

		memory_object_super_upl_request(fo->fo_pager_control,
						(memory_object_offset_t)offset,
						PAGE_SIZE, PAGE_SIZE, 
						&upl, NULL, &page_list_count,
						request_flags);
		upl_range_needed(upl, 0, 1);

		upl_abort(upl, UPL_ABORT_UNAVAILABLE);
		upl_deallocate(upl);
		
		if (drop_object_ref) {
			vm_object_deallocate(compact_object);
		}

		return KERN_SUCCESS;
	}
	vm_object_lock(compact_object);

	assert(compact_object->alive);
	assert(!compact_object->terminating);

	/*
	 * note that the activity_in_progress could be non-zero, but
	 * the pager has not yet been created since the activity_in_progress
	 * count is bumped via vm_pageout_cluster, while the pager isn't created
	 * until the pageout thread runs and starts to process the pages
	 * placed on the I/O queue... once the processing of the compact object
	 * proceeds to the point where it's placed the first page on the I/O
	 * queue, we need to wait until the entire freeze operation has completed.
	 */
	vm_object_paging_wait(compact_object, THREAD_UNINT);

	if (compact_object->pager_ready) {
		vm_object_paging_begin(compact_object);

		compact_object->blocked_access = TRUE;
		pager = (memory_object_t)compact_object->pager;

		vm_object_unlock(compact_object);

		((vm_object_fault_info_t) fault_info)->io_sync = TRUE;

		/*
		 * We have a reference on both the default_freezer
		 * memory object handle and the compact object.
		 */
		kr = dp_memory_object_data_request(pager,
						   compact_offset,
						   length,
						   protection_required,
						   fault_info);
		if (kr != KERN_SUCCESS)
			panic("%d: default_freezer TOC pointed us to default_pager incorrectly\n", kr);

		vm_object_lock(compact_object);

		compact_object->blocked_access = FALSE;
		vm_object_paging_end(compact_object);
	}
	vm_object_lock(src_object);

	if ((compact_page = vm_page_lookup(compact_object, compact_offset)) != VM_PAGE_NULL){
			
		dst_page = vm_page_lookup(src_object, offset - src_object->paging_offset);
			
		if (dst_page && !dst_page->absent){
			/*
			 * Someone raced us here and unpacked
			 * the object behind us.
			 * So cleanup before we return.
			 */
			VM_PAGE_FREE(compact_page);
		} else {
			if (dst_page != NULL) {
				VM_PAGE_FREE(dst_page);
			}
			vm_page_rename(compact_page, src_object, offset - src_object->paging_offset, FALSE);
				
			if (default_freezer_mapping_update(fo->fo_df_handle->dfh_table,
							   mem_obj,
							   offset,
							   NULL,
							   TRUE) != KERN_SUCCESS) {
				printf("Page for object: 0x%lx at offset: 0x%lx not found in table\n", (uintptr_t)src_object, (uintptr_t)offset);
			}
			
			PAGE_WAKEUP_DONE(compact_page);
		}
	} else {
		printf("%d: default_freezer: compact_object doesn't have the page for object 0x%lx at offset 0x%lx \n", kr, (uintptr_t)compact_object, (uintptr_t)compact_offset);
		kr = KERN_SUCCESS;
	}
	vm_object_unlock(src_object);
	vm_object_unlock(compact_object);
	vm_object_deallocate(compact_object);

	return kr;
}

kern_return_t
df_memory_object_data_return(
		__unused memory_object_t		mem_obj,
		__unused memory_object_offset_t	offset,
		__unused memory_object_cluster_size_t			size,
		__unused memory_object_offset_t	*resid_offset,
		__unused int		*io_error,
		__unused boolean_t	dirty,
		__unused boolean_t	kernel_copy,
		__unused int	upl_flags)
{

	panic(" default_freezer: df_memory_object_data_return should not be called\n");
	return KERN_SUCCESS;
}

kern_return_t
df_memory_object_data_initialize(
		__unused memory_object_t mem_obj,
		__unused  memory_object_offset_t offset,
		__unused memory_object_cluster_size_t size)
{
	
	panic(" default_freezer: df_memory_object_data_initialize should not be called\n");
	return KERN_SUCCESS;
}

kern_return_t
df_memory_object_data_unlock(
		__unused memory_object_t mem_obj,
		__unused memory_object_offset_t offset,
		__unused memory_object_size_t length,
		__unused vm_prot_t prot)
{

	panic(" default_freezer: df_memory_object_data_unlock should not be called\n");
	return KERN_FAILURE;
}

kern_return_t
df_memory_object_synchronize(
		__unused memory_object_t mem_obj,
		__unused memory_object_offset_t offset,
		__unused memory_object_size_t length,
		__unused vm_sync_t flags)
{

	panic(" default_freezer: df_memory_object_synchronize should not be called\n");
	return KERN_FAILURE;
}

kern_return_t
df_memory_object_map(
		__unused memory_object_t mem_obj,
		__unused vm_prot_t prot)
{

	panic(" default_freezer: df_memory_object_map should not be called\n");
	return KERN_FAILURE;
}

kern_return_t
df_memory_object_last_unmap(__unused memory_object_t mem_obj)
{

	panic(" default_freezer: df_memory_object_last_unmap should not be called\n");
	return KERN_FAILURE;
}


kern_return_t
df_memory_object_data_reclaim(
		__unused memory_object_t mem_obj,
		__unused boolean_t reclaim_backing_store)
{

	panic("df_memory_object_data_reclaim\n");
	return KERN_SUCCESS;
}


/*
 * The freezer handle is used to make sure that
 * we don't race against the lookup and termination
 * of the compact object.
 */

void
default_freezer_handle_lock(default_freezer_handle_t df_handle) {
	lck_rw_lock_exclusive(&df_handle->dfh_lck);
}

void
default_freezer_handle_unlock(default_freezer_handle_t df_handle) {
	lck_rw_done(&df_handle->dfh_lck);
}

default_freezer_handle_t
default_freezer_handle_allocate(void)
{

	default_freezer_handle_t		df_handle = NULL;
	df_handle = kalloc(sizeof(struct default_freezer_handle));

	if (df_handle) {
		memset(df_handle, 0, sizeof(struct default_freezer_handle));
		lck_rw_init(&df_handle->dfh_lck, &default_freezer_handle_lck_grp, NULL);
		/* No one knows of this handle yet so no need to lock it. */
		default_freezer_handle_reference_locked(df_handle);
	} else {
		panic("Failed to allocated default_freezer_handle structure\n");
	}
	return df_handle;
}

kern_return_t
default_freezer_handle_init(
	default_freezer_handle_t df_handle) 
{
	kern_return_t				kr = KERN_SUCCESS;
	vm_object_t				compact_object = VM_OBJECT_NULL;

	if (df_handle == NULL || df_handle->dfh_table != NULL) {
		kr = KERN_FAILURE;
	} else {
		/* Create our compact object */
		compact_object = vm_object_allocate((vm_map_offset_t)(VM_MAX_ADDRESS) - (vm_map_offset_t)(VM_MIN_ADDRESS));
		if (!compact_object) {
			kr = KERN_FAILURE;
		} else {
			df_handle->dfh_compact_object = compact_object;
			df_handle->dfh_compact_offset = 0;
			df_handle->dfh_table = default_freezer_mapping_create(df_handle->dfh_compact_object, df_handle->dfh_compact_offset);
			if (!df_handle->dfh_table) {
				kr = KERN_FAILURE;
			}	
		}
	}

	return kr;
}

void
default_freezer_handle_reference_locked(
	default_freezer_handle_t df_handle)
{
	assert(df_handle);
	df_handle->dfh_ref_count++;
}

void
default_freezer_handle_deallocate(
	default_freezer_handle_t df_handle)
{
	assert(df_handle);
	default_freezer_handle_lock(df_handle);
	if (default_freezer_handle_deallocate_locked(df_handle)) {
		default_freezer_handle_unlock(df_handle);
	}
}

boolean_t
default_freezer_handle_deallocate_locked(
	default_freezer_handle_t df_handle)
{
	boolean_t	should_unlock = TRUE;

	assert(df_handle);
	df_handle->dfh_ref_count--;
	if (df_handle->dfh_ref_count == 0) {

		if (df_handle->dfh_compact_object) {
			vm_object_deallocate(df_handle->dfh_compact_object);
			df_handle->dfh_compact_object = NULL;
			df_handle->dfh_compact_offset = 0;
		}
			
		if (df_handle->dfh_table) {
			default_freezer_mapping_free(&df_handle->dfh_table, TRUE);
			df_handle->dfh_table = NULL;
		}
	
		lck_rw_done(&df_handle->dfh_lck);
		lck_rw_destroy(&df_handle->dfh_lck, &default_freezer_handle_lck_grp);
		should_unlock = FALSE;

		kfree(df_handle, sizeof(struct default_freezer_handle));
	}
	return should_unlock;
}

void
default_freezer_pageout(
	default_freezer_handle_t df_handle)
{
	assert(df_handle);

	vm_object_pageout(df_handle->dfh_compact_object);
}

#endif /* CONFIG_FREEZE */
