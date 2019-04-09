/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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

#include <atm/atm_internal.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <ipc/ipc_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <vm/vm_map.h>
#include <atm/atm_notification.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <kern/host.h>
#include <kern/kalloc.h>
#include <machine/commpage.h>

#define MAX_ATM_VALUES         (2 * 4096)
#define MAX_TRACE_BUFFER_SIZE  (0x40000000)  /* Restrict to 1GB per task */

#define ATM_VALUE_TO_HANDLE(x) (CAST_DOWN(atm_voucher_id_t, (x)))
#define HANDLE_TO_ATM_VALUE(x) (CAST_DOWN(atm_value_t, (x)))

#define ATM_MAX_HASH_TABLE_SIZE (256)
#define AID_HASH_MASK (0xFF)
#define AID_TO_HASH(x) ((x) & (AID_HASH_MASK))

#define ATM_LIST_DEAD_MAX 15

#define AID_ARRAY_COUNT_MAX (256)

struct atm_value_hash atm_value_hash_table[ATM_MAX_HASH_TABLE_SIZE];
extern int maxproc;

/* Global flag to disable ATM. ATM get value and memory registration will return error. */
boolean_t disable_atm = FALSE;

#if DEVELOPMENT || DEBUG
queue_head_t atm_descriptors_list;
queue_head_t atm_values_list;
#endif

ipc_voucher_attr_control_t  voucher_attr_control;    /* communication channel from ATM to voucher system */
static zone_t atm_value_zone, atm_descriptors_zone, atm_link_objects_zone;

static aid_t get_aid(void);
static mach_atm_subaid_t get_subaid(void);
static atm_value_t atm_value_alloc_init(aid_t);
static void atm_value_dealloc(atm_value_t atm_value);
static void atm_hash_table_init(void);
static kern_return_t atm_value_hash_table_insert(atm_value_t new_atm_value);
static void atm_value_hash_table_delete(atm_value_t atm_value);
static atm_value_t get_atm_value_from_aid(aid_t aid) __unused;
static void atm_value_get_ref(atm_value_t atm_value);
static kern_return_t atm_listener_insert(atm_value_t atm_value, atm_task_descriptor_t task_descriptor, atm_guard_t guard);
static void atm_listener_delete_all(atm_value_t atm_value);
static atm_task_descriptor_t atm_task_descriptor_alloc_init(mach_port_t trace_buffer,uint64_t buffer_size, __assert_only task_t task);
static void atm_descriptor_get_reference(atm_task_descriptor_t task_descriptor);
static void atm_task_descriptor_dealloc(atm_task_descriptor_t task_descriptor);
static kern_return_t atm_value_unregister(atm_value_t atm_value, atm_task_descriptor_t task_descriptor, atm_guard_t guard);
static kern_return_t atm_value_register(atm_value_t atm_value, atm_task_descriptor_t task_descriptor, atm_guard_t guard);
static kern_return_t atm_listener_delete(atm_value_t atm_value, atm_task_descriptor_t task_descriptor, atm_guard_t guard);
static void atm_link_get_reference(atm_link_object_t link_object) __unused;
static void atm_link_dealloc(atm_link_object_t link_object);

kern_return_t
atm_release_value(
	ipc_voucher_attr_manager_t __assert_only manager,
	mach_voucher_attr_key_t __assert_only key,
	mach_voucher_attr_value_handle_t value,
	mach_voucher_attr_value_reference_t sync);

kern_return_t
atm_get_value(
	ipc_voucher_attr_manager_t __assert_only manager,
	mach_voucher_attr_key_t __assert_only key,
	mach_voucher_attr_recipe_command_t command,
	mach_voucher_attr_value_handle_array_t prev_values,
	mach_msg_type_number_t __assert_only prev_value_count,
	mach_voucher_attr_content_t recipe,
	mach_voucher_attr_content_size_t recipe_size,
	mach_voucher_attr_value_handle_t *out_value,
	mach_voucher_attr_value_flags_t  *out_flags,
	ipc_voucher_t *out_value_voucher);

kern_return_t
atm_extract_content(
	ipc_voucher_attr_manager_t __assert_only manager,
	mach_voucher_attr_key_t __assert_only key,
	mach_voucher_attr_value_handle_array_t values,
	mach_msg_type_number_t value_count,
	mach_voucher_attr_recipe_command_t *out_command,
	mach_voucher_attr_content_t out_recipe,
	mach_voucher_attr_content_size_t *in_out_recipe_size);

kern_return_t
atm_command(
	ipc_voucher_attr_manager_t __assert_only manager,
	mach_voucher_attr_key_t __assert_only key,
	mach_voucher_attr_value_handle_array_t values,
	mach_msg_type_number_t value_count,
	mach_voucher_attr_command_t command,
	mach_voucher_attr_content_t in_content,
	mach_voucher_attr_content_size_t in_content_size,
	mach_voucher_attr_content_t out_content,
	mach_voucher_attr_content_size_t *in_out_content_size);

void
atm_release(ipc_voucher_attr_manager_t __assert_only manager);

/*
 * communication channel from voucher system to ATM
 */
struct ipc_voucher_attr_manager atm_manager = {
	.ivam_release_value    = atm_release_value,
	.ivam_get_value        = atm_get_value,
	.ivam_extract_content  = atm_extract_content,
	.ivam_command	       = atm_command,
	.ivam_release          = atm_release,
	.ivam_flags            = IVAM_FLAGS_NONE,
};

#if DEVELOPMENT || DEBUG
decl_lck_mtx_data(, atm_descriptors_list_lock);
decl_lck_mtx_data(, atm_values_list_lock);

lck_grp_t		atm_dev_lock_grp;
lck_attr_t		atm_dev_lock_attr;
lck_grp_attr_t		atm_dev_lock_grp_attr;
#endif

extern vm_map_t kernel_map;
/*
 * Global aid. Incremented on each get_aid.
 */
aid_t global_aid;

/*
 * Global subaid. Incremented on each get_subaid.
 */
mach_atm_subaid_t global_subaid;

/*
 * Lock group attributes for atm sub system.
 */
lck_grp_t		atm_lock_grp;
lck_attr_t		atm_lock_attr;
lck_grp_attr_t		atm_lock_grp_attr;

/*
 * Global that is set by diagnosticd and readable by userspace
 * via the commpage.
 */
static uint32_t atm_diagnostic_config;

/*
 * Routine: atm_init
 * Purpose: Initialize the atm subsystem.
 * Returns: None.
 */
void
atm_init()
{
	kern_return_t kr = KERN_SUCCESS;
	char temp_buf[20];

	/* Disable atm if disable_atm present in device-tree properties or in boot-args */
	if ((PE_get_default("kern.disable_atm", temp_buf, sizeof(temp_buf))) || 
	    (PE_parse_boot_argn("-disable_atm", temp_buf, sizeof(temp_buf)))) {
		disable_atm = TRUE;
	}

	if (!PE_parse_boot_argn("atm_diagnostic_config", &atm_diagnostic_config, sizeof(atm_diagnostic_config))) {
		if (!PE_get_default("kern.atm_diagnostic_config",  &atm_diagnostic_config, sizeof(atm_diagnostic_config))) {
			atm_diagnostic_config = 0;
		}
	}

	/* setup zones for descriptors, values and link objects */
	atm_value_zone       = zinit(sizeof(struct atm_value),
	                       MAX_ATM_VALUES * sizeof(struct atm_value),
	                       sizeof(struct atm_value),
	                       "atm_values");

	atm_descriptors_zone = zinit(sizeof(struct atm_task_descriptor),
	                       MAX_ATM_VALUES * sizeof(struct atm_task_descriptor),
	                       sizeof(struct atm_task_descriptor),
	                       "atm_task_descriptors");

	atm_link_objects_zone = zinit(sizeof(struct atm_link_object),
	                        MAX_ATM_VALUES * sizeof(struct atm_link_object),
	                        sizeof(struct atm_link_object),
	                        "atm_link_objects");

	/* Initialize atm lock group and lock attributes. */
	lck_grp_attr_setdefault(&atm_lock_grp_attr);
	lck_grp_init(&atm_lock_grp, "atm_lock", &atm_lock_grp_attr);
	lck_attr_setdefault(&atm_lock_attr);

	global_aid = 1;
	global_subaid = 1;
	atm_hash_table_init();

#if DEVELOPMENT || DEBUG
	/* Initialize global atm development lock group and lock attributes. */
	lck_grp_attr_setdefault(&atm_dev_lock_grp_attr);
	lck_grp_init(&atm_dev_lock_grp, "atm_dev_lock", &atm_dev_lock_grp_attr);
	lck_attr_setdefault(&atm_dev_lock_attr);

	lck_mtx_init(&atm_descriptors_list_lock, &atm_dev_lock_grp, &atm_dev_lock_attr);
	lck_mtx_init(&atm_values_list_lock, &atm_dev_lock_grp, &atm_dev_lock_attr);

	queue_init(&atm_descriptors_list);
	queue_init(&atm_values_list);
#endif

	/* Register the atm manager with the Vouchers sub system. */
	kr = ipc_register_well_known_mach_voucher_attr_manager(
	                &atm_manager,
	                0,
	                MACH_VOUCHER_ATTR_KEY_ATM,
	                &voucher_attr_control);
	if (kr != KERN_SUCCESS )
		panic("ATM subsystem initialization failed");

	kprintf("ATM subsystem is initialized\n");
	return ;
}


/*
 * ATM Resource Manager Routines.
 */


/*
 * Routine: atm_release_value
 * Purpose: Release a value, if sync matches the sync count in value.
 * Returns: KERN_SUCCESS: on Successful deletion.
 *          KERN_FAILURE: if sync value does not matches.
 */
kern_return_t
atm_release_value(
	ipc_voucher_attr_manager_t		__assert_only manager,
	mach_voucher_attr_key_t			__assert_only key,
	mach_voucher_attr_value_handle_t		      value,
	mach_voucher_attr_value_reference_t	          sync)
{
	atm_value_t atm_value = ATM_VALUE_NULL;

	assert(MACH_VOUCHER_ATTR_KEY_ATM == key);
	assert(manager == &atm_manager);

	atm_value = HANDLE_TO_ATM_VALUE(value);
	if (atm_value == VAM_DEFAULT_VALUE) {
		/* Return success for default value */
		return KERN_SUCCESS;
	}

	if (atm_value->sync != sync) {
		return KERN_FAILURE;
	}

	/* Deallocate the atm value. */
	atm_value_hash_table_delete(atm_value);
	atm_value_dealloc(atm_value);
	return KERN_SUCCESS;
}


/*
 * Routine: atm_get_value
 */
kern_return_t
atm_get_value(
	ipc_voucher_attr_manager_t 		__assert_only manager,
	mach_voucher_attr_key_t 		__assert_only key,
	mach_voucher_attr_recipe_command_t 	          command,
	mach_voucher_attr_value_handle_array_t 	      prev_values,
	mach_msg_type_number_t 			__assert_only prev_value_count,
	mach_voucher_attr_content_t          __unused recipe,
	mach_voucher_attr_content_size_t     __unused recipe_size,
	mach_voucher_attr_value_handle_t             *out_value,
	mach_voucher_attr_value_flags_t              *out_flags,
	ipc_voucher_t 				                 *out_value_voucher)
{
	atm_value_t atm_value = ATM_VALUE_NULL;
	mach_voucher_attr_value_handle_t atm_handle;
	atm_task_descriptor_t task_descriptor = ATM_TASK_DESCRIPTOR_NULL;
	task_t task;
	aid_t aid;
	atm_guard_t guard;
	natural_t i;
	kern_return_t kr = KERN_SUCCESS;

	assert(MACH_VOUCHER_ATTR_KEY_ATM == key);
	assert(manager == &atm_manager);

	/* never an out voucher */
	*out_value_voucher = IPC_VOUCHER_NULL;
	*out_flags = MACH_VOUCHER_ATTR_VALUE_FLAGS_NONE;

	if (disable_atm || (atm_get_diagnostic_config() & ATM_TRACE_DISABLE))
		return KERN_NOT_SUPPORTED;

	switch (command) {

	case MACH_VOUCHER_ATTR_ATM_REGISTER:

		for (i = 0; i < prev_value_count; i++) {
			atm_handle = prev_values[i];
			atm_value = HANDLE_TO_ATM_VALUE(atm_handle);

			if (atm_value == VAM_DEFAULT_VALUE)
				continue;

			if (recipe_size != sizeof(atm_guard_t)) {
				kr = KERN_INVALID_ARGUMENT;
				break;
			}
			memcpy(&guard, recipe, sizeof(atm_guard_t));

			task = current_task();
			task_descriptor = task->atm_context;
				
			kr = atm_value_register(atm_value, task_descriptor, guard);
			if (kr != KERN_SUCCESS) {
				break;
			}

			/* Increment sync value. */
			atm_sync_reference_internal(atm_value);

			*out_value = atm_handle;
			return kr;
		}

		*out_value = ATM_VALUE_TO_HANDLE(VAM_DEFAULT_VALUE);
		break;

	case MACH_VOUCHER_ATTR_ATM_CREATE:

		/* Handle the old case where aid value is created in kernel */
		if (recipe_size == 0) {
			aid = get_aid();
		} else if (recipe_size == sizeof(aid_t)) {
			memcpy(&aid, recipe, sizeof(aid_t));
		} else {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}
		
		/* Allocate a new atm value. */
		atm_value = atm_value_alloc_init(aid);
		if (atm_value == ATM_VALUE_NULL) {
			kr = KERN_RESOURCE_SHORTAGE;
			break;
		}
redrive:	
		kr = atm_value_hash_table_insert(atm_value);
		if (kr != KERN_SUCCESS) {
			if (recipe_size == 0) {
				atm_value->aid = get_aid();
				goto redrive;
			}
			atm_value_dealloc(atm_value);
			break;
		}

		*out_value = ATM_VALUE_TO_HANDLE(atm_value);
		break;

	case MACH_VOUCHER_ATTR_ATM_NULL:
	default:
		kr = KERN_INVALID_ARGUMENT;
		break;
	}

	return kr;
}


/*
 * Routine: atm_extract_content
 * Purpose: Extract a set of aid from an array of voucher values.
 * Returns: KERN_SUCCESS: on Success.
 *          KERN_FAILURE: one of the value is not present in the hash.
 *          KERN_NO_SPACE: insufficeint buffer provided to fill an array of aid.
 */
kern_return_t
atm_extract_content(
	ipc_voucher_attr_manager_t      __assert_only manager,
	mach_voucher_attr_key_t         __assert_only key,
	mach_voucher_attr_value_handle_array_t        values,
	mach_msg_type_number_t 			              value_count,
	mach_voucher_attr_recipe_command_t           *out_command,
	mach_voucher_attr_content_t                   out_recipe,
	mach_voucher_attr_content_size_t             *in_out_recipe_size)
{
	atm_value_t atm_value;
	mach_voucher_attr_value_handle_t atm_handle;
	natural_t i;

	assert(MACH_VOUCHER_ATTR_KEY_ATM == key);
	assert(manager == &atm_manager);

	for (i = 0; i < value_count; i++) {
		atm_handle = values[i];
		atm_value = HANDLE_TO_ATM_VALUE(atm_handle);
		if (atm_value == VAM_DEFAULT_VALUE)
			continue;

		if (( sizeof(aid_t)) > *in_out_recipe_size) {
			*in_out_recipe_size = 0;
			return KERN_NO_SPACE;
		}

		memcpy(&out_recipe[0], &atm_value->aid, sizeof(aid_t));
		*out_command = MACH_VOUCHER_ATTR_ATM_NULL;
		*in_out_recipe_size = sizeof(aid_t);
		return KERN_SUCCESS;
	}

	*in_out_recipe_size = 0;
	return KERN_SUCCESS;
}

/*
 * Routine: atm_command
 * Purpose: Execute a command against a set of ATM values.
 * Returns: KERN_SUCCESS: On successful execution of command.
 	    KERN_FAILURE: On failure.
 */
kern_return_t
atm_command(
	ipc_voucher_attr_manager_t 		   __assert_only manager,
	mach_voucher_attr_key_t 		   __assert_only key,
	mach_voucher_attr_value_handle_array_t 	values,
	mach_msg_type_number_t 			   value_count,
	mach_voucher_attr_command_t		   command,
	mach_voucher_attr_content_t 	   in_content,
	mach_voucher_attr_content_size_t   in_content_size,
	mach_voucher_attr_content_t 	   out_content,
	mach_voucher_attr_content_size_t   *out_content_size)
{
	assert(MACH_VOUCHER_ATTR_KEY_ATM == key);
	assert(manager == &atm_manager);
	atm_value_t atm_value = ATM_VALUE_NULL;
	natural_t i = 0;
	mach_atm_subaid_t *subaid_array = NULL;
	mach_atm_subaid_t next_subaid = 0;
	uint32_t aid_array_count = 0;
	atm_task_descriptor_t task_descriptor = ATM_TASK_DESCRIPTOR_NULL;
	task_t task;
	kern_return_t kr = KERN_SUCCESS;
	atm_guard_t guard;
	
	switch (command) {
	case ATM_ACTION_COLLECT:
		/* Fall through */

	case ATM_ACTION_LOGFAIL:
		return KERN_NOT_SUPPORTED;

	case ATM_FIND_MIN_SUB_AID:
		if ((in_content_size/sizeof(aid_t)) > (*out_content_size/sizeof(mach_atm_subaid_t)))
			return KERN_FAILURE;

		aid_array_count = in_content_size / sizeof(aid_t);
		if (aid_array_count > AID_ARRAY_COUNT_MAX)
			return KERN_FAILURE;

		subaid_array = (mach_atm_subaid_t *) (void *) out_content;
		for (i = 0; i < aid_array_count; i++) {
			subaid_array[i] = ATM_SUBAID32_MAX;
		}

		*out_content_size = aid_array_count * sizeof(mach_atm_subaid_t);

		kr = KERN_SUCCESS;

		break;

	case ATM_ACTION_UNREGISTER:
		/* find the first non-default atm_value */
		for (i = 0; i < value_count; i++) {
			atm_value = HANDLE_TO_ATM_VALUE(values[i]);
			if (atm_value != VAM_DEFAULT_VALUE)
				break;
		}

		/* if we are not able to find any atm values
		 * in stack then this call was made in error
		 */
		if (atm_value == NULL) {
			return KERN_FAILURE;
		}
		if (in_content == NULL || in_content_size != sizeof(atm_guard_t)){
			return KERN_INVALID_ARGUMENT;
		}

		memcpy(&guard, in_content, sizeof(atm_guard_t));
		task = current_task();
		task_descriptor = task->atm_context;

		kr = atm_value_unregister(atm_value, task_descriptor, guard);

		break;

	case ATM_ACTION_REGISTER:
		for (i = 0; i < value_count; i++) {
			atm_value = HANDLE_TO_ATM_VALUE(values[i]);
			if (atm_value != VAM_DEFAULT_VALUE)
				break;
		}
		/* if we are not able to find any atm values
		 * in stack then this call was made in error
		 */
		if (atm_value == NULL) {
			return KERN_FAILURE;
		}
		if (in_content == NULL || in_content_size != sizeof(atm_guard_t)){
			return KERN_INVALID_ARGUMENT;
		}

		memcpy(&guard, in_content, sizeof(atm_guard_t));
		task = current_task();
		task_descriptor = task->atm_context;

		kr = atm_value_register(atm_value, task_descriptor, guard);

		break;

	case ATM_ACTION_GETSUBAID:
		if (out_content == NULL || *out_content_size != sizeof(mach_atm_subaid_t))
			return KERN_FAILURE;

		next_subaid = get_subaid();
		memcpy(out_content, &next_subaid, sizeof(mach_atm_subaid_t));
		break;

	default:
		kr = KERN_INVALID_ARGUMENT;
		break;
	}

	return kr;
}


void
atm_release(
	ipc_voucher_attr_manager_t 		__assert_only manager)
{
	assert(manager == &atm_manager);
}


/*
 * Routine: atm_value_alloc_init
 * Purpose: Allocates an atm value struct and initialize it.
 * Returns: atm_value_t: On Success with a sync count on atm_value.
 *          ATM_VALUE_NULL: On failure.
 */
static atm_value_t
atm_value_alloc_init(aid_t aid)
{
	atm_value_t new_atm_value = ATM_VALUE_NULL;

	new_atm_value = (atm_value_t) zalloc(atm_value_zone);
	if (new_atm_value == ATM_VALUE_NULL)
		panic("Ran out of ATM values structure.\n\n");

	new_atm_value->aid = aid;
	queue_init(&new_atm_value->listeners);
	new_atm_value->sync = 1;
	new_atm_value->listener_count = 0;
	new_atm_value->reference_count = 1;
	lck_mtx_init(&new_atm_value->listener_lock, &atm_lock_grp, &atm_lock_attr);

#if DEVELOPMENT || DEBUG
	lck_mtx_lock(&atm_values_list_lock);
	queue_enter(&atm_values_list, new_atm_value, atm_value_t, value_elt);
	lck_mtx_unlock(&atm_values_list_lock);
#endif
	return new_atm_value;
}


/*
 * Routine: get_aid
 * Purpose: Increment the global aid counter and return it.
 * Returns: aid
 */
static aid_t
get_aid()
{
	aid_t aid;
	aid = (aid_t)OSIncrementAtomic64((SInt64 *)&global_aid);
	return aid;
}


/*
 * Routine: get_subaid
 * Purpose: Increment the global subaid counter and return it.
 * Returns: subaid
 */
static mach_atm_subaid_t
get_subaid()
{
	mach_atm_subaid_t next_subaid;
	next_subaid = (mach_atm_subaid_t)OSIncrementAtomic64((SInt64 *)&global_subaid);
	return next_subaid;
}


/*
 * Routine: atm_value_dealloc
 * Purpose: Drops the reference on atm value and deallocates.
 *          Deletes all the listeners on deallocation.
 * Returns: None.
 */
static void
atm_value_dealloc(atm_value_t atm_value)
{
	if (0 < atm_value_release_internal(atm_value)) {
		return;
	}

	assert(atm_value->reference_count == 0);

	/* Free up the atm value and also remove all the listeners. */
	atm_listener_delete_all(atm_value);

	lck_mtx_destroy(&atm_value->listener_lock, &atm_lock_grp);

#if DEVELOPMENT || DEBUG
	lck_mtx_lock(&atm_values_list_lock);
	queue_remove(&atm_values_list, atm_value, atm_value_t, value_elt);
	lck_mtx_unlock(&atm_values_list_lock);
#endif
	zfree(atm_value_zone, atm_value);
	return;
}


/*
 * Routine: atm_hash_table_init
 * Purpose: Initialize the atm aid hash table.
 * Returns: None.
 */
static void
atm_hash_table_init()
{
	int i;

	for (i = 0; i < ATM_MAX_HASH_TABLE_SIZE; i++) {
		queue_init(&atm_value_hash_table[i].hash_list);
		lck_mtx_init(&atm_value_hash_table[i].hash_list_lock, &atm_lock_grp, &atm_lock_attr);
	}
}


/*
 * Routine: atm_value_hash_table_insert
 * Purpose: Insert an atm value in the hash table.
 * Returns: KERN_SUCCESS on success.
 *          KERN_NAME_EXISTS if atm value already in the hash table.
 */
static kern_return_t
atm_value_hash_table_insert(atm_value_t new_atm_value)
{
	int hash_index;
	atm_value_hash_t hash_list_head;
	aid_t aid = new_atm_value->aid;
	atm_value_t next;

	hash_index = AID_TO_HASH(aid);
	hash_list_head = &atm_value_hash_table[hash_index];

	/* Lock the atm list and search for the aid. */
	lck_mtx_lock(&hash_list_head->hash_list_lock);

	queue_iterate(&hash_list_head->hash_list, next, atm_value_t, vid_hash_elt) {
		if (next->aid == aid) {
			/*
			 * aid found. return error.
			 */
			lck_mtx_unlock(&hash_list_head->hash_list_lock);
			return (KERN_NAME_EXISTS);
		}
	}

	/* Enter the aid in hash and return success. */
	queue_enter(&hash_list_head->hash_list, new_atm_value, atm_value_t, vid_hash_elt);
	lck_mtx_unlock(&hash_list_head->hash_list_lock);
	return KERN_SUCCESS;
}


/*
 * Routine: atm_value_hash_table_delete
 * Purpose: Delete the atm value from the hash table.
 * Returns: None.
 */
static void
atm_value_hash_table_delete(atm_value_t atm_value)
{
	int hash_index;
	atm_value_hash_t hash_list_head;
	aid_t aid = atm_value->aid;

	hash_index = AID_TO_HASH(aid);
	hash_list_head = &atm_value_hash_table[hash_index];

	lck_mtx_lock(&hash_list_head->hash_list_lock);
	queue_remove(&hash_list_head->hash_list, atm_value, atm_value_t, vid_hash_elt);
	lck_mtx_unlock(&hash_list_head->hash_list_lock);
}


/*
 * Routine: get_atm_value_from_aid
 * Purpose: Search a given aid in atm value hash table and
 *          return the atm value stucture.
 * Returns: atm value structure if aid found.
 *          ATM_VALUE_NULL: If aid not found in atm value hash table.
 */
static atm_value_t
get_atm_value_from_aid(aid_t aid)
{
	int hash_index;
	atm_value_hash_t hash_list_head;
	atm_value_t next;

	hash_index = AID_TO_HASH(aid);
	hash_list_head = &atm_value_hash_table[hash_index];

	/* Lock the atm list and search for the aid. */
	lck_mtx_lock(&hash_list_head->hash_list_lock);

	queue_iterate(&hash_list_head->hash_list, next, atm_value_t, vid_hash_elt) {
		if (next->aid == aid) {
			/*
			 * Aid found. Incerease ref count and return
			 * the atm value structure.
			 */
			atm_value_get_ref(next);
			lck_mtx_unlock(&hash_list_head->hash_list_lock);
			return (next);
		}
	}
	lck_mtx_unlock(&hash_list_head->hash_list_lock);
	return ATM_VALUE_NULL;
}


/*
 * Routine: atm_value_get_ref
 * Purpose: Get a reference on atm value.
 * Returns: None.
 */
static void
atm_value_get_ref(atm_value_t atm_value)
{
	atm_value_reference_internal(atm_value);
}


/*
 * Routine: atm_listener_insert
 * Purpose: Insert a listener to an atm value.
 * Returns: KERN_SUCCESS on success.
 *          KERN_FAILURE if the task is already present as a listener.
 */
static kern_return_t
atm_listener_insert(
	atm_value_t 		atm_value,
	atm_task_descriptor_t 	task_descriptor,
	atm_guard_t     	guard)
{
	atm_link_object_t new_link_object;
	atm_link_object_t next, elem;
	int32_t freed_count = 0, dead_but_not_freed = 0, listener_count;
	boolean_t element_found = FALSE;
	queue_head_t free_listeners;

	new_link_object = (atm_link_object_t) zalloc(atm_link_objects_zone);
	new_link_object->descriptor = task_descriptor;
	new_link_object->reference_count = 1;
	new_link_object->guard = guard;

	/* Get a reference on the task descriptor */
	atm_descriptor_get_reference(task_descriptor);
	queue_init(&free_listeners);
	listener_count = atm_value->listener_count;

	/* Check if the task is already on the listener list */
	lck_mtx_lock(&atm_value->listener_lock);

	next = (atm_link_object_t)(void *) queue_first(&atm_value->listeners);
	while (!queue_end(&atm_value->listeners, (queue_entry_t)next)) {
		elem = next;
		next = (atm_link_object_t)(void *) queue_next(&next->listeners_element);

		/* Check for dead tasks */
		if (elem->descriptor->flags == ATM_TASK_DEAD) {
			if ((dead_but_not_freed > ATM_LIST_DEAD_MAX) || elem->guard == 0) {
				queue_remove(&atm_value->listeners, elem, atm_link_object_t, listeners_element);
				queue_enter(&free_listeners, elem, atm_link_object_t, listeners_element);
				atm_listener_count_decr_internal(atm_value);
				freed_count++;
			} else {
				dead_but_not_freed++;
			}
			continue;
		}

		if (element_found)
			continue;

		if (elem->descriptor == task_descriptor) {
			/* Increment reference count on Link object. */
			atm_link_get_reference(elem);

			/* Replace the guard with the new one, the old guard is anyways on unregister path. */
			elem->guard = guard;
			element_found = TRUE;
			KERNEL_DEBUG_CONSTANT((ATM_CODE(ATM_GETVALUE_INFO, (ATM_VALUE_REPLACED))) | DBG_FUNC_NONE,
				VM_KERNEL_ADDRPERM(atm_value), atm_value->aid, guard, 0, 0);

		}
	}

	if (element_found) {
		lck_mtx_unlock(&atm_value->listener_lock);
		/* Drop the extra reference on task descriptor taken by this function. */
		atm_task_descriptor_dealloc(task_descriptor);
		zfree(atm_link_objects_zone, new_link_object);
	} else {
		KERNEL_DEBUG_CONSTANT((ATM_CODE(ATM_GETVALUE_INFO, (ATM_VALUE_ADDED))) | DBG_FUNC_NONE,
				VM_KERNEL_ADDRPERM(atm_value), atm_value->aid, guard, 0, 0);

		queue_enter(&atm_value->listeners, new_link_object, atm_link_object_t, listeners_element);
		atm_listener_count_incr_internal(atm_value);
		lck_mtx_unlock(&atm_value->listener_lock);
	}

	/* Free the link objects */
	while(!queue_empty(&free_listeners)) {
		queue_remove_first(&free_listeners, next, atm_link_object_t, listeners_element);

		/* Deallocate the link object */
		atm_link_dealloc(next);
	}

	KERNEL_DEBUG_CONSTANT((ATM_CODE(ATM_SUBAID_INFO, (ATM_LINK_LIST_TRIM))) | DBG_FUNC_NONE,
		listener_count, freed_count, dead_but_not_freed, VM_KERNEL_ADDRPERM(atm_value), 1);

	return KERN_SUCCESS;
}


/*
 * Routine: atm_listener_delete_all
 * Purpose: Deletes all the listeners for an atm value.
 * Returns: None.
 */
static void
atm_listener_delete_all(atm_value_t atm_value)
{
	atm_link_object_t next;

	while(!queue_empty(&atm_value->listeners)) {
		queue_remove_first(&atm_value->listeners, next, atm_link_object_t, listeners_element);

		/* Deallocate the link object */
		atm_link_dealloc(next);
	}
}


/*
 * Routine: atm_listener_delete
 * Purpose: Deletes a listerner for an atm value.
 * Returns: KERN_SUCCESS on successful unregister.
 *          KERN_INVALID_VALUE on finding a different guard.
 *          KERN_FAILURE on failure.
 */
static kern_return_t
atm_listener_delete(
	atm_value_t atm_value,
	atm_task_descriptor_t task_descriptor,
	atm_guard_t guard)
{
	queue_head_t free_listeners;
	atm_link_object_t next, elem;
	kern_return_t kr = KERN_FAILURE;

	queue_init(&free_listeners);

	lck_mtx_lock(&atm_value->listener_lock);

	next = (atm_link_object_t)(void *) queue_first(&atm_value->listeners);
	while (!queue_end(&atm_value->listeners, (queue_entry_t)next)) {
		elem = next;
		next = (atm_link_object_t)(void *) queue_next(&next->listeners_element);

		if (elem->descriptor == task_descriptor) {
			if (elem->guard == guard) {
				KERNEL_DEBUG_CONSTANT((ATM_CODE(ATM_UNREGISTER_INFO,
					(ATM_VALUE_UNREGISTERED))) | DBG_FUNC_NONE,
					VM_KERNEL_ADDRPERM(atm_value), atm_value->aid, guard, elem->reference_count, 0);
				elem->guard = 0;
				kr = KERN_SUCCESS;
			} else {
				KERNEL_DEBUG_CONSTANT((ATM_CODE(ATM_UNREGISTER_INFO,
					(ATM_VALUE_DIFF_MAILBOX))) | DBG_FUNC_NONE,
					VM_KERNEL_ADDRPERM(atm_value), atm_value->aid, elem->guard, elem->reference_count, 0);
				kr = KERN_INVALID_VALUE;
			}
			if (0 == atm_link_object_release_internal(elem)) {
				queue_remove(&atm_value->listeners, elem, atm_link_object_t, listeners_element);
				queue_enter(&free_listeners, elem, atm_link_object_t, listeners_element);
				atm_listener_count_decr_internal(atm_value);
			}
			break;
		}
	}
	lck_mtx_unlock(&atm_value->listener_lock);

	while(!queue_empty(&free_listeners)) {
		queue_remove_first(&free_listeners, next, atm_link_object_t, listeners_element);
	
		/* Deallocate the link object */
		atm_link_dealloc(next);
	}
	return kr;
}


/*
 * Routine: atm_descriptor_alloc_init
 * Purpose: Allocate an atm task descriptor and initialize it and takes a reference.
 * Returns: atm task descriptor: On success.
 *          NULL: on error.
 */
static atm_task_descriptor_t
atm_task_descriptor_alloc_init(
	mach_port_t		trace_buffer,
	uint64_t		buffer_size,
	task_t 			__assert_only task)
{
	atm_task_descriptor_t new_task_descriptor;

	new_task_descriptor = (atm_task_descriptor_t) zalloc(atm_descriptors_zone);

	new_task_descriptor->trace_buffer = trace_buffer;
	new_task_descriptor->trace_buffer_size = buffer_size;
	new_task_descriptor->reference_count = 1;
	new_task_descriptor->flags = 0;
	lck_mtx_init(&new_task_descriptor->lock, &atm_lock_grp, &atm_lock_attr);

#if DEVELOPMENT || DEBUG
	new_task_descriptor->task = task;
	lck_mtx_lock(&atm_descriptors_list_lock);
	queue_enter(&atm_descriptors_list, new_task_descriptor, atm_task_descriptor_t, descriptor_elt);
	lck_mtx_unlock(&atm_descriptors_list_lock);
#endif

	return new_task_descriptor;
}


/*
 * Routine: atm_descriptor_get_reference
 * Purpose: Get a reference count on task descriptor.
 * Returns: None.
 */
static void
atm_descriptor_get_reference(atm_task_descriptor_t task_descriptor)
{
	atm_task_desc_reference_internal(task_descriptor);
}


/*
 * Routine: atm_task_descriptor_dealloc
 * Prupose: Drops the reference on atm descriptor.
 * Returns: None.
 */
static void
atm_task_descriptor_dealloc(atm_task_descriptor_t task_descriptor)
{
	if (0 < atm_task_desc_release_internal(task_descriptor)) {
		return;
	}

	assert(task_descriptor->reference_count == 0);

#if DEVELOPMENT || DEBUG
	lck_mtx_lock(&atm_descriptors_list_lock);
	queue_remove(&atm_descriptors_list, task_descriptor, atm_task_descriptor_t, descriptor_elt);
	lck_mtx_unlock(&atm_descriptors_list_lock);
#endif
	/* release the send right for the named memory entry */
	ipc_port_release_send(task_descriptor->trace_buffer);
	lck_mtx_destroy(&task_descriptor->lock, &atm_lock_grp);
	zfree(atm_descriptors_zone, task_descriptor);
	return;
}


/*
 * Routine: atm_link_get_reference
 * Purpose: Get a reference count on atm link object.
 * Returns: None.
 */
static void
atm_link_get_reference(atm_link_object_t link_object)
{
	atm_link_object_reference_internal(link_object);
}


/*
 * Routine: atm_link_dealloc
 * Prupose: Drops the reference on link object.
 * Returns: None.
 */
static void
atm_link_dealloc(atm_link_object_t link_object)
{
	/* Drop the reference on atm task descriptor. */
	atm_task_descriptor_dealloc(link_object->descriptor);
	zfree(atm_link_objects_zone, link_object);
}


/*
 * Routine: atm_register_trace_memory
 * Purpose: Registers trace memory for a task.
 * Returns: KERN_SUCCESS: on Success.
 *          KERN_FAILURE: on Error.
 */
kern_return_t
atm_register_trace_memory(
	task_t 			task,
	uint64_t 		trace_buffer_address,
	uint64_t 		buffer_size)
{
	atm_task_descriptor_t task_descriptor;
	mach_port_t trace_buffer = MACH_PORT_NULL;
	kern_return_t kr = KERN_SUCCESS;

	if (disable_atm || (atm_get_diagnostic_config() & ATM_TRACE_DISABLE))
		return KERN_NOT_SUPPORTED;

	if (task != current_task())
		return KERN_INVALID_ARGUMENT;

	if (task->atm_context != NULL
	    || (void *)trace_buffer_address == NULL
	    || buffer_size == 0
	    || (buffer_size & PAGE_MASK) != 0
	    || buffer_size > MAX_TRACE_BUFFER_SIZE) {
		return KERN_INVALID_ARGUMENT;
	}

	vm_map_t map = current_map();
	memory_object_size_t mo_size = (memory_object_size_t) buffer_size;
	kr = mach_make_memory_entry_64(map,
		                          &mo_size,
		                          (mach_vm_offset_t)trace_buffer_address,
		                          VM_PROT_READ,
		                          &trace_buffer,
		                          NULL);
	if (kr != KERN_SUCCESS)
		return kr;

	task_descriptor = atm_task_descriptor_alloc_init(trace_buffer, buffer_size, task);
	if (task_descriptor == ATM_TASK_DESCRIPTOR_NULL) {
		ipc_port_release_send(trace_buffer);
		return KERN_NO_SPACE;
	}

	task_lock(task);
	if (task->atm_context == NULL) {
		task->atm_context = task_descriptor;
		kr = KERN_SUCCESS;
	} else {
		kr = KERN_FAILURE;
	}
	task_unlock(task);

	if (kr != KERN_SUCCESS) {
		/* undo the mapping and allocations since we failed to hook descriptor to task */
		atm_task_descriptor_dealloc(task_descriptor);
	}
	return KERN_SUCCESS;
}

/*
 * Routine: atm_set_diagnostic_config
 * Purpose: Set global atm_diagnostic_config and update the commpage to reflect
 *          the new value.
 * Returns: Error if ATM is disabled.
 */
extern uint32_t atm_diagnostic_config; /* Proxied to commpage for fast user access */
kern_return_t
atm_set_diagnostic_config(uint32_t diagnostic_config)
{
	if (disable_atm)
		return KERN_NOT_SUPPORTED;

	atm_diagnostic_config = diagnostic_config;
	commpage_update_atm_diagnostic_config(atm_diagnostic_config);

	return KERN_SUCCESS;
}


/*
 * Routine: atm_get_diagnostic_config
 * Purpose: Get global atm_diagnostic_config.
 * Returns: Diagnostic value
 */
uint32_t
atm_get_diagnostic_config(void)
{
	return atm_diagnostic_config;
}


/*
 * Routine: atm_value_unregister
 * Purpose: Unregisters a process from an activity id.
 * Returns: KERN_SUCCESS on successful unregister.
 *          KERN_INVALID_VALUE on finding a diff guard.
 *          KERN_FAILURE on failure.
 */
static kern_return_t
atm_value_unregister(
	atm_value_t atm_value,
	atm_task_descriptor_t task_descriptor,
	atm_guard_t guard)
{
	kern_return_t kr;

	if (task_descriptor == ATM_TASK_DESCRIPTOR_NULL)
		return KERN_INVALID_TASK;
	
	kr = atm_listener_delete(atm_value, task_descriptor, guard);
	return kr;
}


/*
 * Routine: atm_value_register
 * Purpose: Registers a process for an activity id.
 * Returns: KERN_SUCCESS on successful register.
 *          KERN_INVALID_TASK on finding a null task atm context.
 *          KERN_FAILURE on failure.
 */
static kern_return_t
atm_value_register(
	atm_value_t atm_value,
	atm_task_descriptor_t task_descriptor,
	atm_guard_t guard)
{
	kern_return_t kr;

	if (task_descriptor == ATM_TASK_DESCRIPTOR_NULL)
		return KERN_INVALID_TASK;

	kr = atm_listener_insert(atm_value, task_descriptor, guard);
	return kr;
}


void
atm_task_descriptor_destroy(atm_task_descriptor_t task_descriptor)
{
	/* Mark the task dead in the task descriptor to make task descriptor eligible for cleanup. */
	lck_mtx_lock(&task_descriptor->lock);
	task_descriptor->flags = ATM_TASK_DEAD;
	lck_mtx_unlock(&task_descriptor->lock);

	atm_task_descriptor_dealloc(task_descriptor);
}
