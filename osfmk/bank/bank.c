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

#include <bank/bank_internal.h>
#include <bank/bank_types.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <ipc/ipc_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <vm/vm_map.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/ledger.h>
#include <sys/kdebug.h>

#include <mach/mach_voucher_attr_control.h>

static zone_t bank_task_zone, bank_account_zone;
#define MAX_BANK_TASK     (CONFIG_TASK_MAX)
#define MAX_BANK_ACCOUNT  (CONFIG_TASK_MAX + CONFIG_THREAD_MAX)

#define BANK_ELEMENT_TO_HANDLE(x) (CAST_DOWN(bank_handle_t, (x)))
#define HANDLE_TO_BANK_ELEMENT(x) (CAST_DOWN(bank_element_t, (x)))

/* Need macro since bank_element_t is 4 byte aligned on release kernel and direct type case gives compilation error */
#define CAST_TO_BANK_TASK(x) ((bank_task_t)((void *)(x)))
#define CAST_TO_BANK_ACCOUNT(x) ((bank_account_t)((void *)(x)))

ipc_voucher_attr_control_t  bank_voucher_attr_control;    /* communication channel from ATM to voucher system */

#if DEVELOPMENT || DEBUG
queue_head_t bank_tasks_list;
queue_head_t bank_accounts_list;
#endif

static ledger_template_t bank_ledger_template = NULL;
struct _bank_ledger_indices bank_ledgers = { -1 };

static bank_task_t bank_task_alloc_init(void);
static bank_account_t bank_account_alloc_init(bank_task_t bank_holder, bank_task_t bank_merchant);
static bank_task_t get_bank_task_context(task_t task);
static void bank_task_dealloc(bank_task_t bank_task, mach_voucher_attr_value_reference_t sync);
static kern_return_t bank_account_dealloc_with_sync(bank_account_t bank_account, mach_voucher_attr_value_reference_t sync);
static void bank_rollup_chit_to_tasks(ledger_t bill, bank_task_t bank_holder, bank_task_t bank_merchant);
static void init_bank_ledgers(void);

kern_return_t
bank_release_value(
	ipc_voucher_attr_manager_t __assert_only manager,
	mach_voucher_attr_key_t __assert_only key,
	mach_voucher_attr_value_handle_t value,
	mach_voucher_attr_value_reference_t sync);

kern_return_t
bank_get_value(
	ipc_voucher_attr_manager_t __assert_only manager,
	mach_voucher_attr_key_t __assert_only key,
	mach_voucher_attr_recipe_command_t command,
	mach_voucher_attr_value_handle_array_t prev_values,
	mach_msg_type_number_t __assert_only prev_value_count,
	mach_voucher_attr_content_t recipe,
	mach_voucher_attr_content_size_t recipe_size,
	mach_voucher_attr_value_handle_t *out_value,
	ipc_voucher_t *out_value_voucher);

kern_return_t
bank_extract_content(
	ipc_voucher_attr_manager_t __assert_only manager,
	mach_voucher_attr_key_t __assert_only key,
	mach_voucher_attr_value_handle_array_t values,
	mach_msg_type_number_t value_count,
	mach_voucher_attr_recipe_command_t *out_command,
	mach_voucher_attr_content_t out_recipe,
	mach_voucher_attr_content_size_t *in_out_recipe_size);

kern_return_t
bank_command(
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
bank_release(ipc_voucher_attr_manager_t __assert_only manager);

/*
 * communication channel from voucher system to ATM
 */
struct ipc_voucher_attr_manager bank_manager = {
	.ivam_release_value    = bank_release_value,
	.ivam_get_value        = bank_get_value,
	.ivam_extract_content  = bank_extract_content,
	.ivam_command	       = bank_command,
	.ivam_release          = bank_release,
};


#if DEVELOPMENT || DEBUG
decl_lck_mtx_data(, bank_tasks_list_lock);
decl_lck_mtx_data(, bank_accounts_list_lock);

lck_grp_t		bank_dev_lock_grp;
lck_attr_t		bank_dev_lock_attr;
lck_grp_attr_t		bank_dev_lock_grp_attr;
#endif

/*
 * Lock group attributes for bank sub system.
 */
lck_grp_t		bank_lock_grp;
lck_attr_t		bank_lock_attr;
lck_grp_attr_t		bank_lock_grp_attr;

/*
 * Routine: bank_init
 * Purpose: Initialize the BANK subsystem.
 * Returns: None.
 */
void
bank_init()
{
	kern_return_t kr = KERN_SUCCESS;
	/* setup zones for bank_task and bank_account objects */
	bank_task_zone       = zinit(sizeof(struct bank_task),
	                       MAX_BANK_TASK * sizeof(struct bank_task),
	                       sizeof(struct bank_task),
	                       "bank_task");

	bank_account_zone    = zinit(sizeof(struct bank_account),
	                       MAX_BANK_ACCOUNT * sizeof(struct bank_account),
	                       sizeof(struct bank_account),
	                       "bank_account");

	init_bank_ledgers();

	/* Initialize bank lock group and lock attributes. */
	lck_grp_attr_setdefault(&bank_lock_grp_attr);
	lck_grp_init(&bank_lock_grp, "bank_lock", &bank_lock_grp_attr);
	lck_attr_setdefault(&bank_lock_attr);

#if DEVELOPMENT || DEBUG
	/* Initialize global bank development lock group and lock attributes. */
	lck_grp_attr_setdefault(&bank_dev_lock_grp_attr);
	lck_grp_init(&bank_dev_lock_grp, "bank_dev_lock", &bank_dev_lock_grp_attr);
	lck_attr_setdefault(&bank_dev_lock_attr);

	lck_mtx_init(&bank_tasks_list_lock, &bank_dev_lock_grp, &bank_dev_lock_attr);
	lck_mtx_init(&bank_accounts_list_lock, &bank_dev_lock_grp, &bank_dev_lock_attr);

	queue_init(&bank_tasks_list);
	queue_init(&bank_accounts_list);
#endif

	/* Register the bank manager with the Vouchers sub system. */
	kr = ipc_register_well_known_mach_voucher_attr_manager(
	                &bank_manager,
	                0,
	                MACH_VOUCHER_ATTR_KEY_BANK,
	                &bank_voucher_attr_control);
	if (kr != KERN_SUCCESS )
		panic("BANK subsystem initialization failed");

	kprintf("BANK subsystem is initialized\n");
	return ;
}


/*
 * BANK Resource Manager Routines.
 */


/*
 * Routine: bank_release_value
 * Purpose: Release a value, if sync matches the sync count in value.
 * Returns: KERN_SUCCESS: on Successful deletion.
 *          KERN_FAILURE: if sync value does not matches.
 */
kern_return_t
bank_release_value(
	ipc_voucher_attr_manager_t		__assert_only manager,
	mach_voucher_attr_key_t			__assert_only key,
	mach_voucher_attr_value_handle_t		      value,
	mach_voucher_attr_value_reference_t	          sync)
{
	bank_task_t bank_task = BANK_TASK_NULL;
	bank_element_t bank_element = BANK_ELEMENT_NULL;
	bank_account_t bank_account = BANK_ACCOUNT_NULL;
	kern_return_t kr = KERN_SUCCESS;

	assert(MACH_VOUCHER_ATTR_KEY_BANK == key);
	assert(manager == &bank_manager);


	bank_element = HANDLE_TO_BANK_ELEMENT(value);
	if (bank_element == BANK_DEFAULT_VALUE) {
		/* Return success for default value */
		return KERN_SUCCESS;
	}


	if (bank_element->be_type == BANK_TASK) {
		bank_task = CAST_TO_BANK_TASK(bank_element);
		
		if (bank_task->bt_made != (int)sync) {
			return KERN_FAILURE;
		}

		bank_task_made_release_num(bank_task, sync);
		bank_task_dealloc(bank_task, sync);
	} else if (bank_element->be_type == BANK_ACCOUNT) {
		bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
		kr = bank_account_dealloc_with_sync(bank_account, sync);
	} else {
		panic("Bogus bank type: %d passed in get_value\n", bank_element->be_type);
	}

	return kr;
}


/*
 * Routine: bank_get_value
 */
kern_return_t
bank_get_value(
	ipc_voucher_attr_manager_t 		__assert_only manager,
	mach_voucher_attr_key_t 		__assert_only key,
	mach_voucher_attr_recipe_command_t 	          command,
	mach_voucher_attr_value_handle_array_t 	      prev_values,
	mach_msg_type_number_t 			      prev_value_count,
	mach_voucher_attr_content_t          __unused recipe,
	mach_voucher_attr_content_size_t     __unused recipe_size,
	mach_voucher_attr_value_handle_t             *out_value,
	ipc_voucher_t 				                 *out_value_voucher)
{
	bank_task_t bank_task = BANK_TASK_NULL;
	bank_task_t bank_holder = BANK_TASK_NULL;
	bank_task_t bank_merchant = BANK_TASK_NULL;
	bank_element_t bank_element = BANK_ELEMENT_NULL;
	bank_account_t bank_account = BANK_ACCOUNT_NULL;
	bank_account_t old_bank_account = BANK_ACCOUNT_NULL;
	mach_voucher_attr_value_handle_t bank_handle;
	task_t task;
	kern_return_t kr = KERN_SUCCESS;
	mach_msg_type_number_t i;

	assert(MACH_VOUCHER_ATTR_KEY_BANK == key);
	assert(manager == &bank_manager);

	/* never an out voucher */
	*out_value_voucher = IPC_VOUCHER_NULL;

	switch (command) {

	case MACH_VOUCHER_ATTR_BANK_CREATE:

		/* Get the bank context from the current task and take a reference on it. */
		task = current_task();
		bank_task = get_bank_task_context(task);
		if (bank_task == BANK_TASK_NULL)
			return KERN_RESOURCE_SHORTAGE;

		bank_task_reference(bank_task);
		bank_task_made_reference(bank_task);

		*out_value = BANK_ELEMENT_TO_HANDLE(bank_task);
		break;

	case MACH_VOUCHER_ATTR_REDEEM:

		for (i = 0; i < prev_value_count; i++) {
			bank_handle = prev_values[i];
			bank_element = HANDLE_TO_BANK_ELEMENT(bank_handle);

			if (bank_element == BANK_DEFAULT_VALUE)
				continue;

			task = current_task();
			if (bank_element->be_type == BANK_TASK) {
				bank_holder = CAST_TO_BANK_TASK(bank_element);
			} else if (bank_element->be_type == BANK_ACCOUNT) {
				old_bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
				bank_holder = old_bank_account->ba_holder;
			} else {
				panic("Bogus bank type: %d passed in get_value\n", bank_element->be_type);
			}

			bank_merchant = get_bank_task_context(task);
			if (bank_merchant == BANK_TASK_NULL)
				return KERN_RESOURCE_SHORTAGE;

			/* Check if trying to redeem for self task, return the bank task */
			if (bank_holder == bank_merchant) {
				bank_task_reference(bank_holder);
				bank_task_made_reference(bank_holder);
				*out_value = BANK_ELEMENT_TO_HANDLE(bank_holder);
				return kr;
			}

			bank_account = bank_account_alloc_init(bank_holder, bank_merchant);
			if (bank_account == BANK_ACCOUNT_NULL)
				return KERN_RESOURCE_SHORTAGE;

			*out_value = BANK_ELEMENT_TO_HANDLE(bank_account);
			return kr;
		}

		*out_value = BANK_ELEMENT_TO_HANDLE(BANK_DEFAULT_VALUE);
		break;
	default:
		kr = KERN_INVALID_ARGUMENT;
		break;
	}

	return kr;
}


/*
 * Routine: bank_extract_content
 * Purpose: Extract a set of aid from an array of voucher values.
 * Returns: KERN_SUCCESS: on Success.
 *          KERN_FAILURE: one of the value is not present in the hash.
 *          KERN_NO_SPACE: insufficeint buffer provided to fill an array of aid.
 */
kern_return_t
bank_extract_content(
	ipc_voucher_attr_manager_t      __assert_only manager,
	mach_voucher_attr_key_t         __assert_only key,
	mach_voucher_attr_value_handle_array_t        values,
	mach_msg_type_number_t 			              value_count,
	mach_voucher_attr_recipe_command_t           *out_command,
	mach_voucher_attr_content_t                   out_recipe,
	mach_voucher_attr_content_size_t             *in_out_recipe_size)
{
	bank_task_t bank_task = BANK_TASK_NULL;
	bank_element_t bank_element = BANK_ELEMENT_NULL;
	bank_account_t bank_account = BANK_ACCOUNT_NULL;
	mach_voucher_attr_value_handle_t bank_handle;
	char buf[MACH_VOUCHER_BANK_CONTENT_SIZE];
	mach_msg_type_number_t i;

	assert(MACH_VOUCHER_ATTR_KEY_BANK == key);
	assert(manager == &bank_manager);

	for (i = 0; i < value_count; i++) {
		bank_handle = values[i];
		bank_element = HANDLE_TO_BANK_ELEMENT(bank_handle);
		if (bank_element == BANK_DEFAULT_VALUE)
			continue;

		if (MACH_VOUCHER_BANK_CONTENT_SIZE > *in_out_recipe_size) {
			*in_out_recipe_size = 0;
			return KERN_NO_SPACE;
		}

		if (bank_element->be_type == BANK_TASK) {
			bank_task = CAST_TO_BANK_TASK(bank_element);
			snprintf(buf, MACH_VOUCHER_BANK_CONTENT_SIZE, 
			         " Bank Context for a pid %d\n", bank_task->bt_pid);
		} else if (bank_element->be_type == BANK_ACCOUNT) {
			bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
			snprintf(buf, MACH_VOUCHER_BANK_CONTENT_SIZE,
			         " Bank Account linking holder pid %d with merchant pid %d\n",
				 bank_account->ba_holder->bt_pid,
				 bank_account->ba_merchant->bt_pid);
		} else {
			panic("Bogus bank type: %d passed in get_value\n", bank_element->be_type);
		}


		memcpy(&out_recipe[0], buf, strlen(buf) + 1);
		*out_command = MACH_VOUCHER_ATTR_BANK_NULL;
		*in_out_recipe_size = (mach_voucher_attr_content_size_t)strlen(buf) + 1;
		return KERN_SUCCESS;
	}

	return KERN_SUCCESS;
}

/*
 * Routine: bank_command
 * Purpose: Execute a command against a set of ATM values.
 * Returns: KERN_SUCCESS: On successful execution of command.
 	    KERN_FAILURE: On failure.
 */
kern_return_t
bank_command(
	ipc_voucher_attr_manager_t 		   __assert_only manager,
	mach_voucher_attr_key_t 		   __assert_only key,
	mach_voucher_attr_value_handle_array_t 	__unused values,
	mach_msg_type_number_t 			__unused value_count,
	mach_voucher_attr_command_t		 __unused command,
	mach_voucher_attr_content_t 	   __unused in_content,
	mach_voucher_attr_content_size_t   __unused in_content_size,
	mach_voucher_attr_content_t 	   __unused out_content,
	mach_voucher_attr_content_size_t   __unused *out_content_size)
{
	bank_task_t bank_task = BANK_TASK_NULL;
	bank_element_t bank_element = BANK_ELEMENT_NULL;
	bank_account_t bank_account = BANK_ACCOUNT_NULL;
	mach_voucher_attr_value_handle_t bank_handle;
	mach_msg_type_number_t i;
	int32_t pid;

	assert(MACH_VOUCHER_ATTR_KEY_BANK == key);
	assert(manager == &bank_manager);

	switch (command) {
	case BANK_ORIGINATOR_PID:

		if ((sizeof(pid)) > *out_content_size) {
			*out_content_size = 0;
			return KERN_NO_SPACE;
		}

		for (i = 0; i < value_count; i++) {
			bank_handle = values[i];
			bank_element = HANDLE_TO_BANK_ELEMENT(bank_handle);
			if (bank_element == BANK_DEFAULT_VALUE)
				continue;

			if (bank_element->be_type == BANK_TASK) {
				bank_task = CAST_TO_BANK_TASK(bank_element);
			} else if (bank_element->be_type == BANK_ACCOUNT) {
				bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
				bank_task = bank_account->ba_holder;
			} else {
				panic("Bogus bank type: %d passed in voucher_command\n", bank_element->be_type);
			}
			pid = bank_task->bt_pid;

			memcpy(&out_content[0], &pid, sizeof(pid));
			*out_content_size = (mach_voucher_attr_content_size_t)sizeof(pid);
			return KERN_SUCCESS;
		}
		/* In the case of no value, return error KERN_INVALID_VALUE */
		*out_content_size = 0;
		return KERN_INVALID_VALUE;

		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}
	return KERN_SUCCESS;
}


void
bank_release(
	ipc_voucher_attr_manager_t 		__assert_only manager)
{
	assert(manager == &bank_manager);
}



/*
 * Bank Internal Routines.
 */

/*
 * Routine: bank_task_alloc_init
 * Purpose: Allocate and initialize a bank task structure.
 * Returns: bank_task_t on Success.
 *          BANK_TASK_NULL: on Failure.
 * Notes:   Leaves the task and creditcard blank and has only 1 ref,
            needs to take 1 extra ref after the task field is initialized.
 */
static bank_task_t
bank_task_alloc_init(void)
{
	bank_task_t new_bank_task;

	new_bank_task = (bank_task_t) zalloc(bank_task_zone);
	if (new_bank_task == BANK_TASK_NULL)
		return BANK_TASK_NULL;

	new_bank_task->bt_type = BANK_TASK;
	new_bank_task->bt_refs = 1;
	new_bank_task->bt_made = 0;
	new_bank_task->bt_pid = 0;
	new_bank_task->bt_creditcard = NULL;
	queue_init(&new_bank_task->bt_accounts_to_pay);
	queue_init(&new_bank_task->bt_accounts_to_charge);
	lck_mtx_init(&new_bank_task->bt_acc_to_pay_lock, &bank_lock_grp, &bank_lock_attr);
	lck_mtx_init(&new_bank_task->bt_acc_to_charge_lock, &bank_lock_grp, &bank_lock_attr);

#if DEVELOPMENT || DEBUG
	new_bank_task->bt_task = NULL;
	lck_mtx_lock(&bank_tasks_list_lock);
	queue_enter(&bank_tasks_list, new_bank_task, bank_task_t, bt_global_elt);
	lck_mtx_unlock(&bank_tasks_list_lock);
#endif
	return (new_bank_task);
}

/*
 * Routine: bank_account_alloc_init
 * Purpose: Allocate and Initialize the bank account struct.
 * Returns: bank_account_t : On Success.
 *          BANK_ACCOUNT_NULL: On Failure.
 */
static bank_account_t
bank_account_alloc_init(
	bank_task_t bank_holder,
	bank_task_t bank_merchant)
{
	bank_account_t new_bank_account;
	bank_account_t bank_account;
	boolean_t entry_found = FALSE;
	ledger_t new_ledger = ledger_instantiate(bank_ledger_template, LEDGER_CREATE_INACTIVE_ENTRIES);

	if (new_ledger == NULL)
		return BANK_ACCOUNT_NULL;

	ledger_entry_setactive(new_ledger, bank_ledgers.cpu_time);
	new_bank_account = (bank_account_t) zalloc(bank_account_zone);
	if (new_bank_account == BANK_ACCOUNT_NULL) {
		ledger_dereference(new_ledger);
		return BANK_ACCOUNT_NULL;
	}

	new_bank_account->ba_type = BANK_ACCOUNT;
	new_bank_account->ba_refs = 1;
	new_bank_account->ba_made = 1;
	new_bank_account->ba_pid = 0;
	new_bank_account->ba_bill = new_ledger;
	new_bank_account->ba_merchant = bank_merchant;
	new_bank_account->ba_holder = bank_holder;

	/* Iterate through accounts need to pay list to find the existing entry */
	lck_mtx_lock(&bank_holder->bt_acc_to_pay_lock);
	queue_iterate(&bank_holder->bt_accounts_to_pay, bank_account, bank_account_t, ba_next_acc_to_pay) {
		if (bank_account->ba_merchant != bank_merchant)
			continue;

		entry_found = TRUE;
		/* Take a made ref, since this value would be returned to voucher system. */
		bank_account_reference(bank_account);
		bank_account_made_reference(bank_account);
		break;
	}

	if (!entry_found) {
	
		/*  Create a linkage between the holder and the merchant task, Grab both the list locks before adding it to the list. */
		lck_mtx_lock(&bank_merchant->bt_acc_to_charge_lock);
	
		/* Add the account entry into Accounts need to pay account link list. */
		queue_enter(&bank_holder->bt_accounts_to_pay, new_bank_account, bank_account_t, ba_next_acc_to_pay);

		/* Add the account entry into Accounts need to charge account link list. */
		queue_enter(&bank_merchant->bt_accounts_to_charge, new_bank_account, bank_account_t, ba_next_acc_to_charge);

		lck_mtx_unlock(&bank_merchant->bt_acc_to_charge_lock);
	}

	lck_mtx_unlock(&bank_holder->bt_acc_to_pay_lock);

	if (entry_found) {
		ledger_dereference(new_ledger);
		zfree(bank_account_zone, new_bank_account);
		return bank_account;
	}
	
	bank_task_reference(bank_holder);
	bank_task_reference(bank_merchant);

#if DEVELOPMENT || DEBUG
	new_bank_account->ba_task = NULL;
	lck_mtx_lock(&bank_accounts_list_lock);
	queue_enter(&bank_accounts_list, new_bank_account, bank_account_t, ba_global_elt);
	lck_mtx_unlock(&bank_accounts_list_lock);
#endif

	return (new_bank_account);
}

/*
 * Routine: get_bank_task_context
 * Purpose: Get the bank context of the given task
 * Returns: bank_task_t on Success.
 *          BANK_TASK_NULL: on Failure.
 * Note:    Initialize bank context if NULL.
 */
static bank_task_t
get_bank_task_context(task_t task)
{
	bank_task_t bank_task;

	if (task->bank_context)
		return (task->bank_context);

	bank_task = bank_task_alloc_init();

	/* Grab the task lock and check if we won the race. */
	task_lock(task);
	if (task->bank_context) {
		task_unlock(task);
		if (bank_task != BANK_TASK_NULL) 
			bank_task_dealloc(bank_task, 1);
		return (task->bank_context);
	} else if (bank_task == BANK_TASK_NULL) {
		task_unlock(task);
		return BANK_TASK_NULL;
	}
	/* We won the race. Take a ref on the ledger and initialize bank task. */
	bank_task->bt_creditcard = task->ledger;
	bank_task->bt_pid = task_pid(task);
#if DEVELOPMENT || DEBUG
	bank_task->bt_task = task;
#endif
	ledger_reference(task->ledger);

	task->bank_context = bank_task;
	task_unlock(task);
	
	return (bank_task);
}
	
/*
 * Routine: bank_task_dealloc
 * Purpose: Drops the reference on bank task.
 * Returns: None.
 */
static void
bank_task_dealloc(
	bank_task_t bank_task,
	mach_voucher_attr_value_reference_t sync)
{
	assert(bank_task->bt_refs >= 0);

	if (bank_task_release_num(bank_task, sync) > (int)sync)
		return;

	assert(bank_task->bt_refs == 0);
	assert(queue_empty(&bank_task->bt_accounts_to_pay));
	assert(queue_empty(&bank_task->bt_accounts_to_charge));

	ledger_dereference(bank_task->bt_creditcard);
	lck_mtx_destroy(&bank_task->bt_acc_to_pay_lock, &bank_lock_grp);
	lck_mtx_destroy(&bank_task->bt_acc_to_charge_lock, &bank_lock_grp);

#if DEVELOPMENT || DEBUG
	lck_mtx_lock(&bank_tasks_list_lock);
	queue_remove(&bank_tasks_list, bank_task, bank_task_t, bt_global_elt);
	lck_mtx_unlock(&bank_tasks_list_lock);
#endif

	zfree(bank_task_zone, bank_task);
}

/*
 * Routine: bank_account_dealloc_with_sync
 * Purpose: Drop the reference on bank account if the sync matches.
 * Returns: KERN_SUCCESS if sync matches.
 *          KERN_FAILURE on mismatch.
 */
static kern_return_t
bank_account_dealloc_with_sync(
	bank_account_t bank_account,
	mach_voucher_attr_value_reference_t sync)
{
	bank_task_t bank_holder = bank_account->ba_holder;
	bank_task_t bank_merchant = bank_account->ba_merchant;

	/* Grab the acc to pay list lock and check the sync value */
	lck_mtx_lock(&bank_holder->bt_acc_to_pay_lock);

	if (bank_account->ba_made != (int)sync) {
		lck_mtx_unlock(&bank_holder->bt_acc_to_pay_lock);
		return KERN_FAILURE;
	}
		
	bank_account_made_release_num(bank_account, sync);

	if (bank_account_release_num(bank_account, sync) > (int)sync)
		panic("Sync and ref value did not match for bank account %p\n", bank_account);


	/* Grab both the acc to pay and acc to charge locks */
	lck_mtx_lock(&bank_merchant->bt_acc_to_charge_lock);

	bank_rollup_chit_to_tasks(bank_account->ba_bill, bank_holder, bank_merchant);
	
	/* Remove the account entry from Accounts need to pay account link list. */
	queue_remove(&bank_holder->bt_accounts_to_pay, bank_account, bank_account_t, ba_next_acc_to_pay);
	
	/* Remove the account entry from Accounts need to charge account link list. */
	queue_remove(&bank_merchant->bt_accounts_to_charge, bank_account, bank_account_t, ba_next_acc_to_charge);
	
	lck_mtx_unlock(&bank_merchant->bt_acc_to_charge_lock);
	lck_mtx_unlock(&bank_holder->bt_acc_to_pay_lock);

	ledger_dereference(bank_account->ba_bill);

	/* Drop the reference of bank holder and merchant */
	bank_task_dealloc(bank_holder, 1);
	bank_task_dealloc(bank_merchant, 1);

#if DEVELOPMENT || DEBUG
	lck_mtx_lock(&bank_accounts_list_lock);
	queue_remove(&bank_accounts_list, bank_account, bank_account_t, ba_global_elt);
	lck_mtx_unlock(&bank_accounts_list_lock);
#endif
	
	zfree(bank_account_zone, bank_account);
	return KERN_SUCCESS;
}

/*
 * Routine: bank_rollup_chit_to_tasks
 * Purpose: Debit and Credit holder's and merchant's ledgers.
 * Returns: None.
 */
static void
bank_rollup_chit_to_tasks(
	ledger_t bill,
	bank_task_t bank_holder,
	bank_task_t bank_merchant)
{
	ledger_amount_t credit;
	ledger_amount_t debit;
	kern_return_t ret;

	ret = ledger_get_entries(bill, bank_ledgers.cpu_time, &credit, &debit);
	if (ret != KERN_SUCCESS) {
		return;
	}

#if DEVELOPMENT || DEBUG
	if (debit != 0) {
		panic("bank_rollup: debit: %lld non zero\n", debit);
	}
#endif

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (BANK_CODE(BANK_ACCOUNT_INFO, (BANK_SETTLE_CPU_TIME))) | DBG_FUNC_NONE,
			bank_merchant->bt_pid, bank_holder->bt_pid, credit, debit, 0);
#if CONFIG_BANK
	ledger_credit(bank_holder->bt_creditcard, task_ledgers.cpu_time_billed_to_me, credit);
	ledger_debit(bank_holder->bt_creditcard, task_ledgers.cpu_time_billed_to_me, debit);
	
	ledger_credit(bank_merchant->bt_creditcard, task_ledgers.cpu_time_billed_to_others, credit);
	ledger_debit(bank_merchant->bt_creditcard, task_ledgers.cpu_time_billed_to_others, debit);
#endif
}



/*
 * Routine: bank_task_destroy
 * Purpose: Drops reference on bank task.
 * Returns: None.
 */
void
bank_task_destroy(bank_task_t bank_task)
{
	bank_task_dealloc(bank_task, 1);
}

/*
 * Routine: init_bank_ledgers
 * Purpose: Initialize template for bank ledgers.
 * Returns: None.
 */
static void
init_bank_ledgers(void) {
	ledger_template_t t;
	int idx;
	
	assert(bank_ledger_template == NULL);

	if ((t = ledger_template_create("Bank ledger")) == NULL)
		panic("couldn't create bank ledger template");

	if ((idx = ledger_entry_add(t, "cpu_time", "sched", "ns")) < 0) {
		panic("couldn't create cpu_time entry for bank ledger template");
	}

	bank_ledgers.cpu_time = idx;
	bank_ledger_template = t;
}

/*
 * Routine: bank_billed_time
 * Purpose: Walk throught the Accounts need to pay account list and get the current billing balance.
 * Returns: balance.
 */
uint64_t
bank_billed_time(bank_task_t bank_task)
{
	int64_t balance = 0;
#ifdef CONFIG_BANK
	bank_account_t bank_account;
	int64_t temp = 0;
	kern_return_t kr;
#endif
	if (bank_task == BANK_TASK_NULL) {
		return balance;
	}
	
#ifdef CONFIG_BANK
	lck_mtx_lock(&bank_task->bt_acc_to_pay_lock);

	kr = ledger_get_balance(bank_task->bt_creditcard, task_ledgers.cpu_time_billed_to_me, &temp);
	if (kr == KERN_SUCCESS && temp >= 0) {
		balance += temp;
	}
#if DEVELOPMENT || DEBUG
	else {
		printf("bank_bill_time: ledger_get_balance failed or negative balance in ledger: %lld\n", temp);
	}
#endif /* DEVELOPMENT || DEBUG */

	queue_iterate(&bank_task->bt_accounts_to_pay, bank_account, bank_account_t, ba_next_acc_to_pay) {
		temp = 0;
		kr = ledger_get_balance(bank_account->ba_bill, bank_ledgers.cpu_time, &temp);
		if (kr == KERN_SUCCESS && temp >= 0) {
			balance += temp;
		}
#if DEVELOPMENT || DEBUG
		else {
			printf("bank_bill_time: ledger_get_balance failed or negative balance in ledger: %lld\n", temp);
		}
#endif /* DEVELOPMENT || DEBUG */
	}
	lck_mtx_unlock(&bank_task->bt_acc_to_pay_lock);
#endif
	return (uint64_t)balance;
}

/*
 * Routine: bank_serviced_time
 * Purpose: Walk throught the Account need to charge account list and get the current balance to be charged.
 * Returns: balance.
 */
uint64_t
bank_serviced_time(bank_task_t bank_task)
{
	int64_t balance = 0;
#ifdef CONFIG_BANK
	bank_account_t bank_account;
	int64_t temp = 0;
	kern_return_t kr;
#endif
	if (bank_task == BANK_TASK_NULL) {
		return balance;
	}

#ifdef CONFIG_BANK
	lck_mtx_lock(&bank_task->bt_acc_to_charge_lock);

	kr = ledger_get_balance(bank_task->bt_creditcard, task_ledgers.cpu_time_billed_to_others, &temp);
	if (kr == KERN_SUCCESS && temp >= 0) {
		balance += temp;
	}
#if DEVELOPMENT || DEBUG
	else {
		printf("bank_serviced_time: ledger_get_balance failed or negative balance in ledger: %lld\n", temp);
	}
#endif /* DEVELOPMENT || DEBUG */

	queue_iterate(&bank_task->bt_accounts_to_charge, bank_account, bank_account_t, ba_next_acc_to_charge) {
		temp = 0;
		kr = ledger_get_balance(bank_account->ba_bill, bank_ledgers.cpu_time, &temp);
		if (kr == KERN_SUCCESS && temp >= 0) {
			balance += temp;
		}
#if DEVELOPMENT || DEBUG
		else {
			printf("bank_serviced_time: ledger_get_balance failed or negative balance in ledger: %lld\n", temp);
		}
#endif /* DEVELOPMENT || DEBUG */
	}
	lck_mtx_unlock(&bank_task->bt_acc_to_charge_lock);
#endif
	return (uint64_t)balance;
}

/*
 * Routine: bank_get_voucher_ledger
 * Purpose: Get the bankledger (chit) from the voucher.
 * Returns: bank_ledger if bank_account attribute present in voucher.
 *          NULL on no attribute ot bank_task attribute.
 */
ledger_t
bank_get_voucher_ledger(ipc_voucher_t voucher)
{
	bank_element_t bank_element = BANK_ELEMENT_NULL;
	bank_account_t bank_account = BANK_ACCOUNT_NULL;
	mach_voucher_attr_value_handle_t vals[MACH_VOUCHER_ATTR_VALUE_MAX_NESTED];
	mach_voucher_attr_value_handle_array_size_t val_count;
	ledger_t bankledger = NULL;
	kern_return_t kr;

	val_count = MACH_VOUCHER_ATTR_VALUE_MAX_NESTED;
	kr = mach_voucher_attr_control_get_values(bank_voucher_attr_control,
				voucher,
				vals,
				&val_count);

	if (kr != KERN_SUCCESS)
		return NULL;

	if (val_count == 0)
		return NULL;

	bank_element = HANDLE_TO_BANK_ELEMENT(vals[0]);
	if (bank_element == BANK_DEFAULT_VALUE)
		return NULL;

	if (bank_element->be_type == BANK_TASK) {
		bankledger = NULL;
	} else if (bank_element->be_type == BANK_ACCOUNT) {
		bank_account = CAST_TO_BANK_ACCOUNT(bank_element);
		bankledger = bank_account->ba_bill;
	} else {
		panic("Bogus bank type: %d passed in bank_get_voucher_ledger\n", bank_element->be_type);
	}

	return (bankledger);
}

/*
 * Routine: bank_swap_thread_bank_ledger
 * Purpose: swap the bank ledger on the thread.
 * Retunrs: None.
 * Note: Should be only called for current thread or thread which is not started.
 */
void
bank_swap_thread_bank_ledger(thread_t thread __unused, ledger_t new_ledger __unused)
{
#ifdef CONFIG_BANK 
	spl_t			s;
	processor_t		processor;
	ledger_t old_ledger = thread->t_bankledger;
	int64_t ctime, effective_ledger_time_consumed = 0; 
	int64_t remainder = 0, consumed = 0; 
	
	if (old_ledger == NULL && new_ledger == NULL)
		return;

	assert((thread == current_thread() || thread->started == 0));

	s = splsched();
	thread_lock(thread);

	/*
	 * Calculation of time elapsed by the thread before voucher swap.
	 * Following is the timeline which shows all the variables used in the calculation below.
	 *
	 *               thread ledger
	 *                 cpu_time
	 *                    |<-          consumed            ->|<- remainder  ->|
	 * timeline  ----------------------------------------------------------------->
	 *                    |                                  |                |
	 *             thread_dispatch                        ctime           quantum end
	 *
	 *                           |<-effective_ledger_time -> |
	 *               deduct_bank_ledger_time
	 */

	ctime = mach_absolute_time();
	processor = thread->last_processor;
	if (processor != NULL) {
		if ((int64_t)processor->quantum_end > ctime)
			remainder = (int64_t)processor->quantum_end - ctime;
	
		consumed = thread->quantum_remaining - remainder;
		effective_ledger_time_consumed = consumed - thread->t_deduct_bank_ledger_time;
	}

	thread->t_deduct_bank_ledger_time = consumed;

	thread->t_bankledger = new_ledger;

	thread_unlock(thread);
	splx(s);
	
	if (old_ledger != NULL)
		ledger_credit(old_ledger,
			bank_ledgers.cpu_time,
			effective_ledger_time_consumed);
#endif
}

