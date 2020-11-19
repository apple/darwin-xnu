/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/kern_return.h>
#include <mach/sync_policy.h>
#include <mach/task.h>

#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/ipc_sync.h>
#include <kern/ipc_tt.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_eventlink.h>
#include <kern/host.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <kern/mach_param.h>
#include <mach/mach_traps.h>
#include <mach/mach_eventlink_server.h>

#include <libkern/OSAtomic.h>

static ZONE_DECLARE(ipc_eventlink_zone, "ipc_eventlink",
    sizeof(struct ipc_eventlink_base), ZC_NONE);

os_refgrp_decl(static, ipc_eventlink_refgrp, "eventlink", NULL);

#if DEVELOPMENT || DEBUG
static queue_head_t ipc_eventlink_list = QUEUE_HEAD_INITIALIZER(ipc_eventlink_list);
static LCK_GRP_DECLARE(ipc_eventlink_dev_lock_grp, "ipc_eventlink_dev_lock");
static LCK_SPIN_DECLARE(global_ipc_eventlink_lock, &ipc_eventlink_dev_lock_grp);

#define global_ipc_eventlink_lock() \
	lck_spin_lock_grp(&global_ipc_eventlink_lock, &ipc_eventlink_dev_lock_grp)
#define global_ipc_eventlink_lock_try() \
	lck_spin_try_lock_grp(&global_ipc_eventlink_lock, &ipc_eventlink_dev_lock_grp)
#define global_ipc_eventlink_unlock() \
	lck_spin_unlock(&global_ipc_eventlink_lock)

#endif /* DEVELOPMENT || DEBUG */

/* Forward declarations */
static struct ipc_eventlink_base *
ipc_eventlink_alloc(void);

static void
ipc_eventlink_initialize(
	struct ipc_eventlink_base *ipc_eventlink_base);

static kern_return_t
ipc_eventlink_destroy_internal(
	struct ipc_eventlink *ipc_eventlink);

static kern_return_t
ipc_eventlink_signal(
	struct ipc_eventlink *ipc_eventlink);

static uint64_t
ipc_eventlink_signal_wait_until_trap_internal(
	mach_port_name_t                     wait_port,
	mach_port_name_t                     signal_port,
	uint64_t                             count,
	mach_eventlink_signal_wait_option_t  el_option,
	kern_clock_id_t                      clock_id,
	uint64_t                             deadline);

static kern_return_t
ipc_eventlink_signal_wait_internal(
	struct ipc_eventlink        *wait_eventlink,
	struct ipc_eventlink        *signal_eventlink,
	uint64_t                    deadline,
	uint64_t                    *count,
	ipc_eventlink_option_t      eventlink_option);

static kern_return_t
ipc_eventlink_convert_wait_result(int wait_result);

static kern_return_t
ipc_eventlink_signal_internal_locked(
	struct ipc_eventlink         *signal_eventlink,
	ipc_eventlink_option_t       eventlink_option);

static kern_return_t
convert_port_to_eventlink_locked(
	ipc_port_t                      port,
	struct ipc_eventlink            **ipc_eventlink_ptr);

static kern_return_t
port_name_to_eventlink(
	mach_port_name_t              name,
	struct ipc_eventlink          **ipc_eventlink_ptr);

/*
 * Name: ipc_eventlink_alloc
 *
 * Description: Allocates an ipc_eventlink struct and initializes it.
 *
 * Args: None.
 *
 * Returns:
 *   ipc_eventlink_base on Success.
 */
static struct ipc_eventlink_base *
ipc_eventlink_alloc(void)
{
	struct ipc_eventlink_base *ipc_eventlink_base = IPC_EVENTLINK_BASE_NULL;
	ipc_eventlink_base = zalloc(ipc_eventlink_zone);

	ipc_eventlink_initialize(ipc_eventlink_base);

#if DEVELOPMENT || DEBUG
	/* Add ipc_eventlink to global list */
	global_ipc_eventlink_lock();
	queue_enter(&ipc_eventlink_list, ipc_eventlink_base,
	    struct ipc_eventlink_base *, elb_global_elm);
	global_ipc_eventlink_unlock();
#endif
	return ipc_eventlink_base;
}

/*
 * Name: ipc_eventlink_initialize
 *
 * Description: Initializes ipc eventlink struct.
 *
 * Args: ipc eventlink base.
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
static void
ipc_eventlink_initialize(
	struct ipc_eventlink_base *ipc_eventlink_base)
{
	int i;
	kern_return_t kr;

	kr = waitq_init(&ipc_eventlink_base->elb_waitq, SYNC_POLICY_DISABLE_IRQ);
	assert(kr == KERN_SUCCESS);

	/* Initialize the count to 2, refs for each ipc eventlink port */
	os_ref_init_count(&ipc_eventlink_base->elb_ref_count, &ipc_eventlink_refgrp, 2);
	ipc_eventlink_base->elb_active = TRUE;
	ipc_eventlink_base->elb_type = IPC_EVENTLINK_TYPE_NO_COPYIN;

	for (i = 0; i < 2; i++) {
		struct ipc_eventlink *ipc_eventlink = &(ipc_eventlink_base->elb_eventlink[i]);

		ipc_eventlink->el_port = ipc_kobject_alloc_port((ipc_kobject_t)ipc_eventlink,
		    IKOT_EVENTLINK, IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);
		/* ipc_kobject_alloc_port never fails */
		ipc_eventlink->el_thread = THREAD_NULL;
		ipc_eventlink->el_sync_counter = 0;
		ipc_eventlink->el_wait_counter = UINT64_MAX;
		ipc_eventlink->el_base = ipc_eventlink_base;
	}
}

/*
 * Name: mach_eventlink_create
 *
 * Description: Allocates an ipc_eventlink struct and initializes it.
 *
 * Args:
 *   task : task port of the process
 *   mach_eventlink_create_option_t: option
 *   eventlink_port_pair: eventlink port array
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
kern_return_t
mach_eventlink_create(
	task_t                             task,
	mach_eventlink_create_option_t     elc_option,
	eventlink_port_pair_t              eventlink_port_pair)
{
	int i;
	struct ipc_eventlink_base *ipc_eventlink_base;

	if (task == TASK_NULL || task != current_task() ||
	    elc_option != MELC_OPTION_NO_COPYIN) {
		return KERN_INVALID_ARGUMENT;
	}

	ipc_eventlink_base = ipc_eventlink_alloc();

	for (i = 0; i < 2; i++) {
		eventlink_port_pair[i] = ipc_eventlink_base->elb_eventlink[i].el_port;
	}

	return KERN_SUCCESS;
}

/*
 * Name: mach_eventlink_destroy
 *
 * Description: Destroy an ipc_eventlink, wakeup all threads.
 *
 * Args:
 *   eventlink: eventlink
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
kern_return_t
mach_eventlink_destroy(
	struct ipc_eventlink *ipc_eventlink)
{
	ipc_eventlink_destroy_internal(ipc_eventlink);

	/* mach_eventlink_destroy should succeed for terminated eventlink */
	return KERN_SUCCESS;
}

/*
 * Name: ipc_eventlink_destroy_internal
 *
 * Description: Destroy an ipc_eventlink, wakeup all threads.
 *
 * Args:
 *   eventlink: eventlink
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
static kern_return_t
ipc_eventlink_destroy_internal(
	struct ipc_eventlink *ipc_eventlink)
{
	spl_t s;
	int i;
	struct ipc_eventlink_base *ipc_eventlink_base;
	thread_t associated_thread[2] = {};
	ipc_port_t ipc_eventlink_port = IPC_PORT_NULL;
	ipc_port_t ipc_eventlink_port_remote = IPC_PORT_NULL;

	if (ipc_eventlink == IPC_EVENTLINK_NULL) {
		return KERN_TERMINATED;
	}

	s = splsched();
	ipc_eventlink_lock(ipc_eventlink);

	ipc_eventlink_base = ipc_eventlink->el_base;

	/* Check if the eventlink is active */
	if (!ipc_eventlink_active(ipc_eventlink)) {
		ipc_eventlink_unlock(ipc_eventlink);
		splx(s);
		return KERN_TERMINATED;
	}

	for (i = 0; i < 2; i++) {
		struct ipc_eventlink *temp_ipc_eventlink = &ipc_eventlink_base->elb_eventlink[i];

		/* Wakeup threads sleeping on eventlink */
		if (temp_ipc_eventlink->el_thread) {
			associated_thread[i] = temp_ipc_eventlink->el_thread;
			temp_ipc_eventlink->el_thread = THREAD_NULL;

			ipc_eventlink_signal_internal_locked(temp_ipc_eventlink,
			    IPC_EVENTLINK_FORCE_WAKEUP);
		}

		/* Only destroy the port on which destroy was called */
		if (temp_ipc_eventlink == ipc_eventlink) {
			ipc_eventlink_port = temp_ipc_eventlink->el_port;
			assert(ipc_eventlink_port != IPC_PORT_NULL);
		} else {
			/* Do not destory the remote port, else eventlink_destroy will fail */
			ipc_eventlink_port_remote = temp_ipc_eventlink->el_port;
			assert(ipc_eventlink_port_remote != IPC_PORT_NULL);
			/*
			 * Take a reference on the remote port, since it could go
			 * away after eventlink lock is dropped.
			 */
			ip_reference(ipc_eventlink_port_remote);
		}
		assert(temp_ipc_eventlink->el_port != IPC_PORT_NULL);
		temp_ipc_eventlink->el_port = IPC_PORT_NULL;
	}

	/* Mark the eventlink as inactive */
	ipc_eventlink_base->elb_active = FALSE;

	ipc_eventlink_unlock(ipc_eventlink);
	splx(s);

	/* Destroy the local eventlink port */
	ipc_port_dealloc_kernel(ipc_eventlink_port);
	/* Drops port reference */

	/* Clear the remote eventlink port without destroying it */
	ip_lock(ipc_eventlink_port_remote);
	if (ip_active(ipc_eventlink_port_remote)) {
		ipc_kobject_set_atomically(ipc_eventlink_port_remote, IKO_NULL, IKOT_EVENTLINK);
	}
	ip_unlock(ipc_eventlink_port_remote);
	ip_release(ipc_eventlink_port_remote);

	for (i = 0; i < 2; i++) {
		if (associated_thread[i] != THREAD_NULL &&
		    associated_thread[i] != THREAD_ASSOCIATE_WILD) {
			thread_deallocate(associated_thread[i]);
		}

		/* Drop the eventlink reference given to port */
		ipc_eventlink_deallocate(ipc_eventlink);
	}
	return KERN_SUCCESS;
}

/*
 * Name: mach_eventlink_associate
 *
 * Description: Associate a thread to eventlink.
 *
 * Args:
 *   eventlink: eventlink
 *   thread: thread needs to be associated
 *   copyin_addr_wait: copyin addr for wait
 *   copyin_mask_wait: copyin mask for wait
 *   copyin_addr_signal: copyin addr for signal
 *   copyin_mask_signal: copyin mask for signal
 *   mach_eventlink_associate_option_t: option for eventlink associate
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
kern_return_t
mach_eventlink_associate(
	struct ipc_eventlink                  *ipc_eventlink,
	thread_t                              thread,
	mach_vm_address_t                     copyin_addr_wait,
	uint64_t                              copyin_mask_wait,
	mach_vm_address_t                     copyin_addr_signal,
	uint64_t                              copyin_mask_signal,
	mach_eventlink_associate_option_t     ela_option)
{
	spl_t s;

	if (ipc_eventlink == IPC_EVENTLINK_NULL) {
		return KERN_TERMINATED;
	}

	if (copyin_addr_wait != 0 || copyin_mask_wait != 0 ||
	    copyin_addr_signal != 0 || copyin_mask_signal != 0) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((thread == NULL && ela_option == MELA_OPTION_NONE) ||
	    (thread != NULL && ela_option == MELA_OPTION_ASSOCIATE_ON_WAIT)) {
		return KERN_INVALID_ARGUMENT;
	}

	s = splsched();
	ipc_eventlink_lock(ipc_eventlink);

	/* Check if eventlink is terminated */
	if (!ipc_eventlink_active(ipc_eventlink)) {
		ipc_eventlink_unlock(ipc_eventlink);
		splx(s);
		return KERN_TERMINATED;
	}

	if (ipc_eventlink->el_thread != NULL) {
		ipc_eventlink_unlock(ipc_eventlink);
		splx(s);
		return KERN_NAME_EXISTS;
	}

	if (ela_option == MELA_OPTION_ASSOCIATE_ON_WAIT) {
		ipc_eventlink->el_thread = THREAD_ASSOCIATE_WILD;
	} else {
		thread_reference(thread);
		ipc_eventlink->el_thread = thread;
	}

	ipc_eventlink_unlock(ipc_eventlink);
	splx(s);
	return KERN_SUCCESS;
}

/*
 * Name: mach_eventlink_disassociate
 *
 * Description: Disassociate a thread from eventlink.
 * Wake up the associated thread if blocked on eventlink.
 *
 * Args:
 *   eventlink: eventlink
 *   mach_eventlink_option_t: option for eventlink disassociate
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
kern_return_t
mach_eventlink_disassociate(
	struct ipc_eventlink                   *ipc_eventlink,
	mach_eventlink_disassociate_option_t   eld_option)
{
	spl_t s;
	thread_t thread;

	if (ipc_eventlink == IPC_EVENTLINK_NULL) {
		return KERN_TERMINATED;
	}

	if (eld_option != MELD_OPTION_NONE) {
		return KERN_INVALID_ARGUMENT;
	}

	s = splsched();
	ipc_eventlink_lock(ipc_eventlink);

	/* Check if eventlink is terminated */
	if (!ipc_eventlink_active(ipc_eventlink)) {
		ipc_eventlink_unlock(ipc_eventlink);
		splx(s);
		return KERN_TERMINATED;
	}

	if (ipc_eventlink->el_thread == NULL) {
		ipc_eventlink_unlock(ipc_eventlink);
		splx(s);
		return KERN_INVALID_ARGUMENT;
	}

	thread = ipc_eventlink->el_thread;
	ipc_eventlink->el_thread = NULL;

	/* wake up the thread if blocked */
	ipc_eventlink_signal_internal_locked(ipc_eventlink,
	    IPC_EVENTLINK_FORCE_WAKEUP);

	ipc_eventlink_unlock(ipc_eventlink);
	splx(s);

	if (thread != THREAD_ASSOCIATE_WILD) {
		thread_deallocate(thread);
	}
	return KERN_SUCCESS;
}

/*
 * Name: mach_eventlink_signal_trap
 *
 * Description: Increment the sync count of eventlink and
 * wake up the thread waiting if sync counter is greater
 * than wake counter.
 *
 * Args:
 *   eventlink: eventlink
 *
 * Returns:
 *   uint64_t: Contains count and error codes.
 */
uint64_t
mach_eventlink_signal_trap(
	mach_port_name_t port,
	uint64_t         signal_count __unused)
{
	struct ipc_eventlink *ipc_eventlink;
	kern_return_t kr;
	uint64_t retval = 0;

	kr = port_name_to_eventlink(port, &ipc_eventlink);
	if (kr == KERN_SUCCESS) {
		/* Signal the remote side of the eventlink */
		kr = ipc_eventlink_signal(eventlink_remote_side(ipc_eventlink));

		/* Deallocate ref returned by port_name_to_eventlink */
		ipc_eventlink_deallocate(ipc_eventlink);
	}

	retval = encode_eventlink_count_and_error(0, kr);
	return retval;
}

/*
 * Name: ipc_eventlink_signal
 *
 * Description: Increment the sync count of eventlink and
 * wake up the thread waiting if sync counter is greater
 * than wake counter.
 *
 * Args:
 *   eventlink: eventlink
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
static kern_return_t
ipc_eventlink_signal(
	struct ipc_eventlink *ipc_eventlink)
{
	kern_return_t kr;
	spl_t s;

	if (ipc_eventlink == IPC_EVENTLINK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	s = splsched();
	ipc_eventlink_lock(ipc_eventlink);

	/* Check if eventlink is terminated */
	if (!ipc_eventlink_active(ipc_eventlink)) {
		ipc_eventlink_unlock(ipc_eventlink);
		splx(s);
		return KERN_TERMINATED;
	}

	kr = ipc_eventlink_signal_internal_locked(ipc_eventlink,
	    IPC_EVENTLINK_NONE);

	ipc_eventlink_unlock(ipc_eventlink);
	splx(s);

	if (kr == KERN_NOT_WAITING) {
		kr = KERN_SUCCESS;
	}

	return kr;
}

/*
 * Name: mach_eventlink_wait_until_trap
 *
 * Description: Wait until local signal count exceeds the
 * specified count or deadline passes.
 *
 * Args:
 *   wait_port: eventlink port for wait
 *   count_ptr: signal count to wait on
 *   el_option: eventlink option
 *   clock_id: clock id
 *   deadline: deadline in mach_absolute_time
 *
 * Returns:
 *   uint64_t: contains count and error codes
 */
uint64_t
mach_eventlink_wait_until_trap(
	mach_port_name_t                    eventlink_port,
	uint64_t                            wait_count,
	mach_eventlink_signal_wait_option_t option,
	kern_clock_id_t                     clock_id,
	uint64_t                            deadline)
{
	return ipc_eventlink_signal_wait_until_trap_internal(
		eventlink_port,
		MACH_PORT_NULL,
		wait_count,
		option,
		clock_id,
		deadline);
}

/*
 * Name: mach_eventlink_signal_wait_until
 *
 * Description: Signal the opposite side of the
 * eventlink and wait until local signal count exceeds the
 * specified count or deadline passes.
 *
 * Args:
 *   wait_port: eventlink port for wait
 *   count_ptr: signal count to wait on
 *   el_option: eventlink option
 *   clock_id: clock id
 *   deadline: deadline in mach_absolute_time
 *
 * Returns:
 *   uint64_t: contains count and error codes
 */
uint64_t
mach_eventlink_signal_wait_until_trap(
	mach_port_name_t                    eventlink_port,
	uint64_t                            wait_count,
	uint64_t                            signal_count __unused,
	mach_eventlink_signal_wait_option_t option,
	kern_clock_id_t                     clock_id,
	uint64_t                            deadline)
{
	return ipc_eventlink_signal_wait_until_trap_internal(
		eventlink_port,
		eventlink_port,
		wait_count,
		option,
		clock_id,
		deadline);
}

/*
 * Name: ipc_eventlink_signal_wait_until_trap_internal
 *
 * Description: Signal the opposite side of the
 * eventlink and wait until local signal count exceeds the
 * specified count or deadline passes.
 *
 * Args:
 *   wait_port: eventlink port for wait
 *   signal_port: eventlink port for signal
 *   count: signal count to wait on
 *   el_option: eventlink option
 *   clock_id: clock id
 *   deadline: deadline in mach_absolute_time
 *
 * Returns:
 *   uint64_t: contains signal count and error codes
 */
static uint64_t
ipc_eventlink_signal_wait_until_trap_internal(
	mach_port_name_t                     wait_port,
	mach_port_name_t                     signal_port,
	uint64_t                             count,
	mach_eventlink_signal_wait_option_t  el_option,
	kern_clock_id_t                      clock_id,
	uint64_t                             deadline)
{
	struct ipc_eventlink *wait_ipc_eventlink = IPC_EVENTLINK_NULL;
	struct ipc_eventlink *signal_ipc_eventlink = IPC_EVENTLINK_NULL;
	kern_return_t kr;
	ipc_eventlink_option_t ipc_eventlink_option = IPC_EVENTLINK_NONE;

	if (clock_id != KERN_CLOCK_MACH_ABSOLUTE_TIME) {
		return encode_eventlink_count_and_error(count, KERN_INVALID_ARGUMENT);
	}

	kr = port_name_to_eventlink(wait_port, &wait_ipc_eventlink);
	if (kr == KERN_SUCCESS) {
		assert(wait_ipc_eventlink != IPC_EVENTLINK_NULL);

		/* Get the remote side of eventlink for signal */
		if (signal_port != MACH_PORT_NULL) {
			signal_ipc_eventlink = eventlink_remote_side(wait_ipc_eventlink);
		}

		if (el_option & MELSW_OPTION_NO_WAIT) {
			ipc_eventlink_option |= IPC_EVENTLINK_NO_WAIT;
		}

		kr = ipc_eventlink_signal_wait_internal(wait_ipc_eventlink,
		    signal_ipc_eventlink, deadline,
		    &count, ipc_eventlink_option);

		/* release ref returned by port_name_to_eventlink */
		ipc_eventlink_deallocate(wait_ipc_eventlink);
	}
	return encode_eventlink_count_and_error(count, kr);
}

/*
 * Name: ipc_eventlink_signal_wait_internal
 *
 * Description: Signal the opposite side of the
 * eventlink and wait until local signal count exceeds the
 * specified count or deadline passes.
 *
 * Args:
 *   wait_eventlink: eventlink for wait
 *   signal_eventlink: eventlink for signal
 *   deadline: deadline in mach_absolute_time
 *   count_ptr: signal count to wait on
 *   el_option: eventlink option
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 *   signal count is returned implicitly in count arg.
 */
static kern_return_t
ipc_eventlink_signal_wait_internal(
	struct ipc_eventlink        *wait_eventlink,
	struct ipc_eventlink        *signal_eventlink,
	uint64_t                    deadline,
	uint64_t                    *count,
	ipc_eventlink_option_t      eventlink_option)
{
	spl_t s;
	kern_return_t kr = KERN_ALREADY_WAITING;
	thread_t self = current_thread();
	struct ipc_eventlink_base *ipc_eventlink_base = wait_eventlink->el_base;
	thread_t handoff_thread = THREAD_NULL;
	thread_handoff_option_t handoff_option = THREAD_HANDOFF_NONE;
	uint64_t old_signal_count;
	wait_result_t wr;

	s = splsched();
	ipc_eventlink_lock(wait_eventlink);

	/* Check if eventlink is terminated */
	if (!ipc_eventlink_active(wait_eventlink)) {
		kr = KERN_TERMINATED;
		goto unlock;
	}

	/* Check if waiting thread is associated to eventlink */
	if (wait_eventlink->el_thread != THREAD_ASSOCIATE_WILD &&
	    wait_eventlink->el_thread != self) {
		kr = KERN_INVALID_ARGUMENT;
		goto unlock;
	}

	/* Check if thread already waiting for associate on wait case */
	if (wait_eventlink->el_thread == THREAD_ASSOCIATE_WILD &&
	    wait_eventlink->el_wait_counter != UINT64_MAX) {
		kr = KERN_INVALID_ARGUMENT;
		goto unlock;
	}

	/* Check if the signal count exceeds the count provided */
	if (*count < wait_eventlink->el_sync_counter) {
		*count = wait_eventlink->el_sync_counter;
		kr = KERN_SUCCESS;
	} else if (eventlink_option & IPC_EVENTLINK_NO_WAIT) {
		/* Check if no block was passed */
		*count =  wait_eventlink->el_sync_counter;
		kr = KERN_OPERATION_TIMED_OUT;
	} else {
		/* Update the wait counter and add thread to waitq */
		wait_eventlink->el_wait_counter = *count;
		old_signal_count = wait_eventlink->el_sync_counter;

		thread_set_pending_block_hint(self, kThreadWaitEventlink);
		(void)waitq_assert_wait64_locked(
			&ipc_eventlink_base->elb_waitq,
			CAST_EVENT64_T(wait_eventlink),
			THREAD_ABORTSAFE,
			TIMEOUT_URGENCY_USER_NORMAL,
			deadline, TIMEOUT_NO_LEEWAY,
			self);

		eventlink_option |= IPC_EVENTLINK_HANDOFF;
	}

	/* Check if we need to signal the other side of eventlink */
	if (signal_eventlink != IPC_EVENTLINK_NULL) {
		kern_return_t signal_kr;
		signal_kr = ipc_eventlink_signal_internal_locked(signal_eventlink,
		    eventlink_option);

		if (signal_kr == KERN_NOT_WAITING) {
			assert(self->handoff_thread == THREAD_NULL);
		}
	}

	if (kr != KERN_ALREADY_WAITING) {
		goto unlock;
	}

	if (self->handoff_thread) {
		handoff_thread = self->handoff_thread;
		self->handoff_thread = THREAD_NULL;
		handoff_option = THREAD_HANDOFF_SETRUN_NEEDED;
	}

	ipc_eventlink_unlock(wait_eventlink);
	splx(s);

	wr = thread_handoff_deallocate(handoff_thread, handoff_option);
	kr = ipc_eventlink_convert_wait_result(wr);

	assert(self->handoff_thread == THREAD_NULL);

	/* Increment the count value if eventlink_signal was called */
	if (kr == KERN_SUCCESS) {
		*count += 1;
	} else {
		*count = old_signal_count;
	}

	return kr;

unlock:
	ipc_eventlink_unlock(wait_eventlink);
	splx(s);
	assert(self->handoff_thread == THREAD_NULL);

	return kr;
}

/*
 * Name: ipc_eventlink_convert_wait_result
 *
 * Description: Convert wait result to return value
 * for wait trap.
 *
 * Args:
 *   wait_result: result from thread handoff
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
static kern_return_t
ipc_eventlink_convert_wait_result(int wait_result)
{
	switch (wait_result) {
	case THREAD_AWAKENED:
		return KERN_SUCCESS;

	case THREAD_TIMED_OUT:
		return KERN_OPERATION_TIMED_OUT;

	case THREAD_INTERRUPTED:
		return KERN_ABORTED;

	case THREAD_RESTART:
		return KERN_TERMINATED;

	default:
		panic("ipc_eventlink_wait_block\n");
		return KERN_FAILURE;
	}
}

/*
 * Name: ipc_eventlink_signal_internal_locked
 *
 * Description: Increment the sync count of eventlink and
 * wake up the thread waiting if sync counter is greater
 * than wake counter.
 *
 * Args:
 *   eventlink: eventlink
 *   ipc_eventlink_option_t: options
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
static kern_return_t
ipc_eventlink_signal_internal_locked(
	struct ipc_eventlink         *signal_eventlink,
	ipc_eventlink_option_t       eventlink_option)
{
	kern_return_t kr = KERN_NOT_WAITING;
	struct ipc_eventlink_base *ipc_eventlink_base = signal_eventlink->el_base;

	if (eventlink_option & IPC_EVENTLINK_FORCE_WAKEUP) {
		/* Adjust the wait counter */
		signal_eventlink->el_wait_counter = UINT64_MAX;

		kr = waitq_wakeup64_all_locked(
			&ipc_eventlink_base->elb_waitq,
			CAST_EVENT64_T(signal_eventlink),
			THREAD_RESTART, NULL,
			WAITQ_ALL_PRIORITIES,
			WAITQ_KEEP_LOCKED);
		return kr;
	}

	/* Increment the eventlink sync count */
	signal_eventlink->el_sync_counter++;

	/* Check if thread needs to be woken up */
	if (signal_eventlink->el_sync_counter > signal_eventlink->el_wait_counter) {
		waitq_options_t wq_option = (eventlink_option & IPC_EVENTLINK_HANDOFF) ?
		    WQ_OPTION_HANDOFF : WQ_OPTION_NONE;

		/* Adjust the wait counter */
		signal_eventlink->el_wait_counter = UINT64_MAX;

		kr = waitq_wakeup64_one_locked(
			&ipc_eventlink_base->elb_waitq,
			CAST_EVENT64_T(signal_eventlink),
			THREAD_AWAKENED, NULL,
			WAITQ_ALL_PRIORITIES,
			WAITQ_KEEP_LOCKED,
			wq_option);
	}

	return kr;
}

/*
 * Name: ipc_eventlink_reference
 *
 * Description: Increment ref on ipc eventlink struct
 *
 * Args:
 *   eventlink: eventlink
 *
 * Returns: None
 */
void
ipc_eventlink_reference(
	struct ipc_eventlink *ipc_eventlink)
{
	os_ref_retain(&ipc_eventlink->el_base->elb_ref_count);
}

/*
 * Name: ipc_eventlink_deallocate
 *
 * Description: Decrement ref on ipc eventlink struct
 *
 * Args:
 *   eventlink: eventlink
 *
 * Returns: None
 */
void
ipc_eventlink_deallocate(
	struct ipc_eventlink *ipc_eventlink)
{
	if (ipc_eventlink == IPC_EVENTLINK_NULL) {
		return;
	}

	struct ipc_eventlink_base *ipc_eventlink_base = ipc_eventlink->el_base;

	if (os_ref_release(&ipc_eventlink_base->elb_ref_count) > 0) {
		return;
	}

	assert(!ipc_eventlink_active(ipc_eventlink));

#if DEVELOPMENT || DEBUG
	/* Remove ipc_eventlink to global list */
	global_ipc_eventlink_lock();
	queue_remove(&ipc_eventlink_list, ipc_eventlink_base,
	    struct ipc_eventlink_base *, elb_global_elm);
	global_ipc_eventlink_unlock();
#endif
	zfree(ipc_eventlink_zone, ipc_eventlink_base);
}

/*
 * Name: convert_port_to_eventlink
 *
 * Description: Convert from a port name in the current
 * space to an ipc eventlink. Produces an ipc eventlink ref,
 * which may be null.
 *
 * Args:
 *   mach_port_t: eventlink port
 *
 * Returns:
 *   ipc_eventlink on Success.
 */
struct ipc_eventlink *
convert_port_to_eventlink(
	mach_port_t     port)
{
	struct ipc_eventlink *ipc_eventlink = IPC_EVENTLINK_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		convert_port_to_eventlink_locked(port, &ipc_eventlink);
		ip_unlock(port);
	}

	return ipc_eventlink;
}

/*
 * Name: convert_port_to_eventlink_locked
 *
 * Description: Convert from a port name in the current
 * space to an ipc eventlink. Produces an ipc eventlink ref,
 * which may be null.
 *
 * Args:
 *   mach_port_name_t: eventlink port name
 *   ipc_eventlink_ptr: pointer to return ipc_eventlink.
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 *   KERN_TERMINATED on inactive eventlink.
 */
static kern_return_t
convert_port_to_eventlink_locked(
	ipc_port_t                      port,
	struct ipc_eventlink            **ipc_eventlink_ptr)
{
	kern_return_t kr = KERN_INVALID_CAPABILITY;
	struct ipc_eventlink *ipc_eventlink = IPC_EVENTLINK_NULL;

	if (ip_active(port) &&
	    ip_kotype(port) == IKOT_EVENTLINK) {
		ipc_eventlink = (struct ipc_eventlink *)port->ip_kobject;

		if (ipc_eventlink) {
			ipc_eventlink_reference(ipc_eventlink);
			kr = KERN_SUCCESS;
		} else {
			kr = KERN_TERMINATED;
		}
	}

	*ipc_eventlink_ptr = ipc_eventlink;
	return kr;
}

/*
 * Name: port_name_to_eventlink
 *
 * Description: Convert from a port name in the current
 * space to an ipc eventlink. Produces an ipc eventlink ref,
 * which may be null.
 *
 * Args:
 *   mach_port_name_t: eventlink port name
 *   ipc_eventlink_ptr: ptr to pass eventlink struct
 *
 * Returns:
 *   KERN_SUCCESS on Success.
 */
static kern_return_t
port_name_to_eventlink(
	mach_port_name_t              name,
	struct ipc_eventlink          **ipc_eventlink_ptr)
{
	ipc_port_t kern_port;
	kern_return_t kr;

	if (!MACH_PORT_VALID(name)) {
		*ipc_eventlink_ptr = IPC_EVENTLINK_NULL;
		return KERN_INVALID_NAME;
	}

	kr = ipc_port_translate_send(current_space(), name, &kern_port);
	if (kr != KERN_SUCCESS) {
		*ipc_eventlink_ptr = IPC_EVENTLINK_NULL;
		return kr;
	}
	/* have the port locked */
	assert(IP_VALID(kern_port));

	kr = convert_port_to_eventlink_locked(kern_port, ipc_eventlink_ptr);
	ip_unlock(kern_port);

	return kr;
}

/*
 * Name: ipc_eventlink_notify
 *
 * Description: Destroy an ipc_eventlink, wakeup all threads.
 *
 * Args:
 *   msg: msg contaning eventlink port
 *
 * Returns:
 *   None.
 */
void
ipc_eventlink_notify(
	mach_msg_header_t *msg)
{
	kern_return_t kr;
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;
	struct ipc_eventlink *ipc_eventlink;

	if (!ip_active(port)) {
		return;
	}

	/* Get ipc_eventlink reference */
	ip_lock(port);

	/* Make sure port is still active */
	if (!ip_active(port)) {
		ip_unlock(port);
		return;
	}

	convert_port_to_eventlink_locked(port, &ipc_eventlink);
	ip_unlock(port);

	kr = ipc_eventlink_destroy_internal(ipc_eventlink);
	if (kr == KERN_TERMINATED) {
		/* eventlink is already inactive, destroy the port */
		ipc_port_dealloc_kernel(port);
	}

	/* Drop the reference returned by convert_port_to_eventlink_locked */
	ipc_eventlink_deallocate(ipc_eventlink);
}

#define WAITQ_TO_EVENTLINK(wq) ((struct ipc_eventlink_base *) ((uintptr_t)(wq) - offsetof(struct ipc_eventlink_base, elb_waitq)))

/*
 * Name: kdp_eventlink_find_owner
 *
 * Description: Find who will signal the waiting thread.
 *
 * Args:
 *   waitq: eventlink waitq
 *   wait_event: eventlink wait event
 *   waitinfo: waitinfo struct
 *
 * Returns:
 *   None.
 */
void
kdp_eventlink_find_owner(
	struct waitq      *waitq,
	event64_t         event,
	thread_waitinfo_t *waitinfo)
{
	assert(waitinfo->wait_type == kThreadWaitEventlink);
	waitinfo->owner = 0;
	waitinfo->context = 0;

	if (waitq_held(waitq)) {
		return;
	}

	struct ipc_eventlink_base *ipc_eventlink_base = WAITQ_TO_EVENTLINK(waitq);

	if (event == CAST_EVENT64_T(&ipc_eventlink_base->elb_eventlink[0])) {
		/* Use the other end of eventlink for signal thread */
		if (ipc_eventlink_base->elb_eventlink[1].el_thread != THREAD_ASSOCIATE_WILD) {
			waitinfo->owner = thread_tid(ipc_eventlink_base->elb_eventlink[1].el_thread);
		} else {
			waitinfo->owner = 0;
		}
	} else if (event == CAST_EVENT64_T(&ipc_eventlink_base->elb_eventlink[1])) {
		/* Use the other end of eventlink for signal thread */
		if (ipc_eventlink_base->elb_eventlink[0].el_thread != THREAD_ASSOCIATE_WILD) {
			waitinfo->owner = thread_tid(ipc_eventlink_base->elb_eventlink[0].el_thread);
		} else {
			waitinfo->owner = 0;
		}
	}

	return;
}
