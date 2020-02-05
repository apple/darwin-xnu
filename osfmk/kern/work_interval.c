/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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


#include <sys/work_interval.h>

#include <kern/work_interval.h>

#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/machine.h>
#include <kern/thread_group.h>
#include <kern/ipc_kobject.h>
#include <kern/task.h>
#include <kern/coalition.h>
#include <kern/policy_internal.h>

#include <mach/kern_return.h>
#include <mach/notify.h>

#include <stdatomic.h>

/*
 * Work Interval structs
 *
 * This struct represents a thread group and/or work interval context
 * in a mechanism that is represented with a kobject.
 *
 * Every thread that has joined a WI has a +1 ref, and the port
 * has a +1 ref as well.
 *
 * TODO: groups need to have a 'is for WI' flag
 *      and they need a flag to create that says 'for WI'
 *      This would allow CLPC to avoid allocating WI support
 *      data unless it is needed
 *
 * TODO: Enforce not having more than one non-group joinable work
 *      interval per thread group.
 *      CLPC only wants to see one WI-notify callout per group.
 */

struct work_interval {
	uint64_t wi_id;
	_Atomic uint32_t wi_ref_count;
	uint32_t wi_create_flags;

	/* for debugging purposes only, does not hold a ref on port */
	ipc_port_t wi_port;

	/*
	 * holds uniqueid and version of creating process,
	 * used to permission-gate notify
	 * TODO: you'd think there would be a better way to do this
	 */
	uint64_t wi_creator_uniqueid;
	uint32_t wi_creator_pid;
	int wi_creator_pidversion;

};

static inline void
wi_retain(struct work_interval *work_interval)
{
	uint32_t old_count;
	old_count = atomic_fetch_add_explicit(&work_interval->wi_ref_count,
	    1, memory_order_relaxed);
	assert(old_count > 0);
}

static inline void
wi_release(struct work_interval *work_interval)
{
	uint32_t old_count;
	old_count = atomic_fetch_sub_explicit(&work_interval->wi_ref_count,
	    1, memory_order_relaxed);
	assert(old_count > 0);

	if (old_count == 1) {

		kfree(work_interval, sizeof(struct work_interval));
	}
}

/*
 * work_interval_port_convert
 *
 * Called with port locked, returns reference to work interval
 * if indeed the port is a work interval kobject port
 */
static struct work_interval *
work_interval_port_convert_locked(ipc_port_t port)
{
	struct work_interval *work_interval = NULL;

	if (!IP_VALID(port)) {
		return NULL;
	}

	if (!ip_active(port)) {
		return NULL;
	}

	if (IKOT_WORK_INTERVAL != ip_kotype(port)) {
		return NULL;
	}

	work_interval = (struct work_interval *)port->ip_kobject;

	wi_retain(work_interval);

	return work_interval;
}

/*
 * port_name_to_work_interval
 *
 * Description: Obtain a reference to the work_interval associated with a given port.
 *
 * Parameters:  name    A Mach port name to translate.
 *
 * Returns:     NULL    The given Mach port did not reference a work_interval.
 *              !NULL   The work_interval that is associated with the Mach port.
 */
static kern_return_t
port_name_to_work_interval(mach_port_name_t     name,
    struct work_interval **work_interval)
{
	if (!MACH_PORT_VALID(name)) {
		return KERN_INVALID_NAME;
	}

	ipc_port_t port = IPC_PORT_NULL;
	kern_return_t kr = KERN_SUCCESS;

	kr = ipc_port_translate_send(current_space(), name, &port);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* port is locked */

	assert(IP_VALID(port));

	struct work_interval *converted_work_interval;

	converted_work_interval = work_interval_port_convert_locked(port);

	/* the port is valid, but doesn't denote a work_interval */
	if (converted_work_interval == NULL) {
		kr = KERN_INVALID_CAPABILITY;
	}

	ip_unlock(port);

	if (kr == KERN_SUCCESS) {
		*work_interval = converted_work_interval;
	}

	return kr;
}


/*
 * work_interval_port_notify
 *
 * Description: Handle a no-senders notification for a work interval port.
 *              Destroys the port and releases its reference on the work interval.
 *
 * Parameters:  msg     A Mach no-senders notification message.
 *
 * Note: This assumes that there is only one create-right-from-work-interval point,
 *       if the ability to extract another send right after creation is added,
 *       this will have to change to handle make-send counts correctly.
 */
void
work_interval_port_notify(mach_msg_header_t *msg)
{
	mach_no_senders_notification_t *notification = (void *)msg;
	ipc_port_t port = notification->not_header.msgh_remote_port;
	struct work_interval *work_interval = NULL;

	if (!IP_VALID(port)) {
		panic("work_interval_port_notify(): invalid port");
	}

	ip_lock(port);

	if (!ip_active(port)) {
		panic("work_interval_port_notify(): inactive port %p", port);
	}

	if (ip_kotype(port) != IKOT_WORK_INTERVAL) {
		panic("work_interval_port_notify(): not the right kobject: %p, %d\n",
		    port, ip_kotype(port));
	}

	if (port->ip_mscount != notification->not_count) {
		panic("work_interval_port_notify(): unexpected make-send count: %p, %d, %d",
		    port, port->ip_mscount, notification->not_count);
	}

	if (port->ip_srights != 0) {
		panic("work_interval_port_notify(): unexpected send right count: %p, %d",
		    port, port->ip_srights);
	}

	work_interval = (struct work_interval *)port->ip_kobject;

	if (work_interval == NULL) {
		panic("work_interval_port_notify(): missing kobject: %p", port);
	}

	ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);

	work_interval->wi_port = MACH_PORT_NULL;

	ip_unlock(port);

	ipc_port_dealloc_kernel(port);
	wi_release(work_interval);
}

/*
 * Change thread's bound work interval to the passed-in work interval
 * Consumes +1 ref on work_interval
 *
 * May also pass NULL to un-set work_interval on the thread
 *
 * Will deallocate any old work interval on the thread
 */
static void
thread_set_work_interval(thread_t thread,
    struct work_interval *work_interval)
{
	assert(thread == current_thread());

	struct work_interval *old_th_wi = thread->th_work_interval;

	/* transfer +1 ref to thread */
	thread->th_work_interval = work_interval;


	if (old_th_wi != NULL) {
		wi_release(old_th_wi);
	}
}

void
work_interval_thread_terminate(thread_t thread)
{
	if (thread->th_work_interval != NULL) {
		thread_set_work_interval(thread, NULL);
	}
}



kern_return_t
kern_work_interval_notify(thread_t thread, struct kern_work_interval_args* kwi_args)
{
	assert(thread == current_thread());
	assert(kwi_args->work_interval_id != 0);

	struct work_interval *work_interval = thread->th_work_interval;

	if (work_interval == NULL ||
	    work_interval->wi_id != kwi_args->work_interval_id) {
		/* This thread must have adopted the work interval to be able to notify */
		return KERN_INVALID_ARGUMENT;
	}

	task_t notifying_task = current_task();

	if (work_interval->wi_creator_uniqueid != get_task_uniqueid(notifying_task) ||
	    work_interval->wi_creator_pidversion != get_task_version(notifying_task)) {
		/* Only the creating task can do a notify */
		return KERN_INVALID_ARGUMENT;
	}

	spl_t s = splsched();


	uint64_t urgency_param1, urgency_param2;
	kwi_args->urgency = thread_get_urgency(thread, &urgency_param1, &urgency_param2);

	splx(s);

	/* called without interrupts disabled */
	machine_work_interval_notify(thread, kwi_args);

	return KERN_SUCCESS;
}

/* Start at 1, 0 is not a valid work interval ID */
static _Atomic uint64_t unique_work_interval_id = 1;

kern_return_t
kern_work_interval_create(thread_t thread,
    struct kern_work_interval_create_args *create_params)
{
	assert(thread == current_thread());

	if (thread->th_work_interval != NULL) {
		/* already assigned a work interval */
		return KERN_FAILURE;
	}

	struct work_interval *work_interval = kalloc(sizeof(*work_interval));

	if (work_interval == NULL) {
		panic("failed to allocate work_interval");
	}

	bzero(work_interval, sizeof(*work_interval));

	uint64_t old_value = atomic_fetch_add_explicit(&unique_work_interval_id, 1,
	    memory_order_relaxed);

	uint64_t work_interval_id = old_value + 1;

	uint32_t create_flags = create_params->wica_create_flags;

	task_t creating_task = current_task();
	if ((create_flags & WORK_INTERVAL_TYPE_MASK) == WORK_INTERVAL_TYPE_CA_CLIENT) {
		/*
		 * CA_CLIENT work intervals do not create new thread groups.
		 * There can only be one CA_CLIENT work interval (created by UIKit or AppKit)
		 * per each application task
		 */
		if (create_flags & WORK_INTERVAL_FLAG_GROUP) {
			return KERN_FAILURE;
		}
		if (!task_is_app(creating_task)) {
			return KERN_NOT_SUPPORTED;
		}
		if (task_set_ca_client_wi(creating_task, true) == false) {
			return KERN_FAILURE;
		}
	}

	*work_interval = (struct work_interval) {
		.wi_id                  = work_interval_id,
		.wi_ref_count           = 1,
		.wi_create_flags        = create_flags,
		.wi_creator_pid         = pid_from_task(creating_task),
		.wi_creator_uniqueid    = get_task_uniqueid(creating_task),
		.wi_creator_pidversion  = get_task_version(creating_task),
	};


	if (create_flags & WORK_INTERVAL_FLAG_JOINABLE) {
		mach_port_name_t name = MACH_PORT_NULL;

		/* work_interval has a +1 ref, moves to the port */
		work_interval->wi_port = ipc_kobject_alloc_port(
			(ipc_kobject_t)work_interval, IKOT_WORK_INTERVAL,
			IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);

		name = ipc_port_copyout_send(work_interval->wi_port, current_space());

		if (!MACH_PORT_VALID(name)) {
			/*
			 * copyout failed (port is already deallocated)
			 * Because of the port-destroyed magic,
			 * the work interval is already deallocated too.
			 */
			return KERN_RESOURCE_SHORTAGE;
		}

		create_params->wica_port = name;
	} else {
		/* work_interval has a +1 ref, moves to the thread */
		thread_set_work_interval(thread, work_interval);
		create_params->wica_port = MACH_PORT_NULL;
	}

	create_params->wica_id = work_interval_id;
	return KERN_SUCCESS;
}


kern_return_t
kern_work_interval_destroy(thread_t thread, uint64_t work_interval_id)
{
	if (work_interval_id == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	if (thread->th_work_interval == NULL ||
	    thread->th_work_interval->wi_id != work_interval_id) {
		/* work ID isn't valid or doesn't match joined work interval ID */
		return KERN_INVALID_ARGUMENT;
	}

	thread_set_work_interval(thread, NULL);

	return KERN_SUCCESS;
}

kern_return_t
kern_work_interval_join(thread_t            thread,
    mach_port_name_t    port_name)
{
	struct work_interval *work_interval = NULL;
	kern_return_t kr;

	if (port_name == MACH_PORT_NULL) {
		/* 'Un-join' the current work interval */
		thread_set_work_interval(thread, NULL);
		return KERN_SUCCESS;
	}

	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* work_interval has a +1 ref */

	assert(work_interval != NULL);

	thread_set_work_interval(thread, work_interval);

	/* ref was consumed by passing it to the thread */

	return KERN_SUCCESS;
}
