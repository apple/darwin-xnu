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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 */

/*
 * File:	ipc_tt.c
 * Purpose:
 *	Task and thread related IPC functions.
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/mach_param.h>
#include <mach/task_special_ports.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>
#include <mach/memory_object_types.h>
#include <mach/mach_traps.h>
#include <mach/task_server.h>
#include <mach/thread_act_server.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/vm_map_server.h>

#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/misc_protos.h>

#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/vm_protos.h>

#include <security/mac_mach_internal.h>

#if CONFIG_CSR
#include <sys/csr.h>
#endif

#if !defined(XNU_TARGET_OS_OSX) && !SECURE_KERNEL
extern int cs_relax_platform_task_ports;
#endif

extern boolean_t IOTaskHasEntitlement(task_t, const char *);

/* forward declarations */
task_t convert_port_to_locked_task(ipc_port_t port, boolean_t eval);
task_inspect_t convert_port_to_locked_task_inspect(ipc_port_t port);
task_read_t convert_port_to_locked_task_read(ipc_port_t port);
static task_read_t convert_port_to_task_read_locked(ipc_port_t port);
static kern_return_t port_allowed_with_task_flavor(int which, mach_task_flavor_t flavor);
static kern_return_t port_allowed_with_thread_flavor(int which, mach_thread_flavor_t flavor);
static task_inspect_t convert_port_to_task_inspect_locked(ipc_port_t port);
static void ipc_port_bind_special_reply_port_locked(ipc_port_t port);
static kern_return_t ipc_port_unbind_special_reply_port(thread_t thread, boolean_t unbind_active_port);
kern_return_t task_conversion_eval(task_t caller, task_t victim);
static ipc_space_t convert_port_to_space_no_eval(ipc_port_t port);
static task_t convert_port_to_task_no_eval(ipc_port_t port);
static thread_t convert_port_to_thread_no_eval(ipc_port_t port);
static ipc_port_t convert_task_to_port_with_flavor(task_t task, mach_task_flavor_t flavor);
static ipc_port_t convert_thread_to_port_with_flavor(thread_t thread, mach_thread_flavor_t flavor);

/*
 *	Routine:	ipc_task_init
 *	Purpose:
 *		Initialize a task's IPC state.
 *
 *		If non-null, some state will be inherited from the parent.
 *		The parent must be appropriately initialized.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_task_init(
	task_t          task,
	task_t          parent)
{
	ipc_space_t space;
	ipc_port_t kport;
	ipc_port_t nport;

	kern_return_t kr;
	int i;


	kr = ipc_space_create(&ipc_table_entries[0], IPC_LABEL_NONE, &space);
	if (kr != KERN_SUCCESS) {
		panic("ipc_task_init");
	}

	space->is_task = task;

	kport = ipc_port_alloc_kernel();

	if (kport == IP_NULL) {
		panic("ipc_task_init");
	}

	nport = ipc_port_alloc_kernel();
	if (nport == IP_NULL) {
		panic("ipc_task_init");
	}

	itk_lock_init(task);
	task->itk_self[TASK_FLAVOR_CONTROL] = kport;
	task->itk_self[TASK_FLAVOR_NAME] = nport;

	/* Lazily allocated on-demand */
	task->itk_self[TASK_FLAVOR_INSPECT] = IP_NULL;
	task->itk_self[TASK_FLAVOR_READ] = IP_NULL;
	task->itk_resume = IP_NULL;

	if (task_is_a_corpse_fork(task)) {
		/*
		 * No sender's notification for corpse would not
		 * work with a naked send right in kernel.
		 */
		task->itk_settable_self = IP_NULL;
	} else {
		task->itk_settable_self = ipc_port_make_send(kport);
	}
	task->itk_debug_control = IP_NULL;
	task->itk_space = space;

#if CONFIG_MACF
	task->exc_actions[0].label = NULL;
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		mac_exc_associate_action_label(&task->exc_actions[i], mac_exc_create_label());
	}
#endif

	/* always zero-out the first (unused) array element */
	bzero(&task->exc_actions[0], sizeof(task->exc_actions[0]));

	if (parent == TASK_NULL) {
		ipc_port_t port;
		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			task->exc_actions[i].port = IP_NULL;
			task->exc_actions[i].flavor = 0;
			task->exc_actions[i].behavior = 0;
			task->exc_actions[i].privileged = FALSE;
		}/* for */

		kr = host_get_host_port(host_priv_self(), &port);
		assert(kr == KERN_SUCCESS);
		task->itk_host = port;

		task->itk_bootstrap = IP_NULL;
		task->itk_seatbelt = IP_NULL;
		task->itk_gssd = IP_NULL;
		task->itk_task_access = IP_NULL;

		for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
			task->itk_registered[i] = IP_NULL;
		}
	} else {
		itk_lock(parent);
		assert(parent->itk_self[TASK_FLAVOR_CONTROL] != IP_NULL);

		/* inherit registered ports */

		for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
			task->itk_registered[i] =
			    ipc_port_copy_send(parent->itk_registered[i]);
		}

		/* inherit exception and bootstrap ports */

		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			task->exc_actions[i].port =
			    ipc_port_copy_send(parent->exc_actions[i].port);
			task->exc_actions[i].flavor =
			    parent->exc_actions[i].flavor;
			task->exc_actions[i].behavior =
			    parent->exc_actions[i].behavior;
			task->exc_actions[i].privileged =
			    parent->exc_actions[i].privileged;
#if CONFIG_MACF
			mac_exc_inherit_action_label(parent->exc_actions + i, task->exc_actions + i);
#endif
		}/* for */
		task->itk_host =
		    ipc_port_copy_send(parent->itk_host);

		task->itk_bootstrap =
		    ipc_port_copy_send(parent->itk_bootstrap);

		task->itk_seatbelt =
		    ipc_port_copy_send(parent->itk_seatbelt);

		task->itk_gssd =
		    ipc_port_copy_send(parent->itk_gssd);

		task->itk_task_access =
		    ipc_port_copy_send(parent->itk_task_access);

		itk_unlock(parent);
	}
}

/*
 *	Routine:	ipc_task_enable
 *	Purpose:
 *		Enable a task for IPC access.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_task_enable(
	task_t          task)
{
	ipc_port_t kport;
	ipc_port_t nport;
	ipc_port_t iport;
	ipc_port_t rdport;

	itk_lock(task);
	kport = task->itk_self[TASK_FLAVOR_CONTROL];
	if (kport != IP_NULL) {
		ipc_kobject_set(kport, (ipc_kobject_t) task, IKOT_TASK_CONTROL);
	}
	nport = task->itk_self[TASK_FLAVOR_NAME];
	if (nport != IP_NULL) {
		ipc_kobject_set(nport, (ipc_kobject_t) task, IKOT_TASK_NAME);
	}
	iport = task->itk_self[TASK_FLAVOR_INSPECT];
	if (iport != IP_NULL) {
		ipc_kobject_set(iport, (ipc_kobject_t) task, IKOT_TASK_INSPECT);
	}
	rdport = task->itk_self[TASK_FLAVOR_READ];
	if (rdport != IP_NULL) {
		ipc_kobject_set(rdport, (ipc_kobject_t) task, IKOT_TASK_READ);
	}

	itk_unlock(task);
}

/*
 *	Routine:	ipc_task_disable
 *	Purpose:
 *		Disable IPC access to a task.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_task_disable(
	task_t          task)
{
	ipc_port_t kport;
	ipc_port_t nport;
	ipc_port_t iport;
	ipc_port_t rdport;
	ipc_port_t rport;

	itk_lock(task);
	kport = task->itk_self[TASK_FLAVOR_CONTROL];
	if (kport != IP_NULL) {
		ipc_kobject_set(kport, IKO_NULL, IKOT_NONE);
	}
	nport = task->itk_self[TASK_FLAVOR_NAME];
	if (nport != IP_NULL) {
		ipc_kobject_set(nport, IKO_NULL, IKOT_NONE);
	}
	iport = task->itk_self[TASK_FLAVOR_INSPECT];
	if (iport != IP_NULL) {
		ipc_kobject_set(iport, IKO_NULL, IKOT_NONE);
	}
	rdport = task->itk_self[TASK_FLAVOR_READ];
	if (rdport != IP_NULL) {
		ipc_kobject_set(rdport, IKO_NULL, IKOT_NONE);
	}

	rport = task->itk_resume;
	if (rport != IP_NULL) {
		/*
		 * From this point onwards this task is no longer accepting
		 * resumptions.
		 *
		 * There are still outstanding suspensions on this task,
		 * even as it is being torn down. Disconnect the task
		 * from the rport, thereby "orphaning" the rport. The rport
		 * itself will go away only when the last suspension holder
		 * destroys his SO right to it -- when he either
		 * exits, or tries to actually use that last SO right to
		 * resume this (now non-existent) task.
		 */
		ipc_kobject_set(rport, IKO_NULL, IKOT_NONE);
	}
	itk_unlock(task);
}

/*
 *	Routine:	ipc_task_terminate
 *	Purpose:
 *		Clean up and destroy a task's IPC state.
 *	Conditions:
 *		Nothing locked.  The task must be suspended.
 *		(Or the current thread must be in the task.)
 */

void
ipc_task_terminate(
	task_t          task)
{
	ipc_port_t kport;
	ipc_port_t nport;
	ipc_port_t iport;
	ipc_port_t rdport;
	ipc_port_t rport;
	int i;

	itk_lock(task);
	kport = task->itk_self[TASK_FLAVOR_CONTROL];

	if (kport == IP_NULL) {
		/* the task is already terminated (can this happen?) */
		itk_unlock(task);
		return;
	}
	task->itk_self[TASK_FLAVOR_CONTROL] = IP_NULL;

	rdport = task->itk_self[TASK_FLAVOR_READ];
	task->itk_self[TASK_FLAVOR_READ] = IP_NULL;

	iport = task->itk_self[TASK_FLAVOR_INSPECT];
	task->itk_self[TASK_FLAVOR_INSPECT] = IP_NULL;

	nport = task->itk_self[TASK_FLAVOR_NAME];
	assert(nport != IP_NULL);
	task->itk_self[TASK_FLAVOR_NAME] = IP_NULL;

	rport = task->itk_resume;
	task->itk_resume = IP_NULL;

	itk_unlock(task);

	/* release the naked send rights */

	if (IP_VALID(task->itk_settable_self)) {
		ipc_port_release_send(task->itk_settable_self);
	}

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(task->exc_actions[i].port)) {
			ipc_port_release_send(task->exc_actions[i].port);
		}
#if CONFIG_MACF
		mac_exc_free_action_label(task->exc_actions + i);
#endif
	}

	if (IP_VALID(task->itk_host)) {
		ipc_port_release_send(task->itk_host);
	}

	if (IP_VALID(task->itk_bootstrap)) {
		ipc_port_release_send(task->itk_bootstrap);
	}

	if (IP_VALID(task->itk_seatbelt)) {
		ipc_port_release_send(task->itk_seatbelt);
	}

	if (IP_VALID(task->itk_gssd)) {
		ipc_port_release_send(task->itk_gssd);
	}

	if (IP_VALID(task->itk_task_access)) {
		ipc_port_release_send(task->itk_task_access);
	}

	if (IP_VALID(task->itk_debug_control)) {
		ipc_port_release_send(task->itk_debug_control);
	}

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		if (IP_VALID(task->itk_registered[i])) {
			ipc_port_release_send(task->itk_registered[i]);
		}
	}

	/* destroy the kernel ports */
	ipc_port_dealloc_kernel(kport);
	ipc_port_dealloc_kernel(nport);
	if (iport != IP_NULL) {
		ipc_port_dealloc_kernel(iport);
	}
	if (rdport != IP_NULL) {
		ipc_port_dealloc_kernel(rdport);
	}
	if (rport != IP_NULL) {
		ipc_port_dealloc_kernel(rport);
	}

	itk_lock_destroy(task);
}

/*
 *	Routine:	ipc_task_reset
 *	Purpose:
 *		Reset a task's IPC state to protect it when
 *		it enters an elevated security context. The
 *		task name port can remain the same - since it
 *              represents no specific privilege.
 *	Conditions:
 *		Nothing locked.  The task must be suspended.
 *		(Or the current thread must be in the task.)
 */

void
ipc_task_reset(
	task_t          task)
{
	ipc_port_t old_kport, new_kport;
	ipc_port_t old_sself;
	ipc_port_t old_rdport;
	ipc_port_t old_iport;
	ipc_port_t old_exc_actions[EXC_TYPES_COUNT];
	int i;

#if CONFIG_MACF
	/* Fresh label to unset credentials in existing labels. */
	struct label *unset_label = mac_exc_create_label();
#endif

	new_kport = ipc_kobject_alloc_port((ipc_kobject_t)task, IKOT_TASK_CONTROL,
	    IPC_KOBJECT_ALLOC_MAKE_SEND);

	itk_lock(task);

	old_kport = task->itk_self[TASK_FLAVOR_CONTROL];
	old_rdport = task->itk_self[TASK_FLAVOR_READ];
	old_iport = task->itk_self[TASK_FLAVOR_INSPECT];

	if (old_kport == IP_NULL) {
		/* the task is already terminated (can this happen?) */
		itk_unlock(task);
		ipc_port_release_send(new_kport);
		ipc_port_dealloc_kernel(new_kport);
#if CONFIG_MACF
		mac_exc_free_label(unset_label);
#endif
		return;
	}

	old_sself = task->itk_settable_self;
	task->itk_settable_self = task->itk_self[TASK_FLAVOR_CONTROL] = new_kport;

	/* Set the old kport to IKOT_NONE and update the exec token while under the port lock */
	ip_lock(old_kport);
	ipc_kobject_set_atomically(old_kport, IKO_NULL, IKOT_NONE);
	task->exec_token += 1;
	ip_unlock(old_kport);

	/* Reset the read and inspect flavors of task port */
	task->itk_self[TASK_FLAVOR_READ] = IP_NULL;
	task->itk_self[TASK_FLAVOR_INSPECT] = IP_NULL;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		old_exc_actions[i] = IP_NULL;

		if (i == EXC_CORPSE_NOTIFY && task_corpse_pending_report(task)) {
			continue;
		}

		if (!task->exc_actions[i].privileged) {
#if CONFIG_MACF
			mac_exc_update_action_label(task->exc_actions + i, unset_label);
#endif
			old_exc_actions[i] = task->exc_actions[i].port;
			task->exc_actions[i].port = IP_NULL;
		}
	}/* for */

	if (IP_VALID(task->itk_debug_control)) {
		ipc_port_release_send(task->itk_debug_control);
	}
	task->itk_debug_control = IP_NULL;

	itk_unlock(task);

#if CONFIG_MACF
	mac_exc_free_label(unset_label);
#endif

	/* release the naked send rights */

	if (IP_VALID(old_sself)) {
		ipc_port_release_send(old_sself);
	}

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
		if (IP_VALID(old_exc_actions[i])) {
			ipc_port_release_send(old_exc_actions[i]);
		}
	}/* for */

	/* destroy all task port flavors */
	ipc_port_dealloc_kernel(old_kport);
	if (old_rdport != IP_NULL) {
		ipc_port_dealloc_kernel(old_rdport);
	}
	if (old_iport != IP_NULL) {
		ipc_port_dealloc_kernel(old_iport);
	}
}

/*
 *	Routine:	ipc_thread_init
 *	Purpose:
 *		Initialize a thread's IPC state.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_init(
	thread_t        thread)
{
	ipc_port_t      kport;

	kport = ipc_kobject_alloc_port((ipc_kobject_t)thread, IKOT_THREAD_CONTROL,
	    IPC_KOBJECT_ALLOC_MAKE_SEND);

	thread->ith_settable_self = thread->ith_self[THREAD_FLAVOR_CONTROL] = kport;
	thread->ith_self[THREAD_FLAVOR_INSPECT] = IP_NULL;
	thread->ith_self[THREAD_FLAVOR_READ] = IP_NULL;
	thread->ith_special_reply_port = NULL;
	thread->exc_actions = NULL;

#if IMPORTANCE_INHERITANCE
	thread->ith_assertions = 0;
#endif

	ipc_kmsg_queue_init(&thread->ith_messages);

	thread->ith_rpc_reply = IP_NULL;
}

void
ipc_thread_init_exc_actions(
	thread_t        thread)
{
	assert(thread->exc_actions == NULL);

	thread->exc_actions = kalloc(sizeof(struct exception_action) * EXC_TYPES_COUNT);
	bzero(thread->exc_actions, sizeof(struct exception_action) * EXC_TYPES_COUNT);

#if CONFIG_MACF
	for (size_t i = 0; i < EXC_TYPES_COUNT; ++i) {
		mac_exc_associate_action_label(thread->exc_actions + i, mac_exc_create_label());
	}
#endif
}

void
ipc_thread_destroy_exc_actions(
	thread_t        thread)
{
	if (thread->exc_actions != NULL) {
#if CONFIG_MACF
		for (size_t i = 0; i < EXC_TYPES_COUNT; ++i) {
			mac_exc_free_action_label(thread->exc_actions + i);
		}
#endif

		kfree(thread->exc_actions,
		    sizeof(struct exception_action) * EXC_TYPES_COUNT);
		thread->exc_actions = NULL;
	}
}

/*
 *	Routine:	ipc_thread_disable
 *	Purpose:
 *		Clean up and destroy a thread's IPC state.
 *	Conditions:
 *		Thread locked.
 */
void
ipc_thread_disable(
	thread_t        thread)
{
	ipc_port_t      kport = thread->ith_self[THREAD_FLAVOR_CONTROL];
	ipc_port_t      iport = thread->ith_self[THREAD_FLAVOR_INSPECT];
	ipc_port_t      rdport = thread->ith_self[THREAD_FLAVOR_READ];

	if (kport != IP_NULL) {
		ipc_kobject_set(kport, IKO_NULL, IKOT_NONE);
	}

	if (iport != IP_NULL) {
		ipc_kobject_set(iport, IKO_NULL, IKOT_NONE);
	}

	if (rdport != IP_NULL) {
		ipc_kobject_set(rdport, IKO_NULL, IKOT_NONE);
	}

	/* unbind the thread special reply port */
	if (IP_VALID(thread->ith_special_reply_port)) {
		ipc_port_unbind_special_reply_port(thread, TRUE);
	}
}

/*
 *	Routine:	ipc_thread_terminate
 *	Purpose:
 *		Clean up and destroy a thread's IPC state.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_terminate(
	thread_t        thread)
{
	ipc_port_t kport = IP_NULL;
	ipc_port_t iport = IP_NULL;
	ipc_port_t rdport = IP_NULL;
	ipc_port_t ith_rpc_reply = IP_NULL;

	thread_mtx_lock(thread);

	kport = thread->ith_self[THREAD_FLAVOR_CONTROL];
	iport = thread->ith_self[THREAD_FLAVOR_INSPECT];
	rdport = thread->ith_self[THREAD_FLAVOR_READ];

	if (kport != IP_NULL) {
		if (IP_VALID(thread->ith_settable_self)) {
			ipc_port_release_send(thread->ith_settable_self);
		}

		thread->ith_settable_self = thread->ith_self[THREAD_FLAVOR_CONTROL] = IP_NULL;
		thread->ith_self[THREAD_FLAVOR_INSPECT] = IP_NULL;
		thread->ith_self[THREAD_FLAVOR_READ] = IP_NULL;

		if (thread->exc_actions != NULL) {
			for (int i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
				if (IP_VALID(thread->exc_actions[i].port)) {
					ipc_port_release_send(thread->exc_actions[i].port);
				}
			}
			ipc_thread_destroy_exc_actions(thread);
		}
	}

#if IMPORTANCE_INHERITANCE
	assert(thread->ith_assertions == 0);
#endif

	assert(ipc_kmsg_queue_empty(&thread->ith_messages));
	ith_rpc_reply = thread->ith_rpc_reply;
	thread->ith_rpc_reply = IP_NULL;

	thread_mtx_unlock(thread);

	if (kport != IP_NULL) {
		ipc_port_dealloc_kernel(kport);
	}
	if (iport != IP_NULL) {
		ipc_port_dealloc_kernel(iport);
	}
	if (rdport != IP_NULL) {
		ipc_port_dealloc_kernel(rdport);
	}
	if (ith_rpc_reply != IP_NULL) {
		ipc_port_dealloc_reply(ith_rpc_reply);
	}
}

/*
 *	Routine:	ipc_thread_reset
 *	Purpose:
 *		Reset the IPC state for a given Mach thread when
 *		its task enters an elevated security context.
 *		All flavors of thread port and its exception ports have
 *		to be reset.  Its RPC reply port cannot have any
 *		rights outstanding, so it should be fine. The thread
 *		inspect and read port are set to NULL.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_thread_reset(
	thread_t        thread)
{
	ipc_port_t old_kport, new_kport;
	ipc_port_t old_sself;
	ipc_port_t old_rdport;
	ipc_port_t old_iport;
	ipc_port_t old_exc_actions[EXC_TYPES_COUNT];
	boolean_t  has_old_exc_actions = FALSE;
	int i;

#if CONFIG_MACF
	struct label *new_label = mac_exc_create_label();
#endif

	new_kport = ipc_kobject_alloc_port((ipc_kobject_t)thread, IKOT_THREAD_CONTROL,
	    IPC_KOBJECT_ALLOC_MAKE_SEND);

	thread_mtx_lock(thread);

	old_kport = thread->ith_self[THREAD_FLAVOR_CONTROL];
	old_rdport = thread->ith_self[THREAD_FLAVOR_READ];
	old_iport = thread->ith_self[THREAD_FLAVOR_INSPECT];
	old_sself = thread->ith_settable_self;

	if (old_kport == IP_NULL && thread->inspection == FALSE) {
		/* the  is already terminated (can this happen?) */
		thread_mtx_unlock(thread);
		ipc_port_release_send(new_kport);
		ipc_port_dealloc_kernel(new_kport);
#if CONFIG_MACF
		mac_exc_free_label(new_label);
#endif
		return;
	}

	thread->ith_settable_self = thread->ith_self[THREAD_FLAVOR_CONTROL] = new_kport;
	thread->ith_self[THREAD_FLAVOR_READ] = IP_NULL;
	thread->ith_self[THREAD_FLAVOR_INSPECT] = IP_NULL;

	if (old_kport != IP_NULL) {
		ipc_kobject_set(old_kport, IKO_NULL, IKOT_NONE);
	}
	if (old_rdport != IP_NULL) {
		ipc_kobject_set(old_rdport, IKO_NULL, IKOT_NONE);
	}
	if (old_iport != IP_NULL) {
		ipc_kobject_set(old_iport, IKO_NULL, IKOT_NONE);
	}

	/*
	 * Only ports that were set by root-owned processes
	 * (privileged ports) should survive
	 */
	if (thread->exc_actions != NULL) {
		has_old_exc_actions = TRUE;
		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			if (thread->exc_actions[i].privileged) {
				old_exc_actions[i] = IP_NULL;
			} else {
#if CONFIG_MACF
				mac_exc_update_action_label(thread->exc_actions + i, new_label);
#endif
				old_exc_actions[i] = thread->exc_actions[i].port;
				thread->exc_actions[i].port = IP_NULL;
			}
		}
	}

	thread_mtx_unlock(thread);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	/* release the naked send rights */

	if (IP_VALID(old_sself)) {
		ipc_port_release_send(old_sself);
	}

	if (has_old_exc_actions) {
		for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; i++) {
			ipc_port_release_send(old_exc_actions[i]);
		}
	}

	/* destroy the kernel port */
	if (old_kport != IP_NULL) {
		ipc_port_dealloc_kernel(old_kport);
	}
	if (old_rdport != IP_NULL) {
		ipc_port_dealloc_kernel(old_rdport);
	}
	if (old_iport != IP_NULL) {
		ipc_port_dealloc_kernel(old_iport);
	}

	/* unbind the thread special reply port */
	if (IP_VALID(thread->ith_special_reply_port)) {
		ipc_port_unbind_special_reply_port(thread, TRUE);
	}
}

/*
 *	Routine:	retrieve_task_self_fast
 *	Purpose:
 *		Optimized version of retrieve_task_self,
 *		that only works for the current task.
 *
 *		Return a send right (possibly null/dead)
 *		for the task's user-visible self port.
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
retrieve_task_self_fast(
	task_t          task)
{
	__assert_only ipc_port_t sright;
	ipc_port_t port;

	assert(task == current_task());

	itk_lock(task);
	assert(task->itk_self[TASK_FLAVOR_CONTROL] != IP_NULL);

	if ((port = task->itk_settable_self) == task->itk_self[TASK_FLAVOR_CONTROL]) {
		/* no interposing */
		sright = ipc_port_copy_send(port);
		assert(sright == port);
	} else {
		port = ipc_port_copy_send(port);
	}
	itk_unlock(task);

	return port;
}

/*
 *	Routine:	retrieve_thread_self_fast
 *	Purpose:
 *		Return a send right (possibly null/dead)
 *		for the thread's user-visible self port.
 *
 *		Only works for the current thread.
 *
 *	Conditions:
 *		Nothing locked.
 */

ipc_port_t
retrieve_thread_self_fast(
	thread_t                thread)
{
	__assert_only ipc_port_t sright;
	ipc_port_t port;

	assert(thread == current_thread());

	thread_mtx_lock(thread);

	assert(thread->ith_self[THREAD_FLAVOR_CONTROL] != IP_NULL);

	if ((port = thread->ith_settable_self) == thread->ith_self[THREAD_FLAVOR_CONTROL]) {
		/* no interposing */
		sright = ipc_port_copy_send(port);
		assert(sright == port);
	} else {
		port = ipc_port_copy_send(port);
	}

	thread_mtx_unlock(thread);

	return port;
}

/*
 *	Routine:	task_self_trap [mach trap]
 *	Purpose:
 *		Give the caller send rights for his own task port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
task_self_trap(
	__unused struct task_self_trap_args *args)
{
	task_t task = current_task();
	ipc_port_t sright;
	mach_port_name_t name;

	sright = retrieve_task_self_fast(task);
	name = ipc_port_copyout_send(sright, task->itk_space);
	return name;
}

/*
 *	Routine:	thread_self_trap [mach trap]
 *	Purpose:
 *		Give the caller send rights for his own thread port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
thread_self_trap(
	__unused struct thread_self_trap_args *args)
{
	thread_t  thread = current_thread();
	task_t task = thread->task;
	ipc_port_t sright;
	mach_port_name_t name;

	sright = retrieve_thread_self_fast(thread);
	name = ipc_port_copyout_send(sright, task->itk_space);
	return name;
}

/*
 *	Routine:	mach_reply_port [mach trap]
 *	Purpose:
 *		Allocate a port for the caller.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
mach_reply_port(
	__unused struct mach_reply_port_args *args)
{
	ipc_port_t port;
	mach_port_name_t name;
	kern_return_t kr;

	kr = ipc_port_alloc(current_task()->itk_space, IPC_PORT_INIT_MESSAGE_QUEUE,
	    &name, &port);
	if (kr == KERN_SUCCESS) {
		ip_unlock(port);
	} else {
		name = MACH_PORT_NULL;
	}
	return name;
}

/*
 *	Routine:	thread_get_special_reply_port [mach trap]
 *	Purpose:
 *		Allocate a special reply port for the calling thread.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		mach_port_name_t: send right & receive right for special reply port.
 *		MACH_PORT_NULL if there are any resource failures
 *		or other errors.
 */

mach_port_name_t
thread_get_special_reply_port(
	__unused struct thread_get_special_reply_port_args *args)
{
	ipc_port_t port;
	mach_port_name_t name;
	kern_return_t kr;
	thread_t thread = current_thread();
	ipc_port_init_flags_t flags = IPC_PORT_INIT_MESSAGE_QUEUE |
	    IPC_PORT_INIT_MAKE_SEND_RIGHT | IPC_PORT_INIT_SPECIAL_REPLY;

	/* unbind the thread special reply port */
	if (IP_VALID(thread->ith_special_reply_port)) {
		kr = ipc_port_unbind_special_reply_port(thread, TRUE);
		if (kr != KERN_SUCCESS) {
			return MACH_PORT_NULL;
		}
	}

	kr = ipc_port_alloc(current_task()->itk_space, flags, &name, &port);
	if (kr == KERN_SUCCESS) {
		ipc_port_bind_special_reply_port_locked(port);
		ip_unlock(port);
	} else {
		name = MACH_PORT_NULL;
	}
	return name;
}

/*
 *	Routine:	ipc_port_bind_special_reply_port_locked
 *	Purpose:
 *		Bind the given port to current thread as a special reply port.
 *	Conditions:
 *		Port locked.
 *	Returns:
 *		None.
 */

static void
ipc_port_bind_special_reply_port_locked(
	ipc_port_t port)
{
	thread_t thread = current_thread();
	assert(thread->ith_special_reply_port == NULL);
	assert(port->ip_specialreply);
	assert(port->ip_sync_link_state == PORT_SYNC_LINK_ANY);

	ip_reference(port);
	thread->ith_special_reply_port = port;
	port->ip_messages.imq_srp_owner_thread = thread;

	ipc_special_reply_port_bits_reset(port);
}

/*
 *	Routine:	ipc_port_unbind_special_reply_port
 *	Purpose:
 *		Unbind the thread's special reply port.
 *		If the special port has threads waiting on turnstile,
 *		update it's inheritor.
 *	Condition:
 *		Nothing locked.
 *	Returns:
 *		None.
 */
static kern_return_t
ipc_port_unbind_special_reply_port(
	thread_t thread,
	boolean_t unbind_active_port)
{
	ipc_port_t special_reply_port = thread->ith_special_reply_port;

	ip_lock(special_reply_port);

	/* Return error if port active and unbind_active_port set to FALSE */
	if (unbind_active_port == FALSE && ip_active(special_reply_port)) {
		ip_unlock(special_reply_port);
		return KERN_FAILURE;
	}

	thread->ith_special_reply_port = NULL;
	ipc_port_adjust_special_reply_port_locked(special_reply_port, NULL,
	    IPC_PORT_ADJUST_UNLINK_THREAD, FALSE);
	/* port unlocked */

	ip_release(special_reply_port);
	return KERN_SUCCESS;
}

/*
 *	Routine:	thread_get_special_port [kernel call]
 *	Purpose:
 *		Clones a send right for one of the thread's
 *		special ports.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The thread is null.
 *		KERN_FAILURE		The thread is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
thread_get_special_port(
	thread_inspect_t         thread,
	int                      which,
	ipc_port_t              *portp);

kern_return_t
static
thread_get_special_port_internal(
	thread_inspect_t         thread,
	int                      which,
	ipc_port_t              *portp,
	mach_thread_flavor_t     flavor)
{
	kern_return_t      kr;
	ipc_port_t port;

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((kr = port_allowed_with_thread_flavor(which, flavor)) != KERN_SUCCESS) {
		return kr;
	}

	thread_mtx_lock(thread);
	if (!thread->active) {
		thread_mtx_unlock(thread);
		return KERN_FAILURE;
	}

	switch (which) {
	case THREAD_KERNEL_PORT:
		port = ipc_port_copy_send(thread->ith_settable_self);
		thread_mtx_unlock(thread);
		break;

	case THREAD_READ_PORT:
	case THREAD_INSPECT_PORT:
		thread_mtx_unlock(thread);
		mach_thread_flavor_t current_flavor = (which == THREAD_READ_PORT) ?
		    THREAD_FLAVOR_READ : THREAD_FLAVOR_INSPECT;
		/* convert_thread_to_port_with_flavor consumes a thread reference */
		thread_reference(thread);
		port = convert_thread_to_port_with_flavor(thread, current_flavor);
		break;

	default:
		thread_mtx_unlock(thread);
		return KERN_INVALID_ARGUMENT;
	}

	*portp = port;

	return KERN_SUCCESS;
}

kern_return_t
thread_get_special_port(
	thread_inspect_t         thread,
	int                      which,
	ipc_port_t              *portp)
{
	return thread_get_special_port_internal(thread, which, portp, THREAD_FLAVOR_CONTROL);
}

kern_return_t
thread_get_special_port_from_user(
	mach_port_t     port,
	int             which,
	ipc_port_t      *portp)
{
	ipc_kobject_type_t kotype;
	kern_return_t kr;

	thread_t thread = convert_port_to_thread_check_type(port, &kotype, THREAD_FLAVOR_INSPECT, FALSE);

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (kotype) {
	case IKOT_THREAD_CONTROL:
		kr = thread_get_special_port_internal(thread, which, portp, THREAD_FLAVOR_CONTROL);
		break;
	case IKOT_THREAD_READ:
		kr = thread_get_special_port_internal(thread, which, portp, THREAD_FLAVOR_READ);
		break;
	case IKOT_THREAD_INSPECT:
		kr = thread_get_special_port_internal(thread, which, portp, THREAD_FLAVOR_INSPECT);
		break;
	default:
		panic("strange kobject type");
		break;
	}

	thread_deallocate(thread);
	return kr;
}

static kern_return_t
port_allowed_with_thread_flavor(
	int                  which,
	mach_thread_flavor_t flavor)
{
	switch (flavor) {
	case THREAD_FLAVOR_CONTROL:
		return KERN_SUCCESS;

	case THREAD_FLAVOR_READ:

		switch (which) {
		case THREAD_READ_PORT:
		case THREAD_INSPECT_PORT:
			return KERN_SUCCESS;
		default:
			return KERN_INVALID_CAPABILITY;
		}

	case THREAD_FLAVOR_INSPECT:

		switch (which) {
		case THREAD_INSPECT_PORT:
			return KERN_SUCCESS;
		default:
			return KERN_INVALID_CAPABILITY;
		}

	default:
		return KERN_INVALID_CAPABILITY;
	}
}

/*
 *	Routine:	thread_set_special_port [kernel call]
 *	Purpose:
 *		Changes one of the thread's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS            Changed the special port.
 *		KERN_INVALID_ARGUMENT   The thread is null.
 *		KERN_FAILURE            The thread is dead.
 *		KERN_INVALID_ARGUMENT   Invalid special port.
 *		KERN_NO_ACCESS          Restricted access to set port.
 */

kern_return_t
thread_set_special_port(
	thread_t                thread,
	int                     which,
	ipc_port_t      port)
{
	kern_return_t   result = KERN_SUCCESS;
	ipc_port_t              *whichp, old = IP_NULL;

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (which) {
	case THREAD_KERNEL_PORT:
#if CONFIG_CSR
		if (csr_check(CSR_ALLOW_KERNEL_DEBUGGER) != 0) {
			/*
			 * Only allow setting of thread-self
			 * special port from user-space when SIP is
			 * disabled (for Mach-on-Mach emulation).
			 */
			return KERN_NO_ACCESS;
		}
#endif
		whichp = &thread->ith_settable_self;
		break;

	default:
		return KERN_INVALID_ARGUMENT;
	}

	thread_mtx_lock(thread);

	if (thread->active) {
		old = *whichp;
		*whichp = port;
	} else {
		result = KERN_FAILURE;
	}

	thread_mtx_unlock(thread);

	if (IP_VALID(old)) {
		ipc_port_release_send(old);
	}

	return result;
}

/*
 *	Routine:	task_get_special_port [kernel call]
 *	Purpose:
 *		Clones a send right for one of the task's
 *		special ports.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_FAILURE		The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 */

kern_return_t
task_get_special_port(
	task_t          task,
	int             which,
	ipc_port_t      *portp);

static kern_return_t
task_get_special_port_internal(
	task_t          task,
	int             which,
	ipc_port_t      *portp,
	mach_task_flavor_t        flavor)
{
	kern_return_t kr;
	ipc_port_t port;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if ((kr = port_allowed_with_task_flavor(which, flavor)) != KERN_SUCCESS) {
		return kr;
	}

	itk_lock(task);
	if (task->itk_self[TASK_FLAVOR_CONTROL] == IP_NULL) {
		itk_unlock(task);
		return KERN_FAILURE;
	}

	switch (which) {
	case TASK_KERNEL_PORT:
		port = ipc_port_copy_send(task->itk_settable_self);
		break;

	case TASK_READ_PORT:
	case TASK_INSPECT_PORT:
		itk_unlock(task);
		mach_task_flavor_t current_flavor = (which == TASK_READ_PORT) ?
		    TASK_FLAVOR_READ : TASK_FLAVOR_INSPECT;
		/* convert_task_to_port_with_flavor consumes a task reference */
		task_reference(task);
		port = convert_task_to_port_with_flavor(task, current_flavor);
		goto copyout;

	case TASK_NAME_PORT:
		port = ipc_port_make_send(task->itk_self[TASK_FLAVOR_NAME]);
		break;

	case TASK_HOST_PORT:
		port = ipc_port_copy_send(task->itk_host);
		break;

	case TASK_BOOTSTRAP_PORT:
		port = ipc_port_copy_send(task->itk_bootstrap);
		break;

	case TASK_SEATBELT_PORT:
		port = ipc_port_copy_send(task->itk_seatbelt);
		break;

	case TASK_ACCESS_PORT:
		port = ipc_port_copy_send(task->itk_task_access);
		break;

	case TASK_DEBUG_CONTROL_PORT:
		port = ipc_port_copy_send(task->itk_debug_control);
		break;

	default:
		itk_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}

	itk_unlock(task);

copyout:
	*portp = port;
	return KERN_SUCCESS;
}

kern_return_t
task_get_special_port(
	task_t          task,
	int             which,
	ipc_port_t      *portp)
{
	return task_get_special_port_internal(task, which, portp, TASK_FLAVOR_CONTROL);
}

kern_return_t
task_get_special_port_from_user(
	mach_port_t     port,
	int             which,
	ipc_port_t      *portp)
{
	ipc_kobject_type_t kotype;
	kern_return_t kr;

	task_t task = convert_port_to_task_check_type(port, &kotype, TASK_FLAVOR_INSPECT, FALSE);

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (kotype) {
	case IKOT_TASK_CONTROL:
		kr = task_get_special_port_internal(task, which, portp, TASK_FLAVOR_CONTROL);
		break;
	case IKOT_TASK_READ:
		kr = task_get_special_port_internal(task, which, portp, TASK_FLAVOR_READ);
		break;
	case IKOT_TASK_INSPECT:
		kr = task_get_special_port_internal(task, which, portp, TASK_FLAVOR_INSPECT);
		break;
	default:
		panic("strange kobject type");
		break;
	}

	task_deallocate(task);
	return kr;
}

static kern_return_t
port_allowed_with_task_flavor(
	int                which,
	mach_task_flavor_t flavor)
{
	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
		return KERN_SUCCESS;

	case TASK_FLAVOR_READ:

		switch (which) {
		case TASK_READ_PORT:
		case TASK_INSPECT_PORT:
		case TASK_NAME_PORT:
			return KERN_SUCCESS;
		default:
			return KERN_INVALID_CAPABILITY;
		}

	case TASK_FLAVOR_INSPECT:

		switch (which) {
		case TASK_INSPECT_PORT:
		case TASK_NAME_PORT:
			return KERN_SUCCESS;
		default:
			return KERN_INVALID_CAPABILITY;
		}

	default:
		return KERN_INVALID_CAPABILITY;
	}
}

/*
 *	Routine:	task_set_special_port [kernel call]
 *	Purpose:
 *		Changes one of the task's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_FAILURE		The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 *      KERN_NO_ACCESS		Restricted access to set port.
 */

kern_return_t
task_set_special_port(
	task_t          task,
	int             which,
	ipc_port_t      port)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (task_is_driver(current_task())) {
		return KERN_NO_ACCESS;
	}

	switch (which) {
	case TASK_KERNEL_PORT:
	case TASK_HOST_PORT:
#if CONFIG_CSR
		if (csr_check(CSR_ALLOW_KERNEL_DEBUGGER) == 0) {
			/*
			 * Only allow setting of task-self / task-host
			 * special ports from user-space when SIP is
			 * disabled (for Mach-on-Mach emulation).
			 */
			break;
		}
#endif
		return KERN_NO_ACCESS;
	default:
		break;
	}

	return task_set_special_port_internal(task, which, port);
}

/*
 *	Routine:	task_set_special_port_internal
 *	Purpose:
 *		Changes one of the task's special ports,
 *		setting it to the supplied send right.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_FAILURE		The task/space is dead.
 *		KERN_INVALID_ARGUMENT	Invalid special port.
 *      KERN_NO_ACCESS		Restricted access to overwrite port.
 */

kern_return_t
task_set_special_port_internal(
	task_t          task,
	int             which,
	ipc_port_t      port)
{
	ipc_port_t old = IP_NULL;
	kern_return_t rc = KERN_INVALID_ARGUMENT;

	if (task == TASK_NULL) {
		goto out;
	}

	itk_lock(task);
	if (task->itk_self[TASK_FLAVOR_CONTROL] == IP_NULL) {
		rc = KERN_FAILURE;
		goto out_unlock;
	}

	switch (which) {
	case TASK_KERNEL_PORT:
		old = task->itk_settable_self;
		task->itk_settable_self = port;
		break;

	case TASK_HOST_PORT:
		old = task->itk_host;
		task->itk_host = port;
		break;

	case TASK_BOOTSTRAP_PORT:
		old = task->itk_bootstrap;
		task->itk_bootstrap = port;
		break;

	/* Never allow overwrite of seatbelt port */
	case TASK_SEATBELT_PORT:
		if (IP_VALID(task->itk_seatbelt)) {
			rc = KERN_NO_ACCESS;
			goto out_unlock;
		}
		task->itk_seatbelt = port;
		break;

	/* Never allow overwrite of the task access port */
	case TASK_ACCESS_PORT:
		if (IP_VALID(task->itk_task_access)) {
			rc = KERN_NO_ACCESS;
			goto out_unlock;
		}
		task->itk_task_access = port;
		break;

	case TASK_DEBUG_CONTROL_PORT:
		old = task->itk_debug_control;
		task->itk_debug_control = port;
		break;

	default:
		rc = KERN_INVALID_ARGUMENT;
		goto out_unlock;
	}/* switch */

	rc = KERN_SUCCESS;

out_unlock:
	itk_unlock(task);

	if (IP_VALID(old)) {
		ipc_port_release_send(old);
	}
out:
	return rc;
}
/*
 *	Routine:	mach_ports_register [kernel call]
 *	Purpose:
 *		Stash a handful of port send rights in the task.
 *		Child tasks will inherit these rights, but they
 *		must use mach_ports_lookup to acquire them.
 *
 *		The rights are supplied in a (wired) kalloc'd segment.
 *		Rights which aren't supplied are assumed to be null.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied rights and memory.
 *	Returns:
 *		KERN_SUCCESS		Stashed the port rights.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_INVALID_ARGUMENT	The task is dead.
 *		KERN_INVALID_ARGUMENT	The memory param is null.
 *		KERN_INVALID_ARGUMENT	Too many port rights supplied.
 */

kern_return_t
mach_ports_register(
	task_t                  task,
	mach_port_array_t       memory,
	mach_msg_type_number_t  portsCnt)
{
	ipc_port_t ports[TASK_PORT_REGISTER_MAX];
	unsigned int i;

	if ((task == TASK_NULL) ||
	    (portsCnt > TASK_PORT_REGISTER_MAX) ||
	    (portsCnt && memory == NULL)) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Pad the port rights with nulls.
	 */

	for (i = 0; i < portsCnt; i++) {
		ports[i] = memory[i];
	}
	for (; i < TASK_PORT_REGISTER_MAX; i++) {
		ports[i] = IP_NULL;
	}

	itk_lock(task);
	if (task->itk_self[TASK_FLAVOR_CONTROL] == IP_NULL) {
		itk_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 *	Replace the old send rights with the new.
	 *	Release the old rights after unlocking.
	 */

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		ipc_port_t old;

		old = task->itk_registered[i];
		task->itk_registered[i] = ports[i];
		ports[i] = old;
	}

	itk_unlock(task);

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		if (IP_VALID(ports[i])) {
			ipc_port_release_send(ports[i]);
		}
	}

	/*
	 *	Now that the operation is known to be successful,
	 *	we can free the memory.
	 */

	if (portsCnt != 0) {
		kfree(memory,
		    (vm_size_t) (portsCnt * sizeof(mach_port_t)));
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	mach_ports_lookup [kernel call]
 *	Purpose:
 *		Retrieves (clones) the stashed port send rights.
 *	Conditions:
 *		Nothing locked.  If successful, the caller gets
 *		rights and memory.
 *	Returns:
 *		KERN_SUCCESS		Retrieved the send rights.
 *		KERN_INVALID_ARGUMENT	The task is null.
 *		KERN_INVALID_ARGUMENT	The task is dead.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
mach_ports_lookup(
	task_t                  task,
	mach_port_array_t       *portsp,
	mach_msg_type_number_t  *portsCnt)
{
	void  *memory;
	vm_size_t size;
	ipc_port_t *ports;
	int i;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	size = (vm_size_t) (TASK_PORT_REGISTER_MAX * sizeof(ipc_port_t));

	memory = kalloc(size);
	if (memory == 0) {
		return KERN_RESOURCE_SHORTAGE;
	}

	itk_lock(task);
	if (task->itk_self[TASK_FLAVOR_CONTROL] == IP_NULL) {
		itk_unlock(task);

		kfree(memory, size);
		return KERN_INVALID_ARGUMENT;
	}

	ports = (ipc_port_t *) memory;

	/*
	 *	Clone port rights.  Because kalloc'd memory
	 *	is wired, we won't fault while holding the task lock.
	 */

	for (i = 0; i < TASK_PORT_REGISTER_MAX; i++) {
		ports[i] = ipc_port_copy_send(task->itk_registered[i]);
	}

	itk_unlock(task);

	*portsp = (mach_port_array_t) ports;
	*portsCnt = TASK_PORT_REGISTER_MAX;
	return KERN_SUCCESS;
}

kern_return_t
task_conversion_eval(task_t caller, task_t victim)
{
	/*
	 * Tasks are allowed to resolve their own task ports, and the kernel is
	 * allowed to resolve anyone's task port.
	 */
	if (caller == kernel_task) {
		return KERN_SUCCESS;
	}

	if (caller == victim) {
		return KERN_SUCCESS;
	}

	/*
	 * Only the kernel can can resolve the kernel's task port. We've established
	 * by this point that the caller is not kernel_task.
	 */
	if (victim == TASK_NULL || victim == kernel_task) {
		return KERN_INVALID_SECURITY;
	}

	task_require(victim);

#if !defined(XNU_TARGET_OS_OSX)
	/*
	 * On platforms other than macOS, only a platform binary can resolve the task port
	 * of another platform binary.
	 */
	if ((victim->t_flags & TF_PLATFORM) && !(caller->t_flags & TF_PLATFORM)) {
#if SECURE_KERNEL
		return KERN_INVALID_SECURITY;
#else
		if (cs_relax_platform_task_ports) {
			return KERN_SUCCESS;
		} else {
			return KERN_INVALID_SECURITY;
		}
#endif /* SECURE_KERNEL */
	}
#endif /* !defined(XNU_TARGET_OS_OSX) */

	return KERN_SUCCESS;
}

/*
 *	Routine: convert_port_to_locked_task
 *	Purpose:
 *		Internal helper routine to convert from a port to a locked
 *		task.  Used by several routines that try to convert from a
 *		task port to a reference on some task related object.
 *	Conditions:
 *		Nothing locked, blocking OK.
 */
task_t
convert_port_to_locked_task(ipc_port_t port, boolean_t eval)
{
	int try_failed_count = 0;

	while (IP_VALID(port)) {
		task_t ct = current_task();
		task_t task;

		ip_lock(port);
		if (!ip_active(port) || (ip_kotype(port) != IKOT_TASK_CONTROL)) {
			ip_unlock(port);
			return TASK_NULL;
		}
		task = (task_t) ip_get_kobject(port);
		assert(task != TASK_NULL);

		if (eval && task_conversion_eval(ct, task)) {
			ip_unlock(port);
			return TASK_NULL;
		}

		/*
		 * Normal lock ordering puts task_lock() before ip_lock().
		 * Attempt out-of-order locking here.
		 */
		if (task_lock_try(task)) {
			ip_unlock(port);
			return task;
		}
		try_failed_count++;

		ip_unlock(port);
		mutex_pause(try_failed_count);
	}
	return TASK_NULL;
}

/*
 *	Routine: convert_port_to_locked_task_inspect
 *	Purpose:
 *		Internal helper routine to convert from a port to a locked
 *		task inspect right. Used by internal routines that try to convert from a
 *		task inspect port to a reference on some task related object.
 *	Conditions:
 *		Nothing locked, blocking OK.
 */
task_inspect_t
convert_port_to_locked_task_inspect(ipc_port_t port)
{
	int try_failed_count = 0;

	while (IP_VALID(port)) {
		task_inspect_t task;

		ip_lock(port);
		if (!ip_active(port) || (ip_kotype(port) != IKOT_TASK_CONTROL &&
		    ip_kotype(port) != IKOT_TASK_READ &&
		    ip_kotype(port) != IKOT_TASK_INSPECT)) {
			ip_unlock(port);
			return TASK_INSPECT_NULL;
		}
		task = (task_inspect_t) ip_get_kobject(port);
		assert(task != TASK_INSPECT_NULL);
		/*
		 * Normal lock ordering puts task_lock() before ip_lock().
		 * Attempt out-of-order locking here.
		 */
		if (task_lock_try((task_t)task)) {
			ip_unlock(port);
			return task;
		}
		try_failed_count++;

		ip_unlock(port);
		mutex_pause(try_failed_count);
	}
	return TASK_INSPECT_NULL;
}

/*
 *	Routine: convert_port_to_locked_task_read
 *	Purpose:
 *		Internal helper routine to convert from a port to a locked
 *		task read right. Used by internal routines that try to convert from a
 *		task read port to a reference on some task related object.
 *	Conditions:
 *		Nothing locked, blocking OK.
 */
task_read_t
convert_port_to_locked_task_read(ipc_port_t port)
{
	int try_failed_count = 0;

	while (IP_VALID(port)) {
		task_read_t task;

		ip_lock(port);
		if (!ip_active(port) || (ip_kotype(port) != IKOT_TASK_CONTROL &&
		    ip_kotype(port) != IKOT_TASK_READ)) {
			ip_unlock(port);
			return TASK_READ_NULL;
		}
		task = (task_read_t)port->ip_kobject;
		assert(task != TASK_READ_NULL);
		/*
		 * Normal lock ordering puts task_lock() before ip_lock().
		 * Attempt out-of-order locking here.
		 */
		if (task_lock_try((task_t)task)) {
			ip_unlock(port);
			return task;
		}
		try_failed_count++;

		ip_unlock(port);
		mutex_pause(try_failed_count);
	}
	return TASK_READ_NULL;
}

static task_t
convert_port_to_task_locked(
	ipc_port_t              port,
	uint32_t                *exec_token,
	boolean_t               eval)
{
	task_t          task = TASK_NULL;

	ip_lock_held(port);
	require_ip_active(port);

	if (ip_kotype(port) == IKOT_TASK_CONTROL) {
		task = (task_t) ip_get_kobject(port);
		assert(task != TASK_NULL);

		if (eval && task_conversion_eval(current_task(), task)) {
			return TASK_NULL;
		}

		if (exec_token) {
			*exec_token = task->exec_token;
		}

		task_reference_internal(task);
	}

	return task;
}

/*
 *	Routine:	convert_port_to_task_with_exec_token
 *	Purpose:
 *		Convert from a port to a task and return
 *		the exec token stored in the task.
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
task_t
convert_port_to_task_with_exec_token(
	ipc_port_t              port,
	uint32_t                *exec_token,
	boolean_t               eval)
{
	task_t          task = TASK_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			task = convert_port_to_task_locked(port, exec_token, eval);
		}
		ip_unlock(port);
	}

	return task;
}

/*
 *	Routine:	convert_port_to_task
 *	Purpose:
 *		Convert from a port to a task.
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
task_t
convert_port_to_task(
	ipc_port_t              port)
{
	return convert_port_to_task_with_exec_token(port, NULL, TRUE);
}

/*
 *	Routine:	convert_port_to_task_no_eval
 *	Purpose:
 *		Convert from a port to a task, skips task_conversion_eval.
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
static task_t
convert_port_to_task_no_eval(
	ipc_port_t              port)
{
	return convert_port_to_task_with_exec_token(port, NULL, FALSE);
}

/*
 *	Routine:	convert_port_to_task_name
 *	Purpose:
 *		Convert from a port to a task name.
 *		Doesn't consume the port ref; produces a task name ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

static task_name_t
convert_port_to_task_name_locked(
	ipc_port_t              port)
{
	task_name_t task = TASK_NAME_NULL;

	ip_lock_held(port);
	require_ip_active(port);

	if (ip_kotype(port) == IKOT_TASK_CONTROL ||
	    ip_kotype(port) == IKOT_TASK_READ ||
	    ip_kotype(port) == IKOT_TASK_INSPECT ||
	    ip_kotype(port) == IKOT_TASK_NAME) {
		task = (task_name_t) ip_get_kobject(port);
		assert(task != TASK_NAME_NULL);

		task_reference_internal(task);
	}

	return task;
}

task_name_t
convert_port_to_task_name(
	ipc_port_t              port)
{
	task_name_t             task = TASK_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			task = convert_port_to_task_name_locked(port);
		}
		ip_unlock(port);
	}

	return task;
}

/*
 *	Routine:	convert_port_to_task_policy
 *	Purpose:
 *		Convert from a port to a task.
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *		If the port is being used with task_port_set(), any task port
 *		type other than TASK_CONTROL requires an entitlement. If the
 *		port is being used with task_port_get(), TASK_NAME requires an
 *		entitlement.
 *	Conditions:
 *		Nothing locked.
 */
static task_t
convert_port_to_task_policy(ipc_port_t port, boolean_t set)
{
	task_t task = TASK_NULL;
	task_t ctask = current_task();

	if (!IP_VALID(port)) {
		return TASK_NULL;
	}

	task = set ?
	    convert_port_to_task(port) :
	    convert_port_to_task_inspect(port);

	if (task == TASK_NULL &&
	    IOTaskHasEntitlement(ctask, "com.apple.private.task_policy")) {
		task = convert_port_to_task_name(port);
	}

	if (task_conversion_eval(ctask, task) != KERN_SUCCESS) {
		task_deallocate(task);
		return TASK_NULL;
	}

	return task;
}

task_policy_set_t
convert_port_to_task_policy_set(ipc_port_t port)
{
	return convert_port_to_task_policy(port, true);
}

task_policy_get_t
convert_port_to_task_policy_get(ipc_port_t port)
{
	return convert_port_to_task_policy(port, false);
}

static task_inspect_t
convert_port_to_task_inspect_locked(
	ipc_port_t              port)
{
	task_inspect_t task = TASK_INSPECT_NULL;

	ip_lock_held(port);
	require_ip_active(port);

	if (ip_kotype(port) == IKOT_TASK_CONTROL ||
	    ip_kotype(port) == IKOT_TASK_READ ||
	    ip_kotype(port) == IKOT_TASK_INSPECT) {
		task = (task_inspect_t) ip_get_kobject(port);
		assert(task != TASK_INSPECT_NULL);

		task_reference_internal(task);
	}

	return task;
}

static task_read_t
convert_port_to_task_read_locked(
	ipc_port_t              port)
{
	task_read_t task = TASK_READ_NULL;

	ip_lock_held(port);
	require_ip_active(port);

	if (ip_kotype(port) == IKOT_TASK_CONTROL ||
	    ip_kotype(port) == IKOT_TASK_READ) {
		task_t ct = current_task();
		task = (task_t)port->ip_kobject;

		assert(task != TASK_READ_NULL);

		if (task_conversion_eval(ct, task)) {
			return TASK_READ_NULL;
		}

		task_reference_internal(task);
	}

	return task;
}

/*
 *	Routine:	convert_port_to_task_check_type
 *	Purpose:
 *		Convert from a port to a task based on port's type.
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *  Arguments:
 *		port:       The port that we do conversion on
 *      kotype:     Returns the IKOT_TYPE of the port, if translation succeeded
 *      at_most:    The lowest capability flavor allowed. In mach_task_flavor_t,
 *                  the higher the flavor number, the lesser the capability, hence the name.
 *      eval_check: Whether to run task_conversion_eval check during the conversion.
 *                  For backward compatibility, some interfaces does not run conversion
 *                  eval on IKOT_TASK_CONTROL.
 *	Conditions:
 *		Nothing locked.
 *  Returns:
 *      task_t and port's type, if translation succeeded;
 *      TASK_NULL and IKOT_NONE, if translation failed
 */
task_t
convert_port_to_task_check_type(
	ipc_port_t              port,
	ipc_kobject_type_t     *kotype,
	mach_task_flavor_t      at_most,
	boolean_t               eval_check)
{
	task_t task = TASK_NULL;
	ipc_kobject_type_t type = IKOT_NONE;

	if (!IP_VALID(port) || !ip_active(port)) {
		goto out;
	}

	switch (ip_kotype(port)) {
	case IKOT_TASK_CONTROL:
		task = eval_check ? convert_port_to_task(port) : convert_port_to_task_no_eval(port);
		if (task != TASK_NULL) {
			type = IKOT_TASK_CONTROL;
		}
		break;
	case IKOT_TASK_READ:
		if (at_most >= TASK_FLAVOR_READ) {
			task = convert_port_to_task_read(port);
			if (task != TASK_READ_NULL) {
				type = IKOT_TASK_READ;
			}
		}
		break;
	case IKOT_TASK_INSPECT:
		if (at_most >= TASK_FLAVOR_INSPECT) {
			task = convert_port_to_task_inspect(port);
			if (task != TASK_INSPECT_NULL) {
				type = IKOT_TASK_INSPECT;
			}
		}
		break;
	case IKOT_TASK_NAME:
		if (at_most >= TASK_FLAVOR_NAME) {
			task = convert_port_to_task_name(port);
			if (task != TASK_NAME_NULL) {
				type = IKOT_TASK_NAME;
			}
		}
		break;
	default:
		break;
	}

out:
	if (kotype) {
		*kotype = type;
	}
	return task;
}

/*
 *	Routine:	convert_port_to_thread_check_type
 *	Purpose:
 *		Convert from a port to a thread based on port's type.
 *		Doesn't consume the port ref; produces a thread ref,
 *		which may be null.
 *      This conversion routine is _ONLY_ supposed to be used
 *      by thread_get_special_port.
 *  Arguments:
 *		port:       The port that we do conversion on
 *      kotype:     Returns the IKOT_TYPE of the port, if translation succeeded
 *      at_most:    The lowest capability flavor allowed. In mach_thread_flavor_t,
 *                  the higher the flavor number, the lesser the capability, hence the name.
 *      eval_check: Whether to run task_conversion_eval check during the conversion.
 *                  For backward compatibility, some interfaces do not run
 *                  conversion eval on IKOT_THREAD_CONTROL.
 *	Conditions:
 *		Nothing locked.
 *  Returns:
 *      thread_t and port's type, if translation succeeded;
 *      THREAD_NULL and IKOT_NONE, if translation failed
 */
thread_t
convert_port_to_thread_check_type(
	ipc_port_t              port,
	ipc_kobject_type_t     *kotype,
	mach_thread_flavor_t    at_most,
	boolean_t               eval_check)
{
	thread_t thread = THREAD_NULL;
	ipc_kobject_type_t type = IKOT_NONE;

	if (!IP_VALID(port) || !ip_active(port)) {
		goto out;
	}

	switch (ip_kotype(port)) {
	case IKOT_THREAD_CONTROL:
		thread = eval_check ? convert_port_to_thread(port) : convert_port_to_thread_no_eval(port);
		if (thread != THREAD_NULL) {
			type = IKOT_THREAD_CONTROL;
		}
		break;
	case IKOT_THREAD_READ:
		if (at_most >= THREAD_FLAVOR_READ) {
			thread = convert_port_to_thread_read(port);
			if (thread != THREAD_READ_NULL) {
				type = IKOT_THREAD_READ;
			}
		}
		break;
	case IKOT_THREAD_INSPECT:
		if (at_most >= THREAD_FLAVOR_INSPECT) {
			thread = convert_port_to_thread_inspect(port);
			if (thread != THREAD_INSPECT_NULL) {
				type = IKOT_THREAD_INSPECT;
			}
		}
		break;
	default:
		break;
	}

out:
	if (kotype) {
		*kotype = type;
	}
	return thread;
}

/*
 *	Routine:	convert_port_to_space_check_type
 *	Purpose:
 *		Convert from a port to a space based on port's type.
 *		Doesn't consume the port ref; produces a space ref,
 *		which may be null.
 *  Arguments:
 *      port:       The port that we do conversion on
 *      kotype:     Returns the IKOT_TYPE of the port, if translation succeeded
 *      at_most:    The lowest capability flavor allowed. In mach_task_flavor_t,
 *                  the higher the flavor number, the lesser the capability, hence the name.
 *      eval_check: Whether to run task_conversion_eval check during the conversion.
 *                  For backward compatibility, some interfaces do not run
 *                  conversion eval on IKOT_TASK_CONTROL.
 *	Conditions:
 *		Nothing locked.
 *  Returns:
 *      ipc_space_t and port's type, if translation succeeded;
 *      IPC_SPACE_NULL and IKOT_NONE, if translation failed
 */
ipc_space_t
convert_port_to_space_check_type(
	ipc_port_t              port,
	ipc_kobject_type_t     *kotype,
	mach_task_flavor_t      at_most,
	boolean_t               eval_check)
{
	ipc_space_t space = IPC_SPACE_NULL;
	ipc_kobject_type_t type = IKOT_NONE;

	if (!IP_VALID(port) || !ip_active(port)) {
		goto out;
	}

	switch (ip_kotype(port)) {
	case IKOT_TASK_CONTROL:
		space = eval_check ? convert_port_to_space(port) : convert_port_to_space_no_eval(port);
		if (space != IPC_SPACE_NULL) {
			type = IKOT_TASK_CONTROL;
		}
		break;
	case IKOT_TASK_READ:
		if (at_most >= TASK_FLAVOR_READ) {
			space = convert_port_to_space_read(port);
			if (space != IPC_SPACE_READ_NULL) {
				type = IKOT_TASK_READ;
			}
		}
		break;
	case IKOT_TASK_INSPECT:
		if (at_most >= TASK_FLAVOR_INSPECT) {
			space = convert_port_to_space_inspect(port);
			if (space != IPC_SPACE_INSPECT_NULL) {
				type = IKOT_TASK_INSPECT;
			}
		}
		break;
	default:
		break;
	}

out:
	if (kotype) {
		*kotype = type;
	}
	return space;
}

/*
 *	Routine:	convert_port_to_task_inspect
 *	Purpose:
 *		Convert from a port to a task inspection right
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
task_inspect_t
convert_port_to_task_inspect(
	ipc_port_t              port)
{
	task_inspect_t task = TASK_INSPECT_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			task = convert_port_to_task_inspect_locked(port);
		}
		ip_unlock(port);
	}

	return task;
}

/*
 *	Routine:	convert_port_to_task_read
 *	Purpose:
 *		Convert from a port to a task read right
 *		Doesn't consume the port ref; produces a task ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
task_read_t
convert_port_to_task_read(
	ipc_port_t              port)
{
	task_read_t task = TASK_READ_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			task = convert_port_to_task_read_locked(port);
		}
		ip_unlock(port);
	}

	return task;
}

/*
 *	Routine:	convert_port_to_task_suspension_token
 *	Purpose:
 *		Convert from a port to a task suspension token.
 *		Doesn't consume the port ref; produces a suspension token ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
task_suspension_token_t
convert_port_to_task_suspension_token(
	ipc_port_t              port)
{
	task_suspension_token_t         task = TASK_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);

		if (ip_active(port) &&
		    ip_kotype(port) == IKOT_TASK_RESUME) {
			task = (task_suspension_token_t) ip_get_kobject(port);
			assert(task != TASK_NULL);

			task_reference_internal(task);
		}

		ip_unlock(port);
	}

	return task;
}

/*
 *	Routine:	convert_port_to_space_with_flavor
 *	Purpose:
 *		Convert from a port to a space.
 *		Doesn't consume the port ref; produces a space ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
static ipc_space_t
convert_port_to_space_with_flavor(
	ipc_port_t         port,
	mach_task_flavor_t flavor,
	boolean_t          eval)
{
	ipc_space_t space;
	task_t task;

	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
		task = convert_port_to_locked_task(port, eval);
		break;
	case TASK_FLAVOR_READ:
		task = convert_port_to_locked_task_read(port);
		break;
	case TASK_FLAVOR_INSPECT:
		task = convert_port_to_locked_task_inspect(port);
		break;
	default:
		task = TASK_NULL;
		break;
	}

	if (task == TASK_NULL) {
		return IPC_SPACE_NULL;
	}

	if (!task->active) {
		task_unlock(task);
		return IPC_SPACE_NULL;
	}

	space = task->itk_space;
	is_reference(space);
	task_unlock(task);
	return space;
}

ipc_space_t
convert_port_to_space(
	ipc_port_t      port)
{
	return convert_port_to_space_with_flavor(port, TASK_FLAVOR_CONTROL, TRUE);
}

static ipc_space_t
convert_port_to_space_no_eval(
	ipc_port_t      port)
{
	return convert_port_to_space_with_flavor(port, TASK_FLAVOR_CONTROL, FALSE);
}

ipc_space_read_t
convert_port_to_space_read(
	ipc_port_t      port)
{
	return convert_port_to_space_with_flavor(port, TASK_FLAVOR_READ, TRUE);
}

ipc_space_inspect_t
convert_port_to_space_inspect(
	ipc_port_t      port)
{
	return convert_port_to_space_with_flavor(port, TASK_FLAVOR_INSPECT, TRUE);
}

/*
 *	Routine:	convert_port_to_map_with_flavor
 *	Purpose:
 *		Convert from a port to a map.
 *		Doesn't consume the port ref; produces a map ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

static vm_map_t
convert_port_to_map_with_flavor(
	ipc_port_t         port,
	mach_task_flavor_t flavor)
{
	task_t task;
	vm_map_t map;

	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
		task = convert_port_to_locked_task(port, TRUE);
		break;
	case TASK_FLAVOR_READ:
		task = convert_port_to_locked_task_read(port);
		break;
	case TASK_FLAVOR_INSPECT:
		task = convert_port_to_locked_task_inspect(port);
		break;
	default:
		task = TASK_NULL;
		break;
	}

	if (task == TASK_NULL) {
		return VM_MAP_NULL;
	}

	if (!task->active) {
		task_unlock(task);
		return VM_MAP_NULL;
	}

	map = task->map;
	if (map->pmap == kernel_pmap) {
		if (flavor == TASK_FLAVOR_CONTROL) {
			panic("userspace has control access to a "
			    "kernel map %p through task %p", map, task);
		}
		if (task != kernel_task) {
			panic("userspace has access to a "
			    "kernel map %p through task %p", map, task);
		}
	} else {
		pmap_require(map->pmap);
	}

	vm_map_reference_swap(map);
	task_unlock(task);
	return map;
}

vm_map_read_t
convert_port_to_map(
	ipc_port_t              port)
{
	return convert_port_to_map_with_flavor(port, TASK_FLAVOR_CONTROL);
}

vm_map_read_t
convert_port_to_map_read(
	ipc_port_t              port)
{
	return convert_port_to_map_with_flavor(port, TASK_FLAVOR_READ);
}

vm_map_inspect_t
convert_port_to_map_inspect(
	ipc_port_t              port)
{
	return convert_port_to_map_with_flavor(port, TASK_FLAVOR_INSPECT);
}


/*
 *	Routine:	convert_port_to_thread
 *	Purpose:
 *		Convert from a port to a thread.
 *		Doesn't consume the port ref; produces an thread ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */

static thread_t
convert_port_to_thread_locked(
	ipc_port_t               port,
	port_to_thread_options_t options,
	boolean_t                eval)
{
	thread_t        thread = THREAD_NULL;

	ip_lock_held(port);
	require_ip_active(port);

	if (ip_kotype(port) == IKOT_THREAD_CONTROL) {
		thread = (thread_t) ip_get_kobject(port);
		assert(thread != THREAD_NULL);

		if (options & PORT_TO_THREAD_NOT_CURRENT_THREAD) {
			if (thread == current_thread()) {
				return THREAD_NULL;
			}
		}

		if (options & PORT_TO_THREAD_IN_CURRENT_TASK) {
			if (thread->task != current_task()) {
				return THREAD_NULL;
			}
		} else {
			/* Use task conversion rules for thread control conversions */
			if (eval && task_conversion_eval(current_task(), thread->task) != KERN_SUCCESS) {
				return THREAD_NULL;
			}
		}

		thread_reference_internal(thread);
	}

	return thread;
}

thread_t
convert_port_to_thread(
	ipc_port_t              port)
{
	thread_t        thread = THREAD_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			thread = convert_port_to_thread_locked(port, PORT_TO_THREAD_NONE, TRUE);
		}
		ip_unlock(port);
	}

	return thread;
}

static thread_t
convert_port_to_thread_no_eval(
	ipc_port_t              port)
{
	thread_t        thread = THREAD_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			thread = convert_port_to_thread_locked(port, PORT_TO_THREAD_NONE, FALSE);
		}
		ip_unlock(port);
	}

	return thread;
}

/*
 *	Routine:	convert_port_to_thread_inspect
 *	Purpose:
 *		Convert from a port to a thread inspect right
 *		Doesn't consume the port ref; produces a thread ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
static thread_inspect_t
convert_port_to_thread_inspect_locked(
	ipc_port_t              port)
{
	thread_inspect_t thread = THREAD_INSPECT_NULL;

	ip_lock_held(port);
	require_ip_active(port);

	if (ip_kotype(port) == IKOT_THREAD_CONTROL ||
	    ip_kotype(port) == IKOT_THREAD_READ ||
	    ip_kotype(port) == IKOT_THREAD_INSPECT) {
		thread = (thread_inspect_t)port->ip_kobject;
		assert(thread != THREAD_INSPECT_NULL);
		thread_reference_internal((thread_t)thread);
	}

	return thread;
}

thread_inspect_t
convert_port_to_thread_inspect(
	ipc_port_t              port)
{
	thread_inspect_t thread = THREAD_INSPECT_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			thread = convert_port_to_thread_inspect_locked(port);
		}
		ip_unlock(port);
	}

	return thread;
}

/*
 *	Routine:	convert_port_to_thread_read
 *	Purpose:
 *		Convert from a port to a thread read right
 *		Doesn't consume the port ref; produces a thread ref,
 *		which may be null.
 *	Conditions:
 *		Nothing locked.
 */
static thread_read_t
convert_port_to_thread_read_locked(
	ipc_port_t              port)
{
	thread_read_t thread = THREAD_READ_NULL;

	ip_lock_held(port);
	require_ip_active(port);

	if (ip_kotype(port) == IKOT_THREAD_CONTROL ||
	    ip_kotype(port) == IKOT_THREAD_READ) {
		thread = (thread_read_t) ip_get_kobject(port);
		assert(thread != THREAD_READ_NULL);

		/* Use task conversion rules for thread control conversions */
		if (task_conversion_eval(current_task(), thread->task) != KERN_SUCCESS) {
			return THREAD_READ_NULL;
		}

		thread_reference_internal((thread_t)thread);
	}

	return thread;
}

thread_read_t
convert_port_to_thread_read(
	ipc_port_t              port)
{
	thread_read_t thread = THREAD_READ_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			thread = convert_port_to_thread_read_locked(port);
		}
		ip_unlock(port);
	}

	return thread;
}


/*
 *	Routine:	convert_thread_to_port_with_flavor
 *	Purpose:
 *		Convert from a thread to a port of given flavor.
 *		Consumes a thread ref; produces a naked send right
 *		which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
static ipc_port_t
convert_thread_to_port_with_flavor(
	thread_t              thread,
	mach_thread_flavor_t  flavor)
{
	ipc_port_t port = IP_NULL;

	thread_mtx_lock(thread);

	if (thread->ith_self[THREAD_FLAVOR_CONTROL] == IP_NULL) {
		goto exit;
	}

	if (flavor == THREAD_FLAVOR_CONTROL) {
		port = ipc_port_make_send(thread->ith_self[flavor]);
	} else {
		if (!thread->active) {
			goto exit;
		}
		ipc_kobject_type_t kotype = (flavor == THREAD_FLAVOR_READ) ? IKOT_THREAD_READ : IKOT_THREAD_INSPECT;
		/*
		 * Claim a send right on the thread read/inspect port, and request a no-senders
		 * notification on that port (if none outstanding). A thread reference is not
		 * donated here even though the ports are created lazily because it doesn't own the
		 * kobject that it points to. Threads manage their lifetime explicitly and
		 * have to synchronize with each other, between the task/thread terminating and the
		 * send-once notification firing, and this is done under the thread mutex
		 * rather than with atomics.
		 */
		(void)ipc_kobject_make_send_lazy_alloc_port(&thread->ith_self[flavor], (ipc_kobject_t)thread,
		    kotype, false, 0);
		port = thread->ith_self[flavor];
	}

exit:
	thread_mtx_unlock(thread);
	thread_deallocate(thread);
	return port;
}

ipc_port_t
convert_thread_to_port(
	thread_t                thread)
{
	return convert_thread_to_port_with_flavor(thread, THREAD_FLAVOR_CONTROL);
}

ipc_port_t
convert_thread_read_to_port(thread_read_t thread)
{
	return convert_thread_to_port_with_flavor(thread, THREAD_FLAVOR_READ);
}

ipc_port_t
convert_thread_inspect_to_port(thread_inspect_t thread)
{
	return convert_thread_to_port_with_flavor(thread, THREAD_FLAVOR_INSPECT);
}


/*
 *	Routine:	port_name_to_thread
 *	Purpose:
 *		Convert from a port name to a thread reference
 *		A name of MACH_PORT_NULL is valid for the null thread.
 *	Conditions:
 *		Nothing locked.
 */
thread_t
port_name_to_thread(
	mach_port_name_t         name,
	port_to_thread_options_t options)
{
	thread_t        thread = THREAD_NULL;
	ipc_port_t      kport;
	kern_return_t kr;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &kport);
		if (kr == KERN_SUCCESS) {
			thread = convert_port_to_thread_locked(kport, options, TRUE);
			ip_unlock(kport);
		}
	}

	return thread;
}

/*
 *	Routine:	port_name_to_task
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *	Conditions:
 *		Nothing locked.
 */
task_t
port_name_to_task(
	mach_port_name_t name)
{
	ipc_port_t kport;
	kern_return_t kr;
	task_t task = TASK_NULL;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &kport);
		if (kr == KERN_SUCCESS) {
			task = convert_port_to_task_locked(kport, NULL, TRUE);
			ip_unlock(kport);
		}
	}
	return task;
}

/*
 *	Routine:	port_name_to_task_read
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *	Conditions:
 *		Nothing locked.
 */
task_read_t
port_name_to_task_read(
	mach_port_name_t name)
{
	ipc_port_t kport;
	kern_return_t kr;
	task_read_t tr = TASK_READ_NULL;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &kport);
		if (kr == KERN_SUCCESS) {
			tr = convert_port_to_task_read_locked(kport);
			ip_unlock(kport);
		}
	}
	return tr;
}

/*
 *	Routine:	port_name_to_task_read_no_eval
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *		It doesnt run the task_conversion_eval check if the port
 *		is of type IKOT_TASK_CONTROL.
 *	Conditions:
 *		Nothing locked.
 */
task_read_t
port_name_to_task_read_no_eval(
	mach_port_name_t name)
{
	ipc_port_t kport;
	kern_return_t kr;
	task_read_t tr = TASK_READ_NULL;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &kport);
		if (kr == KERN_SUCCESS) {
			switch (ip_kotype(kport)) {
			case IKOT_TASK_CONTROL:
				tr = convert_port_to_task_locked(kport, NULL, FALSE);
				break;
			case IKOT_TASK_READ:
				tr = convert_port_to_task_read_locked(kport);
				break;
			default:
				break;
			}
			ip_unlock(kport);
		}
	}
	return tr;
}

/*
 *	Routine:	port_name_to_task_inspect
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *	Conditions:
 *		Nothing locked.
 */
task_inspect_t
port_name_to_task_inspect(
	mach_port_name_t name)
{
	ipc_port_t kport;
	kern_return_t kr;
	task_inspect_t ti = TASK_INSPECT_NULL;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &kport);
		if (kr == KERN_SUCCESS) {
			ti = convert_port_to_task_inspect_locked(kport);
			ip_unlock(kport);
		}
	}
	return ti;
}

/*
 *	Routine:	port_name_to_task_name
 *	Purpose:
 *		Convert from a port name to a task reference
 *		A name of MACH_PORT_NULL is valid for the null task.
 *	Conditions:
 *		Nothing locked.
 */
task_name_t
port_name_to_task_name(
	mach_port_name_t name)
{
	ipc_port_t kport;
	kern_return_t kr;
	task_name_t tn = TASK_NAME_NULL;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &kport);
		if (kr == KERN_SUCCESS) {
			tn = convert_port_to_task_name_locked(kport);
			ip_unlock(kport);
		}
	}
	return tn;
}

/*
 *	Routine:	port_name_to_host
 *	Purpose:
 *		Convert from a port name to a host pointer.
 *		NOTE: This does _not_ return a +1 reference to the host_t
 *	Conditions:
 *		Nothing locked.
 */
host_t
port_name_to_host(
	mach_port_name_t name)
{
	host_t host = HOST_NULL;
	kern_return_t kr;
	ipc_port_t port;

	if (MACH_PORT_VALID(name)) {
		kr = ipc_port_translate_send(current_space(), name, &port);
		if (kr == KERN_SUCCESS) {
			host = convert_port_to_host(port);
			ip_unlock(port);
		}
	}
	return host;
}

/*
 *	Routine:	convert_task_to_port_with_flavor
 *	Purpose:
 *		Convert from a task to a port of given flavor.
 *		Consumes a task ref; produces a naked send right
 *		which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
static ipc_port_t
convert_task_to_port_with_flavor(
	task_t              task,
	mach_task_flavor_t  flavor)
{
	ipc_port_t port = IP_NULL;
	ipc_kobject_type_t kotype = IKOT_NONE;

	itk_lock(task);

	switch (flavor) {
	case TASK_FLAVOR_CONTROL:
	case TASK_FLAVOR_NAME:
		port = ipc_port_make_send(task->itk_self[flavor]);
		break;
	/*
	 * Claim a send right on the task read/inspect port, and request a no-senders
	 * notification on that port (if none outstanding). A task reference is
	 * deliberately not donated here because ipc_kobject_make_send_lazy_alloc_port
	 * is used only for convenience and these ports don't control the lifecycle of
	 * the task kobject. Instead, the task's itk_lock is used to synchronize the
	 * handling of the no-senders notification with the task termination.
	 */
	case TASK_FLAVOR_READ:
	case TASK_FLAVOR_INSPECT:
		if (task->itk_self[TASK_FLAVOR_CONTROL] == IP_NULL) {
			/* task is either disabled or terminated */
			goto exit;
		}
		kotype = (flavor == TASK_FLAVOR_READ) ? IKOT_TASK_READ : IKOT_TASK_INSPECT;
		(void)ipc_kobject_make_send_lazy_alloc_port((ipc_port_t *) &task->itk_self[flavor],
		    (ipc_kobject_t)task, kotype, true, OS_PTRAUTH_DISCRIMINATOR("task.itk_self"));
		port = task->itk_self[flavor];

		break;
	}

exit:
	itk_unlock(task);
	task_deallocate(task);
	return port;
}

ipc_port_t
convert_task_to_port(
	task_t          task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_CONTROL);
}

ipc_port_t
convert_task_read_to_port(
	task_read_t          task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_READ);
}

ipc_port_t
convert_task_inspect_to_port(
	task_inspect_t          task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_INSPECT);
}

ipc_port_t
convert_task_name_to_port(
	task_name_t             task)
{
	return convert_task_to_port_with_flavor(task, TASK_FLAVOR_NAME);
}

/*
 *	Routine:	convert_task_suspend_token_to_port
 *	Purpose:
 *		Convert from a task suspension token to a port.
 *		Consumes a task suspension token ref; produces a naked send-once right
 *		which may be invalid.
 *	Conditions:
 *		Nothing locked.
 */
ipc_port_t
convert_task_suspension_token_to_port(
	task_suspension_token_t         task)
{
	ipc_port_t port;

	task_lock(task);
	if (task->active) {
		if (task->itk_resume == IP_NULL) {
			task->itk_resume = ipc_kobject_alloc_port((ipc_kobject_t) task,
			    IKOT_TASK_RESUME, IPC_KOBJECT_ALLOC_NONE);
		}

		/*
		 * Create a send-once right for each instance of a direct user-called
		 * task_suspend2 call. Each time one of these send-once rights is abandoned,
		 * the notification handler will resume the target task.
		 */
		port = ipc_port_make_sonce(task->itk_resume);
		assert(IP_VALID(port));
	} else {
		port = IP_NULL;
	}

	task_unlock(task);
	task_suspension_token_deallocate(task);

	return port;
}

/*
 *	Routine:	space_deallocate
 *	Purpose:
 *		Deallocate a space ref produced by convert_port_to_space.
 *	Conditions:
 *		Nothing locked.
 */

void
space_deallocate(
	ipc_space_t     space)
{
	if (space != IS_NULL) {
		is_release(space);
	}
}

/*
 *	Routine:	space_read_deallocate
 *	Purpose:
 *		Deallocate a space read ref produced by convert_port_to_space_read.
 *	Conditions:
 *		Nothing locked.
 */

void
space_read_deallocate(
	ipc_space_read_t     space)
{
	if (space != IS_INSPECT_NULL) {
		is_release((ipc_space_t)space);
	}
}

/*
 *	Routine:	space_inspect_deallocate
 *	Purpose:
 *		Deallocate a space inspect ref produced by convert_port_to_space_inspect.
 *	Conditions:
 *		Nothing locked.
 */

void
space_inspect_deallocate(
	ipc_space_inspect_t     space)
{
	if (space != IS_INSPECT_NULL) {
		is_release((ipc_space_t)space);
	}
}


/*
 *	Routine:	thread/task_set_exception_ports [kernel call]
 *	Purpose:
 *			Sets the thread/task exception port, flavor and
 *			behavior for the exception types specified by the mask.
 *			There will be one send right per exception per valid
 *			port.
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Illegal mask bit set.
 *					Illegal exception behavior
 *		KERN_FAILURE		The thread is dead.
 */

kern_return_t
thread_set_exception_ports(
	thread_t                                thread,
	exception_mask_t                exception_mask,
	ipc_port_t                              new_port,
	exception_behavior_t    new_behavior,
	thread_state_flavor_t   new_flavor)
{
	ipc_port_t              old_port[EXC_TYPES_COUNT];
	boolean_t privileged = current_task()->sec_token.val[0] == 0;
	register int    i;

#if CONFIG_MACF
	struct label *new_label;
#endif

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_MASK) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;

		default:
			return KERN_INVALID_ARGUMENT;
		}
	}


	/*
	 * Check the validity of the thread_state_flavor by calling the
	 * VALID_THREAD_STATE_FLAVOR architecture dependent macro defined in
	 * osfmk/mach/ARCHITECTURE/thread_status.h
	 */
	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor)) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	new_label = mac_exc_create_label_for_current_proc();
#endif

	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);

		return KERN_FAILURE;
	}

	if (thread->exc_actions == NULL) {
		ipc_thread_init_exc_actions(thread);
	}
	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(&thread->exc_actions[i], new_label) == 0
#endif
		    ) {
			old_port[i] = thread->exc_actions[i].port;
			thread->exc_actions[i].port = ipc_port_copy_send(new_port);
			thread->exc_actions[i].behavior = new_behavior;
			thread->exc_actions[i].flavor = new_flavor;
			thread->exc_actions[i].privileged = privileged;
		} else {
			old_port[i] = IP_NULL;
		}
	}

	thread_mtx_unlock(thread);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
	}

	if (IP_VALID(new_port)) {        /* consume send right */
		ipc_port_release_send(new_port);
	}

	return KERN_SUCCESS;
}

kern_return_t
task_set_exception_ports(
	task_t                                  task,
	exception_mask_t                exception_mask,
	ipc_port_t                              new_port,
	exception_behavior_t    new_behavior,
	thread_state_flavor_t   new_flavor)
{
	ipc_port_t              old_port[EXC_TYPES_COUNT];
	boolean_t privileged = current_task()->sec_token.val[0] == 0;
	register int    i;

#if CONFIG_MACF
	struct label *new_label;
#endif

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_MASK) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;

		default:
			return KERN_INVALID_ARGUMENT;
		}
	}


	/*
	 * Check the validity of the thread_state_flavor by calling the
	 * VALID_THREAD_STATE_FLAVOR architecture dependent macro defined in
	 * osfmk/mach/ARCHITECTURE/thread_status.h
	 */
	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor)) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	new_label = mac_exc_create_label_for_current_proc();
#endif

	itk_lock(task);

	if (task->itk_self[TASK_FLAVOR_CONTROL] == IP_NULL) {
		itk_unlock(task);

		return KERN_FAILURE;
	}

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(&task->exc_actions[i], new_label) == 0
#endif
		    ) {
			old_port[i] = task->exc_actions[i].port;
			task->exc_actions[i].port =
			    ipc_port_copy_send(new_port);
			task->exc_actions[i].behavior = new_behavior;
			task->exc_actions[i].flavor = new_flavor;
			task->exc_actions[i].privileged = privileged;
		} else {
			old_port[i] = IP_NULL;
		}
	}

	itk_unlock(task);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
	}

	if (IP_VALID(new_port)) {        /* consume send right */
		ipc_port_release_send(new_port);
	}

	return KERN_SUCCESS;
}

/*
 *	Routine:	thread/task_swap_exception_ports [kernel call]
 *	Purpose:
 *			Sets the thread/task exception port, flavor and
 *			behavior for the exception types specified by the
 *			mask.
 *
 *			The old ports, behavior and flavors are returned
 *			Count specifies the array sizes on input and
 *			the number of returned ports etc. on output.  The
 *			arrays must be large enough to hold all the returned
 *			data, MIG returnes an error otherwise.  The masks
 *			array specifies the corresponding exception type(s).
 *
 *	Conditions:
 *		Nothing locked.  If successful, consumes
 *		the supplied send right.
 *
 *		Returns upto [in} CountCnt elements.
 *	Returns:
 *		KERN_SUCCESS		Changed the special port.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Illegal mask bit set.
 *					Illegal exception behavior
 *		KERN_FAILURE		The thread is dead.
 */

kern_return_t
thread_swap_exception_ports(
	thread_t                                        thread,
	exception_mask_t                        exception_mask,
	ipc_port_t                                      new_port,
	exception_behavior_t            new_behavior,
	thread_state_flavor_t           new_flavor,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	ipc_port_t              old_port[EXC_TYPES_COUNT];
	boolean_t privileged = current_task()->sec_token.val[0] == 0;
	unsigned int    i, j, count;

#if CONFIG_MACF
	struct label *new_label;
#endif

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_MASK) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;

		default:
			return KERN_INVALID_ARGUMENT;
		}
	}


	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor)) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	new_label = mac_exc_create_label_for_current_proc();
#endif

	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);
#if CONFIG_MACF
		mac_exc_free_label(new_label);
#endif
		return KERN_FAILURE;
	}

	if (thread->exc_actions == NULL) {
		ipc_thread_init_exc_actions(thread);
	}

	assert(EXC_TYPES_COUNT > FIRST_EXCEPTION);
	for (count = 0, i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT && count < *CountCnt; ++i) {
		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(&thread->exc_actions[i], new_label) == 0
#endif
		    ) {
			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (thread->exc_actions[i].port == ports[j] &&
				    thread->exc_actions[i].behavior == behaviors[j] &&
				    thread->exc_actions[i].flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = ipc_port_copy_send(thread->exc_actions[i].port);

				behaviors[j] = thread->exc_actions[i].behavior;
				flavors[j] = thread->exc_actions[i].flavor;
				++count;
			}

			old_port[i] = thread->exc_actions[i].port;
			thread->exc_actions[i].port = ipc_port_copy_send(new_port);
			thread->exc_actions[i].behavior = new_behavior;
			thread->exc_actions[i].flavor = new_flavor;
			thread->exc_actions[i].privileged = privileged;
		} else {
			old_port[i] = IP_NULL;
		}
	}

	thread_mtx_unlock(thread);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	while (--i >= FIRST_EXCEPTION) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
	}

	if (IP_VALID(new_port)) {        /* consume send right */
		ipc_port_release_send(new_port);
	}

	*CountCnt = count;

	return KERN_SUCCESS;
}

kern_return_t
task_swap_exception_ports(
	task_t                                          task,
	exception_mask_t                        exception_mask,
	ipc_port_t                                      new_port,
	exception_behavior_t            new_behavior,
	thread_state_flavor_t           new_flavor,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	ipc_port_t              old_port[EXC_TYPES_COUNT];
	boolean_t privileged = current_task()->sec_token.val[0] == 0;
	unsigned int    i, j, count;

#if CONFIG_MACF
	struct label *new_label;
#endif

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	if (IP_VALID(new_port)) {
		switch (new_behavior & ~MACH_EXCEPTION_MASK) {
		case EXCEPTION_DEFAULT:
		case EXCEPTION_STATE:
		case EXCEPTION_STATE_IDENTITY:
			break;

		default:
			return KERN_INVALID_ARGUMENT;
		}
	}


	if (new_flavor != 0 && !VALID_THREAD_STATE_FLAVOR(new_flavor)) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	new_label = mac_exc_create_label_for_current_proc();
#endif

	itk_lock(task);

	if (task->itk_self[TASK_FLAVOR_CONTROL] == IP_NULL) {
		itk_unlock(task);
#if CONFIG_MACF
		mac_exc_free_label(new_label);
#endif
		return KERN_FAILURE;
	}

	assert(EXC_TYPES_COUNT > FIRST_EXCEPTION);
	for (count = 0, i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT && count < *CountCnt; ++i) {
		if ((exception_mask & (1 << i))
#if CONFIG_MACF
		    && mac_exc_update_action_label(&task->exc_actions[i], new_label) == 0
#endif
		    ) {
			for (j = 0; j < count; j++) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (task->exc_actions[i].port == ports[j] &&
				    task->exc_actions[i].behavior == behaviors[j] &&
				    task->exc_actions[i].flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = ipc_port_copy_send(task->exc_actions[i].port);
				behaviors[j] = task->exc_actions[i].behavior;
				flavors[j] = task->exc_actions[i].flavor;
				++count;
			}

			old_port[i] = task->exc_actions[i].port;

			task->exc_actions[i].port =     ipc_port_copy_send(new_port);
			task->exc_actions[i].behavior = new_behavior;
			task->exc_actions[i].flavor = new_flavor;
			task->exc_actions[i].privileged = privileged;
		} else {
			old_port[i] = IP_NULL;
		}
	}

	itk_unlock(task);

#if CONFIG_MACF
	mac_exc_free_label(new_label);
#endif

	while (--i >= FIRST_EXCEPTION) {
		if (IP_VALID(old_port[i])) {
			ipc_port_release_send(old_port[i]);
		}
	}

	if (IP_VALID(new_port)) {        /* consume send right */
		ipc_port_release_send(new_port);
	}

	*CountCnt = count;

	return KERN_SUCCESS;
}

/*
 *	Routine:	thread/task_get_exception_ports [kernel call]
 *	Purpose:
 *		Clones a send right for each of the thread/task's exception
 *		ports specified in the mask and returns the behaviour
 *		and flavor of said port.
 *
 *		Returns upto [in} CountCnt elements.
 *
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		KERN_SUCCESS		Extracted a send right.
 *		KERN_INVALID_ARGUMENT	The thread is null,
 *					Invalid special port,
 *					Illegal mask bit set.
 *		KERN_FAILURE		The thread is dead.
 */
kern_return_t
thread_get_exception_ports(
	thread_t                                        thread,
	exception_mask_t                        exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors);

kern_return_t
thread_get_exception_ports(
	thread_t                                        thread,
	exception_mask_t                        exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	unsigned int    i, j, count;

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	thread_mtx_lock(thread);

	if (!thread->active) {
		thread_mtx_unlock(thread);

		return KERN_FAILURE;
	}

	count = 0;

	if (thread->exc_actions == NULL) {
		goto done;
	}

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (thread->exc_actions[i].port == ports[j] &&
				    thread->exc_actions[i].behavior == behaviors[j] &&
				    thread->exc_actions[i].flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = ipc_port_copy_send(thread->exc_actions[i].port);
				behaviors[j] = thread->exc_actions[i].behavior;
				flavors[j] = thread->exc_actions[i].flavor;
				++count;
				if (count >= *CountCnt) {
					break;
				}
			}
		}
	}

done:
	thread_mtx_unlock(thread);

	*CountCnt = count;

	return KERN_SUCCESS;
}

kern_return_t
thread_get_exception_ports_from_user(
	mach_port_t                     port,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t         *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	kern_return_t kr;

	thread_t thread = convert_port_to_thread_check_type(port, NULL, THREAD_FLAVOR_CONTROL, FALSE);

	if (thread == THREAD_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = thread_get_exception_ports(thread, exception_mask, masks, CountCnt, ports, behaviors, flavors);

	thread_deallocate(thread);
	return kr;
}

kern_return_t
task_get_exception_ports(
	task_t                                          task,
	exception_mask_t                        exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors);

kern_return_t
task_get_exception_ports(
	task_t                                          task,
	exception_mask_t                        exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t          *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	unsigned int    i, j, count;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (exception_mask & ~EXC_MASK_VALID) {
		return KERN_INVALID_ARGUMENT;
	}

	itk_lock(task);

	if (task->itk_self[TASK_FLAVOR_CONTROL] == IP_NULL) {
		itk_unlock(task);

		return KERN_FAILURE;
	}

	count = 0;

	for (i = FIRST_EXCEPTION; i < EXC_TYPES_COUNT; ++i) {
		if (exception_mask & (1 << i)) {
			for (j = 0; j < count; ++j) {
				/*
				 * search for an identical entry, if found
				 * set corresponding mask for this exception.
				 */
				if (task->exc_actions[i].port == ports[j] &&
				    task->exc_actions[i].behavior == behaviors[j] &&
				    task->exc_actions[i].flavor == flavors[j]) {
					masks[j] |= (1 << i);
					break;
				}
			}

			if (j == count) {
				masks[j] = (1 << i);
				ports[j] = ipc_port_copy_send(task->exc_actions[i].port);
				behaviors[j] = task->exc_actions[i].behavior;
				flavors[j] = task->exc_actions[i].flavor;
				++count;
				if (count > *CountCnt) {
					break;
				}
			}
		}
	}

	itk_unlock(task);

	*CountCnt = count;

	return KERN_SUCCESS;
}

kern_return_t
task_get_exception_ports_from_user(
	mach_port_t                     port,
	exception_mask_t                exception_mask,
	exception_mask_array_t          masks,
	mach_msg_type_number_t         *CountCnt,
	exception_port_array_t          ports,
	exception_behavior_array_t      behaviors,
	thread_state_flavor_array_t     flavors)
{
	kern_return_t kr;

	task_t task = convert_port_to_task_check_type(port, NULL, TASK_FLAVOR_CONTROL, FALSE);

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = task_get_exception_ports(task, exception_mask, masks, CountCnt, ports, behaviors, flavors);

	task_deallocate(task);
	return kr;
}
