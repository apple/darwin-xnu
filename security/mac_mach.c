/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#include <mach/exception_types.h>
#include <mach/mach_types.h>
#include <osfmk/kern/exception.h>
#include <osfmk/kern/task.h>
#include <sys/codesign.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <kern/task.h>

#include <security/mac_framework.h>
#include <security/mac_internal.h>
#include <security/mac_mach_internal.h>

#if CONFIG_CSR
#include <sys/csr.h>
// Panic on internal builds, just log otherwise.
#define MAC_MACH_UNEXPECTED(fmt...) \
	if (csr_check(CSR_ALLOW_APPLE_INTERNAL) == 0) { panic(fmt); } else { printf(fmt); }
#else
#define MAC_MACH_UNEXPECTED(fmt...) printf(fmt)
#endif

static struct proc *
mac_task_get_proc(struct task *task)
{
	if (task == current_task())
		return proc_self();

	/*
	 * Tasks don't really hold a reference on a proc unless the
	 * calling thread belongs to the task in question.
	 */
	int pid = task_pid(task);
	struct proc *p = proc_find(pid);

	if (p != NULL) {
		if (proc_task(p) == task)
			return p;
		proc_rele(p);
	}
	return NULL;
}

int
mac_task_check_expose_task(struct task *task)
{
	int error;

	struct proc *p = mac_task_get_proc(task);
	if (p == NULL)
		return ESRCH;

	struct ucred *cred = kauth_cred_get();
	MAC_CHECK(proc_check_expose_task, cred, p);
	proc_rele(p);
	return (error);
}

int
mac_task_check_set_host_special_port(struct task *task, int id, struct ipc_port *port)
{
	int error;

	struct proc *p = mac_task_get_proc(task);
	if (p == NULL)
		return ESRCH;

	kauth_cred_t cred = kauth_cred_proc_ref(p);
	MAC_CHECK(proc_check_set_host_special_port, cred, id, port);
	kauth_cred_unref(&cred);
	proc_rele(p);
	return (error);
}

int
mac_task_check_set_host_exception_port(struct task *task, unsigned int exception)
{
	int error;

	struct proc *p = mac_task_get_proc(task);
	if (p == NULL)
		return ESRCH;

	kauth_cred_t cred = kauth_cred_proc_ref(p);
	MAC_CHECK(proc_check_set_host_exception_port, cred, exception);
	kauth_cred_unref(&cred);
	proc_rele(p);
	return (error);
}

int
mac_task_check_set_host_exception_ports(struct task *task, unsigned int exception_mask)
{
	int error = 0;
	int exception;

	struct proc *p = mac_task_get_proc(task);
	if (p == NULL)
		return ESRCH;

	kauth_cred_t cred = kauth_cred_proc_ref(p);
	for (exception = FIRST_EXCEPTION; exception < EXC_TYPES_COUNT; exception++) {
		if (exception_mask & (1 << exception)) {
			MAC_CHECK(proc_check_set_host_exception_port, cred, exception);
			if (error)
				break;
		}
	}
	kauth_cred_unref(&cred);
	proc_rele(p);
	return (error);
}

void
mac_thread_userret(struct thread *td)
{

	MAC_PERFORM(thread_userret, td);
}

/**** Exception Policy
 *
 * Note that the functions below do not fully follow the usual convention for mac policy functions
 * in the kernel. Besides avoiding confusion in how the mac function names are mixed with the actual
 * policy function names, we diverge because the exception policy is somewhat special:
 * It is used in places where allocation and association must be separate, and its labels do not
 * only belong to one type of object as usual, but to two (on exception actions and on tasks as
 * crash labels).
 */

// Label allocation and deallocation, may sleep.

struct label *
mac_exc_create_label(void)
{
	struct label *label = mac_labelzone_alloc(MAC_WAITOK);

	if (label == NULL) {
		return NULL;
	}

	// Policy initialization of the label, typically performs allocations as well.
	// (Unless the policy's full data really fits into a pointer size.)
	MAC_PERFORM(exc_action_label_init, label);
	
	return label;
}

void
mac_exc_free_label(struct label *label)
{
	MAC_PERFORM(exc_action_label_destroy, label);
	mac_labelzone_free(label);
}

// Action label initialization and teardown, may sleep.

void
mac_exc_associate_action_label(struct exception_action *action, struct label *label)
{
	action->label = label;
	MAC_PERFORM(exc_action_label_associate, action, action->label);
}

void
mac_exc_free_action_label(struct exception_action *action)
{
	mac_exc_free_label(action->label);
	action->label = NULL;
}

// Action label update and inheritance, may NOT sleep and must be quick.

int
mac_exc_update_action_label(struct exception_action *action,
							struct label *newlabel) {
	int error;
	
	MAC_CHECK(exc_action_label_update, action, action->label, newlabel);
	
	return (error);
}

int
mac_exc_inherit_action_label(struct exception_action *parent,
							 struct exception_action *child) {
	return mac_exc_update_action_label(child, parent->label);
}

int mac_exc_update_task_crash_label(struct task *task, struct label *label) {
	int error;

	assert(task != kernel_task);

	struct label *crash_label = get_task_crash_label(task);

	MAC_CHECK(exc_action_label_update, NULL, crash_label, label);
	
	return (error);
}

// Process label creation, may sleep.

struct label *
mac_exc_create_label_for_proc(struct proc *proc)
{
	struct label *label = mac_exc_create_label();
	MAC_PERFORM(exc_action_label_populate, label, proc);
	return label;
}

struct label *
mac_exc_create_label_for_current_proc(void)
{
	return mac_exc_create_label_for_proc(current_proc());
}

// Exception handler policy checking, may sleep.

int
mac_exc_action_check_exception_send(struct task *victim_task, struct exception_action *action)
{
	int error = 0;

	struct proc *p = get_bsdtask_info(victim_task);
	struct label *bsd_label = NULL;
	struct label *label = NULL;

	if (p != NULL) {
		// Create a label from the still existing bsd process...
		label = bsd_label = mac_exc_create_label_for_proc(p);
	} else {
		// ... otherwise use the crash label on the task.
		label = get_task_crash_label(victim_task);
	}

	if (label == NULL) {
		MAC_MACH_UNEXPECTED("mac_exc_action_check_exception_send: no exc_action label for process");
		return EPERM;
	}

	MAC_CHECK(exc_action_check_exception_send, label, action, action->label);

	if (bsd_label != NULL) {
		mac_exc_free_label(bsd_label);
	}

	return (error);
}
