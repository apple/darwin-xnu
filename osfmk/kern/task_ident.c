/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <os/refcnt.h>
#include <kern/ipc_kobject.h>
#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/notify.h>
#include <mach/kern_return.h>
#include <security/mac_mach_internal.h>
#include <kern/task_ident.h>

struct proc_ident {
	uint64_t        p_uniqueid;
	pid_t           p_pid;
	int             p_idversion;
};

extern void* proc_find_ident(struct proc_ident const *i);
extern int proc_rele(void* p);
extern task_t proc_task(void* p);
extern struct proc_ident proc_ident(void* p);
extern kern_return_t task_conversion_eval(task_t caller, task_t victim);

struct task_id_token {
	struct proc_ident ident;
	ipc_port_t        port;
	os_refcnt_t       tidt_refs;
};

static ZONE_DECLARE(task_id_token_zone, "task_id_token",
    sizeof(struct task_id_token), ZC_ZFREE_CLEARMEM);

static void
tidt_reference(task_id_token_t token)
{
	if (token == TASK_ID_TOKEN_NULL) {
		return;
	}
	os_ref_retain(&token->tidt_refs);
}

static void
tidt_release(task_id_token_t token)
{
	ipc_port_t port;

	if (token == TASK_ID_TOKEN_NULL) {
		return;
	}

	if (os_ref_release(&token->tidt_refs) > 0) {
		return;
	}

	/* last ref */
	port = token->port;

	require_ip_active(port);
	assert(!port->ip_srights);
	ipc_port_dealloc_kernel(port);

	zfree(task_id_token_zone, token);
}

void
task_id_token_release(task_id_token_t token)
{
	tidt_release(token);
}

void
task_id_token_notify(mach_msg_header_t *msg)
{
	assert(msg->msgh_id == MACH_NOTIFY_NO_SENDERS);

	mach_no_senders_notification_t *not = (mach_no_senders_notification_t *)msg;
	ipc_port_t port = not->not_header.msgh_remote_port;
	task_id_token_t token = ip_get_kobject(port);

	require_ip_active(port);
	assert(IKOT_TASK_ID_TOKEN == ip_kotype(port));
	assert(port->ip_srights == 0);

	tidt_release(token); /* consumes ref given by notification */
}

kern_return_t
task_create_identity_token(
	task_t task,
	task_id_token_t *tokenp)
{
	task_id_token_t token;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	token = zalloc_flags(task_id_token_zone, Z_ZERO | Z_WAITOK | Z_NOFAIL);

	task_lock(task);
	if (task->bsd_info) {
		token->port = IP_NULL;
		token->ident = proc_ident(task->bsd_info);
		/* this reference will be donated to no-senders notification */
		os_ref_init_count(&token->tidt_refs, NULL, 1);
	} else {
		task_unlock(task);
		zfree(task_id_token_zone, token);
		return KERN_INVALID_ARGUMENT;
	}
	task_unlock(task);

	*tokenp = token;

	return KERN_SUCCESS;
}

kern_return_t
task_identity_token_get_task_port(
	task_id_token_t token,
	task_flavor_t  flavor,
	ipc_port_t    *portp)
{
	int which;
	task_t task;
	kern_return_t kr;

	if (token == TASK_ID_TOKEN_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	switch (flavor) {
	case TASK_FLAVOR_NAME:
		which = TASK_NAME_PORT;
		break;
	case TASK_FLAVOR_INSPECT:
		which = TASK_INSPECT_PORT;
		break;
	case TASK_FLAVOR_READ:
		which = TASK_READ_PORT;
		break;
	case TASK_FLAVOR_CONTROL:
		which = TASK_KERNEL_PORT;
		break;
	default:
		return KERN_INVALID_ARGUMENT;
	}

	void* p = proc_find_ident(&token->ident);
	if (p == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	task = proc_task(p);
	task_reference(task);
	proc_rele(p);

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (flavor == TASK_FLAVOR_CONTROL && task == current_task()) {
		*portp = convert_task_to_port_pinned(task); /* consumes task ref */
		return KERN_SUCCESS;
	}
	if (flavor <= TASK_FLAVOR_INSPECT && task_conversion_eval(current_task(), task)) {
		task_deallocate(task);
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_MACF
	if (task != current_task()) {
		if (mac_task_check_task_id_token_get_task(task, flavor)) {
			task_deallocate(task);
			return KERN_DENIED;
		}
	}
#endif

	kr = task_get_special_port(task, which, portp);
	task_deallocate(task);
	return kr;
}

/* Produces token ref */
task_id_token_t
convert_port_to_task_id_token(
	ipc_port_t              port)
{
	task_id_token_t token = TASK_ID_TOKEN_NULL;

	if (IP_VALID(port)) {
		ip_lock(port);
		if (ip_active(port)) {
			if (ip_kotype(port) == IKOT_TASK_ID_TOKEN) {
				token = (task_id_token_t)ip_get_kobject(port);

				zone_require(task_id_token_zone, token);
				tidt_reference(token);
			}
		}
		ip_unlock(port);
	}
	return token;
}

/* Consumes token ref */
ipc_port_t
convert_task_id_token_to_port(
	task_id_token_t token)
{
	boolean_t kr;

	if (token == TASK_ID_TOKEN_NULL) {
		return IP_NULL;
	}

	zone_require(task_id_token_zone, token);

	kr = ipc_kobject_make_send_lazy_alloc_port(&token->port,
	    (ipc_kobject_t) token, IKOT_TASK_ID_TOKEN, IPC_KOBJECT_ALLOC_NONE, false, 0);
	assert(kr == TRUE); /* no-senders notification is armed, consumes token ref */

	return token->port;
}
