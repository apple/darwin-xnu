/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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
#include <kern/kern_types.h>
#include <mach/notify.h>
#include <mach/resource_monitors.h>

#include <mach/host_special_ports.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/fairplayd_notification.h>
#include <mach/arcade_upcall.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/host.h>
#include <kern/ast.h>
#include <kern/task.h>

#include <kern/arcade.h>
#include <mach/arcade_register_server.h>

#include <IOKit/IOBSD.h>

#if !defined(MAXPATHLEN)
#define MAXPATHLEN 4096
#endif

extern struct proc *current_proc(void);
extern int proc_pidpathinfo_internal(struct proc *p, uint64_t arg,
    char *buffer, uint32_t buffersize,
    int32_t *retval);
extern off_t proc_getexecutableoffset(struct proc *p);

/*
 * Simple structure to represent a handle for the Arcade registration.
 *
 * This registration is done with an independent kobject callback, rather
 * than a reply, so that we execute it in the context of the user-space
 * server replying (in order to do an entitlement check on the reply).
 *
 * We cache the resulting upcall port until it fails, and then we go
 * get another one.
 */
struct arcade_register {
	ipc_port_t ar_port;
};
typedef struct arcade_register *arcade_register_t;

static struct arcade_register arcade_register_global;

void
arcade_prepare(task_t task, thread_t thread)
{
	/* Platform binaries are exempt */
	if (task->t_flags & TF_PLATFORM) {
		return;
	}

	/* Check to see if the task has the arcade entitlement */
	if (!IOTaskHasEntitlement(task, "com.apple.developer.arcade-operations")) {
		return;
	}

	/* Others will stop in the AST to make an upcall */
	thread_ast_set(thread, AST_ARCADE);
}

static LCK_GRP_DECLARE(arcade_upcall_lck_grp, "arcade_upcall");
static LCK_MTX_DECLARE(arcade_upcall_mutex, &arcade_upcall_lck_grp);

static ipc_port_t arcade_upcall_port = IP_NULL;
static boolean_t arcade_upcall_refresh_in_progress = FALSE;
static boolean_t arcade_upcall_refresh_waiters = FALSE;

void
arcade_init(void)
{
	ipc_port_t port;

	/* Initialize the global arcade_register kobject and associated port */
	port = ipc_kobject_alloc_port((ipc_kobject_t)&arcade_register_global,
	    IKOT_ARCADE_REG, IPC_KOBJECT_ALLOC_MAKE_SEND);
	os_atomic_store(&arcade_register_global.ar_port, port, release);
}

arcade_register_t
convert_port_to_arcade_register(
	ipc_port_t              port)
{
	arcade_register_t arcade_reg = ARCADE_REG_NULL;

	if (IP_VALID(port)) {
		/* No need to lock port because of how refs managed */
		if (ip_kotype(port) == IKOT_ARCADE_REG) {
			assert(ip_active(port));
			arcade_reg = (arcade_register_t)ip_get_kobject(port);
			assert(arcade_reg == &arcade_register_global);
			assert(arcade_reg->ar_port == port);
		}
	}
	return arcade_reg;
}

ipc_port_t
convert_arcade_register_to_port(
	arcade_register_t arcade_reg)
{
	ipc_port_t port = IP_NULL;

	if (arcade_reg == &arcade_register_global) {
		port = arcade_reg->ar_port;
	}
	return port;
}

kern_return_t
arcade_register_new_upcall(
	arcade_register_t arcade_reg,
	mach_port_t port)
{
	if (arcade_reg == ARCADE_REG_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	assert(arcade_reg == &arcade_register_global);

	/* Check to see if this is the real arcade subscription service */
	if (!IOTaskHasEntitlement(current_task(), "com.apple.arcade.fpsd")) {
		return KERN_INVALID_VALUE;
	}

	lck_mtx_lock(&arcade_upcall_mutex);

	if (arcade_upcall_refresh_in_progress) {
		/* If we have an old arcade upcall port, discard it */
		if (IP_VALID(arcade_upcall_port)) {
			ipc_port_release_send(arcade_upcall_port);
			arcade_upcall_port = IP_NULL;
		}
		arcade_upcall_port = port; /* owns send right */

		/* Wake up anyone waiting for the update */
		lck_mtx_unlock(&arcade_upcall_mutex);
		thread_wakeup(&arcade_upcall_port);
		return KERN_SUCCESS;
	}

	lck_mtx_unlock(&arcade_upcall_mutex);
	return KERN_FAILURE;
}


static kern_return_t
arcade_upcall_refresh(uint64_t deadline)
{
	ipc_port_t fairplayd_port = IP_NULL;
	wait_result_t wr = THREAD_NOT_WAITING;
	kern_return_t kr;

	LCK_MTX_ASSERT(&arcade_upcall_mutex, LCK_MTX_ASSERT_OWNED);

	/* If someone else is doing the update, wait for them */
	if (arcade_upcall_refresh_in_progress) {
		arcade_upcall_refresh_waiters = TRUE;
		wr = lck_mtx_sleep(&arcade_upcall_mutex, LCK_SLEEP_DEFAULT,
		    &arcade_upcall_refresh_in_progress, THREAD_INTERRUPTIBLE);
		goto out;
	}

	arcade_upcall_refresh_in_progress = TRUE;

	/* If we have an old arcade upcall port, discard it */
	if (IP_VALID(arcade_upcall_port)) {
		ipc_port_release_send(arcade_upcall_port);
		arcade_upcall_port = IP_NULL;
	}

	if (host_get_fairplayd_port(host_priv_self(), &fairplayd_port) != KERN_SUCCESS) {
		panic("arcade_upcall_refresh(get fairplayd)");
	}

	/* If no valid fairplayd port registered, we're done */
	if (!IP_VALID(fairplayd_port)) {
		goto finish_in_progress;
	}

	/*
	 * Send a fairplayd notification to request a new arcade upcall port.
	 * Pass along a send right to the arcade_register kobject to complete
	 * the registration.
	 */
	ipc_port_t port = convert_arcade_register_to_port(&arcade_register_global);
	kr = fairplayd_arcade_request(fairplayd_port, port);

	ipc_port_release_send(fairplayd_port);

	switch (kr) {
	case MACH_MSG_SUCCESS:
		break;
	default:
		goto finish_in_progress;
	}

	/*
	 * Wait on the arcade upcall port to get registered through the
	 * registration kobject waiting with a deadline here.
	 */
	wr = lck_mtx_sleep_deadline(&arcade_upcall_mutex, LCK_SLEEP_DEFAULT,
	    &arcade_upcall_port, THREAD_INTERRUPTIBLE, deadline);

finish_in_progress:
	arcade_upcall_refresh_in_progress = FALSE;

	/* Wakeup any waiters */
	if (arcade_upcall_refresh_waiters) {
		arcade_upcall_refresh_waiters = FALSE;
		thread_wakeup_with_result(&arcade_upcall_refresh_in_progress, wr);
	}

out:
	switch (wr) {
	case THREAD_AWAKENED:
		return KERN_SUCCESS;
	default:
		return KERN_FAILURE;
	}
}

static kern_return_t
__MAKING_UPCALL_TO_ARCADE_VALIDATION_SERVICE__(mach_port_t port,
    vm_map_copy_t path,
    vm_size_t pathlen,
    off_t offset,
    boolean_t *should_killp)
{
	mach_msg_type_number_t len = (mach_msg_type_number_t)pathlen;
	return arcade_upcall(port, (vm_offset_t)path, len, offset, should_killp);
}

void
arcade_ast(__unused thread_t thread)
{
	ipc_port_t port;
	uint64_t deadline;
	kern_return_t kr;
	int retval;

	/* Determine the deadline */
	clock_interval_to_deadline(10, NSEC_PER_SEC, &deadline);

restart:
	lck_mtx_lock(&arcade_upcall_mutex);
	port = ipc_port_copy_send(arcade_upcall_port);
	/*
	 * if the arcade_upcall_port was inactive, "port" will be IP_DEAD.
	 * Otherwise, it holds a send right to the arcade_upcall_port.
	 */

	while (!IP_VALID(port)) {
		/*
		 * Refresh the arcade upcall port. If that gives up,
		 * give up ourselves.
		 */
		kr = arcade_upcall_refresh(deadline);
		if (kr != KERN_SUCCESS) {
			lck_mtx_unlock(&arcade_upcall_mutex);
			goto fail;
		}
		port = ipc_port_copy_send(arcade_upcall_port);
	}
	lck_mtx_unlock(&arcade_upcall_mutex);

	/* We have an upcall port send right */

	/* Gather the data we need to send in the upcall */
	off_t offset;
	struct proc *p = current_proc();
	char *path;
	vm_map_copy_t copy;

	kr = kmem_alloc(ipc_kernel_map, (vm_offset_t *)&path, MAXPATHLEN, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		ipc_port_release_send(port);
		return;
	}
	bzero(path, MAXPATHLEN);
	retval = proc_pidpathinfo_internal(p, 0, path, MAXPATHLEN, NULL);
	assert(!retval);
	kr = vm_map_unwire(ipc_kernel_map,
	    vm_map_trunc_page((vm_offset_t)path, VM_MAP_PAGE_MASK(ipc_kernel_map)),
	    vm_map_round_page((vm_offset_t)path + MAXPATHLEN, VM_MAP_PAGE_MASK(ipc_kernel_map)),
	    FALSE);
	assert(kr == KERN_SUCCESS);
	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)path, MAXPATHLEN, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	offset = proc_getexecutableoffset(p);

	/* MAKE THE UPCALL */
	boolean_t should_kill = TRUE;
	kr = __MAKING_UPCALL_TO_ARCADE_VALIDATION_SERVICE__(port, copy, MAXPATHLEN, offset, &should_kill);
	ipc_port_release_send(port);

	switch (kr) {
	case MACH_SEND_INVALID_DEST:
		vm_map_copy_discard(copy);
		OS_FALLTHROUGH;
	case MIG_SERVER_DIED:
		goto restart;
	case KERN_SUCCESS:
		if (should_kill == TRUE) {
			/*
			 * Invalid subscription. UI already presented as to why it did not
			 * launch.
			 */
			task_terminate_internal(current_task());
		}
		break;
	default:
fail:
		/*
		 * Failure of the subscription validation mechanism, not a rejection.
		 * for a missing subscription. There will be no indication WHY this
		 * process didn't launch. We might want this to be an exit_with_reason()
		 * in the future.
		 */
		task_terminate_internal(current_task());
		break;
	}
}
