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

#include <kern/ux_handler.h>
#include <sys/ux_exception.h>

#include <mach/exception.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/mach_port.h>
#include <mach/mig_errors.h>

#include <kern/thread.h>
#include <kern/task.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_tt.h>

#include <ipc/ipc_port.h>

#include <mach/host_priv.h>
#include <kern/host.h>

#include <mach/exc_server.h>
#include <mach/mach_exc_server.h>

#include <libkern/section_keywords.h>

/*
 * Mach kobject port to reflect Mach exceptions into Unix signals.
 *
 * This is the default Mach exception handler for initproc, which
 * then filters to all subprocesses as the host level exception handler for
 * most Mach exceptions.
 */

static const void                      *ux_handler_kobject    = NULL;
SECURITY_READ_ONLY_LATE(ipc_port_t)     ux_handler_port       = IP_NULL;

/*
 * init is called early in Mach initialization
 * when we can initialize read-only memory
 */
void
ux_handler_init(void)
{
	ux_handler_port = ipc_kobject_alloc_port((ipc_kobject_t)&ux_handler_kobject,
	    IKOT_UX_HANDLER, IPC_KOBJECT_ALLOC_NONE);
}

/*
 * setup is called late in BSD initialization from initproc's context
 * so the MAC hook goo inside host_set_exception_ports will be able to
 * set up labels without falling over.
 */
void
ux_handler_setup(void)
{
	ipc_port_t ux_handler_send_right = ipc_port_make_send(ux_handler_port);

	if (!IP_VALID(ux_handler_send_right)) {
		panic("Couldn't allocate send right for ux_handler_port!\n");
	}

	kern_return_t kr = KERN_SUCCESS;

	/*
	 * Consumes 1 send right.
	 *
	 * Instruments uses the RPC_ALERT port, so don't register for that.
	 */
	kr = host_set_exception_ports(host_priv_self(),
	    EXC_MASK_ALL & ~(EXC_MASK_RPC_ALERT),
	    ux_handler_send_right,
	    EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
	    0);

	if (kr != KERN_SUCCESS) {
		panic("host_set_exception_ports failed to set ux_handler! %d", kr);
	}
}

/*
 * Is this port the ux_handler?
 * If so, it's safe to send an exception without checking labels.
 */
boolean_t
is_ux_handler_port(mach_port_t port)
{
	if (ux_handler_port == port) {
		return TRUE;
	} else {
		return FALSE;
	}
}

kern_return_t
catch_mach_exception_raise(
	mach_port_t                  exception_port,
	mach_port_t                  thread_port,
	mach_port_t                  task_port,
	exception_type_t             exception,
	mach_exception_data_t        code,
	__unused mach_msg_type_number_t       codeCnt)
{
	if (exception_port != ux_handler_port) {
		return KERN_FAILURE;
	}

	kern_return_t kr = KERN_SUCCESS;

	thread_t    target_thread   = THREAD_NULL;
	task_t      target_task     = TASK_NULL;

	if ((target_thread = convert_port_to_thread(thread_port)) == THREAD_NULL) {
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}

	if ((target_task = convert_port_to_task(task_port)) == TASK_NULL) {
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}

	kr = handle_ux_exception(target_thread, exception, code[0], code[1]);

out:
	if (kr == KERN_SUCCESS) {
		/*
		 * Following the MIG 'consume on success' protocol,
		 * consume references to the port arguments.
		 * (but NOT the exception_port, as the first argument is borrowed)
		 *
		 * If we return non-success, the kobject server will eat the port
		 * references for us.
		 */

		ipc_port_release_send(thread_port);
		ipc_port_release_send(task_port);
	}

	thread_deallocate(target_thread);
	task_deallocate(target_task);

	return kr;
}

kern_return_t
catch_exception_raise(
	mach_port_t               exception_port,
	mach_port_t               thread,
	mach_port_t               task,
	exception_type_t          exception,
	exception_data_t          code,
	mach_msg_type_number_t    codeCnt)
{
	if (exception_port != ux_handler_port) {
		return KERN_FAILURE;
	}

	mach_exception_data_type_t big_code[EXCEPTION_CODE_MAX] = {
		[0] = code[0],
		[1] = code[1],
	};

	return catch_mach_exception_raise(exception_port,
	           thread,
	           task,
	           exception,
	           big_code,
	           codeCnt);
}

kern_return_t
catch_exception_raise_state(
	__unused mach_port_t                 exception_port,
	__unused exception_type_t            exception,
	__unused const exception_data_t      code,
	__unused mach_msg_type_number_t      codeCnt,
	__unused int                        *flavor,
	__unused const thread_state_t        old_state,
	__unused mach_msg_type_number_t      old_stateCnt,
	__unused thread_state_t              new_state,
	__unused mach_msg_type_number_t     *new_stateCnt)
{
	return KERN_INVALID_ARGUMENT;
}

kern_return_t
catch_mach_exception_raise_state(
	__unused mach_port_t                    exception_port,
	__unused exception_type_t               exception,
	__unused const mach_exception_data_t    code,
	__unused mach_msg_type_number_t         codeCnt,
	__unused int                           *flavor,
	__unused const thread_state_t           old_state,
	__unused mach_msg_type_number_t         old_stateCnt,
	__unused thread_state_t                 new_state,
	__unused mach_msg_type_number_t        *new_stateCnt)
{
	return KERN_INVALID_ARGUMENT;
}

kern_return_t
catch_exception_raise_state_identity(
	__unused mach_port_t                exception_port,
	__unused mach_port_t                thread,
	__unused mach_port_t                task,
	__unused exception_type_t           exception,
	__unused exception_data_t           code,
	__unused mach_msg_type_number_t     codeCnt,
	__unused int                       *flavor,
	__unused thread_state_t             old_state,
	__unused mach_msg_type_number_t     old_stateCnt,
	__unused thread_state_t             new_state,
	__unused mach_msg_type_number_t    *new_stateCnt)
{
	return KERN_INVALID_ARGUMENT;
}

kern_return_t
catch_mach_exception_raise_state_identity(
	__unused mach_port_t                   exception_port,
	__unused mach_port_t                   thread,
	__unused mach_port_t                   task,
	__unused exception_type_t              exception,
	__unused mach_exception_data_t         code,
	__unused mach_msg_type_number_t        codeCnt,
	__unused int                          *flavor,
	__unused thread_state_t                old_state,
	__unused mach_msg_type_number_t        old_stateCnt,
	__unused thread_state_t                new_state,
	__unused mach_msg_type_number_t       *new_stateCnt)
{
	return KERN_INVALID_ARGUMENT;
}
