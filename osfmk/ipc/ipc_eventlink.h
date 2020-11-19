/*
 * Copyright (c) 2000-2019 Apple Computer, Inc. All rights reserved.
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

#ifndef _IPC_IPC_EVENTLINK_H_
#define _IPC_IPC_EVENTLINK_H_

#ifdef MACH_KERNEL_PRIVATE

#include <mach/std_types.h>
#include <mach/port.h>
#include <mach/mach_eventlink_types.h>
#include <mach_assert.h>
#include <mach_debug.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>

#include <kern/assert.h>
#include <kern/kern_types.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_port.h>
#include <kern/waitq.h>
#include <os/refcnt.h>

__options_decl(ipc_eventlink_option_t, uint64_t, {
	IPC_EVENTLINK_NONE          = 0,
	IPC_EVENTLINK_NO_WAIT       = 0x1,
	IPC_EVENTLINK_HANDOFF       = 0x2,
	IPC_EVENTLINK_FORCE_WAKEUP  = 0x4,
});

__options_decl(ipc_eventlink_type_t, uint8_t, {
	IPC_EVENTLINK_TYPE_NO_COPYIN         = 0x1,
	IPC_EVENTLINK_TYPE_WITH_COPYIN       = 0x2,
});

#define THREAD_ASSOCIATE_WILD ((struct thread *) -1)

struct ipc_eventlink_base;

struct ipc_eventlink {
	ipc_port_t                  el_port;             /* Port for eventlink object */
	thread_t                    el_thread;           /* Thread associated with eventlink object */
	struct ipc_eventlink_base   *el_base;            /* eventlink base struct */
	uint64_t                    el_sync_counter;     /* Sync counter for wait/ signal */
	uint64_t                    el_wait_counter;     /* Counter passed in eventlink wait */
};

struct ipc_eventlink_base {
	struct ipc_eventlink          elb_eventlink[2];  /* Eventlink pair */
	struct waitq                  elb_waitq;         /* waitq */
	os_refcnt_t                   elb_ref_count;     /* ref count for eventlink */
	uint32_t                      elb_active:1,
	    elb_type:8;
#if DEVELOPMENT || DEBUG
	queue_chain_t                 elb_global_elm;    /* Global list of eventlinks */
#endif
};

#define IPC_EVENTLINK_BASE_NULL ((struct ipc_eventlink_base *)NULL)
#define ipc_eventlink_active(eventlink) ((eventlink)->el_base->elb_active == TRUE)

#define eventlink_remote_side(eventlink) ((eventlink) == &((eventlink)->el_base->elb_eventlink[0]) ? \
	&((eventlink)->el_base->elb_eventlink[1]) : &((eventlink)->el_base->elb_eventlink[0]))

#define ipc_eventlink_lock(eventlink)     waitq_lock(&(eventlink)->el_base->elb_waitq)
#define ipc_eventlink_unlock(eventlink)   waitq_unlock(&(eventlink)->el_base->elb_waitq)

void ipc_eventlink_init(void);

/* Function declarations */
void
ipc_eventlink_init(void);

struct ipc_eventlink *
convert_port_to_eventlink(
	mach_port_t             port);

void
ipc_eventlink_reference(
	struct ipc_eventlink *ipc_eventlink);

void
ipc_eventlink_deallocate(
	struct ipc_eventlink *ipc_eventlink);

void
ipc_eventlink_notify(
	mach_msg_header_t *msg);

uint64_t
    mach_eventlink_signal_trap(
	mach_port_name_t port,
	uint64_t         signal_count __unused);

uint64_t
mach_eventlink_wait_until_trap(
	mach_port_name_t                    eventlink_port,
	uint64_t                            wait_count,
	mach_eventlink_signal_wait_option_t option,
	kern_clock_id_t                     clock_id,
	uint64_t                            deadline);

uint64_t
    mach_eventlink_signal_wait_until_trap(
	mach_port_name_t                    eventlink_port,
	uint64_t                            wait_count,
	uint64_t                            signal_count __unused,
	mach_eventlink_signal_wait_option_t option,
	kern_clock_id_t                     clock_id,
	uint64_t                            deadline);

#endif /* MACH_KERNEL_PRIVATE */
#endif /* _IPC_IPC_EVENTLINK_H_ */
