/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#ifndef _KERN_EXCEPTION_H_
#define _KERN_EXCEPTION_H_

#include <mach/mach_types.h>
#include <mach/thread_status.h>
#include <mach/exception_types.h>
#include <kern/kern_types.h>

/*
 * Common storage for exception actions.
 * There are arrays of these maintained at the activation, task, and host.
 */
struct exception_action {
	struct ipc_port		*port;		/* exception port */
	thread_state_flavor_t	flavor;		/* state flavor to send */
	exception_behavior_t	behavior;	/* exception type to raise */
};

/* Make an up-call to a thread's exception server */
extern void exception_triage(
	exception_type_t	exception,
	exception_data_t	code,
	mach_msg_type_number_t	codeCnt);

/* Notify system performance monitor */
extern kern_return_t sys_perf_notify(struct task *task,
	exception_data_t	code,
	mach_msg_type_number_t  codeCnt);

#endif	/* _KERN_EXCEPTION_H_ */
