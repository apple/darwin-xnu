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

#include <mach/mach_types.h>
#include <mach/host_special_ports.h>
#include <mach/host_priv.h>
#include <ipc/ipc_port.h>
#include <kern/host.h>

#include <mach/ktrace_background.h>

kern_return_t ktrace_background_available_notify_user(void);

/*
 * If user space has registered for background notifications, send one.
 */
kern_return_t
ktrace_background_available_notify_user(void)
{
	mach_port_t user_port;
	kern_return_t kr;

	kr = host_get_ktrace_background_port(host_priv_self(), &user_port);
	if (kr != KERN_SUCCESS || !IPC_PORT_VALID(user_port)) {
		return KERN_FAILURE;
	}

	kr = send_ktrace_background_available(user_port);
	ipc_port_release_send(user_port);
	return kr;
}
