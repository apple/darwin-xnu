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
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/mach_types.h>
#include <ipc/ipc_port.h>

#include <mach/sysdiagnose_notification.h>

#include <kern/misc_protos.h>
#include <kern/host.h>

#include <sys/kdebug.h>

extern kern_return_t sysdiagnose_notify_user(uint32_t);

/*
 * If userland has registered a port for sysdiagnose notifications, send one now.
 */
kern_return_t
sysdiagnose_notify_user(uint32_t keycode)
{
	mach_port_t user_port;
	kern_return_t kr;

	kr = host_get_sysdiagnose_port(host_priv_self(), &user_port);
	if ((kr != KERN_SUCCESS) || !IPC_PORT_VALID(user_port)) {
		return kr;
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SYSDIAGNOSE, SYSDIAGNOSE_NOTIFY_USER) | DBG_FUNC_START, 0, 0, 0, 0, 0);

	kr = send_sysdiagnose_notification_with_audit_token(user_port, keycode);
	ipc_port_release_send(user_port);
	return kr;
}
