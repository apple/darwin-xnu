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

#ifndef _KERN_SUID_CRED_H
#define _KERN_SUID_CRED_H

#if XNU_KERNEL_PRIVATE

#include <kern/kern_types.h>
#include <mach/mach_types.h>

struct vnode;

extern ipc_port_t convert_suid_cred_to_port(suid_cred_t);

extern void suid_cred_notify(mach_msg_header_t *msg);

extern int suid_cred_verify(ipc_port_t port, struct vnode *vnode, uint32_t *uid);

extern void suid_cred_destroy(ipc_port_t port);

#endif /* XNU_KERNEL_PRIVATE */

#endif /* _KERN_SUID_CRED_H */
