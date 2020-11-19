/*
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
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

#ifndef _KERN_MACH_FILTER_H_
#define _KERN_MACH_FILTER_H_

#if KERNEL_PRIVATE

#include <sys/cdefs.h>
#include <mach/message.h>

/* Sandbox-specific calls for task based message filtering */
typedef boolean_t (*mach_msg_fetch_filter_policy_cbfunc_t) (struct task *task, void *portlabel,
    mach_msg_id_t msgid, mach_msg_filter_id *fpid);

struct mach_msg_filter_callbacks {
	unsigned int version;
	const mach_msg_fetch_filter_policy_cbfunc_t fetch_filter_policy;
};

#define MACH_MSG_FILTER_CALLBACKS_VERSION_0 (0) /* up-to fetch_filter_policy */
#define MACH_MSG_FILTER_CALLBACKS_CURRENT MACH_MSG_FILTER_CALLBACKS_VERSION_0

__BEGIN_DECLS

int mach_msg_filter_register_callback(const struct mach_msg_filter_callbacks *callbacks);

__END_DECLS

#endif /* KERNEL_PRIVATE */

#if XNU_KERNEL_PRIVATE
boolean_t mach_msg_fetch_filter_policy(void *portlabel, mach_msg_id_t msgh_id, mach_msg_filter_id *fid);
#endif /* XNU_KERNEL_PRIVATE */

#endif /* _KERN_MACH_FILTER_H_ */
