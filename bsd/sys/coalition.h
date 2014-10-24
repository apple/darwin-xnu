/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#ifndef _SYS_COALITION_H_
#define _SYS_COALITION_H_

#include <sys/cdefs.h>
#include <Availability.h>
#include <stdint.h>
#include <sys/types.h>

__BEGIN_DECLS

#ifndef KERNEL
/* Userspace syscall prototypes */

/* Syscalls */
int coalition_create(uint64_t *cid_out, uint32_t flags);
int coalition_terminate(uint64_t cid, uint32_t flags);
int coalition_reap(uint64_t cid, uint32_t flags);

/* This struct is also defined in osfmk/kern/coalition.h. Keep in sync. */
struct coalition_resource_usage {
	uint64_t tasks_started;
	uint64_t tasks_exited;
	uint64_t time_nonempty;
	uint64_t cpu_time;
	uint64_t interrupt_wakeups;
	uint64_t platform_idle_wakeups;
	uint64_t bytesread;
	uint64_t byteswritten;
	uint64_t gpu_time;
};

/* Wrappers around __coalition_info syscall (with proper struct types) */
int coalition_info_resource_usage(uint64_t cid, struct coalition_resource_usage *cru, size_t sz);

#endif /* KERNEL */

/* Flags shared by userspace and xnu */

#define COALITION_CREATE_FLAG_PRIVILEGED ((uint32_t)0x1)

#define COALITION_CREATE_FLAG_MASK ((uint32_t)0x1)

#ifdef PRIVATE
/* Flavors shared by only xnu + Libsyscall */

/* Syscall flavors */
#define COALITION_OP_CREATE 1
#define COALITION_OP_TERMINATE 2
#define COALITION_OP_REAP 3

/* coalition_info flavors */
#define COALITION_INFO_RESOURCE_USAGE 1

#endif /* PRIVATE */

__END_DECLS

#endif /* _SYS_COALITION_H_ */
