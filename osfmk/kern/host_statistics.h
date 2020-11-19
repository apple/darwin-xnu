/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 *	kern/host_statistics.h
 *
 *	Definitions for host VM/event statistics data structures.
 *
 */

#ifndef _KERN_HOST_STATISTICS_H_
#define _KERN_HOST_STATISTICS_H_

#include <libkern/OSAtomic.h>
#include <mach/vm_statistics.h>
#include <kern/percpu.h>
#include <os/atomic_private.h>

extern
uint64_t get_pages_grabbed_count(void);

PERCPU_DECL(vm_statistics64_data_t, vm_stat);
PERCPU_DECL(uint64_t, vm_page_grab_count);

#define VM_STAT_INCR(event)                                             \
MACRO_BEGIN                                                             \
	os_atomic_inc(&PERCPU_GET(vm_stat)->event, relaxed);            \
MACRO_END

#define VM_STAT_INCR_BY(event, amount)                                  \
MACRO_BEGIN                                                             \
	os_atomic_add(&PERCPU_GET(vm_stat)->event, amount, relaxed);    \
MACRO_END

#endif  /* _KERN_HOST_STATISTICS_H_ */
