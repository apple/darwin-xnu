/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/task.h>
#include <kern/machine.h>
#include <kern/coalition.h>
#include <sys/errno.h>
#include <kern/queue.h>
#include <kern/locks.h>
#include <kern/thread_group.h>
#include <kern/sched_clutch.h>


#if CONFIG_EMBEDDED
void
thread_group_join_io_storage(void)
{
}

void
sched_perfcontrol_thread_group_recommend(void *machine_data __unused, cluster_type_t new_recommendation __unused)
{
}
#endif /* CONFIG_EMBEDDED */

