/*
 * Copyright (c) 2013 Apple Computer, Inc. All rights reserved.
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

#ifndef _KERN_COALITION_H_
#define _KERN_COALITION_H_

/* only kernel-private interfaces */
#ifdef XNU_KERNEL_PRIVATE
#include <mach/coalition.h>

#if CONFIG_COALITIONS

void coalitions_init(void);

/* These may return:
 * KERN_ALREADY_IN_SET	task is already in a coalition (maybe this one, maybe a different one)
 * KERN_TERMINATED	coalition is already terminated (so it may not adopt any more tasks)
 */
kern_return_t coalitions_adopt_task(coalition_t *coaltions, task_t task);
kern_return_t coalitions_adopt_init_task(task_t task);

/* Currently, no error conditions. If task is not already in a coalition,
 * KERN_SUCCESS is returned because removing it did not fail.
 */
kern_return_t coalitions_remove_task(task_t task);
void          task_release_coalitions(task_t task);

/*
 *
 */
kern_return_t coalitions_set_roles(coalition_t coalitions[COALITION_NUM_TYPES],
				   task_t task, int roles[COALITION_NUM_TYPES]);

uint64_t coalition_id(coalition_t coal);
void     task_coalition_ids(task_t task, uint64_t ids[COALITION_NUM_TYPES]);
void     task_coalition_roles(task_t task, int roles[COALITION_NUM_TYPES]);
int      coalition_type(coalition_t coal);

void     task_coalition_update_gpu_stats(task_t task, uint64_t gpu_ns_delta);
uint32_t task_coalition_adjust_focal_count(task_t task, int count);
uint32_t task_coalition_focal_count(task_t task);
uint32_t task_coalition_adjust_nonfocal_count(task_t task, int count);
uint32_t task_coalition_nonfocal_count(task_t task);

void coalition_for_each_task(coalition_t coal, void *ctx,
			     void (*callback)(coalition_t, void *, task_t));

/* Returns with a reference, or COALITION_NULL.
 * There is no coalition with id 0.
 */
coalition_t coalition_find_by_id(uint64_t coal_id);

/* Returns with a reference and an activation, or COALITION_NULL.
 * There is no coalition with id 0.
 */
coalition_t coalition_find_and_activate_by_id(uint64_t coal_id);

void coalition_remove_active(coalition_t coal);

void coalition_release(coalition_t coal);

/*
 * The following functions are to be used by the syscall wrapper
 * in bsd/kern/kern_proc.c, after it has verified the caller's privilege.
 */

/* This may return:
 * KERN_DEFAULT_SET	The default coalition, which contains the kernel, may
 *			not be terminated.
 * KERN_TERMINATED	The coalition was already reaped.
 * KERN_FAILURE		The coalition was not empty or has never been terminated.
 */
kern_return_t coalition_reap_internal(coalition_t coal);

/* This may return:
 * KERN_DEFAULT_SET	The default coalition, which contains the kernel, may
 *			not be terminated.
 * KERN_TERMINATED	The coalition was already terminated (or even reaped)
 * KERN_INVALID_NAME	The coalition was already reaped.
 */
kern_return_t coalition_request_terminate_internal(coalition_t coal);

/* This may return:
 * KERN_RESOURCE_SHORTAGE	Unable to allocate kernel resources for a
 *				new coalition.
 */
kern_return_t coalition_create_internal(int type, boolean_t privileged, coalition_t *out);

boolean_t coalition_is_privileged(coalition_t coal);
boolean_t task_is_in_privileged_coalition(task_t task, int type);

kern_return_t coalition_resource_usage_internal(coalition_t coal, struct coalition_resource_usage *cru_out);

/*
 * development/debug interfaces
 */
#if defined(DEVELOPMENT) || defined(DEBUG)
int coalition_should_notify(coalition_t coal);
void coalition_set_notify(coalition_t coal, int notify);
#endif

#else /* !CONFIG_COALITIONS */

static inline void task_coalition_update_gpu_stats(__unused task_t task,
						   __unused uint64_t gpu_ns_delta)
{
	return;
}

static inline uint32_t task_coalition_adjust_focal_count(__unused task_t task,
							 __unused int count)
{
	return 0;
}

static inline uint32_t task_coalition_adjust_nonfocal_count(__unused task_t task,
							    __unused int count)
{
	return 0;
}

static inline uint32_t task_coalition_focal_count(__unused task_t task)
{
	return 0;
}

static inline void coalition_for_each_task(__unused coalition_t coal,
					   __unused void *ctx,
					   __unused void (*callback)(coalition_t, void *, task_t))
{
	return;
}

#endif /* CONFIG_COALITIONS */
#endif /* XNU_KERNEL_PRIVATE */
#endif /* _KERN_COALITION_H */
