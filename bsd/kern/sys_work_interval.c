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
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kernel_types.h>
#include <sys/sysproto.h>
#include <sys/priv.h>
#include <sys/work_interval.h>
#include <kern/sched_prim.h>
#include <kern/thread.h>
#include <kern/policy_internal.h>

#include <libkern/libkern.h>

int
work_interval_ctl(__unused proc_t p, struct work_interval_ctl_args *uap, __unused int32_t *retval)
{
	uint32_t	operation = uap->operation;
	int			error = 0;
	kern_return_t	kret = KERN_SUCCESS;
	uint64_t	work_interval_id;
	struct work_interval_notification	notification;

	switch (operation) {
		case WORK_INTERVAL_OPERATION_CREATE:
			if (uap->arg == USER_ADDR_NULL || uap->work_interval_id != 0) {
				return EINVAL;
			}
			if (uap->len < sizeof(work_interval_id)) {
				return ERANGE;
			}

			/*
			 * Privilege check performed up-front, and then the work
			 * ID is allocated for use by the thread
			 */
			error = priv_check_cred(kauth_cred_get(), PRIV_WORK_INTERVAL, 0);
			if (error) {
				return (error);
			}

			kret = thread_policy_create_work_interval(current_thread(),
													  &work_interval_id);
			if (kret == KERN_SUCCESS) {
				error = copyout(&work_interval_id, uap->arg, sizeof(work_interval_id));
			} else {
				error = EINVAL;
			}

			break;
		case WORK_INTERVAL_OPERATION_DESTROY:
			if (uap->arg != USER_ADDR_NULL || uap->work_interval_id == 0) {
				return EINVAL;
			}

			/*
			 * No privilege check, we assume a previous WORK_INTERVAL_OPERATION_CREATE
			 * operation would have allocated a work interval ID for the current
			 * thread, which the scheduler will validate.
			 */
			kret = thread_policy_destroy_work_interval(current_thread(),
													   uap->work_interval_id);
			if (kret != KERN_SUCCESS) {
				error = EINVAL;
			}

			break;
		case WORK_INTERVAL_OPERATION_NOTIFY:
			if (uap->arg == USER_ADDR_NULL || uap->work_interval_id == 0) {
				return EINVAL;
			}
			if (uap->len < sizeof(notification)) {
				return EINVAL;
			}

			/*
			 * No privilege check, we assume a previous WORK_INTERVAL_OPERATION_CREATE
			 * operation would have allocated a work interval ID for the current
			 * thread, which the scheduler will validate.
			 */
			error = copyin(uap->arg, &notification, sizeof(notification));
			if (error) {
				break;
			}

			kret = sched_work_interval_notify(current_thread(),
											  uap->work_interval_id,
											  notification.start,
											  notification.finish,
											  notification.deadline,
											  notification.next_start,
											  notification.flags);
			if (kret != KERN_SUCCESS) {
				error = EINVAL;
				break;
			}

			break;
		default:
			error = ENOTSUP;
			break;
	}

	return (error);
}
