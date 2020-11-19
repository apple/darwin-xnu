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
#include <kern/task.h>
#include <kern/work_interval.h>

#include <libkern/libkern.h>

int
work_interval_ctl(__unused proc_t p, struct work_interval_ctl_args *uap,
    __unused int32_t *retval)
{
	uint32_t        operation = uap->operation;
	int             error = 0;
	kern_return_t   kret = KERN_SUCCESS;
	struct work_interval_notification notification;

	struct work_interval_create_params create_params;
	struct kern_work_interval_create_args create_args;
	mach_port_name_t port_name;

	switch (operation) {
	case WORK_INTERVAL_OPERATION_CREATE:
		return ENOTSUP;
	case WORK_INTERVAL_OPERATION_CREATE2:
		if (uap->arg == USER_ADDR_NULL || uap->work_interval_id != 0) {
			return EINVAL;
		}
		if (uap->len < sizeof(create_params)) {
			return EINVAL;
		}

		if ((error = copyin(uap->arg, &create_params, sizeof(create_params)))) {
			return error;
		}

		if ((error = priv_check_cred(kauth_cred_get(), PRIV_WORK_INTERVAL, 0)) != 0) {
			return error;
		}

		create_args = (struct kern_work_interval_create_args) {
			.wica_id            = create_params.wicp_id,
			.wica_port          = create_params.wicp_port,
			.wica_create_flags  = create_params.wicp_create_flags,
		};

		kret = kern_work_interval_create(current_thread(), &create_args);

		/* thread already has a work interval */
		if (kret == KERN_FAILURE) {
			return EALREADY;
		}

		/* port copyout failed */
		if (kret == KERN_RESOURCE_SHORTAGE) {
			return ENOMEM;
		}

		/* some other failure */
		if (kret != KERN_SUCCESS) {
			return EINVAL;
		}

		create_params = (struct work_interval_create_params) {
			.wicp_id = create_args.wica_id,
			.wicp_port = create_args.wica_port,
			.wicp_create_flags = create_args.wica_create_flags,
		};

		if ((error = copyout(&create_params, uap->arg, sizeof(create_params)))) {
			kern_work_interval_destroy(current_thread(), create_args.wica_id);
			return error;
		}
		break;
	case WORK_INTERVAL_OPERATION_GET_FLAGS:
		if (uap->arg == USER_ADDR_NULL || uap->len < sizeof(create_params)) {
			return EINVAL;
		}

		port_name = (mach_port_name_t) uap->work_interval_id;
		if (!MACH_PORT_VALID(port_name)) {
			return EINVAL;
		}

		create_params = (struct work_interval_create_params) {
			.wicp_port = port_name
		};

		kret = kern_work_interval_get_flags_from_port(port_name, &create_params.wicp_create_flags);
		if (kret != KERN_SUCCESS) {
			return EINVAL;
		}

		if ((error = copyout(&create_params, uap->arg, sizeof(create_params)))) {
			return error;
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
		kret = kern_work_interval_destroy(current_thread(), uap->work_interval_id);
		if (kret != KERN_SUCCESS) {
			return EINVAL;
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
		if ((error = copyin(uap->arg, &notification, sizeof(notification)))) {
			return error;
		}

		struct kern_work_interval_args kwi_args = {
			.work_interval_id   = uap->work_interval_id,
			.start              = notification.start,
			.finish             = notification.finish,
			.deadline           = notification.deadline,
			.next_start         = notification.next_start,
			.notify_flags       = notification.notify_flags,
			.create_flags       = notification.create_flags,
		};

		kret = kern_work_interval_notify(current_thread(), &kwi_args);
		if (kret != KERN_SUCCESS) {
			return EINVAL;
		}

		break;
	case WORK_INTERVAL_OPERATION_JOIN:
		if (uap->arg != USER_ADDR_NULL) {
			return EINVAL;
		}

		/*
		 * No privilege check, because the work interval port
		 * is a capability.
		 */
		kret = kern_work_interval_join(current_thread(),
		    (mach_port_name_t)uap->work_interval_id);
		if (kret != KERN_SUCCESS) {
			return EINVAL;
		}

		break;

	default:
		return ENOTSUP;
	}

	return error;
}
