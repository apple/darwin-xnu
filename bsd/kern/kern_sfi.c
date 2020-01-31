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
 *
 */

#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sfi.h>
#include <libkern/libkern.h>
#include <mach/mach_time.h>
#include <pexpert/pexpert.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/sysproto.h>
#include <sys/sfi.h>
#include <sys/kdebug.h>
#include <sys/priv.h>
#include <kern/policy_internal.h>

/*
 * This file provides the syscall-based configuration facility
 * for Selective Forced Idle (SFI). Input arguments have basic checking
 * applied here, although more specific semantic checking is done in
 * osfmk/kern/sfi.c. All copyin()/copyout() operations are performed
 * in this source file.
 */

#define SFI_DEBUG 0

#if SFI_DEBUG
#define dprintf(...) printf(__VA_ARGS__)
#else
#define dprintf(...) do { } while(0)
#endif

static int proc_apply_sfi_managed(proc_t p, void * arg);

int
sfi_ctl(struct proc *p __unused, struct sfi_ctl_args *uap, int32_t *retval __unused)
{
	uint32_t        operation = uap->operation;
	int                     error = 0;
	kern_return_t   kret = KERN_SUCCESS;
	uint64_t        out_time = 0;

	switch (operation) {
	case SFI_CTL_OPERATION_SFI_SET_WINDOW:
		if (uap->out_time != USER_ADDR_NULL) {
			return EINVAL;
		}
		if (uap->sfi_class != SFI_CLASS_UNSPECIFIED) {
			return EINVAL;
		}

		error = priv_check_cred(kauth_cred_get(), PRIV_SELECTIVE_FORCED_IDLE, 0);
		if (error) {
			dprintf("%s failed privilege check for sfi_ctl: %d\n", p->p_comm, error);
			return error;
		} else {
			dprintf("%s succeeded privilege check for sfi_ctl\n", p->p_comm);
		}

		if (uap->time == 0) {
			/* actually a cancel */
			kret = sfi_window_cancel();
		} else {
			kret = sfi_set_window(uap->time);
		}

		if (kret) {
			error = EINVAL;
		}

		break;
	case SFI_CTL_OPERATION_SFI_GET_WINDOW:
		if (uap->time != 0) {
			return EINVAL;
		}
		if (uap->sfi_class != SFI_CLASS_UNSPECIFIED) {
			return EINVAL;
		}

		kret = sfi_get_window(&out_time);
		if (kret == KERN_SUCCESS) {
			error = copyout(&out_time, uap->out_time, sizeof(out_time));
		} else {
			error = EINVAL;
		}

		break;
	case SFI_CTL_OPERATION_SET_CLASS_OFFTIME:
		if (uap->out_time != USER_ADDR_NULL) {
			return EINVAL;
		}

		error = priv_check_cred(kauth_cred_get(), PRIV_SELECTIVE_FORCED_IDLE, 0);
		if (error) {
			dprintf("%s failed privilege check for sfi_ctl: %d\n", p->p_comm, error);
			return error;
		} else {
			dprintf("%s succeeded privilege check for sfi_ctl\n", p->p_comm);
		}

		if (uap->time == 0) {
			/* actually a cancel */
			kret = sfi_class_offtime_cancel(uap->sfi_class);
		} else {
			kret = sfi_set_class_offtime(uap->sfi_class, uap->time);
		}

		if (kret) {
			error = EINVAL;
		}

		break;
	case SFI_CTL_OPERATION_GET_CLASS_OFFTIME:
		if (uap->time != 0) {
			return EINVAL;
		}

		kret = sfi_get_class_offtime(uap->sfi_class, &out_time);
		if (kret == KERN_SUCCESS) {
			error = copyout(&out_time, uap->out_time, sizeof(out_time));
		} else {
			error = EINVAL;
		}

		break;
	default:
		error = ENOTSUP;
		break;
	}

	return error;
}

static int
proc_apply_sfi_managed(proc_t p, void * arg)
{
	uint32_t flags = *(uint32_t *)arg;
	pid_t pid = p->p_pid;
	boolean_t managed_enabled = (flags == SFI_PROCESS_SET_MANAGED)? TRUE : FALSE;

	if (pid == 0) {         /* ignore setting on kernproc */
		return PROC_RETURNED;
	}

	if (managed_enabled) {
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_PID_SET_MANAGED) | DBG_FUNC_NONE, pid, 0, 0, 0, 0);
	} else {
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_PID_CLEAR_MANAGED) | DBG_FUNC_NONE, pid, 0, 0, 0, 0);
	}

	proc_set_task_policy(p->task,
	    TASK_POLICY_ATTRIBUTE, TASK_POLICY_SFI_MANAGED,
	    managed_enabled ? TASK_POLICY_ENABLE : TASK_POLICY_DISABLE);

	return PROC_RETURNED;
}

int
sfi_pidctl(struct proc *p __unused, struct sfi_pidctl_args *uap, int32_t *retval __unused)
{
	uint32_t        operation = uap->operation;
	pid_t           pid = uap->pid;
	int                     error = 0;
	uint32_t        out_flags = 0;
	boolean_t       managed_enabled;
	proc_t          targetp;

	switch (operation) {
	case SFI_PIDCTL_OPERATION_PID_SET_FLAGS:
		if (uap->out_sfi_flags != USER_ADDR_NULL
		    || !(uap->sfi_flags & SFI_PROCESS_SET_MANAGED_MASK)
		    || uap->sfi_flags == SFI_PROCESS_SET_MANAGED_MASK) {
			return EINVAL;
		}

		error = priv_check_cred(kauth_cred_get(), PRIV_SELECTIVE_FORCED_IDLE, 0);
		if (error) {
			dprintf("%s failed privilege check for sfi_pidctl: %d\n", p->p_comm, error);
			return error;
		} else {
			dprintf("%s succeeded privilege check for sfi_pidctl\n", p->p_comm);
		}

		if (uap->pid == 0) {
			/* only allow SFI_PROCESS_SET_UNMANAGED for pid 0 */
			if (uap->sfi_flags != SFI_PROCESS_SET_UNMANAGED) {
				return EINVAL;
			}

			proc_iterate(PROC_ALLPROCLIST, proc_apply_sfi_managed, (void *)&uap->sfi_flags, NULL, NULL);
			break;
		}

		targetp = proc_find(pid);
		if (!targetp) {
			error = ESRCH;
			break;
		}

		proc_apply_sfi_managed(targetp, (void *)&uap->sfi_flags);

		proc_rele(targetp);

		break;
	case SFI_PIDCTL_OPERATION_PID_GET_FLAGS:
		if (uap->sfi_flags != 0) {
			return EINVAL;
		}
		if (uap->pid == 0) {
			return EINVAL;
		}

		targetp = proc_find(pid);
		if (!targetp) {
			error = ESRCH;
			break;
		}

		managed_enabled = proc_get_task_policy(targetp->task, TASK_POLICY_ATTRIBUTE, TASK_POLICY_SFI_MANAGED);

		proc_rele(targetp);

		out_flags = managed_enabled ? SFI_PROCESS_SET_MANAGED : SFI_PROCESS_SET_UNMANAGED;

		error = copyout(&out_flags, uap->out_sfi_flags, sizeof(out_flags));

		break;
	default:
		error = ENOTSUP;
		break;
	}

	return error;
}
