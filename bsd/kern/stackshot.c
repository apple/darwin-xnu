/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
 *
 * @Apple_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <sys/errno.h>
#include <sys/kauth.h>
#include <sys/proc_internal.h>
#include <sys/stackshot.h>
#include <sys/sysproto.h>

/*
 * Stackshot system calls
 */

#if CONFIG_TELEMETRY
extern kern_return_t stack_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval);
#endif /* CONFIG_TELEMETRY */
extern kern_return_t kern_stack_snapshot_with_reason(char* reason);
extern kern_return_t kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config, size_t stackshot_config_size, boolean_t stackshot_from_user);

static int
stackshot_kern_return_to_bsd_error(kern_return_t kr)
{
	switch (kr) {
	case KERN_SUCCESS:
		return 0;
	case KERN_RESOURCE_SHORTAGE:
		/* could not allocate memory, or stackshot is actually bigger than
		 * SANE_TRACEBUF_SIZE */
		return ENOMEM;
	case KERN_INSUFFICIENT_BUFFER_SIZE:
	case KERN_NO_SPACE:
		/* ran out of buffer to write the stackshot.  Normally this error
		 * causes a larger buffer to be allocated in-kernel, rather than
		 * being returned to the user. */
		return ENOSPC;
	case KERN_NO_ACCESS:
		return EPERM;
	case KERN_MEMORY_PRESENT:
		return EEXIST;
	case KERN_NOT_SUPPORTED:
		return ENOTSUP;
	case KERN_NOT_IN_SET:
		/* requested existing buffer, but there isn't one. */
		return ENOENT;
	case KERN_ABORTED:
		/* kdp did not report an error, but also did not produce any data */
		return EINTR;
	case KERN_FAILURE:
		/* stackshot came across inconsistent data and needed to bail out */
		return EBUSY;
	case KERN_OPERATION_TIMED_OUT:
		/* debugger synchronization timed out */
		return ETIMEDOUT;
	default:
		return EINVAL;
	}
}

/*
 * stack_snapshot_with_config:	Obtains a coherent set of stack traces for specified threads on the sysem,
 *				tracing both kernel and user stacks where available. Allocates a buffer from the
 *				kernel and maps the buffer into the calling task's address space.
 *
 * Inputs:                      uap->stackshot_config_version - version of the stackshot config that is being passed
 *				uap->stackshot_config - pointer to the stackshot config
 *				uap->stackshot_config_size- size of the stackshot config being passed
 * Outputs:			EINVAL if there is a problem with the arguments
 *				EFAULT if we failed to copy in the arguments succesfully
 *				EPERM if the caller is not privileged
 *				ENOTSUP if the caller is passing a version of arguments that is not supported by the kernel
 *				(indicates libsyscall:kernel mismatch) or if the caller is requesting unsupported flags
 *				ENOENT if the caller is requesting an existing buffer that doesn't exist or if the
 *				requested PID isn't found
 *				ENOMEM if the kernel is unable to allocate enough memory to serve the request
 *				ENOSPC if there isn't enough space in the caller's address space to remap the buffer
 *				ESRCH if the target PID isn't found
 *				returns KERN_SUCCESS on success
 */
int
stack_snapshot_with_config(struct proc *p, struct stack_snapshot_with_config_args *uap, __unused int *retval)
{
	int error = 0;
	kern_return_t kr;

	if ((error = suser(kauth_cred_get(), &p->p_acflag))) {
		return error;
	}

	if ((void*)uap->stackshot_config == NULL) {
		return EINVAL;
	}

	switch (uap->stackshot_config_version) {
	case STACKSHOT_CONFIG_TYPE:
		if (uap->stackshot_config_size != sizeof(stackshot_config_t)) {
			return EINVAL;
		}
		stackshot_config_t config;
		error = copyin(uap->stackshot_config, &config, sizeof(stackshot_config_t));
		if (error != KERN_SUCCESS) {
			return EFAULT;
		}
		kr = kern_stack_snapshot_internal(uap->stackshot_config_version, &config, sizeof(stackshot_config_t), TRUE);
		return stackshot_kern_return_to_bsd_error(kr);
	default:
		return ENOTSUP;
	}
}

#if CONFIG_TELEMETRY
/*
 * microstackshot:	Catch all system call for microstackshot related operations, including
 *			enabling/disabling both global and windowed microstackshots as well
 *			as retrieving windowed or global stackshots and the boot profile.
 * Inputs:              uap->tracebuf - address of the user space destination
 *			buffer
 *			uap->tracebuf_size - size of the user space trace buffer
 *			uap->flags - various flags
 * Outputs:		EPERM if the caller is not privileged
 *			EINVAL if the supplied mss_args is NULL, mss_args.tracebuf is NULL or mss_args.tracebuf_size is not sane
 *			ENOMEM if we don't have enough memory to satisfy the request
 *			*retval contains the number of bytes traced, if successful
 *			and -1 otherwise.
 */
int
microstackshot(struct proc *p, struct microstackshot_args *uap, int32_t *retval)
{
	int error = 0;
	kern_return_t kr;

	if ((error = suser(kauth_cred_get(), &p->p_acflag))) {
		return error;
	}

	kr = stack_microstackshot(uap->tracebuf, uap->tracebuf_size, uap->flags, retval);
	return stackshot_kern_return_to_bsd_error(kr);
}
#endif /* CONFIG_TELEMETRY */

/*
 * kern_stack_snapshot_with_reason:	Obtains a coherent set of stack traces for specified threads on the sysem,
 *					tracing both kernel and user stacks where available. Allocates a buffer from the
 *					kernel and stores the address of this buffer.
 *
 * Inputs:                              reason - the reason for triggering a stackshot (unused at the moment, but in the
 *						future will be saved in the stackshot)
 * Outputs:				EINVAL/ENOTSUP if there is a problem with the arguments
 *					EPERM if the caller doesn't pass at least one KERNEL stackshot flag
 *					ENOMEM if the kernel is unable to allocate enough memory to serve the request
 *					ESRCH if the target PID isn't found
 *					returns KERN_SUCCESS on success
 */
int
kern_stack_snapshot_with_reason(__unused char *reason)
{
	stackshot_config_t config;
	kern_return_t kr;

	config.sc_pid = -1;
	config.sc_flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS | STACKSHOT_SAVE_IN_KERNEL_BUFFER |
	    STACKSHOT_KCDATA_FORMAT | STACKSHOT_ENABLE_UUID_FAULTING | STACKSHOT_THREAD_WAITINFO |
	    STACKSHOT_NO_IO_STATS);
	config.sc_delta_timestamp = 0;
	config.sc_out_buffer_addr = 0;
	config.sc_out_size_addr = 0;

	kr = kern_stack_snapshot_internal(STACKSHOT_CONFIG_TYPE, &config, sizeof(stackshot_config_t), FALSE);
	return stackshot_kern_return_to_bsd_error(kr);
}
