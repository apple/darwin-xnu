/*
 * Copyright (c) 2005-2016 Apple Computer, Inc. All rights reserved.
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
 * process policy syscall implementation
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/unistd.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/vm.h>
#include <sys/user.h>

#include <security/audit/audit.h>

#include <mach/machine.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/policy_internal.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/host_info.h>
#include <mach/task_info.h>
#include <mach/thread_info.h>
#include <mach/vm_region.h>

#include <sys/process_policy.h>
#include <sys/proc_info.h>
#include <sys/bsdtask_info.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <sys/msgbuf.h>

#include <machine/machine_routines.h>

#include <kern/ipc_misc.h>
#include <vm/vm_protos.h>

static int handle_lowresource(int scope, int action, int policy, int policy_subtype, user_addr_t attrp, proc_t proc, uint64_t target_threadid);
static int handle_cpuuse(int action, user_addr_t attrp, proc_t proc, uint64_t target_threadid);
static int handle_apptype(int scope, int action, int policy, int policy_subtype, user_addr_t attrp, proc_t proc, uint64_t target_threadid);
static int handle_boost(int scope, int action, int policy, int policy_subtype, user_addr_t attrp, proc_t proc, uint64_t target_threadid);

extern kern_return_t task_suspend(task_t);
extern kern_return_t task_resume(task_t);


/***************************** process_policy ********************/

/*
 *int process_policy(int scope, int action, int policy, int policy_subtype, 
 *                   proc_policy_attribute_t * attrp, pid_t target_pid, 
 *                   uint64_t target_threadid)
 *{ int process_policy(int scope, int action, int policy, int policy_subtype, 
 * user_addr_t attrp, pid_t target_pid, uint64_t target_threadid); }
 */

/* system call implementation */
int
process_policy(__unused struct proc *p, struct process_policy_args * uap, __unused int32_t *retval)
{
	int error = 0;
	int scope = uap->scope;
	int policy = uap->policy;
	int action = uap->action;
	int policy_subtype = uap->policy_subtype;
	user_addr_t attrp = uap->attrp;
	pid_t target_pid = uap->target_pid;
	uint64_t target_threadid = uap->target_threadid;
	proc_t target_proc = PROC_NULL;
	proc_t curp = current_proc();
	kauth_cred_t my_cred;

	if ((scope != PROC_POLICY_SCOPE_PROCESS) && (scope != PROC_POLICY_SCOPE_THREAD)) {
		return(EINVAL);
	}

	if (target_pid == 0 || target_pid == proc_selfpid())
		target_proc = proc_self();
	else
		target_proc = proc_find(target_pid);

	if (target_proc == PROC_NULL)
		return(ESRCH);

	my_cred = kauth_cred_get();

	/* 
	 * Resoure starvation control can be used by unpriv resource owner but priv at the time of ownership claim. This is
	 * checked in low resource handle routine. So bypass the checks here.
	 */
	if ((policy != PROC_POLICY_RESOURCE_STARVATION) && 
		(policy != PROC_POLICY_APPTYPE) && 
		(!kauth_cred_issuser(my_cred) && curp != p))
	{
		error = EPERM;
		goto out;
	}

#if CONFIG_MACF
	switch (policy) {
		case PROC_POLICY_BOOST:
		case PROC_POLICY_RESOURCE_USAGE:
			/* These policies do their own appropriate mac checks */
			break;
		default:
			error = mac_proc_check_sched(curp, target_proc);
			if (error) goto out;
			break;
	}
#endif /* CONFIG_MACF */

	switch(policy) {
		case PROC_POLICY_BACKGROUND:
			error = ENOTSUP;
			break;
		case PROC_POLICY_HARDWARE_ACCESS:
			error = ENOTSUP;
			break;
		case PROC_POLICY_RESOURCE_STARVATION:
			error = handle_lowresource(scope, action, policy, policy_subtype, attrp, target_proc, target_threadid);
			break;
		case PROC_POLICY_RESOURCE_USAGE:
			switch(policy_subtype) {
				case PROC_POLICY_RUSAGE_NONE:
				case PROC_POLICY_RUSAGE_WIREDMEM:
				case PROC_POLICY_RUSAGE_VIRTMEM:
				case PROC_POLICY_RUSAGE_DISK:
				case PROC_POLICY_RUSAGE_NETWORK:
				case PROC_POLICY_RUSAGE_POWER:
					error = ENOTSUP;
					goto out;
				default:
					error = EINVAL;
					goto out;
				case PROC_POLICY_RUSAGE_CPU:
					break;
			}

			error = handle_cpuuse(action, attrp, target_proc, target_threadid);
			break;
		case PROC_POLICY_APPTYPE:
			error = handle_apptype(scope, action, policy, policy_subtype, attrp, target_proc, target_threadid);
			break;
		case PROC_POLICY_BOOST:
			error = handle_boost(scope, action, policy, policy_subtype, attrp, target_proc, target_threadid);
			break;
		default:
			error = EINVAL;
			break;
	}

out:
	proc_rele(target_proc);
	return(error);
}

static int
handle_lowresource(__unused int scope, int action, __unused int policy, int policy_subtype, __unused user_addr_t attrp, proc_t proc, __unused uint64_t target_threadid)
{
	int error = 0;

	switch(policy_subtype) {
		case PROC_POLICY_RS_NONE:
		case PROC_POLICY_RS_VIRTUALMEM:
			break;
		default:
			return(EINVAL);	
	}
	
	if (action == PROC_POLICY_ACTION_RESTORE)
		error = proc_resetpcontrol(proc_pid(proc));
	else
		error = EINVAL;

	return(error);
}


static int 
handle_cpuuse(int action, user_addr_t attrp, proc_t proc, __unused uint64_t target_threadid)
{
	proc_policy_cpuusage_attr_t	cpuattr;
#if CONFIG_MACF
	proc_t 				curp = current_proc();
#endif
	int				entitled = FALSE;
	Boolean				canEnable = FALSE;
	uint64_t			interval = -1ULL;	
	int				error = 0;
	uint8_t				percentage;

#if CONFIG_MACF
	/*
	 * iOS only allows processes to override their own CPU usage monitor
	 * parameters if they have com.apple.private.kernel.override-cpumon.
	 *
	 * Until rdar://24799462 improves our scheme, we are also using the
	 * same entitlement to indicate which processes can resume monitoring
	 * when they otherwise wouldn't be able to.
	 */
	entitled = (mac_proc_check_cpumon(curp) == 0) ? TRUE : FALSE;
	canEnable = (entitled && action == PROC_POLICY_ACTION_ENABLE);

	if (!canEnable && curp != proc) {
		/* can the current process change scheduling parameters? */
		error = mac_proc_check_sched(curp, proc);
		if (error) 	return error;
	}
#endif

	// on macOS tasks can only set and clear their own CPU limits
	if ((action == PROC_POLICY_ACTION_APPLY || action == PROC_POLICY_ACTION_RESTORE)
	     && proc != current_proc()) {
		return (EPERM);
	}

	switch (action) {
		case PROC_POLICY_ACTION_GET: 
			error = proc_get_task_ruse_cpu(proc->task, &cpuattr.ppattr_cpu_attr,
                                        &percentage,
                                        &cpuattr.ppattr_cpu_attr_interval,
                                        &cpuattr.ppattr_cpu_attr_deadline);
			if (error == 0) {
				cpuattr.ppattr_cpu_percentage = percentage;
				cpuattr.ppattr_cpu_attr_interval /= NSEC_PER_SEC;
				error = copyout((proc_policy_cpuusage_attr_t *)&cpuattr, (user_addr_t)attrp, sizeof(proc_policy_cpuusage_attr_t));
			}
			break;

		case PROC_POLICY_ACTION_APPLY: 
		case PROC_POLICY_ACTION_SET: 
			error = copyin((user_addr_t)attrp, (proc_policy_cpuusage_attr_t *)&cpuattr, sizeof(proc_policy_cpuusage_attr_t));
			if (error != 0) {
				return (error);
			}

			/*
			 * The process_policy API uses seconds as the units for the interval,
			 * but the mach task policy SPI uses nanoseconds. Do the conversion,
			 * but preserve -1 as it has special meaning.
			 */
			if (cpuattr.ppattr_cpu_attr_interval != -1ULL) {
				interval = cpuattr.ppattr_cpu_attr_interval * NSEC_PER_SEC;
			} else {
				interval = -1ULL;
			}

			error = proc_set_task_ruse_cpu(proc->task, cpuattr.ppattr_cpu_attr, 
					cpuattr.ppattr_cpu_percentage, 
					interval, 
					cpuattr.ppattr_cpu_attr_deadline,
					entitled); 
			break;

		/* restore process to prior state */
		case PROC_POLICY_ACTION_RESTORE:
			error = proc_clear_task_ruse_cpu(proc->task, entitled);
			break;

		/* re-enable suspended monitor */
		case PROC_POLICY_ACTION_ENABLE:
			error = task_resume_cpumon(proc->task);
			break;

		case PROC_POLICY_ACTION_REMOVE:

		default:
			error = EINVAL;
			break;

	}
				
	return(error);
}


static int
handle_apptype(         int scope,
                        int action,
               __unused int policy,
                        int policy_subtype,
               __unused user_addr_t attrp,
                        proc_t target_proc,
               __unused uint64_t target_threadid)
{
	int error = 0;

	if (scope != PROC_POLICY_SCOPE_PROCESS)
		return (EINVAL);

	/* Temporary compatibility with old importance donation interface until libproc is moved to new boost calls */
	switch (policy_subtype) {
		case PROC_POLICY_IOS_DONATEIMP:
			if (action != PROC_POLICY_ACTION_ENABLE)
				return (EINVAL);
			if (target_proc != current_proc())
				return (EINVAL);
			
			/* PROCESS ENABLE APPTYPE DONATEIMP */
			task_importance_mark_donor(target_proc->task, TRUE);

			return(0);

		case PROC_POLICY_IOS_HOLDIMP:
			if (action != PROC_POLICY_ACTION_ENABLE)
				return (EINVAL);
			if (target_proc != current_proc())
				return (EINVAL);

			/* PROCESS ENABLE APPTYPE HOLDIMP */
			error = task_importance_hold_legacy_external_assertion(current_task(), 1);

			return(error);

		case PROC_POLICY_IOS_DROPIMP:
			if (action != PROC_POLICY_ACTION_ENABLE)
				return (EINVAL);
			if (target_proc != current_proc())
				return (EINVAL);

			/* PROCESS ENABLE APPTYPE DROPIMP */
			error = task_importance_drop_legacy_external_assertion(current_task(), 1);

			return(error);

		default:
			/* continue to TAL handling */
			break;
	}

	if (policy_subtype != PROC_POLICY_OSX_APPTYPE_TAL)
		return (EINVAL);

	/* need to be super user to do this */
	if (kauth_cred_issuser(kauth_cred_get()) == 0)
		return (EPERM);

	if (proc_task_is_tal(target_proc->task) == FALSE)
		return (EINVAL);

	switch (action) {
		case PROC_POLICY_ACTION_ENABLE:
			/* PROCESS ENABLE APPTYPE TAL */
			proc_set_task_policy(target_proc->task,
			                     TASK_POLICY_ATTRIBUTE, TASK_POLICY_TAL,
			                     TASK_POLICY_ENABLE);
			break;
		case PROC_POLICY_ACTION_DISABLE:
			/* PROCESS DISABLE APPTYPE TAL */
			proc_set_task_policy(target_proc->task,
			                     TASK_POLICY_ATTRIBUTE, TASK_POLICY_TAL,
			                     TASK_POLICY_DISABLE);
			break;
		default:
			return (EINVAL);
	}

	return(0);
}

static int
handle_boost(int scope,
             int action,
    __unused int policy,
             int policy_subtype,
    __unused user_addr_t attrp,
             proc_t target_proc,
    __unused uint64_t target_threadid)
{
	int error = 0;

	assert(policy == PROC_POLICY_BOOST);

	if (scope != PROC_POLICY_SCOPE_PROCESS)
		return (EINVAL);

	if (target_proc != current_proc())
		return (EINVAL);

	switch(policy_subtype) {
		case PROC_POLICY_IMP_IMPORTANT:
			if (task_is_importance_receiver_type(target_proc->task) == FALSE)
				return (EINVAL);

			switch (action) {
				case PROC_POLICY_ACTION_HOLD:
					/* PROCESS HOLD BOOST IMPORTANT */
					error = task_importance_hold_legacy_external_assertion(current_task(), 1);
					break;
				case PROC_POLICY_ACTION_DROP:
					/* PROCESS DROP BOOST IMPORTANT */
					error = task_importance_drop_legacy_external_assertion(current_task(), 1);
					break;
				default:
					error = (EINVAL);
					break;
			}
			break;

		case PROC_POLICY_IMP_DONATION:
#if CONFIG_MACF
			error = mac_proc_check_sched(current_proc(), target_proc);
			if (error) return error;
#endif
			switch (action) {
				case PROC_POLICY_ACTION_SET:
					/* PROCESS SET BOOST DONATION */
					task_importance_mark_donor(target_proc->task, TRUE);
					break;
				default:
					error = (EINVAL);
					break;
			}
			break;

		default:
			error = (EINVAL);
			break;
	}

	return(error);
}


/* 
 * KPI to determine if a pid is currently backgrounded. 
 * Returns ESRCH if pid cannot be found or has started exiting.
 * Returns EINVAL if state is NULL.
 * Sets *state to 1 if pid is backgrounded, and 0 otherwise.
 */
int
proc_pidbackgrounded(pid_t pid, uint32_t* state)
{
	proc_t target_proc = PROC_NULL;

	if (state == NULL)
		return(EINVAL);	

	target_proc = proc_find(pid);

	if (target_proc == PROC_NULL)
		return(ESRCH);

	if ( proc_get_effective_task_policy(target_proc->task, TASK_POLICY_DARWIN_BG) ) {
		*state = 1;
	} else {
		*state = 0;
	}

	proc_rele(target_proc);
	return (0);
}

/*
 * Get the darwin background state of the originator. If the current
 * process app type is App, then it is the originator, else if it is
 * a Daemon, then creator of the Resource Accounting attribute of
 * the current thread voucher is the originator of the work.
 */
int
proc_get_originatorbgstate(uint32_t *is_backgrounded)
{
	uint32_t bgstate;
	proc_t p = current_proc();
	uint32_t flagsp;
	kern_return_t kr;
	pid_t pid;
	int ret;
	thread_t thread = current_thread();

	bgstate = proc_get_effective_thread_policy(thread, TASK_POLICY_DARWIN_BG);
	
	/* If current thread or task backgrounded, return background */
	if (bgstate) {
		*is_backgrounded = 1;
		return 0;
	}

	/* Check if current process app type is App, then return foreground */
	proc_get_darwinbgstate(p->task, &flagsp);
	if ((flagsp & PROC_FLAG_APPLICATION) == PROC_FLAG_APPLICATION) {
		*is_backgrounded = 0;
		return 0;
	}

	/*
	 * Get the current voucher origin pid and it's bgstate.The pid
	 * returned here might not be valid or may have been recycled.
	 */
	kr = thread_get_current_voucher_origin_pid(&pid);
	if (kr != KERN_SUCCESS) {
		if (kr == KERN_INVALID_TASK)
			return ESRCH;
		else if (kr == KERN_INVALID_VALUE)
			return ENOATTR;
		else
			return EINVAL;
	}

	ret = proc_pidbackgrounded(pid, is_backgrounded);
	return ret;
}

int
proc_apply_resource_actions(void * bsdinfo, __unused int type, int action)
{
	proc_t p = (proc_t)bsdinfo;

	switch(action) {
		case PROC_POLICY_RSRCACT_THROTTLE:
			/* no need to do anything */
			break;

		case PROC_POLICY_RSRCACT_SUSPEND:
			task_suspend(p->task);
			break;

		case PROC_POLICY_RSRCACT_TERMINATE:
			psignal(p, SIGKILL);
			break;

		case PROC_POLICY_RSRCACT_NOTIFY_KQ:
			/* not implemented */
			break;
		
		case PROC_POLICY_RSRCACT_NOTIFY_EXC:
			panic("shouldn't be applying exception notification to process!");
			break;
	}

	return(0);
}

int
proc_restore_resource_actions(void * bsdinfo, __unused int type, int action)
{
	proc_t p = (proc_t)bsdinfo;

	switch(action) {
		case PROC_POLICY_RSRCACT_THROTTLE:
		case PROC_POLICY_RSRCACT_TERMINATE:
		case PROC_POLICY_RSRCACT_NOTIFY_KQ:
		case PROC_POLICY_RSRCACT_NOTIFY_EXC:
			/* no need to do anything */
			break;

		case PROC_POLICY_RSRCACT_SUSPEND:
			task_resume(p->task);
			break;

	}

	return(0);
}

