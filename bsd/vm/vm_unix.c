/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <meta_features.h>

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/debug.h>
#include <kern/lock.h>
#include <mach/mach_traps.h>
#include <mach/port.h>
#include <mach/task.h>
#include <mach/task_access.h>
#include <mach/task_special_ports.h>
#include <mach/time_value.h>
#include <mach/vm_map.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>

#include <sys/file_internal.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dir.h>
#include <sys/namei.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/vm.h>
#include <sys/file.h>
#include <sys/vnode_internal.h>
#include <sys/mount.h>
#include <sys/trace.h>
#include <sys/kernel.h>
#include <sys/ubc_internal.h>
#include <sys/user.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/sysproto.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

#include <security/audit/audit.h>
#include <bsm/audit_kevents.h>

#include <kern/kalloc.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

#include <machine/spl.h>

#include <mach/shared_region.h>
#include <vm/vm_shared_region.h>

#include <vm/vm_protos.h>

/*
 * Sysctl's related to data/stack execution.  See osfmk/vm/vm_map.c
 */

#ifndef SECURE_KERNEL
extern int allow_stack_exec, allow_data_exec;

SYSCTL_INT(_vm, OID_AUTO, allow_stack_exec, CTLFLAG_RW, &allow_stack_exec, 0, "");
SYSCTL_INT(_vm, OID_AUTO, allow_data_exec, CTLFLAG_RW, &allow_data_exec, 0, "");
#endif /* !SECURE_KERNEL */

static const char *prot_values[] = {
	"none",
	"read-only",
	"write-only",
	"read-write",
	"execute-only",
	"read-execute",
	"write-execute",
	"read-write-execute"
};

void
log_stack_execution_failure(addr64_t vaddr, vm_prot_t prot)
{
	printf("Data/Stack execution not permitted: %s[pid %d] at virtual address 0x%qx, protections were %s\n", 
		current_proc()->p_comm, current_proc()->p_pid, vaddr, prot_values[prot & VM_PROT_ALL]);
}

int shared_region_unnest_logging = 1;

SYSCTL_INT(_vm, OID_AUTO, shared_region_unnest_logging, CTLFLAG_RW,
	   &shared_region_unnest_logging, 0, "");

int vm_shared_region_unnest_log_interval = 10;
int shared_region_unnest_log_count_threshold = 5;

/* These log rate throttling state variables aren't thread safe, but
 * are sufficient unto the task.
 */
static int64_t last_unnest_log_time = 0; 
static int shared_region_unnest_log_count = 0;

void log_unnest_badness(vm_map_t m, vm_map_offset_t s, vm_map_offset_t e) {
	struct timeval tv;
	const char *pcommstr;

	if (shared_region_unnest_logging == 0)
		return;

	if (shared_region_unnest_logging == 1) {
		microtime(&tv);
		if ((tv.tv_sec - last_unnest_log_time) < vm_shared_region_unnest_log_interval) {
			if (shared_region_unnest_log_count++ > shared_region_unnest_log_count_threshold)
				return;
		}
		else {
			last_unnest_log_time = tv.tv_sec;
			shared_region_unnest_log_count = 0;
		}
	}

	pcommstr = current_proc()->p_comm;

	printf("%s (map: %p) triggered DYLD shared region unnest for map: %p, region 0x%qx->0x%qx. While not abnormal for debuggers, this increases system memory footprint until the target exits.\n", current_proc()->p_comm, get_task_map(current_proc()->task), m, (uint64_t)s, (uint64_t)e);
}

int
useracc(
	user_addr_t	addr,
	user_size_t	len,
	int	prot)
{
	return (vm_map_check_protection(
			current_map(),
			vm_map_trunc_page(addr), vm_map_round_page(addr+len),
			prot == B_READ ? VM_PROT_READ : VM_PROT_WRITE));
}

int
vslock(
	user_addr_t	addr,
	user_size_t	len)
{
	kern_return_t kret;
	kret = vm_map_wire(current_map(), vm_map_trunc_page(addr),
			vm_map_round_page(addr+len), 
			VM_PROT_READ | VM_PROT_WRITE ,FALSE);

	switch (kret) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}
}

int
vsunlock(
	user_addr_t addr,
	user_size_t len,
	__unused int dirtied)
{
#if FIXME  /* [ */
	pmap_t		pmap;
	vm_page_t	pg;
	vm_map_offset_t	vaddr;
	ppnum_t		paddr;
#endif  /* FIXME ] */
	kern_return_t kret;

#if FIXME  /* [ */
	if (dirtied) {
		pmap = get_task_pmap(current_task());
		for (vaddr = vm_map_trunc_page(addr);
		     vaddr < vm_map_round_page(addr+len);
				vaddr += PAGE_SIZE) {
			paddr = pmap_extract(pmap, vaddr);
			pg = PHYS_TO_VM_PAGE(paddr);
			vm_page_set_modified(pg);
		}
	}
#endif  /* FIXME ] */
#ifdef	lint
	dirtied++;
#endif	/* lint */
	kret = vm_map_unwire(current_map(), vm_map_trunc_page(addr),
				vm_map_round_page(addr+len), FALSE);
	switch (kret) {
	case KERN_SUCCESS:
		return (0);
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}
}

int
subyte(
	user_addr_t addr,
	int byte)
{
	char character;
	
	character = (char)byte;
	return (copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1);
}

int
suibyte(
	user_addr_t addr,
	int byte)
{
	char character;
	
	character = (char)byte;
	return (copyout((void *)&(character), addr, sizeof(char)) == 0 ? 0 : -1);
}

int fubyte(user_addr_t addr)
{
	unsigned char byte;

	if (copyin(addr, (void *) &byte, sizeof(char)))
		return(-1);
	return(byte);
}

int fuibyte(user_addr_t addr)
{
	unsigned char byte;

	if (copyin(addr, (void *) &(byte), sizeof(char)))
		return(-1);
	return(byte);
}

int
suword(
	user_addr_t addr,
	long word)
{
	return (copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1);
}

long fuword(user_addr_t addr)
{
	long word = 0;

	if (copyin(addr, (void *) &word, sizeof(int)))
		return(-1);
	return(word);
}

/* suiword and fuiword are the same as suword and fuword, respectively */

int
suiword(
	user_addr_t addr,
	long word)
{
	return (copyout((void *) &word, addr, sizeof(int)) == 0 ? 0 : -1);
}

long fuiword(user_addr_t addr)
{
	long word = 0;

	if (copyin(addr, (void *) &word, sizeof(int)))
		return(-1);
	return(word);
}

/*
 * With a 32-bit kernel and mixed 32/64-bit user tasks, this interface allows the
 * fetching and setting of process-sized size_t and pointer values.
 */
int
sulong(user_addr_t addr, int64_t word)
{

	if (IS_64BIT_PROCESS(current_proc())) {
		return(copyout((void *)&word, addr, sizeof(word)) == 0 ? 0 : -1);
	} else {
		return(suiword(addr, (long)word));
	}
}

int64_t
fulong(user_addr_t addr)
{
	int64_t longword;

	if (IS_64BIT_PROCESS(current_proc())) {
		if (copyin(addr, (void *)&longword, sizeof(longword)) != 0)
			return(-1);
		return(longword);
	} else {
		return((int64_t)fuiword(addr));
	}
}

int
suulong(user_addr_t addr, uint64_t uword)
{

	if (IS_64BIT_PROCESS(current_proc())) {
		return(copyout((void *)&uword, addr, sizeof(uword)) == 0 ? 0 : -1);
	} else {
		return(suiword(addr, (uint32_t)uword));
	}
}

uint64_t
fuulong(user_addr_t addr)
{
	uint64_t ulongword;

	if (IS_64BIT_PROCESS(current_proc())) {
		if (copyin(addr, (void *)&ulongword, sizeof(ulongword)) != 0)
			return(-1ULL);
		return(ulongword);
	} else {
		return((uint64_t)fuiword(addr));
	}
}

int
swapon(__unused proc_t procp, __unused struct swapon_args *uap, __unused int *retval)
{
	return(ENOTSUP);
}

/*
 * pid_for_task
 *
 * Find the BSD process ID for the Mach task associated with the given Mach port 
 * name
 *
 * Parameters:	args		User argument descriptor (see below)
 *
 * Indirect parameters:	args->t		Mach port name
 * 			args->pid	Process ID (returned value; see below)
 *
 * Returns:	KERL_SUCCESS	Success
 * 		KERN_FAILURE	Not success           
 *
 * Implicit returns: args->pid		Process ID
 *
 */
kern_return_t
pid_for_task(
	struct pid_for_task_args *args)
{
	mach_port_name_t	t = args->t;
	user_addr_t		pid_addr  = args->pid;  
	proc_t p;
	task_t		t1;
	int	pid = -1;
	kern_return_t	err = KERN_SUCCESS;

	AUDIT_MACH_SYSCALL_ENTER(AUE_PIDFORTASK);
	AUDIT_ARG(mach_port1, t);

	t1 = port_name_to_task(t);

	if (t1 == TASK_NULL) {
		err = KERN_FAILURE;
		goto pftout;
	} else {
		p = get_bsdtask_info(t1);
		if (p) {
			pid  = proc_pid(p);
			err = KERN_SUCCESS;
		} else {
			err = KERN_FAILURE;
		}
	}
	task_deallocate(t1);
pftout:
	AUDIT_ARG(pid, pid);
	(void) copyout((char *) &pid, pid_addr, sizeof(int));
	AUDIT_MACH_SYSCALL_EXIT(err);
	return(err);
}

/* 
 *
 * tfp_policy = KERN_TFP_POLICY_DENY; Deny Mode: None allowed except for self
 * tfp_policy = KERN_TFP_POLICY_DEFAULT; default mode: all posix checks and upcall via task port for authentication
 *
 */
static  int tfp_policy = KERN_TFP_POLICY_DEFAULT;

/*
 *	Routine:	task_for_pid_posix_check
 *	Purpose:
 *			Verify that the current process should be allowed to
 *			get the target process's task port. This is only 
 *			permitted if:
 *			- The current process is root
 *			OR all of the following are true:
 *			- The target process's real, effective, and saved uids
 *			  are the same as the current proc's euid,
 *			- The target process's group set is a subset of the
 *			  calling process's group set, and
 *			- The target process hasn't switched credentials.
 *
 *	Returns:	TRUE: permitted
 *			FALSE: denied
 */
static int
task_for_pid_posix_check(proc_t target)
{
	kauth_cred_t targetcred, mycred;
	uid_t myuid;
	int allowed; 

	/* No task_for_pid on bad targets */
	if (target == PROC_NULL || target->p_stat == SZOMB) {
		return FALSE;
	}

	mycred = kauth_cred_get();
	myuid = kauth_cred_getuid(mycred);

	/* If we're running as root, the check passes */
	if (kauth_cred_issuser(mycred))
		return TRUE;

	/* We're allowed to get our own task port */
	if (target == current_proc())
		return TRUE;

	/* 
	 * Under DENY, only root can get another proc's task port,
	 * so no more checks are needed.
	 */
	if (tfp_policy == KERN_TFP_POLICY_DENY) { 
		return FALSE;
	}

	targetcred = kauth_cred_proc_ref(target);
	allowed = TRUE;

	/* Do target's ruid, euid, and saved uid match my euid? */
	if ((kauth_cred_getuid(targetcred) != myuid) || 
			(targetcred->cr_ruid != myuid) ||
			(targetcred->cr_svuid != myuid)) {
		allowed = FALSE;
		goto out;
	}

	/* Are target's groups a subset of my groups? */
	if (kauth_cred_gid_subset(targetcred, mycred, &allowed) ||
			allowed == 0) {
		allowed = FALSE;
		goto out;
	}

	/* Has target switched credentials? */
	if (target->p_flag & P_SUGID) {
		allowed = FALSE;
		goto out;
	}
	
out:
	kauth_cred_unref(&targetcred);
	return allowed;
}

/*
 *	Routine:	task_for_pid
 *	Purpose:
 *		Get the task port for another "process", named by its
 *		process ID on the same host as "target_task".
 *
 *		Only permitted to privileged processes, or processes
 *		with the same user ID.
 *
 *		Note: if pid == 0, an error is return no matter who is calling.
 *
 * XXX This should be a BSD system call, not a Mach trap!!!
 */
kern_return_t
task_for_pid(
	struct task_for_pid_args *args)
{
	mach_port_name_t	target_tport = args->target_tport;
	int			pid = args->pid;
	user_addr_t		task_addr = args->t;
	proc_t 			p = PROC_NULL;
	task_t			t1 = TASK_NULL;
	mach_port_name_t	tret = MACH_PORT_NULL;
 	ipc_port_t 		tfpport;
	void * sright;
	int error = 0;

	AUDIT_MACH_SYSCALL_ENTER(AUE_TASKFORPID);
	AUDIT_ARG(pid, pid);
	AUDIT_ARG(mach_port1, target_tport);

	/* Always check if pid == 0 */
	if (pid == 0) {
		(void ) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return(KERN_FAILURE);
	}

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return(KERN_FAILURE);
	} 


	p = proc_find(pid);
#if CONFIG_AUDIT
	if (p != PROC_NULL)
		AUDIT_ARG(process, p);
#endif

	if (!(task_for_pid_posix_check(p))) {
		error = KERN_FAILURE;
		goto tfpout;
	}

	if (p->task != TASK_NULL) {
		/* If we aren't root and target's task access port is set... */
		if (!kauth_cred_issuser(kauth_cred_get()) &&
			p != current_proc() &&
			(task_get_task_access_port(p->task, &tfpport) == 0) &&
			(tfpport != IPC_PORT_NULL)) {

			if (tfpport == IPC_PORT_DEAD) {
				error = KERN_PROTECTION_FAILURE;
				goto tfpout;
			}

			/* Call up to the task access server */
			error = check_task_access(tfpport, proc_selfpid(), kauth_getgid(), pid);

			if (error != MACH_MSG_SUCCESS) {
				if (error == MACH_RCV_INTERRUPTED)
					error = KERN_ABORTED;
				else
					error = KERN_FAILURE;
				goto tfpout;
			}
		}
#if CONFIG_MACF
		error = mac_proc_check_get_task(kauth_cred_get(), p);
		if (error) {
			error = KERN_FAILURE;
			goto tfpout;
		}
#endif

		/* Grant task port access */
		task_reference(p->task);
		sright = (void *) convert_task_to_port(p->task);
		tret = ipc_port_copyout_send(
				sright, 
				get_task_ipcspace(current_task()));
	} 
	error = KERN_SUCCESS;

tfpout:
	task_deallocate(t1);
	AUDIT_ARG(mach_port2, tret);
	(void) copyout((char *) &tret, task_addr, sizeof(mach_port_name_t));
	if (p != PROC_NULL)
		proc_rele(p);
	AUDIT_MACH_SYSCALL_EXIT(error);
	return(error);
}

/*
 *	Routine:	task_name_for_pid
 *	Purpose:
 *		Get the task name port for another "process", named by its
 *		process ID on the same host as "target_task".
 *
 *		Only permitted to privileged processes, or processes
 *		with the same user ID.
 *
 * XXX This should be a BSD system call, not a Mach trap!!!
 */

kern_return_t
task_name_for_pid(
	struct task_name_for_pid_args *args)
{
	mach_port_name_t	target_tport = args->target_tport;
	int			pid = args->pid;
	user_addr_t		task_addr = args->t;
	proc_t		p = PROC_NULL;
	task_t		t1;
	mach_port_name_t	tret;
	void * sright;
	int error = 0, refheld = 0;
	kauth_cred_t target_cred;

	AUDIT_MACH_SYSCALL_ENTER(AUE_TASKNAMEFORPID);
	AUDIT_ARG(pid, pid);
	AUDIT_ARG(mach_port1, target_tport);

	t1 = port_name_to_task(target_tport);
	if (t1 == TASK_NULL) {
		(void) copyout((char *)&t1, task_addr, sizeof(mach_port_name_t));
		AUDIT_MACH_SYSCALL_EXIT(KERN_FAILURE);
		return(KERN_FAILURE);
	} 

	p = proc_find(pid);
	if (p != PROC_NULL) {
		AUDIT_ARG(process, p);
		target_cred = kauth_cred_proc_ref(p);
		refheld = 1;

		if ((p->p_stat != SZOMB)
		    && ((current_proc() == p)
			|| kauth_cred_issuser(kauth_cred_get()) 
			|| ((kauth_cred_getuid(target_cred) == kauth_cred_getuid(kauth_cred_get())) && 
			    ((target_cred->cr_ruid == kauth_cred_get()->cr_ruid))))) {

			if (p->task != TASK_NULL) {
				task_reference(p->task);
#if CONFIG_MACF
				error = mac_proc_check_get_task_name(kauth_cred_get(),  p);
				if (error) {
					task_deallocate(p->task);
					goto noperm;
				}
#endif
				sright = (void *)convert_task_name_to_port(p->task);
				tret = ipc_port_copyout_send(sright, 
						get_task_ipcspace(current_task()));
			} else
				tret  = MACH_PORT_NULL;

			AUDIT_ARG(mach_port2, tret);
			(void) copyout((char *)&tret, task_addr, sizeof(mach_port_name_t));
			task_deallocate(t1);
			error = KERN_SUCCESS;
			goto tnfpout;
		}
	}

#if CONFIG_MACF
noperm:
#endif
    task_deallocate(t1);
	tret = MACH_PORT_NULL;
	(void) copyout((char *) &tret, task_addr, sizeof(mach_port_name_t));
	error = KERN_FAILURE;
tnfpout:
	if (refheld != 0)
		kauth_cred_unref(&target_cred);
	if (p != PROC_NULL)
		proc_rele(p);
	AUDIT_MACH_SYSCALL_EXIT(error);
	return(error);
}

kern_return_t
pid_suspend(struct proc *p __unused, struct pid_suspend_args *args, int *ret)
{
	task_t	target = NULL;
	proc_t	targetproc = PROC_NULL;
	int 	pid = args->pid;
	int 	error = 0;

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(p, 0); /* 0 for suspend */
	if (error) {
		error = KERN_FAILURE;
		goto out;
	}
#endif

	if (pid == 0) {
		error = KERN_FAILURE;
		goto out;
	}

	targetproc = proc_find(pid);
	if (!task_for_pid_posix_check(targetproc)) {
		error = KERN_FAILURE;
		goto out;
	}

	target = targetproc->task;
#ifndef CONFIG_EMBEDDED
	if (target != TASK_NULL) {
		mach_port_t tfpport;

		/* If we aren't root and target's task access port is set... */
		if (!kauth_cred_issuser(kauth_cred_get()) &&
			targetproc != current_proc() &&
			(task_get_task_access_port(target, &tfpport) == 0) &&
			(tfpport != IPC_PORT_NULL)) {

			if (tfpport == IPC_PORT_DEAD) {
				error = KERN_PROTECTION_FAILURE;
				goto out;
			}

			/* Call up to the task access server */
			error = check_task_access(tfpport, proc_selfpid(), kauth_getgid(), pid);

			if (error != MACH_MSG_SUCCESS) {
				if (error == MACH_RCV_INTERRUPTED)
					error = KERN_ABORTED;
				else
					error = KERN_FAILURE;
				goto out;
			}
		}
	}
#endif

	task_reference(target);
	error = task_suspend(target);
	task_deallocate(target);

out:
	if (targetproc != PROC_NULL)
		proc_rele(targetproc);
	*ret = error;
	return error;
}

kern_return_t
pid_resume(struct proc *p __unused, struct pid_resume_args *args, int *ret)
{
	task_t	target = NULL;
	proc_t	targetproc = PROC_NULL;
	int 	pid = args->pid;
	int 	error = 0;

#if CONFIG_MACF
	error = mac_proc_check_suspend_resume(p, 1); /* 1 for resume */
	if (error) {
		error = KERN_FAILURE;
		goto out;
	}
#endif

	if (pid == 0) {
		error = KERN_FAILURE;
		goto out;
	}

	targetproc = proc_find(pid);
	if (!task_for_pid_posix_check(targetproc)) {
		error = KERN_FAILURE;
		goto out;
	}

	target = targetproc->task;
#ifndef CONFIG_EMBEDDED
	if (target != TASK_NULL) {
		mach_port_t tfpport;

		/* If we aren't root and target's task access port is set... */
		if (!kauth_cred_issuser(kauth_cred_get()) &&
			targetproc != current_proc() &&
			(task_get_task_access_port(target, &tfpport) == 0) &&
			(tfpport != IPC_PORT_NULL)) {

			if (tfpport == IPC_PORT_DEAD) {
				error = KERN_PROTECTION_FAILURE;
				goto out;
			}

			/* Call up to the task access server */
			error = check_task_access(tfpport, proc_selfpid(), kauth_getgid(), pid);

			if (error != MACH_MSG_SUCCESS) {
				if (error == MACH_RCV_INTERRUPTED)
					error = KERN_ABORTED;
				else
					error = KERN_FAILURE;
				goto out;
			}
		}
	}
#endif

	task_reference(target);
	error = task_resume(target);
	task_deallocate(target);

out:
	if (targetproc != PROC_NULL)
		proc_rele(targetproc);
	*ret = error;
	return error;

	return 0;
}

static int
sysctl_settfp_policy(__unused struct sysctl_oid *oidp, void *arg1,
    __unused int arg2, struct sysctl_req *req)
{
    int error = 0;
	int new_value;

    error = SYSCTL_OUT(req, arg1, sizeof(int));
    if (error || req->newptr == USER_ADDR_NULL)
        return(error);

	if (!is_suser())
		return(EPERM);

	if ((error = SYSCTL_IN(req, &new_value, sizeof(int)))) {
		goto out;
	}
	if ((new_value == KERN_TFP_POLICY_DENY) 
		|| (new_value == KERN_TFP_POLICY_DEFAULT))
			tfp_policy = new_value;
	else
			error = EINVAL;		
out:
    return(error);

}

#if defined(SECURE_KERNEL)
static int kern_secure_kernel = 1;
#else
static int kern_secure_kernel = 0;
#endif

SYSCTL_INT(_kern, OID_AUTO, secure_kernel, CTLFLAG_RD, &kern_secure_kernel, 0, "");

SYSCTL_NODE(_kern, KERN_TFP, tfp, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "tfp");
SYSCTL_PROC(_kern_tfp, KERN_TFP_POLICY, policy, CTLTYPE_INT | CTLFLAG_RW,
    &tfp_policy, sizeof(uint32_t), &sysctl_settfp_policy ,"I","policy");

SYSCTL_INT(_vm, OID_AUTO, shared_region_trace_level, CTLFLAG_RW,
	   &shared_region_trace_level, 0, "");
SYSCTL_INT(_vm, OID_AUTO, shared_region_version, CTLFLAG_RD,
	   &shared_region_version, 0, "");
SYSCTL_INT(_vm, OID_AUTO, shared_region_persistence, CTLFLAG_RW,
	   &shared_region_persistence, 0, "");

/*
 * shared_region_check_np:
 *
 * This system call is intended for dyld.
 *
 * dyld calls this when any process starts to see if the process's shared
 * region is already set up and ready to use.
 * This call returns the base address of the first mapping in the
 * process's shared region's first mapping.
 * dyld will then check what's mapped at that address.
 *
 * If the shared region is empty, dyld will then attempt to map the shared
 * cache file in the shared region via the shared_region_map_np() system call.
 *
 * If something's already mapped in the shared region, dyld will check if it
 * matches the shared cache it would like to use for that process.
 * If it matches, evrything's ready and the process can proceed and use the
 * shared region.
 * If it doesn't match, dyld will unmap the shared region and map the shared
 * cache into the process's address space via mmap().
 *
 * ERROR VALUES
 * EINVAL	no shared region
 * ENOMEM	shared region is empty
 * EFAULT	bad address for "start_address"
 */
int
shared_region_check_np(
	__unused struct proc			*p,
	struct shared_region_check_np_args	*uap,
	__unused int				*retvalp)
{
	vm_shared_region_t	shared_region;
	mach_vm_offset_t	start_address;
	int			error;
	kern_return_t		kr;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] -> check_np(0x%llx)\n",
		 current_thread(), p->p_pid, p->p_comm,
		 (uint64_t)uap->start_address));

	/* retrieve the current tasks's shared region */
	shared_region = vm_shared_region_get(current_task());
	if (shared_region != NULL) {
		/* retrieve address of its first mapping... */
		kr = vm_shared_region_start_address(shared_region,
						    &start_address);
		if (kr != KERN_SUCCESS) {
			error = ENOMEM;
		} else {
			/* ... and give it to the caller */
			error = copyout(&start_address,
					(user_addr_t) uap->start_address,
					sizeof (start_address));
			if (error) {
				SHARED_REGION_TRACE_ERROR(
					("shared_region: %p [%d(%s)] "
					 "check_np(0x%llx) "
					 "copyout(0x%llx) error %d\n",
					 current_thread(), p->p_pid, p->p_comm,
					 (uint64_t)uap->start_address, (uint64_t)start_address,
					 error));
			}
		}
		vm_shared_region_deallocate(shared_region);
	} else {
		/* no shared region ! */
		error = EINVAL;
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] check_np(0x%llx) <- 0x%llx %d\n",
		 current_thread(), p->p_pid, p->p_comm,
		 (uint64_t)uap->start_address, (uint64_t)start_address, error));

	return error;
}

/*
 * shared_region_map_np()
 *
 * This system call is intended for dyld.
 *
 * dyld uses this to map a shared cache file into a shared region.
 * This is usually done only the first time a shared cache is needed.
 * Subsequent processes will just use the populated shared region without
 * requiring any further setup.
 */
int
shared_region_map_np(
	struct proc				*p,
	struct shared_region_map_np_args	*uap,
	__unused int				*retvalp)
{
	int				error;
	kern_return_t			kr;
	int				fd;
	struct fileproc			*fp;
	struct vnode			*vp, *root_vp;
	struct vnode_attr		va;
	off_t				fs;
	memory_object_size_t		file_size;
	user_addr_t			user_mappings;
	struct shared_file_mapping_np	*mappings;
#define SFM_MAX_STACK	8
	struct shared_file_mapping_np	stack_mappings[SFM_MAX_STACK];
	unsigned int			mappings_count;
	vm_size_t			mappings_size;
	memory_object_control_t		file_control;
	struct vm_shared_region		*shared_region;

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] -> map\n",
		 current_thread(), p->p_pid, p->p_comm));

	shared_region = NULL;
	mappings_count = 0;
	mappings_size = 0;
	mappings = NULL;
	fp = NULL;
	vp = NULL;

	/* get file descriptor for shared region cache file */
	fd = uap->fd;

	/* get file structure from file descriptor */
	error = fp_lookup(p, fd, &fp, 0);
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map: "
			 "fd=%d lookup failed (error=%d)\n",
			 current_thread(), p->p_pid, p->p_comm, fd, error));
		goto done;
	}

	/* make sure we're attempting to map a vnode */
	if (fp->f_fglob->fg_type != DTYPE_VNODE) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map: "
			 "fd=%d not a vnode (type=%d)\n",
			 current_thread(), p->p_pid, p->p_comm,
			 fd, fp->f_fglob->fg_type));
		error = EINVAL;
		goto done;
	}

	/* we need at least read permission on the file */
	if (! (fp->f_fglob->fg_flag & FREAD)) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map: "
			 "fd=%d not readable\n",
			 current_thread(), p->p_pid, p->p_comm, fd));
		error = EPERM;
		goto done;
	}

	/* get vnode from file structure */
	error = vnode_getwithref((vnode_t) fp->f_fglob->fg_data);
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map: "
			 "fd=%d getwithref failed (error=%d)\n",
			 current_thread(), p->p_pid, p->p_comm, fd, error));
		goto done;
	}
	vp = (struct vnode *) fp->f_fglob->fg_data;

	/* make sure the vnode is a regular file */
	if (vp->v_type != VREG) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "not a file (type=%d)\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name, vp->v_type));
		error = EINVAL;
		goto done;
	}

	/* make sure vnode is on the process's root volume */
	root_vp = p->p_fd->fd_rdir;
	if (root_vp == NULL) {
		root_vp = rootvnode;
	}
	if (vp->v_mount != root_vp->v_mount) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "not on process's root volume\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name));
		error = EPERM;
		goto done;
	}

	/* make sure vnode is owned by "root" */
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	error = vnode_getattr(vp, &va, vfs_context_current());
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "vnode_getattr(%p) failed (error=%d)\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name, vp, error));
		goto done;
	}
	if (va.va_uid != 0) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "owned by uid=%d instead of 0\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name, va.va_uid));
		error = EPERM;
		goto done;
	}

	/* get vnode size */
	error = vnode_size(vp, &fs, vfs_context_current());
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "vnode_size(%p) failed (error=%d)\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name, vp, error));
		goto done;
	}
	file_size = fs;

	/* get the file's memory object handle */
	file_control = ubc_getobject(vp, UBC_HOLDOBJECT);
	if (file_control == MEMORY_OBJECT_CONTROL_NULL) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "no memory object\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name));
		error = EINVAL;
		goto done;
	}
			 
	/* get the list of mappings the caller wants us to establish */
	mappings_count = uap->count;	/* number of mappings */
	mappings_size = (vm_size_t) (mappings_count * sizeof (mappings[0]));
	if (mappings_count == 0) {
		SHARED_REGION_TRACE_INFO(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "no mappings\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name));
		error = 0;	/* no mappings: we're done ! */
		goto done;
	} else if (mappings_count <= SFM_MAX_STACK) {
		mappings = &stack_mappings[0];
	} else {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "too many mappings (%d)\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name, mappings_count));
		error = EINVAL;
		goto done;
	}

	user_mappings = uap->mappings;	/* the mappings, in user space */
	error = copyin(user_mappings,
		       mappings,
		       mappings_size);
	if (error) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "copyin(0x%llx, %d) failed (error=%d)\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name, (uint64_t)user_mappings, mappings_count, error));
		goto done;
	}

	/* get the process's shared region (setup in vm_map_exec()) */
	shared_region = vm_shared_region_get(current_task());
	if (shared_region == NULL) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "no shared region\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name));
		goto done;
	}

	/* map the file into that shared region's submap */
	kr = vm_shared_region_map_file(shared_region,
				       mappings_count,
				       mappings,
				       file_control,
				       file_size,
				       (void *) p->p_fd->fd_rdir);
	if (kr != KERN_SUCCESS) {
		SHARED_REGION_TRACE_ERROR(
			("shared_region: %p [%d(%s)] map(%p:'%s'): "
			 "vm_shared_region_map_file() failed kr=0x%x\n",
			 current_thread(), p->p_pid, p->p_comm,
			 vp, vp->v_name, kr));
		switch (kr) {
		case KERN_INVALID_ADDRESS:
			error = EFAULT;
			break;
		case KERN_PROTECTION_FAILURE:
			error = EPERM;
			break;
		case KERN_NO_SPACE:
			error = ENOMEM;
			break;
		case KERN_FAILURE:
		case KERN_INVALID_ARGUMENT:
		default:
			error = EINVAL;
			break;
		}
		goto done;
	}

	error = 0;

	/* update the vnode's access time */
	if (! (vnode_vfsvisflags(vp) & MNT_NOATIME)) {
		VATTR_INIT(&va);
		nanotime(&va.va_access_time);
		VATTR_SET_ACTIVE(&va, va_access_time);
		vnode_setattr(vp, &va, vfs_context_current());
	}

	if (p->p_flag & P_NOSHLIB) {
		/* signal that this process is now using split libraries */
		OSBitAndAtomic(~((uint32_t)P_NOSHLIB), &p->p_flag);
	}

done:
	if (vp != NULL) {
		/*
		 * release the vnode...
		 * ubc_map() still holds it for us in the non-error case
		 */
		(void) vnode_put(vp);
		vp = NULL;
	}
	if (fp != NULL) {
		/* release the file descriptor */
		fp_drop(p, fd, fp, 0);
		fp = NULL;
	}

	if (shared_region != NULL) {
		vm_shared_region_deallocate(shared_region);
	}

	SHARED_REGION_TRACE_DEBUG(
		("shared_region: %p [%d(%s)] <- map\n",
		 current_thread(), p->p_pid, p->p_comm));

	return error;
}


/* sysctl overflow room */

/* vm_page_free_target is provided as a makeshift solution for applications that want to
	allocate buffer space, possibly purgeable memory, but not cause inactive pages to be
	reclaimed. It allows the app to calculate how much memory is free outside the free target. */
extern unsigned int	vm_page_free_target;
SYSCTL_INT(_vm, OID_AUTO, vm_page_free_target, CTLFLAG_RD, 
		   &vm_page_free_target, 0, "Pageout daemon free target");

extern unsigned int	vm_memory_pressure;
SYSCTL_INT(_vm, OID_AUTO, memory_pressure, CTLFLAG_RD,
	   &vm_memory_pressure, 0, "Memory pressure indicator");

static int
vm_ctl_page_free_wanted SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int page_free_wanted;

	page_free_wanted = mach_vm_ctl_page_free_wanted();
	return SYSCTL_OUT(req, &page_free_wanted, sizeof (page_free_wanted));
}
SYSCTL_PROC(_vm, OID_AUTO, page_free_wanted,
	    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
	    0, 0, vm_ctl_page_free_wanted, "I", "");

extern unsigned int	vm_page_purgeable_count;
SYSCTL_INT(_vm, OID_AUTO, page_purgeable_count, CTLFLAG_RD,
	   &vm_page_purgeable_count, 0, "Purgeable page count");

extern unsigned int	vm_page_purgeable_wired_count;
SYSCTL_INT(_vm, OID_AUTO, page_purgeable_wired_count, CTLFLAG_RD,
	   &vm_page_purgeable_wired_count, 0, "Wired purgeable page count");

SYSCTL_INT(_vm, OID_AUTO, page_reusable_count, CTLFLAG_RD,
	   &vm_page_stats_reusable.reusable_count, 0, "Reusable page count");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_success, CTLFLAG_RD,
	   &vm_page_stats_reusable.reusable_pages_success, "");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_failure, CTLFLAG_RD,
	   &vm_page_stats_reusable.reusable_pages_failure, "");
SYSCTL_QUAD(_vm, OID_AUTO, reusable_shared, CTLFLAG_RD,
	   &vm_page_stats_reusable.reusable_pages_shared, "");
SYSCTL_QUAD(_vm, OID_AUTO, all_reusable_calls, CTLFLAG_RD,
	   &vm_page_stats_reusable.all_reusable_calls, "");
SYSCTL_QUAD(_vm, OID_AUTO, partial_reusable_calls, CTLFLAG_RD,
	   &vm_page_stats_reusable.partial_reusable_calls, "");
SYSCTL_QUAD(_vm, OID_AUTO, reuse_success, CTLFLAG_RD,
	   &vm_page_stats_reusable.reuse_pages_success, "");
SYSCTL_QUAD(_vm, OID_AUTO, reuse_failure, CTLFLAG_RD,
	   &vm_page_stats_reusable.reuse_pages_failure, "");
SYSCTL_QUAD(_vm, OID_AUTO, all_reuse_calls, CTLFLAG_RD,
	   &vm_page_stats_reusable.all_reuse_calls, "");
SYSCTL_QUAD(_vm, OID_AUTO, partial_reuse_calls, CTLFLAG_RD,
	   &vm_page_stats_reusable.partial_reuse_calls, "");
SYSCTL_QUAD(_vm, OID_AUTO, can_reuse_success, CTLFLAG_RD,
	   &vm_page_stats_reusable.can_reuse_success, "");
SYSCTL_QUAD(_vm, OID_AUTO, can_reuse_failure, CTLFLAG_RD,
	   &vm_page_stats_reusable.can_reuse_failure, "");


int
vm_pressure_monitor(
	__unused struct proc *p,
	struct vm_pressure_monitor_args *uap,
	int *retval)
{
	kern_return_t	kr;
	uint32_t	pages_reclaimed;
	uint32_t	pages_wanted;

	kr = mach_vm_pressure_monitor(
		(boolean_t) uap->wait_for_pressure,
		uap->nsecs_monitored,
		(uap->pages_reclaimed) ? &pages_reclaimed : NULL,
		&pages_wanted);

	switch (kr) {
	case KERN_SUCCESS:
		break;
	case KERN_ABORTED:
		return EINTR;
	default:
		return EINVAL;
	}

	if (uap->pages_reclaimed) {
		if (copyout((void *)&pages_reclaimed,
			    uap->pages_reclaimed,
			    sizeof (pages_reclaimed)) != 0) {
			return EFAULT;
		}
	}

	*retval = (int) pages_wanted;
	return 0;
}
