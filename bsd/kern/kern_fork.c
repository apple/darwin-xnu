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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_fork.c	8.8 (Berkeley) 2/14/95
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <kern/assert.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/user.h>
#include <sys/resourcevar.h>
#include <sys/vnode_internal.h>
#include <sys/file_internal.h>
#include <sys/acct.h>
#include <sys/codesign.h>
#include <sys/sysproto.h>
#if CONFIG_DTRACE
/* Do not include dtrace.h, it redefines kmem_[alloc/free] */
extern void dtrace_fasttrap_fork(proc_t, proc_t);
extern void (*dtrace_helpers_fork)(proc_t, proc_t);
extern void dtrace_lazy_dofs_duplicate(proc_t, proc_t);

#include <sys/dtrace_ptss.h>
#endif

#include <bsm/audit_kernel.h>

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/thread_call.h>
#include <kern/zalloc.h>

#include <machine/spl.h>

#if CONFIG_MACF
#include <security/mac.h>
#include <security/mac_mach_internal.h>
#endif

#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/vm_shared_region.h>

#include <sys/shm_internal.h>	/* for shmfork() */
#include <mach/task.h>		/* for thread_create() */
#include <mach/thread_act.h>	/* for thread_resume() */

#include <sys/sdt.h>

/* XXX routines which should have Mach prototypes, but don't */
void thread_set_parent(thread_t parent, int pid);
extern void act_thread_catt(void *ctx);
void thread_set_child(thread_t child, int pid);
void *act_thread_csave(void);


thread_t cloneproc(proc_t, int); 
proc_t forkproc(proc_t, int);
void forkproc_free(proc_t, int);
thread_t procdup(proc_t parent, proc_t child);
thread_t fork_create_child(task_t parent_task, proc_t child, int inherit_memory, int is64bit);

#define	DOFORK	0x1	/* fork() system call */
#define	DOVFORK	0x2	/* vfork() system call */


/*
 * vfork
 *
 * Description:	vfork system call
 *
 * Parameters:	void			[no arguments]
 *
 * Retval:	0			(to child process)
 *		!0			pid of child (to parent process)
 *		-1			error (see "Returns:")
 *
 * Returns:	EAGAIN			Administrative limit reached
 *		EINVAL			vfork() caled during vfork()
 *		ENOMEM			Failed to allocate new process
 *
 * Note:	After a successful call to this function, the parent process
 *		has its task, thread, and uthread lent to the child process,
 *		and control is returned to the caller; if this function is
 *		invoked as a system call, the return is to user space, and
 *		is effectively running on the child process.
 *
 *		Subsequent calls that operate on process state are permitted,
 *		though discouraged, and will operate on the child process; any
 *		operations on the task, thread, or uthread will result in
 *		changes in the parent state, and, if inheritable, the child
 *		state, when a task, thread, and uthread are realized for the
 *		child process at execve() time, will also be effected.  Given
 *		this, it's recemmended that people use the posix_spawn() call
 *		instead.
 */
int
vfork(proc_t parent, __unused struct vfork_args *uap, register_t *retval)
{
	proc_t child;
	uid_t uid;
	thread_t cur_act = (thread_t)current_thread();
	int count;
	uthread_t ut;
#if CONFIG_MACF
	int err;
#endif

	/*
	 * Although process entries are dynamically created, we still keep
	 * a global limit on the maximum number we will create.  Don't allow
	 * a nonprivileged user to use the last process; don't let root
	 * exceed the limit. The variable nprocs is the current number of
	 * processes, maxproc is the limit.
	 */
	uid = kauth_cred_get()->cr_ruid;
	proc_list_lock();
	if ((nprocs >= maxproc - 1 && uid != 0) || nprocs >= maxproc) {
		proc_list_unlock();
		tablefull("proc");
		retval[1] = 0;
		return (EAGAIN);
	}
	proc_list_unlock();

	/*
	 * Increment the count of procs running with this uid. Don't allow
	 * a nonprivileged user to exceed their current limit, which is
	 * always less than what an rlim_t can hold.
	 * (locking protection is provided by list lock held in chgproccnt)
	 */
	count = chgproccnt(uid, 1);
	if (uid != 0 &&
	    (rlim_t)count > parent->p_rlimit[RLIMIT_NPROC].rlim_cur) {
		(void)chgproccnt(uid, -1);
		return (EAGAIN);
	}

	ut = (uthread_t)get_bsdthread_info(cur_act);
	if (ut->uu_flag & UT_VFORK) {
		printf("vfork called recursively by %s\n", parent->p_comm);
		(void)chgproccnt(uid, -1);
		return (EINVAL);
	}

#if CONFIG_MACF
	/*
	 * Determine if MAC policies applied to the process will allow
	 * it to fork.
	 */
	err = mac_proc_check_fork(parent);
	if (err  != 0) {
		(void)chgproccnt(uid, -1);
		return (err);
	}
#endif

	proc_lock(parent);
	parent->p_lflag  |= P_LVFORK;
	parent->p_vforkcnt++;
	proc_unlock(parent);

	/* The newly created process comes with signal lock held */
	if ((child = forkproc(parent,1)) == NULL) {
		/* Failed to allocate new process */
		(void)chgproccnt(uid, -1);
		/*
		 * XXX kludgy, but necessary without a full flags audit...
		 * XXX these are inherited by the child, which depends on
		 * XXX P_VFORK being set.
		 */
		proc_lock(parent);
		parent->p_lflag &= ~P_LVFORK;
		parent->p_vforkcnt--;
		proc_unlock(parent);
		return (ENOMEM);
	}

#if CONFIG_MACF
	/* allow policies to associate the credential/label  */
	/* that we referenced from the parent ... with the child */
	/* JMM - this really isn't safe, as we can drop that */
	/*       association without informing the policy in other */
	/*       situations (keep long enough to get policies changed) */
	mac_cred_label_associate_fork(child->p_ucred, child);
#endif

	AUDIT_ARG(pid, child->p_pid);

	child->task = parent->task;

	/* make child visible */
	pinsertchild(parent, child);

	child->p_lflag  |= P_LINVFORK;
	child->p_vforkact = cur_act;
	child->p_stat = SRUN;

	ut->uu_flag |= UT_VFORK;
	ut->uu_proc = child;
	ut->uu_userstate = (void *)act_thread_csave();
	ut->uu_vforkmask = ut->uu_sigmask;

	/* temporarily drop thread-set-id state */
	if (ut->uu_flag & UT_SETUID) {
		ut->uu_flag |= UT_WASSETUID;
		ut->uu_flag &= ~UT_SETUID;
	}
	
	thread_set_child(cur_act, child->p_pid);

	microtime(&child->p_start);
	microtime(&child->p_stats->p_start); /* for compat sake */
	child->p_acflag = AFORK;

	/*
	 * Preserve synchronization semantics of vfork.  If waiting for
	 * child to exec or exit, set P_PPWAIT on child, and sleep on our
	 * proc (in case of exit).
	 */
	child->p_lflag |= P_LPPWAIT;

	/* drop the signal lock on the child */
	proc_signalend(child, 0);
	proc_transend(child, 0);

	retval[0] = child->p_pid;
	retval[1] = 1;			/* flag child return for user space */

	DTRACE_PROC1(create, proc_t, child);

	return (0);
}

/*
 * vfork_return
 *
 * Description:	"Return" to parent vfork thread() following execve/_exit;
 *		this is done by reassociating the parent process structure
 *		with the task, thread, and uthread.
 *
 * Parameters:	child			Child process
 *		retval			System call return value array
 *		rval			Return value to present to parent
 *
 * Returns:	void
 *
 * Note:	The caller resumes or exits the parent, as appropriate, after
 *		callling this function.
 */
void
vfork_return(proc_t child, register_t *retval, int rval)
{
	proc_t parent = child->p_pptr;
	thread_t cur_act = (thread_t)current_thread();
	uthread_t ut;
	
	ut = (uthread_t)get_bsdthread_info(cur_act);

	act_thread_catt(ut->uu_userstate);

	/* Make sure only one at this time */
	proc_lock(parent);
	parent->p_vforkcnt--;
	if (parent->p_vforkcnt <0)
		panic("vfork cnt is -ve");
	if (parent->p_vforkcnt <=0)
		parent->p_lflag  &= ~P_LVFORK;
	proc_unlock(parent);
	ut->uu_userstate = 0;
	ut->uu_flag &= ~UT_VFORK;
	/* restore thread-set-id state */
	if (ut->uu_flag & UT_WASSETUID) {
		ut->uu_flag |= UT_SETUID;
		ut->uu_flag &= UT_WASSETUID;
	}
	ut->uu_proc = 0;
	ut->uu_sigmask = ut->uu_vforkmask;
	child->p_lflag  &= ~P_LINVFORK;
	child->p_vforkact = (void *)0;

	thread_set_parent(cur_act, rval);

	if (retval) {
		retval[0] = rval;
		retval[1] = 0;			/* mark parent */
	}

	return;
}


/*
 * fork_create_child
 *
 * Description:	Common operations associated with the creation of a child
 *		process
 *
 * Parameters:	parent_task		parent task
 *		child			child process
 *		inherit_memory		TRUE, if the parents address space is
 *					to be inherited by the child
 *		is64bit			TRUE, if the child being created will
 *					be associated with a 64 bit process
 *					rather than a 32 bit process
 *
 * Note:	This code is called in the fork() case, from the execve() call
 *		graph, if implementing an execve() following a vfork(), from
 *		the posix_spawn() call graph (which implicitly includes a
 *		vfork() equivalent call, and in the system bootstrap case.
 *
 *		It creates a new task and thread (and as a side effect of the
 *		thread creation, a uthread), which is then associated with the
 *		process 'child'.  If the parent process address space is to
 *		be inherited, then a flag indicates that the newly created
 *		task should inherit this from the child task.
 *
 *		As a special concession to bootstrapping the initial process
 *		in the system, it's possible for 'parent_task' to be TASK_NULL;
 *		in this case, 'inherit_memory' MUST be FALSE.
 */
thread_t
fork_create_child(task_t parent_task, proc_t child, int inherit_memory, int is64bit)
{
	thread_t	child_thread = NULL;
	task_t		child_task;
	kern_return_t	result;

	/* Create a new task for the child process */
	result = task_create_internal(parent_task,
					inherit_memory,
					is64bit,
					&child_task);
	if (result != KERN_SUCCESS) {
		printf("execve: task_create_internal failed.  Code: %d\n", result);
		goto bad;
	}

	/* Set the child task to the new task */
	child->task = child_task;

	/* Set child task proc to child proc */
	set_bsdtask_info(child_task, child);

	/* Propagate CPU limit timer from parent */
	if (timerisset(&child->p_rlim_cpu))
		task_vtimer_set(child_task, TASK_VTIMER_RLIM);

	/* Set/clear 64 bit vm_map flag */
	if (is64bit)
		vm_map_set_64bit(get_task_map(child_task));
	else
		vm_map_set_32bit(get_task_map(child_task));

#if CONFIG_MACF
	/* Update task for MAC framework */
	/* valid to use p_ucred as child is still not running ... */
	mac_task_label_update_cred(child->p_ucred, child_task);
#endif

	/* Set child scheduler priority if nice value inherited from parent */
	if (child->p_nice != 0)
		resetpriority(child);

	/* Create a new thread for the child process */
	result = thread_create(child_task, &child_thread);
	if (result != KERN_SUCCESS) {
		printf("execve: thread_create failed. Code: %d\n", result);
		task_deallocate(child_task);
		child_task = NULL;
	}
bad:
	thread_yield_internal(1);

	return(child_thread);
}


/*
 * procdup
 *
 * Description:	Givben a parent process, provide a duplicate task and thread
 *		for a child process of that parent.
 *
 * Parameters:	parent			Parent process to use as the template
 *		child			Child process to duplicate into
 *
 * Returns:	!NULL			Child process thread pointer
 *		NULL			Failure (unspecified)
 *
 * Note:	Most of the heavy lifting is done by fork_create_child(); this
 *		function exists more or less to deal with the 64 bit commpage,
 *		which requires explicit inheritance, the x86 commpage, which
 *		should not need explicit mapping any more, but apparently does,
 *		and to be variant for the bootstrap process.
 *
 *		There is a special case where the system is being bootstraped,
 *		where this function will be called from cloneproc(), called in
 *		turn from bsd_utaskbootstrap().  In this case, we are acting
 *		to create a task and thread (and uthread) for the benefit of
 *		the kernel process - the first process in the system (PID 0).
 *
 *		In that specific case, we will *not* pass a parent task, since
 *		there is *not* parent task present to pass.
 *
 * XXX:		This function should go away; the variance can moved into
 * XXX:		cloneproc(), and the 64bit commpage code can be moved into
 * XXX:		fork_create_child(), after the x86 commpage inheritance is
 * XXX:		corrected.
 */
thread_t
procdup(proc_t parent, proc_t child)
{
	thread_t		child_thread;
	task_t			child_task;

	if (parent->task == kernel_task)
		child_thread = fork_create_child(TASK_NULL, child, FALSE, FALSE);
	else
		child_thread = fork_create_child(parent->task, child, TRUE, (parent->p_flag & P_LP64));

	if (child_thread != NULL) {
		child_task = get_threadtask(child_thread);
		if (parent->p_flag & P_LP64) {
			task_set_64bit(child_task, TRUE);
			OSBitOrAtomic(P_LP64, (UInt32 *)&child->p_flag);
#ifdef __ppc__
			/* LP64todo - clean up hacked mapping of commpage */
			/* 
			 * PPC51: ppc64 is limited to 51-bit addresses.
			 * Memory above that limit is handled specially at
			 * the pmap level.
			 */
			 pmap_map_sharedpage(child_task, get_map_pmap(get_task_map(child_task)));
#endif /* __ppc__ */
		} else {
			task_set_64bit(child_task, FALSE);
			OSBitAndAtomic(~((uint32_t)P_LP64), (UInt32 *)&child->p_flag);
		}
	}

	return(child_thread);
}


/*
 * fork
 *
 * Description:	fork system call.
 *
 * Parameters:	parent			Parent process to fork
 *		uap (void)		[unused]
 *		retval			Return value
 *
 * Returns:	0			Success
 *		EAGAIN			Resource unavailable, try again
 */
int
fork(proc_t parent, __unused struct fork_args *uap, register_t *retval)
{
	proc_t child;
	uid_t uid;
	thread_t newth;
	int count;
	task_t t;
#if CONFIG_MACF
	int err;
#endif

	/*
	 * Although process entries are dynamically created, we still keep
	 * a global limit on the maximum number we will create.  Don't allow
	 * a nonprivileged user to use the last process; don't let root
	 * exceed the limit. The variable nprocs is the current number of
	 * processes, maxproc is the limit.
	 */
	uid = kauth_cred_get()->cr_ruid;
	proc_list_lock();
	if ((nprocs >= maxproc - 1 && uid != 0) || nprocs >= maxproc) {
		proc_list_unlock();
		tablefull("proc");
		retval[1] = 0;
		return (EAGAIN);
	}
	proc_list_unlock();

	/*
	 * Increment the count of procs running with this uid. Don't allow
	 * a nonprivileged user to exceed their current limit, which is
	 * always less than what an rlim_t can hold.
	 * (locking protection is provided by list lock held in chgproccnt)
	 */
	count = chgproccnt(uid, 1);
	if (uid != 0 &&
	    (rlim_t)count > parent->p_rlimit[RLIMIT_NPROC].rlim_cur) {
		(void)chgproccnt(uid, -1);
		return (EAGAIN);
	}

#if CONFIG_MACF
	/*
	 * Determine if MAC policies applied to the process will allow
	 * it to fork.
	 */
	err = mac_proc_check_fork(parent);
	if (err != 0) {
		(void)chgproccnt(uid, -1);
		return (err);
	}
#endif

	/* The newly created process comes with signal lock held */
	if ((newth = cloneproc(parent, 1)) == NULL) {
		/* Failed to create thread */
		(void)chgproccnt(uid, -1);
		return (EAGAIN);
	}

	thread_dup(newth);
	/* child = newth->task->proc; */
	child = (proc_t)(get_bsdtask_info(get_threadtask(newth)));

#if CONFIG_MACF
	/* inform policies of new process sharing this cred/label */
	/* safe to use p_ucred here since child is not running */
	/* JMM - unsafe to assume the association will stay - as */
	/*        there are other ways it can be dropped without */
	/*	  informing the policies. */
	mac_cred_label_associate_fork(child->p_ucred, child);
#endif

	/* propogate change of PID - may get new cred if auditing */
	set_security_token(child);

	AUDIT_ARG(pid, child->p_pid);

	thread_set_child(newth, child->p_pid);

	microtime(&child->p_start);
	microtime(&child->p_stats->p_start);	/* for compat sake */
	child->p_acflag = AFORK;

#if CONFIG_DTRACE
	/*
	 * APPLE NOTE: Solaris does a sprlock() and drops the proc_lock
	 * here. We're cheating a bit and only taking the p_dtrace_sprlock
	 * lock. A full sprlock would task_suspend the parent.
	 */
	lck_mtx_lock(&parent->p_dtrace_sprlock);

	/*
	 * Remove all DTrace tracepoints from the child process. We
	 * need to do this _before_ duplicating USDT providers since
	 * any associated probes may be immediately enabled.
	 */
	if (parent->p_dtrace_count > 0) {
		dtrace_fasttrap_fork(parent, child);
	}

	lck_mtx_unlock(&parent->p_dtrace_sprlock);

	/*
	 * Duplicate any lazy dof(s). This must be done while NOT
	 * holding the parent sprlock! Lock ordering is dtrace_dof_mode_lock,
	 * then sprlock. It is imperative we always call
	 * dtrace_lazy_dofs_duplicate, rather than null check and
	 * call if !NULL. If we NULL test, during lazy dof faulting
	 * we can race with the faulting code and proceed from here to
	 * beyond the helpers copy. The lazy dof faulting will then
	 * fail to copy the helpers to the child process.
	 */
	dtrace_lazy_dofs_duplicate(parent, child);
	
	/*
	 * Duplicate any helper actions and providers. The SFORKING
	 * we set above informs the code to enable USDT probes that
	 * sprlock() may fail because the child is being forked.
	 */
	/*
	 * APPLE NOTE: As best I can tell, Apple's sprlock() equivalent
	 * never fails to find the child. We do not set SFORKING.
	 */
	if (parent->p_dtrace_helpers != NULL && dtrace_helpers_fork) {
		(*dtrace_helpers_fork)(parent, child);
	}

#endif

	/* drop the signal lock on the child */
	proc_signalend(child, 0);
	proc_transend(child, 0);

	/* "Return" to the child */
	(void)thread_resume(newth);

        /* drop the extra references we got during the creation */
        if ((t = (task_t)get_threadtask(newth)) != NULL) {
                task_deallocate(t);
        }
        thread_deallocate(newth);

	proc_knote(parent, NOTE_FORK | child->p_pid);

	retval[0] = child->p_pid;
	retval[1] = 0;			/* flag parent */

	DTRACE_PROC1(create, proc_t, child);

	return (0);
}

/*
 * cloneproc
 *
 * Description: Create a new process from a specified process.
 *
 * Parameters:	parent			The parent process of the process to
 *					be cloned
 *		lock			Whether or not the signal lock was held
 *					when calling cloneproc().
 *
 * Returns:	!NULL			pointer to new child thread
 *		NULL			Failure (unspecified)
 *
 * Note:	On return newly created child process has signal lock held
 *		to block delivery of signal to it if called with lock set.
 *		fork() code needs to explicity remove this lock before
 *		signals can be delivered
 *
 *		In the case of bootstrap, this function can be called from
 *		bsd_utaskbootstrap() in order to bootstrap the first process;
 *		the net effect is to provide a uthread structure for the
 *		kernel process associated with the kernel task.  This results
 *		in a side effect in procdup(), which is why the code is more
 *		complicated at the top of that function.
 */
thread_t
cloneproc(proc_t parent, int lock)
{
	proc_t child;
	thread_t th = NULL;

	if ((child = forkproc(parent,lock)) == NULL) {
		/* Failed to allocate new process */
		goto bad;
	}

	if ((th = procdup(parent, child)) == NULL) {
		/*
		 * Failed to create thread; now we must deconstruct the new
		 * process previously obtained from forkproc().
		 */
		forkproc_free(child, lock);
		goto bad;
	}

	/* make child visible */
	pinsertchild(parent, child);

	/*
	 * Make child runnable, set start time.
	 */
	child->p_stat = SRUN;

bad:
	return(th);
}

/*
 * Destroy a process structure that resulted from a call to forkproc(), but
 * which must be returned to the system because of a subsequent failure
 * preventing it from becoming active.
 *
 * Parameters:	p			The incomplete process from forkproc()
 *		lock			Whether or not the signal lock was held
 *					when calling forkproc().
 *
 * Returns:	(void)
 *
 * Note:	This function should only be used in an error handler following
 *		a call to forkproc().  The 'lock' paramenter should be the same
 *		as the lock parameter passed to forkproc().
 *
 *		Operations occur in reverse order of those in forkproc().
 */
void
forkproc_free(proc_t p, int lock)
{

	/* Drop the signal lock, if it was held */
	if (lock) {
		proc_signalend(p, 0);
		proc_transend(p, 0);
	}

	/*
	 * If we have our own copy of the resource limits structure, we
	 * need to free it.  If it's a shared copy, we need to drop our
	 * reference on it.
	 */
	proc_limitdrop(p, 0);
	p->p_limit = NULL;

#if SYSV_SHM
	/* Need to drop references to the shared memory segment(s), if any */
	if (p->vm_shm) {
		/*
		 * Use shmexec(): we have no address space, so no mappings
		 *
		 * XXX Yes, the routine is badly named.
		 */
		shmexec(p);
	}
#endif

	/* Need to undo the effects of the fdcopy(), if any */
	fdfree(p);

	/*
	 * Drop the reference on a text vnode pointer, if any
	 * XXX This code is broken in forkproc(); see <rdar://4256419>;
	 * XXX if anyone ever uses this field, we will be extremely unhappy.
	 */
	if (p->p_textvp) {
		vnode_rele(p->p_textvp);
		p->p_textvp = NULL;
	}

	/* Stop the profiling clock */
	stopprofclock(p);

	/* Release the credential reference */
	kauth_cred_unref(&p->p_ucred);

	proc_list_lock();
	/* Decrement the count of processes in the system */
	nprocs--;
	proc_list_unlock();

	thread_call_free(p->p_rcall);

	/* Free allocated memory */
	FREE_ZONE(p->p_sigacts, sizeof *p->p_sigacts, M_SIGACTS);
	FREE_ZONE(p->p_stats, sizeof *p->p_stats, M_PSTATS);
	proc_checkdeadrefs(p);
	FREE_ZONE(p, sizeof *p, M_PROC);
}


/*
 * forkproc
 *
 * Description:	Create a new process structure, given a parent process
 *		structure.
 *
 * Parameters:	parent			The parent process
 *		lock			If the signal lock should be taken on
 *					the newly created process.
 *
 * Returns:	!NULL			The new process structure
 *		NULL			Error (insufficient free memory)
 *
 * Note:	When successful, the newly created process structure is
 *		partially initialized; if a caller needs to deconstruct the
 *		returned structure, they must call forkproc_free() to do so.
 */
proc_t
forkproc(proc_t parent, int lock)
{
	struct proc *  child;	/* Our new process */
	static int nextpid = 0, pidwrap = 0, nextpidversion = 0;
	int error = 0;
	struct session *sessp;
	uthread_t uth_parent = (uthread_t)get_bsdthread_info(current_thread());

	MALLOC_ZONE(child, proc_t , sizeof *child, M_PROC, M_WAITOK);
	if (child == NULL) {
		printf("forkproc: M_PROC zone exhausted\n");
		goto bad;
	}
	/* zero it out as we need to insert in hash */
	bzero(child, sizeof *child);

	MALLOC_ZONE(child->p_stats, struct pstats *,
			sizeof *child->p_stats, M_PSTATS, M_WAITOK);
	if (child->p_stats == NULL) {
		printf("forkproc: M_SUBPROC zone exhausted (p_stats)\n");
		FREE_ZONE(child, sizeof *child, M_PROC);
		child = NULL;
		goto bad;
	}
	MALLOC_ZONE(child->p_sigacts, struct sigacts *,
			sizeof *child->p_sigacts, M_SIGACTS, M_WAITOK);
	if (child->p_sigacts == NULL) {
		printf("forkproc: M_SUBPROC zone exhausted (p_sigacts)\n");
		FREE_ZONE(child->p_stats, sizeof *child->p_stats, M_PSTATS);
		FREE_ZONE(child, sizeof *child, M_PROC);
		child = NULL;
		goto bad;
	}
	child->p_rcall = thread_call_allocate((thread_call_func_t)realitexpire, child);
	if (child->p_rcall == NULL) {
		FREE_ZONE(child->p_sigacts, sizeof *child->p_sigacts, M_SIGACTS);
		FREE_ZONE(child->p_stats, sizeof *child->p_stats, M_PSTATS);
		FREE_ZONE(child, sizeof *child, M_PROC);
		child = NULL;
		goto bad;
	}


	/*
	 * Find an unused PID.  
	 */

	proc_list_lock();

	nextpid++;
retry:
	/*
	 * If the process ID prototype has wrapped around,
	 * restart somewhat above 0, as the low-numbered procs
	 * tend to include daemons that don't exit.
	 */
	if (nextpid >= PID_MAX) {
		nextpid = 100;
		pidwrap = 1;
	}
	if (pidwrap != 0) {

		/* if the pid stays in hash both for zombie and runniing state */
		if  (pfind_locked(nextpid) != PROC_NULL) {
			nextpid++;
			goto retry;
		}

		if (pgfind_internal(nextpid) != PGRP_NULL) {
			nextpid++;
			goto retry;
		}	
		if (session_find_internal(nextpid) != SESSION_NULL) {
			nextpid++;
			goto retry;
		}	
	}
	nprocs++;
	child->p_pid = nextpid;
	child->p_idversion = nextpidversion++;
#if 1
	if (child->p_pid != 0) {
		if (pfind_locked(child->p_pid) != PROC_NULL)
			panic("proc in the list already\n");
	}
#endif
	/* Insert in the hash */
	child->p_listflag |= (P_LIST_INHASH | P_LIST_INCREATE);
	LIST_INSERT_HEAD(PIDHASH(child->p_pid), child, p_hash);
	proc_list_unlock();


	/*
	 * We've identified the PID we are going to use; initialize the new
	 * process structure.
	 */
	child->p_stat = SIDL;
	child->p_pgrpid = PGRPID_DEAD;

	/*
	 * The zero'ing of the proc was at the allocation time due to need for insertion
	 * to hash. Copy the section that is to be copied directly from the parent.
	 */
	bcopy(&parent->p_startcopy, &child->p_startcopy,
	    (unsigned) ((caddr_t)&child->p_endcopy - (caddr_t)&child->p_startcopy));

	/*
	 * Some flags are inherited from the parent.
	 * Duplicate sub-structures as needed.
	 * Increase reference counts on shared objects.
	 * The p_stats and p_sigacts substructs are set in vm_fork.
	 */
	child->p_flag = (parent->p_flag & (P_LP64 | P_TRANSLATED | P_AFFINITY));
	if (parent->p_flag & P_PROFIL)
		startprofclock(child);
	/*
	 * Note that if the current thread has an assumed identity, this
	 * credential will be granted to the new process.
	 */
	child->p_ucred = kauth_cred_get_with_ref();

	lck_mtx_init(&child->p_mlock, proc_lck_grp, proc_lck_attr);
	lck_mtx_init(&child->p_fdmlock, proc_lck_grp, proc_lck_attr);
#if CONFIG_DTRACE
	lck_mtx_init(&child->p_dtrace_sprlock, proc_lck_grp, proc_lck_attr);
#endif
	lck_spin_init(&child->p_slock, proc_lck_grp, proc_lck_attr);
	klist_init(&child->p_klist);

	if (child->p_textvp != NULLVP) {
		/* bump references to the text vnode */
		/* Need to hold iocount across the ref call */
		if (vnode_getwithref(child->p_textvp) == 0) {
			error = vnode_ref(child->p_textvp);
			vnode_put(child->p_textvp);
			if (error != 0)
				child->p_textvp = NULLVP;
		}
	}

	/* XXX may fail to copy descriptors to child */
	child->p_fd = fdcopy(parent, uth_parent->uu_cdir);

#if SYSV_SHM
	if (parent->vm_shm) {
		/* XXX may fail to attach shm to child */
		(void)shmfork(parent,child);
	}
#endif
	/*
	 * inherit the limit structure to child
	 */
	proc_limitfork(parent, child);

	if (child->p_limit->pl_rlimit[RLIMIT_CPU].rlim_cur != RLIM_INFINITY) {
		uint64_t rlim_cur = child->p_limit->pl_rlimit[RLIMIT_CPU].rlim_cur;
		child->p_rlim_cpu.tv_sec = (rlim_cur > __INT_MAX__) ? __INT_MAX__ : rlim_cur;
	}

	bzero(&child->p_stats->pstat_startzero,
	    (unsigned) ((caddr_t)&child->p_stats->pstat_endzero -
	    (caddr_t)&child->p_stats->pstat_startzero));

	bzero(&child->p_stats->user_p_prof, sizeof(struct user_uprof));

	if (parent->p_sigacts != NULL)
		(void)memcpy(child->p_sigacts,
				parent->p_sigacts, sizeof *child->p_sigacts);
	else
		(void)memset(child->p_sigacts, 0, sizeof *child->p_sigacts);

	sessp = proc_session(parent);
	if (sessp->s_ttyvp != NULL && parent->p_flag & P_CONTROLT)
		OSBitOrAtomic(P_CONTROLT, (UInt32 *)&child->p_flag);
	session_rele(sessp);

	/* block all signals to reach the process */
	if (lock) {
		proc_signalstart(child, 0);
		proc_transstart(child, 0);
	}

	TAILQ_INIT(&child->p_uthlist);
	TAILQ_INIT(&child->aio_activeq);
	TAILQ_INIT(&child->aio_doneq);
	/* Inherit the parent flags for code sign */
	child->p_csflags = parent->p_csflags;
	child->p_wqthread = parent->p_wqthread;
	child->p_threadstart = parent->p_threadstart;
	child->p_pthsize = parent->p_pthsize;
	workqueue_init_lock(child);

#if CONFIG_LCTX
	child->p_lctx = NULL;
	/* Add new process to login context (if any). */
	if (parent->p_lctx != NULL) {
		LCTX_LOCK(parent->p_lctx);
		enterlctx(child, parent->p_lctx, 0);
	}
#endif

bad:
	return(child);
}

void
proc_lock(proc_t p)
{
	lck_mtx_lock(&p->p_mlock);
}

void
proc_unlock(proc_t p)
{
	lck_mtx_unlock(&p->p_mlock);
}

void
proc_spinlock(proc_t p)
{
	lck_spin_lock(&p->p_slock);
}

void
proc_spinunlock(proc_t p)
{
	lck_spin_unlock(&p->p_slock);
}

void 
proc_list_lock(void)
{
	lck_mtx_lock(proc_list_mlock);
}

void 
proc_list_unlock(void)
{
	lck_mtx_unlock(proc_list_mlock);
}

#include <kern/zalloc.h>

struct zone	*uthread_zone;
static int uthread_zone_inited = 0;

static void
uthread_zone_init(void)
{
	if (!uthread_zone_inited) {
		uthread_zone = zinit(sizeof(struct uthread),
					THREAD_MAX * sizeof(struct uthread),
					THREAD_CHUNK * sizeof(struct uthread),
					"uthreads");
		uthread_zone_inited = 1;
	}
}

void *
uthread_alloc(task_t task, thread_t thread)
{
	proc_t p;
	uthread_t uth;
	uthread_t uth_parent;
	void *ut;

	if (!uthread_zone_inited)
		uthread_zone_init();

	ut = (void *)zalloc(uthread_zone);
	bzero(ut, sizeof(struct uthread));

	p = (proc_t) get_bsdtask_info(task);
	uth = (uthread_t)ut;

	/*
	 * Thread inherits credential from the creating thread, if both
	 * are in the same task.
	 *
	 * If the creating thread has no credential or is from another
	 * task we can leave the new thread credential NULL.  If it needs
	 * one later, it will be lazily assigned from the task's process.
	 */
	uth_parent = (uthread_t)get_bsdthread_info(current_thread());
	if (task == current_task() && 
	    uth_parent != NULL &&
	    IS_VALID_CRED(uth_parent->uu_ucred)) {
		/*
		 * XXX The new thread is, in theory, being created in context
		 * XXX of parent thread, so a direct reference to the parent
		 * XXX is OK.
		 */
		kauth_cred_ref(uth_parent->uu_ucred);
		uth->uu_ucred = uth_parent->uu_ucred;
		/* the credential we just inherited is an assumed credential */
		if (uth_parent->uu_flag & UT_SETUID)
			uth->uu_flag |= UT_SETUID;
	} else {
		uth->uu_ucred = NOCRED;
	}

	
	if ((task != kernel_task) && p) {
		
		proc_lock(p);
		if (uth_parent) {
			if (uth_parent->uu_flag & UT_SAS_OLDMASK)
				uth->uu_sigmask = uth_parent->uu_oldmask;
			else
				uth->uu_sigmask = uth_parent->uu_sigmask;
		}
		uth->uu_context.vc_thread = thread;
		TAILQ_INSERT_TAIL(&p->p_uthlist, uth, uu_list);
		proc_unlock(p);

#if CONFIG_DTRACE
		if (p->p_dtrace_ptss_pages != NULL) {
			uth->t_dtrace_scratch = dtrace_ptss_claim_entry(p);
		}
#endif
	}

	return (ut);
}


/* 
 * This routine frees all the BSD context in uthread except the credential.
 * It does not free the uthread structure as well
 */
void
uthread_cleanup(task_t task, void *uthread, void * bsd_info)
{
	struct _select *sel;
	uthread_t uth = (uthread_t)uthread;
	proc_t p = (proc_t)bsd_info;


	if (uth->uu_lowpri_window) {
	        /*
		 * task is marked as a low priority I/O type
		 * and we've somehow managed to not dismiss the throttle
		 * through the normal exit paths back to user space...
		 * no need to throttle this thread since its going away
		 * but we do need to update our bookeeping w/r to throttled threads
		 */
		throttle_lowpri_io(FALSE);
	}
	/*
	 * Per-thread audit state should never last beyond system
	 * call return.  Since we don't audit the thread creation/
	 * removal, the thread state pointer should never be
	 * non-NULL when we get here.
	 */
	assert(uth->uu_ar == NULL);

	sel = &uth->uu_select;
	/* cleanup the select bit space */
	if (sel->nbytes) {
		FREE(sel->ibits, M_TEMP);
		FREE(sel->obits, M_TEMP);
		sel->nbytes = 0;
	}

	if (uth->uu_cdir) {
		vnode_rele(uth->uu_cdir);
		uth->uu_cdir = NULLVP;
	}

	if (uth->uu_allocsize && uth->uu_wqset){
		kfree(uth->uu_wqset, uth->uu_allocsize);
		sel->count = 0;
		uth->uu_allocsize = 0;
		uth->uu_wqset = 0;
		sel->wql = 0;
	}


	if ((task != kernel_task) && p) {

		if (((uth->uu_flag & UT_VFORK) == UT_VFORK) && (uth->uu_proc != PROC_NULL))  {
			vfork_exit_internal(uth->uu_proc, 0, 1);
		}
		if (get_bsdtask_info(task) == p) { 
			proc_lock(p);
			TAILQ_REMOVE(&p->p_uthlist, uth, uu_list);
			proc_unlock(p);
		}
#if CONFIG_DTRACE
		if (uth->t_dtrace_scratch != NULL) {
			dtrace_ptss_release_entry(p, uth->t_dtrace_scratch);
		}
#endif
	}
}

/* This routine releases the credential stored in uthread */
void
uthread_cred_free(void *uthread)
{
	uthread_t uth = (uthread_t)uthread;

	/* and free the uthread itself */
	if (IS_VALID_CRED(uth->uu_ucred)) {
		kauth_cred_t oldcred = uth->uu_ucred;
		uth->uu_ucred = NOCRED;
		kauth_cred_unref(&oldcred);
	}
}

/* This routine frees the uthread structure held in thread structure */
void
uthread_zone_free(void *uthread)
{
	/* and free the uthread itself */
	zfree(uthread_zone, uthread);
}
