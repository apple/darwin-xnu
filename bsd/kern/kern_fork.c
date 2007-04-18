/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#if KTRACE
#include <sys/ktrace.h>
#endif

#include <bsm/audit_kernel.h>

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/zalloc.h>

#include <machine/spl.h>

#include <vm/vm_protos.h>       // for vm_map_commpage64

thread_t cloneproc(struct proc *, int); 
struct proc * forkproc(struct proc *, int);
thread_t procdup(struct proc *child, struct proc *parent);

#define	DOFORK	0x1	/* fork() system call */
#define	DOVFORK	0x2	/* vfork() system call */
static int fork1(struct proc *, long, register_t *);

/*
 * fork system call.
 */
int
fork(struct proc *p, __unused void *uap, register_t *retval)
{
	return (fork1(p, (long)DOFORK, retval));
}

/*
 * vfork system call
 */
int
vfork(struct proc *p, void *uap, register_t *retval)
{
	register struct proc * newproc;
	register uid_t uid;
	thread_t cur_act = (thread_t)current_thread();
	int count;
	task_t t;
	uthread_t ut;

	/*
	 * Although process entries are dynamically created, we still keep
	 * a global limit on the maximum number we will create.  Don't allow
	 * a nonprivileged user to use the last process; don't let root
	 * exceed the limit. The variable nprocs is the current number of
	 * processes, maxproc is the limit.
	 */
	uid = kauth_cred_get()->cr_ruid;
	if ((nprocs >= maxproc - 1 && uid != 0) || nprocs >= maxproc) {
		tablefull("proc");
		retval[1] = 0;
		return (EAGAIN);
	}

	/*
	 * Increment the count of procs running with this uid. Don't allow
	 * a nonprivileged user to exceed their current limit.
	 */
	count = chgproccnt(uid, 1);
	if (uid != 0 && count > p->p_rlimit[RLIMIT_NPROC].rlim_cur) {
		(void)chgproccnt(uid, -1);
		return (EAGAIN);
	}

	ut = (struct uthread *)get_bsdthread_info(cur_act);
	if (ut->uu_flag & UT_VFORK) {
		printf("vfork called recursively by %s\n", p->p_comm);
		(void)chgproccnt(uid, -1);
		return (EINVAL);
	}
	p->p_flag  |= P_VFORK;
	p->p_vforkcnt++;

	/* The newly created process comes with signal lock held */
	newproc = (struct proc *)forkproc(p,1);

	AUDIT_ARG(pid, newproc->p_pid);

	LIST_INSERT_AFTER(p, newproc, p_pglist);
	newproc->p_pptr = p;
	newproc->task = p->task;
	LIST_INSERT_HEAD(&p->p_children, newproc, p_sibling);
	LIST_INIT(&newproc->p_children);
	LIST_INSERT_HEAD(&allproc, newproc, p_list);
	LIST_INSERT_HEAD(PIDHASH(newproc->p_pid), newproc, p_hash);
	TAILQ_INIT(& newproc->p_evlist);
	newproc->p_stat = SRUN;
	newproc->p_flag  |= P_INVFORK;
	newproc->p_vforkact = cur_act;

	ut->uu_flag |= UT_VFORK;
	ut->uu_proc = newproc;
	ut->uu_userstate = (void *)act_thread_csave();
	ut->uu_vforkmask = ut->uu_sigmask;

	/* temporarily drop thread-set-id state */
	if (ut->uu_flag & UT_SETUID) {
		ut->uu_flag |= UT_WASSETUID;
		ut->uu_flag &= ~UT_SETUID;
	}
	
	thread_set_child(cur_act, newproc->p_pid);

	microtime(&newproc->p_stats->p_start);
	newproc->p_acflag = AFORK;

	/*
	 * Preserve synchronization semantics of vfork.  If waiting for
	 * child to exec or exit, set P_PPWAIT on child, and sleep on our
	 * proc (in case of exit).
	 */
	newproc->p_flag |= P_PPWAIT;

	/* drop the signal lock on the child */
	signal_unlock(newproc);

	retval[0] = newproc->p_pid;
	retval[1] = 1;			/* mark child */

	return (0);
}

/*
 * Return to parent vfork ehread()
 */
void
vfork_return(__unused thread_t th_act, struct proc *p, struct proc *p2,
	register_t *retval)
{
	thread_t cur_act = (thread_t)current_thread();
	uthread_t ut;
	
	ut = (struct uthread *)get_bsdthread_info(cur_act);

	act_thread_catt(ut->uu_userstate);

	/* Make sure only one at this time */
	p->p_vforkcnt--;
	if (p->p_vforkcnt <0)
		panic("vfork cnt is -ve");
	if (p->p_vforkcnt <=0)
		p->p_flag  &= ~P_VFORK;
	ut->uu_userstate = 0;
	ut->uu_flag &= ~UT_VFORK;
	/* restore thread-set-id state */
	if (ut->uu_flag & UT_WASSETUID) {
		ut->uu_flag |= UT_SETUID;
		ut->uu_flag &= UT_WASSETUID;
	}
	ut->uu_proc = 0;
	ut->uu_sigmask = ut->uu_vforkmask;
	p2->p_flag  &= ~P_INVFORK;
	p2->p_vforkact = (void *)0;

	thread_set_parent(cur_act, p2->p_pid);

	if (retval) {
		retval[0] = p2->p_pid;
		retval[1] = 0;			/* mark parent */
	}

	return;
}

thread_t
procdup(struct proc *child, struct proc *parent)
{
	thread_t		thread;
	task_t			task;
 	kern_return_t	result;

	if (parent->task == kernel_task)
		result = task_create_internal(TASK_NULL, FALSE, FALSE, &task);
	else
		result = task_create_internal(parent->task, TRUE, (parent->p_flag & P_LP64), &task);
	if (result != KERN_SUCCESS)
	    printf("fork/procdup: task_create failed. Code: 0x%x\n", result);
	child->task = task;
	/* task->proc = child; */
	set_bsdtask_info(task, child);
	if (parent->p_flag & P_LP64) {
		task_set_64bit(task, TRUE);
		vm_map_set_64bit(get_task_map(task));
		child->p_flag |= P_LP64;
                /* LP64todo - clean up this hacked mapping of commpage */
		pmap_map_sharedpage(task, get_map_pmap(get_task_map(task)));
                vm_map_commpage64(get_task_map(task));
	} else {
		task_set_64bit(task, FALSE);
		vm_map_set_32bit(get_task_map(task));
		child->p_flag &= ~P_LP64;
#ifdef __i386__
		/*
		 * On Intel, the comm page doesn't get mapped automatically
		 * because it goes beyond the end of the VM map in the current
		 * 3GB/1GB address space model.
		 * XXX This explicit mapping will probably become unnecessary
		 * when we switch to the new 4GB/4GB address space model.
		 */
		vm_map_commpage32(get_task_map(task));
#endif	/* __i386__ */
	}
	if (child->p_nice != 0)
		resetpriority(child);
		
	result = thread_create(task, &thread);
	if (result != KERN_SUCCESS)
	    printf("fork/procdup: thread_create failed. Code: 0x%x\n", result);

	return(thread);
}


static int
fork1(p1, flags, retval)
	struct proc *p1;
	long flags;
	register_t *retval;
{
	register struct proc *p2;
	register uid_t uid;
	thread_t newth;
	int count;
	task_t t;

	/*
	 * Although process entries are dynamically created, we still keep
	 * a global limit on the maximum number we will create.  Don't allow
	 * a nonprivileged user to use the last process; don't let root
	 * exceed the limit. The variable nprocs is the current number of
	 * processes, maxproc is the limit.
	 */
	uid = kauth_cred_get()->cr_ruid;
	if ((nprocs >= maxproc - 1 && uid != 0) || nprocs >= maxproc) {
		tablefull("proc");
		retval[1] = 0;
		return (EAGAIN);
	}

	/*
	 * Increment the count of procs running with this uid. Don't allow
	 * a nonprivileged user to exceed their current limit.
	 */
	count = chgproccnt(uid, 1);
	if (uid != 0 && count > p1->p_rlimit[RLIMIT_NPROC].rlim_cur) {
		(void)chgproccnt(uid, -1);
		return (EAGAIN);
	}

	/* The newly created process comes with signal lock held */
	newth = cloneproc(p1, 1);
	thread_dup(newth);
	/* p2 = newth->task->proc; */
	p2 = (struct proc *)(get_bsdtask_info(get_threadtask(newth)));
	set_security_token(p2);         /* propagate change of PID */

	AUDIT_ARG(pid, p2->p_pid);

	thread_set_child(newth, p2->p_pid);

	microtime(&p2->p_stats->p_start);
	p2->p_acflag = AFORK;

	/*
	 * Preserve synchronization semantics of vfork.  If waiting for
	 * child to exec or exit, set P_PPWAIT on child, and sleep on our
	 * proc (in case of exit).
	 */
	if (flags == DOVFORK)
		p2->p_flag |= P_PPWAIT;
	/* drop the signal lock on the child */
	signal_unlock(p2);

	(void) thread_resume(newth);

        /* drop the extra references we got during the creation */
        if ((t = (task_t)get_threadtask(newth)) != NULL) {
                task_deallocate(t);
        }
        thread_deallocate(newth);

	KNOTE(&p1->p_klist, NOTE_FORK | p2->p_pid);

	while (p2->p_flag & P_PPWAIT)
		tsleep(p1, PWAIT, "ppwait", 0);

	retval[0] = p2->p_pid;
	retval[1] = 0;			/* mark parent */

	return (0);
}

/*
 * cloneproc()
 *
 * Create a new process from a specified process.
 * On return newly created child process has signal
 * lock held to block delivery of signal to it if called with
 * lock set. fork() code needs to explicity remove this lock 
 * before signals can be delivered
 */
thread_t
cloneproc(p1, lock)
	register struct proc *p1;
	register int lock;
{
	register struct proc *p2;
	thread_t th;

	p2 = (struct proc *)forkproc(p1,lock);


	th = procdup(p2, p1);	/* child, parent */

	LIST_INSERT_AFTER(p1, p2, p_pglist);
	p2->p_pptr = p1;
	LIST_INSERT_HEAD(&p1->p_children, p2, p_sibling);
	LIST_INIT(&p2->p_children);
	LIST_INSERT_HEAD(&allproc, p2, p_list);
	LIST_INSERT_HEAD(PIDHASH(p2->p_pid), p2, p_hash);
	TAILQ_INIT(&p2->p_evlist);
	/*
	 * Make child runnable, set start time.
	 */
	p2->p_stat = SRUN;

	return(th);
}

struct proc *
forkproc(p1, lock)
	register struct proc *p1;
	register int lock;
{
	register struct proc *p2, *newproc;
	static int nextpid = 0, pidchecked = 0;

	/* Allocate new proc. */
	MALLOC_ZONE(newproc, struct proc *,
			sizeof *newproc, M_PROC, M_WAITOK);
	if (newproc == NULL)
		panic("forkproc: M_PROC zone exhausted");
	MALLOC_ZONE(newproc->p_stats, struct pstats *,
			sizeof *newproc->p_stats, M_SUBPROC, M_WAITOK);
	if (newproc->p_stats == NULL)
		panic("forkproc: M_SUBPROC zone exhausted (p_stats)");
	MALLOC_ZONE(newproc->p_sigacts, struct sigacts *,
			sizeof *newproc->p_sigacts, M_SUBPROC, M_WAITOK);
	if (newproc->p_sigacts == NULL)
		panic("forkproc: M_SUBPROC zone exhausted (p_sigacts)");

	/*
	 * Find an unused process ID.  We remember a range of unused IDs
	 * ready to use (from nextpid+1 through pidchecked-1).
	 */
	nextpid++;
retry:
	/*
	 * If the process ID prototype has wrapped around,
	 * restart somewhat above 0, as the low-numbered procs
	 * tend to include daemons that don't exit.
	 */
	if (nextpid >= PID_MAX) {
		nextpid = 100;
		pidchecked = 0;
	}
	if (nextpid >= pidchecked) {
		int doingzomb = 0;

		pidchecked = PID_MAX;
		/*
		 * Scan the active and zombie procs to check whether this pid
		 * is in use.  Remember the lowest pid that's greater
		 * than nextpid, so we can avoid checking for a while.
		 */
		p2 = allproc.lh_first;
again:
		for (; p2 != 0; p2 = p2->p_list.le_next) {
			while (p2->p_pid == nextpid ||
			    p2->p_pgrp->pg_id == nextpid ||
				p2->p_session->s_sid == nextpid) {
				nextpid++;
				if (nextpid >= pidchecked)
					goto retry;
			}
			if (p2->p_pid > nextpid && pidchecked > p2->p_pid)
				pidchecked = p2->p_pid;
			if (p2->p_pgrp && p2->p_pgrp->pg_id > nextpid && 
			    pidchecked > p2->p_pgrp->pg_id)
				pidchecked = p2->p_pgrp->pg_id;
			if (p2->p_session->s_sid > nextpid &&
				pidchecked > p2->p_session->s_sid)
				pidchecked = p2->p_session->s_sid;
		}
		if (!doingzomb) {
			doingzomb = 1;
			p2 = zombproc.lh_first;
			goto again;
		}
	}

	nprocs++;
	p2 = newproc;
	p2->p_stat = SIDL;
	p2->p_shutdownstate = 0;
	p2->p_pid = nextpid;

	/*
	 * Make a proc table entry for the new process.
	 * Start by zeroing the section of proc that is zero-initialized,
	 * then copy the section that is copied directly from the parent.
	 */
	bzero(&p2->p_startzero,
	    (unsigned) ((caddr_t)&p2->p_endzero - (caddr_t)&p2->p_startzero));
	bcopy(&p1->p_startcopy, &p2->p_startcopy,
	    (unsigned) ((caddr_t)&p2->p_endcopy - (caddr_t)&p2->p_startcopy));
	p2->vm_shm = (void *)NULL; /* Make sure it is zero */

	/*
	 * Some flags are inherited from the parent.
	 * Duplicate sub-structures as needed.
	 * Increase reference counts on shared objects.
	 * The p_stats and p_sigacts substructs are set in vm_fork.
	 */
	p2->p_flag = (p1->p_flag & (P_LP64 | P_TRANSLATED | P_AFFINITY));
	if (p1->p_flag & P_PROFIL)
		startprofclock(p2);
	/*
	 * Note that if the current thread has an assumed identity, this
	 * credential will be granted to the new process.
	 */
	p2->p_ucred = kauth_cred_get_with_ref();

	lck_mtx_init(&p2->p_mlock, proc_lck_grp, proc_lck_attr);
	lck_mtx_init(&p2->p_fdmlock, proc_lck_grp, proc_lck_attr);
	klist_init(&p2->p_klist);

	/* bump references to the text vnode */
	p2->p_textvp = p1->p_textvp;
	if (p2->p_textvp) {
		vnode_rele(p2->p_textvp);
	}
	/* XXX may fail to copy descriptors to child */
	p2->p_fd = fdcopy(p1);

	if (p1->vm_shm) {
		/* XXX may fail to attach shm to child */
		(void)shmfork(p1,p2);
	}
	/*
	 * If p_limit is still copy-on-write, bump refcnt,
	 * otherwise get a copy that won't be modified.
	 * (If PL_SHAREMOD is clear, the structure is shared
	 * copy-on-write.)
	 */
	if (p1->p_limit->p_lflags & PL_SHAREMOD)
		p2->p_limit = limcopy(p1->p_limit);
	else {
		p2->p_limit = p1->p_limit;
		p2->p_limit->p_refcnt++;
	}

	bzero(&p2->p_stats->pstat_startzero,
	    (unsigned) ((caddr_t)&p2->p_stats->pstat_endzero -
	    (caddr_t)&p2->p_stats->pstat_startzero));
	bcopy(&p1->p_stats->pstat_startcopy, &p2->p_stats->pstat_startcopy,
	    ((caddr_t)&p2->p_stats->pstat_endcopy -
	     (caddr_t)&p2->p_stats->pstat_startcopy));

	bzero(&p2->p_stats->user_p_prof, sizeof(struct user_uprof));

	if (p1->p_sigacts != NULL)
		(void)memcpy(p2->p_sigacts,
				p1->p_sigacts, sizeof *p2->p_sigacts);
	else
		(void)memset(p2->p_sigacts, 0, sizeof *p2->p_sigacts);

	if (p1->p_session->s_ttyvp != NULL && p1->p_flag & P_CONTROLT)
		p2->p_flag |= P_CONTROLT;

	p2->p_argslen = p1->p_argslen;
	p2->p_argc = p1->p_argc;
	p2->p_xstat = 0;
	p2->p_ru = NULL;

	p2->p_debugger = 0;	/* don't inherit */
	lockinit(&p2->signal_lock, PVM, "signal", 0, 0);
	/* block all signals to reach the process */
	if (lock)
		signal_lock(p2);
	p2->sigwait = FALSE;
	p2->sigwait_thread = NULL;
	p2->exit_thread = NULL;
	p2->user_stack = p1->user_stack;
	p2->p_vforkcnt = 0;
	p2->p_vforkact = 0;
	p2->p_lflag  = 0;
	p2->p_ladvflag  = 0;
	p2->p_internalref  = 0;
	TAILQ_INIT(&p2->p_uthlist);
	TAILQ_INIT(&p2->aio_activeq);
	TAILQ_INIT(&p2->aio_doneq);
	p2->aio_active_count = 0;
	p2->aio_done_count = 0;

#if KTRACE
	/*
	 * Copy traceflag and tracefile if enabled.
	 * If not inherited, these were zeroed above.
	 */
	if (p1->p_traceflag&KTRFAC_INHERIT) {
		p2->p_traceflag = p1->p_traceflag;
		if ((p2->p_tracep = p1->p_tracep) != NULL) {
		        vnode_ref(p2->p_tracep);
		}
	}
#endif
	return(p2);

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

#include <kern/zalloc.h>

struct zone	*uthread_zone;
int uthread_zone_inited = 0;

void
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
uthread_alloc(task_t task, thread_t thr_act )
{
	struct proc *p;
	struct uthread *uth, *uth_parent;
	void *ut;
	boolean_t funnel_state;

	if (!uthread_zone_inited)
		uthread_zone_init();

	ut = (void *)zalloc(uthread_zone);
	bzero(ut, sizeof(struct uthread));

	p = (struct proc *) get_bsdtask_info(task);
	uth = (struct uthread *)ut;

	/*
	 * Thread inherits credential from the creating thread, if both
	 * are in the same task.
	 *
	 * If the creating thread has no credential or is from another
	 * task we can leave the new thread credential NULL.  If it needs
	 * one later, it will be lazily assigned from the task's process.
	 */
	uth_parent = (struct uthread *)get_bsdthread_info(current_thread());
	if ((task == current_task()) && 
	    (uth_parent != NULL) &&
	    (IS_VALID_CRED(uth_parent->uu_ucred))) {
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
	
	if (task != kernel_task) {
		
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
		if (uth_parent) {
			if (uth_parent->uu_flag & UT_SAS_OLDMASK)
				uth->uu_sigmask = uth_parent->uu_oldmask;
			else
				uth->uu_sigmask = uth_parent->uu_sigmask;
		}
		uth->uu_act = thr_act;
		//signal_lock(p);
		if (p) {
			TAILQ_INSERT_TAIL(&p->p_uthlist, uth, uu_list);
		}
		//signal_unlock(p);
		(void)thread_funnel_set(kernel_flock, funnel_state);
	}

	return (ut);
}


void
uthread_free(task_t task, void *uthread, void * bsd_info)
{
	struct _select *sel;
	struct uthread *uth = (struct uthread *)uthread;
	struct proc * p = (struct proc *)bsd_info;
	boolean_t funnel_state;

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
	}

	if (sel->allocsize && sel->wqset){
		kfree(sel->wqset, sel->allocsize);
		sel->count = 0;
		sel->allocsize = 0;
		sel->wqset = 0;
		sel->wql = 0;
	}

	if (IS_VALID_CRED(uth->uu_ucred)) {
		kauth_cred_t oldcred = uth->uu_ucred;
		uth->uu_ucred = NOCRED;
		kauth_cred_unref(&oldcred);
	}

	if ((task != kernel_task) && p) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
		//signal_lock(p);
		TAILQ_REMOVE(&p->p_uthlist, uth, uu_list);
		//signal_unlock(p);
		(void)thread_funnel_set(kernel_flock, funnel_state);
	}
	/* and free the uthread itself */
	zfree(uthread_zone, uthread);
}
