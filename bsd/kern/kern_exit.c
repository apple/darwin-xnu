/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * @APPLE_LICENSE_HEADER_END@
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
 *	@(#)kern_exit.c	8.7 (Berkeley) 2/12/94
 */
 
#include <machine/reg.h>
#include <machine/psl.h>

#include "compat_43.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/tty.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/kernel.h>
#include <sys/buf.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <mach/mach_types.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/assert.h>

extern char init_task_failure_data[];
int exit1 __P((struct proc *, int, int *));

/*
 * exit --
 *	Death of process.
 */
struct exit_args {
	int	rval;
};
void
exit(p, uap, retval)
	struct proc *p;
	struct exit_args *uap;
	int *retval;
{
	exit1(p, W_EXITCODE(uap->rval, 0), retval);

	/* drop funnel befewo we return */
	thread_funnel_set(kernel_flock, FALSE);
	thread_exception_return();
	/* NOTREACHED */
	while (TRUE)
		thread_block(0);
	/* NOTREACHED */
}

/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */
int
exit1(p, rv, retval)
	register struct proc *p;
	int rv;
	int * retval;
{
	register struct proc *q, *nq;
	thread_t self = current_thread();
	thread_act_t th_act_self = current_act();
	struct task *task = p->task;
	register int i,s;
	struct uthread *ut;

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	 ut = get_bsdthread_info(th_act_self);
	 if (ut->uu_flag & P_VFORK) {
			vfork_exit(p, rv);
			vfork_return(th_act_self, p->p_pptr, p , retval);
			unix_syscall_return(0);
			/* NOT REACHED */
	 }
        signal_lock(p);
	while (p->exit_thread != self) {
		if (sig_try_locked(p) <= 0) {
			if (get_threadtask(th_act_self) != task) {
                                signal_unlock(p);
				return(0);
                        }
			signal_unlock(p);
			thread_terminate(th_act_self);
			thread_funnel_set(kernel_flock, FALSE);
			thread_exception_return();
			/* NOTREACHED */
		}
		sig_lock_to_exit(p);
	}
        signal_unlock(p);
	if (p->p_pid == 1) {
		printf("pid 1 exited (signal %d, exit %d)",
		    WTERMSIG(rv), WEXITSTATUS(rv));
		panic("init died\nState at Last Exception:\n\n%s", 
							init_task_failure_data);
	}

	s = splsched();
	p->p_flag |= P_WEXIT;
	splx(s);
	proc_prepareexit(p);
	p->p_xstat = rv;

	/* task terminate will call proc_terminate and that cleans it up */
	task_terminate_internal(task);

	/*
	 * we come back and returns to AST which 
	 * should cleanup the rest 
	 */
#if 0
	if (task == current_task()) {
		thread_exception_return();
		/*NOTREACHED*/
	}

	while (task == current_task()) {
		thread_terminate_self();
		/*NOTREACHED*/
	}
#endif
	return(0);
}

void
proc_prepareexit(struct proc *p) 
{
	int s;
	struct uthread *ut;
	thread_t self = current_thread();
	thread_act_t th_act_self = current_act();


	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */
	LIST_REMOVE(p, p_list);
	LIST_REMOVE(p, p_hash);

#ifdef PGINPROF
	vmsizmon();
#endif
	/*
	 * If parent is waiting for us to exit or exec,
	 * P_PPWAIT is set; we will wakeup the parent below.
	 */
	p->p_flag &= ~(P_TRACED | P_PPWAIT);
	p->p_sigignore = ~0;
	p->p_siglist = 0;
	ut = get_bsdthread_info(th_act_self);
	ut->uu_sig = 0;
	untimeout(realitexpire, (caddr_t)p);

}

void 
proc_exit(struct proc *p)
{
	register struct proc *q, *nq;
	thread_t self = current_thread();
	thread_act_t th_act_self = current_act();
	struct task *task = p->task;
	register int i,s;
	struct uthread *ut;
	boolean_t funnel_state;

	/* This can happen if thread_terminate of the single thread
	 * process 
	 */

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	if( !(p->p_flag & P_WEXIT)) {
		s = splsched();
		p->p_flag |= P_WEXIT;
		splx(s);
		proc_prepareexit(p);	
	}

	MALLOC_ZONE(p->p_ru, struct rusage *,
			sizeof (*p->p_ru), M_ZOMBIE, M_WAITOK);

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdfree(p);

	/* Close ref SYSV Shared memory*/
	if (p->vm_shm)
		shmexit(p);
	
	if (SESS_LEADER(p)) {
		register struct session *sp = p->p_session;

		if (sp->s_ttyvp) {
			/*
			 * Controlling process.
			 * Signal foreground pgrp,
			 * drain controlling terminal
			 * and revoke access to controlling terminal.
			 */
			if (sp->s_ttyp->t_session == sp) {
				if (sp->s_ttyp->t_pgrp)
					pgsignal(sp->s_ttyp->t_pgrp, SIGHUP, 1);
				(void) ttywait(sp->s_ttyp);
				/*
				 * The tty could have been revoked
				 * if we blocked.
				 */
				if (sp->s_ttyvp)
					VOP_REVOKE(sp->s_ttyvp, REVOKEALL);
			}
			if (sp->s_ttyvp)
				vrele(sp->s_ttyvp);
			sp->s_ttyvp = NULL;
			/*
			 * s_ttyp is not zero'd; we use this to indicate
			 * that the session once had a controlling terminal.
			 * (for logging and informational purposes)
			 */
		}
		sp->s_leader = NULL;
	}

	fixjobc(p, p->p_pgrp, 0);
	p->p_rlimit[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
#if KTRACE
	/* 
	 * release trace file
	 */
	p->p_traceflag = 0;	/* don't trace the vrele() */
	if (p->p_tracep)
		vrele(p->p_tracep);
#endif


	q = p->p_children.lh_first;
	if (q)		/* only need this if any child is S_ZOMB */
		wakeup((caddr_t) initproc);
	for (; q != 0; q = nq) {
		nq = q->p_sibling.le_next;
		proc_reparent(q, initproc);
		/*
		 * Traced processes are killed
		 * since their existence means someone is messing up.
		 */
		if (q->p_flag & P_TRACED) {
			q->p_flag &= ~P_TRACED;
			if (q->sigwait_thread) {
				thread_t sig_shuttle  = getshuttle_thread(q->sigwait_thread);
				/*
				 * The sigwait_thread could be stopped at a
				 * breakpoint. Wake it up to kill.
				 * Need to do this as it could be a thread which is not
				 * the first thread in the task. So any attempts to kill
				 * the process would result into a deadlock on q->sigwait.
				 */
				thread_resume((struct thread *)q->sigwait_thread);
				clear_wait(sig_shuttle, THREAD_INTERRUPTED);
				threadsignal(q->sigwait_thread, SIGKILL, 0);
			}
			psignal(q, SIGKILL);
		}
	}


	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.
	 */
	*p->p_ru = p->p_stats->p_ru;

	timerclear(&p->p_ru->ru_utime);
	timerclear(&p->p_ru->ru_stime);

	if (task) {
		task_basic_info_data_t tinfo;
		task_thread_times_info_data_t ttimesinfo;
		int task_info_stuff, task_ttimes_stuff;
		struct timeval ut,st;

		task_info_stuff	= TASK_BASIC_INFO_COUNT;
		task_info(task, TASK_BASIC_INFO,
			  &tinfo, &task_info_stuff);
		p->p_ru->ru_utime.tv_sec = tinfo.user_time.seconds;
		p->p_ru->ru_utime.tv_usec = tinfo.user_time.microseconds;
		p->p_ru->ru_stime.tv_sec = tinfo.system_time.seconds;
		p->p_ru->ru_stime.tv_usec = tinfo.system_time.microseconds;

		task_ttimes_stuff = TASK_THREAD_TIMES_INFO_COUNT;
		task_info(task, TASK_THREAD_TIMES_INFO,
			  &ttimesinfo, &task_ttimes_stuff);

		ut.tv_sec = ttimesinfo.user_time.seconds;
		ut.tv_usec = ttimesinfo.user_time.microseconds;
		st.tv_sec = ttimesinfo.system_time.seconds;
		st.tv_usec = ttimesinfo.system_time.microseconds;
		timeradd(&ut,&p->p_ru->ru_utime,&p->p_ru->ru_utime);
		timeradd(&st,&p->p_ru->ru_stime,&p->p_ru->ru_stime);
	}


	ruadd(p->p_ru, &p->p_stats->p_cru);

	/*
	 * Free up profiling buffers.
	 */
	{
		struct uprof *p0 = &p->p_stats->p_prof, *p1, *pn;

		p1 = p0->pr_next;
		p0->pr_next = NULL;
		p0->pr_scale = 0;

		for (; p1 != NULL; p1 = pn) {
			pn = p1->pr_next;
			kfree((vm_offset_t)p1, sizeof *p1);
		}
	}

	/*
	 * Other substructures are freed from wait().
	 */
	FREE_ZONE(p->p_stats, sizeof *p->p_stats, M_SUBPROC);
	p->p_stats = NULL;

	FREE_ZONE(p->p_sigacts, sizeof *p->p_sigacts, M_SUBPROC);
	p->p_sigacts = NULL;

	if (--p->p_limit->p_refcnt == 0)
		FREE_ZONE(p->p_limit, sizeof *p->p_limit, M_SUBPROC);
	p->p_limit = NULL;

	/*
	 * Finish up by terminating the task
	 * and halt this thread (only if a
	 * member of the task exiting).
	 */
	p->task = TASK_NULL;
	//task->proc = NULL;
	set_bsdtask_info(task, NULL);

	/*
	 * Notify parent that we're gone.
	 */
	psignal(p->p_pptr, SIGCHLD);

	/* Place onto zombproc. */
	LIST_INSERT_HEAD(&zombproc, p, p_list);
	p->p_stat = SZOMB;

	/* and now wakeup the parent */
	wakeup((caddr_t)p->p_pptr);

	(void) thread_funnel_set(kernel_flock, funnel_state);
}


struct wait4_args {
	int	pid;
	int *status;
	int options;
	struct rusage *rusage;
};

#if COMPAT_43
int
owait(p, uap, retval)
	struct proc *p;
	void *uap;
	int *retval;
{
	struct wait4_args *a;

	a = (struct wait4_args *)get_bsduthreadarg(current_act());

	a->options = 0;
	a->rusage = NULL;
	a->pid = WAIT_ANY;
	a->status = NULL;
	return (wait1(p, a, retval, 1));
}

int
wait4(p, uap, retval)
	struct proc *p;
	struct wait4_args *uap;
	int *retval;
{

	return (wait1(p, uap, retval, 0));
}

struct owait3_args {
	int *status;
	int options;
	struct rusage *rusage;
};

int
owait3(p, uap, retval)
	struct proc *p;
	struct owait3_args *uap;
	int *retval;
{
	struct wait4_args *a;

	a = (struct wait4_args *)get_bsduthreadarg(current_act);

	a->rusage = uap->rusage;
	a->options = uap->options;
	a->status = uap->status;
	a->pid = WAIT_ANY;

	return (wait1(p, a, retval, 1));
}

#else
#define	wait1	wait4
#endif

int
wait1continue(result)
{
  void *vt;
  thread_act_t thread;
  struct uthread *ut;
  int *retval;
  struct proc *p;

	p = current_proc();
	p->p_flag &= ~P_WAITING;

      if (result != 0) {
	  return(result);
	}

    thread = current_act();
	ut = get_bsdthread_info(thread);
	vt = get_bsduthreadarg(thread);
	retval = get_bsduthreadrval(thread);
	wait1((struct proc *)p, (struct wait4_args *)vt, retval, 0);
}

int
wait1(q, uap, retval, compat)
	register struct proc *q;
	register struct wait4_args *uap;
	register_t *retval;
#if COMPAT_43
	int compat;
#endif
{
	register int nfound;
	register struct proc *p, *t;
	int status, error;


#if 0
	/* since we are funneled we don't need to do this atomically, yet */
	if (q->p_flag & P_WAITING) {
	  return(EINVAL);
	}
	q->p_flag |= P_WAITING;   /* only allow single thread to wait() */
#endif

	if (uap->pid == 0)
		uap->pid = -q->p_pgid;

loop:
	nfound = 0;
	for (p = q->p_children.lh_first; p != 0; p = p->p_sibling.le_next) {
		if (uap->pid != WAIT_ANY &&
		    p->p_pid != uap->pid &&
		    p->p_pgid != -(uap->pid))
			continue;
		nfound++;
		if (p->p_stat == SZOMB) {
			retval[0] = p->p_pid;
#if COMPAT_43
			if (compat)
				retval[1] = p->p_xstat;
			else
#endif
			if (uap->status) {
				status = p->p_xstat;	/* convert to int */
				if (error = copyout((caddr_t)&status,
				    (caddr_t)uap->status,
						    sizeof(status))) {
				        q->p_flag &= ~P_WAITING;
					return (error);
				}
			}
			if (uap->rusage &&
			    (error = copyout((caddr_t)p->p_ru,
			    (caddr_t)uap->rusage,
					     sizeof (struct rusage)))) {
				        q->p_flag &= ~P_WAITING;
				return (error);
			}
			/*
			 * If we got the child via a ptrace 'attach',
			 * we need to give it back to the old parent.
			 */
			if (p->p_oppid && (t = pfind(p->p_oppid))) {
				p->p_oppid = 0;
				proc_reparent(p, t);
				psignal(t, SIGCHLD);
				wakeup((caddr_t)t);
				        q->p_flag &= ~P_WAITING;
				return (0);
			}
			p->p_xstat = 0;
			if (p->p_ru) {
				ruadd(&q->p_stats->p_cru, p->p_ru);
				FREE_ZONE(p->p_ru, sizeof *p->p_ru, M_ZOMBIE);
				p->p_ru = NULL;
			} else {
				printf("Warning : lost p_ru for %s\n", p->p_comm);
			}

			/*
			 * Decrement the count of procs running with this uid.
			 */
			(void)chgproccnt(p->p_cred->p_ruid, -1);

			/*
			 * Free up credentials.
			 */
			if (--p->p_cred->p_refcnt == 0) {
				struct ucred *ucr = p->p_ucred;
				struct pcred *pcr;

				if (ucr != NOCRED) {
					p->p_ucred = NOCRED;
					crfree(ucr);
				}
				pcr = p->p_cred;
				p->p_cred = NULL;
				FREE_ZONE(pcr, sizeof *pcr, M_SUBPROC);
			}

			/*
			 * Release reference to text vnode
			 */
			if (p->p_textvp)
				vrele(p->p_textvp);

			/*
			 * Finally finished with old proc entry.
			 * Unlink it from its process group and free it.
			 */
			leavepgrp(p);
			LIST_REMOVE(p, p_list);	/* off zombproc */
			LIST_REMOVE(p, p_sibling);
			FREE_ZONE(p, sizeof *p, M_PROC);
			nprocs--;
				        q->p_flag &= ~P_WAITING;
			return (0);
		}
		if (p->p_stat == SSTOP && (p->p_flag & P_WAITED) == 0 &&
		    (p->p_flag & P_TRACED || uap->options & WUNTRACED)) {
			p->p_flag |= P_WAITED;
			retval[0] = p->p_pid;
#if COMPAT_43
			if (compat) {
				retval[1] = W_STOPCODE(p->p_xstat);
				error = 0;
			} else
#endif
			if (uap->status) {
				status = W_STOPCODE(p->p_xstat);
				error = copyout((caddr_t)&status,
				    (caddr_t)uap->status,
				    sizeof(status));
			} else
				error = 0;
				        q->p_flag &= ~P_WAITING;
			return (error);
		}
	}
	if (nfound == 0) {
				        q->p_flag &= ~P_WAITING;
		return (ECHILD);
	}
	if (uap->options & WNOHANG) {
		retval[0] = 0;
				        q->p_flag &= ~P_WAITING;
		return (0);
	}

	if (error = tsleep0((caddr_t)q, PWAIT | PCATCH, "wait", 0, wait1continue)) {
				        q->p_flag &= ~P_WAITING;
		return (error);
	}
	goto loop;
}

/*
 * make process 'parent' the new parent of process 'child'.
 */
void
proc_reparent(child, parent)
	register struct proc *child;
	register struct proc *parent;
{

	if (child->p_pptr == parent)
		return;

	LIST_REMOVE(child, p_sibling);
	LIST_INSERT_HEAD(&parent->p_children, child, p_sibling);
	child->p_pptr = parent;
}

kern_return_t
init_process(void)
/*
 *	Make the current process an "init" process, meaning
 *	that it doesn't have a parent, and that it won't be
 *	gunned down by kill(-1, 0).
 */
{
	register struct proc *p = current_proc();

	if (suser(p->p_ucred, &p->p_acflag))
		return(KERN_NO_ACCESS);

	if (p->p_pid != 1 && p->p_pgid != p->p_pid)
		enterpgrp(p, p->p_pid, 0);
	p->p_flag |= P_SYSTEM;

	/*
	 *	Take us out of the sibling chain, and
	 *	out of our parent's child chain.
	 */
	LIST_REMOVE(p, p_sibling);
	p->p_sibling.le_prev = NULL;
	p->p_sibling.le_next = NULL;
	p->p_pptr = kernproc;

	return(KERN_SUCCESS);
}

void
process_terminate_self(void)
{
	struct proc *p = current_proc();

	if (p != NULL) {
		exit1(p, W_EXITCODE(0, SIGKILL), (int *)NULL);
		/*NOTREACHED*/
	}
}
/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */

void
vfork_exit(p, rv)
	register struct proc *p;
	int rv;
{
	register struct proc *q, *nq;
	thread_t self = current_thread();
	thread_act_t th_act_self = current_act();
	struct task *task = p->task;
	register int i,s;
	struct uthread *ut;

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	 ut = get_bsdthread_info(th_act_self);
#ifdef FIXME
        signal_lock(p);
	while (p->exit_thread != self) {
		if (sig_try_locked(p) <= 0) {
			if (get_threadtask(th_act_self) != task) {
                                signal_unlock(p);
				return;
                        }
			signal_unlock(p);
			thread_terminate(th_act_self);
			thread_funnel_set(kernel_flock, FALSE);
			thread_exception_return();
			/* NOTREACHED */
		}
		sig_lock_to_exit(p);
	}
        signal_unlock(p);
	if (p->p_pid == 1) {
		printf("pid 1 exited (signal %d, exit %d)",
		    WTERMSIG(rv), WEXITSTATUS(rv));
panic("init died\nState at Last Exception:\n\n%s", init_task_failure_data);
	}
#endif /* FIXME */

	s = splsched();
	p->p_flag |= P_WEXIT;
	splx(s);
	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */
	LIST_REMOVE(p, p_list);
	LIST_REMOVE(p, p_hash);
	/*
	 * If parent is waiting for us to exit or exec,
	 * P_PPWAIT is set; we will wakeup the parent below.
	 */
	p->p_flag &= ~(P_TRACED | P_PPWAIT);
	p->p_sigignore = ~0;
	p->p_siglist = 0;

	ut->uu_sig = 0;
	untimeout(realitexpire, (caddr_t)p);

	p->p_xstat = rv;

	vproc_exit(p);
}


void 
vproc_exit(struct proc *p)
{
	register struct proc *q, *nq;
	thread_t self = current_thread();
	thread_act_t th_act_self = current_act();
	struct task *task = p->task;
	register int i,s;
	struct uthread *ut;
	boolean_t funnel_state;

	MALLOC_ZONE(p->p_ru, struct rusage *,
			sizeof (*p->p_ru), M_ZOMBIE, M_WAITOK);

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdfree(p);

	/* Close ref SYSV Shared memory*/
	if (p->vm_shm)
		shmexit(p);
	
	if (SESS_LEADER(p)) {
		register struct session *sp = p->p_session;

		if (sp->s_ttyvp) {
			/*
			 * Controlling process.
			 * Signal foreground pgrp,
			 * drain controlling terminal
			 * and revoke access to controlling terminal.
			 */
			if (sp->s_ttyp->t_session == sp) {
				if (sp->s_ttyp->t_pgrp)
					pgsignal(sp->s_ttyp->t_pgrp, SIGHUP, 1);
				(void) ttywait(sp->s_ttyp);
				/*
				 * The tty could have been revoked
				 * if we blocked.
				 */
				if (sp->s_ttyvp)
					VOP_REVOKE(sp->s_ttyvp, REVOKEALL);
			}
			if (sp->s_ttyvp)
				vrele(sp->s_ttyvp);
			sp->s_ttyvp = NULL;
			/*
			 * s_ttyp is not zero'd; we use this to indicate
			 * that the session once had a controlling terminal.
			 * (for logging and informational purposes)
			 */
		}
		sp->s_leader = NULL;
	}

	fixjobc(p, p->p_pgrp, 0);
	p->p_rlimit[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
#if KTRACE
	/* 
	 * release trace file
	 */
	p->p_traceflag = 0;	/* don't trace the vrele() */
	if (p->p_tracep)
		vrele(p->p_tracep);
#endif


	q = p->p_children.lh_first;
	if (q)		/* only need this if any child is S_ZOMB */
		wakeup((caddr_t) initproc);
	for (; q != 0; q = nq) {
		nq = q->p_sibling.le_next;
		proc_reparent(q, initproc);
		/*
		 * Traced processes are killed
		 * since their existence means someone is messing up.
		 */
		if (q->p_flag & P_TRACED) {
			q->p_flag &= ~P_TRACED;
			if (q->sigwait_thread) {
				thread_t sig_shuttle  = getshuttle_thread(q->sigwait_thread);
				/*
				 * The sigwait_thread could be stopped at a
				 * breakpoint. Wake it up to kill.
				 * Need to do this as it could be a thread which is not
				 * the first thread in the task. So any attempts to kill
				 * the process would result into a deadlock on q->sigwait.
				 */
				thread_resume((struct thread *)q->sigwait_thread);
				clear_wait(sig_shuttle, THREAD_INTERRUPTED);
				threadsignal(q->sigwait_thread, SIGKILL, 0);
			}
			psignal(q, SIGKILL);
		}
	}


	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.
	 */
	*p->p_ru = p->p_stats->p_ru;

	timerclear(&p->p_ru->ru_utime);
	timerclear(&p->p_ru->ru_stime);

#ifdef  FIXME
	if (task) {
		task_basic_info_data_t tinfo;
		task_thread_times_info_data_t ttimesinfo;
		int task_info_stuff, task_ttimes_stuff;
		struct timeval ut,st;

		task_info_stuff	= TASK_BASIC_INFO_COUNT;
		task_info(task, TASK_BASIC_INFO,
			  &tinfo, &task_info_stuff);
		p->p_ru->ru_utime.tv_sec = tinfo.user_time.seconds;
		p->p_ru->ru_utime.tv_usec = tinfo.user_time.microseconds;
		p->p_ru->ru_stime.tv_sec = tinfo.system_time.seconds;
		p->p_ru->ru_stime.tv_usec = tinfo.system_time.microseconds;

		task_ttimes_stuff = TASK_THREAD_TIMES_INFO_COUNT;
		task_info(task, TASK_THREAD_TIMES_INFO,
			  &ttimesinfo, &task_ttimes_stuff);

		ut.tv_sec = ttimesinfo.user_time.seconds;
		ut.tv_usec = ttimesinfo.user_time.microseconds;
		st.tv_sec = ttimesinfo.system_time.seconds;
		st.tv_usec = ttimesinfo.system_time.microseconds;
		timeradd(&ut,&p->p_ru->ru_utime,&p->p_ru->ru_utime);
		timeradd(&st,&p->p_ru->ru_stime,&p->p_ru->ru_stime);
	}
#endif /* FIXME */

	ruadd(p->p_ru, &p->p_stats->p_cru);

	/*
	 * Free up profiling buffers.
	 */
	{
		struct uprof *p0 = &p->p_stats->p_prof, *p1, *pn;

		p1 = p0->pr_next;
		p0->pr_next = NULL;
		p0->pr_scale = 0;

		for (; p1 != NULL; p1 = pn) {
			pn = p1->pr_next;
			kfree((vm_offset_t)p1, sizeof *p1);
		}
	}

	/*
	 * Other substructures are freed from wait().
	 */
	FREE_ZONE(p->p_stats, sizeof *p->p_stats, M_SUBPROC);
	p->p_stats = NULL;

	FREE_ZONE(p->p_sigacts, sizeof *p->p_sigacts, M_SUBPROC);
	p->p_sigacts = NULL;

	if (--p->p_limit->p_refcnt == 0)
		FREE_ZONE(p->p_limit, sizeof *p->p_limit, M_SUBPROC);
	p->p_limit = NULL;

	/*
	 * Finish up by terminating the task
	 * and halt this thread (only if a
	 * member of the task exiting).
	 */
	p->task = TASK_NULL;

	/*
	 * Notify parent that we're gone.
	 */
	psignal(p->p_pptr, SIGCHLD);

	/* Place onto zombproc. */
	LIST_INSERT_HEAD(&zombproc, p, p_list);
	p->p_stat = SZOMB;

	/* and now wakeup the parent */
	wakeup((caddr_t)p->p_pptr);

}

