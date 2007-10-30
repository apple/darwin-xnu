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
 *	@(#)kern_exit.c	8.7 (Berkeley) 2/12/94
 */
 
#include <machine/reg.h>
#include <machine/psl.h>

#include "compat_43.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/tty.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/kernel.h>
#include <sys/wait.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/syslog.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/aio_kern.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>
#include <sys/filedesc.h>	/* fdfree */
#include <sys/shm_internal.h>	/* shmexit */
#include <sys/acct.h>		/* acct_process */
#include <machine/spl.h>

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/assert.h>
#if KTRACE   
#include <sys/ktrace.h>
#endif

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/mach_traps.h>	/* init_process */

extern char init_task_failure_data[];
int exit1(struct proc *, int, int *);
void proc_prepareexit(struct proc *p);
void vfork_exit(struct proc *p, int rv);
void vproc_exit(struct proc *p);
__private_extern__ void munge_rusage(struct rusage *a_rusage_p, struct user_rusage *a_user_rusage_p);

/*
 * Things which should have prototypes in headers, but don't
 */
void	unix_syscall_return(int);
void	*get_bsduthreadarg(thread_t);
void	proc_exit(struct proc *p);
int	wait1continue(int result);
int	waitidcontinue(int result);
int	*get_bsduthreadrval(thread_t);
kern_return_t	sys_perf_notify(struct task *task, exception_data_t code,
			mach_msg_type_number_t codeCnt);

/*
 * NOTE: Source and target may *NOT* overlap!
 * XXX Should share code with bsd/dev/ppc/unix_signal.c
 */
static void
siginfo_64to32(user_siginfo_t *in, siginfo_t *out)
{
	out->si_signo	= in->si_signo;
	out->si_errno	= in->si_errno;
	out->si_code	= in->si_code;
	out->si_pid	= in->si_pid;
	out->si_uid	= in->si_uid;
	out->si_status	= in->si_status;
	out->si_addr	= CAST_DOWN(void *,in->si_addr);
	/* following cast works for sival_int because of padding */
	out->si_value.sival_ptr	= CAST_DOWN(void *,in->si_value.sival_ptr);
	out->si_band	= in->si_band;			/* range reduction */
	out->pad[0]	= in->pad[0];			/* mcontext.ss.r1 */
}

/*
 * exit --
 *	Death of process.
 */
void
exit(struct proc *p, struct exit_args *uap, int *retval)
{
	exit1(p, W_EXITCODE(uap->rval, 0), retval);

	/* drop funnel before we return */
	thread_funnel_set(kernel_flock, FALSE);
	thread_exception_return();
	/* NOTREACHED */
	while (TRUE)
		thread_block(THREAD_CONTINUE_NULL);
	/* NOTREACHED */
}

/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */
int
exit1(struct proc *p, int rv, int *retval)
{
	thread_t self = current_thread();
	struct task *task = p->task;
	register int s;
	struct uthread *ut;

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	 ut = get_bsdthread_info(self);
	 if (ut->uu_flag & UT_VFORK) {
			vfork_exit(p, rv);
			vfork_return(self, p->p_pptr, p , retval);
			unix_syscall_return(0);
			/* NOT REACHED */
	 }
	AUDIT_SYSCALL_EXIT(0, p, ut); /* Exit is always successfull */
        signal_lock(p);
	while (p->exit_thread != self) {
		if (sig_try_locked(p) <= 0) {
			if (get_threadtask(self) != task) {
                                signal_unlock(p);
				return(0);
                        }
			signal_unlock(p);
			thread_terminate(self);
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

	return(0);
}

void
proc_prepareexit(struct proc *p) 
{
	struct uthread *ut;
	exception_data_t	code[EXCEPTION_CODE_MAX];
	thread_t self = current_thread();

	code[0] = (exception_data_t)0xFF000001;		/* Set terminate code */
	code[1] = (exception_data_t)p->p_pid;		/* Pass out the pid */
	/* Notify the perf server */
	(void)sys_perf_notify(p->task, (exception_data_t)&code, 2);

	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */
	LIST_REMOVE(p, p_list);
	LIST_INSERT_HEAD(&zombproc, p, p_list);	/* Place onto zombproc. */
	LIST_REMOVE(p, p_hash);

#ifdef PGINPROF
	vmsizmon();
#endif
	/*
	 * If parent is waiting for us to exit or exec,
	 * P_PPWAIT is set; we will wakeup the parent below.
	 */
	p->p_flag &= ~(P_TRACED | P_PPWAIT);
	p->p_sigignore = ~(sigcantmask);
	p->p_siglist = 0;
	ut = get_bsdthread_info(self);
	ut->uu_siglist = 0;
	untimeout(realitexpire, (caddr_t)p->p_pid);
}

void 
proc_exit(struct proc *p)
{
	register struct proc *q, *nq, *pp;
	struct task *task = p->task;
	register int s;
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

	p->p_lflag |= P_LPEXIT;
	/* XXX Zombie allocation may fail, in which case stats get lost */
	MALLOC_ZONE(p->p_ru, struct rusage *,
			sizeof (*p->p_ru), M_ZOMBIE, M_WAITOK);

	/*
	 * need to cancel async IO requests that can be cancelled and wait for those
	 * already active.  MAY BLOCK!
	 */
	
	p->p_lflag |= P_LREFDRAIN;
	while (p->p_internalref) {
		p->p_lflag |= P_LREFDRAINWAIT;
		msleep(&p->p_internalref, (lck_mtx_t *)0, 0, "proc_refdrain", 0) ;
	}
	p->p_lflag &= ~P_LREFDRAIN;
	p->p_lflag |= P_LREFDEAD;

	_aio_exit( p );

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdfree(p);

	/* Close ref SYSV Shared memory*/
	if (p->vm_shm)
		shmexit(p);
	/* Release SYSV semaphores */
	semexit(p);
	
	if (SESS_LEADER(p)) {
		register struct session *sp = p->p_session;

		if (sp->s_ttyvp) {
			struct vnode *ttyvp;
			struct vfs_context context;

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
				context.vc_proc = p;
				context.vc_ucred = p->p_ucred;
				if (sp->s_ttyvp)
					VNOP_REVOKE(sp->s_ttyvp, REVOKEALL, &context);
			}
			ttyvp = sp->s_ttyvp;
			sp->s_ttyvp = NULL;
			if (ttyvp) {
				vnode_rele(ttyvp);
			}
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
	(void)acct_process(p);

#if KTRACE
	/* 
	 * release trace file
	 */
	p->p_traceflag = 0;	/* don't trace the vnode_put() */
	if (p->p_tracep) {
		struct vnode *tvp = p->p_tracep;
		p->p_tracep = NULL;
		vnode_rele(tvp);
	}
#endif

	while (q = p->p_children.lh_first) {
		proc_reparent(q, initproc);
		/*
		 * Traced processes are killed
		 * since their existence means someone is messing up.
		 */
		if (q->p_flag & P_TRACED) {
			q->p_flag &= ~P_TRACED;
			if (q->sigwait_thread) {
				/*
				 * The sigwait_thread could be stopped at a
				 * breakpoint. Wake it up to kill.
				 * Need to do this as it could be a thread which is not
				 * the first thread in the task. So any attempts to kill
				 * the process would result into a deadlock on q->sigwait.
				 */
				thread_resume((thread_t)q->sigwait_thread);
				clear_wait(q->sigwait_thread, THREAD_INTERRUPTED);
				threadsignal((thread_t)q->sigwait_thread, SIGKILL, 0);
			}
			psignal(q, SIGKILL);
		}
	}

	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.  If we were unable to allocate a zombie
	 * structure, this information is lost.
	 */
	if (p->p_ru != NULL) {
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
			  (task_info_t)&tinfo, &task_info_stuff);
		p->p_ru->ru_utime.tv_sec = tinfo.user_time.seconds;
		p->p_ru->ru_utime.tv_usec = tinfo.user_time.microseconds;
		p->p_ru->ru_stime.tv_sec = tinfo.system_time.seconds;
		p->p_ru->ru_stime.tv_usec = tinfo.system_time.microseconds;

		task_ttimes_stuff = TASK_THREAD_TIMES_INFO_COUNT;
		task_info(task, TASK_THREAD_TIMES_INFO,
			  (task_info_t)&ttimesinfo, &task_ttimes_stuff);

		ut.tv_sec = ttimesinfo.user_time.seconds;
		ut.tv_usec = ttimesinfo.user_time.microseconds;
		st.tv_sec = ttimesinfo.system_time.seconds;
		st.tv_usec = ttimesinfo.system_time.microseconds;
		timeradd(&ut,&p->p_ru->ru_utime,&p->p_ru->ru_utime);
		timeradd(&st,&p->p_ru->ru_stime,&p->p_ru->ru_stime);
	    }

	    ruadd(p->p_ru, &p->p_stats->p_cru);
	}

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
			kfree(p1, sizeof *p1);
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

	KNOTE(&p->p_klist, NOTE_EXIT);

	/*
	 * Notify parent that we're gone.
	 */
	if (p->p_pptr->p_flag & P_NOCLDWAIT) {
		struct proc *opp = p->p_pptr;

		/*
		 * Add child resource usage to parent before giving
		 * zombie to init.  If we were unable to allocate a
		 * zombie structure, this information is lost.
		 */
		if (p->p_ru != NULL)
			ruadd(&p->p_pptr->p_stats->p_cru, p->p_ru);

		proc_reparent(p, initproc);
		/* If there are no more children wakeup parent */
		if (LIST_EMPTY(&opp->p_children))
			wakeup((caddr_t)opp);
	}
	/* should be fine as parent proc would be initproc */
	pp = p->p_pptr;
	if (pp != initproc) {
		pp->si_pid = p->p_pid;
		pp->si_status = p->p_xstat;
		pp->si_code = CLD_EXITED;
		pp->si_uid = p->p_ucred->cr_ruid;
	}
	/* mark as a zombie */
	p->p_stat = SZOMB;

	psignal(pp, SIGCHLD);

	/* and now wakeup the parent */
	wakeup((caddr_t)p->p_pptr);

	(void) thread_funnel_set(kernel_flock, funnel_state);
}


/*
 * reap_child_process
 *
 * Description:	Given a process from which all status information needed
 *		has already been extracted, if the process is a ptrace
 *		attach process, detach it and give it back to its real
 *		parent, else recover all resources remaining associated
 *		with it.
 *
 * Parameters:	struct proc *parent	Parent of process being reaped
 *		struct proc *child	Process to reap
 *
 * Returns:	0			Process was not reaped because it
 *					came from an attach
 *		1			Process was reaped
 */
static int
reap_child_process(struct proc *parent, struct proc *child)
{
	struct proc *trace_parent;	/* Traced parent process, if tracing */
	struct vnode *tvp;		/* Traced vnode pointer, if used */

	/*
	 * If we got the child via a ptrace 'attach',
	 * we need to give it back to the old parent.
	 */
	if (child->p_oppid && (trace_parent = pfind(child->p_oppid))) {
		child->p_oppid = 0;
		proc_reparent(child, trace_parent);
		if (trace_parent != initproc) {
			trace_parent->si_pid = child->p_pid;
			trace_parent->si_status = child->p_xstat;
			trace_parent->si_code = CLD_CONTINUED;
			trace_parent->si_uid = child->p_ucred->cr_ruid;
		}
		psignal(trace_parent, SIGCHLD);
		wakeup((caddr_t)trace_parent);
		return (0);
	}
	child->p_xstat = 0;
	if (child->p_ru) {
		ruadd(&parent->p_stats->p_cru, child->p_ru);
		FREE_ZONE(child->p_ru, sizeof *child->p_ru, M_ZOMBIE);
		child->p_ru = NULL;
	} else {
		printf("Warning : lost p_ru for %s\n", child->p_comm);
	}

	/*
	 * Decrement the count of procs running with this uid.
	 */
	(void)chgproccnt(child->p_ucred->cr_ruid, -1);

	/*
	 * Free up credentials.
	 */
	if (child->p_ucred != NOCRED) {
		kauth_cred_t ucr = child->p_ucred;
			child->p_ucred = NOCRED;
			kauth_cred_rele(ucr);
		}

	/*
	 * Release reference to text vnode
	 */
	tvp = child->p_textvp;
	child->p_textvp = NULL;
	if (tvp) {
		vnode_rele(tvp);
	}
	/*
	 * Finally finished with old proc entry.
	 * Unlink it from its process group and free it.
	 */
	leavepgrp(child);
	LIST_REMOVE(child, p_list);	/* off zombproc */
	LIST_REMOVE(child, p_sibling);
	child->p_lflag &= ~P_LWAITING;
	wakeup(&child->p_stat);

	lck_mtx_destroy(&child->p_mlock, proc_lck_grp);
	lck_mtx_destroy(&child->p_fdmlock, proc_lck_grp);
	FREE_ZONE(child, sizeof *child, M_PROC);
	nprocs--;
	return (1);
}


int
wait1continue(int result)
{
	void *vt;
	thread_t thread;
	int *retval;
	struct proc *p;

	if (result)
		return(result);

	p = current_proc();
	thread = current_thread();
	vt = get_bsduthreadarg(thread);
	retval = get_bsduthreadrval(thread);
	return(wait4((struct proc *)p, (struct wait4_args *)vt, retval));
}

int
wait4(struct proc *q, struct wait4_args *uap, register_t *retval)
{
	register int nfound;
	register struct proc *p;
	int status, error;

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

		/* XXX This is racy because we don't get the lock!!!! */

		if (p->p_lflag & P_LWAITING) {
			(void)tsleep(&p->p_stat, PWAIT, "waitcoll", 0);
			goto loop;
		}
		p->p_lflag |= P_LWAITING;   /* only allow single thread to wait() */

		if (p->p_stat == SZOMB) {
			retval[0] = p->p_pid;
			if (uap->status) {
				status = p->p_xstat;	/* convert to int */
				error = copyout((caddr_t)&status,
				   			uap->status,
						    sizeof(status));
				if (error) {
					p->p_lflag &= ~P_LWAITING;
					wakeup(&p->p_stat);
					return (error);
				}
			}
			if (uap->rusage) {
				if (p->p_ru == NULL) {
					error = ENOMEM;
				} else {
					if (IS_64BIT_PROCESS(q)) {
						struct user_rusage	my_rusage;
						munge_rusage(p->p_ru, &my_rusage);
						error = copyout((caddr_t)&my_rusage,
							uap->rusage,
							sizeof (my_rusage));
					}
					else {
						error = copyout((caddr_t)p->p_ru,
							uap->rusage,
							sizeof (struct rusage));
					}
				}
				/* information unavailable? */
				if (error) {
					p->p_lflag &= ~P_LWAITING;
					wakeup(&p->p_stat);
					return (error);
				}
			}

			/* Clean up */
			if (!reap_child_process(q, p)) {
				p->p_lflag &= ~P_LWAITING;
				wakeup(&p->p_stat);
			}

			return (0);
		}
		if (p->p_stat == SSTOP && (p->p_flag & P_WAITED) == 0 &&
		    (p->p_flag & P_TRACED || uap->options & WUNTRACED)) {
			p->p_flag |= P_WAITED;
			retval[0] = p->p_pid;
			if (uap->status) {
				status = W_STOPCODE(p->p_xstat);
				error = copyout((caddr_t)&status,
					uap->status,
				    sizeof(status));
			} else
				error = 0;
			p->p_lflag &= ~P_LWAITING;
			wakeup(&p->p_stat);
			return (error);
		}
		p->p_lflag &= ~P_LWAITING;
		wakeup(&p->p_stat);
	}
	if (nfound == 0)
		return (ECHILD);

	if (uap->options & WNOHANG) {
		retval[0] = 0;
		return (0);
	}

	if ((error = tsleep0((caddr_t)q, PWAIT | PCATCH, "wait", 0, wait1continue)))
		return (error);

	goto loop;
}


int
waitidcontinue(int result)
{
	void *vt;
	thread_t thread;
	int *retval;
	struct proc *p;

	if (result)
		return(result);

	p = current_proc();
	thread = current_thread();
	vt = get_bsduthreadarg(thread);
	retval = get_bsduthreadrval(thread);
	return(waitid((struct proc *)p, (struct waitid_args *)vt, retval));
}

/*
 * Description:	Suspend the calling thread until one child of the process
 *		containing the calling thread changes state.
 *
 * Parameters:	uap->idtype		one of P_PID, P_PGID, P_ALL
 *		uap->id			pid_t or gid_t or ignored
 *		uap->infop		Address of signinfo_t struct in
 *					user space into which to return status
 *		uap->options		flag values
 *
 * Returns:	0			Success
 *		!0			Error returning status to user space
 */
int
waitid(struct proc *q, struct waitid_args *uap, register_t *retval)
{
	user_siginfo_t	collect64;	/* siginfo data to return to caller */

	register int nfound;
	register struct proc *p;
	int error;

loop:
	nfound = 0;
	for (p = q->p_children.lh_first; p != 0; p = p->p_sibling.le_next) {
		switch(uap->idtype) {
		case P_PID:	/* child with process ID equal to... */
			if (p->p_pid != (pid_t)uap->id)
				continue;
			break;
		case P_PGID:	/* child with process group ID equal to... */
			if (p->p_pgid != (pid_t)uap->id)
				continue;
			break;
		case P_ALL:	/* any child */
			break;
		}

		/* XXX This is racy because we don't get the lock!!!! */

		/*
		 * Wait collision; go to sleep and restart; used to maintain
		 * the single return for waited process guarantee.
		 */
		if (p->p_lflag & P_LWAITING) {
			(void)tsleep(&p->p_stat, PWAIT, "waitidcoll", 0);
			goto loop;
		}
		p->p_lflag |= P_LWAITING;		/* mark busy */

		nfound++;

		/*
		 * Types of processes we are interested in
		 *
		 * XXX Don't know what to do for WCONTINUED?!?
		 */
		switch(p->p_stat) {
		case SZOMB:		/* Exited */
			if (!(uap->options & WEXITED))
				break;

			/* Collect "siginfo" information for caller */
			collect64.si_signo = 0;
			collect64.si_code = 0;
			collect64.si_errno = 0;
			collect64.si_pid = 0;
			collect64.si_uid = 0;
			collect64.si_addr  = 0;
			collect64.si_status = p->p_xstat;
			collect64.si_band = 0;

			if (IS_64BIT_PROCESS(p)) {
				error = copyout((caddr_t)&collect64,
					uap->infop,
					sizeof(collect64));
			} else {
				siginfo_t collect;
				siginfo_64to32(&collect64,&collect);
				error = copyout((caddr_t)&collect,
					uap->infop,
					sizeof(collect));
			}
			/* information unavailable? */
			if (error) {
				p->p_lflag &= ~P_LWAITING;
				wakeup(&p->p_stat);
				return (error);
			}

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				/* Clean up */
				if (!reap_child_process(q, p)) {
					p->p_lflag &= ~P_LWAITING;
					wakeup(&p->p_stat);
				}
			}

			return (0);

		case SSTOP:		/* Stopped */
			/*
			 * If we are not interested in stopped processes, then
			 * ignore this one.
			 */
			if (!(uap->options & WSTOPPED))
				break;

			/*
			 * If someone has already waited it, we lost a race
			 * to be the one to return status.
			 */
			if ((p->p_flag & P_WAITED) != 0)
				break;

			/*
			 * If this is not a traced process, and they haven't
			 * indicated an interest in untraced processes, then
			 * ignore this one.
			 */
			if (!(p->p_flag & P_TRACED) && !(uap->options & WUNTRACED))
			    	break;

			/* Collect "siginfo" information for caller */
			collect64.si_signo = 0;
			collect64.si_code = 0;
			collect64.si_errno = 0;
			collect64.si_pid = 0;
			collect64.si_uid = 0;
			collect64.si_addr  = 0;
			collect64.si_status = p->p_xstat;
			collect64.si_band = 0;

			if (IS_64BIT_PROCESS(p)) {
				error = copyout((caddr_t)&collect64,
					uap->infop,
					sizeof(collect64));
			} else {
				siginfo_t collect;
				siginfo_64to32(&collect64,&collect);
				error = copyout((caddr_t)&collect,
					uap->infop,
					sizeof(collect));
			}
			/* information unavailable? */
			if (error) {
				p->p_lflag &= ~P_LWAITING;
				wakeup(&p->p_stat);
				return (error);
			}

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				p->p_flag |= P_WAITED;
			}

			p->p_lflag &= ~P_LWAITING;
			wakeup(&p->p_stat);
			return (0);

		default:		/* All others */
					/* ...meaning Continued */
			if (!(uap->options & WCONTINUED))
				break;

			/*
			 * If the flag isn't set, then this process has not
			 * been stopped and continued, or the status has
			 * already been reaped by another caller of waitid().
			 */
			if ((p->p_flag & P_CONTINUED) == 0)
				break;

			/* Collect "siginfo" information for caller */
			collect64.si_signo = 0;
			collect64.si_code = 0;
			collect64.si_errno = 0;
			collect64.si_pid = 0;
			collect64.si_uid = 0;
			collect64.si_addr  = 0;
			collect64.si_status = p->p_xstat;
			collect64.si_band = 0;

			if (IS_64BIT_PROCESS(p)) {
				error = copyout((caddr_t)&collect64,
					uap->infop,
					sizeof(collect64));
			} else {
				siginfo_t collect;
				siginfo_64to32(&collect64,&collect);
				error = copyout((caddr_t)&collect,
					uap->infop,
					sizeof(collect));
			}
			/* information unavailable? */
			if (error) {
				p->p_lflag &= ~P_LWAITING;
				wakeup(&p->p_stat);
				return (error);
			}

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				p->p_flag &= ~P_CONTINUED;
			}

			p->p_lflag &= ~P_LWAITING;
			wakeup(&p->p_stat);
			return (0);

			break;
		}


		/* Not a process we are interested in; go on to next child */
		p->p_lflag &= ~P_LWAITING;
		wakeup(&p->p_stat);
	}

	/* No child processes that could possibly satisfy the request? */
	if (nfound == 0)
		return (ECHILD);

	if (uap->options & WNOHANG) {
		retval[0] = 0;
		return (0);
	}

	if ((error = tsleep0((caddr_t)q, PWAIT | PCATCH, "waitid", 0, waitidcontinue)))
		return (error);

	goto loop;
}

/*
 * make process 'parent' the new parent of process 'child'.
 */
void
proc_reparent(struct proc *child, struct proc *parent)
{

	if (child->p_pptr == parent)
		return;

	LIST_REMOVE(child, p_sibling);
	LIST_INSERT_HEAD(&parent->p_children, child, p_sibling);
	child->p_pptr = parent;

	if (initproc == parent && child->p_stat == SZOMB)
		psignal(initproc, SIGCHLD);
}

/*
 *	Make the current process an "init" process, meaning
 *	that it doesn't have a parent, and that it won't be
 *	gunned down by kill(-1, 0).
 */
kern_return_t
init_process(__unused struct init_process_args *args)
{
	register struct proc *p = current_proc();

	AUDIT_MACH_SYSCALL_ENTER(AUE_INITPROCESS);
	if (suser(kauth_cred_get(), &p->p_acflag)) {
		AUDIT_MACH_SYSCALL_EXIT(KERN_NO_ACCESS);
		return(KERN_NO_ACCESS);
	}

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

	AUDIT_MACH_SYSCALL_EXIT(KERN_SUCCESS);
	return(KERN_SUCCESS);
}


/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */

void
vfork_exit(struct proc *p, int rv)
{
	thread_t self = current_thread();
#ifdef FIXME
	struct task *task = p->task;
#endif
	register int s;
	struct uthread *ut;
	exception_data_t	code[EXCEPTION_CODE_MAX];

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	 ut = get_bsdthread_info(self);
#ifdef FIXME
        signal_lock(p);
	while (p->exit_thread != self) {
		if (sig_try_locked(p) <= 0) {
			if (get_threadtask(self) != task) {
                                signal_unlock(p);
				return;
                        }
			signal_unlock(p);
			thread_terminate(self);
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
	p->p_lflag |= P_LPEXIT;
	splx(s);

	code[0] = (exception_data_t)0xFF000001;		/* Set terminate code */
	code[1] = (exception_data_t)p->p_pid;		/* Pass out the pid */
	/* Notify the perf server */
	(void)sys_perf_notify(p->task, (exception_data_t)&code, 2);

	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */
	LIST_REMOVE(p, p_list);
	LIST_INSERT_HEAD(&zombproc, p, p_list);	/* Place onto zombproc. */
	LIST_REMOVE(p, p_hash);
	/*
	 * If parent is waiting for us to exit or exec,
	 * P_PPWAIT is set; we will wakeup the parent below.
	 */
	p->p_flag &= ~(P_TRACED | P_PPWAIT);
	p->p_sigignore = ~0;
	p->p_siglist = 0;

	ut->uu_siglist = 0;
	untimeout(realitexpire, (caddr_t)p->p_pid);

	p->p_xstat = rv;

	vproc_exit(p);
}

void 
vproc_exit(struct proc *p)
{
	register struct proc *q, *nq, *pp;
#ifdef FIXME
	struct task *task = p->task;
#endif

	/* XXX Zombie allocation may fail, in which case stats get lost */
	MALLOC_ZONE(p->p_ru, struct rusage *,
			sizeof (*p->p_ru), M_ZOMBIE, M_WAITOK);

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdfree(p);

	if (SESS_LEADER(p)) {
		register struct session *sp = p->p_session;

		if (sp->s_ttyvp) {
			struct vnode *ttyvp;
			struct vfs_context context;

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
				context.vc_proc = p;
				context.vc_ucred = p->p_ucred;
				if (sp->s_ttyvp)
					VNOP_REVOKE(sp->s_ttyvp, REVOKEALL, &context);
			}
			ttyvp = sp->s_ttyvp;
			sp->s_ttyvp = NULL;
			if (ttyvp) {
				vnode_rele(ttyvp);
			}
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
	p->p_traceflag = 0;	/* don't trace the vnode_rele() */
	if (p->p_tracep) {
		struct vnode *tvp = p->p_tracep;
		p->p_tracep = NULL;
		vnode_rele(tvp);
	}
#endif

	while (q = p->p_children.lh_first) {
		proc_reparent(q, initproc);
		/*
		 * Traced processes are killed
		 * since their existence means someone is messing up.
		 */
		if (q->p_flag & P_TRACED) {
			q->p_flag &= ~P_TRACED;
			if (q->sigwait_thread) {
				/*
				 * The sigwait_thread could be stopped at a
				 * breakpoint. Wake it up to kill.
				 * Need to do this as it could be a thread which is not
				 * the first thread in the task. So any attempts to kill
				 * the process would result into a deadlock on q->sigwait.
				 */
				thread_resume((thread_t)q->sigwait_thread);
				clear_wait(q->sigwait_thread, THREAD_INTERRUPTED);
				threadsignal((thread_t)q->sigwait_thread, SIGKILL, 0);
			}
			psignal(q, SIGKILL);
		}
	}

	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.  If we were unable to allocate a zombie
	 * structure, this information is lost.
	 */
	if (p->p_ru != NULL) {
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
	}

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
			kfree(p1, sizeof *p1);
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
	pp = p->p_pptr;
	if (pp != initproc) {
		pp->si_pid = p->p_pid;
		pp->si_status = p->p_xstat;
		pp->si_code = CLD_EXITED;
		pp->si_uid = p->p_ucred->cr_ruid;
	}
	/* mark as a zombie */
	p->p_stat = SZOMB;

	psignal(p->p_pptr, SIGCHLD);

	/* and now wakeup the parent */
	wakeup((caddr_t)p->p_pptr);
}

						
/*
 * munge_rusage
 *	LP64 support - long is 64 bits if we are dealing with a 64 bit user
 *	process.  We munge the kernel (32 bit) version of rusage into the
 *	64 bit version.
 */
__private_extern__  void 
munge_rusage(struct rusage *a_rusage_p, struct user_rusage *a_user_rusage_p)
{
	/* timeval changes size, so utime and stime need special handling */
	a_user_rusage_p->ru_utime.tv_sec = a_rusage_p->ru_utime.tv_sec;
	a_user_rusage_p->ru_utime.tv_usec = a_rusage_p->ru_utime.tv_usec;
	a_user_rusage_p->ru_stime.tv_sec = a_rusage_p->ru_stime.tv_sec;
	a_user_rusage_p->ru_stime.tv_usec = a_rusage_p->ru_stime.tv_usec;
	/*
	 * everything else can be a direct assign, since there is no loss
	 * of precision implied boing 32->64.
	 */
	a_user_rusage_p->ru_maxrss = a_rusage_p->ru_maxrss;
	a_user_rusage_p->ru_ixrss = a_rusage_p->ru_ixrss;
	a_user_rusage_p->ru_idrss = a_rusage_p->ru_idrss;
	a_user_rusage_p->ru_isrss = a_rusage_p->ru_isrss;
	a_user_rusage_p->ru_minflt = a_rusage_p->ru_minflt;
	a_user_rusage_p->ru_majflt = a_rusage_p->ru_majflt;
	a_user_rusage_p->ru_nswap = a_rusage_p->ru_nswap;
	a_user_rusage_p->ru_inblock = a_rusage_p->ru_inblock;
	a_user_rusage_p->ru_oublock = a_rusage_p->ru_oublock;
	a_user_rusage_p->ru_msgsnd = a_rusage_p->ru_msgsnd;
	a_user_rusage_p->ru_msgrcv = a_rusage_p->ru_msgrcv;
	a_user_rusage_p->ru_nsignals = a_rusage_p->ru_nsignals;
	a_user_rusage_p->ru_nvcsw = a_rusage_p->ru_nvcsw;
	a_user_rusage_p->ru_nivcsw = a_rusage_p->ru_nivcsw;
}
