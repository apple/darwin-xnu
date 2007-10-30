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
 *	@(#)kern_exit.c	8.7 (Berkeley) 2/12/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
 
#include <machine/reg.h>
#include <machine/psl.h>

#include "compat_43.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/proc.h>
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
#if SYSV_SHM
#include <sys/shm_internal.h>	/* shmexit */
#endif
#include <sys/acct.h>		/* acct_process */

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <kern/sched_prim.h>
#include <kern/assert.h>
#if CONFIG_DTRACE
/* Do not include dtrace.h, it redefines kmem_[alloc/free] */
extern void (*dtrace_fasttrap_exit_ptr)(proc_t);
extern void (*dtrace_helpers_cleanup)(proc_t);
extern void dtrace_lazy_dofs_destroy(proc_t);

#include <sys/dtrace_ptss.h>
#endif

#if CONFIG_MACF
#include <security/mac.h>
#include <sys/syscall.h>
#endif

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/mach_traps.h>	/* init_process */

#include <sys/sdt.h>

extern char init_task_failure_data[];
void proc_prepareexit(proc_t p, int rv);
void vfork_exit(proc_t p, int rv);
void vproc_exit(proc_t p);
__private_extern__ void munge_rusage(struct rusage *a_rusage_p, struct user_rusage *a_user_rusage_p);
static int reap_child_locked(proc_t parent, proc_t child, int deadparent, int locked, int droplock);

/*
 * Things which should have prototypes in headers, but don't
 */
void	*get_bsduthreadarg(thread_t);
void	proc_exit(proc_t p);
int	wait1continue(int result);
int	waitidcontinue(int result);
int	*get_bsduthreadrval(thread_t);
kern_return_t sys_perf_notify(thread_t thread, int pid);
kern_return_t abnormal_exit_notify(mach_exception_data_type_t code, 
		mach_exception_data_type_t subcode);
int 	in_shutdown(void);
void workqueue_exit(struct proc *);
void	delay(int);
			
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
	out->__pad[0]	= in->pad[0];			/* mcontext.ss.r1 */
}

/*
 * exit --
 *	Death of process.
 */
void
exit(proc_t p, struct exit_args *uap, int *retval)
{
	exit1(p, W_EXITCODE(uap->rval, 0), retval);

	/* drop funnel before we return */
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
exit1(proc_t p, int rv, int *retval)
{
	thread_t self = current_thread();
	struct task *task = p->task;
	struct uthread *ut;

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	 ut = get_bsdthread_info(self);
	 if (ut->uu_flag & UT_VFORK) {
			vfork_exit(p, rv);
			vfork_return(p , retval, p->p_pid);
			unix_syscall_return(0);
			/* NOT REACHED */
	 }

	/* 
	 * The parameter list of audit_syscall_exit() was augmented to
	 * take the Darwin syscall number as the first parameter,
	 * which is currently required by mac_audit_postselect().
	 */

	AUDIT_SYSCALL_EXIT(SYS_exit, p, ut, 0); /* Exit is always successfull */

	DTRACE_PROC1(exit, int, CLD_EXITED);

        proc_lock(p);
	while (p->exit_thread != self) {
		if (sig_try_locked(p) <= 0) {
			if (get_threadtask(self) != task) {
				proc_unlock(p);
				return(0);
                        }
			proc_unlock(p);
			thread_terminate(self);
			thread_exception_return();
			/* NOTREACHED */
		}
		sig_lock_to_exit(p);
	}
#if !CONFIG_EMBEDDED /* BER_XXX */
	if (p->p_pid == 1) {
		proc_unlock(p);
		printf("pid 1 exited (signal %d, exit %d)",
		    WTERMSIG(rv), WEXITSTATUS(rv));
		panic("%s died\nState at Last Exception:\n\n%s", 
							(p->p_comm[0] != '\0' ?
								p->p_comm :
								"launchd"),
							init_task_failure_data);
	}
#endif

	p->p_lflag |= P_LEXIT;
	p->p_xstat = rv;

	proc_unlock(p);

	proc_prepareexit(p, rv);

	/* task terminate will call proc_terminate and that cleans it up */
	task_terminate_internal(task);

	return(0);
}

void
proc_prepareexit(proc_t p, int rv) 
{
	mach_exception_data_type_t code, subcode;
	struct uthread *ut;
	thread_t self = current_thread();
	ut = get_bsdthread_info(self);

 	/* If a core should be generated, notify crash reporter */
	if (!in_shutdown() && hassigprop(WTERMSIG(rv), SA_CORE)) {
		/* 
		 * Workaround for processes checking up on PT_DENY_ATTACH:
		 * should be backed out post-Leopard (details in 5431025).
		 */
		if ((SIGSEGV == WTERMSIG(rv)) && 
				(p->p_pptr->p_lflag & P_LNOATTACH)) {
			goto skipcheck;
		}

		/*
		 * Crash Reporter looks for the signal value, original exception
		 * type, and low 20 bits of the original code in code[0] 
		 * (8, 4, and 20 bits respectively). code[1] is unmodified. 
		 */
		code = ((WTERMSIG(rv) & 0xff) << 24) |
			((ut->uu_exception & 0x0f) << 20) | 
			((int)ut->uu_code & 0xfffff);
		subcode = ut->uu_subcode;
		(void) abnormal_exit_notify(code, subcode);
	}

skipcheck:
	/* Notify the perf server */
	(void)sys_perf_notify(self, p->p_pid);

	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */

	proc_list_lock();

	LIST_REMOVE(p, p_list);
	LIST_INSERT_HEAD(&zombproc, p, p_list);	/* Place onto zombproc. */
	/* will not be visible via proc_find */
	p->p_listflag |= P_LIST_EXITED;

	proc_list_unlock();


#ifdef PGINPROF
	vmsizmon();
#endif
	/*
	 * If parent is waiting for us to exit or exec,
	 * P_LPPWAIT is set; we will wakeup the parent below.
	 */
	proc_lock(p);
	p->p_lflag &= ~(P_LTRACED | P_LPPWAIT);
	p->p_sigignore = ~(sigcantmask);
	ut->uu_siglist = 0;
	proc_unlock(p);
}

void 
proc_exit(proc_t p)
{
	proc_t q;
	proc_t pp;
	struct task *task = p->task;
	boolean_t fstate;
	vnode_t tvp = NULLVP;
	struct pgrp * pg;
	struct session *sessp;
	struct uthread * uth;

	/* This can happen if thread_terminate of the single thread
	 * process 
	 */

	uth = (struct uthread *)get_bsdthread_info(current_thread());

	proc_lock(p);
	if( !(p->p_lflag & P_LEXIT)) {
		p->p_lflag |= P_LEXIT;
		proc_unlock(p);
		proc_prepareexit(p, 0);	
		proc_lock(p);
	}

	p->p_lflag |= P_LPEXIT;
	proc_unlock(p);

#if CONFIG_DTRACE
	/*
	 * Free any outstanding lazy dof entries. It is imperative we
	 * always call dtrace_lazy_dofs_destroy, rather than null check
	 * and call if !NULL. If we NULL test, during lazy dof faulting
	 * we can race with the faulting code and proceed from here to
	 * beyond the helpers cleanup. The lazy dof faulting will then
	 * install new helpers which will never be cleaned up, and leak.
	 */
	dtrace_lazy_dofs_destroy(p);

	/*
	 * Clean up any DTrace helper actions or probes for the process.
	 */
	if (p->p_dtrace_helpers != NULL) {
		(*dtrace_helpers_cleanup)(p);
	}

	/*
	 * Clean up any DTrace probes associated with this process.
	 */
	/*
	 * APPLE NOTE: We release ptss pages/entries in dtrace_fasttrap_exit_ptr(),
	 * call this after dtrace_helpers_cleanup()
	 */
	proc_lock(p);
	if (p->p_dtrace_probes && dtrace_fasttrap_exit_ptr) {
		(*dtrace_fasttrap_exit_ptr)(p);
	}
	proc_unlock(p);
#endif

	/* XXX Zombie allocation may fail, in which case stats get lost */
	MALLOC_ZONE(p->p_ru, struct rusage *,
			sizeof (*p->p_ru), M_ZOMBIE, M_WAITOK);

	/*
	 * need to cancel async IO requests that can be cancelled and wait for those
	 * already active.  MAY BLOCK!
	 */
	
	proc_refdrain(p);

	workqueue_exit(p);

	_aio_exit( p );

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdfree(p);

#if SYSV_SHM
	/* Close ref SYSV Shared memory*/
	if (p->vm_shm)
		shmexit(p);
#endif
#if SYSV_SEM
	/* Release SYSV semaphores */
	semexit(p);
#endif
	
	sessp = proc_session(p);
	if (SESS_LEADER(p, sessp)) {

		/* Protected by funnel for tty accesses */
		fstate = thread_funnel_set(kernel_flock, TRUE);

		if (sessp->s_ttyvp != NULLVP) {
			struct vnode *ttyvp;
			int ttyvid;
			struct vfs_context context;
			struct tty * tp;


			/*
			 * Controlling process.
			 * Signal foreground pgrp,
			 * drain controlling terminal
			 * and revoke access to controlling terminal.
			 */
			tp = sessp->s_ttyp;

			if ((tp != TTY_NULL) && (tp->t_session == sessp)) {
				tty_pgsignal(tp, SIGHUP, 1);
				(void) ttywait(tp);
				/*
				 * The tty could have been revoked
				 * if we blocked.
				 */

				session_lock(sessp);
				ttyvp = sessp->s_ttyvp;
				ttyvid = sessp->s_ttyvid;
				sessp->s_ttyvp = NULL;
				sessp->s_ttyvid = 0;
				sessp->s_ttyp = NULL;
				sessp->s_ttypgrpid = NO_PID;
				session_unlock(sessp);

				if ((ttyvp != NULLVP) && (vnode_getwithvid(ttyvp, ttyvid) == 0)) {
					context.vc_thread = proc_thread(p); /* XXX */
					context.vc_ucred = kauth_cred_proc_ref(p);
					VNOP_REVOKE(ttyvp, REVOKEALL, &context);
					vnode_put(ttyvp);
					kauth_cred_unref(&context.vc_ucred);
				}
			} else {
				session_lock(sessp);
				ttyvp = sessp->s_ttyvp;
				sessp->s_ttyvp = NULL;
				sessp->s_ttyvid = 0;
				sessp->s_ttyp = NULL;
				sessp->s_ttypgrpid = NO_PID;
				session_unlock(sessp);
			}
			if (ttyvp)
				vnode_rele(ttyvp);
			/*
			 * s_ttyp is not zero'd; we use this to indicate
			 * that the session once had a controlling terminal.
			 * (for logging and informational purposes)
			 */
		}
		
		(void) thread_funnel_set(kernel_flock, fstate);
		session_lock(sessp);
		sessp->s_leader = NULL;
		session_unlock(sessp);
	}
	session_rele(sessp);

	pg = proc_pgrp(p);
	fixjobc(p, pg, 0);
	pg_rele(pg);

	p->p_rlimit[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;
	(void)acct_process(p);

	proc_list_lock();
	/* wait till parentrefs are dropped and grant no more */
	proc_childdrainstart(p);
	while ((q = p->p_children.lh_first) != NULL) {
		q->p_listflag |= P_LIST_DEADPARENT;
		if (q->p_stat == SZOMB) {
			if (p != q->p_pptr)
				panic("parent child linkage broken");
			/* check for sysctl zomb lookup */
			while ((q->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
				msleep(&q->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
			}
			q->p_listflag |= P_LIST_WAITING;
			/*
			 * This is a named reference and it is not granted
			 * if the reap is already in progress. So we get
			 * the reference here exclusively and their can be
			 * no waiters. So there is no need for a wakeup
			 * after we are done. AlsO  the reap frees the structure
			 * and the proc struct cannot be used for wakeups as well. 
			 * It is safe to use q here as this is system reap
			 */
			(void)reap_child_locked(p, q, 1, 1, 0);
		} else {
			proc_reparentlocked(q, initproc, 0, 1);
			/*
		 	* Traced processes are killed
		 	* since their existence means someone is messing up.
		 	*/
			if (q->p_lflag & P_LTRACED) {
				proc_list_unlock();
				proc_lock(q);
				q->p_lflag &= ~P_LTRACED;
				if (q->sigwait_thread) {
					proc_unlock(q);
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
				} else
					proc_unlock(q);
				psignal(q, SIGKILL);
				proc_list_lock();
			}
		}
	}

	proc_childdrainend(p);
	proc_list_unlock();

	/*
	 * Release reference to text vnode
	 */
	tvp = p->p_textvp;
	p->p_textvp = NULL;
	if (tvp != NULLVP) {
		vnode_rele(tvp);
	}

	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.  If we were unable to allocate a zombie
	 * structure, this information is lost.
	 */
	/* No need for locking here as no one than this thread can access this */
	if (p->p_ru != NULL) {
	    *p->p_ru = p->p_stats->p_ru;

	    timerclear(&p->p_ru->ru_utime);
	    timerclear(&p->p_ru->ru_stime);

	    if (task) {
		task_basic_info_32_data_t tinfo;
		task_thread_times_info_data_t ttimesinfo;
		task_events_info_data_t teventsinfo;
		mach_msg_type_number_t task_info_stuff, task_ttimes_stuff;
		mach_msg_type_number_t task_events_stuff;
		struct timeval ut,st;

		task_info_stuff	= TASK_BASIC_INFO_32_COUNT;
		task_info(task, TASK_BASIC2_INFO_32,
			  (task_info_t)&tinfo, &task_info_stuff);
		p->p_ru->ru_utime.tv_sec = tinfo.user_time.seconds;
		p->p_ru->ru_utime.tv_usec = tinfo.user_time.microseconds;
		p->p_ru->ru_stime.tv_sec = tinfo.system_time.seconds;
		p->p_ru->ru_stime.tv_usec = tinfo.system_time.microseconds;

		p->p_ru->ru_maxrss = tinfo.resident_size;

		task_ttimes_stuff = TASK_THREAD_TIMES_INFO_COUNT;
		task_info(task, TASK_THREAD_TIMES_INFO,
			  (task_info_t)&ttimesinfo, &task_ttimes_stuff);

		ut.tv_sec = ttimesinfo.user_time.seconds;
		ut.tv_usec = ttimesinfo.user_time.microseconds;
		st.tv_sec = ttimesinfo.system_time.seconds;
		st.tv_usec = ttimesinfo.system_time.microseconds;
		timeradd(&ut,&p->p_ru->ru_utime,&p->p_ru->ru_utime);
		timeradd(&st,&p->p_ru->ru_stime,&p->p_ru->ru_stime);

		task_events_stuff = TASK_EVENTS_INFO_COUNT;
		task_info(task, TASK_EVENTS_INFO,
			  (task_info_t)&teventsinfo, &task_events_stuff);

		p->p_ru->ru_minflt = (teventsinfo.faults -
				      teventsinfo.pageins);
		p->p_ru->ru_majflt = teventsinfo.pageins;
		p->p_ru->ru_nivcsw = (teventsinfo.csw -
				      p->p_ru->ru_nvcsw);
		if (p->p_ru->ru_nivcsw < 0)
			p->p_ru->ru_nivcsw = 0;
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

	proc_spinlock(p);
	if (thread_call_cancel(p->p_rcall))
		p->p_ractive--;

	while (p->p_ractive > 0) {
		proc_spinunlock(p);
		
		delay(1);

		proc_spinlock(p);
	}
	proc_spinunlock(p);

	thread_call_free(p->p_rcall);
	p->p_rcall = NULL;

	/*
	 * Other substructures are freed from wait().
	 */
	FREE_ZONE(p->p_stats, sizeof *p->p_stats, M_PSTATS);
	p->p_stats = NULL;

	FREE_ZONE(p->p_sigacts, sizeof *p->p_sigacts, M_SIGACTS);
	p->p_sigacts = NULL;

	proc_limitdrop(p, 1);
	p->p_limit = NULL;


	/*
	 * Finish up by terminating the task
	 * and halt this thread (only if a
	 * member of the task exiting).
	 */
	p->task = TASK_NULL;
	set_bsdtask_info(task, NULL);

	proc_knote(p, NOTE_EXIT);

	/* mark the thread as the one that is doing proc_exit
	 * no need to hold proc lock in uthread_free
	 */
	uth->uu_flag |= UT_PROCEXIT;
	/*
	 * Notify parent that we're gone.
	 */
	pp = proc_parent(p);
	if (pp->p_flag & P_NOCLDWAIT) {

#if 3839178
		/*
		 * If the parent is ignoring SIGCHLD, then POSIX requires
		 * us to not add the resource usage to the parent process -
		 * we are only going to hand it off to init to get reaped.
		 * We should contest the standard in this case on the basis
		 * of RLIMIT_CPU.
		 */
#else	/* !3839178 */
		/*
		 * Add child resource usage to parent before giving
		 * zombie to init.  If we were unable to allocate a
		 * zombie structure, this information is lost.
		 */
		if (p->p_ru != NULL) {
			proc_lock(pp);
			ruadd(&pp->p_stats->p_cru, p->p_ru);
			proc_unlock(pp);
		}
#endif	/* !3839178 */

		/* kernel can reap this one, no need to move it to launchd */
		proc_list_lock();
		p->p_listflag |= P_LIST_DEADPARENT;
		proc_list_unlock();
	}
	if ((p->p_listflag & P_LIST_DEADPARENT) == 0) {
		if (pp != initproc) {
			proc_lock(pp);
			pp->si_pid = p->p_pid;
			pp->si_status = p->p_xstat;
			pp->si_code = CLD_EXITED;
			/*
			 * p_ucred usage is safe as it is an exiting process
			 * and reference is dropped in reap
			 */
			pp->si_uid = p->p_ucred->cr_ruid;
			proc_unlock(pp);
		}
		/* mark as a zombie */
		/* No need to take proc lock as all refs are drained and
		 * no one except parent (reaping ) can look at this.
		 * The write is to an int and is coherent. Also parent is
		 *  keyed off of list lock for reaping
		 */
		p->p_stat = SZOMB;
		/* 
		 * The current process can be reaped so, no one
		 * can depend on this
		 */

		psignal(pp, SIGCHLD);
	
		/* and now wakeup the parent */
		proc_list_lock();
		wakeup((caddr_t)pp);
		proc_list_unlock();
	} else {
		/* should be fine as parent proc would be initproc */
		/* mark as a zombie */
		/* No need to take proc lock as all refs are drained and
		 * no one except parent (reaping ) can look at this.
		 * The write is to an int and is coherent. Also parent is
		 *  keyed off of list lock for reaping
		 */
		proc_list_lock();
		p->p_stat = SZOMB;
		/* check for sysctl zomb lookup */
		while ((p->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
			msleep(&p->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
		}
		/* safe to use p as this is a system reap */
		p->p_listflag |= P_LIST_WAITING;
		/*
		 * This is a named reference and it is not granted
		 * if the reap is already in progress. So we get
		 * the reference here exclusively and their can be
		 * no waiters. So there is no need for a wakeup
		 * after we are done. AlsO  the reap frees the structure
		 * and the proc struct cannot be used for wakeups as well. 
		 * It is safe to use p here as this is system reap
		 */
		(void)reap_child_locked(pp, p, 1, 1, 1);
		/* list lock dropped by reap_child_locked */
	}

	proc_rele(pp);

}


/*
 * reap_child_locked
 *
 * Description:	Given a process from which all status information needed
 *		has already been extracted, if the process is a ptrace
 *		attach process, detach it and give it back to its real
 *		parent, else recover all resources remaining associated
 *		with it.
 *
 * Parameters:	proc_t parent		Parent of process being reaped
 *		proc_t child		Process to reap
 *
 * Returns:	0			Process was not reaped because it
 *					came from an attach
 *		1			Process was reaped
 */
static int
reap_child_locked(proc_t parent, proc_t child, int deadparent, int locked, int droplock)
{
	proc_t trace_parent;	/* Traced parent process, if tracing */

	/*
	 * If we got the child via a ptrace 'attach',
	 * we need to give it back to the old parent.
	 */
	if (locked == 1)
		proc_list_unlock();
	if (child->p_oppid && (trace_parent = proc_find(child->p_oppid))) {
		proc_lock(child);
		child->p_oppid = 0;
		proc_unlock(child);
		if (trace_parent != initproc) {
			/* 
			 * proc internal fileds  and p_ucred usage safe 
			 * here as child is dead and is not reaped or 
			 * reparented yet 
			 */
			proc_lock(trace_parent);
			trace_parent->si_pid = child->p_pid;
			trace_parent->si_status = child->p_xstat;
			trace_parent->si_code = CLD_CONTINUED;
			trace_parent->si_uid = child->p_ucred->cr_ruid;
			proc_unlock(trace_parent);
		}
		proc_reparentlocked(child, trace_parent, 1, 0);
		psignal(trace_parent, SIGCHLD);
		proc_list_lock();
		wakeup((caddr_t)trace_parent);
		child->p_listflag &= ~P_LIST_WAITING;
		wakeup(&child->p_stat);
		proc_list_unlock();
		proc_rele(trace_parent);
		if ((locked == 1) && (droplock == 0))
			proc_list_lock();
		return (0);
	}

	proc_knote(child, NOTE_REAP);

	child->p_xstat = 0;
	if (child->p_ru) {
		proc_lock(parent);
#if 3839178
		/*
		 * If the parent is ignoring SIGCHLD, then POSIX requires
		 * us to not add the resource usage to the parent process -
		 * we are only going to hand it off to init to get reaped.
		 * We should contest the standard in this case on the basis
		 * of RLIMIT_CPU.
		 */
		if (!(parent->p_flag & P_NOCLDWAIT))
#endif	/* 3839178 */
			ruadd(&parent->p_stats->p_cru, child->p_ru);
		proc_unlock(parent);
		FREE_ZONE(child->p_ru, sizeof *child->p_ru, M_ZOMBIE);
		child->p_ru = NULL;
	} else {
		printf("Warning : lost p_ru for %s\n", child->p_comm);
	}

	/*
	 * Decrement the count of procs running with this uid.
	 * p_ucred usage is safe here as it is an exited process.
	 * and refernce is dropped after these calls down below
	 * (locking protection is provided by list lock held in chgproccnt)
	 */
	(void)chgproccnt(child->p_ucred->cr_ruid, -1);

#if CONFIG_LCTX
	ALLLCTX_LOCK;
	leavelctx(child);
	ALLLCTX_UNLOCK;
#endif

	/*
	 * Free up credentials.
	 */
	if (IS_VALID_CRED(child->p_ucred)) {
		kauth_cred_unref(&child->p_ucred);
	}

	/*  XXXX Note NOT SAFE TO USE p_ucred from this point onwards */

	/*
	 * Finally finished with old proc entry.
	 * Unlink it from its process group and free it.
	 */
	leavepgrp(child);

	proc_list_lock();
	LIST_REMOVE(child, p_list);	/* off zombproc */
	parent->p_childrencnt--;
	LIST_REMOVE(child, p_sibling);
	/* If there are no more children wakeup parent */
	if ((deadparent != 0) && (LIST_EMPTY(&parent->p_children)))
		wakeup((caddr_t)parent);	/* with list lock held */
	child->p_listflag &= ~P_LIST_WAITING;
	wakeup(&child->p_stat);

	/* Take it out of process hash */
	LIST_REMOVE(child, p_hash);
	child->p_listflag &= ~P_LIST_INHASH;
	proc_checkdeadrefs(child);
	nprocs--;

	proc_list_unlock();

	lck_mtx_destroy(&child->p_mlock, proc_lck_grp);
	lck_mtx_destroy(&child->p_fdmlock, proc_lck_grp);
#if CONFIG_DTRACE
	lck_mtx_destroy(&child->p_dtrace_sprlock, proc_lck_grp);
#endif
	lck_spin_destroy(&child->p_slock, proc_lck_grp);
	workqueue_destroy_lock(child);

	FREE_ZONE(child, sizeof *child, M_PROC);
	if ((locked == 1) && (droplock == 0))
		proc_list_lock();

	return (1);
}


int
wait1continue(int result)
{
	void *vt;
	thread_t thread;
	int *retval;
	proc_t p;

	if (result)
		return(result);

	p = current_proc();
	thread = current_thread();
	vt = get_bsduthreadarg(thread);
	retval = get_bsduthreadrval(thread);
	return(wait4(p, (struct wait4_args *)vt, retval));
}

int
wait4(proc_t q, struct wait4_args *uap, register_t *retval)
{
	__pthread_testcancel(1);
	return(wait4_nocancel(q, (struct wait4_nocancel_args *)uap, retval));
}

int
wait4_nocancel(proc_t q, struct wait4_nocancel_args *uap, register_t *retval)
{
	int nfound;
	proc_t p;
	int status, error;

	if (uap->pid == 0)
		uap->pid = -q->p_pgrpid;

loop:
	proc_list_lock();
loop1:
	nfound = 0;
	for (p = q->p_children.lh_first; p != 0; p = p->p_sibling.le_next) {
		if (uap->pid != WAIT_ANY &&
		    p->p_pid != uap->pid &&
		    p->p_pgrpid != -(uap->pid))
			continue;

		nfound++;

		/* XXX This is racy because we don't get the lock!!!! */

		if (p->p_listflag & P_LIST_WAITING) {
			(void)msleep(&p->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
			goto loop1;
		}
		p->p_listflag |= P_LIST_WAITING;   /* only allow single thread to wait() */


		if (p->p_stat == SZOMB) {
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif
			retval[0] = p->p_pid;
			if (uap->status) {
				/* Legacy apps expect only 8 bits of status */
				status = 0xffff & p->p_xstat;	/* convert to int */
				error = copyout((caddr_t)&status,
				   			uap->status,
						    sizeof(status));
				if (error) 
					goto out;
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
				if (error) 
					goto out;
			}

			/* Clean up */
			if (!reap_child_locked(q, p, 0, 0, 0)) {
				proc_list_lock();
				p->p_listflag &= ~P_LIST_WAITING;
				wakeup(&p->p_stat);
				proc_list_unlock();
			}

			return (0);
		}
		if (p->p_stat == SSTOP && (p->p_lflag & P_LWAITED) == 0 &&
		    (p->p_lflag & P_LTRACED || uap->options & WUNTRACED)) {
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif
			proc_lock(p);
			p->p_lflag |= P_LWAITED;
			proc_unlock(p);
			retval[0] = p->p_pid;
			if (uap->status) {
				status = W_STOPCODE(p->p_xstat);
				error = copyout((caddr_t)&status,
					uap->status,
				    sizeof(status));
			} else
				error = 0;
			goto out;
		}
		/*
		 * If we are waiting for continued processses, and this
		 * process was continued
		 */
		if ((uap->options & WCONTINUED) &&
		    (p->p_flag & P_CONTINUED)) {
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0)
				goto out;
#endif

			/* Prevent other process for waiting for this event */
			OSBitAndAtomic(~((uint32_t)P_CONTINUED), (UInt32 *)&p->p_flag);
			retval[0] = p->p_pid;
			if (uap->status) {
				status = W_STOPCODE(SIGCONT);
				error = copyout((caddr_t)&status,
					uap->status,
				    sizeof(status));
			} else
				error = 0;
			goto out;
		}
		p->p_listflag &= ~P_LIST_WAITING;
		wakeup(&p->p_stat);
	}
	/* list lock is held when we get here any which way */
	if (nfound == 0) {
		proc_list_unlock();
		return (ECHILD);
	}

	if (uap->options & WNOHANG) {
		retval[0] = 0;
		proc_list_unlock();
		return (0);
	}

	if ((error = msleep0((caddr_t)q, proc_list_mlock, PWAIT | PCATCH | PDROP, "wait", 0, wait1continue)))
		return (error);

	goto loop;
out:
	proc_list_lock();
	p->p_listflag &= ~P_LIST_WAITING;
	wakeup(&p->p_stat);
	proc_list_unlock();
	return (error);
}


int
waitidcontinue(int result)
{
	void *vt;
	thread_t thread;
	int *retval;

	if (result)
		return(result);

	thread = current_thread();
	vt = get_bsduthreadarg(thread);
	retval = get_bsduthreadrval(thread);
	return(waitid(current_proc(), (struct waitid_args *)vt, retval));
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
waitid(proc_t q, struct waitid_args *uap, register_t *retval)
{
	__pthread_testcancel(1);
	return(waitid_nocancel(q, (struct waitid_nocancel_args *)uap, retval));
}

int
waitid_nocancel(proc_t q, struct waitid_nocancel_args *uap, __unused register_t *retval)
{
	user_siginfo_t	collect64;	/* siginfo data to return to caller */

	int nfound;
	proc_t p;
	int error;

	/*
	 * Forced validation of options for T.waitpid 21; should be a TSD!
	 * This will pass the test, but note that we have more bits than the
	 * standard specifies that we will allow in, in this case.  The test
	 * passes because they light all the bits, not just the ones we allow,
	 * and so the following check returns EINVAL like the test wants.
	 */
	if (((uap->options & (WNOHANG|WNOWAIT|WCONTINUED|WUNTRACED|WSTOPPED|WEXITED)) != uap->options) ||
	    (uap->options == 0))
		return (EINVAL);	/* bits set that aren't recognized */

	/*
	 * Overly critical options checking, per POSIX
	 */
	switch(uap->idtype) {
	case P_PID:	/* child with process ID equal to... */
	case P_PGID:	/* child with process group ID equal to... */
		if (((int)uap->id) < 0)
			return (EINVAL);
		break;
	case P_ALL:	/* any child */
		break;
	}

loop:
	proc_list_lock();
loop1:
	nfound = 0;
	for (p = q->p_children.lh_first; p != 0; p = p->p_sibling.le_next) {
		switch(uap->idtype) {
		case P_PID:	/* child with process ID equal to... */
			if (p->p_pid != (pid_t)uap->id)
				continue;
			break;
		case P_PGID:	/* child with process group ID equal to... */
			if (p->p_pgrpid != (pid_t)uap->id)
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
		if (p->p_listflag & P_LIST_WAITING) {
			(void)msleep(&p->p_stat, proc_list_mlock, PWAIT, "waitidcoll", 0);
			goto loop1;
		}
		p->p_listflag |= P_LIST_WAITING;		/* mark busy */

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

			/* drop the lock and the thread is going to return */
			proc_list_unlock();

			/* Collect "siginfo" information for caller */
			collect64.si_signo = SIGCHLD;
			collect64.si_code = 0;
			collect64.si_errno = 0;
			collect64.si_pid = 0;
			collect64.si_uid = 0;
			collect64.si_addr  = 0;
			collect64.si_status = WEXITSTATUS(p->p_xstat);
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
			if (error) 
				goto out;

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				/* Clean up */
				if (!reap_child_locked(q, p, 0, 0, 0)) {
					proc_list_lock();
					p->p_listflag &= ~P_LIST_WAITING;
					wakeup(&p->p_stat);
					proc_list_unlock();
				}
			} else {
				proc_list_lock();
				p->p_listflag &= ~P_LIST_WAITING;
				proc_list_unlock();
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
			if ((p->p_lflag & P_LWAITED) != 0)
				break;

			/* drop the lock and the thread is going to return */
			proc_list_unlock();

			/* Collect "siginfo" information for caller */
			collect64.si_signo = SIGCHLD;
			collect64.si_code = 0;
			collect64.si_errno = 0;
			collect64.si_pid = 0;
			collect64.si_uid = 0;
			collect64.si_addr  = 0;
			proc_lock(p);
			collect64.si_status = p->p_xstat;
			proc_unlock(p);
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
			if (error)
				goto out;

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				proc_lock(p);
				p->p_lflag |= P_LWAITED;
				proc_unlock(p);
			}

			error = 0;
			goto out;

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

			/* drop the lock and the thread is going to return */
			proc_list_unlock();

			/* Collect "siginfo" information for caller */
			proc_lock(p);
			collect64.si_signo = SIGCHLD;
			collect64.si_code = CLD_CONTINUED;
			collect64.si_errno = 0;
			collect64.si_pid = p->p_contproc;
			collect64.si_uid = 0;
			collect64.si_addr  = 0;
			collect64.si_status = p->p_xstat;
			collect64.si_band = 0;
			proc_unlock(p);

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
			if (error)
				goto out;

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				OSBitAndAtomic(~((uint32_t)P_CONTINUED), (UInt32 *)&p->p_flag);
			}

			error = 0;
			goto out;
		}
		/* LIST LOCK IS HELD HERE */
		/* Not a process we are interested in; go on to next child */
		
		p->p_listflag &= ~P_LIST_WAITING;
		wakeup(&p->p_stat);
	}

	/* list lock is always held */
	/* No child processes that could possibly satisfy the request? */
	if (nfound == 0) {
		proc_list_unlock();
		return (ECHILD);
	}

	if (uap->options & WNOHANG) {
		proc_list_unlock();
		return (0);
	}

	if ((error = msleep0((caddr_t)q, proc_list_mlock, PWAIT | PCATCH | PDROP, "waitid", 0, waitidcontinue)))
		return (error);

	goto loop;
out:
	proc_list_lock();
	p->p_listflag &= ~P_LIST_WAITING;
	wakeup(&p->p_stat);
	proc_list_unlock();
	return (error);
}

/*
 * make process 'parent' the new parent of process 'child'.
 */
void
proc_reparentlocked(proc_t child, proc_t parent, int cansignal, int locked)
{
	proc_t oldparent = PROC_NULL;

	if (child->p_pptr == parent)
		return;

	if (locked == 0)
		proc_list_lock();

	oldparent = child->p_pptr;
#if __PROC_INTERNAL_DEBUG
	if (oldparent == PROC_NULL)
		panic("proc_reparent: process %x does not have a parent\n", (unsigned int)child);
#endif

	LIST_REMOVE(child, p_sibling);
#if __PROC_INTERNAL_DEBUG
	if (oldparent->p_childrencnt == 0)
		panic("process children count already 0\n");
#endif
	oldparent->p_childrencnt--;
#if __PROC_INTERNAL_DEBUG1
	if (oldparent->p_childrencnt < 0)
		panic("process children count -ve\n");
#endif
	LIST_INSERT_HEAD(&parent->p_children, child, p_sibling);
	parent->p_childrencnt++;	
	child->p_pptr = parent;
	child->p_ppid = parent->p_pid;

	proc_list_unlock();

	if ((cansignal != 0) && (initproc == parent) && (child->p_stat == SZOMB))
		psignal(initproc, SIGCHLD);
	if (locked == 1)
		proc_list_lock();
}

/*
 *	Make the current process an "init" process, meaning
 *	that it doesn't have a parent, and that it won't be
 *	gunned down by kill(-1, 0).
 */
kern_return_t
init_process(__unused struct init_process_args *args)
{
	proc_t p = current_proc();

	AUDIT_MACH_SYSCALL_ENTER(AUE_INITPROCESS);
	if (suser(kauth_cred_get(), &p->p_acflag)) {
		AUDIT_MACH_SYSCALL_EXIT(KERN_NO_ACCESS);
		return(KERN_NO_ACCESS);
	}

	if (p->p_pid != 1 && p->p_pgrpid != p->p_pid)
		enterpgrp(p, p->p_pid, 0);
	OSBitOrAtomic(P_SYSTEM, (UInt32 *)&p->p_flag);

	/*
	 *	Take us out of the sibling chain, and
	 *	out of our parent's child chain.
	 */
	proc_list_lock();
	LIST_REMOVE(p, p_sibling);
	p->p_sibling.le_prev = NULL;
	p->p_sibling.le_next = NULL;
	p->p_pptr = kernproc;
	p->p_ppid = 0;
	proc_list_unlock();


	AUDIT_MACH_SYSCALL_EXIT(KERN_SUCCESS);
	return(KERN_SUCCESS);
}


/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */

void
vfork_exit(proc_t p, int rv)
{
	vfork_exit_internal(p, rv, 0);
}

void
vfork_exit_internal(proc_t p, int rv, int forceexit)
{
	thread_t self = current_thread();
#ifdef FIXME
	struct task *task = p->task;
#endif
	struct uthread *ut;

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	 ut = get_bsdthread_info(self);


	proc_lock(p);
	 if ((p->p_lflag & P_LPEXIT) == P_LPEXIT) {
		/* 
	 	* This happens when a parent exits/killed and vfork is in progress  
		* other threads. But shutdown code for ex has already called exit1()
	 	*/
		proc_unlock(p);
		return;
	}
	p->p_lflag |= (P_LEXIT | P_LPEXIT);
	proc_unlock(p);

	if (forceexit == 0) {
		/*
		 * parent of a vfork child has already called exit() and the 
		 * thread that has vfork in proress terminates. So there is no
		 * separate address space here and it has already been marked for
		 * termination. This was never covered before and could cause problems
		 * if we block here for outside code.
		 */
		/* Notify the perf server */
		(void)sys_perf_notify(self, p->p_pid);
	}

	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */

	proc_list_lock();

	LIST_REMOVE(p, p_list);
	LIST_INSERT_HEAD(&zombproc, p, p_list);	/* Place onto zombproc. */
	/* will not be visible via proc_find */
	p->p_listflag |= P_LIST_EXITED;

	proc_list_unlock();

	proc_lock(p);
	p->p_xstat = rv;
	p->p_lflag &= ~(P_LTRACED | P_LPPWAIT);
	p->p_sigignore = ~0;
	proc_unlock(p);

	proc_spinlock(p);
	if (thread_call_cancel(p->p_rcall))
		p->p_ractive--;

	while (p->p_ractive > 0) {
		proc_spinunlock(p);
		
		delay(1);

		proc_spinlock(p);
	}
	proc_spinunlock(p);

	thread_call_free(p->p_rcall);
	p->p_rcall = NULL;

	ut->uu_siglist = 0;

	vproc_exit(p);
}

void 
vproc_exit(proc_t p)
{
	proc_t q;
	proc_t pp;
	
	vnode_t tvp;
#ifdef FIXME
	struct task *task = p->task;
#endif
	struct pgrp * pg;
	struct session *sessp;
	boolean_t fstate;

	/* XXX Zombie allocation may fail, in which case stats get lost */
	MALLOC_ZONE(p->p_ru, struct rusage *,
			sizeof (*p->p_ru), M_ZOMBIE, M_WAITOK);


	proc_refdrain(p);

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdfree(p);

	sessp = proc_session(p);
	if (SESS_LEADER(p, sessp)) {
		
		/* Protected by funnel for tty accesses */
		fstate = thread_funnel_set(kernel_flock, TRUE);

		if (sessp->s_ttyvp != NULLVP) {
			struct vnode *ttyvp;
			int ttyvid;
			struct vfs_context context;
			struct tty * tp;

			/*
			 * Controlling process.
			 * Signal foreground pgrp,
			 * drain controlling terminal
			 * and revoke access to controlling terminal.
			 */
			tp = sessp->s_ttyp;

			if ((tp != TTY_NULL) && (tp->t_session == sessp)) {
				tty_pgsignal(tp, SIGHUP, 1);
				(void) ttywait(tp);
				/*
				 * The tty could have been revoked
				 * if we blocked.
				 */

				session_lock(sessp);
				ttyvp = sessp->s_ttyvp;
				ttyvid = sessp->s_ttyvid;
				sessp->s_ttyvp = NULL;
				sessp->s_ttyvid = 0;
				sessp->s_ttyp = NULL;
				sessp->s_ttypgrpid = NO_PID;
				session_unlock(sessp);

			       if ((ttyvp != NULLVP) && (vnode_getwithvid(ttyvp, ttyvid) == 0)) {
					context.vc_thread = proc_thread(p); /* XXX */
					context.vc_ucred = kauth_cred_proc_ref(p);
					VNOP_REVOKE(ttyvp, REVOKEALL, &context);
					vnode_put(ttyvp);
					kauth_cred_unref(&context.vc_ucred);
				}
			} else {
				session_lock(sessp);
				ttyvp = sessp->s_ttyvp;
				sessp->s_ttyvp = NULL;
				sessp->s_ttyvid = 0;
				sessp->s_ttyp = NULL;
				sessp->s_ttypgrpid = NO_PID;
				session_unlock(sessp);
			}
			if (ttyvp) 
				vnode_rele(ttyvp);
			/*
			 * s_ttyp is not zero'd; we use this to indicate
			 * that the session once had a controlling terminal.
			 * (for logging and informational purposes)
			 */
		}
		(void) thread_funnel_set(kernel_flock, fstate);

		session_lock(sessp);
		sessp->s_leader = NULL;
		session_unlock(sessp);
	}
	session_rele(sessp);

	pg = proc_pgrp(p);
	fixjobc(p, pg, 0);
	pg_rele(pg);

	p->p_rlimit[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;

	proc_list_lock();
	proc_childdrainstart(p);
	while ((q = p->p_children.lh_first) != NULL) {
		q->p_listflag |= P_LIST_DEADPARENT;
		if (q->p_stat == SZOMB) {
			if (p != q->p_pptr)
				panic("parent child linkage broken");
			/* check for lookups by zomb sysctl */
			while ((q->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
				msleep(&q->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
			}
			q->p_listflag |= P_LIST_WAITING;
			/*
			 * This is a named reference and it is not granted
			 * if the reap is already in progress. So we get
			 * the reference here exclusively and their can be
			 * no waiters. So there is no need for a wakeup
			 * after we are done. AlsO  the reap frees the structure
			 * and the proc struct cannot be used for wakeups as well. 
			 * It is safe to use q here as this is system reap
			 */
			(void)reap_child_locked(p, q, 1, 1, 0);
		} else {
			proc_reparentlocked(q, initproc, 0, 1);
			/*
		 	* Traced processes are killed
		 	* since their existence means someone is messing up.
		 	*/
			if (q->p_lflag & P_LTRACED) {
				proc_list_unlock();
				proc_lock(q);
				q->p_lflag &= ~P_LTRACED;
				if (q->sigwait_thread) {
					proc_unlock(q);
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
				} else
					proc_unlock(q);
					
				psignal(q, SIGKILL);
				proc_list_lock();
			}
		}
	}

	proc_childdrainend(p);
	proc_list_unlock();

	/*
	 * Release reference to text vnode
	 */
	tvp = p->p_textvp;
	p->p_textvp = NULL;
	if (tvp != NULLVP) {
		vnode_rele(tvp);
	}

	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.  If we were unable to allocate a zombie
	 * structure, this information is lost.
	 */
	/* No need for locking here as no one than this thread can access this */
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
	FREE_ZONE(p->p_stats, sizeof *p->p_stats, M_PSTATS);
	p->p_stats = NULL;

	FREE_ZONE(p->p_sigacts, sizeof *p->p_sigacts, M_SIGACTS);
	p->p_sigacts = NULL;

	proc_limitdrop(p, 1);
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
	pp = proc_parent(p);
	if ((p->p_listflag & P_LIST_DEADPARENT) == 0) {
		if (pp != initproc) {
			proc_lock(pp);
			pp->si_pid = p->p_pid;
			pp->si_status = p->p_xstat;
			pp->si_code = CLD_EXITED;
			/*
			 * p_ucred usage is safe as it is an exiting process
			 * and reference is dropped in reap
			 */
			pp->si_uid = p->p_ucred->cr_ruid;
			proc_unlock(pp);
		}
		/* mark as a zombie */
		/* mark as a zombie */
		/* No need to take proc lock as all refs are drained and
		 * no one except parent (reaping ) can look at this.
		 * The write is to an int and is coherent. Also parent is
		 *  keyed off of list lock for reaping
		 */
		p->p_stat = SZOMB;

		psignal(pp, SIGCHLD);

		/* and now wakeup the parent */
		proc_list_lock();
		wakeup((caddr_t)pp);
		proc_list_unlock();
	} else {
		proc_list_lock();
		p->p_stat = SZOMB;
		/* check for lookups by zomb sysctl */
		while ((p->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
			msleep(&p->p_stat, proc_list_mlock, PWAIT, "waitcoll", 0);
		}
		p->p_listflag |= P_LIST_WAITING;
		/*
		 * This is a named reference and it is not granted
		 * if the reap is already in progress. So we get
		 * the reference here exclusively and their can be
		 * no waiters. So there is no need for a wakeup
		 * after we are done. AlsO  the reap frees the structure
		 * and the proc struct cannot be used for wakeups as well. 
		 * It is safe to use p here as this is system reap
		 */
		(void)reap_child_locked(pp, p, 0, 1, 1);
		/* list lock dropped by reap_child_locked */
	}
	proc_rele(pp);
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
