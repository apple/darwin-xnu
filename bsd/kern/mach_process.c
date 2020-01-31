/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	from: @(#)sys_process.c	8.1 (Berkeley) 6/10/93
 */

#include <machine/reg.h>
#include <machine/psl.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <sys/mount_internal.h>
#include <sys/sysproto.h>
#include <sys/kdebug.h>
#include <sys/codesign.h>               /* cs_allow_invalid() */

#include <security/audit/audit.h>

#include <kern/task.h>
#include <kern/thread.h>

#include <mach/task.h>                  /* for task_resume() */
#include <kern/sched_prim.h>            /* for thread_exception_return() */

#include <pexpert/pexpert.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

/* XXX ken/bsd_kern.c - prototype should be in common header */
int get_task_userstop(task_t);

/* Macros to clear/set/test flags. */
#define SET(t, f)       (t) |= (f)
#define CLR(t, f)       (t) &= ~(f)
#define ISSET(t, f)     ((t) & (f))

extern thread_t port_name_to_thread(mach_port_name_t port_name);
extern thread_t get_firstthread(task_t);


/*
 * sys-trace system call.
 */

int
ptrace(struct proc *p, struct ptrace_args *uap, int32_t *retval)
{
	struct proc *t = current_proc();        /* target process */
	task_t          task;
	thread_t        th_act;
	struct uthread  *ut;
	int tr_sigexc = 0;
	int error = 0;
	int stopped = 0;

	AUDIT_ARG(cmd, uap->req);
	AUDIT_ARG(pid, uap->pid);
	AUDIT_ARG(addr, uap->addr);
	AUDIT_ARG(value32, uap->data);

	if (uap->req == PT_DENY_ATTACH) {
#if (DEVELOPMENT || DEBUG) && CONFIG_EMBEDDED
		if (PE_i_can_has_debugger(NULL)) {
			return 0;
		}
#endif
		proc_lock(p);
		if (ISSET(p->p_lflag, P_LTRACED)) {
			proc_unlock(p);
			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_FRCEXIT) | DBG_FUNC_NONE,
			    p->p_pid, W_EXITCODE(ENOTSUP, 0), 4, 0, 0);
			exit1(p, W_EXITCODE(ENOTSUP, 0), retval);

			thread_exception_return();
			/* NOTREACHED */
		}
		SET(p->p_lflag, P_LNOATTACH);
		proc_unlock(p);

		return 0;
	}

	if (uap->req == PT_FORCEQUOTA) {
		if (kauth_cred_issuser(kauth_cred_get())) {
			OSBitOrAtomic(P_FORCEQUOTA, &t->p_flag);
			return 0;
		} else {
			return EPERM;
		}
	}

	/*
	 *	Intercept and deal with "please trace me" request.
	 */
	if (uap->req == PT_TRACE_ME) {
retry_trace_me: ;
		proc_t pproc = proc_parent(p);
		if (pproc == NULL) {
			return EINVAL;
		}
#if CONFIG_MACF
		/*
		 * NB: Cannot call kauth_authorize_process(..., KAUTH_PROCESS_CANTRACE, ...)
		 *     since that assumes the process being checked is the current process
		 *     when, in this case, it is the current process's parent.
		 *     Most of the other checks in cantrace() don't apply either.
		 */
		if ((error = mac_proc_check_debug(pproc, p)) == 0) {
#endif
		proc_lock(p);
		/* Make sure the process wasn't re-parented. */
		if (p->p_ppid != pproc->p_pid) {
			proc_unlock(p);
			proc_rele(pproc);
			goto retry_trace_me;
		}
		SET(p->p_lflag, P_LTRACED);
		/* Non-attached case, our tracer is our parent. */
		p->p_oppid = p->p_ppid;
		proc_unlock(p);
		/* Child and parent will have to be able to run modified code. */
		cs_allow_invalid(p);
		cs_allow_invalid(pproc);
#if CONFIG_MACF
	}
#endif
		proc_rele(pproc);
		return error;
	}
	if (uap->req == PT_SIGEXC) {
		proc_lock(p);
		if (ISSET(p->p_lflag, P_LTRACED)) {
			SET(p->p_lflag, P_LSIGEXC);
			proc_unlock(p);
			return 0;
		} else {
			proc_unlock(p);
			return EINVAL;
		}
	}

	/*
	 * We do not want ptrace to do anything with kernel or launchd
	 */
	if (uap->pid < 2) {
		return EPERM;
	}

	/*
	 *	Locate victim, and make sure it is traceable.
	 */
	if ((t = proc_find(uap->pid)) == NULL) {
		return ESRCH;
	}

	AUDIT_ARG(process, t);

	task = t->task;
	if (uap->req == PT_ATTACHEXC) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		uap->req = PT_ATTACH;
		tr_sigexc = 1;
	}
	if (uap->req == PT_ATTACH) {
#pragma clang diagnostic pop
		int             err;

#if CONFIG_EMBEDDED
		if (tr_sigexc == 0) {
			error = ENOTSUP;
			goto out;
		}
#endif

		if (kauth_authorize_process(proc_ucred(p), KAUTH_PROCESS_CANTRACE,
		    t, (uintptr_t)&err, 0, 0) == 0) {
			/* it's OK to attach */
			proc_lock(t);
			SET(t->p_lflag, P_LTRACED);
			if (tr_sigexc) {
				SET(t->p_lflag, P_LSIGEXC);
			}

			t->p_oppid = t->p_ppid;
			/* Check whether child and parent are allowed to run modified
			 * code (they'll have to) */
			proc_unlock(t);
			cs_allow_invalid(t);
			cs_allow_invalid(p);
			if (t->p_pptr != p) {
				proc_reparentlocked(t, p, 1, 0);
			}

			proc_lock(t);
			if (get_task_userstop(task) > 0) {
				stopped = 1;
			}
			t->p_xstat = 0;
			proc_unlock(t);
			psignal(t, SIGSTOP);
			/*
			 * If the process was stopped, wake up and run through
			 * issignal() again to properly connect to the tracing
			 * process.
			 */
			if (stopped) {
				task_resume(task);
			}
			error = 0;
			goto out;
		} else {
			/* not allowed to attach, proper error code returned by kauth_authorize_process */
			if (ISSET(t->p_lflag, P_LNOATTACH)) {
				psignal(p, SIGSEGV);
			}

			error = err;
			goto out;
		}
	}

	/*
	 * You can't do what you want to the process if:
	 *	(1) It's not being traced at all,
	 */
	proc_lock(t);
	if (!ISSET(t->p_lflag, P_LTRACED)) {
		proc_unlock(t);
		error = EPERM;
		goto out;
	}

	/*
	 *	(2) it's not being traced by _you_, or
	 */
	if (t->p_pptr != p) {
		proc_unlock(t);
		error = EBUSY;
		goto out;
	}

	/*
	 *	(3) it's not currently stopped.
	 */
	if (t->p_stat != SSTOP) {
		proc_unlock(t);
		error = EBUSY;
		goto out;
	}

	/*
	 *	Mach version of ptrace executes request directly here,
	 *	thus simplifying the interaction of ptrace and signals.
	 */
	/* proc lock is held here */
	switch (uap->req) {
	case PT_DETACH:
		if (t->p_oppid != t->p_ppid) {
			struct proc *pp;

			proc_unlock(t);
			pp = proc_find(t->p_oppid);
			if (pp != PROC_NULL) {
				proc_reparentlocked(t, pp, 1, 0);
				proc_rele(pp);
			} else {
				/* original parent exited while traced */
				proc_list_lock();
				t->p_listflag |= P_LIST_DEADPARENT;
				proc_list_unlock();
				proc_reparentlocked(t, initproc, 1, 0);
			}
			proc_lock(t);
		}

		t->p_oppid = 0;
		CLR(t->p_lflag, P_LTRACED);
		CLR(t->p_lflag, P_LSIGEXC);
		proc_unlock(t);
		goto resume;

	case PT_KILL:
		/*
		 *	Tell child process to kill itself after it
		 *	is resumed by adding NSIG to p_cursig. [see issig]
		 */
		proc_unlock(t);
#if CONFIG_MACF
		error = mac_proc_check_signal(p, t, SIGKILL);
		if (0 != error) {
			goto resume;
		}
#endif
		psignal(t, SIGKILL);
		goto resume;

	case PT_STEP:                   /* single step the child */
	case PT_CONTINUE:               /* continue the child */
		proc_unlock(t);
		th_act = (thread_t)get_firstthread(task);
		if (th_act == THREAD_NULL) {
			error = EINVAL;
			goto out;
		}

		/* force use of Mach SPIs (and task_for_pid security checks) to adjust PC */
		if (uap->addr != (user_addr_t)1) {
			error = ENOTSUP;
			goto out;
		}

		if ((unsigned)uap->data >= NSIG) {
			error = EINVAL;
			goto out;
		}

		if (uap->data != 0) {
#if CONFIG_MACF
			error = mac_proc_check_signal(p, t, uap->data);
			if (0 != error) {
				goto out;
			}
#endif
			psignal(t, uap->data);
		}

		if (uap->req == PT_STEP) {
			/*
			 * set trace bit
			 * we use sending SIGSTOP as a comparable security check.
			 */
#if CONFIG_MACF
			error = mac_proc_check_signal(p, t, SIGSTOP);
			if (0 != error) {
				goto out;
			}
#endif
			if (thread_setsinglestep(th_act, 1) != KERN_SUCCESS) {
				error = ENOTSUP;
				goto out;
			}
		} else {
			/*
			 * clear trace bit if on
			 * we use sending SIGCONT as a comparable security check.
			 */
#if CONFIG_MACF
			error = mac_proc_check_signal(p, t, SIGCONT);
			if (0 != error) {
				goto out;
			}
#endif
			if (thread_setsinglestep(th_act, 0) != KERN_SUCCESS) {
				error = ENOTSUP;
				goto out;
			}
		}
resume:
		proc_lock(t);
		t->p_xstat = uap->data;
		t->p_stat = SRUN;
		if (t->sigwait) {
			wakeup((caddr_t)&(t->sigwait));
			proc_unlock(t);
			if ((t->p_lflag & P_LSIGEXC) == 0) {
				task_resume(task);
			}
		} else {
			proc_unlock(t);
		}

		break;

	case PT_THUPDATE:  {
		proc_unlock(t);
		if ((unsigned)uap->data >= NSIG) {
			error = EINVAL;
			goto out;
		}
		th_act = port_name_to_thread(CAST_MACH_PORT_TO_NAME(uap->addr));
		if (th_act == THREAD_NULL) {
			error = ESRCH;
			goto out;
		}
		ut = (uthread_t)get_bsdthread_info(th_act);
		if (uap->data) {
			ut->uu_siglist |= sigmask(uap->data);
		}
		proc_lock(t);
		t->p_xstat = uap->data;
		t->p_stat = SRUN;
		proc_unlock(t);
		thread_deallocate(th_act);
		error = 0;
	}
	break;
	default:
		proc_unlock(t);
		error = EINVAL;
		goto out;
	}

	error = 0;
out:
	proc_rele(t);
	return error;
}


/*
 * determine if one process (cur_procp) can trace another process (traced_procp).
 */

int
cantrace(proc_t cur_procp, kauth_cred_t creds, proc_t traced_procp, int *errp)
{
	int             my_err;
	/*
	 * You can't trace a process if:
	 *	(1) it's the process that's doing the tracing,
	 */
	if (traced_procp->p_pid == cur_procp->p_pid) {
		*errp = EINVAL;
		return 0;
	}

	/*
	 *	(2) it's already being traced, or
	 */
	if (ISSET(traced_procp->p_lflag, P_LTRACED)) {
		*errp = EBUSY;
		return 0;
	}

	/*
	 *	(3) it's not owned by you, or is set-id on exec
	 *	    (unless you're root).
	 */
	if ((kauth_cred_getruid(creds) != kauth_cred_getruid(proc_ucred(traced_procp)) ||
	    ISSET(traced_procp->p_flag, P_SUGID)) &&
	    (my_err = suser(creds, &cur_procp->p_acflag)) != 0) {
		*errp = my_err;
		return 0;
	}

	if ((cur_procp->p_lflag & P_LTRACED) && isinferior(cur_procp, traced_procp)) {
		*errp = EPERM;
		return 0;
	}

	if (ISSET(traced_procp->p_lflag, P_LNOATTACH)) {
		*errp = EBUSY;
		return 0;
	}

#if CONFIG_MACF
	if ((my_err = mac_proc_check_debug(cur_procp, traced_procp)) != 0) {
		*errp = my_err;
		return 0;
	}
#endif

	return 1;
}
