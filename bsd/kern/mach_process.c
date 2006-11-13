/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

#include <bsm/audit_kernel.h>

#include <kern/task.h>
#include <kern/thread.h>
#include <mach/machine/thread_status.h>


/* Macros to clear/set/test flags. */
#define	SET(t, f)	(t) |= (f)
#define	CLR(t, f)	(t) &= ~(f)
#define	ISSET(t, f)	((t) & (f))

extern thread_t	port_name_to_thread(mach_port_name_t port_name);
extern kern_return_t thread_getstatus(thread_t thread, int flavor, thread_state_t tstate, mach_msg_type_number_t *count);
extern thread_t get_firstthread(task_t);

#if defined (ppc)
extern kern_return_t thread_setstatus(thread_t thread, int flavor, thread_state_t tstate, mach_msg_type_number_t count);
#endif

/*
 * sys-trace system call.
 */

int
ptrace(p, uap, retval)
	struct proc *p;
	struct ptrace_args *uap;
	register_t *retval;
{
	struct proc *t = current_proc();	/* target process */
	task_t		task;
	thread_t	th_act;
	struct uthread 	*ut;
	int		*locr0;
#if defined(ppc)
	struct ppc_thread_state64 statep;
#elif	defined(i386)
	struct i386_saved_state statep;
#else
#error architecture not supported
#endif
	unsigned long state_count;
	int tr_sigexc = 0;

	AUDIT_ARG(cmd, uap->req);
	AUDIT_ARG(pid, uap->pid);
	AUDIT_ARG(addr, uap->addr);
	AUDIT_ARG(value, uap->data);

	if (uap->req == PT_DENY_ATTACH) {
		if (ISSET(p->p_flag, P_TRACED)) {
			exit1(p, W_EXITCODE(ENOTSUP, 0), retval);
			/* drop funnel before we return */
			thread_funnel_set(kernel_flock, FALSE);
			thread_exception_return();
			/* NOTREACHED */
		}
		SET(p->p_flag, P_NOATTACH);

		return(0);
	}

	if (uap->req == PT_FORCEQUOTA) {
		if (is_suser()) {
			SET(t->p_flag, P_FORCEQUOTA);
			return (0);
		} else
			return (EPERM);
	}

	/*
	 *	Intercept and deal with "please trace me" request.
	 */	 
	if (uap->req == PT_TRACE_ME) {
		SET(p->p_flag, P_TRACED);
		/* Non-attached case, our tracer is our parent. */
		t->p_oppid = t->p_pptr->p_pid;
		return(0);
	}
	if (uap->req == PT_SIGEXC) {
		if (ISSET(p->p_flag, P_TRACED)) {
			SET(p->p_flag, P_SIGEXC);
			return(0);
		} else
			return(EINVAL);
	}

	/*
	 *	Locate victim, and make sure it is traceable.
	 */
	if ((t = pfind(uap->pid)) == NULL)
			return (ESRCH);

	AUDIT_ARG(process, t);

	/* We do not want ptrace to do anything with kernel, init 
	 * and mach_init
	 */
	if (uap->pid <=2 )
		return (EPERM);

	task = t->task;
	if (uap->req == PT_ATTACHEXC) {
		uap->req = PT_ATTACH;
		tr_sigexc = 1;
	}
	if (uap->req == PT_ATTACH) {
		int		err;
		
		if ( kauth_authorize_process(proc_ucred(p), KAUTH_PROCESS_CANTRACE, 
									 t, (uintptr_t)&err, 0, 0) == 0 ) {
			/* it's OK to attach */
			SET(t->p_flag, P_TRACED);
			if (tr_sigexc) 
				SET(t->p_flag, P_SIGEXC);
	
			t->p_oppid = t->p_pptr->p_pid;
			if (t->p_pptr != p)
				proc_reparent(t, p);
	
			if (get_task_userstop(task) == 0 ) {
				t->p_xstat = 0;
				psignal(t, SIGSTOP);
			} else {
				t->p_xstat = SIGSTOP; 
				task_resume(task);       
			}
			return(0);
		}
		else {
			/* not allowed to attach, proper error code returned by kauth_authorize_process */
			if (ISSET(t->p_flag, P_NOATTACH)) {
				psignal(p, SIGSEGV);
			}
			return (err);
		}
	}

	/*
	 * You can't do what you want to the process if:
	 *	(1) It's not being traced at all,
	 */
	if (!ISSET(t->p_flag, P_TRACED))
		return (EPERM);

	/*
	 *	(2) it's not being traced by _you_, or
	 */
	if (t->p_pptr != p)
		return (EBUSY);

	/*
	 *	(3) it's not currently stopped.
	 */
	if (t->p_stat != SSTOP)
		return (EBUSY);

	/*
	 *	Mach version of ptrace executes request directly here,
	 *	thus simplifying the interaction of ptrace and signals.
	 */
	switch (uap->req) {

	case PT_DETACH:
		if (t->p_oppid != t->p_pptr->p_pid) {
			struct proc *pp;

			pp = pfind(t->p_oppid);
			proc_reparent(t, pp ? pp : initproc);
		}

		t->p_oppid = 0;
		CLR(t->p_flag, P_TRACED);
		CLR(t->p_flag, P_SIGEXC);
		goto resume;
		
	case PT_KILL:
		/*
		 *	Tell child process to kill itself after it
		 *	is resumed by adding NSIG to p_cursig. [see issig]
		 */
		psignal_lock(t, SIGKILL, 0);
		goto resume;

	case PT_STEP:			/* single step the child */
	case PT_CONTINUE:		/* continue the child */
		th_act = (thread_t)get_firstthread(task);
		if (th_act == THREAD_NULL)
			goto errorLabel;
		ut = (uthread_t)get_bsdthread_info(th_act);
		locr0 = ut->uu_ar0;
#if defined(i386)
		state_count = i386_NEW_THREAD_STATE_COUNT;
		if (thread_getstatus(th_act, i386_NEW_THREAD_STATE, &statep, &state_count)  != KERN_SUCCESS) {
			goto errorLabel;
		}	
#elif defined(ppc)
		state_count = PPC_THREAD_STATE64_COUNT;
		if (thread_getstatus(th_act, PPC_THREAD_STATE64, (thread_state_t)&statep, (mach_msg_type_number_t *)&state_count)  != KERN_SUCCESS) {
			goto errorLabel;
		}	
#else
#error architecture not supported
#endif
		if (uap->addr != (user_addr_t)1) {
#if	defined(i386)
			locr0[PC] = (int)uap->addr;
#elif	defined(ppc)
#define ALIGNED(addr,size)	(((unsigned)(addr)&((size)-1))==0)
		if (!ALIGNED((int)uap->addr, sizeof(int)))
			return (ERESTART);

		statep.srr0 = uap->addr;
		state_count = PPC_THREAD_STATE64_COUNT;
		if (thread_setstatus(th_act, PPC_THREAD_STATE64, (thread_state_t)&statep, state_count)  != KERN_SUCCESS) {
			goto errorLabel;
		}	
#undef 	ALIGNED
#else
#error architecture not implemented!
#endif
		} /* uap->addr != (user_addr_t)1 */

		if ((unsigned)uap->data >= NSIG)
			goto errorLabel;

		if (uap->data != 0) {
			psignal_lock(t, uap->data, 0);
                }
#if defined(ppc)
		state_count = PPC_THREAD_STATE64_COUNT;
		if (thread_getstatus(th_act, PPC_THREAD_STATE64, (thread_state_t)&statep, (mach_msg_type_number_t *)&state_count)  != KERN_SUCCESS) {
			goto errorLabel;
		}	
#endif

#define MSR_SE_BIT	21

		if (uap->req == PT_STEP) {
#if	defined(i386)
			locr0[PS] |= PSL_T;
#elif 	defined(ppc)
			statep.srr1 |= MASK(MSR_SE);
#else
#error architecture not implemented!
#endif
		} /* uap->req == PT_STEP */
		else {  /* PT_CONTINUE - clear trace bit if set */
#if defined(i386)
			locr0[PS] &= ~PSL_T;
#elif defined(ppc)
			statep.srr1 &= ~MASK(MSR_SE);
#endif
		}
#if defined (ppc)
		state_count = PPC_THREAD_STATE64_COUNT;
		if (thread_setstatus(th_act, PPC_THREAD_STATE64, (thread_state_t)&statep, state_count)  != KERN_SUCCESS) {
			goto errorLabel;
		}	
#endif
	resume:
		t->p_xstat = uap->data;
		t->p_stat = SRUN;
		if (t->sigwait) {
			wakeup((caddr_t)&(t->sigwait));
			if ((t->p_flag & P_SIGEXC) == 0)
				task_release(task);
		}
		break;
		
	case PT_THUPDATE:  {
		if ((unsigned)uap->data >= NSIG)
			goto errorLabel;
		th_act = port_name_to_thread(CAST_DOWN(mach_port_name_t, uap->addr));
		if (th_act == THREAD_NULL)
			return (ESRCH);
		ut = (uthread_t)get_bsdthread_info(th_act);
		if (uap->data)
			ut->uu_siglist |= sigmask(uap->data);
		t->p_xstat = uap->data;
		t->p_stat = SRUN;
		thread_deallocate(th_act);
		return(0);
		}
		break;
errorLabel:
	default:
		return(EINVAL);
	}

	return(0);
}


/*
 * determine if one process (cur_procp) can trace another process (traced_procp).
 */

int
cantrace(proc_t cur_procp, kauth_cred_t creds, proc_t traced_procp, int *errp)
{
	int		my_err;
	/*
	 * You can't trace a process if:
	 *	(1) it's the process that's doing the tracing,
	 */
	if (traced_procp->p_pid == cur_procp->p_pid) {
		*errp = EINVAL;
		return (0);
	}

	/*
	 *	(2) it's already being traced, or
	 */
	if (ISSET(traced_procp->p_flag, P_TRACED)) {
		*errp = EBUSY;
		return (0);
	}

	/*
	 *	(3) it's not owned by you, or is set-id on exec
	 *	    (unless you're root).
	 */
	if ((creds->cr_ruid != proc_ucred(traced_procp)->cr_ruid ||
		ISSET(traced_procp->p_flag, P_SUGID)) &&
		(my_err = suser(creds, &cur_procp->p_acflag)) != 0) {
		*errp = my_err;
		return (0);
	}

	if ((cur_procp->p_flag & P_TRACED) && isinferior(cur_procp, traced_procp)) {
		*errp = EPERM;
		return (0);
	}

	if (ISSET(traced_procp->p_flag, P_NOATTACH)) {
		*errp = EBUSY;
		return (0);
	}
	return(1);
}
