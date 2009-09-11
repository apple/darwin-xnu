/*
 * Copyright (c) 1995-2007 Apple Inc. All rights reserved.
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
 *	@(#)kern_sig.c	8.7 (Berkeley) 4/18/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#define	SIGPROP		/* include signal properties table */
#include <sys/param.h>
#include <sys/resourcevar.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/acct.h>
#include <sys/file_internal.h>
#include <sys/kernel.h>
#include <sys/wait.h>
#include <sys/signalvar.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <sys/lock.h>
#include <sys/kdebug.h>

#include <sys/mount.h>
#include <sys/sysproto.h>

#include <security/audit/audit.h>

#include <machine/spl.h>

#include <kern/cpu_number.h>

#include <sys/vm.h>
#include <sys/user.h>		/* for coredump */
#include <kern/ast.h>		/* for APC support */
#include <kern/lock.h>
#include <kern/task.h>		/* extern void   *get_bsdtask_info(task_t); */
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/thread_call.h>
#include <mach/exception.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <libkern/OSAtomic.h>

#include <sys/sdt.h>

/*
 * Missing prototypes that Mach should export
 *
 * +++
 */
extern int thread_enable_fpe(thread_t act, int onoff);
extern thread_t	port_name_to_thread(mach_port_name_t port_name);
extern kern_return_t get_signalact(task_t , thread_t *, int);
extern boolean_t thread_should_abort(thread_t);
extern unsigned int get_useraddr(void);

/*
 * ---
 */

extern void doexception(int exc, mach_exception_code_t code, 
		mach_exception_subcode_t sub);

static void stop(proc_t, proc_t);
int cansignal(proc_t, kauth_cred_t, proc_t, int, int);
int killpg1(proc_t, int, int, int, int);
int setsigvec(proc_t, thread_t, int, struct __kern_sigaction *, boolean_t in_sigstart);
static void psignal_uthread(thread_t, int);
kern_return_t do_bsdexception(int, int, int);
void __posix_sem_syscall_return(kern_return_t);

/* implementations in osfmk/kern/sync_sema.c. We do not want port.h in this scope, so void * them  */
kern_return_t semaphore_timedwait_signal_trap_internal(mach_port_name_t, mach_port_name_t, unsigned int, clock_res_t, void (*)(kern_return_t));
kern_return_t semaphore_timedwait_trap_internal(mach_port_name_t, unsigned int, clock_res_t, void (*)(kern_return_t));
kern_return_t semaphore_wait_signal_trap_internal(mach_port_name_t, mach_port_name_t, void (*)(kern_return_t));
kern_return_t semaphore_wait_trap_internal(mach_port_name_t, void (*)(kern_return_t));

static int	filt_sigattach(struct knote *kn);
static void	filt_sigdetach(struct knote *kn);
static int	filt_signal(struct knote *kn, long hint);
static void	filt_signaltouch(struct knote *kn, struct kevent64_s *kev, 
		long type);

struct filterops sig_filtops = {
        .f_attach = filt_sigattach,
        .f_detach = filt_sigdetach,
        .f_event = filt_signal,
        .f_touch = filt_signaltouch,
};

/* structures  and fns for killpg1 iterartion callback and filters */
struct killpg1_filtargs {
	int  posix;
	proc_t cp;
};

struct killpg1_iterargs {
	proc_t cp;
	kauth_cred_t uc;
	int signum;
	int * nfoundp;
	int zombie;
};

static int killpg1_filt(proc_t p, void * arg);
static int killpg1_pgrpfilt(proc_t p, __unused void * arg);
static int killpg1_callback(proc_t p, void * arg);

static int pgsignal_filt(proc_t p, void * arg);
static int pgsignal_callback(proc_t p, void * arg);
static kern_return_t get_signalthread(proc_t, int, thread_t *);


/* flags for psignal_internal */
#define PSIG_LOCKED     0x1
#define PSIG_VFORK      0x2
#define PSIG_THREAD     0x4


static void psignal_internal(proc_t p, task_t task, thread_t thread, int flavor, int signum);

/*
 * NOTE: Source and target may *NOT* overlap! (target is smaller)
 */
static void
sigaltstack_kern_to_user32(struct kern_sigaltstack *in, struct user32_sigaltstack *out)
{
	out->ss_sp	    = CAST_DOWN_EXPLICIT(user32_addr_t, in->ss_sp);
	out->ss_size	= CAST_DOWN_EXPLICIT(user32_size_t, in->ss_size);
	out->ss_flags	= in->ss_flags;
}

static void
sigaltstack_kern_to_user64(struct kern_sigaltstack *in, struct user64_sigaltstack *out)
{
	out->ss_sp	    = in->ss_sp;
	out->ss_size	= in->ss_size;
	out->ss_flags	= in->ss_flags;
}

/*
 * NOTE: Source and target may are permitted to overlap! (source is smaller);
 * this works because we copy fields in order from the end of the struct to
 * the beginning.
 */
static void
sigaltstack_user32_to_kern(struct user32_sigaltstack *in, struct kern_sigaltstack *out)
{
	out->ss_flags	= in->ss_flags;
	out->ss_size	= in->ss_size;
	out->ss_sp		= CAST_USER_ADDR_T(in->ss_sp);
}
static void
sigaltstack_user64_to_kern(struct user64_sigaltstack *in, struct kern_sigaltstack *out)
{
	out->ss_flags	= in->ss_flags;
	out->ss_size	= in->ss_size;
	out->ss_sp		= in->ss_sp;
}

static void
sigaction_kern_to_user32(struct kern_sigaction *in, struct user32_sigaction *out)
{
	/* This assumes 32 bit __sa_handler is of type sig_t */
	out->__sigaction_u.__sa_handler = CAST_DOWN_EXPLICIT(user32_addr_t,in->__sigaction_u.__sa_handler);
	out->sa_mask = in->sa_mask;
	out->sa_flags = in->sa_flags;
}
static void
sigaction_kern_to_user64(struct kern_sigaction *in, struct user64_sigaction *out)
{
	/* This assumes 32 bit __sa_handler is of type sig_t */
	out->__sigaction_u.__sa_handler = in->__sigaction_u.__sa_handler;
	out->sa_mask = in->sa_mask;
	out->sa_flags = in->sa_flags;
}

static void
__sigaction_user32_to_kern(struct __user32_sigaction *in, struct __kern_sigaction *out)
{
	out->__sigaction_u.__sa_handler = CAST_USER_ADDR_T(in->__sigaction_u.__sa_handler);
	out->sa_tramp = CAST_USER_ADDR_T(in->sa_tramp);
	out->sa_mask = in->sa_mask;
	out->sa_flags = in->sa_flags;
}

static void
__sigaction_user64_to_kern(struct __user64_sigaction *in, struct __kern_sigaction *out)
{
	out->__sigaction_u.__sa_handler = in->__sigaction_u.__sa_handler;
	out->sa_tramp = in->sa_tramp;
	out->sa_mask = in->sa_mask;
	out->sa_flags = in->sa_flags;
}

#if SIGNAL_DEBUG
void ram_printf(int);
int ram_debug=0;
unsigned int rdebug_proc=0;
void
ram_printf(int x)
{
    printf("x is %d",x);

}
#endif /* SIGNAL_DEBUG */


void
signal_setast(thread_t sig_actthread)
{
	act_set_astbsd(sig_actthread);
}

/*
 * Can process p, with ucred uc, send the signal signum to process q?
 * uc is refcounted  by the caller so internal fileds can be used safely
 * when called with zombie arg, list lock is held
 */
int
cansignal(proc_t p, kauth_cred_t uc, proc_t q, int signum, int zombie)
{
	kauth_cred_t my_cred;
	struct session * p_sessp = SESSION_NULL;
	struct session * q_sessp = SESSION_NULL;
#if CONFIG_MACF
	int error;

	error = mac_proc_check_signal(p, q, signum);
	if (error)
		return (0);
#endif

	/* you can signal yourself */
	if (p == q)
		return(1);

	if (!suser(uc, NULL))
		return (1);		/* root can always signal */

	if (zombie == 0)
		proc_list_lock();
	if (p->p_pgrp != PGRP_NULL)
		p_sessp = p->p_pgrp->pg_session;
	if (q->p_pgrp != PGRP_NULL)
		q_sessp = q->p_pgrp->pg_session;

	if (signum == SIGCONT && q_sessp == p_sessp) {
		if (zombie == 0)
			proc_list_unlock();
		return (1);		/* SIGCONT in session */
	}

	if (zombie == 0) 
		proc_list_unlock();

	/*
	 * If the real or effective UID of the sender matches the real
	 * or saved UID of the target, permit the signal to
	 * be sent.
	 */
	if (zombie == 0)
		my_cred = kauth_cred_proc_ref(q);
	else
		my_cred = proc_ucred(q);

	if (uc->cr_ruid == my_cred->cr_ruid ||
	    uc->cr_ruid == my_cred->cr_svuid ||
	    kauth_cred_getuid(uc) == my_cred->cr_ruid ||
	    kauth_cred_getuid(uc) == my_cred->cr_svuid) {
		if (zombie == 0)
			kauth_cred_unref(&my_cred);
		return (1);
	}

	if (zombie == 0)
		kauth_cred_unref(&my_cred);

	return (0);
}


/*
 * Returns:	0			Success
 *		EINVAL
 *	copyout:EFAULT
 *	copyin:EFAULT
 *
 * Notes:	Uses current thread as a parameter to inform PPC to enable
 *		FPU exceptions via setsigvec(); this operation is not proxy
 *		safe!
 */
/* ARGSUSED */
int
sigaction(proc_t p, struct sigaction_args *uap, __unused int32_t *retval)
{
	struct kern_sigaction vec;
	struct __kern_sigaction __vec;

	struct kern_sigaction *sa = &vec;
	struct sigacts *ps = p->p_sigacts;

	int signum;
	int bit, error=0;

	signum = uap->signum;
	if (signum <= 0 || signum >= NSIG ||
	    signum == SIGKILL || signum == SIGSTOP)
		return (EINVAL);

	if (uap->osa) {
		sa->sa_handler = ps->ps_sigact[signum];
		sa->sa_mask = ps->ps_catchmask[signum];
		bit = sigmask(signum);
		sa->sa_flags = 0;
		if ((ps->ps_sigonstack & bit) != 0)
			sa->sa_flags |= SA_ONSTACK;
		if ((ps->ps_sigintr & bit) == 0)
			sa->sa_flags |= SA_RESTART;
		if (ps->ps_siginfo & bit)
			sa->sa_flags |= SA_SIGINFO;
		if (ps->ps_signodefer & bit)
			sa->sa_flags |= SA_NODEFER;
		if (ps->ps_64regset & bit)
			sa->sa_flags |= SA_64REGSET;
		if ((signum == SIGCHLD) && (p->p_flag & P_NOCLDSTOP))
			sa->sa_flags |= SA_NOCLDSTOP;
		if ((signum == SIGCHLD) && (p->p_flag & P_NOCLDWAIT))
			sa->sa_flags |= SA_NOCLDWAIT;

		if (IS_64BIT_PROCESS(p)) {
			struct user64_sigaction	vec64;
			
			sigaction_kern_to_user64(sa, &vec64);
			error = copyout(&vec64, uap->osa, sizeof(vec64));
		} else {
			struct user32_sigaction	vec32;
			
			sigaction_kern_to_user32(sa, &vec32);
			error = copyout(&vec32, uap->osa, sizeof(vec32));
		}
		if (error)
			return (error);
	}
	if (uap->nsa) {
		if (IS_64BIT_PROCESS(p)) {
			struct __user64_sigaction	__vec64;
			
			error = copyin(uap->nsa, &__vec64, sizeof(__vec64));
			__sigaction_user64_to_kern(&__vec64, &__vec);
		} else {
			struct __user32_sigaction	__vec32;
			
			error = copyin(uap->nsa, &__vec32, sizeof(__vec32));
			__sigaction_user32_to_kern(&__vec32, &__vec);
		}
		if (error)
			return (error);
		__vec.sa_flags &= SA_USERSPACE_MASK; /* Only pass on valid sa_flags */
		error = setsigvec(p, current_thread(), signum, &__vec, FALSE);
	}
	return (error);
}

/* Routines to manipulate bits on all threads */
int
clear_procsiglist(proc_t p,  int bit, boolean_t in_signalstart)
{
	struct uthread * uth;
	thread_t thact;

	proc_lock(p);
	if (!in_signalstart)
		proc_signalstart(p, 1);

	if ((p->p_lflag & P_LINVFORK) && p->p_vforkact) {
		thact = p->p_vforkact;	
		uth = (struct uthread *)get_bsdthread_info(thact);
		if (uth) {
			uth->uu_siglist &= ~bit;
		}
		if (!in_signalstart)
			proc_signalend(p, 1);
		proc_unlock(p);
		return(0);
	} 

	TAILQ_FOREACH(uth, &p->p_uthlist, uu_list) {
		uth->uu_siglist &= ~bit;
	}
	p->p_siglist &= ~bit;
	if (!in_signalstart)
		proc_signalend(p, 1);
	proc_unlock(p);

	return(0);
}


static int
unblock_procsigmask(proc_t p,  int bit)
{
	struct uthread * uth;
	thread_t thact;

	proc_lock(p);
	proc_signalstart(p, 1);

	if ((p->p_lflag & P_LINVFORK) && p->p_vforkact) {
		thact = p->p_vforkact;	
		uth = (struct uthread *)get_bsdthread_info(thact);
		if (uth) {
			uth->uu_sigmask &= ~bit;
		}
		p->p_sigmask &= ~bit;
		proc_signalend(p, 1);
		proc_unlock(p);
		return(0);
	} 
	TAILQ_FOREACH(uth, &p->p_uthlist, uu_list) {
		uth->uu_sigmask &= ~bit;
	}
	p->p_sigmask &= ~bit;

	proc_signalend(p, 1);
	proc_unlock(p);
	return(0);
}

static int
block_procsigmask(proc_t p,  int bit)
{
	struct uthread * uth;
	thread_t thact;

	proc_lock(p);
	proc_signalstart(p, 1);

	if ((p->p_lflag & P_LINVFORK) && p->p_vforkact) {
		thact = p->p_vforkact;	
		uth = (struct uthread *)get_bsdthread_info(thact);
		if (uth) {
			uth->uu_sigmask |= bit;
		}
		p->p_sigmask |=  bit;
		proc_signalend(p, 1);
		proc_unlock(p);
		return(0);
	} 
	TAILQ_FOREACH(uth, &p->p_uthlist, uu_list) {
		uth->uu_sigmask |= bit;
	}
	p->p_sigmask |=  bit;

	proc_signalend(p, 1);
	proc_unlock(p);
	return(0);
}

int
set_procsigmask(proc_t p,  int bit)
{
	struct uthread * uth;
	thread_t thact;

	proc_lock(p);
	proc_signalstart(p, 1);

	if ((p->p_lflag & P_LINVFORK) && p->p_vforkact) {
		thact = p->p_vforkact;	
		uth = (struct uthread *)get_bsdthread_info(thact);
		if (uth) {
			uth->uu_sigmask = bit;
		}
		p->p_sigmask =  bit;
		proc_signalend(p, 1);
		proc_unlock(p);
		return(0);
	} 
	TAILQ_FOREACH(uth, &p->p_uthlist, uu_list) {
		uth->uu_sigmask = bit;
	}
	p->p_sigmask =  bit;
	proc_signalend(p, 1);
	proc_unlock(p);

	return(0);
}

/* XXX should be static? */
/*
 * Notes:	The thread parameter is used in the PPC case to select the
 *		thread on which the floating point exception will be enabled
 *		or disabled.  We can't simply take current_thread(), since
 *		this is called from posix_spawn() on the not currently running
 *		process/thread pair.
 *
 *		We mark thread as unused to alow compilation without warning
 *		onnon-PPC platforms.
 */
int
setsigvec(proc_t p, __unused thread_t thread, int signum, struct __kern_sigaction *sa, boolean_t in_sigstart)
{
	struct sigacts *ps = p->p_sigacts;
	int bit;

	if ((signum == SIGKILL || signum == SIGSTOP) &&
		sa->sa_handler != SIG_DFL)
		return(EINVAL);
	bit = sigmask(signum);
	/*
	 * Change setting atomically.
	 */
	ps->ps_sigact[signum] = sa->sa_handler;
	ps->ps_trampact[signum] = sa->sa_tramp;
	ps->ps_catchmask[signum] = sa->sa_mask &~ sigcantmask;
	if (sa->sa_flags & SA_SIGINFO)
		ps->ps_siginfo |= bit;
	else
		ps->ps_siginfo &= ~bit;
	if (sa->sa_flags & SA_64REGSET)
		ps->ps_64regset |= bit;
	else
		ps->ps_64regset &= ~bit;
	if ((sa->sa_flags & SA_RESTART) == 0)
		ps->ps_sigintr |= bit;
	else
		ps->ps_sigintr &= ~bit;
	if (sa->sa_flags & SA_ONSTACK)
		ps->ps_sigonstack |= bit;
	else
		ps->ps_sigonstack &= ~bit;
	if (sa->sa_flags & SA_USERTRAMP)
		ps->ps_usertramp |= bit;
	else
		ps->ps_usertramp &= ~bit;
	if (sa->sa_flags & SA_RESETHAND)
		ps->ps_sigreset |= bit;
	else
		ps->ps_sigreset &= ~bit;
	if (sa->sa_flags & SA_NODEFER)
		ps->ps_signodefer |= bit;
	else
		ps->ps_signodefer &= ~bit;
	if (signum == SIGCHLD) {
		if (sa->sa_flags & SA_NOCLDSTOP)
			OSBitOrAtomic(P_NOCLDSTOP, &p->p_flag);
		else
			OSBitAndAtomic(~((uint32_t)P_NOCLDSTOP), &p->p_flag);
		if ((sa->sa_flags & SA_NOCLDWAIT) || (sa->sa_handler == SIG_IGN))
			OSBitOrAtomic(P_NOCLDWAIT, &p->p_flag);
		else
			OSBitAndAtomic(~((uint32_t)P_NOCLDWAIT), &p->p_flag);
	}

#ifdef __ppc__ 
	if (signum == SIGFPE) {
		if (sa->sa_handler == SIG_DFL || sa->sa_handler == SIG_IGN) 
			thread_enable_fpe(thread, 0);
		else
			thread_enable_fpe(thread, 1);
	}
#endif  /* __ppc__ */
	/*
	 * Set bit in p_sigignore for signals that are set to SIG_IGN,
	 * and for signals set to SIG_DFL where the default is to ignore.
	 * However, don't put SIGCONT in p_sigignore,
	 * as we have to restart the process.
	 */
	if (sa->sa_handler == SIG_IGN ||
	    (sigprop[signum] & SA_IGNORE && sa->sa_handler == SIG_DFL)) {

		clear_procsiglist(p, bit, in_sigstart);
		if (signum != SIGCONT)
			p->p_sigignore |= bit;	/* easier in psignal */
		p->p_sigcatch &= ~bit;
	} else {
		p->p_sigignore &= ~bit;
		if (sa->sa_handler == SIG_DFL)
			p->p_sigcatch &= ~bit;
		else
			p->p_sigcatch |= bit;
	}
	return(0);
}

/*
 * Initialize signal state for process 0;
 * set to ignore signals that are ignored by default.
 */
void
siginit(proc_t p)
{
	int i;

	for (i = 0; i < NSIG; i++)
		if (sigprop[i] & SA_IGNORE && i != SIGCONT)
			p->p_sigignore |= sigmask(i);
}

/*
 * Reset signals for an exec of the specified process.
 */
void
execsigs(proc_t p, thread_t thread)
{
	struct sigacts *ps = p->p_sigacts;
	int nc, mask;
	struct uthread *ut;

	ut = (struct uthread *)get_bsdthread_info(thread);

	/*
	 * transfer saved signal states from the process
	 * back to the current thread.
	 *
	 * NOTE: We do this without the process locked,
	 * because we are guaranteed to be single-threaded
	 * by this point in exec and the p_siglist is
	 * only accessed by threads inside the process.
	 */
	ut->uu_siglist |= p->p_siglist;
	p->p_siglist = 0;

	/*
	 * Reset caught signals.  Held signals remain held
	 * through p_sigmask (unless they were caught,
	 * and are now ignored by default).
	 */
	while (p->p_sigcatch) {
		nc = ffs((long)p->p_sigcatch);
		mask = sigmask(nc);
		p->p_sigcatch &= ~mask;
		if (sigprop[nc] & SA_IGNORE) {
			if (nc != SIGCONT)
				p->p_sigignore |= mask;
			ut->uu_siglist &= ~mask;
		}
		ps->ps_sigact[nc] = SIG_DFL;
	}

	/*
	 * Reset stack state to the user stack.
	 * Clear set of signals caught on the signal stack.
	 */
	/* thread */
	ut->uu_sigstk.ss_flags = SA_DISABLE;
	ut->uu_sigstk.ss_size = 0;
	ut->uu_sigstk.ss_sp = USER_ADDR_NULL;
	ut->uu_flag &= ~UT_ALTSTACK;
	/* process */
	ps->ps_sigonstack = 0;
}

/*
 * Manipulate signal mask.
 * Note that we receive new mask, not pointer,
 * and return old mask as return value;
 * the library stub does the rest.
 */
int
sigprocmask(proc_t p, struct sigprocmask_args *uap, __unused int32_t *retval)
{
	int error = 0;
	sigset_t oldmask, nmask;
	user_addr_t omask = uap->omask;
	struct uthread *ut;

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	oldmask  = ut->uu_sigmask;

	if (uap->mask == USER_ADDR_NULL) {
		/* just want old mask */
		goto out;
	}
	error = copyin(uap->mask, &nmask, sizeof(sigset_t));
	if (error)
		goto out;

	switch (uap->how) {
	case SIG_BLOCK:
		block_procsigmask(p, (nmask & ~sigcantmask));
		signal_setast(current_thread());
		break;

	case SIG_UNBLOCK:
		unblock_procsigmask(p, (nmask & ~sigcantmask));
		signal_setast(current_thread());
		break;

	case SIG_SETMASK:
		set_procsigmask(p, (nmask & ~sigcantmask));
		signal_setast(current_thread());
		break;
	
	default:
		error = EINVAL;
		break;
	}
out:
	if (!error && omask != USER_ADDR_NULL)
		copyout(&oldmask, omask, sizeof(sigset_t));
	return (error);
}

int
sigpending(__unused proc_t p, struct sigpending_args *uap, __unused int32_t *retval)
{
	struct uthread *ut;
	sigset_t pendlist;

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	pendlist = ut->uu_siglist;

	if (uap->osv)
		copyout(&pendlist, uap->osv, sizeof(sigset_t));
	return(0);
}

/*
 * Suspend process until signal, providing mask to be set
 * in the meantime.  Note nonstandard calling convention:
 * libc stub passes mask, not pointer, to save a copyin.
 */

static int
sigcontinue(__unused int error)
{
//	struct uthread *ut = get_bsdthread_info(current_thread());
	unix_syscall_return(EINTR);
}

int
sigsuspend(proc_t p, struct sigsuspend_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(sigsuspend_nocancel(p, (struct sigsuspend_nocancel_args *)uap, retval));
}

int
sigsuspend_nocancel(proc_t p, struct sigsuspend_nocancel_args *uap, __unused int32_t *retval)
{
	struct uthread *ut;

	ut = (struct uthread *)get_bsdthread_info(current_thread());

	/*
	 * When returning from sigpause, we want
	 * the old mask to be restored after the
	 * signal handler has finished.  Thus, we
	 * save it here and mark the sigacts structure
	 * to indicate this.
	 */
	ut->uu_oldmask = ut->uu_sigmask;
	ut->uu_flag |= UT_SAS_OLDMASK;
	ut->uu_sigmask = (uap->mask & ~sigcantmask);
	(void) tsleep0((caddr_t) p, PPAUSE|PCATCH, "pause", 0, sigcontinue);
	/* always return EINTR rather than ERESTART... */
	return (EINTR);
}


int
__disable_threadsignal(__unused proc_t p,
		       __unused struct __disable_threadsignal_args *uap,
		       __unused int32_t *retval)
{
	struct uthread *uth;

	uth = (struct uthread *)get_bsdthread_info(current_thread());

	/* No longer valid to have any signal delivered */
	uth->uu_flag |= (UT_NO_SIGMASK | UT_CANCELDISABLE);

	return(0);

}

void
__pthread_testcancel(int presyscall)
{

	thread_t self = current_thread();
	struct uthread * uthread;

	uthread = (struct uthread *)get_bsdthread_info(self);

	
	uthread->uu_flag &= ~UT_NOTCANCELPT;

	if ((uthread->uu_flag & (UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL) {
		if(presyscall != 0) {
			unix_syscall_return(EINTR);
			/* NOTREACHED */
		} else 
			thread_abort_safely(self);
	}
}



int
__pthread_markcancel(__unused proc_t p,
	struct __pthread_markcancel_args *uap, __unused int32_t *retval)
{
	thread_act_t target_act;
	int error = 0;
	struct uthread *uth;

	target_act = (thread_act_t)port_name_to_thread(uap->thread_port);

	if (target_act == THR_ACT_NULL)
		return (ESRCH);

	uth = (struct uthread *)get_bsdthread_info(target_act);

	/* if the thread is in vfork do not cancel */
	if ((uth->uu_flag & (UT_VFORK | UT_CANCEL | UT_CANCELED )) == 0) {
		uth->uu_flag |= (UT_CANCEL | UT_NO_SIGMASK);
		if (((uth->uu_flag & UT_NOTCANCELPT) == 0) 
			&& ((uth->uu_flag & UT_CANCELDISABLE) == 0))
				thread_abort_safely(target_act);
	}

	thread_deallocate(target_act);
	return (error);
}

/* if action =0 ; return the cancellation state , 
 *      if marked for cancellation, make the thread canceled
 * if action = 1 ; Enable the cancel handling
 * if action = 2; Disable the cancel handling
 */
int
__pthread_canceled(__unused proc_t p,
	struct __pthread_canceled_args *uap, __unused int32_t *retval)
{
	thread_act_t thread;
	struct uthread *uth;
	int action = uap->action;

	thread = current_thread();
	uth = (struct uthread *)get_bsdthread_info(thread);

	switch (action) {
		case 1:
			uth->uu_flag &= ~UT_CANCELDISABLE;
			return(0);
		case 2:
			uth->uu_flag |= UT_CANCELDISABLE;
			return(0);
		case 0:
		default:
			/* if the thread is in vfork do not cancel */
			if((uth->uu_flag & ( UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL) {
				uth->uu_flag &= ~UT_CANCEL;
				uth->uu_flag |= (UT_CANCELED | UT_NO_SIGMASK);
				return(0);
			}
			return(EINVAL);
	}	 	
	return(EINVAL);
}

void
__posix_sem_syscall_return(kern_return_t kern_result) 
{
	int error = 0;

	if (kern_result == KERN_SUCCESS)
		error = 0;
	else if (kern_result == KERN_ABORTED)
		error = EINTR;
	else if (kern_result == KERN_OPERATION_TIMED_OUT) 
		error = ETIMEDOUT;
	else
		error = EINVAL;
	unix_syscall_return(error);
	/* does not return */
}

#if OLD_SEMWAIT_SIGNAL
/*
 * Returns:	0			Success
 *		EINTR
 *		ETIMEDOUT
 *		EINVAL
 *      EFAULT if timespec is NULL
 */
int
__old_semwait_signal(proc_t p, struct __old_semwait_signal_args *uap,
                     int32_t *retval)
{
	__pthread_testcancel(0);
	return(__old_semwait_signal_nocancel(p, (struct __old_semwait_signal_nocancel_args *)uap, retval));
}

int
__old_semwait_signal_nocancel(proc_t p, struct __old_semwait_signal_nocancel_args *uap,
                              __unused int32_t *retval)
{
	
	kern_return_t kern_result;
	int error;
	mach_timespec_t then;
	struct timespec now;
	struct user_timespec ts;
	boolean_t truncated_timeout = FALSE;
	
	if(uap->timeout) {
		
		if (IS_64BIT_PROCESS(p)) {
			struct user64_timespec ts64;
			error = copyin(uap->ts, &ts64, sizeof(ts64));
			ts.tv_sec = ts64.tv_sec;
			ts.tv_nsec = ts64.tv_nsec;
		} else {
			struct user32_timespec ts32;
			error = copyin(uap->ts, &ts32, sizeof(ts32));
			ts.tv_sec = ts32.tv_sec;
			ts.tv_nsec = ts32.tv_nsec;
		}
		
		if (error) {
			return error;
		}
		
		if ((ts.tv_sec & 0xFFFFFFFF00000000ULL) != 0) {
			ts.tv_sec = 0xFFFFFFFF;
			ts.tv_nsec = 0;
			truncated_timeout = TRUE;
		}
		
		if (uap->relative) {
			then.tv_sec = ts.tv_sec;
			then.tv_nsec = ts.tv_nsec;
		} else {
			nanotime(&now);
			
			/* if time has elapsed, set time to null timepsec to bailout rightaway */
			if (now.tv_sec == ts.tv_sec ?
				now.tv_nsec > ts.tv_nsec :
				now.tv_sec > ts.tv_sec) {
				then.tv_sec = 0;
				then.tv_nsec = 0;
			} else {
				then.tv_sec = ts.tv_sec - now.tv_sec;
				then.tv_nsec = ts.tv_nsec - now.tv_nsec;
				if (then.tv_nsec < 0) {
					then.tv_nsec += NSEC_PER_SEC;
					then.tv_sec--; 
				}
			}
		}
		
		if (uap->mutex_sem == 0)
			kern_result = semaphore_timedwait_trap_internal((mach_port_name_t)uap->cond_sem, then.tv_sec, then.tv_nsec, __posix_sem_syscall_return);
		else
			kern_result = semaphore_timedwait_signal_trap_internal(uap->cond_sem, uap->mutex_sem, then.tv_sec, then.tv_nsec, __posix_sem_syscall_return);
		
	} else {
		
		if (uap->mutex_sem == 0)
			kern_result = semaphore_wait_trap_internal(uap->cond_sem, __posix_sem_syscall_return);
		else
			
			kern_result = semaphore_wait_signal_trap_internal(uap->cond_sem, uap->mutex_sem, __posix_sem_syscall_return);
	}
	
	if (kern_result == KERN_SUCCESS && !truncated_timeout)
		return(0);
	else if (kern_result == KERN_SUCCESS && truncated_timeout)
		return(EINTR); /* simulate an exceptional condition because Mach doesn't support a longer timeout */
	else if (kern_result == KERN_ABORTED)
		return(EINTR);
	else if (kern_result == KERN_OPERATION_TIMED_OUT) 
		return(ETIMEDOUT);
	else
		return(EINVAL);
}
#endif /* OLD_SEMWAIT_SIGNAL*/

/*
 * Returns:	0			Success
 *		EINTR
 *		ETIMEDOUT
 *		EINVAL
 *      EFAULT if timespec is NULL
 */
int
__semwait_signal(proc_t p, struct __semwait_signal_args *uap,
                     int32_t *retval)
{
	__pthread_testcancel(0);
	return(__semwait_signal_nocancel(p, (struct __semwait_signal_nocancel_args *)uap, retval));
}

int
__semwait_signal_nocancel(__unused proc_t p, struct __semwait_signal_nocancel_args *uap,
                              __unused int32_t *retval)
{
	
	kern_return_t kern_result;
	mach_timespec_t then;
	struct timespec now;
	struct user_timespec ts;
        boolean_t truncated_timeout = FALSE;
	
	if(uap->timeout) {
                
		ts.tv_sec = uap->tv_sec;
                ts.tv_nsec = uap->tv_nsec;

                if ((ts.tv_sec & 0xFFFFFFFF00000000ULL) != 0) {
                        ts.tv_sec = 0xFFFFFFFF;
                        ts.tv_nsec = 0;
                        truncated_timeout = TRUE;
                }		
		
		if (uap->relative) {
			then.tv_sec = ts.tv_sec;
			then.tv_nsec = ts.tv_nsec;
		} else {
			nanotime(&now);

                        /* if time has elapsed, set time to null timepsec to bailout rightaway */
                        if (now.tv_sec == ts.tv_sec ?
                                now.tv_nsec > ts.tv_nsec :
                                now.tv_sec > ts.tv_sec) {
                                then.tv_sec = 0;
                                then.tv_nsec = 0;
                        } else {
                                then.tv_sec = ts.tv_sec - now.tv_sec;
                                then.tv_nsec = ts.tv_nsec - now.tv_nsec;
                                if (then.tv_nsec < 0) {
                                        then.tv_nsec += NSEC_PER_SEC;
                                        then.tv_sec--;
                                }
                        }
		}
					
		if (uap->mutex_sem == 0)
			kern_result = semaphore_timedwait_trap_internal((mach_port_name_t)uap->cond_sem, then.tv_sec, then.tv_nsec, __posix_sem_syscall_return);
		else
			kern_result = semaphore_timedwait_signal_trap_internal(uap->cond_sem, uap->mutex_sem, then.tv_sec, then.tv_nsec, __posix_sem_syscall_return);
		
	} else {
		
		if (uap->mutex_sem == 0)
			kern_result = semaphore_wait_trap_internal(uap->cond_sem, __posix_sem_syscall_return);
		else
			
			kern_result = semaphore_wait_signal_trap_internal(uap->cond_sem, uap->mutex_sem, __posix_sem_syscall_return);
	}
	
	if (kern_result == KERN_SUCCESS && !truncated_timeout)
                return(0);
        else if (kern_result == KERN_SUCCESS && truncated_timeout)
                return(EINTR); /* simulate an exceptional condition because Mach doesn't support a longer timeout */
	else if (kern_result == KERN_ABORTED)
		return(EINTR);
	else if (kern_result == KERN_OPERATION_TIMED_OUT) 
		return(ETIMEDOUT);
	else
		return(EINVAL);
}


int 
__pthread_kill(__unused proc_t p, struct __pthread_kill_args *uap,
	       __unused int32_t *retval) 
{
	thread_t target_act;
	int error = 0;
	int signum = uap->sig;
	struct uthread *uth;

	target_act = (thread_t)port_name_to_thread(uap->thread_port);

	if (target_act == THREAD_NULL)
		return (ESRCH);
	if ((u_int)signum >= NSIG) {
		error = EINVAL;
		goto out;
	}

	uth = (struct uthread *)get_bsdthread_info(target_act);

	if (uth->uu_flag & UT_NO_SIGMASK) {
		error = ESRCH;
		goto out;
	}

	if (signum)
		psignal_uthread(target_act, signum);
out:
	thread_deallocate(target_act);
	return (error);
}


int 
__pthread_sigmask(__unused proc_t p, struct __pthread_sigmask_args *uap,
		  __unused int32_t *retval)
{
	user_addr_t set = uap->set;
	user_addr_t oset = uap->oset;
	sigset_t nset;
	int error = 0;
	struct uthread *ut;
	sigset_t  oldset;

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	oldset = ut->uu_sigmask;

	if (set == USER_ADDR_NULL) {
		/* need only old mask */
		goto out;
	}

	error = copyin(set, &nset, sizeof(sigset_t));
	if (error)
		goto out;

	switch (uap->how) {
	case SIG_BLOCK:
		ut->uu_sigmask |= (nset & ~sigcantmask);
		break;

	case SIG_UNBLOCK:
		ut->uu_sigmask &= ~(nset);
		signal_setast(current_thread());
		break;

	case SIG_SETMASK:
		ut->uu_sigmask = (nset & ~sigcantmask);
		signal_setast(current_thread());
		break;
	
	default:
		error = EINVAL;

	}
out:
	if (!error && oset != USER_ADDR_NULL)
		copyout(&oldset, oset, sizeof(sigset_t));

	return(error);
}

/*
 * Returns:	0			Success
 *		EINVAL
 *	copyin:EFAULT
 *	copyout:EFAULT
 */
int 
__sigwait(proc_t p, struct __sigwait_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(__sigwait_nocancel(p, (struct __sigwait_nocancel_args *)uap, retval));
}

int 
__sigwait_nocancel(proc_t p, struct __sigwait_nocancel_args *uap, __unused int32_t *retval)
{
	struct uthread *ut;
	struct uthread *uth;
	int error = 0;
	sigset_t mask;
	sigset_t siglist;
	sigset_t sigw=0;
	int signum;

	ut = (struct uthread *)get_bsdthread_info(current_thread());

	if (uap->set == USER_ADDR_NULL)
		return(EINVAL);

	error = copyin(uap->set, &mask, sizeof(sigset_t));
	if (error)
		return(error);

	siglist = (mask & ~sigcantmask);

	if (siglist == 0)
		return(EINVAL);

	proc_lock(p);
	if ((p->p_lflag & P_LINVFORK) && p->p_vforkact) {
		proc_unlock(p);
		return(EINVAL);
	} else {
		proc_signalstart(p, 1);
		TAILQ_FOREACH(uth, &p->p_uthlist, uu_list) {
			if ( (sigw = uth->uu_siglist & siglist) ) {
				break;
			}
		}
		proc_signalend(p, 1);
	}

	if (sigw) {
		/* The signal was pending on a thread */
		goto sigwait1;
	}
	/*
	 * When returning from sigwait, we want
	 * the old mask to be restored after the
	 * signal handler has finished.  Thus, we
	 * save it here and mark the sigacts structure
	 * to indicate this.
	 */
	uth = ut;		/* wait for it to be delivered to us */
	ut->uu_oldmask = ut->uu_sigmask;
	ut->uu_flag |= UT_SAS_OLDMASK;
	if (siglist == (sigset_t)0) {
		proc_unlock(p);
		return(EINVAL);
	}
	/* SIGKILL and SIGSTOP are not maskable as well */
	ut->uu_sigmask = ~(siglist|sigcantmask);
	ut->uu_sigwait = siglist; 

	/* No Continuations for now */
	error =  msleep((caddr_t)&ut->uu_sigwait, &p->p_mlock, PPAUSE|PCATCH, "pause", 0);

	if (error == ERESTART)
		error = 0;

	sigw = (ut->uu_sigwait & siglist);
	ut->uu_sigmask = ut->uu_oldmask;
	ut->uu_oldmask = 0;
	ut->uu_flag &= ~UT_SAS_OLDMASK;
sigwait1:
	ut->uu_sigwait = 0;
	if (!error) {
		signum = ffs((unsigned int)sigw);
		if (!signum)
			panic("sigwait with no signal wakeup");
		/* Clear the pending signal in the thread it was delivered */
		uth->uu_siglist &= ~(sigmask(signum));

#if CONFIG_DTRACE
		DTRACE_PROC2(signal__clear, int, signum, siginfo_t *, &(ut->t_dtrace_siginfo));
#endif

		proc_unlock(p);
		if (uap->sig != USER_ADDR_NULL)
				error = copyout(&signum, uap->sig, sizeof(int));
	} else
		proc_unlock(p);

	return(error);

}

int
sigaltstack(__unused proc_t p, struct sigaltstack_args *uap, __unused int32_t *retval)
{
	struct kern_sigaltstack ss;
	struct kern_sigaltstack *pstk;
	int error;
	struct uthread *uth;
	int onstack;

	uth = (struct uthread *)get_bsdthread_info(current_thread());

	pstk = &uth->uu_sigstk;
	if ((uth->uu_flag & UT_ALTSTACK) == 0)
		uth->uu_sigstk.ss_flags |= SA_DISABLE;
	onstack = pstk->ss_flags & SA_ONSTACK;
	if (uap->oss) {
		if (IS_64BIT_PROCESS(p)) {
			struct user64_sigaltstack ss64;
			sigaltstack_kern_to_user64(pstk, &ss64);			
			error = copyout(&ss64, uap->oss, sizeof(ss64));
		} else {
			struct user32_sigaltstack ss32;
			sigaltstack_kern_to_user32(pstk, &ss32);			
			error = copyout(&ss32, uap->oss, sizeof(ss32));
		}
		if (error)
			return (error);
	}
	if (uap->nss == USER_ADDR_NULL)
		return (0);
	if (IS_64BIT_PROCESS(p)) {
		struct user64_sigaltstack ss64;
		error = copyin(uap->nss, &ss64, sizeof(ss64));
		sigaltstack_user64_to_kern(&ss64, &ss);
	} else {
		struct user32_sigaltstack ss32;
		error = copyin(uap->nss, &ss32, sizeof(ss32));
		sigaltstack_user32_to_kern(&ss32, &ss);
	}
	if (error)
		return (error);
	if ((ss.ss_flags & ~SA_DISABLE) != 0)  {
		return(EINVAL);
	}

	if (ss.ss_flags & SA_DISABLE) {
		/* if we are here we are not in the signal handler ;so no need to check */
		if (uth->uu_sigstk.ss_flags & SA_ONSTACK)
			return (EINVAL);
		uth->uu_flag &= ~UT_ALTSTACK;
		uth->uu_sigstk.ss_flags = ss.ss_flags;
		return (0);
	}
	if (onstack)
		return (EPERM);
/* The older stacksize was 8K, enforce that one so no compat problems */
#define OLDMINSIGSTKSZ 8*1024
	if (ss.ss_size < OLDMINSIGSTKSZ)
		return (ENOMEM);
	uth->uu_flag |= UT_ALTSTACK;
	uth->uu_sigstk= ss;
	return (0);
}

int
kill(proc_t cp, struct kill_args *uap, __unused int32_t *retval)
{
	proc_t p;
	kauth_cred_t uc = kauth_cred_get();
	int posix = uap->posix;		/* !0 if posix behaviour desired */

       AUDIT_ARG(pid, uap->pid);
       AUDIT_ARG(signum, uap->signum);

	if ((u_int)uap->signum >= NSIG)
		return (EINVAL);
	if (uap->pid > 0) {
		/* kill single process */
		if ((p = proc_find(uap->pid)) == NULL) {
			if ((p = pzfind(uap->pid)) != NULL) {
				/*
				 * IEEE Std 1003.1-2001: return success
				 * when killing a zombie.
				 */
				return (0);
			}
			return (ESRCH);
		}
		AUDIT_ARG(process, p);
		if (!cansignal(cp, uc, p, uap->signum, 0)) {
			proc_rele(p);
			return(EPERM);
		}
		if (uap->signum)
			psignal(p, uap->signum);
		proc_rele(p);
		return (0);
	}
	switch (uap->pid) {
	case -1:		/* broadcast signal */
		return (killpg1(cp, uap->signum, 0, 1, posix));
	case 0:			/* signal own process group */
		return (killpg1(cp, uap->signum, 0, 0, posix));
	default:		/* negative explicit process group */
		return (killpg1(cp, uap->signum, -(uap->pid), 0, posix));
	}
	/* NOTREACHED */
}

static int
killpg1_filt(proc_t p, void * arg)
{
	struct killpg1_filtargs * kfargp = (struct killpg1_filtargs *)arg;
	proc_t cp = kfargp->cp;
	int posix = kfargp->posix;


	if (p->p_pid <= 1 || p->p_flag & P_SYSTEM ||
		(!posix && p == cp))
		return(0);
	else
		return(1);
}


static int
killpg1_pgrpfilt(proc_t p, __unused void * arg)
{
        if (p->p_pid <= 1 || p->p_flag & P_SYSTEM ||
                (p->p_stat == SZOMB))
                return(0);
        else
                return(1);
}



static int
killpg1_callback(proc_t p, void * arg)
{
	struct killpg1_iterargs * kargp = (struct killpg1_iterargs *)arg;
        proc_t cp = kargp->cp;
        kauth_cred_t uc = kargp->uc;   /* refcounted by the caller safe to use internal fields */
        int signum = kargp->signum;
	int * nfoundp = kargp->nfoundp;
	int n;
	int zombie = 0;
	int error = 0;

	if ((kargp->zombie != 0) && ((p->p_listflag & P_LIST_EXITED) == P_LIST_EXITED))
		zombie = 1;

	if (zombie != 0) {
		proc_list_lock();
		error = cansignal(cp, uc, p, signum, zombie);
		proc_list_unlock();
	
		if (error != 0 && nfoundp != NULL) {
			n = *nfoundp;
			*nfoundp = n+1;
		}
	} else {
		if (cansignal(cp, uc, p, signum, 0) == 0)
			return(PROC_RETURNED);

		if (nfoundp != NULL) {
			n = *nfoundp;
			*nfoundp = n+1;
		}
		if (signum != 0)
			psignal(p, signum);
	}

	return(PROC_RETURNED);
}

/*
 * Common code for kill process group/broadcast kill.
 * cp is calling process.
 */
int
killpg1(proc_t cp, int signum, int pgid, int all, int posix)
{
	kauth_cred_t uc;
	struct pgrp *pgrp;
	int nfound = 0;
	struct killpg1_iterargs karg;
	struct killpg1_filtargs kfarg;
	int error = 0;
	
	uc = kauth_cred_proc_ref(cp);
	if (all) {
		/* 
		 * broadcast 
		 */
		kfarg.posix = posix;
		kfarg.cp = cp;

		karg.cp = cp;
		karg.uc = uc;
		karg.nfoundp = &nfound;
		karg.signum = signum;
		karg.zombie = 1;

		proc_iterate((PROC_ALLPROCLIST | PROC_ZOMBPROCLIST), killpg1_callback, &karg, killpg1_filt, (void *)&kfarg);

	} else {
		if (pgid == 0) {
			/* 
			 * zero pgid means send to my process group.
			 */
			pgrp = proc_pgrp(cp);
		 } else {
			pgrp = pgfind(pgid);
			if (pgrp == NULL) {
				error = ESRCH;
				goto out;
			}
		}

                karg.nfoundp = &nfound;
                karg.uc = uc;
                karg.signum = signum;
		karg.cp = cp;
		karg.zombie = 0;


		/* PGRP_DROPREF drops the pgrp refernce */
		pgrp_iterate(pgrp, PGRP_BLOCKITERATE | PGRP_DROPREF, killpg1_callback, &karg,
			killpg1_pgrpfilt, NULL);
	}
	error =  (nfound ? 0 : (posix ? EPERM : ESRCH));
out:
	kauth_cred_unref(&uc);
	return (error);
}


/*
 * Send a signal to a process group.
 */
void
gsignal(int pgid, int signum)
{
	struct pgrp *pgrp;

	if (pgid && (pgrp = pgfind(pgid))) {
		pgsignal(pgrp, signum, 0);
		pg_rele(pgrp);
	}
}

/*
 * Send a signal to a process group.  If checkctty is 1,
 * limit to members which have a controlling terminal.
 */

static int
pgsignal_filt(proc_t p, void * arg)
{
	int checkctty = *(int*)arg;

	if ((checkctty == 0) || p->p_flag & P_CONTROLT)
		return(1);
	else 
		return(0);
}


static int
pgsignal_callback(proc_t p, void * arg)
{
        int  signum = *(int*)arg;

	psignal(p, signum);
	return(PROC_RETURNED);
}


void
pgsignal(struct pgrp *pgrp, int signum, int checkctty)
{
	if (pgrp != PGRP_NULL) {
		pgrp_iterate(pgrp, PGRP_BLOCKITERATE, pgsignal_callback, &signum, pgsignal_filt, &checkctty);
	}
}


void
tty_pgsignal(struct tty *tp, int signum, int checkctty)
{
	struct pgrp * pg;

	pg = tty_pgrp(tp);
	if (pg != PGRP_NULL) {
		pgrp_iterate(pg, PGRP_BLOCKITERATE, pgsignal_callback, &signum, pgsignal_filt, &checkctty);
		pg_rele(pg);
	}
}
/*
 * Send a signal caused by a trap to a specific thread.
 */
void
threadsignal(thread_t sig_actthread, int signum, mach_exception_code_t code)
{
	struct uthread *uth;
	struct task * sig_task;
	proc_t p;
	int mask;

	if ((u_int)signum >= NSIG || signum == 0)
		return;

	mask = sigmask(signum);
	if ((mask & threadmask) == 0)
		return;
	sig_task = get_threadtask(sig_actthread);
	p = (proc_t)(get_bsdtask_info(sig_task));

	uth = get_bsdthread_info(sig_actthread);
	if (uth && (uth->uu_flag & UT_VFORK))
		p = uth->uu_proc;

	proc_lock(p);
	if (!(p->p_lflag & P_LTRACED) && (p->p_sigignore & mask)) {
		proc_unlock(p);
		return;
	}

	uth->uu_siglist |= mask;
	uth->uu_code = code;
	proc_unlock(p);

	/* mark on process as well */
	signal_setast(sig_actthread);
}

static kern_return_t
get_signalthread(proc_t p, int signum, thread_t * thr)
{
	struct uthread *uth;
	sigset_t mask = sigmask(signum);
	thread_t sig_thread;
	struct task * sig_task = p->task;
	kern_return_t kret;
	
	*thr = THREAD_NULL;

	if ((p->p_lflag & P_LINVFORK) && p->p_vforkact) {
		sig_thread = p->p_vforkact;	
		kret = check_actforsig(sig_task, sig_thread, 1);
		if (kret == KERN_SUCCESS)  {
			*thr = sig_thread;
			return(KERN_SUCCESS);
		}else
			return(KERN_FAILURE);
	} 

	proc_lock(p);
	TAILQ_FOREACH(uth, &p->p_uthlist, uu_list) {
		if(((uth->uu_flag & UT_NO_SIGMASK)== 0) && 
			(((uth->uu_sigmask & mask) == 0) || (uth->uu_sigwait & mask))) {
			if (check_actforsig(p->task, uth->uu_context.vc_thread, 1) == KERN_SUCCESS) {
				*thr = uth->uu_context.vc_thread;
				proc_unlock(p);
				return(KERN_SUCCESS);
			}
		}
	}
	proc_unlock(p);
	if (get_signalact(p->task, thr, 1) == KERN_SUCCESS) {
		return(KERN_SUCCESS);
	}

	return(KERN_FAILURE);
}

/*
 * Send the signal to the process.  If the signal has an action, the action
 * is usually performed by the target process rather than the caller; we add
 * the signal to the set of pending signals for the process.
 *
 * Exceptions:
 *   o When a stop signal is sent to a sleeping process that takes the
 *     default action, the process is stopped without awakening it.
 *   o SIGCONT restarts stopped processes (or puts them back to sleep)
 *     regardless of the signal action (eg, blocked or ignored).
 *
 * Other ignored signals are discarded immediately.
 */
static void
psignal_internal(proc_t p, task_t task, thread_t thread, int flavor, int signum)
{
	int prop;
	sig_t action = NULL;
	proc_t 		sig_proc;
	thread_t	sig_thread;
	register task_t		sig_task;
	int mask;
	struct uthread *uth;
	kern_return_t kret;
	uid_t r_uid;
	proc_t pp;
	kauth_cred_t my_cred;

	if ((u_int)signum >= NSIG || signum == 0)
		panic("psignal signal number");
	mask = sigmask(signum);
	prop = sigprop[signum];

#if SIGNAL_DEBUG
        if(rdebug_proc && (p != PROC_NULL) && (p == rdebug_proc)) {
                ram_printf(3);
        }
#endif /* SIGNAL_DEBUG */

	/*
	 *	We will need the task pointer later.  Grab it now to
	 *	check for a zombie process.  Also don't send signals
	 *	to kernel internal tasks.
	 */
	if (flavor & PSIG_VFORK) {
		sig_task = task;
		sig_thread = thread;
		sig_proc= p;
	} else if (flavor & PSIG_THREAD) {
		sig_task = get_threadtask(thread);
		sig_thread = thread;
		sig_proc = (proc_t)get_bsdtask_info(sig_task);
	} else {
		sig_task = p->task;
		sig_proc = p;
		sig_thread = (struct thread *)0;
	}
	if (((sig_task == TASK_NULL)  || is_kerneltask(sig_task))) {
		return;
	}

	/*
	 * do not send signals to the process that has the thread
	 * doing a reboot(). Not doing so will mark that thread aborted
	 * and can cause IO failures wich will cause data loss.
	 */
	if (ISSET(sig_proc->p_flag, P_REBOOT)) {
		return;
	}

	if( (flavor & (PSIG_VFORK | PSIG_THREAD)) == 0) {
		proc_knote(sig_proc, NOTE_SIGNAL | signum);
	}


	if ((flavor & PSIG_LOCKED)== 0)
		proc_signalstart(sig_proc, 0);

	/*
	 *	Deliver the signal to the first thread in the task. This
	 *	allows single threaded applications which use signals to
	 *	be able to be linked with multithreaded libraries.  We have
	 *	an implicit reference to the current thread, but need
	 *	an explicit one otherwise.  The thread reference keeps
	 *	the corresponding task data structures around too.  This
	 *	reference is released by thread_deallocate.
	 */
	

	if (((flavor & PSIG_VFORK) == 0) && ((sig_proc->p_lflag & P_LTRACED) == 0) && (sig_proc->p_sigignore & mask)) {
		DTRACE_PROC3(signal__discard, thread_t, sig_thread, proc_t, sig_proc, int, signum);
		goto psigout;
	}

	if (flavor & PSIG_VFORK) {
		action = SIG_DFL;
		act_set_astbsd(sig_thread);
		kret = KERN_SUCCESS;
	} else if (flavor & PSIG_THREAD) {
		/* If successful return with ast set */
		kret = check_actforsig(sig_task, sig_thread, 1);
	} else {
		/* If successful return with ast set */
		kret = get_signalthread(sig_proc, signum, &sig_thread);
	}
	if (kret != KERN_SUCCESS) {
#if SIGNAL_DEBUG
       		ram_printf(1);
#endif /* SIGNAL_DEBUG */
		goto psigout;
	}


	uth = get_bsdthread_info(sig_thread);

	/*
	 * If proc is traced, always give parent a chance.
	 */

	if ((flavor & PSIG_VFORK) == 0) {
		if (sig_proc->p_lflag & P_LTRACED)
			action = SIG_DFL;
		else {
			/*
			 * If the signal is being ignored,
			 * then we forget about it immediately.
			 * (Note: we don't set SIGCONT in p_sigignore,
			 * and if it is set to SIG_IGN,
			 * action will be SIG_DFL here.)
			 */
			if (sig_proc->p_sigignore & mask)
				goto psigout;
			if (uth->uu_sigwait & mask)
				action = KERN_SIG_WAIT;
			else if (uth->uu_sigmask & mask)
				action = KERN_SIG_HOLD;
			else if (sig_proc->p_sigcatch & mask)
				action = KERN_SIG_CATCH;
			else
				action = SIG_DFL;
		}
	}


	proc_lock(sig_proc);

	if (sig_proc->p_nice > NZERO && action == SIG_DFL && (prop & SA_KILL) &&
		(sig_proc->p_lflag & P_LTRACED) == 0)
			sig_proc->p_nice = NZERO;

	if (prop & SA_CONT)
		uth->uu_siglist &= ~stopsigmask;

	if (prop & SA_STOP) {
		struct pgrp *pg;
		/*
		 * If sending a tty stop signal to a member of an orphaned
		 * process group, discard the signal here if the action
		 * is default; don't stop the process below if sleeping,
		 * and don't clear any pending SIGCONT.
		 */
		proc_unlock(sig_proc);
		pg = proc_pgrp(sig_proc);
		if (prop & SA_TTYSTOP && pg->pg_jobc == 0 &&
			action == SIG_DFL) {
			pg_rele(pg);
			goto psigout;
		}
		pg_rele(pg);
		proc_lock(sig_proc);
		uth->uu_siglist &= ~contsigmask;
	}

	uth->uu_siglist |= mask;
	/* 
	 * Repost AST incase sigthread has processed 
	 * ast and missed signal post.
	 */
	if (action == KERN_SIG_CATCH)
		act_set_astbsd(sig_thread);

	
	/*
	 * Defer further processing for signals which are held,
	 * except that stopped processes must be continued by SIGCONT.
	 */
	/* vfork will not go thru as action is SIG_DFL */
	if ((action == KERN_SIG_HOLD) && ((prop & SA_CONT) == 0 || sig_proc->p_stat != SSTOP)) {
		proc_unlock(sig_proc);
		goto psigout;
	}
	/*
	 *	SIGKILL priority twiddling moved here from above because
	 *	it needs sig_thread.  Could merge it into large switch
	 *	below if we didn't care about priority for tracing
	 *	as SIGKILL's action is always SIG_DFL.
	 */
	if ((signum == SIGKILL) && (sig_proc->p_nice > NZERO)) {
		sig_proc->p_nice = NZERO;
	}

	/*
	 *	Process is traced - wake it up (if not already
	 *	stopped) so that it can discover the signal in
	 *	issig() and stop for the parent.
	 */
	if (sig_proc->p_lflag & P_LTRACED) {
	   	if (sig_proc->p_stat != SSTOP)
			goto runlocked;
		else {
			proc_unlock(sig_proc);
			goto psigout;
		}
	}
	if ((flavor & PSIG_VFORK) != 0)
		goto runlocked;

	if (action == KERN_SIG_WAIT) {
#if CONFIG_DTRACE
		/*
		 * DTrace proc signal-clear returns a siginfo_t. Collect the needed info.
		 */
		r_uid = kauth_getruid(); /* per thread credential; protected by our thread context */

		bzero((caddr_t)&(uth->t_dtrace_siginfo), sizeof(uth->t_dtrace_siginfo));

		uth->t_dtrace_siginfo.si_signo = signum;
		uth->t_dtrace_siginfo.si_pid = current_proc()->p_pid;
		uth->t_dtrace_siginfo.si_status = W_EXITCODE(signum, 0);
		uth->t_dtrace_siginfo.si_uid = r_uid;
		uth->t_dtrace_siginfo.si_code = 0;
#endif
		uth->uu_sigwait = mask;
		uth->uu_siglist &= ~mask;
		wakeup(&uth->uu_sigwait);
		/* if it is SIGCONT resume whole process */
		if (prop & SA_CONT) {
			OSBitOrAtomic(P_CONTINUED, &sig_proc->p_flag);
			sig_proc->p_contproc = current_proc()->p_pid;

			proc_unlock(sig_proc);
			(void) task_resume(sig_task);
			goto psigout;
		}
		proc_unlock(sig_proc);
		goto psigout;
	}

	if (action != SIG_DFL) {
		/*
		 *	User wants to catch the signal.
		 *	Wake up the thread, but don't un-suspend it
		 *	(except for SIGCONT).
		 */
		if (prop & SA_CONT) {
			OSBitOrAtomic(P_CONTINUED, &sig_proc->p_flag);
			proc_unlock(sig_proc);
			(void) task_resume(sig_task);
			proc_lock(sig_proc);
			sig_proc->p_stat = SRUN;
		}  else if (sig_proc->p_stat == SSTOP) {
			proc_unlock(sig_proc);
			goto psigout;
		}
		/*
		 * Fill out siginfo structure information to pass to the
		 * signalled process/thread sigaction handler, when it
		 * wakes up.  si_code is 0 because this is an ordinary
		 * signal, not a SIGCHLD, and so si_status is the signal
		 * number itself, instead of the child process exit status.
		 * We shift this left because it will be shifted right before
		 * it is passed to user space.  kind of ugly to use W_EXITCODE
		 * this way, but it beats defining a new macro.
		 *
		 * Note:	Avoid the SIGCHLD recursion case!
		 */
		if (signum != SIGCHLD) {
			proc_unlock(sig_proc);
			r_uid = kauth_getruid();
			proc_lock(sig_proc);

			sig_proc->si_pid = current_proc()->p_pid;
			sig_proc->si_status = W_EXITCODE(signum, 0);
			sig_proc->si_uid = r_uid;
			sig_proc->si_code = 0;
		}

		goto runlocked;
	} else {
		/*	Default action - varies */
		if (mask & stopsigmask) {
			/*
			 * These are the signals which by default
			 * stop a process.
			 *
			 * Don't clog system with children of init
			 * stopped from the keyboard.
			 */
			if (!(prop & SA_STOP) && sig_proc->p_pptr == initproc) {
				proc_unlock(sig_proc);
				psignal_locked(sig_proc, SIGKILL);
				proc_lock(sig_proc);
				uth->uu_siglist &= ~mask;
				proc_unlock(sig_proc);
				goto psigout;
			}
                        
			/*
			 *	Stop the task
			 *	if task hasn't already been stopped by
			 *	a signal.
			 */
			uth->uu_siglist &= ~mask;
			if (sig_proc->p_stat != SSTOP) {
				sig_proc->p_xstat = signum;
				sig_proc->p_stat = SSTOP;
				OSBitAndAtomic(~((uint32_t)P_CONTINUED), &sig_proc->p_flag);
				sig_proc->p_lflag &= ~P_LWAITED;
				proc_unlock(sig_proc);

				pp = proc_parentholdref(sig_proc);
				stop(sig_proc, pp);
				if (( pp != PROC_NULL) && ((pp->p_flag & P_NOCLDSTOP) == 0)) {

					my_cred = kauth_cred_proc_ref(sig_proc);
					r_uid = my_cred->cr_ruid;
					kauth_cred_unref(&my_cred);

					proc_lock(sig_proc);
					pp->si_pid = sig_proc->p_pid;
					/*
					 * POSIX: sigaction for a stopped child
					 * when sent to the parent must set the
					 * child's signal number into si_status.
					 */
					if (signum != SIGSTOP)
						pp->si_status = WEXITSTATUS(sig_proc->p_xstat);
					else
						pp->si_status = W_EXITCODE(signum, signum);
					pp->si_code = CLD_STOPPED;
					pp->si_uid = r_uid;
					proc_unlock(sig_proc);

					psignal(pp, SIGCHLD);
				}
				if (pp != PROC_NULL)
					proc_parentdropref(pp, 0);
			} else
				proc_unlock(sig_proc);
			goto psigout;
		}

		DTRACE_PROC3(signal__send, thread_t, sig_thread, proc_t, p, int, signum);

		/*
		 * enters switch with sig_proc lock held but dropped when
		 * gets out of switch
		 */
		switch (signum) {
			/*
			 * Signals ignored by default have been dealt
			 * with already, since their bits are on in
			 * p_sigignore.
			 */

		case SIGKILL:
			/*
			 * Kill signal always sets process running and
			 * unsuspends it.
			 */
			/*
			 *	Process will be running after 'run'
			 */
			sig_proc->p_stat = SRUN;
			proc_unlock(sig_proc);
			thread_abort(sig_thread);

			goto psigout;

		case SIGCONT:
			/*
			 * Let the process run.  If it's sleeping on an
			 * event, it remains so.
			 */
			OSBitOrAtomic(P_CONTINUED, &sig_proc->p_flag);
			sig_proc->p_contproc = sig_proc->p_pid;

			proc_unlock(sig_proc);
			(void) task_resume(sig_task);
			proc_lock(sig_proc);
			/*
			 * When processing a SIGCONT, we need to check
			 * to see if there are signals pending that
			 * were not delivered because we had been
			 * previously stopped.  If that's the case,
			 * we need to thread_abort_safely() to trigger
			 * interruption of the current system call to
			 * cause their handlers to fire.  If it's only
			 * the SIGCONT, then don't wake up.
			 */
			if (((flavor & (PSIG_VFORK|PSIG_THREAD)) == 0) && (((uth->uu_siglist & ~uth->uu_sigmask) & ~sig_proc->p_sigignore) & ~mask)) {
				uth->uu_siglist &= ~mask;
				sig_proc->p_stat = SRUN;
				goto runlocked;
			}

			uth->uu_siglist &= ~mask;
			sig_proc->p_stat = SRUN;
			proc_unlock(sig_proc);
			goto psigout;

		default:
			/*
			 * A signal which has a default action of killing
			 * the process, and for which there is no handler,
			 * needs to act like SIGKILL
			 */
			if (((flavor & (PSIG_VFORK|PSIG_THREAD)) == 0) && (action == SIG_DFL) && (prop & SA_KILL)) {
				sig_proc->p_stat = SRUN;
				proc_unlock(sig_proc);
				thread_abort(sig_thread);
				goto psigout;
			}

			/*
			 * All other signals wake up the process, but don't
			 * resume it.
			 */
			if (sig_proc->p_stat == SSTOP) {
				proc_unlock(sig_proc);
				goto psigout;
			}
			goto runlocked;
		}
	}
	/*NOTREACHED*/

runlocked:
	/*
	 * If we're being traced (possibly because someone attached us
	 * while we were stopped), check for a signal from the debugger.
	 */
	if (sig_proc->p_stat == SSTOP) {
		if ((sig_proc->p_lflag & P_LTRACED) != 0 && sig_proc->p_xstat != 0)
			uth->uu_siglist |= sigmask(sig_proc->p_xstat); 
		if ((flavor & PSIG_VFORK) != 0) {
			sig_proc->p_stat = SRUN;
		}
		proc_unlock(sig_proc);	
	} else {
		/*
	 	 * setrunnable(p) in BSD and
	 	 * Wake up the thread if it is interruptible.
	 	 */
		sig_proc->p_stat = SRUN;
		proc_unlock(sig_proc);	
		if ((flavor & PSIG_VFORK) == 0)
			thread_abort_safely(sig_thread);
	}
psigout:
	if ((flavor & PSIG_LOCKED)== 0) {
		proc_signalend(sig_proc, 0);
	}
}

void
psignal(proc_t p, int signum)
{
	psignal_internal(p, NULL, NULL, 0, signum);
}

void
psignal_locked(proc_t p, int signum)
{
	psignal_internal(p, NULL, NULL, PSIG_LOCKED, signum);
}

void
psignal_vfork(proc_t p, task_t new_task, thread_t thread, int signum)
{
	psignal_internal(p, new_task, thread, PSIG_VFORK, signum);
}

static void
psignal_uthread(thread_t thread, int signum)
{
	psignal_internal(PROC_NULL, TASK_NULL, thread, PSIG_THREAD, signum);
}


/*
 * If the current process has received a signal (should be caught or cause
 * termination, should interrupt current syscall), return the signal number.
 * Stop signals with default action are processed immediately, then cleared;
 * they aren't returned.  This is checked after each entry to the system for
 * a syscall or trap (though this can usually be done without calling issignal
 * by checking the pending signal masks in the CURSIG macro.) The normal call
 * sequence is
 *
 *	while (signum = CURSIG(curproc))
 *		postsig(signum);
 */
int
issignal(proc_t p)
{
	int signum, mask, prop, sigbits;
	thread_t cur_act;
	struct uthread * ut;
	proc_t pp;
	kauth_cred_t my_cred;
	int retval = 0;
	uid_t r_uid;

	cur_act = current_thread();

#if SIGNAL_DEBUG
        if(rdebug_proc && (p == rdebug_proc)) {
                ram_printf(3);
        }
#endif /* SIGNAL_DEBUG */
	proc_lock(p);

	/*
	 * Try to grab the signal lock.
	 */
	if (sig_try_locked(p) <= 0) {
		proc_unlock(p);
		return(0);
	}

	proc_signalstart(p, 1);

	ut = get_bsdthread_info(cur_act);
	for(;;) {
		sigbits = ut->uu_siglist  & ~ut->uu_sigmask;

		if (p->p_lflag & P_LPPWAIT)
			sigbits &= ~stopsigmask;
		if (sigbits == 0) {	 	/* no signal to send */
			retval = 0;
			goto out;
		}

		signum = ffs((long)sigbits);
		mask = sigmask(signum);
		prop = sigprop[signum];

		/*
		 * We should see pending but ignored signals
		 * only if P_LTRACED was on when they were posted.
		 */
		if (mask & p->p_sigignore && (p->p_lflag & P_LTRACED) == 0) {
			ut->uu_siglist &= ~mask;		/* take the signal! */
			continue;
		}
		if (p->p_lflag & P_LTRACED && (p->p_lflag & P_LPPWAIT) == 0)  {
			task_t	task;
			/*
			 * If traced, always stop, and stay
			 * stopped until released by the debugger.
			 */
			/* ptrace debugging */
			p->p_xstat = signum;
	
			if (p->p_lflag & P_LSIGEXC) {
				p->sigwait = TRUE;
				p->sigwait_thread = cur_act;
				p->p_stat = SSTOP;
				OSBitAndAtomic(~((uint32_t)P_CONTINUED), &p->p_flag);
				p->p_lflag &= ~P_LWAITED;
				ut->uu_siglist &= ~mask;	/* clear the old signal */
				proc_signalend(p, 1);
				proc_unlock(p);
				do_bsdexception(EXC_SOFTWARE, EXC_SOFT_SIGNAL, signum);
				proc_lock(p);
				proc_signalstart(p, 1);
			} else {
				proc_unlock(p);
				my_cred = kauth_cred_proc_ref(p);
				r_uid = my_cred->cr_ruid;
				kauth_cred_unref(&my_cred);

				pp = proc_parentholdref(p);
				if (pp != PROC_NULL) {
					proc_lock(pp);

					pp->si_pid = p->p_pid;
					pp->si_status = p->p_xstat;
					pp->si_code = CLD_TRAPPED;
					pp->si_uid = r_uid;

					proc_unlock(pp);
				}

				/*
			 	*	XXX Have to really stop for debuggers;
			 	*	XXX stop() doesn't do the right thing.
			 	*	XXX Inline the task_suspend because we
			 	*	XXX have to diddle Unix state in the
			 	*	XXX middle of it.
			 	*/
				task = p->task;
				task_suspend(task);

				proc_lock(p);
				p->sigwait = TRUE;
				p->sigwait_thread = cur_act;
				p->p_stat = SSTOP;
				OSBitAndAtomic(~((uint32_t)P_CONTINUED), &p->p_flag);
				p->p_lflag &= ~P_LWAITED;
				ut->uu_siglist &= ~mask;	/* clear the old signal */

				proc_signalend(p, 1);
				proc_unlock(p);

				if (pp != PROC_NULL) {
					psignal(pp, SIGCHLD);
					proc_list_lock();
					wakeup((caddr_t)pp);
					proc_parentdropref(pp, 1);
					proc_list_unlock();
				}

				assert_wait((caddr_t)&p->sigwait, (THREAD_INTERRUPTIBLE));
				thread_block(THREAD_CONTINUE_NULL);
				proc_lock(p);
				proc_signalstart(p, 1);
			}

			p->sigwait = FALSE;
			p->sigwait_thread = NULL;
			wakeup((caddr_t)&p->sigwait_thread);

			/*
			 * This code is to detect when gdb is killed
			 * even as the traced program is attached.
			 * pgsignal would get the SIGKILL to traced program
			 * That's what we are trying to see (I hope)
			 */
			if (ut->uu_siglist & sigmask(SIGKILL)) {
				/*
				 * Wait event may still be outstanding;
				 * clear it, since sig_lock_to_exit will
				 * wait.
				 */
				clear_wait(current_thread(), THREAD_INTERRUPTED);
				sig_lock_to_exit(p);
				/*
			 	* Since this thread will be resumed
			 	* to allow the current syscall to
			 	* be completed, must save u_qsave
			 	* before calling exit().  (Since exit()
			 	* calls closef() which can trash u_qsave.)
			 	*/
				proc_signalend(p, 1);
				proc_unlock(p);
				KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_FRCEXIT) | DBG_FUNC_NONE,
					      p->p_pid, W_EXITCODE(0, SIGKILL), 2, 0, 0);
				exit1(p, W_EXITCODE(0, SIGKILL), (int *)NULL);
				return(0);
			}

			/*
			 *	We may have to quit
			 */
			if (thread_should_abort(current_thread())) {
				retval = 0;
				goto out;
			}
			/*
			 * If parent wants us to take the signal,
			 * then it will leave it in p->p_xstat;
			 * otherwise we just look for signals again.
			 */
			signum = p->p_xstat;
			if (signum == 0)
				continue;
			/*
			 * Put the new signal into p_siglist.  If the
			 * signal is being masked, look for other signals.
			 */
			mask = sigmask(signum);
			ut->uu_siglist |= mask;
			if (ut->uu_sigmask & mask)
				continue;
		}

		/*
		 * Decide whether the signal should be returned.
		 * Return the signal's number, or fall through
		 * to clear it from the pending mask.
		 */

		switch ((long)p->p_sigacts->ps_sigact[signum]) {
		
		case (long)SIG_DFL:
			/*
			 * Don't take default actions on system processes.
			 */
			if (p->p_ppid == 0) {
#if DIAGNOSTIC
				/*
				 * Are you sure you want to ignore SIGSEGV
				 * in init? XXX
				 */
				printf("Process (pid %d) got signal %d\n",
					p->p_pid, signum);
#endif
				break; 				/* == ignore */
			}
			
			/*
			 * If there is a pending stop signal to process
			 * with default action, stop here,
			 * then clear the signal.  However,
			 * if process is member of an orphaned
			 * process group, ignore tty stop signals.
			 */
			if (prop & SA_STOP) {
				struct pgrp * pg;

				proc_unlock(p);
				pg = proc_pgrp(p);
				if (p->p_lflag & P_LTRACED ||
					(pg->pg_jobc == 0 &&
					prop & SA_TTYSTOP)) {
					proc_lock(p);
					pg_rele(pg);
					break;	/* == ignore */
				}
				pg_rele(pg);
				if (p->p_stat != SSTOP) {
					proc_lock(p);
					p->p_xstat = signum;
				
					p->p_stat = SSTOP;
					p->p_lflag &= ~P_LWAITED;
					proc_unlock(p);

					pp = proc_parentholdref(p);
					stop(p, pp);
					if ((pp != PROC_NULL) && ((pp->p_flag & P_NOCLDSTOP) == 0)) {
						my_cred = kauth_cred_proc_ref(p);
						r_uid = my_cred->cr_ruid;
						kauth_cred_unref(&my_cred);

						proc_lock(pp);
						pp->si_pid = p->p_pid;
						pp->si_status = WEXITSTATUS(p->p_xstat);
						pp->si_code = CLD_STOPPED;
						pp->si_uid = r_uid;
						proc_unlock(pp);

						psignal(pp, SIGCHLD);
					}
					if (pp != PROC_NULL)
						proc_parentdropref(pp, 0);
				}
				proc_lock(p);
				break;
			} else if (prop & SA_IGNORE) {
				/*
				 * Except for SIGCONT, shouldn't get here.
				 * Default action is to ignore; drop it.
				 */
				break;		/* == ignore */
			} else {
				ut->uu_siglist &= ~mask;	/* take the signal! */
				retval = signum;
				goto out;
			}

			/*NOTREACHED*/
			break;

		case (long)SIG_IGN:
			/*
			 * Masking above should prevent us ever trying
			 * to take action on an ignored signal other
			 * than SIGCONT, unless process is traced.
			 */
			if ((prop & SA_CONT) == 0 &&
				(p->p_lflag & P_LTRACED) == 0)
				printf("issignal\n");
			break;		/* == ignore */

		default:
			/*
			 * This signal has an action, let
			 * postsig() process it.
			 */
			ut->uu_siglist &= ~mask;		/* take the signal! */
			retval = signum;
			goto out;
		}
		ut->uu_siglist &= ~mask;		/* take the signal! */
		}
	/* NOTREACHED */
out:
	proc_signalend(p,1);
	proc_unlock(p);
	return(retval);
}

/* called from _sleep */
int
CURSIG(proc_t p)
{
	int signum, mask, prop, sigbits;
	thread_t cur_act;
	struct uthread * ut;
	int retnum = 0;
           

	cur_act = current_thread();

	ut = get_bsdthread_info(cur_act);

	if (ut->uu_siglist == 0)
		return (0);

	if (((ut->uu_siglist & ~ut->uu_sigmask) == 0) && ((p->p_lflag & P_LTRACED) == 0))
		return (0);

	sigbits = ut->uu_siglist & ~ut->uu_sigmask;

	for(;;) {
		if (p->p_lflag & P_LPPWAIT)
			sigbits &= ~stopsigmask;
		if (sigbits == 0) {	 	/* no signal to send */
			return (retnum);
		}

		signum = ffs((long)sigbits);
		mask = sigmask(signum);
		prop = sigprop[signum];

		/*
		 * We should see pending but ignored signals
		 * only if P_LTRACED was on when they were posted.
		 */
		if (mask & p->p_sigignore && (p->p_lflag & P_LTRACED) == 0) {
			continue;
		}
		if (p->p_lflag & P_LTRACED && (p->p_lflag & P_LPPWAIT) == 0) {
			/*
			 * Put the new signal into p_siglist.  If the
			 * signal is being masked, look for other signals.
			 */
			mask = sigmask(signum);
			if (ut->uu_sigmask & mask)
				continue;
			return(signum);
		}

		/*
		 * Decide whether the signal should be returned.
		 * Return the signal's number, or fall through
		 * to clear it from the pending mask.
		 */

		switch ((long)p->p_sigacts->ps_sigact[signum]) {
		
		case (long)SIG_DFL:
			/*
			 * Don't take default actions on system processes.
			 */
			if (p->p_ppid == 0) {
#if DIAGNOSTIC
				/*
				 * Are you sure you want to ignore SIGSEGV
				 * in init? XXX
				 */
				printf("Process (pid %d) got signal %d\n",
					p->p_pid, signum);
#endif
				break; 				/* == ignore */
			}
			
			/*
			 * If there is a pending stop signal to process
			 * with default action, stop here,
			 * then clear the signal.  However,
			 * if process is member of an orphaned
			 * process group, ignore tty stop signals.
			 */
			if (prop & SA_STOP) {
				struct pgrp *pg;

				pg = proc_pgrp(p);

				if (p->p_lflag & P_LTRACED ||
					(pg->pg_jobc == 0 &&
					prop & SA_TTYSTOP)) {
					pg_rele(pg);
					break;	/* == ignore */
				}
				pg_rele(pg);
				retnum = signum;
				break;
			} else if (prop & SA_IGNORE) {
				/*
				 * Except for SIGCONT, shouldn't get here.
				 * Default action is to ignore; drop it.
				 */
				break;		/* == ignore */
			} else {
				return (signum);
			}
			/*NOTREACHED*/

		case (long)SIG_IGN:
			/*
			 * Masking above should prevent us ever trying
			 * to take action on an ignored signal other
			 * than SIGCONT, unless process is traced.
			 */
			if ((prop & SA_CONT) == 0 &&
				(p->p_lflag & P_LTRACED) == 0)
				printf("issignal\n");
			break;		/* == ignore */

		default:
			/*
			 * This signal has an action, let
			 * postsig() process it.
			 */
			return (signum);
		}
		sigbits &= ~mask;		/* take the signal! */
	}
	/* NOTREACHED */
}

/*
 * Put the argument process into the stopped state and notify the parent
 * via wakeup.  Signals are handled elsewhere.  The process must not be
 * on the run queue.
 */
static void
stop(proc_t p, proc_t parent)
{
	OSBitAndAtomic(~((uint32_t)P_CONTINUED), &p->p_flag);
	if ((parent != PROC_NULL) && (parent->p_stat != SSTOP)) {
		proc_list_lock();
		wakeup((caddr_t)parent);
		proc_list_unlock();
	}
	(void) task_suspend(p->task);	/*XXX*/
}

/*
 * Take the action for the specified signal
 * from the current set of pending signals.
 */
void
postsig(int signum)
{
	proc_t p = current_proc();
	struct sigacts *ps = p->p_sigacts;
	user_addr_t catcher;
	uint32_t code;
	int mask, returnmask;
	struct uthread * ut;

#if DIAGNOSTIC
	if (signum == 0)
		panic("postsig");
	/*
	 *	This must be called on master cpu
	 */
	if (cpu_number() != master_cpu)
		panic("psig not on master");
#endif

	proc_lock(p);
	/*
	 * Try to grab the signal lock.
	 */
	if (sig_try_locked(p) <= 0) {
		proc_unlock(p);
		return;
	}

	proc_signalstart(p, 1);

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	mask = sigmask(signum);
	ut->uu_siglist &= ~mask;
	catcher = ps->ps_sigact[signum];
	if (catcher == SIG_DFL) {
		/*
		 * Default catcher, where the default is to kill
		 * the process.  (Other cases were ignored above.)
		 */
		sig_lock_to_exit(p);
		p->p_acflag |= AXSIG;
		if (sigprop[signum] & SA_CORE) {
			p->p_sigacts->ps_sig = signum;
			proc_signalend(p, 1);
			proc_unlock(p);
			if (coredump(p) == 0)
				signum |= WCOREFLAG;
		} else  {
			proc_signalend(p, 1);
			proc_unlock(p);
		}
		
#if CONFIG_DTRACE
		bzero((caddr_t)&(ut->t_dtrace_siginfo), sizeof(ut->t_dtrace_siginfo));

		ut->t_dtrace_siginfo.si_signo = signum;
		ut->t_dtrace_siginfo.si_pid = p->si_pid;
		ut->t_dtrace_siginfo.si_uid = p->si_uid;
		ut->t_dtrace_siginfo.si_status = WEXITSTATUS(p->si_status);

		DTRACE_PROC3(signal__handle, int, signum, siginfo_t *, &(ut->t_dtrace_siginfo),
					void (*)(void), SIG_DFL);
#endif

		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_FRCEXIT) | DBG_FUNC_NONE,
					      p->p_pid, W_EXITCODE(0, signum), 3, 0, 0);
		exit1(p, W_EXITCODE(0, signum), (int *)NULL);
		return;
	} else {
		/*
		 * If we get here, the signal must be caught.
		 */
#if DIAGNOSTIC
		if (catcher == SIG_IGN || (ut->uu_sigmask & mask))
			log(LOG_WARNING,
				"postsig: processing masked or ignored signal\n");
#endif

		/*
		 * Set the new mask value and also defer further
		 * occurences of this signal.
		 *
		 * Special case: user has done a sigpause.  Here the
		 * current mask is not of interest, but rather the
		 * mask from before the sigpause is what we want
		 * restored after the signal processing is completed.
		 */
		if (ut->uu_flag & UT_SAS_OLDMASK) {
			returnmask = ut->uu_oldmask;
			ut->uu_flag &= ~UT_SAS_OLDMASK;
			ut->uu_oldmask = 0;
		} else
			returnmask = ut->uu_sigmask;
		ut->uu_sigmask |= ps->ps_catchmask[signum];
		if ((ps->ps_signodefer & mask) == 0)
			ut->uu_sigmask |= mask;
		if ((signum != SIGILL) && (signum != SIGTRAP) && (ps->ps_sigreset & mask)) {
			if ((signum != SIGCONT) && (sigprop[signum] & SA_IGNORE))
				p->p_sigignore |= mask;
			ps->ps_sigact[signum] = SIG_DFL;
			ps->ps_siginfo &= ~mask;
			ps->ps_signodefer &= ~mask;
		}
#ifdef __ppc__
		/* Needs to disable to run in user mode */
		if (signum == SIGFPE) {
			thread_enable_fpe(current_thread(), 0);
		}
#endif  /* __ppc__ */

		if (ps->ps_sig != signum) {
			code = 0;
		} else {
			code = ps->ps_code;
			ps->ps_code = 0;
		}
		OSIncrementAtomicLong(&p->p_stats->p_ru.ru_nsignals);
		sendsig(p, catcher, signum, returnmask, code);
	}
	proc_signalend(p, 1);
	proc_unlock(p);
}

/*
 * Attach a signal knote to the list of knotes for this process.
 *
 * Signal knotes share the knote list with proc knotes.  This
 * could be avoided by using a signal-specific knote list, but
 * probably isn't worth the trouble.
 */

static int
filt_sigattach(struct knote *kn)
{
	proc_t p = current_proc();  /* can attach only to oneself */

	proc_klist_lock();

	kn->kn_ptr.p_proc = p;
	kn->kn_flags |= EV_CLEAR;		/* automatically set */

	KNOTE_ATTACH(&p->p_klist, kn);

	proc_klist_unlock();

	return (0);
}

/*
 * remove the knote from the process list, if it hasn't already
 * been removed by exit processing.  
 */
	   
static void
filt_sigdetach(struct knote *kn)
{
	proc_t p = kn->kn_ptr.p_proc;

	proc_klist_lock();
	kn->kn_ptr.p_proc = NULL;
	KNOTE_DETACH(&p->p_klist, kn);
	proc_klist_unlock();
}

/*
 * Post an event to the signal filter.  Because we share the same list
 * as process knotes, we have to filter out and handle only signal events.
 *
 * We assume that we process fdfree() before we post the NOTE_EXIT for
 * a process during exit.  Therefore, since signal filters can only be
 * set up "in-process", we should have already torn down the kqueue
 * hosting the EVFILT_SIGNAL knote and should never see NOTE_EXIT.
 */
static int
filt_signal(struct knote *kn, long hint)
{

	if (hint & NOTE_SIGNAL) {
		hint &= ~NOTE_SIGNAL;

		if (kn->kn_id == (unsigned int)hint)
			kn->kn_data++;
	} else if (hint & NOTE_EXIT) {
		panic("filt_signal: detected NOTE_EXIT event");
	}

	return (kn->kn_data != 0);
}

static void
filt_signaltouch(struct knote *kn, struct kevent64_s *kev, long type)
{
	proc_klist_lock();
	switch (type) {
	case EVENT_REGISTER:
		kn->kn_sfflags = kev->fflags;
		kn->kn_sdata = kev->data;
		break;
	case EVENT_PROCESS:
		*kev = kn->kn_kevent;
		if (kn->kn_flags & EV_CLEAR) {
			kn->kn_data = 0;
			kn->kn_fflags = 0;
		}
		break;
	default:
		panic("filt_machporttouch() - invalid type (%ld)", type);
		break;
	}
	proc_klist_unlock();
}

void
bsd_ast(thread_t thread)
{
	proc_t p = current_proc();
	struct uthread *ut = get_bsdthread_info(thread);
	int	signum;
	user_addr_t pc;
	static int bsd_init_done = 0;

	if (p == NULL)
		return;

	if ((p->p_flag & P_OWEUPC) && (p->p_flag & P_PROFIL)) {
		pc = get_useraddr();
		addupc_task(p, pc, 1);
		OSBitAndAtomic(~((uint32_t)P_OWEUPC), &p->p_flag);
	}

	if (timerisset(&p->p_vtimer_user.it_value)) {
		uint32_t	microsecs;

		task_vtimer_update(p->task, TASK_VTIMER_USER, &microsecs);

		if (!itimerdecr(p, &p->p_vtimer_user, microsecs)) {
			if (timerisset(&p->p_vtimer_user.it_value))
				task_vtimer_set(p->task, TASK_VTIMER_USER);
			else
				task_vtimer_clear(p->task, TASK_VTIMER_USER);

			psignal(p, SIGVTALRM);
		}
	}

	if (timerisset(&p->p_vtimer_prof.it_value)) {
		uint32_t	microsecs;

		task_vtimer_update(p->task, TASK_VTIMER_PROF, &microsecs);

		if (!itimerdecr(p, &p->p_vtimer_prof, microsecs)) {
			if (timerisset(&p->p_vtimer_prof.it_value))
				task_vtimer_set(p->task, TASK_VTIMER_PROF);
			else
				task_vtimer_clear(p->task, TASK_VTIMER_PROF);

			psignal(p, SIGPROF);
		}
	}

	if (timerisset(&p->p_rlim_cpu)) {
		struct timeval		tv;

		task_vtimer_update(p->task, TASK_VTIMER_RLIM, (uint32_t *) &tv.tv_usec);

		proc_spinlock(p);
		if (p->p_rlim_cpu.tv_sec > 0 || p->p_rlim_cpu.tv_usec > tv.tv_usec) {
			tv.tv_sec = 0;
			timersub(&p->p_rlim_cpu, &tv, &p->p_rlim_cpu);
			proc_spinunlock(p);
		} else {

			timerclear(&p->p_rlim_cpu);
			proc_spinunlock(p);

			task_vtimer_clear(p->task, TASK_VTIMER_RLIM);

			psignal(p, SIGXCPU);
		}
	}

#if CONFIG_DTRACE
	if (ut->t_dtrace_sig) {
	    uint8_t dt_action_sig = ut->t_dtrace_sig;
	    ut->t_dtrace_sig = 0;
	    psignal(p, dt_action_sig);
	}
	if (ut->t_dtrace_stop) {
	    ut->t_dtrace_stop = 0;
	    psignal(p, SIGSTOP);
	}
#endif /* CONFIG_DTRACE */

	if (CHECK_SIGNALS(p, current_thread(), ut)) {
		while ( (signum = issignal(p)) )
			postsig(signum);
	}

	if (!bsd_init_done) {
		bsd_init_done = 1;
		bsdinit_task();
	}

}

/* ptrace set runnable */
void
pt_setrunnable(proc_t p)
{
	task_t task;

	task = p->task;

	if (p->p_lflag & P_LTRACED) {
		proc_lock(p);
		p->p_stat = SRUN;
		proc_unlock(p);
		if (p->sigwait) {
			wakeup((caddr_t)&(p->sigwait));
			if ((p->p_lflag & P_LSIGEXC) == 0) {	// 5878479
				task_release(task);
			}
		}
	}
}

kern_return_t
do_bsdexception(
	    int exc,
	    int code,
	    int sub)
{
	mach_exception_data_type_t   codes[EXCEPTION_CODE_MAX];

	codes[0] = code;	
	codes[1] = sub;
	return(bsd_exception(exc, codes, 2));
}

int
proc_pendingsignals(proc_t p, sigset_t mask)
{
	struct uthread * uth;
	thread_t th;
	sigset_t bits = 0;

	proc_lock(p);
	/* If the process is in proc exit return no signal info */
	if (p->p_lflag & P_LPEXIT)  {
		goto out;
	}

	if ((p->p_lflag & P_LINVFORK) && p->p_vforkact) {
		th = p->p_vforkact;	
		uth = (struct uthread *)get_bsdthread_info(th);
		if (uth) {
			bits = (((uth->uu_siglist & ~uth->uu_sigmask) & ~p->p_sigignore) & mask);
		}
		goto out;
	} 

	bits = 0;
	TAILQ_FOREACH(uth, &p->p_uthlist, uu_list) {
		bits |= (((uth->uu_siglist & ~uth->uu_sigmask) & ~p->p_sigignore) & mask);
	}
out:
	proc_unlock(p);
	return(bits);
}

int
thread_issignal(proc_t p, thread_t th, sigset_t mask)
{
	struct uthread * uth;
	sigset_t  bits=0;

	proc_lock(p);
	uth = (struct uthread *)get_bsdthread_info(th);
	if (uth) {
		bits = (((uth->uu_siglist & ~uth->uu_sigmask) & ~p->p_sigignore) & mask);
	}
	proc_unlock(p);
	return(bits);
}

/*
 * Allow external reads of the sigprop array.
 */
int
hassigprop(int sig, int prop)
{
	return (sigprop[sig] & prop);
}

void
pgsigio(pid_t pgid, int sig)
{ 
	proc_t p = PROC_NULL;

	if (pgid < 0) 
		gsignal(-(pgid), sig);

	else if (pgid > 0 && (p = proc_find(pgid)) != 0) 
		psignal(p, sig);
	if (p != PROC_NULL)
		proc_rele(p);
}


void
proc_signalstart(proc_t p, int locked)
{
	if (locked == 0)
		proc_lock(p);
	while ((p->p_lflag & P_LINSIGNAL) == P_LINSIGNAL) {
		p->p_lflag |= P_LSIGNALWAIT;
		msleep(&p->p_sigmask, &p->p_mlock, 0, "proc_signstart", NULL);
	}
	p->p_lflag |= P_LINSIGNAL;
#if DIAGNOSTIC
#if SIGNAL_DEBUG
#ifdef __ppc__
        {
            int  sp, *fp, numsaved; 
 
            __asm__ volatile("mr %0,r1" : "=r" (sp));

            fp = (int *)*((int *)sp);
            for (numsaved = 0; numsaved < 3; numsaved++) {
                p->lockpc[numsaved] = fp[2];
                if ((int)fp <= 0)
                        break;
                fp = (int *)*fp;
            }
        }
#endif /* __ppc__ */       
#endif /* SIGNAL_DEBUG */
#endif /* DIAGNOSTIC */
	p->p_signalholder = current_thread();
	if (locked == 0)
		proc_unlock(p);

}

void
proc_signalend(proc_t p, int locked)
{
	if (locked == 0)
		proc_lock(p);
	p->p_lflag &= ~P_LINSIGNAL;

#if DIAGNOSTIC
#if SIGNAL_DEBUG
#ifdef __ppc__
        {
            int sp, *fp, numsaved; 
 
            __asm__ volatile("mr %0,r1" : "=r" (sp));

            fp = (int *)*((int *)sp);
            for (numsaved = 0; numsaved < 3; numsaved++) {
                p->unlockpc[numsaved] = fp[2];
                if ((int)fp <= 0)
                        break;
                fp = (int *)*fp;
            }
        }
#endif /* __ppc__ */       
#endif /* SIGNAL_DEBUG */
#endif /* DIAGNOSTIC */

	if ((p->p_lflag & P_LSIGNALWAIT) == P_LSIGNALWAIT) {
		p->p_lflag &= ~P_LSIGNALWAIT;
		wakeup(&p->p_sigmask);
	}
	p->p_signalholder = NULL;
	if (locked == 0)
		proc_unlock(p);
}


void
sig_lock_to_exit(proc_t p)
{
	thread_t	self = current_thread();

	p->exit_thread = self;
	proc_unlock(p);
	(void) task_suspend(p->task);
	proc_lock(p);
}

int
sig_try_locked(proc_t p)
{
	thread_t	self = current_thread();

	while (p->sigwait || p->exit_thread) {
		if (p->exit_thread) {
			return(0);
		}
		msleep((caddr_t)&p->sigwait_thread, &p->p_mlock, PCATCH | PDROP, 0, 0);
		if (thread_should_abort(self)) {
			/*
			 * Terminate request - clean up.
			 */
			proc_lock(p);
			return -1;
		}
		proc_lock(p);
	}
	return 1;
}
