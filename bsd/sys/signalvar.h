/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)signalvar.h	8.3 (Berkeley) 1/4/94
 */

#ifndef	_SYS_SIGNALVAR_H_		/* tmp for user.h */
#define	_SYS_SIGNALVAR_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
/*
 * Kernel signal definitions and data structures,
 * not exported to user programs.
 */

/*
 * Process signal actions and state, needed only within the process
 * (not necessarily resident).
 */
struct	sigacts {
	sig_t	ps_sigact[NSIG];	/* disposition of signals */
	sig_t 	ps_trampact[NSIG];	/* disposition of signals */
	sigset_t ps_catchmask[NSIG];	/* signals to be blocked */
	sigset_t ps_sigonstack;		/* signals to take on sigstack */
	sigset_t ps_sigintr;		/* signals that interrupt syscalls */
	sigset_t ps_sigreset;		/* signals that reset when caught */
	sigset_t ps_signodefer;		/* signals not masked while handled */
	sigset_t ps_siginfo;		/* signals that want SA_SIGINFO args */
	sigset_t ps_oldmask;		/* saved mask from before sigpause */
	int	ps_flags;		/* signal flags, below */
	struct	sigaltstack ps_sigstk;	/* sp & on stack state variable */
	int	ps_sig;			/* for core dump/debugger XXX */
	int	ps_code;		/* for core dump/debugger XXX */
	int	ps_addr;		/* for core dump/debugger XXX */
	sigset_t ps_usertramp;		/* SunOS compat; libc sigtramp XXX */
};

/* signal flags */
#define	SAS_OLDMASK	0x01		/* need to restore mask before pause */
#define	SAS_ALTSTACK	0x02		/* have alternate signal stack */

/* additional signal action values, used only temporarily/internally */
#define	SIG_CATCH	(void (*)())2
#define	SIG_HOLD	(void (*)())3
#define	SIG_WAIT	(void (*)())4

#define pgsigio(pgid, sig, notused) \
	{ \
	struct proc *p; \
	if (pgid < 0) \
		gsignal(-(pgid), sig);\
	else if (pgid > 0 && (p = pfind(pgid)) != 0) \
		psignal(p, sig); \
}

/*
 * get signal action for process and signal; currently only for current process
 */
#define SIGACTION(p, sig)	(p->p_sigacts->ps_sigact[(sig)])

/*
 *	Check for per-process and per thread signals.
 */
#define SHOULDissignal(p,uthreadp) \
	 (((uthreadp)->uu_siglist)	\
	  & ~((((uthreadp)->uu_sigmask) \
	       | (((p)->p_flag & P_TRACED) ? 0 : (p)->p_sigignore)) \
	      & ~sigcantmask))

/*
 *	Check for signals and per-thread signals.  
 *  Use in trap() and syscall() before
 *	exiting kernel.
 */
#define	CHECK_SIGNALS(p, thread, uthreadp)	\
	(!thread_should_halt(thread)	\
	 && (SHOULDissignal(p,uthreadp)))

/*
 * Signal properties and actions.
 * The array below categorizes the signals and their default actions
 * according to the following properties:
 */
#define	SA_KILL		0x01		/* terminates process by default */
#define	SA_CORE		0x02		/* ditto and coredumps */
#define	SA_STOP		0x04		/* suspend process */
#define	SA_TTYSTOP	0x08		/* ditto, from tty */
#define	SA_IGNORE	0x10		/* ignore by default */
#define	SA_CONT		0x20		/* continue if suspended */
#define	SA_CANTMASK	0x40		/* non-maskable, catchable */

#ifdef	SIGPROP
int sigprop[NSIG + 1] = {
	0,			/* unused */
	SA_KILL,		/* SIGHUP */
	SA_KILL,		/* SIGINT */
	SA_KILL|SA_CORE,	/* SIGQUIT */
	SA_KILL|SA_CORE,	/* SIGILL */
	SA_KILL|SA_CORE,	/* SIGTRAP */
	SA_KILL|SA_CORE,	/* SIGABRT */
	SA_KILL|SA_CORE,	/* SIGEMT */
	SA_KILL|SA_CORE,	/* SIGFPE */
	SA_KILL,		/* SIGKILL */
	SA_KILL|SA_CORE,	/* SIGBUS */
	SA_KILL|SA_CORE,	/* SIGSEGV */
	SA_KILL|SA_CORE,	/* SIGSYS */
	SA_KILL,		/* SIGPIPE */
	SA_KILL,		/* SIGALRM */
	SA_KILL,		/* SIGTERM */
	SA_IGNORE,		/* SIGURG */
	SA_STOP,		/* SIGSTOP */
	SA_STOP|SA_TTYSTOP,	/* SIGTSTP */
	SA_IGNORE|SA_CONT,	/* SIGCONT */
	SA_IGNORE,		/* SIGCHLD */
	SA_STOP|SA_TTYSTOP,	/* SIGTTIN */
	SA_STOP|SA_TTYSTOP,	/* SIGTTOU */
	SA_IGNORE,		/* SIGIO */
	SA_KILL,		/* SIGXCPU */
	SA_KILL,		/* SIGXFSZ */
	SA_KILL,		/* SIGVTALRM */
	SA_KILL,		/* SIGPROF */
	SA_IGNORE,		/* SIGWINCH  */
	SA_IGNORE,		/* SIGINFO */
	SA_KILL,		/* SIGUSR1 */
	SA_KILL,		/* SIGUSR2 */
};

#define	contsigmask	(sigmask(SIGCONT))
#define	stopsigmask	(sigmask(SIGSTOP) | sigmask(SIGTSTP) | \
			    sigmask(SIGTTIN) | sigmask(SIGTTOU))

#endif /* SIGPROP */

#define	sigcantmask	(sigmask(SIGKILL) | sigmask(SIGSTOP))

#ifdef KERNEL
/*
 * Machine-independent functions:
 */
int	coredump __P((struct proc *p));
void	execsigs __P((struct proc *p, thread_act_t thr_act));
void	gsignal __P((int pgid, int sig));
int	issignal __P((struct proc *p));
int	CURSIG __P((struct proc *p));
int clear_procsiglist __P((struct proc *p, int bit));
int clear_procsigmask __P((struct proc *p, int bit));
int set_procsigmask __P((struct proc *p, int bit));
void	tty_pgsignal __P((struct pgrp *pgrp, int sig));
void	postsig __P((int sig));
void	siginit __P((struct proc *p));
void	trapsignal __P((struct proc *p, int sig, unsigned code));
void	pt_setrunnable __P((struct proc *p));

/*
 * Machine-dependent functions:
 */
void	sendsig __P((struct proc *, sig_t action, int sig,
	int returnmask, u_long code));

#ifdef __APPLE_API_UNSTABLE
void	psignal __P((struct proc *p, int sig));
void	pgsignal __P((struct pgrp *pgrp, int sig, int checkctty));
#endif /* __APPLE_API_UNSTABLE */

#endif	/* KERNEL */

#endif /* __APPLE_API_PRIVATE */

#endif	/* !_SYS_SIGNALVAR_H_ */
