/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
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
 *	@(#)signal.h	8.2 (Berkeley) 1/21/94
 */

#ifndef	_SYS_SIGNAL_H_
#define	_SYS_SIGNAL_H_

#include <sys/appleapiopts.h>

#if !defined(_ANSI_SOURCE) && !defined(_POSIX_SOURCE)
#define NSIG	32		/* counting 0; could be 33 (mask is 1-32) */
#endif

#include <machine/signal.h>	/* sigcontext; codes for SIGILL, SIGFPE */

#define	SIGHUP	1	/* hangup */
#define	SIGINT	2	/* interrupt */
#define	SIGQUIT	3	/* quit */
#define	SIGILL	4	/* illegal instruction (not reset when caught) */
#if  !defined(_POSIX_SOURCE)
#define	SIGTRAP	5	/* trace trap (not reset when caught) */
#endif
#define	SIGABRT	6	/* abort() */
#if  !defined(_POSIX_SOURCE)
#define	SIGIOT	SIGABRT	/* compatibility */
#define	SIGEMT	7	/* EMT instruction */
#endif
#define	SIGFPE	8	/* floating point exception */
#define	SIGKILL	9	/* kill (cannot be caught or ignored) */
#if  !defined(_POSIX_SOURCE)
#define	SIGBUS	10	/* bus error */
#endif
#define	SIGSEGV	11	/* segmentation violation */
#if  !defined(_POSIX_SOURCE)
#define	SIGSYS	12	/* bad argument to system call */
#endif
#define	SIGPIPE	13	/* write on a pipe with no one to read it */
#define	SIGALRM	14	/* alarm clock */
#define	SIGTERM	15	/* software termination signal from kill */
#if  !defined(_POSIX_SOURCE)
#define	SIGURG	16	/* urgent condition on IO channel */
#endif
#define	SIGSTOP	17	/* sendable stop signal not from tty */
#define	SIGTSTP	18	/* stop signal from tty */
#define	SIGCONT	19	/* continue a stopped process */
#define	SIGCHLD	20	/* to parent on child stop or exit */
#define	SIGTTIN	21	/* to readers pgrp upon background tty read */
#define	SIGTTOU	22	/* like TTIN for output if (tp->t_local&LTOSTOP) */
#if  !defined(_POSIX_SOURCE)
#define	SIGIO	23	/* input/output possible signal */
#define	SIGXCPU	24	/* exceeded CPU time limit */
#define	SIGXFSZ	25	/* exceeded file size limit */
#define	SIGVTALRM 26	/* virtual time alarm */
#define	SIGPROF	27	/* profiling time alarm */
#define SIGWINCH 28	/* window size changes */
#define SIGINFO	29	/* information request */
#endif
#define SIGUSR1 30	/* user defined signal 1 */
#define SIGUSR2 31	/* user defined signal 2 */

#if defined(_ANSI_SOURCE) || defined(__cplusplus)
/*
 * Language spec sez we must list exactly one parameter, even though we
 * actually supply three.  Ugh!
 */
#define	SIG_DFL		(void (*)(int))0
#define	SIG_IGN		(void (*)(int))1
#define	SIG_ERR		(void (*)(int))-1
#else
#define	SIG_DFL		(void (*)())0
#define	SIG_IGN		(void (*)())1
#define	SIG_ERR		(void (*)())-1
#endif

#ifndef _ANSI_SOURCE
#include <sys/types.h>

typedef unsigned int sigset_t;

union sigval {
	/* Members as suggested by Annex C of POSIX 1003.1b. */
	int	sigval_int;
	void	*sigval_ptr;
};

#define	SIGEV_NONE		0		/* No async notification */
#define	SIGEV_SIGNAL	1		/* aio - completion notification */
#ifdef __APPLE_API_PRIVATE
#define SIGEV_THREAD	3		/* A notification function will be called to perform notification */
#endif /*__APPLE_API_PRIVATE */

struct sigevent {
	int				sigev_notify;				/* Notification type */
	int				sigev_signo;				/* Signal number */
	union sigval	sigev_value;				/* Signal value */
	void			(*sigev_notify_function)(union sigval);	  /* Notification function */
	pthread_attr_t	*sigev_notify_attributes;	/* Notification attributes */
};

typedef struct __siginfo {
	int	si_signo;		/* signal number */
	int	si_errno;		/* errno association */
	int	si_code;		/* signal code */
	int	si_pid;			/* sending process */
	unsigned int si_uid;		/* sender's ruid */
	int	si_status;		/* exit value */
	void	*si_addr;		/* faulting instruction */
	union sigval si_value;		/* signal value */
	long	si_band;		/* band event for SIGPOLL */
	unsigned int	pad[7];		/* Reserved for Future Use */
} siginfo_t;

/* 
 * Incase of SIGILL and SIGFPE, si_addr contains the address of 
 *  faulting instruction.
 * Incase of SIGSEGV and SIGBUS, si_addr contains address of 
 *  faulting memory reference.
 * Incase of SIGCHLD, si_pid willhave child process ID,
 *  si_status will contain exit value or signal.
 *  si_uid contains real user ID of the process that sent the signal
 */

/* Values for si_code */

/* Codes for SIGILL */
#define	ILL_NOOP	0	/* if only I knew... */
#define	ILL_ILLOPC	1	/* illegal opcode */
#define	ILL_ILLTRP	2	/* illegal trap */
#define	ILL_PRVOPC	3	/* privileged opcode */

/* Codes for SIGFPE */
#define	FPE_NOOP	0	/* if only I knew... */
#define FPE_FLTDIV	1	/* floating point divide by zero */
#define FPE_FLTOVF	2	/* floating point overflow */
#define FPE_FLTUND	3	/* floating point underflow */
#define FPE_FLTRES	4	/* floating point inexact result */
#define FPE_FLTINV	5	/* invalid floating point operation */

/* Codes for SIGSEGV */
#define	SEGV_NOOP	0	/* if only I knew... */
#define	SEGV_MAPERR	1	/* address not mapped to object */
#define	SEGV_ACCERR	2	/* invalid permissions for mapped to object */

/* Codes for SIGBUS */
#define	BUS_NOOP	0	/* if only I knew... */
#define	BUS_ADRALN	1	/* invalid address alignment */

/* Codes for SIGCHLD */
#define	CLD_NOOP	0	/* if only I knew... */
#define	CLD_EXITED	1	/* child has exited */
#define	CLD_KILLED	2	
	/* child has terminated abnormally and did not create a core file */
#define	CLD_DUMPED	3	
	/* child has terminated abnormally and create a core file */
#define	CLD_TRAPPED	4	/* traced child has trapped */
#define	CLD_STOPPED	5	/* child has stopped */
#define	CLD_CONTINUED	6	/* stopped child has continued */

/* union for signal handlers */
union __sigaction_u {
	void    (*__sa_handler)(int);
	void    (*__sa_sigaction)(int, struct __siginfo *,
		       void *);
};

/* Signal vector template for Kernel user boundary */
struct	__sigaction {
	union __sigaction_u __sigaction_u;  /* signal handler */
	void    (*sa_tramp)(void *, int, int, siginfo_t *, void *);
	sigset_t sa_mask;		/* signal mask to apply */
	int	sa_flags;		/* see signal options below */
};

/*
 * Signal vector "template" used in sigaction call.
 */
struct	sigaction {
	union __sigaction_u __sigaction_u;  /* signal handler */
	sigset_t sa_mask;		/* signal mask to apply */
	int	sa_flags;		/* see signal options below */
};
/* if SA_SIGINFO is set, sa_sigaction is to be used instead of sa_handler. */
#define	sa_handler	__sigaction_u.__sa_handler
#define	sa_sigaction	__sigaction_u.__sa_sigaction


#if  !defined(_POSIX_SOURCE)
#define SA_ONSTACK	0x0001	/* take signal on signal stack */
#define SA_RESTART	0x0002	/* restart system on signal return */
#define	SA_DISABLE	0x0004	/* disable taking signals on alternate stack */
#define	SA_RESETHAND	0x0004	/* reset to SIG_DFL when taking signal */
#define	SA_NODEFER	0x0010	/* don't mask the signal we're delivering */
#define	SA_NOCLDWAIT	0x0020	/* don't keep zombies around */
#define	SA_SIGINFO	0x0040	/* signal handler with SA_SIGINFO args */
#define	SA_USERTRAMP	0x0100	/* do not bounce off kernel's sigtramp */
/* This will provide 64bit register set in a 32bit user address space */
#define	SA_64REGSET	0x0200	/* signal handler with SA_SIGINFO args with 64bit regs information */
#endif
#define SA_NOCLDSTOP	0x0008	/* do not generate SIGCHLD on child stop */

/*
 * Flags for sigprocmask:
 */
#define	SIG_BLOCK	1	/* block specified signal set */
#define	SIG_UNBLOCK	2	/* unblock specified signal set */
#define	SIG_SETMASK	3	/* set specified signal set */

/* POSIX 1003.1b required values. */
#define SI_USER		0x10001
#define SI_QUEUE	0x10002
#define SI_TIMER	0x10003
#define SI_ASYNCIO	0x10004
#define SI_MESGQ	0x10005

#if !defined(_POSIX_SOURCE)
#include <sys/cdefs.h>
typedef	void (*sig_t) __P((int));	/* type of signal function */

/*
 * Structure used in sigaltstack call.
 */
struct	sigaltstack {
	char	*ss_sp;		/* signal stack base */
	int	ss_size;		/* signal stack length */
	int	ss_flags;		/* SA_DISABLE and/or SA_ONSTACK */
};

typedef struct  sigaltstack stack_t;

#define SS_ONSTACK	0x0001	/* take signal on signal stack */
#define	SS_DISABLE	0x0004	/* disable taking signals on alternate stack */
#define	MINSIGSTKSZ	32768	/* (32K)minimum allowable stack */
#define	SIGSTKSZ	131072	/* (128K)recommended stack size */

/*
 * 4.3 compatibility:
 * Signal vector "template" used in sigvec call.
 */
struct	sigvec {
	void	(*sv_handler)(int);	/* signal handler */
	int	sv_mask;		/* signal mask to apply */
	int	sv_flags;		/* see signal options below */
};

#define SV_ONSTACK	SA_ONSTACK
#define SV_INTERRUPT	SA_RESTART	/* same bit, opposite sense */
#define SV_RESETHAND	SA_RESETHAND
#define SV_NODEFER	SA_NODEFER
#define SV_NOCLDSTOP	SA_NOCLDSTOP
#define SV_SIGINFO	SA_SIGINFO

#define sv_onstack sv_flags	/* isn't compatibility wonderful! */

/*
 * Structure used in sigstack call.
 */
struct	sigstack {
	char	*ss_sp;			/* signal stack pointer */
	int	ss_onstack;		/* current status */
};

/*
 * Macro for converting signal number to a mask suitable for
 * sigblock().
 */
#define sigmask(m)	(1 << ((m)-1))

#ifdef	KERNEL
#ifdef __APPLE_API_PRIVATE
/*
 *	signals delivered on a per-thread basis.
 */
#define threadmask (sigmask(SIGILL)|sigmask(SIGTRAP)|\
		    sigmask(SIGIOT)|sigmask(SIGEMT)|\
		    sigmask(SIGFPE)|sigmask(SIGBUS)|\
		    sigmask(SIGSEGV)|sigmask(SIGSYS)|\
		    sigmask(SIGPIPE))
#endif /* __APPLE_API_PRIVATE */
#endif	/* KERNEL */

#define	BADSIG		SIG_ERR

#endif	/* !_POSIX_SOURCE */
#endif	/* !_ANSI_SOURCE */

/*
 * For historical reasons; programs expect signal's return value to be
 * defined by <sys/signal.h>.
 */
__BEGIN_DECLS
void	(*signal __P((int, void (*) __P((int))))) __P((int));
__END_DECLS
#endif	/* !_SYS_SIGNAL_H_ */
