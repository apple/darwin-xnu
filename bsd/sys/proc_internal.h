/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1986, 1989, 1991, 1993
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
 *	@(#)proc_internal.h	8.15 (Berkeley) 5/19/95
 */

#ifndef _SYS_PROC_INTERNAL_H_
#define	_SYS_PROC_INTERNAL_H_

#include <sys/proc.h>
__BEGIN_DECLS
#include <kern/locks.h>
__END_DECLS

/*
 * One structure allocated per session.
 */
struct	session {
	int	s_count;		/* Ref cnt; pgrps in session. */
	struct	proc *s_leader;		/* Session leader. */
	struct	vnode *s_ttyvp;		/* Vnode of controlling terminal. */
	struct	tty *s_ttyp;		/* Controlling terminal. */
	pid_t	s_sid;		/* Session ID */
	char	s_login[MAXLOGNAME];	/* Setlogin() name. */
};

/*
 * One structure allocated per process group.
 */
struct	pgrp {
	LIST_ENTRY(pgrp) pg_hash;	/* Hash chain. */
	LIST_HEAD(, proc) pg_members;	/* Pointer to pgrp members. */
	struct	session *pg_session;	/* Pointer to session. */
	pid_t	pg_id;			/* Pgrp id. */
	int	pg_jobc;	/* # procs qualifying pgrp for job control */
};

struct proc;

#define PROC_NULL (struct proc *)0

#define	p_session	p_pgrp->pg_session
#define	p_pgid		p_pgrp->pg_id

/*
 * Description of a process.
 *
 * This structure contains the information needed to manage a thread of
 * control, known in UN*X as a process; it has references to substructures
 * containing descriptions of things that the process uses, but may share
 * with related processes.  The process structure and the substructures
 * are always addressible except for those marked "(PROC ONLY)" below,
 * which might be addressible only on a processor on which the process
 * is running.
 */
struct	proc {
	LIST_ENTRY(proc) p_list;	/* List of all processes. */

	/* substructures: */
	struct	ucred *p_ucred;		/* Process owner's identity. */
	struct	filedesc *p_fd;		/* Ptr to open files structure. */
	struct	pstats *p_stats;	/* Accounting/statistics (PROC ONLY). */
	struct	plimit *p_limit;	/* Process limits. */
	struct	sigacts *p_sigacts;	/* Signal actions, state (PROC ONLY). */

#define	p_rlimit	p_limit->pl_rlimit

	int	p_flag;			/* P_* flags. */
	char	p_stat;			/* S* process status. */
	char	p_shutdownstate;
	char	p_pad1[2];

	pid_t	p_pid;			/* Process identifier. */
	LIST_ENTRY(proc) p_pglist;	/* List of processes in pgrp. */
	struct	proc *p_pptr;	 	/* Pointer to parent process. */
	LIST_ENTRY(proc) p_sibling;	/* List of sibling processes. */
	LIST_HEAD(, proc) p_children;	/* Pointer to list of children. */

/* The following fields are all zeroed upon creation in fork. */
#define	p_startzero	p_oppid

	pid_t	p_oppid;	 /* Save parent pid during ptrace. XXX */
	int	p_dupfd;	 /* Sideways return value from fdopen. XXX */

	/* scheduling */
	u_int	p_estcpu;	 /* Time averaged value of p_cpticks. */
	int	p_cpticks;	 /* Ticks of cpu time. */
	fixpt_t	p_pctcpu;	 /* %cpu for this process during p_swtime */
	void	*p_wchan;	 /* Sleep address. */
	char	*p_wmesg;	 /* Reason for sleep. */
	u_int	p_swtime;	 /* DEPRECATED (Time swapped in or out.) */
#define	p_argslen p_swtime	 /* Length of process arguments. */
	u_int	p_slptime;	 /* Time since last blocked. */

	struct	itimerval p_realtimer;	/* Alarm timer. */
	struct	timeval p_rtime;	/* Real time. */
	u_quad_t p_uticks;		/* Statclock hits in user mode. */
	u_quad_t p_sticks;		/* Statclock hits in system mode. */
	u_quad_t p_iticks;		/* Statclock hits processing intr. */

	int	p_traceflag;		/* Kernel trace points. */
	struct	vnode *p_tracep;	/* Trace to vnode. */

	sigset_t p_siglist;		/* DEPRECATED. */

	struct	vnode *p_textvp;	/* Vnode of executable. */

/* End area that is zeroed on creation. */
#define	p_endzero	p_hash.le_next

	/*
	 * Not copied, not zero'ed.
	 * Belongs after p_pid, but here to avoid shifting proc elements.
	 */
	LIST_ENTRY(proc) p_hash;	/* Hash chain. */
	TAILQ_HEAD( ,eventqelt) p_evlist;

/* The following fields are all copied upon creation in fork. */
#define	p_startcopy	p_sigmask

	sigset_t p_sigmask;		/* DEPRECATED */
	sigset_t p_sigignore;	/* Signals being ignored. */
	sigset_t p_sigcatch;	/* Signals being caught by user. */

	u_char	p_priority;	/* Process priority. */
	u_char	p_usrpri;	/* User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value. */
	char	p_comm[MAXCOMLEN+1];
	char	p_name[(2*MAXCOMLEN)+1];

	struct 	pgrp *p_pgrp;	/* Pointer to process group. */

/* End area that is copied on creation. */
#define	p_endcopy	p_xstat
	
	u_short	p_xstat;	/* Exit status for wait; also stop signal. */
	u_short	p_acflag;	/* Accounting flags. */
	struct	rusage *p_ru;	/* Exit information. XXX */

	int	p_debugger;	/* 1: can exec set-bit programs if suser */

	void	*task;			/* corresponding task */
	void	*sigwait_thread;	/* 'thread' holding sigwait */
	char 	signal_lock[72];
	boolean_t	 sigwait;	/* indication to suspend */
	void	*exit_thread;		/* Which thread is exiting? */
	user_addr_t user_stack;		/* where user stack was allocated */
	void * exitarg;			/* exit arg for proc terminate */
	void * vm_shm;			/* for sysV shared memory */
	int  p_argc;			/* saved argc for sysctl_procargs() */
	int		p_vforkcnt;		/* number of outstanding vforks */
    void *  p_vforkact;     /* activation running this vfork proc */
	TAILQ_HEAD( , uthread) p_uthlist; /* List of uthreads  */
	/* Following fields are info from SIGCHLD */
	pid_t	si_pid;
	u_short si_status;
	u_short	si_code;
	uid_t	si_uid;
	TAILQ_HEAD( , aio_workq_entry ) aio_activeq; /* active async IO requests */
	int		aio_active_count;	/* entries on aio_activeq */
	TAILQ_HEAD( , aio_workq_entry ) aio_doneq;	 /* completed async IO requests */
	int		aio_done_count;		/* entries on aio_doneq */

	struct klist p_klist;  /* knote list */
	lck_mtx_t	p_mlock;	/* proc lock to protect evques */
	lck_mtx_t	p_fdmlock;	/* proc lock to protect evques */
	unsigned int p_fdlock_pc[4];
	unsigned int p_fdunlock_pc[4];
	int		p_fpdrainwait;
	unsigned int		p_lflag;		/* local flags */
	unsigned int		p_ladvflag;		/* local adv flags*/
	unsigned int		p_internalref;	/* temp refcount field */
#if DIAGNOSTIC
#if SIGNAL_DEBUG
	unsigned int lockpc[8];
	unsigned int unlockpc[8];
#endif /* SIGNAL_DEBUG */
#endif /* DIAGNOSTIC */
};


/* local flags */
#define	P_LDELAYTERM		0x1	/* */
#define	P_LNOZOMB		0x2	/* */
#define P_LLOW_PRI_IO		0x4
#define P_LPEXIT		0x8
#define P_LBACKGROUND_IO	0x10
#define P_LWAITING		0x20
#define P_LREFDRAIN		0x40
#define P_LREFDRAINWAIT		0x80
#define P_LREFDEAD		0x100
#define P_LTHSIGSTACK	0x200

/* advisory flags in the proc */
#define P_LADVLOCK		0x01

// LP64todo - should this move?
/* LP64 version of extern_proc.  all pointers 
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with extern_proc
 * but use native alignment of 64-bit process.
 */

#ifdef KERNEL
#include <sys/time.h>	/* user_timeval, user_itimerval */

struct user_extern_proc {
	union {
		struct {
			user_addr_t __p_forw;	/* Doubly-linked run/sleep queue. */
			user_addr_t __p_back;
		} p_st1;
		struct user_timeval __p_starttime; 	/* process start time */
	} p_un;
	user_addr_t 	p_vmspace;	/* Address space. */
	user_addr_t		p_sigacts;	/* Signal actions, state (PROC ONLY). */
	int		p_flag;			/* P_* flags. */
	char	p_stat;			/* S* process status. */
	pid_t	p_pid;			/* Process identifier. */
	pid_t	p_oppid;		/* Save parent pid during ptrace. XXX */
	int		p_dupfd;		/* Sideways return value from fdopen. XXX */
	/* Mach related  */
	user_addr_t user_stack __attribute((aligned(8)));	/* where user stack was allocated */
	user_addr_t exit_thread;  /* XXX Which thread is exiting? */
	int		p_debugger;		/* allow to debug */
	boolean_t	sigwait;	/* indication to suspend */
	/* scheduling */
	u_int	p_estcpu;	 /* Time averaged value of p_cpticks. */
	int		p_cpticks;	 /* Ticks of cpu time. */
	fixpt_t	p_pctcpu;	 /* %cpu for this process during p_swtime */
	user_addr_t	p_wchan __attribute((aligned(8)));	 /* Sleep address. */
	user_addr_t	p_wmesg;	 /* Reason for sleep. */
	u_int	p_swtime;	 /* Time swapped in or out. */
	u_int	p_slptime;	 /* Time since last blocked. */
	struct	user_itimerval p_realtimer;	/* Alarm timer. */
	struct	user_timeval p_rtime;	/* Real time. */
	u_quad_t p_uticks;		/* Statclock hits in user mode. */
	u_quad_t p_sticks;		/* Statclock hits in system mode. */
	u_quad_t p_iticks;		/* Statclock hits processing intr. */
	int		p_traceflag;		/* Kernel trace points. */
	user_addr_t	p_tracep __attribute((aligned(8)));	/* Trace to vnode. */
	int		p_siglist;		/* DEPRECATED */
	user_addr_t	p_textvp __attribute((aligned(8)));	/* Vnode of executable. */
	int		p_holdcnt;		/* If non-zero, don't swap. */
	sigset_t p_sigmask;	/* DEPRECATED. */
	sigset_t p_sigignore;	/* Signals being ignored. */
	sigset_t p_sigcatch;	/* Signals being caught by user. */
	u_char	p_priority;	/* Process priority. */
	u_char	p_usrpri;	/* User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value. */
	char	p_comm[MAXCOMLEN+1];
	user_addr_t	p_pgrp __attribute((aligned(8)));	/* Pointer to process group. */
	user_addr_t	p_addr;	/* Kernel virtual addr of u-area (PROC ONLY). */
	u_short	p_xstat;	/* Exit status for wait; also stop signal. */
	u_short	p_acflag;	/* Accounting flags. */
	user_addr_t	p_ru __attribute((aligned(8)));	/* Exit information. XXX */
};
#endif	/* KERNEL */

/*
 * We use process IDs <= PID_MAX; PID_MAX + 1 must also fit in a pid_t,
 * as it is used to represent "no process group".
 */
extern int nprocs, maxproc;		/* Current and max number of procs. */
extern int maxprocperuid;		/* Current number of procs per uid */
__private_extern__ int hard_maxproc;	/* hard limit */

#define	PID_MAX		30000
#define	NO_PID		30001

#define SESS_LEADER(p)	((p)->p_session->s_leader == (p))
#define	SESSHOLD(s)	((s)->s_count++)
#define	SESSRELE(s)	sessrele(s)

#define	PIDHASH(pid)	(&pidhashtbl[(pid) & pidhash])
extern LIST_HEAD(pidhashhead, proc) *pidhashtbl;
extern u_long pidhash;

#define	PGRPHASH(pgid)	(&pgrphashtbl[(pgid) & pgrphash])
extern LIST_HEAD(pgrphashhead, pgrp) *pgrphashtbl;
extern u_long pgrphash;
extern lck_grp_t * proc_lck_grp;
extern lck_grp_attr_t * proc_lck_grp_attr;
extern lck_attr_t * proc_lck_attr;

LIST_HEAD(proclist, proc);
extern struct proclist allproc;		/* List of all processes. */
extern struct proclist zombproc;	/* List of zombie processes. */
extern struct proc *initproc;
extern void	pgdelete(struct pgrp *pgrp);
extern void	sessrele(struct session *sess);
extern void	procinit(void);
extern void proc_lock(struct proc *);
extern void proc_unlock(struct proc *);
extern void proc_fdlock(struct proc *);
extern void proc_fdunlock(struct proc *);
__private_extern__ char *proc_core_name(const char *name, uid_t uid, pid_t pid);
extern int isinferior(struct proc *, struct proc *);
extern struct	proc *pfind(pid_t);	/* Find process by id. */
__private_extern__ struct proc *pzfind(pid_t);	/* Find zombie by id. */
extern struct	pgrp *pgfind(pid_t);	/* Find process group by id. */

extern int	chgproccnt(uid_t uid, int diff);
extern int	enterpgrp(struct proc *p, pid_t pgid, int mksess);
extern void	fixjobc(struct proc *p, struct pgrp *pgrp, int entering);
extern int	inferior(struct proc *p);
extern int	leavepgrp(struct proc *p);
extern void	resetpriority(struct proc *);
extern void	setrunnable(struct proc *);
extern void	setrunqueue(struct proc *);
extern int	sleep(void *chan, int pri);
extern int	tsleep0(void *chan, int pri, const char *wmesg, int timo, int (*continuation)(int));
extern int	tsleep1(void *chan, int pri, const char *wmesg, u_int64_t abstime, int (*continuation)(int));
extern int	msleep0(void *chan, lck_mtx_t *mtx, int pri, const char *wmesg, int timo, int (*continuation)(int));
extern void	vfork_return(thread_t th_act, struct proc *p, struct proc *p2, register_t *retval);
extern struct proc * proc_findref(pid_t pid);
extern void  proc_dropref(struct proc *  p);
extern struct proc * proc_refinternal(proc_t  p, int funneled);
extern void  proc_dropinternal(struct proc *  p, int funneled);

#endif	/* !_SYS_PROC_INTERNAL_H_ */
