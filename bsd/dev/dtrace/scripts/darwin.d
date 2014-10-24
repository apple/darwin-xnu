/*
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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

inline int UT_VFORK = 0x02000000;  /* thread has vfork children */
#pragma D binding "1.0" UT_VFORK

inline uthread_t uthread = (mach_kernel`uthread_t)(curthread->uthread); /* ` */
#pragma D binding "1.0" uthread

inline struct proc * curproc = 
	(uthread && (uthread->uu_flag & UT_VFORK) && uthread->uu_proc) ? (struct proc *)uthread->uu_proc :
	((struct proc *)(curthread->task->bsd_info)) != NULL ? ((struct proc *)(curthread->task->bsd_info)) : 
	mach_kernel`kernproc; /* ` */
#pragma D binding "1.0" curproc

/*
 * curthread->thread_tag will have this set if the thread is the main thread
 */   
inline uint32_t THREAD_TAG_MAINTHREAD = 0x1;
inline uint32_t THREAD_TAG_CALLOUT = 0x2;
inline uint32_t THREAD_TAG_IOWORKLOOP = 0x4;

/*
 * mach thread scheduler state
 */
inline int TH_WAIT		= 0x01;
#pragma D binding "1.0" TH_WAIT
inline int TH_SUSP		= 0x02;
#pragma D binding "1.0" TH_SUSP
inline int TH_RUN		= 0x04;
#pragma D binding "1.0" TH_RUN
inline int TH_UNINT		= 0x08;
#pragma D binding "1.0" TH_UNINT
inline int TH_TERMINATE  	= 0x10;
#pragma D binding "1.0" TH_TERMINATE
inline int TH_TERMINATE2	= 0x20;
#pragma D binding "1.0" TH_TERMINATE2
inline int TH_IDLE		= 0x80;
#pragma D binding "1.0" TH_IDLE

/*
 * The following miscellaneous constants are used by the proc(4) translators
 * defined below.
 */
inline char SIDL = 1;
#pragma D binding "1.0" SIDL
inline char SRUN = 2;
#pragma D binding "1.0" SRUN
inline char SSLEEP = 3;
#pragma D binding "1.0" SSLEEP
inline char SSTOP = 4;
#pragma D binding "1.0" SSTOP
inline char SZOMB = 5;
#pragma D binding "1.0" SZOMB
/*
 * SONPROC defined here for compatability with ported scripts
 */
inline char SONPROC = 6;
#pragma D binding "1.0" SONPROC

inline char SOBJ_NONE = 0;
#pragma D binding "1.0" SOBJ_NONE
/*
 * SOBJ_* defined here for compatability with ported scripts
 */
inline char SOBJ_MUTEX = 1;
#pragma D binding "1.0" SOBJ_MUTEX
inline char SOBJ_RWLOCK = 2;
#pragma D binding "1.0" SOBJ_RWLOCK
inline char SOBJ_CV = 3;
#pragma D binding "1.0" SOBJ_CV
inline char SOBJ_SEMA = 4;
#pragma D binding "1.0" SOBJ_SEMA
inline char SOBJ_USER = 5;
#pragma D binding "1.0" SOBJ_USER
inline char SOBJ_USER_PI = 6;
#pragma D binding "1.0" SOBJ_USER_PI
inline char SOBJ_SHUTTLE = 7;
#pragma D binding "1.0" SOBJ_SHUTTLE

inline char PR_MODEL_ILP32 = 1;
#pragma D binding "1.0" PR_MODEL_ILP32
inline char PR_MODEL_LP64 = 2;
#pragma D binding "1.0" PR_MODEL_LP64

/*
 * PR_* defined here for compatability with ported scripts
 */
inline int PR_STOPPED = 0x00000001;
#pragma D binding "1.0" PR_STOPPED
inline int PR_ISTOP = 0x00000002;
#pragma D binding "1.0" PR_ISTOP
inline int PR_DSTOP = 0x00000004;
#pragma D binding "1.0" PR_DSTOP
inline int PR_STEP = 0x00000008;
#pragma D binding "1.0" PR_STEP
inline int PR_ASLEEP = 0x00000010;
#pragma D binding "1.0" PR_ASLEEP
inline int PR_PCINVAL = 0x00000020;
#pragma D binding "1.0" PR_PCINVAL
inline int PR_ASLWP = 0x00000040;
#pragma D binding "1.0" PR_ASLWP
inline int PR_AGENT = 0x00000080;
#pragma D binding "1.0" PR_AGENT
inline int PR_DETACH = 0x00000100;
#pragma D binding "1.0" PR_DETACH
inline int PR_DAEMON = 0x00000200;
#pragma D binding "1.0" PR_DAEMON
inline int PR_ISSYS = 0x00001000;
#pragma D binding "1.0" PR_ISSYS
inline int PR_VFORKP = 0x00002000;
#pragma D binding "1.0" PR_VFORKP
inline int PR_ORPHAN = 0x00004000;
#pragma D binding "1.0" PR_ORPHAN
inline int PR_FORK = 0x00100000;
#pragma D binding "1.0" PR_FORK
inline int PR_RLC = 0x00200000;
#pragma D binding "1.0" PR_RLC
inline int PR_KLC = 0x00400000;
#pragma D binding "1.0" PR_KLC
inline int PR_ASYNC = 0x00800000;
#pragma D binding "1.0" PR_ASYNC
inline int PR_MSACCT = 0x01000000;
#pragma D binding "1.0" PR_MSACCT
inline int PR_BPTADJ = 0x02000000;
#pragma D binding "1.0" PR_BPTADJ
inline int PR_PTRACE = 0x04000000;
#pragma D binding "1.0" PR_PTRACE
inline int PR_MSFORK = 0x08000000;
#pragma D binding "1.0" PR_MSFORK
inline int PR_IDLE = 0x10000000;
#pragma D binding "1.0" PR_IDLE

/*
 * Translate from the kernel's proc_t structure to a proc(4) psinfo_t struct.
 * We do not provide support for pr_size, pr_rssize, pr_pctcpu, and pr_pctmem.
 * We also do not fill in pr_lwp (the lwpsinfo_t for the representative LWP)
 * because we do not have the ability to select and stop any representative.
 * Also, for the moment, pr_wstat, pr_time, and pr_ctime are not supported,
 * but these could be supported by DTrace in the future using subroutines.
 * Note that any member added to this translator should also be added to the
 * kthread_t-to-psinfo_t translator, below.
 */
typedef int taskid_t;
typedef int projid_t;
typedef int poolid_t;
typedef struct timespec timestruc_t; /* (SECONDS, NANOSECONDS) */

typedef struct psinfo {
	int	pr_nlwp;	/* number of active lwps in the process */
	pid_t	pr_pid;		/* unique process id */
	pid_t	pr_ppid;	/* process id of parent */
	pid_t	pr_pgid;	/* pid of process group leader */
	pid_t	pr_sid;		/* session id */
	uid_t	pr_uid;		/* real user id */
	uid_t	pr_euid;	/* effective user id */
	gid_t	pr_gid;		/* real group id */
	gid_t	pr_egid;	/* effective group id */
	uintptr_t pr_addr;	/* address of process */
	dev_t	pr_ttydev;	/* controlling tty device (or PRNODEV) */
	timestruc_t pr_start;/* process start time, DEPRECATED, see pr_start_tv below */
	char pr_fname[16];	/* name of execed file */
	char pr_psargs[80];	/* initial characters of arg list */
	int pr_argc;    	/* initial argument count */
	user_addr_t pr_argv;  /* address of initial argument vector */
	user_addr_t pr_envp;  /* address of initial environment vector */
	char    pr_dmodel;  /* data model of the process */
	taskid_t pr_taskid; /* task id */
	projid_t pr_projid; /* project id */
	poolid_t pr_poolid; /* pool id */
	zoneid_t pr_zoneid; /* zone id */

	struct timeval pr_start_tv; /* process start time, from the epoch (SECONDS, MICROSECONDS) */
} psinfo_t;

inline int P_LP64 = 0x00000004;  /* Process is LP64 */
#pragma D binding "1.0" P_LP64

#pragma D binding "1.0" translator
translator psinfo_t < struct proc * P > {
	pr_nlwp = 	((struct task *)(P->task))->thread_count;
	pr_pid = 	P->p_pid;
	pr_ppid = 	P->p_ppid;
	pr_pgid = 	P->p_pgrp->pg_id;
	pr_sid = 	P->p_pgrp->pg_session->s_sid;
 	pr_uid = 	P->p_ucred->cr_posix.cr_ruid;
 	pr_euid = 	P->p_ucred->cr_posix.cr_uid;
 	pr_gid = 	P->p_ucred->cr_posix.cr_rgid;
 	pr_egid = 	P->p_ucred->cr_posix.cr_groups[0];
	pr_addr = 	(uintptr_t)P;

	pr_ttydev = (P->p_pgrp->pg_session->s_ttyvp == NULL) ? (dev_t)-1 :
		P->p_pgrp->pg_session->s_ttyp->t_dev;

	/*
	 * timestruct_t (SECONDS, NANOSECONDS) is not available directly nor can a further translation
	 * be specified here. Zero the structure. Use pr_start_tv instead.
	 */
	pr_start = *((timestruc_t *)`dtrace_zero); /* ` */

	pr_fname = 	P->p_comm;
	pr_psargs = P->p_comm; /* XXX omits command line arguments XXX */
	pr_argc = P->p_argc;
	pr_argv = P->p_dtrace_argv;
	pr_envp = P->p_dtrace_envp;

	pr_dmodel = (P->p_flag & P_LP64) ? PR_MODEL_LP64 : PR_MODEL_ILP32;

	pr_taskid = 0;
	pr_projid = 0;
	pr_poolid = 0;
	pr_zoneid = 0;

	/*
	 * pstats->pstart is a struct timeval: (SECONDS, MICROSECONDS).
	 */
	pr_start_tv = P->p_start;
};

/*
 * Translate from the kernel's kthread_t structure to a proc(4) psinfo_t
 * struct.  Lacking a facility to define one translator only in terms of
 * another, we explicitly define each member by using the proc_t-to-psinfo_t
 * translator, above; any members added to that translator should also be
 * added here.  (The only exception to this is pr_start, which -- due to it
 * being a structure -- cannot be defined in terms of a translator at all.)
 */
#pragma D binding "1.0" translator
translator psinfo_t < thread_t T > {
	pr_nlwp = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_nlwp;
	pr_pid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_pid;
	pr_ppid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_ppid;
	pr_pgid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_pgid;
	pr_sid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_sid;
	pr_uid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_uid;
	pr_euid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_euid;
	pr_gid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_gid;
	pr_egid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_egid;
	pr_addr = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_addr;
	pr_ttydev = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_ttydev;
	pr_start = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_start; 
	pr_fname = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_fname;
	pr_psargs = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_psargs; /* XXX omits command line arguments XXX */
	pr_argc = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_argc;
	pr_argv = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_argv;
	pr_envp = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_envp;
	pr_dmodel = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_dmodel;
	pr_taskid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_taskid;
	pr_projid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_projid;
	pr_poolid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_poolid;
	pr_zoneid = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_zoneid;

	pr_start_tv = xlate <psinfo_t> ((struct proc *)(T->task->bsd_info)).pr_start_tv; 
};

/*
 * Translate from the kernel's kthread_t structure to a proc(4) lwpsinfo_t.
 * We do not provide support for pr_nice, pr_oldpri, pr_cpu, or pr_pctcpu.
 * Also, for the moment, pr_start and pr_time are not supported, but these
 * could be supported by DTrace in the future using subroutines.
 */

inline processor_t PROCESSOR_NULL = ((processor_t) 0);
#pragma D binding "1.0" PROCESSOR_NULL

typedef int psetid_t;

typedef struct lwpsinfo {
	int	pr_flag;	/* lwp flags (DEPRECATED; do not use) */
	id_t	pr_lwpid;	/* lwp id */
	uintptr_t pr_addr;	/* internal address of lwp */
	uintptr_t pr_wchan;	/* wait addr for sleeping lwp */
	char	pr_stype;	/* synchronization event type */
	char	pr_state;	/* numeric lwp state */
	char	pr_sname;	/* printable character for pr_state */
	short	pr_syscall;	/* system call number (if in syscall) */
	int	pr_pri;		/* priority, high value is high priority */
	char	pr_clname[8];	/* scheduling class name */
	int	pr_thstate;		/* mach thread scheduler state */
	processorid_t pr_onpro;		/* processor which last ran this lwp */
	processorid_t pr_bindpro;	/* processor to which lwp is bound */
	psetid_t pr_bindpset;	/* processor set to which lwp is bound */
} lwpsinfo_t;

#pragma D binding "1.0" translator
translator lwpsinfo_t < thread_t T > {
	pr_flag = 0; /* lwp flags (DEPRECATED; do not use) */
	pr_lwpid = (id_t)T->thread_id;
	pr_addr = (uintptr_t)T;
	pr_wchan = (uintptr_t)(((uthread_t)(T->uthread))->uu_wchan);

	pr_stype = SOBJ_NONE; /* XXX Undefined synch object (or none) XXX */
	pr_state = curproc->p_stat;
	pr_sname = (curproc->p_stat == SIDL) ? 'I' :
			(curproc->p_stat == SRUN) ? 'R' :
			(curproc->p_stat == SSLEEP) ? 'S' :
			(curproc->p_stat == SSTOP) ? 'T' :
			(curproc->p_stat == SZOMB) ? 'Z' : '?';

	pr_syscall = ((uthread_t)(T->uthread))->uu_code;
	pr_pri = T->sched_pri;

	pr_clname = (T->sched_mode & 0x0001) ? "RT" :
			(T->sched_mode & 0x0002) ? "TS" : "SYS";

	pr_onpro = (T->last_processor == PROCESSOR_NULL) ? -1 : T->last_processor->cpu_id;
	pr_bindpro = -1; /* Darwin does not bind threads to processors. */
	pr_bindpset = -1; /* Darwin does not partition processors. */
	pr_thstate = T->state;
};

inline psinfo_t *curpsinfo = xlate <psinfo_t *> (curproc);
#pragma D attributes Stable/Stable/Common curpsinfo
#pragma D binding "1.0" curpsinfo

inline lwpsinfo_t *curlwpsinfo = xlate <lwpsinfo_t *> (curthread);
#pragma D attributes Stable/Stable/Common curlwpsinfo
#pragma D binding "1.0" curlwpsinfo

/* XXX Really want vn_getpath(curproc->p_fd->fd_cdir, , ) but that takes namecache_rw_lock XXX */
inline string cwd = curproc->p_fd->fd_cdir->v_name == NULL ?
	"<unknown>" : stringof(curproc->p_fd->fd_cdir->v_name);
#pragma D attributes Stable/Stable/Common cwd
#pragma D binding "1.0" cwd

/* XXX Really want vn_getpath(curproc->p_fd->fd_rdir, , ) but that takes namecache_rw_lock XXX */
inline string root = curproc->p_fd->fd_rdir == NULL ? "/" :
	curproc->p_fd->fd_rdir->v_name == NULL ? "<unknown>" :
	stringof(curproc->p_fd->fd_rdir->v_name);
#pragma D attributes Stable/Stable/Common root
#pragma D binding "1.0" root
