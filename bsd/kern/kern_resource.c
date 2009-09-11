/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)kern_resource.c	8.5 (Berkeley) 1/21/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/resourcevar.h>
#include <sys/malloc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <machine/spl.h>

#include <sys/mount_internal.h>
#include <sys/sysproto.h>

#include <security/audit/audit.h>

#include <machine/vmparam.h>

#include <mach/mach_types.h>
#include <mach/time_value.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>  /* for thread_policy_set( ) */
#include <kern/lock.h>
#include <kern/thread.h>

#include <kern/task.h>
#include <kern/clock.h>		/* for absolutetime_to_microtime() */
#include <netinet/in.h>		/* for TRAFFIC_MGT_SO_BACKGROUND */
#include <sys/socketvar.h>	/* for struct socket */

#include <vm/vm_map.h>

int	donice(struct proc *curp, struct proc *chgp, int n);
int	dosetrlimit(struct proc *p, u_int which, struct rlimit *limp);
static int do_background_thread(struct proc *curp, int priority);

rlim_t maxdmap = MAXDSIZ;	/* XXX */ 
rlim_t maxsmap = MAXSSIZ - PAGE_SIZE;	/* XXX */ 

/*
 * Limits on the number of open files per process, and the number
 * of child processes per process.
 *
 * Note: would be in kern/subr_param.c in FreeBSD.
 */
__private_extern__ int maxfilesperproc = OPEN_MAX;		/* per-proc open files limit */

SYSCTL_INT( _kern, KERN_MAXPROCPERUID, maxprocperuid, CTLFLAG_RW,
    		&maxprocperuid, 0, "Maximum processes allowed per userid" );

SYSCTL_INT( _kern, KERN_MAXFILESPERPROC, maxfilesperproc, CTLFLAG_RW,       
    		&maxfilesperproc, 0, "Maximum files allowed open per process" );

/* Args and fn for proc_iteration callback used in setpriority */
struct puser_nice_args {
	proc_t curp;
	int	prio;
	id_t	who;
	int *	foundp;
	int *	errorp;
};
static int puser_donice_callback(proc_t p, void * arg);


/* Args and fn for proc_iteration callback used in setpriority */
struct ppgrp_nice_args {
	proc_t curp;
	int	prio;
	int *	foundp;
	int *	errorp;
};
static int ppgrp_donice_callback(proc_t p, void * arg);

/*
 * Resource controls and accounting.
 */
int
getpriority(struct proc *curp, struct getpriority_args *uap, int32_t *retval)
{
	struct proc *p;
	int low = PRIO_MAX + 1;
	kauth_cred_t my_cred;

	/* would also test (uap->who < 0), but id_t is unsigned */
	if (uap->who > 0x7fffffff)
		return (EINVAL);

	switch (uap->which) {

	case PRIO_PROCESS:
		if (uap->who == 0) {
			p = curp;
			low = p->p_nice;
		} else {
			p = proc_find(uap->who);
			if (p == 0)
				break;
			low = p->p_nice;
			proc_rele(p);

		}
		break;

	case PRIO_PGRP: {
		struct pgrp *pg = PGRP_NULL;

		if (uap->who == 0) {
			/* returns the pgrp to ref */
			pg = proc_pgrp(curp);
		 } else if ((pg = pgfind(uap->who)) == PGRP_NULL) {
			break;
		}
		/* No need for iteration as it is a simple scan */
		pgrp_lock(pg);
		for (p = pg->pg_members.lh_first; p != 0; p = p->p_pglist.le_next) {
			if (p->p_nice < low)
				low = p->p_nice;
		}
		pgrp_unlock(pg);
		pg_rele(pg);
		break;
	}

	case PRIO_USER:
		if (uap->who == 0)
			uap->who = kauth_cred_getuid(kauth_cred_get());

		proc_list_lock();

		for (p = allproc.lh_first; p != 0; p = p->p_list.le_next) {
			my_cred = kauth_cred_proc_ref(p);
			if (kauth_cred_getuid(my_cred) == uap->who &&
			    p->p_nice < low)
				low = p->p_nice;
			kauth_cred_unref(&my_cred);
		}

		proc_list_unlock();

		break;

	case PRIO_DARWIN_THREAD: {
		thread_t			thread;
		struct uthread		*ut;

		/* we currently only support the current thread */
		if (uap->who != 0) {
			return (EINVAL);
		}
	
		thread = current_thread();
		ut = get_bsdthread_info(thread);

		low = 0;
		if ( (ut->uu_flag & UT_BACKGROUND) != 0 ) {
			low = 1;
		}
		break;
	}

	default:
		return (EINVAL);
	}
	if (low == PRIO_MAX + 1)
		return (ESRCH);
	*retval = low;
	return (0);
}

/* call back function used for proc iteration in PRIO_USER */
static int
puser_donice_callback(proc_t p, void * arg)
{
	int error, n;
	struct puser_nice_args * pun = (struct puser_nice_args *)arg;
	kauth_cred_t my_cred;

	my_cred = kauth_cred_proc_ref(p);
	if (kauth_cred_getuid(my_cred) == pun->who) {
		error = donice(pun->curp, p, pun->prio);
		if (pun->errorp != NULL)
			*pun->errorp = error;
		if (pun->foundp != NULL) {
			n = *pun->foundp;
			*pun->foundp = n+1;
		}
	}
	kauth_cred_unref(&my_cred);

	return(PROC_RETURNED);
}

/* call back function used for proc iteration in PRIO_PGRP */
static int
ppgrp_donice_callback(proc_t p, void * arg)
{
	int error;
	struct ppgrp_nice_args * pun = (struct ppgrp_nice_args *)arg;
	int n;

	error = donice(pun->curp, p, pun->prio);
	if (pun->errorp != NULL)
		*pun->errorp = error;
	if (pun->foundp!= NULL) {
		n = *pun->foundp;
		*pun->foundp = n+1;
	}

	return(PROC_RETURNED);
}

/*
 * Returns:	0			Success
 *		EINVAL
 *		ESRCH
 *	donice:EPERM
 *	donice:EACCES
 */
/* ARGSUSED */
int
setpriority(struct proc *curp, struct setpriority_args *uap, __unused int32_t *retval)
{
	struct proc *p;
	int found = 0, error = 0;
	int refheld = 0;

	AUDIT_ARG(cmd, uap->which);
	AUDIT_ARG(owner, uap->who, 0);
	AUDIT_ARG(value32, uap->prio);

	/* would also test (uap->who < 0), but id_t is unsigned */
	if (uap->who > 0x7fffffff)
		return (EINVAL);

	switch (uap->which) {

	case PRIO_PROCESS:
		if (uap->who == 0)
			p = curp;
		else {
			p = proc_find(uap->who);
			if (p == 0)
				break;
			refheld = 1;
		}
		error = donice(curp, p, uap->prio);
		found++;
		if (refheld != 0)
			proc_rele(p);
		break;

	case PRIO_PGRP: {
		struct pgrp *pg = PGRP_NULL;
		struct ppgrp_nice_args ppgrp;
		 
		if (uap->who == 0) {
			pg = proc_pgrp(curp);
		 } else if ((pg = pgfind(uap->who)) == PGRP_NULL)
			break;

		ppgrp.curp = curp;
		ppgrp.prio = uap->prio;
		ppgrp.foundp = &found;
		ppgrp.errorp = &error;
		
		/* PGRP_DROPREF drops the reference on process group */
		pgrp_iterate(pg, PGRP_DROPREF, ppgrp_donice_callback, (void *)&ppgrp, NULL, NULL);

		break;
	}

	case PRIO_USER: {
		struct puser_nice_args punice;

		if (uap->who == 0)
			uap->who = kauth_cred_getuid(kauth_cred_get());

		punice.curp = curp;
		punice.prio = uap->prio;
		punice.who = uap->who;
		punice.foundp = &found;
		error = 0;
		punice.errorp = &error;
		proc_iterate(PROC_ALLPROCLIST, puser_donice_callback, (void *)&punice, NULL, NULL);

		break;
	}

	case PRIO_DARWIN_THREAD: {
		/* we currently only support the current thread */
		if (uap->who != 0) {
			return (EINVAL);
		}
		error = do_background_thread(curp, uap->prio);
		found++;
		break;
	}

	default:
		return (EINVAL);
	}
	if (found == 0)
		return (ESRCH);
	return (error);
}


/*
 * Returns:	0			Success
 *		EPERM
 *		EACCES
 *	mac_check_proc_sched:???
 */
int
donice(struct proc *curp, struct proc *chgp, int n)
{
	int error = 0;
	kauth_cred_t ucred;
	kauth_cred_t my_cred;

	ucred = kauth_cred_proc_ref(curp);
	my_cred = kauth_cred_proc_ref(chgp);

	if (suser(ucred, NULL) && ucred->cr_ruid &&
	    kauth_cred_getuid(ucred) != kauth_cred_getuid(my_cred) &&
	    ucred->cr_ruid != kauth_cred_getuid(my_cred)) {
		error = EPERM;
		goto out;
	}
	if (n > PRIO_MAX)
		n = PRIO_MAX;
	if (n < PRIO_MIN)
		n = PRIO_MIN;
	if (n < chgp->p_nice && suser(ucred, &curp->p_acflag)) {
		error = EACCES;
		goto out;
	}
#if CONFIG_MACF
	error = mac_proc_check_sched(curp, chgp);
	if (error) 
		goto out;
#endif
	proc_lock(chgp);
	chgp->p_nice = n;
	proc_unlock(chgp);
	(void)resetpriority(chgp);
out:
	kauth_cred_unref(&ucred);
	kauth_cred_unref(&my_cred);
	return (error);
}

/*
 * do_background_thread
 * Returns:	0			Success
 * XXX - todo - does this need a MACF hook?
 */
static int
do_background_thread(struct proc *curp, int priority)
{
	int									i;
	thread_t							thread;
	struct uthread						*ut;
	thread_precedence_policy_data_t		policy;
	struct filedesc						*fdp;
	struct fileproc						*fp;
	
	thread = current_thread();
	ut = get_bsdthread_info(thread);

	if ( (priority & PRIO_DARWIN_BG) == 0 ) {
		/* turn off backgrounding of thread */
		if ( (ut->uu_flag & UT_BACKGROUND) == 0 ) {
			/* already off */
			return(0);
		}

		/* clear background bit in thread and disable disk IO throttle */
		ut->uu_flag &= ~UT_BACKGROUND;
		ut->uu_iopol_disk = IOPOL_NORMAL;

		/* reset thread priority (we did not save previous value) */
		policy.importance = 0;
		thread_policy_set( thread, THREAD_PRECEDENCE_POLICY,
						   (thread_policy_t)&policy,
						   THREAD_PRECEDENCE_POLICY_COUNT );

		/* disable networking IO throttle.
		 * NOTE - It is a known limitation of the current design that we 
		 * could potentially clear TRAFFIC_MGT_SO_BACKGROUND bit for 
		 * sockets created by other threads within this process.  
		 */
		proc_fdlock(curp);
		fdp = curp->p_fd;
		for ( i = 0; i < fdp->fd_nfiles; i++ ) {
			struct socket		*sockp;
			
			fp = fdp->fd_ofiles[ i ];
			if ( fp == NULL || (fdp->fd_ofileflags[ i ] & UF_RESERVED) != 0 || 
				 fp->f_fglob->fg_type != DTYPE_SOCKET ) {
				continue;
			}
			sockp = (struct socket *)fp->f_fglob->fg_data;
			if ( sockp->so_background_thread != thread ) {
				continue;
			}
			sockp->so_traffic_mgt_flags &= ~TRAFFIC_MGT_SO_BACKGROUND;
			sockp->so_background_thread = NULL;
		}
		proc_fdunlock(curp);

		return(0);
	}
	
	/* background this thread */
	if ( (ut->uu_flag & UT_BACKGROUND) != 0 ) {
		/* already backgrounded */
		return(0);
	}

	/* tag thread as background and throttle disk IO */
	ut->uu_flag |= UT_BACKGROUND;
	ut->uu_iopol_disk = IOPOL_THROTTLE;

	policy.importance = INT_MIN;
	thread_policy_set( thread, THREAD_PRECEDENCE_POLICY,
					   (thread_policy_t)&policy,
					   THREAD_PRECEDENCE_POLICY_COUNT );
	
	/* throttle networking IO happens in socket( ) syscall.
	 * If UT_BACKGROUND is set in the current thread then
	 * TRAFFIC_MGT_SO_BACKGROUND socket option is set.
	 */
	return(0);
}


/*
 * Returns:	0			Success
 *	copyin:EFAULT
 *	dosetrlimit:
 */
/* ARGSUSED */
int
setrlimit(struct proc *p, struct setrlimit_args *uap, __unused int32_t *retval)
{
	struct rlimit alim;
	int error;

	if ((error = copyin(uap->rlp, (caddr_t)&alim,
	    sizeof (struct rlimit))))
		return (error);

	return (dosetrlimit(p, uap->which, &alim));
}

/*
 * Returns:	0			Success
 *		EINVAL
 *		ENOMEM			Cannot copy limit structure
 *	suser:EPERM
 *
 * Notes:	EINVAL is returned both for invalid arguments, and in the
 *		case that the current usage (e.g. RLIMIT_STACK) is already
 *		in excess of the requested limit.
 */
int
dosetrlimit(struct proc *p, u_int which, struct rlimit *limp)
{
	struct rlimit *alimp;
	int error;
	kern_return_t	kr;
	int posix = (which & _RLIMIT_POSIX_FLAG) ? 1 : 0;

	/* Mask out POSIX flag, saved above */
	which &= ~_RLIMIT_POSIX_FLAG;

	if (which >= RLIM_NLIMITS)
		return (EINVAL);

	alimp = &p->p_rlimit[which];
	if (limp->rlim_cur > limp->rlim_max)
		return EINVAL;

	if (limp->rlim_cur > alimp->rlim_max || 
	    limp->rlim_max > alimp->rlim_max)
		if ((error = suser(kauth_cred_get(), &p->p_acflag))) {
			return (error);
	}

	proc_limitblock(p);

	if ((error = proc_limitreplace(p)) != 0) {
		proc_limitunblock(p);
		return(error);
	}

	alimp = &p->p_rlimit[which];
	
	switch (which) {

	case RLIMIT_CPU:
		if (limp->rlim_cur == RLIM_INFINITY) {
			task_vtimer_clear(p->task, TASK_VTIMER_RLIM);
			timerclear(&p->p_rlim_cpu);
		}
		else {
			task_absolutetime_info_data_t	tinfo;
			mach_msg_type_number_t			count;
			struct timeval					ttv, tv;
			clock_sec_t						tv_sec;
			clock_usec_t					tv_usec;

			count = TASK_ABSOLUTETIME_INFO_COUNT;
			task_info(p->task, TASK_ABSOLUTETIME_INFO,
							  	(task_info_t)&tinfo, &count);
			absolutetime_to_microtime(tinfo.total_user + tinfo.total_system,
									  &tv_sec, &tv_usec);
			ttv.tv_sec = tv_sec;
			ttv.tv_usec = tv_usec;

			tv.tv_sec = (limp->rlim_cur > __INT_MAX__ ? __INT_MAX__ : limp->rlim_cur);
			tv.tv_usec = 0;
			timersub(&tv, &ttv, &p->p_rlim_cpu);

			timerclear(&tv);
			if (timercmp(&p->p_rlim_cpu, &tv, >))
				task_vtimer_set(p->task, TASK_VTIMER_RLIM);
			else {
				task_vtimer_clear(p->task, TASK_VTIMER_RLIM);

				timerclear(&p->p_rlim_cpu);

				psignal(p, SIGXCPU);
			}
		}
		break;

	case RLIMIT_DATA:
		if (limp->rlim_cur > maxdmap)
			limp->rlim_cur = maxdmap;
		if (limp->rlim_max > maxdmap)
			limp->rlim_max = maxdmap;
		break;

	case RLIMIT_STACK:
		/* Disallow illegal stack size instead of clipping */
		if (limp->rlim_cur > maxsmap ||
		    limp->rlim_max > maxsmap) {
			if (posix) {
				error = EINVAL;
				goto out;
			}
			else {
				/* 
				 * 4797860 - workaround poorly written installers by 
				 * doing previous implementation (< 10.5) when caller 
				 * is non-POSIX conforming.
				 */
				if (limp->rlim_cur > maxsmap) 
					limp->rlim_cur = maxsmap;
				if (limp->rlim_max > maxsmap) 
					limp->rlim_max = maxsmap;
			}
		}

		/*
		 * Stack is allocated to the max at exec time with only
		 * "rlim_cur" bytes accessible.  If stack limit is going
		 * up make more accessible, if going down make inaccessible.
		 */
		if (limp->rlim_cur > alimp->rlim_cur) {
			user_addr_t addr;
			user_size_t size;
			
				/* grow stack */
				size = round_page_64(limp->rlim_cur);
				size -= round_page_64(alimp->rlim_cur);

#if STACK_GROWTH_UP
				/* go to top of current stack */
			addr = p->user_stack + round_page_64(alimp->rlim_cur);
#else	/* STACK_GROWTH_UP */
			addr = p->user_stack - round_page_64(limp->rlim_cur);
#endif /* STACK_GROWTH_UP */
			kr = mach_vm_protect(current_map(), 
					     addr, size,
					     FALSE, VM_PROT_DEFAULT);
			if (kr != KERN_SUCCESS) {
				error =  EINVAL;
				goto out;
			}
		} else if (limp->rlim_cur < alimp->rlim_cur) {
			user_addr_t addr;
			user_size_t size;
			user_addr_t cur_sp;

				/* shrink stack */

			/*
			 * First check if new stack limit would agree
			 * with current stack usage.
			 * Get the current thread's stack pointer...
			 */
			cur_sp = thread_adjuserstack(current_thread(),
						     0);
#if STACK_GROWTH_UP
			if (cur_sp >= p->user_stack &&
			    cur_sp < (p->user_stack +
				      round_page_64(alimp->rlim_cur))) {
				/* current stack pointer is in main stack */
				if (cur_sp >= (p->user_stack +
					       round_page_64(limp->rlim_cur))) {
					/*
					 * New limit would cause
					 * current usage to be invalid:
					 * reject new limit.
					 */
					error =  EINVAL;
					goto out;
			}
			} else {
				/* not on the main stack: reject */
				error =  EINVAL;
				goto out;
		}
				 
#else	/* STACK_GROWTH_UP */
			if (cur_sp <= p->user_stack &&
			    cur_sp > (p->user_stack -
				      round_page_64(alimp->rlim_cur))) {
				/* stack pointer is in main stack */
				if (cur_sp <= (p->user_stack -
					       round_page_64(limp->rlim_cur))) {
					/*
					 * New limit would cause
					 * current usage to be invalid:
					 * reject new limit.
					 */
					error =  EINVAL;
					goto out;
				}
			} else {
				/* not on the main stack: reject */
				error =  EINVAL;
				goto out;
			}
#endif	/* STACK_GROWTH_UP */
				
			size = round_page_64(alimp->rlim_cur);
			size -= round_page_64(limp->rlim_cur);

#if STACK_GROWTH_UP
			addr = p->user_stack + round_page_64(limp->rlim_cur);
#else	/* STACK_GROWTH_UP */
			addr = p->user_stack - round_page_64(alimp->rlim_cur);
#endif /* STACK_GROWTH_UP */

			kr = mach_vm_protect(current_map(),
					     addr, size,
					     FALSE, VM_PROT_NONE);
			if (kr != KERN_SUCCESS) {
				error =  EINVAL;
				goto out;
			}
		} else {
			/* no change ... */
		}
		break;

	case RLIMIT_NOFILE:
		/* 
		 * Only root can set the maxfiles limits, as it is
		 * systemwide resource.  If we are expecting POSIX behavior,
		 * instead of clamping the value, return EINVAL.  We do this
		 * because historically, people have been able to attempt to
		 * set RLIM_INFINITY to get "whatever the maximum is".
		*/
		if ( is_suser() ) {
			if (limp->rlim_cur != alimp->rlim_cur &&
			    limp->rlim_cur > (rlim_t)maxfiles) {
			    	if (posix) {
					error =  EINVAL;
					goto out;
				}
				limp->rlim_cur = maxfiles;
			}
			if (limp->rlim_max != alimp->rlim_max &&
			    limp->rlim_max > (rlim_t)maxfiles)
				limp->rlim_max = maxfiles;
		}
		else {
			if (limp->rlim_cur != alimp->rlim_cur &&
			    limp->rlim_cur > (rlim_t)maxfilesperproc) {
			    	if (posix) {
					error =  EINVAL;
					goto out;
				}
				limp->rlim_cur = maxfilesperproc;
			}
			if (limp->rlim_max != alimp->rlim_max &&
			    limp->rlim_max > (rlim_t)maxfilesperproc)
				limp->rlim_max = maxfilesperproc;
		}
		break;

	case RLIMIT_NPROC:
		/* 
		 * Only root can set to the maxproc limits, as it is
		 * systemwide resource; all others are limited to
		 * maxprocperuid (presumably less than maxproc).
		 */
		if ( is_suser() ) {
			if (limp->rlim_cur > (rlim_t)maxproc)
				limp->rlim_cur = maxproc;
			if (limp->rlim_max > (rlim_t)maxproc)
				limp->rlim_max = maxproc;
		} 
		else {
			if (limp->rlim_cur > (rlim_t)maxprocperuid)
				limp->rlim_cur = maxprocperuid;
			if (limp->rlim_max > (rlim_t)maxprocperuid)
				limp->rlim_max = maxprocperuid;
		}
		break;

	case RLIMIT_MEMLOCK:
		/*
		 * Tell the Mach VM layer about the new limit value.
		 */

		vm_map_set_user_wire_limit(current_map(), limp->rlim_cur);
		break;
		
	} /* switch... */
	proc_lock(p);
	*alimp = *limp;
	proc_unlock(p);
	error = 0;
out:
	proc_limitunblock(p);
	return (error);
}

/* ARGSUSED */
int
getrlimit(struct proc *p, struct getrlimit_args *uap, __unused int32_t *retval)
{
	struct rlimit lim;

	/*
	 * Take out flag now in case we need to use it to trigger variant
	 * behaviour later.
	 */
	uap->which &= ~_RLIMIT_POSIX_FLAG;

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	proc_limitget(p, uap->which, &lim);
	return (copyout((caddr_t)&lim,
	    		uap->rlp, sizeof (struct rlimit)));
}

/*
 * Transform the running time and tick information in proc p into user,
 * system, and interrupt time usage.
 */
/* No lock on proc is held for this.. */
void
calcru(struct proc *p, struct timeval *up, struct timeval *sp, struct timeval *ip)
{
	task_t			task;

	timerclear(up);
	timerclear(sp);
	if (ip != NULL)
		timerclear(ip);

	task = p->task;
	if (task) {
		task_basic_info_32_data_t tinfo;
		task_thread_times_info_data_t ttimesinfo;
		task_events_info_data_t teventsinfo;
		mach_msg_type_number_t task_info_count, task_ttimes_count;
		mach_msg_type_number_t task_events_count;
		struct timeval ut,st;

		task_info_count	= TASK_BASIC_INFO_32_COUNT;
		task_info(task, TASK_BASIC2_INFO_32,
			  (task_info_t)&tinfo, &task_info_count);
		ut.tv_sec = tinfo.user_time.seconds;
		ut.tv_usec = tinfo.user_time.microseconds;
		st.tv_sec = tinfo.system_time.seconds;
		st.tv_usec = tinfo.system_time.microseconds;
		timeradd(&ut, up, up);
		timeradd(&st, sp, sp);

		task_ttimes_count = TASK_THREAD_TIMES_INFO_COUNT;
		task_info(task, TASK_THREAD_TIMES_INFO,
			  (task_info_t)&ttimesinfo, &task_ttimes_count);

		ut.tv_sec = ttimesinfo.user_time.seconds;
		ut.tv_usec = ttimesinfo.user_time.microseconds;
		st.tv_sec = ttimesinfo.system_time.seconds;
		st.tv_usec = ttimesinfo.system_time.microseconds;
		timeradd(&ut, up, up);
		timeradd(&st, sp, sp);

		task_events_count = TASK_EVENTS_INFO_COUNT;
		task_info(task, TASK_EVENTS_INFO,
			  (task_info_t)&teventsinfo, &task_events_count);

		/*
		 * No need to lock "p":  this does not need to be
		 * completely consistent, right ?
		 */
		p->p_stats->p_ru.ru_minflt = (teventsinfo.faults -
					      teventsinfo.pageins);
		p->p_stats->p_ru.ru_majflt = teventsinfo.pageins;
		p->p_stats->p_ru.ru_nivcsw = (teventsinfo.csw -
					      p->p_stats->p_ru.ru_nvcsw);
		if (p->p_stats->p_ru.ru_nivcsw < 0)
			p->p_stats->p_ru.ru_nivcsw = 0;

		p->p_stats->p_ru.ru_maxrss = tinfo.resident_size;
	}
}

__private_extern__ void munge_user64_rusage(struct rusage *a_rusage_p, struct user64_rusage *a_user_rusage_p);
__private_extern__ void munge_user32_rusage(struct rusage *a_rusage_p, struct user32_rusage *a_user_rusage_p);

/* ARGSUSED */
int
getrusage(struct proc *p, struct getrusage_args *uap, __unused int32_t *retval)
{
	struct rusage *rup, rubuf;
	struct user64_rusage rubuf64;
	struct user32_rusage rubuf32;
	size_t retsize = sizeof(rubuf);			/* default: 32 bits */
	caddr_t retbuf = (caddr_t)&rubuf;		/* default: 32 bits */
	struct timeval utime;
	struct timeval stime;


	switch (uap->who) {
	case RUSAGE_SELF:
		calcru(p, &utime, &stime, NULL);
		proc_lock(p);
		rup = &p->p_stats->p_ru;
		rup->ru_utime = utime;
		rup->ru_stime = stime;

		rubuf = *rup;
		proc_unlock(p);

		break;

	case RUSAGE_CHILDREN:
		proc_lock(p);
		rup = &p->p_stats->p_cru;
		rubuf = *rup;
		proc_unlock(p);
		break;

	default:
		return (EINVAL);
	}
	if (IS_64BIT_PROCESS(p)) {
		retsize = sizeof(rubuf64);
		retbuf = (caddr_t)&rubuf64;
		munge_user64_rusage(&rubuf, &rubuf64);
	} else {
		retsize = sizeof(rubuf32);
		retbuf = (caddr_t)&rubuf32;
		munge_user32_rusage(&rubuf, &rubuf32);
	}

	return (copyout(retbuf, uap->rusage, retsize));
}

void
ruadd(struct rusage *ru, struct rusage *ru2)
{
	long *ip, *ip2;
	long i;

	timeradd(&ru->ru_utime, &ru2->ru_utime, &ru->ru_utime);
	timeradd(&ru->ru_stime, &ru2->ru_stime, &ru->ru_stime);
	if (ru->ru_maxrss < ru2->ru_maxrss)
		ru->ru_maxrss = ru2->ru_maxrss;
	ip = &ru->ru_first; ip2 = &ru2->ru_first;
	for (i = &ru->ru_last - &ru->ru_first; i >= 0; i--)
		*ip++ += *ip2++;
}

void
proc_limitget(proc_t p, int which, struct rlimit * limp)
{
	proc_list_lock();
	limp->rlim_cur = p->p_rlimit[which].rlim_cur;
	limp->rlim_max = p->p_rlimit[which].rlim_max;
	proc_list_unlock();
}


void
proc_limitdrop(proc_t p, int exiting)
{
	struct  plimit * freelim = NULL;
	struct  plimit * freeoldlim = NULL;

	proc_list_lock();

	if (--p->p_limit->pl_refcnt == 0) { 
		freelim = p->p_limit;
		p->p_limit = NULL;
	}
	if ((exiting != 0) && (p->p_olimit != NULL) && (--p->p_olimit->pl_refcnt == 0)) {
		freeoldlim =  p->p_olimit;
		p->p_olimit = NULL;
	}

	proc_list_unlock();
	if (freelim != NULL)
		FREE_ZONE(freelim, sizeof *p->p_limit, M_PLIMIT);
	if (freeoldlim != NULL)
		FREE_ZONE(freeoldlim, sizeof *p->p_olimit, M_PLIMIT);
}


void
proc_limitfork(proc_t parent, proc_t child)
{
	proc_list_lock();
	child->p_limit = parent->p_limit;
	child->p_limit->pl_refcnt++;
	child->p_olimit = NULL;
	proc_list_unlock();
}

void
proc_limitblock(proc_t p)
{
	proc_lock(p);
	while (p->p_lflag & P_LLIMCHANGE) {
		p->p_lflag |= P_LLIMWAIT;
		msleep(&p->p_olimit, &p->p_mlock, 0, "proc_limitblock", NULL);
	}
	p->p_lflag |= P_LLIMCHANGE;
	proc_unlock(p);

}


void
proc_limitunblock(proc_t p)
{
	proc_lock(p);
	p->p_lflag &= ~P_LLIMCHANGE;
	if (p->p_lflag & P_LLIMWAIT) {
		p->p_lflag &= ~P_LLIMWAIT;
		wakeup(&p->p_olimit);
	}
	proc_unlock(p);
}

/* This is called behind serialization provided by proc_limitblock/unlbock */
int
proc_limitreplace(proc_t p)
{
	struct plimit *copy;


	proc_list_lock();

	if (p->p_limit->pl_refcnt == 1) {
		proc_list_unlock();
		return(0);
	}
		
	proc_list_unlock();

	MALLOC_ZONE(copy, struct plimit *,
			sizeof(struct plimit), M_PLIMIT, M_WAITOK);
	if (copy == NULL) {
		return(ENOMEM);
	}

	proc_list_lock();
	bcopy(p->p_limit->pl_rlimit, copy->pl_rlimit,
	    sizeof(struct rlimit) * RLIM_NLIMITS);
	copy->pl_refcnt = 1;
	/* hang on to reference to old till process exits */
	p->p_olimit = p->p_limit;
	p->p_limit = copy;
	proc_list_unlock();

	return(0);
}


/*
 * iopolicysys
 *
 * Description:	System call MUX for use in manipulating I/O policy attributes of the current process or thread
 *
 * Parameters:	cmd				Policy command
 *		arg				Pointer to policy arguments
 *
 * Returns:	0				Success
 *		EINVAL				Invalid command or invalid policy arguments
 *
 */
int
iopolicysys(__unused struct proc *p, __unused struct iopolicysys_args *uap, __unused int32_t *retval)
{
	int	error = 0;
	thread_t thread = THREAD_NULL;
	int *policy;
	struct uthread	*ut = NULL;
	struct _iopol_param_t iop_param;

	if ((error = copyin(uap->arg, &iop_param, sizeof(iop_param))) != 0)
		goto exit;

	if (iop_param.iop_iotype != IOPOL_TYPE_DISK) {
		error = EINVAL;
		goto exit;
	}

	switch (iop_param.iop_scope) {
	case IOPOL_SCOPE_PROCESS:
		policy = &p->p_iopol_disk;
		break;
	case IOPOL_SCOPE_THREAD:
		thread = current_thread();
		ut = get_bsdthread_info(thread);
		policy = &ut->uu_iopol_disk;
		break;
	default:
		error = EINVAL;
		goto exit;
	}
		
	switch(uap->cmd) {
	case IOPOL_CMD_SET:
		switch (iop_param.iop_policy) {
		case IOPOL_DEFAULT:
		case IOPOL_NORMAL:
		case IOPOL_THROTTLE:
		case IOPOL_PASSIVE:
			proc_lock(p);
			*policy = iop_param.iop_policy;
			proc_unlock(p);
			break;
		default:
			error = EINVAL;
			goto exit;
		}
		break;
	case IOPOL_CMD_GET:
		switch (*policy) {
		case IOPOL_DEFAULT:
		case IOPOL_NORMAL:
		case IOPOL_THROTTLE:
		case IOPOL_PASSIVE:
			iop_param.iop_policy = *policy;
			break;
		default: // in-kernel 
			// this should never happen
			printf("%s: unknown I/O policy %d\n", __func__, *policy);
			// restore to default value
			*policy = IOPOL_DEFAULT;
			iop_param.iop_policy = *policy;
		}
		
		error = copyout((caddr_t)&iop_param, uap->arg, sizeof(iop_param));
		break;
	default:
		error = EINVAL; // unknown command
		break;
	}

  exit:
	*retval = error;
	return (error);
}


boolean_t thread_is_io_throttled(void);

boolean_t
thread_is_io_throttled(void) {

	int	policy;
	struct uthread  *ut;

	policy = current_proc()->p_iopol_disk;

	ut = get_bsdthread_info(current_thread());

	if (ut->uu_iopol_disk != IOPOL_DEFAULT)
		policy = ut->uu_iopol_disk;

	if (policy == IOPOL_THROTTLE)
		return TRUE;

	return FALSE;
}
