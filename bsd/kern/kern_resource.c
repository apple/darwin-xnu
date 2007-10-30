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

#include <bsm/audit_kernel.h>

#include <machine/vmparam.h>

#include <mach/mach_types.h>
#include <mach/time_value.h>
#include <mach/task_info.h>
#include <mach/vm_map.h>

#include <vm/vm_map.h>

int	donice(struct proc *curp, struct proc *chgp, int n);
int	dosetrlimit(struct proc *p, u_int which, struct rlimit *limp);

rlim_t maxdmap = MAXDSIZ;	/* XXX */ 
rlim_t maxsmap = MAXSSIZ;	/* XXX */ 

/*
 * Limits on the number of open files per process, and the number
 * of child processes per process.
 *
 * Note: would be in kern/subr_param.c in FreeBSD.
 */
extern int maxprocperuid;		/* max # of procs per user */
int maxfilesperproc = OPEN_MAX;		/* per-proc open files limit */

SYSCTL_INT( _kern, KERN_MAXPROCPERUID, maxprocperuid, CTLFLAG_RW,
    		&maxprocperuid, 0, "Maximum processes allowed per userid" );

SYSCTL_INT( _kern, KERN_MAXFILESPERPROC, maxfilesperproc, CTLFLAG_RW,       
    		&maxfilesperproc, 0, "Maximum files allowed open per process" );


/*
 * Resource controls and accounting.
 */
int
getpriority(struct proc *curp, struct getpriority_args *uap, register_t *retval)
{
	register struct proc *p;
	register int low = PRIO_MAX + 1;

	if (uap->who < 0)
		return (EINVAL);

	switch (uap->which) {

	case PRIO_PROCESS:
		if (uap->who == 0)
			p = curp;
		else
			p = pfind(uap->who);
		if (p == 0)
			break;
		low = p->p_nice;
		break;

	case PRIO_PGRP: {
		register struct pgrp *pg;

		if (uap->who == 0)
			pg = curp->p_pgrp;
		else if ((pg = pgfind(uap->who)) == NULL)
			break;
		for (p = pg->pg_members.lh_first; p != 0; p = p->p_pglist.le_next) {
			if (p->p_nice < low)
				low = p->p_nice;
		}
		break;
	}

	case PRIO_USER:
		if (uap->who == 0)
			uap->who = kauth_cred_getuid(kauth_cred_get());
		for (p = allproc.lh_first; p != 0; p = p->p_list.le_next)
			if (kauth_cred_getuid(p->p_ucred) == uap->who &&
			    p->p_nice < low)
				low = p->p_nice;
		break;

	default:
		return (EINVAL);
	}
	if (low == PRIO_MAX + 1)
		return (ESRCH);
	*retval = low;
	return (0);
}

/* ARGSUSED */
int
setpriority(struct proc *curp, struct setpriority_args *uap, __unused register_t *retval)
{
	register struct proc *p;
	int found = 0, error = 0;

	AUDIT_ARG(cmd, uap->which);
	AUDIT_ARG(owner, uap->who, 0);
	AUDIT_ARG(value, uap->prio);

	if (uap->who < 0)
		return (EINVAL);

	switch (uap->which) {

	case PRIO_PROCESS:
		if (uap->who == 0)
			p = curp;
		else
			p = pfind(uap->who);
		if (p == 0)
			break;
		error = donice(curp, p, uap->prio);
		found++;
		break;

	case PRIO_PGRP: {
		register struct pgrp *pg;
		 
		if (uap->who == 0)
			pg = curp->p_pgrp;
		else if ((pg = pgfind(uap->who)) == NULL)
			break;
		for (p = pg->pg_members.lh_first; p != 0;
		    p = p->p_pglist.le_next) {
			error = donice(curp, p, uap->prio);
			found++;
		}
		break;
	}

	case PRIO_USER:
		if (uap->who == 0)
			uap->who = kauth_cred_getuid(kauth_cred_get());
		for (p = allproc.lh_first; p != 0; p = p->p_list.le_next)
			if (kauth_cred_getuid(p->p_ucred) == uap->who) {
				error = donice(curp, p, uap->prio);
				found++;
			}
		break;

	default:
		return (EINVAL);
	}
	if (found == 0)
		return (ESRCH);
	return (error);
}

int
donice(curp, chgp, n)
	register struct proc *curp, *chgp;
	register int n;
{
	kauth_cred_t ucred = curp->p_ucred;

	if (suser(ucred, NULL) && ucred->cr_ruid &&
	    kauth_cred_getuid(ucred) != kauth_cred_getuid(chgp->p_ucred) &&
	    ucred->cr_ruid != kauth_cred_getuid(chgp->p_ucred))
		return (EPERM);
	if (n > PRIO_MAX)
		n = PRIO_MAX;
	if (n < PRIO_MIN)
		n = PRIO_MIN;
	if (n < chgp->p_nice && suser(ucred, &curp->p_acflag))
		return (EACCES);
	chgp->p_nice = n;
	(void)resetpriority(chgp);
	return (0);
}


/* ARGSUSED */
int
setrlimit(struct proc *p, register struct setrlimit_args *uap, __unused register_t *retval)
{
	struct rlimit alim;
	int error;

	if ((error = copyin(uap->rlp, (caddr_t)&alim,
	    sizeof (struct rlimit))))
		return (error);
	return (dosetrlimit(p, uap->which, &alim));
}

int
dosetrlimit(p, which, limp)
	struct proc *p;
	u_int which;
	struct rlimit *limp;
{
	register struct rlimit *alimp;
	int error;

	if (which >= RLIM_NLIMITS)
		return (EINVAL);
	alimp = &p->p_rlimit[which];
	if (limp->rlim_cur > alimp->rlim_max || 
	    limp->rlim_max > alimp->rlim_max)
		if ((error = suser(kauth_cred_get(), &p->p_acflag)))
			return (error);
	if (limp->rlim_cur > limp->rlim_max)
		limp->rlim_cur = limp->rlim_max;
	if (p->p_limit->p_refcnt > 1 &&
	    (p->p_limit->p_lflags & PL_SHAREMOD) == 0) {
		p->p_limit->p_refcnt--;
		p->p_limit = limcopy(p->p_limit);
		alimp = &p->p_rlimit[which];
	}

	switch (which) {

	case RLIMIT_DATA:
		if (limp->rlim_cur > maxdmap)
			limp->rlim_cur = maxdmap;
		if (limp->rlim_max > maxdmap)
			limp->rlim_max = maxdmap;
		break;

	case RLIMIT_STACK:
		if (limp->rlim_cur > maxsmap)
			limp->rlim_cur = maxsmap;
		if (limp->rlim_max > maxsmap)
			limp->rlim_max = maxsmap;
		/*
		 * Stack is allocated to the max at exec time with only
		 * "rlim_cur" bytes accessible.  If stack limit is going
		 * up make more accessible, if going down make inaccessible.
		 */
		if (limp->rlim_cur != alimp->rlim_cur) {
			user_addr_t addr;
			user_size_t size;
			
			if (limp->rlim_cur > alimp->rlim_cur) {
				/* grow stack */
				size = round_page_64(limp->rlim_cur);
				size -= round_page_64(alimp->rlim_cur);

#if STACK_GROWTH_UP
				/* go to top of current stack */
				addr = p->user_stack + alimp->rlim_cur;
#else STACK_GROWTH_UP
				addr = p->user_stack - alimp->rlim_cur;
				addr -= size;
#endif /* STACK_GROWTH_UP */
				if (mach_vm_allocate(current_map(), 
						     &addr, size,
						     VM_FLAGS_FIXED) != KERN_SUCCESS)
					return(EINVAL);
			} else {
				/* shrink stack */
			}
		}
		break;

	case RLIMIT_NOFILE:
		/* 
		* Only root can set the maxfiles limits, as it is systemwide resource
		*/
		if ( is_suser() ) {
			if (limp->rlim_cur > maxfiles)
				limp->rlim_cur = maxfiles;
			if (limp->rlim_max > maxfiles)
				limp->rlim_max = maxfiles;
		}
		else {
			if (limp->rlim_cur > maxfilesperproc)
				limp->rlim_cur = maxfilesperproc;
			if (limp->rlim_max > maxfilesperproc)
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
			if (limp->rlim_cur > maxproc)
				limp->rlim_cur = maxproc;
			if (limp->rlim_max > maxproc)
				limp->rlim_max = maxproc;
		} 
		else {
			if (limp->rlim_cur > maxprocperuid)
				limp->rlim_cur = maxprocperuid;
			if (limp->rlim_max > maxprocperuid)
				limp->rlim_max = maxprocperuid;
		}
		break;
		
	} /* switch... */
	*alimp = *limp;
	return (0);
}

/* ARGSUSED */
int
getrlimit(struct proc *p, register struct getrlimit_args *uap, __unused register_t *retval)
{
	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	return (copyout((caddr_t)&p->p_rlimit[uap->which],
	    		uap->rlp, sizeof (struct rlimit)));
}

/*
 * Transform the running time and tick information in proc p into user,
 * system, and interrupt time usage.
 */
void
calcru(p, up, sp, ip)
	register struct proc *p;
	register struct timeval *up;
	register struct timeval *sp;
	register struct timeval *ip;
{
	task_t			task;

	timerclear(up);
	timerclear(sp);
	if (ip != NULL)
		timerclear(ip);

	task = p->task;
	if (task) {
		task_basic_info_data_t tinfo;
		task_thread_times_info_data_t ttimesinfo;
		int task_info_stuff, task_ttimes_stuff;
		struct timeval ut,st;

		task_info_stuff	= TASK_BASIC_INFO_COUNT;
		task_info(task, TASK_BASIC_INFO,
			  &tinfo, &task_info_stuff);
		ut.tv_sec = tinfo.user_time.seconds;
		ut.tv_usec = tinfo.user_time.microseconds;
		st.tv_sec = tinfo.system_time.seconds;
		st.tv_usec = tinfo.system_time.microseconds;
		timeradd(&ut, up, up);
		timeradd(&st, sp, sp);

		task_ttimes_stuff = TASK_THREAD_TIMES_INFO_COUNT;
		task_info(task, TASK_THREAD_TIMES_INFO,
			  &ttimesinfo, &task_ttimes_stuff);

		ut.tv_sec = ttimesinfo.user_time.seconds;
		ut.tv_usec = ttimesinfo.user_time.microseconds;
		st.tv_sec = ttimesinfo.system_time.seconds;
		st.tv_usec = ttimesinfo.system_time.microseconds;
		timeradd(&ut, up, up);
		timeradd(&st, sp, sp);
	}
}

__private_extern__ void munge_rusage(struct rusage *a_rusage_p, struct user_rusage *a_user_rusage_p);

/* ARGSUSED */
int
getrusage(register struct proc *p, register struct getrusage_args *uap, __unused register_t *retval)
{
	struct rusage *rup, rubuf;
	struct user_rusage rubuf64;
	size_t retsize = sizeof(rubuf);			/* default: 32 bits */
	caddr_t retbuf = (caddr_t)&rubuf;		/* default: 32 bits */

	switch (uap->who) {
	case RUSAGE_SELF:
		rup = &p->p_stats->p_ru;
		calcru(p, &rup->ru_utime, &rup->ru_stime, NULL);
		// LP64todo: proc struct should have 64 bit version of struct
		rubuf = *rup;
		break;

	case RUSAGE_CHILDREN:
		rup = &p->p_stats->p_cru;
		rubuf = *rup;
		break;

	default:
		return (EINVAL);
	}
	if (IS_64BIT_PROCESS(p)) {
		retsize = sizeof(rubuf64);
		retbuf = (caddr_t)&rubuf64;
		munge_rusage(&rubuf, &rubuf64);
	}
	return (copyout(retbuf, uap->rusage, retsize));
}

void
ruadd(ru, ru2)
	register struct rusage *ru, *ru2;
{
	register long *ip, *ip2;
	register int i;

	timeradd(&ru->ru_utime, &ru2->ru_utime, &ru->ru_utime);
	timeradd(&ru->ru_stime, &ru2->ru_stime, &ru->ru_stime);
	if (ru->ru_maxrss < ru2->ru_maxrss)
		ru->ru_maxrss = ru2->ru_maxrss;
	ip = &ru->ru_first; ip2 = &ru2->ru_first;
	for (i = &ru->ru_last - &ru->ru_first; i >= 0; i--)
		*ip++ += *ip2++;
}

/*
 * Make a copy of the plimit structure.
 * We share these structures copy-on-write after fork,
 * and copy when a limit is changed.
 */
struct plimit *
limcopy(lim)
	struct plimit *lim;
{
	register struct plimit *copy;

	MALLOC_ZONE(copy, struct plimit *,
			sizeof(struct plimit), M_SUBPROC, M_WAITOK);
	if (copy == NULL)
		panic("limcopy");
	bcopy(lim->pl_rlimit, copy->pl_rlimit,
	    sizeof(struct rlimit) * RLIM_NLIMITS);
	copy->p_lflags = 0;
	copy->p_refcnt = 1;
	return (copy);
}
