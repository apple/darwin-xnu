/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <sys/file.h>
#include <sys/resourcevar.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <machine/spl.h>

#include <sys/mount.h>

#include <machine/vmparam.h>

#include <mach/mach_types.h>
#include <mach/time_value.h>
#include <mach/task_info.h>

#include <vm/vm_map.h>

int	donice __P((struct proc *curp, struct proc *chgp, int n));
int	dosetrlimit __P((struct proc *p, u_int which, struct rlimit *limp));

rlim_t maxdmap = MAXDSIZ;	/* XXX */ 
rlim_t maxsmap = MAXSSIZ;	/* XXX */ 

/*
 * Limits on the number of open files per process, and the number
 * of child processes per process.
 *
 * Note: would be in kern/subr_param.c in FreeBSD.
 */
int maxprocperuid = CHILD_MAX;		/* max # of procs per user */
int maxfilesperproc = OPEN_MAX;		/* per-proc open files limit */

SYSCTL_INT( _kern, KERN_MAXPROCPERUID, maxprocperuid, CTLFLAG_RW,
    		&maxprocperuid, 0, "Maximum processes allowed per userid" );

SYSCTL_INT( _kern, KERN_MAXFILESPERPROC, maxfilesperproc, CTLFLAG_RW,       
    		&maxfilesperproc, 0, "Maximum files allowed open per process" );


/*
 * Resource controls and accounting.
 */
struct getpriority_args  {
		int which;
		int who;
};
int
getpriority(curp, uap, retval)
	struct proc *curp;
	register struct getpriority_args *uap;
	register_t *retval;
{
	register struct proc *p;
	register int low = PRIO_MAX + 1;

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
			uap->who = curp->p_ucred->cr_uid;
		for (p = allproc.lh_first; p != 0; p = p->p_list.le_next)
			if (p->p_ucred->cr_uid == uap->who &&
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

struct setpriority_args {
		int which;
		int who;
		int prio;
};
/* ARGSUSED */
int
setpriority(curp, uap, retval)
	struct proc *curp;
	register struct setpriority_args *uap;
	register_t *retval;
{
	register struct proc *p;
	int found = 0, error = 0;

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
			uap->who = curp->p_ucred->cr_uid;
		for (p = allproc.lh_first; p != 0; p = p->p_list.le_next)
			if (p->p_ucred->cr_uid == uap->who) {
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
	register struct pcred *pcred = curp->p_cred;

	if (pcred->pc_ucred->cr_uid && pcred->p_ruid &&
	    pcred->pc_ucred->cr_uid != chgp->p_ucred->cr_uid &&
	    pcred->p_ruid != chgp->p_ucred->cr_uid)
		return (EPERM);
	if (n > PRIO_MAX)
		n = PRIO_MAX;
	if (n < PRIO_MIN)
		n = PRIO_MIN;
	if (n < chgp->p_nice && suser(pcred->pc_ucred, &curp->p_acflag))
		return (EACCES);
	chgp->p_nice = n;
	(void)resetpriority(chgp);
	return (0);
}

#if COMPAT_43
struct osetrlimit_args {
		u_int which;
		struct ogetrlimit * rlp;
};
/* ARGSUSED */
int
osetrlimit(p, uap, retval)
	struct proc *p;
	struct osetrlimit_args *uap;
	register_t *retval;
{
	struct orlimit olim;
	struct rlimit lim;
	int error;

	if (error = copyin((caddr_t)uap->rlp, (caddr_t)&olim,
	    sizeof (struct orlimit)))
		return (error);
	lim.rlim_cur = olim.rlim_cur;
	lim.rlim_max = olim.rlim_max;
	return (dosetrlimit(p, uap->which, &lim));
}

struct ogetrlimit_args {
		u_int which;
		struct ogetrlimit * rlp;
};
/* ARGSUSED */
int
ogetrlimit(p, uap, retval)
	struct proc *p;
	struct ogetrlimit_args *uap;
	register_t *retval;
{
	struct orlimit olim;

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	olim.rlim_cur = p->p_rlimit[uap->which].rlim_cur;
	if (olim.rlim_cur == -1)
		olim.rlim_cur = 0x7fffffff;
	olim.rlim_max = p->p_rlimit[uap->which].rlim_max;
	if (olim.rlim_max == -1)
		olim.rlim_max = 0x7fffffff;
	return (copyout((caddr_t)&olim, (caddr_t)uap->rlp,
	    sizeof(olim)));
}
#endif /* COMPAT_43 */

struct setrlimit_args {
		u_int which;
		struct rlimit * rlp;
};
/* ARGSUSED */
int
setrlimit(p, uap, retval)
	struct proc *p;
	register struct setrlimit_args *uap;
	register_t *retval;
{
	struct rlimit alim;
	int error;

	if (error = copyin((caddr_t)uap->rlp, (caddr_t)&alim,
	    sizeof (struct rlimit)))
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
	extern rlim_t maxdmap, maxsmap;
	int error;

	if (which >= RLIM_NLIMITS)
		return (EINVAL);
	alimp = &p->p_rlimit[which];
	if (limp->rlim_cur > alimp->rlim_max || 
	    limp->rlim_max > alimp->rlim_max)
		if (error = suser(p->p_ucred, &p->p_acflag))
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
			vm_offset_t addr;
			vm_size_t size;
			vm_prot_t prot;
			
			if (limp->rlim_cur > alimp->rlim_cur) {
				/* grow stack */
				size = round_page_64(limp->rlim_cur);
				size -= round_page_64(alimp->rlim_cur);

#if STACK_GROWTH_UP
				/* go to top of current stack */
				addr = trunc_page((unsigned int)(p->user_stack + alimp->rlim_cur));
#else STACK_GROWTH_UP
				addr = trunc_page_32((unsigned int)(p->user_stack - alimp->rlim_cur));
				addr -= size;
#endif /* STACK_GROWTH_UP */
				if (vm_allocate(current_map(),
						&addr, size, FALSE) != KERN_SUCCESS)
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

struct getrlimit_args {
		u_int which;
		struct rlimit * rlp;
};
/* ARGSUSED */
int
getrlimit(p, uap, retval)
	struct proc *p;
	register struct getrlimit_args *uap;
	register_t *retval;
{

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	return (copyout((caddr_t)&p->p_rlimit[uap->which],
	    (caddr_t)uap->rlp, sizeof (struct rlimit)));
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

struct getrusage_args {
		int who;
		struct rusage * rusage;
};
/* ARGSUSED */
int
getrusage(p, uap, retval)
	register struct proc *p;
	register struct getrusage_args *uap;
	register_t *retval;
{
	struct rusage *rup, rubuf;

	switch (uap->who) {

	case RUSAGE_SELF:
		rup = &p->p_stats->p_ru;
		calcru(p, &rup->ru_utime, &rup->ru_stime, NULL);
		rubuf = *rup;
		break;

	case RUSAGE_CHILDREN:
		rup = &p->p_stats->p_cru;
		rubuf = *rup;
		break;

	default:
		return (EINVAL);
	}
	return (copyout((caddr_t)&rubuf, (caddr_t)uap->rusage,
	    sizeof (struct rusage)));
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
	bcopy(lim->pl_rlimit, copy->pl_rlimit,
	    sizeof(struct rlimit) * RLIM_NLIMITS);
	copy->p_lflags = 0;
	copy->p_refcnt = 1;
	return (copy);
}
