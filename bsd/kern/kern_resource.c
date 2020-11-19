/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
#include <kern/thread.h>
#include <kern/policy_internal.h>

#include <kern/task.h>
#include <kern/clock.h>         /* for absolutetime_to_microtime() */
#include <netinet/in.h>         /* for TRAFFIC_MGT_SO_* */
#include <sys/socketvar.h>      /* for struct socket */
#if NECP
#include <net/necp.h>
#endif /* NECP */

#include <vm/vm_map.h>

#include <kern/assert.h>
#include <sys/resource.h>
#include <sys/priv.h>
#include <IOKit/IOBSD.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

int     donice(struct proc *curp, struct proc *chgp, int n);
int     dosetrlimit(struct proc *p, u_int which, struct rlimit *limp);
int     uthread_get_background_state(uthread_t);
static void do_background_socket(struct proc *p, thread_t thread);
static int do_background_thread(thread_t thread, int priority);
static int do_background_proc(struct proc *curp, struct proc *targetp, int priority);
static int set_gpudeny_proc(struct proc *curp, struct proc *targetp, int priority);
static int proc_set_darwin_role(proc_t curp, proc_t targetp, int priority);
static int proc_get_darwin_role(proc_t curp, proc_t targetp, int *priority);
static int get_background_proc(struct proc *curp, struct proc *targetp, int *priority);
int proc_pid_rusage(int pid, int flavor, user_addr_t buf, int32_t *retval);
void gather_rusage_info(proc_t p, rusage_info_current *ru, int flavor);
int fill_task_rusage(task_t task, rusage_info_current *ri);
void fill_task_billed_usage(task_t task, rusage_info_current *ri);
int fill_task_io_rusage(task_t task, rusage_info_current *ri);
int fill_task_qos_rusage(task_t task, rusage_info_current *ri);
uint64_t get_task_logical_writes(task_t task, boolean_t external);
void fill_task_monotonic_rusage(task_t task, rusage_info_current *ri);

int proc_get_rusage(proc_t p, int flavor, user_addr_t buffer, __unused int is_zombie);

rlim_t maxdmap = MAXDSIZ;       /* XXX */
rlim_t maxsmap = MAXSSIZ - PAGE_MAX_SIZE;       /* XXX */

/* For plimit reference count */
os_refgrp_decl(, rlimit_refgrp, "plimit_refcnt", NULL);

ZONE_DECLARE(plimit_zone, "plimit", sizeof(struct plimit), ZC_NOENCRYPT);

/*
 * Limits on the number of open files per process, and the number
 * of child processes per process.
 *
 * Note: would be in kern/subr_param.c in FreeBSD.
 */
__private_extern__ int maxfilesperproc = OPEN_MAX;              /* per-proc open files limit */

SYSCTL_INT(_kern, KERN_MAXPROCPERUID, maxprocperuid, CTLFLAG_RW | CTLFLAG_LOCKED,
    &maxprocperuid, 0, "Maximum processes allowed per userid" );

SYSCTL_INT(_kern, KERN_MAXFILESPERPROC, maxfilesperproc, CTLFLAG_RW | CTLFLAG_LOCKED,
    &maxfilesperproc, 0, "Maximum files allowed open per process" );

/* Args and fn for proc_iteration callback used in setpriority */
struct puser_nice_args {
	proc_t curp;
	int     prio;
	id_t    who;
	int *   foundp;
	int *   errorp;
};
static int puser_donice_callback(proc_t p, void * arg);


/* Args and fn for proc_iteration callback used in setpriority */
struct ppgrp_nice_args {
	proc_t curp;
	int     prio;
	int *   foundp;
	int *   errorp;
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
	int refheld = 0;
	int error = 0;

	/* would also test (uap->who < 0), but id_t is unsigned */
	if (uap->who > 0x7fffffff) {
		return EINVAL;
	}

	switch (uap->which) {
	case PRIO_PROCESS:
		if (uap->who == 0) {
			p = curp;
			low = p->p_nice;
		} else {
			p = proc_find(uap->who);
			if (p == 0) {
				break;
			}
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
		PGMEMBERS_FOREACH(pg, p) {
			if (p->p_nice < low) {
				low = p->p_nice;
			}
		}
		pgrp_unlock(pg);
		pg_rele(pg);
		break;
	}

	case PRIO_USER:
		if (uap->who == 0) {
			uap->who = kauth_cred_getuid(kauth_cred_get());
		}

		proc_list_lock();

		for (p = allproc.lh_first; p != 0; p = p->p_list.le_next) {
			my_cred = kauth_cred_proc_ref(p);
			if (kauth_cred_getuid(my_cred) == uap->who &&
			    p->p_nice < low) {
				low = p->p_nice;
			}
			kauth_cred_unref(&my_cred);
		}

		proc_list_unlock();

		break;

	case PRIO_DARWIN_THREAD:
		/* we currently only support the current thread */
		if (uap->who != 0) {
			return EINVAL;
		}

		low = proc_get_thread_policy(current_thread(), TASK_POLICY_INTERNAL, TASK_POLICY_DARWIN_BG);

		break;

	case PRIO_DARWIN_PROCESS:
		if (uap->who == 0) {
			p = curp;
		} else {
			p = proc_find(uap->who);
			if (p == PROC_NULL) {
				break;
			}
			refheld = 1;
		}

		error = get_background_proc(curp, p, &low);

		if (refheld) {
			proc_rele(p);
		}
		if (error) {
			return error;
		}
		break;

	case PRIO_DARWIN_ROLE:
		if (uap->who == 0) {
			p = curp;
		} else {
			p = proc_find(uap->who);
			if (p == PROC_NULL) {
				break;
			}
			refheld = 1;
		}

		error = proc_get_darwin_role(curp, p, &low);

		if (refheld) {
			proc_rele(p);
		}
		if (error) {
			return error;
		}
		break;

	default:
		return EINVAL;
	}
	if (low == PRIO_MAX + 1) {
		return ESRCH;
	}
	*retval = low;
	return 0;
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
		if (pun->errorp != NULL) {
			*pun->errorp = error;
		}
		if (pun->foundp != NULL) {
			n = *pun->foundp;
			*pun->foundp = n + 1;
		}
	}
	kauth_cred_unref(&my_cred);

	return PROC_RETURNED;
}

/* call back function used for proc iteration in PRIO_PGRP */
static int
ppgrp_donice_callback(proc_t p, void * arg)
{
	int error;
	struct ppgrp_nice_args * pun = (struct ppgrp_nice_args *)arg;
	int n;

	error = donice(pun->curp, p, pun->prio);
	if (pun->errorp != NULL) {
		*pun->errorp = error;
	}
	if (pun->foundp != NULL) {
		n = *pun->foundp;
		*pun->foundp = n + 1;
	}

	return PROC_RETURNED;
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
setpriority(struct proc *curp, struct setpriority_args *uap, int32_t *retval)
{
	struct proc *p;
	int found = 0, error = 0;
	int refheld = 0;

	AUDIT_ARG(cmd, uap->which);
	AUDIT_ARG(owner, uap->who, 0);
	AUDIT_ARG(value32, uap->prio);

	/* would also test (uap->who < 0), but id_t is unsigned */
	if (uap->who > 0x7fffffff) {
		return EINVAL;
	}

	switch (uap->which) {
	case PRIO_PROCESS:
		if (uap->who == 0) {
			p = curp;
		} else {
			p = proc_find(uap->who);
			if (p == 0) {
				break;
			}
			refheld = 1;
		}
		error = donice(curp, p, uap->prio);
		found++;
		if (refheld != 0) {
			proc_rele(p);
		}
		break;

	case PRIO_PGRP: {
		struct pgrp *pg = PGRP_NULL;
		struct ppgrp_nice_args ppgrp;

		if (uap->who == 0) {
			pg = proc_pgrp(curp);
		} else if ((pg = pgfind(uap->who)) == PGRP_NULL) {
			break;
		}

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

		if (uap->who == 0) {
			uap->who = kauth_cred_getuid(kauth_cred_get());
		}

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
			return EINVAL;
		}

		error = do_background_thread(current_thread(), uap->prio);
		found++;
		break;
	}

	case PRIO_DARWIN_PROCESS: {
		if (uap->who == 0) {
			p = curp;
		} else {
			p = proc_find(uap->who);
			if (p == 0) {
				break;
			}
			refheld = 1;
		}

		error = do_background_proc(curp, p, uap->prio);

		found++;
		if (refheld != 0) {
			proc_rele(p);
		}
		break;
	}

	case PRIO_DARWIN_GPU: {
		if (uap->who == 0) {
			return EINVAL;
		}

		p = proc_find(uap->who);
		if (p == PROC_NULL) {
			break;
		}

		error = set_gpudeny_proc(curp, p, uap->prio);

		found++;
		proc_rele(p);
		break;
	}

	case PRIO_DARWIN_ROLE: {
		if (uap->who == 0) {
			p = curp;
		} else {
			p = proc_find(uap->who);
			if (p == PROC_NULL) {
				break;
			}
			refheld = 1;
		}

		error = proc_set_darwin_role(curp, p, uap->prio);

		found++;
		if (refheld != 0) {
			proc_rele(p);
		}
		break;
	}

	default:
		return EINVAL;
	}
	if (found == 0) {
		return ESRCH;
	}
	if (error == EIDRM) {
		*retval = -2;
		error = 0;
	}
	return error;
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

	if (suser(ucred, NULL) && kauth_cred_getruid(ucred) &&
	    kauth_cred_getuid(ucred) != kauth_cred_getuid(my_cred) &&
	    kauth_cred_getruid(ucred) != kauth_cred_getuid(my_cred)) {
		error = EPERM;
		goto out;
	}
	if (n > PRIO_MAX) {
		n = PRIO_MAX;
	}
	if (n < PRIO_MIN) {
		n = PRIO_MIN;
	}
	if (n < chgp->p_nice && suser(ucred, &curp->p_acflag)) {
		error = EACCES;
		goto out;
	}
#if CONFIG_MACF
	error = mac_proc_check_sched(curp, chgp);
	if (error) {
		goto out;
	}
#endif
	proc_lock(chgp);
	chgp->p_nice = (char)n;
	proc_unlock(chgp);
	(void)resetpriority(chgp);
out:
	kauth_cred_unref(&ucred);
	kauth_cred_unref(&my_cred);
	return error;
}

static int
set_gpudeny_proc(struct proc *curp, struct proc *targetp, int priority)
{
	int error = 0;
	kauth_cred_t ucred;
	kauth_cred_t target_cred;

	ucred = kauth_cred_get();
	target_cred = kauth_cred_proc_ref(targetp);

	/* TODO: Entitlement instead of uid check */

	if (!kauth_cred_issuser(ucred) && kauth_cred_getruid(ucred) &&
	    kauth_cred_getuid(ucred) != kauth_cred_getuid(target_cred) &&
	    kauth_cred_getruid(ucred) != kauth_cred_getuid(target_cred)) {
		error = EPERM;
		goto out;
	}

	if (curp == targetp) {
		error = EPERM;
		goto out;
	}

#if CONFIG_MACF
	error = mac_proc_check_sched(curp, targetp);
	if (error) {
		goto out;
	}
#endif

	switch (priority) {
	case PRIO_DARWIN_GPU_DENY:
		task_set_gpu_denied(proc_task(targetp), TRUE);
		break;
	case PRIO_DARWIN_GPU_ALLOW:
		task_set_gpu_denied(proc_task(targetp), FALSE);
		break;
	default:
		error = EINVAL;
		goto out;
	}

out:
	kauth_cred_unref(&target_cred);
	return error;
}

static int
proc_set_darwin_role(proc_t curp, proc_t targetp, int priority)
{
	int error = 0;
	uint32_t flagsp = 0;

	kauth_cred_t ucred, target_cred;

	ucred = kauth_cred_get();
	target_cred = kauth_cred_proc_ref(targetp);

	if (!kauth_cred_issuser(ucred) && kauth_cred_getruid(ucred) &&
	    kauth_cred_getuid(ucred) != kauth_cred_getuid(target_cred) &&
	    kauth_cred_getruid(ucred) != kauth_cred_getuid(target_cred)) {
		if (priv_check_cred(ucred, PRIV_SETPRIORITY_DARWIN_ROLE, 0) != 0) {
			error = EPERM;
			goto out;
		}
	}

	if (curp != targetp) {
#if CONFIG_MACF
		if ((error = mac_proc_check_sched(curp, targetp))) {
			goto out;
		}
#endif
	}

	proc_get_darwinbgstate(proc_task(targetp), &flagsp);
	if ((flagsp & PROC_FLAG_APPLICATION) != PROC_FLAG_APPLICATION) {
		error = ENOTSUP;
		goto out;
	}

	task_role_t role = TASK_UNSPECIFIED;

	if ((error = proc_darwin_role_to_task_role(priority, &role))) {
		goto out;
	}

	proc_set_task_policy(proc_task(targetp), TASK_POLICY_ATTRIBUTE,
	    TASK_POLICY_ROLE, role);

out:
	kauth_cred_unref(&target_cred);
	return error;
}

static int
proc_get_darwin_role(proc_t curp, proc_t targetp, int *priority)
{
	int error = 0;
	int role = 0;

	kauth_cred_t ucred, target_cred;

	ucred = kauth_cred_get();
	target_cred = kauth_cred_proc_ref(targetp);

	if (!kauth_cred_issuser(ucred) && kauth_cred_getruid(ucred) &&
	    kauth_cred_getuid(ucred) != kauth_cred_getuid(target_cred) &&
	    kauth_cred_getruid(ucred) != kauth_cred_getuid(target_cred)) {
		error = EPERM;
		goto out;
	}

	if (curp != targetp) {
#if CONFIG_MACF
		if ((error = mac_proc_check_sched(curp, targetp))) {
			goto out;
		}
#endif
	}

	role = proc_get_task_policy(proc_task(targetp), TASK_POLICY_ATTRIBUTE, TASK_POLICY_ROLE);

	*priority = proc_task_role_to_darwin_role(role);

out:
	kauth_cred_unref(&target_cred);
	return error;
}


static int
get_background_proc(struct proc *curp, struct proc *targetp, int *priority)
{
	int external = 0;
	int error = 0;
	kauth_cred_t ucred, target_cred;

	ucred = kauth_cred_get();
	target_cred = kauth_cred_proc_ref(targetp);

	if (!kauth_cred_issuser(ucred) && kauth_cred_getruid(ucred) &&
	    kauth_cred_getuid(ucred) != kauth_cred_getuid(target_cred) &&
	    kauth_cred_getruid(ucred) != kauth_cred_getuid(target_cred)) {
		error = EPERM;
		goto out;
	}

	external = (curp == targetp) ? TASK_POLICY_INTERNAL : TASK_POLICY_EXTERNAL;

	*priority = proc_get_task_policy(current_task(), external, TASK_POLICY_DARWIN_BG);

out:
	kauth_cred_unref(&target_cred);
	return error;
}

static int
do_background_proc(struct proc *curp, struct proc *targetp, int priority)
{
#if !CONFIG_MACF
#pragma unused(curp)
#endif
	int error = 0;
	kauth_cred_t ucred;
	kauth_cred_t target_cred;
	int external;
	int enable;

	ucred = kauth_cred_get();
	target_cred = kauth_cred_proc_ref(targetp);

	if (!kauth_cred_issuser(ucred) && kauth_cred_getruid(ucred) &&
	    kauth_cred_getuid(ucred) != kauth_cred_getuid(target_cred) &&
	    kauth_cred_getruid(ucred) != kauth_cred_getuid(target_cred)) {
		error = EPERM;
		goto out;
	}

#if CONFIG_MACF
	error = mac_proc_check_sched(curp, targetp);
	if (error) {
		goto out;
	}
#endif

	external = (curp == targetp) ? TASK_POLICY_INTERNAL : TASK_POLICY_EXTERNAL;

	switch (priority) {
	case PRIO_DARWIN_BG:
		enable = TASK_POLICY_ENABLE;
		break;
	case PRIO_DARWIN_NONUI:
		/* ignored for compatibility */
		goto out;
	default:
		/* TODO: EINVAL if priority != 0 */
		enable = TASK_POLICY_DISABLE;
		break;
	}

	proc_set_task_policy(proc_task(targetp), external, TASK_POLICY_DARWIN_BG, enable);

out:
	kauth_cred_unref(&target_cred);
	return error;
}

static void
do_background_socket(struct proc *p, thread_t thread)
{
#if SOCKETS
	struct fileproc *fp;
	int              background = false;
#if NECP
	int              update_necp = false;
#endif /* NECP */

	proc_fdlock(p);

	if (thread != THREAD_NULL) {
		background = proc_get_effective_thread_policy(thread, TASK_POLICY_ALL_SOCKETS_BG);
	} else {
		background = proc_get_effective_task_policy(proc_task(p), TASK_POLICY_ALL_SOCKETS_BG);
	}

	if (background) {
		/*
		 * For PRIO_DARWIN_PROCESS (thread is NULL), simply mark
		 * the sockets with the background flag.  There's nothing
		 * to do here for the PRIO_DARWIN_THREAD case.
		 */
		if (thread == THREAD_NULL) {
			fdt_foreach(fp, p) {
				if (FILEGLOB_DTYPE(fp->fp_glob) == DTYPE_SOCKET) {
					struct socket *sockp = (struct socket *)fp->fp_glob->fg_data;
					socket_set_traffic_mgt_flags(sockp, TRAFFIC_MGT_SO_BACKGROUND);
					sockp->so_background_thread = NULL;
				}
#if NECP
				else if (FILEGLOB_DTYPE(fp->fp_glob) == DTYPE_NETPOLICY) {
					if (necp_set_client_as_background(p, fp, background)) {
						update_necp = true;
					}
				}
#endif /* NECP */
			}
		}
	} else {
		/* disable networking IO throttle.
		 * NOTE - It is a known limitation of the current design that we
		 * could potentially clear TRAFFIC_MGT_SO_BACKGROUND bit for
		 * sockets created by other threads within this process.
		 */
		fdt_foreach(fp, p) {
			struct socket *sockp;

			if (FILEGLOB_DTYPE(fp->fp_glob) == DTYPE_SOCKET) {
				sockp = (struct socket *)fp->fp_glob->fg_data;
				/* skip if only clearing this thread's sockets */
				if ((thread) && (sockp->so_background_thread != thread)) {
					continue;
				}
				socket_clear_traffic_mgt_flags(sockp, TRAFFIC_MGT_SO_BACKGROUND);
				sockp->so_background_thread = NULL;
			}
#if NECP
			else if (FILEGLOB_DTYPE(fp->fp_glob) == DTYPE_NETPOLICY) {
				if (necp_set_client_as_background(p, fp, background)) {
					update_necp = true;
				}
			}
#endif /* NECP */
		}
	}

	proc_fdunlock(p);

#if NECP
	if (update_necp) {
		necp_update_all_clients();
	}
#endif /* NECP */
#else
#pragma unused(p, thread)
#endif
}


/*
 * do_background_thread
 *
 * Requires: thread reference
 *
 * Returns:     0                       Success
 *              EPERM                   Tried to background while in vfork
 * XXX - todo - does this need a MACF hook?
 */
static int
do_background_thread(thread_t thread, int priority)
{
	struct uthread *ut;
	int enable, external;
	int rv = 0;

	ut = get_bsdthread_info(thread);

	/* Backgrounding is unsupported for threads in vfork */
	if ((ut->uu_flag & UT_VFORK) != 0) {
		return EPERM;
	}

	/* Backgrounding is unsupported for workq threads */
	if (thread_is_static_param(thread)) {
		return EPERM;
	}

	/* Not allowed to combine QoS and DARWIN_BG, doing so strips the QoS */
	if (thread_has_qos_policy(thread)) {
		thread_remove_qos_policy(thread);
		rv = EIDRM;
	}

	/* TODO: Fail if someone passes something besides 0 or PRIO_DARWIN_BG */
	enable   = (priority == PRIO_DARWIN_BG) ? TASK_POLICY_ENABLE   : TASK_POLICY_DISABLE;
	external = (current_thread() == thread) ? TASK_POLICY_INTERNAL : TASK_POLICY_EXTERNAL;

	proc_set_thread_policy(thread, external, TASK_POLICY_DARWIN_BG, enable);

	return rv;
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
	    sizeof(struct rlimit)))) {
		return error;
	}

	return dosetrlimit(p, uap->which, &alim);
}

/*
 * Returns:	0			Success
 *		EINVAL
 *	suser:EPERM
 *
 * Notes:	EINVAL is returned both for invalid arguments, and in the
 *		case that the current usage (e.g. RLIMIT_STACK) is already
 *		in excess of the requested limit.
 */
int
dosetrlimit(struct proc *p, u_int which, struct rlimit *newrlim)
{
	struct rlimit        rlim;
	int                  error;
	kern_return_t        kr;
	int                  posix = (which & _RLIMIT_POSIX_FLAG) ? 1 : 0;

	/* Mask out POSIX flag, saved above */
	which &= ~_RLIMIT_POSIX_FLAG;

	/* Unknown resource */
	if (which >= RLIM_NLIMITS) {
		return EINVAL;
	}

	/*
	 * Take a snapshot of the current rlimit values and read this throughout
	 * this routine. This minimizes the critical sections and allow other
	 * processes in the system to access the plimit while we are in the
	 * middle of this setrlimit call.
	 */
	proc_lock(p);
	rlim = p->p_limit->pl_rlimit[which];
	proc_unlock(p);

	error = 0;
	/* Sanity check: new soft limit cannot exceed new hard limit */
	if (newrlim->rlim_cur > newrlim->rlim_max) {
		error = EINVAL;
	}
	/*
	 * Sanity check: only super-user may raise the hard limit.
	 * newrlim->rlim_cur > rlim.rlim_max implies that the call is increasing the hard limit as well.
	 */
	else if (newrlim->rlim_cur > rlim.rlim_max || newrlim->rlim_max > rlim.rlim_max) {
		/* suser() returns 0 if the calling thread is super user. */
		error = suser(kauth_cred_get(), &p->p_acflag);
	}

	if (error) {
		/* Invalid setrlimit request: EINVAL or EPERM */
		return error;
	}

	/* Only one thread is able to change the current process's rlimit values */
	proc_lock(p);
	proc_limitblock(p);
	proc_unlock(p);

	/* We have the reader lock of the process's plimit so it's safe to read the rlimit values */
	switch (which) {
	case RLIMIT_CPU:
		if (newrlim->rlim_cur == RLIM_INFINITY) {
			task_vtimer_clear(p->task, TASK_VTIMER_RLIM);
			timerclear(&p->p_rlim_cpu);
		} else {
			task_absolutetime_info_data_t   tinfo;
			mach_msg_type_number_t          count;
			struct timeval                  ttv, tv;
			clock_sec_t                     tv_sec;
			clock_usec_t                    tv_usec;

			count = TASK_ABSOLUTETIME_INFO_COUNT;
			task_info(p->task, TASK_ABSOLUTETIME_INFO, (task_info_t)&tinfo, &count);
			absolutetime_to_microtime(tinfo.total_user + tinfo.total_system, &tv_sec, &tv_usec);
			ttv.tv_sec = tv_sec;
			ttv.tv_usec = tv_usec;

			tv.tv_sec = (newrlim->rlim_cur > __INT_MAX__ ? __INT_MAX__ : (__darwin_time_t)newrlim->rlim_cur);
			tv.tv_usec = 0;
			timersub(&tv, &ttv, &p->p_rlim_cpu);

			timerclear(&tv);
			if (timercmp(&p->p_rlim_cpu, &tv, >)) {
				task_vtimer_set(p->task, TASK_VTIMER_RLIM);
			} else {
				task_vtimer_clear(p->task, TASK_VTIMER_RLIM);

				timerclear(&p->p_rlim_cpu);

				psignal(p, SIGXCPU);
			}
		}
		break;

	case RLIMIT_DATA:
		if (newrlim->rlim_cur > maxdmap) {
			newrlim->rlim_cur = maxdmap;
		}
		if (newrlim->rlim_max > maxdmap) {
			newrlim->rlim_max = maxdmap;
		}
		break;

	case RLIMIT_STACK:
		if (p->p_lflag & P_LCUSTOM_STACK) {
			/* Process has a custom stack set - rlimit cannot be used to change it */
			error = EINVAL;
			goto out;
		}

		/* Disallow illegal stack size instead of clipping */
		if (newrlim->rlim_cur > maxsmap ||
		    newrlim->rlim_max > maxsmap) {
			if (posix) {
				error = EINVAL;
				goto out;
			} else {
				/*
				 * 4797860 - workaround poorly written installers by
				 * doing previous implementation (< 10.5) when caller
				 * is non-POSIX conforming.
				 */
				if (newrlim->rlim_cur > maxsmap) {
					newrlim->rlim_cur = maxsmap;
				}
				if (newrlim->rlim_max > maxsmap) {
					newrlim->rlim_max = maxsmap;
				}
			}
		}

		/*
		 * Stack is allocated to the max at exec time with only
		 * "rlim_cur" bytes accessible.  If stack limit is going
		 * up make more accessible, if going down make inaccessible.
		 */
		if (newrlim->rlim_cur > rlim.rlim_cur) {
			mach_vm_offset_t addr;
			mach_vm_size_t size;

			/* grow stack */
			size = round_page_64(newrlim->rlim_cur);
			size -= round_page_64(rlim.rlim_cur);

			addr = (mach_vm_offset_t)(p->user_stack - round_page_64(newrlim->rlim_cur));
			kr = mach_vm_protect(current_map(), addr, size, FALSE, VM_PROT_DEFAULT);
			if (kr != KERN_SUCCESS) {
				error =  EINVAL;
				goto out;
			}
		} else if (newrlim->rlim_cur < rlim.rlim_cur) {
			mach_vm_offset_t addr;
			mach_vm_size_t size;
			uint64_t cur_sp;

			/* shrink stack */

			/*
			 * First check if new stack limit would agree
			 * with current stack usage.
			 * Get the current thread's stack pointer...
			 */
			cur_sp = thread_adjuserstack(current_thread(), 0);
			if (cur_sp <= p->user_stack &&
			    cur_sp > (p->user_stack - round_page_64(rlim.rlim_cur))) {
				/* stack pointer is in main stack */
				if (cur_sp <= (p->user_stack - round_page_64(newrlim->rlim_cur))) {
					/*
					 * New limit would cause current usage to be invalid:
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

			size = round_page_64(rlim.rlim_cur);
			size -= round_page_64(rlim.rlim_cur);

			addr = (mach_vm_offset_t)(p->user_stack - round_page_64(rlim.rlim_cur));

			kr = mach_vm_protect(current_map(), addr, size, FALSE, VM_PROT_NONE);
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
		 * Nothing to be done here as we already performed the sanity checks before entering the switch code block.
		 * The real NOFILE limits enforced by the kernel is capped at MIN(RLIMIT_NOFILE, maxfilesperproc)
		 */
		break;

	case RLIMIT_NPROC:
		/*
		 * Only root can set to the maxproc limits, as it is
		 * systemwide resource; all others are limited to
		 * maxprocperuid (presumably less than maxproc).
		 */
		if (kauth_cred_issuser(kauth_cred_get())) {
			if (newrlim->rlim_cur > (rlim_t)maxproc) {
				newrlim->rlim_cur = maxproc;
			}
			if (newrlim->rlim_max > (rlim_t)maxproc) {
				newrlim->rlim_max = maxproc;
			}
		} else {
			if (newrlim->rlim_cur > (rlim_t)maxprocperuid) {
				newrlim->rlim_cur = maxprocperuid;
			}
			if (newrlim->rlim_max > (rlim_t)maxprocperuid) {
				newrlim->rlim_max = maxprocperuid;
			}
		}
		break;

	case RLIMIT_MEMLOCK:
		/*
		 * Tell the Mach VM layer about the new limit value.
		 */
		newrlim->rlim_cur = (vm_size_t)newrlim->rlim_cur;
		vm_map_set_user_wire_limit(current_map(), (vm_size_t)newrlim->rlim_cur);
		break;
	} /* switch... */

	/* Everything checks out and we are now ready to update the rlimit */
	error = 0;

out:

	if (error == 0) {
		/*
		 * COW the current plimit if it's shared, otherwise update it in place.
		 * Finally unblock other threads wishing to change plimit.
		 */
		proc_lock(p);
		proc_limitupdate(p, newrlim, (uint8_t)which);
		proc_limitunblock(p);
		proc_unlock(p);
	} else {
		/*
		 * This setrlimit has failed, just leave the plimit as is and unblock other
		 * threads wishing to change plimit.
		 */
		proc_lock(p);
		proc_limitunblock(p);
		proc_unlock(p);
	}

	return error;
}

/* ARGSUSED */
int
getrlimit(struct proc *p, struct getrlimit_args *uap, __unused int32_t *retval)
{
	struct rlimit lim = {};

	/*
	 * Take out flag now in case we need to use it to trigger variant
	 * behaviour later.
	 */
	uap->which &= ~_RLIMIT_POSIX_FLAG;

	if (uap->which >= RLIM_NLIMITS) {
		return EINVAL;
	}
	proc_limitget(p, uap->which, &lim);
	return copyout((caddr_t)&lim,
	           uap->rlp, sizeof(struct rlimit));
}

/*
 * Transform the running time and tick information in proc p into user,
 * system, and interrupt time usage.
 */
/* No lock on proc is held for this.. */
void
calcru(struct proc *p, struct timeval *up, struct timeval *sp, struct timeval *ip)
{
	task_t                  task;

	timerclear(up);
	timerclear(sp);
	if (ip != NULL) {
		timerclear(ip);
	}

	task = p->task;
	if (task) {
		mach_task_basic_info_data_t tinfo;
		task_thread_times_info_data_t ttimesinfo;
		task_events_info_data_t teventsinfo;
		mach_msg_type_number_t task_info_count, task_ttimes_count;
		mach_msg_type_number_t task_events_count;
		struct timeval ut, st;

		task_info_count = MACH_TASK_BASIC_INFO_COUNT;
		task_info(task, MACH_TASK_BASIC_INFO,
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
		if (p->p_stats->p_ru.ru_nivcsw < 0) {
			p->p_stats->p_ru.ru_nivcsw = 0;
		}

		p->p_stats->p_ru.ru_maxrss = (long)tinfo.resident_size_max;
	}
}

__private_extern__ void munge_user64_rusage(struct rusage *a_rusage_p, struct user64_rusage *a_user_rusage_p);
__private_extern__ void munge_user32_rusage(struct rusage *a_rusage_p, struct user32_rusage *a_user_rusage_p);

/* ARGSUSED */
int
getrusage(struct proc *p, struct getrusage_args *uap, __unused int32_t *retval)
{
	struct rusage *rup, rubuf;
	struct user64_rusage rubuf64 = {};
	struct user32_rusage rubuf32 = {};
	size_t retsize = sizeof(rubuf);                 /* default: 32 bits */
	caddr_t retbuf = (caddr_t)&rubuf;               /* default: 32 bits */
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
		return EINVAL;
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

	return copyout(retbuf, uap->rusage, retsize);
}

void
ruadd(struct rusage *ru, struct rusage *ru2)
{
	long *ip, *ip2;
	long i;

	timeradd(&ru->ru_utime, &ru2->ru_utime, &ru->ru_utime);
	timeradd(&ru->ru_stime, &ru2->ru_stime, &ru->ru_stime);
	if (ru->ru_maxrss < ru2->ru_maxrss) {
		ru->ru_maxrss = ru2->ru_maxrss;
	}
	ip = &ru->ru_first; ip2 = &ru2->ru_first;
	for (i = &ru->ru_last - &ru->ru_first; i >= 0; i--) {
		*ip++ += *ip2++;
	}
}

/*
 * Add the rusage stats of child in parent.
 *
 * It adds rusage statistics of child process and statistics of all its
 * children to its parent.
 *
 * Note: proc lock of parent should be held while calling this function.
 */
void
update_rusage_info_child(struct rusage_info_child *ri, rusage_info_current *ri_current)
{
	ri->ri_child_user_time += (ri_current->ri_user_time +
	    ri_current->ri_child_user_time);
	ri->ri_child_system_time += (ri_current->ri_system_time +
	    ri_current->ri_child_system_time);
	ri->ri_child_pkg_idle_wkups += (ri_current->ri_pkg_idle_wkups +
	    ri_current->ri_child_pkg_idle_wkups);
	ri->ri_child_interrupt_wkups += (ri_current->ri_interrupt_wkups +
	    ri_current->ri_child_interrupt_wkups);
	ri->ri_child_pageins += (ri_current->ri_pageins +
	    ri_current->ri_child_pageins);
	ri->ri_child_elapsed_abstime += ((ri_current->ri_proc_exit_abstime -
	    ri_current->ri_proc_start_abstime) + ri_current->ri_child_elapsed_abstime);
}

/*
 * Reading soft limit from specified resource.
 */
rlim_t
proc_limitgetcur(proc_t p, int which, boolean_t to_lock_proc)
{
	rlim_t rlim_cur;

	assert(p);
	assert(which < RLIM_NLIMITS);

	/*
	 * Serialize access to the process's plimit pointer for concurrent threads.
	 */
	if (to_lock_proc) {
		lck_mtx_assert(&p->p_mlock, LCK_MTX_ASSERT_NOTOWNED);
		proc_lock(p);
	}

	rlim_cur = p->p_limit->pl_rlimit[which].rlim_cur;

	if (to_lock_proc) {
		proc_unlock(p);
	}

	return rlim_cur;
}

/*
 * Writing soft limit to specified resource. This is an internal function
 * used only by proc_exit and vfork_exit_internal to update RLIMIT_FSIZE in
 * place without invoking setrlimit.
 */
void
proc_limitsetcur_internal(proc_t p, int which, rlim_t value)
{
	struct rlimit rlim;

	assert(p);
	assertf(which == RLIMIT_FSIZE, "%s only supports RLIMIT_FSIZE\n", __FUNCTION__);


	proc_lock(p);

	/* Only one thread is able to change rlimit values at a time */
	proc_limitblock(p);

	/* Prepare an rlimit for proc_limitupdate */
	rlim = p->p_limit->pl_rlimit[which];
	rlim.rlim_cur = value;

	/*
	 * proc_limitupdate will COW the current plimit and update specified the soft limit
	 * if the plimit is shared, otherwise it will update the soft limit in place.
	 */
	proc_limitupdate(p, &rlim, (uint8_t)which);

	/* Unblock other threads wishing to change plimit */
	proc_limitunblock(p);

	proc_unlock(p);
}

void
proc_limitget(proc_t p, int which, struct rlimit * limp)
{
	assert(p);
	assert(limp);
	assert(which < RLIM_NLIMITS);

	/* Protect writes to the process's plimit pointer issued by concurrent threads */
	proc_lock(p);

	limp->rlim_cur = p->p_limit->pl_rlimit[which].rlim_cur;
	limp->rlim_max = p->p_limit->pl_rlimit[which].rlim_max;

	proc_unlock(p);
}

void
proc_limitfork(proc_t parent, proc_t child)
{
	assert(parent && child);

	proc_lock(parent);

	/* Child proc inherits parent's plimit */
	child->p_limit = parent->p_limit;

	/* Increment refcnt of the shared plimit */
	os_ref_retain(&parent->p_limit->pl_refcnt);

	proc_unlock(parent);
}

void
proc_limitdrop(proc_t p)
{
	struct plimit *free_plim = NULL;
	os_ref_count_t refcnt;

	proc_lock(p);

	/* Drop the plimit reference before exiting the system */
	refcnt = os_ref_release(&p->p_limit->pl_refcnt);
	if (refcnt == 0) {
		free_plim = p->p_limit;
	}

	p->p_limit = NULL;
	proc_unlock(p);

	/* We are the last user of this plimit, free it now. */
	if (free_plim != NULL) {
		zfree(plimit_zone, free_plim);
	}
}

/*
 * proc_limitblock/unblock are used to serialize access to plimit
 * from concurrent threads within the same process.
 * Callers must be holding the proc lock to enter, return with
 * the proc lock locked
 */
void
proc_limitblock(proc_t p)
{
	lck_mtx_assert(&p->p_mlock, LCK_MTX_ASSERT_OWNED);

	while (p->p_lflag & P_LLIMCHANGE) {
		p->p_lflag |= P_LLIMWAIT;
		msleep(&p->p_limit, &p->p_mlock, 0, "proc_limitblock", NULL);
	}
	p->p_lflag |= P_LLIMCHANGE;
}

/*
 * Callers must be holding the proc lock to enter, return with
 * the proc lock locked
 */
void
proc_limitunblock(proc_t p)
{
	lck_mtx_assert(&p->p_mlock, LCK_MTX_ASSERT_OWNED);

	p->p_lflag &= ~P_LLIMCHANGE;
	if (p->p_lflag & P_LLIMWAIT) {
		p->p_lflag &= ~P_LLIMWAIT;
		wakeup(&p->p_limit);
	}
}

/*
 * Change the rlimit values of process "p" to "rlim" for resource "which".
 *
 * If the current plimit is shared by multiple processes (refcnt > 1):
 *    this routine replaces the process's original plimit with a new plimit,
 *    update the requeted rlimit values, and free the original plimit if this
 *    process is the last user.
 *
 * If the current plimit is used only by the calling process (refcnt == 1):
 *    this routine updates the new rlimit values in place.
 *
 * Note: caller must be holding the proc lock before entering this routine.
 * This routine allocates and frees kernel memory without holding the proc lock
 * to minimize contention, and returns with the proc lock held.
 */
void
proc_limitupdate(proc_t p, struct rlimit *rlim, uint8_t which)
{
	struct plimit  *copy_plim;
	struct plimit  *free_plim;
	os_ref_count_t refcnt;

	assert(p && p->p_limit);
	assert(rlim);
	assert(which < RLIM_NLIMITS);
	lck_mtx_assert(&p->p_mlock, LCK_MTX_ASSERT_OWNED);

	/*
	 * If we are the only user of this plimit, don't bother allocating a plimit
	 * before making changes. Just modify the rlimit values in place.
	 */
	refcnt = os_ref_get_count(&p->p_limit->pl_refcnt);
	if (refcnt == 1) {
		p->p_limit->pl_rlimit[which] = *rlim;
		return;
	}

	/*
	 * Allocating a new plimit for this process to apply the requested rlimit values.
	 * Not holding the lock on the original plimit gives other processes in the system
	 * a chance to access the plimit while we wait for memory below.
	 *
	 * The default zalloc should always succeed when WAIT flag.
	 */
	proc_unlock(p);
	copy_plim = zalloc(plimit_zone);

	/* Copy the current p_limit */
	proc_lock(p);
	bcopy(p->p_limit->pl_rlimit, copy_plim->pl_rlimit, sizeof(struct rlimit) * RLIM_NLIMITS);

	/*
	 * Drop our reference to the old plimit. Other processes sharing the old plimit could
	 * have exited the system when we wait for memory for the new plimit above, thus, we
	 * need to check the refcnt again and free the old plimit if this process is the last
	 * user. Also since we are holding the proc lock here, it's impossible for another threads
	 * to dereference the plimit, so it's safe to free the old plimit memory.
	 */
	free_plim = NULL;
	refcnt = os_ref_release(&p->p_limit->pl_refcnt);
	if (refcnt == 0) {
		free_plim = p->p_limit;
	}
	/* Initialize the newly allocated plimit */
	os_ref_init_count(&copy_plim->pl_refcnt, &rlimit_refgrp, 1);

	/* Apply new rlimit values */
	copy_plim->pl_rlimit[which] = *rlim;

	/* All set, update the process's plimit pointer to the new plimit. */
	p->p_limit = copy_plim;
	proc_unlock(p);

	if (free_plim != NULL) {
		zfree(plimit_zone, free_plim);
	}

	/* Return with proc->p_mlock locked */
	proc_lock(p);
}

static int
iopolicysys_disk(struct proc *p, int cmd, int scope, int policy, struct _iopol_param_t *iop_param);
static int
iopolicysys_vfs_hfs_case_sensitivity(struct proc *p, int cmd, int scope, int policy, struct _iopol_param_t *iop_param);
static int
iopolicysys_vfs_atime_updates(struct proc *p, int cmd, int scope, int policy, struct _iopol_param_t *iop_param);
static int
iopolicysys_vfs_materialize_dataless_files(struct proc *p, int cmd, int scope, int policy, struct _iopol_param_t *iop_param);
static int
iopolicysys_vfs_statfs_no_data_volume(struct proc *p, int cmd, int scope, int policy, struct _iopol_param_t *iop_param);
static int
iopolicysys_vfs_trigger_resolve(struct proc *p, int cmd, int scope, int policy, struct _iopol_param_t *iop_param);
static int
iopolicysys_vfs_ignore_content_protection(struct proc *p, int cmd, int scope, int policy, struct _iopol_param_t *iop_param);

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
iopolicysys(struct proc *p, struct iopolicysys_args *uap, int32_t *retval)
{
	int     error = 0;
	struct _iopol_param_t iop_param;

	if ((error = copyin(uap->arg, &iop_param, sizeof(iop_param))) != 0) {
		goto out;
	}

	switch (iop_param.iop_iotype) {
	case IOPOL_TYPE_DISK:
		error = iopolicysys_disk(p, uap->cmd, iop_param.iop_scope, iop_param.iop_policy, &iop_param);
		if (error == EIDRM) {
			*retval = -2;
			error = 0;
		}
		if (error) {
			goto out;
		}
		break;
	case IOPOL_TYPE_VFS_HFS_CASE_SENSITIVITY:
		error = iopolicysys_vfs_hfs_case_sensitivity(p, uap->cmd, iop_param.iop_scope, iop_param.iop_policy, &iop_param);
		if (error) {
			goto out;
		}
		break;
	case IOPOL_TYPE_VFS_ATIME_UPDATES:
		error = iopolicysys_vfs_atime_updates(p, uap->cmd, iop_param.iop_scope, iop_param.iop_policy, &iop_param);
		if (error) {
			goto out;
		}
		break;
	case IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES:
		error = iopolicysys_vfs_materialize_dataless_files(p, uap->cmd, iop_param.iop_scope, iop_param.iop_policy, &iop_param);
		if (error) {
			goto out;
		}
		break;
	case IOPOL_TYPE_VFS_STATFS_NO_DATA_VOLUME:
		error = iopolicysys_vfs_statfs_no_data_volume(p, uap->cmd, iop_param.iop_scope, iop_param.iop_policy, &iop_param);
		if (error) {
			goto out;
		}
		break;
	case IOPOL_TYPE_VFS_TRIGGER_RESOLVE:
		error = iopolicysys_vfs_trigger_resolve(p, uap->cmd, iop_param.iop_scope, iop_param.iop_policy, &iop_param);
		if (error) {
			goto out;
		}
		break;
	case IOPOL_TYPE_VFS_IGNORE_CONTENT_PROTECTION:
		error = iopolicysys_vfs_ignore_content_protection(p, uap->cmd, iop_param.iop_scope, iop_param.iop_policy, &iop_param);
		if (error) {
			goto out;
		}
		break;
	default:
		error = EINVAL;
		goto out;
	}

	/* Individual iotype handlers are expected to update iop_param, if requested with a GET command */
	if (uap->cmd == IOPOL_CMD_GET) {
		error = copyout((caddr_t)&iop_param, uap->arg, sizeof(iop_param));
		if (error) {
			goto out;
		}
	}

out:
	return error;
}

static int
iopolicysys_disk(struct proc *p __unused, int cmd, int scope, int policy, struct _iopol_param_t *iop_param)
{
	int                     error = 0;
	thread_t        thread;
	int                     policy_flavor;

	/* Validate scope */
	switch (scope) {
	case IOPOL_SCOPE_PROCESS:
		thread = THREAD_NULL;
		policy_flavor = TASK_POLICY_IOPOL;
		break;

	case IOPOL_SCOPE_THREAD:
		thread = current_thread();
		policy_flavor = TASK_POLICY_IOPOL;

		/* Not allowed to combine QoS and (non-PASSIVE) IO policy, doing so strips the QoS */
		if (cmd == IOPOL_CMD_SET && thread_has_qos_policy(thread)) {
			switch (policy) {
			case IOPOL_DEFAULT:
			case IOPOL_PASSIVE:
				break;
			case IOPOL_UTILITY:
			case IOPOL_THROTTLE:
			case IOPOL_IMPORTANT:
			case IOPOL_STANDARD:
				if (!thread_is_static_param(thread)) {
					thread_remove_qos_policy(thread);
					/*
					 * This is not an error case, this is to return a marker to user-space that
					 * we stripped the thread of its QoS class.
					 */
					error = EIDRM;
					break;
				}
				OS_FALLTHROUGH;
			default:
				error = EINVAL;
				goto out;
			}
		}
		break;

	case IOPOL_SCOPE_DARWIN_BG:
#if !defined(XNU_TARGET_OS_OSX)
		/* We don't want this on platforms outside of macOS as BG is always IOPOL_THROTTLE */
		error = ENOTSUP;
		goto out;
#else /* !defined(XNU_TARGET_OS_OSX) */
		thread = THREAD_NULL;
		policy_flavor = TASK_POLICY_DARWIN_BG_IOPOL;
		break;
#endif /* !defined(XNU_TARGET_OS_OSX) */

	default:
		error = EINVAL;
		goto out;
	}

	/* Validate policy */
	if (cmd == IOPOL_CMD_SET) {
		switch (policy) {
		case IOPOL_DEFAULT:
			if (scope == IOPOL_SCOPE_DARWIN_BG) {
				/* the current default BG throttle level is UTILITY */
				policy = IOPOL_UTILITY;
			} else {
				policy = IOPOL_IMPORTANT;
			}
			break;
		case IOPOL_UTILITY:
		/* fall-through */
		case IOPOL_THROTTLE:
			/* These levels are OK */
			break;
		case IOPOL_IMPORTANT:
		/* fall-through */
		case IOPOL_STANDARD:
		/* fall-through */
		case IOPOL_PASSIVE:
			if (scope == IOPOL_SCOPE_DARWIN_BG) {
				/* These levels are invalid for BG */
				error = EINVAL;
				goto out;
			} else {
				/* OK for other scopes */
			}
			break;
		default:
			error = EINVAL;
			goto out;
		}
	}

	/* Perform command */
	switch (cmd) {
	case IOPOL_CMD_SET:
		if (thread != THREAD_NULL) {
			proc_set_thread_policy(thread, TASK_POLICY_INTERNAL, policy_flavor, policy);
		} else {
			proc_set_task_policy(current_task(), TASK_POLICY_INTERNAL, policy_flavor, policy);
		}
		break;
	case IOPOL_CMD_GET:
		if (thread != THREAD_NULL) {
			policy = proc_get_thread_policy(thread, TASK_POLICY_INTERNAL, policy_flavor);
		} else {
			policy = proc_get_task_policy(current_task(), TASK_POLICY_INTERNAL, policy_flavor);
		}
		iop_param->iop_policy = policy;
		break;
	default:
		error = EINVAL;         /* unknown command */
		break;
	}

out:
	return error;
}

static int
iopolicysys_vfs_hfs_case_sensitivity(struct proc *p, int cmd, int scope, int policy, struct _iopol_param_t *iop_param)
{
	int                     error = 0;

	/* Validate scope */
	switch (scope) {
	case IOPOL_SCOPE_PROCESS:
		/* Only process OK */
		break;
	default:
		error = EINVAL;
		goto out;
	}

	/* Validate policy */
	if (cmd == IOPOL_CMD_SET) {
		switch (policy) {
		case IOPOL_VFS_HFS_CASE_SENSITIVITY_DEFAULT:
		/* fall-through */
		case IOPOL_VFS_HFS_CASE_SENSITIVITY_FORCE_CASE_SENSITIVE:
			/* These policies are OK */
			break;
		default:
			error = EINVAL;
			goto out;
		}
	}

	/* Perform command */
	switch (cmd) {
	case IOPOL_CMD_SET:
		if (0 == kauth_cred_issuser(kauth_cred_get())) {
			/* If it's a non-root process, it needs to have the entitlement to set the policy */
			boolean_t entitled = FALSE;
			entitled = IOTaskHasEntitlement(current_task(), "com.apple.private.iopol.case_sensitivity");
			if (!entitled) {
				error = EPERM;
				goto out;
			}
		}

		switch (policy) {
		case IOPOL_VFS_HFS_CASE_SENSITIVITY_DEFAULT:
			OSBitAndAtomic16(~((uint32_t)P_VFS_IOPOLICY_FORCE_HFS_CASE_SENSITIVITY), &p->p_vfs_iopolicy);
			break;
		case IOPOL_VFS_HFS_CASE_SENSITIVITY_FORCE_CASE_SENSITIVE:
			OSBitOrAtomic16((uint32_t)P_VFS_IOPOLICY_FORCE_HFS_CASE_SENSITIVITY, &p->p_vfs_iopolicy);
			break;
		default:
			error = EINVAL;
			goto out;
		}

		break;
	case IOPOL_CMD_GET:
		iop_param->iop_policy = (p->p_vfs_iopolicy & P_VFS_IOPOLICY_FORCE_HFS_CASE_SENSITIVITY)
		    ? IOPOL_VFS_HFS_CASE_SENSITIVITY_FORCE_CASE_SENSITIVE
		    : IOPOL_VFS_HFS_CASE_SENSITIVITY_DEFAULT;
		break;
	default:
		error = EINVAL;         /* unknown command */
		break;
	}

out:
	return error;
}

static inline int
get_thread_atime_policy(struct uthread *ut)
{
	return (ut->uu_flag & UT_ATIME_UPDATE) ? IOPOL_ATIME_UPDATES_OFF : IOPOL_ATIME_UPDATES_DEFAULT;
}

static inline void
set_thread_atime_policy(struct uthread *ut, int policy)
{
	if (policy == IOPOL_ATIME_UPDATES_OFF) {
		ut->uu_flag |= UT_ATIME_UPDATE;
	} else {
		ut->uu_flag &= ~UT_ATIME_UPDATE;
	}
}

static inline void
set_task_atime_policy(struct proc *p, int policy)
{
	if (policy == IOPOL_ATIME_UPDATES_OFF) {
		OSBitOrAtomic16((uint16_t)P_VFS_IOPOLICY_ATIME_UPDATES, &p->p_vfs_iopolicy);
	} else {
		OSBitAndAtomic16(~((uint16_t)P_VFS_IOPOLICY_ATIME_UPDATES), &p->p_vfs_iopolicy);
	}
}

static inline int
get_task_atime_policy(struct proc *p)
{
	return (p->p_vfs_iopolicy & P_VFS_IOPOLICY_ATIME_UPDATES) ? IOPOL_ATIME_UPDATES_OFF : IOPOL_ATIME_UPDATES_DEFAULT;
}

static int
iopolicysys_vfs_atime_updates(struct proc *p __unused, int cmd, int scope, int policy, struct _iopol_param_t *iop_param)
{
	int                     error = 0;
	thread_t                thread;

	/* Validate scope */
	switch (scope) {
	case IOPOL_SCOPE_THREAD:
		thread = current_thread();
		break;
	case IOPOL_SCOPE_PROCESS:
		thread = THREAD_NULL;
		break;
	default:
		error = EINVAL;
		goto out;
	}

	/* Validate policy */
	if (cmd == IOPOL_CMD_SET) {
		switch (policy) {
		case IOPOL_ATIME_UPDATES_DEFAULT:
		case IOPOL_ATIME_UPDATES_OFF:
			break;
		default:
			error = EINVAL;
			goto out;
		}
	}

	/* Perform command */
	switch (cmd) {
	case IOPOL_CMD_SET:
		if (thread != THREAD_NULL) {
			set_thread_atime_policy(get_bsdthread_info(thread), policy);
		} else {
			set_task_atime_policy(p, policy);
		}
		break;
	case IOPOL_CMD_GET:
		if (thread != THREAD_NULL) {
			policy = get_thread_atime_policy(get_bsdthread_info(thread));
		} else {
			policy = get_task_atime_policy(p);
		}
		iop_param->iop_policy = policy;
		break;
	default:
		error = EINVAL;         /* unknown command */
		break;
	}

out:
	return error;
}

static inline int
get_thread_materialize_policy(struct uthread *ut)
{
	if (ut->uu_flag & UT_NSPACE_NODATALESSFAULTS) {
		return IOPOL_MATERIALIZE_DATALESS_FILES_OFF;
	} else if (ut->uu_flag & UT_NSPACE_FORCEDATALESSFAULTS) {
		return IOPOL_MATERIALIZE_DATALESS_FILES_ON;
	}
	/* Default thread behavior is "inherit process behavior". */
	return IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT;
}

static inline void
set_thread_materialize_policy(struct uthread *ut, int policy)
{
	if (policy == IOPOL_MATERIALIZE_DATALESS_FILES_OFF) {
		ut->uu_flag &= ~UT_NSPACE_FORCEDATALESSFAULTS;
		ut->uu_flag |= UT_NSPACE_NODATALESSFAULTS;
	} else if (policy == IOPOL_MATERIALIZE_DATALESS_FILES_ON) {
		ut->uu_flag &= ~UT_NSPACE_NODATALESSFAULTS;
		ut->uu_flag |= UT_NSPACE_FORCEDATALESSFAULTS;
	} else {
		ut->uu_flag &= ~(UT_NSPACE_NODATALESSFAULTS | UT_NSPACE_FORCEDATALESSFAULTS);
	}
}

static inline void
set_proc_materialize_policy(struct proc *p, int policy)
{
	if (policy == IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT) {
		/*
		 * Caller has specified "use the default policy".
		 * The default policy is to NOT materialize dataless
		 * files.
		 */
		policy = IOPOL_MATERIALIZE_DATALESS_FILES_OFF;
	}
	if (policy == IOPOL_MATERIALIZE_DATALESS_FILES_ON) {
		OSBitOrAtomic16((uint16_t)P_VFS_IOPOLICY_MATERIALIZE_DATALESS_FILES, &p->p_vfs_iopolicy);
	} else {
		OSBitAndAtomic16(~((uint16_t)P_VFS_IOPOLICY_MATERIALIZE_DATALESS_FILES), &p->p_vfs_iopolicy);
	}
}

static int
get_proc_materialize_policy(struct proc *p)
{
	return (p->p_vfs_iopolicy & P_VFS_IOPOLICY_MATERIALIZE_DATALESS_FILES) ? IOPOL_MATERIALIZE_DATALESS_FILES_ON : IOPOL_MATERIALIZE_DATALESS_FILES_OFF;
}

static int
iopolicysys_vfs_materialize_dataless_files(struct proc *p __unused, int cmd, int scope, int policy, struct _iopol_param_t *iop_param)
{
	int                     error = 0;
	thread_t                thread;

	/* Validate scope */
	switch (scope) {
	case IOPOL_SCOPE_THREAD:
		thread = current_thread();
		break;
	case IOPOL_SCOPE_PROCESS:
		thread = THREAD_NULL;
		break;
	default:
		error = EINVAL;
		goto out;
	}

	/* Validate policy */
	if (cmd == IOPOL_CMD_SET) {
		switch (policy) {
		case IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT:
		case IOPOL_MATERIALIZE_DATALESS_FILES_OFF:
		case IOPOL_MATERIALIZE_DATALESS_FILES_ON:
			break;
		default:
			error = EINVAL;
			goto out;
		}
	}

	/* Perform command */
	switch (cmd) {
	case IOPOL_CMD_SET:
		if (thread != THREAD_NULL) {
			set_thread_materialize_policy(get_bsdthread_info(thread), policy);
		} else {
			set_proc_materialize_policy(p, policy);
		}
		break;
	case IOPOL_CMD_GET:
		if (thread != THREAD_NULL) {
			policy = get_thread_materialize_policy(get_bsdthread_info(thread));
		} else {
			policy = get_proc_materialize_policy(p);
		}
		iop_param->iop_policy = policy;
		break;
	default:
		error = EINVAL;         /* unknown command */
		break;
	}

out:
	return error;
}

static int
iopolicysys_vfs_statfs_no_data_volume(struct proc *p __unused, int cmd,
    int scope, int policy, struct _iopol_param_t *iop_param)
{
	int error = 0;

	/* Validate scope */
	switch (scope) {
	case IOPOL_SCOPE_PROCESS:
		/* Only process OK */
		break;
	default:
		error = EINVAL;
		goto out;
	}

	/* Validate policy */
	if (cmd == IOPOL_CMD_SET) {
		switch (policy) {
		case IOPOL_VFS_STATFS_NO_DATA_VOLUME_DEFAULT:
		/* fall-through */
		case IOPOL_VFS_STATFS_FORCE_NO_DATA_VOLUME:
			/* These policies are OK */
			break;
		default:
			error = EINVAL;
			goto out;
		}
	}

	/* Perform command */
	switch (cmd) {
	case IOPOL_CMD_SET:
		if (0 == kauth_cred_issuser(kauth_cred_get())) {
			/* If it's a non-root process, it needs to have the entitlement to set the policy */
			boolean_t entitled = FALSE;
			entitled = IOTaskHasEntitlement(current_task(), "com.apple.private.iopol.case_sensitivity");
			if (!entitled) {
				error = EPERM;
				goto out;
			}
		}

		switch (policy) {
		case IOPOL_VFS_STATFS_NO_DATA_VOLUME_DEFAULT:
			OSBitAndAtomic16(~((uint32_t)P_VFS_IOPOLICY_STATFS_NO_DATA_VOLUME), &p->p_vfs_iopolicy);
			break;
		case IOPOL_VFS_STATFS_FORCE_NO_DATA_VOLUME:
			OSBitOrAtomic16((uint32_t)P_VFS_IOPOLICY_STATFS_NO_DATA_VOLUME, &p->p_vfs_iopolicy);
			break;
		default:
			error = EINVAL;
			goto out;
		}

		break;
	case IOPOL_CMD_GET:
		iop_param->iop_policy = (p->p_vfs_iopolicy & P_VFS_IOPOLICY_STATFS_NO_DATA_VOLUME)
		    ? IOPOL_VFS_STATFS_FORCE_NO_DATA_VOLUME
		    : IOPOL_VFS_STATFS_NO_DATA_VOLUME_DEFAULT;
		break;
	default:
		error = EINVAL;         /* unknown command */
		break;
	}

out:
	return error;
}

static int
iopolicysys_vfs_trigger_resolve(struct proc *p __unused, int cmd,
    int scope, int policy, struct _iopol_param_t *iop_param)
{
	int error = 0;

	/* Validate scope */
	switch (scope) {
	case IOPOL_SCOPE_PROCESS:
		/* Only process OK */
		break;
	default:
		error = EINVAL;
		goto out;
	}

	/* Validate policy */
	if (cmd == IOPOL_CMD_SET) {
		switch (policy) {
		case IOPOL_VFS_TRIGGER_RESOLVE_DEFAULT:
		/* fall-through */
		case IOPOL_VFS_TRIGGER_RESOLVE_OFF:
			/* These policies are OK */
			break;
		default:
			error = EINVAL;
			goto out;
		}
	}

	/* Perform command */
	switch (cmd) {
	case IOPOL_CMD_SET:
		switch (policy) {
		case IOPOL_VFS_TRIGGER_RESOLVE_DEFAULT:
			OSBitAndAtomic16(~((uint32_t)P_VFS_IOPOLICY_TRIGGER_RESOLVE_DISABLE), &p->p_vfs_iopolicy);
			break;
		case IOPOL_VFS_TRIGGER_RESOLVE_OFF:
			OSBitOrAtomic16((uint32_t)P_VFS_IOPOLICY_TRIGGER_RESOLVE_DISABLE, &p->p_vfs_iopolicy);
			break;
		default:
			error = EINVAL;
			goto out;
		}

		break;
	case IOPOL_CMD_GET:
		iop_param->iop_policy = (p->p_vfs_iopolicy & P_VFS_IOPOLICY_TRIGGER_RESOLVE_DISABLE)
		    ? IOPOL_VFS_TRIGGER_RESOLVE_OFF
		    : IOPOL_VFS_TRIGGER_RESOLVE_DEFAULT;
		break;
	default:
		error = EINVAL;         /* unknown command */
		break;
	}

out:
	return error;
}

static int
iopolicysys_vfs_ignore_content_protection(struct proc *p, int cmd, int scope,
    int policy, struct _iopol_param_t *iop_param)
{
	int error = 0;

	/* Validate scope */
	switch (scope) {
	case IOPOL_SCOPE_PROCESS:
		/* Only process OK */
		break;
	default:
		error = EINVAL;
		goto out;
	}

	/* Validate policy */
	if (cmd == IOPOL_CMD_SET) {
		switch (policy) {
		case IOPOL_VFS_CONTENT_PROTECTION_DEFAULT:
			OS_FALLTHROUGH;
		case IOPOL_VFS_CONTENT_PROTECTION_IGNORE:
			/* These policies are OK */
			break;
		default:
			error = EINVAL;
			goto out;
		}
	}

	/* Perform command */
	switch (cmd) {
	case IOPOL_CMD_SET:
		if (0 == kauth_cred_issuser(kauth_cred_get())) {
			/* If it's a non-root process, it needs to have the entitlement to set the policy */
			boolean_t entitled = FALSE;
			entitled = IOTaskHasEntitlement(current_task(), "com.apple.private.iopol.case_sensitivity");
			if (!entitled) {
				error = EPERM;
				goto out;
			}
		}

		switch (policy) {
		case IOPOL_VFS_CONTENT_PROTECTION_DEFAULT:
			os_atomic_andnot(&p->p_vfs_iopolicy, P_VFS_IOPOLICY_IGNORE_CONTENT_PROTECTION, relaxed);
			break;
		case IOPOL_VFS_CONTENT_PROTECTION_IGNORE:
			os_atomic_or(&p->p_vfs_iopolicy, P_VFS_IOPOLICY_IGNORE_CONTENT_PROTECTION, relaxed);
			break;
		default:
			error = EINVAL;
			goto out;
		}

		break;
	case IOPOL_CMD_GET:
		iop_param->iop_policy = (os_atomic_load(&p->p_vfs_iopolicy, relaxed) & P_VFS_IOPOLICY_IGNORE_CONTENT_PROTECTION)
		    ? IOPOL_VFS_CONTENT_PROTECTION_IGNORE
		    : IOPOL_VFS_CONTENT_PROTECTION_DEFAULT;
		break;
	default:
		error = EINVAL;         /* unknown command */
		break;
	}

out:
	return error;
}

/* BSD call back function for task_policy networking changes */
void
proc_apply_task_networkbg(void * bsd_info, thread_t thread)
{
	assert(bsd_info != PROC_NULL);

	pid_t pid = proc_pid((proc_t)bsd_info);

	proc_t p = proc_find(pid);

	if (p != PROC_NULL) {
		assert(p == (proc_t)bsd_info);

		do_background_socket(p, thread);
		proc_rele(p);
	}
}

void
gather_rusage_info(proc_t p, rusage_info_current *ru, int flavor)
{
	struct rusage_info_child *ri_child;

	assert(p->p_stats != NULL);
	memset(ru, 0, sizeof(*ru));
	switch (flavor) {
	case RUSAGE_INFO_V5:
#if !XNU_TARGET_OS_OSX && __has_feature(ptrauth_calls)
		if (vm_shared_region_is_reslide(p->task)) {
			ru->ri_flags |= RU_PROC_RUNS_RESLIDE;
		}
#endif /* !XNU_TARGET_OS_OSX && __has_feature(ptrauth_calls) */
		OS_FALLTHROUGH;
	case RUSAGE_INFO_V4:
		ru->ri_logical_writes = get_task_logical_writes(p->task, FALSE);
		ru->ri_lifetime_max_phys_footprint = get_task_phys_footprint_lifetime_max(p->task);
#if CONFIG_LEDGER_INTERVAL_MAX
		ru->ri_interval_max_phys_footprint = get_task_phys_footprint_interval_max(p->task, FALSE);
#endif
		fill_task_monotonic_rusage(p->task, ru);
		OS_FALLTHROUGH;

	case RUSAGE_INFO_V3:
		fill_task_qos_rusage(p->task, ru);
		fill_task_billed_usage(p->task, ru);
		OS_FALLTHROUGH;

	case RUSAGE_INFO_V2:
		fill_task_io_rusage(p->task, ru);
		OS_FALLTHROUGH;

	case RUSAGE_INFO_V1:
		/*
		 * p->p_stats->ri_child statistics are protected under proc lock.
		 */
		proc_lock(p);

		ri_child = &(p->p_stats->ri_child);
		ru->ri_child_user_time = ri_child->ri_child_user_time;
		ru->ri_child_system_time = ri_child->ri_child_system_time;
		ru->ri_child_pkg_idle_wkups = ri_child->ri_child_pkg_idle_wkups;
		ru->ri_child_interrupt_wkups = ri_child->ri_child_interrupt_wkups;
		ru->ri_child_pageins = ri_child->ri_child_pageins;
		ru->ri_child_elapsed_abstime = ri_child->ri_child_elapsed_abstime;

		proc_unlock(p);
		OS_FALLTHROUGH;

	case RUSAGE_INFO_V0:
		proc_getexecutableuuid(p, (unsigned char *)&ru->ri_uuid, sizeof(ru->ri_uuid));
		fill_task_rusage(p->task, ru);
		ru->ri_proc_start_abstime = p->p_stats->ps_start;
	}
}

int
proc_get_rusage(proc_t p, int flavor, user_addr_t buffer, __unused int is_zombie)
{
	rusage_info_current ri_current = {};

	int error = 0;
	size_t size = 0;

	switch (flavor) {
	case RUSAGE_INFO_V0:
		size = sizeof(struct rusage_info_v0);
		break;

	case RUSAGE_INFO_V1:
		size = sizeof(struct rusage_info_v1);
		break;

	case RUSAGE_INFO_V2:
		size = sizeof(struct rusage_info_v2);
		break;

	case RUSAGE_INFO_V3:
		size = sizeof(struct rusage_info_v3);
		break;

	case RUSAGE_INFO_V4:
		size = sizeof(struct rusage_info_v4);
		break;

	case RUSAGE_INFO_V5:
		size = sizeof(struct rusage_info_v5);
		break;
	default:
		return EINVAL;
	}

	if (size == 0) {
		return EINVAL;
	}

	/*
	 * If task is still alive, collect info from the live task itself.
	 * Otherwise, look to the cached info in the zombie proc.
	 */
	if (p->p_ru == NULL) {
		gather_rusage_info(p, &ri_current, flavor);
		ri_current.ri_proc_exit_abstime = 0;
		error = copyout(&ri_current, buffer, size);
	} else {
		ri_current = p->p_ru->ri;
		error = copyout(&p->p_ru->ri, buffer, size);
	}

	return error;
}

static int
mach_to_bsd_rv(int mach_rv)
{
	int bsd_rv = 0;

	switch (mach_rv) {
	case KERN_SUCCESS:
		bsd_rv = 0;
		break;
	case KERN_INVALID_ARGUMENT:
		bsd_rv = EINVAL;
		break;
	default:
		panic("unknown error %#x", mach_rv);
	}

	return bsd_rv;
}

/*
 * Resource limit controls
 *
 * uap->flavor available flavors:
 *
 *     RLIMIT_WAKEUPS_MONITOR
 *     RLIMIT_CPU_USAGE_MONITOR
 *     RLIMIT_THREAD_CPULIMITS
 *     RLIMIT_FOOTPRINT_INTERVAL
 */
int
proc_rlimit_control(__unused struct proc *p, struct proc_rlimit_control_args *uap, __unused int32_t *retval)
{
	proc_t  targetp;
	int     error = 0;
	struct  proc_rlimit_control_wakeupmon wakeupmon_args;
	uint32_t cpumon_flags;
	uint32_t cpulimits_flags;
	kauth_cred_t my_cred, target_cred;
#if CONFIG_LEDGER_INTERVAL_MAX
	uint32_t footprint_interval_flags;
	uint64_t interval_max_footprint;
#endif /* CONFIG_LEDGER_INTERVAL_MAX */

	/* -1 implicitly means our own process (perhaps even the current thread for per-thread attributes) */
	if (uap->pid == -1) {
		targetp = proc_self();
	} else {
		targetp = proc_find(uap->pid);
	}

	/* proc_self() can return NULL for an exiting process */
	if (targetp == PROC_NULL) {
		return ESRCH;
	}

	my_cred = kauth_cred_get();
	target_cred = kauth_cred_proc_ref(targetp);

	if (!kauth_cred_issuser(my_cred) && kauth_cred_getruid(my_cred) &&
	    kauth_cred_getuid(my_cred) != kauth_cred_getuid(target_cred) &&
	    kauth_cred_getruid(my_cred) != kauth_cred_getuid(target_cred)) {
		proc_rele(targetp);
		kauth_cred_unref(&target_cred);
		return EACCES;
	}

	switch (uap->flavor) {
	case RLIMIT_WAKEUPS_MONITOR:
		if ((error = copyin(uap->arg, &wakeupmon_args, sizeof(wakeupmon_args))) != 0) {
			break;
		}
		if ((error = mach_to_bsd_rv(task_wakeups_monitor_ctl(targetp->task, &wakeupmon_args.wm_flags,
		    &wakeupmon_args.wm_rate))) != 0) {
			break;
		}
		error = copyout(&wakeupmon_args, uap->arg, sizeof(wakeupmon_args));
		break;
	case RLIMIT_CPU_USAGE_MONITOR:
		cpumon_flags = (uint32_t)uap->arg; // XXX temporarily stashing flags in argp (12592127)
		error = mach_to_bsd_rv(task_cpu_usage_monitor_ctl(targetp->task, &cpumon_flags));
		break;
	case RLIMIT_THREAD_CPULIMITS:
		cpulimits_flags = (uint32_t)uap->arg; // only need a limited set of bits, pass in void * argument

		if (uap->pid != -1) {
			error = EINVAL;
			break;
		}

		uint8_t percent = 0;
		uint32_t ms_refill = 0;
		uint64_t ns_refill;

		percent = (uint8_t)(cpulimits_flags & 0xffU);                                   /* low 8 bits for percent */
		ms_refill = (cpulimits_flags >> 8) & 0xffffff;          /* next 24 bits represent ms refill value */
		if (percent >= 100) {
			error = EINVAL;
			break;
		}

		ns_refill = ((uint64_t)ms_refill) * NSEC_PER_MSEC;

		error = mach_to_bsd_rv(thread_set_cpulimit(THREAD_CPULIMIT_BLOCK, percent, ns_refill));
		break;

#if CONFIG_LEDGER_INTERVAL_MAX
	case RLIMIT_FOOTPRINT_INTERVAL:
		footprint_interval_flags = (uint32_t)uap->arg; // XXX temporarily stashing flags in argp (12592127)
		/*
		 * There is currently only one option for this flavor.
		 */
		if ((footprint_interval_flags & FOOTPRINT_INTERVAL_RESET) == 0) {
			error = EINVAL;
			break;
		}
		interval_max_footprint = get_task_phys_footprint_interval_max(targetp->task, TRUE);
		break;
#endif /* CONFIG_LEDGER_INTERVAL_MAX */
	default:
		error = EINVAL;
		break;
	}

	proc_rele(targetp);
	kauth_cred_unref(&target_cred);

	/*
	 * Return value from this function becomes errno to userland caller.
	 */
	return error;
}

/*
 * Return the current amount of CPU consumed by this thread (in either user or kernel mode)
 */
int
thread_selfusage(struct proc *p __unused, struct thread_selfusage_args *uap __unused, uint64_t *retval)
{
	uint64_t runtime;

	runtime = thread_get_runtime_self();
	*retval = runtime;

	return 0;
}

#if !MONOTONIC
int
thread_selfcounts(__unused struct proc *p, __unused struct thread_selfcounts_args *uap, __unused int *ret_out)
{
	return ENOTSUP;
}
#endif /* !MONOTONIC */
