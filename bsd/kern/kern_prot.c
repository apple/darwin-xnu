/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1990, 1991, 1993
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
 *	@(#)kern_prot.c	8.9 (Berkeley) 2/14/95
 */

/*
 * System calls related to processes and protection
 */

#include <sys/param.h>
#include <sys/acct.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/kauth.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/malloc.h>

#include <bsm/audit_kernel.h>

#include <sys/mount_internal.h>
#include <sys/sysproto.h>
#include <mach/message.h>
#include <mach/host_security.h>

#include <kern/host.h>

int groupmember(gid_t gid, kauth_cred_t cred);
int is_suser(void);
int is_suser1(void);

extern int prepare_profile_database(int user);

/*
 * setprivexec:  (dis)allow this process to hold
 * task, thread, or execption ports of processes about to exec.
 */
int
setprivexec(struct proc *p, struct setprivexec_args *uap, register_t *retval)
{
	AUDIT_ARG(value, uap->flag);
	*retval = p->p_debugger;
	p->p_debugger = (uap->flag != 0);
	return(0);
}

/* ARGSUSED */
int
getpid(struct proc *p, __unused struct getpid_args *uap, register_t *retval)
{

	*retval = p->p_pid;
	return (0);
}

/* ARGSUSED */
int
getppid(struct proc *p, __unused struct getppid_args *uap, register_t *retval)
{

	*retval = p->p_pptr->p_pid;
	return (0);
}

/* Get process group ID; note that POSIX getpgrp takes no parameter */
int
getpgrp(struct proc *p, __unused struct getpgrp_args *uap, register_t *retval)
{

	*retval = p->p_pgrp->pg_id;
	return (0);
}

/* Get an arbitary pid's process group id */
int
getpgid(struct proc *p, struct getpgid_args *uap, register_t *retval)
{
	struct proc *pt;

	pt = p;
	if (uap->pid == 0)
		goto found;

	if ((pt = pfind(uap->pid)) == 0)
		return (ESRCH);
found:
	*retval = pt->p_pgrp->pg_id;
	return (0);
}

/*
 * Get an arbitary pid's session id.
 */

int
getsid(struct proc *p, struct getsid_args *uap, register_t *retval)
{
	struct proc *pt;

	pt = p;
	if (uap->pid == 0)
		goto found;

	if ((pt = pfind(uap->pid)) == 0)
		return (ESRCH);
found:
	*retval = pt->p_session->s_sid;
	return (0);
}

/* ARGSUSED */
int
getuid(__unused struct proc *p, __unused struct getuid_args *uap, register_t *retval)
{

 	*retval = kauth_getruid();
	return (0);
}

/* ARGSUSED */
int
geteuid(__unused struct proc *p, __unused struct geteuid_args *uap, register_t *retval)
{

 	*retval = kauth_getuid();
	return (0);
}

/*
 * Return the per-thread override identity.
 */
int
gettid(__unused struct proc *p, struct gettid_args *uap, register_t *retval)
{
	struct uthread *uthread = get_bsdthread_info(current_thread());
	int	error;

	/*
	 * If this thread is not running with an override identity, we can't
	 * return one to the caller, so return an error instead.
	 */
	if (!(uthread->uu_flag & UT_SETUID))
		return (ESRCH);

	if ((error = suword(uap->uidp, uthread->uu_ucred->cr_ruid)))
		return (error);
	if ((error = suword(uap->gidp, uthread->uu_ucred->cr_rgid)))
		return (error);

	*retval = 0;
	return (0);
}

/* ARGSUSED */
int
getgid(__unused struct proc *p, __unused struct getgid_args *uap, register_t *retval)
{

	*retval = kauth_getrgid();
	return (0);
}

/*
 * Get effective group ID.  The "egid" is groups[0], and could be obtained
 * via getgroups.  This syscall exists because it is somewhat painful to do
 * correctly in a library function.
 */
/* ARGSUSED */
int
getegid(struct proc *p, __unused struct getegid_args *uap, register_t *retval)
{

	*retval = kauth_getgid();
	return (0);
}

int
getgroups(__unused struct proc *p, struct getgroups_args *uap, register_t *retval)
{
	register int ngrp;
	int error;
	kauth_cred_t cred;

	/* grab reference while we muck around with the credential */
	cred = kauth_cred_get_with_ref();

	if ((ngrp = uap->gidsetsize) == 0) {
		*retval = cred->cr_ngroups;
		kauth_cred_rele(cred);
		return (0);
	}
	if (ngrp < cred->cr_ngroups) {
		kauth_cred_rele(cred);
		return (EINVAL);
	}
	ngrp = cred->cr_ngroups;
	if ((error = copyout((caddr_t)cred->cr_groups,
	    				uap->gidset, 
	    				ngrp * sizeof(gid_t)))) {
		kauth_cred_rele(cred);
		return (error);
	}
	kauth_cred_rele(cred);
	*retval = ngrp;
	return (0);
}

/*
 * Return the per-thread/per-process supplementary groups list.
 */
#warning XXX implement
int
getsgroups(__unused struct proc *p, __unused struct getsgroups_args *uap, __unused register_t *retval)
{
	/* XXX implement */
	return(ENOTSUP);
}

/*
 * Return the per-thread/per-process whiteout groups list.
 */
#warning XXX implement
int
getwgroups(__unused struct proc *p, __unused struct getwgroups_args *uap, __unused register_t *retval)
{
	/* XXX implement */
	return(ENOTSUP);
}

/* ARGSUSED */
int
setsid(struct proc *p, __unused struct setsid_args *uap, register_t *retval)
{

	if (p->p_pgid == p->p_pid || pgfind(p->p_pid) || p->p_flag & P_INVFORK) {
		return (EPERM);
	} else {
		(void)enterpgrp(p, p->p_pid, 1);
		*retval = p->p_pid;
		return (0);
	}
}

/*
 * set process group (setpgid/old setpgrp)
 *
 * caller does setpgid(targpid, targpgid)
 *
 * pid must be caller or child of caller (ESRCH)
 * if a child
 *	pid must be in same session (EPERM)
 *	pid can't have done an exec (EACCES)
 * ig pgid is -ve return EINVAL (as per SUV spec)
 * if pgid != pid
 * 	there must exist some pid in same session having pgid (EPERM)
 * pid must not be session leader (EPERM)
 */
/* ARGSUSED */
int
setpgid(struct proc *curp, register struct setpgid_args *uap, __unused register_t *retval)
{
	register struct proc *targp;		/* target process */
	register struct pgrp *pgrp;		/* target pgrp */

	if (uap->pid != 0 && uap->pid != curp->p_pid) {
		if ((targp = pfind(uap->pid)) == 0 || !inferior(targp))
			return (ESRCH);
		if (targp->p_session != curp->p_session)
			return (EPERM);
		if (targp->p_flag & P_EXEC)
			return (EACCES);
	} else
		targp = curp;
	if (SESS_LEADER(targp))
		return (EPERM);
	if (uap->pgid < 0)
		return(EINVAL);
	if (uap->pgid == 0)
		uap->pgid = targp->p_pid;
	else if (uap->pgid != targp->p_pid)
		if ((pgrp = pgfind(uap->pgid)) == 0 ||
		    pgrp->pg_session != curp->p_session)
			return (EPERM);
	return (enterpgrp(targp, uap->pgid, 0));
}

int
issetugid(struct proc *p, __unused struct issetugid_args *uap, register_t *retval)
{
	/*
	 * Note: OpenBSD sets a P_SUGIDEXEC flag set at execve() time,
	 * we use P_SUGID because we consider changing the owners as
	 * "tainting" as well.
	 * This is significant for procs that start as root and "become"
	 * a user without an exec - programs cannot know *everything*
	 * that libc *might* have put in their data segment.
	 */

	*retval = (p->p_flag & P_SUGID) ? 1 : 0;
	return (0);
}

/* ARGSUSED */
int
setuid(struct proc *p, struct setuid_args *uap, __unused register_t *retval)
{
	register uid_t uid;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	uid = uap->uid;
	AUDIT_ARG(uid, uid, 0, 0, 0);
	if (uid != p->p_ucred->cr_ruid &&
	    (error = suser(p->p_ucred, &p->p_acflag)))
		return (error);
	/*
	 * Everything's okay, do it.
	 * Transfer proc count to new user.
	 * Copy credentials so other references do not see our changes.
	 */

	/* prepare app access profile files */
	prepare_profile_database(uap->uid);
	(void)chgproccnt(kauth_getruid(), -1);
	(void)chgproccnt(uid, 1);

	/* get current credential and take a reference while we muck with it */
	for (;;) {
		my_cred = kauth_cred_proc_ref(p);
		
		/* 
		 * set the credential with new info.  If there is no change we get back 
		 * the same credential we passed in.
		 */
		my_new_cred = kauth_cred_setuid(my_cred, uid);
		if (my_cred != my_new_cred) {
			proc_lock(p);
			/* need to protect for a race where another thread also changed
			 * the credential after we took our reference.  If p_ucred has 
			 * changed then we should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_rele(my_cred);
				kauth_cred_rele(my_new_cred);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			p->p_flag |= P_SUGID;
			proc_unlock(p);
		}
		/* drop our extra reference */
		kauth_cred_rele(my_cred);
		break;
	}
	
	set_security_token(p);
	return (0);
}

/* ARGSUSED */
int
seteuid(struct proc *p, struct seteuid_args *uap, __unused register_t *retval)
{
	register uid_t euid;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	euid = uap->euid;
	AUDIT_ARG(uid, 0, euid, 0, 0);
	if (euid != p->p_ucred->cr_ruid && euid != p->p_ucred->cr_svuid &&
	    (error = suser(p->p_ucred, &p->p_acflag)))
		return (error);
	/*
	 * Everything's okay, do it.  Copy credentials so other references do
	 * not see our changes.  get current credential and take a reference 
	 * while we muck with it
	 */
	for (;;) {
		my_cred = kauth_cred_proc_ref(p);
	
		/* 
		 * set the credential with new info.  If there is no change we get back 
		 * the same credential we passed in.
		 */
		my_new_cred = kauth_cred_seteuid(p->p_ucred, euid);
	
		if (my_cred != my_new_cred) {
			proc_lock(p);
			/* need to protect for a race where another thread also changed
			 * the credential after we took our reference.  If p_ucred has 
			 * changed then we should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_rele(my_cred);
				kauth_cred_rele(my_new_cred);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			p->p_flag |= P_SUGID;
			proc_unlock(p);
		}
		/* drop our extra reference */
		kauth_cred_rele(my_cred);
		break;
	}

	set_security_token(p);
	return (0);
}

/* ARGSUSED */
int
setgid(struct proc *p, struct setgid_args *uap, __unused register_t *retval)
{
	register gid_t gid;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	gid = uap->gid;
	AUDIT_ARG(gid, gid, 0, 0, 0);
	if (gid != p->p_ucred->cr_rgid && (error = suser(p->p_ucred, &p->p_acflag)))
		return (error);

	/* get current credential and take a reference while we muck with it */
	for (;;) {
		my_cred = kauth_cred_proc_ref(p);
		
		/* 
		 * set the credential with new info.  If there is no change we get back 
		 * the same credential we passed in.
		 */
		my_new_cred = kauth_cred_setgid(p->p_ucred, gid);
		if (my_cred != my_new_cred) {
			proc_lock(p);
			/* need to protect for a race where another thread also changed
			 * the credential after we took our reference.  If p_ucred has 
			 * changed then we should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_rele(my_cred);
				kauth_cred_rele(my_new_cred);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			p->p_flag |= P_SUGID;
			proc_unlock(p);
		}
		/* drop our extra reference */
		kauth_cred_rele(my_cred);
		break;
	}
	
	set_security_token(p);
	return (0);
}

/* ARGSUSED */
int
setegid(struct proc *p, struct setegid_args *uap, __unused register_t *retval)
{
	register gid_t egid;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	egid = uap->egid;
	AUDIT_ARG(gid, 0, egid, 0, 0);
	if (egid != p->p_ucred->cr_rgid && egid != p->p_ucred->cr_svgid &&
	    (error = suser(p->p_ucred, &p->p_acflag)))
		return (error);

	/* get current credential and take a reference while we muck with it */
	for (;;) {
		my_cred = kauth_cred_proc_ref(p);
		
		/* 
		 * set the credential with new info.  If there is no change we get back 
		 * the same credential we passed in.
		 */
		my_new_cred = kauth_cred_setegid(p->p_ucred, egid);
		if (my_cred != my_new_cred) {
			proc_lock(p);
			/* need to protect for a race where another thread also changed
			 * the credential after we took our reference.  If p_ucred has 
			 * changed then we should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_rele(my_cred);
				kauth_cred_rele(my_new_cred);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			p->p_flag |= P_SUGID;
			proc_unlock(p);
		}
		/* drop our extra reference */
		kauth_cred_rele(my_cred);
		break;
	}

	set_security_token(p);
	return (0);
}

/*
 * Set the per-thread override identity.  The first parameter can be the
 * current real UID, KAUTH_UID_NONE, or, if the caller is priviledged, it
 * can be any UID.  If it is KAUTH_UID_NONE, then as a special case, this
 * means "revert to the per process credential"; otherwise, if permitted,
 * it changes the effective, real, and saved UIDs and GIDs for the current
 * thread to the requested UID and single GID, and clears all other GIDs.
 */
int
settid(struct proc *p, struct settid_args *uap, __unused register_t *retval)
{
	kauth_cred_t uc;
	struct uthread *uthread = get_bsdthread_info(current_thread());
	register uid_t uid;
	register gid_t gid;

	uid = uap->uid;
	gid = uap->gid;
	AUDIT_ARG(uid, uid, gid, gid, 0);

	if (suser(p->p_ucred, &p->p_acflag) != 0) {
		return (EPERM);
	}
	
	if (uid == KAUTH_UID_NONE) {

		/* must already be assuming another identity in order to revert back */
		if ((uthread->uu_flag & UT_SETUID) == 0)
			return (EPERM);

		/* revert to delayed binding of process credential */
		uc = kauth_cred_proc_ref(p);
		kauth_cred_rele(uthread->uu_ucred);
		uthread->uu_ucred = uc;
		uthread->uu_flag &= ~UT_SETUID;
	} else {
		kauth_cred_t my_cred, my_new_cred;

		/* cannot already be assuming another identity */
		if ((uthread->uu_flag & UT_SETUID) != 0) {
			return (EPERM);
		}

		/*
		 * get a new credential instance from the old if this one changes else
		 * kauth_cred_setuidgid returns the same credential.  we take an extra 
		 * reference on the current credential while we muck wit it here.
		 */
		kauth_cred_ref(uthread->uu_ucred); 
		my_cred = uthread->uu_ucred;
		my_new_cred = kauth_cred_setuidgid(my_cred, uid, gid);
		if (my_cred != my_new_cred)
			uthread->uu_ucred = my_new_cred;
		uthread->uu_flag |= UT_SETUID;

		/* drop our extra reference */
		kauth_cred_rele(my_cred);
	}
	/*
	 * XXX should potentially set per thread security token (there is
	 * XXX none).
	 * XXX it is unclear whether P_SUGID should be st at this point;
	 * XXX in theory, it is being deprecated.
	 */
	return (0);
}

/*
 * Set the per-thread override identity.  Use this system call for a thread to
 * assume the identity of another process or to revert back to normal identity 
 * of the current process.
 * When the "assume" argument is non zero the current thread will assume the 
 * identity of the process represented by the pid argument.
 * When the assume argument is zero we revert back to our normal identity.
 */
int
settid_with_pid(struct proc *p, struct settid_with_pid_args *uap, __unused register_t *retval)
{
	proc_t target_proc;
	struct uthread *uthread = get_bsdthread_info(current_thread());
	kauth_cred_t my_cred, my_target_cred, my_new_cred;

	AUDIT_ARG(pid, uap->pid);
	AUDIT_ARG(value, uap->assume);

	if (suser(p->p_ucred, &p->p_acflag) != 0) {
		return (EPERM);
	}

	/*
	 * XXX should potentially set per thread security token (there is
	 * XXX none).
	 * XXX it is unclear whether P_SUGID should be st at this point;
	 * XXX in theory, it is being deprecated.
	 */

	/*
	 * assume argument tells us to assume the identity of the process with the
	 * id passed in the pid argument.
	 */
	if (uap->assume != 0) {
		/* can't do this if we have already assumed an identity */
		if ((uthread->uu_flag & UT_SETUID) != 0)
			return (EPERM);
	
		target_proc = pfind(uap->pid);
		/* can't assume the identity of the kernel process */
		if (target_proc == NULL || target_proc == kernproc) {
			return (ESRCH);
		}
	
		/*
		 * take a reference on the credential used in our target process then use
		 * it as the identity for our current thread.
		 */
		kauth_cred_ref(uthread->uu_ucred); 
		my_cred = uthread->uu_ucred;
		my_target_cred = kauth_cred_proc_ref(target_proc);
		my_new_cred = kauth_cred_setuidgid(my_cred, my_target_cred->cr_uid, my_target_cred->cr_gid);
		if (my_cred != my_new_cred)
			uthread->uu_ucred = my_new_cred;
	
		uthread->uu_flag |= UT_SETUID;
		
		/* drop our extra references */
		kauth_cred_rele(my_cred);
		kauth_cred_rele(my_target_cred);

		return (0);
	}
	
	/* we are reverting back to normal mode of operation where delayed binding
	 * of the process credential sets the credential in the thread (uu_ucred)
	 */
	if ((uthread->uu_flag & UT_SETUID) == 0)
		return (EPERM);

	/* revert to delayed binding of process credential */
	my_new_cred = kauth_cred_proc_ref(p);
	kauth_cred_rele(uthread->uu_ucred);
	uthread->uu_ucred = my_new_cred;
	uthread->uu_flag &= ~UT_SETUID;
	
	return (0);
}

/* ARGSUSED */
static int
setgroups1(struct proc *p, u_int gidsetsize, user_addr_t gidset, uid_t gmuid, __unused register_t *retval)
{
	register u_int ngrp;
	gid_t	newgroups[NGROUPS] = { 0 };
	int 	error;
	kauth_cred_t my_cred, my_new_cred;
	struct uthread *uthread = get_bsdthread_info(current_thread());

	if ((error = suser(p->p_ucred, &p->p_acflag)))
		return (error);
	ngrp = gidsetsize;
	if (ngrp > NGROUPS)
		return (EINVAL);

	if ( ngrp < 1 ) {
		ngrp = 1;
	}
	else {
		error = copyin(gidset,
			(caddr_t)newgroups, ngrp * sizeof(gid_t));
		if (error) {
			return (error);
		}
	}

	if ((uthread->uu_flag & UT_SETUID) != 0) {
		/*
		 * If this thread is under an assumed identity, set the
		 * supplementary grouplist on the thread credential instead
		 * of the process one.  If we were the only reference holder,
		 * the credential is updated in place, otherwise, our reference
		 * is dropped and we get back a different cred with a reference
		 * already held on it.  Because this is per-thread, we don't
		 * need the referencing/locking/retry required for per-process.
		 *
		 * Hack: this opts into memberd to avoid needing to use a per
		 * thread credential initgroups() instead of setgroups() in
		 * AFP server to address <rdar://4561060>
		 */
		my_cred = uthread->uu_ucred;
		uthread->uu_ucred = kauth_cred_setgroups(my_cred, &newgroups[0], ngrp, my_cred->cr_gmuid);
	} else {

		/*
		 * get current credential and take a reference while we muck
		 * with it
		 */
		for (;;) {
			my_cred = kauth_cred_proc_ref(p);

			/* 
			 * set the credential with new info.  If there is no
			 * change we get back the same credential we passed in.
			 */
			my_new_cred = kauth_cred_setgroups(my_cred, &newgroups[0], ngrp, gmuid);
			if (my_cred != my_new_cred) {
				proc_lock(p);
				/*
				 * need to protect for a race where another
				 * thread also changed the credential after we
				 * took our reference.  If p_ucred has 
				 * changed then we should restart this again
				 * with the new cred.
				 */
				if (p->p_ucred != my_cred) {
					proc_unlock(p);
					kauth_cred_rele(my_cred);
					kauth_cred_rele(my_new_cred);
					/* try again */
					continue;
				}
				p->p_ucred = my_new_cred;
				p->p_flag |= P_SUGID;
				proc_unlock(p);
			}
			/* drop our extra reference */
			kauth_cred_rele(my_cred);
			break;
		}

		AUDIT_ARG(groupset, p->p_ucred->cr_groups, ngrp);
		set_security_token(p);
	}

	return (0);
}

int
initgroups(struct proc *p, struct initgroups_args *uap, __unused register_t *retval)
{
	return(setgroups1(p, uap->gidsetsize, uap->gidset, uap->gmuid, retval));
}

int
setgroups(struct proc *p, struct setgroups_args *uap, __unused register_t *retval)
{
	return(setgroups1(p, uap->gidsetsize, uap->gidset, KAUTH_UID_NONE, retval));
}

/*
 * Set the per-thread/per-process supplementary groups list.
 */
#warning XXX implement
int
setsgroups(__unused struct proc *p, __unused struct setsgroups_args *uap, __unused register_t *retval)
{
	return(ENOTSUP);
}

/*
 * Set the per-thread/per-process whiteout groups list.
 */
#warning XXX implement
int
setwgroups(__unused struct proc *p, __unused struct setwgroups_args *uap, __unused register_t *retval)
{
	return(ENOTSUP);
}

/*
 * Check if gid is a member of the group set.
 *
 * XXX This interface is going away
 */
int
groupmember(gid_t gid, kauth_cred_t cred)
{
	int is_member;

	if (kauth_cred_ismember_gid(cred, gid, &is_member) == 0 && is_member)
		return (1);
	return (0);
}

/*
 * Test whether the specified credentials imply "super-user"
 * privilege; if so, and we have accounting info, set the flag
 * indicating use of super-powers.
 * Returns 0 or error.
 *
 * XXX This interface is going away
 */
int
suser(kauth_cred_t cred, u_short *acflag)
{
#if DIAGNOSTIC
	if (cred == NOCRED || cred == FSCRED)
		panic("suser");
#endif
	if (kauth_cred_getuid(cred) == 0) {
		if (acflag)
			*acflag |= ASU;
		return (0);
	}
	return (EPERM);
}

int
is_suser(void)
{
	struct proc *p = current_proc();

	if (!p)
		return (0);

	return (suser(p->p_ucred, &p->p_acflag) == 0);
}

int
is_suser1(void)
{
	struct proc *p = current_proc();

	if (!p)
		return (0);

	return (suser(p->p_ucred, &p->p_acflag) == 0 ||
			p->p_ucred->cr_ruid == 0 || p->p_ucred->cr_svuid == 0);
}

/*
 * Get login name, if available.
 */
/* ARGSUSED */
int
getlogin(struct proc *p, struct getlogin_args *uap, __unused register_t *retval)
{

	if (uap->namelen > sizeof (p->p_pgrp->pg_session->s_login))
		uap->namelen = sizeof (p->p_pgrp->pg_session->s_login);
	return (copyout((caddr_t) p->p_pgrp->pg_session->s_login,
	   				uap->namebuf, uap->namelen));
}

/*
 * Set login name.
 */
/* ARGSUSED */
int
setlogin(struct proc *p, struct setlogin_args *uap, __unused register_t *retval)
{
	int error;
	int dummy=0;

	if ((error = suser(p->p_ucred, &p->p_acflag)))
		return (error);
	 
	error = copyinstr(uap->namebuf,
	    (caddr_t) p->p_pgrp->pg_session->s_login,
	    sizeof (p->p_pgrp->pg_session->s_login) - 1, (size_t *)&dummy);
	if (!error)
		AUDIT_ARG(text, p->p_pgrp->pg_session->s_login);
	else if (error == ENAMETOOLONG)
		error = EINVAL;
	return (error);
}


/* Set the secrity token of the task with current euid and eguid */
/*
 * XXX This needs to change to give the task a reference and/or an opaque
 * XXX identifier.
 */
int
set_security_token(struct proc * p)
{
	security_token_t sec_token;
	audit_token_t    audit_token;

	/*
	 * Don't allow a vfork child to override the parent's token settings
	 * (since they share a task).  Instead, the child will just have to
	 * suffer along using the parent's token until the exec().  It's all
	 * undefined behavior anyway, right?
	 */
	if (p->task == current_task()) {
		uthread_t	 uthread;
		uthread = (uthread_t)get_bsdthread_info(current_thread());
		if (uthread->uu_flag & UT_VFORK)
			return (1);
	}
		
	/* XXX mach_init doesn't have a p_ucred when it calls this function */
	if (p->p_ucred != NOCRED && p->p_ucred != FSCRED) {
		sec_token.val[0] = kauth_cred_getuid(p->p_ucred);
		sec_token.val[1] = p->p_ucred->cr_gid;
	} else {
		sec_token.val[0] = 0;
		sec_token.val[1] = 0;
	}

	/*
	 * The current layout of the Mach audit token explicitly
	 * adds these fields.  But nobody should rely on such
	 * a literal representation.  Instead, the BSM library
	 * provides a function to convert an audit token into
	 * a BSM subject.  Use of that mechanism will isolate
	 * the user of the trailer from future representation
	 * changes.
	 */
	audit_token.val[0] = p->p_ucred->cr_au.ai_auid;
	audit_token.val[1] = p->p_ucred->cr_uid;
	audit_token.val[2] = p->p_ucred->cr_gid;
	audit_token.val[3] = p->p_ucred->cr_ruid;
	audit_token.val[4] = p->p_ucred->cr_rgid;
	audit_token.val[5] = p->p_pid;
	audit_token.val[6] = p->p_ucred->cr_au.ai_asid;
	audit_token.val[7] = p->p_ucred->cr_au.ai_termid.port;

	return (host_security_set_task_token(host_security_self(),
					   p->task,
					   sec_token,
					   audit_token,
					   (sec_token.val[0]) ?
						HOST_PRIV_NULL :
						host_priv_self()) != KERN_SUCCESS);
}


/*
 * Fill in a struct xucred based on a kauth_cred_t.
 */
__private_extern__
void
cru2x(kauth_cred_t cr, struct xucred *xcr)
{

	bzero(xcr, sizeof(*xcr));
	xcr->cr_version = XUCRED_VERSION;
	xcr->cr_uid = kauth_cred_getuid(cr);
	xcr->cr_ngroups = cr->cr_ngroups;
	bcopy(cr->cr_groups, xcr->cr_groups, sizeof(xcr->cr_groups));
}
