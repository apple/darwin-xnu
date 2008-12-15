/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
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

#if CONFIG_LCTX
#include <sys/lctx.h>
#endif

#if CONFIG_MACF
#include <security/mac_framework.h>
#if CONFIG_MACF_MACH
#include <secuity/mac_mach_internal.h>
#endif
#endif

#include <sys/mount_internal.h>
#include <sys/sysproto.h>
#include <mach/message.h>
#include <mach/host_security.h>

#include <kern/host.h>
#include <kern/task.h>		/* for current_task() */
#include <kern/assert.h>


int groupmember(gid_t gid, kauth_cred_t cred);

/*
 * Credential debugging; we can track entry into a function that might
 * change a credential, and we can track actual credential changes that
 * result.
 *
 * Note:	Does *NOT* currently include per-thread credential changes
 *
 *		We don't use kauth_cred_print() in current debugging, but it
 *		can be used if needed when debugging is active.
 */
#if DEBUG_CRED
#define	DEBUG_CRED_ENTER		printf
#define	DEBUG_CRED_CHANGE		printf
extern void kauth_cred_print(kauth_cred_t cred);
#else	/* !DEBUG_CRED */
#define	DEBUG_CRED_ENTER(fmt, ...)	do {} while (0)
#define	DEBUG_CRED_CHANGE(fmt, ...)	do {} while (0)
#endif	/* !DEBUG_CRED */



/*
 * setprivexec
 *
 * Description:	(dis)allow this process to hold task, thread, or execption
 *		ports of processes about to exec.
 *
 * Parameters:	uap->flag			New value for flag
 *
 * Returns:	int				Previous value of flag
 *
 * XXX:		Belongs in kern_proc.c
 */
int
setprivexec(proc_t p, struct setprivexec_args *uap, register_t *retval)
{
	AUDIT_ARG(value, uap->flag);
	*retval = p->p_debugger;
	p->p_debugger = (uap->flag != 0);
	return(0);
}


/*
 * getpid
 *
 * Description:	get the process ID
 *
 * Parameters:	(void)
 *
 * Returns:	pid_t				Current process ID
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getpid(proc_t p, __unused struct getpid_args *uap, register_t *retval)
{

	*retval = p->p_pid;
	return (0);
}


/*
 * getppid
 *
 * Description: get the parent process ID
 *
 * Parameters:	(void)
 *
 * Returns:	pid_t				Parent process ID
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getppid(proc_t p, __unused struct getppid_args *uap, register_t *retval)
{

	*retval = p->p_ppid;
	return (0);
}


/*
 * getpgrp
 *
 * Description:	get the process group ID of the calling process
 *
 * Parameters:	(void)
 *
 * Returns:	pid_t				Process group ID
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getpgrp(proc_t p, __unused struct getpgrp_args *uap, register_t *retval)
{

	*retval = p->p_pgrpid;
	return (0);
}


/*
 * getpgid
 *
 * Description: Get an arbitary pid's process group id
 *
 * Parameters:	uap->pid			The target pid
 *
 * Returns:	0				Success
 *		ESRCH				No such process
 *
 * Notes:	We are permitted to return EPERM in the case that the target
 *		process is not in the same session as the calling process,
 *		which could be a security consideration
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getpgid(proc_t p, struct getpgid_args *uap, register_t *retval)
{
	proc_t pt;
	int refheld = 0;

	pt = p;
	if (uap->pid == 0)
		goto found;

	if ((pt = proc_find(uap->pid)) == 0)
		return (ESRCH);
	refheld = 1;
found:
	*retval = pt->p_pgrpid;
	if (refheld != 0)
		proc_rele(pt);
	return (0);
}


/*
 * getsid
 *
 * Description:	Get an arbitary pid's session leaders process group ID
 *
 * Parameters:	uap->pid			The target pid
 *
 * Returns:	0				Success
 *		ESRCH				No such process
 *
 * Notes:	We are permitted to return EPERM in the case that the target
 *		process is not in the same session as the calling process,
 *		which could be a security consideration
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getsid(proc_t p, struct getsid_args *uap, register_t *retval)
{
	proc_t pt;
	int refheld = 0;
	struct session * sessp;

	pt = p;
	if (uap->pid == 0)
		goto found;

	if ((pt = proc_find(uap->pid)) == 0)
		return (ESRCH);
	refheld = 1;
found:
	sessp = proc_session(pt);
	*retval = sessp->s_sid;
	session_rele(sessp);

	if (refheld != 0)
		proc_rele(pt);
	return (0);
}


/*
 * getuid
 *
 * Description:	get real user ID for caller
 *
 * Parameters:	(void)
 *
 * Returns:	uid_t				The real uid of the caller
 */
int
getuid(__unused proc_t p, __unused struct getuid_args *uap, register_t *retval)
{

 	*retval = kauth_getruid();
	return (0);
}


/*
 * geteuid
 *
 * Description:	get effective user ID for caller
 *
 * Parameters:	(void)
 *
 * Returns:	uid_t				The effective uid of the caller
 */
int
geteuid(__unused proc_t p, __unused struct geteuid_args *uap, register_t *retval)
{

 	*retval = kauth_getuid();
	return (0);
}


/*
 * gettid
 *
 * Description:	Return the per-thread override identity.
 *
 * Parameters:	uap->uidp			Address of uid_t to get uid
 *		uap->gidp			Address of gid_t to get gid
 *
 * Returns:	0				Success
 *		ESRCH				No per thread identity active
 */
int
gettid(__unused proc_t p, struct gettid_args *uap, register_t *retval)
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


/*
 * getgid
 *
 * Description:	get the real group ID for the calling process
 *
 * Parameters:	(void)
 *
 * Returns:	gid_t				The real gid of the caller
 */
int
getgid(__unused proc_t p, __unused struct getgid_args *uap, register_t *retval)
{

	*retval = kauth_getrgid();
	return (0);
}


/*
 * getegid
 *
 * Description:	get the effective group ID for the calling process
 *
 * Parameters:	(void)
 *
 * Returns:	gid_t				The effective gid of the caller
 *
 * Notes:	As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list.
 *
 *		This could be implemented in Libc instead because of the above
 *		detail.
 */
int
getegid(__unused proc_t p, __unused struct getegid_args *uap, register_t *retval)
{

	*retval = kauth_getgid();
	return (0);
}


/*
 * getgroups
 *
 * Description:	get the list of supplementary groups for the calling process
 *
 * Parameters:	uap->gidsetsize			# of gid_t's in user buffer
 *		uap->gidset			Pointer to user buffer
 *
 * Returns:	0				Success
 *		EINVAL				User buffer too small
 *	copyout:EFAULT				User buffer invalid
 *
 * Retval:	-1				Error
 *		!0				# of groups
 *
 * Notes:	The caller may specify a 0 value for gidsetsize, and we will
 *		then return how large a buffer is required (in gid_t's) to
 *		contain the answer at the time of the call.  Otherwise, we
 *		return the number of gid_t's catually copied to user space.
 *
 *		When called with a 0 gidsetsize from a multithreaded program,
 *		there is no guarantee that another thread may not change the
 *		number of supplementary groups, and therefore a subsequent
 *		call could still fail, unless the maximum possible buffer
 *		size is supplied by the user.
 *
 *		As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list, and will
 *		be returned by this call.
 */
int
getgroups(__unused proc_t p, struct getgroups_args *uap, register_t *retval)
{
	int ngrp;
	int error;
	kauth_cred_t cred;

	/* grab reference while we muck around with the credential */
	cred = kauth_cred_get_with_ref();

	if ((ngrp = uap->gidsetsize) == 0) {
		*retval = cred->cr_ngroups;
		kauth_cred_unref(&cred);
		return (0);
	}
	if (ngrp < cred->cr_ngroups) {
		kauth_cred_unref(&cred);
		return (EINVAL);
	}
	ngrp = cred->cr_ngroups;
	if ((error = copyout((caddr_t)cred->cr_groups,
	    				uap->gidset, 
	    				ngrp * sizeof(gid_t)))) {
		kauth_cred_unref(&cred);
		return (error);
	}
	kauth_cred_unref(&cred);
	*retval = ngrp;
	return (0);
}


/*
 * Return the per-thread/per-process supplementary groups list.
 */
#warning XXX implement getsgroups
int
getsgroups(__unused proc_t p, __unused struct getsgroups_args *uap, __unused register_t *retval)
{
	/* XXX implement */
	return(ENOTSUP);
}

/*
 * Return the per-thread/per-process whiteout groups list.
 */
#warning XXX implement getwgroups
int
getwgroups(__unused proc_t p, __unused struct getwgroups_args *uap, __unused register_t *retval)
{
	/* XXX implement */
	return(ENOTSUP);
}


/*
 * setsid
 *
 * Description:	Create a new session and set the process group ID to the
 *		session ID
 *
 * Parameters:	(void)
 *
 * Returns:	0				Success
 *		EPERM				Permission denied
 *
 * Notes:	If the calling process is not the process group leader; there
 *		is no existing process group with its ID, and we are not
 *		currently in vfork, then this function will create a new
 *		session, a new process group, and put the caller in the
 *		process group (as the sole member) and make it the session
 *		leader (as the sole process in the session).
 *
 *		The existing controlling tty (if any) will be dissociated
 *		from the process, and the next non-O_NOCTTY open of a tty
 *		will establish a new controlling tty.
 *
 * XXX:		Belongs in kern_proc.c
 */
int
setsid(proc_t p, __unused struct setsid_args *uap, register_t *retval)
{
	struct pgrp * pg = PGRP_NULL;

	if (p->p_pgrpid == p->p_pid || (pg = pgfind(p->p_pid)) || p->p_lflag & P_LINVFORK) {
		if (pg != PGRP_NULL)
			pg_rele(pg);
		return (EPERM);
	} else {
		/* enter pgrp works with its own pgrp refcount */
		(void)enterpgrp(p, p->p_pid, 1);
		*retval = p->p_pid;
		return (0);
	}
}


/*
 * setpgid
 *
 * Description: set process group ID for job control
 *
 * Parameters:	uap->pid			Process to change
 *		uap->pgid			Process group to join or create
 *
 * Returns:	0			Success
 *		ESRCH			pid is not the caller or a child of
 *					the caller
 *	enterpgrp:ESRCH			No such process
 *		EACCES			Permission denied due to exec
 *		EINVAL			Invalid argument
 *		EPERM			The target process is not in the same
 *					session as the calling process
 *		EPERM			The target process is a session leader
 *		EPERM			pid and pgid are not the same, and
 *					there is no process in the calling
 *					process whose process group ID matches
 *					pgid
 *
 * Notes:	This function will cause the target process to either join
 *		an existing process process group, or create a new process
 *		group in the session of the calling process.  It cannot be
 *		used to change the process group ID of a process which is
 *		already a session leader.
 *
 *		If the target pid is 0, the pid of the calling process is
 *		substituted as the new target; if pgid is 0, the target pid
 *		is used as the target process group ID.
 *
 * Legacy:	This system call entry point is also used to implement the
 *		legacy library routine setpgrp(), which under POSIX 
 *
 * XXX:		Belongs in kern_proc.c
 */
int
setpgid(proc_t curp, register struct setpgid_args *uap, __unused register_t *retval)
{
	proc_t targp = PROC_NULL;	/* target process */
	struct pgrp *pg = PGRP_NULL;	/* target pgrp */
	int error = 0;
	int refheld = 0;
	int samesess = 0;
	struct session * curp_sessp = SESSION_NULL;
	struct session * targp_sessp = SESSION_NULL;

	curp_sessp = proc_session(curp);

	if (uap->pid != 0 && uap->pid != curp->p_pid) {
		if ((targp = proc_find(uap->pid)) == 0 || !inferior(targp)) {
			if (targp != PROC_NULL)
				refheld = 1;
			error = ESRCH;
			goto out;
		}
		refheld = 1;
		targp_sessp = proc_session(targp);
		if (targp_sessp != curp_sessp) {
			error = EPERM;
			goto out;
		}
		if (targp->p_flag & P_EXEC) {
			error = EACCES;
			goto out;
		}
	} else {
		targp = curp;
		targp_sessp = proc_session(targp);
	}

	if (SESS_LEADER(targp, targp_sessp)) {
		error = EPERM;
		goto out;
	}
	if (targp_sessp != SESSION_NULL) {
		session_rele(targp_sessp);
		targp_sessp = SESSION_NULL;
	}

	if (uap->pgid < 0) {
		error = EINVAL;
		goto out;
	}
	if (uap->pgid == 0)
		uap->pgid = targp->p_pid;
	else if (uap->pgid != targp->p_pid) {
		if ((pg = pgfind(uap->pgid)) == 0){
			error = EPERM;
			goto out;
		}
		samesess = (pg->pg_session != curp_sessp); 
		pg_rele(pg);
		if (samesess != 0) {
			error = EPERM;
			goto out;
		}
	}
	error = enterpgrp(targp, uap->pgid, 0);
out:
	if (targp_sessp != SESSION_NULL)
		session_rele(targp_sessp);
	if (curp_sessp != SESSION_NULL)
		session_rele(curp_sessp);
	if (refheld != 0)
		proc_rele(targp);
	return(error);
}


/*
 * issetugid
 *
 * Description:	Is current process tainted by uid or gid changes system call
 *
 * Parameters:	(void)
 *
 * Returns:	0				Not tainted
 *		1				Tainted
 *
 * Notes:	A process is considered tainted if it was created as a retult
 *		of an execve call from an imnage that had either the SUID or
 *		SGID bit set on the executable, or if it has changed any of its
 *		real, effective, or saved user or group IDs since beginning
 *		execution.
 */
int
issetugid(proc_t p, __unused struct issetugid_args *uap, register_t *retval)
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


/*
 * setuid
 *
 * Description:	Set user ID system call
 *
 * Parameters:	uap->uid			uid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	If called by a privileged process, this function will set the
 *		real, effective, and saved uid to the requested value.
 *
 *		If called from an unprivileged process, but uid is equal to the
 *		real or saved uid, then the effective uid will be set to the
 *		requested value, but the real and saved uid will not change.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 */
int
setuid(proc_t p, struct setuid_args *uap, __unused register_t *retval)
{
	uid_t uid;
	uid_t svuid = KAUTH_UID_NONE;
	uid_t ruid = KAUTH_UID_NONE;
	uid_t gmuid = KAUTH_UID_NONE;
	int error;
	kauth_cred_t my_cred, my_new_cred;


	uid = uap->uid;

	my_cred = kauth_cred_proc_ref(p);

	DEBUG_CRED_ENTER("setuid (%d/%d): %p %d\n", p->p_pid, (p->p_pptr ? p->p_pptr->p_pid : 0), my_cred, uap->uid);
	AUDIT_ARG(uid, uid, 0, 0, 0);

	if (uid != my_cred->cr_ruid &&	/* allow setuid(getuid()) */
	    uid != my_cred->cr_svuid &&	/* allow setuid(saved uid) */
	    (error = suser(my_cred, &p->p_acflag))) {
		kauth_cred_unref(&my_cred);
		return (error);
	}
	/*
	 * Everything's okay, do it.
	 */

	/*
	 * If we are priviledged, then set the saved and real UID too;
	 * otherwise, just set the effective UID
	 */
	if (suser(my_cred, &p->p_acflag) == 0) {
		svuid = uid;
		ruid = uid;
		/*
		 * Transfer proc count to new user.
		 * chgproccnt uses list lock for protection
		 */
		(void)chgproccnt(uid, 1);
		(void)chgproccnt(kauth_getruid(), -1);
	}

	/* get current credential and take a reference while we muck with it */
	for (;;) {
		/*
		 * Only set the gmuid if the current cred has not opt'ed out;
		 * this normally only happens when calling setgroups() instead
		 * of initgroups() to set an explicit group list, or one of the
		 * other group manipulation functions is invoked and results in
		 * a dislocation (i.e. the credential group membership changes
		 * to something other than the default list for the user, as
		 * in entering a group or leaving an exclusion group).
		 */
		if (!(my_cred->cr_flags & CRF_NOMEMBERD))
			gmuid = uid;

  		/* 
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
  		 */
		my_new_cred = kauth_cred_setresuid(my_cred, ruid, uid, svuid, gmuid);
		if (my_cred != my_new_cred) {

			DEBUG_CRED_CHANGE("setuid CH(%d): %p/0x%08x -> %p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

			proc_lock(p);
			/*
			 * We need to protect for a race where another thread
			 * also changed the credential after we took our
			 * reference.  If p_ucred has changed then we should
			 * restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_unref(&my_new_cred);
				my_cred = kauth_cred_proc_ref(p);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
			proc_unlock(p);
		}
		break;
	}
	/* Drop old proc reference or our extra reference */
	kauth_cred_unref(&my_cred);
	
	set_security_token(p);
	return (0);
}


/*
 * seteuid
 *
 * Description:	Set effective user ID system call
 *
 * Parameters:	uap->euid			effective uid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	If called by a privileged process, or called from an
 *		unprivileged process but euid is equal to the real or saved
 *		uid, then the effective uid will be set to the requested
 *		value, but the real and saved uid will not change.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 */
int
seteuid(proc_t p, struct seteuid_args *uap, __unused register_t *retval)
{
	uid_t euid;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	DEBUG_CRED_ENTER("seteuid: %d\n", uap->euid);

	euid = uap->euid;
	AUDIT_ARG(uid, 0, euid, 0, 0);

	my_cred = kauth_cred_proc_ref(p);

	if (euid != my_cred->cr_ruid && euid != my_cred->cr_svuid &&
	    (error = suser(my_cred, &p->p_acflag))) {
		kauth_cred_unref(&my_cred);
		return (error);
	}

	/*
	 * Everything's okay, do it.  Copy credentials so other references do
	 * not see our changes.  get current credential and take a reference 
	 * while we muck with it
	 */
	for (;;) {
  		/* 
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
  		 */
		my_new_cred = kauth_cred_setresuid(my_cred, KAUTH_UID_NONE, euid, KAUTH_UID_NONE, my_cred->cr_gmuid);
	
		if (my_cred != my_new_cred) {

			DEBUG_CRED_CHANGE("seteuid CH(%d): %p/0x%08x -> %p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

			proc_lock(p);
			/*
			 * We need to protect for a race where another thread
			 * also changed the credential after we took our
			 * reference.  If p_ucred has changed then we
			 * should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_unref(&my_new_cred);
				my_cred = kauth_cred_proc_ref(p);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
			proc_unlock(p);
		}
		break;
	}
	/* drop old proc reference or our extra reference */
	kauth_cred_unref(&my_cred);

	set_security_token(p);
	return (0);
}


/*
 * setreuid
 *
 * Description:	Set real and effective user ID system call
 *
 * Parameters:	uap->ruid			real uid to set
 *		uap->euid			effective uid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	A value of -1 is a special case indicating that the uid for
 *		which that value is specified not be changed.  If both values
 *		are specified as -1, no action is taken.
 *
 *		If called by a privileged process, the real and effective uid
 *		will be set to the new value(s) specified.
 *
 *		If called from an unprivileged process, the real uid may be
 *		set to the current value of the real uid, or to the current
 *		value of the saved uid.  The effective uid may be set to the
 *		current value of any of the effective, real, or saved uid.
 *
 *		If the newly requested real uid or effective uid does not
 *		match the saved uid, then set the saved uid to the new
 *		effective uid (potentially unrecoverably dropping saved
 *		privilege).
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 */
int
setreuid(proc_t p, struct setreuid_args *uap, __unused register_t *retval)
{
	uid_t ruid, euid;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	DEBUG_CRED_ENTER("setreuid %d %d\n", uap->ruid, uap->euid);

	ruid = uap->ruid;
	euid = uap->euid;
	if (ruid == (uid_t)-1)
		ruid = KAUTH_UID_NONE;
	if (euid == (uid_t)-1)
		euid = KAUTH_UID_NONE;
	AUDIT_ARG(uid, euid, ruid, 0, 0);

	my_cred = kauth_cred_proc_ref(p);

	if (((ruid != KAUTH_UID_NONE &&		/* allow no change of ruid */
	      ruid != my_cred->cr_ruid &&	/* allow ruid = ruid */
	      ruid != my_cred->cr_uid &&	/* allow ruid = euid */
	      ruid != my_cred->cr_svuid) ||	/* allow ruid = svuid */
	     (euid != KAUTH_UID_NONE &&		/* allow no change of euid */
	      euid != my_cred->cr_uid &&	/* allow euid = euid */
	      euid != my_cred->cr_ruid &&	/* allow euid = ruid */
	      euid != my_cred->cr_svuid)) &&	/* allow euid = svui */
	    (error = suser(my_cred, &p->p_acflag))) { /* allow root user any */
		kauth_cred_unref(&my_cred);
		return (error);
	}

	/*
	 * Everything's okay, do it.  Copy credentials so other references do
	 * not see our changes.  get current credential and take a reference 
	 * while we muck with it
	 */
	for (;;) {
		uid_t new_euid;
		uid_t new_ruid;
		uid_t svuid = KAUTH_UID_NONE;

		new_euid = my_cred->cr_uid;
		new_ruid = my_cred->cr_ruid;
	
  		/* 
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
  		 */
		if (euid == KAUTH_UID_NONE && my_cred->cr_uid != euid) {
			/* changing the effective UID */
			new_euid = euid;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
		}
		if (ruid != KAUTH_UID_NONE && my_cred->cr_ruid != ruid) {
			/* changing the real UID; must do user accounting */
		 	/* chgproccnt uses list lock for protection */
			(void)chgproccnt(ruid, 1);
			(void)chgproccnt(my_cred->cr_ruid, -1);
			new_ruid = ruid;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
		}
		/*
		 * If the newly requested real uid or effective uid does
		 * not match the saved uid, then set the saved uid to the
		 * new effective uid.  We are protected from escalation
		 * by the prechecking.
		 */
		if (my_cred->cr_svuid != uap->ruid &&
		    my_cred->cr_svuid != uap->euid) {
		    	svuid = new_euid;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
		}

		my_new_cred = kauth_cred_setresuid(my_cred, ruid, euid, svuid, my_cred->cr_gmuid);
	
		if (my_cred != my_new_cred) {

			DEBUG_CRED_CHANGE("setreuid CH(%d): %p/0x%08x -> %p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

			proc_lock(p);
			/*
			 * We need to protect for a race where another thread
			 * also changed the credential after we took our
			 * reference.  If p_ucred has changed then we should
			 * restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_unref(&my_new_cred);
				my_cred = kauth_cred_proc_ref(p);
				/* try again */
				continue;
			}
			p->p_ucred = my_new_cred;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag); /* XXX redundant? */
			proc_unlock(p);
		}
		break;
	}
	/* drop old proc reference or our extra reference */
	kauth_cred_unref(&my_cred);

	set_security_token(p);
	return (0);
}


/*
 * setgid
 *
 * Description:	Set group ID system call
 *
 * Parameters:	uap->gid			gid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	If called by a privileged process, this function will set the
 *		real, effective, and saved gid to the requested value.
 *
 *		If called from an unprivileged process, but gid is equal to the
 *		real or saved gid, then the effective gid will be set to the
 *		requested value, but the real and saved gid will not change.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 *
 *		As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list, and
 *		therefore the effective group list may be reordered to keep
 *		the supplementary group list unchanged.
 */
int
setgid(proc_t p, struct setgid_args *uap, __unused register_t *retval)
{
	gid_t gid;
	gid_t rgid = KAUTH_GID_NONE;
	gid_t svgid = KAUTH_GID_NONE;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	DEBUG_CRED_ENTER("setgid(%d/%d): %d\n", p->p_pid, (p->p_pptr ? p->p_pptr->p_pid : 0), uap->gid);

	gid = uap->gid;
	AUDIT_ARG(gid, gid, 0, 0, 0);

	my_cred = kauth_cred_proc_ref(p);

	if (gid != my_cred->cr_rgid &&	/* allow setgid(getgid()) */
	    gid != my_cred->cr_svgid &&	/* allow setgid(saved gid) */
	    (error = suser(my_cred, &p->p_acflag))) {
		kauth_cred_unref(&my_cred);
		return (error);
	}

	/*
	 * If we are priviledged, then set the saved and real GID too;
	 * otherwise, just set the effective GID
	 */
	if (suser(my_cred,  &p->p_acflag) == 0) {
		svgid = gid;
		rgid = gid;
	}

	/* get current credential and take a reference while we muck with it */
	for (;;) {
		
  		/* 
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
  		 */
		my_new_cred = kauth_cred_setresgid(my_cred, rgid, gid, svgid);
		if (my_cred != my_new_cred) {

			DEBUG_CRED_CHANGE("setgid(CH)%d: %p/0x%08x->%p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

			proc_lock(p);
			/*
			 * We need to protect for a race where another thread
			 * also changed the credential after we took our
			 * reference.  If p_ucred has changed then we
			 * should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_unref(&my_new_cred);
				/* try again */
				my_cred = kauth_cred_proc_ref(p);
				continue;
			}
			p->p_ucred = my_new_cred;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
			proc_unlock(p);
		}
		break;
	}
	/* Drop old proc reference or our extra reference */
	kauth_cred_unref(&my_cred);
	
	set_security_token(p);
	return (0);
}


/*
 * setegid
 *
 * Description:	Set effective group ID system call
 *
 * Parameters:	uap->egid			effective gid to set
 *
 * Returns:	0				Success
 *	suser:EPERM
 *
 * Notes:	If called by a privileged process, or called from an
 *		unprivileged process but egid is equal to the real or saved
 *		gid, then the effective gid will be set to the requested
 *		value, but the real and saved gid will not change.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 *
 *		As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list, and
 *		therefore the effective group list may be reordered to keep
 *		the supplementary group list unchanged.
 */
int
setegid(proc_t p, struct setegid_args *uap, __unused register_t *retval)
{
	gid_t egid;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	DEBUG_CRED_ENTER("setegid %d\n", uap->egid);

	egid = uap->egid;
	AUDIT_ARG(gid, 0, egid, 0, 0);

	my_cred = kauth_cred_proc_ref(p);

	if (egid != my_cred->cr_rgid &&
	    egid != my_cred->cr_svgid &&
	    (error = suser(my_cred, &p->p_acflag))) {
		kauth_cred_unref(&my_cred);
		return (error);
	}

	/* get current credential and take a reference while we muck with it */
	for (;;) {
  		/* 
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
  		 */
		my_new_cred = kauth_cred_setresgid(my_cred, KAUTH_GID_NONE, egid, KAUTH_GID_NONE);
		if (my_cred != my_new_cred) {

			DEBUG_CRED_CHANGE("setegid(CH)%d: %p/0x%08x->%p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

			proc_lock(p);
			/*
			 * We need to protect for a race where another thread
			 * also changed the credential after we took our
			 * reference.  If p_ucred has changed then we
			 * should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_unref(&my_new_cred);
				/* try again */
				my_cred = kauth_cred_proc_ref(p);
				continue;
			}
			p->p_ucred = my_new_cred;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
			proc_unlock(p);
		}
		break;
	}

	/* Drop old proc reference or our extra reference */
	kauth_cred_unref(&my_cred);

	set_security_token(p);
	return (0);
}

/*
 * setregid
 *
 * Description:	Set real and effective group ID system call
 *
 * Parameters:	uap->rgid			real gid to set
 *		uap->egid			effective gid to set
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *
 * Notes:	A value of -1 is a special case indicating that the gid for
 *		which that value is specified not be changed.  If both values
 *		are specified as -1, no action is taken.
 *
 *		If called by a privileged process, the real and effective gid
 *		will be set to the new value(s) specified.
 *
 *		If called from an unprivileged process, the real gid may be
 *		set to the current value of the real gid, or to the current
 *		value of the saved gid.  The effective gid may be set to the
 *		current value of any of the effective, real, or saved gid.
 *
 *		If the new real and effective gid will not be equal, or the
 *		new real or effective gid is not the same as the saved gid,
 *		then the saved gid will be updated to reflect the new
 *		effective gid (potentially unrecoverably dropping saved
 *		privilege).
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 *
 *		As an implementation detail, the effective gid is stored as
 *		the first element of the supplementary group list, and
 *		therefore the effective group list may be reordered to keep
 *		the supplementary group list unchanged.
 */
int
setregid(proc_t p, struct setregid_args *uap, __unused register_t *retval)
{
	gid_t rgid, egid;
	int error;
	kauth_cred_t my_cred, my_new_cred;

	DEBUG_CRED_ENTER("setregid %d %d\n", uap->rgid, uap->egid);

	rgid = uap->rgid;
	egid = uap->egid;

	if (rgid == (uid_t)-1)
		rgid = KAUTH_GID_NONE;
	if (egid == (uid_t)-1)
		egid = KAUTH_GID_NONE;
	AUDIT_ARG(gid, egid, rgid, 0, 0);

	my_cred = kauth_cred_proc_ref(p);

	if (((rgid != KAUTH_UID_NONE &&		/* allow no change of rgid */
	      rgid != my_cred->cr_rgid &&	/* allow rgid = rgid */
	      rgid != my_cred->cr_gid &&	/* allow rgid = egid */
	      rgid != my_cred->cr_svgid) ||	/* allow rgid = svgid */
	     (egid != KAUTH_UID_NONE &&		/* allow no change of egid */
	      egid != my_cred->cr_groups[0] &&	/* allow no change of egid */
	      egid != my_cred->cr_gid &&	/* allow egid = egid */
	      egid != my_cred->cr_rgid &&	/* allow egid = rgid */
	      egid != my_cred->cr_svgid)) &&	/* allow egid = svgid */
	    (error = suser(my_cred, &p->p_acflag))) { /* allow root user any */
		kauth_cred_unref(&my_cred);
		return (error);
	}

	/* get current credential and take a reference while we muck with it */
	for (;;) {
		uid_t new_egid = my_cred->cr_gid;
		uid_t new_rgid = my_cred->cr_rgid;
		uid_t svgid = KAUTH_UID_NONE;

		
  		/* 
		 * Set the credential with new info.  If there is no change,
		 * we get back the same credential we passed in; if there is
		 * a change, we drop the reference on the credential we
		 * passed in.  The subsequent compare is safe, because it is
		 * a pointer compare rather than a contents compare.
  		 */
		if (egid == KAUTH_UID_NONE && my_cred->cr_groups[0] != egid) {
			/* changing the effective GID */
			new_egid = egid;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
		}
		if (rgid != KAUTH_UID_NONE && my_cred->cr_rgid != rgid) {
			/* changing the real GID */
			new_rgid = rgid;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
		}
		/*
		 * If the newly requested real gid or effective gid does
		 * not match the saved gid, then set the saved gid to the
		 * new effective gid.  We are protected from escalation
		 * by the prechecking.
		 */
		if (my_cred->cr_svgid != uap->rgid &&
		    my_cred->cr_svgid != uap->egid) {
		    	svgid = new_egid;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
		}

		my_new_cred = kauth_cred_setresgid(my_cred, rgid, egid, svgid);
		if (my_cred != my_new_cred) {

			DEBUG_CRED_CHANGE("setregid(CH)%d: %p/0x%08x->%p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

			proc_lock(p);
			/* need to protect for a race where another thread
			 * also changed the credential after we took our
			 * reference.  If p_ucred has changed then we
			 * should restart this again with the new cred.
			 */
			if (p->p_ucred != my_cred) {
				proc_unlock(p);
				kauth_cred_unref(&my_new_cred);
				/* try again */
				my_cred = kauth_cred_proc_ref(p);
				continue;
			}
			p->p_ucred = my_new_cred;
			OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag); /* XXX redundant? */
			proc_unlock(p);
		}
		break;
	}
	/* Drop old proc reference or our extra reference */
	kauth_cred_unref(&my_cred);

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
settid(proc_t p, struct settid_args *uap, __unused register_t *retval)
{
	kauth_cred_t uc;
	struct uthread *uthread = get_bsdthread_info(current_thread());
	uid_t uid;
	gid_t gid;

	uid = uap->uid;
	gid = uap->gid;
	AUDIT_ARG(uid, uid, gid, gid, 0);

	if (proc_suser(p) != 0) 
		return (EPERM);
	
	if (uid == KAUTH_UID_NONE) {

		/* must already be assuming another identity in order to revert back */
		if ((uthread->uu_flag & UT_SETUID) == 0)
			return (EPERM);

		/* revert to delayed binding of process credential */
		uc = kauth_cred_proc_ref(p);
		kauth_cred_unref(&uthread->uu_ucred);
		uthread->uu_ucred = uc;
		uthread->uu_flag &= ~UT_SETUID;
	} else {
		kauth_cred_t my_cred, my_new_cred;

		/* cannot already be assuming another identity */
		if ((uthread->uu_flag & UT_SETUID) != 0) {
			return (EPERM);
		}

		/*
		 * Get a new credential instance from the old if this one
		 * changes; otherwise kauth_cred_setuidgid() returns the
		 * same credential.  We take an extra reference on the
		 * current credential while we muck with it, so we can do
		 * the post-compare for changes by pointer.
		 */
		kauth_cred_ref(uthread->uu_ucred); 
		my_cred = uthread->uu_ucred;
		my_new_cred = kauth_cred_setuidgid(my_cred, uid, gid);
		if (my_cred != my_new_cred)
			uthread->uu_ucred = my_new_cred;
		uthread->uu_flag |= UT_SETUID;

		/* Drop old uthread reference or our extra reference */
		kauth_cred_unref(&my_cred);
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
 *
 * When the "assume" argument is non zero the current thread will assume the
 * identity of the process represented by the pid argument.
 *
 * When the assume argument is zero we revert back to our normal identity.
 */
int
settid_with_pid(proc_t p, struct settid_with_pid_args *uap, __unused register_t *retval)
{
	proc_t target_proc;
	struct uthread *uthread = get_bsdthread_info(current_thread());
	kauth_cred_t my_cred, my_target_cred, my_new_cred;

	AUDIT_ARG(pid, uap->pid);
	AUDIT_ARG(value, uap->assume);

	if (proc_suser(p) != 0) {
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
	
		target_proc = proc_find(uap->pid);
		/* can't assume the identity of the kernel process */
		if (target_proc == NULL || target_proc == kernproc) {
			if (target_proc!= NULL)
				proc_rele(target_proc);
			return (ESRCH);
		}
	
		/*
		 * Take a reference on the credential used in our target
		 * process then use it as the identity for our current
		 * thread.  We take an extra reference on the current
		 * credential while we muck with it, so we can do the
		 * post-compare for changes by pointer.
		 *
		 * The post-compare is needed for the case that our process
		 * credential has been changed to be identical to our thread
		 * credential following our assumption of a per-thread one,
		 * since the credential cache will maintain a unique instance.
		 */
		kauth_cred_ref(uthread->uu_ucred); 
		my_cred = uthread->uu_ucred;
		my_target_cred = kauth_cred_proc_ref(target_proc);
		my_new_cred = kauth_cred_setuidgid(my_cred, my_target_cred->cr_uid, my_target_cred->cr_gid);
		if (my_cred != my_new_cred)
			uthread->uu_ucred = my_new_cred;
	
		uthread->uu_flag |= UT_SETUID;
		
		/* Drop old uthread reference or our extra reference */
		proc_rele(target_proc);
		kauth_cred_unref(&my_cred);
		kauth_cred_unref(&my_target_cred);

		return (0);
	}
	
	/*
	 * Otherwise, we are reverting back to normal mode of operation where
	 * delayed binding of the process credential sets the credential in
	 * the thread (uu_ucred)
	 */
	if ((uthread->uu_flag & UT_SETUID) == 0)
		return (EPERM);

	/* revert to delayed binding of process credential */
	my_new_cred = kauth_cred_proc_ref(p);
	kauth_cred_unref(&uthread->uu_ucred);
	uthread->uu_ucred = my_new_cred;
	uthread->uu_flag &= ~UT_SETUID;
	
	return (0);
}


/*
 * setgroups1
 *
 * Description: Internal implementation for both the setgroups and initgroups
 *		system calls
 *
 * Parameters:	gidsetsize			Number of groups in set
 *		gidset				Pointer to group list
 *		gmuid				Base gid (initgroups only!)
 *
 * Returns:	0				Success
 *	suser:EPERM				Permision denied
 *		EINVAL				Invalid gidsetsize value
 *	copyin:EFAULT				Bad gidset or gidsetsize is
 *						too large
 *
 * Notes:	When called from a thread running under an assumed per-thread
 *		identity, this function will operate against the per-thread
 *		credential, rather than against the process credential.  In
 *		this specific case, the process credential is verified to
 *		still be privileged at the time of the call, rather than the
 *		per-thread credential for this operation to be permitted.
 *
 *		This effectively means that setgroups/initigroups calls in
 *		a thread running a per-thread credential should occur *after*
 *		the settid call that created it, not before (unlike setuid,
 *		which must be called after, since it will result in privilege
 *		being dropped).
 *
 *		When called normally (i.e. no per-thread assumed identity),
 *		the per process credential is updated per POSIX.
 *
 *		If the credential is changed as a result of this call, then we
 *		flag the process as having set privilege since the last exec.
 */
static int
setgroups1(proc_t p, u_int gidsetsize, user_addr_t gidset, uid_t gmuid, __unused register_t *retval)
{
	u_int ngrp;
	gid_t	newgroups[NGROUPS] = { 0 };
	int 	error;
	kauth_cred_t my_cred, my_new_cred;
	struct uthread *uthread = get_bsdthread_info(current_thread());

	DEBUG_CRED_ENTER("setgroups1 (%d/%d): %d 0x%016x %d\n", p->p_pid, (p->p_pptr ? p->p_pptr->p_pid : 0), gidsetsize, gidset, gmuid);

	ngrp = gidsetsize;
	if (ngrp > NGROUPS)
		return (EINVAL);

	if ( ngrp < 1 ) {
		ngrp = 1;
	} else {
		error = copyin(gidset,
			(caddr_t)newgroups, ngrp * sizeof(gid_t));
		if (error) {
			return (error);
		}
	}

	my_cred = kauth_cred_proc_ref(p);
	if ((error = suser(my_cred, &p->p_acflag))) {
		kauth_cred_unref(&my_cred);
		return (error);
	}

	if ((uthread->uu_flag & UT_SETUID) != 0) {
#if DEBUG_CRED
		int my_cred_flags = uthread->uu_ucred->cr_flags;
#endif	/* DEBUG_CRED */
		kauth_cred_unref(&my_cred);

		/*
		 * If this thread is under an assumed identity, set the
		 * supplementary grouplist on the thread credential instead
		 * of the process one.  If we were the only reference holder,
		 * the credential is updated in place, otherwise, our reference
		 * is dropped and we get back a different cred with a reference
		 * already held on it.  Because this is per-thread, we don't
		 * need the referencing/locking/retry required for per-process.
		 */
		my_cred = uthread->uu_ucred;
		uthread->uu_ucred = kauth_cred_setgroups(my_cred, &newgroups[0], ngrp, gmuid);
#if DEBUG_CRED
		if (my_cred != uthread->uu_ucred) {
			DEBUG_CRED_CHANGE("setgroups1(CH)%d: %p/0x%08x->%p/0x%08x\n", p->p_pid, my_cred, my_cred_flags, uthread->uu_ucred , uthread->uu_ucred ->cr_flags);
		}
#endif	/* DEBUG_CRED */
	} else {

		/*
		 * get current credential and take a reference while we muck
		 * with it
		 */
		for (;;) {
			/* 
			 * Set the credential with new info.  If there is no
			 * change, we get back the same credential we passed
			 * in; if there is a change, we drop the reference on
			 * the credential we passed in.  The subsequent
			 * compare is safe, because it is a pointer compare
			 * rather than a contents compare.
			 */
			my_new_cred = kauth_cred_setgroups(my_cred, &newgroups[0], ngrp, gmuid);
			if (my_cred != my_new_cred) {

				DEBUG_CRED_CHANGE("setgroups1(CH)%d: %p/0x%08x->%p/0x%08x\n", p->p_pid, my_cred, my_cred->cr_flags, my_new_cred, my_new_cred->cr_flags);

				proc_lock(p);
				/*
				 * We need to protect for a race where another
				 * thread also changed the credential after we
				 * took our reference.  If p_ucred has 
				 * changed then we should restart this again
				 * with the new cred.
				 */
				if (p->p_ucred != my_cred) {
					proc_unlock(p);
					kauth_cred_unref(&my_new_cred);
					my_cred = kauth_cred_proc_ref(p);
					/* try again */
					continue;
				}
				p->p_ucred = my_new_cred;
				OSBitOrAtomic(P_SUGID, (UInt32 *)&p->p_flag);
				proc_unlock(p);
			}
			break;
		}
		/* Drop old proc reference or our extra reference */
		AUDIT_ARG(groupset, my_cred->cr_groups, ngrp);
		kauth_cred_unref(&my_cred);


		set_security_token(p);
	}

	return (0);
}


/*
 * initgroups
 *
 * Description: Initialize the default supplementary groups list and set the
 *		gmuid for use by the external group resolver (if any)
 *
 * Parameters:	uap->gidsetsize			Number of groups in set
 *		uap->gidset			Pointer to group list
 *		uap->gmuid			Base gid
 *
 * Returns:	0				Success
 *	setgroups1:EPERM			Permision denied
 *	setgroups1:EINVAL			Invalid gidsetsize value
 *	setgroups1:EFAULT			Bad gidset or gidsetsize is
 *
 * Notes:	This function opts *IN* to memberd participation
 *
 *		The normal purpose of this function is for a privileged
 *		process to indicate supplementary groups and identity for
 *		participation in extended group membership resolution prior
 *		to dropping privilege by assuming a specific user identity.
 *
 *		It is the first half of the primary mechanism whereby user
 *		identity is established to the system by programs such as
 *		/usr/bin/login.  The second half is the drop of uid privilege
 *		for a specific uid corresponding to the user.
 *
 * See also:	setgroups1()
 */
int
initgroups(proc_t p, struct initgroups_args *uap, __unused register_t *retval)
{
	DEBUG_CRED_ENTER("initgroups\n");

	return(setgroups1(p, uap->gidsetsize, uap->gidset, uap->gmuid, retval));
}


/*
 * setgroups
 *
 * Description: Initialize the default supplementary groups list
 *
 * Parameters:	gidsetsize			Number of groups in set
 *		gidset				Pointer to group list
 *
 * Returns:	0				Success
 *	setgroups1:EPERM			Permision denied
 *	setgroups1:EINVAL			Invalid gidsetsize value
 *	setgroups1:EFAULT			Bad gidset or gidsetsize is
 *
 * Notes:	This functions opts *OUT* of memberd participation.
 *
 *		This function exists for compatibility with POSIX.  Most user
 *		programs should use initgroups() instead to ensure correct
 *		participation in group membership resolution when utilizing
 *		a directory service for authentication.
 *
 *		It is identical to an initgroups() call with a gmuid argument
 *		of KAUTH_UID_NONE.
 *
 * See also:	setgroups1()
 */
int
setgroups(proc_t p, struct setgroups_args *uap, __unused register_t *retval)
{
	DEBUG_CRED_ENTER("setgroups\n");

	return(setgroups1(p, uap->gidsetsize, uap->gidset, KAUTH_UID_NONE, retval));
}


/*
 * Set the per-thread/per-process supplementary groups list.
 */
#warning XXX implement setsgroups
int
setsgroups(__unused proc_t p, __unused struct setsgroups_args *uap, __unused register_t *retval)
{
	return(ENOTSUP);
}

/*
 * Set the per-thread/per-process whiteout groups list.
 */
#warning XXX implement setwgroups
int
setwgroups(__unused proc_t p, __unused struct setwgroups_args *uap, __unused register_t *retval)
{
	return(ENOTSUP);
}


/*
 * Check if gid is a member of the group set.
 *
 * XXX This interface is going away; use kauth_cred_ismember_gid() directly
 * XXX instead.
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
 * XXX This interface is going away; use kauth_cred_issuser() directly
 * XXX instead.
 *
 * Note:	This interface exists to implement the "has used privilege"
 *		bit (ASU) in the p_acflags field of the process, which is
 *		only externalized via private sysctl and in process accounting
 *		records.  The flag is technically not required in either case.
 */
int
suser(kauth_cred_t cred, u_short *acflag)
{
#if DIAGNOSTIC
	if (!IS_VALID_CRED(cred))
		panic("suser");
#endif
	if (kauth_cred_getuid(cred) == 0) {
		if (acflag)
			*acflag |= ASU;
		return (0);
	}
	return (EPERM);
}


/*
 * XXX This interface is going away; use kauth_cred_issuser() directly
 * XXX instead.
 */
int
is_suser(void)
{
	proc_t p = current_proc();

	if (!p)
		return (0);

	return (proc_suser(p) == 0);
}


/*
 * XXX This interface is going away; use kauth_cred_issuser() directly
 * XXX instead.
 */
int
is_suser1(void)
{
	proc_t p = current_proc();
	kauth_cred_t my_cred;
	int err;

	if (!p)
		return (0);

	my_cred = kauth_cred_proc_ref(p);

	err =  (suser(my_cred, &p->p_acflag) == 0 ||
			my_cred->cr_ruid == 0 || my_cred->cr_svuid == 0);
	kauth_cred_unref(&my_cred);
	return(err);
}


/*
 * getlogin
 *
 * Description:	Get login name, if available.
 *
 * Parameters:	uap->namebuf			User buffer for return
 *		uap->namelen			User buffer length
 *
 * Returns:	0				Success
 *	copyout:EFAULT
 *
 * Notes:	Intended to obtain a string containing the user name of the
 *		user associated with the controlling terminal for the calling
 *		process.
 *
 *		Not very useful on modern systems, due to inherent length
 *		limitations for the static array in the session structure
 *		which is used to store the login name.
 *
 *		Permitted to return NULL
 *
 * XXX:		Belongs in kern_proc.c
 */
int
getlogin(proc_t p, struct getlogin_args *uap, __unused register_t *retval)
{
	char buffer[MAXLOGNAME+1];
	struct session * sessp;

	bzero(buffer, MAXLOGNAME+1);

	sessp = proc_session(p);

	if (uap->namelen > MAXLOGNAME)
		uap->namelen = MAXLOGNAME;

	if(sessp != SESSION_NULL) {
		session_lock(sessp);
		bcopy( sessp->s_login, buffer, uap->namelen);
		session_unlock(sessp);
	}
	session_rele(sessp);

	return (copyout((caddr_t)buffer, uap->namebuf, uap->namelen));
}


/*
 * setlogin
 *
 * Description:	Set login name.
 *
 * Parameters:	uap->namebuf			User buffer containing name
 *
 * Returns:	0				Success
 *	suser:EPERM				Permission denied
 *	copyinstr:EFAULT			User buffer invalid
 *	copyinstr:EINVAL			Supplied name was too long
 *
 * Notes:	This is a utility system call to support getlogin().
 *
 * XXX:		Belongs in kern_proc.c
 */
int
setlogin(proc_t p, struct setlogin_args *uap, __unused register_t *retval)
{
	int error;
	int dummy=0;
	char buffer[MAXLOGNAME+1];
	struct session * sessp;

	if ((error = proc_suser(p)))
		return (error);

	bzero(&buffer[0], MAXLOGNAME+1);


	error = copyinstr(uap->namebuf,
	    (caddr_t) &buffer[0],
	    MAXLOGNAME - 1, (size_t *)&dummy);

	sessp = proc_session(p);

	if (sessp != SESSION_NULL) {
		session_lock(sessp);
		bcopy(buffer, sessp->s_login, MAXLOGNAME);
		session_unlock(sessp);
		session_rele(sessp);
	}


	if (!error) {
		AUDIT_ARG(text, buffer);
	 } else if (error == ENAMETOOLONG)
		error = EINVAL;
	return (error);
}


/* Set the secrity token of the task with current euid and eguid */
/*
 * XXX This needs to change to give the task a reference and/or an opaque
 * XXX identifier.
 */
int
set_security_token(proc_t p)
{
	security_token_t sec_token;
	audit_token_t    audit_token;
	kauth_cred_t my_cred;
	host_priv_t host_priv;

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
		
	my_cred = kauth_cred_proc_ref(p);
	/* XXX mach_init doesn't have a p_ucred when it calls this function */
	if (IS_VALID_CRED(my_cred)) {
		sec_token.val[0] = kauth_cred_getuid(my_cred);
		sec_token.val[1] = my_cred->cr_gid;
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
	audit_token.val[0] = my_cred->cr_au.ai_auid;
	audit_token.val[1] = my_cred->cr_uid;
	audit_token.val[2] = my_cred->cr_gid;
	audit_token.val[3] = my_cred->cr_ruid;
	audit_token.val[4] = my_cred->cr_rgid;
	audit_token.val[5] = p->p_pid;
	audit_token.val[6] = my_cred->cr_au.ai_asid;
	audit_token.val[7] = p->p_idversion;

#if CONFIG_MACF_MACH
	mac_task_label_update_cred(my_cred, p->task);
#endif
	
	host_priv = (sec_token.val[0]) ? HOST_PRIV_NULL : host_priv_self();
#if CONFIG_MACF
	if (host_priv != HOST_PRIV_NULL && mac_system_check_host_priv(my_cred))
		host_priv = HOST_PRIV_NULL;
#endif
	kauth_cred_unref(&my_cred);

	return (host_security_set_task_token(host_security_self(),
					   p->task,
					   sec_token,
					   audit_token,
					   host_priv) != KERN_SUCCESS);
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

#if CONFIG_LCTX

/*
 * Set Login Context ID
 */
/*
 * MPSAFE - assignment of (visible) process to context protected by ALLLCTX_LOCK,
 *	    LCTX by its own locks.
 */
int
setlcid(proc_t p0, struct setlcid_args *uap, __unused register_t *retval)
{
	proc_t p;
	struct lctx *l;
	int error = 0;
	int refheld = 0;

	AUDIT_ARG(pid, uap->pid);
	AUDIT_ARG(value, uap->lcid);
	if (uap->pid == LCID_PROC_SELF) {	/* Create/Join/Leave */
		p = p0;
	} else {				/* Adopt/Orphan */
		p = proc_find(uap->pid);
		if (p == NULL)
			return (ESRCH);
		refheld = 1;
	}

#if CONFIG_MACF
	error = mac_proc_check_setlcid(p0, p, uap->pid, uap->lcid);
	if (error)
		goto out;
#endif

	switch (uap->lcid) {
	/* Leave/Orphan */
	case LCID_REMOVE:

		/* Only root may Leave/Orphan. */
		if (!is_suser1()) {
			error = EPERM;
			goto out;
		}

		/* Process not in login context. */
		if (p->p_lctx == NULL) {
			error = ENOATTR;
			goto out;
		}

		l = NULL;

		break;

	/* Create */
	case LCID_CREATE:

		/* Create only valid for self! */
		if (uap->pid != LCID_PROC_SELF) {
			error = EPERM;
			goto out;
		}

		/* Already in a login context. */
		if (p->p_lctx != NULL) {
			error = EPERM;
			goto out;
		}

		l = lccreate();
		if (l == NULL) {
			error = ENOMEM;
			goto out;
		}

		LCTX_LOCK(l);

		break;

	/* Join/Adopt */
	default:

		/* Only root may Join/Adopt. */
		if (!is_suser1()) {
			error = EPERM;
			goto out;
		}

		l = lcfind(uap->lcid);
		if (l == NULL) {
			error = ENOATTR;
			goto out;
		}

		break;
	}

	ALLLCTX_LOCK;
	leavelctx(p);
	enterlctx(p, l, (uap->lcid == LCID_CREATE) ? 1 : 0);
	ALLLCTX_UNLOCK;

out:
	if (refheld != 0)
		proc_rele(p);
	return (error);
}

/*
 * Get Login Context ID
 */
/*
 * MPSAFE - membership of (visible) process in a login context
 *	    protected by the all-context lock.
 */
int
getlcid(proc_t p0, struct getlcid_args *uap, register_t *retval)
{
	proc_t p;
	int error = 0;
	int refheld = 0;

	AUDIT_ARG(pid, uap->pid);
	if (uap->pid == LCID_PROC_SELF) {
		p = p0;
	} else {
		p = proc_find(uap->pid);
		if (p == NULL)
			return (ESRCH);
		refheld = 1;
	}

#if CONFIG_MACF
	error = mac_proc_check_getlcid(p0, p, uap->pid);
	if (error)
		goto out;
#endif
	ALLLCTX_LOCK;
	if (p->p_lctx == NULL) {
		error = ENOATTR;
		ALLLCTX_UNLOCK;
		goto out;
	}
	*retval = p->p_lctx->lc_id;
	ALLLCTX_UNLOCK;
 out:
	if (refheld != 0)
		proc_rele(p);

	return (error);
}
#else	/* LCTX */
int
setlcid(proc_t p0, struct setlcid_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
getlcid(proc_t p0, struct getlcid_args *uap, register_t *retval)
{

	return (ENOSYS);
}
#endif	/* !LCTX */
