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
#include <sys/proc.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/malloc.h>

#include <sys/mount.h>
#include <mach/message.h>
#include <mach/host_security.h>

#include <kern/host.h>

/*
 * setprivexec:  (dis)allow this process to hold
 * task, thread, or execption ports of processes about to exec.
 */
struct setprivexec_args {
	int flag;
}; 
int
setprivexec(p, uap, retval)
	struct proc *p;
	register struct setprivexec_args *uap;
	register_t *retval;
{
	*retval = p->p_debugger;
	p->p_debugger = (uap->flag != 0);
	return(0);
}

/* ARGSUSED */
getpid(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{

	*retval = p->p_pid;
#if COMPAT_43
	retval[1] = p->p_pptr->p_pid;
#endif
	return (0);
}

/* ARGSUSED */
getppid(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{

	*retval = p->p_pptr->p_pid;
	return (0);
}

/* Get process group ID; note that POSIX getpgrp takes no parameter */
getpgrp(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{

	*retval = p->p_pgrp->pg_id;
	return (0);
}

/* Get an arbitary pid's process group id */
struct getpgid_args {
	pid_t   pid;
};

int
getpgid(p, uap, retval)
	struct proc *p;
	struct getpgid_args *uap;
	register_t *retval;
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
struct getsid_args {
	pid_t   pid;
};

int
getsid(p, uap, retval)
	struct proc *p;
	struct getsid_args *uap;
	register_t *retval;
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
getuid(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{

	*retval = p->p_cred->p_ruid;
#if COMPAT_43
	retval[1] = p->p_ucred->cr_uid;
#endif
	return (0);
}

/* ARGSUSED */
geteuid(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{

	*retval = p->p_ucred->cr_uid;
	return (0);
}

/* ARGSUSED */
getgid(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{

	*retval = p->p_cred->p_rgid;
#if COMPAT_43
	retval[1] = p->p_ucred->cr_groups[0];
#endif
	return (0);
}

/*
 * Get effective group ID.  The "egid" is groups[0], and could be obtained
 * via getgroups.  This syscall exists because it is somewhat painful to do
 * correctly in a library function.
 */
/* ARGSUSED */
getegid(p, uap, retval)
	struct proc *p;
	void *uap;
	register_t *retval;
{

	*retval = p->p_ucred->cr_groups[0];
	return (0);
}

struct	getgroups_args {
	u_int	gidsetsize;
	gid_t 	*gidset;
};
getgroups(p, uap, retval)
	struct proc *p;
	register struct	getgroups_args *uap;
	register_t *retval;
{
	register struct pcred *pc = p->p_cred;
	register u_int ngrp;
	int error;

	if ((ngrp = uap->gidsetsize) == 0) {
		*retval = pc->pc_ucred->cr_ngroups;
		return (0);
	}
	if (ngrp < pc->pc_ucred->cr_ngroups)
		return (EINVAL);
	pcred_readlock(p);
	ngrp = pc->pc_ucred->cr_ngroups;
	if (error = copyout((caddr_t)pc->pc_ucred->cr_groups,
	    (caddr_t)uap->gidset, ngrp * sizeof(gid_t))) {
	    	pcred_unlock(p);
		return (error);
	}
	pcred_unlock(p);
	*retval = ngrp;
	return (0);
}

/* ARGSUSED */
setsid(p, uap, retval)
	register struct proc *p;
	void *uap;
	register_t *retval;
{

	if (p->p_pgid == p->p_pid || pgfind(p->p_pid)) {
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
 * if pgid != pid
 * 	there must exist some pid in same session having pgid (EPERM)
 * pid must not be session leader (EPERM)
 */
struct setpgid_args {
	int	pid;
	int	pgid;
};
/* ARGSUSED */
setpgid(curp, uap, retval)
	struct proc *curp;
	register struct setpgid_args *uap;
	register_t *retval;
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
	if (uap->pgid == 0)
		uap->pgid = targp->p_pid;
	else if (uap->pgid != targp->p_pid)
		if ((pgrp = pgfind(uap->pgid)) == 0 ||
	            pgrp->pg_session != curp->p_session)
			return (EPERM);
	return (enterpgrp(targp, uap->pgid, 0));
}

struct issetugid_args {
	int dummy;
};
issetugid(p, uap, retval)
	struct proc *p;
	struct issetugid_args *uap;
	register_t *retval;
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

struct setuid_args {
	uid_t	uid;
};
/* ARGSUSED */
setuid(p, uap, retval)
	struct proc *p;
	struct setuid_args *uap;
	register_t *retval;
{
	register struct pcred *pc = p->p_cred;
	register uid_t uid;
	int error;

	uid = uap->uid;
	if (uid != pc->p_ruid &&
	    (error = suser(pc->pc_ucred, &p->p_acflag)))
		return (error);
	/*
	 * Everything's okay, do it.
	 * Transfer proc count to new user.
	 * Copy credentials so other references do not see our changes.
	 */

	/* prepare app access profile files */
	prepare_profile_database(uap->uid);
	pcred_writelock(p);
	(void)chgproccnt(pc->p_ruid, -1);
	(void)chgproccnt(uid, 1);
	pc->pc_ucred = crcopy(pc->pc_ucred);
	pc->pc_ucred->cr_uid = uid;
	pc->p_ruid = uid;
	pc->p_svuid = uid;
	pcred_unlock(p);
	set_security_token(p);
	p->p_flag |= P_SUGID;
	return (0);
}

struct seteuid_args {
	uid_t euid;
};
/* ARGSUSED */
seteuid(p, uap, retval)
	struct proc *p;
	struct seteuid_args *uap;
	register_t *retval;
{
	register struct pcred *pc = p->p_cred;
	register uid_t euid;
	int error;

	euid = uap->euid;
	if (euid != pc->p_ruid && euid != pc->p_svuid &&
	    (error = suser(pc->pc_ucred, &p->p_acflag)))
		return (error);
	/*
	 * Everything's okay, do it.  Copy credentials so other references do
	 * not see our changes.
	 */
	pcred_writelock(p);
	pc->pc_ucred = crcopy(pc->pc_ucred);
	pc->pc_ucred->cr_uid = euid;
	pcred_unlock(p);
	set_security_token(p);
	p->p_flag |= P_SUGID;
	return (0);
}

struct setgid_args {
	gid_t	gid;
};
/* ARGSUSED */
setgid(p, uap, retval)
	struct proc *p;
	struct setgid_args *uap;
	register_t *retval;
{
	register struct pcred *pc = p->p_cred;
	register gid_t gid;
	int error;

	gid = uap->gid;
	if (gid != pc->p_rgid && (error = suser(pc->pc_ucred, &p->p_acflag)))
		return (error);
	pcred_writelock(p);
	pc->pc_ucred = crcopy(pc->pc_ucred);
	pc->pc_ucred->cr_groups[0] = gid;
	pc->p_rgid = gid;
	pc->p_svgid = gid;		/* ??? */
	pcred_unlock(p);
	set_security_token(p);
	p->p_flag |= P_SUGID;
	return (0);
}

struct setegid_args {
	gid_t	egid;
};
/* ARGSUSED */
setegid(p, uap, retval)
	struct proc *p;
	struct setegid_args *uap;
	register_t *retval;
{
	register struct pcred *pc = p->p_cred;
	register gid_t egid;
	int error;

	egid = uap->egid;
	if (egid != pc->p_rgid && egid != pc->p_svgid &&
	    (error = suser(pc->pc_ucred, &p->p_acflag)))
		return (error);
	pcred_writelock(p);
	pc->pc_ucred = crcopy(pc->pc_ucred);
	pc->pc_ucred->cr_groups[0] = egid;
	pcred_unlock(p);
	set_security_token(p);
	p->p_flag |= P_SUGID;
	return (0);
}

struct setgroups_args{
	u_int	gidsetsize;
	gid_t	*gidset;
};

/* ARGSUSED */
setgroups(p, uap, retval)
	struct proc *p;
	struct setgroups_args *uap;
	register_t *retval;
{
	register struct pcred *pc = p->p_cred;
	struct ucred *new, *old;
	register u_int ngrp;
	int error;

	if (error = suser(pc->pc_ucred, &p->p_acflag))
		return (error);
	ngrp = uap->gidsetsize;
	if (ngrp < 1 || ngrp > NGROUPS)
		return (EINVAL);
	new = crget();
	error = copyin((caddr_t)uap->gidset,
	    (caddr_t)new->cr_groups, ngrp * sizeof(gid_t));
	if (error) {
		crfree(new);
		return (error);
	}
	new->cr_ngroups = ngrp;
	pcred_writelock(p);
	old = pc->pc_ucred;
	new->cr_uid = old->cr_uid;
	pc->pc_ucred = new;
	pcred_unlock(p);
	set_security_token(p);
	p->p_flag |= P_SUGID;
	if (old != NOCRED)
		crfree(old);
	return (0);
}

#if COMPAT_43
struct osetreuid_args{
	int	ruid;
	int	euid;
};
/* ARGSUSED */
osetreuid(p, uap, retval)
	register struct proc *p;
	struct osetreuid_args *uap;
	register_t *retval;
{
	struct seteuid_args seuidargs;
	struct setuid_args suidargs;

	/*
	 * There are five cases, and we attempt to emulate them in
	 * the following fashion:
	 * -1, -1: return 0. This is correct emulation.
	 * -1,  N: call seteuid(N). This is correct emulation.
	 *  N, -1: if we called setuid(N), our euid would be changed
	 *         to N as well. the theory is that we don't want to
	 * 	   revoke root access yet, so we call seteuid(N)
	 * 	   instead. This is incorrect emulation, but often
	 *	   suffices enough for binary compatibility.
	 *  N,  N: call setuid(N). This is correct emulation.
	 *  N,  M: call setuid(N). This is close to correct emulation.
	 */
	if (uap->ruid == (uid_t)-1) {
		if (uap->euid == (uid_t)-1)
			return (0);				/* -1, -1 */
		seuidargs.euid = uap->euid;	/* -1,  N */
		return (seteuid(p, &seuidargs, retval));
	}
	if (uap->euid == (uid_t)-1) {
		seuidargs.euid = uap->ruid;	/* N, -1 */
		return (seteuid(p, &seuidargs, retval));
	}
	suidargs.uid = uap->ruid;	/* N, N and N, M */
	return (setuid(p, &suidargs, retval));
}

struct osetregid_args {
	int	rgid;
	int egid;
};
/* ARGSUSED */
osetregid(p, uap, retval)
	register struct proc *p;
	struct osetregid_args *uap;
	register_t *retval;
{
	struct setegid_args segidargs;
	struct setgid_args sgidargs;

	/*
	 * There are five cases, described above in osetreuid()
	 */
	if (uap->rgid == (gid_t)-1) {
		if (uap->egid == (gid_t)-1)
			return (0);				/* -1, -1 */
		segidargs.egid = uap->egid;	/* -1,  N */
		return (setegid(p, &segidargs, retval));
	}
	if (uap->egid == (gid_t)-1) {
		segidargs.egid = uap->rgid;	/* N, -1 */
		return (setegid(p, &segidargs, retval));
	}
	sgidargs.gid = uap->rgid;	/* N, N and N, M */
	return (setgid(p, &sgidargs, retval));
}
#endif /* COMPAT_43 */

/*
 * Check if gid is a member of the group set.
 */
groupmember(gid, cred)
	gid_t gid;
	register struct ucred *cred;
{
	register gid_t *gp;
	gid_t *egp;

	egp = &(cred->cr_groups[cred->cr_ngroups]);
	for (gp = cred->cr_groups; gp < egp; gp++)
		if (*gp == gid)
			return (1);
	return (0);
}

/*
 * Test whether the specified credentials imply "super-user"
 * privilege; if so, and we have accounting info, set the flag
 * indicating use of super-powers.
 * Returns 0 or error.
 */
suser(cred, acflag)
	struct ucred *cred;
	u_short *acflag;
{
#if DIAGNOSTIC
	if (cred == NOCRED || cred == FSCRED)
		panic("suser");
#endif
	if (cred->cr_uid == 0) {
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
			p->p_cred->p_ruid == 0 || p->p_cred->p_svuid == 0);
}

/*
 * Allocate a zeroed cred structure.
 */
struct ucred *
crget()
{
	register struct ucred *cr;

	MALLOC_ZONE(cr, struct ucred *, sizeof(*cr), M_CRED, M_WAITOK);
	bzero((caddr_t)cr, sizeof(*cr));
	cr->cr_ref = 1;
	return (cr);
}

/*
 * Free a cred structure.
 * Throws away space when ref count gets to 0.
 */
void
crfree(cr)
	struct ucred *cr;
{
#if DIAGNOSTIC
	if (cr == NOCRED || cr == FSCRED)
		panic("crfree");
#endif
	if (--cr->cr_ref == 0)
		FREE_ZONE((caddr_t)cr, sizeof *cr, M_CRED);
}

/*
 * Copy cred structure to a new one and free the old one.
 */
struct ucred *
crcopy(cr)
	struct ucred *cr;
{
	struct ucred *newcr;

#if DIAGNOSTIC
	if (cr == NOCRED || cr == FSCRED)
		panic("crcopy");
#endif
	if (cr->cr_ref == 1)
		return (cr);
	newcr = crget();
	*newcr = *cr;
	crfree(cr);
	newcr->cr_ref = 1;
	return (newcr);
}

/*
 * Dup cred struct to a new held one.
 */
struct ucred *
crdup(cr)
	struct ucred *cr;
{
	struct ucred *newcr;

#if DIAGNOSTIC
	if (cr == NOCRED || cr == FSCRED)
		panic("crdup");
#endif
	newcr = crget();
	*newcr = *cr;
	newcr->cr_ref = 1;
	return (newcr);
}

/*
 * Get login name, if available.
 */
struct getlogin_args {
	char 	*namebuf;
	u_int	namelen;
};
/* ARGSUSED */
getlogin(p, uap, retval)
	struct proc *p;
	struct getlogin_args *uap;
	register_t *retval;
{

	if (uap->namelen > sizeof (p->p_pgrp->pg_session->s_login))
		uap->namelen = sizeof (p->p_pgrp->pg_session->s_login);
	return (copyout((caddr_t) p->p_pgrp->pg_session->s_login,
	    (caddr_t)uap->namebuf, uap->namelen));
}

/*
 * Set login name.
 */
struct setlogin_args {
	char	*namebuf;
};
/* ARGSUSED */
setlogin(p, uap, retval)
	struct proc *p;
	struct setlogin_args *uap;
	register_t *retval;
{
	int error;
	int dummy=0;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	 
	error = copyinstr((caddr_t) uap->namebuf,
	    (caddr_t) p->p_pgrp->pg_session->s_login,
	    sizeof (p->p_pgrp->pg_session->s_login) - 1, (size_t *)&dummy);
	if (error == ENAMETOOLONG)
		error = EINVAL;
	return (error);
}


/* Set the secrity token of the task with current euid and eguid */
kern_return_t
set_security_token(struct proc * p)
{
	security_token_t sec_token;

	sec_token.val[0] = p->p_ucred->cr_uid;
	sec_token.val[1] = p->p_ucred->cr_gid;
	return host_security_set_task_token(host_security_self(),
					   p->task,
					   sec_token,
					   (sec_token.val[0]) ?
					        HOST_PRIV_NULL :
						host_priv_self());
}
