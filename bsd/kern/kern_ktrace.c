/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)kern_ktrace.c	8.2 (Berkeley) 9/23/93
 * $FreeBSD: src/sys/kern/kern_ktrace.c,v 1.35.2.4 2001/03/05 13:09:01 obrien Exp $
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#if KTRACE
#include <sys/ktrace.h>
#endif
#include <sys/malloc.h>
#include <sys/syslog.h>

#if KTRACE
static struct ktr_header *ktrgetheader __P((int type));
static void ktrwrite __P((struct vnode *, struct ktr_header *,
	struct uio *, int));
static int ktrcanset __P((struct proc *,struct proc *));
static int ktrsetchildren __P((struct proc *,struct proc *,
	int, int, struct vnode *));
static int ktrops __P((struct proc *,struct proc *,int,int,struct vnode *));


static struct ktr_header *
ktrgetheader(type)
	int type;
{
	register struct ktr_header *kth;
	struct proc *p = current_proc();	/* XXX */

	MALLOC(kth, struct ktr_header *, sizeof (struct ktr_header),
		M_KTRACE, M_WAITOK);
	kth->ktr_type = type;
	microtime(&kth->ktr_time);
	kth->ktr_pid = p->p_pid;
	bcopy(p->p_comm, kth->ktr_comm, MAXCOMLEN);
	return (kth);
}
#endif

void
ktrsyscall(p, code, narg, args, funnel_type)
	struct proc *p;
	int code, narg;
	register_t args[];
	int funnel_type;
{
#if KTRACE
	struct vnode *vp;
	struct	ktr_header *kth;
	struct	ktr_syscall *ktp;
	register int len;
	register_t *argp;
	int i;

	if (!KTRPOINT(p, KTR_SYSCALL))
		return;

	vp = p->p_tracep;
	len = __offsetof(struct ktr_syscall, ktr_args) +
	    (narg * sizeof(register_t));
	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_SYSCALL);
	MALLOC(ktp, struct ktr_syscall *, len, M_KTRACE, M_WAITOK);
	ktp->ktr_code = code;
	ktp->ktr_narg = narg;
	argp = &ktp->ktr_args[0];
	for (i = 0; i < narg; i++)
		*argp++ = args[i];
	kth->ktr_buf = (caddr_t)ktp;
	kth->ktr_len = len;
	ktrwrite(vp, kth, NULL, funnel_type);
	FREE(ktp, M_KTRACE);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
#else
	return;
#endif
}
 
void
ktrsysret(p, code, error, retval, funnel_type)
	struct proc *p;
	int code, error;
	register_t retval;
	int funnel_type;
{
#if KTRACE
	struct vnode *vp;
	struct ktr_header *kth;
	struct ktr_sysret ktp;

	if (!KTRPOINT(p, KTR_SYSRET))
		return;

	vp = p->p_tracep;
	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_SYSRET);
	ktp.ktr_code = code;
	ktp.ktr_error = error;
	ktp.ktr_retval = retval;		/* what about val2 ? */

	kth->ktr_buf = (caddr_t)&ktp;
	kth->ktr_len = sizeof(struct ktr_sysret);

	ktrwrite(vp, kth, NULL, funnel_type);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
#else
	return;
#endif
}

#if KTRACE
void
ktrnamei(vp, path)
	struct vnode *vp;
	char *path;
{
	struct ktr_header *kth;
	struct proc *p = current_proc();	/* XXX */

	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_NAMEI);
	kth->ktr_len = strlen(path);
	kth->ktr_buf = path;

	ktrwrite(vp, kth, NULL, KERNEL_FUNNEL);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
}

void
ktrgenio(vp, fd, rw, uio, error, funnel_type)
	struct vnode *vp;
	int fd;
	enum uio_rw rw;
	struct uio *uio;
	int error;
	int funnel_type;
{
	struct ktr_header *kth;
	struct ktr_genio ktg;
	struct proc *p = current_proc();	/* XXX */

	if (error)
		return;

	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_GENIO);
	ktg.ktr_fd = fd;
	ktg.ktr_rw = rw;
	kth->ktr_buf = (caddr_t)&ktg;
	kth->ktr_len = sizeof(struct ktr_genio);
	uio->uio_offset = 0;
	uio->uio_rw = UIO_WRITE;

	ktrwrite(vp, kth, uio, funnel_type);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
}

void
ktrpsig(vp, sig, action, mask, code, funnel_type)
	struct vnode *vp;
	int sig;
	sig_t action;
	sigset_t *mask;
	int code;
	int funnel_type;
{
	struct ktr_header *kth;
	struct ktr_psig	kp;
	struct proc *p = current_proc();	/* XXX */

	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_PSIG);
	kp.signo = (char)sig;
	kp.action = action;
	kp.mask = *mask;
	kp.code = code;
	kth->ktr_buf = (caddr_t)&kp;
	kth->ktr_len = sizeof (struct ktr_psig);

	ktrwrite(vp, kth, NULL, funnel_type);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
}

void
ktrcsw(vp, out, user, funnel_type)
	struct vnode *vp;
	int out, user;
	int funnel_type;
{
	struct ktr_header *kth;
	struct	ktr_csw kc;
	struct proc *p = current_proc();	/* XXX */

	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_CSW);
	kc.out = out;
	kc.user = user;
	kth->ktr_buf = (caddr_t)&kc;
	kth->ktr_len = sizeof (struct ktr_csw);

	ktrwrite(vp, kth, NULL, funnel_type);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
}
#endif /* KTRACE */

/* Interface and common routines */

/*
 * ktrace system call
 */
struct ktrace_args {
	char	*fname;
	int	ops;
	int	facs;
	int	pid;
};
/* ARGSUSED */
int
ktrace(curp, uap, retval)
	struct proc *curp;
	register struct ktrace_args *uap;
	register_t *retval;
{
#if KTRACE
	register struct vnode *vp = NULL;
	register struct proc *p;
	struct pgrp *pg;
	int facs = uap->facs & ~KTRFAC_ROOT;
	int ops = KTROP(uap->ops);
	int descend = uap->ops & KTRFLAG_DESCEND;
	int ret = 0;
	int error = 0;
	struct nameidata nd;

	curp->p_traceflag |= KTRFAC_ACTIVE;
	if (ops != KTROP_CLEAR) {
		/*
		 * an operation which requires a file argument.
		 */
		NDINIT(&nd, LOOKUP, (NOFOLLOW|LOCKLEAF), UIO_USERSPACE, uap->fname, curp);
		error = vn_open(&nd, FREAD|FWRITE|O_NOFOLLOW, 0);
		if (error) {
			curp->p_traceflag &= ~KTRFAC_ACTIVE;
			return (error);
		}
		vp = nd.ni_vp;
		VOP_UNLOCK(vp, 0, curp);
		if (vp->v_type != VREG) {
			(void) vn_close(vp, FREAD|FWRITE, curp->p_ucred, curp);
			curp->p_traceflag &= ~KTRFAC_ACTIVE;
			return (EACCES);
		}
	}
	/*
	 * Clear all uses of the tracefile
	 */
	if (ops == KTROP_CLEARFILE) {
		LIST_FOREACH(p, &allproc, p_list) {
			if (p->p_tracep == vp) {
				if (ktrcanset(curp, p)) {
					struct vnode *tvp = p->p_tracep;
					/* no more tracing */
					p->p_traceflag = 0;
					if (tvp != NULL) {
						p->p_tracep = NULL;
						vrele(tvp);
					}
				} else
					error = EPERM;
			}
		}
		goto done;
	}

	/*
	 * need something to (un)trace (XXX - why is this here?)
	 */
	if (!facs) {
		error = EINVAL;
		goto done;
	}
	/*
	 * do it
	 */
	if (uap->pid < 0) {
		/*
		 * by process group
		 */
		pg = pgfind(-uap->pid);
		if (pg == NULL) {
			error = ESRCH;
			goto done;
		}
		LIST_FOREACH(p, &pg->pg_members, p_pglist)
			if (descend)
				ret |= ktrsetchildren(curp, p, ops, facs, vp);
			else
				ret |= ktrops(curp, p, ops, facs, vp);

	} else {
		/*
		 * by pid
		 */
		p = pfind(uap->pid);
		if (p == NULL) {
			error = ESRCH;
			goto done;
		}
		if (descend)
			ret |= ktrsetchildren(curp, p, ops, facs, vp);
		else
			ret |= ktrops(curp, p, ops, facs, vp);
	}
	if (!ret)
		error = EPERM;
done:
	if (vp != NULL)
		(void) vn_close(vp, FWRITE, curp->p_ucred, curp);
	curp->p_traceflag &= ~KTRFAC_ACTIVE;
	return (error);
#else
	return ENOSYS;
#endif
}

/*
 * utrace system call
 */
struct  utrace_args {
	const void *    addr;
	size_t  len;
};

/* ARGSUSED */
int
utrace(curp, uap, retval)
	struct proc *curp;
	register struct utrace_args *uap;
	register_t *retval;
{
#if KTRACE
	struct ktr_header *kth;
	struct proc *p = current_proc();	/* XXX */
	register caddr_t cp;

	if (!KTRPOINT(p, KTR_USER))
		return (0);
	if (uap->len > KTR_USER_MAXLEN)
		return (EINVAL);
	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_USER);
	MALLOC(cp, caddr_t, uap->len, M_KTRACE, M_WAITOK);
	if (!copyin(uap->addr, cp, uap->len)) {
		kth->ktr_buf = cp;
		kth->ktr_len = uap->len;
		ktrwrite(p->p_tracep, kth, NULL, KERNEL_FUNNEL);
	}
	FREE(kth, M_KTRACE);
	FREE(cp, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;

	return (0);
#else
	return (ENOSYS);
#endif
}

#if KTRACE
static int
ktrops(curp, p, ops, facs, vp)
	struct proc *p, *curp;
	int ops, facs;
	struct vnode *vp;
{
	struct vnode *tvp;

	if (!ktrcanset(curp, p))
		return (0);
	if (ops == KTROP_SET) {
		if (p->p_tracep != vp) {
			/*
			 * if trace file already in use, relinquish
			 */
			tvp = p->p_tracep;
			VREF(vp);
			p->p_tracep = vp;
			if (tvp != NULL)
				vrele(tvp);
		}
		p->p_traceflag |= facs;
		if (curp->p_ucred->cr_uid == 0)
			p->p_traceflag |= KTRFAC_ROOT;
	} else {
		/* KTROP_CLEAR */
		if (((p->p_traceflag &= ~facs) & KTRFAC_MASK) == 0) {
			/* no more tracing */
			tvp = p->p_tracep;
			p->p_traceflag = 0;
			if (tvp != NULL) {
				p->p_tracep = NULL;
				vrele(tvp);
			}
		}
	}

	return (1);
}

static int
ktrsetchildren(curp, top, ops, facs, vp)
	struct proc *curp, *top;
	int ops, facs;
	struct vnode *vp;
{
	register struct proc *p;
	register int ret = 0;

	p = top;
	for (;;) {
		ret |= ktrops(curp, p, ops, facs, vp);
		/*
		 * If this process has children, descend to them next,
		 * otherwise do any siblings, and if done with this level,
		 * follow back up the tree (but not past top).
		 */
		if (!LIST_EMPTY(&p->p_children))
			p = LIST_FIRST(&p->p_children);
		else for (;;) {
			if (p == top)
				return (ret);
			if (LIST_NEXT(p, p_sibling)) {
				p = LIST_NEXT(p, p_sibling);
				break;
			}
			p = p->p_pptr;
		}
	}
	/*NOTREACHED*/
}

static void
ktrwrite(vp, kth, uio, funnel_type)
	struct vnode *vp;
	register struct ktr_header *kth;
	struct uio *uio;
{
	struct uio auio;
	struct iovec aiov[2];
	register struct proc *p = current_proc();	/* XXX */
	int error;

	if (vp == NULL)
		return;

	if (funnel_type == -1) {
		funnel_t *f = thread_funnel_get();
		if(f == THR_FUNNEL_NULL)
			funnel_type = NO_FUNNEL;
		else if (f == (funnel_t *)network_flock)
			funnel_type = NETWORK_FUNNEL;
		else if (f == (funnel_t *)kernel_flock)
			funnel_type = KERNEL_FUNNEL;
	}

	switch (funnel_type) {
	case KERNEL_FUNNEL:
		/* Nothing more to do */
		break;
	case NETWORK_FUNNEL:
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
		break;
	case NO_FUNNEL:
		(void) thread_funnel_set(kernel_flock, TRUE);
		break;
	default:
		panic("Invalid funnel (%)", funnel_type);
	}
	auio.uio_iov = &aiov[0];
	auio.uio_offset = 0;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_WRITE;
	aiov[0].iov_base = (caddr_t)kth;
	aiov[0].iov_len = sizeof(struct ktr_header);
	auio.uio_resid = sizeof(struct ktr_header);
	auio.uio_iovcnt = 1;
	auio.uio_procp = current_proc();
	if (kth->ktr_len > 0) {
		auio.uio_iovcnt++;
		aiov[1].iov_base = kth->ktr_buf;
		aiov[1].iov_len = kth->ktr_len;
		auio.uio_resid += kth->ktr_len;
		if (uio != NULL)
			kth->ktr_len += uio->uio_resid;
	}
	error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	if (error)
		goto bad;
	(void)VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	error = VOP_WRITE(vp, &auio, IO_UNIT | IO_APPEND, p->p_ucred);
	if (error == 0 && uio != NULL) {
		(void)VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
		error = VOP_WRITE(vp, uio, IO_UNIT | IO_APPEND, p->p_ucred);
	}
	VOP_UNLOCK(vp, 0, p);
	if (!error) {
		switch (funnel_type) {
		case KERNEL_FUNNEL:
			/* Nothing more to do */
			break;
		case NETWORK_FUNNEL:
			thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
			/* switch funnel to NETWORK_FUNNEL */
			break;
		case NO_FUNNEL:
			 (void) thread_funnel_set(kernel_flock, FALSE);
			break;
		default:
			panic("Invalid funnel (%)", funnel_type);
		}
		return;
	}

bad:
	/*
	 * If error encountered, give up tracing on this vnode.
	 */
	log(LOG_NOTICE, "ktrace write failed, errno %d, tracing stopped\n",
	    error);
	LIST_FOREACH(p, &allproc, p_list) {
		if (p->p_tracep == vp) {
			p->p_tracep = NULL;
			p->p_traceflag = 0;
			vrele(vp);
		}
	}

	switch (funnel_type) {
	case KERNEL_FUNNEL:
		/* Nothing more to do */
		break;
	case NETWORK_FUNNEL:
		thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
		/* switch funnel to NETWORK_FUNNEL */
		break;
	case NO_FUNNEL:
		 (void) thread_funnel_set(kernel_flock, FALSE);
		break;
	default:
		panic("Invalid funnel (%)", funnel_type);
	}
}

/*
 * Return true if caller has permission to set the ktracing state
 * of target.  Essentially, the target can't possess any
 * more permissions than the caller.  KTRFAC_ROOT signifies that
 * root previously set the tracing status on the target process, and
 * so, only root may further change it.
 *
 * TODO: check groups.  use caller effective gid.
 */
static int
ktrcanset(callp, targetp)
	struct proc *callp, *targetp;
{
	register struct pcred *caller = callp->p_cred;
	register struct pcred *target = targetp->p_cred;

	if (!PRISON_CHECK(callp, targetp))
		return (0);
	if ((caller->pc_ucred->cr_uid == target->p_ruid &&
	     target->p_ruid == target->p_svuid &&
	     caller->p_rgid == target->p_rgid &&	/* XXX */
	     target->p_rgid == target->p_svgid &&
	     (targetp->p_traceflag & KTRFAC_ROOT) == 0) ||
	     caller->pc_ucred->cr_uid == 0)
		return (1);

	return (0);
}

#endif /* KTRACE */
