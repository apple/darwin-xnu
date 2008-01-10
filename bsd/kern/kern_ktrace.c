/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#if KTRACE
#include <sys/ktrace.h>
#endif
#include <sys/malloc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/uio_internal.h>

#include <bsm/audit_kernel.h>

#if KTRACE
static struct ktr_header *ktrgetheader(int type);
static void ktrwrite(struct vnode *, struct ktr_header *, struct uio *);
static int ktrcanset(struct proc *,struct proc *);
static int ktrsetchildren(struct proc *,struct proc *,
	int, int, struct vnode *);
static int ktrops(struct proc *,struct proc *,int,int,struct vnode *);


static struct ktr_header *
ktrgetheader(type)
	int type;
{
	register struct ktr_header *kth;
	struct proc *p = current_proc();	/* XXX */

	MALLOC(kth, struct ktr_header *, sizeof (struct ktr_header),
		M_KTRACE, M_WAITOK);
	if (kth != NULL) {
		kth->ktr_type = type;
		microtime(&kth->ktr_time);
		kth->ktr_pid = p->p_pid;
		bcopy(p->p_comm, kth->ktr_comm, MAXCOMLEN);
	}
	return (kth);
}
#endif

void
ktrsyscall(p, code, narg, args)
	struct proc *p;
	int code, narg;
	syscall_arg_t args[];
{
#if KTRACE
	struct vnode *vp;
	struct	ktr_header *kth;
	struct	ktr_syscall *ktp;
	register int len;
	u_int64_t *argp;
	int i;

	if (!KTRPOINT(p, KTR_SYSCALL))
		return;

	vp = p->p_tracep;
	len = __offsetof(struct ktr_syscall, ktr_args) +
	    (narg * sizeof(u_int64_t));
	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_SYSCALL);
	if (kth == NULL) {
		p->p_traceflag &= ~KTRFAC_ACTIVE;
		return;
	}
	MALLOC(ktp, struct ktr_syscall *, len, M_KTRACE, M_WAITOK);
	if (ktp == NULL) {
		FREE(kth, M_KTRACE);
		return;
	}
	ktp->ktr_code = code;
	ktp->ktr_narg = narg;
	argp = &ktp->ktr_args[0];
	for (i = 0; i < narg; i++)
		*argp++ = args[i];
	kth->ktr_buf = (caddr_t)ktp;
	kth->ktr_len = len;
	ktrwrite(vp, kth, NULL);
	FREE(ktp, M_KTRACE);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
#else
	return;
#endif
}
 
void
ktrsysret(p, code, error, retval)
	struct proc *p;
	int code, error;
	register_t retval;
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
	if (kth == NULL) {
		p->p_traceflag &= ~KTRFAC_ACTIVE;
		return;
	}
	ktp.ktr_code = code;
	ktp.ktr_error = error;
	ktp.ktr_retval = retval;		/* what about val2 ? */

	kth->ktr_buf = (caddr_t)&ktp;
	kth->ktr_len = sizeof(struct ktr_sysret);

	ktrwrite(vp, kth, NULL);
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
	if (kth == NULL) {
		p->p_traceflag &= ~KTRFAC_ACTIVE;
		return;
	}
	kth->ktr_len = strlen(path);
	kth->ktr_buf = path;

	ktrwrite(vp, kth, NULL);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
}

void
ktrgenio(vp, fd, rw, uio, error)
	struct vnode *vp;
	int fd;
	enum uio_rw rw;
	struct uio *uio;
	int error;
{
	struct ktr_header *kth;
	struct ktr_genio ktg;
	struct proc *p = current_proc();	/* XXX */

	if (error)
		return;

	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_GENIO);
	if (kth == NULL) {
		p->p_traceflag &= ~KTRFAC_ACTIVE;
		return;
	}
	ktg.ktr_fd = fd;
	ktg.ktr_rw = rw;
	kth->ktr_buf = (caddr_t)&ktg;
	kth->ktr_len = sizeof(struct ktr_genio);
	uio->uio_offset = 0;
	uio->uio_rw = UIO_WRITE;

	ktrwrite(vp, kth, uio);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
}

void
ktrpsig(vp, sig, action, mask, code)
	struct vnode *vp;
	int sig;
	sig_t action;
	sigset_t *mask;
	int code;
{
	struct ktr_header *kth;
	struct ktr_psig	kp;
	struct proc *p = current_proc();	/* XXX */

	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_PSIG);
	if (kth == NULL) {
		p->p_traceflag &= ~KTRFAC_ACTIVE;
		return;
	}
	kp.signo = (char)sig;
	kp.action = action;
	kp.mask = *mask;
	kp.code = code;
	kth->ktr_buf = (caddr_t)&kp;
	kth->ktr_len = sizeof (struct ktr_psig);

	ktrwrite(vp, kth, NULL);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
}

void
ktrcsw(vp, out, user)
	struct vnode *vp;
	int out, user;
{
	struct ktr_header *kth;
	struct	ktr_csw kc;
	struct proc *p = current_proc();	/* XXX */

	p->p_traceflag |= KTRFAC_ACTIVE;
	kth = ktrgetheader(KTR_CSW);
	if (kth == NULL) {
		p->p_traceflag &= ~KTRFAC_ACTIVE;
		return;
	}
	kc.out = out;
	kc.user = user;
	kth->ktr_buf = (caddr_t)&kc;
	kth->ktr_len = sizeof (struct ktr_csw);

	ktrwrite(vp, kth, NULL);
	FREE(kth, M_KTRACE);
	p->p_traceflag &= ~KTRFAC_ACTIVE;
}
#endif /* KTRACE */

/* Interface and common routines */

/*
 * ktrace system call
 */
/* ARGSUSED */
int
ktrace(struct proc *curp, register struct ktrace_args *uap, __unused register_t *retval)
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
	struct vfs_context context;

	AUDIT_ARG(cmd, uap->ops);
	AUDIT_ARG(pid, uap->pid);
	AUDIT_ARG(value, uap->facs);

	context.vc_proc = curp;
	context.vc_ucred = kauth_cred_get();

	curp->p_traceflag |= KTRFAC_ACTIVE;
	if (ops != KTROP_CLEAR) {
		/*
		 * an operation which requires a file argument.
		 */
		NDINIT(&nd, LOOKUP, (NOFOLLOW|LOCKLEAF), UIO_USERSPACE, 
			   uap->fname, &context);
		error = vn_open(&nd, FREAD|FWRITE|O_NOFOLLOW, 0);
		if (error) {
			curp->p_traceflag &= ~KTRFAC_ACTIVE;
			return (error);
		}
		vp = nd.ni_vp;

		if (vp->v_type != VREG) {
			(void) vn_close(vp, FREAD|FWRITE, kauth_cred_get(), curp);
			(void) vnode_put(vp);

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
						vnode_rele(tvp);
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
		AUDIT_ARG(process, p);
		if (descend)
			ret |= ktrsetchildren(curp, p, ops, facs, vp);
		else
			ret |= ktrops(curp, p, ops, facs, vp);
	}
	if (!ret)
		error = EPERM;
done:
	if (vp != NULL) {
		(void) vn_close(vp, FWRITE, kauth_cred_get(), curp);
		(void) vnode_put(vp);
	}
	curp->p_traceflag &= ~KTRFAC_ACTIVE;
	return (error);
#else
	return ENOSYS;
#endif
}

/*
 * utrace system call
 */

/* ARGSUSED */
int
utrace(__unused struct proc *curp, register struct utrace_args *uap, __unused register_t *retval)
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
	if (kth == NULL) {
		p->p_traceflag &= ~KTRFAC_ACTIVE;
		return(ENOMEM);
	}
	MALLOC(cp, caddr_t, uap->len, M_KTRACE, M_WAITOK);
	if (cp == NULL) {
		FREE(kth, M_KTRACE);
		return(ENOMEM);
	}
	if (copyin(uap->addr, cp, uap->len) == 0) {
		kth->ktr_buf = cp;
		kth->ktr_len = uap->len;
		ktrwrite(p->p_tracep, kth, NULL);
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
			tvp = p->p_tracep;
			vnode_ref(vp);
			p->p_tracep = vp;

			if (tvp != NULL) {
			        /*
				 * if trace file already in use, relinquish
				 */
				vnode_rele(tvp);
			}
		}
		p->p_traceflag |= facs;
		if (!suser(kauth_cred_get(), NULL))
			p->p_traceflag |= KTRFAC_ROOT;
	} else {
		/* KTROP_CLEAR */
		if (((p->p_traceflag &= ~facs) & KTRFAC_MASK) == 0) {
			/* no more tracing */
			tvp = p->p_tracep;
			p->p_traceflag = 0;
			if (tvp != NULL) {
				p->p_tracep = NULL;
				vnode_rele(tvp);
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
ktrwrite(struct vnode *vp, struct ktr_header *kth, struct uio *uio)
{
	uio_t auio;
	register struct proc *p = current_proc();	/* XXX */
	struct vfs_context context;
	int error;
	char uio_buf[ UIO_SIZEOF(2) ];

	if (vp == NULL)
		return;

	auio = uio_createwithbuffer(2, 0, UIO_SYSSPACE, UIO_WRITE, 
								  &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(kth), sizeof(struct ktr_header));
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	
	if (kth->ktr_len > 0) {
		uio_addiov(auio, CAST_USER_ADDR_T(kth->ktr_buf), kth->ktr_len);
		if (uio != NULL)
			kth->ktr_len += uio_resid(uio);
	}
	if ((error = vnode_getwithref(vp)) == 0) {
	        error = VNOP_WRITE(vp, auio, IO_UNIT | IO_APPEND, &context);
		if (error == 0 && uio != NULL) {
		        error = VNOP_WRITE(vp, uio, IO_UNIT | IO_APPEND, &context);
		}
		vnode_put(vp);
	}
	if (error) {
	        /*
		 * If error encountered, give up tracing on this vnode.
		 */
	        log(LOG_NOTICE, "ktrace write failed, errno %d, tracing stopped\n",
		    error);
		LIST_FOREACH(p, &allproc, p_list) {
		        if (p->p_tracep == vp) {
			        p->p_tracep = NULL;
				p->p_traceflag = 0;
				vnode_rele(vp);
			}
		}
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
ktrcanset(__unused struct proc *callp, struct proc *targetp)
{
	kauth_cred_t caller = kauth_cred_get();
	kauth_cred_t target = targetp->p_ucred;		/* XXX */

#if 0
	/* PRISON_CHECK was defined to 1 always .... */
	if (!PRISON_CHECK(callp, targetp))
		return (0);
#endif
	if ((kauth_cred_getuid(caller) == target->cr_ruid &&
	     target->cr_ruid == target->cr_svuid &&
	     caller->cr_rgid == target->cr_rgid &&	/* XXX */
	     target->cr_rgid == target->cr_svgid &&
	     (targetp->p_traceflag & KTRFAC_ROOT) == 0 &&
	     (targetp->p_flag & P_SUGID) == 0) ||
	     !suser(caller, NULL))
		return (1);

	return (0);
}

#endif /* KTRACE */
