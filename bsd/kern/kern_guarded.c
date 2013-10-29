/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/guarded.h>
#include <kern/kalloc.h>
#include <sys/sysproto.h>
#include <sys/vnode.h>
#include <vfs/vfs_support.h>
#include <security/audit/audit.h>

/*
 * Experimental guarded file descriptor support.
 */

kern_return_t task_exception_notify(exception_type_t exception,
        mach_exception_data_type_t code, mach_exception_data_type_t subcode);

/*
 * Most fd's have an underlying fileproc struct; but some may be
 * guarded_fileproc structs which implement guarded fds.  The latter
 * struct (below) embeds the former.
 *
 * The two types should be distinguished by the "type" portion of f_flags.
 * There's also a magic number to help catch misuse and bugs.
 *
 * This is a bit unpleasant, but results from the desire to allow
 * alternate file behaviours for a few file descriptors without
 * growing the fileproc data structure.
 */

struct guarded_fileproc {
	struct fileproc gf_fileproc;
	u_int		gf_magic;
	u_int		gf_attrs;
	thread_t	gf_thread;
	guardid_t	gf_guard;
	int		gf_exc_fd;
	u_int		gf_exc_code;
};

const size_t sizeof_guarded_fileproc = sizeof (struct guarded_fileproc);

#define FP_TO_GFP(fp)	((struct guarded_fileproc *)(fp))
#define	GFP_TO_FP(gfp)	(&(gfp)->gf_fileproc)

#define GUARDED_FILEPROC_MAGIC	0x29083

struct gfp_crarg {
	guardid_t gca_guard;
	u_int gca_attrs;
};

static struct fileproc *
guarded_fileproc_alloc_init(void *crarg)
{
	struct gfp_crarg *aarg = crarg;
	struct guarded_fileproc *gfp;

	if ((gfp = kalloc(sizeof (*gfp))) == NULL)
		return (NULL);

	bzero(gfp, sizeof (*gfp));
	gfp->gf_fileproc.f_flags = FTYPE_GUARDED;
	gfp->gf_magic = GUARDED_FILEPROC_MAGIC;
	gfp->gf_guard = aarg->gca_guard;
	gfp->gf_attrs = aarg->gca_attrs;

	return (GFP_TO_FP(gfp));
}

void
guarded_fileproc_free(struct fileproc *fp)
{
	struct guarded_fileproc *gfp = FP_TO_GFP(fp);

	if (FILEPROC_TYPE(fp) != FTYPE_GUARDED ||
	    GUARDED_FILEPROC_MAGIC != gfp->gf_magic)
		panic("%s: corrupt fp %p flags %x", __func__, fp, fp->f_flags);

	kfree(gfp, sizeof (*gfp));
}

static int
fp_lookup_guarded(proc_t p, int fd, guardid_t guard,
    struct guarded_fileproc **gfpp)
{
	struct fileproc *fp;
	int error;

	if ((error = fp_lookup(p, fd, &fp, 1)) != 0)
		return (error);
	if (FILEPROC_TYPE(fp) != FTYPE_GUARDED) {
		(void) fp_drop(p, fd, fp, 1);
		return (EINVAL);
	}
	struct guarded_fileproc *gfp = FP_TO_GFP(fp);

	if (GUARDED_FILEPROC_MAGIC != gfp->gf_magic)
		panic("%s: corrupt fp %p", __func__, fp);

	if (guard != gfp->gf_guard) {
		(void) fp_drop(p, fd, fp, 1);
		return (EPERM);	/* *not* a mismatch exception */
	}
	if (gfpp)
		*gfpp = gfp;
	return (0);
}

/*
 * Expected use pattern:
 *
 * if (FP_ISGUARDED(fp, GUARD_CLOSE)) {
 * 	error = fp_guard_exception(p, fd, fp, kGUARD_EXC_CLOSE);
 *      proc_fdunlock(p);
 *      return (error);
 * }
 */

int
fp_isguarded(struct fileproc *fp, u_int attrs)
{
	if (FILEPROC_TYPE(fp) == FTYPE_GUARDED) {
		struct guarded_fileproc *gfp = FP_TO_GFP(fp);

		if (GUARDED_FILEPROC_MAGIC != gfp->gf_magic)
			panic("%s: corrupt gfp %p flags %x",
			    __func__, gfp, fp->f_flags);
		return ((attrs & gfp->gf_attrs) ? 1 : 0);
	}
	return (0);
}

extern char *proc_name_address(void *p);

int
fp_guard_exception(proc_t p, int fd, struct fileproc *fp, u_int code)
{
	if (FILEPROC_TYPE(fp) != FTYPE_GUARDED)
		panic("%s corrupt fp %p flags %x", __func__, fp, fp->f_flags);

	struct guarded_fileproc *gfp = FP_TO_GFP(fp);

	/* all gfd fields protected via proc_fdlock() */
	proc_fdlock_assert(p, LCK_MTX_ASSERT_OWNED);

	if (NULL == gfp->gf_thread) {
		thread_t t = current_thread();
		gfp->gf_thread = t;
		gfp->gf_exc_fd = fd;
		gfp->gf_exc_code = code;

		/*
		 * This thread was the first to attempt the
		 * operation that violated the guard on this fd;
		 * generate an exception.
		 */
		printf("%s: guarded fd exception: "
		    "fd %d code 0x%x guard 0x%llx\n",
		    proc_name_address(p), gfp->gf_exc_fd,
		    gfp->gf_exc_code, gfp->gf_guard);

		thread_guard_violation(t, GUARD_TYPE_FD);
	} else {
		/*
		 * We already recorded a violation on this fd for a
		 * different thread, so posting an exception is
		 * already in progress.  We could pause for a bit
		 * and check again, or we could panic (though that seems
		 * heavy handed), or we could just press on with the
		 * error return alone.  For now, resort to printf.
		 */
		printf("%s: guarded fd exception+: "
		    "fd %d code 0x%x guard 0x%llx\n",
		    proc_name_address(p), gfp->gf_exc_fd,
		    gfp->gf_exc_code, gfp->gf_guard);
	}

	return (EPERM);
}

/*
 * (Invoked before returning to userland from the syscall handler.)
 */
void
fd_guard_ast(thread_t t)
{
	proc_t p = current_proc();
	struct filedesc *fdp = p->p_fd;
	int i;

	proc_fdlock(p);
	for (i = fdp->fd_lastfile; i >= 0; i--) {
		struct fileproc *fp = fdp->fd_ofiles[i];

		if (fp == NULL ||
		    FILEPROC_TYPE(fp) != FTYPE_GUARDED)
			continue;

		struct guarded_fileproc *gfp = FP_TO_GFP(fp);

		if (GUARDED_FILEPROC_MAGIC != gfp->gf_magic)
			panic("%s: corrupt gfp %p flags %x",
			    __func__, gfp, fp->f_flags);

		if (gfp->gf_thread == t) {
			mach_exception_data_type_t code, subcode;

			gfp->gf_thread = NULL;

			/*
			 * EXC_GUARD exception code namespace.
			 *
			 * code:
			 * +-------------------------------------------------+
			 * | [63:61] guard type | [60:0] guard-specific data |
			 * +-------------------------------------------------+
			 *
			 * subcode:
			 * +-------------------------------------------------+
			 * |       [63:0] guard-specific data                |
			 * +-------------------------------------------------+
			 *
			 * At the moment, we have just one guard type: file
			 * descriptor guards.
			 *
			 * File descriptor guards use the exception codes like
			 * so:
			 *
			 * code:			 
			 * +--------------------------------------------------+
			 * |[63:61] GUARD_TYPE_FD | [60:32] flavor | [31:0] fd|
			 * +--------------------------------------------------+
			 *
			 * subcode:
			 * +--------------------------------------------------+
			 * |       [63:0] guard value                         |
			 * +--------------------------------------------------+
			 */
			code = (((uint64_t)GUARD_TYPE_FD) << 61) |
			       (((uint64_t)gfp->gf_exc_code) << 32) |
			       ((uint64_t)gfp->gf_exc_fd);
			subcode = gfp->gf_guard;
			proc_fdunlock(p);

			(void) task_exception_notify(EXC_GUARD, code, subcode);
			psignal(p, SIGKILL);

			return;
		}
	}
	proc_fdunlock(p);
}

/*
 * Experimental guarded file descriptor SPIs
 */

/*
 * int guarded_open_np(const char *pathname, int flags,
 *     const guardid_t *guard, u_int guardflags, ...);
 *
 * In this initial implementation, GUARD_DUP must be specified.
 * GUARD_CLOSE, GUARD_SOCKET_IPC and GUARD_FILEPORT are optional.
 *
 * If GUARD_DUP wasn't specified, then we'd have to do the (extra) work
 * to allow dup-ing a descriptor to inherit the guard onto the new
 * descriptor.  (Perhaps GUARD_DUP behaviours should just always be true
 * for a guarded fd?  Or, more sanely, all the dup operations should
 * just always propagate the guard?)
 *
 * Guarded descriptors are always close-on-exec, and GUARD_CLOSE
 * requires close-on-fork; O_CLOEXEC must be set in flags.
 * This setting is immutable; attempts to clear the flag will
 * cause a guard exception.
 */
int
guarded_open_np(proc_t p, struct guarded_open_np_args *uap, int32_t *retval)
{
	if ((uap->flags & O_CLOEXEC) == 0)
		return (EINVAL);

#define GUARD_REQUIRED (GUARD_DUP)
#define GUARD_ALL      (GUARD_REQUIRED |	\
			(GUARD_CLOSE | GUARD_SOCKET_IPC | GUARD_FILEPORT))

	if (((uap->guardflags & GUARD_REQUIRED) != GUARD_REQUIRED) ||
	    ((uap->guardflags & ~GUARD_ALL) != 0))
		return (EINVAL);

	int error;
	struct gfp_crarg crarg = {
		.gca_attrs = uap->guardflags
	};

	if ((error = copyin(uap->guard,
	    &(crarg.gca_guard), sizeof (crarg.gca_guard))) != 0)
		return (error);

	/*
	 * Disallow certain guard values -- is zero enough?
	 */
	if (crarg.gca_guard == 0)
		return (EINVAL);

	struct filedesc *fdp = p->p_fd;
	struct vnode_attr va;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	int cmode;

	VATTR_INIT(&va);
	cmode = ((uap->mode & ~fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode & ACCESSPERMS);

	NDINIT(&nd, LOOKUP, OP_OPEN, FOLLOW | AUDITVNPATH1, UIO_USERSPACE,
	       uap->path, ctx);

	return (open1(ctx, &nd, uap->flags | O_CLOFORK, &va,
	    guarded_fileproc_alloc_init, &crarg, retval));
}

/*
 * int guarded_kqueue_np(const guardid_t *guard, u_int guardflags);
 *
 * Create a guarded kqueue descriptor with guardid and guardflags.
 *
 * Same restrictions on guardflags as for guarded_open_np().
 * All kqueues are -always- close-on-exec and close-on-fork by themselves.
 *
 * XXX	Is it ever sensible to allow a kqueue fd (guarded or not) to
 *	be sent to another process via a fileport or socket?
 */
int
guarded_kqueue_np(proc_t p, struct guarded_kqueue_np_args *uap, int32_t *retval)
{
	if (((uap->guardflags & GUARD_REQUIRED) != GUARD_REQUIRED) ||
	    ((uap->guardflags & ~GUARD_ALL) != 0))
		return (EINVAL);

	int error;
	struct gfp_crarg crarg = {
		.gca_attrs = uap->guardflags
	};

	if ((error = copyin(uap->guard,
	    &(crarg.gca_guard), sizeof (crarg.gca_guard))) != 0)
		return (error);

	if (crarg.gca_guard == 0)
		return (EINVAL);

	return (kqueue_body(p, guarded_fileproc_alloc_init, &crarg, retval));
}

/*
 * int guarded_close_np(int fd, const guardid_t *guard);
 */
int
guarded_close_np(proc_t p, struct guarded_close_np_args *uap,
    __unused int32_t *retval)
{
	struct guarded_fileproc *gfp;
	int fd = uap->fd;
	int error;
	guardid_t uguard;

	AUDIT_SYSCLOSE(p, fd);

	if ((error = copyin(uap->guard, &uguard, sizeof (uguard))) != 0)
		return (error);

	proc_fdlock(p);
	if ((error = fp_lookup_guarded(p, fd, uguard, &gfp)) != 0) {
		proc_fdunlock(p);
		return (error);
	}
	error = close_internal_locked(p, fd, GFP_TO_FP(gfp), 0);
	proc_fdunlock(p);
	return (error);
}

/*
 * int
 * change_fdguard_np(int fd, const guardid_t *guard, u_int guardflags,
 *    const guardid_t *nguard, u_int nguardflags, int *fdflagsp);
 *
 * Given a file descriptor, atomically exchange <guard, guardflags> for
 * a new guard <nguard, nguardflags>, returning the previous fd
 * flags (see fcntl:F_SETFD) in *fdflagsp.
 *
 * This syscall can be used to either (a) add a new guard to an existing
 * unguarded file descriptor (b) remove the old guard from an existing
 * guarded file descriptor or (c) change the guard (guardid and/or
 * guardflags) on a guarded file descriptor.
 *
 * If 'guard' is NULL, fd must be unguarded at entry. If the call completes
 * successfully the fd will be guarded with <nguard, nguardflags>.
 *
 * Guarding a file descriptor has some side-effects on the "fdflags"
 * associated with the descriptor - in particular FD_CLOEXEC is
 * forced ON unconditionally, and FD_CLOFORK is forced ON by GUARD_CLOSE.
 * Callers who wish to subsequently restore the state of the fd should save
 * the value of *fdflagsp after a successful invocation.
 *
 * If 'nguard' is NULL, fd must be guarded at entry, <guard, guardflags>
 * must match with what's already guarding the descriptor, and the
 * result will be to completely remove the guard.  Note also that the
 * fdflags are copied to the descriptor from the incoming *fdflagsp argument. 
 *
 * If the descriptor is guarded, and neither 'guard' nor 'nguard' is NULL
 * and <guard, guardflags> matches what's already guarding the descriptor,
 * then <nguard, nguardflags> becomes the new guard.  In this case, even if
 * the GUARD_CLOSE flag is being cleared, it is still possible to continue
 * to keep FD_CLOFORK on the descriptor by passing FD_CLOFORK via fdflagsp.
 *
 * Example 1: Guard an unguarded descriptor during a set of operations,
 * then restore the original state of the descriptor.
 *
 * int sav_flags = 0;
 * change_fdguard_np(fd, NULL, 0, &myguard, GUARD_CLOSE, &sav_flags);
 * // do things with now guarded 'fd'
 * change_fdguard_np(fd, &myguard, GUARD_CLOSE, NULL, 0, &sav_flags);
 * // fd now unguarded.
 *
 * Example 2: Change the guard of a guarded descriptor during a set of
 * operations, then restore the original state of the descriptor.
 *
 * int sav_flags = (gdflags & GUARD_CLOSE) ? FD_CLOFORK : 0;
 * change_fdguard_np(fd, &gd, gdflags, &myguard, GUARD_CLOSE, &sav_flags);
 * // do things with 'fd' with a different guard
 * change_fdguard_np(fd, &myg, GUARD_CLOSE, &gd, gdflags, &sav_flags);
 * // back to original guarded state
 */

#define FDFLAGS_GET(p, fd) (*fdflags(p, fd) & (UF_EXCLOSE|UF_FORKCLOSE))
#define FDFLAGS_SET(p, fd, bits) \
	   (*fdflags(p, fd) |= ((bits) & (UF_EXCLOSE|UF_FORKCLOSE)))
#define FDFLAGS_CLR(p, fd, bits) \
	   (*fdflags(p, fd) &= ~((bits) & (UF_EXCLOSE|UF_FORKCLOSE)))

int
change_fdguard_np(proc_t p, struct change_fdguard_np_args *uap,
    __unused int32_t *retval)
{
	struct fileproc *fp;
	int fd = uap->fd;
	int error;
	guardid_t oldg = 0, newg = 0;
	int nfdflags = 0;

	if (0 != uap->guard &&
	    0 != (error = copyin(uap->guard, &oldg, sizeof (oldg))))
		return (error); /* can't copyin current guard */

	if (0 != uap->nguard &&
	    0 != (error = copyin(uap->nguard, &newg, sizeof (newg))))
		return (error); /* can't copyin new guard */

	if (0 != uap->fdflagsp &&
	    0 != (error = copyin(uap->fdflagsp, &nfdflags, sizeof (nfdflags))))
		return (error); /* can't copyin new fdflags */
	    
	proc_fdlock(p);
restart:
	if ((error = fp_lookup(p, fd, &fp, 1)) != 0) {
		proc_fdunlock(p);
		return (error);
	}

	if (0 != uap->fdflagsp) {
		int ofdflags = FDFLAGS_GET(p, fd);
		int ofl = ((ofdflags & UF_EXCLOSE) ? FD_CLOEXEC : 0) |
			((ofdflags & UF_FORKCLOSE) ? FD_CLOFORK : 0);
		proc_fdunlock(p);
		if (0 != (error = copyout(&ofl, uap->fdflagsp, sizeof (ofl)))) {
			proc_fdlock(p);
			goto dropout; /* can't copyout old fdflags */
		}
		proc_fdlock(p);
	}

	if (FILEPROC_TYPE(fp) == FTYPE_GUARDED) {
		if (0 == uap->guard || 0 == uap->guardflags)
			error = EINVAL; /* missing guard! */
		else if (0 == oldg)
			error = EPERM; /* guardids cannot be zero */
	} else {
		if (0 != uap->guard || 0 != uap->guardflags)
			error = EINVAL; /* guard provided, but none needed! */
	}

	if (0 != error)
		goto dropout;

	if (0 != uap->nguard) {
		/*
		 * There's a new guard in town.
		 */
		if (0 == newg)
			error = EINVAL; /* guards cannot contain zero */
		else if (0 == uap->nguardflags)
			error = EINVAL; /* attributes cannot be zero */
		else if (((uap->nguardflags & GUARD_REQUIRED) != GUARD_REQUIRED) ||
		    ((uap->guardflags & ~GUARD_ALL) != 0))
			error = EINVAL; /* must have valid attributes too */
	     
		if (0 != error)
			goto dropout;

		if (FILEPROC_TYPE(fp) == FTYPE_GUARDED) {
			/*
			 * Replace old guard with new guard
			 */
			struct guarded_fileproc *gfp = FP_TO_GFP(fp);

			if (GUARDED_FILEPROC_MAGIC != gfp->gf_magic)
				panic("%s: corrupt gfp %p flags %x",
				      __func__, gfp, fp->f_flags);

			if (oldg == gfp->gf_guard &&
			    uap->guardflags == gfp->gf_attrs) {
				/*
				 * Must match existing guard + attributes
				 * before we'll swap them to new ones, managing
				 * fdflags "side-effects" as we go.   Note that
				 * userland can request FD_CLOFORK semantics.
				 */
				if (gfp->gf_attrs & GUARD_CLOSE)
					FDFLAGS_CLR(p, fd, UF_FORKCLOSE);
				gfp->gf_guard = newg;
				gfp->gf_attrs = uap->nguardflags;
				if (gfp->gf_attrs & GUARD_CLOSE)
					FDFLAGS_SET(p, fd, UF_FORKCLOSE);
				FDFLAGS_SET(p, fd,
				    (nfdflags & FD_CLOFORK) ? UF_FORKCLOSE : 0);
			} else {
				error = EPERM;
			}
			goto dropout;
		} else {
			/*
			 * Add a guard to a previously unguarded descriptor
			 */
			switch (FILEGLOB_DTYPE(fp->f_fglob)) {
			case DTYPE_VNODE:
			case DTYPE_PIPE:
			case DTYPE_SOCKET:
			case DTYPE_KQUEUE:
				break;
			default:
				error = ENOTSUP;
				goto dropout;
			}

			proc_fdunlock(p);

			struct gfp_crarg crarg = {
				.gca_guard = newg,
				.gca_attrs = uap->nguardflags
			};
			struct fileproc *nfp =
				guarded_fileproc_alloc_init(&crarg);

			proc_fdlock(p);

			switch (error = fp_tryswap(p, fd, nfp)) {
				struct guarded_fileproc *gfp;

			case 0: /* guarded-ness comes with side-effects */
				gfp = FP_TO_GFP(nfp);
				if (gfp->gf_attrs & GUARD_CLOSE)
					FDFLAGS_SET(p, fd, UF_FORKCLOSE);
				FDFLAGS_SET(p, fd, UF_EXCLOSE);
				(void) fp_drop(p, fd, nfp, 1);
				fileproc_free(fp);
				break;
			case EKEEPLOOKING: /* f_iocount indicates a collision */
				(void) fp_drop(p, fd, fp, 1);
				fileproc_free(nfp);
				goto restart;
			default:
				(void) fp_drop(p, fd, fp, 1);
				fileproc_free(nfp);
				break;
			}
			proc_fdunlock(p);
			return (error);
		}
	} else {
		/*
		 * No new guard.
		 */
		if (FILEPROC_TYPE(fp) == FTYPE_GUARDED) {
			/*
			 * Remove the guard altogether.
			 */
			struct guarded_fileproc *gfp = FP_TO_GFP(fp);

			if (0 != uap->nguardflags) {
				error = EINVAL;
				goto dropout;
			}

			if (GUARDED_FILEPROC_MAGIC != gfp->gf_magic)
				panic("%s: corrupt gfp %p flags %x",
				      __func__, gfp, fp->f_flags);

			if (oldg != gfp->gf_guard ||
			    uap->guardflags != gfp->gf_attrs) {
				error = EPERM;
				goto dropout;
			}

			proc_fdunlock(p);
			struct fileproc *nfp = fileproc_alloc_init(NULL);
			proc_fdlock(p);

			switch (error = fp_tryswap(p, fd, nfp)) {
			case 0: /* undo side-effects of guarded-ness */
				FDFLAGS_CLR(p, fd, UF_FORKCLOSE | UF_EXCLOSE);
				FDFLAGS_SET(p, fd,
				    (nfdflags & FD_CLOFORK) ? UF_FORKCLOSE : 0);
				FDFLAGS_SET(p, fd,
				    (nfdflags & FD_CLOEXEC) ? UF_EXCLOSE : 0);
				(void) fp_drop(p, fd, nfp, 1);
				fileproc_free(fp);
				break;
			case EKEEPLOOKING: /* f_iocount indicates collision */
				(void) fp_drop(p, fd, fp, 1);
				fileproc_free(nfp);
				goto restart;
			default:
				(void) fp_drop(p, fd, fp, 1);
				fileproc_free(nfp);
				break;
			}
			proc_fdunlock(p);
			return (error);
		} else {
			/*
			 * Not already guarded, and no new guard?
			 */
			error = EINVAL;
		}
	}

dropout:
	(void) fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);
	return (error);
}
		
