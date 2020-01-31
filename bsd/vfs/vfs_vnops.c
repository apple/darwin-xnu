/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)vfs_vnops.c	8.14 (Berkeley) 6/15/95
 *
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
/* Temporary workaround for ubc.h until <rdar://4714366 is resolved */
#define ubc_setcred ubc_setcred_deprecated
#include <sys/ubc.h>
#undef ubc_setcred
int     ubc_setcred(struct vnode *, struct proc *);
#include <sys/conf.h>
#include <sys/disk.h>
#include <sys/fsevents.h>
#include <sys/kdebug.h>
#include <sys/xattr.h>
#include <sys/ubc_internal.h>
#include <sys/uio_internal.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <IOKit/IOBSD.h>
#include <libkern/section_keywords.h>

static int vn_closefile(struct fileglob *fp, vfs_context_t ctx);
static int vn_ioctl(struct fileproc *fp, u_long com, caddr_t data,
    vfs_context_t ctx);
static int vn_read(struct fileproc *fp, struct uio *uio, int flags,
    vfs_context_t ctx);
static int vn_write(struct fileproc *fp, struct uio *uio, int flags,
    vfs_context_t ctx);
static int vn_select( struct fileproc *fp, int which, void * wql,
    vfs_context_t ctx);
static int vn_kqfilt_add(struct fileproc *fp, struct knote *kn,
    struct kevent_internal_s *kev, vfs_context_t ctx);
static void filt_vndetach(struct knote *kn);
static int filt_vnode(struct knote *kn, long hint);
static int filt_vnode_common(struct knote *kn, vnode_t vp, long hint);
static int vn_open_auth_finish(vnode_t vp, int fmode, vfs_context_t ctx);
#if 0
static int vn_kqfilt_remove(struct vnode *vp, uintptr_t ident,
    vfs_context_t ctx);
#endif

const struct fileops vnops = {
	.fo_type = DTYPE_VNODE,
	.fo_read = vn_read,
	.fo_write = vn_write,
	.fo_ioctl = vn_ioctl,
	.fo_select = vn_select,
	.fo_close = vn_closefile,
	.fo_kqfilter = vn_kqfilt_add,
	.fo_drain = NULL,
};

static int filt_vntouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_vnprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);

SECURITY_READ_ONLY_EARLY(struct  filterops) vnode_filtops = {
	.f_isfd = 1,
	.f_attach = NULL,
	.f_detach = filt_vndetach,
	.f_event = filt_vnode,
	.f_touch = filt_vntouch,
	.f_process = filt_vnprocess,
};

/*
 * Common code for vnode open operations.
 * Check permissions, and call the VNOP_OPEN or VNOP_CREATE routine.
 *
 * XXX the profusion of interfaces here is probably a bad thing.
 */
int
vn_open(struct nameidata *ndp, int fmode, int cmode)
{
	return vn_open_modflags(ndp, &fmode, cmode);
}

int
vn_open_modflags(struct nameidata *ndp, int *fmodep, int cmode)
{
	struct vnode_attr va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, cmode);

	return vn_open_auth(ndp, fmodep, &va);
}

static int
vn_open_auth_finish(vnode_t vp, int fmode, vfs_context_t ctx)
{
	int error;

	if ((error = vnode_ref_ext(vp, fmode, 0)) != 0) {
		goto bad;
	}

	/* Call out to allow 3rd party notification of open.
	 * Ignore result of kauth_authorize_fileop call.
	 */
#if CONFIG_MACF
	mac_vnode_notify_open(ctx, vp, fmode);
#endif
	kauth_authorize_fileop(vfs_context_ucred(ctx), KAUTH_FILEOP_OPEN,
	    (uintptr_t)vp, 0);

	return 0;

bad:
	return error;
}

/*
 * May do nameidone() to allow safely adding an FSEvent.  Cue off of ni_dvp to
 * determine whether that has happened.
 */
static int
vn_open_auth_do_create(struct nameidata *ndp, struct vnode_attr *vap, int fmode, boolean_t *did_create, boolean_t *did_open, vfs_context_t ctx)
{
	uint32_t status = 0;
	vnode_t dvp = ndp->ni_dvp;
	int batched;
	int error;
	vnode_t vp;

	batched = vnode_compound_open_available(ndp->ni_dvp);
	*did_open = FALSE;

	VATTR_SET(vap, va_type, VREG);
	if (fmode & O_EXCL) {
		vap->va_vaflags |= VA_EXCLUSIVE;
	}

#if NAMEDRSRCFORK
	if (ndp->ni_cnd.cn_flags & CN_WANTSRSRCFORK) {
		if ((error = vn_authorize_create(dvp, &ndp->ni_cnd, vap, ctx, NULL)) != 0) {
			goto out;
		}
		if ((error = vnode_makenamedstream(dvp, &ndp->ni_vp, XATTR_RESOURCEFORK_NAME, 0, ctx)) != 0) {
			goto out;
		}
		*did_create = TRUE;
	} else {
#endif
	if (!batched) {
		if ((error = vn_authorize_create(dvp, &ndp->ni_cnd, vap, ctx, NULL)) != 0) {
			goto out;
		}
	}

	error = vn_create(dvp, &ndp->ni_vp, ndp, vap, VN_CREATE_DOOPEN, fmode, &status, ctx);
	if (error != 0) {
		if (batched) {
			*did_create = (status & COMPOUND_OPEN_STATUS_DID_CREATE) ? TRUE : FALSE;
		} else {
			*did_create = FALSE;
		}

		if (error == EKEEPLOOKING) {
			if (*did_create) {
				panic("EKEEPLOOKING, but we did a create?");
			}
			if (!batched) {
				panic("EKEEPLOOKING from filesystem that doesn't support compound vnops?");
			}
			if ((ndp->ni_flag & NAMEI_CONTLOOKUP) == 0) {
				panic("EKEEPLOOKING, but continue flag not set?");
			}

			/*
			 * Do NOT drop the dvp: we need everything to continue the lookup.
			 */
			return error;
		}
	} else {
		if (batched) {
			*did_create = (status & COMPOUND_OPEN_STATUS_DID_CREATE) ? 1 : 0;
			*did_open = TRUE;
		} else {
			*did_create = TRUE;
		}
	}
#if NAMEDRSRCFORK
}
#endif

	vp = ndp->ni_vp;

	if (*did_create) {
		int     update_flags = 0;

		// Make sure the name & parent pointers are hooked up
		if (vp->v_name == NULL) {
			update_flags |= VNODE_UPDATE_NAME;
		}
		if (vp->v_parent == NULLVP) {
			update_flags |= VNODE_UPDATE_PARENT;
		}

		if (update_flags) {
			vnode_update_identity(vp, dvp, ndp->ni_cnd.cn_nameptr, ndp->ni_cnd.cn_namelen, ndp->ni_cnd.cn_hash, update_flags);
		}

		vnode_put(dvp);
		ndp->ni_dvp = NULLVP;

#if CONFIG_FSE
		if (need_fsevent(FSE_CREATE_FILE, vp)) {
			add_fsevent(FSE_CREATE_FILE, ctx,
			    FSE_ARG_VNODE, vp,
			    FSE_ARG_DONE);
		}
#endif
	}
out:
	if (ndp->ni_dvp != NULLVP) {
		vnode_put(dvp);
		ndp->ni_dvp = NULLVP;
	}

	return error;
}

/*
 * This is the number of times we'll loop in vn_open_auth without explicitly
 * yielding the CPU when we determine we have to retry.
 */
#define RETRY_NO_YIELD_COUNT    5

/*
 * Open a file with authorization, updating the contents of the structures
 * pointed to by ndp, fmodep, and vap as necessary to perform the requested
 * operation.  This function is used for both opens of existing files, and
 * creation of new files.
 *
 * Parameters:	ndp			The nami data pointer describing the
 *					file
 *		fmodep			A pointer to an int containg the mode
 *					information to be used for the open
 *		vap			A pointer to the vnode attribute
 *					descriptor to be used for the open
 *
 * Indirect:	*			Contents of the data structures pointed
 *					to by the parameters are modified as
 *					necessary to the requested operation.
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 * Notes:	The kauth_filesec_t in 'vap', if any, is in host byte order.
 *
 *		The contents of '*ndp' will be modified, based on the other
 *		arguments to this function, and to return file and directory
 *		data necessary to satisfy the requested operation.
 *
 *		If the file does not exist and we are creating it, then the
 *		O_TRUNC flag will be cleared in '*fmodep' to indicate to the
 *		caller that the file was not truncated.
 *
 *		If the file exists and the O_EXCL flag was not specified, then
 *		the O_CREAT flag will be cleared in '*fmodep' to indicate to
 *		the caller that the existing file was merely opened rather
 *		than created.
 *
 *		The contents of '*vap' will be modified as necessary to
 *		complete the operation, including setting of supported
 *		attribute, clearing of fields containing unsupported attributes
 *		in the request, if the request proceeds without them, etc..
 *
 * XXX:		This function is too complicated in actings on its arguments
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
int
vn_open_auth(struct nameidata *ndp, int *fmodep, struct vnode_attr *vap)
{
	struct vnode *vp;
	struct vnode *dvp;
	vfs_context_t ctx = ndp->ni_cnd.cn_context;
	int error;
	int fmode;
	uint32_t origcnflags;
	boolean_t did_create;
	boolean_t did_open;
	boolean_t need_vnop_open;
	boolean_t batched;
	boolean_t ref_failed;
	int nretries = 0;

again:
	vp = NULL;
	dvp = NULL;
	batched = FALSE;
	did_create = FALSE;
	need_vnop_open = TRUE;
	ref_failed = FALSE;
	fmode = *fmodep;
	origcnflags = ndp->ni_cnd.cn_flags;

	// If raw encrypted mode is requested, handle that here
	if (VATTR_IS_ACTIVE(vap, va_dataprotect_flags)
	    && ISSET(vap->va_dataprotect_flags, VA_DP_RAWENCRYPTED)) {
		fmode |= FENCRYPTED;
	}

	/*
	 * O_CREAT
	 */
	if (fmode & O_CREAT) {
		if ((fmode & O_DIRECTORY)) {
			error = EINVAL;
			goto out;
		}
		ndp->ni_cnd.cn_nameiop = CREATE;
#if CONFIG_TRIGGERS
		ndp->ni_op = OP_LINK;
#endif
		/* Inherit USEDVP, vnode_open() supported flags only */
		ndp->ni_cnd.cn_flags &= (USEDVP | NOCROSSMOUNT);
		ndp->ni_cnd.cn_flags |= LOCKPARENT | LOCKLEAF | AUDITVNPATH1;
		ndp->ni_flag = NAMEI_COMPOUNDOPEN;
#if NAMEDRSRCFORK
		/* open calls are allowed for resource forks. */
		ndp->ni_cnd.cn_flags |= CN_ALLOWRSRCFORK;
#endif
		if ((fmode & O_EXCL) == 0 && (fmode & O_NOFOLLOW) == 0 && (origcnflags & FOLLOW) != 0) {
			ndp->ni_cnd.cn_flags |= FOLLOW;
		}

continue_create_lookup:
		if ((error = namei(ndp))) {
			goto out;
		}

		dvp = ndp->ni_dvp;
		vp = ndp->ni_vp;

		batched = vnode_compound_open_available(dvp);

		/* not found, create */
		if (vp == NULL) {
			/* must have attributes for a new file */
			if (vap == NULL) {
				vnode_put(dvp);
				error = EINVAL;
				goto out;
			}
			/*
			 * Attempt a create.   For a system supporting compound VNOPs, we may
			 * find an existing file or create one; in either case, we will already
			 * have the file open and no VNOP_OPEN() will be needed.
			 */
			error = vn_open_auth_do_create(ndp, vap, fmode, &did_create, &did_open, ctx);

			dvp = ndp->ni_dvp;
			vp = ndp->ni_vp;

			/*
			 * Detected a node that the filesystem couldn't handle.  Don't call
			 * nameidone() yet, because we need that path buffer.
			 */
			if (error == EKEEPLOOKING) {
				if (!batched) {
					panic("EKEEPLOOKING from a filesystem that doesn't support compound VNOPs?");
				}
				goto continue_create_lookup;
			}

			nameidone(ndp);
			if (dvp) {
				panic("Shouldn't have a dvp here.");
			}

			if (error) {
				/*
				 * Check for a create race.
				 */
				if ((error == EEXIST) && !(fmode & O_EXCL)) {
					if (vp) {
						vnode_put(vp);
					}
					goto again;
				}
				goto bad;
			}

			need_vnop_open = !did_open;
		} else {
			if (fmode & O_EXCL) {
				error = EEXIST;
			}

			/*
			 * We have a vnode.  Use compound open if available
			 * or else fall through to "traditional" path.  Note: can't
			 * do a compound open for root, because the parent belongs
			 * to a different FS.
			 */
			if (error == 0 && batched && (vnode_mount(dvp) == vnode_mount(vp))) {
				error = VNOP_COMPOUND_OPEN(dvp, &ndp->ni_vp, ndp, 0, fmode, NULL, NULL, ctx);

				if (error == 0) {
					vp = ndp->ni_vp;
					need_vnop_open = FALSE;
				} else if (error == EKEEPLOOKING) {
					if ((ndp->ni_flag & NAMEI_CONTLOOKUP) == 0) {
						panic("EKEEPLOOKING, but continue flag not set?");
					}
					goto continue_create_lookup;
				}
			}
			nameidone(ndp);
			vnode_put(dvp);
			ndp->ni_dvp = NULLVP;

			if (error) {
				goto bad;
			}

			fmode &= ~O_CREAT;

			/* Fall through */
		}
	} else {
		/*
		 * Not O_CREAT
		 */
		ndp->ni_cnd.cn_nameiop = LOOKUP;
		/* Inherit USEDVP, vnode_open() supported flags only */
		ndp->ni_cnd.cn_flags &= (USEDVP | NOCROSSMOUNT);
		ndp->ni_cnd.cn_flags |= FOLLOW | LOCKLEAF | AUDITVNPATH1 | WANTPARENT;
#if NAMEDRSRCFORK
		/* open calls are allowed for resource forks. */
		ndp->ni_cnd.cn_flags |= CN_ALLOWRSRCFORK;
#endif
		if (fmode & FENCRYPTED) {
			ndp->ni_cnd.cn_flags |= CN_RAW_ENCRYPTED | CN_SKIPNAMECACHE;
		}
		ndp->ni_flag = NAMEI_COMPOUNDOPEN;

		/* preserve NOFOLLOW from vnode_open() */
		if (fmode & O_NOFOLLOW || fmode & O_SYMLINK || (origcnflags & FOLLOW) == 0) {
			ndp->ni_cnd.cn_flags &= ~FOLLOW;
		}

		/* Do a lookup, possibly going directly to filesystem for compound operation */
		do {
			if ((error = namei(ndp))) {
				goto out;
			}
			vp = ndp->ni_vp;
			dvp = ndp->ni_dvp;

			/* Check for batched lookup-open */
			batched = vnode_compound_open_available(dvp);
			if (batched && ((vp == NULLVP) || (vnode_mount(dvp) == vnode_mount(vp)))) {
				error = VNOP_COMPOUND_OPEN(dvp, &ndp->ni_vp, ndp, 0, fmode, NULL, NULL, ctx);
				vp = ndp->ni_vp;
				if (error == 0) {
					need_vnop_open = FALSE;
				} else if (error == EKEEPLOOKING) {
					if ((ndp->ni_flag & NAMEI_CONTLOOKUP) == 0) {
						panic("EKEEPLOOKING, but continue flag not set?");
					}
				}
			}
		} while (error == EKEEPLOOKING);

		nameidone(ndp);
		vnode_put(dvp);
		ndp->ni_dvp = NULLVP;

		if (error) {
			goto bad;
		}
	}

	/*
	 * By this point, nameidone() is called, dvp iocount is dropped,
	 * and dvp pointer is cleared.
	 */
	if (ndp->ni_dvp != NULLVP) {
		panic("Haven't cleaned up adequately in vn_open_auth()");
	}

#if DEVELOPMENT || DEBUG
	/*
	 * XXX VSWAP: Check for entitlements or special flag here
	 * so we can restrict access appropriately.
	 */
#else /* DEVELOPMENT || DEBUG */

	if (vnode_isswap(vp) && (fmode & (FWRITE | O_TRUNC)) && (ctx != vfs_context_kernel())) {
		error = EPERM;
		goto bad;
	}
#endif /* DEVELOPMENT || DEBUG */

	/*
	 * Expect to use this code for filesystems without compound VNOPs, for the root
	 * of a filesystem, which can't be "looked up" in the sense of VNOP_LOOKUP(),
	 * and for shadow files, which do not live on the same filesystems as their "parents."
	 */
	if (need_vnop_open) {
		if (batched && !vnode_isvroot(vp) && !vnode_isnamedstream(vp)) {
			panic("Why am I trying to use VNOP_OPEN() on anything other than the root or a named stream?");
		}

		if (!did_create) {
			error = vn_authorize_open_existing(vp, &ndp->ni_cnd, fmode, ctx, NULL);
			if (error) {
				goto bad;
			}
		}

		if (VATTR_IS_ACTIVE(vap, va_dataprotect_flags)
		    && ISSET(vap->va_dataprotect_flags, VA_DP_RAWUNENCRYPTED)) {
			/* Don't allow unencrypted io request from user space unless entitled */
			boolean_t entitled = FALSE;
#if !SECURE_KERNEL
			entitled = IOTaskHasEntitlement(current_task(), "com.apple.private.security.file-unencrypt-access");
#endif
			if (!entitled) {
				error = EPERM;
				goto bad;
			}
			fmode |= FUNENCRYPTED;
		}

		error = VNOP_OPEN(vp, fmode, ctx);
		if (error) {
			goto bad;
		}
		need_vnop_open = FALSE;
	}

	// if the vnode is tagged VOPENEVT and the current process
	// has the P_CHECKOPENEVT flag set, then we or in the O_EVTONLY
	// flag to the open mode so that this open won't count against
	// the vnode when carbon delete() does a vnode_isinuse() to see
	// if a file is currently in use.  this allows spotlight
	// importers to not interfere with carbon apps that depend on
	// the no-delete-if-busy semantics of carbon delete().
	//
	if (!did_create && (vp->v_flag & VOPENEVT) && (current_proc()->p_flag & P_CHECKOPENEVT)) {
		fmode |= O_EVTONLY;
	}

	/*
	 * Grab reference, etc.
	 */
	error = vn_open_auth_finish(vp, fmode, ctx);
	if (error) {
		ref_failed = TRUE;
		goto bad;
	}

	/* Compound VNOP open is responsible for doing the truncate */
	if (batched || did_create) {
		fmode &= ~O_TRUNC;
	}

	*fmodep = fmode;
	return 0;

bad:
	/* Opened either explicitly or by a batched create */
	if (!need_vnop_open) {
		VNOP_CLOSE(vp, fmode, ctx);
	}

	ndp->ni_vp = NULL;
	if (vp) {
#if NAMEDRSRCFORK
		/* Aggressively recycle shadow files if we error'd out during open() */
		if ((vnode_isnamedstream(vp)) &&
		    (vp->v_parent != NULLVP) &&
		    (vnode_isshadow(vp))) {
			vnode_recycle(vp);
		}
#endif
		vnode_put(vp);
		/*
		 * Check for a race against unlink.  We had a vnode
		 * but according to vnode_authorize or VNOP_OPEN it
		 * no longer exists.
		 *
		 * EREDRIVEOPEN: means that we were hit by the tty allocation race.
		 */
		if (((error == ENOENT) && (*fmodep & O_CREAT)) || (error == EREDRIVEOPEN) || ref_failed) {
			/*
			 * We'll retry here but it may be possible that we get
			 * into a retry "spin" inside the kernel and not allow
			 * threads, which need to run in order for the retry
			 * loop to end, to run. An example is an open of a
			 * terminal which is getting revoked and we spin here
			 * without yielding becasue namei and VNOP_OPEN are
			 * successful but vnode_ref fails. The revoke needs
			 * threads with an iocount to run but if spin here we
			 * may possibly be blcoking other threads from running.
			 *
			 * We start yielding the CPU after some number of
			 * retries for increasing durations. Note that this is
			 * still a loop without an exit condition.
			 */
			nretries += 1;
			if (nretries > RETRY_NO_YIELD_COUNT) {
				/* Every hz/100 secs is 10 msecs ... */
				tsleep(&nretries, PVFS, "vn_open_auth_retry",
				    MIN((nretries * (hz / 100)), hz));
			}
			goto again;
		}
	}

out:
	return error;
}

#if vn_access_DEPRECATED
/*
 * Authorize an action against a vnode.  This has been the canonical way to
 * ensure that the credential/process/etc. referenced by a vfs_context
 * is granted the rights called out in 'mode' against the vnode 'vp'.
 *
 * Unfortunately, the use of VREAD/VWRITE/VEXEC makes it very difficult
 * to add support for more rights.  As such, this interface will be deprecated
 * and callers will use vnode_authorize instead.
 */
int
vn_access(vnode_t vp, int mode, vfs_context_t context)
{
	kauth_action_t  action;

	action = 0;
	if (mode & VREAD) {
		action |= KAUTH_VNODE_READ_DATA;
	}
	if (mode & VWRITE) {
		action |= KAUTH_VNODE_WRITE_DATA;
	}
	if (mode & VEXEC) {
		action |= KAUTH_VNODE_EXECUTE;
	}

	return vnode_authorize(vp, NULL, action, context);
}
#endif  /* vn_access_DEPRECATED */

/*
 * Vnode close call
 */
int
vn_close(struct vnode *vp, int flags, vfs_context_t ctx)
{
	int error;
	int flusherror = 0;

#if NAMEDRSRCFORK
	/* Sync data from resource fork shadow file if needed. */
	if ((vp->v_flag & VISNAMEDSTREAM) &&
	    (vp->v_parent != NULLVP) &&
	    vnode_isshadow(vp)) {
		if (flags & FWASWRITTEN) {
			flusherror = vnode_flushnamedstream(vp->v_parent, vp, ctx);
		}
	}
#endif

	/* work around for foxhound */
	if (vnode_isspec(vp)) {
		(void)vnode_rele_ext(vp, flags, 0);
	}

	/*
	 * On HFS, we flush when the last writer closes.  We do this
	 * because resource fork vnodes hold a reference on data fork
	 * vnodes and that will prevent them from getting VNOP_INACTIVE
	 * which will delay when we flush cached data.  In future, we
	 * might find it beneficial to do this for all file systems.
	 * Note that it's OK to access v_writecount without the lock
	 * in this context.
	 */
	if (vp->v_tag == VT_HFS && (flags & FWRITE) && vp->v_writecount == 1) {
		VNOP_FSYNC(vp, MNT_NOWAIT, ctx);
	}

	error = VNOP_CLOSE(vp, flags, ctx);

#if CONFIG_FSE
	if (flags & FWASWRITTEN) {
		if (need_fsevent(FSE_CONTENT_MODIFIED, vp)) {
			add_fsevent(FSE_CONTENT_MODIFIED, ctx,
			    FSE_ARG_VNODE, vp,
			    FSE_ARG_DONE);
		}
	}
#endif

	if (!vnode_isspec(vp)) {
		(void)vnode_rele_ext(vp, flags, 0);
	}

	if (flusherror) {
		error = flusherror;
	}
	return error;
}

static int
vn_read_swapfile(
	struct vnode    *vp,
	uio_t           uio)
{
	int     error;
	off_t   swap_count, this_count;
	off_t   file_end, read_end;
	off_t   prev_resid;
	char    *my_swap_page;

	/*
	 * Reading from a swap file will get you zeroes.
	 */

	my_swap_page = NULL;
	error = 0;
	swap_count = uio_resid(uio);

	file_end = ubc_getsize(vp);
	read_end = uio->uio_offset + uio_resid(uio);
	if (uio->uio_offset >= file_end) {
		/* uio starts after end of file: nothing to read */
		swap_count = 0;
	} else if (read_end > file_end) {
		/* uio extends beyond end of file: stop before that */
		swap_count -= (read_end - file_end);
	}

	while (swap_count > 0) {
		if (my_swap_page == NULL) {
			MALLOC(my_swap_page, char *, PAGE_SIZE,
			    M_TEMP, M_WAITOK);
			memset(my_swap_page, '\0', PAGE_SIZE);
			/* add an end-of-line to keep line counters happy */
			my_swap_page[PAGE_SIZE - 1] = '\n';
		}
		this_count = swap_count;
		if (this_count > PAGE_SIZE) {
			this_count = PAGE_SIZE;
		}

		prev_resid = uio_resid(uio);
		error = uiomove((caddr_t) my_swap_page,
		    this_count,
		    uio);
		if (error) {
			break;
		}
		swap_count -= (prev_resid - uio_resid(uio));
	}
	if (my_swap_page != NULL) {
		FREE(my_swap_page, M_TEMP);
		my_swap_page = NULL;
	}

	return error;
}
/*
 * Package up an I/O request on a vnode into a uio and do it.
 */
int
vn_rdwr(
	enum uio_rw rw,
	struct vnode *vp,
	caddr_t base,
	int len,
	off_t offset,
	enum uio_seg segflg,
	int ioflg,
	kauth_cred_t cred,
	int *aresid,
	proc_t p)
{
	int64_t resid;
	int result;

	result = vn_rdwr_64(rw,
	    vp,
	    (uint64_t)(uintptr_t)base,
	    (int64_t)len,
	    offset,
	    segflg,
	    ioflg,
	    cred,
	    &resid,
	    p);

	/* "resid" should be bounded above by "len," which is an int */
	if (aresid != NULL) {
		*aresid = resid;
	}

	return result;
}


int
vn_rdwr_64(
	enum uio_rw rw,
	struct vnode *vp,
	uint64_t base,
	int64_t len,
	off_t offset,
	enum uio_seg segflg,
	int ioflg,
	kauth_cred_t cred,
	int64_t *aresid,
	proc_t p)
{
	uio_t auio;
	int spacetype;
	struct vfs_context context;
	int error = 0;
	char uio_buf[UIO_SIZEOF(1)];

	context.vc_thread = current_thread();
	context.vc_ucred = cred;

	if (UIO_SEG_IS_USER_SPACE(segflg)) {
		spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	} else {
		spacetype = UIO_SYSSPACE;
	}
	auio = uio_createwithbuffer(1, offset, spacetype, rw,
	    &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, base, len);

#if CONFIG_MACF
	/* XXXMAC
	 *      IO_NOAUTH should be re-examined.
	 *	Likely that mediation should be performed in caller.
	 */
	if ((ioflg & IO_NOAUTH) == 0) {
		/* passed cred is fp->f_cred */
		if (rw == UIO_READ) {
			error = mac_vnode_check_read(&context, cred, vp);
		} else {
			error = mac_vnode_check_write(&context, cred, vp);
		}
	}
#endif

	if (error == 0) {
		if (rw == UIO_READ) {
			if (vnode_isswap(vp) && ((ioflg & IO_SWAP_DISPATCH) == 0)) {
				error = vn_read_swapfile(vp, auio);
			} else {
				error = VNOP_READ(vp, auio, ioflg, &context);
			}
		} else {
#if DEVELOPMENT || DEBUG
			/*
			 * XXX VSWAP: Check for entitlements or special flag here
			 * so we can restrict access appropriately.
			 */
			error = VNOP_WRITE(vp, auio, ioflg, &context);
#else /* DEVELOPMENT || DEBUG */

			if (vnode_isswap(vp) && ((ioflg & (IO_SWAP_DISPATCH | IO_SKIP_ENCRYPTION)) == 0)) {
				error = EPERM;
			} else {
				error = VNOP_WRITE(vp, auio, ioflg, &context);
			}
#endif /* DEVELOPMENT || DEBUG */
		}
	}

	if (aresid) {
		*aresid = uio_resid(auio);
	} else if (uio_resid(auio) && error == 0) {
		error = EIO;
	}
	return error;
}

static inline void
vn_offset_lock(struct fileglob *fg)
{
	lck_mtx_lock_spin(&fg->fg_lock);
	while (fg->fg_lflags & FG_OFF_LOCKED) {
		fg->fg_lflags |= FG_OFF_LOCKWANT;
		msleep(&fg->fg_lflags, &fg->fg_lock, PVFS | PSPIN,
		    "fg_offset_lock_wait", 0);
	}
	fg->fg_lflags |= FG_OFF_LOCKED;
	lck_mtx_unlock(&fg->fg_lock);
}

static inline void
vn_offset_unlock(struct fileglob *fg)
{
	int lock_wanted = 0;

	lck_mtx_lock_spin(&fg->fg_lock);
	if (fg->fg_lflags & FG_OFF_LOCKWANT) {
		lock_wanted = 1;
	}
	fg->fg_lflags &= ~(FG_OFF_LOCKED | FG_OFF_LOCKWANT);
	lck_mtx_unlock(&fg->fg_lock);
	if (lock_wanted) {
		wakeup(&fg->fg_lflags);
	}
}

/*
 * File table vnode read routine.
 */
static int
vn_read(struct fileproc *fp, struct uio *uio, int flags, vfs_context_t ctx)
{
	struct vnode *vp;
	int error;
	int ioflag;
	off_t count;
	int offset_locked = 0;

	vp = (struct vnode *)fp->f_fglob->fg_data;
	if ((error = vnode_getwithref(vp))) {
		return error;
	}

#if CONFIG_MACF
	error = mac_vnode_check_read(ctx, vfs_context_ucred(ctx), vp);
	if (error) {
		(void)vnode_put(vp);
		return error;
	}
#endif

	/* This signals to VNOP handlers that this read came from a file table read */
	ioflag = IO_SYSCALL_DISPATCH;

	if (fp->f_fglob->fg_flag & FNONBLOCK) {
		ioflag |= IO_NDELAY;
	}
	if ((fp->f_fglob->fg_flag & FNOCACHE) || vnode_isnocache(vp)) {
		ioflag |= IO_NOCACHE;
	}
	if (fp->f_fglob->fg_flag & FENCRYPTED) {
		ioflag |= IO_ENCRYPTED;
	}
	if (fp->f_fglob->fg_flag & FUNENCRYPTED) {
		ioflag |= IO_SKIP_ENCRYPTION;
	}
	if (fp->f_fglob->fg_flag & O_EVTONLY) {
		ioflag |= IO_EVTONLY;
	}
	if (fp->f_fglob->fg_flag & FNORDAHEAD) {
		ioflag |= IO_RAOFF;
	}

	if ((flags & FOF_OFFSET) == 0) {
		if ((vnode_vtype(vp) == VREG) && !vnode_isswap(vp)) {
			vn_offset_lock(fp->f_fglob);
			offset_locked = 1;
		}
		uio->uio_offset = fp->f_fglob->fg_offset;
	}
	count = uio_resid(uio);

	if (vnode_isswap(vp) && !(IO_SKIP_ENCRYPTION & ioflag)) {
		/* special case for swap files */
		error = vn_read_swapfile(vp, uio);
	} else {
		error = VNOP_READ(vp, uio, ioflag, ctx);
	}

	if ((flags & FOF_OFFSET) == 0) {
		fp->f_fglob->fg_offset += count - uio_resid(uio);
		if (offset_locked) {
			vn_offset_unlock(fp->f_fglob);
			offset_locked = 0;
		}
	}

	(void)vnode_put(vp);
	return error;
}


/*
 * File table vnode write routine.
 */
static int
vn_write(struct fileproc *fp, struct uio *uio, int flags, vfs_context_t ctx)
{
	struct vnode *vp;
	int error, ioflag;
	off_t count;
	int clippedsize = 0;
	int partialwrite = 0;
	int residcount, oldcount;
	int offset_locked = 0;
	proc_t p = vfs_context_proc(ctx);

	count = 0;
	vp = (struct vnode *)fp->f_fglob->fg_data;
	if ((error = vnode_getwithref(vp))) {
		return error;
	}

#if DEVELOPMENT || DEBUG
	/*
	 * XXX VSWAP: Check for entitlements or special flag here
	 * so we can restrict access appropriately.
	 */
#else /* DEVELOPMENT || DEBUG */

	if (vnode_isswap(vp)) {
		(void)vnode_put(vp);
		error = EPERM;
		return error;
	}
#endif /* DEVELOPMENT || DEBUG */


#if CONFIG_MACF
	error = mac_vnode_check_write(ctx, vfs_context_ucred(ctx), vp);
	if (error) {
		(void)vnode_put(vp);
		return error;
	}
#endif

	/*
	 * IO_SYSCALL_DISPATCH signals to VNOP handlers that this write came from
	 * a file table write
	 */
	ioflag = (IO_UNIT | IO_SYSCALL_DISPATCH);

	if (vp->v_type == VREG && (fp->f_fglob->fg_flag & O_APPEND)) {
		ioflag |= IO_APPEND;
	}
	if (fp->f_fglob->fg_flag & FNONBLOCK) {
		ioflag |= IO_NDELAY;
	}
	if ((fp->f_fglob->fg_flag & FNOCACHE) || vnode_isnocache(vp)) {
		ioflag |= IO_NOCACHE;
	}
	if (fp->f_fglob->fg_flag & FNODIRECT) {
		ioflag |= IO_NODIRECT;
	}
	if (fp->f_fglob->fg_flag & FSINGLE_WRITER) {
		ioflag |= IO_SINGLE_WRITER;
	}
	if (fp->f_fglob->fg_flag & O_EVTONLY) {
		ioflag |= IO_EVTONLY;
	}

	/*
	 * Treat synchronous mounts and O_FSYNC on the fd as equivalent.
	 *
	 * XXX We treat O_DSYNC as O_FSYNC for now, since we can not delay
	 * XXX the non-essential metadata without some additional VFS work;
	 * XXX the intent at this point is to plumb the interface for it.
	 */
	if ((fp->f_fglob->fg_flag & (O_FSYNC | O_DSYNC)) ||
	    (vp->v_mount && (vp->v_mount->mnt_flag & MNT_SYNCHRONOUS))) {
		ioflag |= IO_SYNC;
	}

	if ((flags & FOF_OFFSET) == 0) {
		if ((vnode_vtype(vp) == VREG) && !vnode_isswap(vp)) {
			vn_offset_lock(fp->f_fglob);
			offset_locked = 1;
		}
		uio->uio_offset = fp->f_fglob->fg_offset;
		count = uio_resid(uio);
	}
	if (((flags & FOF_OFFSET) == 0) &&
	    vfs_context_proc(ctx) && (vp->v_type == VREG) &&
	    (((rlim_t)(uio->uio_offset + uio_resid(uio)) > p->p_rlimit[RLIMIT_FSIZE].rlim_cur) ||
	    ((rlim_t)uio_resid(uio) > (p->p_rlimit[RLIMIT_FSIZE].rlim_cur - uio->uio_offset)))) {
		/*
		 * If the requested residual would cause us to go past the
		 * administrative limit, then we need to adjust the residual
		 * down to cause fewer bytes than requested to be written.  If
		 * we can't do that (e.g. the residual is already 1 byte),
		 * then we fail the write with EFBIG.
		 */
		residcount = uio_resid(uio);
		if ((rlim_t)(uio->uio_offset + uio_resid(uio)) > p->p_rlimit[RLIMIT_FSIZE].rlim_cur) {
			clippedsize =  (uio->uio_offset + uio_resid(uio)) - p->p_rlimit[RLIMIT_FSIZE].rlim_cur;
		} else if ((rlim_t)uio_resid(uio) > (p->p_rlimit[RLIMIT_FSIZE].rlim_cur - uio->uio_offset)) {
			clippedsize = (p->p_rlimit[RLIMIT_FSIZE].rlim_cur - uio->uio_offset);
		}
		if (clippedsize >= residcount) {
			psignal(p, SIGXFSZ);
			error = EFBIG;
			goto error_out;
		}
		partialwrite = 1;
		uio_setresid(uio, residcount - clippedsize);
	}
	if ((flags & FOF_OFFSET) != 0) {
		/* for pwrite, append should  be ignored */
		ioflag &= ~IO_APPEND;
		if (p && (vp->v_type == VREG) &&
		    ((rlim_t)uio->uio_offset >= p->p_rlimit[RLIMIT_FSIZE].rlim_cur)) {
			psignal(p, SIGXFSZ);
			error = EFBIG;
			goto error_out;
		}
		if (p && (vp->v_type == VREG) &&
		    ((rlim_t)(uio->uio_offset + uio_resid(uio)) > p->p_rlimit[RLIMIT_FSIZE].rlim_cur)) {
			//Debugger("vn_bwrite:overstepping the bounds");
			residcount = uio_resid(uio);
			clippedsize =  (uio->uio_offset + uio_resid(uio)) - p->p_rlimit[RLIMIT_FSIZE].rlim_cur;
			partialwrite = 1;
			uio_setresid(uio, residcount - clippedsize);
		}
	}

	error = VNOP_WRITE(vp, uio, ioflag, ctx);

	if (partialwrite) {
		oldcount = uio_resid(uio);
		uio_setresid(uio, oldcount + clippedsize);
	}

	if ((flags & FOF_OFFSET) == 0) {
		if (ioflag & IO_APPEND) {
			fp->f_fglob->fg_offset = uio->uio_offset;
		} else {
			fp->f_fglob->fg_offset += count - uio_resid(uio);
		}
		if (offset_locked) {
			vn_offset_unlock(fp->f_fglob);
			offset_locked = 0;
		}
	}

	/*
	 * Set the credentials on successful writes
	 */
	if ((error == 0) && (vp->v_tag == VT_NFS) && (UBCINFOEXISTS(vp))) {
		/*
		 * When called from aio subsystem, we only have the proc from
		 * which to get the credential, at this point, so use that
		 * instead.  This means aio functions are incompatible with
		 * per-thread credentials (aio operations are proxied).  We
		 * can't easily correct the aio vs. settid race in this case
		 * anyway, so we disallow it.
		 */
		if ((flags & FOF_PCRED) == 0) {
			ubc_setthreadcred(vp, p, current_thread());
		} else {
			ubc_setcred(vp, p);
		}
	}
	(void)vnode_put(vp);
	return error;

error_out:
	if (offset_locked) {
		vn_offset_unlock(fp->f_fglob);
	}
	(void)vnode_put(vp);
	return error;
}

/*
 * File table vnode stat routine.
 *
 * Returns:	0			Success
 *		EBADF
 *		ENOMEM
 *	vnode_getattr:???
 */
int
vn_stat_noauth(struct vnode *vp, void *sbptr, kauth_filesec_t *xsec, int isstat64,
    vfs_context_t ctx, struct ucred *file_cred)
{
	struct vnode_attr va;
	int error;
	u_short mode;
	kauth_filesec_t fsec;
	struct stat *sb = (struct stat *)0;     /* warning avoidance ; protected by isstat64 */
	struct stat64 * sb64 = (struct stat64 *)0;  /* warning avoidance ; protected by isstat64 */

	if (isstat64 != 0) {
		sb64 = (struct stat64 *)sbptr;
	} else {
		sb = (struct stat *)sbptr;
	}
	memset(&va, 0, sizeof(va));
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_fsid);
	VATTR_WANTED(&va, va_fileid);
	VATTR_WANTED(&va, va_mode);
	VATTR_WANTED(&va, va_type);
	VATTR_WANTED(&va, va_nlink);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_gid);
	VATTR_WANTED(&va, va_rdev);
	VATTR_WANTED(&va, va_data_size);
	VATTR_WANTED(&va, va_access_time);
	VATTR_WANTED(&va, va_modify_time);
	VATTR_WANTED(&va, va_change_time);
	VATTR_WANTED(&va, va_create_time);
	VATTR_WANTED(&va, va_flags);
	VATTR_WANTED(&va, va_gen);
	VATTR_WANTED(&va, va_iosize);
	/* lower layers will synthesise va_total_alloc from va_data_size if required */
	VATTR_WANTED(&va, va_total_alloc);
	if (xsec != NULL) {
		VATTR_WANTED(&va, va_uuuid);
		VATTR_WANTED(&va, va_guuid);
		VATTR_WANTED(&va, va_acl);
	}
	error = vnode_getattr(vp, &va, ctx);
	if (error) {
		goto out;
	}
#if CONFIG_MACF
	/*
	 * Give MAC polices a chance to reject or filter the attributes
	 * returned by the filesystem.  Note that MAC policies are consulted
	 * *after* calling the filesystem because filesystems can return more
	 * attributes than were requested so policies wouldn't be authoritative
	 * is consulted beforehand.  This also gives policies an opportunity
	 * to change the values of attributes retrieved.
	 */
	error = mac_vnode_check_getattr(ctx, file_cred, vp, &va);
	if (error) {
		goto out;
	}
#endif
	/*
	 * Copy from vattr table
	 */
	if (isstat64 != 0) {
		sb64->st_dev = va.va_fsid;
		sb64->st_ino = (ino64_t)va.va_fileid;
	} else {
		sb->st_dev = va.va_fsid;
		sb->st_ino = (ino_t)va.va_fileid;
	}
	mode = va.va_mode;
	switch (vp->v_type) {
	case VREG:
		mode |= S_IFREG;
		break;
	case VDIR:
		mode |= S_IFDIR;
		break;
	case VBLK:
		mode |= S_IFBLK;
		break;
	case VCHR:
		mode |= S_IFCHR;
		break;
	case VLNK:
		mode |= S_IFLNK;
		break;
	case VSOCK:
		mode |= S_IFSOCK;
		break;
	case VFIFO:
		mode |= S_IFIFO;
		break;
	default:
		error = EBADF;
		goto out;
	}
	;
	if (isstat64 != 0) {
		sb64->st_mode = mode;
		sb64->st_nlink = VATTR_IS_SUPPORTED(&va, va_nlink) ? va.va_nlink > UINT16_MAX ? UINT16_MAX : (u_int16_t)va.va_nlink : 1;
		sb64->st_uid = va.va_uid;
		sb64->st_gid = va.va_gid;
		sb64->st_rdev = va.va_rdev;
		sb64->st_size = va.va_data_size;
		sb64->st_atimespec = va.va_access_time;
		sb64->st_mtimespec = va.va_modify_time;
		sb64->st_ctimespec = va.va_change_time;
		if (VATTR_IS_SUPPORTED(&va, va_create_time)) {
			sb64->st_birthtimespec =  va.va_create_time;
		} else {
			sb64->st_birthtimespec.tv_sec = sb64->st_birthtimespec.tv_nsec = 0;
		}
		sb64->st_blksize = va.va_iosize;
		sb64->st_flags = va.va_flags;
		sb64->st_blocks = roundup(va.va_total_alloc, 512) / 512;
	} else {
		sb->st_mode = mode;
		sb->st_nlink = VATTR_IS_SUPPORTED(&va, va_nlink) ? va.va_nlink > UINT16_MAX ? UINT16_MAX : (u_int16_t)va.va_nlink : 1;
		sb->st_uid = va.va_uid;
		sb->st_gid = va.va_gid;
		sb->st_rdev = va.va_rdev;
		sb->st_size = va.va_data_size;
		sb->st_atimespec = va.va_access_time;
		sb->st_mtimespec = va.va_modify_time;
		sb->st_ctimespec = va.va_change_time;
		sb->st_blksize = va.va_iosize;
		sb->st_flags = va.va_flags;
		sb->st_blocks = roundup(va.va_total_alloc, 512) / 512;
	}

	/* if we're interested in extended security data and we got an ACL */
	if (xsec != NULL) {
		if (!VATTR_IS_SUPPORTED(&va, va_acl) &&
		    !VATTR_IS_SUPPORTED(&va, va_uuuid) &&
		    !VATTR_IS_SUPPORTED(&va, va_guuid)) {
			*xsec = KAUTH_FILESEC_NONE;
		} else {
			if (VATTR_IS_SUPPORTED(&va, va_acl) && (va.va_acl != NULL)) {
				fsec = kauth_filesec_alloc(va.va_acl->acl_entrycount);
			} else {
				fsec = kauth_filesec_alloc(0);
			}
			if (fsec == NULL) {
				error = ENOMEM;
				goto out;
			}
			fsec->fsec_magic = KAUTH_FILESEC_MAGIC;
			if (VATTR_IS_SUPPORTED(&va, va_uuuid)) {
				fsec->fsec_owner = va.va_uuuid;
			} else {
				fsec->fsec_owner = kauth_null_guid;
			}
			if (VATTR_IS_SUPPORTED(&va, va_guuid)) {
				fsec->fsec_group = va.va_guuid;
			} else {
				fsec->fsec_group = kauth_null_guid;
			}
			if (VATTR_IS_SUPPORTED(&va, va_acl) && (va.va_acl != NULL)) {
				bcopy(va.va_acl, &(fsec->fsec_acl), KAUTH_ACL_COPYSIZE(va.va_acl));
			} else {
				fsec->fsec_acl.acl_entrycount = KAUTH_FILESEC_NOACL;
			}
			*xsec = fsec;
		}
	}

	/* Do not give the generation number out to unpriviledged users */
	if (va.va_gen && !vfs_context_issuser(ctx)) {
		if (isstat64 != 0) {
			sb64->st_gen = 0;
		} else {
			sb->st_gen = 0;
		}
	} else {
		if (isstat64 != 0) {
			sb64->st_gen = va.va_gen;
		} else {
			sb->st_gen = va.va_gen;
		}
	}

	error = 0;
out:
	if (VATTR_IS_SUPPORTED(&va, va_acl) && va.va_acl != NULL) {
		kauth_acl_free(va.va_acl);
	}
	return error;
}

int
vn_stat(struct vnode *vp, void *sb, kauth_filesec_t *xsec, int isstat64, vfs_context_t ctx)
{
	int error;

#if CONFIG_MACF
	error = mac_vnode_check_stat(ctx, NOCRED, vp);
	if (error) {
		return error;
	}
#endif

	/* authorize */
	if ((error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_ATTRIBUTES | KAUTH_VNODE_READ_SECURITY, ctx)) != 0) {
		return error;
	}

	/* actual stat */
	return vn_stat_noauth(vp, sb, xsec, isstat64, ctx, NOCRED);
}


/*
 * File table vnode ioctl routine.
 */
static int
vn_ioctl(struct fileproc *fp, u_long com, caddr_t data, vfs_context_t ctx)
{
	struct vnode *vp = ((struct vnode *)fp->f_fglob->fg_data);
	off_t file_size;
	int error;
	struct vnode *ttyvp;
	struct session * sessp;

	if ((error = vnode_getwithref(vp))) {
		return error;
	}

#if CONFIG_MACF
	error = mac_vnode_check_ioctl(ctx, vp, com);
	if (error) {
		goto out;
	}
#endif

	switch (vp->v_type) {
	case VREG:
	case VDIR:
		if (com == FIONREAD) {
			if ((error = vnode_size(vp, &file_size, ctx)) != 0) {
				goto out;
			}
			*(int *)data = file_size - fp->f_fglob->fg_offset;
			goto out;
		}
		if (com == FIONBIO || com == FIOASYNC) {        /* XXX */
			goto out;
		}
	/* fall into ... */

	default:
		error = ENOTTY;
		goto out;

	case VFIFO:
	case VCHR:
	case VBLK:

		/* Should not be able to set block size from user space */
		if (com == DKIOCSETBLOCKSIZE) {
			error = EPERM;
			goto out;
		}

		if (com == FIODTYPE) {
			if (vp->v_type == VBLK) {
				if (major(vp->v_rdev) >= nblkdev) {
					error = ENXIO;
					goto out;
				}
				*(int *)data = bdevsw[major(vp->v_rdev)].d_type;
			} else if (vp->v_type == VCHR) {
				if (major(vp->v_rdev) >= nchrdev) {
					error = ENXIO;
					goto out;
				}
				*(int *)data = cdevsw[major(vp->v_rdev)].d_type;
			} else {
				error = ENOTTY;
				goto out;
			}
			goto out;
		}
		error = VNOP_IOCTL(vp, com, data, fp->f_fglob->fg_flag, ctx);

		if (error == 0 && com == TIOCSCTTY) {
			sessp = proc_session(vfs_context_proc(ctx));

			session_lock(sessp);
			ttyvp = sessp->s_ttyvp;
			sessp->s_ttyvp = vp;
			sessp->s_ttyvid = vnode_vid(vp);
			session_unlock(sessp);
			session_rele(sessp);
		}
	}
out:
	(void)vnode_put(vp);
	return error;
}

/*
 * File table vnode select routine.
 */
static int
vn_select(struct fileproc *fp, int which, void *wql, __unused vfs_context_t ctx)
{
	int error;
	struct vnode * vp = (struct vnode *)fp->f_fglob->fg_data;
	struct vfs_context context;

	if ((error = vnode_getwithref(vp)) == 0) {
		context.vc_thread = current_thread();
		context.vc_ucred = fp->f_fglob->fg_cred;

#if CONFIG_MACF
		/*
		 * XXX We should use a per thread credential here; minimally,
		 * XXX the process credential should have a persistent
		 * XXX reference on it before being passed in here.
		 */
		error = mac_vnode_check_select(ctx, vp, which);
		if (error == 0)
#endif
		error = VNOP_SELECT(vp, which, fp->f_fglob->fg_flag, wql, ctx);

		(void)vnode_put(vp);
	}
	return error;
}

/*
 * File table vnode close routine.
 */
static int
vn_closefile(struct fileglob *fg, vfs_context_t ctx)
{
	struct vnode *vp = fg->fg_data;
	int error;

	if ((error = vnode_getwithref(vp)) == 0) {
		if (FILEGLOB_DTYPE(fg) == DTYPE_VNODE &&
		    ((fg->fg_flag & FHASLOCK) != 0 ||
		    (fg->fg_lflags & FG_HAS_OFDLOCK) != 0)) {
			struct flock lf = {
				.l_whence = SEEK_SET,
				.l_start = 0,
				.l_len = 0,
				.l_type = F_UNLCK
			};

			if ((fg->fg_flag & FHASLOCK) != 0) {
				(void) VNOP_ADVLOCK(vp, (caddr_t)fg,
				    F_UNLCK, &lf, F_FLOCK, ctx, NULL);
			}

			if ((fg->fg_lflags & FG_HAS_OFDLOCK) != 0) {
				(void) VNOP_ADVLOCK(vp, (caddr_t)fg,
				    F_UNLCK, &lf, F_OFD_LOCK, ctx, NULL);
			}
		}
		error = vn_close(vp, fg->fg_flag, ctx);
		(void) vnode_put(vp);
	}
	return error;
}

/*
 * Returns:	0			Success
 *	VNOP_PATHCONF:???
 */
int
vn_pathconf(vnode_t vp, int name, int32_t *retval, vfs_context_t ctx)
{
	int     error = 0;
	struct vfs_attr vfa;

	switch (name) {
	case _PC_EXTENDED_SECURITY_NP:
		*retval = vfs_extendedsecurity(vnode_mount(vp)) ? 1 : 0;
		break;
	case _PC_AUTH_OPAQUE_NP:
		*retval = vfs_authopaque(vnode_mount(vp));
		break;
	case _PC_2_SYMLINKS:
		*retval = 1;    /* XXX NOTSUP on MSDOS, etc. */
		break;
	case _PC_ALLOC_SIZE_MIN:
		*retval = 1;    /* XXX lie: 1 byte */
		break;
	case _PC_ASYNC_IO:      /* unistd.h: _POSIX_ASYNCHRONUS_IO */
		*retval = 1;    /* [AIO] option is supported */
		break;
	case _PC_PRIO_IO:       /* unistd.h: _POSIX_PRIORITIZED_IO */
		*retval = 0;    /* [PIO] option is not supported */
		break;
	case _PC_REC_INCR_XFER_SIZE:
		*retval = 4096; /* XXX go from MIN to MAX 4K at a time */
		break;
	case _PC_REC_MIN_XFER_SIZE:
		*retval = 4096; /* XXX recommend 4K minimum reads/writes */
		break;
	case _PC_REC_MAX_XFER_SIZE:
		*retval = 65536; /* XXX recommend 64K maximum reads/writes */
		break;
	case _PC_REC_XFER_ALIGN:
		*retval = 4096; /* XXX recommend page aligned buffers */
		break;
	case _PC_SYMLINK_MAX:
		*retval = 255;  /* Minimum acceptable POSIX value */
		break;
	case _PC_SYNC_IO:       /* unistd.h: _POSIX_SYNCHRONIZED_IO */
		*retval = 0;    /* [SIO] option is not supported */
		break;
	case _PC_XATTR_SIZE_BITS:
		/* The number of bits used to store maximum extended
		 * attribute size in bytes.  For example, if the maximum
		 * attribute size supported by a file system is 128K, the
		 * value returned will be 18.  However a value 18 can mean
		 * that the maximum attribute size can be anywhere from
		 * (256KB - 1) to 128KB.  As a special case, the resource
		 * fork can have much larger size, and some file system
		 * specific extended attributes can have smaller and preset
		 * size; for example, Finder Info is always 32 bytes.
		 */
		memset(&vfa, 0, sizeof(vfa));
		VFSATTR_INIT(&vfa);
		VFSATTR_WANTED(&vfa, f_capabilities);
		if (vfs_getattr(vnode_mount(vp), &vfa, ctx) == 0 &&
		    (VFSATTR_IS_SUPPORTED(&vfa, f_capabilities)) &&
		    (vfa.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] & VOL_CAP_INT_EXTENDED_ATTR) &&
		    (vfa.f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] & VOL_CAP_INT_EXTENDED_ATTR)) {
			/* Supports native extended attributes */
			error = VNOP_PATHCONF(vp, name, retval, ctx);
		} else {
			/* Number of bits used to represent the maximum size of
			 * extended attribute stored in an Apple Double file.
			 */
			*retval = AD_XATTR_SIZE_BITS;
		}
		break;
	default:
		error = VNOP_PATHCONF(vp, name, retval, ctx);
		break;
	}

	return error;
}

static int
vn_kqfilt_add(struct fileproc *fp, struct knote *kn,
    struct kevent_internal_s *kev, vfs_context_t ctx)
{
	struct vnode *vp;
	int error = 0;
	int result = 0;

	vp = (struct vnode *)fp->f_fglob->fg_data;

	/*
	 * Don't attach a knote to a dead vnode.
	 */
	if ((error = vget_internal(vp, 0, VNODE_NODEAD)) == 0) {
		switch (kn->kn_filter) {
		case EVFILT_READ:
		case EVFILT_WRITE:
			if (vnode_isfifo(vp)) {
				/* We'll only watch FIFOs that use our fifofs */
				if (!(vp->v_fifoinfo && vp->v_fifoinfo->fi_readsock)) {
					error = ENOTSUP;
				}
			} else if (!vnode_isreg(vp)) {
				if (vnode_ischr(vp)) {
					result = spec_kqfilter(vp, kn, kev);
					if ((kn->kn_flags & EV_ERROR) == 0) {
						/* claimed by a special device */
						vnode_put(vp);
						return result;
					}
				}
				error = EINVAL;
			}
			break;
		case EVFILT_VNODE:
			break;
		default:
			error = EINVAL;
		}

		if (error == 0) {
#if CONFIG_MACF
			error = mac_vnode_check_kqfilter(ctx, fp->f_fglob->fg_cred, kn, vp);
			if (error) {
				vnode_put(vp);
				goto out;
			}
#endif

			kn->kn_hook = (void*)vp;
			kn->kn_hookid = vnode_vid(vp);
			kn->kn_filtid = EVFILTID_VN;

			vnode_lock(vp);
			KNOTE_ATTACH(&vp->v_knotes, kn);
			result = filt_vnode_common(kn, vp, 0);
			vnode_unlock(vp);

			/*
			 * Ask the filesystem to provide remove notifications,
			 * but ignore failure
			 */
			VNOP_MONITOR(vp, 0, VNODE_MONITOR_BEGIN, (void*) kn, ctx);
		}

		vnode_put(vp);
	}

out:
	if (error) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = error;
	}

	return result;
}

static void
filt_vndetach(struct knote *kn)
{
	vfs_context_t ctx = vfs_context_current();
	struct vnode *vp;
	vp = (struct vnode *)kn->kn_hook;
	if (vnode_getwithvid(vp, kn->kn_hookid)) {
		return;
	}

	vnode_lock(vp);
	KNOTE_DETACH(&vp->v_knotes, kn);
	vnode_unlock(vp);

	/*
	 * Tell a (generally networked) filesystem that we're no longer watching
	 * If the FS wants to track contexts, it should still be using the one from
	 * the VNODE_MONITOR_BEGIN.
	 */
	VNOP_MONITOR(vp, 0, VNODE_MONITOR_END, (void*)kn, ctx);
	vnode_put(vp);
}


/*
 * Used for EVFILT_READ
 *
 * Takes only VFIFO or VREG. vnode is locked.  We handle the "poll" case
 * differently than the regular case for VREG files.  If not in poll(),
 * then we need to know current fileproc offset for VREG.
 */
static int64_t
vnode_readable_data_count(vnode_t vp, off_t current_offset, int ispoll)
{
	if (vnode_isfifo(vp)) {
#if FIFO
		int cnt;
		int err = fifo_charcount(vp, &cnt);
		if (err == 0) {
			return (int64_t)cnt;
		} else
#endif
		{
			return 0;
		}
	} else if (vnode_isreg(vp)) {
		if (ispoll) {
			return 1;
		}

		off_t amount;
		amount = vp->v_un.vu_ubcinfo->ui_size - current_offset;
		if (amount > INT64_MAX) {
			return INT64_MAX;
		} else if (amount < INT64_MIN) {
			return INT64_MIN;
		} else {
			return (int64_t)amount;
		}
	} else {
		panic("Should never have an EVFILT_READ except for reg or fifo.");
		return 0;
	}
}

/*
 * Used for EVFILT_WRITE.
 *
 * For regular vnodes, we can always write (1).  For named pipes,
 * see how much space there is in the buffer.  Nothing else is covered.
 */
static intptr_t
vnode_writable_space_count(vnode_t vp)
{
	if (vnode_isfifo(vp)) {
#if FIFO
		long spc;
		int err = fifo_freespace(vp, &spc);
		if (err == 0) {
			return (intptr_t)spc;
		} else
#endif
		{
			return (intptr_t)0;
		}
	} else if (vnode_isreg(vp)) {
		return (intptr_t)1;
	} else {
		panic("Should never have an EVFILT_READ except for reg or fifo.");
		return 0;
	}
}

/*
 * Determine whether this knote should be active
 *
 * This is kind of subtle.
 *      --First, notice if the vnode has been revoked: in so, override hint
 *      --EVFILT_READ knotes are checked no matter what the hint is
 *      --Other knotes activate based on hint.
 *      --If hint is revoke, set special flags and activate
 */
static int
filt_vnode_common(struct knote *kn, vnode_t vp, long hint)
{
	int activate = 0;

	lck_mtx_assert(&vp->v_lock, LCK_MTX_ASSERT_OWNED);

	/* Special handling for vnodes that are in recycle or already gone */
	if (NOTE_REVOKE == hint) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		activate = 1;

		if ((kn->kn_filter == EVFILT_VNODE) && (kn->kn_sfflags & NOTE_REVOKE)) {
			kn->kn_fflags |= NOTE_REVOKE;
		}
	} else {
		switch (kn->kn_filter) {
		case EVFILT_READ:
			kn->kn_data = vnode_readable_data_count(vp, kn->kn_fp->f_fglob->fg_offset, (kn->kn_flags & EV_POLL));

			if (kn->kn_data != 0) {
				activate = 1;
			}
			break;
		case EVFILT_WRITE:
			kn->kn_data = vnode_writable_space_count(vp);

			if (kn->kn_data != 0) {
				activate = 1;
			}
			break;
		case EVFILT_VNODE:
			/* Check events this note matches against the hint */
			if (kn->kn_sfflags & hint) {
				kn->kn_fflags |= hint;         /* Set which event occurred */
			}
			if (kn->kn_fflags != 0) {
				activate = 1;
			}
			break;
		default:
			panic("Invalid knote filter on a vnode!\n");
		}
	}
	return activate;
}

static int
filt_vnode(struct knote *kn, long hint)
{
	vnode_t vp = (struct vnode *)kn->kn_hook;

	return filt_vnode_common(kn, vp, hint);
}

static int
filt_vntouch(struct knote *kn, struct kevent_internal_s *kev)
{
	vnode_t vp = (struct vnode *)kn->kn_hook;
	int activate;
	int hint = 0;

	vnode_lock(vp);
	if (vnode_getiocount(vp, kn->kn_hookid, VNODE_NODEAD | VNODE_WITHID) != 0) {
		/* is recycled */
		hint = NOTE_REVOKE;
	}

	/* accept new input fflags mask */
	kn->kn_sfflags = kev->fflags;

	activate = filt_vnode_common(kn, vp, hint);

	if (hint == 0) {
		vnode_put_locked(vp);
	}
	vnode_unlock(vp);

	return activate;
}

static int
filt_vnprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev)
{
#pragma unused(data)
	vnode_t vp = (struct vnode *)kn->kn_hook;
	int activate;
	int hint = 0;

	vnode_lock(vp);
	if (vnode_getiocount(vp, kn->kn_hookid, VNODE_NODEAD | VNODE_WITHID) != 0) {
		/* Is recycled */
		hint = NOTE_REVOKE;
	}
	activate = filt_vnode_common(kn, vp, hint);
	if (activate) {
		*kev = kn->kn_kevent;
		if (kn->kn_flags & EV_CLEAR) {
			kn->kn_data = 0;
			kn->kn_fflags = 0;
		}
	}

	/* Definitely need to unlock, may need to put */
	if (hint == 0) {
		vnode_put_locked(vp);
	}
	vnode_unlock(vp);

	return activate;
}
