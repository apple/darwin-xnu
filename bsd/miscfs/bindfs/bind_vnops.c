/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

/*-
 * Portions Copyright (c) 1992, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * John Heidemann of the UCLA Ficus project.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *  @(#)null_vnops.c    8.6 (Berkeley) 5/27/95
 *
 * Ancestors:
 *  @(#)lofs_vnops.c    1.2 (Berkeley) 6/18/92
 *  ...and...
 *  @(#)null_vnodeops.c 1.20 92/07/07 UCLA Ficus project
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/xattr.h>
#include <sys/ubc.h>
#include <sys/types.h>
#include <sys/dirent.h>

#include "bindfs.h"

#define BIND_ROOT_INO 2

vop_t * bindfs_vnodeop_p = NULL;

static int
bindfs_default(__unused struct vnop_generic_args * args)
{
	return ENOTSUP;
}

static int
bindfs_getattr(struct vnop_getattr_args * args)
{
	int error;
	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	struct vnode * lowervp = BINDVPTOLOWERVP(args->a_vp);

	error = vnode_getwithref(lowervp);
	if (error == 0) {
		error = VNOP_GETATTR(lowervp, args->a_vap, args->a_context);
		vnode_put(lowervp);

		if (error == 0) {
			if (VATTR_IS_ACTIVE(args->a_vap, va_fsid)) {
				/* fix up fsid so it doesn't say the underlying fs*/
				VATTR_RETURN(args->a_vap, va_fsid, vfs_statfs(vnode_mount(args->a_vp))->f_fsid.val[0]);
			}
			if (VATTR_IS_ACTIVE(args->a_vap, va_fsid64)) {
				/* fix up fsid so it doesn't say the underlying fs*/
				VATTR_RETURN(args->a_vap, va_fsid64, vfs_statfs(vnode_mount(args->a_vp))->f_fsid);
			}
			struct vnode * parent = vnode_parent(args->a_vp);
			if (vnode_isvroot(args->a_vp)) {
				// We can use the lower answers for most questions about the root vnode but need to fix up a few things
				if (VATTR_IS_ACTIVE(args->a_vap, va_fileid)) {
					VATTR_RETURN(args->a_vap, va_fileid, BIND_ROOT_INO);
				}
				if (VATTR_IS_ACTIVE(args->a_vap, va_linkid)) {
					VATTR_RETURN(args->a_vap, va_linkid, BIND_ROOT_INO);
				}
				if (VATTR_IS_ACTIVE(args->a_vap, va_parentid)) {
					// The parent of the root is itself
					VATTR_RETURN(args->a_vap, va_parentid, BIND_ROOT_INO);
				}
			} else if (parent != NULL && vnode_isvroot(parent)) {
				if (VATTR_IS_ACTIVE(args->a_vap, va_parentid)) {
					// This vnode's parent is the root.
					VATTR_RETURN(args->a_vap, va_parentid, BIND_ROOT_INO);
				}
			}
		}
	}

	return error;
}

static int
bindfs_open(struct vnop_open_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	vp    = args->a_vp;
	lvp   = BINDVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_OPEN(lvp, args->a_mode, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
bindfs_close(struct vnop_close_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	vp  = args->a_vp;
	lvp = BINDVPTOLOWERVP(vp);

	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_CLOSE(lvp, args->a_fflag, args->a_context);
		vnode_put(lvp);
	}
	return error;
}

/*
 * We have to carry on the locking protocol on the bind layer vnodes
 * as we progress through the tree. We also have to enforce read-only
 * if this layer is mounted read-only.
 */
static int
bind_lookup(struct vnop_lookup_args * ap)
{
	struct componentname * cnp = ap->a_cnp;
	struct vnode * dvp         = ap->a_dvp;
	struct vnode *vp, *ldvp, *lvp;
	struct mount * mp;
	struct bind_mount * bind_mp;
	int error;

	BINDFSDEBUG("%s parent: %p component: %.*s\n", __FUNCTION__, ap->a_dvp, cnp->cn_namelen, cnp->cn_nameptr);

	mp = vnode_mount(dvp);
	/* rename and delete are not allowed. this is a read only file system */
	if (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME || cnp->cn_nameiop == CREATE) {
		return EROFS;
	}
	bind_mp = MOUNTTOBINDMOUNT(mp);

	// . and .. handling
	if (cnp->cn_nameptr[0] == '.') {
		if (cnp->cn_namelen == 1) {
			vp = dvp;
		} else if (cnp->cn_namelen == 2 && cnp->cn_nameptr[1] == '.') {
			vp = (vnode_isvroot(dvp)) ? dvp : vnode_parent(dvp);
		} else {
			goto notdot;
		}

		error = vp ? vnode_get(vp) : ENOENT;

		if (error == 0) {
			*ap->a_vpp = vp;
		}

		return error;
	}

notdot:
	ldvp = BINDVPTOLOWERVP(dvp);
	vp = lvp = NULL;

	/*
	 * Hold ldvp.  The reference on it, owned by dvp, is lost in
	 * case of dvp reclamation.
	 */
	error = vnode_getwithref(ldvp);
	if (error) {
		return error;
	}

	error = VNOP_LOOKUP(ldvp, &lvp, cnp, ap->a_context);

	vnode_put(ldvp);

	if ((error == 0 || error == EJUSTRETURN) && lvp != NULL) {
		if (ldvp == lvp) {
			vp    = dvp;
			error = vnode_get(vp);
		} else {
			error = bind_nodeget(mp, lvp, dvp, &vp, cnp, 0);
		}
		if (error == 0) {
			*ap->a_vpp = vp;
		}
	}

	/* if we got lvp, drop the iocount from VNOP_LOOKUP */
	if (lvp != NULL) {
		vnode_put(lvp);
	}

	return error;
}

/*
 * Don't think this needs to do anything
 */
static int
bind_inactive(__unused struct vnop_inactive_args * ap)
{
	BINDFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);

	return 0;
}

static int
bind_reclaim(struct vnop_reclaim_args * ap)
{
	struct vnode * vp;
	struct bind_node * xp;
	struct vnode * lowervp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);

	vp = ap->a_vp;

	xp      = VTOBIND(vp);
	lowervp = xp->bind_lowervp;

	vnode_removefsref(vp);

	bind_hashrem(xp);
	vnode_getwithref(lowervp);
	vnode_rele(lowervp);
	vnode_put(lowervp);

	cache_purge(vp);
	vnode_clearfsnode(vp);

	FREE(xp, M_TEMP);

	return 0;
}

/* Get dirent length padded to 4 byte alignment */
#define DIRENT_LEN(namelen) \
	((sizeof(struct dirent) + (namelen + 1) - (__DARWIN_MAXNAMLEN + 1) + 3) & ~3)

/* Get the end of this dirent */
#define DIRENT_END(dep) \
	(((char *)(dep)) + (dep)->d_reclen - 1)

static int
bindfs_readdir(struct vnop_readdir_args * ap)
{
	struct vnode *vp, *lvp, *dvp;
	int error;
	uio_t uio = ap->a_uio;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);
	/* assumption is that any vp that comes through here had to go through lookup
	 */

	if (ap->a_flags & (VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF)) {
		return EINVAL;
	}

	vp    = ap->a_vp;
	dvp = vnode_parent(vp);
	lvp   = BINDVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error != 0) {
		goto lb_end;
	}

	if (vnode_isvroot(vp) || (dvp != NULL && vnode_isvroot(dvp))) {
		size_t bufsize;
		void * bufptr;
		uio_t auio;
		struct dirent *dep;
		size_t bytesread;
		bufsize = 3 * MIN((user_size_t)uio_resid(uio), 87371u) / 8;
		MALLOC(bufptr, void *, bufsize, M_TEMP, M_WAITOK);
		if (bufptr == NULL) {
			return ENOMEM;
		}
		auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
		uio_addiov(auio, (uintptr_t)bufptr, bufsize);
		uio_setoffset(auio, uio_offset(uio));
		error = VNOP_READDIR(lvp, auio, ap->a_flags, ap->a_eofflag, ap->a_numdirent, ap->a_context);
		vnode_put(lvp);
		if (error != 0) {
			goto lb_end;
		}

		dep = (struct dirent *)bufptr;
		bytesread = bufsize - uio_resid(auio);
		while (error == 0 && (char *)dep < ((char *)bufptr + bytesread)) {
			if (DIRENT_END(dep) > ((char *)bufptr + bytesread) ||
			    DIRENT_LEN(dep->d_namlen) > dep->d_reclen) {
				printf("%s: %s: Bad dirent received from directory %s\n", __func__,
				    vfs_statfs(vnode_mount(vp))->f_mntonname,
				    vp->v_name ? vp->v_name : "<unknown>");
				error = EIO;
				break;
			}
			if (dep->d_name[0] == '.') {
				/* re-write the inode number for the mount root */
				/* if vp is the mount root then . = 2 and .. = 2 */
				/* if the parent of vp is the mount root then .. = 2 */
				if ((vnode_isvroot(vp) && dep->d_namlen == 1) ||
				    (dep->d_namlen == 2 && dep->d_name[1] == '.')) {
					dep->d_ino = BIND_ROOT_INO;
				}
			}
			/* Copy entry64 to user's buffer. */
			error = uiomove((caddr_t)dep, dep->d_reclen, uio);
			/* Move to next entry. */
			dep = (struct dirent *)((char *)dep + dep->d_reclen);
		}
		/* Update the real offset using the offset we got from VNOP_READDIR. */
		if (error == 0) {
			uio_setoffset(uio, uio_offset(auio));
		}
		uio_free(auio);
		FREE(bufptr, M_TEMP);
	} else {
		error = VNOP_READDIR(lvp, ap->a_uio, ap->a_flags, ap->a_eofflag, ap->a_numdirent, ap->a_context);
		vnode_put(lvp);
	}

lb_end:
	return error;
}

static int
bindfs_readlink(struct vnop_readlink_args * ap)
{
	BINDFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);
	int error;
	struct vnode *vp, *lvp;

	vp  = ap->a_vp;
	lvp = BINDVPTOLOWERVP(vp);

	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_READLINK(lvp, ap->a_uio, ap->a_context);
		vnode_put(lvp);

		if (error) {
			printf("bindfs: readlink failed: %d\n", error);
		}
	}

	return error;
}

static int
bindfs_pathconf(__unused struct vnop_pathconf_args * args)
{
	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);
	return EINVAL;
}

static int
bindfs_fsync(__unused struct vnop_fsync_args * args)
{
	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);
	return 0;
}

static int
bindfs_mmap(struct vnop_mmap_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	vp    = args->a_vp;
	lvp   = BINDVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_MMAP(lvp, args->a_fflags, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
bindfs_mnomap(struct vnop_mnomap_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	vp    = args->a_vp;
	lvp   = BINDVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_MNOMAP(lvp, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
bindfs_getxattr(struct vnop_getxattr_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	vp    = args->a_vp;
	lvp   = BINDVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_GETXATTR(lvp, args->a_name, args->a_uio, args->a_size, args->a_options, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
bindfs_listxattr(struct vnop_listxattr_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	vp    = args->a_vp;
	lvp   = BINDVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_LISTXATTR(lvp, args->a_uio, args->a_size, args->a_options, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

/* relies on v1 paging */
static int
bindfs_pagein(struct vnop_pagein_args * ap)
{
	int error = EIO;
	struct vnode *vp, *lvp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);

	vp  = ap->a_vp;
	lvp = BINDVPTOLOWERVP(vp);

	if (vnode_vtype(vp) != VREG) {
		return ENOTSUP;
	}

	/*
	 * Ask VM/UBC/VFS to do our bidding
	 */
	if (vnode_getwithvid(lvp, BINDVPTOLOWERVID(vp)) == 0) {
		vm_offset_t ioaddr;
		uio_t auio;
		kern_return_t kret;
		off_t bytes_to_commit;
		off_t lowersize;
		upl_t upl      = ap->a_pl;
		user_ssize_t bytes_remaining = 0;

		auio = uio_create(1, ap->a_f_offset, UIO_SYSSPACE, UIO_READ);
		if (auio == NULL) {
			error = EIO;
			goto exit_no_unmap;
		}

		kret = ubc_upl_map(upl, &ioaddr);
		if (KERN_SUCCESS != kret) {
			panic("bindfs_pagein: ubc_upl_map() failed with (%d)", kret);
		}

		ioaddr += ap->a_pl_offset;

		error = uio_addiov(auio, (user_addr_t)ioaddr, ap->a_size);
		if (error) {
			goto exit;
		}

		lowersize = ubc_getsize(lvp);
		if (lowersize != ubc_getsize(vp)) {
			(void)ubc_setsize(vp, lowersize); /* ignore failures, nothing can be done */
		}

		error = VNOP_READ(lvp, auio, ((ap->a_flags & UPL_IOSYNC) ? IO_SYNC : 0), ap->a_context);

		bytes_remaining = uio_resid(auio);
		if (bytes_remaining > 0 && bytes_remaining <= (user_ssize_t)ap->a_size) {
			/* zero bytes that weren't read in to the upl */
			bzero((void*)((uintptr_t)(ioaddr + ap->a_size - bytes_remaining)), (size_t) bytes_remaining);
		}

exit:
		kret = ubc_upl_unmap(upl);
		if (KERN_SUCCESS != kret) {
			panic("bindfs_pagein: ubc_upl_unmap() failed with (%d)", kret);
		}

		if (auio != NULL) {
			uio_free(auio);
		}

exit_no_unmap:
		if ((ap->a_flags & UPL_NOCOMMIT) == 0) {
			if (!error && (bytes_remaining >= 0) && (bytes_remaining <= (user_ssize_t)ap->a_size)) {
				/* only commit what was read in (page aligned)*/
				bytes_to_commit = ap->a_size - bytes_remaining;
				if (bytes_to_commit) {
					/* need to make sure bytes_to_commit and byte_remaining are page aligned before calling ubc_upl_commit_range*/
					if (bytes_to_commit & PAGE_MASK) {
						bytes_to_commit = (bytes_to_commit & (~PAGE_MASK)) + (PAGE_MASK + 1);
						assert(bytes_to_commit <= (off_t)ap->a_size);

						bytes_remaining = ap->a_size - bytes_to_commit;
					}
					ubc_upl_commit_range(upl, ap->a_pl_offset, (upl_size_t)bytes_to_commit, UPL_COMMIT_FREE_ON_EMPTY);
				}

				/* abort anything thats left */
				if (bytes_remaining) {
					ubc_upl_abort_range(upl, ap->a_pl_offset + (upl_offset_t)bytes_to_commit, (upl_size_t)bytes_remaining, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
				}
			} else {
				ubc_upl_abort_range(upl, ap->a_pl_offset, (upl_size_t)ap->a_size, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
			}
		}
		vnode_put(lvp);
	} else if ((ap->a_flags & UPL_NOCOMMIT) == 0) {
		ubc_upl_abort_range(ap->a_pl, ap->a_pl_offset, (upl_size_t)ap->a_size, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
	}
	return error;
}

static int
bindfs_read(struct vnop_read_args * ap)
{
	int error = EIO;

	struct vnode *vp, *lvp;

	BINDFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);

	vp  = ap->a_vp;
	lvp = BINDVPTOLOWERVP(vp);

	/*
	 * First some house keeping
	 */
	if (vnode_getwithvid(lvp, BINDVPTOLOWERVID(vp)) == 0) {
		if (!vnode_isreg(lvp) && !vnode_islnk(lvp)) {
			error = EPERM;
			goto end;
		}

		if (uio_resid(ap->a_uio) == 0) {
			error = 0;
			goto end;
		}

		/*
		 * Now ask VM/UBC/VFS to do our bidding
		 */

		error = VNOP_READ(lvp, ap->a_uio, ap->a_ioflag, ap->a_context);
		if (error) {
			printf("bindfs: VNOP_READ failed: %d\n", error);
		}
end:
		vnode_put(lvp);
	}
	return error;
}

/*
 * Global vfs data structures
 */

static const struct vnodeopv_entry_desc bindfs_vnodeop_entries[] = {
	{.opve_op = &vnop_default_desc, .opve_impl = (vop_t)bindfs_default},      /* default */
	{.opve_op = &vnop_getattr_desc, .opve_impl = (vop_t)bindfs_getattr},      /* getattr */
	{.opve_op = &vnop_open_desc, .opve_impl = (vop_t)bindfs_open},            /* open */
	{.opve_op = &vnop_close_desc, .opve_impl = (vop_t)bindfs_close},          /* close */
	{.opve_op = &vnop_inactive_desc, .opve_impl = (vop_t)bind_inactive},      /* inactive */
	{.opve_op = &vnop_reclaim_desc, .opve_impl = (vop_t)bind_reclaim},        /* reclaim */
	{.opve_op = &vnop_lookup_desc, .opve_impl = (vop_t)bind_lookup},          /* lookup */
	{.opve_op = &vnop_readdir_desc, .opve_impl = (vop_t)bindfs_readdir},      /* readdir */
	{.opve_op = &vnop_readlink_desc, .opve_impl = (vop_t)bindfs_readlink},    /* readlink */
	{.opve_op = &vnop_pathconf_desc, .opve_impl = (vop_t)bindfs_pathconf},    /* pathconf */
	{.opve_op = &vnop_fsync_desc, .opve_impl = (vop_t)bindfs_fsync},          /* fsync */
	{.opve_op = &vnop_mmap_desc, .opve_impl = (vop_t)bindfs_mmap},            /* mmap */
	{.opve_op = &vnop_mnomap_desc, .opve_impl = (vop_t)bindfs_mnomap},        /* mnomap */
	{.opve_op = &vnop_getxattr_desc, .opve_impl = (vop_t)bindfs_getxattr},    /* getxattr */
	{.opve_op = &vnop_pagein_desc, .opve_impl = (vop_t)bindfs_pagein},        /* pagein */
	{.opve_op = &vnop_read_desc, .opve_impl = (vop_t)bindfs_read},            /* read */
	{.opve_op = &vnop_listxattr_desc, .opve_impl = (vop_t)bindfs_listxattr},  /* listxattr */
	{.opve_op = NULL, .opve_impl = NULL},
};

const struct vnodeopv_desc bindfs_vnodeop_opv_desc = {.opv_desc_vector_p = &bindfs_vnodeop_p, .opv_desc_ops = bindfs_vnodeop_entries};

//BINDFS Specific helper function

int
bindfs_getbackingvnode(vnode_t in_vp, vnode_t* out_vpp)
{
	int result = EINVAL;

	if (out_vpp == NULL || in_vp == NULL) {
		goto end;
	}

	struct vfsstatfs * sp   = NULL;
	mount_t mp = vnode_mount(in_vp);

	sp = vfs_statfs(mp);
	//If this isn't a bindfs vnode or it is but it's a special vnode
	if (strcmp(sp->f_fstypename, "bindfs") != 0) {
		*out_vpp = NULLVP;
		result = ENOENT;
		goto end;
	}

	vnode_t lvp = BINDVPTOLOWERVP(in_vp);
	if ((result = vnode_getwithvid(lvp, BINDVPTOLOWERVID(in_vp)))) {
		goto end;
	}

	*out_vpp = lvp;

end:
	return result;
}
