/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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
#include <sys/xattr.h>
#include <sys/ubc.h>
#include <sys/types.h>
#include <sys/dirent.h>

#include "nullfs.h"

#define NULL_ROOT_INO 2
#define NULL_SECOND_INO 3
#define NULL_THIRD_INO 4

vop_t * nullfs_vnodeop_p = NULL;

/* the mountpoint lock should be held going into this function */
static int
nullfs_isspecialvp(struct vnode * vp)
{
	struct null_mount * null_mp;

	null_mp = MOUNTTONULLMOUNT(vnode_mount(vp));

	/* only check for root and second here, third is special in a different way,
	 * related only to lookup and readdir */
	if (vp && (vp == null_mp->nullm_rootvp || vp == null_mp->nullm_secondvp)) {
		return 1;
	}
	return 0;
}

/* helper function to handle locking where possible */
static int
nullfs_checkspecialvp(struct vnode* vp)
{
	int result = 0;
	struct null_mount * null_mp;

	null_mp = MOUNTTONULLMOUNT(vnode_mount(vp));

	lck_mtx_lock(&null_mp->nullm_lock);
	result = (nullfs_isspecialvp(vp));
	lck_mtx_unlock(&null_mp->nullm_lock);

	return result;
}

static int
nullfs_default(__unused struct vnop_generic_args * args)
{
	NULLFSDEBUG("%s (default)\n", ((struct vnodeop_desc_fake *)args->a_desc)->vdesc_name);
	return ENOTSUP;
}

static int
nullfs_special_getattr(struct vnop_getattr_args * args)
{
	mount_t mp                  = vnode_mount(args->a_vp);
	struct null_mount * null_mp = MOUNTTONULLMOUNT(mp);

	ino_t ino = NULL_ROOT_INO;
	struct vnode_attr covered_rootattr;
	vnode_t checkvp = null_mp->nullm_lowerrootvp;

	VATTR_INIT(&covered_rootattr);
	VATTR_WANTED(&covered_rootattr, va_uid);
	VATTR_WANTED(&covered_rootattr, va_gid);
	VATTR_WANTED(&covered_rootattr, va_create_time);
	VATTR_WANTED(&covered_rootattr, va_modify_time);
	VATTR_WANTED(&covered_rootattr, va_access_time);

	/* prefer to get this from the lower root vp, but if not (i.e. forced unmount
	 * of lower fs) try the mount point covered vnode */
	if (vnode_getwithvid(checkvp, null_mp->nullm_lowerrootvid)) {
		checkvp = vfs_vnodecovered(mp);
		if (checkvp == NULL) {
			return EIO;
		}
	}

	int error = vnode_getattr(checkvp, &covered_rootattr, args->a_context);

	vnode_put(checkvp);
	if (error) {
		/* we should have been able to get attributes fore one of the two choices so
		 * fail if we didn't */
		return error;
	}

	/* we got the attributes of the vnode we cover so plow ahead */
	if (args->a_vp == null_mp->nullm_secondvp) {
		ino = NULL_SECOND_INO;
	}

	VATTR_RETURN(args->a_vap, va_type, vnode_vtype(args->a_vp));
	VATTR_RETURN(args->a_vap, va_rdev, 0);
	VATTR_RETURN(args->a_vap, va_nlink, 3);      /* always just ., .., and the child */
	VATTR_RETURN(args->a_vap, va_total_size, 0); // hoping this is ok

	VATTR_RETURN(args->a_vap, va_data_size, 0); // hoping this is ok
	VATTR_RETURN(args->a_vap, va_data_alloc, 0);
	VATTR_RETURN(args->a_vap, va_iosize, vfs_statfs(mp)->f_iosize);
	VATTR_RETURN(args->a_vap, va_fileid, ino);
	VATTR_RETURN(args->a_vap, va_linkid, ino);
	VATTR_RETURN(args->a_vap, va_fsid, vfs_statfs(mp)->f_fsid.val[0]); // return the fsid of the mount point
	VATTR_RETURN(args->a_vap, va_filerev, 0);
	VATTR_RETURN(args->a_vap, va_gen, 0);
	VATTR_RETURN(args->a_vap, va_flags, UF_HIDDEN); /* mark our fake directories as hidden. People
	                                                   shouldn't be enocouraged to poke around in them */

	if (ino == NULL_SECOND_INO) {
		VATTR_RETURN(args->a_vap, va_parentid, NULL_ROOT_INO); /* no parent at the root, so
		                                                          the only other vnode that
		                                                          goes through this path is
		                                                          second and its parent is
		                                                          1.*/
	}

	if (VATTR_IS_ACTIVE(args->a_vap, va_mode)) {
		/* force dr_xr_xr_x */
		VATTR_RETURN(args->a_vap, va_mode, S_IFDIR | S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	}
	if (VATTR_IS_ACTIVE(args->a_vap, va_uid)) {
		VATTR_RETURN(args->a_vap, va_uid, covered_rootattr.va_uid);
	}
	if (VATTR_IS_ACTIVE(args->a_vap, va_gid)) {
		VATTR_RETURN(args->a_vap, va_gid, covered_rootattr.va_gid);
	}

	if (VATTR_IS_ACTIVE(args->a_vap, va_create_time)) {
		VATTR_SET_SUPPORTED(args->a_vap, va_create_time);
		args->a_vap->va_create_time.tv_sec  = covered_rootattr.va_create_time.tv_sec;
		args->a_vap->va_create_time.tv_nsec = covered_rootattr.va_create_time.tv_nsec;
	}
	if (VATTR_IS_ACTIVE(args->a_vap, va_modify_time)) {
		VATTR_SET_SUPPORTED(args->a_vap, va_modify_time);
		args->a_vap->va_modify_time.tv_sec  = covered_rootattr.va_modify_time.tv_sec;
		args->a_vap->va_modify_time.tv_nsec = covered_rootattr.va_modify_time.tv_nsec;
	}
	if (VATTR_IS_ACTIVE(args->a_vap, va_access_time)) {
		VATTR_SET_SUPPORTED(args->a_vap, va_access_time);
		args->a_vap->va_modify_time.tv_sec  = covered_rootattr.va_access_time.tv_sec;
		args->a_vap->va_modify_time.tv_nsec = covered_rootattr.va_access_time.tv_nsec;
	}

	return 0;
}

static int
nullfs_getattr(struct vnop_getattr_args * args)
{
	int error;
	struct null_mount * null_mp = MOUNTTONULLMOUNT(vnode_mount(args->a_vp));
	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	lck_mtx_lock(&null_mp->nullm_lock);
	if (nullfs_isspecialvp(args->a_vp)) {
		error = nullfs_special_getattr(args);
		lck_mtx_unlock(&null_mp->nullm_lock);
		return error;
	}
	lck_mtx_unlock(&null_mp->nullm_lock);

	/* this will return a different inode for third than read dir will */
	struct vnode * lowervp = NULLVPTOLOWERVP(args->a_vp);

	error = vnode_getwithref(lowervp);
	if (error == 0) {
		error = VNOP_GETATTR(lowervp, args->a_vap, args->a_context);
		vnode_put(lowervp);

		if (error == 0) {
			/* fix up fsid so it doesn't say the underlying fs*/
			VATTR_RETURN(args->a_vap, va_fsid, vfs_statfs(vnode_mount(args->a_vp))->f_fsid.val[0]);
		}
	}

	return error;
}

static int
nullfs_open(struct vnop_open_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	if (nullfs_checkspecialvp(args->a_vp)) {
		return 0; /* nothing extra needed */
	}

	vp    = args->a_vp;
	lvp   = NULLVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_OPEN(lvp, args->a_mode, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
nullfs_close(struct vnop_close_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	if (nullfs_checkspecialvp(args->a_vp)) {
		return 0; /* nothing extra needed */
	}

	vp  = args->a_vp;
	lvp = NULLVPTOLOWERVP(vp);

	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_CLOSE(lvp, args->a_fflag, args->a_context);
		vnode_put(lvp);
	}
	return error;
}

/* get lvp's parent, if possible, even if it isn't set.

   lvp is expected to have an iocount before and after this call.

   if a dvpp is populated the returned vnode has an iocount. */
static int
null_get_lowerparent(vnode_t lvp, vnode_t * dvpp, vfs_context_t ctx)
{
	int error = 0;
	struct vnode_attr va;
	mount_t mp  = vnode_mount(lvp);
	vnode_t dvp = vnode_parent(lvp);

	if (dvp) {
		error = vnode_get(dvp);
		goto end;
	}

	error = ENOENT;
	if (!(mp->mnt_kern_flag & MNTK_PATH_FROM_ID)) {
		goto end;
	}

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_parentid);

	error = vnode_getattr(lvp, &va, ctx);

	if (error || !VATTR_IS_SUPPORTED(&va, va_parentid)) {
		goto end;
	}

	error = VFS_VGET(mp, (ino64_t)va.va_parentid, &dvp, ctx);

end:
	if (error == 0) {
		*dvpp = dvp;
	}
	return error;
}

/* the mountpoint lock should be held going into this function */
static int
null_special_lookup(struct vnop_lookup_args * ap)
{
	struct componentname * cnp  = ap->a_cnp;
	struct vnode * dvp          = ap->a_dvp;
	struct vnode * ldvp         = NULL;
	struct vnode * lvp          = NULL;
	struct vnode * vp           = NULL;
	struct mount * mp           = vnode_mount(dvp);
	struct null_mount * null_mp = MOUNTTONULLMOUNT(mp);
	int error                   = ENOENT;

	if (dvp == null_mp->nullm_rootvp) {
		/* handle . and .. */
		if (cnp->cn_nameptr[0] == '.') {
			if (cnp->cn_namelen == 1 || (cnp->cn_namelen == 2 && cnp->cn_nameptr[1] == '.')) {
				/* this is the root so both . and .. give back the root */
				vp    = dvp;
				error = vnode_get(vp);
				goto end;
			}
		}

		/* our virtual wrapper directory should be d but D is acceptable if the
		 * lower file system is case insensitive */
		if (cnp->cn_namelen == 1 &&
		    (cnp->cn_nameptr[0] == 'd' || (null_mp->nullm_flags & NULLM_CASEINSENSITIVE ? cnp->cn_nameptr[0] == 'D' : 0))) {
			error = 0;
			if (null_mp->nullm_secondvp == NULL) {
				error = null_getnewvnode(mp, NULL, dvp, &vp, cnp, 0);
				if (error) {
					goto end;
				}

				null_mp->nullm_secondvp = vp;
			} else {
				vp    = null_mp->nullm_secondvp;
				error = vnode_get(vp);
			}
		}

	} else if (dvp == null_mp->nullm_secondvp) {
		/* handle . and .. */
		if (cnp->cn_nameptr[0] == '.') {
			if (cnp->cn_namelen == 1) {
				vp    = dvp;
				error = vnode_get(vp);
				goto end;
			} else if (cnp->cn_namelen == 2 && cnp->cn_nameptr[1] == '.') {
				/* parent here is the root vp */
				vp    = null_mp->nullm_rootvp;
				error = vnode_get(vp);
				goto end;
			}
		}
		/* nullmp->nullm_lowerrootvp was set at mount time so don't need to lock to
		 * access it */
		/* v_name should be null terminated but cn_nameptr is not necessarily.
		   cn_namelen is the number of characters before the null in either case */
		error = vnode_getwithvid(null_mp->nullm_lowerrootvp, null_mp->nullm_lowerrootvid);
		if (error) {
			goto end;
		}

		/* We don't want to mess with case insensitivity and unicode, so the plan to
		   check here is
		    1. try to get the lower root's parent
		    2. If we get a parent, then perform a lookup on the lower file system
		   using the parent and the passed in cnp
		    3. If that worked and we got a vp, then see if the vp is lowerrootvp. If
		   so we got a match
		    4. Anything else results in ENOENT.
		    */
		error = null_get_lowerparent(null_mp->nullm_lowerrootvp, &ldvp, ap->a_context);

		if (error == 0) {
			error = VNOP_LOOKUP(ldvp, &lvp, cnp, ap->a_context);
			vnode_put(ldvp);

			if (error == 0) {
				if (lvp == null_mp->nullm_lowerrootvp) {
					/* always check the hashmap for a vnode for this, the root of the
					 * mirrored system */
					error = null_nodeget(mp, lvp, dvp, &vp, cnp, 0);

					if (error == 0 && null_mp->nullm_thirdcovervp == NULL) {
						/* if nodeget succeeded then vp has an iocount*/
						null_mp->nullm_thirdcovervp = vp;
					}
				} else {
					error = ENOENT;
				}
				vnode_put(lvp);
			}
		}
		vnode_put(null_mp->nullm_lowerrootvp);
	}

end:
	if (error == 0) {
		*ap->a_vpp = vp;
	}
	return error;
}

/*
 * We have to carry on the locking protocol on the null layer vnodes
 * as we progress through the tree. We also have to enforce read-only
 * if this layer is mounted read-only.
 */
static int
null_lookup(struct vnop_lookup_args * ap)
{
	struct componentname * cnp = ap->a_cnp;
	struct vnode * dvp         = ap->a_dvp;
	struct vnode *vp, *ldvp, *lvp;
	struct mount * mp;
	struct null_mount * null_mp;
	int error;

	NULLFSDEBUG("%s parent: %p component: %.*s\n", __FUNCTION__, ap->a_dvp, cnp->cn_namelen, cnp->cn_nameptr);

	mp = vnode_mount(dvp);
	/* rename and delete are not allowed. this is a read only file system */
	if (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME || cnp->cn_nameiop == CREATE) {
		return (EROFS);
	}
	null_mp = MOUNTTONULLMOUNT(mp);

	lck_mtx_lock(&null_mp->nullm_lock);
	if (nullfs_isspecialvp(dvp)) {
		error = null_special_lookup(ap);
		lck_mtx_unlock(&null_mp->nullm_lock);
		return error;
	}
	lck_mtx_unlock(&null_mp->nullm_lock);

	// . and .. handling
	if (cnp->cn_nameptr[0] == '.') {
		if (cnp->cn_namelen == 1) {
			vp = dvp;
		} else if (cnp->cn_namelen == 2 && cnp->cn_nameptr[1] == '.') {
			/* mount point crossing is handled in null_special_lookup */
			vp = vnode_parent(dvp);
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
	ldvp = NULLVPTOLOWERVP(dvp);
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
			error = null_nodeget(mp, lvp, dvp, &vp, cnp, 0);
		}
		if (error == 0) {
			*ap->a_vpp = vp;
		}
	}

	/* if we got lvp, drop the iocount from VNOP_LOOKUP */
	if (lvp != NULL) {
		vnode_put(lvp);
	}

	return (error);
}

/*
 * Don't think this needs to do anything
 */
static int
null_inactive(__unused struct vnop_inactive_args * ap)
{
	NULLFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);

	return (0);
}

static int
null_reclaim(struct vnop_reclaim_args * ap)
{
	struct vnode * vp;
	struct null_node * xp;
	struct vnode * lowervp;
	struct null_mount * null_mp = MOUNTTONULLMOUNT(vnode_mount(ap->a_vp));

	NULLFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);

	vp = ap->a_vp;

	xp      = VTONULL(vp);
	lowervp = xp->null_lowervp;

	lck_mtx_lock(&null_mp->nullm_lock);

	vnode_removefsref(vp);

	if (lowervp != NULL) {
		/* root and second don't have a lowervp, so nothing to release and nothing
		 * got hashed */
		if (xp->null_flags & NULL_FLAG_HASHED) {
			/* only call this if we actually made it into the hash list. reclaim gets
			   called also to
			   clean up a vnode that got created when it didn't need to under race
			   conditions */
			null_hashrem(xp);
		}
		vnode_getwithref(lowervp);
		vnode_rele(lowervp);
		vnode_put(lowervp);
	}

	if (vp == null_mp->nullm_rootvp) {
		null_mp->nullm_rootvp = NULL;
	} else if (vp == null_mp->nullm_secondvp) {
		null_mp->nullm_secondvp = NULL;
	} else if (vp == null_mp->nullm_thirdcovervp) {
		null_mp->nullm_thirdcovervp = NULL;
	}

	lck_mtx_unlock(&null_mp->nullm_lock);

	cache_purge(vp);
	vnode_clearfsnode(vp);

	FREE(xp, M_TEMP);

	return 0;
}

#define DIRENT_SZ(dp) ((sizeof(struct dirent) - NAME_MAX) + (((dp)->d_namlen + 1 + 3) & ~3))

static int
store_entry_special(ino_t ino, const char * name, struct uio * uio)
{
	struct dirent e;
	size_t namelen = strlen(name);
	int error      = EINVAL;

	if (namelen + 1 <= NAME_MAX) {
		memset(&e, 0, sizeof(e));

		e.d_ino  = ino;
		e.d_type = DT_DIR;

		e.d_namlen = namelen; /* don't include NUL */
		e.d_reclen = DIRENT_SZ(&e);
		if (uio_resid(uio) >= e.d_reclen) {
			strlcpy(e.d_name, name, NAME_MAX);
			error = uiomove((caddr_t)&e, e.d_reclen, uio);
		} else {
			error = EMSGSIZE;
		}
	}
	return error;
}

static int
nullfs_special_readdir(struct vnop_readdir_args * ap)
{
	struct vnode * vp           = ap->a_vp;
	struct uio * uio            = ap->a_uio;
	struct null_mount * null_mp = MOUNTTONULLMOUNT(vnode_mount(vp));
	off_t offset                = uio_offset(uio);
	int error                   = ERANGE;
	int items                   = 0;
	ino_t ino                   = 0;
	const char * name           = NULL;

	if (ap->a_flags & (VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF))
		return (EINVAL);

	if (offset == 0) {
		/* . case */
		if (vp == null_mp->nullm_rootvp) {
			ino = NULL_ROOT_INO;
		} else /* only get here if vp matches nullm_rootvp or nullm_secondvp */
		{
			ino = NULL_SECOND_INO;
		}
		error = store_entry_special(ino, ".", uio);
		if (error) {
			goto out;
		}
		offset++;
		items++;
	}
	if (offset == 1) {
		/* .. case */
		/* only get here if vp matches nullm_rootvp or nullm_secondvp */
		ino = NULL_ROOT_INO;

		error = store_entry_special(ino, "..", uio);
		if (error) {
			goto out;
		}
		offset++;
		items++;
	}
	if (offset == 2) {
		/* the directory case */
		if (vp == null_mp->nullm_rootvp) {
			ino  = NULL_SECOND_INO;
			name = "d";
		} else /* only get here if vp matches nullm_rootvp or nullm_secondvp */
		{
			ino = NULL_THIRD_INO;
			if (vnode_getwithvid(null_mp->nullm_lowerrootvp, null_mp->nullm_lowerrootvid)) {
				/* In this case the lower file system has been ripped out from under us,
				   but we don't want to error out
				   Instead we just want d to look empty. */
				error = 0;
				goto out;
			}
			name = vnode_getname_printable(null_mp->nullm_lowerrootvp);
		}
		error = store_entry_special(ino, name, uio);

		if (ino == NULL_THIRD_INO) {
			vnode_putname_printable(name);
			vnode_put(null_mp->nullm_lowerrootvp);
		}

		if (error) {
			goto out;
		}
		offset++;
		items++;
	}

out:
	if (error == EMSGSIZE) {
		error = 0; /* return success if we ran out of space, but we wanted to make
		              sure that we didn't update offset and items incorrectly */
	}
	uio_setoffset(uio, offset);
	if (ap->a_numdirent) {
		*ap->a_numdirent = items;
	}
	return error;
}

static int
nullfs_readdir(struct vnop_readdir_args * ap)
{
	struct vnode *vp, *lvp;
	int error;
	struct null_mount * null_mp = MOUNTTONULLMOUNT(vnode_mount(ap->a_vp));

	NULLFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);
	/* assumption is that any vp that comes through here had to go through lookup
	 */

	lck_mtx_lock(&null_mp->nullm_lock);
	if (nullfs_isspecialvp(ap->a_vp)) {
		error = nullfs_special_readdir(ap);
		lck_mtx_unlock(&null_mp->nullm_lock);
		return error;
	}
	lck_mtx_unlock(&null_mp->nullm_lock);

	vp    = ap->a_vp;
	lvp   = NULLVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_READDIR(lvp, ap->a_uio, ap->a_flags, ap->a_eofflag, ap->a_numdirent, ap->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
nullfs_readlink(struct vnop_readlink_args * ap)
{
	NULLFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);
	int error;
	struct vnode *vp, *lvp;

	if (nullfs_checkspecialvp(ap->a_vp)) {
		return ENOTSUP; /* the special vnodes aren't links */
	}

	vp  = ap->a_vp;
	lvp = NULLVPTOLOWERVP(vp);

	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_READLINK(lvp, ap->a_uio, ap->a_context);
		vnode_put(lvp);

		if (error) {
			NULLFSDEBUG("readlink failed: %d\n", error);
		}
	}

	return error;
}

static int
nullfs_pathconf(__unused struct vnop_pathconf_args * args)
{
	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);
	return EINVAL;
}

static int
nullfs_fsync(__unused struct vnop_fsync_args * args)
{
	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);
	return 0;
}

static int
nullfs_mmap(struct vnop_mmap_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	if (nullfs_checkspecialvp(args->a_vp)) {
		return 0; /* nothing extra needed */
	}

	vp    = args->a_vp;
	lvp   = NULLVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_MMAP(lvp, args->a_fflags, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
nullfs_mnomap(struct vnop_mnomap_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	if (nullfs_checkspecialvp(args->a_vp)) {
		return 0; /* nothing extra needed */
	}

	vp    = args->a_vp;
	lvp   = NULLVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_MNOMAP(lvp, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
nullfs_getxattr(struct vnop_getxattr_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	if (nullfs_checkspecialvp(args->a_vp)) {
		return 0; /* nothing extra needed */
	}

	vp    = args->a_vp;
	lvp   = NULLVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_GETXATTR(lvp, args->a_name, args->a_uio, args->a_size, args->a_options, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

static int
nullfs_listxattr(struct vnop_listxattr_args * args)
{
	int error;
	struct vnode *vp, *lvp;

	NULLFSDEBUG("%s %p\n", __FUNCTION__, args->a_vp);

	if (nullfs_checkspecialvp(args->a_vp)) {
		return 0; /* nothing extra needed */
	}

	vp    = args->a_vp;
	lvp   = NULLVPTOLOWERVP(vp);
	error = vnode_getwithref(lvp);
	if (error == 0) {
		error = VNOP_LISTXATTR(lvp, args->a_uio, args->a_size, args->a_options, args->a_context);
		vnode_put(lvp);
	}

	return error;
}

/* relies on v1 paging */
static int
nullfs_pagein(struct vnop_pagein_args * ap)
{
	int error = EIO;
	struct vnode *vp, *lvp;

	NULLFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);

	vp  = ap->a_vp;
	lvp = NULLVPTOLOWERVP(vp);

	if (vnode_vtype(vp) != VREG) {
		return ENOTSUP;
	}

	/*
	 * Ask VM/UBC/VFS to do our bidding
	 */
	if (vnode_getwithvid(lvp, NULLVPTOLOWERVID(vp)) == 0) {
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
			panic("nullfs_pagein: ubc_upl_map() failed with (%d)", kret);
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
		if (bytes_remaining > 0 && bytes_remaining <= (user_ssize_t)ap->a_size)
		{
			/* zero bytes that weren't read in to the upl */
			bzero((void*)((uintptr_t)(ioaddr + ap->a_size - bytes_remaining)), (size_t) bytes_remaining);
		}

	exit:
		kret = ubc_upl_unmap(upl);
		if (KERN_SUCCESS != kret) {
			panic("nullfs_pagein: ubc_upl_unmap() failed with (%d)", kret);
		}

		if (auio != NULL) {
			uio_free(auio);
		}

	exit_no_unmap:
		if ((ap->a_flags & UPL_NOCOMMIT) == 0) {
			if (!error && (bytes_remaining >= 0) && (bytes_remaining <= (user_ssize_t)ap->a_size)) {
				/* only commit what was read in (page aligned)*/
				bytes_to_commit = ap->a_size - bytes_remaining;
				if (bytes_to_commit)
				{
					/* need to make sure bytes_to_commit and byte_remaining are page aligned before calling ubc_upl_commit_range*/
					if (bytes_to_commit & PAGE_MASK)
					{
						bytes_to_commit = (bytes_to_commit & (~PAGE_MASK)) + (PAGE_MASK + 1);
						assert(bytes_to_commit <= (off_t)ap->a_size);

						bytes_remaining = ap->a_size - bytes_to_commit;
					}
					ubc_upl_commit_range(upl, ap->a_pl_offset, (upl_size_t)bytes_to_commit, UPL_COMMIT_FREE_ON_EMPTY);
				}
				
				/* abort anything thats left */
				if (bytes_remaining) {
					ubc_upl_abort_range(upl, ap->a_pl_offset + bytes_to_commit, (upl_size_t)bytes_remaining, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
				}
			} else {
				ubc_upl_abort_range(upl, ap->a_pl_offset, (upl_size_t)ap->a_size, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
			}
		}
		vnode_put(lvp);
	} else if((ap->a_flags & UPL_NOCOMMIT) == 0) {
		ubc_upl_abort_range(ap->a_pl, ap->a_pl_offset, (upl_size_t)ap->a_size, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
	}
	return error;
}

static int
nullfs_read(struct vnop_read_args * ap)
{
	int error = EIO;

	struct vnode *vp, *lvp;

	NULLFSDEBUG("%s %p\n", __FUNCTION__, ap->a_vp);

	if (nullfs_checkspecialvp(ap->a_vp)) {
		return ENOTSUP; /* the special vnodes can't be read */
	}

	vp  = ap->a_vp;
	lvp = NULLVPTOLOWERVP(vp);

	/*
	 * First some house keeping
	 */
	if (vnode_getwithvid(lvp, NULLVPTOLOWERVID(vp)) == 0) {
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
			NULLFSDEBUG("VNOP_READ failed: %d\n", error);
		}
	end:
		vnode_put(lvp);
	}
	return error;
}

/*
 * Global vfs data structures
 */

static struct vnodeopv_entry_desc nullfs_vnodeop_entries[] = {
    {&vnop_default_desc, (vop_t)nullfs_default},     {&vnop_getattr_desc, (vop_t)nullfs_getattr},
    {&vnop_open_desc, (vop_t)nullfs_open},           {&vnop_close_desc, (vop_t)nullfs_close},
    {&vnop_inactive_desc, (vop_t)null_inactive},     {&vnop_reclaim_desc, (vop_t)null_reclaim},
    {&vnop_lookup_desc, (vop_t)null_lookup},         {&vnop_readdir_desc, (vop_t)nullfs_readdir},
    {&vnop_readlink_desc, (vop_t)nullfs_readlink},   {&vnop_pathconf_desc, (vop_t)nullfs_pathconf},
    {&vnop_fsync_desc, (vop_t)nullfs_fsync},         {&vnop_mmap_desc, (vop_t)nullfs_mmap},
    {&vnop_mnomap_desc, (vop_t)nullfs_mnomap},       {&vnop_getxattr_desc, (vop_t)nullfs_getxattr},
    {&vnop_pagein_desc, (vop_t)nullfs_pagein},       {&vnop_read_desc, (vop_t)nullfs_read},
    {&vnop_listxattr_desc, (vop_t)nullfs_listxattr}, {NULL, NULL},
};

struct vnodeopv_desc nullfs_vnodeop_opv_desc = {&nullfs_vnodeop_p, nullfs_vnodeop_entries};
