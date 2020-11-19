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
 * Portions Copyright (c) 1992, 1993, 1995
 *  The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
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
 *  @(#)null_vfsops.c   8.2 (Berkeley) 1/21/94
 *
 * @(#)lofs_vfsops.c    1.2 (Berkeley) 6/18/92
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <security/mac_internal.h>

#include <sys/param.h>

#include <IOKit/IOBSD.h>

#include "bindfs.h"

#define BINDFS_ENTITLEMENT "com.apple.private.bindfs-allow"

#define SIZEOF_MEMBER(type, member) (sizeof(((type *)0)->member))
#define MAX_MNT_FROM_LENGTH (SIZEOF_MEMBER(struct vfsstatfs, f_mntfromname))

static int
bindfs_vfs_getlowerattr(mount_t mp, struct vfs_attr * vfap, vfs_context_t ctx)
{
	memset(vfap, 0, sizeof(*vfap));
	VFSATTR_INIT(vfap);
	VFSATTR_WANTED(vfap, f_bsize);
	VFSATTR_WANTED(vfap, f_iosize);
	VFSATTR_WANTED(vfap, f_blocks);
	VFSATTR_WANTED(vfap, f_bfree);
	VFSATTR_WANTED(vfap, f_bavail);
	VFSATTR_WANTED(vfap, f_bused);
	VFSATTR_WANTED(vfap, f_files);
	VFSATTR_WANTED(vfap, f_ffree);
	VFSATTR_WANTED(vfap, f_capabilities);

	return vfs_getattr(mp, vfap, ctx);
}

/*
 * Mount bind layer
 */
static int
bindfs_mount(struct mount * mp, __unused vnode_t devvp, user_addr_t user_data, vfs_context_t ctx)
{
	int error                 = 0;
	struct vnode *lowerrootvp = NULL, *vp = NULL;
	struct vfsstatfs * sp   = NULL;
	struct bind_mount * xmp = NULL;
	char data[MAXPATHLEN];
	size_t count;
	struct vfs_attr vfa;
	/* set defaults (arbitrary since this file system is readonly) */
	uint32_t bsize  = BLKDEV_IOSIZE;
	size_t iosize   = BLKDEV_IOSIZE;
	uint64_t blocks = 4711 * 4711;
	uint64_t bfree  = 0;
	uint64_t bavail = 0;
	uint64_t bused  = 4711;
	uint64_t files  = 4711;
	uint64_t ffree  = 0;

	kauth_cred_t cred = vfs_context_ucred(ctx);

	BINDFSDEBUG("mp = %p %llx\n", (void *)mp, vfs_flags(mp));

	if (vfs_flags(mp) & MNT_ROOTFS) {
		return EOPNOTSUPP;
	}

	/*
	 * Update is a no-op
	 */
	if (vfs_isupdate(mp)) {
		return ENOTSUP;
	}

	/* check entitlement */
	if (!IOTaskHasEntitlement(current_task(), BINDFS_ENTITLEMENT)) {
		return EPERM;
	}

	/*
	 * Get argument
	 */
	error = copyinstr(user_data, data, MAXPATHLEN - 1, &count);
	if (error) {
		BINDFSERROR("error copying data from user %d\n", error);
		goto error;
	}

	/* This could happen if the system is configured for 32 bit inodes instead of
	 * 64 bit */
	if (count > MAX_MNT_FROM_LENGTH) {
		error = EINVAL;
		BINDFSERROR("path to mount too large for this system %zu vs %lu\n", count, MAX_MNT_FROM_LENGTH);
		goto error;
	}

	error = vnode_lookup(data, 0, &lowerrootvp, ctx);
	if (error) {
		BINDFSERROR("lookup of %s failed error: %d\n", data, error);
		goto error;
	}

	/* lowervrootvp has an iocount after vnode_lookup, drop that for a usecount.
	 *  Keep this to signal what we want to keep around the thing we are mirroring.
	 *  Drop it in unmount.*/
	error = vnode_ref(lowerrootvp);
	vnode_put(lowerrootvp);
	if (error) {
		// If vnode_ref failed, then bind it out so it can't be used anymore in cleanup.
		lowerrootvp = NULL;
		goto error;
	}

	BINDFSDEBUG("mount %s\n", data);

	MALLOC(xmp, struct bind_mount *, sizeof(*xmp), M_TEMP, M_WAITOK | M_ZERO);
	if (xmp == NULL) {
		error = ENOMEM;
		goto error;
	}

	/*
	 * Save reference to underlying FS
	 */
	xmp->bindm_lowerrootvp  = lowerrootvp;
	xmp->bindm_lowerrootvid = vnode_vid(lowerrootvp);

	error = bind_nodeget(mp, lowerrootvp, NULL, &vp, NULL, 1);
	if (error) {
		goto error;
	}
	/* After bind_nodeget our root vnode is in the hash table and we have to usecounts on lowerrootvp
	 * One use count will get dropped when we reclaim the root during unmount.
	 * The other will get dropped in unmount */


	/* vp has an iocount on it from vnode_create. drop that for a usecount. This
	 * is our root vnode so we drop the ref in unmount
	 *
	 * Assuming for now that because we created this vnode and we aren't finished mounting we can get a ref*/
	vnode_ref(vp);
	vnode_put(vp);

	xmp->bindm_rootvp = vp;

	/* read the flags the user set, but then ignore some of them, we will only
	 * allow them if they are set on the lower file system */
	uint64_t flags      = vfs_flags(mp) & (~(MNT_IGNORE_OWNERSHIP | MNT_LOCAL));
	uint64_t lowerflags = vfs_flags(vnode_mount(lowerrootvp)) & (MNT_LOCAL | MNT_QUARANTINE | MNT_IGNORE_OWNERSHIP | MNT_NOEXEC);

	if (lowerflags) {
		flags |= lowerflags;
	}

	/* force these flags */
	flags |= (MNT_DONTBROWSE | MNT_MULTILABEL | MNT_NOSUID | MNT_RDONLY);
	vfs_setflags(mp, flags);

	vfs_setfsprivate(mp, xmp);
	vfs_getnewfsid(mp);
	vfs_setlocklocal(mp);

	/* fill in the stat block */
	sp = vfs_statfs(mp);
	strlcpy(sp->f_mntfromname, data, MAX_MNT_FROM_LENGTH);

	sp->f_flags = flags;

	xmp->bindm_flags = BINDM_CASEINSENSITIVE; /* default to case insensitive */

	error = bindfs_vfs_getlowerattr(vnode_mount(lowerrootvp), &vfa, ctx);
	if (error == 0) {
		if (VFSATTR_IS_SUPPORTED(&vfa, f_bsize)) {
			bsize = vfa.f_bsize;
		}
		if (VFSATTR_IS_SUPPORTED(&vfa, f_iosize)) {
			iosize = vfa.f_iosize;
		}
		if (VFSATTR_IS_SUPPORTED(&vfa, f_blocks)) {
			blocks = vfa.f_blocks;
		}
		if (VFSATTR_IS_SUPPORTED(&vfa, f_bfree)) {
			bfree = vfa.f_bfree;
		}
		if (VFSATTR_IS_SUPPORTED(&vfa, f_bavail)) {
			bavail = vfa.f_bavail;
		}
		if (VFSATTR_IS_SUPPORTED(&vfa, f_bused)) {
			bused = vfa.f_bused;
		}
		if (VFSATTR_IS_SUPPORTED(&vfa, f_files)) {
			files = vfa.f_files;
		}
		if (VFSATTR_IS_SUPPORTED(&vfa, f_ffree)) {
			ffree = vfa.f_ffree;
		}
		if (VFSATTR_IS_SUPPORTED(&vfa, f_capabilities)) {
			if ((vfa.f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] & (VOL_CAP_FMT_CASE_SENSITIVE)) &&
			    (vfa.f_capabilities.valid[VOL_CAPABILITIES_FORMAT] & (VOL_CAP_FMT_CASE_SENSITIVE))) {
				xmp->bindm_flags &= ~BINDM_CASEINSENSITIVE;
			}
		}
	} else {
		goto error;
	}

	sp->f_bsize  = bsize;
	sp->f_iosize = iosize;
	sp->f_blocks = blocks;
	sp->f_bfree  = bfree;
	sp->f_bavail = bavail;
	sp->f_bused  = bused;
	sp->f_files  = files;
	sp->f_ffree  = ffree;

	/* Associate the mac label information from the mirrored filesystem with the
	 * mirror */
	MAC_PERFORM(mount_label_associate, cred, vnode_mount(lowerrootvp), vfs_mntlabel(mp));

	BINDFSDEBUG("lower %s, alias at %s\n", sp->f_mntfromname, sp->f_mntonname);
	return 0;

error:
	if (xmp) {
		FREE(xmp, M_TEMP);
	}
	if (lowerrootvp) {
		vnode_getwithref(lowerrootvp);
		vnode_rele(lowerrootvp);
		vnode_put(lowerrootvp);
	}
	if (vp) {
		/* we made the root vnode but the mount is failed, so clean it up */
		vnode_getwithref(vp);
		vnode_rele(vp);
		/* give vp back */
		vnode_recycle(vp);
		vnode_put(vp);
	}
	return error;
}

/*
 * Free reference to bind layer
 */
static int
bindfs_unmount(struct mount * mp, int mntflags, __unused vfs_context_t ctx)
{
	struct bind_mount * mntdata;
	struct vnode * vp;
	int error, flags;

	BINDFSDEBUG("mp = %p\n", (void *)mp);

	/* check entitlement or superuser*/
	if (!IOTaskHasEntitlement(current_task(), BINDFS_ENTITLEMENT) &&
	    vfs_context_suser(ctx) != 0) {
		return EPERM;
	}

	if (mntflags & MNT_FORCE) {
		flags = FORCECLOSE;
	} else {
		flags = 0;
	}

	mntdata = MOUNTTOBINDMOUNT(mp);
	vp      = mntdata->bindm_rootvp;

	// release our reference on the root before flushing.
	// it will get pulled out of the mount structure by reclaim
	vnode_getalways(vp);

	error = vflush(mp, vp, flags);
	if (error) {
		vnode_put(vp);
		return error;
	}

	if (vnode_isinuse(vp, 1) && flags == 0) {
		vnode_put(vp);
		return EBUSY;
	}

	vnode_rele(vp); // Drop reference taken by bindfs_mount
	vnode_put(vp); // Drop ref taken above

	//Force close to get rid of the last vnode
	(void)vflush(mp, NULL, FORCECLOSE);

	/* no more vnodes, so tear down the mountpoint */

	vfs_setfsprivate(mp, NULL);

	vnode_getalways(mntdata->bindm_lowerrootvp);
	vnode_rele(mntdata->bindm_lowerrootvp);
	vnode_put(mntdata->bindm_lowerrootvp);

	FREE(mntdata, M_TEMP);

	uint64_t vflags = vfs_flags(mp);
	vfs_setflags(mp, vflags & ~MNT_LOCAL);

	return 0;
}

static int
bindfs_root(struct mount * mp, struct vnode ** vpp, __unused vfs_context_t ctx)
{
	struct vnode * vp;
	int error;

	BINDFSDEBUG("mp = %p, vp = %p\n", (void *)mp, (void *)MOUNTTOBINDMOUNT(mp)->bindm_rootvp);

	/*
	 * Return locked reference to root.
	 */
	vp = MOUNTTOBINDMOUNT(mp)->bindm_rootvp;

	error = vnode_get(vp);
	if (error) {
		return error;
	}

	*vpp = vp;
	return 0;
}

static int
bindfs_vfs_getattr(struct mount * mp, struct vfs_attr * vfap, vfs_context_t ctx)
{
	struct vnode * coveredvp = NULL;
	struct vfs_attr vfa;
	struct bind_mount * bind_mp = MOUNTTOBINDMOUNT(mp);
	vol_capabilities_attr_t capabilities;
	struct vfsstatfs * sp = vfs_statfs(mp);

	struct timespec tzero = {.tv_sec = 0, .tv_nsec = 0};

	BINDFSDEBUG("\n");

	/* Set default capabilities in case the lower file system is gone */
	memset(&capabilities, 0, sizeof(capabilities));
	capabilities.capabilities[VOL_CAPABILITIES_FORMAT] = VOL_CAP_FMT_FAST_STATFS | VOL_CAP_FMT_HIDDEN_FILES;
	capabilities.valid[VOL_CAPABILITIES_FORMAT]        = VOL_CAP_FMT_FAST_STATFS | VOL_CAP_FMT_HIDDEN_FILES;

	if (bindfs_vfs_getlowerattr(vnode_mount(bind_mp->bindm_lowerrootvp), &vfa, ctx) == 0) {
		if (VFSATTR_IS_SUPPORTED(&vfa, f_capabilities)) {
			memcpy(&capabilities, &vfa.f_capabilities, sizeof(capabilities));
			/* don't support vget */
			capabilities.capabilities[VOL_CAPABILITIES_FORMAT] &= ~(VOL_CAP_FMT_PERSISTENTOBJECTIDS | VOL_CAP_FMT_PATH_FROM_ID);

			capabilities.capabilities[VOL_CAPABILITIES_FORMAT] |= VOL_CAP_FMT_HIDDEN_FILES; /* Always support UF_HIDDEN */

			capabilities.valid[VOL_CAPABILITIES_FORMAT] &= ~(VOL_CAP_FMT_PERSISTENTOBJECTIDS | VOL_CAP_FMT_PATH_FROM_ID);

			capabilities.valid[VOL_CAPABILITIES_FORMAT] |= VOL_CAP_FMT_HIDDEN_FILES; /* Always support UF_HIDDEN */

			/* dont' support interfaces that only make sense on a writable file system
			 * or one with specific vnops implemented */
			capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] = 0;

			capabilities.valid[VOL_CAPABILITIES_INTERFACES] &=
			    ~(VOL_CAP_INT_SEARCHFS | VOL_CAP_INT_ATTRLIST | VOL_CAP_INT_READDIRATTR | VOL_CAP_INT_EXCHANGEDATA |
			    VOL_CAP_INT_COPYFILE | VOL_CAP_INT_ALLOCATE | VOL_CAP_INT_VOL_RENAME | VOL_CAP_INT_ADVLOCK | VOL_CAP_INT_FLOCK);
		}
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_create_time)) {
		VFSATTR_RETURN(vfap, f_create_time, tzero);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_modify_time)) {
		VFSATTR_RETURN(vfap, f_modify_time, tzero);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_access_time)) {
		VFSATTR_RETURN(vfap, f_access_time, tzero);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_bsize)) {
		VFSATTR_RETURN(vfap, f_bsize, sp->f_bsize);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_iosize)) {
		VFSATTR_RETURN(vfap, f_iosize, sp->f_iosize);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_owner)) {
		VFSATTR_RETURN(vfap, f_owner, 0);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_blocks)) {
		VFSATTR_RETURN(vfap, f_blocks, sp->f_blocks);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_bfree)) {
		VFSATTR_RETURN(vfap, f_bfree, sp->f_bfree);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_bavail)) {
		VFSATTR_RETURN(vfap, f_bavail, sp->f_bavail);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_bused)) {
		VFSATTR_RETURN(vfap, f_bused, sp->f_bused);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_files)) {
		VFSATTR_RETURN(vfap, f_files, sp->f_files);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_ffree)) {
		VFSATTR_RETURN(vfap, f_ffree, sp->f_ffree);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_fssubtype)) {
		VFSATTR_RETURN(vfap, f_fssubtype, 0);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_capabilities)) {
		memcpy(&vfap->f_capabilities, &capabilities, sizeof(vol_capabilities_attr_t));

		VFSATTR_SET_SUPPORTED(vfap, f_capabilities);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_attributes)) {
		vol_attributes_attr_t * volattr = &vfap->f_attributes;

		volattr->validattr.commonattr = 0;
		volattr->validattr.volattr    = ATTR_VOL_NAME | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;
		volattr->validattr.dirattr    = 0;
		volattr->validattr.fileattr   = 0;
		volattr->validattr.forkattr   = 0;

		volattr->nativeattr.commonattr = 0;
		volattr->nativeattr.volattr    = ATTR_VOL_NAME | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;
		volattr->nativeattr.dirattr    = 0;
		volattr->nativeattr.fileattr   = 0;
		volattr->nativeattr.forkattr   = 0;

		VFSATTR_SET_SUPPORTED(vfap, f_attributes);
	}

	if (VFSATTR_IS_ACTIVE(vfap, f_vol_name)) {
		/* The name of the volume is the same as the directory we mounted on */
		coveredvp = vfs_vnodecovered(mp);
		if (coveredvp) {
			const char * name = vnode_getname_printable(coveredvp);
			strlcpy(vfap->f_vol_name, name, MAXPATHLEN);
			vnode_putname_printable(name);

			VFSATTR_SET_SUPPORTED(vfap, f_vol_name);
			vnode_put(coveredvp);
		}
	}

	return 0;
}

static int
bindfs_sync(__unused struct mount * mp, __unused int waitfor, __unused vfs_context_t ctx)
{
	return 0;
}



static int
bindfs_vfs_start(__unused struct mount * mp, __unused int flags, __unused vfs_context_t ctx)
{
	BINDFSDEBUG("\n");
	return 0;
}

extern const struct vnodeopv_desc bindfs_vnodeop_opv_desc;

const struct vnodeopv_desc * bindfs_vnodeopv_descs[] = {
	&bindfs_vnodeop_opv_desc,
};

struct vfsops bindfs_vfsops = {
	.vfs_mount              = bindfs_mount,
	.vfs_unmount            = bindfs_unmount,
	.vfs_start              = bindfs_vfs_start,
	.vfs_root               = bindfs_root,
	.vfs_getattr            = bindfs_vfs_getattr,
	.vfs_sync               = bindfs_sync,
	.vfs_init               = bindfs_init,
	.vfs_sysctl             = NULL,
	.vfs_setattr            = NULL,
};
