/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
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
 * Copyright (c) 1989, 1993
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
 *	@(#)kpi_vfs.c
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

/*
 * External virtual filesystem routines
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/mount_internal.h>
#include <sys/time.h>
#include <sys/vnode_internal.h>
#include <sys/stat.h>
#include <sys/namei.h>
#include <sys/ucred.h>
#include <sys/buf.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <sys/ubc.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/filedesc.h>
#include <sys/event.h>
#include <sys/fsevents.h>
#include <sys/user.h>
#include <sys/lockf.h>
#include <sys/xattr.h>
#include <sys/kdebug.h>

#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <kern/policy_internal.h>

#include <libkern/OSByteOrder.h>

#include <miscfs/specfs/specdev.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <mach/task.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#if NULLFS
#include <miscfs/nullfs/nullfs.h>
#endif

#include <sys/sdt.h>

#define ESUCCESS 0
#undef mount_t
#undef vnode_t

#define COMPAT_ONLY

#define NATIVE_XATTR(VP)  \
	((VP)->v_mount ? (VP)->v_mount->mnt_kern_flag & MNTK_EXTENDED_ATTRS : 0)

#if CONFIG_APPLEDOUBLE
static void xattrfile_remove(vnode_t dvp, const char *basename,
    vfs_context_t ctx, int force);
static void xattrfile_setattr(vnode_t dvp, const char * basename,
    struct vnode_attr * vap, vfs_context_t ctx);
#endif /* CONFIG_APPLEDOUBLE */

static errno_t post_rename(vnode_t fdvp, vnode_t fvp, vnode_t tdvp, vnode_t tvp);

/*
 * vnode_setneedinactive
 *
 * Description: Indicate that when the last iocount on this vnode goes away,
 *              and the usecount is also zero, we should inform the filesystem
 *              via VNOP_INACTIVE.
 *
 * Parameters:  vnode_t		vnode to mark
 *
 * Returns:     Nothing
 *
 * Notes:       Notably used when we're deleting a file--we need not have a
 *              usecount, so VNOP_INACTIVE may not get called by anyone.  We
 *              want it called when we drop our iocount.
 */
void
vnode_setneedinactive(vnode_t vp)
{
	cache_purge(vp);

	vnode_lock_spin(vp);
	vp->v_lflag |= VL_NEEDINACTIVE;
	vnode_unlock(vp);
}


/* ====================================================================== */
/* ************  EXTERNAL KERNEL APIS  ********************************** */
/* ====================================================================== */

/*
 * implementations of exported VFS operations
 */
int
VFS_MOUNT(mount_t mp, vnode_t devvp, user_addr_t data, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_mount == 0)) {
		return ENOTSUP;
	}

	if (vfs_context_is64bit(ctx)) {
		if (vfs_64bitready(mp)) {
			error = (*mp->mnt_op->vfs_mount)(mp, devvp, data, ctx);
		} else {
			error = ENOTSUP;
		}
	} else {
		error = (*mp->mnt_op->vfs_mount)(mp, devvp, data, ctx);
	}

	return error;
}

int
VFS_START(mount_t mp, int flags, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_start == 0)) {
		return ENOTSUP;
	}

	error = (*mp->mnt_op->vfs_start)(mp, flags, ctx);

	return error;
}

int
VFS_UNMOUNT(mount_t mp, int flags, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_unmount == 0)) {
		return ENOTSUP;
	}

	error = (*mp->mnt_op->vfs_unmount)(mp, flags, ctx);

	return error;
}

/*
 * Returns:	0			Success
 *		ENOTSUP			Not supported
 *		<vfs_root>:ENOENT
 *		<vfs_root>:???
 *
 * Note:	The return codes from the underlying VFS's root routine can't
 *		be fully enumerated here, since third party VFS authors may not
 *		limit their error returns to the ones documented here, even
 *		though this may result in some programs functioning incorrectly.
 *
 *		The return codes documented above are those which may currently
 *		be returned by HFS from hfs_vfs_root, which is a simple wrapper
 *		for a call to hfs_vget on the volume mount point, not including
 *		additional error codes which may be propagated from underlying
 *		routines called by hfs_vget.
 */
int
VFS_ROOT(mount_t mp, struct vnode  ** vpp, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_root == 0)) {
		return ENOTSUP;
	}

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	error = (*mp->mnt_op->vfs_root)(mp, vpp, ctx);

	return error;
}

int
VFS_QUOTACTL(mount_t mp, int cmd, uid_t uid, caddr_t datap, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_quotactl == 0)) {
		return ENOTSUP;
	}

	error = (*mp->mnt_op->vfs_quotactl)(mp, cmd, uid, datap, ctx);

	return error;
}

int
VFS_GETATTR(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_getattr == 0)) {
		return ENOTSUP;
	}

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	error = (*mp->mnt_op->vfs_getattr)(mp, vfa, ctx);

	return error;
}

int
VFS_SETATTR(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_setattr == 0)) {
		return ENOTSUP;
	}

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	error = (*mp->mnt_op->vfs_setattr)(mp, vfa, ctx);

	return error;
}

int
VFS_SYNC(mount_t mp, int flags, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_sync == 0)) {
		return ENOTSUP;
	}

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	error = (*mp->mnt_op->vfs_sync)(mp, flags, ctx);

	return error;
}

int
VFS_VGET(mount_t mp, ino64_t ino, struct vnode **vpp, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_vget == 0)) {
		return ENOTSUP;
	}

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	error = (*mp->mnt_op->vfs_vget)(mp, ino, vpp, ctx);

	return error;
}

int
VFS_FHTOVP(mount_t mp, int fhlen, unsigned char *fhp, vnode_t *vpp, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_fhtovp == 0)) {
		return ENOTSUP;
	}

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	error = (*mp->mnt_op->vfs_fhtovp)(mp, fhlen, fhp, vpp, ctx);

	return error;
}

int
VFS_VPTOFH(struct vnode *vp, int *fhlenp, unsigned char *fhp, vfs_context_t ctx)
{
	int error;

	if ((vp->v_mount == dead_mountp) || (vp->v_mount->mnt_op->vfs_vptofh == 0)) {
		return ENOTSUP;
	}

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	error = (*vp->v_mount->mnt_op->vfs_vptofh)(vp, fhlenp, fhp, ctx);

	return error;
}

int
VFS_IOCTL(struct mount *mp, u_long command, caddr_t data,
    int flags, vfs_context_t context)
{
	if (mp == dead_mountp || !mp->mnt_op->vfs_ioctl) {
		return ENOTSUP;
	}

	return mp->mnt_op->vfs_ioctl(mp, command, data, flags,
	           context ?: vfs_context_current());
}

int
VFS_VGET_SNAPDIR(mount_t mp, vnode_t *vpp, vfs_context_t ctx)
{
	int error;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_vget_snapdir == 0)) {
		return ENOTSUP;
	}

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	error = (*mp->mnt_op->vfs_vget_snapdir)(mp, vpp, ctx);

	return error;
}

/* returns the cached throttle mask for the mount_t */
uint64_t
vfs_throttle_mask(mount_t mp)
{
	return mp->mnt_throttle_mask;
}

/* returns a  copy of vfs type name for the mount_t */
void
vfs_name(mount_t mp, char *buffer)
{
	strncpy(buffer, mp->mnt_vtable->vfc_name, MFSNAMELEN);
}

/* returns  vfs type number for the mount_t */
int
vfs_typenum(mount_t mp)
{
	return mp->mnt_vtable->vfc_typenum;
}

/* Safe to cast to "struct label*"; returns "void*" to limit dependence of mount.h on security headers.  */
void*
vfs_mntlabel(mount_t mp)
{
	return (void*)mp->mnt_mntlabel;
}

/* returns command modifier flags of mount_t ie. MNT_CMDFLAGS */
uint64_t
vfs_flags(mount_t mp)
{
	return (uint64_t)(mp->mnt_flag & (MNT_CMDFLAGS | MNT_VISFLAGMASK));
}

/* set any of the command modifier flags(MNT_CMDFLAGS) in mount_t */
void
vfs_setflags(mount_t mp, uint64_t flags)
{
	uint32_t lflags = (uint32_t)(flags & (MNT_CMDFLAGS | MNT_VISFLAGMASK));

	mount_lock(mp);
	mp->mnt_flag |= lflags;
	mount_unlock(mp);
}

/* clear any of the command modifier flags(MNT_CMDFLAGS) in mount_t */
void
vfs_clearflags(mount_t mp, uint64_t flags)
{
	uint32_t lflags = (uint32_t)(flags & (MNT_CMDFLAGS | MNT_VISFLAGMASK));

	mount_lock(mp);
	mp->mnt_flag &= ~lflags;
	mount_unlock(mp);
}

/* Is the mount_t ronly and upgrade read/write requested? */
int
vfs_iswriteupgrade(mount_t mp) /* ronly &&  MNTK_WANTRDWR */
{
	return (mp->mnt_flag & MNT_RDONLY) && (mp->mnt_kern_flag & MNTK_WANTRDWR);
}


/* Is the mount_t mounted ronly */
int
vfs_isrdonly(mount_t mp)
{
	return mp->mnt_flag & MNT_RDONLY;
}

/* Is the mount_t mounted for filesystem synchronous writes? */
int
vfs_issynchronous(mount_t mp)
{
	return mp->mnt_flag & MNT_SYNCHRONOUS;
}

/* Is the mount_t mounted read/write? */
int
vfs_isrdwr(mount_t mp)
{
	return (mp->mnt_flag & MNT_RDONLY) == 0;
}


/* Is mount_t marked for update (ie MNT_UPDATE) */
int
vfs_isupdate(mount_t mp)
{
	return mp->mnt_flag & MNT_UPDATE;
}


/* Is mount_t marked for reload (ie MNT_RELOAD) */
int
vfs_isreload(mount_t mp)
{
	return (mp->mnt_flag & MNT_UPDATE) && (mp->mnt_flag & MNT_RELOAD);
}

/* Is mount_t marked for forced unmount (ie MNT_FORCE or MNTK_FRCUNMOUNT) */
int
vfs_isforce(mount_t mp)
{
	if (mp->mnt_lflag & MNT_LFORCE) {
		return 1;
	} else {
		return 0;
	}
}

int
vfs_isunmount(mount_t mp)
{
	if ((mp->mnt_lflag & MNT_LUNMOUNT)) {
		return 1;
	} else {
		return 0;
	}
}

int
vfs_64bitready(mount_t mp)
{
	if ((mp->mnt_vtable->vfc_vfsflags & VFC_VFS64BITREADY)) {
		return 1;
	} else {
		return 0;
	}
}


int
vfs_authcache_ttl(mount_t mp)
{
	if ((mp->mnt_kern_flag & (MNTK_AUTH_OPAQUE | MNTK_AUTH_CACHE_TTL))) {
		return mp->mnt_authcache_ttl;
	} else {
		return CACHED_RIGHT_INFINITE_TTL;
	}
}

void
vfs_setauthcache_ttl(mount_t mp, int ttl)
{
	mount_lock(mp);
	mp->mnt_kern_flag |= MNTK_AUTH_CACHE_TTL;
	mp->mnt_authcache_ttl = ttl;
	mount_unlock(mp);
}

void
vfs_clearauthcache_ttl(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag &= ~MNTK_AUTH_CACHE_TTL;
	/*
	 * back to the default TTL value in case
	 * MNTK_AUTH_OPAQUE is set on this mount
	 */
	mp->mnt_authcache_ttl = CACHED_LOOKUP_RIGHT_TTL;
	mount_unlock(mp);
}

int
vfs_authopaque(mount_t mp)
{
	if ((mp->mnt_kern_flag & MNTK_AUTH_OPAQUE)) {
		return 1;
	} else {
		return 0;
	}
}

int
vfs_authopaqueaccess(mount_t mp)
{
	if ((mp->mnt_kern_flag & MNTK_AUTH_OPAQUE_ACCESS)) {
		return 1;
	} else {
		return 0;
	}
}

void
vfs_setauthopaque(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag |= MNTK_AUTH_OPAQUE;
	mount_unlock(mp);
}

void
vfs_setauthopaqueaccess(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag |= MNTK_AUTH_OPAQUE_ACCESS;
	mount_unlock(mp);
}

void
vfs_clearauthopaque(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag &= ~MNTK_AUTH_OPAQUE;
	mount_unlock(mp);
}

void
vfs_clearauthopaqueaccess(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag &= ~MNTK_AUTH_OPAQUE_ACCESS;
	mount_unlock(mp);
}

void
vfs_setextendedsecurity(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag |= MNTK_EXTENDED_SECURITY;
	mount_unlock(mp);
}

void
vfs_clearextendedsecurity(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag &= ~MNTK_EXTENDED_SECURITY;
	mount_unlock(mp);
}

void
vfs_setnoswap(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag |= MNTK_NOSWAP;
	mount_unlock(mp);
}

void
vfs_clearnoswap(mount_t mp)
{
	mount_lock(mp);
	mp->mnt_kern_flag &= ~MNTK_NOSWAP;
	mount_unlock(mp);
}

int
vfs_extendedsecurity(mount_t mp)
{
	return mp->mnt_kern_flag & MNTK_EXTENDED_SECURITY;
}

/* returns the max size of short symlink in this mount_t */
uint32_t
vfs_maxsymlen(mount_t mp)
{
	return mp->mnt_maxsymlinklen;
}

/* set  max size of short symlink on mount_t */
void
vfs_setmaxsymlen(mount_t mp, uint32_t symlen)
{
	mp->mnt_maxsymlinklen = symlen;
}

/* return a pointer to the RO vfs_statfs associated with mount_t */
struct vfsstatfs *
vfs_statfs(mount_t mp)
{
	return &mp->mnt_vfsstat;
}

int
vfs_getattr(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx)
{
	int             error;

	if ((error = VFS_GETATTR(mp, vfa, ctx)) != 0) {
		return error;
	}

	/*
	 * If we have a filesystem create time, use it to default some others.
	 */
	if (VFSATTR_IS_SUPPORTED(vfa, f_create_time)) {
		if (VFSATTR_IS_ACTIVE(vfa, f_modify_time) && !VFSATTR_IS_SUPPORTED(vfa, f_modify_time)) {
			VFSATTR_RETURN(vfa, f_modify_time, vfa->f_create_time);
		}
	}

	return 0;
}

int
vfs_setattr(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx)
{
	int error;

	/*
	 * with a read-only system volume, we need to allow rename of the root volume
	 * even if it's read-only.  Don't return EROFS here if setattr changes only
	 * the volume name
	 */
	if (vfs_isrdonly(mp) &&
	    !((mp->mnt_flag & MNT_ROOTFS) && (vfa->f_active == VFSATTR_f_vol_name))) {
		return EROFS;
	}

	error = VFS_SETATTR(mp, vfa, ctx);

	/*
	 * If we had alternate ways of setting vfs attributes, we'd
	 * fall back here.
	 */

	return error;
}

/* return the private data handle stored in mount_t */
void *
vfs_fsprivate(mount_t mp)
{
	return mp->mnt_data;
}

/* set the private data handle in mount_t */
void
vfs_setfsprivate(mount_t mp, void *mntdata)
{
	mount_lock(mp);
	mp->mnt_data = mntdata;
	mount_unlock(mp);
}

/* query whether the mount point supports native EAs */
int
vfs_nativexattrs(mount_t mp)
{
	return mp->mnt_kern_flag & MNTK_EXTENDED_ATTRS;
}

/*
 * return the block size of the underlying
 * device associated with mount_t
 */
int
vfs_devblocksize(mount_t mp)
{
	return mp->mnt_devblocksize;
}

/*
 * Returns vnode with an iocount that must be released with vnode_put()
 */
vnode_t
vfs_vnodecovered(mount_t mp)
{
	vnode_t vp = mp->mnt_vnodecovered;
	if ((vp == NULL) || (vnode_getwithref(vp) != 0)) {
		return NULL;
	} else {
		return vp;
	}
}

/*
 * Returns device vnode backing a mountpoint with an iocount (if valid vnode exists).
 * The iocount must be released with vnode_put().  Note that this KPI is subtle
 * with respect to the validity of using this device vnode for anything substantial
 * (which is discouraged).  If commands are sent to the device driver without
 * taking proper steps to ensure that the device is still open, chaos may ensue.
 * Similarly, this routine should only be called if there is some guarantee that
 * the mount itself is still valid.
 */
vnode_t
vfs_devvp(mount_t mp)
{
	vnode_t vp = mp->mnt_devvp;

	if ((vp != NULLVP) && (vnode_get(vp) == 0)) {
		return vp;
	}

	return NULLVP;
}

/*
 * return the io attributes associated with mount_t
 */
void
vfs_ioattr(mount_t mp, struct vfsioattr *ioattrp)
{
	ioattrp->io_reserved[0] = NULL;
	ioattrp->io_reserved[1] = NULL;
	if (mp == NULL) {
		ioattrp->io_maxreadcnt  = MAXPHYS;
		ioattrp->io_maxwritecnt = MAXPHYS;
		ioattrp->io_segreadcnt  = 32;
		ioattrp->io_segwritecnt = 32;
		ioattrp->io_maxsegreadsize  = MAXPHYS;
		ioattrp->io_maxsegwritesize = MAXPHYS;
		ioattrp->io_devblocksize = DEV_BSIZE;
		ioattrp->io_flags = 0;
		ioattrp->io_max_swappin_available = 0;
	} else {
		ioattrp->io_maxreadcnt  = mp->mnt_maxreadcnt;
		ioattrp->io_maxwritecnt = mp->mnt_maxwritecnt;
		ioattrp->io_segreadcnt  = mp->mnt_segreadcnt;
		ioattrp->io_segwritecnt = mp->mnt_segwritecnt;
		ioattrp->io_maxsegreadsize  = mp->mnt_maxsegreadsize;
		ioattrp->io_maxsegwritesize = mp->mnt_maxsegwritesize;
		ioattrp->io_devblocksize = mp->mnt_devblocksize;
		ioattrp->io_flags = mp->mnt_ioflags;
		ioattrp->io_max_swappin_available = mp->mnt_max_swappin_available;
	}
}


/*
 * set the IO attributes associated with mount_t
 */
void
vfs_setioattr(mount_t mp, struct vfsioattr * ioattrp)
{
	if (mp == NULL) {
		return;
	}
	mp->mnt_maxreadcnt  = ioattrp->io_maxreadcnt;
	mp->mnt_maxwritecnt = ioattrp->io_maxwritecnt;
	mp->mnt_segreadcnt  = ioattrp->io_segreadcnt;
	mp->mnt_segwritecnt = ioattrp->io_segwritecnt;
	mp->mnt_maxsegreadsize = ioattrp->io_maxsegreadsize;
	mp->mnt_maxsegwritesize = ioattrp->io_maxsegwritesize;
	mp->mnt_devblocksize = ioattrp->io_devblocksize;
	mp->mnt_ioflags = ioattrp->io_flags;
	mp->mnt_max_swappin_available = ioattrp->io_max_swappin_available;
}

/*
 * Add a new filesystem into the kernel specified in passed in
 * vfstable structure. It fills in the vnode
 * dispatch vector that is to be passed to when vnodes are created.
 * It returns a handle which is to be used to when the FS is to be removed
 */
typedef int (*PFI)(void *);
extern int vfs_opv_numops;
errno_t
vfs_fsadd(struct vfs_fsentry *vfe, vfstable_t *handle)
{
	struct vfstable *newvfstbl = NULL;
	int     i, j;
	int(***opv_desc_vector_p)(void *);
	int(**opv_desc_vector)(void *);
	const struct vnodeopv_entry_desc        *opve_descp;
	int desccount;
	int descsize;
	PFI *descptr;

	/*
	 * This routine is responsible for all the initialization that would
	 * ordinarily be done as part of the system startup;
	 */

	if (vfe == (struct vfs_fsentry *)0) {
		return EINVAL;
	}

	desccount = vfe->vfe_vopcnt;
	if ((desccount <= 0) || ((desccount > 8)) || (vfe->vfe_vfsops == (struct vfsops *)NULL)
	    || (vfe->vfe_opvdescs == (struct vnodeopv_desc **)NULL)) {
		return EINVAL;
	}

	/* Non-threadsafe filesystems are not supported */
	if ((vfe->vfe_flags &  (VFS_TBLTHREADSAFE | VFS_TBLFSNODELOCK)) == 0) {
		return EINVAL;
	}

	MALLOC(newvfstbl, void *, sizeof(struct vfstable), M_TEMP,
	    M_WAITOK);
	bzero(newvfstbl, sizeof(struct vfstable));
	newvfstbl->vfc_vfsops = vfe->vfe_vfsops;
	strncpy(&newvfstbl->vfc_name[0], vfe->vfe_fsname, MFSNAMELEN);
	if ((vfe->vfe_flags & VFS_TBLNOTYPENUM)) {
		newvfstbl->vfc_typenum = maxvfstypenum++;
	} else {
		newvfstbl->vfc_typenum = vfe->vfe_fstypenum;
	}

	newvfstbl->vfc_refcount = 0;
	newvfstbl->vfc_flags = 0;
	newvfstbl->vfc_mountroot = NULL;
	newvfstbl->vfc_next = NULL;
	newvfstbl->vfc_vfsflags = 0;
	if (vfe->vfe_flags &  VFS_TBL64BITREADY) {
		newvfstbl->vfc_vfsflags |= VFC_VFS64BITREADY;
	}
	if (vfe->vfe_flags &  VFS_TBLVNOP_PAGEINV2) {
		newvfstbl->vfc_vfsflags |= VFC_VFSVNOP_PAGEINV2;
	}
	if (vfe->vfe_flags &  VFS_TBLVNOP_PAGEOUTV2) {
		newvfstbl->vfc_vfsflags |= VFC_VFSVNOP_PAGEOUTV2;
	}
	if ((vfe->vfe_flags & VFS_TBLLOCALVOL) == VFS_TBLLOCALVOL) {
		newvfstbl->vfc_flags |= MNT_LOCAL;
	}
	if ((vfe->vfe_flags & VFS_TBLLOCALVOL) && (vfe->vfe_flags & VFS_TBLGENERICMNTARGS) == 0) {
		newvfstbl->vfc_vfsflags |= VFC_VFSLOCALARGS;
	} else {
		newvfstbl->vfc_vfsflags |= VFC_VFSGENERICARGS;
	}

	if (vfe->vfe_flags &  VFS_TBLNATIVEXATTR) {
		newvfstbl->vfc_vfsflags |= VFC_VFSNATIVEXATTR;
	}
	if (vfe->vfe_flags &  VFS_TBLUNMOUNT_PREFLIGHT) {
		newvfstbl->vfc_vfsflags |= VFC_VFSPREFLIGHT;
	}
	if (vfe->vfe_flags &  VFS_TBLREADDIR_EXTENDED) {
		newvfstbl->vfc_vfsflags |= VFC_VFSREADDIR_EXTENDED;
	}
	if (vfe->vfe_flags & VFS_TBLNOMACLABEL) {
		newvfstbl->vfc_vfsflags |= VFC_VFSNOMACLABEL;
	}
	if (vfe->vfe_flags & VFS_TBLVNOP_NOUPDATEID_RENAME) {
		newvfstbl->vfc_vfsflags |= VFC_VFSVNOP_NOUPDATEID_RENAME;
	}
	if (vfe->vfe_flags & VFS_TBLVNOP_SECLUDE_RENAME) {
		newvfstbl->vfc_vfsflags |= VFC_VFSVNOP_SECLUDE_RENAME;
	}
	if (vfe->vfe_flags & VFS_TBLCANMOUNTROOT) {
		newvfstbl->vfc_vfsflags |= VFC_VFSCANMOUNTROOT;
	}

	/*
	 * Allocate and init the vectors.
	 * Also handle backwards compatibility.
	 *
	 * We allocate one large block to hold all <desccount>
	 * vnode operation vectors stored contiguously.
	 */
	/* XXX - shouldn't be M_TEMP */

	descsize = desccount * vfs_opv_numops * sizeof(PFI);
	MALLOC(descptr, PFI *, descsize,
	    M_TEMP, M_WAITOK);
	bzero(descptr, descsize);

	newvfstbl->vfc_descptr = descptr;
	newvfstbl->vfc_descsize = descsize;

	newvfstbl->vfc_sysctl = NULL;

	for (i = 0; i < desccount; i++) {
		opv_desc_vector_p = vfe->vfe_opvdescs[i]->opv_desc_vector_p;
		/*
		 * Fill in the caller's pointer to the start of the i'th vector.
		 * They'll need to supply it when calling vnode_create.
		 */
		opv_desc_vector = descptr + i * vfs_opv_numops;
		*opv_desc_vector_p = opv_desc_vector;

		for (j = 0; vfe->vfe_opvdescs[i]->opv_desc_ops[j].opve_op; j++) {
			opve_descp = &(vfe->vfe_opvdescs[i]->opv_desc_ops[j]);

			/* Silently skip known-disabled operations */
			if (opve_descp->opve_op->vdesc_flags & VDESC_DISABLED) {
				printf("vfs_fsadd: Ignoring reference in %p to disabled operation %s.\n",
				    vfe->vfe_opvdescs[i], opve_descp->opve_op->vdesc_name);
				continue;
			}

			/*
			 * Sanity check:  is this operation listed
			 * in the list of operations?  We check this
			 * by seeing if its offset is zero.  Since
			 * the default routine should always be listed
			 * first, it should be the only one with a zero
			 * offset.  Any other operation with a zero
			 * offset is probably not listed in
			 * vfs_op_descs, and so is probably an error.
			 *
			 * A panic here means the layer programmer
			 * has committed the all-too common bug
			 * of adding a new operation to the layer's
			 * list of vnode operations but
			 * not adding the operation to the system-wide
			 * list of supported operations.
			 */
			if (opve_descp->opve_op->vdesc_offset == 0 &&
			    opve_descp->opve_op != VDESC(vnop_default)) {
				printf("vfs_fsadd: operation %s not listed in %s.\n",
				    opve_descp->opve_op->vdesc_name,
				    "vfs_op_descs");
				panic("vfs_fsadd: bad operation");
			}
			/*
			 * Fill in this entry.
			 */
			opv_desc_vector[opve_descp->opve_op->vdesc_offset] =
			    opve_descp->opve_impl;
		}


		/*
		 * Finally, go back and replace unfilled routines
		 * with their default.  (Sigh, an O(n^3) algorithm.  I
		 * could make it better, but that'd be work, and n is small.)
		 */
		opv_desc_vector_p = vfe->vfe_opvdescs[i]->opv_desc_vector_p;

		/*
		 * Force every operations vector to have a default routine.
		 */
		opv_desc_vector = *opv_desc_vector_p;
		if (opv_desc_vector[VOFFSET(vnop_default)] == NULL) {
			panic("vfs_fsadd: operation vector without default routine.");
		}
		for (j = 0; j < vfs_opv_numops; j++) {
			if (opv_desc_vector[j] == NULL) {
				opv_desc_vector[j] =
				    opv_desc_vector[VOFFSET(vnop_default)];
			}
		}
	} /* end of each vnodeopv_desc parsing */



	*handle = vfstable_add(newvfstbl);

	if (newvfstbl->vfc_typenum <= maxvfstypenum) {
		maxvfstypenum = newvfstbl->vfc_typenum + 1;
	}

	if (newvfstbl->vfc_vfsops->vfs_init) {
		struct vfsconf vfsc;
		bzero(&vfsc, sizeof(struct vfsconf));
		vfsc.vfc_reserved1 = 0;
		bcopy((*handle)->vfc_name, vfsc.vfc_name, sizeof(vfsc.vfc_name));
		vfsc.vfc_typenum = (*handle)->vfc_typenum;
		vfsc.vfc_refcount = (*handle)->vfc_refcount;
		vfsc.vfc_flags = (*handle)->vfc_flags;
		vfsc.vfc_reserved2 = 0;
		vfsc.vfc_reserved3 = 0;

		(*newvfstbl->vfc_vfsops->vfs_init)(&vfsc);
	}

	FREE(newvfstbl, M_TEMP);

	return 0;
}

/*
 * Removes the filesystem from kernel.
 * The argument passed in is the handle that was given when
 * file system was added
 */
errno_t
vfs_fsremove(vfstable_t handle)
{
	struct vfstable * vfstbl =  (struct vfstable *)handle;
	void *old_desc = NULL;
	errno_t err;

	/* Preflight check for any mounts */
	mount_list_lock();
	if (vfstbl->vfc_refcount != 0) {
		mount_list_unlock();
		return EBUSY;
	}

	/*
	 * save the old descriptor; the free cannot occur unconditionally,
	 * since vfstable_del() may fail.
	 */
	if (vfstbl->vfc_descptr && vfstbl->vfc_descsize) {
		old_desc = vfstbl->vfc_descptr;
	}
	err = vfstable_del(vfstbl);

	mount_list_unlock();

	/* free the descriptor if the delete was successful */
	if (err == 0 && old_desc) {
		FREE(old_desc, M_TEMP);
	}

	return err;
}

void
vfs_setowner(mount_t mp, uid_t uid, gid_t gid)
{
	mp->mnt_fsowner = uid;
	mp->mnt_fsgroup = gid;
}

/*
 * Callers should be careful how they use this; accessing
 * mnt_last_write_completed_timestamp is not thread-safe.  Writing to
 * it isn't either.  Point is: be prepared to deal with strange values
 * being returned.
 */
uint64_t
vfs_idle_time(mount_t mp)
{
	if (mp->mnt_pending_write_size) {
		return 0;
	}

	struct timeval now;

	microuptime(&now);

	return (now.tv_sec
	       - mp->mnt_last_write_completed_timestamp.tv_sec) * 1000000
	       + now.tv_usec - mp->mnt_last_write_completed_timestamp.tv_usec;
}

int
vfs_context_pid(vfs_context_t ctx)
{
	return proc_pid(vfs_context_proc(ctx));
}

int
vfs_context_suser(vfs_context_t ctx)
{
	return suser(ctx->vc_ucred, NULL);
}

/*
 * Return bit field of signals posted to all threads in the context's process.
 *
 * XXX Signals should be tied to threads, not processes, for most uses of this
 * XXX call.
 */
int
vfs_context_issignal(vfs_context_t ctx, sigset_t mask)
{
	proc_t p = vfs_context_proc(ctx);
	if (p) {
		return proc_pendingsignals(p, mask);
	}
	return 0;
}

int
vfs_context_is64bit(vfs_context_t ctx)
{
	proc_t proc = vfs_context_proc(ctx);

	if (proc) {
		return proc_is64bit(proc);
	}
	return 0;
}


/*
 * vfs_context_proc
 *
 * Description:	Given a vfs_context_t, return the proc_t associated with it.
 *
 * Parameters:	vfs_context_t			The context to use
 *
 * Returns:	proc_t				The process for this context
 *
 * Notes:	This function will return the current_proc() if any of the
 *		following conditions are true:
 *
 *		o	The supplied context pointer is NULL
 *		o	There is no Mach thread associated with the context
 *		o	There is no Mach task associated with the Mach thread
 *		o	There is no proc_t associated with the Mach task
 *		o	The proc_t has no per process open file table
 *		o	The proc_t is post-vfork()
 *
 *		This causes this function to return a value matching as
 *		closely as possible the previous behaviour, while at the
 *		same time avoiding the task lending that results from vfork()
 */
proc_t
vfs_context_proc(vfs_context_t ctx)
{
	proc_t  proc = NULL;

	if (ctx != NULL && ctx->vc_thread != NULL) {
		proc = (proc_t)get_bsdthreadtask_info(ctx->vc_thread);
	}
	if (proc != NULL && (proc->p_fd == NULL || (proc->p_lflag & P_LVFORK))) {
		proc = NULL;
	}

	return proc == NULL ? current_proc() : proc;
}

/*
 * vfs_context_get_special_port
 *
 * Description: Return the requested special port from the task associated
 *              with the given context.
 *
 * Parameters:	vfs_context_t			The context to use
 *              int				Index of special port
 *              ipc_port_t *			Pointer to returned port
 *
 * Returns:	kern_return_t			see task_get_special_port()
 */
kern_return_t
vfs_context_get_special_port(vfs_context_t ctx, int which, ipc_port_t *portp)
{
	task_t                  task = NULL;

	if (ctx != NULL && ctx->vc_thread != NULL) {
		task = get_threadtask(ctx->vc_thread);
	}

	return task_get_special_port(task, which, portp);
}

/*
 * vfs_context_set_special_port
 *
 * Description: Set the requested special port in the task associated
 *              with the given context.
 *
 * Parameters:	vfs_context_t			The context to use
 *              int				Index of special port
 *              ipc_port_t			New special port
 *
 * Returns:	kern_return_t			see task_set_special_port()
 */
kern_return_t
vfs_context_set_special_port(vfs_context_t ctx, int which, ipc_port_t port)
{
	task_t                  task = NULL;

	if (ctx != NULL && ctx->vc_thread != NULL) {
		task = get_threadtask(ctx->vc_thread);
	}

	return task_set_special_port(task, which, port);
}

/*
 * vfs_context_thread
 *
 * Description:	Return the Mach thread associated with a vfs_context_t
 *
 * Parameters:	vfs_context_t			The context to use
 *
 * Returns:	thread_t			The thread for this context, or
 *						NULL, if there is not one.
 *
 * Notes:	NULL thread_t's are legal, but discouraged.  They occur only
 *		as a result of a static vfs_context_t declaration in a function
 *		and will result in this function returning NULL.
 *
 *		This is intentional; this function should NOT return the
 *		current_thread() in this case.
 */
thread_t
vfs_context_thread(vfs_context_t ctx)
{
	return ctx->vc_thread;
}


/*
 * vfs_context_cwd
 *
 * Description:	Returns a reference on the vnode for the current working
 *		directory for the supplied context
 *
 * Parameters:	vfs_context_t			The context to use
 *
 * Returns:	vnode_t				The current working directory
 *						for this context
 *
 * Notes:	The function first attempts to obtain the current directory
 *		from the thread, and if it is not present there, falls back
 *		to obtaining it from the process instead.  If it can't be
 *		obtained from either place, we return NULLVP.
 */
vnode_t
vfs_context_cwd(vfs_context_t ctx)
{
	vnode_t cwd = NULLVP;

	if (ctx != NULL && ctx->vc_thread != NULL) {
		uthread_t uth = get_bsdthread_info(ctx->vc_thread);
		proc_t proc;

		/*
		 * Get the cwd from the thread; if there isn't one, get it
		 * from the process, instead.
		 */
		if ((cwd = uth->uu_cdir) == NULLVP &&
		    (proc = (proc_t)get_bsdthreadtask_info(ctx->vc_thread)) != NULL &&
		    proc->p_fd != NULL) {
			cwd = proc->p_fd->fd_cdir;
		}
	}

	return cwd;
}

/*
 * vfs_context_get_cwd
 *
 * Description:	Returns a vnode for the current working	directory for the
 *              supplied context. The returned vnode has an iocount on it
 *              which must be released with a vnode_put().
 *
 * Parameters:	vfs_context_t			The context to use
 *
 * Returns:	vnode_t				The current working directory
 *						for this context
 *
 * Notes:	The function first attempts to obtain the current directory
 *		from the thread, and if it is not present there, falls back
 *		to obtaining it from the process instead.  If it can't be
 *		obtained from either place, we return NULLVP.
 */
vnode_t
vfs_context_get_cwd(vfs_context_t ctx)
{
	vnode_t cwd = NULLVP;

	if (ctx != NULL && ctx->vc_thread != NULL) {
		uthread_t uth = get_bsdthread_info(ctx->vc_thread);
		proc_t proc;

		/*
		 * Get the cwd from the thread; if there isn't one, get it
		 * from the process, instead.
		 */
		cwd = uth->uu_cdir;

		if (cwd) {
			if ((vnode_get(cwd) != 0)) {
				cwd = NULLVP;
			}
		} else if ((proc = (proc_t)get_bsdthreadtask_info(ctx->vc_thread)) != NULL &&
		    proc->p_fd != NULL) {
			proc_fdlock(proc);
			cwd = proc->p_fd->fd_cdir;
			if (cwd && (vnode_get(cwd) != 0)) {
				cwd = NULLVP;
			}
			proc_fdunlock(proc);
		}
	}

	return cwd;
}

/*
 * vfs_context_create
 *
 * Description: Allocate and initialize a new context.
 *
 * Parameters:  vfs_context_t:                  Context to copy, or NULL for new
 *
 * Returns:     Pointer to new context
 *
 * Notes:       Copy cred and thread from argument, if available; else
 *              initialize with current thread and new cred.  Returns
 *              with a reference held on the credential.
 */
vfs_context_t
vfs_context_create(vfs_context_t ctx)
{
	vfs_context_t newcontext;

	newcontext = (vfs_context_t)kalloc(sizeof(struct vfs_context));

	if (newcontext) {
		kauth_cred_t safecred;
		if (ctx) {
			newcontext->vc_thread = ctx->vc_thread;
			safecred = ctx->vc_ucred;
		} else {
			newcontext->vc_thread = current_thread();
			safecred = kauth_cred_get();
		}
		if (IS_VALID_CRED(safecred)) {
			kauth_cred_ref(safecred);
		}
		newcontext->vc_ucred = safecred;
		return newcontext;
	}
	return NULL;
}


vfs_context_t
vfs_context_current(void)
{
	vfs_context_t ctx = NULL;
	volatile uthread_t ut = (uthread_t)get_bsdthread_info(current_thread());

	if (ut != NULL) {
		if (ut->uu_context.vc_ucred != NULL) {
			ctx = &ut->uu_context;
		}
	}

	return ctx == NULL ? vfs_context_kernel() : ctx;
}


/*
 * XXX Do not ask
 *
 * Dangerous hack - adopt the first kernel thread as the current thread, to
 * get to the vfs_context_t in the uthread associated with a kernel thread.
 * This is used by UDF to make the call into IOCDMediaBSDClient,
 * IOBDMediaBSDClient, and IODVDMediaBSDClient to determine whether the
 * ioctl() is being called from kernel or user space (and all this because
 * we do not pass threads into our ioctl()'s, instead of processes).
 *
 * This is also used by imageboot_setup(), called early from bsd_init() after
 * kernproc has been given a credential.
 *
 * Note: The use of proc_thread() here is a convenience to avoid inclusion
 * of many Mach headers to do the reference directly rather than indirectly;
 * we will need to forego this convenience when we reture proc_thread().
 */
static struct vfs_context kerncontext;
vfs_context_t
vfs_context_kernel(void)
{
	if (kerncontext.vc_ucred == NOCRED) {
		kerncontext.vc_ucred = kernproc->p_ucred;
	}
	if (kerncontext.vc_thread == NULL) {
		kerncontext.vc_thread = proc_thread(kernproc);
	}

	return &kerncontext;
}


int
vfs_context_rele(vfs_context_t ctx)
{
	if (ctx) {
		if (IS_VALID_CRED(ctx->vc_ucred)) {
			kauth_cred_unref(&ctx->vc_ucred);
		}
		kfree(ctx, sizeof(struct vfs_context));
	}
	return 0;
}


kauth_cred_t
vfs_context_ucred(vfs_context_t ctx)
{
	return ctx->vc_ucred;
}

/*
 * Return true if the context is owned by the superuser.
 */
int
vfs_context_issuser(vfs_context_t ctx)
{
	return kauth_cred_issuser(vfs_context_ucred(ctx));
}

int
vfs_context_iskernel(vfs_context_t ctx)
{
	return ctx == &kerncontext;
}

/*
 * Given a context, for all fields of vfs_context_t which
 * are not held with a reference, set those fields to the
 * values for the current execution context.  Currently, this
 * just means the vc_thread.
 *
 * Returns: 0 for success, nonzero for failure
 *
 * The intended use is:
 * 1. vfs_context_create()	gets the caller a context
 * 2. vfs_context_bind()        sets the unrefcounted data
 * 3. vfs_context_rele()        releases the context
 *
 */
int
vfs_context_bind(vfs_context_t ctx)
{
	ctx->vc_thread = current_thread();
	return 0;
}

int
vfs_isswapmount(mount_t mnt)
{
	return mnt && ISSET(mnt->mnt_kern_flag, MNTK_SWAP_MOUNT) ? 1 : 0;
}

/* XXXXXXXXXXXXXX VNODE KAPIS XXXXXXXXXXXXXXXXXXXXXXXXX */


/*
 * Convert between vnode types and inode formats (since POSIX.1
 * defines mode word of stat structure in terms of inode formats).
 */
enum vtype
vnode_iftovt(int mode)
{
	return iftovt_tab[((mode) & S_IFMT) >> 12];
}

int
vnode_vttoif(enum vtype indx)
{
	return vttoif_tab[(int)(indx)];
}

int
vnode_makeimode(int indx, int mode)
{
	return (int)(VTTOIF(indx) | (mode));
}


/*
 * vnode manipulation functions.
 */

/* returns system root vnode iocount; It should be released using vnode_put() */
vnode_t
vfs_rootvnode(void)
{
	int error;

	error = vnode_get(rootvnode);
	if (error) {
		return (vnode_t)0;
	} else {
		return rootvnode;
	}
}


uint32_t
vnode_vid(vnode_t vp)
{
	return (uint32_t)(vp->v_id);
}

mount_t
vnode_mount(vnode_t vp)
{
	return vp->v_mount;
}

#if CONFIG_IOSCHED
vnode_t
vnode_mountdevvp(vnode_t vp)
{
	if (vp->v_mount) {
		return vp->v_mount->mnt_devvp;
	} else {
		return (vnode_t)0;
	}
}
#endif

boolean_t
vnode_isonexternalstorage(vnode_t vp)
{
	if (vp) {
		if (vp->v_mount) {
			if (vp->v_mount->mnt_ioflags & MNT_IOFLAGS_PERIPHERAL_DRIVE) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

mount_t
vnode_mountedhere(vnode_t vp)
{
	mount_t mp;

	if ((vp->v_type == VDIR) && ((mp = vp->v_mountedhere) != NULL) &&
	    (mp->mnt_vnodecovered == vp)) {
		return mp;
	} else {
		return (mount_t)NULL;
	}
}

/* returns vnode type of vnode_t */
enum vtype
vnode_vtype(vnode_t vp)
{
	return vp->v_type;
}

/* returns FS specific node saved in vnode */
void *
vnode_fsnode(vnode_t vp)
{
	return vp->v_data;
}

void
vnode_clearfsnode(vnode_t vp)
{
	vp->v_data = NULL;
}

dev_t
vnode_specrdev(vnode_t vp)
{
	return vp->v_rdev;
}


/* Accessor functions */
/* is vnode_t a root vnode */
int
vnode_isvroot(vnode_t vp)
{
	return (vp->v_flag & VROOT)? 1 : 0;
}

/* is vnode_t a system vnode */
int
vnode_issystem(vnode_t vp)
{
	return (vp->v_flag & VSYSTEM)? 1 : 0;
}

/* is vnode_t a swap file vnode */
int
vnode_isswap(vnode_t vp)
{
	return (vp->v_flag & VSWAP)? 1 : 0;
}

/* is vnode_t a tty */
int
vnode_istty(vnode_t vp)
{
	return (vp->v_flag & VISTTY) ? 1 : 0;
}

/* if vnode_t mount operation in progress */
int
vnode_ismount(vnode_t vp)
{
	return (vp->v_flag & VMOUNT)? 1 : 0;
}

/* is this vnode under recyle now */
int
vnode_isrecycled(vnode_t vp)
{
	int ret;

	vnode_lock_spin(vp);
	ret =  (vp->v_lflag & (VL_TERMINATE | VL_DEAD))? 1 : 0;
	vnode_unlock(vp);
	return ret;
}

/* vnode was created by background task requesting rapid aging
 *  and has not since been referenced by a normal task */
int
vnode_israge(vnode_t vp)
{
	return (vp->v_flag & VRAGE)? 1 : 0;
}

int
vnode_needssnapshots(vnode_t vp)
{
	return (vp->v_flag & VNEEDSSNAPSHOT)? 1 : 0;
}


/* Check the process/thread to see if we should skip atime updates */
int
vfs_ctx_skipatime(vfs_context_t ctx)
{
	struct uthread *ut;
	proc_t proc;
	thread_t thr;

	proc = vfs_context_proc(ctx);
	thr = vfs_context_thread(ctx);

	/* Validate pointers in case we were invoked via a kernel context */
	if (thr && proc) {
		ut = get_bsdthread_info(thr);

		if (proc->p_lflag & P_LRAGE_VNODES) {
			return 1;
		}

		if (ut) {
			if (ut->uu_flag & (UT_RAGE_VNODES | UT_ATIME_UPDATE)) {
				return 1;
			}
		}

		if (proc->p_vfs_iopolicy & P_VFS_IOPOLICY_ATIME_UPDATES) {
			return 1;
		}
	}
	return 0;
}

/* is vnode_t marked to not keep data cached once it's been consumed */
int
vnode_isnocache(vnode_t vp)
{
	return (vp->v_flag & VNOCACHE_DATA)? 1 : 0;
}

/*
 * has sequential readahead been disabled on this vnode
 */
int
vnode_isnoreadahead(vnode_t vp)
{
	return (vp->v_flag & VRAOFF)? 1 : 0;
}

int
vnode_is_openevt(vnode_t vp)
{
	return (vp->v_flag & VOPENEVT)? 1 : 0;
}

/* is vnode_t a standard one? */
int
vnode_isstandard(vnode_t vp)
{
	return (vp->v_flag & VSTANDARD)? 1 : 0;
}

/* don't vflush() if SKIPSYSTEM */
int
vnode_isnoflush(vnode_t vp)
{
	return (vp->v_flag & VNOFLUSH)? 1 : 0;
}

/* is vnode_t a regular file */
int
vnode_isreg(vnode_t vp)
{
	return (vp->v_type == VREG)? 1 : 0;
}

/* is vnode_t a directory? */
int
vnode_isdir(vnode_t vp)
{
	return (vp->v_type == VDIR)? 1 : 0;
}

/* is vnode_t a symbolic link ? */
int
vnode_islnk(vnode_t vp)
{
	return (vp->v_type == VLNK)? 1 : 0;
}

int
vnode_lookup_continue_needed(vnode_t vp, struct componentname *cnp)
{
	struct nameidata *ndp = cnp->cn_ndp;

	if (ndp == NULL) {
		panic("vnode_lookup_continue_needed(): cnp->cn_ndp is NULL\n");
	}

	if (vnode_isdir(vp)) {
		if (vp->v_mountedhere != NULL) {
			goto yes;
		}

#if CONFIG_TRIGGERS
		if (vp->v_resolve) {
			goto yes;
		}
#endif /* CONFIG_TRIGGERS */
	}


	if (vnode_islnk(vp)) {
		/* From lookup():  || *ndp->ni_next == '/') No need for this, we know we're NULL-terminated here */
		if (cnp->cn_flags & FOLLOW) {
			goto yes;
		}
		if (ndp->ni_flag & NAMEI_TRAILINGSLASH) {
			goto yes;
		}
	}

	return 0;

yes:
	ndp->ni_flag |= NAMEI_CONTLOOKUP;
	return EKEEPLOOKING;
}

/* is vnode_t a fifo ? */
int
vnode_isfifo(vnode_t vp)
{
	return (vp->v_type == VFIFO)? 1 : 0;
}

/* is vnode_t a block device? */
int
vnode_isblk(vnode_t vp)
{
	return (vp->v_type == VBLK)? 1 : 0;
}

int
vnode_isspec(vnode_t vp)
{
	return ((vp->v_type == VCHR) || (vp->v_type == VBLK)) ? 1 : 0;
}

/* is vnode_t a char device? */
int
vnode_ischr(vnode_t vp)
{
	return (vp->v_type == VCHR)? 1 : 0;
}

/* is vnode_t a socket? */
int
vnode_issock(vnode_t vp)
{
	return (vp->v_type == VSOCK)? 1 : 0;
}

/* is vnode_t a device with multiple active vnodes referring to it? */
int
vnode_isaliased(vnode_t vp)
{
	enum vtype vt = vp->v_type;
	if (!((vt == VCHR) || (vt == VBLK))) {
		return 0;
	} else {
		return vp->v_specflags & SI_ALIASED;
	}
}

/* is vnode_t a named stream? */
int
vnode_isnamedstream(
#if NAMEDSTREAMS
	vnode_t vp
#else
	__unused vnode_t vp
#endif
	)
{
#if NAMEDSTREAMS
	return (vp->v_flag & VISNAMEDSTREAM) ? 1 : 0;
#else
	return 0;
#endif
}

int
vnode_isshadow(
#if NAMEDSTREAMS
	vnode_t vp
#else
	__unused vnode_t vp
#endif
	)
{
#if NAMEDSTREAMS
	return (vp->v_flag & VISSHADOW) ? 1 : 0;
#else
	return 0;
#endif
}

/* does vnode have associated named stream vnodes ? */
int
vnode_hasnamedstreams(
#if NAMEDSTREAMS
	vnode_t vp
#else
	__unused vnode_t vp
#endif
	)
{
#if NAMEDSTREAMS
	return (vp->v_lflag & VL_HASSTREAMS) ? 1 : 0;
#else
	return 0;
#endif
}
/* TBD:  set vnode_t to not cache data after it is consumed once; used for quota */
void
vnode_setnocache(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag |= VNOCACHE_DATA;
	vnode_unlock(vp);
}

void
vnode_clearnocache(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag &= ~VNOCACHE_DATA;
	vnode_unlock(vp);
}

void
vnode_set_openevt(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag |= VOPENEVT;
	vnode_unlock(vp);
}

void
vnode_clear_openevt(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag &= ~VOPENEVT;
	vnode_unlock(vp);
}


void
vnode_setnoreadahead(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag |= VRAOFF;
	vnode_unlock(vp);
}

void
vnode_clearnoreadahead(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag &= ~VRAOFF;
	vnode_unlock(vp);
}

int
vnode_isfastdevicecandidate(vnode_t vp)
{
	return (vp->v_flag & VFASTDEVCANDIDATE)? 1 : 0;
}

void
vnode_setfastdevicecandidate(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag |= VFASTDEVCANDIDATE;
	vnode_unlock(vp);
}

void
vnode_clearfastdevicecandidate(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag &= ~VFASTDEVCANDIDATE;
	vnode_unlock(vp);
}

int
vnode_isautocandidate(vnode_t vp)
{
	return (vp->v_flag & VAUTOCANDIDATE)? 1 : 0;
}

void
vnode_setautocandidate(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag |= VAUTOCANDIDATE;
	vnode_unlock(vp);
}

void
vnode_clearautocandidate(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag &= ~VAUTOCANDIDATE;
	vnode_unlock(vp);
}




/* mark vnode_t to skip vflush() is SKIPSYSTEM */
void
vnode_setnoflush(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag |= VNOFLUSH;
	vnode_unlock(vp);
}

void
vnode_clearnoflush(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_flag &= ~VNOFLUSH;
	vnode_unlock(vp);
}


/* is vnode_t a blkdevice and has a FS mounted on it */
int
vnode_ismountedon(vnode_t vp)
{
	return (vp->v_specflags & SI_MOUNTEDON)? 1 : 0;
}

void
vnode_setmountedon(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_specflags |= SI_MOUNTEDON;
	vnode_unlock(vp);
}

void
vnode_clearmountedon(vnode_t vp)
{
	vnode_lock_spin(vp);
	vp->v_specflags &= ~SI_MOUNTEDON;
	vnode_unlock(vp);
}


void
vnode_settag(vnode_t vp, int tag)
{
	vp->v_tag = tag;
}

int
vnode_tag(vnode_t vp)
{
	return vp->v_tag;
}

vnode_t
vnode_parent(vnode_t vp)
{
	return vp->v_parent;
}

void
vnode_setparent(vnode_t vp, vnode_t dvp)
{
	vp->v_parent = dvp;
}

void
vnode_setname(vnode_t vp, char * name)
{
	vp->v_name = name;
}

/* return the registered  FS name when adding the FS to kernel */
void
vnode_vfsname(vnode_t vp, char * buf)
{
	strlcpy(buf, vp->v_mount->mnt_vtable->vfc_name, MFSNAMELEN);
}

/* return the FS type number */
int
vnode_vfstypenum(vnode_t vp)
{
	return vp->v_mount->mnt_vtable->vfc_typenum;
}

int
vnode_vfs64bitready(vnode_t vp)
{
	/*
	 * Checking for dead_mountp is a bit of a hack for SnowLeopard: <rdar://problem/6269051>
	 */
	if ((vp->v_mount != dead_mountp) && (vp->v_mount->mnt_vtable->vfc_vfsflags & VFC_VFS64BITREADY)) {
		return 1;
	} else {
		return 0;
	}
}



/* return the visible flags on associated mount point of vnode_t */
uint32_t
vnode_vfsvisflags(vnode_t vp)
{
	return vp->v_mount->mnt_flag & MNT_VISFLAGMASK;
}

/* return the command modifier flags on associated mount point of vnode_t */
uint32_t
vnode_vfscmdflags(vnode_t vp)
{
	return vp->v_mount->mnt_flag & MNT_CMDFLAGS;
}

/* return the max symlink of short links  of vnode_t */
uint32_t
vnode_vfsmaxsymlen(vnode_t vp)
{
	return vp->v_mount->mnt_maxsymlinklen;
}

/* return a pointer to the RO vfs_statfs associated with vnode_t's mount point */
struct vfsstatfs *
vnode_vfsstatfs(vnode_t vp)
{
	return &vp->v_mount->mnt_vfsstat;
}

/* return a handle to the FSs specific private handle associated with vnode_t's mount point */
void *
vnode_vfsfsprivate(vnode_t vp)
{
	return vp->v_mount->mnt_data;
}

/* is vnode_t in a rdonly mounted  FS */
int
vnode_vfsisrdonly(vnode_t vp)
{
	return (vp->v_mount->mnt_flag & MNT_RDONLY)? 1 : 0;
}

int
vnode_compound_rename_available(vnode_t vp)
{
	return vnode_compound_op_available(vp, COMPOUND_VNOP_RENAME);
}
int
vnode_compound_rmdir_available(vnode_t vp)
{
	return vnode_compound_op_available(vp, COMPOUND_VNOP_RMDIR);
}
int
vnode_compound_mkdir_available(vnode_t vp)
{
	return vnode_compound_op_available(vp, COMPOUND_VNOP_MKDIR);
}
int
vnode_compound_remove_available(vnode_t vp)
{
	return vnode_compound_op_available(vp, COMPOUND_VNOP_REMOVE);
}
int
vnode_compound_open_available(vnode_t vp)
{
	return vnode_compound_op_available(vp, COMPOUND_VNOP_OPEN);
}

int
vnode_compound_op_available(vnode_t vp, compound_vnop_id_t opid)
{
	return (vp->v_mount->mnt_compound_ops & opid) != 0;
}

/*
 * Returns vnode ref to current working directory; if a per-thread current
 * working directory is in effect, return that instead of the per process one.
 *
 * XXX Published, but not used.
 */
vnode_t
current_workingdir(void)
{
	return vfs_context_cwd(vfs_context_current());
}

/* returns vnode ref to current root(chroot) directory */
vnode_t
current_rootdir(void)
{
	proc_t proc = current_proc();
	struct vnode * vp;

	if ((vp = proc->p_fd->fd_rdir)) {
		if ((vnode_getwithref(vp))) {
			return NULL;
		}
	}
	return vp;
}

/*
 * Get a filesec and optional acl contents from an extended attribute.
 * Function will attempt to retrive ACL, UUID, and GUID information using a
 * read of a named extended attribute (KAUTH_FILESEC_XATTR).
 *
 * Parameters:	vp			The vnode on which to operate.
 *		fsecp			The filesec (and ACL, if any) being
 *					retrieved.
 *		ctx			The vnode context in which the
 *					operation is to be attempted.
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 * Notes:	The kauth_filesec_t in '*fsecp', if retrieved, will be in
 *		host byte order, as will be the ACL contents, if any.
 *		Internally, we will cannonize these values from network (PPC)
 *		byte order after we retrieve them so that the on-disk contents
 *		of the extended attribute are identical for both PPC and Intel
 *		(if we were not being required to provide this service via
 *		fallback, this would be the job of the filesystem
 *		'VNOP_GETATTR' call).
 *
 *		We use ntohl() because it has a transitive property on Intel
 *		machines and no effect on PPC mancines.  This guarantees us
 *
 * XXX:		Deleting rather than ignoreing a corrupt security structure is
 *		probably the only way to reset it without assistance from an
 *		file system integrity checking tool.  Right now we ignore it.
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
static int
vnode_get_filesec(vnode_t vp, kauth_filesec_t *fsecp, vfs_context_t ctx)
{
	kauth_filesec_t fsec;
	uio_t   fsec_uio;
	size_t  fsec_size;
	size_t  xsize, rsize;
	int     error;
	uint32_t        host_fsec_magic;
	uint32_t        host_acl_entrycount;

	fsec = NULL;
	fsec_uio = NULL;

	/* find out how big the EA is */
	error = vn_getxattr(vp, KAUTH_FILESEC_XATTR, NULL, &xsize, XATTR_NOSECURITY, ctx);
	if (error != 0) {
		/* no EA, no filesec */
		if ((error == ENOATTR) || (error == ENOENT) || (error == EJUSTRETURN)) {
			error = 0;
		}
		/* either way, we are done */
		goto out;
	}

	/*
	 * To be valid, a kauth_filesec_t must be large enough to hold a zero
	 * ACE entrly ACL, and if it's larger than that, it must have the right
	 * number of bytes such that it contains an atomic number of ACEs,
	 * rather than partial entries.  Otherwise, we ignore it.
	 */
	if (!KAUTH_FILESEC_VALID(xsize)) {
		KAUTH_DEBUG("    ERROR - Bogus kauth_fiilesec_t: %ld bytes", xsize);
		error = 0;
		goto out;
	}

	/* how many entries would fit? */
	fsec_size = KAUTH_FILESEC_COUNT(xsize);
	if (fsec_size > KAUTH_ACL_MAX_ENTRIES) {
		KAUTH_DEBUG("    ERROR - Bogus (too large) kauth_fiilesec_t: %ld bytes", xsize);
		error = 0;
		goto out;
	}

	/* get buffer and uio */
	if (((fsec = kauth_filesec_alloc(fsec_size)) == NULL) ||
	    ((fsec_uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ)) == NULL) ||
	    uio_addiov(fsec_uio, CAST_USER_ADDR_T(fsec), xsize)) {
		KAUTH_DEBUG("    ERROR - could not allocate iov to read ACL");
		error = ENOMEM;
		goto out;
	}

	/* read security attribute */
	rsize = xsize;
	if ((error = vn_getxattr(vp,
	    KAUTH_FILESEC_XATTR,
	    fsec_uio,
	    &rsize,
	    XATTR_NOSECURITY,
	    ctx)) != 0) {
		/* no attribute - no security data */
		if ((error == ENOATTR) || (error == ENOENT) || (error == EJUSTRETURN)) {
			error = 0;
		}
		/* either way, we are done */
		goto out;
	}

	/*
	 * Validate security structure; the validation must take place in host
	 * byte order.  If it's corrupt, we will just ignore it.
	 */

	/* Validate the size before trying to convert it */
	if (rsize < KAUTH_FILESEC_SIZE(0)) {
		KAUTH_DEBUG("ACL - DATA TOO SMALL (%d)", rsize);
		goto out;
	}

	/* Validate the magic number before trying to convert it */
	host_fsec_magic = ntohl(KAUTH_FILESEC_MAGIC);
	if (fsec->fsec_magic != host_fsec_magic) {
		KAUTH_DEBUG("ACL - BAD MAGIC %x", host_fsec_magic);
		goto out;
	}

	/* Validate the entry count before trying to convert it. */
	host_acl_entrycount = ntohl(fsec->fsec_acl.acl_entrycount);
	if (host_acl_entrycount != KAUTH_FILESEC_NOACL) {
		if (host_acl_entrycount > KAUTH_ACL_MAX_ENTRIES) {
			KAUTH_DEBUG("ACL - BAD ENTRYCOUNT %x", host_acl_entrycount);
			goto out;
		}
		if (KAUTH_FILESEC_SIZE(host_acl_entrycount) > rsize) {
			KAUTH_DEBUG("ACL - BUFFER OVERFLOW (%d entries too big for %d)", host_acl_entrycount, rsize);
			goto out;
		}
	}

	kauth_filesec_acl_setendian(KAUTH_ENDIAN_HOST, fsec, NULL);

	*fsecp = fsec;
	fsec = NULL;
	error = 0;
out:
	if (fsec != NULL) {
		kauth_filesec_free(fsec);
	}
	if (fsec_uio != NULL) {
		uio_free(fsec_uio);
	}
	if (error) {
		*fsecp = NULL;
	}
	return error;
}

/*
 * Set a filesec and optional acl contents into an extended attribute.
 * function will attempt to store ACL, UUID, and GUID information using a
 * write to a named extended attribute (KAUTH_FILESEC_XATTR).  The 'acl'
 * may or may not point to the `fsec->fsec_acl`, depending on whether the
 * original caller supplied an acl.
 *
 * Parameters:	vp			The vnode on which to operate.
 *		fsec			The filesec being set.
 *		acl			The acl to be associated with 'fsec'.
 *		ctx			The vnode context in which the
 *					operation is to be attempted.
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 * Notes:	Both the fsec and the acl are always valid.
 *
 *		The kauth_filesec_t in 'fsec', if any, is in host byte order,
 *		as are the acl contents, if they are used.  Internally, we will
 *		cannonize these values into network (PPC) byte order before we
 *		attempt to write them so that the on-disk contents of the
 *		extended attribute are identical for both PPC and Intel (if we
 *		were not being required to provide this service via fallback,
 *		this would be the job of the filesystem 'VNOP_SETATTR' call).
 *		We reverse this process on the way out, so we leave with the
 *		same byte order we started with.
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
static int
vnode_set_filesec(vnode_t vp, kauth_filesec_t fsec, kauth_acl_t acl, vfs_context_t ctx)
{
	uio_t           fsec_uio;
	int             error;
	uint32_t        saved_acl_copysize;

	fsec_uio = NULL;

	if ((fsec_uio = uio_create(2, 0, UIO_SYSSPACE, UIO_WRITE)) == NULL) {
		KAUTH_DEBUG("    ERROR - could not allocate iov to write ACL");
		error = ENOMEM;
		goto out;
	}
	/*
	 * Save the pre-converted ACL copysize, because it gets swapped too
	 * if we are running with the wrong endianness.
	 */
	saved_acl_copysize = KAUTH_ACL_COPYSIZE(acl);

	kauth_filesec_acl_setendian(KAUTH_ENDIAN_DISK, fsec, acl);

	uio_addiov(fsec_uio, CAST_USER_ADDR_T(fsec), KAUTH_FILESEC_SIZE(0) - KAUTH_ACL_SIZE(KAUTH_FILESEC_NOACL));
	uio_addiov(fsec_uio, CAST_USER_ADDR_T(acl), saved_acl_copysize);
	error = vn_setxattr(vp,
	    KAUTH_FILESEC_XATTR,
	    fsec_uio,
	    XATTR_NOSECURITY,           /* we have auth'ed already */
	    ctx);
	VFS_DEBUG(ctx, vp, "SETATTR - set ACL returning %d", error);

	kauth_filesec_acl_setendian(KAUTH_ENDIAN_HOST, fsec, acl);

out:
	if (fsec_uio != NULL) {
		uio_free(fsec_uio);
	}
	return error;
}


/*
 * Returns:	0			Success
 *		ENOMEM			Not enough space [only if has filesec]
 *		EINVAL			Requested unknown attributes
 *		VNOP_GETATTR:		???
 *		vnode_get_filesec:	???
 *		kauth_cred_guid2uid:	???
 *		kauth_cred_guid2gid:	???
 *		vfs_update_vfsstat:	???
 */
int
vnode_getattr(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx)
{
	kauth_filesec_t fsec;
	kauth_acl_t facl;
	int     error;
	uid_t   nuid;
	gid_t   ngid;

	/*
	 * Reject attempts to fetch unknown attributes.
	 */
	if (vap->va_active & ~VNODE_ATTR_ALL) {
		return EINVAL;
	}

	/* don't ask for extended security data if the filesystem doesn't support it */
	if (!vfs_extendedsecurity(vnode_mount(vp))) {
		VATTR_CLEAR_ACTIVE(vap, va_acl);
		VATTR_CLEAR_ACTIVE(vap, va_uuuid);
		VATTR_CLEAR_ACTIVE(vap, va_guuid);
	}

	/*
	 * If the caller wants size values we might have to synthesise, give the
	 * filesystem the opportunity to supply better intermediate results.
	 */
	if (VATTR_IS_ACTIVE(vap, va_data_alloc) ||
	    VATTR_IS_ACTIVE(vap, va_total_size) ||
	    VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		VATTR_SET_ACTIVE(vap, va_data_size);
		VATTR_SET_ACTIVE(vap, va_data_alloc);
		VATTR_SET_ACTIVE(vap, va_total_size);
		VATTR_SET_ACTIVE(vap, va_total_alloc);
	}

	vap->va_vaflags &= ~VA_USEFSID;

	error = VNOP_GETATTR(vp, vap, ctx);
	if (error) {
		KAUTH_DEBUG("ERROR - returning %d", error);
		goto out;
	}

	/*
	 * If extended security data was requested but not returned, try the fallback
	 * path.
	 */
	if (VATTR_NOT_RETURNED(vap, va_acl) || VATTR_NOT_RETURNED(vap, va_uuuid) || VATTR_NOT_RETURNED(vap, va_guuid)) {
		fsec = NULL;

		if (XATTR_VNODE_SUPPORTED(vp)) {
			/* try to get the filesec */
			if ((error = vnode_get_filesec(vp, &fsec, ctx)) != 0) {
				goto out;
			}
		}
		/* if no filesec, no attributes */
		if (fsec == NULL) {
			VATTR_RETURN(vap, va_acl, NULL);
			VATTR_RETURN(vap, va_uuuid, kauth_null_guid);
			VATTR_RETURN(vap, va_guuid, kauth_null_guid);
		} else {
			/* looks good, try to return what we were asked for */
			VATTR_RETURN(vap, va_uuuid, fsec->fsec_owner);
			VATTR_RETURN(vap, va_guuid, fsec->fsec_group);

			/* only return the ACL if we were actually asked for it */
			if (VATTR_IS_ACTIVE(vap, va_acl)) {
				if (fsec->fsec_acl.acl_entrycount == KAUTH_FILESEC_NOACL) {
					VATTR_RETURN(vap, va_acl, NULL);
				} else {
					facl = kauth_acl_alloc(fsec->fsec_acl.acl_entrycount);
					if (facl == NULL) {
						kauth_filesec_free(fsec);
						error = ENOMEM;
						goto out;
					}
					__nochk_bcopy(&fsec->fsec_acl, facl, KAUTH_ACL_COPYSIZE(&fsec->fsec_acl));
					VATTR_RETURN(vap, va_acl, facl);
				}
			}
			kauth_filesec_free(fsec);
		}
	}
	/*
	 * If someone gave us an unsolicited filesec, toss it.  We promise that
	 * we're OK with a filesystem giving us anything back, but our callers
	 * only expect what they asked for.
	 */
	if (VATTR_IS_SUPPORTED(vap, va_acl) && !VATTR_IS_ACTIVE(vap, va_acl)) {
		if (vap->va_acl != NULL) {
			kauth_acl_free(vap->va_acl);
		}
		VATTR_CLEAR_SUPPORTED(vap, va_acl);
	}

#if 0   /* enable when we have a filesystem only supporting UUIDs */
	/*
	 * Handle the case where we need a UID/GID, but only have extended
	 * security information.
	 */
	if (VATTR_NOT_RETURNED(vap, va_uid) &&
	    VATTR_IS_SUPPORTED(vap, va_uuuid) &&
	    !kauth_guid_equal(&vap->va_uuuid, &kauth_null_guid)) {
		if ((error = kauth_cred_guid2uid(&vap->va_uuuid, &nuid)) == 0) {
			VATTR_RETURN(vap, va_uid, nuid);
		}
	}
	if (VATTR_NOT_RETURNED(vap, va_gid) &&
	    VATTR_IS_SUPPORTED(vap, va_guuid) &&
	    !kauth_guid_equal(&vap->va_guuid, &kauth_null_guid)) {
		if ((error = kauth_cred_guid2gid(&vap->va_guuid, &ngid)) == 0) {
			VATTR_RETURN(vap, va_gid, ngid);
		}
	}
#endif

	/*
	 * Handle uid/gid == 99 and MNT_IGNORE_OWNERSHIP here.
	 */
	if (VATTR_IS_ACTIVE(vap, va_uid)) {
		if (vfs_context_issuser(ctx) && VATTR_IS_SUPPORTED(vap, va_uid)) {
			nuid = vap->va_uid;
		} else if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
			nuid = vp->v_mount->mnt_fsowner;
			if (nuid == KAUTH_UID_NONE) {
				nuid = 99;
			}
		} else if (VATTR_IS_SUPPORTED(vap, va_uid)) {
			nuid = vap->va_uid;
		} else {
			/* this will always be something sensible */
			nuid = vp->v_mount->mnt_fsowner;
		}
		if ((nuid == 99) && !vfs_context_issuser(ctx)) {
			nuid = kauth_cred_getuid(vfs_context_ucred(ctx));
		}
		VATTR_RETURN(vap, va_uid, nuid);
	}
	if (VATTR_IS_ACTIVE(vap, va_gid)) {
		if (vfs_context_issuser(ctx) && VATTR_IS_SUPPORTED(vap, va_gid)) {
			ngid = vap->va_gid;
		} else if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
			ngid = vp->v_mount->mnt_fsgroup;
			if (ngid == KAUTH_GID_NONE) {
				ngid = 99;
			}
		} else if (VATTR_IS_SUPPORTED(vap, va_gid)) {
			ngid = vap->va_gid;
		} else {
			/* this will always be something sensible */
			ngid = vp->v_mount->mnt_fsgroup;
		}
		if ((ngid == 99) && !vfs_context_issuser(ctx)) {
			ngid = kauth_cred_getgid(vfs_context_ucred(ctx));
		}
		VATTR_RETURN(vap, va_gid, ngid);
	}

	/*
	 * Synthesise some values that can be reasonably guessed.
	 */
	if (!VATTR_IS_SUPPORTED(vap, va_iosize)) {
		VATTR_RETURN(vap, va_iosize, vp->v_mount->mnt_vfsstat.f_iosize);
	}

	if (!VATTR_IS_SUPPORTED(vap, va_flags)) {
		VATTR_RETURN(vap, va_flags, 0);
	}

	if (!VATTR_IS_SUPPORTED(vap, va_filerev)) {
		VATTR_RETURN(vap, va_filerev, 0);
	}

	if (!VATTR_IS_SUPPORTED(vap, va_gen)) {
		VATTR_RETURN(vap, va_gen, 0);
	}

	/*
	 * Default sizes.  Ordering here is important, as later defaults build on earlier ones.
	 */
	if (!VATTR_IS_SUPPORTED(vap, va_data_size)) {
		VATTR_RETURN(vap, va_data_size, 0);
	}

	/* do we want any of the possibly-computed values? */
	if (VATTR_IS_ACTIVE(vap, va_data_alloc) ||
	    VATTR_IS_ACTIVE(vap, va_total_size) ||
	    VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		/* make sure f_bsize is valid */
		if (vp->v_mount->mnt_vfsstat.f_bsize == 0) {
			if ((error = vfs_update_vfsstat(vp->v_mount, ctx, VFS_KERNEL_EVENT)) != 0) {
				goto out;
			}
		}

		/* default va_data_alloc from va_data_size */
		if (!VATTR_IS_SUPPORTED(vap, va_data_alloc)) {
			VATTR_RETURN(vap, va_data_alloc, roundup(vap->va_data_size, vp->v_mount->mnt_vfsstat.f_bsize));
		}

		/* default va_total_size from va_data_size */
		if (!VATTR_IS_SUPPORTED(vap, va_total_size)) {
			VATTR_RETURN(vap, va_total_size, vap->va_data_size);
		}

		/* default va_total_alloc from va_total_size which is guaranteed at this point */
		if (!VATTR_IS_SUPPORTED(vap, va_total_alloc)) {
			VATTR_RETURN(vap, va_total_alloc, roundup(vap->va_total_size, vp->v_mount->mnt_vfsstat.f_bsize));
		}
	}

	/*
	 * If we don't have a change time, pull it from the modtime.
	 */
	if (!VATTR_IS_SUPPORTED(vap, va_change_time) && VATTR_IS_SUPPORTED(vap, va_modify_time)) {
		VATTR_RETURN(vap, va_change_time, vap->va_modify_time);
	}

	/*
	 * This is really only supported for the creation VNOPs, but since the field is there
	 * we should populate it correctly.
	 */
	VATTR_RETURN(vap, va_type, vp->v_type);

	/*
	 * The fsid can be obtained from the mountpoint directly.
	 */
	if (VATTR_IS_ACTIVE(vap, va_fsid) &&
	    (!VATTR_IS_SUPPORTED(vap, va_fsid) ||
	    vap->va_vaflags & VA_REALFSID || !(vap->va_vaflags & VA_USEFSID))) {
		VATTR_RETURN(vap, va_fsid, vp->v_mount->mnt_vfsstat.f_fsid.val[0]);
	}

out:
	vap->va_vaflags &= ~VA_USEFSID;

	return error;
}

/*
 * Choose 32 bit or 64 bit fsid
 */
uint64_t
vnode_get_va_fsid(struct vnode_attr *vap)
{
	if (VATTR_IS_SUPPORTED(vap, va_fsid64)) {
		return (uint64_t)vap->va_fsid64.val[0] + ((uint64_t)vap->va_fsid64.val[1] << 32);
	}
	return vap->va_fsid;
}

/*
 * Set the attributes on a vnode in a vnode context.
 *
 * Parameters:	vp			The vnode whose attributes to set.
 *		vap			A pointer to the attributes to set.
 *		ctx			The vnode context in which the
 *					operation is to be attempted.
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 * Notes:	The kauth_filesec_t in 'vap', if any, is in host byte order.
 *
 *		The contents of the data area pointed to by 'vap' may be
 *		modified if the vnode is on a filesystem which has been
 *		mounted with ingore ownership flags, or by the underlyng
 *		VFS itself, or by the fallback code, if the underlying VFS
 *		does not support ACL, UUID, or GUUID attributes directly.
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
int
vnode_setattr(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx)
{
	int     error;
#if CONFIG_FSE
	uint64_t active;
	int     is_perm_change = 0;
	int     is_stat_change = 0;
#endif

	/*
	 * Reject attempts to set unknown attributes.
	 */
	if (vap->va_active & ~VNODE_ATTR_ALL) {
		return EINVAL;
	}

	/*
	 * Make sure the filesystem is mounted R/W.
	 * If not, return an error.
	 */
	if (vfs_isrdonly(vp->v_mount)) {
		error = EROFS;
		goto out;
	}

#if DEVELOPMENT || DEBUG
	/*
	 * XXX VSWAP: Check for entitlements or special flag here
	 * so we can restrict access appropriately.
	 */
#else /* DEVELOPMENT || DEBUG */

	if (vnode_isswap(vp) && (ctx != vfs_context_kernel())) {
		error = EPERM;
		goto out;
	}
#endif /* DEVELOPMENT || DEBUG */

#if NAMEDSTREAMS
	/* For streams, va_data_size is the only setable attribute. */
	if ((vp->v_flag & VISNAMEDSTREAM) && (vap->va_active != VNODE_ATTR_va_data_size)) {
		error = EPERM;
		goto out;
	}
#endif
	/* Check for truncation */
	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		switch (vp->v_type) {
		case VREG:
			/* For regular files it's ok */
			break;
		case VDIR:
			/* Not allowed to truncate directories */
			error = EISDIR;
			goto out;
		default:
			/* For everything else we will clear the bit and let underlying FS decide on the rest */
			VATTR_CLEAR_ACTIVE(vap, va_data_size);
			if (vap->va_active) {
				break;
			}
			/* If it was the only bit set, return success, to handle cases like redirect to /dev/null */
			return 0;
		}
	}

	/*
	 * If ownership is being ignored on this volume, we silently discard
	 * ownership changes.
	 */
	if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
		VATTR_CLEAR_ACTIVE(vap, va_uid);
		VATTR_CLEAR_ACTIVE(vap, va_gid);
	}

	/*
	 * Make sure that extended security is enabled if we're going to try
	 * to set any.
	 */
	if (!vfs_extendedsecurity(vnode_mount(vp)) &&
	    (VATTR_IS_ACTIVE(vap, va_acl) || VATTR_IS_ACTIVE(vap, va_uuuid) || VATTR_IS_ACTIVE(vap, va_guuid))) {
		KAUTH_DEBUG("SETATTR - returning ENOTSUP to request to set extended security");
		error = ENOTSUP;
		goto out;
	}

	/* Never allow the setting of any unsupported superuser flags. */
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		vap->va_flags &= (SF_SUPPORTED | UF_SETTABLE);
	}

#if CONFIG_FSE
	/*
	 * Remember all of the active attributes that we're
	 * attempting to modify.
	 */
	active = vap->va_active & ~VNODE_ATTR_RDONLY;
#endif

	error = VNOP_SETATTR(vp, vap, ctx);

	if ((error == 0) && !VATTR_ALL_SUPPORTED(vap)) {
		error = vnode_setattr_fallback(vp, vap, ctx);
	}

#if CONFIG_FSE
#define PERMISSION_BITS (VNODE_ATTR_BIT(va_uid) | VNODE_ATTR_BIT(va_uuuid) | \
	                 VNODE_ATTR_BIT(va_gid) | VNODE_ATTR_BIT(va_guuid) | \
	                 VNODE_ATTR_BIT(va_mode) | VNODE_ATTR_BIT(va_acl))

	/*
	 * Now that we've changed them, decide whether to send an
	 * FSevent.
	 */
	if ((active & PERMISSION_BITS) & vap->va_supported) {
		is_perm_change = 1;
	} else {
		/*
		 * We've already checked the permission bits, and we
		 * also want to filter out access time / backup time
		 * changes.
		 */
		active &= ~(PERMISSION_BITS |
		    VNODE_ATTR_BIT(va_access_time) |
		    VNODE_ATTR_BIT(va_backup_time));

		/* Anything left to notify about? */
		if (active & vap->va_supported) {
			is_stat_change = 1;
		}
	}

	if (error == 0) {
		if (is_perm_change) {
			if (need_fsevent(FSE_CHOWN, vp)) {
				add_fsevent(FSE_CHOWN, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
			}
		} else if (is_stat_change && need_fsevent(FSE_STAT_CHANGED, vp)) {
			add_fsevent(FSE_STAT_CHANGED, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
		}
	}
#undef PERMISSION_BITS
#endif

out:
	return error;
}

/*
 * Fallback for setting the attributes on a vnode in a vnode context.  This
 * Function will attempt to store ACL, UUID, and GUID information utilizing
 * a read/modify/write operation against an EA used as a backing store for
 * the object.
 *
 * Parameters:	vp			The vnode whose attributes to set.
 *		vap			A pointer to the attributes to set.
 *		ctx			The vnode context in which the
 *					operation is to be attempted.
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 * Notes:	The kauth_filesec_t in 'vap', if any, is in host byte order,
 *		as are the fsec and lfsec, if they are used.
 *
 *		The contents of the data area pointed to by 'vap' may be
 *		modified to indicate that the attribute is supported for
 *		any given requested attribute.
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
int
vnode_setattr_fallback(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx)
{
	kauth_filesec_t fsec;
	kauth_acl_t facl;
	struct kauth_filesec lfsec;
	int     error;

	error = 0;

	/*
	 * Extended security fallback via extended attributes.
	 *
	 * Note that we do not free the filesec; the caller is expected to
	 * do this.
	 */
	if (VATTR_NOT_RETURNED(vap, va_acl) ||
	    VATTR_NOT_RETURNED(vap, va_uuuid) ||
	    VATTR_NOT_RETURNED(vap, va_guuid)) {
		VFS_DEBUG(ctx, vp, "SETATTR - doing filesec fallback");

		/*
		 * Fail for file types that we don't permit extended security
		 * to be set on.
		 */
		if (!XATTR_VNODE_SUPPORTED(vp)) {
			VFS_DEBUG(ctx, vp, "SETATTR - Can't write ACL to file type %d", vnode_vtype(vp));
			error = EINVAL;
			goto out;
		}

		/*
		 * If we don't have all the extended security items, we need
		 * to fetch the existing data to perform a read-modify-write
		 * operation.
		 */
		fsec = NULL;
		if (!VATTR_IS_ACTIVE(vap, va_acl) ||
		    !VATTR_IS_ACTIVE(vap, va_uuuid) ||
		    !VATTR_IS_ACTIVE(vap, va_guuid)) {
			if ((error = vnode_get_filesec(vp, &fsec, ctx)) != 0) {
				KAUTH_DEBUG("SETATTR - ERROR %d fetching filesec for update", error);
				goto out;
			}
		}
		/* if we didn't get a filesec, use our local one */
		if (fsec == NULL) {
			KAUTH_DEBUG("SETATTR - using local filesec for new/full update");
			fsec = &lfsec;
		} else {
			KAUTH_DEBUG("SETATTR - updating existing filesec");
		}
		/* find the ACL */
		facl = &fsec->fsec_acl;

		/* if we're using the local filesec, we need to initialise it */
		if (fsec == &lfsec) {
			fsec->fsec_magic = KAUTH_FILESEC_MAGIC;
			fsec->fsec_owner = kauth_null_guid;
			fsec->fsec_group = kauth_null_guid;
			facl->acl_entrycount = KAUTH_FILESEC_NOACL;
			facl->acl_flags = 0;
		}

		/*
		 * Update with the supplied attributes.
		 */
		if (VATTR_IS_ACTIVE(vap, va_uuuid)) {
			KAUTH_DEBUG("SETATTR - updating owner UUID");
			fsec->fsec_owner = vap->va_uuuid;
			VATTR_SET_SUPPORTED(vap, va_uuuid);
		}
		if (VATTR_IS_ACTIVE(vap, va_guuid)) {
			KAUTH_DEBUG("SETATTR - updating group UUID");
			fsec->fsec_group = vap->va_guuid;
			VATTR_SET_SUPPORTED(vap, va_guuid);
		}
		if (VATTR_IS_ACTIVE(vap, va_acl)) {
			if (vap->va_acl == NULL) {
				KAUTH_DEBUG("SETATTR - removing ACL");
				facl->acl_entrycount = KAUTH_FILESEC_NOACL;
			} else {
				KAUTH_DEBUG("SETATTR - setting ACL with %d entries", vap->va_acl->acl_entrycount);
				facl = vap->va_acl;
			}
			VATTR_SET_SUPPORTED(vap, va_acl);
		}

		/*
		 * If the filesec data is all invalid, we can just remove
		 * the EA completely.
		 */
		if ((facl->acl_entrycount == KAUTH_FILESEC_NOACL) &&
		    kauth_guid_equal(&fsec->fsec_owner, &kauth_null_guid) &&
		    kauth_guid_equal(&fsec->fsec_group, &kauth_null_guid)) {
			error = vn_removexattr(vp, KAUTH_FILESEC_XATTR, XATTR_NOSECURITY, ctx);
			/* no attribute is ok, nothing to delete */
			if (error == ENOATTR) {
				error = 0;
			}
			VFS_DEBUG(ctx, vp, "SETATTR - remove filesec returning %d", error);
		} else {
			/* write the EA */
			error = vnode_set_filesec(vp, fsec, facl, ctx);
			VFS_DEBUG(ctx, vp, "SETATTR - update filesec returning %d", error);
		}

		/* if we fetched a filesec, dispose of the buffer */
		if (fsec != &lfsec) {
			kauth_filesec_free(fsec);
		}
	}
out:

	return error;
}

/*
 * Upcall for a filesystem to tell VFS about an EVFILT_VNODE-type
 * event on a vnode.
 */
int
vnode_notify(vnode_t vp, uint32_t events, struct vnode_attr *vap)
{
	/* These are the same as the corresponding knotes, at least for now.  Cheating a little. */
	uint32_t knote_mask = (VNODE_EVENT_WRITE | VNODE_EVENT_DELETE | VNODE_EVENT_RENAME
	    | VNODE_EVENT_LINK | VNODE_EVENT_EXTEND | VNODE_EVENT_ATTRIB);
	uint32_t dir_contents_mask = (VNODE_EVENT_DIR_CREATED | VNODE_EVENT_FILE_CREATED
	    | VNODE_EVENT_DIR_REMOVED | VNODE_EVENT_FILE_REMOVED);
	uint32_t knote_events = (events & knote_mask);

	/* Permissions are not explicitly part of the kqueue model */
	if (events & VNODE_EVENT_PERMS) {
		knote_events |= NOTE_ATTRIB;
	}

	/* Directory contents information just becomes NOTE_WRITE */
	if ((vnode_isdir(vp)) && (events & dir_contents_mask)) {
		knote_events |= NOTE_WRITE;
	}

	if (knote_events) {
		lock_vnode_and_post(vp, knote_events);
#if CONFIG_FSE
		if (vap != NULL) {
			create_fsevent_from_kevent(vp, events, vap);
		}
#else
		(void)vap;
#endif
	}

	return 0;
}



int
vnode_isdyldsharedcache(vnode_t vp)
{
	return (vp->v_flag & VSHARED_DYLD) ? 1 : 0;
}


/*
 * For a filesystem that isn't tracking its own vnode watchers:
 * check whether a vnode is being monitored.
 */
int
vnode_ismonitored(vnode_t vp)
{
	return vp->v_knotes.slh_first != NULL;
}

int
vnode_getbackingvnode(vnode_t in_vp, vnode_t* out_vpp)
{
	if (out_vpp) {
		*out_vpp = NULLVP;
	}
#if NULLFS
	return nullfs_getbackingvnode(in_vp, out_vpp);
#else
#pragma unused(in_vp)
	return ENOENT;
#endif
}

/*
 * Initialize a struct vnode_attr and activate the attributes required
 * by the vnode_notify() call.
 */
int
vfs_get_notify_attributes(struct vnode_attr *vap)
{
	VATTR_INIT(vap);
	vap->va_active = VNODE_NOTIFY_ATTRS;
	return 0;
}

#if CONFIG_TRIGGERS
int
vfs_settriggercallback(fsid_t *fsid, vfs_trigger_callback_t vtc, void *data, uint32_t flags __unused, vfs_context_t ctx)
{
	int error;
	mount_t mp;

	mp = mount_list_lookupby_fsid(fsid, 0 /* locked */, 1 /* withref */);
	if (mp == NULL) {
		return ENOENT;
	}

	error = vfs_busy(mp, LK_NOWAIT);
	mount_iterdrop(mp);

	if (error != 0) {
		return ENOENT;
	}

	mount_lock(mp);
	if (mp->mnt_triggercallback != NULL) {
		error = EBUSY;
		mount_unlock(mp);
		goto out;
	}

	mp->mnt_triggercallback = vtc;
	mp->mnt_triggerdata = data;
	mount_unlock(mp);

	mp->mnt_triggercallback(mp, VTC_REPLACE, data, ctx);

out:
	vfs_unbusy(mp);
	return 0;
}
#endif /* CONFIG_TRIGGERS */

/*
 *  Definition of vnode operations.
 */

#if 0
/*
*#
*#% lookup       dvp     L ? ?
*#% lookup       vpp     - L -
*/
struct vnop_lookup_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	vfs_context_t a_context;
};
#endif /* 0*/

/*
 * Returns:	0			Success
 *	lock_fsnode:ENOENT		No such file or directory [only for VFS
 *					 that is not thread safe & vnode is
 *					 currently being/has been terminated]
 *	<vfs_lookup>:ENAMETOOLONG
 *	<vfs_lookup>:ENOENT
 *	<vfs_lookup>:EJUSTRETURN
 *	<vfs_lookup>:EPERM
 *	<vfs_lookup>:EISDIR
 *	<vfs_lookup>:ENOTDIR
 *	<vfs_lookup>:???
 *
 * Note:	The return codes from the underlying VFS's lookup routine can't
 *		be fully enumerated here, since third party VFS authors may not
 *		limit their error returns to the ones documented here, even
 *		though this may result in some programs functioning incorrectly.
 *
 *		The return codes documented above are those which may currently
 *		be returned by HFS from hfs_lookup, not including additional
 *		error code which may be propagated from underlying routines.
 */
errno_t
VNOP_LOOKUP(vnode_t dvp, vnode_t *vpp, struct componentname *cnp, vfs_context_t ctx)
{
	int _err;
	struct vnop_lookup_args a;

	a.a_desc = &vnop_lookup_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_context = ctx;

	_err = (*dvp->v_op[vnop_lookup_desc.vdesc_offset])(&a);
	if (_err == 0 && *vpp) {
		DTRACE_FSINFO(lookup, vnode_t, *vpp);
	}

	return _err;
}

#if 0
struct vnop_compound_open_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	int32_t a_flags;
	int32_t a_fmode;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
	void *a_reserved;
};
#endif /* 0 */

int
VNOP_COMPOUND_OPEN(vnode_t dvp, vnode_t *vpp, struct nameidata *ndp, int32_t flags, int32_t fmode, uint32_t *statusp, struct vnode_attr *vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_compound_open_args a;
	int did_create = 0;
	int want_create;
	uint32_t tmp_status = 0;
	struct componentname *cnp = &ndp->ni_cnd;

	want_create = (flags & O_CREAT);

	a.a_desc = &vnop_compound_open_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp; /* Could be NULL */
	a.a_cnp = cnp;
	a.a_flags = flags;
	a.a_fmode = fmode;
	a.a_status = (statusp != NULL) ? statusp : &tmp_status;
	a.a_vap = vap;
	a.a_context = ctx;
	a.a_open_create_authorizer = vn_authorize_create;
	a.a_open_existing_authorizer = vn_authorize_open_existing;
	a.a_reserved = NULL;

	if (dvp == NULLVP) {
		panic("No dvp?");
	}
	if (want_create && !vap) {
		panic("Want create, but no vap?");
	}
	if (!want_create && vap) {
		panic("Don't want create, but have a vap?");
	}

	_err = (*dvp->v_op[vnop_compound_open_desc.vdesc_offset])(&a);
	if (want_create) {
		if (_err == 0 && *vpp) {
			DTRACE_FSINFO(compound_open, vnode_t, *vpp);
		} else {
			DTRACE_FSINFO(compound_open, vnode_t, dvp);
		}
	} else {
		DTRACE_FSINFO(compound_open, vnode_t, *vpp);
	}

	did_create = (*a.a_status & COMPOUND_OPEN_STATUS_DID_CREATE);

	if (did_create && !want_create) {
		panic("Filesystem did a create, even though none was requested?");
	}

	if (did_create) {
#if CONFIG_APPLEDOUBLE
		if (!NATIVE_XATTR(dvp)) {
			/*
			 * Remove stale Apple Double file (if any).
			 */
			xattrfile_remove(dvp, cnp->cn_nameptr, ctx, 0);
		}
#endif /* CONFIG_APPLEDOUBLE */
		/* On create, provide kqueue notification */
		post_event_if_success(dvp, _err, NOTE_WRITE);
	}

	lookup_compound_vnop_post_hook(_err, dvp, *vpp, ndp, did_create);
#if 0 /* FSEvents... */
	if (*vpp && _err && _err != EKEEPLOOKING) {
		vnode_put(*vpp);
		*vpp = NULLVP;
	}
#endif /* 0 */

	return _err;
}

#if 0
struct vnop_create_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_CREATE(vnode_t dvp, vnode_t * vpp, struct componentname * cnp, struct vnode_attr * vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_create_args a;

	a.a_desc = &vnop_create_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_context = ctx;

	_err = (*dvp->v_op[vnop_create_desc.vdesc_offset])(&a);
	if (_err == 0 && *vpp) {
		DTRACE_FSINFO(create, vnode_t, *vpp);
	}

#if CONFIG_APPLEDOUBLE
	if (_err == 0 && !NATIVE_XATTR(dvp)) {
		/*
		 * Remove stale Apple Double file (if any).
		 */
		xattrfile_remove(dvp, cnp->cn_nameptr, ctx, 0);
	}
#endif /* CONFIG_APPLEDOUBLE */

	post_event_if_success(dvp, _err, NOTE_WRITE);

	return _err;
}

#if 0
/*
*#
*#% whiteout     dvp     L L L
*#% whiteout     cnp     - - -
*#% whiteout     flag    - - -
*#
*/
struct vnop_whiteout_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	struct componentname *a_cnp;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_WHITEOUT(__unused vnode_t dvp, __unused struct componentname *cnp,
    __unused int flags, __unused vfs_context_t ctx)
{
	return ENOTSUP;       // XXX OBSOLETE
}

#if 0
/*
*#
*#% mknod        dvp     L U U
*#% mknod        vpp     - X -
*#
*/
struct vnop_mknod_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_MKNOD(vnode_t dvp, vnode_t * vpp, struct componentname * cnp, struct vnode_attr * vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_mknod_args a;

	a.a_desc = &vnop_mknod_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_context = ctx;

	_err = (*dvp->v_op[vnop_mknod_desc.vdesc_offset])(&a);
	if (_err == 0 && *vpp) {
		DTRACE_FSINFO(mknod, vnode_t, *vpp);
	}

	post_event_if_success(dvp, _err, NOTE_WRITE);

	return _err;
}

#if 0
/*
*#
*#% open         vp      L L L
*#
*/
struct vnop_open_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_mode;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_OPEN(vnode_t vp, int mode, vfs_context_t ctx)
{
	int _err;
	struct vnop_open_args a;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_open_desc;
	a.a_vp = vp;
	a.a_mode = mode;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_open_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(open, vnode_t, vp);

	return _err;
}

#if 0
/*
*#
*#% close        vp      U U U
*#
*/
struct vnop_close_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_fflag;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_CLOSE(vnode_t vp, int fflag, vfs_context_t ctx)
{
	int _err;
	struct vnop_close_args a;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_close_desc;
	a.a_vp = vp;
	a.a_fflag = fflag;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_close_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(close, vnode_t, vp);

	return _err;
}

#if 0
/*
*#
*#% access       vp      L L L
*#
*/
struct vnop_access_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_action;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_ACCESS(vnode_t vp, int action, vfs_context_t ctx)
{
	int _err;
	struct vnop_access_args a;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_access_desc;
	a.a_vp = vp;
	a.a_action = action;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_access_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(access, vnode_t, vp);

	return _err;
}

#if 0
/*
*#
*#% getattr      vp      = = =
*#
*/
struct vnop_getattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_GETATTR(vnode_t vp, struct vnode_attr * vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_getattr_args a;

	a.a_desc = &vnop_getattr_desc;
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_getattr_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(getattr, vnode_t, vp);

	return _err;
}

#if 0
/*
*#
*#% setattr      vp      L L L
*#
*/
struct vnop_setattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_SETATTR(vnode_t vp, struct vnode_attr * vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_setattr_args a;

	a.a_desc = &vnop_setattr_desc;
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_setattr_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(setattr, vnode_t, vp);

#if CONFIG_APPLEDOUBLE
	/*
	 * Shadow uid/gid/mod change to extended attribute file.
	 */
	if (_err == 0 && !NATIVE_XATTR(vp)) {
		struct vnode_attr va;
		int change = 0;

		VATTR_INIT(&va);
		if (VATTR_IS_ACTIVE(vap, va_uid)) {
			VATTR_SET(&va, va_uid, vap->va_uid);
			change = 1;
		}
		if (VATTR_IS_ACTIVE(vap, va_gid)) {
			VATTR_SET(&va, va_gid, vap->va_gid);
			change = 1;
		}
		if (VATTR_IS_ACTIVE(vap, va_mode)) {
			VATTR_SET(&va, va_mode, vap->va_mode);
			change = 1;
		}
		if (change) {
			vnode_t dvp;
			const char   *vname;

			dvp = vnode_getparent(vp);
			vname = vnode_getname(vp);

			xattrfile_setattr(dvp, vname, &va, ctx);
			if (dvp != NULLVP) {
				vnode_put(dvp);
			}
			if (vname != NULL) {
				vnode_putname(vname);
			}
		}
	}
#endif /* CONFIG_APPLEDOUBLE */

	/*
	 * If we have changed any of the things about the file that are likely
	 * to result in changes to authorization results, blow the vnode auth
	 * cache
	 */
	if (_err == 0 && (
		    VATTR_IS_SUPPORTED(vap, va_mode) ||
		    VATTR_IS_SUPPORTED(vap, va_uid) ||
		    VATTR_IS_SUPPORTED(vap, va_gid) ||
		    VATTR_IS_SUPPORTED(vap, va_flags) ||
		    VATTR_IS_SUPPORTED(vap, va_acl) ||
		    VATTR_IS_SUPPORTED(vap, va_uuuid) ||
		    VATTR_IS_SUPPORTED(vap, va_guuid))) {
		vnode_uncache_authorized_action(vp, KAUTH_INVALIDATE_CACHED_RIGHTS);

#if NAMEDSTREAMS
		if (vfs_authopaque(vp->v_mount) && vnode_hasnamedstreams(vp)) {
			vnode_t svp;
			if (vnode_getnamedstream(vp, &svp, XATTR_RESOURCEFORK_NAME, NS_OPEN, 0, ctx) == 0) {
				vnode_uncache_authorized_action(svp, KAUTH_INVALIDATE_CACHED_RIGHTS);
				vnode_put(svp);
			}
		}
#endif /* NAMEDSTREAMS */
	}


	post_event_if_success(vp, _err, NOTE_ATTRIB);

	return _err;
}


#if 0
/*
*#
*#% read         vp      L L L
*#
*/
struct vnop_read_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	int a_ioflag;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_READ(vnode_t vp, struct uio * uio, int ioflag, vfs_context_t ctx)
{
	int _err;
	struct vnop_read_args a;
#if CONFIG_DTRACE
	user_ssize_t resid = uio_resid(uio);
#endif

	if (ctx == NULL) {
		return EINVAL;
	}

	a.a_desc = &vnop_read_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_read_desc.vdesc_offset])(&a);
	DTRACE_FSINFO_IO(read,
	    vnode_t, vp, user_ssize_t, (resid - uio_resid(uio)));

	return _err;
}


#if 0
/*
*#
*#% write        vp      L L L
*#
*/
struct vnop_write_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	int a_ioflag;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_WRITE(vnode_t vp, struct uio * uio, int ioflag, vfs_context_t ctx)
{
	struct vnop_write_args a;
	int _err;
#if CONFIG_DTRACE
	user_ssize_t resid = uio_resid(uio);
#endif

	if (ctx == NULL) {
		return EINVAL;
	}

	a.a_desc = &vnop_write_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_write_desc.vdesc_offset])(&a);
	DTRACE_FSINFO_IO(write,
	    vnode_t, vp, user_ssize_t, (resid - uio_resid(uio)));

	post_event_if_success(vp, _err, NOTE_WRITE);

	return _err;
}


#if 0
/*
*#
*#% ioctl        vp      U U U
*#
*/
struct vnop_ioctl_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	u_long a_command;
	caddr_t a_data;
	int a_fflag;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_IOCTL(vnode_t vp, u_long command, caddr_t data, int fflag, vfs_context_t ctx)
{
	int _err;
	struct vnop_ioctl_args a;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	/*
	 * This check should probably have been put in the TTY code instead...
	 *
	 * We have to be careful about what we assume during startup and shutdown.
	 * We have to be able to use the root filesystem's device vnode even when
	 * devfs isn't mounted (yet/anymore), so we can't go looking at its mount
	 * structure.  If there is no data pointer, it doesn't matter whether
	 * the device is 64-bit ready.  Any command (like DKIOCSYNCHRONIZE)
	 * which passes NULL for its data pointer can therefore be used during
	 * mount or unmount of the root filesystem.
	 *
	 * Depending on what root filesystems need to do during mount/unmount, we
	 * may need to loosen this check again in the future.
	 */
	if (vfs_context_is64bit(ctx) && !(vnode_ischr(vp) || vnode_isblk(vp))) {
		if (data != NULL && !vnode_vfs64bitready(vp)) {
			return ENOTTY;
		}
	}

	a.a_desc = &vnop_ioctl_desc;
	a.a_vp = vp;
	a.a_command = command;
	a.a_data = data;
	a.a_fflag = fflag;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_ioctl_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(ioctl, vnode_t, vp);

	return _err;
}


#if 0
/*
*#
*#% select       vp      U U U
*#
*/
struct vnop_select_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_which;
	int a_fflags;
	void *a_wql;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_SELECT(vnode_t vp, int which, int fflags, void * wql, vfs_context_t ctx)
{
	int _err;
	struct vnop_select_args a;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_select_desc;
	a.a_vp = vp;
	a.a_which = which;
	a.a_fflags = fflags;
	a.a_context = ctx;
	a.a_wql = wql;

	_err = (*vp->v_op[vnop_select_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(select, vnode_t, vp);

	return _err;
}


#if 0
/*
*#
*#% exchange fvp         L L L
*#% exchange tvp         L L L
*#
*/
struct vnop_exchange_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_fvp;
	vnode_t a_tvp;
	int a_options;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_EXCHANGE(vnode_t fvp, vnode_t tvp, int options, vfs_context_t ctx)
{
	int _err;
	struct vnop_exchange_args a;

	a.a_desc = &vnop_exchange_desc;
	a.a_fvp = fvp;
	a.a_tvp = tvp;
	a.a_options = options;
	a.a_context = ctx;

	_err = (*fvp->v_op[vnop_exchange_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(exchange, vnode_t, fvp);

	/* Don't post NOTE_WRITE because file descriptors follow the data ... */
	post_event_if_success(fvp, _err, NOTE_ATTRIB);
	post_event_if_success(tvp, _err, NOTE_ATTRIB);

	return _err;
}


#if 0
/*
*#
*#% revoke       vp      U U U
*#
*/
struct vnop_revoke_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_REVOKE(vnode_t vp, int flags, vfs_context_t ctx)
{
	struct vnop_revoke_args a;
	int _err;

	a.a_desc = &vnop_revoke_desc;
	a.a_vp = vp;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_revoke_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(revoke, vnode_t, vp);

	return _err;
}


#if 0
/*
*#
*# mmap_check - vp U U U
*#
*/
struct vnop_mmap_check_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0 */
errno_t
VNOP_MMAP_CHECK(vnode_t vp, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_mmap_check_args a;

	a.a_desc = &vnop_mmap_check_desc;
	a.a_vp = vp;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_mmap_check_desc.vdesc_offset])(&a);
	if (_err == ENOTSUP) {
		_err = 0;
	}
	DTRACE_FSINFO(mmap_check, vnode_t, vp);

	return _err;
}

#if 0
/*
*#
*# mmap - vp U U U
*#
*/
struct vnop_mmap_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_fflags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_MMAP(vnode_t vp, int fflags, vfs_context_t ctx)
{
	int _err;
	struct vnop_mmap_args a;

	a.a_desc = &vnop_mmap_desc;
	a.a_vp = vp;
	a.a_fflags = fflags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_mmap_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(mmap, vnode_t, vp);

	return _err;
}


#if 0
/*
*#
*# mnomap - vp U U U
*#
*/
struct vnop_mnomap_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_MNOMAP(vnode_t vp, vfs_context_t ctx)
{
	int _err;
	struct vnop_mnomap_args a;

	a.a_desc = &vnop_mnomap_desc;
	a.a_vp = vp;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_mnomap_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(mnomap, vnode_t, vp);

	return _err;
}


#if 0
/*
*#
*#% fsync        vp      L L L
*#
*/
struct vnop_fsync_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_waitfor;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_FSYNC(vnode_t vp, int waitfor, vfs_context_t ctx)
{
	struct vnop_fsync_args a;
	int _err;

	a.a_desc = &vnop_fsync_desc;
	a.a_vp = vp;
	a.a_waitfor = waitfor;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_fsync_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(fsync, vnode_t, vp);

	return _err;
}


#if 0
/*
*#
*#% remove       dvp     L U U
*#% remove       vp      L U U
*#
*/
struct vnop_remove_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t a_vp;
	struct componentname *a_cnp;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_REMOVE(vnode_t dvp, vnode_t vp, struct componentname * cnp, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_remove_args a;

	a.a_desc = &vnop_remove_desc;
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*dvp->v_op[vnop_remove_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(remove, vnode_t, vp);

	if (_err == 0) {
		vnode_setneedinactive(vp);
#if CONFIG_APPLEDOUBLE
		if (!(NATIVE_XATTR(dvp))) {
			/*
			 * Remove any associated extended attribute file (._ AppleDouble file).
			 */
			xattrfile_remove(dvp, cnp->cn_nameptr, ctx, 1);
		}
#endif /* CONFIG_APPLEDOUBLE */
	}

	post_event_if_success(vp, _err, NOTE_DELETE | NOTE_LINK);
	post_event_if_success(dvp, _err, NOTE_WRITE);

	return _err;
}

int
VNOP_COMPOUND_REMOVE(vnode_t dvp, vnode_t *vpp, struct nameidata *ndp, int32_t flags, struct vnode_attr *vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_compound_remove_args a;
	int no_vp = (*vpp == NULLVP);

	a.a_desc = &vnop_compound_remove_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = &ndp->ni_cnd;
	a.a_flags = flags;
	a.a_vap = vap;
	a.a_context = ctx;
	a.a_remove_authorizer = vn_authorize_unlink;

	_err = (*dvp->v_op[vnop_compound_remove_desc.vdesc_offset])(&a);
	if (_err == 0 && *vpp) {
		DTRACE_FSINFO(compound_remove, vnode_t, *vpp);
	} else {
		DTRACE_FSINFO(compound_remove, vnode_t, dvp);
	}
	if (_err == 0) {
		vnode_setneedinactive(*vpp);
#if CONFIG_APPLEDOUBLE
		if (!(NATIVE_XATTR(dvp))) {
			/*
			 * Remove any associated extended attribute file (._ AppleDouble file).
			 */
			xattrfile_remove(dvp, ndp->ni_cnd.cn_nameptr, ctx, 1);
		}
#endif /* CONFIG_APPLEDOUBLE */
	}

	post_event_if_success(*vpp, _err, NOTE_DELETE | NOTE_LINK);
	post_event_if_success(dvp, _err, NOTE_WRITE);

	if (no_vp) {
		lookup_compound_vnop_post_hook(_err, dvp, *vpp, ndp, 0);
		if (*vpp && _err && _err != EKEEPLOOKING) {
			vnode_put(*vpp);
			*vpp = NULLVP;
		}
	}

	//printf("VNOP_COMPOUND_REMOVE() returning %d\n", _err);

	return _err;
}

#if 0
/*
*#
*#% link         vp      U U U
*#% link         tdvp    L U U
*#
*/
struct vnop_link_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vnode_t a_tdvp;
	struct componentname *a_cnp;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_LINK(vnode_t vp, vnode_t tdvp, struct componentname * cnp, vfs_context_t ctx)
{
	int _err;
	struct vnop_link_args a;

#if CONFIG_APPLEDOUBLE
	/*
	 * For file systems with non-native extended attributes,
	 * disallow linking to an existing "._" Apple Double file.
	 */
	if (!NATIVE_XATTR(tdvp) && (vp->v_type == VREG)) {
		const char   *vname;

		vname = vnode_getname(vp);
		if (vname != NULL) {
			_err = 0;
			if (vname[0] == '.' && vname[1] == '_' && vname[2] != '\0') {
				_err = EPERM;
			}
			vnode_putname(vname);
			if (_err) {
				return _err;
			}
		}
	}
#endif /* CONFIG_APPLEDOUBLE */

	a.a_desc = &vnop_link_desc;
	a.a_vp = vp;
	a.a_tdvp = tdvp;
	a.a_cnp = cnp;
	a.a_context = ctx;

	_err = (*tdvp->v_op[vnop_link_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(link, vnode_t, vp);

	post_event_if_success(vp, _err, NOTE_LINK);
	post_event_if_success(tdvp, _err, NOTE_WRITE);

	return _err;
}

errno_t
vn_rename(struct vnode *fdvp, struct vnode **fvpp, struct componentname *fcnp, struct vnode_attr *fvap,
    struct vnode *tdvp, struct vnode **tvpp, struct componentname *tcnp, struct vnode_attr *tvap,
    vfs_rename_flags_t flags, vfs_context_t ctx)
{
	int _err;
	struct nameidata *fromnd = NULL;
	struct nameidata *tond = NULL;
#if CONFIG_APPLEDOUBLE
	vnode_t src_attr_vp = NULLVP;
	vnode_t dst_attr_vp = NULLVP;
	char smallname1[48];
	char smallname2[48];
	char *xfromname = NULL;
	char *xtoname = NULL;
#endif /* CONFIG_APPLEDOUBLE */
	int batched;
	uint32_t tdfflags;      // Target directory file flags

	batched = vnode_compound_rename_available(fdvp);

	if (!batched) {
		if (*fvpp == NULLVP) {
			panic("Not batched, and no fvp?");
		}
	}

#if CONFIG_APPLEDOUBLE
	/*
	 * We need to preflight any potential AppleDouble file for the source file
	 * before doing the rename operation, since we could potentially be doing
	 * this operation on a network filesystem, and would end up duplicating
	 * the work.  Also, save the source and destination names.  Skip it if the
	 * source has a "._" prefix.
	 */

	if (!NATIVE_XATTR(fdvp) &&
	    !(fcnp->cn_nameptr[0] == '.' && fcnp->cn_nameptr[1] == '_')) {
		size_t len;
		int error;

		/* Get source attribute file name. */
		len = fcnp->cn_namelen + 3;
		if (len > sizeof(smallname1)) {
			MALLOC(xfromname, char *, len, M_TEMP, M_WAITOK);
		} else {
			xfromname = &smallname1[0];
		}
		strlcpy(xfromname, "._", len);
		strlcat(xfromname, fcnp->cn_nameptr, len);

		/* Get destination attribute file name. */
		len = tcnp->cn_namelen + 3;
		if (len > sizeof(smallname2)) {
			MALLOC(xtoname, char *, len, M_TEMP, M_WAITOK);
		} else {
			xtoname = &smallname2[0];
		}
		strlcpy(xtoname, "._", len);
		strlcat(xtoname, tcnp->cn_nameptr, len);

		/*
		 * Look up source attribute file, keep reference on it if exists.
		 * Note that we do the namei with the nameiop of RENAME, which is different than
		 * in the rename syscall. It's OK if the source file does not exist, since this
		 * is only for AppleDouble files.
		 */
		MALLOC(fromnd, struct nameidata *, sizeof(struct nameidata), M_TEMP, M_WAITOK);
		NDINIT(fromnd, RENAME, OP_RENAME, NOFOLLOW | USEDVP | CN_NBMOUNTLOOK,
		    UIO_SYSSPACE, CAST_USER_ADDR_T(xfromname), ctx);
		fromnd->ni_dvp = fdvp;
		error = namei(fromnd);

		/*
		 * If there was an error looking up source attribute file,
		 * we'll behave as if it didn't exist.
		 */

		if (error == 0) {
			if (fromnd->ni_vp) {
				/* src_attr_vp indicates need to call vnode_put / nameidone later */
				src_attr_vp = fromnd->ni_vp;

				if (fromnd->ni_vp->v_type != VREG) {
					src_attr_vp = NULLVP;
					vnode_put(fromnd->ni_vp);
				}
			}
			/*
			 * Either we got an invalid vnode type (not a regular file) or the namei lookup
			 * suppressed ENOENT as a valid error since we're renaming. Either way, we don't
			 * have a vnode here, so we drop our namei buffer for the source attribute file
			 */
			if (src_attr_vp == NULLVP) {
				nameidone(fromnd);
			}
		}
	}
#endif /* CONFIG_APPLEDOUBLE */

	if (batched) {
		_err = VNOP_COMPOUND_RENAME(fdvp, fvpp, fcnp, fvap, tdvp, tvpp, tcnp, tvap, flags, ctx);
		if (_err != 0) {
			printf("VNOP_COMPOUND_RENAME() returned %d\n", _err);
		}
	} else {
		if (flags) {
			_err = VNOP_RENAMEX(fdvp, *fvpp, fcnp, tdvp, *tvpp, tcnp, flags, ctx);
			if (_err == ENOTSUP && flags == VFS_RENAME_SECLUDE) {
				// Legacy...
				if ((*fvpp)->v_mount->mnt_vtable->vfc_vfsflags & VFC_VFSVNOP_SECLUDE_RENAME) {
					fcnp->cn_flags |= CN_SECLUDE_RENAME;
					_err = VNOP_RENAME(fdvp, *fvpp, fcnp, tdvp, *tvpp, tcnp, ctx);
				}
			}
		} else {
			_err = VNOP_RENAME(fdvp, *fvpp, fcnp, tdvp, *tvpp, tcnp, ctx);
		}
	}

	/*
	 * If moved to a new directory that is restricted,
	 * set the restricted flag on the item moved.
	 */
	if (_err == 0) {
		_err = vnode_flags(tdvp, &tdfflags, ctx);
		if (_err == 0) {
			uint32_t inherit_flags = tdfflags & (UF_DATAVAULT | SF_RESTRICTED);
			if (inherit_flags) {
				uint32_t fflags;
				_err = vnode_flags(*fvpp, &fflags, ctx);
				if (_err == 0 && fflags != (fflags | inherit_flags)) {
					struct vnode_attr va;
					VATTR_INIT(&va);
					VATTR_SET(&va, va_flags, fflags | inherit_flags);
					_err = vnode_setattr(*fvpp, &va, ctx);
				}
			}
		}
	}

#if CONFIG_MACF
	if (_err == 0) {
		mac_vnode_notify_rename(ctx, *fvpp, tdvp, tcnp);
		if (flags & VFS_RENAME_SWAP) {
			mac_vnode_notify_rename(ctx, *tvpp, fdvp, fcnp);
		}
	}
#endif

#if CONFIG_APPLEDOUBLE
	/*
	 * Rename any associated extended attribute file (._ AppleDouble file).
	 */
	if (_err == 0 && !NATIVE_XATTR(fdvp) && xfromname != NULL) {
		int error = 0;

		/*
		 * Get destination attribute file vnode.
		 * Note that tdvp already has an iocount reference. Make sure to check that we
		 * get a valid vnode from namei.
		 */
		MALLOC(tond, struct nameidata *, sizeof(struct nameidata), M_TEMP, M_WAITOK);
		NDINIT(tond, RENAME, OP_RENAME,
		    NOCACHE | NOFOLLOW | USEDVP | CN_NBMOUNTLOOK, UIO_SYSSPACE,
		    CAST_USER_ADDR_T(xtoname), ctx);
		tond->ni_dvp = tdvp;
		error = namei(tond);

		if (error) {
			goto ad_error;
		}

		if (tond->ni_vp) {
			dst_attr_vp = tond->ni_vp;
		}

		if (src_attr_vp) {
			const char *old_name = src_attr_vp->v_name;
			vnode_t old_parent = src_attr_vp->v_parent;

			if (batched) {
				error = VNOP_COMPOUND_RENAME(fdvp, &src_attr_vp, &fromnd->ni_cnd, NULL,
				    tdvp, &dst_attr_vp, &tond->ni_cnd, NULL,
				    0, ctx);
			} else {
				error = VNOP_RENAME(fdvp, src_attr_vp, &fromnd->ni_cnd,
				    tdvp, dst_attr_vp, &tond->ni_cnd, ctx);
			}

			if (error == 0 && old_name == src_attr_vp->v_name &&
			    old_parent == src_attr_vp->v_parent) {
				int update_flags = VNODE_UPDATE_NAME;

				if (fdvp != tdvp) {
					update_flags |= VNODE_UPDATE_PARENT;
				}

				if ((src_attr_vp->v_mount->mnt_vtable->vfc_vfsflags & VFC_VFSVNOP_NOUPDATEID_RENAME) == 0) {
					vnode_update_identity(src_attr_vp, tdvp,
					    tond->ni_cnd.cn_nameptr,
					    tond->ni_cnd.cn_namelen,
					    tond->ni_cnd.cn_hash,
					    update_flags);
				}
			}

			/* kevent notifications for moving resource files
			 * _err is zero if we're here, so no need to notify directories, code
			 * below will do that.  only need to post the rename on the source and
			 * possibly a delete on the dest
			 */
			post_event_if_success(src_attr_vp, error, NOTE_RENAME);
			if (dst_attr_vp) {
				post_event_if_success(dst_attr_vp, error, NOTE_DELETE);
			}
		} else if (dst_attr_vp) {
			/*
			 * Just delete destination attribute file vnode if it exists, since
			 * we didn't have a source attribute file.
			 * Note that tdvp already has an iocount reference.
			 */

			struct vnop_remove_args args;

			args.a_desc    = &vnop_remove_desc;
			args.a_dvp     = tdvp;
			args.a_vp      = dst_attr_vp;
			args.a_cnp     = &tond->ni_cnd;
			args.a_context = ctx;

			if (error == 0) {
				error = (*tdvp->v_op[vnop_remove_desc.vdesc_offset])(&args);

				if (error == 0) {
					vnode_setneedinactive(dst_attr_vp);
				}
			}

			/* kevent notification for deleting the destination's attribute file
			 * if it existed.  Only need to post the delete on the destination, since
			 * the code below will handle the directories.
			 */
			post_event_if_success(dst_attr_vp, error, NOTE_DELETE);
		}
	}
ad_error:
	if (src_attr_vp) {
		vnode_put(src_attr_vp);
		nameidone(fromnd);
	}
	if (dst_attr_vp) {
		vnode_put(dst_attr_vp);
		nameidone(tond);
	}
	if (xfromname && xfromname != &smallname1[0]) {
		FREE(xfromname, M_TEMP);
	}
	if (xtoname && xtoname != &smallname2[0]) {
		FREE(xtoname, M_TEMP);
	}
#endif /* CONFIG_APPLEDOUBLE */
	if (fromnd) {
		FREE(fromnd, M_TEMP);
	}
	if (tond) {
		FREE(tond, M_TEMP);
	}
	return _err;
}


#if 0
/*
*#
*#% rename       fdvp    U U U
*#% rename       fvp     U U U
*#% rename       tdvp    L U U
*#% rename       tvp     X U U
*#
*/
struct vnop_rename_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_fdvp;
	vnode_t a_fvp;
	struct componentname *a_fcnp;
	vnode_t a_tdvp;
	vnode_t a_tvp;
	struct componentname *a_tcnp;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_RENAME(struct vnode *fdvp, struct vnode *fvp, struct componentname *fcnp,
    struct vnode *tdvp, struct vnode *tvp, struct componentname *tcnp,
    vfs_context_t ctx)
{
	int _err = 0;
	struct vnop_rename_args a;

	a.a_desc = &vnop_rename_desc;
	a.a_fdvp = fdvp;
	a.a_fvp = fvp;
	a.a_fcnp = fcnp;
	a.a_tdvp = tdvp;
	a.a_tvp = tvp;
	a.a_tcnp = tcnp;
	a.a_context = ctx;

	/* do the rename of the main file. */
	_err = (*fdvp->v_op[vnop_rename_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(rename, vnode_t, fdvp);

	if (_err) {
		return _err;
	}

	return post_rename(fdvp, fvp, tdvp, tvp);
}

static errno_t
post_rename(vnode_t fdvp, vnode_t fvp, vnode_t tdvp, vnode_t tvp)
{
	if (tvp && tvp != fvp) {
		vnode_setneedinactive(tvp);
	}

	/* Wrote at least one directory.  If transplanted a dir, also changed link counts */
	int events = NOTE_WRITE;
	if (vnode_isdir(fvp)) {
		/* Link count on dir changed only if we are moving a dir and...
		 *      --Moved to new dir, not overwriting there
		 *      --Kept in same dir and DID overwrite
		 */
		if (((fdvp != tdvp) && (!tvp)) || ((fdvp == tdvp) && (tvp))) {
			events |= NOTE_LINK;
		}
	}

	lock_vnode_and_post(fdvp, events);
	if (fdvp != tdvp) {
		lock_vnode_and_post(tdvp, events);
	}

	/* If you're replacing the target, post a deletion for it */
	if (tvp) {
		lock_vnode_and_post(tvp, NOTE_DELETE);
	}

	lock_vnode_and_post(fvp, NOTE_RENAME);

	return 0;
}

#if 0
/*
*#
*#% renamex      fdvp    U U U
*#% renamex      fvp     U U U
*#% renamex      tdvp    L U U
*#% renamex      tvp     X U U
*#
*/
struct vnop_renamex_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_fdvp;
	vnode_t a_fvp;
	struct componentname *a_fcnp;
	vnode_t a_tdvp;
	vnode_t a_tvp;
	struct componentname *a_tcnp;
	vfs_rename_flags_t a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_RENAMEX(struct vnode *fdvp, struct vnode *fvp, struct componentname *fcnp,
    struct vnode *tdvp, struct vnode *tvp, struct componentname *tcnp,
    vfs_rename_flags_t flags, vfs_context_t ctx)
{
	int _err = 0;
	struct vnop_renamex_args a;

	a.a_desc = &vnop_renamex_desc;
	a.a_fdvp = fdvp;
	a.a_fvp = fvp;
	a.a_fcnp = fcnp;
	a.a_tdvp = tdvp;
	a.a_tvp = tvp;
	a.a_tcnp = tcnp;
	a.a_flags = flags;
	a.a_context = ctx;

	/* do the rename of the main file. */
	_err = (*fdvp->v_op[vnop_renamex_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(renamex, vnode_t, fdvp);

	if (_err) {
		return _err;
	}

	return post_rename(fdvp, fvp, tdvp, tvp);
}


int
VNOP_COMPOUND_RENAME(
	struct vnode *fdvp, struct vnode **fvpp, struct componentname *fcnp, struct vnode_attr *fvap,
	struct vnode *tdvp, struct vnode **tvpp, struct componentname *tcnp, struct vnode_attr *tvap,
	uint32_t flags, vfs_context_t ctx)
{
	int _err = 0;
	int events;
	struct vnop_compound_rename_args a;
	int no_fvp, no_tvp;

	no_fvp = (*fvpp) == NULLVP;
	no_tvp = (*tvpp) == NULLVP;

	a.a_desc = &vnop_compound_rename_desc;

	a.a_fdvp = fdvp;
	a.a_fvpp = fvpp;
	a.a_fcnp = fcnp;
	a.a_fvap = fvap;

	a.a_tdvp = tdvp;
	a.a_tvpp = tvpp;
	a.a_tcnp = tcnp;
	a.a_tvap = tvap;

	a.a_flags = flags;
	a.a_context = ctx;
	a.a_rename_authorizer = vn_authorize_rename;
	a.a_reserved = NULL;

	/* do the rename of the main file. */
	_err = (*fdvp->v_op[vnop_compound_rename_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(compound_rename, vnode_t, fdvp);

	if (_err == 0) {
		if (*tvpp && *tvpp != *fvpp) {
			vnode_setneedinactive(*tvpp);
		}
	}

	/* Wrote at least one directory.  If transplanted a dir, also changed link counts */
	if (_err == 0 && *fvpp != *tvpp) {
		if (!*fvpp) {
			panic("No fvpp after compound rename?");
		}

		events = NOTE_WRITE;
		if (vnode_isdir(*fvpp)) {
			/* Link count on dir changed only if we are moving a dir and...
			 *      --Moved to new dir, not overwriting there
			 *      --Kept in same dir and DID overwrite
			 */
			if (((fdvp != tdvp) && (!*tvpp)) || ((fdvp == tdvp) && (*tvpp))) {
				events |= NOTE_LINK;
			}
		}

		lock_vnode_and_post(fdvp, events);
		if (fdvp != tdvp) {
			lock_vnode_and_post(tdvp, events);
		}

		/* If you're replacing the target, post a deletion for it */
		if (*tvpp) {
			lock_vnode_and_post(*tvpp, NOTE_DELETE);
		}

		lock_vnode_and_post(*fvpp, NOTE_RENAME);
	}

	if (no_fvp) {
		lookup_compound_vnop_post_hook(_err, fdvp, *fvpp, fcnp->cn_ndp, 0);
	}
	if (no_tvp && *tvpp != NULLVP) {
		lookup_compound_vnop_post_hook(_err, tdvp, *tvpp, tcnp->cn_ndp, 0);
	}

	if (_err && _err != EKEEPLOOKING) {
		if (*fvpp) {
			vnode_put(*fvpp);
			*fvpp = NULLVP;
		}
		if (*tvpp) {
			vnode_put(*tvpp);
			*tvpp = NULLVP;
		}
	}

	return _err;
}

int
vn_mkdir(struct vnode *dvp, struct vnode **vpp, struct nameidata *ndp,
    struct vnode_attr *vap, vfs_context_t ctx)
{
	if (ndp->ni_cnd.cn_nameiop != CREATE) {
		panic("Non-CREATE nameiop in vn_mkdir()?");
	}

	if (vnode_compound_mkdir_available(dvp)) {
		return VNOP_COMPOUND_MKDIR(dvp, vpp, ndp, vap, ctx);
	} else {
		return VNOP_MKDIR(dvp, vpp, &ndp->ni_cnd, vap, ctx);
	}
}

#if 0
/*
*#
*#% mkdir        dvp     L U U
*#% mkdir        vpp     - L -
*#
*/
struct vnop_mkdir_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	struct vnode_attr *a_vap;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_MKDIR(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp,
    struct vnode_attr *vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_mkdir_args a;

	a.a_desc = &vnop_mkdir_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_context = ctx;

	_err = (*dvp->v_op[vnop_mkdir_desc.vdesc_offset])(&a);
	if (_err == 0 && *vpp) {
		DTRACE_FSINFO(mkdir, vnode_t, *vpp);
	}
#if CONFIG_APPLEDOUBLE
	if (_err == 0 && !NATIVE_XATTR(dvp)) {
		/*
		 * Remove stale Apple Double file (if any).
		 */
		xattrfile_remove(dvp, cnp->cn_nameptr, ctx, 0);
	}
#endif /* CONFIG_APPLEDOUBLE */

	post_event_if_success(dvp, _err, NOTE_LINK | NOTE_WRITE);

	return _err;
}

int
VNOP_COMPOUND_MKDIR(struct vnode *dvp, struct vnode **vpp, struct nameidata *ndp,
    struct vnode_attr *vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_compound_mkdir_args a;

	a.a_desc = &vnop_compound_mkdir_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = &ndp->ni_cnd;
	a.a_vap = vap;
	a.a_flags = 0;
	a.a_context = ctx;
#if 0
	a.a_mkdir_authorizer = vn_authorize_mkdir;
#endif /* 0 */
	a.a_reserved = NULL;

	_err = (*dvp->v_op[vnop_compound_mkdir_desc.vdesc_offset])(&a);
	if (_err == 0 && *vpp) {
		DTRACE_FSINFO(compound_mkdir, vnode_t, *vpp);
	}
#if CONFIG_APPLEDOUBLE
	if (_err == 0 && !NATIVE_XATTR(dvp)) {
		/*
		 * Remove stale Apple Double file (if any).
		 */
		xattrfile_remove(dvp, ndp->ni_cnd.cn_nameptr, ctx, 0);
	}
#endif /* CONFIG_APPLEDOUBLE */

	post_event_if_success(dvp, _err, NOTE_LINK | NOTE_WRITE);

	lookup_compound_vnop_post_hook(_err, dvp, *vpp, ndp, (_err == 0));
	if (*vpp && _err && _err != EKEEPLOOKING) {
		vnode_put(*vpp);
		*vpp = NULLVP;
	}

	return _err;
}

int
vn_rmdir(vnode_t dvp, vnode_t *vpp, struct nameidata *ndp, struct vnode_attr *vap, vfs_context_t ctx)
{
	if (vnode_compound_rmdir_available(dvp)) {
		return VNOP_COMPOUND_RMDIR(dvp, vpp, ndp, vap, ctx);
	} else {
		if (*vpp == NULLVP) {
			panic("NULL vp, but not a compound VNOP?");
		}
		if (vap != NULL) {
			panic("Non-NULL vap, but not a compound VNOP?");
		}
		return VNOP_RMDIR(dvp, *vpp, &ndp->ni_cnd, ctx);
	}
}

#if 0
/*
*#
*#% rmdir        dvp     L U U
*#% rmdir        vp      L U U
*#
*/
struct vnop_rmdir_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t a_vp;
	struct componentname *a_cnp;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t
VNOP_RMDIR(struct vnode *dvp, struct vnode *vp, struct componentname *cnp, vfs_context_t ctx)
{
	int _err;
	struct vnop_rmdir_args a;

	a.a_desc = &vnop_rmdir_desc;
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_rmdir_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(rmdir, vnode_t, vp);

	if (_err == 0) {
		vnode_setneedinactive(vp);
#if CONFIG_APPLEDOUBLE
		if (!(NATIVE_XATTR(dvp))) {
			/*
			 * Remove any associated extended attribute file (._ AppleDouble file).
			 */
			xattrfile_remove(dvp, cnp->cn_nameptr, ctx, 1);
		}
#endif
	}

	/* If you delete a dir, it loses its "." reference --> NOTE_LINK */
	post_event_if_success(vp, _err, NOTE_DELETE | NOTE_LINK);
	post_event_if_success(dvp, _err, NOTE_LINK | NOTE_WRITE);

	return _err;
}

int
VNOP_COMPOUND_RMDIR(struct vnode *dvp, struct vnode **vpp, struct nameidata *ndp,
    struct vnode_attr *vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_compound_rmdir_args a;
	int no_vp;

	a.a_desc = &vnop_mkdir_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = &ndp->ni_cnd;
	a.a_vap = vap;
	a.a_flags = 0;
	a.a_context = ctx;
	a.a_rmdir_authorizer = vn_authorize_rmdir;
	a.a_reserved = NULL;

	no_vp = (*vpp == NULLVP);

	_err = (*dvp->v_op[vnop_compound_rmdir_desc.vdesc_offset])(&a);
	if (_err == 0 && *vpp) {
		DTRACE_FSINFO(compound_rmdir, vnode_t, *vpp);
	}
#if CONFIG_APPLEDOUBLE
	if (_err == 0 && !NATIVE_XATTR(dvp)) {
		/*
		 * Remove stale Apple Double file (if any).
		 */
		xattrfile_remove(dvp, ndp->ni_cnd.cn_nameptr, ctx, 0);
	}
#endif

	if (*vpp) {
		post_event_if_success(*vpp, _err, NOTE_DELETE | NOTE_LINK);
	}
	post_event_if_success(dvp, _err, NOTE_LINK | NOTE_WRITE);

	if (no_vp) {
		lookup_compound_vnop_post_hook(_err, dvp, *vpp, ndp, 0);

#if 0 /* Removing orphaned ._ files requires a vp.... */
		if (*vpp && _err && _err != EKEEPLOOKING) {
			vnode_put(*vpp);
			*vpp = NULLVP;
		}
#endif  /* 0 */
	}

	return _err;
}

#if CONFIG_APPLEDOUBLE
/*
 * Remove a ._ AppleDouble file
 */
#define AD_STALE_SECS  (180)
static void
xattrfile_remove(vnode_t dvp, const char * basename, vfs_context_t ctx, int force)
{
	vnode_t xvp;
	struct nameidata nd;
	char smallname[64];
	char *filename = NULL;
	size_t len;

	if ((basename == NULL) || (basename[0] == '\0') ||
	    (basename[0] == '.' && basename[1] == '_')) {
		return;
	}
	filename = &smallname[0];
	len = snprintf(filename, sizeof(smallname), "._%s", basename);
	if (len >= sizeof(smallname)) {
		len++;  /* snprintf result doesn't include '\0' */
		MALLOC(filename, char *, len, M_TEMP, M_WAITOK);
		len = snprintf(filename, len, "._%s", basename);
	}
	NDINIT(&nd, DELETE, OP_UNLINK, WANTPARENT | LOCKLEAF | NOFOLLOW | USEDVP, UIO_SYSSPACE,
	    CAST_USER_ADDR_T(filename), ctx);
	nd.ni_dvp = dvp;
	if (namei(&nd) != 0) {
		goto out2;
	}

	xvp = nd.ni_vp;
	nameidone(&nd);
	if (xvp->v_type != VREG) {
		goto out1;
	}

	/*
	 * When creating a new object and a "._" file already
	 * exists, check to see if its a stale "._" file.
	 *
	 */
	if (!force) {
		struct vnode_attr va;

		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_data_size);
		VATTR_WANTED(&va, va_modify_time);
		if (VNOP_GETATTR(xvp, &va, ctx) == 0 &&
		    VATTR_IS_SUPPORTED(&va, va_data_size) &&
		    VATTR_IS_SUPPORTED(&va, va_modify_time) &&
		    va.va_data_size != 0) {
			struct timeval tv;

			microtime(&tv);
			if ((tv.tv_sec > va.va_modify_time.tv_sec) &&
			    (tv.tv_sec - va.va_modify_time.tv_sec) > AD_STALE_SECS) {
				force = 1;  /* must be stale */
			}
		}
	}
	if (force) {
		int  error;

		error = VNOP_REMOVE(dvp, xvp, &nd.ni_cnd, 0, ctx);
		if (error == 0) {
			vnode_setneedinactive(xvp);
		}

		post_event_if_success(xvp, error, NOTE_DELETE);
		post_event_if_success(dvp, error, NOTE_WRITE);
	}

out1:
	vnode_put(dvp);
	vnode_put(xvp);
out2:
	if (filename && filename != &smallname[0]) {
		FREE(filename, M_TEMP);
	}
}

/*
 * Shadow uid/gid/mod to a ._ AppleDouble file
 */
static void
xattrfile_setattr(vnode_t dvp, const char * basename, struct vnode_attr * vap,
    vfs_context_t ctx)
{
	vnode_t xvp;
	struct nameidata nd;
	char smallname[64];
	char *filename = NULL;
	size_t len;

	if ((dvp == NULLVP) ||
	    (basename == NULL) || (basename[0] == '\0') ||
	    (basename[0] == '.' && basename[1] == '_')) {
		return;
	}
	filename = &smallname[0];
	len = snprintf(filename, sizeof(smallname), "._%s", basename);
	if (len >= sizeof(smallname)) {
		len++;  /* snprintf result doesn't include '\0' */
		MALLOC(filename, char *, len, M_TEMP, M_WAITOK);
		len = snprintf(filename, len, "._%s", basename);
	}
	NDINIT(&nd, LOOKUP, OP_SETATTR, NOFOLLOW | USEDVP, UIO_SYSSPACE,
	    CAST_USER_ADDR_T(filename), ctx);
	nd.ni_dvp = dvp;
	if (namei(&nd) != 0) {
		goto out2;
	}

	xvp = nd.ni_vp;
	nameidone(&nd);

	if (xvp->v_type == VREG) {
		struct vnop_setattr_args a;

		a.a_desc = &vnop_setattr_desc;
		a.a_vp = xvp;
		a.a_vap = vap;
		a.a_context = ctx;

		(void) (*xvp->v_op[vnop_setattr_desc.vdesc_offset])(&a);
	}

	vnode_put(xvp);
out2:
	if (filename && filename != &smallname[0]) {
		FREE(filename, M_TEMP);
	}
}
#endif /* CONFIG_APPLEDOUBLE */

 #if 0
/*
*#
*#% symlink      dvp     L U U
*#% symlink      vpp     - U -
*#
*/
struct vnop_symlink_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	struct vnode_attr *a_vap;
	char *a_target;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t
VNOP_SYMLINK(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp,
    struct vnode_attr *vap, char *target, vfs_context_t ctx)
{
	int _err;
	struct vnop_symlink_args a;

	a.a_desc = &vnop_symlink_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_target = target;
	a.a_context = ctx;

	_err = (*dvp->v_op[vnop_symlink_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(symlink, vnode_t, dvp);
#if CONFIG_APPLEDOUBLE
	if (_err == 0 && !NATIVE_XATTR(dvp)) {
		/*
		 * Remove stale Apple Double file (if any).  Posts its own knotes
		 */
		xattrfile_remove(dvp, cnp->cn_nameptr, ctx, 0);
	}
#endif /* CONFIG_APPLEDOUBLE */

	post_event_if_success(dvp, _err, NOTE_WRITE);

	return _err;
}

#if 0
/*
*#
*#% readdir      vp      L L L
*#
*/
struct vnop_readdir_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	int a_flags;
	int *a_eofflag;
	int *a_numdirent;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t
VNOP_READDIR(struct vnode *vp, struct uio *uio, int flags, int *eofflag,
    int *numdirent, vfs_context_t ctx)
{
	int _err;
	struct vnop_readdir_args a;
#if CONFIG_DTRACE
	user_ssize_t resid = uio_resid(uio);
#endif

	a.a_desc = &vnop_readdir_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_flags = flags;
	a.a_eofflag = eofflag;
	a.a_numdirent = numdirent;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_readdir_desc.vdesc_offset])(&a);
	DTRACE_FSINFO_IO(readdir,
	    vnode_t, vp, user_ssize_t, (resid - uio_resid(uio)));

	return _err;
}

#if 0
/*
*#
*#% readdirattr  vp      L L L
*#
*/
struct vnop_readdirattr_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	uint32_t a_maxcount;
	uint32_t a_options;
	uint32_t *a_newstate;
	int *a_eofflag;
	uint32_t *a_actualcount;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t
VNOP_READDIRATTR(struct vnode *vp, struct attrlist *alist, struct uio *uio, uint32_t maxcount,
    uint32_t options, uint32_t *newstate, int *eofflag, uint32_t *actualcount, vfs_context_t ctx)
{
	int _err;
	struct vnop_readdirattr_args a;
#if CONFIG_DTRACE
	user_ssize_t resid = uio_resid(uio);
#endif

	a.a_desc = &vnop_readdirattr_desc;
	a.a_vp = vp;
	a.a_alist = alist;
	a.a_uio = uio;
	a.a_maxcount = maxcount;
	a.a_options = options;
	a.a_newstate = newstate;
	a.a_eofflag = eofflag;
	a.a_actualcount = actualcount;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_readdirattr_desc.vdesc_offset])(&a);
	DTRACE_FSINFO_IO(readdirattr,
	    vnode_t, vp, user_ssize_t, (resid - uio_resid(uio)));

	return _err;
}

#if 0
struct vnop_getttrlistbulk_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct attrlist *a_alist;
	struct vnode_attr *a_vap;
	struct uio *a_uio;
	void *a_private
	uint64_t a_options;
	int *a_eofflag;
	uint32_t *a_actualcount;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_GETATTRLISTBULK(struct vnode *vp, struct attrlist *alist,
    struct vnode_attr *vap, struct uio *uio, void *private, uint64_t options,
    int32_t *eofflag, int32_t *actualcount, vfs_context_t ctx)
{
	int _err;
	struct vnop_getattrlistbulk_args a;
#if CONFIG_DTRACE
	user_ssize_t resid = uio_resid(uio);
#endif

	a.a_desc = &vnop_getattrlistbulk_desc;
	a.a_vp = vp;
	a.a_alist = alist;
	a.a_vap = vap;
	a.a_uio = uio;
	a.a_private = private;
	a.a_options = options;
	a.a_eofflag = eofflag;
	a.a_actualcount = actualcount;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_getattrlistbulk_desc.vdesc_offset])(&a);
	DTRACE_FSINFO_IO(getattrlistbulk,
	    vnode_t, vp, user_ssize_t, (resid - uio_resid(uio)));

	return _err;
}

#if 0
/*
*#
*#% readlink     vp      L L L
*#
*/
struct vnop_readlink_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct uio *a_uio;
	vfs_context_t a_context;
};
#endif /* 0 */

/*
 * Returns:	0			Success
 *		lock_fsnode:ENOENT	No such file or directory [only for VFS
 *					 that is not thread safe & vnode is
 *					 currently being/has been terminated]
 *		<vfs_readlink>:EINVAL
 *		<vfs_readlink>:???
 *
 * Note:	The return codes from the underlying VFS's readlink routine
 *		can't be fully enumerated here, since third party VFS authors
 *		may not limit their error returns to the ones documented here,
 *		even though this may result in some programs functioning
 *		incorrectly.
 *
 *		The return codes documented above are those which may currently
 *		be returned by HFS from hfs_vnop_readlink, not including
 *		additional error code which may be propagated from underlying
 *		routines.
 */
errno_t
VNOP_READLINK(struct vnode *vp, struct uio *uio, vfs_context_t ctx)
{
	int _err;
	struct vnop_readlink_args a;
#if CONFIG_DTRACE
	user_ssize_t resid = uio_resid(uio);
#endif
	a.a_desc = &vnop_readlink_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_readlink_desc.vdesc_offset])(&a);
	DTRACE_FSINFO_IO(readlink,
	    vnode_t, vp, user_ssize_t, (resid - uio_resid(uio)));

	return _err;
}

#if 0
/*
*#
*#% inactive     vp      L U U
*#
*/
struct vnop_inactive_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_INACTIVE(struct vnode *vp, vfs_context_t ctx)
{
	int _err;
	struct vnop_inactive_args a;

	a.a_desc = &vnop_inactive_desc;
	a.a_vp = vp;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_inactive_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(inactive, vnode_t, vp);

#if NAMEDSTREAMS
	/* For file systems that do not support namedstream natively, mark
	 * the shadow stream file vnode to be recycled as soon as the last
	 * reference goes away.  To avoid re-entering reclaim code, do not
	 * call recycle on terminating namedstream vnodes.
	 */
	if (vnode_isnamedstream(vp) &&
	    (vp->v_parent != NULLVP) &&
	    vnode_isshadow(vp) &&
	    ((vp->v_lflag & VL_TERMINATE) == 0)) {
		vnode_recycle(vp);
	}
#endif

	return _err;
}


#if 0
/*
*#
*#% reclaim      vp      U U U
*#
*/
struct vnop_reclaim_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_RECLAIM(struct vnode *vp, vfs_context_t ctx)
{
	int _err;
	struct vnop_reclaim_args a;

	a.a_desc = &vnop_reclaim_desc;
	a.a_vp = vp;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_reclaim_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(reclaim, vnode_t, vp);

	return _err;
}


/*
 * Returns:	0			Success
 *	lock_fsnode:ENOENT		No such file or directory [only for VFS
 *					 that is not thread safe & vnode is
 *					 currently being/has been terminated]
 *	<vnop_pathconf_desc>:???	[per FS implementation specific]
 */
#if 0
/*
*#
*#% pathconf     vp      L L L
*#
*/
struct vnop_pathconf_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	int a_name;
	int32_t *a_retval;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_PATHCONF(struct vnode *vp, int name, int32_t *retval, vfs_context_t ctx)
{
	int _err;
	struct vnop_pathconf_args a;

	a.a_desc = &vnop_pathconf_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_retval = retval;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_pathconf_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(pathconf, vnode_t, vp);

	return _err;
}

/*
 * Returns:	0			Success
 *	err_advlock:ENOTSUP
 *	lf_advlock:???
 *	<vnop_advlock_desc>:???
 *
 * Notes:	VFS implementations of advisory locking using calls through
 *		<vnop_advlock_desc> because lock enforcement does not occur
 *		locally should try to limit themselves to the return codes
 *		documented above for lf_advlock and err_advlock.
 */
#if 0
/*
*#
*#% advlock      vp      U U U
*#
*/
struct vnop_advlock_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	caddr_t a_id;
	int a_op;
	struct flock *a_fl;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_ADVLOCK(struct vnode *vp, caddr_t id, int op, struct flock *fl, int flags, vfs_context_t ctx, struct timespec *timeout)
{
	int _err;
	struct vnop_advlock_args a;

	a.a_desc = &vnop_advlock_desc;
	a.a_vp = vp;
	a.a_id = id;
	a.a_op = op;
	a.a_fl = fl;
	a.a_flags = flags;
	a.a_context = ctx;
	a.a_timeout = timeout;

	/* Disallow advisory locking on non-seekable vnodes */
	if (vnode_isfifo(vp)) {
		_err = err_advlock(&a);
	} else {
		if ((vp->v_flag & VLOCKLOCAL)) {
			/* Advisory locking done at this layer */
			_err = lf_advlock(&a);
		} else if (flags & F_OFD_LOCK) {
			/* Non-local locking doesn't work for OFD locks */
			_err = err_advlock(&a);
		} else {
			/* Advisory locking done by underlying filesystem */
			_err = (*vp->v_op[vnop_advlock_desc.vdesc_offset])(&a);
		}
		DTRACE_FSINFO(advlock, vnode_t, vp);
		if (op == F_UNLCK && flags == F_FLOCK) {
			post_event_if_success(vp, _err, NOTE_FUNLOCK);
		}
	}

	return _err;
}



#if 0
/*
*#
*#% allocate     vp      L L L
*#
*/
struct vnop_allocate_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	off_t a_length;
	u_int32_t a_flags;
	off_t *a_bytesallocated;
	off_t a_offset;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t
VNOP_ALLOCATE(struct vnode *vp, off_t length, u_int32_t flags, off_t *bytesallocated, off_t offset, vfs_context_t ctx)
{
	int _err;
	struct vnop_allocate_args a;

	a.a_desc = &vnop_allocate_desc;
	a.a_vp = vp;
	a.a_length = length;
	a.a_flags = flags;
	a.a_bytesallocated = bytesallocated;
	a.a_offset = offset;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_allocate_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(allocate, vnode_t, vp);
#if CONFIG_FSE
	if (_err == 0) {
		add_fsevent(FSE_STAT_CHANGED, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
	}
#endif

	return _err;
}

#if 0
/*
*#
*#% pagein       vp      = = =
*#
*/
struct vnop_pagein_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	upl_t a_pl;
	upl_offset_t a_pl_offset;
	off_t a_f_offset;
	size_t a_size;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_PAGEIN(struct vnode *vp, upl_t pl, upl_offset_t pl_offset, off_t f_offset, size_t size, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_pagein_args a;

	a.a_desc = &vnop_pagein_desc;
	a.a_vp = vp;
	a.a_pl = pl;
	a.a_pl_offset = pl_offset;
	a.a_f_offset = f_offset;
	a.a_size = size;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_pagein_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(pagein, vnode_t, vp);

	return _err;
}

#if 0
/*
*#
*#% pageout      vp      = = =
*#
*/
struct vnop_pageout_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	upl_t a_pl;
	upl_offset_t a_pl_offset;
	off_t a_f_offset;
	size_t a_size;
	int a_flags;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t
VNOP_PAGEOUT(struct vnode *vp, upl_t pl, upl_offset_t pl_offset, off_t f_offset, size_t size, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_pageout_args a;

	a.a_desc = &vnop_pageout_desc;
	a.a_vp = vp;
	a.a_pl = pl;
	a.a_pl_offset = pl_offset;
	a.a_f_offset = f_offset;
	a.a_size = size;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_pageout_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(pageout, vnode_t, vp);

	post_event_if_success(vp, _err, NOTE_WRITE);

	return _err;
}

int
vn_remove(vnode_t dvp, vnode_t *vpp, struct nameidata *ndp, int32_t flags, struct vnode_attr *vap, vfs_context_t ctx)
{
	if (vnode_compound_remove_available(dvp)) {
		return VNOP_COMPOUND_REMOVE(dvp, vpp, ndp, flags, vap, ctx);
	} else {
		return VNOP_REMOVE(dvp, *vpp, &ndp->ni_cnd, flags, ctx);
	}
}

#if CONFIG_SEARCHFS

#if 0
/*
*#
*#% searchfs     vp      L L L
*#
*/
struct vnop_searchfs_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	void *a_searchparams1;
	void *a_searchparams2;
	struct attrlist *a_searchattrs;
	uint32_t a_maxmatches;
	struct timeval *a_timelimit;
	struct attrlist *a_returnattrs;
	uint32_t *a_nummatches;
	uint32_t a_scriptcode;
	uint32_t a_options;
	struct uio *a_uio;
	struct searchstate *a_searchstate;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t
VNOP_SEARCHFS(struct vnode *vp, void *searchparams1, void *searchparams2, struct attrlist *searchattrs, uint32_t maxmatches, struct timeval *timelimit, struct attrlist *returnattrs, uint32_t *nummatches, uint32_t scriptcode, uint32_t options, struct uio *uio, struct searchstate *searchstate, vfs_context_t ctx)
{
	int _err;
	struct vnop_searchfs_args a;

	a.a_desc = &vnop_searchfs_desc;
	a.a_vp = vp;
	a.a_searchparams1 = searchparams1;
	a.a_searchparams2 = searchparams2;
	a.a_searchattrs = searchattrs;
	a.a_maxmatches = maxmatches;
	a.a_timelimit = timelimit;
	a.a_returnattrs = returnattrs;
	a.a_nummatches = nummatches;
	a.a_scriptcode = scriptcode;
	a.a_options = options;
	a.a_uio = uio;
	a.a_searchstate = searchstate;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_searchfs_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(searchfs, vnode_t, vp);

	return _err;
}
#endif /* CONFIG_SEARCHFS */

#if 0
/*
*#
*#% copyfile fvp U U U
*#% copyfile tdvp L U U
*#% copyfile tvp X U U
*#
*/
struct vnop_copyfile_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_fvp;
	vnode_t a_tdvp;
	vnode_t a_tvp;
	struct componentname *a_tcnp;
	int a_mode;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_COPYFILE(struct vnode *fvp, struct vnode *tdvp, struct vnode *tvp, struct componentname *tcnp,
    int mode, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_copyfile_args a;
	a.a_desc = &vnop_copyfile_desc;
	a.a_fvp = fvp;
	a.a_tdvp = tdvp;
	a.a_tvp = tvp;
	a.a_tcnp = tcnp;
	a.a_mode = mode;
	a.a_flags = flags;
	a.a_context = ctx;
	_err = (*fvp->v_op[vnop_copyfile_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(copyfile, vnode_t, fvp);
	return _err;
}

#if 0
struct vnop_clonefile_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_fvp;
	vnode_t a_dvp;
	vnode_t *a_vpp;
	struct componentname *a_cnp;
	struct vnode_attr *a_vap;
	uint32_t a_flags;
	vfs_context_t a_context;
	int (*a_dir_clone_authorizer)(  /* Authorization callback */
		struct vnode_attr *vap,         /* attribute to be authorized */
		kauth_action_t action,         /* action for which attribute is to be authorized */
		struct vnode_attr *dvap,         /* target directory attributes */
		vnode_t sdvp,         /* source directory vnode pointer (optional) */
		mount_t mp,         /* mount point of filesystem */
		dir_clone_authorizer_op_t vattr_op,         /* specific operation requested : setup, authorization or cleanup  */
		uint32_t flags;         /* value passed in a_flags to the VNOP */
		vfs_context_t ctx,                      /* As passed to VNOP */
		void *reserved);                        /* Always NULL */
	void *a_reserved;               /* Currently unused */
};
#endif /* 0 */

errno_t
VNOP_CLONEFILE(vnode_t fvp, vnode_t dvp, vnode_t *vpp,
    struct componentname *cnp, struct vnode_attr *vap, uint32_t flags,
    vfs_context_t ctx)
{
	int _err;
	struct vnop_clonefile_args a;
	a.a_desc = &vnop_clonefile_desc;
	a.a_fvp = fvp;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_flags = flags;
	a.a_context = ctx;

	if (vnode_vtype(fvp) == VDIR) {
		a.a_dir_clone_authorizer = vnode_attr_authorize_dir_clone;
	} else {
		a.a_dir_clone_authorizer = NULL;
	}

	_err = (*dvp->v_op[vnop_clonefile_desc.vdesc_offset])(&a);

	if (_err == 0 && *vpp) {
		DTRACE_FSINFO(clonefile, vnode_t, *vpp);
		if (kdebug_enable) {
			kdebug_lookup(*vpp, cnp);
		}
	}

	post_event_if_success(dvp, _err, NOTE_WRITE);

	return _err;
}

errno_t
VNOP_GETXATTR(vnode_t vp, const char *name, uio_t uio, size_t *size, int options, vfs_context_t ctx)
{
	struct vnop_getxattr_args a;
	int error;

	a.a_desc = &vnop_getxattr_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_uio = uio;
	a.a_size = size;
	a.a_options = options;
	a.a_context = ctx;

	error = (*vp->v_op[vnop_getxattr_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(getxattr, vnode_t, vp);

	return error;
}

errno_t
VNOP_SETXATTR(vnode_t vp, const char *name, uio_t uio, int options, vfs_context_t ctx)
{
	struct vnop_setxattr_args a;
	int error;

	a.a_desc = &vnop_setxattr_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_uio = uio;
	a.a_options = options;
	a.a_context = ctx;

	error = (*vp->v_op[vnop_setxattr_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(setxattr, vnode_t, vp);

	if (error == 0) {
		vnode_uncache_authorized_action(vp, KAUTH_INVALIDATE_CACHED_RIGHTS);
	}

	post_event_if_success(vp, error, NOTE_ATTRIB);

	return error;
}

errno_t
VNOP_REMOVEXATTR(vnode_t vp, const char *name, int options, vfs_context_t ctx)
{
	struct vnop_removexattr_args a;
	int error;

	a.a_desc = &vnop_removexattr_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_options = options;
	a.a_context = ctx;

	error = (*vp->v_op[vnop_removexattr_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(removexattr, vnode_t, vp);

	post_event_if_success(vp, error, NOTE_ATTRIB);

	return error;
}

errno_t
VNOP_LISTXATTR(vnode_t vp, uio_t uio, size_t *size, int options, vfs_context_t ctx)
{
	struct vnop_listxattr_args a;
	int error;

	a.a_desc = &vnop_listxattr_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_size = size;
	a.a_options = options;
	a.a_context = ctx;

	error = (*vp->v_op[vnop_listxattr_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(listxattr, vnode_t, vp);

	return error;
}


#if 0
/*
*#
*#% blktooff vp = = =
*#
*/
struct vnop_blktooff_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	daddr64_t a_lblkno;
	off_t *a_offset;
};
#endif /* 0*/
errno_t
VNOP_BLKTOOFF(struct vnode *vp, daddr64_t lblkno, off_t *offset)
{
	int _err;
	struct vnop_blktooff_args a;

	a.a_desc = &vnop_blktooff_desc;
	a.a_vp = vp;
	a.a_lblkno = lblkno;
	a.a_offset = offset;

	_err = (*vp->v_op[vnop_blktooff_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(blktooff, vnode_t, vp);

	return _err;
}

#if 0
/*
*#
*#% offtoblk vp = = =
*#
*/
struct vnop_offtoblk_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	off_t a_offset;
	daddr64_t *a_lblkno;
};
#endif /* 0*/
errno_t
VNOP_OFFTOBLK(struct vnode *vp, off_t offset, daddr64_t *lblkno)
{
	int _err;
	struct vnop_offtoblk_args a;

	a.a_desc = &vnop_offtoblk_desc;
	a.a_vp = vp;
	a.a_offset = offset;
	a.a_lblkno = lblkno;

	_err = (*vp->v_op[vnop_offtoblk_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(offtoblk, vnode_t, vp);

	return _err;
}

#if 0
/*
*#
*#% blockmap vp L L L
*#
*/
struct vnop_blockmap_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	off_t a_foffset;
	size_t a_size;
	daddr64_t *a_bpn;
	size_t *a_run;
	void *a_poff;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_BLOCKMAP(struct vnode *vp, off_t foffset, size_t size, daddr64_t *bpn, size_t *run, void *poff, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_blockmap_args a;
	size_t localrun = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_blockmap_desc;
	a.a_vp = vp;
	a.a_foffset = foffset;
	a.a_size = size;
	a.a_bpn = bpn;
	a.a_run = &localrun;
	a.a_poff = poff;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_blockmap_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(blockmap, vnode_t, vp);

	/*
	 * We used a local variable to request information from the underlying
	 * filesystem about the length of the I/O run in question.  If
	 * we get malformed output from the filesystem, we cap it to the length
	 * requested, at most.  Update 'run' on the way out.
	 */
	if (_err == 0) {
		if (localrun > size) {
			localrun = size;
		}

		if (run) {
			*run = localrun;
		}
	}

	return _err;
}

#if 0
struct vnop_strategy_args {
	struct vnodeop_desc *a_desc;
	struct buf *a_bp;
};

#endif /* 0*/
errno_t
VNOP_STRATEGY(struct buf *bp)
{
	int _err;
	struct vnop_strategy_args a;
	vnode_t vp = buf_vnode(bp);
	a.a_desc = &vnop_strategy_desc;
	a.a_bp = bp;
	_err = (*vp->v_op[vnop_strategy_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(strategy, vnode_t, vp);
	return _err;
}

#if 0
struct vnop_bwrite_args {
	struct vnodeop_desc *a_desc;
	buf_t a_bp;
};
#endif /* 0*/
errno_t
VNOP_BWRITE(struct buf *bp)
{
	int _err;
	struct vnop_bwrite_args a;
	vnode_t vp = buf_vnode(bp);
	a.a_desc = &vnop_bwrite_desc;
	a.a_bp = bp;
	_err = (*vp->v_op[vnop_bwrite_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(bwrite, vnode_t, vp);
	return _err;
}

#if 0
struct vnop_kqfilt_add_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct knote *a_kn;
	vfs_context_t a_context;
};
#endif
errno_t
VNOP_KQFILT_ADD(struct vnode *vp, struct knote *kn, vfs_context_t ctx)
{
	int _err;
	struct vnop_kqfilt_add_args a;

	a.a_desc = VDESC(vnop_kqfilt_add);
	a.a_vp = vp;
	a.a_kn = kn;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_kqfilt_add_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(kqfilt_add, vnode_t, vp);

	return _err;
}

#if 0
struct vnop_kqfilt_remove_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	uintptr_t a_ident;
	vfs_context_t a_context;
};
#endif
errno_t
VNOP_KQFILT_REMOVE(struct vnode *vp, uintptr_t ident, vfs_context_t ctx)
{
	int _err;
	struct vnop_kqfilt_remove_args a;

	a.a_desc = VDESC(vnop_kqfilt_remove);
	a.a_vp = vp;
	a.a_ident = ident;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_kqfilt_remove_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(kqfilt_remove, vnode_t, vp);

	return _err;
}

errno_t
VNOP_MONITOR(vnode_t vp, uint32_t events, uint32_t flags, void *handle, vfs_context_t ctx)
{
	int _err;
	struct vnop_monitor_args a;

	a.a_desc = VDESC(vnop_monitor);
	a.a_vp = vp;
	a.a_events = events;
	a.a_flags = flags;
	a.a_handle = handle;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_monitor_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(monitor, vnode_t, vp);

	return _err;
}

#if 0
struct vnop_setlabel_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct label *a_vl;
	vfs_context_t a_context;
};
#endif
errno_t
VNOP_SETLABEL(struct vnode *vp, struct label *label, vfs_context_t ctx)
{
	int _err;
	struct vnop_setlabel_args a;

	a.a_desc = VDESC(vnop_setlabel);
	a.a_vp = vp;
	a.a_vl = label;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_setlabel_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(setlabel, vnode_t, vp);

	return _err;
}


#if NAMEDSTREAMS
/*
 * Get a named streamed
 */
errno_t
VNOP_GETNAMEDSTREAM(vnode_t vp, vnode_t *svpp, const char *name, enum nsoperation operation, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_getnamedstream_args a;

	a.a_desc = &vnop_getnamedstream_desc;
	a.a_vp = vp;
	a.a_svpp = svpp;
	a.a_name = name;
	a.a_operation = operation;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_getnamedstream_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(getnamedstream, vnode_t, vp);
	return _err;
}

/*
 * Create a named streamed
 */
errno_t
VNOP_MAKENAMEDSTREAM(vnode_t vp, vnode_t *svpp, const char *name, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_makenamedstream_args a;

	a.a_desc = &vnop_makenamedstream_desc;
	a.a_vp = vp;
	a.a_svpp = svpp;
	a.a_name = name;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_makenamedstream_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(makenamedstream, vnode_t, vp);
	return _err;
}


/*
 * Remove a named streamed
 */
errno_t
VNOP_REMOVENAMEDSTREAM(vnode_t vp, vnode_t svp, const char *name, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_removenamedstream_args a;

	a.a_desc = &vnop_removenamedstream_desc;
	a.a_vp = vp;
	a.a_svp = svp;
	a.a_name = name;
	a.a_flags = flags;
	a.a_context = ctx;

	_err = (*vp->v_op[vnop_removenamedstream_desc.vdesc_offset])(&a);
	DTRACE_FSINFO(removenamedstream, vnode_t, vp);
	return _err;
}
#endif
