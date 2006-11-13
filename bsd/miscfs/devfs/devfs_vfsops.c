/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*-
 * Copyright 1997,1998 Julian Elischer.  All rights reserved.
 * julian@freebsd.org
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * devfs_vfsops.c
 *
 */
/*
 * HISTORY
 *  Dieter Siegmund (dieter@apple.com) Wed Jul 14 13:37:59 PDT 1999
 *  - modified devfs_statfs() to use devfs_stats to calculate the
 *    amount of memory used by devfs
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/vnode_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/mount_internal.h>
#include <sys/malloc.h>

#include "devfs.h"
#include "devfsdefs.h"

static int devfs_statfs( struct mount *mp, struct vfsstatfs *sbp, vfs_context_t context);
static int devfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t context);

static struct vfstable * devfs_vfsp = 0;


/*-
 * Called from the generic VFS startups.
 * This is the second stage of DEVFS initialisation.
 * The probed devices have already been loaded and the 
 * basic structure of the DEVFS created.
 * We take the oportunity to mount the hidden DEVFS layer, so that
 * devices from devfs get sync'd.
 */
static int
devfs_init(struct vfsconf *vfsp)
{
    devfs_vfsp = (struct vfstable *)vfsp; /* remember this for devfs_kernel_mount below */

    if (devfs_sinit())
	return (ENOTSUP);
    devfs_make_node(makedev(0, 0), DEVFS_CHAR, 
		    UID_ROOT, GID_WHEEL, 0622, "console");
    devfs_make_node(makedev(2, 0), DEVFS_CHAR, 
		    UID_ROOT, GID_WHEEL, 0666, "tty");
    devfs_make_node(makedev(3, 0), DEVFS_CHAR, 
		    UID_ROOT, GID_KMEM, 0640, "mem");
    devfs_make_node(makedev(3, 1), DEVFS_CHAR, 
		    UID_ROOT, GID_KMEM, 0640, "kmem");
    devfs_make_node(makedev(3, 2), DEVFS_CHAR, 
		    UID_ROOT, GID_WHEEL, 0666, "null");
    devfs_make_node(makedev(3, 3), DEVFS_CHAR, 
		    UID_ROOT, GID_WHEEL, 0666, "zero");
    devfs_make_node(makedev(6, 0), DEVFS_CHAR, 
		    UID_ROOT, GID_WHEEL, 0600, "klog");
    return 0;
}

/*-
 *  mp	 - pointer to 'mount' structure
 *  path - addr in user space of mount point (ie /usr or whatever)
 *  data - addr in user space of mount params including the
 *         name of the block special file to treat as a filesystem.
 *         (NOT USED)
 *  ndp  - namei data pointer (NOT USED)
 *  p    - proc pointer
 * devfs is special in that it doesn't require any device to be mounted..
 * It makes up its data as it goes along.
 * it must be mounted during single user.. until it is, only std{in/out/err}
 * and the root filesystem are available.
 */
/*proto*/
int
devfs_mount(struct mount *mp, __unused vnode_t devvp, __unused user_addr_t data, vfs_context_t context)
{
	struct devfsmount *devfs_mp_p;	/* devfs specific mount info */
	int error;

	/*-
	 *  If they just want to update, we don't need to do anything.
	 */
	if (mp->mnt_flag & MNT_UPDATE)
	{
		return 0;
	}

	/* Advisory locking should be handled at the VFS layer */
	vfs_setlocklocal(mp);

	/*-
	 *  Well, it's not an update, it's a real mount request.
	 *  Time to get dirty.
	 * HERE we should check to see if we are already mounted here.
	 */

	MALLOC(devfs_mp_p, struct devfsmount *, sizeof(struct devfsmount),
	       M_DEVFSMNT, M_WAITOK);
	if (devfs_mp_p == NULL)
		return (ENOMEM);
	bzero(devfs_mp_p,sizeof(*devfs_mp_p));
	devfs_mp_p->mount = mp;

	/*-
	 *  Fill out some fields
	 */
	mp->mnt_data = (qaddr_t)devfs_mp_p;
	mp->mnt_vfsstat.f_fsid.val[0] = (int32_t)(void *)devfs_mp_p;
	mp->mnt_vfsstat.f_fsid.val[1] = vfs_typenum(mp);
	mp->mnt_flag |= MNT_LOCAL;

	DEVFS_LOCK();
	error = dev_dup_plane(devfs_mp_p);
	DEVFS_UNLOCK();

	if (error) {
		mp->mnt_data = (qaddr_t)0;
		FREE((caddr_t)devfs_mp_p, M_DEVFSMNT);
		return (error);
	} else
	        DEVFS_INCR_MOUNTS();

	/*-
	 *  Copy in the name of the directory the filesystem
	 *  is to be mounted on.
	 *  And we clear the remainder of the character strings
	 *  to be tidy.
	 */
	
	bzero(mp->mnt_vfsstat.f_mntfromname, MAXPATHLEN);
	bcopy("devfs",mp->mnt_vfsstat.f_mntfromname, 5);
	(void)devfs_statfs(mp, &mp->mnt_vfsstat, context);

	return 0;
}


static int
devfs_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t context)
{
	return 0;
}

/*-
 *  Unmount the filesystem described by mp.
 */
static int
devfs_unmount( struct mount *mp, int mntflags, __unused vfs_context_t context)
{
	struct devfsmount *devfs_mp_p = (struct devfsmount *)mp->mnt_data;
	int flags = 0;
	int force = 0;
	int error;
	
	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
		force = 1;
	}
	error = vflush(mp, NULLVP, flags);
	if (error && !force)
		return error;

	DEVFS_LOCK();
	devfs_free_plane(devfs_mp_p);
	DEVFS_UNLOCK();

	DEVFS_DECR_MOUNTS();

	FREE((caddr_t)devfs_mp_p, M_DEVFSMNT);
	mp->mnt_data = (qaddr_t)0;
	mp->mnt_flag &= ~MNT_LOCAL;

	return 0;
}

/* return the address of the root vnode  in *vpp */
static int
devfs_root(struct mount *mp, struct vnode **vpp, vfs_context_t context)
{
	struct devfsmount *devfs_mp_p = (struct devfsmount *)(mp->mnt_data);
	int error;

	DEVFS_LOCK();
	error = devfs_dntovn(devfs_mp_p->plane_root->de_dnp, vpp, context->vc_proc);
	DEVFS_UNLOCK();

	return error;
}

static int
devfs_statfs( struct mount *mp, struct vfsstatfs *sbp, __unused vfs_context_t context)
{
	struct devfsmount *devfs_mp_p = (struct devfsmount *)mp->mnt_data;

	/*-
	 *  Fill in the stat block.
	 */
	//sbp->f_type   = mp->mnt_vfsstat.f_type;
	sbp->f_flags  = 0;		/* XXX */
	sbp->f_bsize  = 512;
	sbp->f_iosize = 512;
	sbp->f_blocks = (devfs_stats.mounts * sizeof(struct devfsmount)
			 + devfs_stats.nodes * sizeof(devnode_t)
			 + devfs_stats.entries * sizeof(devdirent_t)
			 + devfs_stats.stringspace
			 ) / sbp->f_bsize;
	sbp->f_bfree  = 0;
	sbp->f_bavail = 0;
	sbp->f_files  = devfs_stats.nodes;
	sbp->f_ffree  = 0;
	sbp->f_fsid.val[0] = (int32_t)(void *)devfs_mp_p;
	sbp->f_fsid.val[1] = vfs_typenum(mp);

	return 0;
}

static int
devfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t context)
{
	VFSATTR_RETURN(fsap, f_objcount, devfs_stats.nodes);
	VFSATTR_RETURN(fsap, f_maxobjcount, devfs_stats.nodes);
	VFSATTR_RETURN(fsap, f_bsize, 512);
	VFSATTR_RETURN(fsap, f_iosize, 512);
	if (VFSATTR_IS_ACTIVE(fsap, f_blocks) || VFSATTR_IS_ACTIVE(fsap, f_bused)) {
		fsap->f_blocks = (devfs_stats.mounts * sizeof(struct devfsmount)
			 + devfs_stats.nodes * sizeof(devnode_t)
			 + devfs_stats.entries * sizeof(devdirent_t)
			 + devfs_stats.stringspace
			 ) / fsap->f_bsize;
		fsap->f_bused = fsap->f_blocks;
		VFSATTR_SET_SUPPORTED(fsap, f_blocks);
		VFSATTR_SET_SUPPORTED(fsap, f_bused);
	}
	VFSATTR_RETURN(fsap, f_bfree, 0);
	VFSATTR_RETURN(fsap, f_bavail, 0);
	VFSATTR_RETURN(fsap, f_files, devfs_stats.nodes);
	VFSATTR_RETURN(fsap, f_ffree, 0);
	VFSATTR_RETURN(fsap, f_fssubtype, 0);
	
	return 0;
}

static int
devfs_sync(__unused struct mount *mp, __unused int waitfor, __unused vfs_context_t context)
{
    return (0);
}


static int
devfs_vget(__unused struct mount *mp, __unused ino64_t ino, __unused struct vnode **vpp, __unused vfs_context_t context)
{
	return ENOTSUP;
}

/*************************************************************
 * The concept of exporting a kernel generated devfs is stupid
 * So don't handle filehandles
 */

static int
devfs_fhtovp (__unused struct mount *mp, __unused int fhlen, __unused unsigned char *fhp, __unused struct vnode **vpp, __unused vfs_context_t context)
{
	return (EINVAL);
}


static int
devfs_vptofh (__unused struct vnode *vp, __unused int *fhlenp, __unused unsigned char *fhp, __unused vfs_context_t context)
{
	return (EINVAL);
}

static int
devfs_sysctl(__unused int *name, __unused u_int namelen, __unused user_addr_t oldp, 
             __unused size_t *oldlenp, __unused user_addr_t newp, 
             __unused size_t newlen, __unused vfs_context_t context)
{
    return (ENOTSUP);
}

#include <sys/namei.h>

/*
 * Function: devfs_kernel_mount
 * Purpose:
 *   Mount devfs at the given mount point from within the kernel.
 */
int
devfs_kernel_mount(char * mntname)
{
	struct mount *mp;
	int error;
	struct nameidata nd;
	struct vnode  * vp;
	struct vfs_context context;

	if (devfs_vfsp == NULL) {
	    printf("devfs_kernel_mount: devfs_vfsp is NULL\n");
	    return (EINVAL);
	}
	context.vc_proc = current_proc();
	context.vc_ucred = kauth_cred_get();

	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE32,
	    CAST_USER_ADDR_T(mntname), &context);
	if ((error = namei(&nd))) {
	    printf("devfs_kernel_mount: failed to find directory '%s', %d", 
		   mntname, error);
	    return (error);
	}
	nameidone(&nd);
	vp = nd.ni_vp;

	if ((error = VNOP_FSYNC(vp, MNT_WAIT, &context))) {
	    printf("devfs_kernel_mount: vnop_fsync failed: %d\n", error);
	    vnode_put(vp);
	    return (error);
	}
	if ((error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0))) {
	    printf("devfs_kernel_mount: buf_invalidateblks failed: %d\n", error);
	    vnode_put(vp);
	    return (error);
	}
	if (vnode_isdir(vp) == 0) {
	    printf("devfs_kernel_mount: '%s' is not a directory\n", mntname);
	    vnode_put(vp);
	    return (ENOTDIR);
	}
	if ((vnode_mountedhere(vp))) {
	    vnode_put(vp);
	    return (EBUSY);
	}

	/*
	 * Allocate and initialize the filesystem.
	 */
	MALLOC_ZONE(mp, struct mount *, (u_long)sizeof(struct mount),
		M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));

	/* Initialize the default IO constraints */
	mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
	mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;

	mount_lock_init(mp);
	TAILQ_INIT(&mp->mnt_vnodelist);
	TAILQ_INIT(&mp->mnt_workerqueue);
	TAILQ_INIT(&mp->mnt_newvnodes);

	(void)vfs_busy(mp, LK_NOWAIT);
	mp->mnt_op = devfs_vfsp->vfc_vfsops;
	mp->mnt_vtable = devfs_vfsp;
	devfs_vfsp->vfc_refcount++;
	devfs_vfsp->vfc_threadsafe = TRUE;
	devfs_vfsp->vfc_64bitready = TRUE;
	mp->mnt_flag = 0;
	mp->mnt_flag |= devfs_vfsp->vfc_flags & MNT_VISFLAGMASK;
	strncpy(mp->mnt_vfsstat.f_fstypename, devfs_vfsp->vfc_name, MFSTYPENAMELEN);
	vp->v_mountedhere = mp;
	mp->mnt_vnodecovered = vp;
	mp->mnt_vfsstat.f_owner = kauth_cred_getuid(kauth_cred_get());
	(void) copystr(mntname, mp->mnt_vfsstat.f_mntonname, MAXPATHLEN - 1, 0);

	error = devfs_mount(mp, NULL, NULL, &context);

	if (error) {
	    printf("devfs_kernel_mount: mount %s failed: %d", mntname, error);
	    mp->mnt_vtable->vfc_refcount--;

	    vfs_unbusy(mp);

	    mount_lock_destroy(mp);
	    FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
	    vnode_put(vp);
	    return (error);
	}
	vnode_ref(vp);
	vnode_put(vp);
	vfs_unbusy(mp);
	mount_list_add(mp);
	return (0);
}

struct vfsops devfs_vfsops = {
	devfs_mount,
	devfs_start,
	devfs_unmount,
	devfs_root,
	NULL,				/* quotactl */
	devfs_vfs_getattr,
	devfs_sync,
	devfs_vget,
	devfs_fhtovp,
	devfs_vptofh,
	devfs_init,
	devfs_sysctl
};
