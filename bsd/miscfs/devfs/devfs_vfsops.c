/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/malloc.h>

#include "devfs.h"
#include "devfsdefs.h"

static int devfs_statfs( struct mount *mp, struct statfs *sbp, struct proc *p);

static struct vfsconf * devfs_vfsp = 0;
static int 		kernel_mount = 0;


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
    devfs_vfsp = vfsp; /* remember this for devfs_kernel_mount below */

    if (devfs_sinit())
	return (EOPNOTSUPP);
    printf("devfs enabled\n");
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
devfs_mount(struct mount *mp, char *path, caddr_t data,
	    struct nameidata *ndp, struct proc *p)
{
	struct devfsmount *devfs_mp_p;	/* devfs specific mount info */
	int error;
	size_t size;

	/*-
	 *  If they just want to update, we don't need to do anything.
	 */
	if (mp->mnt_flag & MNT_UPDATE)
	{
		return 0;
	}

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
	mp->mnt_stat.f_type = mp->mnt_vfc->vfc_typenum;
	mp->mnt_stat.f_fsid.val[0] = (int32_t)(void *)devfs_mp_p;
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_stat.f_type;
	mp->mnt_flag |= MNT_LOCAL;

	DEVFS_LOCK(p);
	error = dev_dup_plane(devfs_mp_p);
	DEVFS_UNLOCK(p);
	if (error) {
		mp->mnt_data = (qaddr_t)0;
		FREE((caddr_t)devfs_mp_p, M_DEVFSMNT);
		return (error);
	}

	/*-
	 *  Copy in the name of the directory the filesystem
	 *  is to be mounted on.
	 *  And we clear the remainder of the character strings
	 *  to be tidy.
	 */
	
	if (!kernel_mount) {
		copyinstr(path, (caddr_t)mp->mnt_stat.f_mntonname,
			sizeof(mp->mnt_stat.f_mntonname)-1, &size);
		bzero(mp->mnt_stat.f_mntonname + size,
			sizeof(mp->mnt_stat.f_mntonname) - size);
	}
	bzero(mp->mnt_stat.f_mntfromname, MNAMELEN);
	bcopy("devfs",mp->mnt_stat.f_mntfromname, 5);
	DEVFS_INCR_MOUNTS();
	(void)devfs_statfs(mp, &mp->mnt_stat, p);
	return 0;
}


static int
devfs_start(struct mount *mp, int flags, struct proc *p)
{
	return 0;
}

/*-
 *  Unmount the filesystem described by mp.
 */
static int
devfs_unmount( struct mount *mp, int mntflags, struct proc *p)
{
	struct devfsmount *devfs_mp_p = (struct devfsmount *)mp->mnt_data;
	int flags = 0;
	int error;
	
	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
	}
	error = vflush(mp, NULLVP, flags);
	if (error)
		return error;

	DEVFS_LOCK(p);
	devfs_free_plane(devfs_mp_p);
	DEVFS_UNLOCK(p);
	FREE((caddr_t)devfs_mp_p, M_DEVFSMNT);
	DEVFS_DECR_MOUNTS();
	mp->mnt_data = (qaddr_t)0;
	mp->mnt_flag &= ~MNT_LOCAL;

	return 0;
}

/* return the address of the root vnode  in *vpp */
static int
devfs_root(struct mount *mp, struct vnode **vpp)
{
	struct devfsmount *devfs_mp_p = (struct devfsmount *)(mp->mnt_data);
	int error;

	error = devfs_dntovn(devfs_mp_p->plane_root->de_dnp,vpp, 
			     current_proc());
	return error;
}

static int
devfs_quotactl(struct mount *mp, int cmds, uid_t uid, caddr_t arg,
	       struct proc *p)
{
	return EOPNOTSUPP;
}

static int
devfs_statfs( struct mount *mp, struct statfs *sbp, struct proc *p)
{
	struct devfsmount *devfs_mp_p = (struct devfsmount *)mp->mnt_data;

	/*-
	 *  Fill in the stat block.
	 */
	sbp->f_type   = mp->mnt_stat.f_type;
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
	sbp->f_fsid.val[1] = mp->mnt_stat.f_type;

	/*-
	 *  Copy the mounted on and mounted from names into
	 *  the passed in stat block, if it is not the one
	 *  in the mount structure.
	 */
	if (sbp != &mp->mnt_stat) {
		bcopy((caddr_t)mp->mnt_stat.f_mntonname,
			(caddr_t)&sbp->f_mntonname[0], MNAMELEN);
		bcopy((caddr_t)mp->mnt_stat.f_mntfromname,
			(caddr_t)&sbp->f_mntfromname[0], MNAMELEN);
	}
	return 0;
}

static int
devfs_sync(struct mount *mp, int waitfor,struct ucred *cred,struct proc *p)
{
    return (0);
}


static int
devfs_vget(struct mount *mp, void * ino,struct vnode **vpp)
{
	return EOPNOTSUPP;
}

/*************************************************************
 * The concept of exporting a kernel generated devfs is stupid
 * So don't handle filehandles
 */

static int
devfs_fhtovp (struct mount *mp, struct fid *fhp, struct mbuf *nam,
	      struct vnode **vpp, int *exflagsp, struct ucred **credanonp)
{
	return (EINVAL);
}


static int
devfs_vptofh (struct vnode *vp, struct fid *fhp)
{
	return (EINVAL);
}

static int
devfs_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
    return (EOPNOTSUPP);
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
	struct proc *procp;
	struct nameidata nd;
	struct vnode  * vp;

	if (devfs_vfsp == NULL) {
	    printf("devfs_kernel_mount: devfs_vfsp is NULL\n");
	    return (EINVAL);
	}
	procp = current_proc();

	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE,
	    mntname, procp);
	if ((error = namei(&nd))) {
	    printf("devfs_kernel_mount: failed to find directory '%s', %d", 
		   mntname, error);
	    return (error);
	}
	vp = nd.ni_vp;
	if ((error = vinvalbuf(vp, V_SAVE, procp->p_ucred, procp, 0, 0))) {
	    printf("devfs_kernel_mount: vinval failed: %d\n", error);
	    vput(vp);
	    return (error);
	}
	if (vp->v_type != VDIR) {
	    printf("devfs_kernel_mount: '%s' is not a directory\n", mntname);
	    vput(vp);
	    return (ENOTDIR);
	}
	if (vp->v_mountedhere != NULL) {
	    vput(vp);
	    return (EBUSY);
	}

	/*
	 * Allocate and initialize the filesystem.
	 */
	mp = _MALLOC_ZONE((u_long)sizeof(struct mount), M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));

    /* Initialize the default IO constraints */
    mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
    mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;

	lockinit(&mp->mnt_lock, PVFS, "vfslock", 0, 0);
	(void)vfs_busy(mp, LK_NOWAIT, 0, procp);
	LIST_INIT(&mp->mnt_vnodelist);
	mp->mnt_op = devfs_vfsp->vfc_vfsops;
	mp->mnt_vfc = devfs_vfsp;
	devfs_vfsp->vfc_refcount++;
	mp->mnt_flag = 0;
	mp->mnt_flag |= devfs_vfsp->vfc_flags & MNT_VISFLAGMASK;
	strncpy(mp->mnt_stat.f_fstypename, devfs_vfsp->vfc_name, MFSNAMELEN);
	vp->v_mountedhere = mp;
	mp->mnt_vnodecovered = vp;
	mp->mnt_stat.f_owner = procp->p_ucred->cr_uid;
	(void) copystr(mntname, mp->mnt_stat.f_mntonname, MNAMELEN - 1, 0);

	kernel_mount = 1;
	error = devfs_mount(mp, mntname, NULL, NULL, procp);
	kernel_mount = 0;
	if (error) {
	    printf("devfs_kernel_mount: mount %s failed: %d", mntname, error);
	    mp->mnt_vfc->vfc_refcount--;
	    vfs_unbusy(mp, procp);
	    _FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
	    vput(vp);
	    return (error);
	}
	printf("devfs on %s\n", mntname);
	simple_lock(&mountlist_slock);
	CIRCLEQ_INSERT_TAIL(&mountlist, mp, mnt_list);
	simple_unlock(&mountlist_slock);
	VOP_UNLOCK(vp, 0, procp);
	vfs_unbusy(mp, procp);
	return (0);
}

struct vfsops devfs_vfsops = {
	devfs_mount,
	devfs_start,
	devfs_unmount,
	devfs_root,
	devfs_quotactl,
	devfs_statfs,
	devfs_sync,
	devfs_vget,
	devfs_fhtovp,
	devfs_vptofh,
	devfs_init,
	devfs_sysctl,
};
