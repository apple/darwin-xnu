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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1990, 1993, 1994
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
 *	@(#)mfs_vfsops.c	8.4 (Berkeley) 4/16/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/signalvar.h>
#include <sys/vnode.h>
#include <sys/malloc.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>

#include <ufs/mfs/mfsnode.h>
#include <ufs/mfs/mfs_extern.h>

caddr_t	mfs_rootbase;	/* address of mini-root in kernel virtual memory */
u_long	mfs_rootsize;	/* size of mini-root in bytes */

static	int mfs_minor;	/* used for building internal dev_t */

extern int (**mfs_vnodeop_p)(void *);

/*
 * mfs vfs operations.
 */
struct vfsops mfs_vfsops = {
	MOUNT_MFS,
	mfs_mount,
	mfs_start,
	ffs_unmount,
	ufs_root,
	ufs_quotactl,
	mfs_statfs,
	ffs_sync,
	ffs_vget,
	ffs_fhtovp,
	ffs_vptofh,
	mfs_init,
};

/*
 * Called by main() when mfs is going to be mounted as root.
 *
 * Name is updated by mount(8) after booting.
 */
#define ROOTNAME	"mfs_root"

mfs_mountroot()
{
	extern struct vnode *rootvp;
	register struct fs *fs;
	register struct mount *mp;
	struct proc *p = kernel_proc;	/* XXX - WMG*/
	struct ufsmount *ump;
	struct mfsnode *mfsp;
	size_t size;
	int error;

	/*
	 * Get vnodes for swapdev and rootdev.
	 */
#if 0
	if (bdevvp(swapdev, &swapdev_vp) || bdevvp(rootdev, &rootvp))
		panic("mfs_mountroot: can't setup bdevvp's");
#else
	if ( bdevvp(rootdev, &rootvp))
		panic("mfs_mountroot: can't setup bdevvp's");

#endif
	MALLOC_ZONE(mp, struct mount *,
			sizeof(struct mount), M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));

    /* Initialize the default IO constraints */
    mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
    mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;

	mp->mnt_op = &mfs_vfsops;
	mp->mnt_flag = MNT_RDONLY;
	MALLOC(mfsp, struct mfsnode *, sizeof(struct mfsnode), M_MFSNODE, M_WAITOK);
	rootvp->v_data = mfsp;
	rootvp->v_op = mfs_vnodeop_p;
	rootvp->v_tag = VT_MFS;
	mfsp->mfs_baseoff = mfs_rootbase;
	mfsp->mfs_size = mfs_rootsize;
	mfsp->mfs_vnode = rootvp;
	mfsp->mfs_pid = p->p_pid;
	mfsp->mfs_buflist = (struct buf *)0;
	if (error = ffs_mountfs(rootvp, mp, p)) {
		_FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
		_FREE(mfsp, M_MFSNODE);
		return (error);
	}
	if (error = vfs_lock(mp)) {
		(void)ffs_unmount(mp, 0, p);
		_FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
		_FREE(mfsp, M_MFSNODE);
		return (error);
	}
	CIRCLEQ_INSERT_TAIL(&mountlist, mp, mnt_list);
	mp->mnt_vnodecovered = NULLVP;
	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	bzero(fs->fs_fsmnt, sizeof(fs->fs_fsmnt));
	fs->fs_fsmnt[0] = '/';
	bcopy(fs->fs_fsmnt, mp->mnt_stat.f_mntonname, MNAMELEN);
	(void) copystr(ROOTNAME, mp->mnt_stat.f_mntfromname, MNAMELEN - 1,
	    &size);
	bzero(mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
	(void)ffs_statfs(mp, &mp->mnt_stat, p);
	vfs_unlock(mp);
	inittodr((time_t)0);
	return (0);
}

/*
 * This is called early in boot to set the base address and size
 * of the mini-root.
 */
mfs_initminiroot(base)
	caddr_t base;
{
	struct fs *fs = (struct fs *)(base + SBOFF);
	extern int (*mountroot)();

	/* check for valid super block */
	if (fs->fs_magic != FS_MAGIC || fs->fs_bsize > MAXBSIZE ||
	    fs->fs_bsize < sizeof(struct fs))
		return (0);
	mountroot = mfs_mountroot;
	mfs_rootbase = base;
	mfs_rootsize = fs->fs_fsize * fs->fs_size;
	rootdev = makedev(255, mfs_minor++);
	return (mfs_rootsize);
}

/*
 * VFS Operations.
 *
 * mount system call
 */
/* ARGSUSED */
int
mfs_mount(mp, path, data, ndp, p)
	register struct mount *mp;
	char *path;
	caddr_t data;
	struct nameidata *ndp;
	struct proc *p;
{
	struct vnode *devvp;
	struct mfs_args args;
	struct ufsmount *ump;
	register struct fs *fs;
	register struct mfsnode *mfsp;
	size_t size;
	int flags, error;

	if (error = copyin(data, (caddr_t)&args, sizeof (struct mfs_args)))
		return (error);

	/*
	 * If updating, check whether changing from read-only to
	 * read/write; if there is no device name, that's all we do.
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		ump = VFSTOUFS(mp);
		fs = ump->um_fs;
		if (fs->fs_ronly == 0 && (mp->mnt_flag & MNT_RDONLY)) {
			flags = WRITECLOSE;
			if (mp->mnt_flag & MNT_FORCE)
				flags |= FORCECLOSE;
			if (vfs_busy(mp))
				return (EBUSY);
			error = ffs_flushfiles(mp, flags, p);
			vfs_unbusy(mp);
			if (error)
				return (error);
		}
		if (fs->fs_ronly && (mp->mnt_kern_flag & MNTK_WANTRDWR))
			fs->fs_ronly = 0;
#ifdef EXPORTMFS
		if (args.fspec == 0)
			return (vfs_export(mp, &ump->um_export, &args.export));
#endif
		return (0);
	}
	MALLOC(mfsp, struct mfsnode *, sizeof(struct mfsnode), M_MFSNODE, M_WAITOK);
	error = getnewvnode(VT_MFS, (struct mount *)0, mfs_vnodeop_p, &devvp);
	if (error) {
		FREE(mfsp, M_MFSNODE);
		return (error);
	}
	devvp->v_type = VBLK;
	if (checkalias(devvp, makedev(255, mfs_minor++), (struct mount *)0))
		panic("mfs_mount: dup dev");
	devvp->v_data = mfsp;
	mfsp->mfs_baseoff = args.base;
	mfsp->mfs_size = args.size;
	mfsp->mfs_vnode = devvp;
	mfsp->mfs_pid = p->p_pid;
	mfsp->mfs_buflist = (struct buf *)0;
	if (error = ffs_mountfs(devvp, mp, p)) {
		mfsp->mfs_buflist = (struct buf *)-1;
		vrele(devvp);
		return (error);
	}
	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	(void) copyinstr(path, fs->fs_fsmnt, sizeof(fs->fs_fsmnt) - 1, &size);
	bzero(fs->fs_fsmnt + size, sizeof(fs->fs_fsmnt) - size);
	bcopy(fs->fs_fsmnt, mp->mnt_stat.f_mntonname, MNAMELEN);
	(void) copyinstr(args.fspec, mp->mnt_stat.f_mntfromname, MNAMELEN - 1,
	    &size);
	bzero(mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
	return (0);
}

int	mfs_pri = PWAIT | PCATCH;		/* XXX prob. temp */

/*
 * Used to grab the process and keep it in the kernel to service
 * memory filesystem I/O requests.
 *
 * Loop servicing I/O requests.
 * Copy the requested data into or out of the memory filesystem
 * address space.
 */
/* ARGSUSED */
int
mfs_start(mp, flags, p)
	struct mount *mp;
	int flags;
	struct proc *p;
{
	register struct vnode *vp = VFSTOUFS(mp)->um_devvp;
	register struct mfsnode *mfsp = VTOMFS(vp);
	register struct buf *bp;
	register caddr_t base;
	int error = 0;

	base = mfsp->mfs_baseoff;
	while (mfsp->mfs_buflist != (struct buf *)(-1)) {
		while (bp = mfsp->mfs_buflist) {
			mfsp->mfs_buflist = bp->b_actf;
			mfs_doio(bp, base);
			wakeup((caddr_t)bp);
		}
		/*
		 * If a non-ignored signal is received, try to unmount.
		 * If that fails, clear the signal (it has been "processed"),
		 * otherwise we will loop here, as tsleep will always return
		 * EINTR/ERESTART.
		 */
		if (error = tsleep((caddr_t)vp, mfs_pri, "mfsidl", 0))
			if (dounmount(mp, 0, p) != 0)
				CLRSIG(p, CURSIG(p));
	}
	return (error);
}

/*
 * Get file system statistics.
 */
mfs_statfs(mp, sbp, p)
	struct mount *mp;
	struct statfs *sbp;
	struct proc *p;
{
	int error;

	error = ffs_statfs(mp, sbp, p);
#ifdef COMPAT_09
	sbp->f_type = 3;
#else
	sbp->f_type = 0;
#endif
	strncpy(&sbp->f_fstypename[0], mp->mnt_op->vfs_name, MFSNAMELEN);
	sbp->f_fstypename[MFSNAMELEN] = '\0';
	return (error);
}
