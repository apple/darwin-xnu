/*
 * Copyright (c) 1995-2000 Apple Computer, Inc. All rights reserved.
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
 *	@(#)vfs_syscalls.c	8.41 (Berkeley) 6/15/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/attr.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <machine/cons.h>
#include <miscfs/specfs/specdev.h>

struct lock__bsd__	exchangelock;

/*
 * The currently logged-in user, for ownership of files/directories whose on-disk
 * permissions are ignored:
 */
uid_t console_user;

static int change_dir __P((struct nameidata *ndp, struct proc *p));
static void checkdirs __P((struct vnode *olddp));

/* counts number of mount and unmount operations */
unsigned int vfs_nummntops=0;

/*
 * Virtual File System System Calls
 */

/*
 * Mount a file system.
 */
struct mount_args {
	char	*type;
	char	*path;
	int	flags;
	caddr_t	data;
};
/* ARGSUSED */
int
mount(p, uap, retval)
	struct proc *p;
	register struct mount_args *uap;
	register_t *retval;
{
	struct vnode *vp;
	struct mount *mp;
	struct vfsconf *vfsp;
	int error, flag;
	struct vattr va;
	u_long fstypenum;
	struct nameidata nd;
	char fstypename[MFSNAMELEN];
	size_t dummy=0;
	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	
	if ((vp->v_flag & VROOT) &&
		(vp->v_mount->mnt_flag & MNT_ROOTFS)) 
			uap->flags |= MNT_UPDATE;
	
	if (uap->flags & MNT_UPDATE) {
		if ((vp->v_flag & VROOT) == 0) {
			vput(vp);
			return (EINVAL);
		}
		mp = vp->v_mount;
		flag = mp->mnt_flag;
		/*
		 * We only allow the filesystem to be reloaded if it
		 * is currently mounted read-only.
		 */
		if ((uap->flags & MNT_RELOAD) &&
		    ((mp->mnt_flag & MNT_RDONLY) == 0)) {
			vput(vp);
			return (EOPNOTSUPP);	/* Needs translation */
		}
		mp->mnt_flag |=
		    uap->flags & (MNT_RELOAD | MNT_FORCE | MNT_UPDATE);
		/*
		 * Only root, or the user that did the original mount is
		 * permitted to update it.
		 */
		if (mp->mnt_stat.f_owner != p->p_ucred->cr_uid &&
		    (error = suser(p->p_ucred, &p->p_acflag))) {
			vput(vp);
			return (error);
		}
		/*
		 * Do not allow NFS export by non-root users. FOr non-root
		 * users, silently enforce MNT_NOSUID and MNT_NODEV, and
		 * MNT_NOEXEC if mount point is already MNT_NOEXEC.
		 */
		if (p->p_ucred->cr_uid != 0) {
			if (uap->flags & MNT_EXPORTED) {
				vput(vp);
				return (EPERM);
			}
			uap->flags |= MNT_NOSUID | MNT_NODEV;
			if (flag & MNT_NOEXEC)
				uap->flags |= MNT_NOEXEC;
		}
		if (vfs_busy(mp, LK_NOWAIT, 0, p)) {
			vput(vp);
			return (EBUSY);
		}
		VOP_UNLOCK(vp, 0, p);
		goto update;
	}
	/*
	 * If the user is not root, ensure that they own the directory
	 * onto which we are attempting to mount.
	 */
	if ((error = VOP_GETATTR(vp, &va, p->p_ucred, p)) ||
	    (va.va_uid != p->p_ucred->cr_uid &&
	     (error = suser(p->p_ucred, &p->p_acflag)))) {
		vput(vp);
		return (error);
	}
	/*
	 * Do not allow NFS export by non-root users. FOr non-root
	 * users, silently enforce MNT_NOSUID and MNT_NODEV, and
	 * MNT_NOEXEC if mount point is already MNT_NOEXEC.
	 */
	if (p->p_ucred->cr_uid != 0) {
		if (uap->flags & MNT_EXPORTED) {
			vput(vp);
			return (EPERM);
		}
		uap->flags |= MNT_NOSUID | MNT_NODEV;
		if (vp->v_mount->mnt_flag & MNT_NOEXEC)
			uap->flags |= MNT_NOEXEC;
	}
	if (error = vinvalbuf(vp, V_SAVE, p->p_ucred, p, 0, 0)) {
		vput(vp);
		return (error);
	}
	if (vp->v_type != VDIR) {
		vput(vp);
		return (ENOTDIR);
	}
#if COMPAT_43
	/*
	 * Historically filesystem types were identified by number. If we
	 * get an integer for the filesystem type instead of a string, we
	 * check to see if it matches one of the historic filesystem types.
	 */
	fstypenum = (u_long)uap->type;
	if (fstypenum < maxvfsconf) {
		for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
			if (vfsp->vfc_typenum == fstypenum)
				break;
		if (vfsp == NULL) {
			vput(vp);
			return (ENODEV);
		}
		strncpy(fstypename, vfsp->vfc_name, MFSNAMELEN);
	} else
#endif /* COMPAT_43 */
	if (error = copyinstr(uap->type, fstypename, MFSNAMELEN, &dummy)) {
		vput(vp);
		return (error);
	}
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strcmp(vfsp->vfc_name, fstypename))
			break;
	if (vfsp == NULL) {
		vput(vp);
		return (ENODEV);
	}
	simple_lock(&vp->v_interlock);
	if (ISSET(vp->v_flag, VMOUNT) && (vp->v_mountedhere != NULL)) {
		simple_unlock(&vp->v_interlock);
		vput(vp);
		return (EBUSY);
	}
	SET(vp->v_flag, VMOUNT);
	simple_unlock(&vp->v_interlock);

	/*
	 * Allocate and initialize the filesystem.
	 */
	mp = (struct mount *)_MALLOC_ZONE((u_long)sizeof(struct mount),
		M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));
	lockinit(&mp->mnt_lock, PVFS, "vfslock", 0, 0);
	(void)vfs_busy(mp, LK_NOWAIT, 0, p);
	mp->mnt_op = vfsp->vfc_vfsops;
	mp->mnt_vfc = vfsp;
	vfsp->vfc_refcount++;
	mp->mnt_stat.f_type = vfsp->vfc_typenum;
	mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;
	strncpy(mp->mnt_stat.f_fstypename, vfsp->vfc_name, MFSNAMELEN);
	mp->mnt_vnodecovered = vp;
	mp->mnt_stat.f_owner = p->p_ucred->cr_uid;
	VOP_UNLOCK(vp, 0, p);

update:
	/*
	 * Set the mount level flags.
	 */
	if (uap->flags & MNT_RDONLY)
		mp->mnt_flag |= MNT_RDONLY;
	else if (mp->mnt_flag & MNT_RDONLY)
		mp->mnt_kern_flag |= MNTK_WANTRDWR;
	mp->mnt_flag &=~ (MNT_NOSUID | MNT_NOEXEC | MNT_NODEV |
	    MNT_SYNCHRONOUS | MNT_UNION | MNT_ASYNC | MNT_UNKNOWNPERMISSIONS);
	mp->mnt_flag |= uap->flags & (MNT_NOSUID | MNT_NOEXEC |
	    MNT_NODEV | MNT_SYNCHRONOUS | MNT_UNION | MNT_ASYNC | MNT_UNKNOWNPERMISSIONS);
	/*
	 * Mount the filesystem.
	 */
	error = VFS_MOUNT(mp, uap->path, uap->data, &nd, p);
	if (mp->mnt_flag & MNT_UPDATE) {
		vrele(vp);
		if (mp->mnt_kern_flag & MNTK_WANTRDWR)
			mp->mnt_flag &= ~MNT_RDONLY;
		mp->mnt_flag &=~
		    (MNT_UPDATE | MNT_RELOAD | MNT_FORCE);
		mp->mnt_kern_flag &=~ MNTK_WANTRDWR;
		if (error)
			mp->mnt_flag = flag;
		vfs_unbusy(mp, p);
		return (error);
	}
	/*
	 * Put the new filesystem on the mount list after root.
	 */
	cache_purge(vp);
	if (!error) {
		simple_lock(&vp->v_interlock);
		CLR(vp->v_flag, VMOUNT);
		vp->v_mountedhere =mp;
		simple_unlock(&vp->v_interlock);
		simple_lock(&mountlist_slock);
		CIRCLEQ_INSERT_TAIL(&mountlist, mp, mnt_list);
		simple_unlock(&mountlist_slock);
		checkdirs(vp);
		VOP_UNLOCK(vp, 0, p);
		vfs_unbusy(mp, p);
		if (error = VFS_START(mp, 0, p))
			vrele(vp);

		/* increment the operations count */
		if (!error)
			vfs_nummntops++;
	} else {
		simple_lock(&vp->v_interlock);
		CLR(vp->v_flag, VMOUNT);
		simple_unlock(&vp->v_interlock);
		mp->mnt_vfc->vfc_refcount--;
		vfs_unbusy(mp, p);
		_FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
		vput(vp);
	}
	return (error);
}

/*
 * Scan all active processes to see if any of them have a current
 * or root directory onto which the new filesystem has just been
 * mounted. If so, replace them with the new mount point.
 */
static void
checkdirs(olddp)
	struct vnode *olddp;
{
	struct filedesc *fdp;
	struct vnode *newdp;
	struct proc *p;

	if (olddp->v_usecount == 1)
		return;
	if (VFS_ROOT(olddp->v_mountedhere, &newdp))
		panic("mount: lost mount");
	for (p = allproc.lh_first; p != 0; p = p->p_list.le_next) {
		fdp = p->p_fd;
		if (fdp->fd_cdir == olddp) {
			vrele(fdp->fd_cdir);
			VREF(newdp);
			fdp->fd_cdir = newdp;
		}
		if (fdp->fd_rdir == olddp) {
			vrele(fdp->fd_rdir);
			VREF(newdp);
			fdp->fd_rdir = newdp;
		}
	}
	if (rootvnode == olddp) {
		vrele(rootvnode);
		VREF(newdp);
		rootvnode = newdp;
	}
	vput(newdp);
}

/*
 * Unmount a file system.
 *
 * Note: unmount takes a path to the vnode mounted on as argument,
 * not special file (as before).
 */
struct unmount_args {
	char	*path;
	int	flags;
};
/* ARGSUSED */
int
unmount(p, uap, retval)
	struct proc *p;
	register struct unmount_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct mount *mp;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	mp = vp->v_mount;

	/*
	 * Only root, or the user that did the original mount is
	 * permitted to unmount this filesystem.
	 */
	if ((mp->mnt_stat.f_owner != p->p_ucred->cr_uid) &&
	    (error = suser(p->p_ucred, &p->p_acflag))) {
		vput(vp);
		return (error);
	}

	/*
	 * Don't allow unmounting the root file system.
	 */
	if (mp->mnt_flag & MNT_ROOTFS) {
		vput(vp);
		return (EBUSY); /* the root is always busy */
	}

	/*
	 * Must be the root of the filesystem
	 */
	if ((vp->v_flag & VROOT) == 0) {
		vput(vp);
		return (EINVAL);
	}
	vput(vp);
	return (dounmount(mp, uap->flags, p));
}

/*
 * Do the actual file system unmount.
 */
int
dounmount(mp, flags, p)
	register struct mount *mp;
	int flags;
	struct proc *p;
{
	struct vnode *coveredvp;
	int error;

	simple_lock(&mountlist_slock);
	mp->mnt_kern_flag |= MNTK_UNMOUNT;
	lockmgr(&mp->mnt_lock, LK_DRAIN | LK_INTERLOCK, &mountlist_slock, p);
	mp->mnt_flag &=~ MNT_ASYNC;
	ubc_umount(mp);	/* release cached vnodes */
	cache_purgevfs(mp);	/* remove cache entries for this file sys */
	if (((mp->mnt_flag & MNT_RDONLY) ||
	     (error = VFS_SYNC(mp, MNT_WAIT, p->p_ucred, p)) == 0) ||
	    (flags & MNT_FORCE))
		error = VFS_UNMOUNT(mp, flags, p);
	simple_lock(&mountlist_slock);
	if (error) {
		mp->mnt_kern_flag &= ~MNTK_UNMOUNT;
		lockmgr(&mp->mnt_lock, LK_RELEASE | LK_INTERLOCK | LK_REENABLE,
		    &mountlist_slock, p);
		goto out;
	}

	/* increment the operations count */
	if (!error)
		vfs_nummntops++;
	CIRCLEQ_REMOVE(&mountlist, mp, mnt_list);
	if ((coveredvp = mp->mnt_vnodecovered) != NULLVP) {
		coveredvp->v_mountedhere = (struct mount *)0;
		simple_unlock(&mountlist_slock);
		vrele(coveredvp);
		simple_lock(&mountlist_slock);
	}
	mp->mnt_vfc->vfc_refcount--;
	if (mp->mnt_vnodelist.lh_first != NULL) {
		 panic("unmount: dangling vnode"); 
	}
	lockmgr(&mp->mnt_lock, LK_RELEASE | LK_INTERLOCK, &mountlist_slock, p);
out:
	if (mp->mnt_kern_flag & MNTK_MWAIT)
		wakeup((caddr_t)mp);
	if (!error)
		_FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
	return (error);
}

/*
 * Sync each mounted filesystem.
 */
#if DIAGNOSTIC
int syncprt = 0;
struct ctldebug debug0 = { "syncprt", &syncprt };
#endif

struct sync_args {
	int	dummy;
};
int print_vmpage_stat=0;

/* ARGSUSED */
int
sync(p, uap, retval)
	struct proc *p;
	struct sync_args *uap;
	register_t *retval;
{
	register struct mount *mp, *nmp;
	int asyncflag;

	simple_lock(&mountlist_slock);
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
			nmp = mp->mnt_list.cqe_next;
			continue;
		}
		if ((mp->mnt_flag & MNT_RDONLY) == 0) {
			asyncflag = mp->mnt_flag & MNT_ASYNC;
			mp->mnt_flag &= ~MNT_ASYNC;
			VFS_SYNC(mp, MNT_NOWAIT, p->p_ucred, p);
			if (asyncflag)
				mp->mnt_flag |= MNT_ASYNC;
		}
		simple_lock(&mountlist_slock);
		nmp = mp->mnt_list.cqe_next;
		vfs_unbusy(mp, p);
	}
	simple_unlock(&mountlist_slock);

	{
	extern void vm_countdirtypages(void);
	extern unsigned int vp_pagein, vp_pgodirty, vp_pgoclean;
	extern unsigned int dp_pgins, dp_pgouts;
	if(print_vmpage_stat) {
		vm_countdirtypages();
		printf("VP: %d: %d: %d: %d: %d\n", vp_pgodirty, vp_pgoclean, vp_pagein, dp_pgins, dp_pgouts);
	}
	}
#if DIAGNOSTIC
	if (syncprt)
		vfs_bufstats();
#endif /* DIAGNOSTIC */
	return (0);
}

/*
 * Change filesystem quotas.
 */
struct quotactl_args {
	char *path;
	int cmd;
	int uid;
	caddr_t arg;
};
/* ARGSUSED */
int
quotactl(p, uap, retval)
	struct proc *p;
	register struct quotactl_args *uap;
	register_t *retval;
{
	register struct mount *mp;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	mp = nd.ni_vp->v_mount;
	vrele(nd.ni_vp);
	return (VFS_QUOTACTL(mp, uap->cmd, uap->uid,
	    uap->arg, p));
}

/*
 * Get filesystem statistics.
 */
struct statfs_args {
	char *path;
	struct statfs *buf;
};
/* ARGSUSED */
int
statfs(p, uap, retval)
	struct proc *p;
	register struct statfs_args *uap;
	register_t *retval;
{
	register struct mount *mp;
	register struct statfs *sp;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	mp = nd.ni_vp->v_mount;
	sp = &mp->mnt_stat;
	vrele(nd.ni_vp);
	if (error = VFS_STATFS(mp, sp, p))
		return (error);
	sp->f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
/*	return (copyout((caddr_t)sp, (caddr_t)uap->buf, sizeof(*sp))); */
	return (copyout((caddr_t)sp, (caddr_t)uap->buf, sizeof(*sp)-sizeof(sp->f_reserved3)-sizeof(sp->f_reserved4)));
}

/*
 * Get filesystem statistics.
 */
struct fstatfs_args {
	int fd;
	struct statfs *buf;
};
/* ARGSUSED */
int
fstatfs(p, uap, retval)
	struct proc *p;
	register struct fstatfs_args *uap;
	register_t *retval;
{
	struct file *fp;
	struct mount *mp;
	register struct statfs *sp;
	int error;

	if (error = getvnode(p, uap->fd, &fp))
		return (error);
	mp = ((struct vnode *)fp->f_data)->v_mount;
	if (!mp)
		return (EBADF);
	sp = &mp->mnt_stat;
	if (error = VFS_STATFS(mp, sp, p))
		return (error);
	sp->f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
/*	return (copyout((caddr_t)sp, (caddr_t)uap->buf, sizeof(*sp))); */
	return (copyout((caddr_t)sp, (caddr_t)uap->buf, sizeof(*sp)-sizeof(sp->f_reserved3)-sizeof(sp->f_reserved4)));
}

/*
 * Get statistics on all filesystems.
 */
struct getfsstat_args {
	struct statfs *buf;
	long bufsize;
	int flags;
};
int
getfsstat(p, uap, retval)
	struct proc *p;
	register struct getfsstat_args *uap;
	register_t *retval;
{
	register struct mount *mp, *nmp;
	register struct statfs *sp;
	caddr_t sfsp;
	long count, maxcount, error;

	maxcount = uap->bufsize / sizeof(struct statfs);
	sfsp = (caddr_t)uap->buf;
	count = 0;
	simple_lock(&mountlist_slock);
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
			nmp = mp->mnt_list.cqe_next;
			continue;
		}
		if (sfsp && count < maxcount) {
			sp = &mp->mnt_stat;
			/*
			 * If MNT_NOWAIT is specified, do not refresh the
			 * fsstat cache. MNT_WAIT overrides MNT_NOWAIT.
			 */
			if (((uap->flags & MNT_NOWAIT) == 0 ||
			    (uap->flags & MNT_WAIT)) &&
			    (error = VFS_STATFS(mp, sp, p))) {
				simple_lock(&mountlist_slock);
				nmp = mp->mnt_list.cqe_next;
				vfs_unbusy(mp, p);
				continue;
			}
			sp->f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
			if (error = copyout((caddr_t)sp, sfsp, sizeof(*sp)))
				return (error);
			sfsp += sizeof(*sp);
		}
		count++;
		simple_lock(&mountlist_slock);
		nmp = mp->mnt_list.cqe_next;
		vfs_unbusy(mp, p);
	}
	simple_unlock(&mountlist_slock);
	if (sfsp && count > maxcount)
		*retval = maxcount;
	else
		*retval = count;
	return (0);
}

#if COMPAT_GETFSSTAT
ogetfsstat(p, uap, retval)
	struct proc *p;
	register struct getfsstat_args *uap;
	register_t *retval;
{
	register struct mount *mp, *nmp;
	register struct statfs *sp;
	caddr_t sfsp;
	long count, maxcount, error;

	maxcount = uap->bufsize / (sizeof(struct statfs) - sizeof(sp->f_reserved4));
	sfsp = (caddr_t)uap->buf;
	count = 0;
	simple_lock(&mountlist_slock);
	for (mp = mountlist.cqh_first; mp != (void *)&mountlist; mp = nmp) {
		if (vfs_busy(mp, LK_NOWAIT, &mountlist_slock, p)) {
			nmp = mp->mnt_list.cqe_next;
			continue;
		}
		if (sfsp && count < maxcount) {
			sp = &mp->mnt_stat;
			/*
			 * If MNT_NOWAIT is specified, do not refresh the
			 * fsstat cache. MNT_WAIT overrides MNT_NOWAIT.
			 */
			if (((uap->flags & MNT_NOWAIT) == 0 ||
			    (uap->flags & MNT_WAIT)) &&
			    (error = VFS_STATFS(mp, sp, p))) {
				simple_lock(&mountlist_slock);
				nmp = mp->mnt_list.cqe_next;
				vfs_unbusy(mp, p);
				continue;
			}
			sp->f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
			if (error = copyout((caddr_t)sp, sfsp, sizeof(*sp) - sizeof(sp->f_reserved3) - sizeof(sp->f_reserved4)))
				return (error);
			sfsp += sizeof(*sp) - sizeof(sp->f_reserved4);
		}
		count++;
		simple_lock(&mountlist_slock);
		nmp = mp->mnt_list.cqe_next;
		vfs_unbusy(mp, p);
	}
	simple_unlock(&mountlist_slock);
	if (sfsp && count > maxcount)
		*retval = maxcount;
	else
		*retval = count;
	return (0);
}
#endif

/*
 * Change current working directory to a given file descriptor.
 */
struct fchdir_args {
	int	fd;
};
/* ARGSUSED */
int
fchdir(p, uap, retval)
	struct proc *p;
	struct fchdir_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	struct vnode *vp, *tdp;
	struct mount *mp;
	struct file *fp;
	int error;

	if (error = getvnode(p, uap->fd, &fp))
		return (error);
	vp = (struct vnode *)fp->f_data;
	VREF(vp);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	if (vp->v_type != VDIR)
		error = ENOTDIR;
	else
		error = VOP_ACCESS(vp, VEXEC, p->p_ucred, p);
	while (!error && (mp = vp->v_mountedhere) != NULL) {
		if (vfs_busy(mp, 0, 0, p))
			continue;
		error = VFS_ROOT(mp, &tdp);
		vfs_unbusy(mp, p);
		if (error)
			break;
		vput(vp);
		vp = tdp;
	}
	if (error) {
		vput(vp);
		return (error);
	}
	VOP_UNLOCK(vp, 0, p);
	vrele(fdp->fd_cdir);
	fdp->fd_cdir = vp;
	return (0);
}

/*
 * Change current working directory (``.'').
 */
struct chdir_args {
	char	*path;
};
/* ARGSUSED */
int
chdir(p, uap, retval)
	struct proc *p;
	struct chdir_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = change_dir(&nd, p))
		return (error);
	vrele(fdp->fd_cdir);
	fdp->fd_cdir = nd.ni_vp;
	return (0);
}

/*
 * Change notion of root (``/'') directory.
 */
struct chroot_args {
	char	*path;
};
/* ARGSUSED */
int
chroot(p, uap, retval)
	struct proc *p;
	struct chroot_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	int error;
	struct nameidata nd;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = change_dir(&nd, p))
		return (error);

	if(error = clone_system_shared_regions()) {
		vrele(nd.ni_vp);
		return (error);
	}

	if (fdp->fd_rdir != NULL)
		vrele(fdp->fd_rdir);
	fdp->fd_rdir = nd.ni_vp;
	return (0);
}

/*
 * Common routine for chroot and chdir.
 */
static int
change_dir(ndp, p)
	register struct nameidata *ndp;
	struct proc *p;
{
	struct vnode *vp;
	int error;

	if (error = namei(ndp))
		return (error);
	vp = ndp->ni_vp;
	if (vp->v_type != VDIR)
		error = ENOTDIR;
	else
		error = VOP_ACCESS(vp, VEXEC, p->p_ucred, p);
	if (error)
		vput(vp);
	else
		VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * Check permissions, allocate an open file structure,
 * and call the device open routine if any.
 */
struct open_args {
	char	*path;
	int	flags;
	int	mode;
};
int
open(p, uap, retval)
	struct proc *p;
	register struct open_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp = p->p_fd;
	register struct file *fp;
	register struct vnode *vp;
	int flags, cmode;
	struct file *nfp;
	int type, indx, error;
	struct flock lf;
	struct nameidata nd;
	extern struct fileops vnops;

	/* CERT advisory patch applied from FreeBSD */
	/* Refer to Radar#2262895 A. Ramesh */
	flags = FFLAGS(uap->flags);
	if ((flags & (FREAD | FWRITE))==0)
		return(EINVAL);
	if (error = falloc(p, &nfp, &indx))
		return (error);
	fp = nfp;
	cmode = ((uap->mode &~ fdp->fd_cmask) & ALLPERMS) &~ S_ISTXT;
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	p->p_dupfd = -indx - 1;			/* XXX check for fdopen */
	if (error = vn_open(&nd, flags, cmode)) {
		ffree(fp);
		if ((error == ENODEV || error == ENXIO) &&
		    p->p_dupfd >= 0 &&			/* XXX from fdopen */
		    (error =
			dupfdopen(fdp, indx, p->p_dupfd, flags, error)) == 0) {
			*retval = indx;
			return (0);
		}
		if (error == ERESTART)
			error = EINTR;
		fdrelse(p, indx);
		return (error);
	}
	p->p_dupfd = 0;
	vp = nd.ni_vp;
	fp->f_flag = flags & FMASK;
	fp->f_type = DTYPE_VNODE;
	fp->f_ops = &vnops;
	fp->f_data = (caddr_t)vp;
	if (flags & (O_EXLOCK | O_SHLOCK)) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		if (flags & O_EXLOCK)
			lf.l_type = F_WRLCK;
		else
			lf.l_type = F_RDLCK;
		type = F_FLOCK;
		if ((flags & FNONBLOCK) == 0)
			type |= F_WAIT;
		VOP_UNLOCK(vp, 0, p);
		if (error = VOP_ADVLOCK(vp, (caddr_t)fp, F_SETLK, &lf, type)) {
			(void) vn_close(vp, fp->f_flag, fp->f_cred, p);
			ffree(fp);
			fdrelse(p, indx);
			return (error);
		}
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		fp->f_flag |= FHASLOCK;
	}
	VOP_UNLOCK(vp, 0, p);
	*fdflags(p, indx) &= ~UF_RESERVED;
	*retval = indx;
	return (0);
}

#if COMPAT_43
/*
 * Create a file.
 */
struct ocreat_args {
	char	*path;
	int	mode;
};
int
ocreat(p, uap, retval)
	struct proc *p;
	register struct ocreat_args *uap;
	register_t *retval;
{
	struct open_args nuap;

	nuap.path = uap->path;
	nuap.mode = uap->mode;
	nuap.flags = O_WRONLY | O_CREAT | O_TRUNC;
	return (open(p, &nuap, retval));
}
#endif /* COMPAT_43 */

/*
 * Create a special file.
 */
struct mknod_args {
	char	*path;
	int	mode;
	int	dev;
};
/* ARGSUSED */
int
mknod(p, uap, retval)
	struct proc *p;
	register struct mknod_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct vattr vattr;
	int error;
	int whiteout;
	struct nameidata nd;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	NDINIT(&nd, CREATE, LOCKPARENT, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	if (vp != NULL)
		error = EEXIST;
	else {
		VATTR_NULL(&vattr);
		vattr.va_mode = (uap->mode & ALLPERMS) &~ p->p_fd->fd_cmask;
		vattr.va_rdev = uap->dev;
		whiteout = 0;

		switch (uap->mode & S_IFMT) {
		case S_IFMT:	/* used by badsect to flag bad sectors */
			vattr.va_type = VBAD;
			break;
		case S_IFCHR:
			vattr.va_type = VCHR;
			break;
		case S_IFBLK:
			vattr.va_type = VBLK;
			break;
		case S_IFWHT:
			whiteout = 1;
			break;
		default:
			error = EINVAL;
			break;
		}
	}
	if (!error) {
		VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
		if (whiteout) {
			error = VOP_WHITEOUT(nd.ni_dvp, &nd.ni_cnd, CREATE);
			if (error)
				VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
			vput(nd.ni_dvp);
		} else {
			error = VOP_MKNOD(nd.ni_dvp, &nd.ni_vp,
						&nd.ni_cnd, &vattr);
		}
	} else {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (vp)
			vrele(vp);
	}
	return (error);
}

/*
 * Create a named pipe.
 */
struct mkfifo_args {
	char	*path;
	int	mode;
};
/* ARGSUSED */
int
mkfifo(p, uap, retval)
	struct proc *p;
	register struct mkfifo_args *uap;
	register_t *retval;
{
	struct vattr vattr;
	int error;
	struct nameidata nd;

#if !FIFO 
	return (EOPNOTSUPP);
#else
	NDINIT(&nd, CREATE, LOCKPARENT, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	if (nd.ni_vp != NULL) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		return (EEXIST);
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VFIFO;
	vattr.va_mode = (uap->mode & ALLPERMS) &~ p->p_fd->fd_cmask;
	VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
	return (VOP_MKNOD(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr));
#endif /* FIFO */
}

/*
 * Make a hard file link.
 */
struct link_args {
	char	*path;
	char	*link;
};
/* ARGSUSED */
int
link(p, uap, retval)
	struct proc *p;
	register struct link_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	if (vp->v_type == VDIR)
		error = EPERM;   /* POSIX */
	else {
		nd.ni_cnd.cn_nameiop = CREATE;
		nd.ni_cnd.cn_flags = LOCKPARENT;
		nd.ni_dirp = uap->link;
		if ((error = namei(&nd)) == 0) {
			if (nd.ni_vp != NULL)
				error = EEXIST;
			if (!error) {
				VOP_LEASE(nd.ni_dvp, p, p->p_ucred,
				    LEASE_WRITE);
				VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
				error = VOP_LINK(vp, nd.ni_dvp, &nd.ni_cnd);
			} else {
				VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
				if (nd.ni_dvp == nd.ni_vp)
					vrele(nd.ni_dvp);
				else
					vput(nd.ni_dvp);
				if (nd.ni_vp)
					vrele(nd.ni_vp);
			}
		}
	}
	vrele(vp);
	return (error);
}

/*
 * Make a symbolic link.
 */
struct symlink_args {
	char	*path;
	char	*link;
};
/* ARGSUSED */
int
symlink(p, uap, retval)
	struct proc *p;
	register struct symlink_args *uap;
	register_t *retval;
{
	struct vattr vattr;
	char *path;
	int error;
	struct nameidata nd;
	size_t dummy=0;
	MALLOC_ZONE(path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (error = copyinstr(uap->path, path, MAXPATHLEN, &dummy))
		goto out;
	NDINIT(&nd, CREATE, LOCKPARENT, UIO_USERSPACE, uap->link, p);
	if (error = namei(&nd))
		goto out;
	if (nd.ni_vp) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		error = EEXIST;
		goto out;
	}
	VATTR_NULL(&vattr);
	vattr.va_mode = ACCESSPERMS &~ p->p_fd->fd_cmask;
	VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
	error = VOP_SYMLINK(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr, path);
out:
	FREE_ZONE(path, MAXPATHLEN, M_NAMEI);
	return (error);
}

/*
 * Delete a whiteout from the filesystem.
 */
struct undelete_args {
	char	*path;
};
/* ARGSUSED */
int
undelete(p, uap, retval)
	struct proc *p;
	register struct undelete_args *uap;
	register_t *retval;
{
	int error;
	struct nameidata nd;

	NDINIT(&nd, DELETE, LOCKPARENT|DOWHITEOUT, UIO_USERSPACE,
	    uap->path, p);
	error = namei(&nd);
	if (error)
		return (error);

	if (nd.ni_vp != NULLVP || !(nd.ni_cnd.cn_flags & ISWHITEOUT)) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (nd.ni_vp)
			vrele(nd.ni_vp);
		return (EEXIST);
	}

	VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
	if (error = VOP_WHITEOUT(nd.ni_dvp, &nd.ni_cnd, DELETE))
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
	vput(nd.ni_dvp);
	return (error);
}

/*
 * Delete a name from the filesystem.
 */
struct unlink_args {
	char	*path;
};
/* ARGSUSED */
static int
_unlink(p, uap, retval, nodelbusy)
	struct proc *p;
	struct unlink_args *uap;
	register_t *retval;
	int nodelbusy;
{
	register struct vnode *vp;
	int error;
	struct nameidata nd;

	NDINIT(&nd, DELETE, LOCKPARENT, UIO_USERSPACE, uap->path, p);
	/* with hfs semantics, busy files cannot be deleted */
	if (nodelbusy)
		nd.ni_cnd.cn_flags |= NODELETEBUSY;
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

	if (vp->v_type == VDIR)
		error = EPERM;	/* POSIX */
	else {
		/*
		 * The root of a mounted filesystem cannot be deleted.
		 *
		 * XXX: can this only be a VDIR case?
		 */
		if (vp->v_flag & VROOT)
			error = EBUSY;
	}

	if (!error) {
		VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
		error = VOP_REMOVE(nd.ni_dvp, nd.ni_vp, &nd.ni_cnd);
	} else {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (vp != NULLVP)
			vput(vp);
	}
	return (error);
}

/*
 * Delete a name from the filesystem using POSIX semantics.
 */
int
unlink(p, uap, retval)
	struct proc *p;
	struct unlink_args *uap;
	register_t *retval;
{
	return _unlink(p, uap, retval, 0);
}

/*
 * Delete a name from the filesystem using HFS semantics.
 */
int
delete(p, uap, retval)
	struct proc *p;
	struct unlink_args *uap;
	register_t *retval;
{
	return _unlink(p, uap, retval, 1);
}

/*
 * Reposition read/write file offset.
 */
struct lseek_args {
	int	fd;
#ifdef DOUBLE_ALIGN_PARAMS
	int pad;
#endif
	off_t	offset;
	int	whence;
};
int
lseek(p, uap, retval)
	struct proc *p;
	register struct lseek_args *uap;
	register_t *retval;
{
	struct ucred *cred = p->p_ucred;
	struct file *fp;
	struct vattr vattr;
	int error;

	if (error = fdgetf(p, uap->fd, &fp))
		return (error);
	if (fp->f_type != DTYPE_VNODE)
		return (ESPIPE);
	switch (uap->whence) {
	case L_INCR:
		fp->f_offset += uap->offset;
		break;
	case L_XTND:
		if (error =
		    VOP_GETATTR((struct vnode *)fp->f_data, &vattr, cred, p))
			return (error);
		fp->f_offset = uap->offset + vattr.va_size;
		break;
	case L_SET:
		fp->f_offset = uap->offset;
		break;
	default:
		return (EINVAL);
	}
	*(off_t *)retval = fp->f_offset;
	return (0);
}

#if COMPAT_43
/*
 * Reposition read/write file offset.
 */
struct olseek_args {
	int	fd;
	long	offset;
	int	whence;
};
int
olseek(p, uap, retval)
	struct proc *p;
	register struct olseek_args *uap;
	register_t *retval;
{
	struct lseek_args /* {
		syscallarg(int) fd;
#ifdef DOUBLE_ALIGN_PARAMS
        syscallarg(int) pad;
#endif
		syscallarg(off_t) offset;
		syscallarg(int) whence;
	} */ nuap;
	off_t qret;
	int error;

	nuap.fd = uap->fd;
	nuap.offset = uap->offset;
	nuap.whence = uap->whence;
	error = lseek(p, &nuap, &qret);
	*(long *)retval = qret;
	return (error);
}
#endif /* COMPAT_43 */

/*
 * Check access permissions.
 */
struct access_args {
	char	*path;
	int	flags;
};
int
access(p, uap, retval)
	struct proc *p;
	register struct access_args *uap;
	register_t *retval;
{
	register struct ucred *cred = p->p_ucred;
	register struct vnode *vp;
	int error, flags, t_gid, t_uid;
	struct nameidata nd;

	t_uid = cred->cr_uid;
	t_gid = cred->cr_groups[0];
	cred->cr_uid = p->p_cred->p_ruid;
	cred->cr_groups[0] = p->p_cred->p_rgid;
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		goto out1;
	vp = nd.ni_vp;

	/* Flags == 0 means only check for existence. */
	if (uap->flags) {
		flags = 0;
		if (uap->flags & R_OK)
			flags |= VREAD;
		if (uap->flags & W_OK)
			flags |= VWRITE;
		if (uap->flags & X_OK)
			flags |= VEXEC;
		if ((flags & VWRITE) == 0 || (error = vn_writechk(vp)) == 0)
			error = VOP_ACCESS(vp, flags, cred, p);
	}
	vput(vp);
out1:
	cred->cr_uid = t_uid;
	cred->cr_groups[0] = t_gid;
	return (error);
}

#if COMPAT_43
/*
 * Get file status; this version follows links.
 */
struct ostat_args {
	char	*path;
	struct ostat *ub;
};
/* ARGSUSED */
int
ostat(p, uap, retval)
	struct proc *p;
	register struct ostat_args *uap;
	register_t *retval;
{
	struct stat sb;
	struct ostat osb;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	error = vn_stat(nd.ni_vp, &sb, p);
	vput(nd.ni_vp);
	if (error)
		return (error);
	cvtstat(&sb, &osb);
	error = copyout((caddr_t)&osb, (caddr_t)uap->ub, sizeof (osb));
	return (error);
}

/*
 * Get file status; this version does not follow links.
 */
struct olstat_args {
	char	*path;
	struct ostat *ub;
};
/* ARGSUSED */
int
olstat(p, uap, retval)
	struct proc *p;
	register struct olstat_args *uap;
	register_t *retval;
{
	struct vnode *vp, *dvp;
	struct stat sb, sb1;
	struct ostat osb;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, NOFOLLOW | LOCKLEAF | LOCKPARENT, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	/*
	 * For symbolic links, always return the attributes of its
	 * containing directory, except for mode, size, and links.
	 */
	vp = nd.ni_vp;
	dvp = nd.ni_dvp;
	if (vp->v_type != VLNK) {
		if (dvp == vp)
			vrele(dvp);
		else
			vput(dvp);
		error = vn_stat(vp, &sb, p);
		vput(vp);
		if (error)
			return (error);
	} else {
		error = vn_stat(dvp, &sb, p);
		vput(dvp);
		if (error) {
			vput(vp);
			return (error);
		}
		error = vn_stat(vp, &sb1, p);
		vput(vp);
		if (error)
			return (error);
		sb.st_mode &= ~S_IFDIR;
		sb.st_mode |= S_IFLNK;
		sb.st_nlink = sb1.st_nlink;
		sb.st_size = sb1.st_size;
		sb.st_blocks = sb1.st_blocks;
	}
	cvtstat(&sb, &osb);
	error = copyout((caddr_t)&osb, (caddr_t)uap->ub, sizeof (osb));
	return (error);
}

/*
 * Convert from an old to a new stat structure.
 */
void
cvtstat(st, ost)
	struct stat *st;
	struct ostat *ost;
{

	ost->st_dev = st->st_dev;
	ost->st_ino = st->st_ino;
	ost->st_mode = st->st_mode;
	ost->st_nlink = st->st_nlink;
	ost->st_uid = st->st_uid;
	ost->st_gid = st->st_gid;
	ost->st_rdev = st->st_rdev;
	if (st->st_size < (quad_t)1 << 32)
		ost->st_size = st->st_size;
	else
		ost->st_size = -2;
	ost->st_atime = st->st_atime;
	ost->st_mtime = st->st_mtime;
	ost->st_ctime = st->st_ctime;
	ost->st_blksize = st->st_blksize;
	ost->st_blocks = st->st_blocks;
	ost->st_flags = st->st_flags;
	ost->st_gen = st->st_gen;
}
#endif /* COMPAT_43 */

/*
 * Get file status; this version follows links.
 */
struct stat_args {
	char	*path;
	struct stat *ub;
};
/* ARGSUSED */
int
stat(p, uap, retval)
	struct proc *p;
	register struct stat_args *uap;
	register_t *retval;
{
	struct stat sb;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	error = vn_stat(nd.ni_vp, &sb, p);
	vput(nd.ni_vp);
	if (error)
		return (error);
	error = copyout((caddr_t)&sb, (caddr_t)uap->ub, sizeof (sb));
	return (error);
}

/*
 * Get file status; this version does not follow links.
 */
struct lstat_args {
	char	*path;
	struct stat *ub;
};
/* ARGSUSED */
int
lstat(p, uap, retval)
	struct proc *p;
	register struct lstat_args *uap;
	register_t *retval;
{
	int error;
	struct vnode *vp, *dvp;
	struct stat sb, sb1;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, NOFOLLOW | LOCKLEAF | LOCKPARENT, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	/*
	 * For symbolic links, always return the attributes of its containing
	 * directory, except for mode, size, inode number, and links.
	 */
	vp = nd.ni_vp;
	dvp = nd.ni_dvp;
	if ((vp->v_type != VLNK) || ((vp->v_type == VLNK) && (vp->v_tag == VT_NFS))) {
		if (dvp == vp)
			vrele(dvp);
		else
			vput(dvp);
		error = vn_stat(vp, &sb, p);
		vput(vp);
		if (error)
			return (error);
		if (vp->v_type == VLNK)
        	sb.st_mode |= S_IFLNK;
	} else {
		error = vn_stat(dvp, &sb, p);
		vput(dvp);
		if (error) {
			vput(vp);
			return (error);
		}
		error = vn_stat(vp, &sb1, p);
		vput(vp);
		if (error)
			return (error);
		sb.st_mode &= ~S_IFDIR;
		sb.st_mode |= S_IFLNK;
		sb.st_nlink = sb1.st_nlink;
		sb.st_size = sb1.st_size;
		sb.st_blocks = sb1.st_blocks;
		sb.st_ino = sb1.st_ino;
	}
	error = copyout((caddr_t)&sb, (caddr_t)uap->ub, sizeof (sb));
	return (error);
}

/*
 * Get configurable pathname variables.
 */
struct pathconf_args {
	char	*path;
	int	name;
};
/* ARGSUSED */
int
pathconf(p, uap, retval)
	struct proc *p;
	register struct pathconf_args *uap;
	register_t *retval;
{
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	error = VOP_PATHCONF(nd.ni_vp, uap->name, retval);
	vput(nd.ni_vp);
	return (error);
}

/*
 * Return target name of a symbolic link.
 */
struct readlink_args {
	char	*path;
	char	*buf;
	int	count;
};
/* ARGSUSED */
int
readlink(p, uap, retval)
	struct proc *p;
	register struct readlink_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct iovec aiov;
	struct uio auio;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, NOFOLLOW | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	if (vp->v_type != VLNK)
		error = EINVAL;
	else {
		aiov.iov_base = uap->buf;
		aiov.iov_len = uap->count;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_USERSPACE;
		auio.uio_procp = p;
		auio.uio_resid = uap->count;
		error = VOP_READLINK(vp, &auio, p->p_ucred);
	}
	vput(vp);
	*retval = uap->count - auio.uio_resid;
	return (error);
}

/*
 * Change flags of a file given a path name.
 */
struct chflags_args {
	char	*path;
	int	flags;
};
/* ARGSUSED */
int
chflags(p, uap, retval)
	struct proc *p;
	register struct chflags_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct vattr vattr;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	VATTR_NULL(&vattr);
	vattr.va_flags = uap->flags;
	error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
	vput(vp);
	return (error);
}

/*
 * Change flags of a file given a file descriptor.
 */
struct fchflags_args {
	int	fd;
	int	flags;
};
/* ARGSUSED */
int
fchflags(p, uap, retval)
	struct proc *p;
	register struct fchflags_args *uap;
	register_t *retval;
{
	struct vattr vattr;
	struct vnode *vp;
	struct file *fp;
	int error;

	if (error = getvnode(p, uap->fd, &fp))
		return (error);
	vp = (struct vnode *)fp->f_data;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	VATTR_NULL(&vattr);
	vattr.va_flags = uap->flags;
	error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * Change mode of a file given path name.
 */
struct chmod_args {
	char	*path;
	int	mode;
};
/* ARGSUSED */
int
chmod(p, uap, retval)
	struct proc *p;
	register struct chmod_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct vattr vattr;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	VATTR_NULL(&vattr);
	vattr.va_mode = uap->mode & ALLPERMS;
	error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
	vput(vp);
	return (error);
}

/*
 * Change mode of a file given a file descriptor.
 */
struct fchmod_args {
	int	fd;
	int	mode;
};
/* ARGSUSED */
int
fchmod(p, uap, retval)
	struct proc *p;
	register struct fchmod_args *uap;
	register_t *retval;
{
	struct vattr vattr;
	struct vnode *vp;
	struct file *fp;
	int error;

	if (error = getvnode(p, uap->fd, &fp))
		return (error);
	vp = (struct vnode *)fp->f_data;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	VATTR_NULL(&vattr);
	vattr.va_mode = uap->mode & ALLPERMS;
	error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * Set ownership given a path name.
 */
struct chown_args {
	char	*path;
	int	uid;
	int	gid;
};
/* ARGSUSED */
int
chown(p, uap, retval)
	struct proc *p;
	register struct chown_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct vattr vattr;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;

	/*
		XXX A TEMPORARY HACK FOR NOW: Try to track console_user
		by looking for chown() calls on /dev/console from a console process:
	 */
	if ((vp) && (vp->v_specinfo) &&
		(major(vp->v_specinfo->si_rdev) == CONSMAJOR) &&
		(minor(vp->v_specinfo->si_rdev) == 0)) {
		console_user = uap->uid;
	};
	
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	VATTR_NULL(&vattr);
	vattr.va_uid = uap->uid;
	vattr.va_gid = uap->gid;
	error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
	vput(vp);
	return (error);
}

/*
 * Set ownership given a file descriptor.
 */
struct fchown_args {
	int	fd;
	int	uid;
	int	gid;
};
/* ARGSUSED */
int
fchown(p, uap, retval)
	struct proc *p;
	register struct fchown_args *uap;
	register_t *retval;
{
	struct vattr vattr;
	struct vnode *vp;
	struct file *fp;
	int error;

	if (error = getvnode(p, uap->fd, &fp))
		return (error);
	vp = (struct vnode *)fp->f_data;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	VATTR_NULL(&vattr);
	vattr.va_uid = uap->uid;
	vattr.va_gid = uap->gid;
	error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * Set the access and modification times of a file.
 */
struct utimes_args {
	char	*path;
	struct	timeval *tptr;
};
/* ARGSUSED */
int
utimes(p, uap, retval)
	struct proc *p;
	register struct utimes_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct timeval tv[2];
	struct vattr vattr;
	int error;
	struct nameidata nd;

	VATTR_NULL(&vattr);
	if (uap->tptr == NULL) {
		microtime(&tv[0]);
		tv[1] = tv[0];
		vattr.va_vaflags |= VA_UTIMES_NULL;
	} else if (error = copyin((caddr_t)uap->tptr, (caddr_t)tv,
	    sizeof (tv)))
  		return (error);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	vattr.va_atime.tv_sec = tv[0].tv_sec;
	vattr.va_atime.tv_nsec = tv[0].tv_usec * 1000;
	vattr.va_mtime.tv_sec = tv[1].tv_sec;
	vattr.va_mtime.tv_nsec = tv[1].tv_usec * 1000;
	error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
	vput(vp);
	return (error);
}

/*
 * Truncate a file given its path name.
 */
struct truncate_args {
	char	*path;
#ifdef DOUBLE_ALIGN_PARAMS
	int	pad;
#endif
	off_t	length;
};
/* ARGSUSED */
int
truncate(p, uap, retval)
	struct proc *p;
	register struct truncate_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct vattr vattr;
	int error;
	struct nameidata nd;

        if (uap->length < 0)
                return(EINVAL);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	if (vp->v_type == VDIR)
		error = EISDIR;
	else if ((error = vn_writechk(vp)) == 0 &&
	    (error = VOP_ACCESS(vp, VWRITE, p->p_ucred, p)) == 0) {
		VATTR_NULL(&vattr);
		vattr.va_size = uap->length;
		error = VOP_SETATTR(vp, &vattr, p->p_ucred, p);
	}
	vput(vp);
	return (error);
}

/*
 * Truncate a file given a file descriptor.
 */
struct ftruncate_args {
	int	fd;
#ifdef DOUBLE_ALIGN_PARAMS
	int	pad;
#endif
	off_t	length;
};
/* ARGSUSED */
int
ftruncate(p, uap, retval)
	struct proc *p;
	register struct ftruncate_args *uap;
	register_t *retval;
{
	struct vattr vattr;
	struct vnode *vp;
	struct file *fp;
	int error;

        if (uap->length < 0)
                return(EINVAL);
        
	if (error = fdgetf(p, uap->fd, &fp))
		return (error);

	if (fp->f_type == DTYPE_PSXSHM) {
		return(pshm_truncate(p, fp, uap->fd, uap->length, retval));
	}
	if (fp->f_type != DTYPE_VNODE) 
		return (EINVAL);

	
	if ((fp->f_flag & FWRITE) == 0)
		return (EINVAL);
	vp = (struct vnode *)fp->f_data;
	VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	if (vp->v_type == VDIR)
		error = EISDIR;
	else if ((error = vn_writechk(vp)) == 0) {
		VATTR_NULL(&vattr);
		vattr.va_size = uap->length;
		error = VOP_SETATTR(vp, &vattr, fp->f_cred, p);
	}
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

#if COMPAT_43
/*
 * Truncate a file given its path name.
 */
struct otruncate_args {
	char	*path;
	long	length;
};
/* ARGSUSED */
int
otruncate(p, uap, retval)
	struct proc *p;
	register struct otruncate_args *uap;
	register_t *retval;
{
	struct truncate_args /* {
		syscallarg(char *) path;
#ifdef DOUBLE_ALIGN_PARAMS
		syscallarg(int) pad;
#endif
		syscallarg(off_t) length;
	} */ nuap;

	nuap.path = uap->path;
	nuap.length = uap->length;
	return (truncate(p, &nuap, retval));
}

/*
 * Truncate a file given a file descriptor.
 */
struct oftruncate_args {
	int	fd;
	long	length;
};
/* ARGSUSED */
int
oftruncate(p, uap, retval)
	struct proc *p;
	register struct oftruncate_args *uap;
	register_t *retval;
{
	struct ftruncate_args /* {
		syscallarg(int) fd;
#ifdef DOUBLE_ALIGN_PARAMS
		syscallarg(int) pad;
#endif
		syscallarg(off_t) length;
	} */ nuap;

	nuap.fd = uap->fd;
	nuap.length = uap->length;
	return (ftruncate(p, &nuap, retval));
}
#endif /* COMPAT_43 */

/*
 * Sync an open file.
 */
struct fsync_args {
	int	fd;
};
/* ARGSUSED */
int
fsync(p, uap, retval)
	struct proc *p;
	struct fsync_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct file *fp;
	int error;

	if (error = getvnode(p, uap->fd, &fp))
		return (error);
	vp = (struct vnode *)fp->f_data;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	error = VOP_FSYNC(vp, fp->f_cred, MNT_WAIT, p);
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * Duplicate files.  Source must be a file, target must be a file or 
 * must not exist.
 */

struct copyfile_args {
	char	*from;
	char	*to;
        int	mode;
        int 	flags;
};
/* ARGSUSED */
int
copyfile(p, uap, retval)
	struct proc *p;
	register struct copyfile_args *uap;
	register_t *retval;
{
	register struct vnode *tvp, *fvp, *tdvp;
        register struct ucred *cred = p->p_ucred;
	struct nameidata fromnd, tond;
	int error;
        
        /* Check that the flags are valid.  
         */

	if (uap->flags & ~CPF_MASK) {
           return(EINVAL);
        }

	NDINIT(&fromnd, LOOKUP, SAVESTART, UIO_USERSPACE,
	    uap->from, p);
	if (error = namei(&fromnd))
		return (error);
	fvp = fromnd.ni_vp;

	NDINIT(&tond, CREATE,  LOCKPARENT | LOCKLEAF | NOCACHE | SAVESTART,
	    UIO_USERSPACE, uap->to, p);
	if (error = namei(&tond)) {
		vrele(fvp);
		goto out1;
	}
	tdvp = tond.ni_dvp;
	tvp = tond.ni_vp;
	if (tvp != NULL) {
		if (!(uap->flags & CPF_OVERWRITE)) {
			error = EEXIST;
			goto out;
		}
	}

	if (fvp->v_type == VDIR || (tvp && tvp->v_type == VDIR)) {
		error = EISDIR;
		goto out;
	}

        if (error = VOP_ACCESS(tdvp, VWRITE, cred, p)) 	
		goto out;

	if (fvp == tdvp)
		error = EINVAL;
	/*
	 * If source is the same as the destination (that is the
	 * same inode number) then there is nothing to do.
	 * (fixed to have POSIX semantics - CSM 3/2/98)
	 */
	if (fvp == tvp)
		error = -1;
out:
	if (!error) {
		error = VOP_COPYFILE(fvp,tdvp,tvp,&tond.ni_cnd,uap->mode,uap->flags);
	} else {
		VOP_ABORTOP(tdvp, &tond.ni_cnd);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		if (tvp)
			vput(tvp);
		vrele(fvp);
	}
	vrele(tond.ni_startdir);
	FREE_ZONE(tond.ni_cnd.cn_pnbuf, tond.ni_cnd.cn_pnlen, M_NAMEI);
out1:
	if (fromnd.ni_startdir)
		vrele(fromnd.ni_startdir);
	FREE_ZONE(fromnd.ni_cnd.cn_pnbuf, fromnd.ni_cnd.cn_pnlen, M_NAMEI);
	if (error == -1)
		return (0);
	return (error);
}

/*
 * Rename files.  Source and destination must either both be directories,
 * or both not be directories.  If target is a directory, it must be empty.
 */
struct rename_args {
	char	*from;
	char	*to;
};
/* ARGSUSED */
int
rename(p, uap, retval)
	struct proc *p;
	register struct rename_args *uap;
	register_t *retval;
{
	register struct vnode *tvp, *fvp, *tdvp;
	struct nameidata fromnd, tond;
	int error;
	int mntrename;

	mntrename = FALSE;

	NDINIT(&fromnd, DELETE, WANTPARENT | SAVESTART, UIO_USERSPACE,
	    uap->from, p);
	if (error = namei(&fromnd))
		return (error);
	fvp = fromnd.ni_vp;

	NDINIT(&tond, RENAME, LOCKPARENT | LOCKLEAF | NOCACHE | SAVESTART,
	    UIO_USERSPACE, uap->to, p);
	if (error = namei(&tond)) {
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		goto out2;
	}
	tdvp = tond.ni_dvp;
	tvp = tond.ni_vp;

	if (tvp != NULL) {
		if (fvp->v_type == VDIR && tvp->v_type != VDIR) {
			error = ENOTDIR;
			goto out;
		} else if (fvp->v_type != VDIR && tvp->v_type == VDIR) {
			error = EISDIR;
			goto out;
		}
	}
	if (fvp == tdvp)
		error = EINVAL;
	/*
	 * If source is the same as the destination (that is the
	 * same inode number) then there is nothing to do.
	 */
	if (fvp == tvp)
		error = -1;
	
	/*
	 * Allow the renaming of mount points.
	 * - target must not exist
	 * - target must reside in the same directory as source
	 * - union mounts cannot be renamed
	 * - "/" cannot be renamed
	 */
	if ((fvp->v_flag & VROOT)  &&
	    (fvp->v_type == VDIR) &&
	    (tvp == NULL)  &&
	    (fvp->v_mountedhere == NULL)  &&
	    (fromnd.ni_dvp == tond.ni_dvp)  &&
	    ((fvp->v_mount->mnt_flag & (MNT_UNION | MNT_ROOTFS)) == 0)  &&
	    (fvp->v_mount->mnt_vnodecovered != NULLVP)) {
	
		/* switch fvp to the covered vnode */
		fromnd.ni_vp = fvp->v_mount->mnt_vnodecovered;
		vrele(fvp);
		fvp = fromnd.ni_vp;
		VREF(fvp);
		mntrename = TRUE;
	}
out:
	if (!error) {
		VOP_LEASE(tdvp, p, p->p_ucred, LEASE_WRITE);
		if (fromnd.ni_dvp != tdvp)
			VOP_LEASE(fromnd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
		if (tvp)
			VOP_LEASE(tvp, p, p->p_ucred, LEASE_WRITE);
		error = VOP_RENAME(fromnd.ni_dvp, fvp, &fromnd.ni_cnd,
				   tond.ni_dvp, tvp, &tond.ni_cnd);
		if (error)
			goto out1;
		
		/*
		 * update filesystem's mount point data
		 */
		if (mntrename) {
			char *cp, *pathend, *mpname;
			char * tobuf;
			struct mount *mp;
			int maxlen;
			size_t len = 0;

			VREF(fvp);
			vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY, p);
			mp = fvp->v_mountedhere;

			if (vfs_busy(mp, LK_NOWAIT, 0, p)) {
				vput(fvp);
				error = EBUSY;
				goto out1;
			}
			VOP_UNLOCK(fvp, 0, p);
			
			MALLOC_ZONE(tobuf, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
			error = copyinstr(uap->to, tobuf, MAXPATHLEN, &len);
			if (!error) {
				/* find current mount point prefix */
				pathend = &mp->mnt_stat.f_mntonname[0];
				for (cp = pathend; *cp != '\0'; ++cp) {
					if (*cp == '/')
						pathend = cp + 1;
				}
				/* find last component of target name */
				for (mpname = cp = tobuf; *cp != '\0'; ++cp) {
					if (*cp == '/')
						mpname = cp + 1;
				}
				/* append name to prefix */
				maxlen = MNAMELEN - (pathend - mp->mnt_stat.f_mntonname);
				bzero(pathend, maxlen);
				strncpy(pathend, mpname, maxlen - 1);
			}
			FREE_ZONE(tobuf, MAXPATHLEN, M_NAMEI);

			vrele(fvp);
			vfs_unbusy(mp, p);
		}
	} else {
		VOP_ABORTOP(tond.ni_dvp, &tond.ni_cnd);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		if (tvp)
			vput(tvp);
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
	}
out1:
	vrele(tond.ni_startdir);
	FREE_ZONE(tond.ni_cnd.cn_pnbuf, tond.ni_cnd.cn_pnlen, M_NAMEI);
out2:
	if (fromnd.ni_startdir)
		vrele(fromnd.ni_startdir);
	FREE_ZONE(fromnd.ni_cnd.cn_pnbuf, fromnd.ni_cnd.cn_pnlen, M_NAMEI);
	if (error == -1)
		return (0);
	return (error);
}

/*
 * Make a directory file.
 */
struct mkdir_args {
	char	*path;
	int	mode;
};
/* ARGSUSED */
int
mkdir(p, uap, retval)
	struct proc *p;
	register struct mkdir_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct vattr vattr;
	int error;
	struct nameidata nd;

	NDINIT(&nd, CREATE, LOCKPARENT, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	if (vp != NULL) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		return (EEXIST);
	}
	VATTR_NULL(&vattr);
	vattr.va_type = VDIR;
	vattr.va_mode = (uap->mode & ACCESSPERMS) &~ p->p_fd->fd_cmask;
	VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
	error = VOP_MKDIR(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
	if (!error)
		vput(nd.ni_vp);
	return (error);
}

/*
 * Remove a directory file.
 */
struct rmdir_args {
	char	*path;
};
/* ARGSUSED */
int
rmdir(p, uap, retval)
	struct proc *p;
	struct rmdir_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	int error;
	struct nameidata nd;

	NDINIT(&nd, DELETE, LOCKPARENT | LOCKLEAF, UIO_USERSPACE,
	    uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}
	/*
	 * No rmdir "." please.
	 */
	if (nd.ni_dvp == vp) {
		error = EINVAL;
		goto out;
	}
	/*
	 * The root of a mounted filesystem cannot be deleted.
	 */
	if (vp->v_flag & VROOT)
		error = EBUSY;
out:
	if (!error) {
		VOP_LEASE(nd.ni_dvp, p, p->p_ucred, LEASE_WRITE);
		VOP_LEASE(vp, p, p->p_ucred, LEASE_WRITE);
		error = VOP_RMDIR(nd.ni_dvp, nd.ni_vp, &nd.ni_cnd);
	} else {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vput(vp);
	}
	return (error);
}

#if COMPAT_43
/*
 * Read a block of directory entries in a file system independent format.
 */
struct ogetdirentries_args {
	int	fd;
	char	*buf;
	u_int	count;
	long	*basep;
};
int
ogetdirentries(p, uap, retval)
	struct proc *p;
	register struct ogetdirentries_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct file *fp;
	struct uio auio, kuio;
	struct iovec aiov, kiov;
	struct dirent *dp, *edp;
	caddr_t dirbuf;
	int error, eofflag, readcnt;
	long loff;

	if (error = getvnode(p, uap->fd, &fp))
		return (error);
	if ((fp->f_flag & FREAD) == 0)
		return (EBADF);
	vp = (struct vnode *)fp->f_data;
unionread:
	if (vp->v_type != VDIR)
		return (EINVAL);
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_procp = p;
	auio.uio_resid = uap->count;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	loff = auio.uio_offset = fp->f_offset;
#	if (BYTE_ORDER != LITTLE_ENDIAN)
		if (vp->v_mount->mnt_maxsymlinklen <= 0) {
			error = VOP_READDIR(vp, &auio, fp->f_cred, &eofflag,
			    (int *)0, (u_long *)0);
			fp->f_offset = auio.uio_offset;
		} else
#	endif
	{
		kuio = auio;
		kuio.uio_iov = &kiov;
		kuio.uio_segflg = UIO_SYSSPACE;
		kiov.iov_len = uap->count;
		MALLOC(dirbuf, caddr_t, uap->count, M_TEMP, M_WAITOK);
		kiov.iov_base = dirbuf;
		error = VOP_READDIR(vp, &kuio, fp->f_cred, &eofflag,
			    (int *)0, (u_long *)0);
		fp->f_offset = kuio.uio_offset;
		if (error == 0) {
			readcnt = uap->count - kuio.uio_resid;
			edp = (struct dirent *)&dirbuf[readcnt];
			for (dp = (struct dirent *)dirbuf; dp < edp; ) {
#				if (BYTE_ORDER == LITTLE_ENDIAN)
					/*
					 * The expected low byte of
					 * dp->d_namlen is our dp->d_type.
					 * The high MBZ byte of dp->d_namlen
					 * is our dp->d_namlen.
					 */
					dp->d_type = dp->d_namlen;
					dp->d_namlen = 0;
#				else
					/*
					 * The dp->d_type is the high byte
					 * of the expected dp->d_namlen,
					 * so must be zero'ed.
					 */
					dp->d_type = 0;
#				endif
				if (dp->d_reclen > 0) {
					dp = (struct dirent *)
					    ((char *)dp + dp->d_reclen);
				} else {
					error = EIO;
					break;
				}
			}
			if (dp >= edp)
				error = uiomove(dirbuf, readcnt, &auio);
		}
		FREE(dirbuf, M_TEMP);
	}
	VOP_UNLOCK(vp, 0, p);
	if (error)
		return (error);

#if UNION
{
	extern int (**union_vnodeop_p)(void *);
	extern struct vnode *union_dircache __P((struct vnode*, struct proc*));

	if ((uap->count == auio.uio_resid) &&
	    (vp->v_op == union_vnodeop_p)) {
		struct vnode *lvp;

		lvp = union_dircache(vp, p);
		if (lvp != NULLVP) {
			struct vattr va;

			/*
			 * If the directory is opaque,
			 * then don't show lower entries
			 */
			error = VOP_GETATTR(vp, &va, fp->f_cred, p);
			if (va.va_flags & OPAQUE) {
				vput(lvp);
				lvp = NULL;
			}
		}
		
		if (lvp != NULLVP) {
			error = VOP_OPEN(lvp, FREAD, fp->f_cred, p);
			if (error) {
				vput(lvp);
				return (error);
			}
			VOP_UNLOCK(lvp, 0, p);
			fp->f_data = (caddr_t) lvp;
			fp->f_offset = 0;
			error = vn_close(vp, FREAD, fp->f_cred, p);
			if (error)
				return (error);
			vp = lvp;
			goto unionread;
		}
	}
}
#endif /* UNION */

	if ((uap->count == auio.uio_resid) &&
	    (vp->v_flag & VROOT) &&
	    (vp->v_mount->mnt_flag & MNT_UNION)) {
		struct vnode *tvp = vp;
		vp = vp->v_mount->mnt_vnodecovered;
		VREF(vp);
		fp->f_data = (caddr_t) vp;
		fp->f_offset = 0;
		vrele(tvp);
		goto unionread;
	}
	error = copyout((caddr_t)&loff, (caddr_t)uap->basep,
	    sizeof(long));
	*retval = uap->count - auio.uio_resid;
	return (error);
}
#endif /* COMPAT_43 */

/*
 * Read a block of directory entries in a file system independent format.
 */
struct getdirentries_args {
	int	fd;
	char	*buf;
	u_int	count;
	long	*basep;
};
int
getdirentries(p, uap, retval)
	struct proc *p;
	register struct getdirentries_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct file *fp;
	struct uio auio;
	struct iovec aiov;
	long loff;
	int error, eofflag;

	if (error = getvnode(p, uap->fd, &fp))
		return (error);
	if ((fp->f_flag & FREAD) == 0)
		return (EBADF);
	vp = (struct vnode *)fp->f_data;
unionread:
	if (vp->v_type != VDIR)
		return (EINVAL);
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->count;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_procp = p;
	auio.uio_resid = uap->count;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	loff = auio.uio_offset = fp->f_offset;
	error = VOP_READDIR(vp, &auio, fp->f_cred, &eofflag,
			    (int *)0, (u_long *)0);
	fp->f_offset = auio.uio_offset;
	VOP_UNLOCK(vp, 0, p);
	if (error)
		return (error);

#if UNION
{
	extern int (**union_vnodeop_p)(void *);
	extern struct vnode *union_dircache __P((struct vnode*, struct proc*));

	if ((uap->count == auio.uio_resid) &&
	    (vp->v_op == union_vnodeop_p)) {
		struct vnode *lvp;

		lvp = union_dircache(vp, p);
		if (lvp != NULLVP) {
			struct vattr va;

			/*
			 * If the directory is opaque,
			 * then don't show lower entries
			 */
			error = VOP_GETATTR(vp, &va, fp->f_cred, p);
			if (va.va_flags & OPAQUE) {
				vput(lvp);
				lvp = NULL;
			}
		}

		if (lvp != NULLVP) {
			error = VOP_OPEN(lvp, FREAD, fp->f_cred, p);
			if (error) {
				vput(lvp);
				return (error);
			}
			VOP_UNLOCK(lvp, 0, p);
			fp->f_data = (caddr_t) lvp;
			fp->f_offset = 0;
			error = vn_close(vp, FREAD, fp->f_cred, p);
			if (error)
				return (error);
			vp = lvp;
			goto unionread;
		}
	}
}
#endif /* UNION */

	if ((uap->count == auio.uio_resid) &&
	    (vp->v_flag & VROOT) &&
	    (vp->v_mount->mnt_flag & MNT_UNION)) {
		struct vnode *tvp = vp;
		vp = vp->v_mount->mnt_vnodecovered;
		VREF(vp);
		fp->f_data = (caddr_t) vp;
		fp->f_offset = 0;
		vrele(tvp);
		goto unionread;
	}
	error = copyout((caddr_t)&loff, (caddr_t)uap->basep,
	    sizeof(long));
	*retval = uap->count - auio.uio_resid;
	return (error);
}

/*
 * Set the mode mask for creation of filesystem nodes.
 */
struct umask_args {
	int	newmask;
};
int
umask(p, uap, retval)
	struct proc *p;
	struct umask_args *uap;
	register_t *retval;
{
	register struct filedesc *fdp;

	fdp = p->p_fd;
	*retval = fdp->fd_cmask;
	fdp->fd_cmask = uap->newmask & ALLPERMS;
	return (0);
}

/*
 * Void all references to file by ripping underlying filesystem
 * away from vnode.
 */
struct revoke_args {
	char	*path;
};
/* ARGSUSED */
int
revoke(p, uap, retval)
	struct proc *p;
	register struct revoke_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	struct vattr vattr;
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, uap->path, p);
	if (error = namei(&nd))
		return (error);
	vp = nd.ni_vp;
	if (error = VOP_GETATTR(vp, &vattr, p->p_ucred, p))
		goto out;
	if (p->p_ucred->cr_uid != vattr.va_uid &&
	    (error = suser(p->p_ucred, &p->p_acflag)))
		goto out;
	if (vp->v_usecount > 1 || (vp->v_flag & VALIASED))
		VOP_REVOKE(vp, REVOKEALL);
out:
	vrele(vp);
	return (error);
}

/*
 * Convert a user file descriptor to a kernel file entry.
 */
int
getvnode(p, fd, fpp)
	struct proc *p;
	int fd;
	struct file **fpp;
{
	struct file *fp;
	int error;

	if (error = fdgetf(p, fd, &fp))
		return (error);
	if (fp->f_type != DTYPE_VNODE)
		return (EINVAL);
	*fpp = fp;
	return (0);
}
/*
 *  HFS/HFS PlUS SPECIFIC SYSTEM CALLS
 *  The following 10 system calls are designed to support features
 *  which are specific to the HFS & HFS Plus volume formats
 */


/*
 * Make a complex file.  A complex file is one with multiple forks (data streams)
 */
struct mkcomplex_args {
        const char *path;	/* pathname of the file to be created */
	mode_t mode;		/* access mode for the newly created file */
        u_long type;		/* format of the complex file */
};
/* ARGSUSED */
int
mkcomplex(p,uap,retval)
	struct proc *p;
        register struct mkcomplex_args *uap;
        register_t *retval;
			
{
	struct vnode *vp;
        struct vattr vattr;
        int error;
        struct nameidata nd;

	/* mkcomplex wants the directory vnode locked so do that here */

        NDINIT(&nd, CREATE, FOLLOW | LOCKPARENT, UIO_USERSPACE, (char *)uap->path, p);
        if (error = namei(&nd))
                return (error);

	/*  Set the attributes as specified by the user */

        VATTR_NULL(&vattr);
        vattr.va_mode = (uap->mode & ACCESSPERMS);
        error = VOP_MKCOMPLEX(nd.ni_dvp, &vp, &nd.ni_cnd, &vattr, uap->type);

	/*  The mkcomplex call promises to release the parent vnode pointer
	 *  even an an error case so don't do it here unless the operation
	 *  is not supported.  In that case, there isn't anyone to unlock the parent
	 *  The vnode pointer to the file will also be released.
	 */

        if (error)
		{
       		if (error == EOPNOTSUPP)
		   	vput(nd.ni_dvp);
                return (error);
	        }

        return (0);

} /* end of mkcomplex system call */



/*
 * Extended stat call which returns volumeid and vnodeid as well as other info
 */
struct statv_args {
        const char *path;	/* pathname of the target file       */
        struct vstat *vsb;	/* vstat structure for returned info */
};
/* ARGSUSED */
int
statv(p,uap,retval)
        struct proc *p;
        register struct statv_args *uap;
        register_t *retval;

{
	return (EOPNOTSUPP);	/*  We'll just return an error for now */

} /* end of statv system call */



/*
* Extended lstat call which returns volumeid and vnodeid as well as other info
*/
struct lstatv_args {
       const char *path;	/* pathname of the target file       */
       struct vstat *vsb;	/* vstat structure for returned info */
};
/* ARGSUSED */
int
lstatv(p,uap,retval)
       struct proc *p;
       register struct lstatv_args *uap;
       register_t *retval;

{
       return (EOPNOTSUPP);	/*  We'll just return an error for now */
} /* end of lstatv system call */



/*
* Extended fstat call which returns volumeid and vnodeid as well as other info
*/
struct fstatv_args {
       int fd;			/* file descriptor of the target file */
       struct vstat *vsb;	/* vstat structure for returned info  */
};
/* ARGSUSED */
int
fstatv(p,uap,retval)
       struct proc *p;
       register struct fstatv_args *uap;
       register_t *retval;

{
       return (EOPNOTSUPP);	/*  We'll just return an error for now */
} /* end of fstatv system call */



/*
* Obtain attribute information about a file system object
*/

struct getattrlist_args {
       const char *path;	/* pathname of the target object */
       struct attrlist * alist; /* Attributes desired by the user */
       void * attributeBuffer; 	/* buffer to hold returned attributes */
       size_t bufferSize;	/* size of the return buffer */
       unsigned long options;   /* options (follow/don't follow) */
};
/* ARGSUSED */
int
getattrlist (p,uap,retval)
       struct proc *p;
       register struct getattrlist_args *uap;
       register_t *retval;

{
        int error;
        struct nameidata nd;	
	struct iovec aiov;
	struct uio auio;
        struct attrlist attributelist;
	u_long nameiflags;

	/* Get the attributes desire and do our parameter checking */

	if (error = copyin((caddr_t)uap->alist, (caddr_t) &attributelist,
                 sizeof (attributelist)))
		{
		return(error);
		}

	if (attributelist.bitmapcount != ATTR_BIT_MAP_COUNT
#if 0
	    ||	attributelist.commonattr & ~ATTR_CMN_VALIDMASK ||
		attributelist.volattr & ~ATTR_VOL_VALIDMASK ||
		attributelist.dirattr & ~ATTR_DIR_VALIDMASK ||
		attributelist.fileattr & ~ATTR_FILE_VALIDMASK ||
		attributelist.forkattr & ~ATTR_FORK_VALIDMASK
#endif
	)
		{
		return (EINVAL);
		}

	/* Get the vnode for the file we are getting info on.  */
	nameiflags = LOCKLEAF;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
        NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, (char *)uap->path, p);

        if (error = namei(&nd))
                return (error);

	/* Set up the UIO structure for use by the vfs routine */

	
	aiov.iov_base = uap->attributeBuffer;
        aiov.iov_len = uap->bufferSize;  
  	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
        auio.uio_offset = 0;
        auio.uio_rw = UIO_READ;
        auio.uio_segflg = UIO_USERSPACE;
        auio.uio_procp = p;
        auio.uio_resid = uap->bufferSize;


        error = VOP_GETATTRLIST(nd.ni_vp, &attributelist, &auio, p->p_ucred, p);

	/* Unlock and release the vnode which will have been locked by namei */

        vput(nd.ni_vp);

        /* return the effort if we got one, otherwise return success */

        if (error)
            {
            return (error);
            }

        return(0);

} /* end of getattrlist system call */



/*
 * Set attribute information about a file system object
 */

struct setattrlist_args {
      const char *path;		/* pathname of the target object 	  */
      struct attrlist * alist;  /* Attributes being set  by the user 	  */
      void * attributeBuffer; 	/* buffer with attribute values to be set */
      size_t bufferSize;	/* size of the return buffer 		  */
      unsigned long options;    /* options (follow/don't follow) */
};
/* ARGSUSED */
int
setattrlist (p,uap,retval)
      struct proc *p;
      register struct setattrlist_args *uap;
      register_t *retval;

{
	int error;
	struct nameidata nd;	
	struct iovec aiov;
	struct uio auio;
	struct attrlist alist;
	u_long nameiflags;

       /* Get the attributes desired and do our parameter checking */

	if ((error = copyin((caddr_t)uap->alist, (caddr_t) &alist,
	    sizeof (alist)))) {
		return (error);
	}

	if (alist.bitmapcount != ATTR_BIT_MAP_COUNT)
		return (EINVAL);

	/* Get the vnode for the file whose attributes are being set. */
	nameiflags = LOCKLEAF;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, (char *)uap->path, p);
	if (error = namei(&nd))
		return (error);

	/* Set up the UIO structure for use by the vfs routine */
	aiov.iov_base = uap->attributeBuffer;
	aiov.iov_len = uap->bufferSize;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = 0;
	auio.uio_rw = UIO_WRITE;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_procp = p;
	auio.uio_resid = uap->bufferSize;

	error = VOP_SETATTRLIST(nd.ni_vp, &alist, &auio, p->p_ucred, p);

	vput(nd.ni_vp);

	return (error);

} /* end of setattrlist system call */


/*
* Obtain attribute information on objects in a directory while enumerating
* the directory.  This call does not yet support union mounted directories.
* TO DO
*  1.union mounted directories.
*/

struct getdirentriesattr_args {
      int fd;			/* file descriptor */
      struct attrlist *alist;   /* bit map of requested attributes */
      void *buffer;		/* buffer to hold returned attribute info */
      size_t buffersize; 	/* size of the return buffer */
      u_long *count;		/* the count of entries requested/returned */
      u_long *basep;		/* the offset of where we are leaving off in buffer */
      u_long *newstate;		/* a flag to inform of changes in directory */
      u_long options;		/* maybe unused for now */
};
/* ARGSUSED */
int
getdirentriesattr (p,uap,retval)
      struct proc *p;
      register struct getdirentriesattr_args *uap;
      register_t *retval;

{
        register struct vnode *vp;
        struct file *fp;
        struct uio auio;
        struct iovec aiov;
        u_long actualcount;
        u_long newstate;
        int error, eofflag;
        long loff;
        struct attrlist attributelist; 

        /* Get the attributes into kernel space */
        if (error = copyin((caddr_t)uap->alist, (caddr_t) &attributelist, sizeof (attributelist)))
           return(error);
        if (error = copyin((caddr_t)uap->count, (caddr_t) &actualcount, sizeof (u_long)))
           return(error);

        if (error = getvnode(p, uap->fd, &fp))
                return (error);
        if ((fp->f_flag & FREAD) == 0)
                return(EBADF);
        vp = (struct vnode *)fp->f_data;

        if (vp->v_type != VDIR)
            return(EINVAL);

	/* set up the uio structure which will contain the users return buffer */
        aiov.iov_base = uap->buffer;
        aiov.iov_len = uap->buffersize;
        auio.uio_iov = &aiov;
        auio.uio_iovcnt = 1;
        auio.uio_rw = UIO_READ;
        auio.uio_segflg = UIO_USERSPACE;
        auio.uio_procp = p;
        auio.uio_resid = uap->buffersize;
        
        loff = auio.uio_offset = fp->f_offset;
        vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
        error = VOP_READDIRATTR (vp, &attributelist, &auio,
                   actualcount, uap->options, &newstate, &eofflag,
                   &actualcount, ((u_long **)0), p->p_cred);

        VOP_UNLOCK(vp, 0, p);
        if (error) return (error);
        fp->f_offset = auio.uio_offset; /* should be multiple of dirent, not variable */

        if (error = copyout((caddr_t) &actualcount, (caddr_t) uap->count, sizeof(u_long)))
            return (error);
        if (error = copyout((caddr_t) &newstate, (caddr_t) uap->newstate, sizeof(u_long)))
            return (error);
        if (error = copyout((caddr_t)&loff, (caddr_t)uap->basep, sizeof(long)))
            return (error);

	*retval = eofflag;  /* similar to getdirentries */
        return (0); /* return error earlier, an retval of 0 or 1 now */

} /* end of getdirentryattr system call */

/*
* Exchange data between two files
*/

struct exchangedata_args {
      const char *path1;	/* pathname of the first swapee  */
      const char *path2;	/* pathname of the second swapee */
      unsigned long options;    /* options */
};
/* ARGSUSED */
int
exchangedata (p,uap,retval)
      struct proc *p;
      register struct exchangedata_args *uap;
      register_t *retval;

{

	struct nameidata fnd, snd;
	struct vnode *fvp, *svp;
        int error;
	u_long nameiflags;

	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;

		/* Global lock, to prevent race condition, only one exchange at a time */
        lockmgr(&exchangelock, LK_EXCLUSIVE , (struct slock *)0, p);

        NDINIT(&fnd, LOOKUP, nameiflags, UIO_USERSPACE, (char *) uap->path1, p);

        if (error = namei(&fnd))
                goto out2;

        fvp = fnd.ni_vp;

        NDINIT(&snd, LOOKUP, nameiflags, UIO_USERSPACE, (char *)uap->path2, p);

        if (error = namei(&snd)) {
			vrele(fvp);
            goto out2;
	        }

	svp = snd.ni_vp;

	/* if the files are the same, return an inval error */
	if (svp == fvp) {
		vrele(fvp);
		vrele(svp);
        error = EINVAL;
		goto out2;
	 } 

    vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY, p);
    vn_lock(svp, LK_EXCLUSIVE | LK_RETRY, p);

	error = VOP_ACCESS(fvp, VWRITE, p->p_ucred, p);
	if (error) goto out;

	error = VOP_ACCESS(svp, VWRITE, p->p_ucred, p);
	if (error) goto out;

	/* Ok, make the call */
	error = VOP_EXCHANGE (fvp, svp, p->p_ucred, p);

out:
    vput (svp);
	vput (fvp);

out2:
    lockmgr(&exchangelock, LK_RELEASE, (struct slock *)0, p);

	if (error) {
        return (error);
		}
	
	return (0);

} /* end of exchangedata system call */

/*
* Check users access to a file 
*/

struct checkuseraccess_args {
     const char *path;		/* pathname of the target file   */
     uid_t userid;		/* user for whom we are checking access */
     gid_t *groups;		/* Group that we are checking for */
     int ngroups;	        /* Number of groups being checked */
     int accessrequired; 	/* needed access to the file */
     unsigned long options;     /* options */
};

/* ARGSUSED */
int
checkuseraccess (p,uap,retval)
     struct proc *p;
     register struct checkuseraccess_args *uap;
     register_t *retval;

{
	register struct vnode *vp;
	int error;
	struct nameidata nd;
	struct ucred cred;
	int flags;		/*what will actually get passed to access*/
	u_long nameiflags;

	/* Make sure that the number of groups is correct before we do anything */

	if ((uap->ngroups <=  0) || (uap->ngroups > NGROUPS))
		return (EINVAL);

	/* Verify that the caller is root */
	
	if (error = suser(p->p_ucred, &p->p_acflag))
		return(error);

	/* Fill in the credential structure */

	cred.cr_ref = 0;
	cred.cr_uid = uap->userid;
	cred.cr_ngroups = uap->ngroups;
	if (error = copyin((caddr_t) uap->groups, (caddr_t) &(cred.cr_groups), (sizeof(gid_t))*uap->ngroups))
		return (error);

	/* Get our hands on the file */

	nameiflags = LOCKLEAF;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, (char *)uap->path, p);

	if (error = namei(&nd))
       		 return (error);
	vp = nd.ni_vp;
	
	/* Flags == 0 means only check for existence. */

	flags = 0;

	if (uap->accessrequired) {
		if (uap->accessrequired & R_OK)
			flags |= VREAD;
		if (uap->accessrequired & W_OK)
			flags |= VWRITE;
		if (uap->accessrequired & X_OK)
			flags |= VEXEC;
		}
	error = VOP_ACCESS(vp, flags, &cred, p);
		    	
	vput(vp);

	if (error) 
 		return (error);
	
	return (0); 

} /* end of checkuseraccess system call */


struct searchfs_args {
	const char *path;
	struct fssearchblock *searchblock; 
	u_long *nummatches;
	u_long scriptcode;
	u_long options;
 	struct searchstate *state; 
	};
/* ARGSUSED */

int
searchfs (p,uap,retval)
  	struct proc *p;
   	register struct searchfs_args *uap;
   	register_t *retval;

{
	register struct vnode *vp;
	int error=0;
	int fserror = 0;
	struct nameidata nd;
	struct fssearchblock searchblock;
	struct searchstate *state;
	struct attrlist *returnattrs;
	void *searchparams1,*searchparams2;
	struct iovec aiov;
	struct uio auio;
	u_long nummatches;
	int mallocsize;
	u_long nameiflags;
	

	/* Start by copying in fsearchblock paramater list */

	if (error = copyin((caddr_t) uap->searchblock, (caddr_t) &searchblock,sizeof(struct fssearchblock)))
		return(error);

	/* Now malloc a big bunch of space to hold the search parameters, the attrlists and the search state. */
	/* It all has to do into local memory and it's not that big so we might as well  put it all together. */
	/* Searchparams1 shall be first so we might as well use that to hold the base address of the allocated*/
	/* block.  											      */
	
	mallocsize = searchblock.sizeofsearchparams1+searchblock.sizeofsearchparams2 +
		      sizeof(struct attrlist) + sizeof(struct searchstate);

	MALLOC(searchparams1, void *, mallocsize, M_TEMP, M_WAITOK);

	/* Now set up the various pointers to the correct place in our newly allocated memory */

	searchparams2 = (void *) (((caddr_t) searchparams1) + searchblock.sizeofsearchparams1);
	returnattrs = (struct attrlist *) (((caddr_t) searchparams2) + searchblock.sizeofsearchparams2);
	state = (struct searchstate *) (((caddr_t) returnattrs) + sizeof (struct attrlist));

	/* Now copy in the stuff given our local variables. */

	if (error = copyin((caddr_t) searchblock.searchparams1, searchparams1,searchblock.sizeofsearchparams1))
		goto freeandexit;

	if (error = copyin((caddr_t) searchblock.searchparams2, searchparams2,searchblock.sizeofsearchparams2))
		goto freeandexit;

	if (error = copyin((caddr_t) searchblock.returnattrs, (caddr_t) returnattrs, sizeof(struct attrlist)))
		goto freeandexit;
		
	if (error = copyin((caddr_t) uap->state, (caddr_t) state, sizeof(struct searchstate)))
		goto freeandexit;
	
	/* set up the uio structure which will contain the users return buffer */

	aiov.iov_base = searchblock.returnbuffer;
	aiov.iov_len = searchblock.returnbuffersize;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_procp = p;
	auio.uio_resid = searchblock.returnbuffersize;

	nameiflags = LOCKLEAF;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, (char *)uap->path, p);

	if (error = namei(&nd))
		goto freeandexit;

	vp = nd.ni_vp; 

	 
	/*
	 * If searchblock.maxmatches == 0, then skip the search. This has happened 
	 * before and sometimes the underlyning code doesnt deal with it well.
	 */
	 if (searchblock.maxmatches == 0) {
		nummatches = 0;
		goto saveandexit;
	 }

	/*
	   Allright, we have everything we need, so lets make that call.
	   
	   We keep special track of the return value from the file system:
	   EAGAIN is an acceptable error condition that shouldn't keep us
	   from copying out any results...
	 */

	fserror = VOP_SEARCHFS(vp,
							searchparams1,
							searchparams2,
							&searchblock.searchattrs,
							searchblock.maxmatches,
							&searchblock.timelimit,
							returnattrs,
							&nummatches,
							uap->scriptcode,
							uap->options,
							&auio,
							state);
		
saveandexit:

	vput(vp);

	/* Now copy out the stuff that needs copying out. That means the number of matches, the
	   search state.  Everything was already put into he return buffer by the vop call. */

	if (error = copyout((caddr_t) state, (caddr_t) uap->state, sizeof(struct searchstate)))
		goto freeandexit;

	if (error = copyout((caddr_t) &nummatches, (caddr_t) uap->nummatches, sizeof(u_long)))
		goto freeandexit;
	
	error = fserror;

freeandexit:

	FREE(searchparams1,M_TEMP);

	return(error);


} /* end of searchfs system call */


/*
 * Make a filesystem-specific control call:
 */
struct fsctl_args {
       const char *path;	/* pathname of the target object */
       u_long cmd;   		/* cmd (also encodes size/direction of arguments a la ioctl) */
       caddr_t data; 		/* pointer to argument buffer */
       u_long options;		/* options for fsctl processing */
};
/* ARGSUSED */
int
fsctl (p,uap,retval)
	struct proc *p;
	struct fsctl_args *uap;
	register_t *retval;

{
	int error;
	struct nameidata nd;	
	u_long nameiflags;
	u_long cmd = uap->cmd;
	register u_int size;
#define STK_PARAMS 128
	char stkbuf[STK_PARAMS];
	caddr_t data, memp;

	size = IOCPARM_LEN(cmd);
	if (size > IOCPARM_MAX) return (EINVAL);

	memp = NULL;
	if (size > sizeof (stkbuf)) {
		if ((memp = (caddr_t)kalloc(size)) == 0) return ENOMEM;
		data = memp;
	} else {
		data = stkbuf;
	};
	
	if (cmd & IOC_IN) {
		if (size) {
			error = copyin(uap->data, data, (u_int)size);
			if (error) goto FSCtl_Exit;
		} else {
			*(caddr_t *)data = uap->data;
		};
	} else if ((cmd & IOC_OUT) && size) {
		/*
		 * Zero the buffer so the user always
		 * gets back something deterministic.
		 */
		bzero(data, size);
	} else if (cmd & IOC_VOID)
		*(caddr_t *)data = uap->data;

	/* Get the vnode for the file we are getting info on:  */
	nameiflags = LOCKLEAF;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, (char *)uap->path, p);
	if (error = namei(&nd)) goto FSCtl_Exit;
	
	/* Invoke the filesystem-specific code */
	error = VOP_IOCTL(nd.ni_vp, IOCBASECMD(cmd), data, uap->options, p->p_ucred, p);
	
	vput(nd.ni_vp);
	
	/*
	 * Copy any data to user, size was
	 * already set and checked above.
	 */
	if (error == 0 && (cmd & IOC_OUT) && size) error = copyout(data, uap->data, (u_int)size);
	
FSCtl_Exit:
	if (memp) kfree(memp, size);
	
	return error;
}
/* end of fsctl system call */
