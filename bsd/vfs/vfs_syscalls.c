/*
 * Copyright (c) 1995-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/uio_internal.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/dirent.h>
#include <sys/attr.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <sys/quota.h>
#include <sys/kdebug.h>
#include <sys/fsevents.h>
#include <sys/sysproto.h>
#include <sys/xattr.h>
#include <sys/ubc_internal.h>
#include <machine/cons.h>
#include <machine/limits.h>
#include <miscfs/specfs/specdev.h>

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>

#include <vm/vm_pageout.h>

#include <libkern/OSAtomic.h>


/*
 * The currently logged-in user, for ownership of files/directories whose on-disk
 * permissions are ignored:
 */
uid_t console_user;

static int change_dir(struct nameidata *ndp, vfs_context_t ctx);
static void checkdirs(struct vnode *olddp, vfs_context_t ctx);
void enablequotas(struct mount *mp, vfs_context_t ctx);
static int getfsstat_callback(mount_t mp, void * arg);
static int getutimes(user_addr_t usrtvp, struct timespec *tsp);
static int setutimes(vfs_context_t ctx, struct vnode *vp, const struct timespec *ts, int nullflag);
static int sync_callback(mount_t, void *);
static int munge_statfs(struct mount *mp, struct vfsstatfs *sfsp, 
			user_addr_t bufp, int *sizep, boolean_t is_64_bit, 
						boolean_t partial_copy);

__private_extern__ int sync_internal(void);

#ifdef __APPLE_API_OBSOLETE
struct fstatv_args {
       int fd;			/* file descriptor of the target file */
       struct vstat *vsb;	/* vstat structure for returned info  */
};
struct lstatv_args {
       const char *path;	/* pathname of the target file       */
       struct vstat *vsb;	/* vstat structure for returned info */
};
struct mkcomplex_args {
        const char *path;	/* pathname of the file to be created */
		mode_t mode;		/* access mode for the newly created file */
        u_long type;		/* format of the complex file */
};
struct statv_args {
        const char *path;	/* pathname of the target file       */
        struct vstat *vsb;	/* vstat structure for returned info */
};

int fstatv(struct proc *p, struct fstatv_args *uap, register_t *retval);
int lstatv(struct proc *p, struct lstatv_args *uap, register_t *retval);
int mkcomplex(struct proc *p, struct mkcomplex_args *uap, register_t *retval);
int statv(struct proc *p, struct statv_args *uap, register_t *retval);

#endif /* __APPLE_API_OBSOLETE */

#if UNION
extern int (**union_vnodeop_p)(void *);
extern struct vnode *union_dircache(struct vnode*, struct proc*);
#endif /* UNION */

/* counts number of mount and unmount operations */
unsigned int vfs_nummntops=0;

extern struct fileops vnops;

extern void mount_list_add(mount_t mp);
extern void mount_list_remove(mount_t mp);
extern int mount_refdrain(mount_t mp);
extern int vcount(struct vnode *vp);


/*
 * Virtual File System System Calls
 */

/*
 * Mount a file system.
 */
/* ARGSUSED */
int
mount(struct proc *p, register struct mount_args *uap, __unused register_t *retval)
{
	struct vnode *vp;
	struct vnode *devvp = NULLVP;
	struct vnode *device_vnode = NULLVP;
	struct mount *mp;
	struct vfstable *vfsp;
	int error, flag = 0;
	struct vnode_attr va;
	struct vfs_context context;
	struct nameidata nd;
	struct nameidata nd1;
	char fstypename[MFSNAMELEN];
	size_t dummy=0;
	user_addr_t devpath = USER_ADDR_NULL;
	user_addr_t fsmountargs =  uap->data;
	int ronly = 0;
	int mntalloc = 0;
	mode_t accessmode;
	boolean_t is_64bit;
	boolean_t is_rwlock_locked = FALSE;

	AUDIT_ARG(fflags, uap->flags);

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	is_64bit = proc_is64bit(p);

	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		   UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	
	if ((vp->v_flag & VROOT) &&
		(vp->v_mount->mnt_flag & MNT_ROOTFS)) 
			uap->flags |= MNT_UPDATE;
	
	if (uap->flags & MNT_UPDATE) {
		if ((vp->v_flag & VROOT) == 0) {
			error = EINVAL;
			goto out1;
		}
		mp = vp->v_mount;

		/* unmount in progress return error */
		mount_lock(mp);
		if (mp->mnt_lflag & MNT_LUNMOUNT) {
			mount_unlock(mp);
			error = EBUSY;
			goto out1;
		}
		mount_unlock(mp);
		lck_rw_lock_exclusive(&mp->mnt_rwlock);
		is_rwlock_locked = TRUE;
		/*
		 * We only allow the filesystem to be reloaded if it
		 * is currently mounted read-only.
		 */
		if ((uap->flags & MNT_RELOAD) &&
		    ((mp->mnt_flag & MNT_RDONLY) == 0)) {
			error = ENOTSUP;
			goto out1;
		}
		/*
		 * Only root, or the user that did the original mount is
		 * permitted to update it.
		 */
		if (mp->mnt_vfsstat.f_owner != kauth_cred_getuid(context.vc_ucred) &&
		    (error = suser(context.vc_ucred, &p->p_acflag))) {
			goto out1;
		}
		/*
		 * For non-root users, silently enforce MNT_NOSUID and MNT_NODEV,
		 * and MNT_NOEXEC if mount point is already MNT_NOEXEC.
		 */
		if (suser(context.vc_ucred, NULL)) {
			uap->flags |= MNT_NOSUID | MNT_NODEV;
			if (mp->mnt_flag & MNT_NOEXEC)
				uap->flags |= MNT_NOEXEC;
		}
		flag = mp->mnt_flag;

		mp->mnt_flag |=
		    uap->flags & (MNT_RELOAD | MNT_FORCE | MNT_UPDATE);

		vfsp = mp->mnt_vtable;
		goto update;
	}
	/*
	 * If the user is not root, ensure that they own the directory
	 * onto which we are attempting to mount.
	 */
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	if ((error = vnode_getattr(vp, &va, &context)) ||
	    (va.va_uid != kauth_cred_getuid(context.vc_ucred) &&
	     (error = suser(context.vc_ucred, &p->p_acflag)))) {
		goto out1;
	}
	/*
	 * For non-root users, silently enforce MNT_NOSUID and MNT_NODEV, and
	 * MNT_NOEXEC if mount point is already MNT_NOEXEC.
	 */
	if (suser(context.vc_ucred, NULL)) {
		uap->flags |= MNT_NOSUID | MNT_NODEV;
		if (vp->v_mount->mnt_flag & MNT_NOEXEC)
			uap->flags |= MNT_NOEXEC;
	}
	if ( (error = VNOP_FSYNC(vp, MNT_WAIT, &context)) )
		goto out1;

	if ( (error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0)) )
		goto out1;

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out1;
	}
	if ( (error = copyinstr(uap->type, fstypename, MFSNAMELEN, &dummy)) )
		goto out1;

	/* XXXAUDIT: Should we capture the type on the error path as well? */
	AUDIT_ARG(text, fstypename);
	mount_list_lock();
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strcmp(vfsp->vfc_name, fstypename))
			break;
	mount_list_unlock();
	if (vfsp == NULL) {
		error = ENODEV;
		goto out1;
	}
	if (ISSET(vp->v_flag, VMOUNT) && (vp->v_mountedhere != NULL)) {
		error = EBUSY;
		goto out1;
	}
	SET(vp->v_flag, VMOUNT);

	/*
	 * Allocate and initialize the filesystem.
	 */
	MALLOC_ZONE(mp, struct mount *, (u_long)sizeof(struct mount),
		M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_long)sizeof(struct mount));
	mntalloc = 1;

	/* Initialize the default IO constraints */
	mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
	mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;
	mp->mnt_maxsegreadsize = mp->mnt_maxreadcnt;
	mp->mnt_maxsegwritesize = mp->mnt_maxwritecnt;
	mp->mnt_devblocksize = DEV_BSIZE;

	TAILQ_INIT(&mp->mnt_vnodelist);
	TAILQ_INIT(&mp->mnt_workerqueue);
	TAILQ_INIT(&mp->mnt_newvnodes);
	mount_lock_init(mp);
	lck_rw_lock_exclusive(&mp->mnt_rwlock);
	is_rwlock_locked = TRUE;
	mp->mnt_op = vfsp->vfc_vfsops;
	mp->mnt_vtable = vfsp;
	mount_list_lock();
	vfsp->vfc_refcount++;
	mount_list_unlock();
	//mp->mnt_stat.f_type = vfsp->vfc_typenum;
	mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;
	strncpy(mp->mnt_vfsstat.f_fstypename, vfsp->vfc_name, MFSTYPENAMELEN);
	strncpy(mp->mnt_vfsstat.f_mntonname, nd.ni_cnd.cn_pnbuf, MAXPATHLEN);
	mp->mnt_vnodecovered = vp;
	mp->mnt_vfsstat.f_owner = kauth_cred_getuid(context.vc_ucred);

	/* XXX 3762912 hack to support HFS filesystem 'owner' - filesystem may update later */
	vfs_setowner(mp, KAUTH_UID_NONE, KAUTH_GID_NONE);
	
update:
	/*
	 * Set the mount level flags.
	 */
	if (uap->flags & MNT_RDONLY)
		mp->mnt_flag |= MNT_RDONLY;
	else if (mp->mnt_flag & MNT_RDONLY)
		mp->mnt_kern_flag |= MNTK_WANTRDWR;
	mp->mnt_flag &= ~(MNT_NOSUID | MNT_NOEXEC | MNT_NODEV |
			  MNT_SYNCHRONOUS | MNT_UNION | MNT_ASYNC |
			  MNT_UNKNOWNPERMISSIONS | MNT_DONTBROWSE | MNT_AUTOMOUNTED);
	mp->mnt_flag |= uap->flags & (MNT_NOSUID | MNT_NOEXEC |	MNT_NODEV |
				      MNT_SYNCHRONOUS | MNT_UNION | MNT_ASYNC |
				      MNT_UNKNOWNPERMISSIONS | MNT_DONTBROWSE | MNT_AUTOMOUNTED | 
					  MNT_DEFWRITE);

	if (vfsp->vfc_vfsflags & VFC_VFSLOCALARGS) {
		if (is_64bit) {
			if ( (error = copyin(fsmountargs, (caddr_t)&devpath, sizeof(devpath))) )
				goto out1;	
			fsmountargs += sizeof(devpath);
		} else {
			char *tmp;
			if ( (error = copyin(fsmountargs, (caddr_t)&tmp, sizeof(tmp))) )
				goto out1;	
			/* munge into LP64 addr */
			devpath = CAST_USER_ADDR_T(tmp);
			fsmountargs += sizeof(tmp);
		}

		/* if it is not update and device name needs to be parsed */
		if ((devpath)) {
			NDINIT(&nd1, LOOKUP, FOLLOW, UIO_USERSPACE, devpath, &context);
			if ( (error = namei(&nd1)) )
				goto out1;

			strncpy(mp->mnt_vfsstat.f_mntfromname, nd1.ni_cnd.cn_pnbuf, MAXPATHLEN);
			devvp = nd1.ni_vp;

			nameidone(&nd1);

			if (devvp->v_type != VBLK) {
				error = ENOTBLK;
				goto out2;
			}
			if (major(devvp->v_rdev) >= nblkdev) {
				error = ENXIO;
				goto out2;
			}
			/*
			* If mount by non-root, then verify that user has necessary
			* permissions on the device.
			*/
			if (suser(context.vc_ucred, NULL) != 0) {
				accessmode = KAUTH_VNODE_READ_DATA;
				if ((mp->mnt_flag & MNT_RDONLY) == 0)
					accessmode |= KAUTH_VNODE_WRITE_DATA;
				if ((error = vnode_authorize(devvp, NULL, accessmode, &context)) != 0)
					goto out2;
			}
		}
		if (devpath && ((uap->flags & MNT_UPDATE) == 0)) {
			if ( (error = vnode_ref(devvp)) )
				goto out2;
			/*
			* Disallow multiple mounts of the same device.
			* Disallow mounting of a device that is currently in use
			* (except for root, which might share swap device for miniroot).
			* Flush out any old buffers remaining from a previous use.
			*/
			if ( (error = vfs_mountedon(devvp)) )
				goto out3;
	
			if (vcount(devvp) > 1 && !(vfs_flags(mp) & MNT_ROOTFS)) {
				error = EBUSY;
				goto out3;
			}
			if ( (error = VNOP_FSYNC(devvp, MNT_WAIT, &context)) ) {
				error = ENOTBLK;
				goto out3;
			}
			if ( (error = buf_invalidateblks(devvp, BUF_WRITE_DATA, 0, 0)) )
				goto out3;

			ronly = (mp->mnt_flag & MNT_RDONLY) != 0;
			if ( (error = VNOP_OPEN(devvp, ronly ? FREAD : FREAD|FWRITE, &context)) )
				goto out3;

			mp->mnt_devvp = devvp;
			device_vnode = devvp;
		} else {
			if ((mp->mnt_flag & MNT_RDONLY) && (mp->mnt_kern_flag & MNTK_WANTRDWR)) {
				/*
				 * If upgrade to read-write by non-root, then verify
				 * that user has necessary permissions on the device.
				 */
				device_vnode = mp->mnt_devvp;
				if (device_vnode && suser(context.vc_ucred, NULL)) {
					if ((error = vnode_authorize(device_vnode, NULL,
						 KAUTH_VNODE_READ_DATA | KAUTH_VNODE_WRITE_DATA, &context)) != 0)
						goto out2;
				}
			}
			device_vnode = NULLVP;
		}
	}


	/*
	 * Mount the filesystem.
	 */
	error = VFS_MOUNT(mp, device_vnode, fsmountargs, &context);

	if (uap->flags & MNT_UPDATE) {
		if (mp->mnt_kern_flag & MNTK_WANTRDWR)
			mp->mnt_flag &= ~MNT_RDONLY;
		mp->mnt_flag &=~
		    (MNT_UPDATE | MNT_RELOAD | MNT_FORCE);
		mp->mnt_kern_flag &=~ MNTK_WANTRDWR;
		if (error)
			mp->mnt_flag = flag;
		vfs_event_signal(NULL, VQ_UPDATE, (intptr_t)NULL);
		lck_rw_done(&mp->mnt_rwlock);
		is_rwlock_locked = FALSE;
		if (!error)
			enablequotas(mp,&context);
		goto out2;
	}
	/*
	 * Put the new filesystem on the mount list after root.
	 */
	if (!error) {
		CLR(vp->v_flag, VMOUNT);

		vnode_lock(vp);
		vp->v_mountedhere = mp;
		vnode_unlock(vp);

		vnode_ref(vp);

		vfs_event_signal(NULL, VQ_MOUNT, (intptr_t)NULL);
		checkdirs(vp, &context);
		lck_rw_done(&mp->mnt_rwlock);
		is_rwlock_locked = FALSE;
		mount_list_add(mp);
		/* 
		 * there is no cleanup code here so I have made it void 
		 * we need to revisit this
		 */
		(void)VFS_START(mp, 0, &context);

		/* increment the operations count */
		OSAddAtomic(1, (SInt32 *)&vfs_nummntops);
		enablequotas(mp,&context);

		if (device_vnode) {
			device_vnode->v_specflags |= SI_MOUNTEDON;

			/*
			 *   cache the IO attributes for the underlying physical media...
			 *   an error return indicates the underlying driver doesn't
			 *   support all the queries necessary... however, reasonable
			 *   defaults will have been set, so no reason to bail or care
			 */
			vfs_init_io_attributes(device_vnode, mp);
		} 
	} else {
		CLR(vp->v_flag, VMOUNT);
		mount_list_lock();
		mp->mnt_vtable->vfc_refcount--;
		mount_list_unlock();

		if (device_vnode ) {
			VNOP_CLOSE(device_vnode, ronly ? FREAD : FREAD|FWRITE, &context);
			vnode_rele(device_vnode);
		}
		lck_rw_done(&mp->mnt_rwlock);
		is_rwlock_locked = FALSE;
		mount_lock_destroy(mp);
		FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
	}
	nameidone(&nd);

	/*
	 * drop I/O count on covered 'vp' and
	 * on the device vp if there was one
	 */
	if (devpath && devvp)
	        vnode_put(devvp);
	vnode_put(vp);

	return(error);

out3:
	vnode_rele(devvp);
out2:
	if (devpath && devvp)
	        vnode_put(devvp);
out1:
	/* Release mnt_rwlock only when it was taken */
	if (is_rwlock_locked == TRUE) {
		lck_rw_done(&mp->mnt_rwlock);
	}
	if (mntalloc)
		FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
	vnode_put(vp);
	nameidone(&nd);

	return(error);

}

void
enablequotas(struct mount *mp, vfs_context_t context)
{
	struct nameidata qnd;
	int type;
	char qfpath[MAXPATHLEN];
	const char *qfname = QUOTAFILENAME;
	const char *qfopsname = QUOTAOPSNAME;
	const char *qfextension[] = INITQFNAMES;

	if ((strcmp(mp->mnt_vfsstat.f_fstypename, "hfs") != 0 )
                && (strcmp( mp->mnt_vfsstat.f_fstypename, "ufs") != 0))
	  return;

	/* 
	 * Enable filesystem disk quotas if necessary.
	 * We ignore errors as this should not interfere with final mount
	 */
	for (type=0; type < MAXQUOTAS; type++) {
		sprintf(qfpath, "%s/%s.%s", mp->mnt_vfsstat.f_mntonname, qfopsname, qfextension[type]);
		NDINIT(&qnd, LOOKUP, FOLLOW, UIO_SYSSPACE32, CAST_USER_ADDR_T(qfpath), context);
		if (namei(&qnd) != 0)
			continue; 	    /* option file to trigger quotas is not present */
		vnode_put(qnd.ni_vp);
		nameidone(&qnd);
		sprintf(qfpath, "%s/%s.%s", mp->mnt_vfsstat.f_mntonname, qfname, qfextension[type]);

		(void) VFS_QUOTACTL(mp, QCMD(Q_QUOTAON, type), 0, qfpath, context);
	}
	return;
}

/*
 * Scan all active processes to see if any of them have a current
 * or root directory onto which the new filesystem has just been
 * mounted. If so, replace them with the new mount point.
 */
static void
checkdirs(olddp, context)
	struct vnode *olddp;
	vfs_context_t context;
{
	struct filedesc *fdp;
	struct vnode *newdp;
	struct proc *p;
	struct vnode *tvp;
	struct vnode *fdp_cvp;
	struct vnode *fdp_rvp;
	int cdir_changed = 0;
	int rdir_changed = 0;
	boolean_t funnel_state;

	if (olddp->v_usecount == 1)
		return;
	if (VFS_ROOT(olddp->v_mountedhere, &newdp, context))
		panic("mount: lost mount");
	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	for (p = allproc.lh_first; p != 0; p = p->p_list.le_next) {
		proc_fdlock(p);
		fdp = p->p_fd;
		if (fdp == (struct filedesc *)0) {
			proc_fdunlock(p);
			continue;
		}
		fdp_cvp = fdp->fd_cdir;
		fdp_rvp = fdp->fd_rdir;
		proc_fdunlock(p);

		if (fdp_cvp == olddp) {
			vnode_ref(newdp);
			tvp = fdp->fd_cdir;
			fdp_cvp = newdp;
			cdir_changed = 1;
			vnode_rele(tvp);
		}
		if (fdp_rvp == olddp) {
			vnode_ref(newdp);
			tvp = fdp->fd_rdir;
			fdp_rvp = newdp;
			rdir_changed = 1;
			vnode_rele(tvp);
		}
		if (cdir_changed || rdir_changed) {
			proc_fdlock(p);
			fdp->fd_cdir = fdp_cvp;
			fdp->fd_rdir = fdp_rvp;
			proc_fdunlock(p);
		}
	}
	if (rootvnode == olddp) {
		vnode_ref(newdp);
		tvp = rootvnode;
		rootvnode = newdp;
		vnode_rele(tvp);
	}
	thread_funnel_set(kernel_flock, funnel_state);

	vnode_put(newdp);
}

/*
 * Unmount a file system.
 *
 * Note: unmount takes a path to the vnode mounted on as argument,
 * not special file (as before).
 */
/* ARGSUSED */
int
unmount(struct proc *p, register struct unmount_args *uap, __unused register_t *retval)
{
	register struct vnode *vp;
	struct mount *mp;
	int error;
	struct nameidata nd;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	mp = vp->v_mount;
	nameidone(&nd);

	/*
	 * Must be the root of the filesystem
	 */
	if ((vp->v_flag & VROOT) == 0) {
		vnode_put(vp);
		return (EINVAL);
	}
	vnode_put(vp);
	return (safedounmount(mp, uap->flags, p));
}

/*
 * Do the actual file system unmount, prevent some common foot shooting.
 *
 * XXX Should take a "vfs_context_t" instead of a "struct proc *"
 */
int
safedounmount(mp, flags, p)
	struct mount *mp;
	int flags;
	struct proc *p;
{
	int error;

	/*
	 * Only root, or the user that did the original mount is
	 * permitted to unmount this filesystem.
	 */
	if ((mp->mnt_vfsstat.f_owner != kauth_cred_getuid(kauth_cred_get())) &&
	    (error = suser(kauth_cred_get(), &p->p_acflag)))
		return (error);

	/*
	 * Don't allow unmounting the root file system.
	 */
	if (mp->mnt_flag & MNT_ROOTFS)
		return (EBUSY); /* the root is always busy */

	return (dounmount(mp, flags, NULL, p));
}

/*
 * Do the actual file system unmount.
 */
int
dounmount(mp, flags, skiplistrmp, p)
	register struct mount *mp;
	int flags;
	int * skiplistrmp;
	struct proc *p;
{
	struct vnode *coveredvp = (vnode_t)0;
	int error;
	int needwakeup = 0;
	struct vfs_context context;
	int forcedunmount = 0;
	int lflags = 0;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if (flags & MNT_FORCE)
		forcedunmount = 1;
	mount_lock(mp);
	/* XXX post jaguar fix LK_DRAIN - then clean this up */
	if ((flags & MNT_FORCE)) {
		mp->mnt_kern_flag |= MNTK_FRCUNMOUNT;
		mp->mnt_lflag |= MNT_LFORCE;
	}
	if (mp->mnt_lflag & MNT_LUNMOUNT) {
		mp->mnt_lflag |= MNT_LWAIT;
		msleep((caddr_t)mp, &mp->mnt_mlock, (PVFS | PDROP), "dounmount", 0 );
		/*
		 * The prior unmount attempt has probably succeeded.
		 * Do not dereference mp here - returning EBUSY is safest.
		 */
		if (skiplistrmp != NULL)
			*skiplistrmp = 1;
		return (EBUSY);
	}
	mp->mnt_kern_flag |= MNTK_UNMOUNT;
	mp->mnt_lflag |= MNT_LUNMOUNT;
	mp->mnt_flag &=~ MNT_ASYNC;
	mount_unlock(mp);
	lck_rw_lock_exclusive(&mp->mnt_rwlock);
	fsevent_unmount(mp);  /* has to come first! */
	error = 0;
	if (forcedunmount == 0) {
		ubc_umount(mp);	/* release cached vnodes */
		if ((mp->mnt_flag & MNT_RDONLY) == 0) {
			error = VFS_SYNC(mp, MNT_WAIT, &context);
			if (error) {
				mount_lock(mp);
				mp->mnt_kern_flag &= ~MNTK_UNMOUNT;
				mp->mnt_lflag &= ~MNT_LUNMOUNT;
				mp->mnt_lflag &= ~MNT_LFORCE;
				goto out;
			}
		}
	}
	
	if (forcedunmount)
		lflags |= FORCECLOSE;
	error = vflush(mp, NULLVP, SKIPSWAP | SKIPSYSTEM  | SKIPROOT | lflags);
	if ((forcedunmount == 0) && error) {
		mount_lock(mp);
		mp->mnt_kern_flag &= ~MNTK_UNMOUNT;
		mp->mnt_lflag &= ~MNT_LUNMOUNT;
		mp->mnt_lflag &= ~MNT_LFORCE;
		goto out;
	}

	/* make sure there are no one in the mount iterations or lookup */
	mount_iterdrain(mp);

	error = VFS_UNMOUNT(mp, flags, &context);
	if (error) {
		mount_iterreset(mp);
		mount_lock(mp);
		mp->mnt_kern_flag &= ~MNTK_UNMOUNT;
		mp->mnt_lflag &= ~MNT_LUNMOUNT;
		mp->mnt_lflag &= ~MNT_LFORCE;
		goto out;
	}

	/* increment the operations count */
	if (!error)
		OSAddAtomic(1, (SInt32 *)&vfs_nummntops);

	if ( mp->mnt_devvp && mp->mnt_vtable->vfc_vfsflags & VFC_VFSLOCALARGS) {
		mp->mnt_devvp->v_specflags &= ~SI_MOUNTEDON;
		VNOP_CLOSE(mp->mnt_devvp, mp->mnt_flag & MNT_RDONLY ? FREAD : FREAD|FWRITE,
                       &context);
		vnode_rele(mp->mnt_devvp);
	}
	lck_rw_done(&mp->mnt_rwlock);
	mount_list_remove(mp);
	lck_rw_lock_exclusive(&mp->mnt_rwlock);
	
	/* mark the mount point hook in the vp but not drop the ref yet */
	if ((coveredvp = mp->mnt_vnodecovered) != NULLVP) {
			vnode_getwithref(coveredvp);
			vnode_lock(coveredvp);
			coveredvp->v_mountedhere = (struct mount *)0;
			vnode_unlock(coveredvp);
			vnode_put(coveredvp);
	}

	mount_list_lock();
	mp->mnt_vtable->vfc_refcount--;
	mount_list_unlock();

	cache_purgevfs(mp);	/* remove cache entries for this file sys */
	vfs_event_signal(NULL, VQ_UNMOUNT, (intptr_t)NULL);
	mount_lock(mp);
	mp->mnt_lflag |= MNT_LDEAD;

	if (mp->mnt_lflag & MNT_LWAIT) {
	        /*
		 * do the wakeup here
		 * in case we block in mount_refdrain
		 * which will drop the mount lock
		 * and allow anyone blocked in vfs_busy
		 * to wakeup and see the LDEAD state
		 */
		mp->mnt_lflag &= ~MNT_LWAIT;
		wakeup((caddr_t)mp);
	}
	mount_refdrain(mp);
out:
	if (mp->mnt_lflag & MNT_LWAIT) {
		mp->mnt_lflag &= ~MNT_LWAIT;
		needwakeup = 1;	
	}
	mount_unlock(mp);
	lck_rw_done(&mp->mnt_rwlock);

	if (needwakeup)
		wakeup((caddr_t)mp);
	if (!error) {
		if ((coveredvp != NULLVP)) {
			vnode_getwithref(coveredvp);
			vnode_rele(coveredvp);
			vnode_lock(coveredvp);
			if(mp->mnt_crossref == 0) {
				vnode_unlock(coveredvp);
				mount_lock_destroy(mp);
				FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
			}  else {
				coveredvp->v_lflag |= VL_MOUNTDEAD;
				vnode_unlock(coveredvp);
			}
			vnode_put(coveredvp);
		} else if (mp->mnt_flag & MNT_ROOTFS) {
				mount_lock_destroy(mp);
				FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
		} else
			panic("dounmount: no coveredvp");
	}
	return (error);
}

void
mount_dropcrossref(mount_t mp, vnode_t dp, int need_put)
{
		vnode_lock(dp);
		mp->mnt_crossref--;
		if (mp->mnt_crossref < 0)
			panic("mount cross refs -ve");
		if (((dp->v_lflag & VL_MOUNTDEAD) == VL_MOUNTDEAD) && (mp->mnt_crossref == 0)) {
			dp->v_lflag &= ~VL_MOUNTDEAD;
			if (need_put)
			        vnode_put_locked(dp);
			vnode_unlock(dp);
			mount_lock_destroy(mp);
			FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
			return;
		}
		if (need_put)
		        vnode_put_locked(dp);
		vnode_unlock(dp);
}


/*
 * Sync each mounted filesystem.
 */
#if DIAGNOSTIC
int syncprt = 0;
struct ctldebug debug0 = { "syncprt", &syncprt };
#endif

int print_vmpage_stat=0;

static int 
sync_callback(mount_t mp, __unused void * arg)
{
	struct proc * p = current_proc();
	int asyncflag;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if ((mp->mnt_flag & MNT_RDONLY) == 0) {
			asyncflag = mp->mnt_flag & MNT_ASYNC;
			mp->mnt_flag &= ~MNT_ASYNC;
			VFS_SYNC(mp, MNT_NOWAIT, &context);
			if (asyncflag)
				mp->mnt_flag |= MNT_ASYNC;
	}
	return(VFS_RETURNED);
}


extern unsigned int vp_pagein, vp_pgodirty, vp_pgoclean;
extern unsigned int dp_pgins, dp_pgouts;

/* ARGSUSED */
int
sync(__unused struct proc *p, __unused struct sync_args *uap, __unused register_t *retval)
{

	vfs_iterate(LK_NOWAIT, sync_callback, (void *)0);
	{
	if(print_vmpage_stat) {
		vm_countdirtypages();
		printf("VP: %d: %d: %d: %d: %d\n", vp_pgodirty, vp_pgoclean, vp_pagein,
			dp_pgins, dp_pgouts);
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
/* ARGSUSED */
int
quotactl(struct proc *p, register struct quotactl_args *uap, __unused register_t *retval)
{
	register struct mount *mp;
	int error, quota_cmd, quota_status;
	caddr_t datap;
	size_t fnamelen;
	struct nameidata nd;
	struct vfs_context context;
	struct dqblk my_dqblk;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	AUDIT_ARG(uid, uap->uid, 0, 0, 0);
	AUDIT_ARG(cmd, uap->cmd);
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	mp = nd.ni_vp->v_mount;
	vnode_put(nd.ni_vp);
	nameidone(&nd);

	/* copyin any data we will need for downstream code */
	quota_cmd = uap->cmd >> SUBCMDSHIFT;

	switch (quota_cmd) {
	case Q_QUOTAON:
		/* uap->arg specifies a file from which to take the quotas */
		fnamelen = MAXPATHLEN;
		datap = kalloc(MAXPATHLEN);
		error = copyinstr(uap->arg, datap, MAXPATHLEN, &fnamelen);
		break;
	case Q_GETQUOTA:
		/* uap->arg is a pointer to a dqblk structure. */
		datap = (caddr_t) &my_dqblk;
		break;
	case Q_SETQUOTA:
	case Q_SETUSE:
		/* uap->arg is a pointer to a dqblk structure. */
		datap = (caddr_t) &my_dqblk;
		if (proc_is64bit(p)) {
			struct user_dqblk	my_dqblk64;
			error = copyin(uap->arg, (caddr_t)&my_dqblk64, sizeof (my_dqblk64));
			if (error == 0) {
				munge_dqblk(&my_dqblk, &my_dqblk64, FALSE);
			}
		}
		else {
			error = copyin(uap->arg, (caddr_t)&my_dqblk, sizeof (my_dqblk));
		}
		break;
	case Q_QUOTASTAT:
		/* uap->arg is a pointer to an integer */
		datap = (caddr_t) &quota_status;
		break;
	default:
		datap = NULL;
		break;
	} /* switch */

	if (error == 0) {
		error = VFS_QUOTACTL(mp, uap->cmd, uap->uid, datap, &context);
	}

	switch (quota_cmd) {
	case Q_QUOTAON:
		if (datap != NULL)
			kfree(datap, MAXPATHLEN);
		break;
	case Q_GETQUOTA:
		/* uap->arg is a pointer to a dqblk structure we need to copy out to */
		if (error == 0) {
			if (proc_is64bit(p)) {
				struct user_dqblk	my_dqblk64;
				munge_dqblk(&my_dqblk, &my_dqblk64, TRUE);
				error = copyout((caddr_t)&my_dqblk64, uap->arg, sizeof (my_dqblk64));
			}
			else {
				error = copyout(datap, uap->arg, sizeof (struct dqblk));
			}
		}
		break;
	case Q_QUOTASTAT:
		/* uap->arg is a pointer to an integer */
		if (error == 0) {
			error = copyout(datap, uap->arg, sizeof(quota_status));
		}
		break;
	default:
		break;
	} /* switch */

	return (error);
}

/*
 * Get filesystem statistics.
 */
/* ARGSUSED */
int
statfs(struct proc *p, register struct statfs_args *uap, __unused register_t *retval)
{
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;
	struct nameidata nd;
	struct vfs_context context;
	vnode_t vp;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	mp = vp->v_mount;
	sp = &mp->mnt_vfsstat;
	nameidone(&nd);

	error = vfs_update_vfsstat(mp, &context);
	vnode_put(vp);
	if (error != 0) 
		return (error);

	error = munge_statfs(mp, sp, uap->buf, NULL, IS_64BIT_PROCESS(p), TRUE);
	return (error);
}

/*
 * Get filesystem statistics.
 */
/* ARGSUSED */
int
fstatfs(struct proc *p, register struct fstatfs_args *uap, __unused register_t *retval)
{
	struct vnode *vp;
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	AUDIT_ARG(fd, uap->fd);

	if ( (error = file_vnode(uap->fd, &vp)) )
		return (error);

	AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);

	mp = vp->v_mount;
	if (!mp) {
		file_drop(uap->fd);
		return (EBADF);
	}
	sp = &mp->mnt_vfsstat;
	if ((error = vfs_update_vfsstat(mp, &context)) != 0) {
		file_drop(uap->fd);
		return (error);
	}
	file_drop(uap->fd);

	error = munge_statfs(mp, sp, uap->buf, NULL, IS_64BIT_PROCESS(p), TRUE);

	return (error);
}


struct getfsstat_struct {
	user_addr_t	sfsp;
	int		count;
	int		maxcount;
	int		flags;
	int		error;
};


static int
getfsstat_callback(mount_t mp, void * arg)
{
	
	struct getfsstat_struct *fstp = (struct getfsstat_struct *)arg;
	struct vfsstatfs *sp;
	struct proc * p = current_proc();
	int error, my_size;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if (fstp->sfsp && fstp->count < fstp->maxcount) {
		sp = &mp->mnt_vfsstat;
		/*
		 * If MNT_NOWAIT is specified, do not refresh the
		 * fsstat cache. MNT_WAIT overrides MNT_NOWAIT.
		 */
		if (((fstp->flags & MNT_NOWAIT) == 0 || (fstp->flags & MNT_WAIT)) &&
			(error = vfs_update_vfsstat(mp, &context))) {
			KAUTH_DEBUG("vfs_update_vfsstat returned %d", error);
			return(VFS_RETURNED);
		}

		/*
		 * Need to handle LP64 version of struct statfs
		 */
		error = munge_statfs(mp, sp, fstp->sfsp, &my_size, IS_64BIT_PROCESS(p), FALSE);
		if (error) {
			fstp->error = error;
			return(VFS_RETURNED_DONE);
		}
		fstp->sfsp += my_size;
	}
	fstp->count++;
	return(VFS_RETURNED);
}

/*
 * Get statistics on all filesystems.
 */
int
getfsstat(__unused proc_t p, struct getfsstat_args *uap, int *retval)
{
	user_addr_t sfsp;
	int count, maxcount;
	struct getfsstat_struct fst;

	if (IS_64BIT_PROCESS(p)) {
		maxcount = uap->bufsize / sizeof(struct user_statfs);
	}
	else {
		maxcount = uap->bufsize / sizeof(struct statfs);
	}
	sfsp = uap->buf;
	count = 0;

	fst.sfsp = sfsp;
	fst.flags = uap->flags;
	fst.count = 0;
	fst.error = 0;
	fst.maxcount = maxcount;

	
	vfs_iterate(0, getfsstat_callback, &fst);

	if (fst.error ) {
		KAUTH_DEBUG("ERROR - %s gets %d", p->p_comm, fst.error);
		return(fst.error);
	}

	if (fst.sfsp && fst.count > fst.maxcount)
		*retval = fst.maxcount;
	else
		*retval = fst.count;
	return (0);
}

#if COMPAT_GETFSSTAT
ogetfsstat(p, uap, retval)
	struct proc *p;
	register struct getfsstat_args *uap;
	register_t *retval;
{
	return (ENOTSUP);
}
#endif

/*
 * Change current working directory to a given file descriptor.
 */
/* ARGSUSED */
int
fchdir(struct proc *p, struct fchdir_args *uap, __unused register_t *retval)
{
	register struct filedesc *fdp = p->p_fd;
	struct vnode *vp, *tdp, *tvp;
	struct mount *mp;
	int error;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if ( (error = file_vnode(uap->fd, &vp)) )
		return(error);
	if ( (error = vnode_getwithref(vp)) ) {
	        file_drop(uap->fd);
		return(error);
	}

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	if (vp->v_type != VDIR)
		error = ENOTDIR;
	else
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_SEARCH, &context);
	while (!error && (mp = vp->v_mountedhere) != NULL) {
		if (vfs_busy(mp, LK_NOWAIT)) {
			error = EACCES;
			goto out;
		}
		error = VFS_ROOT(mp, &tdp, &context);
		vfs_unbusy(mp);
		if (error)
			break;
		vnode_put(vp);
		vp = tdp;
	}
	if (error)
		goto out;
	if ( (error = vnode_ref(vp)) )
	        goto out;
	vnode_put(vp);

	proc_fdlock(p);
	tvp = fdp->fd_cdir;
	fdp->fd_cdir = vp;
	proc_fdunlock(p);

	if (tvp)
	        vnode_rele(tvp);
	file_drop(uap->fd);

	return (0);
out:
	vnode_put(vp);
	file_drop(uap->fd);

	return(error);
}

/*
 * Change current working directory (``.'').
 */
/* ARGSUSED */
int
chdir(struct proc *p, struct chdir_args *uap, __unused register_t *retval)
{
	register struct filedesc *fdp = p->p_fd;
	int error;
	struct nameidata nd;
	struct vnode *tvp;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = change_dir(&nd, &context);
	if (error)
		return (error);
	if ( (error = vnode_ref(nd.ni_vp)) ) {
	        vnode_put(nd.ni_vp);
		return (error);
	}
	/*
	 * drop the iocount we picked up in change_dir
	 */
	vnode_put(nd.ni_vp);

	proc_fdlock(p);
	tvp = fdp->fd_cdir;
	fdp->fd_cdir = nd.ni_vp;
	proc_fdunlock(p);

	if (tvp)
	        vnode_rele(tvp);

	return (0);
}

/*
 * Change notion of root (``/'') directory.
 */
/* ARGSUSED */
int
chroot(struct proc *p, struct chroot_args *uap, __unused register_t *retval)
{
	register struct filedesc *fdp = p->p_fd;
	int error;
	struct nameidata nd;
	boolean_t	shared_regions_active;
	struct vnode *tvp;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if ((error = suser(kauth_cred_get(), &p->p_acflag)))
		return (error);

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = change_dir(&nd, &context);
	if (error)
		return (error);

	if(p->p_flag & P_NOSHLIB) {
		shared_regions_active = FALSE;
	} else {
		shared_regions_active = TRUE;
	}
	if ((error = clone_system_shared_regions(shared_regions_active,
						 TRUE, /* chain_regions */
						 (int)nd.ni_vp))) {
		vnode_put(nd.ni_vp);
		return (error);
	}
	if ( (error = vnode_ref(nd.ni_vp)) ) {
	        vnode_put(nd.ni_vp);
		return (error);
	}
	vnode_put(nd.ni_vp);

	proc_fdlock(p);
	tvp = fdp->fd_rdir;
	fdp->fd_rdir = nd.ni_vp;
	fdp->fd_flags |= FD_CHROOT;
	proc_fdunlock(p);

	if (tvp != NULL)
		vnode_rele(tvp);

	return (0);
}

/*
 * Common routine for chroot and chdir.
 */
static int
change_dir(struct nameidata *ndp, vfs_context_t ctx)
{
	struct vnode *vp;
	int error;

	if ((error = namei(ndp)))
		return (error);
	nameidone(ndp);
	vp = ndp->ni_vp;
	if (vp->v_type != VDIR)
		error = ENOTDIR;
	else
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_SEARCH, ctx);
	if (error)
		vnode_put(vp);

	return (error);
}

/*
 * Check permissions, allocate an open file structure,
 * and call the device open routine if any.
 */

#warning XXX implement uid, gid
static int
open1(vfs_context_t ctx, user_addr_t upath, int uflags, struct vnode_attr *vap, register_t *retval)
{
	struct proc *p = vfs_context_proc(ctx);
	register struct filedesc *fdp = p->p_fd;
	register struct fileproc *fp;
	register struct vnode *vp;
	int flags, oflags;
	struct fileproc *nfp;
	int type, indx, error;
	struct flock lf;
	struct nameidata nd;

	oflags = uflags;

	if ((oflags & O_ACCMODE) == O_ACCMODE)
		return(EINVAL);
	flags = FFLAGS(uflags);

	AUDIT_ARG(fflags, oflags);
	AUDIT_ARG(mode, vap->va_mode);

	if ( (error = falloc(p, &nfp, &indx)) ) {
		return (error);
	}
	fp = nfp;
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, upath, ctx);
	p->p_dupfd = -indx - 1;			/* XXX check for fdopen */

	if ((error = vn_open_auth(&nd, &flags, vap))) {
		if ((error == ENODEV || error == ENXIO) && (p->p_dupfd >= 0)) {	/* XXX from fdopen */
			if ((error = dupfdopen(fdp, indx, p->p_dupfd, flags, error)) == 0) {
				fp_drop(p, indx, 0, 0);
			        *retval = indx;
				return (0);
			}
		}
		if (error == ERESTART)
		        error = EINTR;
		fp_free(p, indx, fp);

		return (error);
	}
	p->p_dupfd = 0;
	vp = nd.ni_vp;

	fp->f_fglob->fg_flag = flags & (FMASK | O_EVTONLY);
	fp->f_fglob->fg_type = DTYPE_VNODE;
	fp->f_fglob->fg_ops = &vnops;
	fp->f_fglob->fg_data = (caddr_t)vp;

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
		if ((error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_SETLK, &lf, type, ctx)))
			goto bad;
		fp->f_fglob->fg_flag |= FHASLOCK;
	}

	/* try to truncate by setting the size attribute */
	if ((flags & O_TRUNC) && ((error = vnode_setsize(vp, (off_t)0, 0, ctx)) != 0))
		goto bad;

	vnode_put(vp);

	proc_fdlock(p);
	*fdflags(p, indx) &= ~UF_RESERVED;
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = indx;

	return (0);
bad:
	vn_close(vp, fp->f_fglob->fg_flag, fp->f_fglob->fg_cred, p);
	vnode_put(vp);
	fp_free(p, indx, fp);

	return (error);

}

/*
 * An open system call using an extended argument list compared to the regular
 * system call 'open'.
 *
 * Parameters:	p			Process requesting the open
 *		uap			User argument descriptor (see below)
 *		retval			Pointer to an area to receive the
 *					return calue from the system call
 *
 * Indirect:	uap->path		Path to open (same as 'open')
 *		uap->flags		Flags to open (same as 'open'
 *		uap->uid		UID to set, if creating
 *		uap->gid		GID to set, if creating
 *		uap->mode		File mode, if creating (same as 'open')
 *		uap->xsecurity		ACL to set, if creating
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 * Notes:	The kauth_filesec_t in 'va', if any, is in host byte order.
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
int
open_extended(struct proc *p, struct open_extended_args *uap, register_t *retval)
{
	struct vfs_context context;
	register struct filedesc *fdp = p->p_fd;
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vnode_attr va;
	int cmode;

	xsecdst = NULL;
	if ((uap->xsecurity != USER_ADDR_NULL) &&
	    ((ciferror = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0))
		return ciferror;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	VATTR_INIT(&va);
	cmode = ((uap->mode &~ fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode);
	if (uap->uid != KAUTH_UID_NONE)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != KAUTH_GID_NONE)
		VATTR_SET(&va, va_gid, uap->gid);
	if (xsecdst != NULL)
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);

	ciferror = open1(&context, uap->path, uap->flags, &va, retval);
	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);

	return ciferror;
}

int
open(struct proc *p, struct open_args *uap, register_t *retval)
{
	struct vfs_context context;
	register struct filedesc *fdp = p->p_fd;
	struct vnode_attr va;
	int cmode;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	VATTR_INIT(&va);
	/* Mask off all but regular access permissions */
	cmode = ((uap->mode &~ fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode & ACCESSPERMS);

	return(open1(&context, uap->path, uap->flags, &va, retval));
}


/*
 * Create a special file.
 */
static int mkfifo1(vfs_context_t ctx, user_addr_t upath, struct vnode_attr *vap);

int
mknod(struct proc *p, register struct mknod_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;
	struct vfs_context context;
	int error;
	int whiteout = 0;
	struct nameidata nd;
	vnode_t	vp, dvp;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

 	VATTR_INIT(&va);
 	VATTR_SET(&va, va_mode, (uap->mode & ALLPERMS) & ~p->p_fd->fd_cmask);
 	VATTR_SET(&va, va_rdev, uap->dev);

	/* If it's a mknod() of a FIFO, call mkfifo1() instead */
	if ((uap->mode & S_IFMT) == S_IFIFO)
 		return(mkfifo1(&context, uap->path, &va));

	AUDIT_ARG(mode, uap->mode);
	AUDIT_ARG(dev, uap->dev);

	if ((error = suser(context.vc_ucred, &p->p_acflag)))
		return (error);
	NDINIT(&nd, CREATE, LOCKPARENT | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp != NULL) {
		error = EEXIST;
		goto out;
	}

 	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, &context)) != 0)
 		goto out;
  
	switch (uap->mode & S_IFMT) {
	case S_IFMT:	/* used by badsect to flag bad sectors */
		VATTR_SET(&va, va_type, VBAD);
		break;
	case S_IFCHR:
		VATTR_SET(&va, va_type, VCHR);
		break;
	case S_IFBLK:
		VATTR_SET(&va, va_type, VBLK);
		break;
	case S_IFWHT:
		whiteout = 1;
		break;
	default:
		error = EINVAL;
		goto out;
	}
	if (whiteout) {
		error = VNOP_WHITEOUT(dvp, &nd.ni_cnd, CREATE, &context);
	} else {
		error = vn_create(dvp, &vp, &nd.ni_cnd, &va, 0, &context);
	}
	if (error)
		goto out;

	if (vp) {
		int	update_flags = 0;

	        // Make sure the name & parent pointers are hooked up
	        if (vp->v_name == NULL)
			update_flags |= VNODE_UPDATE_NAME;
		if (vp->v_parent == NULLVP)
		        update_flags |= VNODE_UPDATE_PARENT;

		if (update_flags)
		        vnode_update_identity(vp, dvp, nd.ni_cnd.cn_nameptr, nd.ni_cnd.cn_namelen, nd.ni_cnd.cn_hash, update_flags);

		add_fsevent(FSE_CREATE_FILE, &context,
		    FSE_ARG_VNODE, vp,
		    FSE_ARG_DONE);
	}

out:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	if (vp)
	        vnode_put(vp);
	vnode_put(dvp);

	return (error);
}

/*
 * Create a named pipe.
 */
static int
mkfifo1(vfs_context_t ctx, user_addr_t upath, struct vnode_attr *vap)
{
	vnode_t	vp, dvp;
	int error;
	struct nameidata nd;

	NDINIT(&nd, CREATE, LOCKPARENT | AUDITVNPATH1, 
		UIO_USERSPACE, upath, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

   	/* check that this is a new file and authorize addition */
   	if (vp != NULL) {
   		error = EEXIST;
   		goto out;
   	}
   	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx)) != 0)
   		goto out;

   	VATTR_SET(vap, va_type, VFIFO);
 	
  	error = vn_create(dvp, &vp, &nd.ni_cnd, vap, 0, ctx);
out:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	if (vp)
	        vnode_put(vp);
	vnode_put(dvp);

	return error;
}


/*
 * A mkfifo system call using an extended argument list compared to the regular
 * system call 'mkfifo'.
 *
 * Parameters:	p			Process requesting the open
 *		uap			User argument descriptor (see below)
 *		retval			(Ignored)
 *
 * Indirect:	uap->path		Path to fifo (same as 'mkfifo')
 *		uap->uid		UID to set
 *		uap->gid		GID to set
 *		uap->mode		File mode to set (same as 'mkfifo')
 *		uap->xsecurity		ACL to set, if creating
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 * Notes:	The kauth_filesec_t in 'va', if any, is in host byte order.
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
int
mkfifo_extended(struct proc *p, struct mkfifo_extended_args *uap, __unused register_t *retval)
{
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vfs_context context;
	struct vnode_attr va;

	xsecdst = KAUTH_FILESEC_NONE;
	if (uap->xsecurity != USER_ADDR_NULL) {
		if ((ciferror = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0)
			return ciferror;
	}

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	VATTR_INIT(&va);
   	VATTR_SET(&va, va_mode, (uap->mode & ALLPERMS) & ~p->p_fd->fd_cmask);
	if (uap->uid != KAUTH_UID_NONE)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != KAUTH_GID_NONE)
		VATTR_SET(&va, va_gid, uap->gid);
	if (xsecdst != KAUTH_FILESEC_NONE)
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);

	ciferror = mkfifo1(&context, uap->path, &va);

	if (xsecdst != KAUTH_FILESEC_NONE)
		kauth_filesec_free(xsecdst);
	return ciferror;
}

/* ARGSUSED */
int
mkfifo(struct proc *p, register struct mkfifo_args *uap, __unused register_t *retval)
{
	struct vfs_context context;
	struct vnode_attr va;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

   	VATTR_INIT(&va);
   	VATTR_SET(&va, va_mode, (uap->mode & ALLPERMS) & ~p->p_fd->fd_cmask);

	return(mkfifo1(&context, uap->path, &va));
}

/*
 * Make a hard file link.
 */
/* ARGSUSED */
int
link(struct proc *p, register struct link_args *uap, __unused register_t *retval)
{
	vnode_t	vp, dvp, lvp;
	struct nameidata nd;
	struct vfs_context context;
	int error;
	fse_info finfo;
	int need_event, has_listeners;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	vp = dvp = lvp = NULLVP;

	/* look up the object we are linking to */
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	/* we're not allowed to link to directories */
	if (vp->v_type == VDIR) {
		error = EPERM;   /* POSIX */
		goto out;
	}

  	/* or to anything that kauth doesn't want us to (eg. immutable items) */
  	if ((error = vnode_authorize(vp, NULL, KAUTH_VNODE_LINKTARGET, &context)) != 0)
 		goto out;

	/* lookup the target node */
	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT | AUDITVNPATH2;
	nd.ni_dirp = uap->link;
	error = namei(&nd);
	if (error != 0)
		goto out;
	dvp = nd.ni_dvp;
	lvp = nd.ni_vp;
	/* target node must not exist */
	if (lvp != NULLVP) {
		error = EEXIST;
		goto out2;
	}
  	/* cannot link across mountpoints */
  	if (vnode_mount(vp) != vnode_mount(dvp)) {
  		error = EXDEV;
  		goto out2;
  	}
		
  	/* authorize creation of the target note */
  	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, &context)) != 0)
  		goto out2;

	/* and finally make the link */
	error = VNOP_LINK(vp, dvp, &nd.ni_cnd, &context);
	if (error)
		goto out2;

	need_event = need_fsevent(FSE_CREATE_FILE, dvp);
	has_listeners = kauth_authorize_fileop_has_listeners();

	if (need_event || has_listeners) {
		char *target_path = NULL;
		char *link_to_path = NULL;
		int len, link_name_len;

		/* build the path to the new link file */
		target_path = get_pathbuff();
		len = MAXPATHLEN;
		vn_getpath(dvp, target_path, &len);
		target_path[len-1] = '/';
		strcpy(&target_path[len], nd.ni_cnd.cn_nameptr);
		len += nd.ni_cnd.cn_namelen;

		if (has_listeners) {
		        /* build the path to file we are linking to */
		        link_to_path = get_pathbuff();
			link_name_len = MAXPATHLEN;
			vn_getpath(vp, link_to_path, &link_name_len);

			/* call out to allow 3rd party notification of rename. 
			 * Ignore result of kauth_authorize_fileop call.
			 */
			kauth_authorize_fileop(vfs_context_ucred(&context), KAUTH_FILEOP_LINK, 
					       (uintptr_t)link_to_path, (uintptr_t)target_path);
			if (link_to_path != NULL)
			        release_pathbuff(link_to_path);
		}
		if (need_event) {
		        /* construct fsevent */
		        if (get_fse_info(vp, &finfo, &context) == 0) {
			        // build the path to the destination of the link
			        add_fsevent(FSE_CREATE_FILE, &context,
					    FSE_ARG_STRING, len, target_path,
					    FSE_ARG_FINFO, &finfo,
					    FSE_ARG_DONE);
			}
		}
		release_pathbuff(target_path);
	}
out2:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);
out:
	if (lvp)
		vnode_put(lvp);
	if (dvp)
		vnode_put(dvp);
	vnode_put(vp);
	return (error);
}

/*
 * Make a symbolic link.
 *
 * We could add support for ACLs here too...
 */
/* ARGSUSED */
int
symlink(struct proc *p, register struct symlink_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;
	char *path;
	int error;
	struct nameidata nd;
	struct vfs_context context;
	vnode_t	vp, dvp;
	size_t dummy=0;
	
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	MALLOC_ZONE(path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	error = copyinstr(uap->path, path, MAXPATHLEN, &dummy);
	if (error)
		goto out;
	AUDIT_ARG(text, path);	/* This is the link string */

	NDINIT(&nd, CREATE, LOCKPARENT | AUDITVNPATH1, 
		UIO_USERSPACE, uap->link, &context);
	error = namei(&nd);
	if (error)
		goto out;
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp == NULL) {
		VATTR_INIT(&va);
		VATTR_SET(&va, va_type, VLNK);
		VATTR_SET(&va, va_mode, ACCESSPERMS & ~p->p_fd->fd_cmask);

 		/* authorize */
		error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, &context);
		/* get default ownership, etc. */
		if (error == 0)
			error = vnode_authattr_new(dvp, &va, 0, &context);
 		if (error == 0)
			error = VNOP_SYMLINK(dvp, &vp, &nd.ni_cnd, &va, path, &context);

		/* do fallback attribute handling */
		if (error == 0)
			error = vnode_setattr_fallback(vp, &va, &context);
		
		if (error == 0) {
			int	update_flags = 0;

			if (vp == NULL) {
				nd.ni_cnd.cn_nameiop = LOOKUP;
				nd.ni_cnd.cn_flags = 0;
				error = namei(&nd);
				vp = nd.ni_vp;

				if (vp == NULL)
				        goto skipit;
			}
			
#if 0  /* XXX - kauth_todo - is KAUTH_FILEOP_SYMLINK needed? */
			/* call out to allow 3rd party notification of rename. 
			 * Ignore result of kauth_authorize_fileop call.
			 */
			if (kauth_authorize_fileop_has_listeners() &&
				namei(&nd) == 0) {
				char *new_link_path = NULL;
				int		len;
				
				/* build the path to the new link file */
				new_link_path = get_pathbuff();
				len = MAXPATHLEN;
				vn_getpath(dvp, new_link_path, &len);
				new_link_path[len - 1] = '/';
				strcpy(&new_link_path[len], nd.ni_cnd.cn_nameptr);

				kauth_authorize_fileop(vfs_context_ucred(&context), KAUTH_FILEOP_SYMLINK, 
								   (uintptr_t)path, (uintptr_t)new_link_path);
				if (new_link_path != NULL)
					release_pathbuff(new_link_path);
			}
#endif 
			// Make sure the name & parent pointers are hooked up
			if (vp->v_name == NULL)
			        update_flags |= VNODE_UPDATE_NAME;
			if (vp->v_parent == NULLVP)
			        update_flags |= VNODE_UPDATE_PARENT;

			if (update_flags)
			        vnode_update_identity(vp, dvp, nd.ni_cnd.cn_nameptr, nd.ni_cnd.cn_namelen, nd.ni_cnd.cn_hash, update_flags);

			add_fsevent(FSE_CREATE_FILE, &context,
				    FSE_ARG_VNODE, vp,
				    FSE_ARG_DONE);
		}
	} else
		error = EEXIST;

skipit:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	if (vp)
	        vnode_put(vp);
	vnode_put(dvp);
out:
	FREE_ZONE(path, MAXPATHLEN, M_NAMEI);

	return (error);
}

/*
 * Delete a whiteout from the filesystem.
 */
/* ARGSUSED */
#warning XXX authorization not implmented for whiteouts
int
undelete(struct proc *p, register struct undelete_args *uap, __unused register_t *retval)
{
	int error;
	struct nameidata nd;
	struct vfs_context context;
	vnode_t	vp, dvp;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, DELETE, LOCKPARENT|DOWHITEOUT|AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp == NULLVP && (nd.ni_cnd.cn_flags & ISWHITEOUT)) {
		error = VNOP_WHITEOUT(dvp, &nd.ni_cnd, DELETE, &context);
	} else
	        error = EEXIST;

	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	if (vp)
	        vnode_put(vp);
	vnode_put(dvp);

	return (error);
}

/*
 * Delete a name from the filesystem.
 */
/* ARGSUSED */
static int
_unlink(struct proc *p, struct unlink_args *uap, __unused register_t *retval, int nodelbusy)
{
	vnode_t	vp, dvp;
	int error;
	struct nameidata nd;
	struct vfs_context context;
	struct componentname *cnp;
	int flags = 0;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, DELETE, LOCKPARENT | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	cnp = &nd.ni_cnd;

	/* With Carbon delete semantics, busy files cannot be deleted */
	if (nodelbusy)
		flags |= VNODE_REMOVE_NODELETEBUSY;

	error = namei(&nd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp->v_type == VDIR) {
		error = EPERM;	/* POSIX */
	} else {
		/*
		 * The root of a mounted filesystem cannot be deleted.
		 */
		if (vp->v_flag & VROOT) {
			error = EBUSY;
		}
	}
	/* authorize the delete operation */
	if (!error)
		error = vnode_authorize(vp, nd.ni_dvp, KAUTH_VNODE_DELETE, &context);
	
	if (!error) {
		char     *path = NULL;
		int       len;
		fse_info  finfo;

		if (need_fsevent(FSE_DELETE, dvp)) {
		        path = get_pathbuff();
			len = MAXPATHLEN;
			vn_getpath(vp, path, &len);
			get_fse_info(vp, &finfo, &context);
		}
	    	error = VNOP_REMOVE(dvp, vp, &nd.ni_cnd, flags, &context);

	    	if ( !error && path != NULL) {
			add_fsevent(FSE_DELETE, &context,
				    FSE_ARG_STRING, len, path,
				    FSE_ARG_FINFO, &finfo,
				    FSE_ARG_DONE);
	    	}
		if (path != NULL)
		        release_pathbuff(path);
	}
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);
	vnode_put(dvp);
	vnode_put(vp);
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
 * Delete a name from the filesystem using Carbon semantics.
 */
int
delete(p, uap, retval)
	struct proc *p;
	struct delete_args *uap;
	register_t *retval;
{
	return _unlink(p, (struct unlink_args *)uap, retval, 1);
}

/*
 * Reposition read/write file offset.
 */
int
lseek(p, uap, retval)
	struct proc *p;
	register struct lseek_args *uap;
	off_t *retval;
{
	struct fileproc *fp;
	struct vnode *vp;
	struct vfs_context context;
	off_t offset = uap->offset, file_size;
	int error;

	if ( (error = fp_getfvp(p,uap->fd, &fp, &vp)) ) {
	        if (error == ENOTSUP)
		        return (ESPIPE);
		return (error);
	}
	if (vnode_isfifo(vp)) {
		file_drop(uap->fd);
		return(ESPIPE);
	}
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}

	switch (uap->whence) {
	case L_INCR:
		offset += fp->f_fglob->fg_offset;
		break;
	case L_XTND:
		context.vc_proc = p;
		context.vc_ucred = kauth_cred_get();
		if ((error = vnode_size(vp, &file_size, &context)) != 0)
			break;
		offset += file_size;
		break;
	case L_SET:
		break;
	default:
		error = EINVAL;
	}
	if (error == 0) {
		if (uap->offset > 0 && offset < 0) {
			/* Incremented/relative move past max size */
			error = EOVERFLOW;
		} else {
			/*
			 * Allow negative offsets on character devices, per
			 * POSIX 1003.1-2001.  Most likely for writing disk
			 * labels.
			 */
			if (offset < 0 && vp->v_type != VCHR) {
				/* Decremented/relative move before start */
				error = EINVAL;
			} else {
				/* Success */
				fp->f_fglob->fg_offset = offset;
				*retval = fp->f_fglob->fg_offset;
			}
		}
	}
	(void)vnode_put(vp);
	file_drop(uap->fd);
	return (error);
}


/*
 * Check access permissions.
 */
static int
access1(vnode_t vp, vnode_t dvp, int uflags, vfs_context_t ctx)
{
 	kauth_action_t action;
	int error;

 	/*
 	 * If just the regular access bits, convert them to something
	 * that vnode_authorize will understand.
 	 */
 	if (!(uflags & _ACCESS_EXTENDED_MASK)) {
 		action = 0;
  		if (uflags & R_OK)
			action |= KAUTH_VNODE_READ_DATA;	/* aka KAUTH_VNODE_LIST_DIRECTORY */
  		if (uflags & W_OK) {
			if (vnode_isdir(vp)) {
				action |= KAUTH_VNODE_ADD_FILE |
				    KAUTH_VNODE_ADD_SUBDIRECTORY;
				/* might want delete rights here too */
			} else {
				action |= KAUTH_VNODE_WRITE_DATA;
			}
		}
  		if (uflags & X_OK) {
			if (vnode_isdir(vp)) {
				action |= KAUTH_VNODE_SEARCH;
			} else {
				action |= KAUTH_VNODE_EXECUTE;
			}
		}
  	} else {
		/* take advantage of definition of uflags */
		action = uflags >> 8;
	}
	
 	/* action == 0 means only check for existence */
 	if (action != 0) {
 		error = vnode_authorize(vp, dvp, action | KAUTH_VNODE_ACCESS, ctx);
	} else {
		error = 0;
	}

	return(error);
}



/* XXX need to support the check-as uid argument */
int
access_extended(__unused struct proc *p, struct access_extended_args *uap, __unused register_t *retval)
{
	struct accessx_descriptor *input;
	errno_t *result;
	int error, limit, nent, i, j, wantdelete;
	struct vfs_context context;
	struct nameidata nd;
 	int niopts;
	vnode_t vp, dvp;

	input = NULL;
	result = NULL;
	error = 0;
	vp = NULL;
	dvp = NULL;
	context.vc_ucred = NULL;

	/* check input size and fetch descriptor array into allocated storage */
	if (uap->size > ACCESSX_MAX_TABLESIZE)
		return(ENOMEM);
	if (uap->size < sizeof(struct accessx_descriptor))
		return(EINVAL);
	MALLOC(input, struct accessx_descriptor *, uap->size, M_TEMP, M_WAITOK);
	if (input == NULL) {
		error = ENOMEM;
		goto out;
	}
	error = copyin(uap->entries, input, uap->size);
	if (error)
		goto out;

	/*
	 * Access is defined as checking against the process'
 	 * real identity, even if operations are checking the
 	 * effective identity.  So we need to tweak the credential
 	 * in the context.
 	 */
	context.vc_ucred = kauth_cred_copy_real(kauth_cred_get());
	context.vc_proc = current_proc();

	/*
	 * Find out how many entries we have, so we can allocate the result array.
	 */
	limit = uap->size / sizeof(struct accessx_descriptor);
	nent = limit;
	wantdelete = 0;
	for (i = 0; i < nent; i++) {
		/*
		 * Take the offset to the name string for this entry and convert to an
		 * input array index, which would be one off the end of the array if this
		 * was the lowest-addressed name string.
		 */
		j = input[i].ad_name_offset / sizeof(struct accessx_descriptor);
		/* bad input */
		if (j > limit) {
			error = EINVAL;
			goto out;
		}
		/* implicit reference to previous name, not a real offset */
		if (j == 0) {
			/* first entry must have a name string */
			if (i == 0) {
				error = EINVAL;
				goto out;
			}
			continue;
		}
		if (j < nent)
			nent = j;
	}
	if (nent > ACCESSX_MAX_DESCRIPTORS) {
		error = ENOMEM;
		goto out;
	}
	MALLOC(result, errno_t *, nent * sizeof(errno_t), M_TEMP, M_WAITOK);
	if (result == NULL) {
		error = ENOMEM;
		goto out;
	}

	/*
	 * Do the work.
	 */
	error = 0;
	for (i = 0; i < nent; i++) {
		/*
		 * Looking up a new name?
		 */
		if (input[i].ad_name_offset != 0) {
			/* discard old vnodes */
			if (vp) {
				vnode_put(vp);
				vp = NULL;
			}
			if (dvp) {
				vnode_put(dvp);
				dvp = NULL;
			}
			
			/* scan forwards to see if we need the parent this time */
			wantdelete = input[i].ad_flags & _DELETE_OK;
			for (j = i + 1; (j < nent) && (input[j].ad_name_offset == 0); j++)
				if (input[j].ad_flags & _DELETE_OK)
					wantdelete = 1;
			
			niopts = FOLLOW | AUDITVNPATH1;
			/* need parent for vnode_authorize for deletion test */
			if (wantdelete)
				niopts |= WANTPARENT;

			/* do the lookup */
			NDINIT(&nd, LOOKUP, niopts, UIO_SYSSPACE, CAST_USER_ADDR_T((const char *)input + input[i].ad_name_offset), &context);
			error = namei(&nd);
			if (!error) {
				vp = nd.ni_vp;
				if (wantdelete)
					dvp = nd.ni_dvp;
			}
			nameidone(&nd);
		}

		/*
		 * Handle lookup errors.
		 */
		switch(error) {
		case ENOENT:
		case EACCES:
		case EPERM:
		case ENOTDIR:
			result[i] = error;
			break;
		case 0:
			/* run this access check */
			result[i] = access1(vp, dvp, input[i].ad_flags, &context);
			break;
		default:
			/* fatal lookup error */

			goto out;
		}
	}

	/* copy out results */
	error = copyout(result, uap->results, nent * sizeof(errno_t));
	
out:
	if (input)
		FREE(input, M_TEMP);
	if (result)
		FREE(result, M_TEMP);
	if (vp)
		vnode_put(vp);
	if (dvp)
		vnode_put(dvp);
	if (IS_VALID_CRED(context.vc_ucred))
 		kauth_cred_unref(&context.vc_ucred);
	return(error);
}

int
access(__unused struct proc *p, register struct access_args *uap, __unused register_t *retval)
{
	int error;
	struct nameidata nd;
 	int niopts;
	struct vfs_context context;

 	/*
 	 * Access is defined as checking against the process'
 	 * real identity, even if operations are checking the
 	 * effective identity.  So we need to tweak the credential
 	 * in the context.
 	 */
	context.vc_ucred = kauth_cred_copy_real(kauth_cred_get());
	context.vc_proc = current_proc();

	niopts = FOLLOW | AUDITVNPATH1;
 	/* need parent for vnode_authorize for deletion test */
 	if (uap->flags & _DELETE_OK)
 		niopts |= WANTPARENT;
 	NDINIT(&nd, LOOKUP, niopts, UIO_USERSPACE, uap->path, &context);
 	error = namei(&nd);
 	if (error)
 		goto out;

	error = access1(nd.ni_vp, nd.ni_dvp, uap->flags, &context);
 	
 	vnode_put(nd.ni_vp);
 	if (uap->flags & _DELETE_OK)
 		vnode_put(nd.ni_dvp);
  	nameidone(&nd);
  
out:
 	kauth_cred_unref(&context.vc_ucred);
 	return(error);
}


static int
stat2(vfs_context_t ctx, struct nameidata *ndp, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size)
{
	struct stat sb;
	struct user_stat user_sb;
	caddr_t sbp;
	int error, my_size;
	kauth_filesec_t fsec;
	size_t xsecurity_bufsize;

	error = namei(ndp);
	if (error)
		return (error);
	fsec = KAUTH_FILESEC_NONE;
	error = vn_stat(ndp->ni_vp, &sb, (xsecurity != USER_ADDR_NULL ? &fsec : NULL), ctx);
	vnode_put(ndp->ni_vp);
	nameidone(ndp);

	if (error)
		return (error);
	/* Zap spare fields */
	sb.st_lspare = 0;
	sb.st_qspare[0] = 0LL;
	sb.st_qspare[1] = 0LL;
	if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
		munge_stat(&sb, &user_sb); 
		my_size = sizeof(user_sb);
		sbp = (caddr_t)&user_sb;
	}
	else {
		my_size = sizeof(sb);
		sbp = (caddr_t)&sb;
	}
	if ((error = copyout(sbp, ub, my_size)) != 0)
		goto out;

	/* caller wants extended security information? */
	if (xsecurity != USER_ADDR_NULL) {

		/* did we get any? */
		if (fsec == KAUTH_FILESEC_NONE) {
			if (susize(xsecurity_size, 0) != 0) {
				error = EFAULT;
				goto out;
			}
		} else {
			/* find the user buffer size */
			xsecurity_bufsize = fusize(xsecurity_size);

			/* copy out the actual data size */
			if (susize(xsecurity_size, KAUTH_FILESEC_COPYSIZE(fsec)) != 0) {
				error = EFAULT;
				goto out;
			}

			/* if the caller supplied enough room, copy out to it */
			if (xsecurity_bufsize >= KAUTH_FILESEC_COPYSIZE(fsec))
				error = copyout(fsec, xsecurity, KAUTH_FILESEC_COPYSIZE(fsec));
		}
	}
out:
	if (fsec != KAUTH_FILESEC_NONE)
		kauth_filesec_free(fsec);
	return (error);
}

/*
 * Get file status; this version follows links.
 */
static int
stat1(struct proc *p, user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size)
{
	struct nameidata nd;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
	    UIO_USERSPACE, path, &context);
	return(stat2(&context, &nd, ub, xsecurity, xsecurity_size));
}

int
stat_extended(struct proc *p, struct stat_extended_args *uap, __unused register_t *retval)
{
	return (stat1(p, uap->path, uap->ub, uap->xsecurity, uap->xsecurity_size));
}

int
stat(struct proc *p, struct stat_args *uap, __unused register_t *retval)
{
	return(stat1(p, uap->path, uap->ub, 0, 0));
}

/*
 * Get file status; this version does not follow links.
 */
static int
lstat1(struct proc *p, user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size)
{
	struct nameidata nd;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, LOOKUP, NOFOLLOW | AUDITVNPATH1, 
	    UIO_USERSPACE, path, &context);

	return(stat2(&context, &nd, ub, xsecurity, xsecurity_size));
}

int
lstat_extended(struct proc *p, struct lstat_extended_args *uap, __unused register_t *retval)
{
	return (lstat1(p, uap->path, uap->ub, uap->xsecurity, uap->xsecurity_size));
}

int
lstat(struct proc *p, struct lstat_args *uap, __unused register_t *retval)
{
	return(lstat1(p, uap->path, uap->ub, 0, 0));
}

/*
 * Get configurable pathname variables.
 */
/* ARGSUSED */
int
pathconf(p, uap, retval)
	struct proc *p;
	register struct pathconf_args *uap;
	register_t *retval;
{
	int error;
	struct nameidata nd;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);

	error = vn_pathconf(nd.ni_vp, uap->name, retval, &context);

	vnode_put(nd.ni_vp);
	nameidone(&nd);
	return (error);
}

/*
 * Return target name of a symbolic link.
 */
/* ARGSUSED */
int
readlink(p, uap, retval)
	struct proc *p;
	register struct readlink_args *uap;
	register_t *retval;
{
	register struct vnode *vp;
	uio_t auio;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	int error;
	struct nameidata nd;
	struct vfs_context context;
	char uio_buf[ UIO_SIZEOF(1) ];

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, LOOKUP, NOFOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	auio = uio_createwithbuffer(1, 0, spacetype, UIO_READ, 
								  &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, uap->buf, uap->count);
	if (vp->v_type != VLNK)
		error = EINVAL;
	else {
		error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_DATA, &context);
		if (error == 0)
			error = VNOP_READLINK(vp, auio, &context);
	}
	vnode_put(vp);
	// LP64todo - fix this
	*retval = uap->count - (int)uio_resid(auio);
	return (error);
}

/*
 * Change file flags.
 */
static int
chflags1(vnode_t vp, int flags, vfs_context_t ctx)
{
	struct vnode_attr va;
 	kauth_action_t action;
	int error;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_flags, flags);

	/* request authorisation, disregard immutability */
 	if ((error = vnode_authattr(vp, &va, &action, ctx)) != 0)
		goto out;
	/*
	 * Request that the auth layer disregard those file flags it's allowed to when
	 * authorizing this operation; we need to do this in order to be able to
	 * clear immutable flags.
	 */
	if (action && ((error = vnode_authorize(vp, NULL, action | KAUTH_VNODE_NOIMMUTABLE, ctx)) != 0))
		goto out;
	error = vnode_setattr(vp, &va, ctx);

out:
	vnode_put(vp);
	return(error);
}

/*
 * Change flags of a file given a path name.
 */
/* ARGSUSED */
int
chflags(struct proc *p, register struct chflags_args *uap, __unused register_t *retval)
{
	register struct vnode *vp;
	struct vfs_context context;
	int error;
	struct nameidata nd;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	AUDIT_ARG(fflags, uap->flags);
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	nameidone(&nd);

	error = chflags1(vp, uap->flags, &context);

	return(error);
}

/*
 * Change flags of a file given a file descriptor.
 */
/* ARGSUSED */
int
fchflags(struct proc *p, register struct fchflags_args *uap, __unused register_t *retval)
{
	struct vfs_context context;
	struct vnode *vp;
	int error;

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(fflags, uap->flags);
	if ( (error = file_vnode(uap->fd, &vp)) )
		return (error);

	if ((error = vnode_getwithref(vp))) {
		file_drop(uap->fd);
		return(error);
	}

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	error = chflags1(vp, uap->flags, &context);

	file_drop(uap->fd);
	return (error);
}

/*
 * Change security information on a filesystem object.
 */
static int
chmod2(vfs_context_t ctx, struct vnode *vp, struct vnode_attr *vap)
{
	kauth_action_t action;
	int error;
	
	AUDIT_ARG(mode, (mode_t)vap->va_mode);
#warning XXX audit new args

 	/* make sure that the caller is allowed to set this security information */
	if (((error = vnode_authattr(vp, vap, &action, ctx)) != 0) ||
	    ((error = vnode_authorize(vp, NULL, action, ctx)) != 0)) {
		if (error == EACCES)
			error = EPERM;
		return(error);
	}
	
	error = vnode_setattr(vp, vap, ctx);

	return (error);
}


/*
 * Change mode of a file given path name.
 */
static int
chmod1(vfs_context_t ctx, user_addr_t path, struct vnode_attr *vap)
{
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, path, ctx);
	if ((error = namei(&nd)))
		return (error);
	error = chmod2(ctx, nd.ni_vp, vap);
	vnode_put(nd.ni_vp);
	nameidone(&nd);
	return(error);
}

/*
 * A chmod system call using an extended argument list compared to the regular
 * system call 'mkfifo'.
 *
 * Parameters:	p			Process requesting the open
 *		uap			User argument descriptor (see below)
 *		retval			(ignored)
 *
 * Indirect:	uap->path		Path to object (same as 'chmod')
 *		uap->uid		UID to set
 *		uap->gid		GID to set
 *		uap->mode		File mode to set (same as 'chmod')
 *		uap->xsecurity		ACL to set (or delete)
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 * Notes:	The kauth_filesec_t in 'va', if any, is in host byte order.
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
int
chmod_extended(struct proc *p, struct chmod_extended_args *uap, __unused register_t *retval)
{
	struct vfs_context context;
	int error;
	struct vnode_attr va;
	kauth_filesec_t xsecdst;

	VATTR_INIT(&va);
	if (uap->mode != -1)
		VATTR_SET(&va, va_mode, uap->mode & ALLPERMS);
	if (uap->uid != KAUTH_UID_NONE)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != KAUTH_GID_NONE)
		VATTR_SET(&va, va_gid, uap->gid);

	xsecdst = NULL;
	switch(uap->xsecurity) {
		/* explicit remove request */
	case CAST_USER_ADDR_T((void *)1):	/* _FILESEC_REMOVE_ACL */
		VATTR_SET(&va, va_acl, NULL);
		break;
		/* not being set */
	case USER_ADDR_NULL:
		break;
	default:
		if ((error = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0)
			return(error);
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);
		KAUTH_DEBUG("CHMOD - setting ACL with %d entries", va.va_acl->acl_entrycount);
	}
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	error = chmod1(&context, uap->path, &va);

	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);
	return(error);
}

int
chmod(struct proc *p, register struct chmod_args *uap, __unused register_t *retval)
{
	struct vfs_context context;
	struct vnode_attr va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, uap->mode & ALLPERMS);

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	return(chmod1(&context, uap->path, &va));
}

/*
 * Change mode of a file given a file descriptor.
 */
static int
fchmod1(struct proc *p, int fd, struct vnode_attr *vap)
{
	struct vnode *vp;
	int error;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	AUDIT_ARG(fd, fd);

	if ((error = file_vnode(fd, &vp)) != 0)
		return (error);
	if ((error = vnode_getwithref(vp)) != 0) {
		file_drop(fd);
		return(error);
	}
	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	error = chmod2(&context, vp, vap);
	(void)vnode_put(vp);
	file_drop(fd);

	return (error);
}

int
fchmod_extended(struct proc *p, struct fchmod_extended_args *uap, __unused register_t *retval)
{
	int error;
	struct vnode_attr va;
	kauth_filesec_t xsecdst;

	VATTR_INIT(&va);
	if (uap->mode != -1)
		VATTR_SET(&va, va_mode, uap->mode & ALLPERMS);
	if (uap->uid != KAUTH_UID_NONE)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != KAUTH_GID_NONE)
		VATTR_SET(&va, va_gid, uap->gid);

	xsecdst = NULL;
	switch(uap->xsecurity) {
	case USER_ADDR_NULL:
		VATTR_SET(&va, va_acl, NULL);
		break;
	case CAST_USER_ADDR_T(-1):
		break;
	default:
		if ((error = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0)
			return(error);
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);
	}

	error = fchmod1(p, uap->fd, &va);

	
	switch(uap->xsecurity) {
	case USER_ADDR_NULL:
	case CAST_USER_ADDR_T(-1):
		break;
	default:
		if (xsecdst != NULL)
			kauth_filesec_free(xsecdst);
	}
	return(error);
}

int
fchmod(struct proc *p, register struct fchmod_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, uap->mode & ALLPERMS);

	return(fchmod1(p, uap->fd, &va));
}


/*
 * Set ownership given a path name.
 */
/* ARGSUSED */
static int
chown1(vfs_context_t ctx, register struct chown_args *uap, __unused register_t *retval, int follow)
{
	register struct vnode *vp;
	struct vnode_attr va;
	int error;
	struct nameidata nd;
	kauth_action_t action;

	AUDIT_ARG(owner, uap->uid, uap->gid);

	NDINIT(&nd, LOOKUP, (follow ? FOLLOW : 0) | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	/*
	 * XXX A TEMPORARY HACK FOR NOW: Try to track console_user
	 * by looking for chown() calls on /dev/console from a console process.
	 */
	if ((vp) && (vp->v_type == VBLK || vp->v_type == VCHR) && (vp->v_specinfo) &&
		(major(vp->v_specinfo->si_rdev) == CONSMAJOR) &&
		(minor(vp->v_specinfo->si_rdev) == 0)) {
		console_user = uap->uid;
	};
	VATTR_INIT(&va);
	if (uap->uid != VNOVAL)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != VNOVAL)
		VATTR_SET(&va, va_gid, uap->gid);

	/* preflight and authorize attribute changes */
	if ((error = vnode_authattr(vp, &va, &action, ctx)) != 0)
		goto out;
	if (action && ((error = vnode_authorize(vp, NULL, action, ctx)) != 0))
		goto out;
	error = vnode_setattr(vp, &va, ctx);
 
out:
	/*
	 * EACCES is only allowed from namei(); permissions failure should
	 * return EPERM, so we need to translate the error code.
	 */
	if (error == EACCES)
		error = EPERM;
	
	vnode_put(vp);
	return (error);
}

int
chown(struct proc *p, register struct chown_args *uap, register_t *retval)
{
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	return chown1(&context, uap, retval, 1);
}

int
lchown(struct proc *p, register struct lchown_args *uap, register_t *retval)
{
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	/* Argument list identical, but machine generated; cast for chown1() */
	return chown1(&context, (struct chown_args *)uap, retval, 0);
}

/*
 * Set ownership given a file descriptor.
 */
/* ARGSUSED */
int
fchown(struct proc *p, register struct fchown_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;
	struct vfs_context context;
	struct vnode *vp;
	int error;
	kauth_action_t action;

	AUDIT_ARG(owner, uap->uid, uap->gid);
	AUDIT_ARG(fd, uap->fd);

	if ( (error = file_vnode(uap->fd, &vp)) )
		return (error);

	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}
	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	VATTR_INIT(&va);
	if (uap->uid != VNOVAL)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != VNOVAL)
		VATTR_SET(&va, va_gid, uap->gid);

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

 	/* preflight and authorize attribute changes */
	if ((error = vnode_authattr(vp, &va, &action, &context)) != 0)
		goto out;
	if (action && ((error = vnode_authorize(vp, NULL, action, &context)) != 0)) {
		if (error == EACCES)
			error = EPERM;
		goto out;
	}
	error = vnode_setattr(vp, &va, &context);

out:
	(void)vnode_put(vp);
	file_drop(uap->fd);
	return (error);
}

static int
getutimes(usrtvp, tsp)
	user_addr_t usrtvp;
	struct timespec *tsp;
{
	struct user_timeval tv[2];
	int error;

	if (usrtvp == USER_ADDR_NULL) {
		struct timeval old_tv;
		/* XXX Y2038 bug because of microtime argument */
		microtime(&old_tv);
		TIMEVAL_TO_TIMESPEC(&old_tv, &tsp[0]);
		tsp[1] = tsp[0];
	} else {
		if (IS_64BIT_PROCESS(current_proc())) {
			error = copyin(usrtvp, (void *)tv, sizeof(tv));
		} else {
			struct timeval old_tv[2];
			error = copyin(usrtvp, (void *)old_tv, sizeof(old_tv));
			tv[0].tv_sec = old_tv[0].tv_sec;
			tv[0].tv_usec = old_tv[0].tv_usec;
			tv[1].tv_sec = old_tv[1].tv_sec;
			tv[1].tv_usec = old_tv[1].tv_usec;
		}
		if (error)
			return (error);
		TIMEVAL_TO_TIMESPEC(&tv[0], &tsp[0]);
		TIMEVAL_TO_TIMESPEC(&tv[1], &tsp[1]);
	}
	return 0;
}

static int
setutimes(vfs_context_t ctx, struct vnode *vp, const struct timespec *ts,
	int nullflag)
{
	int error;
	struct vnode_attr va;
	kauth_action_t action;

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	VATTR_INIT(&va);
	VATTR_SET(&va, va_access_time, ts[0]);
	VATTR_SET(&va, va_modify_time, ts[1]);
	if (nullflag)
		va.va_vaflags |= VA_UTIMES_NULL;

	if ((error = vnode_authattr(vp, &va, &action, ctx)) != 0)
		goto out;
	/* since we may not need to auth anything, check here */
	if ((action != 0) && ((error = vnode_authorize(vp, NULL, action, ctx)) != 0))
		goto out;
	error = vnode_setattr(vp, &va, ctx);

out:
	return error;
}

/*
 * Set the access and modification times of a file.
 */
/* ARGSUSED */
int
utimes(struct proc *p, register struct utimes_args *uap, __unused register_t *retval)
{
	struct timespec ts[2];
	user_addr_t usrtvp;
	int error;
	struct nameidata nd;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	/* AUDIT: Needed to change the order of operations to do the 
	 * name lookup first because auditing wants the path.
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	nameidone(&nd);

	/*
	 * Fetch the user-supplied time.  If usrtvp is USER_ADDR_NULL, we fetch
	 * the current time instead.
	 */
	usrtvp = uap->tptr;
	if ((error = getutimes(usrtvp, ts)) != 0)
		goto out;

	error = setutimes(&context, nd.ni_vp, ts, usrtvp == USER_ADDR_NULL);

out:
	vnode_put(nd.ni_vp);
	return (error);
}

/*
 * Set the access and modification times of a file.
 */
/* ARGSUSED */
int
futimes(struct proc *p, register struct futimes_args *uap, __unused register_t *retval)
{
	struct timespec ts[2];
	struct vnode *vp;
	user_addr_t usrtvp;
	int error;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	AUDIT_ARG(fd, uap->fd);
	usrtvp = uap->tptr;
	if ((error = getutimes(usrtvp, ts)) != 0)
		return (error);
	if ((error = file_vnode(uap->fd, &vp)) != 0)
		return (error);
	if((error = vnode_getwithref(vp))) {
		file_drop(uap->fd);
		return(error);
	}

	error =  setutimes(&context, vp, ts, usrtvp == 0);
	vnode_put(vp);
	file_drop(uap->fd);
	return(error);
}

/*
 * Truncate a file given its path name.
 */
/* ARGSUSED */
int
truncate(struct proc *p, register struct truncate_args *uap, __unused register_t *retval)
{
	register struct vnode *vp;
	struct vnode_attr va;
	struct vfs_context context;
	int error;
	struct nameidata nd;
	kauth_action_t action;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if (uap->length < 0)
		return(EINVAL);
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	if ((error = namei(&nd)))
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	VATTR_INIT(&va);
	VATTR_SET(&va, va_data_size, uap->length);
	if ((error = vnode_authattr(vp, &va, &action, &context)) != 0)
		goto out;
	if ((action != 0) && ((error = vnode_authorize(vp, NULL, action, &context)) != 0))
		goto out;
	error = vnode_setattr(vp, &va, &context);
out:
	vnode_put(vp);
	return (error);
}

/*
 * Truncate a file given a file descriptor.
 */
/* ARGSUSED */
int
ftruncate(p, uap, retval)
	struct proc *p;
	register struct ftruncate_args *uap;
	register_t *retval;
{
	struct vfs_context context;
	struct vnode_attr va;
	struct vnode *vp;
	struct fileproc *fp;
	int error ;
	int fd = uap->fd;

	context.vc_proc = current_proc();
	context.vc_ucred = kauth_cred_get();
	
	AUDIT_ARG(fd, uap->fd);
	if (uap->length < 0)
		return(EINVAL);
        
	if ( (error = fp_lookup(p,fd,&fp,0)) ) {
		return(error);
	}

	if (fp->f_fglob->fg_type == DTYPE_PSXSHM) {
		error = pshm_truncate(p, fp, uap->fd, uap->length, retval);
		goto out;
	}
	if (fp->f_fglob->fg_type != DTYPE_VNODE)  {
		error = EINVAL;
		goto out;
	}

	vp = (struct vnode *)fp->f_fglob->fg_data;

	if ((fp->f_fglob->fg_flag & FWRITE) == 0) {
		AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);
		error = EINVAL;
		goto out;
	}

	if ((error = vnode_getwithref(vp)) != 0) {
		goto out;
	}

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	VATTR_INIT(&va);
	VATTR_SET(&va, va_data_size, uap->length);
	error = vnode_setattr(vp, &va, &context);
	(void)vnode_put(vp);
out:
	file_drop(fd);
	return (error);
}


/*
 * Sync an open file.
 */
/* ARGSUSED */
int
fsync(struct proc *p, struct fsync_args *uap, __unused register_t *retval)
{
	struct vnode *vp;
	struct fileproc *fp;
	struct vfs_context context;
	int error;

	if ( (error = fp_getfvp(p, uap->fd, &fp, &vp)) )
		return (error);
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}
	context.vc_proc = p;
	context.vc_ucred = fp->f_fglob->fg_cred;

	error = VNOP_FSYNC(vp, MNT_WAIT, &context);

	(void)vnode_put(vp);
	file_drop(uap->fd);
	return (error);
}

/*
 * Duplicate files.  Source must be a file, target must be a file or 
 * must not exist.
 *
 * XXX Copyfile authorisation checking is woefully inadequate, and will not
 *     perform inheritance correctly.
 */
/* ARGSUSED */
int
copyfile(struct proc *p, register struct copyfile_args *uap, __unused register_t *retval)
{
	vnode_t tvp, fvp, tdvp, sdvp;
	struct nameidata fromnd, tond;
	int error;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	/* Check that the flags are valid. */

	if (uap->flags & ~CPF_MASK) {
		return(EINVAL);
	}

	NDINIT(&fromnd, LOOKUP, SAVESTART | AUDITVNPATH1,
		UIO_USERSPACE, uap->from, &context);
	if ((error = namei(&fromnd)))
		return (error);
	fvp = fromnd.ni_vp;

	NDINIT(&tond, CREATE,  LOCKPARENT | LOCKLEAF | NOCACHE | SAVESTART | AUDITVNPATH2,
	    UIO_USERSPACE, uap->to, &context);
	if ((error = namei(&tond))) {
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

	if ((error = vnode_authorize(tdvp, NULL, KAUTH_VNODE_ADD_FILE, &context)) != 0)
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
	if (!error)
	        error = VNOP_COPYFILE(fvp,tdvp,tvp,&tond.ni_cnd,uap->mode,uap->flags,&context);
out:
	sdvp = tond.ni_startdir;
	/*
	 * nameidone has to happen before we vnode_put(tdvp)
	 * since it may need to release the fs_nodelock on the tdvp
	 */
	nameidone(&tond);

	if (tvp)
		vnode_put(tvp);
	vnode_put(tdvp);
	vnode_put(sdvp);
out1:
	vnode_put(fvp);

	if (fromnd.ni_startdir)
	        vnode_put(fromnd.ni_startdir);
	nameidone(&fromnd);

	if (error == -1)
		return (0);
	return (error);
}


/*
 * Rename files.  Source and destination must either both be directories,
 * or both not be directories.  If target is a directory, it must be empty.
 */
/* ARGSUSED */
int
rename(proc_t p, register struct rename_args *uap, __unused register_t *retval)
{
	vnode_t tvp, tdvp;
	vnode_t fvp, fdvp;
	struct nameidata fromnd, tond;
	struct vfs_context context;
	int error;
	int mntrename;
	char *oname, *from_name, *to_name;
	int from_len, to_len;
	int holding_mntlock;
	mount_t locked_mp = NULL;
	vnode_t oparent;
	fse_info from_finfo, to_finfo;
	
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	holding_mntlock = 0;
retry:
	fvp = tvp = NULL;
	fdvp = tdvp = NULL;
	mntrename = FALSE;

	NDINIT(&fromnd, DELETE, WANTPARENT | AUDITVNPATH1, UIO_USERSPACE, uap->from, &context);
	
	if ( (error = namei(&fromnd)) )
	        goto out1;
	fdvp = fromnd.ni_dvp;
	fvp  = fromnd.ni_vp;

	NDINIT(&tond, RENAME, WANTPARENT | AUDITVNPATH2, UIO_USERSPACE, uap->to, &context);
	if (fvp->v_type == VDIR)
		tond.ni_cnd.cn_flags |= WILLBEDIR;

	if ( (error = namei(&tond)) ) {
		/*
		 * Translate error code for rename("dir1", "dir2/.").
		 */
	        if (error == EISDIR && fvp->v_type == VDIR) 
		        error = EINVAL;
		goto out1;
	}
	tdvp = tond.ni_dvp;
	tvp  = tond.ni_vp;

	if (tvp != NULL) {
		if (fvp->v_type == VDIR && tvp->v_type != VDIR) {
			error = ENOTDIR;
			goto out1;
		} else if (fvp->v_type != VDIR && tvp->v_type == VDIR) {
			error = EISDIR;
			goto out1;
		}
	}
	if (fvp == tdvp) {
		error = EINVAL;
		goto out1;
	}

	/*
	 * Authorization.
	 *
	 * If tvp is a directory and not the same as fdvp, or tdvp is not the same as fdvp,
	 * the node is moving between directories and we need rights to remove from the
	 * old and add to the new.
	 *
	 * If tvp already exists and is not a directory, we need to be allowed to delete it.
	 *
	 * Note that we do not inherit when renaming.  XXX this needs to be revisited to
	 * implement the deferred-inherit bit.
	 */
	{
		int moving = 0;

		error = 0;
		if ((tvp != NULL) && vnode_isdir(tvp)) {
			if (tvp != fdvp)
				moving = 1;
		} else if (tdvp != fdvp) {
			moving = 1;
		}
		/*
		 * must have delete rights to remove the old name even in the simple case of
		 * fdvp == tdvp
		 */
		if ((error = vnode_authorize(fvp, fdvp, KAUTH_VNODE_DELETE, &context)) != 0)
			goto auth_exit;
		if (moving) {
			/* moving into tdvp or tvp, must have rights to add */
			if ((error = vnode_authorize(((tvp != NULL) && vnode_isdir(tvp)) ? tvp : tdvp,
				 NULL, 
				 vnode_isdir(fvp) ? KAUTH_VNODE_ADD_SUBDIRECTORY : KAUTH_VNODE_ADD_FILE,
				 &context)) != 0)
				goto auth_exit;
		} else {
			/* node staying in same directory, must be allowed to add new name */
			if ((error = vnode_authorize(fdvp, NULL,
				 vnode_isdir(fvp) ? KAUTH_VNODE_ADD_SUBDIRECTORY : KAUTH_VNODE_ADD_FILE, &context)) != 0)
				goto auth_exit;
		}
		/* overwriting tvp */
		if ((tvp != NULL) && !vnode_isdir(tvp) &&
		    ((error = vnode_authorize(tvp, tdvp, KAUTH_VNODE_DELETE, &context)) != 0))
			goto auth_exit;
 		    
		/* XXX more checks? */

auth_exit:
		/* authorization denied */
		if (error != 0)
			goto out1;
	}
	/*
	 * Allow the renaming of mount points.
	 * - target must not exist
	 * - target must reside in the same directory as source
	 * - union mounts cannot be renamed
	 * - "/" cannot be renamed
	 */
	if ((fvp->v_flag & VROOT) &&
	    (fvp->v_type == VDIR) &&
	    (tvp == NULL)  &&
	    (fvp->v_mountedhere == NULL)  &&
	    (fdvp == tdvp)  &&
	    ((fvp->v_mount->mnt_flag & (MNT_UNION | MNT_ROOTFS)) == 0)  &&
	    (fvp->v_mount->mnt_vnodecovered != NULLVP)) {
		struct vnode *coveredvp;
	
		/* switch fvp to the covered vnode */
		coveredvp = fvp->v_mount->mnt_vnodecovered;
		if ( (vnode_getwithref(coveredvp)) ) {
		        error = ENOENT;
			goto out1;
		}
		vnode_put(fvp);

		fvp = coveredvp;
		mntrename = TRUE;
	}
	/*
	 * Check for cross-device rename.
	 */
	if ((fvp->v_mount != tdvp->v_mount) ||
	    (tvp && (fvp->v_mount != tvp->v_mount))) {
		error = EXDEV;
		goto out1;
	}
	/*
	 * Avoid renaming "." and "..".
	 */
	if (fvp->v_type == VDIR &&
	    ((fdvp == fvp) ||
	     (fromnd.ni_cnd.cn_namelen == 1 && fromnd.ni_cnd.cn_nameptr[0] == '.') ||
	     ((fromnd.ni_cnd.cn_flags | tond.ni_cnd.cn_flags) & ISDOTDOT)) ) {
		error = EINVAL;
		goto out1;
	}
	/*
	 * The following edge case is caught here:
	 * (to cannot be a descendent of from)
	 *
	 *       o fdvp
	 *      /
	 *     /
	 *    o fvp
	 *     \
	 *      \
	 *       o tdvp
	 *      /
	 *     /
	 *    o tvp
	 */
	if (tdvp->v_parent == fvp) {
		error = EINVAL;
		goto out1;
	}

	/*
	 * If source is the same as the destination (that is the
	 * same inode number) then there is nothing to do...
	 * EXCEPT if the underlying file system supports case
	 * insensitivity and is case preserving.  In this case
	 * the file system needs to handle the special case of
	 * getting the same vnode as target (fvp) and source (tvp).
	 *
	 * Only file systems that support pathconf selectors _PC_CASE_SENSITIVE
	 * and _PC_CASE_PRESERVING can have this exception, and they need to
	 * handle the special case of getting the same vnode as target and
	 * source.  NOTE: Then the target is unlocked going into vnop_rename,
	 * so not to cause locking problems. There is a single reference on tvp.
	 *
	 * NOTE - that fvp == tvp also occurs if they are hard linked - NOTE
	 * that correct behaviour then is just to remove the source (link)
	 */
	if (fvp == tvp && fdvp == tdvp) {
		if (fromnd.ni_cnd.cn_namelen == tond.ni_cnd.cn_namelen &&
	       	    !bcmp(fromnd.ni_cnd.cn_nameptr, tond.ni_cnd.cn_nameptr,
			  fromnd.ni_cnd.cn_namelen)) {
			goto out1;
		}
	}

	if (holding_mntlock && fvp->v_mount != locked_mp) {
	        /*
		 * we're holding a reference and lock
		 * on locked_mp, but it no longer matches
		 * what we want to do... so drop our hold
		 */
		mount_unlock_renames(locked_mp);
		mount_drop(locked_mp, 0);
	        holding_mntlock = 0;
	}
	if (tdvp != fdvp && fvp->v_type == VDIR) {
	        /*
		 * serialize renames that re-shape
		 * the tree... if holding_mntlock is
		 * set, then we're ready to go...
		 * otherwise we
		 * first need to drop the iocounts
		 * we picked up, second take the
		 * lock to serialize the access,
		 * then finally start the lookup
		 * process over with the lock held
		 */
	        if (!holding_mntlock) {
		        /*
			 * need to grab a reference on
			 * the mount point before we
			 * drop all the iocounts... once
			 * the iocounts are gone, the mount
			 * could follow
			 */
			locked_mp = fvp->v_mount;
			mount_ref(locked_mp, 0);

			/*
			 * nameidone has to happen before we vnode_put(tvp)
			 * since it may need to release the fs_nodelock on the tvp
			 */
			nameidone(&tond);

			if (tvp)
			        vnode_put(tvp);
			vnode_put(tdvp);

			/*
			 * nameidone has to happen before we vnode_put(fdvp)
			 * since it may need to release the fs_nodelock on the fvp
			 */
			nameidone(&fromnd);

			vnode_put(fvp);
			vnode_put(fdvp);

			mount_lock_renames(locked_mp);
			holding_mntlock = 1;

			goto retry;
		}
	} else {
	        /*
		 * when we dropped the iocounts to take
		 * the lock, we allowed the identity of 
		 * the various vnodes to change... if they did,
		 * we may no longer be dealing with a rename
		 * that reshapes the tree... once we're holding
		 * the iocounts, the vnodes can't change type
		 * so we're free to drop the lock at this point
		 * and continue on
		 */
	        if (holding_mntlock) {
			mount_unlock_renames(locked_mp);
			mount_drop(locked_mp, 0);
		        holding_mntlock = 0;
		}
	}
	// save these off so we can later verify that fvp is the same
	oname   = fvp->v_name;
	oparent = fvp->v_parent;

	if (need_fsevent(FSE_RENAME, fvp)) {
	        get_fse_info(fvp, &from_finfo, &context);

		if (tvp) {
		        get_fse_info(tvp, &to_finfo, &context);
		}
	        from_name = get_pathbuff();
		from_len = MAXPATHLEN;
		vn_getpath(fvp, from_name, &from_len);

		to_name = get_pathbuff();
		to_len = MAXPATHLEN;

		if (tvp && tvp->v_type != VDIR) {
		        vn_getpath(tvp, to_name, &to_len);
		} else {
		        vn_getpath(tdvp, to_name, &to_len);
			// if the path is not just "/", then append a "/"
			if (to_len > 2) {
			        to_name[to_len-1] = '/';
			} else {
			        to_len--;
			}
			strcpy(&to_name[to_len], tond.ni_cnd.cn_nameptr);
			to_len += tond.ni_cnd.cn_namelen + 1;
			to_name[to_len] = '\0';
		}
	} else {
	        from_name = NULL;
	        to_name   = NULL;
	}
	error = VNOP_RENAME(fdvp, fvp, &fromnd.ni_cnd,
			    tdvp, tvp, &tond.ni_cnd,
			    &context);

	if (holding_mntlock) {
		/*
		 * we can drop our serialization
		 * lock now
		 */
		mount_unlock_renames(locked_mp);
		mount_drop(locked_mp, 0);
		holding_mntlock = 0;
	}
	if (error) {
		if (to_name != NULL)
		        release_pathbuff(to_name);
		if (from_name != NULL)
		        release_pathbuff(from_name);
		from_name = to_name = NULL;

		goto out1;
	} 
	
	/* call out to allow 3rd party notification of rename. 
	 * Ignore result of kauth_authorize_fileop call.
	 */
	kauth_authorize_fileop(vfs_context_ucred(&context), KAUTH_FILEOP_RENAME, 
						   (uintptr_t)from_name, (uintptr_t)to_name);

	if (from_name != NULL && to_name != NULL) {
	        if (tvp) {
		        add_fsevent(FSE_RENAME, &context,
				    FSE_ARG_STRING, from_len, from_name,
				    FSE_ARG_FINFO, &from_finfo,
				    FSE_ARG_STRING, to_len, to_name,
				    FSE_ARG_FINFO, &to_finfo,
				    FSE_ARG_DONE);
		} else {
		        add_fsevent(FSE_RENAME, &context,
				    FSE_ARG_STRING, from_len, from_name,
				    FSE_ARG_FINFO, &from_finfo,
				    FSE_ARG_STRING, to_len, to_name,
				    FSE_ARG_DONE);
		}
	}
	if (to_name != NULL)
	        release_pathbuff(to_name);
	if (from_name != NULL)
	        release_pathbuff(from_name);
	from_name = to_name = NULL;
		
	/*
	 * update filesystem's mount point data
	 */
	if (mntrename) {
	        char *cp, *pathend, *mpname;
		char * tobuf;
		struct mount *mp;
		int maxlen;
		size_t len = 0;

		mp = fvp->v_mountedhere;

		if (vfs_busy(mp, LK_NOWAIT)) {
		        error = EBUSY;
			goto out1;
		}
		MALLOC_ZONE(tobuf, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);

		error = copyinstr(uap->to, tobuf, MAXPATHLEN, &len);
		if (!error) {
		        /* find current mount point prefix */
		        pathend = &mp->mnt_vfsstat.f_mntonname[0];
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
			maxlen = MAXPATHLEN - (pathend - mp->mnt_vfsstat.f_mntonname);
			bzero(pathend, maxlen);
			strncpy(pathend, mpname, maxlen - 1);
		}
		FREE_ZONE(tobuf, MAXPATHLEN, M_NAMEI);

		vfs_unbusy(mp);
	}
	/*
	 * fix up name & parent pointers.  note that we first	
	 * check that fvp has the same name/parent pointers it
	 * had before the rename call... this is a 'weak' check
	 * at best...
	 */
	if (oname == fvp->v_name && oparent == fvp->v_parent) {
	        int update_flags;

	        update_flags = VNODE_UPDATE_NAME;

		if (fdvp != tdvp)
		        update_flags |= VNODE_UPDATE_PARENT;

	        vnode_update_identity(fvp, tdvp, tond.ni_cnd.cn_nameptr, tond.ni_cnd.cn_namelen, tond.ni_cnd.cn_hash, update_flags);
	}
out1:
	if (holding_mntlock) {
	        mount_unlock_renames(locked_mp);
		mount_drop(locked_mp, 0);
	}
	if (tdvp) {
		/*
		 * nameidone has to happen before we vnode_put(tdvp)
		 * since it may need to release the fs_nodelock on the tdvp
		 */
		nameidone(&tond);

		if (tvp)
		        vnode_put(tvp);
	        vnode_put(tdvp);
	}
	if (fdvp) {
		/*
		 * nameidone has to happen before we vnode_put(fdvp)
		 * since it may need to release the fs_nodelock on the fdvp
		 */
		nameidone(&fromnd);

		if (fvp)
		        vnode_put(fvp);
	        vnode_put(fdvp);
	}
	return (error);
}

/*
 * Make a directory file.
 */
/* ARGSUSED */
static int
mkdir1(vfs_context_t ctx, user_addr_t path, struct vnode_attr *vap)
{
	vnode_t	vp, dvp;
	int error;
	int update_flags = 0;
	struct nameidata nd;

	AUDIT_ARG(mode, vap->va_mode);
	NDINIT(&nd, CREATE, LOCKPARENT | AUDITVNPATH1, 
		UIO_USERSPACE, path, ctx);
	nd.ni_cnd.cn_flags |= WILLBEDIR;
	error = namei(&nd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

  	if (vp != NULL) {
  		error = EEXIST;
  		goto out;
  	}
   
  	/* authorize addition of a directory to the parent */
  	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_SUBDIRECTORY, ctx)) != 0)
  		goto out;
 	
	VATTR_SET(vap, va_type, VDIR);
   
	/* make the directory */
  	if ((error = vn_create(dvp, &vp, &nd.ni_cnd, vap, 0, ctx)) != 0)
  		goto out;
		
	// Make sure the name & parent pointers are hooked up
	if (vp->v_name == NULL)
	        update_flags |= VNODE_UPDATE_NAME;
	if (vp->v_parent == NULLVP)
	        update_flags |= VNODE_UPDATE_PARENT;

	if (update_flags)
	        vnode_update_identity(vp, dvp, nd.ni_cnd.cn_nameptr, nd.ni_cnd.cn_namelen, nd.ni_cnd.cn_hash, update_flags);

	add_fsevent(FSE_CREATE_DIR, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);

out:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	if (vp)
	        vnode_put(vp);
	vnode_put(dvp);

	return (error);
}


int
mkdir_extended(struct proc *p, register struct mkdir_extended_args *uap, __unused register_t *retval)
{
	struct vfs_context context;
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vnode_attr va;

	xsecdst = NULL;
	if ((uap->xsecurity != USER_ADDR_NULL) &&
	    ((ciferror = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0))
		return ciferror;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	VATTR_INIT(&va);
  	VATTR_SET(&va, va_mode, (uap->mode & ACCESSPERMS) & ~p->p_fd->fd_cmask);
	if (xsecdst != NULL)
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);

	ciferror = mkdir1(&context, uap->path, &va);
	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);
	return ciferror;
}

int
mkdir(struct proc *p, register struct mkdir_args *uap, __unused register_t *retval)
{
	struct vfs_context context;
	struct vnode_attr va;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	VATTR_INIT(&va);
  	VATTR_SET(&va, va_mode, (uap->mode & ACCESSPERMS) & ~p->p_fd->fd_cmask);

	return(mkdir1(&context, uap->path, &va));
}

/*
 * Remove a directory file.
 */
/* ARGSUSED */
int
rmdir(struct proc *p, struct rmdir_args *uap, __unused register_t *retval)
{
        vnode_t vp, dvp;
	int error;
	struct nameidata nd;
	struct vfs_context context;
	
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, DELETE, LOCKPARENT | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp->v_type != VDIR) {
	        /*
		 * rmdir only deals with directories
		 */
		error = ENOTDIR;
	} else if (dvp == vp) {
	        /*
		 * No rmdir "." please.
		 */
		error = EINVAL;
	} else if (vp->v_flag & VROOT) {
	        /*
		 * The root of a mounted filesystem cannot be deleted.
		 */
		error = EBUSY;
	} else {
		error = vnode_authorize(vp, nd.ni_dvp, KAUTH_VNODE_DELETE, &context);
	}
	if (!error) {
		char     *path = NULL;
		int       len;
		fse_info  finfo;
		
		if (need_fsevent(FSE_DELETE, dvp)) {
		        path = get_pathbuff();
			len = MAXPATHLEN;
			vn_getpath(vp, path, &len);
			get_fse_info(vp, &finfo, &context);
		}
		error = VNOP_RMDIR(dvp, vp, &nd.ni_cnd, &context);

		if (!error && path != NULL) {
			add_fsevent(FSE_DELETE, &context,
				FSE_ARG_STRING, len, path,
				FSE_ARG_FINFO, &finfo,
				FSE_ARG_DONE);
		}
		if (path != NULL)
		        release_pathbuff(path);
	}
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);

	vnode_put(dvp);
	vnode_put(vp);

	return (error);
}


/*
 * Read a block of directory entries in a file system independent format.
 */
int
getdirentries(p, uap, retval)
	struct proc *p;
	register struct getdirentries_args *uap;
	register_t *retval;
{
	struct vnode *vp;
	struct vfs_context context;
	struct fileproc *fp;
	uio_t auio;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	long loff;
	int error, eofflag;
	int fd = uap->fd;
	char uio_buf[ UIO_SIZEOF(1) ];

	AUDIT_ARG(fd, uap->fd);
	error = fp_getfvp(p, fd, &fp, &vp);
	if (error)
		return (error);

	if ((fp->f_fglob->fg_flag & FREAD) == 0) {
		AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);
		error = EBADF;
		goto out;
	}
	if ( (error = vnode_getwithref(vp)) ) {
		goto out;
	}

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

unionread:
	if (vp->v_type != VDIR) {
		(void)vnode_put(vp);
		error = EINVAL;
		goto out;
	}
	context.vc_proc = p;
	context.vc_ucred = fp->f_fglob->fg_cred;

	loff = fp->f_fglob->fg_offset;
	auio = uio_createwithbuffer(1, loff, spacetype, UIO_READ, 
								  &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, uap->buf, uap->count);

	error = VNOP_READDIR(vp, auio, 0, &eofflag, (int *)NULL, &context);
	fp->f_fglob->fg_offset = uio_offset(auio);
	if (error) {
		(void)vnode_put(vp);
		goto out;
	}

#if UNION
{
	if ((uap->count == uio_resid(auio)) &&
	    (vp->v_op == union_vnodeop_p)) {
		struct vnode *lvp;

		lvp = union_dircache(vp, p);
		if (lvp != NULLVP) {
			struct vnode_attr va;
			/*
			 * If the directory is opaque,
			 * then don't show lower entries
			 */
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_flags);
			error = vnode_getattr(vp, &va, &context);
			if (va.va_flags & OPAQUE) {
				vnode_put(lvp);
				lvp = NULL;
			}
		}

		if (lvp != NULLVP) {
			error = VNOP_OPEN(lvp, FREAD, &context);
			if (error) {
				vnode_put(lvp);
				goto out;
			}
			vnode_ref(lvp);
			fp->f_fglob->fg_data = (caddr_t) lvp;
			fp->f_fglob->fg_offset = 0;
			error = VNOP_CLOSE(vp, FREAD, &context);
			vnode_rele(vp);
			vnode_put(vp);
			if (error)
				goto out;
			vp = lvp;
			goto unionread;
		}
	}
}
#endif /* UNION */

	if (((user_ssize_t)uap->count == uio_resid(auio)) &&
	    (vp->v_flag & VROOT) &&
	    (vp->v_mount->mnt_flag & MNT_UNION)) {
		struct vnode *tvp = vp;
		vp = vp->v_mount->mnt_vnodecovered;
		vnode_getwithref(vp);
		vnode_ref(vp);
		fp->f_fglob->fg_data = (caddr_t) vp;
		fp->f_fglob->fg_offset = 0;
		vnode_rele(tvp);
		vnode_put(tvp);
		goto unionread;
	}
	vnode_put(vp);
	error = copyout((caddr_t)&loff, uap->basep, sizeof(long));
	// LP64todo - fix this
	*retval = uap->count - uio_resid(auio);
out:
	file_drop(fd);
	return (error);
}

/*
 * Set the mode mask for creation of filesystem nodes.
 */
#warning XXX implement xsecurity

#define UMASK_NOXSECURITY	 (void *)1	/* leave existing xsecurity alone */
static int
umask1(struct proc *p, int newmask, __unused kauth_filesec_t fsec, register_t *retval)
{
	register struct filedesc *fdp;

	AUDIT_ARG(mask, newmask);
	fdp = p->p_fd;
	*retval = fdp->fd_cmask;
	fdp->fd_cmask = newmask & ALLPERMS;
	return (0);
}


int
umask_extended(struct proc *p, struct umask_extended_args *uap, register_t *retval)
{
	int ciferror;
	kauth_filesec_t xsecdst;

	xsecdst = KAUTH_FILESEC_NONE;
	if (uap->xsecurity != USER_ADDR_NULL) {
		if ((ciferror = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0)
			return ciferror;
	} else {
		xsecdst = KAUTH_FILESEC_NONE;
	}

	ciferror = umask1(p, uap->newmask, xsecdst, retval);

	if (xsecdst != KAUTH_FILESEC_NONE)
		kauth_filesec_free(xsecdst);
	return ciferror;
}

int
umask(struct proc *p, struct umask_args *uap, register_t *retval)
{
	return(umask1(p, uap->newmask, UMASK_NOXSECURITY, retval));
}

/*
 * Void all references to file by ripping underlying filesystem
 * away from vnode.
 */
/* ARGSUSED */
int
revoke(struct proc *p, register struct revoke_args *uap, __unused register_t *retval)
{
	register struct vnode *vp;
	struct vnode_attr va;
	struct vfs_context context;
	int error;
	struct nameidata nd;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	if ((error = vnode_getattr(vp, &va, &context)))
		goto out;
	if (kauth_cred_getuid(context.vc_ucred) != va.va_uid &&
	    (error = suser(context.vc_ucred, &p->p_acflag)))
		goto out;
	if (vp->v_usecount > 1 || (vp->v_flag & VALIASED))
		VNOP_REVOKE(vp, REVOKEALL, &context);
out:
	vnode_put(vp);
	return (error);
}


/*
 *  HFS/HFS PlUS SPECIFIC SYSTEM CALLS
 *  The following system calls are designed to support features
 *  which are specific to the HFS & HFS Plus volume formats
 */

#ifdef __APPLE_API_OBSOLETE

/************************************************/
/* *** Following calls will be deleted soon *** */
/************************************************/

/*
 * Make a complex file.  A complex file is one with multiple forks (data streams)
 */
/* ARGSUSED */
int
mkcomplex(__unused struct proc *p, __unused struct mkcomplex_args *uap, __unused register_t *retval)
{
	return (ENOTSUP);
}

/*
 * Extended stat call which returns volumeid and vnodeid as well as other info
 */
/* ARGSUSED */
int
statv(__unused struct proc *p,
	  __unused struct statv_args *uap,
	  __unused register_t *retval)
{
	return (ENOTSUP);	/*  We'll just return an error for now */

} /* end of statv system call */

/*
* Extended lstat call which returns volumeid and vnodeid as well as other info
*/
/* ARGSUSED */
int
lstatv(__unused struct proc *p,
	   __unused struct lstatv_args *uap,
	   __unused register_t *retval)
{
       return (ENOTSUP);	/*  We'll just return an error for now */
} /* end of lstatv system call */

/*
* Extended fstat call which returns volumeid and vnodeid as well as other info
*/
/* ARGSUSED */
int
fstatv(__unused struct proc *p, 
	   __unused struct fstatv_args *uap, 
	   __unused register_t *retval)
{
       return (ENOTSUP);	/*  We'll just return an error for now */
} /* end of fstatv system call */


/************************************************/
/* *** Preceding calls will be deleted soon *** */
/************************************************/

#endif /* __APPLE_API_OBSOLETE */

/*
* Obtain attribute information on objects in a directory while enumerating
* the directory.  This call does not yet support union mounted directories.
* TO DO
*  1.union mounted directories.
*/

/* ARGSUSED */
int
getdirentriesattr (struct proc *p, struct getdirentriesattr_args *uap, register_t *retval)
{
	struct vnode *vp;
	struct fileproc *fp;
	uio_t auio = NULL;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	uint64_t actualcount;
	u_long tmpcount;
	u_long newstate;
	int error, eofflag;
	u_long loff;
	struct attrlist attributelist; 
	struct vfs_context context;
	int fd = uap->fd;
	char uio_buf[ UIO_SIZEOF(1) ];
	kauth_action_t action;

	AUDIT_ARG(fd, fd);
    
	/* Get the attributes into kernel space */
	if ((error = copyin(uap->alist, (caddr_t) &attributelist, sizeof (attributelist))))
		return(error);
	actualcount = fuulong(uap->count);
	if (actualcount == -1ULL)
		return(-1);

	if ( (error = fp_getfvp(p, fd, &fp, &vp)) )
		return (error);

	if ((fp->f_fglob->fg_flag & FREAD) == 0) {
		AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);
		error = EBADF;
		goto out;
	}
	if ( (error = vnode_getwithref(vp)) )
		goto out;

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	if (vp->v_type != VDIR) {
		(void)vnode_put(vp);
		error = EINVAL;
		goto out;
	}

	/* set up the uio structure which will contain the users return buffer */
	loff = fp->f_fglob->fg_offset;
	auio = uio_createwithbuffer(1, loff, spacetype, UIO_READ, 
	    &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, uap->buffer, uap->buffersize);
       
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	tmpcount = (u_long) actualcount;

	/*
	 * If the only item requested is file names, we can let that past with
	 * just LIST_DIRECTORY.  If they want any other attributes, that means
	 * they need SEARCH as well.
	 */
	action = KAUTH_VNODE_LIST_DIRECTORY;
	if ((attributelist.commonattr & ~ATTR_CMN_NAME) ||
	    attributelist.fileattr || attributelist.dirattr)
		action |= KAUTH_VNODE_SEARCH;
	
	if ((error = vnode_authorize(vp, NULL, action, &context)) == 0)
		error = VNOP_READDIRATTR(vp, &attributelist, auio,
		    tmpcount, uap->options, &newstate, &eofflag,
		    &tmpcount, &context);
	(void)vnode_put(vp);
	actualcount = tmpcount;

	if (error) 
		goto out;
	fp->f_fglob->fg_offset = uio_offset(auio); /* should be multiple of dirent, not variable */

	if ((error = suulong(uap->count, actualcount)) != 0)
		goto out;
	if ((error = suulong(uap->newstate, (uint64_t)newstate)) != 0)
		goto out;
	if ((error = suulong(uap->basep, (uint64_t)loff)) != 0)
		goto out;

	*retval = eofflag;  /* similar to getdirentries */
	error = 0;
	out:
	file_drop(fd);
	return (error); /* return error earlier, an retval of 0 or 1 now */

} /* end of getdirentryattr system call */

/*
* Exchange data between two files
*/

/* ARGSUSED */
int
exchangedata (struct proc *p, register struct exchangedata_args *uap, __unused register_t *retval)
{

	struct nameidata fnd, snd;
	struct vfs_context context;
	struct vnode *fvp, *svp;
    int error;
	u_long nameiflags;
	char *fpath = NULL;
	char *spath = NULL;
	int   flen, slen;
	fse_info f_finfo, s_finfo;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;

    NDINIT(&fnd, LOOKUP, nameiflags | AUDITVNPATH1, 
        	UIO_USERSPACE, uap->path1, &context);

    error = namei(&fnd);
    if (error)
        goto out2;

	nameidone(&fnd);
	fvp = fnd.ni_vp;

    NDINIT(&snd, LOOKUP, nameiflags | AUDITVNPATH2, 
        	UIO_USERSPACE, uap->path2, &context);

    error = namei(&snd);
    if (error) {
		vnode_put(fvp);
		goto out2;
    }
	nameidone(&snd);
	svp = snd.ni_vp;

	/*
	 * if the files are the same, return an inval error
	 */
	if (svp == fvp) {
		error = EINVAL;
		goto out;
	} 

	/*
	 * if the files are on different volumes, return an error
	 */
	if (svp->v_mount != fvp->v_mount) {
	        error = EXDEV;
		goto out;
	}
	if (((error = vnode_authorize(fvp, NULL, KAUTH_VNODE_READ_DATA | KAUTH_VNODE_WRITE_DATA, &context)) != 0) ||
	    ((error = vnode_authorize(svp, NULL, KAUTH_VNODE_READ_DATA | KAUTH_VNODE_WRITE_DATA, &context)) != 0))
		goto out;

	if (need_fsevent(FSE_EXCHANGE, fvp) || kauth_authorize_fileop_has_listeners()) {
	        fpath = get_pathbuff();
		spath = get_pathbuff();
		flen = MAXPATHLEN;
		slen = MAXPATHLEN;
		if (vn_getpath(fvp, fpath, &flen) != 0 || fpath[0] == '\0') {
		        printf("exchange: vn_getpath(fvp=0x%x) failed <<%s>>\n",
			       fvp, fpath);
		}
		if (vn_getpath(svp, spath, &slen) != 0 || spath[0] == '\0') {
		        printf("exchange: vn_getpath(svp=0x%x) failed <<%s>>\n",
			       svp, spath);
		}
		get_fse_info(fvp, &f_finfo, &context);
		get_fse_info(svp, &s_finfo, &context);
	}
	/* Ok, make the call */
	error = VNOP_EXCHANGE(fvp, svp, 0, &context);

	if (error == 0) {
	    char *tmpname;

	    if (fpath != NULL && spath != NULL) {
	            /* call out to allow 3rd party notification of exchangedata. 
		     * Ignore result of kauth_authorize_fileop call.
		     */
	            kauth_authorize_fileop(vfs_context_ucred(&context), KAUTH_FILEOP_EXCHANGE, 
					   (uintptr_t)fpath, (uintptr_t)spath);
	    }
	    name_cache_lock();

	    tmpname     = fvp->v_name;
	    fvp->v_name = svp->v_name;
	    svp->v_name = tmpname;
	    
	    if (fvp->v_parent != svp->v_parent) {
		struct vnode *tmp;

		tmp           = fvp->v_parent;
		fvp->v_parent = svp->v_parent;
		svp->v_parent = tmp;
	    }
	    name_cache_unlock();

	    if (fpath != NULL && spath != NULL) {
	            add_fsevent(FSE_EXCHANGE, &context,
				FSE_ARG_STRING, flen, fpath,
				FSE_ARG_FINFO, &f_finfo,
				FSE_ARG_STRING, slen, spath,
				FSE_ARG_FINFO, &s_finfo,
				FSE_ARG_DONE);
	    }
	}
	if (spath != NULL)
	        release_pathbuff(spath);
	if (fpath != NULL)
	        release_pathbuff(fpath);

out:
	vnode_put(svp);
	vnode_put(fvp);
out2:
        return (error);
}


#ifdef __APPLE_API_OBSOLETE

/************************************************/
/* *** Following calls will be deleted soon *** */
/************************************************/

/*
* Check users access to a file 
*/

/* ARGSUSED */
#warning "checkuseraccess copies a cred in from user space but"
#warning "user space has no way of knowing what one looks like"
#warning "this code should use the access_extended spoof-as functionality"
int
checkuseraccess (struct proc *p, register struct checkuseraccess_args *uap, __unused register_t *retval)
{
	register struct vnode *vp;
	int error;
	struct nameidata nd;
	struct ucred template_cred;
	int flags;		/*what will actually get passed to access*/
	u_long nameiflags;
	struct vfs_context context;
	kauth_cred_t my_cred;

	/* Make sure that the number of groups is correct before we do anything */

	if ((uap->ngroups <=  0) || (uap->ngroups > NGROUPS))
		return (EINVAL);

	/* Verify that the caller is root */
	
	if ((error = suser(kauth_cred_get(), &p->p_acflag)))
		return(error);

	/*
	 * Fill in the template credential structure; we use a template because
	 * lookup can attempt to take a persistent reference.
	 */
	template_cred.cr_uid = uap->userid;
	template_cred.cr_ngroups = uap->ngroups;
	if ((error = copyin(CAST_USER_ADDR_T(uap->groups), (caddr_t) &(template_cred.cr_groups), (sizeof(gid_t))*uap->ngroups)))
		return (error);

	my_cred = kauth_cred_create(&template_cred);
	context.vc_proc = p;
	context.vc_ucred = my_cred;

	/* Get our hands on the file */
	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags | AUDITVNPATH1, 
		UIO_USERSPACE, CAST_USER_ADDR_T(uap->path), &context);

	if ((error = namei(&nd))) {
		kauth_cred_unref(&context.vc_ucred);
       		 return (error);
	}
	nameidone(&nd);
	vp = nd.ni_vp;
	
	/* Flags == 0 means only check for existence. */

	flags = 0;

	if (uap->accessrequired) {
		if (uap->accessrequired & R_OK)
			flags |= KAUTH_VNODE_READ_DATA;
		if (uap->accessrequired & W_OK)
			flags |= KAUTH_VNODE_WRITE_DATA;
		if (uap->accessrequired & X_OK)
			flags |= KAUTH_VNODE_EXECUTE;
		}
	error = vnode_authorize(vp, NULL, flags, &context);
		    	
	vnode_put(vp);

	kauth_cred_unref(&context.vc_ucred);
	return (error);
} /* end of checkuseraccess system call */

/************************************************/
/* *** Preceding calls will be deleted soon *** */
/************************************************/

#endif /* __APPLE_API_OBSOLETE */



/* ARGSUSED */

int
searchfs (struct proc *p, register struct searchfs_args *uap, __unused register_t *retval)
{
	register struct vnode *vp;
	int error=0;
	int fserror = 0;
	struct nameidata nd;
	struct user_fssearchblock searchblock;
	struct searchstate *state;
	struct attrlist *returnattrs;
	void *searchparams1,*searchparams2;
	uio_t auio = NULL;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	u_long nummatches;
	int mallocsize;
	u_long nameiflags;
	struct vfs_context context;
	char uio_buf[ UIO_SIZEOF(1) ];

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	/* Start by copying in fsearchblock paramater list */
    if (IS_64BIT_PROCESS(p)) {
       error = copyin(uap->searchblock, (caddr_t) &searchblock, sizeof(searchblock));
    }
    else {
        struct fssearchblock tmp_searchblock;
        error = copyin(uap->searchblock, (caddr_t) &tmp_searchblock, sizeof(tmp_searchblock));
        // munge into 64-bit version
        searchblock.returnattrs = CAST_USER_ADDR_T(tmp_searchblock.returnattrs);
        searchblock.returnbuffer = CAST_USER_ADDR_T(tmp_searchblock.returnbuffer);
        searchblock.returnbuffersize = tmp_searchblock.returnbuffersize;
        searchblock.maxmatches = tmp_searchblock.maxmatches;
        searchblock.timelimit.tv_sec = tmp_searchblock.timelimit.tv_sec;
        searchblock.timelimit.tv_usec = tmp_searchblock.timelimit.tv_usec;
        searchblock.searchparams1 = CAST_USER_ADDR_T(tmp_searchblock.searchparams1);
        searchblock.sizeofsearchparams1 = tmp_searchblock.sizeofsearchparams1;
        searchblock.searchparams2 = CAST_USER_ADDR_T(tmp_searchblock.searchparams2);
        searchblock.sizeofsearchparams2 = tmp_searchblock.sizeofsearchparams2;
        searchblock.searchattrs = tmp_searchblock.searchattrs;
    }
	if (error)
		return(error);

	/* Do a sanity check on sizeofsearchparams1 and sizeofsearchparams2.  
	 */
	if (searchblock.sizeofsearchparams1 > SEARCHFS_MAX_SEARCHPARMS || 
		searchblock.sizeofsearchparams2 > SEARCHFS_MAX_SEARCHPARMS)
		return(EINVAL);
	
	/* Now malloc a big bunch of space to hold the search parameters, the attrlists and the search state. */
	/* It all has to do into local memory and it's not that big so we might as well  put it all together. */
	/* Searchparams1 shall be first so we might as well use that to hold the base address of the allocated*/
	/* block.  											      */
	
	mallocsize = searchblock.sizeofsearchparams1 + searchblock.sizeofsearchparams2 +
		      sizeof(struct attrlist) + sizeof(struct searchstate);

	MALLOC(searchparams1, void *, mallocsize, M_TEMP, M_WAITOK);

	/* Now set up the various pointers to the correct place in our newly allocated memory */

	searchparams2 = (void *) (((caddr_t) searchparams1) + searchblock.sizeofsearchparams1);
	returnattrs = (struct attrlist *) (((caddr_t) searchparams2) + searchblock.sizeofsearchparams2);
	state = (struct searchstate *) (((caddr_t) returnattrs) + sizeof (struct attrlist));

	/* Now copy in the stuff given our local variables. */

	if ((error = copyin(searchblock.searchparams1, searchparams1, searchblock.sizeofsearchparams1)))
		goto freeandexit;

	if ((error = copyin(searchblock.searchparams2, searchparams2, searchblock.sizeofsearchparams2)))
		goto freeandexit;

	if ((error = copyin(searchblock.returnattrs, (caddr_t) returnattrs, sizeof(struct attrlist))))
		goto freeandexit;
		
	if ((error = copyin(uap->state, (caddr_t) state, sizeof(struct searchstate))))
		goto freeandexit;
	
	/* set up the uio structure which will contain the users return buffer */

	auio = uio_createwithbuffer(1, 0, spacetype, UIO_READ, 
								  &uio_buf[0], sizeof(uio_buf));
    uio_addiov(auio, searchblock.returnbuffer, searchblock.returnbuffersize);

	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, &context);

	error = namei(&nd);
	if (error)
		goto freeandexit;

	nameidone(&nd);
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

	fserror = VNOP_SEARCHFS(vp,
							searchparams1,
							searchparams2,
							&searchblock.searchattrs,
							searchblock.maxmatches,
							&searchblock.timelimit,
							returnattrs,
							&nummatches,
							uap->scriptcode,
							uap->options,
							auio,
							state,
							&context);
		
saveandexit:

	vnode_put(vp);

	/* Now copy out the stuff that needs copying out. That means the number of matches, the
	   search state.  Everything was already put into he return buffer by the vop call. */

	if ((error = copyout((caddr_t) state, uap->state, sizeof(struct searchstate))) != 0)
		goto freeandexit;

    if ((error = suulong(uap->nummatches, (uint64_t)nummatches)) != 0)
		goto freeandexit;
	
	error = fserror;

freeandexit:

	FREE(searchparams1,M_TEMP);

	return(error);


} /* end of searchfs system call */


/*
 * Make a filesystem-specific control call:
 */
/* ARGSUSED */
int
fsctl (struct proc *p, struct fsctl_args *uap, __unused register_t *retval)
{
	int error;
	boolean_t is64bit;
	struct nameidata nd;	
	u_long nameiflags;
	u_long cmd = uap->cmd;
	register u_int size;
#define STK_PARAMS 128
	char stkbuf[STK_PARAMS];
	caddr_t data, memp;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	size = IOCPARM_LEN(cmd);
	if (size > IOCPARM_MAX) return (EINVAL);

    is64bit = proc_is64bit(p);

	memp = NULL;
	if (size > sizeof (stkbuf)) {
		if ((memp = (caddr_t)kalloc(size)) == 0) return ENOMEM;
		data = memp;
	} else {
		data = &stkbuf[0];
	};
	
	if (cmd & IOC_IN) {
		if (size) {
			error = copyin(uap->data, data, size);
			if (error) goto FSCtl_Exit;
		} else {
		    if (is64bit) {
    			*(user_addr_t *)data = uap->data;
		    }
		    else {
    			*(uint32_t *)data = (uint32_t)uap->data;
		    }
		};
	} else if ((cmd & IOC_OUT) && size) {
		/*
		 * Zero the buffer so the user always
		 * gets back something deterministic.
		 */
		bzero(data, size);
	} else if (cmd & IOC_VOID) {
        if (is64bit) {
            *(user_addr_t *)data = uap->data;
        }
        else {
            *(uint32_t *)data = (uint32_t)uap->data;
        }
	}

	/* Get the vnode for the file we are getting info on:  */
	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, uap->path, &context);
	if ((error = namei(&nd))) goto FSCtl_Exit;

	/* Invoke the filesystem-specific code */
	error = VNOP_IOCTL(nd.ni_vp, IOCBASECMD(cmd), data, uap->options, &context);
	
	vnode_put(nd.ni_vp);
	nameidone(&nd);
	
	/*
	 * Copy any data to user, size was
	 * already set and checked above.
	 */
	if (error == 0 && (cmd & IOC_OUT) && size) 
		error = copyout(data, uap->data, size);
	
FSCtl_Exit:
	if (memp) kfree(memp, size);
	
	return error;
}
/* end of fsctl system call */

/*
 * An in-kernel sync for power management to call.
 */
__private_extern__ int
sync_internal(void)
{
	int error;

	struct sync_args data;

	int retval[2];


	error = sync(current_proc(), &data, &retval[0]);


	return (error);
} /* end of sync_internal call */


/*
 *  Retrieve the data of an extended attribute.
 */
int
getxattr(struct proc *p, struct getxattr_args *uap, user_ssize_t *retval)
{
	struct vnode *vp;
	struct nameidata nd;
	char attrname[XATTR_MAXNAMELEN+1];
	struct vfs_context context;
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	size_t namelen;
	u_long nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if (uap->options & XATTR_NOSECURITY)
		return (EINVAL);

	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, spacetype, uap->path, &context);
	if ((error = namei(&nd))) {
		return (error);
	}
	vp = nd.ni_vp;
	nameidone(&nd);

	if ((error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen) != 0)) {
		goto out;
	}
	if (xattr_protected(attrname)) {
		error = EPERM;
		goto out;
	}
	if (uap->value && uap->size > 0) {
		auio = uio_createwithbuffer(1, uap->position, spacetype, UIO_READ,
		                            &uio_buf[0], sizeof(uio_buf));
		uio_addiov(auio, uap->value, uap->size);
	}

	error = vn_getxattr(vp, attrname, auio, &attrsize, uap->options, &context);
out:
	vnode_put(vp);

	if (auio) {
		*retval = uap->size - uio_resid(auio);
	} else {
		*retval = (user_ssize_t)attrsize;
	}

	return (error);
}

/*
 * Retrieve the data of an extended attribute.
 */
int
fgetxattr(struct proc *p, struct fgetxattr_args *uap, user_ssize_t *retval)
{
	struct vnode *vp;
	char attrname[XATTR_MAXNAMELEN+1];
	struct vfs_context context;
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	size_t namelen;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOFOLLOW | XATTR_NOSECURITY))
		return (EINVAL);

	if ( (error = file_vnode(uap->fd, &vp)) ) {
		return (error);
	}
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}
	if ((error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen) != 0)) {
		goto out;
	}
	if (xattr_protected(attrname)) {
		error = EPERM;
		goto out;
	}
	if (uap->value && uap->size > 0) {
		auio = uio_createwithbuffer(1, uap->position, spacetype, UIO_READ,
		                            &uio_buf[0], sizeof(uio_buf));
		uio_addiov(auio, uap->value, uap->size);
	}
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	error = vn_getxattr(vp, attrname, auio, &attrsize, uap->options, &context);
out:
	(void)vnode_put(vp);
	file_drop(uap->fd);

	if (auio) {
		*retval = uap->size - uio_resid(auio);
	} else {
		*retval = (user_ssize_t)attrsize;
	}
	return (error);
}

/*
 * Set the data of an extended attribute.
 */
int
setxattr(struct proc *p, struct setxattr_args *uap, int *retval)
{
	struct vnode *vp;
	struct nameidata nd;
	char attrname[XATTR_MAXNAMELEN+1];
	struct vfs_context context;
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t namelen;
	u_long nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if (uap->options & XATTR_NOSECURITY)
		return (EINVAL);

	if ((error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen) != 0)) {
		return (error);
	}
	if (xattr_protected(attrname))
		return(EPERM);
	if (uap->value == 0 || uap->size == 0) {
		return (EINVAL);
	}

	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, spacetype, uap->path, &context);
	if ((error = namei(&nd))) {
		return (error);
	}
	vp = nd.ni_vp;
	nameidone(&nd);

	auio = uio_createwithbuffer(1, uap->position, spacetype, UIO_WRITE,
	                            &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, uap->value, uap->size);

	error = vn_setxattr(vp, attrname, auio, uap->options, &context);
	vnode_put(vp);
	*retval = 0;
	return (error);
}

/*
 * Set the data of an extended attribute.
 */
int
fsetxattr(struct proc *p, struct fsetxattr_args *uap, int *retval)
{
	struct vnode *vp;
	char attrname[XATTR_MAXNAMELEN+1];
	struct vfs_context context;
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t namelen;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOFOLLOW | XATTR_NOSECURITY))
		return (EINVAL);

	if ((error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen) != 0)) {
		return (error);
	}
	if (xattr_protected(attrname))
		return(EPERM);
	if (uap->value == 0 || uap->size == 0) {
		return (EINVAL);
	}
	if ( (error = file_vnode(uap->fd, &vp)) ) {
		return (error);
	}
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}
	auio = uio_createwithbuffer(1, uap->position, spacetype, UIO_WRITE,
	                            &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, uap->value, uap->size);
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	error = vn_setxattr(vp, attrname, auio, uap->options, &context);
	vnode_put(vp);
	file_drop(uap->fd);
	*retval = 0;
	return (error);
}

/*
 * Remove an extended attribute.
 */
#warning "code duplication"
int
removexattr(struct proc *p, struct removexattr_args *uap, int *retval)
{
	struct vnode *vp;
	struct nameidata nd;
	char attrname[XATTR_MAXNAMELEN+1];
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	struct vfs_context context;
	size_t namelen;
	u_long nameiflags;
	int error;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if (uap->options & XATTR_NOSECURITY)
		return (EINVAL);

	error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen);
	if (error != 0) {
		return (error);
	}
	if (xattr_protected(attrname))
		return(EPERM);
	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, spacetype, uap->path, &context);
	if ((error = namei(&nd))) {
		return (error);
	}
	vp = nd.ni_vp;
	nameidone(&nd);

	error = vn_removexattr(vp, attrname, uap->options, &context);
	vnode_put(vp);
	*retval = 0;
	return (error);
}

/*
 * Remove an extended attribute.
 */
#warning "code duplication"
int
fremovexattr(struct proc *p, struct fremovexattr_args *uap, int *retval)
{
	struct vnode *vp;
	char attrname[XATTR_MAXNAMELEN+1];
	struct vfs_context context;
	size_t namelen;
	int error;

	if (uap->options & (XATTR_NOFOLLOW | XATTR_NOSECURITY))
		return (EINVAL);

	error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen);
	if (error != 0) {
		return (error);
	}
	if (xattr_protected(attrname))
		return(EPERM);
	if ( (error = file_vnode(uap->fd, &vp)) ) {
		return (error);
	}
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	error = vn_removexattr(vp, attrname, uap->options, &context);
	vnode_put(vp);
	file_drop(uap->fd);
	*retval = 0;
	return (error);
}

/*
 * Retrieve the list of extended attribute names.
 */
#warning "code duplication"
int
listxattr(struct proc *p, struct listxattr_args *uap, user_ssize_t *retval)
{
	struct vnode *vp;
	struct nameidata nd;
	struct vfs_context context;
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	u_long nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	if (uap->options & XATTR_NOSECURITY)
		return (EINVAL);

	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, spacetype, uap->path, &context);
	if ((error = namei(&nd))) {
		return (error);
	}
	vp = nd.ni_vp;
	nameidone(&nd);
	if (uap->namebuf != 0 && uap->bufsize > 0) {
		// LP64todo - fix this!
		auio = uio_createwithbuffer(1, 0, spacetype, 
								  	  UIO_READ, &uio_buf[0], sizeof(uio_buf));
		uio_addiov(auio, uap->namebuf, uap->bufsize);
	}

	error = vn_listxattr(vp, auio, &attrsize, uap->options, &context);

	vnode_put(vp);
	if (auio) {
		*retval = (user_ssize_t)uap->bufsize - uio_resid(auio);
	} else {
		*retval = (user_ssize_t)attrsize;
	}
	return (error);
}

/*
 * Retrieve the list of extended attribute names.
 */
#warning "code duplication"
int
flistxattr(struct proc *p, struct flistxattr_args *uap, user_ssize_t *retval)
{
	struct vnode *vp;
	struct vfs_context context;
	uio_t auio = NULL;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOFOLLOW | XATTR_NOSECURITY))
		return (EINVAL);

	if ( (error = file_vnode(uap->fd, &vp)) ) {
		return (error);
	}
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}
	if (uap->namebuf != 0 && uap->bufsize > 0) {
		// LP64todo - fix this!
		auio = uio_createwithbuffer(1, 0, spacetype, 
								  	  UIO_READ, &uio_buf[0], sizeof(uio_buf));
		uio_addiov(auio, uap->namebuf, uap->bufsize);
	}
	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	error = vn_listxattr(vp, auio, &attrsize, uap->options, &context);

	vnode_put(vp);
	file_drop(uap->fd);
	if (auio) {
		*retval = (user_ssize_t)uap->bufsize - uio_resid(auio);
	} else {
		*retval = (user_ssize_t)attrsize;
	}
	return (error);
}

/*
 * Common routine to handle various flavors of statfs data heading out
 *	to user space.
 */
static int
munge_statfs(struct mount *mp, struct vfsstatfs *sfsp, 
    user_addr_t bufp, int *sizep, boolean_t is_64_bit, 
    boolean_t partial_copy)
{
	int		error;
	int		my_size, copy_size;

	if (is_64_bit) {
		struct user_statfs sfs;
		my_size = copy_size = sizeof(sfs);
		bzero(&sfs, my_size);
		sfs.f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
		sfs.f_type = mp->mnt_vtable->vfc_typenum;
		sfs.f_reserved1 = (short)sfsp->f_fssubtype;
		sfs.f_bsize = (user_long_t)sfsp->f_bsize;
		sfs.f_iosize = (user_long_t)sfsp->f_iosize;
		sfs.f_blocks = (user_long_t)sfsp->f_blocks;
		sfs.f_bfree = (user_long_t)sfsp->f_bfree;
		sfs.f_bavail = (user_long_t)sfsp->f_bavail;
		sfs.f_files = (user_long_t)sfsp->f_files;
		sfs.f_ffree = (user_long_t)sfsp->f_ffree;
		sfs.f_fsid = sfsp->f_fsid;
		sfs.f_owner = sfsp->f_owner;
		strncpy(&sfs.f_fstypename[0], &sfsp->f_fstypename[0], MFSNAMELEN-1);
		strncpy(&sfs.f_mntonname[0], &sfsp->f_mntonname[0], MNAMELEN-1);
		strncpy(&sfs.f_mntfromname[0], &sfsp->f_mntfromname[0], MNAMELEN-1);

		if (partial_copy) {
			copy_size -= (sizeof(sfs.f_reserved3) + sizeof(sfs.f_reserved4));
		}
		error = copyout((caddr_t)&sfs, bufp, copy_size);
	}
	else {
		struct statfs sfs;
		my_size = copy_size = sizeof(sfs);
		bzero(&sfs, my_size);
		
		sfs.f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
		sfs.f_type = mp->mnt_vtable->vfc_typenum;
		sfs.f_reserved1 = (short)sfsp->f_fssubtype;
		
		/*
		 * It's possible for there to be more than 2^^31 blocks in the filesystem, so we
		 * have to fudge the numbers here in that case.   We inflate the blocksize in order
		 * to reflect the filesystem size as best we can.
		 */
		if ((sfsp->f_blocks > LONG_MAX) 
			/* Hack for 4061702 . I think the real fix is for Carbon to 
			 * look for some volume capability and not depend on hidden
			 * semantics agreed between a FS and carbon. 
			 * f_blocks, f_bfree, and f_bavail set to -1 is the trigger
			 * for Carbon to set bNoVolumeSizes volume attribute.
			 * Without this the webdavfs files cannot be copied onto 
			 * disk as they look huge. This change should not affect
			 * XSAN as they should not setting these to -1..
			 */
			 && (sfsp->f_blocks != 0xffffffffffffffff)
			 && (sfsp->f_bfree != 0xffffffffffffffff)
			 && (sfsp->f_bavail != 0xffffffffffffffff)) {
			int		shift;

			/*
			 * Work out how far we have to shift the block count down to make it fit.
			 * Note that it's possible to have to shift so far that the resulting
			 * blocksize would be unreportably large.  At that point, we will clip
			 * any values that don't fit.
			 *
			 * For safety's sake, we also ensure that f_iosize is never reported as
			 * being smaller than f_bsize.
			 */
			for (shift = 0; shift < 32; shift++) {
				if ((sfsp->f_blocks >> shift) <= LONG_MAX)
					break;
				if ((sfsp->f_bsize << (shift + 1)) > LONG_MAX)
					break;
			}
#define __SHIFT_OR_CLIP(x, s)	((((x) >> (s)) > LONG_MAX) ? LONG_MAX : ((x) >> (s)))
			sfs.f_blocks = (long)__SHIFT_OR_CLIP(sfsp->f_blocks, shift);
			sfs.f_bfree = (long)__SHIFT_OR_CLIP(sfsp->f_bfree, shift);
			sfs.f_bavail = (long)__SHIFT_OR_CLIP(sfsp->f_bavail, shift);
#undef __SHIFT_OR_CLIP
			sfs.f_bsize = (long)(sfsp->f_bsize << shift);
			sfs.f_iosize = lmax(sfsp->f_iosize, sfsp->f_bsize);
		} else {
			/* filesystem is small enough to be reported honestly */
			sfs.f_bsize = (long)sfsp->f_bsize;
			sfs.f_iosize = (long)sfsp->f_iosize;
			sfs.f_blocks = (long)sfsp->f_blocks;
			sfs.f_bfree = (long)sfsp->f_bfree;
			sfs.f_bavail = (long)sfsp->f_bavail;
		}
		sfs.f_files = (long)sfsp->f_files;
		sfs.f_ffree = (long)sfsp->f_ffree;
		sfs.f_fsid = sfsp->f_fsid;
		sfs.f_owner = sfsp->f_owner;
		strncpy(&sfs.f_fstypename[0], &sfsp->f_fstypename[0], MFSNAMELEN-1);
		strncpy(&sfs.f_mntonname[0], &sfsp->f_mntonname[0], MNAMELEN-1);
		strncpy(&sfs.f_mntfromname[0], &sfsp->f_mntfromname[0], MNAMELEN-1);

		if (partial_copy) {
			copy_size -= (sizeof(sfs.f_reserved3) + sizeof(sfs.f_reserved4));
		}
		error = copyout((caddr_t)&sfs, bufp, copy_size);
	}
	
	if (sizep != NULL) {
		*sizep = my_size;
	}
	return(error);
}

/*
 * copy stat structure into user_stat structure.
 */
void munge_stat(struct stat *sbp, struct user_stat *usbp)
{
        bzero(usbp, sizeof(struct user_stat));

	usbp->st_dev = sbp->st_dev;
	usbp->st_ino = sbp->st_ino;
	usbp->st_mode = sbp->st_mode;
	usbp->st_nlink = sbp->st_nlink;
	usbp->st_uid = sbp->st_uid;
	usbp->st_gid = sbp->st_gid;
	usbp->st_rdev = sbp->st_rdev;
#ifndef _POSIX_SOURCE
	usbp->st_atimespec.tv_sec = sbp->st_atimespec.tv_sec;
	usbp->st_atimespec.tv_nsec = sbp->st_atimespec.tv_nsec;
	usbp->st_mtimespec.tv_sec = sbp->st_mtimespec.tv_sec;
	usbp->st_mtimespec.tv_nsec = sbp->st_mtimespec.tv_nsec;
	usbp->st_ctimespec.tv_sec = sbp->st_ctimespec.tv_sec;
	usbp->st_ctimespec.tv_nsec = sbp->st_ctimespec.tv_nsec;
#else
	usbp->st_atime = sbp->st_atime;
	usbp->st_atimensec = sbp->st_atimensec;
	usbp->st_mtime = sbp->st_mtime;
	usbp->st_mtimensec = sbp->st_mtimensec;
	usbp->st_ctime = sbp->st_ctime;
	usbp->st_ctimensec = sbp->st_ctimensec;
#endif
	usbp->st_size = sbp->st_size;
	usbp->st_blocks = sbp->st_blocks;
	usbp->st_blksize = sbp->st_blksize;
	usbp->st_flags = sbp->st_flags;
	usbp->st_gen = sbp->st_gen;
	usbp->st_lspare = sbp->st_lspare;
	usbp->st_qspare[0] = sbp->st_qspare[0];
	usbp->st_qspare[1] = sbp->st_qspare[1];
}
