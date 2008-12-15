/*
 * Copyright (c) 1995-2008 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
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
#include <sys/disk.h>
#include <machine/cons.h>
#include <machine/limits.h>
#include <miscfs/specfs/specdev.h>
#include <miscfs/union/union.h>

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>

#include <vm/vm_pageout.h>

#include <libkern/OSAtomic.h>

#if CONFIG_MACF
#include <security/mac.h>
#include <security/mac_framework.h>
#endif

#if CONFIG_FSE 
#define GET_PATH(x) \
	(x) = get_pathbuff(); 
#define RELEASE_PATH(x) \
	release_pathbuff(x);
#else 
#define GET_PATH(x)	\
	MALLOC_ZONE((x), char *, MAXPATHLEN, M_NAMEI, M_WAITOK); 
#define RELEASE_PATH(x) \
	FREE_ZONE((x), MAXPATHLEN, M_NAMEI);
#endif /* CONFIG_FSE */

/* struct for checkdirs iteration */
struct cdirargs {
	vnode_t olddp;
	vnode_t newdp;
};
/* callback  for checkdirs iteration */
static int checkdirs_callback(proc_t p, void * arg);

static int change_dir(struct nameidata *ndp, vfs_context_t ctx);
static int checkdirs(vnode_t olddp, vfs_context_t ctx);
void enablequotas(struct mount *mp, vfs_context_t ctx);
static int getfsstat_callback(mount_t mp, void * arg);
static int getutimes(user_addr_t usrtvp, struct timespec *tsp);
static int setutimes(vfs_context_t ctx, vnode_t vp, const struct timespec *ts, int nullflag);
static int sync_callback(mount_t, void *);
static int munge_statfs(struct mount *mp, struct vfsstatfs *sfsp, 
			user_addr_t bufp, int *sizep, boolean_t is_64_bit, 
						boolean_t partial_copy);
static int statfs64_common(struct mount *mp, struct vfsstatfs *sfsp, user_addr_t bufp);
int (*union_dircheckp)(struct vnode **, struct fileproc *, vfs_context_t);

__private_extern__
int sync_internal(void);

__private_extern__
int open1(vfs_context_t, struct nameidata *, int, struct vnode_attr *, register_t *);

__private_extern__
int unlink1(vfs_context_t, struct nameidata *, int);


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

int fstatv(proc_t p, struct fstatv_args *uap, register_t *retval);
int lstatv(proc_t p, struct lstatv_args *uap, register_t *retval);
int mkcomplex(proc_t p, struct mkcomplex_args *uap, register_t *retval);
int statv(proc_t p, struct statv_args *uap, register_t *retval);

#endif /* __APPLE_API_OBSOLETE */

/*
 * incremented each time a mount or unmount operation occurs
 * used to invalidate the cached value of the rootvp in the
 * mount structure utilized by cache_lookup_path
 */
int mount_generation = 0;

/* counts number of mount and unmount operations */
unsigned int vfs_nummntops=0;

extern struct fileops vnops;
extern errno_t rmdir_remove_orphaned_appleDouble(vnode_t, vfs_context_t, int *); 


/*
 * Virtual File System System Calls
 */

/*
 * Mount a file system.
 */
/* ARGSUSED */
int
mount(proc_t p, struct mount_args *uap, __unused register_t *retval)
{
	struct __mac_mount_args muap;

	muap.type = uap->type;
	muap.path = uap->path;
	muap.flags = uap->flags;
	muap.data = uap->data;
	muap.mac_p = USER_ADDR_NULL;
	return (__mac_mount(p, &muap, retval));
}

int
__mac_mount(struct proc *p, register struct __mac_mount_args *uap, __unused register_t *retval)
{
	struct vnode *vp;
	struct vnode *devvp = NULLVP;
	struct vnode *device_vnode = NULLVP;
#if CONFIG_MACF
	struct vnode *rvp;
#endif
	struct mount *mp;
	struct vfstable *vfsp = (struct vfstable *)0;
	int error, flag = 0;
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
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

	is_64bit = proc_is64bit(p);

	/*
	 * Get vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, NOTRIGGER | FOLLOW | AUDITVNPATH1, 
		   UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	
	if ((vp->v_flag & VROOT) &&
		(vp->v_mount->mnt_flag & MNT_ROOTFS)) 
			uap->flags |= MNT_UPDATE;

	error = copyinstr(uap->type, fstypename, MFSNAMELEN, &dummy);
	if (error)
		goto out1;
	
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
		if (mp->mnt_vfsstat.f_owner != kauth_cred_getuid(vfs_context_ucred(ctx)) &&
		    (error = suser(vfs_context_ucred(ctx), &p->p_acflag))) {
			goto out1;
		}
#if CONFIG_MACF
		error = mac_mount_check_remount(ctx, mp);
		if (error != 0) {
			lck_rw_done(&mp->mnt_rwlock);
			goto out1;
		}
#endif
		/*
		 * For non-root users, silently enforce MNT_NOSUID and MNT_NODEV,
		 * and MNT_NOEXEC if mount point is already MNT_NOEXEC.
		 */
		if (suser(vfs_context_ucred(ctx), NULL)) {
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
	if ((error = vnode_getattr(vp, &va, ctx)) ||
	    (va.va_uid != kauth_cred_getuid(vfs_context_ucred(ctx)) &&
	     (error = suser(vfs_context_ucred(ctx), &p->p_acflag)))) {
		goto out1;
	}
	/*
	 * For non-root users, silently enforce MNT_NOSUID and MNT_NODEV, and
	 * MNT_NOEXEC if mount point is already MNT_NOEXEC.
	 */
	if (suser(vfs_context_ucred(ctx), NULL)) {
		uap->flags |= MNT_NOSUID | MNT_NODEV;
		if (vp->v_mount->mnt_flag & MNT_NOEXEC)
			uap->flags |= MNT_NOEXEC;
	}
	if ( (error = VNOP_FSYNC(vp, MNT_WAIT, ctx)) )
		goto out1;

	if ( (error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0)) )
		goto out1;

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out1;
	}

	/* XXXAUDIT: Should we capture the type on the error path as well? */
	AUDIT_ARG(text, fstypename);
	mount_list_lock();
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strncmp(vfsp->vfc_name, fstypename, MFSNAMELEN))
			break;
	mount_list_unlock();
	if (vfsp == NULL) {
		error = ENODEV;
		goto out1;
	}
#if CONFIG_MACF
	error = mac_mount_check_mount(ctx, vp,
	    &nd.ni_cnd, vfsp->vfc_name);
	if (error != 0)
		goto out1;
#endif
	if (ISSET(vp->v_flag, VMOUNT) && (vp->v_mountedhere != NULL)) {
		error = EBUSY;
		goto out1;
	}
	vnode_lock_spin(vp);
	SET(vp->v_flag, VMOUNT);
	vnode_unlock(vp);

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
	mp->mnt_alignmentmask = PAGE_MASK;
	mp->mnt_ioflags = 0;
	mp->mnt_realrootvp = NULLVP;
	mp->mnt_authcache_ttl = CACHED_LOOKUP_RIGHT_TTL;

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
	mp->mnt_vfsstat.f_owner = kauth_cred_getuid(vfs_context_ucred(ctx));
	mp->mnt_devbsdunit = LOWPRI_MAX_NUM_DEV - 1;

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
			  MNT_UNKNOWNPERMISSIONS | MNT_DONTBROWSE | MNT_AUTOMOUNTED |
			  MNT_DEFWRITE | MNT_NOATIME | MNT_QUARANTINE);
	mp->mnt_flag |= uap->flags & (MNT_NOSUID | MNT_NOEXEC |	MNT_NODEV |
				      MNT_SYNCHRONOUS | MNT_UNION | MNT_ASYNC |
				      MNT_UNKNOWNPERMISSIONS | MNT_DONTBROWSE | MNT_AUTOMOUNTED | 
					  MNT_DEFWRITE | MNT_NOATIME | MNT_QUARANTINE);

#if CONFIG_MACF
	if (uap->flags & MNT_MULTILABEL) {
		if (vfsp->vfc_vfsflags & VFC_VFSNOMACLABEL) {
			error = EINVAL;
			goto out1;
		}
		mp->mnt_flag |= MNT_MULTILABEL;
	}
#endif

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
			NDINIT(&nd1, LOOKUP, FOLLOW, UIO_USERSPACE, devpath, ctx);
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
			if (suser(vfs_context_ucred(ctx), NULL) != 0) {
				accessmode = KAUTH_VNODE_READ_DATA;
				if ((mp->mnt_flag & MNT_RDONLY) == 0)
					accessmode |= KAUTH_VNODE_WRITE_DATA;
				if ((error = vnode_authorize(devvp, NULL, accessmode, ctx)) != 0)
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
			if ( (error = VNOP_FSYNC(devvp, MNT_WAIT, ctx)) ) {
				error = ENOTBLK;
				goto out3;
			}
			if ( (error = buf_invalidateblks(devvp, BUF_WRITE_DATA, 0, 0)) )
				goto out3;

			ronly = (mp->mnt_flag & MNT_RDONLY) != 0;
#if CONFIG_MACF
			error = mac_vnode_check_open(ctx,
			    devvp,
			    ronly ? FREAD : FREAD|FWRITE);
			if (error)
				goto out3;
#endif /* MAC */
			if ( (error = VNOP_OPEN(devvp, ronly ? FREAD : FREAD|FWRITE, ctx)) )
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
				if (device_vnode && suser(vfs_context_ucred(ctx), NULL)) {
					if ((error = vnode_authorize(device_vnode, NULL,
						 KAUTH_VNODE_READ_DATA | KAUTH_VNODE_WRITE_DATA, ctx)) != 0)
						goto out2;
				}
			}
			device_vnode = NULLVP;
		}
	}
#if CONFIG_MACF
	if ((uap->flags & MNT_UPDATE) == 0) {
		mac_mount_label_init(mp);
		mac_mount_label_associate(ctx, mp);
	}
	if (uap->mac_p != USER_ADDR_NULL) {
		struct user_mac mac;
		char *labelstr = NULL;
		size_t ulen = 0;

		if ((uap->flags & MNT_UPDATE) != 0) {
			error = mac_mount_check_label_update(
			    ctx, mp);
			if (error != 0)
				goto out3;
		}
		if (is_64bit) {
			error = copyin(uap->mac_p, &mac, sizeof(mac));
		} else {
			struct mac mac32;
			error = copyin(uap->mac_p, &mac32, sizeof(mac32));
			mac.m_buflen = mac32.m_buflen;
			mac.m_string = CAST_USER_ADDR_T(mac32.m_string);
		}
		if (error != 0)
			goto out3;
		if ((mac.m_buflen > MAC_MAX_LABEL_BUF_LEN) ||
		    (mac.m_buflen < 2)) {
			error = EINVAL;
			goto out3;
		}
		MALLOC(labelstr, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
		error = copyinstr(mac.m_string, labelstr, mac.m_buflen, &ulen);
		if (error != 0) {
			FREE(labelstr, M_MACTEMP);
			goto out3;
		}
		AUDIT_ARG(mac_string, labelstr);
		error = mac_mount_label_internalize(mp->mnt_mntlabel, labelstr);
		FREE(labelstr, M_MACTEMP);
		if (error != 0)
			goto out3;
	}
#endif
	if (device_vnode != NULL) {
		VNOP_IOCTL(device_vnode, DKIOCGETBSDUNIT, (caddr_t)&mp->mnt_devbsdunit, 0, NULL);
		mp->mnt_devbsdunit %= LOWPRI_MAX_NUM_DEV;
	}

	/*
	 * Mount the filesystem.
	 */
	error = VFS_MOUNT(mp, device_vnode, fsmountargs, ctx);

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
			enablequotas(mp, ctx);
		goto out2;
	}
	/*
	 * Put the new filesystem on the mount list after root.
	 */
	if (error == 0) {
		struct vfs_attr	vfsattr;
#if CONFIG_MACF
		if (vfs_flags(mp) & MNT_MULTILABEL) {
			error = VFS_ROOT(mp, &rvp, ctx);
			if (error) {
				printf("%s() VFS_ROOT returned %d\n", __func__, error);
				goto out3;
			}

			/* VFS_ROOT provides reference so needref = 0 */
			error = vnode_label(mp, NULL, rvp, NULL, 0, ctx);
			if (error)
				goto out3;
		}
#endif	/* MAC */

		vnode_lock_spin(vp);
		CLR(vp->v_flag, VMOUNT);
		vp->v_mountedhere = mp;
		vnode_unlock(vp);

		/*
		 * taking the name_cache_lock exclusively will
		 * insure that everyone is out of the fast path who
		 * might be trying to use a now stale copy of
		 * vp->v_mountedhere->mnt_realrootvp
		 * bumping mount_generation causes the cached values
		 * to be invalidated
		 */
		name_cache_lock();
		mount_generation++;
		name_cache_unlock();

		vnode_ref(vp);

		error = checkdirs(vp, ctx);
		if (error != 0)  {
			/* Unmount the filesystem as cdir/rdirs cannot be updated */
			goto out4;
		}
		/* 
		 * there is no cleanup code here so I have made it void 
		 * we need to revisit this
		 */
		(void)VFS_START(mp, 0, ctx);

		mount_list_add(mp);
		lck_rw_done(&mp->mnt_rwlock);
		is_rwlock_locked = FALSE;

		/* Check if this mounted file system supports EAs or named streams. */
		/* Skip WebDAV file systems for now since they hang in VFS_GETATTR here. */
		VFSATTR_INIT(&vfsattr);
		VFSATTR_WANTED(&vfsattr, f_capabilities);
		if (strncmp(mp->mnt_vfsstat.f_fstypename, "webdav", sizeof("webdav")) != 0 &&
		    vfs_getattr(mp, &vfsattr, ctx) == 0 && 
		    VFSATTR_IS_SUPPORTED(&vfsattr, f_capabilities)) {
			if ((vfsattr.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] & VOL_CAP_INT_EXTENDED_ATTR) &&
			    (vfsattr.f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] & VOL_CAP_INT_EXTENDED_ATTR)) {
				mp->mnt_kern_flag |= MNTK_EXTENDED_ATTRS;
			}
#if NAMEDSTREAMS
			if ((vfsattr.f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] & VOL_CAP_INT_NAMEDSTREAMS) &&
			    (vfsattr.f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] & VOL_CAP_INT_NAMEDSTREAMS)) {
				mp->mnt_kern_flag |= MNTK_NAMED_STREAMS;
			}
#endif
			/* Check if this file system supports path from id lookups. */
			if ((vfsattr.f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] & VOL_CAP_FMT_PATH_FROM_ID) &&
			    (vfsattr.f_capabilities.valid[VOL_CAPABILITIES_FORMAT] & VOL_CAP_FMT_PATH_FROM_ID)) {
				mp->mnt_kern_flag |= MNTK_PATH_FROM_ID;
			} else if (mp->mnt_flag & MNT_DOVOLFS) {
				/* Legacy MNT_DOVOLFS flag also implies path from id lookups. */
				mp->mnt_kern_flag |= MNTK_PATH_FROM_ID;
			}
		}
		if (mp->mnt_vtable->vfc_vfsflags & VFC_VFSNATIVEXATTR) {
			mp->mnt_kern_flag |= MNTK_EXTENDED_ATTRS;
		}
		if (mp->mnt_vtable->vfc_vfsflags & VFC_VFSPREFLIGHT) {
			mp->mnt_kern_flag |= MNTK_UNMOUNT_PREFLIGHT;
		}
		/* increment the operations count */
		OSAddAtomic(1, (SInt32 *)&vfs_nummntops);
		enablequotas(mp, ctx);

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

		/* Now that mount is setup, notify the listeners */
		vfs_event_signal(NULL, VQ_MOUNT, (intptr_t)NULL);
	} else {
		vnode_lock_spin(vp);
		CLR(vp->v_flag, VMOUNT);
		vnode_unlock(vp);
		mount_list_lock();
		mp->mnt_vtable->vfc_refcount--;
		mount_list_unlock();

		if (device_vnode ) {
			VNOP_CLOSE(device_vnode, ronly ? FREAD : FREAD|FWRITE, ctx);
			vnode_rele(device_vnode);
		}
		lck_rw_done(&mp->mnt_rwlock);
		is_rwlock_locked = FALSE;
		mount_lock_destroy(mp);
#if CONFIG_MACF
		mac_mount_label_destroy(mp);
#endif
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
out4:
	(void)VFS_UNMOUNT(mp, MNT_FORCE, ctx);
	if (device_vnode != NULLVP) {
		VNOP_CLOSE(device_vnode, mp->mnt_flag & MNT_RDONLY ? FREAD : FREAD|FWRITE,
                       ctx);

	}
	vnode_lock_spin(vp);
	vp->v_mountedhere = (mount_t) 0;
	vnode_unlock(vp);
	vnode_rele(vp);
out3:
	if (devpath && ((uap->flags & MNT_UPDATE) == 0))
		vnode_rele(devvp);
out2:
	if (devpath && devvp)
	        vnode_put(devvp);
out1:
	/* Release mnt_rwlock only when it was taken */
	if (is_rwlock_locked == TRUE) {
		lck_rw_done(&mp->mnt_rwlock);
	}
	if (mntalloc) {
#if CONFIG_MACF
		mac_mount_label_destroy(mp);
#endif
		mount_list_lock();
		vfsp->vfc_refcount--;
		mount_list_unlock();
		FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
	}
	vnode_put(vp);
	nameidone(&nd);

	return(error);
}

void
enablequotas(struct mount *mp, vfs_context_t ctx)
{
	struct nameidata qnd;
	int type;
	char qfpath[MAXPATHLEN];
	const char *qfname = QUOTAFILENAME;
	const char *qfopsname = QUOTAOPSNAME;
	const char *qfextension[] = INITQFNAMES;

	/* XXX Shoulkd be an MNTK_ flag, instead of strncmp()'s */
	if ((strncmp(mp->mnt_vfsstat.f_fstypename, "hfs", sizeof("hfs")) != 0 )
                && (strncmp( mp->mnt_vfsstat.f_fstypename, "ufs", sizeof("ufs")) != 0))
	  return;

	/* 
	 * Enable filesystem disk quotas if necessary.
	 * We ignore errors as this should not interfere with final mount
	 */
	for (type=0; type < MAXQUOTAS; type++) {
		snprintf(qfpath, sizeof(qfpath), "%s/%s.%s", mp->mnt_vfsstat.f_mntonname, qfopsname, qfextension[type]);
		NDINIT(&qnd, LOOKUP, FOLLOW, UIO_SYSSPACE32, CAST_USER_ADDR_T(qfpath), ctx);
		if (namei(&qnd) != 0)
			continue; 	    /* option file to trigger quotas is not present */
		vnode_put(qnd.ni_vp);
		nameidone(&qnd);
		snprintf(qfpath, sizeof(qfpath),  "%s/%s.%s", mp->mnt_vfsstat.f_mntonname, qfname, qfextension[type]);

		(void) VFS_QUOTACTL(mp, QCMD(Q_QUOTAON, type), 0, qfpath, ctx);
	}
	return;
}


static int
checkdirs_callback(proc_t p, void * arg) 
{
	struct cdirargs * cdrp = (struct cdirargs * )arg;
	vnode_t olddp = cdrp->olddp;
	vnode_t newdp = cdrp->newdp;
	struct filedesc *fdp;
	vnode_t tvp;
	vnode_t fdp_cvp;
	vnode_t fdp_rvp;
	int cdir_changed = 0;
	int rdir_changed = 0;

	/*
	 * XXX Also needs to iterate each thread in the process to see if it
	 * XXX is using a per-thread current working directory, and, if so,
	 * XXX update that as well.
	 */

	proc_fdlock(p);
	fdp = p->p_fd;
	if (fdp == (struct filedesc *)0) {
		proc_fdunlock(p);
		return(PROC_RETURNED);
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
	return(PROC_RETURNED);
}



/*
 * Scan all active processes to see if any of them have a current
 * or root directory onto which the new filesystem has just been
 * mounted. If so, replace them with the new mount point.
 */
static int
checkdirs(vnode_t olddp, vfs_context_t ctx)
{
	vnode_t newdp;
	vnode_t tvp;
	int err;
	struct cdirargs cdr;
	struct uthread * uth = get_bsdthread_info(current_thread());

	if (olddp->v_usecount == 1)
		return(0);
	if (uth != (struct uthread *)0)
		uth->uu_notrigger = 1;
	err = VFS_ROOT(olddp->v_mountedhere, &newdp, ctx);
	if (uth != (struct uthread *)0)
		uth->uu_notrigger = 0;

	if (err != 0) {
#if DIAGNOSTIC
		panic("mount: lost mount: error %d", err);
#endif
		return(err);
	}

	cdr.olddp = olddp;
	cdr.newdp = newdp;
	/* do not block for exec/fork trans as the vp in cwd & rootdir are not changing */
	proc_iterate(PROC_ALLPROCLIST | PROC_NOWAITTRANS, checkdirs_callback, (void *)&cdr, NULL, NULL);

	if (rootvnode == olddp) {
		vnode_ref(newdp);
		tvp = rootvnode;
		rootvnode = newdp;
		vnode_rele(tvp);
	}

	vnode_put(newdp);
	return(0);
}

/*
 * Unmount a file system.
 *
 * Note: unmount takes a path to the vnode mounted on as argument,
 * not special file (as before).
 */
/* ARGSUSED */
int
unmount(__unused proc_t p, struct unmount_args *uap, __unused register_t *retval)
{
	vnode_t vp;
	struct mount *mp;
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, LOOKUP, NOTRIGGER | FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	mp = vp->v_mount;
	nameidone(&nd);

#if CONFIG_MACF
	error = mac_mount_check_umount(ctx, mp);
	if (error != 0) {
		vnode_put(vp);
		return (error);
	}
#endif
	/*
	 * Must be the root of the filesystem
	 */
	if ((vp->v_flag & VROOT) == 0) {
		vnode_put(vp);
		return (EINVAL);
	}
	mount_ref(mp, 0);
	vnode_put(vp);
	/* safedounmount consumes the mount ref */
	return (safedounmount(mp, uap->flags, ctx));
}

int
vfs_unmountbyfsid(fsid_t * fsid, int flags, vfs_context_t ctx)
{
	mount_t mp;

	mp = mount_list_lookupby_fsid(fsid, 0, 1);
	if (mp == (mount_t)0) {
		return(ENOENT);
	}
	mount_ref(mp, 0);
	mount_iterdrop(mp);
	/* safedounmount consumes the mount ref */
	return(safedounmount(mp, flags, ctx));
}


/*
 * The mount struct comes with a mount ref which will be consumed.
 * Do the actual file system unmount, prevent some common foot shooting.
 */
int
safedounmount(struct mount *mp, int flags, vfs_context_t ctx)
{
	int error;
	proc_t p = vfs_context_proc(ctx);

	/*
	 * Only root, or the user that did the original mount is
	 * permitted to unmount this filesystem.
	 */
	if ((mp->mnt_vfsstat.f_owner != kauth_cred_getuid(kauth_cred_get())) &&
	    (error = suser(kauth_cred_get(), &p->p_acflag)))
		goto out;

	/*
	 * Don't allow unmounting the root file system.
	 */
	if (mp->mnt_flag & MNT_ROOTFS) {
		error = EBUSY; /* the root is always busy */
		goto out;
	}

	return (dounmount(mp, flags, 1, ctx));

out:
	mount_drop(mp, 0);
	return(error);
}

/*
 * Do the actual file system unmount.
 */
int
dounmount(struct mount *mp, int flags, int withref, vfs_context_t ctx)
{
	vnode_t coveredvp = (vnode_t)0;
	int error;
	int needwakeup = 0;
	int forcedunmount = 0;
	int lflags = 0;
	struct vnode *devvp = NULLVP;

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
		if(withref != 0)
			mount_drop(mp, 1);
		msleep((caddr_t)mp, &mp->mnt_mlock, (PVFS | PDROP), "dounmount", NULL);
		/*
		 * The prior unmount attempt has probably succeeded.
		 * Do not dereference mp here - returning EBUSY is safest.
		 */
		return (EBUSY);
	}
	mp->mnt_kern_flag |= MNTK_UNMOUNT;
	mp->mnt_lflag |= MNT_LUNMOUNT;
	mp->mnt_flag &=~ MNT_ASYNC;
	/*
	 * anyone currently in the fast path that
	 * trips over the cached rootvp will be
	 * dumped out and forced into the slow path
	 * to regenerate a new cached value
	 */
	mp->mnt_realrootvp = NULLVP;
	mount_unlock(mp);
 
	/*
	 * taking the name_cache_lock exclusively will
	 * insure that everyone is out of the fast path who
	 * might be trying to use a now stale copy of
	 * vp->v_mountedhere->mnt_realrootvp
	 * bumping mount_generation causes the cached values
	 * to be invalidated
	 */
	name_cache_lock();
	mount_generation++;
	name_cache_unlock();


	lck_rw_lock_exclusive(&mp->mnt_rwlock);
	if (withref != 0)
		mount_drop(mp, 0);
#if CONFIG_FSE
	fsevent_unmount(mp);  /* has to come first! */
#endif
	error = 0;
	if (forcedunmount == 0) {
		ubc_umount(mp);	/* release cached vnodes */
		if ((mp->mnt_flag & MNT_RDONLY) == 0) {
			error = VFS_SYNC(mp, MNT_WAIT, ctx);
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

	error = VFS_UNMOUNT(mp, flags, ctx);
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
		/* hold an io reference and drop the usecount before close */
		devvp = mp->mnt_devvp;
		vnode_clearmountedon(devvp);
		vnode_getalways(devvp);
		vnode_rele(devvp);
		VNOP_CLOSE(devvp, mp->mnt_flag & MNT_RDONLY ? FREAD : FREAD|FWRITE,
                       ctx);
		vnode_put(devvp);
	}
	lck_rw_done(&mp->mnt_rwlock);
	mount_list_remove(mp);
	lck_rw_lock_exclusive(&mp->mnt_rwlock);
	
	/* mark the mount point hook in the vp but not drop the ref yet */
	if ((coveredvp = mp->mnt_vnodecovered) != NULLVP) {
			vnode_getwithref(coveredvp);
			vnode_lock_spin(coveredvp);
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
			vnode_lock_spin(coveredvp);
			if(mp->mnt_crossref == 0) {
				vnode_unlock(coveredvp);
				mount_lock_destroy(mp);
#if CONFIG_MACF
				mac_mount_label_destroy(mp);
#endif
				FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
			}  else {
				coveredvp->v_lflag |= VL_MOUNTDEAD;
				vnode_unlock(coveredvp);
			}
			vnode_put(coveredvp);
		} else if (mp->mnt_flag & MNT_ROOTFS) {
				mount_lock_destroy(mp);
#if CONFIG_MACF
				mac_mount_label_destroy(mp);
#endif
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
#if CONFIG_MACF
			mac_mount_label_destroy(mp);
#endif
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
	int asyncflag;

	if ((mp->mnt_flag & MNT_RDONLY) == 0) {
			asyncflag = mp->mnt_flag & MNT_ASYNC;
			mp->mnt_flag &= ~MNT_ASYNC;
			VFS_SYNC(mp, MNT_NOWAIT, vfs_context_current());
			if (asyncflag)
				mp->mnt_flag |= MNT_ASYNC;
	}
	return(VFS_RETURNED);
}


extern unsigned int vp_pagein, vp_pgodirty, vp_pgoclean;
extern unsigned int dp_pgins, dp_pgouts;

/* ARGSUSED */
int
sync(__unused proc_t p, __unused struct sync_args *uap, __unused register_t *retval)
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
#if QUOTA
static int quotactl_funneled(proc_t p, struct quotactl_args *uap, register_t *retval);

int
quotactl(proc_t p, struct quotactl_args *uap, register_t *retval)
{
	boolean_t funnel_state;
	int error;
	
	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	error = quotactl_funneled(p, uap, retval);
	thread_funnel_set(kernel_flock, funnel_state);
	return(error);
}

static int
quotactl_funneled(proc_t p, struct quotactl_args *uap, __unused register_t *retval)
{
	struct mount *mp;
	int error, quota_cmd, quota_status;
	caddr_t datap;
	size_t fnamelen;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	struct dqblk my_dqblk;

	AUDIT_ARG(uid, uap->uid, 0, 0, 0);
	AUDIT_ARG(cmd, uap->cmd);
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
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
		error = VFS_QUOTACTL(mp, uap->cmd, uap->uid, datap, ctx);
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
#else
int
quotactl(__unused proc_t p, __unused struct quotactl_args *uap, __unused register_t *retval)
{
	return (EOPNOTSUPP);
}
#endif /* QUOTA */

/*
 * Get filesystem statistics.
 *
 * Returns:	0			Success
 *	namei:???
 *	vfs_update_vfsstat:???
 *	munge_statfs:EFAULT
 */
/* ARGSUSED */
int
statfs(__unused proc_t p, struct statfs_args *uap, __unused register_t *retval)
{
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	vnode_t vp;

	NDINIT(&nd, LOOKUP, NOTRIGGER | FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	mp = vp->v_mount;
	sp = &mp->mnt_vfsstat;
	nameidone(&nd);

	error = vfs_update_vfsstat(mp, ctx, VFS_USER_EVENT);
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
fstatfs(__unused proc_t p, struct fstatfs_args *uap, __unused register_t *retval)
{
	vnode_t vp;
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;

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
	if ((error = vfs_update_vfsstat(mp,vfs_context_current(),VFS_USER_EVENT)) != 0) {
		file_drop(uap->fd);
		return (error);
	}
	file_drop(uap->fd);

	error = munge_statfs(mp, sp, uap->buf, NULL, IS_64BIT_PROCESS(p), TRUE);

	return (error);
}

/* 
 * Common routine to handle copying of statfs64 data to user space 
 */
static int 
statfs64_common(struct mount *mp, struct vfsstatfs *sfsp, user_addr_t bufp)
{
	int error;
	struct statfs64 sfs;
	
	bzero(&sfs, sizeof(sfs));

	sfs.f_bsize = sfsp->f_bsize;
	sfs.f_iosize = (int32_t)sfsp->f_iosize;
	sfs.f_blocks = sfsp->f_blocks;
	sfs.f_bfree = sfsp->f_bfree;
	sfs.f_bavail = sfsp->f_bavail;
	sfs.f_files = sfsp->f_files;
	sfs.f_ffree = sfsp->f_ffree;
	sfs.f_fsid = sfsp->f_fsid;
	sfs.f_owner = sfsp->f_owner;
	sfs.f_type = mp->mnt_vtable->vfc_typenum;
	sfs.f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
	sfs.f_fssubtype = sfsp->f_fssubtype;
	strlcpy(&sfs.f_fstypename[0], &sfsp->f_fstypename[0], MFSTYPENAMELEN);
	strlcpy(&sfs.f_mntonname[0], &sfsp->f_mntonname[0], MAXPATHLEN);
	strlcpy(&sfs.f_mntfromname[0], &sfsp->f_mntfromname[0], MAXPATHLEN);

	error = copyout((caddr_t)&sfs, bufp, sizeof(sfs));

	return(error);
}

/* 
 * Get file system statistics in 64-bit mode 
 */
int
statfs64(__unused struct proc *p, struct statfs64_args *uap, __unused register_t *retval)
{
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;
	struct nameidata nd;
	vfs_context_t ctxp = vfs_context_current();
	vnode_t vp;

	NDINIT(&nd, LOOKUP, NOTRIGGER | FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctxp);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	mp = vp->v_mount;
	sp = &mp->mnt_vfsstat;
	nameidone(&nd);

	error = vfs_update_vfsstat(mp, ctxp, VFS_USER_EVENT);
	vnode_put(vp);
	if (error != 0) 
		return (error);

	error = statfs64_common(mp, sp, uap->buf);

	return (error);
}

/* 
 * Get file system statistics in 64-bit mode 
 */
int
fstatfs64(__unused struct proc *p, struct fstatfs64_args *uap, __unused register_t *retval)
{
	struct vnode *vp;
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;

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
	if ((error = vfs_update_vfsstat(mp, vfs_context_current(), VFS_USER_EVENT)) != 0) {
		file_drop(uap->fd);
		return (error);
	}
	file_drop(uap->fd);

	error = statfs64_common(mp, sp, uap->buf);

	return (error);
}

struct getfsstat_struct {
	user_addr_t	sfsp;
	user_addr_t	*mp;
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
	int error, my_size;
	vfs_context_t ctx = vfs_context_current();

	if (fstp->sfsp && fstp->count < fstp->maxcount) {
		sp = &mp->mnt_vfsstat;
		/*
		 * If MNT_NOWAIT is specified, do not refresh the
		 * fsstat cache. MNT_WAIT overrides MNT_NOWAIT.
		 */
		if (((fstp->flags & MNT_NOWAIT) == 0 || (fstp->flags & MNT_WAIT)) &&
			(error = vfs_update_vfsstat(mp, ctx,
			    VFS_USER_EVENT))) {
			KAUTH_DEBUG("vfs_update_vfsstat returned %d", error);
			return(VFS_RETURNED);
		}

		/*
		 * Need to handle LP64 version of struct statfs
		 */
		error = munge_statfs(mp, sp, fstp->sfsp, &my_size, IS_64BIT_PROCESS(vfs_context_proc(ctx)), FALSE);
		if (error) {
			fstp->error = error;
			return(VFS_RETURNED_DONE);
		}
		fstp->sfsp += my_size;

		if (fstp->mp) {
			error = mac_mount_label_get(mp, *fstp->mp);
			if (error) {
				fstp->error = error;
				return(VFS_RETURNED_DONE);
			}
			fstp->mp++;
		}
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
	struct __mac_getfsstat_args muap;

	muap.buf = uap->buf;
	muap.bufsize = uap->bufsize;
	muap.mac = USER_ADDR_NULL;
	muap.macsize = 0;
	muap.flags = uap->flags;

	return (__mac_getfsstat(p, &muap, retval));
}

int
__mac_getfsstat(__unused proc_t p, struct __mac_getfsstat_args *uap, int *retval)
{
	user_addr_t sfsp;
	user_addr_t *mp;
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

	mp = NULL;

#if CONFIG_MACF
	if (uap->mac != USER_ADDR_NULL) {
		u_int32_t *mp0;
		int error;
		int i;

		count = (int)(uap->macsize / (IS_64BIT_PROCESS(p) ? 8 : 4));
		if (count != maxcount)
			return (EINVAL);

		/* Copy in the array */
		MALLOC(mp0, u_int32_t *, uap->macsize, M_MACTEMP, M_WAITOK);
		error = copyin(uap->mac, mp0, uap->macsize);
		if (error)
			return (error);

		/* Normalize to an array of user_addr_t */
		MALLOC(mp, user_addr_t *, count * sizeof(user_addr_t), M_MACTEMP, M_WAITOK);
		for (i = 0; i < count; i++) {
			if (IS_64BIT_PROCESS(p))
				mp[i] = ((user_addr_t *)mp0)[i];
			else
				mp[i] = (user_addr_t)mp0[i];
		}
		FREE(mp0, M_MACTEMP);
	}
#endif


	fst.sfsp = sfsp;
	fst.mp = mp;
	fst.flags = uap->flags;
	fst.count = 0;
	fst.error = 0;
	fst.maxcount = maxcount;

	
	vfs_iterate(0, getfsstat_callback, &fst);

	if (mp)
		FREE(mp, M_MACTEMP);

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

static int
getfsstat64_callback(mount_t mp, void * arg)
{
	struct getfsstat_struct *fstp = (struct getfsstat_struct *)arg;
	struct vfsstatfs *sp;
	int error;

	if (fstp->sfsp && fstp->count < fstp->maxcount) {
		sp = &mp->mnt_vfsstat;
		/*
		 * If MNT_NOWAIT is specified, do not refresh the
		 * fsstat cache. MNT_WAIT overrides MNT_NOWAIT.
		 */
		if (((fstp->flags & MNT_NOWAIT) == 0 || (fstp->flags & MNT_WAIT)) &&
		    (error = vfs_update_vfsstat(mp, vfs_context_current(), VFS_USER_EVENT))) {
			KAUTH_DEBUG("vfs_update_vfsstat returned %d", error);
			return(VFS_RETURNED);
		}

		error = statfs64_common(mp, sp, fstp->sfsp);
		if (error) {
			fstp->error = error;
			return(VFS_RETURNED_DONE);
		}
		fstp->sfsp += sizeof(struct statfs64);
	}
	fstp->count++;
	return(VFS_RETURNED);
}

/*
 * Get statistics on all file systems in 64 bit mode.
 */
int
getfsstat64(__unused proc_t p, struct getfsstat64_args *uap, int *retval)
{
	user_addr_t sfsp;
	int count, maxcount;
	struct getfsstat_struct fst;

	maxcount = uap->bufsize / sizeof(struct statfs64);

	sfsp = uap->buf;
	count = 0;

	fst.sfsp = sfsp;
	fst.flags = uap->flags;
	fst.count = 0;
	fst.error = 0;
	fst.maxcount = maxcount;

	vfs_iterate(0, getfsstat64_callback, &fst);

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
ogetfsstat(proc_t p, struct getfsstat_args *uap, register_t *retval)
{
	return (ENOTSUP);
}
#endif

/*
 * Change current working directory to a given file descriptor.
 */
/* ARGSUSED */
static int
common_fchdir(proc_t p, struct fchdir_args *uap, int per_thread)
{
	struct filedesc *fdp = p->p_fd;
	vnode_t vp;
	vnode_t tdp;
	vnode_t tvp;
	struct mount *mp;
	int error;
	vfs_context_t ctx = vfs_context_current();

	if (per_thread && uap->fd == -1) {
		/*
		 * Switching back from per-thread to per process CWD; verify we
		 * in fact have one before proceeding.  The only success case
		 * for this code path is to return 0 preemptively after zapping
		 * the thread structure contents.
		 */
		thread_t th = vfs_context_thread(ctx);
		if (th) {
			uthread_t uth = get_bsdthread_info(th);
			tvp = uth->uu_cdir;
			uth->uu_cdir = NULLVP;
			if (tvp != NULLVP) {
				vnode_rele(tvp);
				return (0);
			}
		}
		return (EBADF);
	}

	if ( (error = file_vnode(uap->fd, &vp)) )
		return(error);
	if ( (error = vnode_getwithref(vp)) ) {
	        file_drop(uap->fd);
		return(error);
	}

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

#if CONFIG_MACF
	error = mac_vnode_check_chdir(ctx, vp);
	if (error)
		goto out;
#endif
	error = vnode_authorize(vp, NULL, KAUTH_VNODE_SEARCH, ctx);
	if (error)
		goto out;

	while (!error && (mp = vp->v_mountedhere) != NULL) {
		if (vfs_busy(mp, LK_NOWAIT)) {
			error = EACCES;
			goto out;
		}
		error = VFS_ROOT(mp, &tdp, ctx);
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

	if (per_thread) {
		thread_t th = vfs_context_thread(ctx);
		if (th) {
			uthread_t uth = get_bsdthread_info(th);
			tvp = uth->uu_cdir;
			uth->uu_cdir = vp;
			OSBitOrAtomic(P_THCWD, (UInt32 *)&p->p_flag);
		} else {
			vnode_rele(vp);
			return (ENOENT);
		}
	} else {
		proc_fdlock(p);
		tvp = fdp->fd_cdir;
		fdp->fd_cdir = vp;
		proc_fdunlock(p);
	}

	if (tvp)
	        vnode_rele(tvp);
	file_drop(uap->fd);

	return (0);
out:
	vnode_put(vp);
	file_drop(uap->fd);

	return(error);
}

int
fchdir(proc_t p, struct fchdir_args *uap, __unused register_t *retval)
{
	return common_fchdir(p, uap, 0);
}

int
__pthread_fchdir(proc_t p, struct __pthread_fchdir_args *uap, __unused register_t *retval)
{
	return common_fchdir(p, (void *)uap, 1);
}

/*
 * Change current working directory (``.'').
 *
 * Returns:	0			Success
 *	change_dir:ENOTDIR
 *	change_dir:???
 *	vnode_ref:ENOENT		No such file or directory
 */
/* ARGSUSED */
static int
common_chdir(proc_t p, struct chdir_args *uap, int per_thread)
{
	struct filedesc *fdp = p->p_fd;
	int error;
	struct nameidata nd;
	vnode_t tvp;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = change_dir(&nd, ctx);
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

	if (per_thread) {
		thread_t th = vfs_context_thread(ctx);
		if (th) {
			uthread_t uth = get_bsdthread_info(th);
			tvp = uth->uu_cdir;
			uth->uu_cdir = nd.ni_vp;
			OSBitOrAtomic(P_THCWD, (UInt32 *)&p->p_flag);
		} else {
			vnode_rele(nd.ni_vp);
			return (ENOENT);
		}
	} else {
		proc_fdlock(p);
		tvp = fdp->fd_cdir;
		fdp->fd_cdir = nd.ni_vp;
		proc_fdunlock(p);
	}

	if (tvp)
	        vnode_rele(tvp);

	return (0);
}

int
chdir(proc_t p, struct chdir_args *uap, __unused register_t *retval)
{
	return common_chdir(p, (void *)uap, 0);
}

int
__pthread_chdir(proc_t p, struct __pthread_chdir_args *uap, __unused register_t *retval)
{
	return common_chdir(p, (void *)uap, 1);
}


/*
 * Change notion of root (``/'') directory.
 */
/* ARGSUSED */
int
chroot(proc_t p, struct chroot_args *uap, __unused register_t *retval)
{
	struct filedesc *fdp = p->p_fd;
	int error;
	struct nameidata nd;
	vnode_t tvp;
	vfs_context_t ctx = vfs_context_current();

	if ((error = suser(kauth_cred_get(), &p->p_acflag)))
		return (error);

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = change_dir(&nd, ctx);
	if (error)
		return (error);

#if CONFIG_MACF
	error = mac_vnode_check_chroot(ctx, nd.ni_vp,
	    &nd.ni_cnd);
	if (error) {
		vnode_put(nd.ni_vp);
		return (error);
	}
#endif

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
 *
 * Returns:	0			Success
 *		ENOTDIR			Not a directory
 *		namei:???		[anything namei can return]
 *		vnode_authorize:???	[anything vnode_authorize can return]
 */
static int
change_dir(struct nameidata *ndp, vfs_context_t ctx)
{
	vnode_t vp;
	int error;

	if ((error = namei(ndp)))
		return (error);
	nameidone(ndp);
	vp = ndp->ni_vp;

	if (vp->v_type != VDIR) {
		vnode_put(vp);
		return (ENOTDIR);
	}

#if CONFIG_MACF
	error = mac_vnode_check_chdir(ctx, vp);
	if (error) {
		vnode_put(vp);
		return (error);
	}
#endif

	error = vnode_authorize(vp, NULL, KAUTH_VNODE_SEARCH, ctx);
	if (error) {
		vnode_put(vp);
		return (error);
	}

	return (error);
}

/*
 * Check permissions, allocate an open file structure,
 * and call the device open routine if any.
 *
 * Returns:	0			Success
 *		EINVAL
 *		EINTR
 *	falloc:ENFILE
 *	falloc:EMFILE
 *	falloc:ENOMEM
 *	vn_open_auth:???
 *	dupfdopen:???
 *	VNOP_ADVLOCK:???
 *	vnode_setsize:???
 */
#warning XXX implement uid, gid
int
open1(vfs_context_t ctx, struct nameidata *ndp, int uflags, struct vnode_attr *vap, register_t *retval)
{
	proc_t p = vfs_context_proc(ctx);
	uthread_t uu = get_bsdthread_info(vfs_context_thread(ctx));
	struct filedesc *fdp = p->p_fd;
	struct fileproc *fp;
	vnode_t vp;
	int flags, oflags;
	struct fileproc *nfp;
	int type, indx, error;
	struct flock lf;
	int no_controlling_tty = 0;
	int deny_controlling_tty = 0;
	struct session *sessp = SESSION_NULL;
	struct vfs_context context = *vfs_context_current();	/* local copy */

	oflags = uflags;

	if ((oflags & O_ACCMODE) == O_ACCMODE)
		return(EINVAL);
	flags = FFLAGS(uflags);

	AUDIT_ARG(fflags, oflags);
	AUDIT_ARG(mode, vap->va_mode);

	if ( (error = falloc(p, &nfp, &indx, ctx)) ) {
		return (error);
	}
	fp = nfp;
	uu->uu_dupfd = -indx - 1;

	if (!(p->p_flag & P_CONTROLT)) {
		sessp = proc_session(p);
		no_controlling_tty = 1;
		/*
		 * If conditions would warrant getting a controlling tty if
		 * the device being opened is a tty (see ttyopen in tty.c),
		 * but the open flags deny it, set a flag in the session to
		 * prevent it.
		 */
		if (SESS_LEADER(p, sessp) &&
		    sessp->s_ttyvp == NULL &&
		    (flags & O_NOCTTY)) {
			session_lock(sessp);
		    	sessp->s_flags |= S_NOCTTY;
			session_unlock(sessp);
			deny_controlling_tty = 1;
		}
	}

	if ((error = vn_open_auth(ndp, &flags, vap))) {
		if ((error == ENODEV || error == ENXIO) && (uu->uu_dupfd >= 0)){	/* XXX from fdopen */
			if ((error = dupfdopen(fdp, indx, uu->uu_dupfd, flags, error)) == 0) {
				fp_drop(p, indx, NULL, 0);
			        *retval = indx;
				if (deny_controlling_tty) {
					session_lock(sessp);
					sessp->s_flags &= ~S_NOCTTY;
					session_unlock(sessp);
				}
				if (sessp != SESSION_NULL)
					session_rele(sessp);
				return (0);
			}
		}
		if (error == ERESTART)
		        error = EINTR;
		fp_free(p, indx, fp);

		if (deny_controlling_tty) {
			session_lock(sessp);
			sessp->s_flags &= ~S_NOCTTY;
			session_unlock(sessp);
		}
		if (sessp != SESSION_NULL)
			session_rele(sessp);
		return (error);
	}
	uu->uu_dupfd = 0;
	vp = ndp->ni_vp;

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
#if CONFIG_MACF
		error = mac_file_check_lock(vfs_context_ucred(ctx), fp->f_fglob,
		    F_SETLK, &lf);
		if (error)
			goto bad;
#endif
		if ((error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_SETLK, &lf, type, ctx)))
			goto bad;
		fp->f_fglob->fg_flag |= FHASLOCK;
	}

	/* try to truncate by setting the size attribute */
	if ((flags & O_TRUNC) && ((error = vnode_setsize(vp, (off_t)0, 0, ctx)) != 0))
		goto bad;

	/*
	 * If the open flags denied the acquisition of a controlling tty,
	 * clear the flag in the session structure that prevented the lower
	 * level code from assigning one.
	 */
	if (deny_controlling_tty) {
		session_lock(sessp);
		sessp->s_flags &= ~S_NOCTTY;
		session_unlock(sessp);
	}

	/*
	 * If a controlling tty was set by the tty line discipline, then we
	 * want to set the vp of the tty into the session structure.  We have
	 * a race here because we can't get to the vp for the tp in ttyopen,
	 * because it's not passed as a parameter in the open path.
	 */
	if (no_controlling_tty && (p->p_flag & P_CONTROLT)) {
		vnode_t ttyvp;
		vnode_ref(vp);
		session_lock(sessp);
		ttyvp = sessp->s_ttyvp;
		sessp->s_ttyvp = vp;
		sessp->s_ttyvid = vnode_vid(vp);
		session_unlock(sessp);
		if (ttyvp != NULLVP)
			vnode_rele(ttyvp);
	}

	vnode_put(vp);

	proc_fdlock(p);
	procfdtbl_releasefd(p, indx, NULL);
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = indx;

	if (sessp != SESSION_NULL)
		session_rele(sessp);
	return (0);
bad:
	if (deny_controlling_tty) {
		session_lock(sessp);
		sessp->s_flags &= ~S_NOCTTY;
		session_unlock(sessp);
	}
	if (sessp != SESSION_NULL)
		session_rele(sessp);

	/* Modify local copy (to not damage thread copy) */
	context.vc_ucred = fp->f_fglob->fg_cred;

	vn_close(vp, fp->f_fglob->fg_flag, &context);
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
open_extended(proc_t p, struct open_extended_args *uap, register_t *retval)
{
	struct filedesc *fdp = p->p_fd;
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vnode_attr va;
	struct nameidata nd;
	int cmode;

	xsecdst = NULL;
	if ((uap->xsecurity != USER_ADDR_NULL) &&
	    ((ciferror = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0))
		return ciferror;

	VATTR_INIT(&va);
	cmode = ((uap->mode &~ fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode);
	if (uap->uid != KAUTH_UID_NONE)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != KAUTH_GID_NONE)
		VATTR_SET(&va, va_gid, uap->gid);
	if (xsecdst != NULL)
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, UIO_USERSPACE, uap->path, vfs_context_current());

	ciferror = open1(vfs_context_current(), &nd, uap->flags, &va, retval);
	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);

	return ciferror;
}

int
open(proc_t p, struct open_args *uap, register_t *retval)
{
	__pthread_testcancel(1);
	return(open_nocancel(p, (struct open_nocancel_args *)uap, retval));
}


int
open_nocancel(proc_t p, struct open_nocancel_args *uap, register_t *retval)
{
	struct filedesc *fdp = p->p_fd;
	struct vnode_attr va;
	struct nameidata nd;
	int cmode;

	VATTR_INIT(&va);
	/* Mask off all but regular access permissions */
	cmode = ((uap->mode &~ fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode & ACCESSPERMS);

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, UIO_USERSPACE, uap->path, vfs_context_current());

	return(open1(vfs_context_current(), &nd, uap->flags, &va, retval));
}


/*
 * Create a special file.
 */
static int mkfifo1(vfs_context_t ctx, user_addr_t upath, struct vnode_attr *vap);

int
mknod(proc_t p, struct mknod_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	int error;
	int whiteout = 0;
	struct nameidata nd;
	vnode_t	vp, dvp;

 	VATTR_INIT(&va);
 	VATTR_SET(&va, va_mode, (uap->mode & ALLPERMS) & ~p->p_fd->fd_cmask);
 	VATTR_SET(&va, va_rdev, uap->dev);

	/* If it's a mknod() of a FIFO, call mkfifo1() instead */
	if ((uap->mode & S_IFMT) == S_IFIFO)
 		return(mkfifo1(ctx, uap->path, &va));

	AUDIT_ARG(mode, uap->mode);
	AUDIT_ARG(dev, uap->dev);

	if ((error = suser(vfs_context_ucred(ctx), &p->p_acflag)))
		return (error);
	NDINIT(&nd, CREATE, LOCKPARENT | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp != NULL) {
		error = EEXIST;
		goto out;
	}

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

#if CONFIG_MACF
	if (!whiteout) {
		error = mac_vnode_check_create(ctx,
		    nd.ni_dvp, &nd.ni_cnd, &va);
		if (error)
			goto out;
	}
#endif

 	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx)) != 0)
 		goto out;

	if (whiteout) {
		error = VNOP_WHITEOUT(dvp, &nd.ni_cnd, CREATE, ctx);
	} else {
		error = vn_create(dvp, &vp, &nd.ni_cnd, &va, 0, ctx);
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

#if CONFIG_FSE
		add_fsevent(FSE_CREATE_FILE, ctx,
		    FSE_ARG_VNODE, vp,
		    FSE_ARG_DONE);
#endif
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
 *
 * Returns:	0			Success
 *		EEXIST
 *	namei:???
 *	vnode_authorize:???
 *	vn_create:???
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
   	VATTR_SET(vap, va_type, VFIFO);

#if CONFIG_MACF
	error = mac_vnode_check_create(ctx, nd.ni_dvp,
	    &nd.ni_cnd, vap);
	if (error)
		goto out;
#endif


   	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx)) != 0)
   		goto out;

 	
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
mkfifo_extended(proc_t p, struct mkfifo_extended_args *uap, __unused register_t *retval)
{
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vnode_attr va;

	xsecdst = KAUTH_FILESEC_NONE;
	if (uap->xsecurity != USER_ADDR_NULL) {
		if ((ciferror = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0)
			return ciferror;
	}

	VATTR_INIT(&va);
   	VATTR_SET(&va, va_mode, (uap->mode & ALLPERMS) & ~p->p_fd->fd_cmask);
	if (uap->uid != KAUTH_UID_NONE)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != KAUTH_GID_NONE)
		VATTR_SET(&va, va_gid, uap->gid);
	if (xsecdst != KAUTH_FILESEC_NONE)
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);

	ciferror = mkfifo1(vfs_context_current(), uap->path, &va);

	if (xsecdst != KAUTH_FILESEC_NONE)
		kauth_filesec_free(xsecdst);
	return ciferror;
}

/* ARGSUSED */
int
mkfifo(proc_t p, struct mkfifo_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;

   	VATTR_INIT(&va);
   	VATTR_SET(&va, va_mode, (uap->mode & ALLPERMS) & ~p->p_fd->fd_cmask);

	return(mkfifo1(vfs_context_current(), uap->path, &va));
}

/*
 * Make a hard file link.
 *
 * Returns:	0			Success
 *		EPERM
 *		EEXIST
 *		EXDEV
 *	namei:???
 *	vnode_authorize:???
 *	VNOP_LINK:???
 */
/* ARGSUSED */
int
link(__unused proc_t p, struct link_args *uap, __unused register_t *retval)
{
	vnode_t	vp, dvp, lvp;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	int error;
	fse_info finfo;
	int need_event, has_listeners;
	char *target_path = NULL;

	vp = dvp = lvp = NULLVP;

	/* look up the object we are linking to */
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	/*
	 * Normally, linking to directories is not supported.
	 * However, some file systems may have limited support.
	 */
	if (vp->v_type == VDIR) {
		if (!(vp->v_mount->mnt_vtable->vfc_vfsflags & VFC_VFSDIRLINKS)) {
			error = EPERM;   /* POSIX */
			goto out;
		}
		/* Linking to a directory requires ownership. */
		if (!kauth_cred_issuser(vfs_context_ucred(ctx))) {
			struct vnode_attr dva;

			VATTR_INIT(&dva);
			VATTR_WANTED(&dva, va_uid);
			if (vnode_getattr(vp, &dva, ctx) != 0 ||
			    !VATTR_IS_SUPPORTED(&dva, va_uid) ||
			    (dva.va_uid != kauth_cred_getuid(vfs_context_ucred(ctx)))) {
				error = EACCES;
				goto out;
			}
		}
	}

	/* lookup the target node */
	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT | AUDITVNPATH2 | CN_NBMOUNTLOOK;
	nd.ni_dirp = uap->link;
	error = namei(&nd);
	if (error != 0)
		goto out;
	dvp = nd.ni_dvp;
	lvp = nd.ni_vp;

#if CONFIG_MACF
	if ((error = mac_vnode_check_link(ctx, dvp, vp, &nd.ni_cnd)) != 0)
		goto out2;
#endif

  	/* or to anything that kauth doesn't want us to (eg. immutable items) */
  	if ((error = vnode_authorize(vp, NULL, KAUTH_VNODE_LINKTARGET, ctx)) != 0)
 		goto out2;

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
  	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx)) != 0)
  		goto out2;

	/* and finally make the link */
	error = VNOP_LINK(vp, dvp, &nd.ni_cnd, ctx);
	if (error)
		goto out2;

#if CONFIG_FSE
	need_event = need_fsevent(FSE_CREATE_FILE, dvp);
#else
	need_event = 0;
#endif
	has_listeners = kauth_authorize_fileop_has_listeners();

	if (need_event || has_listeners) {
		char *link_to_path = NULL;
		int len, link_name_len;

		/* build the path to the new link file */
		GET_PATH(target_path);
		if (target_path == NULL) {
			error = ENOMEM;
			goto out2;
		}

		len = MAXPATHLEN;
		vn_getpath(dvp, target_path, &len);
		if ((len + 1 + nd.ni_cnd.cn_namelen + 1) < MAXPATHLEN) {
		    target_path[len-1] = '/';
		    strlcpy(&target_path[len], nd.ni_cnd.cn_nameptr, MAXPATHLEN-len);
		    len += nd.ni_cnd.cn_namelen;
		}

		if (has_listeners) {
		        /* build the path to file we are linking to */
			GET_PATH(link_to_path);
			if (link_to_path == NULL) {
				error = ENOMEM;
				goto out2;
			}

			link_name_len = MAXPATHLEN;
			vn_getpath(vp, link_to_path, &link_name_len);

			/*
			 * Call out to allow 3rd party notification of rename. 
			 * Ignore result of kauth_authorize_fileop call.
			 */
			kauth_authorize_fileop(vfs_context_ucred(ctx), KAUTH_FILEOP_LINK, 
					       (uintptr_t)link_to_path, (uintptr_t)target_path);
			if (link_to_path != NULL) {
				RELEASE_PATH(link_to_path);
			}
		}
#if CONFIG_FSE
		if (need_event) {
		        /* construct fsevent */
		        if (get_fse_info(vp, &finfo, ctx) == 0) {
			        // build the path to the destination of the link
			        add_fsevent(FSE_CREATE_FILE, ctx,
					    FSE_ARG_STRING, len, target_path,
					    FSE_ARG_FINFO, &finfo,
					    FSE_ARG_DONE);
			}
		}
#endif
	}
out2:
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(&nd);
	if (target_path != NULL) {
		RELEASE_PATH(target_path);
	}
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
symlink(proc_t p, struct symlink_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;
	char *path;
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	vnode_t	vp, dvp;
	size_t dummy=0;
	
	MALLOC_ZONE(path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	error = copyinstr(uap->path, path, MAXPATHLEN, &dummy);
	if (error)
		goto out;
	AUDIT_ARG(text, path);	/* This is the link string */

	NDINIT(&nd, CREATE, LOCKPARENT | AUDITVNPATH1, 
		UIO_USERSPACE, uap->link, ctx);
	error = namei(&nd);
	if (error)
		goto out;
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_type, VLNK);
	VATTR_SET(&va, va_mode, ACCESSPERMS & ~p->p_fd->fd_cmask);
#if CONFIG_MACF
	error = mac_vnode_check_create(ctx,
			dvp, &nd.ni_cnd, &va);
#endif
	if (error != 0) {
	    goto skipit;
	}

	if (vp != NULL) {
	    error = EEXIST;
	    goto skipit;
	}

	/* authorize */
	if (error == 0)
		error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx);
	/* get default ownership, etc. */
	if (error == 0)
		error = vnode_authattr_new(dvp, &va, 0, ctx);
	if (error == 0)
		error = VNOP_SYMLINK(dvp, &vp, &nd.ni_cnd, &va, path, ctx);

	/* do fallback attribute handling */
	if (error == 0)
		error = vnode_setattr_fallback(vp, &va, ctx);
		
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
			if ((len + 1 + nd.ni_cnd.cn_namelen + 1) < MAXPATHLEN) {
				new_link_path[len - 1] = '/';
				strlcpy(&new_link_path[len], nd.ni_cnd.cn_nameptr, MAXPATHLEN-len);
			}
				
			kauth_authorize_fileop(vfs_context_ucred(ctx), KAUTH_FILEOP_SYMLINK, 
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

#if CONFIG_FSE
		add_fsevent(FSE_CREATE_FILE, ctx,
			    FSE_ARG_VNODE, vp,
			    FSE_ARG_DONE);
#endif
	}

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
undelete(__unused proc_t p, struct undelete_args *uap, __unused register_t *retval)
{
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	vnode_t	vp, dvp;

	NDINIT(&nd, DELETE, LOCKPARENT|DOWHITEOUT|AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp == NULLVP && (nd.ni_cnd.cn_flags & ISWHITEOUT)) {
		error = VNOP_WHITEOUT(dvp, &nd.ni_cnd, DELETE, ctx);
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
int
unlink1(vfs_context_t ctx, struct nameidata *ndp, int nodelbusy)
{
	vnode_t	vp, dvp;
	int error;
	struct componentname *cnp;
	char  *path = NULL;
	int  len;
	fse_info  finfo;
	int flags = 0;
	int need_event = 0;
	int has_listeners = 0;

	ndp->ni_cnd.cn_flags |= LOCKPARENT;
	cnp = &ndp->ni_cnd;

	error = namei(ndp);
	if (error)
		return (error);
	dvp = ndp->ni_dvp;
	vp = ndp->ni_vp;

	/* With Carbon delete semantics, busy files cannot be deleted */
	if (nodelbusy) {
		flags |= VNODE_REMOVE_NODELETEBUSY;
	}

	/*
	 * Normally, unlinking of directories is not supported. 
	 * However, some file systems may have limited support.
	 */
	if ((vp->v_type == VDIR) &&
	    !(vp->v_mount->mnt_vtable->vfc_vfsflags & VFC_VFSDIRLINKS)) {
		error = EPERM;	/* POSIX */
	}

	/*
	 * The root of a mounted filesystem cannot be deleted.
	 */
	if (vp->v_flag & VROOT) {
		error = EBUSY;
	}
	if (error)
		goto out;


	/* authorize the delete operation */
#if CONFIG_MACF
	if (!error)
		error = mac_vnode_check_unlink(ctx,
		    dvp, vp, cnp);
#endif /* MAC */
	if (!error)
		error = vnode_authorize(vp, ndp->ni_dvp, KAUTH_VNODE_DELETE, ctx);
	if (error)
		goto out;
	
#if CONFIG_FSE
	need_event = need_fsevent(FSE_DELETE, dvp);
	if (need_event) {
		if ((vp->v_flag & VISHARDLINK) == 0) {
			get_fse_info(vp, &finfo, ctx);
		}
	}
#endif
	has_listeners = kauth_authorize_fileop_has_listeners();
	if (need_event || has_listeners) {
		GET_PATH(path);
		if (path == NULL) {
			error = ENOMEM;
			goto out;
		}
		len = MAXPATHLEN;
		vn_getpath(vp, path, &len);
	}

#if NAMEDRSRCFORK
	if (ndp->ni_cnd.cn_flags & CN_WANTSRSRCFORK)
		error = vnode_removenamedstream(dvp, vp, XATTR_RESOURCEFORK_NAME, 0, ctx);
	else
#endif
		error = VNOP_REMOVE(dvp, vp, &ndp->ni_cnd, flags, ctx);

	/*
	 * Call out to allow 3rd party notification of delete. 
	 * Ignore result of kauth_authorize_fileop call.
	 */
	if (!error) {
		if (has_listeners) {
			kauth_authorize_fileop(vfs_context_ucred(ctx), 
				KAUTH_FILEOP_DELETE, 
				(uintptr_t)vp,
				(uintptr_t)path);
		}

		if (vp->v_flag & VISHARDLINK) {
		    //
		    // if a hardlink gets deleted we want to blow away the
		    // v_parent link because the path that got us to this
		    // instance of the link is no longer valid.  this will
		    // force the next call to get the path to ask the file
		    // system instead of just following the v_parent link.
		    //
		    vnode_update_identity(vp, NULL, NULL, 0, 0, VNODE_UPDATE_PARENT);
		}

#if CONFIG_FSE
		if (need_event) {
			if (vp->v_flag & VISHARDLINK) {
				get_fse_info(vp, &finfo, ctx);
			}
			add_fsevent(FSE_DELETE, ctx,
						FSE_ARG_STRING, len, path,
						FSE_ARG_FINFO, &finfo,
						FSE_ARG_DONE);
		}
#endif
	}
	if (path != NULL)
		RELEASE_PATH(path);

	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
out:
	nameidone(ndp);
	vnode_put(dvp);
	vnode_put(vp);
	return (error);
}

/*
 * Delete a name from the filesystem using POSIX semantics.
 */
int
unlink(__unused proc_t p, struct unlink_args *uap, __unused register_t *retval)
{
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, DELETE, AUDITVNPATH1, UIO_USERSPACE, uap->path, ctx);
	return unlink1(ctx, &nd, 0);
}

/*
 * Delete a name from the filesystem using Carbon semantics.
 */
int
delete(__unused proc_t p, struct delete_args *uap, __unused register_t *retval)
{
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, DELETE, AUDITVNPATH1, UIO_USERSPACE, uap->path, ctx);
	return unlink1(ctx, &nd, 1);
}

/*
 * Reposition read/write file offset.
 */
int
lseek(proc_t p, struct lseek_args *uap, off_t *retval)
{
	struct fileproc *fp;
	vnode_t vp;
	struct vfs_context *ctx;
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


	ctx = vfs_context_current();
#if CONFIG_MACF
	if (uap->whence == L_INCR && uap->offset == 0)
		error = mac_file_check_get_offset(vfs_context_ucred(ctx),
		    fp->f_fglob);
	else
		error = mac_file_check_change_offset(vfs_context_ucred(ctx),
		    fp->f_fglob);
	if (error) {
		file_drop(uap->fd);
		return (error);
	}
#endif
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}

	switch (uap->whence) {
	case L_INCR:
		offset += fp->f_fglob->fg_offset;
		break;
	case L_XTND:
		if ((error = vnode_size(vp, &file_size, ctx)) != 0)
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
 *
 * Returns:	0			Success
 *		vnode_authorize:???
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
	
#if CONFIG_MACF
	error = mac_vnode_check_access(ctx, vp, uflags);
	if (error)
		return (error);
#endif /* MAC */

 	/* action == 0 means only check for existence */
 	if (action != 0) {
 		error = vnode_authorize(vp, dvp, action | KAUTH_VNODE_ACCESS, ctx);
	} else {
		error = 0;
	}

	return(error);
}



/*
 * access_extended
 *
 * Description:	uap->entries			Pointer to argument descriptor
 *		uap->size			Size of the area pointed to by
 *						the descriptor
 *		uap->results			Pointer to the results array
 *
 * Returns:	0			Success
 *		ENOMEM			Insufficient memory
 *		EINVAL			Invalid arguments
 *		namei:EFAULT		Bad address
 *		namei:ENAMETOOLONG	Filename too long
 *		namei:ENOENT		No such file or directory
 *		namei:ELOOP		Too many levels of symbolic links
 *		namei:EBADF		Bad file descriptor
 *		namei:ENOTDIR		Not a directory
 *		namei:???
 *		access1:
 *
 * Implicit returns:
 *		uap->results		Array contents modified
 *
 * Notes:	The uap->entries are structured as an arbitrary length array
 *		of accessx descriptors, followed by one or more NULL terniated
 *		strings
 *
 *			struct accessx_descriptor[0]
 *			...
 *			struct accessx_descriptor[n]
 *			char name_data[0];
 *
 *		We determine the entry count by walking the buffer containing
 *		the uap->entries argument descriptor.  For each descrptor we
 *		see, the valid values for the offset ad_name_offset will be
 *		in the byte range:
 *
 *			[ uap->entries + sizeof(struct accessx_descriptor) ]
 *						to
 *				[ uap->entries + uap->size - 2 ]
 *
 *		since we must have at least one string, and the string must
 *		be at least one character plus the NUL terminator in length.
 *		
 * XXX:		Need to support the check-as uid argument
 */
int
access_extended(__unused proc_t p, struct access_extended_args *uap, __unused register_t *retval)
{
	struct accessx_descriptor *input = NULL;
	errno_t *result = NULL;
	errno_t error = 0;
	int wantdelete = 0;
	unsigned int desc_max, desc_actual, i, j;
	struct vfs_context context;
	struct nameidata nd;
 	int niopts;
	vnode_t vp = NULL;
	vnode_t dvp = NULL;
#define ACCESSX_MAX_DESCR_ON_STACK 10
	struct accessx_descriptor stack_input[ACCESSX_MAX_DESCR_ON_STACK];

	context.vc_ucred = NULL;

	/*
	 * Validate parameters; if valid, copy the descriptor array and string
	 * arguments into local memory.  Before proceeding, the following
	 * conditions must have been met:
	 *
	 * o	The total size is not permitted to exceed ACCESSX_MAX_TABLESIZE
	 * o	There must be sufficient room in the request for at least one
	 *	descriptor and a one yte NUL terminated string.
	 * o	The allocation of local storage must not fail.
	 */
	if (uap->size > ACCESSX_MAX_TABLESIZE)
		return(ENOMEM);
	if (uap->size < (sizeof(struct accessx_descriptor) + 2))
		return(EINVAL);
	if (uap->size <= sizeof (stack_input)) {
		input = stack_input;
	} else {
	MALLOC(input, struct accessx_descriptor *, uap->size, M_TEMP, M_WAITOK);
	if (input == NULL) {
		error = ENOMEM;
		goto out;
	}
	}
	error = copyin(uap->entries, input, uap->size);
	if (error)
		goto out;

	/*
	 * Force NUL termination of the copyin buffer to avoid nami() running
	 * off the end.  If the caller passes us bogus data, they may get a
	 * bogus result.
	 */
	((char *)input)[uap->size - 1] = 0;

	/*
	 * Access is defined as checking against the process' real identity,
 	 * even if operations are checking the effective identity.  This
	 * requires that we use a local vfs context.
 	 */
	context.vc_ucred = kauth_cred_copy_real(kauth_cred_get());
	context.vc_thread = current_thread();

	/*
	 * Find out how many entries we have, so we can allocate the result
	 * array by walking the list and adjusting the count downward by the
	 * earliest string offset we see.
	 */
	desc_max = (uap->size - 2) / sizeof(struct accessx_descriptor);
	desc_actual = desc_max;
	for (i = 0; i < desc_actual; i++) {
		/*
		 * Take the offset to the name string for this entry and
		 * convert to an input array index, which would be one off
		 * the end of the array if this entry was the lowest-addressed
		 * name string.
		 */
		j = input[i].ad_name_offset / sizeof(struct accessx_descriptor);

		/*
		 * An offset greater than the max allowable offset is an error.
		 * It is also an error for any valid entry to point
		 * to a location prior to the end of the current entry, if
		 * it's not a reference to the string of the previous entry.
		 */
		if (j > desc_max || (j != 0 && j <= i)) {
			error = EINVAL;
			goto out;
		}

		/*
		 * An offset of 0 means use the previous descriptor's offset;
		 * this is used to chain multiple requests for the same file
		 * to avoid multiple lookups.
		 */
		if (j == 0) {
			/* This is not valid for the first entry */
			if (i == 0) {
				error = EINVAL;
				goto out;
			}
			continue;
		}

		/*
		 * If the offset of the string for this descriptor is before
		 * what we believe is the current actual last descriptor,
		 * then we need to adjust our estimate downward; this permits
		 * the string table following the last descriptor to be out
		 * of order relative to the descriptor list.
		 */
		if (j < desc_actual)
			desc_actual = j;
	}

	/*
	 * We limit the actual number of descriptors we are willing to process
	 * to a hard maximum of ACCESSX_MAX_DESCRIPTORS.  If the number being
	 * requested does not exceed this limit,
	 */
	if (desc_actual > ACCESSX_MAX_DESCRIPTORS) {
		error = ENOMEM;
		goto out;
	}
	MALLOC(result, errno_t *, desc_actual * sizeof(errno_t), M_TEMP, M_WAITOK);
	if (result == NULL) {
		error = ENOMEM;
		goto out;
	}

	/*
	 * Do the work by iterating over the descriptor entries we know to
	 * at least appear to contain valid data.
	 */
	error = 0;
	for (i = 0; i < desc_actual; i++) {
		/*
		 * If the ad_name_offset is 0, then we use the previous
		 * results to make the check; otherwise, we are looking up
		 * a new file name.
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
			
			/*
			 * Scan forward in the descriptor list to see if we
			 * need the parent vnode.  We will need it if we are
			 * deleting, since we must have rights  to remove
			 * entries in the parent directory, as well as the
			 * rights to delete the object itself.
			 */
			wantdelete = input[i].ad_flags & _DELETE_OK;
			for (j = i + 1; (j < desc_actual) && (input[j].ad_name_offset == 0); j++)
				if (input[j].ad_flags & _DELETE_OK)
					wantdelete = 1;
			
			niopts = FOLLOW | AUDITVNPATH1;

			/* need parent for vnode_authorize for deletion test */
			if (wantdelete)
				niopts |= WANTPARENT;

			/* do the lookup */
			NDINIT(&nd, LOOKUP, niopts, UIO_SYSSPACE, CAST_USER_ADDR_T(((const char *)input) + input[i].ad_name_offset), &context);
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
	error = copyout(result, uap->results, desc_actual * sizeof(errno_t));
	
out:
	if (input && input != stack_input)
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


/*
 * Returns:	0			Success
 *		namei:EFAULT		Bad address
 *		namei:ENAMETOOLONG	Filename too long
 *		namei:ENOENT		No such file or directory
 *		namei:ELOOP		Too many levels of symbolic links
 *		namei:EBADF		Bad file descriptor
 *		namei:ENOTDIR		Not a directory
 *		namei:???
 *		access1:
 */
int
access(__unused proc_t p, struct access_args *uap, __unused register_t *retval)
{
	int error;
	struct nameidata nd;
 	int niopts;
	struct vfs_context context;

#if NAMEDRSRCFORK
	int is_namedstream = 0;
#endif

 	/*
 	 * Access is defined as checking against the process'
 	 * real identity, even if operations are checking the
 	 * effective identity.  So we need to tweak the credential
 	 * in the context.
 	 */
	context.vc_ucred = kauth_cred_copy_real(kauth_cred_get());
	context.vc_thread = current_thread();

	niopts = FOLLOW | AUDITVNPATH1;
 	/* need parent for vnode_authorize for deletion test */
 	if (uap->flags & _DELETE_OK)
 		niopts |= WANTPARENT;
 	NDINIT(&nd, LOOKUP, niopts, UIO_USERSPACE, uap->path, &context);

#if NAMEDRSRCFORK
	/* access(F_OK) calls are allowed for resource forks. */
	if (uap->flags == F_OK)
		nd.ni_cnd.cn_flags |= CN_ALLOWRSRCFORK;
#endif
 	error = namei(&nd);
 	if (error)
 		goto out;

#if NAMEDRSRCFORK
	/* Grab reference on the shadow stream file vnode to
	 * force an inactive on release which will mark it for
	 * recycle
	 */
	if (vnode_isnamedstream(nd.ni_vp) &&
			(nd.ni_vp->v_parent != NULLVP) &&
			((nd.ni_vp->v_parent->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) == 0)) {
		is_namedstream = 1;
		vnode_ref(nd.ni_vp);
	}
#endif

	error = access1(nd.ni_vp, nd.ni_dvp, uap->flags, &context);
 	
#if NAMEDRSRCFORK
	if (is_namedstream) {
		vnode_rele(nd.ni_vp);
	}
#endif

 	vnode_put(nd.ni_vp);
 	if (uap->flags & _DELETE_OK)
 		vnode_put(nd.ni_dvp);
  	nameidone(&nd);
  
out:
 	kauth_cred_unref(&context.vc_ucred);
 	return(error);
}


/*
 * Returns:	0			Success
 *		EFAULT
 *	copyout:EFAULT
 *	namei:???
 *	vn_stat:???
 */
static int
stat2(vfs_context_t ctx, struct nameidata *ndp, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size, int isstat64)
{
	struct stat sb;
	struct stat64 sb64;
	struct user_stat user_sb;
	struct user_stat64 user_sb64;
	caddr_t sbp;
	int error, my_size;
	kauth_filesec_t fsec;
	size_t xsecurity_bufsize;
	void * statptr;

#if NAMEDRSRCFORK
	int is_namedstream = 0;
	/* stat calls are allowed for resource forks. */
	ndp->ni_cnd.cn_flags |= CN_ALLOWRSRCFORK;
#endif
	error = namei(ndp);
	if (error)
		return (error);
	fsec = KAUTH_FILESEC_NONE;
	if (isstat64 != 0) 
		statptr	 = (void *)&sb64;
	else
		statptr	 = (void *)&sb;

#if NAMEDRSRCFORK
	/* Grab reference on the shadow stream file vnode to
	 * force an inactive on release which will mark it for
	 * recycle.
	 */
	if (vnode_isnamedstream(ndp->ni_vp) &&
			(ndp->ni_vp->v_parent != NULLVP) &&
			((ndp->ni_vp->v_parent->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) == 0)) {
		is_namedstream = 1;
		vnode_ref (ndp->ni_vp);
	}
#endif

	error = vn_stat(ndp->ni_vp, statptr, (xsecurity != USER_ADDR_NULL ? &fsec : NULL), isstat64, ctx);

#if NAMEDRSRCFORK
	if (is_namedstream) {
		vnode_rele (ndp->ni_vp);
	}
#endif
	
	vnode_put(ndp->ni_vp);
	nameidone(ndp);

	if (error)
		return (error);
	/* Zap spare fields */
	if (isstat64 != 0) {
		sb64.st_lspare = 0;
		sb64.st_qspare[0] = 0LL;
		sb64.st_qspare[1] = 0LL;
		if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
			munge_stat64(&sb64, &user_sb64); 
			my_size = sizeof(user_sb64);
			sbp = (caddr_t)&user_sb64;
		} else {
			my_size = sizeof(sb64);
			sbp = (caddr_t)&sb64;
		}
		/*
		 * Check if we raced (post lookup) against the last unlink of a file.
		 */
		if ((sb64.st_nlink == 0) && S_ISREG(sb64.st_mode)) {
			sb64.st_nlink = 1;
		}
	} else {
		sb.st_lspare = 0;
		sb.st_qspare[0] = 0LL;
		sb.st_qspare[1] = 0LL;
		if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
			munge_stat(&sb, &user_sb); 
			my_size = sizeof(user_sb);
			sbp = (caddr_t)&user_sb;
		} else {
			my_size = sizeof(sb);
			sbp = (caddr_t)&sb;
		}

		/*
		 * Check if we raced (post lookup) against the last unlink of a file.
		 */
		if ((sb.st_nlink == 0) && S_ISREG(sb.st_mode)) {
			sb.st_nlink = 1;
		}
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
 *
 * Returns:	0			Success
 *	stat2:???			[see stat2() in this file]
 */
static int
stat1(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size, int isstat64)
{
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, LOOKUP, NOTRIGGER | FOLLOW | AUDITVNPATH1, 
	    UIO_USERSPACE, path, ctx);
	return(stat2(ctx, &nd, ub, xsecurity, xsecurity_size, isstat64));
}

int
stat_extended(__unused proc_t p, struct stat_extended_args *uap, __unused register_t *retval)
{
	return (stat1(uap->path, uap->ub, uap->xsecurity, uap->xsecurity_size, 0));
}

/*
 * Returns:	0			Success
 *	stat1:???			[see stat1() in this file]
 */
int
stat(__unused proc_t p, struct stat_args *uap, __unused register_t *retval)
{
	return(stat1(uap->path, uap->ub, 0, 0, 0));
}

int
stat64(__unused proc_t p, struct stat64_args *uap, __unused register_t *retval)
{
	return(stat1(uap->path, uap->ub, 0, 0, 1));
}

int
stat64_extended(__unused proc_t p, struct stat64_extended_args *uap, __unused register_t *retval)
{
	return (stat1(uap->path, uap->ub, uap->xsecurity, uap->xsecurity_size, 1));
}
/*
 * Get file status; this version does not follow links.
 */
static int
lstat1(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size, int isstat64)
{
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, LOOKUP, NOTRIGGER | NOFOLLOW | AUDITVNPATH1, 
	    UIO_USERSPACE, path, ctx);

	return(stat2(ctx, &nd, ub, xsecurity, xsecurity_size, isstat64));
}

int
lstat_extended(__unused proc_t p, struct lstat_extended_args *uap, __unused register_t *retval)
{
	return (lstat1(uap->path, uap->ub, uap->xsecurity, uap->xsecurity_size, 0));
}

int
lstat(__unused proc_t p, struct lstat_args *uap, __unused register_t *retval)
{
	return(lstat1(uap->path, uap->ub, 0, 0, 0));
}
int
lstat64(__unused proc_t p, struct lstat64_args *uap, __unused register_t *retval)
{
	return(lstat1(uap->path, uap->ub, 0, 0, 1));
}

int
lstat64_extended(__unused proc_t p, struct lstat64_extended_args *uap, __unused register_t *retval)
{
	return (lstat1(uap->path, uap->ub, uap->xsecurity, uap->xsecurity_size, 1));
}

/*
 * Get configurable pathname variables.
 *
 * Returns:	0			Success
 *	namei:???
 *	vn_pathconf:???
 *
 * Notes:	Global implementation  constants are intended to be
 *		implemented in this function directly; all other constants
 *		are per-FS implementation, and therefore must be handled in
 *		each respective FS, instead.
 *
 * XXX We implement some things globally right now that should actually be
 * XXX per-FS; we will need to deal with this at some point.
 */
/* ARGSUSED */
int
pathconf(__unused proc_t p, struct pathconf_args *uap, register_t *retval)
{
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);

	error = vn_pathconf(nd.ni_vp, uap->name, retval, ctx);

	vnode_put(nd.ni_vp);
	nameidone(&nd);
	return (error);
}

/*
 * Return target name of a symbolic link.
 */
/* ARGSUSED */
int
readlink(proc_t p, struct readlink_args *uap, register_t *retval)
{
	vnode_t vp;
	uio_t auio;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	char uio_buf[ UIO_SIZEOF(1) ];

	NDINIT(&nd, LOOKUP, NOFOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
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
#if CONFIG_MACF
		error = mac_vnode_check_readlink(ctx,
		    vp);
#endif
		if (error == 0)
			error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_DATA, ctx);
		if (error == 0)
			error = VNOP_READLINK(vp, auio, ctx);
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

#if CONFIG_MACF
	error = mac_vnode_check_setflags(ctx, vp, flags);
	if (error)
		goto out;
#endif

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

	if ((error == 0) && !VATTR_IS_SUPPORTED(&va, va_flags)) {
		error = ENOTSUP;
	}
out:
	vnode_put(vp);
	return(error);
}

/*
 * Change flags of a file given a path name.
 */
/* ARGSUSED */
int
chflags(__unused proc_t p, struct chflags_args *uap, __unused register_t *retval)
{
	vnode_t vp;
	vfs_context_t ctx = vfs_context_current();
	int error;
	struct nameidata nd;

	AUDIT_ARG(fflags, uap->flags);
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	nameidone(&nd);

	error = chflags1(vp, uap->flags, ctx);

	return(error);
}

/*
 * Change flags of a file given a file descriptor.
 */
/* ARGSUSED */
int
fchflags(__unused proc_t p, struct fchflags_args *uap, __unused register_t *retval)
{
	vnode_t vp;
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

	error = chflags1(vp, uap->flags, vfs_context_current());

	file_drop(uap->fd);
	return (error);
}

/*
 * Change security information on a filesystem object.
 *
 * Returns:	0			Success
 *		EPERM			Operation not permitted
 *		vnode_authattr:???	[anything vnode_authattr can return]
 *		vnode_authorize:???	[anything vnode_authorize can return]
 *		vnode_setattr:???	[anything vnode_setattr can return]
 *
 * Notes:	If vnode_authattr or vnode_authorize return EACCES, it will be
 *		translated to EPERM before being returned.
 */
static int
chmod2(vfs_context_t ctx, vnode_t vp, struct vnode_attr *vap)
{
	kauth_action_t action;
	int error;
	
	AUDIT_ARG(mode, (mode_t)vap->va_mode);
#warning XXX audit new args

#if NAMEDSTREAMS
	/* chmod calls are not allowed for resource forks. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		return (EPERM);
	}
#endif

#if CONFIG_MACF
	error = mac_vnode_check_setmode(ctx, vp, (mode_t)vap->va_mode);
	if (error)
		return (error);
#endif

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
 *
 * Returns:	0			Success
 *		namei:???		[anything namei can return]
 *		chmod2:???		[anything chmod2 can return]
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
chmod_extended(__unused proc_t p, struct chmod_extended_args *uap, __unused register_t *retval)
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

	error = chmod1(vfs_context_current(), uap->path, &va);

	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);
	return(error);
}

/*
 * Returns:	0			Success
 *		chmod1:???		[anything chmod1 can return]
 */
int
chmod(__unused proc_t p, struct chmod_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, uap->mode & ALLPERMS);

	return(chmod1(vfs_context_current(), uap->path, &va));
}

/*
 * Change mode of a file given a file descriptor.
 */
static int
fchmod1(__unused proc_t p, int fd, struct vnode_attr *vap)
{
	vnode_t vp;
	int error;

	AUDIT_ARG(fd, fd);

	if ((error = file_vnode(fd, &vp)) != 0)
		return (error);
	if ((error = vnode_getwithref(vp)) != 0) {
		file_drop(fd);
		return(error);
	}
	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	error = chmod2(vfs_context_current(), vp, vap);
	(void)vnode_put(vp);
	file_drop(fd);

	return (error);
}

int
fchmod_extended(proc_t p, struct fchmod_extended_args *uap, __unused register_t *retval)
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
fchmod(proc_t p, struct fchmod_args *uap, __unused register_t *retval)
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
chown1(vfs_context_t ctx, struct chown_args *uap, __unused register_t *retval, int follow)
{
	vnode_t vp;
	struct vnode_attr va;
	int error;
	struct nameidata nd;
	kauth_action_t action;

	AUDIT_ARG(owner, uap->uid, uap->gid);

	NDINIT(&nd, LOOKUP, (follow ? FOLLOW : 0) | NOTRIGGER | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	VATTR_INIT(&va);
	if (uap->uid != VNOVAL)
		VATTR_SET(&va, va_uid, uap->uid);
	if (uap->gid != VNOVAL)
		VATTR_SET(&va, va_gid, uap->gid);

#if CONFIG_MACF
	error = mac_vnode_check_setowner(ctx, vp, uap->uid, uap->gid);
	if (error)
		goto out;
#endif

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
chown(__unused proc_t p, struct chown_args *uap, register_t *retval)
{
	return chown1(vfs_context_current(), uap, retval, 1);
}

int
lchown(__unused proc_t p, struct lchown_args *uap, register_t *retval)
{
	/* Argument list identical, but machine generated; cast for chown1() */
	return chown1(vfs_context_current(), (struct chown_args *)uap, retval, 0);
}

/*
 * Set ownership given a file descriptor.
 */
/* ARGSUSED */
int
fchown(__unused proc_t p, struct fchown_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	vnode_t vp;
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

#if NAMEDSTREAMS
	/* chown calls are not allowed for resource forks. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif

#if CONFIG_MACF
	error = mac_vnode_check_setowner(ctx, vp, uap->uid, uap->gid);
	if (error)
		goto out;
#endif

 	/* preflight and authorize attribute changes */
	if ((error = vnode_authattr(vp, &va, &action, ctx)) != 0)
		goto out;
	if (action && ((error = vnode_authorize(vp, NULL, action, ctx)) != 0)) {
		if (error == EACCES)
			error = EPERM;
		goto out;
	}
	error = vnode_setattr(vp, &va, ctx);

out:
	(void)vnode_put(vp);
	file_drop(uap->fd);
	return (error);
}

static int
getutimes(user_addr_t usrtvp, struct timespec *tsp)
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
setutimes(vfs_context_t ctx, vnode_t vp, const struct timespec *ts,
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

#if NAMEDSTREAMS
	/* utimes calls are not allowed for resource forks. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		error = EPERM;
		goto out;
	}
#endif

#if CONFIG_MACF
	error = mac_vnode_check_setutimes(ctx, vp, ts[0], ts[1]);
	if (error)
		goto out;
#endif
	if ((error = vnode_authattr(vp, &va, &action, ctx)) != 0) {
		if (!nullflag && error == EACCES)
			error = EPERM;
		goto out;
	}

	/* since we may not need to auth anything, check here */
	if ((action != 0) && ((error = vnode_authorize(vp, NULL, action, ctx)) != 0)) {
		if (!nullflag && error == EACCES)
			error = EPERM;
		goto out;
	}
	error = vnode_setattr(vp, &va, ctx);

out:
	return error;
}

/*
 * Set the access and modification times of a file.
 */
/* ARGSUSED */
int
utimes(__unused proc_t p, struct utimes_args *uap, __unused register_t *retval)
{
	struct timespec ts[2];
	user_addr_t usrtvp;
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	/*
	 * AUDIT: Needed to change the order of operations to do the 
	 * name lookup first because auditing wants the path.
	 */
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
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

	error = setutimes(ctx, nd.ni_vp, ts, usrtvp == USER_ADDR_NULL);

out:
	vnode_put(nd.ni_vp);
	return (error);
}

/*
 * Set the access and modification times of a file.
 */
/* ARGSUSED */
int
futimes(__unused proc_t p, struct futimes_args *uap, __unused register_t *retval)
{
	struct timespec ts[2];
	vnode_t vp;
	user_addr_t usrtvp;
	int error;

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

	error =  setutimes(vfs_context_current(), vp, ts, usrtvp == 0);
	vnode_put(vp);
	file_drop(uap->fd);
	return(error);
}

/*
 * Truncate a file given its path name.
 */
/* ARGSUSED */
int
truncate(__unused proc_t p, struct truncate_args *uap, __unused register_t *retval)
{
	vnode_t vp;
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	int error;
	struct nameidata nd;
	kauth_action_t action;

	if (uap->length < 0)
		return(EINVAL);
	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	if ((error = namei(&nd)))
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	VATTR_INIT(&va);
	VATTR_SET(&va, va_data_size, uap->length);

#if CONFIG_MACF
	error = mac_vnode_check_truncate(ctx, NOCRED, vp);
	if (error)
		goto out;
#endif

	if ((error = vnode_authattr(vp, &va, &action, ctx)) != 0)
		goto out;
	if ((action != 0) && ((error = vnode_authorize(vp, NULL, action, ctx)) != 0))
		goto out;
	error = vnode_setattr(vp, &va, ctx);
out:
	vnode_put(vp);
	return (error);
}

/*
 * Truncate a file given a file descriptor.
 */
/* ARGSUSED */
int
ftruncate(proc_t p, struct ftruncate_args *uap, register_t *retval)
{
	vfs_context_t ctx = vfs_context_current();
	struct vnode_attr va;
	vnode_t vp;
	struct fileproc *fp;
	int error ;
	int fd = uap->fd;

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

	vp = (vnode_t)fp->f_fglob->fg_data;

	if ((fp->f_fglob->fg_flag & FWRITE) == 0) {
		AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);
		error = EINVAL;
		goto out;
	}

	if ((error = vnode_getwithref(vp)) != 0) {
		goto out;
	}

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

#if CONFIG_MACF
	error = mac_vnode_check_truncate(ctx,
	    fp->f_fglob->fg_cred, vp);
	if (error) {
		(void)vnode_put(vp);
		goto out;
	}
#endif
	VATTR_INIT(&va);
	VATTR_SET(&va, va_data_size, uap->length);
	error = vnode_setattr(vp, &va, ctx);
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
fsync(proc_t p, struct fsync_args *uap, register_t *retval)
{
	__pthread_testcancel(1);
	return(fsync_nocancel(p, (struct fsync_nocancel_args *)uap, retval));
}

int
fsync_nocancel(proc_t p, struct fsync_nocancel_args *uap, __unused register_t *retval)
{
	vnode_t vp;
	struct fileproc *fp;
	vfs_context_t ctx = vfs_context_current();
	int error;

	if ( (error = fp_getfvp(p, uap->fd, &fp, &vp)) )
		return (error);
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}

	error = VNOP_FSYNC(vp, MNT_WAIT, ctx);

#if NAMEDRSRCFORK
	/* Sync resource fork shadow file if necessary. */
	if ((error == 0) &&
	    (vp->v_flag & VISNAMEDSTREAM) && 
	    (vp->v_parent != NULLVP) &&
	    !(vp->v_parent->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) &&
	    (fp->f_flags & FP_WRITTEN)) {
		(void) vnode_flushnamedstream(vp->v_parent, vp, ctx);
	}
#endif

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
copyfile(__unused proc_t p, struct copyfile_args *uap, __unused register_t *retval)
{
	vnode_t tvp, fvp, tdvp, sdvp;
	struct nameidata fromnd, tond;
	int error;
	vfs_context_t ctx = vfs_context_current();

	/* Check that the flags are valid. */

	if (uap->flags & ~CPF_MASK) {
		return(EINVAL);
	}

	NDINIT(&fromnd, LOOKUP, SAVESTART | AUDITVNPATH1,
		UIO_USERSPACE, uap->from, ctx);
	if ((error = namei(&fromnd)))
		return (error);
	fvp = fromnd.ni_vp;

	NDINIT(&tond, CREATE,  LOCKPARENT | LOCKLEAF | NOCACHE | SAVESTART | AUDITVNPATH2 | CN_NBMOUNTLOOK,
	    UIO_USERSPACE, uap->to, ctx);
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

	if ((error = vnode_authorize(tdvp, NULL, KAUTH_VNODE_ADD_FILE, ctx)) != 0)
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
	        error = VNOP_COPYFILE(fvp, tdvp, tvp, &tond.ni_cnd, uap->mode, uap->flags, ctx);
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
rename(__unused proc_t p, struct rename_args *uap, __unused register_t *retval)
{
	vnode_t tvp, tdvp;
	vnode_t fvp, fdvp;
	struct nameidata fromnd, tond;
	vfs_context_t ctx = vfs_context_current();
	int error;
	int do_retry;
	int mntrename;
	int need_event;
	const char *oname;
	char *from_name = NULL, *to_name = NULL;
	int from_len, to_len;
	int holding_mntlock;
	mount_t locked_mp = NULL;
	vnode_t oparent;
	fse_info from_finfo, to_finfo;
	
	holding_mntlock = 0;
    do_retry = 0;
retry:
	fvp = tvp = NULL;
	fdvp = tdvp = NULL;
	mntrename = FALSE;

	NDINIT(&fromnd, DELETE, WANTPARENT | AUDITVNPATH1, UIO_USERSPACE, uap->from, ctx);
	
	if ( (error = namei(&fromnd)) )
	        goto out1;
	fdvp = fromnd.ni_dvp;
	fvp  = fromnd.ni_vp;

#if CONFIG_MACF
	error = mac_vnode_check_rename_from(ctx, fdvp, fvp, &fromnd.ni_cnd);
	if (error)
		goto out1;
#endif

	NDINIT(&tond, RENAME, WANTPARENT | AUDITVNPATH2 | CN_NBMOUNTLOOK , UIO_USERSPACE, uap->to, ctx);
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

#if CONFIG_MACF
	error = mac_vnode_check_rename_to(ctx,
	    tdvp, tvp, fdvp == tdvp, &tond.ni_cnd);
	if (error)
		goto out1;
#endif

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
         * If the source and destination are the same (i.e. they're
         * links to the same vnode) and the target file system is
         * case sensitive, then there is nothing to do.
         */
	if (fvp == tvp) {
		int pathconf_val;
		
		/*
		 * Note: if _PC_CASE_SENSITIVE selector isn't supported,
		 * then assume that this file system is case sensitive.
		 */
		if (VNOP_PATHCONF(fvp, _PC_CASE_SENSITIVE, &pathconf_val, ctx) != 0 ||
		    pathconf_val != 0) {
			goto out1;
		}	
	}

	/*
	 * Authorization.
	 *
	 * If tvp is a directory and not the same as fdvp, or tdvp is not
	 * the same as fdvp, the node is moving between directories and we
	 * need rights to remove from the old and add to the new.
	 *
	 * If tvp already exists and is not a directory, we need to be
	 * allowed to delete it.
	 *
	 * Note that we do not inherit when renaming.
	 *
	 * XXX This needs to be revisited to implement the deferred-inherit bit
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
		 * must have delete rights to remove the old name even in
		 * the simple case of fdvp == tdvp.
		 *
		 * If fvp is a directory, and we are changing it's parent,
		 * then we also need rights to rewrite its ".." entry as well.
		 */
		if (vnode_isdir(fvp)) {
			if ((error = vnode_authorize(fvp, fdvp, KAUTH_VNODE_DELETE | KAUTH_VNODE_ADD_SUBDIRECTORY, ctx)) != 0)
				goto auth_exit;
		} else {
		if ((error = vnode_authorize(fvp, fdvp, KAUTH_VNODE_DELETE, ctx)) != 0)
			goto auth_exit;
		}
		if (moving) {
			/* moving into tdvp or tvp, must have rights to add */
			if ((error = vnode_authorize(((tvp != NULL) && vnode_isdir(tvp)) ? tvp : tdvp,
				 NULL, 
				 vnode_isdir(fvp) ? KAUTH_VNODE_ADD_SUBDIRECTORY : KAUTH_VNODE_ADD_FILE,
				 ctx)) != 0) {
                /*
                 * We could encounter a race where after doing the namei, tvp stops
                 * being valid. If so, simply re-drive the rename call from the
                 * top.
                 */
                 if (error == ENOENT) {
                     do_retry = 1;
                 }
				goto auth_exit;
			}
		} else {
			/* node staying in same directory, must be allowed to add new name */
			if ((error = vnode_authorize(fdvp, NULL,
				 vnode_isdir(fvp) ? KAUTH_VNODE_ADD_SUBDIRECTORY : KAUTH_VNODE_ADD_FILE, ctx)) != 0)
				goto auth_exit;
		}
		/* overwriting tvp */
		if ((tvp != NULL) && !vnode_isdir(tvp) &&
		    ((error = vnode_authorize(tvp, tdvp, KAUTH_VNODE_DELETE, ctx)) != 0)) {
            /*
             * We could encounter a race where after doing the namei, tvp stops
             * being valid. If so, simply re-drive the rename call from the
             * top.
             */
            if (error == ENOENT) {
                do_retry = 1;
            }
			goto auth_exit;
		}
 		    
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
		vnode_t coveredvp;
	
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

#if CONFIG_FSE
	need_event = need_fsevent(FSE_RENAME, fvp);
	if (need_event) { 
	        get_fse_info(fvp, &from_finfo, ctx);

		if (tvp) {
		        get_fse_info(tvp, &to_finfo, ctx);
		}
	}
#else
	need_event = 0;
#endif /* CONFIG_FSE */

	if (need_event || kauth_authorize_fileop_has_listeners()) {
		GET_PATH(from_name);
		if (from_name == NULL) {
			error = ENOMEM;
			goto out1;
		}
		from_len = MAXPATHLEN;
		vn_getpath(fdvp, from_name, &from_len);
		if ((from_len + 1 + fromnd.ni_cnd.cn_namelen + 1) < MAXPATHLEN) {
		    if (from_len > 2) {
			from_name[from_len-1] = '/';
		    } else {
			from_len--;
		    }
		    strlcpy(&from_name[from_len], fromnd.ni_cnd.cn_nameptr, MAXPATHLEN-from_len);
		    from_len += fromnd.ni_cnd.cn_namelen + 1;
		    from_name[from_len] = '\0';
		}

		GET_PATH(to_name);
		if (to_name == NULL) {
			error = ENOMEM;
			goto out1;
		}

		to_len = MAXPATHLEN;
		vn_getpath(tdvp, to_name, &to_len);
		// if the path is not just "/", then append a "/"
		if ((to_len + 1 + tond.ni_cnd.cn_namelen + 1) < MAXPATHLEN) {
		    if (to_len > 2) {
			to_name[to_len-1] = '/';
		    } else {
			to_len--;
		    }
		    strlcpy(&to_name[to_len], tond.ni_cnd.cn_nameptr, MAXPATHLEN-to_len);
		    to_len += tond.ni_cnd.cn_namelen + 1;
		    to_name[to_len] = '\0';
		}
	} 
	
	error = VNOP_RENAME(fdvp, fvp, &fromnd.ni_cnd,
			    tdvp, tvp, &tond.ni_cnd,
			    ctx);

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
        /*
         * We may encounter a race in the VNOP where the destination didn't 
         * exist when we did the namei, but it does by the time we go and 
         * try to create the entry. In this case, we should re-drive this rename
         * call from the top again.
         */
        if (error == EEXIST) {
            do_retry = 1;
        }

		goto out1;
	} 
	
	/* call out to allow 3rd party notification of rename. 
	 * Ignore result of kauth_authorize_fileop call.
	 */
	kauth_authorize_fileop(vfs_context_ucred(ctx), 
			KAUTH_FILEOP_RENAME, 
			(uintptr_t)from_name, (uintptr_t)to_name);

#if CONFIG_FSE
	if (from_name != NULL && to_name != NULL) {
	        if (tvp) {
		        add_fsevent(FSE_RENAME, ctx,
				    FSE_ARG_STRING, from_len, from_name,
				    FSE_ARG_FINFO, &from_finfo,
				    FSE_ARG_STRING, to_len, to_name,
				    FSE_ARG_FINFO, &to_finfo,
				    FSE_ARG_DONE);
		} else {
		        add_fsevent(FSE_RENAME, ctx,
				    FSE_ARG_STRING, from_len, from_name,
				    FSE_ARG_FINFO, &from_finfo,
				    FSE_ARG_STRING, to_len, to_name,
				    FSE_ARG_DONE);
		}
	}
#endif /* CONFIG_FSE */
		
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
			strlcpy(pathend, mpname, maxlen);
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
	if (to_name != NULL) {
		RELEASE_PATH(to_name);
		to_name = NULL;
	}
	if (from_name != NULL) {
		RELEASE_PATH(from_name);
		from_name = NULL;
	}
	if (holding_mntlock) {
	        mount_unlock_renames(locked_mp);
		mount_drop(locked_mp, 0);
		holding_mntlock = 0;
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

    /*
     * If things changed after we did the namei, then we will re-drive
     * this rename call from the top.
     */
	if(do_retry) {
        do_retry = 0;
		goto retry;
	}

	return (error);
}

/*
 * Make a directory file.
 *
 * Returns:	0			Success
 *		EEXIST
 *	namei:???
 *	vnode_authorize:???
 *	vn_create:???
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

	VATTR_SET(vap, va_type, VDIR);
   
#if CONFIG_MACF
	error = mac_vnode_check_create(ctx,
	    nd.ni_dvp, &nd.ni_cnd, vap);
	if (error)
		goto out;
#endif

  	/* authorize addition of a directory to the parent */
  	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_SUBDIRECTORY, ctx)) != 0)
  		goto out;
 	
   
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

#if CONFIG_FSE
	add_fsevent(FSE_CREATE_DIR, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
#endif

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
mkdir_extended(proc_t p, struct mkdir_extended_args *uap, __unused register_t *retval)
{
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vnode_attr va;

	xsecdst = NULL;
	if ((uap->xsecurity != USER_ADDR_NULL) &&
	    ((ciferror = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0))
		return ciferror;

	VATTR_INIT(&va);
  	VATTR_SET(&va, va_mode, (uap->mode & ACCESSPERMS) & ~p->p_fd->fd_cmask);
	if (xsecdst != NULL)
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);

	ciferror = mkdir1(vfs_context_current(), uap->path, &va);
	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);
	return ciferror;
}

int
mkdir(proc_t p, struct mkdir_args *uap, __unused register_t *retval)
{
	struct vnode_attr va;

	VATTR_INIT(&va);
  	VATTR_SET(&va, va_mode, (uap->mode & ACCESSPERMS) & ~p->p_fd->fd_cmask);

	return(mkdir1(vfs_context_current(), uap->path, &va));
}

/*
 * Remove a directory file.
 */
/* ARGSUSED */
int
rmdir(__unused proc_t p, struct rmdir_args *uap, __unused register_t *retval)
{
	vnode_t vp, dvp;
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	int restart_flag, oldvp_id = -1;

	/* 
	 * This loop exists to restart rmdir in the unlikely case that two
	 * processes are simultaneously trying to remove the same directory
	 * containing orphaned appleDouble files.
	 */
	do {
		restart_flag = 0;

		NDINIT(&nd, DELETE, LOCKPARENT | AUDITVNPATH1, 
				UIO_USERSPACE, uap->path, ctx);
		error = namei(&nd);
		if (error)
			return (error);

		dvp = nd.ni_dvp;
		vp = nd.ni_vp;


		/*
		 * If being restarted check if the new vp
		 * still has the same v_id.
		 */
		if (oldvp_id != -1 && oldvp_id != vp->v_id) {
			error = ENOENT;
			goto out;
		}

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
#if CONFIG_MACF
			error = mac_vnode_check_unlink(ctx, dvp,
					vp, &nd.ni_cnd);
			if (!error)
#endif
				error = vnode_authorize(vp, nd.ni_dvp, KAUTH_VNODE_DELETE, ctx);
		}
		if (!error) {
			char     *path = NULL;
			int       len;
			fse_info  finfo;
			int has_listeners = 0;
			int need_event = 0;

#if CONFIG_FSE
			need_event = need_fsevent(FSE_DELETE, dvp);
			if (need_event) {
				get_fse_info(vp, &finfo, ctx);
			}
#endif
			has_listeners = kauth_authorize_fileop_has_listeners();
			if (need_event || has_listeners) {
				GET_PATH(path);
				if (path == NULL) {
					error = ENOMEM;
					goto out;
				}
				len = MAXPATHLEN;
				vn_getpath(vp, path, &len);
			}

			error = VNOP_RMDIR(dvp, vp, &nd.ni_cnd, ctx);

			/*
			 * Special case to remove orphaned AppleDouble
			 * files. I don't like putting this in the kernel,
			 * but carbon does not like putting this in carbon either,
			 * so here we are.
			 */
			if (error == ENOTEMPTY) {
				error = rmdir_remove_orphaned_appleDouble(vp, ctx, &restart_flag);
				if (error == EBUSY) {
					oldvp_id = vp->v_id;
					goto out;
				}


				/*
				 * Assuming everything went well, we will try the RMDIR again 
				 */
				if (!error)
					error = VNOP_RMDIR(dvp, vp, &nd.ni_cnd, ctx);
			}

			/*
			 * Call out to allow 3rd party notification of delete. 
			 * Ignore result of kauth_authorize_fileop call.
			 */
			if (!error) {
				if (has_listeners) {
					kauth_authorize_fileop(vfs_context_ucred(ctx), 
							KAUTH_FILEOP_DELETE, 
							(uintptr_t)vp,
							(uintptr_t)path);
				}

				if (vp->v_flag & VISHARDLINK) {
				    // see the comment in unlink1() about why we update
				    // the parent of a hard link when it is removed
				    vnode_update_identity(vp, NULL, NULL, 0, 0, VNODE_UPDATE_PARENT);
				}

#if CONFIG_FSE
				if (need_event) {
					add_fsevent(FSE_DELETE, ctx,
							FSE_ARG_STRING, len, path,
							FSE_ARG_FINFO, &finfo,
							FSE_ARG_DONE);
				}
#endif
			}
			if (path != NULL)
				RELEASE_PATH(path);
		}

out:
		/*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&nd);

		vnode_put(dvp);
		vnode_put(vp);

		if (restart_flag == 0) {
			wakeup_one((caddr_t)vp);
			return (error);
		}
		tsleep(vp, PVFS, "rm AD", 1);

	} while (restart_flag != 0);

	return (error);

}

/* Get direntry length padded to 8 byte alignment */
#define DIRENT64_LEN(namlen) \
	((sizeof(struct direntry) + (namlen) - (MAXPATHLEN-1) + 7) & ~7)

static errno_t 
vnode_readdir64(struct vnode *vp, struct uio *uio, int flags, int *eofflag,
                int *numdirent, vfs_context_t ctxp)
{
	/* Check if fs natively supports VNODE_READDIR_EXTENDED */
	if (vp->v_mount->mnt_vtable->vfc_vfsflags & VFC_VFSREADDIR_EXTENDED) {
		return VNOP_READDIR(vp, uio, flags, eofflag, numdirent, ctxp);
	} else {
		size_t bufsize;
		void * bufptr;
		uio_t auio;
		struct direntry entry64;
		struct dirent *dep;
		int bytesread;
		int error;

		/*
		 * Our kernel buffer needs to be smaller since re-packing
		 * will expand each dirent.  The worse case (when the name
		 * length is 3) corresponds to a struct direntry size of 32
		 * bytes (8-byte aligned) and a struct dirent size of 12 bytes
		 * (4-byte aligned).  So having a buffer that is 3/8 the size
		 * will prevent us from reading more than we can pack.
                 *
		 * Since this buffer is wired memory, we will limit the
		 * buffer size to a maximum of 32K. We would really like to 
		 * use 32K in the MIN(), but we use magic number 87371 to
		 * prevent uio_resid() * 3 / 8 from overflowing. 
		 */
		bufsize = 3 * MIN(uio_resid(uio), 87371) / 8;
		MALLOC(bufptr, void *, bufsize, M_TEMP, M_WAITOK);

		auio = uio_create(1, 0, UIO_SYSSPACE32, UIO_READ);
		uio_addiov(auio, (uintptr_t)bufptr, bufsize);
		auio->uio_offset = uio->uio_offset;

		error = VNOP_READDIR(vp, auio, 0, eofflag, numdirent, ctxp);

		dep = (struct dirent *)bufptr;
		bytesread = bufsize - uio_resid(auio);

		/*
		 * Convert all the entries and copy them out to user's buffer.
		 */
		while (error == 0 && (char *)dep < ((char *)bufptr + bytesread)) {
			/* Convert a dirent to a dirent64. */
			entry64.d_ino = dep->d_ino;
			entry64.d_seekoff = 0;
			entry64.d_reclen = DIRENT64_LEN(dep->d_namlen);
			entry64.d_namlen = dep->d_namlen;
			entry64.d_type = dep->d_type;
			bcopy(dep->d_name, entry64.d_name, dep->d_namlen + 1);

			/* Move to next entry. */
			dep = (struct dirent *)((char *)dep + dep->d_reclen);

			/* Copy entry64 to user's buffer. */
			error = uiomove((caddr_t)&entry64, entry64.d_reclen, uio);
		}

		/* Update the real offset using the offset we got from VNOP_READDIR. */
		if (error == 0) {
			uio->uio_offset = auio->uio_offset;
		}
		uio_free(auio);
		FREE(bufptr, M_TEMP);
		return (error);
	}
}

/*
 * Read a block of directory entries in a file system independent format.
 */
static int
getdirentries_common(int fd, user_addr_t bufp, user_size_t bufsize, ssize_t *bytesread,
                     off_t *offset, int flags)
{
	vnode_t vp;
	struct vfs_context context = *vfs_context_current();	/* local copy */
	struct fileproc *fp;
	uio_t auio;
	int spacetype = proc_is64bit(vfs_context_proc(&context)) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	off_t loff;
	int error, eofflag, numdirent;
	char uio_buf[ UIO_SIZEOF(1) ];

	error = fp_getfvp(vfs_context_proc(&context), fd, &fp, &vp);
	if (error) {
		return (error);
	}
	if ((fp->f_fglob->fg_flag & FREAD) == 0) {
		AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);
		error = EBADF;
		goto out;
	}

#if CONFIG_MACF
	error = mac_file_check_change_offset(vfs_context_ucred(&context), fp->f_fglob);
	if (error)
		goto out;
#endif
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

#if CONFIG_MACF
	error = mac_vnode_check_readdir(&context, vp);
	if (error != 0) {
		(void)vnode_put(vp);
		goto out;
	}
#endif /* MAC */

	loff = fp->f_fglob->fg_offset;
	auio = uio_createwithbuffer(1, loff, spacetype, UIO_READ, &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, bufp, bufsize);

	if (flags & VNODE_READDIR_EXTENDED) {
		error = vnode_readdir64(vp, auio, flags, &eofflag, &numdirent, &context);
		fp->f_fglob->fg_offset = uio_offset(auio);
	} else {
		error = VNOP_READDIR(vp, auio, 0, &eofflag, &numdirent, &context);
		fp->f_fglob->fg_offset = uio_offset(auio);
	}
	if (error) {
		(void)vnode_put(vp);
		goto out;
	}

	if ((user_ssize_t)bufsize == uio_resid(auio)){
		if (union_dircheckp) {
			error = union_dircheckp(&vp, fp, &context);
			if (error == -1)
				goto unionread;
			if (error)
				goto out;
		}

		if ((vp->v_flag & VROOT) && (vp->v_mount->mnt_flag & MNT_UNION)) {
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
	}

	vnode_put(vp);
	if (offset) {
		*offset = loff;
	}
	// LP64todo - fix this
	*bytesread = bufsize - uio_resid(auio);
out:
	file_drop(fd);
	return (error);
}


int
getdirentries(__unused struct proc *p, struct getdirentries_args *uap, register_t *retval)
{
	off_t offset;
	long loff;
	ssize_t bytesread;
	int error;

	AUDIT_ARG(fd, uap->fd);
	error = getdirentries_common(uap->fd, uap->buf, uap->count, &bytesread, &offset, 0);

	if (error == 0) {
		loff = (long)offset;
		error = copyout((caddr_t)&loff, uap->basep, sizeof(long));
		*retval = bytesread;
	}
	return (error);
}

int
getdirentries64(__unused struct proc *p, struct getdirentries64_args *uap, user_ssize_t *retval)
{
	off_t offset;
	ssize_t bytesread;
	int error;

	AUDIT_ARG(fd, uap->fd);
	error = getdirentries_common(uap->fd, uap->buf, uap->bufsize, &bytesread, &offset, VNODE_READDIR_EXTENDED);

	if (error == 0) {
		*retval = bytesread;
		error = copyout((caddr_t)&offset, uap->position, sizeof(off_t));
	}
	return (error);
}


/*
 * Set the mode mask for creation of filesystem nodes.
 */
#warning XXX implement xsecurity

#define UMASK_NOXSECURITY	 (void *)1	/* leave existing xsecurity alone */
static int
umask1(proc_t p, int newmask, __unused kauth_filesec_t fsec, register_t *retval)
{
	struct filedesc *fdp;

	AUDIT_ARG(mask, newmask);
	proc_fdlock(p);
	fdp = p->p_fd;
	*retval = fdp->fd_cmask;
	fdp->fd_cmask = newmask & ALLPERMS;
	proc_fdunlock(p);
	return (0);
}


int
umask_extended(proc_t p, struct umask_extended_args *uap, register_t *retval)
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
umask(proc_t p, struct umask_args *uap, register_t *retval)
{
	return(umask1(p, uap->newmask, UMASK_NOXSECURITY, retval));
}

/*
 * Void all references to file by ripping underlying filesystem
 * away from vnode.
 */
/* ARGSUSED */
int
revoke(proc_t p, struct revoke_args *uap, __unused register_t *retval)
{
	vnode_t vp;
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

#if CONFIG_MACF
	error = mac_vnode_check_revoke(ctx, vp);
	if (error)
		goto out;
#endif

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	if ((error = vnode_getattr(vp, &va, ctx)))
		goto out;
	if (kauth_cred_getuid(vfs_context_ucred(ctx)) != va.va_uid &&
	    (error = suser(vfs_context_ucred(ctx), &p->p_acflag)))
		goto out;
	if (vp->v_usecount > 1 || (vp->v_flag & VALIASED))
		VNOP_REVOKE(vp, REVOKEALL, ctx);
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
mkcomplex(__unused proc_t p, __unused struct mkcomplex_args *uap, __unused register_t *retval)
{
	return (ENOTSUP);
}

/*
 * Extended stat call which returns volumeid and vnodeid as well as other info
 */
/* ARGSUSED */
int
statv(__unused proc_t p,
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
lstatv(__unused proc_t p,
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
fstatv(__unused proc_t p, 
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
getdirentriesattr (proc_t p, struct getdirentriesattr_args *uap, register_t *retval)
{
	vnode_t vp;
	struct fileproc *fp;
	uio_t auio = NULL;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	uint32_t count;
	uint32_t newstate;
	int error, eofflag;
	uint32_t loff;
	struct attrlist attributelist; 
	vfs_context_t ctx = vfs_context_current();
	int fd = uap->fd;
	char uio_buf[ UIO_SIZEOF(1) ];
	kauth_action_t action;

	AUDIT_ARG(fd, fd);
    
	/* Get the attributes into kernel space */
	if ((error = copyin(uap->alist, (caddr_t)&attributelist, sizeof(attributelist)))) {
		return(error);
	}
	if ((error = copyin(uap->count, (caddr_t)&count, sizeof(count)))) {
		return(error);
	}
	if ( (error = fp_getfvp(p, fd, &fp, &vp)) ) {
		return (error);
	}
	if ((fp->f_fglob->fg_flag & FREAD) == 0) {
		AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);
		error = EBADF;
		goto out;
	}


#if CONFIG_MACF
	error = mac_file_check_change_offset(vfs_context_ucred(ctx),
	    fp->f_fglob);
	if (error)
		goto out;
#endif


	if ( (error = vnode_getwithref(vp)) )
		goto out;

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	if (vp->v_type != VDIR) {
		(void)vnode_put(vp);
		error = EINVAL;
		goto out;
	}

#if CONFIG_MACF
	error = mac_vnode_check_readdir(ctx, vp);
	if (error != 0) {
		(void)vnode_put(vp);
		goto out;
	}
#endif /* MAC */

	/* set up the uio structure which will contain the users return buffer */
	loff = fp->f_fglob->fg_offset;
	auio = uio_createwithbuffer(1, loff, spacetype, UIO_READ, 
	    &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, uap->buffer, uap->buffersize);
       
	/*
	 * If the only item requested is file names, we can let that past with
	 * just LIST_DIRECTORY.  If they want any other attributes, that means
	 * they need SEARCH as well.
	 */
	action = KAUTH_VNODE_LIST_DIRECTORY;
	if ((attributelist.commonattr & ~ATTR_CMN_NAME) ||
	    attributelist.fileattr || attributelist.dirattr)
		action |= KAUTH_VNODE_SEARCH;
	
	if ((error = vnode_authorize(vp, NULL, action, ctx)) == 0) {
		u_long ulcount = count;

		error = VNOP_READDIRATTR(vp, &attributelist, auio,
					 count,
		                         uap->options, (unsigned long *)&newstate, &eofflag,
		                         &ulcount, ctx);
		if (!error)
			count = ulcount;
	}
	(void)vnode_put(vp);

	if (error) 
		goto out;
	fp->f_fglob->fg_offset = uio_offset(auio); /* should be multiple of dirent, not variable */

	if ((error = copyout((caddr_t) &count, uap->count, sizeof(count))))
		goto out;
	if ((error = copyout((caddr_t) &newstate, uap->newstate, sizeof(newstate))))
		goto out;
	if ((error = copyout((caddr_t) &loff, uap->basep, sizeof(loff))))
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
exchangedata (__unused proc_t p, struct exchangedata_args *uap, __unused register_t *retval)
{

	struct nameidata fnd, snd;
	vfs_context_t ctx = vfs_context_current();
	vnode_t fvp;
	vnode_t svp;
	int error;
	u_long nameiflags;
	char *fpath = NULL;
	char *spath = NULL;
	int   flen, slen;
	fse_info f_finfo, s_finfo;

	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;

    NDINIT(&fnd, LOOKUP, nameiflags | AUDITVNPATH1, 
        	UIO_USERSPACE, uap->path1, ctx);

    error = namei(&fnd);
    if (error)
        goto out2;

	nameidone(&fnd);
	fvp = fnd.ni_vp;

    NDINIT(&snd, LOOKUP | CN_NBMOUNTLOOK, nameiflags | AUDITVNPATH2, 
        	UIO_USERSPACE, uap->path2, ctx);

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

#if CONFIG_MACF
	error = mac_vnode_check_exchangedata(ctx,
	    fvp, svp);
	if (error)
		goto out;
#endif
	if (((error = vnode_authorize(fvp, NULL, KAUTH_VNODE_READ_DATA | KAUTH_VNODE_WRITE_DATA, ctx)) != 0) ||
	    ((error = vnode_authorize(svp, NULL, KAUTH_VNODE_READ_DATA | KAUTH_VNODE_WRITE_DATA, ctx)) != 0))
		goto out;

	if (
#if CONFIG_FSE
	need_fsevent(FSE_EXCHANGE, fvp) || 
#endif
	kauth_authorize_fileop_has_listeners()) {
		GET_PATH(fpath);
		GET_PATH(spath);
		if (fpath == NULL || spath == NULL) {
			error = ENOMEM;
			goto out;
		}
		flen = MAXPATHLEN;
		slen = MAXPATHLEN;
		if (vn_getpath(fvp, fpath, &flen) != 0 || fpath[0] == '\0') {
		        printf("exchange: vn_getpath(fvp=%p) failed <<%s>>\n",
			       fvp, fpath);
		}
		if (vn_getpath(svp, spath, &slen) != 0 || spath[0] == '\0') {
		        printf("exchange: vn_getpath(svp=%p) failed <<%s>>\n",
			       svp, spath);
		}
#if CONFIG_FSE
		get_fse_info(fvp, &f_finfo, ctx);
		get_fse_info(svp, &s_finfo, ctx);
#endif
	}
	/* Ok, make the call */
	error = VNOP_EXCHANGE(fvp, svp, 0, ctx);

	if (error == 0) {
	    const char *tmpname;

	    if (fpath != NULL && spath != NULL) {
	            /* call out to allow 3rd party notification of exchangedata. 
		     * Ignore result of kauth_authorize_fileop call.
		     */
	            kauth_authorize_fileop(vfs_context_ucred(ctx), KAUTH_FILEOP_EXCHANGE, 
					   (uintptr_t)fpath, (uintptr_t)spath);
	    }
	    name_cache_lock();

	    tmpname     = fvp->v_name;
	    fvp->v_name = svp->v_name;
	    svp->v_name = tmpname;
	    
	    if (fvp->v_parent != svp->v_parent) {
		vnode_t tmp;

		tmp           = fvp->v_parent;
		fvp->v_parent = svp->v_parent;
		svp->v_parent = tmp;
	    }
	    name_cache_unlock();

#if CONFIG_FSE
	    if (fpath != NULL && spath != NULL) {
	            add_fsevent(FSE_EXCHANGE, ctx,
				FSE_ARG_STRING, flen, fpath,
				FSE_ARG_FINFO, &f_finfo,
				FSE_ARG_STRING, slen, spath,
				FSE_ARG_FINFO, &s_finfo,
				FSE_ARG_DONE);
	    }
#endif
	}

out:
	if (fpath != NULL)
	        RELEASE_PATH(fpath);
	if (spath != NULL)
	        RELEASE_PATH(spath);
	vnode_put(svp);
	vnode_put(fvp);
out2:
        return (error);
}


/* ARGSUSED */

int
searchfs(proc_t p, struct searchfs_args *uap, __unused register_t *retval)
{
	vnode_t vp;
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
	vfs_context_t ctx = vfs_context_current();
	char uio_buf[ UIO_SIZEOF(1) ];

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
		UIO_USERSPACE, uap->path, ctx);

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
							ctx);
		
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
fsctl (proc_t p, struct fsctl_args *uap, __unused register_t *retval)
{
	int error;
	boolean_t is64bit;
	struct nameidata nd;	
	u_long nameiflags;
	u_long cmd = uap->cmd;
	u_int size;
#define STK_PARAMS 128
	char stkbuf[STK_PARAMS];
	caddr_t data, memp;
	vfs_context_t ctx = vfs_context_current();

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
	NDINIT(&nd, LOOKUP, nameiflags, UIO_USERSPACE, uap->path, ctx);
	if ((error = namei(&nd))) goto FSCtl_Exit;

#if CONFIG_MACF
	error = mac_mount_check_fsctl(ctx, vnode_mount(nd.ni_vp), cmd);
	if (error) {
		vnode_put(nd.ni_vp);
		nameidone(&nd);
		goto FSCtl_Exit;
	}
#endif

	/* Invoke the filesystem-specific code */
	error = VNOP_IOCTL(nd.ni_vp, IOCBASECMD(cmd), data, uap->options, ctx);
	
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
getxattr(proc_t p, struct getxattr_args *uap, user_ssize_t *retval)
{
	vnode_t vp;
	struct nameidata nd;
	char attrname[XATTR_MAXNAMELEN+1];
	vfs_context_t ctx = vfs_context_current();
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	size_t namelen;
	u_long nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOSECURITY | XATTR_NODEFAULT))
		return (EINVAL);

	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, spacetype, uap->path, ctx);
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

	error = vn_getxattr(vp, attrname, auio, &attrsize, uap->options, ctx);
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
fgetxattr(proc_t p, struct fgetxattr_args *uap, user_ssize_t *retval)
{
	vnode_t vp;
	char attrname[XATTR_MAXNAMELEN+1];
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	size_t namelen;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOFOLLOW | XATTR_NOSECURITY | XATTR_NODEFAULT))
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

	error = vn_getxattr(vp, attrname, auio, &attrsize, uap->options, vfs_context_current());
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
setxattr(proc_t p, struct setxattr_args *uap, int *retval)
{
	vnode_t vp;
	struct nameidata nd;
	char attrname[XATTR_MAXNAMELEN+1];
	vfs_context_t ctx = vfs_context_current();
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t namelen;
	u_long nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOSECURITY | XATTR_NODEFAULT))
		return (EINVAL);

	if ((error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen) != 0)) {
		return (error);
	}
	if (xattr_protected(attrname))
		return(EPERM);
	if (uap->size != 0 && uap->value == 0) {
		return (EINVAL);
	}

	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, spacetype, uap->path, ctx);
	if ((error = namei(&nd))) {
		return (error);
	}
	vp = nd.ni_vp;
	nameidone(&nd);

	auio = uio_createwithbuffer(1, uap->position, spacetype, UIO_WRITE,
	                            &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, uap->value, uap->size);

	error = vn_setxattr(vp, attrname, auio, uap->options, ctx);
#if CONFIG_FSE
	if (error == 0) {
		add_fsevent(FSE_XATTR_MODIFIED, ctx,
		    FSE_ARG_VNODE, vp,
		    FSE_ARG_DONE);
	}
#endif
	vnode_put(vp);
	*retval = 0;
	return (error);
}

/*
 * Set the data of an extended attribute.
 */
int
fsetxattr(proc_t p, struct fsetxattr_args *uap, int *retval)
{
	vnode_t vp;
	char attrname[XATTR_MAXNAMELEN+1];
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t namelen;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];
	vfs_context_t ctx = vfs_context_current();

	if (uap->options & (XATTR_NOFOLLOW | XATTR_NOSECURITY | XATTR_NODEFAULT))
		return (EINVAL);

	if ((error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen) != 0)) {
		return (error);
	}
	if (xattr_protected(attrname))
		return(EPERM);
	if (uap->size != 0 && uap->value == 0) {
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

	error = vn_setxattr(vp, attrname, auio, uap->options, vfs_context_current());
#if CONFIG_FSE
	if (error == 0) {
		add_fsevent(FSE_XATTR_MODIFIED, ctx,
		    FSE_ARG_VNODE, vp,
		    FSE_ARG_DONE);
	}
#endif
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
removexattr(proc_t p, struct removexattr_args *uap, int *retval)
{
	vnode_t vp;
	struct nameidata nd;
	char attrname[XATTR_MAXNAMELEN+1];
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	vfs_context_t ctx = vfs_context_current();
	size_t namelen;
	u_long nameiflags;
	int error;

	if (uap->options & (XATTR_NOSECURITY | XATTR_NODEFAULT))
		return (EINVAL);

	error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen);
	if (error != 0) {
		return (error);
	}
	if (xattr_protected(attrname))
		return(EPERM);
	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, nameiflags, spacetype, uap->path, ctx);
	if ((error = namei(&nd))) {
		return (error);
	}
	vp = nd.ni_vp;
	nameidone(&nd);

	error = vn_removexattr(vp, attrname, uap->options, ctx);
#if CONFIG_FSE
	if (error == 0) {
		add_fsevent(FSE_XATTR_REMOVED, ctx,
		    FSE_ARG_VNODE, vp,
		    FSE_ARG_DONE);
	}
#endif
	vnode_put(vp);
	*retval = 0;
	return (error);
}

/*
 * Remove an extended attribute.
 */
#warning "code duplication"
int
fremovexattr(__unused proc_t p, struct fremovexattr_args *uap, int *retval)
{
	vnode_t vp;
	char attrname[XATTR_MAXNAMELEN+1];
	size_t namelen;
	int error;
	vfs_context_t ctx = vfs_context_current();

	if (uap->options & (XATTR_NOFOLLOW | XATTR_NOSECURITY | XATTR_NODEFAULT))
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

	error = vn_removexattr(vp, attrname, uap->options, vfs_context_current());
#if CONFIG_FSE
	if (error == 0) {
		add_fsevent(FSE_XATTR_REMOVED, ctx,
		    FSE_ARG_VNODE, vp,
		    FSE_ARG_DONE);
	}
#endif
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
listxattr(proc_t p, struct listxattr_args *uap, user_ssize_t *retval)
{
	vnode_t vp;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	u_long nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOSECURITY | XATTR_NODEFAULT))
		return (EINVAL);

	nameiflags = ((uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW) | NOTRIGGER;
	NDINIT(&nd, LOOKUP, nameiflags, spacetype, uap->path, ctx);
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

	error = vn_listxattr(vp, auio, &attrsize, uap->options, ctx);

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
flistxattr(proc_t p, struct flistxattr_args *uap, user_ssize_t *retval)
{
	vnode_t vp;
	uio_t auio = NULL;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOFOLLOW | XATTR_NOSECURITY | XATTR_NODEFAULT))
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

	error = vn_listxattr(vp, auio, &attrsize, uap->options, vfs_context_current());

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
 *
 * Returns:	0			Success
 *		EFAULT
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
		strlcpy(&sfs.f_fstypename[0], &sfsp->f_fstypename[0], MFSNAMELEN);
		strlcpy(&sfs.f_mntonname[0], &sfsp->f_mntonname[0], MNAMELEN);
		strlcpy(&sfs.f_mntfromname[0], &sfsp->f_mntfromname[0], MNAMELEN);

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
			 && (sfsp->f_blocks != 0xffffffffffffffffULL)
			 && (sfsp->f_bfree != 0xffffffffffffffffULL)
			 && (sfsp->f_bavail != 0xffffffffffffffffULL)) {
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
		strlcpy(&sfs.f_fstypename[0], &sfsp->f_fstypename[0], MFSNAMELEN);
		strlcpy(&sfs.f_mntonname[0], &sfsp->f_mntonname[0], MNAMELEN);
		strlcpy(&sfs.f_mntfromname[0], &sfsp->f_mntfromname[0], MNAMELEN);

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
#ifndef _POSIX_C_SOURCE
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

/*
 * copy stat64 structure into user_stat64 structure.
 */
void munge_stat64(struct stat64 *sbp, struct user_stat64 *usbp)
{
        bzero(usbp, sizeof(struct user_stat));

	usbp->st_dev = sbp->st_dev;
	usbp->st_ino = sbp->st_ino;
	usbp->st_mode = sbp->st_mode;
	usbp->st_nlink = sbp->st_nlink;
	usbp->st_uid = sbp->st_uid;
	usbp->st_gid = sbp->st_gid;
	usbp->st_rdev = sbp->st_rdev;
#ifndef _POSIX_C_SOURCE
	usbp->st_atimespec.tv_sec = sbp->st_atimespec.tv_sec;
	usbp->st_atimespec.tv_nsec = sbp->st_atimespec.tv_nsec;
	usbp->st_mtimespec.tv_sec = sbp->st_mtimespec.tv_sec;
	usbp->st_mtimespec.tv_nsec = sbp->st_mtimespec.tv_nsec;
	usbp->st_ctimespec.tv_sec = sbp->st_ctimespec.tv_sec;
	usbp->st_ctimespec.tv_nsec = sbp->st_ctimespec.tv_nsec;
	usbp->st_birthtimespec.tv_sec = sbp->st_birthtimespec.tv_sec;
	usbp->st_birthtimespec.tv_nsec = sbp->st_birthtimespec.tv_nsec;
#else
	usbp->st_atime = sbp->st_atime;
	usbp->st_atimensec = sbp->st_atimensec;
	usbp->st_mtime = sbp->st_mtime;
	usbp->st_mtimensec = sbp->st_mtimensec;
	usbp->st_ctime = sbp->st_ctime;
	usbp->st_ctimensec = sbp->st_ctimensec;
	usbp->st_birthtime = sbp->st_birthtime;
	usbp->st_birthtimensec = sbp->st_birthtimensec;
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
