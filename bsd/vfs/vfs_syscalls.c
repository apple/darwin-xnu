/*
 * Copyright (c) 1995-2014 Apple Inc. All rights reserved.
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
#include <sys/imgsrc.h>
#include <sys/sysproto.h>
#include <sys/xattr.h>
#include <sys/fcntl.h>
#include <sys/fsctl.h>
#include <sys/ubc_internal.h>
#include <sys/disk.h>
#include <machine/cons.h>
#include <machine/limits.h>
#include <miscfs/specfs/specdev.h>

#include <security/audit/audit.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/task.h>

#include <vm/vm_pageout.h>

#include <libkern/OSAtomic.h>
#include <pexpert/pexpert.h>

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
static void sync_thread(void *, __unused wait_result_t);
static int sync_async(int);
static int munge_statfs(struct mount *mp, struct vfsstatfs *sfsp, 
			user_addr_t bufp, int *sizep, boolean_t is_64_bit, 
						boolean_t partial_copy);
static int statfs64_common(struct mount *mp, struct vfsstatfs *sfsp,
			user_addr_t bufp);
static int fsync_common(proc_t p, struct fsync_args *uap, int flags);
static int mount_common(char *fstypename, vnode_t pvp, vnode_t vp,
                        struct componentname *cnp, user_addr_t fsmountargs,
                        int flags, uint32_t internal_flags, char *labelstr, boolean_t kernelmount,
                        vfs_context_t ctx);
void vfs_notify_mount(vnode_t pdvp);

int prepare_coveredvp(vnode_t vp, vfs_context_t ctx, struct componentname *cnp, const char *fsname, boolean_t skip_auth);

struct fd_vn_data * fg_vn_data_alloc(void);

static int rmdirat_internal(vfs_context_t, int, user_addr_t, enum uio_seg);

static int fsgetpath_internal(vfs_context_t, int, uint64_t, vm_size_t, caddr_t, int *);

#ifdef CONFIG_IMGSRC_ACCESS
static int authorize_devpath_and_update_mntfromname(mount_t mp, user_addr_t devpath, vnode_t *devvpp, vfs_context_t ctx);
static int place_mount_and_checkdirs(mount_t mp, vnode_t vp, vfs_context_t ctx);
static void undo_place_on_covered_vp(mount_t mp, vnode_t vp);
static int mount_begin_update(mount_t mp, vfs_context_t ctx, int flags);
static void mount_end_update(mount_t mp);
static int relocate_imageboot_source(vnode_t pvp, vnode_t vp, struct componentname *cnp, const char *fsname, vfs_context_t ctx, boolean_t is64bit, user_addr_t fsmountargs, boolean_t by_index);
#endif /* CONFIG_IMGSRC_ACCESS */

int (*union_dircheckp)(struct vnode **, struct fileproc *, vfs_context_t);

__private_extern__
int sync_internal(void);

__private_extern__
int unlink1(vfs_context_t, struct nameidata *, int);

extern lck_grp_t *fd_vn_lck_grp;
extern lck_grp_attr_t *fd_vn_lck_grp_attr;
extern lck_attr_t *fd_vn_lck_attr;

/*
 * incremented each time a mount or unmount operation occurs
 * used to invalidate the cached value of the rootvp in the
 * mount structure utilized by cache_lookup_path
 */
uint32_t mount_generation = 0;

/* counts number of mount and unmount operations */
unsigned int vfs_nummntops=0;

extern const struct fileops vnops;
#if CONFIG_APPLEDOUBLE
extern errno_t rmdir_remove_orphaned_appleDouble(vnode_t, vfs_context_t, int *); 
#endif /* CONFIG_APPLEDOUBLE */

typedef uint32_t vfs_rename_flags_t;
#if CONFIG_SECLUDED_RENAME
enum {
	VFS_SECLUDE_RENAME		= 0x00000001
};
#endif

/*
 * Virtual File System System Calls
 */

#if NFSCLIENT || DEVFS
/*
 * Private in-kernel mounting spi (NFS only, not exported)
 */
 __private_extern__
boolean_t
vfs_iskernelmount(mount_t mp)
{
	return ((mp->mnt_kern_flag & MNTK_KERNEL_MOUNT) ? TRUE : FALSE);
}

 __private_extern__
int
kernel_mount(char *fstype, vnode_t pvp, vnode_t vp, const char *path,
             void *data, __unused size_t datalen, int syscall_flags, __unused uint32_t kern_flags, vfs_context_t ctx)
{
	struct nameidata nd;
	boolean_t did_namei;
	int error;

	NDINIT(&nd, LOOKUP, OP_MOUNT, FOLLOW | AUDITVNPATH1 | WANTPARENT, 
	       UIO_SYSSPACE, CAST_USER_ADDR_T(path), ctx);

	/*
	 * Get the vnode to be covered if it's not supplied
	 */
	if (vp == NULLVP) {
		error = namei(&nd);
		if (error)
			return (error);
		vp = nd.ni_vp;
		pvp = nd.ni_dvp;
		did_namei = TRUE;
	} else {
		char *pnbuf = CAST_DOWN(char *, path);

		nd.ni_cnd.cn_pnbuf = pnbuf;
		nd.ni_cnd.cn_pnlen = strlen(pnbuf) + 1;
		did_namei = FALSE;
	}

	error = mount_common(fstype, pvp, vp, &nd.ni_cnd, CAST_USER_ADDR_T(data),
	                     syscall_flags, kern_flags, NULL, TRUE, ctx);

	if (did_namei) {
		vnode_put(vp);
		vnode_put(pvp);
		nameidone(&nd);
	}

	return (error);
}
#endif /* NFSCLIENT || DEVFS */

/*
 * Mount a file system.
 */
/* ARGSUSED */
int
mount(proc_t p, struct mount_args *uap, __unused int32_t *retval)
{
	struct __mac_mount_args muap;

	muap.type = uap->type;
	muap.path = uap->path;
	muap.flags = uap->flags;
	muap.data = uap->data;
	muap.mac_p = USER_ADDR_NULL;
	return (__mac_mount(p, &muap, retval));
}

void
vfs_notify_mount(vnode_t pdvp) 
{
	vfs_event_signal(NULL, VQ_MOUNT, (intptr_t)NULL);
	lock_vnode_and_post(pdvp, NOTE_WRITE);
}

/*
 * __mac_mount:
 *	Mount a file system taking into account MAC label behavior.
 *	See mount(2) man page for more information
 *
 * Parameters:    p                        Process requesting the mount
 *                uap                      User argument descriptor (see below)
 *                retval                   (ignored)  
 *
 * Indirect:      uap->type                Filesystem type
 *                uap->path                Path to mount
 *                uap->data                Mount arguments  
 *                uap->mac_p               MAC info              
 *                uap->flags               Mount flags
 *                
 *
 * Returns:        0                       Success
 *                !0                       Not success
 */
boolean_t root_fs_upgrade_try = FALSE;

int
__mac_mount(struct proc *p, register struct __mac_mount_args *uap, __unused int32_t *retval)
{
	vnode_t pvp = NULL;
   	vnode_t vp = NULL;
	int need_nameidone = 0;
	vfs_context_t ctx = vfs_context_current();
	char fstypename[MFSNAMELEN];
	struct nameidata nd;
	size_t dummy=0;
	char *labelstr = NULL;
	int flags = uap->flags;
	int error;
#if CONFIG_IMGSRC_ACCESS || CONFIG_MACF 
	boolean_t is_64bit = IS_64BIT_PROCESS(p);
#else
#pragma unused(p)
#endif
	/*
	 * Get the fs type name from user space
	 */
	error = copyinstr(uap->type, fstypename, MFSNAMELEN, &dummy);
	if (error)
		return (error);

	/*
	 * Get the vnode to be covered
	 */
	NDINIT(&nd, LOOKUP, OP_MOUNT, FOLLOW | AUDITVNPATH1 | WANTPARENT, 
	       UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error) {
		goto out;
	}
	need_nameidone = 1;
	vp = nd.ni_vp;
	pvp = nd.ni_dvp;
	
#ifdef CONFIG_IMGSRC_ACCESS
	/* Mounting image source cannot be batched with other operations */
	if (flags == MNT_IMGSRC_BY_INDEX) {
		error = relocate_imageboot_source(pvp, vp, &nd.ni_cnd, fstypename,
		                                  ctx, is_64bit, uap->data, (flags == MNT_IMGSRC_BY_INDEX));
		goto out;
	}
#endif /* CONFIG_IMGSRC_ACCESS */

#if CONFIG_MACF
	/*
	 * Get the label string (if any) from user space
	 */
	if (uap->mac_p != USER_ADDR_NULL) {
		struct user_mac mac;
		size_t ulen = 0;

		if (is_64bit) {
			struct user64_mac mac64;
			error = copyin(uap->mac_p, &mac64, sizeof(mac64));
			mac.m_buflen = mac64.m_buflen;
			mac.m_string = mac64.m_string;
		} else {
			struct user32_mac mac32;
			error = copyin(uap->mac_p, &mac32, sizeof(mac32));
			mac.m_buflen = mac32.m_buflen;
			mac.m_string = mac32.m_string;
		}
		if (error)
			goto out;
		if ((mac.m_buflen > MAC_MAX_LABEL_BUF_LEN) ||
		    (mac.m_buflen < 2)) {
			error = EINVAL;
			goto out;
		}
		MALLOC(labelstr, char *, mac.m_buflen, M_MACTEMP, M_WAITOK);
		error = copyinstr(mac.m_string, labelstr, mac.m_buflen, &ulen);
		if (error) {
			goto out;
		}
		AUDIT_ARG(mac_string, labelstr);
	}
#endif /* CONFIG_MACF */

	AUDIT_ARG(fflags, flags);

	if ((vp->v_flag & VROOT) &&
			(vp->v_mount->mnt_flag & MNT_ROOTFS)) {
		if (!(flags & MNT_UNION)) {
			flags |= MNT_UPDATE;
		}
		else {
			/* 
			 * For a union mount on '/', treat it as fresh
			 * mount instead of update. 
			 * Otherwise, union mouting on '/' used to panic the 
			 * system before, since mnt_vnodecovered was found to 
			 * be NULL for '/' which is required for unionlookup 
			 * after it gets ENOENT on union mount.
			 */
			flags = (flags & ~(MNT_UPDATE));
		}

#ifdef SECURE_KERNEL
		if ((flags & MNT_RDONLY) == 0) {
			/* Release kernels are not allowed to mount "/" as rw */
			error = EPERM;
			goto out;	
		}
#endif
		/*
		 * See 7392553 for more details on why this check exists.
		 * Suffice to say: If this check is ON and something tries
		 * to mount the rootFS RW, we'll turn off the codesign
		 * bitmap optimization.	 
		 */	   
#if CHECK_CS_VALIDATION_BITMAP
		if ((flags & MNT_RDONLY) == 0 ) {
			root_fs_upgrade_try = TRUE;
		}
#endif
	}

	error = mount_common(fstypename, pvp, vp, &nd.ni_cnd, uap->data, flags, 0,
	                     labelstr, FALSE, ctx);

out:

#if CONFIG_MACF
	if (labelstr)
		FREE(labelstr, M_MACTEMP);
#endif /* CONFIG_MACF */

	if (vp) {
		vnode_put(vp);
	}
	if (pvp) {
		vnode_put(pvp);
	}
	if (need_nameidone) {
		nameidone(&nd);
	}

	return (error);
}

/*
 * common mount implementation (final stage of mounting)
 
 * Arguments:
 *  fstypename	file system type (ie it's vfs name)
 *  pvp		parent of covered vnode
 *  vp		covered vnode
 *  cnp		component name (ie path) of covered vnode
 *  flags	generic mount flags
 *  fsmountargs	file system specific data
 *  labelstr	optional MAC label
 *  kernelmount	TRUE for mounts initiated from inside the kernel
 *  ctx		caller's context
 */
static int
mount_common(char *fstypename, vnode_t pvp, vnode_t vp,
             struct componentname *cnp, user_addr_t fsmountargs, int flags, uint32_t internal_flags,
             char *labelstr, boolean_t kernelmount, vfs_context_t ctx)
{
#if !CONFIG_MACF
#pragma unused(labelstr)
#endif
	struct vnode *devvp = NULLVP;
	struct vnode *device_vnode = NULLVP;
#if CONFIG_MACF
	struct vnode *rvp;
#endif
	struct mount *mp;
	struct vfstable *vfsp = (struct vfstable *)0;
	struct proc *p = vfs_context_proc(ctx);
	int error, flag = 0;
	user_addr_t devpath = USER_ADDR_NULL;
	int ronly = 0;
	int mntalloc = 0;
	boolean_t vfsp_ref = FALSE;
	boolean_t is_rwlock_locked = FALSE;
	boolean_t did_rele = FALSE;
	boolean_t have_usecount = FALSE;

	/*
	 * Process an update for an existing mount
	 */
	if (flags & MNT_UPDATE) {
		if ((vp->v_flag & VROOT) == 0) {
			error = EINVAL;
			goto out1;
		}
		mp = vp->v_mount;

		/* unmount in progress return error */
		mount_lock_spin(mp);
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
		if ((flags & MNT_RELOAD) &&
		    ((mp->mnt_flag & MNT_RDONLY) == 0)) {
			error = ENOTSUP;
			goto out1;
		}

		/*
		 * If content protection is enabled, update mounts are not
		 * allowed to turn it off.
		 */
		if ((mp->mnt_flag & MNT_CPROTECT) && 
			   ((flags & MNT_CPROTECT) == 0)) {
			error = EINVAL;
			goto out1;
		}

#ifdef CONFIG_IMGSRC_ACCESS 
		/* Can't downgrade the backer of the root FS */
		if ((mp->mnt_kern_flag & MNTK_BACKS_ROOT) &&
			(!vfs_isrdonly(mp)) && (flags & MNT_RDONLY)) {
			error = ENOTSUP;
			goto out1;
		}
#endif /* CONFIG_IMGSRC_ACCESS */

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
			goto out1;
		}
#endif
		/*
		 * For non-root users, silently enforce MNT_NOSUID and MNT_NODEV,
		 * and MNT_NOEXEC if mount point is already MNT_NOEXEC.
		 */
		if ((!kernelmount) && suser(vfs_context_ucred(ctx), NULL)) {
			flags |= MNT_NOSUID | MNT_NODEV;
			if (mp->mnt_flag & MNT_NOEXEC)
				flags |= MNT_NOEXEC;
		}
		flag = mp->mnt_flag;



		mp->mnt_flag |= flags & (MNT_RELOAD | MNT_FORCE | MNT_UPDATE);

		vfsp = mp->mnt_vtable;
		goto update;
	}
	/*
	 * For non-root users, silently enforce MNT_NOSUID and MNT_NODEV, and
	 * MNT_NOEXEC if mount point is already MNT_NOEXEC.
	 */
	if ((!kernelmount) && suser(vfs_context_ucred(ctx), NULL)) {
		flags |= MNT_NOSUID | MNT_NODEV;
		if (vp->v_mount->mnt_flag & MNT_NOEXEC)
			flags |= MNT_NOEXEC;
	}

	/* XXXAUDIT: Should we capture the type on the error path as well? */
	AUDIT_ARG(text, fstypename);
	mount_list_lock();
	for (vfsp = vfsconf; vfsp; vfsp = vfsp->vfc_next)
		if (!strncmp(vfsp->vfc_name, fstypename, MFSNAMELEN)) {
			vfsp->vfc_refcount++;
			vfsp_ref = TRUE;
			break;
		}
	mount_list_unlock();
	if (vfsp == NULL) {
		error = ENODEV;
		goto out1;
	}

	/*
	 * VFC_VFSLOCALARGS is not currently supported for kernel mounts
	 */
	if (kernelmount && (vfsp->vfc_vfsflags & VFC_VFSLOCALARGS)) {
		error = EINVAL;  /* unsupported request */
		goto out1;
	}

	error = prepare_coveredvp(vp, ctx, cnp, fstypename, ((internal_flags & KERNEL_MOUNT_NOAUTH) != 0));
	if (error != 0) {
		goto out1;
	}

	/*
	 * Allocate and initialize the filesystem (mount_t)
	 */
	MALLOC_ZONE(mp, struct mount *, (u_int32_t)sizeof(struct mount),
		M_MOUNT, M_WAITOK);
	bzero((char *)mp, (u_int32_t)sizeof(struct mount));
	mntalloc = 1;

	/* Initialize the default IO constraints */
	mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
	mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;
	mp->mnt_maxsegreadsize = mp->mnt_maxreadcnt;
	mp->mnt_maxsegwritesize = mp->mnt_maxwritecnt;
	mp->mnt_devblocksize = DEV_BSIZE;
	mp->mnt_alignmentmask = PAGE_MASK;
	mp->mnt_ioqueue_depth = MNT_DEFAULT_IOQUEUE_DEPTH;
	mp->mnt_ioscale = 1;
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
	//mp->mnt_stat.f_type = vfsp->vfc_typenum;
	mp->mnt_flag |= vfsp->vfc_flags & MNT_VISFLAGMASK;
	strlcpy(mp->mnt_vfsstat.f_fstypename, vfsp->vfc_name, MFSTYPENAMELEN);
	strlcpy(mp->mnt_vfsstat.f_mntonname, cnp->cn_pnbuf, MAXPATHLEN);
	mp->mnt_vnodecovered = vp;
	mp->mnt_vfsstat.f_owner = kauth_cred_getuid(vfs_context_ucred(ctx));
	mp->mnt_throttle_mask = LOWPRI_MAX_NUM_DEV - 1;
	mp->mnt_devbsdunit = 0;

	/* XXX 3762912 hack to support HFS filesystem 'owner' - filesystem may update later */
	vfs_setowner(mp, KAUTH_UID_NONE, KAUTH_GID_NONE);

#if NFSCLIENT || DEVFS
	if (kernelmount)
		mp->mnt_kern_flag |= MNTK_KERNEL_MOUNT;
	if ((internal_flags & KERNEL_MOUNT_PERMIT_UNMOUNT) != 0)
		mp->mnt_kern_flag |= MNTK_PERMIT_UNMOUNT;
#endif /* NFSCLIENT || DEVFS */

update:
	/*
	 * Set the mount level flags.
	 */
	if (flags & MNT_RDONLY)
		mp->mnt_flag |= MNT_RDONLY;
	else if (mp->mnt_flag & MNT_RDONLY) {
		// disallow read/write upgrades of file systems that
		// had the TYPENAME_OVERRIDE feature set.
		if (mp->mnt_kern_flag & MNTK_TYPENAME_OVERRIDE) {
			error = EPERM;
			goto out1;
		}
		mp->mnt_kern_flag |= MNTK_WANTRDWR;
	}
	mp->mnt_flag &= ~(MNT_NOSUID | MNT_NOEXEC | MNT_NODEV |
			  MNT_SYNCHRONOUS | MNT_UNION | MNT_ASYNC |
			  MNT_UNKNOWNPERMISSIONS | MNT_DONTBROWSE |
			  MNT_AUTOMOUNTED | MNT_DEFWRITE | MNT_NOATIME |
			  MNT_QUARANTINE | MNT_CPROTECT);
	mp->mnt_flag |= flags & (MNT_NOSUID | MNT_NOEXEC | MNT_NODEV |
				 MNT_SYNCHRONOUS | MNT_UNION | MNT_ASYNC |
				 MNT_UNKNOWNPERMISSIONS | MNT_DONTBROWSE |
				 MNT_AUTOMOUNTED | MNT_DEFWRITE | MNT_NOATIME |
				 MNT_QUARANTINE | MNT_CPROTECT);

#if CONFIG_MACF
	if (flags & MNT_MULTILABEL) {
		if (vfsp->vfc_vfsflags & VFC_VFSNOMACLABEL) {
			error = EINVAL;
			goto out1;
		}
		mp->mnt_flag |= MNT_MULTILABEL;
	}
#endif
	/*
	 * Process device path for local file systems if requested
	 */
	if (vfsp->vfc_vfsflags & VFC_VFSLOCALARGS) {
		if (vfs_context_is64bit(ctx)) {
			if ( (error = copyin(fsmountargs, (caddr_t)&devpath, sizeof(devpath))) )
				goto out1;	
			fsmountargs += sizeof(devpath);
		} else {
			user32_addr_t tmp;
			if ( (error = copyin(fsmountargs, (caddr_t)&tmp, sizeof(tmp))) )
				goto out1;	
			/* munge into LP64 addr */
			devpath = CAST_USER_ADDR_T(tmp);
			fsmountargs += sizeof(tmp);
		}

		/* Lookup device and authorize access to it */
		if ((devpath)) {
			struct nameidata nd;

			NDINIT(&nd, LOOKUP, OP_MOUNT, FOLLOW, UIO_USERSPACE, devpath, ctx);
			if ( (error = namei(&nd)) )
				goto out1;

			strncpy(mp->mnt_vfsstat.f_mntfromname, nd.ni_cnd.cn_pnbuf, MAXPATHLEN);
			devvp = nd.ni_vp;

			nameidone(&nd);

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
				mode_t accessmode = KAUTH_VNODE_READ_DATA;

				if ((mp->mnt_flag & MNT_RDONLY) == 0)
					accessmode |= KAUTH_VNODE_WRITE_DATA;
				if ((error = vnode_authorize(devvp, NULL, accessmode, ctx)) != 0)
					goto out2;
			}
		}
		/* On first mount, preflight and open device */
		if (devpath && ((flags & MNT_UPDATE) == 0)) {
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

		} else if ((mp->mnt_flag & MNT_RDONLY) &&
		           (mp->mnt_kern_flag & MNTK_WANTRDWR) &&
		           (device_vnode = mp->mnt_devvp)) {
			dev_t dev;
			int maj;
			/*
			 * If upgrade to read-write by non-root, then verify
			 * that user has necessary permissions on the device.
			 */
			vnode_getalways(device_vnode);

			if (suser(vfs_context_ucred(ctx), NULL) &&
			    (error = vnode_authorize(device_vnode, NULL, 
			     KAUTH_VNODE_READ_DATA | KAUTH_VNODE_WRITE_DATA,
			     ctx)) != 0) {
				vnode_put(device_vnode);
				goto out2;
			}

			/* Tell the device that we're upgrading */
			dev = (dev_t)device_vnode->v_rdev;
			maj = major(dev);

			if ((u_int)maj >= (u_int)nblkdev)
				panic("Volume mounted on a device with invalid major number.");

			error = bdevsw[maj].d_open(dev, FREAD | FWRITE, S_IFBLK, p);
			vnode_put(device_vnode);
			device_vnode = NULLVP;
			if (error != 0) {
				goto out2;
			}
		}
	}
#if CONFIG_MACF
	if ((flags & MNT_UPDATE) == 0) {
		mac_mount_label_init(mp);
		mac_mount_label_associate(ctx, mp);
	}
	if (labelstr) {
		if ((flags & MNT_UPDATE) != 0) {
			error = mac_mount_check_label_update(ctx, mp);
			if (error != 0)
				goto out3;
		}
	}
#endif
	/*
	 * Mount the filesystem.
	 */
	error = VFS_MOUNT(mp, device_vnode, fsmountargs, ctx);

	if (flags & MNT_UPDATE) {
		if (mp->mnt_kern_flag & MNTK_WANTRDWR)
			mp->mnt_flag &= ~MNT_RDONLY;
		mp->mnt_flag &=~
		    (MNT_UPDATE | MNT_RELOAD | MNT_FORCE);
		mp->mnt_kern_flag &=~ MNTK_WANTRDWR;
		if (error)
			mp->mnt_flag = flag;  /* restore flag value */
		vfs_event_signal(NULL, VQ_UPDATE, (intptr_t)NULL);
		lck_rw_done(&mp->mnt_rwlock);
		is_rwlock_locked = FALSE;
		if (!error)
			enablequotas(mp, ctx);
		goto exit;
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
			error = vnode_label(mp, NULL, rvp, NULL, 0, ctx);
                        /*
			 * drop reference provided by VFS_ROOT
			 */
			vnode_put(rvp);

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

		error = vnode_ref(vp);
		if (error != 0) {
			goto out4;
		}

		have_usecount = TRUE;

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

		if (mount_list_add(mp) != 0) {
			/*
			 * The system is shutting down trying to umount
			 * everything, so fail with a plausible errno.
			 */
			error = EBUSY;
			goto out4;
		}
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
		OSAddAtomic(1, &vfs_nummntops);
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
		vfs_notify_mount(pvp);
	} else {
		/* If we fail a fresh mount, there should be no vnodes left hooked into the mountpoint. */
		if (mp->mnt_vnodelist.tqh_first != NULL) {
			panic("mount_common(): mount of %s filesystem failed with %d, but vnode list is not empty.", 
					mp->mnt_vtable->vfc_name, error);
		}

		vnode_lock_spin(vp);
		CLR(vp->v_flag, VMOUNT);
		vnode_unlock(vp);
		mount_list_lock();
		mp->mnt_vtable->vfc_refcount--;
		mount_list_unlock();

		if (device_vnode ) {
			vnode_rele(device_vnode);
			VNOP_CLOSE(device_vnode, ronly ? FREAD : FREAD|FWRITE, ctx);
		}
		lck_rw_done(&mp->mnt_rwlock);
		is_rwlock_locked = FALSE;
		
		/*
		 * if we get here, we have a mount structure that needs to be freed,
		 * but since the coveredvp hasn't yet been updated to point at it,
		 * no need to worry about other threads holding a crossref on this mp
		 * so it's ok to just free it
		 */
		mount_lock_destroy(mp);
#if CONFIG_MACF
		mac_mount_label_destroy(mp);
#endif
		FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
	}
exit:
	/*
	 * drop I/O count on the device vp if there was one
	 */
	if (devpath && devvp)
	        vnode_put(devvp);

	return(error);

/* Error condition exits */
out4:
	(void)VFS_UNMOUNT(mp, MNT_FORCE, ctx);
	
	/* 
	 * If the mount has been placed on the covered vp,
	 * it may have been discovered by now, so we have
	 * to treat this just like an unmount
	 */
	mount_lock_spin(mp);
	mp->mnt_lflag |= MNT_LDEAD;
	mount_unlock(mp);

	if (device_vnode != NULLVP) {
		vnode_rele(device_vnode);
		VNOP_CLOSE(device_vnode, mp->mnt_flag & MNT_RDONLY ? FREAD : FREAD|FWRITE,
                       ctx);
		did_rele = TRUE;
	}

	vnode_lock_spin(vp);

	mp->mnt_crossref++;
	vp->v_mountedhere = (mount_t) 0;

	vnode_unlock(vp);

	if (have_usecount) {
		vnode_rele(vp);
	}
out3:
	if (devpath && ((flags & MNT_UPDATE) == 0) && (!did_rele))
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
		if (mp->mnt_crossref)
			mount_dropcrossref(mp, vp, 0);
		else {
			mount_lock_destroy(mp);
#if CONFIG_MACF
			mac_mount_label_destroy(mp);
#endif
			FREE_ZONE((caddr_t)mp, sizeof (struct mount), M_MOUNT);
		}
	}
	if (vfsp_ref) {
		mount_list_lock();
		vfsp->vfc_refcount--;
		mount_list_unlock();
	}

	return(error);
}

/* 
 * Flush in-core data, check for competing mount attempts,
 * and set VMOUNT
 */
int
prepare_coveredvp(vnode_t vp, vfs_context_t ctx, struct componentname *cnp, const char *fsname, boolean_t skip_auth)
{
#if !CONFIG_MACF
#pragma unused(cnp,fsname)
#endif
	struct vnode_attr va;
	int error;

	if (!skip_auth) {
		/*
		 * If the user is not root, ensure that they own the directory
		 * onto which we are attempting to mount.
		 */
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_uid);
		if ((error = vnode_getattr(vp, &va, ctx)) ||
				(va.va_uid != kauth_cred_getuid(vfs_context_ucred(ctx)) &&
				 (!vfs_context_issuser(ctx)))) { 
			error = EPERM;
			goto out;
		}
	}

	if ( (error = VNOP_FSYNC(vp, MNT_WAIT, ctx)) )
		goto out;

	if ( (error = buf_invalidateblks(vp, BUF_WRITE_DATA, 0, 0)) )
		goto out;

	if (vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

	if (ISSET(vp->v_flag, VMOUNT) && (vp->v_mountedhere != NULL)) {
		error = EBUSY;
		goto out;
	}

#if CONFIG_MACF
	error = mac_mount_check_mount(ctx, vp,
	    cnp, fsname);
	if (error != 0)
		goto out;
#endif

	vnode_lock_spin(vp);
	SET(vp->v_flag, VMOUNT);
	vnode_unlock(vp);

out:
	return error;
}

#if CONFIG_IMGSRC_ACCESS

#if DEBUG
#define IMGSRC_DEBUG(args...) printf(args)
#else
#define IMGSRC_DEBUG(args...) do { } while(0)
#endif 

static int
authorize_devpath_and_update_mntfromname(mount_t mp, user_addr_t devpath, vnode_t *devvpp, vfs_context_t ctx)
{
	struct nameidata nd;
	vnode_t vp, realdevvp;
	mode_t accessmode;
	int error;

	NDINIT(&nd, LOOKUP, OP_LOOKUP, FOLLOW, UIO_USERSPACE, devpath, ctx);
	if ( (error = namei(&nd)) ) {
		IMGSRC_DEBUG("namei() failed with %d\n", error);
		return error;
	}

	vp = nd.ni_vp;

	if (!vnode_isblk(vp)) {
		IMGSRC_DEBUG("Not block device.\n");
		error = ENOTBLK;
		goto out;
	}

	realdevvp = mp->mnt_devvp;
	if (realdevvp == NULLVP) {
		IMGSRC_DEBUG("No device backs the mount.\n");
		error = ENXIO;
		goto out;
	}

	error = vnode_getwithref(realdevvp);
	if (error != 0) {
		IMGSRC_DEBUG("Coudn't get iocount on device.\n");
		goto out;
	}

	if (vnode_specrdev(vp) != vnode_specrdev(realdevvp)) {
		IMGSRC_DEBUG("Wrong dev_t.\n");
		error = ENXIO;
		goto out1;
	}

	strlcpy(mp->mnt_vfsstat.f_mntfromname, nd.ni_cnd.cn_pnbuf, MAXPATHLEN);

	/*
	 * If mount by non-root, then verify that user has necessary
	 * permissions on the device.
	 */
	if (!vfs_context_issuser(ctx)) {
		accessmode = KAUTH_VNODE_READ_DATA;
		if ((mp->mnt_flag & MNT_RDONLY) == 0)
			accessmode |= KAUTH_VNODE_WRITE_DATA;
		if ((error = vnode_authorize(vp, NULL, accessmode, ctx)) != 0) {
			IMGSRC_DEBUG("Access denied.\n");
			goto out1;
		}
	}

	*devvpp = vp;

out1:
	vnode_put(realdevvp);
out:
	nameidone(&nd);
	if (error) {
		vnode_put(vp);
	}

	return error;
}

/*
 * Clear VMOUNT, set v_mountedhere, and mnt_vnodecovered, ref the vnode,
 * and call checkdirs()
 */
static int
place_mount_and_checkdirs(mount_t mp, vnode_t vp, vfs_context_t ctx)
{
	int error;

	mp->mnt_vnodecovered = vp; /* XXX This is normally only set at init-time ... */

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

	error = vnode_ref(vp);
	if (error != 0) {
		goto out;
	}

	error = checkdirs(vp, ctx);
	if (error != 0)  {
		/* Unmount the filesystem as cdir/rdirs cannot be updated */
		vnode_rele(vp);
		goto out;
	}

out:
	if (error != 0) {
		mp->mnt_vnodecovered = NULLVP;
	}
	return error;
}

static void
undo_place_on_covered_vp(mount_t mp, vnode_t vp)
{
	vnode_rele(vp);
	vnode_lock_spin(vp);
	vp->v_mountedhere = (mount_t)NULL;
	vnode_unlock(vp);

	mp->mnt_vnodecovered = NULLVP;
}

static int
mount_begin_update(mount_t mp, vfs_context_t ctx, int flags)
{
	int error;

	/* unmount in progress return error */
	mount_lock_spin(mp);
	if (mp->mnt_lflag & MNT_LUNMOUNT) {
		mount_unlock(mp);
		return EBUSY;
	}
	mount_unlock(mp);
	lck_rw_lock_exclusive(&mp->mnt_rwlock);

	/*
	 * We only allow the filesystem to be reloaded if it
	 * is currently mounted read-only.
	 */
	if ((flags & MNT_RELOAD) &&
			((mp->mnt_flag & MNT_RDONLY) == 0)) {
		error = ENOTSUP;
		goto out;
	}

	/*
	 * Only root, or the user that did the original mount is
	 * permitted to update it.
	 */
	if (mp->mnt_vfsstat.f_owner != kauth_cred_getuid(vfs_context_ucred(ctx)) &&
			(!vfs_context_issuser(ctx))) { 
		error = EPERM;
		goto out;
	}
#if CONFIG_MACF
	error = mac_mount_check_remount(ctx, mp);
	if (error != 0) {
		goto out;
	}
#endif

out:
	if (error) {
		lck_rw_done(&mp->mnt_rwlock);
	}

	return error;
}

static void 
mount_end_update(mount_t mp)
{
	lck_rw_done(&mp->mnt_rwlock);
}

static int
get_imgsrc_rootvnode(uint32_t height, vnode_t *rvpp)
{
	vnode_t vp;

	if (height >= MAX_IMAGEBOOT_NESTING) {
		return EINVAL;
	}

	vp = imgsrc_rootvnodes[height];
	if ((vp != NULLVP) && (vnode_get(vp) == 0)) {
		*rvpp = vp;
		return 0;
	} else {
		return ENOENT;
	}
}

static int
relocate_imageboot_source(vnode_t pvp, vnode_t vp, struct componentname *cnp, 
		const char *fsname, vfs_context_t ctx, 
		boolean_t is64bit, user_addr_t fsmountargs, boolean_t by_index)
{
	int error;
	mount_t mp;
	boolean_t placed = FALSE;
	vnode_t devvp = NULLVP;
	struct vfstable *vfsp;
	user_addr_t devpath;
	char *old_mntonname;
	vnode_t rvp;
	uint32_t height;
	uint32_t flags;

	/* If we didn't imageboot, nothing to move */
	if (imgsrc_rootvnodes[0] == NULLVP) {
		return EINVAL;
	}

	/* Only root can do this */
	if (!vfs_context_issuser(ctx)) {
		return EPERM;
	}

	IMGSRC_DEBUG("looking for root vnode.\n");

	/*
	 * Get root vnode of filesystem we're moving.
	 */
	if (by_index) {
		if (is64bit) {
			struct user64_mnt_imgsrc_args mia64;
			error = copyin(fsmountargs, &mia64, sizeof(mia64));
			if (error != 0) {
				IMGSRC_DEBUG("Failed to copy in arguments.\n");
				return error;
			}

			height = mia64.mi_height;
			flags = mia64.mi_flags;
			devpath = mia64.mi_devpath;
		} else {
			struct user32_mnt_imgsrc_args mia32;
			error = copyin(fsmountargs, &mia32, sizeof(mia32));
			if (error != 0) {
				IMGSRC_DEBUG("Failed to copy in arguments.\n");
				return error;
			}

			height = mia32.mi_height;
			flags = mia32.mi_flags;
			devpath = mia32.mi_devpath;
		}
	} else {
		/*
		 * For binary compatibility--assumes one level of nesting.
		 */
		if (is64bit) {
			if ( (error = copyin(fsmountargs, (caddr_t)&devpath, sizeof(devpath))) )
				return error;
		} else {
			user32_addr_t tmp;
			if ( (error = copyin(fsmountargs, (caddr_t)&tmp, sizeof(tmp))) )
				return error;

			/* munge into LP64 addr */
			devpath = CAST_USER_ADDR_T(tmp);
		}

		height = 0;
		flags = 0;
	}

	if (flags != 0) {
		IMGSRC_DEBUG("%s: Got nonzero flags.\n", __FUNCTION__);
		return EINVAL;
	}

	error = get_imgsrc_rootvnode(height, &rvp);
	if (error != 0) {
		IMGSRC_DEBUG("getting root vnode failed with %d\n", error);
		return error;
	}

	IMGSRC_DEBUG("got root vnode.\n");

	MALLOC(old_mntonname, char*, MAXPATHLEN, M_TEMP, M_WAITOK);

	/* Can only move once */
	mp = vnode_mount(rvp);
	if ((mp->mnt_kern_flag & MNTK_HAS_MOVED) == MNTK_HAS_MOVED) {
		IMGSRC_DEBUG("Already moved.\n");
		error = EBUSY;
		goto out0;
	}

	IMGSRC_DEBUG("Starting updated.\n");

	/* Get exclusive rwlock on mount, authorize update on mp */
	error = mount_begin_update(mp , ctx, 0);
	if (error != 0) {
		IMGSRC_DEBUG("Starting updated failed with %d\n", error);
		goto out0;
	}

	/* 
	 * It can only be moved once.  Flag is set under the rwlock,
	 * so we're now safe to proceed.
	 */
	if ((mp->mnt_kern_flag & MNTK_HAS_MOVED) == MNTK_HAS_MOVED) {
		IMGSRC_DEBUG("Already moved [2]\n");
		goto out1;
	}
		
	
	IMGSRC_DEBUG("Preparing coveredvp.\n");

	/* Mark covered vnode as mount in progress, authorize placing mount on top */
	error = prepare_coveredvp(vp, ctx, cnp, fsname, FALSE);
	if (error != 0) {
		IMGSRC_DEBUG("Preparing coveredvp failed with %d.\n", error);
		goto out1;
	}
	
	IMGSRC_DEBUG("Covered vp OK.\n");

	/* Sanity check the name caller has provided */
	vfsp = mp->mnt_vtable;
	if (strncmp(vfsp->vfc_name, fsname, MFSNAMELEN) != 0) {
		IMGSRC_DEBUG("Wrong fs name.\n");
		error = EINVAL;
		goto out2;
	}

	/* Check the device vnode and update mount-from name, for local filesystems */
	if (vfsp->vfc_vfsflags & VFC_VFSLOCALARGS) {
		IMGSRC_DEBUG("Local, doing device validation.\n");

		if (devpath != USER_ADDR_NULL) {
			error = authorize_devpath_and_update_mntfromname(mp, devpath, &devvp, ctx);
			if (error) {
				IMGSRC_DEBUG("authorize_devpath_and_update_mntfromname() failed.\n");
				goto out2;
			}

			vnode_put(devvp);
		}
	}

	/* 
	 * Place mp on top of vnode, ref the vnode,  call checkdirs(),
	 * and increment the name cache's mount generation 
	 */

	IMGSRC_DEBUG("About to call place_mount_and_checkdirs().\n");
	error = place_mount_and_checkdirs(mp, vp, ctx);
	if (error != 0) {
		goto out2;
	}

	placed = TRUE;

	strncpy(old_mntonname, mp->mnt_vfsstat.f_mntonname, MAXPATHLEN);
	strncpy(mp->mnt_vfsstat.f_mntonname, cnp->cn_pnbuf, MAXPATHLEN);

	/* Forbid future moves */
	mount_lock(mp);
	mp->mnt_kern_flag |= MNTK_HAS_MOVED;
	mount_unlock(mp);

	/* Finally, add to mount list, completely ready to go */
	if (mount_list_add(mp) != 0) {
		/*
		 * The system is shutting down trying to umount
		 * everything, so fail with a plausible errno.
		 */
		error = EBUSY;
		goto out3;
	}

	mount_end_update(mp);
	vnode_put(rvp);
	FREE(old_mntonname, M_TEMP);

	vfs_notify_mount(pvp);

	return 0;
out3:
	strncpy(mp->mnt_vfsstat.f_mntonname, old_mntonname, MAXPATHLEN);

	mount_lock(mp);
	mp->mnt_kern_flag &= ~(MNTK_HAS_MOVED);
	mount_unlock(mp);

out2:
	/* 
	 * Placing the mp on the vnode clears VMOUNT,
	 * so cleanup is different after that point 
	 */
	if (placed) {
		/* Rele the vp, clear VMOUNT and v_mountedhere */
		undo_place_on_covered_vp(mp, vp);
	} else {
		vnode_lock_spin(vp);
		CLR(vp->v_flag, VMOUNT);
		vnode_unlock(vp);
	}
out1:
	mount_end_update(mp);

out0:
	vnode_put(rvp);
	FREE(old_mntonname, M_TEMP);
	return error;
}

#endif /* CONFIG_IMGSRC_ACCESS */

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
	if (strncmp(mp->mnt_vfsstat.f_fstypename, "hfs", sizeof("hfs")) != 0 ) {
		return;
	}
	/* 
	 * Enable filesystem disk quotas if necessary.
	 * We ignore errors as this should not interfere with final mount
	 */
	for (type=0; type < MAXQUOTAS; type++) {
		snprintf(qfpath, sizeof(qfpath), "%s/%s.%s", mp->mnt_vfsstat.f_mntonname, qfopsname, qfextension[type]);
		NDINIT(&qnd, LOOKUP, OP_MOUNT, FOLLOW, UIO_SYSSPACE,
		       CAST_USER_ADDR_T(qfpath), ctx);
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

	if (olddp->v_usecount == 1)
		return(0);
	err = VFS_ROOT(olddp->v_mountedhere, &newdp, ctx);

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
unmount(__unused proc_t p, struct unmount_args *uap, __unused int32_t *retval)
{
	vnode_t vp;
	struct mount *mp;
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, LOOKUP, OP_UNMOUNT, FOLLOW | AUDITVNPATH1, 
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
	 * If the file system is not responding and MNT_NOBLOCK
	 * is set and not a forced unmount then return EBUSY.
	 */
	if ((mp->mnt_kern_flag & MNT_LNOTRESP) &&
		(flags & MNT_NOBLOCK) && ((flags & MNT_FORCE) == 0)) {
		error = EBUSY;
		goto out;
	}

	/*
	 * Skip authorization if the mount is tagged as permissive and 
	 * this is not a forced-unmount attempt.
	 */
	if (!(((mp->mnt_kern_flag & MNTK_PERMIT_UNMOUNT) != 0) && ((flags & MNT_FORCE) == 0))) {
		/*
		 * Only root, or the user that did the original mount is
		 * permitted to unmount this filesystem.
		 */
		if ((mp->mnt_vfsstat.f_owner != kauth_cred_getuid(kauth_cred_get())) &&
				(error = suser(kauth_cred_get(), &p->p_acflag)))
			goto out;
	}
	/*
	 * Don't allow unmounting the root file system.
	 */
	if (mp->mnt_flag & MNT_ROOTFS) {
		error = EBUSY; /* the root is always busy */
		goto out;
	}

#ifdef CONFIG_IMGSRC_ACCESS
	if (mp->mnt_kern_flag & MNTK_BACKS_ROOT) {
		error = EBUSY;
		goto out;
	}
#endif /* CONFIG_IMGSRC_ACCESS */

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
#if CONFIG_TRIGGERS
	proc_t p = vfs_context_proc(ctx);
	int did_vflush = 0;
	int pflags_save = 0;
#endif /* CONFIG_TRIGGERS */

	mount_lock(mp);

	/*
	 * If already an unmount in progress just return EBUSY.
	 * Even a forced unmount cannot override.
	 */
	if (mp->mnt_lflag & MNT_LUNMOUNT) {
		if (withref != 0)
			mount_drop(mp, 1);
		mount_unlock(mp);
		return (EBUSY);
	}

	if (flags & MNT_FORCE) {
		forcedunmount = 1;
		mp->mnt_lflag |= MNT_LFORCE;
	}

#if CONFIG_TRIGGERS
	if (flags & MNT_NOBLOCK && p != kernproc)
		pflags_save = OSBitOrAtomic(P_NOREMOTEHANG, &p->p_flag);
#endif

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
 
	if (forcedunmount && (flags & MNT_LNOSUB) == 0) {
		/*
		 * Force unmount any mounts in this filesystem.
		 * If any unmounts fail - just leave them dangling.
		 * Avoids recursion.
		 */
		(void) dounmount_submounts(mp, flags | MNT_LNOSUB, ctx);
	}

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

#if CONFIG_TRIGGERS
	vfs_nested_trigger_unmounts(mp, flags, ctx);
	did_vflush = 1;
#endif	
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
		OSAddAtomic(1, &vfs_nummntops);

	if ( mp->mnt_devvp && mp->mnt_vtable->vfc_vfsflags & VFC_VFSLOCALARGS) {
		/* hold an io reference and drop the usecount before close */
		devvp = mp->mnt_devvp;
		vnode_getalways(devvp);
		vnode_rele(devvp);
		VNOP_CLOSE(devvp, mp->mnt_flag & MNT_RDONLY ? FREAD : FREAD|FWRITE,
                       ctx);
		vnode_clearmountedon(devvp);
		vnode_put(devvp);
	}
	lck_rw_done(&mp->mnt_rwlock);
	mount_list_remove(mp);
	lck_rw_lock_exclusive(&mp->mnt_rwlock);

	/* mark the mount point hook in the vp but not drop the ref yet */
	if ((coveredvp = mp->mnt_vnodecovered) != NULLVP) {
		/*
		 * The covered vnode needs special handling. Trying to get an
		 * iocount must not block here as this may lead to deadlocks
		 * if the Filesystem to which the covered vnode belongs is
		 * undergoing forced unmounts. Since we hold a usecount, the
		 * vnode cannot be reused (it can, however, still be terminated)
		 */
		vnode_getalways(coveredvp);
		vnode_lock_spin(coveredvp);

		mp->mnt_crossref++;
		coveredvp->v_mountedhere = (struct mount *)0;
		CLR(coveredvp->v_flag, VMOUNT);

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

#if CONFIG_TRIGGERS
	if (flags & MNT_NOBLOCK && p != kernproc) {
	 	// Restore P_NOREMOTEHANG bit to its previous value
		if ((pflags_save & P_NOREMOTEHANG) == 0)
			OSBitAndAtomic(~((uint32_t) P_NOREMOTEHANG), &p->p_flag);
	}

	/* 
	 * Callback and context are set together under the mount lock, and
	 * never cleared, so we're safe to examine them here, drop the lock, 
	 * and call out.
	 */
	if (mp->mnt_triggercallback != NULL) {
		mount_unlock(mp);
		if (error == 0) {
			mp->mnt_triggercallback(mp, VTC_RELEASE, mp->mnt_triggerdata, ctx);
		} else if (did_vflush) {
			mp->mnt_triggercallback(mp, VTC_REPLACE, mp->mnt_triggerdata, ctx);
		}
	} else {
		mount_unlock(mp);
	}
#else 
	mount_unlock(mp);
#endif /* CONFIG_TRIGGERS */

	lck_rw_done(&mp->mnt_rwlock);

	if (needwakeup)
		wakeup((caddr_t)mp);

	if (!error) {
		if ((coveredvp != NULLVP)) {
			vnode_t pvp = NULLVP;

			/*
			 * The covered vnode needs special handling. Trying to
			 * get an iocount must not block here as this may lead
			 * to deadlocks if the Filesystem to which the covered
			 * vnode belongs is undergoing forced unmounts. Since we
			 * hold a usecount, the  vnode cannot be reused
			 * (it can, however, still be terminated).
			 */
			vnode_getalways(coveredvp);

			mount_dropcrossref(mp, coveredvp, 0);
			/*
			 * We'll _try_ to detect if this really needs to be
			 * done. The coveredvp can only be in termination (or
			 * terminated) if the coveredvp's mount point is in a
			 * forced unmount (or has been) since we still hold the
			 * ref.
			 */
			if (!vnode_isrecycled(coveredvp)) {
				pvp = vnode_getparent(coveredvp);
#if CONFIG_TRIGGERS
				if (coveredvp->v_resolve) {
					vnode_trigger_rearm(coveredvp, ctx);
				}
#endif
			}

			vnode_rele(coveredvp);
			vnode_put(coveredvp);
			coveredvp = NULLVP;

			if (pvp) {
				lock_vnode_and_post(pvp, NOTE_WRITE);
				vnode_put(pvp);
			}
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

/*
 * Unmount any mounts in this filesystem.
 */
void
dounmount_submounts(struct mount *mp, int flags, vfs_context_t ctx)
{
	mount_t	smp;
	fsid_t *fsids, fsid;
	int fsids_sz;
	int count = 0, i, m = 0;
	vnode_t vp;

	mount_list_lock();

	// Get an array to hold the submounts fsids.
	TAILQ_FOREACH(smp, &mountlist, mnt_list)
		count++;
	fsids_sz = count * sizeof(fsid_t);
	MALLOC(fsids, fsid_t *, fsids_sz, M_TEMP, M_NOWAIT);
	if (fsids == NULL) {
		mount_list_unlock();
		goto out;
	}
	fsids[0] = mp->mnt_vfsstat.f_fsid;	// Prime the pump

	/*
	 * Fill the array with submount fsids.
	 * Since mounts are always added to the tail of the mount list, the
	 * list is always in mount order.  
	 * For each mount check if the mounted-on vnode belongs to a
	 * mount that's already added to our array of mounts to be unmounted.
	 */
	for (smp = TAILQ_NEXT(mp, mnt_list); smp; smp = TAILQ_NEXT(smp, mnt_list)) {
		vp = smp->mnt_vnodecovered;
		if (vp == NULL)
			continue;
		fsid = vnode_mount(vp)->mnt_vfsstat.f_fsid;	// Underlying fsid
		for (i = 0; i <= m; i++) {
			if (fsids[i].val[0] == fsid.val[0] &&
			    fsids[i].val[1] == fsid.val[1]) {
				fsids[++m] = smp->mnt_vfsstat.f_fsid;
				break;
			}
		}
	}
	mount_list_unlock();

	// Unmount the submounts in reverse order. Ignore errors.
	for (i = m; i > 0; i--) {
		smp = mount_list_lookupby_fsid(&fsids[i], 0, 1);
		if (smp) {
			mount_ref(smp, 0);
			mount_iterdrop(smp);
			(void) dounmount(smp, flags, 1, ctx);
		}
	}
out:
	if (fsids)
		FREE(fsids, M_TEMP);
}

void
mount_dropcrossref(mount_t mp, vnode_t dp, int need_put)
{
	vnode_lock(dp);
	mp->mnt_crossref--;

	if (mp->mnt_crossref < 0)
		panic("mount cross refs -ve");

	if ((mp != dp->v_mountedhere) && (mp->mnt_crossref == 0)) {
			
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
#endif

int print_vmpage_stat=0;
int sync_timeout = 60;  // Sync time limit (sec)

static int 
sync_callback(mount_t mp, __unused void *arg)
{
	if ((mp->mnt_flag & MNT_RDONLY) == 0) {
		int asyncflag = mp->mnt_flag & MNT_ASYNC;

		mp->mnt_flag &= ~MNT_ASYNC;
		VFS_SYNC(mp, arg ? MNT_WAIT : MNT_NOWAIT, vfs_context_kernel());
		if (asyncflag)
			mp->mnt_flag |= MNT_ASYNC;
	}

	return (VFS_RETURNED);
}

/* ARGSUSED */
int
sync(__unused proc_t p, __unused struct sync_args *uap, __unused int32_t *retval)
{
	vfs_iterate(LK_NOWAIT, sync_callback, NULL);

	if (print_vmpage_stat) {
		vm_countdirtypages();
	}

#if DIAGNOSTIC
	if (syncprt)
		vfs_bufstats();
#endif /* DIAGNOSTIC */
	return 0;
}

static void
sync_thread(void *arg, __unused wait_result_t wr)
{
	int *timeout = (int *) arg;

	vfs_iterate(LK_NOWAIT, sync_callback, NULL);

	if (timeout)
		wakeup((caddr_t) timeout);
	if (print_vmpage_stat) {
		vm_countdirtypages();
	}

#if DIAGNOSTIC
	if (syncprt)
		vfs_bufstats();
#endif /* DIAGNOSTIC */
}

/*
 * Sync in a separate thread so we can time out if it blocks.
 */
static int
sync_async(int timeout)
{
	thread_t thd;
	int error;
	struct timespec ts = {timeout, 0};

	lck_mtx_lock(sync_mtx_lck);
	if (kernel_thread_start(sync_thread, &timeout, &thd) != KERN_SUCCESS) {
		printf("sync_thread failed\n");
		lck_mtx_unlock(sync_mtx_lck);
		return (0);
	}

	error = msleep((caddr_t) &timeout, sync_mtx_lck, (PVFS | PDROP | PCATCH), "sync_thread", &ts);
	if (error) {
		printf("sync timed out: %d sec\n", timeout);
	}
	thread_deallocate(thd);

	return (0);
}

/*
 * An in-kernel sync for power management to call.
 */
__private_extern__ int
sync_internal(void)
{
	(void) sync_async(sync_timeout);

	return 0;
} /* end of sync_internal call */

/*
 * Change filesystem quotas.
 */
#if QUOTA
int
quotactl(proc_t p, struct quotactl_args *uap, __unused int32_t *retval)
{
	struct mount *mp;
	int error, quota_cmd, quota_status;
	caddr_t datap;
	size_t fnamelen;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	struct dqblk my_dqblk;

	AUDIT_ARG(uid, uap->uid);
	AUDIT_ARG(cmd, uap->cmd);
	NDINIT(&nd, LOOKUP, OP_LOOKUP, FOLLOW | AUDITVNPATH1, UIO_USERSPACE,
	       uap->path, ctx);
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
				struct user_dqblk	my_dqblk64 = {.dqb_bhardlimit = 0};
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
quotactl(__unused proc_t p, __unused struct quotactl_args *uap, __unused int32_t *retval)
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
statfs(__unused proc_t p, struct statfs_args *uap, __unused int32_t *retval)
{
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	vnode_t vp;

	NDINIT(&nd, LOOKUP, OP_STATFS, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	mp = vp->v_mount;
	sp = &mp->mnt_vfsstat;
	nameidone(&nd);

	error = vfs_update_vfsstat(mp, ctx, VFS_USER_EVENT);
	if (error != 0) { 
		vnode_put(vp);
		return (error);
	}

	error = munge_statfs(mp, sp, uap->buf, NULL, IS_64BIT_PROCESS(p), TRUE);
	vnode_put(vp);
	return (error);
}

/*
 * Get filesystem statistics.
 */
/* ARGSUSED */
int
fstatfs(__unused proc_t p, struct fstatfs_args *uap, __unused int32_t *retval)
{
	vnode_t vp;
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;

	AUDIT_ARG(fd, uap->fd);

	if ( (error = file_vnode(uap->fd, &vp)) )
		return (error);

	error = vnode_getwithref(vp);
	if (error) {
		file_drop(uap->fd);
		return (error);
	}

	AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);

	mp = vp->v_mount;
	if (!mp) {
		error = EBADF;
		goto out;
	}
	sp = &mp->mnt_vfsstat;
	if ((error = vfs_update_vfsstat(mp,vfs_context_current(),VFS_USER_EVENT)) != 0) {
		goto out;
	}

	error = munge_statfs(mp, sp, uap->buf, NULL, IS_64BIT_PROCESS(p), TRUE);

out:
	file_drop(uap->fd);
	vnode_put(vp);

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
	if (mp->mnt_kern_flag & MNTK_TYPENAME_OVERRIDE) {
		strlcpy(&sfs.f_fstypename[0], &mp->fstypename_override[0], MFSTYPENAMELEN);
	} else {
		strlcpy(&sfs.f_fstypename[0], &sfsp->f_fstypename[0], MFSTYPENAMELEN);
	}
	strlcpy(&sfs.f_mntonname[0], &sfsp->f_mntonname[0], MAXPATHLEN);
	strlcpy(&sfs.f_mntfromname[0], &sfsp->f_mntfromname[0], MAXPATHLEN);

	error = copyout((caddr_t)&sfs, bufp, sizeof(sfs));

	return(error);
}

/* 
 * Get file system statistics in 64-bit mode 
 */
int
statfs64(__unused struct proc *p, struct statfs64_args *uap, __unused int32_t *retval)
{
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;
	struct nameidata nd;
	vfs_context_t ctxp = vfs_context_current();
	vnode_t vp;

	NDINIT(&nd, LOOKUP, OP_STATFS, FOLLOW | AUDITVNPATH1, 
		UIO_USERSPACE, uap->path, ctxp);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	mp = vp->v_mount;
	sp = &mp->mnt_vfsstat;
	nameidone(&nd);

	error = vfs_update_vfsstat(mp, ctxp, VFS_USER_EVENT);
	if (error != 0) { 
		vnode_put(vp);
		return (error);
	}

	error = statfs64_common(mp, sp, uap->buf);
	vnode_put(vp);

	return (error);
}

/* 
 * Get file system statistics in 64-bit mode 
 */
int
fstatfs64(__unused struct proc *p, struct fstatfs64_args *uap, __unused int32_t *retval)
{
	struct vnode *vp;
	struct mount *mp;
	struct vfsstatfs *sp;
	int error;

	AUDIT_ARG(fd, uap->fd);

	if ( (error = file_vnode(uap->fd, &vp)) )
		return (error);

	error = vnode_getwithref(vp);
	if (error) {
		file_drop(uap->fd);
		return (error);
	}

	AUDIT_ARG(vnpath_withref, vp, ARG_VNODE1);

	mp = vp->v_mount;
	if (!mp) {
		error = EBADF;
		goto out;
	}
	sp = &mp->mnt_vfsstat;
	if ((error = vfs_update_vfsstat(mp, vfs_context_current(), VFS_USER_EVENT)) != 0) {
		goto out;
	}

	error = statfs64_common(mp, sp, uap->buf);

out:
	file_drop(uap->fd);
	vnode_put(vp);

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
		 * fsstat cache. MNT_WAIT/MNT_DWAIT overrides MNT_NOWAIT.
		 */
		if (((fstp->flags & MNT_NOWAIT) == 0 || (fstp->flags & (MNT_WAIT | MNT_DWAIT))) &&
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
#if CONFIG_MACF
			error = mac_mount_label_get(mp, *fstp->mp);
			if (error) {
				fstp->error = error;
				return(VFS_RETURNED_DONE);
			}
#endif
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

/*
 * __mac_getfsstat: Get MAC-related file system statistics
 *
 * Parameters:    p                        (ignored)
 *                uap                      User argument descriptor (see below)
 *                retval                   Count of file system statistics (N stats)  
 *
 * Indirect:      uap->bufsize             Buffer size
 *                uap->macsize             MAC info size
 *                uap->buf                 Buffer where information will be returned
 *                uap->mac                 MAC info
 *                uap->flags               File system flags
 *                
 *
 * Returns:        0                       Success
 *                !0                       Not success
 *
 */
int
__mac_getfsstat(__unused proc_t p, struct __mac_getfsstat_args *uap, int *retval)
{
	user_addr_t sfsp;
	user_addr_t *mp;
	size_t count, maxcount, bufsize, macsize;
	struct getfsstat_struct fst;

	bufsize = (size_t) uap->bufsize;
	macsize = (size_t) uap->macsize;

	if (IS_64BIT_PROCESS(p)) {
		maxcount = bufsize / sizeof(struct user64_statfs);
	}
	else {
		maxcount = bufsize / sizeof(struct user32_statfs);
	}
	sfsp = uap->buf;
	count = 0;

	mp = NULL;

#if CONFIG_MACF
	if (uap->mac != USER_ADDR_NULL) {
		u_int32_t *mp0;
		int error;
		unsigned int i;

		count = (macsize / (IS_64BIT_PROCESS(p) ? 8 : 4));
		if (count != maxcount)
			return (EINVAL);

		/* Copy in the array */
		MALLOC(mp0, u_int32_t *, macsize, M_MACTEMP, M_WAITOK);
		if (mp0 == NULL) {
			return (ENOMEM);
		}

		error = copyin(uap->mac, mp0, macsize);
		if (error) {
			FREE(mp0, M_MACTEMP);
			return (error);
		}

		/* Normalize to an array of user_addr_t */
		MALLOC(mp, user_addr_t *, count * sizeof(user_addr_t), M_MACTEMP, M_WAITOK);
		if (mp == NULL) {
			FREE(mp0, M_MACTEMP);
			return (ENOMEM);
		}

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
		 * If MNT_NOWAIT is specified, do not refresh the fsstat
		 * cache. MNT_WAIT overrides MNT_NOWAIT.
		 *
		 * We treat MNT_DWAIT as MNT_WAIT for all instances of
		 * getfsstat, since the constants are out of the same
		 * namespace.
		 */
		if (((fstp->flags & MNT_NOWAIT) == 0 ||
		     (fstp->flags & (MNT_WAIT | MNT_DWAIT))) &&
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

/*
 * gets the associated vnode with the file descriptor passed.
 * as input
 *
 * INPUT
 * ctx - vfs context of caller
 * fd - file descriptor for which vnode is required.
 * vpp - Pointer to pointer to vnode to be returned.
 *
 * The vnode is returned with an iocount so any vnode obtained
 * by this call needs a vnode_put
 *
 */
static int
vnode_getfromfd(vfs_context_t ctx, int fd, vnode_t *vpp)
{
	int error;
	vnode_t vp;
	struct fileproc *fp;
	proc_t p = vfs_context_proc(ctx);

	*vpp =  NULLVP;

	error = fp_getfvp(p, fd, &fp, &vp);
	if (error)
		return (error);

	error = vnode_getwithref(vp);
	if (error) {
		(void)fp_drop(p, fd, fp, 0);
		return (error);
	}

	(void)fp_drop(p, fd, fp, 0);
	*vpp = vp;
	return (error);
}

/*
 * Wrapper function around namei to start lookup from a directory
 * specified by a file descriptor ni_dirfd.
 *
 * In addition to all the errors returned by namei, this call can
 * return ENOTDIR if the file descriptor does not refer to a directory.
 * and EBADF if the file descriptor is not valid.
 */
int
nameiat(struct nameidata *ndp, int dirfd)
{
	if ((dirfd != AT_FDCWD) &&
	    !(ndp->ni_flag & NAMEI_CONTLOOKUP) &&
	    !(ndp->ni_cnd.cn_flags & USEDVP)) {
		int error = 0;
		char c;

		if (UIO_SEG_IS_USER_SPACE(ndp->ni_segflg)) {
			error = copyin(ndp->ni_dirp, &c, sizeof(char));
			if (error)
				return (error);
		} else {
			c = *((char *)(ndp->ni_dirp));
		}

		if (c != '/') {
			vnode_t dvp_at;

			error = vnode_getfromfd(ndp->ni_cnd.cn_context, dirfd,
			    &dvp_at);
			if (error)
				return (error);

			if (vnode_vtype(dvp_at) != VDIR) {
				vnode_put(dvp_at);
				return (ENOTDIR);
			}

			ndp->ni_dvp = dvp_at;
			ndp->ni_cnd.cn_flags |= USEDVP;
			error = namei(ndp);
			ndp->ni_cnd.cn_flags &= ~USEDVP;
			vnode_put(dvp_at);
			return (error);
		}
	}

	return (namei(ndp));
}

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

	AUDIT_ARG(fd, uap->fd);
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
			OSBitOrAtomic(P_THCWD, &p->p_flag);
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
fchdir(proc_t p, struct fchdir_args *uap, __unused int32_t *retval)
{
	return common_fchdir(p, uap, 0);
}

int
__pthread_fchdir(proc_t p, struct __pthread_fchdir_args *uap, __unused int32_t *retval)
{
	return common_fchdir(p, (void *)uap, 1);
}

/*
 * Change current working directory (".").
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

	NDINIT(&nd, LOOKUP, OP_CHDIR, FOLLOW | AUDITVNPATH1, 
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
			OSBitOrAtomic(P_THCWD, &p->p_flag);
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


/*
 * chdir
 *
 * Change current working directory (".") for the entire process
 *
 * Parameters:  p       Process requesting the call
 * 		uap     User argument descriptor (see below)
 * 		retval  (ignored)
 *
 * Indirect parameters:	uap->path	Directory path
 *
 * Returns:	0			Success
 * 		common_chdir: ENOTDIR
 * 		common_chdir: ENOENT	No such file or directory
 * 		common_chdir: ???
 *
 */
int
chdir(proc_t p, struct chdir_args *uap, __unused int32_t *retval)
{
	return common_chdir(p, (void *)uap, 0);
}

/*
 * __pthread_chdir
 *
 * Change current working directory (".") for a single thread
 *
 * Parameters:  p       Process requesting the call
 * 		uap     User argument descriptor (see below)
 * 		retval  (ignored)
 *
 * Indirect parameters:	uap->path	Directory path
 *
 * Returns:	0			Success
 * 		common_chdir: ENOTDIR
 *		common_chdir: ENOENT	No such file or directory
 *		common_chdir: ???
 *
 */
int
__pthread_chdir(proc_t p, struct __pthread_chdir_args *uap, __unused int32_t *retval)
{
	return common_chdir(p, (void *)uap, 1);
}


/*
 * Change notion of root (``/'') directory.
 */
/* ARGSUSED */
int
chroot(proc_t p, struct chroot_args *uap, __unused int32_t *retval)
{
	struct filedesc *fdp = p->p_fd;
	int error;
	struct nameidata nd;
	vnode_t tvp;
	vfs_context_t ctx = vfs_context_current();

	if ((error = suser(kauth_cred_get(), &p->p_acflag)))
		return (error);

	NDINIT(&nd, LOOKUP, OP_CHROOT, FOLLOW | AUDITVNPATH1, 
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
 * Free the vnode data (for directories) associated with the file glob.
 */
struct fd_vn_data *
fg_vn_data_alloc(void)
{
	struct fd_vn_data *fvdata;

	/* Allocate per fd vnode data */
	MALLOC(fvdata, struct fd_vn_data *, (sizeof(struct fd_vn_data)),
	       M_FD_VN_DATA, M_WAITOK | M_ZERO);
	lck_mtx_init(&fvdata->fv_lock, fd_vn_lck_grp, fd_vn_lck_attr);
	return fvdata;
}

/*
 * Free the vnode data (for directories) associated with the file glob.
 */
void
fg_vn_data_free(void *fgvndata)
{
	struct fd_vn_data *fvdata = (struct fd_vn_data *)fgvndata;

	if (fvdata->fv_buf)
		FREE(fvdata->fv_buf, M_FD_DIRBUF);
	lck_mtx_destroy(&fvdata->fv_lock, fd_vn_lck_grp);
	FREE(fvdata, M_FD_VN_DATA);
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
 *
 * XXX Need to implement uid, gid
 */
int
open1(vfs_context_t ctx, struct nameidata *ndp, int uflags,
    struct vnode_attr *vap, fp_allocfn_t fp_zalloc, void *cra,
    int32_t *retval)
{
	proc_t p = vfs_context_proc(ctx);
	uthread_t uu = get_bsdthread_info(vfs_context_thread(ctx));
	struct fileproc *fp;
	vnode_t vp;
	int flags, oflags;
	int type, indx, error;
	struct flock lf;
	int no_controlling_tty = 0;
	int deny_controlling_tty = 0;
	struct session *sessp = SESSION_NULL;

	oflags = uflags;

	if ((oflags & O_ACCMODE) == O_ACCMODE)
		return(EINVAL);
	flags = FFLAGS(uflags);

	AUDIT_ARG(fflags, oflags);
	AUDIT_ARG(mode, vap->va_mode);

	if ((error = falloc_withalloc(p,
	    &fp, &indx, ctx, fp_zalloc, cra)) != 0) {
		return (error);
	}
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
			if ((error = dupfdopen(p->p_fd, indx, uu->uu_dupfd, flags, error)) == 0) {
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
	fp->f_fglob->fg_ops = &vnops;
	fp->f_fglob->fg_data = (caddr_t)vp;

#if CONFIG_PROTECT
	if (VATTR_IS_ACTIVE (vap, va_dataprotect_flags)) {
		if (vap->va_dataprotect_flags & VA_DP_RAWENCRYPTED) {
			fp->f_fglob->fg_flag |= FENCRYPTED;
		}
	}
#endif

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
		if ((error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_SETLK, &lf, type, ctx, NULL)))
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

		session_lock(sessp);
		ttyvp = sessp->s_ttyvp;
		sessp->s_ttyvp = vp;
		sessp->s_ttyvid = vnode_vid(vp);
		session_unlock(sessp);
	}

	/*
	 * For directories we hold some additional information in the fd.
	 */
	if (vnode_vtype(vp) == VDIR) {
		fp->f_fglob->fg_vn_data = fg_vn_data_alloc();
	} else {
		fp->f_fglob->fg_vn_data = NULL;
	}

	vnode_put(vp);

	proc_fdlock(p);
	if (flags & O_CLOEXEC)
		*fdflags(p, indx) |= UF_EXCLOSE;
	if (flags & O_CLOFORK)
		*fdflags(p, indx) |= UF_FORKCLOSE;
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

	struct vfs_context context = *vfs_context_current();
	context.vc_ucred = fp->f_fglob->fg_cred;
    
    	if ((fp->f_fglob->fg_flag & FHASLOCK) &&
	    (FILEGLOB_DTYPE(fp->f_fglob) == DTYPE_VNODE)) {
		lf.l_whence = SEEK_SET;
        	lf.l_start = 0;
        	lf.l_len = 0;
        	lf.l_type = F_UNLCK;
        
        	(void)VNOP_ADVLOCK(
        		vp, (caddr_t)fp->f_fglob, F_UNLCK, &lf, F_FLOCK, ctx, NULL);
	}

	vn_close(vp, fp->f_fglob->fg_flag, &context);
	vnode_put(vp);
	fp_free(p, indx, fp);

	return (error);
}

/*
 * While most of the *at syscall handlers can call nameiat() which
 * is a wrapper around namei, the use of namei and initialisation
 * of nameidata are far removed and in different functions  - namei
 * gets called in vn_open_auth for open1. So we'll just do here what
 * nameiat() does.
 */
static int
open1at(vfs_context_t ctx, struct nameidata *ndp, int uflags,
    struct vnode_attr *vap, fp_allocfn_t fp_zalloc, void *cra, int32_t *retval,
    int dirfd)
{
	if ((dirfd != AT_FDCWD) && !(ndp->ni_cnd.cn_flags & USEDVP)) {
		int error;
		char c;

		if (UIO_SEG_IS_USER_SPACE(ndp->ni_segflg)) {
			error = copyin(ndp->ni_dirp, &c, sizeof(char));
			if (error)
				return (error);
		} else {
			c = *((char *)(ndp->ni_dirp));
		}

		if (c != '/') {
			vnode_t dvp_at;

			error = vnode_getfromfd(ndp->ni_cnd.cn_context, dirfd,
			    &dvp_at);
			if (error)
				return (error);

			if (vnode_vtype(dvp_at) != VDIR) {
				vnode_put(dvp_at);
				return (ENOTDIR);
			}

			ndp->ni_dvp = dvp_at;
			ndp->ni_cnd.cn_flags |= USEDVP;
			error = open1(ctx, ndp, uflags, vap, fp_zalloc, cra,
			    retval);
			vnode_put(dvp_at);
			return (error);
		}
	}

	return (open1(ctx, ndp, uflags, vap, fp_zalloc, cra, retval));
}

/*
 * open_extended: open a file given a path name; with extended argument list (including extended security (ACL)).
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
open_extended(proc_t p, struct open_extended_args *uap, int32_t *retval)
{
	struct filedesc *fdp = p->p_fd;
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vnode_attr va;
	struct nameidata nd;
	int cmode;

	AUDIT_ARG(owner, uap->uid, uap->gid);

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

	NDINIT(&nd, LOOKUP, OP_OPEN, FOLLOW | AUDITVNPATH1, UIO_USERSPACE,
	       uap->path, vfs_context_current());

	ciferror = open1(vfs_context_current(), &nd, uap->flags, &va,
			 fileproc_alloc_init, NULL, retval);
	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);

	return ciferror;
}

/* 
 * Go through the data-protected atomically controlled open (2)
 *  
 * int open_dprotected_np(user_addr_t path, int flags, int class, int dpflags, int mode)
 */
int open_dprotected_np (__unused proc_t p, struct open_dprotected_np_args *uap, int32_t *retval) {
	int flags = uap->flags;
	int class = uap->class;
	int dpflags = uap->dpflags;

	/* 
	 * Follow the same path as normal open(2)
	 * Look up the item if it exists, and acquire the vnode.
	 */
	struct filedesc *fdp = p->p_fd;
	struct vnode_attr va;
	struct nameidata nd;
	int cmode;
	int error;
	
	VATTR_INIT(&va);
	/* Mask off all but regular access permissions */
	cmode = ((uap->mode &~ fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode & ACCESSPERMS);

	NDINIT(&nd, LOOKUP, OP_OPEN, FOLLOW | AUDITVNPATH1, UIO_USERSPACE,
	       uap->path, vfs_context_current());

	/* 
	 * Initialize the extra fields in vnode_attr to pass down our 
	 * extra fields.
	 * 1. target cprotect class.
	 * 2. set a flag to mark it as requiring open-raw-encrypted semantics. 
	 */ 
	if (flags & O_CREAT) {	
		VATTR_SET(&va, va_dataprotect_class, class);
	}
	
	if (dpflags & O_DP_GETRAWENCRYPTED) {
		if ( flags & (O_RDWR | O_WRONLY)) {
			/* Not allowed to write raw encrypted bytes */
			return EINVAL;		
		}			
		VATTR_SET(&va, va_dataprotect_flags, VA_DP_RAWENCRYPTED);
	}

	error = open1(vfs_context_current(), &nd, uap->flags, &va,
		      fileproc_alloc_init, NULL, retval);

	return error;
}

static int
openat_internal(vfs_context_t ctx, user_addr_t path, int flags, int mode,
    int fd, enum uio_seg segflg, int *retval)
{
	struct filedesc *fdp = (vfs_context_proc(ctx))->p_fd;
	struct vnode_attr va;
	struct nameidata nd;
	int cmode;

	VATTR_INIT(&va);
	/* Mask off all but regular access permissions */
	cmode = ((mode &~ fdp->fd_cmask) & ALLPERMS) & ~S_ISTXT;
	VATTR_SET(&va, va_mode, cmode & ACCESSPERMS);

	NDINIT(&nd, LOOKUP, OP_OPEN, FOLLOW | AUDITVNPATH1,
	    segflg, path, ctx);

	return (open1at(ctx, &nd, flags, &va, fileproc_alloc_init, NULL,
	    retval, fd));
}

int
open(proc_t p, struct open_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(open_nocancel(p, (struct open_nocancel_args *)uap, retval));
}

int
open_nocancel(__unused proc_t p, struct open_nocancel_args *uap,
    int32_t *retval)
{
	return (openat_internal(vfs_context_current(), uap->path, uap->flags,
	    uap->mode, AT_FDCWD, UIO_USERSPACE, retval));
}

int
openat_nocancel(__unused proc_t p, struct openat_nocancel_args *uap,
                int32_t *retval)
{
	return (openat_internal(vfs_context_current(), uap->path, uap->flags,
	    uap->mode, uap->fd, UIO_USERSPACE, retval));
}

int
openat(proc_t p, struct openat_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return(openat_nocancel(p, (struct openat_nocancel_args *)uap, retval));
}

/*
 * openbyid_np: open a file given a file system id and a file system object id
 *	the hfs file system object id is an fsobj_id_t {uint32, uint32}
 *	file systems that don't support object ids it is a node id (uint64_t).
 *
 * Parameters:	p			Process requesting the open
 *		uap			User argument descriptor (see below)
 *		retval			Pointer to an area to receive the
 *					return calue from the system call
 *
 * Indirect:	uap->path		Path to open (same as 'open')
 *
 *		uap->fsid		id of target file system
 *		uap->objid		id of target file system object
 *		uap->flags		Flags to open (same as 'open')
 *
 * Returns:	0			Success
 *		!0			errno value
 *
 *
 * XXX:		We should enummerate the possible errno values here, and where
 *		in the code they originated.
 */
int
openbyid_np(__unused proc_t p, struct openbyid_np_args *uap, int *retval)
{
	fsid_t fsid;
	uint64_t objid;
	int error;
	char *buf = NULL;
	int buflen = MAXPATHLEN;
	int pathlen = 0;
	vfs_context_t ctx = vfs_context_current();

	if ((error = copyin(uap->fsid, (caddr_t)&fsid, sizeof(fsid)))) {
		return (error);
	}

	/*uap->obj is an fsobj_id_t defined as struct {uint32_t, uint32_t} */
	if ((error = copyin(uap->objid, (caddr_t)&objid, sizeof(uint64_t)))) {
		return (error);
	}

	AUDIT_ARG(value32, fsid.val[0]);
	AUDIT_ARG(value64, objid);

	/*resolve path from fsis, objid*/
	do {
		MALLOC(buf, char *, buflen + 1, M_TEMP, M_WAITOK);
		if (buf == NULL) {
			return (ENOMEM);
		}

		error = fsgetpath_internal(
			ctx, fsid.val[0], objid,
			buflen, buf, &pathlen);

		if (error) {
			FREE(buf, M_TEMP);
			buf = NULL;
		}
	} while (error == ENOSPC && (buflen += MAXPATHLEN));

	if (error) {
		return error;
	}

	buf[pathlen] = 0;

	error = openat_internal(
		ctx, (user_addr_t)buf, uap->oflags, 0, AT_FDCWD, UIO_SYSSPACE, retval);

	FREE(buf, M_TEMP);

	return error;
}


/*
 * Create a special file.
 */
static int mkfifo1(vfs_context_t ctx, user_addr_t upath, struct vnode_attr *vap);

int
mknod(proc_t p, struct mknod_args *uap, __unused int32_t *retval)
{
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	int error;
	struct nameidata nd;
	vnode_t	vp, dvp;

 	VATTR_INIT(&va);
 	VATTR_SET(&va, va_mode, (uap->mode & ALLPERMS) & ~p->p_fd->fd_cmask);
 	VATTR_SET(&va, va_rdev, uap->dev);

	/* If it's a mknod() of a FIFO, call mkfifo1() instead */
	if ((uap->mode & S_IFMT) == S_IFIFO)
 		return(mkfifo1(ctx, uap->path, &va));

	AUDIT_ARG(mode, uap->mode);
	AUDIT_ARG(value32, uap->dev);

	if ((error = suser(vfs_context_ucred(ctx), &p->p_acflag)))
		return (error);
	NDINIT(&nd, CREATE, OP_MKNOD, LOCKPARENT | AUDITVNPATH1, 
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
	default:
		error = EINVAL;
		goto out;
	}

#if CONFIG_MACF
	error = mac_vnode_check_create(ctx,
	    nd.ni_dvp, &nd.ni_cnd, &va);
	if (error)
		goto out;
#endif

 	if ((error = vnode_authorize(dvp, NULL, KAUTH_VNODE_ADD_FILE, ctx)) != 0)
 		goto out;

	if ((error = vn_create(dvp, &vp, &nd, &va, 0, 0, NULL, ctx)) != 0)
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

	NDINIT(&nd, CREATE, OP_MKFIFO, LOCKPARENT | AUDITVNPATH1, 
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

	if ((error = vn_authorize_create(dvp, &nd.ni_cnd, vap, ctx, NULL)) != 0)
		goto out;

  	error = vn_create(dvp, &vp, &nd, vap, 0, 0, NULL, ctx);
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
 * mkfifo_extended: Create a named pipe; with extended argument list (including extended security (ACL)).
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
mkfifo_extended(proc_t p, struct mkfifo_extended_args *uap, __unused int32_t *retval)
{
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vnode_attr va;

	AUDIT_ARG(owner, uap->uid, uap->gid);

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
mkfifo(proc_t p, struct mkfifo_args *uap, __unused int32_t *retval)
{
	struct vnode_attr va;

   	VATTR_INIT(&va);
   	VATTR_SET(&va, va_mode, (uap->mode & ALLPERMS) & ~p->p_fd->fd_cmask);

	return(mkfifo1(vfs_context_current(), uap->path, &va));
}


static char *
my_strrchr(char *p, int ch)
{
	char *save;

	for (save = NULL;; ++p) {
		if (*p == ch)
			save = p;
		if (!*p)
			return(save);
	}
	/* NOTREACHED */
}

extern int safe_getpath(struct vnode *dvp, char *leafname, char *path, int _len, int *truncated_path);

int
safe_getpath(struct vnode *dvp, char *leafname, char *path, int _len, int *truncated_path)
{
	int ret, len = _len;

	*truncated_path = 0;
	ret = vn_getpath(dvp, path, &len);
	if (ret == 0 && len < (MAXPATHLEN - 1)) {
		if (leafname) {
			path[len-1] = '/';
			len += strlcpy(&path[len], leafname, MAXPATHLEN-len) + 1;
			if (len > MAXPATHLEN) {
				char *ptr;
			
				// the string got truncated!
				*truncated_path = 1;
				ptr = my_strrchr(path, '/');
				if (ptr) {
					*ptr = '\0';   // chop off the string at the last directory component
				}
				len = strlen(path) + 1;
			}
		}
	} else if (ret == 0) {
		*truncated_path = 1;
	} else if (ret != 0) {
		struct vnode *mydvp=dvp;

		if (ret != ENOSPC) {
			printf("safe_getpath: failed to get the path for vp %p (%s) : err %d\n",
			       dvp, dvp->v_name ? dvp->v_name : "no-name", ret);
		}				
		*truncated_path = 1;
		
		do {
			if (mydvp->v_parent != NULL) {
				mydvp = mydvp->v_parent;
			} else if (mydvp->v_mount) {
				strlcpy(path, mydvp->v_mount->mnt_vfsstat.f_mntonname, _len);
				break;
			} else {
				// no parent and no mount point?  only thing is to punt and say "/" changed
				strlcpy(path, "/", _len);
				len = 2;
				mydvp = NULL;
			}
			
			if (mydvp == NULL) {
				break;
			}

			len = _len;
			ret = vn_getpath(mydvp, path, &len);
		} while (ret == ENOSPC);
	}

	return len;
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
static int
linkat_internal(vfs_context_t ctx, int fd1, user_addr_t path, int fd2,
    user_addr_t link, int flag, enum uio_seg segflg)
{
	vnode_t	vp, dvp, lvp;
	struct nameidata nd;
	int follow;
	int error;
#if CONFIG_FSE
	fse_info finfo;
#endif
	int need_event, has_listeners;
	char *target_path = NULL;
	int truncated=0;

	vp = dvp = lvp = NULLVP;

	/* look up the object we are linking to */
	follow = (flag & AT_SYMLINK_FOLLOW) ? FOLLOW : NOFOLLOW;
	NDINIT(&nd, LOOKUP, OP_LOOKUP, AUDITVNPATH1 | follow,
	    segflg, path, ctx);

	error = nameiat(&nd, fd1);
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
#if CONFIG_TRIGGERS
	nd.ni_op = OP_LINK;
#endif
	nd.ni_cnd.cn_nameiop = CREATE;
	nd.ni_cnd.cn_flags = LOCKPARENT | AUDITVNPATH2 | CN_NBMOUNTLOOK;
	nd.ni_dirp = link;
	error = nameiat(&nd, fd2);
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

#if CONFIG_MACF
	(void)mac_vnode_notify_link(ctx, vp, dvp, &nd.ni_cnd);
#endif

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

		len = safe_getpath(dvp, nd.ni_cnd.cn_nameptr, target_path, MAXPATHLEN, &truncated);

		if (has_listeners) {
		        /* build the path to file we are linking to */
			GET_PATH(link_to_path);
			if (link_to_path == NULL) {
				error = ENOMEM;
				goto out2;
			}

			link_name_len = MAXPATHLEN;
			if (vn_getpath(vp, link_to_path, &link_name_len) == 0) {
				/*
				 * Call out to allow 3rd party notification of rename. 
				 * Ignore result of kauth_authorize_fileop call.
				 */
				kauth_authorize_fileop(vfs_context_ucred(ctx), KAUTH_FILEOP_LINK, 
						       (uintptr_t)link_to_path, 
						       (uintptr_t)target_path);
			}
			if (link_to_path != NULL) {
				RELEASE_PATH(link_to_path);
			}
		}
#if CONFIG_FSE
		if (need_event) {
		        /* construct fsevent */
		        if (get_fse_info(vp, &finfo, ctx) == 0) {
				if (truncated) {
					finfo.mode |= FSE_TRUNCATED_PATH;
				}

			        // build the path to the destination of the link
			        add_fsevent(FSE_CREATE_FILE, ctx,
					    FSE_ARG_STRING, len, target_path,
					    FSE_ARG_FINFO, &finfo,
					    FSE_ARG_DONE);
			}
			if (vp->v_parent) {
			    add_fsevent(FSE_STAT_CHANGED, ctx,
				FSE_ARG_VNODE, vp->v_parent,
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

int
link(__unused proc_t p, struct link_args *uap, __unused int32_t *retval)
{
	return (linkat_internal(vfs_context_current(), AT_FDCWD, uap->path,
	    AT_FDCWD, uap->link, AT_SYMLINK_FOLLOW, UIO_USERSPACE));
}

int
linkat(__unused proc_t p, struct linkat_args *uap, __unused int32_t *retval)
{
	if (uap->flag & ~AT_SYMLINK_FOLLOW)
		return (EINVAL);

	return (linkat_internal(vfs_context_current(), uap->fd1, uap->path,
	    uap->fd2, uap->link, uap->flag, UIO_USERSPACE));
}

/*
 * Make a symbolic link.
 *
 * We could add support for ACLs here too...
 */
/* ARGSUSED */
static int
symlinkat_internal(vfs_context_t ctx, user_addr_t path_data, int fd,
    user_addr_t link, enum uio_seg segflg)
{
	struct vnode_attr va;
	char *path;
	int error;
	struct nameidata nd;
	vnode_t	vp, dvp;
	uint32_t dfflags;	// Directory file flags
	size_t dummy=0;
	proc_t p;

	error = 0;
	if (UIO_SEG_IS_USER_SPACE(segflg)) {
		MALLOC_ZONE(path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
		error = copyinstr(path_data, path, MAXPATHLEN, &dummy);
	} else {
		path = (char *)path_data;
	}
	if (error)
		goto out;
	AUDIT_ARG(text, path);	/* This is the link string */

	NDINIT(&nd, CREATE, OP_SYMLINK, LOCKPARENT | AUDITVNPATH1,
            segflg, link, ctx);

	error = nameiat(&nd, fd);
	if (error)
		goto out;
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	p = vfs_context_proc(ctx);
	VATTR_INIT(&va);
	VATTR_SET(&va, va_type, VLNK);
	VATTR_SET(&va, va_mode, ACCESSPERMS & ~p->p_fd->fd_cmask);

	/*
	 * Handle inheritance of restricted flag
	 */
	error = vnode_flags(dvp, &dfflags, ctx);
	if (error)
		goto skipit;
	if (dfflags & SF_RESTRICTED)
		VATTR_SET(&va, va_flags, SF_RESTRICTED);

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

#if CONFIG_MACF
	if (error == 0)
		error = vnode_label(vnode_mount(vp), dvp, vp, &nd.ni_cnd, VNODE_LABEL_CREATE, ctx);
#endif

	/* do fallback attribute handling */
	if (error == 0)
		error = vnode_setattr_fallback(vp, &va, ctx);

	if (error == 0) {
		int	update_flags = 0;

		if (vp == NULL) {
			nd.ni_cnd.cn_nameiop = LOOKUP;
#if CONFIG_TRIGGERS
			nd.ni_op = OP_LOOKUP;
#endif
			nd.ni_cnd.cn_flags = 0;
			error = nameiat(&nd, fd);
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
	if (path && (path != (char *)path_data))
		FREE_ZONE(path, MAXPATHLEN, M_NAMEI);

	return (error);
}

int
symlink(__unused proc_t p, struct symlink_args *uap, __unused int32_t *retval)
{
	return (symlinkat_internal(vfs_context_current(), uap->path, AT_FDCWD,
	    uap->link, UIO_USERSPACE));
}

int
symlinkat(__unused proc_t p, struct symlinkat_args *uap,
    __unused int32_t *retval)
{
	return (symlinkat_internal(vfs_context_current(), uap->path1, uap->fd,
	    uap->path2, UIO_USERSPACE));
}

/*
 * Delete a whiteout from the filesystem.
 * No longer supported.
 */
int
undelete(__unused proc_t p, __unused struct undelete_args *uap, __unused int32_t *retval)
{
	return (ENOTSUP);
}

/*
 * Delete a name from the filesystem.
 */
/* ARGSUSED */
static int
unlink1at(vfs_context_t ctx, struct nameidata *ndp, int unlink_flags, int fd)
{
	vnode_t	vp, dvp;
	int error;
	struct componentname *cnp;
	char  *path = NULL;
	int  len=0;
#if CONFIG_FSE
	fse_info  finfo;
	struct vnode_attr va;
#endif
	int flags = 0;
	int need_event = 0;
	int has_listeners = 0;
	int truncated_path=0;
	int batched;
	struct vnode_attr *vap = NULL;

#if NAMEDRSRCFORK
	/* unlink or delete is allowed on rsrc forks and named streams */
	ndp->ni_cnd.cn_flags |= CN_ALLOWRSRCFORK;
#endif

	ndp->ni_cnd.cn_flags |= LOCKPARENT;
	ndp->ni_flag |= NAMEI_COMPOUNDREMOVE;
	cnp = &ndp->ni_cnd;

lookup_continue:
	error = nameiat(ndp, fd);
	if (error)
		return (error);

	dvp = ndp->ni_dvp;
	vp = ndp->ni_vp;


	/* With Carbon delete semantics, busy files cannot be deleted */
	if (unlink_flags & VNODE_REMOVE_NODELETEBUSY) {
		flags |= VNODE_REMOVE_NODELETEBUSY;
	}
	
	/* Skip any potential upcalls if told to. */
	if (unlink_flags & VNODE_REMOVE_SKIP_NAMESPACE_EVENT) {
		flags |= VNODE_REMOVE_SKIP_NAMESPACE_EVENT;
	}

	if (vp) {
		batched = vnode_compound_remove_available(vp);
		/*
		 * The root of a mounted filesystem cannot be deleted.
		 */
		if (vp->v_flag & VROOT) {
			error = EBUSY;
		}

		if (!batched) {
			error = vn_authorize_unlink(dvp, vp, cnp, ctx, NULL);
			if (error) {
				goto out;
			}
		}
	} else {
		batched = 1;

		if (!vnode_compound_remove_available(dvp)) {
			panic("No vp, but no compound remove?");
		}
	}

#if CONFIG_FSE
	need_event = need_fsevent(FSE_DELETE, dvp);
	if (need_event) {
		if (!batched) {
			if ((vp->v_flag & VISHARDLINK) == 0) {
				/* XXX need to get these data in batched VNOP */
				get_fse_info(vp, &finfo, ctx);
			}
		} else {
			error = vfs_get_notify_attributes(&va);
			if (error) {
				goto out;
			}

			vap = &va;
		}
	}
#endif
	has_listeners = kauth_authorize_fileop_has_listeners();
	if (need_event || has_listeners) {
		if (path == NULL) {
			GET_PATH(path);
			if (path == NULL) {
				error = ENOMEM;
				goto out;
			}
		}
		len = safe_getpath(dvp, ndp->ni_cnd.cn_nameptr, path, MAXPATHLEN, &truncated_path);
	}

#if NAMEDRSRCFORK
	if (ndp->ni_cnd.cn_flags & CN_WANTSRSRCFORK)
		error = vnode_removenamedstream(dvp, vp, XATTR_RESOURCEFORK_NAME, 0, ctx);
	else
#endif
	{
		error = vn_remove(dvp, &ndp->ni_vp, ndp, flags, vap, ctx);
		vp = ndp->ni_vp;
		if (error == EKEEPLOOKING) {
			if (!batched) {
				panic("EKEEPLOOKING, but not a filesystem that supports compound VNOPs?");
			}

			if ((ndp->ni_flag & NAMEI_CONTLOOKUP) == 0) {
				panic("EKEEPLOOKING, but continue flag not set?");
			}

			if (vnode_isdir(vp)) {
				error = EISDIR;
				goto out;
			}
			goto lookup_continue;
		}
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
			} else if (vap) {
				vnode_get_fse_info_from_vap(vp, &finfo, vap);
			}
			if (truncated_path) {
				finfo.mode |= FSE_TRUNCATED_PATH;
			}
			add_fsevent(FSE_DELETE, ctx,
						FSE_ARG_STRING, len, path,
						FSE_ARG_FINFO, &finfo,
						FSE_ARG_DONE);
		}
#endif
	}

out:
	if (path != NULL)
		RELEASE_PATH(path);

#if NAMEDRSRCFORK
	/* recycle the deleted rsrc fork vnode to force a reclaim, which 
	 * will cause its shadow file to go away if necessary.
	 */
	 if (vp && (vnode_isnamedstream(vp)) &&
		(vp->v_parent != NULLVP) &&
		vnode_isshadow(vp)) {
   			vnode_recycle(vp);
	 }	
#endif
	/*
	 * nameidone has to happen before we vnode_put(dvp)
	 * since it may need to release the fs_nodelock on the dvp
	 */
	nameidone(ndp);
	vnode_put(dvp);
	if (vp) {
		vnode_put(vp);
	}
	return (error);
}

int
unlink1(vfs_context_t ctx, struct nameidata *ndp, int unlink_flags)
{
	return (unlink1at(ctx, ndp, unlink_flags, AT_FDCWD));
}

/*
 * Delete a name from the filesystem using POSIX semantics.
 */
static int
unlinkat_internal(vfs_context_t ctx, int fd, user_addr_t path,
    enum uio_seg segflg)
{
	struct nameidata nd;

	NDINIT(&nd, DELETE, OP_UNLINK, AUDITVNPATH1, segflg,
	       path, ctx);
	return (unlink1at(ctx, &nd, 0, fd));
}

int
unlink(__unused proc_t p, struct unlink_args *uap, __unused int32_t *retval)
{
	return (unlinkat_internal(vfs_context_current(), AT_FDCWD, uap->path,
	    UIO_USERSPACE));
}

int
unlinkat(__unused proc_t p, struct unlinkat_args *uap, __unused int32_t *retval)
{
	if (uap->flag & ~AT_REMOVEDIR)
		return (EINVAL);

	if (uap->flag & AT_REMOVEDIR)
		return (rmdirat_internal(vfs_context_current(), uap->fd,
		    uap->path, UIO_USERSPACE));
	else
		return (unlinkat_internal(vfs_context_current(), uap->fd,
		    uap->path, UIO_USERSPACE));
}

/*
 * Delete a name from the filesystem using Carbon semantics.
 */
int
delete(__unused proc_t p, struct delete_args *uap, __unused int32_t *retval)
{
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, DELETE, OP_UNLINK, AUDITVNPATH1, UIO_USERSPACE,
	       uap->path, ctx);
	return unlink1(ctx, &nd, VNODE_REMOVE_NODELETEBUSY);
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

	/* 
	 * An lseek can affect whether data is "available to read."  Use
	 * hint of NOTE_NONE so no EVFILT_VNODE events fire
	 */
	post_event_if_success(vp, error, NOTE_NONE);
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
 * access_extended: Check access permissions in bulk.
 *
 * Description:	uap->entries		Pointer to an array of accessx
 * 					descriptor structs, plus one or 
 * 					more NULL terminated strings (see 
 * 					"Notes" section below).
 *		uap->size		Size of the area pointed to by
 *					uap->entries.
 *		uap->results		Pointer to the results array.
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
 *		of accessx descriptors, followed by one or more NULL terminated
 *		strings
 *
 *			struct accessx_descriptor[0]
 *			...
 *			struct accessx_descriptor[n]
 *			char name_data[0];
 *
 *		We determine the entry count by walking the buffer containing
 *		the uap->entries argument descriptor.  For each descriptor we
 *		see, the valid values for the offset ad_name_offset will be
 *		in the byte range:
 *
 *			[ uap->entries + sizeof(struct accessx_descriptor) ]
 *						to
 *				[ uap->entries + uap->size - 2 ]
 *
 *		since we must have at least one string, and the string must
 *		be at least one character plus the NULL terminator in length.
 *		
 * XXX:		Need to support the check-as uid argument
 */
int
access_extended(__unused proc_t p, struct access_extended_args *uap, __unused int32_t *retval)
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

	AUDIT_ARG(opaque, input, uap->size);

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
			NDINIT(&nd, LOOKUP, OP_ACCESS, niopts, UIO_SYSSPACE,
			       CAST_USER_ADDR_T(((const char *)input) + input[i].ad_name_offset),
			       &context);
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

	AUDIT_ARG(data, result, sizeof(errno_t), desc_actual);

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
static int
faccessat_internal(vfs_context_t ctx, int fd, user_addr_t path, int amode,
    int flag, enum uio_seg segflg)
{
	int error;
	struct nameidata nd;
 	int niopts;
	struct vfs_context context;
#if NAMEDRSRCFORK
	int is_namedstream = 0;
#endif

 	/*
	 * Unless the AT_EACCESS option is used, Access is defined as checking
	 * against the process' real identity, even if operations are checking
	 * the effective identity.  So we need to tweak the credential
 	 * in the context for that case.
 	 */
	if (!(flag & AT_EACCESS))
		context.vc_ucred = kauth_cred_copy_real(kauth_cred_get());
	else
		context.vc_ucred = ctx->vc_ucred;
	context.vc_thread = ctx->vc_thread;


	niopts = FOLLOW | AUDITVNPATH1;
 	/* need parent for vnode_authorize for deletion test */
 	if (amode & _DELETE_OK)
 		niopts |= WANTPARENT;
 	NDINIT(&nd, LOOKUP, OP_ACCESS, niopts, segflg,
	       path, &context);

#if NAMEDRSRCFORK
	/* access(F_OK) calls are allowed for resource forks. */
	if (amode == F_OK)
		nd.ni_cnd.cn_flags |= CN_ALLOWRSRCFORK;
#endif
 	error = nameiat(&nd, fd);
 	if (error)
 		goto out;

#if NAMEDRSRCFORK
	/* Grab reference on the shadow stream file vnode to 
	 * force an inactive on release which will mark it
	 * for recycle.
	 */
	if (vnode_isnamedstream(nd.ni_vp) &&
	    (nd.ni_vp->v_parent != NULLVP) &&
	    vnode_isshadow(nd.ni_vp)) {
		is_namedstream = 1;
		vnode_ref(nd.ni_vp);
	}
#endif

	error = access1(nd.ni_vp, nd.ni_dvp, amode, &context);

#if NAMEDRSRCFORK
	if (is_namedstream) {
		vnode_rele(nd.ni_vp);
	}
#endif

 	vnode_put(nd.ni_vp);
	if (amode & _DELETE_OK)
 		vnode_put(nd.ni_dvp);
  	nameidone(&nd);
  
out:
	if (!(flag & AT_EACCESS))
		kauth_cred_unref(&context.vc_ucred);
	return (error);
}

int
access(__unused proc_t p, struct access_args *uap, __unused int32_t *retval)
{
	return (faccessat_internal(vfs_context_current(), AT_FDCWD,
	    uap->path, uap->flags, 0, UIO_USERSPACE));
}

int
faccessat(__unused proc_t p, struct faccessat_args *uap,
          __unused int32_t *retval)
{
	if (uap->flag & ~AT_EACCESS)
		return (EINVAL);

	return (faccessat_internal(vfs_context_current(), uap->fd,
	    uap->path, uap->amode, uap->flag, UIO_USERSPACE));
}

/*
 * Returns:	0			Success
 *		EFAULT
 *	copyout:EFAULT
 *	namei:???
 *	vn_stat:???
 */
static int
fstatat_internal(vfs_context_t ctx, user_addr_t path, user_addr_t ub,
    user_addr_t xsecurity, user_addr_t xsecurity_size, int isstat64,
    enum uio_seg segflg, int fd, int flag)
{
	struct nameidata nd;
	int follow;
	union {
		struct stat sb;
		struct stat64 sb64;
	} source;
	union {
		struct user64_stat user64_sb;
		struct user32_stat user32_sb;
		struct user64_stat64 user64_sb64;
		struct user32_stat64 user32_sb64;
	} dest;
	caddr_t sbp;
	int error, my_size;
	kauth_filesec_t fsec;
	size_t xsecurity_bufsize;
	void * statptr;

	follow = (flag & AT_SYMLINK_NOFOLLOW) ? NOFOLLOW : FOLLOW;
	NDINIT(&nd, LOOKUP, OP_GETATTR, follow | AUDITVNPATH1,
	    segflg, path, ctx);

#if NAMEDRSRCFORK
	int is_namedstream = 0;
	/* stat calls are allowed for resource forks. */
	nd.ni_cnd.cn_flags |= CN_ALLOWRSRCFORK;
#endif
	error = nameiat(&nd, fd);
	if (error)
		return (error);
	fsec = KAUTH_FILESEC_NONE;

	statptr = (void *)&source;

#if NAMEDRSRCFORK
	/* Grab reference on the shadow stream file vnode to 
	 * force an inactive on release which will mark it 
	 * for recycle.
	 */
	if (vnode_isnamedstream(nd.ni_vp) &&
	    (nd.ni_vp->v_parent != NULLVP) &&
	    vnode_isshadow(nd.ni_vp)) {
		is_namedstream = 1;
		vnode_ref(nd.ni_vp);
	}
#endif

	error = vn_stat(nd.ni_vp, statptr, (xsecurity != USER_ADDR_NULL ? &fsec : NULL), isstat64, ctx);

#if NAMEDRSRCFORK
	if (is_namedstream) {
		vnode_rele(nd.ni_vp);
	}
#endif
	vnode_put(nd.ni_vp);
	nameidone(&nd);

	if (error)
		return (error);
	/* Zap spare fields */
	if (isstat64 != 0) {
		source.sb64.st_lspare = 0;
		source.sb64.st_qspare[0] = 0LL;
		source.sb64.st_qspare[1] = 0LL;
		if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
			munge_user64_stat64(&source.sb64, &dest.user64_sb64); 
			my_size = sizeof(dest.user64_sb64);
			sbp = (caddr_t)&dest.user64_sb64;
		} else {
			munge_user32_stat64(&source.sb64, &dest.user32_sb64); 
			my_size = sizeof(dest.user32_sb64);
			sbp = (caddr_t)&dest.user32_sb64;
		}
		/*
		 * Check if we raced (post lookup) against the last unlink of a file.
		 */
		if ((source.sb64.st_nlink == 0) && S_ISREG(source.sb64.st_mode)) {
			source.sb64.st_nlink = 1;
		}
	} else {
		source.sb.st_lspare = 0;
		source.sb.st_qspare[0] = 0LL;
		source.sb.st_qspare[1] = 0LL;
		if (IS_64BIT_PROCESS(vfs_context_proc(ctx))) {
			munge_user64_stat(&source.sb, &dest.user64_sb); 
			my_size = sizeof(dest.user64_sb);
			sbp = (caddr_t)&dest.user64_sb;
		} else {
			munge_user32_stat(&source.sb, &dest.user32_sb); 
			my_size = sizeof(dest.user32_sb);
			sbp = (caddr_t)&dest.user32_sb;
		}

		/*
		 * Check if we raced (post lookup) against the last unlink of a file.
		 */
		if ((source.sb.st_nlink == 0) && S_ISREG(source.sb.st_mode)) {
			source.sb.st_nlink = 1;
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
 * stat_extended: Get file status; with extended security (ACL).
 *
 * Parameters:    p                       (ignored)
 *                uap                     User argument descriptor (see below)
 *                retval                  (ignored) 
 *
 * Indirect:      uap->path               Path of file to get status from
 *                uap->ub                 User buffer (holds file status info)
 *                uap->xsecurity          ACL to get (extended security)
 *                uap->xsecurity_size     Size of ACL
 *                
 * Returns:        0                      Success
 *                !0                      errno value
 *
 */
int
stat_extended(__unused proc_t p, struct stat_extended_args *uap,
    __unused int32_t *retval)
{
	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    uap->xsecurity, uap->xsecurity_size, 0, UIO_USERSPACE, AT_FDCWD,
	    0));
}

/*
 * Returns:	0			Success
 *	fstatat_internal:???		[see fstatat_internal() in this file]
 */
int
stat(__unused proc_t p, struct stat_args *uap, __unused int32_t *retval)
{
	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    0, 0, 0, UIO_USERSPACE, AT_FDCWD, 0));
}

int
stat64(__unused proc_t p, struct stat64_args *uap, __unused int32_t *retval)
{
	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    0, 0, 1, UIO_USERSPACE, AT_FDCWD, 0));
}

/*
 * stat64_extended: Get file status; can handle large inode numbers; with extended security (ACL).
 *
 * Parameters:    p                       (ignored)
 *                uap                     User argument descriptor (see below)
 *                retval                  (ignored) 
 *
 * Indirect:      uap->path               Path of file to get status from
 *                uap->ub                 User buffer (holds file status info)
 *                uap->xsecurity          ACL to get (extended security)
 *                uap->xsecurity_size     Size of ACL
 *                
 * Returns:        0                      Success
 *                !0                      errno value
 *
 */
int
stat64_extended(__unused proc_t p, struct stat64_extended_args *uap, __unused int32_t *retval)
{
	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    uap->xsecurity, uap->xsecurity_size, 1, UIO_USERSPACE, AT_FDCWD,
	    0));
}

/*
 * lstat_extended: Get file status; does not follow links; with extended security (ACL).
 *
 * Parameters:    p                       (ignored)
 *                uap                     User argument descriptor (see below)
 *                retval                  (ignored) 
 *
 * Indirect:      uap->path               Path of file to get status from
 *                uap->ub                 User buffer (holds file status info)
 *                uap->xsecurity          ACL to get (extended security)
 *                uap->xsecurity_size     Size of ACL
 *                
 * Returns:        0                      Success
 *                !0                      errno value
 *
 */
int
lstat_extended(__unused proc_t p, struct lstat_extended_args *uap, __unused int32_t *retval)
{
	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    uap->xsecurity, uap->xsecurity_size, 0, UIO_USERSPACE, AT_FDCWD,
	    AT_SYMLINK_NOFOLLOW));
}

/*
 * Get file status; this version does not follow links.
 */
int
lstat(__unused proc_t p, struct lstat_args *uap, __unused int32_t *retval)
{
	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    0, 0, 0, UIO_USERSPACE, AT_FDCWD, AT_SYMLINK_NOFOLLOW));
}

int
lstat64(__unused proc_t p, struct lstat64_args *uap, __unused int32_t *retval)
{
	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    0, 0, 1, UIO_USERSPACE, AT_FDCWD, AT_SYMLINK_NOFOLLOW));
}

/*
 * lstat64_extended: Get file status; can handle large inode numbers; does not
 * follow links; with extended security (ACL).
 *
 * Parameters:    p                       (ignored)
 *                uap                     User argument descriptor (see below)
 *                retval                  (ignored) 
 *
 * Indirect:      uap->path               Path of file to get status from
 *                uap->ub                 User buffer (holds file status info)
 *                uap->xsecurity          ACL to get (extended security)
 *                uap->xsecurity_size     Size of ACL
 *                
 * Returns:        0                      Success
 *                !0                      errno value
 *
 */
int
lstat64_extended(__unused proc_t p, struct lstat64_extended_args *uap, __unused int32_t *retval)
{
	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    uap->xsecurity, uap->xsecurity_size, 1, UIO_USERSPACE, AT_FDCWD,
	    AT_SYMLINK_NOFOLLOW));
}

int
fstatat(__unused proc_t p, struct fstatat_args *uap, __unused int32_t *retval)
{
	if (uap->flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    0, 0, 0, UIO_USERSPACE, uap->fd, uap->flag));
}

int
fstatat64(__unused proc_t p, struct fstatat64_args *uap,
    __unused int32_t *retval)
{
	if (uap->flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (fstatat_internal(vfs_context_current(), uap->path, uap->ub,
	    0, 0, 1, UIO_USERSPACE, uap->fd, uap->flag));
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
pathconf(__unused proc_t p, struct pathconf_args *uap, int32_t *retval)
{
	int error;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();

	NDINIT(&nd, LOOKUP, OP_PATHCONF, FOLLOW | AUDITVNPATH1, 
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
static int
readlinkat_internal(vfs_context_t ctx, int fd, user_addr_t path,
    enum uio_seg seg, user_addr_t buf, size_t bufsize, enum uio_seg bufseg,
    int *retval)
{
	vnode_t vp;
	uio_t auio;
	int error;
	struct nameidata nd;
	char uio_buf[ UIO_SIZEOF(1) ];

	NDINIT(&nd, LOOKUP, OP_READLINK, NOFOLLOW | AUDITVNPATH1,
	    seg, path, ctx);

	error = nameiat(&nd, fd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	auio = uio_createwithbuffer(1, 0, bufseg, UIO_READ,
                                    &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, buf, bufsize);
	if (vp->v_type != VLNK) {
		error = EINVAL;
	} else {
#if CONFIG_MACF
		error = mac_vnode_check_readlink(ctx, vp);
#endif
		if (error == 0)
			error = vnode_authorize(vp, NULL, KAUTH_VNODE_READ_DATA,
			                        ctx);
		if (error == 0)
			error = VNOP_READLINK(vp, auio, ctx);
	}
	vnode_put(vp);

	*retval = bufsize - (int)uio_resid(auio);
	return (error);
}

int
readlink(proc_t p, struct readlink_args *uap, int32_t *retval)
{
	enum uio_seg procseg;

	procseg = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	return (readlinkat_internal(vfs_context_current(), AT_FDCWD,
	    CAST_USER_ADDR_T(uap->path), procseg, CAST_USER_ADDR_T(uap->buf),
	    uap->count, procseg, retval));
}

int
readlinkat(proc_t p, struct readlinkat_args *uap, int32_t *retval)
{
	enum uio_seg procseg;

	procseg = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	return (readlinkat_internal(vfs_context_current(), uap->fd, uap->path,
	    procseg, uap->buf, uap->bufsize, procseg, retval));
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
chflags(__unused proc_t p, struct chflags_args *uap, __unused int32_t *retval)
{
	vnode_t vp;
	vfs_context_t ctx = vfs_context_current();
	int error;
	struct nameidata nd;

	AUDIT_ARG(fflags, uap->flags);
	NDINIT(&nd, LOOKUP, OP_SETATTR, FOLLOW | AUDITVNPATH1, 
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
fchflags(__unused proc_t p, struct fchflags_args *uap, __unused int32_t *retval)
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
chmod_vnode(vfs_context_t ctx, vnode_t vp, struct vnode_attr *vap)
{
	kauth_action_t action;
	int error;
	
	AUDIT_ARG(mode, vap->va_mode);
	/* XXX audit new args */

#if NAMEDSTREAMS
	/* chmod calls are not allowed for resource forks. */
	if (vp->v_flag & VISNAMEDSTREAM) {
		return (EPERM);
	}
#endif

#if CONFIG_MACF
	if (VATTR_IS_ACTIVE(vap, va_mode) &&
	    (error = mac_vnode_check_setmode(ctx, vp, (mode_t)vap->va_mode)) != 0)
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
 * Change mode of a file given a path name.
 *
 * Returns:	0			Success
 *		namei:???		[anything namei can return]
 *		chmod_vnode:???		[anything chmod_vnode can return]
 */
static int
chmodat(vfs_context_t ctx, user_addr_t path, struct vnode_attr *vap,
    int fd, int flag, enum uio_seg segflg)
{
	struct nameidata nd;
	int follow, error;

	follow = (flag & AT_SYMLINK_NOFOLLOW) ? NOFOLLOW : FOLLOW;
	NDINIT(&nd, LOOKUP, OP_SETATTR, follow | AUDITVNPATH1,
	    segflg, path, ctx);
	if ((error = nameiat(&nd, fd)))
		return (error);
	error = chmod_vnode(ctx, nd.ni_vp, vap);
	vnode_put(nd.ni_vp);
	nameidone(&nd);
	return(error);
}

/*
 * chmod_extended: Change the mode of a file given a path name; with extended 
 * argument list (including extended security (ACL)).
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
chmod_extended(__unused proc_t p, struct chmod_extended_args *uap, __unused int32_t *retval)
{
	int error;
	struct vnode_attr va;
	kauth_filesec_t xsecdst;

	AUDIT_ARG(owner, uap->uid, uap->gid);

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

	error = chmodat(vfs_context_current(), uap->path, &va, AT_FDCWD, 0,
	    UIO_USERSPACE);

	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);
	return(error);
}

/*
 * Returns:	0			Success
 *		chmodat:???		[anything chmodat can return]
 */
static int
fchmodat_internal(vfs_context_t ctx, user_addr_t path, int mode, int fd,
    int flag, enum uio_seg segflg)
{
	struct vnode_attr va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, mode & ALLPERMS);

	return (chmodat(ctx, path, &va, fd, flag, segflg));
}

int
chmod(__unused proc_t p, struct chmod_args *uap, __unused int32_t *retval)
{
	return (fchmodat_internal(vfs_context_current(), uap->path, uap->mode,
	    AT_FDCWD, 0, UIO_USERSPACE));
}

int
fchmodat(__unused proc_t p, struct fchmodat_args *uap, __unused int32_t *retval)
{
	if (uap->flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (fchmodat_internal(vfs_context_current(), uap->path, uap->mode,
	    uap->fd, uap->flag, UIO_USERSPACE));
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

	error = chmod_vnode(vfs_context_current(), vp, vap);
	(void)vnode_put(vp);
	file_drop(fd);

	return (error);
}

/*
 * fchmod_extended: Change mode of a file given a file descriptor; with
 * extended argument list (including extended security (ACL)).
 *
 * Parameters:    p                       Process requesting to change file mode
 *                uap                     User argument descriptor (see below)
 *                retval                  (ignored) 
 *
 * Indirect:      uap->mode               File mode to set (same as 'chmod')
 *                uap->uid                UID to set
 *                uap->gid                GID to set
 *                uap->xsecurity          ACL to set (or delete)
 *                uap->fd                 File descriptor of file to change mode
 *            
 * Returns:        0                      Success
 *                !0                      errno value
 *
 */
int
fchmod_extended(proc_t p, struct fchmod_extended_args *uap, __unused int32_t *retval)
{
	int error;
	struct vnode_attr va;
	kauth_filesec_t xsecdst;

	AUDIT_ARG(owner, uap->uid, uap->gid);

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
	case CAST_USER_ADDR_T((void *)1):	/* _FILESEC_REMOVE_ACL */
		VATTR_SET(&va, va_acl, NULL);
		break;
		/* not being set */
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
fchmod(proc_t p, struct fchmod_args *uap, __unused int32_t *retval)
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
fchownat_internal(vfs_context_t ctx, int fd, user_addr_t path, uid_t uid,
   gid_t gid, int flag, enum uio_seg segflg)
{
	vnode_t vp;
	struct vnode_attr va;
	int error;
	struct nameidata nd;
	int follow;
	kauth_action_t action;

	AUDIT_ARG(owner, uid, gid);

	follow = (flag & AT_SYMLINK_NOFOLLOW) ? NOFOLLOW : FOLLOW;
	NDINIT(&nd, LOOKUP, OP_SETATTR, follow | AUDITVNPATH1, segflg,
	    path, ctx);
	error = nameiat(&nd, fd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	VATTR_INIT(&va);
	if (uid != (uid_t)VNOVAL)
		VATTR_SET(&va, va_uid, uid);
	if (gid != (gid_t)VNOVAL)
		VATTR_SET(&va, va_gid, gid);

#if CONFIG_MACF
	error = mac_vnode_check_setowner(ctx, vp, uid, gid);
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
chown(__unused proc_t p, struct chown_args *uap, __unused int32_t *retval)
{
	return (fchownat_internal(vfs_context_current(), AT_FDCWD, uap->path,
	    uap->uid, uap->gid, 0, UIO_USERSPACE));
}

int
lchown(__unused proc_t p, struct lchown_args *uap, __unused int32_t *retval)
{
	return (fchownat_internal(vfs_context_current(), AT_FDCWD, uap->path,
	    uap->owner, uap->group, AT_SYMLINK_NOFOLLOW, UIO_USERSPACE));
}

int
fchownat(__unused proc_t p, struct fchownat_args *uap, __unused int32_t *retval)
{
	if (uap->flag & ~AT_SYMLINK_NOFOLLOW)
		return (EINVAL);

	return (fchownat_internal(vfs_context_current(), uap->fd, uap->path,
	    uap->uid, uap->gid, uap->flag, UIO_USERSPACE));
}

/*
 * Set ownership given a file descriptor.
 */
/* ARGSUSED */
int
fchown(__unused proc_t p, struct fchown_args *uap, __unused int32_t *retval)
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
	int error;

	if (usrtvp == USER_ADDR_NULL) {
		struct timeval old_tv;
		/* XXX Y2038 bug because of microtime argument */
		microtime(&old_tv);
		TIMEVAL_TO_TIMESPEC(&old_tv, &tsp[0]);
		tsp[1] = tsp[0];
	} else {
		if (IS_64BIT_PROCESS(current_proc())) {
			struct user64_timeval tv[2];
			error = copyin(usrtvp, (void *)tv, sizeof(tv));
			if (error)
				return (error);
			TIMEVAL_TO_TIMESPEC(&tv[0], &tsp[0]);
			TIMEVAL_TO_TIMESPEC(&tv[1], &tsp[1]);
		} else {
			struct user32_timeval tv[2];
			error = copyin(usrtvp, (void *)tv, sizeof(tv));
			if (error)
				return (error);
			TIMEVAL_TO_TIMESPEC(&tv[0], &tsp[0]);
			TIMEVAL_TO_TIMESPEC(&tv[1], &tsp[1]);
		}
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
utimes(__unused proc_t p, struct utimes_args *uap, __unused int32_t *retval)
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
	NDINIT(&nd, LOOKUP, OP_SETATTR, FOLLOW | AUDITVNPATH1, 
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
futimes(__unused proc_t p, struct futimes_args *uap, __unused int32_t *retval)
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
truncate(__unused proc_t p, struct truncate_args *uap, __unused int32_t *retval)
{
	vnode_t vp;
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	int error;
	struct nameidata nd;
	kauth_action_t action;

	if (uap->length < 0)
		return(EINVAL);
	NDINIT(&nd, LOOKUP, OP_TRUNCATE, FOLLOW | AUDITVNPATH1, 
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
ftruncate(proc_t p, struct ftruncate_args *uap, int32_t *retval)
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

	switch (FILEGLOB_DTYPE(fp->f_fglob)) {
	case DTYPE_PSXSHM:
		error = pshm_truncate(p, fp, uap->fd, uap->length, retval);
		goto out;
	case DTYPE_VNODE:
		break;
	default:
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
 * Sync an open file with synchronized I/O _file_ integrity completion
 */
/* ARGSUSED */
int
fsync(proc_t p, struct fsync_args *uap, __unused int32_t *retval)
{
	__pthread_testcancel(1);
	return(fsync_common(p, uap, MNT_WAIT));
}


/*
 * Sync an open file with synchronized I/O _file_ integrity completion
 *
 * Notes:	This is a legacy support function that does not test for
 *		thread cancellation points.
 */
/* ARGSUSED */
int 
fsync_nocancel(proc_t p, struct fsync_nocancel_args *uap, __unused int32_t *retval)
{
	return(fsync_common(p, (struct fsync_args *)uap, MNT_WAIT));
}


/*
 * Sync an open file with synchronized I/O _data_ integrity completion
 */
/* ARGSUSED */
int
fdatasync(proc_t p, struct fdatasync_args *uap, __unused int32_t *retval)
{
	__pthread_testcancel(1);
	return(fsync_common(p, (struct fsync_args *)uap, MNT_DWAIT));
}


/*
 * fsync_common
 *
 * Common fsync code to support both synchronized I/O file integrity completion
 * (normal fsync) and synchronized I/O data integrity completion (fdatasync).
 *
 * If 'flags' is MNT_DWAIT, the caller is requesting data integrity, which
 * will only guarantee that the file data contents are retrievable.  If
 * 'flags' is MNT_WAIT, the caller is rewuesting file integrity, which also
 * includes additional metadata unnecessary for retrieving the file data
 * contents, such as atime, mtime, ctime, etc., also be committed to stable
 * storage.
 *
 * Parameters:	p				The process
 *		uap->fd				The descriptor to synchronize
 *		flags				The data integrity flags
 *
 * Returns:	int				Success
 *	fp_getfvp:EBADF				Bad file descriptor
 *	fp_getfvp:ENOTSUP			fd does not refer to a vnode
 *	VNOP_FSYNC:???				unspecified
 *
 * Notes:	We use struct fsync_args because it is a short name, and all
 *		caller argument structures are otherwise identical.
 */
static int
fsync_common(proc_t p, struct fsync_args *uap, int flags)
{
	vnode_t vp;
	struct fileproc *fp;
	vfs_context_t ctx = vfs_context_current();
	int error;

	AUDIT_ARG(fd, uap->fd);

	if ( (error = fp_getfvp(p, uap->fd, &fp, &vp)) )
		return (error);
	if ( (error = vnode_getwithref(vp)) ) {
		file_drop(uap->fd);
		return(error);
	}

	AUDIT_ARG(vnpath, vp, ARG_VNODE1);

	error = VNOP_FSYNC(vp, flags, ctx);

#if NAMEDRSRCFORK
	/* Sync resource fork shadow file if necessary. */
	if ((error == 0) &&
	    (vp->v_flag & VISNAMEDSTREAM) && 
	    (vp->v_parent != NULLVP) &&
	    vnode_isshadow(vp) &&
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
copyfile(__unused proc_t p, struct copyfile_args *uap, __unused int32_t *retval)
{
	vnode_t tvp, fvp, tdvp, sdvp;
	struct nameidata fromnd, tond;
	int error;
	vfs_context_t ctx = vfs_context_current();

	/* Check that the flags are valid. */

	if (uap->flags & ~CPF_MASK) {
		return(EINVAL);
	}

	NDINIT(&fromnd, LOOKUP, OP_COPYFILE, SAVESTART | AUDITVNPATH1,
		UIO_USERSPACE, uap->from, ctx);
	if ((error = namei(&fromnd)))
		return (error);
	fvp = fromnd.ni_vp;

	NDINIT(&tond, CREATE, OP_LINK,
	       LOCKPARENT | LOCKLEAF | NOCACHE | SAVESTART | AUDITVNPATH2 | CN_NBMOUNTLOOK,
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
static int
renameat_internal(vfs_context_t ctx, int fromfd, user_addr_t from,
    int tofd, user_addr_t to, int segflg, vfs_rename_flags_t flags)
{
	vnode_t tvp, tdvp;
	vnode_t fvp, fdvp;
	struct nameidata *fromnd, *tond;
	int error;
	int do_retry;
	int mntrename;
	int need_event;
	const char *oname = NULL;
	char *from_name = NULL, *to_name = NULL;
	int from_len=0, to_len=0;
	int holding_mntlock;
	mount_t locked_mp = NULL;
	vnode_t oparent = NULLVP;
#if CONFIG_FSE
	fse_info from_finfo, to_finfo;
#endif
	int from_truncated=0, to_truncated;
	int batched = 0;
	struct vnode_attr *fvap, *tvap;
	int continuing = 0;
	/* carving out a chunk for structs that are too big to be on stack. */
	struct {
		struct nameidata from_node, to_node;
		struct vnode_attr fv_attr, tv_attr;
	} * __rename_data;
	MALLOC(__rename_data, void *, sizeof(*__rename_data), M_TEMP, M_WAITOK);
	fromnd = &__rename_data->from_node;
	tond = &__rename_data->to_node;

	holding_mntlock = 0;
	do_retry = 0;
retry:
	fvp = tvp = NULL;
	fdvp = tdvp = NULL;
	fvap = tvap = NULL;
	mntrename = FALSE;

	NDINIT(fromnd, DELETE, OP_UNLINK, WANTPARENT | AUDITVNPATH1,
	    segflg, from, ctx);
	fromnd->ni_flag = NAMEI_COMPOUNDRENAME;

	NDINIT(tond, RENAME, OP_RENAME, WANTPARENT | AUDITVNPATH2 | CN_NBMOUNTLOOK,
	    segflg, to, ctx);
	tond->ni_flag = NAMEI_COMPOUNDRENAME;

continue_lookup:
	if ((fromnd->ni_flag & NAMEI_CONTLOOKUP) != 0 || !continuing) {
		if ( (error = nameiat(fromnd, fromfd)) )
			goto out1;
		fdvp = fromnd->ni_dvp;
		fvp  = fromnd->ni_vp;

		if (fvp && fvp->v_type == VDIR)
			tond->ni_cnd.cn_flags |= WILLBEDIR;
	}

	if ((tond->ni_flag & NAMEI_CONTLOOKUP) != 0 || !continuing) {
		if ( (error = nameiat(tond, tofd)) ) {
			/*
			 * Translate error code for rename("dir1", "dir2/.").
			 */
			if (error == EISDIR && fvp->v_type == VDIR)
				error = EINVAL;
			goto out1;
		}
		tdvp = tond->ni_dvp;
		tvp  = tond->ni_vp;
	}

	batched = vnode_compound_rename_available(fdvp);
	if (!fvp) {
		/*
		 * Claim: this check will never reject a valid rename.
		 * For success, either fvp must be on the same mount as tdvp, or fvp must sit atop a vnode on the same mount as tdvp.
		 * Suppose fdvp and tdvp are not on the same mount.
		 * If fvp is on the same mount as tdvp, then fvp is not on the same mount as fdvp, so fvp is the root of its filesystem.  If fvp is the root,
		 * 	then you can't move it to within another dir on the same mountpoint.
		 * If fvp sits atop a vnode on the same mount as fdvp, then that vnode must be part of the same mount as fdvp, which is a contradiction.
		 *
		 * If this check passes, then we are safe to pass these vnodes to the same FS.
		 */
		if (fdvp->v_mount != tdvp->v_mount) {
			error = EXDEV;
			goto out1;
		}
		goto skipped_lookup;
	}

	if (!batched) {
		error = vn_authorize_rename(fdvp, fvp, &fromnd->ni_cnd, tdvp, tvp, &tond->ni_cnd, ctx, NULL);
		if (error) {
			if (error == ENOENT) {
				/*
				 * We encountered a race where after doing the namei, tvp stops
				 * being valid. If so, simply re-drive the rename call from the
				 * top.
				 */
				do_retry = 1;
			}
			goto out1;
		}
	}

        /*
         * If the source and destination are the same (i.e. they're
         * links to the same vnode) and the target file system is
         * case sensitive, then there is nothing to do.
	 *
	 * XXX Come back to this.
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
	 * Allow the renaming of mount points.
	 * - target must not exist
	 * - target must reside in the same directory as source
	 * - union mounts cannot be renamed
	 * - "/" cannot be renamed
	 *
	 * XXX Handle this in VFS after a continued lookup (if we missed
	 * in the cache to start off)
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
	 * NOTE - that fvp == tvp also occurs if they are hard linked and
	 * that correct behaviour then is just to return success without doing
	 * anything.
	 *
	 * XXX filesystem should take care of this itself, perhaps...
	 */
	if (fvp == tvp && fdvp == tdvp) {
		if (fromnd->ni_cnd.cn_namelen == tond->ni_cnd.cn_namelen &&
	       	    !bcmp(fromnd->ni_cnd.cn_nameptr, tond->ni_cnd.cn_nameptr,
			  fromnd->ni_cnd.cn_namelen)) {
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
			nameidone(tond);

			if (tvp)
			        vnode_put(tvp);
			vnode_put(tdvp);

			/*
			 * nameidone has to happen before we vnode_put(fdvp)
			 * since it may need to release the fs_nodelock on the fvp
			 */
			nameidone(fromnd);

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

skipped_lookup:
#if CONFIG_FSE
	need_event = need_fsevent(FSE_RENAME, fdvp);
	if (need_event) {
		if (fvp) {
			get_fse_info(fvp, &from_finfo, ctx);
		} else {
			error = vfs_get_notify_attributes(&__rename_data->fv_attr);
			if (error) {
				goto out1;
			}

			fvap = &__rename_data->fv_attr;
		}

		if (tvp) {
		        get_fse_info(tvp, &to_finfo, ctx);
		} else if (batched) {
			error = vfs_get_notify_attributes(&__rename_data->tv_attr);
			if (error) {
				goto out1;
			}

			tvap = &__rename_data->tv_attr;
		}
	}
#else
	need_event = 0;
#endif /* CONFIG_FSE */

	if (need_event || kauth_authorize_fileop_has_listeners()) {
		if (from_name == NULL) {
			GET_PATH(from_name);
			if (from_name == NULL) {
				error = ENOMEM;
				goto out1;
			}
		}

		from_len = safe_getpath(fdvp, fromnd->ni_cnd.cn_nameptr, from_name, MAXPATHLEN, &from_truncated);

		if (to_name == NULL) {
			GET_PATH(to_name);
			if (to_name == NULL) {
				error = ENOMEM;
				goto out1;
			}
		}

		to_len = safe_getpath(tdvp, tond->ni_cnd.cn_nameptr, to_name, MAXPATHLEN, &to_truncated);
	}
#if CONFIG_SECLUDED_RENAME
	if (flags & VFS_SECLUDE_RENAME) {
		fromnd->ni_cnd.cn_flags |=  CN_SECLUDE_RENAME;
	}
#else
	#pragma unused(flags)
#endif
	error = vn_rename(fdvp, &fvp, &fromnd->ni_cnd, fvap,
			    tdvp, &tvp, &tond->ni_cnd, tvap,
			    0, ctx);

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
		if (error == EKEEPLOOKING) {
			if ((fromnd->ni_flag & NAMEI_CONTLOOKUP) == 0) {
				if ((tond->ni_flag & NAMEI_CONTLOOKUP) == 0) {
					panic("EKEEPLOOKING without NAMEI_CONTLOOKUP on either ndp?");
				}
			}

			fromnd->ni_vp = fvp;
			tond->ni_vp = tvp;

			goto continue_lookup;
		}

		/*
		 * We may encounter a race in the VNOP where the destination didn't
		 * exist when we did the namei, but it does by the time we go and
		 * try to create the entry. In this case, we should re-drive this rename
		 * call from the top again.  Currently, only HFS bubbles out ERECYCLE,
		 * but other filesystems susceptible to this race could return it, too.
		 */
		if (error == ERECYCLE) {
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
		if (from_truncated || to_truncated) {
			// set it here since only the from_finfo gets reported up to user space
			from_finfo.mode |= FSE_TRUNCATED_PATH;
		}

		if (tvap && tvp) {
			vnode_get_fse_info_from_vap(tvp, &to_finfo, tvap);
		}
		if (fvap) {
			vnode_get_fse_info_from_vap(fvp, &from_finfo, fvap);
		}

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

		if (UIO_SEG_IS_USER_SPACE(segflg))
			error = copyinstr(to, tobuf, MAXPATHLEN, &len);
		else
			error = copystr((void *)to, tobuf, MAXPATHLEN, &len);
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
	 *
	 * XXX oparent and oname may not be set in the compound vnop case
	 */
	if (batched || (oname == fvp->v_name && oparent == fvp->v_parent)) {
	        int update_flags;

	        update_flags = VNODE_UPDATE_NAME;

		if (fdvp != tdvp)
		        update_flags |= VNODE_UPDATE_PARENT;

	        vnode_update_identity(fvp, tdvp, tond->ni_cnd.cn_nameptr, tond->ni_cnd.cn_namelen, tond->ni_cnd.cn_hash, update_flags);
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
		nameidone(tond);

		if (tvp)
		        vnode_put(tvp);
	        vnode_put(tdvp);
	}
	if (fdvp) {
		/*
		 * nameidone has to happen before we vnode_put(fdvp)
		 * since it may need to release the fs_nodelock on the fdvp
		 */
		nameidone(fromnd);

		if (fvp)
		        vnode_put(fvp);
	        vnode_put(fdvp);
	}

	/*
	 * If things changed after we did the namei, then we will re-drive
	 * this rename call from the top.
	 */
	if (do_retry) {
		do_retry = 0;
		goto retry;
	}

	FREE(__rename_data, M_TEMP);
	return (error);
}

int
rename(__unused proc_t p, struct rename_args *uap, __unused int32_t *retval)
{
	return (renameat_internal(vfs_context_current(), AT_FDCWD, uap->from,
	    AT_FDCWD, uap->to, UIO_USERSPACE, 0));
}

#if CONFIG_SECLUDED_RENAME
int rename_ext(__unused proc_t p, struct rename_ext_args *uap, __unused int32_t *retval)
{
	return renameat_internal(
		vfs_context_current(), 
		AT_FDCWD, uap->from,
		AT_FDCWD, uap->to, 
		UIO_USERSPACE, uap->flags);
}
#endif
 
int
renameat(__unused proc_t p, struct renameat_args *uap, __unused int32_t *retval)
{
	return (renameat_internal(vfs_context_current(), uap->fromfd, uap->from,
	    uap->tofd, uap->to, UIO_USERSPACE, 0));
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
mkdir1at(vfs_context_t ctx, user_addr_t path, struct vnode_attr *vap, int fd,
    enum uio_seg segflg)
{
	vnode_t	vp, dvp;
	int error;
	int update_flags = 0;
	int batched;
	struct nameidata nd;

	AUDIT_ARG(mode, vap->va_mode);
	NDINIT(&nd, CREATE, OP_MKDIR, LOCKPARENT | AUDITVNPATH1, segflg,
	       path, ctx);
	nd.ni_cnd.cn_flags |= WILLBEDIR;
	nd.ni_flag = NAMEI_COMPOUNDMKDIR;

continue_lookup:
	error = nameiat(&nd, fd);
	if (error)
		return (error);
	dvp = nd.ni_dvp;
	vp = nd.ni_vp;

	if (vp != NULL) {
		error = EEXIST;
		goto out;
	}

	batched = vnode_compound_mkdir_available(dvp);

	VATTR_SET(vap, va_type, VDIR);

	/*
	 * XXX
	 * Don't authorize in VFS for compound VNOP.... mkdir -p today assumes that it will
	 * only get EXISTS or EISDIR for existing path components, and not that it could see
	 * EACCESS/EPERM--so if we authorize for mkdir on "/" for "mkdir -p /tmp/foo/bar/baz"
	 * it will fail in a spurious  manner.  Need to figure out if this is valid behavior.
	 */
	if ((error = vn_authorize_mkdir(dvp, &nd.ni_cnd, vap, ctx, NULL)) != 0) {
		if (error == EACCES || error == EPERM) {
			int error2;

			nameidone(&nd);
			vnode_put(dvp);
			dvp = NULLVP;

			/*
			 * Try a lookup without "NAMEI_COMPOUNDVNOP" to make sure we return EEXIST
			 * rather than EACCESS if the target exists.
			 */
			NDINIT(&nd, LOOKUP, OP_MKDIR, AUDITVNPATH1, segflg,
				       	path, ctx);
			error2 = nameiat(&nd, fd);
			if (error2) {
				goto out;
			} else {
				vp = nd.ni_vp;
				error = EEXIST;
				goto out;
			}
		}

		goto out;
	}

	/*
	 * make the directory
	 */
	if ((error = vn_create(dvp, &vp, &nd, vap, 0, 0, NULL, ctx)) != 0) {
		if (error == EKEEPLOOKING) {
			nd.ni_vp = vp;
			goto continue_lookup;
		}

		goto out;
	}

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
	if (dvp)
		vnode_put(dvp);

	return (error);
}

/*
 * mkdir_extended: Create a directory; with extended security (ACL).
 *
 * Parameters:    p                       Process requesting to create the directory
 *                uap                     User argument descriptor (see below)
 *                retval                  (ignored)
 *
 * Indirect:      uap->path               Path of directory to create
 *                uap->mode               Access permissions to set
 *                uap->xsecurity          ACL to set
 *
 * Returns:        0                      Success
 *                !0                      Not success
 *
 */
int
mkdir_extended(proc_t p, struct mkdir_extended_args *uap, __unused int32_t *retval)
{
	int ciferror;
	kauth_filesec_t xsecdst;
	struct vnode_attr va;

	AUDIT_ARG(owner, uap->uid, uap->gid);

	xsecdst = NULL;
	if ((uap->xsecurity != USER_ADDR_NULL) &&
	    ((ciferror = kauth_copyinfilesec(uap->xsecurity, &xsecdst)) != 0))
		return ciferror;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, (uap->mode & ACCESSPERMS) & ~p->p_fd->fd_cmask);
	if (xsecdst != NULL)
		VATTR_SET(&va, va_acl, &xsecdst->fsec_acl);

	ciferror = mkdir1at(vfs_context_current(), uap->path, &va, AT_FDCWD,
	    UIO_USERSPACE);
	if (xsecdst != NULL)
		kauth_filesec_free(xsecdst);
	return ciferror;
}

int
mkdir(proc_t p, struct mkdir_args *uap, __unused int32_t *retval)
{
	struct vnode_attr va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, (uap->mode & ACCESSPERMS) & ~p->p_fd->fd_cmask);

	return (mkdir1at(vfs_context_current(), uap->path, &va, AT_FDCWD,
	    UIO_USERSPACE));
}

int
mkdirat(proc_t p, struct mkdirat_args *uap, __unused int32_t *retval)
{
	struct vnode_attr va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_mode, (uap->mode & ACCESSPERMS) & ~p->p_fd->fd_cmask);

	return(mkdir1at(vfs_context_current(), uap->path, &va, uap->fd,
	    UIO_USERSPACE));
}

static int
rmdirat_internal(vfs_context_t ctx, int fd, user_addr_t dirpath,
    enum uio_seg segflg)
{
	vnode_t vp, dvp;
	int error;
	struct nameidata nd;
	char     *path = NULL;
	int       len=0;
	int has_listeners = 0;
	int need_event = 0;
	int truncated = 0;
#if CONFIG_FSE
	struct vnode_attr va;
#endif /* CONFIG_FSE */
	struct vnode_attr *vap = NULL;
	int batched;

	int restart_flag;

	/*
	 * This loop exists to restart rmdir in the unlikely case that two
	 * processes are simultaneously trying to remove the same directory
	 * containing orphaned appleDouble files.
	 */
	do {
		NDINIT(&nd, DELETE, OP_RMDIR, LOCKPARENT | AUDITVNPATH1,
		    segflg, dirpath, ctx);
		nd.ni_flag = NAMEI_COMPOUNDRMDIR;
continue_lookup:
		restart_flag = 0;
		vap = NULL;

		error = nameiat(&nd, fd);
		if (error)
			return (error);

		dvp = nd.ni_dvp;
		vp = nd.ni_vp;

		if (vp) {
			batched = vnode_compound_rmdir_available(vp);

			if (vp->v_flag & VROOT) {
				/*
				 * The root of a mounted filesystem cannot be deleted.
				 */
				error = EBUSY;
				goto out;
			}

			/*
			 * Removed a check here; we used to abort if vp's vid
			 * was not the same as what we'd seen the last time around.
			 * I do not think that check was valid, because if we retry
			 * and all dirents are gone, the directory could legitimately
			 * be recycled but still be present in a situation where we would
			 * have had permission to delete.  Therefore, we won't make
			 * an effort to preserve that check now that we may not have a
			 * vp here.
			 */

			if (!batched) {
				error = vn_authorize_rmdir(dvp, vp, &nd.ni_cnd, ctx, NULL);
				if (error) {
					goto out;
				}
			}
		} else {
			batched = 1;

			if (!vnode_compound_rmdir_available(dvp)) {
				panic("No error, but no compound rmdir?");
			}
		}

#if CONFIG_FSE
		fse_info  finfo;

		need_event = need_fsevent(FSE_DELETE, dvp);
		if (need_event) {
			if (!batched) {
				get_fse_info(vp, &finfo, ctx);
			} else {
				error = vfs_get_notify_attributes(&va);
				if (error) {
					goto out;
				}

				vap = &va;
			}
		}
#endif
		has_listeners = kauth_authorize_fileop_has_listeners();
		if (need_event || has_listeners) {
			if (path == NULL) {
				GET_PATH(path);
				if (path == NULL) {
					error = ENOMEM;
					goto out;
				}
			}

			len = safe_getpath(dvp, nd.ni_cnd.cn_nameptr, path, MAXPATHLEN, &truncated);
#if CONFIG_FSE
			if (truncated) {
				finfo.mode |= FSE_TRUNCATED_PATH;
			}
#endif
		}

		error = vn_rmdir(dvp, &vp, &nd, vap, ctx);
		nd.ni_vp = vp;
		if (vp == NULLVP) {
			/* Couldn't find a vnode */
			goto out;
		}

		if (error == EKEEPLOOKING) {
			goto continue_lookup;
		}
#if CONFIG_APPLEDOUBLE
		/*
		 * Special case to remove orphaned AppleDouble
		 * files. I don't like putting this in the kernel,
		 * but carbon does not like putting this in carbon either,
		 * so here we are.
		 */
		if (error == ENOTEMPTY) {
			error = rmdir_remove_orphaned_appleDouble(vp, ctx, &restart_flag);
			if (error == EBUSY) {
				goto out;
			}


			/*
			 * Assuming everything went well, we will try the RMDIR again
			 */
			if (!error)
				error = vn_rmdir(dvp, &vp, &nd, vap, ctx);
		}
#endif /* CONFIG_APPLEDOUBLE */
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
				if (vap) {
					vnode_get_fse_info_from_vap(vp, &finfo, vap);
				}
				add_fsevent(FSE_DELETE, ctx,
						FSE_ARG_STRING, len, path,
						FSE_ARG_FINFO, &finfo,
						FSE_ARG_DONE);
			}
#endif
		}

out:
		if (path != NULL) {
			RELEASE_PATH(path);
			path = NULL;
		}
		/*
		 * nameidone has to happen before we vnode_put(dvp)
		 * since it may need to release the fs_nodelock on the dvp
		 */
		nameidone(&nd);
		vnode_put(dvp);

		if (vp)
			vnode_put(vp);

		if (restart_flag == 0) {
			wakeup_one((caddr_t)vp);
			return (error);
		}
		tsleep(vp, PVFS, "rm AD", 1);

	} while (restart_flag != 0);

	return (error);

}

/*
 * Remove a directory file.
 */
/* ARGSUSED */
int
rmdir(__unused proc_t p, struct rmdir_args *uap, __unused int32_t *retval)
{
	return (rmdirat_internal(vfs_context_current(), AT_FDCWD,
	    CAST_USER_ADDR_T(uap->path), UIO_USERSPACE));
}

/* Get direntry length padded to 8 byte alignment */
#define DIRENT64_LEN(namlen) \
	((sizeof(struct direntry) + (namlen) - (MAXPATHLEN-1) + 7) & ~7)

errno_t
vnode_readdir64(struct vnode *vp, struct uio *uio, int flags, int *eofflag,
                int *numdirent, vfs_context_t ctxp)
{
	/* Check if fs natively supports VNODE_READDIR_EXTENDED */
	if ((vp->v_mount->mnt_vtable->vfc_vfsflags & VFC_VFSREADDIR_EXTENDED) && 
		   ((vp->v_mount->mnt_kern_flag & MNTK_DENY_READDIREXT) == 0))	{
		return VNOP_READDIR(vp, uio, flags, eofflag, numdirent, ctxp);
	} else {
		size_t bufsize;
		void * bufptr;
		uio_t auio;
		struct direntry *entry64;
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
		bufsize = 3 * MIN((user_size_t)uio_resid(uio), 87371u) / 8;
		MALLOC(bufptr, void *, bufsize, M_TEMP, M_WAITOK);
		if (bufptr == NULL) {
			return ENOMEM;
		}

		auio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
		uio_addiov(auio, (uintptr_t)bufptr, bufsize);
		auio->uio_offset = uio->uio_offset;

		error = VNOP_READDIR(vp, auio, 0, eofflag, numdirent, ctxp);

		dep = (struct dirent *)bufptr;
		bytesread = bufsize - uio_resid(auio);

		MALLOC(entry64, struct direntry *, sizeof(struct direntry),
		       M_TEMP, M_WAITOK);
		/*
		 * Convert all the entries and copy them out to user's buffer.
		 */
		while (error == 0 && (char *)dep < ((char *)bufptr + bytesread)) {
			size_t	enbufsize = DIRENT64_LEN(dep->d_namlen);

			bzero(entry64, enbufsize);
			/* Convert a dirent to a dirent64. */
			entry64->d_ino = dep->d_ino;
			entry64->d_seekoff = 0;
			entry64->d_reclen = enbufsize;
			entry64->d_namlen = dep->d_namlen;
			entry64->d_type = dep->d_type;
			bcopy(dep->d_name, entry64->d_name, dep->d_namlen + 1);

			/* Move to next entry. */
			dep = (struct dirent *)((char *)dep + dep->d_reclen);

			/* Copy entry64 to user's buffer. */
			error = uiomove((caddr_t)entry64, entry64->d_reclen, uio);
		}

		/* Update the real offset using the offset we got from VNOP_READDIR. */
		if (error == 0) {
			uio->uio_offset = auio->uio_offset;
		}
		uio_free(auio);
		FREE(bufptr, M_TEMP);
		FREE(entry64, M_TEMP);
		return (error);
	}
}

#define GETDIRENTRIES_MAXBUFSIZE	(128 * 1024 * 1024U)

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

	if (bufsize > GETDIRENTRIES_MAXBUFSIZE)
		bufsize = GETDIRENTRIES_MAXBUFSIZE;

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

		if ((vp->v_mount->mnt_flag & MNT_UNION)) {
			struct vnode *tvp = vp;
			if (lookup_traverse_union(tvp, &vp, &context) == 0) {
				vnode_ref(vp);
				fp->f_fglob->fg_data = (caddr_t) vp;
				fp->f_fglob->fg_offset = 0;
				vnode_rele(tvp);
				vnode_put(tvp);
				goto unionread;
			}
			vp = tvp;
		}
	}

	vnode_put(vp);
	if (offset) {
		*offset = loff;
	}
	
	*bytesread = bufsize - uio_resid(auio);
out:
	file_drop(fd);
	return (error);
}


int
getdirentries(__unused struct proc *p, struct getdirentries_args *uap, int32_t *retval)
{
	off_t offset;
	ssize_t bytesread;
	int error;

	AUDIT_ARG(fd, uap->fd);
	error = getdirentries_common(uap->fd, uap->buf, uap->count, &bytesread, &offset, 0);

	if (error == 0) {
		if (proc_is64bit(p)) {
			user64_long_t base = (user64_long_t)offset;
			error = copyout((caddr_t)&base, uap->basep, sizeof(user64_long_t));
		} else {
			user32_long_t base = (user32_long_t)offset;
			error = copyout((caddr_t)&base, uap->basep, sizeof(user32_long_t));
		}
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
 * XXX implement xsecurity
 */
#define UMASK_NOXSECURITY	 (void *)1	/* leave existing xsecurity alone */
static int
umask1(proc_t p, int newmask, __unused kauth_filesec_t fsec, int32_t *retval)
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

/*
 * umask_extended: Set the mode mask for creation of filesystem nodes; with extended security (ACL).
 *
 * Parameters:    p                       Process requesting to set the umask
 *                uap                     User argument descriptor (see below)
 *                retval                  umask of the process (parameter p)
 *
 * Indirect:      uap->newmask            umask to set
 *                uap->xsecurity          ACL to set
 *                
 * Returns:        0                      Success
 *                !0                      Not success
 *
 */
int
umask_extended(proc_t p, struct umask_extended_args *uap, int32_t *retval)
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
umask(proc_t p, struct umask_args *uap, int32_t *retval)
{
	return(umask1(p, uap->newmask, UMASK_NOXSECURITY, retval));
}

/*
 * Void all references to file by ripping underlying filesystem
 * away from vnode.
 */
/* ARGSUSED */
int
revoke(proc_t p, struct revoke_args *uap, __unused int32_t *retval)
{
	vnode_t vp;
	struct vnode_attr va;
	vfs_context_t ctx = vfs_context_current();
	int error;
	struct nameidata nd;

	NDINIT(&nd, LOOKUP, OP_REVOKE, FOLLOW | AUDITVNPATH1, UIO_USERSPACE,
	       uap->path, ctx);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;

	nameidone(&nd);

	if (!(vnode_ischr(vp) || vnode_isblk(vp))) {
		error = ENOTSUP;
		goto out;
	}

	if (vnode_isblk(vp) && vnode_ismountedon(vp)) {
		error = EBUSY;
		goto out;
	}

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
	if (vp->v_usecount > 0 || (vnode_isaliased(vp)))
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


/*
 * Obtain attribute information on objects in a directory while enumerating
 * the directory.
 */
/* ARGSUSED */
int
getdirentriesattr (proc_t p, struct getdirentriesattr_args *uap, int32_t *retval)
{
	vnode_t vp;
	struct fileproc *fp;
	uio_t auio = NULL;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	uint32_t count, savecount;
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
	savecount = count;
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

unionread:
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
	auio = uio_createwithbuffer(1, loff, spacetype, UIO_READ, &uio_buf[0], sizeof(uio_buf));
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

		/* Believe it or not, uap->options only has 32-bits of valid
		 * info, so truncate before extending again */

		error = VNOP_READDIRATTR(vp, &attributelist, auio, count,
				(u_long)(uint32_t)uap->options, &newstate, &eofflag, &count, ctx);
	}

	if (error) {
		(void) vnode_put(vp);
		goto out;
	}

	/*
	 * If we've got the last entry of a directory in a union mount
	 * then reset the eofflag and pretend there's still more to come.
	 * The next call will again set eofflag and the buffer will be empty,
	 * so traverse to the underlying directory and do the directory
	 * read there.
	 */
	if (eofflag && vp->v_mount->mnt_flag & MNT_UNION) {
		if (uio_resid(auio) < (user_ssize_t) uap->buffersize) { // Got some entries
			eofflag = 0;
		} else {						// Empty buffer
			struct vnode *tvp = vp;
			if (lookup_traverse_union(tvp, &vp, ctx) == 0) {
				vnode_ref_ext(vp, fp->f_fglob->fg_flag & O_EVTONLY, 0);
				fp->f_fglob->fg_data = (caddr_t) vp;
				fp->f_fglob->fg_offset = 0; // reset index for new dir
				count = savecount;
				vnode_rele_internal(tvp, fp->f_fglob->fg_flag & O_EVTONLY, 0, 0);
				vnode_put(tvp);
				goto unionread;
			}
			vp = tvp;
		}
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

} /* end of getdirentriesattr system call */

/*
* Exchange data between two files
*/

/* ARGSUSED */
int
exchangedata (__unused proc_t p, struct exchangedata_args *uap, __unused int32_t *retval)
{

	struct nameidata fnd, snd;
	vfs_context_t ctx = vfs_context_current();
	vnode_t fvp;
	vnode_t svp;
	int error;
	u_int32_t nameiflags;
	char *fpath = NULL;
	char *spath = NULL;
	int   flen=0, slen=0;
	int from_truncated=0, to_truncated=0;
#if CONFIG_FSE
	fse_info f_finfo, s_finfo;
#endif
	
	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;

	NDINIT(&fnd, LOOKUP, OP_EXCHANGEDATA, nameiflags | AUDITVNPATH1,
	       UIO_USERSPACE, uap->path1, ctx);

	error = namei(&fnd);
	if (error)
		goto out2;

	nameidone(&fnd);
	fvp = fnd.ni_vp;

	NDINIT(&snd, LOOKUP, OP_EXCHANGEDATA, CN_NBMOUNTLOOK | nameiflags | AUDITVNPATH2, 
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

	/* If they're not files, return an error */
	if ( (vnode_isreg(fvp) == 0) || (vnode_isreg(svp) == 0)) {
		error = EINVAL;
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

		flen = safe_getpath(fvp, NULL, fpath, MAXPATHLEN, &from_truncated);
		slen = safe_getpath(svp, NULL, spath, MAXPATHLEN, &to_truncated);
		
#if CONFIG_FSE
		get_fse_info(fvp, &f_finfo, ctx);
		get_fse_info(svp, &s_finfo, ctx);
		if (from_truncated || to_truncated) {
			// set it here since only the f_finfo gets reported up to user space
			f_finfo.mode |= FSE_TRUNCATED_PATH;
		}
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

/*
 * Return (in MB) the amount of freespace on the given vnode's volume.
 */
uint32_t freespace_mb(vnode_t vp);

uint32_t
freespace_mb(vnode_t vp)
{
	vfs_update_vfsstat(vp->v_mount, vfs_context_current(), VFS_USER_EVENT);	
 	return (((uint64_t)vp->v_mount->mnt_vfsstat.f_bavail *
 	        vp->v_mount->mnt_vfsstat.f_bsize) >> 20);
}

#if CONFIG_SEARCHFS

/* ARGSUSED */

int
searchfs(proc_t p, struct searchfs_args *uap, __unused int32_t *retval)
{
	vnode_t vp, tvp;
	int i, error=0;
	int fserror = 0;
	struct nameidata nd;
	struct user64_fssearchblock searchblock;
	struct searchstate *state;
	struct attrlist *returnattrs;
	struct timeval timelimit;
	void *searchparams1,*searchparams2;
	uio_t auio = NULL;
	int spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	uint32_t nummatches;
	int mallocsize;
	uint32_t nameiflags;
	vfs_context_t ctx = vfs_context_current();
	char uio_buf[ UIO_SIZEOF(1) ];

	/* Start by copying in fsearchblock parameter list */
    if (IS_64BIT_PROCESS(p)) {
        error = copyin(uap->searchblock, (caddr_t) &searchblock, sizeof(searchblock));
        timelimit.tv_sec = searchblock.timelimit.tv_sec;
        timelimit.tv_usec = searchblock.timelimit.tv_usec;
    }
    else {
        struct user32_fssearchblock tmp_searchblock;

        error = copyin(uap->searchblock, (caddr_t) &tmp_searchblock, sizeof(tmp_searchblock));
        // munge into 64-bit version
        searchblock.returnattrs = CAST_USER_ADDR_T(tmp_searchblock.returnattrs);
        searchblock.returnbuffer = CAST_USER_ADDR_T(tmp_searchblock.returnbuffer);
        searchblock.returnbuffersize = tmp_searchblock.returnbuffersize;
        searchblock.maxmatches = tmp_searchblock.maxmatches;
		/* 
		 * These casts are safe. We will promote the tv_sec into a 64 bit long if necessary
		 * from a 32 bit long, and tv_usec is already a signed 32 bit int.
		 */
        timelimit.tv_sec = (__darwin_time_t) tmp_searchblock.timelimit.tv_sec;
        timelimit.tv_usec = (__darwin_useconds_t) tmp_searchblock.timelimit.tv_usec;
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
	/*												      */
	/* NOTE: we allocate an extra 8 bytes to account for the difference in size of the searchstate        */
	/*       due to the changes in rdar://problem/12438273.  That way if a 3rd party file system          */
	/*       assumes the size is still 556 bytes it will continue to work				      */
		 
	mallocsize = searchblock.sizeofsearchparams1 + searchblock.sizeofsearchparams2 +
		sizeof(struct attrlist) + sizeof(struct searchstate) + (2*sizeof(uint32_t));

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

	/*
	 * When searching a union mount, need to set the
	 * start flag at the first call on each layer to
	 * reset state for the new volume.
	 */
	if (uap->options & SRCHFS_START)
		state->ss_union_layer = 0;
	else 
		uap->options |= state->ss_union_flags;
	state->ss_union_flags = 0;

	/*
	 * Because searchparams1 and searchparams2 may contain an ATTR_CMN_NAME search parameter,
	 * which is passed in with an attrreference_t, we need to inspect the buffer manually here.
	 * The KPI does not provide us the ability to pass in the length of the buffers searchparams1 
	 * and searchparams2. To obviate the need for all searchfs-supporting filesystems to 
	 * validate the user-supplied data offset of the attrreference_t, we'll do it here.
	 */

	if (searchblock.searchattrs.commonattr & ATTR_CMN_NAME) {
		attrreference_t* string_ref;
		u_int32_t* start_length;
		user64_size_t param_length;            

		/* validate searchparams1 */
		param_length = searchblock.sizeofsearchparams1;                                           
		/* skip the word that specifies length of the buffer */
		start_length= (u_int32_t*) searchparams1;
		start_length= start_length+1;
		string_ref= (attrreference_t*) start_length;

		/* ensure no negative offsets or too big offsets */
		if (string_ref->attr_dataoffset < 0 ) {
			error = EINVAL;
			goto freeandexit;		
		}
		if (string_ref->attr_length > MAXPATHLEN) {
			error = EINVAL;
			goto freeandexit;
		}
		
		/* Check for pointer overflow in the string ref */
		if (((char*) string_ref + string_ref->attr_dataoffset) < (char*) string_ref) {
			error = EINVAL;
			goto freeandexit;
		}

		if (((char*) string_ref + string_ref->attr_dataoffset) > ((char*)searchparams1 + param_length)) {
			error = EINVAL;
			goto freeandexit;
		}
		if (((char*)string_ref + string_ref->attr_dataoffset + string_ref->attr_length) > ((char*)searchparams1 + param_length)) {
			error = EINVAL;
			goto freeandexit;
		}
	}

	/* set up the uio structure which will contain the users return buffer */
	auio = uio_createwithbuffer(1, 0, spacetype, UIO_READ, &uio_buf[0], sizeof(uio_buf));
 	uio_addiov(auio, searchblock.returnbuffer, searchblock.returnbuffersize);

	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, OP_SEARCHFS, nameiflags | AUDITVNPATH1,
	       UIO_USERSPACE, uap->path, ctx);

	error = namei(&nd);
	if (error)
		goto freeandexit;
	vp = nd.ni_vp;
	nameidone(&nd);

	/*
	 * Switch to the root vnode for the volume
	 */
	error = VFS_ROOT(vnode_mount(vp), &tvp, ctx);
	vnode_put(vp);
	if (error)
		goto freeandexit;
	vp = tvp;

	/*
	 * If it's a union mount, the path lookup takes
	 * us to the top layer. But we may need to descend
	 * to a lower layer. For non-union mounts the layer
	 * is always zero.
	 */
	for (i = 0; i < (int) state->ss_union_layer; i++) {
		if ((vp->v_mount->mnt_flag & MNT_UNION) == 0)
			break;
		tvp = vp;
		vp = vp->v_mount->mnt_vnodecovered;
		if (vp == NULL) {
			vnode_put(tvp);
			error = ENOENT;
			goto freeandexit;
		}
		vnode_getwithref(vp);
		vnode_put(tvp);
	}

#if CONFIG_MACF
	error = mac_vnode_check_searchfs(ctx, vp, &searchblock.searchattrs);
	if (error) {
		vnode_put(vp);
		goto freeandexit;
	}
#endif

	 
	/*
	 * If searchblock.maxmatches == 0, then skip the search. This has happened 
	 * before and sometimes the underlying code doesnt deal with it well.
	 */
	 if (searchblock.maxmatches == 0) {
		nummatches = 0;
		goto saveandexit;
	 }

	/*
	 * Allright, we have everything we need, so lets make that call.
	 * 
	 * We keep special track of the return value from the file system:
	 * EAGAIN is an acceptable error condition that shouldn't keep us
	 * from copying out any results...
	 */

	fserror = VNOP_SEARCHFS(vp,
		searchparams1,
		searchparams2,
		&searchblock.searchattrs,
		(u_long)searchblock.maxmatches,
		&timelimit,
		returnattrs,
		&nummatches,
		(u_long)uap->scriptcode,
		(u_long)uap->options,
		auio,
		(struct searchstate *) &state->ss_fsstate,
		ctx);
		
	/*
	 * If it's a union mount we need to be called again
	 * to search the mounted-on filesystem.
	 */
	if ((vp->v_mount->mnt_flag & MNT_UNION) && fserror == 0) {
		state->ss_union_flags = SRCHFS_START;
		state->ss_union_layer++;	// search next layer down
		fserror = EAGAIN;
	}

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

#else /* CONFIG_SEARCHFS */

int
searchfs(__unused proc_t p, __unused struct searchfs_args *uap, __unused int32_t *retval)
{
	return (ENOTSUP);
}

#endif /* CONFIG_SEARCHFS */


lck_grp_attr_t *  nspace_group_attr;
lck_attr_t *      nspace_lock_attr;
lck_grp_t *       nspace_mutex_group;

lck_mtx_t         nspace_handler_lock;
lck_mtx_t         nspace_handler_exclusion_lock;

time_t snapshot_timestamp=0;
int nspace_allow_virtual_devs=0;

void nspace_handler_init(void);

typedef struct nspace_item_info {
	struct vnode *vp;
	void         *arg;
	uint64_t      op;
	uint32_t      vid;
	uint32_t      flags;
	uint32_t      token;
	uint32_t      refcount;
} nspace_item_info;

#define MAX_NSPACE_ITEMS   128
nspace_item_info nspace_items[MAX_NSPACE_ITEMS];
uint32_t      nspace_item_idx=0;              // also used as the sleep/wakeup rendezvous address
uint32_t      nspace_token_id=0;
uint32_t      nspace_handler_timeout = 15;    // seconds

#define NSPACE_ITEM_NEW         0x0001
#define NSPACE_ITEM_PROCESSING  0x0002
#define NSPACE_ITEM_DEAD        0x0004
#define NSPACE_ITEM_CANCELLED   0x0008
#define NSPACE_ITEM_DONE        0x0010
#define NSPACE_ITEM_RESET_TIMER 0x0020

#define NSPACE_ITEM_NSPACE_EVENT   0x0040
#define NSPACE_ITEM_SNAPSHOT_EVENT 0x0080

#define NSPACE_ITEM_ALL_EVENT_TYPES (NSPACE_ITEM_NSPACE_EVENT | NSPACE_ITEM_SNAPSHOT_EVENT)

//#pragma optimization_level 0

typedef enum {
	NSPACE_HANDLER_NSPACE = 0,
	NSPACE_HANDLER_SNAPSHOT = 1,

	NSPACE_HANDLER_COUNT,
} nspace_type_t;

typedef struct {
	uint64_t handler_tid;
	struct proc *handler_proc;
	int handler_busy;
} nspace_handler_t;

nspace_handler_t nspace_handlers[NSPACE_HANDLER_COUNT];

/* namespace fsctl functions */
static int nspace_flags_matches_handler(uint32_t event_flags, nspace_type_t nspace_type);
static int nspace_item_flags_for_type(nspace_type_t nspace_type);
static int nspace_open_flags_for_type(nspace_type_t nspace_type);
static nspace_type_t nspace_type_for_op(uint64_t op);
static int nspace_is_special_process(struct proc *proc);
static int vn_open_with_vp(vnode_t vp, int fmode, vfs_context_t ctx);
static int wait_for_namespace_event(namespace_handler_data *nhd, nspace_type_t nspace_type);
static int validate_namespace_args (int is64bit, int size);
static int process_namespace_fsctl(nspace_type_t nspace_type, int is64bit, u_int size, caddr_t data);


static inline int nspace_flags_matches_handler(uint32_t event_flags, nspace_type_t nspace_type)
{
	switch(nspace_type) {
		case NSPACE_HANDLER_NSPACE:
			return (event_flags & NSPACE_ITEM_ALL_EVENT_TYPES) == NSPACE_ITEM_NSPACE_EVENT;
		case NSPACE_HANDLER_SNAPSHOT:
			return (event_flags & NSPACE_ITEM_ALL_EVENT_TYPES) == NSPACE_ITEM_SNAPSHOT_EVENT;
		default:
			printf("nspace_flags_matches_handler: invalid type %u\n", (int)nspace_type);
			return 0;
	}
}

static inline int nspace_item_flags_for_type(nspace_type_t nspace_type)
{
	switch(nspace_type) {
		case NSPACE_HANDLER_NSPACE:
			return NSPACE_ITEM_NSPACE_EVENT;
		case NSPACE_HANDLER_SNAPSHOT:
			return NSPACE_ITEM_SNAPSHOT_EVENT;
		default:
			printf("nspace_item_flags_for_type: invalid type %u\n", (int)nspace_type);
			return 0;
	}
}

static inline int nspace_open_flags_for_type(nspace_type_t nspace_type)
{
	switch(nspace_type) {
		case NSPACE_HANDLER_NSPACE:
			return FREAD | FWRITE | O_EVTONLY;
		case NSPACE_HANDLER_SNAPSHOT:
			return FREAD | O_EVTONLY;
		default:
			printf("nspace_open_flags_for_type: invalid type %u\n", (int)nspace_type);
			return 0;
	}
}

static inline nspace_type_t nspace_type_for_op(uint64_t op)
{
	switch(op & NAMESPACE_HANDLER_EVENT_TYPE_MASK) {
		case NAMESPACE_HANDLER_NSPACE_EVENT:
			return NSPACE_HANDLER_NSPACE;
		case NAMESPACE_HANDLER_SNAPSHOT_EVENT:
			return NSPACE_HANDLER_SNAPSHOT;
		default:
			printf("nspace_type_for_op: invalid op mask %llx\n", op & NAMESPACE_HANDLER_EVENT_TYPE_MASK);
			return NSPACE_HANDLER_NSPACE;
	}
}

static inline int nspace_is_special_process(struct proc *proc)
{
	int i;
	for (i = 0; i < NSPACE_HANDLER_COUNT; i++) {
		if (proc == nspace_handlers[i].handler_proc)
			return 1;
	}
	return 0;
}

void
nspace_handler_init(void)
{
	nspace_lock_attr    = lck_attr_alloc_init();
	nspace_group_attr   = lck_grp_attr_alloc_init();
	nspace_mutex_group  = lck_grp_alloc_init("nspace-mutex", nspace_group_attr);
	lck_mtx_init(&nspace_handler_lock, nspace_mutex_group, nspace_lock_attr);
	lck_mtx_init(&nspace_handler_exclusion_lock, nspace_mutex_group, nspace_lock_attr);
	memset(&nspace_items[0], 0, sizeof(nspace_items));
}

void
nspace_proc_exit(struct proc *p)
{
	int i, event_mask = 0;
	
	for (i = 0; i < NSPACE_HANDLER_COUNT; i++) {
		if (p == nspace_handlers[i].handler_proc) {
			event_mask |= nspace_item_flags_for_type(i);
			nspace_handlers[i].handler_tid = 0;
			nspace_handlers[i].handler_proc = NULL;
		}
	}

	if (event_mask == 0) {
		return;
	}
	
	if (event_mask & NSPACE_ITEM_SNAPSHOT_EVENT) {
		// if this process was the snapshot handler, zero snapshot_timeout
		snapshot_timestamp = 0;
	}
	
	//
	// unblock anyone that's waiting for the handler that died
	//
	lck_mtx_lock(&nspace_handler_lock);
	for(i=0; i < MAX_NSPACE_ITEMS; i++) {
		if (nspace_items[i].flags & (NSPACE_ITEM_NEW | NSPACE_ITEM_PROCESSING)) {

			if ( nspace_items[i].flags & event_mask ) {

				if (nspace_items[i].vp && (nspace_items[i].vp->v_flag & VNEEDSSNAPSHOT)) {
					vnode_lock_spin(nspace_items[i].vp);
					nspace_items[i].vp->v_flag &= ~VNEEDSSNAPSHOT;
					vnode_unlock(nspace_items[i].vp);
				}
				nspace_items[i].vp = NULL;
				nspace_items[i].vid = 0;
				nspace_items[i].flags = NSPACE_ITEM_DONE;
				nspace_items[i].token = 0;
				
				wakeup((caddr_t)&(nspace_items[i].vp));
			}
		}
	}
	
	wakeup((caddr_t)&nspace_item_idx);
	lck_mtx_unlock(&nspace_handler_lock);
}


int 
resolve_nspace_item(struct vnode *vp, uint64_t op)
{
	return resolve_nspace_item_ext(vp, op, NULL);
}

int 
resolve_nspace_item_ext(struct vnode *vp, uint64_t op, void *arg)
{
	int i, error, keep_waiting;
	struct timespec ts;
	nspace_type_t nspace_type = nspace_type_for_op(op);

	// only allow namespace events on regular files, directories and symlinks.
	if (vp->v_type != VREG && vp->v_type != VDIR && vp->v_type != VLNK) {
		return 0;
	}

	//
	// if this is a snapshot event and the vnode is on a
	// disk image just pretend nothing happened since any
	// change to the disk image will cause the disk image
	// itself to get backed up and this avoids multi-way
	// deadlocks between the snapshot handler and the ever
	// popular diskimages-helper process.  the variable
	// nspace_allow_virtual_devs allows this behavior to
	// be overridden (for use by the Mobile TimeMachine
	// testing infrastructure which uses disk images)
	//
	if (   (op & NAMESPACE_HANDLER_SNAPSHOT_EVENT)
	    && (vp->v_mount != NULL)
	    && (vp->v_mount->mnt_kern_flag & MNTK_VIRTUALDEV)
	    && !nspace_allow_virtual_devs) {

		return 0;
	}

	// if (thread_tid(current_thread()) == namespace_handler_tid) {
	if (nspace_handlers[nspace_type].handler_proc == NULL) {
		return 0;
	}

	if (nspace_is_special_process(current_proc())) {
		return EDEADLK;
	}

	lck_mtx_lock(&nspace_handler_lock);

retry:
	for(i=0; i < MAX_NSPACE_ITEMS; i++) {
		if (vp == nspace_items[i].vp && op == nspace_items[i].op) {
			break;
		}
	}

	if (i >= MAX_NSPACE_ITEMS) {
		for(i=0; i < MAX_NSPACE_ITEMS; i++) {
			if (nspace_items[i].flags == 0) {
				break;
			}
		}
	} else {
		nspace_items[i].refcount++;
	}
	
	if (i >= MAX_NSPACE_ITEMS) {
		ts.tv_sec = nspace_handler_timeout;
		ts.tv_nsec = 0;

		error = msleep((caddr_t)&nspace_token_id, &nspace_handler_lock, PVFS|PCATCH, "nspace-no-space", &ts);
		if (error == 0) {
			// an entry got free'd up, go see if we can get a slot
			goto retry;
		} else {
			lck_mtx_unlock(&nspace_handler_lock);
			return error;
		}
	}

	//
	// if it didn't already exist, add it.  if it did exist
	// we'll get woken up when someone does a wakeup() on
	// the slot in the nspace_items table.
	//
	if (vp != nspace_items[i].vp) {
		nspace_items[i].vp = vp;
		nspace_items[i].arg = (arg == NSPACE_REARM_NO_ARG) ? NULL : arg;  // arg is {NULL, true, uio *} - only pass uio thru to the user
		nspace_items[i].op = op;
		nspace_items[i].vid = vnode_vid(vp);
		nspace_items[i].flags = NSPACE_ITEM_NEW;
		nspace_items[i].flags |= nspace_item_flags_for_type(nspace_type);
		if (nspace_items[i].flags & NSPACE_ITEM_SNAPSHOT_EVENT) {
			if (arg) {
				vnode_lock_spin(vp);
				vp->v_flag |= VNEEDSSNAPSHOT;
				vnode_unlock(vp);
			}
		}

		nspace_items[i].token = 0;
		nspace_items[i].refcount = 1;
		
		wakeup((caddr_t)&nspace_item_idx);
	}

	//
	// Now go to sleep until the handler does a wakeup on this
	// slot in the nspace_items table (or we timeout).
	//
	keep_waiting = 1;
	while(keep_waiting) {
		ts.tv_sec = nspace_handler_timeout;
		ts.tv_nsec = 0;
		error = msleep((caddr_t)&(nspace_items[i].vp), &nspace_handler_lock, PVFS|PCATCH, "namespace-done", &ts);

		if (nspace_items[i].flags & NSPACE_ITEM_DONE) {
			error = 0;
		} else if (nspace_items[i].flags & NSPACE_ITEM_CANCELLED) {
			error = nspace_items[i].token;
		} else if (error == EWOULDBLOCK || error == ETIMEDOUT) {
			if (nspace_items[i].flags & NSPACE_ITEM_RESET_TIMER) {
				nspace_items[i].flags &= ~NSPACE_ITEM_RESET_TIMER;
				continue;
			} else {
				error = ETIMEDOUT;
			}
		} else if (error == 0) {
			// hmmm, why did we get woken up?
			printf("woken up for token %d but it's not done, cancelled or timedout and error == 0.\n",
			       nspace_items[i].token);
		} 

		if (--nspace_items[i].refcount == 0) {
			nspace_items[i].vp = NULL;     // clear this so that no one will match on it again
			nspace_items[i].arg = NULL;
			nspace_items[i].token = 0;     // clear this so that the handler will not find it anymore
			nspace_items[i].flags = 0;     // this clears it for re-use
		}
		wakeup(&nspace_token_id);
		keep_waiting = 0;
	}

	lck_mtx_unlock(&nspace_handler_lock);

	return error;
}


int
get_nspace_item_status(struct vnode *vp, int32_t *status)
{
	int i;

	lck_mtx_lock(&nspace_handler_lock);
	for(i=0; i < MAX_NSPACE_ITEMS; i++) {
		if (nspace_items[i].vp == vp) {
			break;
		}
	}

	if (i >= MAX_NSPACE_ITEMS) {
		lck_mtx_unlock(&nspace_handler_lock);
		return ENOENT;
	}

	*status = nspace_items[i].flags;
	lck_mtx_unlock(&nspace_handler_lock);
	return 0;
}
	

#if 0
static int
build_volfs_path(struct vnode *vp, char *path, int *len)
{
	struct vnode_attr va;
	int ret;

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_fsid);
	VATTR_WANTED(&va, va_fileid);

	if (vnode_getattr(vp, &va, vfs_context_kernel()) != 0) {
		*len = snprintf(path, *len, "/non/existent/path/because/vnode_getattr/failed") + 1;
		ret = -1;
	} else {
		*len = snprintf(path, *len, "/.vol/%d/%lld", (dev_t)va.va_fsid, va.va_fileid) + 1;
		ret = 0;
	}

	return ret;
}
#endif

//
// Note: this function does NOT check permissions on all of the
// parent directories leading to this vnode.  It should only be
// called on behalf of a root process.  Otherwise a process may
// get access to a file because the file itself is readable even
// though its parent directories would prevent access.
//
static int
vn_open_with_vp(vnode_t vp, int fmode, vfs_context_t ctx)
{
	int error, action;

	if ((error = suser(kauth_cred_get(), &(current_proc()->p_acflag)))) {
		return error;
	}

#if CONFIG_MACF
	error = mac_vnode_check_open(ctx, vp, fmode);
	if (error)
		return error;
#endif

	/* compute action to be authorized */
	action = 0;
	if (fmode & FREAD) {
		action |= KAUTH_VNODE_READ_DATA;
	}
	if (fmode & (FWRITE | O_TRUNC)) {
		/*
		 * If we are writing, appending, and not truncating,
		 * indicate that we are appending so that if the
		 * UF_APPEND or SF_APPEND bits are set, we do not deny
		 * the open.
		 */
		if ((fmode & O_APPEND) && !(fmode & O_TRUNC)) {
			action |= KAUTH_VNODE_APPEND_DATA;
		} else {
			action |= KAUTH_VNODE_WRITE_DATA;
		}
	}

	if ((error = vnode_authorize(vp, NULL, action, ctx)) != 0)
		return error;
		

	//
	// if the vnode is tagged VOPENEVT and the current process
	// has the P_CHECKOPENEVT flag set, then we or in the O_EVTONLY
	// flag to the open mode so that this open won't count against
	// the vnode when carbon delete() does a vnode_isinuse() to see
	// if a file is currently in use.  this allows spotlight
	// importers to not interfere with carbon apps that depend on
	// the no-delete-if-busy semantics of carbon delete().
	//
	if ((vp->v_flag & VOPENEVT) && (current_proc()->p_flag & P_CHECKOPENEVT)) {
		fmode |= O_EVTONLY;
	}

	if ( (error = VNOP_OPEN(vp, fmode, ctx)) ) {
		return error;
	}
	if ( (error = vnode_ref_ext(vp, fmode, 0)) ) {
		VNOP_CLOSE(vp, fmode, ctx);
		return error;
	}

	/* Call out to allow 3rd party notification of open. 
	 * Ignore result of kauth_authorize_fileop call.
	 */
#if CONFIG_MACF
	mac_vnode_notify_open(ctx, vp, fmode);
#endif
	kauth_authorize_fileop(vfs_context_ucred(ctx), KAUTH_FILEOP_OPEN, 
			       (uintptr_t)vp, 0);


	return 0;
}

static int
wait_for_namespace_event(namespace_handler_data *nhd, nspace_type_t nspace_type)
{
	int i, error=0, unblock=0;
	task_t curtask;
	
	lck_mtx_lock(&nspace_handler_exclusion_lock);
	if (nspace_handlers[nspace_type].handler_busy) {
		lck_mtx_unlock(&nspace_handler_exclusion_lock);
		return EBUSY;
	}
	nspace_handlers[nspace_type].handler_busy = 1;
	lck_mtx_unlock(&nspace_handler_exclusion_lock);
	
	/* 
	 * Any process that gets here will be one of the namespace handlers.
	 * As such, they should be prevented from acquiring DMG vnodes during vnode reclamation
	 * as we can cause deadlocks to occur, because the namespace handler may prevent
	 * VNOP_INACTIVE from proceeding.  Mark the current task as a P_DEPENDENCY_CAPABLE 
	 * process.
	 */
	curtask = current_task();
	bsd_set_dependency_capable (curtask);	
	
	lck_mtx_lock(&nspace_handler_lock);
	if (nspace_handlers[nspace_type].handler_proc == NULL) {
		nspace_handlers[nspace_type].handler_tid = thread_tid(current_thread());
		nspace_handlers[nspace_type].handler_proc = current_proc();
	}
	
	while (error == 0) {
		
		for(i=0; i < MAX_NSPACE_ITEMS; i++) {
			if (nspace_items[i].flags & NSPACE_ITEM_NEW) {
				if (!nspace_flags_matches_handler(nspace_items[i].flags, nspace_type)) {
					continue;
				}
				break;
			}
		}
		
		if (i < MAX_NSPACE_ITEMS) {
			nspace_items[i].flags  &= ~NSPACE_ITEM_NEW;
			nspace_items[i].flags  |= NSPACE_ITEM_PROCESSING;
			nspace_items[i].token  = ++nspace_token_id;
			
			if (nspace_items[i].vp) {
				struct fileproc *fp;
				int32_t indx, fmode;
				struct proc *p = current_proc();
				vfs_context_t ctx = vfs_context_current();
				struct vnode_attr va;


				/* 
				 * Use vnode pointer to acquire a file descriptor for
				 * hand-off to userland
				 */
				fmode = nspace_open_flags_for_type(nspace_type);
				error = vnode_getwithvid(nspace_items[i].vp, nspace_items[i].vid);
				if (error) {
					unblock = 1;
					break;
				}
				error = vn_open_with_vp(nspace_items[i].vp, fmode, ctx);
				if (error) {
					unblock = 1;
					vnode_put(nspace_items[i].vp);
					break;
				}
				
				if ((error = falloc(p, &fp, &indx, ctx))) {
					vn_close(nspace_items[i].vp, fmode, ctx);
					vnode_put(nspace_items[i].vp);
					unblock = 1;
					break;
				}
				
				fp->f_fglob->fg_flag = fmode;
				fp->f_fglob->fg_ops = &vnops;
				fp->f_fglob->fg_data = (caddr_t)nspace_items[i].vp;
				
				proc_fdlock(p);
				procfdtbl_releasefd(p, indx, NULL);
				fp_drop(p, indx, fp, 1);
				proc_fdunlock(p);	

				/* 
				 * All variants of the namespace handler struct support these three fields:
				 * token, flags, and the FD pointer
				 */
				error = copyout(&nspace_items[i].token, nhd->token, sizeof(uint32_t));
				error = copyout(&nspace_items[i].op, nhd->flags, sizeof(uint64_t));
				error = copyout(&indx, nhd->fdptr, sizeof(uint32_t));

				/* 
				 * Handle optional fields:
				 * extended version support an info ptr (offset, length), and the
				 * 
				 * namedata version supports a unique per-link object ID
				 *
				 */
				if (nhd->infoptr) {
					uio_t uio = (uio_t)nspace_items[i].arg;
					uint64_t u_offset, u_length;
					
					if (uio) {
						u_offset = uio_offset(uio);
						u_length = uio_resid(uio);
					} else {
						u_offset = 0;
						u_length = 0;
					}						
					error = copyout(&u_offset, nhd->infoptr, sizeof(uint64_t));
					error = copyout(&u_length, nhd->infoptr+sizeof(uint64_t), sizeof(uint64_t));
				}

				if (nhd->objid) {	
					VATTR_INIT(&va);
					VATTR_WANTED(&va, va_linkid);
					error = vnode_getattr(nspace_items[i].vp, &va, ctx);
					if (error == 0 ) {
						uint64_t linkid = 0;
						if (VATTR_IS_SUPPORTED (&va, va_linkid)) {
							linkid = (uint64_t)va.va_linkid;
						}
						error = copyout (&linkid, nhd->objid, sizeof(uint64_t));
					}
				}

				if (error) {
					vn_close(nspace_items[i].vp, fmode, ctx);
					fp_free(p, indx, fp);
					unblock = 1;
				}
				
				vnode_put(nspace_items[i].vp);
				
				break;
			} else {
				printf("wait_for_nspace_event: failed (nspace_items[%d] == %p error %d, name %s)\n",
				       i, nspace_items[i].vp, error, nspace_items[i].vp->v_name);
			}
			
		} else {
			error = msleep((caddr_t)&nspace_item_idx, &nspace_handler_lock, PVFS|PCATCH, "namespace-items", 0);
			if ((nspace_type == NSPACE_HANDLER_SNAPSHOT) && (snapshot_timestamp == 0 || snapshot_timestamp == ~0)) {
				error = EINVAL;
				break;
			}
			
		}
	}
	
	if (unblock) {
		if (nspace_items[i].vp && (nspace_items[i].vp->v_flag & VNEEDSSNAPSHOT)) {
			vnode_lock_spin(nspace_items[i].vp);
			nspace_items[i].vp->v_flag &= ~VNEEDSSNAPSHOT;
			vnode_unlock(nspace_items[i].vp);
		}
		nspace_items[i].vp = NULL;
		nspace_items[i].vid = 0;
		nspace_items[i].flags = NSPACE_ITEM_DONE;
		nspace_items[i].token = 0;
		
		wakeup((caddr_t)&(nspace_items[i].vp));
	}
	
	if (nspace_type == NSPACE_HANDLER_SNAPSHOT) {
		// just go through every snapshot event and unblock it immediately.
		if (error && (snapshot_timestamp == 0 || snapshot_timestamp == ~0)) {
			for(i=0; i < MAX_NSPACE_ITEMS; i++) {
				if (nspace_items[i].flags & NSPACE_ITEM_NEW) {
					if (nspace_flags_matches_handler(nspace_items[i].flags, nspace_type)) {
						nspace_items[i].vp = NULL;
						nspace_items[i].vid = 0;
						nspace_items[i].flags = NSPACE_ITEM_DONE;
						nspace_items[i].token = 0;
						
						wakeup((caddr_t)&(nspace_items[i].vp));					
					}
				}
			}
		}
	}
	
	lck_mtx_unlock(&nspace_handler_lock);
	
	lck_mtx_lock(&nspace_handler_exclusion_lock);
	nspace_handlers[nspace_type].handler_busy = 0;
	lck_mtx_unlock(&nspace_handler_exclusion_lock);
	
	return error;
}

static inline int validate_namespace_args (int is64bit, int size) {

	if (is64bit) {
		/* Must be one of these */
		if (size == sizeof(user64_namespace_handler_info)) {
			goto sizeok;
		}
		if (size == sizeof(user64_namespace_handler_info_ext)) {
			goto sizeok;
		}
		if (size == sizeof(user64_namespace_handler_data)) {
			goto sizeok;
		}
		return EINVAL;
	}
	else {
		/* 32 bit -- must be one of these */
		if (size == sizeof(user32_namespace_handler_info)) {
			goto sizeok;
		}
		if (size == sizeof(user32_namespace_handler_info_ext)) {
			goto sizeok;
		}
		if (size == sizeof(user32_namespace_handler_data)) {
			goto sizeok;
		}
		return EINVAL;
	}

sizeok:

	return 0;

}

static int process_namespace_fsctl(nspace_type_t nspace_type, int is64bit, u_int size, caddr_t data)
{
	int error = 0;
	namespace_handler_data nhd;
	
	bzero (&nhd, sizeof(namespace_handler_data));

	if (nspace_type == NSPACE_HANDLER_SNAPSHOT && 
			(snapshot_timestamp == 0 || snapshot_timestamp == ~0)) {
		return EINVAL;
	}
	
	if ((error = suser(kauth_cred_get(), &(current_proc()->p_acflag)))) {
		return error;
	}
	
	error = validate_namespace_args (is64bit, size);
	if (error) {
		return error;
	}
	
	/* Copy in the userland pointers into our kernel-only struct */

	if (is64bit) {
		/* 64 bit userland structures */
		nhd.token = (user_addr_t)((user64_namespace_handler_info *)data)->token;
		nhd.flags = (user_addr_t)((user64_namespace_handler_info *)data)->flags;
		nhd.fdptr = (user_addr_t)((user64_namespace_handler_info *)data)->fdptr;

		/* If the size is greater than the standard info struct, add in extra fields */
		if (size > (sizeof(user64_namespace_handler_info))) {
			if (size >= (sizeof(user64_namespace_handler_info_ext))) {
				nhd.infoptr = (user_addr_t)((user64_namespace_handler_info_ext *)data)->infoptr;
			}
			if (size == (sizeof(user64_namespace_handler_data))) {
				nhd.objid = (user_addr_t)((user64_namespace_handler_data*)data)->objid;
			}
			/* Otherwise the fields were pre-zeroed when we did the bzero above. */
		}
	} 
	else {
		/* 32 bit userland structures */
		nhd.token = CAST_USER_ADDR_T(((user32_namespace_handler_info *)data)->token);
		nhd.flags = CAST_USER_ADDR_T(((user32_namespace_handler_info *)data)->flags);
		nhd.fdptr = CAST_USER_ADDR_T(((user32_namespace_handler_info *)data)->fdptr);
		
		if (size > (sizeof(user32_namespace_handler_info))) {
			if (size >= (sizeof(user32_namespace_handler_info_ext))) {
				nhd.infoptr = CAST_USER_ADDR_T(((user32_namespace_handler_info_ext *)data)->infoptr);
			}
			if (size == (sizeof(user32_namespace_handler_data))) {
				nhd.objid = (user_addr_t)((user32_namespace_handler_data*)data)->objid;
			}
			/* Otherwise the fields were pre-zeroed when we did the bzero above. */
		}
	}
	
	return wait_for_namespace_event(&nhd, nspace_type);
}

/*
 * Make a filesystem-specific control call:
 */
/* ARGSUSED */
static int
fsctl_internal(proc_t p, vnode_t *arg_vp, u_long cmd, user_addr_t udata, u_long options, vfs_context_t ctx)
{
	int error=0;
	boolean_t is64bit;
	u_int size;
#define STK_PARAMS 128
	char stkbuf[STK_PARAMS];
	caddr_t data, memp;
	vnode_t vp = *arg_vp;

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
			error = copyin(udata, data, size);
			if (error) { 
				if (memp) {
					kfree (memp, size);	
				}
				return error;
			}
		} else {
			if (is64bit) {
				*(user_addr_t *)data = udata;
			}
			else {
				*(uint32_t *)data = (uint32_t)udata;
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
			*(user_addr_t *)data = udata;
		}
		else {
			*(uint32_t *)data = (uint32_t)udata;
		}
	}

	/* Check to see if it's a generic command */
	switch (IOCBASECMD(cmd)) {

		case FSCTL_SYNC_VOLUME: {
			mount_t mp = vp->v_mount;
			int arg = *(uint32_t*)data;

			/* record vid of vp so we can drop it below. */
			uint32_t vvid = vp->v_id;

			/*
			 * Then grab mount_iterref so that we can release the vnode.
			 * Without this, a thread may call vnode_iterate_prepare then
			 * get into a deadlock because we've never released the root vp
			 */
			error = mount_iterref (mp, 0);
			if (error)  {
				break;
			}
			vnode_put(vp);

			/* issue the sync for this volume */
			(void)sync_callback(mp, (arg & FSCTL_SYNC_WAIT) ? &arg : NULL);

			/* 
			 * Then release the mount_iterref once we're done syncing; it's not
			 * needed for the VNOP_IOCTL below
			 */
			mount_iterdrop(mp);

			if (arg & FSCTL_SYNC_FULLSYNC) {
				/* re-obtain vnode iocount on the root vp, if possible */
				error = vnode_getwithvid (vp, vvid);
				if (error == 0) {
					error = VNOP_IOCTL(vp, F_FULLFSYNC, (caddr_t)NULL, 0, ctx);
					vnode_put (vp);
				}
			}
			/* mark the argument VP as having been released */
			*arg_vp = NULL;
		}
		break;

		case FSCTL_SET_PACKAGE_EXTS: {
			user_addr_t ext_strings;
			uint32_t    num_entries;
			uint32_t    max_width;

			if (   (is64bit && size != sizeof(user64_package_ext_info))
					|| (is64bit == 0 && size != sizeof(user32_package_ext_info))) {

				// either you're 64-bit and passed a 64-bit struct or
				// you're 32-bit and passed a 32-bit struct.  otherwise
				// it's not ok.
				error = EINVAL;
				break;
			}

			if (is64bit) {
				ext_strings = ((user64_package_ext_info *)data)->strings;
				num_entries = ((user64_package_ext_info *)data)->num_entries;
				max_width   = ((user64_package_ext_info *)data)->max_width;
			} else {
				ext_strings = CAST_USER_ADDR_T(((user32_package_ext_info *)data)->strings);
				num_entries = ((user32_package_ext_info *)data)->num_entries;
				max_width   = ((user32_package_ext_info *)data)->max_width;
			}
			error = set_package_extensions_table(ext_strings, num_entries, max_width);
		}
		break;

   		/* namespace handlers */	
		case FSCTL_NAMESPACE_HANDLER_GET: {
			error = process_namespace_fsctl(NSPACE_HANDLER_NSPACE, is64bit, size, data);
		}
		break;

		/* Snapshot handlers */
		case FSCTL_OLD_SNAPSHOT_HANDLER_GET: {
			error = process_namespace_fsctl(NSPACE_HANDLER_SNAPSHOT, is64bit, size, data);
		} 
		break;

		case FSCTL_SNAPSHOT_HANDLER_GET_EXT: {
			error = process_namespace_fsctl(NSPACE_HANDLER_SNAPSHOT, is64bit, size, data);
		}
		break;	

		case FSCTL_NAMESPACE_HANDLER_UPDATE: {
			uint32_t token, val;
			int i;

			if ((error = suser(kauth_cred_get(), &(p->p_acflag)))) {
				break;
			}

			if (!nspace_is_special_process(p)) {
				error = EINVAL;
				break;
			}

			token = ((uint32_t *)data)[0];
			val   = ((uint32_t *)data)[1];

			lck_mtx_lock(&nspace_handler_lock);

			for(i=0; i < MAX_NSPACE_ITEMS; i++) {
				if (nspace_items[i].token == token) {
					break;  /* exit for loop, not case stmt */
				}
			}

			if (i >= MAX_NSPACE_ITEMS) {
				error = ENOENT;
			} else {
				//
				// if this bit is set, when resolve_nspace_item() times out
				// it will loop and go back to sleep.
				//
				nspace_items[i].flags |= NSPACE_ITEM_RESET_TIMER;
			}

			lck_mtx_unlock(&nspace_handler_lock);

			if (error) {
				printf("nspace-handler-update: did not find token %u\n", token);
			}
		} 
		break;
	
		case FSCTL_NAMESPACE_HANDLER_UNBLOCK: {	
			uint32_t token, val;
			int i;

			if ((error = suser(kauth_cred_get(), &(p->p_acflag)))) {
				break;
			}

			if (!nspace_is_special_process(p)) {
				error = EINVAL;
				break;
			}

			token = ((uint32_t *)data)[0];
			val   = ((uint32_t *)data)[1];

			lck_mtx_lock(&nspace_handler_lock);

			for(i=0; i < MAX_NSPACE_ITEMS; i++) {
				if (nspace_items[i].token == token) {
					break; /* exit for loop, not case statement */
				}
			}

			if (i >= MAX_NSPACE_ITEMS) {
				printf("nspace-handler-unblock: did not find token %u\n", token);
				error = ENOENT;
			} else {
				if (val == 0 && nspace_items[i].vp) {
					vnode_lock_spin(nspace_items[i].vp);
					nspace_items[i].vp->v_flag &= ~VNEEDSSNAPSHOT;
					vnode_unlock(nspace_items[i].vp);
				}

				nspace_items[i].vp = NULL;
				nspace_items[i].arg = NULL;
				nspace_items[i].op = 0;
				nspace_items[i].vid = 0;
				nspace_items[i].flags = NSPACE_ITEM_DONE;
				nspace_items[i].token = 0;

				wakeup((caddr_t)&(nspace_items[i].vp));
			}

			lck_mtx_unlock(&nspace_handler_lock);
		} 
		break;

		case FSCTL_NAMESPACE_HANDLER_CANCEL: {
			uint32_t token, val;
			int i;

			if ((error = suser(kauth_cred_get(), &(p->p_acflag)))) {
				break;
			}

			if (!nspace_is_special_process(p)) {
				error = EINVAL;
				break;
			}

			token = ((uint32_t *)data)[0];
			val   = ((uint32_t *)data)[1];

			lck_mtx_lock(&nspace_handler_lock);

			for(i=0; i < MAX_NSPACE_ITEMS; i++) {
				if (nspace_items[i].token == token) {
					break;  /* exit for loop, not case stmt */
				}
			}

			if (i >= MAX_NSPACE_ITEMS) {
				printf("nspace-handler-cancel: did not find token %u\n", token);
				error = ENOENT;
			} else {
				if (nspace_items[i].vp) {
					vnode_lock_spin(nspace_items[i].vp);
					nspace_items[i].vp->v_flag &= ~VNEEDSSNAPSHOT;
					vnode_unlock(nspace_items[i].vp);
				}

				nspace_items[i].vp = NULL;			
				nspace_items[i].arg = NULL;			
				nspace_items[i].vid = 0;
				nspace_items[i].token = val;
				nspace_items[i].flags &= ~NSPACE_ITEM_PROCESSING;
				nspace_items[i].flags |= NSPACE_ITEM_CANCELLED;			

				wakeup((caddr_t)&(nspace_items[i].vp));
			}

			lck_mtx_unlock(&nspace_handler_lock);
		} 
		break;

		case FSCTL_NAMESPACE_HANDLER_SET_SNAPSHOT_TIME: {
			if ((error = suser(kauth_cred_get(), &(current_proc()->p_acflag)))) {
				break;
			}

			// we explicitly do not do the namespace_handler_proc check here

			lck_mtx_lock(&nspace_handler_lock);
			snapshot_timestamp = ((uint32_t *)data)[0];
			wakeup(&nspace_item_idx);
			lck_mtx_unlock(&nspace_handler_lock);
			printf("nspace-handler-set-snapshot-time: %d\n", (int)snapshot_timestamp);

		} 
		break;

		case FSCTL_NAMESPACE_ALLOW_DMG_SNAPSHOT_EVENTS:
		{
			if ((error = suser(kauth_cred_get(), &(current_proc()->p_acflag)))) {
				break;
			}

			lck_mtx_lock(&nspace_handler_lock);
			nspace_allow_virtual_devs = ((uint32_t *)data)[0];
			lck_mtx_unlock(&nspace_handler_lock);
			printf("nspace-snapshot-handler will%s allow events on disk-images\n",
					nspace_allow_virtual_devs ? "" : " NOT");
			error = 0;

		}
		break;

		case FSCTL_SET_FSTYPENAME_OVERRIDE: 
		{	
			if ((error = suser(kauth_cred_get(), &(current_proc()->p_acflag)))) {
				break;
			}
			if (vp->v_mount) {
				mount_lock(vp->v_mount);
				if (data[0] != 0) {
					strlcpy(&vp->v_mount->fstypename_override[0], data, MFSTYPENAMELEN);
					vp->v_mount->mnt_kern_flag |= MNTK_TYPENAME_OVERRIDE;
					if (vfs_isrdonly(vp->v_mount) && strcmp(vp->v_mount->fstypename_override, "mtmfs") == 0) {
						vp->v_mount->mnt_kern_flag |= MNTK_EXTENDED_SECURITY;
						vp->v_mount->mnt_kern_flag &= ~MNTK_AUTH_OPAQUE;
					}
				} else {
					if (strcmp(vp->v_mount->fstypename_override, "mtmfs") == 0) {
						vp->v_mount->mnt_kern_flag &= ~MNTK_EXTENDED_SECURITY;
					}
					vp->v_mount->mnt_kern_flag &= ~MNTK_TYPENAME_OVERRIDE;
					vp->v_mount->fstypename_override[0] = '\0';
				}
				mount_unlock(vp->v_mount);
			}
		}
		break;
	   	
		default: {
			/* Invoke the filesystem-specific code */
			error = VNOP_IOCTL(vp, IOCBASECMD(cmd), data, options, ctx);
		}

	} /* end switch stmt */

	/*
	 * if no errors, copy any data to user. Size was
	 * already set and checked above.
	 */
	if (error == 0 && (cmd & IOC_OUT) && size) 
		error = copyout(data, udata, size);
	
	if (memp) {
		kfree(memp, size);
	}
	
	return error;
}

/* ARGSUSED */
int
fsctl (proc_t p, struct fsctl_args *uap, __unused int32_t *retval)
{
	int error;
	struct nameidata nd;	
	u_long nameiflags;
	vnode_t vp = NULL;
	vfs_context_t ctx = vfs_context_current();

	AUDIT_ARG(cmd, uap->cmd);
	AUDIT_ARG(value32, uap->options);
	/* Get the vnode for the file we are getting info on:  */
	nameiflags = 0;
	if ((uap->options & FSOPT_NOFOLLOW) == 0) nameiflags |= FOLLOW;
	NDINIT(&nd, LOOKUP, OP_FSCTL, nameiflags | AUDITVNPATH1,
	       UIO_USERSPACE, uap->path, ctx);
	if ((error = namei(&nd))) goto done;
	vp = nd.ni_vp;
	nameidone(&nd);

#if CONFIG_MACF
	error = mac_mount_check_fsctl(ctx, vnode_mount(vp), uap->cmd);
	if (error) {
		goto done;
	}
#endif

	error = fsctl_internal(p, &vp, uap->cmd, (user_addr_t)uap->data, uap->options, ctx);

done:
	if (vp)
		vnode_put(vp);
	return error;
}
/* ARGSUSED */
int
ffsctl (proc_t p, struct ffsctl_args *uap, __unused int32_t *retval)
{
	int error;
	vnode_t vp = NULL;
	vfs_context_t ctx = vfs_context_current();
	int fd = -1;

	AUDIT_ARG(fd, uap->fd);
	AUDIT_ARG(cmd, uap->cmd);
	AUDIT_ARG(value32, uap->options);
	
	/* Get the vnode for the file we are getting info on:  */
	if ((error = file_vnode(uap->fd, &vp)))
		goto done;
	fd = uap->fd;
	if ((error = vnode_getwithref(vp))) {
		goto done;
	}

#if CONFIG_MACF
	error = mac_mount_check_fsctl(ctx, vnode_mount(vp), uap->cmd);
	if (error) {
		goto done;
	}
#endif

	error = fsctl_internal(p, &vp, uap->cmd, (user_addr_t)uap->data, uap->options, ctx);

done:
	if (fd != -1)
		file_drop(fd);

	if (vp)
		vnode_put(vp);
	return error;
}
/* end of fsctl system call */

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
	u_int32_t nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOSECURITY | XATTR_NODEFAULT))
		return (EINVAL);

	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, OP_GETXATTR, nameiflags, spacetype, uap->path, ctx);
	if ((error = namei(&nd))) {
		return (error);
	}
	vp = nd.ni_vp;
	nameidone(&nd);

	if ((error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen) != 0)) {
		goto out;
	}
	if (xattr_protected(attrname)) {
		if (!vfs_context_issuser(ctx) || strcmp(attrname, "com.apple.system.Security") != 0) {
			error = EPERM;
			goto out;
		}
	}
	/*
	 * the specific check for 0xffffffff is a hack to preserve
	 * binaray compatibilty in K64 with applications that discovered
	 * that passing in a buf pointer and a size of -1 resulted in 
	 * just the size of the indicated extended attribute being returned.
	 * this isn't part of the documented behavior, but because of the
	 * original implemtation's check for "uap->size > 0", this behavior
	 * was allowed. In K32 that check turned into a signed comparison
	 * even though uap->size is unsigned...  in K64, we blow by that
	 * check because uap->size is unsigned and doesn't get sign smeared
	 * in the munger for a 32 bit user app.  we also need to add a 
	 * check to limit the maximum size of the buffer being passed in...
	 * unfortunately, the underlying fileystems seem to just malloc
	 * the requested size even if the actual extended attribute is tiny.
	 * because that malloc is for kernel wired memory, we have to put a
	 * sane limit on it.
	 *
	 * U32 running on K64 will yield 0x00000000ffffffff for uap->size
	 * U64 running on K64 will yield -1 (64 bits wide)
	 * U32/U64 running on K32 will yield -1 (32 bits wide)
	 */
	if (uap->size == 0xffffffff || uap->size == (size_t)-1)
		goto no_uio;

	if (uap->value) {
		if (uap->size > (size_t)XATTR_MAXSIZE)
			uap->size = XATTR_MAXSIZE;
		
		auio = uio_createwithbuffer(1, uap->position, spacetype, UIO_READ,
		                            &uio_buf[0], sizeof(uio_buf));
		uio_addiov(auio, uap->value, uap->size);
	}
no_uio:
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
	u_int32_t nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOSECURITY | XATTR_NODEFAULT))
		return (EINVAL);

	if ((error = copyinstr(uap->attrname, attrname, sizeof(attrname), &namelen) != 0)) {
		if (error == EPERM) {
			/* if the string won't fit in attrname, copyinstr emits EPERM */
			return (ENAMETOOLONG);
		}
		/* Otherwise return the default error from copyinstr to detect ERANGE, etc */
		return error;
	}
	if (xattr_protected(attrname))
		return(EPERM);
	if (uap->size != 0 && uap->value == 0) {
		return (EINVAL);
	}

	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, OP_SETXATTR, nameiflags, spacetype, uap->path, ctx);
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
#if CONFIG_FSE
	vfs_context_t ctx = vfs_context_current();
#endif

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
 * XXX Code duplication here.
 */
int
removexattr(proc_t p, struct removexattr_args *uap, int *retval)
{
	vnode_t vp;
	struct nameidata nd;
	char attrname[XATTR_MAXNAMELEN+1];
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	vfs_context_t ctx = vfs_context_current();
	size_t namelen;
	u_int32_t nameiflags;
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
	NDINIT(&nd, LOOKUP, OP_REMOVEXATTR, nameiflags, spacetype, uap->path, ctx);
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
 * XXX Code duplication here.
 */
int
fremovexattr(__unused proc_t p, struct fremovexattr_args *uap, int *retval)
{
	vnode_t vp;
	char attrname[XATTR_MAXNAMELEN+1];
	size_t namelen;
	int error;
#if CONFIG_FSE
	vfs_context_t ctx = vfs_context_current();
#endif

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
 * XXX Code duplication here.
 */
int
listxattr(proc_t p, struct listxattr_args *uap, user_ssize_t *retval)
{
	vnode_t vp;
	struct nameidata nd;
	vfs_context_t ctx = vfs_context_current();
	uio_t auio = NULL;
	int spacetype = IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
	size_t attrsize = 0;
	u_int32_t nameiflags;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (uap->options & (XATTR_NOSECURITY | XATTR_NODEFAULT))
		return (EINVAL);

	nameiflags = (uap->options & XATTR_NOFOLLOW) ? 0 : FOLLOW;
	NDINIT(&nd, LOOKUP, OP_LISTXATTR, nameiflags, spacetype, uap->path, ctx);
	if ((error = namei(&nd))) {
		return (error);
	}
	vp = nd.ni_vp;
	nameidone(&nd);
	if (uap->namebuf != 0 && uap->bufsize > 0) {
		auio = uio_createwithbuffer(1, 0, spacetype, UIO_READ,
		                            &uio_buf[0], sizeof(uio_buf));
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
 * XXX Code duplication here.
 */
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

static int fsgetpath_internal(
	vfs_context_t ctx, int volfs_id, uint64_t objid,
	vm_size_t bufsize, caddr_t buf, int *pathlen)
{
	int error;
	struct mount *mp = NULL;
	vnode_t vp;
	int length;
	int bpflags;

	if (bufsize > PAGE_SIZE) {
		return (EINVAL);
	}

	if (buf == NULL) {
		return (ENOMEM);
	}

	if ((mp = mount_lookupby_volfsid(volfs_id, 1)) == NULL) {
		error = ENOTSUP;  /* unexpected failure */
		return ENOTSUP;
	}

unionget:
	if (objid == 2) {
		error = VFS_ROOT(mp, &vp, ctx);
	} else {
		error = VFS_VGET(mp, (ino64_t)objid, &vp, ctx);
	}

	if (error == ENOENT && (mp->mnt_flag & MNT_UNION)) {
		/*
		 * If the fileid isn't found and we're in a union
		 * mount volume, then see if the fileid is in the
		 * mounted-on volume.
		 */
		struct mount *tmp = mp;
		mp = vnode_mount(tmp->mnt_vnodecovered);
		vfs_unbusy(tmp);
		if (vfs_busy(mp, LK_NOWAIT) == 0)
			goto unionget;
	} else {
		vfs_unbusy(mp);
	}

	if (error) {
		return error;
	}

#if CONFIG_MACF
	error = mac_vnode_check_fsgetpath(ctx, vp);
	if (error) {
		vnode_put(vp);
		return error;
	}
#endif

	/* Obtain the absolute path to this vnode. */
	bpflags = vfs_context_suser(ctx) ? BUILDPATH_CHECKACCESS : 0;
	bpflags |= BUILDPATH_CHECK_MOVED;
	error = build_path(vp, buf, bufsize, &length, bpflags, ctx);
	vnode_put(vp);

	if (error) {
		goto out;
	}

	AUDIT_ARG(text, buf);

	if (kdebug_enable) {
		long dbg_parms[NUMPARMS];
                int  dbg_namelen;

                dbg_namelen = (int)sizeof(dbg_parms);

        if (length < dbg_namelen) {
			memcpy((char *)dbg_parms, buf, length);
			memset((char *)dbg_parms + length, 0, dbg_namelen - length);

			dbg_namelen = length;
		} else {
			memcpy((char *)dbg_parms, buf + (length - dbg_namelen), dbg_namelen);
		}

		kdebug_lookup_gen_events(dbg_parms, dbg_namelen, (void *)vp, TRUE);
	}

	*pathlen = (user_ssize_t)length; /* may be superseded by error */

out:
	return (error);
}

/*
 * Obtain the full pathname of a file system object by id.
 *
 * This is a private SPI used by the File Manager.
 */
__private_extern__
int
fsgetpath(__unused proc_t p, struct fsgetpath_args *uap, user_ssize_t *retval)
{
	vfs_context_t ctx = vfs_context_current();
	fsid_t fsid;
	char *realpath;
	int length;
	int error;

	if ((error = copyin(uap->fsid, (caddr_t)&fsid, sizeof(fsid)))) {
		return (error);
	}
	AUDIT_ARG(value32, fsid.val[0]);
	AUDIT_ARG(value64, uap->objid);
	/* Restrict output buffer size for now. */
	
	if (uap->bufsize > PAGE_SIZE) {
		return (EINVAL);
	}	
	MALLOC(realpath, char *, uap->bufsize, M_TEMP, M_WAITOK);
	if (realpath == NULL) {
		return (ENOMEM);
	}

	error = fsgetpath_internal(
		ctx, fsid.val[0], uap->objid, 
		uap->bufsize, realpath, &length);

	if (error) {
		goto out;
	}
	
	error = copyout((caddr_t)realpath, uap->buf, length);

	*retval = (user_ssize_t)length; /* may be superseded by error */
out:
	if (realpath) {
		FREE(realpath, M_TEMP);
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
		struct user64_statfs sfs;
		my_size = copy_size = sizeof(sfs);
		bzero(&sfs, my_size);
		sfs.f_flags = mp->mnt_flag & MNT_VISFLAGMASK;
		sfs.f_type = mp->mnt_vtable->vfc_typenum;
		sfs.f_reserved1 = (short)sfsp->f_fssubtype;
		sfs.f_bsize = (user64_long_t)sfsp->f_bsize;
		sfs.f_iosize = (user64_long_t)sfsp->f_iosize;
		sfs.f_blocks = (user64_long_t)sfsp->f_blocks;
		sfs.f_bfree = (user64_long_t)sfsp->f_bfree;
		sfs.f_bavail = (user64_long_t)sfsp->f_bavail;
		sfs.f_files = (user64_long_t)sfsp->f_files;
		sfs.f_ffree = (user64_long_t)sfsp->f_ffree;
		sfs.f_fsid = sfsp->f_fsid;
		sfs.f_owner = sfsp->f_owner;
		if (mp->mnt_kern_flag & MNTK_TYPENAME_OVERRIDE) {
			strlcpy(&sfs.f_fstypename[0], &mp->fstypename_override[0], MFSNAMELEN);
		} else {
			strlcpy(&sfs.f_fstypename[0], &sfsp->f_fstypename[0], MFSNAMELEN);
		}
		strlcpy(&sfs.f_mntonname[0], &sfsp->f_mntonname[0], MNAMELEN);
		strlcpy(&sfs.f_mntfromname[0], &sfsp->f_mntfromname[0], MNAMELEN);

		if (partial_copy) {
			copy_size -= (sizeof(sfs.f_reserved3) + sizeof(sfs.f_reserved4));
		}
		error = copyout((caddr_t)&sfs, bufp, copy_size);
	}
	else {
		struct user32_statfs sfs;

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
		if ((sfsp->f_blocks > INT_MAX) 
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
				if ((sfsp->f_blocks >> shift) <= INT_MAX)
					break;
				if ((sfsp->f_bsize << (shift + 1)) > INT_MAX)
					break;
			}
#define __SHIFT_OR_CLIP(x, s)	((((x) >> (s)) > INT_MAX) ? INT_MAX : ((x) >> (s)))
			sfs.f_blocks = (user32_long_t)__SHIFT_OR_CLIP(sfsp->f_blocks, shift);
			sfs.f_bfree = (user32_long_t)__SHIFT_OR_CLIP(sfsp->f_bfree, shift);
			sfs.f_bavail = (user32_long_t)__SHIFT_OR_CLIP(sfsp->f_bavail, shift);
#undef __SHIFT_OR_CLIP
			sfs.f_bsize = (user32_long_t)(sfsp->f_bsize << shift);
			sfs.f_iosize = lmax(sfsp->f_iosize, sfsp->f_bsize);
		} else {
			/* filesystem is small enough to be reported honestly */
			sfs.f_bsize = (user32_long_t)sfsp->f_bsize;
			sfs.f_iosize = (user32_long_t)sfsp->f_iosize;
			sfs.f_blocks = (user32_long_t)sfsp->f_blocks;
			sfs.f_bfree = (user32_long_t)sfsp->f_bfree;
			sfs.f_bavail = (user32_long_t)sfsp->f_bavail;
		}
		sfs.f_files = (user32_long_t)sfsp->f_files;
		sfs.f_ffree = (user32_long_t)sfsp->f_ffree;
		sfs.f_fsid = sfsp->f_fsid;
		sfs.f_owner = sfsp->f_owner;
		if (mp->mnt_kern_flag & MNTK_TYPENAME_OVERRIDE) {
			strlcpy(&sfs.f_fstypename[0], &mp->fstypename_override[0], MFSNAMELEN);
		} else {
			strlcpy(&sfs.f_fstypename[0], &sfsp->f_fstypename[0], MFSNAMELEN);
		}
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
void munge_user64_stat(struct stat *sbp, struct user64_stat *usbp)
{
	bzero(usbp, sizeof(*usbp));

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

void munge_user32_stat(struct stat *sbp, struct user32_stat *usbp)
{
	bzero(usbp, sizeof(*usbp));

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
void munge_user64_stat64(struct stat64 *sbp, struct user64_stat64 *usbp)
{
	bzero(usbp, sizeof(*usbp));

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

void munge_user32_stat64(struct stat64 *sbp, struct user32_stat64 *usbp)
{
	bzero(usbp, sizeof(*usbp));

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

/*
 * Purge buffer cache for simulating cold starts
 */
static int vnode_purge_callback(struct vnode *vp, __unused void *cargs)
{
	ubc_msync(vp, (off_t)0, ubc_getsize(vp), NULL /* off_t *resid_off */, UBC_PUSHALL | UBC_INVALIDATE);

	return VNODE_RETURNED;
}

static int vfs_purge_callback(mount_t mp, __unused void * arg)
{
	vnode_iterate(mp, VNODE_WAIT | VNODE_ITERATE_ALL, vnode_purge_callback, NULL);

	return VFS_RETURNED;
}

int
vfs_purge(__unused struct proc *p, __unused struct vfs_purge_args *uap, __unused int32_t *retval)
{
	if (!kauth_cred_issuser(kauth_cred_get()))
		return EPERM;

	vfs_iterate(0/* flags */, vfs_purge_callback, NULL);

	return 0;
}

