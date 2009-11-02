/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 * External virtual filesystem routines
 */

#undef	DIAGNOSTIC
#define DIAGNOSTIC 1

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
#include <sys/fsevents.h>
#include <sys/user.h>
#include <sys/lockf.h>
#include <sys/xattr.h>

#include <kern/assert.h>
#include <kern/kalloc.h>

#include <miscfs/specfs/specdev.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>

#define ESUCCESS 0
#undef mount_t
#undef vnode_t

#define COMPAT_ONLY


#define THREAD_SAFE_FS(VP)  \
	((VP)->v_unsafefs ? 0 : 1)

#define NATIVE_XATTR(VP)  \
	((VP)->v_mount ? (VP)->v_mount->mnt_vtable->vfc_vfsflags & VFC_VFSNATIVEXATTR : 0)

static void xattrfile_remove(vnode_t dvp, const char * basename, vfs_context_t context,
                             int thread_safe, int force);
static void xattrfile_setattr(vnode_t dvp, const char * basename, struct vnode_attr * vap,
                              vfs_context_t context, int thread_safe);


static void
vnode_setneedinactive(vnode_t vp)
{
        cache_purge(vp);

        vnode_lock(vp);
	vp->v_lflag |= VL_NEEDINACTIVE;
	vnode_unlock(vp);
}


int
lock_fsnode(vnode_t vp, int *funnel_state)
{
        if (funnel_state)
		*funnel_state = thread_funnel_set(kernel_flock, TRUE);

        if (vp->v_unsafefs) {
		if (vp->v_unsafefs->fsnodeowner == current_thread()) {
		        vp->v_unsafefs->fsnode_count++;
		} else {
		        lck_mtx_lock(&vp->v_unsafefs->fsnodelock);

			if (vp->v_lflag & (VL_TERMWANT | VL_TERMINATE | VL_DEAD)) {
			        lck_mtx_unlock(&vp->v_unsafefs->fsnodelock);

				if (funnel_state)
				        (void) thread_funnel_set(kernel_flock, *funnel_state);
				return (ENOENT);
			}
			vp->v_unsafefs->fsnodeowner = current_thread();
			vp->v_unsafefs->fsnode_count = 1;
		}
	}
	return (0);
}


void
unlock_fsnode(vnode_t vp, int *funnel_state)
{
        if (vp->v_unsafefs) {
   	 	if (--vp->v_unsafefs->fsnode_count == 0) {
		        vp->v_unsafefs->fsnodeowner = NULL;
			lck_mtx_unlock(&vp->v_unsafefs->fsnodelock);
		}
	}
	if (funnel_state)
	        (void) thread_funnel_set(kernel_flock, *funnel_state);
}



/* ====================================================================== */
/* ************  EXTERNAL KERNEL APIS  ********************************** */
/* ====================================================================== */

/*
 * prototypes for exported VFS operations
 */
int 
VFS_MOUNT(struct mount * mp, vnode_t devvp, user_addr_t data, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_mount == 0))
		return(ENOTSUP);

	thread_safe = mp->mnt_vtable->vfc_threadsafe;


	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	
	if (vfs_context_is64bit(context)) {
		if (vfs_64bitready(mp)) {
			error = (*mp->mnt_op->vfs_mount)(mp, devvp, data, context);
		}
		else {
			error = ENOTSUP;
		}
	}
	else {
		error = (*mp->mnt_op->vfs_mount)(mp, devvp, data, context);
	}
	
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_START(struct mount * mp, int flags, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_start == 0))
		return(ENOTSUP);

	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_start)(mp, flags, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_UNMOUNT(struct mount *mp, int flags, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_unmount == 0))
		return(ENOTSUP);

	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_unmount)(mp, flags, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_ROOT(struct mount * mp, struct vnode  ** vpp, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_root == 0))
		return(ENOTSUP);

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_root)(mp, vpp, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_QUOTACTL(struct mount *mp, int cmd, uid_t uid, caddr_t datap, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_quotactl == 0))
		return(ENOTSUP);

	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_quotactl)(mp, cmd, uid, datap, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_GETATTR(struct mount *mp, struct vfs_attr *vfa, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_getattr == 0))
		return(ENOTSUP);

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;
	
	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_getattr)(mp, vfa, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_SETATTR(struct mount *mp, struct vfs_attr *vfa, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_setattr == 0))
		return(ENOTSUP);

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;
	
	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_setattr)(mp, vfa, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_SYNC(struct mount *mp, int flags, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_sync == 0))
		return(ENOTSUP);

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_sync)(mp, flags, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_VGET(struct mount * mp, ino64_t ino, struct vnode **vpp, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_vget == 0))
		return(ENOTSUP);

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_vget)(mp, ino, vpp, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_FHTOVP(struct mount * mp, int fhlen, unsigned char * fhp, vnode_t * vpp, vfs_context_t context) 
{
	int error;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_fhtovp == 0))
		return(ENOTSUP);

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_fhtovp)(mp, fhlen, fhp, vpp, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_VPTOFH(struct vnode * vp, int *fhlenp, unsigned char * fhp, vfs_context_t context)
{
	int error;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if ((vp->v_mount == dead_mountp) || (vp->v_mount->mnt_op->vfs_vptofh == 0))
		return(ENOTSUP);

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*vp->v_mount->mnt_op->vfs_vptofh)(vp, fhlenp, fhp, context);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}


/* returns a  copy of vfs type name for the mount_t */
void 
vfs_name(mount_t mp, char * buffer)
{
        strncpy(buffer, mp->mnt_vtable->vfc_name, MFSNAMELEN);
}

/* returns  vfs type number for the mount_t */
int 
vfs_typenum(mount_t mp)
{
	return(mp->mnt_vtable->vfc_typenum);
}


/* returns command modifier flags of mount_t ie. MNT_CMDFLAGS */
uint64_t 
vfs_flags(mount_t mp)
{
	return((uint64_t)(mp->mnt_flag & (MNT_CMDFLAGS | MNT_VISFLAGMASK)));
}

/* set any of the command modifier flags(MNT_CMDFLAGS) in mount_t */
void 
vfs_setflags(mount_t mp, uint64_t flags)
{
	uint32_t lflags = (uint32_t)(flags & (MNT_CMDFLAGS | MNT_VISFLAGMASK)); 

	mp->mnt_flag |= lflags;
}

/* clear any of the command modifier flags(MNT_CMDFLAGS) in mount_t */
void 
vfs_clearflags(mount_t mp , uint64_t flags)
{
	uint32_t lflags = (uint32_t)(flags & (MNT_CMDFLAGS | MNT_VISFLAGMASK)); 

	mp->mnt_flag &= ~lflags;
}

/* Is the mount_t ronly and upgrade read/write requested? */
int 
vfs_iswriteupgrade(mount_t mp) /* ronly &&  MNTK_WANTRDWR */
{
	return ((mp->mnt_flag & MNT_RDONLY) && (mp->mnt_kern_flag & MNTK_WANTRDWR));
}


/* Is the mount_t mounted ronly */
int 
vfs_isrdonly(mount_t mp)
{
	return (mp->mnt_flag & MNT_RDONLY);
}

/* Is the mount_t mounted for filesystem synchronous writes? */
int 
vfs_issynchronous(mount_t mp)
{
	return (mp->mnt_flag & MNT_SYNCHRONOUS);
}

/* Is the mount_t mounted read/write? */
int 
vfs_isrdwr(mount_t mp)
{
	return ((mp->mnt_flag & MNT_RDONLY) == 0);
}


/* Is mount_t marked for update (ie MNT_UPDATE) */
int 
vfs_isupdate(mount_t mp) 
{
	return (mp->mnt_flag & MNT_UPDATE);
}


/* Is mount_t marked for reload (ie MNT_RELOAD) */
int 
vfs_isreload(mount_t mp)
{
	return ((mp->mnt_flag & MNT_UPDATE) && (mp->mnt_flag & MNT_RELOAD));
}

/* Is mount_t marked for reload (ie MNT_FORCE) */
int 
vfs_isforce(mount_t mp)
{
	if ((mp->mnt_flag & MNT_FORCE) || (mp->mnt_kern_flag & MNTK_FRCUNMOUNT))
		return(1);
	else
		return(0);
}

int
vfs_64bitready(mount_t mp)
{
	if ((mp->mnt_vtable->vfc_64bitready))
		return(1);
	else
		return(0);
}

int
vfs_authopaque(mount_t mp)
{
	if ((mp->mnt_kern_flag & MNTK_AUTH_OPAQUE))
		return(1);
	else
		return(0);
}

int 
vfs_authopaqueaccess(mount_t mp)
{
	if ((mp->mnt_kern_flag & MNTK_AUTH_OPAQUE_ACCESS))
		return(1);
	else
		return(0);
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

int
vfs_extendedsecurity(mount_t mp)
{
	return(mp->mnt_kern_flag & MNTK_EXTENDED_SECURITY);
}

/* returns the max size of short symlink in this mount_t */
uint32_t 
vfs_maxsymlen(mount_t mp)
{
	return(mp->mnt_maxsymlinklen);
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
	return(&mp->mnt_vfsstat);
}

int
vfs_getattr(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx)
{
	int		error;
	char		*vname;

	if ((error = VFS_GETATTR(mp, vfa, ctx)) != 0)
		return(error);

	/*
 	 * If we have a filesystem create time, use it to default some others.
 	 */
 	if (VFSATTR_IS_SUPPORTED(vfa, f_create_time)) {
 		if (VFSATTR_IS_ACTIVE(vfa, f_modify_time) && !VFSATTR_IS_SUPPORTED(vfa, f_modify_time))
 			VFSATTR_RETURN(vfa, f_modify_time, vfa->f_create_time);
 	}

	return(0);
}

int
vfs_setattr(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx)
{
	int error;
	
	if (vfs_isrdonly(mp))
		return EROFS;

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
	return(mp->mnt_data);
}

/* set the private data handle in mount_t */
void 
vfs_setfsprivate(mount_t mp, void *mntdata)
{
	mp->mnt_data = mntdata;
}


/*
 * return the block size of the underlying
 * device associated with mount_t
 */
int
vfs_devblocksize(mount_t mp) {

        return(mp->mnt_devblocksize);
}


/*
 * return the io attributes associated with mount_t
 */
void
vfs_ioattr(mount_t mp, struct vfsioattr *ioattrp)
{
        if (mp == NULL) {
	        ioattrp->io_maxreadcnt  = MAXPHYS;
		ioattrp->io_maxwritecnt = MAXPHYS;
		ioattrp->io_segreadcnt  = 32;
		ioattrp->io_segwritecnt = 32;
		ioattrp->io_maxsegreadsize  = MAXPHYS;
		ioattrp->io_maxsegwritesize = MAXPHYS;
		ioattrp->io_devblocksize = DEV_BSIZE;
	} else {
	        ioattrp->io_maxreadcnt  = mp->mnt_maxreadcnt;
		ioattrp->io_maxwritecnt = mp->mnt_maxwritecnt;
		ioattrp->io_segreadcnt  = mp->mnt_segreadcnt;
		ioattrp->io_segwritecnt = mp->mnt_segwritecnt;
		ioattrp->io_maxsegreadsize  = mp->mnt_maxsegreadsize;
		ioattrp->io_maxsegwritesize = mp->mnt_maxsegwritesize;
		ioattrp->io_devblocksize = mp->mnt_devblocksize;
	}
	ioattrp->io_reserved[0] = 0;
	ioattrp->io_reserved[1] = 0;
	ioattrp->io_reserved[2] = 0;
}


/*
 * set the IO attributes associated with mount_t
 */
void 
vfs_setioattr(mount_t mp, struct vfsioattr * ioattrp)
{
        if (mp == NULL)
	        return;
        mp->mnt_maxreadcnt  = ioattrp->io_maxreadcnt;
	mp->mnt_maxwritecnt = ioattrp->io_maxwritecnt;
	mp->mnt_segreadcnt  = ioattrp->io_segreadcnt;
	mp->mnt_segwritecnt = ioattrp->io_segwritecnt;
	mp->mnt_maxsegreadsize = ioattrp->io_maxsegreadsize;
	mp->mnt_maxsegwritesize = ioattrp->io_maxsegwritesize;
	mp->mnt_devblocksize = ioattrp->io_devblocksize;
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
vfs_fsadd(struct vfs_fsentry *vfe, vfstable_t * handle)
{
#pragma unused(data)
	struct vfstable	*newvfstbl = NULL;
	int	i,j;
	int	(***opv_desc_vector_p)(void *);
	int	(**opv_desc_vector)(void *);
	struct vnodeopv_entry_desc	*opve_descp; 
	int desccount;
	int descsize;
	PFI *descptr;

	/*
	 * This routine is responsible for all the initialization that would
	 * ordinarily be done as part of the system startup;
	 */

	if (vfe == (struct vfs_fsentry *)0)
		return(EINVAL);

	desccount = vfe->vfe_vopcnt;
	if ((desccount <=0) || ((desccount > 5)) || (vfe->vfe_vfsops == (struct vfsops *)NULL)
		|| (vfe->vfe_opvdescs == (struct vnodeopv_desc **)NULL))
		return(EINVAL);


	MALLOC(newvfstbl, void *, sizeof(struct vfstable), M_TEMP,
	       M_WAITOK);
	bzero(newvfstbl, sizeof(struct vfstable));
	newvfstbl->vfc_vfsops = vfe->vfe_vfsops;
	strncpy(&newvfstbl->vfc_name[0], vfe->vfe_fsname, MFSNAMELEN);
	if ((vfe->vfe_flags & VFS_TBLNOTYPENUM))
		newvfstbl->vfc_typenum = maxvfsconf++;
	else
		newvfstbl->vfc_typenum = vfe->vfe_fstypenum;
	
	newvfstbl->vfc_refcount = 0;
	newvfstbl->vfc_flags = 0;
	newvfstbl->vfc_mountroot = NULL;
	newvfstbl->vfc_next = NULL;
	newvfstbl->vfc_threadsafe = 0;
	newvfstbl->vfc_vfsflags = 0;
	if (vfe->vfe_flags &  VFS_TBL64BITREADY)
		newvfstbl->vfc_64bitready= 1;
	if (vfe->vfe_flags &  VFS_TBLTHREADSAFE)
		newvfstbl->vfc_threadsafe= 1;
	if (vfe->vfe_flags &  VFS_TBLFSNODELOCK)
		newvfstbl->vfc_threadsafe= 1;
	if ((vfe->vfe_flags & VFS_TBLLOCALVOL) == VFS_TBLLOCALVOL)
		newvfstbl->vfc_flags |= MNT_LOCAL;
	if (vfe->vfe_flags & VFS_TBLLOCALVOL)
		newvfstbl->vfc_vfsflags |= VFC_VFSLOCALARGS;
	else
		newvfstbl->vfc_vfsflags |= VFC_VFSGENERICARGS;
		

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
	

	for (i= 0; i< desccount; i++ ) {
	opv_desc_vector_p = vfe->vfe_opvdescs[i]->opv_desc_vector_p;
	/*
	 * Fill in the caller's pointer to the start of the i'th vector.
	 * They'll need to supply it when calling vnode_create.
	 */
	opv_desc_vector = descptr + i * vfs_opv_numops;
	*opv_desc_vector_p = opv_desc_vector;

	for (j = 0; vfe->vfe_opvdescs[i]->opv_desc_ops[j].opve_op; j++) {
		opve_descp = &(vfe->vfe_opvdescs[i]->opv_desc_ops[j]);

		/*
		 * Sanity check:  is this operation listed
		 * in the list of operations?  We check this
		 * by seeing if its offest is zero.  Since
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
		    opve_descp->opve_op->vdesc_offset != VOFFSET(vnop_default)) {
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
	if (opv_desc_vector[VOFFSET(vnop_default)] == NULL)
	    panic("vfs_fsadd: operation vector without default routine.");
	for (j = 0; j < vfs_opv_numops; j++)  
		if (opv_desc_vector[j] == NULL)
			opv_desc_vector[j] =
			    opv_desc_vector[VOFFSET(vnop_default)];

	} /* end of each vnodeopv_desc parsing */


	
	*handle = vfstable_add(newvfstbl);

	if (newvfstbl->vfc_typenum <= maxvfsconf )
			maxvfsconf = newvfstbl->vfc_typenum + 1;
	numused_vfsslots++;

	if (newvfstbl->vfc_vfsops->vfs_init)
		(*newvfstbl->vfc_vfsops->vfs_init)((struct vfsconf *)handle);

	FREE(newvfstbl, M_TEMP);

	return(0);
}

/*
 * Removes the filesystem from kernel.
 * The argument passed in is the handle that was given when 
 * file system was added
 */
errno_t  
vfs_fsremove(vfstable_t  handle)
{
	struct vfstable * vfstbl =  (struct vfstable *)handle;
	void *old_desc = NULL;
	errno_t err;
	
	/* Preflight check for any mounts */
	mount_list_lock();
	if ( vfstbl->vfc_refcount != 0 ) {
		mount_list_unlock();
		return EBUSY;
	}
	mount_list_unlock();
	
	/*
	 * save the old descriptor; the free cannot occur unconditionally,
	 * since vfstable_del() may fail.
	 */
	if (vfstbl->vfc_descptr && vfstbl->vfc_descsize) {
		old_desc = vfstbl->vfc_descptr;
	}
	err = vfstable_del(vfstbl);

	/* free the descriptor if the delete was successful */
	if (err == 0 && old_desc) {
		FREE(old_desc, M_TEMP);
	}

	return(err);
}

/*
 * This returns a reference to mount_t
 * which should be dropped using vfs_mountrele().
 * Not doing so will leak a mountpoint
 * and associated data structures.
 */
errno_t 
vfs_mountref(__unused mount_t mp ) /* gives a reference */
{
	return(0);
}

/* This drops the reference on mount_t that was acquired */
errno_t 
vfs_mountrele(__unused mount_t mp ) /* drops reference */
{
	return(0);
}

int
vfs_context_pid(vfs_context_t context)
{
	return (context->vc_proc->p_pid);
}

int
vfs_context_suser(vfs_context_t context)
{
	return (suser(context->vc_ucred, 0));
}
int
vfs_context_issignal(vfs_context_t context, sigset_t mask)
{
	if (context->vc_proc)
		return(proc_pendingsignals(context->vc_proc, mask));
	return(0);
}

int
vfs_context_is64bit(vfs_context_t context)
{
	if (context->vc_proc)
		return(proc_is64bit(context->vc_proc));
	return(0);
}

proc_t
vfs_context_proc(vfs_context_t context)
{
	return (context->vc_proc);
}

vfs_context_t
vfs_context_create(vfs_context_t context)
{
	struct vfs_context *  newcontext;

	newcontext = (struct vfs_context *)kalloc(sizeof(struct vfs_context));

	if (newcontext) {
		if (context) {
			newcontext->vc_proc = context->vc_proc;
			newcontext->vc_ucred = context->vc_ucred;
		} else {
			newcontext->vc_proc = proc_self();
			newcontext->vc_ucred = kauth_cred_get();
		}
	   return(newcontext);
	}
	return((vfs_context_t)0);	
}

int
vfs_context_rele(vfs_context_t context)
{
	if (context)
		kfree(context, sizeof(struct vfs_context));
	return(0);
}


ucred_t
vfs_context_ucred(vfs_context_t context)
{
	return (context->vc_ucred);
}

/*
 * Return true if the context is owned by the superuser.
 */
int
vfs_context_issuser(vfs_context_t context)
{
	return(context->vc_ucred->cr_uid == 0);
}


/* XXXXXXXXXXXXXX VNODE KAPIS XXXXXXXXXXXXXXXXXXXXXXXXX */

 
/*
 * Convert between vnode types and inode formats (since POSIX.1
 * defines mode word of stat structure in terms of inode formats).
 */
enum vtype 
vnode_iftovt(int mode)
{
	return(iftovt_tab[((mode) & S_IFMT) >> 12]);
}

int 
vnode_vttoif(enum vtype indx)
{
	return(vttoif_tab[(int)(indx)]);
}

int 
vnode_makeimode(int indx, int mode)
{
	return (int)(VTTOIF(indx) | (mode));
}


/*
 * vnode manipulation functions.
 */

/* returns system root vnode reference; It should be dropped  using vrele() */
vnode_t  
vfs_rootvnode(void)
{
	int error;

	error = vnode_get(rootvnode);
	if (error)
		return ((vnode_t)0);
	else
		return rootvnode;
}	


uint32_t 
vnode_vid(vnode_t vp)
{
	return ((uint32_t)(vp->v_id));
}	

/* returns a mount reference; drop it with vfs_mountrelease() */
mount_t 
vnode_mount(vnode_t vp)
{
	return (vp->v_mount);
}

/* returns a mount reference iff vnode_t is a dir and is a mount point */
mount_t 
vnode_mountedhere(vnode_t vp)
{
	mount_t mp;

	if ((vp->v_type == VDIR) && ((mp = vp->v_mountedhere) != NULL) &&
	    (mp->mnt_vnodecovered == vp))
		return (mp);
	else
		return (mount_t)NULL;
}

/* returns vnode type of vnode_t */
enum vtype 
vnode_vtype(vnode_t vp)
{
	return (vp->v_type);
}

/* returns FS specific node saved in vnode */
void * 
vnode_fsnode(vnode_t vp)
{
	return (vp->v_data);
}

void 
vnode_clearfsnode(vnode_t vp)
{
	vp->v_data = 0;
}

dev_t 
vnode_specrdev(vnode_t vp)
{
	return(vp->v_rdev);
}


/* Accessor functions */
/* is vnode_t a root vnode */
int 
vnode_isvroot(vnode_t vp)
{
	return ((vp->v_flag & VROOT)? 1 : 0);
}

/* is vnode_t a system vnode */
int 
vnode_issystem(vnode_t vp)
{
	return ((vp->v_flag & VSYSTEM)? 1 : 0);
}

/* if vnode_t mount operation in progress */
int 
vnode_ismount(vnode_t vp)
{
	return ((vp->v_flag & VMOUNT)? 1 : 0);
}

/* is this vnode under recyle now */
int 
vnode_isrecycled(vnode_t vp)
{
	int ret;

	vnode_lock(vp);
	ret =  (vp->v_lflag & (VL_TERMINATE|VL_DEAD))? 1 : 0;
	vnode_unlock(vp);
	return(ret);
}

/* is vnode_t marked to not keep data cached once it's been consumed */
int 
vnode_isnocache(vnode_t vp)
{
	return ((vp->v_flag & VNOCACHE_DATA)? 1 : 0);
}

/*
 * has sequential readahead been disabled on this vnode
 */
int
vnode_isnoreadahead(vnode_t vp)
{
	return ((vp->v_flag & VRAOFF)? 1 : 0);
}

/* is vnode_t a standard one? */
int 
vnode_isstandard(vnode_t vp)
{
	return ((vp->v_flag & VSTANDARD)? 1 : 0);
}

/* don't vflush() if SKIPSYSTEM */
int 
vnode_isnoflush(vnode_t vp)
{
	return ((vp->v_flag & VNOFLUSH)? 1 : 0);
}

/* is vnode_t a regular file */
int 
vnode_isreg(vnode_t vp)
{
	return ((vp->v_type == VREG)? 1 : 0);
}

/* is vnode_t a directory? */
int 
vnode_isdir(vnode_t vp)
{
	return ((vp->v_type == VDIR)? 1 : 0);
}

/* is vnode_t a symbolic link ? */
int 
vnode_islnk(vnode_t vp)
{
	return ((vp->v_type == VLNK)? 1 : 0);
}

/* is vnode_t a fifo ? */
int 
vnode_isfifo(vnode_t vp)
{
	return ((vp->v_type == VFIFO)? 1 : 0);
}

/* is vnode_t a block device? */
int 
vnode_isblk(vnode_t vp)
{
	return ((vp->v_type == VBLK)? 1 : 0);
}

/* is vnode_t a char device? */
int 
vnode_ischr(vnode_t vp)
{
	return ((vp->v_type == VCHR)? 1 : 0);
}

/* is vnode_t a socket? */
int 
vnode_issock(vnode_t vp)
{
	return ((vp->v_type == VSOCK)? 1 : 0);
}


/* TBD:  set vnode_t to not cache data after it is consumed once; used for quota */
void 
vnode_setnocache(vnode_t vp)
{
	vnode_lock(vp);
	vp->v_flag |= VNOCACHE_DATA;
	vnode_unlock(vp);
}

void 
vnode_clearnocache(vnode_t vp)
{
	vnode_lock(vp);
	vp->v_flag &= ~VNOCACHE_DATA;
	vnode_unlock(vp);
}

void 
vnode_setnoreadahead(vnode_t vp)
{
	vnode_lock(vp);
	vp->v_flag |= VRAOFF;
	vnode_unlock(vp);
}

void 
vnode_clearnoreadahead(vnode_t vp)
{
	vnode_lock(vp);
	vp->v_flag &= ~VRAOFF;
	vnode_unlock(vp);
}


/* mark vnode_t to skip vflush() is SKIPSYSTEM */
void 
vnode_setnoflush(vnode_t vp)
{
	vnode_lock(vp);
	vp->v_flag |= VNOFLUSH;
	vnode_unlock(vp);
}

void 
vnode_clearnoflush(vnode_t vp)
{
	vnode_lock(vp);
	vp->v_flag &= ~VNOFLUSH;
	vnode_unlock(vp);
}


/* is vnode_t a blkdevice and has a FS mounted on it */
int 
vnode_ismountedon(vnode_t vp)
{
	return ((vp->v_specflags & SI_MOUNTEDON)? 1 : 0);
}

void 
vnode_setmountedon(vnode_t vp)
{
	vnode_lock(vp);
	vp->v_specflags |= SI_MOUNTEDON;
	vnode_unlock(vp);
}

void 
vnode_clearmountedon(vnode_t vp)
{
	vnode_lock(vp);
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
	return(vp->v_tag);
}

vnode_t 
vnode_parent(vnode_t vp)
{

	return(vp->v_parent);
}

void
vnode_setparent(vnode_t vp, vnode_t dvp)
{
	vp->v_parent = dvp;
}

char *
vnode_name(vnode_t vp)
{
	/* we try to keep v_name a reasonable name for the node */    
	return(vp->v_name);
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
        strncpy(buf, vp->v_mount->mnt_vtable->vfc_name, MFSNAMELEN);
}

/* return the FS type number */
int 
vnode_vfstypenum(vnode_t vp)
{
	return(vp->v_mount->mnt_vtable->vfc_typenum);
}

int
vnode_vfs64bitready(vnode_t vp) 
{

	if ((vp->v_mount->mnt_vtable->vfc_64bitready))
		return(1);
	else
		return(0);
}



/* return the visible flags on associated mount point of vnode_t */
uint32_t 
vnode_vfsvisflags(vnode_t vp)
{
	return(vp->v_mount->mnt_flag & MNT_VISFLAGMASK);
}

/* return the command modifier flags on associated mount point of vnode_t */
uint32_t 
vnode_vfscmdflags(vnode_t vp)
{
	return(vp->v_mount->mnt_flag & MNT_CMDFLAGS);
}

/* return the max symlink of short links  of vnode_t */
uint32_t 
vnode_vfsmaxsymlen(vnode_t vp)
{
	return(vp->v_mount->mnt_maxsymlinklen);
}

/* return a pointer to the RO vfs_statfs associated with vnode_t's mount point */
struct vfsstatfs *
vnode_vfsstatfs(vnode_t vp)
{
        return(&vp->v_mount->mnt_vfsstat);
}

/* return a handle to the FSs specific private handle associated with vnode_t's mount point */
void *
vnode_vfsfsprivate(vnode_t vp)
{
	return(vp->v_mount->mnt_data);
}

/* is vnode_t in a rdonly mounted  FS */
int 
vnode_vfsisrdonly(vnode_t vp)
{
	return ((vp->v_mount->mnt_flag & MNT_RDONLY)? 1 : 0);
}


/* returns vnode ref to current working directory */
vnode_t 
current_workingdir(void)
{
	struct proc *p = current_proc();
	struct vnode * vp ;

	if ( (vp = p->p_fd->fd_cdir) ) {
	        if ( (vnode_getwithref(vp)) )
		        return (NULL);
	}
	return vp;
}

/* returns vnode ref to current root(chroot) directory */
vnode_t 
current_rootdir(void)
{
	struct proc *p = current_proc();
	struct vnode * vp ;

	if ( (vp = p->p_fd->fd_rdir) ) {
	        if ( (vnode_getwithref(vp)) )
		        return (NULL);
	}
	return vp;
}

static int
vnode_get_filesec(vnode_t vp, kauth_filesec_t *fsecp, vfs_context_t ctx)
{
	kauth_filesec_t fsec;
	uio_t	fsec_uio;
	size_t	fsec_size;
	size_t	xsize, rsize;
	int	error;

	fsec = NULL;
	fsec_uio = NULL;
	error = 0;
	
	/* find out how big the EA is */
	if (vn_getxattr(vp, KAUTH_FILESEC_XATTR, NULL, &xsize, XATTR_NOSECURITY, ctx) != 0) {
		/* no EA, no filesec */
		if ((error == ENOATTR) || (error == ENOENT) || (error == EJUSTRETURN))
			error = 0;
		/* either way, we are done */
		goto out;
	}
				
	/* how many entries would fit? */
	fsec_size = KAUTH_FILESEC_COUNT(xsize);

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
		if ((error == ENOATTR) || (error == ENOENT) || (error == EJUSTRETURN))
			error = 0;
		/* either way, we are done */
		goto out;
	}

	/*
	 * Validate security structure.  If it's corrupt, we will
	 * just ignore it.
	 */
	if (rsize < KAUTH_FILESEC_SIZE(0)) {
		KAUTH_DEBUG("ACL - DATA TOO SMALL (%d)", rsize);
		goto out;
	}
	if (fsec->fsec_magic != KAUTH_FILESEC_MAGIC) {
		KAUTH_DEBUG("ACL - BAD MAGIC %x", fsec->fsec_magic);
		goto out;
	}
	if ((fsec->fsec_acl.acl_entrycount != KAUTH_FILESEC_NOACL) &&
	    (fsec->fsec_acl.acl_entrycount > KAUTH_ACL_MAX_ENTRIES)) {
		KAUTH_DEBUG("ACL - BAD ENTRYCOUNT %x", fsec->fsec_entrycount);
		goto out;
	}
	if ((fsec->fsec_acl.acl_entrycount != KAUTH_FILESEC_NOACL) &&
	    (KAUTH_FILESEC_SIZE(fsec->fsec_acl.acl_entrycount) > rsize)) {
		KAUTH_DEBUG("ACL - BUFFER OVERFLOW (%d entries too big for %d)", fsec->fsec_acl.acl_entrycount, rsize);
		goto out;
	}

	*fsecp = fsec;
	fsec = NULL;
	error = 0;
out:
	if (fsec != NULL)
		kauth_filesec_free(fsec);
	if (fsec_uio != NULL)
		uio_free(fsec_uio);
	if (error)
		*fsecp = NULL;
	return(error);
}

static int
vnode_set_filesec(vnode_t vp, kauth_filesec_t fsec, kauth_acl_t acl, vfs_context_t ctx)
{
	uio_t	fsec_uio;
	int	error;

	fsec_uio = NULL;
	
	if ((fsec_uio = uio_create(2, 0, UIO_SYSSPACE, UIO_WRITE)) == NULL) {
		KAUTH_DEBUG("    ERROR - could not allocate iov to write ACL");	
		error = ENOMEM;
		goto out;
	}
	uio_addiov(fsec_uio, CAST_USER_ADDR_T(fsec), sizeof(struct kauth_filesec) - sizeof(struct kauth_acl));
	uio_addiov(fsec_uio, CAST_USER_ADDR_T(acl), KAUTH_ACL_COPYSIZE(acl));
	error = vn_setxattr(vp,
	    KAUTH_FILESEC_XATTR,
	    fsec_uio,
	    XATTR_NOSECURITY, 		/* we have auth'ed already */
	    ctx);
	VFS_DEBUG(ctx, vp, "SETATTR - set ACL returning %d", error);

out:
	if (fsec_uio != NULL)
		uio_free(fsec_uio);
	return(error);
}


int
vnode_getattr(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx)
{
	kauth_filesec_t fsec;
	kauth_acl_t facl;
	int	error;
	uid_t	nuid;
	gid_t	ngid;

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

		if ((vp->v_type == VDIR) || (vp->v_type == VLNK) || (vp->v_type == VREG)) {
			/* try to get the filesec */
			if ((error = vnode_get_filesec(vp, &fsec, ctx)) != 0)
				goto out;
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
					bcopy(&fsec->fsec_acl, facl, KAUTH_ACL_COPYSIZE(&fsec->fsec_acl));
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
		if (vap->va_acl != NULL)
			kauth_acl_free(vap->va_acl);
		VATTR_CLEAR_SUPPORTED(vap, va_acl);
	}

#if 0	/* enable when we have a filesystem only supporting UUIDs */
	/*
	 * Handle the case where we need a UID/GID, but only have extended
	 * security information.
	 */
	if (VATTR_NOT_RETURNED(vap, va_uid) &&
	    VATTR_IS_SUPPORTED(vap, va_uuuid) &&
	    !kauth_guid_equal(&vap->va_uuuid, &kauth_null_guid)) {
		if ((error = kauth_cred_guid2uid(&vap->va_uuuid, &nuid)) == 0)
			VATTR_RETURN(vap, va_uid, nuid);
	}
	if (VATTR_NOT_RETURNED(vap, va_gid) &&
	    VATTR_IS_SUPPORTED(vap, va_guuid) &&
	    !kauth_guid_equal(&vap->va_guuid, &kauth_null_guid)) {
		if ((error = kauth_cred_guid2gid(&vap->va_guuid, &ngid)) == 0)
			VATTR_RETURN(vap, va_gid, ngid);
	}
#endif
	
	/*
	 * Handle uid/gid == 99 and MNT_IGNORE_OWNERSHIP here.
	 */
	if (VATTR_IS_ACTIVE(vap, va_uid)) {
		if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
			nuid = vp->v_mount->mnt_fsowner;
			if (nuid == KAUTH_UID_NONE)
				nuid = 99;
		} else if (VATTR_IS_SUPPORTED(vap, va_uid)) {
			nuid = vap->va_uid;
		} else {
			/* this will always be something sensible */
			nuid = vp->v_mount->mnt_fsowner;
		}
		if ((nuid == 99) && !vfs_context_issuser(ctx))
			nuid = kauth_cred_getuid(vfs_context_ucred(ctx));
		VATTR_RETURN(vap, va_uid, nuid);
	}
	if (VATTR_IS_ACTIVE(vap, va_gid)) {
		if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
			ngid = vp->v_mount->mnt_fsgroup;
			if (ngid == KAUTH_GID_NONE)
				ngid = 99;
		} else if (VATTR_IS_SUPPORTED(vap, va_gid)) {
			ngid = vap->va_gid;
		} else {
			/* this will always be something sensible */
			ngid = vp->v_mount->mnt_fsgroup;
		}
		if ((ngid == 99) && !vfs_context_issuser(ctx))
			ngid = kauth_cred_getgid(vfs_context_ucred(ctx));
		VATTR_RETURN(vap, va_gid, ngid);
	}

	/*
	 * Synthesise some values that can be reasonably guessed.
	 */
	if (!VATTR_IS_SUPPORTED(vap, va_iosize))
		VATTR_RETURN(vap, va_iosize, vp->v_mount->mnt_vfsstat.f_iosize);
	
	if (!VATTR_IS_SUPPORTED(vap, va_flags))
		VATTR_RETURN(vap, va_flags, 0);

	if (!VATTR_IS_SUPPORTED(vap, va_filerev))
		VATTR_RETURN(vap, va_filerev, 0);

	if (!VATTR_IS_SUPPORTED(vap, va_gen))
		VATTR_RETURN(vap, va_gen, 0);

	/*
	 * Default sizes.  Ordering here is important, as later defaults build on earlier ones.
	 */
	if (!VATTR_IS_SUPPORTED(vap, va_data_size))
		VATTR_RETURN(vap, va_data_size, 0);

	/* do we want any of the possibly-computed values? */
	if (VATTR_IS_ACTIVE(vap, va_data_alloc) ||
	    VATTR_IS_ACTIVE(vap, va_total_size) ||
	    VATTR_IS_ACTIVE(vap, va_total_alloc)) {
                /* make sure f_bsize is valid */
                if (vp->v_mount->mnt_vfsstat.f_bsize == 0) {
                    if ((error = vfs_update_vfsstat(vp->v_mount, ctx)) != 0)
                        goto out;
                }

		/* default va_data_alloc from va_data_size */
		if (!VATTR_IS_SUPPORTED(vap, va_data_alloc))
			VATTR_RETURN(vap, va_data_alloc, roundup(vap->va_data_size, vp->v_mount->mnt_vfsstat.f_bsize));

		/* default va_total_size from va_data_size */
		if (!VATTR_IS_SUPPORTED(vap, va_total_size))
			VATTR_RETURN(vap, va_total_size, vap->va_data_size);

		/* default va_total_alloc from va_total_size which is guaranteed at this point */
		if (!VATTR_IS_SUPPORTED(vap, va_total_alloc))
			VATTR_RETURN(vap, va_total_alloc, roundup(vap->va_total_size, vp->v_mount->mnt_vfsstat.f_bsize));
	}

	/*
	 * If we don't have a change time, pull it from the modtime.
	 */
	if (!VATTR_IS_SUPPORTED(vap, va_change_time) && VATTR_IS_SUPPORTED(vap, va_modify_time))
		VATTR_RETURN(vap, va_change_time, vap->va_modify_time);

	/*
	 * This is really only supported for the creation VNOPs, but since the field is there
	 * we should populate it correctly.
	 */
	VATTR_RETURN(vap, va_type, vp->v_type);

	/*
	 * The fsid can be obtained from the mountpoint directly.
	 */
	VATTR_RETURN(vap, va_fsid, vp->v_mount->mnt_vfsstat.f_fsid.val[0]);

out:

	return(error);
}

int
vnode_setattr(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx)
{
	int	error, is_ownership_change=0;

	/*
	 * Make sure the filesystem is mounted R/W.
	 * If not, return an error.
	 */
	if (vfs_isrdonly(vp->v_mount))
		return(EROFS);
	
	/*
	 * If ownership is being ignored on this volume, we silently discard
	 * ownership changes.
	 */
	if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
		VATTR_CLEAR_ACTIVE(vap, va_uid);
		VATTR_CLEAR_ACTIVE(vap, va_gid);
	}

	if (VATTR_IS_ACTIVE(vap, va_uid) || VATTR_IS_ACTIVE(vap, va_gid)) {
	    is_ownership_change = 1;
	}
	
	/*
	 * Make sure that extended security is enabled if we're going to try
	 * to set any.
	 */
	if (!vfs_extendedsecurity(vnode_mount(vp)) &&
	    (VATTR_IS_ACTIVE(vap, va_acl) || VATTR_IS_ACTIVE(vap, va_uuuid) || VATTR_IS_ACTIVE(vap, va_guuid))) {
		KAUTH_DEBUG("SETATTR - returning ENOTSUP to request to set extended security");
		return(ENOTSUP);
	}

	error = VNOP_SETATTR(vp, vap, ctx);

	if ((error == 0) && !VATTR_ALL_SUPPORTED(vap))
		error = vnode_setattr_fallback(vp, vap, ctx);

	/*
	 * If we have changed any of the things about the file that are likely
	 * to result in changes to authorisation results, blow the vnode auth
	 * cache
	 */
	if (VATTR_IS_SUPPORTED(vap, va_mode) ||
	    VATTR_IS_SUPPORTED(vap, va_uid) ||
	    VATTR_IS_SUPPORTED(vap, va_gid) ||
	    VATTR_IS_SUPPORTED(vap, va_flags) ||
	    VATTR_IS_SUPPORTED(vap, va_acl) ||
	    VATTR_IS_SUPPORTED(vap, va_uuuid) ||
	    VATTR_IS_SUPPORTED(vap, va_guuid))
		vnode_uncache_credentials(vp);
	// only send a stat_changed event if this is more than
	// just an access time update
	if (error == 0 && (vap->va_active != VNODE_ATTR_BIT(va_access_time))) {
	    if (need_fsevent(FSE_STAT_CHANGED, vp) || (is_ownership_change && need_fsevent(FSE_CHOWN, vp))) {
		if (is_ownership_change == 0)
		        add_fsevent(FSE_STAT_CHANGED, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
		else
		        add_fsevent(FSE_CHOWN, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
	    }
	}
	return(error);
}

/*
 * Following an operation which sets attributes (setattr, create, etc.) we may
 * need to perform fallback operations to get attributes saved.
 */ 
int
vnode_setattr_fallback(vnode_t vp, struct vnode_attr *vap, vfs_context_t ctx)
{
	kauth_filesec_t fsec;
	kauth_acl_t facl;
	struct kauth_filesec lfsec;
	int	error;

	error = 0;

	/*
	 * Extended security fallback via extended attributes.
	 *
	 * Note that we do not free the filesec; the caller is expected to do this.
	 */
	if (VATTR_NOT_RETURNED(vap, va_acl) ||
	    VATTR_NOT_RETURNED(vap, va_uuuid) ||
	    VATTR_NOT_RETURNED(vap, va_guuid)) {
		VFS_DEBUG(ctx, vp, "SETATTR - doing filesec fallback");

		/*
		 * Fail for file types that we don't permit extended security to be set on.
		 */
		if ((vp->v_type != VDIR) && (vp->v_type != VLNK) && (vp->v_type != VREG)) {
			VFS_DEBUG(ctx, vp, "SETATTR - Can't write ACL to file type %d", vnode_vtype(vp));
			error = EINVAL;
			goto out;
		}

		/*
		 * If we don't have all the extended security items, we need to fetch the existing
		 * data to perform a read-modify-write operation.
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
		 * If the filesec data is all invalid, we can just remove the EA completely.
		 */
		if ((facl->acl_entrycount == KAUTH_FILESEC_NOACL) &&
		    kauth_guid_equal(&fsec->fsec_owner, &kauth_null_guid) &&
		    kauth_guid_equal(&fsec->fsec_group, &kauth_null_guid)) {
			error = vn_removexattr(vp, KAUTH_FILESEC_XATTR, XATTR_NOSECURITY, ctx);
			/* no attribute is ok, nothing to delete */
			if (error == ENOATTR)
				error = 0;
			VFS_DEBUG(ctx, vp, "SETATTR - remove filesec returning %d", error);
		} else {
			/* write the EA */
			error = vnode_set_filesec(vp, fsec, facl, ctx);
			VFS_DEBUG(ctx, vp, "SETATTR - update filesec returning %d", error);
		}

		/* if we fetched a filesec, dispose of the buffer */
		if (fsec != &lfsec)
			kauth_filesec_free(fsec);
	}
out:

	return(error);
}

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

errno_t 
VNOP_LOOKUP(vnode_t dvp, vnode_t *vpp, struct componentname *cnp, vfs_context_t context)
{
	int _err;
	struct vnop_lookup_args a;
	vnode_t vp;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_lookup_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(dvp);

	vnode_cache_credentials(dvp, context);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(dvp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*dvp->v_op[vnop_lookup_desc.vdesc_offset])(&a);

	vp = *vpp;

	if (!thread_safe) {
	        if ( (cnp->cn_flags & ISLASTCN) ) {
		        if ( (cnp->cn_flags & LOCKPARENT) ) {
			        if ( !(cnp->cn_flags & FSNODELOCKHELD) ) {
				        /*
					 * leave the fsnode lock held on
					 * the directory, but restore the funnel...
					 * also indicate that we need to drop the
					 * fsnode_lock when we're done with the
					 * system call processing for this path
					 */
				        cnp->cn_flags |= FSNODELOCKHELD;
					
					(void) thread_funnel_set(kernel_flock, funnel_state);
					return (_err);
				}
			}
		}
		unlock_fsnode(dvp, &funnel_state);
	}
	return (_err);
}

#if 0
/*
 *#
 *#% create       dvp     L L L
 *#% create       vpp     - L -
 *#
 */
 
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
VNOP_CREATE(vnode_t dvp, vnode_t * vpp, struct componentname * cnp, struct vnode_attr * vap, vfs_context_t context)
{
	int _err;
	struct vnop_create_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_create_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(dvp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(dvp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*dvp->v_op[vnop_create_desc.vdesc_offset])(&a);
	if (_err == 0 && !NATIVE_XATTR(dvp)) {
		/* 
		 * Remove stale Apple Double file (if any).
		 */
		xattrfile_remove(dvp, cnp->cn_nameptr, context, thread_safe, 0);
	}
	if (!thread_safe) {
		unlock_fsnode(dvp, &funnel_state);
	}
	return (_err);
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
VNOP_WHITEOUT(vnode_t dvp, struct componentname * cnp, int flags, vfs_context_t context)
{
	int _err;
	struct vnop_whiteout_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_whiteout_desc;
	a.a_dvp = dvp;
	a.a_cnp = cnp;
	a.a_flags = flags;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(dvp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(dvp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*dvp->v_op[vnop_whiteout_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(dvp, &funnel_state);
	}
	return (_err);
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
VNOP_MKNOD(vnode_t dvp, vnode_t * vpp, struct componentname * cnp, struct vnode_attr * vap, vfs_context_t context)
{

       int _err;
       struct vnop_mknod_args a;
       int thread_safe;
       int funnel_state = 0;

       a.a_desc = &vnop_mknod_desc;
       a.a_dvp = dvp;
       a.a_vpp = vpp;
       a.a_cnp = cnp;
       a.a_vap = vap;
       a.a_context = context;
       thread_safe = THREAD_SAFE_FS(dvp);

       if (!thread_safe) {
               if ( (_err = lock_fsnode(dvp, &funnel_state)) ) {
                       return (_err);
               }
       }
       _err = (*dvp->v_op[vnop_mknod_desc.vdesc_offset])(&a);
       if (!thread_safe) {
               unlock_fsnode(dvp, &funnel_state);
       }
       return (_err);
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
VNOP_OPEN(vnode_t vp, int mode, vfs_context_t context)
{
	int _err;
	struct vnop_open_args a;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	a.a_desc = &vnop_open_desc;
	a.a_vp = vp;
	a.a_mode = mode;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
		        if ( (_err = lock_fsnode(vp, NULL)) ) {
			        (void) thread_funnel_set(kernel_flock, funnel_state);
			        return (_err);
			}
		}
	}
	_err = (*vp->v_op[vnop_open_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
			unlock_fsnode(vp, NULL);
		}
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_CLOSE(vnode_t vp, int fflag, vfs_context_t context)
{
	int _err;
	struct vnop_close_args a;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	a.a_desc = &vnop_close_desc;
	a.a_vp = vp;
	a.a_fflag = fflag;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
		        if ( (_err = lock_fsnode(vp, NULL)) ) {
			        (void) thread_funnel_set(kernel_flock, funnel_state);
			        return (_err);
			}
		}
	}
	_err = (*vp->v_op[vnop_close_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
			unlock_fsnode(vp, NULL);
		}
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_ACCESS(vnode_t vp, int action, vfs_context_t context)
{
	int _err;
	struct vnop_access_args a;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	a.a_desc = &vnop_access_desc;
	a.a_vp = vp;
	a.a_action = action;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_access_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_GETATTR(vnode_t vp, struct vnode_attr * vap, vfs_context_t context)
{
	int _err;
	struct vnop_getattr_args a;
	int thread_safe;
	int funnel_state;

	a.a_desc = &vnop_getattr_desc;
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_getattr_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_SETATTR(vnode_t vp, struct vnode_attr * vap, vfs_context_t context)
{
	int _err;
	struct vnop_setattr_args a;
	int thread_safe;
	int funnel_state;

	a.a_desc = &vnop_setattr_desc;
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_setattr_desc.vdesc_offset])(&a);

	/* 
	 * Shadow uid/gid/mod change to extended attibute file.
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
			char   *vname;

			dvp = vnode_getparent(vp);
			vname = vnode_getname(vp);

			xattrfile_setattr(dvp, vname, &va, context, thread_safe);
			if (dvp != NULLVP)
			        vnode_put(dvp);
			if (vname != NULL)
			        vnode_putname(vname);
		}
	}
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
}

#if 0
/*
 *#
 *#% getattrlist  vp      = = =
 *#
 */
struct vnop_getattrlist_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	int a_options;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t
VNOP_GETATTRLIST(vnode_t vp, struct attrlist * alist, struct uio * uio, int options, vfs_context_t context)
{
	int _err;
	struct vnop_getattrlist_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_getattrlist_desc;
	a.a_vp = vp;
	a.a_alist = alist;
	a.a_uio = uio;
	a.a_options = options;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_getattrlist_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
}

#if 0
/*
 *#
 *#% setattrlist  vp      L L L
 *#
 */
struct vnop_setattrlist_args {
	struct vnodeop_desc *a_desc;
	vnode_t a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	int a_options;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t 
VNOP_SETATTRLIST(vnode_t vp, struct attrlist * alist, struct uio * uio, int options, vfs_context_t context)
{
	int _err;
	struct vnop_setattrlist_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_setattrlist_desc;
	a.a_vp = vp;
	a.a_alist = alist;
	a.a_uio = uio;
	a.a_options = options;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_setattrlist_desc.vdesc_offset])(&a);

	vnode_uncache_credentials(vp);

	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_READ(vnode_t vp, struct uio * uio, int ioflag, vfs_context_t context)
{
	int _err;
	struct vnop_read_args a;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}

	a.a_desc = &vnop_read_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
		        if ( (_err = lock_fsnode(vp, NULL)) ) {
			        (void) thread_funnel_set(kernel_flock, funnel_state);
				return (_err);
			}
		}
	}
	_err = (*vp->v_op[vnop_read_desc.vdesc_offset])(&a);

	if (!thread_safe) {
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
			unlock_fsnode(vp, NULL);
		}
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_WRITE(vnode_t vp, struct uio * uio, int ioflag, vfs_context_t context)
{
	struct vnop_write_args a;
	int _err;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}

	a.a_desc = &vnop_write_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
		        if ( (_err = lock_fsnode(vp, NULL)) ) {
			        (void) thread_funnel_set(kernel_flock, funnel_state);
				return (_err);
			}
		}
	}
	_err = (*vp->v_op[vnop_write_desc.vdesc_offset])(&a);

	if (!thread_safe) {
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
			unlock_fsnode(vp, NULL);
		}
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_IOCTL(vnode_t vp, u_long command, caddr_t data, int fflag, vfs_context_t context)
{
	int _err;
	struct vnop_ioctl_args a;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}

	if (vfs_context_is64bit(context)) {
		if (!vnode_vfs64bitready(vp)) {
			return(ENOTTY);
		}
	}

	a.a_desc = &vnop_ioctl_desc;
	a.a_vp = vp;
	a.a_command = command;
	a.a_data = data;
	a.a_fflag = fflag;
	a.a_context= context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
		        if ( (_err = lock_fsnode(vp, NULL)) ) {
			        (void) thread_funnel_set(kernel_flock, funnel_state);
				return (_err);
			}
		}
	}
	_err = (*vp->v_op[vnop_ioctl_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
			unlock_fsnode(vp, NULL);
		}
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_SELECT(vnode_t vp, int which , int fflags, void * wql, vfs_context_t context)
{
	int _err;
	struct vnop_select_args a;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	a.a_desc = &vnop_select_desc;
	a.a_vp = vp;
	a.a_which = which;
	a.a_fflags = fflags;
	a.a_context = context;
	a.a_wql = wql;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
		        if ( (_err = lock_fsnode(vp, NULL)) ) {
			        (void) thread_funnel_set(kernel_flock, funnel_state);
				return (_err);
			}
		}
	}
	_err = (*vp->v_op[vnop_select_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		if (vp->v_type != VCHR && vp->v_type != VFIFO && vp->v_type != VSOCK) {
			unlock_fsnode(vp, NULL);
		}
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_EXCHANGE(vnode_t fvp, vnode_t tvp, int options, vfs_context_t context)
{
	int _err;
	struct vnop_exchange_args a;
	int thread_safe;
	int funnel_state = 0;
	vnode_t	lock_first = NULL, lock_second = NULL;

	a.a_desc = &vnop_exchange_desc;
	a.a_fvp = fvp;
	a.a_tvp = tvp;
	a.a_options = options;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(fvp);

	if (!thread_safe) {
		/*
		 * Lock in vnode address order to avoid deadlocks
		 */
		if (fvp < tvp) {
		        lock_first  = fvp;
			lock_second = tvp;
		} else {
		        lock_first  = tvp;
			lock_second = fvp;
		}
		if ( (_err = lock_fsnode(lock_first, &funnel_state)) ) {
		        return (_err);
		}
		if ( (_err = lock_fsnode(lock_second, NULL)) ) {
		        unlock_fsnode(lock_first, &funnel_state);
			return (_err);
		}
	}
	_err = (*fvp->v_op[vnop_exchange_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(lock_second, NULL);
		unlock_fsnode(lock_first, &funnel_state);
	}
	return (_err);
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
VNOP_REVOKE(vnode_t vp, int flags, vfs_context_t context)
{
	struct vnop_revoke_args a;
	int _err;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_revoke_desc;
	a.a_vp = vp;
	a.a_flags = flags;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	_err = (*vp->v_op[vnop_revoke_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_MMAP(vnode_t vp, int fflags, vfs_context_t context)
{
	int _err;
	struct vnop_mmap_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_mmap_desc;
	a.a_vp = vp;
	a.a_fflags = fflags;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_mmap_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_MNOMAP(vnode_t vp, vfs_context_t context)
{
	int _err;
	struct vnop_mnomap_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_mnomap_desc;
	a.a_vp = vp;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_mnomap_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_FSYNC(vnode_t vp, int waitfor, vfs_context_t context)
{
	struct vnop_fsync_args a;
	int _err;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_fsync_desc;
	a.a_vp = vp;
	a.a_waitfor = waitfor;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_fsync_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_REMOVE(vnode_t dvp, vnode_t vp, struct componentname * cnp, int flags, vfs_context_t context)
{
	int _err;
	struct vnop_remove_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_remove_desc;
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	a.a_flags = flags;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(dvp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*dvp->v_op[vnop_remove_desc.vdesc_offset])(&a);

	if (_err == 0) {
	        vnode_setneedinactive(vp);

		if ( !(NATIVE_XATTR(dvp)) ) {
		        /* 
			 * Remove any associated extended attibute file (._ AppleDouble file).
			 */
		        xattrfile_remove(dvp, cnp->cn_nameptr, context, thread_safe, 1);
		}
	}
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_LINK(vnode_t vp, vnode_t tdvp, struct componentname * cnp, vfs_context_t context)
{
	int _err;
	struct vnop_link_args a;
	int thread_safe;
	int funnel_state = 0;

	/*
	 * For file systems with non-native extended attributes,
	 * disallow linking to an existing "._" Apple Double file.
	 */
	if ( !NATIVE_XATTR(tdvp) && (vp->v_type == VREG)) {
		char   *vname;

		vname = vnode_getname(vp);
		if (vname != NULL) {
			_err = 0;
			if (vname[0] == '.' && vname[1] == '_' && vname[2] != '\0') {
				_err = EPERM;
			}
			vnode_putname(vname);
			if (_err)
				return (_err);
		}
	}
	a.a_desc = &vnop_link_desc;
	a.a_vp = vp;
	a.a_tdvp = tdvp;
	a.a_cnp = cnp;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*tdvp->v_op[vnop_link_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
            vfs_context_t context)
{
	int _err;
	struct vnop_rename_args a;
	int funnel_state = 0;
	char smallname1[48];
	char smallname2[48];
	char *xfromname = NULL;
	char *xtoname = NULL;
	vnode_t	lock_first = NULL, lock_second = NULL;
	vnode_t fdvp_unsafe = NULLVP;
	vnode_t tdvp_unsafe = NULLVP;

	a.a_desc = &vnop_rename_desc;
	a.a_fdvp = fdvp;
	a.a_fvp = fvp;
	a.a_fcnp = fcnp;
	a.a_tdvp = tdvp;
	a.a_tvp = tvp;
	a.a_tcnp = tcnp;
	a.a_context = context;

	if (!THREAD_SAFE_FS(fdvp))
	        fdvp_unsafe = fdvp;
	if (!THREAD_SAFE_FS(tdvp))
	        tdvp_unsafe = tdvp;

	if (fdvp_unsafe != NULLVP) {
		/*
		 * Lock parents in vnode address order to avoid deadlocks
		 * note that it's possible for the fdvp to be unsafe,
		 * but the tdvp to be safe because tvp could be a directory
		 * in the root of a filesystem... in that case, tdvp is the
		 * in the filesystem that this root is mounted on
		 */
	        if (tdvp_unsafe == NULL || fdvp_unsafe == tdvp_unsafe) {
		        lock_first  = fdvp_unsafe;
			lock_second = NULL;
		} else if (fdvp_unsafe < tdvp_unsafe) {
		        lock_first  = fdvp_unsafe;
			lock_second = tdvp_unsafe;
		} else {
		        lock_first  = tdvp_unsafe;
			lock_second = fdvp_unsafe;
		}
		if ( (_err = lock_fsnode(lock_first, &funnel_state)) )
		        return (_err);

		if (lock_second != NULL && (_err = lock_fsnode(lock_second, NULL))) {
		        unlock_fsnode(lock_first, &funnel_state);
			return (_err);
		}

		/*
		 * Lock both children in vnode address order to avoid deadlocks
		 */
	        if (tvp == NULL || tvp == fvp) {
		        lock_first  = fvp;
			lock_second = NULL;
		} else if (fvp < tvp) {
		        lock_first  = fvp;
			lock_second = tvp;
		} else {
		        lock_first  = tvp;
			lock_second = fvp;
		}
		if ( (_err = lock_fsnode(lock_first, NULL)) )
		        goto out1;

		if (lock_second != NULL && (_err = lock_fsnode(lock_second, NULL))) {
		        unlock_fsnode(lock_first, NULL);
			goto out1;
		}
	}
	/* 
	 * Save source and destination names (._ AppleDouble files).
	 * Skip if source already has a "._" prefix.
	 */
	if (!NATIVE_XATTR(fdvp) &&
	    !(fcnp->cn_nameptr[0] == '.' && fcnp->cn_nameptr[1] == '_')) {
		size_t len;

		/* Get source attribute file name. */
		len = fcnp->cn_namelen + 3;
		if (len > sizeof(smallname1)) {
			MALLOC(xfromname, char *, len, M_TEMP, M_WAITOK);
		} else {
			xfromname = &smallname1[0];
		}
		strcpy(xfromname, "._");
		strncat(xfromname, fcnp->cn_nameptr, fcnp->cn_namelen);
		xfromname[len-1] = '\0';

		/* Get destination attribute file name. */
		len = tcnp->cn_namelen + 3;
		if (len > sizeof(smallname2)) {
			MALLOC(xtoname, char *, len, M_TEMP, M_WAITOK);
		} else {
			xtoname = &smallname2[0];
		}
		strcpy(xtoname, "._");
		strncat(xtoname, tcnp->cn_nameptr, tcnp->cn_namelen);
		xtoname[len-1] = '\0';
	}

	_err = (*fdvp->v_op[vnop_rename_desc.vdesc_offset])(&a);

	if (fdvp_unsafe != NULLVP) {
	        if (lock_second != NULL)
		        unlock_fsnode(lock_second, NULL);
		unlock_fsnode(lock_first, NULL);
	}
	if (_err == 0) {
		if (tvp && tvp != fvp)
		        vnode_setneedinactive(tvp);
	}

	/* 
	 * Rename any associated extended attibute file (._ AppleDouble file).
	 */
	if (_err == 0 && !NATIVE_XATTR(fdvp) && xfromname != NULL) {
		struct nameidata fromnd, tond;
		int killdest = 0;
		int error;

		/*
		 * Get source attribute file vnode.
		 * Note that fdvp already has an iocount reference and
		 * using DELETE will take an additional reference.
		 */
		NDINIT(&fromnd, DELETE, NOFOLLOW | USEDVP, UIO_SYSSPACE,
		       CAST_USER_ADDR_T(xfromname), context);
		fromnd.ni_dvp = fdvp;
		error = namei(&fromnd);

		if (error) {
			/* When source doesn't exist there still may be a destination. */
			if (error == ENOENT) {
				killdest = 1;
			} else {
				goto out;
			}
		} else if (fromnd.ni_vp->v_type != VREG) {
			vnode_put(fromnd.ni_vp);
			nameidone(&fromnd);
			killdest = 1;
		}
		if (killdest) {
			struct vnop_remove_args args;

			/*
			 * Get destination attribute file vnode.
			 * Note that tdvp already has an iocount reference.
			 */
			NDINIT(&tond, DELETE, NOFOLLOW | USEDVP, UIO_SYSSPACE,
			       CAST_USER_ADDR_T(xtoname), context);
			tond.ni_dvp = tdvp;
			error = namei(&tond);
			if (error) {
				goto out;
			}
			if (tond.ni_vp->v_type != VREG) {
				vnode_put(tond.ni_vp);
				nameidone(&tond);
				goto out;
			}
			args.a_desc    = &vnop_remove_desc;
			args.a_dvp     = tdvp;
			args.a_vp      = tond.ni_vp;
			args.a_cnp     = &tond.ni_cnd;
			args.a_context = context;

			if (fdvp_unsafe != NULLVP)
			        error = lock_fsnode(tond.ni_vp, NULL);
			if (error == 0) {
			        error = (*tdvp->v_op[vnop_remove_desc.vdesc_offset])(&args);

				if (fdvp_unsafe != NULLVP)
				        unlock_fsnode(tond.ni_vp, NULL);

				if (error == 0)
				        vnode_setneedinactive(tond.ni_vp);
			}
			vnode_put(tond.ni_vp);
			nameidone(&tond);
			goto out;
		}

		/*
		 * Get destination attribute file vnode.
		 */
		NDINIT(&tond, RENAME,
		       NOCACHE | NOFOLLOW | USEDVP, UIO_SYSSPACE,
		       CAST_USER_ADDR_T(xtoname), context);
		tond.ni_dvp = tdvp;
		error = namei(&tond);

		if (error) {
			vnode_put(fromnd.ni_vp);
			nameidone(&fromnd);
			goto out;
		}
		a.a_desc = &vnop_rename_desc;
		a.a_fdvp = fdvp;
		a.a_fvp = fromnd.ni_vp;
		a.a_fcnp = &fromnd.ni_cnd;
		a.a_tdvp = tdvp;
		a.a_tvp = tond.ni_vp;
		a.a_tcnp = &tond.ni_cnd;
		a.a_context = context;

		if (fdvp_unsafe != NULLVP) {
		        /*
			 * Lock in vnode address order to avoid deadlocks
			 */
		        if (tond.ni_vp == NULL || tond.ni_vp == fromnd.ni_vp) {
			        lock_first  = fromnd.ni_vp;
				lock_second = NULL;
			} else if (fromnd.ni_vp < tond.ni_vp) {
			        lock_first  = fromnd.ni_vp;
				lock_second = tond.ni_vp;
			} else {
			        lock_first  = tond.ni_vp;
				lock_second = fromnd.ni_vp;
			}
			if ( (error = lock_fsnode(lock_first, NULL)) == 0) {
			        if (lock_second != NULL && (error = lock_fsnode(lock_second, NULL)) )
				        unlock_fsnode(lock_first, NULL);
			}
		}
		if (error == 0) {
		        error = (*fdvp->v_op[vnop_rename_desc.vdesc_offset])(&a);

			if (fdvp_unsafe != NULLVP) {
			        if (lock_second != NULL)
				        unlock_fsnode(lock_second, NULL);
				unlock_fsnode(lock_first, NULL);
			}
			if (error == 0) {
			        vnode_setneedinactive(fromnd.ni_vp);
				
				if (tond.ni_vp && tond.ni_vp != fromnd.ni_vp)
				        vnode_setneedinactive(tond.ni_vp);
			}
		}
		vnode_put(fromnd.ni_vp);
		if (tond.ni_vp) {
			vnode_put(tond.ni_vp);
		}
		nameidone(&tond);
		nameidone(&fromnd);
	}
out:
	if (xfromname && xfromname != &smallname1[0]) {
		FREE(xfromname, M_TEMP);
	}
	if (xtoname && xtoname != &smallname2[0]) {
		FREE(xtoname, M_TEMP);
	}
out1:
	if (fdvp_unsafe != NULLVP) {
	        if (tdvp_unsafe != NULLVP)
		        unlock_fsnode(tdvp_unsafe, NULL);
		unlock_fsnode(fdvp_unsafe, &funnel_state);
	}
	return (_err);
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
           struct vnode_attr *vap, vfs_context_t context)
{
       int _err;
       struct vnop_mkdir_args a;
       int thread_safe;
       int funnel_state = 0;

       a.a_desc = &vnop_mkdir_desc;
       a.a_dvp = dvp;
       a.a_vpp = vpp;
       a.a_cnp = cnp;
       a.a_vap = vap;
       a.a_context = context;
       thread_safe = THREAD_SAFE_FS(dvp);

       if (!thread_safe) {
               if ( (_err = lock_fsnode(dvp, &funnel_state)) ) {
                       return (_err);
               }
       }
       _err = (*dvp->v_op[vnop_mkdir_desc.vdesc_offset])(&a);
	if (_err == 0 && !NATIVE_XATTR(dvp)) {
		/* 
		 * Remove stale Apple Double file (if any).
		 */
		xattrfile_remove(dvp, cnp->cn_nameptr, context, thread_safe, 0);
	}
       if (!thread_safe) {
               unlock_fsnode(dvp, &funnel_state);
       }
       return (_err);
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
VNOP_RMDIR(struct vnode *dvp, struct vnode *vp, struct componentname *cnp, vfs_context_t context)
{
	int _err;
	struct vnop_rmdir_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_rmdir_desc;
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(dvp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_rmdir_desc.vdesc_offset])(&a);

	if (_err == 0) {
	        vnode_setneedinactive(vp);

		if ( !(NATIVE_XATTR(dvp)) ) {
		        /* 
			 * Remove any associated extended attibute file (._ AppleDouble file).
			 */
		        xattrfile_remove(dvp, cnp->cn_nameptr, context, thread_safe, 1);
		}
	}
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
}

/*
 * Remove a ._ AppleDouble file
 */
#define AD_STALE_SECS  (180)
static void
xattrfile_remove(vnode_t dvp, const char * basename, vfs_context_t context, int thread_safe, int force) {
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
	NDINIT(&nd, DELETE, LOCKLEAF | NOFOLLOW | USEDVP, UIO_SYSSPACE,
	       CAST_USER_ADDR_T(filename), context);
	nd.ni_dvp = dvp;
	if (namei(&nd) != 0)
		goto out2;

	xvp = nd.ni_vp;
	nameidone(&nd);
	if (xvp->v_type != VREG)
		goto out1;

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
		if (VNOP_GETATTR(xvp, &va, context) == 0  &&
		    VATTR_IS_SUPPORTED(&va, va_data_size)  &&
		    VATTR_IS_SUPPORTED(&va, va_modify_time)  &&
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
		struct vnop_remove_args a;
		int  error;
	
		a.a_desc    = &vnop_remove_desc;
		a.a_dvp     = nd.ni_dvp;
		a.a_vp      = xvp;
		a.a_cnp     = &nd.ni_cnd;
		a.a_context = context;

		if (!thread_safe) {
			if ( (lock_fsnode(xvp, NULL)) )
				goto out1;
		}
		error = (*dvp->v_op[vnop_remove_desc.vdesc_offset])(&a);

		if (!thread_safe)
			unlock_fsnode(xvp, NULL);

		if (error == 0)
			vnode_setneedinactive(xvp);
	}
out1:		
	/* Note: nd.ni_dvp's iocount is dropped by caller of VNOP_XXXX */
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
                  vfs_context_t context, int thread_safe) {
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
	NDINIT(&nd, LOOKUP, NOFOLLOW | USEDVP, UIO_SYSSPACE,
	       CAST_USER_ADDR_T(filename), context);
	nd.ni_dvp = dvp;
	if (namei(&nd) != 0)
		goto out2;

	xvp = nd.ni_vp;
	nameidone(&nd);

	if (xvp->v_type == VREG) {
		struct vnop_setattr_args a;

		a.a_desc = &vnop_setattr_desc;
		a.a_vp = xvp;
		a.a_vap = vap;
		a.a_context = context;

		if (!thread_safe) {
			if ( (lock_fsnode(xvp, NULL)) )
				goto out1;
		}
		(void) (*xvp->v_op[vnop_setattr_desc.vdesc_offset])(&a);
		if (!thread_safe) {
			unlock_fsnode(xvp, NULL);
		}
	}
out1:		
	vnode_put(xvp);
out2:
	if (filename && filename != &smallname[0]) {
		FREE(filename, M_TEMP);
	}
}

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
             struct vnode_attr *vap, char *target, vfs_context_t context)
{
       int _err;
       struct vnop_symlink_args a;
       int thread_safe;
       int funnel_state = 0;

       a.a_desc = &vnop_symlink_desc;
       a.a_dvp = dvp;
       a.a_vpp = vpp;
       a.a_cnp = cnp;
       a.a_vap = vap;
       a.a_target = target;
       a.a_context = context;
       thread_safe = THREAD_SAFE_FS(dvp);

       if (!thread_safe) {
               if ( (_err = lock_fsnode(dvp, &funnel_state)) ) {
                       return (_err);
               }
       }
       _err = (*dvp->v_op[vnop_symlink_desc.vdesc_offset])(&a);   
	if (_err == 0 && !NATIVE_XATTR(dvp)) {
		/* 
		 * Remove stale Apple Double file (if any).
		 */
		xattrfile_remove(dvp, cnp->cn_nameptr, context, thread_safe, 0);
	}
       if (!thread_safe) {
               unlock_fsnode(dvp, &funnel_state);
       }
       return (_err);
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
             int *numdirent, vfs_context_t context)
{
	int _err;
	struct vnop_readdir_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_readdir_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_flags = flags;
	a.a_eofflag = eofflag;
	a.a_numdirent = numdirent;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_readdir_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
	u_long a_maxcount;
	u_long a_options;
	u_long *a_newstate;
	int *a_eofflag;
	u_long *a_actualcount;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t 
VNOP_READDIRATTR(struct vnode *vp, struct attrlist *alist, struct uio *uio, u_long maxcount,
                 u_long options, u_long *newstate, int *eofflag, u_long *actualcount, vfs_context_t context)
{
	int _err;
	struct vnop_readdirattr_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_readdirattr_desc;
	a.a_vp = vp;
	a.a_alist = alist;
	a.a_uio = uio;
	a.a_maxcount = maxcount;
	a.a_options = options;
	a.a_newstate = newstate;
	a.a_eofflag = eofflag;
	a.a_actualcount = actualcount;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_readdirattr_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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

errno_t 
VNOP_READLINK(struct vnode *vp, struct uio *uio, vfs_context_t context)
{
	int _err;
	struct vnop_readlink_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_readlink_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_readlink_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_INACTIVE(struct vnode *vp, vfs_context_t context)
{
	int _err;
	struct vnop_inactive_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_inactive_desc;
	a.a_vp = vp;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_inactive_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
VNOP_RECLAIM(struct vnode *vp, vfs_context_t context)
{
	int _err;
	struct vnop_reclaim_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_reclaim_desc;
	a.a_vp = vp;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	_err = (*vp->v_op[vnop_reclaim_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
}


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
	register_t *a_retval;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t 
VNOP_PATHCONF(struct vnode *vp, int name, register_t *retval, vfs_context_t context)
{
	int _err;
	struct vnop_pathconf_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_pathconf_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_retval = retval;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_pathconf_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
}

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
VNOP_ADVLOCK(struct vnode *vp, caddr_t id, int op, struct flock *fl, int flags, vfs_context_t context)
{
	int _err;
	struct vnop_advlock_args a;
	int thread_safe;
	int funnel_state = 0;
	struct uthread * uth;

	a.a_desc = &vnop_advlock_desc;
	a.a_vp = vp;
	a.a_id = id;
	a.a_op = op;
	a.a_fl = fl;
	a.a_flags = flags;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	uth = get_bsdthread_info(current_thread());
	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	/* Disallow advisory locking on non-seekable vnodes */
	if (vnode_isfifo(vp)) {
		_err = err_advlock(&a);
	} else {
		if ((vp->v_flag & VLOCKLOCAL)) {
			/* Advisory locking done at this layer */
			_err = lf_advlock(&a);
		} else {
			/* Advisory locking done by underlying filesystem */
			_err = (*vp->v_op[vnop_advlock_desc.vdesc_offset])(&a);
		}
	}
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_ALLOCATE(struct vnode *vp, off_t length, u_int32_t flags, off_t *bytesallocated, off_t offset, vfs_context_t context)
{
	int _err;
	struct vnop_allocate_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_allocate_desc;
	a.a_vp = vp;
	a.a_length = length;
	a.a_flags = flags;
	a.a_bytesallocated = bytesallocated;
	a.a_offset = offset;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_allocate_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
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
	vm_offset_t a_pl_offset;
	off_t a_f_offset;
	size_t a_size;
	int a_flags;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t 
VNOP_PAGEIN(struct vnode *vp, upl_t pl, vm_offset_t pl_offset, off_t f_offset, size_t size, int flags, vfs_context_t context)
{
	int _err;
	struct vnop_pagein_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_pagein_desc;
	a.a_vp = vp;
	a.a_pl = pl;
	a.a_pl_offset = pl_offset;
	a.a_f_offset = f_offset;
	a.a_size = size;
	a.a_flags = flags;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	_err = (*vp->v_op[vnop_pagein_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
	vm_offset_t a_pl_offset;
	off_t a_f_offset;
	size_t a_size;
	int a_flags;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t 
VNOP_PAGEOUT(struct vnode *vp, upl_t pl, vm_offset_t pl_offset, off_t f_offset, size_t size, int flags, vfs_context_t context)
{
	int _err;
	struct vnop_pageout_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_pageout_desc;
	a.a_vp = vp;
	a.a_pl = pl;
	a.a_pl_offset = pl_offset;
	a.a_f_offset = f_offset;
	a.a_size = size;
	a.a_flags = flags;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	_err = (*vp->v_op[vnop_pageout_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
}


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
	u_long a_maxmatches;
	struct timeval *a_timelimit;
	struct attrlist *a_returnattrs;
	u_long *a_nummatches;
	u_long a_scriptcode;
	u_long a_options;
	struct uio *a_uio;
	struct searchstate *a_searchstate;
	vfs_context_t a_context;
};

#endif /* 0*/
errno_t 
VNOP_SEARCHFS(struct vnode *vp, void *searchparams1, void *searchparams2, struct attrlist *searchattrs, u_long maxmatches, struct timeval *timelimit, struct attrlist *returnattrs, u_long *nummatches, u_long scriptcode, u_long options, struct uio *uio, struct searchstate *searchstate, vfs_context_t context)
{
	int _err;
	struct vnop_searchfs_args a;
	int thread_safe;
	int funnel_state = 0;

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
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_searchfs_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (_err);
}

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
              int mode, int flags, vfs_context_t context)
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
	a.a_context = context;
	_err = (*fvp->v_op[vnop_copyfile_desc.vdesc_offset])(&a);
	return (_err);
}


errno_t
VNOP_GETXATTR(vnode_t vp, const char *name, uio_t uio, size_t *size, int options, vfs_context_t context)
{
	struct vnop_getxattr_args a;
	int error;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_getxattr_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_uio = uio;
	a.a_size = size;
	a.a_options = options;
	a.a_context = context;

	thread_safe = THREAD_SAFE_FS(vp);
	if (!thread_safe) {
		if ( (error = lock_fsnode(vp, &funnel_state)) ) {
			return (error);
		}
	}
	error = (*vp->v_op[vnop_getxattr_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (error);
}

errno_t
VNOP_SETXATTR(vnode_t vp, const char *name, uio_t uio, int options, vfs_context_t context)
{
	struct vnop_setxattr_args a;
	int error;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_setxattr_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_uio = uio;
	a.a_options = options;
	a.a_context = context;

	thread_safe = THREAD_SAFE_FS(vp);
	if (!thread_safe) {
		if ( (error = lock_fsnode(vp, &funnel_state)) ) {
			return (error);
		}
	}
	error = (*vp->v_op[vnop_setxattr_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (error);
}

errno_t
VNOP_REMOVEXATTR(vnode_t vp, const char *name, int options, vfs_context_t context)
{
	struct vnop_removexattr_args a;
	int error;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_removexattr_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_options = options;
	a.a_context = context;

	thread_safe = THREAD_SAFE_FS(vp);
	if (!thread_safe) {
		if ( (error = lock_fsnode(vp, &funnel_state)) ) {
			return (error);
		}
	}
	error = (*vp->v_op[vnop_removexattr_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (error);
}

errno_t
VNOP_LISTXATTR(vnode_t vp, uio_t uio, size_t *size, int options, vfs_context_t context)
{
	struct vnop_listxattr_args a;
	int error;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_listxattr_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_size = size;
	a.a_options = options;
	a.a_context = context;

	thread_safe = THREAD_SAFE_FS(vp);
	if (!thread_safe) {
		if ( (error = lock_fsnode(vp, &funnel_state)) ) {
			return (error);
		}
	}
	error = (*vp->v_op[vnop_listxattr_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return (error);
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
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_blktooff_desc;
	a.a_vp = vp;
	a.a_lblkno = lblkno;
	a.a_offset = offset;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	_err = (*vp->v_op[vnop_blktooff_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_offtoblk_desc;
	a.a_vp = vp;
	a.a_offset = offset;
	a.a_lblkno = lblkno;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	_err = (*vp->v_op[vnop_offtoblk_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
VNOP_BLOCKMAP(struct vnode *vp, off_t foffset, size_t size, daddr64_t *bpn, size_t *run, void *poff, int flags, vfs_context_t context)
{
	int _err;
	struct vnop_blockmap_args a;
	int thread_safe;
	int funnel_state = 0;
	struct vfs_context acontext;

	if (context == NULL) {
		acontext.vc_proc = current_proc();
		acontext.vc_ucred = kauth_cred_get();
		context = &acontext;
	}
	a.a_desc = &vnop_blockmap_desc;
	a.a_vp = vp;
	a.a_foffset = foffset;
	a.a_size = size;
	a.a_bpn = bpn;
	a.a_run = run;
	a.a_poff = poff;
	a.a_flags = flags;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	_err = (*vp->v_op[vnop_blockmap_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (_err);
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
	a.a_desc = &vnop_strategy_desc;
	a.a_bp = bp;
	_err = (*buf_vnode(bp)->v_op[vnop_strategy_desc.vdesc_offset])(&a);
	return (_err);
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
	a.a_desc = &vnop_bwrite_desc;
	a.a_bp = bp;
	_err = (*buf_vnode(bp)->v_op[vnop_bwrite_desc.vdesc_offset])(&a);
	return (_err);
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
VNOP_KQFILT_ADD(struct vnode *vp, struct knote *kn, vfs_context_t context)
{
	int _err;
	struct vnop_kqfilt_add_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = VDESC(vnop_kqfilt_add);
	a.a_vp = vp;
	a.a_kn = kn;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_kqfilt_add_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return(_err);
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
VNOP_KQFILT_REMOVE(struct vnode *vp, uintptr_t ident, vfs_context_t context)
{
	int _err;
	struct vnop_kqfilt_remove_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = VDESC(vnop_kqfilt_remove);
	a.a_vp = vp;
	a.a_ident = ident;
	a.a_context = context;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_kqfilt_remove_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return(_err);
}

