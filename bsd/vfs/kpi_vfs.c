/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#include <sys/fsevents.h>
#include <sys/user.h>
#include <sys/lockf.h>
#include <sys/xattr.h>

#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/task.h>

#include <libkern/OSByteOrder.h>

#include <miscfs/specfs/specdev.h>

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <mach/task.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#define ESUCCESS 0
#undef mount_t
#undef vnode_t

#define COMPAT_ONLY


#define THREAD_SAFE_FS(VP)  \
	((VP)->v_unsafefs ? 0 : 1)

#define NATIVE_XATTR(VP)  \
	((VP)->v_mount ? (VP)->v_mount->mnt_kern_flag & MNTK_EXTENDED_ATTRS : 0)

static void xattrfile_remove(vnode_t dvp, const char *basename,
				vfs_context_t ctx, int thread_safe, int force);
static void xattrfile_setattr(vnode_t dvp, const char * basename,
				struct vnode_attr * vap, vfs_context_t ctx,
				int thread_safe);


static void
vnode_setneedinactive(vnode_t vp)
{
        cache_purge(vp);

        vnode_lock_spin(vp);
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
VFS_MOUNT(mount_t mp, vnode_t devvp, user_addr_t data, vfs_context_t ctx)
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
	
	if (vfs_context_is64bit(ctx)) {
		if (vfs_64bitready(mp)) {
			error = (*mp->mnt_op->vfs_mount)(mp, devvp, data, ctx);
		}
		else {
			error = ENOTSUP;
		}
	}
	else {
		error = (*mp->mnt_op->vfs_mount)(mp, devvp, data, ctx);
	}
	
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_START(mount_t mp, int flags, vfs_context_t ctx)
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
	error = (*mp->mnt_op->vfs_start)(mp, flags, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_UNMOUNT(mount_t mp, int flags, vfs_context_t ctx)
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
	error = (*mp->mnt_op->vfs_unmount)(mp, flags, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
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
 *		for a call to hfs_vget on the volume mount poit, not including
 *		additional error codes which may be propagated from underlying
 *		routines called by hfs_vget.
 */
int 
VFS_ROOT(mount_t mp, struct vnode  ** vpp, vfs_context_t ctx)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_root == 0))
		return(ENOTSUP);

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_root)(mp, vpp, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_QUOTACTL(mount_t mp, int cmd, uid_t uid, caddr_t datap, vfs_context_t ctx)
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
	error = (*mp->mnt_op->vfs_quotactl)(mp, cmd, uid, datap, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return (error);
}

int 
VFS_GETATTR(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_getattr == 0))
		return(ENOTSUP);

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	thread_safe = mp->mnt_vtable->vfc_threadsafe;
	
	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_getattr)(mp, vfa, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_SETATTR(mount_t mp, struct vfs_attr *vfa, vfs_context_t ctx)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_setattr == 0))
		return(ENOTSUP);

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	thread_safe = mp->mnt_vtable->vfc_threadsafe;
	
	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_setattr)(mp, vfa, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_SYNC(mount_t mp, int flags, vfs_context_t ctx)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_sync == 0))
		return(ENOTSUP);

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_sync)(mp, flags, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_VGET(mount_t mp, ino64_t ino, struct vnode **vpp, vfs_context_t ctx)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_vget == 0))
		return(ENOTSUP);

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_vget)(mp, ino, vpp, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_FHTOVP(mount_t mp, int fhlen, unsigned char * fhp, vnode_t * vpp, vfs_context_t ctx) 
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((mp == dead_mountp) || (mp->mnt_op->vfs_fhtovp == 0))
		return(ENOTSUP);

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	thread_safe = mp->mnt_vtable->vfc_threadsafe;

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*mp->mnt_op->vfs_fhtovp)(mp, fhlen, fhp, vpp, ctx);
	if (!thread_safe) {
		(void) thread_funnel_set(kernel_flock, funnel_state);
	}
	return(error);
}

int 
VFS_VPTOFH(struct vnode * vp, int *fhlenp, unsigned char * fhp, vfs_context_t ctx)
{
	int error;
	int thread_safe;
	int funnel_state = 0;

	if ((vp->v_mount == dead_mountp) || (vp->v_mount->mnt_op->vfs_vptofh == 0))
		return(ENOTSUP);

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		funnel_state = thread_funnel_set(kernel_flock, TRUE);
	}
	error = (*vp->v_mount->mnt_op->vfs_vptofh)(vp, fhlenp, fhp, ctx);
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

	mount_lock(mp);
	mp->mnt_flag |= lflags;
	mount_unlock(mp);
}

/* clear any of the command modifier flags(MNT_CMDFLAGS) in mount_t */
void 
vfs_clearflags(mount_t mp , uint64_t flags)
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
	if ((mp->mnt_lflag & MNT_LFORCE) || (mp->mnt_kern_flag & MNTK_FRCUNMOUNT))
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
vfs_authcache_ttl(mount_t mp)
{
        if ( (mp->mnt_kern_flag & (MNTK_AUTH_OPAQUE | MNTK_AUTH_CACHE_TTL)) )
	        return (mp->mnt_authcache_ttl);
	else
	        return (CACHED_RIGHT_INFINITE_TTL);
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

void
vfs_markdependency(mount_t mp)
{
	proc_t p = current_proc();
	mount_lock(mp);
	mp->mnt_dependent_process = p;
	mp->mnt_dependent_pid = proc_pid(p);
	mount_unlock(mp);
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
	mount_lock(mp);
	mp->mnt_data = mntdata;
	mount_unlock(mp);
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
		ioattrp->io_flags = 0;
	} else {
	        ioattrp->io_maxreadcnt  = mp->mnt_maxreadcnt;
		ioattrp->io_maxwritecnt = mp->mnt_maxwritecnt;
		ioattrp->io_segreadcnt  = mp->mnt_segreadcnt;
		ioattrp->io_segwritecnt = mp->mnt_segwritecnt;
		ioattrp->io_maxsegreadsize  = mp->mnt_maxsegreadsize;
		ioattrp->io_maxsegwritesize = mp->mnt_maxsegwritesize;
		ioattrp->io_devblocksize = mp->mnt_devblocksize;
		ioattrp->io_flags = mp->mnt_ioflags;
	}
	ioattrp->io_reserved[0] = NULL;
	ioattrp->io_reserved[1] = NULL;
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
	mp->mnt_ioflags = ioattrp->io_flags;
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
	if ((vfe->vfe_flags & VFS_TBLLOCALVOL) && (vfe->vfe_flags & VFS_TBLGENERICMNTARGS) == 0)
		newvfstbl->vfc_vfsflags |= VFC_VFSLOCALARGS;
	else
		newvfstbl->vfc_vfsflags |= VFC_VFSGENERICARGS;

	if (vfe->vfe_flags &  VFS_TBLNATIVEXATTR)
		newvfstbl->vfc_vfsflags |= VFC_VFSNATIVEXATTR;
	if (vfe->vfe_flags &  VFS_TBLUNMOUNT_PREFLIGHT)
		newvfstbl->vfc_vfsflags |= VFC_VFSPREFLIGHT;
	if (vfe->vfe_flags &  VFS_TBLREADDIR_EXTENDED)
		newvfstbl->vfc_vfsflags |= VFC_VFSREADDIR_EXTENDED;
	if (vfe->vfe_flags & VFS_TBLNOMACLABEL)
		newvfstbl->vfc_vfsflags |= VFC_VFSNOMACLABEL;

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
vfs_context_pid(vfs_context_t ctx)
{
	return (proc_pid(vfs_context_proc(ctx)));
}

int
vfs_context_suser(vfs_context_t ctx)
{
	return (suser(ctx->vc_ucred, NULL));
}

/*
 * XXX Signals should be tied to threads, not processes, for most uses of this
 * XXX call.
 */
int
vfs_context_issignal(vfs_context_t ctx, sigset_t mask)
{
	proc_t p = vfs_context_proc(ctx);
	if (p)
		return(proc_pendingsignals(p, mask));
	return(0);
}

int
vfs_context_is64bit(vfs_context_t ctx)
{
	proc_t proc = vfs_context_proc(ctx);

	if (proc)
		return(proc_is64bit(proc));
	return(0);
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
	proc_t	proc = NULL;

	if (ctx != NULL && ctx->vc_thread != NULL)
		proc = (proc_t)get_bsdthreadtask_info(ctx->vc_thread);
	if (proc != NULL && (proc->p_fd == NULL || (proc->p_lflag & P_LVFORK)))
		proc = NULL;

	return(proc == NULL ? current_proc() : proc);
}

/*
 * vfs_context_get_special_port
 *
 * Description: Return the requested special port from the task associated
 * 		with the given context.
 *
 * Parameters:	vfs_context_t			The context to use
 * 		int				Index of special port
 * 		ipc_port_t *			Pointer to returned port
 *
 * Returns:	kern_return_t			see task_get_special_port()
 */
kern_return_t
vfs_context_get_special_port(vfs_context_t ctx, int which, ipc_port_t *portp)
{
	task_t			task = NULL;

	if (ctx != NULL && ctx->vc_thread != NULL)
		task = get_threadtask(ctx->vc_thread);

	return task_get_special_port(task, which, portp);
}

/*
 * vfs_context_set_special_port
 *
 * Description: Set the requested special port in the task associated
 * 		with the given context.
 *
 * Parameters:	vfs_context_t			The context to use
 * 		int				Index of special port
 * 		ipc_port_t			New special port
 *
 * Returns:	kern_return_t			see task_set_special_port()
 */
kern_return_t
vfs_context_set_special_port(vfs_context_t ctx, int which, ipc_port_t port)
{
	task_t			task = NULL;

	if (ctx != NULL && ctx->vc_thread != NULL)
		task = get_threadtask(ctx->vc_thread);

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
	return(ctx->vc_thread);
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

	if(ctx != NULL && ctx->vc_thread != NULL) {
		uthread_t uth = get_bsdthread_info(ctx->vc_thread);
		proc_t proc;

		/*
		 * Get the cwd from the thread; if there isn't one, get it
		 * from the process, instead.
		 */
		if ((cwd = uth->uu_cdir) == NULLVP &&
		    (proc = (proc_t)get_bsdthreadtask_info(ctx->vc_thread)) != NULL &&
		    proc->p_fd != NULL)
			cwd = proc->p_fd->fd_cdir;
	}

	return(cwd);
}


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
		if (IS_VALID_CRED(safecred))
			kauth_cred_ref(safecred);
		newcontext->vc_ucred = safecred;
		return(newcontext);
	}
	return(NULL);	
}


vfs_context_t
vfs_context_current(void)
{
	vfs_context_t ctx = NULL;
	volatile uthread_t ut = (uthread_t)get_bsdthread_info(current_thread());

	if (ut != NULL ) {
		if (ut->uu_context.vc_ucred != NULL) {
			ctx = &ut->uu_context;
		}
	}

	return(ctx == NULL ? vfs_context_kernel() : ctx);
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
	if (kerncontext.vc_ucred == NOCRED)
		kerncontext.vc_ucred = kernproc->p_ucred;
	if (kerncontext.vc_thread == NULL)
		kerncontext.vc_thread = proc_thread(kernproc);

	return(&kerncontext);
}


int
vfs_context_rele(vfs_context_t ctx)
{
	if (ctx) {
		if (IS_VALID_CRED(ctx->vc_ucred))
			kauth_cred_unref(&ctx->vc_ucred);
		kfree(ctx, sizeof(struct vfs_context));
	}
	return(0);
}


ucred_t
vfs_context_ucred(vfs_context_t ctx)
{
	return (ctx->vc_ucred);
}

/*
 * Return true if the context is owned by the superuser.
 */
int
vfs_context_issuser(vfs_context_t ctx)
{
	return(kauth_cred_issuser(vfs_context_ucred(ctx)));
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
	vp->v_data = NULL;
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

/* is vnode_t a swap file vnode */
int 
vnode_isswap(vnode_t vp)
{
	return ((vp->v_flag & VSWAP)? 1 : 0);
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

	vnode_lock_spin(vp);
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

int
vnode_is_openevt(vnode_t vp)
{
	return ((vp->v_flag & VOPENEVT)? 1 : 0);
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
	return ((vp->v_flag & VISNAMEDSTREAM) ? 1 : 0);
#else
	return (0);
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
	return ((vp->v_specflags & SI_MOUNTEDON)? 1 : 0);
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

const char *
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
	struct vnode * vp ;

	if ( (vp = proc->p_fd->fd_rdir) ) {
	        if ( (vnode_getwithref(vp)) )
		        return (NULL);
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
	uio_t	fsec_uio;
	size_t	fsec_size;
	size_t	xsize, rsize;
	int	error;
	uint32_t	host_fsec_magic;
	uint32_t	host_acl_entrycount;

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
	if (fsec != NULL)
		kauth_filesec_free(fsec);
	if (fsec_uio != NULL)
		uio_free(fsec_uio);
	if (error)
		*fsecp = NULL;
	return(error);
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
	uio_t		fsec_uio;
	int		error;
	uint32_t	saved_acl_copysize;

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

	uio_addiov(fsec_uio, CAST_USER_ADDR_T(fsec), sizeof(struct kauth_filesec) - sizeof(struct kauth_acl));
	uio_addiov(fsec_uio, CAST_USER_ADDR_T(acl), saved_acl_copysize);
	error = vn_setxattr(vp,
	    KAUTH_FILESEC_XATTR,
	    fsec_uio,
	    XATTR_NOSECURITY, 		/* we have auth'ed already */
	    ctx);
	VFS_DEBUG(ctx, vp, "SETATTR - set ACL returning %d", error);

	kauth_filesec_acl_setendian(KAUTH_ENDIAN_HOST, fsec, acl);

out:
	if (fsec_uio != NULL)
		uio_free(fsec_uio);
	return(error);
}


/*
 * Returns:	0			Success
 *		ENOMEM			Not enough space [only if has filesec]
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
		if (vfs_context_issuser(ctx) && VATTR_IS_SUPPORTED(vap, va_uid)) {
			nuid = vap->va_uid;
		} else if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
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
		if (vfs_context_issuser(ctx) && VATTR_IS_SUPPORTED(vap, va_gid)) {
			ngid = vap->va_gid;
		} else if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
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
                    if ((error = vfs_update_vfsstat(vp->v_mount, ctx, VFS_KERNEL_EVENT)) != 0)
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
	int	error, is_perm_change=0;

	/*
	 * Make sure the filesystem is mounted R/W.
	 * If not, return an error.
	 */
	if (vfs_isrdonly(vp->v_mount)) {
		error = EROFS;
		goto out;
	}
#if NAMEDSTREAMS
	/* For streams, va_data_size is the only setable attribute. */
	if ((vp->v_flag & VISNAMEDSTREAM) && (vap->va_active != VNODE_ATTR_va_data_size)) {
		error = EPERM;
		goto out;
	}
#endif
	
	/*
	 * If ownership is being ignored on this volume, we silently discard
	 * ownership changes.
	 */
	if (vp->v_mount->mnt_flag & MNT_IGNORE_OWNERSHIP) {
		VATTR_CLEAR_ACTIVE(vap, va_uid);
		VATTR_CLEAR_ACTIVE(vap, va_gid);
	}

	if (   VATTR_IS_ACTIVE(vap, va_uid)  || VATTR_IS_ACTIVE(vap, va_gid)
	    || VATTR_IS_ACTIVE(vap, va_mode) || VATTR_IS_ACTIVE(vap, va_acl)) {
	    is_perm_change = 1;
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

	error = VNOP_SETATTR(vp, vap, ctx);

	if ((error == 0) && !VATTR_ALL_SUPPORTED(vap))
		error = vnode_setattr_fallback(vp, vap, ctx);

#if CONFIG_FSE
	// only send a stat_changed event if this is more than
	// just an access time update
	if (error == 0 && (vap->va_active != VNODE_ATTR_BIT(va_access_time))) {
	    if (is_perm_change) {
		if (need_fsevent(FSE_CHOWN, vp)) {
		    add_fsevent(FSE_CHOWN, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
		}
	    } else if(need_fsevent(FSE_STAT_CHANGED, vp)) {
		add_fsevent(FSE_STAT_CHANGED, ctx, FSE_ARG_VNODE, vp, FSE_ARG_DONE);
	    }
	}
#endif

out:
	return(error);
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
	int	error;

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
		if ((vp->v_type != VDIR) && (vp->v_type != VLNK) && (vp->v_type != VREG)) {
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
	vnode_t vp;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_lookup_desc;
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_context = ctx;
	thread_safe = THREAD_SAFE_FS(dvp);

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
VNOP_CREATE(vnode_t dvp, vnode_t * vpp, struct componentname * cnp, struct vnode_attr * vap, vfs_context_t ctx)
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
	a.a_context = ctx;
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
		xattrfile_remove(dvp, cnp->cn_nameptr, ctx, thread_safe, 0);
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
VNOP_WHITEOUT(vnode_t dvp, struct componentname * cnp, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_whiteout_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_whiteout_desc;
	a.a_dvp = dvp;
	a.a_cnp = cnp;
	a.a_flags = flags;
	a.a_context = ctx;
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
VNOP_MKNOD(vnode_t dvp, vnode_t * vpp, struct componentname * cnp, struct vnode_attr * vap, vfs_context_t ctx)
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
       a.a_context = ctx;
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
VNOP_OPEN(vnode_t vp, int mode, vfs_context_t ctx)
{
	int _err;
	struct vnop_open_args a;
	int thread_safe;
	int funnel_state = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_open_desc;
	a.a_vp = vp;
	a.a_mode = mode;
	a.a_context = ctx;
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
VNOP_CLOSE(vnode_t vp, int fflag, vfs_context_t ctx)
{
	int _err;
	struct vnop_close_args a;
	int thread_safe;
	int funnel_state = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_close_desc;
	a.a_vp = vp;
	a.a_fflag = fflag;
	a.a_context = ctx;
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
VNOP_ACCESS(vnode_t vp, int action, vfs_context_t ctx)
{
	int _err;
	struct vnop_access_args a;
	int thread_safe;
	int funnel_state = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_access_desc;
	a.a_vp = vp;
	a.a_action = action;
	a.a_context = ctx;
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
VNOP_GETATTR(vnode_t vp, struct vnode_attr * vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_getattr_args a;
	int thread_safe;
	int funnel_state = 0;	/* protected by thread_safe */

	a.a_desc = &vnop_getattr_desc;
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_context = ctx;
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
VNOP_SETATTR(vnode_t vp, struct vnode_attr * vap, vfs_context_t ctx)
{
	int _err;
	struct vnop_setattr_args a;
	int thread_safe;
	int funnel_state = 0;	/* protected by thread_safe */

	a.a_desc = &vnop_setattr_desc;
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_context = ctx;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_setattr_desc.vdesc_offset])(&a);

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

			xattrfile_setattr(dvp, vname, &va, ctx, thread_safe);
			if (dvp != NULLVP)
			        vnode_put(dvp);
			if (vname != NULL)
			        vnode_putname(vname);
		}
	}
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
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
			  VATTR_IS_SUPPORTED(vap, va_guuid)))
	        vnode_uncache_authorized_action(vp, KAUTH_INVALIDATE_CACHED_RIGHTS);

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
VNOP_READ(vnode_t vp, struct uio * uio, int ioflag, vfs_context_t ctx)
{
	int _err;
	struct vnop_read_args a;
	int thread_safe;
	int funnel_state = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	a.a_desc = &vnop_read_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_context = ctx;
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
VNOP_WRITE(vnode_t vp, struct uio * uio, int ioflag, vfs_context_t ctx)
{
	struct vnop_write_args a;
	int _err;
	int thread_safe;
	int funnel_state = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	a.a_desc = &vnop_write_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_context = ctx;
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
VNOP_IOCTL(vnode_t vp, u_long command, caddr_t data, int fflag, vfs_context_t ctx)
{
	int _err;
	struct vnop_ioctl_args a;
	int thread_safe;
	int funnel_state = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}

	if (vfs_context_is64bit(ctx)) {
		if (!vnode_vfs64bitready(vp)) {
			return(ENOTTY);
		}
	}

	a.a_desc = &vnop_ioctl_desc;
	a.a_vp = vp;
	a.a_command = command;
	a.a_data = data;
	a.a_fflag = fflag;
	a.a_context= ctx;
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
VNOP_SELECT(vnode_t vp, int which , int fflags, void * wql, vfs_context_t ctx)
{
	int _err;
	struct vnop_select_args a;
	int thread_safe;
	int funnel_state = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_select_desc;
	a.a_vp = vp;
	a.a_which = which;
	a.a_fflags = fflags;
	a.a_context = ctx;
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
VNOP_EXCHANGE(vnode_t fvp, vnode_t tvp, int options, vfs_context_t ctx)
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
	a.a_context = ctx;
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
VNOP_REVOKE(vnode_t vp, int flags, vfs_context_t ctx)
{
	struct vnop_revoke_args a;
	int _err;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_revoke_desc;
	a.a_vp = vp;
	a.a_flags = flags;
	a.a_context = ctx;
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
VNOP_MMAP(vnode_t vp, int fflags, vfs_context_t ctx)
{
	int _err;
	struct vnop_mmap_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_mmap_desc;
	a.a_vp = vp;
	a.a_fflags = fflags;
	a.a_context = ctx;
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
VNOP_MNOMAP(vnode_t vp, vfs_context_t ctx)
{
	int _err;
	struct vnop_mnomap_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_mnomap_desc;
	a.a_vp = vp;
	a.a_context = ctx;
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
VNOP_FSYNC(vnode_t vp, int waitfor, vfs_context_t ctx)
{
	struct vnop_fsync_args a;
	int _err;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_fsync_desc;
	a.a_vp = vp;
	a.a_waitfor = waitfor;
	a.a_context = ctx;
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
VNOP_REMOVE(vnode_t dvp, vnode_t vp, struct componentname * cnp, int flags, vfs_context_t ctx)
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
	a.a_context = ctx;
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
			 * Remove any associated extended attribute file (._ AppleDouble file).
			 */
		        xattrfile_remove(dvp, cnp->cn_nameptr, ctx, thread_safe, 1);
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
VNOP_LINK(vnode_t vp, vnode_t tdvp, struct componentname * cnp, vfs_context_t ctx)
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
		const char   *vname;

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
	a.a_context = ctx;
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
            vfs_context_t ctx)
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
	a.a_context = ctx;

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
		strlcpy(xfromname, "._", min(sizeof smallname1, len));
		strncat(xfromname, fcnp->cn_nameptr, fcnp->cn_namelen);
		xfromname[len-1] = '\0';

		/* Get destination attribute file name. */
		len = tcnp->cn_namelen + 3;
		if (len > sizeof(smallname2)) {
			MALLOC(xtoname, char *, len, M_TEMP, M_WAITOK);
		} else {
			xtoname = &smallname2[0];
		}
		strlcpy(xtoname, "._", min(sizeof smallname2, len));
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
	 * Rename any associated extended attribute file (._ AppleDouble file).
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
		NDINIT(&fromnd, DELETE, NOFOLLOW | USEDVP | CN_NBMOUNTLOOK, UIO_SYSSPACE,
		       CAST_USER_ADDR_T(xfromname), ctx);
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
			NDINIT(&tond, DELETE, NOFOLLOW | USEDVP | CN_NBMOUNTLOOK, UIO_SYSSPACE,
			       CAST_USER_ADDR_T(xtoname), ctx);
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
			args.a_context = ctx;

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
		       NOCACHE | NOFOLLOW | USEDVP | CN_NBMOUNTLOOK, UIO_SYSSPACE,
		       CAST_USER_ADDR_T(xtoname), ctx);
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
		a.a_context = ctx;

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
			const char *oname;
			vnode_t oparent;

			/* Save these off so we can later verify them (fix up below) */
			oname   = fromnd.ni_vp->v_name;
			oparent = fromnd.ni_vp->v_parent;

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
				/*
				 * Fix up name & parent pointers on ._ file
				 */
				if (oname == fromnd.ni_vp->v_name &&
				    oparent == fromnd.ni_vp->v_parent) {
					int update_flags;
			
					update_flags = VNODE_UPDATE_NAME;
			
					if (fdvp != tdvp)
						update_flags |= VNODE_UPDATE_PARENT;
			
					vnode_update_identity(fromnd.ni_vp, tdvp,
					                      tond.ni_cnd.cn_nameptr,
					                      tond.ni_cnd.cn_namelen,
					                      tond.ni_cnd.cn_hash,
					                      update_flags);
				}
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
           struct vnode_attr *vap, vfs_context_t ctx)
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
       a.a_context = ctx;
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
		xattrfile_remove(dvp, cnp->cn_nameptr, ctx, thread_safe, 0);
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
VNOP_RMDIR(struct vnode *dvp, struct vnode *vp, struct componentname *cnp, vfs_context_t ctx)
{
	int _err;
	struct vnop_rmdir_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_rmdir_desc;
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	a.a_context = ctx;
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
			 * Remove any associated extended attribute file (._ AppleDouble file).
			 */
		        xattrfile_remove(dvp, cnp->cn_nameptr, ctx, thread_safe, 1);
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
xattrfile_remove(vnode_t dvp, const char * basename, vfs_context_t ctx, int thread_safe, int force) {
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
	NDINIT(&nd, DELETE, WANTPARENT | LOCKLEAF | NOFOLLOW | USEDVP, UIO_SYSSPACE,
	       CAST_USER_ADDR_T(filename), ctx);
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
		if (VNOP_GETATTR(xvp, &va, ctx) == 0  &&
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
		a.a_context = ctx;

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
                  vfs_context_t ctx, int thread_safe) {
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
	       CAST_USER_ADDR_T(filename), ctx);
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
		a.a_context = ctx;

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
             struct vnode_attr *vap, char *target, vfs_context_t ctx)
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
       a.a_context = ctx;
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
		xattrfile_remove(dvp, cnp->cn_nameptr, ctx, thread_safe, 0);
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
             int *numdirent, vfs_context_t ctx)
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
	a.a_context = ctx;
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
                 u_long options, u_long *newstate, int *eofflag, u_long *actualcount, vfs_context_t ctx)
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
	a.a_context = ctx;
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
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_readlink_desc;
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_context = ctx;
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
VNOP_INACTIVE(struct vnode *vp, vfs_context_t ctx)
{
	int _err;
	struct vnop_inactive_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_inactive_desc;
	a.a_vp = vp;
	a.a_context = ctx;
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

#if NAMEDSTREAMS
	/* For file systems that do not support namedstreams natively, mark
	 * the shadow stream file vnode to be recycled as soon as the last
	 * reference goes away. To avoid re-entering reclaim code, do not
	 * call recycle on terminating named stream vnodes.
	 */
	if (vnode_isnamedstream(vp) &&
			(vp->v_parent != NULLVP) &&
			((vp->v_parent->v_mount->mnt_kern_flag & MNTK_NAMED_STREAMS) == 0) &&
			((vp->v_lflag & VL_TERMINATE) == 0)) {
		vnode_recycle(vp);
	}
#endif

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
VNOP_RECLAIM(struct vnode *vp, vfs_context_t ctx)
{
	int _err;
	struct vnop_reclaim_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_reclaim_desc;
	a.a_vp = vp;
	a.a_context = ctx;
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
	register_t *a_retval;
	vfs_context_t a_context;
};
#endif /* 0*/
errno_t 
VNOP_PATHCONF(struct vnode *vp, int name, register_t *retval, vfs_context_t ctx)
{
	int _err;
	struct vnop_pathconf_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_pathconf_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_retval = retval;
	a.a_context = ctx;
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
VNOP_ADVLOCK(struct vnode *vp, caddr_t id, int op, struct flock *fl, int flags, vfs_context_t ctx)
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
	a.a_context = ctx;
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
VNOP_ALLOCATE(struct vnode *vp, off_t length, u_int32_t flags, off_t *bytesallocated, off_t offset, vfs_context_t ctx)
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
	a.a_context = ctx;
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
VNOP_PAGEIN(struct vnode *vp, upl_t pl, vm_offset_t pl_offset, off_t f_offset, size_t size, int flags, vfs_context_t ctx)
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
	a.a_context = ctx;
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
VNOP_PAGEOUT(struct vnode *vp, upl_t pl, vm_offset_t pl_offset, off_t f_offset, size_t size, int flags, vfs_context_t ctx)
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
	a.a_context = ctx;
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
VNOP_SEARCHFS(struct vnode *vp, void *searchparams1, void *searchparams2, struct attrlist *searchattrs, u_long maxmatches, struct timeval *timelimit, struct attrlist *returnattrs, u_long *nummatches, u_long scriptcode, u_long options, struct uio *uio, struct searchstate *searchstate, vfs_context_t ctx)
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
	a.a_context = ctx;
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
	return (_err);
}

errno_t
VNOP_GETXATTR(vnode_t vp, const char *name, uio_t uio, size_t *size, int options, vfs_context_t ctx)
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
	a.a_context = ctx;

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
VNOP_SETXATTR(vnode_t vp, const char *name, uio_t uio, int options, vfs_context_t ctx)
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
	a.a_context = ctx;

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
	if (error == 0)
	        vnode_uncache_authorized_action(vp, KAUTH_INVALIDATE_CACHED_RIGHTS);
	return (error);
}

errno_t
VNOP_REMOVEXATTR(vnode_t vp, const char *name, int options, vfs_context_t ctx)
{
	struct vnop_removexattr_args a;
	int error;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = &vnop_removexattr_desc;
	a.a_vp = vp;
	a.a_name = name;
	a.a_options = options;
	a.a_context = ctx;

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
VNOP_LISTXATTR(vnode_t vp, uio_t uio, size_t *size, int options, vfs_context_t ctx)
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
	a.a_context = ctx;

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
VNOP_BLOCKMAP(struct vnode *vp, off_t foffset, size_t size, daddr64_t *bpn, size_t *run, void *poff, int flags, vfs_context_t ctx)
{
	int _err;
	struct vnop_blockmap_args a;
	int thread_safe;
	int funnel_state = 0;

	if (ctx == NULL) {
		ctx = vfs_context_current();
	}
	a.a_desc = &vnop_blockmap_desc;
	a.a_vp = vp;
	a.a_foffset = foffset;
	a.a_size = size;
	a.a_bpn = bpn;
	a.a_run = run;
	a.a_poff = poff;
	a.a_flags = flags;
	a.a_context = ctx;
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
VNOP_KQFILT_ADD(struct vnode *vp, struct knote *kn, vfs_context_t ctx)
{
	int _err;
	struct vnop_kqfilt_add_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = VDESC(vnop_kqfilt_add);
	a.a_vp = vp;
	a.a_kn = kn;
	a.a_context = ctx;
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
VNOP_KQFILT_REMOVE(struct vnode *vp, uintptr_t ident, vfs_context_t ctx)
{
	int _err;
	struct vnop_kqfilt_remove_args a;
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = VDESC(vnop_kqfilt_remove);
	a.a_vp = vp;
	a.a_ident = ident;
	a.a_context = ctx;
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
	int thread_safe;
	int funnel_state = 0;

	a.a_desc = VDESC(vnop_setlabel);
	a.a_vp = vp;
	a.a_vl = label;
	a.a_context = ctx;
	thread_safe = THREAD_SAFE_FS(vp);

	if (!thread_safe) {
		if ( (_err = lock_fsnode(vp, &funnel_state)) ) {
			return (_err);
		}
	}
	_err = (*vp->v_op[vnop_setlabel_desc.vdesc_offset])(&a);
	if (!thread_safe) {
		unlock_fsnode(vp, &funnel_state);
	}
	return(_err);
}


#if NAMEDSTREAMS
/*
 * Get a named streamed
 */
errno_t 
VNOP_GETNAMEDSTREAM(vnode_t vp, vnode_t *svpp, const char *name, enum nsoperation operation, int flags, vfs_context_t ctx)
{
	struct vnop_getnamedstream_args a;

	if (!THREAD_SAFE_FS(vp))
		return (ENOTSUP);
	a.a_desc = &vnop_getnamedstream_desc;
	a.a_vp = vp;
	a.a_svpp = svpp;
	a.a_name = name;
	a.a_operation = operation;
	a.a_flags = flags;
	a.a_context = ctx;

	return (*vp->v_op[vnop_getnamedstream_desc.vdesc_offset])(&a);
}

/*
 * Create a named streamed
 */
errno_t 
VNOP_MAKENAMEDSTREAM(vnode_t vp, vnode_t *svpp, const char *name, int flags, vfs_context_t ctx)
{
	struct vnop_makenamedstream_args a;

	if (!THREAD_SAFE_FS(vp))
		return (ENOTSUP);
	a.a_desc = &vnop_makenamedstream_desc;
	a.a_vp = vp;
	a.a_svpp = svpp;
	a.a_name = name;
	a.a_flags = flags;
	a.a_context = ctx;

	return (*vp->v_op[vnop_makenamedstream_desc.vdesc_offset])(&a);
}


/*
 * Remove a named streamed
 */
errno_t 
VNOP_REMOVENAMEDSTREAM(vnode_t vp, vnode_t svp, const char *name, int flags, vfs_context_t ctx)
{
	struct vnop_removenamedstream_args a;

	if (!THREAD_SAFE_FS(vp))
		return (ENOTSUP);
	a.a_desc = &vnop_removenamedstream_desc;
	a.a_vp = vp;
	a.a_svp = svp;
	a.a_name = name;
	a.a_flags = flags;
	a.a_context = ctx;

	return (*vp->v_op[vnop_removenamedstream_desc.vdesc_offset])(&a);
}
#endif
