/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
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
 *	@(#)fdesc_vfsops.c	8.10 (Berkeley) 5/14/95
 *
 */
/*
* /dev/fd Filesystem
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/proc_internal.h>
#include <sys/resourcevar.h>
#include <sys/filedesc.h>
#include <sys/vnode.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <miscfs/fdesc/fdesc.h>

/*
 * Mount the per-process file descriptors (/dev/fd)
 */
static int
fdesc_mount(struct mount *mp, __unused vnode_t devvp, __unused user_addr_t data, __unused vfs_context_t context)
{
	int error = 0;
	struct fdescmount *fmp;
	struct vnode *rvp;

	/*
	 * Update is a no-op
	 */
	if (mp->mnt_flag & MNT_UPDATE)
		return (ENOTSUP);

	error = fdesc_allocvp(Froot, FD_ROOT, mp, &rvp, VDIR);
	if (error)
		return (error);

	MALLOC(fmp, struct fdescmount *, sizeof(struct fdescmount),
				M_UFSMNT, M_WAITOK);	/* XXX */

	vnode_setnoflush(rvp);
	vnode_ref(rvp);
	vnode_put(rvp);

	fmp->f_root = rvp;
	/* XXX -- don't mark as local to work around fts() problems */
	/*mp->mnt_flag |= MNT_LOCAL;*/
	mp->mnt_data = (qaddr_t) fmp;
	vfs_getnewfsid(mp);

	bzero(mp->mnt_vfsstat.f_mntfromname, MAXPATHLEN);
	bcopy("fdesc", mp->mnt_vfsstat.f_mntfromname, sizeof("fdesc"));
	return (0);
}

static int
fdesc_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t context)
{
	return (0);
}

static int
fdesc_unmount(struct mount *mp, int mntflags, __unused vfs_context_t context)
{
	int error;
	int flags = 0;
	int force = 0;
	struct vnode *rvp = VFSTOFDESC(mp)->f_root;

	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
		force = 1;
	}

	if ( vnode_isinuse(rvp, 1) && !force )
		return (EBUSY);
	if ( (error = vflush(mp, rvp, flags|SKIPSYSTEM)) && !force )
		return (error);

	/*
	 * And mark for recycle after we drop its reference; it away for future re-use
	 */
	vnode_recycle(rvp);
	/*
	 * Release reference on underlying root vnode
	 */
	vnode_rele(rvp);
	/*
	 * Finally, throw away the fdescmount structure
	 */
	_FREE(mp->mnt_data, M_UFSMNT);	/* XXX */
	mp->mnt_data = NULL;

	return (0);
}

int
fdesc_root(struct mount *mp, struct vnode **vpp, __unused vfs_context_t context)
{
	struct vnode *vp;

	/*
	 * Return locked reference to root.
	 */
	vp = VFSTOFDESC(mp)->f_root;
	vnode_get(vp);
	*vpp = vp;
	return (0);
}

#if 0
/*
 * XXX commented out in mount.h
 */
int
fdesc_statfs(__unused struct mount *mp, struct vfsstatfs *sbp, vfs_context_t context)
{
	proc_t p = vfs_context_proc(context);
	struct filedesc *fdp;
	int lim;
	int i;
	int last;
	int freefd;

	/*
	 * Compute number of free file descriptors.
	 * [ Strange results will ensue if the open file
	 * limit is ever reduced below the current number
	 * of open files... ]
	 */
	lim = p->p_rlimit[RLIMIT_NOFILE].rlim_cur;
	fdp = p->p_fd;
	last = min(fdp->fd_nfiles, lim);
	freefd = 0;
	for (i = fdp->fd_freefile; i < last; i++)
		if (fdp->fd_ofiles[i] == NULL &&
				!(fdp->fd_ofileflags[i] & UF_RESERVED))
			freefd++;

	/*
	 * Adjust for the fact that the fdesc array may not
	 * have been fully allocated yet.
	 */
	if (fdp->fd_nfiles < lim)
		freefd += (lim - fdp->fd_nfiles);

	sbp->f_flags = 0;
	sbp->f_bsize = DEV_BSIZE;
	sbp->f_iosize = DEV_BSIZE;
	sbp->f_blocks = (uint64_t)2;		/* 1K to keep df happy */
	sbp->f_bfree = 0;
	sbp->f_bavail = 0;
	sbp->f_files = (uint64_t)((unsigned long)(lim + 1));		/* Allow for "." */
	sbp->f_ffree = (uint64_t)((unsigned long)freefd);		/* See comments above */

	return (0);
}
#endif	/* 0 */

static int
fdesc_vfs_getattr(__unused mount_t mp, struct vfs_attr *fsap, vfs_context_t context)
{
	VFSATTR_RETURN(fsap, f_bsize, DEV_BSIZE);
	VFSATTR_RETURN(fsap, f_iosize, DEV_BSIZE);
	VFSATTR_RETURN(fsap, f_blocks, 2);
	VFSATTR_RETURN(fsap, f_bfree, 0);
	VFSATTR_RETURN(fsap, f_bavail, 0);
	VFSATTR_RETURN(fsap, f_fssubtype, 0);
	
	if (VFSATTR_IS_ACTIVE(fsap, f_objcount) ||
	    VFSATTR_IS_ACTIVE(fsap, f_maxobjcount) ||
	    VFSATTR_IS_ACTIVE(fsap, f_files) ||
	    VFSATTR_IS_ACTIVE(fsap, f_ffree))
	{
		proc_t p = vfs_context_proc(context);
		struct filedesc *fdp;
		int lim;
		int i;
		int last;
		int freefd;
	
		/*
		 * Compute number of free file descriptors.
		 * [ Strange results will ensue if the open file
		 * limit is ever reduced below the current number
		 * of open files... ]
		 */
		lim = p->p_rlimit[RLIMIT_NOFILE].rlim_cur;
		fdp = p->p_fd;
		last = min(fdp->fd_nfiles, lim);
		freefd = 0;
		for (i = fdp->fd_freefile; i < last; i++)
			if (fdp->fd_ofiles[i] == NULL &&
					!(fdp->fd_ofileflags[i] & UF_RESERVED))
				freefd++;
	
		/*
		 * Adjust for the fact that the fdesc array may not
		 * have been fully allocated yet.
		 */
		if (fdp->fd_nfiles < lim)
			freefd += (lim - fdp->fd_nfiles);
		
		VFSATTR_RETURN(fsap, f_objcount, lim+1);
		VFSATTR_RETURN(fsap, f_maxobjcount, lim+1);
		VFSATTR_RETURN(fsap, f_files, lim+1);
		VFSATTR_RETURN(fsap, f_ffree, freefd);
	}
	
	return 0;
}

static int
fdesc_sync(__unused struct mount *mp, __unused int waitfor, __unused vfs_context_t context)
{

	return (0);
}

#define fdesc_fhtovp (int (*) (mount_t, int, unsigned char *, vnode_t *, vfs_context_t))eopnotsupp
#define fdesc_sysctl (int (*) (int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, vfs_context_t))eopnotsupp
#define fdesc_vget (int (*) (mount_t, ino64_t, vnode_t *, vfs_context_t))eopnotsupp
#define fdesc_vptofh (int (*) (vnode_t, int *, unsigned char *, vfs_context_t))eopnotsupp

struct vfsops fdesc_vfsops = {
	fdesc_mount,
	fdesc_start,
	fdesc_unmount,
	fdesc_root,
	NULL, 			/* quotactl */
	fdesc_vfs_getattr,
/*	fdesc_statfs,	XXX commented out in mount.h */
	fdesc_sync,
	fdesc_vget,
	fdesc_fhtovp,
	fdesc_vptofh,
	fdesc_init,
	fdesc_sysctl,
	NULL,
	{NULL}
};
