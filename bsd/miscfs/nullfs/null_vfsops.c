/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1992, 1993
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
 *	@(#)null_vfsops.c	8.7 (Berkeley) 5/14/95
 *
 * @(#)lofs_vfsops.c	1.2 (Berkeley) 6/18/92
 */

/*
 * Null Layer
 * (See null_vnops.c for a description of what this does.)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <miscfs/nullfs/null.h>

/*
 * Mount null layer
 */
static int
nullfs_mount(mp, devvp, data, context)
	struct mount *mp;
	vnode_t devvp;
	user_addr_t data;
	vfs_context_t context;
{
	int error = 0;
	struct user_null_args args;
	struct vnode *lowerrootvp, *vp;
	struct vnode *nullm_rootvp;
	struct null_mount *xmp;
	u_int size;

#ifdef NULLFS_DIAGNOSTIC
	printf("nullfs_mount(mp = %x)\n", mp);
#endif

	/*
	 * Update is a no-op
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		return (ENOTSUP);
		/* return VFS_MOUNT(MOUNTTONULLMOUNT(mp)->nullm_vfs, devvp, data,  p);*/
	}

	/*
	 * Get argument
	 */
	if (vfs_context_is64bit(context)) {
		error = copyin(data, (caddr_t)&args, sizeof (args));
	}
	else {
		struct null_args temp;
		error = copyin(data, (caddr_t)&temp, sizeof (temp));
		args.target = CAST_USER_ADDR_T(temp.target);
	}
	if (error)
		return (error);

	/*
	 * Find lower node
	 */
	NDINIT(ndp, LOOKUP, FOLLOW|WANTPARENT|LOCKLEAF,
		UIO_USERSPACE, args.target, context);
	if (error = namei(ndp))
		return (error);
	nameidone(ndp);
	/*
	 * Sanity check on lower vnode
	 */
	lowerrootvp = ndp->ni_vp;

	vnode_put(ndp->ni_dvp);
	ndp->ni_dvp = NULL;

	xmp = (struct null_mount *) _MALLOC(sizeof(struct null_mount),
				M_UFSMNT, M_WAITOK);	/* XXX */

	/*
	 * Save reference to underlying FS
	 */
	xmp->nullm_vfs = lowerrootvp->v_mount;

	/*
	 * Save reference.  Each mount also holds
	 * a reference on the root vnode.
	 */
	error = null_node_create(mp, lowerrootvp, &vp);
	/*
	 * Make sure the node alias worked
	 */
	if (error) {
		vnode_put(lowerrootvp);
		FREE(xmp, M_UFSMNT);	/* XXX */
		return (error);
	}

	/*
	 * Keep a held reference to the root vnode.
	 * It is vnode_put'd in nullfs_unmount.
	 */
	nullm_rootvp = vp;
	nullm_rootvp->v_flag |= VROOT;
	xmp->nullm_rootvp = nullm_rootvp;
	if (NULLVPTOLOWERVP(nullm_rootvp)->v_mount->mnt_flag & MNT_LOCAL)
		mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_data = (qaddr_t) xmp;
	vfs_getnewfsid(mp);

	(void) copyinstr(args.target, mp->mnt_vfsstat.f_mntfromname, MAXPATHLEN - 1, 
	    &size);
	bzero(mp->mnt_vfsstat.f_mntfromname + size, MNAMELEN - size);
#ifdef NULLFS_DIAGNOSTIC
	printf("nullfs_mount: lower %s, alias at %s\n",
		mp->mnt_vfsstat.f_mntfromname, mp->mnt_vfsstat.f_mntonname);
#endif
	return (0);
}

/*
 * VFS start.  Nothing needed here - the start routine
 * on the underlying filesystem will have been called
 * when that filesystem was mounted.
 */
static int
nullfs_start(mp, flags, context)
	struct mount *mp;
	int flags;
	vfs_context_t context;
{
	return (0);
	/* return VFS_START(MOUNTTONULLMOUNT(mp)->nullm_vfs, flags, context); */
}

/*
 * Free reference to null layer
 */
static int
nullfs_unmount(mp, mntflags, context)
	struct mount *mp;
	int mntflags;
	vfs_context_t context;
{
	struct vnode *nullm_rootvp = MOUNTTONULLMOUNT(mp)->nullm_rootvp;
	int error;
	int flags = 0;
	int force = 0;

#ifdef NULLFS_DIAGNOSTIC
	printf("nullfs_unmount(mp = %x)\n", mp);
#endif

	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
		force = 1;
	}

	if ( (nullm_rootvp->v_usecount > 1) && !force )
		return (EBUSY);
	if ( (error = vflush(mp, nullm_rootvp, flags)) && !force )
		return (error);

#ifdef NULLFS_DIAGNOSTIC
	vprint("alias root of lower", nullm_rootvp);
#endif	 
	/*
	 * Release reference on underlying root vnode
	 */
	vnode_put(nullm_rootvp);
	/*
	 * And blow it away for future re-use
	 */
	vnode_reclaim(nullm_rootvp);
	/*
	 * Finally, throw away the null_mount structure
	 */
	FREE(mp->mnt_data, M_UFSMNT);	/* XXX */
	mp->mnt_data = 0;
	return 0;
}

static int
nullfs_root(mp, vpp, context)
	struct mount *mp;
	struct vnode **vpp;
	vfs_context_t context;
{
	struct proc *p = curproc;	/* XXX */
	struct vnode *vp;

#ifdef NULLFS_DIAGNOSTIC
	printf("nullfs_root(mp = %x, vp = %x->%x)\n", mp,
			MOUNTTONULLMOUNT(mp)->nullm_rootvp,
			NULLVPTOLOWERVP(MOUNTTONULLMOUNT(mp)->nullm_rootvp)
			);
#endif

	/*
	 * Return locked reference to root.
	 */
	vp = MOUNTTONULLMOUNT(mp)->nullm_rootvp;
	vnode_get(vp);
	*vpp = vp;
	return 0;
}

static int
nullfs_quotactl(mp, cmd, uid, datap, context)
	struct mount *mp;
	int cmd;
	uid_t uid;
	caddr_t datap;
	vfs_context_t context;
{
	return VFS_QUOTACTL(MOUNTTONULLMOUNT(mp)->nullm_vfs, cmd, uid, datap, context);
}

static int
nullfs_statfs(mp, sbp, context)
	struct mount *mp;
	struct vfsstatfs *sbp;
	vfs_context_t context;
{
	int error;
	struct vfsstatfs mstat;

#ifdef NULLFS_DIAGNOSTIC
	printf("nullfs_statfs(mp = %x, vp = %x->%x)\n", mp,
			MOUNTTONULLMOUNT(mp)->nullm_rootvp,
			NULLVPTOLOWERVP(MOUNTTONULLMOUNT(mp)->nullm_rootvp)
			);
#endif

	bzero(&mstat, sizeof(mstat));

	error = VFS_STATFS(MOUNTTONULLMOUNT(mp)->nullm_vfs, &mstat, context);
	if (error)
		return (error);

	/* now copy across the "interesting" information and fake the rest */
	//sbp->f_type = mstat.f_type;
	sbp->f_flags = mstat.f_flags;
	sbp->f_bsize = mstat.f_bsize;
	sbp->f_iosize = mstat.f_iosize;
	sbp->f_blocks = mstat.f_blocks;
	sbp->f_bfree = mstat.f_bfree;
	sbp->f_bavail = mstat.f_bavail;
	sbp->f_files = mstat.f_files;
	sbp->f_ffree = mstat.f_ffree;
	return (0);
}

static int
nullfs_sync(__unused struct mount *mp, __unused int waitfor,
	__unused kauth_cred_t cred, __unused vfs_context_t context)
{
	/*
	 * XXX - Assumes no data cached at null layer.
	 */
	return (0);
}

static int
nullfs_vget(mp, ino, vpp, context)
	struct mount *mp;
	ino64_t ino;
	struct vnode **vpp;
	vfs_context_t context;
{
	
	return VFS_VGET(MOUNTTONULLMOUNT(mp)->nullm_vfs, ino, vpp, context);
}

static int
nullfs_fhtovp(mp, fhlen, fhp, vpp, context)
	struct mount *mp;
	int fhlen;
	unsigned char *fhp;
	struct vnode **vpp;
	vfs_context_t context;
{

	return VFS_FHTOVP(MOUNTTONULLMOUNT(mp)->nullm_vfs, fhlen, fhp, vpp, context);
}

static int
nullfs_vptofh(vp, fhlenp, fhp, context)
	struct vnode *vp;
	int *fhlenp;
	unsigned char *fhp;
	vfs_context_t context;
{
	return VFS_VPTOFH(NULLVPTOLOWERVP(vp), fhlenp, fhp, context);
}

int nullfs_init (struct vfsconf *);

#define nullfs_sysctl (int (*) (int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, proc_t))eopnotsupp

struct vfsops null_vfsops = {
	nullfs_mount,
	nullfs_start,
	nullfs_unmount,
	nullfs_root,
	nullfs_quotactl,
	nullfs_statfs,
	nullfs_sync,
	nullfs_vget,
	nullfs_fhtovp,
	nullfs_vptofh,
	nullfs_init,
	nullfs_sysctl
};
