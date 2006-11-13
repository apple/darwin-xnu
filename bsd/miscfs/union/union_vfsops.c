/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1994, 1995 The Regents of the University of California.
 * Copyright (c) 1994, 1995 Jan-Simon Pendry.
 * All rights reserved.
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
 *	@(#)union_vfsops.c	8.20 (Berkeley) 5/20/95
 */

/*
 * Union Layer
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/filedesc.h>
#include <sys/queue.h>
#include <miscfs/union/union.h>

static	int union_itercallback(__unused vnode_t, void *);

/*
 * Mount union filesystem
 */
int
union_mount(mount_t mp, __unused vnode_t devvp, user_addr_t data, vfs_context_t context)
{
	proc_t p = vfs_context_proc(context);
	int error = 0;
	struct user_union_args args;
	struct vnode *lowerrootvp = NULLVP;
	struct vnode *upperrootvp = NULLVP;
	struct union_mount *um = 0;
	kauth_cred_t cred = NOCRED;
	char *cp;
	int len;
	u_int size;
	struct nameidata nd;
	
#ifdef UNION_DIAGNOSTIC
	printf("union_mount(mp = %x)\n", mp);
#endif

	/*
	 * Update is a no-op
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		/*
		 * Need to provide.
		 * 1. a way to convert between rdonly and rdwr mounts.
		 * 2. support for nfs exports.
		 */
		error = ENOTSUP;
		goto bad;
	}

	/*
	 * Get argument
	 */
	if (vfs_context_is64bit(context)) {
		error = copyin(data, (caddr_t)&args, sizeof(args));
	}
	else {
		struct union_args temp;
		error = copyin(data, (caddr_t)&temp, sizeof (temp));
		args.target = CAST_USER_ADDR_T(temp.target);
		args.mntflags = temp.mntflags;
	}
	if (error)
		goto bad;

	lowerrootvp = mp->mnt_vnodecovered;
	vnode_get(lowerrootvp);

	/*
	 * Find upper node.
	 */
	NDINIT(&nd, LOOKUP, FOLLOW|WANTPARENT,
	       (IS_64BIT_PROCESS(p) ? UIO_USERSPACE64 : UIO_USERSPACE32), 
	       args.target, context);

	if ((error = namei(&nd)))
		goto bad;

	nameidone(&nd);
	upperrootvp = nd.ni_vp;
	vnode_put(nd.ni_dvp);
	nd.ni_dvp = NULL;

	if (upperrootvp->v_type != VDIR) {
		error = EINVAL;
		goto bad;
	}
	
//	um = (struct union_mount *) malloc(sizeof(struct union_mount),
//				M_UFSMNT, M_WAITOK);	/* XXX */
	MALLOC(um, struct union_mount *, sizeof(struct union_mount),
				M_UFSMNT, M_WAITOK);

	/*
	 * Keep a held reference to the target vnodes.
	 * They are vnode_put'd in union_unmount.
	 *
	 * Depending on the _BELOW flag, the filesystems are
	 * viewed in a different order.  In effect, this is the
	 * same as providing a mount under option to the mount syscall.
	 */

	um->um_op = args.mntflags & UNMNT_OPMASK;
	switch (um->um_op) {
	case UNMNT_ABOVE:
		um->um_lowervp = lowerrootvp;
		um->um_uppervp = upperrootvp;
		break;

	case UNMNT_BELOW:
		um->um_lowervp = upperrootvp;
		um->um_uppervp = lowerrootvp;
		break;

	case UNMNT_REPLACE:
		vnode_put(lowerrootvp);
		lowerrootvp = NULLVP;
		um->um_uppervp = upperrootvp;
		um->um_lowervp = lowerrootvp;
		break;

	default:
		error = EINVAL;
		goto bad;
	}

	/*
	 * Unless the mount is readonly, ensure that the top layer
	 * supports whiteout operations
	 */
	if ((mp->mnt_flag & MNT_RDONLY) == 0) {
		error = VNOP_WHITEOUT(um->um_uppervp, (struct componentname *) 0,
		                      LOOKUP, context);
		if (error)
			goto bad;
	}

	um->um_cred = kauth_cred_get_with_ref();
	um->um_cmode = UN_DIRMODE &~ p->p_fd->fd_cmask;

	/*
	 * Depending on what you think the MNT_LOCAL flag might mean,
	 * you may want the && to be || on the conditional below.
	 * At the moment it has been defined that the filesystem is
	 * only local if it is all local, ie the MNT_LOCAL flag implies
	 * that the entire namespace is local.  If you think the MNT_LOCAL
	 * flag implies that some of the files might be stored locally
	 * then you will want to change the conditional.
	 */
	if (um->um_op == UNMNT_ABOVE) {
		if (((um->um_lowervp == NULLVP) ||
		     (um->um_lowervp->v_mount->mnt_flag & MNT_LOCAL)) &&
		    (um->um_uppervp->v_mount->mnt_flag & MNT_LOCAL))
			mp->mnt_flag |= MNT_LOCAL;
	}

	/*
	 * Copy in the upper layer's RDONLY flag.  This is for the benefit
	 * of lookup() which explicitly checks the flag, rather than asking
	 * the filesystem for it's own opinion.  This means, that an update
	 * mount of the underlying filesystem to go from rdonly to rdwr
	 * will leave the unioned view as read-only.
	 */
	mp->mnt_flag |= (um->um_uppervp->v_mount->mnt_flag & MNT_RDONLY);

	mp->mnt_data = (qaddr_t) um;
	vfs_getnewfsid(mp);


	switch (um->um_op) {
	case UNMNT_ABOVE:
		cp = "<above>:";
		break;
	case UNMNT_BELOW:
		cp = "<below>:";
		break;
	case UNMNT_REPLACE:
		cp = "";
		break;
	}
	len = strlen(cp);
	bcopy(cp, mp->mnt_vfsstat.f_mntfromname, len);

	cp = mp->mnt_vfsstat.f_mntfromname + len;
	len = MNAMELEN - len;

	(void) copyinstr(args.target, cp, len - 1, (size_t *)&size);
	bzero(cp + size, len - size);

#ifdef UNION_DIAGNOSTIC
	printf("union_mount: from %s, on %s\n",
		mp->mnt_vfsstat.f_mntfromname, mp->mnt_vfsstat.f_mntonname);
#endif
	return (0);

bad:
	if (um)
		_FREE(um, M_UFSMNT);
	if (cred != NOCRED)
		kauth_cred_rele(cred);
	if (upperrootvp)
		vnode_put(upperrootvp);
	if (lowerrootvp)
		vnode_put(lowerrootvp);
	return (error);
}

/*
 * VFS start.  Nothing needed here - the start routine
 * on the underlying filesystem(s) will have been called
 * when that filesystem was mounted.
 */
int
union_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t context)
{

	return (0);
}

static int
union_itercallback(__unused vnode_t vp, void *args)
{
	int  num = *(int *)args;
	
	*(int *)args = num + 1;
	return(VNODE_RETURNED);
}



/*
 * Free reference to union layer
 */
int
union_unmount(mount_t mp, int mntflags, __unused vfs_context_t context)
{
	struct union_mount *um = MOUNTTOUNIONMOUNT(mp);
	struct vnode *um_rootvp;
	int error;
	int freeing;
	int flags = 0;
	kauth_cred_t cred;

#ifdef UNION_DIAGNOSTIC
	printf("union_unmount(mp = %x)\n", mp);
#endif

	if (mntflags & MNT_FORCE)
		flags |= FORCECLOSE;

	if ((error = union_root(mp, &um_rootvp)))
		return (error);

	/*
	 * Keep flushing vnodes from the mount list.
	 * This is needed because of the un_pvp held
	 * reference to the parent vnode.
	 * If more vnodes have been freed on a given pass,
	 * the try again.  The loop will iterate at most
	 * (d) times, where (d) is the maximum tree depth
	 * in the filesystem.
	 */
	for (freeing = 0; vflush(mp, um_rootvp, flags) != 0;) {
		int n = 0;

		vnode_iterate(mp, VNODE_NOLOCK_INTERNAL, union_itercallback, &n);

		/* if this is unchanged then stop */
		if (n == freeing)
			break;

		/* otherwise try once more time */
		freeing = n;
	}

	/* At this point the root vnode should have a single reference */
	if (vnode_isinuse(um_rootvp, 0)) {
		vnode_put(um_rootvp);
		return (EBUSY);
	}

#ifdef UNION_DIAGNOSTIC
	vprint("union root", um_rootvp);
#endif	 
	/*
	 * Discard references to upper and lower target vnodes.
	 */
	if (um->um_lowervp)
		vnode_put(um->um_lowervp);
	vnode_put(um->um_uppervp);
	cred = um->um_cred;
	if (cred != NOCRED) {
		um->um_cred = NOCRED;
		kauth_cred_rele(cred);
	}
	/*
	 * Release reference on underlying root vnode
	 */
	vnode_put(um_rootvp);
	/*
	 * And blow it away for future re-use
	 */
	vnode_reclaim(um_rootvp);
	/*
	 * Finally, throw away the union_mount structure
	 */
	_FREE(mp->mnt_data, M_UFSMNT);	/* XXX */
	mp->mnt_data = 0;
	return (0);
}

int
union_root(mount_t mp, vnode_t *vpp, __unused vfs_context_t context)
{
	struct union_mount *um = MOUNTTOUNIONMOUNT(mp);
	int error;

	/*
	 * Return locked reference to root.
	 */
	vnode_get(um->um_uppervp);
	if (um->um_lowervp)
		vnode_get(um->um_lowervp);
	error = union_allocvp(vpp, mp,
			      (struct vnode *) 0,
			      (struct vnode *) 0,
			      (struct componentname *) 0,
			      um->um_uppervp,
			      um->um_lowervp,
			      1);

	if (error) {
	        vnode_put(um->um_uppervp);
		if (um->um_lowervp)
			vnode_put(um->um_lowervp);
	} 

	return (error);
}

static int
union_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t context)
{
	int error;
	struct union_mount *um = MOUNTTOUNIONMOUNT(mp);
	struct vfs_attr attr;
	uint32_t lbsize = 0;

#ifdef UNION_DIAGNOSTIC
	printf("union_vfs_getattr(mp = %x, lvp = %x, uvp = %x)\n", mp,
			um->um_lowervp,
	       		um->um_uppervp);
#endif

	/* Get values from lower file system (if any) */
	if (um->um_lowervp) {
		VFSATTR_INIT(&attr);
		VFSATTR_WANTED(&attr, f_bsize);
		VFSATTR_WANTED(&attr, f_blocks);
		VFSATTR_WANTED(&attr, f_bused);
		VFSATTR_WANTED(&attr, f_files);
		error = vfs_getattr(um->um_lowervp->v_mount, &attr, context);
		if (error)
			return (error);

		/* now copy across the "interesting" information and fake the rest */
		if (VFSATTR_IS_SUPPORTED(&attr, f_bsize))
			lbsize = attr.f_bsize;
		else
			lbsize = um->um_lowervp->v_mount->mnt_devblocksize;
		fsap->f_blocks = VFSATTR_IS_SUPPORTED(&attr, f_blocks) ? attr.f_blocks : 0;
		fsap->f_bused  = VFSATTR_IS_SUPPORTED(&attr, f_bused)  ? attr.f_bused  : 0;
		fsap->f_files  = VFSATTR_IS_SUPPORTED(&attr, f_files)  ? attr.f_files  : 0;
	} else {
		fsap->f_blocks = 0;
		fsap->f_bused = 0;
		fsap->f_files = 0;
	}

	VFSATTR_INIT(&attr);
	VFSATTR_WANTED(&attr, f_bsize);
	VFSATTR_WANTED(&attr, f_blocks);
	VFSATTR_WANTED(&attr, f_bfree);
	VFSATTR_WANTED(&attr, f_bavail);
	VFSATTR_WANTED(&attr, f_files);
	VFSATTR_WANTED(&attr, f_ffree);
	error = vfs_getattr(um->um_uppervp->v_mount, &attr, context);
	if (error)
		return (error);

	if (VFSATTR_IS_SUPPORTED(&attr, f_bsize)) {
		fsap->f_bsize = attr.f_bsize;
		VFSATTR_SET_SUPPORTED(fsap, f_bsize);
	}
	if (VFSATTR_IS_SUPPORTED(&attr, f_iosize)) {
		fsap->f_iosize = attr.f_iosize;
		VFSATTR_SET_SUPPORTED(fsap, f_iosize);
	}

	/*
	 * if the lower and upper blocksizes differ, then frig the
	 * block counts so that the sizes reported by df make some
	 * kind of sense.  none of this makes sense though.
	 */
	if (VFSATTR_IS_SUPPORTED(&attr, f_bsize))
		fsap->f_bsize = attr.f_bsize;
	else
		fsap->f_bsize =  um->um_uppervp->v_mount->mnt_devblocksize;
	VFSATTR_RETURN(fsap, f_bsize, attr.f_bsize);
	if (fsap->f_bsize != lbsize)
		fsap->f_blocks = fsap->f_blocks * lbsize / attr.f_bsize;

	/*
	 * The "total" fields count total resources in all layers,
	 * the "free" fields count only those resources which are
	 * free in the upper layer (since only the upper layer
	 * is writeable).
	 */
	if (VFSATTR_IS_SUPPORTED(&attr, f_blocks))
		fsap->f_blocks += attr.f_blocks;
	if (VFSATTR_IS_SUPPORTED(&attr, f_bfree))
		fsap->f_bfree = attr.f_bfree;
	if (VFSATTR_IS_SUPPORTED(&attr, f_bavail))
		fsap->f_bavail = attr.f_bavail;
	if (VFSATTR_IS_SUPPORTED(&attr, f_bused))
		fsap->f_bused += attr.f_bused;
	if (VFSATTR_IS_SUPPORTED(&attr, f_files))
		fsap->f_files += attr.f_files;
	if (VFSATTR_IS_SUPPORTED(&attr, f_ffree))
		fsap->f_ffree = attr.f_ffree;

	VFSATTR_SET_SUPPORTED(fsap, f_bsize);
	VFSATTR_SET_SUPPORTED(fsap, f_blocks);
	VFSATTR_SET_SUPPORTED(fsap, f_bfree);
	VFSATTR_SET_SUPPORTED(fsap, f_bavail);
	VFSATTR_SET_SUPPORTED(fsap, f_bused);
	VFSATTR_SET_SUPPORTED(fsap, f_files);
	VFSATTR_SET_SUPPORTED(fsap, f_ffree);

	return (0);
}

/*
 * XXX - Assumes no data cached at union layer.
 */
#define union_sync (int (*) (mount_t, int, ucred_t, vfs_context_t))nullop

#define union_fhtovp (int (*) (mount_t, int, unsigned char *, vnode_t *, vfs_context_t))eopnotsupp
int union_init (struct vfsconf *);
#define union_sysctl (int (*) (int *, u_int, user_addr_t, size_t *, user_addr_t, size_t, vfs_context_t))eopnotsupp
#define union_vget (int (*) (mount_t, ino64_t, vnode_t *, vfs_context_t))eopnotsupp
#define union_vptofh (int (*) (vnode_t, int *, unsigned char *, vfs_context_t))eopnotsupp

struct vfsops union_vfsops = {
	union_mount,
	union_start,
	union_unmount,
	union_root,
	NULL,			/* quotactl */
	union_vfs_getattr,
	union_sync,
	union_vget,
	union_fhtovp,
	union_vptofh,
	union_init,
	union_sysctl
};
