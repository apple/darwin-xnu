/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1993, 1995
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
 *	@(#)ufs_vnops.c	8.27 (Berkeley) 5/27/95
 */

#include <rev_endian_fs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/conf.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/ubc.h>
#include <sys/quota.h>
#include <sys/uio_internal.h>

#include <kern/thread.h>
#include <sys/vm.h>

#include <miscfs/specfs/specdev.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/dir.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>

#if REV_ENDIAN_FS
#include <ufs/ufs/ufs_byte_order.h>
#include <architecture/byte_order.h>
#endif /* REV_ENDIAN_FS */


static int ufs_chmod(struct vnode *, int, kauth_cred_t, struct proc *);
static int ufs_chown(struct vnode *, uid_t, gid_t, kauth_cred_t,
		struct proc *);
static int filt_ufsread(struct knote *kn, long hint);
static int filt_ufswrite(struct knote *kn, long hint);
static int filt_ufsvnode(struct knote *kn, long hint);
static void filt_ufsdetach(struct knote *kn);

#if FIFO
extern void fifo_printinfo(struct vnode *vp);
#endif /* FIFO */
extern int ufs_direnter2(struct vnode *dvp, struct direct *dirp, 
				  vfs_context_t ctx);

static int ufs_readdirext(vnode_t vp, uio_t uio, int *eofflag, int *numdirent,
                          vfs_context_t context);

/*
 * Create a regular file
 */
int
ufs_create(ap)
	struct vnop_create_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	int error;

	if ( (error = ufs_makeinode(ap->a_vap, ap->a_dvp, ap->a_vpp, ap->a_cnp)) )
		return (error);
	VN_KNOTE(ap->a_dvp, NOTE_WRITE);
	return (0);
}

/*
 * Mknod vnode call
 */
int
ufs_mknod(ap)
	struct vnop_mknod_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode_attr *vap = ap->a_vap;
	struct vnode **vpp = ap->a_vpp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *tvp;
	struct inode *ip;
	struct componentname *cnp = ap->a_cnp;
	int error;

	/* use relookup to force correct directory hints */
	cnp->cn_flags &= ~MODMASK;
	cnp->cn_flags |= (WANTPARENT | NOCACHE);
	cnp->cn_nameiop = CREATE;

	(void) relookup(dvp, &tvp, cnp);

	/* get rid of reference relookup returned */
	if (tvp)
		vnode_put(tvp);

	if ( (error =
	      ufs_makeinode(ap->a_vap, ap->a_dvp, vpp, ap->a_cnp)) )
		return (error);
	VN_KNOTE(ap->a_dvp, NOTE_WRITE);
	ip = VTOI(*vpp);
	ip->i_flag |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
	if (vap->va_rdev != VNOVAL) {
		/*
		 * Want to be able to use this to make badblock
		 * inodes, so don't truncate the dev number.
		 */
		ip->i_rdev = vap->va_rdev;
	}
	return (0);
}

/*
 * Open called.
 *
 * Nothing to do.
 */
int
ufs_open(ap)
	struct vnop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		vfs_context_t a_context;
	} */ *ap;
{

	/*
	 * Files marked append-only must be opened for appending.
	 */
	if ((VTOI(ap->a_vp)->i_flags & APPEND) &&
	    (ap->a_mode & (FWRITE | O_APPEND)) == FWRITE)
		return (EPERM);
	return (0);
}

/*
 * Close called.
 *
 * Update the times on the inode.
 */
int
ufs_close(ap)
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct inode *ip = VTOI(vp);
	struct timeval tv;

	if (vnode_isinuse(vp, 1)) {
		microtime(&tv);
		ITIMES(ip, &tv, &tv);
	}

	cluster_push(vp, IO_CLOSE);

	return (0);
}

int
ufs_getattr(ap)
 	struct vnop_getattr_args /* {
		struct vnode *a_vp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct inode *ip = VTOI(vp);
 	register struct vnode_attr *vap = ap->a_vap;
	int devBlockSize=0;
	struct timeval tv;

	microtime(&tv);
  
	ITIMES(ip, &tv, &tv);
	/*
	 * Copy from inode table
	 */
 	VATTR_RETURN(vap, va_fsid, ip->i_dev);
 	VATTR_RETURN(vap, va_fileid, ip->i_number);
 	VATTR_RETURN(vap, va_mode, ip->i_mode & ~IFMT);
 	VATTR_RETURN(vap, va_nlink, ip->i_nlink);
 	VATTR_RETURN(vap, va_uid, ip->i_uid);
 	VATTR_RETURN(vap, va_gid, ip->i_gid);
 	VATTR_RETURN(vap, va_rdev, (dev_t)ip->i_rdev);
 	VATTR_RETURN(vap, va_data_size, ip->i_din.di_size);
 	vap->va_access_time.tv_sec = ip->i_atime;
 	vap->va_access_time.tv_nsec = ip->i_atimensec;
 	VATTR_SET_SUPPORTED(vap, va_access_time);
 	vap->va_modify_time.tv_sec = ip->i_mtime;
 	vap->va_modify_time.tv_nsec = ip->i_mtimensec;
 	VATTR_SET_SUPPORTED(vap, va_modify_time);
 	vap->va_change_time.tv_sec = ip->i_ctime;
 	vap->va_change_time.tv_nsec = ip->i_ctimensec;
 	VATTR_SET_SUPPORTED(vap, va_change_time);
 	VATTR_RETURN(vap, va_flags, ip->i_flags);
 	VATTR_RETURN(vap, va_gen, ip->i_gen);
	if (vp->v_type == VBLK)
 		VATTR_RETURN(vap, va_iosize, BLKDEV_IOSIZE);
	else if (vp->v_type == VCHR)
 		VATTR_RETURN(vap, va_iosize, MAXPHYSIO);
	else
 		VATTR_RETURN(vap, va_iosize, vp->v_mount->mnt_vfsstat.f_iosize);
	devBlockSize = vfs_devblocksize(vnode_mount(vp));
 	VATTR_RETURN(vap, va_data_alloc, dbtob((u_quad_t)ip->i_blocks, devBlockSize));
 	VATTR_RETURN(vap, va_type, vp->v_type);
 	VATTR_RETURN(vap, va_filerev, ip->i_modrev);
	return (0);
}

/*
 * Set attribute vnode op. called from several syscalls
 */
int
ufs_setattr(ap)
	struct vnop_setattr_args /* {
		struct vnode *a_vp;
		struct vnode_attr *a_vap;
		struct proc *a_p;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode_attr *vap = ap->a_vap;
	struct vnode *vp = ap->a_vp;
	struct inode *ip = VTOI(vp);
	kauth_cred_t cred = vfs_context_ucred(ap->a_context);
	struct proc *p = vfs_context_proc(ap->a_context);
	struct timeval atimeval, mtimeval;
	int error;
	uid_t nuid;
	gid_t ngid;

	/*
	 * Go through the fields and update iff set.
	 */
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		ip->i_flags = vap->va_flags;
		ip->i_flag |= IN_CHANGE;
	}
	VATTR_SET_SUPPORTED(vap, va_flags);

	nuid = VATTR_IS_ACTIVE(vap, va_uid) ? vap->va_uid : (uid_t)VNOVAL;
	ngid = VATTR_IS_ACTIVE(vap, va_gid) ? vap->va_gid : (gid_t)VNOVAL;
	if (nuid != (uid_t)VNOVAL || ngid != (gid_t)VNOVAL) {
		if ( (error = ufs_chown(vp, nuid, ngid, cred, p)) )
			return (error);
	}
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);

	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		if ( (error = ffs_truncate_internal(vp, vap->va_data_size, vap->va_vaflags & 0xffff, cred)) )
			return (error);
	}
	VATTR_SET_SUPPORTED(vap, va_data_size);
	
	ip = VTOI(vp);
	if (VATTR_IS_ACTIVE(vap, va_access_time) || VATTR_IS_ACTIVE(vap, va_modify_time)) {
		if (VATTR_IS_ACTIVE(vap, va_access_time))
			ip->i_flag |= IN_ACCESS;
		if (VATTR_IS_ACTIVE(vap, va_modify_time))
			ip->i_flag |= IN_CHANGE | IN_UPDATE;
		atimeval.tv_sec = vap->va_access_time.tv_sec;
		atimeval.tv_usec = vap->va_access_time.tv_nsec / 1000;
		mtimeval.tv_sec = vap->va_modify_time.tv_sec;
		mtimeval.tv_usec = vap->va_modify_time.tv_nsec / 1000;
		if ( (error = ffs_update(vp, &atimeval, &mtimeval, 1)) )
			return (error);
	}
	VATTR_SET_SUPPORTED(vap, va_access_time);
	VATTR_SET_SUPPORTED(vap, va_modify_time);
	
	if (VATTR_IS_ACTIVE(vap, va_mode)) {
		if ((error = ufs_chmod(vp, (int)vap->va_mode, cred, p)))
			return (error);
	}
	VATTR_SET_SUPPORTED(vap, va_mode);
	
	VN_KNOTE(vp, NOTE_ATTRIB);

	return (0);
}

/*
 * Change the mode on a file.
 * Inode must be locked before calling.
 */
static int
ufs_chmod(struct vnode *vp, int mode, kauth_cred_t cred, struct proc *p)
{
	register struct inode *ip = VTOI(vp);

	ip->i_mode &= ~ALLPERMS;
	ip->i_mode |= (mode & ALLPERMS);
	ip->i_flag |= IN_CHANGE;
	return (0);
}

/*
 * Perform chown operation on inode ip;
 * inode must be locked prior to call.
 */
static int
ufs_chown(struct vnode *vp, uid_t uid, gid_t gid, kauth_cred_t cred,
	struct proc *p)
{
	register struct inode *ip = VTOI(vp);
	uid_t ouid;
	gid_t ogid;
	int error = 0;
	int is_member;
#if QUOTA
	register int i;
	int64_t change;   /* in bytes */
	int devBlockSize=0;
#endif /* QUOTA */

	if (uid == (uid_t)VNOVAL)
		uid = ip->i_uid;
	if (gid == (gid_t)VNOVAL)
		gid = ip->i_gid;
	ogid = ip->i_gid;
	ouid = ip->i_uid;
#if QUOTA
	if ( (error = getinoquota(ip)) )
		return (error);
	if (ouid == uid) {
		dqrele(ip->i_dquot[USRQUOTA]);
		ip->i_dquot[USRQUOTA] = NODQUOT;
	}
	if (ogid == gid) {
		dqrele(ip->i_dquot[GRPQUOTA]);
		ip->i_dquot[GRPQUOTA] = NODQUOT;
	}
	devBlockSize = vfs_devblocksize(vnode_mount(vp));

	change = dbtob((int64_t)ip->i_blocks, devBlockSize);
	(void) chkdq(ip, -change, cred, CHOWN);
	(void) chkiq(ip, -1, cred, CHOWN);
	for (i = 0; i < MAXQUOTAS; i++) {
		dqrele(ip->i_dquot[i]);
		ip->i_dquot[i] = NODQUOT;
	}
#endif
	ip->i_gid = gid;
	ip->i_uid = uid;
#if QUOTA
	if ((error = getinoquota(ip)) == 0) {
		if (ouid == uid) {
			dqrele(ip->i_dquot[USRQUOTA]);
			ip->i_dquot[USRQUOTA] = NODQUOT;
		}
		if (ogid == gid) {
			dqrele(ip->i_dquot[GRPQUOTA]);
			ip->i_dquot[GRPQUOTA] = NODQUOT;
		}
		if ((error = chkdq(ip, change, cred, CHOWN)) == 0) {
			if ((error = chkiq(ip, 1, cred, CHOWN)) == 0)
				goto good;
			else
				(void) chkdq(ip, -change, cred, CHOWN|FORCE);
		}
		for (i = 0; i < MAXQUOTAS; i++) {
			dqrele(ip->i_dquot[i]);
			ip->i_dquot[i] = NODQUOT;
		}
	}
	ip->i_gid = ogid;
	ip->i_uid = ouid;
	if (getinoquota(ip) == 0) {
		if (ouid == uid) {
			dqrele(ip->i_dquot[USRQUOTA]);
			ip->i_dquot[USRQUOTA] = NODQUOT;
		}
		if (ogid == gid) {
			dqrele(ip->i_dquot[GRPQUOTA]);
			ip->i_dquot[GRPQUOTA] = NODQUOT;
		}
		(void) chkdq(ip, change, cred, FORCE|CHOWN);
		(void) chkiq(ip, 1, cred, FORCE|CHOWN);
		(void) getinoquota(ip);
	}
	return (error);
good:
	if (getinoquota(ip))
		panic("chown: lost quota");
#endif /* QUOTA */
	if (ouid != uid || ogid != gid)
		ip->i_flag |= IN_CHANGE;
	return (0);
}

int
ufs_ioctl(ap)
	struct vnop_ioctl_args /* {
		struct vnode *a_vp;
		int  a_command;
		caddr_t  a_data;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{

        switch (ap->a_command) {
	
	case 1:
	{       register struct inode *ip;
	        register struct vnode *vp;
		register struct fs *fs;
		register struct radvisory *ra;
		int devBlockSize = 0;
		int error;

		vp = ap->a_vp;

		ra = (struct radvisory *)(ap->a_data);
		ip = VTOI(vp);
		fs = ip->i_fs;

		if ((u_int64_t)ra->ra_offset >= ip->i_size) {
			return (EFBIG);
		}
		devBlockSize = vfs_devblocksize(vnode_mount(vp));

		error = advisory_read(vp, ip->i_size, ra->ra_offset, ra->ra_count);

		return (error);
	}
	default:
	        return (ENOTTY);
	}
}

int
ufs_select(__unused struct vnop_select_args *ap)
{
	/*
	 * We should really check to see if I/O is possible.
	 */
	return (1);
}

/*
 * Mmap a file
 *
 * NB Currently unsupported.
 */
int
ufs_mmap(__unused struct vnop_mmap_args *ap)
{
	return (EINVAL);
}

int
ufs_remove(ap)
	struct vnop_remove_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
		int *a_flags;
		vfs_context_t a_context;
	} */ *ap;
{
        return(ufs_remove_internal(ap->a_dvp, ap->a_vp, ap->a_cnp, ap->a_flags));
}


int
ufs_remove_internal(vnode_t dvp, vnode_t vp, struct componentname *cnp, int flags)
{
	struct inode *ip;
	struct vnode *tvp;
	int error;

	if (flags & VNODE_REMOVE_NODELETEBUSY) {
		/* Caller requested Carbon delete semantics */
		if (vnode_isinuse(vp, 0)) {
			error = EBUSY;
			goto out;
		}
	}
	cnp->cn_flags &= ~MODMASK;
	cnp->cn_flags |= (WANTPARENT | NOCACHE);
	cnp->cn_nameiop = DELETE;

	(void) relookup(dvp, &tvp, cnp);

	if (tvp == NULL)
	        return (ENOENT);
	if (tvp != vp)
	        panic("ufs_remove_internal: relookup returned a different vp");
	/*
	 * get rid of reference relookup returned
	 */
	vnode_put(tvp);


	ip = VTOI(vp);

	if ((error = ufs_dirremove(dvp, cnp)) == 0) {
		ip->i_nlink--;
		ip->i_flag |= IN_CHANGE;
		VN_KNOTE(vp, NOTE_DELETE);
		VN_KNOTE(dvp, NOTE_WRITE);
	}
out:
	return (error);
}

/*
 * link vnode call
 */
int
ufs_link(ap)
	struct vnop_link_args /* {
		struct vnode *a_vp;
		struct vnode *a_tdvp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct vnode *tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	vfs_context_t ctx = cnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	struct inode *ip;
	struct timeval tv;
	int error;

	ip = VTOI(vp);

	if ((nlink_t)ip->i_nlink >= LINK_MAX) {
		error = EMLINK;
		goto out1;
	}
	ip->i_nlink++;
	ip->i_flag |= IN_CHANGE;
	microtime(&tv);
	error = ffs_update(vp, &tv, &tv, 1);
	if (!error)
		error = ufs_direnter(ip, tdvp, cnp);
	if (error) {
		ip->i_nlink--;
		ip->i_flag |= IN_CHANGE;
	}
	VN_KNOTE(vp, NOTE_LINK);
	VN_KNOTE(tdvp, NOTE_WRITE);
out1:
	return (error);
}

/*
 * whiteout vnode call
 */

int
ufs_whiteout(ap)
	struct vnop_whiteout_args /* {
		struct vnode *a_dvp;
		struct componentname *a_cnp;
		int a_flags;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	struct direct newdir;
	int error = 0;

	switch (ap->a_flags) {
	case LOOKUP:
		/* 4.4 format directories support whiteout operations */
		if (dvp->v_mount->mnt_maxsymlinklen > 0)
			return (0);
		return (ENOTSUP);

	case CREATE:
		/* create a new directory whiteout */
#if DIAGNOSTIC
		if (dvp->v_mount->mnt_maxsymlinklen <= 0)
			panic("ufs_whiteout: old format filesystem");
#endif

		newdir.d_ino = WINO;
		newdir.d_namlen = cnp->cn_namelen;
		bcopy(cnp->cn_nameptr, newdir.d_name, (unsigned)cnp->cn_namelen + 1);
		newdir.d_type = DT_WHT;
		error = ufs_direnter2(dvp, &newdir, cnp->cn_context);
		break;

	case DELETE:
		/* remove an existing directory whiteout */
#if DIAGNOSTIC
		if (dvp->v_mount->mnt_maxsymlinklen <= 0)
			panic("ufs_whiteout: old format filesystem");
#endif

		cnp->cn_flags &= ~DOWHITEOUT;
		error = ufs_dirremove(dvp, cnp);
		break;
	}
	return (error);
}


/*
 * Rename system call.
 * 	rename("foo", "bar");
 * is essentially
 *	unlink("bar");
 *	link("foo", "bar");
 *	unlink("foo");
 * but ``atomically''.  Can't do full commit without saving state in the
 * inode on disk which isn't feasible at this time.  Best we can do is
 * always guarantee the target exists.
 *
 * Basic algorithm is:
 *
 * 1) Bump link count on source while we're linking it to the
 *    target.  This also ensure the inode won't be deleted out
 *    from underneath us while we work (it may be truncated by
 *    a concurrent `trunc' or `open' for creation).
 * 2) Link source to destination.  If destination already exists,
 *    delete it first.
 * 3) Unlink source reference to inode if still around. If a
 *    directory was moved and the parent of the destination
 *    is different from the source, patch the ".." entry in the
 *    directory.
 */
int
ufs_rename(ap)
	struct vnop_rename_args  /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *tvp = ap->a_tvp;
	register struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *fdvp = ap->a_fdvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	vfs_context_t ctx = fcnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	struct inode *ip, *xp, *dp;
	struct dirtemplate dirbuf;
	struct timeval tv;
	ino_t doingdirectory = 0, oldparent = 0, newparent = 0;
	int error = 0, ioflag;
	u_char namlen;
	struct vnode *rl_vp = NULL;


	/*
	 * Check if just deleting a link name or if we've lost a race.
	 * If another process completes the same rename after we've looked
	 * up the source and have blocked looking up the target, then the
	 * source and target inodes may be identical now although the
	 * names were never linked.
	 */
	if (fvp == tvp) {
		if (fvp->v_type == VDIR) {
			/*
			 * Linked directories are impossible, so we must
			 * have lost the race.  Pretend that the rename
			 * completed before the lookup.
			 */
#ifdef UFS_RENAME_DEBUG
			printf("ufs_rename: fvp == tvp for directories\n");
#endif
			error = ENOENT;
			goto abortit;
		}

		/*
		 * don't need to check in here for permissions, must already have been granted
		 * ufs_remove_internal now does the relookup
		 */
		error = ufs_remove_internal(fdvp, fvp, fcnp, 0);

		return (error);
	}
	/*
	 * because the vnode_authorization code may have looked up in this directory
	 * between the original lookup and the actual call to VNOP_RENAME, we need
	 * to reset the directory hints... since we haven't dropped the FSNODELOCK
	 * on tdvp since this whole thing started, we expect relookup to return
	 * tvp (which may be NULL)
	 */
	tcnp->cn_flags &= ~MODMASK;
	tcnp->cn_flags |= (WANTPARENT | NOCACHE);

	if ( (error = relookup(tdvp, &rl_vp, tcnp)) )
	        panic("ufs_rename: relookup on target returned error");
	if (rl_vp != tvp) {
	        /*
		 * Don't panic. The only way this state will be reached is if
		 * another rename has taken effect. In that case, it's safe
		 * to restart this rename and let things sort themselves out.
		 */
		if (rl_vp)
			vnode_put(rl_vp);
		error = ERESTART;
		goto abortit;
	}
	if (rl_vp) {
	        vnode_put(rl_vp);
		rl_vp = NULL;
	}
	dp = VTOI(fdvp);
	ip = VTOI(fvp);

	if ((ip->i_mode & IFMT) == IFDIR) {
		if (ip->i_flag & IN_RENAME) {
			error = EINVAL;
			goto abortit;
		}
		ip->i_flag |= IN_RENAME;
		oldparent = dp->i_number;
		doingdirectory++;
	}
	VN_KNOTE(fdvp, NOTE_WRITE);		/* XXX right place? */

	/*
	 * When the target exists, both the directory
	 * and target vnodes are returned locked.
	 */
	dp = VTOI(tdvp);
	xp = NULL;
	if (tvp)
		xp = VTOI(tvp);

	/*
	 * 1) Bump link count while we're moving stuff
	 *    around.  If we crash somewhere before
	 *    completing our work, the link count
	 *    may be wrong, but correctable.
	 */
	ip->i_nlink++;
	ip->i_flag |= IN_CHANGE;
	microtime(&tv);
	if ( (error = ffs_update(fvp, &tv, &tv, 1)) ) {
		goto bad;
	}

	/*
	 * If ".." must be changed (ie the directory gets a new
	 * parent) then the source directory must not be in the
	 * directory heirarchy above the target, as this would
	 * orphan everything below the source directory. Also
	 * the user must have write permission in the source so
	 * as to be able to change "..". We must repeat the call 
	 * to namei, as the parent directory is unlocked by the
	 * call to checkpath().
	 */

	if (oldparent != dp->i_number)
		newparent = dp->i_number;

	if (doingdirectory && newparent) {
		if (error)	/* write access check above */
			goto bad;

		if ( (error = ufs_checkpath(ip, dp, vfs_context_ucred(tcnp->cn_context))) )
			goto bad;

		if ( (error = relookup(tdvp, &tvp, tcnp)) )
			goto bad;
		rl_vp = tvp;

		dp = VTOI(tdvp);
		if (tvp)
			xp = VTOI(tvp);
		else
		        xp = NULL;
	}
	/*
	 * 2) If target doesn't exist, link the target
	 *    to the source and unlink the source. 
	 *    Otherwise, rewrite the target directory
	 *    entry to reference the source inode and
	 *    expunge the original entry's existence.
	 */
	if (xp == NULL) {
		if (dp->i_dev != ip->i_dev)
			panic("rename: EXDEV");
		/*
		 * Account for ".." in new directory.
		 * When source and destination have the same
		 * parent we don't fool with the link count.
		 */
		if (doingdirectory && newparent) {
			if ((nlink_t)dp->i_nlink >= LINK_MAX) {
				error = EMLINK;
				goto bad;
			}
			dp->i_nlink++;
			dp->i_flag |= IN_CHANGE;
			if ( (error = ffs_update(tdvp, &tv, &tv, 1)) )
				goto bad;
		}
		if ( (error = ufs_direnter(ip, tdvp, tcnp)) ) {
			if (doingdirectory && newparent) {
				dp->i_nlink--;
				dp->i_flag |= IN_CHANGE;
				(void)ffs_update(tdvp, &tv, &tv, 1);
			}
			goto bad;
		}
		VN_KNOTE(tdvp, NOTE_WRITE);
	} else {
		if (xp->i_dev != dp->i_dev || xp->i_dev != ip->i_dev)
			panic("rename: EXDEV");
		/*
		 * Short circuit rename(foo, foo).
		 */
		if (xp->i_number == ip->i_number)
			panic("rename: same file");
		/*
		 * Target must be empty if a directory and have no links
		 * to it. Also, ensure source and target are compatible
		 * (both directories, or both not directories).
		 */
		if ((xp->i_mode&IFMT) == IFDIR) {
			if (!ufs_dirempty(xp, dp->i_number, vfs_context_ucred(tcnp->cn_context)) || 
			    xp->i_nlink > 2) {
				error = ENOTEMPTY;
				goto bad;
			}
			if (!doingdirectory) {
				error = ENOTDIR;
				goto bad;
			}
			cache_purge(tdvp);
		} else if (doingdirectory) {
			error = EISDIR;
			goto bad;
		}
		if ( (error = ufs_dirrewrite(dp, ip, tcnp)) )
			goto bad;
		/*
		 * If the target directory is in the same
		 * directory as the source directory,
		 * decrement the link count on the parent
		 * of the target directory.
		 */
		 if (doingdirectory && !newparent) {
			dp->i_nlink--;
			dp->i_flag |= IN_CHANGE;
		}
		VN_KNOTE(tdvp, NOTE_WRITE);
		/*
		 * Adjust the link count of the target to
		 * reflect the dirrewrite above.  If this is
		 * a directory it is empty and there are
		 * no links to it, so we can squash the inode and
		 * any space associated with it.  We disallowed
		 * renaming over top of a directory with links to
		 * it above, as the remaining link would point to
		 * a directory without "." or ".." entries.
		 */
		xp->i_nlink--;
		if (doingdirectory) {
			if (--xp->i_nlink != 0)
				panic("rename: linked directory");
			ioflag = ((tvp)->v_mount->mnt_flag & MNT_ASYNC) ?
			    0 : IO_SYNC;
			error = ffs_truncate_internal(tvp, (off_t)0, ioflag, vfs_context_ucred(tcnp->cn_context));
		}
		xp->i_flag |= IN_CHANGE;
		VN_KNOTE(tvp, NOTE_DELETE);
		xp = NULL;
	}
	if (rl_vp)
	        vnode_put(rl_vp);
	rl_vp = NULL;
	
	/*
	 * 3) Unlink the source.
	 */
	fcnp->cn_flags &= ~MODMASK;
	fcnp->cn_flags |= (WANTPARENT | NOCACHE);

	(void) relookup(fdvp, &fvp, fcnp);

	if (fvp != NULL) {
		xp = VTOI(fvp);
		dp = VTOI(fdvp);
		rl_vp = fvp;
	} else {
		/*
		 * From name has disappeared.
		 */
		if (doingdirectory)
			panic("rename: lost dir entry");

		return (0);
	}
	/*
	 * Ensure that the directory entry still exists and has not
	 * changed while the new name has been entered. If the source is
	 * a file then the entry may have been unlinked or renamed. In
	 * either case there is no further work to be done. If the source
	 * is a directory then it cannot have been rmdir'ed; its link
	 * count of three would cause a rmdir to fail with ENOTEMPTY.
	 * The IN_RENAME flag ensures that it cannot be moved by another
	 * rename.
	 */
	if (xp != ip) {
		if (doingdirectory)
			panic("rename: lost dir entry");
	} else {
		/*
		 * If the source is a directory with a
		 * new parent, the link count of the old
		 * parent directory must be decremented
		 * and ".." set to point to the new parent.
		 */
		if (doingdirectory && newparent) {
			dp->i_nlink--;
			dp->i_flag |= IN_CHANGE;
			error = vn_rdwr(UIO_READ, fvp, (caddr_t)&dirbuf,
				sizeof (struct dirtemplate), (off_t)0,
				UIO_SYSSPACE32, IO_NODELOCKED, 
				vfs_context_ucred(tcnp->cn_context), (int *)0, (struct proc *)0);
			if (error == 0) {
#				if (BYTE_ORDER == LITTLE_ENDIAN)
					if (fvp->v_mount->mnt_maxsymlinklen <= 0)
						namlen = dirbuf.dotdot_type;
					else
						namlen = dirbuf.dotdot_namlen;
#				else
					namlen = dirbuf.dotdot_namlen;
#				endif
				if (namlen != 2 ||
				    dirbuf.dotdot_name[0] != '.' ||
				    dirbuf.dotdot_name[1] != '.') {
					ufs_dirbad(xp, (doff_t)12,
					    "rename: mangled dir");
				} else {
					dirbuf.dotdot_ino = newparent;
					(void) vn_rdwr(UIO_WRITE, fvp,
					    (caddr_t)&dirbuf,
					    sizeof (struct dirtemplate),
					    (off_t)0, UIO_SYSSPACE32,
					    IO_NODELOCKED|IO_SYNC,
					    vfs_context_ucred(tcnp->cn_context), (int *)0,
					    (struct proc *)0);
					cache_purge(fdvp);
				}
			}
		}
		error = ufs_dirremove(fdvp, fcnp);
		if (!error) {
			xp->i_nlink--;
			xp->i_flag |= IN_CHANGE;
		}
		xp->i_flag &= ~IN_RENAME;
	}
	VN_KNOTE(fvp, NOTE_RENAME);

	if (rl_vp)
	        vnode_put(rl_vp);

	return (error);

bad:
	if (rl_vp)
	        vnode_put(rl_vp);

	if (doingdirectory)
		ip->i_flag &= ~IN_RENAME;

	ip->i_nlink--;
	ip->i_flag |= IN_CHANGE;
	ip->i_flag &= ~IN_RENAME;

abortit:
	return (error);
}

/*
 * A virgin directory (no blushing please).
 */
static struct dirtemplate mastertemplate = {
	0, 12, DT_DIR, 1, ".",
	0, DIRBLKSIZ - 12, DT_DIR, 2, ".."
};
static struct odirtemplate omastertemplate = {
	0, 12, 1, ".",
	0, DIRBLKSIZ - 12, 2, ".."
};

/*
 * Mkdir system call
 */
int
ufs_mkdir(ap)
	struct vnop_mkdir_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *dvp = ap->a_dvp;
	register struct vnode_attr *vap = ap->a_vap;
	register struct componentname *cnp = ap->a_cnp;
	register struct inode *ip, *dp;
	struct vnode *tvp;
	struct dirtemplate dirtemplate, *dtp;
	struct timeval tv;
	int error, dmode;

	/* use relookup to force correct directory hints */
	cnp->cn_flags &= ~MODMASK;
	cnp->cn_flags |= (WANTPARENT | NOCACHE);
	cnp->cn_nameiop = CREATE;

	(void) relookup(dvp, &tvp, cnp);

	/* get rid of reference relookup returned */
	if (tvp)
		vnode_put(tvp);

	dp = VTOI(dvp);
	if ((nlink_t)dp->i_nlink >= LINK_MAX) {
		error = EMLINK;
		goto out;
	}
	dmode = vap->va_mode & 0777;
	dmode |= IFDIR;

	/*
	 * Must simulate part of ufs_makeinode here to acquire the inode,
	 * but not have it entered in the parent directory. The entry is
	 * made later after writing "." and ".." entries.
	 */
	if ( (error = ffs_valloc(dvp, (mode_t)dmode, vfs_context_ucred(cnp->cn_context), &tvp)) )
		goto out;
	ip = VTOI(tvp);
	ip->i_uid = ap->a_vap->va_uid;
	ip->i_gid = ap->a_vap->va_gid;
	VATTR_SET_SUPPORTED(ap->a_vap, va_mode);
	VATTR_SET_SUPPORTED(ap->a_vap, va_uid);
	VATTR_SET_SUPPORTED(ap->a_vap, va_gid);
#if QUOTA
	if ((error = getinoquota(ip)) ||
	    (error = chkiq(ip, 1, vfs_context_ucred(cnp->cn_context), 0))) {
		ffs_vfree(tvp, ip->i_number, dmode);
		vnode_put(tvp);
		return (error);
	}
#endif
	ip->i_flag |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
	ip->i_mode = dmode;
	ip->i_nlink = 2;
	if (cnp->cn_flags & ISWHITEOUT)
		ip->i_flags |= UF_OPAQUE;
	microtime(&tv);
	error = ffs_update(tvp, &tv, &tv, 1);

	/*
	 * Bump link count in parent directory
	 * to reflect work done below.  Should
	 * be done before reference is created
	 * so reparation is possible if we crash.
	 */
	dp->i_nlink++;
	dp->i_flag |= IN_CHANGE;
	if ( (error = ffs_update(dvp, &tv, &tv, 1)) )
		goto bad;

	/* Initialize directory with "." and ".." from static template. */
	if (dvp->v_mount->mnt_maxsymlinklen > 0)
		dtp = &mastertemplate;
	else
		dtp = (struct dirtemplate *)&omastertemplate;
	dirtemplate = *dtp;
	dirtemplate.dot_ino = ip->i_number;
	dirtemplate.dotdot_ino = dp->i_number;
	error = vn_rdwr(UIO_WRITE, tvp, (caddr_t)&dirtemplate,
	    sizeof (dirtemplate), (off_t)0, UIO_SYSSPACE32,
	    IO_NODELOCKED|IO_SYNC, vfs_context_ucred(cnp->cn_context), (int *)0, (struct proc *)0);
	if (error) {
		dp->i_nlink--;
		dp->i_flag |= IN_CHANGE;
		goto bad;
	}
	if (DIRBLKSIZ > VFSTOUFS(dvp->v_mount)->um_mountp->mnt_vfsstat.f_bsize)
		panic("ufs_mkdir: blksize"); /* XXX should grow with balloc() */
	else {
		ip->i_size = DIRBLKSIZ;
		ip->i_flag |= IN_CHANGE;
	}

	/* Directory set up, now install it's entry in the parent directory. */
	if ( (error = ufs_direnter(ip, dvp, cnp)) ) {
		dp->i_nlink--;
		dp->i_flag |= IN_CHANGE;
	}
bad:
	/*
	 * No need to do an explicit vnop_truncate here, vnode_put will do it
	 * for us because we set the link count to 0.
	 */
	if (error) {
		ip->i_nlink = 0;
		ip->i_flag |= IN_CHANGE;
		/*
		 * since we're not returning tvp due to the error,
		 * we're responsible for releasing it here
		 */
		vnode_put(tvp);
	} else {
		VN_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);
		*ap->a_vpp = tvp;
	};
out:
	return (error);
}

/*
 * Rmdir system call.
 */
int
ufs_rmdir(ap)
	struct vnop_rmdir_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *tvp;
	struct componentname *cnp = ap->a_cnp;
	struct inode *ip, *dp;
	int error, ioflag;


	ip = VTOI(vp);
	dp = VTOI(dvp);
	/*
	 * No rmdir "." please.
	 */
	if (dp == ip)
		return (EINVAL);


	cnp->cn_flags &= ~MODMASK;
	cnp->cn_flags |= (WANTPARENT | NOCACHE);

	(void) relookup(dvp, &tvp, cnp);

	if (tvp == NULL)
	        return (ENOENT);
	if (tvp != vp)
	        panic("ufs_rmdir: relookup returned a different vp");
	/*
	 * get rid of reference relookup returned
	 */
	vnode_put(tvp);


	/*
	 * Verify the directory is empty (and valid).
	 * (Rmdir ".." won't be valid since
	 *  ".." will contain a reference to
	 *  the current directory and thus be
	 *  non-empty.)
	 */
	error = 0;
	if (ip->i_nlink != 2 ||
	    !ufs_dirempty(ip, dp->i_number, vfs_context_ucred(cnp->cn_context))) {
		error = ENOTEMPTY;
		goto out;
	}
	/*
	 * Delete reference to directory before purging
	 * inode.  If we crash in between, the directory
	 * will be reattached to lost+found,
	 */
	if ( (error = ufs_dirremove(dvp, cnp)) )
		goto out;
	VN_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);
	dp->i_nlink--;
	dp->i_flag |= IN_CHANGE;
	cache_purge(dvp);
	/*
	 * Truncate inode.  The only stuff left
	 * in the directory is "." and "..".  The
	 * "." reference is inconsequential since
	 * we're quashing it.  The ".." reference
	 * has already been adjusted above.  We've
	 * removed the "." reference and the reference
	 * in the parent directory, but there may be
	 * other hard links so decrement by 2 and
	 * worry about them later.
	 */
	ip->i_nlink -= 2;
	ioflag = ((vp)->v_mount->mnt_flag & MNT_ASYNC) ? 0 : IO_SYNC;
	error = ffs_truncate_internal(vp, (off_t)0, ioflag, vfs_context_ucred(cnp->cn_context));
	cache_purge(ITOV(ip));
out:
	VN_KNOTE(vp, NOTE_DELETE);
	return (error);
}

/*
 * symlink -- make a symbolic link
 */
int
ufs_symlink(ap)
	struct vnop_symlink_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vnode_attr *a_vap;
		char *a_target;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp, **vpp = ap->a_vpp;
	register struct inode *ip;
	int len, error;

	if ( (error = ufs_makeinode(ap->a_vap, ap->a_dvp, vpp, ap->a_cnp)) )
		return (error);
	VN_KNOTE(ap->a_dvp, NOTE_WRITE);
	vp = *vpp;
	len = strlen(ap->a_target);
	if (len < vp->v_mount->mnt_maxsymlinklen) {
		ip = VTOI(vp);
		bcopy(ap->a_target, (char *)ip->i_shortlink, len);
		ip->i_size = len;
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
	} else
		error = vn_rdwr(UIO_WRITE, vp, ap->a_target, len, (off_t)0,
		    UIO_SYSSPACE32, IO_NODELOCKED, vfs_context_ucred(ap->a_cnp->cn_context), (int *)0,
		    (struct proc *)0);
	return (error);
}

/*
 * Vnode op for reading directories.
 * 
 * The routine below assumes that the on-disk format of a directory
 * is the same as that defined by <sys/dirent.h>. If the on-disk
 * format changes, then it will be necessary to do a conversion
 * from the on-disk format that read returns to the format defined
 * by <sys/dirent.h>.
 */
int
ufs_readdir(ap)
	struct vnop_readdir_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_flags;
		int *a_eofflag;
		int *a_numdirent;
		vfs_context_t a_context;
	} */ *ap;
{
	struct uio *uio = ap->a_uio;
	int error;
	size_t count, lost;

	if (ap->a_flags & VNODE_READDIR_EXTENDED) {
		return ufs_readdirext(ap->a_vp, uio, ap->a_eofflag,
		                      ap->a_numdirent, ap->a_context);
	}

	// LP64todo - fix this
	count = uio_resid(uio);
	/* Make sure we don't return partial entries. */
	count -= (uio->uio_offset + count) & (DIRBLKSIZ -1);
	if (count <= 0)
		return (EINVAL);
	// LP64todo - fix this
	lost = uio_resid(uio) - count;
	uio_setresid(uio, count);
	uio_iov_len_set(uio, count);
#	if (BYTE_ORDER == LITTLE_ENDIAN)
		if (ap->a_vp->v_mount->mnt_maxsymlinklen > 0) {
			error = ffs_read_internal(ap->a_vp, uio, 0);
		} else {
			struct dirent *dp, *edp;
			struct uio auio;
			struct iovec_32 aiov;
			caddr_t dirbuf;
			int readcnt;
			u_char tmp;

			auio = *uio;
			auio.uio_iovs.iov32p = &aiov;
			auio.uio_iovcnt = 1;
#if 1   /* LP64todo - can't use new segment flags until the drivers are ready */
			auio.uio_segflg = UIO_SYSSPACE;
#else
			auio.uio_segflg = UIO_SYSSPACE32;
#endif 
			aiov.iov_len = count;
			MALLOC(dirbuf, caddr_t, count, M_TEMP, M_WAITOK);
			aiov.iov_base = (uintptr_t)dirbuf;
			error = ffs_read_internal(ap->a_vp, &auio, 0);
			if (error == 0) {
				// LP64todo - fix this
				readcnt = count - uio_resid(&auio);
				edp = (struct dirent *)&dirbuf[readcnt];
				for (dp = (struct dirent *)dirbuf; dp < edp; ) {
					tmp = dp->d_namlen;
					dp->d_namlen = dp->d_type;
					dp->d_type = tmp;
					if (dp->d_reclen > 0) {
						dp = (struct dirent *)
						    ((char *)dp + dp->d_reclen);
					} else {
						error = EIO;
						break;
					}
				}
				if (dp >= edp)
					error = uiomove(dirbuf, readcnt, uio);
			}
			FREE(dirbuf, M_TEMP);
		}
#	else
		error = ffs_read_internal(ap->a_vp, uio, 0);
#	endif

	uio_setresid(uio, (uio_resid(uio) + lost));
	if (ap->a_eofflag)
		*ap->a_eofflag = (off_t)VTOI(ap->a_vp)->i_size <= uio->uio_offset;
	return (error);
}


/*
 *  ufs_readdirext reads directory entries into the buffer pointed
 *  to by uio, in a filesystem independent format.  Up to uio_resid
 *  bytes of data can be transferred.  The data in the buffer is a
 *  series of packed direntry structures where each one contains the
 *  following entries:
 *
 *	d_reclen:   length of record
 *	d_ino:      file number of entry
 *	d_seekoff:  seek offset (used by NFS server, aka cookie)
 *	d_type:     file type
 *	d_namlen:   length of string in d_name
 *	d_name:     null terminated file name
 *
 *  The current position (uio_offset) refers to the next block of
 *  entries.  The offset will only be set to a value previously
 *  returned by ufs_readdirext or zero.  This offset does not have
 *  to match the number of bytes returned (in uio_resid).
 */
#define EXT_DIRENT_LEN(namlen) \
	((sizeof(struct direntry) + (namlen) - (MAXPATHLEN-1) + 3) & ~3)

static int
ufs_readdirext(vnode_t vp, uio_t uio, int *eofflag, int *numdirent,
               __unused vfs_context_t context)
{
	int error;
	size_t count, lost;
	off_t off = uio->uio_offset;
	struct dirent *dp, *edp;
	struct uio auio;
	struct iovec_32 aiov;
	caddr_t dirbuf;
	struct direntry *xdp;
	int nentries = 0;

	// LP64todo - fix this
	count = uio_resid(uio);
	/* Make sure we don't return partial entries. */
	count -= (uio->uio_offset + count) & (DIRBLKSIZ -1);
	if (count <= 0)
		return (EINVAL);
	// LP64todo - fix this
	lost = uio_resid(uio) - count;
	uio_setresid(uio, count);
	uio_iov_len_set(uio, count);

	auio = *uio;
	auio.uio_iovs.iov32p = &aiov;
	auio.uio_iovcnt = 1;
	/* LP64todo - can't use new segment flags until the drivers are ready */
	auio.uio_segflg = UIO_SYSSPACE;
	aiov.iov_len = count;
	MALLOC(dirbuf, caddr_t, count, M_TEMP, M_WAITOK);
	aiov.iov_base = (uintptr_t)dirbuf;

	MALLOC(xdp, struct direntry *, sizeof(struct direntry), M_TEMP, M_WAITOK);

	error = ffs_read_internal(vp, &auio, 0);
	if (error)
		goto out;

	// LP64todo - fix this
	edp = (struct dirent *)&dirbuf[count - uio_resid(&auio)];
	for (dp = (struct dirent *)dirbuf; dp < edp; ) {

#if (BYTE_ORDER == LITTLE_ENDIAN)
		u_char tmp;

		tmp = dp->d_namlen;
		dp->d_namlen = dp->d_type;
		dp->d_type = tmp;
#endif
		xdp->d_reclen = EXT_DIRENT_LEN(dp->d_namlen);
		if (xdp->d_reclen > uio_resid(uio)) {
			break;  /* user buffer is full */
		}
		xdp->d_ino = dp->d_ino;
		xdp->d_namlen = dp->d_namlen;
		xdp->d_type = dp->d_type;
		bcopy(dp->d_name, xdp->d_name, dp->d_namlen + 1);
		off += dp->d_reclen;
		xdp->d_seekoff = off;
		error = uiomove((caddr_t)xdp, xdp->d_reclen, uio);
		if (error) {
			off -= dp->d_reclen;
			break;  /* unexpected this error is */
		}
		nentries++;

		if (dp->d_reclen > 0) {
			dp = (struct dirent *)
			    ((char *)dp + dp->d_reclen);
		} else {
			error = EIO;
			break;
		}
	}
out:
	FREE(dirbuf, M_TEMP);
	FREE(xdp, M_TEMP);

	/* Use the on-disk dirent offset */
	uio_setoffset(uio, off);
	*numdirent = nentries;
	uio_setresid(uio, (uio_resid(uio) + lost));
	if (eofflag)
		*eofflag = (off_t)VTOI(vp)->i_size <= uio->uio_offset;
	return (error);
}


/*
 * Return target name of a symbolic link
 */
int
ufs_readlink(ap)
	struct vnop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	register struct inode *ip = VTOI(vp);
	int isize;

	isize = ip->i_size;
	if (isize < vp->v_mount->mnt_maxsymlinklen) {
		uiomove((char *)ip->i_shortlink, isize, ap->a_uio);
		return (0);
	}
	return (ffs_read_internal(vp, ap->a_uio, 0));
}

/*
 * prepare and issue the I/O
 */
errno_t
ufs_strategy(ap)
	struct vnop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap;
{
	buf_t	bp = ap->a_bp;
	vnode_t	vp = buf_vnode(bp);
	struct inode *ip = VTOI(vp);

        return (buf_strategy(ip->i_devvp, ap));
}

/*
 * Read wrapper for special devices.
 */
int
ufsspec_read(ap)
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{

	/*
	 * Set access flag.
	 */
	VTOI(ap->a_vp)->i_flag |= IN_ACCESS;
	return (VOCALL (spec_vnodeop_p, VOFFSET(vnop_read), ap));
}

/*
 * Write wrapper for special devices.
 */
int
ufsspec_write(
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		kauth_cred_t a_cred;
	} */ *ap)
{

	/*
	 * Set update and change flags.
	 */
	VTOI(ap->a_vp)->i_flag |= IN_CHANGE | IN_UPDATE;
	return (VOCALL (spec_vnodeop_p, VOFFSET(vnop_write), ap));
}

/*
 * Close wrapper for special devices.
 *
 * Update the times on the inode then do device close.
 */
int
ufsspec_close(ap)
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct inode *ip = VTOI(vp);
	struct timeval tv;

	if (ap->a_vp->v_usecount > 1) {
		microtime(&tv);
		ITIMES(ip, &tv, &tv);
	}
	return (VOCALL (spec_vnodeop_p, VOFFSET(vnop_close), ap));
}

#if FIFO
/*
 * Read wrapper for fifo's
 */
int
ufsfifo_read(ap)
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	extern int (**fifo_vnodeop_p)(void *);

	/*
	 * Set access flag.
	 */
	VTOI(ap->a_vp)->i_flag |= IN_ACCESS;
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vnop_read), ap));
}

/*
 * Write wrapper for fifo's.
 */
int
ufsfifo_write(
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		kauth_cred_t a_cred;
	} */ *ap)
{
	extern int (**fifo_vnodeop_p)(void *);

	/*
	 * Set update and change flags.
	 */
	VTOI(ap->a_vp)->i_flag |= IN_CHANGE | IN_UPDATE;
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vnop_write), ap));
}

/*
 * Close wrapper for fifo's.
 *
 * Update the times on the inode then do device close.
 */
int
ufsfifo_close(ap)
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	extern int (**fifo_vnodeop_p)(void *);
	struct vnode *vp = ap->a_vp;
	struct inode *ip = VTOI(vp);
	struct timeval tv;

	if (ap->a_vp->v_usecount > 1) {
		microtime(&tv);
		ITIMES(ip, &tv, &tv);
	}
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vnop_close), ap));
}

/*
 * kqfilt_add wrapper for fifos.
 *
 * Fall through to ufs kqfilt_add routines if needed 
 */
int
ufsfifo_kqfilt_add(ap)
	struct vnop_kqfilt_add_args *ap;
{
	extern int (**fifo_vnodeop_p)(void *);
	int error;

	error = VOCALL(fifo_vnodeop_p, VOFFSET(vnop_kqfilt_add), ap);
	if (error)
		error = ufs_kqfilt_add(ap);
	return (error);
}

#if 0
/*
 * kqfilt_remove wrapper for fifos.
 *
 * Fall through to ufs kqfilt_remove routines if needed 
 */
int
ufsfifo_kqfilt_remove(ap)
	struct vnop_kqfilt_remove_args *ap;
{
	extern int (**fifo_vnodeop_p)(void *);
	int error;

	error = VOCALL(fifo_vnodeop_p, VOFFSET(vnop_kqfilt_remove), ap);
	if (error)
		error = ufs_kqfilt_remove(ap);
	return (error);
}
#endif

#endif /* FIFO */


static struct filterops ufsread_filtops = 
	{ 1, NULL, filt_ufsdetach, filt_ufsread };
static struct filterops ufswrite_filtops = 
	{ 1, NULL, filt_ufsdetach, filt_ufswrite };
static struct filterops ufsvnode_filtops = 
	{ 1, NULL, filt_ufsdetach, filt_ufsvnode };

/*
 #
 #% kqfilt_add	vp	L L L
 #
 vnop_kqfilt_add
	IN struct vnode *vp;
	IN struct knote *kn;
	IN vfs_context_t context;
 */
int
ufs_kqfilt_add(ap)
	struct vnop_kqfilt_add_args /* {
		struct vnode *a_vp;
		struct knote *a_kn;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct knote *kn = ap->a_kn;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &ufsread_filtops;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &ufswrite_filtops;
		break;
	case EVFILT_VNODE:
		kn->kn_fop = &ufsvnode_filtops;
		break;
	default:
		return (1);
	}

	kn->kn_hook = (caddr_t)vp;
	kn->kn_hookid = vnode_vid(vp);

	KNOTE_ATTACH(&VTOI(vp)->i_knotes, kn);

	return (0);
}

static void
filt_ufsdetach(struct knote *kn)
{
	struct vnode *vp;
	int result;
	struct proc *p = current_proc();
	
	vp = (struct vnode *)kn->kn_hook;

	if (vnode_getwithvid(vp, kn->kn_hookid))
		return;

	result = KNOTE_DETACH(&VTOI(vp)->i_knotes, kn);
	vnode_put(vp);
}

static int
filt_ufsread(struct knote *kn, long hint)
{
	struct vnode *vp = (struct vnode *)kn->kn_hook;
	struct inode *ip;
	int dropvp = 0;
	int result;

	if (hint == 0)  {
		if ((vnode_getwithvid(vp, kn->kn_hookid) != 0)) {
			hint = NOTE_REVOKE;
		} else 
			dropvp = 1;
	}
	if (hint == NOTE_REVOKE) {
		/*
		 * filesystem is gone, so set the EOF flag and schedule 
		 * the knote for deletion.
		 */
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}

	/* poll(2) semantics dictate always returning true */
	if (kn->kn_flags & EV_POLL) {
		kn->kn_data = 1;
		result = 1;
	} else {
		ip = VTOI(vp);
		kn->kn_data = ip->i_size - kn->kn_fp->f_fglob->fg_offset;
		result = (kn->kn_data != 0);
	}

	if  (dropvp)
		vnode_put(vp);

	return (result);
}

static int
filt_ufswrite(struct knote *kn, long hint)
{

	int dropvp = 0;
	
	if (hint == 0)  {
		if ((vnode_getwithvid(kn->kn_hook, kn->kn_hookid) != 0)) {
			hint = NOTE_REVOKE;
		} else 
			vnode_put(kn->kn_hook);
	}
	if (hint == NOTE_REVOKE) {
		/*
		 * filesystem is gone, so set the EOF flag and schedule 
		 * the knote for deletion.
		 */
		kn->kn_data = 0;
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}
	kn->kn_data = 0;
	return (1);
}

static int
filt_ufsvnode(struct knote *kn, long hint)
{

	if (hint == 0)  {
		if ((vnode_getwithvid(kn->kn_hook, kn->kn_hookid) != 0)) {
			hint = NOTE_REVOKE;
		} else
			vnode_put(kn->kn_hook);
	}
	if (kn->kn_sfflags & hint)
		kn->kn_fflags |= hint;
	if ((hint == NOTE_REVOKE)) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}
	
	return (kn->kn_fflags != 0);
}

/*
 * Return POSIX pathconf information applicable to ufs filesystems.
 */
int
ufs_pathconf(ap)
	struct vnop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		int *a_retval;
		vfs_context_t a_context;
	} */ *ap;
{

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = LINK_MAX;
		return (0);
	case _PC_NAME_MAX:
		*ap->a_retval = NAME_MAX;
		return (0);
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		return (0);
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		return (0);
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return (0);
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		return (0);
	default:
		return (EINVAL);
	}
	/* NOTREACHED */
}

/*
 * Allocate a new inode.
 */
int
ufs_makeinode(vap, dvp, vpp, cnp)
	struct vnode_attr *vap;
	struct vnode *dvp;
	struct vnode **vpp;
	struct componentname *cnp;
{
	register struct inode *ip, *pdir;
	struct timeval tv;
	struct vnode *tvp;
	int error;
	int is_member;
	int mode;
	
	mode = MAKEIMODE(vap->va_type, vap->va_mode);
	pdir = VTOI(dvp);
	*vpp = NULL;
	if ((mode & IFMT) == 0)
		mode |= IFREG;

	if ( (error = ffs_valloc(dvp, (mode_t)mode, vfs_context_ucred(cnp->cn_context), &tvp)) )
		return (error);

	ip = VTOI(tvp);
	ip->i_gid = vap->va_gid;
	ip->i_uid = vap->va_uid;
	VATTR_SET_SUPPORTED(vap, va_mode);
	VATTR_SET_SUPPORTED(vap, va_uid);
	VATTR_SET_SUPPORTED(vap, va_gid);
#if QUOTA
	if ((error = getinoquota(ip)) ||
	    (error = chkiq(ip, 1, vfs_context_ucred(cnp->cn_context), 0))) {
		ffs_vfree(tvp, ip->i_number, mode);
		vnode_put(tvp);
		return (error);
	}
#endif
	ip->i_flag |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
	ip->i_mode = mode;
	ip->i_nlink = 1;

	if (cnp->cn_flags & ISWHITEOUT)
		ip->i_flags |= UF_OPAQUE;

	/*
	 * Make sure inode goes to disk before directory entry.
	 */
	microtime(&tv);
	if ( (error = ffs_update(tvp, &tv, &tv, 1)) )
		goto bad;
	if ( (error = ufs_direnter(ip, dvp, cnp)) )
		goto bad;

	*vpp = tvp;
	return (0);

bad:
	/*
	 * Write error occurred trying to update the inode
	 * or the directory so must deallocate the inode.
	 */
	ip->i_nlink = 0;
	ip->i_flag |= IN_CHANGE;
	vnode_put(tvp);

	return (error);
}

