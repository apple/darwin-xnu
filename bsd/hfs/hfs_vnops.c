/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/ubc.h>
#include <sys/quota.h>
#include <sys/time.h>
#include <sys/disk.h>

#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>
#include <vfs/vfs_support.h>
#include <machine/spl.h>

#include <sys/kdebug.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_cnode.h"
#include "hfs_lockf.h"
#include "hfs_dbg.h"
#include "hfs_mount.h"
#include "hfs_quota.h"
#include "hfs_endian.h"

#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/FileMgrInternal.h"

#define MAKE_DELETED_NAME(NAME,FID) \
	    (void) sprintf((NAME), "%s%d", HFS_DELETE_PREFIX, (FID))

#define KNDETACH_VNLOCKED 0x00000001

#define CARBON_TEMP_DIR_NAME	"Cleanup At Startup"


/* Global vfs data structures for hfs */


extern unsigned long strtoul(const char *, char **, int);

extern int groupmember(gid_t gid, struct ucred *cred);

static int hfs_makenode(int mode, struct vnode *dvp, struct vnode **vpp,
                        struct componentname *cnp);
                        
static int hfs_vgetrsrc(struct hfsmount *hfsmp, struct vnode *vp,
			struct vnode **rvpp, struct proc *p);

static int hfs_metasync(struct hfsmount *hfsmp, daddr_t node, struct proc *p);

static int hfs_removedir(struct vnode *, struct vnode *, struct componentname *,
                         int);

static int hfs_removefile(struct vnode *, struct vnode *, struct componentname *,
                          int);

/* Options for hfs_removedir and hfs_removefile */
#define HFSRM_PARENT_LOCKED    0x01
#define HFSRM_SKIP_RESERVE     0x02
#define HFSRM_SAVE_NAME        0x04
#define HFSRM_RENAMEOPTS       0x07


int hfs_write_access(struct vnode *vp, struct ucred *cred, struct proc *p, Boolean considerFlags);

int hfs_chflags(struct vnode *vp, u_long flags, struct ucred *cred,
			struct proc *p);
int hfs_chmod(struct vnode *vp, int mode, struct ucred *cred,
			struct proc *p);
int hfs_chown(struct vnode *vp, uid_t uid, gid_t gid,
			struct ucred *cred, struct proc *p);

/*****************************************************************************
*
* Common Operations on vnodes
*
*****************************************************************************/

/*
 * Create a regular file
#% create	dvp	L U U
#% create	vpp	- L -
#
 vop_create {
     IN WILLRELE struct vnode *dvp;
     OUT struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;
	
     We are responsible for freeing the namei buffer,
	 it is done in hfs_makenode()
*/

static int
hfs_create(ap)
	struct vop_create_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	struct vattr *vap = ap->a_vap;

	return (hfs_makenode(MAKEIMODE(vap->va_type, vap->va_mode),
				ap->a_dvp, ap->a_vpp, ap->a_cnp));
}


/*
 * Mknod vnode call

#% mknod	dvp	L U U
#% mknod	vpp	- X -
#
 vop_mknod {
     IN WILLRELE struct vnode *dvp;
     OUT WILLRELE struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;
     */
/* ARGSUSED */

static int
hfs_mknod(ap)
	struct vop_mknod_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	struct vattr *vap = ap->a_vap;
	struct vnode **vpp = ap->a_vpp;
	struct cnode *cp;
	int error;

	if (VTOVCB(ap->a_dvp)->vcbSigWord != kHFSPlusSigWord) {
		VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
		vput(ap->a_dvp);
		return (EOPNOTSUPP);
	}

	/* Create the vnode */
	error = hfs_makenode(MAKEIMODE(vap->va_type, vap->va_mode),
	                     ap->a_dvp, vpp, ap->a_cnp);
	if (error)
		return (error);
	cp = VTOC(*vpp);
	cp->c_flag |= C_ACCESS | C_CHANGE | C_UPDATE;
	if ((vap->va_rdev != VNOVAL) &&
	    (vap->va_type == VBLK || vap->va_type == VCHR))
		cp->c_rdev = vap->va_rdev;
	/*
	 * Remove cnode so that it will be reloaded by lookup and
	 * checked to see if it is an alias of an existing vnode.
	 * Note: unlike UFS, we don't bash v_type here.
	 */
	vput(*vpp);
	vgone(*vpp);
	*vpp = 0;
	return (0);
}


/*
 * Open called.
#% open		vp	L L L
#
 vop_open {
     IN struct vnode *vp;
     IN int mode;
     IN struct ucred *cred;
     IN struct proc *p;
     */


static int
hfs_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct filefork *fp = VTOF(vp);
	struct timeval tv;

	/*
	 * Files marked append-only must be opened for appending.
	 */
	if ((vp->v_type != VDIR) && (VTOC(vp)->c_flags & APPEND) &&
	    (ap->a_mode & (FWRITE | O_APPEND)) == FWRITE)
		return (EPERM);

	if (ap->a_mode & O_EVTONLY) {
		if (vp->v_type == VREG) {
			++VTOF(vp)->ff_evtonly_refs;
		} else {
			++VTOC(vp)->c_evtonly_refs;
		};
	};

	/*
	 * On the first (non-busy) open of a fragmented
	 * file attempt to de-frag it (if its less than 20MB).
	 */
	if ((VTOHFS(vp)->hfs_flags & HFS_READ_ONLY) ||
	    !UBCISVALID(vp) || ubc_isinuse(vp, 1)) {
		return (0);
	}
	fp = VTOF(vp);
	if (fp->ff_blocks &&
	    fp->ff_extents[7].blockCount != 0 &&
	    fp->ff_size <= (20 * 1024 * 1024)) {
		/* 
		 * Wait until system bootup is done (3 min).
		 */
		microuptime(&tv);
		if (tv.tv_sec < (60 * 3)) {
			return (0);
		}
		(void) hfs_relocate(vp, VTOVCB(vp)->nextAllocation + 4096, ap->a_cred, ap->a_p);
	}

	return (0);
}

/*
 * Close called.
 *
 * Update the times on the cnode.
#% close	vp	U U U
#
 vop_close {
     IN struct vnode *vp;
     IN int fflag;
     IN struct ucred *cred;
     IN struct proc *p;
     */


static int
hfs_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
 	register struct cnode *cp = VTOC(vp);
 	register struct filefork *fp = VTOF(vp);
	struct proc *p = ap->a_p;
	struct timeval tv;
	off_t leof;
	u_long blks, blocksize;
	int devBlockSize;
	int error;

	simple_lock(&vp->v_interlock);
	if ((!UBCISVALID(vp) && vp->v_usecount > 1)
	    || (UBCISVALID(vp) && ubc_isinuse(vp, 1))) {
		tv = time;
		CTIMES(cp, &tv, &tv);
	}
	simple_unlock(&vp->v_interlock);

	if (ap->a_fflag & O_EVTONLY) {
		if (vp->v_type == VREG) {
			--VTOF(vp)->ff_evtonly_refs;
		} else {
			--VTOC(vp)->c_evtonly_refs;
		};
	};

	/*
	 * VOP_CLOSE can be called with vp locked (from vclean).
	 * We check for this case using VOP_ISLOCKED and bail.
	 * 
	 * XXX During a force unmount we won't do the cleanup below!
	 */
	if (vp->v_type == VDIR || VOP_ISLOCKED(vp))
		return (0);

	leof = fp->ff_size;
	
	if ((fp->ff_blocks > 0) &&
	    !ISSET(cp->c_flag, C_DELETED) &&
	    ((VTOHFS(vp)->hfs_flags & HFS_READ_ONLY) == 0)) {
		enum vtype our_type = vp->v_type;
		u_long our_id = vp->v_id;
		int was_nocache = ISSET(vp->v_flag, VNOCACHE_DATA);

		error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		if (error)
			return (0);
		/*
		 * Since we can context switch in vn_lock our vnode
		 * could get recycled (eg umount -f).  Double check
		 * that its still ours.
		 */
		if (vp->v_type != our_type || vp->v_id != our_id
		    || cp != VTOC(vp) || !UBCINFOEXISTS(vp)) {
			VOP_UNLOCK(vp, 0, p);
			return (0);
		}

		/*
		 * Last chance to explicitly zero out the areas
		 * that are currently marked invalid:
		 */
		VOP_DEVBLOCKSIZE(cp->c_devvp, &devBlockSize);
		(void) cluster_push(vp);
		SET(vp->v_flag, VNOCACHE_DATA);	/* Don't cache zeros */
		while (!CIRCLEQ_EMPTY(&fp->ff_invalidranges)) {
			struct rl_entry *invalid_range = CIRCLEQ_FIRST(&fp->ff_invalidranges);
			off_t start = invalid_range->rl_start;
			off_t end = invalid_range->rl_end;
    		
			/* The range about to be written must be validated
			 * first, so that VOP_CMAP() will return the
			 * appropriate mapping for the cluster code:
			 */
			rl_remove(start, end, &fp->ff_invalidranges);

			(void) cluster_write(vp, (struct uio *) 0, leof,
					invalid_range->rl_end + 1, invalid_range->rl_start,
					(off_t)0, devBlockSize, IO_HEADZEROFILL | IO_NOZERODIRTY);

			if (ISSET(vp->v_flag, VHASDIRTY))
				(void) cluster_push(vp);

			cp->c_flag |= C_MODIFIED;
		}
		cp->c_flag &= ~C_ZFWANTSYNC;
		cp->c_zftimeout = 0;
		blocksize = VTOVCB(vp)->blockSize;
		blks = leof / blocksize;
		if (((off_t)blks * (off_t)blocksize) != leof)
			blks++;
		/*
		 * Shrink the peof to the smallest size neccessary to contain the leof.
		 */
		if (blks < fp->ff_blocks)
	 		(void) VOP_TRUNCATE(vp, leof, IO_NDELAY, ap->a_cred, p);
		(void) cluster_push(vp);

		if (!was_nocache)
			CLR(vp->v_flag, VNOCACHE_DATA);
		
		/*
		 * If the VOP_TRUNCATE didn't happen to flush the vnode's
		 * information out to disk, force it to be updated now that
		 * all invalid ranges have been zero-filled and validated:
		 */
		if (cp->c_flag & C_MODIFIED) {
			tv = time;
			VOP_UPDATE(vp, &tv, &tv, 0);
		}
		VOP_UNLOCK(vp, 0, p);
	}
	if ((vp->v_flag & VSYSTEM) && (vp->v_usecount == 1))
		vgone(vp);
	return (0);
}

/*
#% access	vp	L L L
#
 vop_access {
     IN struct vnode *vp;
     IN int mode;
     IN struct ucred *cred;
     IN struct proc *p;

     */

static int
hfs_access(ap)
	struct vop_access_args /* {
		struct vnode *a_vp;
		int a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct ucred *cred = ap->a_cred;
	register gid_t *gp;
	mode_t mode = ap->a_mode;
	mode_t mask = 0;
	int i;
	int error;

	/*
	 * Disallow write attempts on read-only file systems;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the file system.
	 */
	if (mode & VWRITE) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			if (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY)
				return (EROFS);
#if QUOTA
			if ((error = hfs_getinoquota(cp)))
				return (error);
#endif /* QUOTA */
			break;
		}
		/* If immutable bit set, nobody gets to write it. */
		if (cp->c_flags & IMMUTABLE)
			return (EPERM);
	}


	/* Otherwise, user id 0 always gets access. */
	if (cred->cr_uid == 0)
		return (0);

	mask = 0;

	/* Otherwise, check the owner. */
	if ( (cp->c_uid == cred->cr_uid) || (cp->c_uid == UNKNOWNUID) ) {
		if (mode & VEXEC)
			mask |= S_IXUSR;
		if (mode & VREAD)
			mask |= S_IRUSR;
		if (mode & VWRITE)
			mask |= S_IWUSR;
  		return ((cp->c_mode & mask) == mask ? 0 : EACCES);
	}

	/* Otherwise, check the groups. */
	if (! (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS)) {
		for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++)
			if (cp->c_gid == *gp) {
				if (mode & VEXEC)
					mask |= S_IXGRP;
				if (mode & VREAD)
					mask |= S_IRGRP;
				if (mode & VWRITE)
					mask |= S_IWGRP;
				return ((cp->c_mode & mask) == mask ? 0 : EACCES);
			}
	}

	/* Otherwise, check everyone else. */
	if (mode & VEXEC)
		mask |= S_IXOTH;
	if (mode & VREAD)
		mask |= S_IROTH;
	if (mode & VWRITE)
		mask |= S_IWOTH;
	return ((cp->c_mode & mask) == mask ? 0 : EACCES);
}



/*
#% getattr	vp	= = =
#
 vop_getattr {
     IN struct vnode *vp;
     IN struct vattr *vap;
     IN struct ucred *cred;
     IN struct proc *p;

     */


/* ARGSUSED */
static int
hfs_getattr(ap)
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct vattr *vap = ap->a_vap;
	struct timeval tv;

	tv = time;
	CTIMES(cp, &tv, &tv);

	vap->va_type = vp->v_type;
	vap->va_mode = cp->c_mode;
	vap->va_nlink = cp->c_nlink;
	/*
	 * [2856576]  Since we are dynamically changing the owner, also
	 * effectively turn off the set-user-id and set-group-id bits,
	 * just like chmod(2) would when changing ownership.  This prevents
	 * a security hole where set-user-id programs run as whoever is
	 * logged on (or root if nobody is logged in yet!)
	 */
	if (cp->c_uid == UNKNOWNUID) {
		vap->va_mode &= ~(S_ISUID | S_ISGID);
		vap->va_uid = ap->a_cred->cr_uid;
	} else {
		vap->va_uid = cp->c_uid;
	}
	vap->va_gid = cp->c_gid;
	vap->va_fsid = cp->c_dev;
	/*
	 * Exporting file IDs from HFS Plus:
	 *
	 * For "normal" files the c_fileid is the same value as the
	 * c_cnid.  But for hard link files, they are different - the
	 * c_cnid belongs to the active directory entry (ie the link)
	 * and the c_fileid is for the actual inode (ie the data file).
	 *
	 * The stat call (getattr) will always return the c_fileid
	 * and Carbon APIs, which are hardlink-ignorant, will always
	 * receive the c_cnid (from getattrlist).
	 */
	vap->va_fileid = cp->c_fileid;
	vap->va_atime.tv_sec = cp->c_atime;
	vap->va_atime.tv_nsec = 0;
	vap->va_mtime.tv_sec = cp->c_mtime;
	vap->va_mtime.tv_nsec = cp->c_mtime_nsec;
	vap->va_ctime.tv_sec = cp->c_ctime;
	vap->va_ctime.tv_nsec = 0;
	vap->va_gen = 0;
	vap->va_flags = cp->c_flags;
	vap->va_rdev = 0;
	vap->va_blocksize = VTOVFS(vp)->mnt_stat.f_iosize;
	vap->va_filerev = 0;
	if (vp->v_type == VDIR) {
		vap->va_size = cp->c_nlink * AVERAGE_HFSDIRENTRY_SIZE;
		vap->va_bytes = 0;
	} else {
		vap->va_size = VTOF(vp)->ff_size;
		vap->va_bytes = (u_quad_t)cp->c_blocks *
				    (u_quad_t)VTOVCB(vp)->blockSize;
		if (vp->v_type == VBLK || vp->v_type == VCHR)
			vap->va_rdev = cp->c_rdev;
	}
	return (0);
}

/*
 * Set attribute vnode op. called from several syscalls
#% setattr	vp	L L L
#
 vop_setattr {
     IN struct vnode *vp;
     IN struct vattr *vap;
     IN struct ucred *cred;
     IN struct proc *p;

     */

static int
hfs_setattr(ap)
	struct vop_setattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vattr *vap = ap->a_vap;
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct ucred *cred = ap->a_cred;
	struct proc *p = ap->a_p;
	struct timeval atimeval, mtimeval;
	int error;

	/*
	 * Check for unsettable attributes.
	 */
	if ((vap->va_type != VNON) || (vap->va_nlink != VNOVAL) ||
	    (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
	    (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
	    ((int)vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL)) {
		return (EINVAL);
	}

	// XXXdbg
	// don't allow people to set the attributes of symlinks
	// (nfs has a bad habit of doing ths and it can cause
	// problems for journaling).
	//
	if (vp->v_type == VLNK) {
		return 0;
	}



	if (vap->va_flags != VNOVAL) {
		if (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY)
			return (EROFS);
		if ((error = hfs_chflags(vp, vap->va_flags, cred, p)))
			return (error);
		if (vap->va_flags & (IMMUTABLE | APPEND))
			return (0);
	}

	if (cp->c_flags & (IMMUTABLE | APPEND))
		return (EPERM);

	// XXXdbg - don't allow modification of the journal or journal_info_block
	if (VTOHFS(vp)->jnl && cp->c_datafork) {
		struct HFSPlusExtentDescriptor *extd;

		extd = &cp->c_datafork->ff_extents[0];
		if (extd->startBlock == VTOVCB(vp)->vcbJinfoBlock || extd->startBlock == VTOHFS(vp)->jnl_start) {
			return EPERM;
		}
	}

	/*
	 * Go through the fields and update iff not VNOVAL.
	 */
	if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
		if (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY)
			return (EROFS);
		if ((error = hfs_chown(vp, vap->va_uid, vap->va_gid, cred, p)))
			return (error);
	}
	if (vap->va_size != VNOVAL) {
		/*
		 * Disallow write attempts on read-only file systems;
		 * unless the file is a socket, fifo, or a block or
		 * character device resident on the file system.
		 */
		switch (vp->v_type) {
		case VDIR:
			return (EISDIR);
 		case VLNK:
		case VREG:
			if (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY)
				return (EROFS);
                	break;
		default:
                	break;
		}
		if ((error = VOP_TRUNCATE(vp, vap->va_size, 0, cred, p)))
			return (error);
	}
	cp = VTOC(vp);
	if (vap->va_atime.tv_sec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL) {
		if (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY)
			return (EROFS);
		if (((error = hfs_owner_rights(VTOHFS(vp), cp->c_uid, cred, p, true)) != 0) &&
		    ((vap->va_vaflags & VA_UTIMES_NULL) == 0 ||
		    (error = VOP_ACCESS(vp, VWRITE, cred, p)))) {
			return (error);
		}
		if (vap->va_atime.tv_sec != VNOVAL)
			cp->c_flag |= C_ACCESS;
		if (vap->va_mtime.tv_sec != VNOVAL) {
			cp->c_flag |= C_CHANGE | C_UPDATE;
			/*
			 * The utimes system call can reset the modification
			 * time but it doesn't know about HFS create times.
			 * So we need to insure that the creation time is
			 * always at least as old as the modification time.
			 */
			if ((VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) &&
			    (cp->c_cnid != kRootDirID) &&
			    (vap->va_mtime.tv_sec < cp->c_itime)) {
				cp->c_itime = vap->va_mtime.tv_sec;
			}
		}
		atimeval.tv_sec = vap->va_atime.tv_sec;
		atimeval.tv_usec = 0;
		mtimeval.tv_sec = vap->va_mtime.tv_sec;
		mtimeval.tv_usec = 0;
		if ((error = VOP_UPDATE(vp, &atimeval, &mtimeval, 1)))
			return (error);
	}
	error = 0;
	if (vap->va_mode != (mode_t)VNOVAL) {
		if (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY)
			return (EROFS);
		error = hfs_chmod(vp, (int)vap->va_mode, cred, p);
	}
	HFS_KNOTE(vp, NOTE_ATTRIB);
	return (error);
}


/*
 * Change the mode on a file.
 * cnode must be locked before calling.
 */
__private_extern__
int
hfs_chmod(vp, mode, cred, p)
	register struct vnode *vp;
	register int mode;
	register struct ucred *cred;
	struct proc *p;
{
	register struct cnode *cp = VTOC(vp);
	int error;

	if (VTOVCB(vp)->vcbSigWord != kHFSPlusSigWord)
		return (0);

	// XXXdbg - don't allow modification of the journal or journal_info_block
	if (VTOHFS(vp)->jnl && cp && cp->c_datafork) {
		struct HFSPlusExtentDescriptor *extd;

		extd = &cp->c_datafork->ff_extents[0];
		if (extd->startBlock == VTOVCB(vp)->vcbJinfoBlock || extd->startBlock == VTOHFS(vp)->jnl_start) {
			return EPERM;
		}
	}

#if OVERRIDE_UNKNOWN_PERMISSIONS
	if (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
		return (0);
	};
#endif
	if ((error = hfs_owner_rights(VTOHFS(vp), cp->c_uid, cred, p, true)) != 0)
		return (error);
	if (cred->cr_uid) {
		if (vp->v_type != VDIR && (mode & S_ISTXT))
			return (EFTYPE);
		if (!groupmember(cp->c_gid, cred) && (mode & S_ISGID))
			return (EPERM);
	}
	cp->c_mode &= ~ALLPERMS;
	cp->c_mode |= (mode & ALLPERMS);
	cp->c_flag |= C_CHANGE;
	return (0);
}


__private_extern__
int
hfs_write_access(struct vnode *vp, struct ucred *cred, struct proc *p, Boolean considerFlags)
{
	struct cnode *cp = VTOC(vp);
	gid_t *gp;
	int retval = 0;
	int i;

	/*
	 * Disallow write attempts on read-only file systems;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the file system.
	 */
	switch (vp->v_type) {
	case VDIR:
 	case VLNK:
	case VREG:
		if (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY)
			return (EROFS);
		break;
	default:
		break;
 	}
 
	/* If immutable bit set, nobody gets to write it. */
	if (considerFlags && (cp->c_flags & IMMUTABLE))
		return (EPERM);

	/* Otherwise, user id 0 always gets access. */
	if (cred->cr_uid == 0)
		return (0);

	/* Otherwise, check the owner. */
	if ((retval = hfs_owner_rights(VTOHFS(vp), cp->c_uid, cred, p, false)) == 0)
		return ((cp->c_mode & S_IWUSR) == S_IWUSR ? 0 : EACCES);
 
	/* Otherwise, check the groups. */
	for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++) {
		if (cp->c_gid == *gp)
			return ((cp->c_mode & S_IWGRP) == S_IWGRP ? 0 : EACCES);
 	}
 
	/* Otherwise, check everyone else. */
	return ((cp->c_mode & S_IWOTH) == S_IWOTH ? 0 : EACCES);
}



/*
 * Change the flags on a file or directory.
 * cnode must be locked before calling.
 */
__private_extern__
int
hfs_chflags(vp, flags, cred, p)
	register struct vnode *vp;
	register u_long flags;
	register struct ucred *cred;
	struct proc *p;
{
	register struct cnode *cp = VTOC(vp);
	int retval;

	if (VTOVCB(vp)->vcbSigWord == kHFSSigWord) {
		if ((retval = hfs_write_access(vp, cred, p, false)) != 0) {
			return retval;
		};
	} else if ((retval = hfs_owner_rights(VTOHFS(vp), cp->c_uid, cred, p, true)) != 0) {
		return retval;
	};

	if (cred->cr_uid == 0) {
		if ((cp->c_flags & (SF_IMMUTABLE | SF_APPEND)) &&
			securelevel > 0) {
			return EPERM;
		};
		cp->c_flags = flags;
	} else {
		if (cp->c_flags & (SF_IMMUTABLE | SF_APPEND) ||
			(flags & UF_SETTABLE) != flags) {
			return EPERM;
		};
		cp->c_flags &= SF_SETTABLE;
		cp->c_flags |= (flags & UF_SETTABLE);
	}
	cp->c_flag |= C_CHANGE;

	return (0);
}


/*
 * Perform chown operation on cnode cp;
 * code must be locked prior to call.
 */
__private_extern__
int
hfs_chown(vp, uid, gid, cred, p)
	register struct vnode *vp;
	uid_t uid;
	gid_t gid;
	struct ucred *cred;
	struct proc *p;
{
	register struct cnode *cp = VTOC(vp);
	uid_t ouid;
	gid_t ogid;
	int error = 0;
#if QUOTA
	register int i;
	int64_t change;
#endif /* QUOTA */

	if (VTOVCB(vp)->vcbSigWord != kHFSPlusSigWord)
		return (EOPNOTSUPP);

	if (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS)
		return (0);
	
	if (uid == (uid_t)VNOVAL)
		uid = cp->c_uid;
	if (gid == (gid_t)VNOVAL)
		gid = cp->c_gid;
	/*
	 * If we don't own the file, are trying to change the owner
	 * of the file, or are not a member of the target group,
	 * the caller must be superuser or the call fails.
	 */
	if ((cred->cr_uid != cp->c_uid || uid != cp->c_uid ||
	    (gid != cp->c_gid && !groupmember((gid_t)gid, cred))) &&
	    (error = suser(cred, &p->p_acflag)))
		return (error);

	ogid = cp->c_gid;
	ouid = cp->c_uid;
#if QUOTA
	if ((error = hfs_getinoquota(cp)))
		return (error);
	if (ouid == uid) {
		dqrele(vp, cp->c_dquot[USRQUOTA]);
		cp->c_dquot[USRQUOTA] = NODQUOT;
	}
	if (ogid == gid) {
		dqrele(vp, cp->c_dquot[GRPQUOTA]);
		cp->c_dquot[GRPQUOTA] = NODQUOT;
	}

	/*
	 * Eventually need to account for (fake) a block per directory
	 *if (vp->v_type == VDIR)
	 *change = VTOVCB(vp)->blockSize;
	 *else
	 */

	change = (int64_t)(cp->c_blocks) * (int64_t)VTOVCB(vp)->blockSize;
	(void) hfs_chkdq(cp, -change, cred, CHOWN);
	(void) hfs_chkiq(cp, -1, cred, CHOWN);
	for (i = 0; i < MAXQUOTAS; i++) {
		dqrele(vp, cp->c_dquot[i]);
		cp->c_dquot[i] = NODQUOT;
	}
#endif /* QUOTA */
	cp->c_gid = gid;
	cp->c_uid = uid;
#if QUOTA
	if ((error = hfs_getinoquota(cp)) == 0) {
		if (ouid == uid) {
			dqrele(vp, cp->c_dquot[USRQUOTA]);
			cp->c_dquot[USRQUOTA] = NODQUOT;
		}
		if (ogid == gid) {
			dqrele(vp, cp->c_dquot[GRPQUOTA]);
			cp->c_dquot[GRPQUOTA] = NODQUOT;
		}
		if ((error = hfs_chkdq(cp, change, cred, CHOWN)) == 0) {
			if ((error = hfs_chkiq(cp, 1, cred, CHOWN)) == 0)
				goto good;
			else
				(void) hfs_chkdq(cp, -change, cred, CHOWN|FORCE);
		}
		for (i = 0; i < MAXQUOTAS; i++) {
			dqrele(vp, cp->c_dquot[i]);
			cp->c_dquot[i] = NODQUOT;
		}
	}
	cp->c_gid = ogid;
	cp->c_uid = ouid;
	if (hfs_getinoquota(cp) == 0) {
		if (ouid == uid) {
			dqrele(vp, cp->c_dquot[USRQUOTA]);
			cp->c_dquot[USRQUOTA] = NODQUOT;
		}
		if (ogid == gid) {
			dqrele(vp, cp->c_dquot[GRPQUOTA]);
			cp->c_dquot[GRPQUOTA] = NODQUOT;
		}
		(void) hfs_chkdq(cp, change, cred, FORCE|CHOWN);
		(void) hfs_chkiq(cp, 1, cred, FORCE|CHOWN);
		(void) hfs_getinoquota(cp);
	}
	return (error);
good:
	if (hfs_getinoquota(cp))
		panic("hfs_chown: lost quota");
#endif /* QUOTA */

	if (ouid != uid || ogid != gid)
		cp->c_flag |= C_CHANGE;
	if (ouid != uid && cred->cr_uid != 0)
		cp->c_mode &= ~S_ISUID;
	if (ogid != gid && cred->cr_uid != 0)
		cp->c_mode &= ~S_ISGID;
	return (0);
}


/*
#
#% exchange fvp		L L L
#% exchange tvp		L L L
#
 */
 /*
  * The hfs_exchange routine swaps the fork data in two files by
  * exchanging some of the information in the cnode.  It is used
  * to preserve the file ID when updating an existing file, in
  * case the file is being tracked through its file ID. Typically
  * its used after creating a new file during a safe-save.
  */
  
static int
hfs_exchange(ap)
	struct vop_exchange_args /* {
		struct vnode *a_fvp;
		struct vnode *a_tvp;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *from_vp = ap->a_fvp;
	struct vnode *to_vp = ap->a_tvp;
	struct cnode *from_cp = VTOC(from_vp);
	struct cnode *to_cp = VTOC(to_vp);
	struct hfsmount *hfsmp = VTOHFS(from_vp);
	struct cat_desc tempdesc;
	struct cat_attr tempattr;
	int error = 0, started_tr = 0, grabbed_lock = 0;
	cat_cookie_t cookie = {0};

	/* The files must be on the same volume. */
	if (from_vp->v_mount != to_vp->v_mount)
		return (EXDEV);

	/* Only normal files can be exchanged. */
	if ((from_vp->v_type != VREG) || (to_vp->v_type != VREG) ||
	    (from_cp->c_flag & C_HARDLINK) || (to_cp->c_flag & C_HARDLINK) ||
	    VNODE_IS_RSRC(from_vp) || VNODE_IS_RSRC(to_vp))
		return (EINVAL);

	// XXXdbg - don't allow modification of the journal or journal_info_block
	if (hfsmp->jnl) {
		struct HFSPlusExtentDescriptor *extd;

		if (from_cp->c_datafork) {
			extd = &from_cp->c_datafork->ff_extents[0];
			if (extd->startBlock == VTOVCB(from_vp)->vcbJinfoBlock || extd->startBlock == hfsmp->jnl_start) {
				return EPERM;
			}
		}

		if (to_cp->c_datafork) {
			extd = &to_cp->c_datafork->ff_extents[0];
			if (extd->startBlock == VTOVCB(to_vp)->vcbJinfoBlock || extd->startBlock == hfsmp->jnl_start) {
				return EPERM;
			}
		}
	}

	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	grabbed_lock = 1;
	if (hfsmp->jnl) {
	    if ((error = journal_start_transaction(hfsmp->jnl)) != 0) {
			goto Err_Exit;
	    }
		started_tr = 1;
	}
	
	/*
	 * Reserve some space in the Catalog file.
	 */
	if ((error = cat_preflight(hfsmp, CAT_EXCHANGE, &cookie, ap->a_p))) {
		goto Err_Exit;
	}

	/* Lock catalog b-tree */
	error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, ap->a_p);
	if (error) goto Err_Exit;

	/* The backend code always tries to delete the virtual
	 * extent id for exchanging files so we neeed to lock
	 * the extents b-tree.
	 */
	error = hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE, ap->a_p);
	if (error) {
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, ap->a_p);
		goto Err_Exit;
	}

	/* Do the exchange */
	error = MacToVFSError(ExchangeFileIDs(HFSTOVCB(hfsmp),
				from_cp->c_desc.cd_nameptr, to_cp->c_desc.cd_nameptr,
				from_cp->c_parentcnid, to_cp->c_parentcnid,
				from_cp->c_hint, to_cp->c_hint));

	(void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_RELEASE, ap->a_p);
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, ap->a_p);

	if (error != E_NONE) {
		goto Err_Exit;
	}

	/* Purge the vnodes from the name cache */
 	if (from_vp)
		cache_purge(from_vp);
	if (to_vp)
		cache_purge(to_vp);

	/* Save a copy of from attributes before swapping. */
	bcopy(&from_cp->c_desc, &tempdesc, sizeof(struct cat_desc));
	bcopy(&from_cp->c_attr, &tempattr, sizeof(struct cat_attr));

	/*
	 * Swap the descriptors and all non-fork related attributes.
	 * (except the modify date)
	 */
	bcopy(&to_cp->c_desc, &from_cp->c_desc, sizeof(struct cat_desc));

	from_cp->c_hint = 0;
	from_cp->c_fileid = from_cp->c_cnid;
	from_cp->c_itime = to_cp->c_itime;
	from_cp->c_btime = to_cp->c_btime;
	from_cp->c_atime = to_cp->c_atime;
	from_cp->c_ctime = to_cp->c_ctime;
	from_cp->c_gid = to_cp->c_gid;
	from_cp->c_uid = to_cp->c_uid;
	from_cp->c_flags = to_cp->c_flags;
	from_cp->c_mode = to_cp->c_mode;
	bcopy(to_cp->c_finderinfo, from_cp->c_finderinfo, 32);

	bcopy(&tempdesc, &to_cp->c_desc, sizeof(struct cat_desc));
	to_cp->c_hint = 0;
	to_cp->c_fileid = to_cp->c_cnid;
	to_cp->c_itime = tempattr.ca_itime;
	to_cp->c_btime = tempattr.ca_btime;
	to_cp->c_atime = tempattr.ca_atime;
	to_cp->c_ctime = tempattr.ca_ctime;
	to_cp->c_gid = tempattr.ca_gid;
	to_cp->c_uid = tempattr.ca_uid;
	to_cp->c_flags = tempattr.ca_flags;
	to_cp->c_mode = tempattr.ca_mode;
	bcopy(tempattr.ca_finderinfo, to_cp->c_finderinfo, 32);

	/* Reinsert into the cnode hash under new file IDs*/
	hfs_chashremove(from_cp);
	hfs_chashremove(to_cp);

	hfs_chashinsert(from_cp);
	hfs_chashinsert(to_cp);

	/*
	 * When a file moves out of "Cleanup At Startup"
	 * we can drop its NODUMP status.
	 */
	if ((from_cp->c_flags & UF_NODUMP) &&
	    (from_cp->c_parentcnid != to_cp->c_parentcnid)) {
		from_cp->c_flags &= ~UF_NODUMP;
		from_cp->c_flag |= C_CHANGE;
	}
	if ((to_cp->c_flags & UF_NODUMP) &&
	    (to_cp->c_parentcnid != from_cp->c_parentcnid)) {
		to_cp->c_flags &= ~UF_NODUMP;
		to_cp->c_flag |= C_CHANGE;
	}

	HFS_KNOTE(from_vp, NOTE_ATTRIB);
	HFS_KNOTE(to_vp, NOTE_ATTRIB);

Err_Exit:
	cat_postflight(hfsmp, &cookie, ap->a_p);

	// XXXdbg
	if (started_tr) {
	    journal_end_transaction(hfsmp->jnl);
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
	}

	return (error);
}


/*

#% fsync	vp	L L L
#
 vop_fsync {
     IN struct vnode *vp;
     IN struct ucred *cred;
     IN int waitfor;
     IN struct proc *p;

     */
static int
hfs_fsync(ap)
	struct vop_fsync_args /* {
		struct vnode *a_vp;
		struct ucred *a_cred;
		int a_waitfor;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
	struct filefork *fp = NULL;
	int retval = 0;
	register struct buf *bp;
	struct timeval tv;
	struct buf *nbp;
	struct hfsmount *hfsmp = VTOHFS(ap->a_vp);
	int s;
	int wait;
	int retry = 0;

	wait = (ap->a_waitfor == MNT_WAIT);

	/* HFS directories don't have any data blocks. */
	if (vp->v_type == VDIR)
		goto metasync;

	/*
	 * For system files flush the B-tree header and
	 * for regular files write out any clusters
	 */
	if (vp->v_flag & VSYSTEM) {
	    if (VTOF(vp)->fcbBTCBPtr != NULL) {
			// XXXdbg
			if (hfsmp->jnl == NULL) {
				BTFlushPath(VTOF(vp));
			}
	    }
	} else if (UBCINFOEXISTS(vp))
		(void) cluster_push(vp);

	/*
	 * When MNT_WAIT is requested and the zero fill timeout
	 * has expired then we must explicitly zero out any areas
	 * that are currently marked invalid (holes).
	 *
	 * Files with NODUMP can bypass zero filling here.
	 */
	if ((wait || (cp->c_flag & C_ZFWANTSYNC)) &&
	    ((cp->c_flags & UF_NODUMP) == 0) &&
	    UBCINFOEXISTS(vp) && (fp = VTOF(vp)) &&
	    cp->c_zftimeout != 0) {
		int devblksize;
		int was_nocache;

		if (time.tv_sec < cp->c_zftimeout) {
			/* Remember that a force sync was requested. */
			cp->c_flag |= C_ZFWANTSYNC;
			goto loop;
		}	
		VOP_DEVBLOCKSIZE(cp->c_devvp, &devblksize);
		was_nocache = ISSET(vp->v_flag, VNOCACHE_DATA);
		SET(vp->v_flag, VNOCACHE_DATA);	/* Don't cache zeros */

		while (!CIRCLEQ_EMPTY(&fp->ff_invalidranges)) {
			struct rl_entry *invalid_range = CIRCLEQ_FIRST(&fp->ff_invalidranges);
			off_t start = invalid_range->rl_start;
			off_t end = invalid_range->rl_end;
    		
			/* The range about to be written must be validated
			 * first, so that VOP_CMAP() will return the
			 * appropriate mapping for the cluster code:
			 */
			rl_remove(start, end, &fp->ff_invalidranges);

			(void) cluster_write(vp, (struct uio *) 0,
					fp->ff_size,
					invalid_range->rl_end + 1,
					invalid_range->rl_start,
					(off_t)0, devblksize,
					IO_HEADZEROFILL | IO_NOZERODIRTY);
			cp->c_flag |= C_MODIFIED;
		}
		(void) cluster_push(vp);
		if (!was_nocache)
			CLR(vp->v_flag, VNOCACHE_DATA);
		cp->c_flag &= ~C_ZFWANTSYNC;
		cp->c_zftimeout = 0;
	}

	/*
	 * Flush all dirty buffers associated with a vnode.
	 */
loop:
	s = splbio();
	for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
		nbp = bp->b_vnbufs.le_next;
		if ((bp->b_flags & B_BUSY))
			continue;
		if ((bp->b_flags & B_DELWRI) == 0)
			panic("hfs_fsync: bp 0x% not dirty (hfsmp 0x%x)", bp, hfsmp);
		// XXXdbg
		if (hfsmp->jnl && (bp->b_flags & B_LOCKED)) {
			if ((bp->b_flags & B_META) == 0) {
				panic("hfs: bp @ 0x%x is locked but not meta! jnl 0x%x\n",
					  bp, hfsmp->jnl);
			}
			// if journal_active() returns >= 0 then the journal is ok and we 
			// shouldn't do anything to this locked block (because it is part 
			// of a transaction).  otherwise we'll just go through the normal 
			// code path and flush the buffer.
			if (journal_active(hfsmp->jnl) >= 0) {
				continue;
			}
		}

		bremfree(bp);
		bp->b_flags |= B_BUSY;
		/* Clear B_LOCKED, should only be set on meta files */
		bp->b_flags &= ~B_LOCKED;

		splx(s);
		/*
		 * Wait for I/O associated with indirect blocks to complete,
		 * since there is no way to quickly wait for them below.
		 */
		if (bp->b_vp == vp || ap->a_waitfor == MNT_NOWAIT)
			(void) bawrite(bp);
		else
			(void) VOP_BWRITE(bp);
		goto loop;
	}

	if (wait) {
		while (vp->v_numoutput) {
			vp->v_flag |= VBWAIT;
			tsleep((caddr_t)&vp->v_numoutput, PRIBIO + 1, "hfs_fsync", 0);
		}

		// XXXdbg -- is checking for hfsmp->jnl == NULL the right
		//           thing to do?
		if (hfsmp->jnl == NULL && vp->v_dirtyblkhd.lh_first) {
			/* still have some dirty buffers */
			if (retry++ > 10) {
				vprint("hfs_fsync: dirty", vp);
				splx(s);
				/*
				 * Looks like the requests are not
				 * getting queued to the driver.
				 * Retrying here causes a cpu bound loop.
				 * Yield to the other threads and hope
				 * for the best.
				 */
				(void)tsleep((caddr_t)&vp->v_numoutput,
					PRIBIO + 1, "hfs_fsync", hz/10);
				retry = 0;
			} else {
				splx(s);
			}
			/* try again */
			goto loop;
		}
	}
	splx(s);

metasync:
   	tv = time;
	if (vp->v_flag & VSYSTEM) {
		if (VTOF(vp)->fcbBTCBPtr != NULL)
			BTSetLastSync(VTOF(vp), tv.tv_sec);
		cp->c_flag &= ~(C_ACCESS | C_CHANGE | C_MODIFIED | C_UPDATE);
	} else /* User file */ {
		retval = VOP_UPDATE(ap->a_vp, &tv, &tv, wait);

		/* When MNT_WAIT is requested push out any delayed meta data */
   		if ((retval == 0) && wait && cp->c_hint &&
   		    !ISSET(cp->c_flag, C_DELETED | C_NOEXISTS)) {
   			hfs_metasync(VTOHFS(vp), cp->c_hint, ap->a_p);
   		}

		// make sure that we've really been called from the user
		// fsync() and if so push out any pending transactions 
		// that this file might is a part of (and get them on
		// stable storage).
		if (vp->v_flag & VFULLFSYNC) {
		    if (hfsmp->jnl) {
			journal_flush(hfsmp->jnl);
		    } else {
			VOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, NOCRED, ap->a_p);
		    }
		}
	}

	return (retval);
}

/* Sync an hfs catalog b-tree node */
static int
hfs_metasync(struct hfsmount *hfsmp, daddr_t node, struct proc *p)
{
	struct vnode *vp;
	struct buf *bp;
	struct buf *nbp;
	int s;

	vp = HFSTOVCB(hfsmp)->catalogRefNum;

	// XXXdbg - don't need to do this on a journaled volume
	if (hfsmp->jnl) {
		return 0;
	}

	if (hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p) != 0)
		return (0);

	/*
	 * Look for a matching node that has been delayed
	 * but is not part of a set (B_LOCKED).
	 */
	s = splbio();
	for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
		nbp = bp->b_vnbufs.le_next;
		if (bp->b_flags & B_BUSY)
			continue;
		if (bp->b_lblkno == node) {
			if (bp->b_flags & B_LOCKED)
				break;

			bremfree(bp);
			bp->b_flags |= B_BUSY;
			splx(s);
			(void) VOP_BWRITE(bp);
			goto exit;
		}
	}
	splx(s);
exit:
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

	return (0);
}

__private_extern__
int
hfs_btsync(struct vnode *vp, int sync_transaction)
{
	struct cnode *cp = VTOC(vp);
	register struct buf *bp;
	struct timeval tv;
	struct buf *nbp;
	struct hfsmount *hfsmp = VTOHFS(vp);
	int s;

	/*
	 * Flush all dirty buffers associated with b-tree.
	 */
loop:
	s = splbio();

	for (bp = vp->v_dirtyblkhd.lh_first; bp; bp = nbp) {
		nbp = bp->b_vnbufs.le_next;
		if ((bp->b_flags & B_BUSY))
			continue;
		if ((bp->b_flags & B_DELWRI) == 0)
			panic("hfs_btsync: not dirty (bp 0x%x hfsmp 0x%x)", bp, hfsmp);

		// XXXdbg
		if (hfsmp->jnl && (bp->b_flags & B_LOCKED)) {
			if ((bp->b_flags & B_META) == 0) {
				panic("hfs: bp @ 0x%x is locked but not meta! jnl 0x%x\n",
					  bp, hfsmp->jnl);
			}
			// if journal_active() returns >= 0 then the journal is ok and we 
			// shouldn't do anything to this locked block (because it is part 
			// of a transaction).  otherwise we'll just go through the normal 
			// code path and flush the buffer.
			if (journal_active(hfsmp->jnl) >= 0) {
			    continue;
			}
		}

		if (sync_transaction && !(bp->b_flags & B_LOCKED))
			continue;

		bremfree(bp);
		bp->b_flags |= B_BUSY;
		bp->b_flags &= ~B_LOCKED;

		splx(s);

		(void) bawrite(bp);

		goto loop;
	}
	splx(s);

	tv = time;
	if ((vp->v_flag & VSYSTEM) && (VTOF(vp)->fcbBTCBPtr != NULL))
		(void) BTSetLastSync(VTOF(vp), tv.tv_sec);
	cp->c_flag &= ~(C_ACCESS | C_CHANGE | C_MODIFIED | C_UPDATE);

	return 0;
}

/*
 * Rmdir system call.
#% rmdir	dvp	L U U
#% rmdir	vp	L U U
#
 vop_rmdir {
     IN WILLRELE struct vnode *dvp;
     IN WILLRELE struct vnode *vp;
     IN struct componentname *cnp;

 */
static int
hfs_rmdir(ap)
	struct vop_rmdir_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{
	return (hfs_removedir(ap->a_dvp, ap->a_vp, ap->a_cnp, 0));
}

/*
 * hfs_removedir
 */
static int
hfs_removedir(dvp, vp, cnp, options)
	struct vnode *dvp;
	struct vnode *vp;
	struct componentname *cnp;
	int options;
{
	struct proc *p = cnp->cn_proc;
	struct cnode *cp;
	struct cnode *dcp;
	struct hfsmount * hfsmp;
	struct timeval tv;
	cat_cookie_t cookie = {0};
	int error = 0, started_tr = 0, grabbed_lock = 0;

	cp = VTOC(vp);
	dcp = VTOC(dvp);
	hfsmp = VTOHFS(vp);

	if (dcp == cp) {
		vrele(dvp);
		vput(vp);
		return (EINVAL);	/* cannot remove "." */
	}

#if QUOTA
	(void)hfs_getinoquota(cp);
#endif
	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	grabbed_lock = 1;
	if (hfsmp->jnl) {
	    if ((error = journal_start_transaction(hfsmp->jnl)) != 0) {
			goto out;
	    }
		started_tr = 1;
	}

	if (!(options & HFSRM_SKIP_RESERVE)) {
		/*
		 * Reserve some space in the Catalog file.
		 */
		if ((error = cat_preflight(hfsmp, CAT_DELETE, &cookie, p))) {
			goto out;
		}
	}

	/*
	 * Verify the directory is empty (and valid).
	 * (Rmdir ".." won't be valid since
	 *  ".." will contain a reference to
	 *  the current directory and thus be
	 *  non-empty.)
	 */
	if (cp->c_entries != 0) {
		error = ENOTEMPTY;
		goto out;
	}
	if ((dcp->c_flags & APPEND) || (cp->c_flags & (IMMUTABLE | APPEND))) {
		error = EPERM;
		goto out;
	}

	/* Remove the entry from the namei cache: */
	cache_purge(vp);

	/* Lock catalog b-tree */
	error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (error) goto out;

	if (cp->c_entries > 0)
		panic("hfs_rmdir: attempting to delete a non-empty directory!");
	/* Remove entry from catalog */
	error = cat_delete(hfsmp, &cp->c_desc, &cp->c_attr);

	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);
	if (error) goto out;

#if QUOTA
	(void)hfs_chkiq(cp, -1, NOCRED, 0);
#endif /* QUOTA */

	/* The parent lost a child */
	if (dcp->c_entries > 0)
		dcp->c_entries--;
	if (dcp->c_nlink > 0)
		dcp->c_nlink--;
	dcp->c_flag |= C_CHANGE | C_UPDATE;
	tv = time;
	(void) VOP_UPDATE(dvp, &tv, &tv, 0);
	HFS_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);

	hfs_volupdate(hfsmp, VOL_RMDIR, (dcp->c_cnid == kHFSRootFolderID));

	cp->c_mode = 0;  /* Makes the vnode go away...see inactive */
	cp->c_flag |= C_NOEXISTS;
out:
	if (!(options & HFSRM_PARENT_LOCKED)) {
		vput(dvp);
	}
	HFS_KNOTE(vp, NOTE_DELETE);
	vput(vp);

	if (!(options & HFSRM_SKIP_RESERVE)) {
		cat_postflight(hfsmp, &cookie, p);
	}
	// XXXdbg
	if (started_tr) { 
	    journal_end_transaction(hfsmp->jnl);
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
	}

	return (error);
}

/*

#% remove	dvp	L U U
#% remove	vp	L U U
#
 vop_remove {
     IN WILLRELE struct vnode *dvp;
     IN WILLRELE struct vnode *vp;
     IN struct componentname *cnp;

     */

static int
hfs_remove(ap)
	struct vop_remove_args /* {
		struct vnode *a_dvp;
		struct vnode *a_vp;
		struct componentname *a_cnp;
	} */ *ap;
{
	return (hfs_removefile(ap->a_dvp, ap->a_vp, ap->a_cnp, 0));
}



/*
 * hfs_removefile
 *
 * Similar to hfs_remove except there are additional options.
 */
static int
hfs_removefile(dvp, vp, cnp, options)
	struct vnode *dvp;
	struct vnode *vp;
	struct componentname *cnp;
	int options;
{
	struct vnode *rvp = NULL;
	struct cnode *cp;
	struct cnode *dcp;
	struct hfsmount *hfsmp;
	struct proc *p = cnp->cn_proc;
	int dataforkbusy = 0;
	int rsrcforkbusy = 0;
	int truncated = 0;
	struct timeval tv;
	cat_cookie_t cookie = {0};
	int error = 0;
	int started_tr = 0, grabbed_lock = 0;
	int refcount, isbigfile = 0;

	/* Directories should call hfs_rmdir! */
	if (vp->v_type == VDIR) {
		error = EISDIR;
		goto out;
	}

	cp = VTOC(vp);
	dcp = VTOC(dvp);
	hfsmp = VTOHFS(vp);
	
	if (cp->c_parentcnid != dcp->c_cnid) {
		error = EINVAL;
		goto out;
	}

	/* Make sure a remove is permitted */
	if ((cp->c_flags & (IMMUTABLE | APPEND)) ||
	    (VTOC(dvp)->c_flags & APPEND) ||
	    VNODE_IS_RSRC(vp)) {
		error = EPERM;
		goto out;
	}

	/*
	 * Aquire a vnode for a non-empty resource fork.
	 * (needed for VOP_TRUNCATE)
	 */
	if (cp->c_blocks - VTOF(vp)->ff_blocks) {
		error = hfs_vgetrsrc(hfsmp, vp, &rvp, p);
		if (error)
			goto out;
	}

	// XXXdbg - don't allow deleting the journal or journal_info_block
	if (hfsmp->jnl && cp->c_datafork) {
		struct HFSPlusExtentDescriptor *extd;

		extd = &cp->c_datafork->ff_extents[0];
		if (extd->startBlock == HFSTOVCB(hfsmp)->vcbJinfoBlock || extd->startBlock == hfsmp->jnl_start) {
			error = EPERM;
			goto out;
		}
	}

	/*
	 * Check if this file is being used.
	 *
	 * The namei done for the remove took a reference on the
	 * vnode (vp).  And we took a ref on the resource vnode (rvp).
	 * Hence set 1 in the tookref parameter of ubc_isinuse().
	 */
	if (VTOC(vp)->c_flag & C_VPREFHELD) {
	    refcount = 2;
	} else {
	    refcount = 1;
	}
	if (UBCISVALID(vp) && ubc_isinuse(vp, refcount))
		dataforkbusy = 1;
	if (rvp && UBCISVALID(rvp) && ubc_isinuse(rvp, 1))
		rsrcforkbusy = 1;

	// need this to check if we have to break the deletion 
	// into multiple pieces
	isbigfile = (VTOC(vp)->c_datafork->ff_size >= HFS_BIGFILE_SIZE);

	/*
	 * Carbon semantics prohibit deleting busy files.
	 * (enforced when NODELETEBUSY is requested)
	 */
	if ((dataforkbusy || rsrcforkbusy) &&
	    ((cnp->cn_flags & NODELETEBUSY) ||
	     (hfsmp->hfs_privdir_desc.cd_cnid == 0))) {
		error = EBUSY;
		goto out;
	}

#if QUOTA
	(void)hfs_getinoquota(cp);
#endif /* QUOTA */

	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	grabbed_lock = 1;
	if (hfsmp->jnl) {
	    if ((error = journal_start_transaction(hfsmp->jnl)) != 0) {
			goto out;
	    }
	    started_tr = 1;
	}

	if (!(options & HFSRM_SKIP_RESERVE)) {
		/*
		 * Reserve some space in the Catalog file.
		 */
		if ((error = cat_preflight(hfsmp, CAT_DELETE, &cookie, p))) {
			goto out;
		}
	}

	/* Remove our entry from the namei cache. */
	cache_purge(vp);

	// XXXdbg - if we're journaled, kill any dirty symlink buffers 
	if (hfsmp->jnl && vp->v_type == VLNK && vp->v_dirtyblkhd.lh_first) {
	    struct buf *bp, *nbp;

	  recheck:
	    for (bp=vp->v_dirtyblkhd.lh_first; bp; bp=nbp) {
			nbp = bp->b_vnbufs.le_next;
			
			if ((bp->b_flags & B_BUSY)) {
				// if it was busy, someone else must be dealing
				// with it so just move on.
				continue;
			}

			if (!(bp->b_flags & B_META)) {
				panic("hfs: symlink bp @ 0x%x is not marked meta-data!\n", bp);
			}

			// if it's part of the current transaction, kill it.
			if (bp->b_flags & B_LOCKED) {
				bremfree(bp);
				bp->b_flags |= B_BUSY;
				journal_kill_block(hfsmp->jnl, bp);
				goto recheck;
			}
	    }
	}
	// XXXdbg

	/*
	 * Truncate any non-busy forks.  Busy forks will
	 * get trucated when their vnode goes inactive.
	 *
	 * (Note: hard links are truncated in VOP_INACTIVE)
	 */
	if ((cp->c_flag & C_HARDLINK) == 0) {
		int mode = cp->c_mode;

		if (!dataforkbusy && !isbigfile && cp->c_datafork->ff_blocks != 0) {
			cp->c_mode = 0;  /* Suppress VOP_UPDATES */
			error = VOP_TRUNCATE(vp, (off_t)0, IO_NDELAY, NOCRED, p);
			cp->c_mode = mode;
			if (error)
				goto out;
			truncated = 1;
		}
		if (!rsrcforkbusy && rvp) {
			cp->c_mode = 0;            /* Suppress VOP_UPDATES */
			error = VOP_TRUNCATE(rvp, (off_t)0, IO_NDELAY, NOCRED, p);
			cp->c_mode = mode;
			if (error)
				goto out;
			truncated = 1;
		}
	}
	/*
	 * There are 3 remove cases to consider:
	 *   1. File is a hardlink    ==> remove the link
	 *   2. File is busy (in use) ==> move/rename the file
	 *   3. File is not in use    ==> remove the file
	 */

	if (cp->c_flag & C_HARDLINK) {
		struct cat_desc desc;

		if ((cnp->cn_flags & HASBUF) == 0 ||
		    cnp->cn_nameptr[0] == '\0') {
			error = ENOENT;	/* name missing! */
			goto out;
		}

		/* Setup a descriptor for the link */
		bzero(&desc, sizeof(desc));
		desc.cd_nameptr = cnp->cn_nameptr;
		desc.cd_namelen = cnp->cn_namelen;
		desc.cd_parentcnid = dcp->c_cnid;
		/* XXX - if cnid is out of sync then the wrong thread rec will get deleted. */
		desc.cd_cnid = cp->c_cnid;

		/* Lock catalog b-tree */
		error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
		if (error)
			goto out;

		/* Delete the link record */
		error = cat_delete(hfsmp, &desc, &cp->c_attr);

		if ((error == 0) && (--cp->c_nlink < 1)) {
			char inodename[32];
			char delname[32];
			struct cat_desc to_desc;
			struct cat_desc from_desc;

			/*
			 * This is now esentially an open deleted file.
			 * Rename it to reflect this state which makes
			 * orphan file cleanup easier (see hfs_remove_orphans).
			 * Note: a rename failure here is not fatal.
			 */	
			MAKE_INODE_NAME(inodename, cp->c_rdev);
			bzero(&from_desc, sizeof(from_desc));
			from_desc.cd_nameptr = inodename;
			from_desc.cd_namelen = strlen(inodename);
			from_desc.cd_parentcnid = hfsmp->hfs_privdir_desc.cd_cnid;
			from_desc.cd_flags = 0;
			from_desc.cd_cnid = cp->c_fileid;

			MAKE_DELETED_NAME(delname, cp->c_fileid);		
			bzero(&to_desc, sizeof(to_desc));
			to_desc.cd_nameptr = delname;
			to_desc.cd_namelen = strlen(delname);
			to_desc.cd_parentcnid = hfsmp->hfs_privdir_desc.cd_cnid;
			to_desc.cd_flags = 0;
			to_desc.cd_cnid = cp->c_fileid;
	
			(void) cat_rename(hfsmp, &from_desc, &hfsmp->hfs_privdir_desc,
			                  &to_desc, (struct cat_desc *)NULL);
			cp->c_flag |= C_DELETED;
		}

		/* Unlock the Catalog */
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

		if (error != 0)
			goto out;

		cp->c_flag |= C_CHANGE;
		tv = time;
		(void) VOP_UPDATE(vp, &tv, &tv, 0);

		hfs_volupdate(hfsmp, VOL_RMFILE, (dcp->c_cnid == kHFSRootFolderID));

	} else if (dataforkbusy || rsrcforkbusy || isbigfile) {
		char delname[32];
		struct cat_desc to_desc;
		struct cat_desc todir_desc;

		/*
		 * Orphan this file (move to hidden directory).
		 */
		bzero(&todir_desc, sizeof(todir_desc));
		todir_desc.cd_parentcnid = 2;

		MAKE_DELETED_NAME(delname, cp->c_fileid);		
		bzero(&to_desc, sizeof(to_desc));
		to_desc.cd_nameptr = delname;
		to_desc.cd_namelen = strlen(delname);
		to_desc.cd_parentcnid = hfsmp->hfs_privdir_desc.cd_cnid;
		to_desc.cd_flags = 0;
		to_desc.cd_cnid = cp->c_cnid;

		/* Lock catalog b-tree */
		error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
		if (error)
			goto out;

		error = cat_rename(hfsmp, &cp->c_desc, &todir_desc,
				&to_desc, (struct cat_desc *)NULL);

		// XXXdbg - only bump this count if we were successful
		if (error == 0) {
			hfsmp->hfs_privdir_attr.ca_entries++;
		}
		(void)cat_update(hfsmp, &hfsmp->hfs_privdir_desc,
				&hfsmp->hfs_privdir_attr, NULL, NULL);

		/* Unlock the Catalog */
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);
		if (error) goto out;

		cp->c_flag |= C_CHANGE | C_DELETED | C_NOEXISTS;
		--cp->c_nlink;
		tv = time;
		(void) VOP_UPDATE(vp, &tv, &tv, 0);

	} else /* Not busy */ {

		if (cp->c_blocks > 0) {
#if 0
			panic("hfs_remove: attempting to delete a non-empty file!");
#else
			printf("hfs_remove: attempting to delete a non-empty file %s\n",
				cp->c_desc.cd_nameptr);
			error = EBUSY;
			goto out;
#endif
		}

		/* Lock catalog b-tree */
		error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
		if (error)
			goto out;

		error = cat_delete(hfsmp, &cp->c_desc, &cp->c_attr);

		if (error && error != ENXIO && error != ENOENT && truncated) {
			if ((cp->c_datafork && cp->c_datafork->ff_size != 0) ||
				(cp->c_rsrcfork && cp->c_rsrcfork->ff_size != 0)) {
				panic("hfs: remove: couldn't delete a truncated file! (%d, data sz %lld; rsrc sz %lld)",
					  error, cp->c_datafork->ff_size, cp->c_rsrcfork->ff_size);
			} else {
				printf("hfs: remove: strangely enough, deleting truncated file %s (%d) got err %d\n",
					   cp->c_desc.cd_nameptr, cp->c_attr.ca_fileid, error);
			}
		}

		/* Unlock the Catalog */
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);
		if (error) goto out;

#if QUOTA
		(void)hfs_chkiq(cp, -1, NOCRED, 0);
#endif /* QUOTA */

		cp->c_mode = 0;
		truncated  = 0;    // because the catalog entry is gone
		cp->c_flag |= C_CHANGE | C_NOEXISTS;
		--cp->c_nlink;
		hfs_volupdate(hfsmp, VOL_RMFILE, (dcp->c_cnid == kHFSRootFolderID));
	}

	/*
	 * All done with this cnode's descriptor...
	 *
	 * Note: all future catalog calls for this cnode must be
	 * by fileid only.  This is OK for HFS (which doesn't have
	 * file thread records) since HFS doesn't support hard
	 * links or the removal of busy files.
	 */
	cat_releasedesc(&cp->c_desc);

	/* In all three cases the parent lost a child */
	if (dcp->c_entries > 0)
		dcp->c_entries--;
	if (dcp->c_nlink > 0)
		dcp->c_nlink--;
	dcp->c_flag |= C_CHANGE | C_UPDATE;
	tv = time;
	(void) VOP_UPDATE(dvp, &tv, &tv, 0);
	HFS_KNOTE(dvp, NOTE_WRITE);

out:
	/* All done with component name... */
	if ((options & HFSRM_SAVE_NAME) == 0 &&
	    (cnp != 0) &&
	    (cnp->cn_flags & (HASBUF | SAVENAME)) == (HASBUF | SAVENAME)) {
		char *tmp = cnp->cn_pnbuf;
		cnp->cn_pnbuf = NULL;
		cnp->cn_flags &= ~HASBUF;
		FREE_ZONE(tmp, cnp->cn_pnlen, M_NAMEI);
	}

	if (!(options & HFSRM_SKIP_RESERVE)) {
		cat_postflight(hfsmp, &cookie, p);
	}

	/* Commit the truncation to the catalog record */
	if (truncated) {
	    cp->c_flag |= C_CHANGE | C_UPDATE | C_FORCEUPDATE;
	    tv = time;
	    (void) VOP_UPDATE(vp, &tv, &tv, 0);
	}

	// XXXdbg
	if (started_tr) {
	    journal_end_transaction(hfsmp->jnl);
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
	}

	HFS_KNOTE(vp, NOTE_DELETE);
	if (rvp) {
		HFS_KNOTE(rvp, NOTE_DELETE);
		vrele(rvp);
	};

	if (error) {
		vput(vp);
	} else {
		VOP_UNLOCK(vp, 0, p);
		// XXXdbg - try to prevent the lost ubc_info panic
		if ((cp->c_flag & C_HARDLINK) == 0 || cp->c_nlink == 0) {
			(void) ubc_uncache(vp);
		}
		vrele(vp);
	}
	if (!(options & HFSRM_PARENT_LOCKED)) {
		vput(dvp);
	}

	return (error);
}


__private_extern__ void
replace_desc(struct cnode *cp, struct cat_desc *cdp)
{
	/* First release allocated name buffer */
	if (cp->c_desc.cd_flags & CD_HASBUF && cp->c_desc.cd_nameptr != 0) {
		char *name = cp->c_desc.cd_nameptr;

		cp->c_desc.cd_nameptr = 0;
		cp->c_desc.cd_namelen = 0;
		cp->c_desc.cd_flags &= ~CD_HASBUF;
		remove_name(name);
	}
	bcopy(cdp, &cp->c_desc, sizeof(cp->c_desc));

	/* Cnode now owns the name buffer */
	cdp->cd_nameptr = 0;
	cdp->cd_namelen = 0;
	cdp->cd_flags &= ~CD_HASBUF;
}


/*
#
#% rename	fdvp   U U U
#% rename	fvp    U U U
#% rename	tdvp   L U U
#% rename	tvp    X U U
#
*/
/*
 * Rename a cnode.
 *
 * The VFS layer guarantees that source and destination will
 * either both be directories, or both not be directories.
 *
 * When the target is a directory, hfs_rename must ensure
 * that it is empty.
 *
 * The rename system call is responsible for freeing
 * the pathname buffers (ie no need to call VOP_ABORTOP).
 */

static int
hfs_rename(ap)
	struct vop_rename_args  /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
	} */ *ap;
{
	struct vnode *tvp = ap->a_tvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *fdvp = ap->a_fdvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct componentname *fcnp = ap->a_fcnp;
	struct proc *p = fcnp->cn_proc;
	struct cnode *fcp = NULL;
	struct cnode *fdcp = NULL;
	struct cnode *tdcp = VTOC(tdvp);
	struct cat_desc from_desc;
	struct cat_desc to_desc;
	struct cat_desc out_desc;
	struct hfsmount *hfsmp = NULL;
	struct timeval tv;
	cat_cookie_t cookie = {0};
	int fdvp_locked, fvp_locked, tdvp_locked, tvp_locked;
	int tvp_deleted;
	int started_tr = 0, grabbed_lock = 0;
	int error = 0;


	/* Establish our vnode lock state. */
	tdvp_locked = 1;
	tvp_locked = (tvp != 0);
	fdvp_locked = 0;
	fvp_locked = 0;
	tvp_deleted = 0;

	/*
	 * Check for cross-device rename.
	 */
	if ((fvp->v_mount != tdvp->v_mount) ||
	    (tvp && (fvp->v_mount != tvp->v_mount))) {
		error = EXDEV;
		goto out;
	}

	/*
	 * When fvp matches tvp they must be case variants
	 * or hard links.
	 *
	 * In some cases tvp will be locked in other cases
	 * it be unlocked with no reference.  Normalize the
	 * state here (unlocked with a reference) so that
	 * we can exit in a known state.
	 */
	if (fvp == tvp) {
		if (VOP_ISLOCKED(tvp) &&
		    (VTOC(tvp)->c_lock.lk_lockholder == p->p_pid) &&
		    (VTOC(tvp)->c_lock.lk_lockthread == current_thread())) {
			vput(tvp);
		}
		tvp = NULL;
		tvp_locked = 0;

		/*
		 * If this a hard link with different parents
		 * and its not a case variant then keep tvp
		 * around for removal.
		 */
		if ((VTOC(fvp)->c_flag & C_HARDLINK) &&
		    ((fdvp != tdvp) ||
		     (hfs_namecmp(fcnp->cn_nameptr, fcnp->cn_namelen,
		                  tcnp->cn_nameptr, tcnp->cn_namelen) != 0))) {
			tvp = fvp;
			vref(tvp);
		}
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
	if (tdcp->c_parentcnid == VTOC(fvp)->c_cnid) {
		error = EINVAL;
		goto out;
	}

	/*
	 * The following two edge cases are caught here:
	 * (note tvp is not empty)
	 *
	 *       o tdvp               o tdvp
	 *      /                    /
	 *     /                    /
	 *    o tvp            tvp o fdvp
	 *     \                    \
	 *      \                    \
	 *       o fdvp               o fvp
	 *      /
	 *     /
	 *    o fvp
	 */
	if (tvp && (tvp->v_type == VDIR) && (VTOC(tvp)->c_entries != 0)) {
		error = ENOTEMPTY;
		goto out;
	}

	/*
	 * The following edge case is caught here:
	 * (the from child and parent are the same)
	 *
	 *          o tdvp
	 *         /
	 *        /
	 *  fdvp o fvp
	 */
	if (fdvp == fvp) {
		error = EINVAL;
		goto out;
	}

	/*
	 * Make sure "from" vnode and its parent are changeable.
	 */
	if ((VTOC(fvp)->c_flags & (IMMUTABLE | APPEND)) ||
	    (VTOC(fdvp)->c_flags & APPEND)) {
		error = EPERM;
		goto out;
	}

	hfsmp = VTOHFS(tdvp);

	/*
	 * If the destination parent directory is "sticky", then the
	 * user must own the parent directory, or the destination of
	 * the rename, otherwise the destination may not be changed
	 * (except by root). This implements append-only directories.
	 *
	 * Note that checks for immutable and write access are done
	 * by the call to VOP_REMOVE.
	 */
	if (tvp && (tdcp->c_mode & S_ISTXT) &&
	    (tcnp->cn_cred->cr_uid != 0) &&
	    (tcnp->cn_cred->cr_uid != tdcp->c_uid) &&
	    (hfs_owner_rights(hfsmp, VTOC(tvp)->c_uid, tcnp->cn_cred, p, false)) ) {
		error = EPERM;
		goto out;
	}

#if QUOTA
	if (tvp)
		(void)hfs_getinoquota(VTOC(tvp));
#endif

	/*
	 * Lock all the vnodes before starting a journal transaction.
	 */

	/*
	 * Simple case (same parent) - just lock child (fvp).
	 */
	if (fdvp == tdvp) {
		if (error = vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY, p))
			goto out;
		fvp_locked = 1;
		goto vnlocked;
	}

	/*
	 * If fdvp is the parent of tdvp then we'll need to
	 * drop tdvp's lock before acquiring a lock on fdvp.
	 *
	 *          fdvp
	 *           o 
	 *          / \
	 *         /   \
	 *   tdvp o     o fvp
	 *         \
	 *          \
	 *           o tvp
	 *
	 *
	 * If the parent directories are unrelated then we'll
	 * need to aquire their vnode locks in vnode address
	 * order.  Otherwise we can race with another rename
	 * call that involves the same vnodes except that to
	 * and from are switched and potentially deadlock.
	 * [ie rename("a/b", "c/d") vs rename("c/d", "a/b")]
	 *
	 * If its not either of the two above cases then we
	 * can safely lock fdvp and fvp.
	 */
	if ((VTOC(fdvp)->c_cnid == VTOC(tdvp)->c_parentcnid) ||
	    ((VTOC(tdvp)->c_cnid != VTOC(fdvp)->c_parentcnid) &&
	     (fdvp < tdvp))) {

		/* Drop locks on tvp and tdvp */
		if (tvp_locked) {
			VOP_UNLOCK(tvp, 0, p);
			tvp_locked = 0;
		}
		VOP_UNLOCK(tdvp, 0, p);
		tdvp_locked = 0;

		/* Aquire locks in correct order */
		if ((error = vn_lock(fdvp, LK_EXCLUSIVE | LK_RETRY, p)))
			goto out;
		fdvp_locked = 1;
		if ((error = vn_lock(tdvp, LK_EXCLUSIVE | LK_RETRY, p)))
			goto out;
		tdvp_locked = 1;

		/*
		 * Now that the parents are locked only one thread
		 * can continue. So the lock order of the children
		 * doesn't really matter
		 */
		if (tvp == fvp) {
			if ((error = vn_lock(tvp, LK_EXCLUSIVE | LK_RETRY, p)))
				goto out;
			tvp_locked = 1;
		} else {
			if (tvp) {
				if ((error = vn_lock(tvp, LK_EXCLUSIVE | LK_RETRY, p)))
					goto out;
				tvp_locked = 1;
			}
			if ((error = vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY, p)))
				goto out;
			fvp_locked = 1;
		}

	} else /* OK to lock fdvp and fvp */ {
		if ((error = vn_lock(fdvp, LK_EXCLUSIVE | LK_RETRY, p)))
			goto out;
		fdvp_locked = 1;
		if (error = vn_lock(fvp, LK_EXCLUSIVE | LK_RETRY, p))
			goto out;
		if (tvp == fvp)
			tvp_locked = 1;
		else
			fvp_locked = 1;
	}

vnlocked:
	fdcp = VTOC(fdvp);
	fcp = VTOC(fvp);

	/* 
	 * While fvp is still locked, purge it from the name cache and
	 * grab it's c_cnid value.  Note that the removal of tvp (below)
	 * can drop fvp's lock when fvp == tvp.
	 */
	cache_purge(fvp);

	/*
	 * When a file moves out of "Cleanup At Startup"
	 * we can drop its NODUMP status.
	 */
	if ((fcp->c_flags & UF_NODUMP) &&
	    (fvp->v_type == VREG) &&
	    (fdvp != tdvp) &&
	    (fdcp->c_desc.cd_nameptr != NULL) &&
	    (strcmp(fdcp->c_desc.cd_nameptr, CARBON_TEMP_DIR_NAME) == 0)) {
		fcp->c_flags &= ~UF_NODUMP;
		fcp->c_flag |= C_CHANGE;
		tv = time;
		(void) VOP_UPDATE(fvp, &tv, &tv, 0);
	}

	bzero(&from_desc, sizeof(from_desc));
	from_desc.cd_nameptr = fcnp->cn_nameptr;
	from_desc.cd_namelen = fcnp->cn_namelen;
	from_desc.cd_parentcnid = fdcp->c_cnid;
	from_desc.cd_flags = fcp->c_desc.cd_flags & ~(CD_HASBUF | CD_DECOMPOSED);
	from_desc.cd_cnid = fcp->c_cnid;

	bzero(&to_desc, sizeof(to_desc));
	to_desc.cd_nameptr = tcnp->cn_nameptr;
	to_desc.cd_namelen = tcnp->cn_namelen;
	to_desc.cd_parentcnid = tdcp->c_cnid;
	to_desc.cd_flags = fcp->c_desc.cd_flags & ~(CD_HASBUF | CD_DECOMPOSED);
	to_desc.cd_cnid = fcp->c_cnid;

	hfs_global_shared_lock_acquire(hfsmp);
	grabbed_lock = 1;
	if (hfsmp->jnl) {
	    if ((error = journal_start_transaction(hfsmp->jnl)) != 0) {
			goto out;
	    }
		started_tr = 1;
	}

	/*
	 * Reserve some space in the Catalog file.
	 */
	if ((error = cat_preflight(hfsmp, CAT_RENAME + CAT_DELETE, &cookie, p))) {
		goto out;
	}

	/*
	 * If the destination exists then it needs to be removed.
	 */

	if (tvp) {
		if (tvp != fvp)
			cache_purge(tvp);
		/*
		 * Note that hfs_removedir and hfs_removefile
		 * will keep tdvp locked with a reference.
		 * But tvp will lose its lock and reference.
		 */
		if (tvp->v_type == VDIR)
			error = hfs_removedir(tdvp, tvp, tcnp, HFSRM_RENAMEOPTS);
		else
			error = hfs_removefile(tdvp, tvp, tcnp, HFSRM_RENAMEOPTS);

		if (tvp == fvp)
			fvp_locked = 0;
		tvp = NULL;
		tvp_locked = 0;
		tvp_deleted = 1;
		if (error)
			goto out;
	}

	/*
	 * All done with tvp and fvp
	 */

	/* Lock catalog b-tree */
	error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (error)
		 goto out;

	error = cat_rename(hfsmp, &from_desc, &tdcp->c_desc, &to_desc, &out_desc);

	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

	if (error) {
		goto out;
	}

	/* Update cnode's catalog descriptor */
	if (fvp_locked) {
   		replace_desc(fcp, &out_desc);
		fcp->c_parentcnid = tdcp->c_cnid;
		fcp->c_hint = 0;
	}

	hfs_volupdate(hfsmp, fvp->v_type == VDIR ? VOL_RMDIR : VOL_RMFILE,
	              (fdcp->c_cnid == kHFSRootFolderID));
	hfs_volupdate(hfsmp, fvp->v_type == VDIR ? VOL_MKDIR : VOL_MKFILE,
	              (tdcp->c_cnid == kHFSRootFolderID));

	/* Update both parent directories. */
	tv = time;
	if (fdvp != tdvp) {
		tdcp->c_nlink++;
		tdcp->c_entries++;
		if (fdcp->c_nlink > 0)
			fdcp->c_nlink--;
		if (fdcp->c_entries > 0)
			fdcp->c_entries--;
		fdcp->c_flag |= C_CHANGE | C_UPDATE;
		(void) VOP_UPDATE(fdvp, &tv, &tv, 0);
	}
	tdcp->c_childhint = out_desc.cd_hint;	/* Cache directory's location */
	tdcp->c_flag |= C_CHANGE | C_UPDATE;
	(void) VOP_UPDATE(tdvp, &tv, &tv, 0);

out:
	if (hfsmp) {
		cat_postflight(hfsmp, &cookie, p);
	}
	if (started_tr) {
	    journal_end_transaction(hfsmp->jnl);
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
	}

	/* Note that if hfs_removedir or hfs_removefile was invoked above they will already have
	   generated a NOTE_WRITE for tdvp and a NOTE_DELETE for tvp.
	 */
	if (error == 0) {
		HFS_KNOTE(fvp, NOTE_RENAME);
		HFS_KNOTE(fdvp, NOTE_WRITE);
		if (tdvp != fdvp) HFS_KNOTE(tdvp, NOTE_WRITE);
	};
	if (fvp_locked) {
		VOP_UNLOCK(fvp, 0, p);
	}
	if (fdvp_locked) {
		VOP_UNLOCK(fdvp, 0, p);
	}
	if (tdvp_locked) {
		VOP_UNLOCK(tdvp, 0, p);
	}
	if (tvp_locked) {
		VOP_UNLOCK(tvp, 0, p);
	}

	vrele(fvp);
	vrele(fdvp);
	if (tvp)
		vrele(tvp);
	vrele(tdvp);

	/* After tvp is removed the only acceptable error is EIO */
	if (error && tvp_deleted)
		error = EIO;

	return (error);
}



/*
 * Mkdir system call
#% mkdir	dvp	L U U
#% mkdir	vpp	- L -
#
 vop_mkdir {
     IN WILLRELE struct vnode *dvp;
     OUT struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;

     We are responsible for freeing the namei buffer,
	 it is done in hfs_makenode()
*/

static int
hfs_mkdir(ap)
	struct vop_mkdir_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
	} */ *ap;
{
	struct vattr *vap = ap->a_vap;

	return (hfs_makenode(MAKEIMODE(vap->va_type, vap->va_mode),
	                     ap->a_dvp, ap->a_vpp, ap->a_cnp));
}


/*
 * symlink -- make a symbolic link
#% symlink	dvp	L U U
#% symlink	vpp	- U -
#
# XXX - note that the return vnode has already been VRELE'ed
#	by the filesystem layer.  To use it you must use vget,
#	possibly with a further namei.
#
 vop_symlink {
     IN WILLRELE struct vnode *dvp;
     OUT WILLRELE struct vnode **vpp;
     IN struct componentname *cnp;
     IN struct vattr *vap;
     IN char *target;

     We are responsible for freeing the namei buffer, 
	 it is done in hfs_makenode().

*/

static int
hfs_symlink(ap)
	struct vop_symlink_args /* {
		struct vnode *a_dvp;
		struct vnode **a_vpp;
		struct componentname *a_cnp;
		struct vattr *a_vap;
		char *a_target;
	} */ *ap;
{
	register struct vnode *vp, **vpp = ap->a_vpp;
	struct hfsmount *hfsmp;
	struct filefork *fp;
	int len, error;
	struct buf *bp = NULL;

	/* HFS standard disks don't support symbolic links */
	if (VTOVCB(ap->a_dvp)->vcbSigWord != kHFSPlusSigWord) {
		VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
		vput(ap->a_dvp);
		return (EOPNOTSUPP);
	}

	/* Check for empty target name */
	if (ap->a_target[0] == 0) {
		VOP_ABORTOP(ap->a_dvp, ap->a_cnp);
		vput(ap->a_dvp);
		return (EINVAL);
	}


	hfsmp = VTOHFS(ap->a_dvp);

	/* Create the vnode */
	if ((error = hfs_makenode(S_IFLNK | ap->a_vap->va_mode,
							  ap->a_dvp, vpp, ap->a_cnp))) {
		return (error);
	}

	vp = *vpp;
	len = strlen(ap->a_target);
	fp = VTOF(vp);

#if QUOTA
	(void)hfs_getinoquota(VTOC(vp));
#endif /* QUOTA */

	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
	    if ((error = journal_start_transaction(hfsmp->jnl)) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			vput(vp);
			return error;
	    }
	}

	/* Allocate space for the link */
	error = VOP_TRUNCATE(vp, len, IO_NOZEROFILL,
	                      ap->a_cnp->cn_cred, ap->a_cnp->cn_proc);
	if (error)
		goto out;	/* XXX need to remove link */

	/* Write the link to disk */
	bp = getblk(vp, 0, roundup((int)fp->ff_size, VTOHFS(vp)->hfs_phys_block_size),
			0, 0, BLK_META);
	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, bp);
	}
	bzero(bp->b_data, bp->b_bufsize);
	bcopy(ap->a_target, bp->b_data, len);
	if (hfsmp->jnl) {
		journal_modify_block_end(hfsmp->jnl, bp);
	} else {
		bawrite(bp);
	}
out:
	if (hfsmp->jnl) {
		journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);
	vput(vp);
	return (error);
}


/*
 * Dummy dirents to simulate the "." and ".." entries of the directory
 * in a hfs filesystem.  HFS doesn't provide these on disk.  Note that
 * the size of these entries is the smallest needed to represent them
 * (only 12 byte each).
 */
static hfsdotentry  rootdots[2] = {
	{
		1,				/* d_fileno */
		sizeof(struct hfsdotentry),	/* d_reclen */
		DT_DIR,				/* d_type */
		1,				/* d_namlen */
		"."				/* d_name */
    },
    {
		1,				/* d_fileno */
		sizeof(struct hfsdotentry),	/* d_reclen */
		DT_DIR,				/* d_type */
		2,				/* d_namlen */
		".."				/* d_name */
	}
};

/*	4.3 Note:
*	There is some confusion as to what the semantics of uio_offset are.
*	In ufs, it represents the actual byte offset within the directory
*	"file."  HFS, however, just uses it as an entry counter - essentially
*	assuming that it has no meaning except to the hfs_readdir function.
*	This approach would be more efficient here, but some callers may
*	assume the uio_offset acts like a byte offset.  NFS in fact
*	monkeys around with the offset field a lot between readdir calls.
*
*	The use of the resid uiop->uio_resid and uiop->uio_iov->iov_len
*	fields is a mess as well.  The libc function readdir() returns
*	NULL (indicating the end of a directory) when either
*	the getdirentries() syscall (which calls this and returns
*	the size of the buffer passed in less the value of uiop->uio_resid)
*	returns 0, or a direct record with a d_reclen of zero.
*	nfs_server.c:rfs_readdir(), on the other hand, checks for the end
*	of the directory by testing uiop->uio_resid == 0.  The solution
*	is to pad the size of the last struct direct in a given
*	block to fill the block if we are not at the end of the directory.
*/


/*
 * NOTE: We require a minimal buffer size of DIRBLKSIZ for two reasons. One, it is the same value
 * returned be stat() call as the block size. This is mentioned in the man page for getdirentries():
 * "Nbytes must be greater than or equal to the block size associated with the file,
 * see stat(2)". Might as well settle on the same size of ufs. Second, this makes sure there is enough
 * room for the . and .. entries that have to added manually.
 */

/* 			
#% readdir	vp	L L L
#
vop_readdir {
    IN struct vnode *vp;
    INOUT struct uio *uio;
    IN struct ucred *cred;
    INOUT int *eofflag;
    OUT int *ncookies;
    INOUT u_long **cookies;
    */
static int
hfs_readdir(ap)
	struct vop_readdir_args /* {
		struct vnode *vp;
		struct uio *uio;
		struct ucred *cred;
		int *eofflag;
		int *ncookies;
		u_long **cookies;
	} */ *ap;
{
	register struct uio *uio = ap->a_uio;
	struct cnode *cp = VTOC(ap->a_vp);
	struct hfsmount *hfsmp = VTOHFS(ap->a_vp);
	struct proc *p = current_proc();
	off_t off = uio->uio_offset;
	int retval = 0;
	int eofflag = 0;
	void *user_start = NULL;
	int   user_len;

	int ncookies=0;
	u_long *cookies=NULL;
	u_long *cookiep=NULL;
 
	/* We assume it's all one big buffer... */
	if (uio->uio_iovcnt > 1 || uio->uio_resid < AVERAGE_HFSDIRENTRY_SIZE)
		return EINVAL;

	// XXXdbg
	// We have to lock the user's buffer here so that we won't
	// fault on it after we've acquired a shared lock on the
	// catalog file.  The issue is that you can get a 3-way
	// deadlock if someone else starts a transaction and then
	// tries to lock the catalog file but can't because we're
	// here and we can't service our page fault because VM is
	// blocked trying to start a transaction as a result of
	// trying to free up pages for our page fault.  It's messy
	// but it does happen on dual-procesors that are paging
	// heavily (see radar 3082639 for more info).  By locking
	// the buffer up-front we prevent ourselves from faulting
	// while holding the shared catalog file lock.
	//
	// Fortunately this and hfs_search() are the only two places
	// currently (10/30/02) that can fault on user data with a
	// shared lock on the catalog file.
	//
	if (hfsmp->jnl && uio->uio_segflg == UIO_USERSPACE) {
		user_start = uio->uio_iov->iov_base;
		user_len   = uio->uio_iov->iov_len;

		if ((retval = vslock(user_start, user_len)) != 0) {
			return retval;
		}
	}

	/* Create the entries for . and .. */
	if (uio->uio_offset < sizeof(rootdots)) {
		caddr_t dep;
		size_t dotsize;
		
		rootdots[0].d_fileno = cp->c_cnid;
		rootdots[1].d_fileno = cp->c_parentcnid;

		if (uio->uio_offset == 0) {
			dep = (caddr_t) &rootdots[0];
			dotsize = 2* sizeof(struct hfsdotentry);
		} else if (uio->uio_offset == sizeof(struct hfsdotentry)) {
			dep = (caddr_t) &rootdots[1];
			dotsize = sizeof(struct hfsdotentry);
		} else {
			retval = EINVAL;
			goto Exit;
		}

		retval = uiomove(dep, dotsize, uio);
		if (retval != 0)
			goto Exit;
	}

	if (ap->a_ncookies != NULL) {
		/*
		 * These cookies are handles that allow NFS to restart
		 * scanning through a directory.  If a directory is large
		 * enough, NFS will issue a successive readdir() with a
		 * uio->uio_offset that is equal to one of these cookies.
		 *
		 * The cookies that we generate are synthesized byte-offsets.
		 * The offset is where the dirent the dirent would be if the
		 * directory were an array of packed dirent structs.  It is
		 * synthetic because that's not how directories are stored in
		 * HFS but other code expects that the cookie is a byte offset.
		 *
		 * We have to pre-allocate the cookies because cat_getdirentries()
		 * is the only one that can properly synthesize the offsets (since
		 * it may have to skip over entries and only it knows the true
		 * virtual offset of any particular directory entry). So we allocate
		 * a cookie table here and pass it in to cat_getdirentries().
		 *
		 * Note that the handling of "." and ".." is mostly done here but
		 * cat_getdirentries() is aware of.
		 *
		 * Only the NFS server uses cookies so fortunately this code is
		 * not executed unless the NFS server is issuing the readdir
		 * request.
		 *
		 * Also note that the NFS server is the one responsible for
		 * free'ing the cookies even though we allocated them.  Ick.
		 *
		 * We allocate a reasonable number of entries for the size of
		 * the buffer that we're going to fill in.  cat_getdirentries()
		 * is smart enough to not overflow if there's more room in the
		 * buffer but not enough room in the cookie table.
		 */
		if (uio->uio_segflg != UIO_SYSSPACE)
			panic("hfs_readdir: unexpected uio from NFS server");

		ncookies = uio->uio_iov->iov_len / (AVERAGE_HFSDIRENTRY_SIZE/2);
		MALLOC(cookies, u_long *, ncookies * sizeof(u_long), M_TEMP, M_WAITOK);

		*ap->a_ncookies = ncookies;
		*ap->a_cookies = cookies;
	}

	/* If there are no children then we're done */	
	if (cp->c_entries == 0) {
		eofflag = 1;
		retval = 0;
		if (cookies) {
		    cookies[0] = 0;
		    cookies[1] = sizeof(struct hfsdotentry);
		}
		goto Exit;
	}

	/* Lock catalog b-tree */
	retval = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_SHARED, p);
	if (retval) goto Exit;

	retval = cat_getdirentries(hfsmp, &cp->c_desc, cp->c_entries, uio, &eofflag, cookies, ncookies);

	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

	if (retval != E_NONE) {
		goto Exit;
	}
	
	/* were we already past eof ? */
	if (uio->uio_offset == off) {
		retval = E_NONE;
		goto Exit;
	}
	
	cp->c_flag |= C_ACCESS;

Exit:;
	if (hfsmp->jnl && user_start) {
		vsunlock(user_start, user_len, TRUE);
	}

	if (ap->a_eofflag)
		*ap->a_eofflag = eofflag;

    return (retval);
}


/*
 * Return target name of a symbolic link
#% readlink	vp	L L L
#
 vop_readlink {
     IN struct vnode *vp;
     INOUT struct uio *uio;
     IN struct ucred *cred;
     */

static int
hfs_readlink(ap)
	struct vop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
	} */ *ap;
{
	int retval;
	struct vnode *vp = ap->a_vp;
	struct cnode *cp;
	struct filefork *fp;

	if (vp->v_type != VLNK)
		return (EINVAL);
 
	cp = VTOC(vp);
	fp = VTOF(vp);
   
	/* Zero length sym links are not allowed */
	if (fp->ff_size == 0 || fp->ff_size > MAXPATHLEN) {
		VTOVCB(vp)->vcbFlags |= kHFS_DamagedVolume;
		return (EINVAL);
	}
    
	/* Cache the path so we don't waste buffer cache resources */
	if (fp->ff_symlinkptr == NULL) {
		struct buf *bp = NULL;

		MALLOC(fp->ff_symlinkptr, char *, fp->ff_size, M_TEMP, M_WAITOK);
		retval = meta_bread(vp, 0,
				roundup((int)fp->ff_size,
					VTOHFS(vp)->hfs_phys_block_size),
						ap->a_cred, &bp);
		if (retval) {
			if (bp)
				brelse(bp);
			if (fp->ff_symlinkptr) {
				FREE(fp->ff_symlinkptr, M_TEMP);
				fp->ff_symlinkptr = NULL;
			}
			return (retval);
		}
		bcopy(bp->b_data, fp->ff_symlinkptr, (size_t)fp->ff_size);
		if (bp) {
			if (VTOHFS(vp)->jnl && (bp->b_flags & B_LOCKED) == 0) {
				bp->b_flags |= B_INVAL;		/* data no longer needed */
			}
			brelse(bp);
		}
	}
	retval = uiomove((caddr_t)fp->ff_symlinkptr, (int)fp->ff_size, ap->a_uio);
#if 1
	/*
	 * Keep track blocks read
	 */
	if ((VTOHFS(vp)->hfc_stage == HFC_RECORDING) && (retval == 0)) {
		
		/*
		 * If this file hasn't been seen since the start of
		 * the current sampling period then start over.
		 */
		if (cp->c_atime < VTOHFS(vp)->hfc_timebase)
			VTOF(vp)->ff_bytesread = fp->ff_size;
		else
			VTOF(vp)->ff_bytesread += fp->ff_size;
		
	//	if (VTOF(vp)->ff_bytesread > fp->ff_size)
	//		cp->c_flag |= C_ACCESS;
	}
#endif
	return (retval);
}

/*
 * Lock an cnode. If its already locked, set the WANT bit and sleep.
#% lock		vp	U L U
#
 vop_lock {
     IN struct vnode *vp;
     IN int flags;
     IN struct proc *p;
     */

static int
hfs_lock(ap)
	struct vop_lock_args /* {
		struct vnode *a_vp;
		int a_flags;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);

	return (lockmgr(&cp->c_lock, ap->a_flags, &vp->v_interlock, ap->a_p));
}

/*
 * Unlock an cnode.
#% unlock	vp	L U L
#
 vop_unlock {
     IN struct vnode *vp;
     IN int flags;
     IN struct proc *p;

     */
static int
hfs_unlock(ap)
	struct vop_unlock_args /* {
		struct vnode *a_vp;
		int a_flags;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);
#if 0
	if (!lockstatus(&cp->c_lock)) {
		printf("hfs_unlock: vnode %s wasn't locked!\n",
			cp->c_desc.cd_nameptr ? cp->c_desc.cd_nameptr : "");
	}
#endif
	return (lockmgr(&cp->c_lock, ap->a_flags | LK_RELEASE,
		&vp->v_interlock, ap->a_p));
}


/*
 * Print out the contents of a cnode.
#% print	vp	= = =
#
 vop_print {
     IN struct vnode *vp;
     */
static int
hfs_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode * vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);

	printf("tag VT_HFS, cnid %d, on dev %d, %d", cp->c_cnid,
		major(cp->c_dev), minor(cp->c_dev));
#if FIFO
	if (vp->v_type == VFIFO)
		fifo_printinfo(vp);
#endif /* FIFO */
	lockmgr_printinfo(&cp->c_lock);
	printf("\n");
	return (0);
}


/*
 * Check for a locked cnode.
#% islocked	vp	= = =
#
 vop_islocked {
     IN struct vnode *vp;

     */
static int
hfs_islocked(ap)
	struct vop_islocked_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	return (lockstatus(&VTOC(ap->a_vp)->c_lock));
}

/*

#% pathconf	vp	L L L
#
 vop_pathconf {
     IN struct vnode *vp;
     IN int name;
     OUT register_t *retval;

     */
static int
hfs_pathconf(ap)
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		int *a_retval;
	} */ *ap;
{
	int retval = 0;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		if (VTOVCB(ap->a_vp)->vcbSigWord == kHFSPlusSigWord)
			*ap->a_retval = HFS_LINK_MAX;
		else
			*ap->a_retval = 1;
		break;
	case _PC_NAME_MAX:
		*ap->a_retval = kHFSPlusMaxFileNameBytes;	/* max # of characters x max utf8 representation */
		break;
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX; /* 1024 */
		break;
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		break;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		break;
	case _PC_NO_TRUNC:
		*ap->a_retval = 0;
		break;
	case _PC_NAME_CHARS_MAX:
		*ap->a_retval = kHFSPlusMaxFileNameChars;
		break;
	case _PC_CASE_SENSITIVE:
		if (VTOHFS(ap->a_vp)->hfs_flags & HFS_CASE_SENSITIVE)
			*ap->a_retval = 1;
		else
			*ap->a_retval = 0;
		break;
	case _PC_CASE_PRESERVING:
		*ap->a_retval = 1;
		break;
	default:
		retval = EINVAL;
	}

	return (retval);
}


/*
 * Advisory record locking support
#% advlock	vp	U U U
#
 vop_advlock {
     IN struct vnode *vp;
     IN caddr_t id;
     IN int op;
     IN struct flock *fl;
     IN int flags;

     */
static int
hfs_advlock(ap)
	struct vop_advlock_args /* {
		struct vnode *a_vp;
		caddr_t  a_id;
		int a_op;
		struct flock *a_fl;
		int a_flags;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct flock *fl = ap->a_fl;
	struct hfslockf *lock;
	struct filefork *fork;
	off_t start, end;
	int retval;

	/* Only regular files can have locks */
	if (vp->v_type != VREG)
		return (EISDIR);

	fork = VTOF(ap->a_vp);
	/*
	 * Avoid the common case of unlocking when cnode has no locks.
 	 */
	if (fork->ff_lockf == (struct hfslockf *)0) {
		if (ap->a_op != F_SETLK) {
			fl->l_type = F_UNLCK;
			return (0);
		}
	}
	/*
	 * Convert the flock structure into a start and end.
	 */
	start = 0;
	switch (fl->l_whence) {
	case SEEK_SET:
	case SEEK_CUR:
		/*
		 * Caller is responsible for adding any necessary offset
		 * when SEEK_CUR is used.
		 */
		start = fl->l_start;
		break;
	case SEEK_END:
		start = fork->ff_size + fl->l_start;
		break;
	default:
		return (EINVAL);
	}

	if (fl->l_len == 0)
 		end = -1;
	else if (fl->l_len > 0)
		end = start + fl->l_len - 1;
	else { /* l_len is negative */
		end = start - 1;
		start += fl->l_len;
	}
	if (start < 0)
		return (EINVAL);

	/*
	 * Create the hfslockf structure
	 */
	MALLOC(lock, struct hfslockf *, sizeof *lock, M_LOCKF, M_WAITOK);
	lock->lf_start = start;
	lock->lf_end = end;
	lock->lf_id = ap->a_id;
	lock->lf_fork = fork;
	lock->lf_type = fl->l_type;
	lock->lf_next = (struct hfslockf *)0;
	TAILQ_INIT(&lock->lf_blkhd);
	lock->lf_flags = ap->a_flags;
	/*
	 * Do the requested operation.
	 */
	switch(ap->a_op) {
	case F_SETLK:
		retval = hfs_setlock(lock);
		break;
	case F_UNLCK:
		retval = hfs_clearlock(lock);
		FREE(lock, M_LOCKF);
		break;
	case F_GETLK:
		retval = hfs_getlock(lock, fl);
		FREE(lock, M_LOCKF);
		break;
	default:
		retval = EINVAL;
		_FREE(lock, M_LOCKF);
            break;
	}

	return (retval);
}



/*
 * Update the access, modified, and node change times as specified
 * by the C_ACCESS, C_UPDATE, and C_CHANGE flags respectively. The
 * C_MODIFIED flag is used to specify that the node needs to be
 * updated but that the times have already been set. The access and
 * modified times are input parameters but the node change time is
 * always taken from the current time. If waitfor is set, then wait
 * for the disk write of the node to complete.
 */
/*
#% update	vp	L L L
	IN struct vnode *vp;
	IN struct timeval *access;
	IN struct timeval *modify;
	IN int waitfor;
*/
static int
hfs_update(ap)
	struct vop_update_args /* {
		struct vnode *a_vp;
		struct timeval *a_access;
		struct timeval *a_modify;
		int a_waitfor;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(ap->a_vp);
	struct proc *p;
	struct cat_fork *dataforkp = NULL;
	struct cat_fork *rsrcforkp = NULL;
	struct cat_fork datafork;
	int updateflag;
	struct hfsmount *hfsmp;
	int error;

	hfsmp = VTOHFS(vp);

	/* XXX do we really want to clear the sytem cnode flags here???? */
	if (((vp->v_flag & VSYSTEM) && (cp->c_cnid < kHFSFirstUserCatalogNodeID))||
	    (VTOHFS(vp)->hfs_flags & HFS_READ_ONLY) ||
	    (cp->c_mode == 0)) {
		cp->c_flag &= ~(C_ACCESS | C_CHANGE | C_MODIFIED | C_UPDATE);
		return (0);
	}

	updateflag = cp->c_flag & (C_ACCESS | C_CHANGE | C_MODIFIED | C_UPDATE | C_FORCEUPDATE);

	/* Nothing to update. */
	if (updateflag == 0) {
		return (0);
	}
	/* HFS standard doesn't have access times. */
	if ((updateflag == C_ACCESS) && (VTOVCB(vp)->vcbSigWord == kHFSSigWord)) {
		return (0);
	}
	if (updateflag & C_ACCESS) {
		/*
		 * When the access time is the only thing changing
		 * then make sure its sufficiently newer before
		 * committing it to disk.
		 */
		if ((updateflag == C_ACCESS) &&
		    (ap->a_access->tv_sec < (cp->c_atime + ATIME_ONDISK_ACCURACY))) {
			return (0);
		}
		cp->c_atime = ap->a_access->tv_sec;
	}
	if (updateflag & C_UPDATE) {
		cp->c_mtime = ap->a_modify->tv_sec;
		cp->c_mtime_nsec = ap->a_modify->tv_usec * 1000;
	}
	if (updateflag & C_CHANGE) {
		cp->c_ctime = time.tv_sec;
		/*
		 * HFS dates that WE set must be adjusted for DST
		 */
		if ((VTOVCB(vp)->vcbSigWord == kHFSSigWord) && gTimeZone.tz_dsttime) {
			cp->c_ctime += 3600;
			cp->c_mtime = cp->c_ctime;
		}
	}
	
	if (cp->c_datafork)
		dataforkp = &cp->c_datafork->ff_data;
	if (cp->c_rsrcfork)
		rsrcforkp = &cp->c_rsrcfork->ff_data;

	p = current_proc();

	/*
	 * For delayed allocations updates are
	 * postponed until an fsync or the file
	 * gets written to disk.
	 *
	 * Deleted files can defer meta data updates until inactive.
	 *
	 * If we're ever called with the C_FORCEUPDATE flag though
	 * we have to do the update.
	 */
	if (ISSET(cp->c_flag, C_FORCEUPDATE) == 0 &&
	    (ISSET(cp->c_flag, C_DELETED) || 
	    (dataforkp && cp->c_datafork->ff_unallocblocks) ||
	    (rsrcforkp && cp->c_rsrcfork->ff_unallocblocks))) {
		if (updateflag & (C_CHANGE | C_UPDATE))
			hfs_volupdate(hfsmp, VOL_UPDATE, 0);	
		cp->c_flag &= ~(C_ACCESS | C_CHANGE | C_UPDATE);
		cp->c_flag |= C_MODIFIED;

		HFS_KNOTE(vp, NOTE_ATTRIB);

		return (0);
	}


	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
		if ((error = journal_start_transaction(hfsmp->jnl)) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			return error;
	    }
	}
			

	/*
	 * For files with invalid ranges (holes) the on-disk
	 * field representing the size of the file (cf_size)
	 * must be no larger than the start of the first hole.
	 */
	if (dataforkp && !CIRCLEQ_EMPTY(&cp->c_datafork->ff_invalidranges)) {
		bcopy(dataforkp, &datafork, sizeof(datafork));
		datafork.cf_size = CIRCLEQ_FIRST(&cp->c_datafork->ff_invalidranges)->rl_start;
		dataforkp = &datafork;
	} else if (dataforkp && (cp->c_datafork->ff_unallocblocks != 0)) {
		// always make sure the block count and the size 
		// of the file match the number of blocks actually
		// allocated to the file on disk
		bcopy(dataforkp, &datafork, sizeof(datafork));
		// make sure that we don't assign a negative block count
		if (cp->c_datafork->ff_blocks < cp->c_datafork->ff_unallocblocks) {
		    panic("hfs: ff_blocks %d is less than unalloc blocks %d\n",
			  cp->c_datafork->ff_blocks, cp->c_datafork->ff_unallocblocks);
		}
		datafork.cf_blocks = (cp->c_datafork->ff_blocks - cp->c_datafork->ff_unallocblocks);
		datafork.cf_size   = datafork.cf_blocks * HFSTOVCB(hfsmp)->blockSize;
		dataforkp = &datafork;
	}

	/*
	 * Lock the Catalog b-tree file.
	 * A shared lock is sufficient since an update doesn't change
	 * the tree and the lock on vp protects the cnode.
	 */
	error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_SHARED, p);
	if (error) {
		if (hfsmp->jnl) {
			journal_end_transaction(hfsmp->jnl);
		}
		hfs_global_shared_lock_release(hfsmp);
		return (error);
	}

	/* XXX - waitfor is not enforced */
	error = cat_update(hfsmp, &cp->c_desc, &cp->c_attr, dataforkp, rsrcforkp);

	 /* Unlock the Catalog b-tree file. */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

	if (updateflag & (C_CHANGE | C_UPDATE | C_FORCEUPDATE))
		hfs_volupdate(hfsmp, VOL_UPDATE, 0);	

	/* After the updates are finished, clear the flags */
	cp->c_flag &= ~(C_ACCESS | C_CHANGE | C_MODIFIED | C_UPDATE | C_FORCEUPDATE);

	// XXXdbg
	if (hfsmp->jnl) {
	    journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);

	HFS_KNOTE(vp, NOTE_ATTRIB);
	
	return (error);
}

/*
 * Allocate a new node
 *
 * Upon leaving, namei buffer must be freed.
 *
 */
static int
hfs_makenode(mode, dvp, vpp, cnp)
	int mode;
	struct vnode *dvp;
	struct vnode **vpp;
	struct componentname *cnp;
{
	struct cnode *cp;
	struct cnode *dcp;
	struct vnode *tvp;
	struct hfsmount *hfsmp;
	struct timeval tv;
	struct proc *p;
	struct cat_desc in_desc, out_desc;
	struct cat_attr attr;
	cat_cookie_t cookie = {0};
	int error, started_tr = 0, grabbed_lock = 0;
	enum vtype vnodetype;

	p = cnp->cn_proc;
	dcp = VTOC(dvp);
	hfsmp = VTOHFS(dvp);
	*vpp = NULL;
	tvp = NULL;
	bzero(&out_desc, sizeof(out_desc));

	if ((mode & S_IFMT) == 0)
		mode |= S_IFREG;
	vnodetype = IFTOVT(mode);

	/* Check if unmount in progress */
	if (VTOVFS(dvp)->mnt_kern_flag & MNTK_UNMOUNT) {
		error = EPERM;
		goto exit;
	}
	/* Check if were out of usable disk space. */
	if ((suser(cnp->cn_cred, NULL) != 0) && (hfs_freeblks(hfsmp, 1) <= 0)) {
		error = ENOSPC;
		goto exit;
	}

	/* Setup the default attributes */
	bzero(&attr, sizeof(attr));
	attr.ca_mode = mode;
	attr.ca_nlink = vnodetype == VDIR ? 2 : 1;
	attr.ca_mtime = time.tv_sec;
	attr.ca_mtime_nsec = time.tv_usec * 1000;
	if ((VTOVCB(dvp)->vcbSigWord == kHFSSigWord) && gTimeZone.tz_dsttime) {
		attr.ca_mtime += 3600;	/* Same as what hfs_update does */
	}
	attr.ca_atime = attr.ca_ctime = attr.ca_itime = attr.ca_mtime;
	if (VTOVFS(dvp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
		attr.ca_uid = hfsmp->hfs_uid;
		attr.ca_gid = hfsmp->hfs_gid;
	} else {
		if (vnodetype == VLNK)
			attr.ca_uid = dcp->c_uid;
		else
			attr.ca_uid = cnp->cn_cred->cr_uid;
		attr.ca_gid = dcp->c_gid;
	}
	/*
	 * Don't tag as a special file (BLK or CHR) until *after*
	 * hfs_getnewvnode is called.  This insures that any
	 * alias checking is defered until hfs_mknod completes.
	 */
	if (vnodetype == VBLK || vnodetype == VCHR)
		attr.ca_mode = (attr.ca_mode & ~S_IFMT) | S_IFREG;

	/* Tag symlinks with a type and creator. */
	if (vnodetype == VLNK) {
		struct FndrFileInfo *fip;

		fip = (struct FndrFileInfo *)&attr.ca_finderinfo;
		fip->fdType    = SWAP_BE32(kSymLinkFileType);
		fip->fdCreator = SWAP_BE32(kSymLinkCreator);
	}
	if ((attr.ca_mode & S_ISGID) &&
	    !groupmember(dcp->c_gid, cnp->cn_cred) &&
	    suser(cnp->cn_cred, NULL)) {
		attr.ca_mode &= ~S_ISGID;
	}
	if (cnp->cn_flags & ISWHITEOUT)
		attr.ca_flags |= UF_OPAQUE;

	/* Setup the descriptor */
	bzero(&in_desc, sizeof(in_desc));
	in_desc.cd_nameptr = cnp->cn_nameptr;
	in_desc.cd_namelen = cnp->cn_namelen;
	in_desc.cd_parentcnid = dcp->c_cnid;
	in_desc.cd_flags = S_ISDIR(mode) ? CD_ISDIR : 0;

	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	grabbed_lock = 1;
	if (hfsmp->jnl) {
	    if ((error = journal_start_transaction(hfsmp->jnl)) != 0) {
			goto exit;
	    }
		started_tr = 1;
	}

	/*
	 * Reserve some space in the Catalog file.
	 *
	 * (we also add CAT_DELETE since our getnewvnode
	 *  request can cause an hfs_inactive call to
	 *  delete an unlinked file)
	 */
	if ((error = cat_preflight(hfsmp, CAT_CREATE | CAT_DELETE, &cookie, p))) {
		goto exit;
	}

	/* Lock catalog b-tree */
	error = hfs_metafilelocking(VTOHFS(dvp), kHFSCatalogFileID, LK_EXCLUSIVE, p);
	if (error)
		goto exit;

	error = cat_create(hfsmp, &in_desc, &attr, &out_desc);

	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking(VTOHFS(dvp), kHFSCatalogFileID, LK_RELEASE, p);		
	if (error)
		goto exit;
	
	/* Update the parent directory */
	dcp->c_childhint = out_desc.cd_hint;	/* Cache directory's location */
	dcp->c_nlink++;
	dcp->c_entries++;
	dcp->c_flag |= C_CHANGE | C_UPDATE;
	tv = time;
	(void) VOP_UPDATE(dvp, &tv, &tv, 0);
	if (vnodetype == VDIR) {
		HFS_KNOTE(dvp, NOTE_WRITE | NOTE_LINK);
	} else {
		HFS_KNOTE(dvp, NOTE_WRITE);
	};

	hfs_volupdate(hfsmp, vnodetype == VDIR ? VOL_MKDIR : VOL_MKFILE,
		(dcp->c_cnid == kHFSRootFolderID));

	// XXXdbg
	// have to end the transaction here before we call hfs_getnewvnode()
	// because that can cause us to try and reclaim a vnode on a different
	// file system which could cause us to start a transaction which can
	// deadlock with someone on that other file system (since we could be
	// holding two transaction locks as well as various vnodes and we did
	// not obtain the locks on them in the proper order).
    //
	// NOTE: this means that if the quota check fails or we have to update
	//       the change time on a block-special device that those changes
	//       will happen as part of independent transactions.
	//
	if (started_tr) {
		journal_end_transaction(hfsmp->jnl);
		started_tr = 0;
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
		grabbed_lock = 0;
	}

	/* Create a vnode for the object just created: */
	error = hfs_getnewvnode(hfsmp, NULL, &out_desc, 0, &attr, NULL, &tvp);
	if (error)
		goto exit;

	// XXXdbg
	cache_enter(dvp, tvp, cnp);

#if QUOTA
	cp = VTOC(tvp);
	/* 
	 * We call hfs_chkiq with FORCE flag so that if we
	 * fall through to the rmdir we actually have 
	 * accounted for the inode
	*/
	if ((error = hfs_getinoquota(cp)) ||
	    (error = hfs_chkiq(cp, 1, cnp->cn_cred, FORCE))) {
		if (tvp->v_type == VDIR)
			VOP_RMDIR(dvp,tvp, cnp);
		else
			VOP_REMOVE(dvp,tvp, cnp);

		// because VOP_RMDIR and VOP_REMOVE already
		// have done the vput()
		dvp = NULL;
		goto exit;
	}
#endif /* QUOTA */

	/*
	 * restore vtype and mode for VBLK and VCHR
	 */
	if (vnodetype == VBLK || vnodetype == VCHR) {
		struct cnode *cp;

		cp = VTOC(tvp);
		cp->c_mode = mode;
		tvp->v_type = IFTOVT(mode);
		cp->c_flag |= C_CHANGE;
		tv = time;
		if ((error = VOP_UPDATE(tvp, &tv, &tv, 1))) {
			vput(tvp);
			goto exit;
		}
	}

	*vpp = tvp;
exit:
	cat_releasedesc(&out_desc);

	cat_postflight(hfsmp, &cookie, p);

	if ((cnp->cn_flags & (HASBUF | SAVESTART)) == HASBUF) {
		char *tmp = cnp->cn_pnbuf;
		cnp->cn_pnbuf = NULL;
		cnp->cn_flags &= ~HASBUF;
		FREE_ZONE(tmp, cnp->cn_pnlen, M_NAMEI);
	}
	/*
	 * Check if a file is located in the "Cleanup At Startup"
	 * directory.  If it is then tag it as NODUMP so that we
	 * can be lazy about zero filling data holes.
	 */
	if ((error == 0) && dvp && (vnodetype == VREG) &&
	    (dcp->c_desc.cd_nameptr != NULL) &&
	    (strcmp(dcp->c_desc.cd_nameptr, CARBON_TEMP_DIR_NAME) == 0)) {
	   	struct vnode *ddvp;
		cnid_t parid;

		parid = dcp->c_parentcnid;
		vput(dvp);
		dvp = NULL;

		/*
		 * The parent of "Cleanup At Startup" should
		 * have the ASCII name of the userid.
		 */
		if (VFS_VGET(HFSTOVFS(hfsmp), &parid, &ddvp) == 0) {
			if (VTOC(ddvp)->c_desc.cd_nameptr &&
			    (cp->c_uid == strtoul(VTOC(ddvp)->c_desc.cd_nameptr, 0, 0))) {
				cp->c_flags |= UF_NODUMP;
				cp->c_flag |= C_CHANGE;
			}
			vput(ddvp);
		}
	}
	if (dvp)
		vput(dvp);

	if (started_tr) {
	    journal_end_transaction(hfsmp->jnl);
		started_tr = 0;
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
		grabbed_lock = 0;
	}

	return (error);
}


static int
hfs_vgetrsrc(struct hfsmount *hfsmp, struct vnode *vp, struct vnode **rvpp, struct proc *p)
{
	struct vnode *rvp;
	struct cnode *cp = VTOC(vp);
	int error;

	if ((rvp = cp->c_rsrc_vp)) {
		/* Use exising vnode */
		error = vget(rvp, 0, p);
		if (error) {
			char * name = VTOC(vp)->c_desc.cd_nameptr;

			if (name)
				printf("hfs_vgetrsrc: couldn't get"
					" resource fork for %s\n", name);
			return (error);
		}
	} else {
		struct cat_fork rsrcfork;

		/* Lock catalog b-tree */
		error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_SHARED, p);
		if (error)
			return (error);

		/* Get resource fork data */
		error = cat_lookup(hfsmp, &cp->c_desc, 1, (struct cat_desc *)0,
				(struct cat_attr *)0, &rsrcfork);

		/* Unlock the Catalog */
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);
		if (error)
			return (error);
		
		error = hfs_getnewvnode(hfsmp, cp, &cp->c_desc, 1, &cp->c_attr,
					&rsrcfork, &rvp);
		if (error)
			return (error);
	}

	*rvpp = rvp;
	return (0);
}


static void
filt_hfsdetach(struct knote *kn)
{
	struct vnode *vp;
	int result;
	struct proc *p = current_proc();
	
	vp = (struct vnode *)kn->kn_hook;
	if (1) {	/* ! KNDETACH_VNLOCKED */
		result = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		if (result) return;
	};

	result = KNOTE_DETACH(&VTOC(vp)->c_knotes, kn);
	
	if (1) {	/* ! KNDETACH_VNLOCKED */
		VOP_UNLOCK(vp, 0, p);
	};
}

/*ARGSUSED*/
static int
filt_hfsread(struct knote *kn, long hint)
{
	struct vnode *vp = (struct vnode *)kn->kn_fp->f_data;

	if (hint == NOTE_REVOKE) {
		/*
		 * filesystem is gone, so set the EOF flag and schedule 
		 * the knote for deletion.
		 */
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		return (1);
	}

	kn->kn_data = VTOF(vp)->ff_size - kn->kn_fp->f_offset;
	return (kn->kn_data != 0);
}

/*ARGSUSED*/
static int
filt_hfswrite(struct knote *kn, long hint)
{
	if (hint == NOTE_REVOKE) {
		/*
		 * filesystem is gone, so set the EOF flag and schedule 
		 * the knote for deletion.
		 */
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
	}
	
	kn->kn_data = 0;
	return (1);
}

static int
filt_hfsvnode(struct knote *kn, long hint)
{

	if (kn->kn_sfflags & hint)
		kn->kn_fflags |= hint;
	if (hint == NOTE_REVOKE) {
		kn->kn_flags |= EV_EOF;
		return (1);
	}
	return (kn->kn_fflags != 0);
}

static struct filterops hfsread_filtops = 
	{ 1, NULL, filt_hfsdetach, filt_hfsread };
static struct filterops hfswrite_filtops = 
	{ 1, NULL, filt_hfsdetach, filt_hfswrite };
static struct filterops hfsvnode_filtops = 
	{ 1, NULL, filt_hfsdetach, filt_hfsvnode };

/*
 #
 #% kqfilt_add	vp	L L L
 #
 vop_kqfilt_add
	IN struct vnode *vp;
	IN struct knote *kn;
	IN struct proc *p;
 */
static int
hfs_kqfilt_add(ap)
	struct vop_kqfilt_add_args /* {
		struct vnode *a_vp;
		struct knote *a_kn;
		struct proc *p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct knote *kn = ap->a_kn;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		if (vp->v_type == VREG) {
			kn->kn_fop = &hfsread_filtops;
		} else {
			return EINVAL;
		};
		break;
	case EVFILT_WRITE:
		if (vp->v_type == VREG) {
			kn->kn_fop = &hfswrite_filtops;
		} else {
			return EINVAL;
		};
		break;
	case EVFILT_VNODE:
		kn->kn_fop = &hfsvnode_filtops;
		break;
	default:
		return (1);
	}

	kn->kn_hook = (caddr_t)vp;

	/* simple_lock(&vp->v_pollinfo.vpi_lock); */
	KNOTE_ATTACH(&VTOC(vp)->c_knotes, kn);
	/* simple_unlock(&vp->v_pollinfo.vpi_lock); */

	return (0);
}

/*
 #
 #% kqfilt_remove	vp	L L L
 #
 vop_kqfilt_remove
	IN struct vnode *vp;
	IN uintptr_t ident;
	IN struct proc *p;
 */
static int
hfs_kqfilt_remove(ap)
	struct vop_kqfilt_remove_args /* {
		struct vnode *a_vp;
		uintptr_t ident;
		struct proc *p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	uintptr_t ident = ap->a_ident;
	int result;

	result = ENOTSUP; /* XXX */
	
	return (result);
}

/*
 * Wrapper for special device reads
 */
static int
hfsspec_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	/*
	 * Set access flag.
	 */
	VTOC(ap->a_vp)->c_flag |= C_ACCESS;
	return (VOCALL (spec_vnodeop_p, VOFFSET(vop_read), ap));
}

/*
 * Wrapper for special device writes
 */
static int
hfsspec_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	/*
	 * Set update and change flags.
	 */
	VTOC(ap->a_vp)->c_flag |= C_CHANGE | C_UPDATE;
	return (VOCALL (spec_vnodeop_p, VOFFSET(vop_write), ap));
}

/*
 * Wrapper for special device close
 *
 * Update the times on the cnode then do device close.
 */
static int
hfsspec_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);

	simple_lock(&vp->v_interlock);
	if (ap->a_vp->v_usecount > 1)
		CTIMES(cp, &time, &time);
	simple_unlock(&vp->v_interlock);
	return (VOCALL (spec_vnodeop_p, VOFFSET(vop_close), ap));
}

#if FIFO
/*
 * Wrapper for fifo reads
 */
static int
hfsfifo_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	extern int (**fifo_vnodeop_p)(void *);

	/*
	 * Set access flag.
	 */
	VTOC(ap->a_vp)->c_flag |= C_ACCESS;
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vop_read), ap));
}

/*
 * Wrapper for fifo writes
 */
static int
hfsfifo_write(ap)
	struct vop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	extern int (**fifo_vnodeop_p)(void *);

	/*
	 * Set update and change flags.
	 */
	VTOC(ap->a_vp)->c_flag |= C_CHANGE | C_UPDATE;
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vop_write), ap));
}

/*
 * Wrapper for fifo close
 *
 * Update the times on the cnode then do device close.
 */
static int
hfsfifo_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	extern int (**fifo_vnodeop_p)(void *);
	struct vnode *vp = ap->a_vp;
	struct cnode *cp = VTOC(vp);

	simple_lock(&vp->v_interlock);
	if (ap->a_vp->v_usecount > 1)
		CTIMES(cp, &time, &time);
	simple_unlock(&vp->v_interlock);
	return (VOCALL (fifo_vnodeop_p, VOFFSET(vop_close), ap));
}

/*
 * kqfilt_add wrapper for fifos.
 *
 * Fall through to hfs kqfilt_add routines if needed 
 */
int
hfsfifo_kqfilt_add(ap)
	struct vop_kqfilt_add_args *ap;
{
	extern int (**fifo_vnodeop_p)(void *);
	int error;

	error = VOCALL(fifo_vnodeop_p, VOFFSET(vop_kqfilt_add), ap);
	if (error)
		error = hfs_kqfilt_add(ap);
	return (error);
}

/*
 * kqfilt_remove wrapper for fifos.
 *
 * Fall through to hfs kqfilt_remove routines if needed 
 */
int
hfsfifo_kqfilt_remove(ap)
	struct vop_kqfilt_remove_args *ap;
{
	extern int (**fifo_vnodeop_p)(void *);
	int error;

	error = VOCALL(fifo_vnodeop_p, VOFFSET(vop_kqfilt_remove), ap);
	if (error)
		error = hfs_kqfilt_remove(ap);
	return (error);
}

#endif /* FIFO */


/*****************************************************************************
*
*	VOP Tables
*
*****************************************************************************/
int hfs_cache_lookup();	/* in hfs_lookup.c */
int hfs_lookup();	/* in hfs_lookup.c */
int hfs_read();		/* in hfs_readwrite.c */
int hfs_write();	/* in hfs_readwrite.c */
int hfs_ioctl();	/* in hfs_readwrite.c */
int hfs_select();	/* in hfs_readwrite.c */
int hfs_bmap();		/* in hfs_readwrite.c */
int hfs_strategy();	/* in hfs_readwrite.c */
int hfs_truncate();	/* in hfs_readwrite.c */
int hfs_allocate();	/* in hfs_readwrite.c */
int hfs_pagein();	/* in hfs_readwrite.c */
int hfs_pageout();	/* in hfs_readwrite.c */
int hfs_search();	/* in hfs_search.c */
int hfs_bwrite();	/* in hfs_readwrite.c */
int hfs_link();		/* in hfs_link.c */
int hfs_blktooff();	/* in hfs_readwrite.c */
int hfs_offtoblk();	/* in hfs_readwrite.c */
int hfs_cmap();		/* in hfs_readwrite.c */
int hfs_getattrlist();	/* in hfs_attrlist.c */
int hfs_setattrlist();	/* in hfs_attrlist.c */
int hfs_readdirattr();	/* in hfs_attrlist.c */
int hfs_inactive();	/* in hfs_cnode.c */
int hfs_reclaim();	/* in hfs_cnode.c */

int (**hfs_vnodeop_p)(void *);

#define VOPFUNC int (*)(void *)

struct vnodeopv_entry_desc hfs_vnodeop_entries[] = {
    { &vop_default_desc, (VOPFUNC)vn_default_error },
    { &vop_lookup_desc, (VOPFUNC)hfs_cache_lookup },		/* lookup */
    { &vop_create_desc, (VOPFUNC)hfs_create },			/* create */
    { &vop_mknod_desc, (VOPFUNC)hfs_mknod },			/* mknod */
    { &vop_open_desc, (VOPFUNC)hfs_open },			/* open */
    { &vop_close_desc, (VOPFUNC)hfs_close },			/* close */
    { &vop_access_desc, (VOPFUNC)hfs_access },			/* access */
    { &vop_getattr_desc, (VOPFUNC)hfs_getattr },		/* getattr */
    { &vop_setattr_desc, (VOPFUNC)hfs_setattr },		/* setattr */
    { &vop_read_desc, (VOPFUNC)hfs_read },			/* read */
    { &vop_write_desc, (VOPFUNC)hfs_write },			/* write */
    { &vop_ioctl_desc, (VOPFUNC)hfs_ioctl },			/* ioctl */
    { &vop_select_desc, (VOPFUNC)hfs_select },			/* select */
    { &vop_revoke_desc, (VOPFUNC)nop_revoke },			/* revoke */
    { &vop_exchange_desc, (VOPFUNC)hfs_exchange },		/* exchange */
    { &vop_mmap_desc, (VOPFUNC)err_mmap },			/* mmap */
    { &vop_fsync_desc, (VOPFUNC)hfs_fsync },			/* fsync */
    { &vop_seek_desc, (VOPFUNC)nop_seek },			/* seek */
    { &vop_remove_desc, (VOPFUNC)hfs_remove },			/* remove */
    { &vop_link_desc, (VOPFUNC)hfs_link },			/* link */
    { &vop_rename_desc, (VOPFUNC)hfs_rename },			/* rename */
    { &vop_mkdir_desc, (VOPFUNC)hfs_mkdir },			/* mkdir */
    { &vop_rmdir_desc, (VOPFUNC)hfs_rmdir },			/* rmdir */
    { &vop_mkcomplex_desc, (VOPFUNC)err_mkcomplex },		/* mkcomplex */
    { &vop_getattrlist_desc, (VOPFUNC)hfs_getattrlist },  /* getattrlist */
    { &vop_setattrlist_desc, (VOPFUNC)hfs_setattrlist },  /* setattrlist */
    { &vop_symlink_desc, (VOPFUNC)hfs_symlink },		/* symlink */
    { &vop_readdir_desc, (VOPFUNC)hfs_readdir },		/* readdir */
    { &vop_readdirattr_desc, (VOPFUNC)hfs_readdirattr },  /* readdirattr */
    { &vop_readlink_desc, (VOPFUNC)hfs_readlink },		/* readlink */
    { &vop_abortop_desc, (VOPFUNC)nop_abortop },		/* abortop */
    { &vop_inactive_desc, (VOPFUNC)hfs_inactive },		/* inactive */
    { &vop_reclaim_desc, (VOPFUNC)hfs_reclaim },		/* reclaim */
    { &vop_lock_desc, (VOPFUNC)hfs_lock },			/* lock */
    { &vop_unlock_desc, (VOPFUNC)hfs_unlock },			/* unlock */
    { &vop_bmap_desc, (VOPFUNC)hfs_bmap },			/* bmap */
    { &vop_strategy_desc, (VOPFUNC)hfs_strategy },		/* strategy */
    { &vop_print_desc, (VOPFUNC)hfs_print },			/* print */
    { &vop_islocked_desc, (VOPFUNC)hfs_islocked },		/* islocked */
    { &vop_pathconf_desc, (VOPFUNC)hfs_pathconf },		/* pathconf */
    { &vop_advlock_desc, (VOPFUNC)hfs_advlock },		/* advlock */
    { &vop_reallocblks_desc, (VOPFUNC)err_reallocblks },  /* reallocblks */
    { &vop_truncate_desc, (VOPFUNC)hfs_truncate },		/* truncate */
    { &vop_allocate_desc, (VOPFUNC)hfs_allocate },		/* allocate */
    { &vop_update_desc, (VOPFUNC)hfs_update },			/* update */
    { &vop_searchfs_desc, (VOPFUNC)hfs_search },		/* search fs */
    { &vop_bwrite_desc, (VOPFUNC)hfs_bwrite },			/* bwrite */
    { &vop_pagein_desc, (VOPFUNC)hfs_pagein },			/* pagein */
    { &vop_pageout_desc,(VOPFUNC) hfs_pageout },		/* pageout */
    { &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* copyfile */
    { &vop_blktooff_desc, (VOPFUNC)hfs_blktooff },		/* blktooff */
    { &vop_offtoblk_desc, (VOPFUNC)hfs_offtoblk },		/* offtoblk */
    { &vop_cmap_desc, (VOPFUNC)hfs_cmap },			/* cmap */
	{ &vop_kqfilt_add_desc, (VOPFUNC)hfs_kqfilt_add },		/* kqfilt_add */
	{ &vop_kqfilt_remove_desc, (VOPFUNC)hfs_kqfilt_remove },		/* kqfilt_remove */
    { NULL, (VOPFUNC)NULL }
};

struct vnodeopv_desc hfs_vnodeop_opv_desc =
{ &hfs_vnodeop_p, hfs_vnodeop_entries };

int (**hfs_specop_p)(void *);
struct vnodeopv_entry_desc hfs_specop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)spec_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)spec_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)spec_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)spec_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)hfsspec_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)hfs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)hfs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)hfs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)hfsspec_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)hfsspec_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)spec_lease_check },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)spec_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)spec_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)spec_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)spec_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)hfs_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)spec_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)spec_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)spec_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)spec_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)spec_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)spec_rmdir },		/* rmdir */
	{ &vop_getattrlist_desc, (VOPFUNC)hfs_getattrlist },
	{ &vop_symlink_desc, (VOPFUNC)spec_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)spec_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)spec_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)spec_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)hfs_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)hfs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)hfs_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)hfs_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)spec_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)spec_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)hfs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)hfs_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)spec_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)spec_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)spec_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)spec_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)spec_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)err_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)spec_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)hfs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)hfs_bwrite },
	{ &vop_devblocksize_desc, (VOPFUNC)spec_devblocksize }, /* devblocksize */
	{ &vop_pagein_desc, (VOPFUNC)hfs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)hfs_pageout },		/* Pageout */
        { &vop_copyfile_desc, (VOPFUNC)err_copyfile },		/* copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)hfs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)hfs_offtoblk },		/* offtoblk */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc hfs_specop_opv_desc =
	{ &hfs_specop_p, hfs_specop_entries };

#if FIFO
int (**hfs_fifoop_p)(void *);
struct vnodeopv_entry_desc hfs_fifoop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)fifo_lookup },		/* lookup */
	{ &vop_create_desc, (VOPFUNC)fifo_create },		/* create */
	{ &vop_mknod_desc, (VOPFUNC)fifo_mknod },		/* mknod */
	{ &vop_open_desc, (VOPFUNC)fifo_open },			/* open */
	{ &vop_close_desc, (VOPFUNC)hfsfifo_close },		/* close */
	{ &vop_access_desc, (VOPFUNC)hfs_access },		/* access */
	{ &vop_getattr_desc, (VOPFUNC)hfs_getattr },		/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)hfs_setattr },		/* setattr */
	{ &vop_read_desc, (VOPFUNC)hfsfifo_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)hfsfifo_write },		/* write */
	{ &vop_lease_desc, (VOPFUNC)fifo_lease_check },		/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)fifo_ioctl },		/* ioctl */
	{ &vop_select_desc, (VOPFUNC)fifo_select },		/* select */
	{ &vop_revoke_desc, (VOPFUNC)fifo_revoke },		/* revoke */
	{ &vop_mmap_desc, (VOPFUNC)fifo_mmap },			/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)hfs_fsync },		/* fsync */
	{ &vop_seek_desc, (VOPFUNC)fifo_seek },			/* seek */
	{ &vop_remove_desc, (VOPFUNC)fifo_remove },		/* remove */
	{ &vop_link_desc, (VOPFUNC)fifo_link },			/* link */
	{ &vop_rename_desc, (VOPFUNC)fifo_rename },		/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)fifo_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)fifo_rmdir },		/* rmdir */
	{ &vop_getattrlist_desc, (VOPFUNC)hfs_getattrlist },
	{ &vop_symlink_desc, (VOPFUNC)fifo_symlink },		/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)fifo_readdir },		/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)fifo_readlink },		/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)fifo_abortop },		/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)hfs_inactive },		/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)hfs_reclaim },		/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)hfs_lock },			/* lock */
	{ &vop_unlock_desc, (VOPFUNC)hfs_unlock },		/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)fifo_bmap },			/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)fifo_strategy },		/* strategy */
	{ &vop_print_desc, (VOPFUNC)hfs_print },		/* print */
	{ &vop_islocked_desc, (VOPFUNC)hfs_islocked },		/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)fifo_pathconf },		/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)fifo_advlock },		/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)fifo_blkatoff },		/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)fifo_valloc },		/* valloc */
	{ &vop_reallocblks_desc, (VOPFUNC)fifo_reallocblks },	/* reallocblks */
	{ &vop_vfree_desc, (VOPFUNC)err_vfree },		/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)fifo_truncate },		/* truncate */
	{ &vop_update_desc, (VOPFUNC)hfs_update },		/* update */
	{ &vop_bwrite_desc, (VOPFUNC)hfs_bwrite },
	{ &vop_pagein_desc, (VOPFUNC)hfs_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)hfs_pageout },		/* Pageout */
    { &vop_copyfile_desc, (VOPFUNC)err_copyfile }, 		/* copyfile */
	{ &vop_blktooff_desc, (VOPFUNC)hfs_blktooff },		/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)hfs_offtoblk },		/* offtoblk */
  	{ &vop_cmap_desc, (VOPFUNC)hfs_cmap },			/* cmap */
	{ &vop_kqfilt_add_desc, (VOPFUNC)hfsfifo_kqfilt_add },  /* kqfilt_add */
	{ &vop_kqfilt_remove_desc, (VOPFUNC)hfsfifo_kqfilt_remove },  /* kqfilt_remove */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc hfs_fifoop_opv_desc =
	{ &hfs_fifoop_p, hfs_fifoop_entries };
#endif /* FIFO */



