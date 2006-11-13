/*
 * Copyright (c) 1999-2005 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1991, 1993, 1994
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
 *      hfs_vfsops.c
 *  derived from	@(#)ufs_vfsops.c	8.8 (Berkeley) 5/20/95
 *
 *      (c) Copyright 1997-2002 Apple Computer, Inc. All rights reserved.
 *
 *      hfs_vfsops.c -- VFS layer for loadable HFS file system.
 *
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kauth.h>

#include <sys/ubc.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/quota.h>
#include <sys/disk.h>
#include <sys/paths.h>
#include <sys/utfconv.h>
#include <sys/kdebug.h>

#include <kern/locks.h>

#include <vfs/vfs_journal.h>

#include <miscfs/specfs/specdev.h>
#include <hfs/hfs_mount.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_cnode.h"
#include "hfs_dbg.h"
#include "hfs_endian.h"
#include "hfs_hotfiles.h"
#include "hfs_quota.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/BTreesInternal.h"


#if	HFS_DIAGNOSTIC
int hfs_dbg_all = 0;
int hfs_dbg_err = 0;
#endif


lck_grp_attr_t *  hfs_group_attr;
lck_attr_t *  hfs_lock_attr;
lck_grp_t *  hfs_mutex_group;
lck_grp_t *  hfs_rwlock_group;


extern struct vnodeopv_desc hfs_vnodeop_opv_desc;

extern void hfs_converterinit(void);

extern void inittodr(time_t base);

extern int  hfs_write_access(struct vnode *, kauth_cred_t, struct proc *, Boolean);


static int hfs_changefs(struct mount *mp, struct hfs_mount_args *args);
static int hfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp, struct vnode **vpp, vfs_context_t context);
static int hfs_flushfiles(struct mount *, int, struct proc *);
static int hfs_flushMDB(struct hfsmount *hfsmp, int waitfor, int altflush);
static int hfs_getmountpoint(struct vnode *vp, struct hfsmount **hfsmpp);
static int hfs_init(struct vfsconf *vfsp);
static int hfs_mount(struct mount *mp, vnode_t  devvp, user_addr_t data, vfs_context_t context);
static int hfs_mountfs(struct vnode *devvp, struct mount *mp, struct hfs_mount_args *args, vfs_context_t context);
static int hfs_reload(struct mount *mp, kauth_cred_t cred, struct proc *p);
static int hfs_vfs_root(struct mount *mp, struct vnode **vpp, vfs_context_t context);
static int hfs_quotactl(struct mount *, int, uid_t, caddr_t, vfs_context_t context);
static int hfs_start(struct mount *mp, int flags, vfs_context_t context);
static int hfs_statfs(struct mount *mp, register struct vfsstatfs *sbp, vfs_context_t context);
static int hfs_sync(struct mount *mp, int waitfor, vfs_context_t context);
static int hfs_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
                      user_addr_t newp, size_t newlen, vfs_context_t context);
static int hfs_unmount(struct mount *mp, int mntflags, vfs_context_t context);
static int hfs_vfs_vget(struct mount *mp, ino64_t ino, struct vnode **vpp, vfs_context_t context);
static int hfs_vptofh(struct vnode *vp, int *fhlenp, unsigned char *fhp, vfs_context_t context);

static int hfs_reclaimspace(struct hfsmount *hfsmp, u_long startblk, u_long reclaimblks);
static int hfs_overlapped_overflow_extents(struct hfsmount *hfsmp, u_int32_t startblk,
                                           u_int32_t catblks, u_int32_t fileID, int rsrcfork);


/*
 * Called by vfs_mountroot when mounting HFS Plus as root.
 */

__private_extern__
int
hfs_mountroot(mount_t mp, vnode_t rvp, vfs_context_t context)
{
	struct hfsmount *hfsmp;
	ExtendedVCB *vcb;
	struct vfsstatfs *vfsp;
	int error;
	
	if ((error = hfs_mountfs(rvp, mp, NULL, context)))
		return (error);

	/* Init hfsmp */
	hfsmp = VFSTOHFS(mp);

	hfsmp->hfs_uid = UNKNOWNUID;
	hfsmp->hfs_gid = UNKNOWNGID;
	hfsmp->hfs_dir_mask = (S_IRWXU | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH); /* 0755 */
	hfsmp->hfs_file_mask = (S_IRWXU | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH); /* 0755 */

	/* Establish the free block reserve. */
	vcb = HFSTOVCB(hfsmp);
	vcb->reserveBlocks = ((u_int64_t)vcb->totalBlocks * HFS_MINFREE) / 100;
	vcb->reserveBlocks = MIN(vcb->reserveBlocks, HFS_MAXRESERVE / vcb->blockSize);

	vfsp = vfs_statfs(mp);
	(void)hfs_statfs(mp, vfsp, NULL);

	return (0);
}


/*
 * VFS Operations.
 *
 * mount system call
 */

static int
hfs_mount(struct mount *mp, vnode_t devvp, user_addr_t data, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	struct hfsmount *hfsmp = NULL;
	struct hfs_mount_args args;
	int retval = E_NONE;
	uint32_t cmdflags;

	if ((retval = copyin(data, (caddr_t)&args, sizeof(args)))) {
		return (retval);
	}
	cmdflags = (uint32_t)vfs_flags(mp) & MNT_CMDFLAGS;
	if (cmdflags & MNT_UPDATE) {
		hfsmp = VFSTOHFS(mp);

		/* Reload incore data after an fsck. */
		if (cmdflags & MNT_RELOAD) {
			if (vfs_isrdonly(mp))
				return hfs_reload(mp, vfs_context_ucred(context), p);
			else
				return (EINVAL);
		}

		/* Change to a read-only file system. */
		if (((hfsmp->hfs_flags & HFS_READ_ONLY) == 0) &&
		    vfs_isrdonly(mp)) {
			int flags;

			/* use VFS_SYNC to push out System (btree) files */
			retval = VFS_SYNC(mp, MNT_WAIT, context);
			if (retval && ((cmdflags & MNT_FORCE) == 0))
				goto out;
		
			flags = WRITECLOSE;
			if (cmdflags & MNT_FORCE)
				flags |= FORCECLOSE;
				
			if ((retval = hfs_flushfiles(mp, flags, p)))
				goto out;
			hfsmp->hfs_flags |= HFS_READ_ONLY;
			retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);

			/* also get the volume bitmap blocks */
			if (!retval) {
				if (vnode_mount(hfsmp->hfs_devvp) == mp) {
					retval = hfs_fsync(hfsmp->hfs_devvp, MNT_WAIT, 0, p);
				} else {
					vnode_get(hfsmp->hfs_devvp);
					retval = VNOP_FSYNC(hfsmp->hfs_devvp, MNT_WAIT, context);
					vnode_put(hfsmp->hfs_devvp);
				}
			}
			if (retval) {
				hfsmp->hfs_flags &= ~HFS_READ_ONLY;
				goto out;
			}
			if (hfsmp->jnl) {
			    hfs_global_exclusive_lock_acquire(hfsmp);

			    journal_close(hfsmp->jnl);
			    hfsmp->jnl = NULL;

			    // Note: we explicitly don't want to shutdown
			    //       access to the jvp because we may need
			    //       it later if we go back to being read-write.

			    hfs_global_exclusive_lock_release(hfsmp);
			}
		}

		/* Change to a writable file system. */
		if (vfs_iswriteupgrade(mp)) {
			retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
			if (retval != E_NONE)
				goto out;

			// If the journal was shut-down previously because we were
			// asked to be read-only, let's start it back up again now
			
			if (   (HFSTOVCB(hfsmp)->vcbAtrb & kHFSVolumeJournaledMask)
			    && hfsmp->jnl == NULL
			    && hfsmp->jvp != NULL) {
			    int jflags;

			    if (hfsmp->hfs_flags & HFS_NEED_JNL_RESET) {
					jflags = JOURNAL_RESET;
			    } else {
					jflags = 0;
			    }
			    
			    hfs_global_exclusive_lock_acquire(hfsmp);

			    hfsmp->jnl = journal_open(hfsmp->jvp,
						      (hfsmp->jnl_start * HFSTOVCB(hfsmp)->blockSize) + (off_t)HFSTOVCB(hfsmp)->hfsPlusIOPosOffset,
						      hfsmp->jnl_size,
						      hfsmp->hfs_devvp,
						      hfsmp->hfs_phys_block_size,
						      jflags,
						      0,
						      hfs_sync_metadata, hfsmp->hfs_mp);

			    hfs_global_exclusive_lock_release(hfsmp);

			    if (hfsmp->jnl == NULL) {
				retval = EINVAL;
				goto out;
			    } else {
				hfsmp->hfs_flags &= ~HFS_NEED_JNL_RESET;
			    }

			}

			/* Only clear HFS_READ_ONLY after a successfull write */
			hfsmp->hfs_flags &= ~HFS_READ_ONLY;

			if (!(hfsmp->hfs_flags & (HFS_READ_ONLY & HFS_STANDARD))) {
				/* setup private/hidden directory for unlinked files */
				FindMetaDataDirectory(HFSTOVCB(hfsmp));
				hfs_remove_orphans(hfsmp);

				/*
				 * Allow hot file clustering if conditions allow.
				 */
				if (hfsmp->hfs_flags & HFS_METADATA_ZONE) {
					(void) hfs_recording_init(hfsmp);
				}
			}
		}

		/* Update file system parameters. */
		retval = hfs_changefs(mp, &args);

	} else /* not an update request */ {

		/* Set the mount flag to indicate that we support volfs  */
		vfs_setflags(mp, (uint64_t)((unsigned int)MNT_DOVOLFS));

		retval = hfs_mountfs(devvp, mp, &args, context);
	}
out:
	if (retval == 0) {
		(void)hfs_statfs(mp, vfs_statfs(mp), context);
	}
	return (retval);
}


struct hfs_changefs_cargs {
	struct hfsmount *hfsmp;
        int		namefix;
        int		permfix;
        int		permswitch;
};

static int
hfs_changefs_callback(struct vnode *vp, void *cargs)
{
	ExtendedVCB *vcb;
	struct cnode *cp;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	struct hfs_changefs_cargs *args;

	args = (struct hfs_changefs_cargs *)cargs;

	cp = VTOC(vp);
	vcb = HFSTOVCB(args->hfsmp);

	if (cat_lookup(args->hfsmp, &cp->c_desc, 0, &cndesc, &cnattr, NULL, NULL)) {
	        /*
		 * If we couldn't find this guy skip to the next one
		 */
	        if (args->namefix)
		        cache_purge(vp);

		return (VNODE_RETURNED);
	}
	/*
	 * Get the real uid/gid and perm mask from disk.
	 */
	if (args->permswitch || args->permfix) {
	        cp->c_uid = cnattr.ca_uid;
		cp->c_gid = cnattr.ca_gid;
		cp->c_mode = cnattr.ca_mode;
	}
	/*
	 * If we're switching name converters then...
	 *   Remove the existing entry from the namei cache.
	 *   Update name to one based on new encoder.
	 */
	if (args->namefix) {
	        cache_purge(vp);
		replace_desc(cp, &cndesc);

		if (cndesc.cd_cnid == kHFSRootFolderID) {
		        strncpy(vcb->vcbVN, cp->c_desc.cd_nameptr, NAME_MAX);
			cp->c_desc.cd_encoding = args->hfsmp->hfs_encoding;
		}
	} else {
	        cat_releasedesc(&cndesc);
	}
	return (VNODE_RETURNED);
}

/* Change fs mount parameters */
static int
hfs_changefs(struct mount *mp, struct hfs_mount_args *args)
{
	int retval = 0;
	int namefix, permfix, permswitch;
	struct hfsmount *hfsmp;
	ExtendedVCB *vcb;
	hfs_to_unicode_func_t	get_unicode_func;
	unicode_to_hfs_func_t	get_hfsname_func;
	u_long old_encoding = 0;
	struct hfs_changefs_cargs cargs;
	uint32_t mount_flags;

	hfsmp = VFSTOHFS(mp);
	vcb = HFSTOVCB(hfsmp);
	mount_flags = (unsigned int)vfs_flags(mp);

	permswitch = (((hfsmp->hfs_flags & HFS_UNKNOWN_PERMS) &&
	               ((mount_flags & MNT_UNKNOWNPERMISSIONS) == 0)) ||
	              (((hfsmp->hfs_flags & HFS_UNKNOWN_PERMS) == 0) &&
	               (mount_flags & MNT_UNKNOWNPERMISSIONS)));

	/* The root filesystem must operate with actual permissions: */
	if (permswitch && (mount_flags & MNT_ROOTFS) && (mount_flags & MNT_UNKNOWNPERMISSIONS)) {
		vfs_clearflags(mp, (uint64_t)((unsigned int)MNT_UNKNOWNPERMISSIONS));	/* Just say "No". */
		return EINVAL;
	}
	if (mount_flags & MNT_UNKNOWNPERMISSIONS)
		hfsmp->hfs_flags |= HFS_UNKNOWN_PERMS;
	else
		hfsmp->hfs_flags &= ~HFS_UNKNOWN_PERMS;

	namefix = permfix = 0;

	/* Change the timezone (Note: this affects all hfs volumes and hfs+ volume create dates) */
	if (args->hfs_timezone.tz_minuteswest != VNOVAL) {
		gTimeZone = args->hfs_timezone;
	}

	/* Change the default uid, gid and/or mask */
	if ((args->hfs_uid != (uid_t)VNOVAL) && (hfsmp->hfs_uid != args->hfs_uid)) {
		hfsmp->hfs_uid = args->hfs_uid;
		if (vcb->vcbSigWord == kHFSPlusSigWord)
			++permfix;
	}
	if ((args->hfs_gid != (gid_t)VNOVAL) && (hfsmp->hfs_gid != args->hfs_gid)) {
		hfsmp->hfs_gid = args->hfs_gid;
		if (vcb->vcbSigWord == kHFSPlusSigWord)
			++permfix;
	}
	if (args->hfs_mask != (mode_t)VNOVAL) {
		if (hfsmp->hfs_dir_mask != (args->hfs_mask & ALLPERMS)) {
			hfsmp->hfs_dir_mask = args->hfs_mask & ALLPERMS;
			hfsmp->hfs_file_mask = args->hfs_mask & ALLPERMS;
			if ((args->flags != VNOVAL) && (args->flags & HFSFSMNT_NOXONFILES))
				hfsmp->hfs_file_mask = (args->hfs_mask & DEFFILEMODE);
			if (vcb->vcbSigWord == kHFSPlusSigWord)
				++permfix;
		}
	}
	
	/* Change the hfs encoding value (hfs only) */
	if ((vcb->vcbSigWord == kHFSSigWord)	&&
	    (args->hfs_encoding != (u_long)VNOVAL)              &&
	    (hfsmp->hfs_encoding != args->hfs_encoding)) {

		retval = hfs_getconverter(args->hfs_encoding, &get_unicode_func, &get_hfsname_func);
		if (retval)
			goto exit;

		/*
		 * Connect the new hfs_get_unicode converter but leave
		 * the old hfs_get_hfsname converter in place so that
		 * we can lookup existing vnodes to get their correctly
		 * encoded names.
		 *
		 * When we're all finished, we can then connect the new
		 * hfs_get_hfsname converter and release our interest
		 * in the old converters.
		 */
		hfsmp->hfs_get_unicode = get_unicode_func;
		old_encoding = hfsmp->hfs_encoding;
		hfsmp->hfs_encoding = args->hfs_encoding;
		++namefix;
	}

	if (!(namefix || permfix || permswitch))
		goto exit;

	/* XXX 3762912 hack to support HFS filesystem 'owner' */
	if (permfix)
		vfs_setowner(mp,
		    hfsmp->hfs_uid == UNKNOWNUID ? KAUTH_UID_NONE : hfsmp->hfs_uid,
		    hfsmp->hfs_gid == UNKNOWNGID ? KAUTH_GID_NONE : hfsmp->hfs_gid);
	
	/*
	 * For each active vnode fix things that changed
	 *
	 * Note that we can visit a vnode more than once
	 * and we can race with fsync.
	 *
	 * hfs_changefs_callback will be called for each vnode
	 * hung off of this mount point
	 * the vnode will be
	 * properly referenced and unreferenced around the callback
	 */
	cargs.hfsmp = hfsmp;
	cargs.namefix = namefix;
	cargs.permfix = permfix;
	cargs.permswitch = permswitch;

	vnode_iterate(mp, 0, hfs_changefs_callback, (void *)&cargs);

	/*
	 * If we're switching name converters we can now
	 * connect the new hfs_get_hfsname converter and
	 * release our interest in the old converters.
	 */
	if (namefix) {
		hfsmp->hfs_get_hfsname = get_hfsname_func;
		vcb->volumeNameEncodingHint = args->hfs_encoding;
		(void) hfs_relconverter(old_encoding);
	}
exit:
	return (retval);
}


struct hfs_reload_cargs {
	struct hfsmount *hfsmp;
        kauth_cred_t cred;
        struct proc	*p;
        int		error;
};

static int
hfs_reload_callback(struct vnode *vp, void *cargs)
{
	struct cnode *cp;
	struct hfs_reload_cargs *args;

	args = (struct hfs_reload_cargs *)cargs;
	/*
	 * flush all the buffers associated with this node
	 */
	(void) buf_invalidateblks(vp, 0, 0, 0);

	cp = VTOC(vp);
	/* 
	 * Remove any directory hints
	 */
	if (vnode_isdir(vp))
	        hfs_reldirhints(cp, 0);

	/*
	 * Re-read cnode data for all active vnodes (non-metadata files).
	 */
	if (!vnode_issystem(vp) && !VNODE_IS_RSRC(vp)) {
	        struct cat_fork *datafork;
		struct cat_desc desc;

		datafork = cp->c_datafork ? &cp->c_datafork->ff_data : NULL;

		/* lookup by fileID since name could have changed */
		if ((args->error = cat_idlookup(args->hfsmp, cp->c_fileid, &desc, &cp->c_attr, datafork)))
		        return (VNODE_RETURNED_DONE);

		/* update cnode's catalog descriptor */
		(void) replace_desc(cp, &desc);
	}
	return (VNODE_RETURNED);
}

/*
 * Reload all incore data for a filesystem (used after running fsck on
 * the root filesystem and finding things to fix). The filesystem must
 * be mounted read-only.
 *
 * Things to do to update the mount:
 *	invalidate all cached meta-data.
 *	invalidate all inactive vnodes.
 *	invalidate all cached file data.
 *	re-read volume header from disk.
 *	re-load meta-file info (extents, file size).
 *	re-load B-tree header data.
 *	re-read cnode data for all active vnodes.
 */
static int
hfs_reload(struct mount *mountp, kauth_cred_t cred, struct proc *p)
{
	register struct vnode *devvp;
	struct buf *bp;
	int sectorsize;
	int error, i;
	struct hfsmount *hfsmp;
	struct HFSPlusVolumeHeader *vhp;
	ExtendedVCB *vcb;
	struct filefork *forkp;
    	struct cat_desc cndesc;
	struct hfs_reload_cargs args;

    	hfsmp = VFSTOHFS(mountp);
	vcb = HFSTOVCB(hfsmp);

	if (vcb->vcbSigWord == kHFSSigWord)
		return (EINVAL);	/* rooting from HFS is not supported! */

	/*
	 * Invalidate all cached meta-data.
	 */
	devvp = hfsmp->hfs_devvp;
	if (buf_invalidateblks(devvp, 0, 0, 0))
		panic("hfs_reload: dirty1");

	args.hfsmp = hfsmp;
	args.cred = cred;
	args.p = p;
	args.error = 0;
	/*
	 * hfs_reload_callback will be called for each vnode
	 * hung off of this mount point that can't be recycled...
	 * vnode_iterate will recycle those that it can (the VNODE_RELOAD option)
	 * the vnode will be in an 'unbusy' state (VNODE_WAIT) and 
	 * properly referenced and unreferenced around the callback
	 */
	vnode_iterate(mountp, VNODE_RELOAD | VNODE_WAIT, hfs_reload_callback, (void *)&args);

	if (args.error)
	        return (args.error);

	/*
	 * Re-read VolumeHeader from disk.
	 */
	sectorsize = hfsmp->hfs_phys_block_size;

	error = (int)buf_meta_bread(hfsmp->hfs_devvp,
			(daddr64_t)((vcb->hfsPlusIOPosOffset / sectorsize) + HFS_PRI_SECTOR(sectorsize)),
			sectorsize, NOCRED, &bp);
	if (error) {
        	if (bp != NULL)
        		buf_brelse(bp);
		return (error);
	}

	vhp = (HFSPlusVolumeHeader *) (buf_dataptr(bp) + HFS_PRI_OFFSET(sectorsize));

	/* Do a quick sanity check */
	if ((SWAP_BE16(vhp->signature) != kHFSPlusSigWord &&
	     SWAP_BE16(vhp->signature) != kHFSXSigWord) ||
	    (SWAP_BE16(vhp->version) != kHFSPlusVersion &&
	     SWAP_BE16(vhp->version) != kHFSXVersion) ||
	    SWAP_BE32(vhp->blockSize) != vcb->blockSize) {
		buf_brelse(bp);
		return (EIO);
	}

	vcb->vcbLsMod		= to_bsd_time(SWAP_BE32(vhp->modifyDate));
	vcb->vcbAtrb		= SWAP_BE32 (vhp->attributes);
	vcb->vcbJinfoBlock  = SWAP_BE32(vhp->journalInfoBlock);
	vcb->vcbClpSiz		= SWAP_BE32 (vhp->rsrcClumpSize);
	vcb->vcbNxtCNID		= SWAP_BE32 (vhp->nextCatalogID);
	vcb->vcbVolBkUp		= to_bsd_time(SWAP_BE32(vhp->backupDate));
	vcb->vcbWrCnt		= SWAP_BE32 (vhp->writeCount);
	vcb->vcbFilCnt		= SWAP_BE32 (vhp->fileCount);
	vcb->vcbDirCnt		= SWAP_BE32 (vhp->folderCount);
	vcb->nextAllocation 	= SWAP_BE32 (vhp->nextAllocation);
	vcb->totalBlocks	= SWAP_BE32 (vhp->totalBlocks);
	vcb->freeBlocks		= SWAP_BE32 (vhp->freeBlocks);
	vcb->encodingsBitmap	= SWAP_BE64 (vhp->encodingsBitmap);
	bcopy(vhp->finderInfo, vcb->vcbFndrInfo, sizeof(vhp->finderInfo));    
	vcb->localCreateDate	= SWAP_BE32 (vhp->createDate); /* hfs+ create date is in local time */ 

	/*
	 * Re-load meta-file vnode data (extent info, file size, etc).
	 */
	forkp = VTOF((struct vnode *)vcb->extentsRefNum);
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		forkp->ff_extents[i].startBlock =
			SWAP_BE32 (vhp->extentsFile.extents[i].startBlock);
		forkp->ff_extents[i].blockCount =
			SWAP_BE32 (vhp->extentsFile.extents[i].blockCount);
	}
	forkp->ff_size      = SWAP_BE64 (vhp->extentsFile.logicalSize);
	forkp->ff_blocks    = SWAP_BE32 (vhp->extentsFile.totalBlocks);
	forkp->ff_clumpsize = SWAP_BE32 (vhp->extentsFile.clumpSize);


	forkp = VTOF((struct vnode *)vcb->catalogRefNum);
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		forkp->ff_extents[i].startBlock	=
			SWAP_BE32 (vhp->catalogFile.extents[i].startBlock);
		forkp->ff_extents[i].blockCount	=
			SWAP_BE32 (vhp->catalogFile.extents[i].blockCount);
	}
	forkp->ff_size      = SWAP_BE64 (vhp->catalogFile.logicalSize);
	forkp->ff_blocks    = SWAP_BE32 (vhp->catalogFile.totalBlocks);
	forkp->ff_clumpsize = SWAP_BE32 (vhp->catalogFile.clumpSize);

	if (hfsmp->hfs_attribute_vp) {
		forkp = VTOF(hfsmp->hfs_attribute_vp);
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			forkp->ff_extents[i].startBlock	=
				SWAP_BE32 (vhp->attributesFile.extents[i].startBlock);
			forkp->ff_extents[i].blockCount	=
				SWAP_BE32 (vhp->attributesFile.extents[i].blockCount);
		}
		forkp->ff_size      = SWAP_BE64 (vhp->attributesFile.logicalSize);
		forkp->ff_blocks    = SWAP_BE32 (vhp->attributesFile.totalBlocks);
		forkp->ff_clumpsize = SWAP_BE32 (vhp->attributesFile.clumpSize);
	}

	forkp = VTOF((struct vnode *)vcb->allocationsRefNum);
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		forkp->ff_extents[i].startBlock	=
			SWAP_BE32 (vhp->allocationFile.extents[i].startBlock);
		forkp->ff_extents[i].blockCount	=
			SWAP_BE32 (vhp->allocationFile.extents[i].blockCount);
	}
	forkp->ff_size      = SWAP_BE64 (vhp->allocationFile.logicalSize);
	forkp->ff_blocks    = SWAP_BE32 (vhp->allocationFile.totalBlocks);
	forkp->ff_clumpsize = SWAP_BE32 (vhp->allocationFile.clumpSize);

	buf_brelse(bp);
	vhp = NULL;

	/*
	 * Re-load B-tree header data
	 */
	forkp = VTOF((struct vnode *)vcb->extentsRefNum);
	if ( (error = MacToVFSError( BTReloadData((FCB*)forkp) )) )
		return (error);

	forkp = VTOF((struct vnode *)vcb->catalogRefNum);
	if ( (error = MacToVFSError( BTReloadData((FCB*)forkp) )) )
		return (error);

	if (hfsmp->hfs_attribute_vp) {
		forkp = VTOF(hfsmp->hfs_attribute_vp);
		if ( (error = MacToVFSError( BTReloadData((FCB*)forkp) )) )
			return (error);
	}

	/* Reload the volume name */
	if ((error = cat_idlookup(hfsmp, kHFSRootFolderID, &cndesc, NULL, NULL)))
		return (error);
	vcb->volumeNameEncodingHint = cndesc.cd_encoding;
	bcopy(cndesc.cd_nameptr, vcb->vcbVN, min(255, cndesc.cd_namelen));
	cat_releasedesc(&cndesc);

	/* Re-establish private/hidden directory for unlinked files */
	FindMetaDataDirectory(vcb);

	/* In case any volume information changed to trigger a notification */
	hfs_generate_volume_notifications(hfsmp);
    
	return (0);
}


/*
 * Common code for mount and mountroot
 */
static int
hfs_mountfs(struct vnode *devvp, struct mount *mp, struct hfs_mount_args *args,
            vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	int retval = E_NONE;
	struct hfsmount	*hfsmp;
	struct buf *bp;
	dev_t dev;
	HFSMasterDirectoryBlock *mdbp;
	int ronly;
	int i;
	int mntwrapper;
	kauth_cred_t cred;
	u_int64_t disksize;
	daddr64_t blkcnt;
	u_int32_t blksize;
	u_int32_t minblksize;
	u_int32_t iswritable;
	daddr64_t mdb_offset;

	ronly = vfs_isrdonly(mp);
	dev = vnode_specrdev(devvp);
	cred = p ? vfs_context_ucred(context) : NOCRED;
	mntwrapper = 0;

	bp = NULL;
	hfsmp = NULL;
	mdbp = NULL;
	minblksize = kHFSBlockSize;

	/* Advisory locking should be handled at the VFS layer */
	vfs_setlocklocal(mp);

	/* Get the real physical block size. */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&blksize, 0, context)) {
		retval = ENXIO;
		goto error_exit;
	}
	/* Switch to 512 byte sectors (temporarily) */
	if (blksize > 512) {
		u_int32_t size512 = 512;

		if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&size512, FWRITE, context)) {
			retval = ENXIO;
			goto error_exit;
		}
	}
	/* Get the number of 512 byte physical blocks. */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, context)) {
		retval = ENXIO;
		goto error_exit;
	}
	/* Compute an accurate disk size (i.e. within 512 bytes) */
	disksize = (u_int64_t)blkcnt * (u_int64_t)512;

	/*
	 * On Tiger it is not necessary to switch the device 
	 * block size to be 4k if there are more than 31-bits
	 * worth of blocks but to insure compatibility with
	 * pre-Tiger systems we have to do it.
	 */
	if (blkcnt > (u_int64_t)0x000000007fffffff) {
		minblksize = blksize = 4096;
	}
	
	/* Now switch to our prefered physical block size. */
	if (blksize > 512) {
		if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&blksize, FWRITE, context)) {
			retval = ENXIO;
			goto error_exit;
		}
		/* Get the count of physical blocks. */
		if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, context)) {
			retval = ENXIO;
			goto error_exit;
		}
	}
	/*
	 * At this point:
	 *   minblksize is the minimum physical block size
	 *   blksize has our prefered physical block size
	 *   blkcnt has the total number of physical blocks
	 */

	mdb_offset = (daddr64_t)HFS_PRI_SECTOR(blksize);
	if ((retval = (int)buf_meta_bread(devvp, mdb_offset, blksize, cred, &bp))) {
		goto error_exit;
	}
	MALLOC(mdbp, HFSMasterDirectoryBlock *, kMDBSize, M_TEMP, M_WAITOK);
	bcopy((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(blksize), mdbp, kMDBSize);
	buf_brelse(bp);
	bp = NULL;

	MALLOC(hfsmp, struct hfsmount *, sizeof(struct hfsmount), M_HFSMNT, M_WAITOK);
	bzero(hfsmp, sizeof(struct hfsmount));
	
	/*
	 *  Init the volume information structure
	 */
	
	lck_mtx_init(&hfsmp->hfs_mutex, hfs_mutex_group, hfs_lock_attr);
	lck_mtx_init(&hfsmp->hfc_mutex, hfs_mutex_group, hfs_lock_attr);
	lck_rw_init(&hfsmp->hfs_global_lock, hfs_rwlock_group, hfs_lock_attr);
	lck_rw_init(&hfsmp->hfs_insync, hfs_rwlock_group, hfs_lock_attr);

	vfs_setfsprivate(mp, hfsmp);
	hfsmp->hfs_mp = mp;			/* Make VFSTOHFS work */
	hfsmp->hfs_raw_dev = vnode_specrdev(devvp);
	hfsmp->hfs_devvp = devvp;
	hfsmp->hfs_phys_block_size = blksize;
	hfsmp->hfs_phys_block_count = blkcnt;
	hfsmp->hfs_flags |= HFS_WRITEABLE_MEDIA;
	if (ronly)
		hfsmp->hfs_flags |= HFS_READ_ONLY;
	if (((unsigned int)vfs_flags(mp)) & MNT_UNKNOWNPERMISSIONS)
		hfsmp->hfs_flags |= HFS_UNKNOWN_PERMS;
	for (i = 0; i < MAXQUOTAS; i++)
		dqfileinit(&hfsmp->hfs_qfiles[i]);

	if (args) {
		hfsmp->hfs_uid = (args->hfs_uid == (uid_t)VNOVAL) ? UNKNOWNUID : args->hfs_uid;
		if (hfsmp->hfs_uid == 0xfffffffd) hfsmp->hfs_uid = UNKNOWNUID;
		hfsmp->hfs_gid = (args->hfs_gid == (gid_t)VNOVAL) ? UNKNOWNGID : args->hfs_gid;
		if (hfsmp->hfs_gid == 0xfffffffd) hfsmp->hfs_gid = UNKNOWNGID;
		vfs_setowner(mp, hfsmp->hfs_uid, hfsmp->hfs_gid);				/* tell the VFS */
		if (args->hfs_mask != (mode_t)VNOVAL) {
			hfsmp->hfs_dir_mask = args->hfs_mask & ALLPERMS;
			if (args->flags & HFSFSMNT_NOXONFILES) {
				hfsmp->hfs_file_mask = (args->hfs_mask & DEFFILEMODE);
			} else {
				hfsmp->hfs_file_mask = args->hfs_mask & ALLPERMS;
			}
		} else {
			hfsmp->hfs_dir_mask = UNKNOWNPERMISSIONS & ALLPERMS;		/* 0777: rwx---rwx */
			hfsmp->hfs_file_mask = UNKNOWNPERMISSIONS & DEFFILEMODE;	/* 0666: no --x by default? */
		}
		if ((args->flags != (int)VNOVAL) && (args->flags & HFSFSMNT_WRAPPER))
			mntwrapper = 1;
	} else {
		/* Even w/o explicit mount arguments, MNT_UNKNOWNPERMISSIONS requires setting up uid, gid, and mask: */
		if (((unsigned int)vfs_flags(mp)) & MNT_UNKNOWNPERMISSIONS) {
			hfsmp->hfs_uid = UNKNOWNUID;
			hfsmp->hfs_gid = UNKNOWNGID;
			vfs_setowner(mp, hfsmp->hfs_uid, hfsmp->hfs_gid);			/* tell the VFS */
			hfsmp->hfs_dir_mask = UNKNOWNPERMISSIONS & ALLPERMS;		/* 0777: rwx---rwx */
			hfsmp->hfs_file_mask = UNKNOWNPERMISSIONS & DEFFILEMODE;	/* 0666: no --x by default? */
		}
	}

	/* Find out if disk media is writable. */
	if (VNOP_IOCTL(devvp, DKIOCISWRITABLE, (caddr_t)&iswritable, 0, context) == 0) {
		if (iswritable)
			hfsmp->hfs_flags |= HFS_WRITEABLE_MEDIA;
		else
			hfsmp->hfs_flags &= ~HFS_WRITEABLE_MEDIA;
	}

	// record the current time at which we're mounting this volume
	{
	    struct timeval tv;
	    microtime(&tv);
	    hfsmp->hfs_mount_time = tv.tv_sec;
	}

	/* Mount a standard HFS disk */
	if ((SWAP_BE16(mdbp->drSigWord) == kHFSSigWord) &&
	    (mntwrapper || (SWAP_BE16(mdbp->drEmbedSigWord) != kHFSPlusSigWord))) {
	        if ((vfs_flags(mp) & MNT_ROOTFS)) {	
			retval = EINVAL;  /* Cannot root from HFS standard disks */
			goto error_exit;
		}
		/* HFS disks can only use 512 byte physical blocks */
		if (blksize > kHFSBlockSize) {
			blksize = kHFSBlockSize;
			if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&blksize, FWRITE, context)) {
				retval = ENXIO;
				goto error_exit;
			}
			if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, context)) {
				retval = ENXIO;
				goto error_exit;
			}
			hfsmp->hfs_phys_block_size = blksize;
			hfsmp->hfs_phys_block_count = blkcnt;
		}
		if (args) {
			hfsmp->hfs_encoding = args->hfs_encoding;
			HFSTOVCB(hfsmp)->volumeNameEncodingHint = args->hfs_encoding;

			/* establish the timezone */
			gTimeZone = args->hfs_timezone;
		}

		retval = hfs_getconverter(hfsmp->hfs_encoding, &hfsmp->hfs_get_unicode,
					&hfsmp->hfs_get_hfsname);
		if (retval)
			goto error_exit;

		retval = hfs_MountHFSVolume(hfsmp, mdbp, p);
		if (retval)
			(void) hfs_relconverter(hfsmp->hfs_encoding);

	} else /* Mount an HFS Plus disk */ {
		HFSPlusVolumeHeader *vhp;
		off_t embeddedOffset;
		int   jnl_disable = 0;
	
		/* Get the embedded Volume Header */
		if (SWAP_BE16(mdbp->drEmbedSigWord) == kHFSPlusSigWord) {
			embeddedOffset = SWAP_BE16(mdbp->drAlBlSt) * kHFSBlockSize;
			embeddedOffset += (u_int64_t)SWAP_BE16(mdbp->drEmbedExtent.startBlock) *
			                  (u_int64_t)SWAP_BE32(mdbp->drAlBlkSiz);

			/*
			 * If the embedded volume doesn't start on a block
			 * boundary, then switch the device to a 512-byte
			 * block size so everything will line up on a block
			 * boundary.
			 */
			if ((embeddedOffset % blksize) != 0) {
				printf("HFS Mount: embedded volume offset not"
				    " a multiple of physical block size (%d);"
				    " switching to 512\n", blksize);
				blksize = 512;
				if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE,
				    (caddr_t)&blksize, FWRITE, context)) {
					retval = ENXIO;
					goto error_exit;
				}
				if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT,
				    (caddr_t)&blkcnt, 0, context)) {
					retval = ENXIO;
					goto error_exit;
				}
				/* Note: relative block count adjustment */
				hfsmp->hfs_phys_block_count *=
				    hfsmp->hfs_phys_block_size / blksize;
				hfsmp->hfs_phys_block_size = blksize;
			}

			disksize = (u_int64_t)SWAP_BE16(mdbp->drEmbedExtent.blockCount) *
			           (u_int64_t)SWAP_BE32(mdbp->drAlBlkSiz);

			hfsmp->hfs_phys_block_count = disksize / blksize;
	
			mdb_offset = (daddr64_t)((embeddedOffset / blksize) + HFS_PRI_SECTOR(blksize));
			retval = (int)buf_meta_bread(devvp, mdb_offset, blksize, cred, &bp);
			if (retval)
				goto error_exit;
			bcopy((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(blksize), mdbp, 512);
			buf_brelse(bp);
			bp = NULL;
			vhp = (HFSPlusVolumeHeader*) mdbp;

		} else /* pure HFS+ */ {
			embeddedOffset = 0;
			vhp = (HFSPlusVolumeHeader*) mdbp;
		}

		// XXXdbg
		//
		hfsmp->jnl = NULL;
		hfsmp->jvp = NULL;
		if (args != NULL && (args->flags & HFSFSMNT_EXTENDED_ARGS) && args->journal_disable) {
		    jnl_disable = 1;
		}
				
		//
		// We only initialize the journal here if the last person
		// to mount this volume was journaling aware.  Otherwise
		// we delay journal initialization until later at the end
		// of hfs_MountHFSPlusVolume() because the last person who
		// mounted it could have messed things up behind our back
		// (so we need to go find the .journal file, make sure it's
		// the right size, re-sync up if it was moved, etc).
		//
		if (   (SWAP_BE32(vhp->lastMountedVersion) == kHFSJMountVersion)
			&& (SWAP_BE32(vhp->attributes) & kHFSVolumeJournaledMask)
			&& !jnl_disable) {
			
			// if we're able to init the journal, mark the mount
			// point as journaled.
			//
			if (hfs_early_journal_init(hfsmp, vhp, args, embeddedOffset, mdb_offset, mdbp, cred) == 0) {
				vfs_setflags(mp, (uint64_t)((unsigned int)MNT_JOURNALED));
			} else {
				// if the journal failed to open, then set the lastMountedVersion
				// to be "FSK!" which fsck_hfs will see and force the fsck instead
				// of just bailing out because the volume is journaled.
				if (!ronly) {
				    HFSPlusVolumeHeader *jvhp;

				    hfsmp->hfs_flags |= HFS_NEED_JNL_RESET;
				    
				    if (mdb_offset == 0) {
					mdb_offset = (daddr64_t)((embeddedOffset / blksize) + HFS_PRI_SECTOR(blksize));
				    }

				    bp = NULL;
				    retval = (int)buf_meta_bread(devvp, mdb_offset, blksize, cred, &bp);
				    if (retval == 0) {
					jvhp = (HFSPlusVolumeHeader *)(buf_dataptr(bp) + HFS_PRI_OFFSET(blksize));
					    
					if (SWAP_BE16(jvhp->signature) == kHFSPlusSigWord || SWAP_BE16(jvhp->signature) == kHFSXSigWord) {
						printf ("hfs(1): Journal replay fail.  Writing lastMountVersion as FSK!\n");
					    jvhp->lastMountedVersion = SWAP_BE32(kFSKMountVersion);
					    buf_bwrite(bp);
					} else {
					    buf_brelse(bp);
					}
					bp = NULL;
				    } else if (bp) {
					buf_brelse(bp);
					// clear this so the error exit path won't try to use it
					bp = NULL;
				    }
				}

				// if this isn't the root device just bail out.
				// If it is the root device we just continue on
				// in the hopes that fsck_hfs will be able to
				// fix any damage that exists on the volume.
				if ( !(vfs_flags(mp) & MNT_ROOTFS)) {
				    retval = EINVAL;
				    goto error_exit;
				}
			}
		}
		// XXXdbg
	
		(void) hfs_getconverter(0, &hfsmp->hfs_get_unicode, &hfsmp->hfs_get_hfsname);

		retval = hfs_MountHFSPlusVolume(hfsmp, vhp, embeddedOffset, disksize, p, args, cred);
		/*
		 * If the backend didn't like our physical blocksize
		 * then retry with physical blocksize of 512.
		 */
		if ((retval == ENXIO) && (blksize > 512) && (blksize != minblksize)) {
			printf("HFS Mount: could not use physical block size "
				"(%d) switching to 512\n", blksize);
			blksize = 512;
			if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&blksize, FWRITE, context)) {
				retval = ENXIO;
				goto error_exit;
			}
			if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, context)) {
				retval = ENXIO;
				goto error_exit;
			}
			devvp->v_specsize = blksize;
			/* Note: relative block count adjustment (in case this is an embedded volume). */
    			hfsmp->hfs_phys_block_count *= hfsmp->hfs_phys_block_size / blksize;
     			hfsmp->hfs_phys_block_size = blksize;
 
			if (hfsmp->jnl) {
			    // close and re-open this with the new block size
			    journal_close(hfsmp->jnl);
			    hfsmp->jnl = NULL;
			    if (hfs_early_journal_init(hfsmp, vhp, args, embeddedOffset, mdb_offset, mdbp, cred) == 0) {
					vfs_setflags(mp, (uint64_t)((unsigned int)MNT_JOURNALED));
				} else {
					// if the journal failed to open, then set the lastMountedVersion
					// to be "FSK!" which fsck_hfs will see and force the fsck instead
					// of just bailing out because the volume is journaled.
					if (!ronly) {
				    	HFSPlusVolumeHeader *jvhp;

				    	hfsmp->hfs_flags |= HFS_NEED_JNL_RESET;
				    
				    	if (mdb_offset == 0) {
							mdb_offset = (daddr64_t)((embeddedOffset / blksize) + HFS_PRI_SECTOR(blksize));
				    	}

				   	 	bp = NULL;
				    	retval = (int)buf_meta_bread(devvp, mdb_offset, blksize, cred, &bp);
				    	if (retval == 0) {
							jvhp = (HFSPlusVolumeHeader *)(buf_dataptr(bp) + HFS_PRI_OFFSET(blksize));
					    
							if (SWAP_BE16(jvhp->signature) == kHFSPlusSigWord || SWAP_BE16(jvhp->signature) == kHFSXSigWord) {
								printf ("hfs(2): Journal replay fail.  Writing lastMountVersion as FSK!\n");
					    		jvhp->lastMountedVersion = SWAP_BE32(kFSKMountVersion);
					    		buf_bwrite(bp);
							} else {
					    		buf_brelse(bp);
							}
							bp = NULL;
				    	} else if (bp) {
							buf_brelse(bp);
							// clear this so the error exit path won't try to use it
							bp = NULL;
				    	}
					}

					// if this isn't the root device just bail out.
					// If it is the root device we just continue on
					// in the hopes that fsck_hfs will be able to
					// fix any damage that exists on the volume.
					if ( !(vfs_flags(mp) & MNT_ROOTFS)) {
				    	retval = EINVAL;
				    	goto error_exit;
					}
				}
			}

			/* Try again with a smaller block size... */
			retval = hfs_MountHFSPlusVolume(hfsmp, vhp, embeddedOffset, disksize, p, args, cred);
		}
		if (retval)
			(void) hfs_relconverter(0);
	}

	// save off a snapshot of the mtime from the previous mount
	// (for matador).
	hfsmp->hfs_last_mounted_mtime = hfsmp->hfs_mtime;

	if ( retval ) {
		goto error_exit;
	}

	mp->mnt_vfsstat.f_fsid.val[0] = (long)dev;
	mp->mnt_vfsstat.f_fsid.val[1] = vfs_typenum(mp);
	vfs_setmaxsymlen(mp, 0);
	mp->mnt_vtable->vfc_threadsafe = TRUE;
	mp->mnt_vtable->vfc_vfsflags |= VFC_VFSNATIVEXATTR;

	if (args) {
		/*
		 * Set the free space warning levels for a non-root volume:
		 *
		 * Set the lower freespace limit (the level that will trigger a warning)
		 * to 5% of the volume size or 250MB, whichever is less, and the desired
		 * level (which will cancel the alert request) to 1/2 above that limit.
		 * Start looking for free space to drop below this level and generate a
		 * warning immediately if needed:
		 */
		hfsmp->hfs_freespace_notify_warninglimit =
			MIN(HFS_LOWDISKTRIGGERLEVEL / HFSTOVCB(hfsmp)->blockSize,
				(HFSTOVCB(hfsmp)->totalBlocks / 100) * HFS_LOWDISKTRIGGERFRACTION);
		hfsmp->hfs_freespace_notify_desiredlevel =
			MIN(HFS_LOWDISKSHUTOFFLEVEL / HFSTOVCB(hfsmp)->blockSize,
				(HFSTOVCB(hfsmp)->totalBlocks / 100) * HFS_LOWDISKSHUTOFFFRACTION);
	} else {
		/*
		 * Set the free space warning levels for the root volume:
		 *
		 * Set the lower freespace limit (the level that will trigger a warning)
		 * to 1% of the volume size or 50MB, whichever is less, and the desired
		 * level (which will cancel the alert request) to 2% or 75MB, whichever is less.
		 */
		hfsmp->hfs_freespace_notify_warninglimit =
			MIN(HFS_ROOTLOWDISKTRIGGERLEVEL / HFSTOVCB(hfsmp)->blockSize,
				(HFSTOVCB(hfsmp)->totalBlocks / 100) * HFS_ROOTLOWDISKTRIGGERFRACTION);
		hfsmp->hfs_freespace_notify_desiredlevel =
			MIN(HFS_ROOTLOWDISKSHUTOFFLEVEL / HFSTOVCB(hfsmp)->blockSize,
				(HFSTOVCB(hfsmp)->totalBlocks / 100) * HFS_ROOTLOWDISKSHUTOFFFRACTION);
	};
	
	/*
	 * Start looking for free space to drop below this level and generate a
	 * warning immediately if needed:
	 */
	hfsmp->hfs_notification_conditions = 0;
	hfs_generate_volume_notifications(hfsmp);
	
	if (ronly == 0) {
		(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
	}
	FREE(mdbp, M_TEMP);
	return (0);

error_exit:
	if (bp)
		buf_brelse(bp);
	if (mdbp)
		FREE(mdbp, M_TEMP);

	if (hfsmp && hfsmp->jvp && hfsmp->jvp != hfsmp->hfs_devvp) {
	    (void)VNOP_CLOSE(hfsmp->jvp, ronly ? FREAD : FREAD|FWRITE, context);
		hfsmp->jvp = NULL;
	}
	if (hfsmp) {
		FREE(hfsmp, M_HFSMNT);
		vfs_setfsprivate(mp, NULL);
	}
        return (retval);
}


/*
 * Make a filesystem operational.
 * Nothing to do at the moment.
 */
/* ARGSUSED */
static int
hfs_start(__unused struct mount *mp, __unused int flags, __unused vfs_context_t context)
{
	return (0);
}


/*
 * unmount system call
 */
static int
hfs_unmount(struct mount *mp, int mntflags, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	int retval = E_NONE;
	int flags;
	int force;
	int started_tr = 0;

	flags = 0;
	force = 0;
	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
		force = 1;
	}

	if ((retval = hfs_flushfiles(mp, flags, p)) && !force)
 		return (retval);

	if (hfsmp->hfs_flags & HFS_METADATA_ZONE)
		(void) hfs_recording_suspend(hfsmp);

	/*
	 * Flush out the b-trees, volume bitmap and Volume Header
	 */
	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0) {
		hfs_start_transaction(hfsmp);
		started_tr = 1;

		if (hfsmp->hfs_attribute_vp) {
			(void) hfs_lock(VTOC(hfsmp->hfs_attribute_vp), HFS_EXCLUSIVE_LOCK);
			retval = hfs_fsync(hfsmp->hfs_attribute_vp, MNT_WAIT, 0, p);
			hfs_unlock(VTOC(hfsmp->hfs_attribute_vp));
			if (retval && !force)
				goto err_exit;
		}

		(void) hfs_lock(VTOC(hfsmp->hfs_catalog_vp), HFS_EXCLUSIVE_LOCK);
		retval = hfs_fsync(hfsmp->hfs_catalog_vp, MNT_WAIT, 0, p);
		hfs_unlock(VTOC(hfsmp->hfs_catalog_vp));
		if (retval && !force)
			goto err_exit;
		
		(void) hfs_lock(VTOC(hfsmp->hfs_extents_vp), HFS_EXCLUSIVE_LOCK);
		retval = hfs_fsync(hfsmp->hfs_extents_vp, MNT_WAIT, 0, p);
		hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
		if (retval && !force)
			goto err_exit;
			
		if (hfsmp->hfs_allocation_vp) {
			(void) hfs_lock(VTOC(hfsmp->hfs_allocation_vp), HFS_EXCLUSIVE_LOCK);
			retval = hfs_fsync(hfsmp->hfs_allocation_vp, MNT_WAIT, 0, p);
			hfs_unlock(VTOC(hfsmp->hfs_allocation_vp));
			if (retval && !force)
				goto err_exit;
		}

		if (hfsmp->hfc_filevp && vnode_issystem(hfsmp->hfc_filevp)) {
			retval = hfs_fsync(hfsmp->hfc_filevp, MNT_WAIT, 0, p);
			if (retval && !force)
				goto err_exit;
		}
#if 0		
		/* See if this volume is damaged, is so do not unmount cleanly */
		if (HFSTOVCB(hfsmp)->vcbFlags & kHFS_DamagedVolume) {
			HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeUnmountedMask;
		} else {
			HFSTOVCB(hfsmp)->vcbAtrb |= kHFSVolumeUnmountedMask;
		}
#else
		HFSTOVCB(hfsmp)->vcbAtrb |= kHFSVolumeUnmountedMask;
#endif
		retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
		if (retval) {
			HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeUnmountedMask;
			if (!force)
				goto err_exit;	/* could not flush everything */
		}

		hfs_end_transaction(hfsmp);
		started_tr = 0;
	}

	if (hfsmp->jnl) {
		journal_flush(hfsmp->jnl);
	}
	
	/*
	 *	Invalidate our caches and release metadata vnodes
	 */
	(void) hfsUnmount(hfsmp, p);

	/*
	 * Last chance to dump unreferenced system files.
	 */
	(void) vflush(mp, NULLVP, FORCECLOSE);

	if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord)
		(void) hfs_relconverter(hfsmp->hfs_encoding);

	// XXXdbg
	if (hfsmp->jnl) {
	    journal_close(hfsmp->jnl);
	    hfsmp->jnl = NULL;
	}

	VNOP_FSYNC(hfsmp->hfs_devvp, MNT_WAIT, context);

	if (hfsmp->jvp && hfsmp->jvp != hfsmp->hfs_devvp) {
	    retval = VNOP_CLOSE(hfsmp->jvp,
	                       hfsmp->hfs_flags & HFS_READ_ONLY ? FREAD : FREAD|FWRITE,
			       context);
	    vnode_put(hfsmp->jvp);
	    hfsmp->jvp = NULL;
	}
	// XXXdbg

#ifdef HFS_SPARSE_DEV
	/* Drop our reference on the backing fs (if any). */
	if ((hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) && hfsmp->hfs_backingfs_rootvp) {
		struct vnode * tmpvp;

		hfsmp->hfs_flags &= ~HFS_HAS_SPARSE_DEVICE;
		tmpvp = hfsmp->hfs_backingfs_rootvp;
		hfsmp->hfs_backingfs_rootvp = NULLVP;
		vnode_rele(tmpvp);
	}
#endif /* HFS_SPARSE_DEV */
	lck_mtx_destroy(&hfsmp->hfc_mutex, hfs_mutex_group);
	FREE(hfsmp, M_HFSMNT);

	return (0);

  err_exit:
	if (started_tr) {
		hfs_end_transaction(hfsmp);
	}
	return retval;
}


/*
 * Return the root of a filesystem.
 */
static int
hfs_vfs_root(struct mount *mp, struct vnode **vpp, __unused vfs_context_t context)
{
	return hfs_vget(VFSTOHFS(mp), (cnid_t)kHFSRootFolderID, vpp, 1);
}


/*
 * Do operations associated with quotas
 */
static int
hfs_quotactl(struct mount *mp, int cmds, uid_t uid, caddr_t datap, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	int cmd, type, error;

#if !QUOTA
	return (ENOTSUP);
#else
	if (uid == -1)
		uid = vfs_context_ucred(context)->cr_ruid;
	cmd = cmds >> SUBCMDSHIFT;

	switch (cmd) {
	case Q_SYNC:
	case Q_QUOTASTAT:
		break;
	case Q_GETQUOTA:
		if (uid == vfs_context_ucred(context)->cr_ruid)
			break;
		/* fall through */
	default:
		if ( (error = vfs_context_suser(context)) )
			return (error);
	}

	type = cmds & SUBCMDMASK;
	if ((u_int)type >= MAXQUOTAS)
		return (EINVAL);
	if (vfs_busy(mp, LK_NOWAIT))
		return (0);

	switch (cmd) {

	case Q_QUOTAON:
		error = hfs_quotaon(p, mp, type, datap);
		break;

	case Q_QUOTAOFF:
		error = hfs_quotaoff(p, mp, type);
		break;

	case Q_SETQUOTA:
		error = hfs_setquota(mp, uid, type, datap);
		break;

	case Q_SETUSE:
		error = hfs_setuse(mp, uid, type, datap);
		break;

	case Q_GETQUOTA:
		error = hfs_getquota(mp, uid, type, datap);
		break;

	case Q_SYNC:
		error = hfs_qsync(mp);
		break;

	case Q_QUOTASTAT:
		error = hfs_quotastat(mp, type, datap);
		break;

	default:
		error = EINVAL;
		break;
	}
	vfs_unbusy(mp);

	return (error);
#endif /* QUOTA */
}

/* Subtype is composite of bits */
#define HFS_SUBTYPE_JOURNALED      0x01
#define HFS_SUBTYPE_CASESENSITIVE  0x02
/* bits 2 - 6 reserved */
#define HFS_SUBTYPE_STANDARDHFS    0x80

/*
 * Get file system statistics.
 */
static int
hfs_statfs(struct mount *mp, register struct vfsstatfs *sbp, __unused vfs_context_t context)
{
	ExtendedVCB *vcb = VFSTOVCB(mp);
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	u_long freeCNIDs;
	uint16_t subtype = 0;

	freeCNIDs = (u_long)0xFFFFFFFF - (u_long)vcb->vcbNxtCNID;

	sbp->f_bsize = (uint32_t)vcb->blockSize;
	sbp->f_iosize = (size_t)(MAX_UPL_TRANSFER * PAGE_SIZE);
	sbp->f_blocks = (uint64_t)((unsigned long)vcb->totalBlocks);
	sbp->f_bfree = (uint64_t)((unsigned long )hfs_freeblks(hfsmp, 0));
	sbp->f_bavail = (uint64_t)((unsigned long )hfs_freeblks(hfsmp, 1));
	sbp->f_files = (uint64_t)((unsigned long )(vcb->totalBlocks - 2));  /* max files is constrained by total blocks */
	sbp->f_ffree = (uint64_t)((unsigned long )(MIN(freeCNIDs, sbp->f_bavail)));

	/*
	 * Subtypes (flavors) for HFS
	 *   0:   Mac OS Extended
	 *   1:   Mac OS Extended (Journaled) 
	 *   2:   Mac OS Extended (Case Sensitive) 
	 *   3:   Mac OS Extended (Case Sensitive, Journaled) 
	 *   4 - 127:   Reserved
	 * 128:   Mac OS Standard
	 * 
	 */
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		subtype = HFS_SUBTYPE_STANDARDHFS;
	} else /* HFS Plus */ {
		if (hfsmp->jnl)
			subtype |= HFS_SUBTYPE_JOURNALED;
		if (hfsmp->hfs_flags & HFS_CASE_SENSITIVE)
			subtype |= HFS_SUBTYPE_CASESENSITIVE;
	}
	sbp->f_fssubtype = subtype;

	return (0);
}


//
// XXXdbg -- this is a callback to be used by the journal to
//           get meta data blocks flushed out to disk.
//
// XXXdbg -- be smarter and don't flush *every* block on each
//           call.  try to only flush some so we don't wind up
//           being too synchronous.
//
__private_extern__
void
hfs_sync_metadata(void *arg)
{
	struct mount *mp = (struct mount *)arg;
	struct hfsmount *hfsmp;
	ExtendedVCB *vcb;
	buf_t	bp;
	int  sectorsize, retval;
	daddr64_t priIDSector;
	hfsmp = VFSTOHFS(mp);
	vcb = HFSTOVCB(hfsmp);

	// now make sure the super block is flushed
	sectorsize = hfsmp->hfs_phys_block_size;
	priIDSector = (daddr64_t)((vcb->hfsPlusIOPosOffset / sectorsize) +
				  HFS_PRI_SECTOR(sectorsize));
	retval = (int)buf_meta_bread(hfsmp->hfs_devvp, priIDSector, sectorsize, NOCRED, &bp);
	if ((retval != 0) && (retval != ENXIO)) {
		printf("hfs_sync_metadata: can't read volume header at %d! (retval 0x%x)\n",
			priIDSector, retval);
	}

	if (retval == 0 && ((buf_flags(bp) & (B_DELWRI | B_LOCKED)) == B_DELWRI)) {
	    buf_bwrite(bp);
	} else if (bp) {
	    buf_brelse(bp);
	}

	// the alternate super block...
	// XXXdbg - we probably don't need to do this each and every time.
	//          hfs_btreeio.c:FlushAlternate() should flag when it was
	//          written...
	if (hfsmp->hfs_alt_id_sector) {
		retval = (int)buf_meta_bread(hfsmp->hfs_devvp, hfsmp->hfs_alt_id_sector, sectorsize, NOCRED, &bp);
		if (retval == 0 && ((buf_flags(bp) & (B_DELWRI | B_LOCKED)) == B_DELWRI)) {
		    buf_bwrite(bp);
		} else if (bp) {
		    buf_brelse(bp);
		}
	}
}


struct hfs_sync_cargs {
        kauth_cred_t cred;
        struct proc  *p;
        int    waitfor;
        int    error;
};


static int
hfs_sync_callback(struct vnode *vp, void *cargs)
{
	struct cnode *cp;
	struct hfs_sync_cargs *args;
	int error;

	args = (struct hfs_sync_cargs *)cargs;

	if (hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK) != 0) {
		return (VNODE_RETURNED);
	}
	cp = VTOC(vp);

	if ((cp->c_flag & C_MODIFIED) ||
	    (cp->c_touch_acctime | cp->c_touch_chgtime | cp->c_touch_modtime) ||
	    vnode_hasdirtyblks(vp)) {
	        error = hfs_fsync(vp, args->waitfor, 0, args->p);

		if (error)
		        args->error = error;
	}
	hfs_unlock(cp);
	return (VNODE_RETURNED);
}



/*
 * Go through the disk queues to initiate sandbagged IO;
 * go through the inodes to write those that have been modified;
 * initiate the writing of the super block if it has been modified.
 *
 * Note: we are always called with the filesystem marked `MPBUSY'.
 */
static int
hfs_sync(struct mount *mp, int waitfor, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	struct cnode *cp;
	struct hfsmount *hfsmp;
	ExtendedVCB *vcb;
	struct vnode *meta_vp[4];
	int i;
	int error, allerror = 0;
	struct hfs_sync_cargs args;

	/*
	 * During MNT_UPDATE hfs_changefs might be manipulating
	 * vnodes so back off
	 */
	if (((uint32_t)vfs_flags(mp)) & MNT_UPDATE)	/* XXX MNT_UPDATE may not be visible here */
		return (0);

	hfsmp = VFSTOHFS(mp);
	if (hfsmp->hfs_flags & HFS_READ_ONLY)
		return (EROFS);

	/* skip over frozen volumes */
	if (!lck_rw_try_lock_shared(&hfsmp->hfs_insync))
		return 0;

	args.cred = vfs_context_proc(context);
	args.waitfor = waitfor;
	args.p = p;
	args.error = 0;
	/*
	 * hfs_sync_callback will be called for each vnode
	 * hung off of this mount point... the vnode will be
	 * properly referenced and unreferenced around the callback
	 */
	vnode_iterate(mp, 0, hfs_sync_callback, (void *)&args);

	if (args.error)
	        allerror = args.error;

	vcb = HFSTOVCB(hfsmp);

	meta_vp[0] = vcb->extentsRefNum;
	meta_vp[1] = vcb->catalogRefNum;
	meta_vp[2] = vcb->allocationsRefNum;  /* This is NULL for standard HFS */
	meta_vp[3] = hfsmp->hfs_attribute_vp; /* Optional file */

	/* Now sync our three metadata files */
	for (i = 0; i < 4; ++i) {
		struct vnode *btvp;

		btvp = meta_vp[i];;
		if ((btvp==0) || (vnode_mount(btvp) != mp))
			continue;

		/* XXX use hfs_systemfile_lock instead ? */
		(void) hfs_lock(VTOC(btvp), HFS_EXCLUSIVE_LOCK);
		cp = VTOC(btvp);

		if (((cp->c_flag &  C_MODIFIED) == 0) &&
		    (cp->c_touch_acctime == 0) &&
		    (cp->c_touch_chgtime == 0) &&
		    (cp->c_touch_modtime == 0) &&
		    vnode_hasdirtyblks(btvp) == 0) {
			hfs_unlock(VTOC(btvp));
			continue;
		}
		error = vnode_get(btvp);
		if (error) {
			hfs_unlock(VTOC(btvp));
			continue;
		}
		if ((error = hfs_fsync(btvp, waitfor, 0, p)))
			allerror = error;

		hfs_unlock(cp);
		vnode_put(btvp);
	};

	/*
	 * Force stale file system control information to be flushed.
	 */
	if (vcb->vcbSigWord == kHFSSigWord) {
		if ((error = VNOP_FSYNC(hfsmp->hfs_devvp, waitfor, context))) {
			allerror = error;
		}
	}
#if QUOTA
	hfs_qsync(mp);
#endif /* QUOTA */

	hfs_hotfilesync(hfsmp, p);
	/*
	 * Write back modified superblock.
	 */

	if (IsVCBDirty(vcb)) {
		error = hfs_flushvolumeheader(hfsmp, waitfor, 0);
		if (error)
			allerror = error;
	}

	if (hfsmp->jnl) {
	    journal_flush(hfsmp->jnl);
	}

	lck_rw_unlock_shared(&hfsmp->hfs_insync);	
	return (allerror);
}


/*
 * File handle to vnode
 *
 * Have to be really careful about stale file handles:
 * - check that the cnode id is valid
 * - call hfs_vget() to get the locked cnode
 * - check for an unallocated cnode (i_mode == 0)
 * - check that the given client host has export rights and return
 *   those rights via. exflagsp and credanonp
 */
static int
hfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp, struct vnode **vpp, vfs_context_t context)
{
	struct hfsfid *hfsfhp;
	struct vnode *nvp;
	int result;

	*vpp = NULL;
	hfsfhp = (struct hfsfid *)fhp;

	if (fhlen < sizeof(struct hfsfid))
		return (EINVAL);

	result = hfs_vget(VFSTOHFS(mp), ntohl(hfsfhp->hfsfid_cnid), &nvp, 0);
	if (result) {
		if (result == ENOENT)
			result = ESTALE;
		return result;
	}
	
	/* The createtime can be changed by hfs_setattr or hfs_setattrlist.
	 * For NFS, we are assuming that only if the createtime was moved
	 * forward would it mean the fileID got reused in that session by
	 * wrapping. We don't have a volume ID or other unique identifier to
	 * to use here for a generation ID across reboots, crashes where 
	 * metadata noting lastFileID didn't make it to disk but client has
	 * it, or volume erasures where fileIDs start over again. Lastly,
	 * with HFS allowing "wraps" of fileIDs now, this becomes more
	 * error prone. Future, would be change the "wrap bit" to a unique
	 * wrap number and use that for generation number. For now do this.
	 */  
	if ((ntohl(hfsfhp->hfsfid_gen) < VTOC(nvp)->c_itime)) {
		hfs_unlock(VTOC(nvp));
		vnode_put(nvp);
		return (ESTALE);
	}
	*vpp = nvp;

	hfs_unlock(VTOC(nvp));
	return (0);
}


/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
static int
hfs_vptofh(struct vnode *vp, int *fhlenp, unsigned char *fhp, vfs_context_t context)
{
	struct cnode *cp;
	struct hfsfid *hfsfhp;

	if (ISHFS(VTOVCB(vp)))
		return (ENOTSUP);	/* hfs standard is not exportable */

	if (*fhlenp < (int)sizeof(struct hfsfid))
		return (EOVERFLOW);

	cp = VTOC(vp);
	hfsfhp = (struct hfsfid *)fhp;
	hfsfhp->hfsfid_cnid = htonl(cp->c_fileid);
	hfsfhp->hfsfid_gen = htonl(cp->c_itime);
	*fhlenp = sizeof(struct hfsfid);
	
	return (0);
}


/*
 * Initial HFS filesystems, done only once.
 */
static int
hfs_init(__unused struct vfsconf *vfsp)
{
	static int done = 0;

	if (done)
		return (0);
	done = 1;
	hfs_chashinit();
	hfs_converterinit();
#if QUOTA
	dqinit();
#endif /* QUOTA */

	BTReserveSetup();
	
	
	hfs_lock_attr    = lck_attr_alloc_init();
	hfs_group_attr   = lck_grp_attr_alloc_init();
	hfs_mutex_group  = lck_grp_alloc_init("hfs-mutex", hfs_group_attr);
	hfs_rwlock_group = lck_grp_alloc_init("hfs-rwlock", hfs_group_attr);
	

	return (0);
}

static int
hfs_getmountpoint(vp, hfsmpp)
	struct vnode *vp;
	struct hfsmount **hfsmpp;
{
	struct hfsmount * hfsmp;
	char fstypename[MFSNAMELEN];

	if (vp == NULL)
		return (EINVAL);
	
	if (!vnode_isvroot(vp))
		return (EINVAL);

	vnode_vfsname(vp, fstypename);
	if (strcmp(fstypename, "hfs") != 0)
		return (EINVAL);

	hfsmp = VTOHFS(vp);

	if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord)
		return (EINVAL);

	*hfsmpp = hfsmp;

	return (0);
}

// XXXdbg
#include <sys/filedesc.h>

/*
 * HFS filesystem related variables.
 */
static int
hfs_sysctl(int *name, __unused u_int namelen, user_addr_t oldp, size_t *oldlenp, 
			user_addr_t newp, size_t newlen, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	int error;
	struct hfsmount *hfsmp;

	/* all sysctl names at this level are terminal */

	if (name[0] == HFS_ENCODINGBIAS) {
		u_int32_t bias;

		bias = hfs_getencodingbias();
		error = sysctl_int(oldp, oldlenp, newp, newlen, &bias);
		if (error == 0 && newp)
			hfs_setencodingbias(bias);
		return (error);

	} else if (name[0] == HFS_EXTEND_FS) {
        u_int64_t  newsize;
		vnode_t vp = p->p_fd->fd_cdir;

		if (newp == USER_ADDR_NULL || vp == NULL)
			return (EINVAL);
		if ((error = hfs_getmountpoint(vp, &hfsmp)))
			return (error);
		error = sysctl_quad(oldp, oldlenp, newp, newlen, &newsize);
		if (error)
			return (error);
	
		error = hfs_extendfs(hfsmp, newsize, context);		
		return (error);

	} else if (name[0] == HFS_ENCODINGHINT) {
		size_t bufsize;
		size_t bytes;
		u_int32_t hint;
		u_int16_t *unicode_name;
		char *filename;

		bufsize = MAX(newlen * 3, MAXPATHLEN);
		MALLOC(filename, char *, newlen, M_TEMP, M_WAITOK);
		MALLOC(unicode_name, u_int16_t *, bufsize, M_TEMP, M_WAITOK);

		error = copyin(newp, (caddr_t)filename, newlen);
		if (error == 0) {
			error = utf8_decodestr(filename, newlen - 1, unicode_name,
			                       &bytes, bufsize, 0, UTF_DECOMPOSED);
			if (error == 0) {
				hint = hfs_pickencoding(unicode_name, bytes / 2);
				error = sysctl_int(oldp, oldlenp, USER_ADDR_NULL, 0, &hint);
			}
		}
		FREE(unicode_name, M_TEMP);
		FREE(filename, M_TEMP);
		return (error);

	} else if (name[0] == HFS_ENABLE_JOURNALING) {
		// make the file system journaled...
		struct vnode *vp = p->p_fd->fd_cdir, *jvp;
		ExtendedVCB *vcb;
		struct cat_attr jnl_attr, jinfo_attr;
		struct cat_fork jnl_fork, jinfo_fork;
		void *jnl = NULL;
		int lockflags;

		/* Only root can enable journaling */
		if (!is_suser()) {
			return (EPERM);
		}
		if (vp == NULL)
		        return EINVAL;

		hfsmp = VTOHFS(vp);
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
			return EROFS;
		}
		if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord) {
			printf("hfs: can't make a plain hfs volume journaled.\n");
			return EINVAL;
		}

		if (hfsmp->jnl) {
		    printf("hfs: volume @ mp 0x%x is already journaled!\n", vnode_mount(vp));
		    return EAGAIN;
		}

		vcb = HFSTOVCB(hfsmp);
		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);
		if (BTHasContiguousNodes(VTOF(vcb->catalogRefNum)) == 0 ||
			BTHasContiguousNodes(VTOF(vcb->extentsRefNum)) == 0) {

			printf("hfs: volume has a btree w/non-contiguous nodes.  can not enable journaling.\n");
			hfs_systemfile_unlock(hfsmp, lockflags);
			return EINVAL;
		}
		hfs_systemfile_unlock(hfsmp, lockflags);

		// make sure these both exist!
		if (   GetFileInfo(vcb, kHFSRootFolderID, ".journal_info_block", &jinfo_attr, &jinfo_fork) == 0
			|| GetFileInfo(vcb, kHFSRootFolderID, ".journal", &jnl_attr, &jnl_fork) == 0) {

			return EINVAL;
		}

		hfs_sync(hfsmp->hfs_mp, MNT_WAIT, context);

		printf("hfs: Initializing the journal (joffset 0x%llx sz 0x%llx)...\n",
			   (off_t)name[2], (off_t)name[3]);

		jvp = hfsmp->hfs_devvp;
		jnl = journal_create(jvp,
							 (off_t)name[2] * (off_t)HFSTOVCB(hfsmp)->blockSize
							 + HFSTOVCB(hfsmp)->hfsPlusIOPosOffset,
							 (off_t)((unsigned)name[3]),
							 hfsmp->hfs_devvp,
							 hfsmp->hfs_phys_block_size,
							 0,
							 0,
							 hfs_sync_metadata, hfsmp->hfs_mp);

		if (jnl == NULL) {
			printf("hfs: FAILED to create the journal!\n");
			if (jvp && jvp != hfsmp->hfs_devvp) {
				VNOP_CLOSE(jvp, hfsmp->hfs_flags & HFS_READ_ONLY ? FREAD : FREAD|FWRITE, context);
			}
			jvp = NULL;

			return EINVAL;
		} 

		hfs_global_exclusive_lock_acquire(hfsmp);
		
		/*
		 * Flush all dirty metadata buffers.
		 */
		buf_flushdirtyblks(hfsmp->hfs_devvp, MNT_WAIT, 0, "hfs_sysctl");
		buf_flushdirtyblks(hfsmp->hfs_extents_vp, MNT_WAIT, 0, "hfs_sysctl");
		buf_flushdirtyblks(hfsmp->hfs_catalog_vp, MNT_WAIT, 0, "hfs_sysctl");
		buf_flushdirtyblks(hfsmp->hfs_allocation_vp, MNT_WAIT, 0, "hfs_sysctl");
		if (hfsmp->hfs_attribute_vp)
			buf_flushdirtyblks(hfsmp->hfs_attribute_vp, MNT_WAIT, 0, "hfs_sysctl");

		HFSTOVCB(hfsmp)->vcbJinfoBlock = name[1];
		HFSTOVCB(hfsmp)->vcbAtrb |= kHFSVolumeJournaledMask;
		hfsmp->jvp = jvp;
		hfsmp->jnl = jnl;

		// save this off for the hack-y check in hfs_remove()
		hfsmp->jnl_start        = (u_int32_t)name[2];
		hfsmp->jnl_size         = (off_t)((unsigned)name[3]);
		hfsmp->hfs_jnlinfoblkid = jinfo_attr.ca_fileid;
		hfsmp->hfs_jnlfileid    = jnl_attr.ca_fileid;

		vfs_setflags(hfsmp->hfs_mp, (uint64_t)((unsigned int)MNT_JOURNALED));

		hfs_global_exclusive_lock_release(hfsmp);
		hfs_flushvolumeheader(hfsmp, MNT_WAIT, 1);

		return 0;
	} else if (name[0] == HFS_DISABLE_JOURNALING) {
		// clear the journaling bit 
		struct vnode *vp = p->p_fd->fd_cdir;
		
		/* Only root can disable journaling */
		if (!is_suser()) {
			return (EPERM);
		}
		if (vp == NULL)
		        return EINVAL;

		hfsmp = VTOHFS(vp);

		printf("hfs: disabling journaling for mount @ 0x%x\n", vnode_mount(vp));

		hfs_global_exclusive_lock_acquire(hfsmp);

		// Lights out for you buddy!
		journal_close(hfsmp->jnl);
		hfsmp->jnl = NULL;

		if (hfsmp->jvp && hfsmp->jvp != hfsmp->hfs_devvp) {
			VNOP_CLOSE(hfsmp->jvp, hfsmp->hfs_flags & HFS_READ_ONLY ? FREAD : FREAD|FWRITE, context);
		}
		hfsmp->jvp = NULL;
		vfs_clearflags(hfsmp->hfs_mp, (uint64_t)((unsigned int)MNT_JOURNALED));
		hfsmp->jnl_start        = 0;
		hfsmp->hfs_jnlinfoblkid = 0;
		hfsmp->hfs_jnlfileid    = 0;
		
		HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeJournaledMask;
		
		hfs_global_exclusive_lock_release(hfsmp);
		hfs_flushvolumeheader(hfsmp, MNT_WAIT, 1);

		return 0;
	} else if (name[0] == HFS_GET_JOURNAL_INFO) {
		struct vnode *vp = p->p_fd->fd_cdir;
		off_t jnl_start, jnl_size;

		if (vp == NULL)
		        return EINVAL;

		hfsmp = VTOHFS(vp);
	    if (hfsmp->jnl == NULL) {
			jnl_start = 0;
			jnl_size  = 0;
	    } else {
			jnl_start = (off_t)(hfsmp->jnl_start * HFSTOVCB(hfsmp)->blockSize) + (off_t)HFSTOVCB(hfsmp)->hfsPlusIOPosOffset;
			jnl_size  = (off_t)hfsmp->jnl_size;
	    }

	    if ((error = copyout((caddr_t)&jnl_start, CAST_USER_ADDR_T(name[1]), sizeof(off_t))) != 0) {
			return error;
		}
	    if ((error = copyout((caddr_t)&jnl_size, CAST_USER_ADDR_T(name[2]), sizeof(off_t))) != 0) {
			return error;
		}

		return 0;
	} else if (name[0] == HFS_SET_PKG_EXTENSIONS) {

	    return set_package_extensions_table((void *)name[1], name[2], name[3]);
	    
	} else if (name[0] == VFS_CTL_QUERY) {
    	struct sysctl_req *req;
    	struct vfsidctl vc;
	    struct user_vfsidctl user_vc;
    	struct mount *mp;
 	    struct vfsquery vq;
	    boolean_t is_64_bit;
	
    	is_64_bit = proc_is64bit(p); 
		req = CAST_DOWN(struct sysctl_req *, oldp);	/* we're new style vfs sysctl. */
        
        if (is_64_bit) {
            error = SYSCTL_IN(req, &user_vc, sizeof(user_vc));
            if (error) return (error);
            
            mp = vfs_getvfs(&user_vc.vc_fsid);
        } 
        else {
            error = SYSCTL_IN(req, &vc, sizeof(vc));
            if (error) return (error);
            
            mp = vfs_getvfs(&vc.vc_fsid);
        }
        if (mp == NULL) return (ENOENT);
        
		hfsmp = VFSTOHFS(mp);
		bzero(&vq, sizeof(vq));
		vq.vq_flags = hfsmp->hfs_notification_conditions;
		return SYSCTL_OUT(req, &vq, sizeof(vq));;
	};

	return (ENOTSUP);
}


static int
hfs_vfs_vget(struct mount *mp, ino64_t ino, struct vnode **vpp, __unused vfs_context_t context)
{
	return hfs_vget(VFSTOHFS(mp), (cnid_t)ino, vpp, 1);
}


/*
 * Look up an HFS object by ID.
 *
 * The object is returned with an iocount reference and the cnode locked.
 *
 * If the object is a file then it will represent the data fork.
 */
__private_extern__
int
hfs_vget(struct hfsmount *hfsmp, cnid_t cnid, struct vnode **vpp, int skiplock)
{
	struct vnode *vp = NULL;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	struct cat_fork cnfork;
	struct componentname cn;
	u_int32_t linkref = 0;
	int error;
	
	/* Check for cnids that should't be exported. */
	if ((cnid < kHFSFirstUserCatalogNodeID)
	&&  (cnid != kHFSRootFolderID && cnid != kHFSRootParentID))
		return (ENOENT);

	/* Don't export HFS Private Data dir. */
	if (cnid == hfsmp->hfs_privdir_desc.cd_cnid)
		return (ENOENT);

	/*
	 * Check the hash first
	 */
	vp = hfs_chash_getvnode(hfsmp->hfs_raw_dev, cnid, 0, skiplock);
	if (vp) {
		*vpp = vp;
		return(0);
	}

	bzero(&cndesc, sizeof(cndesc));
	bzero(&cnattr, sizeof(cnattr));
	bzero(&cnfork, sizeof(cnfork));

	/*
	 * Not in hash, lookup in catalog
	 */
	if (cnid == kHFSRootParentID) {
		static char hfs_rootname[] = "/";

		cndesc.cd_nameptr = &hfs_rootname[0];
		cndesc.cd_namelen = 1;
		cndesc.cd_parentcnid = kHFSRootParentID;
		cndesc.cd_cnid = kHFSRootFolderID;
		cndesc.cd_flags = CD_ISDIR;

		cnattr.ca_fileid = kHFSRootFolderID;
		cnattr.ca_nlink = 2;
		cnattr.ca_entries = 1;
		cnattr.ca_mode = (S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO);
	} else {
		int lockflags;

		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
		error = cat_idlookup(hfsmp, cnid, &cndesc, &cnattr, &cnfork);
		hfs_systemfile_unlock(hfsmp, lockflags);

		if (error) {
			*vpp = NULL;
			return (error);
		}

		/*
		 * If we just looked up a raw hardlink inode,
		 * then finish initializing it.
		 */
		if ((cndesc.cd_parentcnid == hfsmp->hfs_privdir_desc.cd_cnid) &&
		    (bcmp(cndesc.cd_nameptr, HFS_INODE_PREFIX, HFS_INODE_PREFIX_LEN) == 0)) {
			linkref = strtoul((const char*)&cndesc.cd_nameptr[HFS_INODE_PREFIX_LEN], NULL, 10);
			cnattr.ca_rdev = linkref;
		}
	}

	/*
	 * Supply hfs_getnewvnode with a component name. 
	 */
	MALLOC_ZONE(cn.cn_pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN | HASBUF;
	cn.cn_context = NULL;
	cn.cn_pnlen = MAXPATHLEN;
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = cndesc.cd_namelen;
	cn.cn_hash = 0;
	cn.cn_consume = 0;
	bcopy(cndesc.cd_nameptr, cn.cn_nameptr, cndesc.cd_namelen + 1);

	/* XXX should we supply the parent as well... ? */
	error = hfs_getnewvnode(hfsmp, NULLVP, &cn, &cndesc, 0, &cnattr, &cnfork, &vp);
	if (error == 0 && linkref != 0) {
		VTOC(vp)->c_flag |= C_HARDLINK;
	}

	FREE_ZONE(cn.cn_pnbuf, cn.cn_pnlen, M_NAMEI);

	cat_releasedesc(&cndesc);
	*vpp = vp;
	if (vp && skiplock)
		hfs_unlock(VTOC(vp));
	return (error);
}


/*
 * Flush out all the files in a filesystem.
 */
static int
hfs_flushfiles(struct mount *mp, int flags, struct proc *p)
{
	struct hfsmount *hfsmp;
	struct vnode *skipvp = NULLVP;
	int quotafilecnt;
	int i;
	int error;

	hfsmp = VFSTOHFS(mp);

#if QUOTA
	/*
	 * The open quota files have an indirect reference on
	 * the root directory vnode.  We must account for this
	 * extra reference when doing the intial vflush.
	 */
	quotafilecnt = 0;
	if (((unsigned int)vfs_flags(mp)) & MNT_QUOTA) {

		/* Find out how many quota files we have open. */
		for (i = 0; i < MAXQUOTAS; i++) {
			if (hfsmp->hfs_qfiles[i].qf_vp != NULLVP)
				++quotafilecnt;
		}

		/* Obtain the root vnode so we can skip over it. */
		skipvp = hfs_chash_getvnode(hfsmp->hfs_raw_dev, kHFSRootFolderID, 0, 0);
	}
#endif /* QUOTA */

	error = vflush(mp, skipvp, SKIPSYSTEM | SKIPSWAP | flags);
	if (error != 0)
		return(error);

	error = vflush(mp, skipvp, SKIPSYSTEM | flags);

#if QUOTA
	if (((unsigned int)vfs_flags(mp)) & MNT_QUOTA) {
		if (skipvp) {
			/*
			 * See if there are additional references on the
			 * root vp besides the ones obtained from the open
			 * quota files and the hfs_chash_getvnode call above.
			 */
			if ((error == 0) &&
			    (vnode_isinuse(skipvp,  quotafilecnt))) {
				error = EBUSY;  /* root directory is still open */
			}
			hfs_unlock(VTOC(skipvp));
			vnode_put(skipvp);
		}
		if (error && (flags & FORCECLOSE) == 0)
			return (error);

		for (i = 0; i < MAXQUOTAS; i++) {
			if (hfsmp->hfs_qfiles[i].qf_vp == NULLVP)
				continue;
			hfs_quotaoff(p, mp, i);
		}
		error = vflush(mp, NULLVP, SKIPSYSTEM | flags);
	}
#endif /* QUOTA */

	return (error);
}

/*
 * Update volume encoding bitmap (HFS Plus only)
 */
__private_extern__
void
hfs_setencodingbits(struct hfsmount *hfsmp, u_int32_t encoding)
{
#define  kIndexMacUkrainian	48  /* MacUkrainian encoding is 152 */
#define  kIndexMacFarsi		49  /* MacFarsi encoding is 140 */

	UInt32	index;

	switch (encoding) {
	case kTextEncodingMacUkrainian:
		index = kIndexMacUkrainian;
		break;
	case kTextEncodingMacFarsi:
		index = kIndexMacFarsi;
		break;
	default:
		index = encoding;
		break;
	}

	if (index < 64) {
		HFS_MOUNT_LOCK(hfsmp, TRUE)
		hfsmp->encodingsBitmap |= (u_int64_t)(1ULL << index);
		hfsmp->vcbFlags |= 0xFF00;
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
	}
}

/*
 * Update volume stats
 *
 * On journal volumes this will cause a volume header flush
 */
__private_extern__
int
hfs_volupdate(struct hfsmount *hfsmp, enum volop op, int inroot)
{
	struct timeval tv;

	microtime(&tv);

	lck_mtx_lock(&hfsmp->hfs_mutex);

	hfsmp->vcbFlags |= 0xFF00;
	hfsmp->hfs_mtime = tv.tv_sec;

	switch (op) {
	case VOL_UPDATE:
		break;
	case VOL_MKDIR:
		if (hfsmp->hfs_dircount != 0xFFFFFFFF)
			++hfsmp->hfs_dircount;
		if (inroot && hfsmp->vcbNmRtDirs != 0xFFFF)
			++hfsmp->vcbNmRtDirs;
		break;
	case VOL_RMDIR:
		if (hfsmp->hfs_dircount != 0)
			--hfsmp->hfs_dircount;
		if (inroot && hfsmp->vcbNmRtDirs != 0xFFFF)
			--hfsmp->vcbNmRtDirs;
		break;
	case VOL_MKFILE:
		if (hfsmp->hfs_filecount != 0xFFFFFFFF)
			++hfsmp->hfs_filecount;
		if (inroot && hfsmp->vcbNmFls != 0xFFFF)
			++hfsmp->vcbNmFls;
		break;
	case VOL_RMFILE:
		if (hfsmp->hfs_filecount != 0)
			--hfsmp->hfs_filecount;
		if (inroot && hfsmp->vcbNmFls != 0xFFFF)
			--hfsmp->vcbNmFls;
		break;
	}

	lck_mtx_unlock(&hfsmp->hfs_mutex);

	if (hfsmp->jnl) {
		hfs_flushvolumeheader(hfsmp, 0, 0);
	}

	return (0);
}


static int
hfs_flushMDB(struct hfsmount *hfsmp, int waitfor, int altflush)
{
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	struct filefork *fp;
	HFSMasterDirectoryBlock	*mdb;
	struct buf *bp = NULL;
	int retval;
	int sectorsize;
	ByteCount namelen;

	sectorsize = hfsmp->hfs_phys_block_size;
	retval = (int)buf_bread(hfsmp->hfs_devvp, (daddr64_t)HFS_PRI_SECTOR(sectorsize), sectorsize, NOCRED, &bp);
	if (retval) {
		if (bp)
			buf_brelse(bp);
		return retval;
	}

	lck_mtx_lock(&hfsmp->hfs_mutex);

	mdb = (HFSMasterDirectoryBlock *)(buf_dataptr(bp) + HFS_PRI_OFFSET(sectorsize));
    
	mdb->drCrDate	= SWAP_BE32 (UTCToLocal(to_hfs_time(vcb->vcbCrDate)));
	mdb->drLsMod	= SWAP_BE32 (UTCToLocal(to_hfs_time(vcb->vcbLsMod)));
	mdb->drAtrb	= SWAP_BE16 (vcb->vcbAtrb);
	mdb->drNmFls	= SWAP_BE16 (vcb->vcbNmFls);
	mdb->drAllocPtr	= SWAP_BE16 (vcb->nextAllocation);
	mdb->drClpSiz	= SWAP_BE32 (vcb->vcbClpSiz);
	mdb->drNxtCNID	= SWAP_BE32 (vcb->vcbNxtCNID);
	mdb->drFreeBks	= SWAP_BE16 (vcb->freeBlocks);

	namelen = strlen(vcb->vcbVN);
	retval = utf8_to_hfs(vcb, namelen, vcb->vcbVN, mdb->drVN);
	/* Retry with MacRoman in case that's how it was exported. */
	if (retval)
		retval = utf8_to_mac_roman(namelen, vcb->vcbVN, mdb->drVN);
	
	mdb->drVolBkUp	= SWAP_BE32 (UTCToLocal(to_hfs_time(vcb->vcbVolBkUp)));
	mdb->drWrCnt	= SWAP_BE32 (vcb->vcbWrCnt);
	mdb->drNmRtDirs	= SWAP_BE16 (vcb->vcbNmRtDirs);
	mdb->drFilCnt	= SWAP_BE32 (vcb->vcbFilCnt);
	mdb->drDirCnt	= SWAP_BE32 (vcb->vcbDirCnt);
	
	bcopy(vcb->vcbFndrInfo, mdb->drFndrInfo, sizeof(mdb->drFndrInfo));

	fp = VTOF(vcb->extentsRefNum);
	mdb->drXTExtRec[0].startBlock = SWAP_BE16 (fp->ff_extents[0].startBlock);
	mdb->drXTExtRec[0].blockCount = SWAP_BE16 (fp->ff_extents[0].blockCount);
	mdb->drXTExtRec[1].startBlock = SWAP_BE16 (fp->ff_extents[1].startBlock);
	mdb->drXTExtRec[1].blockCount = SWAP_BE16 (fp->ff_extents[1].blockCount);
	mdb->drXTExtRec[2].startBlock = SWAP_BE16 (fp->ff_extents[2].startBlock);
	mdb->drXTExtRec[2].blockCount = SWAP_BE16 (fp->ff_extents[2].blockCount);
	mdb->drXTFlSize	= SWAP_BE32 (fp->ff_blocks * vcb->blockSize);
	mdb->drXTClpSiz	= SWAP_BE32 (fp->ff_clumpsize);
	FTOC(fp)->c_flag &= ~C_MODIFIED;
	
	fp = VTOF(vcb->catalogRefNum);
	mdb->drCTExtRec[0].startBlock = SWAP_BE16 (fp->ff_extents[0].startBlock);
	mdb->drCTExtRec[0].blockCount = SWAP_BE16 (fp->ff_extents[0].blockCount);
	mdb->drCTExtRec[1].startBlock = SWAP_BE16 (fp->ff_extents[1].startBlock);
	mdb->drCTExtRec[1].blockCount = SWAP_BE16 (fp->ff_extents[1].blockCount);
	mdb->drCTExtRec[2].startBlock = SWAP_BE16 (fp->ff_extents[2].startBlock);
	mdb->drCTExtRec[2].blockCount = SWAP_BE16 (fp->ff_extents[2].blockCount);
	mdb->drCTFlSize	= SWAP_BE32 (fp->ff_blocks * vcb->blockSize);
	mdb->drCTClpSiz	= SWAP_BE32 (fp->ff_clumpsize);
	FTOC(fp)->c_flag &= ~C_MODIFIED;

	MarkVCBClean( vcb );

	lck_mtx_unlock(&hfsmp->hfs_mutex);

	/* If requested, flush out the alternate MDB */
	if (altflush) {
		struct buf *alt_bp = NULL;

		if (buf_meta_bread(hfsmp->hfs_devvp, hfsmp->hfs_alt_id_sector, sectorsize, NOCRED, &alt_bp) == 0) {
			bcopy(mdb, (char *)buf_dataptr(alt_bp) + HFS_ALT_OFFSET(sectorsize), kMDBSize);

			(void) VNOP_BWRITE(alt_bp);
		} else if (alt_bp)
			buf_brelse(alt_bp);
	}

	if (waitfor != MNT_WAIT)
		buf_bawrite(bp);
	else 
		retval = VNOP_BWRITE(bp);

	return (retval);
}

/*
 *  Flush any dirty in-memory mount data to the on-disk
 *  volume header.
 *
 *  Note: the on-disk volume signature is intentionally
 *  not flushed since the on-disk "H+" and "HX" signatures
 *  are always stored in-memory as "H+".
 */
__private_extern__
int
hfs_flushvolumeheader(struct hfsmount *hfsmp, int waitfor, int altflush)
{
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	struct filefork *fp;
	HFSPlusVolumeHeader *volumeHeader;
	int retval;
	struct buf *bp;
	int i;
	int sectorsize;
	daddr64_t priIDSector;
	int critical = 0;
	u_int16_t  signature;
	u_int16_t  hfsversion;

	if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		return(0);
	}
	if (vcb->vcbSigWord == kHFSSigWord)
		return hfs_flushMDB(hfsmp, waitfor, altflush);

	if (altflush)
		critical = 1;
	sectorsize = hfsmp->hfs_phys_block_size;
	priIDSector = (daddr64_t)((vcb->hfsPlusIOPosOffset / sectorsize) +
				  HFS_PRI_SECTOR(sectorsize));

	if (hfs_start_transaction(hfsmp) != 0) {
	    return EINVAL;
	}

	retval = (int)buf_meta_bread(hfsmp->hfs_devvp, priIDSector, sectorsize, NOCRED, &bp);
	if (retval) {
		if (bp)
			buf_brelse(bp);

		hfs_end_transaction(hfsmp);

		printf("HFS: err %d reading VH blk (%s)\n", retval, vcb->vcbVN);
		return (retval);
	}

	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, bp);
	}

	volumeHeader = (HFSPlusVolumeHeader *)((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(sectorsize));

	/*
	 * Sanity check what we just read.
	 */
	signature = SWAP_BE16 (volumeHeader->signature);
	hfsversion   = SWAP_BE16 (volumeHeader->version);
	if ((signature != kHFSPlusSigWord && signature != kHFSXSigWord) ||
	    (hfsversion < kHFSPlusVersion) || (hfsversion > 100) ||
	    (SWAP_BE32 (volumeHeader->blockSize) != vcb->blockSize)) {
#if 1
		panic("HFS: corrupt VH on %s, sig 0x%04x, ver %d, blksize %d",
		      vcb->vcbVN, signature, hfsversion,
		      SWAP_BE32 (volumeHeader->blockSize));
#endif
		printf("HFS: corrupt VH blk (%s)\n", vcb->vcbVN);
		buf_brelse(bp);
		return (EIO);
	}

	/*
	 * For embedded HFS+ volumes, update create date if it changed
	 * (ie from a setattrlist call)
	 */
	if ((vcb->hfsPlusIOPosOffset != 0) &&
	    (SWAP_BE32 (volumeHeader->createDate) != vcb->localCreateDate)) {
		struct buf *bp2;
		HFSMasterDirectoryBlock	*mdb;

		retval = (int)buf_meta_bread(hfsmp->hfs_devvp, (daddr64_t)HFS_PRI_SECTOR(sectorsize),
				sectorsize, NOCRED, &bp2);
		if (retval) {
			if (bp2)
				buf_brelse(bp2);
			retval = 0;
		} else {
			mdb = (HFSMasterDirectoryBlock *)(buf_dataptr(bp2) +
				HFS_PRI_OFFSET(sectorsize));

			if ( SWAP_BE32 (mdb->drCrDate) != vcb->localCreateDate )
			  {
				if (hfsmp->jnl) {
				    journal_modify_block_start(hfsmp->jnl, bp2);
				}

				mdb->drCrDate = SWAP_BE32 (vcb->localCreateDate);	/* pick up the new create date */

				if (hfsmp->jnl) {
					journal_modify_block_end(hfsmp->jnl, bp2);
				} else {
					(void) VNOP_BWRITE(bp2);		/* write out the changes */
				}
			  }
			else
			  {
				buf_brelse(bp2);						/* just release it */
			  }
		  }	
	}

	if (1 /* hfsmp->jnl == 0 */) {
		lck_mtx_lock(&hfsmp->hfs_mutex);
	}

	/* Note: only update the lower 16 bits worth of attributes */
	volumeHeader->attributes       = SWAP_BE32 (vcb->vcbAtrb);
	volumeHeader->journalInfoBlock = SWAP_BE32 (vcb->vcbJinfoBlock);
	if (hfsmp->jnl) {
		volumeHeader->lastMountedVersion = SWAP_BE32 (kHFSJMountVersion);
	} else {
		volumeHeader->lastMountedVersion = SWAP_BE32 (kHFSPlusMountVersion);
	}
	volumeHeader->createDate	= SWAP_BE32 (vcb->localCreateDate);  /* volume create date is in local time */
	volumeHeader->modifyDate	= SWAP_BE32 (to_hfs_time(vcb->vcbLsMod));
	volumeHeader->backupDate	= SWAP_BE32 (to_hfs_time(vcb->vcbVolBkUp));
	volumeHeader->fileCount		= SWAP_BE32 (vcb->vcbFilCnt);
	volumeHeader->folderCount	= SWAP_BE32 (vcb->vcbDirCnt);
	volumeHeader->totalBlocks	= SWAP_BE32 (vcb->totalBlocks);
	volumeHeader->freeBlocks	= SWAP_BE32 (vcb->freeBlocks);
	volumeHeader->nextAllocation	= SWAP_BE32 (vcb->nextAllocation);
	volumeHeader->rsrcClumpSize	= SWAP_BE32 (vcb->vcbClpSiz);
	volumeHeader->dataClumpSize	= SWAP_BE32 (vcb->vcbClpSiz);
	volumeHeader->nextCatalogID	= SWAP_BE32 (vcb->vcbNxtCNID);
	volumeHeader->writeCount	= SWAP_BE32 (vcb->vcbWrCnt);
	volumeHeader->encodingsBitmap	= SWAP_BE64 (vcb->encodingsBitmap);

	if (bcmp(vcb->vcbFndrInfo, volumeHeader->finderInfo, sizeof(volumeHeader->finderInfo)) != 0) {
		bcopy(vcb->vcbFndrInfo, volumeHeader->finderInfo, sizeof(volumeHeader->finderInfo));
		critical = 1;
	}

	/* Sync Extents over-flow file meta data */
	fp = VTOF(vcb->extentsRefNum);
	if (FTOC(fp)->c_flag & C_MODIFIED) {
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			volumeHeader->extentsFile.extents[i].startBlock	=
				SWAP_BE32 (fp->ff_extents[i].startBlock);
			volumeHeader->extentsFile.extents[i].blockCount	=
				SWAP_BE32 (fp->ff_extents[i].blockCount);
		}
		volumeHeader->extentsFile.logicalSize = SWAP_BE64 (fp->ff_size);
		volumeHeader->extentsFile.totalBlocks = SWAP_BE32 (fp->ff_blocks);
		volumeHeader->extentsFile.clumpSize   = SWAP_BE32 (fp->ff_clumpsize);
		FTOC(fp)->c_flag &= ~C_MODIFIED;
	}

	/* Sync Catalog file meta data */
	fp = VTOF(vcb->catalogRefNum);
	if (FTOC(fp)->c_flag & C_MODIFIED) {
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			volumeHeader->catalogFile.extents[i].startBlock	=
				SWAP_BE32 (fp->ff_extents[i].startBlock);
			volumeHeader->catalogFile.extents[i].blockCount	=
				SWAP_BE32 (fp->ff_extents[i].blockCount);
		}
		volumeHeader->catalogFile.logicalSize = SWAP_BE64 (fp->ff_size);
		volumeHeader->catalogFile.totalBlocks = SWAP_BE32 (fp->ff_blocks);
		volumeHeader->catalogFile.clumpSize   = SWAP_BE32 (fp->ff_clumpsize);
		FTOC(fp)->c_flag &= ~C_MODIFIED;
	}

	/* Sync Allocation file meta data */
	fp = VTOF(vcb->allocationsRefNum);
	if (FTOC(fp)->c_flag & C_MODIFIED) {
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			volumeHeader->allocationFile.extents[i].startBlock =
				SWAP_BE32 (fp->ff_extents[i].startBlock);
			volumeHeader->allocationFile.extents[i].blockCount =
				SWAP_BE32 (fp->ff_extents[i].blockCount);
		}
		volumeHeader->allocationFile.logicalSize = SWAP_BE64 (fp->ff_size);
		volumeHeader->allocationFile.totalBlocks = SWAP_BE32 (fp->ff_blocks);
		volumeHeader->allocationFile.clumpSize   = SWAP_BE32 (fp->ff_clumpsize);
		FTOC(fp)->c_flag &= ~C_MODIFIED;
	}

	/* Sync Attribute file meta data */
	if (hfsmp->hfs_attribute_vp) {
		fp = VTOF(hfsmp->hfs_attribute_vp);
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			volumeHeader->attributesFile.extents[i].startBlock =
				SWAP_BE32 (fp->ff_extents[i].startBlock);
			volumeHeader->attributesFile.extents[i].blockCount =
				SWAP_BE32 (fp->ff_extents[i].blockCount);
		}
		FTOC(fp)->c_flag &= ~C_MODIFIED;
		volumeHeader->attributesFile.logicalSize = SWAP_BE64 (fp->ff_size);
		volumeHeader->attributesFile.totalBlocks = SWAP_BE32 (fp->ff_blocks);
		volumeHeader->attributesFile.clumpSize   = SWAP_BE32 (fp->ff_clumpsize);
	}

	vcb->vcbFlags &= 0x00FF;

	if (1 /* hfsmp->jnl == 0 */) {
		lck_mtx_unlock(&hfsmp->hfs_mutex);
	}

	/* If requested, flush out the alternate volume header */
	if (altflush && hfsmp->hfs_alt_id_sector) {
		struct buf *alt_bp = NULL;

		if (buf_meta_bread(hfsmp->hfs_devvp, hfsmp->hfs_alt_id_sector, sectorsize, NOCRED, &alt_bp) == 0) {
			if (hfsmp->jnl) {
				journal_modify_block_start(hfsmp->jnl, alt_bp);
			}

			bcopy(volumeHeader, (char *)buf_dataptr(alt_bp) + HFS_ALT_OFFSET(sectorsize), kMDBSize);

			if (hfsmp->jnl) {
				journal_modify_block_end(hfsmp->jnl, alt_bp);
			} else {
				(void) VNOP_BWRITE(alt_bp);
			}
		} else if (alt_bp)
			buf_brelse(alt_bp);
	}

	if (hfsmp->jnl) {
		journal_modify_block_end(hfsmp->jnl, bp);
	} else {
		if (waitfor != MNT_WAIT)
			buf_bawrite(bp);
		else {
		    retval = VNOP_BWRITE(bp);
		    /* When critical data changes, flush the device cache */
		    if (critical && (retval == 0)) {
			(void) VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE,
					 NULL, FWRITE, NULL);
		    }
		}
	}
	hfs_end_transaction(hfsmp);
 
	return (retval);
}


/*
 * Extend a file system.
 */
__private_extern__
int
hfs_extendfs(struct hfsmount *hfsmp, u_int64_t newsize, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	kauth_cred_t cred = vfs_context_ucred(context);
	struct  vnode *vp;
	struct  vnode *devvp;
	struct  buf *bp;
	struct  filefork *fp = NULL;
	ExtendedVCB  *vcb;
	struct  cat_fork forkdata;
	u_int64_t  oldsize;
	u_int64_t  newblkcnt;
	u_int64_t  prev_phys_block_count;
	u_int32_t  addblks;
	u_int64_t  sectorcnt;
	u_int32_t  sectorsize;
	daddr64_t  prev_alt_sector;
	daddr_t	   bitmapblks;
	int  lockflags;
	int  error;

	devvp = hfsmp->hfs_devvp;
	vcb = HFSTOVCB(hfsmp);

	/*
	 * - HFS Plus file systems only. 
	 * - Journaling must be enabled.
	 * - No embedded volumes.
	 */
	if ((vcb->vcbSigWord == kHFSSigWord) ||
	     (hfsmp->jnl == NULL) ||
	     (vcb->hfsPlusIOPosOffset != 0)) {
		return (EPERM);
	}
	/*
	 * If extending file system by non-root, then verify
	 * ownership and check permissions.
	 */
	if (suser(cred, NULL)) {
		error = hfs_vget(hfsmp, kHFSRootFolderID, &vp, 0);

		if (error)
			return (error);
		error = hfs_owner_rights(hfsmp, VTOC(vp)->c_uid, cred, p, 0);
		if (error == 0) {
			error = hfs_write_access(vp, cred, p, false);
		}
		hfs_unlock(VTOC(vp));
		vnode_put(vp);
		if (error)
			return (error);

		error = vnode_authorize(devvp, NULL, KAUTH_VNODE_READ_DATA | KAUTH_VNODE_WRITE_DATA, context);
		if (error)
			return (error);
	}
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&sectorsize, 0, context)) {
		return (ENXIO);
	}
	if (sectorsize != hfsmp->hfs_phys_block_size) {
		return (ENXIO);
	}
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&sectorcnt, 0, context)) {
		return (ENXIO);
	}
	if ((sectorsize * sectorcnt) < newsize) {
		printf("hfs_extendfs: not enough space on device\n");
		return (ENOSPC);
	}
	oldsize = (u_int64_t)hfsmp->totalBlocks * (u_int64_t)hfsmp->blockSize;

	/*
	 * Validate new size.
	 */
	if ((newsize <= oldsize) || (newsize % sectorsize)) {
		printf("hfs_extendfs: invalid size\n");
		return (EINVAL);
	}
	newblkcnt = newsize / vcb->blockSize;
	if (newblkcnt > (u_int64_t)0xFFFFFFFF)
		return (EOVERFLOW);

	addblks = newblkcnt - vcb->totalBlocks;

	printf("hfs_extendfs: growing %s by %d blocks\n", vcb->vcbVN, addblks);
	/*
	 * Enclose changes inside a transaction.
	 */
	if (hfs_start_transaction(hfsmp) != 0) {
		return (EINVAL);
	}

	lockflags = hfs_systemfile_lock(hfsmp, SFL_EXTENTS | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	vp = vcb->allocationsRefNum;
	fp = VTOF(vp);
	bcopy(&fp->ff_data, &forkdata, sizeof(forkdata));

	/*
	 * Calculate additional space required (if any) by allocation bitmap.
	 */
	bitmapblks = roundup(newblkcnt / 8, vcb->vcbVBMIOSize) / vcb->blockSize;
	if (bitmapblks > (daddr_t)fp->ff_blocks)
		bitmapblks -= fp->ff_blocks;
	else
		bitmapblks = 0;

	if (bitmapblks > 0) {
		daddr64_t blkno;
		daddr_t blkcnt;

		/*
		 * Add a new extent to the allocation bitmap file.
		 */
		error = AddFileExtent(vcb, fp, vcb->totalBlocks, bitmapblks);
		if (error) {
			printf("hfs_extendfs: error %d adding extents\n", error);
			goto out;
		}
		blkcnt = bitmapblks;
		blkno  = (daddr64_t)fp->ff_blocks;
		fp->ff_blocks += bitmapblks;
		fp->ff_size += (u_int64_t)bitmapblks * (u_int64_t)vcb->blockSize;
		VTOC(vp)->c_blocks = fp->ff_blocks;
		/*
		 * Zero out the new bitmap blocks.
		 */
		{
	
			bp = NULL;
			while (blkcnt > 0) {
				error = (int)buf_meta_bread(vp, blkno, vcb->blockSize, NOCRED, &bp);
				if (error) {
					if (bp) {
						buf_brelse(bp);
					}
					break;
				}
				bzero((char *)buf_dataptr(bp), vcb->blockSize);
				buf_markaged(bp);
				error = (int)buf_bwrite(bp);
				if (error)
					break;
				--blkcnt;
				++blkno;
			}
		}
		if (error) {
			printf("hfs_extendfs: error %d  clearing blocks\n", error);
			goto out;
		}
		/*
		 * Mark the new bitmap space as allocated.
		 */
		error = BlockMarkAllocated(vcb, vcb->totalBlocks, bitmapblks);
		if (error) {
			printf("hfs_extendfs: error %d setting bitmap\n", error);
			goto out;
		}
	}
	/*
	 * Mark the new alternate VH as allocated.
	 */
	if (vcb->blockSize == 512)
		error = BlockMarkAllocated(vcb, vcb->totalBlocks + addblks - 2, 2);
	else
		error = BlockMarkAllocated(vcb, vcb->totalBlocks + addblks - 1, 1);
	if (error) {
		printf("hfs_extendfs: error %d setting bitmap (VH)\n", error);
		goto out;
	}
	/*
	 * Mark the old alternate VH as free.
	 */
	if (vcb->blockSize == 512)
		(void) BlockMarkFree(vcb, vcb->totalBlocks - 2, 2);
	else 
		(void) BlockMarkFree(vcb, vcb->totalBlocks - 1, 1);
	/*
	 * Adjust file system variables for new space.
	 */
	prev_phys_block_count = hfsmp->hfs_phys_block_count;
	prev_alt_sector = hfsmp->hfs_alt_id_sector;

	vcb->totalBlocks += addblks;
	vcb->freeBlocks += addblks - bitmapblks;
	hfsmp->hfs_phys_block_count = newsize / sectorsize;
	hfsmp->hfs_alt_id_sector = (hfsmp->hfsPlusIOPosOffset / sectorsize) +
	                          HFS_ALT_SECTOR(sectorsize, hfsmp->hfs_phys_block_count);
	MarkVCBDirty(vcb);
	error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
	if (error) {
		printf("hfs_extendfs: couldn't flush volume headers (%d)", error);
		/*
		 * Restore to old state.
		 */
		fp->ff_size -= (u_int64_t)bitmapblks * (u_int64_t)vcb->blockSize;
		vcb->totalBlocks -= addblks;
		vcb->freeBlocks -= addblks - bitmapblks;
		hfsmp->hfs_phys_block_count = prev_phys_block_count;
		hfsmp->hfs_alt_id_sector = prev_alt_sector;
		MarkVCBDirty(vcb);
		if (vcb->blockSize == 512)
			(void) BlockMarkAllocated(vcb, vcb->totalBlocks - 2, 2);
		else
			(void) BlockMarkAllocated(vcb, vcb->totalBlocks - 1, 1);
		goto out;
	}
	/*
	 * Invalidate the old alternate volume header.
	 */
	bp = NULL;
	if (prev_alt_sector) {
		if (buf_meta_bread(hfsmp->hfs_devvp, prev_alt_sector, sectorsize,
				   NOCRED, &bp) == 0) {
			journal_modify_block_start(hfsmp->jnl, bp);
	
			bzero((char *)buf_dataptr(bp) + HFS_ALT_OFFSET(sectorsize), kMDBSize);
	
			journal_modify_block_end(hfsmp->jnl, bp);
		} else if (bp) {
			buf_brelse(bp);
		}
	}
out:
	if (error && fp) {
		/* Restore allocation fork. */
		bcopy(&forkdata, &fp->ff_data, sizeof(forkdata));
		VTOC(vp)->c_blocks = fp->ff_blocks;

	}
	hfs_systemfile_unlock(hfsmp, lockflags);
	hfs_end_transaction(hfsmp);

	return (error);
}

#define HFS_MIN_SIZE  (32LL * 1024LL * 1024LL)

/*
 * Truncate a file system (while still mounted).
 */
__private_extern__
int
hfs_truncatefs(struct hfsmount *hfsmp, u_int64_t newsize, __unused vfs_context_t context)
{
	struct  buf *bp = NULL;
	u_int64_t oldsize;
	u_int32_t newblkcnt;
	u_int32_t reclaimblks;
	int lockflags = 0;
	int transaction_begun = 0;
	int error;

	
	lck_mtx_lock(&hfsmp->hfs_mutex);
	if (hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS) {
		lck_mtx_unlock(&hfsmp->hfs_mutex);
		return (EALREADY);
	}
	hfsmp->hfs_flags |= HFS_RESIZE_IN_PROGRESS;
	hfsmp->hfs_resize_filesmoved = 0;
	hfsmp->hfs_resize_totalfiles = 0;
	lck_mtx_unlock(&hfsmp->hfs_mutex);

	/*
	 * - Journaled HFS Plus volumes only.
	 * - No embedded volumes.
	 */
	if ((hfsmp->jnl == NULL) ||
	    (hfsmp->hfsPlusIOPosOffset != 0)) {
		error = EPERM;
		goto out;
	}
	oldsize = (u_int64_t)hfsmp->totalBlocks * (u_int64_t)hfsmp->blockSize;
	newblkcnt = newsize / hfsmp->blockSize;
	reclaimblks = hfsmp->totalBlocks - newblkcnt;

	/* Make sure new size is valid. */
	if ((newsize < HFS_MIN_SIZE) ||
	    (newsize >= oldsize) ||
	    (newsize % hfsmp->hfs_phys_block_size)) {
		error = EINVAL;
		goto out;
	}
	/* Make sure there's enough space to work with. */
	if (reclaimblks >= hfs_freeblks(hfsmp, 1)) {
		error = ENOSPC;
		goto out;
	}
	/* Start with a clean journal. */
	journal_flush(hfsmp->jnl);

	if (hfs_start_transaction(hfsmp) != 0) {
		error = EINVAL;
		goto out;
	}
	transaction_begun = 1;

	/*
	 * Look for files that have blocks beyond newblkcnt.
	 */
	if (hfs_isallocated(hfsmp, newblkcnt, reclaimblks - 1)) {
		/*
		 * hfs_reclaimspace will use separate transactions when
		 * relocating files (so we don't overwhelm the journal).
		 */
		hfs_end_transaction(hfsmp);
		transaction_begun = 0;

		/* Attempt to reclaim some space. */ 
		if (hfs_reclaimspace(hfsmp, newblkcnt, reclaimblks) != 0) {
			printf("hfs_truncatefs: couldn't reclaim space on %s\n", hfsmp->vcbVN);
			error = ENOSPC;
			goto out;
		}
		if (hfs_start_transaction(hfsmp) != 0) {
			error = EINVAL;
			goto out;
		}
		transaction_begun = 1;
		
		/* Check if we're clear now. */
		if (hfs_isallocated(hfsmp, newblkcnt, reclaimblks - 1)) {
			printf("hfs_truncatefs: didn't reclaim enough space on %s\n", hfsmp->vcbVN);
			error = EAGAIN;  /* tell client to try again */
			goto out;
		}
	}
	lockflags = hfs_systemfile_lock(hfsmp, SFL_EXTENTS | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);

	/*
	 * Mark the old alternate volume header as free. 
	 * We don't bother shrinking allocation bitmap file.
	 */
	 if (hfsmp->blockSize == 512) 
		(void) BlockMarkFree(hfsmp, hfsmp->totalBlocks - 2, 2);
	else 
		(void) BlockMarkFree(hfsmp, hfsmp->totalBlocks - 1, 1);

	/*
	 * Allocate last block for alternate volume header.
	 */
	if (hfsmp->blockSize == 512)
		error = BlockMarkAllocated(hfsmp, newblkcnt - 2, 2);
	else
		error = BlockMarkAllocated(hfsmp, newblkcnt - 1, 1);

	if (error) {
		goto out;
	}

	/*
	 * Invalidate the existing alternate volume header.
	 *
	 * Don't do this as a transaction (don't call journal_modify_block)
	 * since this block will be outside of the truncated file system!
	 */
	if (hfsmp->hfs_alt_id_sector) {
		if (buf_meta_bread(hfsmp->hfs_devvp, hfsmp->hfs_alt_id_sector,
		                   hfsmp->hfs_phys_block_size, NOCRED, &bp) == 0) {
	
			bzero((void*)((char *)buf_dataptr(bp) + HFS_ALT_OFFSET(hfsmp->hfs_phys_block_size)), kMDBSize);
			(void) VNOP_BWRITE(bp);
		} else if (bp) {
			buf_brelse(bp);
		}
		bp = NULL;
	}

	/* Log successful shrinking. */
	printf("hfs_truncatefs: shrank \"%s\" to %d blocks (was %d blocks)\n",
	       hfsmp->vcbVN, newblkcnt, hfsmp->totalBlocks);

	/*
	 * Adjust file system variables and flush them to disk.
	 */
	hfsmp->freeBlocks -= hfsmp->totalBlocks - newblkcnt;
	hfsmp->totalBlocks = newblkcnt;
	hfsmp->hfs_phys_block_count = newsize / hfsmp->hfs_phys_block_size;
	hfsmp->hfs_alt_id_sector = HFS_ALT_SECTOR(hfsmp->hfs_phys_block_size, hfsmp->hfs_phys_block_count);
	MarkVCBDirty(hfsmp);
	error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
	if (error)
		panic("hfs_truncatefs: unexpected error flushing volume header (%d)\n", error);
out:
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (transaction_begun) {
		hfs_end_transaction(hfsmp);
		journal_flush(hfsmp->jnl);
	}

	lck_mtx_lock(&hfsmp->hfs_mutex);
	hfsmp->hfs_flags &= ~HFS_RESIZE_IN_PROGRESS;
	lck_mtx_unlock(&hfsmp->hfs_mutex);

	return (error);
}


/*
 * Reclaim space at the end of a file system.
 */
static int
hfs_reclaimspace(struct hfsmount *hfsmp, u_long startblk, u_long reclaimblks)
{
	struct vnode *vp = NULL;
	FCB *fcb;
	struct BTreeIterator * iterator = NULL;
	struct FSBufferDescriptor btdata;
	struct HFSPlusCatalogFile filerec;
	struct filefork *fp;
	u_int32_t  saved_next_allocation;
	cnid_t * cnidbufp;
	size_t cnidbufsize;
	int filecnt = 0;
	int maxfilecnt;
	u_long block;
	u_long datablks;
	u_long rsrcblks;
	u_long blkstomove = 0;
	int lockflags;
	int i;
	int error;
	int lastprogress = 0;


	/* Check if Attributes file overlaps reclaim area. */
	if (hfsmp->hfs_attribute_vp) {
		fp = VTOF(hfsmp->hfs_attribute_vp);
		datablks = 0;
		for (i = 0; i < kHFSPlusExtentDensity; ++i) {
			if (fp->ff_extents[i].blockCount == 0) {
				break;
			}
			datablks += fp->ff_extents[i].blockCount;
			block = fp->ff_extents[i].startBlock + fp->ff_extents[i].blockCount;
			if (block >= startblk) {
				printf("hfs_reclaimspace: Attributes file can't move\n");
				return (EPERM);
			}
		}
		if ((i == kHFSPlusExtentDensity) && (fp->ff_blocks > datablks)) {
			if (hfs_overlapped_overflow_extents(hfsmp, startblk, datablks, kHFSAttributesFileID, 0)) {
				printf("hfs_reclaimspace: Attributes file can't move\n");
				return (EPERM);
			}
		}
	}
	/* Check if Catalog file overlaps reclaim area. */
	fp = VTOF(hfsmp->hfs_catalog_vp);
	datablks = 0;
	for (i = 0; i < kHFSPlusExtentDensity; ++i) {
		if (fp->ff_extents[i].blockCount == 0) {
			break;
		}
		datablks += fp->ff_extents[i].blockCount;
		block = fp->ff_extents[i].startBlock + fp->ff_extents[i].blockCount;
		if (block >= startblk) {
			printf("hfs_reclaimspace: Catalog file can't move\n");
			return (EPERM);
		}
	}
	if ((i == kHFSPlusExtentDensity) && (fp->ff_blocks > datablks)) {
		if (hfs_overlapped_overflow_extents(hfsmp, startblk, datablks, kHFSCatalogFileID, 0)) {
			printf("hfs_reclaimspace: Catalog file can't move\n");
			return (EPERM);
		}
	}

	/* For now move a maximum of 250,000 files. */
	maxfilecnt = MIN(hfsmp->hfs_filecount, 250000);
	maxfilecnt = MIN((u_long)maxfilecnt, reclaimblks);
	cnidbufsize = maxfilecnt * sizeof(cnid_t);
	if (kmem_alloc(kernel_map, (vm_offset_t *)&cnidbufp, cnidbufsize)) {
		return (ENOMEM);
	}	
	if (kmem_alloc(kernel_map, (vm_offset_t *)&iterator, sizeof(*iterator))) {
		kmem_free(kernel_map, (vm_offset_t)cnidbufp, cnidbufsize);
		return (ENOMEM);
	}	

	saved_next_allocation = hfsmp->nextAllocation;
	hfsmp->nextAllocation = hfsmp->hfs_metazone_start;

	fcb = VTOF(hfsmp->hfs_catalog_vp);
	bzero(iterator, sizeof(*iterator));

	btdata.bufferAddress = &filerec;
	btdata.itemSize = sizeof(filerec);
	btdata.itemCount = 1;

	/* Keep the Catalog and extents files locked during iteration. */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_EXTENTS, HFS_SHARED_LOCK);

	error = BTIterateRecord(fcb, kBTreeFirstRecord, iterator, NULL, NULL);
	if (error) {
		goto end_iteration;
	}
	/*
	 * Iterate over all the catalog records looking for files
	 * that overlap into the space we're trying to free up.
	 */
	for (filecnt = 0; filecnt < maxfilecnt; ) {
		error = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
		if (error) {
			if (error == fsBTRecordNotFoundErr || error == fsBTEndOfIterationErr) {
				error = 0;				
			}
			break;
		}
		if (filerec.recordType != kHFSPlusFileRecord) {
			continue;
		}
		datablks = rsrcblks = 0;
		/* 
		 * Check if either fork overlaps target space.
		 */
		for (i = 0; i < kHFSPlusExtentDensity; ++i) {
			if (filerec.dataFork.extents[i].blockCount != 0) {
				datablks += filerec.dataFork.extents[i].blockCount;
				block = filerec.dataFork.extents[i].startBlock +
						filerec.dataFork.extents[i].blockCount;
				if (block >= startblk) {
					if ((filerec.fileID == hfsmp->hfs_jnlfileid) ||
						(filerec.fileID == hfsmp->hfs_jnlinfoblkid)) {
						printf("hfs_reclaimspace: cannot move active journal\n");
						error = EPERM;
						goto end_iteration;
					}
					cnidbufp[filecnt++] = filerec.fileID;
					blkstomove += filerec.dataFork.totalBlocks;
					break;
				}
			}
			if (filerec.resourceFork.extents[i].blockCount != 0) {
				rsrcblks += filerec.resourceFork.extents[i].blockCount;
				block = filerec.resourceFork.extents[i].startBlock +
						filerec.resourceFork.extents[i].blockCount;
				if (block >= startblk) {
					cnidbufp[filecnt++] = filerec.fileID;
					blkstomove += filerec.resourceFork.totalBlocks;
					break;
				}
			}
		}
		/*
		 * Check for any overflow extents that overlap.
		 */
		if (i == kHFSPlusExtentDensity) {
			if (filerec.dataFork.totalBlocks > datablks) {
				if (hfs_overlapped_overflow_extents(hfsmp, startblk, datablks, filerec.fileID, 0)) {
					cnidbufp[filecnt++] = filerec.fileID;
					blkstomove += filerec.dataFork.totalBlocks;
				}
			} else if (filerec.resourceFork.totalBlocks > rsrcblks) {
				if (hfs_overlapped_overflow_extents(hfsmp, startblk, rsrcblks, filerec.fileID, 1)) {
					cnidbufp[filecnt++] = filerec.fileID;
					blkstomove += filerec.resourceFork.totalBlocks;
				}
			}
		}
	}

end_iteration:
	if (filecnt == 0) {
		error = ENOSPC;
	}
	/* All done with catalog. */
	hfs_systemfile_unlock(hfsmp, lockflags);
	if (error)
		goto out;

	/*
	 * Double check space requirements to make sure
	 * there is enough space to relocate any files
	 * that reside in the reclaim area.
	 *
	 *                                          Blocks To Move --------------
	 *                                                            |    |    |
	 *                                                            V    V    V
	 * ------------------------------------------------------------------------
	 * |                                                        | /   ///  // |
	 * |                                                        | /   ///  // |
	 * |                                                        | /   ///  // |
	 * ------------------------------------------------------------------------
	 *
	 * <------------------- New Total Blocks ------------------><-- Reclaim -->
	 *
	 * <------------------------ Original Total Blocks ----------------------->
	 *
	 */
	if ((reclaimblks + blkstomove) >= hfs_freeblks(hfsmp, 1)) {
		error = ENOSPC;
		goto out;
	}
	hfsmp->hfs_resize_filesmoved = 0;
	hfsmp->hfs_resize_totalfiles = filecnt;
	
	/* Now move any files that are in the way. */
	for (i = 0; i < filecnt; ++i) {
		struct vnode * rvp;

		if (hfs_vget(hfsmp, cnidbufp[i], &vp, 0) != 0)
			continue;

		/* Relocate any data fork blocks. */
		if (VTOF(vp)->ff_blocks > 0) {
			error = hfs_relocate(vp, hfsmp->hfs_metazone_end + 1, kauth_cred_get(), current_proc());
		}
		if (error) 
			break;

		/* Relocate any resource fork blocks. */
		if ((VTOC((vp))->c_blocks - VTOF((vp))->ff_blocks) > 0) {
			error = hfs_vgetrsrc(hfsmp, vp, &rvp, current_proc());
			if (error)
				break;
			error = hfs_relocate(rvp, hfsmp->hfs_metazone_end + 1, kauth_cred_get(), current_proc());
			vnode_put(rvp);
			if (error)
				break;
		}
		hfs_unlock(VTOC(vp));
		vnode_put(vp);
		vp = NULL;

		++hfsmp->hfs_resize_filesmoved;

		/* Report intermediate progress. */
		if (filecnt > 100) {
			int progress;

			progress = (i * 100) / filecnt;
			if (progress > (lastprogress + 9)) {
				printf("hfs_reclaimspace: %d%% done...\n", progress);
				lastprogress = progress;
			}
		}
	}
	if (vp) {
		hfs_unlock(VTOC(vp));
		vnode_put(vp);
		vp = NULL;
	}
	if (hfsmp->hfs_resize_filesmoved != 0) {
		printf("hfs_reclaimspace: relocated %d files on \"%s\"\n",
		       (int)hfsmp->hfs_resize_filesmoved, hfsmp->vcbVN);
	}
out:
	kmem_free(kernel_map, (vm_offset_t)iterator, sizeof(*iterator));
	kmem_free(kernel_map, (vm_offset_t)cnidbufp, cnidbufsize);

	/*
	 * Restore the roving allocation pointer on errors.
	 * (but only if we didn't move any files)
	 */
	if (error && hfsmp->hfs_resize_filesmoved == 0) {
		hfsmp->nextAllocation = saved_next_allocation;
	}
	return (error);
}


/*
 * Check if there are any overflow extents that overlap.
 */
static int
hfs_overlapped_overflow_extents(struct hfsmount *hfsmp, u_int32_t startblk, u_int32_t catblks, u_int32_t fileID, int rsrcfork)
{
	struct BTreeIterator * iterator = NULL;
	struct FSBufferDescriptor btdata;
	HFSPlusExtentRecord extrec;
	HFSPlusExtentKey *extkeyptr;
	FCB *fcb;
	u_int32_t block;
	u_int8_t forktype;
	int overlapped = 0;
	int i;
	int error;

	forktype = rsrcfork ? 0xFF : 0;
	if (kmem_alloc(kernel_map, (vm_offset_t *)&iterator, sizeof(*iterator))) {
		return (0);
	}	
	bzero(iterator, sizeof(*iterator));
	extkeyptr = (HFSPlusExtentKey *)&iterator->key;
	extkeyptr->keyLength = kHFSPlusExtentKeyMaximumLength;
	extkeyptr->forkType = forktype;
	extkeyptr->fileID = fileID;
	extkeyptr->startBlock = catblks;

	btdata.bufferAddress = &extrec;
	btdata.itemSize = sizeof(extrec);
	btdata.itemCount = 1;
	
	fcb = VTOF(hfsmp->hfs_extents_vp);

	error = BTSearchRecord(fcb, iterator, &btdata, NULL, iterator);
	while (error == 0) {
		/* Stop when we encounter a different file. */
		if ((extkeyptr->fileID != fileID) ||
		    (extkeyptr->forkType != forktype)) {
			break;
		}
		/* 
		 * Check if the file overlaps target space.
		 */
		for (i = 0; i < kHFSPlusExtentDensity; ++i) {
			if (extrec[i].blockCount == 0) {
				break;
			}
			block = extrec[i].startBlock + extrec[i].blockCount;
			if (block >= startblk) {
				overlapped = 1;
				break;
			}
		}
		/* Look for more records. */
		error = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
	}

	kmem_free(kernel_map, (vm_offset_t)iterator, sizeof(*iterator));
	return (overlapped);
}


/*
 * Calculate the progress of a file system resize operation.
 */
__private_extern__
int
hfs_resize_progress(struct hfsmount *hfsmp, u_int32_t *progress)
{
	if ((hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS) == 0) {
		return (ENXIO);
	}

	if (hfsmp->hfs_resize_totalfiles > 0)
		*progress = (hfsmp->hfs_resize_filesmoved * 100) / hfsmp->hfs_resize_totalfiles;
	else
		*progress = 0;

	return (0);
}


/*
 * Get file system attributes.
 */
static int
hfs_vfs_getattr(struct mount *mp, struct vfs_attr *fsap, __unused vfs_context_t context)
{
	ExtendedVCB *vcb = VFSTOVCB(mp);
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	u_long freeCNIDs;

	freeCNIDs = (u_long)0xFFFFFFFF - (u_long)hfsmp->vcbNxtCNID;

	VFSATTR_RETURN(fsap, f_objcount, (uint64_t)hfsmp->vcbFilCnt + (uint64_t)hfsmp->vcbDirCnt);
	VFSATTR_RETURN(fsap, f_filecount, (uint64_t)hfsmp->vcbFilCnt);
	VFSATTR_RETURN(fsap, f_dircount, (uint64_t)hfsmp->vcbDirCnt);
	VFSATTR_RETURN(fsap, f_maxobjcount, (uint64_t)0xFFFFFFFF);
	VFSATTR_RETURN(fsap, f_iosize, (size_t)(MAX_UPL_TRANSFER * PAGE_SIZE));
	VFSATTR_RETURN(fsap, f_blocks, (uint64_t)hfsmp->totalBlocks);
	VFSATTR_RETURN(fsap, f_bfree, (uint64_t)hfs_freeblks(hfsmp, 0));
	VFSATTR_RETURN(fsap, f_bavail, (uint64_t)hfs_freeblks(hfsmp, 1));
	VFSATTR_RETURN(fsap, f_bsize, (uint32_t)vcb->blockSize);
	/* XXX needs clarification */
	VFSATTR_RETURN(fsap, f_bused, hfsmp->totalBlocks - hfs_freeblks(hfsmp, 1));
	/* Maximum files is constrained by total blocks. */
	VFSATTR_RETURN(fsap, f_files, (uint64_t)(hfsmp->totalBlocks - 2));
	VFSATTR_RETURN(fsap, f_ffree, MIN((uint64_t)freeCNIDs, (uint64_t)hfs_freeblks(hfsmp, 1)));

	fsap->f_fsid.val[0] = hfsmp->hfs_raw_dev;
	fsap->f_fsid.val[1] = vfs_typenum(mp);
	VFSATTR_SET_SUPPORTED(fsap, f_fsid);

	VFSATTR_RETURN(fsap, f_signature, vcb->vcbSigWord);
	VFSATTR_RETURN(fsap, f_carbon_fsid, 0);

	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		vol_capabilities_attr_t *cap;
	
		cap = &fsap->f_capabilities;

		if (hfsmp->hfs_flags & HFS_STANDARD) {
			cap->capabilities[VOL_CAPABILITIES_FORMAT] =
				VOL_CAP_FMT_PERSISTENTOBJECTIDS |
				VOL_CAP_FMT_CASE_PRESERVING |
				VOL_CAP_FMT_FAST_STATFS;
		} else {
			cap->capabilities[VOL_CAPABILITIES_FORMAT] =
				VOL_CAP_FMT_PERSISTENTOBJECTIDS |
				VOL_CAP_FMT_SYMBOLICLINKS |
				VOL_CAP_FMT_HARDLINKS |
				VOL_CAP_FMT_JOURNAL |
				(hfsmp->jnl ? VOL_CAP_FMT_JOURNAL_ACTIVE : 0) |
				(hfsmp->hfs_flags & HFS_CASE_SENSITIVE ? VOL_CAP_FMT_CASE_SENSITIVE : 0) |
				VOL_CAP_FMT_CASE_PRESERVING |
				VOL_CAP_FMT_FAST_STATFS | 
				VOL_CAP_FMT_2TB_FILESIZE;
		}
		cap->capabilities[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_SEARCHFS |
			VOL_CAP_INT_ATTRLIST |
			VOL_CAP_INT_NFSEXPORT |
			VOL_CAP_INT_READDIRATTR |
			VOL_CAP_INT_EXCHANGEDATA |
			VOL_CAP_INT_ALLOCATE |
			VOL_CAP_INT_VOL_RENAME |
			VOL_CAP_INT_ADVLOCK |
			VOL_CAP_INT_FLOCK;
		cap->capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
		cap->capabilities[VOL_CAPABILITIES_RESERVED2] = 0;

		cap->valid[VOL_CAPABILITIES_FORMAT] =
			VOL_CAP_FMT_PERSISTENTOBJECTIDS |
			VOL_CAP_FMT_SYMBOLICLINKS |
			VOL_CAP_FMT_HARDLINKS |
			VOL_CAP_FMT_JOURNAL |
			VOL_CAP_FMT_JOURNAL_ACTIVE |
			VOL_CAP_FMT_NO_ROOT_TIMES |
			VOL_CAP_FMT_SPARSE_FILES |
			VOL_CAP_FMT_ZERO_RUNS |
			VOL_CAP_FMT_CASE_SENSITIVE |
			VOL_CAP_FMT_CASE_PRESERVING |
			VOL_CAP_FMT_FAST_STATFS |
			VOL_CAP_FMT_2TB_FILESIZE;
		cap->valid[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_SEARCHFS |
			VOL_CAP_INT_ATTRLIST |
			VOL_CAP_INT_NFSEXPORT |
			VOL_CAP_INT_READDIRATTR |
			VOL_CAP_INT_EXCHANGEDATA |
			VOL_CAP_INT_COPYFILE |
			VOL_CAP_INT_ALLOCATE |
			VOL_CAP_INT_VOL_RENAME |
			VOL_CAP_INT_ADVLOCK |
			VOL_CAP_INT_FLOCK;
		cap->valid[VOL_CAPABILITIES_RESERVED1] = 0;
		cap->valid[VOL_CAPABILITIES_RESERVED2] = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		vol_attributes_attr_t *attrp = &fsap->f_attributes;

        	attrp->validattr.commonattr = ATTR_CMN_VALIDMASK;
        	attrp->validattr.volattr = ATTR_VOL_VALIDMASK & ~ATTR_VOL_INFO;
        	attrp->validattr.dirattr = ATTR_DIR_VALIDMASK;
        	attrp->validattr.fileattr = ATTR_FILE_VALIDMASK;
        	attrp->validattr.forkattr = 0;

        	attrp->nativeattr.commonattr = ATTR_CMN_VALIDMASK;
        	attrp->nativeattr.volattr = ATTR_VOL_VALIDMASK & ~ATTR_VOL_INFO;
        	attrp->nativeattr.dirattr = ATTR_DIR_VALIDMASK;
        	attrp->nativeattr.fileattr = ATTR_FILE_VALIDMASK;
        	attrp->nativeattr.forkattr = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}	
	fsap->f_create_time.tv_sec = hfsmp->vcbCrDate;
	fsap->f_create_time.tv_nsec = 0;
	VFSATTR_SET_SUPPORTED(fsap, f_create_time);
	fsap->f_modify_time.tv_sec = hfsmp->vcbLsMod;
	fsap->f_modify_time.tv_nsec = 0;
	VFSATTR_SET_SUPPORTED(fsap, f_modify_time);

	fsap->f_backup_time.tv_sec = hfsmp->vcbVolBkUp;
	fsap->f_backup_time.tv_nsec = 0;
	VFSATTR_SET_SUPPORTED(fsap, f_backup_time);
	if (VFSATTR_IS_ACTIVE(fsap, f_fssubtype)) {
		uint16_t subtype = 0;

		/*
		 * Subtypes (flavors) for HFS
		 *   0:   Mac OS Extended
		 *   1:   Mac OS Extended (Journaled) 
		 *   2:   Mac OS Extended (Case Sensitive) 
		 *   3:   Mac OS Extended (Case Sensitive, Journaled) 
		 *   4 - 127:   Reserved
		 * 128:   Mac OS Standard
		 * 
		 */
		if (hfsmp->hfs_flags & HFS_STANDARD) {
			subtype = HFS_SUBTYPE_STANDARDHFS;
		} else /* HFS Plus */ {
			if (hfsmp->jnl)
				subtype |= HFS_SUBTYPE_JOURNALED;
			if (hfsmp->hfs_flags & HFS_CASE_SENSITIVE)
				subtype |= HFS_SUBTYPE_CASESENSITIVE;
		}
		fsap->f_fssubtype = subtype;
		VFSATTR_SET_SUPPORTED(fsap, f_fssubtype);
	}

	if (VFSATTR_IS_ACTIVE(fsap, f_vol_name)) {
		strncpy(fsap->f_vol_name, hfsmp->vcbVN, MAXPATHLEN);
		fsap->f_vol_name[MAXPATHLEN - 1] = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_vol_name);
	}
	return (0);
}

/*
 * Perform a volume rename.  Requires the FS' root vp.
 */
static int
hfs_rename_volume(struct vnode *vp, const char *name, proc_t p)
{
	ExtendedVCB *vcb = VTOVCB(vp);
	struct cnode *cp = VTOC(vp);
	struct hfsmount *hfsmp = VTOHFS(vp);
	struct cat_desc to_desc;
	struct cat_desc todir_desc;
	struct cat_desc new_desc;
	cat_cookie_t cookie;
	int lockflags;
	int error = 0;

	/*
	 * Ignore attempts to rename a volume to a zero-length name.
	 */
	if (name[0] == 0)
		return(0);

	bzero(&to_desc, sizeof(to_desc));
	bzero(&todir_desc, sizeof(todir_desc));
	bzero(&new_desc, sizeof(new_desc));
	bzero(&cookie, sizeof(cookie));

	todir_desc.cd_parentcnid = kHFSRootParentID;
	todir_desc.cd_cnid = kHFSRootFolderID;
	todir_desc.cd_flags = CD_ISDIR;

	to_desc.cd_nameptr = name;
	to_desc.cd_namelen = strlen(name);
	to_desc.cd_parentcnid = kHFSRootParentID;
	to_desc.cd_cnid = cp->c_cnid;
	to_desc.cd_flags = CD_ISDIR;

	if ((error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK)) == 0) {
		if ((error = hfs_start_transaction(hfsmp)) == 0) {
			if ((error = cat_preflight(hfsmp, CAT_RENAME, &cookie, p)) == 0) {
				lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);

				error = cat_rename(hfsmp, &cp->c_desc, &todir_desc, &to_desc, &new_desc);

				/*
				 * If successful, update the name in the VCB, ensure it's terminated.
				 */
				if (!error) {
					strncpy(vcb->vcbVN, name, sizeof(vcb->vcbVN));
					vcb->vcbVN[sizeof(vcb->vcbVN) - 1] = 0;
				}

				hfs_systemfile_unlock(hfsmp, lockflags);
				cat_postflight(hfsmp, &cookie, p);
			
				if (error)
					vcb->vcbFlags |= 0xFF00;
				(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
			}
			hfs_end_transaction(hfsmp);
		}			
		if (!error) {
			/* Release old allocated name buffer */
			if (cp->c_desc.cd_flags & CD_HASBUF) {
				char *name = cp->c_desc.cd_nameptr;
		
				cp->c_desc.cd_nameptr = 0;
				cp->c_desc.cd_namelen = 0;
				cp->c_desc.cd_flags &= ~CD_HASBUF;
				vfs_removename(name);
			}			
			/* Update cnode's catalog descriptor */
			replace_desc(cp, &new_desc);
			vcb->volumeNameEncodingHint = new_desc.cd_encoding;
			cp->c_touch_chgtime = TRUE;
		}

		hfs_unlock(cp);
	}
	
	return(error);
}

/*
 * Get file system attributes.
 */
static int
hfs_vfs_setattr(struct mount *mp, struct vfs_attr *fsap, __unused vfs_context_t context)
{
	kauth_cred_t cred = vfs_context_ucred(context);
	int error = 0;

	/*
	 * Must be superuser or owner of filesystem to change volume attributes
	 */
	if (!kauth_cred_issuser(cred) && (kauth_cred_getuid(cred) != vfs_statfs(mp)->f_owner))
		return(EACCES);

	if (VFSATTR_IS_ACTIVE(fsap, f_vol_name)) {
		vnode_t root_vp;
		
		error = hfs_vfs_root(mp, &root_vp, context);
		if (error)
			goto out;

		error = hfs_rename_volume(root_vp, fsap->f_vol_name, vfs_context_proc(context));
		(void) vnode_put(root_vp);
		if (error)
			goto out;

		VFSATTR_SET_SUPPORTED(fsap, f_vol_name);
	}

out:
	return error;
}


/*
 * hfs vfs operations.
 */
struct vfsops hfs_vfsops = {
	hfs_mount,
	hfs_start,
	hfs_unmount,
	hfs_vfs_root,
	hfs_quotactl,
	hfs_vfs_getattr, 	/* was hfs_statfs */
	hfs_sync,
	hfs_vfs_vget,
	hfs_fhtovp,
	hfs_vptofh,
	hfs_init,
	hfs_sysctl,
	hfs_vfs_setattr
};
