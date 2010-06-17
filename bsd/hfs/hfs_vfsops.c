/*
 * Copyright (c) 1999-2010 Apple Inc. All rights reserved.
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
#include <sys/ubc_internal.h>
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
#include <sys/fslog.h>

#include <kern/locks.h>

#include <vfs/vfs_journal.h>

#include <miscfs/specfs/specdev.h>
#include <hfs/hfs_mount.h>

#include <libkern/crypto/md5.h>
#include <uuid/uuid.h>

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

/* Enable/disable debugging code for live volume resizing */
int hfs_resize_debug = 0;

lck_grp_attr_t *  hfs_group_attr;
lck_attr_t *  hfs_lock_attr;
lck_grp_t *  hfs_mutex_group;
lck_grp_t *  hfs_rwlock_group;

extern struct vnodeopv_desc hfs_vnodeop_opv_desc;
extern struct vnodeopv_desc hfs_std_vnodeop_opv_desc;

/* not static so we can re-use in hfs_readwrite.c for build_path calls */
int hfs_vfs_vget(struct mount *mp, ino64_t ino, struct vnode **vpp, vfs_context_t context);

static int hfs_changefs(struct mount *mp, struct hfs_mount_args *args);
static int hfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp, struct vnode **vpp, vfs_context_t context);
static int hfs_flushfiles(struct mount *, int, struct proc *);
static int hfs_flushMDB(struct hfsmount *hfsmp, int waitfor, int altflush);
static int hfs_getmountpoint(struct vnode *vp, struct hfsmount **hfsmpp);
static int hfs_init(struct vfsconf *vfsp);
static int hfs_mount(struct mount *mp, vnode_t  devvp, user_addr_t data, vfs_context_t context);
static int hfs_mountfs(struct vnode *devvp, struct mount *mp, struct hfs_mount_args *args, int journal_replay_only, vfs_context_t context);
static int hfs_reload(struct mount *mp);
static int hfs_vfs_root(struct mount *mp, struct vnode **vpp, vfs_context_t context);
static int hfs_quotactl(struct mount *, int, uid_t, caddr_t, vfs_context_t context);
static int hfs_start(struct mount *mp, int flags, vfs_context_t context);
static int hfs_statfs(struct mount *mp, register struct vfsstatfs *sbp, vfs_context_t context);
static int hfs_sync(struct mount *mp, int waitfor, vfs_context_t context);
static int hfs_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
                      user_addr_t newp, size_t newlen, vfs_context_t context);
static int hfs_unmount(struct mount *mp, int mntflags, vfs_context_t context);
static int hfs_vptofh(struct vnode *vp, int *fhlenp, unsigned char *fhp, vfs_context_t context);

static int hfs_reclaimspace(struct hfsmount *hfsmp, u_int32_t startblk, u_int32_t reclaimblks, vfs_context_t context);
static int hfs_overlapped_overflow_extents(struct hfsmount *hfsmp, u_int32_t startblk, u_int32_t fileID);
static int hfs_journal_replay(vnode_t devvp, vfs_context_t context);


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

	if ((error = hfs_mountfs(rvp, mp, NULL, 0, context)))
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
	u_int32_t cmdflags;

	if ((retval = copyin(data, (caddr_t)&args, sizeof(args)))) {
		return (retval);
	}
	cmdflags = (u_int32_t)vfs_flags(mp) & MNT_CMDFLAGS;
	if (cmdflags & MNT_UPDATE) {
		hfsmp = VFSTOHFS(mp);

		/* Reload incore data after an fsck. */
		if (cmdflags & MNT_RELOAD) {
			if (vfs_isrdonly(mp))
				return hfs_reload(mp);
			else
				return (EINVAL);
		}

		/* Change to a read-only file system. */
		if (((hfsmp->hfs_flags & HFS_READ_ONLY) == 0) &&
		    vfs_isrdonly(mp)) {
			int flags;

			/* Set flag to indicate that a downgrade to read-only
			 * is in progress and therefore block any further 
			 * modifications to the file system.
			 */
			hfs_global_exclusive_lock_acquire(hfsmp);
			hfsmp->hfs_flags |= HFS_RDONLY_DOWNGRADE;
			hfsmp->hfs_downgrading_proc = current_thread();
			hfs_global_exclusive_lock_release(hfsmp);

			/* use VFS_SYNC to push out System (btree) files */
			retval = VFS_SYNC(mp, MNT_WAIT, context);
			if (retval && ((cmdflags & MNT_FORCE) == 0)) {
				hfsmp->hfs_flags &= ~HFS_RDONLY_DOWNGRADE;
				hfsmp->hfs_downgrading_proc = NULL;
				goto out;
			}
		
			flags = WRITECLOSE;
			if (cmdflags & MNT_FORCE)
				flags |= FORCECLOSE;
				
			if ((retval = hfs_flushfiles(mp, flags, p))) {
				hfsmp->hfs_flags &= ~HFS_RDONLY_DOWNGRADE;
				hfsmp->hfs_downgrading_proc = NULL;
				goto out;
			}

			/* mark the volume cleanly unmounted */
			hfsmp->vcbAtrb |= kHFSVolumeUnmountedMask;
			retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
			hfsmp->hfs_flags |= HFS_READ_ONLY;

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
				hfsmp->hfs_flags &= ~HFS_RDONLY_DOWNGRADE;
				hfsmp->hfs_downgrading_proc = NULL;
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

			hfsmp->hfs_downgrading_proc = NULL;
		}

		/* Change to a writable file system. */
		if (vfs_iswriteupgrade(mp)) {

			/*
			 * On inconsistent disks, do not allow read-write mount
			 * unless it is the boot volume being mounted.
			 */
			if (!(vfs_flags(mp) & MNT_ROOTFS) &&
					(hfsmp->vcbAtrb & kHFSVolumeInconsistentMask)) {
				retval = EINVAL;
				goto out;
			}

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
						      hfsmp->hfs_logical_block_size,
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

			/* See if we need to erase unused Catalog nodes due to <rdar://problem/6947811>. */
			retval = hfs_erase_unused_nodes(hfsmp);
			if (retval != E_NONE)
				goto out;
			
			/* Only clear HFS_READ_ONLY after a successful write */
			hfsmp->hfs_flags &= ~HFS_READ_ONLY;

			/* If this mount point was downgraded from read-write 
			 * to read-only, clear that information as we are now 
			 * moving back to read-write.
			 */
			hfsmp->hfs_flags &= ~HFS_RDONLY_DOWNGRADE;
			hfsmp->hfs_downgrading_proc = NULL;

			/* mark the volume dirty (clear clean unmount bit) */
			hfsmp->vcbAtrb &= ~kHFSVolumeUnmountedMask;

			retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
			if (retval != E_NONE)
				goto out;

			if (!(hfsmp->hfs_flags & (HFS_READ_ONLY | HFS_STANDARD))) {
				/* Setup private/hidden directories for hardlinks. */
				hfs_privatedir_init(hfsmp, FILE_HARDLINKS);
				hfs_privatedir_init(hfsmp, DIR_HARDLINKS);

				hfs_remove_orphans(hfsmp);

				/*
				 * Allow hot file clustering if conditions allow.
				 */
				if (hfsmp->hfs_flags & HFS_METADATA_ZONE) {
					(void) hfs_recording_init(hfsmp);
				}
				/* Force ACLs on HFS+ file systems. */
				if (vfs_extendedsecurity(HFSTOVFS(hfsmp)) == 0) {
					vfs_setextendedsecurity(HFSTOVFS(hfsmp));
				}
			}
		}

		/* Update file system parameters. */
		retval = hfs_changefs(mp, &args);

	} else /* not an update request */ {

		/* Set the mount flag to indicate that we support volfs  */
		vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_DOVOLFS));

		retval = hfs_mountfs(devvp, mp, &args, 0, context);
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
	int lockflags;
	int error;

	args = (struct hfs_changefs_cargs *)cargs;

	cp = VTOC(vp);
	vcb = HFSTOVCB(args->hfsmp);

	lockflags = hfs_systemfile_lock(args->hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
	error = cat_lookup(args->hfsmp, &cp->c_desc, 0, &cndesc, &cnattr, NULL, NULL);
	hfs_systemfile_unlock(args->hfsmp, lockflags);
	if (error) {
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
		        strlcpy((char *)vcb->vcbVN, (const char *)cp->c_desc.cd_nameptr, NAME_MAX+1);
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
	u_int32_t old_encoding = 0;
	struct hfs_changefs_cargs cargs;
	u_int32_t mount_flags;

	hfsmp = VFSTOHFS(mp);
	vcb = HFSTOVCB(hfsmp);
	mount_flags = (unsigned int)vfs_flags(mp);

	hfsmp->hfs_flags |= HFS_IN_CHANGEFS;
	
	permswitch = (((hfsmp->hfs_flags & HFS_UNKNOWN_PERMS) &&
	               ((mount_flags & MNT_UNKNOWNPERMISSIONS) == 0)) ||
	              (((hfsmp->hfs_flags & HFS_UNKNOWN_PERMS) == 0) &&
	               (mount_flags & MNT_UNKNOWNPERMISSIONS)));

	/* The root filesystem must operate with actual permissions: */
	if (permswitch && (mount_flags & MNT_ROOTFS) && (mount_flags & MNT_UNKNOWNPERMISSIONS)) {
		vfs_clearflags(mp, (u_int64_t)((unsigned int)MNT_UNKNOWNPERMISSIONS));	/* Just say "No". */
		retval = EINVAL;
		goto exit;
	}
	if (mount_flags & MNT_UNKNOWNPERMISSIONS)
		hfsmp->hfs_flags |= HFS_UNKNOWN_PERMS;
	else
		hfsmp->hfs_flags &= ~HFS_UNKNOWN_PERMS;

	namefix = permfix = 0;

	/*
	 * Tracking of hot files requires up-to-date access times.  So if
	 * access time updates are disabled, we must also disable hot files.
	 */
	if (mount_flags & MNT_NOATIME) {
		(void) hfs_recording_suspend(hfsmp);
	}
	
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
	    (args->hfs_encoding != (u_int32_t)VNOVAL)              &&
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
	 *
	 * The vnode will be properly referenced and unreferenced 
	 * around the callback
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
	hfsmp->hfs_flags &= ~HFS_IN_CHANGEFS;
	return (retval);
}


struct hfs_reload_cargs {
	struct hfsmount *hfsmp;
        int		error;
};

static int
hfs_reload_callback(struct vnode *vp, void *cargs)
{
	struct cnode *cp;
	struct hfs_reload_cargs *args;
	int lockflags;

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
		lockflags = hfs_systemfile_lock(args->hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
		args->error = cat_idlookup(args->hfsmp, cp->c_fileid, 0, &desc, &cp->c_attr, datafork);
		hfs_systemfile_unlock(args->hfsmp, lockflags);
		if (args->error) {
		        return (VNODE_RETURNED_DONE);
		}

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
hfs_reload(struct mount *mountp)
{
	register struct vnode *devvp;
	struct buf *bp;
	int error, i;
	struct hfsmount *hfsmp;
	struct HFSPlusVolumeHeader *vhp;
	ExtendedVCB *vcb;
	struct filefork *forkp;
    	struct cat_desc cndesc;
	struct hfs_reload_cargs args;
	daddr64_t priIDSector;

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
	priIDSector = (daddr64_t)((vcb->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size) + 
			HFS_PRI_SECTOR(hfsmp->hfs_logical_block_size));

	error = (int)buf_meta_bread(hfsmp->hfs_devvp,
			HFS_PHYSBLK_ROUNDDOWN(priIDSector, hfsmp->hfs_log_per_phys),
			hfsmp->hfs_physical_block_size, NOCRED, &bp);
	if (error) {
        	if (bp != NULL)
        		buf_brelse(bp);
		return (error);
	}

	vhp = (HFSPlusVolumeHeader *) (buf_dataptr(bp) + HFS_PRI_OFFSET(hfsmp->hfs_physical_block_size));

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
	HFS_UPDATE_NEXT_ALLOCATION(vcb, SWAP_BE32 (vhp->nextAllocation));
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
	if ((error = cat_idlookup(hfsmp, kHFSRootFolderID, 0, &cndesc, NULL, NULL)))
		return (error);
	vcb->volumeNameEncodingHint = cndesc.cd_encoding;
	bcopy(cndesc.cd_nameptr, vcb->vcbVN, min(255, cndesc.cd_namelen));
	cat_releasedesc(&cndesc);

	/* Re-establish private/hidden directories. */
	hfs_privatedir_init(hfsmp, FILE_HARDLINKS);
	hfs_privatedir_init(hfsmp, DIR_HARDLINKS);

	/* In case any volume information changed to trigger a notification */
	hfs_generate_volume_notifications(hfsmp);
    
	return (0);
}



static void
hfs_syncer(void *arg0, void *unused)
{
#pragma unused(unused)

    struct hfsmount *hfsmp = arg0;
    clock_sec_t secs;
    clock_usec_t usecs;
    uint32_t delay = HFS_META_DELAY;
    uint64_t now;
    static int no_max=1;

    clock_get_calendar_microtime(&secs, &usecs);
    now = ((uint64_t)secs * 1000000ULL) + (uint64_t)usecs;

    //
    // If the amount of pending writes is more than our limit, wait
    // for 2/3 of it to drain and then flush the journal. 
    //
    if (hfsmp->hfs_mp->mnt_pending_write_size > hfsmp->hfs_max_pending_io) {
	    int counter=0;
	    uint64_t pending_io, start, rate;
	    
	    no_max = 0;

	    hfs_start_transaction(hfsmp);   // so we hold off any new i/o's

	    pending_io = hfsmp->hfs_mp->mnt_pending_write_size;
	    
	    clock_get_calendar_microtime(&secs, &usecs);
	    start = ((uint64_t)secs * 1000000ULL) + (uint64_t)usecs;

	    while(hfsmp->hfs_mp->mnt_pending_write_size > (pending_io/3) && counter++ < 500) {
		    tsleep((caddr_t)hfsmp, PRIBIO, "hfs-wait-for-io-to-drain", 10);
	    }

	    if (counter >= 500) {
		    printf("hfs: timed out waiting for io to drain (%lld)\n", (int64_t)hfsmp->hfs_mp->mnt_pending_write_size);
	    }

	    if (hfsmp->jnl) {
		    journal_flush(hfsmp->jnl);
	    } else {
		    hfs_sync(hfsmp->hfs_mp, MNT_WAIT, vfs_context_kernel());
	    }

	    clock_get_calendar_microtime(&secs, &usecs);
	    now = ((uint64_t)secs * 1000000ULL) + (uint64_t)usecs;
	    hfsmp->hfs_last_sync_time = now;
	    rate = ((pending_io * 1000000ULL) / (now - start));     // yields bytes per second

	    hfs_end_transaction(hfsmp);
	    
	    //
	    // If a reasonable amount of time elapsed then check the
	    // i/o rate.  If it's taking less than 1 second or more
	    // than 2 seconds, adjust hfs_max_pending_io so that we
	    // will allow about 1.5 seconds of i/o to queue up.
	    //
	    if ((now - start) >= 300000) {
		    uint64_t scale = (pending_io * 100) / rate;
		    
		    if (scale < 100 || scale > 200) {
			    // set it so that it should take about 1.5 seconds to drain
			    hfsmp->hfs_max_pending_io = (rate * 150ULL) / 100ULL;
		    }
	    }
  
    } else if (   ((now - hfsmp->hfs_last_sync_time) >= 5000000ULL)
	       || (((now - hfsmp->hfs_last_sync_time) >= 100000LL)
		   && ((now - hfsmp->hfs_last_sync_request_time) >= 100000LL)
		   && (hfsmp->hfs_active_threads == 0)
		   && (hfsmp->hfs_global_lock_nesting == 0))) {

	    //
	    // Flush the journal if more than 5 seconds elapsed since
	    // the last sync OR we have not sync'ed recently and the
	    // last sync request time was more than 100 milliseconds
	    // ago and no one is in the middle of a transaction right
	    // now.  Else we defer the sync and reschedule it.
	    //
	    if (hfsmp->jnl) {
		    lck_rw_lock_shared(&hfsmp->hfs_global_lock);

		    journal_flush(hfsmp->jnl);

		    lck_rw_unlock_shared(&hfsmp->hfs_global_lock);
	    } else {
		    hfs_sync(hfsmp->hfs_mp, MNT_WAIT, vfs_context_kernel());
	    }

	    clock_get_calendar_microtime(&secs, &usecs);
	    now = ((uint64_t)secs * 1000000ULL) + (uint64_t)usecs;
	    hfsmp->hfs_last_sync_time = now;
	    
    } else if (hfsmp->hfs_active_threads == 0) {
	    uint64_t deadline;

	    clock_interval_to_deadline(delay, HFS_MILLISEC_SCALE, &deadline);
	    thread_call_enter_delayed(hfsmp->hfs_syncer, deadline);

	    // note: we intentionally return early here and do not
	    // decrement the sync_scheduled and sync_incomplete
	    // variables because we rescheduled the timer.

	    return;
    }
	    
    //
    // NOTE: we decrement these *after* we're done the journal_flush() since
    // it can take a significant amount of time and so we don't want more
    // callbacks scheduled until we're done this one.
    //
    OSDecrementAtomic((volatile SInt32 *)&hfsmp->hfs_sync_scheduled);
    OSDecrementAtomic((volatile SInt32 *)&hfsmp->hfs_sync_incomplete);
    wakeup((caddr_t)&hfsmp->hfs_sync_incomplete);
}


extern int IOBSDIsMediaEjectable( const char *cdev_name );

/*
 * Common code for mount and mountroot
 */
static int
hfs_mountfs(struct vnode *devvp, struct mount *mp, struct hfs_mount_args *args,
            int journal_replay_only, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	int retval = E_NONE;
	struct hfsmount	*hfsmp = NULL;
	struct buf *bp;
	dev_t dev;
	HFSMasterDirectoryBlock *mdbp = NULL;
	int ronly;
#if QUOTA
	int i;
#endif
	int mntwrapper;
	kauth_cred_t cred;
	u_int64_t disksize;
	daddr64_t log_blkcnt;
	u_int32_t log_blksize;
	u_int32_t phys_blksize;
	u_int32_t minblksize;
	u_int32_t iswritable;
	daddr64_t mdb_offset;
	int isvirtual = 0;
	int isroot = 0;

	if (args == NULL) {
		/* only hfs_mountroot passes us NULL as the 'args' argument */
		isroot = 1;
	}

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

	/* Get the logical block size (treated as physical block size everywhere) */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&log_blksize, 0, context)) {
		retval = ENXIO;
		goto error_exit;
	}
	if (log_blksize == 0 || log_blksize > 1024*1024*1024) {
		printf("hfs: logical block size 0x%x looks bad.  Not mounting.\n", log_blksize);
		retval = ENXIO;
		goto error_exit;
	}
	
	/* Get the physical block size. */
	retval = VNOP_IOCTL(devvp, DKIOCGETPHYSICALBLOCKSIZE, (caddr_t)&phys_blksize, 0, context);
	if (retval) {
		if ((retval != ENOTSUP) && (retval != ENOTTY)) {
			retval = ENXIO;
			goto error_exit;
		}
		/* If device does not support this ioctl, assume that physical 
		 * block size is same as logical block size 
		 */
		phys_blksize = log_blksize;
	}
	if (phys_blksize == 0 || phys_blksize > 1024*1024*1024) {
		printf("hfs: physical block size 0x%x looks bad.  Not mounting.\n", phys_blksize);
		retval = ENXIO;
		goto error_exit;
	}

	/* Switch to 512 byte sectors (temporarily) */
	if (log_blksize > 512) {
		u_int32_t size512 = 512;

		if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&size512, FWRITE, context)) {
			retval = ENXIO;
			goto error_exit;
		}
	}
	/* Get the number of 512 byte physical blocks. */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0, context)) {
		/* resetting block size may fail if getting block count did */
		(void)VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&log_blksize, FWRITE, context);

		retval = ENXIO;
		goto error_exit;
	}
	/* Compute an accurate disk size (i.e. within 512 bytes) */
	disksize = (u_int64_t)log_blkcnt * (u_int64_t)512;

	/*
	 * On Tiger it is not necessary to switch the device 
	 * block size to be 4k if there are more than 31-bits
	 * worth of blocks but to insure compatibility with
	 * pre-Tiger systems we have to do it.
	 *
	 * If the device size is not a multiple of 4K (8 * 512), then
	 * switching the logical block size isn't going to help because
	 * we will be unable to write the alternate volume header.
	 * In this case, just leave the logical block size unchanged.
	 */
	if (log_blkcnt > 0x000000007fffffff && (log_blkcnt & 7) == 0) {
		minblksize = log_blksize = 4096;
		if (phys_blksize < log_blksize)
			phys_blksize = log_blksize;
	}
	
	/*
	 * The cluster layer is not currently prepared to deal with a logical
	 * block size larger than the system's page size.  (It can handle
	 * blocks per page, but not multiple pages per block.)  So limit the
	 * logical block size to the page size.
	 */
	if (log_blksize > PAGE_SIZE)
		log_blksize = PAGE_SIZE;
	
	/* Now switch to our preferred physical block size. */
	if (log_blksize > 512) {
		if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&log_blksize, FWRITE, context)) {
			retval = ENXIO;
			goto error_exit;
		}
		/* Get the count of physical blocks. */
		if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0, context)) {
			retval = ENXIO;
			goto error_exit;
		}
	}
	/*
	 * At this point:
	 *   minblksize is the minimum physical block size
	 *   log_blksize has our preferred physical block size
	 *   log_blkcnt has the total number of physical blocks
	 */

	mdb_offset = (daddr64_t)HFS_PRI_SECTOR(log_blksize);
	if ((retval = (int)buf_meta_bread(devvp, 
				HFS_PHYSBLK_ROUNDDOWN(mdb_offset, (phys_blksize/log_blksize)), 
				phys_blksize, cred, &bp))) {
		goto error_exit;
	}
	MALLOC(mdbp, HFSMasterDirectoryBlock *, kMDBSize, M_TEMP, M_WAITOK);
	if (mdbp == NULL) {
		retval = ENOMEM;
		goto error_exit;
	}
	bcopy((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(phys_blksize), mdbp, kMDBSize);
	buf_brelse(bp);
	bp = NULL;

	MALLOC(hfsmp, struct hfsmount *, sizeof(struct hfsmount), M_HFSMNT, M_WAITOK);
	if (hfsmp == NULL) {
		retval = ENOMEM;
		goto error_exit;
	}
	bzero(hfsmp, sizeof(struct hfsmount));
	
	hfs_chashinit_finish(hfsmp);

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
	vnode_ref(devvp);  /* Hold a ref on the device, dropped when hfsmp is freed. */
	hfsmp->hfs_logical_block_size = log_blksize;
	hfsmp->hfs_logical_block_count = log_blkcnt;
	hfsmp->hfs_physical_block_size = phys_blksize;
	hfsmp->hfs_log_per_phys = (phys_blksize / log_blksize);
	hfsmp->hfs_flags |= HFS_WRITEABLE_MEDIA;
	if (ronly)
		hfsmp->hfs_flags |= HFS_READ_ONLY;
	if (((unsigned int)vfs_flags(mp)) & MNT_UNKNOWNPERMISSIONS)
		hfsmp->hfs_flags |= HFS_UNKNOWN_PERMS;

#if QUOTA
	for (i = 0; i < MAXQUOTAS; i++)
		dqfileinit(&hfsmp->hfs_qfiles[i]);
#endif

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
	struct timeval tv;
	microtime(&tv);
	hfsmp->hfs_mount_time = tv.tv_sec;

	/* Mount a standard HFS disk */
	if ((SWAP_BE16(mdbp->drSigWord) == kHFSSigWord) &&
	    (mntwrapper || (SWAP_BE16(mdbp->drEmbedSigWord) != kHFSPlusSigWord))) {

		/* On 10.6 and beyond, non read-only mounts for HFS standard vols get rejected */
		if (vfs_isrdwr(mp)) {
			retval = EROFS;
			goto error_exit;
		}
		/* Treat it as if it's read-only and not writeable */
		hfsmp->hfs_flags |= HFS_READ_ONLY;
		hfsmp->hfs_flags &= ~HFS_WRITEABLE_MEDIA;

	   	/* If only journal replay is requested, exit immediately */
		if (journal_replay_only) {
			retval = 0;
			goto error_exit;
		}

	        if ((vfs_flags(mp) & MNT_ROOTFS)) {	
			retval = EINVAL;  /* Cannot root from HFS standard disks */
			goto error_exit;
		}
		/* HFS disks can only use 512 byte physical blocks */
		if (log_blksize > kHFSBlockSize) {
			log_blksize = kHFSBlockSize;
			if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&log_blksize, FWRITE, context)) {
				retval = ENXIO;
				goto error_exit;
			}
			if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0, context)) {
				retval = ENXIO;
				goto error_exit;
			}
			hfsmp->hfs_logical_block_size = log_blksize;
			hfsmp->hfs_logical_block_count = log_blkcnt;
			hfsmp->hfs_physical_block_size = log_blksize;
			hfsmp->hfs_log_per_phys = 1;
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
			if ((embeddedOffset % log_blksize) != 0) {
				printf("hfs_mountfs: embedded volume offset not"
				    " a multiple of physical block size (%d);"
				    " switching to 512\n", log_blksize);
				log_blksize = 512;
				if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE,
				    (caddr_t)&log_blksize, FWRITE, context)) {
					retval = ENXIO;
					goto error_exit;
				}
				if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT,
				    (caddr_t)&log_blkcnt, 0, context)) {
					retval = ENXIO;
					goto error_exit;
				}
				/* Note: relative block count adjustment */
				hfsmp->hfs_logical_block_count *=
				    hfsmp->hfs_logical_block_size / log_blksize;
				
				/* Update logical /physical block size */
				hfsmp->hfs_logical_block_size = log_blksize;
				hfsmp->hfs_physical_block_size = log_blksize;
				phys_blksize = log_blksize;
				hfsmp->hfs_log_per_phys = 1;
			}

			disksize = (u_int64_t)SWAP_BE16(mdbp->drEmbedExtent.blockCount) *
			           (u_int64_t)SWAP_BE32(mdbp->drAlBlkSiz);

			hfsmp->hfs_logical_block_count = disksize / log_blksize;
	
			mdb_offset = (daddr64_t)((embeddedOffset / log_blksize) + HFS_PRI_SECTOR(log_blksize));
			retval = (int)buf_meta_bread(devvp, HFS_PHYSBLK_ROUNDDOWN(mdb_offset, hfsmp->hfs_log_per_phys),
					phys_blksize, cred, &bp);
			if (retval)
				goto error_exit;
			bcopy((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(phys_blksize), mdbp, 512);
			buf_brelse(bp);
			bp = NULL;
			vhp = (HFSPlusVolumeHeader*) mdbp;

		} else /* pure HFS+ */ {
			embeddedOffset = 0;
			vhp = (HFSPlusVolumeHeader*) mdbp;
		}

		/*
		 * On inconsistent disks, do not allow read-write mount
		 * unless it is the boot volume being mounted.  We also
		 * always want to replay the journal if the journal_replay_only
		 * flag is set because that will (most likely) get the
		 * disk into a consistent state before fsck_hfs starts
		 * looking at it.
		 */
		if (  !(vfs_flags(mp) & MNT_ROOTFS)
		   && (SWAP_BE32(vhp->attributes) & kHFSVolumeInconsistentMask)
		   && !journal_replay_only
		   && !(hfsmp->hfs_flags & HFS_READ_ONLY)) {
			retval = EINVAL;
			goto error_exit;
		}


		// XXXdbg
		//
		hfsmp->jnl = NULL;
		hfsmp->jvp = NULL;
		if (args != NULL && (args->flags & HFSFSMNT_EXTENDED_ARGS) && 
		    args->journal_disable) {
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
			if ((retval = hfs_early_journal_init(hfsmp, vhp, args, embeddedOffset, mdb_offset, mdbp, cred)) == 0) {
				vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_JOURNALED));
			} else {
				if (retval == EROFS) {
					// EROFS is a special error code that means the volume has an external
					// journal which we couldn't find.  in that case we do not want to
					// rewrite the volume header - we'll just refuse to mount the volume.
					retval = EINVAL;
					goto error_exit;
				}

				// if the journal failed to open, then set the lastMountedVersion
				// to be "FSK!" which fsck_hfs will see and force the fsck instead
				// of just bailing out because the volume is journaled.
				if (!ronly) {
				    HFSPlusVolumeHeader *jvhp;

				    hfsmp->hfs_flags |= HFS_NEED_JNL_RESET;
				    
				    if (mdb_offset == 0) {
					mdb_offset = (daddr64_t)((embeddedOffset / log_blksize) + HFS_PRI_SECTOR(log_blksize));
				    }

				    bp = NULL;
				    retval = (int)buf_meta_bread(devvp, 
						    HFS_PHYSBLK_ROUNDDOWN(mdb_offset, hfsmp->hfs_log_per_phys), 
						    phys_blksize, cred, &bp);
				    if (retval == 0) {
					jvhp = (HFSPlusVolumeHeader *)(buf_dataptr(bp) + HFS_PRI_OFFSET(phys_blksize));
					    
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
	
		/* Either the journal is replayed successfully, or there 
		 * was nothing to replay, or no journal exists.  In any case,
		 * return success.
		 */
		if (journal_replay_only) {
			retval = 0;
			goto error_exit;
		}

		(void) hfs_getconverter(0, &hfsmp->hfs_get_unicode, &hfsmp->hfs_get_hfsname);

		retval = hfs_MountHFSPlusVolume(hfsmp, vhp, embeddedOffset, disksize, p, args, cred);
		/*
		 * If the backend didn't like our physical blocksize
		 * then retry with physical blocksize of 512.
		 */
		if ((retval == ENXIO) && (log_blksize > 512) && (log_blksize != minblksize)) {
			printf("hfs_mountfs: could not use physical block size "
				"(%d) switching to 512\n", log_blksize);
			log_blksize = 512;
			if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&log_blksize, FWRITE, context)) {
				retval = ENXIO;
				goto error_exit;
			}
			if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0, context)) {
				retval = ENXIO;
				goto error_exit;
			}
			devvp->v_specsize = log_blksize;
			/* Note: relative block count adjustment (in case this is an embedded volume). */
    			hfsmp->hfs_logical_block_count *= hfsmp->hfs_logical_block_size / log_blksize;
     			hfsmp->hfs_logical_block_size = log_blksize;
     			hfsmp->hfs_log_per_phys = hfsmp->hfs_physical_block_size / log_blksize;
 
			if (hfsmp->jnl && hfsmp->jvp == devvp) {
			    // close and re-open this with the new block size
			    journal_close(hfsmp->jnl);
			    hfsmp->jnl = NULL;
			    if (hfs_early_journal_init(hfsmp, vhp, args, embeddedOffset, mdb_offset, mdbp, cred) == 0) {
					vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_JOURNALED));
				} else {
					// if the journal failed to open, then set the lastMountedVersion
					// to be "FSK!" which fsck_hfs will see and force the fsck instead
					// of just bailing out because the volume is journaled.
					if (!ronly) {
				    	HFSPlusVolumeHeader *jvhp;

				    	hfsmp->hfs_flags |= HFS_NEED_JNL_RESET;
				    
				    	if (mdb_offset == 0) {
							mdb_offset = (daddr64_t)((embeddedOffset / log_blksize) + HFS_PRI_SECTOR(log_blksize));
				    	}

				   	 	bp = NULL;
				    	retval = (int)buf_meta_bread(devvp, HFS_PHYSBLK_ROUNDDOWN(mdb_offset, hfsmp->hfs_log_per_phys), 
							phys_blksize, cred, &bp);
				    	if (retval == 0) {
							jvhp = (HFSPlusVolumeHeader *)(buf_dataptr(bp) + HFS_PRI_OFFSET(phys_blksize));
					    
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

	mp->mnt_vtable->vfc_vfsflags |= VFC_VFSNATIVEXATTR;
#if NAMEDSTREAMS
	mp->mnt_kern_flag |= MNTK_NAMED_STREAMS;
#endif
	if (!(hfsmp->hfs_flags & HFS_STANDARD)) {
		/* Tell VFS that we support directory hard links. */
		mp->mnt_vtable->vfc_vfsflags |= VFC_VFSDIRLINKS;
	} else {
		/* HFS standard doesn't support extended readdir! */
		mp->mnt_vtable->vfc_vfsflags &= ~VFC_VFSREADDIR_EXTENDED;
	}

	if (args) {
		/*
		 * Set the free space warning levels for a non-root volume:
		 *
		 * Set the "danger" limit to 1% of the volume size or 100MB, whichever
		 * is less.  Set the "warning" limit to 2% of the volume size or 150MB,
		 * whichever is less.  And last, set the "desired" freespace level to
		 * to 3% of the volume size or 200MB, whichever is less.
		 */
		hfsmp->hfs_freespace_notify_dangerlimit =
			MIN(HFS_VERYLOWDISKTRIGGERLEVEL / HFSTOVCB(hfsmp)->blockSize,
				(HFSTOVCB(hfsmp)->totalBlocks / 100) * HFS_VERYLOWDISKTRIGGERFRACTION);
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
		 * Set the "danger" limit to 5% of the volume size or 125MB, whichever
		 * is less.  Set the "warning" limit to 10% of the volume size or 250MB,
		 * whichever is less.  And last, set the "desired" freespace level to
		 * to 11% of the volume size or 375MB, whichever is less.
		 */
		hfsmp->hfs_freespace_notify_dangerlimit =
			MIN(HFS_ROOTVERYLOWDISKTRIGGERLEVEL / HFSTOVCB(hfsmp)->blockSize,
				(HFSTOVCB(hfsmp)->totalBlocks / 100) * HFS_ROOTVERYLOWDISKTRIGGERFRACTION);
		hfsmp->hfs_freespace_notify_warninglimit =
			MIN(HFS_ROOTLOWDISKTRIGGERLEVEL / HFSTOVCB(hfsmp)->blockSize,
				(HFSTOVCB(hfsmp)->totalBlocks / 100) * HFS_ROOTLOWDISKTRIGGERFRACTION);
		hfsmp->hfs_freespace_notify_desiredlevel =
			MIN(HFS_ROOTLOWDISKSHUTOFFLEVEL / HFSTOVCB(hfsmp)->blockSize,
				(HFSTOVCB(hfsmp)->totalBlocks / 100) * HFS_ROOTLOWDISKSHUTOFFFRACTION);
	};
	
	/* Check if the file system exists on virtual device, like disk image */
	if (VNOP_IOCTL(devvp, DKIOCISVIRTUAL, (caddr_t)&isvirtual, 0, context) == 0) {
		if (isvirtual) {
			hfsmp->hfs_flags |= HFS_VIRTUAL_DEVICE;
		}
	}

	/* do not allow ejectability checks on the root device */
	if (isroot == 0) {
		if ((hfsmp->hfs_flags & HFS_VIRTUAL_DEVICE) == 0 && 
				IOBSDIsMediaEjectable(mp->mnt_vfsstat.f_mntfromname)) {
			hfsmp->hfs_max_pending_io = 4096*1024;   // a reasonable value to start with.
			hfsmp->hfs_syncer = thread_call_allocate(hfs_syncer, hfsmp);
			if (hfsmp->hfs_syncer == NULL) {
				printf("hfs: failed to allocate syncer thread callback for %s (%s)\n",
						mp->mnt_vfsstat.f_mntfromname, mp->mnt_vfsstat.f_mntonname);
			}
		}
	}

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
		vnode_clearmountedon(hfsmp->jvp);
		(void)VNOP_CLOSE(hfsmp->jvp, ronly ? FREAD : FREAD|FWRITE, vfs_context_kernel());
		hfsmp->jvp = NULL;
	}
	if (hfsmp) {
		if (hfsmp->hfs_devvp) {
			vnode_rele(hfsmp->hfs_devvp);
		}
		hfs_delete_chash(hfsmp);

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
	 * Cancel any pending timers for this volume.  Then wait for any timers
	 * which have fired, but whose callbacks have not yet completed.
	 */
	if (hfsmp->hfs_syncer)
	{
		struct timespec ts = {0, 100000000};	/* 0.1 seconds */
		
		/*
		 * Cancel any timers that have been scheduled, but have not
		 * fired yet.  NOTE: The kernel considers a timer complete as
		 * soon as it starts your callback, so the kernel does not
		 * keep track of the number of callbacks in progress.
		 */
		if (thread_call_cancel(hfsmp->hfs_syncer))
			OSDecrementAtomic((volatile SInt32 *)&hfsmp->hfs_sync_incomplete);
		thread_call_free(hfsmp->hfs_syncer);
		hfsmp->hfs_syncer = NULL;
		
		/*
		 * This waits for all of the callbacks that were entered before
		 * we did thread_call_cancel above, but have not completed yet.
		 */
		while(hfsmp->hfs_sync_incomplete > 0)
		{
			msleep((caddr_t)&hfsmp->hfs_sync_incomplete, NULL, PWAIT, "hfs_unmount", &ts);
		}
		
		if (hfsmp->hfs_sync_incomplete < 0)
			panic("hfs_unmount: pm_sync_incomplete underflow!\n");
	}
	
	/*
	 * Flush out the b-trees, volume bitmap and Volume Header
	 */
	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0) {
		retval = hfs_start_transaction(hfsmp);
		if (retval == 0) {
		    started_tr = 1;
		} else if (!force) {
		    goto err_exit;
		}

		if (hfsmp->hfs_startup_vp) {
			(void) hfs_lock(VTOC(hfsmp->hfs_startup_vp), HFS_EXCLUSIVE_LOCK);
			retval = hfs_fsync(hfsmp->hfs_startup_vp, MNT_WAIT, 0, p);
			hfs_unlock(VTOC(hfsmp->hfs_startup_vp));
			if (retval && !force)
				goto err_exit;
		}

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

		/* If runtime corruption was detected, indicate that the volume
		 * was not unmounted cleanly.
		 */
		if (hfsmp->vcbAtrb & kHFSVolumeInconsistentMask) {
			HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeUnmountedMask;
		} else {
			HFSTOVCB(hfsmp)->vcbAtrb |= kHFSVolumeUnmountedMask;
		}

		if (hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
			int i;
			u_int32_t min_start = hfsmp->totalBlocks;

			// set the nextAllocation pointer to the smallest free block number
			// we've seen so on the next mount we won't rescan unnecessarily
			for(i=0; i < (int)hfsmp->vcbFreeExtCnt; i++) {
				if (hfsmp->vcbFreeExt[i].startBlock < min_start) {
					min_start = hfsmp->vcbFreeExt[i].startBlock;
				}
			}
			if (min_start < hfsmp->nextAllocation) {
				hfsmp->nextAllocation = min_start;
			}
		}


		retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
		if (retval) {
			HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeUnmountedMask;
			if (!force)
				goto err_exit;	/* could not flush everything */
		}

		if (started_tr) {
		    hfs_end_transaction(hfsmp);
		    started_tr = 0;
		}
	}

	if (hfsmp->jnl) {
		hfs_journal_flush(hfsmp);
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
	    vnode_clearmountedon(hfsmp->jvp);
	    retval = VNOP_CLOSE(hfsmp->jvp,
	                       hfsmp->hfs_flags & HFS_READ_ONLY ? FREAD : FREAD|FWRITE,
			       vfs_context_kernel());
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
	vnode_rele(hfsmp->hfs_devvp);

	hfs_delete_chash(hfsmp);
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
#if !QUOTA
static int
hfs_quotactl(__unused struct mount *mp, __unused int cmds, __unused uid_t uid, __unused caddr_t datap, __unused vfs_context_t context)
{
	return (ENOTSUP);
}
#else
static int
hfs_quotactl(struct mount *mp, int cmds, uid_t uid, caddr_t datap, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	int cmd, type, error;

	if (uid == ~0U)
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
}
#endif /* QUOTA */

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
	u_int32_t freeCNIDs;
	u_int16_t subtype = 0;

	freeCNIDs = (u_int32_t)0xFFFFFFFF - (u_int32_t)vcb->vcbNxtCNID;

	sbp->f_bsize = (u_int32_t)vcb->blockSize;
	sbp->f_iosize = (size_t)cluster_max_io_size(mp, 0);
	sbp->f_blocks = (u_int64_t)((u_int32_t)vcb->totalBlocks);
	sbp->f_bfree = (u_int64_t)((u_int32_t )hfs_freeblks(hfsmp, 0));
	sbp->f_bavail = (u_int64_t)((u_int32_t )hfs_freeblks(hfsmp, 1));
	sbp->f_files = (u_int64_t)((u_int32_t )(vcb->totalBlocks - 2));  /* max files is constrained by total blocks */
	sbp->f_ffree = (u_int64_t)((u_int32_t )(MIN(freeCNIDs, sbp->f_bavail)));

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
	int  retval;
	daddr64_t priIDSector;
	hfsmp = VFSTOHFS(mp);
	vcb = HFSTOVCB(hfsmp);

	// now make sure the super block is flushed
	priIDSector = (daddr64_t)((vcb->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size) +
				  HFS_PRI_SECTOR(hfsmp->hfs_logical_block_size));

	retval = (int)buf_meta_bread(hfsmp->hfs_devvp, 
			HFS_PHYSBLK_ROUNDDOWN(priIDSector, hfsmp->hfs_log_per_phys),
			hfsmp->hfs_physical_block_size, NOCRED, &bp);
	if ((retval != 0 ) && (retval != ENXIO)) {
		printf("hfs_sync_metadata: can't read volume header at %d! (retval 0x%x)\n",
		       (int)priIDSector, retval);
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
		retval = (int)buf_meta_bread(hfsmp->hfs_devvp, 
				HFS_PHYSBLK_ROUNDDOWN(hfsmp->hfs_alt_id_sector, hfsmp->hfs_log_per_phys),
				hfsmp->hfs_physical_block_size, NOCRED, &bp);
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

	hfsmp = VFSTOHFS(mp);

	/*
	 * hfs_changefs might be manipulating vnodes so back off
	 */
	if (hfsmp->hfs_flags & HFS_IN_CHANGEFS)
		return (0);

	if (hfsmp->hfs_flags & HFS_READ_ONLY)
		return (EROFS);

	/* skip over frozen volumes */
	if (!lck_rw_try_lock_shared(&hfsmp->hfs_insync))
		return 0;

	args.cred = kauth_cred_get();
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

	hfs_hotfilesync(hfsmp, vfs_context_kernel());

	/*
	 * Write back modified superblock.
	 */
	if (IsVCBDirty(vcb)) {
		error = hfs_flushvolumeheader(hfsmp, waitfor, 0);
		if (error)
			allerror = error;
	}

	if (hfsmp->jnl) {
	    hfs_journal_flush(hfsmp);
	}

	{
		clock_sec_t secs;
		clock_usec_t usecs;
		uint64_t now;

		clock_get_calendar_microtime(&secs, &usecs);
		now = ((uint64_t)secs * 1000000ULL) + (uint64_t)usecs;
		hfsmp->hfs_last_sync_time = now;
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
hfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp, struct vnode **vpp, __unused vfs_context_t context)
{
	struct hfsfid *hfsfhp;
	struct vnode *nvp;
	int result;

	*vpp = NULL;
	hfsfhp = (struct hfsfid *)fhp;

	if (fhlen < (int)sizeof(struct hfsfid))
		return (EINVAL);

	result = hfs_vget(VFSTOHFS(mp), ntohl(hfsfhp->hfsfid_cnid), &nvp, 0);
	if (result) {
		if (result == ENOENT)
			result = ESTALE;
		return result;
	}

	/* 
	 * We used to use the create time as the gen id of the file handle,
	 * but it is not static enough because it can change at any point 
	 * via system calls.  We still don't have another volume ID or other
	 * unique identifier to use for a generation ID across reboots that
	 * persists until the file is removed.  Using only the CNID exposes
	 * us to the potential wrap-around case, but as of 2/2008, it would take
	 * over 2 months to wrap around if the machine did nothing but allocate
	 * CNIDs.  Using some kind of wrap counter would only be effective if
	 * each file had the wrap counter associated with it.  For now, 
	 * we use only the CNID to identify the file as it's good enough.
	 */	 

	*vpp = nvp;

	hfs_unlock(VTOC(nvp));
	return (0);
}


/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
static int
hfs_vptofh(struct vnode *vp, int *fhlenp, unsigned char *fhp, __unused vfs_context_t context)
{
	struct cnode *cp;
	struct hfsfid *hfsfhp;

	if (ISHFS(VTOVCB(vp)))
		return (ENOTSUP);	/* hfs standard is not exportable */

	if (*fhlenp < (int)sizeof(struct hfsfid))
		return (EOVERFLOW);

	cp = VTOC(vp);
	hfsfhp = (struct hfsfid *)fhp;
	/* only the CNID is used to identify the file now */
	hfsfhp->hfsfid_cnid = htonl(cp->c_fileid);
	hfsfhp->hfsfid_gen = htonl(cp->c_fileid);
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

	BTReserveSetup();
	
	
	hfs_lock_attr    = lck_attr_alloc_init();
	hfs_group_attr   = lck_grp_attr_alloc_init();
	hfs_mutex_group  = lck_grp_alloc_init("hfs-mutex", hfs_group_attr);
	hfs_rwlock_group = lck_grp_alloc_init("hfs-rwlock", hfs_group_attr);
	
#if HFS_COMPRESSION
    decmpfs_init();
#endif

	return (0);
}

static int
hfs_getmountpoint(struct vnode *vp, struct hfsmount **hfsmpp)
{
	struct hfsmount * hfsmp;
	char fstypename[MFSNAMELEN];

	if (vp == NULL)
		return (EINVAL);
	
	if (!vnode_isvroot(vp))
		return (EINVAL);

	vnode_vfsname(vp, fstypename);
	if (strncmp(fstypename, "hfs", sizeof(fstypename)) != 0)
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
		int bias;

		bias = hfs_getencodingbias();
		error = sysctl_int(oldp, oldlenp, newp, newlen, &bias);
		if (error == 0 && newp)
			hfs_setencodingbias(bias);
		return (error);

	} else if (name[0] == HFS_EXTEND_FS) {
        u_int64_t  newsize;
		vnode_t vp = vfs_context_cwd(context);

		if (newp == USER_ADDR_NULL || vp == NULLVP)
			return (EINVAL);
		if ((error = hfs_getmountpoint(vp, &hfsmp)))
			return (error);
		error = sysctl_quad(oldp, oldlenp, newp, newlen, (quad_t *)&newsize);
		if (error)
			return (error);
	
		error = hfs_extendfs(hfsmp, newsize, context);		
		return (error);

	} else if (name[0] == HFS_ENCODINGHINT) {
		size_t bufsize;
		size_t bytes;
		u_int32_t hint;
		u_int16_t *unicode_name = NULL;
		char *filename = NULL;

		if ((newlen <= 0) || (newlen > MAXPATHLEN)) 
			return (EINVAL);

		bufsize = MAX(newlen * 3, MAXPATHLEN);
		MALLOC(filename, char *, newlen, M_TEMP, M_WAITOK);
		if (filename == NULL) {
			error = ENOMEM;
			goto encodinghint_exit;
		}
		MALLOC(unicode_name, u_int16_t *, bufsize, M_TEMP, M_WAITOK);
		if (filename == NULL) {
			error = ENOMEM;
			goto encodinghint_exit;
		}

		error = copyin(newp, (caddr_t)filename, newlen);
		if (error == 0) {
			error = utf8_decodestr((u_int8_t *)filename, newlen - 1, unicode_name,
			                       &bytes, bufsize, 0, UTF_DECOMPOSED);
			if (error == 0) {
				hint = hfs_pickencoding(unicode_name, bytes / 2);
				error = sysctl_int(oldp, oldlenp, USER_ADDR_NULL, 0, (int32_t *)&hint);
			}
		}

encodinghint_exit:
		if (unicode_name)
			FREE(unicode_name, M_TEMP);
		if (filename)
			FREE(filename, M_TEMP);
		return (error);

	} else if (name[0] == HFS_ENABLE_JOURNALING) {
		// make the file system journaled...
		vnode_t vp = vfs_context_cwd(context);
		vnode_t jvp;
		ExtendedVCB *vcb;
		struct cat_attr jnl_attr, jinfo_attr;
		struct cat_fork jnl_fork, jinfo_fork;
		void *jnl = NULL;
		int lockflags;

		/* Only root can enable journaling */
		if (!is_suser()) {
			return (EPERM);
		}
		if (vp == NULLVP)
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
		    printf("hfs: volume @ mp %p is already journaled!\n", vnode_mount(vp));
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

		//
		// XXXdbg - note that currently (Sept, 08) hfs_util does not support
		//          enabling the journal on a separate device so it is safe
		//          to just copy hfs_devvp here.  If hfs_util gets the ability
		//          to dynamically enable the journal on a separate device then
		//          we will have to do the same thing as hfs_early_journal_init()
		//          to locate and open the journal device.
		//
		jvp = hfsmp->hfs_devvp;
		jnl = journal_create(jvp,
							 (off_t)name[2] * (off_t)HFSTOVCB(hfsmp)->blockSize
							 + HFSTOVCB(hfsmp)->hfsPlusIOPosOffset,
							 (off_t)((unsigned)name[3]),
							 hfsmp->hfs_devvp,
							 hfsmp->hfs_logical_block_size,
							 0,
							 0,
							 hfs_sync_metadata, hfsmp->hfs_mp);

		if (jnl == NULL) {
			printf("hfs: FAILED to create the journal!\n");
			if (jvp && jvp != hfsmp->hfs_devvp) {
				vnode_clearmountedon(jvp);
				VNOP_CLOSE(jvp, hfsmp->hfs_flags & HFS_READ_ONLY ? FREAD : FREAD|FWRITE, vfs_context_kernel());
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

		vfs_setflags(hfsmp->hfs_mp, (u_int64_t)((unsigned int)MNT_JOURNALED));

		hfs_global_exclusive_lock_release(hfsmp);
		hfs_flushvolumeheader(hfsmp, MNT_WAIT, 1);

		{
			fsid_t fsid;
		
			fsid.val[0] = (int32_t)hfsmp->hfs_raw_dev;
			fsid.val[1] = (int32_t)vfs_typenum(HFSTOVFS(hfsmp));
			vfs_event_signal(&fsid, VQ_UPDATE, (intptr_t)NULL);
		}
		return 0;
	} else if (name[0] == HFS_DISABLE_JOURNALING) {
		// clear the journaling bit 
		vnode_t vp = vfs_context_cwd(context);
		
		/* Only root can disable journaling */
		if (!is_suser()) {
			return (EPERM);
		}
		if (vp == NULLVP)
		        return EINVAL;

		hfsmp = VTOHFS(vp);

		/* 
		 * Disabling journaling is disallowed on volumes with directory hard links
		 * because we have not tested the relevant code path.
		 */  
		if (hfsmp->hfs_private_attr[DIR_HARDLINKS].ca_entries != 0){
			printf("hfs: cannot disable journaling on volumes with directory hardlinks\n");
			return EPERM;
		}

		printf("hfs: disabling journaling for mount @ %p\n", vnode_mount(vp));

		hfs_global_exclusive_lock_acquire(hfsmp);

		// Lights out for you buddy!
		journal_close(hfsmp->jnl);
		hfsmp->jnl = NULL;

		if (hfsmp->jvp && hfsmp->jvp != hfsmp->hfs_devvp) {
			vnode_clearmountedon(hfsmp->jvp);
			VNOP_CLOSE(hfsmp->jvp, hfsmp->hfs_flags & HFS_READ_ONLY ? FREAD : FREAD|FWRITE, vfs_context_kernel());
			vnode_put(hfsmp->jvp);
		}
		hfsmp->jvp = NULL;
		vfs_clearflags(hfsmp->hfs_mp, (u_int64_t)((unsigned int)MNT_JOURNALED));
		hfsmp->jnl_start        = 0;
		hfsmp->hfs_jnlinfoblkid = 0;
		hfsmp->hfs_jnlfileid    = 0;
		
		HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeJournaledMask;
		
		hfs_global_exclusive_lock_release(hfsmp);
		hfs_flushvolumeheader(hfsmp, MNT_WAIT, 1);

		{
			fsid_t fsid;
		
			fsid.val[0] = (int32_t)hfsmp->hfs_raw_dev;
			fsid.val[1] = (int32_t)vfs_typenum(HFSTOVFS(hfsmp));
			vfs_event_signal(&fsid, VQ_UPDATE, (intptr_t)NULL);
		}
		return 0;
	} else if (name[0] == HFS_GET_JOURNAL_INFO) {
		vnode_t vp = vfs_context_cwd(context);
		off_t jnl_start, jnl_size;

		if (vp == NULLVP)
		        return EINVAL;

		/* 64-bit processes won't work with this sysctl -- can't fit a pointer into an int! */
		if (proc_is64bit(current_proc()))
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

	    return set_package_extensions_table((user_addr_t)((unsigned)name[1]), name[2], name[3]);
	    
	} else if (name[0] == VFS_CTL_QUERY) {
    	struct sysctl_req *req;
    	union union_vfsidctl vc;
    	struct mount *mp;
 	    struct vfsquery vq;
	
		req = CAST_DOWN(struct sysctl_req *, oldp);	/* we're new style vfs sysctl. */
        
        error = SYSCTL_IN(req, &vc, proc_is64bit(p)? sizeof(vc.vc64):sizeof(vc.vc32));
		if (error) return (error);

		mp = vfs_getvfs(&vc.vc32.vc_fsid); /* works for 32 and 64 */
        if (mp == NULL) return (ENOENT);
        
		hfsmp = VFSTOHFS(mp);
		bzero(&vq, sizeof(vq));
		vq.vq_flags = hfsmp->hfs_notification_conditions;
		return SYSCTL_OUT(req, &vq, sizeof(vq));;
	} else if (name[0] == HFS_REPLAY_JOURNAL) {
		vnode_t devvp = NULL;
		int device_fd;
		if (namelen != 2) {
			return (EINVAL);
		}
		device_fd = name[1];
		error = file_vnode(device_fd, &devvp);
		if (error) {
			return error;
		}
		error = vnode_getwithref(devvp);
		if (error) {
			file_drop(device_fd);
			return error;
		}
		error = hfs_journal_replay(devvp, context);
		file_drop(device_fd);
		vnode_put(devvp);
		return error;
	}

	return (ENOTSUP);
}

/* 
 * hfs_vfs_vget is not static since it is used in hfs_readwrite.c to support
 * the build_path ioctl.  We use it to leverage the code below that updates
 * the origin list cache if necessary
 */

int
hfs_vfs_vget(struct mount *mp, ino64_t ino, struct vnode **vpp, __unused vfs_context_t context)
{
	int error;
	int lockflags;
	struct hfsmount *hfsmp;

	hfsmp = VFSTOHFS(mp);

	error = hfs_vget(hfsmp, (cnid_t)ino, vpp, 1);
	if (error)
		return (error);

	/*
	 * ADLs may need to have their origin state updated
	 * since build_path needs a valid parent.  The same is true
	 * for hardlinked files as well.  There isn't a race window here
	 * in re-acquiring the cnode lock since we aren't pulling any data 
	 * out of the cnode; instead, we're going to the catalog.
	 */
	if ((VTOC(*vpp)->c_flag & C_HARDLINK) &&
	    (hfs_lock(VTOC(*vpp), HFS_EXCLUSIVE_LOCK) == 0)) {
		cnode_t *cp = VTOC(*vpp);
		struct cat_desc cdesc;
		
		if (!hfs_haslinkorigin(cp)) {
			lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
			error = cat_findname(hfsmp, (cnid_t)ino, &cdesc);
			hfs_systemfile_unlock(hfsmp, lockflags);
			if (error == 0) {
				if ((cdesc.cd_parentcnid != hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) &&
					(cdesc.cd_parentcnid != hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid)) {
					hfs_savelinkorigin(cp, cdesc.cd_parentcnid);
				}
				cat_releasedesc(&cdesc);
			}
		}
		hfs_unlock(cp);
	}
	return (0);
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
	struct vnode *vp = NULLVP;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	struct cat_fork cnfork;
	u_int32_t linkref = 0;
	int error;
	
	/* Check for cnids that should't be exported. */
	if ((cnid < kHFSFirstUserCatalogNodeID) &&
	    (cnid != kHFSRootFolderID && cnid != kHFSRootParentID)) {
		return (ENOENT);
	}
	/* Don't export our private directories. */
	if (cnid == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid ||
	    cnid == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
		return (ENOENT);
	}
	/*
	 * Check the hash first
	 */
	vp = hfs_chash_getvnode(hfsmp, cnid, 0, skiplock);
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

		cndesc.cd_nameptr = (const u_int8_t *)&hfs_rootname[0];
		cndesc.cd_namelen = 1;
		cndesc.cd_parentcnid = kHFSRootParentID;
		cndesc.cd_cnid = kHFSRootFolderID;
		cndesc.cd_flags = CD_ISDIR;

		cnattr.ca_fileid = kHFSRootFolderID;
		cnattr.ca_linkcount = 1;
		cnattr.ca_entries = 1;
		cnattr.ca_dircount = 1;
		cnattr.ca_mode = (S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO);
	} else {
		int lockflags;
		cnid_t pid;
		const char *nameptr;

		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
		error = cat_idlookup(hfsmp, cnid, 0, &cndesc, &cnattr, &cnfork);
		hfs_systemfile_unlock(hfsmp, lockflags);

		if (error) {
			*vpp = NULL;
			return (error);
		}

		/*
		 * Check for a raw hardlink inode and save its linkref.
		 */
		pid = cndesc.cd_parentcnid;
		nameptr = (const char *)cndesc.cd_nameptr;

		if ((pid == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid) &&
		    (bcmp(nameptr, HFS_INODE_PREFIX, HFS_INODE_PREFIX_LEN) == 0)) {
			linkref = strtoul(&nameptr[HFS_INODE_PREFIX_LEN], NULL, 10);

		} else if ((pid == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) &&
		           (bcmp(nameptr, HFS_DIRINODE_PREFIX, HFS_DIRINODE_PREFIX_LEN) == 0)) {
			linkref = strtoul(&nameptr[HFS_DIRINODE_PREFIX_LEN], NULL, 10);

		} else if ((pid == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid) &&
		           (bcmp(nameptr, HFS_DELETE_PREFIX, HFS_DELETE_PREFIX_LEN) == 0)) {
			*vpp = NULL;
			cat_releasedesc(&cndesc);
			return (ENOENT);  /* open unlinked file */
		}
	}

	/*
	 * Finish initializing cnode descriptor for hardlinks.
	 *
	 * We need a valid name and parent for reverse lookups.
	 */
	if (linkref) {
		cnid_t nextlinkid;
		cnid_t prevlinkid;
		struct cat_desc linkdesc;
		int lockflags;

		cnattr.ca_linkref = linkref;

		/*
		 * Pick up the first link in the chain and get a descriptor for it.
		 * This allows blind volfs paths to work for hardlinks.
		 */
		if ((hfs_lookuplink(hfsmp, linkref, &prevlinkid,  &nextlinkid) == 0) &&
		    (nextlinkid != 0)) {
			lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
			error = cat_findname(hfsmp, nextlinkid, &linkdesc);
			hfs_systemfile_unlock(hfsmp, lockflags);
			if (error == 0) {
				cat_releasedesc(&cndesc);
				bcopy(&linkdesc, &cndesc, sizeof(linkdesc));
			}
		}	
	}

	if (linkref) {
		error = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &cnfork, &vp);
		if (error == 0) {
			VTOC(vp)->c_flag |= C_HARDLINK;
			vnode_setmultipath(vp);
		}
	} else {
		struct componentname cn;

		/* Supply hfs_getnewvnode with a component name. */
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
	
		error = hfs_getnewvnode(hfsmp, NULLVP, &cn, &cndesc, 0, &cnattr, &cnfork, &vp);

		if (error == 0 && (VTOC(vp)->c_flag & C_HARDLINK)) {
			hfs_savelinkorigin(VTOC(vp), cndesc.cd_parentcnid);
		}
		FREE_ZONE(cn.cn_pnbuf, cn.cn_pnlen, M_NAMEI);
	}
	cat_releasedesc(&cndesc);

	*vpp = vp;
	if (vp && skiplock) {
		hfs_unlock(VTOC(vp));
	}
	return (error);
}


/*
 * Flush out all the files in a filesystem.
 */
static int
#if QUOTA
hfs_flushfiles(struct mount *mp, int flags, struct proc *p)
#else
hfs_flushfiles(struct mount *mp, int flags, __unused struct proc *p)
#endif /* QUOTA */
{
	struct hfsmount *hfsmp;
	struct vnode *skipvp = NULLVP;
	int error;
#if QUOTA
	int quotafilecnt;
	int i;
#endif

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
		skipvp = hfs_chash_getvnode(hfsmp, kHFSRootFolderID, 0, 0);
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

	u_int32_t	index;

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

	if (index < 64 && (hfsmp->encodingsBitmap & (u_int64_t)(1ULL << index)) == 0) {
		HFS_MOUNT_LOCK(hfsmp, TRUE)
		hfsmp->encodingsBitmap |= (u_int64_t)(1ULL << index);
		MarkVCBDirty(hfsmp);
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

	MarkVCBDirty(hfsmp);
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

	sectorsize = hfsmp->hfs_logical_block_size;
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

	namelen = strlen((char *)vcb->vcbVN);
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
	HFSPlusVolumeHeader *volumeHeader, *altVH;
	int retval;
	struct buf *bp, *alt_bp;
	int i;
	daddr64_t priIDSector;
	int critical;
	u_int16_t  signature;
	u_int16_t  hfsversion;

	if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		return(0);
	}
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return hfs_flushMDB(hfsmp, waitfor, altflush);
	}
	critical = altflush;
	priIDSector = (daddr64_t)((vcb->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size) +
				  HFS_PRI_SECTOR(hfsmp->hfs_logical_block_size));

	if (hfs_start_transaction(hfsmp) != 0) {
	    return EINVAL;
	}

	bp = NULL;
	alt_bp = NULL;

	retval = (int)buf_meta_bread(hfsmp->hfs_devvp, 
			HFS_PHYSBLK_ROUNDDOWN(priIDSector, hfsmp->hfs_log_per_phys),
			hfsmp->hfs_physical_block_size, NOCRED, &bp);
	if (retval) {
		printf("hfs: err %d reading VH blk (%s)\n", retval, vcb->vcbVN);
		goto err_exit;
	}

	volumeHeader = (HFSPlusVolumeHeader *)((char *)buf_dataptr(bp) + 
			HFS_PRI_OFFSET(hfsmp->hfs_physical_block_size));

	/*
	 * Sanity check what we just read.  If it's bad, try the alternate
	 * instead.
	 */
	signature = SWAP_BE16 (volumeHeader->signature);
	hfsversion   = SWAP_BE16 (volumeHeader->version);
	if ((signature != kHFSPlusSigWord && signature != kHFSXSigWord) ||
	    (hfsversion < kHFSPlusVersion) || (hfsversion > 100) ||
	    (SWAP_BE32 (volumeHeader->blockSize) != vcb->blockSize)) {
		printf("hfs: corrupt VH on %s, sig 0x%04x, ver %d, blksize %d%s\n",
		      vcb->vcbVN, signature, hfsversion,
		      SWAP_BE32 (volumeHeader->blockSize),
		      hfsmp->hfs_alt_id_sector ? "; trying alternate" : "");
		hfs_mark_volume_inconsistent(hfsmp);
		
		if (hfsmp->hfs_alt_id_sector) {
			retval = buf_meta_bread(hfsmp->hfs_devvp, 
			    HFS_PHYSBLK_ROUNDDOWN(hfsmp->hfs_alt_id_sector, hfsmp->hfs_log_per_phys),
			    hfsmp->hfs_physical_block_size, NOCRED, &alt_bp);
			if (retval) {
				printf("hfs: err %d reading alternate VH (%s)\n", retval, vcb->vcbVN);
				goto err_exit;
			}
			
			altVH = (HFSPlusVolumeHeader *)((char *)buf_dataptr(alt_bp) + 
				HFS_ALT_OFFSET(hfsmp->hfs_physical_block_size));
			signature = SWAP_BE16(altVH->signature);
			hfsversion = SWAP_BE16(altVH->version);
			
			if ((signature != kHFSPlusSigWord && signature != kHFSXSigWord) ||
			    (hfsversion < kHFSPlusVersion) || (kHFSPlusVersion > 100) ||
			    (SWAP_BE32(altVH->blockSize) != vcb->blockSize)) {
				printf("hfs: corrupt alternate VH on %s, sig 0x%04x, ver %d, blksize %d\n",
				    vcb->vcbVN, signature, hfsversion,
				    SWAP_BE32(altVH->blockSize));
				retval = EIO;
				goto err_exit;
			}
			
			/* The alternate is plausible, so use it. */
			bcopy(altVH, volumeHeader, kMDBSize);
			buf_brelse(alt_bp);
			alt_bp = NULL;
		} else {
			/* No alternate VH, nothing more we can do. */
			retval = EIO;
			goto err_exit;
		}
	}

	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, bp);
	}

	/*
	 * For embedded HFS+ volumes, update create date if it changed
	 * (ie from a setattrlist call)
	 */
	if ((vcb->hfsPlusIOPosOffset != 0) &&
	    (SWAP_BE32 (volumeHeader->createDate) != vcb->localCreateDate)) {
		struct buf *bp2;
		HFSMasterDirectoryBlock	*mdb;

		retval = (int)buf_meta_bread(hfsmp->hfs_devvp, 
				HFS_PHYSBLK_ROUNDDOWN(HFS_PRI_SECTOR(hfsmp->hfs_logical_block_size), hfsmp->hfs_log_per_phys),
				hfsmp->hfs_physical_block_size, NOCRED, &bp2);
		if (retval) {
			if (bp2)
				buf_brelse(bp2);
			retval = 0;
		} else {
			mdb = (HFSMasterDirectoryBlock *)(buf_dataptr(bp2) +
				HFS_PRI_OFFSET(hfsmp->hfs_physical_block_size));

			if ( SWAP_BE32 (mdb->drCrDate) != vcb->localCreateDate )
			  {
				if (hfsmp->jnl) {
				    journal_modify_block_start(hfsmp->jnl, bp2);
				}

				mdb->drCrDate = SWAP_BE32 (vcb->localCreateDate);	/* pick up the new create date */

				if (hfsmp->jnl) {
					journal_modify_block_end(hfsmp->jnl, bp2, NULL, NULL);
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

	lck_mtx_lock(&hfsmp->hfs_mutex);

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

	/*
	 * System files are only dirty when altflush is set.
	 */
	if (altflush == 0) {
		goto done;
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

	/* Sync Startup file meta data */
	if (hfsmp->hfs_startup_vp) {
		fp = VTOF(hfsmp->hfs_startup_vp);
		if (FTOC(fp)->c_flag & C_MODIFIED) {
			for (i = 0; i < kHFSPlusExtentDensity; i++) {
				volumeHeader->startupFile.extents[i].startBlock =
					SWAP_BE32 (fp->ff_extents[i].startBlock);
				volumeHeader->startupFile.extents[i].blockCount =
					SWAP_BE32 (fp->ff_extents[i].blockCount);
			}
			volumeHeader->startupFile.logicalSize = SWAP_BE64 (fp->ff_size);
			volumeHeader->startupFile.totalBlocks = SWAP_BE32 (fp->ff_blocks);
			volumeHeader->startupFile.clumpSize   = SWAP_BE32 (fp->ff_clumpsize);
			FTOC(fp)->c_flag &= ~C_MODIFIED;
		}
	}

done:
	MarkVCBClean(hfsmp);
	lck_mtx_unlock(&hfsmp->hfs_mutex);

	/* If requested, flush out the alternate volume header */
	if (altflush && hfsmp->hfs_alt_id_sector) {
		if (buf_meta_bread(hfsmp->hfs_devvp, 
				HFS_PHYSBLK_ROUNDDOWN(hfsmp->hfs_alt_id_sector, hfsmp->hfs_log_per_phys),
				hfsmp->hfs_physical_block_size, NOCRED, &alt_bp) == 0) {
			if (hfsmp->jnl) {
				journal_modify_block_start(hfsmp->jnl, alt_bp);
			}

			bcopy(volumeHeader, (char *)buf_dataptr(alt_bp) + 
					HFS_ALT_OFFSET(hfsmp->hfs_physical_block_size), 
					kMDBSize);

			if (hfsmp->jnl) {
				journal_modify_block_end(hfsmp->jnl, alt_bp, NULL, NULL);
			} else {
				(void) VNOP_BWRITE(alt_bp);
			}
		} else if (alt_bp)
			buf_brelse(alt_bp);
	}

	if (hfsmp->jnl) {
		journal_modify_block_end(hfsmp->jnl, bp, NULL, NULL);
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

err_exit:
	if (alt_bp)
		buf_brelse(alt_bp);
	if (bp)
		buf_brelse(bp);
	hfs_end_transaction(hfsmp);
	return retval;
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
	u_int32_t  phys_sectorsize;
	daddr64_t  prev_alt_sector;
	daddr_t	   bitmapblks;
	int  lockflags = 0;
	int  error;
	int64_t oldBitmapSize;
	Boolean  usedExtendFileC = false;
	int transaction_begun = 0;
	
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
	if (sectorsize != hfsmp->hfs_logical_block_size) {
		return (ENXIO);
	}
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&sectorcnt, 0, context)) {
		return (ENXIO);
	}
	if ((sectorsize * sectorcnt) < newsize) {
		printf("hfs_extendfs: not enough space on device\n");
		return (ENOSPC);
	}
	error = VNOP_IOCTL(devvp, DKIOCGETPHYSICALBLOCKSIZE, (caddr_t)&phys_sectorsize, 0, context);
	if (error) {
		if ((error != ENOTSUP) && (error != ENOTTY)) {
			return (ENXIO);
		}
		/* If ioctl is not supported, force physical and logical sector size to be same */
		phys_sectorsize = sectorsize;
	}
	oldsize = (u_int64_t)hfsmp->totalBlocks * (u_int64_t)hfsmp->blockSize;

	/*
	 * Validate new size.
	 */
	if ((newsize <= oldsize) || (newsize % sectorsize) || (newsize % phys_sectorsize)) {
		printf("hfs_extendfs: invalid size\n");
		return (EINVAL);
	}
	newblkcnt = newsize / vcb->blockSize;
	if (newblkcnt > (u_int64_t)0xFFFFFFFF)
		return (EOVERFLOW);

	addblks = newblkcnt - vcb->totalBlocks;

	printf("hfs_extendfs: growing %s by %d blocks\n", vcb->vcbVN, addblks);

	HFS_MOUNT_LOCK(hfsmp, TRUE);
	if (hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS) {
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		error = EALREADY;
		goto out;
	}
	hfsmp->hfs_flags |= HFS_RESIZE_IN_PROGRESS;
	HFS_MOUNT_UNLOCK(hfsmp, TRUE);

	/* Invalidate the current free extent cache */
	invalidate_free_extent_cache(hfsmp);
	
	/*
	 * Enclose changes inside a transaction.
	 */
	if (hfs_start_transaction(hfsmp) != 0) {
		error = EINVAL;
		goto out;
	}
	transaction_begun = 1;

	/*
	 * Note: we take the attributes lock in case we have an attribute data vnode
	 * which needs to change size.
	 */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE | SFL_EXTENTS | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	vp = vcb->allocationsRefNum;
	fp = VTOF(vp);
	bcopy(&fp->ff_data, &forkdata, sizeof(forkdata));

	/*
	 * Calculate additional space required (if any) by allocation bitmap.
	 */
	oldBitmapSize = fp->ff_size;
	bitmapblks = roundup((newblkcnt+7) / 8, vcb->vcbVBMIOSize) / vcb->blockSize;
	if (bitmapblks > (daddr_t)fp->ff_blocks)
		bitmapblks -= fp->ff_blocks;
	else
		bitmapblks = 0;

	if (bitmapblks > 0) {
		daddr64_t blkno;
		daddr_t blkcnt;
		off_t bytesAdded;

		/*
		 * Get the bitmap's current size (in allocation blocks) so we know
		 * where to start zero filling once the new space is added.  We've
		 * got to do this before the bitmap is grown.
		 */
		blkno  = (daddr64_t)fp->ff_blocks;

		/*
		 * Try to grow the allocation file in the normal way, using allocation
		 * blocks already existing in the file system.  This way, we might be
		 * able to grow the bitmap contiguously, or at least in the metadata
		 * zone.
		 */
		error = ExtendFileC(vcb, fp, bitmapblks * vcb->blockSize, 0,
				kEFAllMask | kEFNoClumpMask | kEFReserveMask | kEFMetadataMask,
				&bytesAdded);

		if (error == 0) {
			usedExtendFileC = true;
		} else {
			/*
			 * If the above allocation failed, fall back to allocating the new
			 * extent of the bitmap from the space we're going to add.  Since those
			 * blocks don't yet belong to the file system, we have to update the
			 * extent list directly, and manually adjust the file size.
			 */
			bytesAdded = 0;
			error = AddFileExtent(vcb, fp, vcb->totalBlocks, bitmapblks);
			if (error) {
				printf("hfs_extendfs: error %d adding extents\n", error);
				goto out;
			}
			fp->ff_blocks += bitmapblks;
			VTOC(vp)->c_blocks = fp->ff_blocks;
			VTOC(vp)->c_flag |= C_MODIFIED;
		}
		
		/*
		 * Update the allocation file's size to include the newly allocated
		 * blocks.  Note that ExtendFileC doesn't do this, which is why this
		 * statement is outside the above "if" statement.
		 */
		fp->ff_size += (u_int64_t)bitmapblks * (u_int64_t)vcb->blockSize;
		
		/*
		 * Zero out the new bitmap blocks.
		 */
		{
	
			bp = NULL;
			blkcnt = bitmapblks;
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
		 *
		 * Note that ExtendFileC will have marked any blocks it allocated, so
		 * this is only needed if we used AddFileExtent.  Also note that this
		 * has to come *after* the zero filling of new blocks in the case where
		 * we used AddFileExtent (since the part of the bitmap we're touching
		 * is in those newly allocated blocks).
		 */
		if (!usedExtendFileC) {
			error = BlockMarkAllocated(vcb, vcb->totalBlocks, bitmapblks);
			if (error) {
				printf("hfs_extendfs: error %d setting bitmap\n", error);
				goto out;
			}
			vcb->freeBlocks -= bitmapblks;
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
	prev_phys_block_count = hfsmp->hfs_logical_block_count;
	prev_alt_sector = hfsmp->hfs_alt_id_sector;

	vcb->totalBlocks += addblks;
	vcb->freeBlocks += addblks;
	hfsmp->hfs_logical_block_count = newsize / sectorsize;
	hfsmp->hfs_alt_id_sector = (hfsmp->hfsPlusIOPosOffset / sectorsize) +
	                          HFS_ALT_SECTOR(sectorsize, hfsmp->hfs_logical_block_count);
	MarkVCBDirty(vcb);
	error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
	if (error) {
		printf("hfs_extendfs: couldn't flush volume headers (%d)", error);
		/*
		 * Restore to old state.
		 */
		if (usedExtendFileC) {
			(void) TruncateFileC(vcb, fp, oldBitmapSize, false);
		} else {
			fp->ff_blocks -= bitmapblks;
			fp->ff_size -= (u_int64_t)bitmapblks * (u_int64_t)vcb->blockSize;
			/*
			 * No need to mark the excess blocks free since those bitmap blocks
			 * are no longer part of the bitmap.  But we do need to undo the
			 * effect of the "vcb->freeBlocks -= bitmapblks" above.
			 */
			vcb->freeBlocks += bitmapblks;
		}
		vcb->totalBlocks -= addblks;
		vcb->freeBlocks -= addblks;
		hfsmp->hfs_logical_block_count = prev_phys_block_count;
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
		if (buf_meta_bread(hfsmp->hfs_devvp, 
				HFS_PHYSBLK_ROUNDDOWN(prev_alt_sector, hfsmp->hfs_log_per_phys),
				hfsmp->hfs_physical_block_size, NOCRED, &bp) == 0) {
			journal_modify_block_start(hfsmp->jnl, bp);
	
			bzero((char *)buf_dataptr(bp) + HFS_ALT_OFFSET(hfsmp->hfs_physical_block_size), kMDBSize);
	
			journal_modify_block_end(hfsmp->jnl, bp, NULL, NULL);
		} else if (bp) {
			buf_brelse(bp);
		}
	}
	
	/*
	 * TODO: Adjust the size of the metadata zone based on new volume size?
	 */
	 
	/*
	 * Adjust the size of hfsmp->hfs_attrdata_vp
	 */
	if (hfsmp->hfs_attrdata_vp) {
		struct cnode *attr_cp;
		struct filefork *attr_fp;
		
		if (vnode_get(hfsmp->hfs_attrdata_vp) == 0) {
			attr_cp = VTOC(hfsmp->hfs_attrdata_vp);
			attr_fp = VTOF(hfsmp->hfs_attrdata_vp);
			
			attr_cp->c_blocks = newblkcnt;
			attr_fp->ff_blocks = newblkcnt;
			attr_fp->ff_extents[0].blockCount = newblkcnt;
			attr_fp->ff_size = (off_t) newblkcnt * hfsmp->blockSize;
			ubc_setsize(hfsmp->hfs_attrdata_vp, attr_fp->ff_size);
			vnode_put(hfsmp->hfs_attrdata_vp);
		}
	}

out:
	if (error && fp) {
		/* Restore allocation fork. */
		bcopy(&forkdata, &fp->ff_data, sizeof(forkdata));
		VTOC(vp)->c_blocks = fp->ff_blocks;

	}
	/*
	   Regardless of whether or not the totalblocks actually increased,
	   we should reset the allocLimit field. If it changed, it will
	   get updated; if not, it will remain the same.
	*/
	HFS_MOUNT_LOCK(hfsmp, TRUE);	
	hfsmp->hfs_flags &= ~HFS_RESIZE_IN_PROGRESS;
	hfsmp->allocLimit = vcb->totalBlocks;
	HFS_MOUNT_UNLOCK(hfsmp, TRUE);	
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (transaction_begun) {
		hfs_end_transaction(hfsmp);
	}

	return (error);
}

#define HFS_MIN_SIZE  (32LL * 1024LL * 1024LL)

/*
 * Truncate a file system (while still mounted).
 */
__private_extern__
int
hfs_truncatefs(struct hfsmount *hfsmp, u_int64_t newsize, vfs_context_t context)
{
	struct  buf *bp = NULL;
	u_int64_t oldsize;
	u_int32_t newblkcnt;
	u_int32_t reclaimblks = 0;
	int lockflags = 0;
	int transaction_begun = 0;
	Boolean updateFreeBlocks = false;
	int error;

	HFS_MOUNT_LOCK(hfsmp, TRUE);	
	if (hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS) {
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);	
		return (EALREADY);
	}
	hfsmp->hfs_flags |= HFS_RESIZE_IN_PROGRESS;
	hfsmp->hfs_resize_filesmoved = 0;
	hfsmp->hfs_resize_totalfiles = 0;
	HFS_MOUNT_UNLOCK(hfsmp, TRUE);	

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

	if (hfs_resize_debug) {
		printf ("hfs_truncatefs: old: size=%qu, blkcnt=%u, freeblks=%u\n", oldsize, hfsmp->totalBlocks, hfs_freeblks(hfsmp, 1));
		printf ("hfs_truncatefs: new: size=%qu, blkcnt=%u, reclaimblks=%u\n", newsize, newblkcnt, reclaimblks);
	}

	/* Make sure new size is valid. */
	if ((newsize < HFS_MIN_SIZE) ||
	    (newsize >= oldsize) ||
	    (newsize % hfsmp->hfs_logical_block_size) ||
	    (newsize % hfsmp->hfs_physical_block_size)) {
		printf ("hfs_truncatefs: invalid size (newsize=%qu, oldsize=%qu)\n", newsize, oldsize);
		error = EINVAL;
		goto out;
	}
	/* Make sure that the file system has enough free blocks reclaim */
	if (reclaimblks >= hfs_freeblks(hfsmp, 1)) {
		printf("hfs_truncatefs: insufficient space (need %u blocks; have %u free blocks)\n", reclaimblks, hfs_freeblks(hfsmp, 1));
		error = ENOSPC;
		goto out;
	}
	
	/* Invalidate the current free extent cache */
	invalidate_free_extent_cache(hfsmp);
	
	/* Start with a clean journal. */
	hfs_journal_flush(hfsmp);
	
	if (hfs_start_transaction(hfsmp) != 0) {
		error = EINVAL;
		goto out;
	}
	transaction_begun = 1;

	/*
	 * Prevent new allocations from using the part we're trying to truncate.
	 *
	 * NOTE: allocLimit is set to the allocation block number where the new
	 * alternate volume header will be.  That way there will be no files to
	 * interfere with allocating the new alternate volume header, and no files
	 * in the allocation blocks beyond (i.e. the blocks we're trying to
	 * truncate away.
	 */
	HFS_MOUNT_LOCK(hfsmp, TRUE);	
	if (hfsmp->blockSize == 512) 
		hfsmp->allocLimit = newblkcnt - 2;
	else
		hfsmp->allocLimit = newblkcnt - 1;
	/* Update the volume free block count to reflect the total number of 
	 * free blocks that will exist after a successful resize.
	 */
	hfsmp->freeBlocks -= reclaimblks;
	updateFreeBlocks = true;
	HFS_MOUNT_UNLOCK(hfsmp, TRUE);	

	/*
	 * Look for files that have blocks at or beyond the location of the
	 * new alternate volume header
	 */
	if (hfs_isallocated(hfsmp, hfsmp->allocLimit, reclaimblks)) {
		/*
		 * hfs_reclaimspace will use separate transactions when
		 * relocating files (so we don't overwhelm the journal).
		 */
		hfs_end_transaction(hfsmp);
		transaction_begun = 0;

		/* Attempt to reclaim some space. */ 
		error = hfs_reclaimspace(hfsmp, hfsmp->allocLimit, reclaimblks, context);
		if (error != 0) {
			printf("hfs_truncatefs: couldn't reclaim space on %s (error=%d)\n", hfsmp->vcbVN, error);
			error = ENOSPC;
			goto out;
		}
		if (hfs_start_transaction(hfsmp) != 0) {
			error = EINVAL;
			goto out;
		}
		transaction_begun = 1;
		
		/* Check if we're clear now. */
		error = hfs_isallocated(hfsmp, hfsmp->allocLimit, reclaimblks);
		if (error != 0) {
			printf("hfs_truncatefs: didn't reclaim enough space on %s (error=%d)\n", hfsmp->vcbVN, error);
			error = EAGAIN;  /* tell client to try again */
			goto out;
		}
	}
	
	/*
	 * Note: we take the attributes lock in case we have an attribute data vnode
	 * which needs to change size.
	 */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE | SFL_EXTENTS | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);

	/*
	 * Mark the old alternate volume header as free. 
	 * We don't bother shrinking allocation bitmap file.
	 */
	if (hfsmp->blockSize == 512) 
		(void) BlockMarkFree(hfsmp, hfsmp->totalBlocks - 2, 2);
	else 
		(void) BlockMarkFree(hfsmp, hfsmp->totalBlocks - 1, 1);

	/*
	 * Allocate last 1KB for alternate volume header.
	 */
	error = BlockMarkAllocated(hfsmp, hfsmp->allocLimit, (hfsmp->blockSize == 512) ? 2 : 1);
	if (error) {
		printf("hfs_truncatefs: Error %d allocating new alternate volume header\n", error);
		goto out;
	}

	/*
	 * Invalidate the existing alternate volume header.
	 *
	 * Don't include this in a transaction (don't call journal_modify_block)
	 * since this block will be outside of the truncated file system!
	 */
	if (hfsmp->hfs_alt_id_sector) {
		error = buf_meta_bread(hfsmp->hfs_devvp, 
				HFS_PHYSBLK_ROUNDDOWN(hfsmp->hfs_alt_id_sector, hfsmp->hfs_log_per_phys),
				hfsmp->hfs_physical_block_size, NOCRED, &bp);
		if (error == 0) {
			bzero((void*)((char *)buf_dataptr(bp) + HFS_ALT_OFFSET(hfsmp->hfs_physical_block_size)), kMDBSize);
			(void) VNOP_BWRITE(bp);
		} else {
			if (bp) {
				buf_brelse(bp);
			}
		}
		bp = NULL;
	}

	/* Log successful shrinking. */
	printf("hfs_truncatefs: shrank \"%s\" to %d blocks (was %d blocks)\n",
	       hfsmp->vcbVN, newblkcnt, hfsmp->totalBlocks);

	/*
	 * Adjust file system variables and flush them to disk.
	 */
	hfsmp->totalBlocks = newblkcnt;
	hfsmp->hfs_logical_block_count = newsize / hfsmp->hfs_logical_block_size;
	hfsmp->hfs_alt_id_sector = HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size, hfsmp->hfs_logical_block_count);
	MarkVCBDirty(hfsmp);
	error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
	if (error)
		panic("hfs_truncatefs: unexpected error flushing volume header (%d)\n", error);
	
	/*
	 * TODO: Adjust the size of the metadata zone based on new volume size?
	 */
	
	/*
	 * Adjust the size of hfsmp->hfs_attrdata_vp
	 */
	if (hfsmp->hfs_attrdata_vp) {
		struct cnode *cp;
		struct filefork *fp;
		
		if (vnode_get(hfsmp->hfs_attrdata_vp) == 0) {
			cp = VTOC(hfsmp->hfs_attrdata_vp);
			fp = VTOF(hfsmp->hfs_attrdata_vp);
			
			cp->c_blocks = newblkcnt;
			fp->ff_blocks = newblkcnt;
			fp->ff_extents[0].blockCount = newblkcnt;
			fp->ff_size = (off_t) newblkcnt * hfsmp->blockSize;
			ubc_setsize(hfsmp->hfs_attrdata_vp, fp->ff_size);
			vnode_put(hfsmp->hfs_attrdata_vp);
		}
	}
	
out:
	lck_mtx_lock(&hfsmp->hfs_mutex);
	if (error && (updateFreeBlocks == true)) 
		hfsmp->freeBlocks += reclaimblks;
	hfsmp->allocLimit = hfsmp->totalBlocks;
	if (hfsmp->nextAllocation >= hfsmp->allocLimit)
		hfsmp->nextAllocation = hfsmp->hfs_metazone_end + 1;
	hfsmp->hfs_flags &= ~HFS_RESIZE_IN_PROGRESS;
	HFS_MOUNT_UNLOCK(hfsmp, TRUE);	
	
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (transaction_begun) {
		hfs_end_transaction(hfsmp);
		hfs_journal_flush(hfsmp);
		/* Just to be sure, sync all data to the disk */
		(void) VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, context);
	}

	return (error);
}


/*
 * Invalidate the physical block numbers associated with buffer cache blocks
 * in the given extent of the given vnode.
 */
struct hfs_inval_blk_no {
	daddr64_t sectorStart;
	daddr64_t sectorCount;
};
static int
hfs_invalidate_block_numbers_callback(buf_t bp, void *args_in)
{
	daddr64_t blkno;
	struct hfs_inval_blk_no *args;
	
	blkno = buf_blkno(bp);
	args = args_in;
	
	if (blkno >= args->sectorStart && blkno < args->sectorStart+args->sectorCount)
		buf_setblkno(bp, buf_lblkno(bp));

	return BUF_RETURNED;
}
static void
hfs_invalidate_sectors(struct vnode *vp, daddr64_t sectorStart, daddr64_t sectorCount)
{
	struct hfs_inval_blk_no args;
	args.sectorStart = sectorStart;
	args.sectorCount = sectorCount;
	
	buf_iterate(vp, hfs_invalidate_block_numbers_callback, BUF_SCAN_DIRTY|BUF_SCAN_CLEAN, &args);
}


/*
 * Copy the contents of an extent to a new location.  Also invalidates the
 * physical block number of any buffer cache block in the copied extent
 * (so that if the block is written, it will go through VNOP_BLOCKMAP to
 * determine the new physical block number).
 */
static int
hfs_copy_extent(
	struct hfsmount *hfsmp,
	struct vnode *vp,		/* The file whose extent is being copied. */
	u_int32_t oldStart,		/* The start of the source extent. */
	u_int32_t newStart,		/* The start of the destination extent. */
	u_int32_t blockCount,	/* The number of allocation blocks to copy. */
	vfs_context_t context)
{
	int err = 0;
	size_t bufferSize;
	void *buffer = NULL;
	struct vfsioattr ioattr;
	buf_t bp = NULL;
	off_t resid;
	size_t ioSize;
	u_int32_t ioSizeSectors;	/* Device sectors in this I/O */
	daddr64_t srcSector, destSector;
	u_int32_t sectorsPerBlock = hfsmp->blockSize / hfsmp->hfs_logical_block_size;

	/*
	 * Sanity check that we have locked the vnode of the file we're copying.
	 *
	 * But since hfs_systemfile_lock() doesn't actually take the lock on
	 * the allocation file if a journal is active, ignore the check if the
	 * file being copied is the allocation file.
	 */
	struct cnode *cp = VTOC(vp);
	if (cp != hfsmp->hfs_allocation_cp && cp->c_lockowner != current_thread())
		panic("hfs_copy_extent: vp=%p (cp=%p) not owned?\n", vp, cp);

	/*
	 * Determine the I/O size to use
	 *
	 * NOTE: Many external drives will result in an ioSize of 128KB.
	 * TODO: Should we use a larger buffer, doing several consecutive
	 * reads, then several consecutive writes?
	 */
	vfs_ioattr(hfsmp->hfs_mp, &ioattr);
	bufferSize = MIN(ioattr.io_maxreadcnt, ioattr.io_maxwritecnt);
	if (kmem_alloc(kernel_map, (vm_offset_t*) &buffer, bufferSize))
		return ENOMEM;

	/* Get a buffer for doing the I/O */
	bp = buf_alloc(hfsmp->hfs_devvp);
	buf_setdataptr(bp, (uintptr_t)buffer);
	
	resid = (off_t) blockCount * (off_t) hfsmp->blockSize;
	srcSector = (daddr64_t) oldStart * hfsmp->blockSize / hfsmp->hfs_logical_block_size;
	destSector = (daddr64_t) newStart * hfsmp->blockSize / hfsmp->hfs_logical_block_size;
	while (resid > 0) {
		ioSize = MIN(bufferSize, (size_t) resid);
		ioSizeSectors = ioSize / hfsmp->hfs_logical_block_size;
		
		/* Prepare the buffer for reading */
		buf_reset(bp, B_READ);
		buf_setsize(bp, ioSize);
		buf_setcount(bp, ioSize);
		buf_setblkno(bp, srcSector);
		buf_setlblkno(bp, srcSector);
		
		/* Do the read */
		err = VNOP_STRATEGY(bp);
		if (!err)
			err = buf_biowait(bp);
		if (err) {
			printf("hfs_copy_extent: Error %d from VNOP_STRATEGY (read)\n", err);
			break;
		}
		
		/* Prepare the buffer for writing */
		buf_reset(bp, B_WRITE);
		buf_setsize(bp, ioSize);
		buf_setcount(bp, ioSize);
		buf_setblkno(bp, destSector);
		buf_setlblkno(bp, destSector);
		if (vnode_issystem(vp) && journal_uses_fua(hfsmp->jnl))
			buf_markfua(bp);
			
		/* Do the write */
		vnode_startwrite(hfsmp->hfs_devvp);
		err = VNOP_STRATEGY(bp);
		if (!err)
			err = buf_biowait(bp);
		if (err) {
			printf("hfs_copy_extent: Error %d from VNOP_STRATEGY (write)\n", err);
			break;
		}
		
		resid -= ioSize;
		srcSector += ioSizeSectors;
		destSector += ioSizeSectors;
	}
	if (bp)
		buf_free(bp);
	if (buffer)
		kmem_free(kernel_map, (vm_offset_t)buffer, bufferSize);

	/* Make sure all writes have been flushed to disk. */
	if (vnode_issystem(vp) && !journal_uses_fua(hfsmp->jnl)) {
		err = VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, context);
		if (err) {
			printf("hfs_copy_extent: DKIOCSYNCHRONIZECACHE failed (%d)\n", err);
			err = 0;	/* Don't fail the copy. */
		}
	}

	if (!err)
		hfs_invalidate_sectors(vp, (daddr64_t)oldStart*sectorsPerBlock, (daddr64_t)blockCount*sectorsPerBlock);

	return err;
}


static int
hfs_relocate_callback(__unused HFSPlusExtentKey *key, HFSPlusExtentRecord *record, HFSPlusExtentRecord *state)
{
	bcopy(state, record, sizeof(HFSPlusExtentRecord));
	return 0;
}

/*
 * Reclaim space at the end of a volume, used by a given file.
 *
 * This routine attempts to move any extent which contains allocation blocks
 * at or after "startblk."  A separate transaction is used to do the move.
 * The contents of any moved extents are read and written via the volume's
 * device vnode -- NOT via "vp."  During the move, moved blocks which are part
 * of a transaction have their physical block numbers invalidated so they will
 * eventually be written to their new locations.
 *
 * Inputs:
 *    hfsmp       The volume being resized.
 *    startblk    Blocks >= this allocation block need to be moved.
 *    locks       Which locks need to be taken for the given system file.
 *    vp          The vnode for the system file.
 *
 *    The caller of this function, hfs_reclaimspace(), grabs cnode lock 
 *    for non-system files before calling this function.  
 *
 * Outputs:
 *    blks_moved  Total number of allocation blocks moved by this routine.
 */
static int
hfs_reclaim_file(struct hfsmount *hfsmp, struct vnode *vp, u_long startblk, int locks, u_int32_t *blks_moved, vfs_context_t context)
{
	int error;
	int lockflags;
	int i;
	u_long datablks;
	u_long end_block;
	u_int32_t oldStartBlock;
	u_int32_t newStartBlock;
	u_int32_t oldBlockCount;
	u_int32_t newBlockCount;
	struct filefork *fp;
	struct cnode *cp;
	int is_sysfile;
	int took_truncate_lock = 0;
	struct BTreeIterator *iterator = NULL;
	u_int8_t forktype;
	u_int32_t fileID;
		
	/* If there is no vnode for this file, then there's nothing to do. */	
	if (vp == NULL)
		return 0;

	cp = VTOC(vp);
	fileID = cp->c_cnid;
	is_sysfile = vnode_issystem(vp);
	forktype = VNODE_IS_RSRC(vp) ? 0xFF : 0;

	/* Flush all the buffer cache blocks and cluster pages associated with 
	 * this vnode.  
	 *
	 * If the current vnode is a system vnode, all the buffer cache blocks 
	 * associated with it should already be sync'ed to the disk as part of 
	 * journal flush in hfs_truncatefs().  Normally there should not be 
	 * buffer cache blocks for regular files, but for objects like symlinks,
	 * we can have buffer cache blocks associated with the vnode.  Therefore
	 * we call buf_flushdirtyblks() always.  Resource fork data for directory 
	 * hard links are directly written using buffer cache for device vnode, 
	 * which should also be sync'ed as part of journal flush in hfs_truncatefs().
	 * 
	 * Flushing cluster pages should be the normal case for regular files, 
	 * and really should not do anything for system files.  But just to be 
	 * sure that all blocks associated with this vnode is sync'ed to the 
	 * disk, we call both buffer cache and cluster layer functions.  
	 */
	buf_flushdirtyblks(vp, MNT_NOWAIT, 0, "hfs_reclaim_file");
	
	if (!is_sysfile) {
		/* The caller grabs cnode lock for non-system files only, therefore 
		 * we unlock only non-system files before calling cluster layer.
		 */
		hfs_unlock(cp);
		hfs_lock_truncate(cp, TRUE);
		took_truncate_lock = 1;
	}
	(void) cluster_push(vp, 0);
	if (!is_sysfile) {
		error = hfs_lock(cp, HFS_FORCE_LOCK);
		if (error) {
			hfs_unlock_truncate(cp, TRUE);
			return error;
		}

		/* If the file no longer exists, nothing left to do */
		if (cp->c_flag & C_NOEXISTS) {
			hfs_unlock_truncate(cp, TRUE);
			return 0;
		}
	}

	/* Wait for any in-progress writes to this vnode to complete, so that we'll
	 * be copying consistent bits.  (Otherwise, it's possible that an async
	 * write will complete to the old extent after we read from it.  That
	 * could lead to corruption.)
	 */
	error = vnode_waitforwrites(vp, 0, 0, 0, "hfs_reclaim_file");
	if (error) {
		printf("hfs_reclaim_file: Error %d from vnode_waitforwrites\n", error);
		return error;
	}

	if (hfs_resize_debug) {
		printf("hfs_reclaim_file: Start relocating %sfork for fileid=%u name=%.*s\n", (forktype ? "rsrc" : "data"), fileID, cp->c_desc.cd_namelen, cp->c_desc.cd_nameptr);
	}

	/* We always need the allocation bitmap and extents B-tree */
	locks |= SFL_BITMAP | SFL_EXTENTS;
	
	error = hfs_start_transaction(hfsmp);
	if (error) {
		printf("hfs_reclaim_file: hfs_start_transaction returned %d\n", error);
		if (took_truncate_lock) {
			hfs_unlock_truncate(cp, TRUE);
		}
		return error;
	}
	lockflags = hfs_systemfile_lock(hfsmp, locks, HFS_EXCLUSIVE_LOCK);
	fp = VTOF(vp);
	datablks = 0;
	*blks_moved = 0;

	/* Relocate non-overflow extents */
	for (i = 0; i < kHFSPlusExtentDensity; ++i) {
		if (fp->ff_extents[i].blockCount == 0)
			break;
		oldStartBlock = fp->ff_extents[i].startBlock;
		oldBlockCount = fp->ff_extents[i].blockCount;
		datablks += oldBlockCount;
		end_block = oldStartBlock + oldBlockCount;
		/* Check if the file overlaps the target space */
		if (end_block > startblk) {
			/* Allocate a new extent */
			error = BlockAllocate(hfsmp, 1, oldBlockCount, oldBlockCount, true, (is_sysfile ? true : false), &newStartBlock, &newBlockCount);
			if (error) {
				printf("hfs_reclaim_file: BlockAllocate (error=%d) for fileID=%u %u:(%u,%u)\n", error, fileID, i, oldStartBlock, oldBlockCount);
				goto fail;
			}
			if (newBlockCount != oldBlockCount) {
				printf("hfs_reclaim_file: fileID=%u - newBlockCount=%u, oldBlockCount=%u", fileID, newBlockCount, oldBlockCount);
				if (BlockDeallocate(hfsmp, newStartBlock, newBlockCount)) {
					hfs_mark_volume_inconsistent(hfsmp);
				}
				goto fail;
			}

			/* Copy data from old location to new location */
			error = hfs_copy_extent(hfsmp, vp, oldStartBlock, newStartBlock, newBlockCount, context);
			if (error) {
				printf("hfs_reclaim_file: hfs_copy_extent error=%d for fileID=%u %u:(%u,%u) to %u:(%u,%u)\n", error, fileID, i, oldStartBlock, oldBlockCount, i, newStartBlock, newBlockCount);
				if (BlockDeallocate(hfsmp, newStartBlock, newBlockCount)) {
					hfs_mark_volume_inconsistent(hfsmp);
				}
				goto fail;
			}
			fp->ff_extents[i].startBlock = newStartBlock;
			cp->c_flag |= C_MODIFIED;
			*blks_moved += newBlockCount;

			/* Deallocate the old extent */
			error = BlockDeallocate(hfsmp, oldStartBlock, oldBlockCount);
			if (error) {
				printf("hfs_reclaim_file: BlockDeallocate returned %d\n", error);
				hfs_mark_volume_inconsistent(hfsmp);
				goto fail;
			}

			/* If this is a system file, sync the volume header on disk */
			if (is_sysfile) {
				error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
				if (error) {
					printf("hfs_reclaim_file: hfs_flushvolumeheader returned %d\n", error);
					hfs_mark_volume_inconsistent(hfsmp);
					goto fail;
				}
			}

			if (hfs_resize_debug) {
				printf ("hfs_reclaim_file: Relocated %u:(%u,%u) to %u:(%u,%u)\n", i, oldStartBlock, oldBlockCount, i, newStartBlock, newBlockCount);
			}
		}
	}

	/* Relocate overflow extents (if any) */
	if (i == kHFSPlusExtentDensity && fp->ff_blocks > datablks) {
		struct FSBufferDescriptor btdata;
		HFSPlusExtentRecord record;
		HFSPlusExtentKey *key;
		FCB *fcb;
		int overflow_count = 0;

		if (kmem_alloc(kernel_map, (vm_offset_t*) &iterator, sizeof(*iterator))) {
			printf("hfs_reclaim_file: kmem_alloc failed!\n");
			error = ENOMEM;
			goto fail;
		}

		bzero(iterator, sizeof(*iterator));
		key = (HFSPlusExtentKey *) &iterator->key;
		key->keyLength = kHFSPlusExtentKeyMaximumLength;
		key->forkType = forktype;
		key->fileID = fileID;
		key->startBlock = datablks;
	
		btdata.bufferAddress = &record;
		btdata.itemSize = sizeof(record);
		btdata.itemCount = 1;
	
		fcb = VTOF(hfsmp->hfs_extents_vp);

		error = BTSearchRecord(fcb, iterator, &btdata, NULL, iterator);
		while (error == 0) {
			/* Stop when we encounter a different file or fork. */
			if ((key->fileID != fileID) || 
			    (key->forkType != forktype)) {
				break;
			}
		
			/* Just track the overflow extent record number for debugging... */
			if (hfs_resize_debug) {
				overflow_count++;
			}

			/* 
			 * Check if the file overlaps target space.
			 */
			for (i = 0; i < kHFSPlusExtentDensity; ++i) {
				if (record[i].blockCount == 0) {
					goto fail;
				}
				oldStartBlock = record[i].startBlock;
				oldBlockCount = record[i].blockCount;
				end_block = oldStartBlock + oldBlockCount;
				if (end_block > startblk) {
					error = BlockAllocate(hfsmp, 1, oldBlockCount, oldBlockCount, true, (is_sysfile ? true : false), &newStartBlock, &newBlockCount);
					if (error) {
						printf("hfs_reclaim_file: BlockAllocate (error=%d) for fileID=%u %u:(%u,%u)\n", error, fileID, i, oldStartBlock, oldBlockCount);
						goto fail;
					}
					if (newBlockCount != oldBlockCount) {
						printf("hfs_reclaim_file: fileID=%u - newBlockCount=%u, oldBlockCount=%u", fileID, newBlockCount, oldBlockCount);
						if (BlockDeallocate(hfsmp, newStartBlock, newBlockCount)) {
							hfs_mark_volume_inconsistent(hfsmp);
						}
						goto fail;
					}
					error = hfs_copy_extent(hfsmp, vp, oldStartBlock, newStartBlock, newBlockCount, context);
					if (error) {
						printf("hfs_reclaim_file: hfs_copy_extent error=%d for fileID=%u (%u,%u) to (%u,%u)\n", error, fileID, oldStartBlock, oldBlockCount, newStartBlock, newBlockCount);
						if (BlockDeallocate(hfsmp, newStartBlock, newBlockCount)) {
							hfs_mark_volume_inconsistent(hfsmp);
						}
						goto fail;
					}
					record[i].startBlock = newStartBlock;
					cp->c_flag |= C_MODIFIED;
					*blks_moved += newBlockCount;

					/*
					 * NOTE: To support relocating overflow extents of the
					 * allocation file, we must update the BTree record BEFORE
					 * deallocating the old extent so that BlockDeallocate will
					 * use the extent's new location to calculate physical block
					 * numbers.  (This is for the case where the old extent's
					 * bitmap bits actually reside in the extent being moved.)
					 */
					error = BTUpdateRecord(fcb, iterator, (IterateCallBackProcPtr) hfs_relocate_callback, &record);
					if (error) {
						printf("hfs_reclaim_file: BTUpdateRecord returned %d\n", error);
						hfs_mark_volume_inconsistent(hfsmp);
						goto fail;
					}
					error = BlockDeallocate(hfsmp, oldStartBlock, oldBlockCount);
					if (error) {
						printf("hfs_reclaim_file: BlockDeallocate returned %d\n", error);
						hfs_mark_volume_inconsistent(hfsmp);
						goto fail;
					}
					if (hfs_resize_debug) {
						printf ("hfs_reclaim_file: Relocated overflow#%d %u:(%u,%u) to %u:(%u,%u)\n", overflow_count, i, oldStartBlock, oldBlockCount, i, newStartBlock, newBlockCount);
					}
				}
			}
			/* Look for more records. */
			error = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
			if (error == btNotFound) {
				error = 0;
				break;
			}
		}
	}
	
fail:
	if (iterator) {
		kmem_free(kernel_map, (vm_offset_t)iterator, sizeof(*iterator));
	}

	(void) hfs_systemfile_unlock(hfsmp, lockflags);

	if ((*blks_moved != 0) && (is_sysfile == false)) {
		(void) hfs_update(vp, MNT_WAIT);
	}

	(void) hfs_end_transaction(hfsmp);

	if (took_truncate_lock) {
		hfs_unlock_truncate(cp, TRUE);
	}

	if (hfs_resize_debug) {
		printf("hfs_reclaim_file: Finished relocating %sfork for fileid=%u (error=%d)\n", (forktype ? "rsrc" : "data"), fileID, error);
	}

	return error;
}


/*
 * This journal_relocate callback updates the journal info block to point
 * at the new journal location.  This write must NOT be done using the
 * transaction.  We must write the block immediately.  We must also force
 * it to get to the media so that the new journal location will be seen by
 * the replay code before we can safely let journaled blocks be written
 * to their normal locations.
 *
 * The tests for journal_uses_fua below are mildly hacky.  Since the journal
 * and the file system are both on the same device, I'm leveraging what
 * the journal has decided about FUA.
 */
struct hfs_journal_relocate_args {
	struct hfsmount *hfsmp;
	vfs_context_t context;
	u_int32_t newStartBlock;
};

static errno_t
hfs_journal_relocate_callback(void *_args)
{
	int error;
	struct hfs_journal_relocate_args *args = _args;
	struct hfsmount *hfsmp = args->hfsmp;
	buf_t bp;
	JournalInfoBlock *jibp;

	error = buf_meta_bread(hfsmp->hfs_devvp,
		hfsmp->vcbJinfoBlock * (hfsmp->blockSize/hfsmp->hfs_logical_block_size),
		hfsmp->blockSize, vfs_context_ucred(args->context), &bp);
	if (error) {
		printf("hfs_reclaim_journal_file: failed to read JIB (%d)\n", error);
		return error;
	}
	jibp = (JournalInfoBlock*) buf_dataptr(bp);
	jibp->offset = SWAP_BE64((u_int64_t)args->newStartBlock * hfsmp->blockSize);
	jibp->size = SWAP_BE64(hfsmp->jnl_size);
	if (journal_uses_fua(hfsmp->jnl))
		buf_markfua(bp);
	error = buf_bwrite(bp);
	if (error) {
		printf("hfs_reclaim_journal_file: failed to write JIB (%d)\n", error);
		return error;
	}
	if (!journal_uses_fua(hfsmp->jnl)) {
		error = VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, args->context);
		if (error) {
			printf("hfs_reclaim_journal_file: DKIOCSYNCHRONIZECACHE failed (%d)\n", error);
			error = 0;		/* Don't fail the operation. */
		}
	}

	return error;
}


static int
hfs_reclaim_journal_file(struct hfsmount *hfsmp, vfs_context_t context)
{
	int error;
	int lockflags;
	u_int32_t oldStartBlock;
	u_int32_t newStartBlock;
	u_int32_t oldBlockCount;
	u_int32_t newBlockCount;
	struct cat_desc journal_desc;
	struct cat_attr journal_attr;
	struct cat_fork journal_fork;
	struct hfs_journal_relocate_args callback_args;

	error = hfs_start_transaction(hfsmp);
	if (error) {
		printf("hfs_reclaim_journal_file: hfs_start_transaction returned %d\n", error);
		return error;
	}
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	
	oldBlockCount = hfsmp->jnl_size / hfsmp->blockSize;
	
	/* TODO: Allow the journal to change size based on the new volume size. */
	error = BlockAllocate(hfsmp, 1, oldBlockCount, oldBlockCount, true, true, &newStartBlock, &newBlockCount);
	if (error) {
		printf("hfs_reclaim_journal_file: BlockAllocate returned %d\n", error);
		goto fail;
	}
	if (newBlockCount != oldBlockCount) {
		printf("hfs_reclaim_journal_file: newBlockCount != oldBlockCount (%u, %u)\n", newBlockCount, oldBlockCount);
		goto free_fail;
	}
	
	error = BlockDeallocate(hfsmp, hfsmp->jnl_start, oldBlockCount);
	if (error) {
		printf("hfs_reclaim_journal_file: BlockDeallocate returned %d\n", error);
		goto free_fail;
	}

	/* Update the catalog record for .journal */
	error = cat_idlookup(hfsmp, hfsmp->hfs_jnlfileid, 1, &journal_desc, &journal_attr, &journal_fork);
	if (error) {
		printf("hfs_reclaim_journal_file: cat_idlookup returned %d\n", error);
		goto free_fail;
	}
	oldStartBlock = journal_fork.cf_extents[0].startBlock;
	journal_fork.cf_size = newBlockCount * hfsmp->blockSize;
	journal_fork.cf_extents[0].startBlock = newStartBlock;
	journal_fork.cf_extents[0].blockCount = newBlockCount;
	journal_fork.cf_blocks = newBlockCount;
	error = cat_update(hfsmp, &journal_desc, &journal_attr, &journal_fork, NULL);
	cat_releasedesc(&journal_desc);  /* all done with cat descriptor */
	if (error) {
		printf("hfs_reclaim_journal_file: cat_update returned %d\n", error);
		goto free_fail;
	}
	callback_args.hfsmp = hfsmp;
	callback_args.context = context;
	callback_args.newStartBlock = newStartBlock;
	
	error = journal_relocate(hfsmp->jnl, (off_t)newStartBlock*hfsmp->blockSize,
		(off_t)newBlockCount*hfsmp->blockSize, 0,
		hfs_journal_relocate_callback, &callback_args);
	if (error) {
		/* NOTE: journal_relocate will mark the journal invalid. */
		printf("hfs_reclaim_journal_file: journal_relocate returned %d\n", error);
		goto fail;
	}
	hfsmp->jnl_start = newStartBlock;
	hfsmp->jnl_size = (off_t)newBlockCount * hfsmp->blockSize;

	hfs_systemfile_unlock(hfsmp, lockflags);
	error = hfs_end_transaction(hfsmp);
	if (error) {
		printf("hfs_reclaim_journal_file: hfs_end_transaction returned %d\n", error);
	}
	
	if (!error && hfs_resize_debug) {
		printf ("hfs_reclaim_journal_file: Successfully relocated journal from (%u,%u) to (%u,%u)\n", oldStartBlock, oldBlockCount, newStartBlock, newBlockCount);
	}
	return error;

free_fail:
	(void) BlockDeallocate(hfsmp, newStartBlock, newBlockCount);
fail:
	hfs_systemfile_unlock(hfsmp, lockflags);
	(void) hfs_end_transaction(hfsmp);
	if (hfs_resize_debug) {
		printf ("hfs_reclaim_journal_file: Error relocating journal file (error=%d)\n", error);
	}
	return error;
}


/*
 * Move the journal info block to a new location.  We have to make sure the
 * new copy of the journal info block gets to the media first, then change
 * the field in the volume header and the catalog record.
 */
static int
hfs_reclaim_journal_info_block(struct hfsmount *hfsmp, vfs_context_t context)
{
	int error;
	int lockflags;
	u_int32_t oldBlock;
	u_int32_t newBlock;
	u_int32_t blockCount;
	struct cat_desc jib_desc;
	struct cat_attr jib_attr;
	struct cat_fork jib_fork;
	buf_t old_bp, new_bp;
	
	error = hfs_start_transaction(hfsmp);
	if (error) {
		printf("hfs_reclaim_journal_info_block: hfs_start_transaction returned %d\n", error);
		return error;
	}
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	
	error = BlockAllocate(hfsmp, 1, 1, 1, true, true, &newBlock, &blockCount);
	if (error) {
		printf("hfs_reclaim_journal_info_block: BlockAllocate returned %d\n", error);
		goto fail;
	}
	if (blockCount != 1) {
		printf("hfs_reclaim_journal_info_block: blockCount != 1 (%u)\n", blockCount);
		goto free_fail;
	}
	error = BlockDeallocate(hfsmp, hfsmp->vcbJinfoBlock, 1);
	if (error) {
		printf("hfs_reclaim_journal_info_block: BlockDeallocate returned %d\n", error);
		goto free_fail;
	}
	
	/* Copy the old journal info block content to the new location */
	error = buf_meta_bread(hfsmp->hfs_devvp,
		hfsmp->vcbJinfoBlock * (hfsmp->blockSize/hfsmp->hfs_logical_block_size),
		hfsmp->blockSize, vfs_context_ucred(context), &old_bp);
	if (error) {
		printf("hfs_reclaim_journal_info_block: failed to read JIB (%d)\n", error);
		goto free_fail;
	}
	new_bp = buf_getblk(hfsmp->hfs_devvp,
		newBlock * (hfsmp->blockSize/hfsmp->hfs_logical_block_size),
		hfsmp->blockSize, 0, 0, BLK_META);
	bcopy((char*)buf_dataptr(old_bp), (char*)buf_dataptr(new_bp), hfsmp->blockSize);
	buf_brelse(old_bp);
	if (journal_uses_fua(hfsmp->jnl))
		buf_markfua(new_bp);
	error = buf_bwrite(new_bp);
	if (error) {
		printf("hfs_reclaim_journal_info_block: failed to write new JIB (%d)\n", error);
		goto free_fail;
	}
	if (!journal_uses_fua(hfsmp->jnl)) {
		error = VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, context);
		if (error) {
			printf("hfs_reclaim_journal_info_block: DKIOCSYNCHRONIZECACHE failed (%d)\n", error);
			/* Don't fail the operation. */
		}
	}
	
	/* Update the catalog record for .journal_info_block */
	error = cat_idlookup(hfsmp, hfsmp->hfs_jnlinfoblkid, 1, &jib_desc, &jib_attr, &jib_fork);
	if (error) {
		printf("hfs_reclaim_journal_file: cat_idlookup returned %d\n", error);
		goto fail;
	}
	oldBlock = jib_fork.cf_extents[0].startBlock;
	jib_fork.cf_size = hfsmp->blockSize;
	jib_fork.cf_extents[0].startBlock = newBlock;
	jib_fork.cf_extents[0].blockCount = 1;
	jib_fork.cf_blocks = 1;
	error = cat_update(hfsmp, &jib_desc, &jib_attr, &jib_fork, NULL);
	cat_releasedesc(&jib_desc);  /* all done with cat descriptor */
	if (error) {
		printf("hfs_reclaim_journal_info_block: cat_update returned %d\n", error);
		goto fail;
	}
	
	/* Update the pointer to the journal info block in the volume header. */
	hfsmp->vcbJinfoBlock = newBlock;
	error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
	if (error) {
		printf("hfs_reclaim_journal_info_block: hfs_flushvolumeheader returned %d\n", error);
		goto fail;
	}
	hfs_systemfile_unlock(hfsmp, lockflags);
	error = hfs_end_transaction(hfsmp);
	if (error) {
		printf("hfs_reclaim_journal_info_block: hfs_end_transaction returned %d\n", error);
	}
	error = hfs_journal_flush(hfsmp);
	if (error) {
		printf("hfs_reclaim_journal_info_block: journal_flush returned %d\n", error);
	}

	if (!error && hfs_resize_debug) {
		printf ("hfs_reclaim_journal_info_block: Successfully relocated journal info block from (%u,%u) to (%u,%u)\n", oldBlock, blockCount, newBlock, blockCount);
	}
	return error;

free_fail:
	(void) BlockDeallocate(hfsmp, newBlock, blockCount);
fail:
	hfs_systemfile_unlock(hfsmp, lockflags);
	(void) hfs_end_transaction(hfsmp);
	if (hfs_resize_debug) {
		printf ("hfs_reclaim_journal_info_block: Error relocating journal info block (error=%d)\n", error);
	}
	return error;
}


/*
 * Reclaim space at the end of a file system.
 *
 * Inputs - 
 * 	startblk 	- start block of the space being reclaimed
 * 	reclaimblks 	- number of allocation blocks to reclaim
 */
static int
hfs_reclaimspace(struct hfsmount *hfsmp, u_int32_t startblk, u_int32_t reclaimblks, vfs_context_t context)
{
	struct vnode *vp = NULL;
	FCB *fcb;
	struct BTreeIterator * iterator = NULL;
	struct FSBufferDescriptor btdata;
	struct HFSPlusCatalogFile filerec;
	u_int32_t  saved_next_allocation;
	cnid_t * cnidbufp;
	size_t cnidbufsize;
	int filecnt = 0;
	int maxfilecnt;
	u_int32_t block;
	int lockflags;
	int i, j;
	int error;
	int lastprogress = 0;
	u_int32_t blks_moved = 0;
	u_int32_t total_blks_moved = 0;
	Boolean need_relocate;

	/* Relocate extents of the Allocation file if they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_allocation_vp, startblk, SFL_BITMAP, &blks_moved, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim allocation file returned %d\n", error);
		return error;
	}
	total_blks_moved += blks_moved;

	/* Relocate extents of the Extents B-tree if they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_extents_vp, startblk, SFL_EXTENTS, &blks_moved, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim extents b-tree returned %d\n", error);
		return error;
	}
	total_blks_moved += blks_moved;

	/* Relocate extents of the Catalog B-tree if they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_catalog_vp, startblk, SFL_CATALOG, &blks_moved, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim catalog b-tree returned %d\n", error);
		return error;
	}
	total_blks_moved += blks_moved;

	/* Relocate extents of the Attributes B-tree if they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_attribute_vp, startblk, SFL_ATTRIBUTE, &blks_moved, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim attribute b-tree returned %d\n", error);
		return error;
	}
	total_blks_moved += blks_moved;

	/* Relocate extents of the Startup File if there is one and they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_startup_vp, startblk, SFL_STARTUP, &blks_moved, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim startup file returned %d\n", error);
		return error;
	}
	total_blks_moved += blks_moved;
	
	/*
	 * We need to make sure the alternate volume header gets flushed if we moved
	 * any extents in the volume header.  But we need to do that before
	 * shrinking the size of the volume, or else the journal code will panic
	 * with an invalid (too large) block number.
	 *
	 * Note that total_blks_moved will be set if ANY extent was moved, even
	 * if it was just an overflow extent.  In this case, the journal_flush isn't
	 * strictly required, but shouldn't hurt.
	 */
	if (total_blks_moved) {
		hfs_journal_flush(hfsmp);
	}

	if (hfsmp->jnl_start + (hfsmp->jnl_size / hfsmp->blockSize) > startblk) {
		error = hfs_reclaim_journal_file(hfsmp, context);
		if (error) {
			printf("hfs_reclaimspace: hfs_reclaim_journal_file failed (%d)\n", error);
			return error;
		}
	}
	
	if (hfsmp->vcbJinfoBlock >= startblk) {
		error = hfs_reclaim_journal_info_block(hfsmp, context);
		if (error) {
			printf("hfs_reclaimspace: hfs_reclaim_journal_info_block failed (%d)\n", error);
			return error;
		}
	}
	
	/* For now move a maximum of 250,000 files. */
	maxfilecnt = MIN(hfsmp->hfs_filecount, 250000);
	maxfilecnt = MIN((u_int32_t)maxfilecnt, reclaimblks);
	cnidbufsize = maxfilecnt * sizeof(cnid_t);
	if (kmem_alloc(kernel_map, (vm_offset_t *)&cnidbufp, cnidbufsize)) {
		return (ENOMEM);
	}	
	if (kmem_alloc(kernel_map, (vm_offset_t *)&iterator, sizeof(*iterator))) {
		kmem_free(kernel_map, (vm_offset_t)cnidbufp, cnidbufsize);
		return (ENOMEM);
	}	

	saved_next_allocation = hfsmp->nextAllocation;
	/* Always try allocating new blocks after the metadata zone */
	HFS_UPDATE_NEXT_ALLOCATION(hfsmp, hfsmp->hfs_metazone_start);

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
	 * that overlap into the space we're trying to free up and 
	 * the total number of blocks that will require relocation.
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

		need_relocate = false;
		/* Check if data fork overlaps the target space */
		for (i = 0; i < kHFSPlusExtentDensity; ++i) {
			if (filerec.dataFork.extents[i].blockCount == 0) {
				break;
			}
			block = filerec.dataFork.extents[i].startBlock +
				filerec.dataFork.extents[i].blockCount;
			if (block >= startblk) {
				if ((filerec.fileID == hfsmp->hfs_jnlfileid) ||
				    (filerec.fileID == hfsmp->hfs_jnlinfoblkid)) {
					printf("hfs_reclaimspace: cannot move active journal\n");
					error = EPERM;
					goto end_iteration;
				}
				need_relocate = true;
				goto save_fileid;
			}
		}

		/* Check if resource fork overlaps the target space */
		for (j = 0; j < kHFSPlusExtentDensity; ++j) {
			if (filerec.resourceFork.extents[j].blockCount == 0) {
				break;
			}
			block = filerec.resourceFork.extents[j].startBlock +
				filerec.resourceFork.extents[j].blockCount;
			if (block >= startblk) {
				need_relocate = true;
				goto save_fileid;
			}
		}

		/* Check if any forks' overflow extents overlap the target space */
		if ((i == kHFSPlusExtentDensity) || (j == kHFSPlusExtentDensity)) {
			if (hfs_overlapped_overflow_extents(hfsmp, startblk, filerec.fileID)) {
				need_relocate = true;
				goto save_fileid;
			}
		}

save_fileid:
		if (need_relocate == true) {
			cnidbufp[filecnt++] = filerec.fileID;
			if (hfs_resize_debug) {
				printf ("hfs_reclaimspace: Will relocate extents for fileID=%u\n", filerec.fileID);
			}
		}
	}

end_iteration:
	/* If no regular file was found to be relocated and 
	 * no system file was moved, we probably do not have 
	 * enough space to relocate the system files, or 
	 * something else went wrong.
	 */
	if ((filecnt == 0) && (total_blks_moved == 0)) {
		printf("hfs_reclaimspace: no files moved\n");
		error = ENOSPC;
	}
	/* All done with catalog. */
	hfs_systemfile_unlock(hfsmp, lockflags);
	if (error || filecnt == 0)
		goto out;

	hfsmp->hfs_resize_filesmoved = 0;
	hfsmp->hfs_resize_totalfiles = filecnt;
	
	/* Now move any files that are in the way. */
	for (i = 0; i < filecnt; ++i) {
		struct vnode *rvp;
		struct cnode *cp;
		struct filefork *datafork;

		if (hfs_vget(hfsmp, cnidbufp[i], &vp, 0) != 0)
			continue;
		
		cp = VTOC(vp);
		datafork = VTOF(vp);

		/* Relocating directory hard links is not supported, so we punt (see radar 6217026). */
		if ((cp->c_flag & C_HARDLINK) && vnode_isdir(vp)) {
			printf("hfs_reclaimspace: Unable to relocate directory hard link id=%d\n", cp->c_cnid);
			error = EINVAL;
		       	goto out;
		}

		/* Relocate any overlapping data fork blocks. */
		if (datafork && datafork->ff_blocks > 0) {
			error = hfs_reclaim_file(hfsmp, vp, startblk, 0, &blks_moved, context);
			if (error)  {
				printf ("hfs_reclaimspace: Error reclaiming datafork blocks of fileid=%u (error=%d)\n", cnidbufp[i], error);
				break;
			}
			total_blks_moved += blks_moved;
		}

		/* Relocate any overlapping resource fork blocks. */
		if ((cp->c_blocks - (datafork ? datafork->ff_blocks : 0)) > 0) {
			error = hfs_vgetrsrc(hfsmp, vp, &rvp, TRUE, TRUE);
			if (error) {
				printf ("hfs_reclaimspace: Error looking up rvp for fileid=%u (error=%d)\n", cnidbufp[i], error);
				break;
			}
			error = hfs_reclaim_file(hfsmp, rvp, startblk, 0, &blks_moved, context);
			VTOC(rvp)->c_flag |= C_NEED_RVNODE_PUT;
			if (error) {
				printf ("hfs_reclaimspace: Error reclaiming rsrcfork blocks of fileid=%u (error=%d)\n", cnidbufp[i], error);
				break;
			}
			total_blks_moved += blks_moved;
		}
		hfs_unlock(cp);
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
		printf("hfs_reclaimspace: relocated %u blocks from %d files on \"%s\"\n",
			total_blks_moved, (int)hfsmp->hfs_resize_filesmoved, hfsmp->vcbVN);
	}
out:
	kmem_free(kernel_map, (vm_offset_t)iterator, sizeof(*iterator));
	kmem_free(kernel_map, (vm_offset_t)cnidbufp, cnidbufsize);

	/*
	 * Restore the roving allocation pointer on errors.
	 * (but only if we didn't move any files)
	 */
	if (error && hfsmp->hfs_resize_filesmoved == 0) {
		HFS_UPDATE_NEXT_ALLOCATION(hfsmp, saved_next_allocation);
	}
	return (error);
}


/*
 * Check if there are any overflow data or resource fork extents that overlap 
 * into the disk space that is being reclaimed.  
 *
 * Output - 
 * 	1 - One of the overflow extents need to be relocated
 * 	0 - No overflow extents need to be relocated, or there was an error
 */
static int
hfs_overlapped_overflow_extents(struct hfsmount *hfsmp, u_int32_t startblk, u_int32_t fileID)
{
	struct BTreeIterator * iterator = NULL;
	struct FSBufferDescriptor btdata;
	HFSPlusExtentRecord extrec;
	HFSPlusExtentKey *extkeyptr;
	FCB *fcb;
	int overlapped = 0;
	int i;
	int error;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&iterator, sizeof(*iterator))) {
		return 0;
	}	
	bzero(iterator, sizeof(*iterator));
	extkeyptr = (HFSPlusExtentKey *)&iterator->key;
	extkeyptr->keyLength = kHFSPlusExtentKeyMaximumLength;
	extkeyptr->forkType = 0;
	extkeyptr->fileID = fileID;
	extkeyptr->startBlock = 0;

	btdata.bufferAddress = &extrec;
	btdata.itemSize = sizeof(extrec);
	btdata.itemCount = 1;
	
	fcb = VTOF(hfsmp->hfs_extents_vp);

	/* This will position the iterator just before the first overflow 
	 * extent record for given fileID.  It will always return btNotFound, 
	 * so we special case the error code.
	 */
	error = BTSearchRecord(fcb, iterator, &btdata, NULL, iterator);
	if (error && (error != btNotFound)) {
		goto out;
	}

	/* BTIterateRecord() might return error if the btree is empty, and 
	 * therefore we return that the extent does not overflow to the caller
	 */
	error = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
	while (error == 0) {
		/* Stop when we encounter a different file. */
		if (extkeyptr->fileID != fileID) {
			break;
		}
		/* Check if any of the forks exist in the target space. */
		for (i = 0; i < kHFSPlusExtentDensity; ++i) {
			if (extrec[i].blockCount == 0) {
				break;
			}
			if ((extrec[i].startBlock + extrec[i].blockCount) >= startblk) {
				overlapped = 1;
				goto out;
			}
		}
		/* Look for more records. */
		error = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
	}

out:
	kmem_free(kernel_map, (vm_offset_t)iterator, sizeof(*iterator));
	return overlapped;
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
 * Creates a UUID from a unique "name" in the HFS UUID Name space.
 * See version 3 UUID.
 */
static void
hfs_getvoluuid(struct hfsmount *hfsmp, uuid_t result)
{
	MD5_CTX  md5c;
	uint8_t  rawUUID[8];

	((uint32_t *)rawUUID)[0] = hfsmp->vcbFndrInfo[6];
	((uint32_t *)rawUUID)[1] = hfsmp->vcbFndrInfo[7];

	MD5Init( &md5c );
	MD5Update( &md5c, HFS_UUID_NAMESPACE_ID, sizeof( uuid_t ) );
	MD5Update( &md5c, rawUUID, sizeof (rawUUID) );
	MD5Final( result, &md5c );

	result[6] = 0x30 | ( result[6] & 0x0F );
	result[8] = 0x80 | ( result[8] & 0x3F );
}

/*
 * Get file system attributes.
 */
static int
hfs_vfs_getattr(struct mount *mp, struct vfs_attr *fsap, __unused vfs_context_t context)
{
#define HFS_ATTR_CMN_VALIDMASK (ATTR_CMN_VALIDMASK & ~(ATTR_CMN_NAMEDATTRCOUNT | ATTR_CMN_NAMEDATTRLIST))
#define HFS_ATTR_FILE_VALIDMASK (ATTR_FILE_VALIDMASK & ~(ATTR_FILE_FILETYPE | ATTR_FILE_FORKCOUNT | ATTR_FILE_FORKLIST))

	ExtendedVCB *vcb = VFSTOVCB(mp);
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	u_int32_t freeCNIDs;

	freeCNIDs = (u_int32_t)0xFFFFFFFF - (u_int32_t)hfsmp->vcbNxtCNID;

	VFSATTR_RETURN(fsap, f_objcount, (u_int64_t)hfsmp->vcbFilCnt + (u_int64_t)hfsmp->vcbDirCnt);
	VFSATTR_RETURN(fsap, f_filecount, (u_int64_t)hfsmp->vcbFilCnt);
	VFSATTR_RETURN(fsap, f_dircount, (u_int64_t)hfsmp->vcbDirCnt);
	VFSATTR_RETURN(fsap, f_maxobjcount, (u_int64_t)0xFFFFFFFF);
	VFSATTR_RETURN(fsap, f_iosize, (size_t)cluster_max_io_size(mp, 0));
	VFSATTR_RETURN(fsap, f_blocks, (u_int64_t)hfsmp->totalBlocks);
	VFSATTR_RETURN(fsap, f_bfree, (u_int64_t)hfs_freeblks(hfsmp, 0));
	VFSATTR_RETURN(fsap, f_bavail, (u_int64_t)hfs_freeblks(hfsmp, 1));
	VFSATTR_RETURN(fsap, f_bsize, (u_int32_t)vcb->blockSize);
	/* XXX needs clarification */
	VFSATTR_RETURN(fsap, f_bused, hfsmp->totalBlocks - hfs_freeblks(hfsmp, 1));
	/* Maximum files is constrained by total blocks. */
	VFSATTR_RETURN(fsap, f_files, (u_int64_t)(hfsmp->totalBlocks - 2));
	VFSATTR_RETURN(fsap, f_ffree, MIN((u_int64_t)freeCNIDs, (u_int64_t)hfs_freeblks(hfsmp, 1)));

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
				VOL_CAP_FMT_FAST_STATFS |
				VOL_CAP_FMT_HIDDEN_FILES |
				VOL_CAP_FMT_PATH_FROM_ID;
		} else {
			cap->capabilities[VOL_CAPABILITIES_FORMAT] =
				VOL_CAP_FMT_PERSISTENTOBJECTIDS |
				VOL_CAP_FMT_SYMBOLICLINKS |
				VOL_CAP_FMT_HARDLINKS |
				VOL_CAP_FMT_JOURNAL |
				VOL_CAP_FMT_ZERO_RUNS |
				(hfsmp->jnl ? VOL_CAP_FMT_JOURNAL_ACTIVE : 0) |
				(hfsmp->hfs_flags & HFS_CASE_SENSITIVE ? VOL_CAP_FMT_CASE_SENSITIVE : 0) |
				VOL_CAP_FMT_CASE_PRESERVING |
				VOL_CAP_FMT_FAST_STATFS | 
				VOL_CAP_FMT_2TB_FILESIZE |
				VOL_CAP_FMT_HIDDEN_FILES |
#if HFS_COMPRESSION
				VOL_CAP_FMT_PATH_FROM_ID |
				VOL_CAP_FMT_DECMPFS_COMPRESSION;
#else
				VOL_CAP_FMT_PATH_FROM_ID;
#endif
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
			VOL_CAP_INT_FLOCK |
#if NAMEDSTREAMS
			VOL_CAP_INT_EXTENDED_ATTR |
			VOL_CAP_INT_NAMEDSTREAMS;
#else
			VOL_CAP_INT_EXTENDED_ATTR;
#endif
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
			VOL_CAP_FMT_2TB_FILESIZE |
			VOL_CAP_FMT_OPENDENYMODES |
			VOL_CAP_FMT_HIDDEN_FILES |
#if HFS_COMPRESSION
			VOL_CAP_FMT_PATH_FROM_ID |
			VOL_CAP_FMT_DECMPFS_COMPRESSION;
#else
			VOL_CAP_FMT_PATH_FROM_ID;
#endif
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
			VOL_CAP_INT_FLOCK |
			VOL_CAP_INT_MANLOCK |
#if NAMEDSTREAMS
			VOL_CAP_INT_EXTENDED_ATTR |
			VOL_CAP_INT_NAMEDSTREAMS;
#else
			VOL_CAP_INT_EXTENDED_ATTR;
#endif
		cap->valid[VOL_CAPABILITIES_RESERVED1] = 0;
		cap->valid[VOL_CAPABILITIES_RESERVED2] = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		vol_attributes_attr_t *attrp = &fsap->f_attributes;

        	attrp->validattr.commonattr = HFS_ATTR_CMN_VALIDMASK;
        	attrp->validattr.volattr = ATTR_VOL_VALIDMASK & ~ATTR_VOL_INFO;
        	attrp->validattr.dirattr = ATTR_DIR_VALIDMASK;
        	attrp->validattr.fileattr = HFS_ATTR_FILE_VALIDMASK;
        	attrp->validattr.forkattr = 0;

        	attrp->nativeattr.commonattr = HFS_ATTR_CMN_VALIDMASK;
        	attrp->nativeattr.volattr = ATTR_VOL_VALIDMASK & ~ATTR_VOL_INFO;
        	attrp->nativeattr.dirattr = ATTR_DIR_VALIDMASK;
        	attrp->nativeattr.fileattr = HFS_ATTR_FILE_VALIDMASK;
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
		u_int16_t subtype = 0;

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
		strlcpy(fsap->f_vol_name, (char *) hfsmp->vcbVN, MAXPATHLEN);
		VFSATTR_SET_SUPPORTED(fsap, f_vol_name);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_uuid)) {
		hfs_getvoluuid(hfsmp, fsap->f_uuid);
		VFSATTR_SET_SUPPORTED(fsap, f_uuid);
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

	to_desc.cd_nameptr = (const u_int8_t *)name;
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
					strlcpy((char *)vcb->vcbVN, name, sizeof(vcb->vcbVN));
				}

				hfs_systemfile_unlock(hfsmp, lockflags);
				cat_postflight(hfsmp, &cookie, p);
			
				if (error)
					MarkVCBDirty(vcb);
				(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
			}
			hfs_end_transaction(hfsmp);
		}			
		if (!error) {
			/* Release old allocated name buffer */
			if (cp->c_desc.cd_flags & CD_HASBUF) {
				const char *tmp_name = (const char *)cp->c_desc.cd_nameptr;
		
				cp->c_desc.cd_nameptr = 0;
				cp->c_desc.cd_namelen = 0;
				cp->c_desc.cd_flags &= ~CD_HASBUF;
				vfs_removename(tmp_name);
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

/* If a runtime corruption is detected, set the volume inconsistent 
 * bit in the volume attributes.  The volume inconsistent bit is a persistent
 * bit which represents that the volume is corrupt and needs repair.  
 * The volume inconsistent bit can be set from the kernel when it detects
 * runtime corruption or from file system repair utilities like fsck_hfs when
 * a repair operation fails.  The bit should be cleared only from file system 
 * verify/repair utility like fsck_hfs when a verify/repair succeeds.
 */
void hfs_mark_volume_inconsistent(struct hfsmount *hfsmp)
{
	HFS_MOUNT_LOCK(hfsmp, TRUE);	
	if ((hfsmp->vcbAtrb & kHFSVolumeInconsistentMask) == 0) {
		hfsmp->vcbAtrb |= kHFSVolumeInconsistentMask;
		MarkVCBDirty(hfsmp);
	}
	if ((hfsmp->hfs_flags & HFS_READ_ONLY)==0) {	
		/* Log information to ASL log */
		fslog_fs_corrupt(hfsmp->hfs_mp);
		printf("hfs: Runtime corruption detected on %s, fsck will be forced on next mount.\n", hfsmp->vcbVN);
	}
	HFS_MOUNT_UNLOCK(hfsmp, TRUE);
}

/* Replay the journal on the device node provided.  Returns zero if 
 * journal replay succeeded or no journal was supposed to be replayed.
 */
static int hfs_journal_replay(vnode_t devvp, vfs_context_t context)
{
	int retval = 0;
	struct mount *mp = NULL;
	struct hfs_mount_args *args = NULL;

	/* Replay allowed only on raw devices */
	if (!vnode_ischr(devvp)) {
		retval = EINVAL;
		goto out;
	}

	/* Create dummy mount structures */
	MALLOC(mp, struct mount *, sizeof(struct mount), M_TEMP, M_WAITOK);
	if (mp == NULL) {
		retval = ENOMEM;
		goto out;
	}
	bzero(mp, sizeof(struct mount));
	mount_lock_init(mp);

	MALLOC(args, struct hfs_mount_args *, sizeof(struct hfs_mount_args), M_TEMP, M_WAITOK);
	if (args == NULL) {
		retval = ENOMEM;
		goto out;
	}
	bzero(args, sizeof(struct hfs_mount_args));

	retval = hfs_mountfs(devvp, mp, args, 1, context);
	buf_flushdirtyblks(devvp, MNT_WAIT, 0, "hfs_journal_replay");

out:
	if (mp) {
		mount_lock_destroy(mp);
		FREE(mp, M_TEMP);
	}
	if (args) {
		FREE(args, M_TEMP);
	}
	return retval;
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
	hfs_vfs_setattr,
	{NULL}
};
