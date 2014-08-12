/*
 * Copyright (c) 1999-2014 Apple Inc. All rights reserved.
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
#include <sys/ubc.h>
#include <sys/buf_internal.h>

/* for parsing boot-args */
#include <pexpert/pexpert.h>


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
#include "hfs_btreeio.h"
#include "hfs_kdebug.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/BTreesInternal.h"

#if CONFIG_PROTECT
#include <sys/cprotect.h>
#endif

#define HFS_MOUNT_DEBUG 1

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
lck_grp_t *  hfs_spinlock_group;

extern struct vnodeopv_desc hfs_vnodeop_opv_desc;

#if CONFIG_HFS_STD
extern struct vnodeopv_desc hfs_std_vnodeop_opv_desc;
static int hfs_flushMDB(struct hfsmount *hfsmp, int waitfor, int altflush);
#endif

/* not static so we can re-use in hfs_readwrite.c for build_path calls */
int hfs_vfs_vget(struct mount *mp, ino64_t ino, struct vnode **vpp, vfs_context_t context);

static int hfs_changefs(struct mount *mp, struct hfs_mount_args *args);
static int hfs_fhtovp(struct mount *mp, int fhlen, unsigned char *fhp, struct vnode **vpp, vfs_context_t context);
static int hfs_flushfiles(struct mount *, int, struct proc *);
static int hfs_getmountpoint(struct vnode *vp, struct hfsmount **hfsmpp);
static int hfs_init(struct vfsconf *vfsp);
static void hfs_locks_destroy(struct hfsmount *hfsmp);
static int hfs_vfs_root(struct mount *mp, struct vnode **vpp, vfs_context_t context);
static int hfs_quotactl(struct mount *, int, uid_t, caddr_t, vfs_context_t context);
static int hfs_start(struct mount *mp, int flags, vfs_context_t context);
static int hfs_vptofh(struct vnode *vp, int *fhlenp, unsigned char *fhp, vfs_context_t context);
static int hfs_file_extent_overlaps(struct hfsmount *hfsmp, u_int32_t allocLimit, struct HFSPlusCatalogFile *filerec);
static int hfs_journal_replay(vnode_t devvp, vfs_context_t context);
static int hfs_reclaimspace(struct hfsmount *hfsmp, u_int32_t allocLimit, u_int32_t reclaimblks, vfs_context_t context);
static int hfs_extend_journal(struct hfsmount *hfsmp, u_int32_t sector_size, u_int64_t sector_count, vfs_context_t context);

void hfs_initialize_allocator (struct hfsmount *hfsmp);
int hfs_teardown_allocator (struct hfsmount *hfsmp);

int hfs_mount(struct mount *mp, vnode_t  devvp, user_addr_t data, vfs_context_t context);
int hfs_mountfs(struct vnode *devvp, struct mount *mp, struct hfs_mount_args *args, int journal_replay_only, vfs_context_t context);
int hfs_reload(struct mount *mp);
int hfs_statfs(struct mount *mp, register struct vfsstatfs *sbp, vfs_context_t context);
int hfs_sync(struct mount *mp, int waitfor, vfs_context_t context);
int hfs_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
                      user_addr_t newp, size_t newlen, vfs_context_t context);
int hfs_unmount(struct mount *mp, int mntflags, vfs_context_t context);

/*
 * Called by vfs_mountroot when mounting HFS Plus as root.
 */

int
hfs_mountroot(mount_t mp, vnode_t rvp, vfs_context_t context)
{
	struct hfsmount *hfsmp;
	ExtendedVCB *vcb;
	struct vfsstatfs *vfsp;
	int error;

	if ((error = hfs_mountfs(rvp, mp, NULL, 0, context))) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mountroot: hfs_mountfs returned %d, rvp (%p) name (%s) \n", 
					error, rvp, (rvp->v_name ? rvp->v_name : "unknown device"));
		}
		return (error);
	}

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

int
hfs_mount(struct mount *mp, vnode_t devvp, user_addr_t data, vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	struct hfsmount *hfsmp = NULL;
	struct hfs_mount_args args;
	int retval = E_NONE;
	u_int32_t cmdflags;

	if ((retval = copyin(data, (caddr_t)&args, sizeof(args)))) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mount: copyin returned %d for fs\n", retval);
		}
		return (retval);
	}
	cmdflags = (u_int32_t)vfs_flags(mp) & MNT_CMDFLAGS;
	if (cmdflags & MNT_UPDATE) {
		hfsmp = VFSTOHFS(mp);

		/* Reload incore data after an fsck. */
		if (cmdflags & MNT_RELOAD) {
			if (vfs_isrdonly(mp)) {
				int error = hfs_reload(mp);
				if (error && HFS_MOUNT_DEBUG) {
					printf("hfs_mount: hfs_reload returned %d on %s \n", error, hfsmp->vcbVN);
				}
				return error;
			}
			else {
				if (HFS_MOUNT_DEBUG) {
					printf("hfs_mount: MNT_RELOAD not supported on rdwr filesystem %s\n", hfsmp->vcbVN);
				}
				return (EINVAL);
			}
		}

		/* Change to a read-only file system. */
		if (((hfsmp->hfs_flags & HFS_READ_ONLY) == 0) &&
		    vfs_isrdonly(mp)) {
			int flags;

			/* Set flag to indicate that a downgrade to read-only
			 * is in progress and therefore block any further 
			 * modifications to the file system.
			 */
			hfs_lock_global (hfsmp, HFS_EXCLUSIVE_LOCK);
			hfsmp->hfs_flags |= HFS_RDONLY_DOWNGRADE;
			hfsmp->hfs_downgrading_proc = current_thread();
			hfs_unlock_global (hfsmp);

			/* use VFS_SYNC to push out System (btree) files */
			retval = VFS_SYNC(mp, MNT_WAIT, context);
			if (retval && ((cmdflags & MNT_FORCE) == 0)) {
				hfsmp->hfs_flags &= ~HFS_RDONLY_DOWNGRADE;
				hfsmp->hfs_downgrading_proc = NULL;
				if (HFS_MOUNT_DEBUG) {
					printf("hfs_mount: VFS_SYNC returned %d during b-tree sync of %s \n", retval, hfsmp->vcbVN);
				}
				goto out;
			}
		
			flags = WRITECLOSE;
			if (cmdflags & MNT_FORCE)
				flags |= FORCECLOSE;
				
			if ((retval = hfs_flushfiles(mp, flags, p))) {
				hfsmp->hfs_flags &= ~HFS_RDONLY_DOWNGRADE;
				hfsmp->hfs_downgrading_proc = NULL;
				if (HFS_MOUNT_DEBUG) {
					printf("hfs_mount: hfs_flushfiles returned %d on %s \n", retval, hfsmp->vcbVN);
				}
				goto out;
			}

			/* mark the volume cleanly unmounted */
			hfsmp->vcbAtrb |= kHFSVolumeUnmountedMask;
			retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
			hfsmp->hfs_flags |= HFS_READ_ONLY;

			/*
			 * Close down the journal. 
			 *
			 * NOTE: It is critically important to close down the journal
			 * and have it issue all pending I/O prior to calling VNOP_FSYNC below.
			 * In a journaled environment it is expected that the journal be
			 * the only actor permitted to issue I/O for metadata blocks in HFS.
			 * If we were to call VNOP_FSYNC prior to closing down the journal,
			 * we would inadvertantly issue (and wait for) the I/O we just 
			 * initiated above as part of the flushvolumeheader call.
			 * 
			 * To avoid this, we follow the same order of operations as in
			 * unmount and issue the journal_close prior to calling VNOP_FSYNC.
			 */
	
			if (hfsmp->jnl) {
				hfs_lock_global (hfsmp, HFS_EXCLUSIVE_LOCK);

			    journal_close(hfsmp->jnl);
			    hfsmp->jnl = NULL;

			    // Note: we explicitly don't want to shutdown
			    //       access to the jvp because we may need
			    //       it later if we go back to being read-write.

				hfs_unlock_global (hfsmp);
			}


			/*
			 * Write out any pending I/O still outstanding against the device node
			 * now that the journal has been closed.
			 */
			if (retval == 0) {
				vnode_get(hfsmp->hfs_devvp);
				retval = VNOP_FSYNC(hfsmp->hfs_devvp, MNT_WAIT, context);
				vnode_put(hfsmp->hfs_devvp);
			}

			if (retval) {
				if (HFS_MOUNT_DEBUG) {
					printf("hfs_mount: FSYNC on devvp returned %d for fs %s\n", retval, hfsmp->vcbVN);
				}
				hfsmp->hfs_flags &= ~HFS_RDONLY_DOWNGRADE;
				hfsmp->hfs_downgrading_proc = NULL;
				hfsmp->hfs_flags &= ~HFS_READ_ONLY;
				goto out;
			}
		
			if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
				if (hfsmp->hfs_summary_table) {
					int err = 0;
					/* 
					 * Take the bitmap lock to serialize against a concurrent bitmap scan still in progress 
					 */
					if (hfsmp->hfs_allocation_vp) {
						err = hfs_lock (VTOC(hfsmp->hfs_allocation_vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
					}
					FREE (hfsmp->hfs_summary_table, M_TEMP);
					hfsmp->hfs_summary_table = NULL;
					hfsmp->hfs_flags &= ~HFS_SUMMARY_TABLE;
					if (err == 0 && hfsmp->hfs_allocation_vp){
						hfs_unlock (VTOC(hfsmp->hfs_allocation_vp));
					}
				}
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
				if (HFS_MOUNT_DEBUG) {
					printf("hfs_mount: attempting to mount inconsistent non-root volume %s\n",  (hfsmp->vcbVN));
				}
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

				hfs_lock_global (hfsmp, HFS_EXCLUSIVE_LOCK);

				/* We provide the mount point twice here: The first is used as
				 * an opaque argument to be passed back when hfs_sync_metadata
				 * is called.  The second is provided to the throttling code to
				 * indicate which mount's device should be used when accounting
				 * for metadata writes.
				 */
				hfsmp->jnl = journal_open(hfsmp->jvp,
						(hfsmp->jnl_start * HFSTOVCB(hfsmp)->blockSize) + (off_t)HFSTOVCB(hfsmp)->hfsPlusIOPosOffset,
						hfsmp->jnl_size,
						hfsmp->hfs_devvp,
						hfsmp->hfs_logical_block_size,
						jflags,
						0,
						hfs_sync_metadata, hfsmp->hfs_mp,
						hfsmp->hfs_mp);
				
				/*
				 * Set up the trim callback function so that we can add
				 * recently freed extents to the free extent cache once
				 * the transaction that freed them is written to the
				 * journal on disk.
				 */
				if (hfsmp->jnl)
					journal_trim_set_callback(hfsmp->jnl, hfs_trim_callback, hfsmp);
				
				hfs_unlock_global (hfsmp);

				if (hfsmp->jnl == NULL) {
					if (HFS_MOUNT_DEBUG) {
						printf("hfs_mount: journal_open == NULL; couldn't be opened on %s \n", (hfsmp->vcbVN));
					}
					retval = EINVAL;
					goto out;
				} else {
					hfsmp->hfs_flags &= ~HFS_NEED_JNL_RESET;
				}

			}

			/* See if we need to erase unused Catalog nodes due to <rdar://problem/6947811>. */
			retval = hfs_erase_unused_nodes(hfsmp);
			if (retval != E_NONE) {
				if (HFS_MOUNT_DEBUG) {
					printf("hfs_mount: hfs_erase_unused_nodes returned %d for fs %s\n", retval, hfsmp->vcbVN);
				}
				goto out;
			}

			/* If this mount point was downgraded from read-write 
			 * to read-only, clear that information as we are now 
			 * moving back to read-write.
			 */
			hfsmp->hfs_flags &= ~HFS_RDONLY_DOWNGRADE;
			hfsmp->hfs_downgrading_proc = NULL;

			/* mark the volume dirty (clear clean unmount bit) */
			hfsmp->vcbAtrb &= ~kHFSVolumeUnmountedMask;

			retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
			if (retval != E_NONE) {
				if (HFS_MOUNT_DEBUG) {
					printf("hfs_mount: hfs_flushvolumeheader returned %d for fs %s\n", retval, hfsmp->vcbVN);
				}
				goto out;
			}
		
			/* Only clear HFS_READ_ONLY after a successful write */
			hfsmp->hfs_flags &= ~HFS_READ_ONLY;


			if (!(hfsmp->hfs_flags & (HFS_READ_ONLY | HFS_STANDARD))) {
				/* Setup private/hidden directories for hardlinks. */
				hfs_privatedir_init(hfsmp, FILE_HARDLINKS);
				hfs_privatedir_init(hfsmp, DIR_HARDLINKS);

				hfs_remove_orphans(hfsmp);

				/*
				 * Allow hot file clustering if conditions allow.
				 */
				if ((hfsmp->hfs_flags & HFS_METADATA_ZONE) && 
					   ((hfsmp->hfs_mp->mnt_kern_flag & MNTK_SSD) == 0))	{
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
		if (retval &&  HFS_MOUNT_DEBUG) {
			printf("hfs_mount: hfs_changefs returned %d for %s\n", retval, hfsmp->vcbVN);
		}

	} else /* not an update request */ {

		/* Set the mount flag to indicate that we support volfs  */
		vfs_setflags(mp, (u_int64_t)((unsigned int)MNT_DOVOLFS));

		retval = hfs_mountfs(devvp, mp, &args, 0, context);
		if (retval) { 
			const char *name = vnode_getname(devvp);
			printf("hfs_mount: hfs_mountfs returned error=%d for device %s\n", retval, (name ? name : "unknown-dev"));
			if (name) {
				vnode_putname(name);
			}
			goto out;
		}

		/* After hfs_mountfs succeeds, we should have valid hfsmp */
		hfsmp = VFSTOHFS(mp);

		/*
		 * Check to see if the file system exists on CoreStorage.  
		 *
		 * This must be done after examining the root folder's CP EA since
		 * hfs_vfs_root will create a vnode (which must not occur until after
		 * we've established the CP level of the FS).
		 */ 
		if (retval == 0) {
			errno_t err;
			vnode_t root_vnode;
			err = hfs_vfs_root(mp, &root_vnode, context);
			if (err == 0) {
				if (VNOP_IOCTL(devvp, _DKIOCCSSETFSVNODE,
							(caddr_t)&root_vnode, 0, context) == 0) {
					err = vnode_ref(root_vnode);
					if (err == 0) {
						hfsmp->hfs_flags |= HFS_CS;
					}
				}

				err = vnode_put(root_vnode);
				if (err) {
					printf("hfs: could not release io count on root vnode with error: %d\n",
							err);
				}
			} else {
				printf("hfs: could not get root vnode with error: %d\n",
						err);
			}
		}
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
	error = cat_lookup(args->hfsmp, &cp->c_desc, 0, 0, &cndesc, &cnattr, NULL, NULL);
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
	struct hfs_changefs_cargs cargs;
	u_int32_t mount_flags;

#if CONFIG_HFS_STD
	u_int32_t old_encoding = 0;
	hfs_to_unicode_func_t	get_unicode_func;
	unicode_to_hfs_func_t	get_hfsname_func;
#endif

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
	
#if CONFIG_HFS_STD
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
#endif

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

#if CONFIG_HFS_STD
	/*
	 * If we're switching name converters we can now
	 * connect the new hfs_get_hfsname converter and
	 * release our interest in the old converters.
	 */
	if (namefix) {
		/* HFS standard only */
		hfsmp->hfs_get_hfsname = get_hfsname_func;
		vcb->volumeNameEncodingHint = args->hfs_encoding;
		(void) hfs_relconverter(old_encoding);
	}
#endif

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
	if (!vnode_issystem(vp) && !VNODE_IS_RSRC(vp) && (cp->c_fileid >= kHFSFirstUserCatalogNodeID)) {
	        struct cat_fork *datafork;
		struct cat_desc desc;

		datafork = cp->c_datafork ? &cp->c_datafork->ff_data : NULL;

		/* lookup by fileID since name could have changed */
		lockflags = hfs_systemfile_lock(args->hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
		args->error = cat_idlookup(args->hfsmp, cp->c_fileid, 0, 0, &desc, &cp->c_attr, datafork);
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
int
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
	if ((error = cat_idlookup(hfsmp, kHFSRootFolderID, 0, 0, &cndesc, NULL, NULL)))
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

__unused
static uint64_t tv_to_usecs(struct timeval *tv)
{
	return tv->tv_sec * 1000000ULL + tv->tv_usec;
}

// Returns TRUE if b - a >= usecs
static boolean_t hfs_has_elapsed (const struct timeval *a, 
                                  const struct timeval *b,
                                  uint64_t usecs)
{
    struct timeval diff;
    timersub(b, a, &diff);
    return diff.tv_sec * 1000000ULL + diff.tv_usec >= usecs;
}

static void
hfs_syncer(void *arg0, void *unused)
{
#pragma unused(unused)
    
    struct hfsmount *hfsmp = arg0;
    struct timeval   now;

    microuptime(&now);

    KERNEL_DEBUG_CONSTANT(HFSDBG_SYNCER | DBG_FUNC_START, hfsmp, 
                          tv_to_usecs(&now),
                          tv_to_usecs(&hfsmp->hfs_mp->mnt_last_write_completed_timestamp), 
                          hfsmp->hfs_mp->mnt_pending_write_size, 0);

    hfs_syncer_lock(hfsmp);

    if (!hfsmp->hfs_syncer) {
        // hfs_unmount is waiting for us leave now and let it do the sync
        hfsmp->hfs_sync_incomplete = FALSE;
        hfs_syncer_unlock(hfsmp);
        hfs_syncer_wakeup(hfsmp);
        return;
    }

    /* Check to see whether we should flush now: either the oldest is
       > HFS_MAX_META_DELAY or HFS_META_DELAY has elapsed since the
       request and there are no pending writes. */

    boolean_t flush_now = FALSE;

    if (hfs_has_elapsed(&hfsmp->hfs_sync_req_oldest, &now, HFS_MAX_META_DELAY))
        flush_now = TRUE;
    else if (!hfsmp->hfs_mp->mnt_pending_write_size) {
        /* N.B. accessing mnt_last_write_completed_timestamp is not thread safe, but
           it won't matter for what we're using it for. */
        if (hfs_has_elapsed(&hfsmp->hfs_mp->mnt_last_write_completed_timestamp,
                            &now,
                            HFS_META_DELAY)) {
            flush_now = TRUE;
        }
    }

    if (!flush_now) {
        thread_call_t syncer = hfsmp->hfs_syncer;

        hfs_syncer_unlock(hfsmp);

        hfs_syncer_queue(syncer);

        return;
    }

    timerclear(&hfsmp->hfs_sync_req_oldest);

    hfs_syncer_unlock(hfsmp);

    KERNEL_DEBUG_CONSTANT(HFSDBG_SYNCER_TIMED | DBG_FUNC_START, 
                          tv_to_usecs(&now),
                          tv_to_usecs(&hfsmp->hfs_mp->mnt_last_write_completed_timestamp),
                          tv_to_usecs(&hfsmp->hfs_mp->mnt_last_write_issued_timestamp), 
                          hfsmp->hfs_mp->mnt_pending_write_size, 0);

    if (hfsmp->hfs_syncer_thread) {
        printf("hfs: syncer already running!");
		return;
	}

    hfsmp->hfs_syncer_thread = current_thread();

    hfs_start_transaction(hfsmp);   // so we hold off any new writes

    /*
     * We intentionally do a synchronous flush (of the journal or entire volume) here.
     * For journaled volumes, this means we wait until the metadata blocks are written
     * to both the journal and their final locations (in the B-trees, etc.).
     *
     * This tends to avoid interleaving the metadata writes with other writes (for
     * example, user data, or to the journal when a later transaction notices that
     * an earlier transaction has finished its async writes, and then updates the
     * journal start in the journal header).  Avoiding interleaving of writes is
     * very good for performance on simple flash devices like SD cards, thumb drives;
     * and on devices like floppies.  Since removable devices tend to be this kind of
     * simple device, doing a synchronous flush actually improves performance in
     * practice.
     *
     * NOTE: For non-journaled volumes, the call to hfs_sync will also cause dirty
     * user data to be written.
     */
    if (hfsmp->jnl) {
        hfs_journal_flush(hfsmp, TRUE);
    } else {
        hfs_sync(hfsmp->hfs_mp, MNT_WAIT, vfs_context_kernel());
    }

    KERNEL_DEBUG_CONSTANT(HFSDBG_SYNCER_TIMED | DBG_FUNC_END, 
                          (microuptime(&now), tv_to_usecs(&now)),
                          tv_to_usecs(&hfsmp->hfs_mp->mnt_last_write_completed_timestamp), 
                          tv_to_usecs(&hfsmp->hfs_mp->mnt_last_write_issued_timestamp), 
                          hfsmp->hfs_mp->mnt_pending_write_size, 0);

    hfs_end_transaction(hfsmp);

    hfsmp->hfs_syncer_thread = NULL;

    hfs_syncer_lock(hfsmp);

    // If hfs_unmount lets us and we missed a sync, schedule again
    if (hfsmp->hfs_syncer && timerisset(&hfsmp->hfs_sync_req_oldest)) {
        thread_call_t syncer = hfsmp->hfs_syncer;

        hfs_syncer_unlock(hfsmp);

        hfs_syncer_queue(syncer);
    } else {
        hfsmp->hfs_sync_incomplete = FALSE;
        hfs_syncer_unlock(hfsmp);
        hfs_syncer_wakeup(hfsmp);
    }

    /* BE CAREFUL WHAT YOU ADD HERE: at this point hfs_unmount is free
       to continue and therefore hfsmp might be invalid. */

    KERNEL_DEBUG_CONSTANT(HFSDBG_SYNCER | DBG_FUNC_END, 0, 0, 0, 0, 0);
}


extern int IOBSDIsMediaEjectable( const char *cdev_name );

/*
 * Call into the allocator code and perform a full scan of the bitmap file.
 * 
 * This allows us to TRIM unallocated ranges if needed, and also to build up
 * an in-memory summary table of the state of the allocated blocks.
 */
void hfs_scan_blocks (struct hfsmount *hfsmp) {
	/*
	 * Take the allocation file lock.  Journal transactions will block until
	 * we're done here. 
	 */
	
	int flags = hfs_systemfile_lock(hfsmp, SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	
	/* 
	 * We serialize here with the HFS mount lock as we're mounting.
	 * 
	 * The mount can only proceed once this thread has acquired the bitmap 
	 * lock, since we absolutely do not want someone else racing in and 
	 * getting the bitmap lock, doing a read/write of the bitmap file, 
	 * then us getting the bitmap lock.
	 * 
	 * To prevent this, the mount thread takes the HFS mount mutex, starts us 
	 * up, then immediately msleeps on the scan_var variable in the mount 
	 * point as a condition variable.  This serialization is safe since 
	 * if we race in and try to proceed while they're still holding the lock, 
	 * we'll block trying to acquire the global lock.  Since the mount thread 
	 * acquires the HFS mutex before starting this function in a new thread, 
	 * any lock acquisition on our part must be linearizably AFTER the mount thread's. 
	 *
	 * Note that the HFS mount mutex is always taken last, and always for only
	 * a short time.  In this case, we just take it long enough to mark the
	 * scan-in-flight bit.
	 */
	(void) hfs_lock_mount (hfsmp);
	hfsmp->scan_var |= HFS_ALLOCATOR_SCAN_INFLIGHT;
	wakeup((caddr_t) &hfsmp->scan_var);
	hfs_unlock_mount (hfsmp);

	/* Initialize the summary table */
	if (hfs_init_summary (hfsmp)) {
		printf("hfs: could not initialize summary table for %s\n", hfsmp->vcbVN);
	}	

	/*
	 * ScanUnmapBlocks assumes that the bitmap lock is held when you 
	 * call the function. We don't care if there were any errors issuing unmaps.
	 *
	 * It will also attempt to build up the summary table for subsequent
	 * allocator use, as configured.
	 */
	(void) ScanUnmapBlocks(hfsmp);

	hfs_systemfile_unlock(hfsmp, flags);
}

static int hfs_root_unmounted_cleanly = 0;

SYSCTL_DECL(_vfs_generic);
SYSCTL_INT(_vfs_generic, OID_AUTO, root_unmounted_cleanly, CTLFLAG_RD, &hfs_root_unmounted_cleanly, 0, "Root filesystem was unmounted cleanly");

/*
 * Common code for mount and mountroot
 */
int
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
	u_int32_t device_features = 0;
	int isssd;
	
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
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mountfs: DKIOCGETBLOCKSIZE failed\n");
		}
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
			if (HFS_MOUNT_DEBUG) {
				printf("hfs_mountfs: DKIOCGETPHYSICALBLOCKSIZE failed\n");
			}
			retval = ENXIO;
			goto error_exit;
		}
		/* If device does not support this ioctl, assume that physical 
		 * block size is same as logical block size 
		 */
		phys_blksize = log_blksize;
	}
	if (phys_blksize == 0 || phys_blksize > MAXBSIZE) {
		printf("hfs: physical block size 0x%x looks bad.  Not mounting.\n", phys_blksize);
		retval = ENXIO;
		goto error_exit;
	}

	/* Switch to 512 byte sectors (temporarily) */
	if (log_blksize > 512) {
		u_int32_t size512 = 512;

		if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&size512, FWRITE, context)) {
			if (HFS_MOUNT_DEBUG) {
				printf("hfs_mountfs: DKIOCSETBLOCKSIZE failed \n");
			}
			retval = ENXIO;
			goto error_exit;
		}
	}
	/* Get the number of 512 byte physical blocks. */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0, context)) {
		/* resetting block size may fail if getting block count did */
		(void)VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&log_blksize, FWRITE, context);
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mountfs: DKIOCGETBLOCKCOUNT failed\n");
		}
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
	if (log_blksize > PAGE_SIZE) {
		log_blksize = PAGE_SIZE;
	}

	/* Now switch to our preferred physical block size. */
	if (log_blksize > 512) {
		if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&log_blksize, FWRITE, context)) {
			if (HFS_MOUNT_DEBUG) { 
				printf("hfs_mountfs: DKIOCSETBLOCKSIZE (2) failed\n");
			}
			retval = ENXIO;
			goto error_exit;
		}
		/* Get the count of physical blocks. */
		if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0, context)) {
			if (HFS_MOUNT_DEBUG) { 
				printf("hfs_mountfs: DKIOCGETBLOCKCOUNT (2) failed\n");
			}
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
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mountfs: buf_meta_bread failed with %d\n", retval);
		}
		goto error_exit;
	}
	MALLOC(mdbp, HFSMasterDirectoryBlock *, kMDBSize, M_TEMP, M_WAITOK);
	if (mdbp == NULL) {
		retval = ENOMEM;
		if (HFS_MOUNT_DEBUG) { 
			printf("hfs_mountfs: MALLOC failed\n");
		}
		goto error_exit;
	}
	bcopy((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(phys_blksize), mdbp, kMDBSize);
	buf_brelse(bp);
	bp = NULL;

	MALLOC(hfsmp, struct hfsmount *, sizeof(struct hfsmount), M_HFSMNT, M_WAITOK);
	if (hfsmp == NULL) {
		if (HFS_MOUNT_DEBUG) { 
			printf("hfs_mountfs: MALLOC (2) failed\n");
		}
		retval = ENOMEM;
		goto error_exit;
	}
	bzero(hfsmp, sizeof(struct hfsmount));
	
	hfs_chashinit_finish(hfsmp);
	
	/* Init the ID lookup hashtable */
	hfs_idhash_init (hfsmp);

	/*
	 * See if the disk supports unmap (trim).
	 *
	 * NOTE: vfs_init_io_attributes has not been called yet, so we can't use the io_flags field
	 * returned by vfs_ioattr.  We need to call VNOP_IOCTL ourselves.
	 */
	if (VNOP_IOCTL(devvp, DKIOCGETFEATURES, (caddr_t)&device_features, 0, context) == 0) {
		if (device_features & DK_FEATURE_UNMAP) {
			hfsmp->hfs_flags |= HFS_UNMAP;
		}
	}	

	/* 
	 * See if the disk is a solid state device, too.  We need this to decide what to do about 
	 * hotfiles.
	 */
	if (VNOP_IOCTL(devvp, DKIOCISSOLIDSTATE, (caddr_t)&isssd, 0, context) == 0) {
		if (isssd) {
			hfsmp->hfs_flags |= HFS_SSD;
		}
	}


	/*
	 *  Init the volume information structure
	 */
	
	lck_mtx_init(&hfsmp->hfs_mutex, hfs_mutex_group, hfs_lock_attr);
	lck_mtx_init(&hfsmp->hfc_mutex, hfs_mutex_group, hfs_lock_attr);
	lck_rw_init(&hfsmp->hfs_global_lock, hfs_rwlock_group, hfs_lock_attr);
	lck_rw_init(&hfsmp->hfs_insync, hfs_rwlock_group, hfs_lock_attr);
	lck_spin_init(&hfsmp->vcbFreeExtLock, hfs_spinlock_group, hfs_lock_attr);
	
	vfs_setfsprivate(mp, hfsmp);
	hfsmp->hfs_mp = mp;			/* Make VFSTOHFS work */
	hfsmp->hfs_raw_dev = vnode_specrdev(devvp);
	hfsmp->hfs_devvp = devvp;
	vnode_ref(devvp);  /* Hold a ref on the device, dropped when hfsmp is freed. */
	hfsmp->hfs_logical_block_size = log_blksize;
	hfsmp->hfs_logical_block_count = log_blkcnt;
	hfsmp->hfs_logical_bytes = (uint64_t) log_blksize * (uint64_t) log_blkcnt;
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
#if CONFIG_HFS_STD 
		/* On 10.6 and beyond, non read-only mounts for HFS standard vols get rejected */
		if (vfs_isrdwr(mp)) {
			retval = EROFS;
			goto error_exit;
		}

		printf("hfs_mountfs: Mounting HFS Standard volumes was deprecated in Mac OS 10.7 \n");

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
			hfsmp->hfs_logical_bytes = (uint64_t) log_blksize * (uint64_t) log_blkcnt;
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
#else
		/* On platforms where HFS Standard is not supported, deny the mount altogether */
		retval = EINVAL;
		goto error_exit;
#endif

	} 
	else { /* Mount an HFS Plus disk */
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

					if (HFS_MOUNT_DEBUG) { 
						printf("hfs_mountfs: DKIOCSETBLOCKSIZE (3) failed\n");
					}				
					retval = ENXIO;
					goto error_exit;
				}
				if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT,
				    (caddr_t)&log_blkcnt, 0, context)) {
					if (HFS_MOUNT_DEBUG) { 
						printf("hfs_mountfs: DKIOCGETBLOCKCOUNT (3) failed\n");
					}
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
	
			hfsmp->hfs_logical_bytes = (uint64_t) hfsmp->hfs_logical_block_count * (uint64_t) hfsmp->hfs_logical_block_size;
			
			mdb_offset = (daddr64_t)((embeddedOffset / log_blksize) + HFS_PRI_SECTOR(log_blksize));
			retval = (int)buf_meta_bread(devvp, HFS_PHYSBLK_ROUNDDOWN(mdb_offset, hfsmp->hfs_log_per_phys),
					phys_blksize, cred, &bp);
			if (retval) {
				if (HFS_MOUNT_DEBUG) { 
					printf("hfs_mountfs: buf_meta_bread (2) failed with %d\n", retval);
				}
				goto error_exit;
			}
			bcopy((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(phys_blksize), mdbp, 512);
			buf_brelse(bp);
			bp = NULL;
			vhp = (HFSPlusVolumeHeader*) mdbp;

		} 
		else { /* pure HFS+ */ 
			embeddedOffset = 0;
			vhp = (HFSPlusVolumeHeader*) mdbp;
		}

		if (isroot) {
			hfs_root_unmounted_cleanly = ((SWAP_BE32(vhp->attributes) & kHFSVolumeUnmountedMask) != 0);
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
			
			if (HFS_MOUNT_DEBUG) { 
				printf("hfs_mountfs: failed to mount non-root inconsistent disk\n");
			}
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
					if (HFS_MOUNT_DEBUG) { 
						printf("hfs_mountfs: hfs_early_journal_init indicated external jnl \n");
					}
					retval = EINVAL;
					goto error_exit;
				}

				// if the journal failed to open, then set the lastMountedVersion
				// to be "FSK!" which fsck_hfs will see and force the fsck instead
				// of just bailing out because the volume is journaled.
				if (!ronly) {
					if (HFS_MOUNT_DEBUG) { 
						printf("hfs_mountfs: hfs_early_journal_init failed, setting to FSK \n");
					}

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
					if (HFS_MOUNT_DEBUG) { 
						printf("hfs_mountfs: hfs_early_journal_init failed, erroring out \n");
					}
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
				if (HFS_MOUNT_DEBUG) { 
					printf("hfs_mountfs: DKIOCSETBLOCKSIZE (4) failed \n");
				}
				retval = ENXIO;
				goto error_exit;
			}
			if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&log_blkcnt, 0, context)) {
				if (HFS_MOUNT_DEBUG) { 
					printf("hfs_mountfs: DKIOCGETBLOCKCOUNT (4) failed \n");
				}
				retval = ENXIO;
				goto error_exit;
			}
			devvp->v_specsize = log_blksize;
			/* Note: relative block count adjustment (in case this is an embedded volume). */
			hfsmp->hfs_logical_block_count *= hfsmp->hfs_logical_block_size / log_blksize;
			hfsmp->hfs_logical_block_size = log_blksize;
			hfsmp->hfs_log_per_phys = hfsmp->hfs_physical_block_size / log_blksize;
	
			hfsmp->hfs_logical_bytes = (uint64_t) hfsmp->hfs_logical_block_count * (uint64_t) hfsmp->hfs_logical_block_size;

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
						if (HFS_MOUNT_DEBUG) { 
							printf("hfs_mountfs: hfs_early_journal_init (2) resetting.. \n");
						}
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
						if (HFS_MOUNT_DEBUG) { 
							printf("hfs_mountfs: hfs_early_journal_init (2) failed \n");
						}
				    	retval = EINVAL;
				    	goto error_exit;
					}
				}
			}

			/* Try again with a smaller block size... */
			retval = hfs_MountHFSPlusVolume(hfsmp, vhp, embeddedOffset, disksize, p, args, cred);
			if (retval && HFS_MOUNT_DEBUG) {
				printf("hfs_MountHFSPlusVolume (late) returned %d\n",retval); 
			}
		}
		if (retval)
			(void) hfs_relconverter(0);
	}

	// save off a snapshot of the mtime from the previous mount
	// (for matador).
	hfsmp->hfs_last_mounted_mtime = hfsmp->hfs_mtime;

	if ( retval ) {
		if (HFS_MOUNT_DEBUG) { 
			printf("hfs_mountfs: encountered failure %d \n", retval);
		}
		goto error_exit;
	}

	mp->mnt_vfsstat.f_fsid.val[0] = dev;
	mp->mnt_vfsstat.f_fsid.val[1] = vfs_typenum(mp);
	vfs_setmaxsymlen(mp, 0);

	mp->mnt_vtable->vfc_vfsflags |= VFC_VFSNATIVEXATTR;
#if NAMEDSTREAMS
	mp->mnt_kern_flag |= MNTK_NAMED_STREAMS;
#endif
	if ((hfsmp->hfs_flags & HFS_STANDARD) == 0 ) {
		/* Tell VFS that we support directory hard links. */
		mp->mnt_vtable->vfc_vfsflags |= VFC_VFSDIRLINKS;
	} 
#if CONFIG_HFS_STD
	else {
		/* HFS standard doesn't support extended readdir! */
		mount_set_noreaddirext (mp);
	}
#endif

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
		 * Set the "danger" limit to 5% of the volume size or 512MB, whichever
		 * is less.  Set the "warning" limit to 10% of the volume size or 1GB,
		 * whichever is less.  And last, set the "desired" freespace level to
		 * to 11% of the volume size or 1.25GB, whichever is less.
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
			hfsmp->hfs_syncer = thread_call_allocate(hfs_syncer, hfsmp);
			if (hfsmp->hfs_syncer == NULL) {
				printf("hfs: failed to allocate syncer thread callback for %s (%s)\n",
						mp->mnt_vfsstat.f_mntfromname, mp->mnt_vfsstat.f_mntonname);
			}
		}
	}

	printf("hfs: mounted %s on device %s\n", (hfsmp->vcbVN ? (const char*) hfsmp->vcbVN : "unknown"),
            (devvp->v_name ? devvp->v_name : (isroot ? "root_device": "unknown device")));

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
		hfs_locks_destroy(hfsmp);
		hfs_delete_chash(hfsmp);
		hfs_idhash_destroy (hfsmp);

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
int
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

	printf("hfs: unmount initiated on %s on device %s\n", 
			(hfsmp->vcbVN ? (const char*) hfsmp->vcbVN : "unknown"),
			(hfsmp->hfs_devvp ? ((hfsmp->hfs_devvp->v_name ? hfsmp->hfs_devvp->v_name : "unknown device")) : "unknown device"));

	if ((retval = hfs_flushfiles(mp, flags, p)) && !force)
 		return (retval);

	if (hfsmp->hfs_flags & HFS_METADATA_ZONE)
		(void) hfs_recording_suspend(hfsmp);

    // Tidy up the syncer
	if (hfsmp->hfs_syncer)
	{
        hfs_syncer_lock(hfsmp);

        /* First, make sure everything else knows we don't want any more
           requests queued. */
        thread_call_t syncer = hfsmp->hfs_syncer;
        hfsmp->hfs_syncer = NULL;

        hfs_syncer_unlock(hfsmp);

        // Now deal with requests that are outstanding
        if (hfsmp->hfs_sync_incomplete) {
            if (thread_call_cancel(syncer)) {
                // We managed to cancel the timer so we're done
                hfsmp->hfs_sync_incomplete = FALSE;
            } else {
                // Syncer must be running right now so we have to wait
                hfs_syncer_lock(hfsmp);
                while (hfsmp->hfs_sync_incomplete)
                    hfs_syncer_wait(hfsmp);
                hfs_syncer_unlock(hfsmp);
            }
        }

        // Now we're safe to free the syncer
		thread_call_free(syncer);
	}

	if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
		if (hfsmp->hfs_summary_table) {
			int err = 0;
			/* 
		 	 * Take the bitmap lock to serialize against a concurrent bitmap scan still in progress 
			 */
			if (hfsmp->hfs_allocation_vp) {
				err = hfs_lock (VTOC(hfsmp->hfs_allocation_vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
			}
			FREE (hfsmp->hfs_summary_table, M_TEMP);
			hfsmp->hfs_summary_table = NULL;
			hfsmp->hfs_flags &= ~HFS_SUMMARY_TABLE;
			
			if (err == 0 && hfsmp->hfs_allocation_vp){
				hfs_unlock (VTOC(hfsmp->hfs_allocation_vp));
			}

		}
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
			(void) hfs_lock(VTOC(hfsmp->hfs_startup_vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
			retval = hfs_fsync(hfsmp->hfs_startup_vp, MNT_WAIT, 0, p);
			hfs_unlock(VTOC(hfsmp->hfs_startup_vp));
			if (retval && !force)
				goto err_exit;
		}

		if (hfsmp->hfs_attribute_vp) {
			(void) hfs_lock(VTOC(hfsmp->hfs_attribute_vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
			retval = hfs_fsync(hfsmp->hfs_attribute_vp, MNT_WAIT, 0, p);
			hfs_unlock(VTOC(hfsmp->hfs_attribute_vp));
			if (retval && !force)
				goto err_exit;
		}

		(void) hfs_lock(VTOC(hfsmp->hfs_catalog_vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		retval = hfs_fsync(hfsmp->hfs_catalog_vp, MNT_WAIT, 0, p);
		hfs_unlock(VTOC(hfsmp->hfs_catalog_vp));
		if (retval && !force)
			goto err_exit;
		
		(void) hfs_lock(VTOC(hfsmp->hfs_extents_vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		retval = hfs_fsync(hfsmp->hfs_extents_vp, MNT_WAIT, 0, p);
		hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
		if (retval && !force)
			goto err_exit;
			
		if (hfsmp->hfs_allocation_vp) {
			(void) hfs_lock(VTOC(hfsmp->hfs_allocation_vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
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
			lck_spin_lock(&hfsmp->vcbFreeExtLock);
			for(i=0; i < (int)hfsmp->vcbFreeExtCnt; i++) {
				if (hfsmp->vcbFreeExt[i].startBlock < min_start) {
					min_start = hfsmp->vcbFreeExt[i].startBlock;
				}
			}
			lck_spin_unlock(&hfsmp->vcbFreeExtLock);
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
		hfs_journal_flush(hfsmp, FALSE);
	}
	
	/*
	 *	Invalidate our caches and release metadata vnodes
	 */
	(void) hfsUnmount(hfsmp, p);

#if CONFIG_HFS_STD
	if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord) {
		(void) hfs_relconverter(hfsmp->hfs_encoding);
	}
#endif

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

	/*
	 * Last chance to dump unreferenced system files.
	 */
	(void) vflush(mp, NULLVP, FORCECLOSE);

#if HFS_SPARSE_DEV
	/* Drop our reference on the backing fs (if any). */
	if ((hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) && hfsmp->hfs_backingfs_rootvp) {
		struct vnode * tmpvp;

		hfsmp->hfs_flags &= ~HFS_HAS_SPARSE_DEVICE;
		tmpvp = hfsmp->hfs_backingfs_rootvp;
		hfsmp->hfs_backingfs_rootvp = NULLVP;
		vnode_rele(tmpvp);
	}
#endif /* HFS_SPARSE_DEV */

	vnode_rele(hfsmp->hfs_devvp);

	hfs_locks_destroy(hfsmp);
	hfs_delete_chash(hfsmp);
	hfs_idhash_destroy(hfsmp);
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
	return hfs_vget(VFSTOHFS(mp), (cnid_t)kHFSRootFolderID, vpp, 1, 0);
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
		uid = kauth_cred_getuid(vfs_context_ucred(context));
	cmd = cmds >> SUBCMDSHIFT;

	switch (cmd) {
	case Q_SYNC:
	case Q_QUOTASTAT:
		break;
	case Q_GETQUOTA:
		if (uid == kauth_cred_getuid(vfs_context_ucred(context)))
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
int
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
	if ((hfsmp->hfs_flags & HFS_STANDARD) == 0) {
		/* HFS+ & variants */
		if (hfsmp->jnl) {
			subtype |= HFS_SUBTYPE_JOURNALED;
		}
		if (hfsmp->hfs_flags & HFS_CASE_SENSITIVE) {
			subtype |= HFS_SUBTYPE_CASESENSITIVE;
		}
	}
#if CONFIG_HFS_STD
	else {
		/* HFS standard */
		subtype = HFS_SUBTYPE_STANDARDHFS;
	} 
#endif
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

	if (hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
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
int
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
		(void) hfs_lock(VTOC(btvp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
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


#if CONFIG_HFS_STD
	/*
	 * Force stale file system control information to be flushed.
	 */
	if (vcb->vcbSigWord == kHFSSigWord) {
		if ((error = VNOP_FSYNC(hfsmp->hfs_devvp, waitfor, context))) {
			allerror = error;
		}
	}
#endif

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
	    hfs_journal_flush(hfsmp, FALSE);
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

	result = hfs_vget(VFSTOHFS(mp), ntohl(hfsfhp->hfsfid_cnid), &nvp, 0, 0);
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
 * Initialize HFS filesystems, done only once per boot.
 *
 * HFS is not a kext-based file system.  This makes it difficult to find 
 * out when the last HFS file system was unmounted and call hfs_uninit() 
 * to deallocate data structures allocated in hfs_init().  Therefore we 
 * never deallocate memory allocated by lock attribute and group initializations 
 * in this function.
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
	hfs_spinlock_group = lck_grp_alloc_init("hfs-spinlock", hfs_group_attr);
	
#if HFS_COMPRESSION
	decmpfs_init();
#endif

	return (0);
}


/*
 * Destroy all locks, mutexes and spinlocks in hfsmp on unmount or failed mount
 */ 
static void 
hfs_locks_destroy(struct hfsmount *hfsmp)
{

	lck_mtx_destroy(&hfsmp->hfs_mutex, hfs_mutex_group);
	lck_mtx_destroy(&hfsmp->hfc_mutex, hfs_mutex_group);
	lck_rw_destroy(&hfsmp->hfs_global_lock, hfs_rwlock_group);
	lck_rw_destroy(&hfsmp->hfs_insync, hfs_rwlock_group);
	lck_spin_destroy(&hfsmp->vcbFreeExtLock, hfs_spinlock_group);

	return;
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
int
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
		struct cat_attr jnl_attr;
	    struct cat_attr	jinfo_attr;
		struct cat_fork jnl_fork;
		struct cat_fork jinfo_fork;
		buf_t jib_buf;
		uint64_t jib_blkno;
		uint32_t tmpblkno;
		uint64_t journal_byte_offset;
		uint64_t journal_size;
		vnode_t jib_vp = NULLVP;
		struct JournalInfoBlock local_jib;
		int err = 0;
		void *jnl = NULL;
		int lockflags;

		/* Only root can enable journaling */
		if (!kauth_cred_issuser(kauth_cred_get())) {
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

		/* Set up local copies of the initialization info */
		tmpblkno = (uint32_t) name[1];
		jib_blkno = (uint64_t) tmpblkno;
		journal_byte_offset = (uint64_t) name[2];
		journal_byte_offset *= hfsmp->blockSize;
		journal_byte_offset += hfsmp->hfsPlusIOPosOffset;
		journal_size = (uint64_t)((unsigned)name[3]);

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

		/*
		 * At this point, we have a copy of the metadata that lives in the catalog for the
		 * journal info block.  Compare that the journal info block's single extent matches
		 * that which was passed into this sysctl.  
		 *
		 * If it is different, deny the journal enable call.
		 */
		if (jinfo_fork.cf_blocks > 1) {
			/* too many blocks */
			return EINVAL;
		}

		if (jinfo_fork.cf_extents[0].startBlock != jib_blkno) {
			/* Wrong block */
			return EINVAL;
		}

		/*   
		 * We want to immediately purge the vnode for the JIB.
		 * 
		 * Because it was written to from userland, there's probably 
		 * a vnode somewhere in the vnode cache (possibly with UBC backed blocks). 
		 * So we bring the vnode into core, then immediately do whatever 
		 * we can to flush/vclean it out.  This is because those blocks will be 
		 * interpreted as user data, which may be treated separately on some platforms
		 * than metadata.  If the vnode is gone, then there cannot be backing blocks
		 * in the UBC.
		 */
		if (hfs_vget (hfsmp, jinfo_attr.ca_fileid, &jib_vp, 1, 0)) {
			return EINVAL;
		} 
		/*
		 * Now we have a vnode for the JIB. recycle it. Because we hold an iocount
		 * on the vnode, we'll just mark it for termination when the last iocount
		 * (hopefully ours), is dropped.
		 */
		vnode_recycle (jib_vp);
		err = vnode_put (jib_vp);
		if (err) {
			return EINVAL;	
		}

		/* Initialize the local copy of the JIB (just like hfs.util) */
		memset (&local_jib, 'Z', sizeof(struct JournalInfoBlock));
		local_jib.flags = SWAP_BE32(kJIJournalInFSMask);
		/* Note that the JIB's offset is in bytes */
		local_jib.offset = SWAP_BE64(journal_byte_offset);
		local_jib.size = SWAP_BE64(journal_size);  

		/* 
		 * Now write out the local JIB.  This essentially overwrites the userland
		 * copy of the JIB.  Read it as BLK_META to treat it as a metadata read/write.
		 */
		jib_buf = buf_getblk (hfsmp->hfs_devvp, 
				jib_blkno * (hfsmp->blockSize / hfsmp->hfs_logical_block_size), 
				hfsmp->blockSize, 0, 0, BLK_META);
		char* buf_ptr = (char*) buf_dataptr (jib_buf);

		/* Zero out the portion of the block that won't contain JIB data */
		memset (buf_ptr, 0, hfsmp->blockSize);

		bcopy(&local_jib, buf_ptr, sizeof(local_jib));
		if (buf_bwrite (jib_buf)) {
			return EIO;
		}		

		/* Force a flush track cache */
		(void) VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, context);


		/* Now proceed with full volume sync */
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
		jnl = journal_create(jvp, journal_byte_offset, journal_size, 
							 hfsmp->hfs_devvp,
							 hfsmp->hfs_logical_block_size,
							 0,
							 0,
							 hfs_sync_metadata, hfsmp->hfs_mp,
							 hfsmp->hfs_mp);

		/*
		 * Set up the trim callback function so that we can add
		 * recently freed extents to the free extent cache once
		 * the transaction that freed them is written to the
		 * journal on disk.
		 */
		if (jnl)
			journal_trim_set_callback(jnl, hfs_trim_callback, hfsmp);

		if (jnl == NULL) {
			printf("hfs: FAILED to create the journal!\n");
			if (jvp && jvp != hfsmp->hfs_devvp) {
				vnode_clearmountedon(jvp);
				VNOP_CLOSE(jvp, hfsmp->hfs_flags & HFS_READ_ONLY ? FREAD : FREAD|FWRITE, vfs_context_kernel());
			}
			jvp = NULL;

			return EINVAL;
		} 

		hfs_lock_global (hfsmp, HFS_EXCLUSIVE_LOCK);

		/*
		 * Flush all dirty metadata buffers.
		 */
		buf_flushdirtyblks(hfsmp->hfs_devvp, TRUE, 0, "hfs_sysctl");
		buf_flushdirtyblks(hfsmp->hfs_extents_vp, TRUE, 0, "hfs_sysctl");
		buf_flushdirtyblks(hfsmp->hfs_catalog_vp, TRUE, 0, "hfs_sysctl");
		buf_flushdirtyblks(hfsmp->hfs_allocation_vp, TRUE, 0, "hfs_sysctl");
		if (hfsmp->hfs_attribute_vp)
			buf_flushdirtyblks(hfsmp->hfs_attribute_vp, TRUE, 0, "hfs_sysctl");

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

		hfs_unlock_global (hfsmp);
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
		if (!kauth_cred_issuser(kauth_cred_get())) {
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

		hfs_lock_global (hfsmp, HFS_EXCLUSIVE_LOCK);

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
		
		hfs_unlock_global (hfsmp);

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
	} else if (name[0] == HFS_ENABLE_RESIZE_DEBUG) {
		hfs_resize_debug = 1;
		printf ("hfs_sysctl: Enabled volume resize debugging.\n");
		return 0;
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

	error = hfs_vget(hfsmp, (cnid_t)ino, vpp, 1, 0);
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
	    (hfs_lock(VTOC(*vpp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) == 0)) {
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
int
hfs_vget(struct hfsmount *hfsmp, cnid_t cnid, struct vnode **vpp, int skiplock, int allow_deleted)
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
	vp = hfs_chash_getvnode(hfsmp, cnid, 0, skiplock, allow_deleted);
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
		error = cat_idlookup(hfsmp, cnid, 0, 0, &cndesc, &cnattr, &cnfork);
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
		cnid_t lastid;
		struct cat_desc linkdesc;
		int linkerr = 0;
		
		cnattr.ca_linkref = linkref;
		bzero (&linkdesc, sizeof (linkdesc));

		/* 
		 * If the caller supplied the raw inode value, then we don't know exactly
		 * which hardlink they wanted. It's likely that they acquired the raw inode
		 * value BEFORE the item became a hardlink, in which case, they probably
		 * want the oldest link.  So request the oldest link from the catalog.
		 * 
		 * Unfortunately, this requires that we iterate through all N hardlinks. On the plus
		 * side, since we know that we want the last linkID, we can also have this one
		 * call give us back the name of the last ID, since it's going to have it in-hand...
		 */
		linkerr = hfs_lookup_lastlink (hfsmp, linkref, &lastid, &linkdesc);
		if ((linkerr == 0) && (lastid != 0)) {
			/* 
			 * Release any lingering buffers attached to our local descriptor.
			 * Then copy the name and other business into the cndesc 
			 */
			cat_releasedesc (&cndesc);
			bcopy (&linkdesc, &cndesc, sizeof(linkdesc));	
		}	
		/* If it failed, the linkref code will just use whatever it had in-hand below. */
	}

	if (linkref) {
		int newvnode_flags = 0;
		
		error = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr,
								&cnfork, &vp, &newvnode_flags);
		if (error == 0) {
			VTOC(vp)->c_flag |= C_HARDLINK;
			vnode_setmultipath(vp);
		}
	} else {
		struct componentname cn;
		int newvnode_flags = 0;

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
	
		error = hfs_getnewvnode(hfsmp, NULLVP, &cn, &cndesc, 0, &cnattr, 
								&cnfork, &vp, &newvnode_flags);

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
	int accounted_root_usecounts;
#if QUOTA
	int i;
#endif

	hfsmp = VFSTOHFS(mp);

	accounted_root_usecounts = 0;
#if QUOTA
	/*
	 * The open quota files have an indirect reference on
	 * the root directory vnode.  We must account for this
	 * extra reference when doing the intial vflush.
	 */
	if (((unsigned int)vfs_flags(mp)) & MNT_QUOTA) {
		/* Find out how many quota files we have open. */
		for (i = 0; i < MAXQUOTAS; i++) {
			if (hfsmp->hfs_qfiles[i].qf_vp != NULLVP)
				++accounted_root_usecounts;
		}
	}
#endif /* QUOTA */
	if (hfsmp->hfs_flags & HFS_CS) {
		++accounted_root_usecounts;
	}

	if (accounted_root_usecounts > 0) {
		/* Obtain the root vnode so we can skip over it. */
		skipvp = hfs_chash_getvnode(hfsmp, kHFSRootFolderID, 0, 0, 0);
	}

	error = vflush(mp, skipvp, SKIPSYSTEM | SKIPSWAP | flags);
	if (error != 0)
		return(error);

	error = vflush(mp, skipvp, SKIPSYSTEM | flags);

	if (skipvp) {
		/*
		 * See if there are additional references on the
		 * root vp besides the ones obtained from the open
		 * quota files and CoreStorage.
		 */
		if ((error == 0) &&
		    (vnode_isinuse(skipvp,  accounted_root_usecounts))) {
			error = EBUSY;  /* root directory is still open */
		}
		hfs_unlock(VTOC(skipvp));
		/* release the iocount from the hfs_chash_getvnode call above. */
		vnode_put(skipvp);
	}
	if (error && (flags & FORCECLOSE) == 0)
		return (error);

#if QUOTA
	if (((unsigned int)vfs_flags(mp)) & MNT_QUOTA) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if (hfsmp->hfs_qfiles[i].qf_vp == NULLVP)
				continue;
			hfs_quotaoff(p, mp, i);
		}
	}
#endif /* QUOTA */
	if (hfsmp->hfs_flags & HFS_CS) {
		error = VNOP_IOCTL(hfsmp->hfs_devvp, _DKIOCCSSETFSVNODE,
		    (caddr_t)NULL, 0, vfs_context_kernel());
		vnode_rele(skipvp);
		printf("hfs_flushfiles: VNOP_IOCTL(_DKIOCCSSETFSVNODE) failed with error code %d\n",
		    error);

		/* ignore the CS error and proceed with the unmount. */
		error = 0;
	}
	if (skipvp) {
		error = vflush(mp, NULLVP, SKIPSYSTEM | flags);
	}

	return (error);
}

/*
 * Update volume encoding bitmap (HFS Plus only)
 * 
 * Mark a legacy text encoding as in-use (as needed)
 * in the volume header of this HFS+ filesystem.
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

	/* Only mark the encoding as in-use if it wasn't already set */
	if (index < 64 && (hfsmp->encodingsBitmap & (u_int64_t)(1ULL << index)) == 0) {
		hfs_lock_mount (hfsmp);
		hfsmp->encodingsBitmap |= (u_int64_t)(1ULL << index);
		MarkVCBDirty(hfsmp);
		hfs_unlock_mount(hfsmp);
	}
}

/*
 * Update volume stats
 *
 * On journal volumes this will cause a volume header flush
 */
int
hfs_volupdate(struct hfsmount *hfsmp, enum volop op, int inroot)
{
	struct timeval tv;

	microtime(&tv);

	hfs_lock_mount (hfsmp);

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

	hfs_unlock_mount (hfsmp);

	if (hfsmp->jnl) {
		hfs_flushvolumeheader(hfsmp, 0, 0);
	}

	return (0);
}


#if CONFIG_HFS_STD
static int
hfs_flushMDB(struct hfsmount *hfsmp, int waitfor, int altflush)
{
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	struct filefork *fp;
	HFSMasterDirectoryBlock	*mdb;
	struct buf *bp = NULL;
	int retval;
	int sector_size;
	ByteCount namelen;

	sector_size = hfsmp->hfs_logical_block_size;
	retval = (int)buf_bread(hfsmp->hfs_devvp, (daddr64_t)HFS_PRI_SECTOR(sector_size), sector_size, NOCRED, &bp);
	if (retval) {
		if (bp)
			buf_brelse(bp);
		return retval;
	}

	hfs_lock_mount (hfsmp);

	mdb = (HFSMasterDirectoryBlock *)(buf_dataptr(bp) + HFS_PRI_OFFSET(sector_size));
    
	mdb->drCrDate	= SWAP_BE32 (UTCToLocal(to_hfs_time(vcb->hfs_itime)));
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

	hfs_unlock_mount (hfsmp);

	/* If requested, flush out the alternate MDB */
	if (altflush) {
		struct buf *alt_bp = NULL;

		if (buf_meta_bread(hfsmp->hfs_devvp, hfsmp->hfs_alt_id_sector, sector_size, NOCRED, &alt_bp) == 0) {
			bcopy(mdb, (char *)buf_dataptr(alt_bp) + HFS_ALT_OFFSET(sector_size), kMDBSize);

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
#endif

/*
 *  Flush any dirty in-memory mount data to the on-disk
 *  volume header.
 *
 *  Note: the on-disk volume signature is intentionally
 *  not flushed since the on-disk "H+" and "HX" signatures
 *  are always stored in-memory as "H+".
 */
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
#if CONFIG_HFS_STD
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return hfs_flushMDB(hfsmp, waitfor, altflush);
	}
#endif
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
		printf("hfs: err %d reading VH blk (vol=%s)\n", retval, vcb->vcbVN);
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

	hfs_lock_mount (hfsmp);

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
	hfs_unlock_mount (hfsmp);

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
	u_int64_t  sector_count;
	u_int32_t  sector_size;
	u_int32_t  phys_sector_size;
	u_int32_t  overage_blocks;	
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
		error = hfs_vget(hfsmp, kHFSRootFolderID, &vp, 0, 0);

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
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&sector_size, 0, context)) {
		return (ENXIO);
	}
	if (sector_size != hfsmp->hfs_logical_block_size) {
		return (ENXIO);
	}
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&sector_count, 0, context)) {
		return (ENXIO);
	}
	if ((sector_size * sector_count) < newsize) {
		printf("hfs_extendfs: not enough space on device (vol=%s)\n", hfsmp->vcbVN);
		return (ENOSPC);
	}
	error = VNOP_IOCTL(devvp, DKIOCGETPHYSICALBLOCKSIZE, (caddr_t)&phys_sector_size, 0, context);
	if (error) {
		if ((error != ENOTSUP) && (error != ENOTTY)) {
			return (ENXIO);
		}
		/* If ioctl is not supported, force physical and logical sector size to be same */
		phys_sector_size = sector_size;
	}
	oldsize = (u_int64_t)hfsmp->totalBlocks * (u_int64_t)hfsmp->blockSize;

	/*
	 * Validate new size.
	 */
	if ((newsize <= oldsize) || (newsize % sector_size) || (newsize % phys_sector_size)) {
		printf("hfs_extendfs: invalid size (newsize=%qu, oldsize=%qu)\n", newsize, oldsize);
		return (EINVAL);
	}
	newblkcnt = newsize / vcb->blockSize;
	if (newblkcnt > (u_int64_t)0xFFFFFFFF) {
		printf ("hfs_extendfs: current blockSize=%u too small for newsize=%qu\n", hfsmp->blockSize, newsize);
		return (EOVERFLOW);
	}

	addblks = newblkcnt - vcb->totalBlocks;

	if (hfs_resize_debug) {
		printf ("hfs_extendfs: old: size=%qu, blkcnt=%u\n", oldsize, hfsmp->totalBlocks);
		printf ("hfs_extendfs: new: size=%qu, blkcnt=%u, addblks=%u\n", newsize, (u_int32_t)newblkcnt, addblks);
	}
	printf("hfs_extendfs: will extend \"%s\" by %d blocks\n", vcb->vcbVN, addblks);

	hfs_lock_mount (hfsmp);
	if (hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS) {
		hfs_unlock_mount(hfsmp);
		error = EALREADY;
		goto out;
	}
	hfsmp->hfs_flags |= HFS_RESIZE_IN_PROGRESS;
	hfs_unlock_mount (hfsmp);
	
	/* Start with a clean journal. */
	hfs_journal_flush(hfsmp, TRUE);

	/*
	 * Enclose changes inside a transaction.
	 */
	if (hfs_start_transaction(hfsmp) != 0) {
		error = EINVAL;
		goto out;
	}
	transaction_begun = 1;


	/* Update the hfsmp fields for the physical information about the device */	
	prev_phys_block_count = hfsmp->hfs_logical_block_count;
	prev_alt_sector = hfsmp->hfs_alt_id_sector;

	hfsmp->hfs_logical_block_count = sector_count;
	/* 
	 * Note that the new AltVH location must be based on the device's EOF rather than the new
	 * filesystem's EOF, so we use logical_block_count here rather than newsize.
	 */
	hfsmp->hfs_alt_id_sector = (hfsmp->hfsPlusIOPosOffset / sector_size) +
	                          HFS_ALT_SECTOR(sector_size, hfsmp->hfs_logical_block_count);
	hfsmp->hfs_logical_bytes = (uint64_t) sector_count * (uint64_t) sector_size;


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

	/* 
	 * The allocation bitmap can contain unused bits that are beyond end of 
	 * current volume's allocation blocks.  Usually they are supposed to be 
	 * zero'ed out but there can be cases where they might be marked as used. 
	 * After extending the file system, those bits can represent valid 
	 * allocation blocks, so we mark all the bits from the end of current 
	 * volume to end of allocation bitmap as "free".
	 *
	 * Figure out the number of overage blocks before proceeding though,
	 * so we don't add more bytes to our I/O than necessary.  
	 * First figure out the total number of blocks representable by the 
	 * end of the bitmap file vs. the total number of blocks in the new FS.
	 * Then subtract away the number of blocks in the current FS.  This is how much
	 * we can mark as free right now without having to grow the bitmap file.
	 */
	overage_blocks = fp->ff_blocks * vcb->blockSize * 8;
	overage_blocks = MIN (overage_blocks, newblkcnt);
   	overage_blocks -= vcb->totalBlocks;

	BlockMarkFreeUnused(vcb, vcb->totalBlocks, overage_blocks);

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
				kEFAllMask | kEFNoClumpMask | kEFReserveMask 
				| kEFMetadataMask | kEFContigMask, &bytesAdded);

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
			printf("hfs_extendfs: error %d clearing blocks\n", error);
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
	vcb->totalBlocks += addblks;
	vcb->freeBlocks += addblks;
	MarkVCBDirty(vcb);
	error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
	if (error) {
		printf("hfs_extendfs: couldn't flush volume headers (%d)", error);
		/*
		 * Restore to old state.
		 */
		if (usedExtendFileC) {
			(void) TruncateFileC(vcb, fp, oldBitmapSize, 0, FORK_IS_RSRC(fp), 
								 FTOC(fp)->c_fileid, false);
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
		if (vcb->blockSize == 512) {
			if (BlockMarkAllocated(vcb, vcb->totalBlocks - 2, 2)) {
				hfs_mark_volume_inconsistent(hfsmp);
			}
		} else {
			if (BlockMarkAllocated(vcb, vcb->totalBlocks - 1, 1)) {
				hfs_mark_volume_inconsistent(hfsmp);
			}
		}
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
	 * Update the metadata zone size based on current volume size
	 */
	hfs_metadatazone_init(hfsmp, false);
	 
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

	/*
	 * Update the R/B Tree if necessary.  Since we don't have to drop the systemfile 
	 * locks in the middle of these operations like we do in the truncate case
	 * where we have to relocate files, we can only update the red-black tree
	 * if there were actual changes made to the bitmap.  Also, we can't really scan the 
	 * new portion of the bitmap before it has been allocated. The BlockMarkAllocated
	 * routines are smart enough to avoid the r/b tree if the portion they are manipulating is
	 * not currently controlled by the tree.  
	 *
	 * We only update hfsmp->allocLimit if totalBlocks actually increased. 
	 */
	if (error == 0) {
		UpdateAllocLimit(hfsmp, hfsmp->totalBlocks);
	}

	/* Release all locks and sync up journal content before 
	 * checking and extending, if required, the journal 
	 */
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		lockflags = 0;
	}
	if (transaction_begun) {
		hfs_end_transaction(hfsmp);
		hfs_journal_flush(hfsmp, TRUE);
		transaction_begun = 0;
	}

	/* Increase the journal size, if required. */
	error = hfs_extend_journal(hfsmp, sector_size, sector_count, context);
	if (error) {
		printf ("hfs_extendfs: Could not extend journal size\n");
		goto out_noalloc;
	}

	/* Log successful extending */
	printf("hfs_extendfs: extended \"%s\" to %d blocks (was %d blocks)\n",
	       hfsmp->vcbVN, hfsmp->totalBlocks, (u_int32_t)(oldsize/hfsmp->blockSize));
	
out:
	if (error && fp) {
		/* Restore allocation fork. */
		bcopy(&forkdata, &fp->ff_data, sizeof(forkdata));
		VTOC(vp)->c_blocks = fp->ff_blocks;
		
	}

out_noalloc:
	hfs_lock_mount (hfsmp);
	hfsmp->hfs_flags &= ~HFS_RESIZE_IN_PROGRESS;
	hfs_unlock_mount (hfsmp);
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (transaction_begun) {
		hfs_end_transaction(hfsmp);
		hfs_journal_flush(hfsmp, FALSE);
		/* Just to be sure, sync all data to the disk */
		(void) VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, context);
	}
	if (error) {
		printf ("hfs_extentfs: failed error=%d on vol=%s\n", MacToVFSError(error), hfsmp->vcbVN);
	}

	return MacToVFSError(error);
}

#define HFS_MIN_SIZE  (32LL * 1024LL * 1024LL)

/*
 * Truncate a file system (while still mounted).
 */
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
	Boolean disable_sparse = false;
	int error = 0;

	hfs_lock_mount (hfsmp);
	if (hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS) {
		hfs_unlock_mount (hfsmp);
		return (EALREADY);
	}
	hfsmp->hfs_flags |= HFS_RESIZE_IN_PROGRESS;
	hfsmp->hfs_resize_blocksmoved = 0;
	hfsmp->hfs_resize_totalblocks = 0;
	hfsmp->hfs_resize_progress = 0;
	hfs_unlock_mount (hfsmp);

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

	/* 
	 * Make sure that the file system has enough free blocks reclaim.
	 *
	 * Before resize, the disk is divided into four zones - 
	 * 	A. Allocated_Stationary - These are allocated blocks that exist 
	 * 	   before the new end of disk.  These blocks will not be 
	 * 	   relocated or modified during resize.
	 * 	B. Free_Stationary - These are free blocks that exist before the
	 * 	   new end of disk.  These blocks can be used for any new 
	 * 	   allocations during resize, including allocation for relocating 
	 * 	   data from the area of disk being reclaimed. 
	 * 	C. Allocated_To-Reclaim - These are allocated blocks that exist
	 *         beyond the new end of disk.  These blocks need to be reclaimed 
	 *         during resize by allocating equal number of blocks in Free 
	 *         Stationary zone and copying the data. 
	 *      D. Free_To-Reclaim - These are free blocks that exist beyond the 
	 *         new end of disk.  Nothing special needs to be done to reclaim
	 *         them. 
	 *
	 * Total number of blocks on the disk before resize:
	 * ------------------------------------------------
	 * 	Total Blocks = Allocated_Stationary + Free_Stationary + 
	 * 	               Allocated_To-Reclaim + Free_To-Reclaim
	 *
	 * Total number of blocks that need to be reclaimed:
	 * ------------------------------------------------
	 *	Blocks to Reclaim = Allocated_To-Reclaim + Free_To-Reclaim 
	 *
	 * Note that the check below also makes sure that we have enough space 
	 * to relocate data from Allocated_To-Reclaim to Free_Stationary.   
	 * Therefore we do not need to check total number of blocks to relocate 
	 * later in the code.
	 *
	 * The condition below gets converted to: 
	 *
	 * Allocated To-Reclaim + Free To-Reclaim >= Free Stationary + Free To-Reclaim 
	 *
	 * which is equivalent to:
	 *
	 *              Allocated To-Reclaim >= Free Stationary
	 */
	if (reclaimblks >= hfs_freeblks(hfsmp, 1)) {
		printf("hfs_truncatefs: insufficient space (need %u blocks; have %u free blocks)\n", reclaimblks, hfs_freeblks(hfsmp, 1));
		error = ENOSPC;
		goto out;
	}
	
	/* Start with a clean journal. */
	hfs_journal_flush(hfsmp, TRUE);
	
	if (hfs_start_transaction(hfsmp) != 0) {
		error = EINVAL;
		goto out;
	}
	transaction_begun = 1;
	
	/* Take the bitmap lock to update the alloc limit field */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	
	/*
	 * Prevent new allocations from using the part we're trying to truncate.
	 *
	 * NOTE: allocLimit is set to the allocation block number where the new
	 * alternate volume header will be.  That way there will be no files to
	 * interfere with allocating the new alternate volume header, and no files
	 * in the allocation blocks beyond (i.e. the blocks we're trying to
	 * truncate away.
	 *
	 * Also shrink the red-black tree if needed.
	 */
	if (hfsmp->blockSize == 512) {
		error = UpdateAllocLimit (hfsmp, newblkcnt - 2);
	}
	else {
		error = UpdateAllocLimit (hfsmp, newblkcnt - 1);
	}

	/* Sparse devices use first fit allocation which is not ideal 
	 * for volume resize which requires best fit allocation.  If a 
	 * sparse device is being truncated, disable the sparse device 
	 * property temporarily for the duration of resize.  Also reset 
	 * the free extent cache so that it is rebuilt as sorted by 
	 * totalBlocks instead of startBlock.  
	 *
	 * Note that this will affect all allocations on the volume and 
	 * ideal fix would be just to modify resize-related allocations, 
	 * but it will result in complexity like handling of two free 
	 * extent caches sorted differently, etc.  So we stick to this 
	 * solution for now. 
	 */
	hfs_lock_mount (hfsmp);
	if (hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
		hfsmp->hfs_flags &= ~HFS_HAS_SPARSE_DEVICE;
		ResetVCBFreeExtCache(hfsmp);
		disable_sparse = true;
	}
	
	/* 
	 * Update the volume free block count to reflect the total number 
	 * of free blocks that will exist after a successful resize.
	 * Relocation of extents will result in no net change in the total
	 * free space on the disk.  Therefore the code that allocates 
	 * space for new extent and deallocates the old extent explicitly 
	 * prevents updating the volume free block count.  It will also 
	 * prevent false disk full error when the number of blocks in 
	 * an extent being relocated is more than the free blocks that 
	 * will exist after the volume is resized.
	 */
	hfsmp->freeBlocks -= reclaimblks;
	updateFreeBlocks = true;
	hfs_unlock_mount(hfsmp);

	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		lockflags = 0;	
	}
	
	/*
	 * Update the metadata zone size to match the new volume size,
	 * and if it too less, metadata zone might be disabled.
	 */
	hfs_metadatazone_init(hfsmp, false);

	/*
	 * If some files have blocks at or beyond the location of the
	 * new alternate volume header, recalculate free blocks and 
	 * reclaim blocks.  Otherwise just update free blocks count.
	 *
	 * The current allocLimit is set to the location of new alternate 
	 * volume header, and reclaimblks are the total number of blocks 
	 * that need to be reclaimed.  So the check below is really 
	 * ignoring the blocks allocated for old alternate volume header. 
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
	 * Allocate last 1KB for alternate volume header.
	 */
	error = BlockMarkAllocated(hfsmp, hfsmp->allocLimit, (hfsmp->blockSize == 512) ? 2 : 1);
	if (error) {
		printf("hfs_truncatefs: Error %d allocating new alternate volume header\n", error);
		goto out;
	}

	/*
	 * Mark the old alternate volume header as free. 
	 * We don't bother shrinking allocation bitmap file.
	 */
	if (hfsmp->blockSize == 512) 
		(void) BlockMarkFree(hfsmp, hfsmp->totalBlocks - 2, 2);
	else 
		(void) BlockMarkFree(hfsmp, hfsmp->totalBlocks - 1, 1);

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
	hfsmp->hfs_logical_bytes = (uint64_t) hfsmp->hfs_logical_block_count * (uint64_t) hfsmp->hfs_logical_block_size;

	/*
	 * Note that although the logical block size is updated here, it is only done for
	 * the benefit of the partition management software.  The logical block count change 
	 * has not yet actually been propagated to the disk device yet. 
	 */

	hfsmp->hfs_alt_id_sector = HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size, hfsmp->hfs_logical_block_count);
	MarkVCBDirty(hfsmp);
	error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
	if (error)
		panic("hfs_truncatefs: unexpected error flushing volume header (%d)\n", error);

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
	/* 
	 * Update the allocLimit to acknowledge the last one or two blocks now.
	 * Add it to the tree as well if necessary.
	 */
	UpdateAllocLimit (hfsmp, hfsmp->totalBlocks);
	
	hfs_lock_mount (hfsmp);
	if (disable_sparse == true) {
		/* Now that resize is completed, set the volume to be sparse 
		 * device again so that all further allocations will be first 
		 * fit instead of best fit.  Reset free extent cache so that 
		 * it is rebuilt.
		 */
		hfsmp->hfs_flags |= HFS_HAS_SPARSE_DEVICE;
		ResetVCBFreeExtCache(hfsmp);
	}

	if (error && (updateFreeBlocks == true)) {
		hfsmp->freeBlocks += reclaimblks;
	}
	
	if (hfsmp->nextAllocation >= hfsmp->allocLimit) {
		hfsmp->nextAllocation = hfsmp->hfs_metazone_end + 1;
	}
	hfsmp->hfs_flags &= ~HFS_RESIZE_IN_PROGRESS;
	hfs_unlock_mount (hfsmp);
	
	/* On error, reset the metadata zone for original volume size */
	if (error && (updateFreeBlocks == true)) {
		hfs_metadatazone_init(hfsmp, false);
	}
	
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (transaction_begun) {
		hfs_end_transaction(hfsmp);
		hfs_journal_flush(hfsmp, FALSE);
		/* Just to be sure, sync all data to the disk */
		(void) VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, context);
	}

	if (error) {
		printf ("hfs_truncatefs: failed error=%d on vol=%s\n", MacToVFSError(error), hfsmp->vcbVN);
	}

	return MacToVFSError(error);
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
 *
 * At this point, for regular files, we hold the truncate lock exclusive
 * and the cnode lock exclusive.
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
#if CONFIG_PROTECT
	int cpenabled = 0;
#endif

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

#if CONFIG_PROTECT
	/* 
	 * Prepare the CP blob and get it ready for use, if necessary.
	 *
	 * Note that we specifically *exclude* system vnodes (catalog, bitmap, extents, EAs),
	 * because they are implicitly protected via the media key on iOS.  As such, they
	 * must not be relocated except with the media key.  So it is OK to not pass down
	 * a special cpentry to the IOMedia/LwVM code for handling. 
	 */
	if (!vnode_issystem (vp) && vnode_isreg(vp) && cp_fs_protected (hfsmp->hfs_mp)) {
		int cp_err = 0;
		/* 
		 * Ideally, the file whose extents we are about to manipulate is using the
		 * newer offset-based IVs so that we can manipulate it regardless of the 
		 * current lock state.  However, we must maintain support for older-style 
		 * EAs.  
		 * 
		 * For the older EA case, the IV was tied to the device LBA for file content.
		 * This means that encrypted data cannot be moved from one location to another
		 * in the filesystem without garbling the IV data.  As a result, we need to 
		 * access the file's plaintext because we cannot do our AES-symmetry trick 
		 * here.  This requires that we attempt a key-unwrap here (via cp_handle_relocate) 
		 * to make forward progress.  If the keys are unavailable then we will 
		 * simply stop the resize in its tracks here since we cannot move 
		 * this extent at this time.
		 */
		if ((cp->c_cpentry->cp_flags & CP_OFF_IV_ENABLED) == 0) {
			cp_err = cp_handle_relocate(cp, hfsmp);
		}

		if (cp_err) {
			printf ("hfs_copy_extent: cp_handle_relocate failed (%d) \n", cp_err);
			return cp_err;
		}

		cpenabled = 1;
	}
#endif


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

		/*
		 * Note that because this is an I/O to the device vp
		 * it is correct to have lblkno and blkno both point to the 
		 * start sector being read from.  If it were being issued against the
		 * underlying file then that would be different.
		 */

		/* Attach the new CP blob  to the buffer if needed */
#if CONFIG_PROTECT
		if (cpenabled) {
			if (cp->c_cpentry->cp_flags & CP_OFF_IV_ENABLED) {
				/* attach the RELOCATION_INFLIGHT flag for the underlying call to VNOP_STRATEGY */
				cp->c_cpentry->cp_flags |= CP_RELOCATION_INFLIGHT;
				buf_setcpaddr(bp, hfsmp->hfs_resize_cpentry);
			}
			else {
				/* 
				 * Use the cnode's cp key.  This file is tied to the 
				 * LBAs of the physical blocks that it occupies.
				 */
				buf_setcpaddr (bp, cp->c_cpentry);
			}
		
			/* Initialize the content protection file offset to start at 0 */
			buf_setcpoff (bp, 0);
		}
#endif

		/* Do the read */
		err = VNOP_STRATEGY(bp);
		if (!err)
			err = buf_biowait(bp);
		if (err) {
#if CONFIG_PROTECT
			/* Turn the flag off in error cases. */
			if (cpenabled) {
				cp->c_cpentry->cp_flags &= ~CP_RELOCATION_INFLIGHT;
			}
#endif
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

#if CONFIG_PROTECT
		/* Attach the CP to the buffer if needed */
		if (cpenabled) {
			if (cp->c_cpentry->cp_flags & CP_OFF_IV_ENABLED) {
				buf_setcpaddr(bp, hfsmp->hfs_resize_cpentry);
			}
			else {
				/* 
				 * Use the cnode's CP key.  This file is still tied
				 * to the LBAs of the physical blocks that it occupies.
				 */
				buf_setcpaddr (bp, cp->c_cpentry);
			}
			/* 
			 * The last STRATEGY call may have updated the cp file offset behind our
			 * back, so we cannot trust it.  Re-initialize the content protection
			 * file offset back to 0 before initiating the write portion of this I/O.
			 */
			buf_setcpoff (bp, 0);
		}			
#endif
			
		/* Do the write */
		vnode_startwrite(hfsmp->hfs_devvp);
		err = VNOP_STRATEGY(bp);
		if (!err) {
			err = buf_biowait(bp);
		}
#if CONFIG_PROTECT
		/* Turn the flag off regardless once the strategy call finishes. */
		if (cpenabled) {
			cp->c_cpentry->cp_flags &= ~CP_RELOCATION_INFLIGHT;
		}
#endif
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


/* Structure to store state of reclaiming extents from a 
 * given file.  hfs_reclaim_file()/hfs_reclaim_xattr() 
 * initializes the values in this structure which are then 
 * used by code that reclaims and splits the extents.
 */
struct hfs_reclaim_extent_info {
	struct vnode *vp;
	u_int32_t fileID;
	u_int8_t forkType;
	u_int8_t is_dirlink;                 /* Extent belongs to directory hard link */
	u_int8_t is_sysfile;                 /* Extent belongs to system file */
	u_int8_t is_xattr;                   /* Extent belongs to extent-based xattr */
	u_int8_t extent_index;
	int lockflags;                       /* Locks that reclaim and split code should grab before modifying the extent record */
	u_int32_t blocks_relocated;          /* Total blocks relocated for this file till now */
	u_int32_t recStartBlock;             /* File allocation block number (FABN) for current extent record */
	u_int32_t cur_blockCount;            /* Number of allocation blocks that have been checked for reclaim */
	struct filefork *catalog_fp;         /* If non-NULL, extent is from catalog record */
	union record {
		HFSPlusExtentRecord overflow;/* Extent record from overflow extents btree */
		HFSPlusAttrRecord xattr;     /* Attribute record for large EAs */
	} record;
	HFSPlusExtentDescriptor *extents;    /* Pointer to current extent record being processed.
					      * For catalog extent record, points to the correct 
					      * extent information in filefork.  For overflow extent 
					      * record, or xattr record, points to extent record 
					      * in the structure above
					      */
	struct cat_desc *dirlink_desc;	
	struct cat_attr *dirlink_attr;
	struct filefork *dirlink_fork;	      /* For directory hard links, fp points actually to this */
	struct BTreeIterator *iterator;       /* Shared read/write iterator, hfs_reclaim_file/xattr() 
                                               * use it for reading and hfs_reclaim_extent()/hfs_split_extent() 
					       * use it for writing updated extent record 
					       */ 
	struct FSBufferDescriptor btdata;     /* Shared btdata for reading/writing extent record, same as iterator above */
	u_int16_t recordlen;
	int overflow_count;                   /* For debugging, counter for overflow extent record */
	FCB *fcb;                             /* Pointer to the current btree being traversed */
};

/* 
 * Split the current extent into two extents, with first extent 
 * to contain given number of allocation blocks.  Splitting of 
 * extent creates one new extent entry which can result in 
 * shifting of many entries through all the extent records of a 
 * file, and/or creating a new extent record in the overflow 
 * extent btree. 
 *
 * Example:
 * The diagram below represents two consecutive extent records, 
 * for simplicity, lets call them record X and X+1 respectively.
 * Interesting extent entries have been denoted by letters.  
 * If the letter is unchanged before and after split, it means 
 * that the extent entry was not modified during the split.  
 * A '.' means that the entry remains unchanged after the split 
 * and is not relevant for our example.  A '0' means that the 
 * extent entry is empty.  
 *
 * If there isn't sufficient contiguous free space to relocate 
 * an extent (extent "C" below), we will have to break the one 
 * extent into multiple smaller extents, and relocate each of 
 * the smaller extents individually.  The way we do this is by 
 * finding the largest contiguous free space that is currently 
 * available (N allocation blocks), and then convert extent "C" 
 * into two extents, C1 and C2, that occupy exactly the same 
 * allocation blocks as extent C.  Extent C1 is the first 
 * N allocation blocks of extent C, and extent C2 is the remainder 
 * of extent C.  Then we can relocate extent C1 since we know 
 * we have enough contiguous free space to relocate it in its 
 * entirety.  We then repeat the process starting with extent C2. 
 *
 * In record X, only the entries following entry C are shifted, and 
 * the original entry C is replaced with two entries C1 and C2 which
 * are actually two extent entries for contiguous allocation blocks.
 *
 * Note that the entry E from record X is shifted into record X+1 as 
 * the new first entry.  Since the first entry of record X+1 is updated, 
 * the FABN will also get updated with the blockCount of entry E.  
 * This also results in shifting of all extent entries in record X+1.  
 * Note that the number of empty entries after the split has been 
 * changed from 3 to 2. 
 *
 * Before:
 *               record X                           record X+1
 *  ---------------------===---------     ---------------------------------
 *  | A | . | . | . | B | C | D | E |     | F | . | . | . | G | 0 | 0 | 0 |
 *  ---------------------===---------     ---------------------------------    
 *
 * After:
 *  ---------------------=======-----     ---------------------------------
 *  | A | . | . | . | B | C1| C2| D |     | E | F | . | . | . | G | 0 | 0 |
 *  ---------------------=======-----     ---------------------------------    
 *
 *  C1.startBlock = C.startBlock          
 *  C1.blockCount = N
 *
 *  C2.startBlock = C.startBlock + N
 *  C2.blockCount = C.blockCount - N
 *
 *                                        FABN = old FABN - E.blockCount
 *
 * Inputs: 
 *	extent_info -   This is the structure that contains state about 
 *	                the current file, extent, and extent record that 
 *	                is being relocated.  This structure is shared 
 *	                among code that traverses through all the extents 
 *	                of the file, code that relocates extents, and 
 *	                code that splits the extent. 
 *	newBlockCount - The blockCount of the extent to be split after 
 *	                successfully split operation.
 * Output:
 * 	Zero on success, non-zero on failure.
 */
static int 
hfs_split_extent(struct hfs_reclaim_extent_info *extent_info, uint32_t newBlockCount)
{
	int error = 0;
	int index = extent_info->extent_index;
	int i;
	HFSPlusExtentDescriptor shift_extent; /* Extent entry that should be shifted into next extent record */
	HFSPlusExtentDescriptor last_extent;
	HFSPlusExtentDescriptor *extents; /* Pointer to current extent record being manipulated */
	HFSPlusExtentRecord *extents_rec = NULL;
	HFSPlusExtentKey *extents_key = NULL;
	HFSPlusAttrRecord *xattr_rec = NULL;
	HFSPlusAttrKey *xattr_key = NULL;
	struct BTreeIterator iterator;
	struct FSBufferDescriptor btdata;
	uint16_t reclen;
	uint32_t read_recStartBlock;	/* Starting allocation block number to read old extent record */
	uint32_t write_recStartBlock;	/* Starting allocation block number to insert newly updated extent record */
	Boolean create_record = false;
	Boolean is_xattr;
	struct cnode *cp;
       
	is_xattr = extent_info->is_xattr;
	extents = extent_info->extents;
	cp = VTOC(extent_info->vp);

	if (newBlockCount == 0) {
		if (hfs_resize_debug) {
			printf ("hfs_split_extent: No splitting required for newBlockCount=0\n");
		}
		return error;
	}

	if (hfs_resize_debug) {
		printf ("hfs_split_extent: Split record:%u recStartBlock=%u %u:(%u,%u) for %u blocks\n", extent_info->overflow_count, extent_info->recStartBlock, index, extents[index].startBlock, extents[index].blockCount, newBlockCount);
	}

	/* Extents overflow btree can not have more than 8 extents.  
	 * No split allowed if the 8th extent is already used. 
	 */
	if ((extent_info->fileID == kHFSExtentsFileID) && (extents[kHFSPlusExtentDensity - 1].blockCount != 0)) {
		printf ("hfs_split_extent: Maximum 8 extents allowed for extents overflow btree, cannot split further.\n");
		error = ENOSPC;
		goto out;
	}

	/* Determine the starting allocation block number for the following
	 * overflow extent record, if any, before the current record 
	 * gets modified. 
	 */
	read_recStartBlock = extent_info->recStartBlock;
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		if (extents[i].blockCount == 0) {
			break;
		}
		read_recStartBlock += extents[i].blockCount;
	}

	/* Shift and split */
	if (index == kHFSPlusExtentDensity-1) {
		/* The new extent created after split will go into following overflow extent record */
		shift_extent.startBlock = extents[index].startBlock + newBlockCount;
		shift_extent.blockCount = extents[index].blockCount - newBlockCount;

		/* Last extent in the record will be split, so nothing to shift */
	} else {
		/* Splitting of extents can result in at most of one 
		 * extent entry to be shifted into following overflow extent 
		 * record.  So, store the last extent entry for later. 
		 */
		shift_extent = extents[kHFSPlusExtentDensity-1];
		if ((hfs_resize_debug) && (shift_extent.blockCount != 0)) {
			printf ("hfs_split_extent: Save 7:(%u,%u) to shift into overflow record\n", shift_extent.startBlock, shift_extent.blockCount);
		}

		/* Start shifting extent information from the end of the extent 
		 * record to the index where we want to insert the new extent.
		 * Note that kHFSPlusExtentDensity-1 is already saved above, and 
		 * does not need to be shifted.  The extent entry that is being 
		 * split does not get shifted.
		 */
		for (i = kHFSPlusExtentDensity-2; i > index; i--) {
			if (hfs_resize_debug) {
				if (extents[i].blockCount) {
					printf ("hfs_split_extent: Shift %u:(%u,%u) to %u:(%u,%u)\n", i, extents[i].startBlock, extents[i].blockCount, i+1, extents[i].startBlock, extents[i].blockCount);
				}
			}
			extents[i+1] = extents[i];
		}
	}

	if (index == kHFSPlusExtentDensity-1) {
		/* The second half of the extent being split will be the overflow 
		 * entry that will go into following overflow extent record.  The
		 * value has been stored in 'shift_extent' above, so there is 
		 * nothing to be done here.
		 */
	} else {
		/* Update the values in the second half of the extent being split 
		 * before updating the first half of the split.  Note that the 
		 * extent to split or first half of the split is at index 'index' 
		 * and a new extent or second half of the split will be inserted at 
		 * 'index+1' or into following overflow extent record. 
		 */ 
		extents[index+1].startBlock = extents[index].startBlock + newBlockCount;
		extents[index+1].blockCount = extents[index].blockCount - newBlockCount;
	}
	/* Update the extent being split, only the block count will change */
	extents[index].blockCount = newBlockCount;

	if (hfs_resize_debug) {
		printf ("hfs_split_extent: Split %u:(%u,%u) and ", index, extents[index].startBlock, extents[index].blockCount);
		if (index != kHFSPlusExtentDensity-1) {
			printf ("%u:(%u,%u)\n", index+1, extents[index+1].startBlock, extents[index+1].blockCount);
		} else {
			printf ("overflow:(%u,%u)\n", shift_extent.startBlock, shift_extent.blockCount);
		}
	}

	/* Write out information about the newly split extent to the disk */
	if (extent_info->catalog_fp) {
		/* (extent_info->catalog_fp != NULL) means the newly split 
		 * extent exists in the catalog record.  This means that 
		 * the cnode was updated.  Therefore, to write out the changes,
		 * mark the cnode as modified.   We cannot call hfs_update()
		 * in this function because the caller hfs_reclaim_extent() 
		 * is holding the catalog lock currently.
		 */
		cp->c_flag |= C_MODIFIED;
	} else {
		/* The newly split extent is for large EAs or is in overflow 
		 * extent record, so update it directly in the btree using the 
		 * iterator information from the shared extent_info structure
	 	 */
		error = BTReplaceRecord(extent_info->fcb, extent_info->iterator, 
				&(extent_info->btdata), extent_info->recordlen);
		if (error) {
			printf ("hfs_split_extent: fileID=%u BTReplaceRecord returned error=%d\n", extent_info->fileID, error);
			goto out;
		}
	}
		
	/* No extent entry to be shifted into another extent overflow record */
	if (shift_extent.blockCount == 0) {
		if (hfs_resize_debug) {
			printf ("hfs_split_extent: No extent entry to be shifted into overflow records\n");
		}
		error = 0;
		goto out;
	}

	/* The overflow extent entry has to be shifted into an extent 
	 * overflow record.  This means that we might have to shift 
	 * extent entries from all subsequent overflow records by one. 
	 * We start iteration from the first record to the last record, 
	 * and shift the extent entry from one record to another.  
	 * We might have to create a new extent record for the last 
	 * extent entry for the file. 
	 */
	
	/* Initialize iterator to search the next record */
	bzero(&iterator, sizeof(iterator));
	if (is_xattr) {
		/* Copy the key from the iterator that was used to update the modified attribute record. */
		xattr_key = (HFSPlusAttrKey *)&(iterator.key);
		bcopy((HFSPlusAttrKey *)&(extent_info->iterator->key), xattr_key, sizeof(HFSPlusAttrKey));
		/* Note: xattr_key->startBlock will be initialized later in the iteration loop */

		MALLOC(xattr_rec, HFSPlusAttrRecord *, 
				sizeof(HFSPlusAttrRecord), M_TEMP, M_WAITOK);
		if (xattr_rec == NULL) {
			error = ENOMEM;
			goto out;
		}
		btdata.bufferAddress = xattr_rec;
		btdata.itemSize = sizeof(HFSPlusAttrRecord);
		btdata.itemCount = 1;
		extents = xattr_rec->overflowExtents.extents;
	} else {
		/* Initialize the extent key for the current file */
		extents_key = (HFSPlusExtentKey *) &(iterator.key);
		extents_key->keyLength = kHFSPlusExtentKeyMaximumLength;
		extents_key->forkType = extent_info->forkType;
		extents_key->fileID = extent_info->fileID;
		/* Note: extents_key->startBlock will be initialized later in the iteration loop */
		
		MALLOC(extents_rec, HFSPlusExtentRecord *, 
				sizeof(HFSPlusExtentRecord), M_TEMP, M_WAITOK);
		if (extents_rec == NULL) {
			error = ENOMEM;
			goto out;
		}
		btdata.bufferAddress = extents_rec;
		btdata.itemSize = sizeof(HFSPlusExtentRecord);
		btdata.itemCount = 1;
		extents = extents_rec[0];
	}

	/* The overflow extent entry has to be shifted into an extent 
	 * overflow record.  This means that we might have to shift 
	 * extent entries from all subsequent overflow records by one. 
	 * We start iteration from the first record to the last record, 
	 * examine one extent record in each iteration and shift one 
	 * extent entry from one record to another.  We might have to 
	 * create a new extent record for the last extent entry for the 
	 * file. 
	 *
	 * If shift_extent.blockCount is non-zero, it means that there is 
	 * an extent entry that needs to be shifted into the next 
	 * overflow extent record.  We keep on going till there are no such 
	 * entries left to be shifted.  This will also change the starting 
	 * allocation block number of the extent record which is part of 
	 * the key for the extent record in each iteration.  Note that 
	 * because the extent record key is changing while we are searching, 
	 * the record can not be updated directly, instead it has to be 
	 * deleted and inserted again.
	 */
	while (shift_extent.blockCount) {
		if (hfs_resize_debug) {
			printf ("hfs_split_extent: Will shift (%u,%u) into overflow record with startBlock=%u\n", shift_extent.startBlock, shift_extent.blockCount, read_recStartBlock);
		}

		/* Search if there is any existing overflow extent record
		 * that matches the current file and the logical start block 
		 * number.
		 *
		 * For this, the logical start block number in the key is 
		 * the value calculated based on the logical start block 
		 * number of the current extent record and the total number 
		 * of blocks existing in the current extent record.  
		 */
		if (is_xattr) {
			xattr_key->startBlock = read_recStartBlock;
		} else {
			extents_key->startBlock = read_recStartBlock;
		}
		error = BTSearchRecord(extent_info->fcb, &iterator, &btdata, &reclen, &iterator);
		if (error) {
			if (error != btNotFound) {
				printf ("hfs_split_extent: fileID=%u startBlock=%u BTSearchRecord error=%d\n", extent_info->fileID, read_recStartBlock, error);
				goto out;
			}
			/* No matching record was found, so create a new extent record.
			 * Note:  Since no record was found, we can't rely on the 
			 * btree key in the iterator any longer.  This will be initialized
			 * later before we insert the record.
			 */
			create_record = true;
		}
	
		/* The extra extent entry from the previous record is being inserted
		 * as the first entry in the current extent record.  This will change 
		 * the file allocation block number (FABN) of the current extent 
		 * record, which is the startBlock value from the extent record key.
		 * Since one extra entry is being inserted in the record, the new 
		 * FABN for the record will less than old FABN by the number of blocks 
		 * in the new extent entry being inserted at the start.  We have to 
		 * do this before we update read_recStartBlock to point at the 
		 * startBlock of the following record.
		 */
		write_recStartBlock = read_recStartBlock - shift_extent.blockCount;
		if (hfs_resize_debug) {
			if (create_record) {
				printf ("hfs_split_extent: No records found for startBlock=%u, will create new with startBlock=%u\n", read_recStartBlock, write_recStartBlock);
			}
		}

		/* Now update the read_recStartBlock to account for total number 
		 * of blocks in this extent record.  It will now point to the 
		 * starting allocation block number for the next extent record.
		 */
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			if (extents[i].blockCount == 0) {
				break;
			}
			read_recStartBlock += extents[i].blockCount;
		}

		if (create_record == true) {
			/* Initialize new record content with only one extent entry */
			bzero(extents, sizeof(HFSPlusExtentRecord));
			/* The new record will contain only one extent entry */
			extents[0] = shift_extent;
			/* There are no more overflow extents to be shifted */
			shift_extent.startBlock = shift_extent.blockCount = 0;

			if (is_xattr) {
				/* BTSearchRecord above returned btNotFound,
				 * but since the attribute btree is never empty
				 * if we are trying to insert new overflow 
				 * record for the xattrs, the extents_key will
				 * contain correct data.  So we don't need to 
				 * re-initialize it again like below. 
				 */

				/* Initialize the new xattr record */
				xattr_rec->recordType = kHFSPlusAttrExtents; 
				xattr_rec->overflowExtents.reserved = 0;
				reclen = sizeof(HFSPlusAttrExtents);
			} else {
				/* BTSearchRecord above returned btNotFound, 
				 * which means that extents_key content might 
				 * not correspond to the record that we are 
				 * trying to create, especially when the extents 
				 * overflow btree is empty.  So we reinitialize 
				 * the extents_key again always. 
				 */
				extents_key->keyLength = kHFSPlusExtentKeyMaximumLength;
				extents_key->forkType = extent_info->forkType;
				extents_key->fileID = extent_info->fileID;

				/* Initialize the new extent record */
				reclen = sizeof(HFSPlusExtentRecord);
			}
		} else {
			/* The overflow extent entry from previous record will be 
			 * the first entry in this extent record.  If the last 
			 * extent entry in this record is valid, it will be shifted 
			 * into the following extent record as its first entry.  So 
			 * save the last entry before shifting entries in current 
			 * record.
			 */
			last_extent = extents[kHFSPlusExtentDensity-1];
			
			/* Shift all entries by one index towards the end */
			for (i = kHFSPlusExtentDensity-2; i >= 0; i--) {
				extents[i+1] = extents[i];
			}

			/* Overflow extent entry saved from previous record 
			 * is now the first entry in the current record.
			 */
			extents[0] = shift_extent;

			if (hfs_resize_debug) {
				printf ("hfs_split_extent: Shift overflow=(%u,%u) to record with updated startBlock=%u\n", shift_extent.startBlock, shift_extent.blockCount, write_recStartBlock);
			}

			/* The last entry from current record will be the 
			 * overflow entry which will be the first entry for 
			 * the following extent record.
			 */
			shift_extent = last_extent;

			/* Since the key->startBlock is being changed for this record, 
			 * it should be deleted and inserted with the new key.
			 */
			error = BTDeleteRecord(extent_info->fcb, &iterator);
			if (error) {
				printf ("hfs_split_extent: fileID=%u startBlock=%u BTDeleteRecord error=%d\n", extent_info->fileID, read_recStartBlock, error);
				goto out;
			}
			if (hfs_resize_debug) {
				printf ("hfs_split_extent: Deleted extent record with startBlock=%u\n", (is_xattr ? xattr_key->startBlock : extents_key->startBlock));
			}
		}

		/* Insert the newly created or modified extent record */
		bzero(&iterator.hint, sizeof(iterator.hint));
		if (is_xattr) {
			xattr_key->startBlock = write_recStartBlock;
		} else {
			extents_key->startBlock = write_recStartBlock;
		}
		error = BTInsertRecord(extent_info->fcb, &iterator, &btdata, reclen);
		if (error) {
			printf ("hfs_split_extent: fileID=%u, startBlock=%u BTInsertRecord error=%d\n", extent_info->fileID, write_recStartBlock, error);
			goto out;
		}
		if (hfs_resize_debug) {
			printf ("hfs_split_extent: Inserted extent record with startBlock=%u\n", write_recStartBlock);
		}
	}

out:
	/* 
	 * Extents overflow btree or attributes btree headers might have 
	 * been modified during the split/shift operation, so flush the 
	 * changes to the disk while we are inside journal transaction.  
	 * We should only be able to generate I/O that modifies the B-Tree 
	 * header nodes while we're in the middle of a journal transaction.  
	 * Otherwise it might result in panic during unmount.
	 */
	BTFlushPath(extent_info->fcb);

	if (extents_rec) {
		FREE (extents_rec, M_TEMP);
	}
	if (xattr_rec) {
		FREE (xattr_rec, M_TEMP);
	}
	return error;
}


/* 
 * Relocate an extent if it lies beyond the expected end of volume.
 *
 * This function is called for every extent of the file being relocated.  
 * It allocates space for relocation, copies the data, deallocates 
 * the old extent, and update corresponding on-disk extent.  If the function 
 * does not find contiguous space to  relocate an extent, it splits the 
 * extent in smaller size to be able to relocate it out of the area of 
 * disk being reclaimed.  As an optimization, if an extent lies partially 
 * in the area of the disk being reclaimed, it is split so that we only 
 * have to relocate the area that was overlapping with the area of disk
 * being reclaimed. 
 *
 * Note that every extent is relocated in its own transaction so that 
 * they do not overwhelm the journal.  This function handles the extent
 * record that exists in the catalog record, extent record from overflow 
 * extents btree, and extents for large EAs.
 *
 * Inputs: 
 *	extent_info - This is the structure that contains state about 
 *	              the current file, extent, and extent record that 
 *	              is being relocated.  This structure is shared 
 *	              among code that traverses through all the extents 
 *	              of the file, code that relocates extents, and 
 *	              code that splits the extent. 
 */
static int
hfs_reclaim_extent(struct hfsmount *hfsmp, const u_long allocLimit, struct hfs_reclaim_extent_info *extent_info, vfs_context_t context)
{
	int error = 0;
	int index;
	struct cnode *cp;
	u_int32_t oldStartBlock;
	u_int32_t oldBlockCount;
	u_int32_t newStartBlock;
	u_int32_t newBlockCount;
	u_int32_t roundedBlockCount;
	uint16_t node_size;
	uint32_t remainder_blocks;
	u_int32_t alloc_flags;
	int blocks_allocated = false;

	index = extent_info->extent_index;
	cp = VTOC(extent_info->vp);

	oldStartBlock = extent_info->extents[index].startBlock;
	oldBlockCount = extent_info->extents[index].blockCount;

	if (0 && hfs_resize_debug) {
		printf ("hfs_reclaim_extent: Examine record:%u recStartBlock=%u, %u:(%u,%u)\n", extent_info->overflow_count, extent_info->recStartBlock, index, oldStartBlock, oldBlockCount);
	}

	/* If the current extent lies completely within allocLimit, 
	 * it does not require any relocation. 
	 */
	if ((oldStartBlock + oldBlockCount) <= allocLimit) {
		extent_info->cur_blockCount += oldBlockCount;
		return error;
	} 

	/* Every extent should be relocated in its own transaction
	 * to make sure that we don't overflow the journal buffer.
	 */
	error = hfs_start_transaction(hfsmp);
	if (error) {
		return error;
	}
	extent_info->lockflags = hfs_systemfile_lock(hfsmp, extent_info->lockflags, HFS_EXCLUSIVE_LOCK);

	/* Check if the extent lies partially in the area to reclaim, 
	 * i.e. it starts before allocLimit and ends beyond allocLimit.  
	 * We have already skipped extents that lie completely within 
	 * allocLimit in the check above, so we only check for the 
	 * startBlock.  If it lies partially, split it so that we 
	 * only relocate part of the extent.
	 */
	if (oldStartBlock < allocLimit) {
		newBlockCount = allocLimit - oldStartBlock;

		if (hfs_resize_debug) {
			int idx = extent_info->extent_index;
			printf ("hfs_reclaim_extent: Split straddling extent %u:(%u,%u) for %u blocks\n", idx, extent_info->extents[idx].startBlock, extent_info->extents[idx].blockCount, newBlockCount);
		}

		/* If the extent belongs to a btree, check and trim 
		 * it to be multiple of the node size. 
		 */
		if (extent_info->is_sysfile) {
			node_size = get_btree_nodesize(extent_info->vp);
			/* If the btree node size is less than the block size, 
			 * splitting this extent will not split a node across 
			 * different extents.  So we only check and trim if 
			 * node size is more than the allocation block size. 
			 */ 
			if (node_size > hfsmp->blockSize) {
				remainder_blocks = newBlockCount % (node_size / hfsmp->blockSize);
				if (remainder_blocks) {
					newBlockCount -= remainder_blocks;
					if (hfs_resize_debug) {
						printf ("hfs_reclaim_extent: Round-down newBlockCount to be multiple of nodeSize, node_allocblks=%u, old=%u, new=%u\n", node_size/hfsmp->blockSize, newBlockCount + remainder_blocks, newBlockCount);
					}
				}
			}
			/* The newBlockCount is zero because of rounding-down so that
			 * btree nodes are not split across extents.  Therefore this
			 * straddling extent across resize-boundary does not require 
			 * splitting.  Skip over to relocating of complete extent.
			 */
			if (newBlockCount == 0) {
				if (hfs_resize_debug) {
					printf ("hfs_reclaim_extent: After round-down newBlockCount=0, skip split, relocate full extent\n");
				}
				goto relocate_full_extent;
			}
		}

		/* Split the extents into two parts --- the first extent lies
		 * completely within allocLimit and therefore does not require
		 * relocation.  The second extent will require relocation which
		 * will be handled when the caller calls this function again 
		 * for the next extent. 
		 */
		error = hfs_split_extent(extent_info, newBlockCount);
		if (error == 0) {
			/* Split success, no relocation required */
			goto out;
		}
		/* Split failed, so try to relocate entire extent */
		if (hfs_resize_debug) {
			int idx = extent_info->extent_index;
			printf ("hfs_reclaim_extent: Split straddling extent %u:(%u,%u) for %u blocks failed, relocate full extent\n", idx, extent_info->extents[idx].startBlock, extent_info->extents[idx].blockCount, newBlockCount);
		}
	}

relocate_full_extent:
	/* At this point, the current extent requires relocation.  
	 * We will try to allocate space equal to the size of the extent 
	 * being relocated first to try to relocate it without splitting.  
	 * If the allocation fails, we will try to allocate contiguous 
	 * blocks out of metadata zone.  If that allocation also fails, 
	 * then we will take a whatever contiguous block run is returned 
	 * by the allocation, split the extent into two parts, and then 
	 * relocate the first splitted extent. 
	 */
	alloc_flags = HFS_ALLOC_FORCECONTIG | HFS_ALLOC_SKIPFREEBLKS;  
	if (extent_info->is_sysfile) {
		alloc_flags |= HFS_ALLOC_METAZONE;
	}

	error = BlockAllocate(hfsmp, 1, oldBlockCount, oldBlockCount, alloc_flags, 
			&newStartBlock, &newBlockCount);
	if ((extent_info->is_sysfile == false) && 
	    ((error == dskFulErr) || (error == ENOSPC))) {
		/* For non-system files, try reallocating space in metadata zone */
		alloc_flags |= HFS_ALLOC_METAZONE;
		error = BlockAllocate(hfsmp, 1, oldBlockCount, oldBlockCount, 
				alloc_flags, &newStartBlock, &newBlockCount);
	} 
	if ((error == dskFulErr) || (error == ENOSPC)) {
		/* We did not find desired contiguous space for this extent.  
		 * So don't worry about getting contiguity anymore.  Also, allow using
		 * blocks that were recently deallocated.
		 */
		alloc_flags &= ~HFS_ALLOC_FORCECONTIG;
		alloc_flags |= HFS_ALLOC_FLUSHTXN;

		error = BlockAllocate(hfsmp, 1, oldBlockCount, oldBlockCount, 
				alloc_flags, &newStartBlock, &newBlockCount);
		if (error) {
			printf ("hfs_reclaim_extent: fileID=%u start=%u, %u:(%u,%u) BlockAllocate error=%d\n", extent_info->fileID, extent_info->recStartBlock, index, oldStartBlock, oldBlockCount, error);
			goto out;
		}
		blocks_allocated = true;

		/* The number of blocks allocated is less than the requested 
		 * number of blocks.  For btree extents, check and trim the 
		 * extent to be multiple of the node size. 
		 */
		if (extent_info->is_sysfile) {
			node_size = get_btree_nodesize(extent_info->vp);
			if (node_size > hfsmp->blockSize) {
				remainder_blocks = newBlockCount % (node_size / hfsmp->blockSize);
				if (remainder_blocks) {
					roundedBlockCount = newBlockCount - remainder_blocks;
					/* Free tail-end blocks of the newly allocated extent */
					BlockDeallocate(hfsmp, newStartBlock + roundedBlockCount,
							       newBlockCount - roundedBlockCount,
							       HFS_ALLOC_SKIPFREEBLKS);
					newBlockCount = roundedBlockCount;
					if (hfs_resize_debug) {
						printf ("hfs_reclaim_extent: Fixing extent block count, node_blks=%u, old=%u, new=%u\n", node_size/hfsmp->blockSize, newBlockCount + remainder_blocks, newBlockCount);
					}
					if (newBlockCount == 0) {
						printf ("hfs_reclaim_extent: Not enough contiguous blocks available to relocate fileID=%d\n", extent_info->fileID);
						error = ENOSPC;
						goto out;
					}
				}
			}
		}

		/* The number of blocks allocated is less than the number of 
		 * blocks requested, so split this extent --- the first extent 
		 * will be relocated as part of this function call and the caller
		 * will handle relocating the second extent by calling this 
		 * function again for the second extent. 
		 */
		error = hfs_split_extent(extent_info, newBlockCount);
		if (error) {
			printf ("hfs_reclaim_extent: fileID=%u start=%u, %u:(%u,%u) split error=%d\n", extent_info->fileID, extent_info->recStartBlock, index, oldStartBlock, oldBlockCount, error);
			goto out;
		}
		oldBlockCount = newBlockCount;
	}
	if (error) {
		printf ("hfs_reclaim_extent: fileID=%u start=%u, %u:(%u,%u) contig BlockAllocate error=%d\n", extent_info->fileID, extent_info->recStartBlock, index, oldStartBlock, oldBlockCount, error);
		goto out;
	}
	blocks_allocated = true;

	/* Copy data from old location to new location */
	error = hfs_copy_extent(hfsmp, extent_info->vp, oldStartBlock, 
			newStartBlock, newBlockCount, context);
	if (error) {
		printf ("hfs_reclaim_extent: fileID=%u start=%u, %u:(%u,%u)=>(%u,%u) hfs_copy_extent error=%d\n", extent_info->fileID, extent_info->recStartBlock, index, oldStartBlock, oldBlockCount, newStartBlock, newBlockCount, error);
		goto out;
	}

	/* Update the extent record with the new start block information */
	extent_info->extents[index].startBlock = newStartBlock;

	/* Sync the content back to the disk */
	if (extent_info->catalog_fp) {
		/* Update the extents in catalog record */
		if (extent_info->is_dirlink) {
			error = cat_update_dirlink(hfsmp, extent_info->forkType, 
					extent_info->dirlink_desc, extent_info->dirlink_attr, 
					&(extent_info->dirlink_fork->ff_data));
		} else {
			cp->c_flag |= C_MODIFIED;
			/* If this is a system file, sync volume headers on disk */
			if (extent_info->is_sysfile) {
				error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
			}
		}
	} else {
		/* Replace record for extents overflow or extents-based xattrs */
		error = BTReplaceRecord(extent_info->fcb, extent_info->iterator, 
				&(extent_info->btdata), extent_info->recordlen);
	}
	if (error) {
		printf ("hfs_reclaim_extent: fileID=%u, update record error=%u\n", extent_info->fileID, error);
		goto out;
	}

	/* Deallocate the old extent */
	error = BlockDeallocate(hfsmp, oldStartBlock, oldBlockCount, HFS_ALLOC_SKIPFREEBLKS);
	if (error) {
		printf ("hfs_reclaim_extent: fileID=%u start=%u, %u:(%u,%u) BlockDeallocate error=%d\n", extent_info->fileID, extent_info->recStartBlock, index, oldStartBlock, oldBlockCount, error);
		goto out;
	}
	extent_info->blocks_relocated += newBlockCount;

	if (hfs_resize_debug) {
		printf ("hfs_reclaim_extent: Relocated record:%u %u:(%u,%u) to (%u,%u)\n", extent_info->overflow_count, index, oldStartBlock, oldBlockCount, newStartBlock, newBlockCount);
	}

out:
	if (error != 0) {
		if (blocks_allocated == true) {
			BlockDeallocate(hfsmp, newStartBlock, newBlockCount, HFS_ALLOC_SKIPFREEBLKS);
		}
	} else {
		/* On success, increment the total allocation blocks processed */
		extent_info->cur_blockCount += newBlockCount;
	}

	hfs_systemfile_unlock(hfsmp, extent_info->lockflags);

	/* For a non-system file, if an extent entry from catalog record 
	 * was modified, sync the in-memory changes to the catalog record
	 * on disk before ending the transaction.
	 */
	 if ((extent_info->catalog_fp) && 
	     (extent_info->is_sysfile == false)) {
		(void) hfs_update(extent_info->vp, MNT_WAIT);
	}

	hfs_end_transaction(hfsmp);

	return error;
}

/* Report intermediate progress during volume resize */
static void 
hfs_truncatefs_progress(struct hfsmount *hfsmp)
{
	u_int32_t cur_progress = 0;

	hfs_resize_progress(hfsmp, &cur_progress);
	if (cur_progress > (hfsmp->hfs_resize_progress + 9)) {
		printf("hfs_truncatefs: %d%% done...\n", cur_progress);
		hfsmp->hfs_resize_progress = cur_progress;
	}
	return;
}

/*
 * Reclaim space at the end of a volume for given file and forktype. 
 *
 * This routine attempts to move any extent which contains allocation blocks
 * at or after "allocLimit."  A separate transaction is used for every extent 
 * that needs to be moved.  If there is not contiguous space available for 
 * moving an extent, it can be split into smaller extents.  The contents of 
 * any moved extents are read and written via the volume's device vnode -- 
 * NOT via "vp."  During the move, moved blocks which are part of a transaction 
 * have their physical block numbers invalidated so they will eventually be 
 * written to their new locations.
 *
 * This function is also called for directory hard links.  Directory hard links
 * are regular files with no data fork and resource fork that contains alias 
 * information for backward compatibility with pre-Leopard systems.  However 
 * non-Mac OS X implementation can add/modify data fork or resource fork 
 * information to directory hard links, so we check, and if required, relocate 
 * both data fork and resource fork.  
 *
 * Inputs:
 *    hfsmp       The volume being resized.
 *    vp          The vnode for the system file.
 *    fileID	  ID of the catalog record that needs to be relocated
 *    forktype	  The type of fork that needs relocated,
 *    			kHFSResourceForkType for resource fork,
 *    			kHFSDataForkType for data fork
 *    allocLimit  Allocation limit for the new volume size, 
 *    		  do not use this block or beyond.  All extents 
 *    		  that use this block or any blocks beyond this limit 
 *    		  will be relocated.
 *
 * Side Effects:
 * hfsmp->hfs_resize_blocksmoved is incremented by the number of allocation 
 * blocks that were relocated. 
 */
static int
hfs_reclaim_file(struct hfsmount *hfsmp, struct vnode *vp, u_int32_t fileID, 
		u_int8_t forktype, u_long allocLimit, vfs_context_t context)
{
	int error = 0;
	struct hfs_reclaim_extent_info *extent_info;
	int i;
	int lockflags = 0;
	struct cnode *cp;
	struct filefork *fp;
	int took_truncate_lock = false;
	int release_desc = false;
	HFSPlusExtentKey *key;
		
	/* If there is no vnode for this file, then there's nothing to do. */	
	if (vp == NULL) {
		return 0;
	}

	cp = VTOC(vp);

	if (hfs_resize_debug) {
		const char *filename = (const char *) cp->c_desc.cd_nameptr;
		int namelen = cp->c_desc.cd_namelen;

		if (filename == NULL) {
			filename = "";
			namelen = 0;
		}
		printf("hfs_reclaim_file: reclaiming '%.*s'\n", namelen, filename);
	}

	MALLOC(extent_info, struct hfs_reclaim_extent_info *, 
	       sizeof(struct hfs_reclaim_extent_info), M_TEMP, M_WAITOK);
	if (extent_info == NULL) {
		return ENOMEM;
	}
	bzero(extent_info, sizeof(struct hfs_reclaim_extent_info));
	extent_info->vp = vp;
	extent_info->fileID = fileID;
	extent_info->forkType = forktype;
	extent_info->is_sysfile = vnode_issystem(vp);
	if (vnode_isdir(vp) && (cp->c_flag & C_HARDLINK)) {
		extent_info->is_dirlink = true;
	}
	/* We always need allocation bitmap and extent btree lock */
	lockflags = SFL_BITMAP | SFL_EXTENTS;
	if ((fileID == kHFSCatalogFileID) || (extent_info->is_dirlink == true)) {
		lockflags |= SFL_CATALOG;
	} else if (fileID == kHFSAttributesFileID) {
		lockflags |= SFL_ATTRIBUTE;
	} else if (fileID == kHFSStartupFileID) {
		lockflags |= SFL_STARTUP;
	}
	extent_info->lockflags = lockflags;
	extent_info->fcb = VTOF(hfsmp->hfs_extents_vp);

	/* Flush data associated with current file on disk. 
	 *
	 * If the current vnode is directory hard link, no flushing of 
	 * journal or vnode is required.  The current kernel does not 
	 * modify data/resource fork of directory hard links, so nothing 
	 * will be in the cache.  If a directory hard link is newly created, 
	 * the resource fork data is written directly using devvp and 
	 * the code that actually relocates data (hfs_copy_extent()) also
	 * uses devvp for its I/O --- so they will see a consistent copy. 
	 */
	if (extent_info->is_sysfile) {
		/* If the current vnode is system vnode, flush journal 
		 * to make sure that all data is written to the disk.
		 */
		error = hfs_journal_flush(hfsmp, TRUE);
		if (error) {
			printf ("hfs_reclaim_file: journal_flush returned %d\n", error);
			goto out;
		}
	} else if (extent_info->is_dirlink == false) {
		/* Flush all blocks associated with this regular file vnode.  
		 * Normally there should not be buffer cache blocks for regular 
		 * files, but for objects like symlinks, we can have buffer cache 
		 * blocks associated with the vnode.  Therefore we call
		 * buf_flushdirtyblks() also.
		 */
		buf_flushdirtyblks(vp, 0, BUF_SKIP_LOCKED, "hfs_reclaim_file");

		hfs_unlock(cp);
		hfs_lock_truncate(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
		took_truncate_lock = true;
		(void) cluster_push(vp, 0);
		error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
		if (error) {
			goto out;
		}

		/* If the file no longer exists, nothing left to do */
		if (cp->c_flag & C_NOEXISTS) {
			error = 0;
			goto out;
		}

		/* Wait for any in-progress writes to this vnode to complete, so that we'll
		 * be copying consistent bits.  (Otherwise, it's possible that an async
		 * write will complete to the old extent after we read from it.  That
		 * could lead to corruption.)
		 */
		error = vnode_waitforwrites(vp, 0, 0, 0, "hfs_reclaim_file");
		if (error) {
			goto out;
		}
	}

	if (hfs_resize_debug) {
		printf("hfs_reclaim_file: === Start reclaiming %sfork for %sid=%u ===\n", (forktype ? "rsrc" : "data"), (extent_info->is_dirlink ? "dirlink" : "file"), fileID);
	}

	if (extent_info->is_dirlink) {
		MALLOC(extent_info->dirlink_desc, struct cat_desc *, 
				sizeof(struct cat_desc), M_TEMP, M_WAITOK);
		MALLOC(extent_info->dirlink_attr, struct cat_attr *, 
				sizeof(struct cat_attr), M_TEMP, M_WAITOK);
		MALLOC(extent_info->dirlink_fork, struct filefork *, 
				sizeof(struct filefork), M_TEMP, M_WAITOK);
		if ((extent_info->dirlink_desc == NULL) || 
		    (extent_info->dirlink_attr == NULL) || 
		    (extent_info->dirlink_fork == NULL)) {
			error = ENOMEM;
			goto out;
		}

		/* Lookup catalog record for directory hard link and 
		 * create a fake filefork for the value looked up from 
		 * the disk. 
		 */
		fp = extent_info->dirlink_fork;
		bzero(extent_info->dirlink_fork, sizeof(struct filefork));
		extent_info->dirlink_fork->ff_cp = cp;
		lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);
		error = cat_lookup_dirlink(hfsmp, fileID, forktype, 
				extent_info->dirlink_desc, extent_info->dirlink_attr, 
				&(extent_info->dirlink_fork->ff_data));	
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (error) {
			printf ("hfs_reclaim_file: cat_lookup_dirlink for fileID=%u returned error=%u\n", fileID, error);
			goto out;
		}
		release_desc = true;
	} else {
		fp = VTOF(vp);
	}

	extent_info->catalog_fp = fp;
	extent_info->recStartBlock = 0;
	extent_info->extents = extent_info->catalog_fp->ff_extents;
	/* Relocate extents from the catalog record */
	for (i = 0; i < kHFSPlusExtentDensity; ++i) {
		if (fp->ff_extents[i].blockCount == 0) {
			break;
		}
		extent_info->extent_index = i;
		error = hfs_reclaim_extent(hfsmp, allocLimit, extent_info, context);
		if (error) {
			printf ("hfs_reclaim_file: fileID=%u #%d %u:(%u,%u) hfs_reclaim_extent error=%d\n", fileID, extent_info->overflow_count, i, fp->ff_extents[i].startBlock, fp->ff_extents[i].blockCount, error);
			goto out;
		}
	}
		
	/* If the number of allocation blocks processed for reclaiming 
	 * are less than total number of blocks for the file, continuing 
	 * working on overflow extents record.
	 */
	if (fp->ff_blocks <= extent_info->cur_blockCount) {
		if (0 && hfs_resize_debug) {
			printf ("hfs_reclaim_file: Nothing more to relocate, offset=%d, ff_blocks=%u, cur_blockCount=%u\n", i, fp->ff_blocks, extent_info->cur_blockCount);
		}
		goto out;
	}

	if (hfs_resize_debug) {
		printf ("hfs_reclaim_file: Will check overflow records, offset=%d, ff_blocks=%u, cur_blockCount=%u\n", i, fp->ff_blocks, extent_info->cur_blockCount);
	}

	MALLOC(extent_info->iterator, struct BTreeIterator *, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (extent_info->iterator == NULL) {
		error = ENOMEM;
		goto out;
	}
	bzero(extent_info->iterator, sizeof(struct BTreeIterator));
	key = (HFSPlusExtentKey *) &(extent_info->iterator->key);
	key->keyLength = kHFSPlusExtentKeyMaximumLength;
	key->forkType = forktype;
	key->fileID = fileID;
	key->startBlock = extent_info->cur_blockCount;

	extent_info->btdata.bufferAddress = extent_info->record.overflow;
	extent_info->btdata.itemSize = sizeof(HFSPlusExtentRecord);
	extent_info->btdata.itemCount = 1;

	extent_info->catalog_fp = NULL;

	/* Search the first overflow extent with expected startBlock as 'cur_blockCount' */
	lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);
	error = BTSearchRecord(extent_info->fcb, extent_info->iterator, 
			&(extent_info->btdata), &(extent_info->recordlen), 
			extent_info->iterator);
	hfs_systemfile_unlock(hfsmp, lockflags);
	while (error == 0) {
		extent_info->overflow_count++;
		extent_info->recStartBlock = key->startBlock;
		extent_info->extents = extent_info->record.overflow;
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			if (extent_info->record.overflow[i].blockCount == 0) {
				goto out;
			}
			extent_info->extent_index = i;
			error = hfs_reclaim_extent(hfsmp, allocLimit, extent_info, context);
			if (error) {
				printf ("hfs_reclaim_file: fileID=%u #%d %u:(%u,%u) hfs_reclaim_extent error=%d\n", fileID, extent_info->overflow_count, i, extent_info->record.overflow[i].startBlock, extent_info->record.overflow[i].blockCount, error);
				goto out;
			}
		}

		/* Look for more overflow records */
		lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);
		error = BTIterateRecord(extent_info->fcb, kBTreeNextRecord, 
				extent_info->iterator, &(extent_info->btdata), 
				&(extent_info->recordlen));
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (error) {
			break;
		}
		/* Stop when we encounter a different file or fork. */
		if ((key->fileID != fileID) || (key->forkType != forktype)) {
			break;
		}
	}
	if (error == fsBTRecordNotFoundErr || error == fsBTEndOfIterationErr) {
		error = 0;
	}
	
out:
	/* If any blocks were relocated, account them and report progress */
	if (extent_info->blocks_relocated) {
		hfsmp->hfs_resize_blocksmoved += extent_info->blocks_relocated;
		hfs_truncatefs_progress(hfsmp);
		if (fileID < kHFSFirstUserCatalogNodeID) {
			printf ("hfs_reclaim_file: Relocated %u blocks from fileID=%u on \"%s\"\n", 
					extent_info->blocks_relocated, fileID, hfsmp->vcbVN); 
		}
	}
	if (extent_info->iterator) {
		FREE(extent_info->iterator, M_TEMP);
	}
	if (release_desc == true) {
		cat_releasedesc(extent_info->dirlink_desc);
	}
	if (extent_info->dirlink_desc) {
		FREE(extent_info->dirlink_desc, M_TEMP);
	}
	if (extent_info->dirlink_attr) {
		FREE(extent_info->dirlink_attr, M_TEMP);
	}
	if (extent_info->dirlink_fork) {
		FREE(extent_info->dirlink_fork, M_TEMP);
	}
	if ((extent_info->blocks_relocated != 0) && (extent_info->is_sysfile == false)) {
		(void) hfs_update(vp, MNT_WAIT);
	}
	if (took_truncate_lock) {
		hfs_unlock_truncate(cp, HFS_LOCK_DEFAULT);
	}
	if (extent_info) {
		FREE(extent_info, M_TEMP);
	}
	if (hfs_resize_debug) {
		printf("hfs_reclaim_file: === Finished relocating %sfork for fileid=%u (error=%d) ===\n", (forktype ? "rsrc" : "data"), fileID, error);
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
	u_int32_t newBlockCount;
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
		printf("hfs_journal_relocate_callback: failed to read JIB (%d)\n", error);
		if (bp) {
        		buf_brelse(bp);
		}
		return error;
	}
	jibp = (JournalInfoBlock*) buf_dataptr(bp);
	jibp->offset = SWAP_BE64((u_int64_t)args->newStartBlock * hfsmp->blockSize);
	jibp->size = SWAP_BE64((u_int64_t)args->newBlockCount * hfsmp->blockSize);
	if (journal_uses_fua(hfsmp->jnl))
		buf_markfua(bp);
	error = buf_bwrite(bp);
	if (error) {
		printf("hfs_journal_relocate_callback: failed to write JIB (%d)\n", error);
		return error;
	}
	if (!journal_uses_fua(hfsmp->jnl)) {
		error = VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE, NULL, FWRITE, args->context);
		if (error) {
			printf("hfs_journal_relocate_callback: DKIOCSYNCHRONIZECACHE failed (%d)\n", error);
			error = 0;		/* Don't fail the operation. */
		}
	}

	return error;
}


/* Type of resize operation in progress */
#define HFS_RESIZE_TRUNCATE	1
#define HFS_RESIZE_EXTEND	2

/* 
 * Core function to relocate the journal file.  This function takes the 
 * journal size of the newly relocated journal --- the caller can 
 * provide a new journal size if they want to change the size of 
 * the journal.  The function takes care of updating the journal info 
 * block and all other data structures correctly.
 *
 * Note: This function starts a transaction and grabs the btree locks. 
 */
static int
hfs_relocate_journal_file(struct hfsmount *hfsmp, u_int32_t jnl_size, int resize_type, vfs_context_t context)
{
	int error;
	int journal_err;
	int lockflags;
	u_int32_t oldStartBlock;
	u_int32_t newStartBlock;
	u_int32_t oldBlockCount;
	u_int32_t newBlockCount;
	u_int32_t jnlBlockCount;
	u_int32_t alloc_skipfreeblks;
	struct cat_desc journal_desc;
	struct cat_attr journal_attr;
	struct cat_fork journal_fork;
	struct hfs_journal_relocate_args callback_args;

	/* Calculate the number of allocation blocks required for the journal */ 
	jnlBlockCount = howmany(jnl_size, hfsmp->blockSize);

	/* 
	 * During truncatefs(), the volume free block count is updated
	 * before relocating data and reflects the total number of free
	 * blocks that will exist on volume after the resize is successful.
	 * This means that the allocation blocks required for relocation 
	 * have already been reserved and accounted for in the free block 
	 * count.  Therefore, block allocation and deallocation routines 
	 * can skip the free block check by passing HFS_ALLOC_SKIPFREEBLKS 
	 * flag. 
	 *
	 * This special handling is not required when the file system 
	 * is being extended as we want all the allocated and deallocated
	 * blocks to be accounted for correctly. 
	 */
	if (resize_type == HFS_RESIZE_TRUNCATE) {
		alloc_skipfreeblks = HFS_ALLOC_SKIPFREEBLKS;
	} else {
		alloc_skipfreeblks = 0;
	}

	error = hfs_start_transaction(hfsmp);
	if (error) {
		printf("hfs_relocate_journal_file: hfs_start_transaction returned %d\n", error);
		return error;
	}
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	
	error = BlockAllocate(hfsmp, 1, jnlBlockCount, jnlBlockCount, 
			HFS_ALLOC_METAZONE | HFS_ALLOC_FORCECONTIG | HFS_ALLOC_FLUSHTXN | alloc_skipfreeblks,
			 &newStartBlock, &newBlockCount);
	if (error) {
		printf("hfs_relocate_journal_file: BlockAllocate returned %d\n", error);
		goto fail;
	}
	if (newBlockCount != jnlBlockCount) {
		printf("hfs_relocate_journal_file: newBlockCount != jnlBlockCount (%u, %u)\n", newBlockCount, jnlBlockCount);
		goto free_fail;
	}
	
	error = cat_idlookup(hfsmp, hfsmp->hfs_jnlfileid, 1, 0, &journal_desc, &journal_attr, &journal_fork);
	if (error) {
		printf("hfs_relocate_journal_file: cat_idlookup returned %d\n", error);
		goto free_fail;
	}

	oldStartBlock = journal_fork.cf_extents[0].startBlock;
	oldBlockCount = journal_fork.cf_extents[0].blockCount;
	error = BlockDeallocate(hfsmp, oldStartBlock, oldBlockCount, alloc_skipfreeblks);
	if (error) {
		printf("hfs_relocate_journal_file: BlockDeallocate returned %d\n", error);
		goto free_fail;
	}

	/* Update the catalog record for .journal */
	journal_fork.cf_size = newBlockCount * hfsmp->blockSize;
	journal_fork.cf_extents[0].startBlock = newStartBlock;
	journal_fork.cf_extents[0].blockCount = newBlockCount;
	journal_fork.cf_blocks = newBlockCount;
	error = cat_update(hfsmp, &journal_desc, &journal_attr, &journal_fork, NULL);
	cat_releasedesc(&journal_desc);  /* all done with cat descriptor */
	if (error) {
		printf("hfs_relocate_journal_file: cat_update returned %d\n", error);
		goto free_fail;
	}
	
	/*
	 * If the journal is part of the file system, then tell the journal
	 * code about the new location.  If the journal is on an external
	 * device, then just keep using it as-is.
	 */
	if (hfsmp->jvp == hfsmp->hfs_devvp) {
		callback_args.hfsmp = hfsmp;
		callback_args.context = context;
		callback_args.newStartBlock = newStartBlock;
		callback_args.newBlockCount = newBlockCount;

		error = journal_relocate(hfsmp->jnl, (off_t)newStartBlock*hfsmp->blockSize,
			(off_t)newBlockCount*hfsmp->blockSize, 0,
			hfs_journal_relocate_callback, &callback_args);
		if (error) {
			/* NOTE: journal_relocate will mark the journal invalid. */
			printf("hfs_relocate_journal_file: journal_relocate returned %d\n", error);
			goto fail;
		}
		if (hfs_resize_debug) {
			printf ("hfs_relocate_journal_file: Successfully relocated journal from (%u,%u) to (%u,%u)\n", oldStartBlock, oldBlockCount, newStartBlock, newBlockCount);
		}
		hfsmp->jnl_start = newStartBlock;
		hfsmp->jnl_size = (off_t)newBlockCount * hfsmp->blockSize;
	}

	hfs_systemfile_unlock(hfsmp, lockflags);
	error = hfs_end_transaction(hfsmp);
	if (error) {
		printf("hfs_relocate_journal_file: hfs_end_transaction returned %d\n", error);
	}

	return error;

free_fail:
	journal_err = BlockDeallocate(hfsmp, newStartBlock, newBlockCount, HFS_ALLOC_SKIPFREEBLKS); 
	if (journal_err) {
		printf("hfs_relocate_journal_file: BlockDeallocate returned %d\n", error);
		hfs_mark_volume_inconsistent(hfsmp);
	}
fail:
	hfs_systemfile_unlock(hfsmp, lockflags);
	(void) hfs_end_transaction(hfsmp);
	if (hfs_resize_debug) {
		printf ("hfs_relocate_journal_file: Error relocating journal file (error=%d)\n", error);
	}
	return error;
}


/* 
 * Relocate the journal file when the file system is being truncated.  
 * We do not down-size the journal when the file system size is 
 * reduced, so we always provide the current journal size to the 
 * relocate code. 
 */
static int 
hfs_reclaim_journal_file(struct hfsmount *hfsmp, u_int32_t allocLimit, vfs_context_t context)
{
	int error = 0;
	u_int32_t startBlock;
	u_int32_t blockCount = hfsmp->jnl_size / hfsmp->blockSize;

	/*
	 * Figure out the location of the .journal file.  When the journal
	 * is on an external device, we need to look up the .journal file.
	 */
	if (hfsmp->jvp == hfsmp->hfs_devvp) {
		startBlock = hfsmp->jnl_start;
		blockCount = hfsmp->jnl_size / hfsmp->blockSize;
	} else {
		u_int32_t fileid;
		u_int32_t old_jnlfileid;
		struct cat_attr attr;
		struct cat_fork fork;

		/*
		 * The cat_lookup inside GetFileInfo will fail because hfs_jnlfileid
		 * is set, and it is trying to hide the .journal file.  So temporarily
		 * unset the field while calling GetFileInfo.
		 */
		old_jnlfileid = hfsmp->hfs_jnlfileid;
		hfsmp->hfs_jnlfileid = 0;
		fileid = GetFileInfo(hfsmp, kHFSRootFolderID, ".journal", &attr, &fork);
		hfsmp->hfs_jnlfileid = old_jnlfileid;
		if (fileid != old_jnlfileid) {
			printf("hfs_reclaim_journal_file: cannot find .journal file!\n");
			return EIO;
		}

		startBlock = fork.cf_extents[0].startBlock;
		blockCount = fork.cf_extents[0].blockCount;
	}

	if (startBlock + blockCount <= allocLimit) {
		/* The journal file does not require relocation */
		return 0;
	}

	error = hfs_relocate_journal_file(hfsmp, blockCount * hfsmp->blockSize, HFS_RESIZE_TRUNCATE, context);
	if (error == 0) {
		hfsmp->hfs_resize_blocksmoved += blockCount;
		hfs_truncatefs_progress(hfsmp);
		printf ("hfs_reclaim_journal_file: Relocated %u blocks from journal on \"%s\"\n", 
				blockCount, hfsmp->vcbVN);
	}

	return error;
}


/*
 * Move the journal info block to a new location.  We have to make sure the
 * new copy of the journal info block gets to the media first, then change
 * the field in the volume header and the catalog record.
 */
static int
hfs_reclaim_journal_info_block(struct hfsmount *hfsmp, u_int32_t allocLimit, vfs_context_t context)
{
	int error;
	int journal_err;
	int lockflags;
	u_int32_t oldBlock;
	u_int32_t newBlock;
	u_int32_t blockCount;
	struct cat_desc jib_desc;
	struct cat_attr jib_attr;
	struct cat_fork jib_fork;
	buf_t old_bp, new_bp;

	if (hfsmp->vcbJinfoBlock <= allocLimit) {
		/* The journal info block does not require relocation */
		return 0;
	}
	
	error = hfs_start_transaction(hfsmp);
	if (error) {
		printf("hfs_reclaim_journal_info_block: hfs_start_transaction returned %d\n", error);
		return error;
	}
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	
	error = BlockAllocate(hfsmp, 1, 1, 1, 
			HFS_ALLOC_METAZONE | HFS_ALLOC_FORCECONTIG | HFS_ALLOC_SKIPFREEBLKS | HFS_ALLOC_FLUSHTXN, 
			&newBlock, &blockCount);
	if (error) {
		printf("hfs_reclaim_journal_info_block: BlockAllocate returned %d\n", error);
		goto fail;
	}
	if (blockCount != 1) {
		printf("hfs_reclaim_journal_info_block: blockCount != 1 (%u)\n", blockCount);
		goto free_fail;
	}
	
	/* Copy the old journal info block content to the new location */
	error = buf_meta_bread(hfsmp->hfs_devvp,
		hfsmp->vcbJinfoBlock * (hfsmp->blockSize/hfsmp->hfs_logical_block_size),
		hfsmp->blockSize, vfs_context_ucred(context), &old_bp);
	if (error) {
		printf("hfs_reclaim_journal_info_block: failed to read JIB (%d)\n", error);
		if (old_bp) {
        		buf_brelse(old_bp);
		}
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

	/* Deallocate the old block once the new one has the new valid content */
	error = BlockDeallocate(hfsmp, hfsmp->vcbJinfoBlock, 1, HFS_ALLOC_SKIPFREEBLKS);
	if (error) {
		printf("hfs_reclaim_journal_info_block: BlockDeallocate returned %d\n", error);
		goto free_fail;
	}

	
	/* Update the catalog record for .journal_info_block */
	error = cat_idlookup(hfsmp, hfsmp->hfs_jnlinfoblkid, 1, 0, &jib_desc, &jib_attr, &jib_fork);
	if (error) {
		printf("hfs_reclaim_journal_info_block: cat_idlookup returned %d\n", error);
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
	error = hfs_journal_flush(hfsmp, FALSE);
	if (error) {
		printf("hfs_reclaim_journal_info_block: journal_flush returned %d\n", error);
	}

	/* Account for the block relocated and print progress */
	hfsmp->hfs_resize_blocksmoved += 1;
	hfs_truncatefs_progress(hfsmp);
	if (!error) {
		printf ("hfs_reclaim_journal_info: Relocated 1 block from journal info on \"%s\"\n", 
				hfsmp->vcbVN);
		if (hfs_resize_debug) {
			printf ("hfs_reclaim_journal_info_block: Successfully relocated journal info block from (%u,%u) to (%u,%u)\n", oldBlock, blockCount, newBlock, blockCount);
		}
	}
	return error;

free_fail:
	journal_err = BlockDeallocate(hfsmp, newBlock, blockCount, HFS_ALLOC_SKIPFREEBLKS); 
	if (journal_err) {
		printf("hfs_reclaim_journal_info_block: BlockDeallocate returned %d\n", error);
		hfs_mark_volume_inconsistent(hfsmp);
	}

fail:
	hfs_systemfile_unlock(hfsmp, lockflags);
	(void) hfs_end_transaction(hfsmp);
	if (hfs_resize_debug) {
		printf ("hfs_reclaim_journal_info_block: Error relocating journal info block (error=%d)\n", error);
	}
	return error;
}


static u_int64_t
calculate_journal_size(struct hfsmount *hfsmp, u_int32_t sector_size, u_int64_t sector_count) 
{
	u_int64_t journal_size;
	u_int32_t journal_scale;

#define DEFAULT_JOURNAL_SIZE (8*1024*1024)
#define MAX_JOURNAL_SIZE     (512*1024*1024)

	/* Calculate the journal size for this volume.   We want 
	 * at least 8 MB of journal for each 100 GB of disk space. 
	 * We cap the size at 512 MB, unless the allocation block
	 * size is larger, in which case, we use one allocation 
	 * block.
	 */
	journal_scale = (sector_size * sector_count) / ((u_int64_t)100 * 1024 * 1024 * 1024);
	journal_size = DEFAULT_JOURNAL_SIZE * (journal_scale + 1);
	if (journal_size > MAX_JOURNAL_SIZE) {
		journal_size = MAX_JOURNAL_SIZE;
	}
	if (journal_size < hfsmp->blockSize) {
		journal_size = hfsmp->blockSize;
	}
	return journal_size;
}
		

/* 
 * Calculate the expected journal size based on current partition size.  
 * If the size of the current journal is less than the calculated size, 
 * force journal relocation with the new journal size. 
 */
static int 
hfs_extend_journal(struct hfsmount *hfsmp, u_int32_t sector_size, u_int64_t sector_count, vfs_context_t context)
{
	int error = 0;
	u_int64_t calc_journal_size;

	if (hfsmp->jvp != hfsmp->hfs_devvp) {
		if (hfs_resize_debug) {
			printf("hfs_extend_journal: not resizing the journal because it is on an external device.\n");
		}
		return 0;
	}

	calc_journal_size = calculate_journal_size(hfsmp, sector_size, sector_count);
	if (calc_journal_size <= hfsmp->jnl_size) {
		/* The journal size requires no modification */
		goto out;
	}

	if (hfs_resize_debug) {
		printf ("hfs_extend_journal: journal old=%u, new=%qd\n", hfsmp->jnl_size, calc_journal_size);
	}

	/* Extend the journal to the new calculated size */
	error = hfs_relocate_journal_file(hfsmp, calc_journal_size, HFS_RESIZE_EXTEND, context);
	if (error == 0) {
		printf ("hfs_extend_journal: Extended journal size to %u bytes on \"%s\"\n", 
				hfsmp->jnl_size, hfsmp->vcbVN);
	}
out:
	return error;
}


/*
 * This function traverses through all extended attribute records for a given 
 * fileID, and calls function that reclaims data blocks that exist in the 
 * area of the disk being reclaimed which in turn is responsible for allocating 
 * new space, copying extent data, deallocating new space, and if required, 
 * splitting the extent.
 *
 * Note: The caller has already acquired the cnode lock on the file.  Therefore
 * we are assured that no other thread would be creating/deleting/modifying 
 * extended attributes for this file.  
 *
 * Side Effects:
 * hfsmp->hfs_resize_blocksmoved is incremented by the number of allocation 
 * blocks that were relocated. 
 *
 * Returns: 
 * 	0 on success, non-zero on failure.
 */
static int 
hfs_reclaim_xattr(struct hfsmount *hfsmp, struct vnode *vp, u_int32_t fileID, u_int32_t allocLimit, vfs_context_t context) 
{
	int error = 0;
	struct hfs_reclaim_extent_info *extent_info;
	int i;
	HFSPlusAttrKey *key;
	int *lockflags;

	if (hfs_resize_debug) {
		printf("hfs_reclaim_xattr: === Start reclaiming xattr for id=%u ===\n", fileID);
	}

	MALLOC(extent_info, struct hfs_reclaim_extent_info *, 
	       sizeof(struct hfs_reclaim_extent_info), M_TEMP, M_WAITOK);
	if (extent_info == NULL) {
		return ENOMEM;
	}
	bzero(extent_info, sizeof(struct hfs_reclaim_extent_info));
	extent_info->vp = vp;
	extent_info->fileID = fileID;
	extent_info->is_xattr = true;
	extent_info->is_sysfile = vnode_issystem(vp);
	extent_info->fcb = VTOF(hfsmp->hfs_attribute_vp);
	lockflags = &(extent_info->lockflags);
	*lockflags = SFL_ATTRIBUTE | SFL_BITMAP;

	/* Initialize iterator from the extent_info structure */
	MALLOC(extent_info->iterator, struct BTreeIterator *, 
	       sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (extent_info->iterator == NULL) {
		error = ENOMEM;
		goto out;
	}
	bzero(extent_info->iterator, sizeof(struct BTreeIterator));

	/* Build attribute key */
	key = (HFSPlusAttrKey *)&(extent_info->iterator->key);
	error = hfs_buildattrkey(fileID, NULL, key);
	if (error) {
		goto out;
	}

	/* Initialize btdata from extent_info structure.  Note that the 
	 * buffer pointer actually points to the xattr record from the 
	 * extent_info structure itself.
	 */
	extent_info->btdata.bufferAddress = &(extent_info->record.xattr);
	extent_info->btdata.itemSize = sizeof(HFSPlusAttrRecord);
	extent_info->btdata.itemCount = 1;

	/* 
	 * Sync all extent-based attribute data to the disk.
	 *
	 * All extent-based attribute data I/O is performed via cluster 
	 * I/O using a virtual file that spans across entire file system 
	 * space.  
	 */
	hfs_lock_truncate(VTOC(hfsmp->hfs_attrdata_vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
	(void)cluster_push(hfsmp->hfs_attrdata_vp, 0);
	error = vnode_waitforwrites(hfsmp->hfs_attrdata_vp, 0, 0, 0, "hfs_reclaim_xattr");
	hfs_unlock_truncate(VTOC(hfsmp->hfs_attrdata_vp), HFS_LOCK_DEFAULT);
	if (error) {
		goto out;
	}

	/* Search for extended attribute for current file.  This 
	 * will place the iterator before the first matching record.
	 */
	*lockflags = hfs_systemfile_lock(hfsmp, *lockflags, HFS_EXCLUSIVE_LOCK);
	error = BTSearchRecord(extent_info->fcb, extent_info->iterator, 
			&(extent_info->btdata), &(extent_info->recordlen), 
			extent_info->iterator);
	hfs_systemfile_unlock(hfsmp, *lockflags);
	if (error) {
		if (error != btNotFound) {
			goto out;
		}
		/* btNotFound is expected here, so just mask it */
		error = 0;
	} 

	while (1) {
		/* Iterate to the next record */
		*lockflags = hfs_systemfile_lock(hfsmp, *lockflags, HFS_EXCLUSIVE_LOCK);
		error = BTIterateRecord(extent_info->fcb, kBTreeNextRecord, 
				extent_info->iterator, &(extent_info->btdata), 
				&(extent_info->recordlen));
		hfs_systemfile_unlock(hfsmp, *lockflags);

		/* Stop the iteration if we encounter end of btree or xattr with different fileID */
		if (error || key->fileID != fileID) {
			if (error == fsBTRecordNotFoundErr || error == fsBTEndOfIterationErr) {
				error = 0;				
			}
			break;
		}

		/* We only care about extent-based EAs */
		if ((extent_info->record.xattr.recordType != kHFSPlusAttrForkData) && 
		    (extent_info->record.xattr.recordType != kHFSPlusAttrExtents)) {
			continue;
		}

		if (extent_info->record.xattr.recordType == kHFSPlusAttrForkData) {
			extent_info->overflow_count = 0;
			extent_info->extents = extent_info->record.xattr.forkData.theFork.extents;
		} else if (extent_info->record.xattr.recordType == kHFSPlusAttrExtents) {
			extent_info->overflow_count++;
			extent_info->extents = extent_info->record.xattr.overflowExtents.extents;
		}
			
		extent_info->recStartBlock = key->startBlock;
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			if (extent_info->extents[i].blockCount == 0) {
				break;
			} 
			extent_info->extent_index = i;
			error = hfs_reclaim_extent(hfsmp, allocLimit, extent_info, context);
			if (error) {
				printf ("hfs_reclaim_xattr: fileID=%u hfs_reclaim_extent error=%d\n", fileID, error); 
				goto out;
			}
		}
	}

out:
	/* If any blocks were relocated, account them and report progress */
	if (extent_info->blocks_relocated) {
		hfsmp->hfs_resize_blocksmoved += extent_info->blocks_relocated;
		hfs_truncatefs_progress(hfsmp);
	}
	if (extent_info->iterator) {
		FREE(extent_info->iterator, M_TEMP);
	}
	if (extent_info) {
		FREE(extent_info, M_TEMP);
	}
	if (hfs_resize_debug) {
		printf("hfs_reclaim_xattr: === Finished relocating xattr for fileid=%u (error=%d) ===\n", fileID, error);
	}
	return error;
}

/* 
 * Reclaim any extent-based extended attributes allocation blocks from 
 * the area of the disk that is being truncated.
 *
 * The function traverses the attribute btree to find out the fileIDs
 * of the extended attributes that need to be relocated.  For every 
 * file whose large EA requires relocation, it looks up the cnode and 
 * calls hfs_reclaim_xattr() to do all the work for allocating 
 * new space, copying data, deallocating old space, and if required, 
 * splitting the extents.
 *
 * Inputs: 
 * 	allocLimit    - starting block of the area being reclaimed
 *
 * Returns:
 *   	returns 0 on success, non-zero on failure.
 */
static int
hfs_reclaim_xattrspace(struct hfsmount *hfsmp, u_int32_t allocLimit, vfs_context_t context)
{
	int error = 0;
	FCB *fcb;
	struct BTreeIterator *iterator = NULL;
	struct FSBufferDescriptor btdata;
	HFSPlusAttrKey *key;
	HFSPlusAttrRecord rec;
	int lockflags = 0;
	cnid_t prev_fileid = 0;
	struct vnode *vp;
	int need_relocate;
	int btree_operation;
	u_int32_t files_moved = 0;
	u_int32_t prev_blocksmoved;
	int i;

	fcb = VTOF(hfsmp->hfs_attribute_vp);
	/* Store the value to print total blocks moved by this function in end */
	prev_blocksmoved = hfsmp->hfs_resize_blocksmoved;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&iterator, sizeof(*iterator))) {
		return ENOMEM;
	}	
	bzero(iterator, sizeof(*iterator));
	key = (HFSPlusAttrKey *)&iterator->key;
	btdata.bufferAddress = &rec;
	btdata.itemSize = sizeof(rec);
	btdata.itemCount = 1;

	need_relocate = false;
	btree_operation = kBTreeFirstRecord;
	/* Traverse the attribute btree to find extent-based EAs to reclaim */
	while (1) {
		lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE, HFS_SHARED_LOCK);
		error = BTIterateRecord(fcb, btree_operation, iterator, &btdata, NULL);
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (error) {
			if (error == fsBTRecordNotFoundErr || error == fsBTEndOfIterationErr) {
				error = 0;				
			}
			break;
		}
		btree_operation = kBTreeNextRecord;

		/* If the extents of current fileID were already relocated, skip it */
		if (prev_fileid == key->fileID) {
			continue;
		}

		/* Check if any of the extents in the current record need to be relocated */
		need_relocate = false;
		switch(rec.recordType) {
			case kHFSPlusAttrForkData:
				for (i = 0; i < kHFSPlusExtentDensity; i++) {
					if (rec.forkData.theFork.extents[i].blockCount == 0) {
						break;
					}
					if ((rec.forkData.theFork.extents[i].startBlock + 
					     rec.forkData.theFork.extents[i].blockCount) > allocLimit) {
						need_relocate = true;
						break;
					}
				}
				break;

			case kHFSPlusAttrExtents:
				for (i = 0; i < kHFSPlusExtentDensity; i++) {
					if (rec.overflowExtents.extents[i].blockCount == 0) {
						break;
					}
					if ((rec.overflowExtents.extents[i].startBlock + 
					     rec.overflowExtents.extents[i].blockCount) > allocLimit) {
						need_relocate = true;
						break;
					}
				}
				break;
		};

		/* Continue iterating to next attribute record */
		if (need_relocate == false) {
			continue;
		}

		/* Look up the vnode for corresponding file.  The cnode 
		 * will be locked which will ensure that no one modifies 
		 * the xattrs when we are relocating them.
		 *
		 * We want to allow open-unlinked files to be moved, 
		 * so provide allow_deleted == 1 for hfs_vget().
		 */
		if (hfs_vget(hfsmp, key->fileID, &vp, 0, 1) != 0) {
			continue;
		}

		error = hfs_reclaim_xattr(hfsmp, vp, key->fileID, allocLimit, context);
		hfs_unlock(VTOC(vp));
		vnode_put(vp);
		if (error) {
			printf ("hfs_reclaim_xattrspace: Error relocating xattrs for fileid=%u (error=%d)\n", key->fileID, error);
			break;
		}
		prev_fileid = key->fileID;
		files_moved++;
	}

	if (files_moved) {
		printf("hfs_reclaim_xattrspace: Relocated %u xattr blocks from %u files on \"%s\"\n", 
				(hfsmp->hfs_resize_blocksmoved - prev_blocksmoved),
				files_moved, hfsmp->vcbVN);
	}

	kmem_free(kernel_map, (vm_offset_t)iterator, sizeof(*iterator));
	return error;
}

/* 
 * Reclaim blocks from regular files.
 *
 * This function iterates over all the record in catalog btree looking 
 * for files with extents that overlap into the space we're trying to 
 * free up.  If a file extent requires relocation, it looks up the vnode 
 * and calls function to relocate the data.
 *
 * Returns:
 * 	Zero on success, non-zero on failure. 
 */
static int 
hfs_reclaim_filespace(struct hfsmount *hfsmp, u_int32_t allocLimit, vfs_context_t context) 
{
	int error;
	FCB *fcb;
	struct BTreeIterator *iterator = NULL;
	struct FSBufferDescriptor btdata;
	int btree_operation;
	int lockflags;
	struct HFSPlusCatalogFile filerec;
	struct vnode *vp;
	struct vnode *rvp;
	struct filefork *datafork;
	u_int32_t files_moved = 0;
	u_int32_t prev_blocksmoved;

#if CONFIG_PROTECT
	int keys_generated = 0;
#endif

	fcb = VTOF(hfsmp->hfs_catalog_vp);
	/* Store the value to print total blocks moved by this function at the end */
	prev_blocksmoved = hfsmp->hfs_resize_blocksmoved;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&iterator, sizeof(*iterator))) {
		error = ENOMEM;	
		goto reclaim_filespace_done;
	}

#if CONFIG_PROTECT
	/*
	 * For content-protected filesystems, we may need to relocate files that
	 * are encrypted.  If they use the new-style offset-based IVs, then
	 * we can move them regardless of the lock state.  We create a temporary
	 * key here that we use to read/write the data, then we discard it at the
	 * end of the function.
	 */
	if (cp_fs_protected (hfsmp->hfs_mp)) {
		int needs = 0;
		error = cp_needs_tempkeys(hfsmp, &needs);

		if ((error == 0) && (needs)) {
			error = cp_entry_gentempkeys(&hfsmp->hfs_resize_cpentry, hfsmp);
			if (error == 0) {
				keys_generated = 1;
			}
		}
	
		if (error) {
			printf("hfs_reclaimspace: Error generating temporary keys for resize (%d)\n", error);
			goto reclaim_filespace_done;
		}
	}

#endif

	bzero(iterator, sizeof(*iterator));

	btdata.bufferAddress = &filerec;
	btdata.itemSize = sizeof(filerec);
	btdata.itemCount = 1;

	btree_operation = kBTreeFirstRecord;
	while (1) {
		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
		error = BTIterateRecord(fcb, btree_operation, iterator, &btdata, NULL);
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (error) {
			if (error == fsBTRecordNotFoundErr || error == fsBTEndOfIterationErr) {
				error = 0;				
			}
			break;
		}
		btree_operation = kBTreeNextRecord;

		if (filerec.recordType != kHFSPlusFileRecord) {
			continue;
		}

		/* Check if any of the extents require relocation */
		if (hfs_file_extent_overlaps(hfsmp, allocLimit, &filerec) == false) {
			continue;
		}

		/* We want to allow open-unlinked files to be moved, so allow_deleted == 1 */
		if (hfs_vget(hfsmp, filerec.fileID, &vp, 0, 1) != 0) {
			if (hfs_resize_debug) {
				printf("hfs_reclaim_filespace: hfs_vget(%u) failed.\n", filerec.fileID);
			}
			continue;
		}

		/* If data fork exists or item is a directory hard link, relocate blocks */
		datafork = VTOF(vp);
		if ((datafork && datafork->ff_blocks > 0) || vnode_isdir(vp)) {
			error = hfs_reclaim_file(hfsmp, vp, filerec.fileID, 
					kHFSDataForkType, allocLimit, context);
			if (error)  {
				printf ("hfs_reclaimspace: Error reclaiming datafork blocks of fileid=%u (error=%d)\n", filerec.fileID, error);
				hfs_unlock(VTOC(vp));
				vnode_put(vp);
				break;
			}
		}

		/* If resource fork exists or item is a directory hard link, relocate blocks */
		if (((VTOC(vp)->c_blocks - (datafork ? datafork->ff_blocks : 0)) > 0) || vnode_isdir(vp)) {
			if (vnode_isdir(vp)) {
				/* Resource fork vnode lookup is invalid for directory hard link. 
				 * So we fake data fork vnode as resource fork vnode.
				 */
				rvp = vp;
			} else {
				error = hfs_vgetrsrc(hfsmp, vp, &rvp, TRUE, FALSE);
				if (error) {
					printf ("hfs_reclaimspace: Error looking up rvp for fileid=%u (error=%d)\n", filerec.fileID, error);
					hfs_unlock(VTOC(vp));
					vnode_put(vp);
					break;
				}
				VTOC(rvp)->c_flag |= C_NEED_RVNODE_PUT;
			}

			error = hfs_reclaim_file(hfsmp, rvp, filerec.fileID, 
					kHFSResourceForkType, allocLimit, context);
			if (error) {
				printf ("hfs_reclaimspace: Error reclaiming rsrcfork blocks of fileid=%u (error=%d)\n", filerec.fileID, error);
				hfs_unlock(VTOC(vp));
				vnode_put(vp);
				break;
			}
		}

		/* The file forks were relocated successfully, now drop the 
		 * cnode lock and vnode reference, and continue iterating to 
		 * next catalog record.
		 */
		hfs_unlock(VTOC(vp));
		vnode_put(vp);
		files_moved++;
	}

	if (files_moved) {
		printf("hfs_reclaim_filespace: Relocated %u blocks from %u files on \"%s\"\n", 
				(hfsmp->hfs_resize_blocksmoved - prev_blocksmoved),
				files_moved, hfsmp->vcbVN);
	}

reclaim_filespace_done:
	if (iterator) {
		kmem_free(kernel_map, (vm_offset_t)iterator, sizeof(*iterator));
	}

#if CONFIG_PROTECT
	if (keys_generated) {
		cp_entry_destroy(hfsmp->hfs_resize_cpentry);
		hfsmp->hfs_resize_cpentry = NULL;
	}
#endif
	return error;
}

/*
 * Reclaim space at the end of a file system.
 *
 * Inputs - 
 * 	allocLimit 	- start block of the space being reclaimed
 * 	reclaimblks 	- number of allocation blocks to reclaim
 */
static int
hfs_reclaimspace(struct hfsmount *hfsmp, u_int32_t allocLimit, u_int32_t reclaimblks, vfs_context_t context)
{
	int error = 0;

	/* 
	 * Preflight the bitmap to find out total number of blocks that need 
	 * relocation. 
	 *
	 * Note: Since allocLimit is set to the location of new alternate volume 
	 * header, the check below does not account for blocks allocated for old 
	 * alternate volume header.
	 */
	error = hfs_count_allocated(hfsmp, allocLimit, reclaimblks, &(hfsmp->hfs_resize_totalblocks));
	if (error) {
		printf ("hfs_reclaimspace: Unable to determine total blocks to reclaim error=%d\n", error);
		return error;
	}
	if (hfs_resize_debug) {
		printf ("hfs_reclaimspace: Total number of blocks to reclaim = %u\n", hfsmp->hfs_resize_totalblocks);
	}

	/* Just to be safe, sync the content of the journal to the disk before we proceed */
	hfs_journal_flush(hfsmp, TRUE);

	/* First, relocate journal file blocks if they're in the way.  
	 * Doing this first will make sure that journal relocate code 
	 * gets access to contiguous blocks on disk first.  The journal
	 * file has to be contiguous on the disk, otherwise resize will 
	 * fail. 
	 */
	error = hfs_reclaim_journal_file(hfsmp, allocLimit, context);
	if (error) {
		printf("hfs_reclaimspace: hfs_reclaim_journal_file failed (%d)\n", error);
		return error;
	}
	
	/* Relocate journal info block blocks if they're in the way. */
	error = hfs_reclaim_journal_info_block(hfsmp, allocLimit, context);
	if (error) {
		printf("hfs_reclaimspace: hfs_reclaim_journal_info_block failed (%d)\n", error);
		return error;
	}

	/* Relocate extents of the Extents B-tree if they're in the way.
	 * Relocating extents btree before other btrees is important as 
	 * this will provide access to largest contiguous block range on 
	 * the disk for relocating extents btree.  Note that extents btree 
	 * can only have maximum of 8 extents.
	 */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_extents_vp, kHFSExtentsFileID, 
			kHFSDataForkType, allocLimit, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim extents b-tree returned %d\n", error);
		return error;
	}

	/* Relocate extents of the Allocation file if they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_allocation_vp, kHFSAllocationFileID, 
			kHFSDataForkType, allocLimit, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim allocation file returned %d\n", error);
		return error;
	}

	/* Relocate extents of the Catalog B-tree if they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_catalog_vp, kHFSCatalogFileID, 
			kHFSDataForkType, allocLimit, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim catalog b-tree returned %d\n", error);
		return error;
	}

	/* Relocate extents of the Attributes B-tree if they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_attribute_vp, kHFSAttributesFileID, 
			kHFSDataForkType, allocLimit, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim attribute b-tree returned %d\n", error);
		return error;
	}

	/* Relocate extents of the Startup File if there is one and they're in the way. */
	error = hfs_reclaim_file(hfsmp, hfsmp->hfs_startup_vp, kHFSStartupFileID, 
			kHFSDataForkType, allocLimit, context);
	if (error) {
		printf("hfs_reclaimspace: reclaim startup file returned %d\n", error);
		return error;
	}
	
	/*
	 * We need to make sure the alternate volume header gets flushed if we moved
	 * any extents in the volume header.  But we need to do that before
	 * shrinking the size of the volume, or else the journal code will panic
	 * with an invalid (too large) block number.
	 *
	 * Note that blks_moved will be set if ANY extent was moved, even
	 * if it was just an overflow extent.  In this case, the journal_flush isn't
	 * strictly required, but shouldn't hurt.
	 */
	if (hfsmp->hfs_resize_blocksmoved) {
		hfs_journal_flush(hfsmp, TRUE);
	}

	/* Reclaim extents from catalog file records */
	error = hfs_reclaim_filespace(hfsmp, allocLimit, context);
	if (error) {
		printf ("hfs_reclaimspace: hfs_reclaim_filespace returned error=%d\n", error);
		return error;
	}

	/* Reclaim extents from extent-based extended attributes, if any */
	error = hfs_reclaim_xattrspace(hfsmp, allocLimit, context);
	if (error) {
		printf ("hfs_reclaimspace: hfs_reclaim_xattrspace returned error=%d\n", error);
		return error;
	}

	return error;
}


/*
 * Check if there are any extents (including overflow extents) that overlap 
 * into the disk space that is being reclaimed.  
 *
 * Output - 
 * 	true  - One of the extents need to be relocated
 * 	false - No overflow extents need to be relocated, or there was an error
 */
static int
hfs_file_extent_overlaps(struct hfsmount *hfsmp, u_int32_t allocLimit, struct HFSPlusCatalogFile *filerec)
{
	struct BTreeIterator * iterator = NULL;
	struct FSBufferDescriptor btdata;
	HFSPlusExtentRecord extrec;
	HFSPlusExtentKey *extkeyptr;
	FCB *fcb;
	int overlapped = false;
	int i, j;
	int error;
	int lockflags = 0;
	u_int32_t endblock;

	/* Check if data fork overlaps the target space */
	for (i = 0; i < kHFSPlusExtentDensity; ++i) {
		if (filerec->dataFork.extents[i].blockCount == 0) {
			break;
		}
		endblock = filerec->dataFork.extents[i].startBlock +
			filerec->dataFork.extents[i].blockCount;
		if (endblock > allocLimit) {
			overlapped = true;
			goto out;
		}
	}

	/* Check if resource fork overlaps the target space */
	for (j = 0; j < kHFSPlusExtentDensity; ++j) {
		if (filerec->resourceFork.extents[j].blockCount == 0) {
			break;
		}
		endblock = filerec->resourceFork.extents[j].startBlock +
			filerec->resourceFork.extents[j].blockCount;
		if (endblock > allocLimit) {
			overlapped = true;
			goto out;
		}
	}

	/* Return back if there are no overflow extents for this file */
	if ((i < kHFSPlusExtentDensity) && (j < kHFSPlusExtentDensity)) {
		goto out;
	}

	if (kmem_alloc(kernel_map, (vm_offset_t *)&iterator, sizeof(*iterator))) {
		return 0;
	}	
	bzero(iterator, sizeof(*iterator));
	extkeyptr = (HFSPlusExtentKey *)&iterator->key;
	extkeyptr->keyLength = kHFSPlusExtentKeyMaximumLength;
	extkeyptr->forkType = 0;
	extkeyptr->fileID = filerec->fileID;
	extkeyptr->startBlock = 0;

	btdata.bufferAddress = &extrec;
	btdata.itemSize = sizeof(extrec);
	btdata.itemCount = 1;
	
	fcb = VTOF(hfsmp->hfs_extents_vp);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_EXTENTS, HFS_SHARED_LOCK);

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
		if (extkeyptr->fileID != filerec->fileID) {
			break;
		}
		/* Check if any of the forks exist in the target space. */
		for (i = 0; i < kHFSPlusExtentDensity; ++i) {
			if (extrec[i].blockCount == 0) {
				break;
			}
			endblock = extrec[i].startBlock + extrec[i].blockCount;
			if (endblock > allocLimit) {
				overlapped = true;
				goto out;
			}
		}
		/* Look for more records. */
		error = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
	}

out:
	if (lockflags) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (iterator) {
		kmem_free(kernel_map, (vm_offset_t)iterator, sizeof(*iterator));
	}
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

	if (hfsmp->hfs_resize_totalblocks > 0) {
		*progress = (u_int32_t)((hfsmp->hfs_resize_blocksmoved * 100ULL) / hfsmp->hfs_resize_totalblocks);
	} else {
		*progress = 0;
	}

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
#define HFS_ATTR_CMN_VALIDMASK ATTR_CMN_VALIDMASK
#define HFS_ATTR_FILE_VALIDMASK (ATTR_FILE_VALIDMASK & ~(ATTR_FILE_FILETYPE | ATTR_FILE_FORKCOUNT | ATTR_FILE_FORKLIST))
#define HFS_ATTR_CMN_VOL_VALIDMASK (ATTR_CMN_VALIDMASK & ~(ATTR_CMN_ACCTIME))

	ExtendedVCB *vcb = VFSTOVCB(mp);
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	u_int32_t freeCNIDs;

	int searchfs_on = 0;
	int exchangedata_on = 1;

#if CONFIG_SEARCHFS
	searchfs_on = 1;
#endif

#if CONFIG_PROTECT
	if (cp_fs_protected(mp)) {
		exchangedata_on = 0;
	}
#endif

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

		if ((hfsmp->hfs_flags & HFS_STANDARD) == 0) {
			/* HFS+ & variants */
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
#if CONFIG_HFS_STD
		else {
			/* HFS standard */
			cap->capabilities[VOL_CAPABILITIES_FORMAT] =
				VOL_CAP_FMT_PERSISTENTOBJECTIDS |
				VOL_CAP_FMT_CASE_PRESERVING |
				VOL_CAP_FMT_FAST_STATFS |
				VOL_CAP_FMT_HIDDEN_FILES |
				VOL_CAP_FMT_PATH_FROM_ID;
		}
#endif

		/*
		 * The capabilities word in 'cap' tell you whether or not 
		 * this particular filesystem instance has feature X enabled.
		 */

		cap->capabilities[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_ATTRLIST |
			VOL_CAP_INT_NFSEXPORT |
			VOL_CAP_INT_READDIRATTR |
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
		
		/* HFS may conditionally support searchfs and exchangedata depending on the runtime */

		if (searchfs_on) {
			cap->capabilities[VOL_CAPABILITIES_INTERFACES] |= VOL_CAP_INT_SEARCHFS;
		}
		if (exchangedata_on) {
			cap->capabilities[VOL_CAPABILITIES_INTERFACES] |= VOL_CAP_INT_EXCHANGEDATA;
		}

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

		/*
		 * Bits in the "valid" field tell you whether or not the on-disk
		 * format supports feature X.
		 */

		cap->valid[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_ATTRLIST |
			VOL_CAP_INT_NFSEXPORT |
			VOL_CAP_INT_READDIRATTR |
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

		/* HFS always supports exchangedata and searchfs in the on-disk format natively */
		cap->valid[VOL_CAPABILITIES_INTERFACES] |= (VOL_CAP_INT_SEARCHFS | VOL_CAP_INT_EXCHANGEDATA);


		cap->valid[VOL_CAPABILITIES_RESERVED1] = 0;
		cap->valid[VOL_CAPABILITIES_RESERVED2] = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		vol_attributes_attr_t *attrp = &fsap->f_attributes;

        	attrp->validattr.commonattr = HFS_ATTR_CMN_VOL_VALIDMASK;
        	attrp->validattr.volattr = ATTR_VOL_VALIDMASK & ~ATTR_VOL_INFO;
        	attrp->validattr.dirattr = ATTR_DIR_VALIDMASK;
        	attrp->validattr.fileattr = HFS_ATTR_FILE_VALIDMASK;
        	attrp->validattr.forkattr = 0;

        	attrp->nativeattr.commonattr = HFS_ATTR_CMN_VOL_VALIDMASK;
        	attrp->nativeattr.volattr = ATTR_VOL_VALIDMASK & ~ATTR_VOL_INFO;
        	attrp->nativeattr.dirattr = ATTR_DIR_VALIDMASK;
        	attrp->nativeattr.fileattr = HFS_ATTR_FILE_VALIDMASK;
        	attrp->nativeattr.forkattr = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}	
	fsap->f_create_time.tv_sec = hfsmp->hfs_itime;
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
		if ((hfsmp->hfs_flags & HFS_STANDARD) == 0) {
			if (hfsmp->jnl) {
				subtype |= HFS_SUBTYPE_JOURNALED;
			}
			if (hfsmp->hfs_flags & HFS_CASE_SENSITIVE) {
				subtype |= HFS_SUBTYPE_CASESENSITIVE;
			}
		}
#if CONFIG_HFS_STD
		else {
			subtype = HFS_SUBTYPE_STANDARDHFS;
		} 
#endif
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
	char converted_volname[256];
	size_t volname_length = 0;
	size_t conv_volname_length = 0;
	

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

	if ((error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT)) == 0) {
		if ((error = hfs_start_transaction(hfsmp)) == 0) {
			if ((error = cat_preflight(hfsmp, CAT_RENAME, &cookie, p)) == 0) {
				lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);

				error = cat_rename(hfsmp, &cp->c_desc, &todir_desc, &to_desc, &new_desc);

				/*
				 * If successful, update the name in the VCB, ensure it's terminated.
				 */
				if (error == 0) {
					strlcpy((char *)vcb->vcbVN, name, sizeof(vcb->vcbVN));

					volname_length = strlen ((const char*)vcb->vcbVN);
#define DKIOCCSSETLVNAME _IOW('d', 198, char[256])
					/* Send the volume name down to CoreStorage if necessary */	
					error = utf8_normalizestr(vcb->vcbVN, volname_length, (u_int8_t*)converted_volname, &conv_volname_length, 256, UTF_PRECOMPOSED);
					if (error == 0) {
						(void) VNOP_IOCTL (hfsmp->hfs_devvp, DKIOCCSSETLVNAME, converted_volname, 0, vfs_context_current());
					}
					error = 0;
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
	hfs_lock_mount (hfsmp);
	if ((hfsmp->vcbAtrb & kHFSVolumeInconsistentMask) == 0) {
		hfsmp->vcbAtrb |= kHFSVolumeInconsistentMask;
		MarkVCBDirty(hfsmp);
	}
	if ((hfsmp->hfs_flags & HFS_READ_ONLY)==0) {	
		/* Log information to ASL log */
		fslog_fs_corrupt(hfsmp->hfs_mp);
		printf("hfs: Runtime corruption detected on %s, fsck will be forced on next mount.\n", hfsmp->vcbVN);
	}
	hfs_unlock_mount (hfsmp);
}

/* Replay the journal on the device node provided.  Returns zero if 
 * journal replay succeeded or no journal was supposed to be replayed.
 */
static int hfs_journal_replay(vnode_t devvp, vfs_context_t context)
{
	int retval = 0;
	int error = 0;
	struct mount *mp = NULL;
	struct hfs_mount_args *args = NULL;

	/* Replay allowed only on raw devices */
	if (!vnode_ischr(devvp) && !vnode_isblk(devvp)) {
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
	buf_flushdirtyblks(devvp, TRUE, 0, "hfs_journal_replay");
	
	/* FSYNC the devnode to be sure all data has been flushed */
	error = VNOP_FSYNC(devvp, MNT_WAIT, context);
	if (error) {
		retval = error;
	}

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
