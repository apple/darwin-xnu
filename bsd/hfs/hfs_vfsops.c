/*
 * Copyright (c) 1999-2002 Apple Computer, Inc. All rights reserved.
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

#include <sys/ubc.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/lock.h>
#include <sys/quota.h>
#include <sys/disk.h>

// XXXdbg
#include <vfs/vfs_journal.h>

#include <miscfs/specfs/specdev.h>
#include <hfs/hfs_mount.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_cnode.h"
#include "hfs_dbg.h"
#include "hfs_endian.h"
#include "hfs_quota.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/BTreesInternal.h"


#if	HFS_DIAGNOSTIC
int hfs_dbg_all = 0;
int hfs_dbg_err = 0;
#endif


extern struct vnodeopv_desc hfs_vnodeop_opv_desc;

extern void hfs_converterinit(void);

extern void inittodr( time_t base);


static int hfs_changefs __P((struct mount *mp, struct hfs_mount_args *args,
		struct proc *p));
static int hfs_reload __P((struct mount *mp, struct ucred *cred, struct proc *p));

static int hfs_mountfs __P((struct vnode *devvp, struct mount *mp, struct proc *p,
		struct hfs_mount_args *args));
static int hfs_statfs __P((struct mount *mp, register struct statfs *sbp,
		struct proc *p));


/*
 * Called by vfs_mountroot when mounting HFS Plus as root.
 */
int
hfs_mountroot()
{
	extern struct vnode *rootvp;
	struct mount *mp;
	struct proc *p = current_proc();	/* XXX */
	struct hfsmount *hfsmp;
	ExtendedVCB *vcb;
	int error;
	
	/*
	 * Get vnode for rootdev.
	 */
	if ((error = bdevvp(rootdev, &rootvp))) {
		printf("hfs_mountroot: can't setup bdevvp");
		return (error);
	}
	if ((error = vfs_rootmountalloc("hfs", "root_device", &mp))) {
		vrele(rootvp); /* release the reference from bdevvp() */
		return (error);
	}
	if ((error = hfs_mountfs(rootvp, mp, p, NULL))) {
		mp->mnt_vfc->vfc_refcount--;
		vfs_unbusy(mp, p);
		vrele(rootvp); /* release the reference from bdevvp() */
		_FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
		return (error);
	}
	simple_lock(&mountlist_slock);
	CIRCLEQ_INSERT_TAIL(&mountlist, mp, mnt_list);
	simple_unlock(&mountlist_slock);
	
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

	(void)hfs_statfs(mp, &mp->mnt_stat, p);
	
	vfs_unbusy(mp, p);
	inittodr(HFSTOVCB(hfsmp)->vcbLsMod);
	return (0);
}


/*
 * VFS Operations.
 *
 * mount system call
 */

static int
hfs_mount(mp, path, data, ndp, p)
	register struct mount *mp;
	char *path;
	caddr_t data;
	struct nameidata *ndp;
	struct proc *p;
{
	struct hfsmount *hfsmp = NULL;
	struct vnode *devvp;
	struct hfs_mount_args args;
	size_t size;
	int retval = E_NONE;
	int flags;
	mode_t accessmode;

	if ((retval = copyin(data, (caddr_t)&args, sizeof(args))))
		goto error_exit;

	/*
	 * If updating, check whether changing from read-only to
	 * read/write; if there is no device name, that's all we do.
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		
		hfsmp = VFSTOHFS(mp);
		if ((hfsmp->hfs_fs_ronly == 0) && (mp->mnt_flag & MNT_RDONLY)) {
		
			/* use VFS_SYNC to push out System (btree) files */
			retval = VFS_SYNC(mp, MNT_WAIT, p->p_ucred, p);
			if (retval && ((mp->mnt_flag & MNT_FORCE) == 0))
				goto error_exit;
		
			flags = WRITECLOSE;
			if (mp->mnt_flag & MNT_FORCE)
				flags |= FORCECLOSE;
				
			if ((retval = hfs_flushfiles(mp, flags, p)))
				goto error_exit;
			hfsmp->hfs_fs_ronly = 1;
			retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);

			/* also get the volume bitmap blocks */
			if (!retval)
				retval = VOP_FSYNC(hfsmp->hfs_devvp, NOCRED, MNT_WAIT, p);

			if (retval) {
				hfsmp->hfs_fs_ronly = 0;
				goto error_exit;
			}
		}

		if ((mp->mnt_flag & MNT_RELOAD) &&
			(retval = hfs_reload(mp, ndp->ni_cnd.cn_cred, p)))
			goto error_exit;

		if (hfsmp->hfs_fs_ronly && (mp->mnt_kern_flag & MNTK_WANTRDWR)) {
			/*
			 * If upgrade to read-write by non-root, then verify
			 * that user has necessary permissions on the device.
			 */
			if (p->p_ucred->cr_uid != 0) {
				devvp = hfsmp->hfs_devvp;
				vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, p);
				if ((retval = VOP_ACCESS(devvp, VREAD | VWRITE, p->p_ucred, p))) {
					VOP_UNLOCK(devvp, 0, p);
					goto error_exit;
				}
				VOP_UNLOCK(devvp, 0, p);
			}
			retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
	
			if (retval != E_NONE)
				goto error_exit;

			/* only change hfs_fs_ronly after a successfull write */
			hfsmp->hfs_fs_ronly = 0;
		}

		if ((hfsmp->hfs_fs_ronly == 0) &&
		    (HFSTOVCB(hfsmp)->vcbSigWord == kHFSPlusSigWord)) {
			/* setup private/hidden directory for unlinked files */
			hfsmp->hfs_private_metadata_dir = FindMetaDataDirectory(HFSTOVCB(hfsmp));
			if (hfsmp->jnl)
				hfs_remove_orphans(hfsmp);
		}

		if (args.fspec == 0) {
			/*
			 * Process export requests.
			 */
			return vfs_export(mp, &hfsmp->hfs_export, &args.export);
		}
	}

	/*
	 * Not an update, or updating the name: look up the name
	 * and verify that it refers to a sensible block device.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW, UIO_USERSPACE, args.fspec, p);
	retval = namei(ndp);
	if (retval != E_NONE) {
		DBG_ERR(("hfs_mount: CAN'T GET DEVICE: %s, %x\n", args.fspec, ndp->ni_vp->v_rdev));
		goto error_exit;
	}

	devvp = ndp->ni_vp;

	if (devvp->v_type != VBLK) {
		vrele(devvp);
		retval = ENOTBLK;
		goto error_exit;
	}
	if (major(devvp->v_rdev) >= nblkdev) {
		vrele(devvp);
		retval = ENXIO;
		goto error_exit;
	}

	/*
	 * If mount by non-root, then verify that user has necessary
	 * permissions on the device.
	 */
	if (p->p_ucred->cr_uid != 0) {
		accessmode = VREAD;
		if ((mp->mnt_flag & MNT_RDONLY) == 0)
			accessmode |= VWRITE;
		vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, p);
		if ((retval = VOP_ACCESS(devvp, accessmode, p->p_ucred, p))) {
			vput(devvp);
			goto error_exit;
		}
		VOP_UNLOCK(devvp, 0, p);
	}

	if ((mp->mnt_flag & MNT_UPDATE) == 0) {
		retval = hfs_mountfs(devvp, mp, p, &args);
		if (retval != E_NONE)
			vrele(devvp);
	} else {
		if (devvp != hfsmp->hfs_devvp)
			retval = EINVAL;	/* needs translation */
		else
			retval = hfs_changefs(mp, &args, p);
		vrele(devvp);
	}

	if (retval != E_NONE) {
		goto error_exit;
	}

	/* Set the mount flag to indicate that we support volfs  */
	mp->mnt_flag |= MNT_DOVOLFS;
    if (VFSTOVCB(mp)->vcbSigWord == kHFSSigWord) {
    	/* HFS volumes only want roman-encoded names: */
    	mp->mnt_flag |= MNT_FIXEDSCRIPTENCODING;
    }
	(void) copyinstr(path, mp->mnt_stat.f_mntonname, MNAMELEN-1, &size);

	bzero(mp->mnt_stat.f_mntonname + size, MNAMELEN - size);
	(void) copyinstr(args.fspec, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, &size);
	bzero(mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
	(void)hfs_statfs(mp, &mp->mnt_stat, p);
	return (E_NONE);

error_exit:

	return (retval);
}


/* Change fs mount parameters */
static int
hfs_changefs(mp, args, p)
	struct mount *mp;
	struct hfs_mount_args *args;
	struct proc *p;
{
	int retval = 0;
	int namefix, permfix, permswitch;
	struct hfsmount *hfsmp;
	struct cnode *cp;
	ExtendedVCB *vcb;
	register struct vnode *vp, *nvp;
	hfs_to_unicode_func_t	get_unicode_func;
	unicode_to_hfs_func_t	get_hfsname_func;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	u_long old_encoding;

	hfsmp = VFSTOHFS(mp);
	vcb = HFSTOVCB(hfsmp);
	permswitch = (((hfsmp->hfs_unknownpermissions != 0) && ((mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) == 0)) ||
					((hfsmp->hfs_unknownpermissions == 0) && ((mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) != 0)));
	/* The root filesystem must operate with actual permissions: */
	if (permswitch && (mp->mnt_flag & MNT_ROOTFS) && (mp->mnt_flag & MNT_UNKNOWNPERMISSIONS)) {
		mp->mnt_flag &= ~MNT_UNKNOWNPERMISSIONS;	/* Just say "No". */
		return EINVAL;
	};		
	hfsmp->hfs_unknownpermissions = ((mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) != 0);
	namefix =  permfix = 0;

	/* Change the timezone (Note: this affects all hfs volumes and hfs+ volume create dates) */
	if (args->hfs_timezone.tz_minuteswest != VNOVAL) {
		gTimeZone = args->hfs_timezone;
	}

	/* Change the default uid, gid and/or mask */
	if ((args->hfs_uid != (uid_t)VNOVAL) && (hfsmp->hfs_uid != args->hfs_uid)) {
		hfsmp->hfs_uid = args->hfs_uid;
		if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSPlusSigWord)
			++permfix;
	}
	if ((args->hfs_gid != (gid_t)VNOVAL) && (hfsmp->hfs_gid != args->hfs_gid)) {
		hfsmp->hfs_gid = args->hfs_gid;
		if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSPlusSigWord)
			++permfix;
	}
	if (args->hfs_mask != (mode_t)VNOVAL) {
		if (hfsmp->hfs_dir_mask != (args->hfs_mask & ALLPERMS)) {
			hfsmp->hfs_dir_mask = args->hfs_mask & ALLPERMS;
			hfsmp->hfs_file_mask = args->hfs_mask & ALLPERMS;
			if ((args->flags != VNOVAL) && (args->flags & HFSFSMNT_NOXONFILES))
				hfsmp->hfs_file_mask = (args->hfs_mask & DEFFILEMODE);
			if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSPlusSigWord)
				++permfix;
		}
	}
	
	/* Change the hfs encoding value (hfs only) */
	if ((HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord)	&&
	    (hfsmp->hfs_encoding != (u_long)VNOVAL)		&&
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

	/*
	 * For each active vnode fix things that changed
	 *
	 * Note that we can visit a vnode more than once
	 * and we can race with fsync.
	 */
	simple_lock(&mntvnode_slock);
loop:
	for (vp = mp->mnt_vnodelist.lh_first; vp != NULL; vp = nvp) {
		/*
		 * If the vnode that we are about to fix is no longer
		 * associated with this mount point, start over.
		 */
		if (vp->v_mount != mp)
	            goto loop;
	 
	        simple_lock(&vp->v_interlock);
	        nvp = vp->v_mntvnodes.le_next;
		if (vp->v_flag & VSYSTEM) {
			simple_unlock(&vp->v_interlock);
			continue;
		}
	        simple_unlock(&mntvnode_slock);
	        retval = vget(vp, LK_EXCLUSIVE | LK_NOWAIT | LK_INTERLOCK, p);
	        if (retval) {
	            simple_lock(&mntvnode_slock);
	            if (retval == ENOENT)
	                goto loop;
	            continue;
	        }
	
		cp = VTOC(vp);

		retval = cat_lookup(hfsmp, &cp->c_desc, 0, &cndesc, &cnattr, NULL);
		/* If we couldn't find this guy skip to the next one */
		if (retval) {
			if (namefix)
				cache_purge(vp);
			vput(vp);
			simple_lock(&mntvnode_slock);
			continue;
		}

		if (permswitch || permfix) {
			cp->c_uid = cnattr.ca_uid;
			cp->c_gid = cnattr.ca_gid;
			cp->c_mode = cnattr.ca_mode;
		}
		
		/*
		 * If we're switching name converters then...
		 *   Remove the existing entry from the namei cache.
		 *   Update name to one based on new encoder.
		 */
		if (namefix) {
			cache_purge(vp);
			replace_desc(cp, &cndesc);

			if (cndesc.cd_cnid == kHFSRootFolderID) {
				strncpy(vcb->vcbVN, cp->c_desc.cd_nameptr, NAME_MAX);
				cp->c_desc.cd_encoding = hfsmp->hfs_encoding;
			}
		} else {
			cat_releasedesc(&cndesc);
		}
        	vput(vp);
        	simple_lock(&mntvnode_slock);

	} /* end for (vp...) */
	simple_unlock(&mntvnode_slock);
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
hfs_reload(mountp, cred, p)
	register struct mount *mountp;
	struct ucred *cred;
	struct proc *p;
{
	register struct vnode *vp, *nvp, *devvp;
	struct cnode *cp;
	struct buf *bp;
	int sectorsize;
	int error, i;
	struct hfsmount *hfsmp;
	struct HFSPlusVolumeHeader *vhp;
	ExtendedVCB *vcb;
	struct filefork *forkp;
    	struct cat_desc cndesc;

	if ((mountp->mnt_flag & MNT_RDONLY) == 0)
		return (EINVAL);

    	hfsmp = VFSTOHFS(mountp);
	vcb = HFSTOVCB(hfsmp);

	if (vcb->vcbSigWord == kHFSSigWord)
		return (EINVAL);	/* rooting from HFS is not supported! */

	/*
	 * Invalidate all cached meta-data.
	 */
	devvp = hfsmp->hfs_devvp;
	if (vinvalbuf(devvp, 0, cred, p, 0, 0))
		panic("hfs_reload: dirty1");
    	InvalidateCatalogCache(vcb);

loop:
	simple_lock(&mntvnode_slock);
	for (vp = mountp->mnt_vnodelist.lh_first; vp != NULL; vp = nvp) {
		if (vp->v_mount != mountp) {
			simple_unlock(&mntvnode_slock);
			goto loop;
		}
		nvp = vp->v_mntvnodes.le_next;

		/*
		 * Invalidate all inactive vnodes.
		 */
		if (vrecycle(vp, &mntvnode_slock, p))
			goto loop;

		/*
		 * Invalidate all cached file data.
		 */
		simple_lock(&vp->v_interlock);
		simple_unlock(&mntvnode_slock);
		if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, p)) {
			goto loop;
		}
		if (vinvalbuf(vp, 0, cred, p, 0, 0))
			panic("hfs_reload: dirty2");

		/*
		 * Re-read cnode data for all active vnodes (non-metadata files).
		 */
		cp = VTOC(vp);
		if ((vp->v_flag & VSYSTEM) == 0 && !VNODE_IS_RSRC(vp)) {
			struct cat_fork *datafork;
			struct cat_desc desc;

			datafork = cp->c_datafork ? &cp->c_datafork->ff_data : NULL;

			/* lookup by fileID since name could have changed */
			if ((error = cat_idlookup(hfsmp, cp->c_fileid, &desc, &cp->c_attr, datafork))) {
				vput(vp);
				return (error);
			}


			/* update cnode's catalog descriptor */
   			(void) replace_desc(cp, &desc);
		}
		vput(vp);
		simple_lock(&mntvnode_slock);
	}
	simple_unlock(&mntvnode_slock);

	/*
	 * Re-read VolumeHeader from disk.
	 */
	sectorsize = hfsmp->hfs_phys_block_size;

	error = meta_bread(hfsmp->hfs_devvp,
			(vcb->hfsPlusIOPosOffset / sectorsize) + HFS_PRI_SECTOR(sectorsize),
			sectorsize, NOCRED, &bp);
	if (error) {
        	if (bp != NULL)
        		brelse(bp);
		return (error);
	}

	vhp = (HFSPlusVolumeHeader *) (bp->b_data + HFS_PRI_OFFSET(sectorsize));

	/* Do a quick sanity check */
	if (SWAP_BE16(vhp->signature) != kHFSPlusSigWord ||
	    SWAP_BE16(vhp->version) != kHFSPlusVersion   ||
	    SWAP_BE32(vhp->blockSize) != vcb->blockSize) {
		brelse(bp);
		return (EIO);
	}

	vcb->vcbLsMod		= to_bsd_time(SWAP_BE32(vhp->modifyDate));
	vcb->vcbAtrb		= (UInt16) SWAP_BE32 (vhp->attributes);	/* VCB only uses lower 16 bits */
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

	brelse(bp);
	vhp = NULL;

	/*
	 * Re-load B-tree header data
	 */
	forkp = VTOF((struct vnode *)vcb->extentsRefNum);
	if (error = MacToVFSError( BTReloadData((FCB*)forkp) ))
		return (error);

	forkp = VTOF((struct vnode *)vcb->catalogRefNum);
	if (error = MacToVFSError( BTReloadData((FCB*)forkp) ))
		return (error);

	/* Reload the volume name */
	if ((error = cat_idlookup(hfsmp, kHFSRootFolderID, &cndesc, NULL, NULL)))
		return (error);
	vcb->volumeNameEncodingHint = cndesc.cd_encoding;
	bcopy(cndesc.cd_nameptr, vcb->vcbVN, min(255, cndesc.cd_namelen));
	cat_releasedesc(&cndesc);

	/* Re-establish private/hidden directory for unlinked files */
	hfsmp->hfs_private_metadata_dir = FindMetaDataDirectory(vcb);

	return (0);
}


static int
get_raw_device(char *fspec, int is_user, int ronly, struct vnode **rvp, struct ucred *cred, struct proc *p)
{
	char            *rawbuf;
	char            *dp;
	size_t           namelen;
	struct nameidata nd;
	int               retval;

	*rvp = NULL;

	MALLOC(rawbuf, char *, MAXPATHLEN, M_HFSMNT, M_WAITOK);
	if (rawbuf == NULL) {
		retval = ENOMEM;
		goto error_exit;
	}

	if (is_user) {
		retval = copyinstr(fspec, rawbuf, MAXPATHLEN - 1, &namelen);
		if (retval != E_NONE) {
			FREE(rawbuf, M_HFSMNT);
			goto error_exit;
		}
	} else {
		strcpy(rawbuf, fspec);
		namelen = strlen(rawbuf);
	}

	/* make sure it's null terminated */
	rawbuf[MAXPATHLEN-1] = '\0';   

	dp = &rawbuf[namelen-1];
	while(dp >= rawbuf && *dp != '/') {
		dp--;
	}
			
	if (dp != NULL) {
		dp++;
	} else {
		dp = rawbuf;
	}
			
	/* make room for and insert the 'r' for the raw device */
	memmove(dp+1, dp, strlen(dp)+1);
	*dp = 'r';

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, rawbuf, p);
	retval = namei(&nd);
	if (retval != E_NONE) {
		DBG_ERR(("hfs_mountfs: can't open raw device for journal: %s, %x\n", rawbuf, nd.ni_vp->v_rdev));
		FREE(rawbuf, M_HFSMNT);
		goto error_exit;
	}

	*rvp = nd.ni_vp;
	if ((retval = VOP_OPEN(*rvp, ronly ? FREAD : FREAD|FWRITE, FSCRED, p))) {
		*rvp = NULL;
		goto error_exit;
	}

	// don't need this any more
	FREE(rawbuf, M_HFSMNT);

	return 0;

  error_exit:
	if (*rvp) {
	    (void)VOP_CLOSE(*rvp, ronly ? FREAD : FREAD|FWRITE, cred, p);
	}

	if (rawbuf) {
		FREE(rawbuf, M_HFSMNT);
	}
	return retval;
}



/*
 * Common code for mount and mountroot
 */
static int
hfs_mountfs(struct vnode *devvp, struct mount *mp, struct proc *p,
	struct hfs_mount_args *args)
{
	int retval = E_NONE;
	struct hfsmount	*hfsmp;
	struct buf *bp;
	dev_t dev;
	HFSMasterDirectoryBlock *mdbp;
	int ronly;
	int i;
	int mntwrapper;
	struct ucred *cred;
	u_int64_t disksize;
	u_int64_t blkcnt;
	u_int32_t blksize;
	u_int32_t minblksize;
	u_int32_t iswritable;
	daddr_t   mdb_offset;

	dev = devvp->v_rdev;
	cred = p ? p->p_ucred : NOCRED;
	mntwrapper = 0;
    /*
     * Disallow multiple mounts of the same device.
     * Disallow mounting of a device that is currently in use
     * (except for root, which might share swap device for miniroot).
     * Flush out any old buffers remaining from a previous use.
     */
    if ((retval = vfs_mountedon(devvp)))
        return (retval);
    if ((vcount(devvp) > 1) && (devvp != rootvp))
                return (EBUSY);
    if ((retval = vinvalbuf(devvp, V_SAVE, cred, p, 0, 0)))
        return (retval);

    ronly = (mp->mnt_flag & MNT_RDONLY) != 0;
    if ((retval = VOP_OPEN(devvp, ronly ? FREAD : FREAD|FWRITE, FSCRED, p)))
        return (retval);

	bp = NULL;
	hfsmp = NULL;
	mdbp = NULL;
	minblksize = kHFSBlockSize;

	/* Get the real physical block size. */
	if (VOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&blksize, 0, cred, p)) {
		retval = ENXIO;
		goto error_exit;
	}
	/* Switch to 512 byte sectors (temporarily) */
	if (blksize > 512) {
		u_int32_t size512 = 512;

		if (VOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&size512, FWRITE, cred, p)) {
			retval = ENXIO;
			goto error_exit;
		}
	}
	/* Get the number of 512 byte physical blocks. */
	if (VOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, cred, p)) {
		retval = ENXIO;
		goto error_exit;
	}
	/* Compute an accurate disk size (i.e. within 512 bytes) */
	disksize = blkcnt * (u_int64_t)512;

	/*
	 * There are only 31 bits worth of block count in
	 * the buffer cache.  So for large volumes a 4K
	 * physical block size is needed.
	 */
	if (blkcnt > (u_int64_t)0x000000007fffffff) {
		minblksize = blksize = 4096;
	}
	/* Now switch to our prefered physical block size. */
	if (blksize > 512) {
		if (VOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&blksize, FWRITE, cred, p)) {
			retval = ENXIO;
			goto error_exit;
		}
		/* Get the count of physical blocks. */
		if (VOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, cred, p)) {
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
	devvp->v_specsize = blksize;

	/* cache the IO attributes */
	if ((retval = vfs_init_io_attributes(devvp, mp))) {
		printf("hfs_mountfs: vfs_init_io_attributes returned %d\n",
			retval);
		return (retval);
	}

	mdb_offset = HFS_PRI_SECTOR(blksize);
	if ((retval = meta_bread(devvp, HFS_PRI_SECTOR(blksize), blksize, cred, &bp))) {
		goto error_exit;
	}
	MALLOC(mdbp, HFSMasterDirectoryBlock *, kMDBSize, M_TEMP, M_WAITOK);
	bcopy(bp->b_data + HFS_PRI_OFFSET(blksize), mdbp, kMDBSize);
	brelse(bp);
	bp = NULL;

	MALLOC(hfsmp, struct hfsmount *, sizeof(struct hfsmount), M_HFSMNT, M_WAITOK);
	bzero(hfsmp, sizeof(struct hfsmount));

	simple_lock_init(&hfsmp->hfs_renamelock);
	
	/*
	*  Init the volume information structure
	*/
	mp->mnt_data = (qaddr_t)hfsmp;
	hfsmp->hfs_mp = mp;			/* Make VFSTOHFS work */
	hfsmp->hfs_vcb.vcb_hfsmp = hfsmp;	/* Make VCBTOHFS work */
	hfsmp->hfs_raw_dev = devvp->v_rdev;
	hfsmp->hfs_devvp = devvp;
	hfsmp->hfs_phys_block_size = blksize;
	hfsmp->hfs_phys_block_count = blkcnt;
	hfsmp->hfs_media_writeable = 1;
	hfsmp->hfs_fs_ronly = ronly;
	hfsmp->hfs_unknownpermissions = ((mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) != 0);
	for (i = 0; i < MAXQUOTAS; i++)
		hfsmp->hfs_qfiles[i].qf_vp = NULLVP;

	if (args) {
		hfsmp->hfs_uid = (args->hfs_uid == (uid_t)VNOVAL) ? UNKNOWNUID : args->hfs_uid;
		if (hfsmp->hfs_uid == 0xfffffffd) hfsmp->hfs_uid = UNKNOWNUID;
		hfsmp->hfs_gid = (args->hfs_gid == (gid_t)VNOVAL) ? UNKNOWNGID : args->hfs_gid;
		if (hfsmp->hfs_gid == 0xfffffffd) hfsmp->hfs_gid = UNKNOWNGID;
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
		if (mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
			hfsmp->hfs_uid = UNKNOWNUID;
			hfsmp->hfs_gid = UNKNOWNGID;
			hfsmp->hfs_dir_mask = UNKNOWNPERMISSIONS & ALLPERMS;		/* 0777: rwx---rwx */
			hfsmp->hfs_file_mask = UNKNOWNPERMISSIONS & DEFFILEMODE;	/* 0666: no --x by default? */
		}
	}

	/* Find out if disk media is writable. */
	if (VOP_IOCTL(devvp, DKIOCISWRITABLE, (caddr_t)&iswritable, 0, cred, p) == 0) {
		if (iswritable)
			hfsmp->hfs_media_writeable = 1;
		else
			hfsmp->hfs_media_writeable = 0;
	}

	/* Mount a standard HFS disk */
	if ((SWAP_BE16(mdbp->drSigWord) == kHFSSigWord) &&
	    (mntwrapper || (SWAP_BE16(mdbp->drEmbedSigWord) != kHFSPlusSigWord))) {
		if (devvp == rootvp) {
			retval = EINVAL;  /* Cannot root from HFS standard disks */
			goto error_exit;
		}
		/* HFS disks can only use 512 byte physical blocks */
		if (blksize > kHFSBlockSize) {
			blksize = kHFSBlockSize;
			if (VOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&blksize, FWRITE, cred, p)) {
				retval = ENXIO;
				goto error_exit;
			}
			if (VOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, cred, p)) {
				retval = ENXIO;
				goto error_exit;
			}
			devvp->v_specsize = blksize;
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
				if (VOP_IOCTL(devvp, DKIOCSETBLOCKSIZE,
				    (caddr_t)&blksize, FWRITE, cred, p)) {
					retval = ENXIO;
					goto error_exit;
				}
				if (VOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT,
				    (caddr_t)&blkcnt, 0, cred, p)) {
					retval = ENXIO;
					goto error_exit;
				}
				/* XXX do we need to call vfs_init_io_attributes again? */
				devvp->v_specsize = blksize;
				/* Note: relative block count adjustment */
				hfsmp->hfs_phys_block_count *=
				    hfsmp->hfs_phys_block_size / blksize;
				hfsmp->hfs_phys_block_size = blksize;
			}

			disksize = (u_int64_t)SWAP_BE16(mdbp->drEmbedExtent.blockCount) *
			           (u_int64_t)SWAP_BE32(mdbp->drAlBlkSiz);

			hfsmp->hfs_phys_block_count = disksize / blksize;
	
			mdb_offset = (embeddedOffset / blksize) + HFS_PRI_SECTOR(blksize);
			retval = meta_bread(devvp, mdb_offset, blksize, cred, &bp);
			if (retval)
				goto error_exit;
			bcopy(bp->b_data + HFS_PRI_OFFSET(blksize), mdbp, 512);
			brelse(bp);
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
				mp->mnt_flag |= MNT_JOURNALED;
			} else {
				retval = EINVAL;
				goto error_exit;
			}
		}
		// XXXdbg
	
		(void) hfs_getconverter(0, &hfsmp->hfs_get_unicode, &hfsmp->hfs_get_hfsname);

		retval = hfs_MountHFSPlusVolume(hfsmp, vhp, embeddedOffset, disksize, p, args);
		/*
		 * If the backend didn't like our physical blocksize
		 * then retry with physical blocksize of 512.
		 */
		if ((retval == ENXIO) && (blksize > 512) && (blksize != minblksize)) {
			printf("HFS Mount: could not use physical block size "
				"(%d) switching to 512\n", blksize);
			blksize = 512;
			if (VOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&blksize, FWRITE, cred, p)) {
				retval = ENXIO;
				goto error_exit;
			}
			if (VOP_IOCTL(devvp, DKIOCGETBLOCKCOUNT, (caddr_t)&blkcnt, 0, cred, p)) {
				retval = ENXIO;
				goto error_exit;
			}
			devvp->v_specsize = blksize;
			/* Note: relative block count adjustment (in case this is an embedded volume). */
    			hfsmp->hfs_phys_block_count *= hfsmp->hfs_phys_block_size / blksize;
     			hfsmp->hfs_phys_block_size = blksize;
 
			/* Try again with a smaller block size... */
			retval = hfs_MountHFSPlusVolume(hfsmp, vhp, embeddedOffset, disksize, p, args);
		}
		if (retval)
			(void) hfs_relconverter(0);
	}

	if ( retval ) {
		goto error_exit;
	}

	mp->mnt_stat.f_fsid.val[0] = (long)dev;
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	mp->mnt_maxsymlinklen = 0;
	devvp->v_specflags |= SI_MOUNTEDON;

	if (ronly == 0) {
		(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, 0);
	}
	FREE(mdbp, M_TEMP);
	return (0);

error_exit:
	if (bp)
		brelse(bp);
	if (mdbp)
		FREE(mdbp, M_TEMP);
	(void)VOP_CLOSE(devvp, ronly ? FREAD : FREAD|FWRITE, cred, p);
	if (hfsmp && hfsmp->jvp && hfsmp->jvp != hfsmp->hfs_devvp) {
	    (void)VOP_CLOSE(hfsmp->jvp, ronly ? FREAD : FREAD|FWRITE, cred, p);
		hfsmp->jvp = NULL;
	}
	if (hfsmp) {
		FREE(hfsmp, M_HFSMNT);
		mp->mnt_data = (qaddr_t)0;
	}
        return (retval);
}


/*
 * Make a filesystem operational.
 * Nothing to do at the moment.
 */
/* ARGSUSED */
static int
hfs_start(mp, flags, p)
	struct mount *mp;
	int flags;
	struct proc *p;
{
	return (0);
}


/*
 * unmount system call
 */
static int
hfs_unmount(mp, mntflags, p)
	struct mount *mp;
	int mntflags;
	struct proc *p;
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	int retval = E_NONE;
	int flags;
	int force;
	int started_tr = 0, grabbed_lock = 0;

	flags = 0;
	force = 0;
	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
		force = 1;
	}

	if ((retval = hfs_flushfiles(mp, flags, p)) && !force)
 		return (retval);

	/*
	 * Flush out the b-trees, volume bitmap and Volume Header
	 */
	if (hfsmp->hfs_fs_ronly == 0) {
		hfs_global_shared_lock_acquire(hfsmp);
		grabbed_lock = 1;
	    if (hfsmp->jnl) {
			journal_start_transaction(hfsmp->jnl);
			started_tr = 1;
		}
		
		retval = VOP_FSYNC(HFSTOVCB(hfsmp)->catalogRefNum, NOCRED, MNT_WAIT, p);
		if (retval && !force)
			goto err_exit;
		
		retval = VOP_FSYNC(HFSTOVCB(hfsmp)->extentsRefNum, NOCRED, MNT_WAIT, p);
		if (retval && !force)
			goto err_exit;
			
		// if we have an allocation file, sync it too so we don't leave dirty
		// blocks around
		if (HFSTOVCB(hfsmp)->allocationsRefNum) {
		    if (retval = VOP_FSYNC(HFSTOVCB(hfsmp)->allocationsRefNum, NOCRED, MNT_WAIT, p)) {
			if (!force)
			    goto err_exit;
		    }
		}

		if (retval = VOP_FSYNC(hfsmp->hfs_devvp, NOCRED, MNT_WAIT, p)) {
			if (!force)
				goto err_exit;
		}
		
		/* See if this volume is damaged, is so do not unmount cleanly */
		if (HFSTOVCB(hfsmp)->vcbFlags & kHFS_DamagedVolume) {
			HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeUnmountedMask;
		} else {
			HFSTOVCB(hfsmp)->vcbAtrb |= kHFSVolumeUnmountedMask;
		}

		retval = hfs_flushvolumeheader(hfsmp, MNT_WAIT, 1);
		if (retval) {
			HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeUnmountedMask;
			if (!force)
				goto err_exit;	/* could not flush everything */
		}

		if (hfsmp->jnl) {
			journal_end_transaction(hfsmp->jnl);
			started_tr = 0;
		}
		if (grabbed_lock) {
			hfs_global_shared_lock_release(hfsmp);
			grabbed_lock = 0;
		}
	}

	if (hfsmp->jnl) {
		journal_flush(hfsmp->jnl);
	}
	
	/*
	 *	Invalidate our caches and release metadata vnodes
	 */
	(void) hfsUnmount(hfsmp, p);

	if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord)
		(void) hfs_relconverter(hfsmp->hfs_encoding);

	// XXXdbg
	if (hfsmp->jnl) {
	    journal_close(hfsmp->jnl);
	}

	if (hfsmp->jvp && hfsmp->jvp != hfsmp->hfs_devvp) {
	    retval = VOP_CLOSE(hfsmp->jvp, hfsmp->hfs_fs_ronly ? FREAD : FREAD|FWRITE,
			       NOCRED, p);
	    vrele(hfsmp->jvp);
		hfsmp->jvp = NULL;
	}
	// XXXdbg

	hfsmp->hfs_devvp->v_specflags &= ~SI_MOUNTEDON;
	retval = VOP_CLOSE(hfsmp->hfs_devvp,
		    hfsmp->hfs_fs_ronly ? FREAD : FREAD|FWRITE,
		    NOCRED, p);
	if (retval && !force)
		return(retval);

	vrele(hfsmp->hfs_devvp);
	FREE(hfsmp, M_HFSMNT);
	mp->mnt_data = (qaddr_t)0;
	return (0);

  err_exit:
	if (hfsmp->jnl && started_tr) {
		journal_end_transaction(hfsmp->jnl);
	}
	if (grabbed_lock) {
		hfs_global_shared_lock_release(hfsmp);
	}
	return retval;
}


/*
 * Return the root of a filesystem.
 *
 *              OUT - vpp, should be locked and vget()'d (to increment usecount and lock)
 */
static int
hfs_root(mp, vpp)
	struct mount *mp;
	struct vnode **vpp;
{
	struct vnode *nvp;
	int retval;
	UInt32 rootObjID = kRootDirID;

	if ((retval = VFS_VGET(mp, &rootObjID, &nvp)))
		return (retval);

	*vpp = nvp;
	return (0);
}


/*
 * Do operations associated with quotas
 */
int
hfs_quotactl(mp, cmds, uid, arg, p)
	struct mount *mp;
	int cmds;
	uid_t uid;
	caddr_t arg;
	struct proc *p;
{
	int cmd, type, error;

#if !QUOTA
	return (EOPNOTSUPP);
#else
	if (uid == -1)
		uid = p->p_cred->p_ruid;
	cmd = cmds >> SUBCMDSHIFT;

	switch (cmd) {
	case Q_SYNC:
	case Q_QUOTASTAT:
		break;
	case Q_GETQUOTA:
		if (uid == p->p_cred->p_ruid)
			break;
		/* fall through */
	default:
		if (error = suser(p->p_ucred, &p->p_acflag))
			return (error);
	}

	type = cmds & SUBCMDMASK;
	if ((u_int)type >= MAXQUOTAS)
		return (EINVAL);
	if (vfs_busy(mp, LK_NOWAIT, 0, p))
		return (0);

	switch (cmd) {

	case Q_QUOTAON:
		error = hfs_quotaon(p, mp, type, arg, UIO_USERSPACE);
		break;

	case Q_QUOTAOFF:
		error = hfs_quotaoff(p, mp, type);
		break;

	case Q_SETQUOTA:
		error = hfs_setquota(mp, uid, type, arg);
		break;

	case Q_SETUSE:
		error = hfs_setuse(mp, uid, type, arg);
		break;

	case Q_GETQUOTA:
		error = hfs_getquota(mp, uid, type, arg);
		break;

	case Q_SYNC:
		error = hfs_qsync(mp);
		break;

	case Q_QUOTASTAT:
		error = hfs_quotastat(mp, type, arg);
		break;

	default:
		error = EINVAL;
		break;
	}
	vfs_unbusy(mp, p);
	return (error);
#endif /* QUOTA */
}




/*
 * Get file system statistics.
 */
static int
hfs_statfs(mp, sbp, p)
	struct mount *mp;
	register struct statfs *sbp;
	struct proc *p;
{
	ExtendedVCB *vcb = VFSTOVCB(mp);
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	u_long freeCNIDs;

	freeCNIDs = (u_long)0xFFFFFFFF - (u_long)vcb->vcbNxtCNID;

	sbp->f_bsize = vcb->blockSize;
	sbp->f_iosize = hfsmp->hfs_logBlockSize;
	sbp->f_blocks = vcb->totalBlocks;
	sbp->f_bfree = hfs_freeblks(hfsmp, 0);
	sbp->f_bavail = hfs_freeblks(hfsmp, 1);
	sbp->f_files = vcb->totalBlocks - 2;  /* max files is constrained by total blocks */
	sbp->f_ffree = MIN(freeCNIDs, sbp->f_bavail);
	
	sbp->f_type = 0;
	if (sbp != &mp->mnt_stat) {
		sbp->f_type = mp->mnt_vfc->vfc_typenum;
		bcopy((caddr_t)mp->mnt_stat.f_mntonname,
			(caddr_t)&sbp->f_mntonname[0], MNAMELEN);
		bcopy((caddr_t)mp->mnt_stat.f_mntfromname,
			(caddr_t)&sbp->f_mntfromname[0], MNAMELEN);
	}
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
	struct cnode *cp;
	struct hfsmount *hfsmp;
	ExtendedVCB *vcb;
	struct vnode *meta_vp[3];
	struct buf *bp;
	int i, sectorsize, priIDSector, altIDSector, retval;
	int error, allerror = 0;

	hfsmp = VFSTOHFS(mp);
	vcb = HFSTOVCB(hfsmp);

	bflushq(BQ_META, mp);


#if 1     // XXXdbg - I do not believe this is necessary...
          //          but if I pull it out, then the journal
	      //          does not seem to get flushed properly
	      //          when it is closed....
	
	// now make sure the super block is flushed
	sectorsize = hfsmp->hfs_phys_block_size;
	priIDSector = (vcb->hfsPlusIOPosOffset / sectorsize) +
                  HFS_PRI_SECTOR(sectorsize);
	retval = meta_bread(hfsmp->hfs_devvp, priIDSector, sectorsize, NOCRED, &bp);
	if (retval != 0) {
		panic("hfs: sync_metadata: can't read super-block?! (retval 0x%x, priIDSector)\n",
			  retval, priIDSector);
	}

	if (retval == 0 && (bp->b_flags & B_DELWRI) && (bp->b_flags & B_LOCKED) == 0) {
	    bwrite(bp);
	} else if (bp) {
	    brelse(bp);
	}

	// the alternate super block...
	// XXXdbg - we probably don't need to do this each and every time.
	//          hfs_btreeio.c:FlushAlternate() should flag when it was
	//          written...
	altIDSector = (vcb->hfsPlusIOPosOffset / sectorsize) +
			HFS_ALT_SECTOR(sectorsize, hfsmp->hfs_phys_block_count);
	retval = meta_bread(hfsmp->hfs_devvp, altIDSector, sectorsize, NOCRED, &bp);
	if (retval == 0 && (bp->b_flags & B_DELWRI) && (bp->b_flags & B_LOCKED) == 0) {
	    bwrite(bp);
	} else if (bp) {
	    brelse(bp);
	}
#endif
	
}

/*
 * Go through the disk queues to initiate sandbagged IO;
 * go through the inodes to write those that have been modified;
 * initiate the writing of the super block if it has been modified.
 *
 * Note: we are always called with the filesystem marked `MPBUSY'.
 */
static int
hfs_sync(mp, waitfor, cred, p)
	struct mount *mp;
	int waitfor;
	struct ucred *cred;
	struct proc *p;
{
	struct vnode *nvp, *vp;
	struct cnode *cp;
	struct hfsmount *hfsmp;
	ExtendedVCB *vcb;
	struct vnode *meta_vp[3];
	int i;
	int error, allerror = 0;

	/*
	 * During MNT_UPDATE hfs_changefs might be manipulating
	 * vnodes so back off
	 */
	if (mp->mnt_flag & MNT_UPDATE)
		return (0);

	hfsmp = VFSTOHFS(mp);
	if (hfsmp->hfs_fs_ronly != 0) {
		panic("update: rofs mod");
	};

#if 0
	// XXXdbg first go through and flush out any modified
	//        meta data blocks so they go out in order...
	bflushq(BQ_META, mp);
	bflushq(BQ_LRU,  mp);
	// only flush locked blocks if we're not doing journaling
	if (hfsmp->jnl == NULL) {
	    bflushq(BQ_LOCKED, mp);
	}
#endif

	/*
	 * Write back each 'modified' vnode
	 */

loop:
	simple_lock(&mntvnode_slock);
	for (vp = mp->mnt_vnodelist.lh_first; vp != NULL; vp = nvp) {
		 int didhold;
		/*
		 * If the vnode that we are about to sync is no longer
		 * associated with this mount point, start over.
		 */
		if (vp->v_mount != mp) {
			simple_unlock(&mntvnode_slock);
			goto loop;
		}

		simple_lock(&vp->v_interlock);
		nvp = vp->v_mntvnodes.le_next;

		cp = VTOC(vp);

		// restart our whole search if this guy is locked
		// or being reclaimed.
		// XXXdbg - at some point this should go away or we
		//          need to change all file systems to have
		//          this same code.  vget() should never return
		//          success if either of these conditions is
		//          true.
		if (vp->v_tag != VT_HFS || cp == NULL) {
			simple_unlock(&vp->v_interlock);
			continue;
		}

		if ((vp->v_flag & VSYSTEM) || (vp->v_type == VNON) ||
		    (((cp->c_flag & (C_ACCESS | C_CHANGE | C_MODIFIED | C_UPDATE)) == 0) &&
		    (vp->v_dirtyblkhd.lh_first == NULL) && !(vp->v_flag & VHASDIRTY))) {
			simple_unlock(&vp->v_interlock);
			simple_unlock(&mntvnode_slock);
			simple_lock(&mntvnode_slock);
			continue;
		}

		simple_unlock(&mntvnode_slock);
		error = vget(vp, LK_EXCLUSIVE | LK_NOWAIT | LK_INTERLOCK, p);
		if (error) {
			if (error == ENOENT)
				goto loop;
			simple_lock(&mntvnode_slock);
			continue;
		}
		
		didhold = ubc_hold(vp);
		if ((error = VOP_FSYNC(vp, cred, waitfor, p))) {
			allerror = error;
		};
		VOP_UNLOCK(vp, 0, p);
		if (didhold)
			ubc_rele(vp);
		vrele(vp);
		simple_lock(&mntvnode_slock);
	};

	vcb = HFSTOVCB(hfsmp);

	meta_vp[0] = vcb->extentsRefNum;
	meta_vp[1] = vcb->catalogRefNum;
	meta_vp[2] = vcb->allocationsRefNum;  /* This is NULL for standard HFS */

	/* Now sync our three metadata files */
	for (i = 0; i < 3; ++i) {
		struct vnode *btvp;

		btvp = btvp = meta_vp[i];;
		if ((btvp==0) || (btvp->v_type == VNON) || (btvp->v_mount != mp))
			continue;

		simple_lock(&btvp->v_interlock);
		cp = VTOC(btvp);
		if (((cp->c_flag & (C_ACCESS | C_CHANGE | C_MODIFIED | C_UPDATE)) == 0) &&
		    (btvp->v_dirtyblkhd.lh_first == NULL) && !(btvp->v_flag & VHASDIRTY)) {
			simple_unlock(&btvp->v_interlock);
			continue;
		}
		simple_unlock(&mntvnode_slock);
		error = vget(btvp, LK_EXCLUSIVE | LK_NOWAIT | LK_INTERLOCK, p);
		if (error) {
			simple_lock(&mntvnode_slock);
			continue;
		}
		if ((error = VOP_FSYNC(btvp, cred, waitfor, p)))
			allerror = error;
		VOP_UNLOCK(btvp, 0, p);
		vrele(btvp);
		simple_lock(&mntvnode_slock);
	};

	simple_unlock(&mntvnode_slock);

	/*
	 * Force stale file system control information to be flushed.
	 */
	if (vcb->vcbSigWord == kHFSSigWord) {
		if ((error = VOP_FSYNC(hfsmp->hfs_devvp, cred, waitfor, p)))
			allerror = error;
	}
#if QUOTA
	hfs_qsync(mp);
#endif /* QUOTA */
	/*
	 * Write back modified superblock.
	 */

	if (IsVCBDirty(vcb)) {
		// XXXdbg - debugging, remove
		if (hfsmp->jnl) {
			//printf("hfs: sync: strange, a journaled volume w/dirty VCB? jnl 0x%x hfsmp 0x%x\n",
			//	  hfsmp->jnl, hfsmp);
		}

		error = hfs_flushvolumeheader(hfsmp, waitfor, 0);
		if (error)
			allerror = error;
	}

	if (hfsmp->jnl) {
	    journal_flush(hfsmp->jnl);
	}
	
  err_exit:
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
hfs_fhtovp(mp, fhp, nam, vpp, exflagsp, credanonp)
	register struct mount *mp;
	struct fid *fhp;
	struct mbuf *nam;
	struct vnode **vpp;
	int *exflagsp;
	struct ucred **credanonp;
{
	struct hfsfid *hfsfhp;
	struct vnode *nvp;
	int result;
	struct netcred *np;

	*vpp = NULL;
	hfsfhp = (struct hfsfid *)fhp;

	/*
	 * Get the export permission structure for this <mp, client> tuple.
	 */
	np = vfs_export_lookup(mp, &VFSTOHFS(mp)->hfs_export, nam);
	if (np == NULL) {
		return EACCES;
	};

	result = VFS_VGET(mp, &hfsfhp->hfsfid_cnid, &nvp);
	if (result) return result;
	if (nvp == NULL) return ESTALE;
	
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
	if ((hfsfhp->hfsfid_gen < VTOC(nvp)->c_itime)) {
		vput(nvp);
		return (ESTALE);
	};
	
	*vpp = nvp;
	*exflagsp = np->netc_exflags;
	*credanonp = &np->netc_anon;
	
	return (0);
}


/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
static int
hfs_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{
	struct cnode *cp;
	struct hfsfid *hfsfhp;

	if (ISHFS(VTOVCB(vp)))
		return (EOPNOTSUPP);	/* hfs standard is not exportable */

	cp = VTOC(vp);
	hfsfhp = (struct hfsfid *)fhp;
	hfsfhp->hfsfid_len = sizeof(struct hfsfid);
	hfsfhp->hfsfid_pad = 0;
	hfsfhp->hfsfid_cnid = cp->c_cnid;
	hfsfhp->hfsfid_gen = cp->c_itime;
	
	return (0);
}


/*
 * Initial HFS filesystems, done only once.
 */
static int
hfs_init(vfsp)
	struct vfsconf *vfsp;
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

	/*
	 * Allocate Catalog Iterator cache...
	 */
	(void) InitCatalogCache();

	return (0);
}


// XXXdbg
#include <sys/filedesc.h>


/*
 * HFS filesystem related variables.
 */
static int
hfs_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	extern u_int32_t hfs_encodingbias;

	/* all sysctl names at this level are terminal */

	if (name[0] == HFS_ENCODINGBIAS)
		return (sysctl_int(oldp, oldlenp, newp, newlen,
				&hfs_encodingbias));
	else if (name[0] == 0x082969) {
		// make the file system journaled...
		struct vnode *vp = p->p_fd->fd_cdir, *jvp;
		struct hfsmount *hfsmp;
		ExtendedVCB *vcb;
		int retval;
		struct cat_attr jnl_attr, jinfo_attr;
		struct cat_fork jnl_fork, jinfo_fork;
		void *jnl = NULL;

		/* Only root can enable journaling */
        if (current_proc()->p_ucred->cr_uid != 0) {
			return (EPERM);
		}
		hfsmp = VTOHFS(vp);
		if (hfsmp->hfs_fs_ronly) {
			return EROFS;
		}
		if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord) {
			printf("hfs: can't make a plain hfs volume journaled.\n");
			return EINVAL;
		}

		if (hfsmp->jnl) {
		    printf("hfs: volume @ mp 0x%x is already journaled!\n", vp->v_mount);
		    return EAGAIN;
		}

		vcb = HFSTOVCB(hfsmp);
		if (BTHasContiguousNodes(VTOF(vcb->catalogRefNum)) == 0 ||
			BTHasContiguousNodes(VTOF(vcb->extentsRefNum)) == 0) {

			printf("hfs: volume has a btree w/non-contiguous nodes.  can not enable journaling.\n");
			return EINVAL;
		}

		// make sure these both exist!
		if (   GetFileInfo(vcb, kRootDirID, ".journal_info_block", &jinfo_attr, &jinfo_fork) == 0
			|| GetFileInfo(vcb, kRootDirID, ".journal", &jnl_attr, &jnl_fork) == 0) {

			return EINVAL;
		}

		hfs_sync(hfsmp->hfs_mp, MNT_WAIT, FSCRED, p);
		bflushq(BQ_META);

		printf("hfs: Initializing the journal (joffset 0x%llx sz 0x%llx)...\n",
			   (off_t)name[2], (off_t)name[3]);

		jvp = hfsmp->hfs_devvp;
		jnl = journal_create(jvp,
							 (off_t)name[2] * (off_t)HFSTOVCB(hfsmp)->blockSize
							 + HFSTOVCB(hfsmp)->hfsPlusIOPosOffset,
							 (off_t)name[3],
							 hfsmp->hfs_devvp,
							 hfsmp->hfs_phys_block_size,
							 0,
							 0,
							 hfs_sync_metadata, hfsmp->hfs_mp);

		if (jnl == NULL) {
			printf("hfs: FAILED to create the journal!\n");
			if (jvp && jvp != hfsmp->hfs_devvp) {
				VOP_CLOSE(jvp, hfsmp->hfs_fs_ronly ? FREAD : FREAD|FWRITE, FSCRED, p);
			}
			jvp = NULL;

			return EINVAL;
		} 

		hfs_global_exclusive_lock_acquire(hfsmp);
		
		HFSTOVCB(hfsmp)->vcbJinfoBlock = name[1];
		HFSTOVCB(hfsmp)->vcbAtrb |= kHFSVolumeJournaledMask;
		hfsmp->jvp = jvp;
		hfsmp->jnl = jnl;

		// save this off for the hack-y check in hfs_remove()
		hfsmp->jnl_start        = (u_int32_t)name[2];
		hfsmp->hfs_jnlinfoblkid = jinfo_attr.ca_fileid;
		hfsmp->hfs_jnlfileid    = jnl_attr.ca_fileid;

		hfsmp->hfs_mp->mnt_flag |= MNT_JOURNALED;

		hfs_global_exclusive_lock_release(hfsmp);
		hfs_flushvolumeheader(hfsmp, MNT_WAIT, 1);

		return 0;
	} else if (name[0] == 0x031272) {
		// clear the journaling bit 
		struct vnode *vp = p->p_fd->fd_cdir;
		struct hfsmount *hfsmp;
		void *jnl;
		int retval;
		
		/* Only root can disable journaling */
        if (current_proc()->p_ucred->cr_uid != 0) {
			return (EPERM);
		}
		hfsmp = VTOHFS(vp);
		if (hfsmp->jnl == NULL) {
			return EINVAL;
		}

		printf("hfs: disabling journaling for mount @ 0x%x\n", vp->v_mount);

		jnl = hfsmp->jnl;
		
		hfs_global_exclusive_lock_acquire(hfsmp);

		// Lights out for you buddy!
		hfsmp->jnl = NULL;
		journal_close(jnl);

		if (hfsmp->jvp && hfsmp->jvp != hfsmp->hfs_devvp) {
			VOP_CLOSE(hfsmp->jvp, hfsmp->hfs_fs_ronly ? FREAD : FREAD|FWRITE, FSCRED, p);
		}
		hfsmp->jnl = NULL;
		hfsmp->jvp = NULL;
		hfsmp->hfs_mp->mnt_flag &= ~MNT_JOURNALED;
		hfsmp->jnl_start        = 0;
		hfsmp->hfs_jnlinfoblkid = 0;
		hfsmp->hfs_jnlfileid    = 0;
		
		HFSTOVCB(hfsmp)->vcbAtrb &= ~kHFSVolumeJournaledMask;
		
		hfs_global_exclusive_lock_release(hfsmp);
		hfs_flushvolumeheader(hfsmp, MNT_WAIT, 1);

		return 0;
	}

	return (EOPNOTSUPP);
}


/*	This will return a vnode of either a directory or a data vnode based on an object id. If
 *  it is a file id, its data fork will be returned.
 */
static int
hfs_vget(mp, ino, vpp)
	struct mount *mp;
	void *ino;
	struct vnode **vpp;
{
	cnid_t cnid = *(cnid_t *)ino;
	
	/* Check for cnids that should't be exported. */
	if ((cnid < kHFSFirstUserCatalogNodeID)
	&&  (cnid != kHFSRootFolderID && cnid != kHFSRootParentID))
		return (ENOENT);
	/* Don't export HFS Private Data dir. */
	if (cnid == VFSTOHFS(mp)->hfs_privdir_desc.cd_cnid)
		return (ENOENT);

	return (hfs_getcnode(VFSTOHFS(mp), cnid, NULL, 0, NULL, NULL, vpp));
}

/*
 * Flush out all the files in a filesystem.
 */
int
hfs_flushfiles(struct mount *mp, int flags, struct proc *p)
{
	register struct hfsmount *hfsmp;
	int i;
	int error;

#if QUOTA
	hfsmp = VFSTOHFS(mp);

	if (mp->mnt_flag & MNT_QUOTA) {
		if (error = vflush(mp, NULLVP, SKIPSYSTEM|flags))
			return (error);
		for (i = 0; i < MAXQUOTAS; i++) {
			if (hfsmp->hfs_qfiles[i].qf_vp == NULLVP)
				continue;
			hfs_quotaoff(p, mp, i);
		}
		/*
		 * Here we fall through to vflush again to ensure
		 * that we have gotten rid of all the system vnodes.
		 */
	}
#endif /* QUOTA */

	error = vflush(mp, NULLVP, (SKIPSYSTEM | SKIPSWAP | flags));
	error = vflush(mp, NULLVP, (SKIPSYSTEM | flags));

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

	if (index < 128) {
		HFSTOVCB(hfsmp)->encodingsBitmap |= (1 << index);
		HFSTOVCB(hfsmp)->vcbFlags |= 0xFF00;
	}
}

/*
 * Update volume stats
 */
__private_extern__
int
hfs_volupdate(struct hfsmount *hfsmp, enum volop op, int inroot)
{
	ExtendedVCB *vcb;

	vcb = HFSTOVCB(hfsmp);
	vcb->vcbFlags |= 0xFF00;
	vcb->vcbLsMod = time.tv_sec;

	switch (op) {
	case VOL_UPDATE:
		break;
	case VOL_MKDIR:
		if (vcb->vcbDirCnt != 0xFFFFFFFF)
			++vcb->vcbDirCnt;
		if (inroot && vcb->vcbNmRtDirs != 0xFFFF)
			++vcb->vcbNmRtDirs;
		break;
	case VOL_RMDIR:
		if (vcb->vcbDirCnt != 0)
			--vcb->vcbDirCnt;
		if (inroot && vcb->vcbNmRtDirs != 0xFFFF)
			--vcb->vcbNmRtDirs;
		break;
	case VOL_MKFILE:
		if (vcb->vcbFilCnt != 0xFFFFFFFF)
			++vcb->vcbFilCnt;
		if (inroot && vcb->vcbNmFls != 0xFFFF)
			++vcb->vcbNmFls;
		break;
	case VOL_RMFILE:
		if (vcb->vcbFilCnt != 0)
			--vcb->vcbFilCnt;
		if (inroot && vcb->vcbNmFls != 0xFFFF)
			--vcb->vcbNmFls;
		break;
	}

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
	retval = bread(hfsmp->hfs_devvp, HFS_PRI_SECTOR(sectorsize), sectorsize, NOCRED, &bp);
	if (retval) {
		if (bp)
			brelse(bp);
		return retval;
	}

	DBG_ASSERT(bp != NULL);
	DBG_ASSERT(bp->b_data != NULL);
	DBG_ASSERT(bp->b_bcount == size);

	if (hfsmp->jnl) {
		panic("hfs: standard hfs volumes should not be journaled!\n");
	}

	mdb = (HFSMasterDirectoryBlock *)(bp->b_data + HFS_PRI_OFFSET(sectorsize));
    
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
	
	fp = VTOF(vcb->catalogRefNum);
	mdb->drCTExtRec[0].startBlock = SWAP_BE16 (fp->ff_extents[0].startBlock);
	mdb->drCTExtRec[0].blockCount = SWAP_BE16 (fp->ff_extents[0].blockCount);
	mdb->drCTExtRec[1].startBlock = SWAP_BE16 (fp->ff_extents[1].startBlock);
	mdb->drCTExtRec[1].blockCount = SWAP_BE16 (fp->ff_extents[1].blockCount);
	mdb->drCTExtRec[2].startBlock = SWAP_BE16 (fp->ff_extents[2].startBlock);
	mdb->drCTExtRec[2].blockCount = SWAP_BE16 (fp->ff_extents[2].blockCount);
	mdb->drCTFlSize	= SWAP_BE32 (fp->ff_blocks * vcb->blockSize);
	mdb->drCTClpSiz	= SWAP_BE32 (fp->ff_clumpsize);

	/* If requested, flush out the alternate MDB */
	if (altflush) {
		struct buf *alt_bp = NULL;
		u_long altIDSector;

		altIDSector = HFS_ALT_SECTOR(sectorsize, hfsmp->hfs_phys_block_count);

		if (meta_bread(hfsmp->hfs_devvp, altIDSector, sectorsize, NOCRED, &alt_bp) == 0) {
			bcopy(mdb, alt_bp->b_data + HFS_ALT_OFFSET(sectorsize), kMDBSize);

			(void) VOP_BWRITE(alt_bp);
		} else if (alt_bp)
			brelse(alt_bp);
	}

	if (waitfor != MNT_WAIT)
		bawrite(bp);
	else 
		retval = VOP_BWRITE(bp);
 
	MarkVCBClean( vcb );

	return (retval);
}


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
	int priIDSector;
	int critical = 0;

	if (vcb->vcbSigWord == kHFSSigWord)
		return hfs_flushMDB(hfsmp, waitfor, altflush);

	if (altflush)
		critical = 1;
	sectorsize = hfsmp->hfs_phys_block_size;
	priIDSector = (vcb->hfsPlusIOPosOffset / sectorsize) +
			HFS_PRI_SECTOR(sectorsize);

	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
		if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
		    return EINVAL;
	    }
	}

	retval = meta_bread(hfsmp->hfs_devvp, priIDSector, sectorsize, NOCRED, &bp);
	if (retval) {
		if (bp)
			brelse(bp);

		if (hfsmp->jnl) {
			journal_end_transaction(hfsmp->jnl);
		}
		hfs_global_shared_lock_release(hfsmp);

		return (retval);
	}

	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, bp);
	}

	volumeHeader = (HFSPlusVolumeHeader *)((char *)bp->b_data + HFS_PRI_OFFSET(sectorsize));

	/*
	 * For embedded HFS+ volumes, update create date if it changed
	 * (ie from a setattrlist call)
	 */
	if ((vcb->hfsPlusIOPosOffset != 0) &&
	    (SWAP_BE32 (volumeHeader->createDate) != vcb->localCreateDate)) {
		struct buf *bp2;
		HFSMasterDirectoryBlock	*mdb;

		retval = meta_bread(hfsmp->hfs_devvp, HFS_PRI_SECTOR(sectorsize),
				sectorsize, NOCRED, &bp2);
		if (retval) {
			if (bp2)
				brelse(bp2);
			retval = 0;
		} else {
			mdb = (HFSMasterDirectoryBlock *)(bp2->b_data +
				HFS_PRI_OFFSET(sectorsize));

			if ( SWAP_BE32 (mdb->drCrDate) != vcb->localCreateDate )
			  {
				// XXXdbg
				if (hfsmp->jnl) {
				    journal_modify_block_start(hfsmp->jnl, bp2);
				}

				mdb->drCrDate = SWAP_BE32 (vcb->localCreateDate);	/* pick up the new create date */

				// XXXdbg
				if (hfsmp->jnl) {
					journal_modify_block_end(hfsmp->jnl, bp2);
				} else {
					(void) VOP_BWRITE(bp2);		/* write out the changes */
				}
			  }
			else
			  {
				brelse(bp2);						/* just release it */
			  }
		  }	
	}

// XXXdbg - only monkey around with the volume signature on non-root volumes
//
#if 0
	if (hfsmp->jnl &&
		hfsmp->hfs_fs_ronly == 0 &&
		(HFSTOVFS(hfsmp)->mnt_flag & MNT_ROOTFS) == 0) {
		
		int old_sig = volumeHeader->signature;

		if (vcb->vcbAtrb & kHFSVolumeUnmountedMask) {
			volumeHeader->signature = kHFSPlusSigWord;
		} else {
			volumeHeader->signature = kHFSJSigWord;
		}

		if (old_sig != volumeHeader->signature) {
			altflush = 1;
		}
	}
#endif
// XXXdbg

	/* Note: only update the lower 16 bits worth of attributes */
	volumeHeader->attributes	= SWAP_BE32 ((SWAP_BE32 (volumeHeader->attributes) & 0xFFFF0000) + (UInt16) vcb->vcbAtrb);
	volumeHeader->journalInfoBlock = SWAP_BE32(vcb->vcbJinfoBlock);
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
	volumeHeader->freeBlocks	= SWAP_BE32 (vcb->freeBlocks);
	volumeHeader->nextAllocation	= SWAP_BE32 (vcb->nextAllocation);
	volumeHeader->rsrcClumpSize	= SWAP_BE32 (vcb->vcbClpSiz);
	volumeHeader->dataClumpSize	= SWAP_BE32 (vcb->vcbClpSiz);
	volumeHeader->nextCatalogID	= SWAP_BE32 (vcb->vcbNxtCNID);
	volumeHeader->writeCount	= SWAP_BE32 (vcb->vcbWrCnt);
	volumeHeader->encodingsBitmap	= SWAP_BE64 (vcb->encodingsBitmap);

	if (bcmp(vcb->vcbFndrInfo, volumeHeader->finderInfo, sizeof(volumeHeader->finderInfo)) != 0)
		critical = 1;
	bcopy(vcb->vcbFndrInfo, volumeHeader->finderInfo, sizeof(volumeHeader->finderInfo));

	/* Sync Extents over-flow file meta data */
	fp = VTOF(vcb->extentsRefNum);
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		volumeHeader->extentsFile.extents[i].startBlock	=
			SWAP_BE32 (fp->ff_extents[i].startBlock);
		volumeHeader->extentsFile.extents[i].blockCount	=
			SWAP_BE32 (fp->ff_extents[i].blockCount);
	}
	FTOC(fp)->c_flag &= ~C_MODIFIED;
	volumeHeader->extentsFile.logicalSize = SWAP_BE64 (fp->ff_size);
	volumeHeader->extentsFile.totalBlocks = SWAP_BE32 (fp->ff_blocks);
	volumeHeader->extentsFile.clumpSize   = SWAP_BE32 (fp->ff_clumpsize);

	/* Sync Catalog file meta data */
	fp = VTOF(vcb->catalogRefNum);
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		volumeHeader->catalogFile.extents[i].startBlock	=
			SWAP_BE32 (fp->ff_extents[i].startBlock);
		volumeHeader->catalogFile.extents[i].blockCount	=
			SWAP_BE32 (fp->ff_extents[i].blockCount);
	}
	FTOC(fp)->c_flag &= ~C_MODIFIED;
	volumeHeader->catalogFile.logicalSize = SWAP_BE64 (fp->ff_size);
	volumeHeader->catalogFile.totalBlocks = SWAP_BE32 (fp->ff_blocks);
	volumeHeader->catalogFile.clumpSize   = SWAP_BE32 (fp->ff_clumpsize);

	/* Sync Allocation file meta data */
	fp = VTOF(vcb->allocationsRefNum);
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		volumeHeader->allocationFile.extents[i].startBlock =
			SWAP_BE32 (fp->ff_extents[i].startBlock);
		volumeHeader->allocationFile.extents[i].blockCount =
			SWAP_BE32 (fp->ff_extents[i].blockCount);
	}
	FTOC(fp)->c_flag &= ~C_MODIFIED;
	volumeHeader->allocationFile.logicalSize = SWAP_BE64 (fp->ff_size);
	volumeHeader->allocationFile.totalBlocks = SWAP_BE32 (fp->ff_blocks);
	volumeHeader->allocationFile.clumpSize   = SWAP_BE32 (fp->ff_clumpsize);

	/* If requested, flush out the alternate volume header */
	if (altflush) {
		struct buf *alt_bp = NULL;
		u_long altIDSector;

		altIDSector = (vcb->hfsPlusIOPosOffset / sectorsize) +
			HFS_ALT_SECTOR(sectorsize, hfsmp->hfs_phys_block_count);

		if (meta_bread(hfsmp->hfs_devvp, altIDSector, sectorsize, NOCRED, &alt_bp) == 0) {
			if (hfsmp->jnl) {
				journal_modify_block_start(hfsmp->jnl, alt_bp);
			}

			bcopy(volumeHeader, alt_bp->b_data + HFS_ALT_OFFSET(sectorsize), kMDBSize);

			if (hfsmp->jnl) {
				journal_modify_block_end(hfsmp->jnl, alt_bp);
			} else {
				(void) VOP_BWRITE(alt_bp);
			}
		} else if (alt_bp)
			brelse(alt_bp);
	}

	// XXXdbg
	if (hfsmp->jnl) {
		journal_modify_block_end(hfsmp->jnl, bp);
		journal_end_transaction(hfsmp->jnl);
	} else {
		if (waitfor != MNT_WAIT)
			bawrite(bp);
		else {
		    retval = VOP_BWRITE(bp);
		    /* When critical data changes, flush the device cache */
		    if (critical && (retval == 0)) {
			(void) VOP_IOCTL(hfsmp->hfs_devvp, DKIOCSYNCHRONIZECACHE,
					 NULL, FWRITE, NOCRED, current_proc());
		    }
		}
	}
	hfs_global_shared_lock_release(hfsmp);
 
	vcb->vcbFlags &= 0x00FF;
	return (retval);
}


/*
 * hfs vfs operations.
 */
struct vfsops hfs_vfsops = {
	hfs_mount,
	hfs_start,
	hfs_unmount,
	hfs_root,
	hfs_quotactl,
	hfs_statfs,
	hfs_sync,
	hfs_vget,
	hfs_fhtovp,
	hfs_vptofh,
	hfs_init,
	hfs_sysctl
};
