/*
 * Copyright (c) 2013-2014 Apple Inc. All rights reserved.
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
#include <sys/systm.h>
#include <sys/kauth.h>
#include <sys/ubc.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/buf_internal.h>
#include <vfs/vfs_journal.h>
#include <miscfs/specfs/specdev.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_cnode.h"
#include "hfs_endian.h"
#include "hfs_btreeio.h"

#if CONFIG_PROTECT
#include <sys/cprotect.h>
#endif

/* Enable/disable debugging code for live volume resizing */
int hfs_resize_debug = 0;

static int hfs_file_extent_overlaps(struct hfsmount *hfsmp, u_int32_t allocLimit, struct HFSPlusCatalogFile *filerec);
static int hfs_reclaimspace(struct hfsmount *hfsmp, u_int32_t allocLimit, u_int32_t reclaimblks, vfs_context_t context);
static int hfs_extend_journal(struct hfsmount *hfsmp, u_int32_t sector_size, u_int64_t sector_count, vfs_context_t context);

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
	daddr64_t  prev_fs_alt_sector;
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
	/* Check if partition size is correct for new file system size */
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
	prev_fs_alt_sector = hfsmp->hfs_fs_avh_sector;
    
	hfsmp->hfs_logical_block_count = sector_count;
	hfsmp->hfs_logical_bytes = (uint64_t) sector_count * (uint64_t) sector_size;
	
	/*
	 * It is possible that the new file system is smaller than the partition size.
	 * Therefore, update offsets for AVH accordingly.
	 */
	if (hfs_resize_debug) {
		printf ("hfs_extendfs: old: partition_avh_sector=%qu, fs_avh_sector=%qu\n", 
				hfsmp->hfs_partition_avh_sector, hfsmp->hfs_fs_avh_sector);
	}
	hfsmp->hfs_partition_avh_sector = (hfsmp->hfsPlusIOPosOffset / sector_size) +
		HFS_ALT_SECTOR(sector_size, hfsmp->hfs_logical_block_count);
	
	hfsmp->hfs_fs_avh_sector = (hfsmp->hfsPlusIOPosOffset / sector_size) + 
		HFS_ALT_SECTOR(sector_size, (newsize/hfsmp->hfs_logical_block_size));
	if (hfs_resize_debug) {
		printf ("hfs_extendfs: new: partition_avh_sector=%qu, fs_avh_sector=%qu\n", 
				hfsmp->hfs_partition_avh_sector, hfsmp->hfs_fs_avh_sector);
	}

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
		hfsmp->hfs_fs_avh_sector = prev_fs_alt_sector;
		/* Do not revert hfs_partition_avh_sector because the 
		 * partition size is larger than file system size
		 */
		MarkVCBDirty(vcb);
		if (vcb->blockSize == 512) {
			if (BlockMarkAllocated(vcb, vcb->totalBlocks - 2, 2)) {
				hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
			}
		} else {
			if (BlockMarkAllocated(vcb, vcb->totalBlocks - 1, 1)) {
				hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
			}
		}
		goto out;
	}
	/*
	 * Invalidate the old alternate volume header.  We are growing the filesystem so
	 * this sector must be returned to the FS as free space.
	 */
	bp = NULL;
	if (prev_fs_alt_sector) {
		if (buf_meta_bread(hfsmp->hfs_devvp,
                           HFS_PHYSBLK_ROUNDDOWN(prev_fs_alt_sector, hfsmp->hfs_log_per_phys),
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
	
	/* Don't invalidate the old AltVH yet.  It is still valid until the partition size is updated ! */
    
	/* Log successful shrinking. */
	printf("hfs_truncatefs: shrank \"%s\" to %d blocks (was %d blocks)\n",
	       hfsmp->vcbVN, newblkcnt, hfsmp->totalBlocks);
    
	/*
	 * Adjust file system variables and flush them to disk.
	 *
	 * Note that although the logical block size is updated here, it is only
	 * done for the benefit/convenience of the partition management software.  The
	 * logical block count change has not yet actually been propagated to
	 * the disk device yet (and we won't get any notification when it does).
	 */
	hfsmp->totalBlocks = newblkcnt;
	hfsmp->hfs_logical_block_count = newsize / hfsmp->hfs_logical_block_size;
	hfsmp->hfs_logical_bytes = (uint64_t) hfsmp->hfs_logical_block_count * (uint64_t) hfsmp->hfs_logical_block_size;
    
	/*
	 * At this point, a smaller HFS file system exists in a larger volume.
	 * As per volume format, the alternate volume header is located 1024 bytes
	 * before end of the partition.  So, until the partition is also resized,
	 * a valid alternate volume header will need to be updated at 1024 bytes
	 * before end of the volume.  Under normal circumstances, a file system
	 * resize is always followed by a volume resize, so we also need to
	 * write a copy of the new alternate volume header at 1024 bytes before
	 * end of the new file system.
	 */
	if (hfs_resize_debug) {
		printf ("hfs_truncatefs: old: partition_avh_sector=%qu, fs_avh_sector=%qu\n", 
				hfsmp->hfs_partition_avh_sector, hfsmp->hfs_fs_avh_sector);
	}
	hfsmp->hfs_fs_avh_sector = HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size, hfsmp->hfs_logical_block_count);
	/* Note hfs_partition_avh_sector stays unchanged! partition size has not yet been modified */
	if (hfs_resize_debug) {
		printf ("hfs_truncatefs: new: partition_avh_sector=%qu, fs_avh_sector=%qu\n", 
				hfsmp->hfs_partition_avh_sector, hfsmp->hfs_fs_avh_sector);
	}
	
	MarkVCBDirty(hfsmp);
	error = hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);
	if (error) {
		panic("hfs_truncatefs: unexpected error flushing volume header (%d)\n", error);
	}
    
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
		/*
		 * We did not find desired contiguous space for this
		 * extent, when we asked for it, including the metazone allocations.
		 * At this point we are not worrying about getting contiguity anymore.
		 *
		 * HOWEVER, if we now allow blocks to be used which were recently
		 * de-allocated, we may find a contiguous range (though this seems
		 * unlikely). As a result, assume that we will have to split the
		 * current extent into two pieces, but if we are able to satisfy
		 * the request with a single extent, detect that as well.
		 */
		alloc_flags &= ~HFS_ALLOC_FORCECONTIG;
		alloc_flags |= HFS_ALLOC_FLUSHTXN;
        
		error = BlockAllocate(hfsmp, 1, oldBlockCount, oldBlockCount,
                              alloc_flags, &newStartBlock, &newBlockCount);
		if (error) {
			printf ("hfs_reclaim_extent: fileID=%u start=%u, %u:(%u,%u) BlockAllocate error=%d\n", extent_info->fileID, extent_info->recStartBlock, index, oldStartBlock, oldBlockCount, error);
			goto out;
		}
        
		/*
		 * Allowing recently deleted extents may now allow us to find
		 * a single contiguous extent in the amount & size desired.  If so,
		 * do NOT split this extent into two pieces.  This is technically a
		 * check for "< oldBlockCount", but we use != to highlight the point
		 * that the special case is when they're equal. The allocator should
		 * never vend back more blocks than were requested.
		 */
		if (newBlockCount != oldBlockCount) {
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
		} /* end oldBlockCount != newBlockCount */
	} /* end allocation request for any available free space */
    
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
		hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
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
		hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
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
				error = hfs_vgetrsrc(hfsmp, vp, &rvp);
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
