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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/vnode.h>


#include "hfs.h"
#include "hfs_cnode.h"
#include "hfs_dbg.h"
#include "hfs_endian.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/BTreesPrivate.h"

#define FORCESYNCBTREEWRITES 0


static int ClearBTNodes(struct vnode *vp, long blksize, off_t offset, off_t amount);


__private_extern__
OSStatus SetBTreeBlockSize(FileReference vp, ByteCount blockSize, ItemCount minBlockCount)
{
	BTreeControlBlockPtr	bTreePtr;
	
	DBG_ASSERT(vp != NULL);
	DBG_ASSERT(blockSize >= kMinNodeSize);
    if (blockSize > MAXBSIZE )
        return (fsBTBadNodeSize);

	bTreePtr = (BTreeControlBlockPtr)VTOF(vp)->fcbBTCBPtr;
	bTreePtr->nodeSize = blockSize;
	
    return (E_NONE);
}


__private_extern__
OSStatus GetBTreeBlock(FileReference vp, UInt32 blockNum, GetBlockOptions options, BlockDescriptor *block)
{
    OSStatus	 retval = E_NONE;
    struct buf   *bp = NULL;

	if (options & kGetEmptyBlock)
		bp = getblk(vp, blockNum, block->blockSize, 0, 0, BLK_META);
	else
		retval = meta_bread(vp, blockNum, block->blockSize, NOCRED, &bp);

    DBG_ASSERT(bp != NULL);
    DBG_ASSERT(bp->b_data != NULL);
    DBG_ASSERT(bp->b_bcount == block->blockSize);
    DBG_ASSERT(bp->b_lblkno == blockNum);

    if (bp == NULL)
        retval = -1;	//XXX need better error

    if (retval == E_NONE) {
        block->blockHeader = bp;
        block->buffer = bp->b_data;
        block->blockReadFromDisk = (bp->b_flags & B_CACHE) == 0;	/* not found in cache ==> came from disk */

		// XXXdbg 
		block->isModified = 0;

#if BYTE_ORDER == LITTLE_ENDIAN
        /* Endian swap B-Tree node (only if it's a valid block) */
        if (!(options & kGetEmptyBlock)) {
            /* This happens when we first open the b-tree, we might not have all the node data on hand */
            if ((((BTNodeDescriptor *)block->buffer)->kind == kBTHeaderNode) &&
                (((BTHeaderRec *)((char *)block->buffer + 14))->nodeSize != bp->b_bcount) &&
                (SWAP_BE16 (((BTHeaderRec *)((char *)block->buffer + 14))->nodeSize) != bp->b_bcount)) {

                /* Don't swap the descriptors at all, we don't care (this block will be invalidated) */
                SWAP_BT_NODE (block, ISHFSPLUS(VTOVCB(vp)), VTOC(vp)->c_fileid, 3);

            /* The node needs swapping */
            } else if (*((UInt16 *)((char *)block->buffer + (block->blockSize - sizeof (UInt16)))) == 0x0e00) {
                SWAP_BT_NODE (block, ISHFSPLUS(VTOVCB(vp)), VTOC(vp)->c_fileid, 0);
#if 0
            /* The node is not already in native byte order, hence corrupt */
            } else if (*((UInt16 *)((char *)block->buffer + (block->blockSize - sizeof (UInt16)))) != 0x000e) {
                panic ("%s Corrupt B-Tree node detected!\n", "GetBTreeBlock:");
#endif
            }
        }
#endif
    } else {
    	if (bp)
   			brelse(bp);
        block->blockHeader = NULL;
        block->buffer = NULL;
    }

    return (retval);
}


__private_extern__
void ModifyBlockStart(FileReference vp, BlockDescPtr blockPtr)
{
	struct hfsmount	*hfsmp = VTOHFS(vp);
    struct buf *bp = NULL;

	if (hfsmp->jnl == NULL) {
		return;
	}
	
    bp = (struct buf *) blockPtr->blockHeader;
    if (bp == NULL) {
		panic("ModifyBlockStart: null bp  for blockdescptr 0x%x?!?\n", blockPtr);
		return;
    }

	journal_modify_block_start(hfsmp->jnl, bp);
	blockPtr->isModified = 1;
}

static int
btree_journal_modify_block_end(struct hfsmount *hfsmp, struct buf *bp)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    struct vnode *vp = bp->b_vp;
    BlockDescriptor block;
				    
    /* Prepare the block pointer */
    block.blockHeader = bp;
    block.buffer = bp->b_data;
    /* not found in cache ==> came from disk */
    block.blockReadFromDisk = (bp->b_flags & B_CACHE) == 0;
    block.blockSize = bp->b_bcount;

    // XXXdbg have to swap the data before it goes in the journal
    SWAP_BT_NODE (&block, ISHFSPLUS (VTOVCB(vp)), VTOC(vp)->c_fileid, 1);
#endif

    return journal_modify_block_end(hfsmp->jnl, bp);
}


__private_extern__
OSStatus ReleaseBTreeBlock(FileReference vp, BlockDescPtr blockPtr, ReleaseBlockOptions options)
{
    struct hfsmount	*hfsmp = VTOHFS(vp);
    extern int bdwrite_internal(struct buf *, int);
    OSStatus	retval = E_NONE;
    struct buf *bp = NULL;

    bp = (struct buf *) blockPtr->blockHeader;

    if (bp == NULL) {
        retval = -1;
        goto exit;
    }

    if (options & kTrashBlock) {
		bp->b_flags |= B_INVAL;
		if (hfsmp->jnl && (bp->b_flags & B_LOCKED)) {
			journal_kill_block(hfsmp->jnl, bp);
		} else {
			brelse(bp);	/* note: B-tree code will clear blockPtr->blockHeader and blockPtr->buffer */
		}
    } else {
        if (options & kForceWriteBlock) {
			if (hfsmp->jnl) {
				if (blockPtr->isModified == 0) {
					panic("hfs: releaseblock: modified is 0 but forcewrite set! bp 0x%x\n", bp);
				}

				retval = btree_journal_modify_block_end(hfsmp, bp);
				blockPtr->isModified = 0;
			} else {
				retval = VOP_BWRITE(bp);
			}
        } else if (options & kMarkBlockDirty) {
            if ((options & kLockTransaction) && hfsmp->jnl == NULL) {
                /*
                 *
                 * Set the B_LOCKED flag and unlock the buffer, causing brelse to move
                 * the buffer onto the LOCKED free list.  This is necessary, otherwise
                 * getnewbuf() would try to reclaim the buffers using bawrite, which
                 * isn't going to work.
                 *
                 */
                extern int count_lock_queue __P((void));
                /* Don't hog all the buffers... */
                if (count_lock_queue() > kMaxLockedMetaBuffers) {
                     hfs_btsync(vp, HFS_SYNCTRANS);
                     /* Rollback sync time to cause a sync on lock release... */
                     (void) BTSetLastSync(VTOF(vp), time.tv_sec - (kMaxSecsForFsync + 1));
                }

				bp->b_flags |= B_LOCKED;
            }

            /* 
             * Delay-write this block.
             * If the maximum delayed buffers has been exceeded then
             * free up some buffers and fall back to an asynchronous write.
             */
			if (hfsmp->jnl) {
				if (blockPtr->isModified == 0) {
					panic("hfs: releaseblock: modified is 0 but markdirty set! bp 0x%x\n", bp);
				}
				retval = btree_journal_modify_block_end(hfsmp, bp);
				blockPtr->isModified = 0;
			} else if (bdwrite_internal(bp, 1) != 0) {
                hfs_btsync(vp, 0);
                /* Rollback sync time to cause a sync on lock release... */
                (void) BTSetLastSync(VTOF(vp), time.tv_sec - (kMaxSecsForFsync + 1));
                bp->b_flags &= ~B_LOCKED;
                bawrite(bp);
            }
        } else {
			// check if we had previously called journal_modify_block_start() 
			// on this block and if so, abort it (which will call brelse()).
			if (hfsmp->jnl && blockPtr->isModified) {
				// XXXdbg - I don't want to call modify_block_abort()
				//          because I think it may be screwing up the
				//          journal and blowing away a block that has
				//          valid data in it.
				//   
				//    journal_modify_block_abort(hfsmp->jnl, bp);
				//panic("hfs: releaseblock called for 0x%x but mod_block_start previously called.\n", bp);
				btree_journal_modify_block_end(hfsmp, bp);
				blockPtr->isModified = 0;
			} else {
				brelse(bp);	/* note: B-tree code will clear blockPtr->blockHeader and blockPtr->buffer */
			}
        };
    };

exit:
    return (retval);
}


__private_extern__
OSStatus ExtendBTreeFile(FileReference vp, FSSize minEOF, FSSize maxEOF)
{
#pragma unused (maxEOF)

	OSStatus	retval, ret;
	UInt64		actualBytesAdded, origSize;
	UInt64		bytesToAdd;
	u_int32_t	startAllocation;
	u_int32_t	fileblocks;
	BTreeInfoRec btInfo;
	ExtendedVCB	*vcb;
	FCB			*filePtr;
    struct proc *p = NULL;
	UInt64 		trim = 0;	

	filePtr = GetFileControlBlock(vp);

	if ( minEOF > filePtr->fcbEOF )
	{
		bytesToAdd = minEOF - filePtr->fcbEOF;

		if (bytesToAdd < filePtr->ff_clumpsize)
			bytesToAdd = filePtr->ff_clumpsize;		//XXX why not always be a mutiple of clump size?
	}
	else
	{
		return -1;
	}

	vcb = VTOVCB(vp);
	
	/*
	 * The Extents B-tree can't have overflow extents. ExtendFileC will
	 * return an error if an attempt is made to extend the Extents B-tree
	 * when the resident extents are exhausted.
	 */
    /* XXX warning - this can leave the volume bitmap unprotected during ExtendFileC call */
	if(VTOC(vp)->c_fileid != kHFSExtentsFileID)
	{
		p = current_proc();
		/* lock extents b-tree (also protects volume bitmap) */
 		retval = hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_EXCLUSIVE, p);
		if (retval)
			return (retval);
	}

    (void) BTGetInformation(filePtr, 0, &btInfo);

#if 0  // XXXdbg
	/*
	 * The b-tree code expects nodes to be contiguous. So when
	 * the allocation block size is less than the b-tree node
	 * size, we need to force disk allocations to be contiguous.
	 */
	if (vcb->blockSize >= btInfo.nodeSize) {
		extendFlags = 0;
	} else {
		/* Ensure that all b-tree nodes are contiguous on disk */
		extendFlags = kEFContigMask;
	}
#endif

	origSize = filePtr->fcbEOF;
	fileblocks = filePtr->ff_blocks;
	startAllocation = vcb->nextAllocation;

	// loop trying to get a contiguous chunk that's an integer multiple
	// of the btree node size.  if we can't get a contiguous chunk that
	// is at least the node size then we break out of the loop and let
	// the error propagate back up.
	do {
		retval = ExtendFileC(vcb, filePtr, bytesToAdd, 0,
		                     kEFContigMask | kEFMetadataMask,
		                     &actualBytesAdded);
		if (retval == dskFulErr && actualBytesAdded == 0) {

			if (bytesToAdd == btInfo.nodeSize || bytesToAdd < (minEOF - origSize)) {
				// if we're here there's nothing else to try, we're out
				// of space so we break and bail out.
				break;
			} else {
				bytesToAdd >>= 1;
				if (bytesToAdd < btInfo.nodeSize) {
					bytesToAdd = btInfo.nodeSize;
				} else if ((bytesToAdd % btInfo.nodeSize) != 0) {
					// make sure it's an integer multiple of the nodeSize
					bytesToAdd -= (bytesToAdd % btInfo.nodeSize);
				}
			}
		}
	} while (retval == dskFulErr && actualBytesAdded == 0);
	
	/*
	 * If a new extent was added then move the roving allocator
	 * reference forward by the current b-tree file size so 
	 * there's plenty of room to grow.
	 */
	if ((retval == 0) &&
	    ((VCBTOHFS(vcb)->hfs_flags & HFS_METADATA_ZONE) == 0) &&
	    (vcb->nextAllocation > startAllocation) &&
	    ((vcb->nextAllocation + fileblocks) < vcb->totalBlocks)) {
		vcb->nextAllocation += fileblocks;
	}
		
	filePtr->fcbEOF = (u_int64_t)filePtr->ff_blocks * (u_int64_t)vcb->blockSize;

	// XXXdbg ExtendFileC() could have returned an error even though
	// it grew the file to be big enough for our needs.  If this is
	// the case, we don't care about retval so we blow it away.
	//
	if (filePtr->fcbEOF >= minEOF && retval != 0) {
		retval = 0;
	}

	// XXXdbg if the file grew but isn't large enough or isn't an
	// even multiple of the nodeSize then trim things back.  if
	// the file isn't large enough we trim back to the original
	// size.  otherwise we trim back to be an even multiple of the
	// btree node size.
	//
	if ((filePtr->fcbEOF < minEOF) || (actualBytesAdded % btInfo.nodeSize) != 0) {

		if (filePtr->fcbEOF < minEOF) {
			retval = dskFulErr;
			
			if (filePtr->fcbEOF < origSize) {
				panic("hfs: btree file eof %lld less than orig size %lld!\n",
					  filePtr->fcbEOF, origSize);
			}
			
			trim = filePtr->fcbEOF - origSize;
			if (trim != actualBytesAdded) {
				panic("hfs: trim == %lld but actualBytesAdded == %lld\n",
					  trim, actualBytesAdded);
			}
		} else {
			trim = (actualBytesAdded % btInfo.nodeSize);
		}

		ret = TruncateFileC(vcb, filePtr, filePtr->fcbEOF - trim, 0);
		filePtr->fcbEOF = (u_int64_t)filePtr->ff_blocks * (u_int64_t)vcb->blockSize;

		// XXXdbg - panic if the file didn't get trimmed back properly
		if ((filePtr->fcbEOF % btInfo.nodeSize) != 0) {
			panic("hfs: truncate file didn't! fcbEOF %lld nsize %d fcb 0x%x\n",
				  filePtr->fcbEOF, btInfo.nodeSize, filePtr);
		}

		if (ret) {
			// XXXdbg - this probably doesn't need to be a panic()
			panic("hfs: error truncating btree files (sz 0x%llx, trim %lld, ret %d)\n",
				  filePtr->fcbEOF, trim, ret);
			return ret;
		}
		actualBytesAdded -= trim;
	}

	if(VTOC(vp)->c_fileid != kHFSExtentsFileID) {
		/*
		 * Get any extents overflow b-tree changes to disk ASAP!
		 */
		(void) BTFlushPath(VTOF(vcb->extentsRefNum));
		(void) VOP_FSYNC(vcb->extentsRefNum, NOCRED, MNT_WAIT, p);

		(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, p);
	}

	if ((filePtr->fcbEOF % btInfo.nodeSize) != 0) {
		panic("hfs: extendbtree: fcb 0x%x has eof 0x%llx not a multiple of 0x%x (trim %llx)\n",
			  filePtr, filePtr->fcbEOF, btInfo.nodeSize, trim);
	}

	/*
	 * Update the Alternate MDB or Alternate VolumeHeader
	 */
	if ((VTOC(vp)->c_fileid == kHFSExtentsFileID)	||
	    (VTOC(vp)->c_fileid == kHFSCatalogFileID)	||
	    (VTOC(vp)->c_fileid == kHFSAttributesFileID)
	   ) {
		MarkVCBDirty( vcb );
		ret = hfs_flushvolumeheader(VCBTOHFS(vcb), MNT_WAIT, HFS_ALTFLUSH);
	} else {
		struct timeval tv = time;

		VTOC(vp)->c_flag |= C_CHANGE | C_UPDATE;
		(void) VOP_UPDATE(vp, &tv, &tv, MNT_WAIT);
	}

	ret = ClearBTNodes(vp, btInfo.nodeSize, filePtr->fcbEOF - actualBytesAdded, actualBytesAdded);
	if (ret)
		return (ret);
	
	return retval;
}


/*
 * Clear out (zero) new b-tree nodes on disk.
 */
static int
ClearBTNodes(struct vnode *vp, long blksize, off_t offset, off_t amount)
{
	struct hfsmount *hfsmp = VTOHFS(vp);
	struct buf *bp = NULL;
	daddr_t blk;
	daddr_t blkcnt;
    
	blk = offset / blksize;
	blkcnt = amount / blksize;
	
	while (blkcnt > 0) {
		bp = getblk(vp, blk, blksize, 0, 0, BLK_META);
		if (bp == NULL)
			continue;

        // XXXdbg
		if (hfsmp->jnl) {
			// XXXdbg -- skipping this for now since it makes a transaction
			//           become *way* too large
		    //journal_modify_block_start(hfsmp->jnl, bp);
		}

		bzero((char *)bp->b_data, blksize);
		bp->b_flags |= B_AGE;

        // XXXdbg
		if (hfsmp->jnl) {
			// XXXdbg -- skipping this for now since it makes a transaction
			//           become *way* too large
			//journal_modify_block_end(hfsmp->jnl, bp);

			// XXXdbg - remove this once we decide what to do with the
			//          writes to the journal
			if ((blk % 32) == 0)
			    VOP_BWRITE(bp);
			else
			    bawrite(bp);
		} else {
			/* wait/yield every 32 blocks so we don't hog all the buffers */
			if ((blk % 32) == 0)
				VOP_BWRITE(bp);
			else
				bawrite(bp);
		}
		--blkcnt;
		++blk;
	}

	return (0);
}
