/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
OSStatus ReleaseBTreeBlock(FileReference vp, BlockDescPtr blockPtr, ReleaseBlockOptions options)
{
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
    	brelse(bp);	/* note: B-tree code will clear blockPtr->blockHeader and blockPtr->buffer */
    } else {
        if (options & kForceWriteBlock) {
            retval = VOP_BWRITE(bp);
        } else if (options & kMarkBlockDirty) {
#if FORCESYNCBTREEWRITES
            VOP_BWRITE(bp);
#else
            if (options & kLockTransaction) {
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
            if (bdwrite_internal(bp, 1) != 0) {
                hfs_btsync(vp, 0);
                /* Rollback sync time to cause a sync on lock release... */
                (void) BTSetLastSync(VTOF(vp), time.tv_sec - (kMaxSecsForFsync + 1));
                bp->b_flags &= ~B_LOCKED;
                bawrite(bp);
            }

#endif
        } else {
    		brelse(bp);	/* note: B-tree code will clear blockPtr->blockHeader and blockPtr->buffer */
        };
    };

exit:
    return (retval);
}


__private_extern__
OSStatus ExtendBTreeFile(FileReference vp, FSSize minEOF, FSSize maxEOF)
{
#pragma unused (maxEOF)

	OSStatus	retval;
	UInt64		actualBytesAdded;
	UInt64		bytesToAdd;
    UInt32		extendFlags;
	u_int32_t	startAllocation;
	u_int32_t	fileblocks;
	BTreeInfoRec btInfo;
	ExtendedVCB	*vcb;
	FCB			*filePtr;
    struct proc *p = NULL;


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

	/*
	 * The b-tree code expects nodes to be contiguous. So when
	 * the allocation block size is less than the b-tree node
	 * size, we need to force disk allocations to be contiguous.
	 */
	if (vcb->blockSize >= btInfo.nodeSize) {
		extendFlags = 0;
	} else {
		/* Ensure that all b-tree nodes are contiguous on disk */
		extendFlags = kEFAllMask | kEFContigMask;
	}

	fileblocks = filePtr->ff_blocks;
	startAllocation = vcb->nextAllocation;

	retval = ExtendFileC(vcb, filePtr, bytesToAdd, 0, extendFlags, &actualBytesAdded);

	/*
	 * If a new extent was added then move the roving allocator
	 * reference forward by the current b-tree file size so 
	 * there's plenty of room to grow.
	 */
	if ((retval == 0) &&
	    (vcb->nextAllocation > startAllocation) &&
	    ((vcb->nextAllocation + fileblocks) < vcb->totalBlocks)) {
		vcb->nextAllocation += fileblocks;
	}
		
	if(VTOC(vp)->c_fileid != kHFSExtentsFileID) {
		/*
		 * Get any extents overflow b-tree changes to disk ASAP!
		 */
		if (retval == 0) {
			(void) BTFlushPath(VTOF(vcb->extentsRefNum));
			(void) VOP_FSYNC(vcb->extentsRefNum, NOCRED, MNT_WAIT, p);
		}
		(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, p);
	}
	if (retval)
		return (retval);
	
	filePtr->fcbEOF = (u_int64_t)filePtr->ff_blocks * (u_int64_t)vcb->blockSize;

	retval = ClearBTNodes(vp, btInfo.nodeSize, filePtr->fcbEOF - actualBytesAdded, actualBytesAdded);	
	if (retval)
		return (retval);
	
	/*
	 * Update the Alternate MDB or Alternate VolumeHeader
	 */
	if ((VTOC(vp)->c_fileid == kHFSExtentsFileID)	||
	    (VTOC(vp)->c_fileid == kHFSCatalogFileID)	||
	    (VTOC(vp)->c_fileid == kHFSAttributesFileID)
	   ) {
		MarkVCBDirty( vcb );
		retval = hfs_flushvolumeheader(VCBTOHFS(vcb), MNT_WAIT, HFS_ALTFLUSH);
	}
	
	return retval;
}


/*
 * Clear out (zero) new b-tree nodes on disk.
 */
static int
ClearBTNodes(struct vnode *vp, long blksize, off_t offset, off_t amount)
{
	struct buf *bp = NULL;
	daddr_t blk;
	daddr_t blkcnt;
    
	blk = offset / blksize;
	blkcnt = amount / blksize;
	
	while (blkcnt > 0) {
		bp = getblk(vp, blk, blksize, 0, 0, BLK_META);
		if (bp == NULL)
			continue;
		bzero((char *)bp->b_data, blksize);
		bp->b_flags |= B_AGE;

		 /* wait/yield every 32 blocks so we don't hog all the buffers */
		if ((blk % 32) == 0)
			VOP_BWRITE(bp);
		else
			bawrite(bp);
		--blkcnt;
		++blk;
	}

	return (0);
}
