/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*	@(#)hfs_btreeio.c
*
*	(c) 1998, 2000 Apple Computer, Inc.  All Rights Reserved
*
*	hfs_btreeio.c -- I/O Routines for the HFS B-tree files.
*
*	HISTORY
*	15-Feb-2000	Don Brady	Added ClearBTNodes.
*	16-Jul-1998	Don Brady		In ExtendBtreeFile force all b-tree nodes to be contiguous on disk.
*	 4-Jun-1998	Pat Dirks		Changed to do all B*-Tree writes synchronously (FORCESYNCBTREEWRITES = 1)
*	18-apr-1998	Don Brady		Call brelse on bread failure.
*	17-Apr-1998	Pat Dirks		Fixed ReleaseBTreeBlock to not call brelse when bwrite or bdwrite is called.
*	13-apr-1998	Don Brady		Add ExtendBTreeFile routine (from BTreeWrapper.c).
*	26-mar-1998	Don Brady		SetBTreeBlockSize was incorrectly excluding 512 byte blockSize.
*	18-feb-1998	Don Brady		Initially created file.
*
*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/mount.h>
#include <sys/vnode.h>


#include "hfs.h"
#include "hfs_dbg.h"
#include "hfs_endian.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/BTreesPrivate.h"

#define FORCESYNCBTREEWRITES 0

static OSStatus FlushAlternate( ExtendedVCB *vcb );

static int ClearBTNodes(struct vnode *vp, long blksize, off_t offset, off_t amount);


OSStatus SetBTreeBlockSize(FileReference vp, ByteCount blockSize, ItemCount minBlockCount)
{
	BTreeControlBlockPtr	bTreePtr;
	
	DBG_ASSERT(vp != NULL);
	DBG_ASSERT(VTOFCB(vp) != NULL);
	DBG_ASSERT(VTOFCB(vp)->fcbBTCBPtr != NULL);
	DBG_ASSERT(blockSize >= kMinNodeSize);
    if (blockSize > MAXBSIZE )
        return (fsBTBadNodeSize);

    DBG_TREE(("SetBlockSizeProc: blockSize=%ld for file %ld\n", blockSize, H_FILEID(VTOH(vp))));

	bTreePtr = (BTreeControlBlockPtr)(VTOH(vp)->fcbBTCBPtr);
	bTreePtr->nodeSize = blockSize;
	
    return (E_NONE);
}


OSStatus GetBTreeBlock(FileReference vp, UInt32 blockNum, GetBlockOptions options, BlockDescriptor *block)
{
    OSStatus	 retval = E_NONE;
    struct buf   *bp = NULL;

    if (options & kGetEmptyBlock)
        bp = getblk (vp,
                    IOBLKNOFORBLK(blockNum, VTOHFS(vp)->hfs_phys_block_size),
                    IOBYTECCNTFORBLK(blockNum, block->blockSize, VTOHFS(vp)->hfs_phys_block_size),
                    0,
                    0,
                    BLK_META);
    else
        retval = meta_bread(vp,
                        IOBLKNOFORBLK(blockNum, VTOHFS(vp)->hfs_phys_block_size),
                        IOBYTECCNTFORBLK(blockNum, block->blockSize, VTOHFS(vp)->hfs_phys_block_size),
                        NOCRED,
                        &bp);

    DBG_ASSERT(bp != NULL);
    DBG_ASSERT(bp->b_data != NULL);
    DBG_ASSERT(bp->b_bcount == block->blockSize);
    DBG_ASSERT(bp->b_lblkno == blockNum);

    if (bp == NULL)
        retval = -1;	//XXX need better error

    if (retval == E_NONE) {
        block->blockHeader = bp;
        block->buffer = bp->b_data + IOBYTEOFFSETFORBLK(bp->b_blkno, VTOHFS(vp)->hfs_phys_block_size);
        block->blockReadFromDisk = (bp->b_flags & B_CACHE) == 0;	/* not found in cache ==> came from disk */

#if BYTE_ORDER == LITTLE_ENDIAN
        /* Endian swap B-Tree node (only if it's a valid block) */
        if (!(options & kGetEmptyBlock)) {
            /* This happens when we first open the b-tree, we might not have all the node data on hand */
            if ((((BTNodeDescriptor *)block->buffer)->kind == kBTHeaderNode) &&
                (((BTHeaderRec *)((char *)block->buffer + 14))->nodeSize != bp->b_bcount) &&
                (SWAP_BE16 (((BTHeaderRec *)((char *)block->buffer + 14))->nodeSize) != bp->b_bcount)) {

                /* Don't swap the descriptors at all, we don't care (this block will be invalidated) */
                SWAP_BT_NODE (block, ISHFSPLUS(VTOVCB(vp)), H_FILEID(VTOH(vp)), 3);

            /* The node needs swapping */
            } else if (*((UInt16 *)((char *)block->buffer + (block->blockSize - sizeof (UInt16)))) == 0x0e00) {
                SWAP_BT_NODE (block, ISHFSPLUS(VTOVCB(vp)), H_FILEID(VTOH(vp)), 0);
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


OSStatus ReleaseBTreeBlock(FileReference vp, BlockDescPtr blockPtr, ReleaseBlockOptions options)
{
    OSStatus	retval = E_NONE;
    struct buf *bp = NULL;

    bp = (struct buf *) blockPtr->blockHeader;

    if (bp == NULL) {
        DBG_TREE(("ReleaseBlockProc: blockHeader is zero!\n"));
        retval = -1;
        goto exit;
    }

    if (options & kTrashBlock) {
        bp->b_flags |= B_INVAL;
    	brelse(bp);	/* note: B-tree code will clear blockPtr->blockHeader and blockPtr->buffer */
    } else {
        if (options & kForceWriteBlock) {
            bp->b_flags |= B_DIRTY;
            retval = VOP_BWRITE(bp);
        } else if (options & kMarkBlockDirty) {
            bp->b_flags |= B_DIRTY;
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
				if (count_lock_queue() > kMaxLockedMetaBuffers)
					hfs_fsync_transaction(vp);
	            bp->b_flags |= B_LOCKED;
	        };
            bdwrite(bp);

#endif
        } else {
    		brelse(bp);	/* note: B-tree code will clear blockPtr->blockHeader and blockPtr->buffer */
        };
    };

exit:
    return (retval);
}


OSStatus ExtendBTreeFile(FileReference vp, FSSize minEOF, FSSize maxEOF)
{
#pragma unused (maxEOF)

	OSStatus	retval;
	UInt64		actualBytesAdded;
	UInt64		bytesToAdd;
    UInt32		extendFlags;
	BTreeInfoRec btInfo;
	ExtendedVCB	*vcb;
	FCB			*filePtr;
    struct proc *p = NULL;


	filePtr = GetFileControlBlock(vp);

	if ( minEOF > filePtr->fcbEOF )
	{
		bytesToAdd = minEOF - filePtr->fcbEOF;

		if (bytesToAdd < filePtr->fcbClmpSize)
			bytesToAdd = filePtr->fcbClmpSize;		//XXX why not always be a mutiple of clump size?
	}
	else
	{
		DBG_TREE((" ExtendBTreeFile: minEOF is smaller than current size!"));
		return -1;
	}

	vcb = FCBTOVCB(filePtr);
	
	/*
	 * The Extents B-tree can't have overflow extents. ExtendFileC will
	 * return an error if an attempt is made to extend the Extents B-tree
	 * when the resident extents are exhausted.
	 */
    /* XXX warning - this can leave the volume bitmap unprotected during ExtendFileC call */
	if(H_FILEID(filePtr) != kHFSExtentsFileID)
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

    retval = ExtendFileC(vcb, filePtr, bytesToAdd, 0, extendFlags, &actualBytesAdded);

	if(H_FILEID(filePtr) != kHFSExtentsFileID)
		(void) hfs_metafilelocking(VTOHFS(vp), kHFSExtentsFileID, LK_RELEASE, p);

	if (retval)
		return (retval);

	if (actualBytesAdded < bytesToAdd)
		DBG_TREE((" ExtendBTreeFile: actualBytesAdded < bytesToAdd!"));
	
	filePtr->fcbEOF = filePtr->fcbPLen;

	retval = ClearBTNodes(vp, btInfo.nodeSize, filePtr->fcbEOF - actualBytesAdded, actualBytesAdded);	
	if (retval)
		return (retval);
	
	/*
	 * Update the Alternate MDB or Alternate VolumeHeader
	 */
	if ((H_FILEID(filePtr) == kHFSExtentsFileID)	||
	    (H_FILEID(filePtr) == kHFSCatalogFileID)	||
	    (H_FILEID(filePtr) == kHFSAttributesFileID)
	   ) {
		MarkVCBDirty( vcb );
		if (vcb->vcbSigWord == kHFSPlusSigWord) {
			retval = hfs_flushvolumeheader(VCBTOHFS(vcb), 0);
		} else {
			retval = hfs_flushMDB(VCBTOHFS(vcb), 0);
		}
		if (retval == 0) {
			retval = FlushAlternate(vcb);
		}
	}
	
	return retval;
}


static OSStatus
FlushAlternate( ExtendedVCB *vcb )
{
	void *maindata;
	void *altdata;
	int result;

	/* Get the main MDB/VolumeHeader block */
	result = GetBlock_glue(gbDefault,
                	(vcb->hfsPlusIOPosOffset / kHFSBlockSize) + kMasterDirectoryBlock,
                	(Ptr *)&maindata, kNoFileReference, vcb);
	if (result) return (result);
	
	/* Get the alternate MDB/VolumeHeader block */
	result = GetBlock_glue( gbDefault, vcb->altIDSector,
                	(Ptr *)&altdata, kNoFileReference, vcb );

	if (result == 0) {
		bcopy(maindata, altdata, kMDBSize);

		result = RelBlock_glue( (Ptr)altdata, rbWriteMask );
	}

	(void) RelBlock_glue( (Ptr)maindata, rbFreeMask );
	
	return (result);
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
		bp->b_flags |= (B_DIRTY | B_AGE);

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
