/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
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

    if (options & kGetEmptyBlock) {
        daddr64_t blkno;
        off_t offset;

        offset = (daddr64_t)blockNum * (daddr64_t)block->blockSize;
        bp = buf_getblk(vp, (daddr64_t)blockNum, block->blockSize, 0, 0, BLK_META);
        if (bp &&
            VNOP_BLOCKMAP(vp, offset, block->blockSize, &blkno, NULL, NULL, 0, NULL) == 0) {
            buf_setblkno(bp, blkno);
        }
    } else {
        retval = buf_meta_bread(vp, (daddr64_t)blockNum, block->blockSize, NOCRED, &bp);
    }
    if (bp == NULL)
        retval = -1;	//XXX need better error

    if (retval == E_NONE) {
        block->blockHeader = bp;
        block->buffer = (char *)buf_dataptr(bp);
    	block->blockNum = buf_lblkno(bp);
        block->blockReadFromDisk = (buf_fromcache(bp) == 0);	/* not found in cache ==> came from disk */

		// XXXdbg 
		block->isModified = 0;

        /* Check and endian swap B-Tree node (only if it's a valid block) */
        if (!(options & kGetEmptyBlock)) {
            /* This happens when we first open the b-tree, we might not have all the node data on hand */
            if ((((BTNodeDescriptor *)block->buffer)->kind == kBTHeaderNode) &&
                (((BTHeaderRec *)((char *)block->buffer + 14))->nodeSize != buf_count(bp)) &&
                (SWAP_BE16 (((BTHeaderRec *)((char *)block->buffer + 14))->nodeSize) != buf_count(bp))) {

                /*
                 * Don't swap the node descriptor, record offsets, or other records.
                 * This record will be invalidated and re-read with the correct node
                 * size once the B-tree control block is set up with the node size
                 * from the header record.
                 */
                retval = hfs_swap_BTNode (block, vp, kSwapBTNodeHeaderRecordOnly);

			} else if (block->blockReadFromDisk) {
            	/*
            	 * The node was just read from disk, so always swap/check it.
            	 * This is necessary on big endian since the test below won't trigger.
            	 */
                retval = hfs_swap_BTNode (block, vp, kSwapBTNodeBigToHost);
            } else if (*((UInt16 *)((char *)block->buffer + (block->blockSize - sizeof (UInt16)))) == 0x0e00) {
				/*
				 * The node was left in the cache in non-native order, so swap it.
				 * This only happens on little endian, after the node is written
				 * back to disk.
				 */
                retval = hfs_swap_BTNode (block, vp, kSwapBTNodeBigToHost);
            }
            
    		/*
    		 * If we got an error, then the node is only partially swapped.
    		 * We mark the buffer invalid so that the next attempt to get the
    		 * node will read it and attempt to swap again, and will notice
    		 * the error again.  If we didn't do this, the next attempt to get
    		 * the node might use the partially swapped node as-is.
    		 */
            if (retval)
				buf_markinvalid(bp);
        }
    }
    
    if (retval) {
    	if (bp)
			buf_brelse(bp);
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
	int retval;
    struct vnode *vp = buf_vnode(bp);
    BlockDescriptor block;
				    
    /* Prepare the block pointer */
    block.blockHeader = bp;
    block.buffer = (char *)buf_dataptr(bp);
    block.blockNum = buf_lblkno(bp);
    /* not found in cache ==> came from disk */
    block.blockReadFromDisk = (buf_fromcache(bp) == 0);
    block.blockSize = buf_count(bp);

    // XXXdbg have to swap the data before it goes in the journal
    retval = hfs_swap_BTNode (&block, vp, kSwapBTNodeHostToBig);
    if (retval)
    	panic("btree_journal_modify_block_end: about to write corrupt node!\n");

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
                buf_markinvalid(bp);

		if (hfsmp->jnl && (buf_flags(bp) & B_LOCKED)) {
			journal_kill_block(hfsmp->jnl, bp);
		} else {
			buf_brelse(bp);	/* note: B-tree code will clear blockPtr->blockHeader and blockPtr->buffer */
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
				retval = VNOP_BWRITE(bp);
			}
        } else if (options & kMarkBlockDirty) {
			struct timeval tv;
			microuptime(&tv);
            if ((options & kLockTransaction) && hfsmp->jnl == NULL) {
                /*
                 *
                 * Set the B_LOCKED flag and unlock the buffer, causing buf_brelse to move
                 * the buffer onto the LOCKED free list.  This is necessary, otherwise
                 * getnewbuf() would try to reclaim the buffers using buf_bawrite, which
                 * isn't going to work.
                 *
                 */
                extern int count_lock_queue(void);

                /* Don't hog all the buffers... */
                if (count_lock_queue() > kMaxLockedMetaBuffers) {
                     hfs_btsync(vp, HFS_SYNCTRANS);
                     /* Rollback sync time to cause a sync on lock release... */
                     (void) BTSetLastSync(VTOF(vp), tv.tv_sec - (kMaxSecsForFsync + 1));
                }
		buf_setflags(bp, B_LOCKED);
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
                (void) BTSetLastSync(VTOF(vp), tv.tv_sec - (kMaxSecsForFsync + 1));

                buf_clearflags(bp, B_LOCKED);
                buf_bawrite(bp);
            }
        } else {
			// check if we had previously called journal_modify_block_start() 
			// on this block and if so, abort it (which will call buf_brelse()).
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
				buf_brelse(bp);	/* note: B-tree code will clear blockPtr->blockHeader and blockPtr->buffer */
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

	OSStatus	retval = 0, ret = 0;
	UInt64		actualBytesAdded, origSize;
	UInt64		bytesToAdd;
	u_int32_t	startAllocation;
	u_int32_t	fileblocks;
	BTreeInfoRec btInfo;
	ExtendedVCB	*vcb;
	FCB			*filePtr;
    struct proc *p = NULL;
	UInt64 		trim = 0;
	int  lockflags = 0;

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

	/* Protect allocation bitmap and extents overflow file. */
	lockflags = SFL_BITMAP;
	if (VTOC(vp)->c_fileid != kHFSExtentsFileID)
		lockflags |= SFL_EXTENTS;
	lockflags = hfs_systemfile_lock(vcb, lockflags, HFS_EXCLUSIVE_LOCK);

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
			goto out;
		}
		actualBytesAdded -= trim;
	}

	if(VTOC(vp)->c_fileid != kHFSExtentsFileID) {
		/*
		 * Get any extents overflow b-tree changes to disk ASAP!
		 */
		(void) BTFlushPath(VTOF(vcb->extentsRefNum));
		(void) hfs_fsync(vcb->extentsRefNum, MNT_WAIT, 0, p);
	}
	hfs_systemfile_unlock(vcb, lockflags);
	lockflags = 0;

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
		VTOC(vp)->c_flag |= C_MODIFIED;
		MarkVCBDirty( vcb );
		ret = hfs_flushvolumeheader(VCBTOHFS(vcb), MNT_WAIT, HFS_ALTFLUSH);
	} else {
		VTOC(vp)->c_touch_chgtime = TRUE;
		VTOC(vp)->c_touch_modtime = TRUE;
		(void) hfs_update(vp, TRUE);
	}

	ret = ClearBTNodes(vp, btInfo.nodeSize, filePtr->fcbEOF - actualBytesAdded, actualBytesAdded);
out:
	if (retval == 0)
		retval = ret;
	
	if (lockflags)
		hfs_systemfile_unlock(vcb, lockflags);
	
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
	daddr64_t blk;
	daddr64_t blkcnt;
    
	blk = offset / blksize;
	blkcnt = amount / blksize;
	
	while (blkcnt > 0) {
		bp = buf_getblk(vp, blk, blksize, 0, 0, BLK_META);
		if (bp == NULL)
			continue;

        // XXXdbg
		if (hfsmp->jnl) {
			// XXXdbg -- skipping this for now since it makes a transaction
			//           become *way* too large
		    //journal_modify_block_start(hfsmp->jnl, bp);
		}
		bzero((char *)buf_dataptr(bp), blksize);

		buf_markaged(bp);

        // XXXdbg
		if (hfsmp->jnl) {
			// XXXdbg -- skipping this for now since it makes a transaction
			//           become *way* too large
			//journal_modify_block_end(hfsmp->jnl, bp);

			// XXXdbg - remove this once we decide what to do with the
			//          writes to the journal
			if ((blk % 32) == 0)
			    VNOP_BWRITE(bp);
			else
			    buf_bawrite(bp);
		} else {
			/* wait/yield every 32 blocks so we don't hog all the buffers */
			if ((blk % 32) == 0)
				VNOP_BWRITE(bp);
			else
				buf_bawrite(bp);
		}
		--blkcnt;
		++blk;
	}

	return (0);
}


extern char  hfs_attrname[];

extern int  hfs_attrkeycompare(HFSPlusAttrKey *searchKey, HFSPlusAttrKey *trialKey);

int  hfs_create_attr_btree(struct hfsmount *hfsmp, uint32_t nodesize, uint32_t nodecnt);

/*
 * Create an HFS+ Attribute B-tree File.
 *
 * A journal transaction must be already started.
 */
int
hfs_create_attr_btree(struct hfsmount *hfsmp, uint32_t nodesize, uint32_t nodecnt)
{
	struct vnode* vp = NULL;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	struct cat_fork cfork;
	BlockDescriptor blkdesc;
	BTNodeDescriptor  *ndp;
	BTHeaderRec  *bthp;
	BTreeControlBlockPtr btcb = NULL;
	struct buf *bp = NULL;
	void * buffer;
	u_int16_t *index;
	u_int16_t  offset;
	int result;

	printf("Creating HFS+ Attribute B-tree File (%d nodes) on %s\n", nodecnt, hfsmp->vcbVN);

	/*
	 * Set up Attribute B-tree vnode
	 */
	bzero(&cndesc, sizeof(cndesc));
	cndesc.cd_parentcnid = kHFSRootParentID;
	cndesc.cd_flags |= CD_ISMETA;
	cndesc.cd_nameptr = hfs_attrname;
	cndesc.cd_namelen = strlen(hfs_attrname);
	cndesc.cd_cnid = kHFSAttributesFileID;

	bzero(&cnattr, sizeof(cnattr));
	cnattr.ca_nlink = 1;
	cnattr.ca_mode = S_IFREG;
	cnattr.ca_fileid = cndesc.cd_cnid;

	bzero(&cfork, sizeof(cfork));
	cfork.cf_clump = nodesize * nodecnt;

	result = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &cfork, &vp);
	if (result)
		return (result);

	/*
	 * Set up Attribute B-tree control block
	 */
	MALLOC(btcb, BTreeControlBlock *, sizeof(BTreeControlBlock), M_TEMP, M_WAITOK);
        bzero(btcb, sizeof(BTreeControlBlock));

	btcb->nodeSize          = nodesize;
	btcb->maxKeyLength      = kHFSPlusAttrKeyMaximumLength;
	btcb->btreeType         = 0xFF;
	btcb->attributes        = kBTVariableIndexKeysMask | kBTBigKeysMask;
	btcb->version           = kBTreeVersion;
	btcb->writeCount        = 1;
	btcb->flags             = 0;  /* kBTHeaderDirty */
	btcb->fileRefNum        = vp;
	btcb->getBlockProc      = GetBTreeBlock;
	btcb->releaseBlockProc  = ReleaseBTreeBlock;
	btcb->setEndOfForkProc  = ExtendBTreeFile;
	btcb->keyCompareProc    = (KeyCompareProcPtr)hfs_attrkeycompare;
	VTOF(vp)->fcbBTCBPtr    = btcb;

	/*
	 * Allocate some space
	 */
	result = ExtendBTreeFile(vp, nodesize, cfork.cf_clump);
	if (result)
		goto exit;

	btcb->totalNodes = VTOF(vp)->ff_size / nodesize;
	btcb->freeNodes = btcb->totalNodes - 1;

	/*
	 * Initialize the b-tree header on disk
	 */
	bp = buf_getblk(vp, 0, nodesize, 0, 0, BLK_META);
	if (bp == NULL) {
		result = EIO;
		goto exit;
	}

	buffer = (void *)buf_dataptr(bp);
	blkdesc.buffer = buffer;
	blkdesc.blockHeader = (void *)bp;
	blkdesc.blockReadFromDisk = 0;
	blkdesc.isModified = 0;

	ModifyBlockStart(vp, &blkdesc);

	if (buf_size(bp) != nodesize)
		panic("hfs_create_attr_btree: bad buffer size (%d)\n", buf_size(bp));

	bzero(buffer, nodesize);
	index = (int16_t *)buffer;

	/* FILL IN THE NODE DESCRIPTOR:  */
	ndp = (BTNodeDescriptor *)buffer;
	ndp->kind = kBTHeaderNode;
	ndp->numRecords = 3;
	offset = sizeof(BTNodeDescriptor);
	index[(nodesize / 2) - 1] = offset;

	/* FILL IN THE HEADER RECORD:  */
	bthp = (BTHeaderRec *)((UInt8 *)buffer + offset);
	bthp->nodeSize     = nodesize;
	bthp->totalNodes   = btcb->totalNodes;
	bthp->freeNodes    = btcb->freeNodes;
	bthp->clumpSize    = cfork.cf_clump;
	bthp->btreeType    = 0xFF;
	bthp->attributes   = kBTVariableIndexKeysMask | kBTBigKeysMask;
	bthp->maxKeyLength = kHFSPlusAttrKeyMaximumLength;
	bthp->keyCompareType = kHFSBinaryCompare;
	offset += sizeof(BTHeaderRec);
	index[(nodesize / 2) - 2] = offset;

	/* FILL IN THE USER RECORD:  */
	offset += kBTreeHeaderUserBytes;
	index[(nodesize / 2) - 3] = offset;

	/* FILL IN THE MAP RECORD (only one node in use). */
	*((u_int8_t *)buffer + offset) = 0x80;
	offset += nodesize - sizeof(BTNodeDescriptor) - sizeof(BTHeaderRec)
			   - kBTreeHeaderUserBytes - (4 * sizeof(int16_t));
	index[(nodesize / 2) - 4] = offset;

	if (hfsmp->jnl) {
		result = btree_journal_modify_block_end(hfsmp, bp);
	} else {
		result = VNOP_BWRITE(bp);
	}
	if (result)
		goto exit;

	/* Publish new btree file */
	hfsmp->hfs_attribute_vp = vp;
	(void) hfs_flushvolumeheader(hfsmp, MNT_WAIT, HFS_ALTFLUSH);

exit:
	hfs_unlock(VTOC(vp));
	if (result) {
		if (btcb) {
			FREE (btcb, M_TEMP);
		}
		vnode_put(vp);
	//	hfs_truncate();  /* XXX need to give back blocks */
	}
	return (result);
}



