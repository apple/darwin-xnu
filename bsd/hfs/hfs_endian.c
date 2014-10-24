/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
 * hfs_endian.c
 *
 * This file implements endian swapping routines for the HFS/HFS Plus
 * volume format.
 */

#include "hfs_endian.h"
#include "hfs_dbg.h"
#include "hfscommon/headers/BTreesPrivate.h"

#undef ENDIAN_DEBUG

/*
 * Internal swapping routines
 *
 * These routines handle swapping the records of leaf and index nodes.  The
 * layout of the keys and records varies depending on the kind of B-tree
 * (determined by fileID).
 *
 * The direction parameter must be kSwapBTNodeBigToHost or kSwapBTNodeHostToBig.
 * The kSwapBTNodeHeaderRecordOnly "direction" is not valid for these routines.
 */
int hfs_swap_HFSPlusBTInternalNode (BlockDescriptor *src, HFSCatalogNodeID fileID, enum HFSBTSwapDirection direction);
void hfs_swap_HFSPlusForkData (HFSPlusForkData *src);

#if CONFIG_HFS_STD
int hfs_swap_HFSBTInternalNode (BlockDescriptor *src, HFSCatalogNodeID fileID, enum HFSBTSwapDirection direction);
#endif

/*
 * hfs_swap_HFSPlusForkData
 */
void
hfs_swap_HFSPlusForkData (
    HFSPlusForkData *src
)
{
    int i;

	src->logicalSize		= SWAP_BE64 (src->logicalSize);

	src->clumpSize			= SWAP_BE32 (src->clumpSize);
	src->totalBlocks		= SWAP_BE32 (src->totalBlocks);

    for (i = 0; i < kHFSPlusExtentDensity; i++) {
        src->extents[i].startBlock	= SWAP_BE32 (src->extents[i].startBlock);
        src->extents[i].blockCount	= SWAP_BE32 (src->extents[i].blockCount);
    }
}

/*
 * hfs_swap_BTNode
 *
 *  NOTE: This operation is not naturally symmetric.
 *        We have to determine which way we're swapping things.
 */
int
hfs_swap_BTNode (
    BlockDescriptor *src,
    vnode_t vp,
    enum HFSBTSwapDirection direction,
    u_int8_t allow_empty_node
)
{
    BTNodeDescriptor *srcDesc = src->buffer;
    u_int16_t *srcOffs = NULL;
	BTreeControlBlockPtr btcb = (BTreeControlBlockPtr)VTOF(vp)->fcbBTCBPtr;
    u_int16_t i; /* index to match srcDesc->numRecords */
    int error = 0;

#ifdef ENDIAN_DEBUG
    if (direction == kSwapBTNodeBigToHost) {
        printf ("hfs: BE -> Native Swap\n");
    } else if (direction == kSwapBTNodeHostToBig) {
        printf ("hfs: Native -> BE Swap\n");
    } else if (direction == kSwapBTNodeHeaderRecordOnly) {
        printf ("hfs: Not swapping descriptors\n");
    } else {
        panic ("hfs_swap_BTNode: This is impossible");
    }
#endif

    /*
     * If we are doing a swap from on-disk to in-memory, then swap the node
     * descriptor and record offsets before we need to use them.
     */
    if (direction == kSwapBTNodeBigToHost) {
        srcDesc->fLink		= SWAP_BE32 (srcDesc->fLink);
        srcDesc->bLink		= SWAP_BE32 (srcDesc->bLink);
    
    	/*
    	 * When first opening a BTree, we have to read the header node before the
    	 * control block is initialized.  In this case, totalNodes will be zero,
    	 * so skip the bounds checking. Also, we should ignore the header node when
		 * checking for invalid forwards and backwards links, since the header node's
		 * links can point back to itself legitimately.
    	 */
    	if (btcb->totalNodes != 0) {
			if (srcDesc->fLink >= btcb->totalNodes) {
				printf("hfs_swap_BTNode: invalid forward link (0x%08x >= 0x%08x)\n", srcDesc->fLink, btcb->totalNodes);
				error = fsBTInvalidHeaderErr;
				goto fail;
			}
			if (srcDesc->bLink >= btcb->totalNodes) {
				printf("hfs_swap_BTNode: invalid backward link (0x%08x >= 0x%08x)\n", srcDesc->bLink, btcb->totalNodes);
				error = fsBTInvalidHeaderErr;
				goto fail;
			}
			
			if ((src->blockNum != 0) && (srcDesc->fLink == (u_int32_t) src->blockNum)) {
				printf("hfs_swap_BTNode: invalid forward link (0x%08x == 0x%08x)\n",
						srcDesc->fLink, (u_int32_t) src->blockNum);
				error = fsBTInvalidHeaderErr;
				goto fail;
			}
			if ((src->blockNum != 0) && (srcDesc->bLink == (u_int32_t) src->blockNum)) {
				printf("hfs_swap_BTNode: invalid backward link (0x%08x == 0x%08x)\n",
						srcDesc->bLink, (u_int32_t) src->blockNum);
				error = fsBTInvalidHeaderErr;
				goto fail;
			}


		}
		
		/* 
		 * Check srcDesc->kind.  Don't swap it because it's only one byte.
		 */
		if (srcDesc->kind < kBTLeafNode || srcDesc->kind > kBTMapNode) {
			printf("hfs_swap_BTNode: invalid node kind (%d)\n", srcDesc->kind);
			error = fsBTInvalidHeaderErr;
			goto fail;
		}
		
		/*
		 * Check srcDesc->height.  Don't swap it because it's only one byte.
		 */
		if (srcDesc->height > kMaxTreeDepth) {
			printf("hfs_swap_BTNode: invalid node height (%d)\n", srcDesc->height);
			error = fsBTInvalidHeaderErr;
			goto fail;
		}
        
        /* Don't swap srcDesc->reserved */
    
        srcDesc->numRecords	= SWAP_BE16 (srcDesc->numRecords);
        
        /*
         * Swap the node offsets (including the free space one!).
         */
        srcOffs = (u_int16_t *)((char *)src->buffer + (src->blockSize - ((srcDesc->numRecords + 1) * sizeof (u_int16_t))));

        /*
         * Sanity check that the record offsets are within the node itself.
         */
        if ((char *)srcOffs > ((char *)src->buffer + src->blockSize) ||
            (char *)srcOffs < ((char *)src->buffer + sizeof(BTNodeDescriptor))) {
            printf("hfs_swap_BTNode: invalid record count (0x%04X)\n", srcDesc->numRecords);
            error = fsBTInvalidHeaderErr;
            goto fail;
        }

		/*
		 * Swap and sanity check each of the record offsets.
		 */
        for (i = 0; i <= srcDesc->numRecords; i++) {
            srcOffs[i]	= SWAP_BE16 (srcOffs[i]);

            /*
             * Sanity check: must be even, and within the node itself.
             *
             * We may be called to swap an unused node, which contains all zeroes.
			 * Unused nodes are expected only when allow_empty_node is true.
			 * If it is false and record offset is zero, return error.
             */
            if ((srcOffs[i] & 1) || (
			    (allow_empty_node == false) && (srcOffs[i] == 0)) ||
				(srcOffs[i] < sizeof(BTNodeDescriptor) && srcOffs[i] != 0) || 
				(srcOffs[i] >= src->blockSize)) { 
            	printf("hfs_swap_BTNode: record #%d invalid offset (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
            	error = fsBTInvalidHeaderErr;
            	goto fail;
            }

            /*
             * Make sure the offsets are strictly increasing.  Note that we're looping over
             * them backwards, hence the order in the comparison.
             */
            if ((i != 0) && (srcOffs[i] >= srcOffs[i-1])) {
            	printf("hfs_swap_BTNode: offsets %d and %d out of order (0x%04X, 0x%04X)\n",
            	    srcDesc->numRecords-i-1, srcDesc->numRecords-i, srcOffs[i], srcOffs[i-1]);
            	error = fsBTInvalidHeaderErr;
            	goto fail;
            }
        }
    }
    
    /*
     * Swap the records (ordered by frequency of access)
     */
    if ((srcDesc->kind == kBTIndexNode) ||
        (srcDesc-> kind == kBTLeafNode)) {

        if (VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) {
            error = hfs_swap_HFSPlusBTInternalNode (src, VTOC(vp)->c_fileid, direction);
        } 
#if CONFIG_HFS_STD
		else {
            error = hfs_swap_HFSBTInternalNode (src, VTOC(vp)->c_fileid, direction);
        }
#endif
        
        if (error) goto fail;
        
    } else if (srcDesc-> kind == kBTMapNode) {
        /* Don't swap the bitmaps, they'll be done in the bitmap routines */
    
    } else if (srcDesc-> kind == kBTHeaderNode) {
        /* The header's offset is hard-wired because we cannot trust the offset pointers. */
        BTHeaderRec *srcHead = (BTHeaderRec *)((char *)src->buffer + sizeof(BTNodeDescriptor));
        
        srcHead->treeDepth		=	SWAP_BE16 (srcHead->treeDepth);
        
        srcHead->rootNode		=	SWAP_BE32 (srcHead->rootNode);
        srcHead->leafRecords	=	SWAP_BE32 (srcHead->leafRecords);
        srcHead->firstLeafNode	=	SWAP_BE32 (srcHead->firstLeafNode);
        srcHead->lastLeafNode	=	SWAP_BE32 (srcHead->lastLeafNode);
        
        srcHead->nodeSize		=	SWAP_BE16 (srcHead->nodeSize);
        srcHead->maxKeyLength	=	SWAP_BE16 (srcHead->maxKeyLength);
        
        srcHead->totalNodes		=	SWAP_BE32 (srcHead->totalNodes);
        srcHead->freeNodes		=	SWAP_BE32 (srcHead->freeNodes);
        
        srcHead->clumpSize		=	SWAP_BE32 (srcHead->clumpSize);
        srcHead->attributes		=	SWAP_BE32 (srcHead->attributes);

        /* Don't swap srcHead->reserved1 */
        /* Don't swap srcHead->btreeType; it's only one byte */
        /* Don't swap srcHead->reserved2 */
        /* Don't swap srcHead->reserved3 */
        /* Don't swap bitmap */
    }
    
    /*
     * If we are doing a swap from in-memory to on-disk, then swap the node
     * descriptor and record offsets after we're done using them.
     */
    if (direction == kSwapBTNodeHostToBig) {
		/*
		 * Sanity check and swap the forward and backward links.
		 * Ignore the header node since its forward and backwards links can legitimately
		 * point to itself.
		 */
		if (srcDesc->fLink >= btcb->totalNodes) {
			panic("hfs_UNswap_BTNode: invalid forward link (0x%08X)\n", srcDesc->fLink);
			error = fsBTInvalidHeaderErr;
			goto fail;
		}
		if ((src->blockNum != 0) && (srcDesc->fLink == (u_int32_t) src->blockNum)) {
			panic ("hfs_UNswap_BTNode: invalid forward link (0x%08x == 0x%08x)\n", 
					srcDesc->fLink, (u_int32_t) src->blockNum);
			error = fsBTInvalidHeaderErr;
			goto fail;
		}
		
		if (srcDesc->bLink >= btcb->totalNodes) {
			panic("hfs_UNswap_BTNode: invalid backward link (0x%08X)\n", srcDesc->bLink);
			error = fsBTInvalidHeaderErr;
			goto fail;
		}
		if ((src->blockNum != 0) && (srcDesc->bLink == (u_int32_t) src->blockNum)) {
			panic ("hfs_UNswap_BTNode: invalid backward link (0x%08x == 0x%08x)\n", 
					srcDesc->bLink, (u_int32_t) src->blockNum);
			error = fsBTInvalidHeaderErr;
			goto fail;
		}


        srcDesc->fLink		= SWAP_BE32 (srcDesc->fLink);
        srcDesc->bLink		= SWAP_BE32 (srcDesc->bLink);
    
		/* 
		 * Check srcDesc->kind.  Don't swap it because it's only one byte.
		 */
		if (srcDesc->kind < kBTLeafNode || srcDesc->kind > kBTMapNode) {
			panic("hfs_UNswap_BTNode: invalid node kind (%d)\n", srcDesc->kind);
			error = fsBTInvalidHeaderErr;
			goto fail;
		}

		/* 
		 * Check srcDesc->height.  Don't swap it because it's only one byte.
		 */
		if (srcDesc->height > kMaxTreeDepth) {
			panic("hfs_UNswap_BTNode: invalid node height (%d)\n", srcDesc->height);
			error = fsBTInvalidHeaderErr;
			goto fail;
		}

        /* Don't swap srcDesc->reserved */
    
        /*
         * Swap the node offsets (including the free space one!).
         */
        srcOffs = (u_int16_t *)((char *)src->buffer + (src->blockSize - ((srcDesc->numRecords + 1) * sizeof (u_int16_t))));

        /*
         * Sanity check that the record offsets are within the node itself.
         */
        if ((char *)srcOffs > ((char *)src->buffer + src->blockSize) ||
        	(char *)srcOffs < ((char *)src->buffer + sizeof(BTNodeDescriptor))) {
            panic("hfs_UNswap_BTNode: invalid record count (0x%04X)\n", srcDesc->numRecords);
            error = fsBTInvalidHeaderErr;
            goto fail;
        }

		/*
		 * Swap and sanity check each of the record offsets.
		 */
        for (i = 0; i <= srcDesc->numRecords; i++) {
            /*
             * Sanity check: must be even, and within the node itself.
             *
             * We may be called to swap an unused node, which contains all zeroes.
	    	 * This can happen when the last record from a node gets deleted.
             * This is why we allow the record offset to be zero.
	     	 * Unused nodes are expected only when allow_empty_node is true 
	     	 * (the caller should set it to true for kSwapBTNodeBigToHost). 
             */
            if ((srcOffs[i] & 1) || 
			    ((allow_empty_node == false) && (srcOffs[i] == 0)) ||
				(srcOffs[i] < sizeof(BTNodeDescriptor) && srcOffs[i] != 0) || 
				(srcOffs[i] >= src->blockSize)) {
            	panic("hfs_UNswap_BTNode: record #%d invalid offset (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
            	error = fsBTInvalidHeaderErr;
            	goto fail;
            }

            /*
             * Make sure the offsets are strictly increasing.  Note that we're looping over
             * them backwards, hence the order in the comparison.
             */
            if ((i < srcDesc->numRecords) && (srcOffs[i+1] >= srcOffs[i])) {
            	panic("hfs_UNswap_BTNode: offsets %d and %d out of order (0x%04X, 0x%04X)\n",
            	    srcDesc->numRecords-i-2, srcDesc->numRecords-i-1, srcOffs[i+1], srcOffs[i]);
            	error = fsBTInvalidHeaderErr;
            	goto fail;
            }

            srcOffs[i]	= SWAP_BE16 (srcOffs[i]);
        }
        
        srcDesc->numRecords	= SWAP_BE16 (srcDesc->numRecords);
    }

fail:
	if (error) {
		/*
		 * Log some useful information about where the corrupt node is.
		 */
		printf("hfs: node=%lld fileID=%u volume=%s device=%s\n", src->blockNum, VTOC(vp)->c_fileid,
			VTOVCB(vp)->vcbVN, vfs_statfs(vnode_mount(vp))->f_mntfromname);
		hfs_mark_inconsistent(VTOVCB(vp), HFS_INCONSISTENCY_DETECTED);
	}
	
    return (error);
}

int
hfs_swap_HFSPlusBTInternalNode (
    BlockDescriptor *src,
    HFSCatalogNodeID fileID,
    enum HFSBTSwapDirection direction
)
{
    BTNodeDescriptor *srcDesc = src->buffer;
    u_int16_t *srcOffs = (u_int16_t *)((char *)src->buffer + (src->blockSize - (srcDesc->numRecords * sizeof (u_int16_t))));
    char *nextRecord;	/*  Points to start of record following current one */
    
    /*
     * i is an int32 because it needs to be negative to index the offset to free space.
     * srcDesc->numRecords is a u_int16_t and is unlikely to become 32-bit so this should be ok.
     */

    int32_t i;
    u_int32_t j;

    if (fileID == kHFSExtentsFileID) {
        HFSPlusExtentKey *srcKey;
        HFSPlusExtentDescriptor *srcRec;
		size_t recordSize;	/* Size of the data part of the record, or node number for index nodes */
        
        if (srcDesc->kind == kBTIndexNode)
        	recordSize = sizeof(u_int32_t);
        else
        	recordSize = sizeof(HFSPlusExtentDescriptor);

        for (i = 0; i < srcDesc->numRecords; i++) {
        	/* Point to the start of the record we're currently checking. */
            srcKey = (HFSPlusExtentKey *)((char *)src->buffer + srcOffs[i]);
            
            /*
             * Point to start of next (larger offset) record.  We'll use this
             * to be sure the current record doesn't overflow into the next
             * record.
             */
			nextRecord = (char *)src->buffer + srcOffs[i-1];

			/*
			 * Make sure the key and data are within the buffer.  Since both key
			 * and data are fixed size, this is relatively easy.  Note that this
			 * relies on the keyLength being a constant; we verify the keyLength
			 * below.
			 */
			if ((char *)srcKey + sizeof(HFSPlusExtentKey) + recordSize > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: extents key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: extents key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				}
				return fsBTInvalidNodeErr;
			}
			
            if (direction == kSwapBTNodeBigToHost) 
            	srcKey->keyLength = SWAP_BE16 (srcKey->keyLength);
            if (srcKey->keyLength != sizeof(*srcKey) - sizeof(srcKey->keyLength)) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: extents key #%d invalid length (%d)\n", srcDesc->numRecords-i-1, srcKey->keyLength);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: extents key #%d invalid length (%d)\n", srcDesc->numRecords-i-1, srcKey->keyLength);
				}
				return fsBTInvalidNodeErr;
            }
            srcRec = (HFSPlusExtentDescriptor *)((char *)srcKey + srcKey->keyLength + sizeof(srcKey->keyLength));
            if (direction == kSwapBTNodeHostToBig)
            	srcKey->keyLength = SWAP_BE16 (srcKey->keyLength);

            /* Don't swap srcKey->forkType; it's only one byte */
            /* Don't swap srcKey->pad */

            srcKey->fileID			= SWAP_BE32 (srcKey->fileID);
            srcKey->startBlock		= SWAP_BE32 (srcKey->startBlock);
            
            if (srcDesc->kind == kBTIndexNode) {
            	/* For index nodes, the record data is just a child node number. */
                *((u_int32_t *)srcRec) = SWAP_BE32 (*((u_int32_t *)srcRec));
            } else {
				/* Swap the extent data */
				for (j = 0; j < kHFSPlusExtentDensity; j++) {
					srcRec[j].startBlock	= SWAP_BE32 (srcRec[j].startBlock);
					srcRec[j].blockCount	= SWAP_BE32 (srcRec[j].blockCount);
				}
            }
        }

    } else if (fileID == kHFSCatalogFileID) {
        HFSPlusCatalogKey *srcKey;
        int16_t *srcPtr;
        u_int16_t keyLength;

        for (i = 0; i < srcDesc->numRecords; i++) {
        	/* Point to the start of the record we're currently checking. */
            srcKey = (HFSPlusCatalogKey *)((char *)src->buffer + srcOffs[i]);

            /*
             * Point to start of next (larger offset) record.  We'll use this
             * to be sure the current record doesn't overflow into the next
             * record.
             */
			nextRecord = (char *)src->buffer + (uintptr_t)(srcOffs[i-1]);

			/*
			 * Make sure we can safely dereference the keyLength and parentID fields. 
			 */
			if ((char *)srcKey + offsetof(HFSPlusCatalogKey, nodeName.unicode[0]) > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: catalog key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: catalog key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				}
				return fsBTInvalidNodeErr;
			}

			/*
			 * Swap and sanity check the key length
			 */
            if (direction == kSwapBTNodeBigToHost)
            	srcKey->keyLength = SWAP_BE16 (srcKey->keyLength);
            keyLength = srcKey->keyLength;	/* Put it in a local (native order) because we use it several times */
            if (direction == kSwapBTNodeHostToBig)
            	srcKey->keyLength = SWAP_BE16 (keyLength);
            
            /* Sanity check the key length */
            if (keyLength < kHFSPlusCatalogKeyMinimumLength || keyLength > kHFSPlusCatalogKeyMaximumLength) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: catalog key #%d invalid length (%d)\n", srcDesc->numRecords-i-1, keyLength);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: catalog key #%d invalid length (%d)\n", srcDesc->numRecords-i-1, keyLength);
				}
				return fsBTInvalidNodeErr;
            }

            /*
             * Make sure that we can safely dereference the record's type field or
             * an index node's child node number.
             */
            srcPtr = (int16_t *)((char *)srcKey + keyLength + sizeof(srcKey->keyLength));
            if ((char *)srcPtr + sizeof(u_int32_t) > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: catalog key #%d too big\n", srcDesc->numRecords-i-1);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: catalog key #%d too big\n", srcDesc->numRecords-i-1);
				}
				return fsBTInvalidNodeErr;
            }

            srcKey->parentID						= SWAP_BE32 (srcKey->parentID);

			/*
			 * Swap and sanity check the key's node name
			 */
            if (direction == kSwapBTNodeBigToHost)
            	srcKey->nodeName.length	= SWAP_BE16 (srcKey->nodeName.length);
            /* Make sure name length is consistent with key length */
            if (keyLength < sizeof(srcKey->parentID) + sizeof(srcKey->nodeName.length) +
                srcKey->nodeName.length*sizeof(srcKey->nodeName.unicode[0])) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: catalog record #%d keyLength=%d expected=%lu\n",
						srcDesc->numRecords-i, keyLength, sizeof(srcKey->parentID) + sizeof(srcKey->nodeName.length) +
                    	srcKey->nodeName.length*sizeof(srcKey->nodeName.unicode[0]));
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: catalog record #%d keyLength=%d expected=%lu\n",
						srcDesc->numRecords-i, keyLength, sizeof(srcKey->parentID) + sizeof(srcKey->nodeName.length) +
                    	srcKey->nodeName.length*sizeof(srcKey->nodeName.unicode[0]));
				}
				return fsBTInvalidNodeErr;
            }
            for (j = 0; j < srcKey->nodeName.length; j++) {
                srcKey->nodeName.unicode[j]	= SWAP_BE16 (srcKey->nodeName.unicode[j]);
            }
            if (direction == kSwapBTNodeHostToBig)
            	srcKey->nodeName.length	= SWAP_BE16 (srcKey->nodeName.length);
 
            /* 
             * For index nodes, the record data is just the child's node number.
             * Skip over swapping the various types of catalog record.
             */
            if (srcDesc->kind == kBTIndexNode) {
                *((u_int32_t *)srcPtr) = SWAP_BE32 (*((u_int32_t *)srcPtr));
                continue;
            }
            
            /* Make sure the recordType is in native order before using it. */
            if (direction == kSwapBTNodeBigToHost)
            	srcPtr[0] = SWAP_BE16 (srcPtr[0]);
            
            if (srcPtr[0] == kHFSPlusFolderRecord) {
                HFSPlusCatalogFolder *srcRec = (HFSPlusCatalogFolder *)srcPtr;
                if ((char *)srcRec + sizeof(*srcRec) > nextRecord) {
					if (direction == kSwapBTNodeHostToBig) {
						panic("hfs_swap_HFSPlusBTInternalNode: catalog folder record #%d too big\n", srcDesc->numRecords-i-1);
					} else {
						printf("hfs_swap_HFSPlusBTInternalNode: catalog folder record #%d too big\n", srcDesc->numRecords-i-1);
					}
					return fsBTInvalidNodeErr;
                }

                srcRec->flags				= SWAP_BE16 (srcRec->flags);
                srcRec->valence				= SWAP_BE32 (srcRec->valence);
                srcRec->folderID			= SWAP_BE32 (srcRec->folderID);
                srcRec->createDate			= SWAP_BE32 (srcRec->createDate);
                srcRec->contentModDate		= SWAP_BE32 (srcRec->contentModDate);
                srcRec->attributeModDate	= SWAP_BE32 (srcRec->attributeModDate);
                srcRec->accessDate			= SWAP_BE32 (srcRec->accessDate);
                srcRec->backupDate			= SWAP_BE32 (srcRec->backupDate);
                
                srcRec->bsdInfo.ownerID		= SWAP_BE32 (srcRec->bsdInfo.ownerID);
                srcRec->bsdInfo.groupID		= SWAP_BE32 (srcRec->bsdInfo.groupID);
    
                /* Don't swap srcRec->bsdInfo.adminFlags; it's only one byte */
                /* Don't swap srcRec->bsdInfo.ownerFlags; it's only one byte */
    
                srcRec->bsdInfo.fileMode			= SWAP_BE16 (srcRec->bsdInfo.fileMode);
                srcRec->bsdInfo.special.iNodeNum	= SWAP_BE32 (srcRec->bsdInfo.special.iNodeNum);
    
                srcRec->textEncoding		= SWAP_BE32 (srcRec->textEncoding);
    
                /* Don't swap srcRec->userInfo */
                /* Don't swap srcRec->finderInfo */
                srcRec->folderCount = SWAP_BE32 (srcRec->folderCount);
   
            } else if (srcPtr[0] == kHFSPlusFileRecord) {
                HFSPlusCatalogFile *srcRec = (HFSPlusCatalogFile *)srcPtr;
                if ((char *)srcRec + sizeof(*srcRec) > nextRecord) {
					if (direction == kSwapBTNodeHostToBig) {
						panic("hfs_swap_HFSPlusBTInternalNode: catalog file record #%d too big\n", srcDesc->numRecords-i-1);
					} else {
						printf("hfs_swap_HFSPlusBTInternalNode: catalog file record #%d too big\n", srcDesc->numRecords-i-1);
					}
					return fsBTInvalidNodeErr;
                }
                
                srcRec->flags				= SWAP_BE16 (srcRec->flags);
    
                srcRec->fileID				= SWAP_BE32 (srcRec->fileID);
    
                srcRec->createDate			= SWAP_BE32 (srcRec->createDate);
                srcRec->contentModDate		= SWAP_BE32 (srcRec->contentModDate);
                srcRec->attributeModDate	= SWAP_BE32 (srcRec->attributeModDate);
                srcRec->accessDate			= SWAP_BE32 (srcRec->accessDate);
                srcRec->backupDate			= SWAP_BE32 (srcRec->backupDate);
    
                srcRec->bsdInfo.ownerID		= SWAP_BE32 (srcRec->bsdInfo.ownerID);
                srcRec->bsdInfo.groupID		= SWAP_BE32 (srcRec->bsdInfo.groupID);
    
                /* Don't swap srcRec->bsdInfo.adminFlags; it's only one byte */
                /* Don't swap srcRec->bsdInfo.ownerFlags; it's only one byte */
    
                srcRec->bsdInfo.fileMode			= SWAP_BE16 (srcRec->bsdInfo.fileMode);
                srcRec->bsdInfo.special.iNodeNum	= SWAP_BE32 (srcRec->bsdInfo.special.iNodeNum);
    
                srcRec->textEncoding		= SWAP_BE32 (srcRec->textEncoding);
			
                /* If kHFSHasLinkChainBit is set, reserved1 is hl_FirstLinkID.  
				 * In all other context, it is expected to be zero.
				 */
                srcRec->reserved1 = SWAP_BE32 (srcRec->reserved1);

                /* Don't swap srcRec->userInfo */
                /* Don't swap srcRec->finderInfo */
                /* Don't swap srcRec->reserved2 */
    
                hfs_swap_HFSPlusForkData (&srcRec->dataFork);
                hfs_swap_HFSPlusForkData (&srcRec->resourceFork);
            
            } else if ((srcPtr[0] == kHFSPlusFolderThreadRecord) ||
                       (srcPtr[0] == kHFSPlusFileThreadRecord)) {
    
				/*
				 * Make sure there is room for parentID and name length.
				 */
                HFSPlusCatalogThread *srcRec = (HFSPlusCatalogThread *)srcPtr;
				if ((char *) &srcRec->nodeName.unicode[0] > nextRecord) {
					if (direction == kSwapBTNodeHostToBig) {
						panic("hfs_swap_HFSPlusBTInternalNode: catalog thread record #%d too big\n", srcDesc->numRecords-i-1);
					} else {
						printf("hfs_swap_HFSPlusBTInternalNode: catalog thread record #%d too big\n", srcDesc->numRecords-i-1);
					}
					return fsBTInvalidNodeErr;
				}

                /* Don't swap srcRec->reserved */
                
                srcRec->parentID						= SWAP_BE32 (srcRec->parentID);
                
                if (direction == kSwapBTNodeBigToHost)
                	srcRec->nodeName.length	= SWAP_BE16 (srcRec->nodeName.length);

                /* 
                 * Make sure there is room for the name in the buffer.
                 * Then swap the characters of the name itself.
                 */
				if ((char *) &srcRec->nodeName.unicode[srcRec->nodeName.length] > nextRecord) {
					if (direction == kSwapBTNodeHostToBig) {
						panic("hfs_swap_HFSPlusBTInternalNode: catalog thread record #%d name too big\n", srcDesc->numRecords-i-1);
					} else {
						printf("hfs_swap_HFSPlusBTInternalNode: catalog thread record #%d name too big\n", srcDesc->numRecords-i-1);
					}
					return fsBTInvalidNodeErr;
				}
                for (j = 0; j < srcRec->nodeName.length; j++) {
                    srcRec->nodeName.unicode[j]	= SWAP_BE16 (srcRec->nodeName.unicode[j]);
                }
                
                if (direction == kSwapBTNodeHostToBig)
                	srcRec->nodeName.length = SWAP_BE16 (srcRec->nodeName.length);

            } else {
				if (direction == kSwapBTNodeHostToBig) {
            		panic("hfs_swap_HFSPlusBTInternalNode: unrecognized catalog record type (0x%04X; record #%d)\n", srcPtr[0], srcDesc->numRecords-i-1);
				} else {
            		printf("hfs_swap_HFSPlusBTInternalNode: unrecognized catalog record type (0x%04X; record #%d)\n", srcPtr[0], srcDesc->numRecords-i-1);
				}
				return fsBTInvalidNodeErr;
            }
    
            /* We can swap the record type now that we're done using it. */
            if (direction == kSwapBTNodeHostToBig)
            	srcPtr[0] = SWAP_BE16 (srcPtr[0]);
        }
        
    } else if (fileID == kHFSAttributesFileID) {
    	HFSPlusAttrKey *srcKey;
    	HFSPlusAttrRecord *srcRec;
    	u_int16_t keyLength;
		u_int32_t attrSize = 0;

    	for (i = 0; i < srcDesc->numRecords; i++) {
        	/* Point to the start of the record we're currently checking. */
    		srcKey = (HFSPlusAttrKey *)((char *)src->buffer + srcOffs[i]);

            /*
             * Point to start of next (larger offset) record.  We'll use this
             * to be sure the current record doesn't overflow into the next
             * record.
             */
			nextRecord = (char *)src->buffer + srcOffs[i-1];

    		/* Make sure there is room in the buffer for a minimal key */
    		if ((char *) &srcKey->attrName[1] > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: attr key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: attr key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				}
				return fsBTInvalidNodeErr;
    		}
    		
    		/* Swap the key length field */
    		if (direction == kSwapBTNodeBigToHost)
    			srcKey->keyLength = SWAP_BE16(srcKey->keyLength);
    		keyLength = srcKey->keyLength;	/* Keep a copy in native order */
    		if (direction == kSwapBTNodeHostToBig)
    			srcKey->keyLength = SWAP_BE16(srcKey->keyLength);

            /*
             * Make sure that we can safely dereference the record's type field or
             * an index node's child node number.
             */
    		srcRec = (HFSPlusAttrRecord *)((char *)srcKey + keyLength + sizeof(srcKey->keyLength));
    		if ((char *)srcRec + sizeof(u_int32_t) > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: attr key #%d too big (%d)\n", srcDesc->numRecords-i-1, keyLength);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: attr key #%d too big (%d)\n", srcDesc->numRecords-i-1, keyLength);
				}
				return fsBTInvalidNodeErr;
    		}
    		
    		srcKey->fileID = SWAP_BE32(srcKey->fileID);
    		srcKey->startBlock = SWAP_BE32(srcKey->startBlock);

			/* 
			 * Swap and check the attribute name
			 */
    		if (direction == kSwapBTNodeBigToHost)
    			srcKey->attrNameLen = SWAP_BE16(srcKey->attrNameLen);
    		/* Sanity check the attribute name length */
    		if (srcKey->attrNameLen > kHFSMaxAttrNameLen || keyLength < (kHFSPlusAttrKeyMinimumLength + sizeof(u_int16_t)*srcKey->attrNameLen)) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: attr key #%d keyLength=%d attrNameLen=%d\n", srcDesc->numRecords-i-1, keyLength, srcKey->attrNameLen);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: attr key #%d keyLength=%d attrNameLen=%d\n", srcDesc->numRecords-i-1, keyLength, srcKey->attrNameLen);
				}
				return fsBTInvalidNodeErr;
    		}
    		for (j = 0; j < srcKey->attrNameLen; j++)
    			srcKey->attrName[j] = SWAP_BE16(srcKey->attrName[j]);
    		if (direction == kSwapBTNodeHostToBig)
    			srcKey->attrNameLen = SWAP_BE16(srcKey->attrNameLen);
    		
            /* 
             * For index nodes, the record data is just the child's node number.
             * Skip over swapping the various types of attribute record.
             */
            if (srcDesc->kind == kBTIndexNode) {
                *((u_int32_t *)srcRec) = SWAP_BE32 (*((u_int32_t *)srcRec));
                continue;
            }
            
            /* Swap the record data */
            if (direction == kSwapBTNodeBigToHost)
            	srcRec->recordType = SWAP_BE32(srcRec->recordType);
            switch (srcRec->recordType) {
            	case kHFSPlusAttrInlineData:
            		/* Is there room for the inline data header? */
            		if ((char *) &srcRec->attrData.attrData[0]  > nextRecord) {
						if (direction == kSwapBTNodeHostToBig) {
							panic("hfs_swap_HFSPlusBTInternalNode: attr inline #%d too big\n", srcDesc->numRecords-i-1);
						} else {
							printf("hfs_swap_HFSPlusBTInternalNode: attr inline #%d too big\n", srcDesc->numRecords-i-1);
						}
						return fsBTInvalidNodeErr;
            		}
            		
            		/* We're not swapping the reserved fields */
            		
            		/* Swap the attribute size */
            		if (direction == kSwapBTNodeHostToBig)
            			attrSize = srcRec->attrData.attrSize;
            		srcRec->attrData.attrSize = SWAP_BE32(srcRec->attrData.attrSize);
            		if (direction == kSwapBTNodeBigToHost)
            			attrSize = srcRec->attrData.attrSize;
            			
            		/* Is there room for the inline attribute data? */
            		if ((char *) &srcRec->attrData.attrData[attrSize] > nextRecord) {
						if (direction == kSwapBTNodeHostToBig) {
							panic("hfs_swap_HFSPlusBTInternalNode: attr inline #%d too big (attrSize=%u)\n", srcDesc->numRecords-i-1, attrSize);
						} else {
							printf("hfs_swap_HFSPlusBTInternalNode: attr inline #%d too big (attrSize=%u)\n", srcDesc->numRecords-i-1, attrSize);
						}
						return fsBTInvalidNodeErr;
            		}
            		
            		/* Not swapping the attribute data itself */
            		break;
            		
            	case kHFSPlusAttrForkData:
            		/* Is there room for the fork data record? */
            		if ((char *)srcRec + sizeof(HFSPlusAttrForkData) > nextRecord) {
						if (direction == kSwapBTNodeHostToBig) {
							panic("hfs_swap_HFSPlusBTInternalNode: attr fork data #%d too big\n", srcDesc->numRecords-i-1);
						} else {
							printf("hfs_swap_HFSPlusBTInternalNode: attr fork data #%d too big\n", srcDesc->numRecords-i-1);
						}
						return fsBTInvalidNodeErr;
            		}
            		
            		/* We're not swapping the reserved field */
            		
            		hfs_swap_HFSPlusForkData(&srcRec->forkData.theFork);
            		break;
            		
            	case kHFSPlusAttrExtents:
            		/* Is there room for an extent record? */
            		if ((char *)srcRec + sizeof(HFSPlusAttrExtents) > nextRecord) {
						if (direction == kSwapBTNodeHostToBig) {
							panic("hfs_swap_HFSPlusBTInternalNode: attr extents #%d too big\n", srcDesc->numRecords-i-1);
						} else {
							printf("hfs_swap_HFSPlusBTInternalNode: attr extents #%d too big\n", srcDesc->numRecords-i-1);
						}
						return fsBTInvalidNodeErr;
            		}
            		
            		/* We're not swapping the reserved field */
            		
            		for (j = 0; j < kHFSPlusExtentDensity; j++) {
            			srcRec->overflowExtents.extents[j].startBlock =
            				SWAP_BE32(srcRec->overflowExtents.extents[j].startBlock);
            			srcRec->overflowExtents.extents[j].blockCount =
            				SWAP_BE32(srcRec->overflowExtents.extents[j].blockCount);
            		}
            		break;
            }
            if (direction == kSwapBTNodeHostToBig)
            	srcRec->recordType = SWAP_BE32(srcRec->recordType);
    	}
    } else if (fileID > kHFSFirstUserCatalogNodeID) {
    	/* The only B-tree with a non-system CNID that we use is the hotfile B-tree */
		HotFileKey *srcKey;
		u_int32_t *srcRec;
        
		for (i = 0; i < srcDesc->numRecords; i++) {
        	/* Point to the start of the record we're currently checking. */
			srcKey = (HotFileKey *)((char *)src->buffer + srcOffs[i]);

            /*
             * Point to start of next (larger offset) record.  We'll use this
             * to be sure the current record doesn't overflow into the next
             * record.
             */
			nextRecord = (char *)src->buffer + srcOffs[i-1];

			/* Make sure there is room for the key (HotFileKey) and data (u_int32_t) */
			if ((char *)srcKey + sizeof(HotFileKey) + sizeof(u_int32_t) > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: hotfile #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: hotfile #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				}
				return fsBTInvalidNodeErr;
			}
			
			/* Swap and sanity check the key length field */
			if (direction == kSwapBTNodeBigToHost)
				srcKey->keyLength = SWAP_BE16 (srcKey->keyLength);
			if (srcKey->keyLength != sizeof(*srcKey) - sizeof(srcKey->keyLength)) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSPlusBTInternalNode: hotfile #%d incorrect keyLength %d\n", srcDesc->numRecords-i-1, srcKey->keyLength);
				} else {
					printf("hfs_swap_HFSPlusBTInternalNode: hotfile #%d incorrect keyLength %d\n", srcDesc->numRecords-i-1, srcKey->keyLength);
				}
				return fsBTInvalidNodeErr;
			}
			srcRec = (u_int32_t *)((char *)srcKey + srcKey->keyLength + sizeof(srcKey->keyLength));
			if (direction == kSwapBTNodeHostToBig)
				srcKey->keyLength = SWAP_BE16 (srcKey->keyLength);

			/* Don't swap srcKey->forkType */
			/* Don't swap srcKey->pad */

			srcKey->temperature = SWAP_BE32 (srcKey->temperature);
			srcKey->fileID = SWAP_BE32 (srcKey->fileID);
             
			*((u_int32_t *)srcRec) = SWAP_BE32 (*((u_int32_t *)srcRec));
		}
    } else {
        panic ("hfs_swap_HFSPlusBTInternalNode: fileID %u is not a system B-tree\n", fileID);
    }


    return (0);
}

#if CONFIG_HFS_STD
int
hfs_swap_HFSBTInternalNode (
    BlockDescriptor *src,
    HFSCatalogNodeID fileID,
    enum HFSBTSwapDirection direction
)
{
    BTNodeDescriptor *srcDesc = src->buffer;
    u_int16_t *srcOffs = (u_int16_t *)((char *)src->buffer + (src->blockSize - (srcDesc->numRecords * sizeof (u_int16_t))));
	char *nextRecord;	/*  Points to start of record following current one */

    /*
     * i is an int32 because it needs to be negative to index the offset to free space.
     * srcDesc->numRecords is a u_int16_t and is unlikely to become 32-bit so this should be ok.
     */
    int32_t i;
    u_int32_t j;

    if (fileID == kHFSExtentsFileID) {
        HFSExtentKey *srcKey;
        HFSExtentDescriptor *srcRec;
		size_t recordSize;	/* Size of the data part of the record, or node number for index nodes */
        
        if (srcDesc->kind == kBTIndexNode)
        	recordSize = sizeof(u_int32_t);
        else
        	recordSize = sizeof(HFSExtentDescriptor);

        for (i = 0; i < srcDesc->numRecords; i++) {
        	/* Point to the start of the record we're currently checking. */
            srcKey = (HFSExtentKey *)((char *)src->buffer + srcOffs[i]);

            /*
             * Point to start of next (larger offset) record.  We'll use this
             * to be sure the current record doesn't overflow into the next
             * record.
             */
			nextRecord = (char *)src->buffer + srcOffs[i-1];

			/*
			 * Make sure the key and data are within the buffer.  Since both key
			 * and data are fixed size, this is relatively easy.  Note that this
			 * relies on the keyLength being a constant; we verify the keyLength
			 * below.
			 */
			if ((char *)srcKey + sizeof(HFSExtentKey) + recordSize > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSBTInternalNode: extents key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				} else {
					printf("hfs_swap_HFSBTInternalNode: extents key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				}
				return fsBTInvalidNodeErr;
			}
			
            /* Don't swap srcKey->keyLength (it's only one byte), but do sanity check it */
            if (srcKey->keyLength != sizeof(*srcKey) - sizeof(srcKey->keyLength)) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSBTInternalNode: extents key #%d invalid length (%d)\n", srcDesc->numRecords-i-1, srcKey->keyLength);
				} else {
					printf("hfs_swap_HFSBTInternalNode: extents key #%d invalid length (%d)\n", srcDesc->numRecords-i-1, srcKey->keyLength);
				}
				return fsBTInvalidNodeErr;
            }

            /* Don't swap srcKey->forkType; it's only one byte */

            srcKey->fileID			= SWAP_BE32 (srcKey->fileID);
            srcKey->startBlock		= SWAP_BE16 (srcKey->startBlock);

            /* Point to record data (round up to even byte boundary) */
            srcRec = (HFSExtentDescriptor *)((char *)srcKey + ((srcKey->keyLength + 2) & ~1));
    
            if (srcDesc->kind == kBTIndexNode) {
            	/* For index nodes, the record data is just a child node number. */
                *((u_int32_t *)srcRec) = SWAP_BE32 (*((u_int32_t *)srcRec));
            } else {
				/* Swap the extent data */
				for (j = 0; j < kHFSExtentDensity; j++) {
					srcRec[j].startBlock	= SWAP_BE16 (srcRec[j].startBlock);
					srcRec[j].blockCount	= SWAP_BE16 (srcRec[j].blockCount);
				}
            }
        }
        
    } else if (fileID == kHFSCatalogFileID) {
        HFSCatalogKey *srcKey;
        int16_t *srcPtr;
        unsigned expectedKeyLength;

        for (i = 0; i < srcDesc->numRecords; i++) {
        	/* Point to the start of the record we're currently checking. */
            srcKey = (HFSCatalogKey *)((char *)src->buffer + srcOffs[i]);

            /*
             * Point to start of next (larger offset) record.  We'll use this
             * to be sure the current record doesn't overflow into the next
             * record.
             */
			nextRecord = (char *)src->buffer + srcOffs[i-1];

			/*
			 * Make sure we can safely dereference the keyLength and parentID fields.
			 * The value 8 below is 1 bytes for keyLength + 1 byte reserved + 4 bytes
			 * for parentID + 1 byte for nodeName's length + 1 byte to round up the
			 * record start to an even offset, which forms a minimal key.
			 */
			if ((char *)srcKey + 8 > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSBTInternalNode: catalog key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				} else {
					printf("hfs_swap_HFSBTInternalNode: catalog key #%d offset too big (0x%04X)\n", srcDesc->numRecords-i-1, srcOffs[i]);
				}
				return fsBTInvalidNodeErr;
			}
			
            /* Don't swap srcKey->keyLength (it's only one byte), but do sanity check it */
            if (srcKey->keyLength < kHFSCatalogKeyMinimumLength || srcKey->keyLength > kHFSCatalogKeyMaximumLength) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSBTInternalNode: catalog key #%d invalid length (%d)\n", srcDesc->numRecords-i-1, srcKey->keyLength);
				} else {
					printf("hfs_swap_HFSBTInternalNode: catalog key #%d invalid length (%d)\n", srcDesc->numRecords-i-1, srcKey->keyLength);
				}
				return fsBTInvalidNodeErr;
            }
            
            /* Don't swap srcKey->reserved */

            srcKey->parentID			= SWAP_BE32 (srcKey->parentID);

            /* Don't swap srcKey->nodeName */
            
			/* Make sure the keyLength is big enough for the key's content */
			if (srcDesc->kind == kBTIndexNode)
				expectedKeyLength = sizeof(*srcKey) - sizeof(srcKey->keyLength);
			else
				expectedKeyLength = srcKey->nodeName[0] + kHFSCatalogKeyMinimumLength;
            if (srcKey->keyLength < expectedKeyLength) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSBTInternalNode: catalog record #%d keyLength=%u expected=%u\n",
						srcDesc->numRecords-i, srcKey->keyLength, expectedKeyLength);
				} else {
					printf("hfs_swap_HFSBTInternalNode: catalog record #%d keyLength=%u expected=%u\n",
						srcDesc->numRecords-i, srcKey->keyLength, expectedKeyLength);
				}
				return fsBTInvalidNodeErr;
            }

            /* Point to record data (round up to even byte boundary) */
            srcPtr = (int16_t *)((char *)srcKey + ((srcKey->keyLength + 2) & ~1));
            
            /*
             * Make sure that we can safely dereference the record's type field or
             * and index node's child node number.
             */
            if ((char *)srcPtr + sizeof(u_int32_t) > nextRecord) {
				if (direction == kSwapBTNodeHostToBig) {
					panic("hfs_swap_HFSBTInternalNode: catalog key #%d too big\n", srcDesc->numRecords-i-1);
				} else {
					printf("hfs_swap_HFSBTInternalNode: catalog key #%d too big\n", srcDesc->numRecords-i-1);
				}
				return fsBTInvalidNodeErr;
            }
            
            /* 
             * For index nodes, the record data is just the child's node number.
             * Skip over swapping the various types of catalog record.
             */
            if (srcDesc->kind == kBTIndexNode) {
                *((u_int32_t *)srcPtr) = SWAP_BE32 (*((u_int32_t *)srcPtr));
                continue;
            }
    
            /* Make sure the recordType is in native order before using it. */
            if (direction == kSwapBTNodeBigToHost)
            	srcPtr[0] = SWAP_BE16 (srcPtr[0]);
            
            if (srcPtr[0] == kHFSFolderRecord) {
                HFSCatalogFolder *srcRec = (HFSCatalogFolder *)srcPtr;
                if ((char *)srcRec + sizeof(*srcRec) > nextRecord) {
					if (direction == kSwapBTNodeHostToBig) {
						panic("hfs_swap_HFSBTInternalNode: catalog folder record #%d too big\n", srcDesc->numRecords-i-1);
					} else {
						printf("hfs_swap_HFSBTInternalNode: catalog folder record #%d too big\n", srcDesc->numRecords-i-1);
					}
					return fsBTInvalidNodeErr;
                }
                
                srcRec->flags				= SWAP_BE16 (srcRec->flags);
                srcRec->valence				= SWAP_BE16 (srcRec->valence);
                
                srcRec->folderID			= SWAP_BE32 (srcRec->folderID);
                srcRec->createDate			= SWAP_BE32 (srcRec->createDate);
                srcRec->modifyDate			= SWAP_BE32 (srcRec->modifyDate);
                srcRec->backupDate			= SWAP_BE32 (srcRec->backupDate);
    
                /* Don't swap srcRec->userInfo */
                /* Don't swap srcRec->finderInfo */
                /* Don't swap resserved array */
    
            } else if (srcPtr[0] == kHFSFileRecord) {
                HFSCatalogFile *srcRec = (HFSCatalogFile *)srcPtr;
                if ((char *)srcRec + sizeof(*srcRec) > nextRecord) {
					if (direction == kSwapBTNodeHostToBig) {
						panic("hfs_swap_HFSBTInternalNode: catalog file record #%d too big\n", srcDesc->numRecords-i-1);
					} else {
						printf("hfs_swap_HFSBTInternalNode: catalog file record #%d too big\n", srcDesc->numRecords-i-1);
					}
					return fsBTInvalidNodeErr;
                }
                
                srcRec->flags				= srcRec->flags;
                srcRec->fileType			= srcRec->fileType;
    
                /* Don't swap srcRec->userInfo */
    
                srcRec->fileID				= SWAP_BE32 (srcRec->fileID);
                
                srcRec->dataStartBlock		= SWAP_BE16 (srcRec->dataStartBlock);
                srcRec->dataLogicalSize		= SWAP_BE32 (srcRec->dataLogicalSize);
                srcRec->dataPhysicalSize	= SWAP_BE32 (srcRec->dataPhysicalSize);
                
                srcRec->rsrcStartBlock		= SWAP_BE16 (srcRec->rsrcStartBlock);
                srcRec->rsrcLogicalSize		= SWAP_BE32 (srcRec->rsrcLogicalSize);
                srcRec->rsrcPhysicalSize	= SWAP_BE32 (srcRec->rsrcPhysicalSize);
                
                srcRec->createDate			= SWAP_BE32 (srcRec->createDate);
                srcRec->modifyDate			= SWAP_BE32 (srcRec->modifyDate);
                srcRec->backupDate			= SWAP_BE32 (srcRec->backupDate);
    
                /* Don't swap srcRec->finderInfo */
    
                srcRec->clumpSize			= SWAP_BE16 (srcRec->clumpSize);
                
                /* Swap the two sets of extents as an array of six (three each) u_int16_t */
                for (j = 0; j < kHFSExtentDensity * 2; j++) {
                    srcRec->dataExtents[j].startBlock	= SWAP_BE16 (srcRec->dataExtents[j].startBlock);
                    srcRec->dataExtents[j].blockCount	= SWAP_BE16 (srcRec->dataExtents[j].blockCount);
                }
    
                /* Don't swap srcRec->reserved */
                
            } else if ((srcPtr[0] == kHFSFolderThreadRecord) ||
                    (srcPtr[0] == kHFSFileThreadRecord)) {
                HFSCatalogThread *srcRec = (HFSCatalogThread *)srcPtr;
                
                /* Make sure there is room for parentID and name length */
                if ((char *) &srcRec->nodeName[1] > nextRecord) {
					if (direction == kSwapBTNodeHostToBig) {
						panic("hfs_swap_HFSBTInternalNode: catalog thread record #%d too big\n", srcDesc->numRecords-i-1);
					} else {
						printf("hfs_swap_HFSBTInternalNode: catalog thread record #%d too big\n", srcDesc->numRecords-i-1);
					}
					return fsBTInvalidNodeErr;
                }
    
                /* Don't swap srcRec->reserved array */
    
                srcRec->parentID			= SWAP_BE32 (srcRec->parentID);
    
                /* Don't swap srcRec->nodeName */
                
    			/* Make sure there is room for the name in the buffer */
                if ((char *) &srcRec->nodeName[srcRec->nodeName[0]] > nextRecord) {
					if (direction == kSwapBTNodeHostToBig) {
						panic("hfs_swap_HFSBTInternalNode: catalog thread record #%d name too big\n", srcDesc->numRecords-i-1);
					} else {
						printf("hfs_swap_HFSBTInternalNode: catalog thread record #%d name too big\n", srcDesc->numRecords-i-1);
					}
					return fsBTInvalidNodeErr;
                }
            } else {
				if (direction == kSwapBTNodeHostToBig) {
            		panic("hfs_swap_HFSBTInternalNode: unrecognized catalog record type (0x%04X; record #%d)\n", srcPtr[0], srcDesc->numRecords-i-1);
				} else {
            		printf("hfs_swap_HFSBTInternalNode: unrecognized catalog record type (0x%04X; record #%d)\n", srcPtr[0], srcDesc->numRecords-i-1);
				}
				return fsBTInvalidNodeErr;
            }
    
            /* We can swap the record type now that we're done using it */
            if (direction == kSwapBTNodeHostToBig)
            	srcPtr[0] = SWAP_BE16 (srcPtr[0]);
        }
        
    } else {
        panic ("hfs_swap_HFSBTInternalNode: fileID %u is not a system B-tree\n", fileID);
    }

    return (0);
}
#endif

