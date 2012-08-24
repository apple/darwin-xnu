/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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
	File:		VolumeAllocation.c

	Contains:	Routines for accessing and modifying the volume bitmap.

	Version:	HFS Plus 1.0

	Copyright:	� 1996-2009 by Apple Computer, Inc., all rights reserved.

*/

/*
Public routines:
	BlockAllocate
					Allocate space on a volume.  Can allocate space contiguously.
					If not contiguous, then allocation may be less than what was
					asked for.  Returns the starting block number, and number of
					blocks.  (Will only do a single extent???)
	BlockDeallocate
					Deallocate a contiguous run of allocation blocks.
 
	BlockMarkAllocated
					Exported wrapper to mark blocks as in-use.  This will correctly determine
					whether or not the red-black tree is enabled and call the appropriate function 
					if applicable.
	BlockMarkFree
					Exported wrapper to mark blocks as freed.  This will correctly determine whether or
					not the red-black tree is enabled and call the appropriate function if applicable.

 
	ResetVCBFreeExtCache
					Since the red-black tree obviates the need to maintain the free extent cache, we do
					not update it if the tree is also live.  As a result, if we ever need to destroy the trees
					we should reset the free extent cache so it doesn't confuse us when we need to fall back to the
					bitmap scanning allocator.
					We also reset and disable the free extent cache when volume resizing is 
					in flight.
 
	UpdateAllocLimit 
					Adjusts the AllocLimit field in the hfs mount point.  This is used when we need to prevent
					allocations from occupying space in the region we are modifying during a filesystem resize.  
					At other times, it should be consistent with the total number of allocation blocks in the 
					filesystem.  It is also used to shrink or grow the number of blocks that the red-black tree should
					know about. If growing, scan the new range of bitmap, and if shrinking, reduce the
					number of items in the tree that we can allocate from.

	UnmapBlocks	
					Issues DKIOCUNMAPs to the device as it fills the internal volume buffer when iterating
					the volume bitmap.
 
Internal routines:
	Note that the RBTree routines are guarded by a cpp check for CONFIG_HFS_ALLOC_RBTREE.  This
	is to cut down on space for functions that could not possibly be used if they are not planning to 
	use the red-black tree code.
 
	BlockMarkFreeRBTree
					Make an internal call to BlockMarkFree and then update 
					and/or create Red-Black Tree allocation tree nodes to correspond
					to the free space being generated.
	BlockMarkFreeInternal
					Mark a contiguous range of blocks as free.  The corresponding
					bits in the volume bitmap will be cleared.  This will actually do the work
					of modifying the bitmap for us.
					
	BlockMarkAllocatedRBTree
					Make an internal call to BlockAllocateMarked, which will update the 
					bitmap on-disk when we allocate blocks.  If that is successful, then
					we'll remove the appropriate entries from the red-black tree.
	BlockMarkAllocatedInternal
					Mark a contiguous range of blocks as allocated.  The cor-
					responding bits in the volume bitmap are set.  Also tests to see
					if any of the blocks were previously unallocated.  
	BlockFindContiguous
					Find a contiguous range of blocks of a given size.  The caller
					specifies where to begin the search (by block number).  The
					block number of the first block in the range is returned.  This is only
					called by the bitmap scanning logic as the red-black tree should be able
					to do this internally by searching its tree. 
	BlockAllocateAny
					Find and allocate a contiguous range of blocks up to a given size.  The
					first range of contiguous free blocks found are allocated, even if there
					are fewer blocks than requested (and even if a contiguous range of blocks
					of the given size exists elsewhere).
	BlockAllocateAnyBitmap
					Finds a range of blocks per the above requirements without using the 
					Allocation RB Tree.  This relies on the bitmap-scanning logic in order to find
					any valid range of free space needed.
	BlockAllocateAnyRBTree
					Finds a valid range of blocks per the above requirements by searching
					the red-black tree.  We can just make an internal call to 
					BlockAllocateContigRBTree to find the valid range.
	BlockAllocateContig
					Find and allocate a contiguous range of blocks of a given size.  If
					a contiguous range of free blocks of the given size isn't found, then
					the allocation fails (i.e. it is "all or nothing").  This routine is
					essentially a wrapper function around its related sub-functions,
					BlockAllocateContigBitmap and BlockAllocateContigRBTree, which use,
					respectively, the original HFS+ bitmap scanning logic and the new 
					Red-Black Tree to search and manage free-space decisions.  This function
					contains logic for when to use which of the allocation algorithms,
					depending on the free space contained in the volume.
	BlockAllocateContigBitmap
					Finds and allocates a range of blocks specified by the size parameters
					using the original HFS+ bitmap scanning logic.  The red-black tree
					will not be updated if this function is used.  
	BlockAllocateContigRBTree
					Finds and allocates a range of blocks specified by the size parameters
					using the new red/black tree data structure and search algorithms
					provided by the tree library.  Updates the red/black tree nodes after
					the on-disk data structure (bitmap) has been updated. 
	BlockAllocateKnown
					Try to allocate space from known free space in the volume's
					free extent cache.

	ReadBitmapBlock
					Given an allocation block number, read the bitmap block that
					contains that allocation block into a caller-supplied buffer.

	ReleaseBitmapBlock
					Release a bitmap block back into the buffer cache.
	
	remove_free_extent_cache
					Remove an extent from the free extent cache.  Handles overlaps
					with multiple extents in the cache, and handles splitting an
					extent in the cache if the extent to be removed is in the middle
					of a cached extent.
	
	add_free_extent_cache
					Add an extent to the free extent cache.  It will merge the
					input extent with extents already in the cache.
 
 
Debug/Test Routines
	hfs_isallocated
					Test to see if any blocks in a range are allocated.  Journal or
					allocation file lock must be held.
 
	hfs_isallocated_scan
					Test to see if any blocks in a range are allocated.  Releases and
					invalidates the block used when finished.
	
	hfs_isrbtree_active
					Test to see if the allocation red-black tree is live.  This function
					requires either an exclusive or shared lock on the allocation bitmap file
					in the HFS mount structure, to prevent red-black tree pointers from disappearing.
 
	hfs_isrbtree_allocated
					Test to see if the specified extent is marked as allocated in the red-black tree.
					Multiplexes between the metadata zone trees and the normal allocation zone trees
					depending on the offset of the extent specified.
					
	check_rbtree_extents
					Void function that wraps around the above function (hfs_isrbtree_allocated)
					and checks to see that the return value was appropriate based on the assertion we're
					trying to validate (whether or not the specified extent should be marked as free 
					or allocated).
	
	hfs_validate_rbtree
					Exhaustive search function that will check every allocation block for its status in the
					red-black tree and then check the corresponding status in the bitmap file.  If the two are out
					of sync, it will panic.  Note that this function is extremely expensive and must NEVER
					be run outside of debug code.
 
	hfs_checktreelinks
					Checks the embedded linked list structure of the red black tree for integrity.  The next pointer
					should always point to whatever extent_tree_offset_next returns.
 
 
Red Black Tree Specific Routines
	GenerateTree
					Build a red-black tree for the given filesystem's bitmap.
 
	DestroyTrees
					Destroy the tree on the given filesystem 


	hfs_alloc_scan_block
					Given a starting allocation block number, figures out which physical block contains that 
					allocation block's bit, and scans it from the starting bit until either the ending bit or
					the end of the block.  Free space extents are inserted into the appropriate red-black tree.
					
*/

#include "../../hfs_macos_defs.h"

#include <sys/types.h>
#include <sys/buf.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/disk.h>
#include <sys/ubc.h>
#include <sys/uio.h>
#include <kern/kalloc.h>
/* For VM Page size */
#include <libkern/libkern.h>

#include "../../hfs.h"
#include "../../hfs_dbg.h"
#include "../../hfs_format.h"
#include "../../hfs_endian.h"
#include "../../hfs_macos_defs.h"
#include "../headers/FileMgrInternal.h"
#include "../headers/HybridAllocator.h"
#include "../../hfs_kdebug.h"

/* Headers for unmap-on-mount support */
#include <vfs/vfs_journal.h>
#include <sys/disk.h>

#ifndef CONFIG_HFS_TRIM
#define CONFIG_HFS_TRIM 0
#endif

/*
 * Use sysctl vfs.generic.hfs.kdebug.allocation to control which
 * KERNEL_DEBUG_CONSTANT events are enabled at runtime.  (They're
 * disabled by default because there can be a lot of these events,
 * and we don't want to overwhelm the kernel debug buffer.  If you
 * want to watch these events in particular, just set the sysctl.)
 */
static int hfs_kdebug_allocation = 0;
SYSCTL_DECL(_vfs_generic);
SYSCTL_NODE(_vfs_generic, OID_AUTO, hfs, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "HFS file system");
SYSCTL_NODE(_vfs_generic_hfs, OID_AUTO, kdebug, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "HFS kdebug");
SYSCTL_INT(_vfs_generic_hfs_kdebug, OID_AUTO, allocation, CTLFLAG_RW|CTLFLAG_LOCKED, &hfs_kdebug_allocation, 0, "Enable kdebug logging for HFS allocations");
enum {
	/*
	 * HFSDBG_ALLOC_ENABLED: Log calls to BlockAllocate and
	 * BlockDeallocate, including the internal BlockAllocateXxx
	 * routines so we can see how an allocation was satisfied.
	 *
	 * HFSDBG_EXT_CACHE_ENABLED: Log routines that read or write the
	 * free extent cache.
	 *
	 * HFSDBG_UNMAP_ENABLED: Log events involving the trim list.
	 *
	 * HFSDBG_BITMAP_ENABLED: Log accesses to the volume bitmap (setting
	 * or clearing bits, scanning the bitmap).
	 */
	HFSDBG_ALLOC_ENABLED		= 1,
	HFSDBG_EXT_CACHE_ENABLED	= 2,
	HFSDBG_UNMAP_ENABLED		= 4,
	HFSDBG_BITMAP_ENABLED		= 8
};

enum {
	kBytesPerWord			=	4,
	kBitsPerByte			=	8,
	kBitsPerWord			=	32,

	kBitsWithinWordMask		=	kBitsPerWord-1
};

#define kLowBitInWordMask	0x00000001ul
#define kHighBitInWordMask	0x80000000ul
#define kAllBitsSetInWord	0xFFFFFFFFul


#define ALLOC_DEBUG 0

static OSErr ReadBitmapBlock(
	ExtendedVCB		*vcb,
	u_int32_t		bit,
	u_int32_t		**buffer,
	uintptr_t		*blockRef);

static OSErr ReleaseBitmapBlock(
	ExtendedVCB		*vcb,
	uintptr_t		blockRef,
	Boolean			dirty);

static OSErr BlockAllocateAny(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		endingBlock,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks);

static OSErr BlockAllocateAnyBitmap(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		endingBlock,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks);

static OSErr BlockAllocateContig(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		minBlocks,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks);

static OSErr BlockAllocateContigBitmap(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		minBlocks,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks);

static OSErr BlockFindContiguous(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		endingBlock,
	u_int32_t		minBlocks,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks);

static OSErr BlockAllocateKnown(
	ExtendedVCB		*vcb,
	u_int32_t		maxBlocks,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks);

static OSErr BlockMarkAllocatedInternal (
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	register u_int32_t	numBlocks);

static OSErr BlockMarkFreeInternal(
	ExtendedVCB	*vcb,
	u_int32_t	startingBlock,
	u_int32_t	numBlocks, 
	Boolean 	do_validate);


static OSErr ReleaseScanBitmapBlock( struct buf *bp );

static int hfs_track_unmap_blocks (struct hfsmount *hfsmp, u_int32_t offset, 
                             u_int32_t numBlocks, struct jnl_trim_list *list);

static int hfs_issue_unmap (struct hfsmount *hfsmp, struct jnl_trim_list *list);

static int hfs_alloc_scan_block(struct hfsmount *hfsmp, 
								u_int32_t startbit, 
								u_int32_t endBit, 
								u_int32_t *bitToScan,
                                struct jnl_trim_list *list);

int hfs_isallocated_scan (struct hfsmount *hfsmp,
								 u_int32_t startingBlock,
								 u_int32_t *bp_buf);

#if CONFIG_HFS_ALLOC_RBTREE
static OSErr BlockAllocateAnyRBTree(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks);

static OSErr BlockAllocateContigRBTree(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		minBlocks,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks,
	u_int32_t 		forceContig);

static OSErr BlockMarkAllocatedRBTree(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t	numBlocks);
	
static OSErr BlockMarkFreeRBTree(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t	numBlocks);

static int
hfs_isrbtree_allocated (struct hfsmount * hfsmp, 
	u_int32_t startBlock, 
	u_int32_t numBlocks,
	extent_node_t** node1);

extern void
hfs_validate_rbtree (struct hfsmount *hfsmp, 
					 u_int32_t start, 
					 u_int32_t end);

static void hfs_checktreelinks (struct hfsmount *hfsmp);


void check_rbtree_extents (struct hfsmount *hfsmp,
	u_int32_t start,
	u_int32_t numBlocks,
	int shouldBeFree);

#define ASSERT_FREE 1
#define ASSERT_ALLOC 0
								
#endif /* CONFIG_HFS_ALLOC_RBTREE */

/* Functions for manipulating free extent cache */
static void remove_free_extent_cache(struct hfsmount *hfsmp, u_int32_t startBlock, u_int32_t blockCount);
static Boolean add_free_extent_cache(struct hfsmount *hfsmp, u_int32_t startBlock, u_int32_t blockCount);
static void sanity_check_free_ext(struct hfsmount *hfsmp, int check_allocated);

#if ALLOC_DEBUG
/*
 * Validation Routine to verify that the TRIM list maintained by the journal
 * is in good shape relative to what we think the bitmap should have.  We should
 * never encounter allocated blocks in the TRIM list, so if we ever encounter them,
 * we panic.  
 */
int trim_validate_bitmap (struct hfsmount *hfsmp);
int trim_validate_bitmap (struct hfsmount *hfsmp) {
	u_int64_t blockno_offset;
	u_int64_t numblocks;
	int i;
	int count;
	u_int32_t startblk;
	u_int32_t blks;
	int err = 0;
	uint32_t alloccount = 0;

	if (hfsmp->jnl) {
		struct journal *jnl = (struct journal*)hfsmp->jnl;
		if (jnl->active_tr) {
			struct jnl_trim_list *trim = &(jnl->active_tr->trim);
			count = trim->extent_count;
			for (i = 0; i < count; i++) {
				blockno_offset = trim->extents[i].offset;
				blockno_offset = blockno_offset - (uint64_t)hfsmp->hfsPlusIOPosOffset;
				blockno_offset = blockno_offset / hfsmp->blockSize;
				numblocks = trim->extents[i].length / hfsmp->blockSize;

				startblk = (u_int32_t)blockno_offset;
				blks = (u_int32_t) numblocks;
				err = hfs_count_allocated (hfsmp, startblk, blks, &alloccount);

				if (err == 0 && alloccount != 0) {
					panic ("trim_validate_bitmap: %d blocks @ ABN %d are allocated!", alloccount, startblk);
				}
			}
		}
	}
	return 0;
}

#endif


/*
 ;________________________________________________________________________________
 ;
 ; Routine:		hfs_unmap_free_extent
 ;
 ; Function:		Make note of a range of allocation blocks that should be
 ;				unmapped (trimmed).  That is, the given range of blocks no
 ;				longer have useful content, and the device can unmap the
 ;				previous contents.  For example, a solid state disk may reuse
 ;				the underlying storage for other blocks.
 ;
 ;				This routine is only supported for journaled volumes.  The extent
 ;				being freed is passed to the journal code, and the extent will
 ;				be unmapped after the current transaction is written to disk.
 ;
 ; Input Arguments:
 ;	hfsmp			- The volume containing the allocation blocks.
 ;	startingBlock	- The first allocation block of the extent being freed.
 ;	numBlocks		- The number of allocation blocks of the extent being freed.
 ;________________________________________________________________________________
 */
static void hfs_unmap_free_extent(struct hfsmount *hfsmp, u_int32_t startingBlock, u_int32_t numBlocks)
{
	u_int64_t offset;
	u_int64_t length;
	u_int64_t device_sz;
	int err = 0;
			
	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_FREE | DBG_FUNC_START, startingBlock, numBlocks, 0, 0, 0);
	
	if (ALLOC_DEBUG) {
		if (hfs_isallocated(hfsmp, startingBlock, numBlocks)) {
			panic("hfs: %p: (%u,%u) unmapping allocated blocks", hfsmp, startingBlock, numBlocks);
		}
	}
	
	if (hfsmp->jnl != NULL) {
		device_sz = hfsmp->hfs_logical_bytes;
		offset = (u_int64_t) startingBlock * hfsmp->blockSize + (u_int64_t) hfsmp->hfsPlusIOPosOffset;
		length = (u_int64_t) numBlocks * hfsmp->blockSize;

		/* Validate that the trim is in a valid range of bytes */
		if ((offset >= device_sz) || ((offset + length) > device_sz)) {
			printf("hfs_unmap_free_ext: ignoring trim @ off %lld len %lld \n", offset, length);
			err = EINVAL;
		}

		if (err == 0) {
			err = journal_trim_add_extent(hfsmp->jnl, offset, length);
			if (err) {
				printf("hfs_unmap_free_extent: error %d from journal_trim_add_extent", err);
			}
		}
	}
	
	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_FREE | DBG_FUNC_END, err, 0, 0, 0, 0);
}



/*
 ;________________________________________________________________________________
 ;
 ; Routine:		hfs_track_unmap_blocks
 ;
 ; Function:	Make note of a range of allocation blocks that should be
 ;				unmapped (trimmed).  That is, the given range of blocks no
 ;				longer have useful content, and the device can unmap the
 ;				previous contents.  For example, a solid state disk may reuse
 ;				the underlying storage for other blocks.
 ;
 ;				This routine is only supported for journaled volumes.  
 ; 
 ;              *****NOTE*****: 
 ;              This function should *NOT* be used when the volume is fully 
 ;              mounted.  This function is intended to support a bitmap iteration
 ;              at mount time to fully inform the SSD driver of the state of all blocks
 ;              at mount time, and assumes that there is no allocation/deallocation
 ;              interference during its iteration.,
 ;
 ; Input Arguments:
 ;	hfsmp			- The volume containing the allocation blocks.
 ;	offset          - The first allocation block of the extent being freed.
 ;	numBlocks		- The number of allocation blocks of the extent being freed.
 ;  list            - The list of currently tracked trim ranges.
 ;________________________________________________________________________________
 */
static int hfs_track_unmap_blocks (struct hfsmount *hfsmp, u_int32_t start, 
                              u_int32_t numBlocks, struct jnl_trim_list *list) {
    
    u_int64_t offset;
    u_int64_t length;
    int error = 0;
    
    if ((hfsmp->hfs_flags & HFS_UNMAP) && (hfsmp->jnl != NULL)) {
        int extent_no = list->extent_count;
        offset = (u_int64_t) start * hfsmp->blockSize + (u_int64_t) hfsmp->hfsPlusIOPosOffset;
        length = (u_int64_t) numBlocks * hfsmp->blockSize;
        
        
        list->extents[extent_no].offset = offset;
        list->extents[extent_no].length = length;
        list->extent_count++;
        if (list->extent_count == list->allocated_count) {
            error = hfs_issue_unmap (hfsmp, list);
        }
    }

    return error;
}

/*
 ;________________________________________________________________________________
 ;
 ; Routine:		hfs_issue_unmap
 ;
 ; Function:	Issue a DKIOCUNMAP for all blocks currently tracked by the jnl_trim_list
 ;
 ; Input Arguments:
 ;	hfsmp			- The volume containing the allocation blocks.
 ;  list            - The list of currently tracked trim ranges.
 ;________________________________________________________________________________
 */

static int hfs_issue_unmap (struct hfsmount *hfsmp, struct jnl_trim_list *list) {
    dk_unmap_t unmap;
    int error = 0;
    
    if (list->extent_count > 0) {
        bzero(&unmap, sizeof(unmap));
        unmap.extents = list->extents;
        unmap.extentsCount = list->extent_count;
        
        /* Issue a TRIM and flush them out */
        error = VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCUNMAP, (caddr_t)&unmap, 0, vfs_context_kernel());
        
        bzero (list->extents, (list->allocated_count * sizeof(dk_extent_t)));
        list->extent_count = 0;
    }
    return error;
}



/*
 ;________________________________________________________________________________
 ;
 ; Routine:		hfs_unmap_alloc_extent
 ;
 ; Function:		Make note of a range of allocation blocks, some of
 ;				which may have previously been passed to hfs_unmap_free_extent,
 ;				is now in use on the volume.  The given blocks will be removed
 ;				from any pending DKIOCUNMAP.
 ;
 ; Input Arguments:
 ;	hfsmp			- The volume containing the allocation blocks.
 ;	startingBlock	- The first allocation block of the extent being allocated.
 ;	numBlocks		- The number of allocation blocks being allocated.
 ;________________________________________________________________________________
 */
static void hfs_unmap_alloc_extent(struct hfsmount *hfsmp, u_int32_t startingBlock, u_int32_t numBlocks)
{
	u_int64_t offset;
	u_int64_t length;
	int err;
	
	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_ALLOC | DBG_FUNC_START, startingBlock, numBlocks, 0, 0, 0);
	
	if (hfsmp->jnl != NULL) {
		offset = (u_int64_t) startingBlock * hfsmp->blockSize + (u_int64_t) hfsmp->hfsPlusIOPosOffset;
		length = (u_int64_t) numBlocks * hfsmp->blockSize;
		
		err = journal_trim_remove_extent(hfsmp->jnl, offset, length);
		if (err) {
			printf("hfs_unmap_alloc_extent: error %d from journal_trim_remove_extent", err);
		}
	}
	
	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_ALLOC | DBG_FUNC_END, err, 0, 0, 0, 0);
}


/*
;________________________________________________________________________________
;
; Routine:		hfs_trim_callback
;
; Function:		This function is called when a transaction that freed extents
;				(via hfs_unmap_free_extent/journal_trim_add_extent) has been
;				written to the on-disk journal.  This routine will add those
;				extents to the free extent cache so that they can be reused.
;
;				CAUTION: This routine is called while the journal's trim lock
;				is held shared, so that no other thread can reuse any portion
;				of those extents.  We must be very careful about which locks
;				we take from within this callback, to avoid deadlock.  The
;				call to add_free_extent_cache will end up taking the cache's
;				lock (just long enough to add these extents to the cache).
;
;				CAUTION: If the journal becomes invalid (eg., due to an I/O
;				error when trying to write to the journal), this callback
;				will stop getting called, even if extents got freed before
;				the journal became invalid!
;
; Input Arguments:
;	arg				- The hfsmount of the volume containing the extents.
;	extent_count	- The number of extents freed in the transaction.
;	extents			- An array of extents (byte ranges) that were freed.
;________________________________________________________________________________
*/
__private_extern__ void
hfs_trim_callback(void *arg, uint32_t extent_count, const dk_extent_t *extents)
{
	uint32_t i;
	uint32_t startBlock, numBlocks;
	struct hfsmount *hfsmp = arg;
	
	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_CALLBACK | DBG_FUNC_START, 0, extent_count, 0, 0, 0);
	
	for (i=0; i<extent_count; ++i) {
		/* Convert the byte range in *extents back to a range of allocation blocks. */
		startBlock = (extents[i].offset - hfsmp->hfsPlusIOPosOffset) / hfsmp->blockSize;
		numBlocks = extents[i].length / hfsmp->blockSize;
		(void) add_free_extent_cache(hfsmp, startBlock, numBlocks);
	}

	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_CALLBACK | DBG_FUNC_END, 0, 0, 0, 0, 0);
}


/*
 ;________________________________________________________________________________
 ;
 ; Routine:		UnmapBlocks
 ;
 ; Function:	Traverse the bitmap, and issue DKIOCUNMAPs to the underlying
 ;				device as needed so that the underlying disk device is as
 ;				up-to-date as possible with which blocks are unmapped.
 ;
 ; Input Arguments:
 ;	hfsmp			- The volume containing the allocation blocks.
 ;________________________________________________________________________________
 */

__private_extern__
u_int32_t UnmapBlocks (struct hfsmount *hfsmp) {
	u_int32_t blocks_scanned = 0;
	int error = 0;
    struct jnl_trim_list trimlist;
    
    /*
     *struct jnl_trim_list {
     uint32_t    allocated_count;
     uint32_t    extent_count;
     dk_extent_t *extents;
     };
    */
    bzero (&trimlist, sizeof(trimlist));
    if (CONFIG_HFS_TRIM) {
        int alloc_count = PAGE_SIZE / sizeof(dk_extent_t);
        void *extents = kalloc (alloc_count * sizeof(dk_extent_t));
        if (extents == NULL) {
            return ENOMEM;
        }
        trimlist.extents = (dk_extent_t*)extents;
        trimlist.allocated_count = alloc_count;
        trimlist.extent_count = 0;
        
        
        
        while ((blocks_scanned < hfsmp->totalBlocks) && (error == 0)){
            error = hfs_alloc_scan_block (hfsmp, blocks_scanned, hfsmp->totalBlocks, 
                                          &blocks_scanned, &trimlist);
            if (error) {
                printf("HFS: bitmap unmap scan error: %d\n", error);
                break;
            }
        }
        if (error == 0) {
            hfs_issue_unmap(hfsmp, &trimlist);
        }
        if (trimlist.extents) {
            kfree (trimlist.extents, (trimlist.allocated_count * sizeof(dk_extent_t)));
        }
	}
	return error;
}

/*
 ;________________________________________________________________________________
 ;
 ; Routine:	   BlockAllocate
 ;
 ; Function:   Allocate space on a volume.	If contiguous allocation is requested,
 ;			   at least the requested number of bytes will be allocated or an
 ;			   error will be returned.	If contiguous allocation is not forced,
 ;			   the space will be allocated with the first largest extent available 
 ;			   at the requested starting allocation block.  If there is not enough
 ;			   room there, a block allocation of less than the requested size will be
 ;			   allocated.
 ;
 ;			   If the requested starting block is 0 (for new file allocations),
 ;			   the volume's allocation block pointer will be used as a starting
 ;			   point.
 ;
 ; Input Arguments:
 ;	 vcb			 - Pointer to ExtendedVCB for the volume to allocate space on
 ;	 fcb			 - Pointer to FCB for the file for which storage is being allocated
 ;	 startingBlock	 - Preferred starting allocation block, 0 = no preference
 ;	 minBlocks	 	 - Number of blocks requested.	If the allocation is non-contiguous,
 ;					   less than this may actually be allocated
 ;	 maxBlocks	 	 - The maximum number of blocks to allocate.  If there is additional free
 ;					   space after bytesRequested, then up to maxBlocks bytes should really
 ;					   be allocated.  (Used by ExtendFileC to round up allocations to a multiple
 ;					   of the file's clump size.)
 ;	 flags           - Flags to specify options like contiguous, use metadata zone, 
 ;					   skip free block check, etc.
 ;
 ; Output:
 ;	 (result)		 - Error code, zero for successful allocation
 ;	 *startBlock	 - Actual starting allocation block
 ;	 *actualBlocks	 - Actual number of allocation blocks allocated
 ;
 ; Side effects:
 ;	 The volume bitmap is read and updated; the volume bitmap cache may be changed.
 ;________________________________________________________________________________
 */
OSErr BlockAllocate (
	ExtendedVCB		*vcb,				/* which volume to allocate space on */
	u_int32_t		startingBlock,		/* preferred starting block, or 0 for no preference */
	u_int32_t		minBlocks,		/* desired number of blocks to allocate */
	u_int32_t		maxBlocks,		/* maximum number of blocks to allocate */
	u_int32_t		flags,			/* option flags */
	u_int32_t		*actualStartBlock,	/* actual first block of allocation */
	u_int32_t		*actualNumBlocks)	/* number of blocks actually allocated; if forceContiguous */
							/* was zero, then this may represent fewer than minBlocks */
{
	u_int32_t  freeBlocks;
	OSErr			err;
	Boolean			updateAllocPtr = false;		//	true if nextAllocation needs to be updated
	struct hfsmount	*hfsmp;
	Boolean useMetaZone;
	Boolean forceContiguous;

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_BLOCK_ALLOCATE | DBG_FUNC_START, startingBlock, minBlocks, maxBlocks, flags, 0);
	
	if (flags & HFS_ALLOC_FORCECONTIG) {
		forceContiguous = true;
	} else {
		forceContiguous = false;
	}

	if (flags & HFS_ALLOC_METAZONE) {
		useMetaZone = true;
	} else {
		useMetaZone = false;
	}

	//TODO: Figure out when we need to re-enable the RB-Tree. 
	
	
	//TODO: Make sure we use allocLimit when appropriate.
	
	/*
	 * TODO: Update BlockAllocate and its sub-functions to do cooperative allocation and bitmap scanning
	 * in conjunction with the Generate Tree function.   If the red-black tree does not currently contain
	 * an allocation block of appropriate size, then start scanning blocks FOR the tree generation function until
	 * we find what we need.  We'll update the tree fields when we're done, indicating that we've advanced the
	 * high water mark for the tree.  
	 */
	
	//
	//	Initialize outputs in case we get an error
	//
	*actualStartBlock = 0;
	*actualNumBlocks = 0;
	hfsmp = VCBTOHFS (vcb);
	freeBlocks = hfs_freeblks(hfsmp, 0);
	
	
	/* Skip free block check if blocks are being allocated for relocating 
	 * data during truncating a volume.
	 * 
	 * During hfs_truncatefs(), the volume free block count is updated 
	 * before relocating data to reflect the total number of free blocks 
	 * that will exist on the volume after resize is successful.  This 
	 * means that we have reserved allocation blocks required for relocating 
	 * the data and hence there is no need to check the free blocks.
	 * It will also prevent resize failure when the number of blocks in 
	 * an extent being relocated is more than the free blocks that will 
	 * exist after the volume is resized.
	 */
	if ((flags & HFS_ALLOC_SKIPFREEBLKS) == 0) {
		//	If the disk is already full, don't bother.
		if (freeBlocks == 0) {
			err = dskFulErr;
			goto Exit;
		}
		if (forceContiguous && freeBlocks < minBlocks) {
			err = dskFulErr;
			goto Exit;
		}

		/*
		 * Clip if necessary so we don't over-subscribe the free blocks.
		 */
		if (minBlocks > freeBlocks) {
			minBlocks = freeBlocks;
		}
		if (maxBlocks > freeBlocks) {
			maxBlocks = freeBlocks;
		}
	}

	//
	//	If caller didn't specify a starting block number, then use the volume's
	//	next block to allocate from.
	//
	if (startingBlock == 0) {
		HFS_MOUNT_LOCK(vcb, TRUE);
		
		/* Sparse Allocation and nextAllocation are both used even if the R/B Tree is on */
		if (vcb->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
			startingBlock = vcb->sparseAllocation;
		} 
		else {
			startingBlock = vcb->nextAllocation;
		}
		HFS_MOUNT_UNLOCK(vcb, TRUE);
		updateAllocPtr = true;
	}
	
	
	if (startingBlock >= vcb->allocLimit) {
		startingBlock = 0; /* overflow so start at beginning */
	}

	//
	//	If the request must be contiguous, then find a sequence of free blocks
	//	that is long enough.  Otherwise, find the first free block.
	//
	if (forceContiguous) {
		err = BlockAllocateContig(vcb, startingBlock, minBlocks, maxBlocks,
		                          useMetaZone, actualStartBlock, actualNumBlocks);
		/*
		 * If we allocated from a new position then also update the roving allocator.  
		 * This will keep the roving allocation pointer up-to-date even 
		 * if we are using the new R/B tree allocator, since
		 * it doesn't matter to us here, how the underlying allocator found 
		 * the block to vend out.
		 */
		if ((err == noErr) &&
		    (*actualStartBlock > startingBlock) &&
		    ((*actualStartBlock < VCBTOHFS(vcb)->hfs_metazone_start) ||
	    	     (*actualStartBlock > VCBTOHFS(vcb)->hfs_metazone_end))) {
			updateAllocPtr = true;
		}
	} else {
#if CONFIG_HFS_ALLOC_RBTREE
		/* 
		 * If the RB-Tree Allocator is live, just go straight for a 
		 * BlockAllocateAny call and return the result.  Otherwise, 
		 * resort to the bitmap scanner.
		 */
		if (hfs_isrbtree_active(VCBTOHFS(vcb))) {
			/* Start by trying to allocate from the starting block forward */
			err = BlockAllocateAny(vcb, startingBlock, vcb->allocLimit,
								   maxBlocks, useMetaZone, actualStartBlock,
								   actualNumBlocks);
			
			/* 
			 * Because the RB-Tree is live, the previous call to BlockAllocateAny
			 * will use the rbtree variant.  As a result, it will automatically search the 
			 * metadata zone for a valid extent if needed.  If we get a return value of 
			 * noErr, we found a valid extent and we can skip to the end.  If the error indicates
			 * the disk is full, that's an equally valid return code and we can skip to the end, too.
			 */
			if (err == noErr || err == dskFulErr) {
				goto Exit; 
			}
			else {
				//TODO: only tear down tree if the tree is finished building.
				//Make sure to handle the ENOSPC condition properly.  We shouldn't error out in that case.
				/* Tear down tree if we encounter an error */
				if (hfsmp->extent_tree_flags & HFS_ALLOC_RB_ACTIVE) {
					hfsmp->extent_tree_flags |= HFS_ALLOC_RB_ERRORED;
					DestroyTrees(hfsmp);
					ResetVCBFreeExtCache(hfsmp);				
				}
				else {
					goto Exit;
				}
				// fall through to the normal allocation since the rb-tree allocation failed.
			}
		}
#endif
					
		/*
		 * Scan the bitmap once, gather the N largest free extents, then
		 * allocate from these largest extents.  Repeat as needed until
		 * we get all the space we needed.  We could probably build up
		 * that list when the higher level caller tried (and failed) a
		 * contiguous allocation first.
		 *
		 * Note that the free-extent cache will be cease to be updated if
		 * we are using the red-black tree for allocations.  If we jettison 
		 * the tree, then we will reset the free-extent cache and start over.
		 */
		
		err = BlockAllocateKnown(vcb, maxBlocks, actualStartBlock, actualNumBlocks);
		/* dskFulErr out of BlockAllocateKnown indicates an empty Free Extent Cache */

		if (err == dskFulErr) {
			/* 
			 * Now we have to do a bigger scan.  Start at startingBlock and go up until the
			 * allocation limit.
			 */
			err = BlockAllocateAny(vcb, startingBlock, vcb->allocLimit,
			                       maxBlocks, useMetaZone, actualStartBlock,
			                       actualNumBlocks);
		}
		if (err == dskFulErr) {
			/*
			 * We may be out of space in the normal zone; go up to the starting block from
			 * the start of the volume.
			 */
			err = BlockAllocateAny(vcb, 1, startingBlock, maxBlocks,
			                       useMetaZone, actualStartBlock,
			                       actualNumBlocks);
		}
	}

Exit:
	// if we actually allocated something then go update the
	// various bits of state that we maintain regardless of
	// whether there was an error (i.e. partial allocations
	// still need to update things like the free block count).
	//
	if (*actualNumBlocks != 0) {
		//
		//	If we used the volume's roving allocation pointer, then we need to update it.
		//	Adding in the length of the current allocation might reduce the next allocate
		//	call by avoiding a re-scan of the already allocated space.  However, the clump
		//	just allocated can quite conceivably end up being truncated or released when
		//	the file is closed or its EOF changed.  Leaving the allocation pointer at the
		//	start of the last allocation will avoid unnecessary fragmentation in this case.
		//
		HFS_MOUNT_LOCK(vcb, TRUE);

		lck_spin_lock(&hfsmp->vcbFreeExtLock);
		if (vcb->vcbFreeExtCnt == 0 && vcb->hfs_freed_block_count == 0) {
			vcb->sparseAllocation = *actualStartBlock;
		}
		lck_spin_unlock(&hfsmp->vcbFreeExtLock);
		if (*actualNumBlocks < vcb->hfs_freed_block_count) {
			vcb->hfs_freed_block_count -= *actualNumBlocks;
		} else {
			vcb->hfs_freed_block_count = 0;
		}

		if (updateAllocPtr &&
				((*actualStartBlock < VCBTOHFS(vcb)->hfs_metazone_start) ||
				 (*actualStartBlock > VCBTOHFS(vcb)->hfs_metazone_end))) {
			HFS_UPDATE_NEXT_ALLOCATION(vcb, *actualStartBlock);
		}

		(void) remove_free_extent_cache(hfsmp, *actualStartBlock, *actualNumBlocks);

		/* 
		 * Update the number of free blocks on the volume 
		 *
		 * Skip updating the free blocks count if the block are 
		 * being allocated to relocate data as part of hfs_truncatefs()
		 */
		if ((flags & HFS_ALLOC_SKIPFREEBLKS) == 0) {
			vcb->freeBlocks -= *actualNumBlocks;
		}
		MarkVCBDirty(vcb);
		HFS_MOUNT_UNLOCK(vcb, TRUE);

		hfs_generate_volume_notifications(VCBTOHFS(vcb));
	}
	
	if (ALLOC_DEBUG) {
		if (err == noErr) {
			if (*actualStartBlock >= hfsmp->totalBlocks) {
				panic ("BlockAllocate: vending invalid blocks!");
			}
			if (*actualStartBlock >= hfsmp->allocLimit) {
				panic ("BlockAllocate: vending block past allocLimit!");
			}
			
			if ((*actualStartBlock + *actualNumBlocks) >= hfsmp->totalBlocks) {	
				panic ("BlockAllocate: vending too many invalid blocks!");
			}
			
			if ((*actualStartBlock + *actualNumBlocks) >= hfsmp->allocLimit) {	
				panic ("BlockAllocate: vending too many invalid blocks past allocLimit!");
			}
		}
	}
	
	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_BLOCK_ALLOCATE | DBG_FUNC_END, err, *actualStartBlock, *actualNumBlocks, 0, 0);

	return err;
}


/*
;________________________________________________________________________________
;
; Routine:	   BlockDeallocate
;
; Function:    Update the bitmap to deallocate a run of disk allocation blocks
;
; Input Arguments:
;	 vcb		- Pointer to ExtendedVCB for the volume to free space on
;	 firstBlock	- First allocation block to be freed
;	 numBlocks	- Number of allocation blocks to free up (must be > 0!)
;
; Output:
;	 (result)	- Result code
;
; Side effects:
;	 The volume bitmap is read and updated; the volume bitmap cache may be changed.
;	 The Allocator's red-black trees may also be modified as a result.
;________________________________________________________________________________
*/

OSErr BlockDeallocate (
	ExtendedVCB		*vcb,			//	Which volume to deallocate space on
	u_int32_t		firstBlock,		//	First block in range to deallocate
	u_int32_t		numBlocks, 		//	Number of contiguous blocks to deallocate
	u_int32_t 		flags)
{
	OSErr			err;
	struct hfsmount *hfsmp;
	hfsmp = VCBTOHFS(vcb);
	
	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_BLOCK_DEALLOCATE | DBG_FUNC_START, firstBlock, numBlocks, flags, 0, 0);

	//
	//	If no blocks to deallocate, then exit early
	//
	if (numBlocks == 0) {
		err = noErr;
		goto Exit;
	}
	
	
	if (ALLOC_DEBUG) {
		if (firstBlock >= hfsmp->totalBlocks) {
			panic ("BlockDeallocate: freeing invalid blocks!");
		}
		
		if ((firstBlock + numBlocks) >= hfsmp->totalBlocks) {	
			panic ("BlockDeallocate: freeing too many invalid blocks!");
		}			
	}
	
	
	

	/*
	 * If we're using the red-black tree code, then try to free the
	 * blocks by marking them in the red-black tree first.  If the tree
	 * is not active for whatever reason (or we're not using the 
	 * R/B Tree code at all), then go straight for the BlockMarkFree 
	 * function. 
	 *
	 * Remember that we can get into this function if the tree isn't finished
	 * building.  In that case, check to see if the block we're de-allocating is
	 * past the high watermark
	 */
#if CONFIG_HFS_ALLOC_RBTREE
	if (hfs_isrbtree_active(VCBTOHFS(vcb))) {
		/*
		 * BlockMarkFreeRBTree deals with the case where we are resizing the
		 * filesystem (shrinking), and we need to manipulate the bitmap beyond the portion
		 * that is currenly controlled by the r/b tree.
		 */
		
		//TODO: Update multiplexing code for the half-finished case.
		err = BlockMarkFreeRBTree(vcb, firstBlock, numBlocks);
		adjustFreeExtCache = 0;
	}
	else {
		err = BlockMarkFreeInternal(vcb, firstBlock, numBlocks, true);
	}

#else
	err = BlockMarkFreeInternal(vcb, firstBlock, numBlocks, true);
#endif
	if (err)
		goto Exit;

	//
	//	Update the volume's free block count, and mark the VCB as dirty.
	//
	HFS_MOUNT_LOCK(vcb, TRUE);
	
	/* 
	 * Do not update the free block count.  This flags is specified 
	 * when a volume is being truncated.  
	 */
	if ((flags & HFS_ALLOC_SKIPFREEBLKS) == 0) {
		vcb->freeBlocks += numBlocks;
	}

	vcb->hfs_freed_block_count += numBlocks;

	if (vcb->nextAllocation == (firstBlock + numBlocks)) {
		HFS_UPDATE_NEXT_ALLOCATION(vcb, (vcb->nextAllocation - numBlocks));
	}

	if (hfsmp->jnl == NULL) {
		/*
		 * In the journal case, we'll add the free extent once the journal
		 * calls us back to tell us it wrote the transaction to disk.
		 */
		(void) add_free_extent_cache(vcb, firstBlock, numBlocks);
		
		/*
		 * If the journal case, we'll only update sparseAllocation once the
		 * free extent cache becomes empty (when we remove the last entry
		 * from the cache).  Skipping it here means we're less likely to
		 * find a recently freed extent via the bitmap before it gets added
		 * to the free extent cache.
		 */
		if (firstBlock < vcb->sparseAllocation) {
			vcb->sparseAllocation = firstBlock;
		}
	}
	
	MarkVCBDirty(vcb);
  	HFS_MOUNT_UNLOCK(vcb, TRUE); 

	hfs_generate_volume_notifications(VCBTOHFS(vcb));
Exit:

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_BLOCK_DEALLOCATE | DBG_FUNC_END, err, 0, 0, 0, 0);

	return err;
}


u_int8_t freebitcount[16] = {
	4, 3, 3, 2, 3, 2, 2, 1,  /* 0 1 2 3 4 5 6 7 */
	3, 2, 2, 1, 2, 1, 1, 0,  /* 8 9 A B C D E F */
};

u_int32_t
MetaZoneFreeBlocks(ExtendedVCB *vcb)
{
	u_int32_t freeblocks;
	u_int32_t *currCache;
	uintptr_t blockRef;
	u_int32_t bit;
	u_int32_t lastbit;
	int bytesleft;
	int bytesperblock;
	u_int8_t byte;
	u_int8_t *buffer;

	blockRef = 0;
	bytesleft = freeblocks = 0;
	buffer = NULL;
	bit = VCBTOHFS(vcb)->hfs_metazone_start;
	if (bit == 1)
		bit = 0;
	
	lastbit = VCBTOHFS(vcb)->hfs_metazone_end;
	bytesperblock = vcb->vcbVBMIOSize;

	/*
	 *  Count all the bits from bit to lastbit.
	 */
	while (bit < lastbit) {
		/*
		 *  Get next bitmap block.
		 */
		if (bytesleft == 0) {
			if (blockRef) {
				(void) ReleaseBitmapBlock(vcb, blockRef, false);
				blockRef = 0;
			}
			if (ReadBitmapBlock(vcb, bit, &currCache, &blockRef) != 0) {
				return (0);
			}
			buffer = (u_int8_t *)currCache;
			bytesleft = bytesperblock;
		}
		byte = *buffer++;
		freeblocks += freebitcount[byte & 0x0F];
		freeblocks += freebitcount[(byte >> 4) & 0x0F];
		bit += kBitsPerByte;
		--bytesleft;
	}
	if (blockRef)
		(void) ReleaseBitmapBlock(vcb, blockRef, false);

	return (freeblocks);
}


/*
 * Obtain the next allocation block (bit) that's
 * outside the metadata allocation zone.
 */
static u_int32_t NextBitmapBlock(
	ExtendedVCB		*vcb,
	u_int32_t		bit)
{
	struct  hfsmount *hfsmp = VCBTOHFS(vcb);

	if ((hfsmp->hfs_flags & HFS_METADATA_ZONE) == 0)
		return (bit);
	/*
	 * Skip over metadata allocation zone.
	 */
	if ((bit >= hfsmp->hfs_metazone_start) &&
	    (bit <= hfsmp->hfs_metazone_end)) {
		bit = hfsmp->hfs_metazone_end + 1;
	}
	return (bit);
}


/*
;_______________________________________________________________________
;
; Routine:	ReadBitmapBlock
;
; Function:	Read in a bitmap block corresponding to a given allocation
;			block (bit).  Return a pointer to the bitmap block.
;
; Inputs:
;	vcb			--	Pointer to ExtendedVCB
;	bit			--	Allocation block whose bitmap block is desired
;
; Outputs:
;	buffer		--	Pointer to bitmap block corresonding to "block"
;	blockRef
;_______________________________________________________________________
*/
static OSErr ReadBitmapBlock(
	ExtendedVCB		*vcb,
	u_int32_t		bit,
	u_int32_t		**buffer,
	uintptr_t		*blockRef)
{
	OSErr			err;
	struct buf *bp = NULL;
	struct vnode *vp = NULL;
	daddr64_t block;
	u_int32_t blockSize;

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_READ_BITMAP_BLOCK | DBG_FUNC_START, bit, 0, 0, 0, 0);

	/*
	 * volume bitmap blocks are protected by the allocation file lock
	 */
	REQUIRE_FILE_LOCK(vcb->hfs_allocation_vp, false);	

	blockSize = (u_int32_t)vcb->vcbVBMIOSize;
	block = (daddr64_t)(bit / (blockSize * kBitsPerByte));

	if (vcb->vcbSigWord == kHFSPlusSigWord) {
		vp = vcb->hfs_allocation_vp;	/* use allocation file vnode */

	} else /* hfs */ {
		vp = VCBTOHFS(vcb)->hfs_devvp;	/* use device I/O vnode */
		block += vcb->vcbVBMSt;			/* map to physical block */
	}

	err = (int)buf_meta_bread(vp, block, blockSize, NOCRED, &bp);

	if (bp) {
		if (err) {
			buf_brelse(bp);
			*blockRef = 0;
			*buffer = NULL;
		} else {
			*blockRef = (uintptr_t)bp;
			*buffer = (u_int32_t *)buf_dataptr(bp);
		}
	}

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_READ_BITMAP_BLOCK | DBG_FUNC_END, err, 0, 0, 0, 0);

	return err;
}


/*
;_______________________________________________________________________
;
; Routine:	ReleaseBitmapBlock
;
; Function:	Relase a bitmap block. 
;
; Inputs:
;	vcb
;	blockRef
;	dirty
;_______________________________________________________________________
*/
static OSErr ReleaseBitmapBlock(
	ExtendedVCB		*vcb,
	uintptr_t		blockRef,
	Boolean			dirty)
{
	struct buf *bp = (struct buf *)blockRef;
	
	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_RELEASE_BITMAP_BLOCK | DBG_FUNC_START, dirty, 0, 0, 0, 0);

	if (blockRef == 0) {
		if (dirty)
			panic("hfs: ReleaseBitmapBlock: missing bp");
		return (0);
	}

	if (bp) {
		if (dirty) {
			// XXXdbg
			struct hfsmount *hfsmp = VCBTOHFS(vcb);
			
			if (hfsmp->jnl) {
				journal_modify_block_end(hfsmp->jnl, bp, NULL, NULL);
			} else {
				buf_bdwrite(bp);
			}
		} else {
			buf_brelse(bp);
		}
	}

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_RELEASE_BITMAP_BLOCK | DBG_FUNC_END, 0, 0, 0, 0, 0);

	return (0);
}

/*
 * ReleaseScanBitmapBlock is used to release struct bufs that were 
 * created for use by bitmap scanning code.  We want to force 
 * them to be purged out of the buffer cache ASAP, so we'll release them differently
 * than in the ReleaseBitmapBlock case.  Alternately, we know that we're only reading 
 * the blocks, so we will never dirty them as part of the tree building scan.
 */

static OSErr ReleaseScanBitmapBlock(struct buf *bp ) {
	
	if (bp == NULL) {
		return (0);
	}
	
	if (bp) {
		/* Mark the buffer invalid if it isn't locked, then release it */
		if ((buf_flags(bp) & B_LOCKED) == 0) {
			buf_markinvalid(bp);
		}
		buf_brelse(bp);
	}
	
	return (0);
	
	
}

/*
_______________________________________________________________________

Routine:	BlockAllocateContig

Function:	Allocate a contiguous group of allocation blocks.  The
			allocation is all-or-nothing.  The caller guarantees that
			there are enough free blocks (though they may not be
			contiguous, in which case this call will fail).

Inputs:
	vcb				Pointer to volume where space is to be allocated
	startingBlock	Preferred first block for allocation
	minBlocks		Minimum number of contiguous blocks to allocate
	maxBlocks		Maximum number of contiguous blocks to allocate
	useMetaZone

Outputs:
	actualStartBlock	First block of range allocated, or 0 if error
	actualNumBlocks		Number of blocks allocated, or 0 if error
_______________________________________________________________________
*/
static OSErr BlockAllocateContig(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		minBlocks,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks)
{

#if CONFIG_HFS_ALLOC_RBTREE
	if (hfs_isrbtree_active(VCBTOHFS(vcb))) {
		return BlockAllocateContigRBTree(vcb, startingBlock, minBlocks, maxBlocks, useMetaZone, 
				actualStartBlock, actualNumBlocks, 1);
	}
#endif
	return BlockAllocateContigBitmap(vcb, startingBlock, minBlocks, 
			maxBlocks, useMetaZone, actualStartBlock, actualNumBlocks);	
}

/*
 * Variant of BlockAllocateContig that uses the original bitmap-searching logic
 */

static OSErr BlockAllocateContigBitmap(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		minBlocks,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks)
{
	OSErr	err;

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_CONTIG_BITMAP | DBG_FUNC_START, startingBlock, minBlocks, maxBlocks, useMetaZone, 0);

	//
	//	Find a contiguous group of blocks at least minBlocks long.
	//	Determine the number of contiguous blocks available (up
	//	to maxBlocks).
	//

	/*
	 * NOTE: If the only contiguous free extent of at least minBlocks
	 * crosses startingBlock (i.e. starts before, ends after), then we
	 * won't find it. Earlier versions *did* find this case by letting
	 * the second search look past startingBlock by minBlocks.  But
	 * with the free extent cache, this can lead to duplicate entries
	 * in the cache, causing the same blocks to be allocated twice.
	 */
	err = BlockFindContiguous(vcb, startingBlock, vcb->allocLimit, minBlocks,
	                          maxBlocks, useMetaZone, actualStartBlock, actualNumBlocks);
	if (err == dskFulErr && startingBlock != 0) {
		/*
		 * Constrain the endingBlock so we don't bother looking for ranges
		 * that would overlap those found in the previous call.
		 */
		err = BlockFindContiguous(vcb, 1, startingBlock, minBlocks, maxBlocks,
		                          useMetaZone, actualStartBlock, actualNumBlocks);
	}
	//
	//	Now mark those blocks allocated.
	//
	if (err == noErr)
		err = BlockMarkAllocatedInternal(vcb, *actualStartBlock, *actualNumBlocks);
	
	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_CONTIG_BITMAP | DBG_FUNC_END, err, *actualStartBlock, *actualNumBlocks, 0, 0);

	return err;
}

#if CONFIG_HFS_ALLOC_RBTREE
/*
 * Variant of BlockAllocateContig that uses the newer red-black tree library
 * in order to manage free space extents.  This will search the red-black tree
 * and return results in the same fashion as BlockAllocateContigBitmap.
 * 
 * Note that this function is invoked from both the red-black tree variant of BlockAllocateany
 * as well as BlockAllocateContig.  In order to determine when we should vend contiguous chunks over
 * locality-based-searches, we use the forceContig argument to determine who called us.
 */

static OSErr BlockAllocateContigRBTree(
						  ExtendedVCB		*vcb,
						  u_int32_t		startingBlock,
						  u_int32_t		minBlocks,
						  u_int32_t		maxBlocks,
						  Boolean			useMetaZone,
						  u_int32_t		*actualStartBlock,
						  u_int32_t		*actualNumBlocks,
						  u_int32_t 	forceContig)
{
	OSErr	err;
	struct hfsmount *hfsmp = VCBTOHFS(vcb);
	extent_node_t search_sentinel;
	extent_node_t *node = NULL;
	extent_node_t tempnode;
	
	bzero (&tempnode, sizeof(extent_node_t));
	
	/* Begin search at the end of the file, via startingBlock */
	memset (&search_sentinel, 0, sizeof(extent_node_t));
	search_sentinel.offset = startingBlock;
	
	*actualStartBlock = 0;
	*actualNumBlocks = 0;
	
	/* 
	 * Find the first available extent that satifies the allocation by searching
	 * from the starting point and moving forward
	 */
	node = extent_tree_off_search_next(&hfsmp->offset_tree, &search_sentinel);
	
	if (node) {
		*actualStartBlock = node->offset;
		*actualNumBlocks = node->length;
	}
	
	 /* If we managed to grab at least minBlocks of space, then we're done. */

	if (*actualNumBlocks >= minBlocks) {
		if (*actualNumBlocks > maxBlocks) {
			*actualNumBlocks = maxBlocks;
		}
		
		
		/* Check to see if blocks are already marked as in-use */
		if (ALLOC_DEBUG) {
			REQUIRE_FILE_LOCK(vcb->hfs_allocation_vp, false);
			if (hfs_isallocated(hfsmp, *actualStartBlock, *actualNumBlocks)) {
				printf("bad node: %p, offset %d, length %d\n", node, node->offset,node->length);
				panic ("HFS RBTree Allocator: Blocks starting @ %x for %x blocks in use already\n",
					   *actualStartBlock, *actualNumBlocks);
			}
		}
		
		/*
		 * BlockMarkAllocatedRBTree is responsible for removing the nodes
		 * from the red-black tree after the bitmap has been updated on-disk.
		 */
		err = BlockMarkAllocatedRBTree(vcb, *actualStartBlock, *actualNumBlocks);
		if (err == noErr) {
			
			if ( ALLOC_DEBUG ) {
				REQUIRE_FILE_LOCK(vcb->hfs_allocation_vp, false);
				if (!hfs_isallocated(hfsmp, *actualStartBlock, *actualNumBlocks)) {
					panic ("HFS RBTree Allocator: Blocks starting @ %x for %x blocks not in use yet\n",
						   *actualStartBlock, *actualNumBlocks);
				}
				check_rbtree_extents (VCBTOHFS(vcb), *actualStartBlock, *actualNumBlocks, ASSERT_ALLOC);		
			}		
			
			return err;
		}
	}
	
	/*
	 * We may have failed to grow at the end of the file.  We'll try to find 
	 * appropriate free extents, searching by size in the normal allocation zone.
	 * 
	 * However, if we're allocating on behalf of a sparse device that hasn't explicitly
	 * requested a contiguous chunk, then we try to search by offset, even if it 
	 * means fragmenting the file.  We want all available entries starting 
	 * from the front of the disk to avoid creating new bandfiles.  As a result, 
	 * we'll start by searching the offset tree rather than the normal length 
	 * tree. Note that this function can be invoked from BlockAllocateAny, in 
	 * which the minimum block size is 1 block, making it easy to succeed. 
	 */
	search_sentinel.offset = hfsmp->hfs_metazone_end;
	search_sentinel.length = minBlocks;
	
	if ((vcb->hfs_flags & HFS_HAS_SPARSE_DEVICE) && (forceContig == 0)) {
		/* just start with the first offset node */
		node = extent_tree_off_search_next(&hfsmp->offset_tree, &search_sentinel);		
	}
	else {
		/* 
		 * Otherwise, start from the end of the metadata zone or our next allocation pointer, 
		 * and try to find the first chunk of size >= min.
		 */
		node = extent_tree_off_search_nextWithSize (&hfsmp->offset_tree, &search_sentinel);
		
		if (node == NULL) {
			extent_node_t *metaend_node;
			/* 
			 * Maybe there's a free extent coalesced with the space still in the metadata 
			 * zone.  If there is, find it and allocate from the middle of it, starting at
			 * the end of the metadata zone.
			 *
			 * If search_prev yields a result that is not offset == metazone_end, then that
			 * means no node existed at that offset.  If the previous node's offset + length crosses
			 * the metazone boundary, then allocate from there.  If it is too small to 
			 * cross the metazone boundary, then it is of no importance and we'd have to 
			 * report ENOSPC.
			 */
			metaend_node = extent_tree_off_search_prev(&hfsmp->offset_tree, &search_sentinel);
			
			if ((metaend_node) && (metaend_node->offset < hfsmp->hfs_metazone_end)) {
				u_int32_t node_end = metaend_node->offset + metaend_node->length;
				if (node_end > hfsmp->hfs_metazone_end) {
					u_int32_t modified_length = node_end - hfsmp->hfs_metazone_end;
					if (modified_length >= minBlocks) {
						/* 
						 * Then we can allocate it.  Fill in the contents into tempnode,
						 * and BlockMarkAllocatedRBTree below will take care of the rest.
						 */
						tempnode.offset = hfsmp->hfs_metazone_end;
						tempnode.length = MIN(minBlocks, node_end - tempnode.offset);
						node = &tempnode;
					}
				}
			}
		}
	}
	
	 /* If we can't find anything useful, search the metadata zone as a last resort. */
	
	if ((!node) && useMetaZone) {
		search_sentinel.offset = 0;
		search_sentinel.length = minBlocks;
		node = extent_tree_off_search_nextWithSize (&hfsmp->offset_tree, &search_sentinel);
	}
	
	/* If we found something useful, then go ahead and update the bitmap */
	if ((node) && (node->length >= minBlocks)) {
		*actualStartBlock = node->offset;
		if (node->length >= maxBlocks) {
			*actualNumBlocks = maxBlocks;
		}
		else {
			*actualNumBlocks = node->length;
		}

		err = BlockMarkAllocatedRBTree(vcb, *actualStartBlock, *actualNumBlocks);
		
		if (err == noErr) {
			if ( ALLOC_DEBUG ) {
				REQUIRE_FILE_LOCK(vcb->hfs_allocation_vp, false);
				if (!hfs_isallocated(hfsmp, *actualStartBlock, *actualNumBlocks)) {
					panic ("HFS RBTree Allocator: Blocks starting @ %x for %x blocks not in use yet\n",
						   *actualStartBlock, *actualNumBlocks);
				}
				check_rbtree_extents (VCBTOHFS(vcb), *actualStartBlock, *actualNumBlocks, ASSERT_ALLOC);		
			}
		}
	}
	else {
		int destroy_trees = 0;
		/*
		 * TODO: Add High-water mark check here.  If we couldn't find anything useful, 
		 * when do we tear down the tree?  Or should the logic be in BlockAllocateContig??
		 */
		if (destroy_trees) {
			DestroyTrees(VCBTOHFS(vcb));
			/* Reset the Free Ext Cache since we'll be using it now. */
			ResetVCBFreeExtCache(VCBTOHFS(vcb));
		}
		
		if (ALLOC_DEBUG) {
			printf("HFS allocator: No space on FS (%s). Node  %p Start %d Min %d, Max %d, Tree still alive.\n", 
				   hfsmp->vcbVN, node, startingBlock, minBlocks, maxBlocks);
			
			/* Dump the list ? */
			extent_tree_offset_print(&hfsmp->offset_tree);
			
			printf("HFS allocator: Done printing list on FS (%s). Min %d, Max %d, Tree still alive.\n", 
				   hfsmp->vcbVN, minBlocks, maxBlocks);


			
		}
		err = dskFulErr;
	}
	
	if (err == noErr) {
		if (ALLOC_DEBUG) {
			if ((*actualStartBlock + *actualNumBlocks) > vcb->allocLimit)
				panic("hfs: BlockAllocateAny: allocation overflow on \"%s\"", vcb->vcbVN);
		}
	}
	else {
		*actualStartBlock = 0;
		*actualNumBlocks = 0;
	}
	
	return err;
	
}
#endif



/*
_______________________________________________________________________

Routine:	BlockAllocateAny

Function:	Allocate one or more allocation blocks.  If there are fewer
			free blocks than requested, all free blocks will be
			allocated.  The caller guarantees that there is at least
			one free block.

Inputs:
	vcb				Pointer to volume where space is to be allocated
	startingBlock	Preferred first block for allocation
	endingBlock		Last block to check + 1
	maxBlocks		Maximum number of contiguous blocks to allocate
	useMetaZone

Outputs:
	actualStartBlock	First block of range allocated, or 0 if error
	actualNumBlocks		Number of blocks allocated, or 0 if error
_______________________________________________________________________
*/

/*
 * BlockAllocateAny acts as a multiplexer between BlockAllocateAnyRBTree
 * and BlockAllocateAnyBitmap, which uses the bitmap scanning logic.  
 */

static OSErr BlockAllocateAny(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	register u_int32_t	endingBlock,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks)
{
	
#if CONFIG_HFS_ALLOC_RBTREE
	if (hfs_isrbtree_active(VCBTOHFS(vcb))) {
		return BlockAllocateAnyRBTree(vcb, startingBlock, maxBlocks, useMetaZone, actualStartBlock, actualNumBlocks);
	}
#endif
	return BlockAllocateAnyBitmap(vcb, startingBlock, endingBlock, maxBlocks, useMetaZone, actualStartBlock, actualNumBlocks);

}


#if CONFIG_HFS_ALLOC_RBTREE
/*
 * BlockAllocateAnyRBTree finds one or more allocation blocks by using
 * the red-black allocation tree to figure out where the free ranges are.  
 * This function is typically used as a last resort becuase we were unable to 
 * find the right ranges.  Outputs are the same as BlockAllocateAnyBitmap.
 */
static OSErr BlockAllocateAnyRBTree(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks)
{	
	OSErr err;
	
	/* 
	 * BlockAllocateContig 
	 */
	/* If we're using the red-black tree, try searching at the specified offsets. */
	err = BlockAllocateContigRBTree(vcb, startingBlock, 1, maxBlocks, useMetaZone, 
									actualStartBlock, actualNumBlocks, 0);
	return err;
	
}
#endif

/*
 * BlockAllocateAnyBitmap finds free ranges by scanning the bitmap to figure out
 * where the free allocation blocks are.  Inputs and outputs are the same as for
 * BlockAllocateAny and BlockAllocateAnyRBTree
 */

static OSErr BlockAllocateAnyBitmap(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	register u_int32_t	endingBlock,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks)
{
	OSErr			err;
	register u_int32_t	block;			//	current block number
	register u_int32_t	currentWord;	//	Pointer to current word within bitmap block
	register u_int32_t	bitMask;		//	Word with given bits already set (ready to OR in)
	register u_int32_t	wordsLeft;		//	Number of words left in this bitmap block
	u_int32_t  *buffer = NULL;
	u_int32_t  *currCache = NULL;
	uintptr_t  blockRef;
	u_int32_t  bitsPerBlock;
	u_int32_t  wordsPerBlock;
	Boolean dirty = false;
	struct hfsmount *hfsmp = VCBTOHFS(vcb);

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_ANY_BITMAP | DBG_FUNC_START, startingBlock, endingBlock, maxBlocks, useMetaZone, 0);

	/*
	 * When we're skipping the metadata zone and the start/end
	 * range overlaps with the metadata zone then adjust the 
	 * start to be outside of the metadata zone.  If the range
	 * is entirely inside the metadata zone then we can deny the
	 * request (dskFulErr).
	 */
	if (!useMetaZone && (vcb->hfs_flags & HFS_METADATA_ZONE)) {
		if (startingBlock <= vcb->hfs_metazone_end) {
			if (endingBlock > (vcb->hfs_metazone_end + 2))
				startingBlock = vcb->hfs_metazone_end + 1;
			else {
				err = dskFulErr;
				goto Exit;
			}
		}
	}

	//	Since this routine doesn't wrap around
	if (maxBlocks > (endingBlock - startingBlock)) {
		maxBlocks = endingBlock - startingBlock;
	}

	//
	//	Pre-read the first bitmap block
	//
	err = ReadBitmapBlock(vcb, startingBlock, &currCache, &blockRef);
	if (err != noErr) goto Exit;
	buffer = currCache;

	//
	//	Set up the current position within the block
	//
	{
		u_int32_t wordIndexInBlock;
		
		bitsPerBlock  = vcb->vcbVBMIOSize * kBitsPerByte;
		wordsPerBlock = vcb->vcbVBMIOSize / kBytesPerWord;

		wordIndexInBlock = (startingBlock & (bitsPerBlock-1)) / kBitsPerWord;
		buffer += wordIndexInBlock;
		wordsLeft = wordsPerBlock - wordIndexInBlock;
		currentWord = SWAP_BE32 (*buffer);
		bitMask = kHighBitInWordMask >> (startingBlock & kBitsWithinWordMask);
	}
	
	//
	//	Find the first unallocated block
	//
	block=startingBlock;
	while (block < endingBlock) {
		if ((currentWord & bitMask) == 0)
			break;

		//	Next bit
		++block;
		bitMask >>= 1;
		if (bitMask == 0) {
			//	Next word
			bitMask = kHighBitInWordMask;
			++buffer;

			if (--wordsLeft == 0) {
				//	Next block
				buffer = currCache = NULL;
				err = ReleaseBitmapBlock(vcb, blockRef, false);
				if (err != noErr) goto Exit;

				/*
				 * Skip over metadata blocks.
				 */
				if (!useMetaZone) {
					block = NextBitmapBlock(vcb, block);
				}
				if (block >= endingBlock) {
					err = dskFulErr;
					goto Exit;
				}

				err = ReadBitmapBlock(vcb, block, &currCache, &blockRef);
				if (err != noErr) goto Exit;
				buffer = currCache;

				wordsLeft = wordsPerBlock;
			}
			currentWord = SWAP_BE32 (*buffer);
		}
	}

	//	Did we get to the end of the bitmap before finding a free block?
	//	If so, then couldn't allocate anything.
	if (block >= endingBlock) {
		err = dskFulErr;
		goto Exit;
	}

	//	Return the first block in the allocated range
	*actualStartBlock = block;
	dirty = true;
	
	//	If we could get the desired number of blocks before hitting endingBlock,
	//	then adjust endingBlock so we won't keep looking.  Ideally, the comparison
	//	would be (block + maxBlocks) < endingBlock, but that could overflow.  The
	//	comparison below yields identical results, but without overflow.
	if (block < (endingBlock-maxBlocks)) {
		endingBlock = block + maxBlocks;	//	if we get this far, we've found enough
	}
	
	// XXXdbg
	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, (struct buf *)blockRef);
	}

	//
	//	Allocate all of the consecutive blocks
	//
	while ((currentWord & bitMask) == 0) {
		//	Allocate this block
		currentWord |= bitMask;
		
		//	Move to the next block.  If no more, then exit.
		++block;
		if (block == endingBlock)
			break;

		//	Next bit
		bitMask >>= 1;
		if (bitMask == 0) {
			*buffer = SWAP_BE32 (currentWord);					//	update value in bitmap
			
			//	Next word
			bitMask = kHighBitInWordMask;
			++buffer;
			
			if (--wordsLeft == 0) {
				//	Next block
				buffer = currCache = NULL;
				err = ReleaseBitmapBlock(vcb, blockRef, true);
				if (err != noErr) goto Exit;

				/*
				 * Skip over metadata blocks.
				 */
				if (!useMetaZone) {
					u_int32_t nextBlock;

					nextBlock = NextBitmapBlock(vcb, block);
					if (nextBlock != block) {
						goto Exit;  /* allocation gap, so stop */
					}
				}

				err = ReadBitmapBlock(vcb, block, &currCache, &blockRef);
				if (err != noErr) goto Exit;
				buffer = currCache;

				// XXXdbg
				if (hfsmp->jnl) {
					journal_modify_block_start(hfsmp->jnl, (struct buf *)blockRef);
				}
				
				wordsLeft = wordsPerBlock;
			}
			
			currentWord = SWAP_BE32 (*buffer);
		}
	}
	*buffer = SWAP_BE32 (currentWord);							//	update the last change

Exit:
	if (err == noErr) {
		*actualNumBlocks = block - *actualStartBlock;

		// sanity check
		if ((*actualStartBlock + *actualNumBlocks) > vcb->allocLimit) {
			panic("hfs: BlockAllocateAny: allocation overflow on \"%s\"", vcb->vcbVN);
		}
		
		/*
		 * Beware!
		 * Because this function directly manipulates the bitmap to mark the
		 * blocks it came across as allocated, we must inform the journal (and
		 * subsequently, the journal's trim list) that we are allocating these 
		 * blocks, just like in BlockMarkAllocatedInternal.  hfs_unmap_alloc_extent
		 * and the functions it calls will serialize behind the journal trim list lock
		 * to ensure that either the asynchronous flush/TRIM/UNMAP happens prior to
		 * us manipulating the trim list, or we get there first and successfully remove
		 * these bitmap blocks before the TRIM happens.
		 */
		hfs_unmap_alloc_extent (vcb, *actualStartBlock, *actualNumBlocks);
	}
	else {
		*actualStartBlock = 0;
		*actualNumBlocks = 0;
	}

	if (currCache)
		(void) ReleaseBitmapBlock(vcb, blockRef, dirty);

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_ANY_BITMAP | DBG_FUNC_END, err, *actualStartBlock, *actualNumBlocks, 0, 0);

	return err;
}


/*
_______________________________________________________________________

Routine:	BlockAllocateKnown

Function:	Try to allocate space from known free space in the free
			extent cache.

Inputs:
	vcb				Pointer to volume where space is to be allocated
	maxBlocks		Maximum number of contiguous blocks to allocate

Outputs:
	actualStartBlock	First block of range allocated, or 0 if error
	actualNumBlocks		Number of blocks allocated, or 0 if error

Returns:
	dskFulErr		Free extent cache is empty
_______________________________________________________________________
*/

static OSErr BlockAllocateKnown(
	ExtendedVCB		*vcb,
	u_int32_t		maxBlocks,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks)
{
	OSErr			err;	
	u_int32_t		foundBlocks;

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_KNOWN_BITMAP | DBG_FUNC_START, 0, 0, maxBlocks, 0, 0);

	HFS_MOUNT_LOCK(vcb, TRUE);
	lck_spin_lock(&vcb->vcbFreeExtLock);
	if ((hfs_isrbtree_active(vcb) == true) || 
		vcb->vcbFreeExtCnt == 0 || 
	    vcb->vcbFreeExt[0].blockCount == 0) {
		lck_spin_unlock(&vcb->vcbFreeExtLock);
		HFS_MOUNT_UNLOCK(vcb, TRUE);
		if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
			KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_KNOWN_BITMAP | DBG_FUNC_END, dskFulErr, *actualStartBlock, *actualNumBlocks, 0, 0);
		return dskFulErr;
	}
	lck_spin_unlock(&vcb->vcbFreeExtLock);
	HFS_MOUNT_UNLOCK(vcb, TRUE);

	lck_spin_lock(&vcb->vcbFreeExtLock);

	//	Just grab up to maxBlocks of the first (largest) free exent.
	*actualStartBlock = vcb->vcbFreeExt[0].startBlock;
	foundBlocks = vcb->vcbFreeExt[0].blockCount;
	if (foundBlocks > maxBlocks)
		foundBlocks = maxBlocks;
	*actualNumBlocks = foundBlocks;
	
	lck_spin_unlock(&vcb->vcbFreeExtLock);

	remove_free_extent_cache(vcb, *actualStartBlock, *actualNumBlocks);
	
	// sanity check
	if ((*actualStartBlock + *actualNumBlocks) > vcb->allocLimit) 
	{
		printf ("hfs: BlockAllocateKnown() found allocation overflow on \"%s\"", vcb->vcbVN);
		hfs_mark_volume_inconsistent(vcb);
		*actualStartBlock = 0;
		*actualNumBlocks = 0;
		err = EIO;
	} 
	else 
	{
		//
		//	Now mark the found extent in the bitmap
		//
		err = BlockMarkAllocatedInternal(vcb, *actualStartBlock, *actualNumBlocks);
	}

	sanity_check_free_ext(vcb, 0);

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_KNOWN_BITMAP | DBG_FUNC_END, err, *actualStartBlock, *actualNumBlocks, 0, 0);

	return err;
}

/*
 * BlockMarkAllocated
 * 
 * This is a wrapper function around the internal calls which will actually mark the blocks
 * as in-use.  It will mark the blocks in the red-black tree if appropriate.  We need to do 
 * this logic here to avoid callers having to deal with whether or not the red-black tree
 * is enabled.
 */


OSErr BlockMarkAllocated(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	register u_int32_t	numBlocks)
{
	struct hfsmount *hfsmp;
	
	hfsmp = VCBTOHFS(vcb);
#if CONFIG_HFS_ALLOC_RBTREE
	if (hfs_isrbtree_active(hfsmp)) {
		int err;
		
		if ((startingBlock >= hfsmp->offset_block_end) && 
			(hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS)) {
			/* 
			 * We're manipulating a portion of the bitmap that is not controlled by the
			 * red-black tree.  Just update the bitmap and don't bother manipulating the tree
			 */
			goto justbitmap;
		}
		
		err = BlockMarkAllocatedRBTree(vcb, startingBlock, numBlocks);
		if (err == noErr) {
			if ( ALLOC_DEBUG ) {
				REQUIRE_FILE_LOCK(hfsmp->hfs_allocation_vp, false);
				if (!hfs_isallocated(hfsmp, startingBlock, numBlocks)) {
					panic ("HFS RBTree Allocator: Blocks starting @ %x for %x blocks not in use yet\n",
						   startingBlock, numBlocks);
				}
				check_rbtree_extents (hfsmp, startingBlock, numBlocks, ASSERT_ALLOC);		
			}
		}
		return err;

	}
justbitmap:
#endif

	return BlockMarkAllocatedInternal(vcb, startingBlock, numBlocks);
	
}



/*
_______________________________________________________________________

Routine:	BlockMarkAllocatedInternal

Function:	Mark a contiguous group of blocks as allocated (set in the
			bitmap).  It assumes those bits are currently marked
			deallocated (clear in the bitmap).  Note that this function
			must be called regardless of whether or not the bitmap or
			tree-based allocator is used, as all allocations must correctly
			be marked on-disk.  If the tree-based approach is running, then
			this will be done before the node is removed from the tree.

Inputs:
	vcb				Pointer to volume where space is to be allocated
	startingBlock	First block number to mark as allocated
	numBlocks		Number of blocks to mark as allocated
_______________________________________________________________________
*/
static 
OSErr BlockMarkAllocatedInternal (
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	register u_int32_t	numBlocks)
{
	OSErr			err;
	register u_int32_t	*currentWord;	//	Pointer to current word within bitmap block
	register u_int32_t	wordsLeft;		//	Number of words left in this bitmap block
	register u_int32_t	bitMask;		//	Word with given bits already set (ready to OR in)
	u_int32_t		firstBit;		//	Bit index within word of first bit to allocate
	u_int32_t		numBits;		//	Number of bits in word to allocate
	u_int32_t		*buffer = NULL;
	uintptr_t  blockRef;
	u_int32_t  bitsPerBlock;
	u_int32_t  wordsPerBlock;
	// XXXdbg
	struct hfsmount *hfsmp = VCBTOHFS(vcb);

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_MARK_ALLOC_BITMAP | DBG_FUNC_START, startingBlock, numBlocks, 0, 0, 0);

	hfs_unmap_alloc_extent(vcb, startingBlock, numBlocks);
	
	//
	//	Pre-read the bitmap block containing the first word of allocation
	//

	err = ReadBitmapBlock(vcb, startingBlock, &buffer, &blockRef);
	if (err != noErr) goto Exit;
	//
	//	Initialize currentWord, and wordsLeft.
	//
	{
		u_int32_t wordIndexInBlock;
		
		bitsPerBlock  = vcb->vcbVBMIOSize * kBitsPerByte;
		wordsPerBlock = vcb->vcbVBMIOSize / kBytesPerWord;

		wordIndexInBlock = (startingBlock & (bitsPerBlock-1)) / kBitsPerWord;
		currentWord = buffer + wordIndexInBlock;
		wordsLeft = wordsPerBlock - wordIndexInBlock;
	}
	
	// XXXdbg
	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, (struct buf *)blockRef);
	}

	//
	//	If the first block to allocate doesn't start on a word
	//	boundary in the bitmap, then treat that first word
	//	specially.
	//

	firstBit = startingBlock % kBitsPerWord;
	if (firstBit != 0) {
		bitMask = kAllBitsSetInWord >> firstBit;	//	turn off all bits before firstBit
		numBits = kBitsPerWord - firstBit;			//	number of remaining bits in this word
		if (numBits > numBlocks) {
			numBits = numBlocks;					//	entire allocation is inside this one word
			bitMask &= ~(kAllBitsSetInWord >> (firstBit + numBits));	//	turn off bits after last
		}
#if DEBUG_BUILD
		if ((*currentWord & SWAP_BE32 (bitMask)) != 0) {
			panic("hfs: BlockMarkAllocatedInternal: blocks already allocated!");
		}
#endif
		*currentWord |= SWAP_BE32 (bitMask);		//	set the bits in the bitmap
		numBlocks -= numBits;						//	adjust number of blocks left to allocate

		++currentWord;								//	move to next word
		--wordsLeft;								//	one less word left in this block
	}

	//
	//	Allocate whole words (32 blocks) at a time.
	//

	bitMask = kAllBitsSetInWord;					//	put this in a register for 68K
	while (numBlocks >= kBitsPerWord) {
		if (wordsLeft == 0) {
			//	Read in the next bitmap block
			startingBlock += bitsPerBlock;			//	generate a block number in the next bitmap block
			
			buffer = NULL;
			err = ReleaseBitmapBlock(vcb, blockRef, true);
			if (err != noErr) goto Exit;

			err = ReadBitmapBlock(vcb, startingBlock, &buffer, &blockRef);
			if (err != noErr) goto Exit;

			// XXXdbg
			if (hfsmp->jnl) {
				journal_modify_block_start(hfsmp->jnl, (struct buf *)blockRef);
			}

			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
#if DEBUG_BUILD
		if (*currentWord != 0) {
			panic("hfs: BlockMarkAllocatedInternal: blocks already allocated!");
		}
#endif
		*currentWord = SWAP_BE32 (bitMask);
		numBlocks -= kBitsPerWord;

		++currentWord;								//	move to next word
		--wordsLeft;								//	one less word left in this block
	}
	
	//
	//	Allocate any remaining blocks.
	//
	
	if (numBlocks != 0) {
		bitMask = ~(kAllBitsSetInWord >> numBlocks);	//	set first numBlocks bits
		if (wordsLeft == 0) {
			//	Read in the next bitmap block
			startingBlock += bitsPerBlock;				//	generate a block number in the next bitmap block
			
			buffer = NULL;
			err = ReleaseBitmapBlock(vcb, blockRef, true);
			if (err != noErr) goto Exit;

			err = ReadBitmapBlock(vcb, startingBlock, &buffer, &blockRef);
			if (err != noErr) goto Exit;

			// XXXdbg
			if (hfsmp->jnl) {
				journal_modify_block_start(hfsmp->jnl, (struct buf *)blockRef);
			}
			
			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
#if DEBUG_BUILD
		if ((*currentWord & SWAP_BE32 (bitMask)) != 0) {
			panic("hfs: BlockMarkAllocatedInternal: blocks already allocated!");
		}
#endif
		*currentWord |= SWAP_BE32 (bitMask);			//	set the bits in the bitmap

		//	No need to update currentWord or wordsLeft
	}

Exit:

	if (buffer)
		(void)ReleaseBitmapBlock(vcb, blockRef, true);

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_MARK_ALLOC_BITMAP | DBG_FUNC_END, err, 0, 0, 0, 0);

	return err;
}

#if CONFIG_HFS_ALLOC_RBTREE
/*
 * This is a wrapper function around BlockMarkAllocated.  This function is
 * called when the RB Tree-based allocator needs to mark a block as in-use.
 * This function should take the locks that would not normally be 
 * necessary for the normal bitmap allocator, and then call the function.  Once 
 * the on-disk data structures are updated properly, then this will remove the 
 * appropriate node from the tree.
 */

static OSErr BlockMarkAllocatedRBTree(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		numBlocks)
{
	OSErr err;
	struct hfsmount *hfsmp  = VCBTOHFS(vcb);
	int rb_err = 0;

	
	if (ALLOC_DEBUG) {
		REQUIRE_FILE_LOCK(vcb->hfs_allocation_vp, false);
		if (hfs_isallocated(hfsmp, startingBlock, numBlocks)) {
			panic ("HFS RBTree Allocator: Blocks starting @ %x for %x blocks in use already\n",
				   startingBlock, numBlocks);
		}
		check_rbtree_extents (VCBTOHFS(vcb), startingBlock, numBlocks, ASSERT_FREE);		
	}
	
	err = BlockMarkAllocatedInternal (vcb, startingBlock, numBlocks);
	
	if (err == noErr) {

		if (ALLOC_DEBUG) {
			if (!hfs_isallocated(hfsmp, startingBlock, numBlocks)) {
				panic ("HFS RBTree Allocator: Blocks starting @ %x for %x blocks not in use yet!\n",
					   startingBlock, numBlocks);
			}
		}
		
		/*
		 * Mark the blocks in the offset tree.
		 */
		rb_err = extent_tree_offset_alloc_space(&hfsmp->offset_tree, numBlocks, startingBlock);
		if (rb_err) {
			if (ALLOC_DEBUG) {
				printf("HFS RBTree Allocator: Could not mark blocks as in-use! %d \n", rb_err);
			}
			
			/* 
			 * We may be called from the BlockMarkAllocated interface, in which case, they would
			 * not be picking extents from their start. Do a check here, find if the specified
			 * extent is free, and if it is, then find the containing node.
			 */
			extent_node_t *node = NULL;
			extent_node_t search_sentinel;
			search_sentinel.offset = startingBlock;
			
			node = extent_tree_off_search_prev(&hfsmp->offset_tree, &search_sentinel);
			
			if (node) {
				rb_err = extent_tree_offset_alloc_unaligned (&hfsmp->offset_tree, numBlocks, startingBlock);
			}
			
			if (ALLOC_DEBUG) {
				if (rb_err) {
					printf ("HFS RBTree Allocator: Still Couldn't mark blocks as in-use! %d\n", rb_err);
				}
			}
		}
		if (ALLOC_DEBUG) {
			check_rbtree_extents (VCBTOHFS(vcb), startingBlock, numBlocks, ASSERT_ALLOC);		
		}
	}
	
	/* 
	 * If we encountered a red-black tree error, for now, we immediately back off and force
	 * destruction of rb-tree.  Set the persistent error-detected bit in the mount point.
	 * That will ensure that even if we reach a low-water-mark in the future we will still
	 * not allow the rb-tree to be used.  On next mount, we will force a re-construction from
	 * on-disk state.  As a fallback, we will now resort to the bitmap-scanning behavior.
	 */
	if (rb_err) {
		/* Mark RB-Trees with error */
		hfsmp->extent_tree_flags |= HFS_ALLOC_RB_ERRORED;
		DestroyTrees(hfsmp);
		/* Reset the Free Ext Cache since we'll be using it now. */
		ResetVCBFreeExtCache(hfsmp);
		printf("HFS: Red-Black Allocator Tree BlockMarkAllocated error\n");
	}
	
	return err;
}
#endif



/*
 * BlockMarkFree
 * 
 * This is a wrapper function around the internal calls which will actually mark the blocks
 * as freed.  It will mark the blocks in the red-black tree if appropriate.  We need to do 
 * this logic here to avoid callers having to deal with whether or not the red-black tree
 * is enabled.
 *
 */
OSErr BlockMarkFree(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	register u_int32_t	numBlocks)
{
	struct hfsmount *hfsmp;
	hfsmp = VCBTOHFS(vcb);
#if CONFIG_HFS_ALLOC_RBTREE		
	if (hfs_isrbtree_active(hfsmp)) {		
		int err;
		
		if ((startingBlock >= hfsmp->offset_block_end) && 
			(hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS)) {
			/* 
			 * We're manipulating a portion of the bitmap that is not controlled by the
			 * red-black tree.  Just update the bitmap and don't bother manipulating the tree
			 */
			goto justbitmap;
		}
		
		err = BlockMarkFreeRBTree(vcb, startingBlock, numBlocks);
		if (err == noErr) {
			if ( ALLOC_DEBUG ) {
				REQUIRE_FILE_LOCK(hfsmp->hfs_allocation_vp, false);
				if (hfs_isallocated(hfsmp, startingBlock, numBlocks)) {
					panic ("HFS RBTree Allocator: Blocks starting @ %x for %x blocks in use!\n",
						   startingBlock, numBlocks);
				}
				check_rbtree_extents (hfsmp, startingBlock, numBlocks, ASSERT_FREE);		
			}
		}
		return err;
	}
justbitmap:
#endif
	return BlockMarkFreeInternal(vcb, startingBlock, numBlocks, true);
	
}


/*
 * BlockMarkFreeUnused
 * 
 * Scan the bitmap block beyond end of current file system for bits 
 * that are marked as used.  If any of the bits are marked as used,
 * this function marks them free.
 *
 * Note:  This was specifically written to mark all bits beyond 
 * end of current file system during hfs_extendfs(), which makes
 * sure that all the new blocks added to the file system are 
 * marked as free.   We expect that all the blocks beyond end of
 * current file system are always marked as free, but there might 
 * be cases where are marked as used.  This function assumes that 
 * the number of blocks marked as used incorrectly are relatively
 * small, otherwise this can overflow journal transaction size
 * on certain file system configurations (example, large unused 
 * bitmap with relatively small journal). 
 *
 * Input:
 * 	startingBlock: First block of the range to mark unused
 * 	numBlocks: Number of blocks in the range to mark unused
 *
 * Returns: zero on success, non-zero on error.
 */
OSErr BlockMarkFreeUnused(ExtendedVCB *vcb, u_int32_t startingBlock, register u_int32_t	numBlocks)
{
	int error = 0;
	struct hfsmount *hfsmp = VCBTOHFS(vcb);
	u_int32_t curNumBlocks;
	u_int32_t  bitsPerBlock;
	u_int32_t lastBit;

	/* Use the optimal bitmap I/O size instead of bitmap block size */
	bitsPerBlock  = hfsmp->vcbVBMIOSize * kBitsPerByte;

	/* 
	 * First clear any non bitmap allocation block aligned bits
	 *
	 * Calculate the first bit in the bitmap block next to 
	 * the bitmap block containing the bit for startingBlock.
	 * Using this value, we calculate the total number of 
	 * bits to be marked unused from startingBlock to the 
	 * end of bitmap block containing startingBlock. 
	 */
	lastBit = ((startingBlock + (bitsPerBlock - 1))/bitsPerBlock) * bitsPerBlock;
	curNumBlocks = lastBit - startingBlock;
	if (curNumBlocks > numBlocks) {
		curNumBlocks = numBlocks;
	}
	error = BlockMarkFreeInternal(vcb, startingBlock, curNumBlocks, false);
	if (error) {
		return error;
	}
	startingBlock += curNumBlocks;
	numBlocks -= curNumBlocks;

	/* 
	 * Check a full bitmap block for any 'used' bit.  If any bit is used,
	 * mark all the bits only in that bitmap block as free.  This ensures
	 * that we do not write unmodified bitmap blocks and do not 
	 * overwhelm the journal. 
	 *
	 * The code starts by checking full bitmap block at a time, and 
	 * marks entire bitmap block as free only if any bit in that bitmap 
	 * block is marked as used.  In the end, it handles the last bitmap 
	 * block which might be partially full by only checking till the 
	 * caller-specified last bit and if any bit is set, only mark that 
	 * range as free.
	 */
	while (numBlocks) {
		if (numBlocks >= bitsPerBlock) {
			curNumBlocks = bitsPerBlock;
		} else {
			curNumBlocks = numBlocks;
		}
		if (hfs_isallocated(hfsmp, startingBlock, curNumBlocks) == true) {
			error = BlockMarkFreeInternal(vcb, startingBlock, curNumBlocks, false);
			if (error) {
				return error;
			}
		}
		startingBlock += curNumBlocks;
		numBlocks -= curNumBlocks;
	}

	return error;
}

/*
_______________________________________________________________________

Routine:	BlockMarkFreeInternal

Function:	Mark a contiguous group of blocks as free (clear in the
			bitmap).  It assumes those bits are currently marked
			allocated (set in the bitmap).

Inputs:
	vcb				Pointer to volume where space is to be freed
	startingBlock	First block number to mark as freed
	numBlocks		Number of blocks to mark as freed
	do_validate 	If true, validate that the blocks being 
					deallocated to check if they are within totalBlocks
					for current volume and whether they were allocated
					before they are marked free.
_______________________________________________________________________
*/
static 
OSErr BlockMarkFreeInternal(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock_in,
	register u_int32_t	numBlocks_in,
	Boolean 		do_validate)
{
	OSErr		err;
	u_int32_t	startingBlock = startingBlock_in;
	u_int32_t	numBlocks = numBlocks_in;
	uint32_t	unmapStart = startingBlock_in;
	uint32_t	unmapCount = numBlocks_in;
	uint32_t	wordIndexInBlock;
	u_int32_t	*currentWord;	//	Pointer to current word within bitmap block
	u_int32_t	wordsLeft;		//	Number of words left in this bitmap block
	u_int32_t	bitMask;		//	Word with given bits already set (ready to OR in)
	u_int32_t	currentBit;		//	Bit index within word of current bit to allocate
	u_int32_t	numBits;		//	Number of bits in word to allocate
	u_int32_t	*buffer = NULL;
	uintptr_t	blockRef;
	u_int32_t	bitsPerBlock;
	u_int32_t	wordsPerBlock;
    // XXXdbg
	struct hfsmount *hfsmp = VCBTOHFS(vcb);
	
	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_MARK_FREE_BITMAP | DBG_FUNC_START, startingBlock_in, numBlocks_in, do_validate, 0, 0);

	/*
	 * NOTE: We use vcb->totalBlocks instead of vcb->allocLimit because we
	 * need to be able to free blocks being relocated during hfs_truncatefs.
	 */
	if ((do_validate == true) && 
	    (startingBlock + numBlocks > vcb->totalBlocks)) {
		if (ALLOC_DEBUG) {
			panic ("BlockMarkFreeInternal() free non-existent blocks at %u (numBlock=%u) on vol %s\n", startingBlock, numBlocks, vcb->vcbVN);
		}
		
		printf ("hfs: BlockMarkFreeInternal() trying to free non-existent blocks starting at %u (numBlock=%u) on volume %s\n", startingBlock, numBlocks, vcb->vcbVN);
		hfs_mark_volume_inconsistent(vcb);
		err = EIO;
		goto Exit;
	}
	
	//
	//	Pre-read the bitmap block containing the first word of allocation
	//
	
	err = ReadBitmapBlock(vcb, startingBlock, &buffer, &blockRef);
	if (err != noErr) goto Exit;
	// XXXdbg
	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, (struct buf *)blockRef);
	}
	
	//
	//	Figure out how many bits and words per bitmap block.
	//
	bitsPerBlock  = vcb->vcbVBMIOSize * kBitsPerByte;
	wordsPerBlock = vcb->vcbVBMIOSize / kBytesPerWord;
	wordIndexInBlock = (startingBlock & (bitsPerBlock-1)) / kBitsPerWord;
	
	//
	// Look for a range of free blocks immediately before startingBlock
	// (up to the start of the current bitmap block).  Set unmapStart to
	// the first free block.
	//
	currentWord = buffer + wordIndexInBlock;
	currentBit = startingBlock % kBitsPerWord;
	bitMask = kHighBitInWordMask >> currentBit;
	while (true) {
		// Move currentWord/bitMask back by one bit
		bitMask <<= 1;
		if (bitMask == 0) {
			if (--currentWord < buffer)
				break;
			bitMask = kLowBitInWordMask;
		}
		
		if (*currentWord & SWAP_BE32(bitMask))
			break;	// Found an allocated block.  Stop searching.
		--unmapStart;
		++unmapCount;
	}
	
	//
	//	If the first block to free doesn't start on a word
	//	boundary in the bitmap, then treat that first word
	//	specially.
	//
	
	currentWord = buffer + wordIndexInBlock;
	wordsLeft = wordsPerBlock - wordIndexInBlock;
	currentBit = startingBlock % kBitsPerWord;
	if (currentBit != 0) {
		bitMask = kAllBitsSetInWord >> currentBit;	//	turn off all bits before currentBit
		numBits = kBitsPerWord - currentBit;		//	number of remaining bits in this word
		if (numBits > numBlocks) {
			numBits = numBlocks;					//	entire allocation is inside this one word
			bitMask &= ~(kAllBitsSetInWord >> (currentBit + numBits));	//	turn off bits after last
		}
		if ((do_validate == true) && 
		    (*currentWord & SWAP_BE32 (bitMask)) != SWAP_BE32 (bitMask)) {
			goto Corruption;
		}
		*currentWord &= SWAP_BE32 (~bitMask);		//	clear the bits in the bitmap
		numBlocks -= numBits;						//	adjust number of blocks left to free
		
		++currentWord;								//	move to next word
		--wordsLeft;								//	one less word left in this block
	}
	
	//
	//	Free whole words (32 blocks) at a time.
	//
	
	while (numBlocks >= kBitsPerWord) {
		if (wordsLeft == 0) {
			//	Read in the next bitmap block
			startingBlock += bitsPerBlock;			//	generate a block number in the next bitmap block
			
			buffer = NULL;
			err = ReleaseBitmapBlock(vcb, blockRef, true);
			if (err != noErr) goto Exit;
			
			err = ReadBitmapBlock(vcb, startingBlock, &buffer, &blockRef);
			if (err != noErr) goto Exit;
			
			// XXXdbg
			if (hfsmp->jnl) {
				journal_modify_block_start(hfsmp->jnl, (struct buf *)blockRef);
			}
			
			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
		if ((do_validate == true) && 
		    (*currentWord != SWAP_BE32 (kAllBitsSetInWord))) {
			goto Corruption;
		}
		*currentWord = 0;							//	clear the entire word
		numBlocks -= kBitsPerWord;
		
		++currentWord;								//	move to next word
		--wordsLeft;									//	one less word left in this block
	}
	
	//
	//	Free any remaining blocks.
	//
	
	if (numBlocks != 0) {
		bitMask = ~(kAllBitsSetInWord >> numBlocks);	//	set first numBlocks bits
		if (wordsLeft == 0) {
			//	Read in the next bitmap block
			startingBlock += bitsPerBlock;				//	generate a block number in the next bitmap block
			
			buffer = NULL;
			err = ReleaseBitmapBlock(vcb, blockRef, true);
			if (err != noErr) goto Exit;
			
			err = ReadBitmapBlock(vcb, startingBlock, &buffer, &blockRef);
			if (err != noErr) goto Exit;
			
			// XXXdbg
			if (hfsmp->jnl) {
				journal_modify_block_start(hfsmp->jnl, (struct buf *)blockRef);
			}
			
			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
		if ((do_validate == true) && 
		    (*currentWord & SWAP_BE32 (bitMask)) != SWAP_BE32 (bitMask)) {
			goto Corruption;
		}
		*currentWord &= SWAP_BE32 (~bitMask);			//	clear the bits in the bitmap
		
		//	No need to update currentWord or wordsLeft
	}
	
	//
	// Look for a range of free blocks immediately after the range we just freed
	// (up to the end of the current bitmap block).
	//
	wordIndexInBlock = ((startingBlock_in + numBlocks_in - 1) & (bitsPerBlock-1)) / kBitsPerWord;
	wordsLeft = wordsPerBlock - wordIndexInBlock;
	currentWord = buffer + wordIndexInBlock;
	currentBit = (startingBlock_in + numBlocks_in - 1) % kBitsPerWord;
	bitMask = kHighBitInWordMask >> currentBit;
	while (true) {
		// Move currentWord/bitMask/wordsLeft forward one bit
		bitMask >>= 1;
		if (bitMask == 0) {
			if (--wordsLeft == 0)
				break;
			++currentWord;
			bitMask = kHighBitInWordMask;
		}
		
		if (*currentWord & SWAP_BE32(bitMask))
			break;	// Found an allocated block.  Stop searching.
		++unmapCount;
	}
	
Exit:
	
	if (buffer)
		(void)ReleaseBitmapBlock(vcb, blockRef, true);
	
	if (err == noErr) {
		hfs_unmap_free_extent(vcb, unmapStart, unmapCount);
	}

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_MARK_FREE_BITMAP | DBG_FUNC_END, err, 0, 0, 0, 0);

	return err;
	
Corruption:
#if DEBUG_BUILD
	panic("hfs: BlockMarkFreeInternal: blocks not allocated!");
#else
	printf ("hfs: BlockMarkFreeInternal() trying to free unallocated blocks on volume %s\n", vcb->vcbVN);
	hfs_mark_volume_inconsistent(vcb);
	err = EIO;
	goto Exit;
#endif
}


#if CONFIG_HFS_ALLOC_RBTREE
/*
 * This is a wrapper function around BlockMarkFree.  This function is
 * called when the RB Tree-based allocator needs to mark a block as no longer
 * in use. This function should take the locks that would not normally be 
 * necessary for the normal bitmap deallocator, and then call the function.  Once 
 * the on-disk data structures are updated properly, then this will update an
 * existing rb-tree node if possible, or else create a new one. 
 */

OSErr BlockMarkFreeRBTree(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	register u_int32_t	numBlocks)
{
	OSErr err;
	struct hfsmount *hfsmp  = VCBTOHFS(vcb);
	int rb_err = 0;
	
	if (ALLOC_DEBUG) {
		REQUIRE_FILE_LOCK(vcb->hfs_allocation_vp, false);
		if (!hfs_isallocated(hfsmp, startingBlock, numBlocks)) {
			panic ("HFS RBTree Allocator: Trying to free blocks starting @ %x for %x but blocks not in use! \n",
				   startingBlock, numBlocks);
		}
		check_rbtree_extents (VCBTOHFS(vcb), startingBlock, numBlocks, ASSERT_ALLOC);		
	}	
	
	err = BlockMarkFreeInternal(vcb, startingBlock, numBlocks, true);
	
	if (err == noErr) {
		
		/*
		 * During a filesystem truncation, we may need to relocate files out of the
		 * portion of the bitmap that is no longer controlled by the r/b tree. 
		 * In this case, just update the bitmap and do not attempt to manipulate the tree.
		 */
		if ((startingBlock >= hfsmp->offset_block_end) && 
			(hfsmp->hfs_flags & HFS_RESIZE_IN_PROGRESS)) {
			goto free_error;
		}
		
		extent_node_t *newnode;
		
		if (ALLOC_DEBUG) {
			/* 
			 * Validate that the blocks in question are not allocated in the bitmap, and that they're
			 * not in the offset tree, since it should be tracking free extents, rather than allocated 
			 * extents
			 */
			if (hfs_isallocated(hfsmp, startingBlock, numBlocks)) {
				panic ("HFS RBTree Allocator: Blocks starting @ %x for %x blocks still marked in-use!\n",
					   startingBlock, numBlocks);
			}
		}		
		
		if ((hfsmp->extent_tree_flags & HFS_ALLOC_RB_ACTIVE) == 0) {
			if (startingBlock >= hfsmp->offset_block_end) {
				/*
				 * If the tree generation code has not yet finished scanning the
				 * bitmap region containing this extent, do nothing.  If the start 
				 * of the range to be deallocated is greater than the current high 
				 * watermark on the offset tree, just bail out and let the scanner catch up with us. 
				 */							
				rb_err = 0;
				goto free_error;
			}
		}
		
		newnode = extent_tree_free_space(&hfsmp->offset_tree, numBlocks, startingBlock);
		if (newnode == NULL) {
			rb_err = 1;
			goto free_error;
		}
		
		if (ALLOC_DEBUG) {
			check_rbtree_extents (VCBTOHFS(vcb), startingBlock, numBlocks, ASSERT_FREE);
		}
		
	}
	
free_error:
	/* 
	 * We follow the same principle as in BlockMarkAllocatedRB. 
	 * If we encounter an error in adding the extents to the rb-tree, then immediately
	 * back off, destroy the trees, and persistently set a bit in the runtime hfsmp flags
	 * to indicate we should not use the rb-tree until next mount, when we can force a rebuild.
	 */
	if (rb_err) {
		/* Mark RB-Trees with error */
		hfsmp->extent_tree_flags |= HFS_ALLOC_RB_ERRORED;
		DestroyTrees(hfsmp);
		/* Reset the Free Ext Cache since we'll be using it now. */
		ResetVCBFreeExtCache(hfsmp);
		printf("HFS: Red-Black Allocator Tree BlockMarkFree error\n");
	}
	
	
	return err;
	
}
#endif

/*
_______________________________________________________________________

Routine:	BlockFindContiguous

Function:	Find a contiguous range of blocks that are free (bits
			clear in the bitmap).  If a contiguous range of the
			minimum size can't be found, an error will be returned.
			This is only needed to support the bitmap-scanning logic,
			as the red-black tree should be able to do this by internally
			searching its tree.

Inputs:
	vcb				Pointer to volume where space is to be allocated
	startingBlock	Preferred first block of range
	endingBlock		Last possible block in range + 1
	minBlocks		Minimum number of blocks needed.  Must be > 0.
	maxBlocks		Maximum (ideal) number of blocks desired
	useMetaZone	OK to dip into metadata allocation zone

Outputs:
	actualStartBlock	First block of range found, or 0 if error
	actualNumBlocks		Number of blocks found, or 0 if error

Returns:
	noErr			Found at least minBlocks contiguous
	dskFulErr		No contiguous space found, or all less than minBlocks
_______________________________________________________________________
*/

static OSErr BlockFindContiguous(
	ExtendedVCB		*vcb,
	u_int32_t		startingBlock,
	u_int32_t		endingBlock,
	u_int32_t		minBlocks,
	u_int32_t		maxBlocks,
	Boolean			useMetaZone,
	u_int32_t		*actualStartBlock,
	u_int32_t		*actualNumBlocks)
{
	OSErr			err;
	register u_int32_t	currentBlock;		//	Block we're currently looking at.
	u_int32_t			firstBlock;			//	First free block in current extent.
	u_int32_t			stopBlock;			//	If we get to this block, stop searching for first free block.
	u_int32_t			foundBlocks;		//	Number of contiguous free blocks in current extent.
	u_int32_t			*buffer = NULL;
	register u_int32_t	*currentWord;
	register u_int32_t	bitMask;
	register u_int32_t	wordsLeft;
	register u_int32_t	tempWord;
	uintptr_t  blockRef;
	u_int32_t  wordsPerBlock;
	u_int32_t  updated_free_extent = 0;

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_BLOCK_FIND_CONTIG | DBG_FUNC_START, startingBlock, endingBlock, minBlocks, maxBlocks, 0);

	/*
	 * When we're skipping the metadata zone and the start/end
	 * range overlaps with the metadata zone then adjust the 
	 * start to be outside of the metadata zone.  If the range
	 * is entirely inside the metadata zone then we can deny the
	 * request (dskFulErr).
	 */
	if (!useMetaZone && (vcb->hfs_flags & HFS_METADATA_ZONE)) {
		if (startingBlock <= vcb->hfs_metazone_end) {
			if (endingBlock > (vcb->hfs_metazone_end + 2))
				startingBlock = vcb->hfs_metazone_end + 1;
			else
				goto DiskFull;
		}
	}

	if ((endingBlock - startingBlock) < minBlocks)
	{
		//	The set of blocks we're checking is smaller than the minimum number
		//	of blocks, so we couldn't possibly find a good range.
		goto DiskFull;
	}

	stopBlock = endingBlock - minBlocks + 1;
	currentBlock = startingBlock;
	firstBlock = 0;

	/*
	 * Skip over metadata blocks.
	 */
	if (!useMetaZone)
		currentBlock = NextBitmapBlock(vcb, currentBlock);

	//
	//	Pre-read the first bitmap block.
	//
	err = ReadBitmapBlock(vcb, currentBlock, &buffer, &blockRef);
	if ( err != noErr ) goto ErrorExit;

	//
	//	Figure out where currentBlock is within the buffer.
	//
	wordsPerBlock = vcb->vcbVBMIOSize / kBytesPerWord;

	wordsLeft = (currentBlock / kBitsPerWord) & (wordsPerBlock-1);	// Current index into buffer
	currentWord = buffer + wordsLeft;
	wordsLeft = wordsPerBlock - wordsLeft;
	
	do
	{
		foundBlocks = 0;
		
		//============================================================
		//	Look for a free block, skipping over allocated blocks.
		//============================================================

		//
		//	Check an initial partial word (if any)
		//
		bitMask = currentBlock & kBitsWithinWordMask;
		if (bitMask)
		{			
			tempWord = SWAP_BE32(*currentWord);			//	Fetch the current word only once
			bitMask = kHighBitInWordMask >> bitMask;
			while (tempWord & bitMask)
			{
				bitMask >>= 1;
				++currentBlock;
			}

			//	Did we find an unused bit (bitMask != 0), or run out of bits (bitMask == 0)? 
			if (bitMask)
				goto FoundUnused;

			//	Didn't find any unused bits, so we're done with this word.
			++currentWord;
			--wordsLeft;
		}

		//
		//	Check whole words
		//
		while (currentBlock < stopBlock)
		{
			//	See if it's time to read another block.
			if (wordsLeft == 0)
			{
				buffer = NULL;
				err = ReleaseBitmapBlock(vcb, blockRef, false);
				if (err != noErr) goto ErrorExit;

				/*
				 * Skip over metadata blocks.
				 */
				if (!useMetaZone) {
					currentBlock = NextBitmapBlock(vcb, currentBlock);
					if (currentBlock >= stopBlock) {
						goto LoopExit;
					}
				}

				err = ReadBitmapBlock(vcb, currentBlock, &buffer, &blockRef);
				if ( err != noErr ) goto ErrorExit;
				
				currentWord = buffer;
				wordsLeft = wordsPerBlock;
			}
			
			//	See if any of the bits are clear
			if ((tempWord = SWAP_BE32(*currentWord)) + 1)	//	non-zero if any bits were clear
			{
				//	Figure out which bit is clear
				bitMask = kHighBitInWordMask;
				while (tempWord & bitMask)
				{
					bitMask >>= 1;
					++currentBlock;
				}
				
				break;		//	Found the free bit; break out to FoundUnused.
			}

			//	Keep looking at the next word
			currentBlock += kBitsPerWord;
			++currentWord;
			--wordsLeft;
		}

FoundUnused:
		//	Make sure the unused bit is early enough to use
		if (currentBlock >= stopBlock)
		{
			break;
		}

		//	Remember the start of the extent
		firstBlock = currentBlock;

		//============================================================
		//	Count the number of contiguous free blocks.
		//============================================================

		//
		//	Check an initial partial word (if any)
		//
		bitMask = currentBlock & kBitsWithinWordMask;
		if (bitMask)
		{
			tempWord = SWAP_BE32(*currentWord);			//	Fetch the current word only once
			bitMask = kHighBitInWordMask >> bitMask;
			while (bitMask && !(tempWord & bitMask))
			{
				bitMask >>= 1;
				++currentBlock;
			}

			//	Did we find a used bit (bitMask != 0), or run out of bits (bitMask == 0)? 
			if (bitMask)
				goto FoundUsed;

			//	Didn't find any used bits, so we're done with this word.
			++currentWord;
			--wordsLeft;
		}
		
		//
		//	Check whole words
		//
		while (currentBlock < endingBlock)
		{
			//	See if it's time to read another block.
			if (wordsLeft == 0)
			{
				buffer = NULL;
				err = ReleaseBitmapBlock(vcb, blockRef, false);
				if (err != noErr) goto ErrorExit;

				/*
				 * Skip over metadata blocks.
				 */
				if (!useMetaZone) {
					u_int32_t nextBlock;

					nextBlock = NextBitmapBlock(vcb, currentBlock);
					if (nextBlock != currentBlock) {
						goto LoopExit;  /* allocation gap, so stop */
					}
				}

				err = ReadBitmapBlock(vcb, currentBlock, &buffer, &blockRef);
				if ( err != noErr ) goto ErrorExit;
				
				currentWord = buffer;
				wordsLeft = wordsPerBlock;
			}
			
			//	See if any of the bits are set
			if ((tempWord = SWAP_BE32(*currentWord)) != 0)
			{
				//	Figure out which bit is set
				bitMask = kHighBitInWordMask;
				while (!(tempWord & bitMask))
				{
					bitMask >>= 1;
					++currentBlock;
				}
				
				break;		//	Found the used bit; break out to FoundUsed.
			}

			//	Keep looking at the next word
			currentBlock += kBitsPerWord;
			++currentWord;
			--wordsLeft;
			
			//	If we found at least maxBlocks, we can quit early.
			if ((currentBlock - firstBlock) >= maxBlocks)
				break;
		}

FoundUsed:
		//	Make sure we didn't run out of bitmap looking for a used block.
		//	If so, pin to the end of the bitmap.
		if (currentBlock > endingBlock)
			currentBlock = endingBlock;

		//	Figure out how many contiguous free blocks there were.
		//	Pin the answer to maxBlocks.
		foundBlocks = currentBlock - firstBlock;
		if (foundBlocks > maxBlocks)
			foundBlocks = maxBlocks;
		if (foundBlocks >= minBlocks)
			break;		//	Found what we needed!

		/* We did not find the total blocks were were looking for, but 
		 * lets add this free block run to our free extent cache list
		 */
		updated_free_extent = add_free_extent_cache(vcb, firstBlock, foundBlocks);

	} while (currentBlock < stopBlock);
LoopExit:

	//	Return the outputs.
	if (foundBlocks < minBlocks)
	{
DiskFull:
		err = dskFulErr;
ErrorExit:
		*actualStartBlock = 0;
		*actualNumBlocks = 0;
	}
	else
	{
		err = noErr;
		*actualStartBlock = firstBlock;
		*actualNumBlocks = foundBlocks;
		/*
		 * Sanity check for overflow
		 */
		if ((firstBlock + foundBlocks) > vcb->allocLimit) {
			panic("hfs: blk allocation overflow on \"%s\" sb:0x%08x eb:0x%08x cb:0x%08x fb:0x%08x stop:0x%08x min:0x%08x found:0x%08x",
				vcb->vcbVN, startingBlock, endingBlock, currentBlock,
				firstBlock, stopBlock, minBlocks, foundBlocks);
		}
	}
	
	if (updated_free_extent && (vcb->hfs_flags & HFS_HAS_SPARSE_DEVICE)) {
		int i;
		u_int32_t min_start = vcb->totalBlocks;
			
		// set the nextAllocation pointer to the smallest free block number
		// we've seen so on the next mount we won't rescan unnecessarily
		lck_spin_lock(&vcb->vcbFreeExtLock);
		for(i=0; i < (int)vcb->vcbFreeExtCnt; i++) {
			if (vcb->vcbFreeExt[i].startBlock < min_start) {
				min_start = vcb->vcbFreeExt[i].startBlock;
			}
		}
		lck_spin_unlock(&vcb->vcbFreeExtLock);
		if (min_start != vcb->totalBlocks) {
			if (min_start < vcb->nextAllocation) {
				vcb->nextAllocation = min_start;
			}
			if (min_start < vcb->sparseAllocation) {
				vcb->sparseAllocation = min_start;
			}
		}
	}
	
	if (buffer)
		(void) ReleaseBitmapBlock(vcb, blockRef, false);

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_BLOCK_FIND_CONTIG | DBG_FUNC_END, err, *actualStartBlock, *actualNumBlocks, 0, 0);

	return err;
}


#if CONFIG_HFS_ALLOC_RBTREE
/*
 * Wrapper function around hfs_isrbtree_allocated.  This just takes the start offset,
 * and the number of blocks, and whether or not we should check if the blocks are
 * free or not.  This function is designed to be used primarily with the debug #ifdef
 * enabled, so it results in a panic if anything unexpected occurs.
 *
 * shouldBeFree will be nonzero if the caller expects the zone to be free.
 */

void check_rbtree_extents (struct hfsmount *hfsmp, u_int32_t startBlocks,
								 u_int32_t numBlocks, int shouldBeFree) {
	int alloc;
	extent_node_t *node1 = NULL;
	u_int32_t off1 = 0;
	u_int32_t len1 = 0;
	alloc = hfs_isrbtree_allocated (hfsmp, startBlocks, numBlocks, &node1);
	
	if (node1) {
		off1 = node1->offset;
		len1 = node1->length;
	}
	
	if (shouldBeFree) {
		/* 
		 * If the region should be free, then we expect to see extents in the tree
		 * matching this start and length.  Alloc != 0 means some portion of the extent
		 * specified was allocated. 
		 */ 
		if (alloc != 0){
			panic ("HFS check_rbtree_extents: Node (%p) do not exist! "
				   "node1 off (%d),len(%d),, start(%d) end(%d)\n",
				   node1, off1, len1, startBlocks, numBlocks);
		}
	}
	else {
		/* 
		 * Otherwise, this means that the region should be allocated, and if we find
		 * an extent matching it, that's bad.
		 */
		if (alloc == 0){
			panic ("HFS check_rbtree_extents: Node (%p) exists! "
				   "node1 off (%d),len(%d), start(%d) end(%d)\n",
				   node1, off1, len1, startBlocks, numBlocks);
		}
	}
}
#endif

#if CONFIG_HFS_ALLOC_RBTREE
/*
 * Exhaustive validation search.  This function iterates over all allocation blocks and 
 * compares their status in the red-black tree vs. the allocation bitmap.  If the two are out of sync
 * then it will panic.  Bitmap lock must be held while this function is run.
 *
 * Because this function requires a red-black tree search to validate every allocation block, it is
 * very expensive and should ONLY be run in debug mode, and even then, infrequently. 
 * 
 * 'end' is non-inclusive, so it should represent the total number of blocks in the volume.
 * 
 */
void
hfs_validate_rbtree (struct hfsmount *hfsmp, u_int32_t start, u_int32_t end){
	
	u_int32_t current;
	extent_node_t* node1;
	
	hfs_checktreelinks (hfsmp);
	
	for (current = start; current < end; current++) {
		node1 = NULL;
		int rbtree = hfs_isrbtree_allocated(hfsmp, current, 1, &node1);
		int bitmap = hfs_isallocated(hfsmp, current, 1);
		
		if (bitmap != rbtree){
			panic("HFS: Allocator mismatch @ block %d -- bitmap %d : rbtree %d\n", 
				  current, bitmap, rbtree);
		}
	}
}

/*
 * Exhaustive Red-Black Tree Linked List verification routine.  
 *
 * This function iterates through the red-black tree's nodes, and then verifies that the linked list
 * embedded within each of the nodes accurately points to the correct node as its "next" pointer.
 * The bitmap lock must be held while this function is run.
 */

void 
hfs_checktreelinks (struct hfsmount *hfsmp) {
	extent_tree_offset_t *tree = &hfsmp->offset_tree;
	
	extent_node_t *current = NULL;
	extent_node_t *next = NULL;
	extent_node_t *treenext;
	
	current = extent_tree_off_first (tree);
	
	while (current) {
		next = current->offset_next;
		treenext = extent_tree_off_next (tree, current);
		if (next != treenext) {
			panic("hfs_checktreelinks: mismatch for node (%p), next: %p , treenext %p !\n", current, next, treenext);
		}
		current = treenext;
	}
}

#endif


#if CONFIG_HFS_ALLOC_RBTREE
/*
 * Test to see if any free blocks exist at a given offset.
 * If there exists a node at the specified offset, it will return the appropriate
 * node.
 *
 * NULL indicates allocated blocks exist at that offset. 
 * 
 * Allocation file lock must be held.
 *
 * Returns:
 *	1 if blocks in the range are allocated.
 *	0 if all blocks in the range are free.
 */

static int
hfs_isrbtree_allocated (struct hfsmount *hfsmp, u_int32_t startBlock, 
						u_int32_t numBlocks, extent_node_t **ret_node) {
	
	extent_node_t search_sentinel;
	extent_node_t *node = NULL;
	extent_node_t *nextnode = NULL;
	
	/*
	 * With only one tree, then we just have to validate that there are entries 
	 * in the R/B tree at the specified offset if it really is free.
	 */
	search_sentinel.offset = startBlock;
	search_sentinel.length = numBlocks;
	
	node = extent_tree_off_search_prev(&hfsmp->offset_tree, &search_sentinel);
	if (node) {

		*ret_node = node;
		nextnode = extent_tree_off_next (&hfsmp->offset_tree, node);
		if (nextnode != node->offset_next) {
			panic ("hfs_rbtree_isallocated: Next pointers out of sync!\n");
		}
				
		/* 
		 * Check to see if it is a superset of our target range. Because we started
		 * with the offset or some offset prior to it, then we know the node's offset is 
		 * at least <= startBlock.  So, if the end of the node is greater than the end of
		 * our target range, then the whole range is free.
		 */ 
	
		if ((node->offset + node->length) >= (startBlock + numBlocks)) {
			if (node->offset > startBlock) {
				panic ("hfs_rbtree_isallocated: bad node ordering!");
			}	
			return 0;
		}
	}	
	/* 
	 * We got here if either our node search resulted in a node whose extent 
	 * was strictly before our target offset, or we couldnt' find a previous node
	 * at all (the beginning of the volume).  If the former, then we can infer that 
	 * at least one block in the target range is allocated since the next node's offset
	 * must be greater than startBlock.
	 *
	 * Either way, this means that the target node is unavailable to allocate, so
	 * just return 1;
	 */	
	return 1;
}


#endif

/* 
 * Count number of bits set in the given 32-bit unsigned number 
 *
 * Returns:
 * 	Number of bits set
 */
static int num_bits_set(u_int32_t num) 
{
	int count;

	for (count = 0; num; count++) {
		num &= num - 1;
	}

	return count;
}

/* 
 * For a given range of blocks, find the total number of blocks 
 * allocated.  If 'stop_on_first' is true, it stops as soon as it 
 * encounters the first allocated block.  This option is useful 
 * to determine if any block is allocated or not. 
 *
 * Inputs:
 * 	startingBlock	First allocation block number of the range to be scanned.
 * 	numBlocks	Total number of blocks that need to be scanned.
 * 	stop_on_first	Stop the search after the first allocated block is found.
 *
 * Output:
 * 	allocCount	Total number of allocation blocks allocated in the given range.
 *
 * 			On error, it is the number of allocated blocks found 
 * 			before the function got an error. 
 *
 * 			If 'stop_on_first' is set, 
 * 				allocCount = 1 if any allocated block was found.
 * 				allocCount = 0 if no allocated block was found.
 *
 * Returns:
 * 	0 on success, non-zero on failure. 
 */
static int 
hfs_isallocated_internal(struct hfsmount *hfsmp, u_int32_t startingBlock, 
		u_int32_t numBlocks, Boolean stop_on_first, u_int32_t *allocCount)
{
	u_int32_t  *currentWord;   // Pointer to current word within bitmap block
	u_int32_t  wordsLeft;      // Number of words left in this bitmap block
	u_int32_t  bitMask;        // Word with given bits already set (ready to test)
	u_int32_t  firstBit;       // Bit index within word of first bit to allocate
	u_int32_t  numBits;        // Number of bits in word to allocate
	u_int32_t  *buffer = NULL;
	uintptr_t  blockRef;
	u_int32_t  bitsPerBlock;
	u_int32_t  wordsPerBlock;
 	u_int32_t  blockCount = 0;
	int  error;

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_IS_ALLOCATED | DBG_FUNC_START, startingBlock, numBlocks, stop_on_first, 0, 0);

	/*
	 * Pre-read the bitmap block containing the first word of allocation
	 */
	error = ReadBitmapBlock(hfsmp, startingBlock, &buffer, &blockRef);
	if (error)
		goto JustReturn;

	/*
	 * Initialize currentWord, and wordsLeft.
	 */
	{
		u_int32_t wordIndexInBlock;
		
		bitsPerBlock  = hfsmp->vcbVBMIOSize * kBitsPerByte;
		wordsPerBlock = hfsmp->vcbVBMIOSize / kBytesPerWord;

		wordIndexInBlock = (startingBlock & (bitsPerBlock-1)) / kBitsPerWord;
		currentWord = buffer + wordIndexInBlock;
		wordsLeft = wordsPerBlock - wordIndexInBlock;
	}
	
	/*
	 * First test any non word aligned bits.
	 */
	firstBit = startingBlock % kBitsPerWord;
	if (firstBit != 0) {
		bitMask = kAllBitsSetInWord >> firstBit;
		numBits = kBitsPerWord - firstBit;
		if (numBits > numBlocks) {
			numBits = numBlocks;
			bitMask &= ~(kAllBitsSetInWord >> (firstBit + numBits));
		}
		if ((*currentWord & SWAP_BE32 (bitMask)) != 0) {
			if (stop_on_first) {
				blockCount = 1;
				goto Exit;
			}
			blockCount += num_bits_set(*currentWord & SWAP_BE32 (bitMask));
		}
		numBlocks -= numBits;
		++currentWord;
		--wordsLeft;
	}

	/*
	 * Test whole words (32 blocks) at a time.
	 */
	while (numBlocks >= kBitsPerWord) {
		if (wordsLeft == 0) {
			/* Read in the next bitmap block. */
			startingBlock += bitsPerBlock;
			
			buffer = NULL;
			error = ReleaseBitmapBlock(hfsmp, blockRef, false);
			if (error) goto Exit;

			error = ReadBitmapBlock(hfsmp, startingBlock, &buffer, &blockRef);
			if (error) goto Exit;

			/* Readjust currentWord and wordsLeft. */
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
		if (*currentWord != 0) {
			if (stop_on_first) {
				blockCount = 1;
				goto Exit;
			} 
			blockCount += num_bits_set(*currentWord);
		}
		numBlocks -= kBitsPerWord;
		++currentWord;
		--wordsLeft;
	}
	
	/*
	 * Test any remaining blocks.
	 */
	if (numBlocks != 0) {
		bitMask = ~(kAllBitsSetInWord >> numBlocks);
		if (wordsLeft == 0) {
			/* Read in the next bitmap block */
			startingBlock += bitsPerBlock;
			
			buffer = NULL;
			error = ReleaseBitmapBlock(hfsmp, blockRef, false);
			if (error) goto Exit;

			error = ReadBitmapBlock(hfsmp, startingBlock, &buffer, &blockRef);
			if (error) goto Exit;

			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
		if ((*currentWord & SWAP_BE32 (bitMask)) != 0) {
			if (stop_on_first) {
				blockCount = 1;
				goto Exit;
			}
			blockCount += num_bits_set(*currentWord & SWAP_BE32 (bitMask));
		}
	}
Exit:
	if (buffer) {
		(void)ReleaseBitmapBlock(hfsmp, blockRef, false);
	}
	if (allocCount) {
		*allocCount = blockCount;
	}

JustReturn:
	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_IS_ALLOCATED | DBG_FUNC_END, error, 0, blockCount, 0, 0);

	return (error);
}

/* 
 * Count total number of blocks that are allocated in the given 
 * range from the bitmap.  This is used to preflight total blocks 
 * that need to be relocated during volume resize.  
 *
 * The journal or allocation file lock must be held.
 *
 * Returns:
 * 	0 on success, non-zero on failure.  
 * 	On failure, allocCount is zero. 
 */
int
hfs_count_allocated(struct hfsmount *hfsmp, u_int32_t startBlock,
		u_int32_t numBlocks, u_int32_t *allocCount)
{
	return hfs_isallocated_internal(hfsmp, startBlock, numBlocks, false, allocCount);
}

/*
 * Test to see if any blocks in a range are allocated.
 * 
 * Note:  On error, this function returns 1, which means that 
 * one or more blocks in the range are allocated.  This function 
 * is primarily used for volume resize and we do not want 
 * to report to the caller that the blocks are free when we 
 * were not able to deterministically find it out.  So on error, 
 * we always report that the blocks are allocated.  
 *
 * The journal or allocation file lock must be held.
 *
 * Returns 
 *	0 if all blocks in the range are free.
 *	1 if blocks in the range are allocated, or there was an error.
 */
int 
hfs_isallocated(struct hfsmount *hfsmp, u_int32_t startingBlock, u_int32_t numBlocks)
{
	int error; 
	u_int32_t allocCount;

	error = hfs_isallocated_internal(hfsmp, startingBlock, numBlocks, true, &allocCount);
	if (error) {
		/* On error, we always say that the blocks are allocated 
		 * so that volume resize does not return false success.
		 */
		return 1;
	} else {
		/* The function was deterministically able to find out 
		 * if there was any block allocated or not.  In that case,
		 * the value in allocCount is good enough to be returned 
		 * back to the caller.
		 */
		return allocCount;
	}
} 

/*
 * Check to see if the red-black tree is live.  Allocation file lock must be held
 * shared or exclusive to call this function. Note that we may call this even if
 * HFS is built without activating the red-black tree code.
 */
__private_extern__
int 
hfs_isrbtree_active(struct hfsmount *hfsmp){
	
	//TODO: Update this function to deal with a truncate/resize coming in when the tree
	//isn't fully finished.  maybe we need to check the flags for something other than ENABLED?
	
#if CONFIG_HFS_ALLOC_RBTREE
	if (ALLOC_DEBUG) {
		REQUIRE_FILE_LOCK(hfsmp->hfs_allocation_vp, false);
	}
	if (hfsmp){
		
		if (hfsmp->extent_tree_flags & HFS_ALLOC_RB_ENABLED) {
			return 1;
		}
	}
#else
	#pragma unused (hfsmp)
#endif
	/* If the RB Tree code is not enabled, then just always return 0 */
	return 0;
}


/* 
 * This function scans the specified bitmap block and acts on it as necessary.
 * We may add it to the list of blocks to be UNMAP/TRIM'd or add it to allocator
 * data structures.  This function is not #if'd to the CONFIG_RB case because
 * we want to use it unilaterally at mount time if on a UNMAP-capable device.
 * 
 * Additionally, we may want an allocating thread to invoke this if the tree 
 * does not have enough extents to satisfy an allocation request.
 * 
 * startbit		- the allocation block represented by a bit in 'allocblock' where we need to
 *				start our scan.  For instance, we may need to start the normal allocation scan
 *				in the middle of an existing allocation block.
 * endBit		- the allocation block where we should end this search (inclusive).
 * bitToScan	- output argument for this function to specify the next bit to scan.
 *
 * Returns:
 *		0 on success
 *		nonzero on failure. 
 */

static int hfs_alloc_scan_block(struct hfsmount *hfsmp, u_int32_t startbit, 
                                u_int32_t endBit, u_int32_t *bitToScan, 
                                struct jnl_trim_list *list) {
    
	int error;
	u_int32_t curAllocBlock;
	struct buf *blockRef = NULL;
	u_int32_t *buffer = NULL;
	u_int32_t wordIndexInBlock;
	u_int32_t blockSize = (u_int32_t)hfsmp->vcbVBMIOSize;
	u_int32_t wordsPerBlock = blockSize / kBytesPerWord; 
	u_int32_t offset = 0;
	u_int32_t size = 0;
    
	/* 
	 * Read the appropriate block from the bitmap file.  ReadBitmapBlock
	 * figures out which actual on-disk block corresponds to the bit we're 
	 * looking at.
	 */	
	error = ReadBitmapBlock(hfsmp, startbit, &buffer, (uintptr_t*)&blockRef);
	if (error) {
		return error;
	}
	
	/* curAllocBlock represents the logical block we're analyzing. */
	curAllocBlock = startbit;	
    
	/*  Figure out which word curAllocBlock corresponds to in the block we read  */
	wordIndexInBlock = (curAllocBlock / kBitsPerWord) % wordsPerBlock;
	
	/* Scan a word at a time */
	while (wordIndexInBlock < wordsPerBlock) {
		u_int32_t currentWord = SWAP_BE32(buffer[wordIndexInBlock]);
		u_int32_t curBit;
		
		/* modulate curBit because it may start in the middle of a word */
		for (curBit = curAllocBlock % kBitsPerWord; curBit < kBitsPerWord; curBit++) {
			
			u_int32_t is_allocated = currentWord & (1 << (kBitsWithinWordMask - curBit));
			if (ALLOC_DEBUG) {
				u_int32_t res = hfs_isallocated_scan (hfsmp, curAllocBlock, buffer); 
				if ( ((res) && (!is_allocated)) || ((!res) && (is_allocated))) {
					panic("hfs_alloc_scan: curAllocBit %u, curBit (%d), word (0x%x), is_allocated (0x%x)  res(0x%x) \n",
						  curAllocBlock, curBit, currentWord, is_allocated, res);
				}
			}
			/* 
			 * If curBit is not allocated, keep track of the start of the free range.
			 * Increment a running tally on how many free blocks in a row we've seen.
			 */
			if (!is_allocated) {
				size++;
				if (offset == 0) {
					offset = curAllocBlock;
				}
			}
			else {
				/* 
				 * If we hit an allocated block, insert the extent that tracked the range
				 * we saw, and reset our tally counter.
				 */
				if (size != 0) {
#if CONFIG_HFS_ALLOC_RBTREE
					extent_tree_free_space(&hfsmp->offset_tree, size, offset);	
#endif
                    hfs_track_unmap_blocks (hfsmp, offset, size, list);                    
                    size = 0;
                    offset = 0;
				}
			}
			curAllocBlock++;
			/*
			 * Exit early if the next bit we'd analyze would take us beyond the end of the 
			 * range that we're supposed to scan.  
			 */
			if (curAllocBlock >= endBit) {
				goto DoneScanning;
			}
		}
		wordIndexInBlock++;
	}
DoneScanning:
	
	/* We may have been tracking a range of free blocks that hasn't been inserted yet. */
	if (size != 0) {
#if CONFIG_HFS_ALLOC_RBTREE
		extent_tree_free_space(&hfsmp->offset_tree, size, offset);
#endif
        hfs_track_unmap_blocks (hfsmp, offset, size, list);
	}
	/* 
	 * curAllocBlock represents the next block we need to scan while we're in this 
	 * function. 
	 */
	*bitToScan = curAllocBlock;
	
	ReleaseScanBitmapBlock(blockRef);
    
	return 0;
}


/*
 * This function is basically the same as hfs_isallocated, except it's designed for 
 * use with the red-black tree validation code.  It assumes we're only checking whether
 * one bit is active, and that we're going to pass in the buf to use, since GenerateTree
 * calls ReadBitmapBlock and will have that buf locked down for the duration of its operation.
 *
 * This should not be called in general purpose scanning code.
 */
int hfs_isallocated_scan(struct hfsmount *hfsmp, u_int32_t startingBlock, u_int32_t *bp_buf) {
	
	u_int32_t  *currentWord;   // Pointer to current word within bitmap block
	u_int32_t  bitMask;        // Word with given bits already set (ready to test)
	u_int32_t  firstBit;       // Bit index within word of first bit to allocate
	u_int32_t  numBits;        // Number of bits in word to allocate
	u_int32_t  bitsPerBlock;
	uintptr_t  blockRef;
	u_int32_t  wordsPerBlock;
	u_int32_t  numBlocks = 1;
	u_int32_t  *buffer = NULL;

	int  inuse = 0;
	int error;
	
	
	if (bp_buf) {
		/* just use passed-in buffer if avail. */
		buffer = bp_buf;
	}
	else {
		/*
		 * Pre-read the bitmap block containing the first word of allocation
		 */
		error = ReadBitmapBlock(hfsmp, startingBlock, &buffer, &blockRef);
		if (error)
			return (error);
	}
	
	/*
	 * Initialize currentWord, and wordsLeft.
	 */
	u_int32_t wordIndexInBlock;
	
	bitsPerBlock  = hfsmp->vcbVBMIOSize * kBitsPerByte;
	wordsPerBlock = hfsmp->vcbVBMIOSize / kBytesPerWord;
	
	wordIndexInBlock = (startingBlock & (bitsPerBlock-1)) / kBitsPerWord;
	currentWord = buffer + wordIndexInBlock;
		
	/*
	 * First test any non word aligned bits.
	 */
	firstBit = startingBlock % kBitsPerWord;
	bitMask = kAllBitsSetInWord >> firstBit;
	numBits = kBitsPerWord - firstBit;
	if (numBits > numBlocks) {
		numBits = numBlocks;
		bitMask &= ~(kAllBitsSetInWord >> (firstBit + numBits));
	}
	if ((*currentWord & SWAP_BE32 (bitMask)) != 0) {
		inuse = 1;
		goto Exit;
	}
	numBlocks -= numBits;
	++currentWord;
	
Exit:
	if(bp_buf == NULL) {
		if (buffer) {
			(void)ReleaseBitmapBlock(hfsmp, blockRef, false);
		}
	}
	return (inuse);
	
	
	
}

#if CONFIG_HFS_ALLOC_RBTREE

/*
 * Extern function that is called from mount and upgrade mount routines
 * that enable us to initialize the tree.
 */

__private_extern__
u_int32_t InitTree(struct hfsmount *hfsmp) {
	extent_tree_init (&(hfsmp->offset_tree));
	return 0;
}


/*
 * This function builds the trees specified in its arguments. It uses
 * buf_meta_breads to scan through the bitmap and re-build the tree state.
 * It is very important to use buf_meta_bread because we need to ensure that we 
 * read the most current version of the blocks that we're scanning.  If we used 
 * cluster_io, then journaled transactions could still be sitting in RAM since they are
 * written to disk in the proper location asynchronously.  
 *
 * Because this could be still running when mount has finished, we need to check
 * after every allocation block that we're working on if an unmount or some other 
 * operation that would cause us to teardown has come in. (think downgrade mount).
 * If an unmount has come in, then abort whatever we're doing and return -1
 * to indicate we hit an error.  If we don't do this, we'd hold up unmount for
 * a very long time.
 *
 * This function assumes that the bitmap lock is acquired exclusively before being
 * called.  It will drop the lock and then re-acquire it during operation, but 
 * will always return with the lock held.
 */
__private_extern__
u_int32_t GenerateTree(struct hfsmount *hfsmp, u_int32_t endBlock, int *flags, int initialscan) {
	
	REQUIRE_FILE_LOCK(hfsmp->hfs_allocation_vp, false);
	
	u_int32_t *cur_block_eof;
	int error = 0;
	
	int USE_FINE_GRAINED_LOCKING = 0;
		
	/* Initialize the block counter while we hold the bitmap lock */
	cur_block_eof = &hfsmp->offset_block_end;
	
	/*
	 * This loop advances over all allocation bitmap blocks of the current region 
	 * to scan them and add the results into the red-black tree.  We use the mount point
	 * variable offset_block_end as our loop counter.  This gives us flexibility
	 * because we can release the allocation bitmap lock and allow a thread that wants 
	 * to make an allocation to grab the lock and do some scanning on our behalf while we're 
	 * waiting to re-acquire the lock.  Then, the allocating thread will only do as much bitmap 
	 * scanning as needed to fulfill its allocation.
	 * 
	 * If the other thread does IO for us, then it will update the offset_block_end 
	 * variable as well, since it will use the same hfs_alloc_scan_block function to do its bit
	 * scanning.  So when we re-grab the lock, our current EOF/loop will immediately skip us to the next 
	 * block that needs scanning.
	 */
	
	while (*cur_block_eof < endBlock) {

		/* 
		 * If the filesystem is being resized before the bitmap has been fully scanned, we'll 
		 * update our endBlock to match the current allocation limit in the hfsmp struct.
		 * The allocLimit field would only be be updated while holding the bitmap lock, so we won't
		 * be executing this code at the same time that the resize is going on.  
		 */
		if ((initialscan) && (endBlock != hfsmp->allocLimit)) {			
			
			/* If we're past the new/modified allocLimit, then just stop immediately.*/
			if (*cur_block_eof >= hfsmp->allocLimit ) {
				break;
			}
			endBlock = hfsmp->allocLimit;
		}
		
		/* 
		 * TODO: fix unmount stuff!
		 * See rdar://7391404
		 *
		 * Once the RB allocator is checked in, we'll want to augment it to not hold the 
		 * allocation bitmap lock for the entire duration of the tree scan.  For a first check-in
		 * it's ok to do that but we can't leave it like that forever.
		 * 
		 * The gist of the new algorithm will work as follows:
		 * if an unmount is in flight and has been detected:
		 *		abort tree-build.
		 *		unset tree-in-progress bit.
		 *		wakeup unmount thread
		 *		unlock allocation bitmap lock, fail out.
		 *
		 * The corresponding code in the unmount side should already be in place. 
		 */
		
		error = hfs_alloc_scan_block (hfsmp, *cur_block_eof, endBlock, cur_block_eof);
				
		//TODO: Fix this below!
		if (USE_FINE_GRAINED_LOCKING){
			hfs_systemfile_unlock(hfsmp, *flags);
			*flags = hfs_systemfile_lock(hfsmp, SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
		}
		//TODO: Infer that if *flags == 0, we don't actually need to lock/unlock. 
	}
	
	return error;
}

/*
 * This function destroys the specified rb-trees associated with the mount point. 
 */
__private_extern__
void DestroyTrees(struct hfsmount *hfsmp) {
	
	if (ALLOC_DEBUG) {
		REQUIRE_FILE_LOCK(hfsmp->hfs_allocation_vp, false);
		printf("DestroyTrees: Validating red/black tree for vol %s\n", (char*) hfsmp->vcbVN);
		hfs_validate_rbtree (hfsmp, 0, hfsmp->offset_block_end );
	}
	
	/*
	 * extent_tree_destroy will start with the first entry in the tree (by offset), then
	 * iterate through the tree quickly using its embedded linked list.  This results in tree
	 * destruction in O(n) time.
	 */
	
	if (hfsmp->extent_tree_flags & HFS_ALLOC_RB_ENABLED) {
		extent_tree_destroy(&hfsmp->offset_tree);
		
		/* Mark Trees as disabled */
		hfsmp->extent_tree_flags &= ~HFS_ALLOC_RB_ENABLED;		
	}
	
	return;
}	

#endif

/*
 * This function resets all of the data structures relevant to the
 * free extent cache stored in the hfsmount struct.  
 * 
 * If we are using the red-black tree code then we need to account for the fact that 
 * we may encounter situations where we need to jettison the tree.  If that is the 
 * case, then we fail-over to the bitmap scanning logic, but we need to ensure that 
 * the free ext cache is zeroed before we start using it.  
 *
 * We also reset and disable the cache when allocLimit is updated... which 
 * is when a volume is being resized (via hfs_truncatefs() or hfs_extendfs()). 
 * It is independent of the type of allocator being used currently.
 */
void ResetVCBFreeExtCache(struct hfsmount *hfsmp) 
{
	int bytes;
	void *freeExt;

	if (hfs_kdebug_allocation & HFSDBG_EXT_CACHE_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_RESET_EXTENT_CACHE | DBG_FUNC_START, 0, 0, 0, 0, 0);

	lck_spin_lock(&hfsmp->vcbFreeExtLock);
	
	/* reset Free Extent Count */
	hfsmp->vcbFreeExtCnt = 0;
	
	/* reset the actual array */
	bytes = kMaxFreeExtents * sizeof(HFSPlusExtentDescriptor);
	freeExt = (void*)(hfsmp->vcbFreeExt);
	
	bzero (freeExt, bytes);
	
	lck_spin_unlock(&hfsmp->vcbFreeExtLock);

	if (hfs_kdebug_allocation & HFSDBG_EXT_CACHE_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_RESET_EXTENT_CACHE | DBG_FUNC_END, 0, 0, 0, 0, 0);

	return;
}

/*
 * This function is used to inform the allocator if we have to effectively shrink
 * or grow the total number of allocation blocks via hfs_truncatefs or hfs_extendfs. 
 *
 * The bitmap lock must be held when calling this function.  This function also modifies the
 * allocLimit field in the hfs mount point structure in the general case. 
 * 
 * In the shrinking case, we'll have to remove all free extents from the red-black
 * tree past the specified offset new_end_block.  In the growth case, we'll have to force
 * a re-scan of the new allocation blocks from our current allocLimit to the new end block.
 * 
 * new_end_block represents the total number of blocks available for allocation in the resized
 * filesystem.  Block #new_end_block should not be allocatable in the resized filesystem since it
 * will be out of the (0, n-1) range that are indexable in the bitmap.
 *
 * Returns	0 on success
 *			errno on failure
 */
__private_extern__
u_int32_t UpdateAllocLimit (struct hfsmount *hfsmp, u_int32_t new_end_block) {
	
	/* 
	 * Update allocLimit to the argument specified, but don't do anything else 
	 * if the red/black tree is not enabled.
	 */
	hfsmp->allocLimit = new_end_block;

	/* Invalidate the free extent cache completely so that 
	 * it does not have any extents beyond end of current 
	 * volume.
	 */
	ResetVCBFreeExtCache(hfsmp);

#if CONFIG_HFS_ALLOC_RBTREE
	/* Shrinking the existing filesystem */
	if ((new_end_block < hfsmp->offset_block_end) &&
		(hfsmp->extent_tree_flags & HFS_ALLOC_RB_ACTIVE)) {	
		extent_node_t search_sentinel;
		extent_node_t *node = NULL;
		/* Remover points to the current item to free/remove from the tree */
		extent_node_t *remover = NULL;
		
		/* Begin search at the specified offset */
		memset (&search_sentinel, 0, sizeof(extent_node_t));
		search_sentinel.offset = new_end_block;
				
		/* 
		 * Find the first available extent that satifies the allocation by searching
		 * from the starting point or 1 earlier.  We may need to split apart an existing node
		 * if it straddles the new alloc limit.
		 */
		node = extent_tree_off_search_prev(&hfsmp->offset_tree, &search_sentinel);
		if (node) {
			/* If it's an exact match, then just remove them all from this point forward */
			if (node->offset == new_end_block) {
				/* 
				 * Find the previous entry and update its next pointer to NULL
				 * since this entry is biting the dust.  Update remover to node.
				 */
				extent_node_t *prev = NULL;
				prev = extent_tree_off_prev (&hfsmp->offset_tree, node);
				if (prev) {
					prev->offset_next = NULL;
				}
				remover = node;
			}
			else {
				/* See if we need to split this node */
				if ((node->offset + node->length) > new_end_block) {
					/* 
					 * Update node to reflect its new size up until new_end_block.
					 */
					remover = node->offset_next;
					node->length = new_end_block - node->offset;
					/* node is becoming the last free extent in the volume.  */
					node->offset_next = NULL;
				}
				else {
					if (node->offset_next == NULL) {
						/*
						 * 'node' points to the last free extent in the volume. 
						 * Coincidentally, it is also before the new cut-off point at which 
						 * we will stop representing bitmap values in the tree.  Just bail out now.
						 */
						return 0;
					}
					/* 
					 * Otherwise, point our temp variable 'remover' to the node where
					 * we'll need to start yanking things out of the tree, and make 'node' 
					 * the last element in the tree in the linked list.
					 */
					remover = node->offset_next;
					if (remover->offset <= new_end_block) {
						panic ("UpdateAllocLimit: Invalid RBTree node next ptr!");
					}
					node->offset_next = NULL;
				}
			}
			
			/* 
			 * Remover is our "temp" pointer that points to the current node to remove from 
			 * the offset tree.  We'll simply iterate through the tree linked list, removing the current
			 * element from the tree, freeing them as we come across them.
			 */
			while (remover) {
				extent_node_t *next = remover->offset_next;
				extent_tree_remove_node (&hfsmp->offset_tree, remover);
				free_node (remover);
				remover = next;
			}
			
			if (ALLOC_DEBUG) {
				printf ("UpdateAllocLimit: Validating rbtree after truncation\n");
				hfs_validate_rbtree (hfsmp, 0, new_end_block-1);
			}
			
			/* 
			 * Don't forget to shrink offset_block_end after a successful truncation 
			 * new_end_block should represent the number of blocks available on the 
			 * truncated volume.
			 */
			
			hfsmp->offset_block_end = new_end_block;
			
			return 0;
		}
		else {
			if (ALLOC_DEBUG) {
				panic ("UpdateAllocLimit: no prev!");
			}
			return ENOSPC;
		}
	}
	/* Growing the existing filesystem */
	else if ((new_end_block > hfsmp->offset_block_end) &&
		(hfsmp->extent_tree_flags & HFS_ALLOC_RB_ACTIVE)) {	
		int flags = 0;
		int retval = 0;
		
		if (ALLOC_DEBUG) {
			printf ("UpdateAllocLimit: Validating rbtree prior to growth\n");
			hfs_validate_rbtree (hfsmp, 0, hfsmp->offset_block_end);
		}
		
		
		retval = GenerateTree (hfsmp, new_end_block, &flags, 0);
		
		/*
		 * Don't forget to update offset_block_end after a successful tree extension.
		 */
		if (retval == 0) {
			
			if (ALLOC_DEBUG) {
				printf ("UpdateAllocLimit: Validating rbtree after growth\n");
				hfs_validate_rbtree (hfsmp, 0, new_end_block);
			}
			
			hfsmp->offset_block_end = new_end_block;
		}
		
		return retval;
	}
	/* Otherwise, do nothing. fall through to the code below. */	
	printf ("error : off_block_end: %d, alloclimit: %d, new_end_block: %d\n", 
			hfsmp->offset_block_end,hfsmp->allocLimit, new_end_block);
#endif

	return 0;

}


/*
 * Remove an extent from the list of free extents.
 *
 * This is a low-level routine.	 It does not handle overlaps or splitting;
 * that is the responsibility of the caller.  The input extent must exactly
 * match an extent already in the list; it will be removed, and any following
 * extents in the list will be shifted up.
 *
 * Inputs:
 *	startBlock - Start of extent to remove
 *	blockCount - Number of blocks in extent to remove
 *
 * Result:
 *	The index of the extent that was removed.
 */
static void remove_free_extent_list(struct hfsmount *hfsmp, int index)
{
	if (index < 0 || (uint32_t)index >= hfsmp->vcbFreeExtCnt) {
		if (ALLOC_DEBUG)
			panic("hfs: remove_free_extent_list: %p: index (%d) out of range (0, %u)", hfsmp, index, hfsmp->vcbFreeExtCnt);
		else
			printf("hfs: remove_free_extent_list: %p: index (%d) out of range (0, %u)", hfsmp, index, hfsmp->vcbFreeExtCnt);
		return;
	}
	int shift_count = hfsmp->vcbFreeExtCnt - index - 1;
	if (shift_count > 0) {
		memmove(&hfsmp->vcbFreeExt[index], &hfsmp->vcbFreeExt[index+1], shift_count * sizeof(hfsmp->vcbFreeExt[0]));
	}
	hfsmp->vcbFreeExtCnt--;
}


/*
 * Add an extent to the list of free extents.
 *
 * This is a low-level routine.	 It does not handle overlaps or coalescing;
 * that is the responsibility of the caller.  This routine *does* make
 * sure that the extent it is adding is inserted in the correct location.
 * If the list is full, this routine will handle either removing the last
 * extent in the list to make room for the new extent, or ignoring the
 * new extent if it is "worse" than the last extent in the list.
 *
 * Inputs:
 *	startBlock - Start of extent to add
 *	blockCount - Number of blocks in extent to add
 *
 * Result:
 *	The index where the extent that was inserted, or kMaxFreeExtents
 *	if the extent was not inserted (the list was full, and the extent
 *	being added was "worse" than everything in the list).
 */
static int add_free_extent_list(struct hfsmount *hfsmp, u_int32_t startBlock, u_int32_t blockCount)
{
	uint32_t i;
	
	/* ALLOC_DEBUG: Make sure no extents in the list overlap or are contiguous with the input extent. */
	if (ALLOC_DEBUG) {
		uint32_t endBlock = startBlock + blockCount;
		for (i = 0; i < hfsmp->vcbFreeExtCnt; ++i) {
			if (endBlock < hfsmp->vcbFreeExt[i].startBlock ||
				startBlock > (hfsmp->vcbFreeExt[i].startBlock + hfsmp->vcbFreeExt[i].blockCount)) {
					continue;
			}
			panic("hfs: add_free_extent_list: %p: extent(%u %u) overlaps existing extent (%u %u) at index %d",
				hfsmp, startBlock, blockCount, hfsmp->vcbFreeExt[i].startBlock, hfsmp->vcbFreeExt[i].blockCount, i);
		}
	}	 

	/* Figure out what index the new extent should be inserted at. */
	for (i = 0; i < hfsmp->vcbFreeExtCnt; ++i) {
		if (hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
			/* The list is sorted by increasing offset. */
			if (startBlock < hfsmp->vcbFreeExt[i].startBlock) {
				break;
			}
		} else {
			/* The list is sorted by decreasing size. */
			if (blockCount > hfsmp->vcbFreeExt[i].blockCount) {
				break;
			}
		}
	}
	
	/* When we get here, i is the index where the extent should be inserted. */
	if (i == kMaxFreeExtents) {
		/*
		 * The new extent is worse than anything already in the list,
		 * and the list is full, so just ignore the extent to be added.
		 */
		return i;
	}
	
	/*
	 * Grow the list (if possible) to make room for an insert.
	 */
	if (hfsmp->vcbFreeExtCnt < kMaxFreeExtents)
		hfsmp->vcbFreeExtCnt++;
	
	/*
	 * If we'll be keeping any extents after the insert position, then shift them.
	 */
	int shift_count = hfsmp->vcbFreeExtCnt - i - 1;
	if (shift_count > 0) {
		memmove(&hfsmp->vcbFreeExt[i+1], &hfsmp->vcbFreeExt[i], shift_count * sizeof(hfsmp->vcbFreeExt[0]));
	}
	
	/* Finally, store the new extent at its correct position. */
	hfsmp->vcbFreeExt[i].startBlock = startBlock;
	hfsmp->vcbFreeExt[i].blockCount = blockCount;
	return i;
}


/*
 * Remove an entry from free extent cache after it has been allocated.
 *
 * This is a high-level routine.  It handles removing a portion of a
 * cached extent, potentially splitting it into two (if the cache was
 * already full, throwing away the extent that would sort last).  It
 * also handles removing an extent that overlaps multiple extents in
 * the cache.
 *
 * Inputs: 
 *	hfsmp		- mount point structure 
 *	startBlock	- starting block of the extent to be removed. 
 *	blockCount	- number of blocks of the extent to be removed.
 */
static void remove_free_extent_cache(struct hfsmount *hfsmp, u_int32_t startBlock, u_int32_t blockCount)
{
	u_int32_t i, insertedIndex;
	u_int32_t currentStart, currentEnd, endBlock;
	int extentsRemoved = 0;
	
#if CONFIG_HFS_ALLOC_RBTREE
	/* If red-black tree is enabled, no free extent cache is necessary */
	if (hfs_isrbtree_active(hfsmp) == true) {
		return;
	}
#endif
	
	if (hfs_kdebug_allocation & HFSDBG_EXT_CACHE_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_REMOVE_EXTENT_CACHE | DBG_FUNC_START, startBlock, blockCount, 0, 0, 0);
	
	endBlock = startBlock + blockCount;
	
	lck_spin_lock(&hfsmp->vcbFreeExtLock);
	
	/*
	 * Iterate over all of the extents in the free extent cache, removing or
	 * updating any entries that overlap with the input extent.
	 */
	for (i = 0; i < hfsmp->vcbFreeExtCnt; ++i) {
		currentStart = hfsmp->vcbFreeExt[i].startBlock;
		currentEnd = currentStart + hfsmp->vcbFreeExt[i].blockCount;
		
		/*
		 * If the current extent is entirely before or entirely after the
		 * the extent to be removed, then we keep it as-is.
		 */
		if (currentEnd <= startBlock || currentStart >= endBlock) {
			continue;
		}
		
		/*
		 * If the extent being removed entirely contains the current extent,
		 * then remove the current extent.
		 */
		if (startBlock <= currentStart && endBlock >= currentEnd) {
			remove_free_extent_list(hfsmp, i);
			
			/*
			 * We just removed the extent at index i.  The extent at
			 * index i+1 just got shifted to index i.  So decrement i
			 * to undo the loop's "++i", and the next iteration will
			 * examine index i again, which contains the next extent
			 * in the list.
			 */
			--i;
			++extentsRemoved;
			continue;
		}
		
		/*
		 * If the extent being removed is strictly "in the middle" of the
		 * current extent, then we need to split the current extent into
		 * two discontiguous extents (the "head" and "tail").  The good
		 * news is that we don't need to examine any other extents in
		 * the list.
		 */
		if (startBlock > currentStart && endBlock < currentEnd) {
			remove_free_extent_list(hfsmp, i);
			add_free_extent_list(hfsmp, currentStart, startBlock - currentStart);
			add_free_extent_list(hfsmp, endBlock, currentEnd - endBlock);
			break;
		}
		
		/*
		 * The only remaining possibility is that the extent to be removed
		 * overlaps the start or end (but not both!) of the current extent.
		 * So we need to replace the current extent with a shorter one.
		 *
		 * The only tricky part is that the updated extent might be at a
		 * different index than the original extent.  If the updated extent
		 * was inserted after the current extent, then we need to re-examine
		 * the entry at index i, since it now contains the extent that was
		 * previously at index i+1.	 If the updated extent was inserted
		 * before or at the same index as the removed extent, then the
		 * following extents haven't changed position.
		 */
		remove_free_extent_list(hfsmp, i);
		if (startBlock > currentStart) {
			/* Remove the tail of the current extent. */
			insertedIndex = add_free_extent_list(hfsmp, currentStart, startBlock - currentStart);
		} else {
			/* Remove the head of the current extent. */
			insertedIndex = add_free_extent_list(hfsmp, endBlock, currentEnd - endBlock);
		}
		if (insertedIndex > i) {
			--i;	/* Undo the "++i" in the loop, so we examine the entry at index i again. */
		}
	}
	
	lck_spin_unlock(&hfsmp->vcbFreeExtLock);
	
	sanity_check_free_ext(hfsmp, 0);
	
	if (hfs_kdebug_allocation & HFSDBG_EXT_CACHE_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_REMOVE_EXTENT_CACHE | DBG_FUNC_END, 0, 0, 0, extentsRemoved, 0);
	
	return;
}


/*
 * Add an entry to free extent cache after it has been deallocated.	 
 *
 * This is a high-level routine.  It will merge overlapping or contiguous
 * extents into a single, larger extent.
 *
 * If the extent provided has blocks beyond current allocLimit, it is
 * clipped to allocLimit (so that we won't accidentally find and allocate
 * space beyond allocLimit).
 *
 * Inputs: 
 *	hfsmp		- mount point structure 
 *	startBlock	- starting block of the extent to be removed. 
 *	blockCount	- number of blocks of the extent to be removed.
 *
 * Returns:
 *	true		- if the extent was added successfully to the list
 *	false		- if the extent was not added to the list, maybe because 
 *			  the extent was beyond allocLimit, or is not best 
 *			  candidate to be put in the cache.
 */
static Boolean add_free_extent_cache(struct hfsmount *hfsmp, u_int32_t startBlock, u_int32_t blockCount)
{
	Boolean retval = false;
	uint32_t endBlock;
	uint32_t currentEnd;
	uint32_t i; 
	
	if (hfs_kdebug_allocation & HFSDBG_EXT_CACHE_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ADD_EXTENT_CACHE | DBG_FUNC_START, startBlock, blockCount, 0, 0, 0);
	
	/*
	 * If using the red-black tree allocator, then there's no need to special case 
	 * for the sparse device case.	We'll simply add the region we've recently freed
	 * to the red-black tree, where it will get sorted by offset and length.  The only special 
	 * casing will need to be done on the allocation side, where we may favor free extents
	 * based on offset even if it will cause fragmentation.	 This may be true, for example, if
	 * we are trying to reduce the number of bandfiles created in a sparse bundle disk image. 
	 */
#if CONFIG_HFS_ALLOC_RBTREE
	if (hfs_isrbtree_active(hfsmp) == true) {
		goto out_not_locked;
	}
#endif
	
	/* No need to add extent that is beyond current allocLimit */
	if (startBlock >= hfsmp->allocLimit) {
		goto out_not_locked;
	}
	
	/* If end of the free extent is beyond current allocLimit, clip the extent */
	if ((startBlock + blockCount) > hfsmp->allocLimit) {
		blockCount = hfsmp->allocLimit - startBlock;
	}
	
	lck_spin_lock(&hfsmp->vcbFreeExtLock);
	
	/*
	 * Make a pass through the free extent cache, looking for known extents that
	 * overlap or are contiguous with the extent to be added.  We'll remove those
	 * extents from the cache, and incorporate them into the new extent to be added.
	 */
	endBlock = startBlock + blockCount;
	for (i=0; i < hfsmp->vcbFreeExtCnt; ++i) {
		currentEnd = hfsmp->vcbFreeExt[i].startBlock + hfsmp->vcbFreeExt[i].blockCount;
		if (hfsmp->vcbFreeExt[i].startBlock > endBlock || currentEnd < startBlock) {
			/* Extent i does not overlap and is not contiguous, so keep it. */
			continue;
		} else {
			/* We need to remove extent i and combine it with the input extent. */
			if (hfsmp->vcbFreeExt[i].startBlock < startBlock)
				startBlock = hfsmp->vcbFreeExt[i].startBlock;
			if (currentEnd > endBlock)
				endBlock = currentEnd;
			
			remove_free_extent_list(hfsmp, i);
			/*
			 * We just removed the extent at index i.  The extent at
			 * index i+1 just got shifted to index i.  So decrement i
			 * to undo the loop's "++i", and the next iteration will
			 * examine index i again, which contains the next extent
			 * in the list.
			 */
			--i;
		}
	}
	add_free_extent_list(hfsmp, startBlock, endBlock - startBlock);
	
	lck_spin_unlock(&hfsmp->vcbFreeExtLock);
	
out_not_locked:
	sanity_check_free_ext(hfsmp, 0);
	
	if (hfs_kdebug_allocation & HFSDBG_EXT_CACHE_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ADD_EXTENT_CACHE | DBG_FUNC_END, 0, 0, 0, retval, 0);
	
	return retval;
}

/* Debug function to check if the free extent cache is good or not */
static void sanity_check_free_ext(struct hfsmount *hfsmp, int check_allocated)
{
	u_int32_t i, j;

	/* Do not do anything if debug is not on, or if we're using the red-black tree */
	if ((ALLOC_DEBUG == 0) || (hfs_isrbtree_active(hfsmp) == true)) {
		return;
	}

	lck_spin_lock(&hfsmp->vcbFreeExtLock);
	
	if (hfsmp->vcbFreeExtCnt > kMaxFreeExtents)
		panic("hfs: %p: free extent count (%u) is too large", hfsmp, hfsmp->vcbFreeExtCnt);
	
	/* 
	 * Iterate the Free extent cache and ensure no entries are bogus or refer to
	 * allocated blocks.
	 */
	for(i=0; i < hfsmp->vcbFreeExtCnt; i++) {
		u_int32_t start, nblocks;

		start   = hfsmp->vcbFreeExt[i].startBlock;
		nblocks = hfsmp->vcbFreeExt[i].blockCount;

		//printf ("hfs: %p: slot:%d (%u,%u)\n", hfsmp, i, start, nblocks);

		/* Check if any of the blocks in free extent cache are allocated.  
		 * This should not be enabled always because it might take 
		 * very long for large extents that get added to the list.
		 *
		 * We have to drop vcbFreeExtLock while we call hfs_isallocated
		 * because it is going to do I/O.  Note that the free extent
		 * cache could change.  That's a risk we take when using this
		 * debugging code.  (Another alternative would be to try to
		 * detect when the free extent cache changed, and perhaps
		 * restart if the list changed while we dropped the lock.)
		 */
		if (check_allocated) {
			lck_spin_unlock(&hfsmp->vcbFreeExtLock);
			if (hfs_isallocated(hfsmp, start, nblocks)) {
				panic("hfs: %p: slot %d:(%u,%u) in the free extent array is allocated\n",
					  hfsmp, i, start, nblocks);
			}
			lck_spin_lock(&hfsmp->vcbFreeExtLock);
		}

		/* Check if any part of the extent is beyond allocLimit */
		if ((start > hfsmp->allocLimit) || ((start + nblocks) > hfsmp->allocLimit)) {
			panic ("hfs: %p: slot %d:(%u,%u) in the free extent array is beyond allocLimit=%u\n",
					hfsmp, i, start, nblocks, hfsmp->allocLimit);
		}

		/* Check if there are any duplicate start blocks */
		for(j=i+1; j < hfsmp->vcbFreeExtCnt; j++) {
			if (start == hfsmp->vcbFreeExt[j].startBlock) {
				panic("hfs: %p: slot %d:(%u,%u) and %d:(%u,%u) are duplicate\n", 
				      hfsmp, i, start, nblocks, j, hfsmp->vcbFreeExt[j].startBlock, 
				      hfsmp->vcbFreeExt[j].blockCount);
			}
		}

		/* Check if the entries are out of order */
		if ((i+1) != hfsmp->vcbFreeExtCnt) {
			if (hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
				/* sparse devices are sorted by starting block number (ascending) */
				if (hfsmp->vcbFreeExt[i].startBlock > hfsmp->vcbFreeExt[i+1].startBlock) {
					panic ("hfs: %p: SPARSE %d:(%u,%u) and %d:(%u,%u) are out of order\n", 
						hfsmp, i, start, nblocks, i+1, hfsmp->vcbFreeExt[i+1].startBlock, 
						hfsmp->vcbFreeExt[i+1].blockCount);
				}
			} else {
				/* normally sorted by block count (descending) */
				if (hfsmp->vcbFreeExt[i].blockCount < hfsmp->vcbFreeExt[i+1].blockCount) {
					panic ("hfs: %p: %d:(%u,%u) and %d:(%u,%u) are out of order\n", 
						hfsmp, i, start, nblocks, i+1, hfsmp->vcbFreeExt[i+1].startBlock, 
						hfsmp->vcbFreeExt[i+1].blockCount);
				}
			}
		}
	}
	lck_spin_unlock(&hfsmp->vcbFreeExtLock);
}
