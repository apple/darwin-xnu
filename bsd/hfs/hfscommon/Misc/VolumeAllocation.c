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

	ScanUnmapBlocks	
					Traverse the entire allocation bitmap.  Potentially issue DKIOCUNMAPs to the device as it 
					tracks unallocated ranges when iterating the volume bitmap.  Additionally, build up the in-core
					summary table of the allocation bitmap.
 
Internal routines:
	BlockMarkFreeInternal
					Mark a contiguous range of blocks as free.  The corresponding
					bits in the volume bitmap will be cleared.  This will actually do the work
					of modifying the bitmap for us.
					
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
	BlockAllocateContig
					Find and allocate a contiguous range of blocks of a given size.  If
					a contiguous range of free blocks of the given size isn't found, then
					the allocation fails (i.e. it is "all or nothing"). 
	BlockAllocateKnown
					Try to allocate space from known free space in the volume's
					free extent cache.
	ReadBitmapBlock
					Given an allocation block number, read the bitmap block that
					contains that allocation block into a caller-supplied buffer.

	ReleaseBitmapBlock
					Release a bitmap block back into the buffer cache.
	
	ReadBitmapRange
					Given an allocation block number, read a range of bitmap that
					must begin at that allocation block into a caller supplied buffer.

	ReleaseBitmapRange
					Release and invalidate a buf_t corresponding to the bitmap
					back into the UBC in order to prevent coherency issues.

	remove_free_extent_cache
					Remove an extent from the free extent cache.  Handles overlaps
					with multiple extents in the cache, and handles splitting an
					extent in the cache if the extent to be removed is in the middle
					of a cached extent.
	
	add_free_extent_cache
					Add an extent to the free extent cache.  It will merge the
					input extent with extents already in the cache.
	CheckUnmappedBytes
					Check whether or not the current transaction
					has allocated blocks that were recently freed. This may have data safety implications.


 
Debug/Test Routines
	hfs_isallocated
					Test to see if any blocks in a range are allocated.  Journal or
					allocation file lock must be held.
 
	hfs_isallocated_scan
					Test to see if any blocks in a range are allocated.  Releases and
					invalidates the block used when finished.
	 
Optimization Routines 
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
#include <sys/malloc.h>

/* For VM Page size */
#include <libkern/libkern.h>

#include "../../hfs.h"
#include "../../hfs_dbg.h"
#include "../../hfs_format.h"
#include "../../hfs_endian.h"
#include "../../hfs_macos_defs.h"
#include "../headers/FileMgrInternal.h"
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

#define HFS_MIN_SUMMARY_BLOCKSIZE 4096

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
		u_int32_t		flags,
		Boolean			trustSummary,
		u_int32_t		*actualStartBlock,
		u_int32_t		*actualNumBlocks);

static OSErr BlockAllocateAnyBitmap(
		ExtendedVCB		*vcb,
		u_int32_t		startingBlock,
		u_int32_t		endingBlock,
		u_int32_t		maxBlocks,
		u_int32_t		flags,
		u_int32_t		*actualStartBlock,
		u_int32_t		*actualNumBlocks);

static OSErr BlockAllocateContig(
		ExtendedVCB		*vcb,
		u_int32_t		startingBlock,
		u_int32_t		minBlocks,
		u_int32_t		maxBlocks,
		u_int32_t		flags,
		u_int32_t		*actualStartBlock,
		u_int32_t		*actualNumBlocks);

static OSErr BlockFindContiguous(
		ExtendedVCB		*vcb,
		u_int32_t		startingBlock,
		u_int32_t		endingBlock,
		u_int32_t		minBlocks,
		u_int32_t		maxBlocks,
		Boolean			useMetaZone,
		Boolean			trustSummary,
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


static OSErr ReadBitmapRange (struct hfsmount *hfsmp, uint32_t offset, uint32_t iosize,
		uint32_t **buffer, struct buf **blockRef);

static OSErr ReleaseScanBitmapRange( struct buf *bp );

static int hfs_track_unmap_blocks (struct hfsmount *hfsmp, u_int32_t offset, 
		u_int32_t numBlocks, struct jnl_trim_list *list);

static int hfs_issue_unmap (struct hfsmount *hfsmp, struct jnl_trim_list *list);

static int hfs_alloc_scan_range(struct hfsmount *hfsmp, 
		u_int32_t startbit, 
		u_int32_t *bitToScan,
		struct jnl_trim_list *list);

static int hfs_scan_range_size (struct hfsmount* hfsmp, uint32_t start, uint32_t *iosize);
static uint32_t CheckUnmappedBytes (struct hfsmount *hfsmp, uint64_t blockno, uint64_t numblocks, int *recent, uint32_t *next);

/* Bitmap Re-use Detection */
static inline int extents_overlap (uint32_t start1, uint32_t len1,
		uint32_t start2, uint32_t len2) {
	return !( ((start1 + len1) <= start2) || ((start2 + len2) <= start1) );
}


int hfs_isallocated_scan (struct hfsmount *hfsmp,
		u_int32_t startingBlock,
		u_int32_t *bp_buf);

/* Summary Table Functions */
static int hfs_set_summary (struct hfsmount *hfsmp, uint32_t summarybit, uint32_t inuse);
static int hfs_get_summary_index (struct hfsmount *hfsmp, uint32_t block, uint32_t *index);
static int hfs_find_summary_free (struct hfsmount *hfsmp, uint32_t block, uint32_t *newblock);
static int hfs_get_summary_allocblock (struct hfsmount *hfsmp, uint32_t summarybit, uint32_t *alloc);
static int hfs_release_summary (struct hfsmount *hfsmp, uint32_t start, uint32_t length);
static int hfs_check_summary (struct hfsmount *hfsmp, uint32_t start, uint32_t *freeblocks);
static int hfs_rebuild_summary (struct hfsmount *hfsmp);

#if 0
static int hfs_get_next_summary (struct hfsmount *hfsmp, uint32_t block, uint32_t *newblock);
#endif

/* Used in external mount code to initialize the summary table */
int hfs_init_summary (struct hfsmount *hfsmp);

#if ALLOC_DEBUG 
void hfs_validate_summary (struct hfsmount *hfsmp);
#endif


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
			printf("hfs_unmap_free_ext: ignoring trim vol=%s @ off %lld len %lld \n", hfsmp->vcbVN, offset, length);
			err = EINVAL;
		}

		if (err == 0) {
			err = journal_trim_add_extent(hfsmp->jnl, offset, length);
			if (err) {
				printf("hfs_unmap_free_extent: error %d from journal_trim_add_extent for vol=%s", err, hfsmp->vcbVN);
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

static int hfs_issue_unmap (struct hfsmount *hfsmp, struct jnl_trim_list *list) 
{
	dk_unmap_t unmap;
	int error = 0;

	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED) {
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_SCAN_TRIM | DBG_FUNC_START, hfsmp->hfs_raw_dev, 0, 0, 0, 0);
	}

	if (list->extent_count > 0) {
		bzero(&unmap, sizeof(unmap));
		unmap.extents = list->extents;
		unmap.extentsCount = list->extent_count;

		if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED) {
			KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_SCAN_TRIM | DBG_FUNC_NONE, hfsmp->hfs_raw_dev, unmap.extentsCount, 0, 0, 0);
		}
	
#if CONFIG_PROTECT
		/* 
		 * If we have not yet completed the first scan through the bitmap, then
		 * optionally inform the block driver below us that this is an initialization
		 * TRIM scan, if it can deal with this information.
		 */
		if ((hfsmp->scan_var & HFS_ALLOCATOR_SCAN_COMPLETED) == 0) {
			unmap.options |= _DK_UNMAP_INITIALIZE;	
		}
#endif
		/* Issue a TRIM and flush them out */
		error = VNOP_IOCTL(hfsmp->hfs_devvp, DKIOCUNMAP, (caddr_t)&unmap, 0, vfs_context_kernel());

		bzero (list->extents, (list->allocated_count * sizeof(dk_extent_t)));
		bzero (&unmap, sizeof(unmap));
		list->extent_count = 0;
	}

	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED) {
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_SCAN_TRIM | DBG_FUNC_END, error, hfsmp->hfs_raw_dev, 0, 0, 0);
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
			printf("hfs_unmap_alloc_extent: error %d from journal_trim_remove_extent for vol=%s", err, hfsmp->vcbVN);
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
   ; Routine:		CheckUnmappedBytes
   ;
   ; Function:	From the specified inputs, determine if the extent in question overlaps 
   ;				space that was recently freed, where the recently freed space may still be
   ;				lingering in an uncommitted journal transaction.  This may have data safety 
   ;				implications.  The intended use is to decide whether or not to force a journal flush
   ;				before allowing file data I/O to be issued.  If we did not do this
   ;				then it would be possible to issue the file I/O ahead of the
   ;				journal, resulting in data being overwritten if the transaction either
   ;				is not committed or cannot be replayed.
   ;
   ;		NOTE: This function assumes that the journal and catalog/extent locks are held.
   ;
   ; Input Arguments:
   ;	hfsmp			- The volume containing the allocation blocks.
   ;	foffset			- start of the extent in question (in allocation blocks)
   ;	numbytes		- number of blocks in the extent.
   ;  recently_freed:	- output pointer containing whether or not the blocks were freed recently
   ;  overlap_end 		- end of the overlap between the argument extent and the trim list (in allocation blocks)
   ;
   ; Output:
   ;
   ; 		Returns 0 if we could determine extent validity for this (or a previous transaction)
   ; 		Returns errno if there was an error
   ;
   ;		If returned 0, then recently freed will contain a boolean that indicates
   ;		that it was recently freed.
   ;________________________________________________________________________________
 */

u_int32_t
CheckUnmappedBytes (struct hfsmount *hfsmp, uint64_t blockno, uint64_t numblocks, int *recently_freed, uint32_t *overlap_end) {
	uint64_t device_offset;
	uint64_t numbytes;
	uint32_t err = 0;
	uint64_t lba_overlap_end;

	if (hfsmp->jnl != NULL) {
		/*
		 * Convert the allocation block # and the number of blocks into device-relative
		 * offsets so that they can be compared using the TRIM list.
		 */
		uint64_t device_sz = hfsmp->hfs_logical_bytes;
		device_offset = blockno * ((uint64_t)hfsmp->blockSize);
		device_offset += hfsmp->hfsPlusIOPosOffset;
		numbytes = (((uint64_t)hfsmp->blockSize) * numblocks);

		/* 
		 * Since we check that the device_offset isn't too large, it's safe to subtract it
		 * from the size in the second check.
		 */
		if ((device_offset >= device_sz) || (numbytes > (device_sz - device_offset))) {
			return EINVAL;
		}

		/* Ask the journal if this extent overlaps with any pending TRIMs */
		if (journal_trim_extent_overlap (hfsmp->jnl, device_offset, numbytes, &lba_overlap_end)) {
			*recently_freed = 1;

			/* Convert lba_overlap_end back into allocation blocks */
			uint64_t end_offset = lba_overlap_end - hfsmp->hfsPlusIOPosOffset;
			end_offset = end_offset / ((uint64_t) hfsmp->blockSize);
			*overlap_end = (uint32_t) end_offset;
		}
		else {
			*recently_freed = 0;
		}
		err = 0;
	}
	else {
		/* There may not be a journal.  In that case, always return success.  */
		*recently_freed = 0;
	}
	return err;

}


/*
 ;________________________________________________________________________________
 ;
 ; Routine:		ScanUnmapBlocks
 ;
 ; Function:	Traverse the bitmap, and potentially issue DKIOCUNMAPs to the underlying
 ;				device as needed so that the underlying disk device is as
 ;				up-to-date as possible with which blocks are unmapped.
 ;				Additionally build up the summary table as needed.
 ;
 ;				This function reads the bitmap in large block size 
 ; 				(up to 1MB) unlink the runtime which reads the bitmap 
 ; 				in 4K block size.  So if this function is being called 
 ;				after the volume is mounted and actively modified, the 
 ;				caller needs to invalidate all of the existing buffers 
 ;				associated with the bitmap vnode before calling this 
 ; 				function.  If the buffers are not invalidated, it can 
 ;				cause but_t collision and potential data corruption.
 ;  
 ; Input Arguments:
 ;	hfsmp			- The volume containing the allocation blocks.
 ;________________________________________________________________________________
 */

__private_extern__
u_int32_t ScanUnmapBlocks (struct hfsmount *hfsmp) 
{
	u_int32_t blocks_scanned = 0;
	int error = 0;
	struct jnl_trim_list trimlist;

	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED) {
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_SCAN | DBG_FUNC_START, hfsmp->hfs_raw_dev, 0, 0, 0, 0);
	}

	/*
	 *struct jnl_trim_list {
	 uint32_t    allocated_count;
	 uint32_t    extent_count;
	 dk_extent_t *extents;
	 };
	 */

	/* 
	 * The scanning itself here is not tied to the presence of CONFIG_HFS_TRIM
	 * which is now enabled for most architectures.  Instead, any trim related 
	 * work should be tied to whether the underlying storage media supports 
	 * UNMAP, as any solid state device would on desktop or embedded.
	 * 
	 * We do this because we may want to scan the full bitmap on desktop
	 * for spinning media for the purposes of building up the 
	 * summary table. 
	 * 
	 * We also avoid sending TRIMs down to the underlying media if the mount is read-only.
	 */

	if ((hfsmp->hfs_flags & HFS_UNMAP) && 
			((hfsmp->hfs_flags & HFS_READ_ONLY) == 0)) {
		/* If the underlying device supports unmap and the mount is read-write, initialize */
		int alloc_count = PAGE_SIZE / sizeof(dk_extent_t);
		void *extents = kalloc (alloc_count * sizeof(dk_extent_t));
		if (extents == NULL) {
			return ENOMEM;
		}
		bzero (&trimlist, sizeof(trimlist));
		trimlist.extents = (dk_extent_t*)extents;
		trimlist.allocated_count = alloc_count;
		trimlist.extent_count = 0;
	}

	while ((blocks_scanned < hfsmp->totalBlocks) && (error == 0)){

		error = hfs_alloc_scan_range (hfsmp, blocks_scanned, &blocks_scanned, &trimlist);

		if (error) {
			printf("HFS: bitmap scan range error: %d on vol=%s\n", error, hfsmp->vcbVN);
			break;
		}
	}

	if ((hfsmp->hfs_flags & HFS_UNMAP) && 
			((hfsmp->hfs_flags & HFS_READ_ONLY) == 0)) {
		if (error == 0) {
			hfs_issue_unmap(hfsmp, &trimlist);
		}
		if (trimlist.extents) {
			kfree (trimlist.extents, (trimlist.allocated_count * sizeof(dk_extent_t)));
		}
	}

	/* 
	 * This is in an #if block because hfs_validate_summary prototype and function body
	 * will only show up if ALLOC_DEBUG is on, to save wired memory ever so slightly.
	 */
#if ALLOC_DEBUG
	sanity_check_free_ext(hfsmp, 1);
	if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
		/* Validate the summary table too! */
		hfs_validate_summary(hfsmp);
		printf("HFS: Summary validation complete on %s\n", hfsmp->vcbVN);
	}
#endif

	if (hfs_kdebug_allocation & HFSDBG_UNMAP_ENABLED) {
		KERNEL_DEBUG_CONSTANT(HFSDBG_UNMAP_SCAN | DBG_FUNC_END, error, hfsmp->hfs_raw_dev, 0, 0, 0);
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
 ;	 *actualBlccks	 - Actual number of allocation blocks allocated
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
		u_int32_t		*actualNumBlocks)	
/*
 *  actualNumBlocks is the number of blocks actually allocated; 
 * if forceContiguous was zero, then this may represent fewer than minBlocks 
 */
{
	u_int32_t  freeBlocks;
	OSErr			err;
	Boolean			updateAllocPtr = false;		//	true if nextAllocation needs to be updated
	struct hfsmount	*hfsmp;
	Boolean useMetaZone;
	Boolean forceContiguous;
	Boolean forceFlush;

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

	if (flags & HFS_ALLOC_FLUSHTXN) {
		forceFlush = true;
	}
	else {
		forceFlush = false;
	}


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
		hfs_lock_mount (hfsmp);

		/* Sparse Allocation and nextAllocation are both used even if the R/B Tree is on */
		if (vcb->hfs_flags & HFS_HAS_SPARSE_DEVICE) {
			startingBlock = vcb->sparseAllocation;
		} 
		else {
			startingBlock = vcb->nextAllocation;
		}
		hfs_unlock_mount(hfsmp);
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
				flags, actualStartBlock, actualNumBlocks);
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

		/* Disable HFS_ALLOC_FLUSHTXN if needed */
		if (forceFlush) {
			flags &= ~HFS_ALLOC_FLUSHTXN;
		}

		/* 
		 * BlockAllocateKnown only examines the free extent cache; anything in there will
		 * have been committed to stable storage already.
		 */
		err = BlockAllocateKnown(vcb, maxBlocks, actualStartBlock, actualNumBlocks);

		/* dskFulErr out of BlockAllocateKnown indicates an empty Free Extent Cache */

		if (err == dskFulErr) {
			/* 
			 * Now we have to do a bigger scan.  Start at startingBlock and go up until the
			 * allocation limit.  We 'trust' the summary bitmap in this call, if it tells us
			 * that it could not find any free space.
			 */
			err = BlockAllocateAny(vcb, startingBlock, vcb->allocLimit,
					maxBlocks, flags, true, 
					actualStartBlock, actualNumBlocks);
		}
		if (err == dskFulErr) {
			/*
			 * Vary the behavior here if the summary table is on or off.  
			 * If it is on, then we don't trust it it if we get into this case and
			 * basically do a full scan for maximum coverage.
			 * If it is off, then we trust the above and go up until the startingBlock.
			 */
			if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
				err = BlockAllocateAny(vcb, 1, vcb->allocLimit, maxBlocks,
						flags, false, 
						actualStartBlock, actualNumBlocks);
			}
			else {
				err = BlockAllocateAny(vcb, 1, startingBlock, maxBlocks,
						flags, false, 
						actualStartBlock, actualNumBlocks);
			}	

			/*
		     * Last Resort: Find/use blocks that may require a journal flush.
	 		 */		 
			if (err == dskFulErr && forceFlush) {
				flags |= HFS_ALLOC_FLUSHTXN;
				err = BlockAllocateAny(vcb, 1, vcb->allocLimit, maxBlocks,
						flags, false, 
						actualStartBlock, actualNumBlocks);
			}
		}
	}

Exit:
	if ((hfsmp->hfs_flags & HFS_CS) && *actualNumBlocks != 0) {
		errno_t ec;
		_dk_cs_map_t cm;
		uint64_t mapped_blocks;

		cm.cm_extent.offset = (uint64_t)*actualStartBlock * hfsmp->blockSize + hfsmp->hfsPlusIOPosOffset;
		cm.cm_extent.length = (uint64_t)*actualNumBlocks * hfsmp->blockSize;
		cm.cm_bytes_mapped = 0;
		ec = VNOP_IOCTL(hfsmp->hfs_devvp, _DKIOCCSMAP, (caddr_t)&cm, 0, vfs_context_current());
		if (ec != 0 && ec != ENOSPC) {
			printf ("VNOP_IOCTL(_DKIOCCSMAP) returned an unexpected error code=%d\n", ec);
			err = ec;
			goto Exit_CS;
		}
		mapped_blocks = cm.cm_bytes_mapped / hfsmp->blockSize;
		/* CoreStorage returned more blocks than requested */
		if (mapped_blocks > *actualNumBlocks) {
			printf ("VNOP_IOCTL(_DKIOCCSMAP) mapped too many blocks, mapped=%lld, actual=%d\n", 
					mapped_blocks, *actualNumBlocks);
		}
		if (*actualNumBlocks > mapped_blocks) {
			if (forceContiguous && mapped_blocks < minBlocks) {
				mapped_blocks = 0;
			}
		}
		uint64_t numBlocksToFree = *actualNumBlocks - mapped_blocks;
		uint64_t firstBlockToFree = *actualStartBlock + mapped_blocks;
		if (numBlocksToFree > 0) {
			err = BlockDeallocate(vcb, firstBlockToFree, numBlocksToFree, flags);
			if (err != noErr) {
				printf ("BlockDeallocate failed (err=%d)\n", err);
				goto Exit_CS;
			}
		}
		*actualNumBlocks = mapped_blocks;
		if (*actualNumBlocks == 0 && err == noErr) {
			err = dskFulErr;
		}
	}
Exit_CS: 
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
		hfs_lock_mount (hfsmp);

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
		hfs_unlock_mount(hfsmp);

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
	 * If we're using the summary bitmap, then try to mark the bits
	 * as potentially usable/free before actually deallocating them.
	 * It is better to be slightly speculative here for correctness.
	 */

	(void) hfs_release_summary (hfsmp, firstBlock, numBlocks);

	err = BlockMarkFreeInternal(vcb, firstBlock, numBlocks, true);

	if (err) {
		goto Exit;
	}

	//
	//	Update the volume's free block count, and mark the VCB as dirty.
	//
	hfs_lock_mount(hfsmp);
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
	hfs_unlock_mount(hfsmp);

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

	/* HFS+ / HFSX */
	if (vcb->vcbSigWord != kHFSSigWord) {
		vp = vcb->hfs_allocation_vp;	/* use allocation file vnode */
	} 
#if CONFIG_HFS_STD
	else {
		/* HFS Standard */	
		vp = VCBTOHFS(vcb)->hfs_devvp;	/* use device I/O vnode */
		block += vcb->vcbVBMSt;			/* map to physical block */
	}
#endif

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
; Routine:	ReadBitmapRange
;
; Function:	Read in a range of the bitmap starting at the given offset. 
;			Use the supplied size to determine the amount of I/O to generate
;			against the bitmap file. Return a pointer to the bitmap block.
;
; Inputs:
;	hfsmp		--	Pointer to hfs mount
;	offset		--	byte offset into the bitmap file 
;	size		--  How much I/O to generate against the bitmap file.
;
; Outputs:
;	buffer		--	Pointer to bitmap block data corresonding to "block"
;	blockRef	--  struct 'buf' pointer which MUST be released in a subsequent call.
;_______________________________________________________________________
*/
static OSErr ReadBitmapRange(struct hfsmount *hfsmp, uint32_t offset,
		uint32_t iosize, uint32_t **buffer, struct buf **blockRef)
{

	OSErr			err;
	struct buf *bp = NULL;
	struct vnode *vp = NULL;
	daddr64_t block;

	/* This function isn't supported for HFS standard */
	if (hfsmp->vcbSigWord != kHFSPlusSigWord) {
		return EINVAL;
	}

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED) {
		KERNEL_DEBUG_CONSTANT(HFSDBG_READ_BITMAP_RANGE | DBG_FUNC_START, offset, iosize, 0, 0, 0);
	}

	/*
	 * volume bitmap blocks are protected by the allocation file lock
	 */
	REQUIRE_FILE_LOCK(vcb->hfs_allocation_vp, false);	

	vp = hfsmp->hfs_allocation_vp;	/* use allocation file vnode */

	/*
	 * The byte offset argument must be converted into bitmap-relative logical 
	 * block numbers before using it in buf_meta_bread.
	 * 
	 * buf_meta_bread (and the things it calls) will eventually try to
	 * reconstruct the byte offset into the file by multiplying the logical 
	 * block number passed in below by the vcbVBMIOSize field in the mount
	 * point.  So we prepare for that by converting the byte offset back into
	 * logical blocks in terms of VBMIOSize units.
	 * 
	 * The amount of I/O requested and the byte offset should be computed 
	 * based on the helper function in the frame that called us, so we can
	 * get away with just doing a simple divide here.
	 */
	block = (daddr64_t)(offset / hfsmp->vcbVBMIOSize);

	err = (int) buf_meta_bread(vp, block, iosize, NOCRED, &bp);

	if (bp) {
		if (err) {
			buf_brelse(bp);
			*blockRef = 0;
			*buffer = NULL;
		} else {
			*blockRef = bp;
			*buffer = (u_int32_t *)buf_dataptr(bp);
		}
	}

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED) {
		KERNEL_DEBUG_CONSTANT(HFSDBG_READ_BITMAP_RANGE | DBG_FUNC_END, err, 0, 0, 0, 0);
	}

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
 * ReleaseScanBitmapRange
 *
 * This is used to release struct bufs that were created for use by 
 * bitmap scanning code.  Because they may be of sizes different than the
 * typical runtime manipulation code, we want to force them to be purged out 
 * of the buffer cache ASAP, so we'll release them differently than in the 
 * ReleaseBitmapBlock case.  
 *
 * Additionally, because we know that we're only reading the blocks and that they
 * should have been clean prior to reading them, we will never 
 * issue a write to them (thus dirtying them).
 */

static OSErr ReleaseScanBitmapRange(struct buf *bp ) {

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED) {
		KERNEL_DEBUG_CONSTANT(HFSDBG_RELEASE_BITMAP_BLOCK | DBG_FUNC_START, 0, 0, 0, 0, 0);
	}

	if (bp) {
		/* Mark the buffer invalid if it isn't locked, then release it */
		if ((buf_flags(bp) & B_LOCKED) == 0) {
			buf_markinvalid(bp);
		}
		buf_brelse(bp);
	}

	if (hfs_kdebug_allocation & HFSDBG_BITMAP_ENABLED) {
		KERNEL_DEBUG_CONSTANT(HFSDBG_RELEASE_SCAN_BITMAP | DBG_FUNC_END, 0, 0, 0, 0, 0);
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
	flags

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
		u_int32_t		flags,
		u_int32_t		*actualStartBlock,
		u_int32_t		*actualNumBlocks)
{
	OSErr retval = noErr;
	uint32_t currentStart = startingBlock;

	uint32_t foundStart = 0; // values to emit to caller
	uint32_t foundCount = 0;

	uint32_t collision_start = 0;  // if we have to re-allocate a recently deleted extent, use this
	uint32_t collision_count = 0;

	int err;
	int allowReuse = (flags & HFS_ALLOC_FLUSHTXN);
	Boolean useMetaZone = (flags & HFS_ALLOC_METAZONE);

	int recently_deleted = 0;
	struct hfsmount *hfsmp = VCBTOHFS(vcb);

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_CONTIG_BITMAP | DBG_FUNC_START, startingBlock, minBlocks, maxBlocks, useMetaZone, 0);

	while ((retval == noErr) && (foundStart == 0) && (foundCount == 0)) {

		/* Try and find something that works. */
		do {
			/*
			 * NOTE: If the only contiguous free extent of at least minBlocks
			 * crosses startingBlock (i.e. starts before, ends after), then we
			 * won't find it. Earlier versions *did* find this case by letting
			 * the second search look past startingBlock by minBlocks.  But
			 * with the free extent cache, this can lead to duplicate entries
			 * in the cache, causing the same blocks to be allocated twice.
			 */
			retval = BlockFindContiguous(vcb, currentStart, vcb->allocLimit, minBlocks, 
					maxBlocks, useMetaZone, true, &foundStart, &foundCount);

			if (retval == dskFulErr && currentStart != 0) {
				/*
				 * We constrain the endingBlock so we don't bother looking for ranges
				 * that would overlap those found in the previous call, if the summary bitmap
				 * is not on for this volume.  If it is, then we assume that it was not trust
				 * -worthy and do a full scan.
				 */
				if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
					retval = BlockFindContiguous(vcb, 1, vcb->allocLimit, minBlocks, 
							maxBlocks, useMetaZone, false, &foundStart, &foundCount);
				}
				else {
					retval = BlockFindContiguous(vcb, 1, currentStart, minBlocks, 
							maxBlocks, useMetaZone, false, &foundStart, &foundCount);
				}
			}	
		} while (0);

		if (retval != noErr) {
			goto bailout;
		}

		/* Do we overlap with the recently found collision extent? */
		if (collision_start) {
			if (extents_overlap (foundStart, foundCount, collision_start, collision_count)) {
				/* 
				 * We've looped around, and the only thing we could use was the collision extent.
				 * Since we are allowed to use it, go ahead and do so now.
				 */
				if(allowReuse) {
					/* 
					 * then we couldn't find anything except values which might have been 
					 * recently deallocated. just return our cached value if we are allowed to.
					 */
					foundStart = collision_start;
					foundCount = collision_count;
					goto bailout;
				}
				else {
					/* Otherwise, we looped around and couldn't find anything that wouldn't require a journal flush. */
					retval = dskFulErr;
					goto bailout;
				}	
			}
		}

		/* OK, we know we must not have collided . See if this one is recently deleted */
		if (hfsmp->jnl) {
			recently_deleted = 0;
			uint32_t nextStart;
			err = CheckUnmappedBytes (hfsmp, (uint64_t)foundStart,
					(uint64_t) foundCount, &recently_deleted, &nextStart);
			if (err == 0) {
				if(recently_deleted != 0) {
					/* 
					 * these blocks were recently deleted/deallocated.  Cache the extent, but
					 * but keep searching to see if we can find one that won't collide here. 
					 */
					if (collision_start == 0) {
						collision_start = foundStart;
						collision_count = foundCount;
					}
					recently_deleted = 0;

					/* 
					 * advance currentStart to the point just past the overlap we just found. Note that 
					 * we will automatically loop around to start of the bitmap as needed.
					 */
					currentStart = nextStart;
					/* Unset foundStart/Count to allow it to loop around again. */
					foundStart = 0;
					foundCount = 0;
				}
			}
		} // end jnl/deleted case

		/* 
		 * If we found something good, we'd break out of the loop at the top; foundCount
		 * and foundStart should be set.
		 */

	} // end while loop. 

bailout:
	/* mark the blocks as in-use */
	if (retval == noErr) {
		*actualStartBlock = foundStart;
		*actualNumBlocks = foundCount;
		err = BlockMarkAllocatedInternal(vcb, *actualStartBlock, *actualNumBlocks);

		if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED) {
			KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_CONTIG_BITMAP | DBG_FUNC_END, *actualStartBlock, *actualNumBlocks, 0, 0, 0);
		}
	}

	return retval;

}


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

static OSErr BlockAllocateAny(
		ExtendedVCB		*vcb,
		u_int32_t		startingBlock,
		register u_int32_t	endingBlock,
		u_int32_t		maxBlocks,
		u_int32_t		flags,
		Boolean			trustSummary,
		u_int32_t		*actualStartBlock,
		u_int32_t		*actualNumBlocks)
{

	/*
	 * If it is enabled, scan through the summary table to find the first free block.
	 *
	 * If it reports that there are not any free blocks, we could have a false
	 * positive, so in that case, use the input arguments as a pass through.
	 */
	uint32_t start_blk  = startingBlock;
	uint32_t end_blk = endingBlock;
	struct hfsmount *hfsmp;
	OSErr err;

	hfsmp = (struct hfsmount*)vcb;
	if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
		uint32_t suggested_start;

		/* 
		 * If the summary table is enabled, scan through it to find the first free 
		 * block.  If there was an error, or we couldn't find anything free in the
		 * summary table, then just leave the start_blk fields unmodified. We wouldn't
		 * have gotten to this point if the mount point made it look like there was possibly
		 * free space in the FS. 
		 */
		err = hfs_find_summary_free (hfsmp, startingBlock, &suggested_start);
		if (err == 0) {
			start_blk = suggested_start;
		}
		else {
			/* Differentiate between ENOSPC and a more esoteric error in the above call. */
			if ((err == ENOSPC) && (trustSummary)) {
				/* 
				 * The 'trustSummary' argument is for doing a full scan if we really
				 * really, need the space and we think it's somewhere but can't find it in the
				 * summary table. If it's true, then we trust the summary table and return 
				 * dskFulErr if we couldn't find it above.
				 */
				return dskFulErr;
			}
			/* 
			 * If either trustSummary was false or we got a different errno, then we
			 * want to fall through to the real bitmap single i/o code...
			 */ 
		}
	}

	err =  BlockAllocateAnyBitmap(vcb, start_blk, end_blk, maxBlocks, 
			flags, actualStartBlock, actualNumBlocks);

	return err;
}


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
		u_int32_t		flags,
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
	uint32_t summary_block_scan = 0;
	Boolean useMetaZone = (flags & HFS_ALLOC_METAZONE);
	Boolean forceFlush = (flags & HFS_ALLOC_FLUSHTXN);

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_ANY_BITMAP | DBG_FUNC_START, startingBlock, endingBlock, maxBlocks, useMetaZone, 0);

restartSearchAny:
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

	/*
	 * While loop 1:
	 *		Find the first unallocated block starting at 'block'
	 */
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
				if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
					/*
					 * If summary_block_scan is non-zero, then we must have
					 * pulled a bitmap file block into core, and scanned through
					 * the entire thing.  Because we're in this loop, we are 
					 * implicitly trusting that the bitmap didn't have any knowledge
					 * about this particular block.  As a result, update the bitmap
					 * (lazily, now that we've scanned it) with our findings that 
					 * this particular block is completely used up.
					 */
					if (summary_block_scan != 0) {
						uint32_t summary_bit;
						(void) hfs_get_summary_index (hfsmp, summary_block_scan, &summary_bit);
						hfs_set_summary (hfsmp, summary_bit, 1);
						summary_block_scan = 0;
					}
				}

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
				summary_block_scan = block;
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


	/* 
	 * Don't move forward just yet.  Verify that either one of the following
	 * two conditions is true:
	 * 1) journaling is not enabled
	 * 2) block is not currently on any pending TRIM list. 
	 */
	if (hfsmp->jnl != NULL && (forceFlush == false)) {
		int recently_deleted = 0;
		uint32_t nextblk;
		err = CheckUnmappedBytes (hfsmp, (uint64_t) block, 1, &recently_deleted, &nextblk);
		if ((err == 0) && (recently_deleted)) {

			/* release the bitmap block & unset currCache.  we may jump past it. */
			err = ReleaseBitmapBlock(vcb, blockRef, false);
			currCache = NULL;
			if (err != noErr) {
				goto Exit;
			}
			/* set our start to nextblk, and re-do the search. */
			startingBlock = nextblk;
			goto restartSearchAny;
		}
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

	/*
	 * While loop 2:
	 *		Scan the bitmap, starting at 'currentWord' in the current
	 *		bitmap block.  Continue iterating through the bitmap until
	 * 		either we hit an allocated block, or until we have accumuluated
	 *		maxBlocks worth of bitmap.
	 */
	
	/* Continue until we see an allocated block */
	while ((currentWord & bitMask) == 0) {	
		//	Move to the next block.  If no more, then exit.
		++block;
		if (block == endingBlock) {
			break;
		}

		//	Next bit
		bitMask >>= 1;
		if (bitMask == 0) {
			//	Next word
			bitMask = kHighBitInWordMask;
			++buffer;

			if (--wordsLeft == 0) {
				//	Next block
				buffer = currCache = NULL;

				/* We're only reading the bitmap here, so mark it as clean */
				err = ReleaseBitmapBlock(vcb, blockRef, false);
				if (err != noErr) {
					goto Exit;
				}

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

				if (block >= endingBlock) {
					goto Exit;
				}

				err = ReadBitmapBlock(vcb, block, &currCache, &blockRef);
				if (err != noErr) {
					goto Exit;
				}
				buffer = currCache;
				wordsLeft = wordsPerBlock;
			}
			currentWord = SWAP_BE32 (*buffer);
		}
	}

Exit:
	if (currCache) {
		/* Release the bitmap reference prior to marking bits in-use */
		(void) ReleaseBitmapBlock(vcb, blockRef, false);
		currCache = NULL;
	}

	if (err == noErr) {
		*actualNumBlocks = block - *actualStartBlock;
	
		// sanity check
		if ((*actualStartBlock + *actualNumBlocks) > vcb->allocLimit) {
			panic("hfs: BlockAllocateAny: allocation overflow on \"%s\"", vcb->vcbVN);
		}

		/* Mark the bits found as in-use */
		err = BlockMarkAllocatedInternal (vcb, *actualStartBlock, *actualNumBlocks);
	}
	else {
		*actualStartBlock = 0;
		*actualNumBlocks = 0;
	}

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
	struct hfsmount *hfsmp = VCBTOHFS(vcb);

	if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
		KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_KNOWN_BITMAP | DBG_FUNC_START, 0, 0, maxBlocks, 0, 0);

	hfs_lock_mount (hfsmp);
	lck_spin_lock(&vcb->vcbFreeExtLock);
	if ( vcb->vcbFreeExtCnt == 0 || 
			vcb->vcbFreeExt[0].blockCount == 0) {
		lck_spin_unlock(&vcb->vcbFreeExtLock);
		hfs_unlock_mount(hfsmp);
		if (hfs_kdebug_allocation & HFSDBG_ALLOC_ENABLED)
			KERNEL_DEBUG_CONSTANT(HFSDBG_ALLOC_KNOWN_BITMAP | DBG_FUNC_END, dskFulErr, *actualStartBlock, *actualNumBlocks, 0, 0);
		return dskFulErr;
	}
	lck_spin_unlock(&vcb->vcbFreeExtLock);
	hfs_unlock_mount(hfsmp);

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
		hfs_mark_inconsistent(vcb, HFS_INCONSISTENCY_DETECTED);
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

	int force_flush = 0;
	/*
	 * Since we are about to mark these bits as in-use 
	 * in the bitmap, decide if we need to alert the caller
	 * that a journal flush might be appropriate. It's safe to 
	 * poke at the journal pointer here since we MUST have 
	 * called start_transaction by the time this function is invoked.  
	 * If the journal is enabled, then it will have taken the requisite 
	 * journal locks.  If it is not enabled, then we have taken 
	 * a shared lock on the global lock.
	 */
	if (hfsmp->jnl) {
		uint32_t ignore;
		err = CheckUnmappedBytes (hfsmp, (uint64_t) startingBlock, (uint64_t)numBlocks, &force_flush, &ignore);
		if ((err == 0) && (force_flush)) {
			journal_request_immediate_flush (hfsmp->jnl);		
		}
	}

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
		hfs_mark_inconsistent(vcb, HFS_INCONSISTENCY_DETECTED);
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
	hfs_mark_inconsistent(vcb, HFS_INCONSISTENCY_DETECTED);
	err = EIO;
	goto Exit;
#endif
}


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
		Boolean			trustSummary,
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
	struct hfsmount *hfsmp = (struct hfsmount*) vcb;

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

	/*
	 * Use the summary table if we can.  Skip over any totally
	 * allocated blocks.  currentBlock should now point to the first
	 * block beyond the metadata zone if the metazone allocations are not
	 * allowed in this invocation.
	 */
	if ((trustSummary) && (hfsmp->hfs_flags & HFS_SUMMARY_TABLE)) {
		uint32_t suggestion;
		if (hfs_find_summary_free (hfsmp, currentBlock, &suggestion) == 0) {
			currentBlock = suggestion;
		}		
	}


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

	/*
	 * This outer do-while loop is the main body of this function.  Its job is 
	 * to search through the blocks (until we hit 'stopBlock'), and iterate
	 * through swaths of allocated bitmap until it finds free regions.
	 */

	do
	{
		foundBlocks = 0;
		uint32_t summary_block_scan = 0;
		/*
		 * Inner while loop 1:
		 *		Look for free blocks, skipping over allocated ones.
		 *
		 * Initialization starts with checking the initial partial word
		 * if applicable.
		 */
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
				if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
					/*
					 * If summary_block_scan is non-zero, then we must have
					 * pulled a bitmap file block into core, and scanned through
					 * the entire thing.  Because we're in this loop, we are 
					 * implicitly trusting that the bitmap didn't have any knowledge
					 * about this particular block.  As a result, update the bitmap
					 * (lazily, now that we've scanned it) with our findings that 
					 * this particular block is completely used up.
					 */
					if (summary_block_scan != 0) {
						uint32_t summary_bit;
						(void) hfs_get_summary_index (hfsmp, summary_block_scan, &summary_bit);
						hfs_set_summary (hfsmp, summary_bit, 1);
						summary_block_scan = 0;
					}
				}
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

				/* Skip over fully allocated bitmap blocks if we can */
				if ((trustSummary) && (hfsmp->hfs_flags & HFS_SUMMARY_TABLE)) {
					uint32_t suggestion;
					if (hfs_find_summary_free (hfsmp, currentBlock, &suggestion) == 0) {
						if (suggestion < stopBlock) {
							currentBlock = suggestion;
						}			
					}
				}

				err = ReadBitmapBlock(vcb, currentBlock, &buffer, &blockRef);
				if ( err != noErr ) goto ErrorExit;

				/*
				 * Set summary_block_scan to be the block we just read into the block cache.
				 *
				 * At this point, we've just read an allocation block worth of bitmap file
				 * into the buffer above, but we don't know if it is completely allocated or not.
				 * If we find that it is completely allocated/full then we will jump 
				 * through this loop again and set the appropriate summary bit as fully allocated.
				 */	
				summary_block_scan = currentBlock;
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


		/*
		 * Inner while loop 2:
		 *		We get here if we find a free block. Count the number
		 * 		of contiguous free blocks observed.
		 * 
		 * Initialization starts with checking the initial partial word
		 * if applicable.
		 */
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

		/*
		 * We did not find the total blocks were were looking for, but 
		 * add this free block run to our free extent cache list, if possible.
		 */
		if (hfsmp->jnl == NULL) {
			/* If there is no journal, go ahead and add to the free ext cache. */
			updated_free_extent = add_free_extent_cache(vcb, firstBlock, foundBlocks);
		}
		else {
			/*
			 * If journaled, only add to the free extent cache if this block is not
			 * waiting for a TRIM to complete; that implies that the transaction that freed it
			 * has not yet been committed to stable storage. 
			 */
			int recently_deleted = 0;
			uint32_t nextblock;
			err = CheckUnmappedBytes(hfsmp, (uint64_t)firstBlock, 
					(uint64_t)foundBlocks, &recently_deleted, &nextblock);
			if ((err) || (recently_deleted == 0))  {
				/* if we hit an error, or the blocks not recently freed, go ahead and insert it */
				updated_free_extent = add_free_extent_cache(vcb, firstBlock, foundBlocks);
			}
			err = 0;
		}

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
 * CONFIG_HFS_RBTREE
 * Check to see if the red-black tree is live.  Allocation file lock must be held
 * shared or exclusive to call this function. Note that we may call this even if
 * HFS is built without activating the red-black tree code.
 */
__private_extern__
int 
hfs_isrbtree_active(struct hfsmount *hfsmp){

#pragma unused (hfsmp)

	/* Just return 0 for now */
	return 0;
}



/* Summary Table Functions */
/*
 * hfs_check_summary:
 * 
 * This function should be used to query the summary table to see if we can
 * bypass a bitmap block or not when we're trying to find a free allocation block.
 *
 *
 * Inputs:
 * 		allocblock - allocation block number. Will be used to infer the correct summary bit.
 * 		hfsmp -- filesystem in question.
 * 
 * Output Arg:
 *		*freeblocks - set to 1 if we believe at least one free blocks in this vcbVBMIOSize
 * 		page of bitmap file.
 * 
 *
 * Returns:
 * 		0 on success
 *		EINVAL on error
 * 	
 */

static int hfs_check_summary (struct hfsmount *hfsmp, uint32_t allocblock, uint32_t *freeblocks) {

	int err = EINVAL;
	if (hfsmp->vcbVBMIOSize) {
		if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
			uint32_t index;
			if (hfs_get_summary_index (hfsmp, allocblock, &index)) {
				*freeblocks = 0;
				return EINVAL;
			}

			/* Ok, now that we have the bit index into the array, what byte is it in ? */
			uint32_t byteindex = index / kBitsPerByte;
			uint8_t current_byte = hfsmp->hfs_summary_table[byteindex];
			uint8_t bit_in_byte = index % kBitsPerByte;

			if (current_byte & (1 << bit_in_byte)) {
				/* 
				 * We do not believe there is anything free in the
				 * entire vcbVBMIOSize'd block.
				 */
				*freeblocks = 0;
			}	
			else {
				/* Looks like there might be a free block here... */
				*freeblocks = 1;
			}
		}
		err = 0;
	}

	return err;
}


#if 0
/*
 * hfs_get_next_summary
 *
 * From a given allocation block, jump to the allocation block at the start of the
 * next vcbVBMIOSize boundary.  This is useful when trying to quickly skip over
 * large swaths of bitmap once we have determined that the bitmap is relatively full. 
 *
 * Inputs: hfsmount, starting allocation block number
 * Output Arg: *newblock will contain the allocation block number to start
 * querying.
 * 
 * Returns:
 *		0 on success
 * 		EINVAL if the block argument is too large to be used, or the summary table not live.
 * 		EFBIG if there are no more summary bits to be queried
 */
static int 
hfs_get_next_summary (struct hfsmount *hfsmp, uint32_t block, uint32_t *newblock) {

	u_int32_t bits_per_iosize = hfsmp->vcbVBMIOSize * kBitsPerByte;
	u_int32_t start_offset;
	u_int32_t next_offset;
	int err = EINVAL; 

	if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
		if ((err = hfs_get_summary_index(hfsmp, block, &start_offset))) {
			return err;
		}

		next_offset = start_offset++;	

		if ((start_offset >= hfsmp->hfs_summary_size) || (next_offset >= hfsmp->hfs_summary_size)) {
			/* Can't jump to the next summary bit. */
			return EINVAL;
		}

		/* Otherwise, compute and return */
		*newblock = next_offset * bits_per_iosize;
		if (*newblock >= hfsmp->totalBlocks) {
			return EINVAL;
		}
		err = 0;
	}

	return err;
}

#endif

/*
 * hfs_release_summary 
 * 
 * Given an extent that is about to be de-allocated on-disk, determine the number
 * of summary bitmap bits that need to be marked as 'potentially available'.
 * Then go ahead and mark them as free.
 *
 *	Inputs:
 * 		hfsmp 		- hfs mount
 * 		block 		- starting allocation block.
 * 		length		- length of the extent.
 * 
 * 	Returns:
 *		EINVAL upon any errors.
 */
static int hfs_release_summary(struct hfsmount *hfsmp, uint32_t start_blk, uint32_t length) {
	int err = EINVAL;
	uint32_t end_blk = (start_blk + length) - 1;

	if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
		/* Figure out what the starting / ending block's summary bits are */
		uint32_t start_bit;
		uint32_t end_bit;
		uint32_t current_bit;

		err = hfs_get_summary_index (hfsmp, start_blk, &start_bit);
		if (err) {
			goto release_err;
		}
		err = hfs_get_summary_index (hfsmp, end_blk, &end_bit);
		if (err) {
			goto release_err;
		}

		if (ALLOC_DEBUG) {
			if (start_bit > end_bit) {
				panic ("HFS: start > end!, %d %d ", start_bit, end_bit);
			}
		}
		current_bit = start_bit;
		while (current_bit <= end_bit) {
			err = hfs_set_summary (hfsmp, current_bit, 0); 
			current_bit++;
		}
	}

release_err:
	return err;
}

/*
 * hfs_find_summary_free
 * 
 * Given a allocation block as input, returns an allocation block number as output as a 
 * suggestion for where to start scanning the bitmap in order to find free blocks.  It will
 * determine the vcbVBMIOsize of the input allocation block, convert that into a summary
 * bit, then keep iterating over the summary bits in order to find the first free one.
 * 
 * Inputs:
 *		hfsmp 		- hfs mount
 * 		block		- starting allocation block
 * 		newblock 	- output block as suggestion
 * 
 * Returns:
 * 		0 on success
 * 		ENOSPC if we could not find a free block 
 */

int hfs_find_summary_free (struct hfsmount *hfsmp, uint32_t block,  uint32_t *newblock) {

	int err = ENOSPC;
	uint32_t bit_index = 0;
	uint32_t maybe_has_blocks = 0;

	if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
		uint32_t byte_index;
		uint8_t curbyte;
		uint8_t bit_in_byte;
		uint32_t summary_cap;

		/* 
		 * We generate a cap for the summary search because the summary table
		 * always represents a full summary of the bitmap FILE, which may
		 * be way more bits than are necessary for the actual filesystem 
		 * whose allocations are mapped by the bitmap.
		 * 
		 * Compute how much of hfs_summary_size is useable for the given number
		 * of allocation blocks eligible on this FS.
		 */
		err = hfs_get_summary_index (hfsmp, hfsmp->allocLimit, &summary_cap);
		if (err) {
			goto summary_exit;
		}

		/* Check the starting block first */
		err = hfs_check_summary (hfsmp, block, &maybe_has_blocks);
		if (err) {
			goto summary_exit;
		}

		if (maybe_has_blocks) {
			/* 
			 * It looks like the initial start block could have something.  
			 * Short-circuit and just use that.
			 */
			*newblock = block;
			goto summary_exit;
		}

		/*
		 * OK, now we know that the first block was useless.  
		 * Get the starting summary bit, and find it in the array 
		 */
		maybe_has_blocks = 0;
		err = hfs_get_summary_index (hfsmp, block, &bit_index);
		if (err) {
			goto summary_exit;
		}

		/* Iterate until we find something. */
		while (bit_index <= summary_cap) {
			byte_index = bit_index / kBitsPerByte;
			curbyte = hfsmp->hfs_summary_table[byte_index];
			bit_in_byte = bit_index % kBitsPerByte;

			if (curbyte & (1 << bit_in_byte)) {
				/* nothing here.  increment and move on */
				bit_index++;
			}
			else {
				/* 
				 * found something! convert bit_index back into 
				 * an allocation block for use. 'newblock' will now
				 * contain the proper allocation block # based on the bit
				 * index.
				 */
				err = hfs_get_summary_allocblock (hfsmp, bit_index, newblock);	
				if (err) {
					goto summary_exit;
				}
				maybe_has_blocks = 1;
				break;
			}
		}

		/* If our loop didn't find anything, set err to ENOSPC */
		if (maybe_has_blocks == 0) {
			err = ENOSPC;
		}
	}	

	/* If the summary table is not active for this mount, we'll just return ENOSPC */
summary_exit:
	if (maybe_has_blocks) {
		err = 0;
	}

	return err;
}

/*
 * hfs_get_summary_allocblock
 * 
 * Convert a summary bit into an allocation block number to use to start searching for free blocks.
 * 
 * Inputs:
 *		hfsmp 			- hfs mount
 * 		summarybit 		- summmary bit index 
 *		*alloc			- allocation block number in the bitmap file.
 *
 * Output:
 *		0 on success
 * 		EINVAL on failure
 */
int hfs_get_summary_allocblock (struct hfsmount *hfsmp, uint32_t
		summarybit, uint32_t *alloc) {
	uint32_t bits_per_iosize = hfsmp->vcbVBMIOSize * kBitsPerByte;
	uint32_t allocblk;

	allocblk = summarybit * bits_per_iosize;

	if (allocblk >= hfsmp->totalBlocks) {
		return EINVAL;
	}
	else {
		*alloc = allocblk;
	}

	return 0;
}


/*
 * hfs_set_summary:
 * 
 * This function should be used to manipulate the summary table 
 *
 * The argument 'inuse' will set the value of the bit in question to one or zero
 * depending on its value.
 *
 * Inputs:
 * 		hfsmp 		- hfs mount
 *		summarybit	- the bit index into the summary table to set/unset.
 * 		inuse		- the value to assign to the bit.
 *
 * Returns:
 * 		0 on success
 *		EINVAL on error
 * 	
 */

static int hfs_set_summary (struct hfsmount *hfsmp, uint32_t summarybit, uint32_t inuse) {

	int err = EINVAL;
	if (hfsmp->vcbVBMIOSize) {
		if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {	

			if (ALLOC_DEBUG) {
				if (hfsmp->hfs_summary_table == NULL) {
					panic ("hfs_set_summary: no table for %p ", hfsmp);
				}
			}

			/* Ok, now that we have the bit index into the array, what byte is it in ? */
			uint32_t byte_index = summarybit / kBitsPerByte;
			uint8_t current_byte = hfsmp->hfs_summary_table[byte_index];
			uint8_t bit_in_byte = summarybit % kBitsPerByte;

			if (inuse) {
				current_byte = (current_byte | (1 << bit_in_byte));
			}
			else {
				current_byte = (current_byte & ~(1 << bit_in_byte));
			}

			hfsmp->hfs_summary_table[byte_index] = current_byte;
		}
		err = 0;
	}

	return err;
}


/*
 * hfs_get_summary_index:
 *
 * This is a helper function which determines what summary bit represents the vcbVBMIOSize worth
 * of IO against the bitmap file.
 * 
 * Returns:
 *		0 on success
 * 		EINVAL on failure
 */
static int hfs_get_summary_index (struct hfsmount *hfsmp, uint32_t block, uint32_t* index) {
	uint32_t summary_bit;
	uint32_t bits_per_iosize;
	int err = EINVAL;

	if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
		/* Is the input block bigger than the total number of blocks? */
		if (block >= hfsmp->totalBlocks) {
			return EINVAL;
		}

		/* Is there even a vbmIOSize set? */
		if (hfsmp->vcbVBMIOSize == 0) {
			return EINVAL;
		}

		bits_per_iosize = hfsmp->vcbVBMIOSize * kBitsPerByte;

		summary_bit = block / bits_per_iosize;

		*index = summary_bit;
		err = 0;
	}

	return err;
}

/*
 * hfs_init_summary
 * 
 * From a given mount structure, compute how big the summary table should be for the given
 * filesystem, then allocate and bzero the memory.
 *
 * Returns:
 * 0 on success
 * EINVAL on failure
 */
int
hfs_init_summary (struct hfsmount *hfsmp) {

	uint32_t summary_size;	
	uint32_t summary_size_bytes;
	uint8_t *summary_table;

	if (hfsmp->hfs_allocation_cp == NULL) {
		if (ALLOC_DEBUG) {
			printf("hfs: summary table cannot progress without a bitmap cnode! \n");
		}
		return EINVAL;
	}
	/* 
	 * The practical maximum size of the summary table is 16KB:  
	 *
	 *		(512MB maximum bitmap size / (4k -- min alloc block size)) / 8 bits/byte.
	 * 
	 * HFS+ will allow filesystems with allocation block sizes smaller than 4k, but
	 * the end result is that we'll start to issue I/O in 2k or 1k sized chunks, which makes
	 * supporting this much worse.  The math would instead look like this:
	 * (512MB / 2k) / 8 == 32k. 
	 * 
	 * So, we will disallow the summary table if the allocation block size is < 4k.
	 */

	if (hfsmp->blockSize < HFS_MIN_SUMMARY_BLOCKSIZE) {
		printf("hfs: summary table not allowed on FS with block size of %d\n", hfsmp->blockSize);
		return EINVAL;
	}

	summary_size = hfsmp->hfs_allocation_cp->c_blocks;

	if (ALLOC_DEBUG) {
		printf("HFS Summary Table Initialization: Bitmap %u blocks\n", 
				hfsmp->hfs_allocation_cp->c_blocks);
	}

	/*
	 * If the bitmap IO size is not the same as the allocation block size then
	 * then re-compute the number of summary bits necessary.  Note that above, the 
	 * the default size is the number of allocation blocks in the bitmap *FILE* 
	 * (not the number of bits in the bitmap itself).  If the allocation block size
	 * is large enough though, we may need to increase this. 
	 */
	if (hfsmp->blockSize != hfsmp->vcbVBMIOSize) {
		uint64_t lrg_size = (uint64_t) hfsmp->hfs_allocation_cp->c_blocks * (uint64_t) hfsmp->blockSize;
		lrg_size = lrg_size / (uint64_t)hfsmp->vcbVBMIOSize;

		/* With a full bitmap and 64k-capped iosize chunks, this would be 64k */
		summary_size = (uint32_t) lrg_size;
	}

	/* 
	 * If the block size is the same as the IO Size, then the total number of blocks
	 * is already equal to the number of IO units, which is our number of summary bits.
	 */

	summary_size_bytes = summary_size / kBitsPerByte;
	/* Always add one byte, just in case we have a dangling number of bits */
	summary_size_bytes++;

	if (ALLOC_DEBUG) {
		printf("HFS Summary Table: vcbVBMIOSize %d summary bits %d \n", hfsmp->vcbVBMIOSize, summary_size); 
		printf("HFS Summary Table Size (in bytes) %d \n", summary_size_bytes); 
	}

	/* Store the field in the mount point, and then MALLOC/bzero the memory */
	hfsmp->hfs_summary_size = summary_size;
	hfsmp->hfs_summary_bytes = summary_size_bytes;

	MALLOC (summary_table, uint8_t*, summary_size_bytes, M_TEMP, M_WAITOK);	
	if (summary_table == NULL) {
		return ENOMEM;
	}
	bzero (summary_table, summary_size_bytes);

	/* enable the summary table */
	hfsmp->hfs_flags |= HFS_SUMMARY_TABLE;
	hfsmp->hfs_summary_table = summary_table;

	if (ALLOC_DEBUG) {
		if (hfsmp->hfs_summary_table == NULL) {
			panic ("HFS Summary Init: no table for %p\n", hfsmp);
		}
	}
	return 0;
}

/*
 * hfs_rebuild_summary
 *
 * This function should be used to allocate a new hunk of memory for use as a summary
 * table, then copy the existing data into it.  We use it whenever the filesystem's size
 * changes.  When a resize is in progress, you can still use the extant summary
 * table if it is active.
 * 
 * Inputs:
 * 		hfsmp 		-- FS in question
 * 		newlength	-- new length of the FS in allocation blocks.
 *
 * Outputs: 
 *		0 on success, EINVAL on failure.  If this function fails,  the summary table
 * 		will be disabled for future use.
 *
 */
static int hfs_rebuild_summary (struct hfsmount *hfsmp) {

	uint32_t new_summary_size;

	new_summary_size = hfsmp->hfs_allocation_cp->c_blocks;


	if (ALLOC_DEBUG) {
		printf("HFS Summary Table Re-init: bitmap %u blocks\n", new_summary_size);
	}

	/* 
	 * If the bitmap IO size is not the same as the allocation block size, then re-compute
	 * the number of summary bits necessary.  Note that above, the default size is the number
	 * of allocation blocks in the bitmap *FILE* (not the number of bits that the bitmap manages).
	 * If the allocation block size is large enough though, we may need to increase this, as 
	 * bitmap IO is capped at 64k per IO
	 */
	if (hfsmp->blockSize != hfsmp->vcbVBMIOSize) {
		uint64_t lrg_size = (uint64_t) hfsmp->hfs_allocation_cp->c_blocks * (uint64_t) hfsmp->blockSize;
		lrg_size = lrg_size / (uint64_t)hfsmp->vcbVBMIOSize;

		/* With a full bitmap and 64k-capped iosize chunks, this would be 64k */
		new_summary_size = (uint32_t) lrg_size;
	}

	/* 
	 * Ok, we have the new summary bitmap theoretical max size.  See if it's the same as 
	 * what we've got already...
	 */
	if (new_summary_size != hfsmp->hfs_summary_size) {
		uint32_t summarybytes = new_summary_size / kBitsPerByte;
		uint32_t copysize;
		uint8_t *newtable;
		/* Add one byte for slop */
		summarybytes++;

		if (ALLOC_DEBUG) {
			printf("HFS Summary Table: vcbVBMIOSize %d summary bits %d \n", hfsmp->vcbVBMIOSize, new_summary_size);
			printf("HFS Summary Table Size (in bytes) %d \n", summarybytes);
		}

		/* Attempt to MALLOC the memory */
		MALLOC (newtable, uint8_t*, summarybytes, M_TEMP, M_WAITOK);
		if (newtable == NULL) {
			/* 
			 * ERROR!  We need to disable the table now 
			 */
			FREE (hfsmp->hfs_summary_table, M_TEMP);
			hfsmp->hfs_summary_table = NULL;
			hfsmp->hfs_flags &= ~HFS_SUMMARY_TABLE;	
			return EINVAL;
		}
		bzero (newtable, summarybytes);

		/* 
		 * The new table may be smaller than the old one. If this is true, then
		 * we can't copy the full size of the existing summary table into the new
		 * one. 
		 * 
		 * The converse is not an issue since we bzeroed the table above. 
		 */ 
		copysize = hfsmp->hfs_summary_bytes;
		if (summarybytes < hfsmp->hfs_summary_bytes) {	
			copysize = summarybytes;
		}
		memcpy (newtable, hfsmp->hfs_summary_table, copysize); 

		/* We're all good.  Destroy the old copy and update ptrs */
		FREE (hfsmp->hfs_summary_table, M_TEMP);

		hfsmp->hfs_summary_table = newtable;
		hfsmp->hfs_summary_size = new_summary_size;	
		hfsmp->hfs_summary_bytes = summarybytes;
	}

	return 0;
}


#if ALLOC_DEBUG
/* 
 * hfs_validate_summary
 * 
 * Validation routine for the summary table.  Debug-only function.
 * 
 * Bitmap lock must be held.
 *
 */
void hfs_validate_summary (struct hfsmount *hfsmp) {
	uint32_t i;
	int err;

	/* 
	 * Iterate over all of the bits in the summary table, and verify if 
	 * there really are free blocks in the pages that we believe may
	 * may contain free blocks.
	 */

	if (hfsmp->hfs_summary_table == NULL) {
		panic ("HFS Summary: No HFS summary table!");
	}	

	/* 131072 bits == 16384 bytes.  This is the theoretical max size of the summary table. we add 1 byte for slop */
	if (hfsmp->hfs_summary_size == 0 || hfsmp->hfs_summary_size > 131080) {
		panic("HFS Summary: Size is bad! %d", hfsmp->hfs_summary_size);
	}

	if (hfsmp->vcbVBMIOSize == 0) {
		panic("HFS Summary: no VCB VBM IO Size !");
	}

	printf("hfs: summary validation beginning on %s\n", hfsmp->vcbVN);
	printf("hfs: summary validation %d summary bits, %d summary blocks\n", hfsmp->hfs_summary_size, hfsmp->totalBlocks);


	/* iterate through all possible summary bits */
	for (i = 0; i < hfsmp->hfs_summary_size ; i++) {

		uint32_t bits_per_iosize = hfsmp->vcbVBMIOSize * kBitsPerByte;
		uint32_t byte_offset = hfsmp->vcbVBMIOSize * i;

		/* Compute the corresponding allocation block for the summary bit. */
		uint32_t alloc_block = i * bits_per_iosize;

		/* 
		 * We use a uint32_t pointer here because it will speed up 
		 * access to the real bitmap data on disk. 
		 */
		uint32_t *block_data;
		struct buf *bp;
		int counter;
		int counter_max;
		int saw_free_bits = 0;

		/* Get the block */
		if ((err = ReadBitmapRange (hfsmp, byte_offset, hfsmp->vcbVBMIOSize, &block_data,  &bp))) {
			panic ("HFS Summary: error (%d) in ReadBitmapRange!", err);
		}

		/* Query the status of the bit and then make sure we match */
		uint32_t maybe_has_free_blocks;
		err = hfs_check_summary (hfsmp, alloc_block, &maybe_has_free_blocks);
		if (err) {
			panic ("HFS Summary: hfs_check_summary returned error (%d) ", err);
		}
		counter_max = hfsmp->vcbVBMIOSize / kBytesPerWord;

		for (counter = 0; counter < counter_max; counter++) {
			uint32_t word = block_data[counter];

			/* We assume that we'll not find any free bits here. */
			if (word != kAllBitsSetInWord) {
				if (maybe_has_free_blocks) {
					/* All done */
					saw_free_bits = 1;
					break;
				}
				else {
					panic ("HFS Summary: hfs_check_summary saw free bits!");
				}
			}
		}

		if (maybe_has_free_blocks && (saw_free_bits == 0)) {
			panic ("HFS Summary: did not see free bits !");	
		}

		/* Release the block. */
		if ((err =  ReleaseScanBitmapRange (bp))) {
			panic ("HFS Summary: Error (%d) in ReleaseScanBitmapRange", err);
		}
	}

	printf("hfs: summary validation completed successfully on %s\n", hfsmp->vcbVN);

	return;
}
#endif

/*
 * hfs_alloc_scan_range:
 *
 * This function should be used to scan large ranges of the allocation bitmap
 * at one time.  It makes two key assumptions:
 * 
 * 		1) Bitmap lock is held during the duration of the call (exclusive)
 * 		2) There are no pages in the buffer cache for any of the bitmap 
 * 		blocks that we may encounter.  It *MUST* be completely empty.
 * 
 * The expected use case is when we are scanning the bitmap in full while we are 
 * still mounting the filesystem in order to issue TRIMs or build up the summary 
 * table for the mount point. It should be done after any potential journal replays
 * are completed and their I/Os fully issued.
 * 
 * The key reason for assumption (2) above is that this function will try to issue 
 * I/O against the bitmap file in chunks as large a possible -- essentially as 
 * much as the buffer layer will handle (1MB).  Because the size of these I/Os 
 * is larger than what would be expected during normal runtime we must invalidate 
 * the buffers as soon as we are done with them so that they do not persist in 
 * the buffer cache for other threads to find, as they'll typically be doing 
 * allocation-block size I/Os instead.
 * 
 * Input Args:
 *		hfsmp 		- hfs mount data structure
 * 		startbit 	- allocation block # to start our scan. It must be aligned
 *					on a vcbVBMIOsize boundary.
 *		list		- journal trim list data structure for issuing TRIMs
 *
 * Output Args:
 *		bitToScan 	- Return the next bit to scan if this function is called again. 
 *					Caller will supply this into the next invocation
 *					of this call as 'startbit'. 	
 */

static int hfs_alloc_scan_range(struct hfsmount *hfsmp, u_int32_t startbit, 
		u_int32_t *bitToScan, struct jnl_trim_list *list) {

	int error;
	int readwrite = 1;
	u_int32_t curAllocBlock;
	struct buf *blockRef = NULL;
	u_int32_t *buffer = NULL;
	u_int32_t free_offset = 0; //tracks the start of the current free range
	u_int32_t size = 0; // tracks the length of the current free range.
	u_int32_t iosize = 0; //how much io we should generate against the bitmap
	u_int32_t byte_off; // byte offset into the bitmap file.
	u_int32_t completed_size; // how much io was actually completed
	u_int32_t last_bitmap_block;
	u_int32_t current_word;	
	u_int32_t word_index = 0;	

	/* summary table building */
	uint32_t summary_bit = 0;
	uint32_t saw_free_blocks = 0;
	uint32_t last_marked = 0;

	if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		readwrite = 0;
	}

	/* 
	 * Compute how much I/O we should generate here.
	 * hfs_scan_range_size will validate that the start bit 
	 * converted into a byte offset into the bitmap file,
	 * is aligned on a VBMIOSize boundary. 
	 */
	error = hfs_scan_range_size (hfsmp, startbit, &iosize);
	if (error) {
		if (ALLOC_DEBUG) {
			panic ("hfs_alloc_scan_range: hfs_scan_range_size error %d\n", error);
		}
		return error;
	}

	if (iosize < hfsmp->vcbVBMIOSize) {
		if (ALLOC_DEBUG) {
			panic ("hfs_alloc_scan_range: iosize too small! (iosize %d)\n", iosize);
		}
		return EINVAL;
	}

	/* hfs_scan_range_size should have verified startbit.  Convert it to bytes */
	byte_off = startbit / kBitsPerByte;

	/*
	 * When the journal replays blocks, it does so by writing directly to the disk
	 * device (bypassing any filesystem vnodes and such).  When it finishes its I/Os
	 * it also immediately re-reads and invalidates the range covered by the bp so
	 * it does not leave anything lingering in the cache (for iosize reasons).  
	 * 
	 * As such, it is safe to do large I/Os here with ReadBitmapRange. 
	 *
	 * NOTE: It is not recommended, but it is possible to call the function below
	 * on sections of the bitmap that may be in core already as long as the pages are not
	 * dirty.  In that case, we'd notice that something starting at that
	 * logical block of the bitmap exists in the metadata cache, and we'd check 
	 * if the iosize requested is the same as what was already allocated for it.  
	 * Odds are pretty good we're going to request something larger.  In that case, 
	 * we just free the existing memory associated with the buf and reallocate a 
	 * larger range. This function should immediately invalidate it as soon as we're 
	 * done scanning, so this shouldn't cause any coherency issues.
	 */

	error = ReadBitmapRange(hfsmp, byte_off, iosize, &buffer, &blockRef);
	if (error) {
		if (ALLOC_DEBUG) {
			panic ("hfs_alloc_scan_range: start %d iosize %d ReadBitmapRange error %d\n", startbit, iosize, error);
		}
		return error;
	}

	/* 
	 * At this point, we have a giant wired buffer that represents some portion of
	 * the bitmap file that we want to analyze.   We may not have gotten all 'iosize'
	 * bytes though, so clip our ending bit to what we actually read in.
	 */
	completed_size = buf_count(blockRef);
	last_bitmap_block = completed_size * kBitsPerByte;
	last_bitmap_block = last_bitmap_block + startbit;

	/* Cap the last block to the total number of blocks if required */
	if (last_bitmap_block > hfsmp->totalBlocks) {
		last_bitmap_block = hfsmp->totalBlocks;
	}	

	/* curAllocBlock represents the logical block we're analyzing. */
	curAllocBlock = startbit;	
	word_index = 0;
	size = 0;

	if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
		if (hfs_get_summary_index (hfsmp, startbit, &summary_bit)) {
			error = EINVAL;
			if (ALLOC_DEBUG) {
				panic ("hfs_alloc_scan_range: Could not acquire summary index for %u", startbit);
			}
			return error;
		}
		/* 
		 * summary_bit should now be set to the summary bit corresponding to
		 * the allocation block of the first bit that we're supposed to scan
		 */ 
	}
	saw_free_blocks = 0;

	while (curAllocBlock < last_bitmap_block) {
		u_int32_t bit;

		/* Update the summary table as needed */
		if (hfsmp->hfs_flags & HFS_SUMMARY_TABLE) {
			if (ALLOC_DEBUG) {
				if (hfsmp->hfs_summary_table == NULL) {
					panic ("hfs_alloc_scan_range: no summary table!");
				}
			}	

			uint32_t temp_summary;
			error = hfs_get_summary_index (hfsmp, curAllocBlock, &temp_summary);
			if (error) {
				if (ALLOC_DEBUG) {
					panic ("hfs_alloc_scan_range: could not get summary index for %u", curAllocBlock);
				}
				return EINVAL;
			}

			if (ALLOC_DEBUG) {
				if (temp_summary < summary_bit) {
					panic ("hfs_alloc_scan_range: backwards summary bit?\n");
				}
			}

			/* 
			 * If temp_summary is greater than summary_bit, then this
			 * means that the next allocation block crosses a vcbVBMIOSize boundary
			 * and we should treat this range of on-disk data as part of a new summary
			 * bit.
			 */ 
			if (temp_summary > summary_bit) {
				if (saw_free_blocks == 0) {
					/* Mark the bit as totally consumed in the summary table */
					hfs_set_summary (hfsmp, summary_bit, 1);
				}
				else {
					/* Mark the bit as potentially free in summary table */
					hfs_set_summary (hfsmp, summary_bit, 0);
				}
				last_marked = summary_bit;
				/* 
				 * Any time we set the summary table, update our counter which tracks
				 * what the last bit that was fully marked in the summary table. 
				 *  
				 * Then reset our marker which says we haven't seen a free bit yet.
				 */
				saw_free_blocks = 0;
				summary_bit = temp_summary;
			}
		} /* End summary table conditions */

		current_word = SWAP_BE32(buffer[word_index]);
		/* Iterate through the word 1 bit at a time... */
		for (bit = 0 ; bit < kBitsPerWord ; bit++, curAllocBlock++) {
			if (curAllocBlock >= last_bitmap_block) {
				break;
			}
			u_int32_t allocated = (current_word & (kHighBitInWordMask >> bit));

			if (allocated) { 
				if (size != 0) {
					if (readwrite) {
						/* Insert the previously tracked range of free blocks to the trim list */
						hfs_track_unmap_blocks (hfsmp, free_offset, size, list);
					}
					add_free_extent_cache (hfsmp, free_offset, size);
					size = 0;
					free_offset = 0;
				}
			}
			else {
				/* Not allocated */
				size++;
				if (free_offset == 0) {
					/* Start a new run of free spcae at curAllocBlock */
					free_offset = curAllocBlock;
				}
				if (saw_free_blocks == 0) {
					saw_free_blocks = 1;
				}
			}
		} /* end for loop iterating through the word */

		if (curAllocBlock < last_bitmap_block) {
			word_index++;
		}

	} /* End while loop (iterates through last_bitmap_block) */


	/* 
	 * We've (potentially) completed our pass through this region of bitmap, 
	 * but one thing we may not have done is updated that last summary bit for 
	 * the last page we scanned, because we would have never transitioned across 
	 * a vcbVBMIOSize boundary again.  Check for that and update the last bit
	 * as needed.
	 * 
	 * Note that 'last_bitmap_block' is *not* inclusive WRT the very last bit in the bitmap
	 * for the region of bitmap on-disk that we were scanning. (it is one greater).
	 */
	if ((curAllocBlock >= last_bitmap_block) && 
			(hfsmp->hfs_flags & HFS_SUMMARY_TABLE)) { 
		uint32_t temp_summary;
		/* temp_block should be INSIDE the region we just scanned, so subtract 1 */
		uint32_t temp_block = last_bitmap_block - 1;
		error = hfs_get_summary_index (hfsmp, temp_block, &temp_summary);
		if (error) {
			if (ALLOC_DEBUG) {
				panic ("hfs_alloc_scan_range: end bit curAllocBlock %u, last_bitmap_block %u", curAllocBlock, last_bitmap_block);
			}
			return EINVAL;
		}

		/* Did we already update this in the table? */
		if (temp_summary > last_marked) {
			if (saw_free_blocks == 0) {
				hfs_set_summary (hfsmp, temp_summary, 1);
			}
			else {
				hfs_set_summary (hfsmp, temp_summary, 0);
			}
		}
	}

	/* 
	 * We may have been tracking a range of free blocks that hasn't been inserted yet. 
	 * Keep the logic for the TRIM and free extent separate from that of the summary 
	 * table management even though they are closely linked.
	 */
	if (size != 0) {
		if (readwrite) {
			hfs_track_unmap_blocks (hfsmp, free_offset, size, list);
		}
		add_free_extent_cache (hfsmp, free_offset, size);
	}

	/* 
	 * curAllocBlock represents the next block we need to scan when we return
	 * to this function. 
	 */
	*bitToScan = curAllocBlock;
	ReleaseScanBitmapRange(blockRef);

	return 0;

}



/*
 * Compute the maximum I/O size to generate against the bitmap file
 * Will attempt to generate at LEAST VBMIOsize I/Os for interior ranges of the bitmap. 
 * 
 * Inputs:
 *		hfsmp		-- hfsmount to look at 
 *		bitmap_off 	-- bit offset into the bitmap file
 *	
 * Outputs:
 * 		iosize	-- iosize to generate.
 *
 * Returns:
 *		0 on success; EINVAL otherwise 
 */
static int hfs_scan_range_size (struct hfsmount *hfsmp, uint32_t bitmap_st, uint32_t *iosize) {

	/* 
	 * The maximum bitmap size is 512MB regardless of ABN size, so we can get away
	 * with 32 bit math in this function.
	 */

	uint32_t bitmap_len;
	uint32_t remaining_bitmap;
	uint32_t target_iosize;
	uint32_t bitmap_off; 

	/* Is this bit index not word aligned?  If so, immediately fail. */
	if (bitmap_st % kBitsPerWord) {
		if (ALLOC_DEBUG) {
			panic ("hfs_scan_range_size unaligned start bit! bitmap_st %d \n", bitmap_st);
		}
		return EINVAL;
	}

	/* bitmap_off is in bytes, not allocation blocks/bits */
	bitmap_off = bitmap_st / kBitsPerByte;

	if ((hfsmp->totalBlocks <= bitmap_st) || (bitmap_off > (512 * 1024 * 1024))) {
		if (ALLOC_DEBUG) {
			panic ("hfs_scan_range_size: invalid start! bitmap_st %d, bitmap_off %d\n", bitmap_st, bitmap_off);
		}
		return EINVAL;
	}

	/* 
	 * Also invalid if it's not at least aligned to HFS bitmap logical
	 * block boundaries.  We don't have to emit an iosize that's an 
	 * exact multiple of the VBMIOSize, but it must start on such 
	 * a boundary.
	 *
	 * The vcbVBMIOSize may be SMALLER than the allocation block size
	 * on a FS with giant allocation blocks, but it will never be
	 * greater than it, so it should be safe to start I/O
	 * aligned on a VBMIOsize boundary. 
	 */
	if (bitmap_off & (hfsmp->vcbVBMIOSize - 1)) {
		if (ALLOC_DEBUG) {
			panic ("hfs_scan_range_size: unaligned start! bitmap_off %d\n", bitmap_off);
		}
		return EINVAL;
	}

	/* 
	 * Generate the total bitmap file length in bytes, then round up
	 * that value to the end of the last allocation block, if needed (It 
	 * will probably be needed).  We won't scan past the last actual 
	 * allocation block.  
	 *
	 * Unless we're completing the bitmap scan (or bitmap < 1MB), we
	 * have to complete the I/O on VBMIOSize boundaries, but we can only read
	 * up until the end of the bitmap file.
	 */
	bitmap_len = hfsmp->totalBlocks / kBitsPerByte;
	if (bitmap_len % (hfsmp->blockSize)) {
		bitmap_len = (bitmap_len / hfsmp->blockSize);
		/* round up to the end of the next alloc block */
		bitmap_len++;

		/* Convert the # of alloc blocks back to bytes. */
		bitmap_len = bitmap_len * hfsmp->blockSize;	
	}

	remaining_bitmap = bitmap_len - bitmap_off;

	/* 
	 * io size is the MIN of the maximum I/O we can generate or the
	 * remaining amount of bitmap.
	 */
	target_iosize = MIN((MAXBSIZE), remaining_bitmap);
	*iosize = target_iosize;

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
	 * Update allocLimit to the argument specified
	 */
	hfsmp->allocLimit = new_end_block;

	/* Invalidate the free extent cache completely so that 
	 * it does not have any extents beyond end of current 
	 * volume.
	 */
	ResetVCBFreeExtCache(hfsmp);

	/* Force a rebuild of the summary table. */
	(void) hfs_rebuild_summary (hfsmp);

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

	/* Do not do anything if debug is not on */
	if (ALLOC_DEBUG == 0) {
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

