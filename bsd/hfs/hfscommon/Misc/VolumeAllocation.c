/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
	File:		VolumeAllocation.c

	Contains:	Routines for accessing and modifying the volume bitmap.

	Version:	HFS Plus 1.0

	Copyright:	© 1996-2001 by Apple Computer, Inc., all rights reserved.

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


Internal routines:
	BlockMarkFree
					Mark a contiguous range of blocks as free.  The corresponding
					bits in the volume bitmap will be cleared.
	BlockMarkAllocated
					Mark a contiguous range of blocks as allocated.  The cor-
					responding bits in the volume bitmap are set.  Also tests to see
					if any of the blocks were previously unallocated.
	FindContiguous
					Find a contiguous range of blocks of a given size.  The caller
					specifies where to begin the search (by block number).  The
					block number of the first block in the range is returned.
	BlockAllocateAny
					Find and allocate a contiguous range of blocks up to a given size.  The
					first range of contiguous free blocks found are allocated, even if there
					are fewer blocks than requested (and even if a contiguous range of blocks
					of the given size exists elsewhere).
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
*/

#include "../../hfs_macos_defs.h"

#include <sys/types.h>
#include <sys/buf.h>
#include <sys/systm.h>

#include "../../hfs.h"
#include "../../hfs_dbg.h"
#include "../../hfs_format.h"
#include "../../hfs_endian.h"

#include "../headers/FileMgrInternal.h"


enum {
	kBytesPerWord			=	4,
	kBitsPerByte			=	8,
	kBitsPerWord			=	32,

	kBitsWithinWordMask		=	kBitsPerWord-1
};

#define kLowBitInWordMask	0x00000001ul
#define kHighBitInWordMask	0x80000000ul
#define kAllBitsSetInWord	0xFFFFFFFFul


static OSErr ReadBitmapBlock(
	ExtendedVCB		*vcb,
	UInt32			bit,
	UInt32			**buffer,
	UInt32			*blockRef);

static OSErr ReleaseBitmapBlock(
	ExtendedVCB		*vcb,
	UInt32			blockRef,
	Boolean			dirty);

static OSErr BlockAllocateAny(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	UInt32			endingBlock,
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks);

static OSErr BlockAllocateContig(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	UInt32			minBlocks,
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks);

static OSErr BlockFindContiguous(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	UInt32			endingBlock,
	UInt32			minBlocks,
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks);

static OSErr BlockMarkAllocated(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	UInt32			numBlocks);

static OSErr BlockMarkFree(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	UInt32			numBlocks);

static OSErr BlockAllocateKnown(
	ExtendedVCB		*vcb,
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks);


/*
;________________________________________________________________________________
;
; Routine:	   BlkAlloc
;
; Function:    Allocate space on a volume.	If contiguous allocation is requested,
;			   at least the requested number of bytes will be allocated or an
;			   error will be returned.	If contiguous allocation is not forced,
;			   the space will be allocated at the first free fragment following
;			   the requested starting allocation block.  If there is not enough
;			   room there, a block of less than the requested size will be
;			   allocated.
;
;			   If the requested starting block is 0 (for new file allocations),
;			   the volume's allocation block pointer will be used as a starting
;			   point.
;
;			   All requests will be rounded up to the next highest clump size, as
;			   indicated in the file's FCB.
;
; Input Arguments:
;	 vcb			 - Pointer to ExtendedVCB for the volume to allocate space on
;	 fcb			 - Pointer to FCB for the file for which storage is being allocated
;	 startingBlock	 - Preferred starting allocation block, 0 = no preference
;	 forceContiguous - Force contiguous flag - if bit 0 set (NE), allocation is contiguous
;					   or an error is returned
;	 bytesRequested	 - Number of bytes requested.	If the allocation is non-contiguous,
;					   less than this may actually be allocated
;	 bytesMaximum	 - The maximum number of bytes to allocate.  If there is additional free
;					   space after bytesRequested, then up to bytesMaximum bytes should really
;					   be allocated.  (Used by ExtendFileC to round up allocations to a multiple
;					   of the file's clump size.)
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
	UInt32			startingBlock,		/* preferred starting block, or 0 for no preference */
	SInt64			bytesRequested,		/* desired number of BYTES to allocate */
	SInt64			bytesMaximum,		/* maximum number of bytes to allocate */
	Boolean			forceContiguous,	/* non-zero to force contiguous allocation and to force */
										/* bytesRequested bytes to actually be allocated */
	UInt32			*actualStartBlock,	/* actual first block of allocation */
	UInt32			*actualNumBlocks)	/* number of blocks actually allocated; if forceContiguous */
										/* was zero, then this may represent fewer than bytesRequested */
										/* bytes */
{
	OSErr			err;
	UInt32			minBlocks;					//	minimum number of allocation blocks requested
	UInt32			maxBlocks;					//	number of allocation blocks requested, rounded to clump size
	Boolean			updateAllocPtr = false;		//	true if nextAllocation needs to be updated

	//
	//	Initialize outputs in case we get an error
	//
	*actualStartBlock = 0;
	*actualNumBlocks = 0;
	
	//
	//	Compute the number of allocation blocks requested, and maximum
	//
	minBlocks = FileBytesToBlocks(bytesRequested, vcb->blockSize);
	maxBlocks = FileBytesToBlocks(bytesMaximum, vcb->blockSize);
	
	//
	//	If the disk is already full, don't bother.
	//
	if (vcb->freeBlocks == 0) {
		err = dskFulErr;
		goto Exit;
	}
	if (forceContiguous && vcb->freeBlocks < minBlocks) {
		err = dskFulErr;
		goto Exit;
	}
	
	//
	//	If caller didn't specify a starting block number, then use the volume's
	//	next block to allocate from.
	//
	if (startingBlock == 0) {
		VCB_LOCK(vcb);
		startingBlock = vcb->nextAllocation;
		VCB_UNLOCK(vcb);
		updateAllocPtr = true;
	}

	//
	//	If the request must be contiguous, then find a sequence of free blocks
	//	that is long enough.  Otherwise, find the first free block.
	//
	if (forceContiguous) {
		err = BlockAllocateContig(vcb, startingBlock, minBlocks, maxBlocks, actualStartBlock, actualNumBlocks);
	} else {
		/*
		 * Scan the bitmap once, gather the N largest free extents, then
		 * allocate from these largest extents.  Repeat as needed until
		 * we get all the space we needed.  We could probably build up
		 * that list when the higher level caller tried (and failed) a
		 * contiguous allocation first.
		 */
		err = BlockAllocateKnown(vcb, maxBlocks, actualStartBlock, actualNumBlocks);
		if (err == dskFulErr)
			err = BlockAllocateAny(vcb, startingBlock, vcb->totalBlocks, maxBlocks, actualStartBlock, actualNumBlocks);
		if (err == dskFulErr)
			err = BlockAllocateAny(vcb, 0, startingBlock, maxBlocks, actualStartBlock, actualNumBlocks);
	}

	if (err == noErr) {
		//
		//	If we used the volume's roving allocation pointer, then we need to update it.
		//	Adding in the length of the current allocation might reduce the next allocate
		//	call by avoiding a re-scan of the already allocated space.  However, the clump
		//	just allocated can quite conceivably end up being truncated or released when
		//	the file is closed or its EOF changed.  Leaving the allocation pointer at the
		//	start of the last allocation will avoid unnecessary fragmentation in this case.
		//
		VCB_LOCK(vcb);

		if (updateAllocPtr)
			vcb->nextAllocation = *actualStartBlock;
		
		//
		//	Update the number of free blocks on the volume
		//
		vcb->freeBlocks -= *actualNumBlocks;
		VCB_UNLOCK(vcb);

		MarkVCBDirty(vcb);
	}
	
Exit:

	return err;
}


/*
;________________________________________________________________________________
;
; Routine:	   BlkDealloc
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
;________________________________________________________________________________
*/

OSErr BlockDeallocate (
	ExtendedVCB		*vcb,			//	Which volume to deallocate space on
	UInt32			firstBlock,		//	First block in range to deallocate
	UInt32			numBlocks)		//	Number of contiguous blocks to deallocate
{
	OSErr			err;
	
	//
	//	If no blocks to deallocate, then exit early
	//
	if (numBlocks == 0) {
		err = noErr;
		goto Exit;
	}

	//
	//	Call internal routine to free the sequence of blocks
	//
	err = BlockMarkFree(vcb, firstBlock, numBlocks);
	if (err)
		goto Exit;

	//
	//	Update the volume's free block count, and mark the VCB as dirty.
	//
	VCB_LOCK(vcb);
	vcb->freeBlocks += numBlocks;
	VCB_UNLOCK(vcb);
	MarkVCBDirty(vcb);

Exit:

	return err;
}


/*
;_______________________________________________________________________
;
; Routine:	FileBytesToBlocks
;
; Function:	Divide numerator by denominator, rounding up the result if there
;			was a remainder.  This is frequently used for computing the number
;			of whole and/or partial blocks used by some count of bytes.
;			Actuall divides a 64 bit by a 32 bit into a 32bit result
;		
;			CAREFULL!!! THIS CAN CAUSE OVERFLOW....USER BEWARE!!!
;_______________________________________________________________________
*/
UInt32 FileBytesToBlocks(
	SInt64 numerator,
	UInt32 denominator)
{
	UInt32	quotient;
	
	quotient = (UInt32)(numerator / denominator);
	if (quotient * denominator != numerator)
		quotient++;
	
	return quotient;
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
	UInt32			bit,
	UInt32			**buffer,
	UInt32			*blockRef)
{
	OSErr			err;
	struct buf *bp = NULL;
	struct vnode *vp = NULL;
	UInt32 block;
	UInt32 blockSize;

	/*
	 * volume bitmap blocks are protected by the Extents B-tree lock
	 */
	REQUIRE_FILE_LOCK(vcb->extentsRefNum, false);	

	blockSize = (UInt32)vcb->vcbVBMIOSize;
	block = bit / (blockSize * kBitsPerByte);

	if (vcb->vcbSigWord == kHFSPlusSigWord) {
		vp = vcb->allocationsRefNum;	/* use allocation file vnode */

	} else /* hfs */ {
		vp = VCBTOHFS(vcb)->hfs_devvp;	/* use device I/O vnode */
		block += vcb->vcbVBMSt;			/* map to physical block */
	}

	err = meta_bread(vp, block, blockSize, NOCRED, &bp);

	if (bp) {
		if (err) {
			brelse(bp);
			*blockRef = NULL;
			*buffer = NULL;
		} else {
			*blockRef = (UInt32)bp;
			*buffer = (UInt32 *)bp->b_data;
		}
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
	UInt32			blockRef,
	Boolean			dirty)
{
	struct buf *bp = (struct buf *)blockRef;

	if (bp) {
		if (dirty) {
			bp->b_flags |= B_DIRTY;
			bdwrite(bp);
		} else {
			brelse(bp);
		}
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

Outputs:
	actualStartBlock	First block of range allocated, or 0 if error
	actualNumBlocks		Number of blocks allocated, or 0 if error
_______________________________________________________________________
*/
static OSErr BlockAllocateContig(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	UInt32			minBlocks,
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks)
{
	OSErr	err;

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
	err = BlockFindContiguous(vcb, startingBlock, vcb->totalBlocks, minBlocks, maxBlocks,
								  actualStartBlock, actualNumBlocks);
	if (err == dskFulErr && startingBlock != 0) {
		/*
		 * Constrain the endingBlock so we don't bother looking for ranges
		 * that would overlap those found in the previous call.
		 */
		err = BlockFindContiguous(vcb, 0, startingBlock, minBlocks, maxBlocks,
									  actualStartBlock, actualNumBlocks);
	}
	if (err != noErr) goto Exit;

	//
	//	Now mark those blocks allocated.
	//
	err = BlockMarkAllocated(vcb, *actualStartBlock, *actualNumBlocks);
	
Exit:
	if (err != noErr) {
		*actualStartBlock = 0;
		*actualNumBlocks = 0;
	}
	
	return err;
}

extern OSErr LookupBufferMapping(caddr_t bufferAddress, struct buf **bpp, int *mappingIndexPtr);

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

Outputs:
	actualStartBlock	First block of range allocated, or 0 if error
	actualNumBlocks		Number of blocks allocated, or 0 if error
_______________________________________________________________________
*/
static OSErr BlockAllocateAny(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	register UInt32	endingBlock,
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks)
{
	OSErr			err;
	register UInt32	block;			//	current block number
	register UInt32	currentWord;	//	Pointer to current word within bitmap block
	register UInt32	bitMask;		//	Word with given bits already set (ready to OR in)
	register UInt32	wordsLeft;		//	Number of words left in this bitmap block
    UInt32			*buffer = NULL;
    UInt32			*currCache = NULL;
	UInt32  blockRef;
	UInt32  bitsPerBlock;
	UInt32  wordsPerBlock;
	Boolean dirty = false;

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
		UInt32 wordIndexInBlock;
		
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
	if (block == endingBlock) {
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

                err = ReadBitmapBlock(vcb, block, &currCache, &blockRef);
				if (err != noErr) goto Exit;
                buffer = currCache;

				wordsLeft = wordsPerBlock;
			}
			
			currentWord = SWAP_BE32 (*buffer);
		}
	}
	*buffer = SWAP_BE32 (currentWord);							//	update the last change

Exit:
	if (err == noErr) {
		*actualNumBlocks = block - *actualStartBlock;
	}
	else {
		*actualStartBlock = 0;
		*actualNumBlocks = 0;
	}
	
    if (currCache)
    	(void) ReleaseBitmapBlock(vcb, blockRef, dirty);

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
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks)
{
	UInt32			i;
	UInt32			foundBlocks;
	UInt32			newStartBlock, newBlockCount;
	
	if (vcb->vcbFreeExtCnt == 0)
		return dskFulErr;

	//	Just grab up to maxBlocks of the first (largest) free exent.
	*actualStartBlock = vcb->vcbFreeExt[0].startBlock;
	foundBlocks = vcb->vcbFreeExt[0].blockCount;
	if (foundBlocks > maxBlocks)
		foundBlocks = maxBlocks;
	*actualNumBlocks = foundBlocks;
	
	//	Adjust the start and length of that extent.
	newStartBlock = vcb->vcbFreeExt[0].startBlock + foundBlocks;
	newBlockCount = vcb->vcbFreeExt[0].blockCount - foundBlocks;
	
	//	The first extent might not be the largest anymore.  Bubble up any
	//	(now larger) extents to the top of the list.
	for (i=1; i<vcb->vcbFreeExtCnt; ++i)
	{
		if (vcb->vcbFreeExt[i].blockCount > newBlockCount)
		{
			vcb->vcbFreeExt[i-1].startBlock = vcb->vcbFreeExt[i].startBlock;
			vcb->vcbFreeExt[i-1].blockCount = vcb->vcbFreeExt[i].blockCount;
		}
		else
		{
			break;
		}
	}
	
	//	If this is now the smallest known free extent, then it might be smaller than
	//	other extents we didn't keep track of.  So, just forget about this extent.
	//	After the previous loop, (i-1) is the index of the extent we just allocated from.
	if (i == vcb->vcbFreeExtCnt)
	{
		//	It's now the smallest extent, so forget about it
		--vcb->vcbFreeExtCnt;
	}
	else
	{
		//	It's not the smallest, so store it in its proper place
		vcb->vcbFreeExt[i-1].startBlock = newStartBlock;
		vcb->vcbFreeExt[i-1].blockCount = newBlockCount;
	}
	
	//
	//	Now mark the found extent in the bitmap
	//
	return BlockMarkAllocated(vcb, *actualStartBlock, *actualNumBlocks);
}



/*
_______________________________________________________________________

Routine:	BlockMarkAllocated

Function:	Mark a contiguous group of blocks as allocated (set in the
			bitmap).  It assumes those bits are currently marked
			deallocated (clear in the bitmap).

Inputs:
	vcb				Pointer to volume where space is to be allocated
	startingBlock	First block number to mark as allocated
	numBlocks		Number of blocks to mark as allocated
_______________________________________________________________________
*/
static OSErr BlockMarkAllocated(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	register UInt32	numBlocks)
{
	OSErr			err;
	register UInt32	*currentWord;	//	Pointer to current word within bitmap block
	register UInt32	wordsLeft;		//	Number of words left in this bitmap block
	register UInt32	bitMask;		//	Word with given bits already set (ready to OR in)
	UInt32			firstBit;		//	Bit index within word of first bit to allocate
	UInt32			numBits;		//	Number of bits in word to allocate
	UInt32			*buffer = NULL;
	UInt32  blockRef;
	UInt32  bitsPerBlock;
	UInt32  wordsPerBlock;

	//
	//	Pre-read the bitmap block containing the first word of allocation
	//

	err = ReadBitmapBlock(vcb, startingBlock, &buffer, &blockRef);
	if (err != noErr) goto Exit;
	//
	//	Initialize currentWord, and wordsLeft.
	//
	{
		UInt32 wordIndexInBlock;
		
		bitsPerBlock  = vcb->vcbVBMIOSize * kBitsPerByte;
		wordsPerBlock = vcb->vcbVBMIOSize / kBytesPerWord;

		wordIndexInBlock = (startingBlock & (bitsPerBlock-1)) / kBitsPerWord;
		currentWord = buffer + wordIndexInBlock;
		wordsLeft = wordsPerBlock - wordIndexInBlock;
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
			panic("BlockMarkAllocated: blocks already allocated!");
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

			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
#if DEBUG_BUILD
		if (*currentWord != 0) {
			panic("BlockMarkAllocated: blocks already allocated!");
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

			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
#if DEBUG_BUILD
		if ((*currentWord & SWAP_BE32 (bitMask)) != 0) {
			panic("BlockMarkAllocated: blocks already allocated!");
		}
#endif
		*currentWord |= SWAP_BE32 (bitMask);			//	set the bits in the bitmap

		//	No need to update currentWord or wordsLeft
	}

Exit:

	if (buffer)
		(void)ReleaseBitmapBlock(vcb, blockRef, true);

	return err;
}


/*
_______________________________________________________________________

Routine:	BlockMarkFree

Function:	Mark a contiguous group of blocks as free (clear in the
			bitmap).  It assumes those bits are currently marked
			allocated (set in the bitmap).

Inputs:
	vcb				Pointer to volume where space is to be freed
	startingBlock	First block number to mark as freed
	numBlocks		Number of blocks to mark as freed
_______________________________________________________________________
*/
static OSErr BlockMarkFree(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	register UInt32	numBlocks)
{
	OSErr			err;
	register UInt32	*currentWord;	//	Pointer to current word within bitmap block
	register UInt32	wordsLeft;		//	Number of words left in this bitmap block
	register UInt32	bitMask;		//	Word with given bits already set (ready to OR in)
	UInt32			firstBit;		//	Bit index within word of first bit to allocate
	UInt32			numBits;		//	Number of bits in word to allocate
	UInt32			*buffer = NULL;
	UInt32  blockRef;
	UInt32  bitsPerBlock;
	UInt32  wordsPerBlock;

	//
	//	Pre-read the bitmap block containing the first word of allocation
	//

	err = ReadBitmapBlock(vcb, startingBlock, &buffer, &blockRef);
	if (err != noErr) goto Exit;
	//
	//	Initialize currentWord, and wordsLeft.
	//
	{
		UInt32 wordIndexInBlock;
		
		bitsPerBlock  = vcb->vcbVBMIOSize * kBitsPerByte;
		wordsPerBlock = vcb->vcbVBMIOSize / kBytesPerWord;

		wordIndexInBlock = (startingBlock & (bitsPerBlock-1)) / kBitsPerWord;
		currentWord = buffer + wordIndexInBlock;
		wordsLeft = wordsPerBlock - wordIndexInBlock;
	}
	
	//
	//	If the first block to free doesn't start on a word
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
		if ((*currentWord & SWAP_BE32 (bitMask)) != SWAP_BE32 (bitMask)) {
			panic("BlockMarkFree: blocks not allocated!");
		}
#endif
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

			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}

#if DEBUG_BUILD
		if (*currentWord != SWAP_BE32 (kAllBitsSetInWord)) {
			panic("BlockMarkFree: blocks not allocated!");
		}
#endif
		*currentWord = 0;							//	clear the entire word
		numBlocks -= kBitsPerWord;
		
		++currentWord;								//	move to next word
		--wordsLeft;								//	one less word left in this block
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

			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = wordsPerBlock;
		}
#if DEBUG_BUILD
		if ((*currentWord & SWAP_BE32 (bitMask)) != SWAP_BE32 (bitMask)) {
			panic("BlockMarkFree: blocks not allocated!");
		}
#endif
		*currentWord &= SWAP_BE32 (~bitMask);			//	clear the bits in the bitmap

		//	No need to update currentWord or wordsLeft
	}

Exit:

	if (buffer)
		(void)ReleaseBitmapBlock(vcb, blockRef, true);

	return err;
}


/*
_______________________________________________________________________

Routine:	BlockFindContiguous

Function:	Find a contiguous range of blocks that are free (bits
			clear in the bitmap).  If a contiguous range of the
			minimum size can't be found, an error will be returned.

Inputs:
	vcb				Pointer to volume where space is to be allocated
	startingBlock	Preferred first block of range
	endingBlock		Last possible block in range + 1
	minBlocks		Minimum number of blocks needed.  Must be > 0.
	maxBlocks		Maximum (ideal) number of blocks desired

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
	UInt32			startingBlock,
	UInt32			endingBlock,
	UInt32			minBlocks,
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks)
{
	OSErr			err;
	register UInt32	currentBlock;		//	Block we're currently looking at.
	UInt32			firstBlock;			//	First free block in current extent.
	UInt32			stopBlock;			//	If we get to this block, stop searching for first free block.
	UInt32			foundBlocks;		//	Number of contiguous free blocks in current extent.
	UInt32			*buffer = NULL;
	register UInt32	*currentWord;
	register UInt32	bitMask;
	register UInt32	wordsLeft;
	register UInt32	tempWord;
	UInt32  blockRef;
	UInt32  wordsPerBlock;

	if ((endingBlock - startingBlock) < minBlocks)
	{
		//	The set of blocks we're checking is smaller than the minimum number
		//	of blocks, so we couldn't possibly find a good range.
		goto DiskFull;
	}

	stopBlock = endingBlock - minBlocks + 1;
	currentBlock = startingBlock;
	
	//
	//	Pre-read the first bitmap block.
	//
	err = ReadBitmapBlock(vcb, currentBlock, &buffer, &blockRef);
	if ( err != noErr ) goto ErrorExit;

	//
	//	Figure out where currentBlock is within the buffer.
	//
	wordsPerBlock = vcb->vcbVBMIOSize / kBytesPerWord;

	wordsLeft = (startingBlock / kBitsPerWord) & (wordsPerBlock-1);	// Current index into buffer
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
			tempWord = *currentWord;			//	Fetch the current word only once
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

				err = ReadBitmapBlock(vcb, currentBlock, &buffer, &blockRef);
				if ( err != noErr ) goto ErrorExit;
				
				currentWord = buffer;
				wordsLeft = wordsPerBlock;
			}
			
			//	See if any of the bits are clear
			if ((tempWord=*currentWord) + 1)	//	non-zero if any bits were clear
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
			tempWord = *currentWord;			//	Fetch the current word only once
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

				err = ReadBitmapBlock(vcb, currentBlock, &buffer, &blockRef);
				if ( err != noErr ) goto ErrorExit;
				
				currentWord = buffer;
				wordsLeft = wordsPerBlock;
			}
			
			//	See if any of the bits are set
			if ((tempWord=*currentWord) != 0)
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

		//	This free chunk wasn't big enough.  Try inserting it into the free extent cache in case
		//	the allocation wasn't forced contiguous.
		tempWord = vcb->vcbFreeExtCnt;
		if (tempWord == kMaxFreeExtents && vcb->vcbFreeExt[kMaxFreeExtents-1].blockCount < foundBlocks)
			--tempWord;
		if (tempWord < kMaxFreeExtents)
		{
			//	We're going to add this extent.  Bubble any smaller extents down in the list.
			while (tempWord && vcb->vcbFreeExt[tempWord-1].blockCount < foundBlocks)
			{
				vcb->vcbFreeExt[tempWord] = vcb->vcbFreeExt[tempWord-1];
				--tempWord;
			}
			vcb->vcbFreeExt[tempWord].startBlock = firstBlock;
			vcb->vcbFreeExt[tempWord].blockCount = foundBlocks;
			
			if (vcb->vcbFreeExtCnt < kMaxFreeExtents)
				++vcb->vcbFreeExtCnt;
		}
	} while (currentBlock < stopBlock);


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
	}
	
	if (buffer)
		(void) ReleaseBitmapBlock(vcb, blockRef, false);

	return err;
}


