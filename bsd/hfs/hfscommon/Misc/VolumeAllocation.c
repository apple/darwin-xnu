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
/*
	File:		VolumeAllocation.c

	Contains:	Routines for accessing and modifying the volume bitmap.

	Version:	HFS Plus 1.0

	Copyright:	© 1996-2000 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Mark Day

		Other Contact:		Greg Parks

		Technology:			HFS+

	Writers:

		(djb)	Don Brady
		(DSH)	Deric Horn
		(msd)	Mark Day

	Change History (most recent first):
	  <MacOSX>	 1/22/2000	djb	Removed unused BlockCheck and BlockVerifyAllocated routines.
	  <MacOSX>	 4/27/98	djb	Remove references to unused/legacy vcbFreeBks.
	  <MacOSX>	 4/27/98	djb	Remove unneccessary DebugStr in BlockVerifyAllocated.
	  <MacOSX>	 4/17/98	djb	Add VCB locking.
	  <MacOSX>	 4/13/98	djb	Add RequireFileLock checking to ReadBitmapBlock.
	  <MacOSX>	 3/31/98	djb	Sync up with final HFSVolumes.h header file.

	  <12>	1	0/31/97		DSH		Modify BlockVerifyAllocated() so DFA can call without actually
									writing to the disk.
	  <CS11>	10/20/97	msd		The way BlockAllocate rounds up to a multiple of the clump size
									is wrong. ExtendFileC should do the round-up and pass the result
									into BlockAllocate. Removed the fcb parameter to BlockAllocate;
									added a bytesMaximum parameter.
	  <CS10>	10/17/97	msd		Conditionalize DebugStrs.
	   <CS9>	  9/4/97	djb		Add logging to BlockAllocate.
	   <CS8>	  9/4/97	msd		Add a histogram of allocation sizes. Use DEBUG_BUILD instead of
									VSM_DEBUG to generate DebugStr messages.
	   <CS7>	 8/14/97	msd		Bug 1662332. Don't mark blocks dirty in UpdateFreeCount. In
									BlockVerifyAllocated, only mark blocks dirty if they've actually
									changed.
	   <CS6>	 7/16/97	DSH		FilesInternal.i renamed FileMgrInternal.i to avoid name
									collision
	   <CS5>	  7/8/97	DSH		Loading PrecompiledHeaders from define passed in on C line
	   <CS4>	 6/12/97	msd		Export BlockAllocateAny and UpdateVCBFreeBlks.
		 <3>	  5/8/97	DSH		Added comments and ascii diagram of new BlockFindContiguous()
									algorithm.
		 <2>	  5/7/97	DSH		New faster BlockFindContiguous algorithm.  It searches backwards
									until a dirty bit is found instead of forwards.
	   <CS1>	 4/25/97	djb		first checked in

	 <HFS21>	 4/14/97	msd		Fix UpdateVCBFreeBlks so free space calculation doesn't overflow
									on volumes bigger than 4GB.
	 <HFS20>	  4/4/97	djb		Get in sync with volume format changes.
	 <HFS19>	 1/27/97	msd		Speed up BlockCheck and UpdateFreeCount. Removed DebugStr from
									BlockCheck; there are now DebugStr's in BlockVerifyAllocated,
									before the bitmap gets fixed (so potential problems can be
									debugged easier). Adjusted comments about internal routines.
									Changed names of "Fast" routines back to their original names
									(since the originals are now removed).
	 <HFS18>	 1/24/97	msd		Speed up allocation and deallocation.
	 <HFS17>	 1/21/97	msd		Add instrumentation for function entry/exit.  BlockAllocate and
									ReadBitMapBlock use the event tag to log bytes requested and
									block number (respectively).
	 <HFS16>	 1/15/97	djb		Add HFS+ supprt to BlockCheck (for MountCheck).
	 <HFS15>	 1/13/97	DSH		Use vcb->nextAllocation instead of vcbAllocPtr.
	 <HFS14>	  1/9/97	djb		UpdateVCBFreeBlks is not converting correctly.
	 <HFS13>	  1/6/97	djb		Use vcb's allocationsRefNum to access allocation file.
	 <HFS12>	  1/2/97	DSH		Added UpdateVCBFreeBlks() to update vcbFreeBks whenever we
									update vcb->freeblocks.
	 <HFS11>	12/19/96	DSH		All refs to VCB are now refs to ExtendedVCB
	 <HFS10>	12/12/96	msd		DivideAndRoundUp should not be declared as static.
	  <HFS9>	12/10/96	msd		Check PRAGMA_LOAD_SUPPORTED before loading precompiled headers.
	  <HFS8>	 12/4/96	DSH		PrecompiledHeaders
	  <HFS7>	11/27/96	djb		Added AllocateFreeSpace for HFS wrapper support.
	  <HFS6>	11/27/96	msd		Changed ReadBitmapBlock to read from HFS+ allocation file.
									Temporarily uses the vcbVBMSt field of the VCB as the allocation
									file's refnum until extended VCB changes are checked in.
	  <HFS5>	11/26/96	msd		VSM and FileExtentMapping routines use FCB instead of FCBRec.
	  <HFS4>	11/20/96	DSH		Changed a parameter in GetBlock_glue, so I also changed the
									caller.
	  <HFS3>	11/20/96	msd		Include FilesInternal.h. Remove definition of MarkVCBDirty
									(since it is now in FilesInternal.h).
	  <HFS2>	11/12/96	msd		Need to bound allocations to be within the last allocation block
									of the volume (function AllocateAt).
	  <HFS1>	11/11/96	msd		first checked in
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
	UpdateFreeCount
					Computes the number of free allocation blocks on a volume.
					The vcb's free block count is updated.

	AllocateFreeSpace
					Allocates all the remaining free space (used for embedding HFS+ volumes).

	BlockAllocateAny
					Find and allocate a contiguous range of blocks up to a given size.  The
					first range of contiguous free blocks found are allocated, even if there
					are fewer blocks than requested (and even if a contiguous range of blocks
					of the given size exists elsewhere).

	UpdateVCBFreeBlks
					Given an ExtenddVCB, calculate the vcbFreeBks value
					so that vcbFreeBks*vcbAlBlkSiz == freeBlocks*blockSize.

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
	BlockAllocateContig
					Find and allocate a contiguous range of blocks of a given size.  If
					a contiguous range of free blocks of the given size isn't found, then
					the allocation fails (i.e. it is "all or nothing").
	ReadBitmapBlock
					Given an allocation block number, read the bitmap block that
					contains that allocation block into a caller-supplied buffer.
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

#include "../headers/HFSInstrumentation.h"

#define EXPLICIT_BUFFER_RELEASES 1

enum {
	kBitsPerByte			=	8,
	kBitsPerWord			=	32,
	kWordsPerBlock			=	128,
	kBytesPerBlock			=	512,
	kBitsPerBlock			=	4096,
	
	kBitsWithinWordMask		=	kBitsPerWord-1,
	kBitsWithinBlockMask	=	kBitsPerBlock-1,
	kWordsWithinBlockMask	=	kWordsPerBlock-1,
	
	kExtentsPerRecord		=	3
};

#define kLowBitInWordMask	0x00000001ul
#define kHighBitInWordMask	0x80000000ul
#define kAllBitsSetInWord	0xFFFFFFFFul


static OSErr ReadBitmapBlock(
	ExtendedVCB		*vcb,
	UInt32			block,
	UInt32			**buffer);

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
;
; Modification history:
;	<06Oct85>  PWD	Changed to check for errors after calls to ReadBM and NextWord
;					Relocated call to MarkBlock in allocation loop
;					Changed to call NextBit
; <21Oct85>   PWD	Changed to check VCBFreeBks before attempting to allocate any block.
;					Speed up scan for free space by checking for all 1's.
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

	LogStartTime(kTraceBlockAllocate);

#if HFSInstrumentation
	InstSplitHistogramClassRef	histogram;
	InstTraceClassRef			trace;
	InstEventTag				eventTag;
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:VSM:BlockAllocate", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	err = InstCreateSplitHistogramClass(kInstRootClassRef, "HFS:VSM:BlockAllocate size", 0, 512, 16384, 262144, 16384,
										kInstEnableClassMask, &histogram);
	if (err != noErr) DebugStr("\pError from InstCreateHistogramClass");

	eventTag = bytesRequested;		// a cheap way to get bytesRequested into the log
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
	InstUpdateHistogram( histogram, bytesRequested, 1);
#endif

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
		err = BlockAllocateAny(vcb, startingBlock, vcb->totalBlocks, maxBlocks, actualStartBlock, actualNumBlocks);
		if (err == dskFulErr) {
			err = BlockAllocateAny(vcb, 0, startingBlock, maxBlocks, actualStartBlock, actualNumBlocks);
			};
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

		UpdateVCBFreeBlks( vcb );
		MarkVCBDirty(vcb);
	}
	
Exit:

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif
	LogEndTime(kTraceBlockAllocate, err);

	return err;
}


/*
;________________________________________________________________________________
;
; Routine:	   UpdateVCBFreeBlks
;
; Function:    Whenever the freeBlocks field in the ExtendedVCB is updated,
;			   we must also recalculate the (UInt16) vcbFreeBks field in the
;			   traditional HFS VCB structure.
;
; Input Arguments:
;	 vcb		- Pointer to ExtendedVCB for the volume to free space on
;________________________________________________________________________________
*/
void UpdateVCBFreeBlks( ExtendedVCB *vcb )
{
	#if DEBUG_BUILD
		if ( vcb->vcbSigWord == kHFSSigWord && vcb->freeBlocks > 0xFFFF )
			DebugStr("\p UpdateVCBFreeBlks: freeBlocks overflow!");
	#endif
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
;
; Modification history:
;
;	<06Oct85>  PWD	Changed to check for error after calls to ReadBM and NextWord
;					Now calls NextBit to read successive bits from the bitmap
;________________________________________________________________________________
*/

OSErr BlockDeallocate (
	ExtendedVCB		*vcb,			//	Which volume to deallocate space on
	UInt32			firstBlock,		//	First block in range to deallocate
	UInt32			numBlocks)		//	Number of contiguous blocks to deallocate
{
	OSErr			err;
	
#if HFSInstrumentation
	InstTraceClassRef	trace;
	InstEventTag		eventTag;
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:VSM:BlockDeallocate", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	eventTag = InstCreateEventTag();
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
#endif

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
	UpdateVCBFreeBlks( vcb );
	MarkVCBDirty(vcb);

Exit:

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif

	return err;
}


/*
;_______________________________________________________________________
;
; Routine:		UpdateFree
; Arguments:	vcb	-- ExtendedVCB for volume
;
; Called By:	MountVol
; Function: 	This routine is used as part of the MountVol consistency check
;				to figure out the number of free allocation blocks in the volume.
;
; Modification History:
;	<08Sep85>  LAK	New today.
;	<06Oct85>  PWD	Added explicit check for errors after calls to ReadBM, NextWord
;					Now calls NextBit.
;_______________________________________________________________________
*/

OSErr UpdateFreeCount (
	ExtendedVCB	*vcb)				//	Volume whose free block count should be updated
{
	OSErr			err;
	register UInt32	wordsLeft;		//	Number of words left in this bitmap block
	register UInt32	numBlocks;		//	Number of blocks left to scan
	register UInt32	freeCount;		//	Running count of free blocks found so far
	register UInt32	temp;
	UInt32			blockNum;		//	Block number of first block in this bitmap block
	UInt32			*buffer = NULL;	//	Pointer to bitmap block
	register UInt32	*currentWord;	//	Pointer to current word in bitmap block
	
#if HFSInstrumentation
	InstTraceClassRef	trace;
	InstEventTag		eventTag;
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:VSM:UpdateFreeCount", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	eventTag = InstCreateEventTag();
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
#endif

	//
	//	Pre-read the first bitmap block
	//

	err = ReadBitmapBlock(vcb, 0, &buffer);
	if (err != noErr) goto Exit;

	//
	//	Initialize buffer stuff
	//
	currentWord = buffer;
	wordsLeft = kWordsPerBlock;
	numBlocks = vcb->totalBlocks;
	freeCount = 0;
	blockNum = 0;
	
	//
	//	Scan whole words first
	//
	
	while (numBlocks >= kBitsPerWord) {
		//	See if it's time to move to the next bitmap block
		if (wordsLeft == 0) {
			//	Read in the next bitmap block
			blockNum += kBitsPerBlock;				//	generate a block number in the next bitmap block
			
#if EXPLICIT_BUFFER_RELEASES
			err = RelBlock_glue((Ptr)buffer, rbDefault);
			if (err != noErr) goto Exit;
			buffer = NULL;
#endif
			err = ReadBitmapBlock(vcb, blockNum, &buffer);
			if (err != noErr) goto Exit;
			
			//	Readjust currentWord, wordsLeft
			currentWord = buffer;
			wordsLeft = kWordsPerBlock;
		}
		
		//	We count free blocks by inverting the word in the bitmap and counting set bits.
		temp = ~(*currentWord);
		while (temp) {
			++freeCount;
			temp &= temp-1;			//	this clears least significant bit that is currently set
		}

		numBlocks -= kBitsPerWord;
		++currentWord;								//	move to next word
		--wordsLeft;								//	one less word left in this block
	}
	
	//
	//	Check any remaining blocks.
	//
	
	if (numBlocks != 0) {
		if (wordsLeft == 0) {
			//	Read in the next bitmap block
			blockNum += kBitsPerBlock;				//	generate a block number in the next bitmap block
			
#if EXPLICIT_BUFFER_RELEASES
			err = RelBlock_glue((Ptr)buffer, rbDefault);
			if (err != noErr) goto Exit;
			buffer = NULL;
#endif
			err = ReadBitmapBlock(vcb, blockNum, &buffer);
			if (err != noErr) goto Exit;
			
			//	Readjust currentWord, wordsLeft
			currentWord = buffer;
			wordsLeft = kWordsPerBlock;
		}
		
		//	We count free blocks by inverting the word in the bitmap and counting set bits.
		temp = SWAP_BE32 (~(*currentWord));
		while (numBlocks != 0) {
			if (temp & kHighBitInWordMask)
				++freeCount;
			temp <<= 1;
			--numBlocks;
		}
	}

	VCB_LOCK(vcb);
	vcb->freeBlocks = freeCount;
	VCB_UNLOCK(vcb);
	UpdateVCBFreeBlks( vcb );

Exit:

#if EXPLICIT_BUFFER_RELEASES
	if (buffer) {
		(void)RelBlock_glue((Ptr)buffer, rbDefault);		/* Ignore any additional errors */
	};
#endif

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif

	return err;
}



/*
;_______________________________________________________________________
;
; Routine:		AllocateFreeSpace
; Arguments:	vcb	-- ExtendedVCB for volume
;
; Called By:	HFSDiskInitComponent
; Function: 	This routine is used as part of DiskInit to create an
;				embedded HFS+ volume.
;
; Note: Assumes that the free space is contiguous (true for a freshly erased disk)
;_______________________________________________________________________
*/

OSErr AllocateFreeSpace (
	ExtendedVCB		*vcb,				//	Volume whose free space is about to be expropriated
	UInt32			*startBlock,		// return where free space starts
	UInt32			*actualBlocks)		// return the number of blocks in free space
{
	OSErr			err;

	err = BlockAllocateAny(vcb, 0, vcb->totalBlocks, vcb->freeBlocks, startBlock, actualBlocks);

	if (err == noErr) {
		VCB_LOCK(vcb);
		vcb->freeBlocks = 0;	// sorry, no more blocks left!
		VCB_UNLOCK(vcb);
		MarkVCBDirty(vcb);
	}
	
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
;			block.  Return a pointer to the bitmap block.
;
; Inputs:
;	vcb			--	Pointer to ExtendedVCB
;	block		--	Allocation block whose bitmap block is desired
;
; Outputs:
;	buffer		--	Pointer to bitmap block corresonding to "block"
;_______________________________________________________________________
*/
static OSErr ReadBitmapBlock(
	ExtendedVCB		*vcb,
	UInt32			block,
	UInt32			**buffer)
{
	OSErr			err;

#if HFSInstrumentation
	InstTraceClassRef	trace;
	InstEventTag		eventTag;
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:VSM:ReadBitmapBlock", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	eventTag = block;		// a cheap way to get the block number into the log
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
#endif

	err = noErr;

	REQUIRE_FILE_LOCK(vcb->extentsRefNum, false);	/* bitmap blocks are covered by the Extents B-tree lock */

	if (vcb->vcbSigWord == kHFSSigWord) {
		//
		//	HFS: Turn block number into physical block offset within the
		//	bitmap, and then the physical block within the volume.
		//
		block /= kBitsPerBlock;		// block offset within bitmap
		block += vcb->vcbVBMSt;		// block within whole volume
	}
	else {
		FCB		*allocFile;
		daddr_t	startBlock;
		size_t	availableBytes;
		
		//
		//	HFS+: Read from allocation file.  We simply convert the block number into a byte
		//	offset within the allocation file and then determine which block that byte is in.
		//
		allocFile = GetFileControlBlock(vcb->allocationsRefNum);

		//
		//	Find out which physical block holds byte #offset in allocation file.  Note that we
		//	map only 1 byte (the one we asked for).
		//
		err = MapFileBlockC(vcb, allocFile, (size_t)1, (off_t)(block/kBitsPerByte), &startBlock, &availableBytes);
		block = startBlock;
	}

	if (err == noErr) {
	            err = GetBlock_glue(
#if EXPLICIT_BUFFER_RELEASES
								0,						// No options
#else
                                gbReleaseMask,			// Release block immediately.  We only work on one
														// block at a time.  Call MarkBlock later if dirty.
#endif
                                block,					// Physical block on volume
                                (Ptr *) buffer,			// A place to return the buffer pointer
                                kNoFileReference,		// Not a file read
                                vcb);					// Volume to read from
	}

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif

	return err;
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
	err = BlockFindContiguous(vcb, startingBlock, vcb->totalBlocks, minBlocks, maxBlocks,
								  actualStartBlock, actualNumBlocks);
	if (err == dskFulErr) {
		//€€ Should constrain the endingBlock here, so we don't bother looking for ranges
		//€€ that start after startingBlock, since we already checked those.
		err = BlockFindContiguous(vcb, 0, vcb->totalBlocks, minBlocks, maxBlocks,
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
OSErr BlockAllocateAny(
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

#if HFS_DIAGNOSTIC
    struct buf *bp = NULL;
    int mappingEntry;
#endif

	//	Since this routine doesn't wrap around
	if (maxBlocks > (endingBlock - startingBlock)) {
		maxBlocks = endingBlock - startingBlock;
	}

    DBG_TREE (("\nAllocating starting at %ld, maxblocks %ld\n", startingBlock, maxBlocks));	
	//
	//	Pre-read the first bitmap block
	//
    err = ReadBitmapBlock(vcb, startingBlock, &currCache);
    DBG_TREE (("\n1. Read bit map at %ld, buffer is 0x%x\n", startingBlock, (int)currCache));	
	if (err != noErr) goto Exit;
    buffer = currCache;
    MarkBlock_glue((Ptr) currCache);		//	this block will be dirty
    DBG_ASSERT(! LookupBufferMapping((caddr_t)currCache, &bp, &mappingEntry));

	//
	//	Set up the current position within the block
	//
	{
		UInt32 wordIndexInBlock;

		wordIndexInBlock = (startingBlock & kBitsWithinBlockMask) / kBitsPerWord;
		buffer += wordIndexInBlock;
		wordsLeft = kWordsPerBlock - wordIndexInBlock;
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
#if EXPLICIT_BUFFER_RELEASES
            	DBG_ASSERT(! LookupBufferMapping((caddr_t)currCache, &bp, &mappingEntry));
            	err = RelBlock_glue((Ptr)currCache, rbDefault);
				if (err != noErr) goto Exit;
                buffer = currCache = NULL;
#endif
                err = ReadBitmapBlock(vcb, block, &currCache);
				if (err != noErr) goto Exit;
                buffer = currCache;
                DBG_TREE (("\n2. Read bit map at %ld, buffer is 0x%x\n", block, (int)currCache));	
                DBG_ASSERT(! LookupBufferMapping((caddr_t)currCache, &bp, &mappingEntry));
                MarkBlock_glue((Ptr) currCache);		//	this block will be dirty

				wordsLeft = kWordsPerBlock;
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
#if EXPLICIT_BUFFER_RELEASES
            	DBG_ASSERT(! LookupBufferMapping((caddr_t)currCache, &bp, &mappingEntry));
           	 	err = RelBlock_glue((Ptr)currCache, rbDefault);
				if (err != noErr) goto Exit;
                buffer = currCache = NULL;
#endif
                err = ReadBitmapBlock(vcb, block, &currCache);
				if (err != noErr) goto Exit;
                buffer = currCache;
                DBG_TREE (("\n3. Read bit map at %ld, buffer is 0x%x\n", block, (int)currCache));	
                DBG_ASSERT(! LookupBufferMapping((caddr_t)currCache, &bp, &mappingEntry));
                MarkBlock_glue((Ptr) currCache);		//	this block will be dirty

				wordsLeft = kWordsPerBlock;
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
	
#if EXPLICIT_BUFFER_RELEASES
    if (currCache) {
        DBG_ASSERT(! LookupBufferMapping((caddr_t)currCache, &bp, &mappingEntry));
        (void)RelBlock_glue((Ptr)currCache, rbDefault);		/* Ignore any additional errors */
        };
#endif

	return err;
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

#if HFSInstrumentation
	InstTraceClassRef	trace;
	InstEventTag		eventTag;
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:VSM:BlockMarkAllocated", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	eventTag = InstCreateEventTag();
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
#endif

	//
	//	Pre-read the bitmap block containing the first word of allocation
	//

	err = ReadBitmapBlock(vcb, startingBlock, &buffer);
	if (err != noErr) goto Exit;
	MarkBlock_glue((Ptr) buffer);		//	this block will be dirty

	//
	//	Initialize currentWord, and wordsLeft.
	//
	{
		UInt32 wordIndexInBlock;

		wordIndexInBlock = (startingBlock & kBitsWithinBlockMask) / kBitsPerWord;
		currentWord = buffer + wordIndexInBlock;
		wordsLeft = kWordsPerBlock - wordIndexInBlock;
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
			DebugStr("\pFATAL: blocks already allocated!");
			//err = fsDSIntErr;
			//goto Exit;
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
			startingBlock += kBitsPerBlock;			//	generate a block number in the next bitmap block
			
#if EXPLICIT_BUFFER_RELEASES
			err = RelBlock_glue((Ptr)buffer, rbDefault);
			if (err != noErr) goto Exit;
			buffer = NULL;
#endif
			err = ReadBitmapBlock(vcb, startingBlock, &buffer);
			if (err != noErr) goto Exit;
			MarkBlock_glue((Ptr) buffer);			//	this block will be dirty
			
			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = kWordsPerBlock;
		}
#if DEBUG_BUILD
		if (*currentWord != 0) {
			DebugStr("\pFATAL: blocks already allocated!");
			//err = fsDSIntErr;
			//goto Exit;
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
			startingBlock += kBitsPerBlock;				//	generate a block number in the next bitmap block
			
#if EXPLICIT_BUFFER_RELEASES
			err = RelBlock_glue((Ptr)buffer, rbDefault);
			if (err != noErr) goto Exit;
			buffer = NULL;
#endif
			err = ReadBitmapBlock(vcb, startingBlock, &buffer);
			if (err != noErr) goto Exit;
			MarkBlock_glue((Ptr) buffer);				//	this block will be dirty
			
			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = kWordsPerBlock;
		}
#if DEBUG_BUILD
		if ((*currentWord & SWAP_BE32 (bitMask)) != 0) {
			DebugStr("\pFATAL: blocks already allocated!");
			//err = fsDSIntErr;
			//goto Exit;
		}
#endif
		*currentWord |= SWAP_BE32 (bitMask);			//	set the bits in the bitmap

		//	No need to update currentWord or wordsLeft
	}

Exit:

#if EXPLICIT_BUFFER_RELEASES
	if (buffer) {
		(void)RelBlock_glue((Ptr)buffer, rbDefault);		/* Ignore any additional errors */
	};
#endif

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif

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

#if HFSInstrumentation
	InstTraceClassRef	trace;
	InstEventTag		eventTag;
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:VSM:BlockMarkFree", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	eventTag = InstCreateEventTag();
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
#endif

	//
	//	Pre-read the bitmap block containing the first word of allocation
	//

	err = ReadBitmapBlock(vcb, startingBlock, &buffer);
	if (err != noErr) goto Exit;
	MarkBlock_glue((Ptr) buffer);		//	this block will be dirty

	//
	//	Initialize currentWord, and wordsLeft.
	//
	{
		UInt32 wordIndexInBlock;

		wordIndexInBlock = (startingBlock & kBitsWithinBlockMask) / kBitsPerWord;
		currentWord = buffer + wordIndexInBlock;
		wordsLeft = kWordsPerBlock - wordIndexInBlock;
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
			DebugStr("\pFATAL: blocks not allocated!");
			//err = fsDSIntErr;
			//goto Exit;
		}
#endif
		*currentWord &= SWAP_BE32 (~bitMask);		//	clear the bits in the bitmap
		numBlocks -= numBits;						//	adjust number of blocks left to free

		++currentWord;								//	move to next word
		--wordsLeft;								//	one less word left in this block
	}

	//
	//	Allocate whole words (32 blocks) at a time.
	//

	while (numBlocks >= kBitsPerWord) {
		if (wordsLeft == 0) {
			//	Read in the next bitmap block
			startingBlock += kBitsPerBlock;			//	generate a block number in the next bitmap block
			
#if EXPLICIT_BUFFER_RELEASES
			err = RelBlock_glue((Ptr)buffer, rbDefault);
			if (err != noErr) goto Exit;
			buffer = NULL;
#endif
			err = ReadBitmapBlock(vcb, startingBlock, &buffer);
			if (err != noErr) goto Exit;
			MarkBlock_glue((Ptr) buffer);			//	this block will be dirty
			
			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = kWordsPerBlock;
		}

#if DEBUG_BUILD
		if (*currentWord != SWAP_BE32 (kAllBitsSetInWord)) {
			DebugStr("\pFATAL: blocks not allocated!");
			//err = fsDSIntErr;
			//goto Exit;
		}
#endif
		*currentWord = 0;							//	clear the entire word
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
			startingBlock += kBitsPerBlock;				//	generate a block number in the next bitmap block
			
#if EXPLICIT_BUFFER_RELEASES
			err = RelBlock_glue((Ptr)buffer, rbDefault);
			if (err != noErr) goto Exit;
			buffer = NULL;
#endif
			err = ReadBitmapBlock(vcb, startingBlock, &buffer);
			if (err != noErr) goto Exit;
			MarkBlock_glue((Ptr) buffer);				//	this block will be dirty
			
			//	Readjust currentWord and wordsLeft
			currentWord = buffer;
			wordsLeft = kWordsPerBlock;
		}
#if DEBUG_BUILD
		if ((*currentWord & SWAP_BE32 (bitMask)) != SWAP_BE32 (bitMask)) {
			DebugStr("\pFATAL: blocks not allocated!");
			//err = fsDSIntErr;
			//goto Exit;
		}
#endif
		*currentWord &= SWAP_BE32 (~bitMask);			//	clear the bits in the bitmap

		//	No need to update currentWord or wordsLeft
	}

Exit:

#if EXPLICIT_BUFFER_RELEASES
	if (buffer) {
		(void)RelBlock_glue((Ptr)buffer, rbDefault);		/* Ignore any additional errors */
	};
#endif

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif

	return err;
}


/*
_______________________________________________________________________

Routine:	BlockFindContiguous

Function:	Find a contiguous range of blocks that are free (bits
			clear in the bitmap).  If a contiguous range of the
			minimum size can't be found, an error will be returned.
			
			€€ It would be nice if we could skip over whole words
			€€ with all bits set.
			
			€€ When we find a bit set, and are about to set freeBlocks
			€€ to 0, we should check to see whether there are still
			€€ minBlocks bits left in the bitmap.

Inputs:
	vcb				Pointer to volume where space is to be allocated
	startingBlock	Preferred first block of range
	endingBlock		Last possible block in range + 1
	minBlocks		Minimum number of blocks needed.  Must be > 0.
	maxBlocks		Maximum (ideal) number of blocks desired

Outputs:
	actualStartBlock	First block of range found, or 0 if error
	actualNumBlocks		Number of blocks found, or 0 if error
_______________________________________________________________________
*/
/*
_________________________________________________________________________________________
	(DSH) 5/8/97 Description of BlockFindContiguous() algorithm
	Finds a contiguous range of free blocks by searching back to front.  This
	allows us to skip ranges of bits knowing that they are not candidates for
	a match because they are too small.  The below ascii diagrams illustrate
	the algorithm in action.
	
	Representation of a piece of a volume bitmap file
	If BlockFindContiguous() is called with minBlocks == 10, maxBlocks == 20


Fig. 1 initialization of variables, "<--" represents direction of travel

startingBlock (passed in)
	|
	1  0  1  0  1  0  1  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1
	|                       <--|
stopBlock                 currentBlock                        freeBlocks == 0
                                                              countedFreeBlocks == 0

Fig. 2 dirty bit found

	1  0  1  0  1  0  1  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1
	|                 |
stopBlock        currentBlock                                 freeBlocks == 3
                                                              countedFreeBlocks == 0

Fig. 3 reset variables to search for remainder of minBlocks

	1  0  1  0  1  0  1  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1
	|_________________|           |                 |
	     Unsearched            stopBlock        currentBlock    freeBlocks == 0
	                                                            countedFreeBlocks == 3

Fig. 4 minBlocks contiguous blocks found, *actualStartBlock is set

	1  0  1  0  1  0  1  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1
	|_________________|           |
	     Unsearched            stopBlock                      freeBlocks == 7
	                          currentBlock                    countedFreeBlocks == 3

Fig. 5 Now run it forwards trying to accumalate up to maxBlocks if possible

	1  0  1  0  1  0  1  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1
	|_________________|                                | -->
	     Unsearched                               currentBlock
		                                                      *actualNumBlocks == 10

Fig. 6 Dirty bit is found, return actual number of contiguous blocks found

	1  0  1  0  1  0  1  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1
	|_________________|                                                  |
	     Unsearched                                                 currentBlock
		                                                      *actualNumBlocks == 16
_________________________________________________________________________________________
*/

static OSErr BlockFindContiguous(
	ExtendedVCB		*vcb,
	UInt32			startingBlock,
	register UInt32	endingBlock,
	UInt32			minBlocks,
	UInt32			maxBlocks,
	UInt32			*actualStartBlock,
	UInt32			*actualNumBlocks)
{
	OSErr			err;
	register UInt32	bitMask;			//	mask of bit within word for currentBlock
	register UInt32	tempWord;			//	bitmap word currently being examined
	register UInt32	freeBlocks;			//	number of contiguous free blocks so far
	register UInt32	currentBlock;		//	block number we're currently examining
	UInt32			wordsLeft;			//	words remaining in bitmap block
	UInt32			*buffer = NULL;
	register UInt32	*currentWord;
	
	UInt32			stopBlock;			//	when all blocks until stopBlock are free, we found enough
	UInt32			countedFreeBlocks;	//	how many contiguous free block behind stopBlock
	UInt32			currentSector;		//	which allocations file sector

#if HFSInstrumentation
	InstTraceClassRef		trace;
	InstEventTag			eventTag;
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:VSM:BlockFindContiguous", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	eventTag = InstCreateEventTag();
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
#endif

	if ((endingBlock - startingBlock) < minBlocks) {
		//	The set of blocks we're checking is smaller than the minimum number
		//	of blocks, so we couldn't possibly find a good range.
		err = dskFulErr;
		goto Exit;
	}
	
	//	Search for min blocks from back to front.
	//	If min blocks is found, advance the allocation pointer up to max blocks
	
	//
	//	Pre-read the bitmap block containing currentBlock
	//
	stopBlock		= startingBlock;
	currentBlock	= startingBlock + minBlocks - 1;		//	(-1) to include startingBlock
	
	err = ReadBitmapBlock( vcb, currentBlock, &buffer );
	if ( err != noErr ) goto Exit;
	
	//
	//	Init buffer, currentWord, wordsLeft, and bitMask
	//
	{
		UInt32 wordIndexInBlock;

		wordIndexInBlock = ( currentBlock & kBitsWithinBlockMask ) / kBitsPerWord;
		currentWord		= buffer + wordIndexInBlock;
				
		wordsLeft		= wordIndexInBlock;
		tempWord		= SWAP_BE32 (*currentWord);
		bitMask			= kHighBitInWordMask >> ( currentBlock & kBitsWithinWordMask );
		currentSector	= currentBlock / kBitsPerBlock;
	}
	
	//
	//	Look for maxBlocks free blocks.  If we find an allocated block,
	//	see if we've found minBlocks.
	//
	freeBlocks			= 0;
	countedFreeBlocks	= 0;

	while ( currentBlock >= stopBlock )
	{
		//	Check current bit
		if ((tempWord & bitMask) == 0)
		{
			++freeBlocks;
		}
		else															//	Used bitmap block found
		{
			if ( ( freeBlocks +  countedFreeBlocks ) >= minBlocks )
			{
				break;													//	Found enough
			}
			else
			{
				//	We found a dirty bit, so we want to check if the next (minBlocks-freeBlocks) blocks
				//	are free beyond what we have already checked. At Fig.2 setting up for Fig.3
				
				stopBlock			= currentBlock + 1 + freeBlocks;	//	Advance stop condition
				currentBlock		+= minBlocks;
				if ( currentBlock >= endingBlock ) break;
				countedFreeBlocks	= freeBlocks;
				freeBlocks			= 0;								//	Not enough; look for another range

				if ( currentSector != currentBlock / kBitsPerBlock )
				{
#if EXPLICIT_BUFFER_RELEASES
					err = RelBlock_glue((Ptr)buffer, rbDefault);
					if (err != noErr) goto Exit;
					buffer = NULL;
#endif
					err = ReadBitmapBlock( vcb, currentBlock, &buffer );
					if (err != noErr) goto Exit;
					currentSector = currentBlock / kBitsPerBlock;
				}
					
				wordsLeft	= ( currentBlock & kBitsWithinBlockMask ) / kBitsPerWord;
				currentWord	= buffer + wordsLeft;
				tempWord	= SWAP_BE32 (*currentWord);
				bitMask		= kHighBitInWordMask >> ( currentBlock & kBitsWithinWordMask );

				continue;												//	Back to the while loop
			}
		}
		
		//	Move to next bit
		--currentBlock;
		bitMask <<= 1;
		if (bitMask == 0)												//	On a word boundry, start masking words
		{
			bitMask = kLowBitInWordMask;

			//	Move to next word
NextWord:
			if ( wordsLeft != 0 )
			{
				--currentWord;
				--wordsLeft;
			}
			else
			{
				//	Read in the next bitmap block
#if EXPLICIT_BUFFER_RELEASES
				err = RelBlock_glue((Ptr)buffer, rbDefault);
				if (err != noErr) goto Exit;
				buffer = NULL;
#endif
				err = ReadBitmapBlock( vcb, currentBlock, &buffer );
				if (err != noErr) goto Exit;
				
				//	Adjust currentWord, wordsLeft, currentSector
				currentSector	= currentBlock / kBitsPerBlock;
				currentWord		= buffer + kWordsPerBlock - 1;	//	Last word in buffer
				wordsLeft		= kWordsPerBlock - 1;
			}
			
			tempWord = SWAP_BE32 (*currentWord);				//	Grab the current word

			//
			//	If we found a whole word of free blocks, quickly skip over it.
			//	NOTE: we could actually go beyond the end of the bitmap if the
			//	number of allocation blocks on the volume is not a multiple of
			//	32.  If this happens, we'll adjust currentBlock and freeBlocks
			//	after the loop.
			//
			if ( tempWord == 0 )
			{
				freeBlocks		+= kBitsPerWord;
				currentBlock	-= kBitsPerWord;
				if ( freeBlocks + countedFreeBlocks >= minBlocks )
					break;									//	Found enough
				goto NextWord;
			}
		}
	}

	if ( freeBlocks + countedFreeBlocks < minBlocks )
	{
		*actualStartBlock	= 0;
		*actualNumBlocks	= 0;
		err					= dskFulErr;
		goto Exit;
	}

	//
	//	When we get here, we know we've found minBlocks continuous space.
	//	At Fig.4, setting up for Fig.5
	//	From here we do a forward search accumalating additional free blocks.
	//
	
	*actualNumBlocks	= minBlocks;
	*actualStartBlock	= stopBlock - countedFreeBlocks;	//	ActualStartBlock is set to return to the user
	currentBlock		= *actualStartBlock + minBlocks;	//	Right after found free space
	
	//	Now lets see if we can run the actualNumBlocks number all the way up to maxBlocks
	if ( currentSector != currentBlock / kBitsPerBlock )
	{
#if EXPLICIT_BUFFER_RELEASES
		err = RelBlock_glue((Ptr)buffer, rbDefault);
		if (err != noErr) goto Exit;
		buffer = NULL;
#endif
		err = ReadBitmapBlock( vcb, currentBlock, &buffer );
		if (err != noErr)
		{
			err	= noErr;									//	We already found the space
			goto Exit;
		}
		
		currentSector = currentBlock / kBitsPerBlock;
	}

	//
	//	Init buffer, currentWord, wordsLeft, and bitMask
	//
	{
		UInt32 wordIndexInBlock;

		wordIndexInBlock = (currentBlock & kBitsWithinBlockMask) / kBitsPerWord;
		currentWord		= buffer + wordIndexInBlock;
		tempWord		= SWAP_BE32 (*currentWord);
		wordsLeft		= kWordsPerBlock - wordIndexInBlock;
		bitMask			= kHighBitInWordMask >> (currentBlock & kBitsWithinWordMask);
	}

	if ( *actualNumBlocks < maxBlocks )
	{
		while ( currentBlock < endingBlock )
		{
				
			if ( (tempWord & bitMask) == 0 )
			{
				*actualNumBlocks	+= 1;
				
				if ( *actualNumBlocks == maxBlocks )
					break;
			}
			else
			{
				break;
			}
	
			//	Move to next bit
			++currentBlock;
			bitMask >>= 1;
			if (bitMask == 0)
			{
				bitMask = kHighBitInWordMask;
				++currentWord;
	
				if ( --wordsLeft == 0)
				{
#if EXPLICIT_BUFFER_RELEASES
					err = RelBlock_glue((Ptr)buffer, rbDefault);
					if (err != noErr) goto Exit;
					buffer = NULL;
#endif
					err = ReadBitmapBlock(vcb, currentBlock, &buffer);
					if (err != noErr) break;
					
					//	Adjust currentWord, wordsLeft
					currentWord		= buffer;
					wordsLeft		= kWordsPerBlock;
				}
				tempWord = SWAP_BE32 (*currentWord);		//	grab the current word
			}
		}
	}
	
Exit:

#if EXPLICIT_BUFFER_RELEASES
	if (buffer) {
		(void)RelBlock_glue((Ptr)buffer, rbDefault);		/* Ignore any additional errors */
	};
#endif

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif

	return err;
}


