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
	File:		FileExtentMapping.c

	Contains:	xxx put contents here xxx

	Version:	HFS Plus 1.0

	Written by:	Dave Heller, Mark Day

	Copyright:	© 1996-1999 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Mark Day

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(DSH)	Deric Horn
		(msd)	Mark Day
		(djb)	Don Brady

	Change History (most recent first):
	  <MacOSX>	  9/9/99	djb		Fix fcbModifiedMask flag testing logic.
	  <MacOSX>	 8/25/98	djb		Flush extents b-tree header if dirty (2371088).
	  <MacOSX>	 6/30/98	djb		Add functions NodesAreContiguous and ExtentsAreIntegral (for radar #2249539).
	  <MacOSX>	 6/23/98	djb		Changed DeallocFile to DeleteFile which now deletes the catalog record.
	  								Fixed UpdateExtentRecord to pass correct fcb to Btree routines. Fixed
	  								hfs+ bug in CreateExtentRecord (double dereference).
	  <MacOSX>	 5/20/98	djb		In ExtendFileC don't lie about the peof! (radar #2230094).
	  <MacOSX>	 4/17/98	djb		Add VCB locking.
	  <MacOSX>	  4/2/98	djb		Switch over to real BTree interface (no more BTreeWrapper.c).
	  <MacOSX>	 3/31/98	djb		Sync up with final HFSVolumes.h header file.

	  <CS24>	 1/23/98	msd		Bug 2208024: AllocContig is actually allocating one extent even
									though there is not enough contiguous space.
	  <CS23>	 12/2/97	DSH		GetFCBExtentRecord no longer static so DFA can use it.
	  <CS22>	10/20/97	msd		When allocating more space for a file, do the clump size
									calculations in ExtendFileC, not BlockAllocate. Undo change from
									<CS18>.
	  <CS21>	10/17/97	msd		Conditionalize DebugStrs.
	  <CS20>	10/16/97	msd		Simplify the code path for MapFileBlockC (logical to physical
									block mapping) in the typical case where the file isn't
									fragmented so badly that it has extents in the extents B-tree.
									Simplified some of the calculations for all cases.
	  <CS19>	10/13/97	DSH		FindExtentRecord & DeleteExtentRecord are also being used by DFA
									no longer static.
	  <CS18>	 10/6/97	msd		When extending a file, set the physical EOF to include any extra
									space allocated due to a file's clump size.
	  <CS17>	 9/19/97	msd		Remove the MapLogicalToPhysical SPI. It was never used and is
									not being tested anyway.
	  <CS16>	  9/5/97	msd		In CompareExtentKeys and CompareExtentKeysPlus, use the symbolic
									constants for key length. Don't DebugStr unless DEBUG_BUILD is
									set.
	  <CS15>	 7/24/97	djb		Add instrumentation to MapFileBlockC
	  <CS14>	 7/16/97	DSH		FilesInternal.i renamed FileMgrInternal.i to avoid name
									collision
	  <CS13>	 7/15/97	DSH		AdjEOF() mark the FCB as modified. (1664389)
	  <CS12>	  7/8/97	DSH		Loading PrecompiledHeaders from define passed in on C line
	  <CS11>	  7/3/97	msd		Bug #1663518. Remove DebugStr when setting the FCB extent record
									for a volume control file.
	  <CS10>	 6/27/97	msd		Moved enum kFirstFileRefnum to FilesInternal.
	   <CS9>	 6/24/97	djb		Include "CatalogPrivate.h"
	   <CS8>	 6/16/97	msd		Finish implementation of CreateLargeFile SPI.
	   <CS7>	 6/12/97	msd		Add stub for CreateLargeFile SPI.
	   <CS6>	  6/5/97	msd		Add MapLogicalToPhysical.
	   <CS5>	  6/2/97	msd		In TruncateFileC, don't update the extent record unless it was
									actually changed (prevents extra updates when truncating to the
									end of the extent, and it is the last extent of the file.) Added
									an AdjustEOF routine called by the assembly AdjEOF routine. It
									copies the EOF, physical length, and extent information from one
									FCB to all other FCBs for that fork.
	   <CS4>	 5/20/97	DSH		Removed const declaration in MapFileBlocC, const is benign when
									passing by value, and SC requires it to match prototype.
	   <CS3>	 5/15/97	msd		Change enum kResourceForkType from -1 to 0xFF since it is now
									unsigned. Change all forkType parameters to UInt8.
	   <CS2>	  5/7/97	msd		When checking for an unused extent descriptor, check the length,
									not the starting block.
	   <CS1>	 4/24/97	djb		first checked in
	 <HFS25>	 4/11/97	DSH		use extended VCB fields catalogRefNum, and extentsRefNum.
	 <HFS24>	  4/4/97	djb		Get in sync with volume format changes.
	 <HFS23>	 3/17/97	DSH		Casting to compile with SC.
	 <HFS22>	 2/26/97	msd		Add instrumentation in ExtendFileC and TruncateFileC. In
									CompareExtentKeys and CompareExtentKeysPlus, make sure the key
									lengths are correct.
	 <HFS21>	  2/5/97	msd		The comparison with fsBTStartOfIterationErr didn't work because
									the enum is an unsigned long; it is now casted to an OSErr
									before comparing.
	 <HFS20>	 1/31/97	msd		In FindExtentRecord, turn an fsBTStartOfIterationErr error into
									btNotFound.
	 <HFS19>	 1/28/97	msd		Fixed bug in MapFileBlockC where it returned the wrong number of
									bytes available at the given block number.  This could
									potentially cause programs to read or write over other files.
	 <HFS18>	 1/16/97	djb		Extent key compare procs now return SInt32. Fixed
									UpdateExtentRecord - it was passing a pointer to an ExtentKey
									pointer.
	 <HFS17>	 1/10/97	msd		Change TruncateFileC to call DellocateFork when the new PEOF is
									0. Fixes a fxRangeErr returned when no extents existed.
	 <HFS16>	  1/6/97	msd		Previous change prevents extent records from being removed if
									the files new PEOF is in the local (FCB/catalog) extents.
	 <HFS15>	  1/3/97	djb		Temp fix in TruncateFileC to prevent unwanted calls to
									TruncateExtents.
	 <HFS14>	12/23/96	msd		Previous change to SearchExtentFile didn't set up the outputs
									for hint and key when the FCB extent record wasn't full.
	 <HFS13>	12/20/96	msd		In SearchExtentFile, don't bother searching the extents file if
									the FCB's extent record wasn't full, or if the FCB was for the
									extents file itself. Modified SearchExtentRecord to return a
									Boolean to indicate that the record was not full.
	 <HFS12>	12/19/96	DSH		Changed refs from VCB to ExtendedVCB
	 <HFS11>	12/19/96	djb		Updated for new B-tree Manager interface.
	 <HFS10>	12/12/96	djb		Really use new SPI for GetCatalogNode.
	  <HFS9>	12/12/96	djb		Use new Catalog SPI for GetCatalogNode. Added Mark's changes to
									MapFileBlockC.
	  <HFS8>	12/11/96	msd		TruncateFileC must always release extents, even if PEOF hasn't
									changed (since allocation may have been rounded up due to clump
									size).
	  <HFS7>	12/10/96	msd		Check PRAGMA_LOAD_SUPPORTED before loading precompiled headers.
	  <HFS6>	 12/4/96	DSH		Precompiled headers
	  <HFS5>	11/26/96	msd		Add an exported routine to grow the parallel FCB table to
									accomodate the HFS+ ExtentRecord.
	  <HFS4>	11/26/96	msd		Convert internal routines to use ExtentKey and ExtentRecord
									(instead of the raw HFS structures).
	  <HFS3>	11/21/96	msd		Added CompareExtentKeysPlus().
	  <HFS2>	11/20/96	msd		Finish porting FXM to C.
	  <HFS1>	 11/6/96	DKH		first checked in

*/


#include "../../hfs.h"
#include "../../hfs_format.h"
#include "../../hfs_endian.h"

#include "../headers/FileMgrInternal.h"
#include "../headers/BTreesInternal.h"
#include "../headers/CatalogPrivate.h"		// calling a private catalog routine (LocateCatalogNode)

#include "../headers/HFSInstrumentation.h"

#include <sys/malloc.h>
 
/*
============================================================
Public (Exported) Routines:
============================================================
	DeAllocFile		Deallocate all disk space allocated to a specified file.
					Both forks are deallocated.

	ExtendFileC		Allocate more space to a given file.

	CompareExtentKeys
					Compare two extents file keys (a search key and a trial
					key).  Used by the BTree manager when searching for,
					adding, or deleting keys in the extents file of an HFS
					volume.
					
	CompareExtentKeysPlus
					Compare two extents file keys (a search key and a trial
					key).  Used by the BTree manager when searching for,
					adding, or deleting keys in the extents file of an HFS+
					volume.
					
	MapFileBlockC	Convert (map) an offset within a given file into a
					physical disk address.
					
	TruncateFileC	Truncates the disk space allocated to a file.  The file
					space is truncated to a specified new physical EOF, rounded
					up to the next allocation block boundry.  There is an option
					to truncate to the end of the extent containing the new EOF.
	
	FlushExtentFile
					Flush the extents file for a given volume.

	GrowParallelFCBs
					Make sure the parallel FCB entries are big enough to support
					the HFS+ ExtentRecord.  If not, the array is grown and the
					pre-existing data copied over.

	AdjustEOF
					Copy EOF, physical length, and extent records from one FCB
					to all other FCBs for that fork.  This is used when a file is
					grown or shrunk as the result of a Write, SetEOF, or Allocate.

	MapLogicalToPhysical
					Map some position in a file to a volume block number.  Also
					returns the number of contiguous bytes that are mapped there.
					This is a queued HFSDispatch call that does the equivalent of
					MapFileBlockC, using a parameter block.

============================================================
Internal Routines:
============================================================
	FindExtentRecord
					Search the extents BTree for a particular extent record.
	SearchExtentFile
					Search the FCB and extents file for an extent record that
					contains a given file position (in bytes).
	SearchExtentRecord
					Search a given extent record to see if it contains a given
					file position (in bytes).  Used by SearchExtentFile.
	ReleaseExtents
					Deallocate all allocation blocks in all extents of an extent
					data record.
	TruncateExtents
					Deallocate blocks and delete extent records for all allocation
					blocks beyond a certain point in a file.  The starting point
					must be the first file allocation block for some extent record
					for the file.
	DeallocateFork
					Deallocate all allocation blocks belonging to a given fork.
	UpdateExtentRecord
					If the extent record came from the extents file, write out
					the updated record; otherwise, copy the updated record into
					the FCB resident extent record.  If the record has no extents,
					and was in the extents file, then delete the record instead.
*/

enum
{
	kTwoGigabytes			= (UInt32) 0x80000000,
	
	kDataForkType			= 0,
	kResourceForkType		= 0xFF,
	
	kPreviousRecord			= -1,
	
	kSectorSize				= 512		// Size of a physical sector
};

void HFSToHFSPlusExtents(
	const HFSExtentRecord	oldExtents,
	HFSPlusExtentRecord		newExtents);

OSErr HFSPlusToHFSExtents(
	const HFSPlusExtentRecord	oldExtents,
	HFSExtentRecord				newExtents);

OSErr FindExtentRecord(
	const ExtendedVCB		*vcb,
	UInt8					forkType,
	UInt32					fileID,
	UInt32					startBlock,
	Boolean					allowPrevious,
	HFSPlusExtentKey		*foundKey,
	HFSPlusExtentRecord		foundData,
	UInt32					*foundHint);

OSErr DeleteExtentRecord(
	const ExtendedVCB		*vcb,
	UInt8					forkType,
	UInt32					fileID,
	UInt32					startBlock);

static OSErr CreateExtentRecord(
	const ExtendedVCB		*vcb,
	HFSPlusExtentKey		*key,
	HFSPlusExtentRecord		extents,
	UInt32					*hint);


OSErr GetFCBExtentRecord(
	const FCB				*fcb,
	HFSPlusExtentRecord		extents);

static OSErr SearchExtentFile(
	const ExtendedVCB		*vcb,
	const FCB	 			*fcb,
	SInt64 					filePosition,
	HFSPlusExtentKey		*foundExtentKey,
	HFSPlusExtentRecord		foundExtentData,
	UInt32					*foundExtentDataIndex,
	UInt32					*extentBTreeHint,
	UInt32					*endingFABNPlusOne );

static OSErr SearchExtentRecord(
	const ExtendedVCB		*vcb,
	UInt32					searchFABN,
	const HFSPlusExtentRecord	extentData,
	UInt32					extentDataStartFABN,
	UInt32					*foundExtentDataOffset,
	UInt32					*endingFABNPlusOne,
	Boolean					*noMoreExtents);

static OSErr ReleaseExtents(
	ExtendedVCB				*vcb,
	const HFSPlusExtentRecord	extentRecord,
	UInt32					*numReleasedAllocationBlocks,
	Boolean 				*releasedLastExtent);

static OSErr DeallocateFork(
	ExtendedVCB 		*vcb,
	HFSCatalogNodeID	fileID,
	UInt8			forkType,
	HFSPlusExtentRecord	catalogExtents,
	Boolean *		recordDeleted);

static OSErr TruncateExtents(
	ExtendedVCB			*vcb,
	UInt8				forkType,
	UInt32				fileID,
	UInt32				startBlock,
	Boolean *			recordDeleted);

static OSErr UpdateExtentRecord (
	const ExtendedVCB		*vcb,
	FCB						*fcb,
	const HFSPlusExtentKey	*extentFileKey,
	const HFSPlusExtentRecord	extentData,
	UInt32					extentBTreeHint);

static OSErr MapFileBlockFromFCB(
	const ExtendedVCB		*vcb,
	const FCB				*fcb,
	SInt64					offset,			// Desired offset in bytes from start of file
	UInt32					*firstFABN,		// FABN of first block of found extent
	UInt32					*firstBlock,	// Corresponding allocation block number
	UInt32					*nextFABN);		// FABN of block after end of extent

static Boolean ExtentsAreIntegral(
	const HFSPlusExtentRecord extentRecord,
	UInt32		mask,
	UInt32		*blocksChecked,
	Boolean		*checkedLastExtent);

//_________________________________________________________________________________
//
//	Routine:	FindExtentRecord
//
//	Purpose:	Search the extents BTree for an extent record matching the given
//				FileID, fork, and starting file allocation block number.
//
//	Inputs:
//		vcb				Volume to search
//		forkType		0 = data fork, -1 = resource fork
//		fileID			File's FileID (CatalogNodeID)
//		startBlock		Starting file allocation block number
//		allowPrevious	If the desired record isn't found and this flag is set,
//						then see if the previous record belongs to the same fork.
//						If so, then return it.
//
//	Outputs:
//		foundKey	The key data for the record actually found
//		foundData	The extent record actually found (NOTE: on an HFS volume, the
//					fourth entry will be zeroes.
//		foundHint	The BTree hint to find the node again
//_________________________________________________________________________________
OSErr FindExtentRecord(
	const ExtendedVCB	*vcb,
	UInt8				forkType,
	UInt32				fileID,
	UInt32				startBlock,
	Boolean				allowPrevious,
	HFSPlusExtentKey	*foundKey,
	HFSPlusExtentRecord	foundData,
	UInt32				*foundHint)
{
	FCB *				fcb;
	BTreeIterator		btIterator;
	FSBufferDescriptor	btRecord;
	OSErr				err;
	UInt16				btRecordSize;
	
	err = noErr;
	*foundHint = 0;
	fcb = GetFileControlBlock(vcb->extentsRefNum);
	
	(void) BTInvalidateHint(&btIterator);

	if (vcb->vcbSigWord == kHFSSigWord) {
		HFSExtentKey *		extentKeyPtr;
		HFSExtentRecord		extentData;

		extentKeyPtr = (HFSExtentKey*) &btIterator.key;
		extentKeyPtr->keyLength	= kHFSExtentKeyMaximumLength;
		extentKeyPtr->forkType = forkType;
		extentKeyPtr->fileID = fileID;
		extentKeyPtr->startBlock = startBlock;
		
		btRecord.bufferAddress = &extentData;
		btRecord.itemSize = sizeof(HFSExtentRecord);
		btRecord.itemCount = 1;

		err = BTSearchRecord(fcb, &btIterator, kInvalidMRUCacheKey, &btRecord, &btRecordSize, &btIterator);

		if (err == btNotFound && allowPrevious) {
			err = BTIterateRecord(fcb, kBTreePrevRecord, &btIterator, &btRecord, &btRecordSize);

			//	A previous record may not exist, so just return btNotFound (like we would if
			//	it was for the wrong file/fork).
			if (err == (OSErr) fsBTStartOfIterationErr)		//¥¥ fsBTStartOfIterationErr is type unsigned long
				err = btNotFound;

			if (err == noErr) {
				//	Found a previous record.  Does it belong to the same fork of the same file?
				if (extentKeyPtr->fileID != fileID || extentKeyPtr->forkType != forkType)
					err = btNotFound;
			}
		}

		if (err == noErr) {
			UInt16	i;
			
			//	Copy the found key back for the caller
			foundKey->keyLength 	= kHFSPlusExtentKeyMaximumLength;
			foundKey->forkType		= extentKeyPtr->forkType;
			foundKey->pad			= 0;
			foundKey->fileID		= extentKeyPtr->fileID;
			foundKey->startBlock	= extentKeyPtr->startBlock;
			
			//	Copy the found data back for the caller
			foundData[0].startBlock = extentData[0].startBlock;
			foundData[0].blockCount = extentData[0].blockCount;
			foundData[1].startBlock = extentData[1].startBlock;
			foundData[1].blockCount = extentData[1].blockCount;
			foundData[2].startBlock = extentData[2].startBlock;
			foundData[2].blockCount = extentData[2].blockCount;
			
			for (i = 3; i < kHFSPlusExtentDensity; ++i)
			{
				foundData[i].startBlock = 0;
				foundData[i].blockCount = 0;
			}
		}
	}
	else {		// HFS Plus volume
		HFSPlusExtentKey *	extentKeyPtr;
		HFSPlusExtentRecord	extentData;

		extentKeyPtr = (HFSPlusExtentKey*) &btIterator.key;
		extentKeyPtr->keyLength	 = kHFSPlusExtentKeyMaximumLength;
		extentKeyPtr->forkType	 = forkType;
		extentKeyPtr->pad		 = 0;
		extentKeyPtr->fileID	 = fileID;
		extentKeyPtr->startBlock = startBlock;
		
		btRecord.bufferAddress = &extentData;
		btRecord.itemSize = sizeof(HFSPlusExtentRecord);
		btRecord.itemCount = 1;

		err = BTSearchRecord(fcb, &btIterator, kInvalidMRUCacheKey, &btRecord, &btRecordSize, &btIterator);

		if (err == btNotFound && allowPrevious) {
			err = BTIterateRecord(fcb, kBTreePrevRecord, &btIterator, &btRecord, &btRecordSize);

			//	A previous record may not exist, so just return btNotFound (like we would if
			//	it was for the wrong file/fork).
			if (err == (OSErr) fsBTStartOfIterationErr)		//¥¥ fsBTStartOfIterationErr is type unsigned long
				err = btNotFound;

			if (err == noErr) {
				//	Found a previous record.  Does it belong to the same fork of the same file?
				if (extentKeyPtr->fileID != fileID || extentKeyPtr->forkType != forkType)
					err = btNotFound;
			}
		}

		if (err == noErr) {
			//	Copy the found key back for the caller
			BlockMoveData(extentKeyPtr, foundKey, sizeof(HFSPlusExtentKey));
			//	Copy the found data back for the caller
			BlockMoveData(&extentData, foundData, sizeof(HFSPlusExtentRecord));
		}
	}
	
	*foundHint = btIterator.hint.nodeNum;
	return err;
}



static OSErr CreateExtentRecord(
	const ExtendedVCB	*vcb,
	HFSPlusExtentKey	*key,
	HFSPlusExtentRecord	extents,
	UInt32				*hint)
{
	BTreeIterator		btIterator;
	FSBufferDescriptor	btRecord;
	UInt16				btRecordSize;
	OSErr				err;
	
	err = noErr;
	*hint = 0;
	(void) BTInvalidateHint(&btIterator);
	
	if (vcb->vcbSigWord == kHFSSigWord) {
		HFSExtentKey *		keyPtr;
		HFSExtentRecord		data;
		
		btRecordSize = sizeof(HFSExtentRecord);
		btRecord.bufferAddress = &data;
		btRecord.itemSize = btRecordSize;
		btRecord.itemCount = 1;

		keyPtr = (HFSExtentKey*) &btIterator.key;
		keyPtr->keyLength	= kHFSExtentKeyMaximumLength;
		keyPtr->forkType	= key->forkType;
		keyPtr->fileID		= key->fileID;
		keyPtr->startBlock	= key->startBlock;
		
		err = HFSPlusToHFSExtents(extents, data);
	}
	else {		// HFS Plus volume
		btRecordSize = sizeof(HFSPlusExtentRecord);
		btRecord.bufferAddress = extents;
		btRecord.itemSize = btRecordSize;
		btRecord.itemCount = 1;

		BlockMoveData(key, &btIterator.key, sizeof(HFSPlusExtentKey));
	}

	if (err == noErr)
		err = BTInsertRecord(GetFileControlBlock(vcb->extentsRefNum), &btIterator, &btRecord, btRecordSize);

	if (err == noErr)
		*hint = btIterator.hint.nodeNum;

	return err;
}


OSErr DeleteExtentRecord(
	const ExtendedVCB	*vcb,
	UInt8				forkType,
	UInt32				fileID,
	UInt32				startBlock)
{
	BTreeIterator		btIterator;
	OSErr				err;
	
	err = noErr;
	(void) BTInvalidateHint(&btIterator);
	
	if (vcb->vcbSigWord == kHFSSigWord) {
		HFSExtentKey *	keyPtr;

		keyPtr = (HFSExtentKey*) &btIterator.key;
		keyPtr->keyLength	= kHFSExtentKeyMaximumLength;
		keyPtr->forkType	= forkType;
		keyPtr->fileID		= fileID;
		keyPtr->startBlock	= startBlock;
	}
	else {		//	HFS Plus volume
		HFSPlusExtentKey *	keyPtr;

		keyPtr = (HFSPlusExtentKey*) &btIterator.key;
		keyPtr->keyLength	= kHFSPlusExtentKeyMaximumLength;
		keyPtr->forkType	= forkType;
		keyPtr->pad			= 0;
		keyPtr->fileID		= fileID;
		keyPtr->startBlock	= startBlock;
	}

	err = BTDeleteRecord(GetFileControlBlock(vcb->extentsRefNum), &btIterator);
	
	return err;
}



//_________________________________________________________________________________
//
// Routine:		MapFileBlock
//
// Function: 	Maps a file position into a physical disk address.
//
// Input:		A2.L  -  VCB pointer
//				(A1,D1.W)  -  FCB pointer
//				D4.L  -  number of bytes desired
//				D5.L  -  file position (byte address)
//
// Output:		D3.L  -  physical start block
//				D6.L  -  number of contiguous bytes available (up to D4 bytes)
//				D0.L  -  result code												<01Oct85>
//						   0 = ok
//						   FXRangeErr = file position beyond mapped range			<17Oct85>
//						   FXOvFlErr = extents file overflow						<17Oct85>
//						   other = error											<17Oct85>
//
// Called By:	Log2Phys (read/write in place), Cache (map a file block).
//_________________________________________________________________________________

OSErr MapFileBlockC (
	ExtendedVCB		*vcb,				// volume that file resides on
	FCB				*fcb,				// FCB of file
	size_t			numberOfBytes,		// number of contiguous bytes desired
	off_t			offset,				// starting offset within file (in bytes)
	daddr_t			*startSector,		// first 512-byte sector (NOT an allocation block)
	size_t			*availableBytes)	// number of contiguous bytes (up to numberOfBytes)
{
	OSErr				err;
	UInt32				allocBlockSize;			//	Size of the volume's allocation block
	HFSPlusExtentKey	foundKey;
	HFSPlusExtentRecord	foundData;
	UInt32				foundIndex;
	UInt32				hint;
	UInt32				firstFABN;				// file allocation block of first block in found extent
	UInt32				nextFABN;				// file allocation block of block after end of found extent
	off_t				dataEnd;				// (offset) end of range that is contiguous
	UInt32				sectorsPerBlock;		// Number of sectors per allocation block
	UInt32				startBlock;				// volume allocation block corresponding to firstFABN
	daddr_t				temp;
	off_t				tmpOff;
	
	
	LogStartTime(kTraceMapFileBlock);

	allocBlockSize = vcb->blockSize;
	
	err = MapFileBlockFromFCB(vcb, fcb, offset, &firstFABN, &startBlock, &nextFABN);
	if (err != noErr) {
		err = SearchExtentFile(vcb, fcb, offset, &foundKey, foundData, &foundIndex, &hint, &nextFABN);
		if (err == noErr) {
			startBlock = foundData[foundIndex].startBlock;
			firstFABN = nextFABN - foundData[foundIndex].blockCount;
		}
	}
	
	if (err != noErr)
	{
		LogEndTime(kTraceMapFileBlock, err);

		return err;
	}

	//
	//	Determine the end of the available space.  It will either be the end of the extent,
	//	or the file's PEOF, whichever is smaller.
	//
	dataEnd = (off_t)((off_t)(nextFABN) * (off_t)(allocBlockSize));		// Assume valid data through end of this extent
	if (fcb->fcbPLen < dataEnd)					// Is PEOF shorter?
		dataEnd = fcb->fcbPLen;					// Yes, so only map up to PEOF
	
	//	Compute the number of sectors in an allocation block
	sectorsPerBlock = allocBlockSize / kSectorSize;	// sectors per allocation block
	
	//
	//	Compute the absolute sector number that contains the offset of the given file
	//
	temp = (daddr_t)((offset - (off_t)((off_t)(firstFABN) * (off_t)(allocBlockSize)))/kSectorSize);	// offset in sectors from start of the extent
	temp += startBlock * sectorsPerBlock;			// offset in sectors from start of allocation block space
    if (vcb->vcbSigWord == kHFSPlusSigWord)
        temp += vcb->hfsPlusIOPosOffset/512;  /* offset inside wrapper */
    else
        temp += vcb->vcbAlBlSt;		/* offset in sectors from start of volume */
	
	//	Return the desired sector for file position "offset"
	*startSector = temp;
	
	//
	//	Determine the number of contiguous bytes until the end of the extent
	//	(or the amount they asked for, whichever comes first).
	//
	tmpOff = dataEnd - offset;
	if (tmpOff > (off_t)(numberOfBytes))
		*availableBytes = numberOfBytes;	// more there than they asked for, so pin the output
	else
		*availableBytes = tmpOff;
	LogEndTime(kTraceMapFileBlock, noErr);

	return noErr;
}


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	ReleaseExtents
//
//	Function: 	Release the extents of a single extent data record.
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

static OSErr ReleaseExtents(
	ExtendedVCB 			*vcb,
	const HFSPlusExtentRecord	extentRecord,
	UInt32					*numReleasedAllocationBlocks,
	Boolean 				*releasedLastExtent)
{
	UInt32	extentIndex;
	UInt32	numberOfExtents;
	OSErr	err = noErr;
	
	*numReleasedAllocationBlocks = 0;
	*releasedLastExtent = false;
	
	if (vcb->vcbSigWord == kHFSPlusSigWord)
		numberOfExtents = kHFSPlusExtentDensity;
	else
		numberOfExtents = kHFSExtentDensity;

	for( extentIndex = 0; extentIndex < numberOfExtents; extentIndex++)
	{
		UInt32	numAllocationBlocks;
		
		// Loop over the extent record and release the blocks associated with each extent.
		
		numAllocationBlocks = extentRecord[extentIndex].blockCount;
		if ( numAllocationBlocks == 0 )
		{
			*releasedLastExtent = true;
			break;
		}

		err = BlockDeallocate( vcb, extentRecord[extentIndex].startBlock, numAllocationBlocks );
		if ( err != noErr )
			break;
					
		*numReleasedAllocationBlocks += numAllocationBlocks;		//	bump FABN to beg of next extent
	}

	return( err );
}



//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	TruncateExtents
//
//	Purpose:	Delete extent records whose starting file allocation block number
//				is greater than or equal to a given starting block number.  The
//				allocation blocks represented by the extents are deallocated.
//
//	Inputs:
//		vcb			Volume to operate on
//		fileID		Which file to operate on
//		startBlock	Starting file allocation block number for first extent
//					record to delete.
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

static OSErr TruncateExtents(
	ExtendedVCB		*vcb,
	UInt8			forkType,
	UInt32			fileID,
	UInt32			startBlock,
	Boolean *		recordDeleted)
{
	OSErr				err;
	UInt32				numberExtentsReleased;
	Boolean				releasedLastExtent;
	UInt32				hint;
	HFSPlusExtentKey	key;
	HFSPlusExtentRecord	extents;

	while (true) {
		err = FindExtentRecord(vcb, forkType, fileID, startBlock, false, &key, extents, &hint);
		if (err != noErr) {
			if (err == btNotFound)
				err = noErr;
			break;
		}
		
		err = ReleaseExtents( vcb, extents, &numberExtentsReleased, &releasedLastExtent );
		if (err != noErr) break;
		
		err = DeleteExtentRecord(vcb, forkType, fileID, startBlock);
		if (err != noErr) break;

		*recordDeleted = true;
		startBlock += numberExtentsReleased;
	}
	
	return err;
}



//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	DeallocateFork
//
//	Function: 	De-allocates all disk space allocated to a specified fork.
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

static OSErr DeallocateFork(
	ExtendedVCB 		*vcb,
	HFSCatalogNodeID	fileID,
	UInt8			forkType,
	HFSPlusExtentRecord	catalogExtents,
	Boolean *		recordDeleted) /* true if a record was deleted */
{
	OSErr				err;
	UInt32				numReleasedAllocationBlocks;
	Boolean				releasedLastExtent;
	
	//	Release the catalog extents
	err = ReleaseExtents( vcb, catalogExtents, &numReleasedAllocationBlocks, &releasedLastExtent );
	// Release the extra extents, if present
	if (err == noErr && !releasedLastExtent)
		err = TruncateExtents(vcb, forkType, fileID, numReleasedAllocationBlocks, recordDeleted);

	return( err );
}

//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	FlushExtentFile
//
//	Function: 	Flushes the extent file for a specified volume
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

OSErr FlushExtentFile( ExtendedVCB *vcb )
{
	FCB *	fcb;
	OSErr	err;
	
	fcb = GetFileControlBlock(vcb->extentsRefNum);
	err = BTFlushPath(fcb);
	if ( err == noErr )
	{
		// If the FCB for the extent "file" is dirty, mark the VCB as dirty.
		
        if ((fcb->fcbFlags & fcbModifiedMask) != 0)
		{
			MarkVCBDirty( vcb );
			err = FlushVolumeControlBlock( vcb );
		}
	}
	
	return( err );
}

//-------------------------------------------------------------------------------
//	Routine:	DeleteFile
//
//	Function: 	De-allocates all disk space allocated to a specified file 
//				including the space used by the catalog (ie the catalog record).
//				The space occupied by both forks is also deallocated.
//
//-------------------------------------------------------------------------------

OSErr DeleteFile( ExtendedVCB *vcb, HFSCatalogNodeID parDirID, ConstUTF8Param catalogName, UInt32 catalogHint )
{
	OSErr			err;
	OSErr			errDF, errRF;
	CatalogNodeData	catalogData;
	Boolean			recordDeleted;
	
	recordDeleted = false;
	
	INIT_CATALOGDATA(&catalogData, kCatNameNoCopyName);
	
	// Find catalog data in catalog
    err = GetCatalogNode( vcb, parDirID, catalogName, kUndefinedStrLen, catalogHint, &catalogData, &catalogHint);
	if( err != noErr )
		goto Exit;

	
	// Check to make sure record is for a file
	if ( catalogData.cnd_type != kCatalogFileNode )
	{
		err = notAFileErr;
		goto Exit;
	}
	
	//
	// Always delete the Catalog record first (to minimize disk corruption)
	//
	err = DeleteCatalogNode(vcb, parDirID, catalogName, catalogHint);
	if( err != noErr )
		goto Exit;

	//
	// Note: we don't report errors from DeallocateFork since the
	// file no longer exists (since DeleteCatalogNode succeeded).
	// Any errors mean that there are possibly some orphaned disk
	// blocks but from the clients perspective the file was deleted.
	//

	// Deallocate data fork extents
	errDF = DeallocateFork( vcb, catalogData.cnd_nodeID, kDataForkType,
		    catalogData.cnd_datafork.extents, &recordDeleted );

	// Deallocate resource fork extents
	errRF = DeallocateFork( vcb, catalogData.cnd_nodeID, kResourceForkType,
		    catalogData.cnd_rsrcfork.extents, &recordDeleted );

	if (recordDeleted)
		err = FlushExtentFile( vcb );

	CLEAN_CATALOGDATA(&catalogData);
	return (errDF ? errDF : (errRF ? errRF : err));
Exit:
	
	CLEAN_CATALOGDATA(&catalogData);
	return( err );
}

//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	CompareExtentKeys
//
//	Function: 	Compares two extent file keys (a search key and a trial key) for
//				an HFS volume.
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

SInt32 CompareExtentKeys( const HFSExtentKey *searchKey, const HFSExtentKey *trialKey )
{
	SInt32	result;		//	± 1
	
	#if DEBUG_BUILD
		if (searchKey->keyLength != kHFSExtentKeyMaximumLength)
			DebugStr("\pHFS: search Key is wrong length");
		if (trialKey->keyLength != kHFSExtentKeyMaximumLength)
			DebugStr("\pHFS: trial Key is wrong length");
	#endif
	
	result = -1;		//	assume searchKey < trialKey
	
	if (searchKey->fileID == trialKey->fileID) {
		//
		//	FileNum's are equal; compare fork types
		//
		if (searchKey->forkType == trialKey->forkType) {
			//
			//	Fork types are equal; compare allocation block number
			//
			if (searchKey->startBlock == trialKey->startBlock) {
				//
				//	Everything is equal
				//
				result = 0;
			}
			else {
				//
				//	Allocation block numbers differ; determine sign
				//
				if (searchKey->startBlock > trialKey->startBlock)
					result = 1;
			}
		}
		else {
			//
			//	Fork types differ; determine sign
			//
			if (searchKey->forkType > trialKey->forkType)
				result = 1;
		}
	}
	else {
		//
		//	FileNums differ; determine sign
		//
		if (searchKey->fileID > trialKey->fileID)
			result = 1;
	}
	
	return( result );
}



//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	CompareExtentKeysPlus
//
//	Function: 	Compares two extent file keys (a search key and a trial key) for
//				an HFS volume.
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

SInt32 CompareExtentKeysPlus( const HFSPlusExtentKey *searchKey, const HFSPlusExtentKey *trialKey )
{
	SInt32	result;		//	± 1
	
	#if DEBUG_BUILD
		if (searchKey->keyLength != kHFSPlusExtentKeyMaximumLength)
			DebugStr("\pHFS: search Key is wrong length");
		if (trialKey->keyLength != kHFSPlusExtentKeyMaximumLength)
			DebugStr("\pHFS: trial Key is wrong length");
	#endif
	
	result = -1;		//	assume searchKey < trialKey
	
	if (searchKey->fileID == trialKey->fileID) {
		//
		//	FileNum's are equal; compare fork types
		//
		if (searchKey->forkType == trialKey->forkType) {
			//
			//	Fork types are equal; compare allocation block number
			//
			if (searchKey->startBlock == trialKey->startBlock) {
				//
				//	Everything is equal
				//
				result = 0;
			}
			else {
				//
				//	Allocation block numbers differ; determine sign
				//
				if (searchKey->startBlock > trialKey->startBlock)
					result = 1;
			}
		}
		else {
			//
			//	Fork types differ; determine sign
			//
			if (searchKey->forkType > trialKey->forkType)
				result = 1;
		}
	}
	else {
		//
		//	FileNums differ; determine sign
		//
		if (searchKey->fileID > trialKey->fileID)
			result = 1;
	}
	
	return( result );
}



//_________________________________________________________________________________
//
// Routine:		Extendfile
//
// Function: 	Extends the disk space allocated to a file.
//
// Input:		A2.L  -  VCB pointer
//				A1.L  -  pointer to FCB array
//				D1.W  -  file refnum
//				D3.B  -  option flags
//							kEFContigMask - force contiguous allocation
//							kEFAllMask - allocate all requested bytes or none
//							NOTE: You may not set both options.
//				D4.L  -  number of additional bytes to allocate
//
// Output:		D0.W  -  result code
//							 0 = ok
//							 -n = IO error
//				D6.L  -  number of bytes allocated
//
// Called by:	FileAloc,FileWrite,SetEof
//
// Note: 		ExtendFile updates the PEOF in the FCB.
//_________________________________________________________________________________

OSErr ExtendFileC (
	ExtendedVCB		*vcb,				// volume that file resides on
	FCB				*fcb,				// FCB of file to truncate
	SInt64			bytesToAdd,			// number of bytes to allocate
	UInt32			flags,				// EFContig and/or EFAll
	SInt64			*actualBytesAdded)	// number of bytes actually allocated
{
	OSErr				err;
	UInt32				volumeBlockSize;
	SInt64				blocksToAdd;
	SInt64				bytesThisExtent;
	HFSPlusExtentKey	foundKey;
	HFSPlusExtentRecord	foundData;
	UInt32				foundIndex;
	UInt32				hint;
	UInt32				nextBlock;
	UInt32				startBlock;
	Boolean				allOrNothing;
	Boolean				forceContig;
	Boolean				wantContig;
	Boolean				needsFlush;
	UInt32				actualStartBlock;
	UInt32				actualNumBlocks;
	UInt32				numExtentsPerRecord;
	SInt64				maximumBytes;
	SInt64				peof;
	SInt64				previousPEOF;
	

#if HFSInstrumentation
	InstTraceClassRef	trace;
	InstEventTag		eventTag;
	InstDataDescriptorRef	traceDescriptor;
	FSVarsRec			*fsVars = (FSVarsRec *) LMGetFSMVars();

	traceDescriptor = (InstDataDescriptorRef) fsVars->later[2];
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:Extents:ExtendFileC", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	eventTag = InstCreateEventTag();
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
#endif

	needsFlush = false;
	*actualBytesAdded = 0;
	volumeBlockSize = vcb->blockSize;
	allOrNothing = ((flags & kEFAllMask) != 0);
	forceContig = ((flags & kEFContigMask) != 0);
	previousPEOF = fcb->fcbPLen;

	if (vcb->vcbSigWord == kHFSPlusSigWord)
		numExtentsPerRecord = kHFSPlusExtentDensity;
	else
		numExtentsPerRecord = kHFSExtentDensity;

	//
	//	Make sure the request and new PEOF are less than 2GB if HFS.
	//
	if (vcb->vcbSigWord == kHFSSigWord) {
		if (bytesToAdd >=  kTwoGigabytes)
			goto Overflow;
		if ((fcb->fcbPLen + bytesToAdd) >= kTwoGigabytes)
			goto Overflow;
		}
	//
	//	Determine how many blocks need to be allocated.
	//	Round up the number of desired bytes to add.
	//
	blocksToAdd = FileBytesToBlocks(bytesToAdd, volumeBlockSize);
	bytesToAdd = (SInt64)((SInt64)blocksToAdd * (SInt64)volumeBlockSize);
	
	//
	//	If the file's clump size is larger than the allocation block size,
	//	then set the maximum number of bytes to the requested number of bytes
	//	rounded up to a multiple of the clump size.
	//
	if (fcb->fcbClmpSize > volumeBlockSize) {
		maximumBytes = (SInt64)FileBytesToBlocks(bytesToAdd, fcb->fcbClmpSize);
		maximumBytes *= fcb->fcbClmpSize;
	}
	else {
		maximumBytes = bytesToAdd;
	}
	
	//
	//	Compute new physical EOF, rounded up to a multiple of a block.
	//
	if ((vcb->vcbSigWord == kHFSSigWord) && ((fcb->fcbPLen + bytesToAdd) >= (SInt64) kTwoGigabytes))	//	Too big?
		if (allOrNothing)					// Yes, must they have it all?
			goto Overflow;						// Yes, can't have it
		else {
			--blocksToAdd;						// No, give give 'em one block less
			bytesToAdd -= volumeBlockSize;
		}

	//
	//	If allocation is all-or-nothing, make sure there are
	//	enough free blocks on the volume (quick test).
	//
	if (allOrNothing && (blocksToAdd > (SInt64)vcb->freeBlocks)) {
		err = dskFulErr;
		goto ErrorExit;
	}
	
	//
	//	See if there are already enough blocks allocated to the file.
	//
	peof = fcb->fcbPLen + bytesToAdd;			// potential new PEOF
	err = SearchExtentFile(vcb, fcb, peof-1, &foundKey, foundData, &foundIndex, &hint, &nextBlock);
	if (err == noErr) {
		//	Enough blocks are already allocated.  Just update the FCB to reflect the new length.
		fcb->fcbPLen = peof;
		H_EXTENDSIZE(fcb, bytesToAdd);
		fcb->fcbFlags |= fcbModifiedMask;
		goto Exit;
	}
	if (err != fxRangeErr)		// Any real error?
		goto ErrorExit;				// Yes, so exit immediately

	//
	//	Adjust the PEOF to the end of the last extent.
	//
	peof = (SInt64)((SInt64)nextBlock * (SInt64)volumeBlockSize);			// currently allocated PEOF
	bytesThisExtent = peof - fcb->fcbPLen;
	if (bytesThisExtent != 0) {
		fcb->fcbPLen = peof;
		H_EXTENDSIZE(fcb, bytesThisExtent);
		fcb->fcbFlags |= fcbModifiedMask;
		bytesToAdd -= bytesThisExtent;
	}
	
	//
	//	Allocate some more space.
	//
	//	First try a contiguous allocation (of the whole amount).
	//	If that fails, get whatever we can.
	//		If forceContig, then take whatever we got
	//		else, keep getting bits and pieces (non-contig)
	err = noErr;
	wantContig = true;
	do {
		startBlock = foundData[foundIndex].startBlock + foundData[foundIndex].blockCount;
		err = BlockAllocate(vcb, startBlock, bytesToAdd, maximumBytes, wantContig, &actualStartBlock, &actualNumBlocks);
		if (err == dskFulErr) {
			if (forceContig)
				break;			// AllocContig failed because not enough contiguous space
			if (wantContig) {
				//	Couldn't get one big chunk, so get whatever we can.
				err = noErr;
				wantContig = false;
				continue;
			}
			if (actualNumBlocks != 0)
				err = noErr;
		}
		if (err == noErr) {
#if HFSInstrumentation
			{
				struct {
					UInt32	fileID;
					UInt32	start;
					UInt32	count;
					UInt32	fabn;
				} x;
				
				x.fileID = H_FILEID(fcb);
				x.start = actualStartBlock;
				x.count = actualNumBlocks;
				x.fabn = nextBlock;
				
				InstLogTraceEventWithDataStructure( trace, eventTag, kInstMiddleEvent, traceDescriptor,
													(UInt8 *) &x, sizeof(x));
			}
#endif
			//	Add the new extent to the existing extent record, or create a new one.
			if (actualStartBlock == startBlock) {
				//	We grew the file's last extent, so just adjust the number of blocks.
				foundData[foundIndex].blockCount += actualNumBlocks;
				err = UpdateExtentRecord(vcb, fcb, &foundKey, foundData, hint);
				if (err != noErr) break;
			}
			else {
				UInt16	i;

				//	Need to add a new extent.  See if there is room in the current record.
				if (foundData[foundIndex].blockCount != 0)	//	Is current extent free to use?
					++foundIndex;							// 	No, so use the next one.
				if (foundIndex == numExtentsPerRecord) {
					//	This record is full.  Need to create a new one.
					if (H_FILEID(fcb) == kHFSExtentsFileID) {
						err = fxOvFlErr;		// Oops.  Can't extend extents file (?? really ??)
						break;
					}
					
					foundKey.keyLength = kHFSPlusExtentKeyMaximumLength;
					if (fcb->fcbFlags & fcbResourceMask)
						foundKey.forkType = kResourceForkType;
					else
						foundKey.forkType = kDataForkType;
					foundKey.pad = 0;
					foundKey.fileID = H_FILEID(fcb);
					foundKey.startBlock = nextBlock;
					
					foundData[0].startBlock = actualStartBlock;
					foundData[0].blockCount = actualNumBlocks;
					
					// zero out remaining extents...
					for (i = 1; i < kHFSPlusExtentDensity; ++i)
					{
						foundData[i].startBlock = 0;
						foundData[i].blockCount = 0;
					}

					foundIndex = 0;
					
					err = CreateExtentRecord(vcb, &foundKey, foundData, &hint);
					if (err == fxOvFlErr) {
						//	We couldn't create an extent record because extents B-tree
						//	couldn't grow.  Dellocate the extent just allocated and
						//	return a disk full error.
						(void) BlockDeallocate(vcb, actualStartBlock, actualNumBlocks);
						err = dskFulErr;
					}
					if (err != noErr) break;

					needsFlush = true;		//	We need to update the B-tree header
				}
				else {
					//	Add a new extent into this record and update.
					foundData[foundIndex].startBlock = actualStartBlock;
					foundData[foundIndex].blockCount = actualNumBlocks;
					err = UpdateExtentRecord(vcb, fcb, &foundKey, foundData, hint);
					if (err != noErr) break;
				}
			}
			
			// Figure out how many bytes were actually allocated.
			// NOTE: BlockAllocate could have allocated more than we asked for.
			// Don't set the PEOF beyond what our client asked for.
			nextBlock += actualNumBlocks;
			bytesThisExtent = (SInt64)((SInt64)actualNumBlocks * (SInt64)volumeBlockSize);
			if (bytesThisExtent > bytesToAdd) {
				bytesToAdd = 0;
			}
			else {
				bytesToAdd -= bytesThisExtent;
				maximumBytes -= bytesThisExtent;
			}
            fcb->fcbPLen += bytesThisExtent;
            H_EXTENDSIZE(fcb, bytesThisExtent);
			fcb->fcbFlags |= fcbModifiedMask;

			//	If contiguous allocation was requested, then we've already got one contiguous
			//	chunk.  If we didn't get all we wanted, then adjust the error to disk full.
			if (forceContig) {
				if (bytesToAdd != 0)
					err = dskFulErr;
				break;			//	We've already got everything that's contiguous
			}
		}
	} while (err == noErr && bytesToAdd);

ErrorExit:
Exit:
	*actualBytesAdded = fcb->fcbPLen - previousPEOF;

	if (needsFlush)
		(void) FlushExtentFile(vcb);

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif

	return err;

Overflow:
	err = fileBoundsErr;
	goto ErrorExit;
}



//_________________________________________________________________________________
//
// Routine:		TruncateFileC
//
// Function: 	Truncates the disk space allocated to a file.  The file space is
//				truncated to a specified new PEOF rounded up to the next allocation
//				block boundry.  If the 'TFTrunExt' option is specified, the file is
//				truncated to the end of the extent containing the new PEOF.
//
// Input:		A2.L  -  VCB pointer
//				A1.L  -  pointer to FCB array
//				D1.W  -  file refnum
//				D2.B  -  option flags
//						   TFTrunExt - truncate to the extent containing new PEOF
//				D3.L  -  new PEOF
//
// Output:		D0.W  -  result code
//							 0 = ok
//							 -n = IO error
//
// Note: 		TruncateFile updates the PEOF in the FCB.
//_________________________________________________________________________________

OSErr TruncateFileC (
	ExtendedVCB		*vcb,				// volume that file resides on
	FCB				*fcb,				// FCB of file to truncate
	SInt64			peof,				// new physical size for file
	Boolean			truncateToExtent)	// if true, truncate to end of extent containing newPEOF
{
	OSErr				err;
	UInt32				nextBlock;		//	next file allocation block to consider
	UInt32				startBlock;		//	Physical (volume) allocation block number of start of a range
	UInt32				physNumBlocks;	//	Number of allocation blocks in file (according to PEOF)
	UInt32				numBlocks;
	HFSPlusExtentKey	key;			//	key for current extent record; key->keyLength == 0 if FCB's extent record
	UInt32				hint;			//	BTree hint corresponding to key
	HFSPlusExtentRecord	extentRecord;
	UInt32				extentIndex;
	UInt32				extentNextBlock;
	UInt32				numExtentsPerRecord;
	SInt64                          temp64;
	UInt8				forkType;
	Boolean				extentChanged;	// true if we actually changed an extent
	Boolean				recordDeleted;	// true if an extent record got deleted
	
#if HFSInstrumentation
	InstTraceClassRef	trace;
	InstEventTag		eventTag;
	InstDataDescriptorRef	traceDescriptor;
	FSVarsRec			*fsVars = (FSVarsRec *) LMGetFSMVars();

	traceDescriptor = (InstDataDescriptorRef) fsVars->later[2];
	
	err = InstCreateTraceClass(kInstRootClassRef, "HFS:Extents:TruncateFileC", 'hfs+', kInstEnableClassMask, &trace);
	if (err != noErr) DebugStr("\pError from InstCreateTraceClass");

	eventTag = InstCreateEventTag();
	InstLogTraceEvent( trace, eventTag, kInstStartEvent);
#endif

	recordDeleted = false;
	
	if (vcb->vcbSigWord == kHFSPlusSigWord)
		numExtentsPerRecord = kHFSPlusExtentDensity;
	else
		numExtentsPerRecord = kHFSExtentDensity;

	if (fcb->fcbFlags & fcbResourceMask)
		forkType = kResourceForkType;
	else
		forkType = kDataForkType;

	temp64 = fcb->fcbPLen / (SInt64)vcb->blockSize;		// number of allocation blocks currently in file
	physNumBlocks = (UInt32)temp64;

	//
	//	Round newPEOF up to a multiple of the allocation block size.  If new size is
	//	two gigabytes or more, then round down by one allocation block (??? really?
	//	shouldn't that be an error?).
	//
	nextBlock = FileBytesToBlocks(peof, vcb->blockSize);	// number of allocation blocks to remain in file
	peof = (SInt64)((SInt64)nextBlock * (SInt64)vcb->blockSize);					// number of bytes in those blocks
	if ((vcb->vcbSigWord == kHFSSigWord) && (peof >= (UInt32) kTwoGigabytes)) {
		#if DEBUG_BUILD
			DebugStr("\pHFS: Trying to truncate a file to 2GB or more");
		#endif
		err = fileBoundsErr;
		goto ErrorExit;
	}

	//
	//	Update FCB's length
	//
	H_TRUNCSIZE(fcb, fcb->fcbPLen - peof);
	fcb->fcbPLen = peof;
	fcb->fcbFlags |= fcbModifiedMask;
	
	//
	//	If the new PEOF is 0, then truncateToExtent has no meaning (we should always deallocate
	//	all storage).
	//
	if (peof == 0) {
		int i;
		
		//	Deallocate all the extents for this fork
		err = DeallocateFork(vcb, H_FILEID(fcb), forkType, fcb->fcbExtents, &recordDeleted);
		if (err != noErr) goto ErrorExit;	//	got some error, so return it
		
		//	Update the catalog extent record (making sure it's zeroed out)
		if (err == noErr) {
			for (i=0; i < kHFSPlusExtentDensity; i++) {
				fcb->fcbExtents[i].startBlock = 0;
				fcb->fcbExtents[i].blockCount = 0;
			}
		}
		goto Done;
	}
	
	//
	//	Find the extent containing byte (peof-1).  This is the last extent we'll keep.
	//	(If truncateToExtent is true, we'll keep the whole extent; otherwise, we'll only
	//	keep up through peof).  The search will tell us how many allocation blocks exist
	//	in the found extent plus all previous extents.
	//
	err = SearchExtentFile(vcb, fcb, peof-1, &key, extentRecord, &extentIndex, &hint, &extentNextBlock);
	if (err != noErr) goto ErrorExit;

	extentChanged = false;		//	haven't changed the extent yet
	
	if (!truncateToExtent) {
		//
		//	Shorten this extent.  It may be the case that the entire extent gets
		//	freed here.
		//
		numBlocks = extentNextBlock - nextBlock;	//	How many blocks in this extent to free up
		if (numBlocks != 0) {
			//	Compute first volume allocation block to free
			startBlock = extentRecord[extentIndex].startBlock + extentRecord[extentIndex].blockCount - numBlocks;
			//	Free the blocks in bitmap
			err = BlockDeallocate(vcb, startBlock, numBlocks);
			if (err != noErr) goto ErrorExit;
			//	Adjust length of this extent
			extentRecord[extentIndex].blockCount -= numBlocks;
			//	If extent is empty, set start block to 0
			if (extentRecord[extentIndex].blockCount == 0)
				extentRecord[extentIndex].startBlock = 0;
			//	Remember that we changed the extent record
			extentChanged = true;
		}
	}
	
	//
	//	Now move to the next extent in the record, and set up the file allocation block number
	//
	nextBlock = extentNextBlock;		//	Next file allocation block to free
	++extentIndex;						//	Its index within the extent record
	
	//
	//	Release all following extents in this extent record.  Update the record.
	//
	while (extentIndex < numExtentsPerRecord && extentRecord[extentIndex].blockCount != 0) {
		numBlocks = extentRecord[extentIndex].blockCount;
		//	Deallocate this extent
		err = BlockDeallocate(vcb, extentRecord[extentIndex].startBlock, numBlocks);
		if (err != noErr) goto ErrorExit;
		//	Update next file allocation block number
		nextBlock += numBlocks;
		//	Zero out start and length of this extent to delete it from record
		extentRecord[extentIndex].startBlock = 0;
		extentRecord[extentIndex].blockCount = 0;
		//	Remember that we changed an extent
		extentChanged = true;
		//	Move to next extent in record
		++extentIndex;
	}
	
	//
	//	If any of the extents in the current record were changed, then update that
	//	record (in the FCB, or extents file).
	//
	if (extentChanged) {
		err = UpdateExtentRecord(vcb, fcb, &key, extentRecord, hint);
		if (err != noErr) goto ErrorExit;
	}
	
	//
	//	If there are any following allocation blocks, then we need
	//	to seach for their extent records and delete those allocation
	//	blocks.
	//
	if (nextBlock < physNumBlocks)
		err = TruncateExtents(vcb, forkType, H_FILEID(fcb), nextBlock, &recordDeleted);

Done:
ErrorExit:

	if (recordDeleted)
		(void) FlushExtentFile(vcb);

#if HFSInstrumentation
	InstLogTraceEvent( trace, eventTag, kInstEndEvent);
#endif

	return err;
}



//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	SearchExtentRecord (was XRSearch)
//
//	Function: 	Searches extent record for the extent mapping a given file
//				allocation block number (FABN).
//
//	Input:		searchFABN  			-  desired FABN
//				extentData  			-  pointer to extent data record (xdr)
//				extentDataStartFABN  	-  beginning FABN for extent record
//
//	Output:		foundExtentDataOffset  -  offset to extent entry within xdr
//							result = noErr, offset to extent mapping desired FABN
//							result = FXRangeErr, offset to last extent in record
//				endingFABNPlusOne	-  ending FABN +1
//				noMoreExtents		- True if the extent was not found, and the
//									  extent record was not full (so don't bother
//									  looking in subsequent records); false otherwise.
//
//	Result:		noErr = ok
//				FXRangeErr = desired FABN > last mapped FABN in record
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

static OSErr SearchExtentRecord(
	const ExtendedVCB		*vcb,
	UInt32					searchFABN,
	const HFSPlusExtentRecord	extentData,
	UInt32					extentDataStartFABN,
	UInt32					*foundExtentIndex,
	UInt32					*endingFABNPlusOne,
	Boolean					*noMoreExtents)
{
	OSErr	err = noErr;
	UInt32	extentIndex;
	UInt32	numberOfExtents;
	UInt32	numAllocationBlocks;
	Boolean	foundExtent;
	
	*endingFABNPlusOne 	= extentDataStartFABN;
	*noMoreExtents		= false;
	foundExtent			= false;

	if (vcb->vcbSigWord == kHFSPlusSigWord)
		numberOfExtents = kHFSPlusExtentDensity;
	else
		numberOfExtents = kHFSExtentDensity;
	
	for( extentIndex = 0; extentIndex < numberOfExtents; ++extentIndex )
	{
		
		// Loop over the extent record and find the search FABN.
		
		numAllocationBlocks = extentData[extentIndex].blockCount;
		if ( numAllocationBlocks == 0 )
		{
			break;
		}

		*endingFABNPlusOne += numAllocationBlocks;
		
		if( searchFABN < *endingFABNPlusOne )
		{
			// Found the extent.
			foundExtent = true;
			break;
		}
	}
	
	if( foundExtent )
	{
		// Found the extent. Note the extent offset
		*foundExtentIndex = extentIndex;
	}
	else
	{
		// Did not find the extent. Set foundExtentDataOffset accordingly
		if( extentIndex > 0 )
		{
			*foundExtentIndex = extentIndex - 1;
		}
		else
		{
			*foundExtentIndex = 0;
		}
		
		// If we found an empty extent, then set noMoreExtents.
		if (extentIndex < numberOfExtents)
			*noMoreExtents = true;

		// Finally, return an error to the caller
		err = fxRangeErr;
	}

	return( err );
}

//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	SearchExtentFile (was XFSearch)
//
//	Function: 	Searches extent file (including the FCB resident extent record)
//				for the extent mapping a given file position.
//
//	Input:		vcb  			-  VCB pointer
//				fcb  			-  FCB pointer
//				filePosition  	-  file position (byte address)
//
// Output:		foundExtentKey  		-  extent key record (xkr)
//							If extent was found in the FCB's resident extent record,
//							then foundExtentKey->keyLength will be set to 0.
//				foundExtentData			-  extent data record(xdr)
//				foundExtentIndex  	-  index to extent entry in xdr
//							result =  0, offset to extent mapping desired FABN
//							result = FXRangeErr, offset to last extent in record
//									 (i.e., kNumExtentsPerRecord-1)
//				extentBTreeHint  		-  BTree hint for extent record
//							kNoHint = Resident extent record
//				endingFABNPlusOne  		-  ending FABN +1
//
//	Result:
//		noErr			Found an extent that contains the given file position
//		FXRangeErr		Given position is beyond the last allocated extent
//		(other)			(some other internal I/O error)
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

static OSErr SearchExtentFile(
	const ExtendedVCB 	*vcb,
	const FCB	 		*fcb,
	SInt64 				filePosition,
	HFSPlusExtentKey	*foundExtentKey,
	HFSPlusExtentRecord	foundExtentData,
	UInt32				*foundExtentIndex,
	UInt32				*extentBTreeHint,
	UInt32				*endingFABNPlusOne )
{
	OSErr				err;
	UInt32				filePositionBlock;
	SInt64                          temp64;
	Boolean				noMoreExtents;
	
	temp64 = filePosition / (SInt64)vcb->blockSize;
	filePositionBlock = (UInt32)temp64;

    bcopy ( fcb->fcbExtents, foundExtentData, sizeof(HFSPlusExtentRecord));
	
	//	Search the resident FCB first.
    err = SearchExtentRecord( vcb, filePositionBlock, foundExtentData, 0,
									foundExtentIndex, endingFABNPlusOne, &noMoreExtents );

	if( err == noErr ) {
		// Found the extent. Set results accordingly
		*extentBTreeHint = kNoHint;			// no hint, because not in the BTree
		foundExtentKey->keyLength = 0;		// 0 = the FCB itself
		
		goto Exit;
	}
	
	//	Didn't find extent in FCB.  If FCB's extent record wasn't full, there's no point
	//	in searching the extents file.  Note that SearchExtentRecord left us pointing at
	//	the last valid extent (or the first one, if none were valid).  This means we need
	//	to fill in the hint and key outputs, just like the "if" statement above.
	if ( noMoreExtents ) {
		*extentBTreeHint = kNoHint;			// no hint, because not in the BTree
		foundExtentKey->keyLength = 0;		// 0 = the FCB itself
		err = fxRangeErr;		// There are no more extents, so must be beyond PEOF
		goto Exit;
	}
	
	//
	//	Find the desired record, or the previous record if it is the same fork
	//
	err = FindExtentRecord(vcb, (fcb->fcbFlags & fcbResourceMask) ? kResourceForkType : kDataForkType,
						   H_FILEID(fcb), filePositionBlock, true, foundExtentKey, foundExtentData, extentBTreeHint);

	if (err == btNotFound) {
		//
		//	If we get here, the desired position is beyond the extents in the FCB, and there are no extents
		//	in the extents file.  Return the FCB's extents and a range error.
		//
		*extentBTreeHint = kNoHint;
		foundExtentKey->keyLength = 0;
		err = GetFCBExtentRecord(fcb, foundExtentData);
		//	Note: foundExtentIndex and endingFABNPlusOne have already been set as a result of the very
		//	first SearchExtentRecord call in this function (when searching in the FCB's extents, and
		//	we got a range error).
		
		return fxRangeErr;
	}
	
	//
	//	If we get here, there was either a BTree error, or we found an appropriate record.
	//	If we found a record, then search it for the correct index into the extents.
	//
	if (err == noErr) {
		//	Find appropriate index into extent record
		err = SearchExtentRecord(vcb, filePositionBlock, foundExtentData, foundExtentKey->startBlock,
								 foundExtentIndex, endingFABNPlusOne, &noMoreExtents);
	}

Exit:
	return err;
}



//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	UpdateExtentRecord
//
//	Function: 	Write new extent data to an existing extent record with a given key.
//				If all of the extents are empty, and the extent record is in the
//				extents file, then the record is deleted.
//
//	Input:		vcb			  			-	the volume containing the extents
//				fcb						-	the file that owns the extents
//				extentFileKey  			-	pointer to extent key record (xkr)
//						If the key length is 0, then the extents are actually part
//						of the catalog record, stored in the FCB.
//				extentData  			-	pointer to extent data record (xdr)
//				extentBTreeHint			-	hint for given key, or kNoHint
//
//	Result:		noErr = ok
//				(other) = error from BTree
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

static OSErr UpdateExtentRecord (
	const ExtendedVCB		*vcb,
	FCB						*fcb,
	const HFSPlusExtentKey	*extentFileKey,
	const HFSPlusExtentRecord	extentData,
	UInt32					extentBTreeHint)
{
	BTreeIterator		btIterator;
	FSBufferDescriptor	btRecord;
	UInt16				btRecordSize;
	FCB *				btFCB;
    OSErr				err = noErr;
	
	if (extentFileKey->keyLength == 0) {	// keyLength == 0 means the FCB's extent record
		BlockMoveData(extentData, fcb->fcbExtents, sizeof(HFSPlusExtentRecord));
		fcb->fcbFlags |= fcbModifiedMask;
	}
	else {
		//
		//	Need to find and change a record in Extents BTree
		//
		btFCB = GetFileControlBlock(vcb->extentsRefNum);

		if (vcb->vcbSigWord == kHFSSigWord) {
			HFSExtentKey *	key;				// Actual extent key used on disk in HFS
			HFSExtentRecord	foundData;			// The extent data actually found

			key = (HFSExtentKey*) &btIterator.key;
			key->keyLength	= kHFSExtentKeyMaximumLength;
			key->forkType	= extentFileKey->forkType;
			key->fileID		= extentFileKey->fileID;
			key->startBlock	= extentFileKey->startBlock;

			btIterator.hint.index = 0;
			btIterator.hint.nodeNum = extentBTreeHint;

			btRecord.bufferAddress = &foundData;
			btRecord.itemSize = sizeof(HFSExtentRecord);
			btRecord.itemCount = 1;

			err = BTSearchRecord(btFCB, &btIterator, kInvalidMRUCacheKey, &btRecord,
								 &btRecordSize, &btIterator);
			
			if (err == noErr)
				err = HFSPlusToHFSExtents(extentData, (HFSExtentDescriptor *)&foundData);

			if (err == noErr)
				err = BTReplaceRecord(btFCB, &btIterator, &btRecord, btRecordSize);
		}
		else {		//	HFS Plus volume
			HFSPlusExtentRecord	foundData;		// The extent data actually found

			BlockMoveData(extentFileKey, &btIterator.key, sizeof(HFSPlusExtentKey));

			btIterator.hint.index = 0;
			btIterator.hint.nodeNum = extentBTreeHint;

			btRecord.bufferAddress = &foundData;
			btRecord.itemSize = sizeof(HFSPlusExtentRecord);
			btRecord.itemCount = 1;

			err = BTSearchRecord(btFCB, &btIterator, kInvalidMRUCacheKey, &btRecord,
								 &btRecordSize, &btIterator);
	
			if (err == noErr) {
				BlockMoveData(extentData, &foundData, sizeof(HFSPlusExtentRecord));
				err = BTReplaceRecord(btFCB, &btIterator, &btRecord, btRecordSize);
			}
		}
	}
	
	return err;
}



void HFSToHFSPlusExtents(
	const HFSExtentRecord	oldExtents,
	HFSPlusExtentRecord		newExtents)
{
	UInt32	i;

	// copy the first 3 extents
	newExtents[0].startBlock = oldExtents[0].startBlock;
	newExtents[0].blockCount = oldExtents[0].blockCount;
	newExtents[1].startBlock = oldExtents[1].startBlock;
	newExtents[1].blockCount = oldExtents[1].blockCount;
	newExtents[2].startBlock = oldExtents[2].startBlock;
	newExtents[2].blockCount = oldExtents[2].blockCount;

	// zero out the remaining ones
	for (i = 3; i < kHFSPlusExtentDensity; ++i)
	{
		newExtents[i].startBlock = 0;
		newExtents[i].blockCount = 0;
	}
}



OSErr HFSPlusToHFSExtents(
	const HFSPlusExtentRecord	oldExtents,
	HFSExtentRecord		newExtents)
{
	OSErr	err;
	
	err = noErr;

	// copy the first 3 extents
	newExtents[0].startBlock = oldExtents[0].startBlock;
	newExtents[0].blockCount = oldExtents[0].blockCount;
	newExtents[1].startBlock = oldExtents[1].startBlock;
	newExtents[1].blockCount = oldExtents[1].blockCount;
	newExtents[2].startBlock = oldExtents[2].startBlock;
	newExtents[2].blockCount = oldExtents[2].blockCount;

	#if DEBUG_BUILD
		if (oldExtents[3].startBlock || oldExtents[3].blockCount) {
			DebugStr("\pExtentRecord with > 3 extents is invalid for HFS");
			err = fsDSIntErr;
		}
	#endif
	
	return err;
}




OSErr GetFCBExtentRecord(
	const FCB			*fcb,
	HFSPlusExtentRecord	extents)
{
	
	BlockMoveData(fcb->fcbExtents, extents, sizeof(HFSPlusExtentRecord));
	
	return noErr;
}



//ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Routine:	MapFileBlockFromFCB
//
//	Function: 	Determine if the given file offset is within the set of extents
//				stored in the FCB.  If so, return the file allocation
//				block number of the start of the extent, volume allocation block number
//				of the start of the extent, and file allocation block number immediately
//				following the extent.
//
//	Input:		vcb			  			-	the volume containing the extents
//				fcb						-	the file that owns the extents
//				offset					-	desired offset in bytes
//
//	Output:		firstFABN				-	file alloc block number of start of extent
//				firstBlock				-	volume alloc block number of start of extent
//				nextFABN				-	file alloc block number of next extent
//
//	Result:		noErr		= ok
//				fxRangeErr	= beyond FCB's extents
//ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
static OSErr MapFileBlockFromFCB(
	const ExtendedVCB		*vcb,
	const FCB				*fcb,
	SInt64					offset,			// Desired offset in bytes from start of file
	UInt32					*firstFABN,		// FABN of first block of found extent
	UInt32					*firstBlock,	// Corresponding allocation block number
	UInt32					*nextFABN)		// FABN of block after end of extent
{
	UInt32	index;
	UInt32	offsetBlocks;
	SInt64  temp64;
	
	temp64 = offset / (SInt64)vcb->blockSize;
	offsetBlocks = (UInt32)temp64;

	if (vcb->vcbSigWord == kHFSSigWord) {
		/* XXX SER Do we need to test for overflow values ??? */
		UInt16	blockCount;
		UInt16	currentFABN;
		
		currentFABN = 0;
		
		for (index=0; index<kHFSExtentDensity; index++) {

			blockCount = fcb->fcbExtents[index].blockCount;

			if (blockCount == 0)
				return fxRangeErr;				//	ran out of extents!

			//	Is it in this extent?
			if (offsetBlocks < blockCount) {
				*firstFABN	= currentFABN;
				*firstBlock	= fcb->fcbExtents[index].startBlock;
				currentFABN += blockCount;		//	faster to add these as UInt16 first, then extend to UInt32
				*nextFABN	= currentFABN;
				return noErr;					//	found the right extent
			}

			//	Not in current extent, so adjust counters and loop again
			offsetBlocks -= blockCount;
			currentFABN += blockCount;
		}
	}
	else {
		UInt32	blockCount;
		UInt32	currentFABN;
		
		currentFABN = 0;
		
		for (index=0; index<kHFSPlusExtentDensity; index++) {

			blockCount = fcb->fcbExtents[index].blockCount;

			if (blockCount == 0)
				return fxRangeErr;				//	ran out of extents!

			//	Is it in this extent?
			if (offsetBlocks < blockCount) {
				*firstFABN	= currentFABN;
				*firstBlock	= fcb->fcbExtents[index].startBlock;
				*nextFABN	= currentFABN + blockCount;
				return noErr;					//	found the right extent
			}

			//	Not in current extent, so adjust counters and loop again
			offsetBlocks -= blockCount;
			currentFABN += blockCount;
		}
	}
	
	//	If we fall through here, the extent record was full, but the offset was
	//	beyond those extents.
	
	return fxRangeErr;
}


//_________________________________________________________________________________
//
// Routine:		ExtentsAreIntegral
//
// Purpose:		Ensure that each extent can hold an integral number of nodes
//				Called by the NodesAreContiguous function
//_________________________________________________________________________________

static Boolean ExtentsAreIntegral(
	const HFSPlusExtentRecord extentRecord,
	UInt32		mask,
	UInt32		*blocksChecked,
	Boolean		*checkedLastExtent)
{
	UInt32		blocks;
	UInt32		extentIndex;

	*blocksChecked = 0;
	*checkedLastExtent = false;
	
	for(extentIndex = 0; extentIndex < kHFSPlusExtentDensity; extentIndex++)
	{		
		blocks = extentRecord[extentIndex].blockCount;
		
		if ( blocks == 0 )
		{
			*checkedLastExtent = true;
			break;
		}

		*blocksChecked += blocks;

		if (blocks & mask)
			return false;
	}
	
	return true;
}


//_________________________________________________________________________________
//
// Routine:		NodesAreContiguous
//
// Purpose:		Ensure that all b-tree nodes are contiguous on disk
//				Called by BTOpenPath during volume mount
//_________________________________________________________________________________

Boolean NodesAreContiguous(
	ExtendedVCB	*vcb,
	FCB			*fcb,
	UInt32		nodeSize)
{
	UInt32				mask;
	UInt32				startBlock;
	UInt32				blocksChecked;
	UInt32				hint;
	HFSPlusExtentKey	key;
	HFSPlusExtentRecord	extents;
	OSErr				result;
	Boolean				lastExtentReached;
	

	if (vcb->blockSize >= nodeSize)
		return TRUE;

	mask = (nodeSize / vcb->blockSize) - 1;

	// check the local extents
	(void) GetFCBExtentRecord(fcb, extents);
	if ( !ExtentsAreIntegral(extents, mask, &blocksChecked, &lastExtentReached) )
		return FALSE;

	if (lastExtentReached || (SInt64)((SInt64)blocksChecked * (SInt64)vcb->blockSize) >= fcb->fcbPLen)
		return TRUE;

	startBlock = blocksChecked;

	// check the overflow extents (if any)
	while ( !lastExtentReached )
	{
		result = FindExtentRecord(vcb, kDataForkType, H_FILEID(fcb), startBlock, FALSE, &key, extents, &hint);
		if (result) break;

		if ( !ExtentsAreIntegral(extents, mask, &blocksChecked, &lastExtentReached) )
			return FALSE;

		startBlock += blocksChecked;
	}

	return TRUE;
}

