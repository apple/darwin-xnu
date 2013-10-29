/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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


#include "../../hfs.h"
#include "../../hfs_format.h"
#include "../../hfs_endian.h"

#include "../headers/FileMgrInternal.h"
#include "../headers/BTreesInternal.h"

#include <sys/malloc.h>
 
/*
============================================================
Public (Exported) Routines:
============================================================

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

static const int64_t kTwoGigabytes = 0x80000000LL;

enum
{
	kDataForkType			= 0,
	kResourceForkType		= 0xFF,
	
	kPreviousRecord			= -1
};


#if CONFIG_HFS_STD
static OSErr HFSPlusToHFSExtents(
	const HFSPlusExtentRecord	oldExtents,
	HFSExtentRecord				newExtents);
#endif

static OSErr FindExtentRecord(
	const ExtendedVCB		*vcb,
	u_int8_t				forkType,
	u_int32_t				fileID,
	u_int32_t				startBlock,
	Boolean					allowPrevious,
	HFSPlusExtentKey		*foundKey,
	HFSPlusExtentRecord		foundData,
	u_int32_t				*foundHint);

static OSErr DeleteExtentRecord(
	const ExtendedVCB		*vcb,
	u_int8_t				forkType,
	u_int32_t				fileID,
	u_int32_t				startBlock);

static OSErr CreateExtentRecord(
	ExtendedVCB		*vcb,
	HFSPlusExtentKey		*key,
	HFSPlusExtentRecord		extents,
	u_int32_t				*hint);


static OSErr GetFCBExtentRecord(
	const FCB				*fcb,
	HFSPlusExtentRecord		extents);

static OSErr SearchExtentFile(
	ExtendedVCB		*vcb,
	const FCB	 			*fcb,
	int64_t 				filePosition,
	HFSPlusExtentKey		*foundExtentKey,
	HFSPlusExtentRecord		foundExtentData,
	u_int32_t				*foundExtentDataIndex,
	u_int32_t				*extentBTreeHint,
	u_int32_t				*endingFABNPlusOne );

static OSErr SearchExtentRecord(
	ExtendedVCB		*vcb,
	u_int32_t				searchFABN,
	const HFSPlusExtentRecord	extentData,
	u_int32_t				extentDataStartFABN,
	u_int32_t				*foundExtentDataOffset,
	u_int32_t				*endingFABNPlusOne,
	Boolean					*noMoreExtents);

static OSErr ReleaseExtents(
	ExtendedVCB				*vcb,
	const HFSPlusExtentRecord	extentRecord,
	u_int32_t				*numReleasedAllocationBlocks,
	Boolean 				*releasedLastExtent);

static OSErr DeallocateFork(
	ExtendedVCB 		*vcb,
	HFSCatalogNodeID	fileID,
	u_int8_t			forkType,
	HFSPlusExtentRecord	catalogExtents,
	Boolean *		recordDeleted);

static OSErr TruncateExtents(
	ExtendedVCB			*vcb,
	u_int8_t			forkType,
	u_int32_t			fileID,
	u_int32_t			startBlock,
	Boolean *			recordDeleted);

static OSErr UpdateExtentRecord (
	ExtendedVCB		*vcb,
	FCB				*fcb,
	int				deleted,
	const HFSPlusExtentKey	*extentFileKey,
	const HFSPlusExtentRecord	extentData,
	u_int32_t					extentBTreeHint);

static Boolean ExtentsAreIntegral(
	const HFSPlusExtentRecord extentRecord,
	u_int32_t	mask,
	u_int32_t	*blocksChecked,
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
static OSErr FindExtentRecord(
	const ExtendedVCB	*vcb,
	u_int8_t			forkType,
	u_int32_t			fileID,
	u_int32_t			startBlock,
	Boolean				allowPrevious,
	HFSPlusExtentKey	*foundKey,
	HFSPlusExtentRecord	foundData,
	u_int32_t			*foundHint)
{
	FCB *				fcb;
	struct BTreeIterator *btIterator = NULL;
	FSBufferDescriptor	btRecord;
	OSErr				err;
	u_int16_t			btRecordSize;
	
	err = noErr;
	if (foundHint)
		*foundHint = 0;
	fcb = GetFileControlBlock(vcb->extentsRefNum);

	MALLOC (btIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (btIterator == NULL) {
		return memFullErr;  // translates to ENOMEM
	}
	bzero(btIterator, sizeof(*btIterator));

	/* HFS Plus / HFSX */
	if (vcb->vcbSigWord != kHFSSigWord) {
		HFSPlusExtentKey *	extentKeyPtr;
		HFSPlusExtentRecord	extentData;

		extentKeyPtr = (HFSPlusExtentKey*) &btIterator->key;
		extentKeyPtr->keyLength	 = kHFSPlusExtentKeyMaximumLength;
		extentKeyPtr->forkType	 = forkType;
		extentKeyPtr->pad		 = 0;
		extentKeyPtr->fileID	 = fileID;
		extentKeyPtr->startBlock = startBlock;
		
		btRecord.bufferAddress = &extentData;
		btRecord.itemSize = sizeof(HFSPlusExtentRecord);
		btRecord.itemCount = 1;

		err = BTSearchRecord(fcb, btIterator, &btRecord, &btRecordSize, btIterator);

		if (err == btNotFound && allowPrevious) {
			err = BTIterateRecord(fcb, kBTreePrevRecord, btIterator, &btRecord, &btRecordSize);

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
			// Copy the found key back for the caller
			if (foundKey)
				BlockMoveData(extentKeyPtr, foundKey, sizeof(HFSPlusExtentKey));
			// Copy the found data back for the caller
			BlockMoveData(&extentData, foundData, sizeof(HFSPlusExtentRecord));
		}
	}
#if CONFIG_HFS_STD
	else { 
		HFSExtentKey *		extentKeyPtr;
		HFSExtentRecord		extentData;

		extentKeyPtr = (HFSExtentKey*) &btIterator->key;
		extentKeyPtr->keyLength	= kHFSExtentKeyMaximumLength;
		extentKeyPtr->forkType = forkType;
		extentKeyPtr->fileID = fileID;
		extentKeyPtr->startBlock = startBlock;
		
		btRecord.bufferAddress = &extentData;
		btRecord.itemSize = sizeof(HFSExtentRecord);
		btRecord.itemCount = 1;

		err = BTSearchRecord(fcb, btIterator, &btRecord, &btRecordSize, btIterator);

		if (err == btNotFound && allowPrevious) {
			err = BTIterateRecord(fcb, kBTreePrevRecord, btIterator, &btRecord, &btRecordSize);

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
			u_int16_t	i;
			
			// Copy the found key back for the caller
			if (foundKey) {
				foundKey->keyLength  = kHFSPlusExtentKeyMaximumLength;
				foundKey->forkType   = extentKeyPtr->forkType;
				foundKey->pad        = 0;
				foundKey->fileID     = extentKeyPtr->fileID;
				foundKey->startBlock = extentKeyPtr->startBlock;
			}
			// Copy the found data back for the caller
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
#endif

	if (foundHint)
		*foundHint = btIterator->hint.nodeNum;

	FREE(btIterator, M_TEMP);
	return err;
}



static OSErr CreateExtentRecord(
	ExtendedVCB	*vcb,
	HFSPlusExtentKey	*key,
	HFSPlusExtentRecord	extents,
	u_int32_t			*hint)
{
	struct BTreeIterator *btIterator = NULL;
	FSBufferDescriptor	btRecord;
	u_int16_t  btRecordSize;
	int  lockflags;
	OSErr  err;
	
	err = noErr;
	*hint = 0;

	MALLOC (btIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (btIterator == NULL) {
		return memFullErr;  // translates to ENOMEM
	}
	bzero(btIterator, sizeof(*btIterator));

	/*
	 * The lock taken by callers of ExtendFileC is speculative and
	 * only occurs when the file already has overflow extents. So
	 * We need to make sure we have the lock here.  The extents
	 * btree lock can be nested (its recursive) so we always take
	 * it here.
	 */
	lockflags = hfs_systemfile_lock(vcb, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);

	/* HFS+/HFSX */
	if (vcb->vcbSigWord != kHFSSigWord) {
		btRecordSize = sizeof(HFSPlusExtentRecord);
		btRecord.bufferAddress = extents;
		btRecord.itemSize = btRecordSize;
		btRecord.itemCount = 1;

		BlockMoveData(key, &btIterator->key, sizeof(HFSPlusExtentKey));
	}
#if CONFIG_HFS_STD
	else {
		/* HFS Standard */
		HFSExtentKey *		keyPtr;
		HFSExtentRecord		data;
		
		btRecordSize = sizeof(HFSExtentRecord);
		btRecord.bufferAddress = &data;
		btRecord.itemSize = btRecordSize;
		btRecord.itemCount = 1;

		keyPtr = (HFSExtentKey*) &btIterator->key;
		keyPtr->keyLength	= kHFSExtentKeyMaximumLength;
		keyPtr->forkType	= key->forkType;
		keyPtr->fileID		= key->fileID;
		keyPtr->startBlock	= key->startBlock;
		
		err = HFSPlusToHFSExtents(extents, data);
	}
#endif

	if (err == noErr)
		err = BTInsertRecord(GetFileControlBlock(vcb->extentsRefNum), btIterator, &btRecord, btRecordSize);

	if (err == noErr)
		*hint = btIterator->hint.nodeNum;

	(void) BTFlushPath(GetFileControlBlock(vcb->extentsRefNum));
	
	hfs_systemfile_unlock(vcb, lockflags);

	FREE (btIterator, M_TEMP);	
	return err;
}


static OSErr DeleteExtentRecord(
	const ExtendedVCB	*vcb,
	u_int8_t			forkType,
	u_int32_t			fileID,
	u_int32_t			startBlock)
{
	struct BTreeIterator *btIterator = NULL;
	OSErr				err;
	
	err = noErr;

	MALLOC (btIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (btIterator == NULL) {
		return memFullErr;  // translates to ENOMEM
	}
	bzero(btIterator, sizeof(*btIterator));
	
	/* HFS+ / HFSX */
	if (vcb->vcbSigWord != kHFSSigWord) {		//	HFS Plus volume
		HFSPlusExtentKey *	keyPtr;

		keyPtr = (HFSPlusExtentKey*) &btIterator->key;
		keyPtr->keyLength	= kHFSPlusExtentKeyMaximumLength;
		keyPtr->forkType	= forkType;
		keyPtr->pad			= 0;
		keyPtr->fileID		= fileID;
		keyPtr->startBlock	= startBlock;
	}
#if CONFIG_HFS_STD
	else {
		/* HFS standard */
		HFSExtentKey *	keyPtr;

		keyPtr = (HFSExtentKey*) &btIterator->key;
		keyPtr->keyLength	= kHFSExtentKeyMaximumLength;
		keyPtr->forkType	= forkType;
		keyPtr->fileID		= fileID;
		keyPtr->startBlock	= startBlock;
	}
#endif

	err = BTDeleteRecord(GetFileControlBlock(vcb->extentsRefNum), btIterator);
	(void) BTFlushPath(GetFileControlBlock(vcb->extentsRefNum));
	

	FREE(btIterator, M_TEMP);
	return err;
}



//_________________________________________________________________________________
//
// Routine:		MapFileBlock
//
// Function: 	Maps a file position into a physical disk address.
//
//_________________________________________________________________________________

OSErr MapFileBlockC (
	ExtendedVCB		*vcb,				// volume that file resides on
	FCB				*fcb,				// FCB of file
	size_t			numberOfBytes,		// number of contiguous bytes desired
	off_t			offset,				// starting offset within file (in bytes)
	daddr64_t		*startSector,		// first sector (NOT an allocation block)
	size_t			*availableBytes)	// number of contiguous bytes (up to numberOfBytes)
{
	OSErr				err;
	u_int32_t			allocBlockSize;			//	Size of the volume's allocation block
	u_int32_t			sectorSize;
	HFSPlusExtentKey	foundKey;
	HFSPlusExtentRecord	foundData;
	u_int32_t			foundIndex;
	u_int32_t			hint;
	u_int32_t			firstFABN;				// file allocation block of first block in found extent
	u_int32_t			nextFABN;				// file allocation block of block after end of found extent
	off_t				dataEnd;				// (offset) end of range that is contiguous
	u_int32_t			sectorsPerBlock;		// Number of sectors per allocation block
	u_int32_t			startBlock;				// volume allocation block corresponding to firstFABN
	daddr64_t			temp;
	off_t				tmpOff;

	allocBlockSize = vcb->blockSize;
	sectorSize = VCBTOHFS(vcb)->hfs_logical_block_size;

	err = SearchExtentFile(vcb, fcb, offset, &foundKey, foundData, &foundIndex, &hint, &nextFABN);
	if (err == noErr) {
		startBlock = foundData[foundIndex].startBlock;
		firstFABN = nextFABN - foundData[foundIndex].blockCount;
	}
	
	if (err != noErr)
	{
		return err;
	}

	//
	//	Determine the end of the available space.  It will either be the end of the extent,
	//	or the file's PEOF, whichever is smaller.
	//
	dataEnd = (off_t)((off_t)(nextFABN) * (off_t)(allocBlockSize));   // Assume valid data through end of this extent
	if (((off_t)fcb->ff_blocks * (off_t)allocBlockSize) < dataEnd)    // Is PEOF shorter?
		dataEnd = (off_t)fcb->ff_blocks * (off_t)allocBlockSize;  // Yes, so only map up to PEOF
	
	//	Compute the number of sectors in an allocation block
	sectorsPerBlock = allocBlockSize / sectorSize;	// sectors per allocation block
	
	//
	//	Compute the absolute sector number that contains the offset of the given file
	//	offset in sectors from start of the extent +
	//      offset in sectors from start of allocation block space
	//
	temp = (daddr64_t)((offset - (off_t)((off_t)(firstFABN) * (off_t)(allocBlockSize)))/sectorSize);
	temp += (daddr64_t)startBlock * (daddr64_t)sectorsPerBlock;

	/* Add in any volume offsets */
	if (vcb->vcbSigWord == kHFSPlusSigWord)
		temp += vcb->hfsPlusIOPosOffset / sectorSize;
	else
		temp += vcb->vcbAlBlSt;
	
	//	Return the desired sector for file position "offset"
	*startSector = temp;
	
	//
	//	Determine the number of contiguous bytes until the end of the extent
	//	(or the amount they asked for, whichever comes first).
	//
	if (availableBytes)
	{
		tmpOff = dataEnd - offset;
		/*
		 * Disallow negative runs.
		 */
		if (tmpOff <= 0) {
			return EINVAL;
		}

		if (tmpOff > (off_t)(numberOfBytes)) {
			*availableBytes = numberOfBytes;  // more there than they asked for, so pin the output
		}
		else {
			*availableBytes = tmpOff;
		}
	}

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
	u_int32_t				*numReleasedAllocationBlocks,
	Boolean 				*releasedLastExtent)
{
	u_int32_t	extentIndex;
	u_int32_t	numberOfExtents;
	OSErr	err = noErr;
	
	*numReleasedAllocationBlocks = 0;
	*releasedLastExtent = false;
	
	if (vcb->vcbSigWord == kHFSPlusSigWord)
		numberOfExtents = kHFSPlusExtentDensity;
	else
		numberOfExtents = kHFSExtentDensity;

	for( extentIndex = 0; extentIndex < numberOfExtents; extentIndex++)
	{
		u_int32_t	numAllocationBlocks;
		
		// Loop over the extent record and release the blocks associated with each extent.
		
		numAllocationBlocks = extentRecord[extentIndex].blockCount;
		if ( numAllocationBlocks == 0 )
		{
			*releasedLastExtent = true;
			break;
		}

		err = BlockDeallocate( vcb, extentRecord[extentIndex].startBlock, numAllocationBlocks , 0);
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
	u_int8_t		forkType,
	u_int32_t		fileID,
	u_int32_t		startBlock,
	Boolean *		recordDeleted)
{
	OSErr				err;
	u_int32_t			numberExtentsReleased;
	Boolean				releasedLastExtent;
	u_int32_t			hint;
	HFSPlusExtentKey	key;
	HFSPlusExtentRecord	extents;
	int  lockflags;

	/*
	 * The lock taken by callers of TruncateFileC is speculative and
	 * only occurs when the file already has overflow extents. So
	 * We need to make sure we have the lock here.  The extents
	 * btree lock can be nested (its recursive) so we always take
	 * it here.
	 */
	lockflags = hfs_systemfile_lock(vcb, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);

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
	hfs_systemfile_unlock(vcb, lockflags);
	
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
	u_int8_t			forkType,
	HFSPlusExtentRecord	catalogExtents,
	Boolean *		recordDeleted) /* true if a record was deleted */
{
	OSErr				err;
	u_int32_t			numReleasedAllocationBlocks;
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
	int  lockflags;
	
	fcb = GetFileControlBlock(vcb->extentsRefNum);

	lockflags = hfs_systemfile_lock(vcb, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);
	err = BTFlushPath(fcb);
	hfs_systemfile_unlock(vcb, lockflags);

	if ( err == noErr )
	{
		// If the FCB for the extent "file" is dirty, mark the VCB as dirty.
		
        if (FTOC(fcb)->c_flag & C_MODIFIED)
		{
			MarkVCBDirty( vcb );
		//	err = FlushVolumeControlBlock( vcb );
		}
	}
	
	return( err );
}


#if CONFIG_HFS_STD
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	CompareExtentKeys
//
//	Function: 	Compares two extent file keys (a search key and a trial key) for
//				an HFS volume.
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

__private_extern__
int32_t CompareExtentKeys( const HFSExtentKey *searchKey, const HFSExtentKey *trialKey )
{
	int32_t	result;		//	± 1
	
	#if DEBUG_BUILD
		if (searchKey->keyLength != kHFSExtentKeyMaximumLength)
			DebugStr("HFS: search Key is wrong length");
		if (trialKey->keyLength != kHFSExtentKeyMaximumLength)
			DebugStr("HFS: trial Key is wrong length");
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
#endif


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	CompareExtentKeysPlus
//
//	Function: 	Compares two extent file keys (a search key and a trial key) for
//				an HFS volume.
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

__private_extern__
int32_t CompareExtentKeysPlus( const HFSPlusExtentKey *searchKey, const HFSPlusExtentKey *trialKey )
{
	int32_t	result;		//	± 1
	
	#if DEBUG_BUILD
		if (searchKey->keyLength != kHFSPlusExtentKeyMaximumLength)
			DebugStr("HFS: search Key is wrong length");
		if (trialKey->keyLength != kHFSPlusExtentKeyMaximumLength)
			DebugStr("HFS: trial Key is wrong length");
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

/*
 * Add a file extent to a file.
 *
 * Used by hfs_extendfs to extend the volume allocation bitmap file.
 *
 */
int
AddFileExtent(ExtendedVCB *vcb, FCB *fcb, u_int32_t startBlock, u_int32_t blockCount)
{
	HFSPlusExtentKey foundKey;
	HFSPlusExtentRecord foundData;
	u_int32_t foundIndex;
	u_int32_t hint;
	u_int32_t nextBlock;
	int64_t peof;
	int i;
	int error;

	peof = (int64_t)(fcb->ff_blocks + blockCount) * (int64_t)vcb->blockSize;

	error = SearchExtentFile(vcb, fcb, peof-1, &foundKey, foundData, &foundIndex, &hint, &nextBlock);
	if (error != fxRangeErr)
		return (EBUSY);

	/*
	 * Add new extent.  See if there is room in the current record.
	 */
	if (foundData[foundIndex].blockCount != 0)
		++foundIndex;
	if (foundIndex == kHFSPlusExtentDensity) {
		/*
		 * Existing record is full so create a new one.
		 */
		foundKey.keyLength = kHFSPlusExtentKeyMaximumLength;
		foundKey.forkType = kDataForkType;
		foundKey.pad = 0;
		foundKey.fileID = FTOC(fcb)->c_fileid;
		foundKey.startBlock = nextBlock;
		
		foundData[0].startBlock = startBlock;
		foundData[0].blockCount = blockCount;
		
		/* zero out remaining extents. */
		for (i = 1; i < kHFSPlusExtentDensity; ++i) {
			foundData[i].startBlock = 0;
			foundData[i].blockCount = 0;
		}

		foundIndex = 0;

		error = CreateExtentRecord(vcb, &foundKey, foundData, &hint);
		if (error == fxOvFlErr)
			error = dskFulErr;
	} else {
		/* 
		 * Add a new extent into existing record.
		 */
		foundData[foundIndex].startBlock = startBlock;
		foundData[foundIndex].blockCount = blockCount;
		error = UpdateExtentRecord(vcb, fcb, 0, &foundKey, foundData, hint);
	}
	(void) FlushExtentFile(vcb);

	return (error);
}


//_________________________________________________________________________________
//
// Routine:		Extendfile
//
// Function: 	Extends the disk space allocated to a file.
//
//_________________________________________________________________________________

OSErr ExtendFileC (
	ExtendedVCB		*vcb,				// volume that file resides on
	FCB				*fcb,				// FCB of file to truncate
	int64_t			bytesToAdd,			// number of bytes to allocate
	u_int32_t		blockHint,			// desired starting allocation block
	u_int32_t		flags,				// EFContig and/or EFAll
	int64_t			*actualBytesAdded)	// number of bytes actually allocated
{
	OSErr				err;
	u_int32_t			volumeBlockSize;
	int64_t				blocksToAdd;
	int64_t				bytesThisExtent;
	HFSPlusExtentKey	foundKey;
	HFSPlusExtentRecord	foundData;
	u_int32_t			foundIndex;
	u_int32_t			hint;
	u_int32_t			nextBlock;
	u_int32_t			startBlock;
	Boolean				allOrNothing;
	Boolean				forceContig;
	Boolean				wantContig;
	Boolean				useMetaZone;
	Boolean				needsFlush;
	int					allowFlushTxns;
	u_int32_t			actualStartBlock;
	u_int32_t			actualNumBlocks;
	u_int32_t			numExtentsPerRecord;
	int64_t				maximumBytes;
	int64_t 			availbytes;
	int64_t				peof;
	u_int32_t			prevblocks;
	struct hfsmount *hfsmp = (struct hfsmount*)vcb;	
	allowFlushTxns = 0;
	needsFlush = false;
	*actualBytesAdded = 0;
	volumeBlockSize = vcb->blockSize;
	allOrNothing = ((flags & kEFAllMask) != 0);
	forceContig = ((flags & kEFContigMask) != 0);
	prevblocks = fcb->ff_blocks;

	if (vcb->vcbSigWord != kHFSSigWord) {
		numExtentsPerRecord = kHFSPlusExtentDensity;
	}
#if CONFIG_HFS_STD
	else {
		/* HFS Standard */
		numExtentsPerRecord = kHFSExtentDensity;

		/* Make sure the request and new PEOF are less than 2GB if HFS std*/
		if (bytesToAdd >=  kTwoGigabytes)
			goto HFS_Std_Overflow;
		if ((((int64_t)fcb->ff_blocks * (int64_t)volumeBlockSize) + bytesToAdd) >= kTwoGigabytes)
			goto HFS_Std_Overflow;
	}
#endif

	//
	//	Determine how many blocks need to be allocated.
	//	Round up the number of desired bytes to add.
	//
	blocksToAdd = howmany(bytesToAdd, volumeBlockSize);
	bytesToAdd = (int64_t)((int64_t)blocksToAdd * (int64_t)volumeBlockSize);

	/*
	 * For deferred allocations just reserve the blocks.
	 */
	if ((flags & kEFDeferMask)
	&&  (vcb->vcbSigWord == kHFSPlusSigWord)
	&&  (bytesToAdd < (int64_t)HFS_MAX_DEFERED_ALLOC)
	&&  (blocksToAdd < hfs_freeblks(VCBTOHFS(vcb), 1))) {
		hfs_lock_mount (hfsmp);
		vcb->loanedBlocks += blocksToAdd;
		hfs_unlock_mount(hfsmp);

		fcb->ff_unallocblocks += blocksToAdd;
		FTOC(fcb)->c_blocks   += blocksToAdd;
		fcb->ff_blocks        += blocksToAdd;

		FTOC(fcb)->c_flag |= C_MODIFIED | C_FORCEUPDATE;
		*actualBytesAdded = bytesToAdd;
		return (0);
	}
	/* 
	 * Give back any unallocated blocks before doing real allocations.
	 */
	if (fcb->ff_unallocblocks > 0) {
		u_int32_t loanedBlocks;

		loanedBlocks = fcb->ff_unallocblocks;
		blocksToAdd += loanedBlocks;
		bytesToAdd = (int64_t)blocksToAdd * (int64_t)volumeBlockSize;
		FTOC(fcb)->c_blocks -= loanedBlocks;
		fcb->ff_blocks -= loanedBlocks;
		fcb->ff_unallocblocks  = 0;

		hfs_lock_mount(hfsmp);
		vcb->loanedBlocks -= loanedBlocks;
		hfs_unlock_mount(hfsmp);
	}

	//
	//	If the file's clump size is larger than the allocation block size,
	//	then set the maximum number of bytes to the requested number of bytes
	//	rounded up to a multiple of the clump size.
	//
	if ((vcb->vcbClpSiz > (int32_t)volumeBlockSize)
	&&  (bytesToAdd < (int64_t)HFS_MAX_DEFERED_ALLOC)
	&&  (flags & kEFNoClumpMask) == 0) {
		maximumBytes = (int64_t)howmany(bytesToAdd, vcb->vcbClpSiz);
		maximumBytes *= vcb->vcbClpSiz;
	} else {
		maximumBytes = bytesToAdd;
	}
	
#if CONFIG_HFS_STD
	//
	//	Compute new physical EOF, rounded up to a multiple of a block.
	//
	if ( (vcb->vcbSigWord == kHFSSigWord) &&		//	Too big?
		 ((((int64_t)fcb->ff_blocks * (int64_t)volumeBlockSize) + bytesToAdd) >= kTwoGigabytes) ) {
		if (allOrNothing)					// Yes, must they have it all?
			goto HFS_Std_Overflow;						// Yes, can't have it
		else {
			--blocksToAdd;						// No, give give 'em one block less
			bytesToAdd -= volumeBlockSize;
		}
	}
#endif

	//
	//	If allocation is all-or-nothing, make sure there are
	//	enough free blocks on the volume (quick test).
	//
	if (allOrNothing &&
	    (blocksToAdd > hfs_freeblks(VCBTOHFS(vcb), flags & kEFReserveMask))) {
		err = dskFulErr;
		goto ErrorExit;
	}
	
	//
	//	See if there are already enough blocks allocated to the file.
	//
	peof = ((int64_t)fcb->ff_blocks * (int64_t)volumeBlockSize) + bytesToAdd;  // potential new PEOF
	err = SearchExtentFile(vcb, fcb, peof-1, &foundKey, foundData, &foundIndex, &hint, &nextBlock);
	if (err == noErr) {
		//	Enough blocks are already allocated.  Just update the FCB to reflect the new length.
		fcb->ff_blocks = peof / volumeBlockSize;
		FTOC(fcb)->c_blocks += (bytesToAdd / volumeBlockSize);
		FTOC(fcb)->c_flag |= C_MODIFIED | C_FORCEUPDATE;
		goto Exit;
	}
	if (err != fxRangeErr)		// Any real error?
		goto ErrorExit;				// Yes, so exit immediately

	//
	//	Adjust the PEOF to the end of the last extent.
	//
	peof = (int64_t)((int64_t)nextBlock * (int64_t)volumeBlockSize);			// currently allocated PEOF
	bytesThisExtent = (int64_t)(nextBlock - fcb->ff_blocks) * (int64_t)volumeBlockSize;
	if (bytesThisExtent != 0) {
		fcb->ff_blocks = nextBlock;
		FTOC(fcb)->c_blocks += (bytesThisExtent / volumeBlockSize);
		FTOC(fcb)->c_flag |= C_MODIFIED;
		bytesToAdd -= bytesThisExtent;
	}
	
	//
	//	Allocate some more space.
	//
	//	First try a contiguous allocation (of the whole amount).
	//	If that fails, get whatever we can.
	//		If forceContig, then take whatever we got
	//		else, keep getting bits and pieces (non-contig)
	
	/*
	 * Note that for sparse devices (like sparse bundle dmgs), we
	 * should only be aggressive with re-using once-allocated pieces
	 * if we're not dealing with system files.  If we're trying to operate
	 * on behalf of a system file, we need the maximum contiguous amount
	 * possible.  For non-system files we favor locality and fragmentation over
	 * contiguity as it can result in fewer blocks being needed from the underlying
	 * filesystem that the sparse image resides upon. 
	 */
	err = noErr;
	if (   (vcb->hfs_flags & HFS_HAS_SPARSE_DEVICE)
			&& (fcb->ff_cp->c_fileid >= kHFSFirstUserCatalogNodeID)
			&& (flags & kEFMetadataMask) == 0) {
		/*
		 * We want locality over contiguity so by default we set wantContig to 
		 * false unless we hit one of the circumstances below.
		 */ 
		wantContig = false;
		if (hfs_isrbtree_active(VCBTOHFS(vcb))) {
			/* 
			 * If the red-black tree is acive, we can always find a suitable contiguous
			 * chunk.  So if the user specifically requests contiguous files,  we should 
			 * honor that no matter what kind of device it is.
			 */
			if (forceContig) {
				wantContig = true;
			}
		}
		else {
			/* 
			 * If the red-black tree is not active, then only set wantContig to true
			 * if we have never done a contig scan on the device, which would populate
			 * the free extent cache.  Note that the caller may explicitly unset the 
			 * DID_CONTIG_SCAN bit in order to force us to vend a contiguous extent here
			 * if the caller wants to get a contiguous chunk.
			 */
			if ((vcb->hfs_flags & HFS_DID_CONTIG_SCAN) == 0) { 
				vcb->hfs_flags |= HFS_DID_CONTIG_SCAN;	
				wantContig = true;
			}
		}
	} 
	else {
		wantContig = true;
	}
	useMetaZone = flags & kEFMetadataMask;
	do {
		if (blockHint != 0)
			startBlock = blockHint;
		else
			startBlock = foundData[foundIndex].startBlock + foundData[foundIndex].blockCount;

		actualNumBlocks = 0;
		actualStartBlock = 0;
			
		/* Find number of free blocks based on reserved block flag option */
		availbytes = (int64_t)hfs_freeblks(VCBTOHFS(vcb), flags & kEFReserveMask) *
		             (int64_t)volumeBlockSize;
		if (availbytes <= 0) {
			err = dskFulErr;
		} else {
			if (wantContig && (availbytes < bytesToAdd))
				err = dskFulErr;
			else {
				uint32_t ba_flags = 0;
				if (wantContig) {
					ba_flags |= HFS_ALLOC_FORCECONTIG;	
				}
				if (useMetaZone) {
					ba_flags |= HFS_ALLOC_METAZONE;
				}
				if (allowFlushTxns) {
					ba_flags |= HFS_ALLOC_FLUSHTXN;
				}

				err = BlockAllocate(
						  vcb,
						  startBlock,
						  howmany(MIN(bytesToAdd, availbytes), volumeBlockSize),
						  howmany(MIN(maximumBytes, availbytes), volumeBlockSize),
						  ba_flags,
						  &actualStartBlock,
						  &actualNumBlocks);
			}
		}
		if (err == dskFulErr) {
			if (forceContig) {
				if (allowFlushTxns == 0) {
					/* If we're forcing contiguity, re-try but allow plucking from recently freed regions */
					allowFlushTxns = 1;
					wantContig = 1;
					err = noErr;
					continue;
				}
				else {
					break;			// AllocContig failed because not enough contiguous space
				}
			}
			if (wantContig) {
				//	Couldn't get one big chunk, so get whatever we can.
				err = noErr;
				wantContig = false;
				continue;
			}
			if (actualNumBlocks != 0)
				err = noErr;

			if (useMetaZone == 0) {
				/* Couldn't get anything so dip into metadat zone */
				err = noErr;
				useMetaZone = 1;
				continue;
			}

			/* If we couldn't find what we needed without flushing the journal, then go ahead and do it now */
			if (allowFlushTxns == 0) {
				allowFlushTxns = 1;
				err = noErr;
				continue;
			}

		}
		if (err == noErr) {
		    if (actualNumBlocks != 0) {
				// this catalog entry *must* get forced to disk when
				// hfs_update() is called
				FTOC(fcb)->c_flag |= C_FORCEUPDATE;
			}

			//	Add the new extent to the existing extent record, or create a new one.
			if ((actualStartBlock == startBlock) && (blockHint == 0)) {
				//	We grew the file's last extent, so just adjust the number of blocks.
				foundData[foundIndex].blockCount += actualNumBlocks;
				err = UpdateExtentRecord(vcb, fcb, 0, &foundKey, foundData, hint);
				if (err != noErr) break;
			}
			else {
				u_int16_t	i;

				//	Need to add a new extent.  See if there is room in the current record.
				if (foundData[foundIndex].blockCount != 0)	//	Is current extent free to use?
					++foundIndex;							// 	No, so use the next one.
				if (foundIndex == numExtentsPerRecord) {
					//	This record is full.  Need to create a new one.
					if (FTOC(fcb)->c_fileid == kHFSExtentsFileID) {
						(void) BlockDeallocate(vcb, actualStartBlock, actualNumBlocks, 0);
						err = dskFulErr;		// Oops.  Can't extend extents file past first record.
						break;
					}
					
					foundKey.keyLength = kHFSPlusExtentKeyMaximumLength;
					if (FORK_IS_RSRC(fcb))
						foundKey.forkType = kResourceForkType;
					else
						foundKey.forkType = kDataForkType;
					foundKey.pad = 0;
					foundKey.fileID = FTOC(fcb)->c_fileid;
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
						(void) BlockDeallocate(vcb, actualStartBlock, actualNumBlocks, 0);
						err = dskFulErr;
					}
					if (err != noErr) break;

					needsFlush = true;		//	We need to update the B-tree header
				}
				else {
					//	Add a new extent into this record and update.
					foundData[foundIndex].startBlock = actualStartBlock;
					foundData[foundIndex].blockCount = actualNumBlocks;
					err = UpdateExtentRecord(vcb, fcb, 0, &foundKey, foundData, hint);
					if (err != noErr) break;
				}
			}
			
			// Figure out how many bytes were actually allocated.
			// NOTE: BlockAllocate could have allocated more than we asked for.
			// Don't set the PEOF beyond what our client asked for.
			nextBlock += actualNumBlocks;
			bytesThisExtent = (int64_t)((int64_t)actualNumBlocks * (int64_t)volumeBlockSize);
			if (bytesThisExtent > bytesToAdd) {
				bytesToAdd = 0;
			}
			else {
				bytesToAdd -= bytesThisExtent;
				maximumBytes -= bytesThisExtent;
			}
			fcb->ff_blocks += (bytesThisExtent / volumeBlockSize);
			FTOC(fcb)->c_blocks += (bytesThisExtent / volumeBlockSize);
			FTOC(fcb)->c_flag |= C_MODIFIED | C_FORCEUPDATE;

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
	if (VCBTOHFS(vcb)->hfs_flags & HFS_METADATA_ZONE) {
		/* Keep the roving allocator out of the metadata zone. */
		if (vcb->nextAllocation >= VCBTOHFS(vcb)->hfs_metazone_start &&
		    vcb->nextAllocation <= VCBTOHFS(vcb)->hfs_metazone_end) {
			hfs_lock_mount (hfsmp);
			HFS_UPDATE_NEXT_ALLOCATION(vcb, VCBTOHFS(vcb)->hfs_metazone_end + 1);	
			MarkVCBDirty(vcb);
			hfs_unlock_mount(hfsmp);
		}
	}
	if (prevblocks < fcb->ff_blocks) {
		*actualBytesAdded = (int64_t)(fcb->ff_blocks - prevblocks) * (int64_t)volumeBlockSize;
	} else {
		*actualBytesAdded = 0;
	}

	if (needsFlush)
		(void) FlushExtentFile(vcb);

	return err;

#if CONFIG_HFS_STD
HFS_Std_Overflow:
#endif
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
//_________________________________________________________________________________

OSErr TruncateFileC (
	ExtendedVCB		*vcb,				// volume that file resides on
	FCB				*fcb,				// FCB of file to truncate
	int64_t			peof,				// new physical size for file
	int				deleted,			// if nonzero, the file's catalog record has already been deleted.
	int				rsrc,				// does this represent a resource fork or not?
	uint32_t		fileid,				// the fileid of the file we're manipulating.
	Boolean			truncateToExtent)	// if true, truncate to end of extent containing newPEOF

{
	OSErr				err;
	u_int32_t			nextBlock;		//	next file allocation block to consider
	u_int32_t			startBlock;		//	Physical (volume) allocation block number of start of a range
	u_int32_t			physNumBlocks;	//	Number of allocation blocks in file (according to PEOF)
	u_int32_t			numBlocks;
	HFSPlusExtentKey	key;			//	key for current extent record; key->keyLength == 0 if FCB's extent record
	u_int32_t			hint;			//	BTree hint corresponding to key
	HFSPlusExtentRecord	extentRecord;
	u_int32_t			extentIndex;
	u_int32_t			extentNextBlock;
	u_int32_t			numExtentsPerRecord;
	int64_t             temp64;
	u_int8_t			forkType;
	Boolean				extentChanged;	// true if we actually changed an extent
	Boolean				recordDeleted;	// true if an extent record got deleted

	recordDeleted = false;
	
	if (vcb->vcbSigWord == kHFSPlusSigWord) {
		numExtentsPerRecord = kHFSPlusExtentDensity;
	}
	else {
		numExtentsPerRecord = kHFSExtentDensity;
	}
	
	if (rsrc) {
		forkType = kResourceForkType;
	}
	else {
		forkType = kDataForkType;
	}
	
	temp64 = fcb->ff_blocks;
	physNumBlocks = (u_int32_t)temp64;

	//
	//	Round newPEOF up to a multiple of the allocation block size.  If new size is
	//	two gigabytes or more, then round down by one allocation block (??? really?
	//	shouldn't that be an error?).
	//
	nextBlock = howmany(peof, vcb->blockSize);	// number of allocation blocks to remain in file
	peof = (int64_t)((int64_t)nextBlock * (int64_t)vcb->blockSize);					// number of bytes in those blocks

#if CONFIG_HFS_STD
	if ((vcb->vcbSigWord == kHFSSigWord) && (peof >= kTwoGigabytes)) {
		#if DEBUG_BUILD
			DebugStr("HFS: Trying to truncate a file to 2GB or more");
		#endif
		err = fileBoundsErr;
		goto ErrorExit;
	}
#endif

	//
	//	Update FCB's length
	//
	/*
	 * XXX Any errors could cause ff_blocks and c_blocks to get out of sync...
	 */
	numBlocks = peof / vcb->blockSize;
	if (!deleted) {
		FTOC(fcb)->c_blocks -= (fcb->ff_blocks - numBlocks);
	}
	fcb->ff_blocks = numBlocks;
	
	// this catalog entry is modified and *must* get forced 
	// to disk when hfs_update() is called
	if (!deleted) {
		/* 
		 * If the file is already C_NOEXISTS, then the catalog record
		 * has been removed from disk already.  We wouldn't need to force 
		 * another update
		 */
		FTOC(fcb)->c_flag |= (C_MODIFIED | C_FORCEUPDATE);
	}
	//
	//	If the new PEOF is 0, then truncateToExtent has no meaning (we should always deallocate
	//	all storage).
	//
	if (peof == 0) {
		int i;
		
		//	Deallocate all the extents for this fork
		err = DeallocateFork(vcb, fileid, forkType, fcb->fcbExtents, &recordDeleted);
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
			err = BlockDeallocate(vcb, startBlock, numBlocks, 0);
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
		err = BlockDeallocate(vcb, extentRecord[extentIndex].startBlock, numBlocks, 0);
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
		err = UpdateExtentRecord(vcb, fcb, deleted, &key, extentRecord, hint);
		if (err != noErr) goto ErrorExit;
	}
	
	//
	//	If there are any following allocation blocks, then we need
	//	to seach for their extent records and delete those allocation
	//	blocks.
	//
	if (nextBlock < physNumBlocks)
		err = TruncateExtents(vcb, forkType, fileid, nextBlock, &recordDeleted);

Done:
ErrorExit:
	if (recordDeleted)
		(void) FlushExtentFile(vcb);

	return err;
}


/*
 * HFS Plus only
 *
 */
OSErr HeadTruncateFile (
	ExtendedVCB  *vcb,
	FCB  *fcb,
	u_int32_t  headblks)
{
	HFSPlusExtentRecord  extents;
	HFSPlusExtentRecord  tailExtents;
	HFSCatalogNodeID  fileID;
	u_int8_t  forkType;
	u_int32_t  blkcnt;
	u_int32_t  startblk;
	u_int32_t  blksfreed;
	int  i, j;
	int  error = 0;
	int  lockflags;


	if (vcb->vcbSigWord != kHFSPlusSigWord)
		return (-1);

	forkType = FORK_IS_RSRC(fcb) ? kResourceForkType : kDataForkType;
	fileID = FTOC(fcb)->c_fileid;
	bzero(tailExtents, sizeof(tailExtents));

	blksfreed = 0;
	startblk = 0;

	/*
	 * Process catalog resident extents
	 */
	for (i = 0, j = 0; i < kHFSPlusExtentDensity; ++i) {
		blkcnt = fcb->fcbExtents[i].blockCount;
		if (blkcnt == 0)
			break;  /* end of extents */

		if (blksfreed < headblks) {
			error = BlockDeallocate(vcb, fcb->fcbExtents[i].startBlock, blkcnt, 0);
			/*
			 * Any errors after the first BlockDeallocate
			 * must be ignored so we can put the file in
			 * a known state.
			 */
			if (error ) {
				if (i == 0)
					goto ErrorExit;  /* uh oh */
				else {
					error = 0;
					printf("hfs: HeadTruncateFile: problems deallocating %s (%d)\n",
					       FTOC(fcb)->c_desc.cd_nameptr ? (const char *)FTOC(fcb)->c_desc.cd_nameptr : "", error);
				}
			}

			blksfreed += blkcnt;
			fcb->fcbExtents[i].startBlock = 0;
			fcb->fcbExtents[i].blockCount = 0;
		} else {
			tailExtents[j].startBlock = fcb->fcbExtents[i].startBlock;
			tailExtents[j].blockCount = blkcnt;
			++j;
		}
		startblk += blkcnt;	
	}
	
	if (blkcnt == 0)
		goto CopyExtents;

	lockflags = hfs_systemfile_lock(vcb, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);

	/* 
	 * Process overflow extents
	 */
	for (;;) {
		u_int32_t  extblks;

		error = FindExtentRecord(vcb, forkType, fileID, startblk, false, NULL, extents, NULL);
		if (error) {
			/*
			 * Any errors after the first BlockDeallocate
			 * must be ignored so we can put the file in
			 * a known state.
			 */
			if (error != btNotFound)
				printf("hfs: HeadTruncateFile: problems finding extents %s (%d)\n",
				       FTOC(fcb)->c_desc.cd_nameptr ? (const char *)FTOC(fcb)->c_desc.cd_nameptr : "", error);
			error = 0;
			break;
		}

		for(i = 0, extblks = 0; i < kHFSPlusExtentDensity; ++i) {
			blkcnt = extents[i].blockCount;
			if (blkcnt == 0)
				break;  /* end of extents */

			if (blksfreed < headblks) {
				error = BlockDeallocate(vcb, extents[i].startBlock, blkcnt, 0);
				if (error) {
					printf("hfs: HeadTruncateFile: problems deallocating %s (%d)\n",
					       FTOC(fcb)->c_desc.cd_nameptr ? (const char *)FTOC(fcb)->c_desc.cd_nameptr : "", error);
					error = 0;
				}
				blksfreed += blkcnt;
			} else {
				tailExtents[j].startBlock = extents[i].startBlock;
				tailExtents[j].blockCount = blkcnt;
				++j;
			}
			extblks += blkcnt;		
		}
		
		error = DeleteExtentRecord(vcb, forkType, fileID, startblk);
		if (error) {
			printf("hfs: HeadTruncateFile: problems deallocating %s (%d)\n",
				FTOC(fcb)->c_desc.cd_nameptr ? (const char *)FTOC(fcb)->c_desc.cd_nameptr : "", error);
			error = 0;
		}
		
		if (blkcnt == 0)
			break;  /* all done */

		startblk += extblks;
	}
	hfs_systemfile_unlock(vcb, lockflags);

CopyExtents:
	if (blksfreed) {
		bcopy(tailExtents, fcb->fcbExtents, sizeof(tailExtents));
		blkcnt = fcb->ff_blocks - headblks;
		FTOC(fcb)->c_blocks -= headblks;
		fcb->ff_blocks = blkcnt;

		FTOC(fcb)->c_flag |= C_FORCEUPDATE;
		FTOC(fcb)->c_touch_chgtime = TRUE;

		(void) FlushExtentFile(vcb);
	}

ErrorExit:	
	return MacToVFSError(error);
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
	ExtendedVCB		*vcb,
	u_int32_t				searchFABN,
	const HFSPlusExtentRecord	extentData,
	u_int32_t				extentDataStartFABN,
	u_int32_t				*foundExtentIndex,
	u_int32_t				*endingFABNPlusOne,
	Boolean					*noMoreExtents)
{
	OSErr	err = noErr;
	u_int32_t	extentIndex;
	/* Set it to the HFS std value */
	u_int32_t	numberOfExtents = kHFSExtentDensity;
	u_int32_t	numAllocationBlocks;
	Boolean	foundExtent;
	
	*endingFABNPlusOne 	= extentDataStartFABN;
	*noMoreExtents		= false;
	foundExtent			= false;

	/* Override numberOfExtents for HFS+/HFSX */
	if (vcb->vcbSigWord != kHFSSigWord) {
		numberOfExtents = kHFSPlusExtentDensity;
	}
	
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
	ExtendedVCB 	*vcb,
	const FCB	 		*fcb,
	int64_t 			filePosition,
	HFSPlusExtentKey	*foundExtentKey,
	HFSPlusExtentRecord	foundExtentData,
	u_int32_t			*foundExtentIndex,
	u_int32_t			*extentBTreeHint,
	u_int32_t			*endingFABNPlusOne )
{
	OSErr				err;
	u_int32_t			filePositionBlock;
	int64_t                         temp64;
	Boolean				noMoreExtents;
	int  lockflags;
	
	temp64 = filePosition / (int64_t)vcb->blockSize;
	filePositionBlock = (u_int32_t)temp64;

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
	lockflags = hfs_systemfile_lock(vcb, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);

	err = FindExtentRecord(vcb, FORK_IS_RSRC(fcb) ? kResourceForkType : kDataForkType,
						   FTOC(fcb)->c_fileid, filePositionBlock, true, foundExtentKey, foundExtentData, extentBTreeHint);
	hfs_systemfile_unlock(vcb, lockflags);

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



//============================================================================
//	Routine:	UpdateExtentRecord
//
//	Function: 	Write new extent data to an existing extent record with a given key.
//				If all of the extents are empty, and the extent record is in the
//				extents file, then the record is deleted.
//
//	Input:		vcb			  			-	the volume containing the extents
//				fcb						-	the file that owns the extents
//				deleted					-	whether or not the file is already deleted
//				extentFileKey  			-	pointer to extent key record (xkr)
//						If the key length is 0, then the extents are actually part
//						of the catalog record, stored in the FCB.
//				extentData  			-	pointer to extent data record (xdr)
//				extentBTreeHint			-	hint for given key, or kNoHint
//
//	Result:		noErr = ok
//				(other) = error from BTree
//============================================================================

static OSErr UpdateExtentRecord (ExtendedVCB *vcb, FCB  *fcb, int deleted,
								 const HFSPlusExtentKey  *extentFileKey,
								 const HFSPlusExtentRecord  extentData,
								 u_int32_t  extentBTreeHint) 
{
    OSErr err = noErr;
	
	if (extentFileKey->keyLength == 0) {	// keyLength == 0 means the FCB's extent record
		BlockMoveData(extentData, fcb->fcbExtents, sizeof(HFSPlusExtentRecord));
		if (!deleted) {
			FTOC(fcb)->c_flag |= C_MODIFIED;
		}
	}
	else {
		struct BTreeIterator *btIterator = NULL;
		FSBufferDescriptor btRecord;
		u_int16_t btRecordSize;
		FCB * btFCB;
		int lockflags;

		//
		//	Need to find and change a record in Extents BTree
		//
		btFCB = GetFileControlBlock(vcb->extentsRefNum);
		
		MALLOC (btIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
		if (btIterator == NULL) {
			return memFullErr;  // translates to ENOMEM
		}
		bzero(btIterator, sizeof(*btIterator));

		/*
		 * The lock taken by callers of ExtendFileC/TruncateFileC is
		 * speculative and only occurs when the file already has
		 * overflow extents. So we need to make sure we have the lock
		 * here.  The extents btree lock can be nested (its recursive)
		 * so we always take it here.
		 */
		lockflags = hfs_systemfile_lock(vcb, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);

		/* HFS+/HFSX */
		if (vcb->vcbSigWord != kHFSSigWord) {		//	HFS Plus volume
			HFSPlusExtentRecord	foundData;		// The extent data actually found

			BlockMoveData(extentFileKey, &btIterator->key, sizeof(HFSPlusExtentKey));

			btIterator->hint.index = 0;
			btIterator->hint.nodeNum = extentBTreeHint;

			btRecord.bufferAddress = &foundData;
			btRecord.itemSize = sizeof(HFSPlusExtentRecord);
			btRecord.itemCount = 1;

			err = BTSearchRecord(btFCB, btIterator, &btRecord, &btRecordSize, btIterator);
	
			if (err == noErr) {
				BlockMoveData(extentData, &foundData, sizeof(HFSPlusExtentRecord));
				err = BTReplaceRecord(btFCB, btIterator, &btRecord, btRecordSize);
			}
			(void) BTFlushPath(btFCB);
		}
#if CONFIG_HFS_STD
		else {
			/* HFS Standard */
			HFSExtentKey *	key;				// Actual extent key used on disk in HFS
			HFSExtentRecord	foundData;			// The extent data actually found

			key = (HFSExtentKey*) &btIterator->key;
			key->keyLength	= kHFSExtentKeyMaximumLength;
			key->forkType	= extentFileKey->forkType;
			key->fileID		= extentFileKey->fileID;
			key->startBlock	= extentFileKey->startBlock;

			btIterator->hint.index = 0;
			btIterator->hint.nodeNum = extentBTreeHint;

			btRecord.bufferAddress = &foundData;
			btRecord.itemSize = sizeof(HFSExtentRecord);
			btRecord.itemCount = 1;

			err = BTSearchRecord(btFCB, btIterator, &btRecord, &btRecordSize, btIterator);

			if (err == noErr)
				err = HFSPlusToHFSExtents(extentData, (HFSExtentDescriptor *)&foundData);

			if (err == noErr)
				err = BTReplaceRecord(btFCB, btIterator, &btRecord, btRecordSize);
			(void) BTFlushPath(btFCB);

		}
#endif

		hfs_systemfile_unlock(vcb, lockflags);

		FREE(btIterator, M_TEMP);
	}
	
	return err;
}



#if CONFIG_HFS_STD
static OSErr HFSPlusToHFSExtents(
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
			DebugStr("ExtentRecord with > 3 extents is invalid for HFS");
			err = fsDSIntErr;
		}
	#endif
	
	return err;
}
#endif



static OSErr GetFCBExtentRecord(
	const FCB			*fcb,
	HFSPlusExtentRecord	extents)
{
	
	BlockMoveData(fcb->fcbExtents, extents, sizeof(HFSPlusExtentRecord));
	
	return noErr;
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
	u_int32_t	mask,
	u_int32_t	*blocksChecked,
	Boolean		*checkedLastExtent)
{
	u_int32_t	blocks;
	u_int32_t	extentIndex;

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
	u_int32_t	nodeSize)
{
	u_int32_t			mask;
	u_int32_t			startBlock;
	u_int32_t			blocksChecked;
	u_int32_t			hint;
	HFSPlusExtentKey	key;
	HFSPlusExtentRecord	extents;
	OSErr				result;
	Boolean				lastExtentReached;
	int  lockflags;
	

	if (vcb->blockSize >= nodeSize)
		return TRUE;

	mask = (nodeSize / vcb->blockSize) - 1;

	// check the local extents
	(void) GetFCBExtentRecord(fcb, extents);
	if ( !ExtentsAreIntegral(extents, mask, &blocksChecked, &lastExtentReached) )
		return FALSE;

	if ( lastExtentReached || 
		 (int64_t)((int64_t)blocksChecked * (int64_t)vcb->blockSize) >= (int64_t)fcb->ff_size)
		return TRUE;

	startBlock = blocksChecked;

	lockflags = hfs_systemfile_lock(vcb, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);

	// check the overflow extents (if any)
	while ( !lastExtentReached )
	{
		result = FindExtentRecord(vcb, kDataForkType, fcb->ff_cp->c_fileid, startBlock, FALSE, &key, extents, &hint);
		if (result) break;

		if ( !ExtentsAreIntegral(extents, mask, &blocksChecked, &lastExtentReached) ) {
			hfs_systemfile_unlock(vcb, lockflags);
			return FALSE;
		}
		startBlock += blocksChecked;
	}
	hfs_systemfile_unlock(vcb, lockflags);
	return TRUE;
}

