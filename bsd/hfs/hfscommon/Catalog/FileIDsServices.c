/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#include "../../hfs_macos_defs.h"
#include "../../hfs_format.h"

#include	"../headers/FileMgrInternal.h"
#include	"../headers/HFSUnicodeWrappers.h"
#include	"../headers/CatalogPrivate.h"
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <libkern/libkern.h>


struct ExtentsRecBuffer {
	ExtentKey	extentKey;
	ExtentRecord	extentData;
};
typedef struct ExtentsRecBuffer ExtentsRecBuffer;


static u_int32_t CheckExtents( void *extents, u_int32_t blocks, Boolean isHFSPlus );
static OSErr  DeleteExtents( ExtendedVCB *vcb, u_int32_t fileNumber, int quitEarly, u_int8_t forkType, Boolean isHFSPlus );
static OSErr  MoveExtents( ExtendedVCB *vcb, u_int32_t srcFileID, u_int32_t destFileID, int quitEarly, u_int8_t forkType, Boolean isHFSPlus );

#if CONFIG_HFS_STD
static void  CopyCatalogNodeInfo( CatalogRecord *src, CatalogRecord *dest );
#endif

static void  CopyBigCatalogNodeInfo( CatalogRecord *src, CatalogRecord *dest );
static void  CopyExtentInfo( ExtentKey *key, ExtentRecord *data, ExtentsRecBuffer *buffer, u_int16_t bufferCount );

/* 
 * This function moves the overflow extents associated with srcID into the file associated with dstID.
 * We should have already verified that 'srcID' has overflow extents. So now we move all of the overflow
 * extent records.
 */
OSErr MoveData( ExtendedVCB *vcb, HFSCatalogNodeID srcID, HFSCatalogNodeID destID, int rsrc) { 
	
	OSErr		err;
	
	/* 
	 * Only the source file should have extents, so we just track those.
	 * We operate on the fork represented by the open FD that was used to call into this
	 * function
	 */
	if (rsrc) {		
		/* Copy the extent overflow blocks. */
		err = MoveExtents( vcb, srcID, destID, 1, (u_int8_t)0xff, 1);
		if ( err != noErr ) {
			if ( err != dskFulErr ) {
				return( err );
			}
			/* 
			 * In case of error, we would have probably run into problems
			 * growing the extents b-tree.  Since the move is actually a copy + delete
			 * just delete the new entries. Same for below.
			 */
			err = DeleteExtents( vcb, destID, 1, (u_int8_t)0xff, 1); 
			ReturnIfError( err ); //	we are doomed. Just QUIT!
			goto FlushAndReturn;
		}
	}
	else {		
		/* Copy the extent overflow blocks. */
		err = MoveExtents( vcb, srcID, destID, 1, 0, 1);
		if ( err != noErr ) {
			if ( err != dskFulErr ) {
				return( err );
			}
			err = DeleteExtents( vcb, destID, 1, 0, 1); 
			ReturnIfError( err ); //	we are doomed. Just QUIT!
			goto FlushAndReturn;
		}
	}
	
FlushAndReturn:
	/* Write out the catalog and extent overflow B-Tree changes */
	err = FlushCatalog( vcb );
	err = FlushExtentFile( vcb );
	
	return( err );
}


OSErr ExchangeFileIDs( ExtendedVCB *vcb, ConstUTF8Param srcName, ConstUTF8Param destName, HFSCatalogNodeID srcID, HFSCatalogNodeID destID, u_int32_t srcHint, u_int32_t destHint )
{
	CatalogKey	srcKey;		// 518 bytes
	CatalogKey	destKey;	// 518 bytes
	CatalogRecord	srcData;	// 520 bytes
	CatalogRecord	destData;	// 520 bytes
	CatalogRecord	swapData;	// 520 bytes
	int16_t		numSrcExtentBlocks;
	int16_t		numDestExtentBlocks;
	OSErr		err;
	Boolean		isHFSPlus = ( vcb->vcbSigWord == kHFSPlusSigWord );

	err = BuildCatalogKeyUTF8(vcb, srcID, srcName, kUndefinedStrLen, &srcKey, NULL);
	ReturnIfError(err);

	err = BuildCatalogKeyUTF8(vcb, destID, destName, kUndefinedStrLen, &destKey, NULL);
	ReturnIfError(err);

	if ( isHFSPlus )
	{
		//--	Step 1: Check the catalog nodes for extents
		
		//--	locate the source file, test for extents in extent file, and copy the cat record for later
		err = LocateCatalogNodeByKey( vcb, srcHint, &srcKey, &srcData, &srcHint );
		ReturnIfError( err );
	
		if ( srcData.recordType != kHFSPlusFileRecord )
			return( cmFThdDirErr );					//	Error "cmFThdDirErr = it is a directory"
			
		//--	Check if there are any extents in the source file
		//€€	I am only checling the extents in the low 32 bits, routine will fail if files extents after 2 gig are in overflow
		numSrcExtentBlocks = CheckExtents( srcData.hfsPlusFile.dataFork.extents, srcData.hfsPlusFile.dataFork.totalBlocks, isHFSPlus );
		if ( numSrcExtentBlocks == 0 )					//	then check the resource fork extents
			numSrcExtentBlocks = CheckExtents( srcData.hfsPlusFile.resourceFork.extents, srcData.hfsPlusFile.resourceFork.totalBlocks, isHFSPlus );

		//--	Check if there are any extents in the destination file
		err = LocateCatalogNodeByKey( vcb, destHint, &destKey, &destData, &destHint );
		ReturnIfError( err );
	
		if ( destData.recordType != kHFSPlusFileRecord )
			return( cmFThdDirErr );					//	Error "cmFThdDirErr = it is a directory"

		numDestExtentBlocks = CheckExtents( destData.hfsPlusFile.dataFork.extents, destData.hfsPlusFile.dataFork.totalBlocks, isHFSPlus );
		if ( numDestExtentBlocks == 0 )					//	then check the resource fork extents
			numDestExtentBlocks = CheckExtents( destData.hfsPlusFile.resourceFork.extents, destData.hfsPlusFile.resourceFork.totalBlocks, isHFSPlus );

		//--	Step 2: Exchange the Extent key in the extent file
		
		//--	Exchange the extents key in the extent file
		err = DeleteExtents( vcb, kHFSBogusExtentFileID, 0, 0, isHFSPlus );
		ReturnIfError( err );
		
		if ( numSrcExtentBlocks && numDestExtentBlocks )	//	if both files have extents
		{
			//--	Change the source extents file ids to our known bogus value
			err = MoveExtents( vcb, srcData.hfsPlusFile.fileID, kHFSBogusExtentFileID, 0,0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr ) {
					return( err );
                }
				else {
                    err = DeleteExtents( vcb, kHFSBogusExtentFileID, 0, 0, isHFSPlus );
                    ReturnIfError( err );					//	we are doomed. Just QUIT!
                    
                    err = FlushCatalog( vcb );   			//	flush the catalog
                    err = FlushExtentFile( vcb );			//	flush the extent file (unneeded for common case, but it's cheap)
                    return( dskFulErr );
                }
			}
			
			//--	Change the destination extents file id's to the source id's
			err = MoveExtents( vcb, destData.hfsPlusFile.fileID, srcData.hfsPlusFile.fileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

ExUndo2aPlus:	err = DeleteExtents( vcb, srcData.hfsPlusFile.fileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

                err = MoveExtents( vcb, kHFSBogusExtentFileID, srcData.hfsPlusFile.fileID, 0, 0, isHFSPlus );	//	Move the extents back
				ReturnIfError( err );					//	we are doomed. Just QUIT!
					
                err = DeleteExtents( vcb, kHFSBogusExtentFileID, 0, 0, isHFSPlus );
                ReturnIfError( err );					//	we are doomed. Just QUIT!
                    
                err = FlushCatalog( vcb );   			//	flush the catalog
                err = FlushExtentFile( vcb );			//	flush the extent file (unneeded for common case, but it's cheap)
                return( dskFulErr );

			}
			
			//--	Change the bogus extents file id's to the dest id's
            err = MoveExtents( vcb, kHFSBogusExtentFileID, destData.hfsPlusFile.fileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

				err = DeleteExtents( vcb, destData.hfsPlusFile.fileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

				err = MoveExtents( vcb, srcData.hfsPlusFile.fileID, destData.hfsPlusFile.fileID, 0, 0, isHFSPlus );	//	Move the extents back
				ReturnIfError( err );					//	we are doomed. Just QUIT!
					
				goto ExUndo2aPlus;
			}
			
		}
		else if ( numSrcExtentBlocks )	//	just the source file has extents
		{
			err = MoveExtents( vcb, srcData.hfsPlusFile.fileID, destData.hfsPlusFile.fileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

				err = DeleteExtents( vcb, srcData.hfsPlusFile.fileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

				goto FlushAndReturn;
			}
		}
		else if ( numDestExtentBlocks )	//	just the destination file has extents
		{
			err = MoveExtents( vcb, destData.hfsPlusFile.fileID, srcData.hfsPlusFile.fileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

				err = DeleteExtents( vcb, destData.hfsPlusFile.fileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

				goto FlushAndReturn;
			}
		}

		//--	Step 3: Change the data in the catalog nodes
		
		//--	find the source cnode and put dest info in it
		err = LocateCatalogNodeByKey( vcb, srcHint, &srcKey, &srcData, &srcHint );
		if ( err != noErr )
			return( cmBadNews );
		
		BlockMoveData( &srcData, &swapData, sizeof(CatalogRecord) );
		CopyBigCatalogNodeInfo( &destData, &srcData );
		
		err = ReplaceBTreeRecord( vcb->catalogRefNum, &srcKey, srcHint, &srcData, sizeof(HFSPlusCatalogFile), &srcHint );
		ReturnIfError( err );

		//	find the destination cnode and put source info in it		
		err = LocateCatalogNodeByKey( vcb, destHint, &destKey, &destData, &destHint );
		if ( err != noErr )
			return( cmBadNews );
			
		CopyBigCatalogNodeInfo( &swapData, &destData );
		err = ReplaceBTreeRecord( vcb->catalogRefNum, &destKey, destHint, &destData, sizeof(HFSPlusCatalogFile), &destHint );
		ReturnIfError( err );
	}
#if CONFIG_HFS_STD
	else		//	HFS	//
	{
		//--	Step 1: Check the catalog nodes for extents
		
		//--	locate the source file, test for extents in extent file, and copy the cat record for later
		err = LocateCatalogNodeByKey( vcb, srcHint, &srcKey, &srcData, &srcHint );
		ReturnIfError( err );
	
		if ( srcData.recordType != kHFSFileRecord )
			return( cmFThdDirErr );					//	Error "cmFThdDirErr = it is a directory"
			
		//--	Check if there are any extents in the source file
		numSrcExtentBlocks = CheckExtents( srcData.hfsFile.dataExtents, srcData.hfsFile.dataPhysicalSize / vcb->blockSize, isHFSPlus );
		if ( numSrcExtentBlocks == 0 )					//	then check the resource fork extents
			numSrcExtentBlocks = CheckExtents( srcData.hfsFile.rsrcExtents, srcData.hfsFile.rsrcPhysicalSize / vcb->blockSize, isHFSPlus );
		
		
		//€€	Do we save the found source node for later use?
		
				
		//--	Check if there are any extents in the destination file
		err = LocateCatalogNodeByKey( vcb, destHint, &destKey, &destData, &destHint );
		ReturnIfError( err );
	
		if ( destData.recordType != kHFSFileRecord )
			return( cmFThdDirErr );					//	Error "cmFThdDirErr = it is a directory"

		numDestExtentBlocks = CheckExtents( destData.hfsFile.dataExtents, destData.hfsFile.dataPhysicalSize / vcb->blockSize, isHFSPlus );
		if ( numDestExtentBlocks == 0 )					//	then check the resource fork extents
			numDestExtentBlocks = CheckExtents( destData.hfsFile.rsrcExtents, destData.hfsFile.rsrcPhysicalSize / vcb->blockSize, isHFSPlus );
			
		//€€	Do we save the found destination node for later use?


		//--	Step 2: Exchange the Extent key in the extent file
		
		//--	Exchange the extents key in the extent file
        err = DeleteExtents( vcb, kHFSBogusExtentFileID, 0, 0, isHFSPlus );
		ReturnIfError( err );
		
		if ( numSrcExtentBlocks && numDestExtentBlocks )	//	if both files have extents
		{
			//--	Change the source extents file ids to our known bogus value
        err = MoveExtents( vcb, srcData.hfsFile.fileID, kHFSBogusExtentFileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

ExUndo1a:		err = DeleteExtents( vcb, kHFSBogusExtentFileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

				err = FlushCatalog( vcb );   			//	flush the catalog
				err = FlushExtentFile( vcb );			//	flush the extent file (unneeded for common case, but it's cheap)			
				return( dskFulErr );
			}
			
			//--	Change the destination extents file id's to the source id's
			err = MoveExtents( vcb, destData.hfsFile.fileID, srcData.hfsFile.fileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

ExUndo2a:		err = DeleteExtents( vcb, srcData.hfsFile.fileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

                err = MoveExtents( vcb, kHFSBogusExtentFileID, srcData.hfsFile.fileID, 0, 0, isHFSPlus );	//	Move the extents back
				ReturnIfError( err );					//	we are doomed. Just QUIT!
					
				goto ExUndo1a;
			}
			
			//--	Change the bogus extents file id's to the dest id's
            err = MoveExtents( vcb, kHFSBogusExtentFileID, destData.hfsFile.fileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

				err = DeleteExtents( vcb, destData.hfsFile.fileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

				err = MoveExtents( vcb, srcData.hfsFile.fileID, destData.hfsFile.fileID, 0, 0, isHFSPlus );	//	Move the extents back
				ReturnIfError( err );					//	we are doomed. Just QUIT!
					
				goto ExUndo2a;
			}
			
		}
		else if ( numSrcExtentBlocks )	//	just the source file has extents
		{
			err = MoveExtents( vcb, srcData.hfsFile.fileID, destData.hfsFile.fileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

				err = DeleteExtents( vcb, srcData.hfsFile.fileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

				goto FlushAndReturn;
			}
		}
		else if ( numDestExtentBlocks )	//	just the destination file has extents
		{
			err = MoveExtents( vcb, destData.hfsFile.fileID, srcData.hfsFile.fileID, 0, 0, isHFSPlus );
			if ( err != noErr )
			{
				if ( err != dskFulErr )
					return( err );

				err = DeleteExtents( vcb, destData.hfsFile.fileID, 0, 0, isHFSPlus );
				ReturnIfError( err );					//	we are doomed. Just QUIT!

				goto FlushAndReturn;
			}
		}

		//--	Step 3: Change the data in the catalog nodes
		
		//--	find the source cnode and put dest info in it
		err = LocateCatalogNodeByKey( vcb, srcHint, &srcKey, &srcData, &srcHint );
		if ( err != noErr )
			return( cmBadNews );
		
		BlockMoveData( &srcData, &swapData, sizeof(CatalogRecord) );
		//€€	Asm source copies from the saved dest catalog node
		CopyCatalogNodeInfo( &destData, &srcData );
		
		err = ReplaceBTreeRecord( vcb->catalogRefNum, &srcKey, srcHint, &srcData, sizeof(HFSCatalogFile), &srcHint );
		ReturnIfError( err );

		
		//	find the destination cnode and put source info in it		
		err = LocateCatalogNodeByKey( vcb, destHint, &destKey, &destData, &destHint );
		if ( err != noErr )
			return( cmBadNews );
			
		CopyCatalogNodeInfo( &swapData, &destData );
		err = ReplaceBTreeRecord( vcb->catalogRefNum, &destKey, destHint, &destData, sizeof(HFSCatalogFile), &destHint );
		ReturnIfError( err );
	}
#endif

	err = noErr;

	//--	Step 4: Error Handling section


FlushAndReturn:
	err = FlushCatalog( vcb );   			//	flush the catalog
	err = FlushExtentFile( vcb );			//	flush the extent file (unneeded for common case, but it's cheap)			
	return( err );
}


#if CONFIG_HFS_STD
static void  CopyCatalogNodeInfo( CatalogRecord *src, CatalogRecord *dest )
{
	dest->hfsFile.dataLogicalSize	= src->hfsFile.dataLogicalSize;
	dest->hfsFile.dataPhysicalSize = src->hfsFile.dataPhysicalSize;
	dest->hfsFile.rsrcLogicalSize	= src->hfsFile.rsrcLogicalSize;
	dest->hfsFile.rsrcPhysicalSize = src->hfsFile.rsrcPhysicalSize;
	dest->hfsFile.modifyDate = src->hfsFile.modifyDate;
	BlockMoveData( src->hfsFile.dataExtents, dest->hfsFile.dataExtents, sizeof(HFSExtentRecord) );
	BlockMoveData( src->hfsFile.rsrcExtents, dest->hfsFile.rsrcExtents, sizeof(HFSExtentRecord) );
}
#endif

static void  CopyBigCatalogNodeInfo( CatalogRecord *src, CatalogRecord *dest )
{
	BlockMoveData( &src->hfsPlusFile.dataFork, &dest->hfsPlusFile.dataFork, sizeof(HFSPlusForkData) );
	BlockMoveData( &src->hfsPlusFile.resourceFork, &dest->hfsPlusFile.resourceFork, sizeof(HFSPlusForkData) );
	dest->hfsPlusFile.contentModDate = src->hfsPlusFile.contentModDate;
}


static OSErr  MoveExtents( ExtendedVCB *vcb, u_int32_t srcFileID, u_int32_t destFileID, int quitEarly, u_int8_t forkType, Boolean isHFSPlus )
{
	FCB *				fcb;
	ExtentsRecBuffer	extentsBuffer[kNumExtentsToCache];
	ExtentKey *			extentKeyPtr;
	ExtentRecord		extentData;
	struct BTreeIterator *btIterator = NULL;
	struct BTreeIterator *tmpIterator = NULL;
	FSBufferDescriptor	btRecord;
	u_int16_t			btKeySize;
	u_int16_t			btRecordSize;
	int16_t				i, j;
	OSErr				err;
	
	MALLOC (btIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (btIterator == NULL) {
		return memFullErr;  // translates to ENOMEM
	}


	MALLOC (tmpIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (tmpIterator == NULL) {	
		FREE (btIterator, M_TEMP);	
		return memFullErr;  // translates to ENOMEM
	}

	bzero(btIterator, sizeof(*btIterator));
	bzero (tmpIterator, sizeof(*tmpIterator));


	fcb = GetFileControlBlock(vcb->extentsRefNum);
	
	(void) BTInvalidateHint(btIterator);
	extentKeyPtr = (ExtentKey*) &btIterator->key;
	btRecord.bufferAddress = &extentData;
	btRecord.itemCount = 1;

	//--	Collect the extent records

	//
	//	A search on the following key will cause the BTree to be positioned immediately
	//	before the first extent record for file #srcFileID, but not actually positioned
	//	on any record.  This is because there cannot be an extent record with FABN = 0
	//	(the first extent of the fork, which would be in the catalog entry, not an extent
	//	record).
	//
	//	Using BTIterateRecord with kBTreeNextRecord will then get that first extent record.
	//
	if (isHFSPlus) {
		btRecord.itemSize = sizeof(HFSPlusExtentRecord);
		btKeySize = sizeof(HFSPlusExtentKey);

		extentKeyPtr->hfsPlus.keyLength	 = kHFSPlusExtentKeyMaximumLength;
		extentKeyPtr->hfsPlus.forkType	 = forkType;
		extentKeyPtr->hfsPlus.pad		 = 0;
		extentKeyPtr->hfsPlus.fileID	 = srcFileID;
		extentKeyPtr->hfsPlus.startBlock = 0;
	}
#if CONFIG_HFS_STD
	else {
		btRecord.itemSize = sizeof(HFSExtentRecord);
		btKeySize = sizeof(HFSExtentKey);

		extentKeyPtr->hfs.keyLength	 = kHFSExtentKeyMaximumLength;
		extentKeyPtr->hfs.forkType	 = 0;
		extentKeyPtr->hfs.fileID	 = srcFileID;
		extentKeyPtr->hfs.startBlock = 0;
	}
#else
    else {
        return cmBadNews;
    }
#endif
	
	//
	//	We do an initial BTSearchRecord to position the BTree's iterator just before any extent
	//	records for srcFileID.  We then do a few BTIterateRecord and BTInsertRecord of those found
	//	records, but with destFileID as the file number in the key.  Keep doing this sequence of
	//	BTIterateRecord and BTInsertRecord until we find an extent for another file, or there are
	//	no more extent records in the tree.
	//
	//	Basically, we're copying records kNumExtentsToCache at a time.  The copies have their file ID
	//	set to destFileID.
	//
	//	This depends on BTInsertRecord not effecting the iterator used by BTIterateRecord.  If it
	//	_did_ effect the iterator, then we would need to do a BTSearchRecord before each series
	//	of BTIterateRecord.  We'd need to set up the key for BTSearchRecord to find the last record
	//	we found, so that BTIterateRecord would get the next one (the first we haven't processed).
	//

	err = BTSearchRecord(fcb, btIterator, &btRecord, &btRecordSize, btIterator);
	
	//	We expect a btNotFound here, since there shouldn't be an extent record with FABN = 0.
	if (err != btNotFound)
	{
		if ( DEBUG_BUILD )
			DebugStr("Unexpected error from SearchBTreeRecord");
		
		if (err == noErr)			//	If we found such a bogus extent record, then the tree is really messed up
			err = cmBadNews;		//	so return an error that conveys the disk is hosed.
		
		FREE (tmpIterator, M_TEMP);	
		FREE (btIterator, M_TEMP);
		return err;
	}

	do
	{
		btRecord.bufferAddress = &extentData;
		btRecord.itemCount = 1;

		for ( i=0 ; i<kNumExtentsToCache ; i++ )
		{
			HFSCatalogNodeID	foundFileID = 0;
			
			err = BTIterateRecord(fcb, kBTreeNextRecord, btIterator, &btRecord, &btRecordSize);
			if ( err == btNotFound )		//	Did we run out of extent records in the extents tree?
				break;						//	if xkrFNum(A0) is cleared on this error, then this test is bogus!
			else if ( err != noErr ) {
				FREE (btIterator, M_TEMP);
				FREE (tmpIterator, M_TEMP);
				return( err );				//	must be ioError
			}
            if (isHFSPlus) {
                foundFileID = extentKeyPtr->hfsPlus.fileID;
            }
#if CONFIG_HFS_STD
            else {
                foundFileID = extentKeyPtr->hfs.fileID;
            }
#endif
			if ( foundFileID == srcFileID ) {
				/* Check if we need to quit early. */
				if (quitEarly && isHFSPlus) {
					if (extentKeyPtr->hfsPlus.forkType != forkType) {
						break;
					}
				}
				CopyExtentInfo(extentKeyPtr, &extentData, extentsBuffer, i);
			}
			else{
				/* The fileID's are of a different file.  We're done here. */
				break;
			}
		}
		
		
		
		//--	edit each extent key, and reinsert each extent record in the extent file
		if (isHFSPlus)
			btRecordSize = sizeof(HFSPlusExtentRecord);
#if CONFIG_HFS_STD
		else
			btRecordSize = sizeof(HFSExtentRecord);
#endif
        
		for ( j=0 ; j<i ; j++ )
		{

			if (isHFSPlus)
				extentsBuffer[j].extentKey.hfsPlus.fileID = destFileID;	//	change only the id in the key to dest ID
#if CONFIG_HFS_STD
			else
				extentsBuffer[j].extentKey.hfs.fileID = destFileID;	//	change only the id in the key to dest ID
#endif
            
			// get iterator and buffer descriptor ready...
			(void) BTInvalidateHint(tmpIterator);
			BlockMoveData(&(extentsBuffer[j].extentKey), &tmpIterator->key, btKeySize);
			btRecord.bufferAddress = &(extentsBuffer[j].extentData);

			err = BTInsertRecord(fcb, tmpIterator, &btRecord, btRecordSize);
			if ( err != noErr ) {								
				/* Parse the error and free iterators */
				FREE (btIterator, M_TEMP);
				FREE (tmpIterator, M_TEMP);
				if ( err == btExists )
				{
					if ( DEBUG_BUILD ) {
						DebugStr("Can't insert record -- already exists"); 
					}
					return( cmBadNews );
				}
				else {
					return( err );
				}			
			}
		}

		//--	okay, done with this buffered batch, go get the next set of extent records
		//	If our buffer is not full, we must be done, or recieved an error
		
		if ( i != kNumExtentsToCache )			//	if the buffer is not full, we must be done
		{
			err = DeleteExtents( vcb, srcFileID, quitEarly, forkType, isHFSPlus );	//	Now delete all the extent entries with the sourceID
			if ( DEBUG_BUILD && err != noErr )
				DebugStr("Error from DeleteExtents");
			break;									//	we're done!
		}
	} while ( true );
	
	FREE (tmpIterator, M_TEMP);
	FREE (btIterator, M_TEMP);

	return( err );
}


static void  CopyExtentInfo( ExtentKey *key, ExtentRecord *data, ExtentsRecBuffer *buffer, u_int16_t bufferCount )
{
	BlockMoveData( key, &(buffer[bufferCount].extentKey), sizeof( ExtentKey ) );
	BlockMoveData( data, &(buffer[bufferCount].extentData), sizeof( ExtentRecord ) );
}


//--	Delete all extents in extent file that have the ID given.
static OSErr  DeleteExtents( ExtendedVCB *vcb, u_int32_t fileID, int quitEarly,  u_int8_t forkType, Boolean isHFSPlus )
{
	FCB *				fcb;
	ExtentKey *			extentKeyPtr;
	ExtentRecord		extentData;
	struct BTreeIterator *btIterator = NULL;
	struct BTreeIterator *tmpIterator = NULL;
	FSBufferDescriptor	btRecord;
	u_int16_t			btRecordSize;
	OSErr				err;

    

	MALLOC (btIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (btIterator == NULL) {
		return memFullErr;  // translates to ENOMEM
	}

	MALLOC (tmpIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (tmpIterator == NULL) {	
		FREE (btIterator, M_TEMP);	
		return memFullErr;  // translates to ENOMEM
	}

	bzero(btIterator, sizeof(*btIterator));
	bzero (tmpIterator, sizeof(*tmpIterator));

	fcb = GetFileControlBlock(vcb->extentsRefNum);

	(void) BTInvalidateHint(btIterator);
	extentKeyPtr = (ExtentKey*) &btIterator->key;
	btRecord.bufferAddress = &extentData;
	btRecord.itemCount = 1;

	//	The algorithm is to position the BTree just before any extent records for fileID.
	//	Then just keep getting successive records.  If the record is still for fileID,
	//	then delete it.
	
	if (isHFSPlus) {
		btRecord.itemSize = sizeof(HFSPlusExtentRecord);

		extentKeyPtr->hfsPlus.keyLength	 = kHFSPlusExtentKeyMaximumLength;
		extentKeyPtr->hfsPlus.forkType	 = forkType;
		extentKeyPtr->hfsPlus.pad		 = 0;
		extentKeyPtr->hfsPlus.fileID	 = fileID;
		extentKeyPtr->hfsPlus.startBlock = 0;
	}
#if CONFIG_HFS_STD
	else {
		btRecord.itemSize = sizeof(HFSExtentRecord);

		extentKeyPtr->hfs.keyLength	 = kHFSExtentKeyMaximumLength;
		extentKeyPtr->hfs.forkType	 = forkType;
		extentKeyPtr->hfs.fileID	 = fileID;
		extentKeyPtr->hfs.startBlock = 0;
	}
#else 
    else return cmBadNews;
#endif

	err = BTSearchRecord(fcb, btIterator, &btRecord, &btRecordSize, btIterator);
	if ( err != btNotFound )
	{
		if (err == noErr) {		//	Did we find a bogus extent record?
			err = cmBadNews;	//	Yes, so indicate things are messed up.
		}
		
		return err;				//	Got some unexpected error, so return it
	}

	do
	{
		HFSCatalogNodeID	foundFileID = 0;

		err = BTIterateRecord(fcb, kBTreeNextRecord, btIterator, &btRecord, &btRecordSize);
		if ( err != noErr )
		{
			if (err == btNotFound)	//	If we hit the end of the BTree
				err = noErr;		//		then it's OK
				
			break;					//	We're done now.
		}
        if (isHFSPlus) {
            foundFileID = extentKeyPtr->hfsPlus.fileID;
        }
#if CONFIG_HFS_STD
        else {
            foundFileID = extentKeyPtr->hfs.fileID;
        }
#endif
        
		if ( foundFileID != fileID ) {
			break;					//	numbers don't match, we must be done
		}
		if (quitEarly && isHFSPlus) {
			/* If we're only deleting one type of fork, then quit early if it doesn't match */
			if (extentKeyPtr->hfsPlus.forkType != forkType) {
				break;
			}
		}
		
		*tmpIterator = *btIterator;
		err = BTDeleteRecord( fcb, tmpIterator );
		if (err != noErr)
			break;
	}	while ( true );
	
	FREE (tmpIterator, M_TEMP);
	FREE (btIterator, M_TEMP);

	return( err );
}


//	Check if there are extents represented in the extents overflow file.
static u_int32_t  CheckExtents( void *extents, u_int32_t totalBlocks, Boolean isHFSPlus )
{
	u_int32_t		extentAllocationBlocks;
	u_int16_t		i;


	if ( totalBlocks == 0 )
		return( 0 );
		
	extentAllocationBlocks = 0;
	
	if ( isHFSPlus )
	{
		for ( i = 0 ; i < kHFSPlusExtentDensity ; i++ )
		{
			extentAllocationBlocks += ((HFSPlusExtentDescriptor *)extents)[i].blockCount;
			if ( extentAllocationBlocks >= totalBlocks )		//	greater than or equal (extents can add past eof if 'Close" crashes w/o truncating new clump)
				return( 0 );
		}
	}
#if CONFIG_HFS_STD
	else
	{
		for ( i = 0 ; i < kHFSExtentDensity ; i++ )
		{
			extentAllocationBlocks += ((HFSExtentDescriptor *)extents)[i].blockCount;
			if ( extentAllocationBlocks >= totalBlocks )		//	greater than or equal (extents can add past eof if 'Close" crashes w/o truncating new clump)
				return( 0 );
		}
	}
#endif
	
	return( extentAllocationBlocks );
}
