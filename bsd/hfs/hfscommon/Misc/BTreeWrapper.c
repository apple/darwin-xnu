/*
 * Copyright (c) 2000,2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include "../headers/BTreesPrivate.h"


// local routines
static OSErr	CheckBTreeKey(const BTreeKey *key, const BTreeControlBlock *btcb);
static Boolean	ValidHFSRecord(const void *record, const BTreeControlBlock *btcb, UInt16 recordSize);




OSErr SearchBTreeRecord(FileReference refNum, const void* key, UInt32 hint, void* foundKey, void* data, UInt16 *dataSize, UInt32 *newHint)
{
	panic("SearchBTreeRecord is dead code!");
	return (-1);
#if 0
	FSBufferDescriptor	 btRecord;
	BTreeIterator		 searchIterator;
	FCB					*fcb;
	BTreeControlBlock	*btcb;
	OSStatus			 result;


	fcb = GetFileControlBlock(refNum);
	btcb = (BTreeControlBlock*) fcb->fcbBTCBPtr;

	btRecord.bufferAddress = data;
	btRecord.itemCount = 1;
	if ( btcb->maxKeyLength == kHFSExtentKeyMaximumLength )
		btRecord.itemSize = sizeof(HFSExtentRecord);
	else if ( btcb->maxKeyLength == kHFSPlusExtentKeyMaximumLength )
		btRecord.itemSize = sizeof(HFSPlusExtentRecord);
	else
		btRecord.itemSize = sizeof(CatalogRecord);

	searchIterator.hint.writeCount = 0;	// clear these out for debugging...
	searchIterator.hint.reserved1 = 0;
	searchIterator.hint.reserved2 = 0;

	searchIterator.hint.nodeNum = hint;
	searchIterator.hint.index = 0;

	result = CheckBTreeKey((BTreeKey *) key, btcb);
	ExitOnError(result);

	BlockMoveData(key, &searchIterator.key, CalcKeySize(btcb, (BTreeKey *) key));		//€€ should we range check against maxkeylen?
	
	result = BTSearchRecord( fcb, &searchIterator, &btRecord, dataSize, &searchIterator );

	if (result == noErr)
	{
		*newHint = searchIterator.hint.nodeNum;

		result = CheckBTreeKey(&searchIterator.key, btcb);
		ExitOnError(result);

		BlockMoveData(&searchIterator.key, foundKey, CalcKeySize(btcb, &searchIterator.key));	//€€ warning, this could overflow user's buffer!!!

		if ( DEBUG_BUILD && !ValidHFSRecord(data, btcb, *dataSize) )
			DebugStr("\pSearchBTreeRecord: bad record?");
	}

ErrorExit:

	return result;
#endif
}


OSErr ReplaceBTreeRecord(FileReference refNum, const void* key, UInt32 hint, void *newData, UInt16 dataSize, UInt32 *newHint)
{
	FSBufferDescriptor	btRecord;
	BTreeIterator		iterator;
	FCB					*fcb;
	BTreeControlBlock	*btcb;
	OSStatus			result;


	fcb = GetFileControlBlock(refNum);
	btcb = (BTreeControlBlock*) fcb->fcbBTCBPtr;

	btRecord.bufferAddress = newData;
	btRecord.itemSize = dataSize;
	btRecord.itemCount = 1;

	iterator.hint.nodeNum = hint;

	result = CheckBTreeKey((BTreeKey *) key, btcb);
	ExitOnError(result);

	BlockMoveData(key, &iterator.key, CalcKeySize(btcb, (BTreeKey *) key));		//€€ should we range check against maxkeylen?

	if ( DEBUG_BUILD && !ValidHFSRecord(newData, btcb, dataSize) )
		DebugStr("\pReplaceBTreeRecord: bad record?");

	result = BTReplaceRecord( fcb, &iterator, &btRecord, dataSize );

	*newHint = iterator.hint.nodeNum;

	//€€ do we need to invalidate the iterator?

ErrorExit:

	return result;
}



static OSErr CheckBTreeKey(const BTreeKey *key, const BTreeControlBlock *btcb)
{
	UInt16	keyLen;
	
	if ( btcb->attributes & kBTBigKeysMask )
		keyLen = key->length16;
	else
		keyLen = key->length8;

	if ( (keyLen < 6) || (keyLen > btcb->maxKeyLength) )
	{
		if ( DEBUG_BUILD )
			DebugStr("\pCheckBTreeKey: bad key length!");
		return fsBTInvalidKeyLengthErr;
	}
	
	return noErr;
}


static Boolean ValidHFSRecord(const void *record, const BTreeControlBlock *btcb, UInt16 recordSize)
{
	UInt32			cNodeID;
	
	if ( btcb->maxKeyLength == kHFSExtentKeyMaximumLength )
	{
		return ( recordSize == sizeof(HFSExtentRecord) );
	}
	else if (btcb->maxKeyLength == kHFSPlusExtentKeyMaximumLength )
	{
		return ( recordSize == sizeof(HFSPlusExtentRecord) );
	}
	else // Catalog record
	{
		CatalogRecord *catalogRecord = (CatalogRecord*) record;

		switch(catalogRecord->recordType)
		{
			case kHFSFolderRecord:
			{
				if ( recordSize != sizeof(HFSCatalogFolder) )
					return false;
				if ( catalogRecord->hfsFolder.flags != 0 )
					return false;
				if ( catalogRecord->hfsFolder.valence > 0x7FFF )
					return false;
					
				cNodeID = catalogRecord->hfsFolder.folderID;
	
				if ( (cNodeID == 0) || (cNodeID < 16 && cNodeID > 2) )
					return false;
			}
			break;

			case kHFSPlusFolderRecord:
			{
				if ( recordSize != sizeof(HFSPlusCatalogFolder) )
					return false;
				if ( catalogRecord->hfsPlusFolder.flags != 0 )
					return false;
				if ( catalogRecord->hfsPlusFolder.valence > 0x7FFF )
					return false;
					
				cNodeID = catalogRecord->hfsPlusFolder.folderID;
	
				if ( (cNodeID == 0) || (cNodeID < 16 && cNodeID > 2) )
					return false;
			}
			break;
	
			case kHFSFileRecord:
			{
//				UInt16					i;
				HFSExtentDescriptor	*dataExtent;
				HFSExtentDescriptor	*rsrcExtent;
				
				if ( recordSize != sizeof(HFSCatalogFile) )
					return false;								
				if ( (catalogRecord->hfsFile.flags & ~(0x83)) != 0 )
					return false;
					
				cNodeID = catalogRecord->hfsFile.fileID;
				
				if ( cNodeID < 16 )
					return false;
		
				// make sure 0 ¾ LEOF ¾ PEOF for both forks
				
				if ( catalogRecord->hfsFile.dataLogicalSize < 0 )
					return false;
				if ( catalogRecord->hfsFile.dataPhysicalSize < catalogRecord->hfsFile.dataLogicalSize )
					return false;
				if ( catalogRecord->hfsFile.rsrcLogicalSize < 0 )
					return false;
				if ( catalogRecord->hfsFile.rsrcPhysicalSize < catalogRecord->hfsFile.rsrcLogicalSize )
					return false;
		
				dataExtent = (HFSExtentDescriptor*) &catalogRecord->hfsFile.dataExtents;
				rsrcExtent = (HFSExtentDescriptor*) &catalogRecord->hfsFile.rsrcExtents;
	
#if 0
				for (i = 0; i < kHFSExtentDensity; ++i)
				{
					if ( (dataExtent[i].blockCount > 0) && (dataExtent[i].startBlock == 0) )
						return false;
					if ( (rsrcExtent[i].blockCount > 0) && (rsrcExtent[i].startBlock == 0) )
						return false;
				}
#endif
			}
			break;
	
			case kHFSPlusFileRecord:
			{
//				UInt16					i;
				HFSPlusExtentDescriptor	*dataExtent;
				HFSPlusExtentDescriptor	*rsrcExtent;
				
				if ( recordSize != sizeof(HFSPlusCatalogFile) )
					return false;								
				if ( (catalogRecord->hfsPlusFile.flags & ~(0x83)) != 0 )
					return false;
					
				cNodeID = catalogRecord->hfsPlusFile.fileID;
				
				if ( cNodeID < 16 )
					return false;
		
				// make sure 0 ¾ LEOF ¾ PEOF for both forks
		
				dataExtent = (HFSPlusExtentDescriptor*) &catalogRecord->hfsPlusFile.dataFork.extents;
				rsrcExtent = (HFSPlusExtentDescriptor*) &catalogRecord->hfsPlusFile.resourceFork.extents;
	
#if 0
				for (i = 0; i < kHFSPlusExtentDensity; ++i)
				{
					if ( (dataExtent[i].blockCount > 0) && (dataExtent[i].startBlock == 0) )
						return false;
					if ( (rsrcExtent[i].blockCount > 0) && (rsrcExtent[i].startBlock == 0) )
						return false;
				}
#endif
			}
			break;

			case kHFSFolderThreadRecord:
			case kHFSFileThreadRecord:
			{
				if ( recordSize != sizeof(HFSCatalogThread) )
					return false;
	
				cNodeID = catalogRecord->hfsThread.parentID;
				if ( (cNodeID == 0) || (cNodeID < 16 && cNodeID > 2) )
					return false;
							
				if ( (catalogRecord->hfsThread.nodeName[0] == 0) ||
					 (catalogRecord->hfsThread.nodeName[0] > 31) )
					return false;
			}
			break;
		
			case kHFSPlusFolderThreadRecord:
			case kHFSPlusFileThreadRecord:
			{
				if ( recordSize > sizeof(HFSPlusCatalogThread) || recordSize < (sizeof(HFSPlusCatalogThread) - sizeof(HFSUniStr255)))
					return false;
	
				cNodeID = catalogRecord->hfsPlusThread.parentID;
				if ( (cNodeID == 0) || (cNodeID < 16 && cNodeID > 2) )
					return false;
							
				if ( (catalogRecord->hfsPlusThread.nodeName.length == 0) ||
					 (catalogRecord->hfsPlusThread.nodeName.length > 255) )
					return false;
			}
			break;

			default:
				return false;
		}
	}
	
	return true;	// record appears to be OK
}
