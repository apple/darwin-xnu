/*
 * Copyright (c) 2000, 2002, 2005-2013 Apple Inc. All rights reserved.
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

#include "../headers/BTreesPrivate.h"
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <libkern/libkern.h>


// local routines
static OSErr	CheckBTreeKey(const BTreeKey *key, const BTreeControlBlock *btcb);
static Boolean	ValidHFSRecord(const void *record, const BTreeControlBlock *btcb, u_int16_t recordSize);


OSErr ReplaceBTreeRecord(FileReference refNum, const void* key, u_int32_t hint, void *newData, u_int16_t dataSize, u_int32_t *newHint)
{
	FSBufferDescriptor	btRecord;
	struct BTreeIterator *iterator = NULL;
	FCB					*fcb;
	BTreeControlBlock	*btcb;
	OSStatus			result;

	MALLOC (iterator, struct BTreeIterator *, sizeof (struct BTreeIterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		return memFullErr;  //translates to ENOMEM		
	}
	bzero (iterator, sizeof (*iterator));

	fcb = GetFileControlBlock(refNum);
	btcb = (BTreeControlBlock*) fcb->fcbBTCBPtr;

	btRecord.bufferAddress = newData;
	btRecord.itemSize = dataSize;
	btRecord.itemCount = 1;

	iterator->hint.nodeNum = hint;

	result = CheckBTreeKey((const BTreeKey *) key, btcb);
	if (result) {
		goto ErrorExit;
	}

	BlockMoveData(key, &iterator->key, CalcKeySize(btcb, (const BTreeKey *) key));		//€€ should we range check against maxkeylen?

	if ( DEBUG_BUILD && !ValidHFSRecord(newData, btcb, dataSize) )
		DebugStr("ReplaceBTreeRecord: bad record?");

	result = BTReplaceRecord( fcb, iterator, &btRecord, dataSize );

	*newHint = iterator->hint.nodeNum;

ErrorExit:

	FREE (iterator, M_TEMP);
	return result;
}



static OSErr CheckBTreeKey(const BTreeKey *key, const BTreeControlBlock *btcb)
{
	u_int16_t	keyLen;
	
	if ( btcb->attributes & kBTBigKeysMask )
		keyLen = key->length16;
	else
		keyLen = key->length8;

	if ( (keyLen < 6) || (keyLen > btcb->maxKeyLength) )
	{
		if ( DEBUG_BUILD )
			DebugStr("CheckBTreeKey: bad key length!");
		return fsBTInvalidKeyLengthErr;
	}
	
	return noErr;
}


static Boolean ValidHFSRecord(const void *record, const BTreeControlBlock *btcb, u_int16_t recordSize)
{
	u_int32_t			cNodeID;
	
	if (btcb->maxKeyLength == kHFSPlusExtentKeyMaximumLength )
	{
		return ( recordSize == sizeof(HFSPlusExtentRecord) );
	}
#if CONFIG_HFS_STD
	else if ( btcb->maxKeyLength == kHFSExtentKeyMaximumLength )
	{
		return ( recordSize == sizeof(HFSExtentRecord) );
	}
#endif

	else // Catalog record
	{
		const CatalogRecord *catalogRecord = (const CatalogRecord*) record;

		switch(catalogRecord->recordType)
		{

#if CONFIG_HFS_STD
			/*
			 * HFS standard File/folder records and File/Folder Thread records
			 * are only valid on configs that support HFS standard.
			 */
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

			case kHFSFileRecord:
			{
				const HFSExtentDescriptor	*dataExtent;
				const HFSExtentDescriptor	*rsrcExtent;
				
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
		
				dataExtent = (const HFSExtentDescriptor*) &catalogRecord->hfsFile.dataExtents;
				rsrcExtent = (const HFSExtentDescriptor*) &catalogRecord->hfsFile.rsrcExtents;
	
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

			case kHFSFileThreadRecord:
			case kHFSFolderThreadRecord:
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
#endif

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
		
			case kHFSPlusFileRecord:
			{
//				u_int16_t					i;
				const HFSPlusExtentDescriptor	*dataExtent;
				const HFSPlusExtentDescriptor	*rsrcExtent;
				
				if ( recordSize != sizeof(HFSPlusCatalogFile) )
					return false;								
				if ( (catalogRecord->hfsPlusFile.flags & ~(0x83)) != 0 )
					return false;
					
				cNodeID = catalogRecord->hfsPlusFile.fileID;
				
				if ( cNodeID < 16 )
					return false;
		
				// make sure 0 ¾ LEOF ¾ PEOF for both forks
		
				dataExtent = (const HFSPlusExtentDescriptor*) &catalogRecord->hfsPlusFile.dataFork.extents;
				rsrcExtent = (const HFSPlusExtentDescriptor*) &catalogRecord->hfsPlusFile.resourceFork.extents;
	
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

			case kHFSPlusFileThreadRecord:
			case kHFSPlusFolderThreadRecord:
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
