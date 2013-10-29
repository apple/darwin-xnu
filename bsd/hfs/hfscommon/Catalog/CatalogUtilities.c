/*
 * Copyright (c) 2000-2002, 2004-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/utfconv.h>
#include <sys/stat.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <libkern/libkern.h>

#include	"../headers/FileMgrInternal.h"
#include	"../headers/BTreesInternal.h"
#include	"../headers/CatalogPrivate.h"
#include	"../headers/HFSUnicodeWrappers.h"
#include 	"../headers/BTreesPrivate.h"
#include	<string.h>

//
//	Routine:	LocateCatalogNodeByKey
//
// Function: 	Locates the catalog record for an existing folder or file
//				CNode and returns the key and data records.
//

OSErr
LocateCatalogNodeByKey(const ExtendedVCB *volume, u_int32_t hint, CatalogKey *keyPtr,
						CatalogRecord *dataPtr, u_int32_t *newHint)
{
	OSErr				result;
	CatalogName 		*nodeName = NULL;
	HFSCatalogNodeID	threadParentID;
	u_int16_t tempSize;
	FSBufferDescriptor	 btRecord;
	struct BTreeIterator *searchIterator;
	FCB			*fcb;

	MALLOC (searchIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (searchIterator == NULL) {
		return memFullErr;  // translates to ENOMEM
	}

	bzero(searchIterator, sizeof(*searchIterator));

	fcb = GetFileControlBlock(volume->catalogRefNum);

	btRecord.bufferAddress = dataPtr;
	btRecord.itemCount = 1;
	btRecord.itemSize = sizeof(CatalogRecord);

	searchIterator->hint.nodeNum = hint;

	bcopy(keyPtr, &searchIterator->key, sizeof(CatalogKey));
	
	result = BTSearchRecord( fcb, searchIterator, &btRecord, &tempSize, searchIterator );

	if (result == noErr)
	{
		*newHint = searchIterator->hint.nodeNum;

		BlockMoveData(&searchIterator->key, keyPtr, sizeof(CatalogKey));
	}

	if (result == btNotFound) {
		result = cmNotFound;
	}	

	if (result) {
		FREE(searchIterator, M_TEMP);
		return result;
	}
	
	// if we got a thread record, then go look up real record
	switch ( dataPtr->recordType )
	{

#if CONFIG_HFS_STD
		case kHFSFileThreadRecord:
		case kHFSFolderThreadRecord:
			threadParentID = dataPtr->hfsThread.parentID;
			nodeName = (CatalogName *) &dataPtr->hfsThread.nodeName;
			break;
#endif

		case kHFSPlusFileThreadRecord:
		case kHFSPlusFolderThreadRecord:
			threadParentID = dataPtr->hfsPlusThread.parentID;
			nodeName = (CatalogName *) &dataPtr->hfsPlusThread.nodeName;	
			break;

		default:
			threadParentID = 0;
			break;
	}
	
	if ( threadParentID )		// found a thread
		result = LocateCatalogRecord(volume, threadParentID, nodeName, kNoHint, keyPtr, dataPtr, newHint);
	
	FREE (searchIterator, M_TEMP);
	return result;
}



//*******************************************************************************
//	Routine:	LocateCatalogRecord
//
// Function: 	Locates the catalog record associated with folderID and name
//
//*******************************************************************************

OSErr
LocateCatalogRecord(const ExtendedVCB *volume, HFSCatalogNodeID folderID, const CatalogName *name,
					__unused u_int32_t hint, CatalogKey *keyPtr, CatalogRecord *dataPtr, u_int32_t *newHint)
{
	OSErr result;
	uint16_t tempSize;
	FSBufferDescriptor btRecord;
	struct BTreeIterator *searchIterator = NULL;
	FCB *fcb;
	BTreeControlBlock *btcb;

	MALLOC (searchIterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
	if (searchIterator == NULL) {
		return memFullErr;  // translates to ENOMEM
	}

	bzero(searchIterator, sizeof(*searchIterator));


	fcb = GetFileControlBlock(volume->catalogRefNum);
	btcb = (BTreeControlBlock *)fcb->fcbBTCBPtr;
	
	btRecord.bufferAddress = dataPtr;
	btRecord.itemCount = 1;
	btRecord.itemSize = sizeof(CatalogRecord);

	BuildCatalogKey(folderID, name, (volume->vcbSigWord == kHFSPlusSigWord), (CatalogKey *)&searchIterator->key);

	result = BTSearchRecord(fcb, searchIterator, &btRecord, &tempSize, searchIterator);
	if (result == noErr) {
		*newHint = searchIterator->hint.nodeNum;
		BlockMoveData(&searchIterator->key, keyPtr, CalcKeySize(btcb, &searchIterator->key));
	}

	FREE (searchIterator, M_TEMP);
	return (result == btNotFound ? cmNotFound : result);
}



/*
 *	Routine:	BuildCatalogKey
 *
 *	Function: 	Constructs a catalog key record (ckr) given the parent
 *				folder ID and CName.  Works for both classic and extended
 *				HFS volumes.
 *
 */

void
BuildCatalogKey(HFSCatalogNodeID parentID, const CatalogName *cName, Boolean isHFSPlus, CatalogKey *key)
{
	if ( isHFSPlus )
	{
		key->hfsPlus.keyLength			= kHFSPlusCatalogKeyMinimumLength;	// initial key length (4 + 2)
		key->hfsPlus.parentID			= parentID;		// set parent ID
		key->hfsPlus.nodeName.length	= 0;			// null CName length
		if ( cName != NULL )
		{
			CopyCatalogName(cName, (CatalogName *) &key->hfsPlus.nodeName, isHFSPlus);
			key->hfsPlus.keyLength += sizeof(UniChar) * cName->ustr.length;	// add CName size to key length
		}
	}
#if CONFIG_HFS_STD
	else
	{
		key->hfs.keyLength		= kHFSCatalogKeyMinimumLength;	// initial key length (1 + 4 + 1)
		key->hfs.reserved		= 0;				// clear unused byte
		key->hfs.parentID		= parentID;			// set parent ID
		key->hfs.nodeName[0]	= 0;				// null CName length
		if ( cName != NULL )
		{
			UpdateCatalogName(cName->pstr, key->hfs.nodeName);
			key->hfs.keyLength += key->hfs.nodeName[0];		// add CName size to key length
		}
	}
#endif

}

OSErr
BuildCatalogKeyUTF8(ExtendedVCB *volume, HFSCatalogNodeID parentID, const unsigned char *name, u_int32_t nameLength,
		    CatalogKey *key, u_int32_t *textEncoding)
{
	OSErr err = 0;

    if ( name == NULL)
        nameLength = 0;
    else if (nameLength == kUndefinedStrLen)
        nameLength = strlen((const char *)name);

	if ( volume->vcbSigWord == kHFSPlusSigWord ) {
		size_t unicodeBytes = 0;

		key->hfsPlus.keyLength = kHFSPlusCatalogKeyMinimumLength;	// initial key length (4 + 2)
		key->hfsPlus.parentID = parentID;			// set parent ID
		key->hfsPlus.nodeName.length = 0;			// null CName length
		if ( nameLength > 0 ) {
			err = utf8_decodestr(name, nameLength, key->hfsPlus.nodeName.unicode,
				&unicodeBytes, sizeof(key->hfsPlus.nodeName.unicode), ':', UTF_DECOMPOSED);
			key->hfsPlus.nodeName.length = unicodeBytes / sizeof(UniChar);
			key->hfsPlus.keyLength += unicodeBytes;
		}

		if (textEncoding && (*textEncoding != kTextEncodingMacUnicode))
			*textEncoding = hfs_pickencoding(key->hfsPlus.nodeName.unicode,
				key->hfsPlus.nodeName.length);
	}
#if CONFIG_HFS_STD
	else {
		key->hfs.keyLength		= kHFSCatalogKeyMinimumLength;	// initial key length (1 + 4 + 1)
		key->hfs.reserved		= 0;				// clear unused byte
		key->hfs.parentID		= parentID;			// set parent ID
		key->hfs.nodeName[0]	= 0;				// null CName length
		if ( nameLength > 0 ) {
			err = utf8_to_hfs(volume, nameLength, name, &key->hfs.nodeName[0]);
			/*
			 * Retry with MacRoman in case that's how it was exported.
			 * When textEncoding != NULL we know that this is a create
			 * or rename call and can skip the retry (ugly but it works).
			 */
			if (err && (textEncoding == NULL))
				err = utf8_to_mac_roman(nameLength, name, &key->hfs.nodeName[0]);
			key->hfs.keyLength += key->hfs.nodeName[0];		// add CName size to key length
		}
		if (textEncoding)
			*textEncoding = 0;
	}
#endif

	if (err) {
		if (err == ENAMETOOLONG)
			err = bdNamErr;	/* name is too long */
		else
			err = paramErr;	/* name has invalid characters */
	}

	return err;
}


//*******************************************************************************
//	Routine:	FlushCatalog
//
// Function: 	Flushes the catalog for a specified volume.
//
//*******************************************************************************

OSErr
FlushCatalog(ExtendedVCB *volume)
{
	FCB *	fcb;
	OSErr	result;
	struct hfsmount *hfsmp = VCBTOHFS (volume);
	
	fcb = GetFileControlBlock(volume->catalogRefNum);
	result = BTFlushPath(fcb);

	if (result == noErr)
	{
		//--- check if catalog's fcb is dirty...
		
		if ( 0 /*fcb->fcbFlags & fcbModifiedMask*/ )
		{
			hfs_lock_mount (hfsmp);
			MarkVCBDirty(volume);	// Mark the VCB dirty
			volume->vcbLsMod = GetTimeUTC();	// update last modified date
			hfs_unlock_mount (hfsmp);

		//	result = FlushVolumeControlBlock(volume);
		}
	}
	
	return result;
}


//ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Routine:	UpdateCatalogName
//
//	Function: 	Updates a CName.
//
//ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

void
UpdateCatalogName(ConstStr31Param srcName, Str31 destName)
{
	Size length = srcName[0];
	
	if (length > CMMaxCName)
		length = CMMaxCName;				// truncate to max

	destName[0] = length;					// set length byte
	
	BlockMoveData(&srcName[1], &destName[1], length);
}

//_______________________________________________________________________

void
CopyCatalogName(const CatalogName *srcName, CatalogName *dstName, Boolean isHFSPlus)
{
	u_int32_t	length = 0;
	
	if ( srcName == NULL )
	{
		if ( dstName != NULL )
			dstName->ustr.length = 0;	// set length byte to zero (works for both unicode and pascal)		
		return;
	}
	
	if (isHFSPlus) {
		length = sizeof(UniChar) * (srcName->ustr.length + 1);
	}
#if CONFIG_HFS_STD
	else {
		length = sizeof(u_int8_t) + srcName->pstr[0];
	}
#endif

	if ( length > 1 )
		BlockMoveData(srcName, dstName, length);
	else
		dstName->ustr.length = 0;	// set length byte to zero (works for both unicode and pascal)		
}

