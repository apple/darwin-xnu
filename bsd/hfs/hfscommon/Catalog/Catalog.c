/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

#pragma segment Catalog

#include <sys/param.h>
#include <sys/utfconv.h>

#include	"../../hfs_endian.h"

#include	"../headers/FileMgrInternal.h"
#include	"../headers/BTreesInternal.h"
#include	"../headers/CatalogPrivate.h"
#include	"../headers/HFSUnicodeWrappers.h"


// External routines

extern SInt32 FastRelString( ConstStr255Param str1, ConstStr255Param str2 );


//_________________________________________________________________________________
//	Exported Routines
//
//		CompareCatalogKeys  -  Compares two catalog keys.
//
//_________________________________________________________________________________



UInt32
GetDirEntrySize(BTreeIterator *bip, ExtendedVCB * vol)
{
	CatalogKey *	ckp;
	CatalogName *	cnp;
	ByteCount	utf8chars;
	UInt8		name[kdirentMaxNameBytes + 1];
	OSErr		result;

	ckp = (CatalogKey*) &bip->key;

	if (vol->vcbSigWord == kHFSPlusSigWord) {
		cnp = (CatalogName*) &ckp->hfsPlus.nodeName;
		utf8chars = utf8_encodelen(cnp->ustr.unicode,
				    cnp->ustr.length * sizeof(UniChar), ':', 0);
		if (utf8chars > kdirentMaxNameBytes)
			utf8chars = kdirentMaxNameBytes;
	} else { /* hfs */
		cnp = (CatalogName*) ckp->hfs.nodeName;
		result = hfs_to_utf8(vol, cnp->pstr, kdirentMaxNameBytes + 1,
				&utf8chars, name);
		if (result) {
			/*
			 * When an HFS name cannot be encoded with the current
			 * volume encoding we use MacRoman as a fallback.
			 */
			result = mac_roman_to_utf8(cnp->pstr, MAXHFSVNODELEN + 1,
					                           &utf8chars, name);
		}
	}

	return DIRENTRY_SIZE(utf8chars);
}
/*
 * NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  NOTE  
 * 
 * This is assuming maxinum size of a name is 255 (kdirentMaxNameBytes), which is incorrect.
 * Any caller of this has to make sure names > 255 are mangled!!!!!!!!
 */

OSErr
PositionIterator(CatalogIterator *cip, UInt32 offset, BTreeIterator *bip, UInt16 *op)
{
#define CAT_START_OFFSET (2 * sizeof(struct hfsdotentry))
	ExtendedVCB *	vol;
	FCB *		fcb;
	OSErr		result = 0;

	/* are we past the end of a directory? */
	if (cip->folderID != cip->parentID)
		return(cmNotFound);

	vol = cip->volume;
	fcb = GetFileControlBlock(vol->catalogRefNum);

	/* make a btree iterator from catalog iterator */
	UpdateBtreeIterator(cip, bip);

	if (cip->currentOffset == offset) {
		*op = kBTreeCurrentRecord;

	} else if (cip->nextOffset == offset) {
		*op = kBTreeNextRecord;

	} else { /* start from beginning */
		*op = kBTreeNextRecord;

		/* Position iterator at the folder's thread record */
		result = BTSearchRecord(fcb, bip, NULL, NULL, bip);
		if (result)
			goto exit;
		
		/* find offset (note: n^2 / 2) */
		if (offset > CAT_START_OFFSET) { 
			HFSCatalogNodeID  pid, *idp;
			UInt32	curOffset, nextOffset;

			/* get first record (ie offset 24) */
			result = BTIterateRecord( fcb, kBTreeNextRecord, bip, NULL, NULL );		
			if (result)
				goto exit;

			if (vol->vcbSigWord == kHFSPlusSigWord)
				idp = &((CatalogKey*) &bip->key)->hfsPlus.parentID;
			else
				idp = &((CatalogKey*) &bip->key)->hfs.parentID;
			
			pid = *idp;

			curOffset = CAT_START_OFFSET;
	 		nextOffset = CAT_START_OFFSET + GetDirEntrySize(bip, vol);

			while (nextOffset < offset) {
				result = BTIterateRecord( fcb, kBTreeNextRecord, bip, NULL, NULL );		
				if (result)
					goto exit;
				
				/* check for parent change */
				if (pid != *idp) {
					result = cmNotFound;	/* offset past end of directory */
					goto exit;
				}

				curOffset = nextOffset;
				nextOffset += GetDirEntrySize(bip, vol);
			};
	
			if (nextOffset != offset) {
				result = cmNotFound;
				goto exit;
			}
	
			UpdateCatalogIterator(bip, cip);
			cip->currentOffset = curOffset;
			cip->nextOffset = nextOffset;
		}
	}

exit:	
	if (result == btNotFound)
		result = cmNotFound;

	return result;

} /* end PositionIterator */


//_________________________________________________________________________________
//	Routine:	CompareCatalogKeys
//
//	Function: 	Compares two catalog keys (a search key and a trial key).
//
// 	Result:		+n  search key > trial key
//				 0  search key = trial key
//				-n  search key < trial key
//_________________________________________________________________________________

SInt32
CompareCatalogKeys(HFSCatalogKey *searchKey, HFSCatalogKey *trialKey)
{
	HFSCatalogNodeID	searchParentID, trialParentID;
	SInt32	result;

	searchParentID = searchKey->parentID;
	trialParentID = trialKey->parentID;

	if ( searchParentID > trialParentID ) 	// parent dirID is unsigned
		result = 1;
	else if ( searchParentID < trialParentID )
		result = -1;
	else // parent dirID's are equal, compare names
		result = FastRelString(searchKey->nodeName, trialKey->nodeName);

	return result;
}


//_________________________________________________________________________________
//	Routine:	CompareExtendedCatalogKeys
//
//	Function: 	Compares two large catalog keys (a search key and a trial key).
//
// 	Result:		+n  search key > trial key
//				 0  search key = trial key
//				-n  search key < trial key
//_________________________________________________________________________________

SInt32
CompareExtendedCatalogKeys(HFSPlusCatalogKey *searchKey, HFSPlusCatalogKey *trialKey)
{
	SInt32			result;
	HFSCatalogNodeID	searchParentID, trialParentID;

	searchParentID = searchKey->parentID;
	trialParentID = trialKey->parentID;
	
	if ( searchParentID > trialParentID ) 	// parent node IDs are unsigned
	{
		result = 1;
	}
	else if ( searchParentID < trialParentID )
	{
		result = -1;
	}
	else // parent node ID's are equal, compare names
	{
		if ( searchKey->nodeName.length == 0 || trialKey->nodeName.length == 0 )
			result = searchKey->nodeName.length - trialKey->nodeName.length;
		else
			result = FastUnicodeCompare(&searchKey->nodeName.unicode[0], searchKey->nodeName.length,
										&trialKey->nodeName.unicode[0], trialKey->nodeName.length);
	}

	return result;
}

