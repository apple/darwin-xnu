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
	File:		CatalogUtilities.c

	Contains:	Private Catalog Manager support routines.

	Version:	HFS Plus 1.0

	Copyright:	© 1997-2000 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Don Brady

		Other Contact:		Mark Day

		Technology:			xxx put technology here xxx

	Writers:

		(DSH)	Deric Horn
		(msd)	Mark Day
		(djb)	Don Brady

	Change History (most recent first):
 	  <MacOSX>	  1/8/99	djb		Fixing LocateCatalogNodeByMangledName...
 	  <MacOSX>	  1/7/99	djb		In BuildCatalogKeyUTF8 check name length against NAME_MAX.
 	  <MacOSX>	 12/7/98	djb		Add ExtractTextEncoding routine to get text encodings.
 	  <MacOSX>	11/20/98	djb		Add support for UTF-8 names.
 	  <MacOSX>	 8/31/98	djb		GetTimeLocal now takes an input.
	  <MacOSX>	 4/17/98	djb		Add VCB locking.
	  <MacOSX>	  4/3/98	djb		Removed last name conversion cache from LocateCatalogNodeWithRetry.
	  <MacOSX>	  4/2/98	djb		InvalidateCatalogNodeCache and TrashCatalogNodeCache are not used in MacOS X.
	  <MacOSX>	03/31/98	djb		Sync up with final HFSVolumes.h header file.

	  <CS24>	 1/29/98	DSH		Add TrashCatalogNodeCache for TrashAllFSCaches API support.
	  <CS23>	12/15/97	djb		Radar #2202860, In LocateCatalogNodeByMangledName remap
									cmParentNotFound error code to cmNotFound.
	  <CS22>	12/10/97	DSH		2201501, Pin the leof and peof to multiple of allocation blocks
									under 2 Gig.
	  <CS21>	 12/9/97	DSH		2201501, Pin returned leof values to 2^31-1 (SInt32), instead of
									2^32-1
	  <CS20>	11/26/97	djb		Radar #2005688, 2005461 - need to handle kTextMalformedInputErr.
	  <CS19>	11/25/97	djb		Radar #2002357 (again) fix new bug introduced in <CS18>.
	  <CS18>	11/17/97	djb		PrepareInputName routine now returns an error.
	  <CS17>	10/19/97	msd		Bug 1684586. GetCatInfo and SetCatInfo use only contentModDate.
	  <CS16>	10/17/97	djb		Add ConvertInputNameToUnicode for Catalog Create/Rename.
	  <CS15>	10/14/97	djb		Fix LocateCatalogNode's MakeFSSpec optimization (radar #1683166)
	  <CS14>	10/13/97	djb		Copy text encoding in CopyCatalogNodeData. Fix cut/paste error
									in VolumeHasEncodings macro. When accessing encoding bitmap use
									the MapEncodingToIndex and MapIndexToEncoding macros.
	  <CS13>	 10/1/97	djb		Remove old Catalog Iterator code...
	  <CS12>	  9/8/97	msd		Make sure a folder's modifyDate is set whenever its
									contentModDate is set.
	  <CS11>	  9/4/97	djb		Add MakeFSSpec optimization.
	  <CS10>	  9/4/97	msd		In CatalogNodeData, change attributeModDate to modifyDate.
	   <CS9>	 8/26/97	djb		Back out <CS4> (UpdateFolderCount must maintain vcbNmFls for HFS
									Plus volumes too).
	   <CS8>	 8/14/97	djb		Remove hard link support.
	   <CS7>	 7/18/97	msd		Include LowMemPriv.h.
	   <CS6>	 7/16/97	DSH		FilesInternal.i renamed FileMgrInternal.i to avoid name
									collision
	   <CS5>	  7/8/97	DSH		Loading PrecompiledHeaders from define passed in on C line
	   <CS4>	 6/27/97	msd		UpdateFolderCount should update number of root files/folders for
									HFS volumes, not HFS Plus.
	   <CS3>	 6/24/97	djb		LocateCatalogNodeWithRetry did not always set result code.
	   <CS2>	 6/24/97	djb		Add LocateCatalogNodeByMangledName routine
	   <CS1>	 6/24/97	djb		first checked in
*/
#include <sys/param.h>
#include <sys/utfconv.h>

#include	"../headers/FileMgrInternal.h"
#include	"../headers/BTreesInternal.h"
#include	"../headers/CatalogPrivate.h"
#include	"../headers/HFSUnicodeWrappers.h"
#include	<string.h>

static void ExtractTextEncoding (ItemCount length, ConstUniCharArrayPtr string, UInt32 * textEncoding);

//*******************************************************************************
//	Routine:	LocateCatalogNode
//
// Function: 	Locates the catalog record for an existing folder or file
//				CNode and returns pointers to the key and data records.
//
//*******************************************************************************

OSErr
LocateCatalogNode(const ExtendedVCB *volume, HFSCatalogNodeID folderID, const CatalogName *name,
					UInt32 hint, CatalogKey *keyPtr, CatalogRecord *dataPtr, UInt32 *newHint)
{
	OSErr				result;
	CatalogName 		*nodeName = NULL;	/* To ward off uninitialized use warnings from compiler */
	HFSCatalogNodeID	threadParentID;


	result = LocateCatalogRecord(volume, folderID, name, hint, keyPtr, dataPtr, newHint);
	ReturnIfError(result);
	
	// if we got a thread record, then go look up real record
	switch ( dataPtr->recordType )
	{
		case kHFSFileThreadRecord:
		case kHFSFolderThreadRecord:
			threadParentID = dataPtr->hfsThread.parentID;
			nodeName = (CatalogName *) &dataPtr->hfsThread.nodeName;
			break;

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
	
	return result;
}

//
//	Routine:	LocateCatalogNodeByKey
//
// Function: 	Locates the catalog record for an existing folder or file
//				CNode and returns the key and data records.
//

OSErr
LocateCatalogNodeByKey(const ExtendedVCB *volume, UInt32 hint, CatalogKey *keyPtr,
						CatalogRecord *dataPtr, UInt32 *newHint)
{
	OSErr				result;
	CatalogName 		*nodeName = NULL;	/* To ward off uninitialized use warnings from compiler */
	HFSCatalogNodeID	threadParentID;
	UInt16 tempSize;


	result = SearchBTreeRecord(volume->catalogRefNum, keyPtr, hint, keyPtr,
								dataPtr, &tempSize, newHint);
	if (result == btNotFound)
		result = cmNotFound;	
	ReturnIfError(result);
	
	// if we got a thread record, then go look up real record
	switch ( dataPtr->recordType )
	{
		case kHFSFileThreadRecord:
		case kHFSFolderThreadRecord:
			threadParentID = dataPtr->hfsThread.parentID;
			nodeName = (CatalogName *) &dataPtr->hfsThread.nodeName;
			break;

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
	
	return result;
}


#if 0
//*******************************************************************************
//	Routine:	LocateCatalogNodeWithRetry
//
// Function: 	Locates the catalog record for an existing folder or file node.
//				For HFS Plus volumes a retry is performed when a catalog node is
//				not found and the volume contains more than one text encoding.
//
//ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ

#define VolumeHasEncodings(v) \
	( ((v)->encodingsBitmap != 0 )

#define	EncodingInstalled(i) \
	( (fsVars)->gConversionContext[(i)].toUnicode != 0 )

#define	EncodingUsedByVolume(v,i) \
	( ((v)->encodingsBitmap & (1 << (i))) )


OSErr
LocateCatalogNodeWithRetry (const ExtendedVCB *volume, HFSCatalogNodeID folderID, ConstStr31Param pascalName, CatalogName *unicodeName,
							UInt32 hint, CatalogKey *keyPtr, CatalogRecord *dataPtr, UInt32 *newHint)
{
	TextEncoding		defaultEncoding;
	TextEncoding		encoding;
	ItemCount			encodingsToTry;
	FSVarsRec			*fsVars;
	OSErr				result = cmNotFound;

	fsVars = (FSVarsRec*) LMGetFSMVars();	// used by macros

	defaultEncoding = GetDefaultTextEncoding();
	encodingsToTry = CountInstalledEncodings();

	// 1. Try finding file using default encoding (typical case)

	{
		--encodingsToTry;
		result = PrepareInputName(pascalName, true, defaultEncoding, unicodeName);
		if (result == noErr)
			result = LocateCatalogNode(volume, folderID, unicodeName, hint, keyPtr, dataPtr, newHint);
		else
			result = cmNotFound;

		if ( result != cmNotFound || encodingsToTry == 0)
			return result;
	}

	//
	// XXX if the pascal string contains all 7-bit ascii then we don't need to do anymore retries
	//

	// 2. Try finding file using Mac Roman (if not already tried above)

	if ( defaultEncoding != kTextEncodingMacRoman )
	{
		--encodingsToTry;
		result = PrepareInputName(pascalName, true, kTextEncodingMacRoman, unicodeName);
		if (result == noErr)
			result = LocateCatalogNode(volume, folderID, unicodeName, hint, keyPtr, dataPtr, newHint);
		else
			result = cmNotFound;

		if ( result != cmNotFound || encodingsToTry == 0 )
			return result;
	}

	// 3. Try with encodings from disk (if any)

	if ( VolumeHasEncodings(volume) )	// any left to try?
	{
		UInt32	index;

		index = 0;	// since we pre increment this will skip MacRoman (which was already tried above)

		while ( index < kMacBaseEncodingCount )
		{
			++index;
			
			encoding = MapIndexToEncoding(index);

			if ( encoding == defaultEncoding )
				continue;		// we did this one already

			if ( EncodingInstalled(index) && EncodingUsedByVolume(volume, index) )
			{
				--encodingsToTry;
				result = PrepareInputName(pascalName, true, encoding, unicodeName);
				if (result == noErr)
					result = LocateCatalogNode(volume, folderID, unicodeName, hint, keyPtr, dataPtr, newHint);
				else
					result = cmNotFound;

				if ( result != cmNotFound || encodingsToTry == 0 )
					return result;
			}
		}
	}

	// 4. Try any remaining encodings (if any)

	{
		UInt32	index;

		index = 0;	// since we pre increment this will skip MacRoman (which was already tried above)
	
		while ( (encodingsToTry > 0) && (index < kMacBaseEncodingCount) )
		{
			++index;
	
			encoding = MapIndexToEncoding(index);
	
			if ( encoding == defaultEncoding )
				continue;		// we did this one already
	
			if ( EncodingInstalled(index) && EncodingUsedByVolume(volume, index) == false )
			{
				--encodingsToTry;
				result = PrepareInputName(pascalName, true, encoding, unicodeName);
				if (result == noErr)
					result = LocateCatalogNode(volume, folderID, unicodeName, hint, keyPtr, dataPtr, newHint);
				else
					result = cmNotFound;

				if ( result != cmNotFound || encodingsToTry == 0 )
					return result;
			}
		}
	}

	return cmNotFound;
}
#endif

//*******************************************************************************
//	Routine:	LocateCatalogNodeByMangledName
//
// Function: 	Locates the catalog record associated with a mangled name (if any)
//
//*******************************************************************************
#define kMaxCompareLen		64		/* If it compares this far...lets believe it */

OSErr
LocateCatalogNodeByMangledName( const ExtendedVCB *volume, HFSCatalogNodeID folderID,
								const unsigned char * name, UInt32 length, CatalogKey *keyPtr,
								CatalogRecord *dataPtr, UInt32 *hintPtr )
{
	HFSCatalogNodeID 	fileID;
	unsigned char		nodeName[kMaxCompareLen+1];
	OSErr				result;
	size_t			actualDstLen;
	ByteCount			prefixlen;


	if (name == NULL || name[0] == '\0')
		return cmNotFound;

	fileID = GetEmbeddedFileID(name, length, &prefixlen);

	if ( fileID < kHFSFirstUserCatalogNodeID )
		return cmNotFound;
		
	result = LocateCatalogNode(volume, fileID, NULL, kNoHint, keyPtr, dataPtr, hintPtr);
	if ( result == cmParentNotFound )	// GetCatalogNode already handled cmParentNotFound case 	<CS23>
		result = cmNotFound;			// so remap													<CS23>
	ReturnIfError(result);
		
	// first make sure that the parents match
	if ( folderID != keyPtr->hfsPlus.parentID )
		return cmNotFound;			// not the same folder so this is a false match

	(void) utf8_encodestr(keyPtr->hfsPlus.nodeName.unicode,
			keyPtr->hfsPlus.nodeName.length * sizeof (UniChar),
			nodeName, &actualDstLen, kMaxCompareLen+1, ':', 0);

	prefixlen = min(prefixlen, kMaxCompareLen);
	
	if ((prefixlen - actualDstLen) < 6)
		prefixlen = actualDstLen;	/* To take into account UTF8 rounding */
		
	if ( (actualDstLen < prefixlen) || bcmp(nodeName, name, prefixlen-6) != 0)
		return cmNotFound;	// mangled names didn't match so this is a false match
	
	return noErr;	// we found it
}


//*******************************************************************************
//	Routine:	LocateCatalogRecord
//
// Function: 	Locates the catalog record associated with folderID and name
//
//*******************************************************************************

OSErr
LocateCatalogRecord(const ExtendedVCB *volume, HFSCatalogNodeID folderID, const CatalogName *name,
					UInt32 hint, CatalogKey *keyPtr, CatalogRecord *dataPtr, UInt32 *newHint)
{
	OSErr			result;
	CatalogKey		tempKey;	// 518 bytes
	UInt16			tempSize;

	BuildCatalogKey(folderID, name, (volume->vcbSigWord == kHFSPlusSigWord), &tempKey);

	if ( name == NULL )
		hint = kNoHint;			// no CName given so clear the hint

	result = SearchBTreeRecord(volume->catalogRefNum, &tempKey, hint, keyPtr, dataPtr, &tempSize, newHint);
	
	return (result == btNotFound ? cmNotFound : result);	
}


//*******************************************************************************
//	Routine:	LocateCatalogThread
//
//	Function: 	Locates a catalog thread record in the catalog BTree file and 
//				returns a pointer to the data record.
//
//*******************************************************************************

OSErr
LocateCatalogThread(const ExtendedVCB *volume, HFSCatalogNodeID nodeID, CatalogRecord *threadData, UInt16 *threadSize, UInt32 *threadHint)
{
	CatalogKey	threadKey;	// 518 bytes
	OSErr		result;

	//--- build key record

	BuildCatalogKey(nodeID, NULL, (volume->vcbSigWord == kHFSPlusSigWord), &threadKey);

	//--- locate thread record in BTree

	result = SearchBTreeRecord( volume->catalogRefNum, &threadKey, kNoHint, &threadKey,
								threadData, threadSize, threadHint);
	
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
}

/*
 * for HFS, only MacRoman is supported. If a non-MacRoman character is found, an error is returned
 */
OSErr
BuildCatalogKeyUTF8(ExtendedVCB *volume, HFSCatalogNodeID parentID, const char *name, UInt32 nameLength,
		    CatalogKey *key, UInt32 *textEncoding)
{
	OSErr err = 0;

    if ( name == NULL)
        nameLength = 0;
    else if (nameLength == kUndefinedStrLen)
        nameLength = strlen(name);

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

		if (textEncoding)
		ExtractTextEncoding(key->hfsPlus.nodeName.length, key->hfsPlus.nodeName.unicode, textEncoding);
	}
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

	if (err) {
		if (err == ENAMETOOLONG)
			err = bdNamErr;	/* name is too long */
		else
			err = paramErr;	/* name has invalid characters */
	}

	return err;
}


/*
 * make a guess at the text encoding value that coresponds to the Unicode characters
 */
static void
ExtractTextEncoding(ItemCount length, ConstUniCharArrayPtr string, UInt32 * textEncoding)
{
	int i;
	UniChar ch;

	*textEncoding = 0;

	for (i = 0; i < length; ++i) {
		ch = string[i];
		/* CJK codepoints are 0x3000 thru 0x9FFF */
		if (ch >= 0x3000) {
			if (ch < 0xa000) {
				*textEncoding = kTextEncodingMacJapanese;
				break;
			}

			/* fullwidth character codepoints are 0xFF00 thru 0xFFEF */
			if (ch >= 0xff00 && ch <= 0xffef) {
				*textEncoding = kTextEncodingMacJapanese;
				break;	
			}
		}
	}
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
	
	fcb = GetFileControlBlock(volume->catalogRefNum);
	result = BTFlushPath(fcb);

	if (result == noErr)
	{
		//--- check if catalog's fcb is dirty...
		
		if ( fcb->fcbFlags & fcbModifiedMask )
		{
			VCB_LOCK(volume);
			volume->vcbFlags |= 0xFF00;		// Mark the VCB dirty
			volume->vcbLsMod = GetTimeUTC();	// update last modified date
			VCB_UNLOCK(volume);

			result = FlushVolumeControlBlock(volume);
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


//*******************************************************************************
//	Routine:	AdjustVolumeCounts
//
//	Function: 	Adjusts the folder and file counts in the VCB
//
//*******************************************************************************

void
AdjustVolumeCounts(ExtendedVCB *volume, SInt16 type, SInt16 delta)
{
	//€€ also update extended VCB fields...

	VCB_LOCK(volume);

	if (type == kHFSFolderRecord || type == kHFSPlusFolderRecord)
		volume->vcbDirCnt += delta;			// adjust volume folder count, €€ worry about overflow?
	else
		volume->vcbFilCnt += delta;			// adjust volume file count
	
	volume->vcbFlags |= 0xFF00;		// Mark the VCB dirty
	volume->vcbLsMod = GetTimeUTC();	// update last modified date

	VCB_UNLOCK(volume);
}


//*******************************************************************************

void
UpdateVolumeEncodings(ExtendedVCB *volume, TextEncoding encoding)
{
	UInt32	index;

	encoding &= 0x7F;
	
	index = MapEncodingToIndex(encoding);

	VCB_LOCK(volume);

	volume->encodingsBitmap |= (1 << index);

	VCB_UNLOCK(volume);
		
	// vcb should already be marked dirty
}


//*******************************************************************************

OSErr
UpdateFolderCount( ExtendedVCB *volume, HFSCatalogNodeID parentID, const CatalogName *name, SInt16 newType,
					UInt32 hint, SInt16 valenceDelta)
{
	CatalogKey			tempKey;	// 518 bytes
	CatalogRecord		tempData;	// 520 bytes
	UInt32				tempHint;
	HFSCatalogNodeID	folderID;
	UInt16				recordSize;
	OSErr				result;

#if 0
	result = SearchBTreeRecord(volume->catalogRefNum, parentKey, hint,
								&tempKey, &tempData, &recordSize, &tempHint);
	if (result)
		return (result == btNotFound ? cmNotFound : result);	
#else

	result = LocateCatalogNode(volume, parentID, name, hint, &tempKey, &tempData, &tempHint);
	ReturnIfError(result);
#endif

	if ( volume->vcbSigWord == kHFSPlusSigWord ) // HFS Plus
	{
		UInt32		timeStamp;
		
		if ( DEBUG_BUILD && tempData.recordType != kHFSPlusFolderRecord )
			DebugStr("\p UpdateFolder: found HFS folder on HFS+ volume!");

		timeStamp = GetTimeUTC();
		/* adjust valence, but don't go negative */
		if (valenceDelta > 0)
			tempData.hfsPlusFolder.valence += valenceDelta;
		else if (tempData.hfsPlusFolder.valence != 0)
			tempData.hfsPlusFolder.valence += valenceDelta;
		else
			volume->vcbFlags |= kHFS_DamagedVolume;
		tempData.hfsPlusFolder.contentModDate = timeStamp;	// set date/time last modified
		folderID = tempData.hfsPlusFolder.folderID;
		recordSize = sizeof(tempData.hfsPlusFolder);
	}
	else // classic HFS
	{
		if ( DEBUG_BUILD && tempData.recordType != kHFSFolderRecord )
			DebugStr("\p UpdateFolder: found HFS+ folder on HFS volume!");

		/* adjust valence, but don't go negative */
		if (valenceDelta > 0)
			tempData.hfsFolder.valence += valenceDelta;
		else if (tempData.hfsFolder.valence != 0)
			tempData.hfsFolder.valence += valenceDelta;
		else
			volume->vcbFlags |= kHFS_DamagedVolume;
		tempData.hfsFolder.modifyDate = GetTimeLocal(true);		// set date/time last modified
		folderID = tempData.hfsFolder.folderID;
		recordSize = sizeof(tempData.hfsFolder);
	}
	
	result = ReplaceBTreeRecord(volume->catalogRefNum, &tempKey, tempHint,
								&tempData, recordSize, &tempHint);
	ReturnIfError(result);

	if ( folderID == kHFSRootFolderID )
	{
		if (newType == kHFSFolderRecord || newType == kHFSPlusFolderRecord)
		{
			VCB_LOCK(volume);
			volume->vcbNmRtDirs += valenceDelta;	// adjust root folder count (undefined for HFS Plus)
			VCB_UNLOCK(volume);
		}
		else
		{
			VCB_LOCK(volume);
			volume->vcbNmFls += valenceDelta;		// adjust root file count (used by GetVolInfo)
			VCB_UNLOCK(volume);
		}
	}

	//XXX also update extended VCB fields...

	return result;
}


//*******************************************************************************

UInt16	
GetCatalogRecordSize(const CatalogRecord *dataRecord)
{
	switch (dataRecord->recordType)
	{
		case kHFSFileRecord:
			return sizeof(HFSCatalogFile);

		case kHFSFolderRecord:
			return sizeof(HFSCatalogFolder);

		case kHFSPlusFileRecord:
			return sizeof(HFSPlusCatalogFile);

		case kHFSPlusFolderRecord:
			return sizeof(HFSPlusCatalogFolder);
			
		case kHFSFolderThreadRecord:
		case kHFSFileThreadRecord:
			return sizeof(HFSCatalogThread);

		case kHFSPlusFolderThreadRecord:
		case kHFSPlusFileThreadRecord:
			return sizeof(HFSPlusCatalogThread);

		default:
			return 0;
	}
}


//*******************************************************************************

void
CopyCatalogNodeData(const ExtendedVCB *volume, const CatalogRecord *dataPtr, CatalogNodeData *nodeData)
{
	/* convert classic hfs records to hfs plus format */

	if (dataPtr->recordType == kHFSFolderRecord) {
		nodeData->cnd_type = kCatalogFolderNode;
		nodeData->cnd_flags = dataPtr->hfsFolder.flags;
		nodeData->cnd_nodeID = dataPtr->hfsFolder.folderID;
		nodeData->cnd_createDate = LocalToUTC(dataPtr->hfsFolder.createDate);
		nodeData->cnd_contentModDate = LocalToUTC(dataPtr->hfsFolder.modifyDate);
		nodeData->cnd_backupDate = LocalToUTC(dataPtr->hfsFolder.backupDate);
		nodeData->cnd_valence = dataPtr->hfsFolder.valence;

		BlockMoveData(&dataPtr->hfsFolder.userInfo, &nodeData->cnd_finderInfo, 32);
	} else if (dataPtr->recordType == kHFSFileRecord) {
			UInt32	i;

		nodeData->cnd_type = kCatalogFileNode;
		nodeData->cnd_flags = dataPtr->hfsFile.flags;
		nodeData->cnd_nodeID = dataPtr->hfsFile.fileID;
		nodeData->cnd_createDate = LocalToUTC(dataPtr->hfsFile.createDate);
		nodeData->cnd_contentModDate = LocalToUTC(dataPtr->hfsFile.modifyDate);
		nodeData->cnd_backupDate = LocalToUTC(dataPtr->hfsFile.backupDate);
		nodeData->cnd_linkCount = 0;

		BlockMoveData(&dataPtr->hfsFile.userInfo, &nodeData->cnd_finderInfo, 16);
		BlockMoveData(&dataPtr->hfsFile.finderInfo, (void*)((UInt32)&nodeData->cnd_finderInfo + 16), 16);

		nodeData->cnd_datafork.logicalSize = dataPtr->hfsFile.dataLogicalSize;
		nodeData->cnd_datafork.totalBlocks =
			dataPtr->hfsFile.dataPhysicalSize / volume->blockSize;

		nodeData->cnd_rsrcfork.logicalSize  = dataPtr->hfsFile.rsrcLogicalSize;
		nodeData->cnd_rsrcfork.totalBlocks =
			dataPtr->hfsFile.rsrcPhysicalSize / volume->blockSize;

		for (i = 0; i < kHFSExtentDensity; ++i) {
			nodeData->cnd_datafork.extents[i].startBlock =
				(UInt32) (dataPtr->hfsFile.dataExtents[i].startBlock);

			nodeData->cnd_datafork.extents[i].blockCount =
				(UInt32) (dataPtr->hfsFile.dataExtents[i].blockCount);

			nodeData->cnd_rsrcfork.extents[i].startBlock =
				(UInt32) (dataPtr->hfsFile.rsrcExtents[i].startBlock);

			nodeData->cnd_rsrcfork.extents[i].blockCount =
				(UInt32) (dataPtr->hfsFile.rsrcExtents[i].blockCount);
		}
		for (i = kHFSExtentDensity; i < kHFSPlusExtentDensity; ++i) {
			nodeData->cnd_datafork.extents[i].startBlock = 0;
			nodeData->cnd_datafork.extents[i].blockCount = 0;
			nodeData->cnd_rsrcfork.extents[i].startBlock = 0;
			nodeData->cnd_rsrcfork.extents[i].blockCount = 0;
		}
	} else {
		nodeData->cnd_type = 0;
	}
}


//_______________________________________________________________________

void
CopyCatalogName(const CatalogName *srcName, CatalogName *dstName, Boolean isHFSPLus)
{
	UInt32	length;
	
	if ( srcName == NULL )
	{
		if ( dstName != NULL )
			dstName->ustr.length = 0;	// set length byte to zero (works for both unicode and pascal)		
		return;
	}
	
	if (isHFSPLus)
		length = sizeof(UniChar) * (srcName->ustr.length + 1);
	else
		length = sizeof(UInt8) + srcName->pstr[0];

	if ( length > 1 )
		BlockMoveData(srcName, dstName, length);
	else
		dstName->ustr.length = 0;	// set length byte to zero (works for both unicode and pascal)		
}

//_______________________________________________________________________

UInt32
CatalogNameLength(const CatalogName *name, Boolean isHFSPlus)
{
	if (isHFSPlus)
		return name->ustr.length;
	else
		return name->pstr[0];
}



