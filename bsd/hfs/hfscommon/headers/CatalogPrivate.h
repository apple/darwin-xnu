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
	File:		CatalogPrivate.h

	Contains:	Private Catalog Manager interfaces.

	Version:	HFS Plus 1.0

	Copyright:	© 1997-1998 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Don Brady

		Other Contact:		xxx put other contact here xxx

		Technology:			xxx put technology here xxx

	Writers:

		(JL)	Jim Luther
		(msd)	Mark Day
		(DSH)	Deric Horn
		(djb)	Don Brady

	Change History (most recent first):
	  <MacOSX>	 11/10/98	djb		Remove obsolete PrepareInputName prototype;
	  <MacOSX>	  4/6/98	djb		Added lock data stuctures and ReleaseCatalogIterator prototype;
	  <MacOSX>	  4/6/98	djb		Removed CatalogDataCache since its no longer used.
	  <MacOSX>	  4/2/98	djb		InvalidateCatalogNodeCache does nothing under MacOS X.
	  <MacOSX>	 3/31/98	djb		Sync up with final HFSVolumes.h header file.

	  <CS10>	11/20/97	djb		Radar #2002357. Fixing retry mechanism.
	   <CS9>	11/17/97	djb		PrepareInputName routine now returns an error.
	   <CS8>	11/13/97	djb		Radar #1683572. Move CatalogIterator to this file from
									FileMgrInternal.i. Double size of short unicode name.
	   <CS7>	10/31/97	JL		#2000184 - Changed prototypes for CreateFileThreadID and
									ExchangeFiles.
	   <CS6>	10/17/97	msd		In CatalogCacheGlobals, add room for a single UniStr255 so
									catalog iterators can step over long Unicode names.
	   <CS5>	10/17/97	djb		Add ConvertInputNameToUnicode for Catalog Create/Rename.
	   <CS4>	 10/1/97	djb		Change catalog iterator implementation.
	   <CS3>	 7/16/97	DSH		FilesInternal.i renamed FileMgrInternal.i to avoid name
									collision
	   <CS2>	 6/24/97	djb		Add LocateCatalogNodeByMangledName routine.
	   <CS1>	 6/24/97	djb		first checked in
*/

#ifndef	__CATALOGPRIVATE__
#define __CATALOGPRIVATE__

#include "../../hfs_format.h"

#include	"FileMgrInternal.h"
#include	"BTreesInternal.h"

	#include <sys/lock.h>

// private catalog data cache



enum {
	kCatalogIteratorCount = 16		// total number of Catalog iterators (shared by all HFS/HFS Plus volumes)
};


// Catalog Iterator Name Types
enum {
	kShortPascalName,
	kShortUnicodeName,
	kLongUnicodeName	// non-local name
};


// short unicode name (used by CatalogIterator)
struct UniStr63 {
	UInt16		length;			/* number of unicode characters */
	UniChar		unicode[63];		/* unicode characters */
};
typedef struct UniStr63 UniStr63;


struct CatalogIterator
{
	struct CatalogIterator *nextMRU;	// next iterator in MRU order
	struct CatalogIterator *nextLRU;	// next iterator in LRU order

	ExtendedVCB		*volume;
	SInt16			currentIndex;
	SInt16			reserved;
	UInt32			currentOffset;
	UInt32			nextOffset;
	HFSCatalogNodeID	folderID;

	UInt32			btreeNodeHint;	// node the key was last seen in
	UInt16			btreeIndexHint;	// index the key was last seen at
	UInt16			nameType;	// { 0 = Pascal, 1 = Unicode, 3 = long name}
	HFSCatalogNodeID	parentID;	// parent folder ID
	union
	{
		Str31		pascalName;
		UniStr63	unicodeName;
		HFSUniStr255 *	longNamePtr;
	} folderName;

	struct lock__bsd__	iterator_lock;
};
typedef struct CatalogIterator CatalogIterator;


struct CatalogCacheGlobals {
	UInt32			iteratorCount;	// Number of iterators in cache
	CatalogIterator *	mru;
	CatalogIterator *	lru;
	UInt32			reserved;
	HFSUniStr255		longName;	// used by a single kLongUnicodeName iterator

	simple_lock_data_t	simplelock;
};
typedef struct CatalogCacheGlobals CatalogCacheGlobals;


//
// Private Catalog Manager Routines (for use only by Catalog Manager, CatSearch and FileID Services)
//

extern	OSErr	LocateCatalogThread( const ExtendedVCB *volume, HFSCatalogNodeID nodeID, CatalogRecord *threadData,
									 UInt16 *threadSize, UInt32 *threadHint);

extern	OSErr	LocateCatalogNode(	const ExtendedVCB *volume, HFSCatalogNodeID folderID, const CatalogName *name,
									UInt32 hint, CatalogKey *key, CatalogRecord *data, UInt32 *newHint);

extern OSErr	LocateCatalogNodeByKey ( const ExtendedVCB *volume, UInt32 hint, CatalogKey *keyPtr,
										 CatalogRecord *dataPtr, UInt32 *newHint );

extern OSErr	LocateCatalogRecord( const ExtendedVCB *volume, HFSCatalogNodeID folderID, const CatalogName *name,
									 UInt32 hint, CatalogKey *keyPtr, CatalogRecord *dataPtr, UInt32 *newHint);

extern OSErr	LocateCatalogNodeWithRetry ( const ExtendedVCB *volume, HFSCatalogNodeID folderID, ConstStr31Param pascalName,
											 CatalogName *unicodeName, UInt32 hint, CatalogKey *keyPtr, CatalogRecord *dataPtr,
											 UInt32 *newHint );

extern OSErr	LocateCatalogNodeByMangledName( const ExtendedVCB *volume, HFSCatalogNodeID folderID, 
				ConstStr31Param name, UInt32 length,
				CatalogKey *keyPtr, CatalogRecord *dataPtr, UInt32 *hintPtr );

extern OSErr	FlushCatalog( ExtendedVCB *volume);

#define			InvalidateCatalogNodeCache(v, pid)

extern OSErr	UpdateFolderCount( ExtendedVCB *volume, HFSCatalogNodeID parentID, const CatalogName *name, SInt16 newType,
								   UInt32 hint, SInt16 valenceDelta);

extern UInt16	GetCatalogRecordSize( const CatalogRecord *dataRecord);

extern void		ConvertInputNameToUnicode(ConstStr31Param name, TextEncoding encodingHint,
										  TextEncoding *actualEncoding, CatalogName *catalogName);

extern	void	BuildCatalogKey( HFSCatalogNodeID parentID, const CatalogName *name, Boolean isHFSPlus,
								 CatalogKey *key);

extern	OSErr	BuildCatalogKeyUTF8(ExtendedVCB *volume, HFSCatalogNodeID parentID, const char *name,
				    UInt32 length, CatalogKey *key, UInt32 *textEncoding);

extern	void	UpdateCatalogName( ConstStr31Param srcName, Str31 destName);

extern UInt32	CatalogNameLength( const CatalogName *name, Boolean isHFSPlus);

extern void		CopyCatalogName( const CatalogName *srcName, CatalogName *dstName, Boolean isHFSPLus);

extern OSErr	ResolveFileID( ExtendedVCB *vcb, HFSCatalogNodeID fileID, HFSCatalogNodeID *parentID, Str31 name );

#if 0
extern OSErr	CreateFileThreadID( FIDParam *filePB, WDCBRecPtr *wdcbPtr );

extern OSErr	ExchangeFiles( FIDParam *filePB, WDCBRecPtr *wdcbPtr );
#endif 

extern void		CopyCatalogNodeData( const ExtendedVCB *volume, const CatalogRecord *dataPtr, CatalogNodeData *nodeData);

extern void		UpdateVolumeEncodings( ExtendedVCB *volume, TextEncoding encoding);

extern void		AdjustVolumeCounts( ExtendedVCB *volume, SInt16 type, SInt16 delta );


// Catalog Iterator Routines

extern CatalogIterator* oGetCatalogIterator( const ExtendedVCB *volume, HFSCatalogNodeID folderID, UInt16 index);
extern CatalogIterator* GetCatalogIterator(ExtendedVCB *volume, HFSCatalogNodeID folderID, UInt32 offset);

extern OSErr	ReleaseCatalogIterator( CatalogIterator *catalogIterator );

extern void		TrashCatalogIterator( const ExtendedVCB *volume, HFSCatalogNodeID folderID );

void			AgeCatalogIterator( CatalogIterator *catalogIterator );

extern void		UpdateBtreeIterator( const CatalogIterator *catalogIterator, BTreeIterator *btreeIterator );

extern void		UpdateCatalogIterator( const BTreeIterator *btreeIterator, CatalogIterator *catalogIterator );


#endif //__CATALOGPRIVATE__
