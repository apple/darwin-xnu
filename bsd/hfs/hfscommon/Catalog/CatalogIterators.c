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
	File:		CatalogIterators.c

	Contains:	Catalog Iterator Implementation

	Version:	HFS Plus 1.0

	Copyright:	© 1997-1998 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Don Brady

		Other Contact:		Mark Day

		Technology:			Mac OS File System

	Writers:

		(msd)	Mark Day
		(djb)	Don Brady

	Change History (most recent first):
	   <MacOSX>	 4/23/98	djb		Re-enable InvalidateCatalogCache (was commented out).
	   <MacOSX>	  4/6/98	djb		Add locking for cache globals (list) and iterators.
	   <MacOSX>	  4/2/98	djb		Define gCatalogCacheGlobals here instead of FSVars.
	   <MacOSX>	 3/31/98	djb		Sync up with final HFSVolumes.h header file.

	   <CS3>	11/13/97	djb		Radar #1683572 - Fix for indexed GetFileInfo.
	   <CS2>	10/17/97	msd		Bug 1683506. Add support for long Unicode names in
									CatalogIterators. Added a single global buffer for long Unicode
									names; it is used by at most one CatalogIterator at a time.
	   <CS1>	 10/1/97	djb		first checked in
*/


#include "../../hfs_macos_defs.h"
#include "../../hfs.h"
#include "../../hfs_dbg.h"
#include "../../hfs_format.h"

#include	"../headers/FileMgrInternal.h"
#include	"../headers/BTreesInternal.h"
#include	"../headers/CatalogPrivate.h"


#include <sys/param.h>
#include <sys/systm.h>
#include <libkern/libkern.h>
#include <sys/lock.h>

static void	InsertCatalogIteratorAsMRU( CatalogCacheGlobals *cacheGlobals, CatalogIterator *iterator );

static void InsertCatalogIteratorAsLRU( CatalogCacheGlobals *cacheGlobals, CatalogIterator *iterator );

static void PrepareForLongName( CatalogIterator *iterator );


#if TARGET_API_MACOS_X
  CatalogCacheGlobals  *gCatalogCacheGlobals;

  #define GetCatalogCacheGlobals()		(gCatalogCacheGlobals)

  #define CATALOG_ITER_LIST_LOCK(g)		simple_lock(&(g)->simplelock)

  #define CATALOG_ITER_LIST_UNLOCK(g)	simple_unlock(&(g)->simplelock)

  #define CI_LOCK(i)					lockmgr(&(i)->iterator_lock, LK_EXCLUSIVE, (simple_lock_t) 0, current_proc())
	
#define CI_UNLOCK(i)					lockmgr(&(i)->iterator_lock, LK_RELEASE, (simple_lock_t) 0, current_proc())

#define CI_SLEEPLESS_LOCK(i)			lockmgr(&(i)->iterator_lock, LK_EXCLUSIVE | LK_NOWAIT, (simple_lock_t) 0, current_proc())	

#define CI_LOCK_FROM_LIST(g,i)		lockmgr(&(i)->iterator_lock, LK_EXCLUSIVE | LK_INTERLOCK, &(g)->simplelock, current_proc())

#else /* TARGET_API_MACOS_X */

  #define GetCatalogCacheGlobals()		((CatalogCacheGlobals*) ((FSVarsRec*) LMGetFSMVars()->gCatalogCacheGlobals))

  #define CATALOG_ITER_LIST_LOCK(g)

  #define CATALOG_ITER_LIST_UNLOCK(g)

  #define CI_LOCK(i)					0
	
  #define CI_UNLOCK(i)					0
  
  #define CI_SLEEPLESS_LOCK(i)			0

  #define CI_LOCK_FROM_LIST(g,i)		0

#endif


//_______________________________________________________________________________
//	Routine:	InitCatalogCache
//
//	Function: 	Allocates cache, and initializes all the cache structures.
//
//_______________________________________________________________________________
OSErr
InitCatalogCache(void)
{
	CatalogCacheGlobals *	cacheGlobals;
	CatalogIterator *		iterator;
	UInt32					cacheSize;
	UInt16					i;
	UInt16					lastIterator;
	OSErr					err;


	cacheSize = sizeof(CatalogCacheGlobals) + ( kCatalogIteratorCount * sizeof(CatalogIterator) );
	cacheGlobals = (CatalogCacheGlobals *) NewPtrSysClear( cacheSize );

	cacheGlobals->iteratorCount = kCatalogIteratorCount;

	lastIterator = kCatalogIteratorCount - 1;		//	last iterator number, since they start at 0
	
	//	Initialize the MRU order for the cache
	cacheGlobals->mru = (CatalogIterator *) ( (Ptr)cacheGlobals + sizeof(CatalogCacheGlobals) );

	//	Initialize the LRU order for the cache
	cacheGlobals->lru = (CatalogIterator *) ( (Ptr)(cacheGlobals->mru) + (lastIterator * sizeof(CatalogIterator)) );
	

	//	Traverse iterators, setting initial mru, lru, and default values
	for ( i = 0, iterator = cacheGlobals->mru; i < kCatalogIteratorCount ; i++, iterator = iterator->nextMRU )
	{
		if ( i == lastIterator )
			iterator->nextMRU = nil;	// terminate the list
		else
			iterator->nextMRU = (CatalogIterator *) ( (Ptr)iterator + sizeof(CatalogIterator) );

		if ( i == 0 )
			iterator->nextLRU = nil;	// terminate the list	
		else
			iterator->nextLRU = (CatalogIterator *) ( (Ptr)iterator - sizeof(CatalogIterator) );

        #if TARGET_API_MACOS_X
		lockinit(&iterator->iterator_lock, PINOD, "hfs_catalog_iterator", 0, 0);
	  #endif
	}
	
  #if TARGET_API_MAC_OS8
	(FSVarsRec*) LMGetFSMVars()->gCatalogCacheGlobals = (Ptr) cacheGlobals;
  #endif

  #if TARGET_API_MACOS_X
	gCatalogCacheGlobals = cacheGlobals;
	simple_lock_init(&cacheGlobals->simplelock);
  #endif
	
	return noErr;
}


//_______________________________________________________________________________
//	Routine:	InvalidateCatalogCache
//
//	Function: 	Trash any interators matching volume parameter
//
//_______________________________________________________________________________
void PrintCatalogIterator( void );

void
InvalidateCatalogCache( ExtendedVCB *volume )
{
	TrashCatalogIterator( volume, 0 );
}


//_______________________________________________________________________________
//	Routine:	PrintCatalogIterator
//
//	Function: 	Prints all interators
//
//_______________________________________________________________________________
#if HFS_DIAGNOSTIC
void
PrintCatalogIterator( void )
{
    CatalogIterator		*iterator;
    CatalogCacheGlobals	*cacheGlobals = GetCatalogCacheGlobals();
	int					i;

    PRINTIT("CatalogCacheGlobals @ 0x%08lX are:\n", (unsigned long)cacheGlobals);
    PRINTIT("\titeratorCount: %ld \n", cacheGlobals->iteratorCount);
    PRINTIT("\tmru: 0x%08lX \n", (unsigned long)cacheGlobals->mru);
    PRINTIT("\tlru: 0x%08lX \n", (unsigned long)cacheGlobals->lru);

    for ( iterator = cacheGlobals->mru, i=0 ; iterator != nil && i<32  ; iterator = iterator->nextMRU, i++)
      {
        PRINTIT("%d: ", i);
        PRINTIT(" i: 0x%08lX", (unsigned long)iterator);
        PRINTIT(" M: 0x%08lX", (unsigned long)iterator->nextMRU);
        PRINTIT(" L: 0x%08lX", (unsigned long)iterator->nextLRU);
        PRINTIT("\n");
     }
}
#endif

//_______________________________________________________________________________
//	Routine:	TrashCatalogIterator
//
//	Function: 	Trash any interators matching volume and folder parameters
//
//_______________________________________________________________________________
void
TrashCatalogIterator( const ExtendedVCB *volume, HFSCatalogNodeID folderID )
{
	CatalogIterator		*iterator;
	CatalogCacheGlobals	*cacheGlobals = GetCatalogCacheGlobals();

	CATALOG_ITER_LIST_LOCK(cacheGlobals);

	for ( iterator = cacheGlobals->mru ; iterator != nil ; iterator = iterator->nextMRU )
	{
		top:

		// first match the volume
		if ( iterator->volume != volume )
			continue;

		// now match the folder (or all folders if 0)
		if ( (folderID == 0) || (folderID == iterator->folderID) )
		{
			CatalogIterator	*next;

			iterator->volume = 0;	// trash it
			iterator->folderID = 0;

			next = iterator->nextMRU;	// remember the next iterator
			
			// if iterator is not already last then make it last
			if ( next != nil )
			{
				InsertCatalogIteratorAsLRU( cacheGlobals, iterator );
				
				// iterator->nextMRU will always be zero (since we moved it to the end)
				// so set up the next iterator manually (we know its not nil)
				iterator = next;	
				goto top;			// process the next iterator
			}
		}
	}

	CATALOG_ITER_LIST_UNLOCK(cacheGlobals);
}


//_______________________________________________________________________________
//	Routine:	AgeCatalogIterator
//
//	Function: 	Move iterator to the end of the list...
//
//_______________________________________________________________________________
void
AgeCatalogIterator ( CatalogIterator *catalogIterator )
{
	CatalogCacheGlobals *	cacheGlobals = GetCatalogCacheGlobals();

	CATALOG_ITER_LIST_LOCK(cacheGlobals);

	//PRINTIT(" AgeCatalogIterator: v=%d, d=%ld, i=%d\n", catalogIterator->volRefNum, catalogIterator->folderID, catalogIterator->currentIndex);

	InsertCatalogIteratorAsLRU( cacheGlobals, catalogIterator );

	CATALOG_ITER_LIST_UNLOCK(cacheGlobals);
}


//_______________________________________________________________________________
//	Routine:	GetCatalogIterator
//
//	Function: 	Release interest in Catalog iterator
//
//_______________________________________________________________________________
OSErr
ReleaseCatalogIterator( CatalogIterator* catalogIterator)
{
#if TARGET_API_MACOS_X
	//PRINTIT(" ReleaseCatalogIterator: v=%d, d=%ld, i=%d\n", catalogIterator->volRefNum, catalogIterator->folderID, catalogIterator->currentIndex);
	return CI_UNLOCK(catalogIterator);
#else
	return noErr;
#endif
}


//_______________________________________________________________________________
//	Routine:	GetCatalogIterator
//
//	Function: 	Returns an iterator associated with the volume, folderID, index,
//				and iterationType (kIterateFilesOnly or kIterateAll).
//				Searches the cache in MRU order.
//				Inserts the resulting iterator at the head of mru automatically
//
//	Note:		The returned iterator is locked and ReleaseCatalogIterator must
//				be called to unlock it.
//
//_______________________________________________________________________________

CatalogIterator*
GetCatalogIterator(ExtendedVCB *volume, HFSCatalogNodeID folderID, UInt32 offset)
{
	CatalogCacheGlobals *cacheGlobals = GetCatalogCacheGlobals();
	CatalogIterator *iterator;
	CatalogIterator *bestIterator;

	bestIterator = NULL;

	CATALOG_ITER_LIST_LOCK(cacheGlobals);

	for (iterator = cacheGlobals->mru ; iterator != nil ; iterator = iterator->nextMRU) {

		/* first make sure volume and folder id match */
		if ((iterator->volume != volume) || (iterator->folderID != folderID)) {
			continue;
		}

		/* ignore busy iterators */
		if ( CI_SLEEPLESS_LOCK(iterator) == EBUSY ) {
			//PRINTIT(" GetCatalogIterator: busy v=%d, d=%ld, i=%d\n", volume, folderID, iterator->currentIndex);
			continue;
		}

		/* we matched volume, folder id, now check the offset */
		if ( iterator->currentOffset == offset || iterator->nextOffset == offset) {
			bestIterator = iterator;	// we scored! - so get out of this loop
			break;				// break with iterator locked
		}

		(void) CI_UNLOCK(iterator);	// unlock iterator before moving to the next one
	}

	// check if we didn't get one or if the one we got is too far away...
	if (bestIterator == NULL)
	{
		bestIterator = cacheGlobals->lru;			// start over with a new iterator

		//PRINTIT(" GetCatalogIterator: recycle v=%d, d=%ld, i=%d\n", bestIterator->volume, bestIterator->folderID, bestIterator->currentIndex);
		(void) CI_LOCK_FROM_LIST(cacheGlobals, bestIterator);	// XXX we should not eat the error!
	
		CATALOG_ITER_LIST_LOCK(cacheGlobals);			// grab the lock again for MRU Insert below...

		bestIterator->volume = volume;			// update the iterator's volume
		bestIterator->folderID = folderID;			// ... and folderID
		bestIterator->currentIndex = 0xFFFFFFFF;			// ... and offspring index marker
		bestIterator->currentOffset = 0xFFFFFFFF;
		bestIterator->nextOffset = 0xFFFFFFFF;
		
		bestIterator->btreeNodeHint = 0;
		bestIterator->btreeIndexHint = 0;
		bestIterator->parentID = folderID;			// set key to folderID + empty name
		bestIterator->folderName.unicodeName.length = 0;	// clear pascal/unicode name

		if ( volume->vcbSigWord == kHFSPlusSigWord )
			bestIterator->nameType = kShortUnicodeName;
		else
			bestIterator->nameType = kShortPascalName;
	}
	else {
		//PRINTIT(" GetCatalogIterator: found v=%d, d=%ld, i=%d\n", bestIterator->volume, bestIterator->folderID, bestIterator->currentIndex);
	}

	// put this iterator at the front of the list
	InsertCatalogIteratorAsMRU( cacheGlobals, bestIterator );

	CATALOG_ITER_LIST_UNLOCK(cacheGlobals);

	return bestIterator;	// return our best shot

} /* GetCatalogIterator */


//_______________________________________________________________________________
//	Routine:	UpdateBtreeIterator
//
//	Function: 	Fills in a BTreeIterator from a CatalogIterator
//
//	Assumes:	catalogIterator->nameType is correctly initialized!
//				catalogIterator is locked (MacOS X)
//_______________________________________________________________________________
void
UpdateBtreeIterator(const CatalogIterator *catalogIterator, BTreeIterator *btreeIterator)
{
	CatalogName *	nodeName;
	Boolean			isHFSPlus;


	btreeIterator->hint.writeCount  = 0;
	btreeIterator->hint.nodeNum 	= catalogIterator->btreeNodeHint;
	btreeIterator->hint.index		= catalogIterator->btreeIndexHint;

	switch (catalogIterator->nameType)
	{
		case kShortPascalName:
			if ( catalogIterator->folderName.pascalName[0] > 0 )
				nodeName  = (CatalogName *) catalogIterator->folderName.pascalName;
			else
				nodeName = NULL;

			isHFSPlus = false;
			break;

		case kShortUnicodeName:
			if ( catalogIterator->folderName.unicodeName.length > 0 )
				nodeName  = (CatalogName *) &catalogIterator->folderName.unicodeName;
			else
				nodeName = NULL;

			isHFSPlus = true;
			break;

		case kLongUnicodeName:
			if ( catalogIterator->folderName.longNamePtr->length > 0 )
				nodeName  = (CatalogName *) catalogIterator->folderName.longNamePtr;
			else
				nodeName = NULL;

			isHFSPlus = true;
			break;

		default:
			return;
	}

	BuildCatalogKey(catalogIterator->parentID, nodeName, isHFSPlus, (CatalogKey*) &btreeIterator->key);
}


//_______________________________________________________________________________
//	Routine:	UpdateCatalogIterator
//
//	Function: 	Updates a CatalogIterator from a BTreeIterator
//
//	Assumes:	catalogIterator->nameType is correctly initialized!
//				catalogIterator is locked (MacOS X)
//_______________________________________________________________________________
void
UpdateCatalogIterator (const BTreeIterator *btreeIterator, CatalogIterator *catalogIterator)
{
	void *			srcName;
	void *			dstName;
	UInt16			nameSize;
	CatalogKey *	catalogKey;


	catalogIterator->btreeNodeHint  = btreeIterator->hint.nodeNum;
	catalogIterator->btreeIndexHint = btreeIterator->hint.index;

	catalogKey = (CatalogKey*) &btreeIterator->key;

	switch (catalogIterator->nameType)
	{
		case kShortPascalName:
			catalogIterator->parentID = catalogKey->hfs.parentID;

			dstName  = catalogIterator->folderName.pascalName;
			srcName	 = catalogKey->hfs.nodeName;
			nameSize = catalogKey->hfs.nodeName[0] + sizeof(UInt8);
			break;

		case kShortUnicodeName:
			catalogIterator->parentID = catalogKey->hfsPlus.parentID;

			dstName  = &catalogIterator->folderName.unicodeName;
			srcName  = &catalogKey->hfsPlus.nodeName;
			nameSize = (catalogKey->hfsPlus.nodeName.length + 1) * sizeof(UInt16);

			//	See if we need to make this iterator use long names
			if ( nameSize > sizeof(catalogIterator->folderName.unicodeName) )
			{
				PrepareForLongName(catalogIterator);		//	Find a long name buffer to use
				dstName  = catalogIterator->folderName.longNamePtr;
			}
			break;

		case kLongUnicodeName:
			catalogIterator->parentID = catalogKey->hfsPlus.parentID;

			dstName  = catalogIterator->folderName.longNamePtr;
			srcName  = &catalogKey->hfsPlus.nodeName;
			nameSize = (catalogKey->hfsPlus.nodeName.length + 1) * sizeof(UInt16);
			break;

		default:
			return;
	}

	if (catalogIterator->parentID != catalogIterator->folderID)
		catalogIterator->nextOffset = 0xFFFFFFFF;

	BlockMoveData(srcName, dstName, nameSize);

} // end UpdateCatalogIterator


//_______________________________________________________________________________
//	Routine:	InsertCatalogIteratorAsMRU
//
//	Function: 	Moves catalog iterator to head of mru order in double linked list
//
//				Assumes list simple lock is held
//_______________________________________________________________________________
static void
InsertCatalogIteratorAsMRU ( CatalogCacheGlobals *cacheGlobals, CatalogIterator *iterator )
{
	CatalogIterator	*swapIterator;

	if ( cacheGlobals->mru != iterator )					//	if it's not already the mru iterator
	{
		swapIterator = cacheGlobals->mru;						//	put it in the front of the double queue
		cacheGlobals->mru = iterator;
		iterator->nextLRU->nextMRU = iterator->nextMRU;
		if ( iterator->nextMRU != nil )
			iterator->nextMRU->nextLRU = iterator->nextLRU;
		else
			cacheGlobals->lru= iterator->nextLRU;
		iterator->nextMRU	= swapIterator;
		iterator->nextLRU	= nil;
		swapIterator->nextLRU	= iterator;
	}
}


//________________________________________________________________________________
//	Routine:	InsertCatalogIteratorAsLRU
//
//	Function: 	Moves catalog iterator to head of lru order in double linked list
//
//				Assumes list simple lock is held
//_______________________________________________________________________________
static void
InsertCatalogIteratorAsLRU ( CatalogCacheGlobals *cacheGlobals, CatalogIterator *iterator )
{
	CatalogIterator	*swapIterator;

	if ( cacheGlobals->lru != iterator )
	{
		swapIterator = cacheGlobals->lru;
		cacheGlobals->lru = iterator;
		iterator->nextMRU->nextLRU = iterator->nextLRU;
		if ( iterator->nextLRU != nil )
			iterator->nextLRU->nextMRU = iterator->nextMRU;
		else
			cacheGlobals->mru= iterator->nextMRU;
		iterator->nextLRU	= swapIterator;
		iterator->nextMRU	= nil;
		swapIterator->nextMRU	= iterator;
	}
}



//_______________________________________________________________________________
//	Routine:	PrepareForLongName
//
//	Function: 	Takes a CatalogIterator whose nameType is kShortUnicodeName, and
//				changes the nameType to kLongUnicodeName.
//
//  Since long Unicode names aren't stored in the CatalogIterator itself, we have
//	to point to an HFSUniStr255 for storage.  In the current implementation, we have
//	just one such global buffer in the cache globals.  We'll set the iterator to
//	point to the global buffer and invalidate the iterator that was using it
//	(i.e. the iterator whose nameType is kLongUnicodeName).
//
//	Eventually, we might want to have a list of long name buffers which we recycle
//	using an LRU algorithm.  Or perhaps, some other way....
//
//	Assumes:	catalogIterator is locked (MacOS X)
//_______________________________________________________________________________
static void
PrepareForLongName ( CatalogIterator *iterator )
{
	CatalogCacheGlobals	*cacheGlobals = GetCatalogCacheGlobals();
	CatalogIterator		*iter;
	
	if (DEBUG_BUILD && iterator->nameType != kShortUnicodeName)
		DebugStr("\p PrepareForLongName: nameType is wrong!");
	
	//
	//	Walk through all the iterators.  The first iterator whose nameType
	//	is kLongUnicodeName is invalidated (because it is using the global
	//	long name buffer).
	//
	
	CATALOG_ITER_LIST_LOCK(cacheGlobals);

	for ( iter = cacheGlobals->mru ; iter != nil ; iter = iter->nextMRU )
	{
		if (iter->nameType == kLongUnicodeName)
		{
			// if iterator is not already last then make it last
			if ( iter->nextMRU != nil )
				InsertCatalogIteratorAsLRU( cacheGlobals, iter );
			
			(void) CI_LOCK_FROM_LIST(cacheGlobals,iter);
			iter->volume = 0;	// trash it
			iter->folderID = 0;
			(void) CI_UNLOCK(iter);

            #if TARGET_API_MACOS_X
			break;
		  #endif
		}
	}

	/*
	 * if iter is nil then none of the iterators was using the LongUnicodeName buffer
	 */
	if (iter == nil)
		CATALOG_ITER_LIST_UNLOCK(cacheGlobals);
	
	//
	//	Change the nameType of this iterator and point to the global
	//	long name buffer. Note - this iterator is already locked
	//
	iterator->nameType = kLongUnicodeName;
	iterator->folderName.longNamePtr = &cacheGlobals->longName;
}

