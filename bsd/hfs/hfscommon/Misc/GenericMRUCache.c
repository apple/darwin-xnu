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
	File:		GenericMRUCache.c

	Contains:	Contains cache accessor routines based on MRU / LRU ordering.

	Version:	HFS+ 1.0

	Copyright:	© 1997-1998 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Deric Horn

		Other Contact:		Don Brady

		Technology:			HFS+

	Writers:

		(DSH)	Deric Horn

	Change History (most recent first):

	   <CS2>	 1/29/98	DSH		Add TrashMRUCache for TrashAllFSCaches API support.
	   <CS1>	 7/25/97	DSH		first checked in
*/

#include "../../hfs_macos_defs.h"
#include "../headers/FileMgrInternal.h"

enum {
	//	error codes
	errNotInCache			= -123,
	errInvalidKey			= -124
};


struct CacheBlock {
	struct CacheBlock		*nextMRU;					//	next node in MRU order
	struct CacheBlock		*nextLRU;					//	next node in LRU order
	UInt32					flags;						//	status flags
	UInt32					key;						//	comparrison Key
	char					buffer[1];					//	user defineable data
};
typedef struct CacheBlock CacheBlock;

struct CacheGlobals {
	UInt32					cacheBlockSize;				//	Size of CacheBlock structure including the buffer
	UInt32					cacheBufferSize;			//	Size of cache buffer
	UInt32					numCacheBlocks;				//	Number of blocks in cache
	CacheBlock				*mru;
	CacheBlock				*lru;
};
typedef struct CacheGlobals CacheGlobals;


//
//	Internal routines
//
static void InsertAsMRU	( CacheGlobals *cacheGlobals, CacheBlock *cacheBlock );
static void InsertAsLRU	( CacheGlobals *cacheGlobals, CacheBlock *cacheBlock );


//
//	Diagram of Cache structures
//
//	_______        ________        ________            ________
//	|data |        | buff |        | buff |            | buff |
//	| mru |----->  | nMRU |----->  | nMRU |--> °°° --->| nMRU |-->€
//	| lru |-\   €<-| nLRU |  <-----| nLRU |<-- °°° <---| nLRU |
//	-------  \     --------        --------            --------
//            \                                           |
//	           \-----------------------------------------/
//	CacheGlobals					CacheBlock's




//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	InitMRUCache
//
//	Function: 	Allocates cache, and initializes all the cache structures.
//
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
OSErr	InitMRUCache( UInt32 bufferSize, UInt32 numCacheBlocks, Ptr *cachePtr )
{
	OSErr			err;
	short			i, lastBuffer;
	CacheBlock		*cacheBlock;
	CacheGlobals	*cacheGlobals;
	UInt32			cacheBlockSize	= offsetof( CacheBlock, buffer ) + bufferSize;
	
	cacheGlobals	= (CacheGlobals *) NewPtrSysClear( sizeof( CacheGlobals ) +  ( numCacheBlocks * cacheBlockSize ) );
	err = MemError();
	
	if ( err == noErr )
	{
		cacheGlobals->cacheBlockSize	= cacheBlockSize;
		cacheGlobals->cacheBufferSize	= bufferSize;
		cacheGlobals->numCacheBlocks	= numCacheBlocks;

		lastBuffer = numCacheBlocks - 1;							//	last buffer number, since they start at 0
		
		//	Initialize the LRU order for the cache
		cacheGlobals->lru = (CacheBlock *)((Ptr)cacheGlobals + sizeof( CacheGlobals ) + (lastBuffer * cacheBlockSize));
		cacheGlobals->lru->nextMRU = nil;
		
		//	Initialize the MRU order for the cache
		cacheGlobals->mru = (CacheBlock *)( (Ptr)cacheGlobals + sizeof( CacheGlobals ) );	//	points to 1st cache block
		cacheGlobals->mru->nextLRU = nil;
		
		//	Traverse nodes, setting initial mru, lru, and default values
		for ( i=0, cacheBlock=cacheGlobals->mru; i<lastBuffer ; i++ )
		{
			cacheBlock->key		= kInvalidMRUCacheKey;				//	initialize key to illegal while we're at it
			cacheBlock->flags	= 0;
			cacheBlock->nextMRU	= (CacheBlock *) ( (Ptr)cacheBlock + cacheBlockSize );
			cacheBlock			= cacheBlock->nextMRU;
		}
		//	And the last Block
		cacheGlobals->lru->key	= kInvalidMRUCacheKey;
		cacheBlock->flags		= 0;

		for ( i=0, cacheBlock=cacheGlobals->lru; i<lastBuffer ; i++ )
		{
			cacheBlock->nextLRU = (CacheBlock *) ( (Ptr)cacheBlock - cacheBlockSize );
			cacheBlock = cacheBlock->nextLRU;
		}
		
		*cachePtr	= (Ptr) cacheGlobals;							//	return cacheGlobals to user
	}
	else
	{
		*cachePtr	= nil;
	}
	
	return( err );
}


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	DisposeMRUCache
//
//	Function: 	Dispose of all memory allocated by the cache
//
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
OSErr	DisposeMRUCache( Ptr cachePtr )
{
	OSErr		err;
	
	DisposePtr( cachePtr );
	err = MemError();
	
	return( err );
}


//ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Routine:	TrashMRUCache
//
//	Function: 	Invalidates all entries in the MRU cache pointed to by cachePtr.
//
//ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
void	TrashMRUCache( Ptr cachePtr )
{
	CacheGlobals	*cacheGlobals	= (CacheGlobals *) cachePtr;
	CacheBlock		*cacheBlock;
	
	for ( cacheBlock = cacheGlobals->mru ; cacheBlock != nil ; cacheBlock = cacheBlock->nextMRU )
	{
		cacheBlock->flags	= 0;					//	Clear the flags
		cacheBlock->key		= kInvalidMRUCacheKey;	//	Make it an illegal value
	}
}


//ÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑÑ
//	Routine:	GetMRUCacheBlock
//
//	Function: 	Return buffer associated with the passed in key.
//				Search the cache in MRU order
//				€ We can insert the found cache block at the head of mru automatically
//
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
OSErr	GetMRUCacheBlock( UInt32 key, Ptr cachePtr, Ptr *buffer )
{
	CacheBlock		*cacheBlock;
	CacheGlobals	*cacheGlobals	= (CacheGlobals *) cachePtr;
	
//	if ( key == kInvalidMRUCacheKey )		//	removed for performance
//		return( errInvalidKey );
		
	for ( cacheBlock = cacheGlobals->mru ; (cacheBlock != nil) && (cacheBlock->key != kInvalidMRUCacheKey) ; cacheBlock = cacheBlock->nextMRU )
	{
		if ( cacheBlock->key == key )
		{
			InsertAsMRU( cacheGlobals, cacheBlock );
			*buffer = (Ptr) cacheBlock->buffer;
			return( noErr );
		}
	}
	
	return( errNotInCache );
}



//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	InvalidateMRUCacheBlock
//
//	Function: 	Place the cache block at the head of the lru queue and mark it invalid
//
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
void	InvalidateMRUCacheBlock( Ptr cachePtr, Ptr buffer )
{
	CacheGlobals	*cacheGlobals	= (CacheGlobals *) cachePtr;
	CacheBlock		*cacheBlock;
	
	cacheBlock = (CacheBlock *) (buffer - offsetof( CacheBlock, buffer ));
	cacheBlock->flags	= 0;					//	Clear the flags
	cacheBlock->key		= kInvalidMRUCacheKey;	//	Make it an illegal value
	InsertAsLRU( cacheGlobals, cacheBlock );
}


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	InsertMRUCacheBlock
//
//	Function: 	Place the CacheBlock associated with the passed in key at the
//				head of the mru queue and replace the buffer with the passed in buffer
//
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
void	InsertMRUCacheBlock( Ptr cachePtr, UInt32 key, Ptr buffer )
{
	CacheBlock		*cacheBlock = NULL;
	Ptr				cacheBuffer;
	OSErr			err;
	CacheGlobals	*cacheGlobals	= (CacheGlobals *) cachePtr;
	UInt32			cacheBufferSize;
	
	err = GetMRUCacheBlock( key, cachePtr, &cacheBuffer );
	if ( err == errNotInCache )
	    cacheBlock = cacheGlobals->lru;
	else if ( err == noErr )
		cacheBlock = (CacheBlock *) (cacheBuffer - offsetof( CacheBlock, buffer ));
	
	cacheBufferSize	= cacheGlobals->cacheBufferSize;
	if ( cacheBufferSize == sizeof(UInt32) )
		*(UInt32*)cacheBlock->buffer = *(UInt32*)buffer;
	else
		BlockMoveData( buffer, cacheBlock->buffer, cacheBufferSize );
	InsertAsMRU( cacheGlobals, cacheBlock );
	
	cacheBlock->flags	= 0;
	cacheBlock->key		= key;
}




//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	InsertMRUCacheBlock
//
//	Function: 	Moves cache block to head of mru order in double linked list of cached blocks
//
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
static void	InsertAsMRU	( CacheGlobals *cacheGlobals, CacheBlock *cacheBlock )
{
	CacheBlock	*swapBlock;

	if ( cacheGlobals->mru != cacheBlock )					//	if it's not already the mru cacheBlock
	{
		swapBlock = cacheGlobals->mru;						//	put it in the front of the double queue
		cacheGlobals->mru = cacheBlock;
		cacheBlock->nextLRU->nextMRU = cacheBlock->nextMRU;
		if ( cacheBlock->nextMRU != nil )
			cacheBlock->nextMRU->nextLRU = cacheBlock->nextLRU;
		else
			cacheGlobals->lru= cacheBlock->nextLRU;
		cacheBlock->nextMRU	= swapBlock;
		cacheBlock->nextLRU	= nil;
		swapBlock->nextLRU	= cacheBlock;
	}
}


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	InsertMRUCacheBlock
//
//	Function: 	Moves cache block to head of lru order in double linked list of cached blocks
//
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
static void InsertAsLRU	( CacheGlobals *cacheGlobals, CacheBlock *cacheBlock )
{
	CacheBlock	*swapBlock;

	if ( cacheGlobals->lru != cacheBlock )
	{
		swapBlock = cacheGlobals->lru;
		cacheGlobals->lru = cacheBlock;
		cacheBlock->nextMRU->nextLRU = cacheBlock->nextLRU;
		if ( cacheBlock->nextLRU != nil )
			cacheBlock->nextLRU->nextMRU = cacheBlock->nextMRU;
		else
			cacheGlobals->mru= cacheBlock->nextMRU;
		cacheBlock->nextLRU	= swapBlock;
		cacheBlock->nextMRU	= nil;
		swapBlock->nextMRU	= cacheBlock;
	}
}


