/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
	File:		BTreesInternal.h

	Contains:	IPI to File Manager B-tree

	Version:	HFS Plus 1.0

	Copyright:	© 1996-1998 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Don Brady

		Other Contact:		Mark Day

		Technology:			File Systems

	Writers:

		(msd)	Mark Day
		(DSH)	Deric Horn
		(djb)	Don Brady

	Change History (most recent first):
	
	  <RHAP>	 9/22/99	ser		Added prototypes for BTGetLastSync and BTSetLastSync
	  <RHAP>	 6/22/98	djb		Add ERR_BASE to btree error codes to make them negative (for MacOS X only).

	   <CS7>	 7/28/97	msd		Add enum for fsBTTimeOutErr.
	   <CS6>	 7/25/97	DSH		Added heuristicHint as parameter to BTSearchRecord.
	   <CS5>	 7/24/97	djb		Add blockReadFromDisk flag to BlockDescriptor. Callbacks now use
									a file refNum instead of an FCB.
	   <CS4>	 7/16/97	DSH		FilesInternal.i renamed FileMgrInternal.i to avoid name
									collision
	   <CS3>	  6/2/97	DSH		Added SetEndOfForkProc() prototype, so Attributes.c can call it
									directly.
	   <CS2>	 5/19/97	djb		kMaxKeyLength is now 520.
	   <CS1>	 4/28/97	djb		first checked in

	  <HFS6>	 3/17/97	DSH		Remove Key Comparison prototype, already in FilesInternal.h.
	  <HFS5>	 2/19/97	djb		Add SetBlockSizeProcPtr. Add blockSize field to BlockDescriptor.
									Remove E_ type error enums.
	  <HFS4>	 1/27/97	djb		Include Types.h and FilesInternal.h.
	  <HFS3>	 1/13/97	djb		Added kBTreeCurrentRecord for BTIterateRecord.
	  <HFS2>	  1/3/97	djb		Added support for large keys.
	  <HFS1>	12/19/96	djb		first checked in

*/

#ifndef	__BTREESINTERNAL__
#define __BTREESINTERNAL__

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE

#ifndef __FILEMGRINTERNAL__
#include "FileMgrInternal.h"
#endif

enum {
	fsBTInvalidHeaderErr			= btBadHdr,
	fsBTBadRotateErr				= dsBadRotate,
	fsBTInvalidNodeErr				= btBadNode,
	fsBTRecordTooLargeErr			= btNoFit,
	fsBTRecordNotFoundErr			= btNotFound,
	fsBTDuplicateRecordErr			= btExists,
	fsBTFullErr						= btNoSpaceAvail,

	fsBTInvalidFileErr				= ERR_BASE + 0x0302,	/* no BTreeCB has been allocated for fork*/
	fsBTrFileAlreadyOpenErr			= ERR_BASE + 0x0303,
	fsBTInvalidIteratorErr			= ERR_BASE + 0x0308,
	fsBTEmptyErr					= ERR_BASE + 0x030A,
	fsBTNoMoreMapNodesErr			= ERR_BASE + 0x030B,
	fsBTBadNodeSize					= ERR_BASE + 0x030C,
	fsBTBadNodeType					= ERR_BASE + 0x030D,
	fsBTInvalidKeyLengthErr			= ERR_BASE + 0x030E,
	fsBTStartOfIterationErr			= ERR_BASE + 0x0353,
	fsBTEndOfIterationErr			= ERR_BASE + 0x0354,
	fsBTUnknownVersionErr			= ERR_BASE + 0x0355,
	fsBTTreeTooDeepErr				= ERR_BASE + 0x0357,
	fsIteratorExitedScopeErr		= ERR_BASE + 0x0A02,	/* iterator exited the scope*/
	fsIteratorScopeExceptionErr		= ERR_BASE + 0x0A03,	/* iterator is undefined due to error or movement of scope locality*/
	fsUnknownIteratorMovementErr	= ERR_BASE + 0x0A04,	/* iterator movement is not defined*/
	fsInvalidIterationMovmentErr	= ERR_BASE + 0x0A05,	/* iterator movement is invalid in current context*/
	fsClientIDMismatchErr			= ERR_BASE + 0x0A06,	/* wrong client process ID*/
	fsEndOfIterationErr				= ERR_BASE + 0x0A07,	/* there were no objects left to return on iteration*/
	fsBTTimeOutErr					= ERR_BASE + 0x0A08		/* BTree scan interrupted -- no time left for physical I/O */
};

struct BlockDescriptor{
	void		*buffer;
	void		*blockHeader;
	ByteCount	 blockSize;
	Boolean		 blockReadFromDisk;
	Byte         isModified;             // XXXdbg - for journaling
	Byte		 reserved[2];
};
typedef struct BlockDescriptor BlockDescriptor;
typedef BlockDescriptor *BlockDescPtr;


struct FSBufferDescriptor {
	void *		bufferAddress;
	ByteCount	itemSize;
	ItemCount	itemCount;
};
typedef struct FSBufferDescriptor FSBufferDescriptor;

typedef FSBufferDescriptor *FSBufferDescriptorPtr;


/*
	Fork Level Access Method Block get options
*/
enum {
		kGetBlock			= 0x00000000,
		kForceReadBlock		= 0x00000002,	//€€ how does this relate to Read/Verify? Do we need this?
		kGetEmptyBlock		= 0x00000008
};
typedef OptionBits	GetBlockOptions;

/*
	Fork Level Access Method Block release options
*/
enum {
		kReleaseBlock		= 0x00000000,
		kForceWriteBlock	= 0x00000001,
		kMarkBlockDirty		= 0x00000002,
		kTrashBlock			= 0x00000004,
		kLockTransaction    = 0x00000100
};
typedef OptionBits	ReleaseBlockOptions;

typedef	UInt64	FSSize;
typedef	UInt32	ForkBlockNumber;

/*============================================================================
	Fork Level Buffered I/O Access Method
============================================================================*/

typedef	OSStatus	(* GetBlockProcPtr)		(FileReference				 fileRefNum,
											 UInt32						 blockNum,
											 GetBlockOptions			 options,
											 BlockDescriptor			*block );
							 

typedef	OSStatus	(* ReleaseBlockProcPtr)	(FileReference				 fileRefNum,
											 BlockDescPtr				 blockPtr,
											 ReleaseBlockOptions		 options );

typedef	OSStatus	(* SetEndOfForkProcPtr)	(FileReference				 fileRefNum,
											 FSSize						 minEOF,
											 FSSize						 maxEOF );
								 
typedef	OSStatus	(* SetBlockSizeProcPtr)	(FileReference				 fileRefNum,
											 ByteCount					 blockSize,
											 ItemCount					 minBlockCount );

OSStatus		SetEndOfForkProc ( FileReference fileRefNum, FSSize minEOF, FSSize maxEOF );


/*
	B*Tree Information Version
*/

enum BTreeInformationVersion{
	kBTreeInfoVersion	= 0
};

/*
	B*Tree Iteration Operation Constants
*/

enum BTreeIterationOperations{
	kBTreeFirstRecord,
	kBTreeNextRecord,
	kBTreePrevRecord,
	kBTreeLastRecord,
	kBTreeCurrentRecord
};
typedef UInt16 BTreeIterationOperation;


/*
	Btree types: 0 is HFS CAT/EXT file, 1~127 are AppleShare B*Tree files, 128~254 unused
	hfsBtreeType	EQU		0			; control file
	validBTType		EQU		$80			; user btree type starts from 128
	userBT1Type		EQU		$FF			; 255 is our Btree type. Used by BTInit and BTPatch
*/

enum BTreeTypes{
	kHFSBTreeType			=   0,		// control file
	kUserBTreeType			= 128,		// user btree type starts from 128
	kReservedBTreeType		= 255		//
};


typedef BTreeKey *BTreeKeyPtr;


/*
	BTreeInfoRec Structure - for BTGetInformation
*/
struct BTreeInfoRec{
	UInt16				version;
	UInt16				nodeSize;
	UInt16				maxKeyLength;
	UInt16				treeDepth;
	UInt32				lastfsync;		/* Last time that this was fsynced  */
	ItemCount			numRecords;
	ItemCount			numNodes;
	ItemCount			numFreeNodes;
	UInt32				reserved;
};
typedef struct BTreeInfoRec BTreeInfoRec;
typedef BTreeInfoRec *BTreeInfoPtr;

/*
	BTreeHint can never be exported to the outside. Use UInt32 BTreeHint[4],
	UInt8 BTreeHint[16], etc.
 */
struct BTreeHint{
	ItemCount				writeCount;
	UInt32					nodeNum;			// node the key was last seen in
	UInt16					index;				// index then key was last seen at
	UInt16					reserved1;
	UInt32					reserved2;
};
typedef struct BTreeHint BTreeHint;
typedef BTreeHint *BTreeHintPtr;

/*
	BTree Iterator
*/
struct BTreeIterator{
	BTreeHint				hint;
	UInt16					version;
	UInt16					reserved;
	UInt32					hitCount;			// Total number of leaf records hit
	UInt32					maxLeafRecs;		// Max leaf records over iteration
	BTreeKey				key;
};
typedef struct BTreeIterator BTreeIterator;
typedef BTreeIterator *BTreeIteratorPtr;


/*============================================================================
	B*Tree SPI
============================================================================*/

/*
	Key Comparison Function ProcPtr Type - for BTOpenPath
*/
//typedef SInt32 				(* KeyCompareProcPtr)(BTreeKeyPtr a, BTreeKeyPtr b);


typedef SInt32 (* IterateCallBackProcPtr)(BTreeKeyPtr key, void * record, UInt16 recordLen, void * state);

extern OSStatus	BTOpenPath			(FCB		 				*filePtr,
									 KeyCompareProcPtr			 keyCompareProc,
									 GetBlockProcPtr			 getBlockProc,
									 ReleaseBlockProcPtr		 releaseBlockProc,
									 SetEndOfForkProcPtr		 setEndOfForkProc,
									 SetBlockSizeProcPtr		 setBlockSizeProc );

extern OSStatus	BTClosePath			(FCB		 				*filePtr );


extern OSStatus	BTSearchRecord		(FCB		 				*filePtr,
									 BTreeIterator				*searchIterator,
									 FSBufferDescriptor			*btRecord,
									 UInt16						*recordLen,
									 BTreeIterator				*resultIterator );

extern OSStatus	BTIterateRecord		(FCB		 				*filePtr,
									 BTreeIterationOperation	 operation,
									 BTreeIterator				*iterator,
									 FSBufferDescriptor			*btRecord,
									 UInt16						*recordLen );


extern OSStatus BTIterateRecords(FCB *filePtr, BTreeIterationOperation operation, BTreeIterator *iterator,
		 IterateCallBackProcPtr	 callBackProc, void * callBackState);

extern OSStatus	BTInsertRecord		(FCB		 				*filePtr,
									 BTreeIterator				*iterator,
									 FSBufferDescriptor			*btrecord,
									 UInt16						 recordLen );

extern OSStatus	BTReplaceRecord		(FCB		 				*filePtr,
									 BTreeIterator				*iterator,
									 FSBufferDescriptor			*btRecord,
									 UInt16						 recordLen );

extern OSStatus	BTUpdateRecord		(FCB		 				*filePtr,
									 BTreeIterator				*iterator,
									 IterateCallBackProcPtr		 callBackProc,
									 void						*callBackState );

extern OSStatus	BTDeleteRecord		(FCB		 				*filePtr,
									 BTreeIterator				*iterator );

extern OSStatus	BTGetInformation	(FCB		 				*filePtr,
									 UInt16						 version,
									 BTreeInfoRec				*info );

extern OSStatus	BTFlushPath			(FCB		 				*filePtr );

extern OSStatus BTReloadData		(FCB *filePtr);

extern OSStatus	BTInvalidateHint	(BTreeIterator				*iterator );

extern OSStatus	BTGetLastSync		(FCB		 				*filePtr,
									 UInt32						*lastfsync );

extern OSStatus	BTSetLastSync		(FCB		 				*filePtr,
									 UInt32						lastfsync );

extern OSStatus	BTCheckFreeSpace	(FCB		 				*filePtr);

extern OSStatus	BTHasContiguousNodes(FCB		 				*filePtr);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif // __BTREESINTERNAL__
