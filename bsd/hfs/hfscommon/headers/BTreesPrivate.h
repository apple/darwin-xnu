/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
	File:		BTreesPrivate.h

	Contains:	Private interface file for the BTree Module.

	Version:	xxx put the technology version here xxx

	Written by:	Gordon Sheridan and Bill Bruffey

	Copyright:	© 1992-1999 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Don Brady

		Other Contact:		Mark Day

		Technology:			File Systems

	Writers:

		(msd)	Mark Day
		(DSH)	Deric Horn
		(djb)	Don Brady
		(ser)	Scott Roberts
		(dkh)	Dave Heller

	Change History (most recent first):
	   <MacOSX>	 3/19/99	djb		Disable MoveRecordsLeft/Right macros since bcopy is broken.
	
	   <MacOSX>	 8/10/98	djb		Removed unused BTreeIterator from BTreeControlBlock, fixed alignment.

	   <CS5>	  9/4/97	djb		Convert MoveRecordsLeft and GetLeftSiblingNode to macros.
	   <CS4>	 7/24/97	djb		Add macro for GetRecordAddress (was a function before).
	   <CS3>	 7/21/97	msd		GetRecordByIndex now returns an OSStatus.
	   <CS2>	 7/16/97	DSH		FilesInternal.i renamed FileMgrInternal.i to avoid name
									collision
	   <CS1>	 4/23/97	djb		first checked in

	  <HFS6>	 3/17/97	DSH		Added a refCon field to BTreeControlBlock, for DFA use, to point
									to additional data.  Fixed Panic macros for use with SC.
	  <HFS5>	 2/19/97	djb		Add InsertKey struct. Moved on-disk definitions to
									HFSBTreesPriv.h
	  <HFS4>	 1/27/97	djb		InsertTree and DeleteTree are now recursive and support variable
									sized index keys.
	  <HFS3>	 1/15/97	djb		Move GetFileRefNumFromFCB macro to FilesInternal.h. Added
									kBTVariableIndexKeysMask.
	  <HFS2>	  1/3/97	djb		Added support for large keys.
	  <HFS1>	12/19/96	djb		first checked in

	History applicable to original Scarecrow Design:

		 <7>	10/25/96	ser		Changing for new VFPI
		 <6>	10/18/96	ser		Converting over VFPI changes
		 <5>	 9/17/96	dkh		More BTree statistics
		 <4>	 9/16/96	dkh		Revised BTree statistics
		 <3>	 6/20/96	dkh		Radar #1358740. Switch from using Pools to debug MemAllocators.
		 <2>	 12/7/95	dkh		D10E2 build. Changed usage of Ref data type to LogicalAddress.
		 <1>	10/18/95	rst		Moved from Scarecrow project.

		<19>	11/22/94	djb		Add prototype for GetMapNode
		<18>	11/16/94	prp		Add IsItAHint routine prototype.
		<17>	 9/30/94	prp		Get in sync with D2 interface changes.
		<16>	 7/25/94	wjk		Eliminate usage of BytePtr in favor of UInt8 *.
		<15>	 7/22/94	wjk		Convert to the new set of header files.
		<14>	 5/31/94	srs		Moved Btree types to public interface
		<13>	 12/9/93	wjk		Add 68k alignment pragma's around persistent structures.
		<12>	11/30/93	wjk		Move from Makefiles to BuildFiles. Fit into the ModernOS and
									NRCmds environments.
		<11>	11/23/93	wjk		Changes required to compile on the RS6000.
		<10>	 8/30/93	CH		Removed the M_ExitOnError and M_ReturnErrorIf macros which were
									already defined in FileSystemPriv.h (included here).
		 <9>	 8/30/93	CH		Added parens around the M_ReturnErrorIf macro.
		 <8>	 5/21/93	gs		Add kBadClose flag. Add some prototypes for internal routines.
		 <7>	 5/10/93	gs		Change Ptr to BytePtr. Move BTreeTypes to BTree.h. Add
									DeleteTree prototype.
		 <6>	 3/23/93	gs		Remove mysterious "flags" field from HeaderRec structure. Move
									prototypes of private functions to top of respective source
									files.
		 <5>	  2/8/93	gs		Update to use FSAgent.h Get/Release/SetEOF/SetBlockSize
									procPtrs. Add UpdateNode routine.
		 <4>	12/10/92	gs		Add Key Descriptor function declarations.
		 <3>	 12/8/92	gs		Add HeaderRec structure and incorporate review feedback.
		 <2>	 12/2/92	gs		Add GetNode and ReleaseNode callback procptrs to BTree CB, and
									add internal function declarations.
		 <1>	11/15/92	gs		first checked in

*/

#ifndef	__BTREESPRIVATE__
#define __BTREESPRIVATE__

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE

#include "../../hfs_macos_defs.h"

#ifndef __FILEMGRINTERNAL__
#include "FileMgrInternal.h"
#endif

#ifndef __BTREESINTERNAL__
#include "BTreesInternal.h"
#endif


/////////////////////////////////// Constants ///////////////////////////////////

#define		kBTreeVersion		  1
#define		kMaxTreeDepth		 16


#define		kHeaderNodeNum		  0
#define		kKeyDescRecord		  1


// Header Node Record Offsets
enum {
	kHeaderRecOffset	=	0x000E,
	kKeyDescRecOffset	=	0x0078,
	kHeaderMapRecOffset	=	0x00F8
};

#define		kMinNodeSize		512

#define		kMinRecordSize		  6
										// where is minimum record size enforced?

// miscellaneous BTree constants
enum {
			kOffsetSize				= 2
};

// Insert Operations
typedef enum {
			kInsertRecord			= 0,
			kReplaceRecord			= 1
} InsertType;

// illegal string attribute bits set in mask
#define		kBadStrAttribMask		0xCF



//////////////////////////////////// Macros /////////////////////////////////////

#define		M_NodesInMap(mapSize)				((mapSize) << 3)

#define		M_ClearBitNum(integer,bitNumber) 	((integer) &= (~(1<<(bitNumber))))
#define		M_SetBitNum(integer,bitNumber) 		((integer) |= (1<<(bitNumber)))
#define		M_IsOdd(integer) 					(((integer) & 1) != 0)
#define		M_IsEven(integer) 					(((integer) & 1) == 0)
#define		M_BTreeHeaderDirty(btreePtr)		btreePtr->flags |= kBTHeaderDirty

#define		M_MapRecordSize(nodeSize)			(nodeSize - sizeof (BTNodeDescriptor) - 6)
#define		M_HeaderMapRecordSize(nodeSize)		(nodeSize - sizeof(BTNodeDescriptor) - sizeof(BTHeaderRec) - 128 - 8)

#define		M_SWAP_BE16_ClearBitNum(integer,bitNumber)  ((integer) &= SWAP_BE16(~(1<<(bitNumber))))
#define		M_SWAP_BE16_SetBitNum(integer,bitNumber)    ((integer) |= SWAP_BE16(1<<(bitNumber)))

///////////////////////////////////// Types /////////////////////////////////////

typedef struct BTreeControlBlock {					// fields specific to BTree CBs

	UInt8		keyCompareType;   /* Key string Comparison Type */
	UInt8						 btreeType;
	UInt16						 treeDepth;
	FileReference				 fileRefNum;		// refNum of btree file
	KeyCompareProcPtr			 keyCompareProc;
	UInt32						 rootNode;
	UInt32						 leafRecords;
	UInt32						 firstLeafNode;
	UInt32						 lastLeafNode;
	UInt16						 nodeSize;
	UInt16						 maxKeyLength;
	UInt32						 totalNodes;
	UInt32						 freeNodes;

	UInt16						 reserved3;			// 4-byte alignment

	// new fields
	SInt16						 version;
	UInt32						 flags;				// dynamic flags
	UInt32						 attributes;		// persistent flags
	UInt32						 writeCount;
	UInt32						 lastfsync;		/* Last time that this was fsynced  */

	GetBlockProcPtr			 	 getBlockProc;
	ReleaseBlockProcPtr			 releaseBlockProc;
	SetEndOfForkProcPtr			 setEndOfForkProc;

	// statistical information
	UInt32						 numGetNodes;
	UInt32						 numGetNewNodes;
	UInt32						 numReleaseNodes;
	UInt32						 numUpdateNodes;
	UInt32						 numMapNodesRead;	// map nodes beyond header node
	UInt32						 numHintChecks;
	UInt32						 numPossibleHints;	// Looks like a formated hint
	UInt32						 numValidHints;		// Hint used to find correct record.
	UInt32					reservedNodes;
} BTreeControlBlock, *BTreeControlBlockPtr;


UInt32 CalcKeySize(const BTreeControlBlock *btcb, const BTreeKey *key);
#define CalcKeySize(btcb, key)			( ((btcb)->attributes & kBTBigKeysMask) ? ((key)->length16 + 2) : ((key)->length8 + 1) )

UInt32 KeyLength(const BTreeControlBlock *btcb, const BTreeKey *key);
#define KeyLength(btcb, key)			( ((btcb)->attributes & kBTBigKeysMask) ? (key)->length16 : (key)->length8 )



typedef enum {
					kBTHeaderDirty	= 0x00000001
}	BTreeFlags;


typedef	SInt8				*NodeBuffer;
typedef BlockDescriptor		 NodeRec, *NodePtr;		//€€ remove this someday...




//// Tree Path Table - constructed by SearchTree, used by InsertTree and DeleteTree

typedef struct {
	UInt32				node;				// node number
	UInt16				index;
	UInt16				reserved;			// align size to a power of 2
} TreePathRecord, *TreePathRecordPtr;

typedef TreePathRecord		TreePathTable [kMaxTreeDepth];


//// InsertKey - used by InsertTree, InsertLevel and InsertNode

struct InsertKey {
	BTreeKeyPtr		keyPtr;
	UInt8 *			recPtr;
	UInt16			keyLength;
	UInt16			recSize;
	Boolean			replacingKey;
	Boolean			skipRotate;
};

typedef struct InsertKey InsertKey;


//// For Notational Convenience

typedef	BTNodeDescriptor*	 NodeDescPtr;
typedef UInt8				*RecordPtr;
typedef BTreeKeyPtr			 KeyPtr;


//////////////////////////////////// Globals ////////////////////////////////////


//////////////////////////////////// Macros /////////////////////////////////////

#if DEBUG_BUILD
	#define Panic( message )					DebugStr( (ConstStr255Param) message )
	#define PanicIf( condition, message )		if ( condition != 0 )	DebugStr( message )
#else
	#define Panic( message )
	#define PanicIf( condition, message )
#endif

//	Exit function on error
#define M_ExitOnError( result )	if ( ( result ) != noErr )	goto ErrorExit; else ;

//	Test for passed condition and return if true
#define	M_ReturnErrorIf( condition, error )	if ( condition )	return( error )

//////////////////////////////// Key Operations /////////////////////////////////

SInt32		CompareKeys				(BTreeControlBlockPtr	 btreePtr,
									 KeyPtr					 searchKey,
									 KeyPtr					 trialKey );

//////////////////////////////// Map Operations /////////////////////////////////

OSStatus	AllocateNode			(BTreeControlBlockPtr	 btreePtr,
									 UInt32					*nodeNum);

OSStatus	FreeNode				(BTreeControlBlockPtr	 btreePtr,
									 UInt32					 nodeNum);

OSStatus	ExtendBTree				(BTreeControlBlockPtr	 btreePtr,
									 UInt32					 nodes );

UInt32		CalcMapBits				(BTreeControlBlockPtr	 btreePtr);

SInt32		BTAvailableNodes			(BTreeControlBlock *btree);

void 		BTUpdateReserve				(BTreeControlBlockPtr btreePtr,
                                                         int nodes);

//////////////////////////////// Misc Operations ////////////////////////////////

UInt16		CalcKeyRecordSize		(UInt16					 keySize,
									 UInt16					 recSize );

OSStatus	VerifyHeader			(FCB					*filePtr,
									 BTHeaderRec				*header );

OSStatus	UpdateHeader			(BTreeControlBlockPtr	 btreePtr,
						 Boolean forceWrite );

OSStatus	FindIteratorPosition	(BTreeControlBlockPtr	 btreePtr,
									 BTreeIteratorPtr		 iterator,
									 BlockDescriptor		*left,
									 BlockDescriptor		*middle,
									 BlockDescriptor		*right,
									 UInt32					*nodeNum,
									 UInt16					*index,
									 Boolean				*foundRecord );

OSStatus	CheckInsertParams		(FCB					*filePtr,
									 BTreeIterator			*iterator,
									 FSBufferDescriptor		*record,
									 UInt16					 recordLen );

OSStatus	TrySimpleReplace		(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 nodePtr,
									 BTreeIterator			*iterator,
									 FSBufferDescriptor		*record,
									 UInt16					 recordLen,
									 Boolean				*recordInserted );

OSStatus	IsItAHint				(BTreeControlBlockPtr 	 btreePtr, 
									 BTreeIterator 			*iterator, 
									 Boolean 				*answer );

//////////////////////////////// Node Operations ////////////////////////////////

//// Node Operations

OSStatus	GetNode					(BTreeControlBlockPtr	 btreePtr,
									 UInt32					 nodeNum,
									 NodeRec				*returnNodePtr );

OSStatus	GetLeftSiblingNode		(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node,
									 NodeRec				*left );

#define		GetLeftSiblingNode(btree,node,left)			GetNode ((btree), ((NodeDescPtr)(node))->bLink, (left))

OSStatus	GetRightSiblingNode		(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node,
									 NodeRec				*right );

#define		GetRightSiblingNode(btree,node,right)		GetNode ((btree), ((NodeDescPtr)(node))->fLink, (right))


OSStatus	GetNewNode				(BTreeControlBlockPtr	 btreePtr,
									 UInt32					 nodeNum,
									 NodeRec				*returnNodePtr );

OSStatus	ReleaseNode				(BTreeControlBlockPtr	 btreePtr,
									 NodePtr				 nodePtr );

OSStatus	TrashNode				(BTreeControlBlockPtr	 btreePtr,
									 NodePtr				 nodePtr );

// XXXdbg
void ModifyBlockStart(FileReference vp, BlockDescPtr blockPtr);
// XXXdbg

OSStatus	UpdateNode				(BTreeControlBlockPtr	 btreePtr,
									 NodePtr				 nodePtr,
									 UInt32					 transactionID,
									 UInt32					 flags );

OSStatus	GetMapNode				(BTreeControlBlockPtr	 btreePtr,
									 BlockDescriptor		 *nodePtr,
									 UInt16					 **mapPtr,
									 UInt16					 *mapSize );

//// Node Buffer Operations

void		ClearNode				(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node );

UInt16		GetNodeDataSize			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node );

UInt16		GetNodeFreeSize			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node );


//// Record Operations

Boolean		InsertRecord			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr	 		 node,
									 UInt16	 				 index,
									 RecordPtr				 recPtr,
									 UInt16					 recSize );

Boolean		InsertKeyRecord			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr 			 node,
									 UInt16	 				 index,
									 KeyPtr					 keyPtr,
									 UInt16					 keyLength,
									 RecordPtr				 recPtr,
									 UInt16					 recSize );

void		DeleteRecord			(BTreeControlBlockPtr	btree,
									 NodeDescPtr	 		node,
									 UInt16	 				index );


Boolean		SearchNode				(BTreeControlBlockPtr	 btree,
									 NodeDescPtr			 node,
									 KeyPtr					 searchKey,
									 UInt16					*index );

OSStatus	GetRecordByIndex		(BTreeControlBlockPtr	 btree,
									 NodeDescPtr			 node,
									 UInt16					 index,
									 KeyPtr					*keyPtr,
									 UInt8 *				*dataPtr,
									 UInt16					*dataSize );

UInt8 *		GetRecordAddress		(BTreeControlBlockPtr	 btree,
									 NodeDescPtr			 node,
									 UInt16					 index );

#define GetRecordAddress(btreePtr,node,index)		((UInt8 *)(node) + (*(short *) ((UInt8 *)(node) + (btreePtr)->nodeSize - ((index) << 1) - kOffsetSize)))


UInt16		GetRecordSize			(BTreeControlBlockPtr	 btree,
									 NodeDescPtr			 node,
									 UInt16					 index );

UInt32		GetChildNodeNum			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 nodePtr,
									 UInt16					 index );

void		MoveRecordsLeft			(UInt8 *				 src,
									 UInt8 *				 dst,
									 UInt16					 bytesToMove );

#define		MoveRecordsLeft(src,dst,bytes)			bcopy((src),(dst),(bytes))

void		MoveRecordsRight		(UInt8 *				 src,
									 UInt8 *				 dst,
									 UInt16					 bytesToMove );

#define		MoveRecordsRight(src,dst,bytes)			bcopy((src),(dst),(bytes))


//////////////////////////////// Tree Operations ////////////////////////////////

OSStatus	SearchTree				(BTreeControlBlockPtr	 btreePtr,
									 BTreeKeyPtr			 keyPtr,
									 TreePathTable			 treePathTable,
									 UInt32					*nodeNum,
									 BlockDescriptor		*nodePtr,
									 UInt16					*index );

OSStatus	InsertTree				(BTreeControlBlockPtr	 btreePtr,
									 TreePathTable			 treePathTable,
									 KeyPtr					 keyPtr,
									 UInt8 *				 recPtr,
									 UInt16					 recSize,
									 BlockDescriptor		*targetNode,
									 UInt16					 index,
									 UInt16					 level,
									 Boolean				 replacingKey,
									 UInt32					*insertNode );

OSStatus	DeleteTree				(BTreeControlBlockPtr	 btreePtr,
									 TreePathTable			 treePathTable,
									 BlockDescriptor		*targetNode,
									 UInt16					 index,
									 UInt16					 level );

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif //__BTREESPRIVATE__
