/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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

	u_int8_t		keyCompareType;   /* Key string Comparison Type */
	u_int8_t					 btreeType;
	u_int16_t					 treeDepth;
	FileReference				 fileRefNum;		// refNum of btree file
	KeyCompareProcPtr			 keyCompareProc;
	u_int32_t					 rootNode;
	u_int32_t					 leafRecords;
	u_int32_t					 firstLeafNode;
	u_int32_t					 lastLeafNode;
	u_int16_t					 nodeSize;
	u_int16_t					 maxKeyLength;
	u_int32_t					 totalNodes;
	u_int32_t					 freeNodes;

	u_int16_t					 reserved3;			// 4-byte alignment

	// new fields
	int16_t						 version;
	u_int32_t					 flags;				// dynamic flags
	u_int32_t					 attributes;		// persistent flags
	u_int32_t					 writeCount;
	u_int32_t					 lastfsync;		/* Last time that this was fsynced  */

	GetBlockProcPtr			 	 getBlockProc;
	ReleaseBlockProcPtr			 releaseBlockProc;
	SetEndOfForkProcPtr			 setEndOfForkProc;

	// statistical information
	u_int32_t					 numGetNodes;
	u_int32_t					 numGetNewNodes;
	u_int32_t					 numReleaseNodes;
	u_int32_t					 numUpdateNodes;
	u_int32_t					 numMapNodesRead;	// map nodes beyond header node
	u_int32_t					 numHintChecks;
	u_int32_t					 numPossibleHints;	// Looks like a formated hint
	u_int32_t					 numValidHints;		// Hint used to find correct record.
	u_int32_t					reservedNodes;
	BTreeIterator   iterator; // useable when holding exclusive b-tree lock
} BTreeControlBlock, *BTreeControlBlockPtr;


u_int32_t CalcKeySize(const BTreeControlBlock *btcb, const BTreeKey *key);
#define CalcKeySize(btcb, key)			( ((btcb)->attributes & kBTBigKeysMask) ? ((key)->length16 + 2) : ((key)->length8 + 1) )

u_int32_t KeyLength(const BTreeControlBlock *btcb, const BTreeKey *key);
#define KeyLength(btcb, key)			( ((btcb)->attributes & kBTBigKeysMask) ? (key)->length16 : (key)->length8 )



typedef enum {
					kBTHeaderDirty	= 0x00000001
}	BTreeFlags;


typedef	int8_t				*NodeBuffer;
typedef BlockDescriptor		 NodeRec, *NodePtr;		//€€ remove this someday...




//// Tree Path Table - constructed by SearchTree, used by InsertTree and DeleteTree

typedef struct {
	u_int32_t				node;				// node number
	u_int16_t				index;
	u_int16_t				reserved;			// align size to a power of 2
} TreePathRecord, *TreePathRecordPtr;

typedef TreePathRecord		TreePathTable [kMaxTreeDepth];


//// InsertKey - used by InsertTree, InsertLevel and InsertNode

struct InsertKey {
	BTreeKeyPtr		keyPtr;
	u_int8_t *		recPtr;
	u_int16_t		keyLength;
	u_int16_t		recSize;
	Boolean			replacingKey;
	Boolean			skipRotate;
};

typedef struct InsertKey InsertKey;


//// For Notational Convenience

typedef	BTNodeDescriptor*	 NodeDescPtr;
typedef u_int8_t			*RecordPtr;
typedef BTreeKeyPtr			 KeyPtr;


//////////////////////////////////// Globals ////////////////////////////////////


//////////////////////////////////// Macros /////////////////////////////////////

#if DEBUG_BUILD
	#define Panic( message )					DebugStr( message )
	#define PanicIf( condition, message )		do { if ( condition != 0 )	DebugStr( message ); } while(0)
#else
	#define Panic( message )				do { } while(0)
	#define PanicIf( condition, message )	do { } while(0)
#endif

//	Exit function on error
#define M_ExitOnError( result )	do { if ( ( result ) != noErr )	goto ErrorExit; } while(0)

//	Test for passed condition and return if true
#define	M_ReturnErrorIf( condition, error )	do { if ( condition )	return( error ); } while(0)

//////////////////////////////// Key Operations /////////////////////////////////

int32_t		CompareKeys				(BTreeControlBlockPtr	 btreePtr,
									 KeyPtr					 searchKey,
									 KeyPtr					 trialKey );

//////////////////////////////// Map Operations /////////////////////////////////

OSStatus	AllocateNode			(BTreeControlBlockPtr	 btreePtr,
									 u_int32_t				*nodeNum);

OSStatus	FreeNode				(BTreeControlBlockPtr	 btreePtr,
									 u_int32_t				 nodeNum);

OSStatus	ExtendBTree				(BTreeControlBlockPtr	 btreePtr,
									 u_int32_t				 nodes );

u_int32_t	CalcMapBits				(BTreeControlBlockPtr	 btreePtr);


void 		BTUpdateReserve				(BTreeControlBlockPtr btreePtr,
                                                         int nodes);

//////////////////////////////// Misc Operations ////////////////////////////////

u_int16_t	CalcKeyRecordSize		(u_int16_t				 keySize,
									 u_int16_t				 recSize );

OSStatus	VerifyHeader			(FCB					*filePtr,
									 BTHeaderRec				*header );

OSStatus	UpdateHeader			(BTreeControlBlockPtr	 btreePtr,
						 Boolean forceWrite );

OSStatus	FindIteratorPosition	(BTreeControlBlockPtr	 btreePtr,
									 BTreeIteratorPtr		 iterator,
									 BlockDescriptor		*left,
									 BlockDescriptor		*middle,
									 BlockDescriptor		*right,
									 u_int32_t				*nodeNum,
									 u_int16_t				*index,
									 Boolean				*foundRecord );

OSStatus	CheckInsertParams		(FCB					*filePtr,
									 BTreeIterator			*iterator,
									 FSBufferDescriptor		*record,
									 u_int16_t				 recordLen );

OSStatus	TrySimpleReplace		(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 nodePtr,
									 BTreeIterator			*iterator,
									 FSBufferDescriptor		*record,
									 u_int16_t				 recordLen,
									 Boolean				*recordInserted );

OSStatus	IsItAHint				(BTreeControlBlockPtr 	 btreePtr, 
									 BTreeIterator 			*iterator, 
									 Boolean 				*answer );

extern OSStatus TreeIsDirty(BTreeControlBlockPtr btreePtr);

//////////////////////////////// Node Operations ////////////////////////////////

//// Node Operations

OSStatus	GetNode					(BTreeControlBlockPtr	 btreePtr,
									 u_int32_t				 nodeNum,
									 u_int32_t 				 flags, 
									 NodeRec				*returnNodePtr );

/* Flags for GetNode() */
#define		kGetNodeHint	0x1		/* If set, the node is being looked up using a hint */

OSStatus	GetLeftSiblingNode		(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node,
									 NodeRec				*left );

#define		GetLeftSiblingNode(btree,node,left)			GetNode ((btree), ((NodeDescPtr)(node))->bLink, 0, (left))

OSStatus	GetRightSiblingNode		(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node,
									 NodeRec				*right );

#define		GetRightSiblingNode(btree,node,right)		GetNode ((btree), ((NodeDescPtr)(node))->fLink, 0, (right))


OSStatus	GetNewNode				(BTreeControlBlockPtr	 btreePtr,
									 u_int32_t				 nodeNum,
									 NodeRec				*returnNodePtr );

OSStatus	ReleaseNode				(BTreeControlBlockPtr	 btreePtr,
									 NodePtr				 nodePtr );

OSStatus	TrashNode				(BTreeControlBlockPtr	 btreePtr,
									 NodePtr				 nodePtr );

OSStatus	UpdateNode				(BTreeControlBlockPtr	 btreePtr,
									 NodePtr				 nodePtr,
									 u_int32_t				 transactionID,
									 u_int32_t				 flags );

//// Node Buffer Operations

void		ClearNode				(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node );

u_int16_t	GetNodeDataSize			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node );

u_int16_t	GetNodeFreeSize			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 node );


//// Record Operations

Boolean		InsertRecord			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr	 		 node,
									 u_int16_t	 			 index,
									 RecordPtr				 recPtr,
									 u_int16_t				 recSize );

Boolean		InsertKeyRecord			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr 			 node,
									 u_int16_t	 			 index,
									 KeyPtr					 keyPtr,
									 u_int16_t				 keyLength,
									 RecordPtr				 recPtr,
									 u_int16_t				 recSize );

void		DeleteRecord			(BTreeControlBlockPtr	btree,
									 NodeDescPtr	 		node,
									 u_int16_t	 			index );


Boolean		SearchNode				(BTreeControlBlockPtr	 btree,
									 NodeDescPtr			 node,
									 KeyPtr					 searchKey,
									 u_int16_t				*index );

OSStatus	GetRecordByIndex		(BTreeControlBlockPtr	 btree,
									 NodeDescPtr			 node,
									 u_int16_t				 index,
									 KeyPtr					*keyPtr,
									 u_int8_t *				*dataPtr,
									 u_int16_t				*dataSize );

u_int8_t *	GetRecordAddress		(BTreeControlBlockPtr	 btree,
									 NodeDescPtr			 node,
									 u_int16_t				 index );

#define GetRecordAddress(btreePtr,node,index)		((u_int8_t *)(node) + (*(short *) ((u_int8_t *)(node) + (btreePtr)->nodeSize - ((index) << 1) - kOffsetSize)))


u_int16_t	GetRecordSize			(BTreeControlBlockPtr	 btree,
									 NodeDescPtr			 node,
									 u_int16_t				 index );

u_int32_t	GetChildNodeNum			(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 nodePtr,
									 u_int16_t				 index );

void		MoveRecordsLeft			(u_int8_t *				 src,
									 u_int8_t *				 dst,
									 u_int16_t				 bytesToMove );

#define		MoveRecordsLeft(src,dst,bytes)			bcopy((src),(dst),(bytes))

void		MoveRecordsRight		(u_int8_t *				 src,
									 u_int8_t *				 dst,
									 u_int16_t				 bytesToMove );

#define		MoveRecordsRight(src,dst,bytes)			bcopy((src),(dst),(bytes))


//////////////////////////////// Tree Operations ////////////////////////////////

OSStatus	SearchTree				(BTreeControlBlockPtr	 btreePtr,
									 BTreeKeyPtr			 keyPtr,
									 TreePathTable			 treePathTable,
									 u_int32_t				*nodeNum,
									 BlockDescriptor		*nodePtr,
									 u_int16_t				*index );

OSStatus	InsertTree				(BTreeControlBlockPtr	 btreePtr,
									 TreePathTable			 treePathTable,
									 KeyPtr					 keyPtr,
									 u_int8_t *				 recPtr,
									 u_int16_t				 recSize,
									 BlockDescriptor		*targetNode,
									 u_int16_t				 index,
									 u_int16_t				 level,
									 Boolean				 replacingKey,
									 u_int32_t				*insertNode );

OSStatus	DeleteTree				(BTreeControlBlockPtr	 btreePtr,
									 TreePathTable			 treePathTable,
									 BlockDescriptor		*targetNode,
									 u_int16_t				 index,
									 u_int16_t				 level );

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif //__BTREESPRIVATE__
