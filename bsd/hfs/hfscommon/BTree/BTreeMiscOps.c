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
	File:		BTreeMiscOps.c

	Contains:	Miscellaneous operations for the BTree Module.

	Version:	xxx put the technology version here xxx

	Written by:	Gordon Sheridan and Bill Bruffey

	Copyright:	© 1992-1999 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Don Brady

		Other Contact:		Mark Day

		Technology:			File Systems

	Writers:

		(DSH)	Deric Horn
		(msd)	Mark Day
		(djb)	Don Brady

	Change History (most recent first):

	   <MOSXS>	  6/1/99	djb		Sync up with Mac OS 8.6.
	   <CS2>	  9/4/97	djb		Optimize TrySimpleReplace for the case where record size is not
									changing.
	   <CS1>	 4/23/97	djb		first checked in

	  <HFS7>	 3/31/97	djb		Move ClearMemory to Utilities.c.
	  <HFS6>	 3/17/97	DSH		Casting for DFA
	  <HFS5>	 2/27/97	msd		Remove temporary fix from last revision. BTree EOF's should be
									correct now, so check for strict equality.
	  <HFS4>	 2/26/97	msd		Fix a casting problem in ClearMemory. TEMPORARY FIX: Made
									VerifyHeader more lenient, allowing the EOF to be greater than
									the amount actually used by nodes; this should really be fixed
									in the formatting code (which needs to compute the real BTree
									sizes before writing the volume header).
	  <HFS3>	 2/19/97	djb		Added ClearMemory. Changed CalcKeyLength to KeyLength.
	  <HFS2>	  1/3/97	djb		Added support for large keys.
	  <HFS1>	12/19/96	djb		first checked in

	History applicable to original Scarecrow Design:

		 <9>	10/25/96	ser		Changing for new VFPI
		 <8>	10/18/96	ser		Converting over VFPI changes
		 <7>	 9/17/96	dkh		More BTree statistics. Change IsItAHint to not always check to
									see if the hint node is allocated.
		 <6>	 9/16/96	dkh		Revised BTree statistics.
		 <5>	 6/20/96	dkh		Radar #1358740. Change from using Pools to debug MemAllocators.
		 <4>	 1/22/96	dkh		Change Pools.i inclusion to PoolsPriv.i
		 <3>	 1/10/96	msd		Change 64-bit math to use real function names from Math64.i.
		 <2>	 12/7/95	dkh		D10E2 build. Changed usage of Ref data type to LogicalAddress.
		 <1>	10/18/95	rst		Moved from Scarecrow project.

		<19>	 4/26/95	prp		In UpdateHeader, clear the dirty flag after the BTree is updated.
		<18>	 1/12/95	wjk		Adopt Model FileSystem changes in D5.
		<17>	11/16/94	prp		Add IsItAHint routine and use it whenever hint's node number was
									used for testing.
		<16>	 10/5/94	bk		add pools.h include file
		<15>	 9/30/94	prp		Get in sync with D2 interface changes.
		<14>	 7/22/94	wjk		Convert to the new set of header files.
		<13>	 12/2/93	wjk		Move from Makefiles to BuildFiles. Fit into the ModernOS and
									NRCmds environments.
		<12>	11/30/93	wjk		Move from Makefiles to BuildFiles. Fit into the ModernOS and
									NRCmds environments.
		<11>	11/23/93	wjk		Changes required to compile on the RS6000.
		<10>	 8/31/93	prp		Use U64SetU instead of S64Set.
		 <9>	  6/2/93	gs		Update for changes to FSErrors.h and add some comments.
		 <8>	 5/21/93	gs		Modify UpdateHeader to write out attributes. Remove
									Get/UpdateNode from TrySimpleReplace.
		 <7>	 5/10/93	gs		Add TrySimpleReplace routine.
		 <6>	 3/23/93	gs		Change MoveData to take void * instead of Ptr. Add UpdateHeader
									and ClearBytes routines.
		 <5>	  2/8/93	gs		Add FindIteratorPosition.
		 <4>	12/10/92	gs		Implement CheckKeyDescriptor and the KeyDescriptor interpreter.
		 <3>	 12/8/92	gs		Add GetKeyDescriptor, VerifyHeader, and Alloc/Dealloc memory
									routines.
		 <2>	 12/2/92	gs		Add CompareKeys routine.
		 <1>	11/15/92	gs		first checked in

*/

#include "../headers/BTreesPrivate.h"


////////////////////////////// Routine Definitions //////////////////////////////

/*-------------------------------------------------------------------------------
Routine:	CalcKeyRecordSize	-	Return size of combined key/record structure.

Function:	Rounds keySize and recSize so they will end on word boundaries.
			Does NOT add size of offset.

Input:		keySize		- length of key (including length field)
			recSize		- length of record data

Output:		none
			
Result:		UInt16		- size of combined key/record that will be inserted in btree
-------------------------------------------------------------------------------*/

UInt16		CalcKeyRecordSize		(UInt16					 keySize,
									 UInt16					 recSize )
{
	if ( M_IsOdd (keySize) )	keySize += 1;	// pad byte
	
	if (M_IsOdd (recSize) )		recSize += 1;	// pad byte
	
	return	(keySize + recSize);
}



/*-------------------------------------------------------------------------------
Routine:	VerifyHeader	-	Validate fields of the BTree header record.

Function:	Examines the fields of the BTree header record to determine if the
			fork appears to contain a valid BTree.
			
Input:		forkPtr		- pointer to fork control block
			header		- pointer to BTree header
			
			
Result:		noErr		- success
			!= noErr	- failure
-------------------------------------------------------------------------------*/

OSStatus	VerifyHeader	(FCB				*filePtr,
							 BTHeaderRec			 *header )
{
	UInt64		forkSize;
	UInt32		totalNodes;
	

	switch (header->nodeSize)							// node size == 512*2^n
	{
		case   512:
		case  1024:
		case  2048:
		case  4096:
		case  8192:
		case 16384:
		case 32768:		break;
		default:		return	fsBTInvalidHeaderErr;			//€€ E_BadNodeType
	}
	
	totalNodes = header->totalNodes;

	forkSize = (UInt64)totalNodes * (UInt64)header->nodeSize;
	
	if ( forkSize != filePtr->fcbEOF )
		return fsBTInvalidHeaderErr;
	
	if ( header->freeNodes >= totalNodes )
		return fsBTInvalidHeaderErr;
	
	if ( header->rootNode >= totalNodes )
		return fsBTInvalidHeaderErr;
	
	if ( header->firstLeafNode >= totalNodes )
		return fsBTInvalidHeaderErr;
	
	if ( header->lastLeafNode >= totalNodes )
		return fsBTInvalidHeaderErr;
	
	if ( header->treeDepth > kMaxTreeDepth )
		return fsBTInvalidHeaderErr;


	/////////////////////////// Check BTree Type ////////////////////////////////
	
	switch (header->btreeType)
	{
		case	0:					// HFS Type - no Key Descriptor
		case	kUserBTreeType:		// with Key Descriptors etc.
		case	kReservedBTreeType:	// Desktop Mgr BTree ?
									break;

		default:					return fsBTUnknownVersionErr;		
	}
	
	return noErr;
}



__private_extern__
OSStatus TreeIsDirty(BTreeControlBlockPtr btreePtr)
{
    return (btreePtr->flags & kBTHeaderDirty);
}



/*-------------------------------------------------------------------------------
Routine:	UpdateHeader	-	Write BTreeInfoRec fields to Header node.

Function:	Checks the kBTHeaderDirty flag in the BTreeInfoRec and updates the
			header node if necessary.
			
Input:		btreePtr		- pointer to BTreeInfoRec
			
			
Result:		noErr		- success
			!= noErr	- failure
-------------------------------------------------------------------------------*/

OSStatus UpdateHeader(BTreeControlBlockPtr btreePtr, Boolean forceWrite)
{
	OSStatus				err;
	BlockDescriptor			node;
	BTHeaderRec	*header;	
	UInt32 options;

	if ((btreePtr->flags & kBTHeaderDirty) == 0)			// btree info already flushed
	return	noErr;
	
	
	err = GetNode (btreePtr, kHeaderNodeNum, &node );
	if (err != noErr) {
		return	err;
	}
	
	// XXXdbg
	ModifyBlockStart(btreePtr->fileRefNum, &node);

	header = (BTHeaderRec*) ((char *)node.buffer + sizeof(BTNodeDescriptor));
	
	header->treeDepth		= btreePtr->treeDepth;
	header->rootNode		= btreePtr->rootNode;
	header->leafRecords		= btreePtr->leafRecords;
	header->firstLeafNode	= btreePtr->firstLeafNode;
	header->lastLeafNode	= btreePtr->lastLeafNode;
	header->nodeSize		= btreePtr->nodeSize;			//€€ this shouldn't change
	header->maxKeyLength	= btreePtr->maxKeyLength;		//€€ neither should this
	header->totalNodes		= btreePtr->totalNodes;
	header->freeNodes		= btreePtr->freeNodes;
	header->btreeType		= btreePtr->btreeType;

	// ignore	header->clumpSize;							//€€ rename this field?

	if (forceWrite)
		options = kForceWriteBlock;
	else
		options = kLockTransaction;

	err = UpdateNode (btreePtr, &node, 0, options);

	btreePtr->flags &= (~kBTHeaderDirty);

	return	err;
}



/*-------------------------------------------------------------------------------
Routine:	FindIteratorPosition	-	One_line_description.

Function:	Brief_description_of_the_function_and_any_side_effects

Algorithm:	see FSC.BT.BTIterateRecord.PICT

Note:		//€€ document side-effects of bad node hints

Input:		btreePtr		- description
			iterator		- description
			

Output:		iterator		- description
			left			- description
			middle			- description
			right			- description
			nodeNum			- description
			returnIndex		- description
			foundRecord		- description
			
			
Result:		noErr		- success
			!= noErr	- failure
-------------------------------------------------------------------------------*/

OSStatus	FindIteratorPosition	(BTreeControlBlockPtr	 btreePtr,
									 BTreeIteratorPtr		 iterator,
									 BlockDescriptor		*left,
									 BlockDescriptor		*middle,
									 BlockDescriptor		*right,
									 UInt32					*returnNodeNum,
									 UInt16					*returnIndex,
									 Boolean				*foundRecord )
{
	OSStatus		err;
	Boolean			foundIt;
	UInt32			nodeNum;
	UInt16			leftIndex,	index,	rightIndex;
	Boolean			validHint;

	// assume btreePtr valid
	// assume left, middle, right point to BlockDescriptors
	// assume nodeNum points to UInt32
	// assume index points to UInt16
	// assume foundRecord points to Boolean
	
	left->buffer		= nil;
	left->blockHeader   = nil;
	middle->buffer		= nil;
	middle->blockHeader	= nil;
	right->buffer		= nil;
	right->blockHeader	= nil;
	
	foundIt				= false;
	
	if (iterator == nil)						// do we have an iterator?
	{
		err = fsBTInvalidIteratorErr;
		goto ErrorExit;
	}

	err = IsItAHint (btreePtr, iterator, &validHint);
	M_ExitOnError (err);

	nodeNum = iterator->hint.nodeNum;
	if (! validHint)							// does the hint appear to be valid?
	{
		goto SearchTheTree;
	}
	
	err = GetNode (btreePtr, nodeNum, middle);
	if( err == fsBTInvalidNodeErr )	// returned if nodeNum is out of range
		goto SearchTheTree;
		
	M_ExitOnError (err);
	
	if ( ((NodeDescPtr) middle->buffer)->kind != kBTLeafNode ||
		 ((NodeDescPtr) middle->buffer)->numRecords <= 0 )
	{	
		goto SearchTheTree;
	}
		
	++btreePtr->numValidHints;
	
	foundIt = SearchNode (btreePtr, middle->buffer, &iterator->key, &index);
	if (foundIt == true)
	{
		goto SuccessfulExit;
	}
	
	if (index == 0)
	{
		if (((NodeDescPtr) middle->buffer)->bLink == 0)		// before 1st btree record
		{
			goto SuccessfulExit;
		}
		
		nodeNum = ((NodeDescPtr) middle->buffer)->bLink;
		
		err = GetLeftSiblingNode (btreePtr, middle->buffer, left);
		M_ExitOnError (err);
		
		if ( ((NodeDescPtr) left->buffer)->kind != kBTLeafNode ||
			 ((NodeDescPtr) left->buffer)->numRecords <= 0 )
		{	
			goto SearchTheTree;
		}
		
		foundIt = SearchNode (btreePtr, left->buffer, &iterator->key, &leftIndex);
		if (foundIt == true)
		{
			*right			= *middle;
			*middle			= *left;
			left->buffer	= nil;
			index			= leftIndex;
			
			goto SuccessfulExit;
		}
		
		if (leftIndex == 0)									// we're lost!
		{
			goto SearchTheTree;
		}
		else if (leftIndex >= ((NodeDescPtr) left->buffer)->numRecords)
		{
			nodeNum = ((NodeDescPtr) left->buffer)->fLink;
			
			PanicIf (index != 0, "\pFindIteratorPosition: index != 0");	//€€ just checking...
			goto SuccessfulExit;
		}
		else
		{
			*right			= *middle;
			*middle			= *left;
			left->buffer	= nil;
			index			= leftIndex;
			
			goto SuccessfulExit;
		}
	}
	else if (index >= ((NodeDescPtr) middle->buffer)->numRecords)
	{
		if (((NodeDescPtr) middle->buffer)->fLink == 0)	// beyond last record
		{
			goto SuccessfulExit;
		}
		
		nodeNum = ((NodeDescPtr) middle->buffer)->fLink;
		
		err = GetRightSiblingNode (btreePtr, middle->buffer, right);
		M_ExitOnError (err);
		
		if ( ((NodeDescPtr) right->buffer)->kind != kBTLeafNode ||
			 ((NodeDescPtr) right->buffer)->numRecords <= 0 )
		{	
			goto SearchTheTree;
		}

		foundIt = SearchNode (btreePtr, right->buffer, &iterator->key, &rightIndex);
		if (rightIndex >= ((NodeDescPtr) right->buffer)->numRecords)		// we're lost
		{
			goto SearchTheTree;
		}
		else	// we found it, or rightIndex==0, or rightIndex<numRecs
		{
			*left			= *middle;
			*middle			= *right;
			right->buffer	= nil;
			index			= rightIndex;
			
			goto SuccessfulExit;
		}
	}

	
	//////////////////////////// Search The Tree ////////////////////////////////	

SearchTheTree:
	{
		TreePathTable	treePathTable;		// so we only use stack space if we need to

		err = ReleaseNode (btreePtr, left);			M_ExitOnError (err);
		err = ReleaseNode (btreePtr, middle);		M_ExitOnError (err);
		err = ReleaseNode (btreePtr, right);		M_ExitOnError (err);
	
		err = SearchTree ( btreePtr, &iterator->key, treePathTable, &nodeNum, middle, &index);
		switch (err)				//€€ separate find condition from exceptions
		{
			case noErr:			foundIt = true;				break;
			case fsBTRecordNotFoundErr:						break;
			default:				goto ErrorExit;
		}
	}

	/////////////////////////////// Success! ////////////////////////////////////

SuccessfulExit:
	
	*returnNodeNum	= nodeNum;
	*returnIndex 	= index;
	*foundRecord	= foundIt;
	
	return	noErr;
	
	
	////////////////////////////// Error Exit ///////////////////////////////////

ErrorExit:

	(void)	ReleaseNode (btreePtr, left);
	(void)	ReleaseNode (btreePtr, middle);
	(void)	ReleaseNode (btreePtr, right);

	*returnNodeNum	= 0;
	*returnIndex 	= 0;
	*foundRecord	= false;

	return	err;
}



/////////////////////////////// CheckInsertParams ///////////////////////////////

OSStatus	CheckInsertParams		(FCB						*filePtr,
									 BTreeIterator				*iterator,
									 FSBufferDescriptor			*record,
									 UInt16						 recordLen )
{
	BTreeControlBlockPtr	btreePtr;
	
	if (filePtr == nil)									return	paramErr;

	btreePtr = (BTreeControlBlockPtr) filePtr->fcbBTCBPtr;
	if (btreePtr == nil)								return	fsBTInvalidFileErr;
	if (iterator == nil)								return	paramErr;
	if (record	 == nil)								return	paramErr;
	
	//	check total key/record size limit
	if ( CalcKeyRecordSize (CalcKeySize(btreePtr, &iterator->key), recordLen) > (btreePtr->nodeSize >> 1))
		return	fsBTRecordTooLargeErr;
	
	return	noErr;
}



/*-------------------------------------------------------------------------------
Routine:	TrySimpleReplace	-	Attempts a simple insert, set, or replace.

Function:	If a hint exitst for the iterator, attempt to find the key in the hint
			node. If the key is found, an insert operation fails. If the is not
			found, a replace operation fails. If the key was not found, and the
			insert position is greater than 0 and less than numRecords, the record
			is inserted, provided there is enough freeSpace.  If the key was found,
			and there is more freeSpace than the difference between the new record
			and the old record, the old record is deleted and the new record is
			inserted.

Assumptions:	iterator key has already been checked by CheckKey


Input:		btreePtr		- description
			iterator		- description
			record			- description
			recordLen		- description
			operation		- description
			

Output:		recordInserted		- description
			
						
Result:		noErr			- success
			E_RecordExits		- insert operation failure
			!= noErr		- GetNode, ReleaseNode, UpdateNode returned an error
-------------------------------------------------------------------------------*/

OSStatus	TrySimpleReplace		(BTreeControlBlockPtr	 btreePtr,
									 NodeDescPtr			 nodePtr,
									 BTreeIterator			*iterator,
									 FSBufferDescriptor		*record,
									 UInt16					 recordLen,
									 Boolean				*recordInserted )
{
	UInt32				oldSpace;
	UInt32				spaceNeeded;
	UInt16				index;
	UInt16				keySize;
	Boolean				foundIt;
	Boolean				didItFit;
	
	
	*recordInserted	= false;								// we'll assume this won't work...
	
	if ( nodePtr->kind != kBTLeafNode )
		return	noErr;	// we're in the weeds!

	foundIt	= SearchNode (btreePtr, nodePtr, &iterator->key, &index);	

	if ( foundIt == false )
		return	noErr;	// we might be lost...
		
	keySize = CalcKeySize(btreePtr, &iterator->key);	// includes length field
	
	spaceNeeded	= CalcKeyRecordSize (keySize, recordLen);
	
	oldSpace = GetRecordSize (btreePtr, nodePtr, index);
	
	if ( spaceNeeded == oldSpace )
	{
		UInt8 *		dst;

		dst = GetRecordAddress (btreePtr, nodePtr, index);

		if ( M_IsOdd (keySize) )
			++keySize;			// add pad byte
		
		dst += keySize;		// skip over key to point at record

		BlockMoveData(record->bufferAddress, dst, recordLen);	// blast away...

		*recordInserted = true;
	}
	else if ( (GetNodeFreeSize(btreePtr, nodePtr) + oldSpace) >= spaceNeeded)
	{
		DeleteRecord (btreePtr, nodePtr, index);
	
		didItFit = InsertKeyRecord (btreePtr, nodePtr, index,
										&iterator->key, KeyLength(btreePtr, &iterator->key),
										record->bufferAddress, recordLen);
		PanicIf (didItFit == false, "\pTrySimpleInsert: InsertKeyRecord returned false!");

		*recordInserted = true;
	}
	// else not enough space...

	return	noErr;
}


/*-------------------------------------------------------------------------------
Routine:	IsItAHint	-	checks the hint within a BTreeInterator.

Function:	checks the hint within a BTreeInterator.  If it is non-zero, it may 
			possibly be valid. 

Input:		btreePtr	- pointer to control block for BTree file
			iterator	- pointer to BTreeIterator
			
Output:		answer		- true if the hint looks reasonable
						- false if the hint is 0
			
Result:		noErr			- success
-------------------------------------------------------------------------------*/


OSStatus	IsItAHint	(BTreeControlBlockPtr btreePtr, BTreeIterator *iterator, Boolean *answer)
{
	++btreePtr->numHintChecks;
	
#if DEBUG_BUILD
	if (iterator->hint.nodeNum >= btreePtr->totalNodes)
	{
		*answer = false;
	} else 

#endif
	if (iterator->hint.nodeNum == 0)
	{
		*answer = false;
	}
	else
	{
		*answer = true;
		++btreePtr->numPossibleHints;
	}
	
	return noErr;
}
