/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
	File:		FilesInternal.h

	Contains:	IPI for File Manager (HFS Plus)

	Version:	HFS Plus 1.0

	Copyright:	� 1996-2001 by Apple Computer, Inc., all rights reserved.

*/
#ifndef __FILEMGRINTERNAL__
#define __FILEMGRINTERNAL__

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE

#include <sys/param.h>
#include <sys/vnode.h>

#if !HFS_ALLOC_TEST

#include "../../hfs.h"
#include "../../hfs_macos_defs.h"
#include "../../hfs_format.h"
#include "../../hfs_cnode.h"

#endif

#ifdef __cplusplus
extern "C" {
#endif

/* CatalogNodeID is used to track catalog objects */
typedef u_int32_t		HFSCatalogNodeID;

/* internal error codes*/

#if TARGET_API_MACOS_X
  #define ERR_BASE	-32767
#else
  #define ERR_BASE	0
#endif

enum {
																/* FXM errors*/
	fxRangeErr					= ERR_BASE + 16,				/* file position beyond mapped range*/
	fxOvFlErr					= ERR_BASE + 17,				/* extents file overflow*/
																/* Unicode errors*/
	uniTooLongErr				= ERR_BASE + 24,				/* Unicode string too long to convert to Str31*/
	uniBufferTooSmallErr		= ERR_BASE + 25,				/* Unicode output buffer too small*/
	uniNotMappableErr			= ERR_BASE + 26,				/* Unicode string can't be mapped to given script*/
																/* BTree Manager errors*/
	btNotFound					= ERR_BASE + 32,				/* record not found*/
	btExists					= ERR_BASE + 33,				/* record already exists*/
	btNoSpaceAvail				= ERR_BASE + 34,				/* no available space*/
	btNoFit						= ERR_BASE + 35,				/* record doesn't fit in node */
	btBadNode					= ERR_BASE + 36,				/* bad node detected*/
	btBadHdr					= ERR_BASE + 37,				/* bad BTree header record detected*/
	dsBadRotate					= ERR_BASE + 64,				/* bad BTree rotate*/
																/* Catalog Manager errors*/
	cmNotFound					= ERR_BASE + 48,				/* CNode not found*/
	cmExists					= ERR_BASE + 49,				/* CNode already exists*/
	cmNotEmpty					= ERR_BASE + 50,				/* directory CNode not empty (valence = 0)*/
	cmRootCN					= ERR_BASE + 51,				/* invalid reference to root CNode*/
	cmBadNews					= ERR_BASE + 52,				/* detected bad catalog structure*/
	cmFThdDirErr				= ERR_BASE + 53,				/* thread belongs to a directory not a file*/
	cmFThdGone					= ERR_BASE + 54,				/* file thread doesn't exist*/
	cmParentNotFound			= ERR_BASE + 55,				/* CNode for parent ID does not exist*/
																/* TFS internal errors*/
	fsDSIntErr					= -127							/* Internal file system error*/
};


/* internal flags*/

enum {
	kEFAllMask      = 0x01,   /* allocate all requested bytes or none */
	kEFContigMask   = 0x02,   /* force contiguous allocation */
	kEFReserveMask  = 0x04,   /* keep block reserve */
	kEFDeferMask    = 0x08,   /* defer file block allocations */
	kEFNoClumpMask  = 0x10,   /* don't round up to clump size */
	kEFMetadataMask  = 0x20,  /* metadata allocation */

	kTFTrunExtBit				= 0,							/*	truncate to the extent containing new PEOF*/
	kTFTrunExtMask				= 1
};

enum {
	kUndefinedStrLen			= 0,							/* Unknown string length */
	kNoHint						= 0,

																/*	FileIDs variables*/
	kNumExtentsToCache			= 4								/*	just guessing for ExchangeFiles*/
};


/* Universal Extent Key */

union ExtentKey {
	HFSExtentKey 					hfs;
	HFSPlusExtentKey 				hfsPlus;
};
typedef union ExtentKey					ExtentKey;
/* Universal extent descriptor */

union ExtentDescriptor {
	HFSExtentDescriptor 			hfs;
	HFSPlusExtentDescriptor 		hfsPlus;
};
typedef union ExtentDescriptor			ExtentDescriptor;
/* Universal extent record */

union ExtentRecord {
	HFSExtentRecord 				hfs;
	HFSPlusExtentRecord 			hfsPlus;
};
typedef union ExtentRecord				ExtentRecord;


enum {
	CMMaxCName					= kHFSMaxFileNameChars
};



/* Universal catalog name*/

union CatalogName {
	Str31 							pstr;
	HFSUniStr255 					ustr;
};
typedef union CatalogName CatalogName;


/*
 * MacOS accessor routines
 */
#define GetFileControlBlock(fref)		VTOF((fref))
#define GetFileRefNumFromFCB(fcb)		FTOV((fcb))

/*	Test for error and return if error occurred*/
EXTERN_API_C( void )
ReturnIfError					(OSErr 					result);

#define	ReturnIfError(result)				do {	if ( (result) != noErr ) return (result); } while(0)

/*	Exit function on error*/
EXTERN_API_C( void )
ExitOnError						(OSErr 					result);

#define	ExitOnError( result )				do {	if ( ( result ) != noErr )	goto ErrorExit; } while(0)



/* Catalog Manager Routines (IPI)*/

EXTERN_API_C( OSErr )
ExchangeFileIDs					(ExtendedVCB *			volume,
								 ConstUTF8Param			srcName,
								 ConstUTF8Param			destName,
								 HFSCatalogNodeID		srcID,
								 HFSCatalogNodeID		destID,
								 u_int32_t				srcHint,
								 u_int32_t				destHint );

EXTERN_API_C( OSErr )
MoveData( ExtendedVCB *vcb, HFSCatalogNodeID srcID, HFSCatalogNodeID destID, int rsrc);

/* BTree Manager Routines*/

typedef CALLBACK_API_C( int32_t , KeyCompareProcPtr )(void *a, void *b);


EXTERN_API_C( OSErr )
ReplaceBTreeRecord				(FileReference 				refNum,
								 const void *			key,
								 u_int32_t 				hint,
								 void *					newData,
								 u_int16_t 				dataSize,
								 u_int32_t *			newHint);


/*	Prototypes for exported routines in VolumeAllocation.c*/

/* 
 * Flags for BlockAllocate(), BlockDeallocate() and hfs_block_alloc.
 * Some of these are for internal use only.  See the comment at the
 * top of hfs_alloc_int for more details on the semantics of these
 * flags.
 */ 
#define HFS_ALLOC_FORCECONTIG		0x001	//force contiguous block allocation; minblocks must be allocated
#define HFS_ALLOC_METAZONE			0x002	//can use metazone blocks
#define HFS_ALLOC_SKIPFREEBLKS		0x004	//skip checking/updating freeblocks during alloc/dealloc
#define HFS_ALLOC_FLUSHTXN			0x008	//pick best fit for allocation, even if a jnl flush is req'd
#define HFS_ALLOC_TENTATIVE			0x010	//reserved allocation that can be claimed back
#define HFS_ALLOC_LOCKED			0x020	//reserved allocation that can't be claimed back
#define HFS_ALLOC_IGNORE_TENTATIVE	0x040	//Steal tentative blocks if necessary
#define HFS_ALLOC_IGNORE_RESERVED	0x080	//Ignore tentative/committed blocks
#define HFS_ALLOC_USE_TENTATIVE		0x100	//Use the supplied tentative range (if possible)
#define HFS_ALLOC_COMMIT			0x200	//Commit the supplied extent to disk
#define HFS_ALLOC_TRY_HARD			0x400	//Search hard to try and get maxBlocks; implies HFS_ALLOC_FLUSHTXN
#define HFS_ALLOC_ROLL_BACK			0x800	//Reallocate blocks that were just deallocated
#define HFS_ALLOC_FAST_DEV          0x1000  //Prefer fast device for allocation

typedef uint32_t hfs_block_alloc_flags_t;

struct rl_entry;
EXTERN_API_C( OSErr )
BlockAllocate					(ExtendedVCB *			 vcb,
								 u_int32_t 				 startingBlock,
								 u_int32_t 				 minBlocks,
								 u_int32_t 				 maxBlocks,
								 hfs_block_alloc_flags_t flags,
								 u_int32_t *			 startBlock,
								 u_int32_t *			 actualBlocks);

typedef struct hfs_alloc_extra_args {
	// Used with HFS_ALLOC_TRY_HARD and HFS_ALLOC_FORCECONTIG
	uint32_t				max_blocks;

	// Used with with HFS_ALLOC_USE_TENTATIVE & HFS_ALLOC_COMMIT
	struct rl_entry		  **reservation_in;

	// Used with HFS_ALLOC_TENTATIVE & HFS_ALLOC_LOCKED
	struct rl_entry		  **reservation_out;

	/*
	 * If the maximum cannot be returned, the allocation will be
	 * trimmed to the specified alignment after taking
	 * @alignment_offset into account.  @alignment and
	 * @alignment_offset are both in terms of blocks, *not* bytes.
	 * The result will be such that:
	 *
	 *   (block_count + @alignment_offset) % @alignment == 0
	 *
	 * Alignment is *not* guaranteed.
	 *
	 * One example where alignment might be useful is in the case
	 * where the page size is greater than the allocation block size
	 * and I/O is being performed in multiples of the page size.
	 */
	int						alignment;
	int						alignment_offset;
} hfs_alloc_extra_args_t;

/*
 * Same as BlockAllocate but slightly different API.
 * @extent.startBlock is a hint for where to start searching and
 * @extent.blockCount is the minimum number of blocks acceptable.
 * Additional arguments can be passed in @extra_args and use will
 * depend on @flags.  See comment at top of hfs_block_alloc_int for
 * more information.
 */
errno_t hfs_block_alloc(hfsmount_t *hfsmp,
						HFSPlusExtentDescriptor *extent,
						hfs_block_alloc_flags_t flags,
						hfs_alloc_extra_args_t *extra_args);

EXTERN_API_C( OSErr )
BlockDeallocate					(ExtendedVCB *			 vcb,
								 u_int32_t 				 firstBlock,
								 u_int32_t 				 numBlocks,
								 hfs_block_alloc_flags_t flags);

EXTERN_API_C ( void )
ResetVCBFreeExtCache(struct hfsmount *hfsmp);

EXTERN_API_C( OSErr )
BlockMarkAllocated(ExtendedVCB *vcb, u_int32_t startingBlock, u_int32_t numBlocks);

EXTERN_API_C( OSErr )
BlockMarkFree( ExtendedVCB *vcb, u_int32_t startingBlock, u_int32_t numBlocks);

EXTERN_API_C( OSErr )
BlockMarkFreeUnused( ExtendedVCB *vcb, u_int32_t startingBlock, u_int32_t numBlocks);

EXTERN_API_C( u_int32_t )
MetaZoneFreeBlocks(ExtendedVCB *vcb);
	
EXTERN_API_C( u_int32_t )
UpdateAllocLimit (struct hfsmount *hfsmp, u_int32_t new_end_block);

EXTERN_API_C( u_int32_t )
ScanUnmapBlocks(struct hfsmount *hfsmp);

EXTERN_API_C( int )
hfs_init_summary (struct hfsmount *hfsmp);

errno_t hfs_find_free_extents(struct hfsmount *hfsmp,
							  void (*callback)(void *data, off_t), void *callback_arg);

void hfs_free_tentative(hfsmount_t *hfsmp, struct rl_entry **reservation);
void hfs_free_locked(hfsmount_t *hfsmp, struct rl_entry **reservation);

/*	File Extent Mapping routines*/
EXTERN_API_C( OSErr )
FlushExtentFile					(ExtendedVCB *			vcb);

#if CONFIG_HFS_STD
EXTERN_API_C( int32_t )
CompareExtentKeys				(const HFSExtentKey *	searchKey,
								 const HFSExtentKey *	trialKey);
#endif

EXTERN_API_C( int32_t )
CompareExtentKeysPlus			(const HFSPlusExtentKey *searchKey,
								 const HFSPlusExtentKey *trialKey);

OSErr SearchExtentFile(ExtendedVCB			*vcb,
					   const FCB	 		*fcb,
					   int64_t 				 filePosition,
					   HFSPlusExtentKey		*foundExtentKey,
					   HFSPlusExtentRecord	 foundExtentData,
					   u_int32_t			*foundExtentDataIndex,
					   u_int32_t			*extentBTreeHint,
					   u_int32_t			*endingFABNPlusOne );

EXTERN_API_C( OSErr )
TruncateFileC (ExtendedVCB *vcb, FCB *fcb, int64_t peof, int deleted, 
			   int rsrc, uint32_t fileid, Boolean truncateToExtent);
	
EXTERN_API_C( OSErr )
ExtendFileC						(ExtendedVCB *			vcb,
								 FCB *					fcb,
								 int64_t 				bytesToAdd,
								 u_int32_t 				blockHint,
								 u_int32_t 				flags,
								 int64_t *				actualBytesAdded);

EXTERN_API_C( OSErr )
MapFileBlockC					(ExtendedVCB *			vcb,
								 FCB *					fcb,
								 size_t 				numberOfBytes,
								 off_t 					offset,
								 daddr64_t *				startBlock,
								 size_t *				availableBytes);

OSErr HeadTruncateFile(ExtendedVCB  *vcb, FCB  *fcb, u_int32_t  headblks);

EXTERN_API_C( int )
AddFileExtent (ExtendedVCB *vcb, FCB *fcb, u_int32_t startBlock, u_int32_t blockCount);

#if TARGET_API_MACOS_X
EXTERN_API_C( Boolean )
NodesAreContiguous				(ExtendedVCB *			vcb,
								 FCB *					fcb,
								 u_int32_t				nodeSize);
#endif

/*	Get the current time in UTC (GMT)*/
EXTERN_API_C( u_int32_t )
GetTimeUTC						(void);

EXTERN_API_C( u_int32_t )
LocalToUTC						(u_int32_t 				localTime);

EXTERN_API_C( u_int32_t )
UTCToLocal						(u_int32_t 				utcTime);


#ifdef __cplusplus
}
#endif

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* __FILEMGRINTERNAL__ */

