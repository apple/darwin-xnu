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
	File:		VolumeRequests.c

	Contains:	MountVolume and related utility routines for HFS & HFS Plus

	Version:	HFS Plus 1.0

	Written by:	Deric Horn

	Copyright:	© 1996-1998 by Apple Computer, Inc., all rights reserved.

	File Ownership:

		DRI:				Deric Horn

		Other Contacts:		Mark Day, Don Brady

		Technology:			File Systems

	Writers:

		(JL)	Jim Luther
		(msd)	Mark Day
		(DSH)	Deric Horn
		(djb)	Don Brady

	Change History (most recent first):
	  <MacOSX>	 7/28/98	djb		GetDiskBlocks is now implemented in MacOSStubs.c (radar #2258148).
	  <MacOSX>	  4/3/98	djb		Conditionally remove FSVars reference from GetVolumeNameFromCatalog.
	  <MacOSX>	 3/31/98	djb		Sync up with final HFSVolumes.h header file.
	  <CS47>	 1/29/98	DSH		TrashAllFSCaches is responsible for trashing all file system and
									disk caches. Called from FlushVol when the HFS bit is set.
	  <CS46>	12/12/97	DSH		2003877, when vcbAllocPtr was copied to nextAllocation it was
									getting sign extended.
	  <CS45>	11/26/97	DSH		2003459, fcbs was not being initialized if volume was offline
									and we are executing an unconditional unmount.
	  <CS44>	11/24/97	DSH		2005507, FlushVolumeControlBlock() keeps MDB drCrDate in sync
									with VolumeHeader createDate.
	  <CS43>	11/11/97	DSH		1685873, RemountWrappedVolumes was only remounting the first
									HFS+ volume in the queue, causing HFS wrappers to be mounted if
									multiple volumes had been mounted before InitHFSPlus.
	  <CS42>	 11/4/97	DSH		Clear FCB when getting a new one.
	  <CS41>	 11/3/97	JL		#2001483 - Removed unneeded parameters from MountVolume,
									MountHFSVolume, MountHFSPlusVolume, GetVolumeInformation,
									GetXVolumeInformation and AddVCB (and added local variables as
									needed). Return WDCBRecPtr from UnMountVolume. Set wdcb
									parameter to NULL in GetXVolumeInformation if working directory
									was not specified.
	  <CS40>	10/31/97	DSH		Added consistencyStatus parameter to MountCheck
	  <CS39>	10/23/97	msd		Bug 1685113. The VolumeHeader's createDate should be in local
									time (not GMT) and identical to the MDB's drCrDate (and VCB's
									vcbCrDate). When checking for a remount of an offline HFS Plus
									volume, compare write counts instead of mod dates (which could
									be fooled by the user changing time zones). Force MountCheck to
									run if the volume was last mounted by Bride 1.0b2 or earlier.
	  <CS38>	10/17/97	msd		Conditionalize DebugStrs.
	  <CS37>	10/13/97	djb		Update volumeNameEncodingHint when updating the volume name.
	  <CS36>	10/10/97	msd		Bug 1683571. The dates in the volume header are in GMT, so be
									sure to convert them when mounting a volume or flushing the
									volume header.
	  <CS35>	 10/2/97	DSH		In UnmountVolume() check that the drive is on line before
									determining if wrapper volume needs to be renamed causing IO.
	  <CS34>	 10/1/97	DSH		Run on disk version of MountCheck instead of ROM version for
									boot volumes1682475.
	  <CS33>	 10/1/97	djb		Add calls to InvalidateCatalogCache (part of radar #1678833).
	  <CS32>	 9/26/97	DSH		Removed debugging code: support for 'W' key wrapper mounting.
	  <CS31>	 9/17/97	DSH		hfsPlusIOPosOffset was uninitialized for Wrapperless volumes.
	  <CS30>	  9/5/97	djb		In MountVol initialize Catalog cache before calling Catalog!
	  <CS29>	  9/4/97	msd		PropertyCloseVolume renamed to AttributesCloseVolume. Remove
									call to AttributesOpenVolume (it no longer exists).
	  <CS28>	  9/2/97	DSH		VolumeHeader is now 3rd sector in partition, altVH is 2nd to
									last cor compatability.  Initial support for wrapperless
									volumes.
	  <CS27>	 8/26/97	djb		Only call CountRootFiles during MountVol.
	  <CS26>	 8/20/97	msd		If the HFS Plus volume version doesn't match, mount the wrapper
									instead.
	  <CS25>	 8/19/97	djb		Add error handling to RenameWrapperVolume.
	  <CS24>	 8/15/97	msd		Bug 1673999. In MakeVCBsExtendedVCBs, copy old VCB's vcbAllocPtr
									to new VCB's nextAllocation field.
	  <CS23>	 8/12/97	djb		Fixed GetXVolInfo to only use extended vcb fields for local
									volumes (radar# 1673177)
	  <CS22>	 8/11/97	DSH		vcbNmAlBlks is now taken from the embededExtent.blockCount
									(1669121).
	  <CS21>	 8/11/97	djb		Return actual count of files in root directory for HFS Plus
									volumes (Radar #1669118). Added local CountRootFiles routine.
									8/5/97 msd Make sure version field in VolumeHeader is exactly
									kHFSPlusVersion. 8/1/97 djb GetXVolumeInformation now returns
									extFSErr when FSID is nonzero (Radar #1649503).
	  <CS20>	 7/25/97	DSH		Init and Dispose of GenericMRUCache within ExtendedVCB.
	  <CS19>	 7/16/97	DSH		FilesInternal.x -> FileMgrInternal.x to avoid name collision
	  <CS18>	 7/15/97	DSH		Remount Wrapper volumes mounted before HFS+ initialization
									(166729)
	  <CS17>	 7/15/97	djb		Remove ioXVersion checking in GetXVolInfo (radar #1666217).
	  <CS16>	  7/8/97	DSH		Loading PrecompiledHeaders from define passed in on C line
	  <CS15>	  7/7/97	djb		Add GetVolumeNameFromCatalog routine.
	  <CS14>	  7/7/97	DSH		GetNewVRefNum now get's a recycled vRefNum. Bug 1664445 in
									Installer was cacheing the vRefNum while CheckDisk unmounts and
									remounts disk.
	  <CS13>	 6/30/97	DSH		shadowing values obsoleteVCBXTRef, and obsoleteVCBCTRef when
									HFS+ volume is mounted.
	  <CS12>	 6/26/97	DSH		GetVolInfo returns HFS signature for HFS+ volumes, GetXVolInfo
									returns real signature.
	  <CS11>	 6/24/97	DSH		MakeVCBsExtendedVCBs was using wdcb->count as count not byte
									count.
	  <CS10>	 6/18/97	djb		Set/get volume encodingsBitmap.
	   <CS9>	 6/16/97	msd		Include String.h and Disks.h.
	   <CS8>	 6/12/97	djb		Get in sync with HFS Plus format changes.
	   <CS7>	 6/11/97	msd		Make GetXVolumeInformation return true allocation block size. It
									now checks the ioXVersion field.
	   <CS6>	 5/28/97	msd		When flushing the volume header, write out the allocation file's
									clump size (from the FCB). When mounting an HFS Plus volume,
									zero the entire FCB extent record, not just the first extent,
									for the various volume control files.
	   <CS5>	 5/19/97	djb		Add calls to CreateVolumeCatalogCache,
									DisposeVolumeCatalogCache.
	   <CS4>	  5/9/97	djb		Get in sync with new FilesInternal.i
	   <CS3>	  5/8/97	DSH		Only mount HFS+ volumes with version < 2.0 in the VolumeHeader.
									Return wrgVolTypErr if too new.
	   <CS2>	  5/2/97	djb		Disable Manual Eject code since its buggy!
	   <CS1>	 4/25/97	djb		first checked in

	 <HFS32>	 4/11/97	DSH		MountHFSPlusVolume gets volume name from catalog, and
									UnmountVolume shadows the name back to the wrapper partition.
	 <HFS31>	  4/8/97	msd		Once volume is mounted, call AttributesOpenVolume to allow a
									buffer to be allocated.
	 <HFS30>	  4/7/97	msd		In FlushVolumeControlBlock, don't update the attributes BTree
									fields in the Volume Header unless an attributes BTree was
									already open.
	 <HFS29>	  4/7/97	msd		In SetupFCB, add case for attributes BTree. Add code to set up
									the attributes BTree. Remove call to PropertyOpenVolume. In
									FlushVolumeControlBlock, write out any changes to the attributes
									BTree.
	 <HFS28>	  4/4/97	djb		Get in sync with volume format changes.
	 <HFS27>	 3/31/97	djb		Added catalogDataCache to VCB; Remove ClearMem routine.
	 <HFS26>	 3/18/97	msd		In MountHFSPlusVolume, the free blocks calculation can overflow,
									setting vcbFreeBks to a too-small value.
	 <HFS25>	 3/17/97	DSH		Added some utility functions AddVCB, GetParallelFCBFromRefNum,
									casting for SC, and made some functions extern for DFA.
	 <HFS24>	  3/5/97	msd		Add calls to Property Manager to open and close the volume. When
									unmounting an HFS+ volume, the allocation (bitmap) file now gets
									closed.
	 <HFS23>	 2/19/97	djb		Update to 16-bit HFS Plus signature.
	 <HFS22>	 2/12/97	msd		In GetXVolumeInformation, the result code could be
									uninitialized.
	 <HFS21>	 1/23/97	DSH		UpdateAlternateVoumeControlBlock()
	 <HFS20>	 1/15/97	djb		Remove MountCheckStub. Add file names to fcbs for debugging.
	 <HFS19>	 1/13/97	DSH		Use ExtendedVCB nextAllocation instead of vcbAllocPtr through
									all code.
	 <HFS18>	  1/9/97	djb		Get in sync with new VolumeHeader and Extended VCB.
	 <HFS17>	  1/6/97	djb		Changed API to ParallelFCBFromRefnum (pragma parameter was
									broken).
	 <HFS16>	  1/6/97	msd		Set only the defined bits in the MDB drAtrb field (when copying
									from VCB vcbAtrb field).
	 <HFS15>	  1/6/97	DSH		CloseFile requires VCB to be passed in.
	 <HFS14>	  1/6/97	djb		FlushVolumeControlBlock was writing to absolute block 0 instead
									of to block zero of the embedded volume.
	 <HFS13>	12/20/96	msd		A comparison was using "=" instead of "=="; might have caused
									the wrong volume to be set as the default.
	 <HFS12>	12/19/96	DSH		Setting up ExtendedVCBs
	 <HFS11>	12/19/96	djb		Updated for new B-tree Manager interface.
	 <HFS10>	12/18/96	msd		Change GetVCBRefNum so it can actually return a VCB pointer.
	  <HFS9>	12/12/96	djb		Use new SPI for GetCatalogNode.
	  <HFS8>	12/12/96	msd		Fix a bunch of errors (mostly type mismatch) when compiling with
									Metrowerks.
	  <HFS7>	12/12/96	DSH		adding some util functions
	  <HFS6>	12/10/96	msd		Check PRAGMA_LOAD_SUPPORTED before loading precompiled headers.
	  <HFS5>	 12/4/96	DSH		Ported GetVolumeInformation & GetXVolumeInformation.
		<3*>	11/20/96	DSH		HFS Plus support to MountVolume
	  <HFS3>	11/20/96	DSH		Added UnmountVol and related routines, also backed out <2>
									because C_FXMKeyCmp is passed as a parameter from C but called
									from Asm in BTOpen so we need a Case ON Asm entry point.
	  <HFS2>	11/20/96	msd		Use CompareExtentKeys() instead of CFXMKeyCmp().
	  <HFS1>	11/19/96	DSH		first checked in
		 <1>	11/19/96	DSH		first checked in

*/
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/malloc.h>

#include "../../hfs.h"
#include "../../hfs_endian.h"

#include "../headers/FileMgrInternal.h"

#define		kIDSectorOffset	2

OSErr	GetNewFCB( ExtendedVCB *vcb, FileReference* fRefPtr);

OSErr	AccessBTree( ExtendedVCB *vcb, FileReference refNum, UInt32 fileID, UInt32 fileClumpSize, void *CompareRoutine );

UInt16	DivUp( UInt32 byteRun, UInt32 blockSize );

Boolean	IsARamDiskDriver( void );

OSErr	GetVCBRefNum( ExtendedVCB **vcb, short vRefNum );

OSErr	ValidMasterDirectoryBlock( HFSMasterDirectoryBlock *mdb );

void	RenameWrapperVolume( Str27 newVolumeName, UInt16 driveNumber );

OSErr	CheckExternalFileSystem( ExtendedVCB *vcb );

OSErr	FlushVolume( ExtendedVCB *vcb );

FCB		*SetupFCB( ExtendedVCB *vcb, FileReference refNum, UInt32 fileID, UInt32 fileClumpSize );

void	AddVCB( ExtendedVCB	*vcb, short driveNumber, short ioDRefNum );

short	IsPressed( unsigned short k );

FileReference	GetNewVRefNum();

OSErr	GetVolumeNameFromCatalog(ExtendedVCB *vcb);

#if TARGET_API_MAC_OS8
static UInt16 CountRootFiles(ExtendedVCB *vcb);
#endif /* TARGET_API_MAC_OS8 */


#if ( hasHFSManualEject )
static void SetVCBManEject(ExtendedVCB *vcb);
#endif

// External routines

extern	OSErr	C_FlushMDB( ExtendedVCB *volume );

extern	OSErr	DisposeVolumeCacheBlocks( ExtendedVCB *vcb );

extern	void	DisposeVolumeControlBlock( ExtendedVCB *vcb );

extern	OSErr	FlushVolumeBuffers( ExtendedVCB *vcb );

extern	void	MultiplyUInt32IntoUInt64( UInt64 *wideResult, UInt32 num1, UInt32 num2 );

extern void		TrashCatalogNodeCache( void );


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	VolumeWritable		Asm: CVFlgs
//
//	Function: 	Check the volume's flags to see if modify requests are allowed.
//
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
OSErr	VolumeWritable( ExtendedVCB *vcb )
{
	if ( !(vcb->vcbAtrb & 0x8000) )		//	if the volume is not locked
	{
		if ( ! (*((Ptr)&(vcb->vcbAtrb) + 1) & kHFSVolumeHardwareLockMask) )	//	if it's not write protected
			return( noErr );
	else
			return( wPrErr );
		}
		else
	{
		return( vLckdErr );
	}
}


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	DivUp from Asm: DivUp
//
//	Function:	Given a number of bytes and block size, calculate the number of
//				blocks needd to hold all the bytes.
//
// 	Result:		Number of physical blocks needed
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
UInt16	DivUp( UInt32 byteRun, UInt32 blockSize )
{
	UInt32	blocks;
	
	blocks = (byteRun + blockSize - 1) / blockSize;							//	Divide up, remember this is integer math.
	
	if ( blocks > 0xffff )													//	maximum 16 bit value
		blocks = 0xffff;
		
	return( (UInt16) blocks );
}




//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	HFSBlocksFromTotalSectors
//
//	Function:	Given the total number of sectors on the volume, calculate
//				the 16Bit number of allocation blocks, and allocation block size.
//
// 	Result:		none
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
void	HFSBlocksFromTotalSectors( UInt32 totalSectors, UInt32 *blockSize, UInt16 *blockCount )
{
	UInt16	newBlockSizeInSectors	= 1;
	UInt32	newBlockCount			= totalSectors;
	
	while ( newBlockCount > 0XFFFF )
	{
		newBlockSizeInSectors++;
		newBlockCount	=  totalSectors / newBlockSizeInSectors;
	}
	
	*blockSize	= newBlockSizeInSectors * 512;
	*blockCount	= newBlockCount;
}




//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	ValidMasterDirectoryBlock
//
//	Function:	Run some sanity checks to make sure the MDB is valid
//
// 	Result:		error
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
OSErr	ValidMasterDirectoryBlock( HFSMasterDirectoryBlock *mdb )
{
	OSErr			err;
	
	if ( (SWAP_BE16 (mdb->drSigWord) == kHFSPlusSigWord) || (SWAP_BE16 (mdb->drSigWord) == kHFSSigWord) )	//	if HFS or HFS Plus volume
	{
		if ( (SWAP_BE32 (mdb->drAlBlkSiz) != 0) && ((SWAP_BE32 (mdb->drAlBlkSiz) & 0x01FF) == 0) )			//	non zero multiple of 512
			err = noErr;
		else
			err = badMDBErr;
	}
	else
	{
		err = noMacDskErr;
	}
	
	return( err );
}


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
//	Routine:	ValidVolumeHeader
//
//	Function:	Run some sanity checks to make sure the VolumeHeader is valid
//
// 	Result:		error
//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹
OSErr	ValidVolumeHeader( HFSPlusVolumeHeader *volumeHeader )
{
	OSErr	err;
	
	if ( SWAP_BE16 (volumeHeader->signature) == kHFSPlusSigWord && SWAP_BE16 (volumeHeader->version) == kHFSPlusVersion )
	{
		if ( (SWAP_BE32 (volumeHeader->blockSize) != 0) && ((SWAP_BE32 (volumeHeader->blockSize) & 0x01FF) == 0) )			//	non zero multiple of 512
			err = noErr;
		else
			err = badMDBErr;									//€€	I want badVolumeHeaderErr in Errors.i
	}
	else
	{
		err = noMacDskErr;
	}
	
	return( err );
}




//_______________________________________________________________________
//
//	Routine:	CountRootFiles
//
//	Input:		pointer to VCB
//
//	Function: 	Return a count of the number of files and folders in
//				the root directory of a volume.  For HFS volumes, this
//				is maintained in the VCB (and MDB).  For HFS Plus volumes,
//				we get the valence of the root directory from its catalog
//				record.
//_______________________________________________________________________
UInt16 CountRootFiles(ExtendedVCB *vcb)
{
	OSErr			err;
	CatalogNodeData	catNodeData;
	UInt32			hint;
	UInt16			rootCount;
	
//	if (vcb->vcbSigWord == kHFSSigWord || vcb->vcbFSID != 0) {
//		return vcb->vcbNmFls;
//	}
	
	//	Here, it's an HFS Plus volume, so get the valence from the root
	//	directory's catalog record.
	
	rootCount = 0;
	
	INIT_CATALOGDATA(&catNodeData, kCatNameNoCopyName);
	
    err = GetCatalogNode( vcb, kHFSRootFolderID, nil, kUndefinedStrLen, kNoHint, &catNodeData, &hint );
	if ( err == noErr ) {
		if (catNodeData.cnd_valence < 65536)
			rootCount = catNodeData.cnd_valence;
	else
			rootCount = 65535;			//	if the value is too large, pin it
	}
	CLEAN_CATALOGDATA(&catNodeData);

	return rootCount;
}



//_______________________________________________________________________
//
//	Routine:	FlushVolumeControlBlock
//	Arguments:	ExtendedVCB		*vcb
//	Output:		OSErr			err
//
//	Function: 	Flush volume information to either the VolumeHeader of the Master Directory Block
//_______________________________________________________________________

OSErr	FlushVolumeControlBlock( ExtendedVCB *vcb )
{
	OSErr			err;

	if ( ! IsVCBDirty( vcb ) )			//	if it's not dirty
		return( noErr );

	if ( vcb->vcbSigWord == kHFSPlusSigWord )
	{
        err = C_FlushMDB( vcb );		//	Go flush the VCB info BEFORE close
	}
	else
	{
		// This routine doesn't really return an error!!!
		// So for now, we will just return noErr
		err = C_FlushMDB( vcb );		//	Go flush the VCB info BEFORE close
		return( noErr );
	}

	return( err );
}


//‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹‹

OSErr GetVolumeNameFromCatalog( ExtendedVCB *vcb )
{
	CatalogNodeData	nodeData;
	UInt32			hint;
	OSErr			err;

	INIT_CATALOGDATA(&nodeData, 0);

	err = GetCatalogNode( vcb, kHFSRootFolderID, NULL, kUndefinedStrLen, kNoHint, &nodeData, &hint );

	if ( err == noErr )
	{
		BlockMoveData( nodeData.cnm_nameptr, vcb->vcbVN, min(255, nodeData.cnm_length));
		vcb->volumeNameEncodingHint = nodeData.cnd_textEncoding;

		/* HFS+ uses the root directory's create date since its in GMT */
		if (vcb->vcbSigWord == kHFSPlusSigWord)
			vcb->vcbCrDate = nodeData.cnd_createDate;
	}

	CLEAN_CATALOGDATA(&nodeData);
		
	return err;
}
