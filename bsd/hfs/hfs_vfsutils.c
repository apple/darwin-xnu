/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
/*	@(#)hfs_vfsutils.c	4.0
*
*	(c) 1997-2000 Apple Computer, Inc.  All Rights Reserved
*
*	hfs_vfsutils.c -- Routines that go between the HFS layer and the VFS.
*
*	Change History (most recent first):
*
*	22-Jan-2000	Don Brady	Remove calls to MountCheck.
*	 7-Sep-1999	Don Brady	Add HFS Plus hard-link support.
*	25-Aug-1999	Don Brady	Dont't use vcbAlBlSt for HFS plus volumes (2350009).
*	 9-Aug-1999 Pat Dirks		Added support for ATTR_VOL_ENCODINGSUSED [#2357367].
*	16-Jul-1999	Pat Dirks		Fixed PackCommonCatalogInfoAttributeBlock to return full range of possible vnode types [#2317604]
*	15-Jun-1999	Pat Dirks		Added support for return of mounted device in hfs_getattrlist [#2345297].
*	 9-Jun-1999	Don Brady		Cleanup vcb accesses in hfs_MountHFSVolume.
*	 3-Jun-1999	Don Brady		Remove references to unused/legacy vcb fields (eg vcbXTClpSiz).
*	21-May-1999	Don Brady		Add call to hfs_vinit in hfsGet to support mknod.
*	 6-Apr-1999	Don Brady		Fixed de-reference of NULL dvp in hfsGet.
*	22-Mar-1999	Don Brady		Add support for UFS delete semantics.
*	 1-Mar-1999	Scott Roberts	Dont double MALLOC on long names.
*	23-Feb-1999	Pat Dirks		Change incrementing of meta refcount to be done BEFORE lock is acquired.
*	 2-Feb-1999	Pat Dirks		For volume ATTR_CMN_SCRIPT use vcb->volumeNameEncodingHint instead of 0.
*	10-Mar-1999	Don Brady		Removing obsolete code.
*	 2-Feb-1999	Don Brady		For volume ATTR_CMN_SCRIPT use vcb->volumeNameEncodingHint instead of 0.
*	18-Jan-1999	Pat Dirks		Changed CopyCatalogToHFSNode to start with ACCESSPERMS instead of adding
*								write access only for unlocked files (now handled via IMMUTABLE setting)
*	 7-Dec-1998 Pat Dirks		Changed PackCatalogInfoFileAttributeBlock to return proper I/O block size.
*	 7-Dec-1998	Don Brady		Pack the real text encoding instead of zero.
*	16-Dec-1998	Don Brady		Use the root's crtime intead of vcb create time for getattrlist.
*	16-Dec-1998	Don Brady		Use the root's crtime intead of vcb create time for getattrlist.
*	 2-Dec-1998	Scott Roberts	Copy the mdbVN correctly into the vcb.
*    3-Dec-1998 Pat Dirks		Added support for ATTR_VOL_MOUNTFLAGS.
*	20-Nov-1998	Don Brady		Add support for UTF-8 names.
*   18-Nov-1998	Pat Dirks		Changed UnpackCommonAttributeBlock to call wait for hfs_chflags to update catalog entry when changing flags
*   13-Nov-1998 Pat Dirks       Changed BestBlockSizeFit to try PAGE_SIZE only and skip check for MAXBSIZE.
*	10-Nov-1998	Pat Dirks		Changed CopyCatalogToHFSNode to ensure consistency between lock flag and IMMUTABLE bits.
*   10-Nov-1998	Pat Dirks		Added MapFileOffset(), LogicalBlockSize() and UpdateBlockMappingTable() routines.
*	18-Nov-1998	Pat Dirks		Changed PackVolAttributeBlock to return proper logical block size
*                               for ATTR_VOL_IOBLOCKSIZE attribute.
*	 3-Nov-1998	Umesh Vaishampayan	Changes to deal with "struct timespec"
*								change in the kernel.	
*	23-Sep-1998	Don Brady		In UnpackCommonAttributeBlock simplified setting of gid, uid and mode.
*   10-Nov-1998	Pat Dirks		Added MapFileOffset(), LogicalBlockSize() and UpdateBlockMappingTable() routines.
*	17-Sep-1998	Pat Dirks		Changed BestBlockSizeFit to try MAXBSIZE and PAGE_SIZE first.
*	 8-Sep-1998	Don Brady		Fix CopyVNodeToCatalogNode to use h_mtime for contentModDate (instead of h_ctime).
*	 4-Sep-1998	Pat Dirks		Added BestBlockSizeFit routine.
*	18-Aug-1998	Don Brady		Change DEBUG_BREAK_MSG to a DBG_UTILS in MacToVFSError (radar #2262802).
*	30-Jun-1998	Don Brady		Add calls to MacToVFSError to hfs/hfsplus mount routines (for radar #2249539).
*	22-Jun-1998	Don Brady		Add more error cases to MacToVFSError; all HFS Common errors are negative.
*								Changed hfsDelete to call DeleteFile for files.
*	 4-Jun-1998	Pat Dirks		Changed incorrect references to 'vcbAlBlkSize' to 'blockSize';
*								Added hfsCreateFileID.
*	 4-Jun-1998	Don Brady		Add hfsMoveRename to replace hfsMove and hfsRename. Use VPUT/VRELE macros
*								instead of vput/vrele to catch bad ref counts.
*	28-May-1998	Pat Dirks		Adjusted for change in definition of ATTR_CMN_NAME and removed ATTR_CMN_RAWDEVICE.
*	 7-May-1998	Don Brady		Added check for NULL vp to hfs_metafilelocking (radar #2233832).
*	24-Apr-1998	Pat Dirks		Fixed AttributeBlockSize to return only length of variable attribute block.
*	4/21/1998	Don Brady		Add SUPPORTS_MAC_ALIASES conditional (for radar #2225419).
*	4/21/1998	Don Brady		Map cmNotEmpty errors to ENOTEMPTY (radar #2229259).
*	4/21/1998	Don Brady		Fix up time/date conversions.
*	4/20/1998	Don Brady		Remove course-grained hfs metadata locking.
*	4/18/1998	Don Brady		Add VCB locking.
*	4/17/1998	Pat Dirks		Fixed PackFileAttributeBlock to return more up-to-date EOF/PEOF info from vnode.
*	4/15/1998	Don Brady		Add hasOverflowExtents and hfs_metafilelocking. Use ExtendBTreeFile instead
*								of SetEndOfForkProc. Set forktype for system files.
*	4/14/1998	Deric Horn		PackCatalogInfoAttributeBlock(), and related packing routines to
*								pack attribute data given hfsCatalogInfo, without the objects vnode;
*	4/14/1998 	Scott Roberts	Add execute priviledges to all hfs objects.
*	 4/9/1998	Don Brady		Add MDB/VolumeHeader flushing to hfsUnmount;
*	 4/8/1998	Don Brady		Make sure vcbVRefNum field gets initialized (use MAKE_VREFNUM).
*	 4/6/1998	Don Brady		Removed calls to CreateVolumeCatalogCache (obsolete).
*	4/06/1998	Scott Roberts	Added complex file support.
*	4/02/1998	Don Brady		UpdateCatalogNode now takes parID and name as input.
*	3/31/1998	Don Brady		Sync up with final HFSVolumes.h header file.
*	3/31/1998	Don Brady		Check result from UFSToHFSStr to make sure hfs/hfs+ names are not greater
*								than 31 characters.
*	3/30/1998	Don Brady		In InitMetaFileVNode set VSYSTEM bit in vnode's v_flag.
*	3/26/1998	Don Brady		Cleaned up hfs_MountXXX routines. Removed CloseBtreeFile and OpenBTreeFile.
*								Simplified hfsUnmount (removed MacOS specific code).
*	3/17/1998	Don Brady		AttributeBlockSize calculation did not account for the size field (4bytes).
*	  							PackVolCommonAttributes and PackCommonAttributeBlock for ATTR_CMN_NAME
*	  							were not setting up the name correctly.
*	3/17/1998	Don Brady		Changed CreateCatalogNode interface to take kCatalogFolderNode and
*								kCatalogFileNode as type input. Also, force MountCheck to always run.
*	12-nov-1997	Scott Roberts	Initially created file.
*	17-Mar-98	ser				Broke out and created CopyCatalogToHFSNode()
*
*/
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/lock.h>
#include <sys/buf.h>
#include <sys/ubc.h>
#include <sys/unistd.h>

#include "hfs.h"
#include "hfs_dbg.h"
#include "hfs_mount.h"
#include "hfs_endian.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"

#define		SUPPORTS_MAC_ALIASES	0
#define		kMaxSecsForFsync	5

#define BYPASSBLOCKINGOPTIMIZATION 0

extern int (**hfs_vnodeop_p)(void *);
extern int (**hfs_specop_p)(void *);
extern int (**hfs_fifoop_p)(void *);
extern int count_lock_queue __P((void));
extern uid_t console_user;

OSErr	ValidMasterDirectoryBlock( HFSMasterDirectoryBlock *mdb );

/* Externs from vhash */
extern void hfs_vhashins_sibling(dev_t dev, UInt32 nodeID, struct hfsnode *hp, struct hfsfilemeta **fm);
extern void hfs_vhashins(dev_t dev, UInt32 nodeID,struct hfsnode *hp);
extern struct vnode *hfs_vhashget(dev_t dev, UInt32 nodeID, UInt8 forkType);

extern int hfs_vinit( struct mount *mntp, int (**specops)(void *), int (**fifoops)(), struct vnode **vpp);

extern OSErr GetVolumeNameFromCatalog(ExtendedVCB *vcb);

static int InitMetaFileVNode(struct vnode *vp, off_t eof, u_long clumpSize, const HFSPlusExtentRecord extents,
							 HFSCatalogNodeID fileID, void * keyCompareProc);

static void ReleaseMetaFileVNode(struct vnode *vp);

static void RemovedMetaDataDirectory(ExtendedVCB *vcb);

void CopyCatalogToObjectMeta(struct hfsCatalogInfo *catalogInfo, struct vnode *vp, struct hfsfilemeta *fm);
void CopyCatalogToFCB(struct hfsCatalogInfo *catalogInfo, struct vnode *vp);
void hfs_name_CatToMeta(CatalogNodeData *nodeData, struct hfsfilemeta *fm);
u_int32_t GetLogicalBlockSize(struct vnode *vp);

/* BTree accessor routines */
extern OSStatus GetBTreeBlock(FileReference vp, UInt32 blockNum, GetBlockOptions options, BlockDescriptor *block);
extern OSStatus SetBTreeBlockSize(FileReference vp, ByteCount blockSize, ItemCount minBlockCount);
extern OSStatus ExtendBTreeFile(FileReference vp, FSSize minEOF, FSSize maxEOF);
extern OSStatus ReleaseBTreeBlock(FileReference vp, BlockDescPtr blockPtr, ReleaseBlockOptions options);

//*******************************************************************************
// Note: Finder information in the HFS/HFS+ metadata are considered opaque and
//       hence are not in the right byte order on little endian machines. It is
//       the responsibility of the finder and other clients to swap the data.
//*******************************************************************************

//*******************************************************************************
//	Routine:	hfs_MountHFSVolume
//
//
//*******************************************************************************

OSErr hfs_MountHFSVolume(struct hfsmount *hfsmp, HFSMasterDirectoryBlock *mdb,
		u_long sectors, struct proc *p)
{
    ExtendedVCB 			*vcb = HFSTOVCB(hfsmp);
    struct vnode 			*tmpvnode;
    OSErr					err;
    HFSPlusExtentRecord		extents;
	ByteCount utf8chars;
    DBG_FUNC_NAME("hfs_MountHFSVolume");
    DBG_PRINT_FUNC_NAME();

    if (hfsmp == nil || mdb == nil)				/* exit if bad paramater */
		return (EINVAL);

    err = ValidMasterDirectoryBlock( mdb );		/* make sure this is an HFS disk */
    if (err)
    	return MacToVFSError(err);

	/* don't mount a writeable volume if its dirty, it must be cleaned by fsck_hfs */
	if ((hfsmp->hfs_fs_ronly == 0) && ((SWAP_BE16 (mdb->drAtrb) & kHFSVolumeUnmountedMask) == 0))
		return (EINVAL);
		
	/*
	 * The MDB seems OK: transfer info from it into VCB
	 * Note - the VCB starts out clear (all zeros)
	 *
	 */
	vcb->vcbVRefNum			= MAKE_VREFNUM(hfsmp->hfs_raw_dev);

	vcb->vcbSigWord			= SWAP_BE16 (mdb->drSigWord);
	vcb->vcbCrDate			= LocalToUTC (SWAP_BE32 (mdb->drCrDate));
	vcb->localCreateDate	= SWAP_BE32 (mdb->drCrDate);
	vcb->vcbLsMod			= LocalToUTC (SWAP_BE32 (mdb->drLsMod));
	vcb->vcbAtrb			= SWAP_BE16 (mdb->drAtrb);
	vcb->vcbNmFls			= SWAP_BE16 (mdb->drNmFls);
	vcb->vcbVBMSt			= SWAP_BE16 (mdb->drVBMSt);
	vcb->nextAllocation		= SWAP_BE16 (mdb->drAllocPtr);
	vcb->totalBlocks		= SWAP_BE16 (mdb->drNmAlBlks);
	vcb->blockSize			= SWAP_BE32 (mdb->drAlBlkSiz);
	vcb->vcbClpSiz			= SWAP_BE32 (mdb->drClpSiz);
	vcb->vcbAlBlSt			= SWAP_BE16 (mdb->drAlBlSt);
	vcb->vcbNxtCNID			= SWAP_BE32 (mdb->drNxtCNID);
	vcb->freeBlocks			= SWAP_BE16 (mdb->drFreeBks);
	vcb->vcbVolBkUp			= LocalToUTC (SWAP_BE32 (mdb->drVolBkUp));
	vcb->vcbWrCnt			= SWAP_BE32 (mdb->drWrCnt);
	vcb->vcbNmRtDirs		= SWAP_BE16 (mdb->drNmRtDirs);
	vcb->vcbFilCnt			= SWAP_BE32 (mdb->drFilCnt);
	vcb->vcbDirCnt			= SWAP_BE32 (mdb->drDirCnt);
	bcopy(mdb->drFndrInfo, vcb->vcbFndrInfo, sizeof(vcb->vcbFndrInfo));
	vcb->nextAllocation		= SWAP_BE16 ( mdb->drAllocPtr);	/* Duplicate?!?!?! */
	vcb->encodingsBitmap = 0;
	vcb->vcbWrCnt++;	/* Compensate for write of MDB on last flush */
	/*
	 * Copy the drVN field, which is a Pascal String to the vcb, which is a cstring
	 */

	/* convert hfs encoded name into UTF-8 string */
	err = hfs_to_utf8(vcb, mdb->drVN, NAME_MAX, &utf8chars, vcb->vcbVN);
	/*
	 * When an HFS name cannot be encoded with the current
	 * volume encoding we use MacRoman as a fallback.
	 */
	if (err || (utf8chars == 0))
		(void) mac_roman_to_utf8(mdb->drVN, NAME_MAX, &utf8chars, vcb->vcbVN);

	vcb->altIDSector = sectors - 2;

    //	Initialize our dirID/nodePtr cache associated with this volume.
    err = InitMRUCache( sizeof(UInt32), kDefaultNumMRUCacheBlocks, &(vcb->hintCachePtr) );
    ReturnIfError( err );

    hfsmp->hfs_logBlockSize = BestBlockSizeFit(vcb->blockSize, MAXBSIZE, hfsmp->hfs_phys_block_size);
	vcb->vcbVBMIOSize = kHFSBlockSize;

    // XXX PPD: Should check here for hardware lock flag and set flags in VCB/MP appropriately
	VCB_LOCK_INIT(vcb);

	/*
	 * Set up Extents B-tree vnode...
	 */ 
	err = GetInitializedVNode(hfsmp, &tmpvnode);
	if (err) goto MtVolErr;
    /* HFSToHFSPlusExtents(mdb->drXTExtRec, extents); */ /* ASDFADSFSD */
	extents[0].startBlock = SWAP_BE16 (mdb->drXTExtRec[0].startBlock);
	extents[0].blockCount = SWAP_BE16 (mdb->drXTExtRec[0].blockCount);
	extents[1].startBlock = SWAP_BE16 (mdb->drXTExtRec[1].startBlock);
	extents[1].blockCount = SWAP_BE16 (mdb->drXTExtRec[1].blockCount);
	extents[2].startBlock = SWAP_BE16 (mdb->drXTExtRec[2].startBlock);
	extents[2].blockCount = SWAP_BE16 (mdb->drXTExtRec[2].blockCount);
    
    err = InitMetaFileVNode(tmpvnode, SWAP_BE32 (mdb->drXTFlSize), SWAP_BE32 (mdb->drXTClpSiz), extents,
							kHFSExtentsFileID, CompareExtentKeys);
    if (err) goto MtVolErr;

	/*
	 * Set up Catalog B-tree vnode...
	 */ 
	err = GetInitializedVNode(hfsmp, &tmpvnode);
	if (err) goto MtVolErr;
    /* HFSToHFSPlusExtents(mdb->drCTExtRec, extents); */
	extents[0].startBlock = SWAP_BE16 (mdb->drCTExtRec[0].startBlock);
	extents[0].blockCount = SWAP_BE16 (mdb->drCTExtRec[0].blockCount);
	extents[1].startBlock = SWAP_BE16 (mdb->drCTExtRec[1].startBlock);
	extents[1].blockCount = SWAP_BE16 (mdb->drCTExtRec[1].blockCount);
	extents[2].startBlock = SWAP_BE16 (mdb->drCTExtRec[2].startBlock);
	extents[2].blockCount = SWAP_BE16 (mdb->drCTExtRec[2].blockCount);
    
    err = InitMetaFileVNode(tmpvnode, SWAP_BE32 (mdb->drCTFlSize), SWAP_BE32 (mdb->drCTClpSiz), extents,
							kHFSCatalogFileID, CompareCatalogKeys);
	if (err) goto MtVolErr;

      	/* mark the volume dirty (clear clean unmount bit) */
	vcb->vcbAtrb &=	~kHFSVolumeUnmountedMask;

	/* Remove any MetaDataDirectory from hfs disks */
	if (hfsmp->hfs_fs_ronly == 0)
		RemovedMetaDataDirectory(vcb);

	/*
	 * all done with b-trees so we can unlock now...
	 */
    VOP_UNLOCK(vcb->catalogRefNum, 0, p);
    VOP_UNLOCK(vcb->extentsRefNum, 0, p);

    err = noErr;

    if ( err == noErr )
      {
        if ( !(vcb->vcbAtrb & kHFSVolumeHardwareLockMask) )		//	if the disk is not write protected
          {
            MarkVCBDirty( vcb );								//	mark VCB dirty so it will be written
          }
      }
    goto	CmdDone;

    //--	Release any resources allocated so far before exiting with an error:
MtVolErr:;
	ReleaseMetaFileVNode(vcb->catalogRefNum);
	ReleaseMetaFileVNode(vcb->extentsRefNum);

CmdDone:;
    return( err );
}

//*******************************************************************************
//	Routine:	hfs_MountHFSPlusVolume
//
//
//*******************************************************************************

OSErr hfs_MountHFSPlusVolume(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
	u_long embBlkOffset, u_long sectors, struct proc *p)
{
    register ExtendedVCB	*vcb;
    HFSPlusForkData			*fdp;
    struct vnode 			*tmpvnode;
    OSErr					retval;

    if (hfsmp == nil || vhp == nil)		/*	exit if bad paramater */
		return (EINVAL);

	DBG_VFS(("hfs_MountHFSPlusVolume: signature=0x%x, version=%d, blockSize=%ld\n",
            SWAP_BE16 (vhp->signature),
            SWAP_BE16 (vhp->version),
            SWAP_BE32 (vhp->blockSize)));

    retval = ValidVolumeHeader(vhp);	/*	make sure this is an HFS Plus disk */
    if (retval)
    	return MacToVFSError(retval);
   
	/* don't mount a writable volume if its dirty, it must be cleaned by fsck_hfs */
	if (hfsmp->hfs_fs_ronly == 0 && (SWAP_BE32 (vhp->attributes) & kHFSVolumeUnmountedMask) == 0)
		return (EINVAL);
	/*
	 * The VolumeHeader seems OK: transfer info from it into VCB
	 * Note - the VCB starts out clear (all zeros)
	 */
	vcb = HFSTOVCB(hfsmp);

	//DBG_ASSERT((hfsmp->hfs_raw_dev & 0xFFFF0000) == 0);
	vcb->vcbVRefNum		=	MAKE_VREFNUM(hfsmp->hfs_raw_dev);
	vcb->vcbSigWord		=	SWAP_BE16 (vhp->signature);
	vcb->vcbLsMod		=	SWAP_BE32 (vhp->modifyDate);
	vcb->vcbAtrb		=	(UInt16) SWAP_BE32 (vhp->attributes);		// VCB only uses lower 16 bits
	vcb->vcbClpSiz		=	SWAP_BE32 (vhp->rsrcClumpSize);
	vcb->vcbNxtCNID		=	SWAP_BE32 (vhp->nextCatalogID);
	vcb->vcbVolBkUp		=	SWAP_BE32 (vhp->backupDate);
	vcb->vcbWrCnt		=	SWAP_BE32 (vhp->writeCount);
	vcb->vcbFilCnt		=	SWAP_BE32 (vhp->fileCount);
	vcb->vcbDirCnt		=	SWAP_BE32 (vhp->folderCount);
	
	/* copy 32 bytes of Finder info */
	bcopy(vhp->finderInfo, vcb->vcbFndrInfo, sizeof(vhp->finderInfo));    

	vcb->vcbAlBlSt = 0;		/* hfs+ allocation blocks start at first block of volume */
	vcb->vcbWrCnt++;		/* compensate for write of Volume Header on last flush */

	VCB_LOCK_INIT(vcb);

	/*	Now fill in the Extended VCB info */
	vcb->nextAllocation			=	SWAP_BE32 (vhp->nextAllocation);
	vcb->totalBlocks			=	SWAP_BE32 (vhp->totalBlocks);
	vcb->freeBlocks				=	SWAP_BE32 (vhp->freeBlocks);
	vcb->blockSize				=	SWAP_BE32 (vhp->blockSize);
	vcb->checkedDate			=	SWAP_BE32 (vhp->checkedDate);
	vcb->encodingsBitmap		=	SWAP_BE64 (vhp->encodingsBitmap);
	
	vcb->hfsPlusIOPosOffset		=	embBlkOffset * 512;

	vcb->altIDSector = embBlkOffset + sectors - 2;

	vcb->localCreateDate		=	SWAP_BE32 (vhp->createDate); /* in local time, not GMT! */

    /* Update the logical block size in the mount struct (currently set up from the wrapper MDB)
       using the new blocksize value: */
    hfsmp->hfs_logBlockSize = BestBlockSizeFit(vcb->blockSize, MAXBSIZE, hfsmp->hfs_phys_block_size);
	vcb->vcbVBMIOSize = min(vcb->blockSize, MAXPHYSIO);

    // XXX PPD: Should check here for hardware lock flag and set flags in VCB/MP appropriately
    // vcb->vcbAtrb |= kVolumeHardwareLockMask;	// XXX this line for debugging only!!!!

    //	Initialize our dirID/nodePtr cache associated with this volume.
    retval = InitMRUCache( sizeof(UInt32), kDefaultNumMRUCacheBlocks, &(vcb->hintCachePtr) );
    if (retval != noErr) goto ErrorExit;

	/*
	 * Set up Extents B-tree vnode...
	 */ 
	retval = GetInitializedVNode(hfsmp, &tmpvnode);
	if (retval) goto ErrorExit;
    fdp = &vhp->extentsFile;
    SWAP_HFS_PLUS_FORK_DATA (fdp);
	retval = InitMetaFileVNode(tmpvnode, fdp->logicalSize, fdp->clumpSize, fdp->extents,
								kHFSExtentsFileID, CompareExtentKeysPlus);
    SWAP_HFS_PLUS_FORK_DATA (fdp);
    if (retval) goto ErrorExit;

	/*
	 * Set up Catalog B-tree vnode...
	 */ 
	retval = GetInitializedVNode(hfsmp, &tmpvnode);
	if (retval) goto ErrorExit;
	fdp = &vhp->catalogFile;
    SWAP_HFS_PLUS_FORK_DATA (fdp);
	retval = InitMetaFileVNode(tmpvnode, fdp->logicalSize, fdp->clumpSize, fdp->extents,
								kHFSCatalogFileID, CompareExtendedCatalogKeys);
    SWAP_HFS_PLUS_FORK_DATA (fdp);
	if (retval) goto ErrorExit;

	/*
	 * Set up Allocation file vnode...
	 */  
	retval = GetInitializedVNode(hfsmp, &tmpvnode);
	if (retval) goto ErrorExit;
	fdp = &vhp->allocationFile;
    SWAP_HFS_PLUS_FORK_DATA (fdp);
	retval = InitMetaFileVNode(tmpvnode, fdp->logicalSize, fdp->clumpSize, fdp->extents,
								kHFSAllocationFileID, NULL);
    SWAP_HFS_PLUS_FORK_DATA (fdp);
	if (retval) goto ErrorExit;
 
	/*
	 * Now that Catalog file is open get the volume name from the catalog
	 */
	retval = MacToVFSError( GetVolumeNameFromCatalog(vcb) );	
	if (retval != noErr) goto ErrorExit;

	/* mark the volume dirty (clear clean unmount bit) */
	vcb->vcbAtrb &=	~kHFSVolumeUnmountedMask;

	/* setup private/hidden directory for unlinked files */
	hfsmp->hfs_private_metadata_dir = FindMetaDataDirectory(vcb);

	/*
	 * all done with metadata files so we can unlock now...
	 */
	VOP_UNLOCK(vcb->allocationsRefNum, 0, p);
	VOP_UNLOCK(vcb->catalogRefNum, 0, p);
	VOP_UNLOCK(vcb->extentsRefNum, 0, p);

	if ( !(vcb->vcbAtrb & kHFSVolumeHardwareLockMask) )		//	if the disk is not write protected
	{
		MarkVCBDirty( vcb );								//	mark VCB dirty so it will be written
	}
	
	DBG_VFS(("hfs_MountHFSPlusVolume: returning (%d)\n", retval));

	return (0);


ErrorExit:
	/*
	 * A fatal error occured and the volume cannot be mounted
	 * release any resources that we aquired...
	 */

	DBG_VFS(("hfs_MountHFSPlusVolume: fatal error (%d)\n", retval));

	InvalidateCatalogCache(vcb);
    
	ReleaseMetaFileVNode(vcb->allocationsRefNum);
	ReleaseMetaFileVNode(vcb->catalogRefNum);
	ReleaseMetaFileVNode(vcb->extentsRefNum);

	return (retval);
}


/*
 * ReleaseMetaFileVNode
 *
 * vp	L - -
 */
static void ReleaseMetaFileVNode(struct vnode *vp)
{
	if (vp)
	{
		FCB *fcb = VTOFCB(vp);

		if (fcb->fcbBTCBPtr != NULL)
			(void) BTClosePath(fcb);	/* ignore errors since there is only one path open */

		/* release the node even if BTClosePath fails */
		if (VOP_ISLOCKED(vp))
			vput(vp);
		else
			vrele(vp);
	}
}


/*
 * InitMetaFileVNode
 *
 * vp	U L L
 */
static int InitMetaFileVNode(struct vnode *vp, off_t eof, u_long clumpSize, const HFSPlusExtentRecord extents,
							 HFSCatalogNodeID fileID, void * keyCompareProc)
{
	FCB				*fcb;
	ExtendedVCB		*vcb;
	int				result = 0;

	DBG_ASSERT(vp != NULL);
	DBG_ASSERT(vp->v_data != NULL);

	vcb = VTOVCB(vp);
	fcb = VTOFCB(vp);

	switch (fileID)
	{
		case kHFSExtentsFileID:
			vcb->extentsRefNum = vp;
			break;

		case kHFSCatalogFileID:
			vcb->catalogRefNum = vp;
			break;

		case kHFSAllocationFileID:
			vcb->allocationsRefNum = vp;
			break;

		default:
			panic("InitMetaFileVNode: invalid fileID!");
	}

	fcb->fcbEOF = eof;
	fcb->fcbPLen = eof;
	fcb->fcbClmpSize = clumpSize;
	H_FILEID(VTOH(vp)) = fileID;
	H_DIRID(VTOH(vp)) = kHFSRootParentID;
	H_FORKTYPE(VTOH(vp)) = kSysFile;

    bcopy(extents, fcb->fcbExtents, sizeof(HFSPlusExtentRecord));

	/*
	 * Lock the hfsnode and insert the hfsnode into the hash queue:
	 */
	hfs_vhashins(H_DEV(VTOH(vp)), fileID, VTOH(vp));
	vp->v_flag |= VSYSTEM;	/* tag our metadata files (used by vflush call) */

	/* As the vnode is a system vnode we don't need UBC */
	if(UBCINFOEXISTS(vp)) {
		/* So something is wrong if the it exists */
		panic("ubc exists for system vnode");
	}
    
    if (keyCompareProc != NULL) {
		result = BTOpenPath(fcb,
							(KeyCompareProcPtr) keyCompareProc,
							GetBTreeBlock,
							ReleaseBTreeBlock,
							ExtendBTreeFile,
							SetBTreeBlockSize);
		result = MacToVFSError(result);
	}

    return (result);
}


/*************************************************************
*
* Unmounts a hfs volume.
*	At this point vflush() has been called (to dump all non-metadata files)
*
*************************************************************/

short hfsUnmount( register struct hfsmount *hfsmp, struct proc *p)
{
    ExtendedVCB	*vcb = HFSTOVCB(hfsmp);
    int			retval = E_NONE;

	(void) DisposeMRUCache(vcb->hintCachePtr);
	InvalidateCatalogCache( vcb );
	// XXX PPD: Should dispose of any allocated volume cache here: call DisposeVolumeCacheBlocks( vcb )?

	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, p);
	(void) hfs_metafilelocking(hfsmp, kHFSExtentsFileID, LK_EXCLUSIVE, p);

	if (vcb->vcbSigWord == kHFSPlusSigWord)
		ReleaseMetaFileVNode(vcb->allocationsRefNum);

	ReleaseMetaFileVNode(vcb->catalogRefNum);
	ReleaseMetaFileVNode(vcb->extentsRefNum);

	return (retval);
}


/*
 * hfs_resolvelink - auto resolve HFS+ hardlinks
 *
 * Used after calling GetCatalogNode or GetCatalogOffspring
 */
void hfs_resolvelink(ExtendedVCB *vcb, CatalogNodeData *cndp)
{
	struct FInfo *fip;
	char iNodeName[32];
	UInt32 hint;
	UInt32 indlinkno;
	UInt32 linkparid, linkcnid;
	OSErr result;

	fip = (struct FInfo *) &cndp->cnd_finderInfo;

	/*
	 * if this is an indirect link (hardlink) then auto resolve it...
	 */
	if ((vcb->vcbSigWord == kHFSPlusSigWord)
		&& (cndp->cnd_type == kCatalogFileNode)
	    && (fip->fdType == kHardLinkFileType)
	    && (fip->fdCreator == kHFSPlusCreator)
	    && ((cndp->cnd_createDate == vcb->vcbCrDate) ||
			(cndp->cnd_createDate == VCBTOHFS(vcb)->hfs_metadata_createdate))) {
		
		indlinkno = cndp->cnd_iNodeNum;
		MAKE_INODE_NAME(iNodeName, indlinkno);
		/*
		 * Get nodeData from the data node file. 
		 * Flag the node data to NOT copy the name (ie preserve the original)
		 * Also preserve the parent directory ID.
		 */
		linkparid = cndp->cnm_parID;
		linkcnid = cndp->cnd_nodeID;
		cndp->cnm_flags |= kCatNameNoCopyName;
		result = GetCatalogNode(vcb, VCBTOHFS(vcb)->hfs_private_metadata_dir,
		                iNodeName, 0, 0, cndp, &hint);
		cndp->cnm_flags &= ~kCatNameNoCopyName;

		/* Make sure there's a reference */
		if (result == 0) {
			if (cndp->cnd_linkCount == 0) cndp->cnd_linkCount = 2;
			
			/* Keep a copy of iNodeNum to put into h_indnodeno */
			cndp->cnd_iNodeNumCopy = indlinkno;
			cndp->cnm_parID = linkparid;
			cndp->cnd_linkCNID = linkcnid;
		}
	}
}


/*
 * Performs a lookup on the given dirID, name. Returns the catalog info
 *
 * If len is -1, then it is a null terminated string, pass it along to MacOS as kUndefinedStrLen
 */

short hfs_getcatalog (ExtendedVCB *vcb, UInt32 parentDirID, char *name, short len, hfsCatalogInfo *catInfo)
{
	OSErr result;
    UInt32		length;
	
    if (len == -1 )	{		/* Convert it to MacOS terms */
        if (name)
            length = strlen(name);
        else
            length = kUndefinedStrLen;
    }
	else
        length = len;

	result = GetCatalogNode(vcb, parentDirID, name, length, catInfo->hint, &catInfo->nodeData, 	&catInfo->hint);

#if HFS_DIAGNOSTICS
	if (catInfo->nodeData.cnm_nameptr) {
		DBG_ASSERT(strlen(catInfo->nodeData.cnm_nameptr) == catInfo->nodeData.cnm_length);
	}
#endif

	if (result == 0)
		hfs_resolvelink(vcb, &catInfo->nodeData);

	return MacToVFSError(result);
}



short hfsDelete (ExtendedVCB *vcb, UInt32 parentDirID, StringPtr name, short isfile, UInt32 catalogHint)
{
    OSErr result = noErr;
    
    /* XXX have all the file's blocks been flushed/trashed? */

	/*
	 * DeleteFile will delete the catalog node and then
	 * free up any disk space used by the file.
	 */
	if (isfile)
		result = DeleteFile(vcb, parentDirID, name, catalogHint);
	else /* is a directory */
		result = DeleteCatalogNode(vcb, parentDirID, name, catalogHint);

    if (result)
        DBG_ERR(("on Delete, DeleteFile returned: %d: dirid: %ld name: %s\n", result, parentDirID, name));
		
   	return MacToVFSError(result);
}


short hfsMoveRename (ExtendedVCB *vcb, UInt32 oldDirID, char *oldName, UInt32 newDirID, char *newName, UInt32 *hint)
{
    OSErr result = noErr;

    result = MoveRenameCatalogNode(vcb, oldDirID,oldName, *hint, newDirID, newName, hint, 0);

    if (result)
        DBG_ERR(("on hfsMoveRename, MoveRenameCatalogNode returned: %d: newdirid: %ld newname: %s\n", result, newDirID, newName));
        

    return MacToVFSError(result);
}

/* XXX SER pass back the hint so other people can use it */


short hfsCreate(ExtendedVCB *vcb, UInt32 dirID, char *name, int	mode, UInt32 tehint)
{
    OSErr				result = noErr;
    HFSCatalogNodeID 	catalogNodeID;
    UInt32 				catalogHint;
    UInt32				type;

	/* just test for directories, the default is to create a file (like symlinks) */
	if ((mode & IFMT) == IFDIR)
		type = kCatalogFolderNode;
	else
		type = kCatalogFileNode;

    result = CreateCatalogNode (vcb, dirID, name, type, &catalogNodeID, &catalogHint, tehint);
 
    return MacToVFSError(result);
}


short hfsCreateFileID (ExtendedVCB *vcb, UInt32 parentDirID, StringPtr name, UInt32 catalogHint, UInt32 *fileIDPtr)
{
	return MacToVFSError(CreateFileIDRef(vcb, parentDirID, name, catalogHint, fileIDPtr));
}


/********************************************************************************/
/*																				*/
/*	hfs_vget_catinfo - Returns a vnode derived from a hfs catInfo struct	*/
/*																				*/
/********************************************************************************/

int hfs_vget_catinfo(struct vnode *parent_vp, struct hfsCatalogInfo *catInfo, u_int32_t forkType, struct vnode **target_vp)
{
	int		retval = E_NONE;

    if (forkType == kDefault) {
        if (catInfo->nodeData.cnd_type == kCatalogFolderNode)
            forkType = kDirectory;
        else
            forkType = kDataFork;
    }
    
	*target_vp = hfs_vhashget(H_DEV(VTOH(parent_vp)), catInfo->nodeData.cnd_nodeID, forkType);

	if (*target_vp == NULL)
		retval = hfs_vcreate( VTOVCB(parent_vp), catInfo, forkType, target_vp);

	return (retval);
}



/************************************************************************/
/*	hfs_vcreate - Returns a vnode derived from hfs							*/
/*																		*/
/*	When creating the vnode, care must be made to set the				*/
/*	correct fields in the correct order. Calls to malloc()				*/
/*	and other subroutines, can cause a context switch,					*/
/*	and the fields must be ready for the possibility					*/
/*																		*/
/*											 							*/
/************************************************************************/

short hfs_vcreate(ExtendedVCB *vcb, hfsCatalogInfo *catInfo, UInt8 forkType, struct vnode **vpp)
{
	struct hfsnode		*hp;
	struct vnode		*vp;
	struct hfsmount		*hfsmp;
	struct hfsfilemeta	*fm;
	struct mount		*mp;
	struct vfsFCB		*xfcb;
	dev_t				dev;
	short				retval;

	hfsmp	= VCBTOHFS(vcb);
	mp		= HFSTOVFS(hfsmp);
	dev		= hfsmp->hfs_raw_dev;

	/* Check if unmount in progress */
	if (mp->mnt_kern_flag & MNTK_UNMOUNT) {
		*vpp = NULL;
		return (EPERM);
	}

	/*
	 * If this is a hard link then check if the
	 * data node already exists in our hash.
	 */
	if ((forkType == kDataFork)
		&& (catInfo->nodeData.cnd_type == kCatalogFileNode)
		&& ((catInfo->nodeData.cnd_mode & IFMT) == IFREG)
		&& (catInfo->nodeData.cnd_linkCount > 0)) {
		vp = hfs_vhashget(dev, catInfo->nodeData.cnd_nodeID, kDataFork);
		if (vp != NULL) {
			/* Use the name of the link and it's parent ID. */
			hp = VTOH(vp);
			H_DIRID(hp) = catInfo->nodeData.cnm_parID;
			hfs_set_metaname(catInfo->nodeData.cnm_nameptr, hp->h_meta, hfsmp);
			*vpp = vp;
			return (0);
		}
	}

	MALLOC_ZONE(hp, struct hfsnode *, sizeof(struct hfsnode), M_HFSNODE, M_WAITOK);
	bzero((caddr_t)hp, sizeof(struct hfsnode));
	hp->h_nodeflags |= IN_ALLOCATING;
	lockinit(&hp->h_lock, PINOD, "hfsnode", 0, 0);
	H_FORKTYPE(hp) = forkType;
	rl_init(&hp->h_invalidranges);

	/*
	 * There were several blocking points since we first
	 * checked the hash. Now that we're through blocking,
	 * check the hash again in case we're racing for the
	 * same hnode.
	 */
	vp = hfs_vhashget(dev, catInfo->nodeData.cnd_nodeID, forkType);
	if (vp != NULL) {
		/* We lost the race, use the winner's vnode */
		FREE_ZONE(hp, sizeof(struct hfsnode), M_HFSNODE);
		*vpp = vp;
		UBCINFOCHECK("hfs_vcreate", vp);
		return (0);
	}

	/*
	 * Insert the hfsnode into the hash queue, also if meta exists
	 * add to sibling list and return the meta address
	 */
	fm = NULL;
	if  (SIBLING_FORKTYPE(forkType))
		hfs_vhashins_sibling(dev, catInfo->nodeData.cnd_nodeID, hp, &fm);
	else
		hfs_vhashins(dev, catInfo->nodeData.cnd_nodeID, hp);

	/* Allocate a new vnode. If unsuccesful, leave after freeing memory */
	if ((retval = getnewvnode(VT_HFS, mp, hfs_vnodeop_p, &vp))) {
		hfs_vhashrem(hp);
		if (hp->h_nodeflags & IN_WANT) {
			hp->h_nodeflags &= ~IN_WANT;
			wakeup(hp);
		}
		FREE_ZONE(hp, sizeof(struct hfsnode), M_HFSNODE);
		*vpp = NULL;
		return (retval);
	}
	hp->h_vp = vp;
	vp->v_data = hp;

	hp->h_nodeflags &= ~IN_ALLOCATING;
	if (hp->h_nodeflags & IN_WANT) {
		hp->h_nodeflags &= ~IN_WANT;
		wakeup((caddr_t)hp);
	}

	/*
	 * If needed allocate and init the object meta data:
	 */
	if (fm == NULL) {
		/* Allocate it....remember we can do a context switch here */
		MALLOC_ZONE(fm, struct hfsfilemeta *, sizeof(struct hfsfilemeta), M_HFSFMETA, M_WAITOK);
		bzero(fm, sizeof(struct hfsfilemeta));

		/* Fill it in */
		/*
		 * NOTICE: XXX Even though we have added the vnode to the hash so it is alive on TWO
		 * accessable lists, we  do not assign it until later,
		 * this helps to make sure we do not use a half initiated meta
		 */

		/* Init the sibling list if needed */
		if (SIBLING_FORKTYPE(forkType)) {
			simple_lock_init(&fm->h_siblinglock);
			CIRCLEQ_INIT(&fm->h_siblinghead);
			CIRCLEQ_INSERT_HEAD(&fm->h_siblinghead, hp, h_sibling);
		};

		fm->h_dev = dev;
		CopyCatalogToObjectMeta(catInfo, vp, fm);

		/*
		 * the vnode is finally alive, with the exception of the FCB below,
		 * It is finally locked and ready for its debutante ball
		 */
		hp->h_meta = fm;
	};
	fm->h_usecount++;

	/*
	 * Init the File Control Block.
	 */
	CopyCatalogToFCB(catInfo, vp);

	/*
	 * Finish vnode initialization.
	 * Setting the v_type 'stamps' the vnode as 'complete', so should be done almost last. 
	 * 
	 * At this point the vnode should be locked and fully allocated. And ready to be used
	 * or accessed. (though having it locked prevents most of this, it
	 * can still be accessed through lists and hashs).
	 */
	vp->v_type = IFTOVT(hp->h_meta->h_mode);
	if ((vp->v_type == VREG) 
		&& (UBCINFOMISSING(vp) || UBCINFORECLAIMED(vp))) {
		ubc_info_init(vp);
	}

	/*
	 * Initialize the vnode from the inode, check for aliases, sets the VROOT flag.
	 * Note that the underlying vnode may have changed.
	 */
	if ((retval = hfs_vinit(mp, hfs_specop_p, hfs_fifoop_p, &vp))) {
		vput(vp);
		*vpp = NULL;
		return (retval);
	}

	/*
	 * Finish inode initialization now that aliasing has been resolved.
	 */
	hp->h_meta->h_devvp = hfsmp->hfs_devvp;
	VREF(hp->h_meta->h_devvp);
    
	*vpp = vp;
	return 0;
}

void CopyCatalogToObjectMeta(struct hfsCatalogInfo *catalogInfo, struct vnode *vp, struct hfsfilemeta *fm)
{
	ExtendedVCB				*vcb = VTOVCB(vp);
	struct mount			*mp = VTOVFS(vp);
	Boolean					isHFSPlus, isDirectory;
	ushort					finderFlags;
	ushort filetype;

	DBG_ASSERT (fm != NULL);
	DBG_ASSERT (fm->h_namelen == 0);
	DBG_ASSERT (fm->h_namePtr == 0);
	
	DBG_UTILS(("\tCopying to file's meta data: name:%s, nodeid:%ld\n", catalogInfo->nodeData.cnm_nameptr, catalogInfo->nodeData.cnd_nodeID));

	isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);
	isDirectory = (catalogInfo->nodeData.cnd_type == kCatalogFolderNode);
	finderFlags = SWAP_BE16 (((struct FInfo *)(&catalogInfo->nodeData.cnd_finderInfo))->fdFlags);

	/* Copy over the dirid, and hint */
	fm->h_nodeID = catalogInfo->nodeData.cnd_nodeID;
	fm->h_dirID = catalogInfo->nodeData.cnm_parID;
	fm->h_hint = catalogInfo->hint;

	/* Copy over the name */
	hfs_name_CatToMeta(&catalogInfo->nodeData, fm);


	/* get dates in BSD format */
	fm->h_mtime = to_bsd_time(catalogInfo->nodeData.cnd_contentModDate);
	fm->h_crtime = to_bsd_time(catalogInfo->nodeData.cnd_createDate);
	fm->h_butime = to_bsd_time(catalogInfo->nodeData.cnd_backupDate);
	if (isHFSPlus) {
		fm->h_atime = to_bsd_time(catalogInfo->nodeData.cnd_accessDate);
		fm->h_ctime = to_bsd_time(catalogInfo->nodeData.cnd_attributeModDate);
	}
	else {
		fm->h_atime = to_bsd_time(catalogInfo->nodeData.cnd_contentModDate);
		fm->h_ctime = to_bsd_time(catalogInfo->nodeData.cnd_contentModDate);
	}

	/* Now the rest */
	if (isHFSPlus && (catalogInfo->nodeData.cnd_mode & IFMT)) {
		fm->h_uid = catalogInfo->nodeData.cnd_ownerID;
		fm->h_gid = catalogInfo->nodeData.cnd_groupID;
		fm->h_pflags = catalogInfo->nodeData.cnd_ownerFlags |
		               (catalogInfo->nodeData.cnd_adminFlags << 16);
		fm->h_mode = (mode_t)catalogInfo->nodeData.cnd_mode;
#if 1
		if (fm->h_uid == 0xFFFFFFFD) {	/* 0xfffffffd = 4294967293, the old "unknown" */
			fm->h_uid = UNKNOWNUID;
			fm->h_metaflags |= IN_CHANGE;
			vcb->vcbFlags |= kHFS_DamagedVolume;	/* Trigger fsck on next mount */
		};
		if (fm->h_gid == 0xFFFFFFFD) {	/* 0xfffffffd = 4294967293, the old "unknown" */
			fm->h_gid = UNKNOWNGID;
			fm->h_metaflags |= IN_CHANGE;
			vcb->vcbFlags |= kHFS_DamagedVolume;	/* Trigger fsck on next mount */
		};
#endif
		filetype = fm->h_mode & IFMT;
		if (filetype == IFCHR || filetype == IFBLK)
			fm->h_rdev = catalogInfo->nodeData.cnd_rawDevice;
		else {
			fm->h_rdev = 0;
#if HFS_HARDLINKS
			if (catalogInfo->nodeData.cnd_type == kCatalogFileNode  &&
			    catalogInfo->nodeData.cnd_linkCount > 0) {
				fm->h_nlink = catalogInfo->nodeData.cnd_linkCount;
				fm->h_indnodeno = catalogInfo->nodeData.cnd_iNodeNumCopy;
				fm->h_metaflags |= IN_DATANODE;
			}
#endif
		}

		if (mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
			/*
			 *	Override the permissions as determined by the mount auguments
			 *  in ALMOST the same way unset permissions are treated but keep
			 *	track of whether or not the file or folder is hfs locked
			 *  by leaving the h_pflags field unchanged from what was unpacked
			 *  out of the catalog.
			 */ 
			fm->h_metaflags |= IN_UNSETACCESS;			
			fm->h_uid = VTOHFS(vp)->hfs_uid;
			fm->h_gid = VTOHFS(vp)->hfs_gid;
#if OVERRIDE_UNKNOWN_PERMISSIONS
			/* Default access is full read/write/execute: */
			/* XXX won't this smash IFCHR, IFBLK and IFLNK (for no-follow lookups)? */
			fm->h_mode = ACCESSPERMS;	/* 0777: rwxrwxrwx */
			fm->h_rdev = 0;
			
			/* ... but no more than that permitted by the mount point's: */
			if (isDirectory) {
				fm->h_mode &= VTOHFS(vp)->hfs_dir_mask;
			}
			else {
				fm->h_mode &= VTOHFS(vp)->hfs_file_mask;
			}
			
			if(isDirectory)
				fm->h_mode |= IFDIR;
			else if (SUPPORTS_MAC_ALIASES && (finderFlags & kIsAlias))	/* aliases will be symlinks in the future */
				fm->h_mode |= IFLNK;
			else
				fm->h_mode |= IFREG;
#endif
		};
	} else {
		/*
		 *	Set the permissions as determined by the mount auguments
		 *	but keep in account if the file or folder is hfs locked
		 */ 
		fm->h_metaflags |= IN_UNSETACCESS;			
		fm->h_uid = VTOHFS(vp)->hfs_uid;
		fm->h_gid = VTOHFS(vp)->hfs_gid;
		fm->h_pflags = 0;	/* No valid pflags on disk (IMMUTABLE is synced from lock flag later) */
		fm->h_rdev = 0;		/* No valid rdev on disk */
		/* Default access is full read/write/execute: */
		fm->h_mode = ACCESSPERMS;	/* 0777: rwxrwxrwx */
		
		/* ... but no more than that permitted by the mount point's: */
		if (isDirectory) {
			fm->h_mode &= VTOHFS(vp)->hfs_dir_mask;
		}
		else {
			fm->h_mode &= VTOHFS(vp)->hfs_file_mask;
		}
		
		if(isDirectory)
			fm->h_mode |= IFDIR;
		else if (SUPPORTS_MAC_ALIASES && (finderFlags & kIsAlias))	/* aliases will be symlinks in the future */
			fm->h_mode |= IFLNK;
		else
			fm->h_mode |= IFREG;
	};

	/* Make sure that there is no nodeType/mode mismatch */
	if (isDirectory && ((fm->h_mode & IFMT) != IFDIR)) {
	 	fm->h_mode &= ~IFMT;		/* Clear the bad bits */
	 	fm->h_mode |= IFDIR;		/* Set the proper one */
	};

	/* Make sure the IMMUTABLE bits are in sync with the locked flag in the catalog: */
	if (!isDirectory) {
		if (catalogInfo->nodeData.cnd_flags & kHFSFileLockedMask) {
			/* The file's supposed to be locked:
			   Make sure at least one of the IMMUTABLE bits is set: */
			if ((fm->h_pflags & (SF_IMMUTABLE | UF_IMMUTABLE)) == 0) {
				fm->h_pflags |= UF_IMMUTABLE;				/* Set the user-changable IMMUTABLE bit */
			};
		} else {
			/* The file's supposed to be unlocked: */
			fm->h_pflags &= ~(SF_IMMUTABLE | UF_IMMUTABLE);
		};
	};

	if (isDirectory) {
		fm->h_nlink = 2 + catalogInfo->nodeData.cnd_valence;
		fm->h_size = (2 * sizeof(hfsdotentry)) + 
			(catalogInfo->nodeData.cnd_valence * AVERAGE_HFSDIRENTRY_SIZE);
		if (fm->h_size < MAX_HFSDIRENTRY_SIZE)
			fm->h_size = MAX_HFSDIRENTRY_SIZE;
	} else {
		fm->h_size = (off_t)vcb->blockSize *
			(off_t)(catalogInfo->nodeData.cnd_rsrcfork.totalBlocks +
			 catalogInfo->nodeData.cnd_datafork.totalBlocks);
	}
}


void CopyCatalogToFCB(struct hfsCatalogInfo *catalogInfo, struct vnode *vp)
{
	FCB 					*fcb = VTOFCB(vp);
	ExtendedVCB				*vcb = VTOVCB(vp);
	Boolean					isHFSPlus, isDirectory, isResource;
	HFSPlusExtentDescriptor *extents;
	UInt8					forkType;

	DBG_ASSERT (vp != NULL);
	DBG_ASSERT (fcb != NULL);
	DBG_ASSERT (vcb != NULL);
	DBG_ASSERT (VTOH(vp) != NULL);

	forkType = H_FORKTYPE(VTOH(vp));
	isResource = (forkType == kRsrcFork);
	isDirectory = (catalogInfo->nodeData.cnd_type == kCatalogFolderNode);
	isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);

	/* Init the fcb */
	fcb->fcbFlags = catalogInfo->nodeData.cnd_flags;

	if (forkType != kDirectory) {
		fcb->fcbFlags &= kHFSFileLockedMask;		/* Clear resource, dirty bits */
		if (fcb->fcbFlags != 0)						/* if clear, its not locked, then.. */
			fcb->fcbFlags = fcbFileLockedMask;		/* duplicate the bit for later use */

		fcb->fcbClmpSize = vcb->vcbClpSiz;	/*XXX why not use the one in catalogInfo? */

		if (isResource) 
			extents = catalogInfo->nodeData.cnd_rsrcfork.extents;
		else
			extents = catalogInfo->nodeData.cnd_datafork.extents;

		/* Copy the extents to their correct location: */
		bcopy (extents, fcb->fcbExtents, sizeof(HFSPlusExtentRecord));

		if (isResource) {	
			fcb->fcbEOF = catalogInfo->nodeData.cnd_rsrcfork.logicalSize;
			fcb->fcbPLen = (off_t)((off_t)catalogInfo->nodeData.cnd_rsrcfork.totalBlocks * (off_t)vcb->blockSize);
			fcb->fcbFlags |= fcbResourceMask;
		}  else {
			fcb->fcbEOF = catalogInfo->nodeData.cnd_datafork.logicalSize;
			fcb->fcbPLen = (off_t)((off_t)catalogInfo->nodeData.cnd_datafork.totalBlocks * (off_t)vcb->blockSize);
		};
	};


}

int hasOverflowExtents(struct hfsnode *hp)
{
	ExtendedVCB		*vcb = HTOVCB(hp);
	FCB				*fcb = HTOFCB(hp);
	u_long			blocks;

	if (vcb->vcbSigWord == kHFSPlusSigWord)
	  {

		if (fcb->fcbExtents[7].blockCount == 0)
			return false;
		
		blocks = fcb->fcbExtents[0].blockCount +
				 fcb->fcbExtents[1].blockCount +
				 fcb->fcbExtents[2].blockCount +
				 fcb->fcbExtents[3].blockCount +
				 fcb->fcbExtents[4].blockCount +
				 fcb->fcbExtents[5].blockCount +
				 fcb->fcbExtents[6].blockCount +
				 fcb->fcbExtents[7].blockCount;	
	  }
	else
	  {
		if (fcb->fcbExtents[2].blockCount == 0)
			return false;
		
		blocks = fcb->fcbExtents[0].blockCount +
				 fcb->fcbExtents[1].blockCount +
				 fcb->fcbExtents[2].blockCount;	
	  }

	return ((fcb->fcbPLen / vcb->blockSize) > blocks);
}


int hfs_metafilelocking(struct hfsmount *hfsmp, u_long fileID, u_int flags, struct proc *p)
{
	ExtendedVCB		*vcb;
	struct vnode	*vp = NULL;
	int				numOfLockedBuffs;
	int	retval = 0;

	vcb = HFSTOVCB(hfsmp);

	DBG_UTILS(("hfs_metafilelocking: vol: %d, file: %d %s%s%s\n", vcb->vcbVRefNum, fileID,
			((flags & LK_TYPE_MASK) == LK_RELEASE ? "RELEASE" : ""),
			((flags & LK_TYPE_MASK) == LK_EXCLUSIVE ? "EXCLUSIVE" : ""),
			((flags & LK_TYPE_MASK) == LK_SHARED ? "SHARED" : "") ));


 	switch (fileID)
	{
		case kHFSExtentsFileID:
			vp = vcb->extentsRefNum;
			break;

		case kHFSCatalogFileID:
			vp = vcb->catalogRefNum;
			break;

		case kHFSAllocationFileID:
			/* bitmap is covered by Extents B-tree locking */
			/* FALL THROUGH */
		default:
			panic("hfs_lockmetafile: invalid fileID");
	}

	if (vp != NULL) {

		/* Release, if necesary any locked buffer caches */
    	if ((flags & LK_TYPE_MASK) == LK_RELEASE) {
   			struct timeval tv = time;
			u_int32_t		lastfsync = tv.tv_sec; 
			
			(void) BTGetLastSync(VTOFCB(vp), &lastfsync);
			
			numOfLockedBuffs = count_lock_queue();
			if ((numOfLockedBuffs > kMaxLockedMetaBuffers) || ((numOfLockedBuffs>1) && ((tv.tv_sec - lastfsync) > kMaxSecsForFsync))) {
			   	DBG_UTILS(("Synching meta deta: %d... # locked buffers = %d, fsync gap = %ld\n", H_FILEID(VTOH(vp)),
			   			numOfLockedBuffs, (tv.tv_sec - lastfsync)));
				hfs_fsync_transaction(vp);
			};
		};
		
		retval = lockmgr(&VTOH(vp)->h_lock, flags, &vp->v_interlock, p);
	};

	return retval;
}


/*
 * There are three ways to qualify for ownership rights on an object:
 *
 * 1. (a) Your UID matches the UID of the vnode
 *    (b) The object in question is owned by "unknown" and your UID matches the console user's UID
 * 2. (a) Permissions on the filesystem are being ignored and your UID matches the replacement UID
 *    (b) Permissions on the filesystem are being ignored and the replacement UID is "unknown" and
 *        your UID matches the console user UID
 * 3. You are root
 *
 */
int hfs_owner_rights(struct vnode *vp, struct ucred *cred, struct proc *p, Boolean invokesuperuserstatus) {
    return ((cred->cr_uid == VTOH(vp)->h_meta->h_uid) ||										/* [1a] */
    		((VTOH(vp)->h_meta->h_uid == UNKNOWNUID) && (cred->cr_uid == console_user)) ||		/* [1b] */
    		((VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) &&									/* [2] */
    		 ((cred->cr_uid == VTOHFS(vp)->hfs_uid) ||											/* [2a] */
    		  ((VTOHFS(vp)->hfs_uid == UNKNOWNUID) && (cred->cr_uid == console_user)))) ||		/* [2b] */
    		(invokesuperuserstatus && (suser(cred, &p->p_acflag) == 0))) ? 0 : EPERM;
}



int hfs_catalogentry_owner_rights(uid_t obj_uid, struct mount *mp, struct ucred *cred, struct proc *p, Boolean invokesuperuserstatus) {
    return ((cred->cr_uid == obj_uid) ||														/* [1a] */
    		((obj_uid == UNKNOWNUID) && (cred->cr_uid == console_user)) ||						/* [1b] */
    		((mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) &&											/* [2] */
    		 ((cred->cr_uid == VFSTOHFS(mp)->hfs_uid) ||										/* [2a] */
    		  ((VFSTOHFS(mp)->hfs_uid == UNKNOWNUID) && (cred->cr_uid == console_user)))) ||	/* [2b] */
    		(invokesuperuserstatus && (suser(cred, &p->p_acflag) == 0))) ? 0 : EPERM;
}



void CopyVNodeToCatalogNode (struct vnode *vp, struct CatalogNodeData *nodeData)
{
    ExtendedVCB 			*vcb;
    FCB						*fcb;
    struct hfsnode 			*hp;
    Boolean					isHFSPlus, isResource;
    HFSPlusExtentDescriptor	*extents;
    off_t					fileReadLimit;

    hp = VTOH(vp);
    vcb = HTOVCB(hp);
    fcb = HTOFCB(hp);
    isResource = (H_FORKTYPE(hp) == kRsrcFork);
    isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);

    /* date and time of last fork modification */
    if (hp->h_meta->h_mtime != 0)
		nodeData->cnd_contentModDate = to_hfs_time(hp->h_meta->h_mtime);

	if (isHFSPlus) {
		/* Make sure that there is no nodeType/mode mismatch */
		if ((nodeData->cnd_type == kCatalogFolderNode) 
				&& ((hp->h_meta->h_mode & IFMT) != IFDIR)) {

			DBG_ASSERT((hp->h_meta->h_mode & IFMT) == IFDIR);
		 	hp->h_meta->h_mode &= ~IFMT;		/* Clear the bad bits */
		 	hp->h_meta->h_mode |= IFDIR;		/* Set the proper one */
		};
		/* date and time of last modification (any kind) */
		if (hp->h_meta->h_ctime != 0)
			nodeData->cnd_attributeModDate = to_hfs_time(hp->h_meta->h_ctime);
		/* date and time of last access (MacOS X only) */
		if (hp->h_meta->h_atime != 0)
			nodeData->cnd_accessDate = to_hfs_time(hp->h_meta->h_atime);
		/* hfs_setattr can change the create date */
		if (hp->h_meta->h_crtime != 0)
			nodeData->cnd_createDate = to_hfs_time(hp->h_meta->h_crtime);
		if (! (hp->h_meta->h_metaflags & IN_UNSETACCESS)) {
			nodeData->cnd_adminFlags = hp->h_meta->h_pflags >> 16;
			nodeData->cnd_ownerFlags = hp->h_meta->h_pflags & 0x000000FF;
			nodeData->cnd_mode = hp->h_meta->h_mode;
			nodeData->cnd_ownerID = hp->h_meta->h_uid;
			nodeData->cnd_groupID = hp->h_meta->h_gid;
		}
	};

	/* the rest only applies to files */
	if (nodeData->cnd_type == kCatalogFileNode) {
		if (hp->h_meta->h_pflags & (SF_IMMUTABLE | UF_IMMUTABLE)) {
			/* The file is locked: set the locked bit in the catalog. */
			nodeData->cnd_flags |= kHFSFileLockedMask;
		} else {
			/* The file is unlocked: make sure the locked bit in the catalog is clear. */
			nodeData->cnd_flags &= ~kHFSFileLockedMask;
		};
		if (CIRCLEQ_EMPTY(&hp->h_invalidranges)) {
			fileReadLimit = fcb->fcbEOF;
		} else {
			fileReadLimit = CIRCLEQ_FIRST(&hp->h_invalidranges)->rl_start;
		};
		if (isResource) {
			extents = nodeData->cnd_rsrcfork.extents;
			nodeData->cnd_rsrcfork.logicalSize = fileReadLimit;
			nodeData->cnd_rsrcfork.totalBlocks = fcb->fcbPLen / vcb->blockSize;
		} else {
			extents = nodeData->cnd_datafork.extents;
			nodeData->cnd_datafork.logicalSize = fileReadLimit;
			nodeData->cnd_datafork.totalBlocks = fcb->fcbPLen / vcb->blockSize;
		};

		bcopy ( fcb->fcbExtents, extents, sizeof(HFSPlusExtentRecord));

		if ((vp->v_type == VBLK) || (vp->v_type == VCHR))
			nodeData->cnd_rawDevice = hp->h_meta->h_rdev;
		else if (hp->h_meta->h_metaflags & IN_DATANODE)
			nodeData->cnd_linkCount = hp->h_meta->h_nlink;
	
	    if (vp->v_type == VLNK) {
	        ((struct FInfo *)(&nodeData->cnd_finderInfo))->fdType = SWAP_BE32 (kSymLinkFileType);
	        ((struct FInfo *)(&nodeData->cnd_finderInfo))->fdCreator = SWAP_BE32 (kSymLinkCreator);
	
			/* Set this up as an alias */
			#if SUPPORTS_MAC_ALIASES
				((struct FInfo *)(&nodeData->cnd_finderInfo))->fdFlags |= SWAP_BE16 (kIsAlias);
			#endif
		}
	}
 }


/*********************************************************************

	Sets the name in the filemeta structure

	XXX Does not preflight if changing from one size to another
	XXX Currently not protected from context switching

*********************************************************************/

void hfs_set_metaname(char *name, struct hfsfilemeta *fm, struct hfsmount *hfsmp)
{
int			namelen = strlen(name);
char		*tname, *fname;

#if HFS_DIAGNOSTIC
	DBG_ASSERT(name != NULL);
	DBG_ASSERT(fm != NULL);
    if (fm->h_namePtr) {
        DBG_ASSERT(fm->h_namelen == strlen(fm->h_namePtr));
        if (strlen(fm->h_namePtr) > MAXHFSVNODELEN)
            DBG_ASSERT(fm->h_metaflags & IN_LONGNAME);
	};
	if (fm->h_metaflags & IN_LONGNAME) {
		DBG_ASSERT(fm->h_namePtr != (char *)fm->h_fileName);
		DBG_ASSERT(fm->h_namePtr != NULL);
	};
#endif	//HFS_DIAGNOSTIC
	
	/*
	 * Details that have to be dealt with:
	 * 1. No name is allocated. fm->h_namePtr should be NULL
	 * 2. A name is being changed and:
	 *	a. it was in static space and now cannot fit
	 *	b. It was malloc'd and now will fit in the static
	 *	c. It did and will fit in the static
	 * This could be a little smarter:
	 * - Dont re'malloc if the new name is smaller (but then wasting memory)
	 * - If its a longname but the same size, we still free and malloc
	 * - 
	 */

	
	/* Allocate the new memory */
	if (namelen > MAXHFSVNODELEN) {
		/*
		 * Notice the we ALWAYS allocate, even if the new is less then the old,
		 * or even if they are the SAME
		 */
		MALLOC(tname, char *, namelen+1, M_TEMP, M_WAITOK);
	}
	else
		tname = fm->h_fileName;

	simple_lock(&hfsmp->hfs_renamelock);
	
	/* Check to see if there is something to free, if yes, remember it */ 
	if (fm->h_metaflags & IN_LONGNAME)
		fname = fm->h_namePtr;
	else
		fname = NULL;
	
	/* Set the flag */
	if (namelen > MAXHFSVNODELEN) {
		fm->h_metaflags |= IN_LONGNAME;
		}
		else {
		fm->h_metaflags &= ~IN_LONGNAME;
	};

	/* Now copy it over */
	bcopy(name, tname, namelen+1);

	fm->h_namePtr = tname;
	fm->h_namelen = namelen;

	simple_unlock(&hfsmp->hfs_renamelock);

	/* Lastly, free the old, if set */
	if (fname != NULL)
		FREE(fname, M_TEMP);

}

void hfs_name_CatToMeta(CatalogNodeData *nodeData, struct hfsfilemeta *fm)
{
char		*fname;

#if HFS_DIAGNOSTIC
	DBG_ASSERT(nodeData != NULL);
	DBG_ASSERT(fm != NULL);
    if (fm->h_namePtr) {
        DBG_ASSERT(fm->h_namelen == strlen(fm->h_namePtr));
        if (strlen(fm->h_namePtr) > MAXHFSVNODELEN)
            DBG_ASSERT(fm->h_metaflags & IN_LONGNAME);
	};
	if (fm->h_metaflags & IN_LONGNAME) {
		DBG_ASSERT(fm->h_namePtr != (char *)fm->h_fileName);
		DBG_ASSERT(fm->h_namePtr != NULL);
	};
	
	DBG_ASSERT(nodeData->cnm_nameptr != NULL);
	
	if (nodeData->cnm_length) {
		DBG_ASSERT(strlen(nodeData->cnm_nameptr) == nodeData->cnm_length);
		}
	
	if (nodeData->cnm_length > MAXHFSVNODELEN) 
		{ DBG_ASSERT(nodeData->cnm_nameptr != nodeData->cnm_namespace); }
	else if (nodeData->cnm_nameptr) 
		{ DBG_ASSERT(nodeData->cnm_nameptr == nodeData->cnm_namespace); }

#endif	//HFS_DIAGNOSTIC
	

	/* Check to see if there is something to free, if yes, remember it */ 
	if (fm->h_metaflags & IN_LONGNAME)
		fname = fm->h_namePtr;
	else
		fname = NULL;

	/* Set the flag */
	if (nodeData->cnm_length > MAXHFSVNODELEN) {
		fm->h_metaflags |= IN_LONGNAME;
	} else {
		fm->h_metaflags &= ~IN_LONGNAME;
	};

	/* Copy over the name */
	if (nodeData->cnm_nameptr == nodeData->cnm_namespace) {
		bcopy(nodeData->cnm_namespace, fm->h_fileName, nodeData->cnm_length+1);
		fm->h_namePtr = fm->h_fileName;
	} 
	else {
		fm->h_namePtr = nodeData->cnm_nameptr;
	}

	fm->h_namelen = nodeData->cnm_length;

	nodeData->cnm_flags |= kCatNameIsConsumed;
	nodeData->cnm_flags &= ~kCatNameIsAllocated;
	nodeData->cnm_length =  0;
	nodeData->cnm_nameptr =  (char *)0;
	nodeData->cnm_namespace[0] = 0;

	/* Lastly, free the old, if set */
	if (fname != NULL)
		FREE(fname, M_TEMP);
}



unsigned long DerivePermissionSummary(uid_t obj_uid, gid_t obj_gid, mode_t obj_mode, struct mount *mp, struct ucred *cred, struct proc *p) {
    register gid_t *gp;
    unsigned long permissions;
    int i;

     /* User id 0 (root) always gets access. */
     if (cred->cr_uid == 0) {
         permissions = R_OK | W_OK | X_OK;
         goto Exit;
     };

    /* Otherwise, check the owner. */
    if (hfs_catalogentry_owner_rights(obj_uid, mp, cred, p, false) == 0) {
        permissions = ((unsigned long)obj_mode & S_IRWXU) >> 6;
        goto Exit;
    }

    /* Otherwise, check the groups. */
    if (! (mp->mnt_flag & MNT_UNKNOWNPERMISSIONS)) {
	    for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++) {
	        if (obj_gid == *gp) {
	            permissions = ((unsigned long)obj_mode & S_IRWXG) >> 3;
				goto Exit;
	        }
	    };
	};

    /* Otherwise, settle for 'others' access. */
    permissions = (unsigned long)obj_mode & S_IRWXO;

Exit:
	return permissions;    
}



int AttributeBlockSize(struct attrlist *attrlist) {
	int size;
	attrgroup_t a;
	
#if ((ATTR_CMN_NAME			| ATTR_CMN_DEVID			| ATTR_CMN_FSID 			| ATTR_CMN_OBJTYPE 		| \
      ATTR_CMN_OBJTAG		| ATTR_CMN_OBJID			| ATTR_CMN_OBJPERMANENTID	| ATTR_CMN_PAROBJID		| \
      ATTR_CMN_SCRIPT		| ATTR_CMN_CRTIME			| ATTR_CMN_MODTIME			| ATTR_CMN_CHGTIME		| \
      ATTR_CMN_ACCTIME		| ATTR_CMN_BKUPTIME			| ATTR_CMN_FNDRINFO			| ATTR_CMN_OWNERID		| \
      ATTR_CMN_GRPID		| ATTR_CMN_ACCESSMASK		| ATTR_CMN_NAMEDATTRCOUNT	| ATTR_CMN_NAMEDATTRLIST| \
      ATTR_CMN_FLAGS		| ATTR_CMN_USERACCESS) != ATTR_CMN_VALIDMASK)
#error AttributeBlockSize: Missing bits in common mask computation!
#endif
          DBG_ASSERT((attrlist->commonattr & ~ATTR_CMN_VALIDMASK) == 0);

#if ((ATTR_VOL_FSTYPE		| ATTR_VOL_SIGNATURE		| ATTR_VOL_SIZE				| ATTR_VOL_SPACEFREE 	| \
      ATTR_VOL_SPACEAVAIL	| ATTR_VOL_MINALLOCATION	| ATTR_VOL_ALLOCATIONCLUMP	| ATTR_VOL_IOBLOCKSIZE	| \
      ATTR_VOL_OBJCOUNT		| ATTR_VOL_FILECOUNT		| ATTR_VOL_DIRCOUNT			| ATTR_VOL_MAXOBJCOUNT	| \
      ATTR_VOL_MOUNTPOINT	| ATTR_VOL_NAME				| ATTR_VOL_MOUNTFLAGS       | ATTR_VOL_INFO			| \
      ATTR_VOL_MOUNTEDDEVICE| ATTR_VOL_ENCODINGSUSED	| ATTR_VOL_CAPABILITIES		| ATTR_VOL_ATTRIBUTES) != ATTR_VOL_VALIDMASK)
#error AttributeBlockSize: Missing bits in volume mask computation!
#endif
          DBG_ASSERT((attrlist->volattr & ~ATTR_VOL_VALIDMASK) == 0);

#if ((ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT | ATTR_DIR_MOUNTSTATUS) != ATTR_DIR_VALIDMASK)
#error AttributeBlockSize: Missing bits in directory mask computation!
#endif
      DBG_ASSERT((attrlist->dirattr & ~ATTR_DIR_VALIDMASK) == 0);
#if ((ATTR_FILE_LINKCOUNT	| ATTR_FILE_TOTALSIZE		| ATTR_FILE_ALLOCSIZE 		| ATTR_FILE_IOBLOCKSIZE 	| \
      ATTR_FILE_CLUMPSIZE	| ATTR_FILE_DEVTYPE			| ATTR_FILE_FILETYPE		| ATTR_FILE_FORKCOUNT		| \
      ATTR_FILE_FORKLIST	| ATTR_FILE_DATALENGTH		| ATTR_FILE_DATAALLOCSIZE	| ATTR_FILE_DATAEXTENTS		| \
      ATTR_FILE_RSRCLENGTH	| ATTR_FILE_RSRCALLOCSIZE	| ATTR_FILE_RSRCEXTENTS) != ATTR_FILE_VALIDMASK)
#error AttributeBlockSize: Missing bits in file mask computation!
#endif
          DBG_ASSERT((attrlist->fileattr & ~ATTR_FILE_VALIDMASK) == 0);

#if ((ATTR_FORK_TOTALSIZE | ATTR_FORK_ALLOCSIZE) != ATTR_FORK_VALIDMASK)
#error AttributeBlockSize: Missing bits in fork mask computation!
#endif
      DBG_ASSERT((attrlist->forkattr & ~ATTR_FORK_VALIDMASK) == 0);

	size = 0;
	
	if ((a = attrlist->commonattr) != 0) {
        if (a & ATTR_CMN_NAME) size += sizeof(struct attrreference);
		if (a & ATTR_CMN_DEVID) size += sizeof(dev_t);
		if (a & ATTR_CMN_FSID) size += sizeof(fsid_t);
		if (a & ATTR_CMN_OBJTYPE) size += sizeof(fsobj_type_t);
		if (a & ATTR_CMN_OBJTAG) size += sizeof(fsobj_tag_t);
		if (a & ATTR_CMN_OBJID) size += sizeof(fsobj_id_t);
        if (a & ATTR_CMN_OBJPERMANENTID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_PAROBJID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_SCRIPT) size += sizeof(text_encoding_t);
		if (a & ATTR_CMN_CRTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_MODTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_CHGTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_ACCTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_BKUPTIME) size += sizeof(struct timespec);
		if (a & ATTR_CMN_FNDRINFO) size += 32 * sizeof(UInt8);
		if (a & ATTR_CMN_OWNERID) size += sizeof(uid_t);
		if (a & ATTR_CMN_GRPID) size += sizeof(gid_t);
		if (a & ATTR_CMN_ACCESSMASK) size += sizeof(u_long);
		if (a & ATTR_CMN_NAMEDATTRCOUNT) size += sizeof(u_long);
		if (a & ATTR_CMN_NAMEDATTRLIST) size += sizeof(struct attrreference);
		if (a & ATTR_CMN_FLAGS) size += sizeof(u_long);
		if (a & ATTR_CMN_USERACCESS) size += sizeof(u_long);
	};
	if ((a = attrlist->volattr) != 0) {
		if (a & ATTR_VOL_FSTYPE) size += sizeof(u_long);
		if (a & ATTR_VOL_SIGNATURE) size += sizeof(u_long);
		if (a & ATTR_VOL_SIZE) size += sizeof(off_t);
		if (a & ATTR_VOL_SPACEFREE) size += sizeof(off_t);
		if (a & ATTR_VOL_SPACEAVAIL) size += sizeof(off_t);
		if (a & ATTR_VOL_MINALLOCATION) size += sizeof(off_t);
		if (a & ATTR_VOL_ALLOCATIONCLUMP) size += sizeof(off_t);
		if (a & ATTR_VOL_IOBLOCKSIZE) size += sizeof(u_long);
		if (a & ATTR_VOL_OBJCOUNT) size += sizeof(u_long);
		if (a & ATTR_VOL_FILECOUNT) size += sizeof(u_long);
		if (a & ATTR_VOL_DIRCOUNT) size += sizeof(u_long);
		if (a & ATTR_VOL_MAXOBJCOUNT) size += sizeof(u_long);
		if (a & ATTR_VOL_MOUNTPOINT) size += sizeof(struct attrreference);
        if (a & ATTR_VOL_NAME) size += sizeof(struct attrreference);
        if (a & ATTR_VOL_MOUNTFLAGS) size += sizeof(u_long);
        if (a & ATTR_VOL_MOUNTEDDEVICE) size += sizeof(struct attrreference);
        if (a & ATTR_VOL_ENCODINGSUSED) size += sizeof(unsigned long long);
        if (a & ATTR_VOL_CAPABILITIES) size += sizeof(vol_capabilities_attr_t);
        if (a & ATTR_VOL_ATTRIBUTES) size += sizeof(vol_attributes_attr_t);
	};
	if ((a = attrlist->dirattr) != 0) {
		if (a & ATTR_DIR_LINKCOUNT) size += sizeof(u_long);
		if (a & ATTR_DIR_ENTRYCOUNT) size += sizeof(u_long);
		if (a & ATTR_DIR_MOUNTSTATUS) size += sizeof(u_long);
	};
	if ((a = attrlist->fileattr) != 0) {
		if (a & ATTR_FILE_LINKCOUNT) size += sizeof(u_long);
		if (a & ATTR_FILE_TOTALSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_ALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_IOBLOCKSIZE) size += sizeof(size_t);
		if (a & ATTR_FILE_CLUMPSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_DEVTYPE) size += sizeof(u_long);
		if (a & ATTR_FILE_FILETYPE) size += sizeof(u_long);
		if (a & ATTR_FILE_FORKCOUNT) size += sizeof(u_long);
		if (a & ATTR_FILE_FORKLIST) size += sizeof(struct attrreference);
		if (a & ATTR_FILE_DATALENGTH) size += sizeof(off_t);
		if (a & ATTR_FILE_DATAALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_DATAEXTENTS) size += sizeof(extentrecord);
		if (a & ATTR_FILE_RSRCLENGTH) size += sizeof(off_t);
		if (a & ATTR_FILE_RSRCALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_RSRCEXTENTS) size += sizeof(extentrecord);
	};
	if ((a = attrlist->forkattr) != 0) {
		if (a & ATTR_FORK_TOTALSIZE) size += sizeof(off_t);
		if (a & ATTR_FORK_ALLOCSIZE) size += sizeof(off_t);
	};

    return size;
}



char* FindMountpointName(struct mount *mp) {
	size_t namelength = strlen(mp->mnt_stat.f_mntonname);
	int foundchars = 0;
	char *c;
	
	if (namelength == 0) return NULL;
	
	/* Look backwards through the name string, looking for the first slash
	   encountered (which must precede the last part of the pathname)
	 */
	for (c = mp->mnt_stat.f_mntonname + namelength - 1; namelength > 0; --c, --namelength) {
		if (*c != '/') {
			foundchars = 1;
		} else if (foundchars) {
			return (c + 1);
		};
	};
	
	return mp->mnt_stat.f_mntonname;
}



void PackObjectName(struct vnode *vp,
					char *name,
					size_t namelen,
					void **attrbufptrptr,
					void **varbufptrptr) {
	char *mpname;
	size_t mpnamelen;
	u_long attrlength;
	
	/* The name of an object may be incorrect for the root of a mounted filesystem
	   because it may be mounted on a different directory name than the name of the
	   volume (such as "blah-1".  For the root directory, it's best to return the
	   last element of the location where the volume's mounted:
	 */
	if ((vp->v_flag & VROOT) && (mpname = FindMountpointName(vp->v_mount))) {
		mpnamelen = strlen(mpname);
		
		/* Trim off any trailing slashes: */
		while ((mpnamelen > 0) && (mpname[mpnamelen-1] == '/')) {
			--mpnamelen;
		};
		
		/* If there's anything left, use it instead of the volume's name */
		if (mpnamelen > 0) {
			name = mpname;
			namelen = mpnamelen;
		};
	};
	
	attrlength = namelen + 1;
    ((struct attrreference *)(*attrbufptrptr))->attr_dataoffset = (char *)(*varbufptrptr) - (char *)(*attrbufptrptr);
    ((struct attrreference *)(*attrbufptrptr))->attr_length = attrlength;
    (void) strncpy((unsigned char *)(*varbufptrptr), name, attrlength);

    /* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
    (char *)(*varbufptrptr) += attrlength + ((4 - (attrlength & 3)) & 3);
    ++((struct attrreference *)(*attrbufptrptr));
}



void PackVolCommonAttributes(struct attrlist *alist,
							 struct vnode *root_vp,
			   				 struct hfsCatalogInfo *root_catInfo,
							 void **attrbufptrptr,
							 void **varbufptrptr) {
    void *attrbufptr;
    void *varbufptr;
    attrgroup_t a;
    struct hfsnode *root_hp = VTOH(root_vp);
    struct mount *mp = VTOVFS(root_vp);
    struct hfsmount *hfsmp = VTOHFS(root_vp);
    ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	u_long attrlength;
	
	attrbufptr = *attrbufptrptr;
	varbufptr = *varbufptrptr;

    if ((a = alist->commonattr) != 0) {
        if (a & ATTR_CMN_NAME) {
        	PackObjectName(root_vp, H_NAME(root_hp), root_hp->h_meta->h_namelen, &attrbufptr, &varbufptr);
        };
		if (a & ATTR_CMN_DEVID) *((dev_t *)attrbufptr)++ = hfsmp->hfs_raw_dev;
		if (a & ATTR_CMN_FSID) {
			*((fsid_t *)attrbufptr) = mp->mnt_stat.f_fsid;
			++((fsid_t *)attrbufptr);
		};
		if (a & ATTR_CMN_OBJTYPE) *((fsobj_type_t *)attrbufptr)++ = 0;
		if (a & ATTR_CMN_OBJTAG) *((fsobj_tag_t *)attrbufptr)++ = VT_HFS;
		if (a & ATTR_CMN_OBJID)	{
			((fsobj_id_t *)attrbufptr)->fid_objno = 0;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
        if (a & ATTR_CMN_OBJPERMANENTID) {
            ((fsobj_id_t *)attrbufptr)->fid_objno = 0;
            ((fsobj_id_t *)attrbufptr)->fid_generation = 0;
            ++((fsobj_id_t *)attrbufptr);
        };
		if (a & ATTR_CMN_PAROBJID) {
            ((fsobj_id_t *)attrbufptr)->fid_objno = 0;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
		VCB_LOCK(vcb);
        if (a & ATTR_CMN_SCRIPT) *((text_encoding_t *)attrbufptr)++ = vcb->volumeNameEncodingHint;
		/* NOTE: all VCB dates are in Mac OS time */
		if (a & ATTR_CMN_CRTIME) {
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(vcb->vcbCrDate);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_MODTIME) {
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(vcb->vcbLsMod);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_CHGTIME) {
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(vcb->vcbLsMod);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_ACCTIME) {
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(vcb->vcbLsMod);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_BKUPTIME) {
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(vcb->vcbVolBkUp);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_FNDRINFO) {
            bcopy (&vcb->vcbFndrInfo, attrbufptr, sizeof(vcb->vcbFndrInfo));
            (char *)attrbufptr += sizeof(vcb->vcbFndrInfo);
		};
		VCB_UNLOCK(vcb);
		if (a & ATTR_CMN_OWNERID) {
			if (mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
				*((uid_t *)attrbufptr)++ =
					(VTOHFS(root_vp)->hfs_uid == UNKNOWNUID) ? console_user : VTOHFS(root_vp)->hfs_uid;
			} else {
				*((uid_t *)attrbufptr)++ =
					(root_hp->h_meta->h_uid == UNKNOWNUID) ? console_user : root_hp->h_meta->h_uid;
			};
		};
		if (a & ATTR_CMN_GRPID) {
			if (mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
				*((gid_t *)attrbufptr)++ = VTOHFS(root_vp)->hfs_gid;
			} else {
				*((gid_t *)attrbufptr)++ = root_hp->h_meta->h_gid;
			};
		};
		if (a & ATTR_CMN_ACCESSMASK) *((u_long *)attrbufptr)++ = (u_long)root_hp->h_meta->h_mode;
		if (a & ATTR_CMN_NAMEDATTRCOUNT) *((u_long *)attrbufptr)++ = 0;			/* XXX PPD TBC */
		if (a & ATTR_CMN_NAMEDATTRLIST) {
			attrlength = 0;
            ((struct attrreference *)attrbufptr)->attr_dataoffset = 0;
            ((struct attrreference *)attrbufptr)->attr_length = attrlength;
			
			/* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
            (char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
            ++((struct attrreference *)attrbufptr);
		};
		if (a & ATTR_CMN_FLAGS) *((u_long *)attrbufptr)++ = root_hp->h_meta->h_pflags;
		if (a & ATTR_CMN_USERACCESS) {
			if (mp->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
				*((u_long *)attrbufptr)++ =
					DerivePermissionSummary((VTOHFS(root_vp)->hfs_uid == UNKNOWNUID) ? console_user : VTOHFS(root_vp)->hfs_uid,
											VTOHFS(root_vp)->hfs_gid,
											root_hp->h_meta->h_mode,
											VTOVFS(root_vp),
											current_proc()->p_ucred,
											current_proc());
			} else {
				*((u_long *)attrbufptr)++ =
					DerivePermissionSummary((root_hp->h_meta->h_uid == UNKNOWNUID) ? console_user : root_hp->h_meta->h_uid,
											root_hp->h_meta->h_gid,
											root_hp->h_meta->h_mode,
											VTOVFS(root_vp),
											current_proc()->p_ucred,
											current_proc());
			};
		};
	};
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}



void PackVolAttributeBlock(struct attrlist *alist,
						   struct vnode *root_vp,
			   			   struct hfsCatalogInfo *root_catInfo,
						   void **attrbufptrptr,
						   void **varbufptrptr) {
    void *attrbufptr;
    void *varbufptr;
    attrgroup_t a;
    struct mount *mp = VTOVFS(root_vp);
    struct hfsmount *hfsmp = VTOHFS(root_vp);
    ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	u_long attrlength;
	
	attrbufptr = *attrbufptrptr;
	varbufptr = *varbufptrptr;
	
	if ((a = alist->volattr) != 0) {
		VCB_LOCK(vcb);
		if (a & ATTR_VOL_FSTYPE) *((u_long *)attrbufptr)++ = (u_long)mp->mnt_vfc->vfc_typenum;
		if (a & ATTR_VOL_SIGNATURE) *((u_long *)attrbufptr)++ = (u_long)vcb->vcbSigWord;
        if (a & ATTR_VOL_SIZE) *((off_t *)attrbufptr)++ = (off_t)vcb->totalBlocks * (off_t)vcb->blockSize;
        if (a & ATTR_VOL_SPACEFREE) *((off_t *)attrbufptr)++ = (off_t)vcb->freeBlocks * (off_t)vcb->blockSize;
        if (a & ATTR_VOL_SPACEAVAIL) *((off_t *)attrbufptr)++ = (off_t)vcb->freeBlocks * (off_t)vcb->blockSize;
        if (a & ATTR_VOL_MINALLOCATION) *((off_t *)attrbufptr)++ = (off_t)vcb->blockSize;
        if (a & ATTR_VOL_ALLOCATIONCLUMP) *((off_t *)attrbufptr)++ = (off_t)(vcb->vcbClpSiz);
        if (a & ATTR_VOL_IOBLOCKSIZE) *((u_long *)attrbufptr)++ = (u_long)hfsmp->hfs_logBlockSize;
		if (a & ATTR_VOL_OBJCOUNT) *((u_long *)attrbufptr)++ = (u_long)vcb->vcbFilCnt + (u_long)vcb->vcbDirCnt;
		if (a & ATTR_VOL_FILECOUNT) *((u_long *)attrbufptr)++ = (u_long)vcb->vcbFilCnt;
		if (a & ATTR_VOL_DIRCOUNT) *((u_long *)attrbufptr)++ = (u_long)vcb->vcbDirCnt;
		if (a & ATTR_VOL_MAXOBJCOUNT) *((u_long *)attrbufptr)++ = 0xFFFFFFFF;
		if (a & ATTR_VOL_MOUNTPOINT) {
            ((struct attrreference *)attrbufptr)->attr_dataoffset = (char *)varbufptr - (char *)attrbufptr;
            ((struct attrreference *)attrbufptr)->attr_length = strlen(mp->mnt_stat.f_mntonname) + 1;
			attrlength = ((struct attrreference *)attrbufptr)->attr_length;
			attrlength = attrlength + ((4 - (attrlength & 3)) & 3);		/* round up to the next 4-byte boundary: */
			(void) bcopy(mp->mnt_stat.f_mntonname, varbufptr, attrlength);
			
			/* Advance beyond the space just allocated: */
            (char *)varbufptr += attrlength;
            ++((struct attrreference *)attrbufptr);
		};
        if (a & ATTR_VOL_NAME) {
            ((struct attrreference *)attrbufptr)->attr_dataoffset = (char *)varbufptr - (char *)attrbufptr;
            ((struct attrreference *)attrbufptr)->attr_length = VTOH(root_vp)->h_meta->h_namelen + 1;
			attrlength = ((struct attrreference *)attrbufptr)->attr_length;
			attrlength = attrlength + ((4 - (attrlength & 3)) & 3);		/* round up to the next 4-byte boundary: */
            bcopy(H_NAME(VTOH(root_vp)), varbufptr, attrlength);

			/* Advance beyond the space just allocated: */
            (char *)varbufptr += attrlength;
            ++((struct attrreference *)attrbufptr);
        };
        if (a & ATTR_VOL_MOUNTFLAGS) *((u_long *)attrbufptr)++ = (u_long)mp->mnt_flag;
        if (a & ATTR_VOL_MOUNTEDDEVICE) {
            ((struct attrreference *)attrbufptr)->attr_dataoffset = (char *)varbufptr - (char *)attrbufptr;
            ((struct attrreference *)attrbufptr)->attr_length = strlen(mp->mnt_stat.f_mntfromname) + 1;
			attrlength = ((struct attrreference *)attrbufptr)->attr_length;
			attrlength = attrlength + ((4 - (attrlength & 3)) & 3);		/* round up to the next 4-byte boundary: */
			(void) bcopy(mp->mnt_stat.f_mntfromname, varbufptr, attrlength);
			
			/* Advance beyond the space just allocated: */
            (char *)varbufptr += attrlength;
            ++((struct attrreference *)attrbufptr);
        };
        if (a & ATTR_VOL_ENCODINGSUSED) *((unsigned long long *)attrbufptr)++ = (unsigned long long)vcb->encodingsBitmap;
        if (a & ATTR_VOL_CAPABILITIES) {
        	if (vcb->vcbSigWord == kHFSPlusSigWord) {
        	    ((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_FORMAT] =
        	    VOL_CAP_FMT_PERSISTENTOBJECTIDS | VOL_CAP_FMT_SYMBOLICLINKS | VOL_CAP_FMT_HARDLINKS;
        	} else { /* Plain HFS */
        	    ((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_FORMAT] =
        	    VOL_CAP_FMT_PERSISTENTOBJECTIDS;
        	}
        	((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_INTERFACES] =
        			VOL_CAP_INT_SEARCHFS | VOL_CAP_INT_ATTRLIST | VOL_CAP_INT_NFSEXPORT | VOL_CAP_INT_READDIRATTR;
        	((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
        	((vol_capabilities_attr_t *)attrbufptr)->capabilities[VOL_CAPABILITIES_RESERVED2] = 0;

        	((vol_capabilities_attr_t *)attrbufptr)->valid[VOL_CAPABILITIES_FORMAT] =
        			VOL_CAP_FMT_PERSISTENTOBJECTIDS | VOL_CAP_FMT_SYMBOLICLINKS | VOL_CAP_FMT_HARDLINKS;
        	((vol_capabilities_attr_t *)attrbufptr)->valid[VOL_CAPABILITIES_INTERFACES] =
        			VOL_CAP_INT_SEARCHFS | VOL_CAP_INT_ATTRLIST | VOL_CAP_INT_NFSEXPORT | VOL_CAP_INT_READDIRATTR;
        	((vol_capabilities_attr_t *)attrbufptr)->valid[VOL_CAPABILITIES_RESERVED1] = 0;
        	((vol_capabilities_attr_t *)attrbufptr)->valid[VOL_CAPABILITIES_RESERVED2] = 0;

            ++((vol_capabilities_attr_t *)attrbufptr);
        };
        if (a & ATTR_VOL_ATTRIBUTES) {
        	((vol_attributes_attr_t *)attrbufptr)->validattr.commonattr = ATTR_CMN_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->validattr.volattr = ATTR_VOL_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->validattr.dirattr = ATTR_DIR_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->validattr.fileattr = ATTR_FILE_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->validattr.forkattr = ATTR_FORK_VALIDMASK;

        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.commonattr = ATTR_CMN_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.volattr = ATTR_VOL_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.dirattr = ATTR_DIR_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.fileattr = ATTR_FILE_VALIDMASK;
        	((vol_attributes_attr_t *)attrbufptr)->nativeattr.forkattr = ATTR_FORK_VALIDMASK;

            ++((vol_attributes_attr_t *)attrbufptr);
        };
		VCB_UNLOCK(vcb);
	};
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}




void PackVolumeInfo(struct attrlist *alist,
                    struct vnode *root_vp,
                    struct hfsCatalogInfo *root_catinfo,
                    void **attrbufptrptr,
                    void **varbufptrptr) {

    PackVolCommonAttributes(alist, root_vp, root_catinfo, attrbufptrptr, varbufptrptr);
    PackVolAttributeBlock(alist, root_vp, root_catinfo, attrbufptrptr, varbufptrptr);
};

// Pack the common attribute contents of an objects hfsCatalogInfo
void PackCommonCatalogInfoAttributeBlock(struct attrlist		*alist,
							 			struct vnode			*root_vp,
										struct hfsCatalogInfo	*catalogInfo,
										void					**attrbufptrptr,
										void					**varbufptrptr )
{
	struct hfsnode	*hp;
	void			*attrbufptr;
	void			*varbufptr;
	attrgroup_t		a;
	u_long			attrlength;
	Boolean			isHFSPlus;
	
	hp			= VTOH(root_vp);
	attrbufptr	= *attrbufptrptr;
	varbufptr	= *varbufptrptr;
	isHFSPlus = (VTOVCB(root_vp)->vcbSigWord == kHFSPlusSigWord);
	
	if ((a = alist->commonattr) != 0)
	{
		if (a & ATTR_CMN_NAME)										
            {
            attrlength = strlen(catalogInfo->nodeData.cnm_nameptr) + 1;
            ((struct attrreference *)attrbufptr)->attr_dataoffset = (char *)varbufptr - (char *)attrbufptr;
            ((struct attrreference *)attrbufptr)->attr_length = attrlength;
            (void) strncpy((unsigned char *)varbufptr,
                           catalogInfo->nodeData.cnm_nameptr, attrlength);
 
            /* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
            (char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
            ++((struct attrreference *)attrbufptr);
            };
		if (a & ATTR_CMN_DEVID) *((dev_t *)attrbufptr)++			= H_DEV(hp);
		if (a & ATTR_CMN_FSID) {
			*((fsid_t *)attrbufptr) = VTOVFS(root_vp)->mnt_stat.f_fsid;
			++((fsid_t *)attrbufptr);
		};
		if (a & ATTR_CMN_OBJTYPE)
		{
			switch (catalogInfo->nodeData.cnd_type) {
			  case kCatalogFolderNode:
				*((fsobj_type_t *)attrbufptr)++	= VDIR;
				break;

			  case kCatalogFileNode:
			  	/* Files in an HFS+ catalog can represent many things (regular files, symlinks, block/character devices, ...) */
    			if ((HTOVCB(hp)->vcbSigWord == kHFSPlusSigWord) &&
    				(catalogInfo->nodeData.cnd_mode & IFMT)) {
					*((fsobj_type_t *)attrbufptr)++	=
					    IFTOVT((mode_t)catalogInfo->nodeData.cnd_mode);
				} else {
					*((fsobj_type_t *)attrbufptr)++	= VREG;
				};
				break;
				
			  default:
			  	*((fsobj_type_t *)attrbufptr)++	= VNON;
			  	break;
			};
		}
		if (a & ATTR_CMN_OBJTAG) *((fsobj_tag_t *)attrbufptr)++ = root_vp->v_tag;
        if (a & ATTR_CMN_OBJID) {
            u_int32_t cnid;
 
            /* For hard links use the link's cnid */
            if (catalogInfo->nodeData.cnd_iNodeNumCopy != 0)
			  	cnid = catalogInfo->nodeData.cnd_linkCNID;
            else
			  	cnid = catalogInfo->nodeData.cnd_nodeID;
            ((fsobj_id_t *)attrbufptr)->fid_objno = cnid;
            ((fsobj_id_t *)attrbufptr)->fid_generation = 0;
            ++((fsobj_id_t *)attrbufptr);
        };
        if (a & ATTR_CMN_OBJPERMANENTID) {
            u_int32_t cnid;
 
            /* For hard links use the link's cnid */
            if (catalogInfo->nodeData.cnd_iNodeNumCopy != 0)
			  	cnid = catalogInfo->nodeData.cnd_linkCNID;
			else
			  	cnid = catalogInfo->nodeData.cnd_nodeID;
            ((fsobj_id_t *)attrbufptr)->fid_objno = cnid;
            ((fsobj_id_t *)attrbufptr)->fid_generation = 0;
            ++((fsobj_id_t *)attrbufptr);
        };
		if (a & ATTR_CMN_PAROBJID)
		{
            ((fsobj_id_t *)attrbufptr)->fid_objno = catalogInfo->nodeData.cnm_parID;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
        if (a & ATTR_CMN_SCRIPT)
	  {
	    if (HTOVCB(hp)->vcbSigWord == kHFSPlusSigWord) {
			*((text_encoding_t *)attrbufptr)++ = catalogInfo->nodeData.cnd_textEncoding;
	    } else {
			*((text_encoding_t *)attrbufptr)++ = VTOHFS(root_vp)->hfs_encoding;
	    }
	  };
		if (a & ATTR_CMN_CRTIME)
		{
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(catalogInfo->nodeData.cnd_createDate);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_MODTIME)
		{
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(catalogInfo->nodeData.cnd_contentModDate);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_CHGTIME)
		{
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(catalogInfo->nodeData.cnd_attributeModDate);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_ACCTIME)
		{
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(catalogInfo->nodeData.cnd_accessDate);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_BKUPTIME)
		{
			((struct timespec *)attrbufptr)->tv_sec = to_bsd_time(catalogInfo->nodeData.cnd_backupDate);
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_FNDRINFO)
		{
			bcopy (&catalogInfo->nodeData.cnd_finderInfo, attrbufptr, sizeof(catalogInfo->nodeData.cnd_finderInfo));
			(char *)attrbufptr += sizeof(catalogInfo->nodeData.cnd_finderInfo);
		};
		if (a & ATTR_CMN_OWNERID) {
			if ((VTOVFS(root_vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) ||
				((catalogInfo->nodeData.cnd_mode & IFMT) == 0)) {
				*((uid_t *)attrbufptr)++ =
					(VTOHFS(root_vp)->hfs_uid == UNKNOWNUID) ? console_user : VTOHFS(root_vp)->hfs_uid;
			} else {
				*((uid_t *)attrbufptr)++ =
					(catalogInfo->nodeData.cnd_ownerID == UNKNOWNUID) ? console_user : catalogInfo->nodeData.cnd_ownerID;
			};
		}
		if (a & ATTR_CMN_GRPID) {
			if ((VTOVFS(root_vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) ||
				((catalogInfo->nodeData.cnd_mode & IFMT) == 0)) {
				*((gid_t *)attrbufptr)++ = VTOHFS(root_vp)->hfs_gid;
			} else {
				*((gid_t *)attrbufptr)++ = catalogInfo->nodeData.cnd_groupID;
			};
		}
		if (a & ATTR_CMN_ACCESSMASK) {
			if (((catalogInfo->nodeData.cnd_mode & IFMT) == 0)
#if OVERRIDE_UNKNOWN_PERMISSIONS
				|| (VTOVFS(root_vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS)
#endif
				) {
				switch (catalogInfo->nodeData.cnd_type) {
				  case kCatalogFileNode:
				  	/* Files in an HFS+ catalog can represent many things (regular files, symlinks, block/character devices, ...) */
					*((u_long *)attrbufptr)++ = (u_long)(IFREG | (ACCESSPERMS & (u_long)(VTOHFS(root_vp)->hfs_file_mask)));
					break;
					
				  case kCatalogFolderNode:
					*((u_long *)attrbufptr)++ = (u_long)(IFDIR | (ACCESSPERMS & (u_long)(VTOHFS(root_vp)->hfs_dir_mask)));
					break;
				  
				  default:
					*((u_long *)attrbufptr)++ = (u_long)((catalogInfo->nodeData.cnd_mode & IFMT) |
														 VTOHFS(root_vp)->hfs_dir_mask);
				};
			} else {
				*((u_long *)attrbufptr)++ =
				    (u_long)catalogInfo->nodeData.cnd_mode;
			};
		}
		if (a & ATTR_CMN_NAMEDATTRCOUNT) *((u_long *)attrbufptr)++ = 0;			/* XXX PPD TBC */
		if (a & ATTR_CMN_NAMEDATTRLIST)
		{
			attrlength = 0;
			((struct attrreference *)attrbufptr)->attr_dataoffset	= 0;
			((struct attrreference *)attrbufptr)->attr_length		= attrlength;
			
			/* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
			(char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
			++((struct attrreference *)attrbufptr);
		};
		if (a & ATTR_CMN_FLAGS) {
			u_long flags;

			if (catalogInfo->nodeData.cnd_mode & IFMT)
				flags = catalogInfo->nodeData.cnd_ownerFlags |
				        catalogInfo->nodeData.cnd_adminFlags << 16;
			else
				flags = 0;

			if (catalogInfo->nodeData.cnd_type == kCatalogFileNode) {
				if (catalogInfo->nodeData.cnd_flags & kHFSFileLockedMask)
					flags |= UF_IMMUTABLE;
				else
					flags &= ~UF_IMMUTABLE;
			};
			*((u_long *)attrbufptr)++ = flags;
		};
		if (a & ATTR_CMN_USERACCESS) {
			if ((VTOVFS(root_vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) ||
				((catalogInfo->nodeData.cnd_mode & IFMT) == 0)) {
				*((u_long *)attrbufptr)++ =
					DerivePermissionSummary((VTOHFS(root_vp)->hfs_uid == UNKNOWNUID) ? console_user : VTOHFS(root_vp)->hfs_uid,
											VTOHFS(root_vp)->hfs_gid,
#if OVERRIDE_UNKNOWN_PERMISSIONS
											(catalogInfo->nodeData.cnd_type == kCatalogFileNode) ? VTOHFS(root_vp)->hfs_file_mask : VTOHFS(root_vp)->hfs_dir_mask,
#else
											(catalogInfo->nodeData.cnd_mode & IFMT) ?
												(u_long)catalogInfo->nodeData.cnd_mode :
												((catalogInfo->nodeData.cnd_type == kCatalogFileNode) ?
													VTOHFS(root_vp)->hfs_file_mask :
													VTOHFS(root_vp)->hfs_dir_mask),
#endif
											VTOVFS(root_vp),
											current_proc()->p_ucred,
											current_proc());
			} else {
				*((u_long *)attrbufptr)++ =
					DerivePermissionSummary((catalogInfo->nodeData.cnd_ownerID == UNKNOWNUID) ? console_user : catalogInfo->nodeData.cnd_ownerID,
											catalogInfo->nodeData.cnd_groupID,
											(mode_t)catalogInfo->nodeData.cnd_mode,
											VTOVFS(root_vp),
											current_proc()->p_ucred,
											current_proc());
			};
		};
	};
	
	*attrbufptrptr	= attrbufptr;
	*varbufptrptr	= varbufptr;
}


void PackCommonAttributeBlock(struct attrlist *alist,
							  struct vnode *vp,
							  struct hfsCatalogInfo *catInfo,
							  void **attrbufptrptr,
							  void **varbufptrptr) {
	struct hfsnode *hp;
    void *attrbufptr;
    void *varbufptr;
    attrgroup_t a;
	u_long attrlength;
	
	hp = VTOH(vp);
	
	attrbufptr = *attrbufptrptr;
	varbufptr = *varbufptrptr;
	
    if ((a = alist->commonattr) != 0) {
        if (a & ATTR_CMN_NAME) {
			PackObjectName(vp, H_NAME(hp), hp->h_meta->h_namelen, &attrbufptr, &varbufptr);
        };
		if (a & ATTR_CMN_DEVID) *((dev_t *)attrbufptr)++ = H_DEV(hp);
		if (a & ATTR_CMN_FSID) {
			*((fsid_t *)attrbufptr) = VTOVFS(vp)->mnt_stat.f_fsid;
			++((fsid_t *)attrbufptr);
		};
		if (a & ATTR_CMN_OBJTYPE) *((fsobj_type_t *)attrbufptr)++ = vp->v_type;
		if (a & ATTR_CMN_OBJTAG) *((fsobj_tag_t *)attrbufptr)++ = vp->v_tag;
        if (a & ATTR_CMN_OBJID)	{
            u_int32_t cnid;

            /* For hard links use the link's cnid */
            if (hp->h_meta->h_metaflags & IN_DATANODE)
                cnid = catInfo->nodeData.cnd_linkCNID;
            else
                cnid = H_FILEID(hp);
            ((fsobj_id_t *)attrbufptr)->fid_objno = cnid;
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
        if (a & ATTR_CMN_OBJPERMANENTID)	{
            u_int32_t cnid;

            /* For hard links use the link's cnid */
            if (hp->h_meta->h_metaflags & IN_DATANODE)
                cnid = catInfo->nodeData.cnd_linkCNID;
            else
                cnid = H_FILEID(hp);
            ((fsobj_id_t *)attrbufptr)->fid_objno = cnid;
            ((fsobj_id_t *)attrbufptr)->fid_generation = 0;
            ++((fsobj_id_t *)attrbufptr);
        };
		if (a & ATTR_CMN_PAROBJID) {
            ((fsobj_id_t *)attrbufptr)->fid_objno = H_DIRID(hp);
			((fsobj_id_t *)attrbufptr)->fid_generation = 0;
			++((fsobj_id_t *)attrbufptr);
		};
        if (a & ATTR_CMN_SCRIPT)
	  {
	    if (HTOVCB(hp)->vcbSigWord == kHFSPlusSigWord) {
			*((text_encoding_t *)attrbufptr)++ = catInfo->nodeData.cnd_textEncoding;
	    } else {
			*((text_encoding_t *)attrbufptr)++ = VTOHFS(vp)->hfs_encoding;
	    }
	  };
		if (a & ATTR_CMN_CRTIME) {
			((struct timespec *)attrbufptr)->tv_sec = hp->h_meta->h_crtime;
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_MODTIME) {
			((struct timespec *)attrbufptr)->tv_sec = hp->h_meta->h_mtime;
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_CHGTIME) {
			((struct timespec *)attrbufptr)->tv_sec = hp->h_meta->h_ctime;
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_ACCTIME) {
			((struct timespec *)attrbufptr)->tv_sec = hp->h_meta->h_atime;
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_BKUPTIME) {
			((struct timespec *)attrbufptr)->tv_sec = hp->h_meta->h_butime;
			((struct timespec *)attrbufptr)->tv_nsec = 0;
			++((struct timespec *)attrbufptr);
		};
		if (a & ATTR_CMN_FNDRINFO) {
			bcopy (&catInfo->nodeData.cnd_finderInfo, attrbufptr, sizeof(catInfo->nodeData.cnd_finderInfo));
			(char *)attrbufptr += sizeof(catInfo->nodeData.cnd_finderInfo);
		};
		if (a & ATTR_CMN_OWNERID) {
			if (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
				*((uid_t *)attrbufptr)++ =
					(VTOHFS(vp)->hfs_uid == UNKNOWNUID) ? console_user : VTOHFS(vp)->hfs_uid;
			} else {
				*((uid_t *)attrbufptr)++ =
					(hp->h_meta->h_uid == UNKNOWNUID) ? console_user : hp->h_meta->h_uid;
			}
		};
		if (a & ATTR_CMN_GRPID) {
			if (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
				*((gid_t *)attrbufptr)++ = VTOHFS(vp)->hfs_gid;
			} else {
				*((gid_t *)attrbufptr)++ = hp->h_meta->h_gid;
			};
		};
		if (a & ATTR_CMN_ACCESSMASK) *((u_long *)attrbufptr)++ = (u_long)hp->h_meta->h_mode;
		if (a & ATTR_CMN_NAMEDATTRCOUNT) *((u_long *)attrbufptr)++ = 0;			/* XXX PPD TBC */
		if (a & ATTR_CMN_NAMEDATTRLIST) {
			attrlength = 0;
            ((struct attrreference *)attrbufptr)->attr_dataoffset = 0;
            ((struct attrreference *)attrbufptr)->attr_length = attrlength;
			
			/* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
            (char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
            ++((struct attrreference *)attrbufptr);
		};
		if (a & ATTR_CMN_FLAGS) *((u_long *)attrbufptr)++ = hp->h_meta->h_pflags;
		if (a & ATTR_CMN_USERACCESS) {
			if (VTOVFS(vp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
				*((u_long *)attrbufptr)++ =
					DerivePermissionSummary((VTOHFS(vp)->hfs_uid == UNKNOWNUID) ? console_user : VTOHFS(vp)->hfs_uid,
											VTOHFS(vp)->hfs_gid,
											hp->h_meta->h_mode,
											VTOVFS(vp),
											current_proc()->p_ucred,
											current_proc());
			} else {
				*((u_long *)attrbufptr)++ =
					DerivePermissionSummary((hp->h_meta->h_uid == UNKNOWNUID) ? console_user : hp->h_meta->h_uid,
											hp->h_meta->h_gid,
											hp->h_meta->h_mode,
											VTOVFS(vp),
											current_proc()->p_ucred,
											current_proc());
			};
		};
	};
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}


//	Pack the directory attributes given hfsCatalogInfo
void PackCatalogInfoDirAttributeBlock( struct attrlist *alist, struct vnode *vp, 
	struct hfsCatalogInfo *catInfo, void **attrbufptrptr, void **varbufptrptr )
{
	void		*attrbufptr;
	attrgroup_t	a;
	u_long valence;
	
	attrbufptr	= *attrbufptrptr;
	a			= alist->dirattr;
	
	if ( (catInfo->nodeData.cnd_type == kCatalogFolderNode) && (a != 0) ) {
		valence = catInfo->nodeData.cnd_valence;
		if ((catInfo->nodeData.cnm_parID == kRootParID) &&
		    (VTOHFS(vp)->hfs_private_metadata_dir != 0)) {
			--valence;	/* hide private dir */
		}
		/* The 'link count' is faked */
		if (a & ATTR_DIR_LINKCOUNT)
			*((u_long *)attrbufptr)++ = 2 + valence;
		if (a & ATTR_DIR_ENTRYCOUNT)
			*((u_long *)attrbufptr)++ = valence;
		if (a & ATTR_DIR_MOUNTSTATUS)
			*((u_long *)attrbufptr)++ = 0;
	};
	
	*attrbufptrptr = attrbufptr;
}


void PackDirAttributeBlock(struct attrlist *alist,
						   struct vnode *vp,
						   struct hfsCatalogInfo *catInfo,
						   void **attrbufptrptr,
						   void **varbufptrptr) {
	void *attrbufptr;
	attrgroup_t a;
	u_long valence;
	
	attrbufptr = *attrbufptrptr;
	
	a = alist->dirattr;
	if ((vp->v_type == VDIR) && (a != 0)) {
		valence = catInfo->nodeData.cnd_valence;
		if ((catInfo->nodeData.cnm_parID == kRootParID) &&
		    (VTOHFS(vp)->hfs_private_metadata_dir != 0)) {
				--valence;	/* hide private dir */
		}

		/* The 'link count' is faked */
		if (a & ATTR_DIR_LINKCOUNT)
			*((u_long *)attrbufptr)++ = 2 + valence;
		if (a & ATTR_DIR_ENTRYCOUNT) 
			*((u_long *)attrbufptr)++ = valence;
		if (a & ATTR_DIR_MOUNTSTATUS) {
			if (vp->v_mountedhere) {
				*((u_long *)attrbufptr)++ = DIR_MNTSTATUS_MNTPOINT;
			} else {
				*((u_long *)attrbufptr)++ = 0;
			};
		};
	};
	
	*attrbufptrptr = attrbufptr;
}



//	Pack the file attributes from the hfsCatalogInfo for the file.
void PackCatalogInfoFileAttributeBlock( struct attrlist *alist, struct vnode *root_vp, struct hfsCatalogInfo *catInfo, void **attrbufptrptr, void **varbufptrptr )
{
	void			*attrbufptr;
	void			*varbufptr;
	attrgroup_t		a;
	u_long			attrlength;
	ExtendedVCB		*vcb			= VTOVCB(root_vp);
	
	attrbufptr	= *attrbufptrptr;
	varbufptr	= *varbufptrptr;
	
	a = alist->fileattr;
	if ( (catInfo->nodeData.cnd_type == kCatalogFileNode) && (a != 0) )
	{
#if HFS_HARDLINKS
		if (a & ATTR_FILE_LINKCOUNT) {
			u_long linkcnt = catInfo->nodeData.cnd_linkCount;

			if (linkcnt < 1)
				linkcnt = 1;
			*((u_long *)attrbufptr)++ = linkcnt;
		}
#else
		if (a & ATTR_FILE_LINKCOUNT) *((u_long *)attrbufptr)++ = 1;
#endif
		if (a & ATTR_FILE_TOTALSIZE) {
			*((off_t *)attrbufptr)++ =
			    (off_t)catInfo->nodeData.cnd_datafork.logicalSize +
			    (off_t)catInfo->nodeData.cnd_rsrcfork.logicalSize;
		}
		if (a & ATTR_FILE_ALLOCSIZE) {
			*((off_t *)attrbufptr)++ =
			    (off_t)((off_t)catInfo->nodeData.cnd_datafork.totalBlocks * (off_t)vcb->blockSize) +
			    (off_t)((off_t)catInfo->nodeData.cnd_rsrcfork.totalBlocks * (off_t)vcb->blockSize);
		}
		if (a & ATTR_FILE_IOBLOCKSIZE) {
			*((u_long *)attrbufptr)++ = (u_long)(VTOHFS(root_vp)->hfs_logBlockSize);
		}
		if (a & ATTR_FILE_CLUMPSIZE) {
			*((u_long *)attrbufptr)++ = vcb->vcbClpSiz;
		}
		if (a & ATTR_FILE_DEVTYPE) {
			u_long rawdev;
			u_short filetype;

			filetype = (catInfo->nodeData.cnd_mode & IFMT);
			if (filetype == IFCHR || filetype == IFBLK)
				rawdev = (u_long)catInfo->nodeData.cnd_rawDevice;
			else
				rawdev = 0;
			
			*((u_long *)attrbufptr)++ = rawdev;
		}
		if (a & ATTR_FILE_FILETYPE) {
			*((u_long *)attrbufptr)++ = 0;	/* XXX PPD */
		}
		if (a & ATTR_FILE_FORKCOUNT) {
			*((u_long *)attrbufptr)++ = 2;	/* XXX PPD */
		}
		if (a & ATTR_FILE_FORKLIST) {
			attrlength = 0;
			((struct attrreference *)attrbufptr)->attr_dataoffset = 0;
			((struct attrreference *)attrbufptr)->attr_length = attrlength;
			
			/* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
			(char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
			++((struct attrreference *)attrbufptr);
		};
		if (a & ATTR_FILE_DATALENGTH) {
			*((off_t *)attrbufptr)++ =
			    (off_t)catInfo->nodeData.cnd_datafork.logicalSize;
		}
		if (a & ATTR_FILE_DATAALLOCSIZE) {
			*((off_t *)attrbufptr)++ =
			    (off_t)((off_t)catInfo->nodeData.cnd_datafork.totalBlocks * (off_t)vcb->blockSize);
		}
		if (a & ATTR_FILE_DATAEXTENTS) {
			bcopy(&catInfo->nodeData.cnd_datafork.extents, attrbufptr, sizeof(extentrecord));
			(char *)attrbufptr += sizeof(extentrecord) + ((4 - (sizeof(extentrecord) & 3)) & 3);
		};
		if (a & ATTR_FILE_RSRCLENGTH) {
			*((off_t *)attrbufptr)++ =
			    (off_t)catInfo->nodeData.cnd_rsrcfork.logicalSize;
		}
		if (a & ATTR_FILE_RSRCALLOCSIZE) {
			*((off_t *)attrbufptr)++ =
			    (off_t)((off_t)catInfo->nodeData.cnd_rsrcfork.totalBlocks * (off_t)vcb->blockSize);
		}
		if (a & ATTR_FILE_RSRCEXTENTS) {
			bcopy(&catInfo->nodeData.cnd_rsrcfork.extents, attrbufptr, sizeof(extentrecord));
			(char *)attrbufptr += sizeof(extentrecord) + ((4 - (sizeof(extentrecord) & 3)) & 3);
		};
	};
	
	*attrbufptrptr	= attrbufptr;
	*varbufptrptr	= varbufptr;
}


void PackFileAttributeBlock(struct attrlist *alist,
							struct vnode *vp,
							struct hfsCatalogInfo *catInfo,
							void **attrbufptrptr,
							void **varbufptrptr) {
    struct hfsnode *hp = VTOH(vp);
    FCB *fcb = HTOFCB(hp);
	ExtendedVCB *vcb = HTOVCB(hp);
    Boolean isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);
    void *attrbufptr = *attrbufptrptr;
    void *varbufptr = *varbufptrptr;
    attrgroup_t a = alist->fileattr;
	u_long attrlength;
	
	if (a != 0) {
#if HFS_HARDLINKS
		if (a & ATTR_FILE_LINKCOUNT) {
			u_long linkcnt = catInfo->nodeData.cnd_linkCount;
			
			if (linkcnt < 1)
				linkcnt = 1;
			*((u_long *)attrbufptr)++ = linkcnt;
		}
#else
		if (a & ATTR_FILE_LINKCOUNT) *((u_long *)attrbufptr)++ = 1;
#endif
		if (a & ATTR_FILE_TOTALSIZE) {
			*((off_t *)attrbufptr)++ =
			    (off_t)catInfo->nodeData.cnd_datafork.logicalSize +
			    (off_t)catInfo->nodeData.cnd_rsrcfork.logicalSize;
		}
		if (a & ATTR_FILE_ALLOCSIZE) {
			switch (H_FORKTYPE(hp)) {
			case kDataFork:
				*((off_t *)attrbufptr)++ =
				    (off_t)fcb->fcbPLen +
				    (off_t)((off_t)catInfo->nodeData.cnd_rsrcfork.totalBlocks * (off_t)vcb->blockSize);
				break;
			case kRsrcFork:
				*((off_t *)attrbufptr)++ =
				    (off_t)fcb->fcbPLen +
				    (off_t)((off_t)catInfo->nodeData.cnd_datafork.totalBlocks * (off_t)vcb->blockSize);
				break;
			default:
				*((off_t *)attrbufptr)++ =
				    (off_t)((off_t)catInfo->nodeData.cnd_datafork.totalBlocks * (off_t)vcb->blockSize) +
				    (off_t)((off_t)catInfo->nodeData.cnd_rsrcfork.totalBlocks * (off_t)vcb->blockSize);
		  };
		}; 
		if (a & ATTR_FILE_IOBLOCKSIZE) *((u_long *)attrbufptr)++ = GetLogicalBlockSize(vp);
		if (a & ATTR_FILE_CLUMPSIZE) *((u_long *)attrbufptr)++ = fcb->fcbClmpSize;
		if (a & ATTR_FILE_DEVTYPE) {
			u_long rawdev;
			
			if ((vp->v_type == VBLK) || (vp->v_type == VCHR))
				rawdev = (u_long)catInfo->nodeData.cnd_rawDevice;
			else
				rawdev = 0;
			*((u_long *)attrbufptr)++ = rawdev;
		}
		if (a & ATTR_FILE_FILETYPE) *((u_long *)attrbufptr)++ = 0;			/* XXX PPD */
		if (a & ATTR_FILE_FORKCOUNT) *((u_long *)attrbufptr)++ = 2;			/* XXX PPD */
		if (a & ATTR_FILE_FORKLIST) {
			attrlength = 0;
            ((struct attrreference *)attrbufptr)->attr_dataoffset = 0;
            ((struct attrreference *)attrbufptr)->attr_length = attrlength;
			
			/* Advance beyond the space just allocated and round up to the next 4-byte boundary: */
            (char *)varbufptr += attrlength + ((4 - (attrlength & 3)) & 3);
            ++((struct attrreference *)attrbufptr);
		};
		if (H_FORKTYPE(hp) == kDataFork) {
			if (a & ATTR_FILE_DATALENGTH)
			   *((off_t *)attrbufptr)++ = fcb->fcbEOF;
			if (a & ATTR_FILE_DATAALLOCSIZE) *((off_t *)attrbufptr)++ = fcb->fcbPLen;
			if (a & ATTR_FILE_DATAEXTENTS) {
			    bcopy ( fcb->fcbExtents, attrbufptr, sizeof(extentrecord));
				(char *)attrbufptr += sizeof(extentrecord) + ((4 - (sizeof(extentrecord) & 3)) & 3);
			};
		} else {
			if (a & ATTR_FILE_DATALENGTH) {
				*((off_t *)attrbufptr)++ =
				    (off_t)catInfo->nodeData.cnd_datafork.logicalSize;
			}
			if (a & ATTR_FILE_DATAALLOCSIZE) {
				*((off_t *)attrbufptr)++ =
				    (off_t)((off_t)catInfo->nodeData.cnd_datafork.totalBlocks * (off_t)vcb->blockSize);
			}
			if (a & ATTR_FILE_DATAEXTENTS) {
				bcopy(&catInfo->nodeData.cnd_datafork.extents, attrbufptr, sizeof(extentrecord));
				(char *)attrbufptr += sizeof(extentrecord) + ((4 - (sizeof(extentrecord) & 3)) & 3);
			};
		};
		if (H_FORKTYPE(hp) == kRsrcFork) {
			if (a & ATTR_FILE_RSRCLENGTH) 
			   *((off_t *)attrbufptr)++ = fcb->fcbEOF;
			if (a & ATTR_FILE_RSRCALLOCSIZE) *((off_t *)attrbufptr)++ = fcb->fcbPLen;
			if (a & ATTR_FILE_RSRCEXTENTS) {
			    bcopy ( fcb->fcbExtents, attrbufptr, sizeof(extentrecord));
				(char *)attrbufptr += sizeof(extentrecord) + ((4 - (sizeof(extentrecord) & 3)) & 3);
			};
		} else {
			if (a & ATTR_FILE_RSRCLENGTH) {
				*((off_t *)attrbufptr)++ =
				    (off_t)catInfo->nodeData.cnd_rsrcfork.logicalSize;
			}
			if (a & ATTR_FILE_RSRCALLOCSIZE) {
				*((off_t *)attrbufptr)++ =
				    (off_t)((off_t)catInfo->nodeData.cnd_rsrcfork.totalBlocks * (off_t)vcb->blockSize);
			}
			if (a & ATTR_FILE_RSRCEXTENTS) {
				bcopy(&catInfo->nodeData.cnd_rsrcfork.extents, attrbufptr, sizeof(extentrecord));
				(char *)attrbufptr += sizeof(extentrecord) + ((4 - (sizeof(extentrecord) & 3)) & 3);
			};
		};
	};
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}

#if 0
void PackForkAttributeBlock(struct attrlist *alist,
							struct vnode *vp,
							struct hfsCatalogInfo *catInfo,
							void **attrbufptrptr,
							void **varbufptrptr) {
	/* XXX PPD TBC */
}
#endif


//	This routine takes catInfo, and alist, as inputs and packs it into an attribute block.
void PackCatalogInfoAttributeBlock ( struct attrlist *alist, struct vnode *root_vp, struct hfsCatalogInfo *catInfo, void **attrbufptrptr, void **varbufptrptr)
{
	//XXX	Preflight that alist only contains bits with fields in catInfo

	PackCommonCatalogInfoAttributeBlock( alist, root_vp, catInfo, attrbufptrptr, varbufptrptr );
	
	switch ( catInfo->nodeData.cnd_type )
	{
		case kCatalogFolderNode:
            PackCatalogInfoDirAttributeBlock( alist, root_vp, catInfo, attrbufptrptr, varbufptrptr );
			break;
		
	  	case kCatalogFileNode:
            PackCatalogInfoFileAttributeBlock( alist, root_vp, catInfo, attrbufptrptr, varbufptrptr );
			break;
	  
	 	default:	/* Without this the compiler complains about VNON,VBLK,VCHR,VLNK,VSOCK,VFIFO,VBAD and VSTR not being handled... */
			/* XXX PPD - Panic? */
			break;
	}
}



void PackAttributeBlock(struct attrlist *alist,
						struct vnode *vp,
						struct hfsCatalogInfo *catInfo,
						void **attrbufptrptr,
						void **varbufptrptr)
{
	if (alist->volattr != 0) {
		DBG_ASSERT((vp->v_flag & VROOT) != 0);
		PackVolumeInfo(alist,vp, catInfo, attrbufptrptr, varbufptrptr);
	} else {
		PackCommonAttributeBlock(alist, vp, catInfo, attrbufptrptr, varbufptrptr);
		
		switch (vp->v_type) {
		case VDIR:
			PackDirAttributeBlock(alist, vp, catInfo, attrbufptrptr, varbufptrptr);
			break;
			
		case VREG:
		case VLNK:
			PackFileAttributeBlock(alist, vp, catInfo, attrbufptrptr, varbufptrptr);
			break;
		  
		  /* Without this the compiler complains about VNON,VBLK,VCHR,VLNK,VSOCK,VFIFO,VBAD and VSTR
		     not being handled...
		   */
		default:
			/* XXX PPD - Panic? */
			break;
		};
	};
};



void UnpackVolumeAttributeBlock(struct attrlist *alist,
								struct vnode *root_vp,
								ExtendedVCB *vcb,
								void **attrbufptrptr,
								void **varbufptrptr) {
	void *attrbufptr = *attrbufptrptr;
	attrgroup_t a;
	
    if ((alist->commonattr == 0) && (alist->volattr == 0)) {
        return;		/* Get out without dirtying the VCB */
    };

    VCB_LOCK(vcb);

	a = alist->commonattr;
	
	if (a & ATTR_CMN_SCRIPT) {
		vcb->volumeNameEncodingHint = (u_int32_t)*(((text_encoding_t *)attrbufptr)++);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_SCRIPT;
#endif
	};
	if (a & ATTR_CMN_CRTIME) {
		vcb->vcbCrDate = to_hfs_time((UInt32)((struct timespec *)attrbufptr)->tv_sec);
		/* Need to update the local time also */
		vcb->localCreateDate = UTCToLocal(vcb->vcbCrDate);
		++((struct timespec *)attrbufptr);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_CRTIME;
#endif
	};
	if (a & ATTR_CMN_MODTIME) {
		vcb->vcbLsMod = to_hfs_time((UInt32)((struct timespec *)attrbufptr)->tv_sec);
		++((struct timespec *)attrbufptr);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_MODTIME;
#endif
	};
	if (a & ATTR_CMN_BKUPTIME) {
		vcb->vcbVolBkUp = to_hfs_time((UInt32)((struct timespec *)attrbufptr)->tv_sec);
		++((struct timespec *)attrbufptr);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_BKUPTIME;
#endif
	};
	if (a & ATTR_CMN_FNDRINFO) {
		bcopy (attrbufptr, &vcb->vcbFndrInfo, sizeof(vcb->vcbFndrInfo));
		(char *)attrbufptr += sizeof(vcb->vcbFndrInfo);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_FNDRINFO;
#endif
	};
	
	DBG_ASSERT(a == 0);				/* All common attributes for volumes must've been handled by now... */

	a = alist->volattr & ~ATTR_VOL_INFO;
	if (a & ATTR_VOL_NAME) {
        copystr(((char *)attrbufptr) + *((u_long *)attrbufptr), vcb->vcbVN, sizeof(vcb->vcbVN), NULL);
        (char *)attrbufptr += sizeof(struct attrreference);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_VOL_NAME;
#endif
	};
	
	DBG_ASSERT(a == 0);				/* All common attributes for volumes must've been handled by now... */

    vcb->vcbFlags |= 0xFF00;		// Mark the VCB dirty

    VCB_UNLOCK(vcb);
}


void UnpackCommonAttributeBlock(struct attrlist *alist,
								struct vnode *vp,
								struct hfsCatalogInfo *catInfo,
								void **attrbufptrptr,
								void **varbufptrptr) {
	struct hfsnode *hp = VTOH(vp);
    void *attrbufptr;
    attrgroup_t a;
	
	attrbufptr = *attrbufptrptr;

    DBG_ASSERT(catInfo != NULL);
	
	a = alist->commonattr;
	if (a & ATTR_CMN_SCRIPT) {
		catInfo->nodeData.cnd_textEncoding = (u_int32_t)*((text_encoding_t *)attrbufptr)++;
		UpdateVolumeEncodings(VTOVCB(vp), catInfo->nodeData.cnd_textEncoding);		/* Update the volume encoding */
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_SCRIPT;
#endif
	};
	if (a & ATTR_CMN_CRTIME) {
		catInfo->nodeData.cnd_createDate = to_hfs_time((UInt32)((struct timespec *)attrbufptr)->tv_sec);
		VTOH(vp)->h_meta->h_crtime = (UInt32)((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_CRTIME;
#endif
	};
	if (a & ATTR_CMN_MODTIME) {
		catInfo->nodeData.cnd_contentModDate = to_hfs_time((UInt32)((struct timespec *)attrbufptr)->tv_sec);
		VTOH(vp)->h_meta->h_mtime = (UInt32)((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
		hp->h_nodeflags &= ~IN_UPDATE;
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_MODTIME;
#endif
	};
	if (a & ATTR_CMN_CHGTIME) {
		catInfo->nodeData.cnd_attributeModDate = to_hfs_time((UInt32)((struct timespec *)attrbufptr)->tv_sec);
		VTOH(vp)->h_meta->h_ctime = (UInt32)((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
		hp->h_nodeflags &= ~IN_CHANGE;
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_CHGTIME;
#endif
	};
	if (a & ATTR_CMN_ACCTIME) {
		catInfo->nodeData.cnd_accessDate = to_hfs_time((UInt32)((struct timespec *)attrbufptr)->tv_sec);
		VTOH(vp)->h_meta->h_atime = (UInt32)((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
		hp->h_nodeflags &= ~IN_ACCESS;
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_ACCTIME;
#endif
	};
	if (a & ATTR_CMN_BKUPTIME) {
		catInfo->nodeData.cnd_backupDate = to_hfs_time((UInt32)((struct timespec *)attrbufptr)->tv_sec);
		VTOH(vp)->h_meta->h_butime = (UInt32)((struct timespec *)attrbufptr)->tv_sec;
		++((struct timespec *)attrbufptr);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_BKUPTIME;
#endif
	};
	if (a & ATTR_CMN_FNDRINFO) {
		bcopy (attrbufptr, &catInfo->nodeData.cnd_finderInfo, sizeof(catInfo->nodeData.cnd_finderInfo));
		(char *)attrbufptr += sizeof(catInfo->nodeData.cnd_finderInfo);
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_FNDRINFO;
#endif
	};
	if (a & ATTR_CMN_OWNERID) {
        if (VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) {
			u_int32_t uid = (u_int32_t)*((uid_t *)attrbufptr)++;
			if (uid != (uid_t)VNOVAL)
				hp->h_meta->h_uid = uid;	/* catalog will get updated by hfs_chown() */
        }
		else {
            ((uid_t *)attrbufptr)++;
		}
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_OWNERID;
#endif
	};
	if (a & ATTR_CMN_GRPID) {
        u_int32_t gid = (u_int32_t)*((gid_t *)attrbufptr)++;
        if (VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) {
            if (gid != (gid_t)VNOVAL)
                hp->h_meta->h_gid = gid;					/* catalog will get updated by hfs_chown() */
        };
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_GRPID;
#endif
	};
	if (a & ATTR_CMN_ACCESSMASK) {
        u_int16_t mode = (u_int16_t)*((u_long *)attrbufptr)++;
        if (VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) {
            if (mode != (mode_t)VNOVAL) {
                hp->h_meta->h_mode &= ~ALLPERMS;
                hp->h_meta->h_mode |= (mode & ALLPERMS);	/* catalog will get updated by hfs_chmod() */
            }
        };
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_ACCESSMASK;
#endif
	};
	if (a & ATTR_CMN_FLAGS) {
		u_long flags = *((u_long *)attrbufptr)++;
        /* Flags are settable only on HFS+ volumes.  A special exception is made for the IMMUTABLE
           flags (SF_IMMUTABLE and UF_IMMUTABLE), which can be set on HFS volumes as well: */
        if ((VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) ||
            ((VTOVCB(vp)->vcbSigWord == kHFSSigWord) && ((flags & ~IMMUTABLE) == 0))) {
            if (flags != (u_long)VNOVAL) {
                hp->h_meta->h_pflags = flags;				/* catalog will get updated by hfs_chflags */
            };
        };
#if HFS_DIAGNOSTIC
		a &= ~ATTR_CMN_FLAGS;
#endif
	};

#if HFS_DIAGNOSTIC
	if (a != 0) {
		DEBUG_BREAK_MSG(("UnpackCommonAttributes: unhandled bit: 0x%08X\n", a));
	};
#endif

	*attrbufptrptr = attrbufptr;
//	*varbufptrptr = varbufptr;
}



#if 0
void UnpackDirAttributeBlock(struct attrlist *alist,
							 struct vnode *vp,
							 struct hfsCatalogInfo *catInfo,
							 void **attrbufptrptr,
							 void **varbufptrptr) {
    void *attrbufptr;
    void *varbufptr;
    attrgroup_t a;
	u_long attrlength;
	
	attrbufptr = *attrbufptrptr;
	varbufptr = *varbufptrptr;
	
	/* XXX PPD TBC */
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}
#endif



#if 0
void UnpackFileAttributeBlock(struct attrlist *alist,
							  struct vnode *vp,
							  struct hfsCatalogInfo *catInfo,
							  void **attrbufptrptr,
							  void **varbufptrptr) {
    void *attrbufptr;
    void *varbufptr;
    attrgroup_t a;
	u_long attrlength;
	
	attrbufptr = *attrbufptrptr;
	varbufptr = *varbufptrptr;
	
	/* XXX PPD TBC */
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}
#endif



#if 0
void UnpackForkAttributeBlock(struct attrlist *alist,
							struct vnode *vp,
							struct hfsCatalogInfo *catInfo,
							void **attrbufptrptr,
							void **varbufptrptr) {
    void *attrbufptr;
    void *varbufptr;
    attrgroup_t a;
	u_long attrlength;
	
	attrbufptr = *attrbufptrptr;
	varbufptr = *varbufptrptr;
	
	/* XXX PPD TBC */
	
	*attrbufptrptr = attrbufptr;
	*varbufptrptr = varbufptr;
}
#endif



void UnpackAttributeBlock(struct attrlist *alist,
						  struct vnode *vp,
						  struct hfsCatalogInfo *catInfo,
						  void **attrbufptrptr,
						  void **varbufptrptr) {


	if (alist->volattr != 0) {
		UnpackVolumeAttributeBlock(alist, vp, VTOVCB(vp), attrbufptrptr, varbufptrptr);
		return;
	};
	
	/* We're dealing with a vnode object here: */
	UnpackCommonAttributeBlock(alist, vp, catInfo, attrbufptrptr, varbufptrptr);
	
#if 0
	switch (vp->v_type) {
	  case VDIR:
		UnpackDirAttributeBlock(alist, vp, catInfo, attrbufptrptr, varbufptrptr);
		break;

	  case VREG:
   /* case VCPLX: */			/* XXX PPD TBC */
		UnpackFileAttributeBlock(alist, vp, catInfo, attrbufptrptr, varbufptrptr);
		break;

	  case VFORK:
		UnpackForkAttributeBlock(alist, vp, catInfo, attrbufptrptr, varbufptrptr);
		break;

	  /* Without this the compiler complains about VNON,VBLK,VCHR,VLNK,VSOCK,VFIFO,VBAD and VSTR
	     not being handled...
	   */
	  default:
		/* XXX PPD - Panic? */
		break;
	};
#endif

};


unsigned long BestBlockSizeFit(unsigned long allocationBlockSize,
                               unsigned long blockSizeLimit,
                               unsigned long baseMultiple) {
    /*
       Compute the optimal (largest) block size (no larger than allocationBlockSize) that is less than the
       specified limit but still an even multiple of the baseMultiple.
     */
    int baseBlockCount, blockCount;
    unsigned long trialBlockSize;

    if (allocationBlockSize % baseMultiple != 0) {
        /*
           Whoops: the allocation blocks aren't even multiples of the specified base:
           no amount of dividing them into even parts will be a multiple, either then!
        */
        return 512;		/* Hope for the best */
    };

    /* Try the obvious winner first, to prevent 12K allocation blocks, for instance,
       from being handled as two 6K logical blocks instead of 3 4K logical blocks.
       Even though the former (the result of the loop below) is the larger allocation
       block size, the latter is more efficient: */
    if (allocationBlockSize % PAGE_SIZE == 0) return PAGE_SIZE;

    /* No clear winner exists: pick the largest even fraction <= MAXBSIZE: */
    baseBlockCount = allocationBlockSize / baseMultiple;				/* Now guaranteed to be an even multiple */

    for (blockCount = baseBlockCount; blockCount > 0; --blockCount) {
        trialBlockSize = blockCount * baseMultiple;
        if (allocationBlockSize % trialBlockSize == 0) {				/* An even multiple? */
            if ((trialBlockSize <= blockSizeLimit) &&
                (trialBlockSize % baseMultiple == 0)) {
                return trialBlockSize;
            };
        };
    };

    /* Note: we should never get here, since blockCount = 1 should always work,
       but this is nice and safe and makes the compiler happy, too ... */
    return 512;
}


/*
 * To make the HFS Plus filesystem follow UFS unlink semantics, a remove
 * of an active vnode is translated to a move/rename so the file appears
 * deleted. The destination folder for these move/renames is setup here
 * and a reference to it is place in hfsmp->hfs_private_metadata_dir.
 */
u_long
FindMetaDataDirectory(ExtendedVCB *vcb)
{
	char namep[32];
	hfsCatalogInfo catInfo;
	HFSCatalogNodeID dirID;
	u_int32_t metadata_createdate;
	int retval;
	
	if (vcb->vcbSigWord != kHFSPlusSigWord)
		return (0);

	dirID = 0;
	metadata_createdate = 0;
	strncpy(namep, HFSPLUS_PRIVATE_DIR, sizeof(namep));
	INIT_CATALOGDATA(&catInfo.nodeData, kCatNameNoCopyName);
	catInfo.hint = kNoHint;

	/* lock catalog b-tree */
	retval = hfs_metafilelocking(VCBTOHFS(vcb), kHFSCatalogFileID, LK_SHARED, current_proc());	
	if (retval)  goto Err_Exit;

	if (hfs_getcatalog(vcb, kRootDirID, namep, -1, &catInfo) == 0) {
		dirID = catInfo.nodeData.cnd_nodeID;
		metadata_createdate = catInfo.nodeData.cnd_createDate;
	} else if (VCBTOHFS(vcb)->hfs_fs_ronly == 0) {
		if (CreateCatalogNode(vcb, kRootDirID, namep, kCatalogFolderNode, &dirID, &catInfo.hint, 0) == 0) {
			catInfo.hint = kNoHint;
			if (hfs_getcatalog(vcb, kRootDirID, namep, -1, &catInfo) == 0) {

				/* create date is later used for validation */
				catInfo.nodeData.cnd_createDate = vcb->vcbCrDate;
				metadata_createdate = catInfo.nodeData.cnd_createDate;

				/* directory with no permissions owned by root */
				catInfo.nodeData.cnd_mode = IFDIR;
				catInfo.nodeData.cnd_adminFlags = (SF_IMMUTABLE >> 16);

				/* hidden and off the desktop view */
				((struct DInfo *)(&catInfo.nodeData.cnd_finderInfo))->frLocation.v = SWAP_BE16 (22460);
				((struct DInfo *)(&catInfo.nodeData.cnd_finderInfo))->frLocation.h = SWAP_BE16 (22460);
				((struct DInfo *)(&catInfo.nodeData.cnd_finderInfo))->frFlags |= SWAP_BE16 (kIsInvisible + kNameLocked);		
	
				(void) UpdateCatalogNode(vcb, kRootDirID, namep, catInfo.hint, &catInfo.nodeData);
			}
		}
	}

	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(VCBTOHFS(vcb), kHFSCatalogFileID, LK_RELEASE, current_proc());
	
	VCBTOHFS(vcb)->hfs_metadata_createdate = metadata_createdate;
Err_Exit:	
	CLEAN_CATALOGDATA(&catInfo.nodeData);

	return dirID;
}


static void
RemovedMetaDataDirectory(ExtendedVCB *vcb)
{
	char name[32];
	hfsCatalogInfo catInfo;
	int retval;
	
	strncpy(name, HFSPLUS_PRIVATE_DIR, sizeof(name));
	INIT_CATALOGDATA(&catInfo.nodeData, kCatNameNoCopyName);

	/* lock catalog b-tree */
	retval = hfs_metafilelocking(VCBTOHFS(vcb), kHFSCatalogFileID, LK_SHARED, current_proc());	
	if (retval)  goto Err_Exit;

	/* If the HFSPLUSMETADATAFOLDER exists then delete it. */
	retval = GetCatalogNode(vcb, kRootDirID, name, strlen(name), kNoHint,
							&catInfo.nodeData, &catInfo.hint);
	if (retval == 0 && (catInfo.nodeData.cnd_type == kCatalogFolderNode)) {
		(void) DeleteCatalogNode(vcb, kRootDirID, name, catInfo.hint);
		printf("hfs_mount: removed \"%s\" from hfs volume \"%s\"\n", name, vcb->vcbVN);
	}

	/* unlock catalog b-tree */
	(void) hfs_metafilelocking(VCBTOHFS(vcb), kHFSCatalogFileID, LK_RELEASE, current_proc());

Err_Exit:	
	CLEAN_CATALOGDATA(&catInfo.nodeData);
}

/*
 * This will return the correct logical block size for a given vnode.
 * For most files, it is the allocation block size, for meta data like
 * BTrees, this is kept as part of the BTree private nodeSize
 */
u_int32_t
GetLogicalBlockSize(struct vnode *vp)
{
u_int32_t logBlockSize;
	
	DBG_ASSERT(vp != NULL);

	/* start with default */
	logBlockSize = VTOHFS(vp)->hfs_logBlockSize;

	if (vp->v_flag & VSYSTEM) {
		if (VTOH(vp)->fcbBTCBPtr != NULL) {
			BTreeInfoRec			bTreeInfo;
	
			/*
			 * We do not lock the BTrees, because if we are getting block..then the tree
			 * should be locked in the first place.
			 * We just want the nodeSize wich will NEVER change..so even if the world
			 * is changing..the nodeSize should remain the same. Which argues why lock
			 * it in the first place??
			 */
			
			(void) BTGetInformation	(VTOFCB(vp), kBTreeInfoVersion, &bTreeInfo);
					
			logBlockSize = bTreeInfo.nodeSize;

		} else if (H_FILEID(VTOH(vp)) == kHFSAllocationFileID) {
				logBlockSize = VTOVCB(vp)->vcbVBMIOSize;
		}
	}

	DBG_ASSERT(logBlockSize > 0);
	
	return logBlockSize;	
}

/*
 * Map HFS Common errors (negative) to BSD error codes (positive).
 * Positive errors (ie BSD errors) are passed through unchanged.
 */
short MacToVFSError(OSErr err)
{
    if (err >= 0) {
        if (err > 0) {
            DBG_ERR(("MacToVFSError: passing error #%d unchanged...\n", err));
        };
        return err;
    };

    if (err != 0) {
        DBG_ERR(("MacToVFSError: mapping error code %d...\n", err));
    };
    
	switch (err) {
	  case dirFulErr:							/*    -33 */
	  case dskFulErr:							/*    -34 */
	  case btNoSpaceAvail:						/* -32733 */
	  case fxOvFlErr:							/* -32750 */
		return ENOSPC;							/*    +28 */

	  case btBadNode:							/* -32731 */
	  case ioErr:								/*   -36 */
		return EIO;								/*    +5 */

	  case mFulErr:								/*   -41 */
	  case memFullErr:							/*  -108 */
		return ENOMEM;							/*   +12 */

	  case tmfoErr:								/*   -42 */
		/* Consider EMFILE (Too many open files, 24)? */	
		return ENFILE;							/*   +23 */

	  case nsvErr:								/*   -35 */
	  case fnfErr:								/*   -43 */
	  case dirNFErr:							/*  -120 */
	  case fidNotFound:							/* -1300 */
		return ENOENT;							/*    +2 */

	  case wPrErr:								/*   -44 */
	  case vLckdErr:							/*   -46 */
	  case fsDSIntErr:							/*  -127 */
		return EROFS;							/*   +30 */

	  case opWrErr:								/*   -49 */
	  case fLckdErr:							/*   -45 */
		return EACCES;							/*   +13 */

	  case permErr:								/*   -54 */
	  case wrPermErr:							/*   -61 */
		return EPERM;							/*    +1 */

	  case fBsyErr:								/*   -47 */
		return EBUSY;							/*   +16 */

	  case dupFNErr:							/*    -48 */
	  case fidExists:							/*  -1301 */
	  case cmExists:							/* -32718 */
	  case btExists:							/* -32734 */
		return EEXIST;							/*    +17 */

	  case rfNumErr:							/*   -51 */
		return EBADF;							/*    +9 */

	  case notAFileErr:							/* -1302 */
		return EISDIR;							/*   +21 */

	  case cmNotFound:							/* -32719 */
	  case btNotFound:							/* -32735 */	
		return ENOENT;							/*     28 */

	  case cmNotEmpty:							/* -32717 */
		return ENOTEMPTY;						/*     66 */

	  case cmFThdDirErr:						/* -32714 */
		return EISDIR;							/*     21 */

	  case fxRangeErr:							/* -32751 */
		return EIO;								/*      5 */

	  case bdNamErr:							/*   -37 */
		return ENAMETOOLONG;					/*    63 */

	  case fnOpnErr:							/*   -38 */
	  case eofErr:								/*   -39 */
	  case posErr:								/*   -40 */
	  case paramErr:							/*   -50 */
	  case badMDBErr:							/*   -60 */
	  case badMovErr:							/*  -122 */
	  case sameFileErr:							/* -1306 */
	  case badFidErr:							/* -1307 */
	  case fileBoundsErr:						/* -1309 */
		return EINVAL;							/*   +22 */

	  default:
		DBG_UTILS(("Unmapped MacOS error: %d\n", err));
		return EIO;								/*   +5 */
	}
}


/*
 * All of our debugging functions
 */

#if HFS_DIAGNOSTIC

void debug_vn_status (char* introStr, struct vnode *vn)
{
    DBG_VOP(("%s:\t",introStr));
    if (vn != NULL)
      {
        if (vn->v_tag != VT_HFS)
          {
            DBG_VOP(("NON-HFS VNODE Ox%08lX\n", (unsigned long)vn));
          }
        else if(vn->v_tag==VT_HFS && (vn->v_data==NULL || VTOH((vn))->h_valid != HFS_VNODE_MAGIC))
          {
            DBG_VOP(("BAD VNODE PRIVATE DATA!!!!\n"));
          }
        else
          {
            DBG_VOP(("r: %d & ", vn->v_usecount));
            if (lockstatus(&VTOH(vn)->h_lock))
              {
                DBG_VOP_CONT(("is L\n"));
              }
            else
              {
                DBG_VOP_CONT(("is U\n"));
              }
          }
      }
    else
      {
        DBG_VOP(("vnode is NULL\n"));
      };
}

void debug_vn_print (char* introStr, struct vnode *vn)
{
//  DBG_FUNC_NAME("DBG_VN_PRINT");
    DBG_ASSERT (vn != NULL);
    DBG_VFS(("%s: ",introStr));
    DBG_VFS_CONT(("vnode: 0x%x is a ", (uint)vn));
    switch (vn->v_tag)
      {
        case VT_UFS:
            DBG_VFS_CONT(("%s","UFS"));
            break;
        case VT_HFS:
            DBG_VFS_CONT(("%s","HFS"));
            break;
        default:
            DBG_VFS_CONT(("%s","UNKNOWN"));
            break;
      }

    DBG_VFS_CONT((" vnode\n"));
    if (vn->v_tag==VT_HFS)
      {
        if (vn->v_data==NULL)
          {
            DBG_VFS(("BAD VNODE PRIVATE DATA!!!!\n"));
          }
        else
          {
            DBG_VFS(("     Name: %s Id: %ld ",H_NAME(VTOH(vn)), H_FILEID(VTOH(vn))));
          }
      }
    else
        DBG_VFS(("     "));

    DBG_VFS_CONT(("Refcount: %d\n", vn->v_usecount));
    if (VOP_ISLOCKED(vn))
      {
        DBG_VFS(("     The vnode is locked\n"));
      }
    else
      {
        DBG_VFS(("     The vnode is not locked\n"));
      }
}

void debug_rename_test_locks (char* 			introStr,
                            struct vnode 	*fvp,
                            struct vnode 	*fdvp,
                            struct vnode 	*tvp,
                            struct vnode 	*tdvp,
                            int				fstatus,
                            int				fdstatus,
                            int				tstatus,
                            int				tdstatus
)
{
    DBG_VOP(("\t%s: ", introStr));
    if (fvp) {if(lockstatus(&VTOH(fvp)->h_lock)){DBG_VFS_CONT(("L"));} else {DBG_VFS_CONT(("U"));}} else { DBG_VFS_CONT(("X"));};
    if (fdvp) {if(lockstatus(&VTOH(fdvp)->h_lock)){DBG_VFS_CONT(("L"));} else {DBG_VFS_CONT(("U"));}} else { DBG_VFS_CONT(("X"));};
    if (tvp) {if(lockstatus(&VTOH(tvp)->h_lock)){DBG_VFS_CONT(("L"));} else {DBG_VFS_CONT(("U"));}} else { DBG_VFS_CONT(("X"));};
    if (tdvp) {if(lockstatus(&VTOH(tdvp)->h_lock)){DBG_VFS_CONT(("L"));} else {DBG_VFS_CONT(("U"));}} else { DBG_VFS_CONT(("X"));};
    DBG_VFS_CONT(("\n"));

    if (fvp) {
        if (lockstatus(&VTOH(fvp)->h_lock)) {
            if (fstatus==VOPDBG_UNLOCKED) {
                DBG_VOP(("\tfvp should be NOT LOCKED and it is\n"));
            }
        } else if (fstatus == VOPDBG_LOCKED) {
            DBG_VOP(("\tfvp should be LOCKED and it isnt\n"));
        }
    }

    if (fdvp) {
        if (lockstatus(&VTOH(fdvp)->h_lock)) {
            if (fdstatus==VOPDBG_UNLOCKED) {
                DBG_VOP(("\tfdvp should be NOT LOCKED and it is\n"));
            }
        } else if (fdstatus == VOPDBG_LOCKED) {
            DBG_VOP(("\tfdvp should be LOCKED and it isnt\n"));
        }
    }

    if (tvp) {
        if (lockstatus(&VTOH(tvp)->h_lock)) {
            if (tstatus==VOPDBG_UNLOCKED) {
                DBG_VOP(("\ttvp should be NOT LOCKED and it is\n"));
            }
        } else if (tstatus == VOPDBG_LOCKED) {
            DBG_VOP(("\ttvp should be LOCKED and it isnt\n"));
        }
    }

    if (tdvp) {
        if (lockstatus(&VTOH(tdvp)->h_lock)) {
            if (tdstatus==VOPDBG_UNLOCKED) {
                DBG_VOP(("\ttdvp should be NOT LOCKED and it is\n"));
            }
        } else if (tdstatus == VOPDBG_LOCKED) {
            DBG_VOP(("\ttdvp should be LOCKED and it isnt\n"));

        }
    }

}
#endif /* HFS_DIAGNOSTIC */


#if HFS_DIAGNOSTIC
void debug_check_buffersizes(struct vnode *vp, struct hfsnode *hp, struct buf *bp) {
    DBG_ASSERT(bp->b_validoff == 0);
    DBG_ASSERT(bp->b_dirtyoff == 0);
    DBG_ASSERT((bp->b_bcount == HTOHFS(hp)->hfs_logBlockSize) ||
                   ((bp->b_bcount % 512 == 0) &&
                    (bp->b_validend > 0) &&
                    (bp->b_dirtyend > 0) &&
                    (bp->b_bcount < HTOHFS(hp)->hfs_logBlockSize)));

    if (bp->b_validend == 0) {
        DBG_ASSERT(bp->b_dirtyend == 0);
    } else {
        DBG_ASSERT(bp->b_validend == bp->b_bcount);
        DBG_ASSERT(bp->b_dirtyend <= bp->b_bcount);
    };
}


void debug_check_blocksizes(struct vnode *vp) {
    struct hfsnode *hp = VTOH(vp);
    struct buf *bp;

    if (vp->v_flag & VSYSTEM) return;

    for (bp = vp->v_cleanblkhd.lh_first; bp != NULL; bp = bp->b_vnbufs.le_next) {
        debug_check_buffersizes(vp, hp, bp);
    };

    for (bp = vp->v_dirtyblkhd.lh_first; bp != NULL; bp = bp->b_vnbufs.le_next) {
        debug_check_buffersizes(vp, hp, bp);
    };
}

void debug_check_catalogdata(struct CatalogNodeData *cat) {

	if (cat->cnm_nameptr == NULL) {
        DBG_ASSERT((cat->cnm_flags & kCatNameIsAllocated) == 0);
	}
	else if (cat->cnm_nameptr == cat->cnm_namespace) {
        DBG_ASSERT((cat->cnm_flags & kCatNameIsAllocated) == 0);
    }
    else {
        DBG_ASSERT((cat->cnm_flags & kCatNameIsAllocated) == kCatNameIsAllocated);
    }

	if (cat->cnm_nameptr) {
		DBG_ASSERT(strlen(cat->cnm_nameptr) == cat->cnm_length);
	}
		
	if (cat->cnm_flags & kCatNameIsConsumed) {
        DBG_ASSERT((cat->cnm_flags & kCatNameIsAllocated) == 0);
    }

	if (cat->cnm_flags & kCatNameNoCopyName) {
        DBG_ASSERT((cat->cnm_flags & (kCatNameIsAllocated|kCatNameIsConsumed|kCatNameIsMangled)) == 0);
        DBG_ASSERT(cat->cnm_length == 0);
        DBG_ASSERT(cat->cnm_nameptr == 0);
        DBG_ASSERT(strlen(cat->cnm_namespace) == 0);
        }

}

extern void hfs_vhash_dbg(struct hfsnode *hp);

/* Checks the valicity of a hfs vnode */
void debug_check_vnode(struct vnode *vp, int stage) {
    struct hfsnode *hp;
    u_long size;
	int i;

	/* vcb stuff */
	if (VTOHFS(vp)->hfs_mount_flags & kHFSBootVolumeInconsistentMask)
        DEBUG_BREAK_MSG(("Volume is damaged!"));
	
    /* vnode stuff */
    if (vp==NULL)
        DEBUG_BREAK_MSG(("Null vnode"));
    if (vp->v_tag != VT_HFS)
        DEBUG_BREAK_MSG(("Not a HFS vnode, it is a %d", vp->v_tag));
    if (vp->v_data==NULL)
        DEBUG_BREAK_MSG(("v_data is NULL"));

    /* hfsnode stuff */
    hp = VTOH(vp);
    if (hp->h_valid != HFS_VNODE_MAGIC)
        DEBUG_BREAK_MSG(("Bad Formed HFS node"));
    if (hp->h_vp==NULL || hp->h_vp!=vp)
        DEBUG_BREAK_MSG(("Bad hfsnode vnode pte"));
    if (hp->h_meta == NULL)
        DEBUG_BREAK_MSG(("Bad hfsnode meta ptr"));
    switch (H_FORKTYPE(hp)) {
        case kDataFork:
        case kRsrcFork:
            if ((hp->h_meta->h_siblinghead.cqh_first == NULL) || (hp->h_meta->h_siblinghead.cqh_last == NULL))
                DEBUG_BREAK_MSG(("Null sibling header"));
            if ((hp->h_sibling.cqe_next==NULL) || (hp->h_sibling.cqe_prev==NULL))
                DEBUG_BREAK_MSG(("Null sibling list"));
                if (hp->h_meta->h_usecount<1 || hp->h_meta->h_usecount>2)
                    DEBUG_BREAK_MSG(("Bad sibling usecount"));
                    break;
        case kDirectory:
        case kSysFile:
            if ((hp->h_meta->h_siblinghead.cqh_first != NULL) || (hp->h_meta->h_siblinghead.cqh_last != NULL))
                DEBUG_BREAK_MSG(("Non Null sibling header"));
            if ((hp->h_sibling.cqe_next!=NULL) || (hp->h_sibling.cqe_prev!=NULL))
                DEBUG_BREAK_MSG(("Null sibling list"));
                if (hp->h_meta->h_usecount!=1)
                    DEBUG_BREAK_MSG(("Bad usecount"));

                    break;
        default:
            DEBUG_BREAK_MSG(("Bad hfsnode fork type"));
            }

    /* hfsmeta stuff */
    if (hp->h_meta->h_devvp == NULL)
        DEBUG_BREAK_MSG(("Bad hfsnode dev vnode"));
    if (H_DEV(hp) == 0)
        DEBUG_BREAK_MSG(("Bad dev id"));
    if (H_FILEID(hp) == 0)
        DEBUG_BREAK_MSG(("Bad file id"));
    
    if (((hp->h_meta->h_metaflags & IN_DATANODE)==0) && (H_DIRID(hp) == 0) && (H_FILEID(hp) != 1))
        DEBUG_BREAK_MSG(("Bad dir id"));
    
    if (hp->h_meta->h_namePtr == NULL && hp->h_meta->h_namelen!=0)
        DEBUG_BREAK_MSG(("hfs meta h_namelen is not 0"));
    if (hp->h_meta->h_namePtr != NULL && strlen(hp->h_meta->h_namePtr) != hp->h_meta->h_namelen)
        DEBUG_BREAK_MSG(("Bad hfs meta h_namelen"));

   /* Check the hash */
	hfs_vhash_dbg(hp);

	/* Check to see if we want to compare with the disk */
	if (stage > 200) {
		int retval;
		hfsCatalogInfo catInfo;

		INIT_CATALOGDATA(&catInfo.nodeData, 0);
		catInfo.hint = 0;

		if (hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_SHARED, current_proc()))
			return;

		if (hfs_getcatalog(VTOVCB(vp), H_DIRID(hp), hp->h_meta->h_namePtr, hp->h_meta->h_namelen, &catInfo))
			DEBUG_BREAK_MSG(("Could not find hfsnode Catalog record"));

		(void) hfs_metafilelocking(VTOHFS(vp), kHFSCatalogFileID, LK_RELEASE, current_proc());

		if (H_FILEID(hp) != catInfo.nodeData.cnd_nodeID)
			DEBUG_BREAK_MSG(("hfsnode catalog node id mismatch"));
		if (H_DIRID(hp) != catInfo.nodeData.cnm_parID)
			DEBUG_BREAK_MSG(("hfsnode catalog dir id mismatch"));
		if (strcmp(hp->h_meta->h_namePtr, catInfo.nodeData.cnm_nameptr) != 0)
			DEBUG_BREAK_MSG(("hfsnode catalog name mismatch"));
		/* Check dates too??? */

		CLEAN_CATALOGDATA(&catInfo.nodeData);

		}


	/* Check Extents */
	{
    for(i = 0, size = 0; i < kHFSPlusExtentDensity; i++)
      {	
        size += hp->fcbExtents[i].blockCount;	
      }

    if (hp->fcbEOF > hp->fcbPLen)
        DEBUG_BREAK_MSG(("fcbPLen is smaller than fcbEOF"));

    if (hp->fcbExtents[kHFSPlusExtentDensity-1].blockCount == 0) {
        if ((off_t)size * (off_t)VTOVCB(vp)->blockSize != hp->fcbPLen)
            DEBUG_BREAK_MSG(("fcbPLen does not match extents"));
	} else {
        if ( hp->fcbPLen < (off_t)size * (off_t)VTOVCB(vp)->blockSize)
            DEBUG_BREAK_MSG(("fcbPLen is smaller than extents"));
	}
    for(i = 0; i < kHFSPlusExtentDensity; i++)
      {	
        if (hp->fcbExtents[i].blockCount == 0 || hp->fcbExtents[i].startBlock == 0)
            break;	
      }
    if ((VTOVCB(vp)->vcbSigWord == kHFSSigWord) && i > kHFSExtentDensity)
        DEBUG_BREAK_MSG(("Illegal value in extents for ordinary HFS"));
    if (i > kHFSPlusExtentDensity) {
        for(; i < kHFSPlusExtentDensity; i++)
          {
            if (hp->fcbExtents[i].blockCount != 0 || hp->fcbExtents[i].startBlock != 0)
                DEBUG_BREAK_MSG(("Illegal value in extents"));
          }
    }
	}

    
    /* BTree stuff */
    if (0 && vp->v_flag & VSYSTEM) {
    	BTreeInfoRec			info;
    	
    	BTGetInformation(hp, 0, &info);
    	if (hp->fcbBTCBPtr == NULL)
               DEBUG_BREAK_MSG(("Null fcbBTCBPtr"));
    	if (H_HINT(hp) == 0)
               DEBUG_BREAK_MSG(("hint is 0"));
    	if (H_HINT(hp) > info.numNodes)
               DEBUG_BREAK_MSG(("hint > numNodes"));
    }

}

#endif /* HFS_DIAGNOSTIC */
