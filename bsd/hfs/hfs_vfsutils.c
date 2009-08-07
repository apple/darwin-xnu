/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
/*	@(#)hfs_vfsutils.c	4.0
*
*	(c) 1997-2002 Apple Computer, Inc.  All Rights Reserved
*
*	hfs_vfsutils.c -- Routines that go between the HFS layer and the VFS.
*
*/
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/buf_internal.h>
#include <sys/ubc.h>
#include <sys/unistd.h>
#include <sys/utfconv.h>
#include <sys/kauth.h>
#include <sys/fcntl.h>
#include <sys/vnode_internal.h>

#include <libkern/OSAtomic.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_dbg.h"
#include "hfs_mount.h"
#include "hfs_endian.h"
#include "hfs_cnode.h"
#include "hfs_fsctl.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"

static void ReleaseMetaFileVNode(struct vnode *vp);
static int  hfs_late_journal_init(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp, void *_args);

static void hfs_metadatazone_init(struct hfsmount *);
static u_int32_t hfs_hotfile_freeblocks(struct hfsmount *);


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
unsigned char hfs_catname[] = "Catalog B-tree";
unsigned char hfs_extname[] = "Extents B-tree";
unsigned char hfs_vbmname[] = "Volume Bitmap";
unsigned char hfs_attrname[] = "Attribute B-tree";
unsigned char hfs_startupname[] = "Startup File";


__private_extern__
OSErr hfs_MountHFSVolume(struct hfsmount *hfsmp, HFSMasterDirectoryBlock *mdb,
		__unused struct proc *p)
{
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	int error;
	ByteCount utf8chars;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	struct cat_fork fork;

	/* Block size must be a multiple of 512 */
	if (SWAP_BE32(mdb->drAlBlkSiz) == 0 ||
	    (SWAP_BE32(mdb->drAlBlkSiz) & 0x01FF) != 0)
		return (EINVAL);

	/* don't mount a writeable volume if its dirty, it must be cleaned by fsck_hfs */
	if (((hfsmp->hfs_flags & HFS_READ_ONLY) == 0) &&
	    ((SWAP_BE16(mdb->drAtrb) & kHFSVolumeUnmountedMask) == 0)) {
		return (EINVAL);
	}
	hfsmp->hfs_flags |= HFS_STANDARD;
	/*
	 * The MDB seems OK: transfer info from it into VCB
	 * Note - the VCB starts out clear (all zeros)
	 *
	 */
	vcb->vcbSigWord		= SWAP_BE16 (mdb->drSigWord);
	vcb->vcbCrDate		= to_bsd_time(LocalToUTC(SWAP_BE32(mdb->drCrDate)));
	vcb->localCreateDate	= SWAP_BE32 (mdb->drCrDate);
	vcb->vcbLsMod		= to_bsd_time(LocalToUTC(SWAP_BE32(mdb->drLsMod)));
	vcb->vcbAtrb		= SWAP_BE16 (mdb->drAtrb);
	vcb->vcbNmFls		= SWAP_BE16 (mdb->drNmFls);
	vcb->vcbVBMSt		= SWAP_BE16 (mdb->drVBMSt);
	vcb->nextAllocation	= SWAP_BE16 (mdb->drAllocPtr);
	vcb->totalBlocks	= SWAP_BE16 (mdb->drNmAlBlks);
	vcb->allocLimit		= vcb->totalBlocks;
	vcb->blockSize		= SWAP_BE32 (mdb->drAlBlkSiz);
	vcb->vcbClpSiz		= SWAP_BE32 (mdb->drClpSiz);
	vcb->vcbAlBlSt		= SWAP_BE16 (mdb->drAlBlSt);
	vcb->vcbNxtCNID		= SWAP_BE32 (mdb->drNxtCNID);
	vcb->freeBlocks		= SWAP_BE16 (mdb->drFreeBks);
	vcb->vcbVolBkUp		= to_bsd_time(LocalToUTC(SWAP_BE32(mdb->drVolBkUp)));
	vcb->vcbWrCnt		= SWAP_BE32 (mdb->drWrCnt);
	vcb->vcbNmRtDirs	= SWAP_BE16 (mdb->drNmRtDirs);
	vcb->vcbFilCnt		= SWAP_BE32 (mdb->drFilCnt);
	vcb->vcbDirCnt		= SWAP_BE32 (mdb->drDirCnt);
	bcopy(mdb->drFndrInfo, vcb->vcbFndrInfo, sizeof(vcb->vcbFndrInfo));
	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0)
		vcb->vcbWrCnt++;	/* Compensate for write of MDB on last flush */

	/* convert hfs encoded name into UTF-8 string */
	error = hfs_to_utf8(vcb, mdb->drVN, NAME_MAX, &utf8chars, vcb->vcbVN);
	/*
	 * When an HFS name cannot be encoded with the current
	 * volume encoding we use MacRoman as a fallback.
	 */
	if (error || (utf8chars == 0))
		(void) mac_roman_to_utf8(mdb->drVN, NAME_MAX, &utf8chars, vcb->vcbVN);

	hfsmp->hfs_logBlockSize = BestBlockSizeFit(vcb->blockSize, MAXBSIZE, hfsmp->hfs_logical_block_size);
	vcb->vcbVBMIOSize = kHFSBlockSize;

	hfsmp->hfs_alt_id_sector = HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size,
	                                          hfsmp->hfs_logical_block_count);

	bzero(&cndesc, sizeof(cndesc));
	cndesc.cd_parentcnid = kHFSRootParentID;
	cndesc.cd_flags |= CD_ISMETA;
	bzero(&cnattr, sizeof(cnattr));
	cnattr.ca_linkcount = 1;
	cnattr.ca_mode = S_IFREG;
	bzero(&fork, sizeof(fork));

	/*
	 * Set up Extents B-tree vnode
	 */
	cndesc.cd_nameptr = hfs_extname;
	cndesc.cd_namelen = strlen((char *)hfs_extname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSExtentsFileID;
	fork.cf_size = SWAP_BE32(mdb->drXTFlSize);
	fork.cf_blocks = fork.cf_size / vcb->blockSize;
	fork.cf_clump = SWAP_BE32(mdb->drXTClpSiz);
	fork.cf_vblocks = 0;
	fork.cf_extents[0].startBlock = SWAP_BE16(mdb->drXTExtRec[0].startBlock);
	fork.cf_extents[0].blockCount = SWAP_BE16(mdb->drXTExtRec[0].blockCount);
	fork.cf_extents[1].startBlock = SWAP_BE16(mdb->drXTExtRec[1].startBlock);
	fork.cf_extents[1].blockCount = SWAP_BE16(mdb->drXTExtRec[1].blockCount);
	fork.cf_extents[2].startBlock = SWAP_BE16(mdb->drXTExtRec[2].startBlock);
	fork.cf_extents[2].blockCount = SWAP_BE16(mdb->drXTExtRec[2].blockCount);
	cnattr.ca_blocks = fork.cf_blocks;

	error = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &fork,
	                        &hfsmp->hfs_extents_vp);
	if (error) goto MtVolErr;
	error = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_extents_vp),
	                                 (KeyCompareProcPtr)CompareExtentKeys));
	if (error) {
		hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
		goto MtVolErr;
	}
	hfsmp->hfs_extents_cp = VTOC(hfsmp->hfs_extents_vp);

	/*
	 * Set up Catalog B-tree vnode...
	 */ 
	cndesc.cd_nameptr = hfs_catname;
	cndesc.cd_namelen = strlen((char *)hfs_catname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSCatalogFileID;
	fork.cf_size = SWAP_BE32(mdb->drCTFlSize);
	fork.cf_blocks = fork.cf_size / vcb->blockSize;
	fork.cf_clump = SWAP_BE32(mdb->drCTClpSiz);
	fork.cf_vblocks = 0;
	fork.cf_extents[0].startBlock = SWAP_BE16(mdb->drCTExtRec[0].startBlock);
	fork.cf_extents[0].blockCount = SWAP_BE16(mdb->drCTExtRec[0].blockCount);
	fork.cf_extents[1].startBlock = SWAP_BE16(mdb->drCTExtRec[1].startBlock);
	fork.cf_extents[1].blockCount = SWAP_BE16(mdb->drCTExtRec[1].blockCount);
	fork.cf_extents[2].startBlock = SWAP_BE16(mdb->drCTExtRec[2].startBlock);
	fork.cf_extents[2].blockCount = SWAP_BE16(mdb->drCTExtRec[2].blockCount);
	cnattr.ca_blocks = fork.cf_blocks;

	error = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &fork,
	                        &hfsmp->hfs_catalog_vp);
	if (error) {
		hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
		goto MtVolErr;
	}
	error = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_catalog_vp),
	                                 (KeyCompareProcPtr)CompareCatalogKeys));
	if (error) {
		hfs_unlock(VTOC(hfsmp->hfs_catalog_vp));
		hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
		goto MtVolErr;
	}
	hfsmp->hfs_catalog_cp = VTOC(hfsmp->hfs_catalog_vp);

	/*
	 * Set up dummy Allocation file vnode (used only for locking bitmap)
	 */  
	cndesc.cd_nameptr = hfs_vbmname;
	cndesc.cd_namelen = strlen((char *)hfs_vbmname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSAllocationFileID;
	bzero(&fork, sizeof(fork));
	cnattr.ca_blocks = 0;

	error = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &fork,
	                         &hfsmp->hfs_allocation_vp);
	if (error) {
		hfs_unlock(VTOC(hfsmp->hfs_catalog_vp));
		hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
		goto MtVolErr;
	}
	hfsmp->hfs_allocation_cp = VTOC(hfsmp->hfs_allocation_vp);

      	/* mark the volume dirty (clear clean unmount bit) */
	vcb->vcbAtrb &=	~kHFSVolumeUnmountedMask;

    if (error == noErr)
      {
		error = cat_idlookup(hfsmp, kHFSRootFolderID, 0, NULL, NULL, NULL);
      }

    if ( error == noErr )
      {
        if ( !(vcb->vcbAtrb & kHFSVolumeHardwareLockMask) )		//	if the disk is not write protected
          {
            MarkVCBDirty( vcb );								//	mark VCB dirty so it will be written
          }
      }

	/*
	 * all done with system files so we can unlock now...
	 */
	hfs_unlock(VTOC(hfsmp->hfs_allocation_vp));
	hfs_unlock(VTOC(hfsmp->hfs_catalog_vp));
	hfs_unlock(VTOC(hfsmp->hfs_extents_vp));

    goto	CmdDone;

    //--	Release any resources allocated so far before exiting with an error:
MtVolErr:
	ReleaseMetaFileVNode(hfsmp->hfs_catalog_vp);
	ReleaseMetaFileVNode(hfsmp->hfs_extents_vp);

CmdDone:
    return (error);
}

//*******************************************************************************
//	Routine:	hfs_MountHFSPlusVolume
//
//
//*******************************************************************************

__private_extern__
OSErr hfs_MountHFSPlusVolume(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
	off_t embeddedOffset, u_int64_t disksize, __unused struct proc *p, void *args, kauth_cred_t cred)
{
	register ExtendedVCB *vcb;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	struct cat_fork cfork;
	u_int32_t blockSize;
	daddr64_t spare_sectors;
	struct BTreeInfoRec btinfo;
	u_int16_t  signature;
	u_int16_t  hfs_version;
	int  i;
	OSErr retval;

	signature = SWAP_BE16(vhp->signature);
	hfs_version = SWAP_BE16(vhp->version);

	if (signature == kHFSPlusSigWord) {
		if (hfs_version != kHFSPlusVersion) {
			printf("hfs_mount: invalid HFS+ version: %d\n", hfs_version);
			return (EINVAL);
		}
	} else if (signature == kHFSXSigWord) {
		if (hfs_version != kHFSXVersion) {
			printf("hfs_mount: invalid HFSX version: %d\n", hfs_version);
			return (EINVAL);
		}
		/* The in-memory signature is always 'H+'. */
		signature = kHFSPlusSigWord;
		hfsmp->hfs_flags |= HFS_X;
	} else {
		/* Removed printf for invalid HFS+ signature because it gives
		 * false error for UFS root volume 
		 */
		return (EINVAL);
	}

	/* Block size must be at least 512 and a power of 2 */
	blockSize = SWAP_BE32(vhp->blockSize);
	if (blockSize < 512 || !powerof2(blockSize))
		return (EINVAL);
   
	/* don't mount a writable volume if its dirty, it must be cleaned by fsck_hfs */
	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0 && hfsmp->jnl == NULL &&
	    (SWAP_BE32(vhp->attributes) & kHFSVolumeUnmountedMask) == 0)
		return (EINVAL);

	/* Make sure we can live with the physical block size. */
	if ((disksize & (hfsmp->hfs_logical_block_size - 1)) ||
	    (embeddedOffset & (hfsmp->hfs_logical_block_size - 1)) ||
	    (blockSize < hfsmp->hfs_logical_block_size)) {
		return (ENXIO);
	}

	/* If allocation block size is less than the physical 
	 * block size, we assume that the physical block size 
	 * is same as logical block size.  The physical block 
	 * size value is used to round down the offsets for 
	 * reading and writing the primary and alternate volume 
	 * headers at physical block boundary and will cause 
	 * problems if it is less than the block size.
	 */
	if (blockSize < hfsmp->hfs_physical_block_size) {
		hfsmp->hfs_physical_block_size = hfsmp->hfs_logical_block_size;
		hfsmp->hfs_log_per_phys = 1;
	}

	/*
	 * The VolumeHeader seems OK: transfer info from it into VCB
	 * Note - the VCB starts out clear (all zeros)
	 */
	vcb = HFSTOVCB(hfsmp);

	vcb->vcbSigWord	= signature;
	vcb->vcbJinfoBlock = SWAP_BE32(vhp->journalInfoBlock);
	vcb->vcbLsMod	= to_bsd_time(SWAP_BE32(vhp->modifyDate));
	vcb->vcbAtrb	= SWAP_BE32(vhp->attributes);
	vcb->vcbClpSiz	= SWAP_BE32(vhp->rsrcClumpSize);
	vcb->vcbNxtCNID	= SWAP_BE32(vhp->nextCatalogID);
	vcb->vcbVolBkUp	= to_bsd_time(SWAP_BE32(vhp->backupDate));
	vcb->vcbWrCnt	= SWAP_BE32(vhp->writeCount);
	vcb->vcbFilCnt	= SWAP_BE32(vhp->fileCount);
	vcb->vcbDirCnt	= SWAP_BE32(vhp->folderCount);
	
	/* copy 32 bytes of Finder info */
	bcopy(vhp->finderInfo, vcb->vcbFndrInfo, sizeof(vhp->finderInfo));    

	vcb->vcbAlBlSt = 0;		/* hfs+ allocation blocks start at first block of volume */
	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0)
		vcb->vcbWrCnt++;	/* compensate for write of Volume Header on last flush */

	/* Now fill in the Extended VCB info */
	vcb->nextAllocation	= SWAP_BE32(vhp->nextAllocation);
	vcb->totalBlocks	= SWAP_BE32(vhp->totalBlocks);
	vcb->allocLimit		= vcb->totalBlocks;
	vcb->freeBlocks		= SWAP_BE32(vhp->freeBlocks);
	vcb->blockSize		= blockSize;
	vcb->encodingsBitmap	= SWAP_BE64(vhp->encodingsBitmap);
	vcb->localCreateDate	= SWAP_BE32(vhp->createDate);
	
	vcb->hfsPlusIOPosOffset	= embeddedOffset;

	/* Default to no free block reserve */
	vcb->reserveBlocks = 0;

	/*
	 * Update the logical block size in the mount struct
	 * (currently set up from the wrapper MDB) using the
	 * new blocksize value:
	 */
	hfsmp->hfs_logBlockSize = BestBlockSizeFit(vcb->blockSize, MAXBSIZE, hfsmp->hfs_logical_block_size);
	vcb->vcbVBMIOSize = min(vcb->blockSize, MAXPHYSIO);

	/*
	 * Validate and initialize the location of the alternate volume header.
	 */
	spare_sectors = hfsmp->hfs_logical_block_count -
	                (((daddr64_t)vcb->totalBlocks * blockSize) /
	                   hfsmp->hfs_logical_block_size);

	if (spare_sectors > (daddr64_t)(blockSize / hfsmp->hfs_logical_block_size)) {
		hfsmp->hfs_alt_id_sector = 0;  /* partition has grown! */
	} else {
		hfsmp->hfs_alt_id_sector = (hfsmp->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size) +
					   HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size,
							  hfsmp->hfs_logical_block_count);
	}

	bzero(&cndesc, sizeof(cndesc));
	cndesc.cd_parentcnid = kHFSRootParentID;
	cndesc.cd_flags |= CD_ISMETA;
	bzero(&cnattr, sizeof(cnattr));
	cnattr.ca_linkcount = 1;
	cnattr.ca_mode = S_IFREG;

	/*
	 * Set up Extents B-tree vnode
	 */
	cndesc.cd_nameptr = hfs_extname;
	cndesc.cd_namelen = strlen((char *)hfs_extname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSExtentsFileID;

	cfork.cf_size    = SWAP_BE64 (vhp->extentsFile.logicalSize);
	cfork.cf_new_size= 0;
	cfork.cf_clump   = SWAP_BE32 (vhp->extentsFile.clumpSize);
	cfork.cf_blocks  = SWAP_BE32 (vhp->extentsFile.totalBlocks);
	cfork.cf_vblocks = 0;
	cnattr.ca_blocks = cfork.cf_blocks;
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		cfork.cf_extents[i].startBlock =
				SWAP_BE32 (vhp->extentsFile.extents[i].startBlock);
		cfork.cf_extents[i].blockCount =
				SWAP_BE32 (vhp->extentsFile.extents[i].blockCount);
	}
	retval = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &cfork,
	                         &hfsmp->hfs_extents_vp);
	if (retval)
	{
		goto ErrorExit;
	}
	hfsmp->hfs_extents_cp = VTOC(hfsmp->hfs_extents_vp);
	hfs_unlock(hfsmp->hfs_extents_cp);

	retval = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_extents_vp),
	                                  (KeyCompareProcPtr) CompareExtentKeysPlus));
	if (retval)
	{
		goto ErrorExit;
	}
	/*
	 * Set up Catalog B-tree vnode
	 */ 
	cndesc.cd_nameptr = hfs_catname;
	cndesc.cd_namelen = strlen((char *)hfs_catname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSCatalogFileID;

	cfork.cf_size    = SWAP_BE64 (vhp->catalogFile.logicalSize);
	cfork.cf_clump   = SWAP_BE32 (vhp->catalogFile.clumpSize);
	cfork.cf_blocks  = SWAP_BE32 (vhp->catalogFile.totalBlocks);
	cfork.cf_vblocks = 0;
	cnattr.ca_blocks = cfork.cf_blocks;
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		cfork.cf_extents[i].startBlock =
				SWAP_BE32 (vhp->catalogFile.extents[i].startBlock);
		cfork.cf_extents[i].blockCount =
				SWAP_BE32 (vhp->catalogFile.extents[i].blockCount);
	}
	retval = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &cfork,
	                         &hfsmp->hfs_catalog_vp);
	if (retval) {
		goto ErrorExit;
	}
	hfsmp->hfs_catalog_cp = VTOC(hfsmp->hfs_catalog_vp);
	hfs_unlock(hfsmp->hfs_catalog_cp);

	retval = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_catalog_vp),
	                                  (KeyCompareProcPtr) CompareExtendedCatalogKeys));
	if (retval) {
		goto ErrorExit;
	}
	if ((hfsmp->hfs_flags & HFS_X) &&
	    BTGetInformation(VTOF(hfsmp->hfs_catalog_vp), 0, &btinfo) == 0) {
		if (btinfo.keyCompareType == kHFSBinaryCompare) {
			hfsmp->hfs_flags |= HFS_CASE_SENSITIVE;
			/* Install a case-sensitive key compare */
			(void) BTOpenPath(VTOF(hfsmp->hfs_catalog_vp),
			                  (KeyCompareProcPtr)cat_binarykeycompare);
		}
	}

	/*
	 * Set up Allocation file vnode
	 */  
	cndesc.cd_nameptr = hfs_vbmname;
	cndesc.cd_namelen = strlen((char *)hfs_vbmname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSAllocationFileID;

	cfork.cf_size    = SWAP_BE64 (vhp->allocationFile.logicalSize);
	cfork.cf_clump   = SWAP_BE32 (vhp->allocationFile.clumpSize);
	cfork.cf_blocks  = SWAP_BE32 (vhp->allocationFile.totalBlocks);
	cfork.cf_vblocks = 0;
	cnattr.ca_blocks = cfork.cf_blocks;
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		cfork.cf_extents[i].startBlock =
				SWAP_BE32 (vhp->allocationFile.extents[i].startBlock);
		cfork.cf_extents[i].blockCount =
				SWAP_BE32 (vhp->allocationFile.extents[i].blockCount);
	}
	retval = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &cfork,
	                         &hfsmp->hfs_allocation_vp);
	if (retval) {
		goto ErrorExit;
	}
	hfsmp->hfs_allocation_cp = VTOC(hfsmp->hfs_allocation_vp);
	hfs_unlock(hfsmp->hfs_allocation_cp);

	/*
	 * Set up Attribute B-tree vnode
	 */
	if (vhp->attributesFile.totalBlocks != 0) {
		cndesc.cd_nameptr = hfs_attrname;
		cndesc.cd_namelen = strlen((char *)hfs_attrname);
		cndesc.cd_cnid = cnattr.ca_fileid = kHFSAttributesFileID;
	
		cfork.cf_size    = SWAP_BE64 (vhp->attributesFile.logicalSize);
		cfork.cf_clump   = SWAP_BE32 (vhp->attributesFile.clumpSize);
		cfork.cf_blocks  = SWAP_BE32 (vhp->attributesFile.totalBlocks);
		cfork.cf_vblocks = 0;
		cnattr.ca_blocks = cfork.cf_blocks;
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			cfork.cf_extents[i].startBlock =
					SWAP_BE32 (vhp->attributesFile.extents[i].startBlock);
			cfork.cf_extents[i].blockCount =
					SWAP_BE32 (vhp->attributesFile.extents[i].blockCount);
		}
		retval = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &cfork,
					 &hfsmp->hfs_attribute_vp);
		if (retval) {
			goto ErrorExit;
		}
		hfsmp->hfs_attribute_cp = VTOC(hfsmp->hfs_attribute_vp);
		hfs_unlock(hfsmp->hfs_attribute_cp);
		retval = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_attribute_vp),
						  (KeyCompareProcPtr) hfs_attrkeycompare));
		if (retval) {
			goto ErrorExit;
		}
	}

	/*
	 * Set up Startup file vnode
	 */
	if (vhp->startupFile.totalBlocks != 0) {
		cndesc.cd_nameptr = hfs_startupname;
		cndesc.cd_namelen = strlen((char *)hfs_startupname);
		cndesc.cd_cnid = cnattr.ca_fileid = kHFSStartupFileID;
	
		cfork.cf_size    = SWAP_BE64 (vhp->startupFile.logicalSize);
		cfork.cf_clump   = SWAP_BE32 (vhp->startupFile.clumpSize);
		cfork.cf_blocks  = SWAP_BE32 (vhp->startupFile.totalBlocks);
		cfork.cf_vblocks = 0;
		cnattr.ca_blocks = cfork.cf_blocks;
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			cfork.cf_extents[i].startBlock =
					SWAP_BE32 (vhp->startupFile.extents[i].startBlock);
			cfork.cf_extents[i].blockCount =
					SWAP_BE32 (vhp->startupFile.extents[i].blockCount);
		}
		retval = hfs_getnewvnode(hfsmp, NULL, NULL, &cndesc, 0, &cnattr, &cfork,
					 &hfsmp->hfs_startup_vp);
		if (retval) {
			goto ErrorExit;
		}
		hfsmp->hfs_startup_cp = VTOC(hfsmp->hfs_startup_vp);
		hfs_unlock(hfsmp->hfs_startup_cp);
	}
	
	/* Pick up volume name and create date */
	retval = cat_idlookup(hfsmp, kHFSRootFolderID, 0, &cndesc, &cnattr, NULL);
	if (retval) {
		goto ErrorExit;
	}
	vcb->vcbCrDate = cnattr.ca_itime;
	vcb->volumeNameEncodingHint = cndesc.cd_encoding;
	bcopy(cndesc.cd_nameptr, vcb->vcbVN, min(255, cndesc.cd_namelen));
	cat_releasedesc(&cndesc);

	/* mark the volume dirty (clear clean unmount bit) */
	vcb->vcbAtrb &=	~kHFSVolumeUnmountedMask;
	if (hfsmp->jnl && (hfsmp->hfs_flags & HFS_READ_ONLY) == 0) {
		hfs_flushvolumeheader(hfsmp, TRUE, 0);
	}

	/* kHFSHasFolderCount is only supported/updated on HFSX volumes */
	if ((hfsmp->hfs_flags & HFS_X) != 0) {
		hfsmp->hfs_flags |= HFS_FOLDERCOUNT;
	}

	//
	// Check if we need to do late journal initialization.  This only
	// happens if a previous version of MacOS X (or 9) touched the disk.
	// In that case hfs_late_journal_init() will go re-locate the journal 
	// and journal_info_block files and validate that they're still kosher.
	//
	if (   (vcb->vcbAtrb & kHFSVolumeJournaledMask)
		&& (SWAP_BE32(vhp->lastMountedVersion) != kHFSJMountVersion)
		&& (hfsmp->jnl == NULL)) {

		retval = hfs_late_journal_init(hfsmp, vhp, args);
		if (retval != 0) {
			hfsmp->jnl = NULL;
			
			// if the journal failed to open, then set the lastMountedVersion
			// to be "FSK!" which fsck_hfs will see and force the fsck instead
			// of just bailing out because the volume is journaled.
			if (!(hfsmp->hfs_flags & HFS_READ_ONLY)) {
				HFSPlusVolumeHeader *jvhp;
				daddr64_t mdb_offset;
				struct buf *bp = NULL;
				
				hfsmp->hfs_flags |= HFS_NEED_JNL_RESET;
				    
				mdb_offset = (daddr64_t)((embeddedOffset / blockSize) + HFS_PRI_SECTOR(blockSize));

				retval = (int)buf_meta_bread(hfsmp->hfs_devvp, 
						HFS_PHYSBLK_ROUNDDOWN(mdb_offset, hfsmp->hfs_log_per_phys),
						hfsmp->hfs_physical_block_size, cred, &bp);
				if (retval == 0) {
					jvhp = (HFSPlusVolumeHeader *)(buf_dataptr(bp) + HFS_PRI_OFFSET(hfsmp->hfs_physical_block_size));
					    
					if (SWAP_BE16(jvhp->signature) == kHFSPlusSigWord || SWAP_BE16(jvhp->signature) == kHFSXSigWord) {
						printf ("hfs(3): Journal replay fail.  Writing lastMountVersion as FSK!\n");
						jvhp->lastMountedVersion = SWAP_BE32(kFSKMountVersion);
					   	buf_bwrite(bp);
					} else {
						buf_brelse(bp);
					}
					bp = NULL;
				} else if (bp) {
					buf_brelse(bp);
					// clear this so the error exit path won't try to use it
					bp = NULL;
			    }
			}

			retval = EINVAL;
			goto ErrorExit;
		} else if (hfsmp->jnl) {
			vfs_setflags(hfsmp->hfs_mp, (u_int64_t)((unsigned int)MNT_JOURNALED));
		}
	} else if (hfsmp->jnl || ((vcb->vcbAtrb & kHFSVolumeJournaledMask) && (hfsmp->hfs_flags & HFS_READ_ONLY))) {
		struct cat_attr jinfo_attr, jnl_attr;
		
		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		    vcb->vcbAtrb &= ~kHFSVolumeJournaledMask;
		}

		// if we're here we need to fill in the fileid's for the
		// journal and journal_info_block.
		hfsmp->hfs_jnlinfoblkid = GetFileInfo(vcb, kRootDirID, ".journal_info_block", &jinfo_attr, NULL);
		hfsmp->hfs_jnlfileid    = GetFileInfo(vcb, kRootDirID, ".journal", &jnl_attr, NULL);
		if (hfsmp->hfs_jnlinfoblkid == 0 || hfsmp->hfs_jnlfileid == 0) {
			printf("hfs: danger! couldn't find the file-id's for the journal or journal_info_block\n");
			printf("hfs: jnlfileid %d, jnlinfoblkid %d\n", hfsmp->hfs_jnlfileid, hfsmp->hfs_jnlinfoblkid);
		}

		if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		    vcb->vcbAtrb |= kHFSVolumeJournaledMask;
		}

		if (hfsmp->jnl == NULL) {
		    vfs_clearflags(hfsmp->hfs_mp, (u_int64_t)((unsigned int)MNT_JOURNALED));
		}
	}

	/*
	 * Establish a metadata allocation zone.
	 */
	hfs_metadatazone_init(hfsmp);

	/*
	 * Make any metadata zone adjustments.
	 */
	if (hfsmp->hfs_flags & HFS_METADATA_ZONE) {
		/* Keep the roving allocator out of the metadata zone. */
		if (vcb->nextAllocation >= hfsmp->hfs_metazone_start &&
		    vcb->nextAllocation <= hfsmp->hfs_metazone_end) {	    
			HFS_UPDATE_NEXT_ALLOCATION(hfsmp, hfsmp->hfs_metazone_end + 1);
		}
	}

	/* Setup private/hidden directories for hardlinks. */
	hfs_privatedir_init(hfsmp, FILE_HARDLINKS);
	hfs_privatedir_init(hfsmp, DIR_HARDLINKS);

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0) 
		hfs_remove_orphans(hfsmp);

	if ( !(vcb->vcbAtrb & kHFSVolumeHardwareLockMask) )	// if the disk is not write protected
	{
		MarkVCBDirty( vcb );	// mark VCB dirty so it will be written
	}

	/*
	 * Allow hot file clustering if conditions allow.
	 */
	if ((hfsmp->hfs_flags & HFS_METADATA_ZONE)  &&
	    ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0)) {
		(void) hfs_recording_init(hfsmp);
	}

	/* Force ACLs on HFS+ file systems. */
	vfs_setextendedsecurity(HFSTOVFS(hfsmp));

	/* Check if volume supports writing of extent-based extended attributes */
	hfs_check_volxattr(hfsmp, HFS_SET_XATTREXTENTS_STATE);

	return (0);

ErrorExit:
	/*
	 * A fatal error occurred and the volume cannot be mounted
	 * release any resources that we aquired...
	 */
	if (hfsmp->hfs_attribute_vp)
		ReleaseMetaFileVNode(hfsmp->hfs_attribute_vp);
	ReleaseMetaFileVNode(hfsmp->hfs_allocation_vp);
	ReleaseMetaFileVNode(hfsmp->hfs_catalog_vp);
	ReleaseMetaFileVNode(hfsmp->hfs_extents_vp);

	return (retval);
}


/*
 * ReleaseMetaFileVNode
 *
 * vp	L - -
 */
static void ReleaseMetaFileVNode(struct vnode *vp)
{
	struct filefork *fp;

	if (vp && (fp = VTOF(vp))) {
		if (fp->fcbBTCBPtr != NULL) {
			(void)hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK);
			(void) BTClosePath(fp);
			hfs_unlock(VTOC(vp));
		}

		/* release the node even if BTClosePath fails */
		vnode_recycle(vp);
		vnode_put(vp);
	}
}


/*************************************************************
*
* Unmounts a hfs volume.
*	At this point vflush() has been called (to dump all non-metadata files)
*
*************************************************************/

__private_extern__
int
hfsUnmount( register struct hfsmount *hfsmp, __unused struct proc *p)
{
	/* Get rid of our attribute data vnode (if any). */
	if (hfsmp->hfs_attrdata_vp) {
		vnode_t advp = hfsmp->hfs_attrdata_vp;
	
		if (vnode_get(advp) == 0) {
			vnode_rele_ext(advp, O_EVTONLY, 0);
			vnode_put(advp);
		}
		hfsmp->hfs_attrdata_vp = NULLVP;
	}

	if (hfsmp->hfs_startup_vp)
		ReleaseMetaFileVNode(hfsmp->hfs_startup_vp);

	if (hfsmp->hfs_allocation_vp)
		ReleaseMetaFileVNode(hfsmp->hfs_allocation_vp);

	if (hfsmp->hfs_attribute_vp)
		ReleaseMetaFileVNode(hfsmp->hfs_attribute_vp);

	ReleaseMetaFileVNode(hfsmp->hfs_catalog_vp);
	ReleaseMetaFileVNode(hfsmp->hfs_extents_vp);

	/*
	 * Setting these pointers to NULL so that any references
	 * past this point will fail, and tell us the point of failure.
	 * Also, facilitates a check in hfs_update for a null catalog
	 * vp
	 */
	hfsmp->hfs_allocation_vp = NULL;
	hfsmp->hfs_attribute_vp = NULL;
	hfsmp->hfs_catalog_vp = NULL;
	hfsmp->hfs_extents_vp = NULL;
	hfsmp->hfs_startup_vp = NULL;

	return (0);
}


/*
 * Test if fork has overflow extents.
 */
__private_extern__
int
overflow_extents(struct filefork *fp)
{
	u_long blocks;

	//
	// If the vnode pointer is NULL then we're being called
	// from hfs_remove_orphans() with a faked-up filefork
	// and therefore it has to be an HFS+ volume.  Otherwise
	// we check through the volume header to see what type
	// of volume we're on.
        //
	if (FTOV(fp) == NULL || VTOVCB(FTOV(fp))->vcbSigWord == kHFSPlusSigWord) {
		if (fp->ff_extents[7].blockCount == 0)
			return (0);

		blocks = fp->ff_extents[0].blockCount +
		         fp->ff_extents[1].blockCount +
		         fp->ff_extents[2].blockCount +
		         fp->ff_extents[3].blockCount +
		         fp->ff_extents[4].blockCount +
		         fp->ff_extents[5].blockCount +
		         fp->ff_extents[6].blockCount +
		         fp->ff_extents[7].blockCount;	
	} else {
		if (fp->ff_extents[2].blockCount == 0)
			return false;
		
		blocks = fp->ff_extents[0].blockCount +
		         fp->ff_extents[1].blockCount +
		         fp->ff_extents[2].blockCount;	
	  }

	return (fp->ff_blocks > blocks);
}


/*
 * Lock HFS system file(s).
 */
__private_extern__
int
hfs_systemfile_lock(struct hfsmount *hfsmp, int flags, enum hfslocktype locktype)
{
	/*
	 * Locking order is Catalog file, Attributes file, Startup file, Bitmap file, Extents file
	 */
	if (flags & SFL_CATALOG) {

#ifdef HFS_CHECK_LOCK_ORDER
		if (hfsmp->hfs_attribute_cp && hfsmp->hfs_attribute_cp->c_lockowner == current_thread()) {
			panic("hfs_systemfile_lock: bad lock order (Attributes before Catalog)");
		}
		if (hfsmp->hfs_startup_cp && hfsmp->hfs_startup_cp->c_lockowner == current_thread()) {
			panic("hfs_systemfile_lock: bad lock order (Startup before Catalog)");
		}
		if (hfsmp-> hfs_extents_cp && hfsmp->hfs_extents_cp->c_lockowner == current_thread()) {
			panic("hfs_systemfile_lock: bad lock order (Extents before Catalog)");
		}
#endif /* HFS_CHECK_LOCK_ORDER */

		(void) hfs_lock(hfsmp->hfs_catalog_cp, locktype);
		/*
		 * When the catalog file has overflow extents then
		 * also acquire the extents b-tree lock if its not
		 * already requested.
		 */
		if ((flags & SFL_EXTENTS) == 0 &&
		    overflow_extents(VTOF(hfsmp->hfs_catalog_vp))) {
			flags |= SFL_EXTENTS;
		}
	}
	if (flags & SFL_ATTRIBUTE) {

#ifdef HFS_CHECK_LOCK_ORDER
		if (hfsmp->hfs_startup_cp && hfsmp->hfs_startup_cp->c_lockowner == current_thread()) {
			panic("hfs_systemfile_lock: bad lock order (Startup before Attributes)");
		}
		if (hfsmp->hfs_extents_cp && hfsmp->hfs_extents_cp->c_lockowner == current_thread()) {
			panic("hfs_systemfile_lock: bad lock order (Extents before Attributes)");
		}
#endif /* HFS_CHECK_LOCK_ORDER */

		if (hfsmp->hfs_attribute_cp) {
			(void) hfs_lock(hfsmp->hfs_attribute_cp, locktype);
			/*
			 * When the attribute file has overflow extents then
			 * also acquire the extents b-tree lock if its not
			 * already requested.
			 */
			if ((flags & SFL_EXTENTS) == 0 &&
			    overflow_extents(VTOF(hfsmp->hfs_attribute_vp))) {
				flags |= SFL_EXTENTS;
			}
		} else {
			flags &= ~SFL_ATTRIBUTE;
		}
	}
	if (flags & SFL_STARTUP) {
#ifdef HFS_CHECK_LOCK_ORDER
		if (hfsmp-> hfs_extents_cp && hfsmp->hfs_extents_cp->c_lockowner == current_thread()) {
			panic("hfs_systemfile_lock: bad lock order (Extents before Startup)");
		}
#endif /* HFS_CHECK_LOCK_ORDER */

		(void) hfs_lock(hfsmp->hfs_startup_cp, locktype);
		/*
		 * When the startup file has overflow extents then
		 * also acquire the extents b-tree lock if its not
		 * already requested.
		 */
		if ((flags & SFL_EXTENTS) == 0 &&
		    overflow_extents(VTOF(hfsmp->hfs_startup_vp))) {
			flags |= SFL_EXTENTS;
		}
	}
	/* 
	 * To prevent locks being taken in the wrong order, the extent lock
	 * gets a bitmap lock as well.
	 */
	if (flags & (SFL_BITMAP | SFL_EXTENTS)) {
		/*
		 * Since the only bitmap operations are clearing and
		 * setting bits we always need exclusive access. And
		 * when we have a journal, we can "hide" behind that
		 * lock since we can only change the bitmap from
		 * within a transaction.
		 */
		if (hfsmp->jnl || (hfsmp->hfs_allocation_cp == NULL)) {
			flags &= ~SFL_BITMAP;
		} else {
			(void) hfs_lock(hfsmp->hfs_allocation_cp, HFS_EXCLUSIVE_LOCK);
			/* The bitmap lock is also grabbed when only extent lock 
			 * was requested. Set the bitmap lock bit in the lock
			 * flags which callers will use during unlock.
			 */
			flags |= SFL_BITMAP;
		}
	}
	if (flags & SFL_EXTENTS) {
		/*
		 * Since the extents btree lock is recursive we always
		 * need exclusive access.
		 */
		(void) hfs_lock(hfsmp->hfs_extents_cp, HFS_EXCLUSIVE_LOCK);
	}
	return (flags);
}

/*
 * unlock HFS system file(s).
 */
__private_extern__
void
hfs_systemfile_unlock(struct hfsmount *hfsmp, int flags)
{
	struct timeval tv;
	u_int32_t lastfsync;
	int numOfLockedBuffs;

	if (hfsmp->jnl == NULL) {
		microuptime(&tv);
		lastfsync = tv.tv_sec;
	}
	if (flags & SFL_STARTUP && hfsmp->hfs_startup_cp) {
		hfs_unlock(hfsmp->hfs_startup_cp);
	}
	if (flags & SFL_ATTRIBUTE && hfsmp->hfs_attribute_cp) {
		if (hfsmp->jnl == NULL) {
			BTGetLastSync((FCB*)VTOF(hfsmp->hfs_attribute_vp), &lastfsync);
			numOfLockedBuffs = count_lock_queue();
			if ((numOfLockedBuffs > kMaxLockedMetaBuffers) ||
			    ((numOfLockedBuffs > 1) && ((tv.tv_sec - lastfsync) >
			      kMaxSecsForFsync))) {
				hfs_btsync(hfsmp->hfs_attribute_vp, HFS_SYNCTRANS);
			}
		}
		hfs_unlock(hfsmp->hfs_attribute_cp);
	}
	if (flags & SFL_CATALOG) {
		if (hfsmp->jnl == NULL) {
			BTGetLastSync((FCB*)VTOF(hfsmp->hfs_catalog_vp), &lastfsync);
			numOfLockedBuffs = count_lock_queue();
			if ((numOfLockedBuffs > kMaxLockedMetaBuffers) ||
			    ((numOfLockedBuffs > 1) && ((tv.tv_sec - lastfsync) >
			      kMaxSecsForFsync))) {
				hfs_btsync(hfsmp->hfs_catalog_vp, HFS_SYNCTRANS);
			}
		}
		hfs_unlock(hfsmp->hfs_catalog_cp);
	}
	if (flags & SFL_BITMAP) {
		hfs_unlock(hfsmp->hfs_allocation_cp);
	}
	if (flags & SFL_EXTENTS) {
		if (hfsmp->jnl == NULL) {
			BTGetLastSync((FCB*)VTOF(hfsmp->hfs_extents_vp), &lastfsync);
			numOfLockedBuffs = count_lock_queue();
			if ((numOfLockedBuffs > kMaxLockedMetaBuffers) ||
			    ((numOfLockedBuffs > 1) && ((tv.tv_sec - lastfsync) >
			      kMaxSecsForFsync))) {
				hfs_btsync(hfsmp->hfs_extents_vp, HFS_SYNCTRANS);
			}
		}
		hfs_unlock(hfsmp->hfs_extents_cp);
	}
}


/*
 * RequireFileLock
 *
 * Check to see if a vnode is locked in the current context
 * This is to be used for debugging purposes only!!
 */
#if HFS_DIAGNOSTIC
void RequireFileLock(FileReference vp, int shareable)
{
	int locked;

	/* The extents btree and allocation bitmap are always exclusive. */
	if (VTOC(vp)->c_fileid == kHFSExtentsFileID ||
	    VTOC(vp)->c_fileid == kHFSAllocationFileID) {
		shareable = 0;
	}
	
	locked = VTOC(vp)->c_lockowner == (void *)current_thread();
	
	if (!locked && !shareable) {
		switch (VTOC(vp)->c_fileid) {
		case kHFSExtentsFileID:
			panic("extents btree not locked! v: 0x%08X\n #\n", (u_int)vp);
			break;
		case kHFSCatalogFileID:
			panic("catalog btree not locked! v: 0x%08X\n #\n", (u_int)vp);
			break;
		case kHFSAllocationFileID:
			/* The allocation file can hide behind the jornal lock. */
			if (VTOHFS(vp)->jnl == NULL)
				panic("allocation file not locked! v: 0x%08X\n #\n", (u_int)vp);
			break;
		case kHFSStartupFileID:
			panic("startup file not locked! v: 0x%08X\n #\n", (u_int)vp);
		case kHFSAttributesFileID:
			panic("attributes btree not locked! v: 0x%08X\n #\n", (u_int)vp);
			break;
		}
	}
}
#endif


/*
 * There are three ways to qualify for ownership rights on an object:
 *
 * 1. (a) Your UID matches the cnode's UID.
 *    (b) The object in question is owned by "unknown"
 * 2. (a) Permissions on the filesystem are being ignored and
 *        your UID matches the replacement UID.
 *    (b) Permissions on the filesystem are being ignored and
 *        the replacement UID is "unknown".
 * 3. You are root.
 *
 */
int
hfs_owner_rights(struct hfsmount *hfsmp, uid_t cnode_uid, kauth_cred_t cred,
		__unused struct proc *p, int invokesuperuserstatus)
{
	if ((kauth_cred_getuid(cred) == cnode_uid) ||                                    /* [1a] */
	    (cnode_uid == UNKNOWNUID) ||  									  /* [1b] */
	    ((((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS) &&          /* [2] */
	      ((kauth_cred_getuid(cred) == hfsmp->hfs_uid) ||                            /* [2a] */
	        (hfsmp->hfs_uid == UNKNOWNUID))) ||                           /* [2b] */
	    (invokesuperuserstatus && (suser(cred, 0) == 0))) {    /* [3] */
		return (0);
	} else {	
		return (EPERM);
	}
}


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


__private_extern__
u_long
GetFileInfo(ExtendedVCB *vcb, __unused u_int32_t dirid, const char *name,
			struct cat_attr *fattr, struct cat_fork *forkinfo)
{
	struct hfsmount * hfsmp;
	struct cat_desc jdesc;
	int lockflags;
	int error;
	
	if (vcb->vcbSigWord != kHFSPlusSigWord)
		return (0);

	hfsmp = VCBTOHFS(vcb);

	memset(&jdesc, 0, sizeof(struct cat_desc));
	jdesc.cd_parentcnid = kRootDirID;
	jdesc.cd_nameptr = (const u_int8_t *)name;
	jdesc.cd_namelen = strlen(name);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
	error = cat_lookup(hfsmp, &jdesc, 0, NULL, fattr, forkinfo, NULL);
	hfs_systemfile_unlock(hfsmp, lockflags);

	if (error == 0) {
		return (fattr->ca_fileid);
	} else if (hfsmp->hfs_flags & HFS_READ_ONLY) {
		return (0);
	}

	return (0);	/* XXX what callers expect on an error */
}


/*
 * On HFS Plus Volumes, there can be orphaned files or directories
 * These are files or directories that were unlinked while busy. 
 * If the volume was not cleanly unmounted then some of these may
 * have persisted and need to be removed.
 */
__private_extern__
void
hfs_remove_orphans(struct hfsmount * hfsmp)
{
	struct BTreeIterator * iterator = NULL;
	struct FSBufferDescriptor btdata;
	struct HFSPlusCatalogFile filerec;
	struct HFSPlusCatalogKey * keyp;
	struct proc *p = current_proc();
	FCB *fcb;
	ExtendedVCB *vcb;
	char filename[32];
	char tempname[32];
	size_t namelen;
	cat_cookie_t cookie;
	int catlock = 0;
	int catreserve = 0;
	int started_tr = 0;
	int lockflags;
	int result;
	int orphanedlinks = 0;

	bzero(&cookie, sizeof(cookie));

	if (hfsmp->hfs_flags & HFS_CLEANED_ORPHANS)
		return;

	vcb = HFSTOVCB(hfsmp);
	fcb = VTOF(hfsmp->hfs_catalog_vp);

	btdata.bufferAddress = &filerec;
	btdata.itemSize = sizeof(filerec);
	btdata.itemCount = 1;

	MALLOC(iterator, struct BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	
	/* Build a key to "temp" */
	keyp = (HFSPlusCatalogKey*)&iterator->key;
	keyp->parentID = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
	keyp->nodeName.length = 4;  /* "temp" */
	keyp->keyLength = kHFSPlusCatalogKeyMinimumLength + keyp->nodeName.length * 2;
	keyp->nodeName.unicode[0] = 't';
	keyp->nodeName.unicode[1] = 'e';
	keyp->nodeName.unicode[2] = 'm';
	keyp->nodeName.unicode[3] = 'p';

	/*
	 * Position the iterator just before the first real temp file/dir.
	 */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
	(void) BTSearchRecord(fcb, iterator, NULL, NULL, iterator);
	hfs_systemfile_unlock(hfsmp, lockflags);

	/* Visit all the temp files/dirs in the HFS+ private directory. */
	for (;;) {
		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
		result = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (result)
			break;
		if (keyp->parentID != hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid)
			break;
		
		(void) utf8_encodestr(keyp->nodeName.unicode, keyp->nodeName.length * 2,
		                      (u_int8_t *)filename, &namelen, sizeof(filename), 0, 0);
		
		(void) snprintf(tempname, sizeof(tempname), "%s%d",
				HFS_DELETE_PREFIX, filerec.fileID);
		
		/*
		 * Delete all files (and directories) named "tempxxx", 
		 * where xxx is the file's cnid in decimal.
		 *
		 */
		if (bcmp(tempname, filename, namelen) == 0) {
   			struct filefork dfork;
    			struct filefork rfork;
  			struct cnode cnode;

			bzero(&dfork, sizeof(dfork));
			bzero(&rfork, sizeof(rfork));
			bzero(&cnode, sizeof(cnode));
			
			/* Delete any attributes, ignore errors */
			(void) hfs_removeallattr(hfsmp, filerec.fileID);
			
			if (hfs_start_transaction(hfsmp) != 0) {
			    printf("hfs_remove_orphans: failed to start transaction\n");
			    goto exit;
			}
			started_tr = 1;
		
			/*
			 * Reserve some space in the Catalog file.
			 */
			if (cat_preflight(hfsmp, CAT_DELETE, &cookie, p) != 0) {
			    printf("hfs_remove_orphans: cat_preflight failed\n");
				goto exit;
			}
			catreserve = 1;

			lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_ATTRIBUTE | SFL_EXTENTS | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
			catlock = 1;

			/* Build a fake cnode */
			cat_convertattr(hfsmp, (CatalogRecord *)&filerec, &cnode.c_attr,
			                &dfork.ff_data, &rfork.ff_data);
			cnode.c_desc.cd_parentcnid = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
			cnode.c_desc.cd_nameptr = (const u_int8_t *)filename;
			cnode.c_desc.cd_namelen = namelen;
			cnode.c_desc.cd_cnid = cnode.c_attr.ca_fileid;
			cnode.c_blocks = dfork.ff_blocks + rfork.ff_blocks;

			/* Position iterator at previous entry */
			if (BTIterateRecord(fcb, kBTreePrevRecord, iterator,
			    NULL, NULL) != 0) {
				break;
			}

			/* Truncate the file to zero (both forks) */
			if (dfork.ff_blocks > 0) {
				u_int64_t fsize;
				
				dfork.ff_cp = &cnode;
				cnode.c_datafork = &dfork;
				cnode.c_rsrcfork = NULL;
				fsize = (u_int64_t)dfork.ff_blocks * (u_int64_t)HFSTOVCB(hfsmp)->blockSize;
				while (fsize > 0) {
				    if (fsize > HFS_BIGFILE_SIZE && overflow_extents(&dfork)) {
						fsize -= HFS_BIGFILE_SIZE;
					} else {
						fsize = 0;
					}

					if (TruncateFileC(vcb, (FCB*)&dfork, fsize, false) != 0) {
						printf("error truncting data fork!\n");
						break;
					}

					//
					// if we're iteratively truncating this file down,
					// then end the transaction and start a new one so
					// that no one transaction gets too big.
					//
					if (fsize > 0 && started_tr) {
						/* Drop system file locks before starting 
						 * another transaction to preserve lock order.
						 */
						hfs_systemfile_unlock(hfsmp, lockflags);
						catlock = 0;
						hfs_end_transaction(hfsmp);

						if (hfs_start_transaction(hfsmp) != 0) {
							started_tr = 0;
							break;
						}
						lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG | SFL_ATTRIBUTE | SFL_EXTENTS | SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
						catlock = 1;
					}
				}
			}

			if (rfork.ff_blocks > 0) {
				rfork.ff_cp = &cnode;
				cnode.c_datafork = NULL;
				cnode.c_rsrcfork = &rfork;
				if (TruncateFileC(vcb, (FCB*)&rfork, 0, false) != 0) {
					printf("error truncting rsrc fork!\n");
					break;
				}
			}

			/* Remove the file or folder record from the Catalog */	
			if (cat_delete(hfsmp, &cnode.c_desc, &cnode.c_attr) != 0) {
				printf("hfs_remove_orphans: error deleting cat rec for id %d!\n", cnode.c_desc.cd_cnid);
				hfs_systemfile_unlock(hfsmp, lockflags);
				catlock = 0;
				hfs_volupdate(hfsmp, VOL_UPDATE, 0);
				break;
			}
			++orphanedlinks;

			/* Update parent and volume counts */	
			hfsmp->hfs_private_attr[FILE_HARDLINKS].ca_entries--;
			if (cnode.c_attr.ca_mode & S_IFDIR) {
				DEC_FOLDERCOUNT(hfsmp, hfsmp->hfs_private_attr[FILE_HARDLINKS]);
			}

			(void)cat_update(hfsmp, &hfsmp->hfs_private_desc[FILE_HARDLINKS],
			                 &hfsmp->hfs_private_attr[FILE_HARDLINKS], NULL, NULL);

			/* Drop locks and end the transaction */
			hfs_systemfile_unlock(hfsmp, lockflags);
			cat_postflight(hfsmp, &cookie, p);
			catlock = catreserve = 0;

			/* 
			   Now that Catalog is unlocked, update the volume info, making
			   sure to differentiate between files and directories
			*/
			if (cnode.c_attr.ca_mode & S_IFDIR) {
				hfs_volupdate(hfsmp, VOL_RMDIR, 0);
			}
			else{
 				hfs_volupdate(hfsmp, VOL_RMFILE, 0);
			}

			if (started_tr) {
				hfs_end_transaction(hfsmp);
				started_tr = 0;
			}

		} /* end if */
	} /* end for */
	if (orphanedlinks > 0)
		printf("HFS: Removed %d orphaned unlinked files or directories \n", orphanedlinks);
exit:
	if (catlock) {
		hfs_systemfile_unlock(hfsmp, lockflags);
	}
	if (catreserve) {
		cat_postflight(hfsmp, &cookie, p);
	}
	if (started_tr) {
		hfs_end_transaction(hfsmp);
	}

	FREE(iterator, M_TEMP);
	hfsmp->hfs_flags |= HFS_CLEANED_ORPHANS;
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

	if (vnode_issystem(vp)) {
		if (VTOF(vp)->fcbBTCBPtr != NULL) {
			BTreeInfoRec			bTreeInfo;
	
			/*
			 * We do not lock the BTrees, because if we are getting block..then the tree
			 * should be locked in the first place.
			 * We just want the nodeSize wich will NEVER change..so even if the world
			 * is changing..the nodeSize should remain the same. Which argues why lock
			 * it in the first place??
			 */
			
			(void) BTGetInformation	(VTOF(vp), kBTreeInfoVersion, &bTreeInfo);
					
			logBlockSize = bTreeInfo.nodeSize;

		} else if (VTOC(vp)->c_fileid == kHFSAllocationFileID) {
				logBlockSize = VTOVCB(vp)->vcbVBMIOSize;
		}
	}

	DBG_ASSERT(logBlockSize > 0);
	
	return logBlockSize;	
}

__private_extern__
u_int32_t
hfs_freeblks(struct hfsmount * hfsmp, int wantreserve)
{
	u_int32_t freeblks;
	u_int32_t rsrvblks;
	u_int32_t loanblks;

	/*
	 * We don't bother taking the mount lock
	 * to look at these values since the values
	 * themselves are each updated automically
	 * on aligned addresses.
	 */
	freeblks = hfsmp->freeBlocks;
	rsrvblks = hfsmp->reserveBlocks;
	loanblks = hfsmp->loanedBlocks;
	if (wantreserve) {
		if (freeblks > rsrvblks)
			freeblks -= rsrvblks;
		else
			freeblks = 0;
	}
	if (freeblks > loanblks)
		freeblks -= loanblks;
	else
		freeblks = 0;

#ifdef HFS_SPARSE_DEV
	/* 
	 * When the underlying device is sparse, check the
	 * available space on the backing store volume.
	 */
	if ((hfsmp->hfs_flags & HFS_HAS_SPARSE_DEVICE) && hfsmp->hfs_backingfs_rootvp) {
		struct vfsstatfs *vfsp;  /* 272 bytes */
		u_int64_t vfreeblks;
		u_int32_t loanedblks;
		struct mount * backingfs_mp;
		struct timeval now;

		backingfs_mp = vnode_mount(hfsmp->hfs_backingfs_rootvp);

		microtime(&now);
		if ((now.tv_sec - hfsmp->hfs_last_backingstatfs) >= 1) {
		    vfs_update_vfsstat(backingfs_mp, vfs_context_kernel(), VFS_KERNEL_EVENT);
		    hfsmp->hfs_last_backingstatfs = now.tv_sec;
		}

		if ((vfsp = vfs_statfs(backingfs_mp))) {
			HFS_MOUNT_LOCK(hfsmp, TRUE);
			vfreeblks = vfsp->f_bavail;
			/* Normalize block count if needed. */
			if (vfsp->f_bsize != hfsmp->blockSize) {
				vfreeblks = ((u_int64_t)vfreeblks * (u_int64_t)(vfsp->f_bsize)) / hfsmp->blockSize;
			}
			if (vfreeblks > (unsigned int)hfsmp->hfs_sparsebandblks)
				vfreeblks -= hfsmp->hfs_sparsebandblks;
			else
				vfreeblks = 0;
			
			/* Take into account any delayed allocations. */
			loanedblks = 2 * hfsmp->loanedBlocks;
			if (vfreeblks > loanedblks)
				vfreeblks -= loanedblks;
			else
				vfreeblks = 0;

			freeblks = MIN(vfreeblks, freeblks);
			HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		}
	}
#endif /* HFS_SPARSE_DEV */

	return (freeblks);
}

/*
 * Map HFS Common errors (negative) to BSD error codes (positive).
 * Positive errors (ie BSD errors) are passed through unchanged.
 */
short MacToVFSError(OSErr err)
{
	if (err >= 0)
        	return err;

	switch (err) {
	case dskFulErr:			/*    -34 */
	case btNoSpaceAvail:		/* -32733 */
		return ENOSPC;
	case fxOvFlErr:			/* -32750 */
		return EOVERFLOW;
	
	case btBadNode:			/* -32731 */
		return EIO;
	
	case memFullErr:		/*  -108 */
		return ENOMEM;		/*   +12 */
	
	case cmExists:			/* -32718 */
	case btExists:			/* -32734 */
		return EEXIST;		/*    +17 */
	
	case cmNotFound:		/* -32719 */
	case btNotFound:		/* -32735 */	
		return ENOENT;		/*     28 */
	
	case cmNotEmpty:		/* -32717 */
		return ENOTEMPTY;	/*     66 */
	
	case cmFThdDirErr:		/* -32714 */
		return EISDIR;		/*     21 */
	
	case fxRangeErr:		/* -32751 */
		return ERANGE;
	
	case bdNamErr:			/*   -37 */
		return ENAMETOOLONG;	/*    63 */
	
	case paramErr:			/*   -50 */
	case fileBoundsErr:		/* -1309 */
		return EINVAL;		/*   +22 */
	
	case fsBTBadNodeSize:
		return ENXIO;

	default:
		return EIO;		/*   +5 */
	}
}


/*
 * Find the current thread's directory hint for a given index.
 *
 * Requires an exclusive lock on directory cnode.
 *
 * Use detach if the cnode lock must be dropped while the hint is still active.
 */
__private_extern__
directoryhint_t *
hfs_getdirhint(struct cnode *dcp, int index, int detach)
{
	struct timeval tv;
	directoryhint_t *hint;
	boolean_t need_remove, need_init;
	const u_int8_t * name;

	microuptime(&tv);

	/*
	 *  Look for an existing hint first.  If not found, create a new one (when
	 *  the list is not full) or recycle the oldest hint.  Since new hints are
	 *  always added to the head of the list, the last hint is always the
	 *  oldest.
	 */
	TAILQ_FOREACH(hint, &dcp->c_hintlist, dh_link) {
		if (hint->dh_index == index)
			break;
	}
	if (hint != NULL) { /* found an existing hint */
		need_init = false;
		need_remove = true;
	} else { /* cannot find an existing hint */
		need_init = true;
		if (dcp->c_dirhintcnt < HFS_MAXDIRHINTS) { /* we don't need recycling */
			/* Create a default directory hint */
			MALLOC_ZONE(hint, directoryhint_t *, sizeof(directoryhint_t), M_HFSDIRHINT, M_WAITOK);
			++dcp->c_dirhintcnt;
			need_remove = false;
		} else {				/* recycle the last (i.e., the oldest) hint */
			hint = TAILQ_LAST(&dcp->c_hintlist, hfs_hinthead);
			if ((hint->dh_desc.cd_flags & CD_HASBUF) &&
			    (name = hint->dh_desc.cd_nameptr)) {
				hint->dh_desc.cd_nameptr = NULL;
				hint->dh_desc.cd_namelen = 0;
				hint->dh_desc.cd_flags &= ~CD_HASBUF;				
				vfs_removename((const char *)name);
			}
			need_remove = true;
		}
	}

	if (need_remove)
		TAILQ_REMOVE(&dcp->c_hintlist, hint, dh_link);

	if (detach)
		--dcp->c_dirhintcnt;
	else
		TAILQ_INSERT_HEAD(&dcp->c_hintlist, hint, dh_link);

	if (need_init) {
		hint->dh_index = index;
		hint->dh_desc.cd_flags = 0;
		hint->dh_desc.cd_encoding = 0;
		hint->dh_desc.cd_namelen = 0;
		hint->dh_desc.cd_nameptr = NULL;
		hint->dh_desc.cd_parentcnid = dcp->c_fileid;
		hint->dh_desc.cd_hint = dcp->c_childhint;
		hint->dh_desc.cd_cnid = 0;
	}
	hint->dh_time = tv.tv_sec;
	return (hint);
}

/*
 * Release a single directory hint.
 *
 * Requires an exclusive lock on directory cnode.
 */
__private_extern__
void
hfs_reldirhint(struct cnode *dcp, directoryhint_t * relhint)
{
	const u_int8_t * name;
	directoryhint_t *hint;

	/* Check if item is on list (could be detached) */
	TAILQ_FOREACH(hint, &dcp->c_hintlist, dh_link) {
		if (hint == relhint) {
			TAILQ_REMOVE(&dcp->c_hintlist, relhint, dh_link);
			--dcp->c_dirhintcnt;
			break;
		}
	}
	name = relhint->dh_desc.cd_nameptr;
	if ((relhint->dh_desc.cd_flags & CD_HASBUF) && (name != NULL)) {
		relhint->dh_desc.cd_nameptr = NULL;
		relhint->dh_desc.cd_namelen = 0;
		relhint->dh_desc.cd_flags &= ~CD_HASBUF;
		vfs_removename((const char *)name);
	}
	FREE_ZONE(relhint, sizeof(directoryhint_t), M_HFSDIRHINT);
}

/*
 * Release directory hints for given directory
 *
 * Requires an exclusive lock on directory cnode.
 */
__private_extern__
void
hfs_reldirhints(struct cnode *dcp, int stale_hints_only)
{
	struct timeval tv;
	directoryhint_t *hint, *prev;
	const u_int8_t * name;

	if (stale_hints_only)
		microuptime(&tv);

	/* searching from the oldest to the newest, so we can stop early when releasing stale hints only */
	for (hint = TAILQ_LAST(&dcp->c_hintlist, hfs_hinthead); hint != NULL; hint = prev) {
		if (stale_hints_only && (tv.tv_sec - hint->dh_time) < HFS_DIRHINT_TTL)
			break;  /* stop here if this entry is too new */
		name = hint->dh_desc.cd_nameptr;
		if ((hint->dh_desc.cd_flags & CD_HASBUF) && (name != NULL)) {
			hint->dh_desc.cd_nameptr = NULL;
			hint->dh_desc.cd_namelen = 0;
			hint->dh_desc.cd_flags &= ~CD_HASBUF;
			vfs_removename((const char *)name);
		}
		prev = TAILQ_PREV(hint, hfs_hinthead, dh_link); /* must save this pointer before calling FREE_ZONE on this node */
		TAILQ_REMOVE(&dcp->c_hintlist, hint, dh_link);
		FREE_ZONE(hint, sizeof(directoryhint_t), M_HFSDIRHINT);
		--dcp->c_dirhintcnt;
	}
}

/*
 * Insert a detached directory hint back into the list of dirhints.
 *
 * Requires an exclusive lock on directory cnode.
 */
__private_extern__
void
hfs_insertdirhint(struct cnode *dcp, directoryhint_t * hint)
{
	directoryhint_t *test;

	TAILQ_FOREACH(test, &dcp->c_hintlist, dh_link) {
		if (test == hint)
			panic("hfs_insertdirhint: hint %p already on list!", hint);
	}

	TAILQ_INSERT_HEAD(&dcp->c_hintlist, hint, dh_link);
	++dcp->c_dirhintcnt;
}

/*
 * Perform a case-insensitive compare of two UTF-8 filenames.
 *
 * Returns 0 if the strings match.
 */
__private_extern__
int
hfs_namecmp(const u_int8_t *str1, size_t len1, const u_int8_t *str2, size_t len2)
{
	u_int16_t *ustr1, *ustr2;
	size_t ulen1, ulen2;
	size_t maxbytes;
	int cmp = -1;

	if (len1 != len2)
		return (cmp);

	maxbytes = kHFSPlusMaxFileNameChars << 1;
	MALLOC(ustr1, u_int16_t *, maxbytes << 1, M_TEMP, M_WAITOK);
	ustr2 = ustr1 + (maxbytes >> 1);

	if (utf8_decodestr(str1, len1, ustr1, &ulen1, maxbytes, ':', 0) != 0)
		goto out;
	if (utf8_decodestr(str2, len2, ustr2, &ulen2, maxbytes, ':', 0) != 0)
		goto out;
	
	cmp = FastUnicodeCompare(ustr1, ulen1>>1, ustr2, ulen2>>1);
out:
	FREE(ustr1, M_TEMP);
	return (cmp);
}


__private_extern__
int
hfs_early_journal_init(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
					   void *_args, off_t embeddedOffset, daddr64_t mdb_offset,
					   HFSMasterDirectoryBlock *mdbp, kauth_cred_t cred)
{
	JournalInfoBlock *jibp;
	struct buf       *jinfo_bp, *bp;
	int               sectors_per_fsblock, arg_flags=0, arg_tbufsz=0;
	int               retval;
	uint32_t		  blksize = hfsmp->hfs_logical_block_size;
	struct vnode     *devvp;
	struct hfs_mount_args *args = _args;
	u_int32_t	  jib_flags;
	u_int64_t	  jib_offset;
	u_int64_t	  jib_size;
	
	devvp = hfsmp->hfs_devvp;

	if (args != NULL && (args->flags & HFSFSMNT_EXTENDED_ARGS)) {
		arg_flags  = args->journal_flags;
		arg_tbufsz = args->journal_tbuffer_size;
	}

	sectors_per_fsblock = SWAP_BE32(vhp->blockSize) / blksize;
				
	retval = (int)buf_meta_bread(devvp,
						(daddr64_t)((embeddedOffset/blksize) + 
						(SWAP_BE32(vhp->journalInfoBlock)*sectors_per_fsblock)),
						SWAP_BE32(vhp->blockSize), cred, &jinfo_bp);
	if (retval)
		return retval;

	jibp = (JournalInfoBlock *)buf_dataptr(jinfo_bp);
	jib_flags  = SWAP_BE32(jibp->flags);
	jib_offset = SWAP_BE64(jibp->offset);
	jib_size   = SWAP_BE64(jibp->size);

	if (jib_flags & kJIJournalInFSMask) {
		hfsmp->jvp = hfsmp->hfs_devvp;
	} else {
		printf("hfs: journal not stored in fs! don't know what to do.\n");
		buf_brelse(jinfo_bp);
		return EINVAL;
	}

	// save this off for the hack-y check in hfs_remove()
	hfsmp->jnl_start = jib_offset / SWAP_BE32(vhp->blockSize);
	hfsmp->jnl_size  = jib_size;

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) && (vfs_flags(hfsmp->hfs_mp) & MNT_ROOTFS) == 0) {
	    // if the file system is read-only, check if the journal is empty.
	    // if it is, then we can allow the mount.  otherwise we have to
	    // return failure.
	    retval = journal_is_clean(hfsmp->jvp,
		                      jib_offset + embeddedOffset,
				      jib_size,
				      devvp,
		                      hfsmp->hfs_logical_block_size);

	    hfsmp->jnl = NULL;

	    buf_brelse(jinfo_bp);

	    if (retval) {
	      printf("hfs: early journal init: volume on %s is read-only and journal is dirty.  Can not mount volume.\n",
                     vnode_name(devvp));
	    }

	    return retval;
	}

	if (jib_flags & kJIJournalNeedInitMask) {
		printf("hfs: Initializing the journal (joffset 0x%llx sz 0x%llx)...\n",
			   jib_offset + embeddedOffset, jib_size);
		hfsmp->jnl = journal_create(hfsmp->jvp,
									jib_offset + embeddedOffset,
									jib_size,
									devvp,
									blksize,
									arg_flags,
									arg_tbufsz,
									hfs_sync_metadata, hfsmp->hfs_mp);

		// no need to start a transaction here... if this were to fail
		// we'd just re-init it on the next mount.
		jib_flags &= ~kJIJournalNeedInitMask;
		jibp->flags  = SWAP_BE32(jib_flags);
		buf_bwrite(jinfo_bp);
		jinfo_bp = NULL;
		jibp     = NULL;
	} else { 
		//printf("hfs: Opening the journal (joffset 0x%llx sz 0x%llx vhp_blksize %d)...\n",
		//	   jib_offset + embeddedOffset,
		//	   jib_size, SWAP_BE32(vhp->blockSize));
				
		hfsmp->jnl = journal_open(hfsmp->jvp,
								  jib_offset + embeddedOffset,
								  jib_size,
								  devvp,
								  blksize,
								  arg_flags,
								  arg_tbufsz,
								  hfs_sync_metadata, hfsmp->hfs_mp);

		buf_brelse(jinfo_bp);
		jinfo_bp = NULL;
		jibp     = NULL;

		if (hfsmp->jnl && mdbp) {
			// reload the mdb because it could have changed
			// if the journal had to be replayed.
			if (mdb_offset == 0) {
				mdb_offset = (daddr64_t)((embeddedOffset / blksize) + HFS_PRI_SECTOR(blksize));
			}
			retval = (int)buf_meta_bread(devvp, 
					HFS_PHYSBLK_ROUNDDOWN(mdb_offset, hfsmp->hfs_log_per_phys),
					hfsmp->hfs_physical_block_size, cred, &bp);
			if (retval) {
				buf_brelse(bp);
				printf("hfs: failed to reload the mdb after opening the journal (retval %d)!\n",
					   retval);
				return retval;
			}
			bcopy((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(hfsmp->hfs_physical_block_size), mdbp, 512);
			buf_brelse(bp);
			bp = NULL;
		}
	}


	//printf("journal @ 0x%x\n", hfsmp->jnl);
	
	// if we expected the journal to be there and we couldn't
	// create it or open it then we have to bail out.
	if (hfsmp->jnl == NULL) {
		printf("hfs: early jnl init: failed to open/create the journal (retval %d).\n", retval);
		return EINVAL;
	}

	return 0;
}


//
// This function will go and re-locate the .journal_info_block and
// the .journal files in case they moved (which can happen if you
// run Norton SpeedDisk).  If we fail to find either file we just
// disable journaling for this volume and return.  We turn off the
// journaling bit in the vcb and assume it will get written to disk
// later (if it doesn't on the next mount we'd do the same thing
// again which is harmless).  If we disable journaling we don't
// return an error so that the volume is still mountable.
//
// If the info we find for the .journal_info_block and .journal files
// isn't what we had stored, we re-set our cached info and proceed
// with opening the journal normally.
//
static int
hfs_late_journal_init(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp, void *_args)
{
	JournalInfoBlock *jibp;
	struct buf       *jinfo_bp;
	int               sectors_per_fsblock, arg_flags=0, arg_tbufsz=0;
	int               retval, write_jibp = 0, recreate_journal = 0;
	struct vnode     *devvp;
	struct cat_attr   jib_attr, jattr;
	struct cat_fork   jib_fork, jfork;
	ExtendedVCB      *vcb;
	u_long            fid;
	struct hfs_mount_args *args = _args;
	u_int32_t	  jib_flags;
	u_int64_t	  jib_offset;
	u_int64_t	  jib_size;
	
	devvp = hfsmp->hfs_devvp;
	vcb = HFSTOVCB(hfsmp);
	
	if (args != NULL && (args->flags & HFSFSMNT_EXTENDED_ARGS)) {
		if (args->journal_disable) {
			return 0;
		}

		arg_flags  = args->journal_flags;
		arg_tbufsz = args->journal_tbuffer_size;
	}

	fid = GetFileInfo(vcb, kRootDirID, ".journal_info_block", &jib_attr, &jib_fork);
	if (fid == 0 || jib_fork.cf_extents[0].startBlock == 0 || jib_fork.cf_size == 0) {
		printf("hfs: can't find the .journal_info_block! disabling journaling (start: %d).\n",
			   jib_fork.cf_extents[0].startBlock);
		vcb->vcbAtrb &= ~kHFSVolumeJournaledMask;
		return 0;
	}
	hfsmp->hfs_jnlinfoblkid = fid;

	// make sure the journal_info_block begins where we think it should.
	if (SWAP_BE32(vhp->journalInfoBlock) != jib_fork.cf_extents[0].startBlock) {
		printf("hfs: The journal_info_block moved (was: %d; is: %d).  Fixing up\n",
			   SWAP_BE32(vhp->journalInfoBlock), jib_fork.cf_extents[0].startBlock);

		vcb->vcbJinfoBlock    = jib_fork.cf_extents[0].startBlock;
		vhp->journalInfoBlock = SWAP_BE32(jib_fork.cf_extents[0].startBlock);
		recreate_journal = 1;
	}


	sectors_per_fsblock = SWAP_BE32(vhp->blockSize) / hfsmp->hfs_logical_block_size;
	retval = (int)buf_meta_bread(devvp,
						(daddr64_t)(vcb->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size + 
						(SWAP_BE32(vhp->journalInfoBlock)*sectors_per_fsblock)),
						SWAP_BE32(vhp->blockSize), NOCRED, &jinfo_bp);
	if (retval) {
		printf("hfs: can't read journal info block. disabling journaling.\n");
		vcb->vcbAtrb &= ~kHFSVolumeJournaledMask;
		return 0;
	}

	jibp = (JournalInfoBlock *)buf_dataptr(jinfo_bp);
	jib_flags  = SWAP_BE32(jibp->flags);
	jib_offset = SWAP_BE64(jibp->offset);
	jib_size   = SWAP_BE64(jibp->size);

	fid = GetFileInfo(vcb, kRootDirID, ".journal", &jattr, &jfork);
	if (fid == 0 || jfork.cf_extents[0].startBlock == 0 || jfork.cf_size == 0) {
		printf("hfs: can't find the journal file! disabling journaling (start: %d)\n",
			   jfork.cf_extents[0].startBlock);
		buf_brelse(jinfo_bp);
		vcb->vcbAtrb &= ~kHFSVolumeJournaledMask;
		return 0;
	}
	hfsmp->hfs_jnlfileid = fid;

	// make sure the journal file begins where we think it should.
	if ((jib_offset / (u_int64_t)vcb->blockSize) != jfork.cf_extents[0].startBlock) {
		printf("hfs: The journal file moved (was: %lld; is: %d).  Fixing up\n",
			   (jib_offset / (u_int64_t)vcb->blockSize), jfork.cf_extents[0].startBlock);

		jib_offset = (u_int64_t)jfork.cf_extents[0].startBlock * (u_int64_t)vcb->blockSize;
		write_jibp   = 1;
		recreate_journal = 1;
	}

	// check the size of the journal file.
	if (jib_size != (u_int64_t)jfork.cf_extents[0].blockCount*vcb->blockSize) {
		printf("hfs: The journal file changed size! (was %lld; is %lld).  Fixing up.\n",
			   jib_size, (u_int64_t)jfork.cf_extents[0].blockCount*vcb->blockSize);
		
		jib_size = (u_int64_t)jfork.cf_extents[0].blockCount * vcb->blockSize;
		write_jibp = 1;
		recreate_journal = 1;
	}
	
	if (jib_flags & kJIJournalInFSMask) {
		hfsmp->jvp = hfsmp->hfs_devvp;
	} else {
		printf("hfs: journal not stored in fs! don't know what to do.\n");
		buf_brelse(jinfo_bp);
		return EINVAL;
	}

	// save this off for the hack-y check in hfs_remove()
	hfsmp->jnl_start = jib_offset / SWAP_BE32(vhp->blockSize);
	hfsmp->jnl_size  = jib_size;

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) && (vfs_flags(hfsmp->hfs_mp) & MNT_ROOTFS) == 0) {
	    // if the file system is read-only, check if the journal is empty.
	    // if it is, then we can allow the mount.  otherwise we have to
	    // return failure.
	    retval = journal_is_clean(hfsmp->jvp,
		                      jib_offset + (off_t)vcb->hfsPlusIOPosOffset,
				      jib_size,
				      devvp,
		                      hfsmp->hfs_logical_block_size);

	    hfsmp->jnl = NULL;

	    buf_brelse(jinfo_bp);

	    if (retval) {
	      printf("hfs: late journal init: volume on %s is read-only and journal is dirty.  Can not mount volume.\n",
		     vnode_name(devvp));
	    }

	    return retval;
	}

	if ((jib_flags & kJIJournalNeedInitMask) || recreate_journal) {
		printf("hfs: Initializing the journal (joffset 0x%llx sz 0x%llx)...\n",
			   jib_offset + (off_t)vcb->hfsPlusIOPosOffset, jib_size);
		hfsmp->jnl = journal_create(hfsmp->jvp,
									jib_offset + (off_t)vcb->hfsPlusIOPosOffset,
									jib_size,
									devvp,
									hfsmp->hfs_logical_block_size,
									arg_flags,
									arg_tbufsz,
									hfs_sync_metadata, hfsmp->hfs_mp);

		// no need to start a transaction here... if this were to fail
		// we'd just re-init it on the next mount.
		jib_flags &= ~kJIJournalNeedInitMask;
		write_jibp   = 1;

	} else { 
		//
		// if we weren't the last person to mount this volume
		// then we need to throw away the journal because it
		// is likely that someone else mucked with the disk.
		// if the journal is empty this is no big deal.  if the
		// disk is dirty this prevents us from replaying the
		// journal over top of changes that someone else made.
		//
		arg_flags |= JOURNAL_RESET;
		
		//printf("hfs: Opening the journal (joffset 0x%llx sz 0x%llx vhp_blksize %d)...\n",
		//	   jib_offset + (off_t)vcb->hfsPlusIOPosOffset,
		//	   jib_size, SWAP_BE32(vhp->blockSize));
				
		hfsmp->jnl = journal_open(hfsmp->jvp,
								  jib_offset + (off_t)vcb->hfsPlusIOPosOffset,
								  jib_size,
								  devvp,
								  hfsmp->hfs_logical_block_size,
								  arg_flags,
								  arg_tbufsz,
								  hfs_sync_metadata, hfsmp->hfs_mp);
	}
			

	if (write_jibp) {
		jibp->flags  = SWAP_BE32(jib_flags);
		jibp->offset = SWAP_BE64(jib_offset);
		jibp->size   = SWAP_BE64(jib_size);

		buf_bwrite(jinfo_bp);
	} else {
		buf_brelse(jinfo_bp);
	} 
	jinfo_bp = NULL;
	jibp     = NULL;

	//printf("journal @ 0x%x\n", hfsmp->jnl);
	
	// if we expected the journal to be there and we couldn't
	// create it or open it then we have to bail out.
	if (hfsmp->jnl == NULL) {
		printf("hfs: late jnl init: failed to open/create the journal (retval %d).\n", retval);
		return EINVAL;
	}

	return 0;
}

/*
 * Calculate the allocation zone for metadata.
 *
 * This zone includes the following:
 *	Allocation Bitmap file
 *	Overflow Extents file
 *	Journal file
 *	Quota files
 *	Clustered Hot files
 *	Catalog file
 *
 *                          METADATA ALLOCATION ZONE
 * ____________________________________________________________________________
 * |    |    |     |               |                              |           |
 * | BM | JF | OEF |    CATALOG    |--->                          | HOT FILES |
 * |____|____|_____|_______________|______________________________|___________|
 *
 * <------------------------------- N * 128 MB ------------------------------->
 *
 */
#define GIGABYTE  (u_int64_t)(1024*1024*1024)

#define OVERFLOW_DEFAULT_SIZE (4*1024*1024)
#define OVERFLOW_MAXIMUM_SIZE (128*1024*1024)
#define JOURNAL_DEFAULT_SIZE  (8*1024*1024)
#define JOURNAL_MAXIMUM_SIZE  (512*1024*1024)
#define HOTBAND_MINIMUM_SIZE  (10*1024*1024)
#define HOTBAND_MAXIMUM_SIZE  (512*1024*1024)

static void
hfs_metadatazone_init(struct hfsmount *hfsmp)
{
	ExtendedVCB  *vcb;
	u_int64_t  fs_size;
	u_int64_t  zonesize;
	u_int64_t  temp;
	u_int64_t  filesize;
	u_int32_t  blk;
	int  items;

	vcb = HFSTOVCB(hfsmp);
	fs_size = (u_int64_t)vcb->blockSize * (u_int64_t)vcb->totalBlocks;

	/*
	 * For volumes less than 10 GB, don't bother.
	 */
	if (fs_size < ((u_int64_t)10 * GIGABYTE))
		return;
	/*
	 * Skip non-journaled volumes as well.
	 */
	if (hfsmp->jnl == NULL)
		return;

	/*
	 * Start with allocation bitmap (a fixed size).
	 */
	zonesize = roundup(vcb->totalBlocks / 8, vcb->vcbVBMIOSize);

	/*
	 * Overflow Extents file gets 4 MB per 100 GB.
	 */
	items = fs_size / ((u_int64_t)100 * GIGABYTE);
	filesize = (u_int64_t)(items + 1) * OVERFLOW_DEFAULT_SIZE;
	if (filesize > OVERFLOW_MAXIMUM_SIZE)
		filesize = OVERFLOW_MAXIMUM_SIZE;
	zonesize += filesize;
	hfsmp->hfs_overflow_maxblks = filesize / vcb->blockSize;

	/*
	 * Plan for at least 8 MB of journal for each
	 * 100 GB of disk space (up to a 512 MB).
	 */
	items = fs_size / ((u_int64_t)100 * GIGABYTE);
	filesize = (u_int64_t)(items + 1) * JOURNAL_DEFAULT_SIZE;
	if (filesize > JOURNAL_MAXIMUM_SIZE)
		filesize = JOURNAL_MAXIMUM_SIZE;
	zonesize += filesize;

	/*
	 * Catalog file gets 10 MB per 1 GB.
	 *
	 * How about considering the current catalog size (used nodes * node size)
	 * and the current file data size to help estimate the required
	 * catalog size.
	 */
	filesize = MIN((fs_size / 1024) * 10, GIGABYTE);
	hfsmp->hfs_catalog_maxblks = filesize / vcb->blockSize;
	zonesize += filesize;

	/*
	 * Add space for hot file region.
	 *
	 * ...for now, use 5 MB per 1 GB (0.5 %)
	 */
	filesize = (fs_size / 1024) * 5;
	if (filesize > HOTBAND_MAXIMUM_SIZE)
		filesize = HOTBAND_MAXIMUM_SIZE;
	else if (filesize < HOTBAND_MINIMUM_SIZE)
		filesize = HOTBAND_MINIMUM_SIZE;
	/*
	 * Calculate user quota file requirements.
	 */
	items = QF_USERS_PER_GB * (fs_size / GIGABYTE);
	if (items < QF_MIN_USERS)
		items = QF_MIN_USERS;
	else if (items > QF_MAX_USERS)
		items = QF_MAX_USERS;
	if (!powerof2(items)) {
		int x = items;
		items = 4;
		while (x>>1 != 1) {
			x = x >> 1;
			items = items << 1;
		}
	}
	filesize += (items + 1) * sizeof(struct dqblk);
	/*
	 * Calculate group quota file requirements.
	 *
	 */
	items = QF_GROUPS_PER_GB * (fs_size / GIGABYTE);
	if (items < QF_MIN_GROUPS)
		items = QF_MIN_GROUPS;
	else if (items > QF_MAX_GROUPS)
		items = QF_MAX_GROUPS;
	if (!powerof2(items)) {
		int x = items;
		items = 4;
		while (x>>1 != 1) {
			x = x >> 1;
			items = items << 1;
		}
	}
	filesize += (items + 1) * sizeof(struct dqblk);
	zonesize += filesize;

	/*
	 * Round up entire zone to a bitmap block's worth.
	 * The extra space goes to the catalog file and hot file area.
	 */
	temp = zonesize;
	zonesize = roundup(zonesize, (u_int64_t)vcb->vcbVBMIOSize * 8 * vcb->blockSize);
	temp = zonesize - temp;  /* temp has extra space */
	filesize += temp / 3;
	hfsmp->hfs_catalog_maxblks += (temp - (temp / 3)) / vcb->blockSize;

	hfsmp->hfs_hotfile_maxblks = filesize / vcb->blockSize;

	/* Convert to allocation blocks. */
	blk = zonesize / vcb->blockSize;

	/* The default metadata zone location is at the start of volume. */
	hfsmp->hfs_metazone_start = 1;
	hfsmp->hfs_metazone_end = blk - 1;
	
	/* The default hotfile area is at the end of the zone. */
	hfsmp->hfs_hotfile_start = blk - (filesize / vcb->blockSize);
	hfsmp->hfs_hotfile_end = hfsmp->hfs_metazone_end;
	hfsmp->hfs_hotfile_freeblks = hfs_hotfile_freeblocks(hfsmp);
#if 0
	printf("HFS: metadata zone is %d to %d\n", hfsmp->hfs_metazone_start, hfsmp->hfs_metazone_end);
	printf("HFS: hot file band is %d to %d\n", hfsmp->hfs_hotfile_start, hfsmp->hfs_hotfile_end);
	printf("HFS: hot file band free blocks = %d\n", hfsmp->hfs_hotfile_freeblks);
#endif
	hfsmp->hfs_flags |= HFS_METADATA_ZONE;
}


static u_int32_t
hfs_hotfile_freeblocks(struct hfsmount *hfsmp)
{
	ExtendedVCB  *vcb = HFSTOVCB(hfsmp);
	int  lockflags;
	int  freeblocks;

	lockflags = hfs_systemfile_lock(hfsmp, SFL_BITMAP, HFS_EXCLUSIVE_LOCK);
	freeblocks = MetaZoneFreeBlocks(vcb);
	hfs_systemfile_unlock(hfsmp, lockflags);

	/* Minus Extents overflow file reserve. */
	freeblocks -=
		hfsmp->hfs_overflow_maxblks - VTOF(hfsmp->hfs_extents_vp)->ff_blocks;
	/* Minus catalog file reserve. */
	freeblocks -=
		hfsmp->hfs_catalog_maxblks - VTOF(hfsmp->hfs_catalog_vp)->ff_blocks;
	if (freeblocks < 0)
		freeblocks = 0;

	return MIN(freeblocks, hfsmp->hfs_hotfile_maxblks);
}

/*
 * Determine if a file is a "virtual" metadata file.
 * This includes journal and quota files.
 */
__private_extern__
int
hfs_virtualmetafile(struct cnode *cp)
{
	const char * filename;


	if (cp->c_parentcnid != kHFSRootFolderID)
		return (0);

	filename = (const char *)cp->c_desc.cd_nameptr;
	if (filename == NULL)
		return (0);

	if ((strncmp(filename, ".journal", sizeof(".journal")) == 0) ||
	    (strncmp(filename, ".journal_info_block", sizeof(".journal_info_block")) == 0) ||
	    (strncmp(filename, ".quota.user", sizeof(".quota.user")) == 0) ||
	    (strncmp(filename, ".quota.group", sizeof(".quota.group")) == 0) ||
	    (strncmp(filename, ".hotfiles.btree", sizeof(".hotfiles.btree")) == 0))
		return (1);

	return (0);
}



//
// Fire off a timed callback to sync the disk if the
// volume is on ejectable media.
//
 __private_extern__
void
hfs_sync_ejectable(struct hfsmount *hfsmp)
{
	if (hfsmp->hfs_syncer)	{
		uint32_t secs, usecs;
		uint64_t now;

		clock_get_calendar_microtime(&secs, &usecs);
		now = ((uint64_t)secs * 1000000) + usecs;

		if (hfsmp->hfs_sync_scheduled == 0) {
			uint64_t deadline;

			hfsmp->hfs_last_sync_request_time = now;

			clock_interval_to_deadline(HFS_META_DELAY, HFS_MILLISEC_SCALE, &deadline);

			/*
			 * Increment hfs_sync_scheduled on the assumption that we're the
			 * first thread to schedule the timer.  If some other thread beat
			 * us, then we'll decrement it.  If we *were* the first to
			 * schedule the timer, then we need to keep track that the
			 * callback is waiting to complete.
			 */
			OSIncrementAtomic((volatile SInt32 *)&hfsmp->hfs_sync_scheduled);
			if (thread_call_enter_delayed(hfsmp->hfs_syncer, deadline))
				OSDecrementAtomic((volatile SInt32 *)&hfsmp->hfs_sync_scheduled);
			else
				OSIncrementAtomic((volatile SInt32 *)&hfsmp->hfs_sync_incomplete);
		}		
	}
}


__private_extern__
int
hfs_start_transaction(struct hfsmount *hfsmp)
{
	int ret, unlock_on_err=0;
	void * thread = current_thread();

#ifdef HFS_CHECK_LOCK_ORDER
	/*
	 * You cannot start a transaction while holding a system
	 * file lock. (unless the transaction is nested.)
	 */
	if (hfsmp->jnl && journal_owner(hfsmp->jnl) != thread) {
		if (hfsmp->hfs_catalog_cp && hfsmp->hfs_catalog_cp->c_lockowner == thread) {
			panic("hfs_start_transaction: bad lock order (cat before jnl)\n");
		}
		if (hfsmp->hfs_attribute_cp && hfsmp->hfs_attribute_cp->c_lockowner == thread) {
			panic("hfs_start_transaction: bad lock order (attr before jnl)\n");
		}
		if (hfsmp->hfs_extents_cp && hfsmp->hfs_extents_cp->c_lockowner == thread) {
			panic("hfs_start_transaction: bad lock order (ext before jnl)\n");
		}
	}
#endif /* HFS_CHECK_LOCK_ORDER */

    if (hfsmp->jnl == NULL || journal_owner(hfsmp->jnl) != thread) {
	lck_rw_lock_shared(&hfsmp->hfs_global_lock);
	OSAddAtomic(1, (SInt32 *)&hfsmp->hfs_active_threads);
	unlock_on_err = 1;
    }

	/* If a downgrade to read-only mount is in progress, no other
	 * process than the downgrade process is allowed to modify 
	 * the file system.
	 */
	if ((hfsmp->hfs_flags & HFS_RDONLY_DOWNGRADE) && 
			(hfsmp->hfs_downgrading_proc != thread)) {
		ret = EROFS;
		goto out;
	}

    if (hfsmp->jnl) {
	ret = journal_start_transaction(hfsmp->jnl);
	if (ret == 0) {
	    OSAddAtomic(1, (SInt32 *)&hfsmp->hfs_global_lock_nesting);
	}
    } else {
	ret = 0;
    }

out:
    if (ret != 0 && unlock_on_err) {
	lck_rw_unlock_shared(&hfsmp->hfs_global_lock);
	OSAddAtomic(-1, (SInt32 *)&hfsmp->hfs_active_threads);
    }

    return ret;
}

__private_extern__
int
hfs_end_transaction(struct hfsmount *hfsmp)
{
    int need_unlock=0, ret;

    if (    hfsmp->jnl == NULL
	|| (   journal_owner(hfsmp->jnl) == current_thread()
	    && (OSAddAtomic(-1, (SInt32 *)&hfsmp->hfs_global_lock_nesting) == 1)) ) {

	    need_unlock = 1;
    } 

    if (hfsmp->jnl) {
	ret = journal_end_transaction(hfsmp->jnl);
    } else {
	ret = 0;
    }

    if (need_unlock) {
	OSAddAtomic(-1, (SInt32 *)&hfsmp->hfs_active_threads);
	lck_rw_unlock_shared(&hfsmp->hfs_global_lock);
	hfs_sync_ejectable(hfsmp);
    }

    return ret;
}
