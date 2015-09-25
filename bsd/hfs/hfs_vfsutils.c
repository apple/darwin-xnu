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
#include <sys/mount_internal.h>
#include <sys/buf.h>
#include <sys/buf_internal.h>
#include <sys/ubc.h>
#include <sys/unistd.h>
#include <sys/utfconv.h>
#include <sys/kauth.h>
#include <sys/fcntl.h>
#include <sys/fsctl.h>
#include <sys/vnode_internal.h>
#include <kern/clock.h>
#include <stdbool.h>

#include <libkern/OSAtomic.h>

/* for parsing boot-args */
#include <pexpert/pexpert.h>

#if CONFIG_PROTECT
#include <sys/cprotect.h>
#endif

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

/* Enable/disable debugging code for live volume resizing, defined in hfs_resize.c */
extern int hfs_resize_debug;

static void ReleaseMetaFileVNode(struct vnode *vp);
static int  hfs_late_journal_init(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp, void *_args);

static u_int32_t hfs_hotfile_freeblocks(struct hfsmount *);
static void hfs_thaw_locked(struct hfsmount *hfsmp);

#define HFS_MOUNT_DEBUG 1


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

#if CONFIG_HFS_STD
OSErr hfs_MountHFSVolume(struct hfsmount *hfsmp, HFSMasterDirectoryBlock *mdb,
		__unused struct proc *p)
{
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	int error;
	ByteCount utf8chars;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	struct cat_fork fork;
	int newvnode_flags = 0;

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
	vcb->hfs_itime		= to_bsd_time(LocalToUTC(SWAP_BE32(mdb->drCrDate)));
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
	if (error || (utf8chars == 0)) {
		error = mac_roman_to_utf8(mdb->drVN, NAME_MAX, &utf8chars, vcb->vcbVN);
		/* If we fail to encode to UTF8 from Mac Roman, the name is bad.  Deny the mount */
		if (error) {
			goto MtVolErr;
		}
	}

	hfsmp->hfs_logBlockSize = BestBlockSizeFit(vcb->blockSize, MAXBSIZE, hfsmp->hfs_logical_block_size);
	vcb->vcbVBMIOSize = kHFSBlockSize;

	/* Generate the partition-based AVH location */
	hfsmp->hfs_partition_avh_sector = HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size,
	                                          hfsmp->hfs_logical_block_count);
	
	/* HFS standard is read-only, so just stuff the FS location in here, too */
	hfsmp->hfs_fs_avh_sector = hfsmp->hfs_partition_avh_sector;	

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
	                        &hfsmp->hfs_extents_vp, &newvnode_flags);
	if (error) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfs (std): error creating Ext Vnode (%d) \n", error);
		}
		goto MtVolErr;
	}
	error = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_extents_vp),
	                                 (KeyCompareProcPtr)CompareExtentKeys));
	if (error) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfs (std): error opening Ext Vnode (%d) \n", error);
		}
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
	                        &hfsmp->hfs_catalog_vp, &newvnode_flags);
	if (error) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfs (std): error creating catalog Vnode (%d) \n", error);
		}
		hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
		goto MtVolErr;
	}
	error = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_catalog_vp),
	                                 (KeyCompareProcPtr)CompareCatalogKeys));
	if (error) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfs (std): error opening catalog Vnode (%d) \n", error);
		}
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
	                         &hfsmp->hfs_allocation_vp, &newvnode_flags);
	if (error) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfs (std): error creating bitmap Vnode (%d) \n", error);
		}
		hfs_unlock(VTOC(hfsmp->hfs_catalog_vp));
		hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
		goto MtVolErr;
	}
	hfsmp->hfs_allocation_cp = VTOC(hfsmp->hfs_allocation_vp);

      	/* mark the volume dirty (clear clean unmount bit) */
	vcb->vcbAtrb &=	~kHFSVolumeUnmountedMask;

    if (error == noErr) {
		error = cat_idlookup(hfsmp, kHFSRootFolderID, 0, 0, NULL, NULL, NULL);
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfs (std): error looking up root folder (%d) \n", error);
		}
	}
	
    if (error == noErr) {
		/* If the disk isn't write protected.. */
        if ( !(vcb->vcbAtrb & kHFSVolumeHardwareLockMask)) {
            MarkVCBDirty (vcb); //	mark VCB dirty so it will be written
		}
	}
	
	/*
	 * all done with system files so we can unlock now...
	 */
	hfs_unlock(VTOC(hfsmp->hfs_allocation_vp));
	hfs_unlock(VTOC(hfsmp->hfs_catalog_vp));
	hfs_unlock(VTOC(hfsmp->hfs_extents_vp));
	
	if (error == noErr) {
		/* If successful, then we can just return once we've unlocked the cnodes */
		return error;
	}

    //--	Release any resources allocated so far before exiting with an error:
MtVolErr:
	hfsUnmount(hfsmp, NULL);

    return (error);
}

#endif

//*******************************************************************************
//
// Sanity check Volume Header Block:
//		Input argument *vhp is a pointer to a HFSPlusVolumeHeader block that has
//		not been endian-swapped and represents the on-disk contents of this sector.
//		This routine will not change the endianness of vhp block.
//
//*******************************************************************************
OSErr hfs_ValidateHFSPlusVolumeHeader(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp)
{
	u_int16_t signature;
	u_int16_t hfs_version;
	u_int32_t blockSize;

	signature = SWAP_BE16(vhp->signature);
	hfs_version = SWAP_BE16(vhp->version);

	if (signature == kHFSPlusSigWord) {
		if (hfs_version != kHFSPlusVersion) {
			printf("hfs_ValidateHFSPlusVolumeHeader: invalid HFS+ version: %x\n", hfs_version);
			return (EINVAL);
		}
	} else if (signature == kHFSXSigWord) {
		if (hfs_version != kHFSXVersion) {
			printf("hfs_ValidateHFSPlusVolumeHeader: invalid HFSX version: %x\n", hfs_version);
			return (EINVAL);
		}
	} else {
		/* Removed printf for invalid HFS+ signature because it gives
		 * false error for UFS root volume
		 */
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_ValidateHFSPlusVolumeHeader: unknown Volume Signature : %x\n", signature);
		}
		return (EINVAL);
	}

	/* Block size must be at least 512 and a power of 2 */
	blockSize = SWAP_BE32(vhp->blockSize);
	if (blockSize < 512 || !powerof2(blockSize)) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_ValidateHFSPlusVolumeHeader: invalid blocksize (%d) \n", blockSize);
		}
		return (EINVAL);
	}

	if (blockSize < hfsmp->hfs_logical_block_size) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_ValidateHFSPlusVolumeHeader: invalid physical blocksize (%d), hfs_logical_blocksize (%d) \n",
					blockSize, hfsmp->hfs_logical_block_size);
		}
		return (EINVAL);
	}
	return 0;
}

//*******************************************************************************
//	Routine:	hfs_MountHFSPlusVolume
//
//
//*******************************************************************************

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
	int newvnode_flags = 0;
	int  i;
	OSErr retval;
	char converted_volname[256];
	size_t volname_length = 0;
	size_t conv_volname_length = 0;

	signature = SWAP_BE16(vhp->signature);
	hfs_version = SWAP_BE16(vhp->version);

	retval = hfs_ValidateHFSPlusVolumeHeader(hfsmp, vhp);
	if (retval)
		return retval;

	if (signature == kHFSXSigWord) {
		/* The in-memory signature is always 'H+'. */
		signature = kHFSPlusSigWord;
		hfsmp->hfs_flags |= HFS_X;
	}

	blockSize = SWAP_BE32(vhp->blockSize);
	/* don't mount a writable volume if its dirty, it must be cleaned by fsck_hfs */
	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0 && hfsmp->jnl == NULL &&
	    (SWAP_BE32(vhp->attributes) & kHFSVolumeUnmountedMask) == 0) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfsplus: cannot mount dirty non-journaled volumes\n");
		}
		return (EINVAL);
	}

	/* Make sure we can live with the physical block size. */
	if ((disksize & (hfsmp->hfs_logical_block_size - 1)) ||
	    (embeddedOffset & (hfsmp->hfs_logical_block_size - 1))) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfsplus: hfs_logical_blocksize (%d) \n",
					hfsmp->hfs_logical_block_size);
		}
		return (ENXIO);
	}

	/*
	 * If allocation block size is less than the physical block size,
	 * same data could be cached in two places and leads to corruption.
	 *
	 * HFS Plus reserves one allocation block for the Volume Header.
	 * If the physical size is larger, then when we read the volume header,
	 * we will also end up reading in the next allocation block(s).
	 * If those other allocation block(s) is/are modified, and then the volume
	 * header is modified, the write of the volume header's buffer will write
	 * out the old contents of the other allocation blocks.
	 *
	 * We assume that the physical block size is same as logical block size.
	 * The physical block size value is used to round down the offsets for
	 * reading and writing the primary and alternate volume headers.
	 *
	 * The same logic to ensure good hfs_physical_block_size is also in
	 * hfs_mountfs so that hfs_mountfs, hfs_MountHFSPlusVolume and
	 * later are doing the I/Os using same block size.
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
	 *
	 * Note that there may be spare sectors beyond the end of the filesystem that still 
	 * belong to our partition. 
	 */

	spare_sectors = hfsmp->hfs_logical_block_count -
	                (((daddr64_t)vcb->totalBlocks * blockSize) /
	                   hfsmp->hfs_logical_block_size);

	/*
	 * Differentiate between "innocuous" spare sectors and the more unusual
	 * degenerate case:
	 * 
	 * *** Innocuous spare sectors exist if:
	 * 
	 * A) the number of bytes assigned to the partition (by multiplying logical 
	 * block size * logical block count) is greater than the filesystem size 
	 * (by multiplying allocation block count and allocation block size)
	 * 
	 * and
	 * 
	 * B) the remainder is less than the size of a full allocation block's worth of bytes.
	 * 
	 * This handles the normal case where there may be a few extra sectors, but the two
	 * are fundamentally in sync.
	 *
	 * *** Degenerate spare sectors exist if:
	 * A) The number of bytes assigned to the partition (by multiplying logical
	 * block size * logical block count) is greater than the filesystem size 
	 * (by multiplying allocation block count and block size).
	 * 
	 * and
	 *
	 * B) the remainder is greater than a full allocation's block worth of bytes.
	 * In this case,  a smaller file system exists in a larger partition.  
	 * This can happen in various ways, including when volume is resized but the 
	 * partition is yet to be resized.  Under this condition, we have to assume that
	 * a partition management software may resize the partition to match 
	 * the file system size in the future.  Therefore we should update 
	 * alternate volume header at two locations on the disk, 
	 *   a. 1024 bytes before end of the partition
	 *   b. 1024 bytes before end of the file system 
	 */

	if (spare_sectors > (daddr64_t)(blockSize / hfsmp->hfs_logical_block_size)) {
		/* 
		 * Handle the degenerate case above. FS < partition size.
		 * AVH located at 1024 bytes from the end of the partition
		 */
		hfsmp->hfs_partition_avh_sector = (hfsmp->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size) +
					   HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size, hfsmp->hfs_logical_block_count);

		/* AVH located at 1024 bytes from the end of the filesystem */
		hfsmp->hfs_fs_avh_sector = (hfsmp->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size) +
					   HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size,
						(((daddr64_t)vcb->totalBlocks * blockSize) / hfsmp->hfs_logical_block_size));
	} 
	else {
		/* Innocuous spare sectors; Partition & FS notion are in sync */
		hfsmp->hfs_partition_avh_sector = (hfsmp->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size) +
					   HFS_ALT_SECTOR(hfsmp->hfs_logical_block_size, hfsmp->hfs_logical_block_count);

		hfsmp->hfs_fs_avh_sector = hfsmp->hfs_partition_avh_sector;
	}
	if (hfs_resize_debug) {
		printf ("hfs_MountHFSPlusVolume: partition_avh_sector=%qu, fs_avh_sector=%qu\n", 
				hfsmp->hfs_partition_avh_sector, hfsmp->hfs_fs_avh_sector);
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
	                         &hfsmp->hfs_extents_vp, &newvnode_flags);
	if (retval)
	{
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfsplus: hfs_getnewvnode returned (%d) getting extentoverflow BT\n", retval);
		}
		goto ErrorExit;
	}
	hfsmp->hfs_extents_cp = VTOC(hfsmp->hfs_extents_vp);
	hfs_unlock(hfsmp->hfs_extents_cp);

	retval = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_extents_vp),
	                                  (KeyCompareProcPtr) CompareExtentKeysPlus));
	if (retval)
	{
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfsplus: BTOpenPath returned (%d) getting extentoverflow BT\n", retval);
		}
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
	                         &hfsmp->hfs_catalog_vp, &newvnode_flags);
	if (retval) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfsplus: hfs_getnewvnode returned (%d) getting catalog BT\n", retval);
		}
		goto ErrorExit;
	}
	hfsmp->hfs_catalog_cp = VTOC(hfsmp->hfs_catalog_vp);
	hfs_unlock(hfsmp->hfs_catalog_cp);

	retval = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_catalog_vp),
	                                  (KeyCompareProcPtr) CompareExtendedCatalogKeys));
	if (retval) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfsplus: BTOpenPath returned (%d) getting catalog BT\n", retval);
		}
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
	                         &hfsmp->hfs_allocation_vp, &newvnode_flags);
	if (retval) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfsplus: hfs_getnewvnode returned (%d) getting bitmap\n", retval);
		}
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
					 &hfsmp->hfs_attribute_vp, &newvnode_flags);
		if (retval) {
			if (HFS_MOUNT_DEBUG) {
				printf("hfs_mounthfsplus: hfs_getnewvnode returned (%d) getting EA BT\n", retval);
			}
			goto ErrorExit;
		}
		hfsmp->hfs_attribute_cp = VTOC(hfsmp->hfs_attribute_vp);
		hfs_unlock(hfsmp->hfs_attribute_cp);
		retval = MacToVFSError(BTOpenPath(VTOF(hfsmp->hfs_attribute_vp),
						  (KeyCompareProcPtr) hfs_attrkeycompare));
		if (retval) {
			if (HFS_MOUNT_DEBUG) {
				printf("hfs_mounthfsplus: BTOpenPath returned (%d) getting EA BT\n", retval);
			}
			goto ErrorExit;
		}

		/* Initialize vnode for virtual attribute data file that spans the 
		 * entire file system space for performing I/O to attribute btree
		 * We hold iocount on the attrdata vnode for the entire duration 
		 * of mount (similar to btree vnodes)
		 */
		retval = init_attrdata_vnode(hfsmp);
		if (retval) {
			if (HFS_MOUNT_DEBUG) {
				printf("hfs_mounthfsplus: init_attrdata_vnode returned (%d) for virtual EA file\n", retval);
			}
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
					 &hfsmp->hfs_startup_vp, &newvnode_flags);
		if (retval) {
			if (HFS_MOUNT_DEBUG) {
				printf("hfs_mounthfsplus: hfs_getnewvnode returned (%d) getting startup file\n", retval);
			}
			goto ErrorExit;
		}
		hfsmp->hfs_startup_cp = VTOC(hfsmp->hfs_startup_vp);
		hfs_unlock(hfsmp->hfs_startup_cp);
	}
	
	/* 
	 * Pick up volume name and create date 
	 *
	 * Acquiring the volume name should not manipulate the bitmap, only the catalog
	 * btree and possibly the extents overflow b-tree.
	 */
	retval = cat_idlookup(hfsmp, kHFSRootFolderID, 0, 0, &cndesc, &cnattr, NULL);
	if (retval) {
		if (HFS_MOUNT_DEBUG) {
			printf("hfs_mounthfsplus: cat_idlookup returned (%d) getting rootfolder \n", retval);
		}
		goto ErrorExit;
	}
	vcb->hfs_itime = cnattr.ca_itime;
	vcb->volumeNameEncodingHint = cndesc.cd_encoding;
	bcopy(cndesc.cd_nameptr, vcb->vcbVN, min(255, cndesc.cd_namelen));
	volname_length = strlen ((const char*)vcb->vcbVN);
	cat_releasedesc(&cndesc);
	
#define DKIOCCSSETLVNAME _IOW('d', 198, char[256])


	/* Send the volume name down to CoreStorage if necessary */	
	retval = utf8_normalizestr(vcb->vcbVN, volname_length, (u_int8_t*)converted_volname, &conv_volname_length, 256, UTF_PRECOMPOSED);
	if (retval == 0) {
		(void) VNOP_IOCTL (hfsmp->hfs_devvp, DKIOCCSSETLVNAME, converted_volname, 0, vfs_context_current());
	}	
	
	/* reset retval == 0. we don't care about errors in volname conversion */
	retval = 0;

	
	/* 
	 * We now always initiate a full bitmap scan even if the volume is read-only because this is 
	 * our only shot to do I/Os of dramaticallly different sizes than what the buffer cache ordinarily
	 * expects. TRIMs will not be delivered to the underlying media if the volume is not 
	 * read-write though.  
	 */
	thread_t allocator_scanner;
	hfsmp->scan_var = 0;

	/* Take the HFS mount mutex and wait on scan_var */
	hfs_lock_mount (hfsmp);

	kernel_thread_start ((thread_continue_t) hfs_scan_blocks, hfsmp, &allocator_scanner);
	/* Wait until it registers that it's got the appropriate locks */
	while ((hfsmp->scan_var & HFS_ALLOCATOR_SCAN_INFLIGHT) == 0) {
		(void) msleep (&hfsmp->scan_var, &hfsmp->hfs_mutex, (PDROP | PINOD), "hfs_scan_blocks", 0);
		if (hfsmp->scan_var & HFS_ALLOCATOR_SCAN_INFLIGHT) {
			break;
		}
		else {
			hfs_lock_mount (hfsmp);
		}
	}

	thread_deallocate (allocator_scanner);

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
			if (retval == EROFS) {
				// EROFS is a special error code that means the volume has an external
				// journal which we couldn't find.  in that case we do not want to
				// rewrite the volume header - we'll just refuse to mount the volume.
				if (HFS_MOUNT_DEBUG) {
					printf("hfs_mounthfsplus: hfs_late_journal_init returned (%d), maybe an external jnl?\n", retval);
				}
				retval = EINVAL;
				goto ErrorExit;
			}

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

				bp = NULL;
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
			
			if (HFS_MOUNT_DEBUG) {
				printf("hfs_mounthfsplus: hfs_late_journal_init returned (%d)\n", retval);
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

	if ( !(vcb->vcbAtrb & kHFSVolumeHardwareLockMask) )	// if the disk is not write protected
	{
		MarkVCBDirty( vcb );	// mark VCB dirty so it will be written
	}

	/*
	 * Distinguish 3 potential cases involving content protection:
	 * 1. mount point bit set; vcbAtrb does not support it. Fail.
	 * 2. mount point bit set; vcbattrb supports it. we're good.
	 * 3. mount point bit not set; vcbatrb supports it, turn bit on, then good.
	 */
	if (vfs_flags(hfsmp->hfs_mp) & MNT_CPROTECT) {
		/* Does the mount point support it ? */
		if ((vcb->vcbAtrb & kHFSContentProtectionMask) == 0) {
			/* Case 1 above */
			retval = EINVAL;
			goto ErrorExit;
		}
	}
	else {
		/* not requested in the mount point. Is it in FS? */
		if (vcb->vcbAtrb & kHFSContentProtectionMask) {
			/* Case 3 above */
			vfs_setflags (hfsmp->hfs_mp, MNT_CPROTECT);
		}
	}

	/* At this point, if the mount point flag is set, we can enable it. */
	if (vfs_flags(hfsmp->hfs_mp) & MNT_CPROTECT) {
		/* Cases 2+3 above */
#if CONFIG_PROTECT
		/* Get the EAs as needed. */
		int cperr = 0;
		uint16_t majorversion;
		uint16_t minorversion;
		uint64_t flags;
		uint8_t cryptogen = 0;
		struct cp_root_xattr *xattr = NULL;
		MALLOC (xattr, struct cp_root_xattr*, sizeof(struct cp_root_xattr), M_TEMP, M_WAITOK);
		if (xattr == NULL) {
			retval = ENOMEM;
			goto ErrorExit;
		}
		bzero (xattr, sizeof(struct cp_root_xattr));

		/* go get the EA to get the version information */
		cperr = cp_getrootxattr (hfsmp, xattr);
		/* 
		 * If there was no EA there, then write one out. 
		 * Assuming EA is not present on the root means 
		 * this is an erase install or a very old FS
		 */

		if (cperr == 0) {
			/* Have to run a valid CP version. */
			if ((xattr->major_version < CP_PREV_MAJOR_VERS) || (xattr->major_version > CP_NEW_MAJOR_VERS)) {
				cperr = EINVAL;
			}
		}
		else if (cperr == ENOATTR) {
			printf("No root EA set, creating new EA with new version: %d\n", CP_NEW_MAJOR_VERS);
			bzero(xattr, sizeof(struct cp_root_xattr));
			xattr->major_version = CP_NEW_MAJOR_VERS;
			xattr->minor_version = CP_MINOR_VERS;
			cperr = cp_setrootxattr (hfsmp, xattr);
		}
		majorversion = xattr->major_version;
		minorversion = xattr->minor_version;
		flags = xattr->flags;
		if (xattr->flags & CP_ROOT_CRYPTOG1) {
			cryptogen = 1;
		}

		if (xattr) {
			FREE(xattr, M_TEMP);
		}

		/* Recheck for good status */
		if (cperr == 0) {
			/* If we got here, then the CP version is valid. Set it in the mount point */
			hfsmp->hfs_running_cp_major_vers = majorversion;
			printf("Running with CP root xattr: %d.%d\n", majorversion, minorversion);
			hfsmp->cproot_flags = flags;
			hfsmp->cp_crypto_generation = cryptogen;

			/* 
			 * Acquire the boot-arg for the AKS default key; if invalid, obtain from the device tree.
			 * Ensure that the boot-arg's value is valid for FILES (not directories),
			 * since only files are actually protected for now.
			 */ 
			 
			PE_parse_boot_argn("aks_default_class", &hfsmp->default_cp_class, sizeof(hfsmp->default_cp_class));
			
			if (cp_is_valid_class(0, hfsmp->default_cp_class) == 0) {
				PE_get_default("kern.default_cp_class", &hfsmp->default_cp_class, sizeof(hfsmp->default_cp_class));
			}
			
			if (cp_is_valid_class(0, hfsmp->default_cp_class) == 0) {
				hfsmp->default_cp_class = PROTECTION_CLASS_C;
			}
		}
		else {
			retval = EPERM;
			goto ErrorExit;
		}
#else
		/* If CONFIG_PROTECT not built, ignore CP */
		vfs_clearflags(hfsmp->hfs_mp, MNT_CPROTECT);	
#endif
	}

	/*
	 * Establish a metadata allocation zone.
	 */
	hfs_metadatazone_init(hfsmp, false);

	/*
	 * Make any metadata zone adjustments.
	 */
	if (hfsmp->hfs_flags & HFS_METADATA_ZONE) {
		/* Keep the roving allocator out of the metadata zone. */
		if (vcb->nextAllocation >= hfsmp->hfs_metazone_start &&
		    vcb->nextAllocation <= hfsmp->hfs_metazone_end) {	    
			HFS_UPDATE_NEXT_ALLOCATION(hfsmp, hfsmp->hfs_metazone_end + 1);
		}
	} else {
		if (vcb->nextAllocation <= 1) {
			vcb->nextAllocation = hfsmp->hfs_min_alloc_start;
		}
	}
	vcb->sparseAllocation = hfsmp->hfs_min_alloc_start;

	/* Setup private/hidden directories for hardlinks. */
	hfs_privatedir_init(hfsmp, FILE_HARDLINKS);
	hfs_privatedir_init(hfsmp, DIR_HARDLINKS);

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0) 
		hfs_remove_orphans(hfsmp);

	/* See if we need to erase unused Catalog nodes due to <rdar://problem/6947811>. */
	if ((hfsmp->hfs_flags & HFS_READ_ONLY) == 0)
	{
		retval = hfs_erase_unused_nodes(hfsmp);
		if (retval) {
			if (HFS_MOUNT_DEBUG) {
				printf("hfs_mounthfsplus: hfs_erase_unused_nodes returned (%d) for %s \n", retval, hfsmp->vcbVN);
			}

			goto ErrorExit;
		}
	}
		
	/*
	 * Allow hot file clustering if conditions allow.
	 */
	if ((hfsmp->hfs_flags & HFS_METADATA_ZONE)  &&
	    ((hfsmp->hfs_flags & (HFS_READ_ONLY | HFS_SSD)) == 0)) {
		(void) hfs_recording_init(hfsmp);
	}

	/* Force ACLs on HFS+ file systems. */
	vfs_setextendedsecurity(HFSTOVFS(hfsmp));

	/* Enable extent-based extended attributes by default */
	hfsmp->hfs_flags |= HFS_XATTR_EXTENTS;

	return (0);

ErrorExit:
	/*
	 * A fatal error occurred and the volume cannot be mounted, so 
	 * release any resources that we acquired...
	 */
	hfsUnmount(hfsmp, NULL);
		
	if (HFS_MOUNT_DEBUG) {
		printf("hfs_mounthfsplus: encountered error (%d)\n", retval);
	}
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
			(void)hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
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

int
hfsUnmount( register struct hfsmount *hfsmp, __unused struct proc *p)
{
	/* Get rid of our attribute data vnode (if any).  This is done 
	 * after the vflush() during mount, so we don't need to worry 
	 * about any locks.
	 */
	if (hfsmp->hfs_attrdata_vp) {
		ReleaseMetaFileVNode(hfsmp->hfs_attrdata_vp);
		hfsmp->hfs_attrdata_vp = NULLVP;
	}

	if (hfsmp->hfs_startup_vp) {
		ReleaseMetaFileVNode(hfsmp->hfs_startup_vp);
		hfsmp->hfs_startup_cp = NULL;
		hfsmp->hfs_startup_vp = NULL;
	}
	
	if (hfsmp->hfs_attribute_vp) {
		ReleaseMetaFileVNode(hfsmp->hfs_attribute_vp);
		hfsmp->hfs_attribute_cp = NULL;
		hfsmp->hfs_attribute_vp = NULL;
	}

	if (hfsmp->hfs_catalog_vp) {
		ReleaseMetaFileVNode(hfsmp->hfs_catalog_vp);
		hfsmp->hfs_catalog_cp = NULL;
		hfsmp->hfs_catalog_vp = NULL;
	}

	if (hfsmp->hfs_extents_vp) {
		ReleaseMetaFileVNode(hfsmp->hfs_extents_vp);
		hfsmp->hfs_extents_cp = NULL;
		hfsmp->hfs_extents_vp = NULL;
	}

	if (hfsmp->hfs_allocation_vp) {
		ReleaseMetaFileVNode(hfsmp->hfs_allocation_vp);
		hfsmp->hfs_allocation_cp = NULL;
		hfsmp->hfs_allocation_vp = NULL;
	}

	return (0);
}


/*
 * Test if fork has overflow extents.
 *
 * Returns: 
 * 	non-zero - overflow extents exist
 * 	zero     - overflow extents do not exist 
 */
__private_extern__
bool overflow_extents(struct filefork *fp)
{
	u_int32_t blocks;

	//
	// If the vnode pointer is NULL then we're being called
	// from hfs_remove_orphans() with a faked-up filefork
	// and therefore it has to be an HFS+ volume.  Otherwise
	// we check through the volume header to see what type
	// of volume we're on.
	//

#if CONFIG_HFS_STD
	if (FTOV(fp) && VTOVCB(FTOV(fp))->vcbSigWord == kHFSSigWord) {
		if (fp->ff_extents[2].blockCount == 0)
			return false;

		blocks = fp->ff_extents[0].blockCount +
			fp->ff_extents[1].blockCount +
			fp->ff_extents[2].blockCount;	

		return fp->ff_blocks > blocks;
	}
#endif

	if (fp->ff_extents[7].blockCount == 0)
		return false;

	blocks = fp->ff_extents[0].blockCount +
		fp->ff_extents[1].blockCount +
		fp->ff_extents[2].blockCount +
		fp->ff_extents[3].blockCount +
		fp->ff_extents[4].blockCount +
		fp->ff_extents[5].blockCount +
		fp->ff_extents[6].blockCount +
		fp->ff_extents[7].blockCount;	

	return fp->ff_blocks > blocks;
}

static __attribute__((pure))
boolean_t hfs_is_frozen(struct hfsmount *hfsmp)
{
	return (hfsmp->hfs_freeze_state == HFS_FROZEN
			|| (hfsmp->hfs_freeze_state == HFS_FREEZING
				&& current_thread() != hfsmp->hfs_freezing_thread));
}

/*
 * Lock the HFS global journal lock 
 */
int 
hfs_lock_global (struct hfsmount *hfsmp, enum hfs_locktype locktype) 
{
	thread_t thread = current_thread();

	if (hfsmp->hfs_global_lockowner == thread) {
		panic ("hfs_lock_global: locking against myself!");
	}

	/*
	 * This check isn't really necessary but this stops us taking
	 * the mount lock in most cases.  The essential check is below.
	 */
	if (hfs_is_frozen(hfsmp)) {
		/*
		 * Unfortunately, there is no easy way of getting a notification
		 * for when a process is exiting and it's possible for the exiting 
		 * process to get blocked somewhere else.  To catch this, we
		 * periodically monitor the frozen process here and thaw if
		 * we spot that it's exiting.
		 */
frozen:
		hfs_lock_mount(hfsmp);

		struct timespec ts = { 0, 500 * NSEC_PER_MSEC };

		while (hfs_is_frozen(hfsmp)) {
			if (hfsmp->hfs_freeze_state == HFS_FROZEN
				&& proc_exiting(hfsmp->hfs_freezing_proc)) {
				hfs_thaw_locked(hfsmp);
				break;
			}

			msleep(&hfsmp->hfs_freeze_state, &hfsmp->hfs_mutex,
			       PWAIT, "hfs_lock_global (frozen)", &ts);
		}
		hfs_unlock_mount(hfsmp);
	}

	/* HFS_SHARED_LOCK */
	if (locktype == HFS_SHARED_LOCK) {
		lck_rw_lock_shared (&hfsmp->hfs_global_lock);
		hfsmp->hfs_global_lockowner = HFS_SHARED_OWNER;
	}
	/* HFS_EXCLUSIVE_LOCK */
	else {
		lck_rw_lock_exclusive (&hfsmp->hfs_global_lock);
		hfsmp->hfs_global_lockowner = thread;
	}

	/* 
	 * We have to check if we're frozen again because of the time
	 * between when we checked and when we took the global lock.
	 */
	if (hfs_is_frozen(hfsmp)) {
		hfs_unlock_global(hfsmp);
		goto frozen;
	}

	return 0;
}


/*
 * Unlock the HFS global journal lock
 */
void 
hfs_unlock_global (struct hfsmount *hfsmp) 
{	
	thread_t thread = current_thread();

	/* HFS_LOCK_EXCLUSIVE */
	if (hfsmp->hfs_global_lockowner == thread) {
		hfsmp->hfs_global_lockowner = NULL;
		lck_rw_unlock_exclusive (&hfsmp->hfs_global_lock);
	}
	/* HFS_LOCK_SHARED */
	else {
		lck_rw_unlock_shared (&hfsmp->hfs_global_lock);
	}
}

/*
 * Lock the HFS mount lock
 * 
 * Note: this is a mutex, not a rw lock! 
 */
inline 
void hfs_lock_mount (struct hfsmount *hfsmp) {
	lck_mtx_lock (&(hfsmp->hfs_mutex)); 
}

/*
 * Unlock the HFS mount lock
 *
 * Note: this is a mutex, not a rw lock! 
 */
inline
void hfs_unlock_mount (struct hfsmount *hfsmp) {
	lck_mtx_unlock (&(hfsmp->hfs_mutex));
}

/*
 * Lock HFS system file(s).
 */
int
hfs_systemfile_lock(struct hfsmount *hfsmp, int flags, enum hfs_locktype locktype)
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

		if (hfsmp->hfs_catalog_cp) {
			(void) hfs_lock(hfsmp->hfs_catalog_cp, locktype, HFS_LOCK_DEFAULT);
			/*
			 * When the catalog file has overflow extents then
			 * also acquire the extents b-tree lock if its not
			 * already requested.
			 */
			if (((flags & SFL_EXTENTS) == 0) &&
			    (hfsmp->hfs_catalog_vp != NULL) && 
			    (overflow_extents(VTOF(hfsmp->hfs_catalog_vp)))) {
				flags |= SFL_EXTENTS;
			}
		} else {
			flags &= ~SFL_CATALOG;
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
			(void) hfs_lock(hfsmp->hfs_attribute_cp, locktype, HFS_LOCK_DEFAULT);
			/*
			 * When the attribute file has overflow extents then
			 * also acquire the extents b-tree lock if its not
			 * already requested.
			 */
			if (((flags & SFL_EXTENTS) == 0) &&
			    (hfsmp->hfs_attribute_vp != NULL) &&
			    (overflow_extents(VTOF(hfsmp->hfs_attribute_vp)))) {
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

		if (hfsmp->hfs_startup_cp) {
			(void) hfs_lock(hfsmp->hfs_startup_cp, locktype, HFS_LOCK_DEFAULT);
			/*
			 * When the startup file has overflow extents then
			 * also acquire the extents b-tree lock if its not
			 * already requested.
			 */
			if (((flags & SFL_EXTENTS) == 0) &&
			    (hfsmp->hfs_startup_vp != NULL) &&
			    (overflow_extents(VTOF(hfsmp->hfs_startup_vp)))) {
				flags |= SFL_EXTENTS;
			}
		} else {
			flags &= ~SFL_STARTUP;
		}
	}

	/* 
	 * To prevent locks being taken in the wrong order, the extent lock
	 * gets a bitmap lock as well.
	 */
	if (flags & (SFL_BITMAP | SFL_EXTENTS)) {
		if (hfsmp->hfs_allocation_cp) {
			(void) hfs_lock(hfsmp->hfs_allocation_cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
			/* 
			 * The bitmap lock is also grabbed when only extent lock 
			 * was requested. Set the bitmap lock bit in the lock
			 * flags which callers will use during unlock.
			 */
			flags |= SFL_BITMAP;
		} else {
			flags &= ~SFL_BITMAP;
		}
	}

	if (flags & SFL_EXTENTS) {
		/*
		 * Since the extents btree lock is recursive we always
		 * need exclusive access.
		 */
		if (hfsmp->hfs_extents_cp) {
			(void) hfs_lock(hfsmp->hfs_extents_cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);

			if (hfsmp->hfs_mp->mnt_kern_flag & MNTK_SWAP_MOUNT) {
				/*
				 * because we may need this lock on the pageout path (if a swapfile allocation
				 * spills into the extents overflow tree), we will grant the holder of this
				 * lock the privilege of dipping into the reserve free pool in order to prevent
				 * a deadlock from occurring if we need those pageouts to complete before we
				 * will make any new pages available on the free list... the deadlock can occur
				 * if this thread needs to allocate memory while this lock is held
				 */
				if (set_vm_privilege(TRUE) == FALSE) {
					/*
					 * indicate that we need to drop vm_privilege 
					 * when we unlock
					 */
					flags |= SFL_VM_PRIV;
				}
			}
		} else {
			flags &= ~SFL_EXTENTS;
		}
	}

	return (flags);
}

/*
 * unlock HFS system file(s).
 */
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
	if (flags & SFL_CATALOG && hfsmp->hfs_catalog_cp) {
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
	if (flags & SFL_BITMAP && hfsmp->hfs_allocation_cp) {
		hfs_unlock(hfsmp->hfs_allocation_cp);
	}
	if (flags & SFL_EXTENTS && hfsmp->hfs_extents_cp) {
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

		if (flags & SFL_VM_PRIV) {
			/*
			 * revoke the vm_privilege we granted this thread
			 * now that we have unlocked the overflow extents
			 */
			set_vm_privilege(FALSE);
		}
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
	
	locked = VTOC(vp)->c_lockowner == current_thread();
	
	if (!locked && !shareable) {
		switch (VTOC(vp)->c_fileid) {
		case kHFSExtentsFileID:
			panic("hfs: extents btree not locked! v: 0x%08X\n #\n", (u_int)vp);
			break;
		case kHFSCatalogFileID:
			panic("hfs: catalog btree not locked! v: 0x%08X\n #\n", (u_int)vp);
			break;
		case kHFSAllocationFileID:
			/* The allocation file can hide behind the jornal lock. */
			if (VTOHFS(vp)->jnl == NULL)
				panic("hfs: allocation file not locked! v: 0x%08X\n #\n", (u_int)vp);
			break;
		case kHFSStartupFileID:
			panic("hfs: startup file not locked! v: 0x%08X\n #\n", (u_int)vp);
		case kHFSAttributesFileID:
			panic("hfs: attributes btree not locked! v: 0x%08X\n #\n", (u_int)vp);
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


u_int32_t BestBlockSizeFit(u_int32_t allocationBlockSize,
                               u_int32_t blockSizeLimit,
                               u_int32_t baseMultiple) {
    /*
       Compute the optimal (largest) block size (no larger than allocationBlockSize) that is less than the
       specified limit but still an even multiple of the baseMultiple.
     */
    int baseBlockCount, blockCount;
    u_int32_t trialBlockSize;

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


u_int32_t
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
	error = cat_lookup(hfsmp, &jdesc, 0, 0, NULL, fattr, forkinfo, NULL);
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
	int orphaned_files = 0;
	int orphaned_dirs = 0;

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
			int mode = 0;

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
				    if (fsize > HFS_BIGFILE_SIZE) {
						fsize -= HFS_BIGFILE_SIZE;
					} else {
						fsize = 0;
					}

					if (TruncateFileC(vcb, (FCB*)&dfork, fsize, 1, 0, 
									  cnode.c_attr.ca_fileid, false) != 0) {
						printf("hfs: error truncating data fork!\n");
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
				if (TruncateFileC(vcb, (FCB*)&rfork, 0, 1, 1, cnode.c_attr.ca_fileid, false) != 0) {
					printf("hfs: error truncating rsrc fork!\n");
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
			
			mode = cnode.c_attr.ca_mode & S_IFMT;

			if (mode == S_IFDIR) {
				orphaned_dirs++;
			}
			else {
				orphaned_files++;
			}

			/* Update parent and volume counts */	
			hfsmp->hfs_private_attr[FILE_HARDLINKS].ca_entries--;
			if (mode == S_IFDIR) {
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
			if (mode == S_IFDIR) {
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
	if (orphaned_files > 0 || orphaned_dirs > 0)
		printf("hfs: Removed %d orphaned / unlinked files and %d directories \n", orphaned_files, orphaned_dirs);
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

#if HFS_SPARSE_DEV
static bool hfs_get_backing_free_blks(hfsmount_t *hfsmp, uint64_t *pfree_blks)
{
	struct vfsstatfs *vfsp;  /* 272 bytes */
	uint64_t vfreeblks;
	struct timeval now;

	hfs_lock_mount(hfsmp);

	vnode_t backing_vp = hfsmp->hfs_backingfs_rootvp;
	if (!backing_vp) {
		hfs_unlock_mount(hfsmp);
		return false;
	}

	// usecount is not enough; we need iocount
	if (vnode_get(backing_vp)) {
		hfs_unlock_mount(hfsmp);
		*pfree_blks = 0;
		return true;
	}

	uint32_t loanedblks = hfsmp->loanedBlocks;
	uint32_t bandblks	= hfsmp->hfs_sparsebandblks;
	uint64_t maxblks	= hfsmp->hfs_backingfs_maxblocks;

	hfs_unlock_mount(hfsmp);

	mount_t backingfs_mp = vnode_mount(backing_vp);

	microtime(&now);
	if ((now.tv_sec - hfsmp->hfs_last_backingstatfs) >= 1) {
		vfs_update_vfsstat(backingfs_mp, vfs_context_kernel(), VFS_KERNEL_EVENT);
		hfsmp->hfs_last_backingstatfs = now.tv_sec;
	}

	if (!(vfsp = vfs_statfs(backingfs_mp))) {
		vnode_put(backing_vp);
		return false;
	}

	vfreeblks = vfsp->f_bavail;
	/* Normalize block count if needed. */
	if (vfsp->f_bsize != hfsmp->blockSize)
		vfreeblks = vfreeblks * vfsp->f_bsize / hfsmp->blockSize;
	if (vfreeblks > bandblks)
		vfreeblks -= bandblks;
	else
		vfreeblks = 0;

	/* 
	 * Take into account any delayed allocations.  It is not
	 * certain what the original reason for the "2 *" is.  Most
	 * likely it is to allow for additional requirements in the
	 * host file system and metadata required by disk images.  The
	 * number of loaned blocks is likely to be small and we will
	 * stop using them as we get close to the limit.
	 */
	loanedblks = 2 * loanedblks;
	if (vfreeblks > loanedblks)
		vfreeblks -= loanedblks;
	else
		vfreeblks = 0;

	if (maxblks)
		vfreeblks = MIN(vfreeblks, maxblks);

	vnode_put(backing_vp);

	*pfree_blks = vfreeblks;

	return true;
}
#endif

u_int32_t
hfs_freeblks(struct hfsmount * hfsmp, int wantreserve)
{
	u_int32_t freeblks;
	u_int32_t rsrvblks;
	u_int32_t loanblks;

	/*
	 * We don't bother taking the mount lock
	 * to look at these values since the values
	 * themselves are each updated atomically
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

#if HFS_SPARSE_DEV
	/* 
	 * When the underlying device is sparse, check the
	 * available space on the backing store volume.
	 */
	uint64_t vfreeblks;
	if (hfs_get_backing_free_blks(hfsmp, &vfreeblks))
		freeblks = MIN(freeblks, vfreeblks);
#endif /* HFS_SPARSE_DEV */

	if (hfsmp->hfs_flags & HFS_CS) {
		uint64_t cs_free_bytes;
		uint64_t cs_free_blks;
		if (VNOP_IOCTL(hfsmp->hfs_devvp, _DKIOCCSGETFREEBYTES,
		    (caddr_t)&cs_free_bytes, 0, vfs_context_kernel()) == 0) {
			cs_free_blks = cs_free_bytes / hfsmp->blockSize;
			if (cs_free_blks > loanblks)
				cs_free_blks -= loanblks;
			else
				cs_free_blks = 0;
			freeblks = MIN(cs_free_blks, freeblks);
		}
	}

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

	/* BSD/VFS internal errnos */
	switch (err) {
		case ERESERVEDNAME: /* -8 */
			return err;
	}

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


typedef struct jopen_cb_info {
	off_t   jsize;
	char   *desired_uuid;
        struct  vnode *jvp;
	size_t  blksize;
	int     need_clean;
	int     need_init;
} jopen_cb_info;

static int
journal_open_cb(const char *bsd_dev_name, const char *uuid_str, void *arg)
{
	struct nameidata nd;
	jopen_cb_info *ji = (jopen_cb_info *)arg;
	char bsd_name[256];
	int error;
	
	strlcpy(&bsd_name[0], "/dev/", sizeof(bsd_name));
	strlcpy(&bsd_name[5], bsd_dev_name, sizeof(bsd_name)-5);

	if (ji->desired_uuid && ji->desired_uuid[0] && strcmp(uuid_str, ji->desired_uuid) != 0) {
		return 1;   // keep iterating
	}

	// if we're here, either the desired uuid matched or there was no
	// desired uuid so let's try to open the device for writing and
	// see if it works.  if it does, we'll use it.
	
	NDINIT(&nd, LOOKUP, OP_LOOKUP, LOCKLEAF, UIO_SYSSPACE32, CAST_USER_ADDR_T(bsd_name), vfs_context_kernel());
	if ((error = namei(&nd))) {
		printf("hfs: journal open cb: error %d looking up device %s (dev uuid %s)\n", error, bsd_name, uuid_str);
		return 1;   // keep iterating
	}

	ji->jvp = nd.ni_vp;
	nameidone(&nd);

	if (ji->jvp == NULL) {
		printf("hfs: journal open cb: did not find %s (error %d)\n", bsd_name, error);
	} else {
		error = VNOP_OPEN(ji->jvp, FREAD|FWRITE, vfs_context_kernel());
		if (error == 0) {
			// if the journal is dirty and we didn't specify a desired
			// journal device uuid, then do not use the journal.  but
			// if the journal is just invalid (e.g. it hasn't been
			// initialized) then just set the need_init flag.
			if (ji->need_clean && ji->desired_uuid && ji->desired_uuid[0] == '\0') {
				error = journal_is_clean(ji->jvp, 0, ji->jsize, (void *)1, ji->blksize);
				if (error == EBUSY) {
					VNOP_CLOSE(ji->jvp, FREAD|FWRITE, vfs_context_kernel());
					vnode_put(ji->jvp);
					ji->jvp = NULL;
					return 1;    // keep iterating
				} else if (error == EINVAL) {
					ji->need_init = 1;
				}
			}

			if (ji->desired_uuid && ji->desired_uuid[0] == '\0') {
				strlcpy(ji->desired_uuid, uuid_str, 128);
			}
			vnode_setmountedon(ji->jvp);
			return 0;   // stop iterating
		} else {
			vnode_put(ji->jvp);
			ji->jvp = NULL;
		}
	}

	return 1;   // keep iterating
}

extern void IOBSDIterateMediaWithContent(const char *uuid_cstring, int (*func)(const char *bsd_dev_name, const char *uuid_str, void *arg), void *arg);
kern_return_t IOBSDGetPlatformSerialNumber(char *serial_number_str, u_int32_t len);


static vnode_t
open_journal_dev(const char *vol_device,
		 int need_clean,
		 char *uuid_str,
		 char *machine_serial_num,
		 off_t jsize,
		 size_t blksize,
		 int *need_init)
{
    int retry_counter=0;
    jopen_cb_info ji;

    ji.jsize        = jsize;
    ji.desired_uuid = uuid_str;
    ji.jvp          = NULL;
    ji.blksize      = blksize;
    ji.need_clean   = need_clean;
    ji.need_init    = 0;

//    if (uuid_str[0] == '\0') {
//	    printf("hfs: open journal dev: %s: locating any available non-dirty external journal partition\n", vol_device);
//    } else {
//	    printf("hfs: open journal dev: %s: trying to find the external journal partition w/uuid %s\n", vol_device, uuid_str);
//    }
    while (ji.jvp == NULL && retry_counter++ < 4) {
	    if (retry_counter > 1) {
		    if (uuid_str[0]) {
			    printf("hfs: open_journal_dev: uuid %s not found.  waiting 10sec.\n", uuid_str);
		    } else {
			    printf("hfs: open_journal_dev: no available external journal partition found.  waiting 10sec.\n");
		    }
		    delay_for_interval(10* 1000000, NSEC_PER_USEC);    // wait for ten seconds and then try again
	    }

	    IOBSDIterateMediaWithContent(EXTJNL_CONTENT_TYPE_UUID, journal_open_cb, &ji);
    }

    if (ji.jvp == NULL) {
	    printf("hfs: volume: %s: did not find jnl device uuid: %s from machine serial number: %s\n",
		   vol_device, uuid_str, machine_serial_num);
    }

    *need_init = ji.need_init;

    return ji.jvp;
}


int
hfs_early_journal_init(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
					   void *_args, off_t embeddedOffset, daddr64_t mdb_offset,
					   HFSMasterDirectoryBlock *mdbp, kauth_cred_t cred)
{
	JournalInfoBlock *jibp;
	struct buf       *jinfo_bp, *bp;
	int               sectors_per_fsblock, arg_flags=0, arg_tbufsz=0;
	int               retval, write_jibp = 0;
	uint32_t		  blksize = hfsmp->hfs_logical_block_size;
	struct vnode     *devvp;
	struct hfs_mount_args *args = _args;
	u_int32_t	  jib_flags;
	u_int64_t	  jib_offset;
	u_int64_t	  jib_size;
	const char *dev_name;
	
	devvp = hfsmp->hfs_devvp;
	dev_name = vnode_getname_printable(devvp);

	if (args != NULL && (args->flags & HFSFSMNT_EXTENDED_ARGS)) {
		arg_flags  = args->journal_flags;
		arg_tbufsz = args->journal_tbuffer_size;
	}

	sectors_per_fsblock = SWAP_BE32(vhp->blockSize) / blksize;
				
	jinfo_bp = NULL;
	retval = (int)buf_meta_bread(devvp,
						(daddr64_t)((embeddedOffset/blksize) + 
						((u_int64_t)SWAP_BE32(vhp->journalInfoBlock)*sectors_per_fsblock)),
						hfsmp->hfs_physical_block_size, cred, &jinfo_bp);
	if (retval) {
		if (jinfo_bp) {
			buf_brelse(jinfo_bp);
		}
		goto cleanup_dev_name;
	}
	
	jibp = (JournalInfoBlock *)buf_dataptr(jinfo_bp);
	jib_flags  = SWAP_BE32(jibp->flags);
	jib_size   = SWAP_BE64(jibp->size);

	if (jib_flags & kJIJournalInFSMask) {
		hfsmp->jvp = hfsmp->hfs_devvp;
		jib_offset = SWAP_BE64(jibp->offset);
	} else {
	    int need_init=0;
	
	    // if the volume was unmounted cleanly then we'll pick any
	    // available external journal partition
	    //
	    if (SWAP_BE32(vhp->attributes) & kHFSVolumeUnmountedMask) {
		    *((char *)&jibp->ext_jnl_uuid[0]) = '\0';
	    }

	    hfsmp->jvp = open_journal_dev(dev_name,
					  !(jib_flags & kJIJournalNeedInitMask),
					  (char *)&jibp->ext_jnl_uuid[0],
					  (char *)&jibp->machine_serial_num[0],
					  jib_size,
					  hfsmp->hfs_logical_block_size,
					  &need_init);
	    if (hfsmp->jvp == NULL) {
		    buf_brelse(jinfo_bp);
		    retval = EROFS;
		    goto cleanup_dev_name;
	    } else {
		    if (IOBSDGetPlatformSerialNumber(&jibp->machine_serial_num[0], sizeof(jibp->machine_serial_num)) != KERN_SUCCESS) {
			    strlcpy(&jibp->machine_serial_num[0], "unknown-machine-uuid", sizeof(jibp->machine_serial_num));
		    }
	    }

	    jib_offset = 0;
	    write_jibp = 1;
	    if (need_init) {
		    jib_flags |= kJIJournalNeedInitMask;
	    }
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
		    const char *name = vnode_getname_printable(devvp);
		    printf("hfs: early journal init: volume on %s is read-only and journal is dirty.  Can not mount volume.\n",
		    name);
		    vnode_putname_printable(name);
	    }

	    goto cleanup_dev_name;
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
									hfs_sync_metadata, hfsmp->hfs_mp,
									hfsmp->hfs_mp);
		if (hfsmp->jnl)
			journal_trim_set_callback(hfsmp->jnl, hfs_trim_callback, hfsmp);

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
								  hfs_sync_metadata, hfsmp->hfs_mp,
								  hfsmp->hfs_mp);
		if (hfsmp->jnl)
			journal_trim_set_callback(hfsmp->jnl, hfs_trim_callback, hfsmp);

		if (write_jibp) {
			buf_bwrite(jinfo_bp);
		} else {
			buf_brelse(jinfo_bp);
		}
		jinfo_bp = NULL;
		jibp     = NULL;

		if (hfsmp->jnl && mdbp) {
			// reload the mdb because it could have changed
			// if the journal had to be replayed.
			if (mdb_offset == 0) {
				mdb_offset = (daddr64_t)((embeddedOffset / blksize) + HFS_PRI_SECTOR(blksize));
			}
			bp = NULL;
			retval = (int)buf_meta_bread(devvp, 
					HFS_PHYSBLK_ROUNDDOWN(mdb_offset, hfsmp->hfs_log_per_phys),
					hfsmp->hfs_physical_block_size, cred, &bp);
			if (retval) {
				if (bp) {
					buf_brelse(bp);
				}
				printf("hfs: failed to reload the mdb after opening the journal (retval %d)!\n",
					   retval);
				goto cleanup_dev_name;
			}
			bcopy((char *)buf_dataptr(bp) + HFS_PRI_OFFSET(hfsmp->hfs_physical_block_size), mdbp, 512);
			buf_brelse(bp);
			bp = NULL;
		}
	}

	// if we expected the journal to be there and we couldn't
	// create it or open it then we have to bail out.
	if (hfsmp->jnl == NULL) {
		printf("hfs: early jnl init: failed to open/create the journal (retval %d).\n", retval);
		retval = EINVAL;
		goto cleanup_dev_name;
	}

	retval = 0;
	
cleanup_dev_name:
	vnode_putname_printable(dev_name);
	return retval;
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
	u_int32_t            fid;
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
	jinfo_bp = NULL;
	retval = (int)buf_meta_bread(devvp,
						(vcb->hfsPlusIOPosOffset / hfsmp->hfs_logical_block_size + 
						((u_int64_t)SWAP_BE32(vhp->journalInfoBlock)*sectors_per_fsblock)),
						hfsmp->hfs_physical_block_size, NOCRED, &jinfo_bp);
	if (retval) {
		if (jinfo_bp) {
			buf_brelse(jinfo_bp);
		}
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
	if ((jib_flags & kJIJournalInFSMask) && (jib_offset / (u_int64_t)vcb->blockSize) != jfork.cf_extents[0].startBlock) {
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
		jib_offset += (off_t)vcb->hfsPlusIOPosOffset;
	} else {
	    const char *dev_name;
	    int need_init = 0;
	
	    dev_name = vnode_getname_printable(devvp);

            // since the journal is empty, just use any available external journal
	    *((char *)&jibp->ext_jnl_uuid[0]) = '\0';

	    // this fills in the uuid of the device we actually get
	    hfsmp->jvp = open_journal_dev(dev_name,
					  !(jib_flags & kJIJournalNeedInitMask),
					  (char *)&jibp->ext_jnl_uuid[0],
					  (char *)&jibp->machine_serial_num[0],
					  jib_size,
					  hfsmp->hfs_logical_block_size,
					  &need_init);
	    if (hfsmp->jvp == NULL) {
		    buf_brelse(jinfo_bp);
		    vnode_putname_printable(dev_name);
		    return EROFS;
	    } else {
		    if (IOBSDGetPlatformSerialNumber(&jibp->machine_serial_num[0], sizeof(jibp->machine_serial_num)) != KERN_SUCCESS) {
			    strlcpy(&jibp->machine_serial_num[0], "unknown-machine-serial-num", sizeof(jibp->machine_serial_num));
		    }
	    }
	    jib_offset = 0;
	    recreate_journal = 1;
	    write_jibp = 1;
	    if (need_init) {
		    jib_flags |= kJIJournalNeedInitMask;
	    }
	    vnode_putname_printable(dev_name);
	}

	// save this off for the hack-y check in hfs_remove()
	hfsmp->jnl_start = jib_offset / SWAP_BE32(vhp->blockSize);
	hfsmp->jnl_size  = jib_size;

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) && (vfs_flags(hfsmp->hfs_mp) & MNT_ROOTFS) == 0) {
	    // if the file system is read-only, check if the journal is empty.
	    // if it is, then we can allow the mount.  otherwise we have to
	    // return failure.
	    retval = journal_is_clean(hfsmp->jvp,
				      jib_offset,
				      jib_size,
				      devvp,
		                      hfsmp->hfs_logical_block_size);

	    hfsmp->jnl = NULL;

	    buf_brelse(jinfo_bp);

	    if (retval) {
		    const char *name = vnode_getname_printable(devvp);
		    printf("hfs: late journal init: volume on %s is read-only and journal is dirty.  Can not mount volume.\n", 
		    name);
		    vnode_putname_printable(name);
	    }

	    return retval;
	}

	if ((jib_flags & kJIJournalNeedInitMask) || recreate_journal) {
		printf("hfs: Initializing the journal (joffset 0x%llx sz 0x%llx)...\n",
			   jib_offset, jib_size);
		hfsmp->jnl = journal_create(hfsmp->jvp,
									jib_offset,
									jib_size,
									devvp,
									hfsmp->hfs_logical_block_size,
									arg_flags,
									arg_tbufsz,
									hfs_sync_metadata, hfsmp->hfs_mp,
									hfsmp->hfs_mp);
		if (hfsmp->jnl)
			journal_trim_set_callback(hfsmp->jnl, hfs_trim_callback, hfsmp);

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
		//	   jib_offset,
		//	   jib_size, SWAP_BE32(vhp->blockSize));
				
		hfsmp->jnl = journal_open(hfsmp->jvp,
								  jib_offset,
								  jib_size,
								  devvp,
								  hfsmp->hfs_logical_block_size,
								  arg_flags,
								  arg_tbufsz,
								  hfs_sync_metadata, hfsmp->hfs_mp,
								  hfsmp->hfs_mp);
		if (hfsmp->jnl)
			journal_trim_set_callback(hfsmp->jnl, hfs_trim_callback, hfsmp);
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

/* Initialize the metadata zone.
 *
 * If the size of  the volume is less than the minimum size for
 * metadata zone, metadata zone is disabled.
 *
 * If disable is true, disable metadata zone unconditionally.
 */
void
hfs_metadatazone_init(struct hfsmount *hfsmp, int disable)
{
	ExtendedVCB  *vcb;
	u_int64_t  fs_size;
	u_int64_t  zonesize;
	u_int64_t  temp;
	u_int64_t  filesize;
	u_int32_t  blk;
	int  items, really_do_it=1;

	vcb = HFSTOVCB(hfsmp);
	fs_size = (u_int64_t)vcb->blockSize * (u_int64_t)vcb->allocLimit;

	/*
	 * For volumes less than 10 GB, don't bother.
	 */
	if (fs_size < ((u_int64_t)10 * GIGABYTE)) {
		really_do_it = 0;
	}
	
	/*
	 * Skip non-journaled volumes as well.
	 */
	if (hfsmp->jnl == NULL) {
		really_do_it = 0;
	}

	/* If caller wants to disable metadata zone, do it */
	if (disable == true) {
		really_do_it = 0;
	}

	/*
	 * Start with space for the boot blocks and Volume Header.
	 * 1536 = byte offset from start of volume to end of volume header:
	 * 1024 bytes is the offset from the start of the volume to the
	 * start of the volume header (defined by the volume format)
	 * + 512 bytes (the size of the volume header).
	 */
	zonesize = roundup(1536, hfsmp->blockSize);
	
	/*
	 * Add the on-disk size of allocation bitmap.
	 */
	zonesize += hfsmp->hfs_allocation_cp->c_datafork->ff_blocks * hfsmp->blockSize;
	
	/* 
	 * Add space for the Journal Info Block and Journal (if they're in
	 * this file system).
	 */
	if (hfsmp->jnl && hfsmp->jvp == hfsmp->hfs_devvp) {
		zonesize += hfsmp->blockSize + hfsmp->jnl_size;
	}
	
	/*
	 * Add the existing size of the Extents Overflow B-tree.
	 * (It rarely grows, so don't bother reserving additional room for it.)
	 */
	zonesize += hfsmp->hfs_extents_cp->c_datafork->ff_blocks * hfsmp->blockSize;
	
	/*
	 * If there is an Attributes B-tree, leave room for 11 clumps worth.
	 * newfs_hfs allocates one clump, and leaves a gap of 10 clumps.
	 * When installing a full OS install onto a 20GB volume, we use
	 * 7 to 8 clumps worth of space (depending on packages), so that leaves
	 * us with another 3 or 4 clumps worth before we need another extent.
	 */
	if (hfsmp->hfs_attribute_cp) {
		zonesize += 11 * hfsmp->hfs_attribute_cp->c_datafork->ff_clumpsize;
	}
	
	/*
	 * Leave room for 11 clumps of the Catalog B-tree.
	 * Again, newfs_hfs allocates one clump plus a gap of 10 clumps.
	 * When installing a full OS install onto a 20GB volume, we use
	 * 7 to 8 clumps worth of space (depending on packages), so that leaves
	 * us with another 3 or 4 clumps worth before we need another extent.
	 */
	zonesize += 11 * hfsmp->hfs_catalog_cp->c_datafork->ff_clumpsize;
	
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
	if (hfsmp->hfs_flags & HFS_QUOTAS) {
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
	}
	zonesize += filesize;

	/*
	 * Round up entire zone to a bitmap block's worth.
	 * The extra space goes to the catalog file and hot file area.
	 */
	temp = zonesize;
	zonesize = roundup(zonesize, (u_int64_t)vcb->vcbVBMIOSize * 8 * vcb->blockSize);
	hfsmp->hfs_min_alloc_start = zonesize / vcb->blockSize;
	/*
	 * If doing the round up for hfs_min_alloc_start would push us past
	 * allocLimit, then just reset it back to 0.  Though using a value 
	 * bigger than allocLimit would not cause damage in the block allocator
	 * code, this value could get stored in the volume header and make it out 
	 * to disk, making the volume header technically corrupt.
	 */
	if (hfsmp->hfs_min_alloc_start >= hfsmp->allocLimit) {
		hfsmp->hfs_min_alloc_start = 0;
	}

	if (really_do_it == 0) {
		/* If metadata zone needs to be disabled because the 
		 * volume was truncated, clear the bit and zero out 
		 * the values that are no longer needed.
		 */
		if (hfsmp->hfs_flags & HFS_METADATA_ZONE) {
			/* Disable metadata zone */
			hfsmp->hfs_flags &= ~HFS_METADATA_ZONE;
			
			/* Zero out mount point values that are not required */
			hfsmp->hfs_catalog_maxblks = 0;
			hfsmp->hfs_hotfile_maxblks = 0;
			hfsmp->hfs_hotfile_start = 0;
			hfsmp->hfs_hotfile_end = 0;
			hfsmp->hfs_hotfile_freeblks = 0;
			hfsmp->hfs_metazone_start = 0;
			hfsmp->hfs_metazone_end = 0;
		}
		
		return;
	}
	
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
	if (vfs_flags(HFSTOVFS(hfsmp)) & MNT_ROOTFS) {
		hfsmp->hfs_hotfile_start = blk - (filesize / vcb->blockSize);
		hfsmp->hfs_hotfile_end = hfsmp->hfs_metazone_end;
		hfsmp->hfs_hotfile_freeblks = hfs_hotfile_freeblocks(hfsmp);
	}
	else {
		hfsmp->hfs_hotfile_start = 0;
		hfsmp->hfs_hotfile_end = 0;
		hfsmp->hfs_hotfile_freeblks = 0;
	}
#if 0
	printf("hfs: metadata zone is %d to %d\n", hfsmp->hfs_metazone_start, hfsmp->hfs_metazone_end);
	printf("hfs: hot file band is %d to %d\n", hfsmp->hfs_hotfile_start, hfsmp->hfs_hotfile_end);
	printf("hfs: hot file band free blocks = %d\n", hfsmp->hfs_hotfile_freeblks);
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

__private_extern__
void hfs_syncer_lock(struct hfsmount *hfsmp)
{
    hfs_lock_mount(hfsmp);
}

__private_extern__ 
void hfs_syncer_unlock(struct hfsmount *hfsmp)
{
    hfs_unlock_mount(hfsmp);
}

__private_extern__
void hfs_syncer_wait(struct hfsmount *hfsmp)
{
    msleep(&hfsmp->hfs_sync_incomplete, &hfsmp->hfs_mutex, PWAIT, 
           "hfs_syncer_wait", NULL);
}

__private_extern__
void hfs_syncer_wakeup(struct hfsmount *hfsmp)
{
    wakeup(&hfsmp->hfs_sync_incomplete);
}

__private_extern__
uint64_t hfs_usecs_to_deadline(uint64_t usecs)
{
    uint64_t deadline;
    clock_interval_to_deadline(usecs, NSEC_PER_USEC, &deadline);
    return deadline;
}

__private_extern__
void hfs_syncer_queue(thread_call_t syncer)
{
    if (thread_call_enter_delayed_with_leeway(syncer,
                                              NULL,
                                              hfs_usecs_to_deadline(HFS_META_DELAY),
                                              0,
                                              THREAD_CALL_DELAY_SYS_BACKGROUND)) {
		printf("hfs: syncer already scheduled!\n");
    }
}

//
// Fire off a timed callback to sync the disk if the
// volume is on ejectable media.
//
 __private_extern__
void
hfs_sync_ejectable(struct hfsmount *hfsmp)
{
    // If we don't have a syncer or we get called by the syncer, just return
    if (!hfsmp->hfs_syncer || current_thread() == hfsmp->hfs_syncer_thread)
        return;

    hfs_syncer_lock(hfsmp);

    if (!timerisset(&hfsmp->hfs_sync_req_oldest))
        microuptime(&hfsmp->hfs_sync_req_oldest);

    /* If hfs_unmount is running, it will set hfs_syncer to NULL. Also we
       don't want to queue again if there is a sync outstanding. */
    if (!hfsmp->hfs_syncer || hfsmp->hfs_sync_incomplete) {
        hfs_syncer_unlock(hfsmp);
        return;
    }

    hfsmp->hfs_sync_incomplete = TRUE;

    thread_call_t syncer = hfsmp->hfs_syncer;

    hfs_syncer_unlock(hfsmp);

    hfs_syncer_queue(syncer);
}

int
hfs_start_transaction(struct hfsmount *hfsmp)
{
	int ret = 0, unlock_on_err = 0;
	thread_t thread = current_thread();

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
		/* 
		 * The global lock should be held shared if journal is 
		 * active to prevent disabling.  If we're not the owner 
		 * of the journal lock, verify that we're not already
		 * holding the global lock exclusive before moving on.	 
		 */
		if (hfsmp->hfs_global_lockowner == thread) {
			ret = EBUSY;
			goto out;
		}

		hfs_lock_global (hfsmp, HFS_SHARED_LOCK);
		OSAddAtomic(1, (SInt32 *)&hfsmp->hfs_active_threads);
		unlock_on_err = 1;
	}

	/* If a downgrade to read-only mount is in progress, no other
	 * thread than the downgrade thread is allowed to modify 
	 * the file system.
	 */
	if ((hfsmp->hfs_flags & HFS_RDONLY_DOWNGRADE) && 
	    hfsmp->hfs_downgrading_thread != thread) {
		ret = EROFS;
		goto out;
	}

	if (hfsmp->jnl) {
		ret = journal_start_transaction(hfsmp->jnl);
		if (ret == 0) {
			OSAddAtomic(1, &hfsmp->hfs_global_lock_nesting);
		}
	} else {
		ret = 0;
	}

out:
	if (ret != 0 && unlock_on_err) {
		hfs_unlock_global (hfsmp);
		OSAddAtomic(-1, (SInt32 *)&hfsmp->hfs_active_threads);
	}

    return ret;
}

int
hfs_end_transaction(struct hfsmount *hfsmp)
{
    int need_unlock=0, ret;

    if ((hfsmp->jnl == NULL) || ( journal_owner(hfsmp->jnl) == current_thread()
	    && (OSAddAtomic(-1, &hfsmp->hfs_global_lock_nesting) == 1)) ) {
	    need_unlock = 1;
    } 

	if (hfsmp->jnl) {
		ret = journal_end_transaction(hfsmp->jnl);
	} else {
		ret = 0;
	}

	if (need_unlock) {
		OSAddAtomic(-1, (SInt32 *)&hfsmp->hfs_active_threads);
		hfs_unlock_global (hfsmp);
		hfs_sync_ejectable(hfsmp);
	}

    return ret;
}


void 
hfs_journal_lock(struct hfsmount *hfsmp) 
{
	/* Only peek at hfsmp->jnl while holding the global lock */
	hfs_lock_global (hfsmp, HFS_SHARED_LOCK);
	if (hfsmp->jnl) {
		journal_lock(hfsmp->jnl);
	}
	hfs_unlock_global (hfsmp);
}

void 
hfs_journal_unlock(struct hfsmount *hfsmp) 
{
	/* Only peek at hfsmp->jnl while holding the global lock */
	hfs_lock_global (hfsmp, HFS_SHARED_LOCK);
	if (hfsmp->jnl) {
		journal_unlock(hfsmp->jnl);
	}
	hfs_unlock_global (hfsmp);
}

/* 
 * Flush the contents of the journal to the disk. 
 *
 *  Input: 
 *  	wait_for_IO - 
 *  	If TRUE, wait to write in-memory journal to the disk 
 *  	consistently, and also wait to write all asynchronous 
 *  	metadata blocks to its corresponding locations
 *  	consistently on the disk.  This means that the journal 
 *  	is empty at this point and does not contain any 
 *  	transactions.  This is overkill in normal scenarios  
 *  	but is useful whenever the metadata blocks are required 
 *  	to be consistent on-disk instead of just the journal 
 *  	being consistent; like before live verification 
 *  	and live volume resizing.  
 *
 *  	If FALSE, only wait to write in-memory journal to the 
 *  	disk consistently.  This means that the journal still 
 *  	contains uncommitted transactions and the file system 
 *  	metadata blocks in the journal transactions might be 
 *  	written asynchronously to the disk.  But there is no 
 *  	guarantee that they are written to the disk before 
 *  	returning to the caller.  Note that this option is 
 *  	sufficient for file system data integrity as it 
 *  	guarantees consistent journal content on the disk.
 */
int
hfs_journal_flush(struct hfsmount *hfsmp, boolean_t wait_for_IO)
{
	int ret;

	/* Only peek at hfsmp->jnl while holding the global lock */
	hfs_lock_global (hfsmp, HFS_SHARED_LOCK);
	if (hfsmp->jnl) {
		ret = journal_flush(hfsmp->jnl, wait_for_IO);
	} else {
		ret = 0;
	}
	hfs_unlock_global (hfsmp);
	
	return ret;
}


/*
 * hfs_erase_unused_nodes
 *
 * Check wheter a volume may suffer from unused Catalog B-tree nodes that
 * are not zeroed (due to <rdar://problem/6947811>).  If so, just write
 * zeroes to the unused nodes.
 *
 * How do we detect when a volume needs this repair?  We can't always be
 * certain.  If a volume was created after a certain date, then it may have
 * been created with the faulty newfs_hfs.  Since newfs_hfs only created one
 * clump, we can assume that if a Catalog B-tree is larger than its clump size,
 * that means that the entire first clump must have been written to, which means
 * there shouldn't be unused and unwritten nodes in that first clump, and this
 * repair is not needed.
 *
 * We have defined a bit in the Volume Header's attributes to indicate when the
 * unused nodes have been repaired.  A newer newfs_hfs will set this bit.
 * As will fsck_hfs when it repairs the unused nodes.
 */
int hfs_erase_unused_nodes(struct hfsmount *hfsmp)
{
	int result; 
	struct filefork *catalog;
	int lockflags;
	
	if (hfsmp->vcbAtrb & kHFSUnusedNodeFixMask)
	{
		/* This volume has already been checked and repaired. */
		return 0;
	}

	if ((hfsmp->localCreateDate < kHFSUnusedNodesFixDate))
	{
		/* This volume is too old to have had the problem. */
		hfsmp->vcbAtrb |= kHFSUnusedNodeFixMask;
		return 0;
	}

	catalog = hfsmp->hfs_catalog_cp->c_datafork;
	if (catalog->ff_size > catalog->ff_clumpsize)
	{
		/* The entire first clump must have been in use at some point. */
		hfsmp->vcbAtrb |= kHFSUnusedNodeFixMask;
		return 0;
	}
	
	/*
	 * If we get here, we need to zero out those unused nodes.
	 *
	 * We start a transaction and lock the catalog since we're going to be
	 * making on-disk changes.  But note that BTZeroUnusedNodes doens't actually
	 * do its writing via the journal, because that would be too much I/O
	 * to fit in a transaction, and it's a pain to break it up into multiple
	 * transactions.  (It behaves more like growing a B-tree would.)
	 */
	printf("hfs_erase_unused_nodes: updating volume %s.\n", hfsmp->vcbVN);
	result = hfs_start_transaction(hfsmp);
	if (result)
		goto done;
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
	result = BTZeroUnusedNodes(catalog);
	vnode_waitforwrites(hfsmp->hfs_catalog_vp, 0, 0, 0, "hfs_erase_unused_nodes");
	hfs_systemfile_unlock(hfsmp, lockflags);
	hfs_end_transaction(hfsmp);
	if (result == 0)
		hfsmp->vcbAtrb |= kHFSUnusedNodeFixMask;
	printf("hfs_erase_unused_nodes: done updating volume %s.\n", hfsmp->vcbVN);

done:
	return result;
}


extern time_t snapshot_timestamp;

int
check_for_tracked_file(struct vnode *vp, time_t ctime, uint64_t op_type, void *arg)
{
	int snapshot_error = 0;
	
	if (vp == NULL) {
		return 0;
	}
	
	/* Swap files are special; skip them */
	if (vnode_isswap(vp)) {
		return 0;
	}

	if (ctime != 0 && snapshot_timestamp != 0 && (ctime <= snapshot_timestamp || vnode_needssnapshots(vp))) {
		// the change time is within this epoch
		int error;
		
		error = resolve_nspace_item_ext(vp, op_type | NAMESPACE_HANDLER_SNAPSHOT_EVENT, arg);
		if (error == EDEADLK) {
			snapshot_error = 0;
		} else if (error) {
			if (error == EAGAIN) {
				printf("hfs: cow-snapshot: timed out waiting for namespace handler...\n");
			} else if (error == EINTR) {
				// printf("hfs: cow-snapshot: got a signal while waiting for namespace handler...\n");
				snapshot_error = EINTR;
			}
		}
	}
	
	if (snapshot_error) return snapshot_error;
	
	return 0;
}

int
check_for_dataless_file(struct vnode *vp, uint64_t op_type)
{
	int error;

	if (vp == NULL || (VTOC(vp)->c_bsdflags & UF_COMPRESSED) == 0 || VTOCMP(vp) == NULL || VTOCMP(vp)->cmp_type != DATALESS_CMPFS_TYPE) {
		// there's nothing to do, it's not dataless
		return 0;
	}

	/* Swap files are special; ignore them */
	if (vnode_isswap(vp)) {
		return 0;	
	}

	// printf("hfs: dataless: encountered a file with the dataless bit set! (vp %p)\n", vp);
	error = resolve_nspace_item(vp, op_type | NAMESPACE_HANDLER_NSPACE_EVENT);
	if (error == EDEADLK && op_type == NAMESPACE_HANDLER_WRITE_OP) {
		error = 0;
	} else if (error) {
		if (error == EAGAIN) {
			printf("hfs: dataless: timed out waiting for namespace handler...\n");
			// XXXdbg - return the fabled ENOTPRESENT (i.e. EJUKEBOX)?
			return 0;				
		} else if (error == EINTR) {
			// printf("hfs: dataless: got a signal while waiting for namespace handler...\n");
			return EINTR;
		}
	} else if (VTOC(vp)->c_bsdflags & UF_COMPRESSED) {
		//
		// if we're here, the dataless bit is still set on the file 
		// which means it didn't get handled.  we return an error
		// but it's presently ignored by all callers of this function.
		//
		// XXXdbg - EDATANOTPRESENT is what we really need...
		//
		return EBADF;
	}				

	return error;
}


//
// NOTE: this function takes care of starting a transaction and
//       acquiring the systemfile lock so that it can call
//       cat_update().
//
// NOTE: do NOT hold and cnode locks while calling this function
//       to avoid deadlocks (because we take a lock on the root
//       cnode)
//
int
hfs_generate_document_id(struct hfsmount *hfsmp, uint32_t *docid)
{
	struct vnode *rvp;
	struct cnode *cp;
	int error;
	
	error = VFS_ROOT(HFSTOVFS(hfsmp), &rvp, vfs_context_kernel());
	if (error) {
		return error;
	}

	cp = VTOC(rvp);
	if ((error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT)) != 0) {
		return error;
	}
	struct FndrExtendedDirInfo *extinfo = (struct FndrExtendedDirInfo *)((void *)((char *)&cp->c_attr.ca_finderinfo + 16));
	
	int lockflags;
	if (hfs_start_transaction(hfsmp) != 0) {
		return error;
	}
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
					
	if (extinfo->document_id == 0) {
		// initialize this to start at 3 (one greater than the root-dir id)
		extinfo->document_id = 3;
	}

	*docid = extinfo->document_id++;

	// mark the root cnode dirty
	cp->c_flag |= C_MODIFIED | C_FORCEUPDATE;
	(void) cat_update(hfsmp, &cp->c_desc, &cp->c_attr, NULL, NULL);

	hfs_systemfile_unlock (hfsmp, lockflags);
	(void) hfs_end_transaction(hfsmp);
		
	(void) hfs_unlock(cp);

	vnode_put(rvp);
	rvp = NULL;

	return 0;
}


/* 
 * Return information about number of file system allocation blocks 
 * taken by metadata on a volume.  
 *  
 * This function populates struct hfsinfo_metadata with allocation blocks 
 * used by extents overflow btree, catalog btree, bitmap, attribute btree, 
 * journal file, and sum of all of the above.  
 */
int 
hfs_getinfo_metadata_blocks(struct hfsmount *hfsmp, struct hfsinfo_metadata *hinfo)
{
	int lockflags = 0;
	int ret_lockflags = 0;

	/* Zero out the output buffer */
	bzero(hinfo, sizeof(struct hfsinfo_metadata));

	/* 
	 * Getting number of allocation blocks for all btrees 
	 * should be a quick operation, so we grab locks for 
	 * all of them at the same time
	 */
	lockflags = SFL_CATALOG | SFL_EXTENTS | SFL_BITMAP | SFL_ATTRIBUTE;
	ret_lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_EXCLUSIVE_LOCK);
	/* 
	 * Make sure that we were able to acquire all locks requested 
	 * to protect us against conditions like unmount in progress.
	 */
	if ((lockflags & ret_lockflags) != lockflags) {
		/* Release any locks that were acquired */
		hfs_systemfile_unlock(hfsmp, ret_lockflags);
		return EPERM;
	}

	/* Get information about all the btrees */
	hinfo->extents = hfsmp->hfs_extents_cp->c_datafork->ff_blocks;
	hinfo->catalog = hfsmp->hfs_catalog_cp->c_datafork->ff_blocks;
	hinfo->allocation = hfsmp->hfs_allocation_cp->c_datafork->ff_blocks;
	hinfo->attribute = hfsmp->hfs_attribute_cp->c_datafork->ff_blocks;

	/* Done with btrees, give up the locks */
	hfs_systemfile_unlock(hfsmp, ret_lockflags);

	/* Get information about journal file */
	hinfo->journal = howmany(hfsmp->jnl_size, hfsmp->blockSize);

	/* Calculate total number of metadata blocks */
	hinfo->total = hinfo->extents + hinfo->catalog + 
			hinfo->allocation + hinfo->attribute +
			hinfo->journal;
	
	return 0;
}

static int
hfs_freezewrite_callback(struct vnode *vp, __unused void *cargs)
{
	vnode_waitforwrites(vp, 0, 0, 0, "hfs freeze 8");

	return 0;
}

__private_extern__
int hfs_freeze(struct hfsmount *hfsmp)
{
	// First make sure some other process isn't freezing
	hfs_lock_mount(hfsmp);
	while (hfsmp->hfs_freeze_state != HFS_THAWED) {
		if (msleep(&hfsmp->hfs_freeze_state, &hfsmp->hfs_mutex,
				   PWAIT | PCATCH, "hfs freeze 1", NULL) == EINTR) {
			hfs_unlock_mount(hfsmp);
			return EINTR;
		}
	}

	// Stop new syncers from starting
	hfsmp->hfs_freeze_state = HFS_WANT_TO_FREEZE;

	// Now wait for all syncers to finish
	while (hfsmp->hfs_syncers) {
		if (msleep(&hfsmp->hfs_freeze_state, &hfsmp->hfs_mutex,
			   PWAIT | PCATCH, "hfs freeze 2", NULL) == EINTR) {
			hfs_thaw_locked(hfsmp);
			hfs_unlock_mount(hfsmp);
			return EINTR;				
		}
	}
	hfs_unlock_mount(hfsmp);

	// flush things before we get started to try and prevent
	// dirty data from being paged out while we're frozen.
	// note: we can't do this once we're in the freezing state because
	// other threads will need to take the global lock
	vnode_iterate(hfsmp->hfs_mp, 0, hfs_freezewrite_callback, NULL);

	// Block everything in hfs_lock_global now
	hfs_lock_mount(hfsmp);
	hfsmp->hfs_freeze_state = HFS_FREEZING;
	hfsmp->hfs_freezing_thread = current_thread();
	hfs_unlock_mount(hfsmp);

	/* Take the exclusive lock to flush out anything else that
	   might have the global lock at the moment and also so we
	   can flush the journal. */
	hfs_lock_global(hfsmp, HFS_EXCLUSIVE_LOCK);
	journal_flush(hfsmp->jnl, TRUE);
	hfs_unlock_global(hfsmp);

	// don't need to iterate on all vnodes, we just need to
	// wait for writes to the system files and the device vnode
	//
	// Now that journal flush waits for all metadata blocks to 
	// be written out, waiting for btree writes is probably no
	// longer required.
	if (HFSTOVCB(hfsmp)->extentsRefNum)
		vnode_waitforwrites(HFSTOVCB(hfsmp)->extentsRefNum, 0, 0, 0, "hfs freeze 3");
	if (HFSTOVCB(hfsmp)->catalogRefNum)
		vnode_waitforwrites(HFSTOVCB(hfsmp)->catalogRefNum, 0, 0, 0, "hfs freeze 4");
	if (HFSTOVCB(hfsmp)->allocationsRefNum)
		vnode_waitforwrites(HFSTOVCB(hfsmp)->allocationsRefNum, 0, 0, 0, "hfs freeze 5");
	if (hfsmp->hfs_attribute_vp)
		vnode_waitforwrites(hfsmp->hfs_attribute_vp, 0, 0, 0, "hfs freeze 6");
	vnode_waitforwrites(hfsmp->hfs_devvp, 0, 0, 0, "hfs freeze 7");

	// We're done, mark frozen
	hfs_lock_mount(hfsmp);
	hfsmp->hfs_freeze_state  = HFS_FROZEN;
	hfsmp->hfs_freezing_proc = current_proc();
	hfs_unlock_mount(hfsmp);

	return 0;
}

__private_extern__
int hfs_thaw(struct hfsmount *hfsmp, const struct proc *process)
{
	hfs_lock_mount(hfsmp);

	if (hfsmp->hfs_freeze_state != HFS_FROZEN) {
		hfs_unlock_mount(hfsmp);
		return EINVAL;
	}
	if (process && hfsmp->hfs_freezing_proc != process) {
		hfs_unlock_mount(hfsmp);
		return EPERM;
	}

	hfs_thaw_locked(hfsmp);

	hfs_unlock_mount(hfsmp);

	return 0;
}

static void hfs_thaw_locked(struct hfsmount *hfsmp)
{
	hfsmp->hfs_freezing_proc = NULL;
	hfsmp->hfs_freeze_state = HFS_THAWED;

	wakeup(&hfsmp->hfs_freeze_state);
}
