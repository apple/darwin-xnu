/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
#include <sys/namei.h>
#include <sys/lock.h>
#include <sys/buf.h>
#include <sys/ubc.h>
#include <sys/unistd.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_dbg.h"
#include "hfs_mount.h"
#include "hfs_endian.h"
#include "hfs_cnode.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"


extern int count_lock_queue __P((void));
extern uid_t console_user;


static void ReleaseMetaFileVNode(struct vnode *vp);
static int  hfs_late_journal_init(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp, void *_args);

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
char hfs_catname[] = "Catalog B-tree";
char hfs_extname[] = "Extents B-tree";
char hfs_vbmname[] = "Volume Bitmap";

char hfs_privdirname[] =
	"\xE2\x90\x80\xE2\x90\x80\xE2\x90\x80\xE2\x90\x80HFS+ Private Data";

OSErr hfs_MountHFSVolume(struct hfsmount *hfsmp, HFSMasterDirectoryBlock *mdb,
		struct proc *p)
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
	if ((hfsmp->hfs_fs_ronly == 0) && ((SWAP_BE16(mdb->drAtrb) & kHFSVolumeUnmountedMask) == 0))
		return (EINVAL);
		
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
	if (!hfsmp->hfs_fs_ronly)
		vcb->vcbWrCnt++;	/* Compensate for write of MDB on last flush */

	/* convert hfs encoded name into UTF-8 string */
	error = hfs_to_utf8(vcb, mdb->drVN, NAME_MAX, &utf8chars, vcb->vcbVN);
	/*
	 * When an HFS name cannot be encoded with the current
	 * volume encoding we use MacRoman as a fallback.
	 */
	if (error || (utf8chars == 0))
		(void) mac_roman_to_utf8(mdb->drVN, NAME_MAX, &utf8chars, vcb->vcbVN);

	hfsmp->hfs_logBlockSize = BestBlockSizeFit(vcb->blockSize, MAXBSIZE, hfsmp->hfs_phys_block_size);
	vcb->vcbVBMIOSize = kHFSBlockSize;

	VCB_LOCK_INIT(vcb);

	bzero(&cndesc, sizeof(cndesc));
	cndesc.cd_parentcnid = kRootParID;
	bzero(&cnattr, sizeof(cnattr));
	cnattr.ca_nlink = 1;
	cnattr.ca_mode = S_IFREG;
	bzero(&fork, sizeof(fork));

	/*
	 * Set up Extents B-tree vnode
	 */
	cndesc.cd_nameptr = hfs_extname;
	cndesc.cd_namelen = strlen(hfs_extname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSExtentsFileID;
	fork.cf_size = SWAP_BE32(mdb->drXTFlSize);
	fork.cf_blocks = fork.cf_size / vcb->blockSize;
	fork.cf_clump = SWAP_BE32(mdb->drXTClpSiz);
	fork.cf_extents[0].startBlock = SWAP_BE16(mdb->drXTExtRec[0].startBlock);
	fork.cf_extents[0].blockCount = SWAP_BE16(mdb->drXTExtRec[0].blockCount);
	fork.cf_extents[1].startBlock = SWAP_BE16(mdb->drXTExtRec[1].startBlock);
	fork.cf_extents[1].blockCount = SWAP_BE16(mdb->drXTExtRec[1].blockCount);
	fork.cf_extents[2].startBlock = SWAP_BE16(mdb->drXTExtRec[2].startBlock);
	fork.cf_extents[2].blockCount = SWAP_BE16(mdb->drXTExtRec[2].blockCount);
	cnattr.ca_blocks = fork.cf_blocks;

	error = hfs_getnewvnode(hfsmp, NULL, &cndesc, 0, &cnattr, &fork,
	                        &vcb->extentsRefNum);
	if (error) goto MtVolErr;
	error = MacToVFSError(BTOpenPath(VTOF(vcb->extentsRefNum),
	                                 (KeyCompareProcPtr)CompareExtentKeys,
	                                 GetBTreeBlock, ReleaseBTreeBlock, 
	                                 ExtendBTreeFile, SetBTreeBlockSize));
	if (error) {
		VOP_UNLOCK(vcb->extentsRefNum, 0, p);
		goto MtVolErr;
	}

	/*
	 * Set up Catalog B-tree vnode...
	 */ 
	cndesc.cd_nameptr = hfs_catname;
	cndesc.cd_namelen = strlen(hfs_catname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSCatalogFileID;
	fork.cf_size = SWAP_BE32(mdb->drCTFlSize);
	fork.cf_blocks = fork.cf_size / vcb->blockSize;
	fork.cf_clump = SWAP_BE32(mdb->drCTClpSiz);
	fork.cf_extents[0].startBlock = SWAP_BE16(mdb->drCTExtRec[0].startBlock);
	fork.cf_extents[0].blockCount = SWAP_BE16(mdb->drCTExtRec[0].blockCount);
	fork.cf_extents[1].startBlock = SWAP_BE16(mdb->drCTExtRec[1].startBlock);
	fork.cf_extents[1].blockCount = SWAP_BE16(mdb->drCTExtRec[1].blockCount);
	fork.cf_extents[2].startBlock = SWAP_BE16(mdb->drCTExtRec[2].startBlock);
	fork.cf_extents[2].blockCount = SWAP_BE16(mdb->drCTExtRec[2].blockCount);
	cnattr.ca_blocks = fork.cf_blocks;

	error = hfs_getnewvnode(hfsmp, NULL, &cndesc, 0, &cnattr, &fork,
	                        &vcb->catalogRefNum);
	if (error) {
		VOP_UNLOCK(vcb->extentsRefNum, 0, p);
		goto MtVolErr;
	}
	error = MacToVFSError(BTOpenPath(VTOF(vcb->catalogRefNum),
	                                 (KeyCompareProcPtr)CompareCatalogKeys,
	                                 GetBTreeBlock, ReleaseBTreeBlock,
	                                 ExtendBTreeFile, SetBTreeBlockSize));
	if (error) {
		VOP_UNLOCK(vcb->catalogRefNum, 0, p);
		VOP_UNLOCK(vcb->extentsRefNum, 0, p);
		goto MtVolErr;
	}

      	/* mark the volume dirty (clear clean unmount bit) */
	vcb->vcbAtrb &=	~kHFSVolumeUnmountedMask;

	/*
	 * all done with b-trees so we can unlock now...
	 */
	VOP_UNLOCK(vcb->catalogRefNum, 0, p);
	VOP_UNLOCK(vcb->extentsRefNum, 0, p);

    if ( error == noErr )
      {
        if ( !(vcb->vcbAtrb & kHFSVolumeHardwareLockMask) )		//	if the disk is not write protected
          {
            MarkVCBDirty( vcb );								//	mark VCB dirty so it will be written
          }
      }
    goto	CmdDone;

    //--	Release any resources allocated so far before exiting with an error:
MtVolErr:
	ReleaseMetaFileVNode(vcb->catalogRefNum);
	ReleaseMetaFileVNode(vcb->extentsRefNum);

CmdDone:
    return (error);
}

//*******************************************************************************
//	Routine:	hfs_MountHFSPlusVolume
//
//
//*******************************************************************************

OSErr hfs_MountHFSPlusVolume(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
	off_t embeddedOffset, u_int64_t disksize, struct proc *p, void *args)
{
	register ExtendedVCB *vcb;
	struct cat_desc cndesc;
	struct cat_attr cnattr;
	UInt32 blockSize;
	OSErr retval;

	// XXXdbg - added the kHFSJSigWord case
	if ((SWAP_BE16(vhp->signature) != kHFSPlusSigWord &&
		 SWAP_BE16(vhp->signature) != kHFSJSigWord) ||
	    SWAP_BE16(vhp->version) != kHFSPlusVersion) {
		// XXXdbg
		printf("hfs: mount: sig 0x%x and version 0x%x are not HFS or HFS+.\n",
			   vhp->signature, vhp->version);
		return (EINVAL);
	}

	/* Block size must be at least 512 and a power of 2 */
	blockSize = SWAP_BE32(vhp->blockSize);
	if (blockSize < 512 || (blockSize & (blockSize-1)) != 0)
		return (EINVAL);
   
	/* don't mount a writable volume if its dirty, it must be cleaned by fsck_hfs */
	if (hfsmp->hfs_fs_ronly == 0 && hfsmp->jnl == NULL && (SWAP_BE32(vhp->attributes) & kHFSVolumeUnmountedMask) == 0)
		return (EINVAL);

	/* Make sure we can live with the physical block size. */
	if ((disksize & (hfsmp->hfs_phys_block_size - 1)) ||
	    (embeddedOffset & (hfsmp->hfs_phys_block_size - 1)) ||
	    (SWAP_BE32(vhp->blockSize) < hfsmp->hfs_phys_block_size)) {
		return (ENXIO);
	}
	/*
	 * The VolumeHeader seems OK: transfer info from it into VCB
	 * Note - the VCB starts out clear (all zeros)
	 */
	vcb = HFSTOVCB(hfsmp);

	vcb->vcbSigWord	= SWAP_BE16(vhp->signature);

	// XXXdbg - remap this in case we've mounted a dirty journaled volume
	if (vcb->vcbSigWord == kHFSJSigWord) {
		vcb->vcbSigWord = kHFSPlusSigWord;
	}

	vcb->vcbJinfoBlock = SWAP_BE32(vhp->journalInfoBlock);
	vcb->vcbLsMod	= to_bsd_time(SWAP_BE32(vhp->modifyDate));
	vcb->vcbAtrb	= (UInt16)SWAP_BE32(vhp->attributes);
	vcb->vcbClpSiz	= SWAP_BE32(vhp->rsrcClumpSize);
	vcb->vcbNxtCNID	= SWAP_BE32(vhp->nextCatalogID);
	vcb->vcbVolBkUp	= to_bsd_time(SWAP_BE32(vhp->backupDate));
	vcb->vcbWrCnt	= SWAP_BE32(vhp->writeCount);
	vcb->vcbFilCnt	= SWAP_BE32(vhp->fileCount);
	vcb->vcbDirCnt	= SWAP_BE32(vhp->folderCount);
	
	/* copy 32 bytes of Finder info */
	bcopy(vhp->finderInfo, vcb->vcbFndrInfo, sizeof(vhp->finderInfo));    

	vcb->vcbAlBlSt = 0;		/* hfs+ allocation blocks start at first block of volume */
	if (!hfsmp->hfs_fs_ronly)
		vcb->vcbWrCnt++;	/* compensate for write of Volume Header on last flush */

	VCB_LOCK_INIT(vcb);

	/* Now fill in the Extended VCB info */
	vcb->nextAllocation	= SWAP_BE32(vhp->nextAllocation);
	vcb->totalBlocks	= SWAP_BE32(vhp->totalBlocks);
	vcb->freeBlocks		= SWAP_BE32(vhp->freeBlocks);
	vcb->blockSize		= SWAP_BE32(vhp->blockSize);
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
	hfsmp->hfs_logBlockSize = BestBlockSizeFit(vcb->blockSize, MAXBSIZE, hfsmp->hfs_phys_block_size);
	vcb->vcbVBMIOSize = min(vcb->blockSize, MAXPHYSIO);

	bzero(&cndesc, sizeof(cndesc));
	cndesc.cd_parentcnid = kRootParID;
	bzero(&cnattr, sizeof(cnattr));
	cnattr.ca_nlink = 1;
	cnattr.ca_mode = S_IFREG;

	/*
	 * Set up Extents B-tree vnode
	 */
	cndesc.cd_nameptr = hfs_extname;
	cndesc.cd_namelen = strlen(hfs_extname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSExtentsFileID;

	SWAP_HFS_PLUS_FORK_DATA (&vhp->extentsFile);
	cnattr.ca_blocks = vhp->extentsFile.totalBlocks;

	retval = hfs_getnewvnode(hfsmp, NULL, &cndesc, 0, &cnattr,
	                         (struct cat_fork *)&vhp->extentsFile,
	                         &vcb->extentsRefNum);
	SWAP_HFS_PLUS_FORK_DATA (&vhp->extentsFile);

	if (retval) goto ErrorExit;
	retval = MacToVFSError(BTOpenPath(VTOF(vcb->extentsRefNum),
	                                  (KeyCompareProcPtr) CompareExtentKeysPlus,
	                                  GetBTreeBlock, ReleaseBTreeBlock,
	                                  ExtendBTreeFile, SetBTreeBlockSize));
	if (retval) {
		VOP_UNLOCK(vcb->extentsRefNum, 0, p);
		goto ErrorExit;
	}

	/*
	 * Set up Catalog B-tree vnode
	 */ 
	cndesc.cd_nameptr = hfs_catname;
	cndesc.cd_namelen = strlen(hfs_catname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSCatalogFileID;

	SWAP_HFS_PLUS_FORK_DATA(&vhp->catalogFile);
	cnattr.ca_blocks = vhp->catalogFile.totalBlocks;

	retval = hfs_getnewvnode(hfsmp, NULL, &cndesc, 0, &cnattr,
	                         (struct cat_fork *)&vhp->catalogFile,
	                         &vcb->catalogRefNum);
	SWAP_HFS_PLUS_FORK_DATA(&vhp->catalogFile);
	if (retval) {
		VOP_UNLOCK(vcb->extentsRefNum, 0, p);
		goto ErrorExit;
	}
	retval = MacToVFSError(BTOpenPath(VTOF(vcb->catalogRefNum),
	                                  (KeyCompareProcPtr) CompareExtendedCatalogKeys,
	                                  GetBTreeBlock, ReleaseBTreeBlock,
	                                  ExtendBTreeFile, SetBTreeBlockSize));
	if (retval) {
		VOP_UNLOCK(vcb->catalogRefNum, 0, p);
		VOP_UNLOCK(vcb->extentsRefNum, 0, p);
		goto ErrorExit;
	}

	/*
	 * Set up Allocation file vnode
	 */  
	cndesc.cd_nameptr = hfs_vbmname;
	cndesc.cd_namelen = strlen(hfs_vbmname);
	cndesc.cd_cnid = cnattr.ca_fileid = kHFSAllocationFileID;

	SWAP_HFS_PLUS_FORK_DATA(&vhp->allocationFile);
	cnattr.ca_blocks = vhp->allocationFile.totalBlocks;

	retval = hfs_getnewvnode(hfsmp, NULL, &cndesc, 0, &cnattr,
	                         (struct cat_fork *)&vhp->allocationFile,
	                         &vcb->allocationsRefNum);
	SWAP_HFS_PLUS_FORK_DATA(&vhp->allocationFile);
	if (retval) {
		VOP_UNLOCK(vcb->catalogRefNum, 0, p);
		VOP_UNLOCK(vcb->extentsRefNum, 0, p);
		goto ErrorExit;
	}

	/* Pick up volume name and create date */
	retval = cat_idlookup(hfsmp, kHFSRootFolderID, &cndesc, &cnattr, NULL);
	if (retval) {
		VOP_UNLOCK(vcb->allocationsRefNum, 0, p);
		VOP_UNLOCK(vcb->catalogRefNum, 0, p);
		VOP_UNLOCK(vcb->extentsRefNum, 0, p);
		goto ErrorExit;
	}
	vcb->vcbCrDate = cnattr.ca_itime;
	vcb->volumeNameEncodingHint = cndesc.cd_encoding;
	bcopy(cndesc.cd_nameptr, vcb->vcbVN, min(255, cndesc.cd_namelen));
	cat_releasedesc(&cndesc);

	/* mark the volume dirty (clear clean unmount bit) */
	vcb->vcbAtrb &=	~kHFSVolumeUnmountedMask;
	if (hfsmp->jnl && hfsmp->hfs_fs_ronly == 0) {
		hfs_flushvolumeheader(hfsmp, TRUE, TRUE);
	}

	/*
	 * all done with metadata files so we can unlock now...
	 */
	VOP_UNLOCK(vcb->allocationsRefNum, 0, p);
	VOP_UNLOCK(vcb->catalogRefNum, 0, p);
	VOP_UNLOCK(vcb->extentsRefNum, 0, p);

	/* setup private/hidden directory for unlinked files */
	hfsmp->hfs_private_metadata_dir = FindMetaDataDirectory(vcb);
	if (hfsmp->jnl && (hfsmp->hfs_fs_ronly == 0))
		hfs_remove_orphans(hfsmp);

	if ( !(vcb->vcbAtrb & kHFSVolumeHardwareLockMask) )	// if the disk is not write protected
	{
		MarkVCBDirty( vcb );	// mark VCB dirty so it will be written
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
			goto ErrorExit;
		} else if (hfsmp->jnl) {
			hfsmp->hfs_mp->mnt_flag |= MNT_JOURNALED;
		}
	} else if (hfsmp->jnl) {
		struct cat_attr jinfo_attr, jnl_attr;
		
		// if we're here we need to fill in the fileid's for the
		// journal and journal_info_block.
		hfsmp->hfs_jnlinfoblkid = GetFileInfo(vcb, kRootDirID, ".journal_info_block", &jinfo_attr, NULL);
		hfsmp->hfs_jnlfileid    = GetFileInfo(vcb, kRootDirID, ".journal", &jnl_attr, NULL);
		if (hfsmp->hfs_jnlinfoblkid == 0 || hfsmp->hfs_jnlfileid == 0) {
			printf("hfs: danger! couldn't find the file-id's for the journal or journal_info_block\n");
			printf("hfs: jnlfileid %d, jnlinfoblkid %d\n", hfsmp->hfs_jnlfileid, hfsmp->hfs_jnlinfoblkid);
		}
	}


	return (0);

ErrorExit:
	/*
	 * A fatal error occured and the volume cannot be mounted
	 * release any resources that we aquired...
	 */

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
	struct filefork *fp;

	if (vp && (fp = VTOF(vp))) {
		if (fp->fcbBTCBPtr != NULL)
			(void) BTClosePath(fp);

		/* release the node even if BTClosePath fails */
		vrele(vp);
		vgone(vp);
	}
}


/*************************************************************
*
* Unmounts a hfs volume.
*	At this point vflush() has been called (to dump all non-metadata files)
*
*************************************************************/

short hfsUnmount( register struct hfsmount *hfsmp, struct proc *p)
{
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	int retval = E_NONE;

	InvalidateCatalogCache( vcb );

	if (vcb->vcbSigWord == kHFSPlusSigWord)
		ReleaseMetaFileVNode(vcb->allocationsRefNum);

	ReleaseMetaFileVNode(vcb->catalogRefNum);
	ReleaseMetaFileVNode(vcb->extentsRefNum);

	return (retval);
}


/*
 * Some 3rd party kexts link against hfs_getcatalog so keep a stub for now.
 */
short
hfs_getcatalog(void *p1, u_long p2, void *p3, short p4, void *p5)
{
	return ENOENT;
}


int overflow_extents(struct filefork *fp)
{
	u_long blocks;

	if (VTOVCB(FTOV(fp))->vcbSigWord == kHFSPlusSigWord) {
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


/* __private_extern__ */
int
hfs_metafilelocking(struct hfsmount *hfsmp, u_long fileID, u_int flags, struct proc *p)
{
	ExtendedVCB		*vcb;
	struct vnode	*vp = NULL;
	int				numOfLockedBuffs;
	int	retval = 0;

	vcb = HFSTOVCB(hfsmp);

 	switch (fileID) {
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

	/* Release, if necesary any locked buffer caches */
	if ((flags & LK_TYPE_MASK) == LK_RELEASE) {
		struct timeval tv = time;
		u_int32_t		lastfsync = tv.tv_sec; 
		
		(void) BTGetLastSync((FCB*)VTOF(vp), &lastfsync);
		
		numOfLockedBuffs = count_lock_queue();
		if ((numOfLockedBuffs > kMaxLockedMetaBuffers) || ((numOfLockedBuffs>1) && ((tv.tv_sec - lastfsync) > kMaxSecsForFsync))) {
			hfs_btsync(vp, HFS_SYNCTRANS);
		}
	} else {
		flags |= LK_RETRY;
	}
	
	retval = lockmgr(&VTOC(vp)->c_lock, flags, &vp->v_interlock, p);

	return (retval);
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
	struct lock__bsd__ *lkp;
	int locked = false;
	pid_t pid;
	void * self;

	pid = current_proc()->p_pid;
	self = (void *) current_thread();
	lkp = &VTOC(vp)->c_lock;

	simple_lock(&lkp->lk_interlock);
	
	if (shareable && (lkp->lk_sharecount > 0) && (lkp->lk_lockholder == LK_NOPROC))
		locked = true;
	else if ((lkp->lk_exclusivecount > 0) && (lkp->lk_lockholder == pid) && (lkp->lk_lockthread == self))
		locked = true;

	simple_unlock(&lkp->lk_interlock);
	
	if (!locked) {
		switch (VTOC(vp)->c_fileid) {
			case 3:
				DEBUG_BREAK_MSG((" #\n # RequireFileLock: extent btree vnode not locked! v: 0x%08X\n #\n", (u_int)vp));
				break;

			case 4:
				DEBUG_BREAK_MSG((" #\n # RequireFileLock: catalog btree vnode not locked! v: 0x%08X\n #\n", (u_int)vp));
				break;

			default:
				DEBUG_BREAK_MSG((" #\n # RequireFileLock: file (%d) not locked! v: 0x%08X\n #\n", VTOC(vp)->c_fileid, (u_int)vp));
				break;
		}
	}
}
#endif


/*
 * There are three ways to qualify for ownership rights on an object:
 *
 * 1. (a) Your UID matches the cnode's UID.
 *    (b) The object in question is owned by "unknown" and
 *        your UID matches the console user's UID.
 * 2. (a) Permissions on the filesystem are being ignored and
 *        your UID matches the replacement UID.
 *    (b) Permissions on the filesystem are being ignored and
 *        the replacement UID is "unknown" and
 *        your UID matches the console user UID.
 * 3. You are root.
 *
 */
int
hfs_owner_rights(struct hfsmount *hfsmp, uid_t cnode_uid, struct ucred *cred,
		struct proc *p, int invokesuperuserstatus)
{
	if ((cred->cr_uid == cnode_uid) ||                                    /* [1a] */
	    ((cnode_uid == UNKNOWNUID) && (cred->cr_uid == console_user)) ||  /* [1b] */
	    ((HFSTOVFS(hfsmp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) &&          /* [2] */
	      ((cred->cr_uid == hfsmp->hfs_uid) ||                            /* [2a] */
	        ((hfsmp->hfs_uid == UNKNOWNUID) &&                            /* [2b] */
	          (cred->cr_uid == console_user)))) ||
	    (invokesuperuserstatus && (suser(cred, &p->p_acflag) == 0))) {    /* [3] */
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


/*
 * To make the HFS Plus filesystem follow UFS unlink semantics, a remove
 * of an active vnode is translated to a move/rename so the file appears
 * deleted. The destination folder for these move/renames is setup here
 * and a reference to it is place in hfsmp->hfs_private_metadata_dir.
 */
u_long
FindMetaDataDirectory(ExtendedVCB *vcb)
{
	struct hfsmount * hfsmp;
	struct vnode * dvp = NULL;
	struct cnode * dcp = NULL;
	struct FndrDirInfo * fndrinfo;
	struct cat_desc out_desc = {0};
	struct timeval tv;
	int error;
	
	if (vcb->vcbSigWord != kHFSPlusSigWord)
		return (0);

	hfsmp = VCBTOHFS(vcb);

	if (hfsmp->hfs_privdir_desc.cd_parentcnid == 0) {
		hfsmp->hfs_privdir_desc.cd_parentcnid = kRootDirID;
		hfsmp->hfs_privdir_desc.cd_nameptr = hfs_privdirname;
		hfsmp->hfs_privdir_desc.cd_namelen = strlen(hfs_privdirname);
		hfsmp->hfs_privdir_desc.cd_flags = CD_ISDIR;
	}

	/* Lock catalog b-tree */
	error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, current_proc());	
	if (error)
		return (0);

	error = cat_lookup(hfsmp, &hfsmp->hfs_privdir_desc, 0, NULL,
			&hfsmp->hfs_privdir_attr, NULL);

	if (error == 0) {
		/* Unlock catalog b-tree */
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, current_proc());
		hfsmp->hfs_metadata_createdate = hfsmp->hfs_privdir_attr.ca_itime;
		return (hfsmp->hfs_privdir_attr.ca_fileid);
	} else if (hfsmp->hfs_fs_ronly) {
		/* Unlock catalog b-tree */
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, current_proc());
		return (0);
	}
    
	/* Setup the default attributes */
	bzero(&hfsmp->hfs_privdir_attr, sizeof(struct cat_attr));
	hfsmp->hfs_privdir_attr.ca_mode = S_IFDIR;
	hfsmp->hfs_privdir_attr.ca_flags = SF_IMMUTABLE;
	hfsmp->hfs_privdir_attr.ca_nlink = 2;
	hfsmp->hfs_privdir_attr.ca_itime = vcb->vcbCrDate;
	hfsmp->hfs_privdir_attr.ca_mtime = time.tv_sec;

	/* hidden and off the desktop view */
	fndrinfo = (struct FndrDirInfo *)&hfsmp->hfs_privdir_attr.ca_finderinfo;
	fndrinfo->frLocation.v = SWAP_BE16 (22460);
	fndrinfo->frLocation.h = SWAP_BE16 (22460);
	fndrinfo->frFlags |= SWAP_BE16 (kIsInvisible + kNameLocked);		

	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
	    if ((error = journal_start_transaction(hfsmp->jnl)) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			return (0);
	    }
	}

	error = cat_create(hfsmp, &hfsmp->hfs_privdir_desc,
			&hfsmp->hfs_privdir_attr, &out_desc);

	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, current_proc());
	if (error) {
	    if (hfsmp->jnl) {
			journal_end_transaction(hfsmp->jnl);
	    }
		hfs_global_shared_lock_release(hfsmp);

	    return (0);
	}

	hfsmp->hfs_privdir_desc.cd_hint = out_desc.cd_hint;
	hfsmp->hfs_privdir_desc.cd_cnid = out_desc.cd_cnid;
	hfsmp->hfs_privdir_attr.ca_fileid = out_desc.cd_cnid;
	hfsmp->hfs_metadata_createdate = vcb->vcbCrDate;
	
	if (VFS_ROOT(HFSTOVFS(hfsmp), &dvp) == 0) {
		dcp = VTOC(dvp);
		dcp->c_childhint = out_desc.cd_hint;
		dcp->c_nlink++;
		dcp->c_entries++;
		dcp->c_flag |= C_CHANGE | C_UPDATE;
		tv = time;
		(void) VOP_UPDATE(dvp, &tv, &tv, 0);
		vput(dvp);
	}
	hfs_volupdate(hfsmp, VOL_MKDIR, 1);
	if (hfsmp->jnl) {
	    journal_end_transaction(hfsmp->jnl);
	} 
	hfs_global_shared_lock_release(hfsmp);

	cat_releasedesc(&out_desc);

	return (out_desc.cd_cnid);
}

__private_extern__
u_long
GetFileInfo(ExtendedVCB *vcb, u_int32_t dirid, char *name,
			struct cat_attr *fattr, struct cat_fork *forkinfo)
{
	struct hfsmount * hfsmp;
	struct vnode * dvp = NULL;
	struct cnode * dcp = NULL;
	struct FndrDirInfo * fndrinfo;
	struct cat_desc jdesc;
	struct timeval tv;
	int error;
	
	if (vcb->vcbSigWord != kHFSPlusSigWord)
		return (0);

	hfsmp = VCBTOHFS(vcb);

	memset(&jdesc, 0, sizeof(struct cat_desc));
	jdesc.cd_parentcnid = kRootDirID;
	jdesc.cd_nameptr = name;
	jdesc.cd_namelen = strlen(name);

	/* Lock catalog b-tree */
	error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, current_proc());	
	if (error)
		return (0);

	error = cat_lookup(hfsmp, &jdesc, 0, NULL, fattr, forkinfo);

	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, current_proc());

	if (error == 0) {
		return (fattr->ca_fileid);
	} else if (hfsmp->hfs_fs_ronly) {
		return (0);
	}
}


/*
 * On Journaled HFS, there can be orphaned files.  These
 * are files that were unlinked while busy. If the volume
 * was not cleanly unmounted then some of these files may
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
	FCB *fcb;
	ExtendedVCB *vcb;
	char filename[32];
	char tempname[32];
	size_t namelen;
	int catlock = 0;
	int result, started_tr = 0;
	
	if (hfsmp->hfs_orphans_cleaned)
		return;

	vcb = HFSTOVCB(hfsmp);
	fcb = VTOF(vcb->catalogRefNum);

	btdata.bufferAddress = &filerec;
	btdata.itemSize = sizeof(filerec);
	btdata.itemCount = 1;

	MALLOC(iterator, struct BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	keyp = (HFSPlusCatalogKey*)&iterator->key;
	keyp->parentID = hfsmp->hfs_private_metadata_dir;

	// XXXdbg
	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
	    if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			return;
	    }
		started_tr = 1;
	}

	/* Lock catalog b-tree */
	result = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_EXCLUSIVE, current_proc());	
	if (result)
		goto exit;
	catlock = 1;

	/*
	 * Position the iterator at the folder thread record.
	 * (i.e. one record before first child)
	 */
	result = BTSearchRecord(fcb, iterator, NULL, NULL, iterator);
	if (result)
		goto exit;

	/* Visit all the children in the HFS+ private directory. */
	for (;;) {
		result = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
		if (result)
			break;
		if (keyp->parentID != hfsmp->hfs_private_metadata_dir)
			break;
		if (filerec.recordType != kHFSPlusFileRecord)
			continue;
		
		(void) utf8_encodestr(keyp->nodeName.unicode, keyp->nodeName.length * 2,
		                      filename, &namelen, sizeof(filename), 0, 0);
		
		(void) sprintf(tempname, "%s%d", HFS_DELETE_PREFIX, filerec.fileID);
		
		/*
		 * Delete all files named "tempxxx", where
		 * xxx is the file's cnid in decimal.
		 *
		 * Delete all files named "iNodexxx", that
		 * have a link count of zero.
		 */
		if (bcmp(tempname, filename, namelen) == 0) {
   			struct filefork fork = {0};
   			struct cnode cnode = {0};

			// XXXdebug
			//printf("hfs_remove_orphans: removing %s\n", filename);

			/* Build a fake cnode */
			cnode.c_desc.cd_parentcnid = hfsmp->hfs_private_metadata_dir;
			cnode.c_desc.cd_nameptr = filename;
			cnode.c_desc.cd_namelen = namelen;
			cnode.c_desc.cd_cnid = filerec.fileID;
			cnode.c_attr.ca_fileid = filerec.fileID;
			cnode.c_blocks = filerec.dataFork.totalBlocks +
			                 filerec.resourceFork.totalBlocks;

			/* Position iterator at previous entry */
			if (BTIterateRecord(fcb, kBTreePrevRecord, iterator,
			    NULL, NULL) != 0)
				break;
			
			/* Truncate the file to zero (both forks) */
			if (filerec.dataFork.totalBlocks > 0) {
				fork.ff_cp = &cnode;
				cnode.c_datafork = &fork;
				bcopy(&filerec.dataFork, &fork.ff_data, sizeof(struct cat_fork));
				if (TruncateFileC(vcb, (FCB*)&fork, 0, false) != 0) {
					printf("error truncting data fork!\n");
					break;
				}
			}
			if (filerec.resourceFork.totalBlocks > 0) {
				fork.ff_cp = &cnode;
				cnode.c_datafork = NULL;
				cnode.c_rsrcfork = &fork;
				bcopy(&filerec.resourceFork, &fork.ff_data, sizeof(struct cat_fork));
				if (TruncateFileC(vcb, (FCB*)&fork, 0, false) != 0) {
					printf("error truncting rsrc fork!\n");
					break;
				}
			}

			/* Remove the file record from the Catalog */	
			if (cat_delete(hfsmp, &cnode.c_desc, &cnode.c_attr) != 0) {
				printf("error deleting cat rec!\n");
				break;
			}
			
			/* Update parent and volume counts */	
			hfsmp->hfs_privdir_attr.ca_entries--;
			(void)cat_update(hfsmp, &hfsmp->hfs_privdir_desc,
			                 &hfsmp->hfs_privdir_attr, NULL, NULL);
 			hfs_volupdate(hfsmp, VOL_RMFILE, 0);
		}
	}
	
exit:
	/* Unlock catalog b-tree */
	if (catlock)
		(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, current_proc());

	if (started_tr) {
		journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);

	FREE(iterator, M_TEMP);
	hfsmp->hfs_orphans_cleaned = 1;
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
	struct vcb_t *vcb = HFSTOVCB(hfsmp);
	u_int32_t freeblks;

	freeblks = vcb->freeBlocks;
	if (wantreserve) {
		if (freeblks > vcb->reserveBlocks)
			freeblks -= vcb->reserveBlocks;
		else
			freeblks = 0;
	}

	freeblks -= vcb->loanedBlocks;
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
		return ENOSPC;
	case btNoSpaceAvail:	/* -32733 */
		return EFBIG;
	case fxOvFlErr:			/* -32750 */
		return EOVERFLOW;
	
	case btBadNode:			/* -32731 */
		return EBADF;
	
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
 * Get the directory entry name hint for a given index.
 * The directory cnode (dcp) must be locked.
 */
__private_extern__
char *
hfs_getnamehint(struct cnode *dcp, int index)
{
	struct hfs_index *entry;
	void *self;

	if (index > 0) {
		self = current_thread();
		SLIST_FOREACH(entry, &dcp->c_indexlist, hi_link) {
			if ((entry->hi_index == index)
			&&  (entry->hi_thread == self))
				return (entry->hi_name);
		}
	}

	return (NULL);
}

/*
 * Save a directory entry name hint for a given index.
 * The directory cnode (dcp) must be locked.
 */
__private_extern__
void
hfs_savenamehint(struct cnode *dcp, int index, const char * namehint)
{
	struct hfs_index *entry;
	int len;

	if (index > 0) {
		len = strlen(namehint);
		MALLOC(entry, struct hfs_index *, len + sizeof(struct hfs_index),
			M_TEMP, M_WAITOK);
		entry->hi_index = index;
		entry->hi_thread = current_thread();
		bcopy(namehint, entry->hi_name, len + 1);
		SLIST_INSERT_HEAD(&dcp->c_indexlist, entry, hi_link);
	}
}

/*
 * Release the directory entry name hint for a given index.
 * The directory cnode (dcp) must be locked.
 */
__private_extern__
void
hfs_relnamehint(struct cnode *dcp, int index)
{
	struct hfs_index *entry;
	void *self;

	if (index > 0) {
		self = current_thread();
		SLIST_FOREACH(entry, &dcp->c_indexlist, hi_link) {
			if ((entry->hi_index == index)
			&&  (entry->hi_thread == self)) {
				SLIST_REMOVE(&dcp->c_indexlist, entry, hfs_index,
					hi_link);
				FREE(entry, M_TEMP);
				break;
			}
		}
	}
}

/*
 * Release all directory entry name hints.
 */
__private_extern__
void
hfs_relnamehints(struct cnode *dcp)
{
	struct hfs_index *entry;
	struct hfs_index *next;

	if (!SLIST_EMPTY(&dcp->c_indexlist)) {
		for(entry = SLIST_FIRST(&dcp->c_indexlist);
		    entry != NULL;
		    entry = next) {
			next = SLIST_NEXT(entry, hi_link);
			SLIST_REMOVE(&dcp->c_indexlist, entry, hfs_index, hi_link);
			FREE(entry, M_TEMP);
		}
	}
}


/*
 * Perform a case-insensitive compare of two UTF-8 filenames.
 *
 * Returns 0 if the strings match.
 */
__private_extern__
int
hfs_namecmp(const char *str1, size_t len1, const char *str2, size_t len2)
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
					   void *_args, int embeddedOffset, int mdb_offset,
					   HFSMasterDirectoryBlock *mdbp, struct ucred *cred)
{
	JournalInfoBlock *jibp;
	struct buf       *jinfo_bp, *bp;
	int               sectors_per_fsblock, arg_flags=0, arg_tbufsz=0;
	int               retval, blksize = hfsmp->hfs_phys_block_size;
	struct vnode     *devvp;
	struct hfs_mount_args *args = _args;

	devvp = hfsmp->hfs_devvp;

	if (args != NULL && (args->flags & HFSFSMNT_EXTENDED_ARGS)) {
		arg_flags  = args->journal_flags;
		arg_tbufsz = args->journal_tbuffer_size;
	}

	sectors_per_fsblock = SWAP_BE32(vhp->blockSize) / blksize;
				
	retval = meta_bread(devvp,
						embeddedOffset/blksize + 
						(SWAP_BE32(vhp->journalInfoBlock)*sectors_per_fsblock),
						SWAP_BE32(vhp->blockSize), cred, &jinfo_bp);
	if (retval)
		return retval;

	jibp = (JournalInfoBlock *)jinfo_bp->b_data;
	jibp->flags  = SWAP_BE32(jibp->flags);
	jibp->offset = SWAP_BE64(jibp->offset);
	jibp->size   = SWAP_BE64(jibp->size);

	if (jibp->flags & kJIJournalInFSMask) {
		hfsmp->jvp = hfsmp->hfs_devvp;
	} else {
		printf("hfs: journal not stored in fs! don't know what to do.\n");
		brelse(jinfo_bp);
		return EINVAL;
	}

	// save this off for the hack-y check in hfs_remove()
	hfsmp->jnl_start = jibp->offset / SWAP_BE32(vhp->blockSize);

	if (jibp->flags & kJIJournalNeedInitMask) {
		printf("hfs: Initializing the journal (joffset 0x%llx sz 0x%llx)...\n",
			   jibp->offset + (off_t)embeddedOffset, jibp->size);
		hfsmp->jnl = journal_create(hfsmp->jvp,
									jibp->offset + (off_t)embeddedOffset,
									jibp->size,
									devvp,
									blksize,
									arg_flags,
									arg_tbufsz,
									hfs_sync_metadata, hfsmp->hfs_mp);

		// no need to start a transaction here... if this were to fail
		// we'd just re-init it on the next mount.
		jibp->flags &= ~kJIJournalNeedInitMask;
		jibp->flags  = SWAP_BE32(jibp->flags);
		bwrite(jinfo_bp);
		jinfo_bp = NULL;
		jibp     = NULL;
	} else { 
		//printf("hfs: Opening the journal (joffset 0x%llx sz 0x%llx vhp_blksize %d)...\n",
		//	   jibp->offset + (off_t)embeddedOffset,
		//	   jibp->size, SWAP_BE32(vhp->blockSize));
				
		hfsmp->jnl = journal_open(hfsmp->jvp,
								  jibp->offset + (off_t)embeddedOffset,
								  jibp->size,
								  devvp,
								  blksize,
								  arg_flags,
								  arg_tbufsz,
								  hfs_sync_metadata, hfsmp->hfs_mp);

		brelse(jinfo_bp);
		jinfo_bp = NULL;
		jibp     = NULL;

		if (hfsmp->jnl && mdbp) {
			// reload the mdb because it could have changed
			// if the journal had to be replayed.
			retval = meta_bread(devvp, mdb_offset, blksize, cred, &bp);
			if (retval) {
				brelse(bp);
				printf("hfs: failed to reload the mdb after opening the journal (retval %d)!\n",
					   retval);
				return retval;
			}
			bcopy(bp->b_data + HFS_PRI_OFFSET(blksize), mdbp, 512);
			brelse(bp);
			bp = NULL;
		}
	}


	//printf("journal @ 0x%x\n", hfsmp->jnl);
	
	// if we expected the journal to be there and we couldn't
	// create it or open it then we have to bail out.
	if (hfsmp->jnl == NULL) {
		hfsmp->jnl_start = 0;
		
		printf("hfs: failed to open/create the journal (retval %d).\n", retval);
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
	struct buf       *jinfo_bp, *bp;
	int               sectors_per_fsblock, arg_flags=0, arg_tbufsz=0;
	int               retval, need_flush = 0, write_jibp = 0;
	struct vnode     *devvp;
	struct cat_attr   jib_attr, jattr;
	struct cat_fork   jib_fork, jfork;
	ExtendedVCB      *vcb;
	u_long            fid;
	struct hfs_mount_args *args = _args;
	
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
	}


	sectors_per_fsblock = SWAP_BE32(vhp->blockSize) / hfsmp->hfs_phys_block_size;
	retval = meta_bread(devvp,
						vcb->hfsPlusIOPosOffset / hfsmp->hfs_phys_block_size + 
						(SWAP_BE32(vhp->journalInfoBlock)*sectors_per_fsblock),
						SWAP_BE32(vhp->blockSize), NOCRED, &jinfo_bp);
	if (retval) {
		printf("hfs: can't read journal info block. disabling journaling.\n");
		vcb->vcbAtrb &= ~kHFSVolumeJournaledMask;
		return 0;
	}

	jibp = (JournalInfoBlock *)jinfo_bp->b_data;
	jibp->flags  = SWAP_BE32(jibp->flags);
	jibp->offset = SWAP_BE64(jibp->offset);
	jibp->size   = SWAP_BE64(jibp->size);

	fid = GetFileInfo(vcb, kRootDirID, ".journal", &jattr, &jfork);
	if (fid == 0 || jfork.cf_extents[0].startBlock == 0 || jfork.cf_size == 0) {
		printf("hfs: can't find the journal file! disabling journaling (start: %d)\n",
			   jfork.cf_extents[0].startBlock);
		brelse(jinfo_bp);
		vcb->vcbAtrb &= ~kHFSVolumeJournaledMask;
		return 0;
	}
	hfsmp->hfs_jnlfileid = fid;

	// make sure the journal file begins where we think it should.
	if ((jibp->offset / (u_int64_t)vcb->blockSize) != jfork.cf_extents[0].startBlock) {
		printf("hfs: The journal file moved (was: %lld; is: %d).  Fixing up\n",
			   (jibp->offset / (u_int64_t)vcb->blockSize), jfork.cf_extents[0].startBlock);

		jibp->offset = (u_int64_t)jfork.cf_extents[0].startBlock * (u_int64_t)vcb->blockSize;
		write_jibp   = 1;
	}

	// check the size of the journal file.
	if (jibp->size != (u_int64_t)jfork.cf_extents[0].blockCount*vcb->blockSize) {
		printf("hfs: The journal file changed size! (was %lld; is %lld).  Fixing up.\n",
			   jibp->size, (u_int64_t)jfork.cf_extents[0].blockCount*vcb->blockSize);
		
		jibp->size = (u_int64_t)jfork.cf_extents[0].blockCount * vcb->blockSize;
		write_jibp = 1;
	}
	
	if (jibp->flags & kJIJournalInFSMask) {
		hfsmp->jvp = hfsmp->hfs_devvp;
	} else {
		printf("hfs: journal not stored in fs! don't know what to do.\n");
		brelse(jinfo_bp);
		return EINVAL;
	}

	// save this off for the hack-y check in hfs_remove()
	hfsmp->jnl_start = jibp->offset / SWAP_BE32(vhp->blockSize);

	if (jibp->flags & kJIJournalNeedInitMask) {
		printf("hfs: Initializing the journal (joffset 0x%llx sz 0x%llx)...\n",
			   jibp->offset + (off_t)vcb->hfsPlusIOPosOffset, jibp->size);
		hfsmp->jnl = journal_create(hfsmp->jvp,
									jibp->offset + (off_t)vcb->hfsPlusIOPosOffset,
									jibp->size,
									devvp,
									hfsmp->hfs_phys_block_size,
									arg_flags,
									arg_tbufsz,
									hfs_sync_metadata, hfsmp->hfs_mp);

		// no need to start a transaction here... if this were to fail
		// we'd just re-init it on the next mount.
		jibp->flags &= ~kJIJournalNeedInitMask;
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
		//	   jibp->offset + (off_t)vcb->hfsPlusIOPosOffset,
		//	   jibp->size, SWAP_BE32(vhp->blockSize));
				
		hfsmp->jnl = journal_open(hfsmp->jvp,
								  jibp->offset + (off_t)vcb->hfsPlusIOPosOffset,
								  jibp->size,
								  devvp,
								  hfsmp->hfs_phys_block_size,
								  arg_flags,
								  arg_tbufsz,
								  hfs_sync_metadata, hfsmp->hfs_mp);
	}
			

	if (write_jibp) {
		jibp->flags  = SWAP_BE32(jibp->flags);
		jibp->offset = SWAP_BE64(jibp->offset);
		jibp->size   = SWAP_BE64(jibp->size);

		bwrite(jinfo_bp);
	} else {
		brelse(jinfo_bp);
	} 
	jinfo_bp = NULL;
	jibp     = NULL;

	//printf("journal @ 0x%x\n", hfsmp->jnl);
	
	// if we expected the journal to be there and we couldn't
	// create it or open it then we have to bail out.
	if (hfsmp->jnl == NULL) {
		hfsmp->jnl_start = 0;
		
		printf("hfs: failed to open/create the journal (retval %d).\n", retval);
		return EINVAL;
	}

	return 0;
}
