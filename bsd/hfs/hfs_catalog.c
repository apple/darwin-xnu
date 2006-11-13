/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <vfs/vfs_support.h>
#include <libkern/libkern.h>

#include <sys/utfconv.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_format.h"
#include "hfs_endian.h"

#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"


/*
 * Initialization of an FSBufferDescriptor structure.
 */
#define BDINIT(bd, addr) { \
	(bd).bufferAddress = (addr); \
	(bd).itemSize = sizeof(*(addr)); \
	(bd).itemCount = 1; \
}


struct btobj {
	BTreeIterator		iterator;
	HFSPlusCatalogKey 	key;
	CatalogRecord		data;
};

struct update_state {
	struct cat_desc *	s_desc;	
	struct cat_attr *	s_attr;
	struct cat_fork *	s_datafork;
	struct cat_fork *	s_rsrcfork;
	struct hfsmount *	s_hfsmp;
};

struct position_state {
	int        error;
	u_int32_t  count;
	u_int32_t  index;
	u_int32_t  parentID;
	struct hfsmount *hfsmp;
};

/* Map file mode type to directory entry types */
u_char modetodirtype[16] = {
	DT_REG, DT_FIFO, DT_CHR, DT_UNKNOWN,
	DT_DIR, DT_UNKNOWN, DT_BLK, DT_UNKNOWN,
	DT_REG, DT_UNKNOWN, DT_LNK, DT_UNKNOWN,
	DT_SOCK, DT_UNKNOWN, DT_WHT, DT_UNKNOWN
};
#define MODE_TO_DT(mode)  (modetodirtype[((mode) & S_IFMT) >> 12])


static int cat_lookupbykey(struct hfsmount *hfsmp, CatalogKey *keyp, u_long hint, int wantrsrc,
                  struct cat_desc *descp, struct cat_attr *attrp, struct cat_fork *forkp, cnid_t *desc_cnid);

static int cat_lookupmangled(struct hfsmount *hfsmp, struct cat_desc *descp, int wantrsrc,
                  struct cat_desc *outdescp, struct cat_attr *attrp, struct cat_fork *forkp);

extern int mac_roman_to_unicode(const Str31 hfs_str, UniChar *uni_str,
                                UInt32 maxCharLen, UInt32 *unicodeChars);

extern int unicode_to_hfs(ExtendedVCB *vcb, ByteCount srcLen,
                          const u_int16_t* srcStr, Str31 dstStr, int retry);


/* Internal catalog support routines */

static int cat_findposition(const CatalogKey *ckp, const CatalogRecord *crp,
                            struct position_state *state);

static int resolvelinkid(struct hfsmount *hfsmp, u_long linkref, ino_t *ino);

static int getkey(struct hfsmount *hfsmp, cnid_t cnid, CatalogKey * key);

static int buildkey(struct hfsmount *hfsmp, struct cat_desc *descp,
			HFSPlusCatalogKey *key, int retry);

static void buildthreadkey(HFSCatalogNodeID parentID, int std_hfs, CatalogKey *key);

static void buildrecord(struct cat_attr *attrp, cnid_t cnid, int std_hfs, u_int32_t encoding, CatalogRecord *crp, int *recordSize);

static int catrec_update(const CatalogKey *ckp, CatalogRecord *crp, struct update_state *state);

static int builddesc(const HFSPlusCatalogKey *key, cnid_t cnid, u_long hint, u_long encoding,
			int isdir, struct cat_desc *descp);

static void getbsdattr(struct hfsmount *hfsmp, const struct HFSPlusCatalogFile *crp, struct cat_attr * attrp);

static void promotekey(struct hfsmount *hfsmp, const HFSCatalogKey *hfskey, HFSPlusCatalogKey *keyp, u_long *encoding);
static void promotefork(struct hfsmount *hfsmp, const struct HFSCatalogFile *file, int resource, struct cat_fork * forkp);
static void promoteattr(struct hfsmount *hfsmp, const CatalogRecord *dataPtr, struct HFSPlusCatalogFile *crp);

static cnid_t getcnid(const CatalogRecord *crp);
static u_long getencoding(const CatalogRecord *crp);
static cnid_t getparentcnid(const CatalogRecord *recp);

static int isadir(const CatalogRecord *crp);

static int buildthread(void *keyp, void *recp, int std_hfs, int directory);


__private_extern__
int
cat_preflight(struct hfsmount *hfsmp, catops_t ops, cat_cookie_t *cookie, struct proc *p)
{
	FCB *fcb;
	int lockflags;
	int result;

	fcb = GetFileControlBlock(hfsmp->hfs_catalog_vp);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
	 
	result = BTReserveSpace(fcb, ops, (void*)cookie);
	
	hfs_systemfile_unlock(hfsmp, lockflags);

	return MacToVFSError(result);
}

__private_extern__
void
cat_postflight(struct hfsmount *hfsmp, cat_cookie_t *cookie, struct proc *p)
{
	FCB *fcb;
	int lockflags;

	fcb = GetFileControlBlock(hfsmp->hfs_catalog_vp);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);

	(void) BTReleaseReserve(fcb, (void*)cookie);

	hfs_systemfile_unlock(hfsmp, lockflags);
}

 
__private_extern__
void
cat_convertattr(
	struct hfsmount *hfsmp,
	CatalogRecord * recp,
	struct cat_attr *attrp,
	struct cat_fork *datafp,
	struct cat_fork *rsrcfp)
{
	int std_hfs = HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord;

	if (std_hfs) {
		struct HFSPlusCatalogFile cnoderec;

		promoteattr(hfsmp, recp, &cnoderec);
		getbsdattr(hfsmp, &cnoderec, attrp);
	} else {
		getbsdattr(hfsmp, (struct HFSPlusCatalogFile *)recp, attrp);
	}

	if (isadir(recp))
		bzero(datafp, sizeof(*datafp));
	else if (std_hfs) {
		promotefork(hfsmp, (HFSCatalogFile *)&recp->hfsFile, 0, datafp);
		promotefork(hfsmp, (HFSCatalogFile *)&recp->hfsFile, 1, rsrcfp);
	} else {
		/* Convert the data fork. */
		datafp->cf_size = recp->hfsPlusFile.dataFork.logicalSize;
		datafp->cf_blocks = recp->hfsPlusFile.dataFork.totalBlocks;
		if ((hfsmp->hfc_stage == HFC_RECORDING) &&
		    (attrp->ca_atime >= hfsmp->hfc_timebase)) {
			datafp->cf_bytesread =
				recp->hfsPlusFile.dataFork.clumpSize *
				HFSTOVCB(hfsmp)->blockSize;
		} else {
			datafp->cf_bytesread = 0;
		}
		datafp->cf_vblocks = 0;
		bcopy(&recp->hfsPlusFile.dataFork.extents[0],
		      &datafp->cf_extents[0], sizeof(HFSPlusExtentRecord));

		/* Convert the resource fork. */
		rsrcfp->cf_size = recp->hfsPlusFile.resourceFork.logicalSize;
		rsrcfp->cf_blocks = recp->hfsPlusFile.resourceFork.totalBlocks;
		if ((hfsmp->hfc_stage == HFC_RECORDING) &&
		    (attrp->ca_atime >= hfsmp->hfc_timebase)) {
			datafp->cf_bytesread =
				recp->hfsPlusFile.resourceFork.clumpSize *
				HFSTOVCB(hfsmp)->blockSize;
		} else {
			datafp->cf_bytesread = 0;
		}
		rsrcfp->cf_vblocks = 0;
		bcopy(&recp->hfsPlusFile.resourceFork.extents[0],
		      &rsrcfp->cf_extents[0], sizeof(HFSPlusExtentRecord));
	}
}

__private_extern__
int
cat_convertkey(
	struct hfsmount *hfsmp,
	CatalogKey *key,
	CatalogRecord * recp,
	struct cat_desc *descp)
{
	int std_hfs = HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord;
	HFSPlusCatalogKey * pluskey = NULL;
	u_long encoding;

	if (std_hfs) {
		MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
		promotekey(hfsmp, (HFSCatalogKey *)key, pluskey, &encoding);

	} else {
		pluskey = (HFSPlusCatalogKey *)key;
		encoding = getencoding(recp);
	}

	builddesc(pluskey, getcnid(recp), 0, encoding, isadir(recp), descp);
	if (std_hfs) {
		FREE(pluskey, M_TEMP);
	}
	return (0);
}


/*
 * cat_releasedesc
 */
__private_extern__
void
cat_releasedesc(struct cat_desc *descp)
{
	char * name;

	if (descp == NULL)
		return;

	if ((descp->cd_flags & CD_HASBUF) &&
	    (descp->cd_nameptr != NULL)) {
	    	name = descp->cd_nameptr;
		descp->cd_nameptr = NULL;
		descp->cd_namelen = 0;
		descp->cd_flags &= ~CD_HASBUF;
		vfs_removename(name);
	}
	descp->cd_nameptr = NULL;
	descp->cd_namelen = 0;
}

/*
 * These Catalog functions allow access to the HFS Catalog (database).
 * The catalog b-tree lock must be aquired before calling any of these routines.
 */

/*
 * cat_lookup - lookup a catalog node using a cnode decriptor
 */
__private_extern__
int
cat_lookup(struct hfsmount *hfsmp, struct cat_desc *descp, int wantrsrc,
             struct cat_desc *outdescp, struct cat_attr *attrp,
             struct cat_fork *forkp, cnid_t *desc_cnid)
{
	CatalogKey * keyp;
	int std_hfs;
	int result;

	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);

	MALLOC(keyp, CatalogKey *, sizeof(CatalogKey), M_TEMP, M_WAITOK);

	result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)keyp, 1);
	if (result)
		goto exit;

	result = cat_lookupbykey(hfsmp, keyp, descp->cd_hint, wantrsrc, outdescp, attrp, forkp, desc_cnid);
	
	if (result == ENOENT) {
		if (!std_hfs) {
			struct cat_desc temp_desc;
			if (outdescp == NULL) {
				bzero(&temp_desc, sizeof(temp_desc));
				outdescp = &temp_desc;
			}
			result = cat_lookupmangled(hfsmp, descp, wantrsrc, outdescp, attrp, forkp);
			if (desc_cnid) {
			    *desc_cnid = outdescp->cd_cnid;
			}
			if (outdescp == &temp_desc) {
				/* Release the local copy of desc */
				cat_releasedesc(outdescp);
			}
		} else if (hfsmp->hfs_encoding != kTextEncodingMacRoman) {
		//	make MacRoman key from utf-8
		//	result = cat_lookupbykey(hfsmp, keyp, descp->cd_hint, attrp, forkp);
		//	update desc text encoding so that other catalog ops succeed
		}
	}
exit:	
	FREE(keyp, M_TEMP);

	return (result);
}

__private_extern__
int
cat_insertfilethread(struct hfsmount *hfsmp, struct cat_desc *descp)
{
	struct BTreeIterator *iterator;
	struct FSBufferDescriptor file_data;
	struct HFSCatalogFile file_rec;
	UInt16 datasize;
	FCB *fcb;
	int result;

	if (HFSTOVCB(hfsmp)->vcbSigWord != kHFSSigWord)
		return (EINVAL);

	fcb = GetFileControlBlock(HFSTOVCB(hfsmp)->catalogRefNum);

	MALLOC(iterator, BTreeIterator *, 2 * sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(&iterator[0], 2* sizeof(*iterator));
	result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)&iterator[0].key, 0);
	if (result)
		goto exit;

	BDINIT(file_data, &file_rec);
	result = BTSearchRecord(fcb, &iterator[0], &file_data, &datasize, &iterator[0]);
	if (result) 
		goto exit;

	if (file_rec.recordType != kHFSFileRecord) {
		result = EISDIR;
		goto exit;
	}

	if ((file_rec.flags & kHFSThreadExistsMask) == 0) {
		struct FSBufferDescriptor thread_data;
		struct HFSCatalogThread thread_rec;

		file_rec.flags |= kHFSThreadExistsMask;
		BDINIT(thread_data, &thread_rec);
		thread_data.itemSize = buildthread(&iterator[0].key, &thread_rec, 1, 0);
		buildthreadkey(file_rec.fileID, 1, (CatalogKey *)&iterator[1].key);
	
		result = BTInsertRecord(fcb, &iterator[1], &thread_data, thread_data.itemSize);
		if (result)
			goto exit;
	
		(void) BTReplaceRecord(fcb, &iterator[0], &file_data, datasize);
		(void) BTFlushPath(fcb);
	}	
exit:
	(void) BTFlushPath(fcb);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}


/*
 * cat_findname - obtain a descriptor from cnid
 *
 * Only a thread lookup is performed.
 */
__private_extern__
int
cat_findname(struct hfsmount *hfsmp, cnid_t cnid, struct cat_desc *outdescp)
{
	struct BTreeIterator * iterator;
	FSBufferDescriptor btdata;
	CatalogKey * keyp;
	CatalogRecord * recp;
	int isdir;
	int result;
	int std_hfs;

	isdir = 0;
	std_hfs = (hfsmp->hfs_flags & HFS_STANDARD);

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	buildthreadkey(cnid, std_hfs, (CatalogKey *)&iterator->key);
	iterator->hint.nodeNum = 0;

	MALLOC(recp, CatalogRecord *, sizeof(CatalogRecord), M_TEMP, M_WAITOK);
	BDINIT(btdata, recp);

	result = BTSearchRecord(VTOF(hfsmp->hfs_catalog_vp), iterator, &btdata, NULL, NULL);
	if (result)
		goto exit;

	/* Turn thread record into a cnode key (in place). */
	switch (recp->recordType) {
	case kHFSFolderThreadRecord:
		isdir = 1;
		/* fall through */
	case kHFSFileThreadRecord:
		keyp = (CatalogKey *)((char *)&recp->hfsThread.reserved + 6);
		keyp->hfs.keyLength = kHFSCatalogKeyMinimumLength + keyp->hfs.nodeName[0];
		break;

	case kHFSPlusFolderThreadRecord:
		isdir = 1;
		/* fall through */
	case kHFSPlusFileThreadRecord:
		keyp = (CatalogKey *)&recp->hfsPlusThread.reserved;
		keyp->hfsPlus.keyLength = kHFSPlusCatalogKeyMinimumLength +
		                          (keyp->hfsPlus.nodeName.length * 2);
		break;
	default:
		result = ENOENT;
		goto exit;
	}
	if (std_hfs) {
		HFSPlusCatalogKey * pluskey = NULL;
		u_long encoding;

		MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
		promotekey(hfsmp, &keyp->hfs, pluskey, &encoding);
		builddesc(pluskey, cnid, 0, encoding, isdir, outdescp);
		FREE(pluskey, M_TEMP);

	} else {
		builddesc((HFSPlusCatalogKey *)keyp, cnid, 0, 0, isdir, outdescp);
	}
exit:
	FREE(recp, M_TEMP);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}

/*
 * cat_idlookup - lookup a catalog node using a cnode id
 */
__private_extern__
int
cat_idlookup(struct hfsmount *hfsmp, cnid_t cnid, struct cat_desc *outdescp,
                 struct cat_attr *attrp, struct cat_fork *forkp)
{
	struct BTreeIterator * iterator;
	FSBufferDescriptor btdata;
	UInt16	datasize;
	CatalogKey * keyp;
	CatalogRecord * recp;
	int result;
	int std_hfs;

	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	buildthreadkey(cnid, std_hfs, (CatalogKey *)&iterator->key);

	MALLOC(recp, CatalogRecord *, sizeof(CatalogRecord), M_TEMP, M_WAITOK);
	BDINIT(btdata, recp);

	result = BTSearchRecord(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), iterator,
				&btdata, &datasize, iterator);
	if (result)
		goto exit;

	/* Turn thread record into a cnode key (in place) */
	switch (recp->recordType) {
	case kHFSFileThreadRecord:
	case kHFSFolderThreadRecord:
		keyp = (CatalogKey *)((char *)&recp->hfsThread.reserved + 6);
		keyp->hfs.keyLength = kHFSCatalogKeyMinimumLength + keyp->hfs.nodeName[0];
		break;

	case kHFSPlusFileThreadRecord:
	case kHFSPlusFolderThreadRecord:
		keyp = (CatalogKey *)&recp->hfsPlusThread.reserved;
		keyp->hfsPlus.keyLength = kHFSPlusCatalogKeyMinimumLength +
		                          (keyp->hfsPlus.nodeName.length * 2);
		break;

	default:
		result = ENOENT;
		goto exit;
	}

	result = cat_lookupbykey(hfsmp, keyp, 0, 0, outdescp, attrp, forkp, NULL);
exit:
	FREE(recp, M_TEMP);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}


/*
 * cat_lookupmangled - lookup a catalog node using a mangled name
 */
static int
cat_lookupmangled(struct hfsmount *hfsmp, struct cat_desc *descp, int wantrsrc,
                  struct cat_desc *outdescp, struct cat_attr *attrp, struct cat_fork *forkp)
{
	cnid_t fileID;
	int prefixlen;
	int result;
	
	if (wantrsrc)
		return (ENOENT);

	fileID = GetEmbeddedFileID(descp->cd_nameptr, descp->cd_namelen, &prefixlen);
	if (fileID < kHFSFirstUserCatalogNodeID)
		return (ENOENT);

	result = cat_idlookup(hfsmp, fileID, outdescp, attrp, forkp);
	if (result)
		return (ENOENT);

	/* It must be in the correct directory */
	if (descp->cd_parentcnid != outdescp->cd_parentcnid)
		goto falsematch;

	if ((outdescp->cd_namelen < prefixlen) ||
	    bcmp(outdescp->cd_nameptr, descp->cd_nameptr, prefixlen-6) != 0)
		goto falsematch;

	return (0);

falsematch:
	cat_releasedesc(outdescp);
	return (ENOENT);
}


/*
 * cat_lookupbykey - lookup a catalog node using a cnode key
 */
static int
cat_lookupbykey(struct hfsmount *hfsmp, CatalogKey *keyp, u_long hint, int wantrsrc,
                  struct cat_desc *descp, struct cat_attr *attrp, struct cat_fork *forkp, cnid_t *desc_cnid)
{
	struct BTreeIterator * iterator;
	FSBufferDescriptor btdata;
	CatalogRecord * recp;
	UInt16  datasize;
	int result;
	int std_hfs;
	u_long ilink = 0;
	cnid_t cnid = 0;
	u_long encoding = 0;

	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);

	MALLOC(recp, CatalogRecord *, sizeof(CatalogRecord), M_TEMP, M_WAITOK);
	BDINIT(btdata, recp);
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	iterator->hint.nodeNum = hint;
	bcopy(keyp, &iterator->key, sizeof(CatalogKey));

	result = BTSearchRecord(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), iterator,
				&btdata, &datasize, iterator);
	if (result) 
		goto exit;

	/* Save the cnid now in case there's a hard link */
	cnid = getcnid(recp);
	encoding = getencoding(recp);
	hint = iterator->hint.nodeNum;

	/* Hide the journal files (if any) */
	if ((hfsmp->jnl || ((HFSTOVCB(hfsmp)->vcbAtrb & kHFSVolumeJournaledMask) && (hfsmp->hfs_flags & HFS_READ_ONLY))) &&
		((cnid == hfsmp->hfs_jnlfileid) ||
		 (cnid == hfsmp->hfs_jnlinfoblkid))) {

		result = ENOENT;
		goto exit;
	}

	/*
	 * When a hardlink link is encountered, auto resolve it
	 */
	if (!std_hfs
	    && (attrp || forkp) 
	    && (recp->recordType == kHFSPlusFileRecord)
	    && (SWAP_BE32(recp->hfsPlusFile.userInfo.fdType) == kHardLinkFileType)
	    && (SWAP_BE32(recp->hfsPlusFile.userInfo.fdCreator) == kHFSPlusCreator)
	    && ((to_bsd_time(recp->hfsPlusFile.createDate) == (time_t)HFSTOVCB(hfsmp)->vcbCrDate) ||
	        (to_bsd_time(recp->hfsPlusFile.createDate) == (time_t)hfsmp->hfs_metadata_createdate))) {

		ilink = recp->hfsPlusFile.bsdInfo.special.iNodeNum;

		(void) resolvelink(hfsmp, ilink, (struct HFSPlusCatalogFile *)recp);
	}

	if (attrp != NULL) {
		if (std_hfs) {
			struct HFSPlusCatalogFile cnoderec;

			promoteattr(hfsmp, recp, &cnoderec);
			getbsdattr(hfsmp, &cnoderec, attrp);
		} else {
			getbsdattr(hfsmp, (struct HFSPlusCatalogFile *)recp, attrp);
			if (ilink)
				attrp->ca_rdev = ilink;
		}
	}
	if (forkp != NULL) {
		if (isadir(recp)) {
			bzero(forkp, sizeof(*forkp));
		} else if (std_hfs) {
			promotefork(hfsmp, (HFSCatalogFile *)&recp->hfsFile, wantrsrc, forkp);
		} else if (wantrsrc) {
			/* Convert the resource fork. */
			forkp->cf_size = recp->hfsPlusFile.resourceFork.logicalSize;
			forkp->cf_blocks = recp->hfsPlusFile.resourceFork.totalBlocks;
			if ((hfsmp->hfc_stage == HFC_RECORDING) &&
			    (to_bsd_time(recp->hfsPlusFile.accessDate) >= hfsmp->hfc_timebase)) {
				forkp->cf_bytesread =
					recp->hfsPlusFile.resourceFork.clumpSize *
					HFSTOVCB(hfsmp)->blockSize;
			} else {
				forkp->cf_bytesread = 0;
			}
			forkp->cf_vblocks = 0;
			bcopy(&recp->hfsPlusFile.resourceFork.extents[0],
			      &forkp->cf_extents[0], sizeof(HFSPlusExtentRecord));
		} else {
			int i;
			u_int32_t validblks;

			/* Convert the data fork. */
			forkp->cf_size = recp->hfsPlusFile.dataFork.logicalSize;
			forkp->cf_blocks = recp->hfsPlusFile.dataFork.totalBlocks;
			if ((hfsmp->hfc_stage == HFC_RECORDING) &&
			    (to_bsd_time(recp->hfsPlusFile.accessDate) >= hfsmp->hfc_timebase)) {
				forkp->cf_bytesread =
					recp->hfsPlusFile.dataFork.clumpSize *
					HFSTOVCB(hfsmp)->blockSize;
			} else {
				forkp->cf_bytesread = 0;
			}
			forkp->cf_vblocks = 0;
			bcopy(&recp->hfsPlusFile.dataFork.extents[0],
			      &forkp->cf_extents[0], sizeof(HFSPlusExtentRecord));

			/* Validate the fork's resident extents. */
			validblks = 0;
			for (i = 0; i < kHFSPlusExtentDensity; ++i) {
				if (forkp->cf_extents[i].startBlock + forkp->cf_extents[i].blockCount >= hfsmp->totalBlocks) {
					/* Suppress any bad extents so a remove can succeed. */
					forkp->cf_extents[i].startBlock = 0;
					forkp->cf_extents[i].blockCount = 0;
					/* Disable writes */
					if (attrp != NULL) {
						attrp->ca_mode &= S_IFMT | S_IRUSR | S_IRGRP | S_IROTH;
					}
				} else {
					validblks += forkp->cf_extents[i].blockCount;
				}
			}
			/* Adjust for any missing blocks. */
			if ((validblks < forkp->cf_blocks) && (forkp->cf_extents[7].blockCount == 0)) {
				u_int64_t psize;

				forkp->cf_blocks = validblks;
				if (attrp != NULL) {
					attrp->ca_blocks = validblks + recp->hfsPlusFile.resourceFork.totalBlocks;
				}
				psize = (u_int64_t)validblks * (u_int64_t)hfsmp->blockSize;
				if (psize < forkp->cf_size) {
					forkp->cf_size = psize;
				}

			}
		}
	}
	if (descp != NULL) {
		HFSPlusCatalogKey * pluskey = NULL;

		if (std_hfs) {
			MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
			promotekey(hfsmp, (HFSCatalogKey *)&iterator->key, pluskey, &encoding);
	
		} else
			pluskey = (HFSPlusCatalogKey *)&iterator->key;

		builddesc(pluskey, cnid, hint, encoding, isadir(recp), descp);
		if (std_hfs) {
			FREE(pluskey, M_TEMP);
		}
	}

	if (desc_cnid != NULL) {
	    *desc_cnid = cnid;
	}
exit:
	FREE(iterator, M_TEMP);
	FREE(recp, M_TEMP);

	return MacToVFSError(result);
}


/*
 * cat_create - create a node in the catalog
 */
__private_extern__
int
cat_create(struct hfsmount *hfsmp, struct cat_desc *descp, struct cat_attr *attrp,
	struct cat_desc *out_descp)
{
	ExtendedVCB * vcb;
	FCB * fcb;
	struct btobj * bto;
	FSBufferDescriptor btdata;
	u_int32_t nextCNID;
	u_int32_t datalen;
	int std_hfs;
	int result = 0;
	u_long encoding;
	int modeformat;
	int mntlock = 0;

	modeformat = attrp->ca_mode & S_IFMT;

	vcb = HFSTOVCB(hfsmp);
	fcb = GetFileControlBlock(vcb->catalogRefNum);
	std_hfs = (vcb->vcbSigWord == kHFSSigWord);

	/*
	 * Atomically get the next CNID.  If we have wrapped the CNIDs
	 * then keep the hfsmp lock held until we have found a CNID.
	 */
	HFS_MOUNT_LOCK(hfsmp, TRUE);
	mntlock = 1;
	nextCNID = hfsmp->vcbNxtCNID;
	if (nextCNID == 0xFFFFFFFF) {
		if (std_hfs) {
			result = ENOSPC;
		} else {
			hfsmp->vcbNxtCNID = kHFSFirstUserCatalogNodeID;
			hfsmp->vcbAtrb |= kHFSCatalogNodeIDsReusedMask;
		}
	} else {
		hfsmp->vcbNxtCNID++;
	}
	hfsmp->vcbFlags |= 0xFF00;
	/* OK to drop lock if CNIDs are not wrapping */
	if ((hfsmp->vcbAtrb & kHFSCatalogNodeIDsReusedMask) == 0) {
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		mntlock = 0;
		if (result)
			return (result);  /* HFS only exit */
	}

	/* Get space for iterator, key and data */	
	MALLOC(bto, struct btobj *, sizeof(struct btobj), M_TEMP, M_WAITOK);
	bto->iterator.hint.nodeNum = 0;

	result = buildkey(hfsmp, descp, &bto->key, 0);
	if (result)
		goto exit;

	if (!std_hfs) {
		encoding = hfs_pickencoding(bto->key.nodeName.unicode,
			bto->key.nodeName.length);
		hfs_setencodingbits(hfsmp, encoding);
	}

	/*
	 * Insert the thread record first
	 */
	if (!std_hfs || (modeformat == S_IFDIR)) {
		datalen = buildthread((void*)&bto->key, &bto->data, std_hfs,
				S_ISDIR(attrp->ca_mode));
		btdata.bufferAddress = &bto->data;
		btdata.itemSize = datalen;
		btdata.itemCount = 1;
		
		for (;;) {
			buildthreadkey(nextCNID, std_hfs, (CatalogKey *) &bto->iterator.key);

			result = BTInsertRecord(fcb, &bto->iterator, &btdata, datalen);
			if ((result == btExists) && !std_hfs && mntlock) {
				/*
				 * Allow CNIDs on HFS Plus volumes to wrap around
				 */
				if (++nextCNID < kHFSFirstUserCatalogNodeID) {
					nextCNID = kHFSFirstUserCatalogNodeID;
				}
				continue;
			}
			break;
		}
		if (result) goto exit;
	}
	
	/*
	 * CNID is now established. If we have wrapped then
	 * update the vcbNxtCNID and drop the vcb lock.
	 */
	if (mntlock) {
		hfsmp->vcbNxtCNID = nextCNID + 1;
		if (hfsmp->vcbNxtCNID < kHFSFirstUserCatalogNodeID) {
			hfsmp->vcbNxtCNID = kHFSFirstUserCatalogNodeID;
		}
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);
		mntlock = 0;
	}

	/*
	 * Now insert the file/directory record
	 */
	buildrecord(attrp, nextCNID, std_hfs, encoding, &bto->data, &datalen);
	btdata.bufferAddress = &bto->data;
	btdata.itemSize = datalen;
	btdata.itemCount = 1;
	
	bcopy(&bto->key, &bto->iterator.key, sizeof(bto->key));

	result = BTInsertRecord(fcb, &bto->iterator, &btdata, datalen);
	if (result) {
		if (result == btExists)
			result = EEXIST;

		/* Back out the thread record */
		if (!std_hfs || S_ISDIR(attrp->ca_mode)) {
			buildthreadkey(nextCNID, std_hfs, (CatalogKey *)&bto->iterator.key);
			(void) BTDeleteRecord(fcb, &bto->iterator);
		}
		goto exit;
	}

	/*
	 * Insert was Successfull, update name, parent and volume
	 */


	if (out_descp != NULL) {
		HFSPlusCatalogKey * pluskey = NULL;

		if (std_hfs) {
			MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
			promotekey(hfsmp, (HFSCatalogKey *)&bto->iterator.key, pluskey, &encoding);
	
		} else
			pluskey = (HFSPlusCatalogKey *)&bto->iterator.key;

		builddesc(pluskey, nextCNID, bto->iterator.hint.nodeNum,
			encoding, S_ISDIR(attrp->ca_mode), out_descp);
		if (std_hfs) {
			FREE(pluskey, M_TEMP);
		}
	}
	attrp->ca_fileid = nextCNID;

exit:
	if (mntlock)
		HFS_MOUNT_UNLOCK(hfsmp, TRUE);

	(void) BTFlushPath(fcb);
	FREE(bto, M_TEMP);

	return MacToVFSError(result);
}


/*
 * cnode_rename - rename a catalog node
 *
 * Assumes that the target's directory exists.
 *
 * Order of B-tree operations:
 *	1. BTSearchRecord(from_cnode, &data);
 *	2. BTInsertRecord(to_cnode, &data);
 *	3. BTDeleteRecord(from_cnode);
 *	4. BTDeleteRecord(from_thread);
 *	5. BTInsertRecord(to_thread);
 */
__private_extern__
int 
cat_rename (
	struct hfsmount * hfsmp,
	struct cat_desc * from_cdp,
	struct cat_desc * todir_cdp,
	struct cat_desc * to_cdp,
	struct cat_desc * out_cdp )
{
	struct BTreeIterator * to_iterator = NULL;
	struct BTreeIterator * from_iterator = NULL;
	FSBufferDescriptor btdata;
	CatalogRecord * recp = NULL;
	HFSPlusCatalogKey * to_key;
	ExtendedVCB * vcb;
	FCB * fcb;
	UInt16	datasize;
	int result = 0;
	int sourcegone = 0;
	int skipthread = 0;
	int directory = from_cdp->cd_flags & CD_ISDIR;
	int std_hfs;
	u_long encoding = 0;

	vcb = HFSTOVCB(hfsmp);
	fcb = GetFileControlBlock(vcb->catalogRefNum);
	std_hfs = (vcb->vcbSigWord == kHFSSigWord);

	if (from_cdp->cd_namelen == 0 || to_cdp->cd_namelen == 0)
		return (EINVAL);

	MALLOC(from_iterator, BTreeIterator *, sizeof(*from_iterator), M_TEMP, M_WAITOK);
	bzero(from_iterator, sizeof(*from_iterator));
	if ((result = buildkey(hfsmp, from_cdp, (HFSPlusCatalogKey *)&from_iterator->key, 0)))
		goto exit;	

	MALLOC(to_iterator, BTreeIterator *, sizeof(*to_iterator), M_TEMP, M_WAITOK);
	bzero(to_iterator, sizeof(*to_iterator));
	if ((result = buildkey(hfsmp, to_cdp, (HFSPlusCatalogKey *)&to_iterator->key, 0)))
		goto exit;	

	to_key = (HFSPlusCatalogKey *)&to_iterator->key;
	MALLOC(recp, CatalogRecord *, sizeof(CatalogRecord), M_TEMP, M_WAITOK);
	BDINIT(btdata, recp);

	/*
	 * When moving a directory, make sure its a valid move.
	 */
	if (directory && (from_cdp->cd_parentcnid != to_cdp->cd_parentcnid)) {
		struct BTreeIterator iterator;
		cnid_t cnid = from_cdp->cd_cnid;
		cnid_t pathcnid = todir_cdp->cd_parentcnid;

		/* First check the obvious ones */
		if (cnid == fsRtDirID  ||
		    cnid == to_cdp->cd_parentcnid  ||
		    cnid == pathcnid) {
			result = EINVAL;
			goto exit;
		}
		bzero(&iterator, sizeof(iterator));
		/*
		 * Traverese destination path all the way back to the root
		 * making sure that source directory is not encountered.
		 *
		 */
		while (pathcnid > fsRtDirID) {
			buildthreadkey(pathcnid, std_hfs,
					(CatalogKey *)&iterator.key);
			result = BTSearchRecord(fcb, &iterator, &btdata,
					&datasize, NULL);
			if (result) goto exit;
			
			pathcnid = getparentcnid(recp);
			if (pathcnid == cnid) {
				result = EINVAL;
				goto exit;
			}
		}
	}

	/*
	 * Step 1: Find cnode data at old location
	 */
	result = BTSearchRecord(fcb, from_iterator, &btdata,
				&datasize, from_iterator);
	if (result) {
		if (std_hfs || (result != btNotFound)) 
			goto exit;
	
		struct cat_desc temp_desc;

		/* Probably the node has mangled name */
		result = cat_lookupmangled(hfsmp, from_cdp, 0, &temp_desc, NULL, NULL); 
		if (result) 
			goto exit;
			
		/* The file has mangled name.  Search the cnode data using full name */
		bzero(from_iterator, sizeof(*from_iterator));
		result = buildkey(hfsmp, &temp_desc, (HFSPlusCatalogKey *)&from_iterator->key, 0);
		if (result) {
			cat_releasedesc(&temp_desc);
			goto exit;
		}

		result = BTSearchRecord(fcb, from_iterator, &btdata, &datasize, from_iterator);
		if (result) {
			cat_releasedesc(&temp_desc);
			goto exit;
		}
		
		cat_releasedesc(&temp_desc);
	}

	/* Update the text encoding (on disk and in descriptor) */
	if (!std_hfs) {
		encoding = hfs_pickencoding(to_key->nodeName.unicode,
				to_key->nodeName.length);
		hfs_setencodingbits(hfsmp, encoding);
		recp->hfsPlusFile.textEncoding = encoding;
		if (out_cdp)
			out_cdp->cd_encoding = encoding;
	}
	
	if (std_hfs && !directory &&
	    !(recp->hfsFile.flags & kHFSThreadExistsMask))
		skipthread = 1;
#if 0
	/*
	 * If the keys are identical then there's nothing left to do!
	 *
	 * update the hint and exit
	 *
	 */
	if (std_hfs && hfskeycompare(to_key, iter->key) == 0)
		goto exit;	
	if (!std_hfs && hfspluskeycompare(to_key, iter->key) == 0)
		goto exit;	
#endif

	/* Step 2: Insert cnode at new location */
	result = BTInsertRecord(fcb, to_iterator, &btdata, datasize);
	if (result == btExists) {
		int fromtype = recp->recordType;

		if (from_cdp->cd_parentcnid != to_cdp->cd_parentcnid)
			goto exit; /* EEXIST */

		/* Find cnode data at new location */
		result = BTSearchRecord(fcb, to_iterator, &btdata, &datasize, NULL);
		if (result)
			goto exit;
		
		if ((fromtype != recp->recordType) ||
		    (from_cdp->cd_cnid != getcnid(recp))) {
			result = EEXIST;
			goto exit; /* EEXIST */
		}
		/* The old name is a case variant and must be removed */
		result = BTDeleteRecord(fcb, from_iterator);
		if (result)
			goto exit;

		/* Insert cnode (now that case duplicate is gone) */
		result = BTInsertRecord(fcb, to_iterator, &btdata, datasize);
		if (result) {
			/* Try and restore original before leaving */
		    // XXXdbg
		    #if 1
		       {
		       	int err;
			err = BTInsertRecord(fcb, from_iterator, &btdata, datasize);
			if (err)
				panic("cat_create: could not undo (BTInsert = %d)", err);
		       }
		    #else
			(void) BTInsertRecord(fcb, from_iterator, &btdata, datasize);
		    #endif
			goto exit;
		}
		sourcegone = 1;
	}
	if (result)
		goto exit;

	/* Step 3: Remove cnode from old location */
	if (!sourcegone) {
		result = BTDeleteRecord(fcb, from_iterator);
		if (result) {
			/* Try and delete new record before leaving */
		  // XXXdbg
		  #if 1
		     {
		     	int err;
			err = BTDeleteRecord(fcb, to_iterator);
			if (err)
				panic("cat_create: could not undo (BTDelete = %d)", err);
		     }			
		  #else
			(void) BTDeleteRecord(fcb, to_iterator);
		  #endif
			goto exit;
		}
	}

	/* #### POINT OF NO RETURN #### */

	/*
	 * Step 4: Remove cnode's old thread record
	 */
	buildthreadkey(from_cdp->cd_cnid, std_hfs, (CatalogKey *)&from_iterator->key);
	(void) BTDeleteRecord(fcb, from_iterator);

	/*
	 * Step 5: Insert cnode's new thread record
	 * (optional for HFS files)
	 */
	if (!skipthread) {
		datasize = buildthread(&to_iterator->key, recp, std_hfs, directory);
		btdata.itemSize = datasize;
		buildthreadkey(from_cdp->cd_cnid, std_hfs, (CatalogKey *)&from_iterator->key);
		result = BTInsertRecord(fcb, from_iterator, &btdata, datasize);
	}

	if (out_cdp) {
		HFSPlusCatalogKey * pluskey = NULL;

		if (std_hfs) {
			MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
			promotekey(hfsmp, (HFSCatalogKey *)&to_iterator->key, pluskey, &encoding);

			/* Save the real encoding hint in the Finder Info (field 4). */
			if (directory && from_cdp->cd_cnid == kHFSRootFolderID) {
				u_long realhint;

				realhint = hfs_pickencoding(pluskey->nodeName.unicode, pluskey->nodeName.length);
				vcb->vcbFndrInfo[4] = SET_HFS_TEXT_ENCODING(realhint);
			}
	
		} else
			pluskey = (HFSPlusCatalogKey *)&to_iterator->key;

		builddesc(pluskey, from_cdp->cd_cnid, to_iterator->hint.nodeNum,
			encoding, directory, out_cdp);
		if (std_hfs) {
			FREE(pluskey, M_TEMP);
		}
	}
exit:
	(void) BTFlushPath(fcb);
	if (from_iterator)
		FREE(from_iterator, M_TEMP);
	if (to_iterator)
		FREE(to_iterator, M_TEMP);
	if (recp)
		FREE(recp, M_TEMP);
	return MacToVFSError(result);
}


/*
 * cat_delete - delete a node from the catalog
 *
 * Order of B-tree operations:
 *	1. BTDeleteRecord(cnode);
 *	2. BTDeleteRecord(thread);
 *	3. BTUpdateRecord(parent);
 */
__private_extern__
int
cat_delete(struct hfsmount *hfsmp, struct cat_desc *descp, struct cat_attr *attrp)
{
	ExtendedVCB * vcb;
	FCB * fcb;
	BTreeIterator *iterator;
	cnid_t cnid;
	int std_hfs;
	int result;

	vcb = HFSTOVCB(hfsmp);
	fcb = GetFileControlBlock(vcb->catalogRefNum);
	std_hfs = (vcb->vcbSigWord == kHFSSigWord);

	/* Preflight check:
	 *
	 * The root directory cannot be deleted
	 * A directory must be empty
	 * A file must be zero length (no blocks)
	 */
	if (descp->cd_cnid < kHFSFirstUserCatalogNodeID ||
	    descp->cd_parentcnid == kHFSRootParentID)
		return (EINVAL);

	/* XXX Preflight Missing */
	
	/* Get space for iterator */	
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	iterator->hint.nodeNum = 0;

	/*
	 * Derive a key from either the file ID (for a virtual inode)
	 * or the descriptor.
	 */
	if (descp->cd_namelen == 0) {
	    result = getkey(hfsmp, attrp->ca_fileid, (CatalogKey *)&iterator->key);
	    cnid = attrp->ca_fileid;
	} else {
		result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)&iterator->key, 0);
		cnid = descp->cd_cnid;
	}
	if (result)
		goto exit;

	/* Delete record */
	result = BTDeleteRecord(fcb, iterator);
	if (result) {
		if (std_hfs || (result != btNotFound))
			goto exit;

		struct cat_desc temp_desc;
		
		/* Probably the node has mangled name */
		result = cat_lookupmangled(hfsmp, descp, 0, &temp_desc, attrp, NULL); 
		if (result) 
			goto exit;
		
		/* The file has mangled name.  Delete the file using full name  */
		bzero(iterator, sizeof(*iterator));
		result = buildkey(hfsmp, &temp_desc, (HFSPlusCatalogKey *)&iterator->key, 0);
		cnid = temp_desc.cd_cnid;
		if (result) {
			cat_releasedesc(&temp_desc);
			goto exit;
		}

		result = BTDeleteRecord(fcb, iterator);
		if (result) { 
			cat_releasedesc(&temp_desc);
			goto exit;
		}

		cat_releasedesc(&temp_desc);
	}

	/* Delete thread record, ignore errors */
	buildthreadkey(cnid, std_hfs, (CatalogKey *)&iterator->key);
	(void) BTDeleteRecord(fcb, iterator);

exit:
	(void) BTFlushPath(fcb);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}


/*
 * cnode_update - update the catalog node described by descp
 * using the data from attrp and forkp.
 */
__private_extern__
int
cat_update(struct hfsmount *hfsmp, struct cat_desc *descp, struct cat_attr *attrp,
	struct cat_fork *dataforkp, struct cat_fork *rsrcforkp)
{
	ExtendedVCB * vcb;
	FCB * fcb;
	BTreeIterator * iterator;
	struct update_state state;
	int std_hfs;
	int result;

	vcb = HFSTOVCB(hfsmp);
	fcb = GetFileControlBlock(vcb->catalogRefNum);
	std_hfs = (vcb->vcbSigWord == kHFSSigWord);

	state.s_desc = descp;
	state.s_attr = attrp;
	state.s_datafork = dataforkp;
	state.s_rsrcfork = rsrcforkp;
	state.s_hfsmp = hfsmp;

	/* Get space for iterator */	
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);

	/*
	 * For open-deleted files we need to do a lookup by cnid
	 * (using thread rec).
	 *
	 * For hard links, the target of the update is the inode
	 * itself (not the link record) so a lookup by fileid
	 * (i.e. thread rec) is needed.
	 */
	if ((descp->cd_cnid != attrp->ca_fileid) || (descp->cd_namelen == 0))
		result = getkey(hfsmp, attrp->ca_fileid, (CatalogKey *)&iterator->key);
	else
		result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)&iterator->key, 0);
	if (result)
		goto exit;

	/* Pass a node hint */
	iterator->hint.nodeNum = descp->cd_hint;

	result = BTUpdateRecord(fcb, iterator,
	                        (IterateCallBackProcPtr)catrec_update, &state);
	if (result)
		goto exit;

	/* Update the node hint. */
	descp->cd_hint = iterator->hint.nodeNum;

exit:
	(void) BTFlushPath(fcb);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}

/*
 * catrec_update - Update the fields of a catalog record
 * This is called from within BTUpdateRecord.
 */
static int
catrec_update(const CatalogKey *ckp, CatalogRecord *crp, struct update_state *state)
{
	struct cat_desc *descp;
	struct cat_attr *attrp;
	struct cat_fork *forkp;
	struct hfsmount *hfsmp;
	long blksize;
	int i;

	descp   = state->s_desc;
	attrp   = state->s_attr;
	hfsmp   = state->s_hfsmp;
	blksize = HFSTOVCB(hfsmp)->blockSize;

	switch (crp->recordType) {
	case kHFSFolderRecord: {
		HFSCatalogFolder *dir;
		
		dir = (struct HFSCatalogFolder *)crp;
		/* Do a quick sanity check */
		if ((ckp->hfs.parentID != descp->cd_parentcnid) ||
		    (dir->folderID != descp->cd_cnid))
			return (btNotFound);
		dir->valence    = attrp->ca_entries;
		dir->createDate = UTCToLocal(to_hfs_time(attrp->ca_itime));
		dir->modifyDate = UTCToLocal(to_hfs_time(attrp->ca_mtime));
		dir->backupDate = UTCToLocal(to_hfs_time(attrp->ca_btime));
		bcopy(&attrp->ca_finderinfo[0], &dir->userInfo, 16);
		bcopy(&attrp->ca_finderinfo[16], &dir->finderInfo, 16);
		break;
	}
	case kHFSFileRecord: {
		HFSCatalogFile *file;
		
		file = (struct HFSCatalogFile *)crp;
		/* Do a quick sanity check */
		if ((ckp->hfs.parentID != descp->cd_parentcnid) ||
		    (file->fileID != attrp->ca_fileid))
			return (btNotFound);
		file->createDate = UTCToLocal(to_hfs_time(attrp->ca_itime));
		file->modifyDate = UTCToLocal(to_hfs_time(attrp->ca_mtime));
		file->backupDate = UTCToLocal(to_hfs_time(attrp->ca_btime));
		bcopy(&attrp->ca_finderinfo[0], &file->userInfo, 16);
		bcopy(&attrp->ca_finderinfo[16], &file->finderInfo, 16);
		if (state->s_rsrcfork) {
			forkp = state->s_rsrcfork;
			file->rsrcLogicalSize  = forkp->cf_size;
			file->rsrcPhysicalSize = forkp->cf_blocks * blksize;
			for (i = 0; i < kHFSExtentDensity; ++i) {
				file->rsrcExtents[i].startBlock =
					(u_int16_t)forkp->cf_extents[i].startBlock;
				file->rsrcExtents[i].blockCount =
					(u_int16_t)forkp->cf_extents[i].blockCount;
			}
		}
		if (state->s_datafork) {
			forkp = state->s_datafork;
			file->dataLogicalSize  = forkp->cf_size;
			file->dataPhysicalSize = forkp->cf_blocks * blksize;
			for (i = 0; i < kHFSExtentDensity; ++i) {
				file->dataExtents[i].startBlock =
					(u_int16_t)forkp->cf_extents[i].startBlock;
				file->dataExtents[i].blockCount =
					(u_int16_t)forkp->cf_extents[i].blockCount;
			}
		}
		break;
	}
	case kHFSPlusFolderRecord: {
		HFSPlusCatalogFolder *dir;
		
		dir = (struct HFSPlusCatalogFolder *)crp;
		/* Do a quick sanity check */
		if ((ckp->hfsPlus.parentID != descp->cd_parentcnid) ||
			(dir->folderID != descp->cd_cnid)) 
			return (btNotFound);
		dir->flags            = attrp->ca_recflags;
		dir->valence          = attrp->ca_entries;
		dir->createDate       = to_hfs_time(attrp->ca_itime);
		dir->contentModDate   = to_hfs_time(attrp->ca_mtime);
		dir->backupDate       = to_hfs_time(attrp->ca_btime);
		dir->accessDate       = to_hfs_time(attrp->ca_atime);
		attrp->ca_atimeondisk = attrp->ca_atime;	
		dir->attributeModDate = to_hfs_time(attrp->ca_ctime);
		dir->textEncoding     = descp->cd_encoding;
		dir->attrBlocks       = attrp->ca_attrblks;
		bcopy(&attrp->ca_finderinfo[0], &dir->userInfo, 32);
		/*
		 * Update the BSD Info if it was already initialized on
		 * disk or if the runtime values have been modified.
		 *
		 * If the BSD info was already initialized, but
		 * MNT_UNKNOWNPERMISSIONS is set, then the runtime IDs are
		 * probably different than what was on disk.  We don't want
		 * to overwrite the on-disk values (so if we turn off
		 * MNT_UNKNOWNPERMISSIONS, the old IDs get used again).
		 * This way, we can still change fields like the mode or
		 * dates even when MNT_UNKNOWNPERMISSIONS is set.
		 *
		 * Note that if MNT_UNKNOWNPERMISSIONS is set, hfs_chown
		 * won't change the uid or gid from their defaults.  So, if
		 * the BSD info wasn't set, and the runtime values are not
		 * default, then what changed was the mode or flags.  We
		 * have to set the uid and gid to something, so use the
		 * supplied values (which will be default), which has the
		 * same effect as creating a new file while
		 * MNT_UNKNOWNPERMISSIONS is set.
		 */
		if ((dir->bsdInfo.fileMode != 0) ||
		    (attrp->ca_flags != 0) ||
		    (attrp->ca_uid != hfsmp->hfs_uid) ||
		    (attrp->ca_gid != hfsmp->hfs_gid) ||
		    ((attrp->ca_mode & ALLPERMS) !=
		     (hfsmp->hfs_dir_mask & ACCESSPERMS))) {
			if ((dir->bsdInfo.fileMode == 0) ||
			    (((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS) == 0) {
				dir->bsdInfo.ownerID = attrp->ca_uid;
				dir->bsdInfo.groupID = attrp->ca_gid;
			}
			dir->bsdInfo.ownerFlags = attrp->ca_flags & 0x000000FF;
			dir->bsdInfo.adminFlags = attrp->ca_flags >> 16;
			dir->bsdInfo.fileMode   = attrp->ca_mode;
		}
		break;
	}
	case kHFSPlusFileRecord: {
		HFSPlusCatalogFile *file;
		
		file = (struct HFSPlusCatalogFile *)crp;
		/* Do a quick sanity check */
		if (file->fileID != attrp->ca_fileid)
			return (btNotFound);
		file->flags            = attrp->ca_recflags;
		file->createDate       = to_hfs_time(attrp->ca_itime);
		file->contentModDate   = to_hfs_time(attrp->ca_mtime);
		file->backupDate       = to_hfs_time(attrp->ca_btime);
		file->accessDate       = to_hfs_time(attrp->ca_atime);
		attrp->ca_atimeondisk  = attrp->ca_atime;	
		file->attributeModDate = to_hfs_time(attrp->ca_ctime);
		file->textEncoding     = descp->cd_encoding;
		file->attrBlocks       = attrp->ca_attrblks;
		bcopy(&attrp->ca_finderinfo[0], &file->userInfo, 32);
		/*
		 * Update the BSD Info if it was already initialized on
		 * disk or if the runtime values have been modified.
		 *
		 * If the BSD info was already initialized, but
		 * MNT_UNKNOWNPERMISSIONS is set, then the runtime IDs are
		 * probably different than what was on disk.  We don't want
		 * to overwrite the on-disk values (so if we turn off
		 * MNT_UNKNOWNPERMISSIONS, the old IDs get used again).
		 * This way, we can still change fields like the mode or
		 * dates even when MNT_UNKNOWNPERMISSIONS is set.
		 *
		 * Note that if MNT_UNKNOWNPERMISSIONS is set, hfs_chown
		 * won't change the uid or gid from their defaults.  So, if
		 * the BSD info wasn't set, and the runtime values are not
		 * default, then what changed was the mode or flags.  We
		 * have to set the uid and gid to something, so use the
		 * supplied values (which will be default), which has the
		 * same effect as creating a new file while
		 * MNT_UNKNOWNPERMISSIONS is set.
		 */
		if ((file->bsdInfo.fileMode != 0) ||
		    (attrp->ca_flags != 0) ||
		    (attrp->ca_uid != hfsmp->hfs_uid) ||
		    (attrp->ca_gid != hfsmp->hfs_gid) ||
		    ((attrp->ca_mode & ALLPERMS) !=
		     (hfsmp->hfs_file_mask & ACCESSPERMS))) {
			if ((file->bsdInfo.fileMode == 0) ||
			    (((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS) == 0) {
				file->bsdInfo.ownerID = attrp->ca_uid;
				file->bsdInfo.groupID = attrp->ca_gid;
			}
			file->bsdInfo.ownerFlags = attrp->ca_flags & 0x000000FF;
			file->bsdInfo.adminFlags = attrp->ca_flags >> 16;
			file->bsdInfo.fileMode   = attrp->ca_mode;
		}
		if (state->s_rsrcfork) {
			forkp = state->s_rsrcfork;
			file->resourceFork.logicalSize = forkp->cf_size;
			file->resourceFork.totalBlocks = forkp->cf_blocks;
			bcopy(&forkp->cf_extents[0], &file->resourceFork.extents,
				sizeof(HFSPlusExtentRecord));
			/* Push blocks read to disk */
			file->resourceFork.clumpSize =
					howmany(forkp->cf_bytesread, blksize);
		}
		if (state->s_datafork) {
			forkp = state->s_datafork;
			file->dataFork.logicalSize = forkp->cf_size;
			file->dataFork.totalBlocks = forkp->cf_blocks;
			bcopy(&forkp->cf_extents[0], &file->dataFork.extents,
				sizeof(HFSPlusExtentRecord));
			/* Push blocks read to disk */
			file->dataFork.clumpSize =
					howmany(forkp->cf_bytesread, blksize);
		}

		if ((file->resourceFork.extents[0].startBlock != 0) &&
		    (file->resourceFork.extents[0].startBlock ==
		     file->dataFork.extents[0].startBlock))
			panic("catrec_update: rsrc fork == data fork");

		/* Synchronize the lock state */
		if (attrp->ca_flags & (SF_IMMUTABLE | UF_IMMUTABLE))
			file->flags |= kHFSFileLockedMask;
		else
			file->flags &= ~kHFSFileLockedMask;

		/* Push out special field if necessary */
		if (S_ISBLK(attrp->ca_mode) || S_ISCHR(attrp->ca_mode))
			file->bsdInfo.special.rawDevice = attrp->ca_rdev;
		else if (descp->cd_cnid != attrp->ca_fileid
		     ||  attrp->ca_nlink == 2)
			file->bsdInfo.special.linkCount = attrp->ca_nlink;
		break;
	}
	default:
		return (btNotFound);
	}
	return (0);
}

/*
 * Callback to collect directory entries.
 * Called with readattr_state for each item in a directory.
 */
struct readattr_state {
	struct hfsmount *hfsmp;
	struct cat_entrylist *list;
	cnid_t	dir_cnid;
	int stdhfs;
	int error;
};

static int
cat_readattr(const CatalogKey *key, const CatalogRecord *rec,
             struct readattr_state *state)
{
	struct cat_entrylist *list = state->list;
	struct hfsmount *hfsmp = state->hfsmp;
	struct cat_entry *cep;
	cnid_t parentcnid;

	if (list->realentries >= list->maxentries)
		return (0);  /* stop */
	
	parentcnid = state->stdhfs ? key->hfs.parentID : key->hfsPlus.parentID;

	switch(rec->recordType) {
	case kHFSPlusFolderRecord:
	case kHFSPlusFileRecord:
	case kHFSFolderRecord:
	case kHFSFileRecord:
		if (parentcnid != state->dir_cnid) {
			state->error = ENOENT;
			return (0);	/* stop */
		}
		break;
	default:
		state->error = ENOENT;
		return (0);	/* stop */
	}

	/* Hide the private meta data directory and journal files */
	if (parentcnid == kHFSRootFolderID) {
		if ((rec->recordType == kHFSPlusFolderRecord) &&
		    (rec->hfsPlusFolder.folderID == hfsmp->hfs_privdir_desc.cd_cnid)) {
			return (1);	/* continue */
		}
		if ((hfsmp->jnl || ((HFSTOVCB(hfsmp)->vcbAtrb & kHFSVolumeJournaledMask) && (hfsmp->hfs_flags & HFS_READ_ONLY))) &&
		    (rec->recordType == kHFSPlusFileRecord) &&
		    ((rec->hfsPlusFile.fileID == hfsmp->hfs_jnlfileid) ||
		     (rec->hfsPlusFile.fileID == hfsmp->hfs_jnlinfoblkid))) {

			return (1);	/* continue */
		}
	}

	cep = &list->entry[list->realentries++];

	if (state->stdhfs) {
		struct HFSPlusCatalogFile cnoderec;
		HFSPlusCatalogKey * pluskey;
		long encoding;

		promoteattr(hfsmp, rec, &cnoderec);
		getbsdattr(hfsmp, &cnoderec, &cep->ce_attr);

		MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
		promotekey(hfsmp, (HFSCatalogKey *)key, pluskey, &encoding);
		builddesc(pluskey, getcnid(rec), 0, encoding, isadir(rec), &cep->ce_desc);
		FREE(pluskey, M_TEMP);

		if (rec->recordType == kHFSFileRecord) {
			int blksize = HFSTOVCB(hfsmp)->blockSize;

			cep->ce_datasize = rec->hfsFile.dataLogicalSize;
			cep->ce_datablks = rec->hfsFile.dataPhysicalSize / blksize;
			cep->ce_rsrcsize = rec->hfsFile.rsrcLogicalSize;
			cep->ce_rsrcblks = rec->hfsFile.rsrcPhysicalSize / blksize;
		}
	} else {
		getbsdattr(hfsmp, (struct HFSPlusCatalogFile *)rec, &cep->ce_attr);
		builddesc((HFSPlusCatalogKey *)key, getcnid(rec), 0, getencoding(rec),
			isadir(rec), &cep->ce_desc);
		
		if (rec->recordType == kHFSPlusFileRecord) {
			cep->ce_datasize = rec->hfsPlusFile.dataFork.logicalSize;
			cep->ce_datablks = rec->hfsPlusFile.dataFork.totalBlocks;
			cep->ce_rsrcsize = rec->hfsPlusFile.resourceFork.logicalSize;
			cep->ce_rsrcblks = rec->hfsPlusFile.resourceFork.totalBlocks;
			
			/* Save link reference for later processing. */
			if ((SWAP_BE32(rec->hfsPlusFile.userInfo.fdType) == kHardLinkFileType)
			&&  (SWAP_BE32(rec->hfsPlusFile.userInfo.fdCreator) == kHFSPlusCreator))
				cep->ce_attr.ca_rdev = rec->hfsPlusFile.bsdInfo.special.iNodeNum;
		}
	}

	return (list->realentries < list->maxentries);
}

/*
 * Pack a cat_entrylist buffer with attributes from the catalog
 *
 * Note: index is zero relative
 */
__private_extern__
int
cat_getentriesattr(struct hfsmount *hfsmp, directoryhint_t *dirhint, struct cat_entrylist *ce_list)
{
	FCB* fcb;
	CatalogKey * key;
	BTreeIterator * iterator;
	struct readattr_state state;
	cnid_t parentcnid;
	int i;
	int std_hfs;
	int index;
	int have_key;
	int result = 0;

	ce_list->realentries = 0;

	fcb = GetFileControlBlock(HFSTOVCB(hfsmp)->catalogRefNum);
	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);
	parentcnid = dirhint->dh_desc.cd_parentcnid;

	state.hfsmp = hfsmp;
	state.list = ce_list;
	state.dir_cnid = parentcnid;
	state.stdhfs = std_hfs;
	state.error = 0;

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	key = (CatalogKey *)&iterator->key;
	have_key = 0;
	iterator->hint.nodeNum = dirhint->dh_desc.cd_hint;
	index = dirhint->dh_index + 1;

	/*
	 * Attempt to build a key from cached filename
	 */
	if (dirhint->dh_desc.cd_namelen != 0) {
		if (buildkey(hfsmp, &dirhint->dh_desc, (HFSPlusCatalogKey *)key, 0) == 0) {
			have_key = 1;
		}
	}

	/*
	 * If the last entry wasn't cached then position the btree iterator
	 */
	if ((index == 0) || !have_key) {
		/*
		 * Position the iterator at the directory's thread record.
		 * (i.e. just before the first entry)
		 */
		buildthreadkey(dirhint->dh_desc.cd_parentcnid, (hfsmp->hfs_flags & HFS_STANDARD), key);
		result = BTSearchRecord(fcb, iterator, NULL, NULL, iterator);
		if (result) {
			result = MacToVFSError(result);
			goto exit;
		}
	
		/*
		 * Iterate until we reach the entry just
		 * before the one we want to start with.
		 */
		if (index > 0) {
			struct position_state ps;

			ps.error = 0;
			ps.count = 0;
			ps.index = index;
			ps.parentID = dirhint->dh_desc.cd_parentcnid;
			ps.hfsmp = hfsmp;

			result = BTIterateRecords(fcb, kBTreeNextRecord, iterator,
			                          (IterateCallBackProcPtr)cat_findposition, &ps);
			if (ps.error)
				result = ps.error;
			else
				result = MacToVFSError(result);
			if (result) {
				result = MacToVFSError(result);
				goto exit;
			}
		}
	}

	/* Fill list with entries starting at iterator->key. */
	result = BTIterateRecords(fcb, kBTreeNextRecord, iterator,
			(IterateCallBackProcPtr)cat_readattr, &state);

	if (state.error)
		result = state.error;
	else if (ce_list->realentries == 0)
		result = ENOENT;
	else
		result = MacToVFSError(result);

	if (std_hfs)
		goto exit;

	/*
	 *  Resolve any hard links.
	 */
	for (i = 0; i < (int)ce_list->realentries; ++i) {
		struct FndrFileInfo *fip;
		struct cat_entry *cep;
		struct HFSPlusCatalogFile filerec;

		cep = &ce_list->entry[i];
		if (!S_ISREG(cep->ce_attr.ca_mode))
			continue;
	
		/* Note: Finder info is still in Big Endian */
		fip = (struct FndrFileInfo *)&cep->ce_attr.ca_finderinfo;

		/* Check for hard link signature. */
		if ((cep->ce_attr.ca_rdev != 0)
		&&  (SWAP_BE32(fip->fdType) == kHardLinkFileType)
		&&  (SWAP_BE32(fip->fdCreator) == kHFSPlusCreator)
		&&  ((cep->ce_attr.ca_itime == (time_t)HFSTOVCB(hfsmp)->vcbCrDate) ||
		     (cep->ce_attr.ca_itime == (time_t)hfsmp->hfs_metadata_createdate))) {

			if (resolvelink(hfsmp, cep->ce_attr.ca_rdev, &filerec) != 0)
				continue;
			/* Repack entry from inode record. */
			getbsdattr(hfsmp, &filerec, &cep->ce_attr);		
			cep->ce_datasize = filerec.dataFork.logicalSize;
			cep->ce_datablks = filerec.dataFork.totalBlocks;
			cep->ce_rsrcsize = filerec.resourceFork.logicalSize;
			cep->ce_rsrcblks = filerec.resourceFork.totalBlocks;
		}
	}
exit:
	FREE(iterator, M_TEMP);
	
	return MacToVFSError(result);
}

#define SMALL_DIRENTRY_SIZE  (int)(sizeof(struct dirent) - (MAXNAMLEN + 1) + 8)

/*
 * Callback to pack directory entries.
 * Called with packdirentry_state for each item in a directory.
 */

/* Hard link information collected during cat_getdirentries. */
struct linkinfo {
	u_long       link_ref;
	user_addr_t  dirent_addr;
};
typedef struct linkinfo linkinfo_t;

/* State information for the cat_packdirentry callback function. */
struct packdirentry_state {
	int            cbs_extended;
	u_int32_t      cbs_parentID;
	u_int32_t      cbs_index;
	uio_t	       cbs_uio;
	ExtendedVCB *  cbs_hfsmp;
	int            cbs_result;
	int32_t        cbs_nlinks;
	int32_t        cbs_maxlinks;
	linkinfo_t *   cbs_linkinfo;
	struct cat_desc * cbs_desc;
//	struct dirent  * cbs_stdentry;
	// followign fields are only used for NFS readdir, which uses the next file id as the seek offset of each entry
	struct direntry * cbs_direntry;
	struct direntry * cbs_prevdirentry;
	u_int32_t      cbs_previlinkref;
	Boolean        cbs_hasprevdirentry;
	Boolean        cbs_eof;
};

static int
cat_packdirentry(const CatalogKey *ckp, const CatalogRecord *crp,
                 struct packdirentry_state *state)
{
	struct hfsmount *hfsmp;
	CatalogName *cnp;
	cnid_t curID;
	OSErr result;
	struct dirent catent;
	struct direntry * entry = NULL;
	time_t itime;
	u_int32_t ilinkref = 0;
	u_int32_t curlinkref = 0;
	cnid_t  cnid;
	int hide = 0;
	u_int8_t type;
	u_int8_t is_mangled = 0;
	char *nameptr;
	user_addr_t uiobase;
	size_t namelen = 0;
	size_t maxnamelen;
	size_t uiosize = 0;
	caddr_t uioaddr;
	Boolean stop_after_pack = false;
	
	hfsmp = state->cbs_hfsmp;

	if (hfsmp->hfs_flags & HFS_STANDARD)
		curID = ckp->hfs.parentID;
	else
		curID = ckp->hfsPlus.parentID;

	/* We're done when parent directory changes */
	if (state->cbs_parentID != curID) {
		if (state->cbs_extended) {
			if (state->cbs_hasprevdirentry) { /* the last record haven't been returned yet, so we want to stop after
											   * packing the last item */
				stop_after_pack = true;
			} else {
				state->cbs_result = ENOENT;
				return (0);	/* stop */
			}				
		} else {
			state->cbs_result = ENOENT;
			return (0);	/* stop */
		}
	}

	if (state->cbs_extended) {
		entry = state->cbs_direntry;
		nameptr = &entry->d_name[0];
		maxnamelen = NAME_MAX;
	} else {
		nameptr = &catent.d_name[0];
		maxnamelen = NAME_MAX;
	}

	if (state->cbs_extended && stop_after_pack) {
		cnid = INT_MAX;			/* the last item returns a non-zero invalid cookie */
	} else {
		if (!(hfsmp->hfs_flags & HFS_STANDARD)) {
			switch(crp->recordType) {
			case kHFSPlusFolderRecord:
				type = DT_DIR;
				cnid = crp->hfsPlusFolder.folderID;
				/* Hide our private meta data directory */
				if ((curID == kHFSRootFolderID) &&
					(cnid == hfsmp->hfs_privdir_desc.cd_cnid)) {
					hide = 1;
				}

				break;
			case kHFSPlusFileRecord:
				itime = to_bsd_time(crp->hfsPlusFile.createDate);
				/*
				 * When a hardlink link is encountered save its link ref.
				 */
				if ((SWAP_BE32(crp->hfsPlusFile.userInfo.fdType) == kHardLinkFileType) &&
					(SWAP_BE32(crp->hfsPlusFile.userInfo.fdCreator) == kHFSPlusCreator) &&
					((itime == (time_t)hfsmp->hfs_itime) ||
					 (itime == (time_t)hfsmp->hfs_metadata_createdate))) {
					ilinkref = crp->hfsPlusFile.bsdInfo.special.iNodeNum;
				}
				type = MODE_TO_DT(crp->hfsPlusFile.bsdInfo.fileMode);
				cnid = crp->hfsPlusFile.fileID;
				/* Hide the journal files */
				if ((curID == kHFSRootFolderID) &&
					((hfsmp->jnl || ((HFSTOVCB(hfsmp)->vcbAtrb & kHFSVolumeJournaledMask) && (hfsmp->hfs_flags & HFS_READ_ONLY)))) &&
					((cnid == hfsmp->hfs_jnlfileid) ||
					 (cnid == hfsmp->hfs_jnlinfoblkid))) {
					hide = 1;
				}
				break;
			default:
				return (0);	/* stop */
			};

			cnp = (CatalogName*) &ckp->hfsPlus.nodeName;
			result = utf8_encodestr(cnp->ustr.unicode, cnp->ustr.length * sizeof(UniChar),
									nameptr, &namelen, maxnamelen + 1, ':', 0);
			if (result == ENAMETOOLONG) {
				result = ConvertUnicodeToUTF8Mangled(cnp->ustr.length * sizeof(UniChar),
													 cnp->ustr.unicode, maxnamelen + 1,
													 (ByteCount*)&namelen, nameptr,
													 cnid);		
				is_mangled = 1;
			}
		} else { /* hfs */
			switch(crp->recordType) {
			case kHFSFolderRecord:
				type = DT_DIR;
				cnid = crp->hfsFolder.folderID;
				break;
			case kHFSFileRecord:
				type = DT_REG;
				cnid = crp->hfsFile.fileID;
				break;
			default:
				return (0);	/* stop */
			};

			cnp = (CatalogName*) ckp->hfs.nodeName;
			result = hfs_to_utf8(hfsmp, cnp->pstr, maxnamelen + 1,
								 (ByteCount *)&namelen, nameptr);
			/*
			 * When an HFS name cannot be encoded with the current
			 * volume encoding we use MacRoman as a fallback.
			 */
			if (result)
				result = mac_roman_to_utf8(cnp->pstr, maxnamelen + 1,
										   (ByteCount *)&namelen, nameptr);
		}
	}

	if (state->cbs_extended) {
		/*
		 * The index is 1 relative and includes "." and ".."
		 *
		 * Also stuff the cnid in the upper 32 bits of the cookie.  The cookie is stored to the previous entry, which
		 * will be packed and copied this time
		 */
		state->cbs_prevdirentry->d_seekoff = (state->cbs_index + 3) | ((u_int64_t)cnid << 32);
		uiosize = state->cbs_prevdirentry->d_reclen;
		uioaddr = (caddr_t) state->cbs_prevdirentry;
	} else {
		catent.d_type = type;
		catent.d_namlen = namelen;
		catent.d_reclen = uiosize = STD_DIRENT_LEN(namelen);
		if (hide)
			catent.d_fileno = 0;  /* file number = 0 means skip entry */
		else
			catent.d_fileno = cnid;
		uioaddr = (caddr_t) &catent;
	}

	/* Save current base address for post processing of hard-links. */
	uiobase = uio_curriovbase(state->cbs_uio);

	/* If this entry won't fit then we're done */
	if ((uiosize > uio_resid(state->cbs_uio)) ||
	    (ilinkref != 0 && state->cbs_nlinks == state->cbs_maxlinks)) {
		return (0);	/* stop */
	}

	if (!state->cbs_extended || state->cbs_hasprevdirentry) {
		state->cbs_result = uiomove(uioaddr, uiosize, state->cbs_uio);
		if (state->cbs_result == 0) {
			++state->cbs_index;

			/* Remember previous entry */
			state->cbs_desc->cd_cnid = cnid;
			if (type == DT_DIR) {
				state->cbs_desc->cd_flags |= CD_ISDIR;
			} else {
				state->cbs_desc->cd_flags &= ~CD_ISDIR;
			}
			if (state->cbs_desc->cd_nameptr != NULL) {
				vfs_removename(state->cbs_desc->cd_nameptr);
			}
#if 0
			state->cbs_desc->cd_encoding = xxxx;
#endif
			if (!is_mangled) {
				state->cbs_desc->cd_namelen = namelen;
				state->cbs_desc->cd_nameptr = vfs_addname(nameptr, namelen, 0, 0);
			} else {
				/* Store unmangled name for the directory hint else it will 
				 * restart readdir at the last location again 
				 */
				char *new_nameptr;
				size_t bufsize;
				size_t tmp_namelen = 0;
			
				cnp = (CatalogName *)&ckp->hfsPlus.nodeName;
				bufsize = 1 + utf8_encodelen(cnp->ustr.unicode,
											 cnp->ustr.length * sizeof(UniChar),
											 ':', 0);
				MALLOC(new_nameptr, char *, bufsize, M_TEMP, M_WAITOK);
				result = utf8_encodestr(cnp->ustr.unicode,
										cnp->ustr.length * sizeof(UniChar),
										new_nameptr, &tmp_namelen,
										bufsize, ':', 0);
			
				state->cbs_desc->cd_namelen = tmp_namelen;
				state->cbs_desc->cd_nameptr = vfs_addname(new_nameptr, tmp_namelen, 0, 0);
			
				FREE(new_nameptr, M_TEMP);
			} 
		}
		if (state->cbs_hasprevdirentry) {
			curlinkref = ilinkref;               /* save current */
			ilinkref = state->cbs_previlinkref;  /* use previous */
		}
		/*
		 * Record any hard links for post processing.
		 */
		if ((ilinkref != 0) &&
			(state->cbs_result == 0) &&
			(state->cbs_nlinks < state->cbs_maxlinks)) {
			state->cbs_linkinfo[state->cbs_nlinks].dirent_addr = uiobase;
			state->cbs_linkinfo[state->cbs_nlinks].link_ref = ilinkref;
			state->cbs_nlinks++;
		}
		if (state->cbs_hasprevdirentry) {
			ilinkref = curlinkref;   /* restore current */
		}
	}

	if (state->cbs_extended) {	/* fill the direntry to be used the next time */
		if (stop_after_pack) {
			state->cbs_eof = true;
			return (0);	/* stop */
		}
		entry->d_type = type;
		entry->d_namlen = namelen;
		entry->d_reclen = EXT_DIRENT_LEN(namelen);
		if (hide)
			entry->d_fileno = 0;  /* file number = 0 means skip entry */
		else
			entry->d_fileno = cnid;
		/* swap the current and previous entry */
		struct direntry * tmp;
		tmp = state->cbs_direntry;
		state->cbs_direntry = state->cbs_prevdirentry;
		state->cbs_prevdirentry = tmp;
		state->cbs_hasprevdirentry = true;
		state->cbs_previlinkref = ilinkref;
	}

	/* Continue iteration if there's room */
	return (state->cbs_result == 0  &&
		uio_resid(state->cbs_uio) >= SMALL_DIRENTRY_SIZE);
}


/*
 * Pack a uio buffer with directory entries from the catalog
 */
__private_extern__
int
cat_getdirentries(struct hfsmount *hfsmp, int entrycnt, directoryhint_t *dirhint,
				  uio_t uio, int extended, int * items, int * eofflag)
{
	FCB* fcb;
	BTreeIterator * iterator;
	CatalogKey * key;
	struct packdirentry_state state;
	void * buffer;
	int bufsize;
	int maxlinks;
	int result;
	int index;
	int have_key;
	
	fcb = GetFileControlBlock(hfsmp->hfs_catalog_vp);

	/*
	 * Get a buffer for link info array, btree iterator and a direntry:
	 */
	maxlinks = MIN(entrycnt, uio_resid(uio) / SMALL_DIRENTRY_SIZE);
	bufsize = (maxlinks * sizeof(linkinfo_t)) + sizeof(*iterator);
	if (extended) {
		bufsize += 2*sizeof(struct direntry);
	}
	MALLOC(buffer, void *, bufsize, M_TEMP, M_WAITOK);
	bzero(buffer, bufsize);

	state.cbs_extended = extended;
	state.cbs_hasprevdirentry = false;
	state.cbs_previlinkref = 0;
	state.cbs_nlinks = 0;
	state.cbs_maxlinks = maxlinks;
	state.cbs_linkinfo = (linkinfo_t *) buffer;

	iterator = (BTreeIterator *) ((char *)buffer + (maxlinks * sizeof(linkinfo_t)));
	key = (CatalogKey *)&iterator->key;
	have_key = 0;
	index = dirhint->dh_index + 1;
	if (extended) {
		state.cbs_direntry = (struct direntry *)((char *)iterator + sizeof(BTreeIterator));
		state.cbs_prevdirentry = state.cbs_direntry + 1;
		state.cbs_eof = false;
	}
	/*
	 * Attempt to build a key from cached filename
	 */
	if (dirhint->dh_desc.cd_namelen != 0) {
		if (buildkey(hfsmp, &dirhint->dh_desc, (HFSPlusCatalogKey *)key, 0) == 0) {
			have_key = 1;
		}
	}

	/*
	 * If the last entry wasn't cached then position the btree iterator
	 */
	if ((index == 0) || !have_key) {
		/*
		 * Position the iterator at the directory's thread record.
		 * (i.e. just before the first entry)
		 */
		buildthreadkey(dirhint->dh_desc.cd_parentcnid, (hfsmp->hfs_flags & HFS_STANDARD), key);
		result = BTSearchRecord(fcb, iterator, NULL, NULL, iterator);
		if (result) {
			result = MacToVFSError(result);
			goto cleanup;
		}
	
		/*
		 * Iterate until we reach the entry just
		 * before the one we want to start with.
		 */
		if (index > 0) {
			struct position_state ps;

			ps.error = 0;
			ps.count = 0;
			ps.index = index;
			ps.parentID = dirhint->dh_desc.cd_parentcnid;
			ps.hfsmp = hfsmp;

			result = BTIterateRecords(fcb, kBTreeNextRecord, iterator,
			                          (IterateCallBackProcPtr)cat_findposition, &ps);
			if (ps.error)
				result = ps.error;
			else
				result = MacToVFSError(result);
			if (result) {
				result = MacToVFSError(result);
				goto cleanup;
			}
		}
	}

	state.cbs_index = index;
	state.cbs_hfsmp = hfsmp;
	state.cbs_uio = uio;
	state.cbs_desc = &dirhint->dh_desc;
	state.cbs_result = 0;
	state.cbs_parentID = dirhint->dh_desc.cd_parentcnid;

	enum BTreeIterationOperations op;
	if (extended && index != 0 && have_key)
		op = kBTreeCurrentRecord;
	else
		op = kBTreeNextRecord;

	/*
	 * Process as many entries as possible starting at iterator->key.
	 */
	result = BTIterateRecords(fcb, op, iterator,
	                          (IterateCallBackProcPtr)cat_packdirentry, &state);

	/* Note that state.cbs_index is still valid on errors */
	*items = state.cbs_index - index;
	index = state.cbs_index;

	if (state.cbs_eof) {
		*eofflag = 1;
	}
	
	/* Finish updating the catalog iterator. */
	dirhint->dh_desc.cd_hint = iterator->hint.nodeNum;
	dirhint->dh_desc.cd_flags |= CD_DECOMPOSED;
	dirhint->dh_index = index - 1;
	
	/*
	 * Post process any hard links to get the real file id.
	 */
	if (state.cbs_nlinks > 0) {
		u_int32_t fileid = 0;
		user_addr_t address;
		int i;

		for (i = 0; i < state.cbs_nlinks; ++i) {
			if (resolvelinkid(hfsmp, state.cbs_linkinfo[i].link_ref, &fileid) != 0)
				continue;
			/* This assumes that d_ino is always first field. */
			address = state.cbs_linkinfo[i].dirent_addr;
			if (address == (user_addr_t)0)
				continue;
			if (uio_isuserspace(uio)) {
				(void) copyout(&fileid, address,
				               extended ? sizeof(ino64_t) : sizeof(ino_t));
			} else /* system space */ {
				ino64_t *inoptr = (ino64_t *)CAST_DOWN(caddr_t, address);
				*inoptr = fileid;
			}
		}
	}

	if (state.cbs_result)
		result = state.cbs_result;
	else
		result = MacToVFSError(result);

	if (result == ENOENT) {
		result = 0;
	}

cleanup:
	FREE(buffer, M_TEMP);
	
	return (result);
}


/*
 * Callback to establish directory position.
 * Called with position_state for each item in a directory.
 */
static int
cat_findposition(const CatalogKey *ckp, const CatalogRecord *crp,
                 struct position_state *state)
{
	cnid_t curID;

	if (state->hfsmp->hfs_flags & HFS_STANDARD)
		curID = ckp->hfs.parentID;
	else
		curID = ckp->hfsPlus.parentID;

	/* Make sure parent directory didn't change */
	if (state->parentID != curID) {
		state->error = EINVAL;
		return (0);  /* stop */
	}

	/* Count this entry */
	switch(crp->recordType) {
	case kHFSPlusFolderRecord:
	case kHFSPlusFileRecord:
	case kHFSFolderRecord:
	case kHFSFileRecord:
		++state->count;
		break;
	default:
		printf("cat_findposition: invalid record type %d in dir %d\n",
			crp->recordType, curID);
		state->error = EINVAL;
		return (0);  /* stop */
	};

	return (state->count < state->index);
}


/*
 * cat_binarykeycompare - compare two HFS Plus catalog keys.

 * The name portion of the key is compared using a 16-bit binary comparison. 
 * This is called from the b-tree code.
 */
__private_extern__
int
cat_binarykeycompare(HFSPlusCatalogKey *searchKey, HFSPlusCatalogKey *trialKey)
{
	u_int32_t searchParentID, trialParentID;
	int result;

	searchParentID = searchKey->parentID;
	trialParentID = trialKey->parentID;
	result = 0;
	
	if (searchParentID > trialParentID) {
		++result;
	} else if (searchParentID < trialParentID) {
		--result;
	} else {
		u_int16_t * str1 = &searchKey->nodeName.unicode[0];
		u_int16_t * str2 = &trialKey->nodeName.unicode[0];
		int length1 = searchKey->nodeName.length;
		int length2 = trialKey->nodeName.length;
		u_int16_t c1, c2;
		int length;
	
		if (length1 < length2) {
			length = length1;
			--result;
		} else if (length1 > length2) {
			length = length2;
			++result;
		} else {
			length = length1;
		}
	
		while (length--) {
			c1 = *(str1++);
			c2 = *(str2++);
	
			if (c1 > c2) {
				result = 1;
				break;
			}
			if (c1 < c2) {
				result = -1;
				break;
			}
		}
	}

	return result;
}


/*
 * Compare two standard HFS catalog keys
 *
 * Result: +n  search key > trial key
 *          0  search key = trial key
 *         -n  search key < trial key
 */
int
CompareCatalogKeys(HFSCatalogKey *searchKey, HFSCatalogKey *trialKey)
{
	cnid_t searchParentID, trialParentID;
	int result;

	searchParentID = searchKey->parentID;
	trialParentID = trialKey->parentID;

	if (searchParentID > trialParentID)
		result = 1;
	else if (searchParentID < trialParentID)
		result = -1;
	else /* parent dirID's are equal, compare names */
		result = FastRelString(searchKey->nodeName, trialKey->nodeName);

	return result;
}


/*
 * Compare two HFS+ catalog keys
 *
 * Result: +n  search key > trial key
 *          0  search key = trial key
 *         -n  search key < trial key
 */
int
CompareExtendedCatalogKeys(HFSPlusCatalogKey *searchKey, HFSPlusCatalogKey *trialKey)
{
	cnid_t searchParentID, trialParentID;
	int result;

	searchParentID = searchKey->parentID;
	trialParentID = trialKey->parentID;
	
	if (searchParentID > trialParentID) {
		result = 1;
	}
	else if (searchParentID < trialParentID) {
		result = -1;
	} else {
		/* parent node ID's are equal, compare names */
		if ( searchKey->nodeName.length == 0 || trialKey->nodeName.length == 0 )
			result = searchKey->nodeName.length - trialKey->nodeName.length;
		else
			result = FastUnicodeCompare(&searchKey->nodeName.unicode[0],
			                            searchKey->nodeName.length,
			                            &trialKey->nodeName.unicode[0],
			                            trialKey->nodeName.length);
	}

	return result;
}


/*
 * buildkey - build a Catalog b-tree key from a cnode descriptor
 */
static int
buildkey(struct hfsmount *hfsmp, struct cat_desc *descp,
	HFSPlusCatalogKey *key, int retry)
{
	int utf8_flags = 0;
	int result = 0;
	size_t unicodeBytes = 0;

	if (descp->cd_namelen == 0 || descp->cd_nameptr[0] == '\0')
		return (EINVAL);  /* invalid name */

	key->parentID = descp->cd_parentcnid;
	key->nodeName.length = 0;
	/*
	 * Convert filename from UTF-8 into Unicode
	 */
	
	if ((descp->cd_flags & CD_DECOMPOSED) == 0)
		utf8_flags |= UTF_DECOMPOSED;
	result = utf8_decodestr(descp->cd_nameptr, descp->cd_namelen,
		key->nodeName.unicode, &unicodeBytes,
		sizeof(key->nodeName.unicode), ':', utf8_flags);
	key->nodeName.length = unicodeBytes / sizeof(UniChar);
	key->keyLength = kHFSPlusCatalogKeyMinimumLength + unicodeBytes;
	if (result) {
		if (result != ENAMETOOLONG)
			result = EINVAL;  /* name has invalid characters */
		return (result);
	}

	/*
	 * For HFS volumes convert to an HFS compatible key
	 *
	 * XXX need to save the encoding that succeeded
	 */
	if (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord) {
		HFSCatalogKey hfskey;

		bzero(&hfskey, sizeof(hfskey));
		hfskey.keyLength = kHFSCatalogKeyMinimumLength;
		hfskey.parentID = key->parentID;
		hfskey.nodeName[0] = 0;
		if (key->nodeName.length > 0) {
			if (unicode_to_hfs(HFSTOVCB(hfsmp),
				key->nodeName.length * 2,
				key->nodeName.unicode,
				&hfskey.nodeName[0], retry) != 0) {
				return (EINVAL);
			}
			hfskey.keyLength += hfskey.nodeName[0];
		}
		bcopy(&hfskey, key, sizeof(hfskey));
	}
	return (0);
 }


/*
 * Resolve hard link reference to obtain the inode record.
 */
__private_extern__
int
resolvelink(struct hfsmount *hfsmp, u_long linkref, struct HFSPlusCatalogFile *recp)
{
	FSBufferDescriptor btdata;
	struct BTreeIterator *iterator;
	struct cat_desc idesc;
	char inodename[32];
	int result = 0;

	BDINIT(btdata, recp);
	MAKE_INODE_NAME(inodename, linkref);

	/* Get space for iterator */	
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	/* Build a descriptor for private dir. */	
	idesc.cd_parentcnid = hfsmp->hfs_privdir_desc.cd_cnid;
	idesc.cd_nameptr = inodename;
	idesc.cd_namelen = strlen(inodename);
	idesc.cd_flags = 0;
	idesc.cd_hint = 0;
	idesc.cd_encoding = 0;
	(void) buildkey(hfsmp, &idesc, (HFSPlusCatalogKey *)&iterator->key, 0);

	result = BTSearchRecord(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), iterator,
				&btdata, NULL, NULL);

	if (result == 0) {
		/* Make sure there's a reference */
		if (recp->bsdInfo.special.linkCount == 0)
			recp->bsdInfo.special.linkCount = 2;
	} else {
		printf("HFS resolvelink: can't find %s\n", inodename);
	}

	FREE(iterator, M_TEMP);

	return (result ? ENOENT : 0);
}

/*
 * Resolve hard link reference to obtain the inode number.
 */
static int
resolvelinkid(struct hfsmount *hfsmp, u_long linkref, ino_t *ino)
{
	struct HFSPlusCatalogFile record;
	int error;
	
	error = resolvelink(hfsmp, linkref, &record);
	if (error == 0) {
		if (record.fileID == 0)
			error = ENOENT;
		else
			*ino = record.fileID;
	}
	return (error);
}

/*
 * getkey - get a key from id by doing a thread lookup
 */
static int
getkey(struct hfsmount *hfsmp, cnid_t cnid, CatalogKey * key)
{
	struct BTreeIterator * iterator;
	FSBufferDescriptor btdata;
	UInt16	datasize;
	CatalogKey * keyp;
	CatalogRecord * recp;
	int result;
	int std_hfs;

	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	buildthreadkey(cnid, std_hfs, (CatalogKey *)&iterator->key);

	MALLOC(recp, CatalogRecord *, sizeof(CatalogRecord), M_TEMP, M_WAITOK);
	BDINIT(btdata, recp);

	result = BTSearchRecord(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), iterator,
				&btdata, &datasize, iterator);
	if (result)
		goto exit;

	/* Turn thread record into a cnode key (in place) */
	switch (recp->recordType) {
	case kHFSFileThreadRecord:
	case kHFSFolderThreadRecord:
		keyp = (CatalogKey *)((char *)&recp->hfsThread.reserved + 6);
		keyp->hfs.keyLength = kHFSCatalogKeyMinimumLength + keyp->hfs.nodeName[0];
		bcopy(keyp, key, keyp->hfs.keyLength + 1);
		break;

	case kHFSPlusFileThreadRecord:
	case kHFSPlusFolderThreadRecord:
		keyp = (CatalogKey *)&recp->hfsPlusThread.reserved;
		keyp->hfsPlus.keyLength = kHFSPlusCatalogKeyMinimumLength +
		                          (keyp->hfsPlus.nodeName.length * 2);
		bcopy(keyp, key, keyp->hfsPlus.keyLength + 2);
		break;

	default:
		result = ENOENT;
		break;
	}

exit:
	FREE(iterator, M_TEMP);
	FREE(recp, M_TEMP);

	return MacToVFSError(result);
}

/*
 * getkeyplusattr - From id, fetch the key and the bsd attrs for a file/dir (could pass
 * null arguments to cat_idlookup instead, but we save around 10% by not building the 
 * cat_desc here). Both key and attrp must point to real structures.
 */
__private_extern__
int
cat_getkeyplusattr(struct hfsmount *hfsmp, cnid_t cnid, CatalogKey * key, struct cat_attr *attrp)
{
	int result;

	result = getkey(hfsmp, cnid, key);
       
	if (result == 0) {
		result = cat_lookupbykey(hfsmp, key, 0, 0, NULL, attrp, NULL, NULL);
	}

	return MacToVFSError(result);
}


/*
 * buildrecord - build a default catalog directory or file record
 */
static void
buildrecord(struct cat_attr *attrp, cnid_t cnid, int std_hfs, u_int32_t encoding,
            CatalogRecord *crp, int *recordSize)
{
	int type = attrp->ca_mode & S_IFMT;
	u_int32_t createtime = to_hfs_time(attrp->ca_itime);

	if (std_hfs) {
		createtime = UTCToLocal(createtime);
		if (type == S_IFDIR) {
			bzero(crp, sizeof(HFSCatalogFolder));
			crp->recordType = kHFSFolderRecord;
			crp->hfsFolder.folderID = cnid;
			crp->hfsFolder.createDate = createtime;
			crp->hfsFolder.modifyDate = createtime;
			bcopy(attrp->ca_finderinfo, &crp->hfsFolder.userInfo, 32);
			*recordSize = sizeof(HFSCatalogFolder);
		} else {
			bzero(crp, sizeof(HFSCatalogFile));
			crp->recordType = kHFSFileRecord;
			crp->hfsFile.fileID = cnid;
			crp->hfsFile.createDate = createtime;
			crp->hfsFile.modifyDate = createtime;
			bcopy(attrp->ca_finderinfo, &crp->hfsFile.userInfo, 16);
			bcopy(&attrp->ca_finderinfo[16], &crp->hfsFile.finderInfo, 16);
			*recordSize = sizeof(HFSCatalogFile);
		}
	} else {
		struct HFSPlusBSDInfo * bsdp = NULL;
		struct FndrFileInfo * fip = NULL;

		if (type == S_IFDIR) {
			crp->recordType = kHFSPlusFolderRecord;
			crp->hfsPlusFolder.flags = 0;
			crp->hfsPlusFolder.valence = 0;
			crp->hfsPlusFolder.folderID = cnid;	
			crp->hfsPlusFolder.createDate = createtime;
			crp->hfsPlusFolder.contentModDate = createtime;
			crp->hfsPlusFolder.attributeModDate = createtime;
			crp->hfsPlusFolder.accessDate = createtime;
			crp->hfsPlusFolder.backupDate = 0;
			crp->hfsPlusFolder.textEncoding = encoding;
			crp->hfsPlusFolder.attrBlocks = 0;
			bcopy(attrp->ca_finderinfo, &crp->hfsPlusFolder.userInfo, 32);
			bsdp = &crp->hfsPlusFolder.bsdInfo;
			bsdp->special.rawDevice = 0;
			*recordSize = sizeof(HFSPlusCatalogFolder);
		} else {
			crp->recordType = kHFSPlusFileRecord;
			crp->hfsPlusFile.flags = kHFSThreadExistsMask;
			crp->hfsPlusFile.reserved1 = 0;
			crp->hfsPlusFile.fileID = cnid;
			crp->hfsPlusFile.createDate = createtime;
			crp->hfsPlusFile.contentModDate = createtime;
			crp->hfsPlusFile.accessDate = createtime;
			crp->hfsPlusFile.attributeModDate = createtime;
			crp->hfsPlusFile.backupDate = 0;
			crp->hfsPlusFile.textEncoding = encoding;
			crp->hfsPlusFile.attrBlocks = 0;
			bsdp = &crp->hfsPlusFile.bsdInfo;
			bsdp->special.rawDevice = 0;
			switch(type) {
			case S_IFBLK:
			case S_IFCHR:
				/* BLK/CHR need to save the device info */
				bsdp->special.rawDevice = attrp->ca_rdev;
				bzero(&crp->hfsPlusFile.userInfo, 32);
				break;
			case S_IFREG:
				/* Hardlink links need to save the linkref */
				fip = (FndrFileInfo *)&attrp->ca_finderinfo;
				if ((SWAP_BE32(fip->fdType) == kHardLinkFileType) &&
				    (SWAP_BE32(fip->fdCreator) == kHFSPlusCreator)) {
					bsdp->special.iNodeNum = attrp->ca_rdev;
				}
				bcopy(attrp->ca_finderinfo, &crp->hfsPlusFile.userInfo, 32);
				break;
			case S_IFLNK:
				/* Symlinks also have a type and creator */
				bcopy(attrp->ca_finderinfo, &crp->hfsPlusFile.userInfo, 32);
				break;
			}
			bzero(&crp->hfsPlusFile.dataFork, 2*sizeof(HFSPlusForkData));
			*recordSize = sizeof(HFSPlusCatalogFile);
		}
		bsdp->ownerID    = attrp->ca_uid;
		bsdp->groupID    = attrp->ca_gid;
		bsdp->fileMode   = attrp->ca_mode;
		bsdp->adminFlags = attrp->ca_flags >> 16;
		bsdp->ownerFlags = attrp->ca_flags & 0x000000FF;
	}
}


/*
 * builddesc - build a cnode descriptor from an HFS+ key
 */
static int
builddesc(const HFSPlusCatalogKey *key, cnid_t cnid, u_long hint, u_long encoding,
	int isdir, struct cat_desc *descp)
{
	int result = 0;
	char * nameptr;
	size_t bufsize;
	size_t utf8len;
	char tmpbuff[128];

	/* guess a size... */
	bufsize = (3 * key->nodeName.length) + 1;
	if (bufsize >= sizeof(tmpbuff) - 1) {
	    MALLOC(nameptr, char *, bufsize, M_TEMP, M_WAITOK);
	} else {
	    nameptr = &tmpbuff[0];
	}

	result = utf8_encodestr(key->nodeName.unicode,
			key->nodeName.length * sizeof(UniChar),
			nameptr, (size_t *)&utf8len,
			bufsize, ':', 0);

	if (result == ENAMETOOLONG) {
		bufsize = 1 + utf8_encodelen(key->nodeName.unicode,
		                             key->nodeName.length * sizeof(UniChar),
		                             ':', 0);
		FREE(nameptr, M_TEMP);
		MALLOC(nameptr, char *, bufsize, M_TEMP, M_WAITOK);

		result = utf8_encodestr(key->nodeName.unicode,
		                        key->nodeName.length * sizeof(UniChar),
		                        nameptr, (size_t *)&utf8len,
		                        bufsize, ':', 0);
	}
	descp->cd_parentcnid = key->parentID;
	descp->cd_nameptr = vfs_addname(nameptr, utf8len, 0, 0);
	descp->cd_namelen = utf8len;
	descp->cd_cnid = cnid;
	descp->cd_hint = hint;
	descp->cd_flags = CD_DECOMPOSED | CD_HASBUF;
	if (isdir)
		descp->cd_flags |= CD_ISDIR;	
	descp->cd_encoding = encoding;
	if (nameptr != &tmpbuff[0]) {
	    FREE(nameptr, M_TEMP);
	}
	return result;
}


/*
 * getbsdattr - get attributes in bsd format
 *
 */
static void
getbsdattr(struct hfsmount *hfsmp, const struct HFSPlusCatalogFile *crp, struct cat_attr * attrp)
{
	int isDirectory = (crp->recordType == kHFSPlusFolderRecord);
	const struct HFSPlusBSDInfo *bsd = &crp->bsdInfo;

	attrp->ca_recflags = crp->flags;
	attrp->ca_nlink = 1;
	attrp->ca_atime = to_bsd_time(crp->accessDate);
	attrp->ca_atimeondisk = attrp->ca_atime;	
	attrp->ca_mtime = to_bsd_time(crp->contentModDate);
	attrp->ca_ctime = to_bsd_time(crp->attributeModDate);
	attrp->ca_itime = to_bsd_time(crp->createDate);
	attrp->ca_btime = to_bsd_time(crp->backupDate);

	if ((bsd->fileMode & S_IFMT) == 0) {
		attrp->ca_flags = 0;
		attrp->ca_uid = hfsmp->hfs_uid;
		attrp->ca_gid = hfsmp->hfs_gid;
		if (isDirectory)
			attrp->ca_mode = S_IFDIR | (hfsmp->hfs_dir_mask & ACCESSPERMS);
		else
			attrp->ca_mode = S_IFREG | (hfsmp->hfs_file_mask & ACCESSPERMS);
		attrp->ca_rdev = 0;
	} else {
		attrp->ca_rdev = 0;
		attrp->ca_uid = bsd->ownerID;
		attrp->ca_gid = bsd->groupID;
		attrp->ca_flags = bsd->ownerFlags | (bsd->adminFlags << 16);
		attrp->ca_mode = (mode_t)bsd->fileMode;
		switch (attrp->ca_mode & S_IFMT) {
		case S_IFCHR: /* fall through */
		case S_IFBLK:
			attrp->ca_rdev = bsd->special.rawDevice;
			break;
		case S_IFREG:
			/* Pick up the hard link count */
			if (bsd->special.linkCount > 0)
				attrp->ca_nlink = bsd->special.linkCount;
			break;
		}

		if (((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS) {
			/*
			 *  Override the permissions as determined by the mount auguments
			 *  in ALMOST the same way unset permissions are treated but keep
			 *  track of whether or not the file or folder is hfs locked
			 *  by leaving the h_pflags field unchanged from what was unpacked
			 *  out of the catalog.
			 */
			attrp->ca_uid = hfsmp->hfs_uid;
			attrp->ca_gid = hfsmp->hfs_gid;
		}
	}

	if (isDirectory) {
		if (!S_ISDIR(attrp->ca_mode)) {
			attrp->ca_mode &= ~S_IFMT;
			attrp->ca_mode |= S_IFDIR;
		}
		attrp->ca_nlink = 2 + ((HFSPlusCatalogFolder *)crp)->valence;
		attrp->ca_entries = ((HFSPlusCatalogFolder *)crp)->valence;
		attrp->ca_attrblks = ((HFSPlusCatalogFolder *)crp)->attrBlocks;
	} else {
		/* Keep IMMUTABLE bits in sync with HFS locked flag */
		if (crp->flags & kHFSFileLockedMask) {
			/* The file's supposed to be locked:
			   Make sure at least one of the IMMUTABLE bits is set: */
			if ((attrp->ca_flags & (SF_IMMUTABLE | UF_IMMUTABLE)) == 0)
				attrp->ca_flags |= UF_IMMUTABLE;
		} else {
			/* The file's supposed to be unlocked: */
			attrp->ca_flags &= ~(SF_IMMUTABLE | UF_IMMUTABLE);
		}
		/* get total blocks (both forks) */
		attrp->ca_blocks = crp->dataFork.totalBlocks + crp->resourceFork.totalBlocks;
		attrp->ca_attrblks = crp->attrBlocks;
		/* On HFS+ the ThreadExists flag must always be set. */
		if ((hfsmp->hfs_flags & HFS_STANDARD) == 0)
			attrp->ca_recflags |= kHFSThreadExistsMask;
	}
	
	attrp->ca_fileid = crp->fileID;

	bcopy(&crp->userInfo, attrp->ca_finderinfo, 32);
}

/*
 * promotekey - promote hfs key to hfs plus key
 *
 */
static void
promotekey(struct hfsmount *hfsmp, const HFSCatalogKey *hfskey,
           HFSPlusCatalogKey *keyp, u_long *encoding)
{
	hfs_to_unicode_func_t hfs_get_unicode = hfsmp->hfs_get_unicode;
	UInt32 uniCount;
	int error;

	*encoding = hfsmp->hfs_encoding;

	error = hfs_get_unicode(hfskey->nodeName, keyp->nodeName.unicode,
	                        kHFSPlusMaxFileNameChars, &uniCount);
	/*
	 * When an HFS name cannot be encoded with the current
	 * encoding use MacRoman as a fallback.
	 */
	if (error && hfsmp->hfs_encoding != kTextEncodingMacRoman) {
		*encoding = 0;
		(void) mac_roman_to_unicode(hfskey->nodeName,
		                            keyp->nodeName.unicode,
		                            kHFSPlusMaxFileNameChars,
		                            &uniCount);
	}

	keyp->nodeName.length = uniCount;
	keyp->parentID = hfskey->parentID;
}

/*
 * promotefork - promote hfs fork info to hfs plus
 *
 */
static void
promotefork(struct hfsmount *hfsmp, const struct HFSCatalogFile *filep,
            int resource, struct cat_fork * forkp)
{
	struct HFSPlusExtentDescriptor *xp;
	u_long blocksize = HFSTOVCB(hfsmp)->blockSize;

	bzero(forkp, sizeof(*forkp));
	xp = &forkp->cf_extents[0];
	if (resource) {
		forkp->cf_size = filep->rsrcLogicalSize;
		forkp->cf_blocks = filep->rsrcPhysicalSize / blocksize;
		forkp->cf_bytesread = 0;
		forkp->cf_vblocks = 0;
		xp[0].startBlock = (u_int32_t)filep->rsrcExtents[0].startBlock;
		xp[0].blockCount = (u_int32_t)filep->rsrcExtents[0].blockCount;
		xp[1].startBlock = (u_int32_t)filep->rsrcExtents[1].startBlock;
		xp[1].blockCount = (u_int32_t)filep->rsrcExtents[1].blockCount;
		xp[2].startBlock = (u_int32_t)filep->rsrcExtents[2].startBlock;
		xp[2].blockCount = (u_int32_t)filep->rsrcExtents[2].blockCount;
	} else {
		forkp->cf_size = filep->dataLogicalSize;
		forkp->cf_blocks = filep->dataPhysicalSize / blocksize;
		forkp->cf_bytesread = 0;
		forkp->cf_vblocks = 0;
		xp[0].startBlock = (u_int32_t)filep->dataExtents[0].startBlock;
		xp[0].blockCount = (u_int32_t)filep->dataExtents[0].blockCount;
		xp[1].startBlock = (u_int32_t)filep->dataExtents[1].startBlock;
		xp[1].blockCount = (u_int32_t)filep->dataExtents[1].blockCount;
		xp[2].startBlock = (u_int32_t)filep->dataExtents[2].startBlock;
		xp[2].blockCount = (u_int32_t)filep->dataExtents[2].blockCount;
	}
}

/*
 * promoteattr - promote hfs catalog attributes to hfs plus
 *
 */
static void
promoteattr(struct hfsmount *hfsmp, const CatalogRecord *dataPtr, struct HFSPlusCatalogFile *crp)
{
	u_long blocksize = HFSTOVCB(hfsmp)->blockSize;

	if (dataPtr->recordType == kHFSFolderRecord) {
		struct HFSCatalogFolder * folder;

		folder = (struct HFSCatalogFolder *) dataPtr;
		crp->recordType       = kHFSPlusFolderRecord;
		crp->flags            = folder->flags;
		crp->fileID           = folder->folderID;
		crp->createDate       = LocalToUTC(folder->createDate);
		crp->contentModDate   = LocalToUTC(folder->modifyDate);
		crp->backupDate       = LocalToUTC(folder->backupDate);
		crp->reserved1        = folder->valence;
		bcopy(&folder->userInfo, &crp->userInfo, 32);
	} else /* file */ {
		struct HFSCatalogFile * file;

		file = (struct HFSCatalogFile *) dataPtr;
		crp->recordType       = kHFSPlusFileRecord;
		crp->flags            = file->flags;
		crp->fileID           = file->fileID;
		crp->createDate       = LocalToUTC(file->createDate);
		crp->contentModDate   = LocalToUTC(file->modifyDate);
		crp->backupDate       = LocalToUTC(file->backupDate);
		crp->reserved1        = 0;
		bcopy(&file->userInfo, &crp->userInfo, 16);
		bcopy(&file->finderInfo, &crp->finderInfo, 16);
		crp->dataFork.totalBlocks = file->dataPhysicalSize / blocksize;
		crp->resourceFork.totalBlocks = file->rsrcPhysicalSize / blocksize;
	}
	crp->textEncoding = 0;
	crp->attributeModDate = crp->contentModDate;
	crp->accessDate = crp->contentModDate;
	bzero(&crp->bsdInfo, sizeof(HFSPlusBSDInfo));
	crp->attrBlocks = 0;
}

/*
 * Build a catalog node thread record from a catalog key
 * and return the size of the record.
 */
static int
buildthread(void *keyp, void *recp, int std_hfs, int directory)
{
	int size = 0;

	if (std_hfs) {
		HFSCatalogKey *key = (HFSCatalogKey *)keyp;
		HFSCatalogThread *rec = (HFSCatalogThread *)recp;

		size = sizeof(HFSCatalogThread);
		bzero(rec, size);
		if (directory)
			rec->recordType = kHFSFolderThreadRecord;
		else
			rec->recordType = kHFSFileThreadRecord;
		rec->parentID = key->parentID;
		bcopy(key->nodeName, rec->nodeName, key->nodeName[0]+1);

	} else /* HFS+ */ {
		HFSPlusCatalogKey *key = (HFSPlusCatalogKey *)keyp;
		HFSPlusCatalogThread *rec = (HFSPlusCatalogThread *)recp;

		size = sizeof(HFSPlusCatalogThread);
		if (directory)
			rec->recordType = kHFSPlusFolderThreadRecord;
		else
			rec->recordType = kHFSPlusFileThreadRecord;
		rec->reserved = 0;
		rec->parentID = key->parentID;			
		bcopy(&key->nodeName, &rec->nodeName,
			sizeof(UniChar) * (key->nodeName.length + 1));

		/* HFS Plus has varaible sized thread records */
		size -= (sizeof(rec->nodeName.unicode) -
			  (rec->nodeName.length * sizeof(UniChar)));
	}
	
	return (size);
}

/*
 * Build a catalog node thread key.
 */
static void
buildthreadkey(HFSCatalogNodeID parentID, int std_hfs, CatalogKey *key)
{
	if (std_hfs) {
		key->hfs.keyLength = kHFSCatalogKeyMinimumLength;
		key->hfs.reserved = 0;
		key->hfs.parentID = parentID;
		key->hfs.nodeName[0] = 0;
	} else {
		key->hfsPlus.keyLength = kHFSPlusCatalogKeyMinimumLength;
		key->hfsPlus.parentID = parentID;
		key->hfsPlus.nodeName.length = 0;
	}
}

/*
 * Extract the text encoding from a catalog node record.
 */
static u_long 
getencoding(const CatalogRecord *crp)
{
	u_long encoding;

	if (crp->recordType == kHFSPlusFolderRecord)
		encoding = crp->hfsPlusFolder.textEncoding;
	else if (crp->recordType == kHFSPlusFileRecord)
		encoding = crp->hfsPlusFile.textEncoding;
	else
		encoding = 0;

	return (encoding);
}

/*
 * Extract the CNID from a catalog node record.
 */
static cnid_t 
getcnid(const CatalogRecord *crp)
{
	cnid_t cnid = 0;

	switch (crp->recordType) {
	case kHFSFolderRecord:
		cnid = crp->hfsFolder.folderID;
		break;
	case kHFSFileRecord:
		cnid = crp->hfsFile.fileID;
		break;
	case kHFSPlusFolderRecord:
		cnid = crp->hfsPlusFolder.folderID;
		break;
	case kHFSPlusFileRecord:
		cnid = crp->hfsPlusFile.fileID;
		break;
	default:
		printf("hfs: getcnid: unknown recordType (crp @ 0x%x)\n", crp);
		break;
	}

	return (cnid);
}

/*
 * Extract the parent ID from a catalog node record.
 */
static cnid_t 
getparentcnid(const CatalogRecord *recp)
{
	cnid_t cnid = 0;

	switch (recp->recordType) {
	case kHFSFileThreadRecord:
	case kHFSFolderThreadRecord:
		cnid = recp->hfsThread.parentID;
		break;

	case kHFSPlusFileThreadRecord:
	case kHFSPlusFolderThreadRecord:
		cnid = recp->hfsPlusThread.parentID;
		break;
	default:
		panic("hfs: getparentcnid: unknown recordType (crp @ 0x%x)\n", recp);
		break;
	}

	return (cnid);
}

/*
 * Determine if a catalog node record is a directory.
 */
static int 
isadir(const CatalogRecord *crp)
{
	return (crp->recordType == kHFSFolderRecord ||
		crp->recordType == kHFSPlusFolderRecord);
}

