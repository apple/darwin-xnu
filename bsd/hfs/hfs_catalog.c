/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/dirent.h>
#include <vfs/vfs_support.h>
#include <libkern/libkern.h>

#include <sys/utfconv.h>

#include "hfs.h"
#include "hfs_catalog.h"
#include "hfs_format.h"
#include "hfs_endian.h"

#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/CatalogPrivate.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"

extern OSErr PositionIterator(CatalogIterator *cip, UInt32 offset, BTreeIterator *bip, UInt16 *op);

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


static int cat_lookupbykey(struct hfsmount *hfsmp, CatalogKey *keyp, u_long hint, int wantrsrc,
                  struct cat_desc *descp, struct cat_attr *attrp, struct cat_fork *forkp);

static int cat_lookupmangled(struct hfsmount *hfsmp, struct cat_desc *descp, int wantrsrc,
                  struct cat_desc *outdescp, struct cat_attr *attrp, struct cat_fork *forkp);

extern int mac_roman_to_unicode(const Str31 hfs_str, UniChar *uni_str,
                                UInt32 maxCharLen, UInt32 *unicodeChars);

extern int unicode_to_hfs(ExtendedVCB *vcb, ByteCount srcLen,
                          const u_int16_t* srcStr, Str31 dstStr, int retry);


/* Internal catalog support routines */

int resolvelink(struct hfsmount *hfsmp, u_long linkref, struct HFSPlusCatalogFile *recp);

static int getkey(struct hfsmount *hfsmp, cnid_t cnid, CatalogKey * key);

static int buildkey(struct hfsmount *hfsmp, struct cat_desc *descp,
			HFSPlusCatalogKey *key, int retry);

static void buildthreadkey(HFSCatalogNodeID parentID, int std_hfs, CatalogKey *key);

static void buildrecord(struct cat_attr *attrp, cnid_t cnid, int std_hfs, u_int32_t encoding, CatalogRecord *crp, int *recordSize);

static int catrec_update(const CatalogKey *ckp, CatalogRecord *crp, u_int16_t reclen, struct update_state *state);

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
		bcopy(&recp->hfsPlusFile.dataFork, datafp, sizeof(*datafp));
		bcopy(&recp->hfsPlusFile.resourceFork, rsrcfp, sizeof(*rsrcfp));
	}
}

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
		FREE(name, M_TEMP);
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
int
cat_lookup(struct hfsmount *hfsmp, struct cat_desc *descp, int wantrsrc,
             struct cat_desc *outdescp, struct cat_attr *attrp,
             struct cat_fork *forkp)
{
	CatalogKey * keyp;
	int std_hfs;
	int result;

	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);

	MALLOC(keyp, CatalogKey *, sizeof(CatalogKey), M_TEMP, M_WAITOK);

	result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)keyp, 1);
	if (result)
		goto exit;

	result = cat_lookupbykey(hfsmp, keyp, descp->cd_hint, wantrsrc, outdescp, attrp, forkp);
	
	if (result == ENOENT) {
		if (!std_hfs) {
			result = cat_lookupmangled(hfsmp, descp, wantrsrc, outdescp, attrp, forkp);
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

	// XXXdbg - preflight all btree operations to make sure there's enough space
	result = BTCheckFreeSpace(fcb);
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
 * cat_idlookup - lookup a catalog node using a cnode id
 */
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

	result = cat_lookupbykey(hfsmp, keyp, 0, 0, outdescp, attrp, forkp);
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
                  struct cat_desc *descp, struct cat_attr *attrp, struct cat_fork *forkp)
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
	if (hfsmp->jnl &&
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
	    && ((to_bsd_time(recp->hfsPlusFile.createDate) == HFSTOVCB(hfsmp)->vcbCrDate) ||
	        (to_bsd_time(recp->hfsPlusFile.createDate) == hfsmp->hfs_metadata_createdate))) {

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
		if (isadir(recp))
			bzero(forkp, sizeof(*forkp));
		else if (std_hfs)
			promotefork(hfsmp, (HFSCatalogFile *)&recp->hfsFile, wantrsrc, forkp);
		else if (wantrsrc)
			bcopy(&recp->hfsPlusFile.resourceFork, forkp, sizeof(*forkp));
		else
			bcopy(&recp->hfsPlusFile.dataFork, forkp, sizeof(*forkp));
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
exit:
	FREE(iterator, M_TEMP);
	FREE(recp, M_TEMP);

	return MacToVFSError(result);
}


/*
 * cat_create - create a node in the catalog
 */
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
	int result;
	u_long encoding;
	int modeformat;

	modeformat = attrp->ca_mode & S_IFMT;

	vcb = HFSTOVCB(hfsmp);
	fcb = GetFileControlBlock(vcb->catalogRefNum);
	nextCNID = vcb->vcbNxtCNID;
	std_hfs = (vcb->vcbSigWord == kHFSSigWord);

	if (std_hfs && nextCNID == 0xFFFFFFFF)
		return (ENOSPC);

	/* Get space for iterator, key and data */	
	MALLOC(bto, struct btobj *, sizeof(struct btobj), M_TEMP, M_WAITOK);
	bzero(bto, sizeof(struct btobj));

	result = buildkey(hfsmp, descp, &bto->key, 0);
	if (result)
		goto exit;

	if (!std_hfs) {
		encoding = hfs_pickencoding(bto->key.nodeName.unicode,
			bto->key.nodeName.length);
		hfs_setencodingbits(hfsmp, encoding);
	}

	// XXXdbg - preflight all btree operations to make sure there's enough space
	result = BTCheckFreeSpace(fcb);
	if (result)
		goto exit;

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
			if (result == btExists && !std_hfs) {
				/*
				 * Allow CNIDs on HFS Plus volumes to wrap around
				 */
				++nextCNID;
				if (nextCNID < kHFSFirstUserCatalogNodeID) {
					vcb->vcbAtrb |= kHFSCatalogNodeIDsReusedMask;
					vcb->vcbFlags |= 0xFF00;
					nextCNID = kHFSFirstUserCatalogNodeID;
				}
				continue;
			}
			break;
		}
		if (result) goto exit;
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

	/* Update parent stats */
	TrashCatalogIterator(vcb, descp->cd_parentcnid);
	
	/* Update volume stats */
	if (++nextCNID < kHFSFirstUserCatalogNodeID) {
		vcb->vcbAtrb |= kHFSCatalogNodeIDsReusedMask;
		nextCNID = kHFSFirstUserCatalogNodeID;
	}
	vcb->vcbNxtCNID = nextCNID;
	vcb->vcbFlags |= 0xFF00;

exit:
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

	// XXXdbg - preflight all btree operations to make sure there's enough space
	result = BTCheckFreeSpace(fcb);
	if (result)
		goto exit;

	to_key = (HFSPlusCatalogKey *)&to_iterator->key;
	MALLOC(recp, CatalogRecord *, sizeof(CatalogRecord), M_TEMP, M_WAITOK);
	BDINIT(btdata, recp);

	/*
	 * When moving a directory, make sure its a valid move.
	 */
	if (directory && (from_cdp->cd_parentcnid != to_cdp->cd_parentcnid)) {
		struct BTreeIterator iterator = {0};
		cnid_t cnid = from_cdp->cd_cnid;
		cnid_t pathcnid = todir_cdp->cd_parentcnid;

		/* First check the obvious ones */
		if (cnid == fsRtDirID  ||
		    cnid == to_cdp->cd_parentcnid  ||
		    cnid == pathcnid) {
			result = EINVAL;
			goto exit;
		}

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
	if (result)
		goto exit;

	/* Update the text encoding (on disk and in descriptor */
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

	/* Trash the iterator caches */
	TrashCatalogIterator(vcb, from_cdp->cd_parentcnid);
	if (from_cdp->cd_parentcnid != to_cdp->cd_parentcnid)
		TrashCatalogIterator(vcb, to_cdp->cd_parentcnid);

	/* Step 2: Insert cnode at new location */
	result = BTInsertRecord(fcb, to_iterator, &btdata, datasize);
	if (result == btExists) {
		int fromtype = recp->recordType;

		if (from_cdp->cd_parentcnid != to_cdp->cd_parentcnid)
			goto exit; /* EEXIST */

		/* Find cnode data at new location */
		result = BTSearchRecord(fcb, to_iterator, &btdata, &datasize, NULL);
		
		if ((fromtype != recp->recordType) ||
		    (from_cdp->cd_cnid != getcnid(recp)))
			goto exit; /* EEXIST */
		
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
	    descp->cd_parentcnid == kRootParID)
		return (EINVAL);

	/* XXX Preflight Missing */
	
	/* Get space for iterator */	
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

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

	// XXXdbg - preflight all btree operations to make sure there's enough space
	result = BTCheckFreeSpace(fcb);
	if (result)
		goto exit;

	/* Delete record */
	result = BTDeleteRecord(fcb, iterator);
	if (result)
		goto exit;

	/* Delete thread record, ignore errors */
	buildthreadkey(cnid, std_hfs, (CatalogKey *)&iterator->key);
	(void) BTDeleteRecord(fcb, iterator);

	TrashCatalogIterator(vcb, descp->cd_parentcnid);

exit:
	(void) BTFlushPath(fcb);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}


/*
 * cnode_update - update the catalog node described by descp
 * using the data from attrp and forkp.
 */
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
	bzero(iterator, sizeof(*iterator));

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
catrec_update(const CatalogKey *ckp, CatalogRecord *crp, u_int16_t reclen,
              struct update_state *state)
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
		dir->valence          = attrp->ca_entries;
		dir->createDate       = to_hfs_time(attrp->ca_itime);
		dir->contentModDate   = to_hfs_time(attrp->ca_mtime);
		dir->backupDate       = to_hfs_time(attrp->ca_btime);
		dir->accessDate       = to_hfs_time(attrp->ca_atime);
		dir->attributeModDate = to_hfs_time(attrp->ca_ctime);
		dir->textEncoding     = descp->cd_encoding;
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
			    (HFSTOVFS(hfsmp)->mnt_flag &
			     MNT_UNKNOWNPERMISSIONS) == 0) {
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
		file->createDate       = to_hfs_time(attrp->ca_itime);
		file->contentModDate   = to_hfs_time(attrp->ca_mtime);
		file->backupDate       = to_hfs_time(attrp->ca_btime);
		file->accessDate       = to_hfs_time(attrp->ca_atime);
		file->attributeModDate = to_hfs_time(attrp->ca_ctime);
		file->textEncoding     = descp->cd_encoding;
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
			    (HFSTOVFS(hfsmp)->mnt_flag &
			     MNT_UNKNOWNPERMISSIONS) == 0) {
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
		}
		if (state->s_datafork) {
			forkp = state->s_datafork;
			file->dataFork.logicalSize = forkp->cf_size;
			file->dataFork.totalBlocks = forkp->cf_blocks;
			bcopy(&forkp->cf_extents[0], &file->dataFork.extents,
				sizeof(HFSPlusExtentRecord));
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
 * catrec_readattr - 
 * This is called from within BTIterateRecords.
 */
struct readattr_state {
	struct hfsmount *hfsmp;
	struct cat_entrylist *list;
	cnid_t	dir_cnid;
	int stdhfs;
	int error;
};

static int
catrec_readattr(const CatalogKey *key, const CatalogRecord *rec,
		u_long node, struct readattr_state *state)
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
	if (parentcnid == kRootDirID) {
		if ((rec->recordType == kHFSPlusFolderRecord) &&
		    (rec->hfsPlusFolder.folderID == hfsmp->hfs_private_metadata_dir)) {
			return (1);	/* continue */
		}
		if (hfsmp->jnl &&
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
		builddesc(pluskey, getcnid(rec), node, encoding, isadir(rec), &cep->ce_desc);
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
		builddesc((HFSPlusCatalogKey *)key, getcnid(rec), node, getencoding(rec),
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
 * Note: index is zero relative
 */
int
cat_getentriesattr(struct hfsmount *hfsmp, struct cat_desc *prevdesc, int index,
		struct cat_entrylist *ce_list)
{
	FCB* fcb;
	CatalogKey * key;
	BTreeIterator * iterator;
	struct readattr_state state;
	cnid_t parentcnid;
	int i;
	int std_hfs;
	int result = 0;

	ce_list->realentries = 0;

	fcb = GetFileControlBlock(HFSTOVCB(hfsmp)->catalogRefNum);
	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);
	parentcnid = prevdesc->cd_parentcnid;

	state.hfsmp = hfsmp;
	state.list = ce_list;
	state.dir_cnid = parentcnid;
	state.stdhfs = std_hfs;
	state.error = 0;

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	key = (CatalogKey *)&iterator->key;
	iterator->hint.nodeNum = prevdesc->cd_hint;

	/*
	 * If the last entry wasn't cached then establish the iterator
	 */
	if ((index == 0) ||
	    (prevdesc->cd_namelen == 0) ||
	    (buildkey(hfsmp, prevdesc, (HFSPlusCatalogKey *)key, 0) != 0)) {
		int i;
		/*
		 * Position the iterator at the directory thread.
		 * (ie just before the first entry)
		 */
		buildthreadkey(parentcnid, std_hfs, key);
		result = BTSearchRecord(fcb, iterator, NULL, NULL, iterator);
		if (result)
			goto exit;  /* bad news */
		/*
		 * Iterate until we reach the entry just
		 * before the one we want to start with.
		 */
		for (i = 0; i < index; ++i) {
			result = BTIterateRecord(fcb, kBTreeNextRecord, iterator, NULL, NULL);
			if (result)
				goto exit;  /* bad news */
		}
	}

	/* Fill list with entries. */
	result = BTIterateRecords(fcb, kBTreeNextRecord, iterator,
			(IterateCallBackProcPtr)catrec_readattr, &state);

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
	for (i = 0; i < ce_list->realentries; ++i) {
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
		&&  ((cep->ce_attr.ca_itime == HFSTOVCB(hfsmp)->vcbCrDate) ||
		     (cep->ce_attr.ca_itime == hfsmp->hfs_metadata_createdate))) {

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


struct read_state {
	u_int32_t	cbs_parentID;
	u_int32_t	cbs_hiddenDirID;
	u_int32_t	cbs_hiddenJournalID;
	u_int32_t	cbs_hiddenInfoBlkID;
	off_t		cbs_lastoffset;
	struct uio *	cbs_uio;
	ExtendedVCB *	cbs_vcb;
	int16_t		cbs_hfsPlus;
	int16_t		cbs_result;
};


static int
catrec_read(const CatalogKey *ckp, const CatalogRecord *crp,
		    u_int16_t recordLen, struct read_state *state)
{
	CatalogName *cnp;
	size_t utf8chars;
	u_int32_t curID;
	OSErr result;
	struct dirent catent;
	
	if (state->cbs_hfsPlus)
		curID = ckp->hfsPlus.parentID;
	else
		curID = ckp->hfs.parentID;

	/* We're done when parent directory changes */
	if (state->cbs_parentID != curID) {
lastitem:
/*
 * The NSDirectoryList class chokes on empty records (it doesnt check d_reclen!)
 * so remove padding for now...
 */
#if 0
		/*
		 * Pad the end of list with an empty record.
		 * This eliminates an extra call by readdir(3c).
		 */
		catent.d_fileno = 0;
		catent.d_reclen = 0;
		catent.d_type = 0;
		catent.d_namlen = 0;
		*(int32_t*)&catent.d_name[0] = 0;

		state->cbs_lastoffset = state->cbs_uio->uio_offset;

		state->cbs_result = uiomove((caddr_t) &catent, 12, state->cbs_uio);
		if (state->cbs_result == 0)
			state->cbs_result = ENOENT;
#else
		state->cbs_lastoffset = state->cbs_uio->uio_offset;
		state->cbs_result = ENOENT;
#endif
		return (0);	/* stop */
	}

	if (state->cbs_hfsPlus) {
		switch(crp->recordType) {
		case kHFSPlusFolderRecord:
			catent.d_type = DT_DIR;
			catent.d_fileno = crp->hfsPlusFolder.folderID;
			break;
		case kHFSPlusFileRecord:
			catent.d_type = DT_REG;
			catent.d_fileno = crp->hfsPlusFile.fileID;
			break;
		default:
			return (0);	/* stop */
		};

		cnp = (CatalogName*) &ckp->hfsPlus.nodeName;
		result = utf8_encodestr(cnp->ustr.unicode, cnp->ustr.length * sizeof(UniChar),
				catent.d_name, &utf8chars, kdirentMaxNameBytes + 1, ':', 0);
		if (result == ENAMETOOLONG) {
			result = ConvertUnicodeToUTF8Mangled(cnp->ustr.length * sizeof(UniChar),
			    	cnp->ustr.unicode, kdirentMaxNameBytes + 1, (ByteCount*)&utf8chars, catent.d_name, catent.d_fileno);		
		}
	} else { /* hfs */
		switch(crp->recordType) {
		case kHFSFolderRecord:
			catent.d_type = DT_DIR;
			catent.d_fileno = crp->hfsFolder.folderID;
			break;
		case kHFSFileRecord:
			catent.d_type = DT_REG;
			catent.d_fileno = crp->hfsFile.fileID;
			break;
		default:
			return (0);	/* stop */
		};

		cnp = (CatalogName*) ckp->hfs.nodeName;
		result = hfs_to_utf8(state->cbs_vcb, cnp->pstr, kdirentMaxNameBytes + 1,
				    (ByteCount *)&utf8chars, catent.d_name);
		/*
		 * When an HFS name cannot be encoded with the current
		 * volume encoding we use MacRoman as a fallback.
		 */
		if (result)
			result = mac_roman_to_utf8(cnp->pstr, kdirentMaxNameBytes + 1,
				    (ByteCount *)&utf8chars, catent.d_name);
	}

	catent.d_namlen = utf8chars;
	catent.d_reclen = DIRENTRY_SIZE(utf8chars);
	
	/* hide our private meta data directory */
	if (curID == kRootDirID				&&
	    catent.d_fileno == state->cbs_hiddenDirID	&&
	    catent.d_type == DT_DIR)
		goto lastitem;

	/* Hide the journal files */
	if ((curID == kRootDirID) &&
	    (catent.d_type == DT_REG) &&
	    ((catent.d_fileno == state->cbs_hiddenJournalID) ||
	     (catent.d_fileno == state->cbs_hiddenInfoBlkID))) {

		return (1);	/* skip and continue */
	}

	state->cbs_lastoffset = state->cbs_uio->uio_offset;

	/* if this entry won't fit then we're done */
	if (catent.d_reclen > state->cbs_uio->uio_resid)
		return (0);	/* stop */

	state->cbs_result = uiomove((caddr_t) &catent, catent.d_reclen, state->cbs_uio);

	/* continue iteration if there's room */
	return (state->cbs_result == 0  &&
		state->cbs_uio->uio_resid >= AVERAGE_HFSDIRENTRY_SIZE);
}

/*
 *
 */
int
cat_getdirentries(struct hfsmount *hfsmp, struct cat_desc *descp,
		struct uio *uio, int *eofflag)
{
	ExtendedVCB *vcb = HFSTOVCB(hfsmp);
	BTreeIterator * iterator;
	CatalogIterator *cip;
	u_int32_t diroffset;
	u_int16_t op;
	struct read_state state;
	u_int32_t dirID = descp->cd_cnid;
	int result;

	diroffset = uio->uio_offset;
	*eofflag = 0;

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	/* get an iterator and position it */
	cip = GetCatalogIterator(vcb, dirID, diroffset);

	result = PositionIterator(cip, diroffset, iterator, &op);
	if (result == cmNotFound) {
		*eofflag = 1;
		result = 0;
		AgeCatalogIterator(cip);
		goto cleanup;
	} else if ((result = MacToVFSError(result)))
		goto cleanup;

	state.cbs_hiddenDirID = hfsmp->hfs_private_metadata_dir;
	if (hfsmp->jnl) {
		state.cbs_hiddenJournalID = hfsmp->hfs_jnlfileid;
		state.cbs_hiddenInfoBlkID = hfsmp->hfs_jnlinfoblkid;
	}

	state.cbs_lastoffset = cip->currentOffset;
	state.cbs_vcb = vcb;
	state.cbs_uio = uio;
	state.cbs_result = 0;
	state.cbs_parentID = dirID;

	if (vcb->vcbSigWord == kHFSPlusSigWord)
		state.cbs_hfsPlus = 1;
	else
		state.cbs_hfsPlus = 0;

	/* process as many entries as possible... */
	result = BTIterateRecords(GetFileControlBlock(vcb->catalogRefNum), op,
		 iterator, (IterateCallBackProcPtr)catrec_read, &state);

	if (state.cbs_result)
		result = state.cbs_result;
	else
		result = MacToVFSError(result);

	if (result == ENOENT) {
		*eofflag = 1;
		result = 0;
	}

	if (result == 0) {
		cip->currentOffset = state.cbs_lastoffset;
		cip->nextOffset = uio->uio_offset;
		UpdateCatalogIterator(iterator, cip);
	}

cleanup:
	if (result) {
		cip->volume = 0;
		cip->folderID = 0;
		AgeCatalogIterator(cip);
	}

	(void) ReleaseCatalogIterator(cip);
	FREE(iterator, M_TEMP);
	
	return (result);
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
	idesc.cd_parentcnid = hfsmp->hfs_private_metadata_dir;
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
			bzero(crp, sizeof(HFSPlusCatalogFolder));
			crp->recordType = kHFSPlusFolderRecord;
			crp->hfsPlusFolder.folderID = cnid;	
			crp->hfsPlusFolder.createDate = createtime;
			crp->hfsPlusFolder.contentModDate = createtime;
			crp->hfsPlusFolder.accessDate = createtime;
			crp->hfsPlusFolder.attributeModDate = createtime;
			crp->hfsPlusFolder.textEncoding = encoding;
			bcopy(attrp->ca_finderinfo, &crp->hfsPlusFolder.userInfo, 32);
			bsdp = &crp->hfsPlusFolder.bsdInfo;
			*recordSize = sizeof(HFSPlusCatalogFolder);
		} else {
			bzero(crp, sizeof(HFSPlusCatalogFile));
			crp->recordType = kHFSPlusFileRecord;
			crp->hfsPlusFile.fileID = cnid;
			crp->hfsPlusFile.createDate = createtime;
			crp->hfsPlusFile.contentModDate = createtime;
			crp->hfsPlusFile.accessDate = createtime;
			crp->hfsPlusFile.attributeModDate = createtime;
			crp->hfsPlusFile.flags |= kHFSThreadExistsMask;
			crp->hfsPlusFile.textEncoding = encoding;
			bsdp = &crp->hfsPlusFile.bsdInfo;
			switch(type) {
			case S_IFBLK:
			case S_IFCHR:
				/* BLK/CHR need to save the device info */
				bsdp->special.rawDevice = attrp->ca_rdev;
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
	long bufsize;
	size_t utf8len;

	/* guess a size... */
	bufsize = (3 * key->nodeName.length) + 1;
	MALLOC(nameptr, char *, bufsize, M_TEMP, M_WAITOK);

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
	descp->cd_nameptr = nameptr;
	descp->cd_namelen = utf8len;
	descp->cd_cnid = cnid;
	descp->cd_hint = hint;
	descp->cd_flags = CD_DECOMPOSED | CD_HASBUF;
	if (isdir)
		descp->cd_flags |= CD_ISDIR;
	descp->cd_encoding = encoding;
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

	attrp->ca_nlink = 1;
	attrp->ca_atime = to_bsd_time(crp->accessDate);
	attrp->ca_mtime = to_bsd_time(crp->contentModDate);
	attrp->ca_mtime_nsec = 0;
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

		if (HFSTOVFS(hfsmp)->mnt_flag & MNT_UNKNOWNPERMISSIONS) {
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
		xp[0].startBlock = (u_int32_t)filep->rsrcExtents[0].startBlock;
		xp[0].blockCount = (u_int32_t)filep->rsrcExtents[0].blockCount;
		xp[1].startBlock = (u_int32_t)filep->rsrcExtents[1].startBlock;
		xp[1].blockCount = (u_int32_t)filep->rsrcExtents[1].blockCount;
		xp[2].startBlock = (u_int32_t)filep->rsrcExtents[2].startBlock;
		xp[2].blockCount = (u_int32_t)filep->rsrcExtents[2].blockCount;
	} else {
		forkp->cf_size = filep->dataLogicalSize;
		forkp->cf_blocks = filep->dataPhysicalSize / blocksize;
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
	crp->reserved2 = 0;
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
		panic("hfs: getcnid: unknown recordType (crp @ 0x%x)\n", crp);
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


