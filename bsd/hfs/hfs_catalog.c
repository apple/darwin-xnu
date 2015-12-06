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
#include "hfscommon/headers/BTreesPrivate.h"
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
	const struct cat_fork *	s_datafork;
	const struct cat_fork *	s_rsrcfork;
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


#define HFS_LOOKUP_SYSFILE	0x1	/* If set, allow lookup of system files */
#define HFS_LOOKUP_HARDLINK	0x2	/* If set, allow lookup of hard link records and not resolve the hard links */
#define HFS_LOOKUP_CASESENSITIVE	0x4	/* If set, verify results of a file/directory record match input case */
static int cat_lookupbykey(struct hfsmount *hfsmp, CatalogKey *keyp, int flags, u_int32_t hint, int wantrsrc,
                  struct cat_desc *descp, struct cat_attr *attrp, struct cat_fork *forkp, cnid_t *desc_cnid);

int cat_lookupmangled(struct hfsmount *hfsmp, struct cat_desc *descp, int wantrsrc,
                  struct cat_desc *outdescp, struct cat_attr *attrp, struct cat_fork *forkp);

/* Internal catalog support routines */

static int cat_findposition(const CatalogKey *ckp, const CatalogRecord *crp,
                            struct position_state *state);

static int resolvelinkid(struct hfsmount *hfsmp, u_int32_t linkref, ino_t *ino);

static int getkey(struct hfsmount *hfsmp, cnid_t cnid, CatalogKey * key);

static int buildkey(struct hfsmount *hfsmp, struct cat_desc *descp,
			HFSPlusCatalogKey *key, int retry);

static void buildthreadkey(HFSCatalogNodeID parentID, int std_hfs, CatalogKey *key);

static void buildrecord(struct cat_attr *attrp, cnid_t cnid, int std_hfs, u_int32_t encoding, CatalogRecord *crp, u_int32_t *recordSize);

static int catrec_update(const CatalogKey *ckp, CatalogRecord *crp, struct update_state *state);

static int builddesc(const HFSPlusCatalogKey *key, cnid_t cnid, u_int32_t hint, u_int32_t encoding,
			int isdir, struct cat_desc *descp);

static void getbsdattr(struct hfsmount *hfsmp, const struct HFSPlusCatalogFile *crp, struct cat_attr * attrp);

#if CONFIG_HFS_STD
static void promotekey(struct hfsmount *hfsmp, const HFSCatalogKey *hfskey, HFSPlusCatalogKey *keyp, u_int32_t *encoding);
static void promotefork(struct hfsmount *hfsmp, const struct HFSCatalogFile *file, int resource, struct cat_fork * forkp);
static void promoteattr(struct hfsmount *hfsmp, const CatalogRecord *dataPtr, struct HFSPlusCatalogFile *crp);
#endif

static cnid_t getcnid(const CatalogRecord *crp);
static u_int32_t getencoding(const CatalogRecord *crp);
static cnid_t getparentcnid(const CatalogRecord *recp);

static int isadir(const CatalogRecord *crp);

static int buildthread(void *keyp, void *recp, int std_hfs, int directory);

static int cat_makealias(struct hfsmount *hfsmp, u_int32_t inode_num, struct HFSPlusCatalogFile *crp);

static int cat_update_internal(struct hfsmount *hfsmp, int update_hardlink, struct cat_desc *descp, struct cat_attr *attrp,
	const struct cat_fork *dataforkp, const struct cat_fork *rsrcforkp);



/* HFS ID Hashtable Functions */
#define IDHASH(hfsmp, inum) (&hfsmp->hfs_idhashtbl[(inum) & hfsmp->hfs_idhash])

/* Initialize the HFS ID hash table */
void
hfs_idhash_init (struct hfsmount *hfsmp) {
	/* secured by catalog lock so no lock init needed */
	hfsmp->hfs_idhashtbl = hashinit(HFS_IDHASH_DEFAULT, M_HFSMNT, &hfsmp->hfs_idhash);	
}

/* Free the HFS ID hash table */
void
hfs_idhash_destroy (struct hfsmount *hfsmp) {
	/* during failed mounts & unmounts */
	FREE(hfsmp->hfs_idhashtbl, M_HFSMNT);
}

/*
from hfs_catalog.h:
typedef struct cat_preflightid {
	cnid_t fileid;
	LIST_ENTRY(cat_preflightid) id_hash;
} cat_preflightid_t;

from hfs.h:
  u_long hfs_idhash; / size of cnid/fileid hash table -1 /
  LIST_HEAD(idhashhead, cat_preflightid) *hfs_idhashtbl; / base of ID hash /
*/

/* 
 * Check the run-time ID hashtable.  
 * 
 * The catalog lock must be held (like other functions in this file).
 *
 * Returns: 
 * 		1 if the ID is in the hash table.
 *		0 if the ID is not in the hash table
 */ 
int cat_check_idhash (struct hfsmount *hfsmp, cnid_t test_fileid) {

	cat_preflightid_t *preflight;
	int found = 0;

	for (preflight = IDHASH(hfsmp, test_fileid)->lh_first; preflight ; preflight = preflight->id_hash.le_next) {
		if (preflight->fileid == test_fileid) {
			found = 1;
			break;	
		}
	}

	return found;   	
}

/* Insert the supplied preflight into the ID hash table */ 
int cat_insert_idhash (struct hfsmount *hfsmp, cat_preflightid_t *preflight) {

	if (preflight) {
		LIST_INSERT_HEAD(IDHASH(hfsmp, (preflight->fileid)), preflight, id_hash);
		return 0;
	}
	return -1;
}


/* Remove the data structure with the specified ID from the hashtable */
int cat_remove_idhash (cat_preflightid_t *preflight) {
	
	if ((preflight) && ((preflight->id_hash.le_next || preflight->id_hash.le_prev))) {
		LIST_REMOVE (preflight, id_hash);
		preflight->id_hash.le_next = NULL;
		preflight->id_hash.le_prev = NULL;

		return 0;
	}

	return -1;
}

/*
 * Acquire a new CNID for use.  
 * 
 * This is slightly more complicated than just pulling the value from the
 * hfsmount data structure.  We need to validate that the ID is not in-use
 * even if we've not wrapped around and that there are not any lingering
 * or orphaned fileIDs for this ID. 
 *
 * Also validate that there are not any pending insertions into the
 * catalog by checking the ID hash table. 
 */
int 
cat_acquire_cnid (struct hfsmount *hfsmp, cnid_t *new_cnid) 
{
	uint32_t nextCNID;
	struct BTreeIterator *iterator;
	FSBufferDescriptor btdata;
	uint16_t datasize;
	CatalogRecord *recp;
	int result = 0;
	int std_hfs;
	int wrapped = 0;

	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);
	/*
	 * Get the next CNID. We can change it since we hold the catalog lock.
	 */
nextid:
	nextCNID = hfsmp->vcbNxtCNID;
	if (nextCNID == 0xFFFFFFFF) {
		if (std_hfs) {
			return (ENOSPC);
		} else {
			wrapped++;
			if (wrapped > 1) {
				/* don't allow more than one wrap-around */
				return ENOSPC;
			}
			hfs_lock_mount (hfsmp);
			hfsmp->vcbNxtCNID = kHFSFirstUserCatalogNodeID;
			hfsmp->vcbAtrb |= kHFSCatalogNodeIDsReusedMask;
			hfs_unlock_mount (hfsmp);
		}
	} else {
		hfsmp->vcbNxtCNID++;
	}
	hfs_note_header_minor_change(hfsmp);

	/* First check that there are not any entries pending in the hash table with this ID */
	if (cat_check_idhash (hfsmp, nextCNID)) {
		/* Someone wants to insert this into the catalog but hasn't done so yet. Skip it */
		goto nextid;
	}

	/* Check to see if a thread record exists for the target ID we just got */
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	buildthreadkey(nextCNID, std_hfs, (CatalogKey *)&iterator->key);

	MALLOC(recp, CatalogRecord *, sizeof(CatalogRecord), M_TEMP, M_WAITOK);
	BDINIT(btdata, recp);

	result = BTSearchRecord(hfsmp->hfs_catalog_cp->c_datafork, iterator, &btdata, &datasize, iterator);
	FREE (recp, M_TEMP);
	FREE (iterator, M_TEMP);

	if (result == btNotFound) {
		/* Good.  File ID was not in use. Move on to checking EA B-Tree */
		result = file_attribute_exist (hfsmp, nextCNID);
		if (result == EEXIST) {
			/* This CNID has orphaned EAs.  Skip it and move on to the next one */
			result = 0;
			goto nextid;
		}
		if (result) {
			/* For any other error, return the result */
			return result;
		}

		/*
		 * Now validate that there are no lingering cnodes with this ID.  If a cnode
		 * has been removed on-disk (marked C_NOEXISTS), but has not yet been reclaimed,
		 * then it will still have an entry in the cnode hash table.  This means that
		 * a subsequent lookup will find THAT entry and believe this one has been deleted
		 * prematurely.  If there is a lingering cnode, then just skip this entry and move on.
		 * 
		 * Note that we pass (existence_only == 1) argument to hfs_chash_snoop.
		 */
		if (!std_hfs && (hfsmp->vcbAtrb & kHFSCatalogNodeIDsReusedMask)) {
			if (hfs_chash_snoop (hfsmp, nextCNID, 1, NULL, NULL) == 0) {
				goto nextid;
			}
		}

		/* 
		 * If we get here, then we didn't see any thread records, orphaned EAs, 
	     * or stale cnodes. This ID is safe to vend out.
		 */
		*new_cnid = nextCNID;
	}
	else if (result == noErr) {
		/* move on to the next ID */
		goto nextid;
	}	
	else {
		/* For any other situation, just bail out */
		return EIO; 
	}

	return 0;	

}

int
cat_preflight(struct hfsmount *hfsmp, catops_t ops, cat_cookie_t *cookie, __unused proc_t p)
{
	int lockflags = 0;
	int result;

	if (hfsmp->hfs_catalog_cp->c_lockowner != current_thread())
		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);
	 
	result = BTReserveSpace(hfsmp->hfs_catalog_cp->c_datafork, ops, (void*)cookie);

	if (lockflags)
		hfs_systemfile_unlock(hfsmp, lockflags);

	return MacToVFSError(result);
}

void
cat_postflight(struct hfsmount *hfsmp, cat_cookie_t *cookie, __unused proc_t p)
{
	int lockflags = 0;

	if (hfsmp->hfs_catalog_cp->c_lockowner != current_thread())
		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);

	(void) BTReleaseReserve(hfsmp->hfs_catalog_cp->c_datafork, (void*)cookie);

	if (lockflags)
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

	if (std_hfs == 0) {
		getbsdattr(hfsmp, (struct HFSPlusCatalogFile *)recp, attrp);
	}
#if CONFIG_HFS_STD
	else {
		struct HFSPlusCatalogFile cnoderec;

		promoteattr(hfsmp, recp, &cnoderec);
		getbsdattr(hfsmp, &cnoderec, attrp);
	} 
#endif

	if (isadir(recp)) {
		bzero(datafp, sizeof(*datafp));
	}
#if CONFIG_HFS_STD
	else if (std_hfs) {
		promotefork(hfsmp, (HFSCatalogFile *)&recp->hfsFile, 0, datafp);
		promotefork(hfsmp, (HFSCatalogFile *)&recp->hfsFile, 1, rsrcfp);
	} 
#endif
	else {
		/* Convert the data fork. */
		datafp->cf_size = recp->hfsPlusFile.dataFork.logicalSize;
		datafp->cf_new_size = 0;
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
		rsrcfp->cf_new_size = 0;
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

/*
 * Convert a raw catalog key and record into an in-core catalog descriptor.
 *
 * Note: The caller is responsible for releasing the catalog descriptor.
 */
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
	u_int32_t encoding;
	cnid_t cnid = 0;
	int err = 0;

	if (std_hfs == 0) {
		pluskey = (HFSPlusCatalogKey *)key;
		encoding = getencoding(recp);
	}
#if CONFIG_HFS_STD
	else {
		MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
		promotekey(hfsmp, (HFSCatalogKey *)key, pluskey, &encoding);
	}
#endif
  
	/* Get the CNID before calling builddesc.  Need to error check it. */
	cnid = getcnid(recp);
	if (cnid == 0) {
		/* If ths CNID == 0, it's invalid. Mark as corrupt */
		hfs_mark_inconsistent (hfsmp, HFS_INCONSISTENCY_DETECTED);
		err = EINVAL;
	}
	else {
		builddesc(pluskey, cnid, 0, encoding, isadir(recp), descp);
	}

#if CONFIG_HFS_STD
	if (std_hfs) {
		FREE(pluskey, M_TEMP);
	}
#endif

	return err;
}


/*
 * cat_releasedesc
 */
__private_extern__
void
cat_releasedesc(struct cat_desc *descp)
{
	const u_int8_t * name;

	if (descp == NULL)
		return;

	if ((descp->cd_flags & CD_HASBUF) &&
	    (descp->cd_nameptr != NULL)) {
	    	name = descp->cd_nameptr;
		descp->cd_nameptr = NULL;
		descp->cd_namelen = 0;
		vfs_removename((const char *)name);
	}
	descp->cd_nameptr = NULL;
	descp->cd_namelen = 0;
	descp->cd_flags &= ~CD_HASBUF;
}

/*
 * These Catalog functions allow access to the HFS Catalog (database).
 * The catalog b-tree lock must be acquired before calling any of these routines.
 */

/*
 * cat_lookup - lookup a catalog node using a cnode descriptor
 *
 * Note: The caller is responsible for releasing the output
 * catalog descriptor (when supplied outdescp is non-null).
 */
int
cat_lookup(struct hfsmount *hfsmp, struct cat_desc *descp, int wantrsrc, int force_casesensitive_lookup,
             struct cat_desc *outdescp, struct cat_attr *attrp,
             struct cat_fork *forkp, cnid_t *desc_cnid)
{
	CatalogKey * keyp;
	int std_hfs;
	int result;
	int flags;

	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);
	flags = force_casesensitive_lookup ? HFS_LOOKUP_CASESENSITIVE : 0;

	MALLOC(keyp, CatalogKey *, sizeof(CatalogKey), M_TEMP, M_WAITOK);

	result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)keyp, 1);
	if (result)
		goto exit;

	result = cat_lookupbykey(hfsmp, keyp, flags, descp->cd_hint, wantrsrc, outdescp, attrp, forkp, desc_cnid);
	
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

int
cat_insertfilethread(struct hfsmount *hfsmp, struct cat_desc *descp)
{
	struct BTreeIterator *iterator;
	struct FSBufferDescriptor file_data;
	struct HFSCatalogFile file_rec;
	u_int16_t datasize;
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
 *
 * Note: The caller is responsible for releasing the output
 * catalog descriptor (when supplied outdescp is non-null).

 */
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

#if CONFIG_HFS_STD
		case kHFSFolderThreadRecord:
			isdir = 1;
			/* fall through */
		case kHFSFileThreadRecord:
			keyp = (CatalogKey *)((char *)&recp->hfsThread.reserved + 6);
			keyp->hfs.keyLength = kHFSCatalogKeyMinimumLength + keyp->hfs.nodeName[0];
			break;
#endif

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

	if (std_hfs == 0) {
		builddesc((HFSPlusCatalogKey *)keyp, cnid, 0, 0, isdir, outdescp);
	}
#if CONFIG_HFS_STD
	else {
		HFSPlusCatalogKey * pluskey = NULL;
		u_int32_t encoding;

		MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
		promotekey(hfsmp, &keyp->hfs, pluskey, &encoding);
		builddesc(pluskey, cnid, 0, encoding, isdir, outdescp);
		FREE(pluskey, M_TEMP);
	}
#endif	

exit:
	FREE(recp, M_TEMP);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}

/*
 * cat_idlookup - lookup a catalog node using a cnode id
 *
 * Note: The caller is responsible for releasing the output
 * catalog descriptor (when supplied outdescp is non-null).
 */
int
cat_idlookup(struct hfsmount *hfsmp, cnid_t cnid, int allow_system_files, int wantrsrc,
    struct cat_desc *outdescp, struct cat_attr *attrp, struct cat_fork *forkp)
{
	struct BTreeIterator * iterator;
	FSBufferDescriptor btdata;
	u_int16_t	datasize;
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

#if CONFIG_HFS_STD
		case kHFSFileThreadRecord:
		case kHFSFolderThreadRecord:
			keyp = (CatalogKey *)((char *)&recp->hfsThread.reserved + 6);

			/* check for NULL name */
			if (keyp->hfs.nodeName[0] == 0) {
				result = ENOENT;
				goto exit;
			}

			keyp->hfs.keyLength = kHFSCatalogKeyMinimumLength + keyp->hfs.nodeName[0];
			break;
#endif

		case kHFSPlusFileThreadRecord:
		case kHFSPlusFolderThreadRecord:
			keyp = (CatalogKey *)&recp->hfsPlusThread.reserved;

			/* check for NULL name */
			if (keyp->hfsPlus.nodeName.length == 0) {
				result = ENOENT;
				goto exit;
			}

			keyp->hfsPlus.keyLength = kHFSPlusCatalogKeyMinimumLength +
				(keyp->hfsPlus.nodeName.length * 2);
			break;

		default:
			result = ENOENT;
			goto exit;
	}

	result = cat_lookupbykey(hfsmp, keyp, 
			((allow_system_files != 0) ? HFS_LOOKUP_SYSFILE : 0), 
			0, wantrsrc, outdescp, attrp, forkp, NULL);
	/* No corresponding file/folder record found for a thread record,
	 * mark the volume inconsistent.
	 */
	if (result == 0 && outdescp) {
		cnid_t dcnid = outdescp->cd_cnid;
		/*
		 * Just for sanity's case, let's make sure that
		 * the key in the thread matches the key in the record.
		 */
		if (cnid != dcnid) {
			printf("hfs: cat_idlookup: Requested cnid (%d / %08x) != dcnid (%d / %08x)\n", cnid, cnid, dcnid, dcnid);
			result = ENOENT;
		}
	}
exit:
	FREE(recp, M_TEMP);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}


/*
 * cat_lookupmangled - lookup a catalog node using a mangled name
 */
int
cat_lookupmangled(struct hfsmount *hfsmp, struct cat_desc *descp, int wantrsrc,
                  struct cat_desc *outdescp, struct cat_attr *attrp, struct cat_fork *forkp)
{
	cnid_t fileID;
	u_int32_t prefixlen;
	int result;
	u_int8_t utf8[NAME_MAX + 1];
	u_int32_t utf8len;
	u_int16_t unicode[kHFSPlusMaxFileNameChars + 1];
	size_t unicodelen;
	
	if (wantrsrc)
		return (ENOENT);

	fileID = GetEmbeddedFileID(descp->cd_nameptr, descp->cd_namelen, &prefixlen);
	if (fileID < (cnid_t)kHFSFirstUserCatalogNodeID)
		return (ENOENT);

	if (fileID == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid ||
		fileID == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid ||
		fileID == hfsmp->hfs_jnlfileid ||
		fileID == hfsmp->hfs_jnlinfoblkid) {
		return (ENOENT);
	}

	result = cat_idlookup(hfsmp, fileID, 0, 0, outdescp, attrp, forkp);
	if (result)
		return (ENOENT);
	/* It must be in the correct directory */
	if (descp->cd_parentcnid != outdescp->cd_parentcnid)
		goto falsematch;

	/*
	 * Compare the mangled version of file name looked up from the 
	 * disk with the mangled name provided by the user.  Note that 
	 * this comparison is case-sensitive, which should be fine
	 * since we're trying to prevent user space from constructing
	 * a mangled name that differs from the one they'd get from the
	 * file system.
	 */
	result = utf8_decodestr(outdescp->cd_nameptr, outdescp->cd_namelen,
			unicode, &unicodelen, sizeof(unicode), ':', 0);
	if (result) {
		goto falsematch;
	}
	result = ConvertUnicodeToUTF8Mangled(unicodelen, unicode, 
			sizeof(utf8), &utf8len, utf8, fileID);
	if ((result != 0) || 
	    ((u_int16_t)descp->cd_namelen != utf8len) ||
	    (bcmp(descp->cd_nameptr, utf8, utf8len) != 0)) { 
		goto falsematch;
	}

	return (0);

falsematch:
	cat_releasedesc(outdescp);
	return (ENOENT);
}


/*
 * cat_lookupbykey - lookup a catalog node using a cnode key
 */
static int
cat_lookupbykey(struct hfsmount *hfsmp, CatalogKey *keyp, int flags, u_int32_t hint, int wantrsrc,
                  struct cat_desc *descp, struct cat_attr *attrp, struct cat_fork *forkp, cnid_t *desc_cnid)
{
	struct BTreeIterator * iterator;
	FSBufferDescriptor btdata;
	CatalogRecord * recp;
	u_int16_t  datasize;
	int result;
	int std_hfs;
	u_int32_t ilink = 0;
	cnid_t cnid = 0;
	u_int32_t encoding = 0;
	cnid_t parentid = 0;

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

	/* Save the cnid, parentid, and encoding now in case there's a hard link or inode */
	cnid = getcnid(recp);
	if (cnid == 0) {
		/* CNID of 0 is invalid.  Mark as corrupt */
		hfs_mark_inconsistent (hfsmp, HFS_INCONSISTENCY_DETECTED);
		result = EINVAL;
		goto exit;
	}

	if (std_hfs == 0) {
		parentid = keyp->hfsPlus.parentID;
	}
	
	encoding = getencoding(recp);
	hint = iterator->hint.nodeNum;

	/* Hide the journal files (if any) */
	if ((hfsmp->jnl || ((HFSTOVCB(hfsmp)->vcbAtrb & kHFSVolumeJournaledMask) && (hfsmp->hfs_flags & HFS_READ_ONLY))) &&
		((cnid == hfsmp->hfs_jnlfileid) || (cnid == hfsmp->hfs_jnlinfoblkid)) &&
		 !(flags & HFS_LOOKUP_SYSFILE)) {
		result = ERESERVEDNAME;
		goto exit;
	}

	if (!std_hfs && !(hfsmp->hfs_flags & HFS_CASE_SENSITIVE)) {
		/* Make sure the case of the file was correct if requested */
		if (flags & HFS_LOOKUP_CASESENSITIVE) {
			if (0 != cat_binarykeycompare(&keyp->hfsPlus, (HFSPlusCatalogKey *)&iterator->key)) {
				result = ERESERVEDNAME;
				goto exit;
			}
		}
	}
	
	/*
	 * When a hardlink link is encountered, auto resolve it.
	 *
	 * The catalog record will change, and possibly its type.
	 */
	if (!std_hfs
	    && (attrp || forkp) 
	    && (recp->recordType == kHFSPlusFileRecord)
	    && ((to_bsd_time(recp->hfsPlusFile.createDate) == (time_t)hfsmp->hfs_itime) ||
	        (to_bsd_time(recp->hfsPlusFile.createDate) == (time_t)hfsmp->hfs_metadata_createdate))) {
		int isdirlink = 0;
		int isfilelink = 0;

		if ((SWAP_BE32(recp->hfsPlusFile.userInfo.fdType) == kHardLinkFileType) &&
		    (SWAP_BE32(recp->hfsPlusFile.userInfo.fdCreator) == kHFSPlusCreator)) {
			isfilelink = 1;
		} else if ((recp->hfsPlusFile.flags & kHFSHasLinkChainMask) && 
		           (SWAP_BE32(recp->hfsPlusFile.userInfo.fdType) == kHFSAliasType) && 
			   (SWAP_BE32(recp->hfsPlusFile.userInfo.fdCreator) == kHFSAliasCreator)) {
			isdirlink = 1;
		}
		if ((isfilelink || isdirlink) && !(flags & HFS_LOOKUP_HARDLINK)) {
			ilink = recp->hfsPlusFile.hl_linkReference;
			(void) cat_resolvelink(hfsmp, ilink, isdirlink, (struct HFSPlusCatalogFile *)recp);
		}
	}

	if (attrp != NULL) { 
		if (std_hfs == 0) {
			getbsdattr(hfsmp, (struct HFSPlusCatalogFile *)recp, attrp);
			if (ilink) {
				/* Update the inode number for this hard link */
				attrp->ca_linkref = ilink;
			}
			
			/* 
			 * Set kHFSHasLinkChainBit for hard links, and reset it for all 
			 * other items.  Also set linkCount to 1 for regular files.
			 *
			 * Due to some bug (rdar://8505977), some regular files can have 
			 * kHFSHasLinkChainBit set and linkCount more than 1 even if they 
			 * are not really hard links.  The runtime code should not consider 
			 * these files has hard links.  Therefore we reset the kHFSHasLinkChainBit 
			 * and linkCount for regular file before we vend it out.  This might 
			 * also result in repairing the bad files on disk, if the corresponding 
			 * file is modified and updated on disk.  
			 */
			if (ilink) {
				/* This is a hard link and the link count bit was not set */
				if (!(attrp->ca_recflags & kHFSHasLinkChainMask)) {
					printf ("hfs: set hardlink bit on vol=%s cnid=%u inoid=%u\n", hfsmp->vcbVN, cnid, ilink);
					attrp->ca_recflags |= kHFSHasLinkChainMask;
				}
			} else { 
				/* Make sure that this non-hard link (regular) record is not 
				 * an inode record that was looked up and we do not end up 
				 * reseting the hard link bit on it.
				 */
				if ((parentid != hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid) && 
				    (parentid != hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid)) {
					/* This is not a hard link or inode and the link count bit was set */
					if (attrp->ca_recflags & kHFSHasLinkChainMask) {
						printf ("hfs: clear hardlink bit on vol=%s cnid=%u\n", hfsmp->vcbVN, cnid);
						attrp->ca_recflags &= ~kHFSHasLinkChainMask;
					}
					/* This is a regular file and the link count was more than 1 */
					if (S_ISREG(attrp->ca_mode) && (attrp->ca_linkcount > 1)) {
						printf ("hfs: set linkcount=1 on vol=%s cnid=%u old=%u\n", hfsmp->vcbVN, cnid, attrp->ca_linkcount);
						attrp->ca_linkcount = 1;
					}
				}
			}
		}
#if CONFIG_HFS_STD
		else {
			struct HFSPlusCatalogFile cnoderec;

			promoteattr(hfsmp, recp, &cnoderec);
			getbsdattr(hfsmp, &cnoderec, attrp);	
		}
#endif
	}
	if (forkp != NULL) {
		if (isadir(recp)) {
			bzero(forkp, sizeof(*forkp));
		} 
#if CONFIG_HFS_STD
		else if (std_hfs) {
			promotefork(hfsmp, (HFSCatalogFile *)&recp->hfsFile, wantrsrc, forkp);
		} 
#endif
		else if (wantrsrc) {
			/* Convert the resource fork. */
			forkp->cf_size = recp->hfsPlusFile.resourceFork.logicalSize;
			forkp->cf_new_size = 0;
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
			forkp->cf_new_size = 0;
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
				off_t psize;

				/* 
				 * This is technically a volume corruption. 
				 * If the total number of blocks calculated by iterating + summing
				 * the extents in the resident extent records, is less than that 
				 * which is reported in the catalog entry, we should force a fsck.  
				 * Only modifying ca_blocks here is not guaranteed to make it out 
				 * to disk; it is a runtime-only field. 
				 * 
				 * Note that we could have gotten into this state if we had invalid ranges 
				 * that existed in borrowed blocks that somehow made it out to disk. 
				 * The cnode's on disk block count should never be greater 
				 * than that which is in its extent records.
				 */

				(void) hfs_mark_inconsistent (hfsmp, HFS_INCONSISTENCY_DETECTED);

				forkp->cf_blocks = validblks;
				if (attrp != NULL) {
					attrp->ca_blocks = validblks + recp->hfsPlusFile.resourceFork.totalBlocks;
				}
				psize = (off_t)validblks * (off_t)hfsmp->blockSize;
				if (psize < forkp->cf_size) {
					forkp->cf_size = psize;
				}

			}
		}
	}
	if (descp != NULL) {
		HFSPlusCatalogKey * pluskey = NULL;

		if (std_hfs == 0) {
			pluskey = (HFSPlusCatalogKey *)&iterator->key;
		}
#if CONFIG_HFS_STD
		else {
			MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
			promotekey(hfsmp, (HFSCatalogKey *)&iterator->key, pluskey, &encoding);
	
		}
#endif	
	
		builddesc(pluskey, cnid, hint, encoding, isadir(recp), descp);

#if CONFIG_HFS_STD
		if (std_hfs) {
			FREE(pluskey, M_TEMP);
		}
#endif

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
 *
 * NOTE: both the catalog file and attribute file locks must
 *       be held before calling this function.
 *
 * The caller is responsible for releasing the output
 * catalog descriptor (when supplied outdescp is non-null).
 */
int
cat_create(struct hfsmount *hfsmp, cnid_t new_fileid, struct cat_desc *descp, struct cat_attr *attrp,
	struct cat_desc *out_descp)
{
	FCB * fcb;
	struct btobj * bto;
	FSBufferDescriptor btdata;
	u_int32_t datalen;
	int std_hfs;
	int result = 0;
	u_int32_t encoding = kTextEncodingMacRoman;
	int modeformat;

	modeformat = attrp->ca_mode & S_IFMT;

	fcb = hfsmp->hfs_catalog_cp->c_datafork;
	std_hfs = (hfsmp->hfs_flags & HFS_STANDARD);

	/* The caller is expected to reserve a CNID before calling this function! */
	
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
		
		/* Caller asserts the following:
		 *	1) this CNID is not in use by any orphaned EAs 
		 *  2) There are no lingering cnodes (removed on-disk but still in-core) with this CNID
		 *  3) There are no thread or catalog records for this ID 
		 */		 
		buildthreadkey(new_fileid, std_hfs, (CatalogKey *) &bto->iterator.key);
		result = BTInsertRecord(fcb, &bto->iterator, &btdata, datalen);
		if (result) {
			goto exit;
		}
	}

	/*
	 * Now insert the file/directory record
	 */
	buildrecord(attrp, new_fileid, std_hfs, encoding, &bto->data, &datalen);
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
			buildthreadkey(new_fileid, std_hfs, (CatalogKey *)&bto->iterator.key);
			if (BTDeleteRecord(fcb, &bto->iterator)) {
				/* Error on deleting extra thread record, mark 
				 * volume inconsistent 
				 */
				printf ("hfs: cat_create() failed to delete thread record id=%u on vol=%s\n", new_fileid, hfsmp->vcbVN);
				hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
			}
		}
		goto exit;
	}

	/*
	 * Insert was successful, update name, parent and volume
	 */
	if (out_descp != NULL) {
		HFSPlusCatalogKey * pluskey = NULL;

		if (std_hfs == 0) {
			pluskey = (HFSPlusCatalogKey *)&bto->iterator.key;
		}
#if CONFIG_HFS_STD
		else {
			MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
			promotekey(hfsmp, (HFSCatalogKey *)&bto->iterator.key, pluskey, &encoding);
		} 
#endif

		builddesc(pluskey, new_fileid, bto->iterator.hint.nodeNum,
			encoding, S_ISDIR(attrp->ca_mode), out_descp);
#if CONFIG_HFS_STD
		if (std_hfs) {
			FREE(pluskey, M_TEMP);
		}
#endif

	}
	attrp->ca_fileid = new_fileid;

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
 *
 * Note: The caller is responsible for releasing the output
 * catalog descriptor (when supplied out_cdp is non-null).
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
	u_int16_t	datasize;
	int result = 0;
	int sourcegone = 0;
	int skipthread = 0;
	int directory = from_cdp->cd_flags & CD_ISDIR;
	int is_dirlink = 0;
	int std_hfs;
	u_int32_t encoding = 0;

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
		struct BTreeIterator *dir_iterator = NULL;

		cnid_t cnid = from_cdp->cd_cnid;
		cnid_t pathcnid = todir_cdp->cd_parentcnid;
	
		/* First check the obvious ones */
		if (cnid == fsRtDirID  ||
		    cnid == to_cdp->cd_parentcnid  ||
		    cnid == pathcnid) {
			result = EINVAL;
			goto exit;
		}
		/* now allocate the dir_iterator */
		MALLOC (dir_iterator, struct BTreeIterator*, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK);
		if (dir_iterator == NULL) {
			return ENOMEM; 
		}
		bzero(dir_iterator, sizeof(*dir_iterator));
			
		/*
		 * Traverse destination path all the way back to the root
		 * making sure that source directory is not encountered.
		 *
		 */
		while (pathcnid > fsRtDirID) {
			buildthreadkey(pathcnid, std_hfs, (CatalogKey *)&dir_iterator->key);
			result = BTSearchRecord(fcb, dir_iterator, &btdata, &datasize, NULL);
			if (result) {
				FREE(dir_iterator, M_TEMP);
				goto exit;
			}
			pathcnid = getparentcnid(recp);
			if (pathcnid == cnid || pathcnid == 0) {
				result = EINVAL;
				FREE(dir_iterator, M_TEMP);
				goto exit;
			}
		}
		FREE(dir_iterator, M_TEMP);
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

	/* Check if the source is directory hard link.  We do not change 
	 * directory flag because it is later used to initialize result descp
	 */
	if ((!std_hfs) && 
	    (directory) && 
	    (recp->recordType == kHFSPlusFileRecord) &&
	    (recp->hfsPlusFile.flags & kHFSHasLinkChainMask)) {
	    	is_dirlink  = 1;
	}

	/*
	 * Update the text encoding (on disk and in descriptor).
	 *
	 * Note that hardlink inodes don't require a text encoding hint.
	 */
	if (!std_hfs &&
	    todir_cdp->cd_parentcnid != hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid &&
	    todir_cdp->cd_parentcnid != hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
		encoding = hfs_pickencoding(to_key->nodeName.unicode, to_key->nodeName.length);
		hfs_setencodingbits(hfsmp, encoding);
		recp->hfsPlusFile.textEncoding = encoding;
		if (out_cdp)
			out_cdp->cd_encoding = encoding;
	}

#if CONFIG_HFS_STD
	if (std_hfs && !directory &&
	    !(recp->hfsFile.flags & kHFSThreadExistsMask)) {
		skipthread = 1;
	}
#endif

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
		cnid_t cnid = 0;

		if (from_cdp->cd_parentcnid != to_cdp->cd_parentcnid)
			goto exit; /* EEXIST */

		/* Find cnode data at new location */
		result = BTSearchRecord(fcb, to_iterator, &btdata, &datasize, NULL);
		if (result)
			goto exit;
		
		/* Get the CNID after calling searchrecord */
		cnid  = getcnid (recp);
		if (cnid == 0) {
			hfs_mark_inconsistent(hfsmp, HFS_INCONSISTENCY_DETECTED);
			result = EINVAL;
			goto exit;
		}

		if ((fromtype != recp->recordType) ||
		    (from_cdp->cd_cnid != cnid)) {
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
			if (err) {
				printf("hfs: cat_create: could not undo (BTInsert = %d)\n", err);
				hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
				result = err;
				goto exit;
			}
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
			if (err) {
				printf("hfs: cat_create: could not undo (BTDelete = %d)\n", err);
				hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
				result = err;
				goto exit;
			}
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
		/* For directory hard links, always create a file thread 
		 * record.  For everything else, use the directory flag.
		 */
		if (is_dirlink) {
			datasize = buildthread(&to_iterator->key, recp, std_hfs, false);
		} else {
			datasize = buildthread(&to_iterator->key, recp, std_hfs, directory);
		}
		btdata.itemSize = datasize;
		buildthreadkey(from_cdp->cd_cnid, std_hfs, (CatalogKey *)&from_iterator->key);
		result = BTInsertRecord(fcb, from_iterator, &btdata, datasize);
	}

	if (out_cdp) {
		HFSPlusCatalogKey * pluskey = NULL;

		if (std_hfs == 0) {	
			pluskey = (HFSPlusCatalogKey *)&to_iterator->key;
		}
#if CONFIG_HFS_STD
		else {
			MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
			promotekey(hfsmp, (HFSCatalogKey *)&to_iterator->key, pluskey, &encoding);

			/* Save the real encoding hint in the Finder Info (field 4). */
			if (directory && from_cdp->cd_cnid == kHFSRootFolderID) {
				u_int32_t realhint;

				realhint = hfs_pickencoding(pluskey->nodeName.unicode, pluskey->nodeName.length);
				vcb->vcbFndrInfo[4] = SET_HFS_TEXT_ENCODING(realhint);
			}
		}
#endif

		builddesc(pluskey, from_cdp->cd_cnid, to_iterator->hint.nodeNum,
			encoding, directory, out_cdp);
#if CONFIG_HFS_STD
		if (std_hfs) {
			FREE(pluskey, M_TEMP);
		}
#endif

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
	FCB * fcb;
	BTreeIterator *iterator;
	cnid_t cnid;
	int std_hfs;
	int result;

	fcb = hfsmp->hfs_catalog_cp->c_datafork;
	std_hfs = (hfsmp->hfs_flags & HFS_STANDARD);

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
	
	/* Borrow the btcb iterator since we have an exclusive catalog lock. */	
	iterator = &((BTreeControlBlockPtr)(fcb->ff_sysfileinfo))->iterator;
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

	/* Delete thread record.  On error, mark volume inconsistent */
	buildthreadkey(cnid, std_hfs, (CatalogKey *)&iterator->key);
	if (BTDeleteRecord(fcb, iterator)) {
		if (!std_hfs) {
			printf ("hfs: cat_delete() failed to delete thread record id=%u on vol=%s\n", cnid, hfsmp->vcbVN);
			hfs_mark_inconsistent(hfsmp, HFS_OP_INCOMPLETE);
		}
	}

exit:
	(void) BTFlushPath(fcb);

	return MacToVFSError(result);
}


/*
 * cat_update_internal - update the catalog node described by descp
 * using the data from attrp and forkp.  
 * If update_hardlink is true, the hard link catalog record is updated
 * and not the inode catalog record. 
 */
static int
cat_update_internal(struct hfsmount *hfsmp, int update_hardlink, struct cat_desc *descp, struct cat_attr *attrp,
	const struct cat_fork *dataforkp, const struct cat_fork *rsrcforkp)
{
	FCB * fcb;
	BTreeIterator * iterator;
	struct update_state state;
	int result;

	fcb = hfsmp->hfs_catalog_cp->c_datafork;

	state.s_desc = descp;
	state.s_attr = attrp;
	state.s_datafork = dataforkp;
	state.s_rsrcfork = rsrcforkp;
	state.s_hfsmp = hfsmp;

	/* Borrow the btcb iterator since we have an exclusive catalog lock. */	
	iterator = &((BTreeControlBlockPtr)(fcb->ff_sysfileinfo))->iterator;

	/*
	 * For open-deleted files we need to do a lookup by cnid
	 * (using thread rec).
	 *
	 * For hard links and if not requested by caller, the target 
	 * of the update is the inode itself (not the link record) 
	 * so a lookup by fileid (i.e. thread rec) is needed.
	 */
	if ((update_hardlink == false) && 
	    ((descp->cd_cnid != attrp->ca_fileid) ||
	     (descp->cd_namelen == 0) ||
	     (attrp->ca_recflags & kHFSHasLinkChainMask))) {
		result = getkey(hfsmp, attrp->ca_fileid, (CatalogKey *)&iterator->key);
	} else {
		result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)&iterator->key, 0);
	}
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

	return MacToVFSError(result);
}

/*
 * cat_update - update the catalog node described by descp
 * using the data from attrp and forkp. 
 */
int
cat_update(struct hfsmount *hfsmp, struct cat_desc *descp, struct cat_attr *attrp,
	const struct cat_fork *dataforkp, const struct cat_fork *rsrcforkp)
{
	return cat_update_internal(hfsmp, false, descp, attrp, dataforkp, rsrcforkp);
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
	const struct cat_fork *forkp;
	struct hfsmount *hfsmp;
	long blksize;

	descp   = state->s_desc;
	attrp   = state->s_attr;
	hfsmp   = state->s_hfsmp;
	blksize = HFSTOVCB(hfsmp)->blockSize;

	switch (crp->recordType) {

#if CONFIG_HFS_STD
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
		int i;

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

		/* Synchronize the lock state */
		if (attrp->ca_flags & (SF_IMMUTABLE | UF_IMMUTABLE))
			file->flags |= kHFSFileLockedMask;
		else
			file->flags &= ~kHFSFileLockedMask;
		break;
	}
#endif
	
	case kHFSPlusFolderRecord: {
		HFSPlusCatalogFolder *dir;
		
		dir = (struct HFSPlusCatalogFolder *)crp;
		/* Do a quick sanity check */
		if (dir->folderID != attrp->ca_fileid) {
			printf("hfs: catrec_update: id %d != %d, vol=%s\n", dir->folderID, attrp->ca_fileid, hfsmp->vcbVN);
			return (btNotFound);
		}
		dir->flags            = attrp->ca_recflags;
		dir->valence          = attrp->ca_entries;
		dir->createDate       = to_hfs_time(attrp->ca_itime);
		dir->contentModDate   = to_hfs_time(attrp->ca_mtime);
		dir->backupDate       = to_hfs_time(attrp->ca_btime);
		dir->accessDate       = to_hfs_time(attrp->ca_atime);
		attrp->ca_atimeondisk = attrp->ca_atime;	
		dir->attributeModDate = to_hfs_time(attrp->ca_ctime);
		/* Note: directory hardlink inodes don't require a text encoding hint. */
		if (ckp->hfsPlus.parentID != hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
			dir->textEncoding = descp->cd_encoding;
		}
		dir->folderCount      = attrp->ca_dircount;
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
			/* A directory hardlink has a link count. */
			if (attrp->ca_linkcount > 1 || dir->hl_linkCount > 1) {
				dir->hl_linkCount = attrp->ca_linkcount;
			}
		}
		break;
	}
	case kHFSPlusFileRecord: {
		HFSPlusCatalogFile *file;
		int is_dirlink; 
		
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
		/*
		 * Note: file hardlink inodes don't require a text encoding
		 * hint, but they do have a first link value.
		 */
		if (ckp->hfsPlus.parentID == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid) {
			file->hl_firstLinkID = attrp->ca_firstlink;
		} else {
			file->textEncoding = descp->cd_encoding;
		}
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
		 *
		 * Do not modify bsdInfo for directory hard link records.
		 * They are set during creation and are not modifiable, so just 
		 * leave them alone. 
		 */
		is_dirlink = (file->flags & kHFSHasLinkChainMask) &&     
			     (SWAP_BE32(file->userInfo.fdType) == kHFSAliasType) && 
			     (SWAP_BE32(file->userInfo.fdCreator) == kHFSAliasCreator);

		if (!is_dirlink && 
		    ((file->bsdInfo.fileMode != 0) ||
		     (attrp->ca_flags != 0) ||
		     (attrp->ca_uid != hfsmp->hfs_uid) ||
		     (attrp->ca_gid != hfsmp->hfs_gid) ||
		     ((attrp->ca_mode & ALLPERMS) !=
		      (hfsmp->hfs_file_mask & ACCESSPERMS)))) {
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
		     file->dataFork.extents[0].startBlock)) {
			panic("hfs: catrec_update: rsrc fork == data fork");
		}

		/* Synchronize the lock state */
		if (attrp->ca_flags & (SF_IMMUTABLE | UF_IMMUTABLE))
			file->flags |= kHFSFileLockedMask;
		else
			file->flags &= ~kHFSFileLockedMask;

		/* Push out special field if necessary */
		if (S_ISBLK(attrp->ca_mode) || S_ISCHR(attrp->ca_mode)) {
			file->bsdInfo.special.rawDevice = attrp->ca_rdev;
		} 
		else {
			/* 
			 * Protect against the degenerate case where the descriptor contains the
			 * raw inode ID in its CNID field.  If the HFSPlusCatalogFile record indicates
			 * the linkcount was greater than 1 (the default value), then it must have become
			 * a hardlink.  In this case, update the linkcount from the cat_attr passed in.
			 */
			if ((descp->cd_cnid != attrp->ca_fileid) || (attrp->ca_linkcount > 1 ) ||
				(file->hl_linkCount > 1)) {
				file->hl_linkCount = attrp->ca_linkcount;
			}
		}
		break;
	}
	default:
		return (btNotFound);
	}
	return (0);
}

/* This function sets kHFSHasChildLinkBit in a directory hierarchy in the 
 * catalog btree of given cnid by walking up the parent chain till it reaches 
 * either the root folder, or the private metadata directory for storing 
 * directory hard links.  This function updates the corresponding in-core 
 * cnode, if any, and the directory record in the catalog btree.
 * On success, returns zero.  On failure, returns non-zero value.
 */
__private_extern__
int 
cat_set_childlinkbit(struct hfsmount *hfsmp, cnid_t cnid)
{
	int retval = 0;
	int lockflags = 0;
	struct cat_desc desc;
	struct cat_attr attr;

	while ((cnid != kHFSRootFolderID) && (cnid != kHFSRootParentID) &&
	       (cnid != hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid)) {
		/* Update the bit in corresponding cnode, if any, in the hash.
		 * If the cnode has the bit already set, stop the traversal.
		 */
		retval = hfs_chash_set_childlinkbit(hfsmp, cnid);
		if (retval == 0) {
			break;
		}

		/* Update the catalog record on disk if either cnode was not
		 * found in the hash, or if a cnode was found and the cnode 
		 * did not have the bit set previously.
		 */
		retval = hfs_start_transaction(hfsmp);
		if (retval) {
			break;
		}
		lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_EXCLUSIVE_LOCK);

		/* Look up our catalog folder record */
		retval = cat_idlookup(hfsmp, cnid, 0, 0, &desc, &attr, NULL);
		if (retval) {
			hfs_systemfile_unlock(hfsmp, lockflags);
			hfs_end_transaction(hfsmp);
			break;
		}

		/* Update the bit in the catalog record */
		attr.ca_recflags |= kHFSHasChildLinkMask;
		retval = cat_update(hfsmp, &desc, &attr, NULL, NULL);
		if (retval) {
			hfs_systemfile_unlock(hfsmp, lockflags);
			hfs_end_transaction(hfsmp);
			cat_releasedesc(&desc);
			break;
		}

		hfs_systemfile_unlock(hfsmp, lockflags);
		hfs_end_transaction(hfsmp);

		cnid = desc.cd_parentcnid;
		cat_releasedesc(&desc);
	}

	return retval;
}

/* This function traverses the parent directory hierarchy from the given 
 * directory to one level below root directory and checks if any of its 
 * ancestors is - 
 * 	1. A directory hard link.  
 * 	2. The 'pointed at' directory.
 * If any of these conditions fail or an internal error is encountered 
 * during look up of the catalog record, this function returns non-zero value.
 */
__private_extern__
int
cat_check_link_ancestry(struct hfsmount *hfsmp, cnid_t cnid, cnid_t pointed_at_cnid)
{
	HFSPlusCatalogKey *keyp;
	BTreeIterator *ip;
	FSBufferDescriptor btdata;
	HFSPlusCatalogFolder folder;
	FCB *fcb;
	int invalid;
	int result;

	invalid = 0;
	BDINIT(btdata, &folder);
	MALLOC(ip, BTreeIterator *, sizeof(*ip), M_TEMP, M_WAITOK);
	keyp = (HFSPlusCatalogKey *)&ip->key;
	fcb = hfsmp->hfs_catalog_cp->c_datafork;

	while (cnid != kHFSRootParentID) {
		/* Check if the 'pointed at' directory is an ancestor */
		if (pointed_at_cnid == cnid) {
			invalid = 1;
			break;
		}
		if ((result = getkey(hfsmp, cnid, (CatalogKey *)keyp))) {
			printf("hfs: cat_check_link_ancestry: getkey failed id=%u, vol=%s\n", cnid, hfsmp->vcbVN);
			invalid = 1;  /* On errors, assume an invalid parent */
			break;
		}
		if ((result = BTSearchRecord(fcb, ip, &btdata, NULL, NULL))) {
			printf("hfs: cat_check_link_ancestry: cannot find id=%u, vol=%s\n", cnid, hfsmp->vcbVN);
			invalid = 1;  /* On errors, assume an invalid parent */
			break;
		}
		/* Check if this ancestor is a directory hard link */
		if (folder.flags & kHFSHasLinkChainMask) {
			invalid = 1;
			break;
		}
		cnid = keyp->parentID;
	}
	FREE(ip, M_TEMP);
	return (invalid);
}


/*
 * update_siblinglinks_callback - update a link's chain
 */

struct linkupdate_state {
	cnid_t filelinkid;
	cnid_t prevlinkid;
	cnid_t nextlinkid;
};

static int
update_siblinglinks_callback(__unused const CatalogKey *ckp, CatalogRecord *crp, struct linkupdate_state *state)
{
	HFSPlusCatalogFile *file;

	if (crp->recordType != kHFSPlusFileRecord) {
		printf("hfs: update_siblinglinks_callback: unexpected rec type %d\n", crp->recordType);
		return (btNotFound);
	}

	file = (struct HFSPlusCatalogFile *)crp;
	if (file->flags & kHFSHasLinkChainMask) {
		if (state->prevlinkid != HFS_IGNORABLE_LINK) {
			file->hl_prevLinkID = state->prevlinkid;
		}
		if (state->nextlinkid != HFS_IGNORABLE_LINK) {
			file->hl_nextLinkID = state->nextlinkid;
		}
	} else {
		printf("hfs: update_siblinglinks_callback: file %d isn't a chain\n", file->fileID);
	}
	return (0);
}

/*
 * cat_update_siblinglinks - update a link's chain
 */
int
cat_update_siblinglinks(struct hfsmount *hfsmp, cnid_t linkfileid, cnid_t prevlinkid, cnid_t nextlinkid)
{
	FCB * fcb;
	BTreeIterator * iterator;
	struct linkupdate_state state;
	int result;

	fcb = hfsmp->hfs_catalog_cp->c_datafork;
	state.filelinkid = linkfileid;
	state.prevlinkid = prevlinkid;
	state.nextlinkid = nextlinkid;

	/* Create an iterator for use by us temporarily */
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	
	result = getkey(hfsmp, linkfileid, (CatalogKey *)&iterator->key);
	if (result == 0) {
		result = BTUpdateRecord(fcb, iterator, (IterateCallBackProcPtr)update_siblinglinks_callback, &state);
		(void) BTFlushPath(fcb);
	} else {
		printf("hfs: cat_update_siblinglinks: couldn't resolve cnid=%d, vol=%s\n", linkfileid, hfsmp->vcbVN);
	}
	
	FREE (iterator, M_TEMP);
	return MacToVFSError(result);
}

/*
 * cat_lookuplink - lookup a link by it's name
 */
int
cat_lookuplink(struct hfsmount *hfsmp, struct cat_desc *descp, cnid_t *linkfileid, cnid_t *prevlinkid,  cnid_t *nextlinkid)
{
	FCB * fcb;
	BTreeIterator * iterator;
	struct FSBufferDescriptor btdata;
	struct HFSPlusCatalogFile file;
	int result;

	fcb = hfsmp->hfs_catalog_cp->c_datafork;

	/* Create an iterator for use by us temporarily */
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	if ((result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)&iterator->key, 0))) {
		goto exit;
	}
	BDINIT(btdata, &file);

	if ((result = BTSearchRecord(fcb, iterator, &btdata, NULL, NULL))) {
		goto exit;
	}
	if (file.recordType != kHFSPlusFileRecord) {
		result = ENOENT;
		goto exit;
	}
	*linkfileid = file.fileID;

	if (file.flags & kHFSHasLinkChainMask) {
		*prevlinkid = file.hl_prevLinkID;
		*nextlinkid = file.hl_nextLinkID;
	} else {
		*prevlinkid = 0;
		*nextlinkid = 0;
	}
exit:
	FREE(iterator, M_TEMP);
	return MacToVFSError(result);
}


/*
 * cat_lookup_siblinglinks - lookup previous and next link ID for link using its cnid
 */
int
cat_lookup_siblinglinks(struct hfsmount *hfsmp, cnid_t linkfileid, cnid_t *prevlinkid,  cnid_t *nextlinkid)
{
	FCB * fcb;
	BTreeIterator * iterator;
	struct FSBufferDescriptor btdata;
	struct HFSPlusCatalogFile file;
	int result;

	fcb = hfsmp->hfs_catalog_cp->c_datafork;

	/* Create an iterator for use by us temporarily */
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	
	if ((result = getkey(hfsmp, linkfileid, (CatalogKey *)&iterator->key))) {
		goto exit;
	}
	BDINIT(btdata, &file);

	if ((result = BTSearchRecord(fcb, iterator, &btdata, NULL, NULL))) {
		goto exit;
	}
	/* The prev/next chain is only valid when kHFSHasLinkChainMask is set. */
	if (file.flags & kHFSHasLinkChainMask) {
		cnid_t parent;

		parent = ((HFSPlusCatalogKey *)&iterator->key)->parentID;

		/* directory inodes don't have a chain (its in an EA) */
		if (parent == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
			result = ENOLINK;  /* signal to caller to get head of list */
		} else if (parent == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid) {
			*prevlinkid = 0;
			*nextlinkid = file.hl_firstLinkID;
		} else {
			*prevlinkid = file.hl_prevLinkID;
			*nextlinkid = file.hl_nextLinkID;
		}
	} else {
		*prevlinkid = 0;
		*nextlinkid = 0;
	}
exit:
	FREE(iterator, M_TEMP);		
	return MacToVFSError(result);
}


/*
 * cat_lookup_lastlink - find the last sibling link in the chain (no "next" ptr)
 */
int
cat_lookup_lastlink(struct hfsmount *hfsmp, cnid_t linkfileid, 
		cnid_t *lastlink, struct cat_desc *cdesc)
{
	FCB * fcb;
	BTreeIterator * iterator;
	struct FSBufferDescriptor btdata;
	struct HFSPlusCatalogFile file;
	int result;
	int itercount = 0;
	int foundlast = 0;
	cnid_t currentlink = linkfileid;
	
	fcb = hfsmp->hfs_catalog_cp->c_datafork;
	
	/* Create an iterator for use by us temporarily */
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);

	while ((foundlast == 0) && (itercount < HFS_LINK_MAX )) {
		itercount++;
		bzero(iterator, sizeof(*iterator));

		if ((result = getkey(hfsmp, currentlink, (CatalogKey *)&iterator->key))) {
			goto exit;
		}
		BDINIT(btdata, &file);

		if ((result = BTSearchRecord(fcb, iterator, &btdata, NULL, NULL))) {
			goto exit;
		}

		/* The prev/next chain is only valid when kHFSHasLinkChainMask is set. */
		if (file.flags & kHFSHasLinkChainMask) {
			cnid_t parent;

			parent = ((HFSPlusCatalogKey *)&iterator->key)->parentID;
			/* 
			 * The raw inode for a directory hardlink doesn't have a chain.
			 * Its link information lives in an EA. 
			 */
			if (parent == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
				/* We don't iterate to find the oldest directory hardlink. */
				result = ENOLINK; 
				goto exit;
			} 
			else if (parent == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid) {
				/* Raw inode for file hardlink (the base inode) */
				currentlink = file.hl_firstLinkID;
			
				/* 
				 * One minor special-casing here is necessary.
				 * If our ID brought us to the raw hardlink inode, and it does
				 * not have any siblings, then it's an open-unlinked file, and we
				 * should not proceed any further.
				 */ 
				if (currentlink == 0) {
					result = ENOLINK;
					goto exit;
				}
			} 
			else {
				/* Otherwise, this item's parent is a legitimate directory in the namespace */
				if (file.hl_nextLinkID == 0) {
					/* If nextLinkID is 0, then we found the end; no more hardlinks */
					foundlast = 1;
					*lastlink = currentlink;
					/* 
					 * Since we had to construct a catalog key to do this lookup
					 * we still hold it in-hand.  We might as well use it to build 
					 * the descriptor that the caller asked for.
					 */
					builddesc ((HFSPlusCatalogKey*)&iterator->key, currentlink, 0, 0, 0, cdesc);
					break;
				}

				currentlink = file.hl_nextLinkID;
			}
		} 
		else {
			/* Sorry, can't help you without a link chain */
			result = ENOLINK;
			goto exit;
		}
	}
exit:
	/* If we didn't find what we were looking for, zero out the args */
	if (foundlast == 0) {
		if (cdesc) {
			bzero (cdesc, sizeof(struct cat_desc));
		}
		if (lastlink) {
			*lastlink = 0;
		}
	}

	FREE(iterator, M_TEMP);		
	return MacToVFSError(result);
}


/*
 * cat_createlink - create a link in the catalog
 *
 * The following cat_attr fields are expected to be set:
 *	 ca_linkref
 *	 ca_itime
 *	 ca_mode (S_IFREG)
 *	 ca_recflags
 *	 ca_flags
 *	 ca_finderinfo (type and creator)
 */
int
cat_createlink(struct hfsmount *hfsmp, struct cat_desc *descp, struct cat_attr *attrp,
               cnid_t nextlinkid, cnid_t *linkfileid)
{
	FCB * fcb;
	struct btobj * bto;
	FSBufferDescriptor btdata;
	HFSPlusForkData *rsrcforkp;
	u_int32_t nextCNID;
	u_int32_t datalen;
	u_int32_t encoding;
	int thread_inserted = 0;
	int alias_allocated = 0;
	int result = 0;
	int std_hfs;

	std_hfs = (hfsmp->hfs_flags & HFS_STANDARD);

	fcb = hfsmp->hfs_catalog_cp->c_datafork;

	/*
	 * Get the next CNID.  Note that we are currently holding catalog lock.
	 */
	result = cat_acquire_cnid(hfsmp, &nextCNID);
	if (result) {
		return result;
	}

	/* Get space for iterator, key and data */	
	MALLOC(bto, struct btobj *, sizeof(struct btobj), M_TEMP, M_WAITOK);
	bto->iterator.hint.nodeNum = 0;
	rsrcforkp = &bto->data.hfsPlusFile.resourceFork;

	result = buildkey(hfsmp, descp, &bto->key, 0);
	if (result) {
		printf("hfs: cat_createlink: err %d from buildkey\n", result);
		goto exit;
	}

	/* This is our only chance to set the encoding (other than a rename). */
	encoding = hfs_pickencoding(bto->key.nodeName.unicode, bto->key.nodeName.length);

	/* 
	 * Insert the thread record first.
	 */
	datalen = buildthread((void*)&bto->key, &bto->data, 0, 0);
	btdata.bufferAddress = &bto->data;
	btdata.itemSize = datalen;
	btdata.itemCount = 1;

	buildthreadkey(nextCNID, 0, (CatalogKey *) &bto->iterator.key);
	result = BTInsertRecord(fcb, &bto->iterator, &btdata, datalen);
	if (result) {
		goto exit;
	}
	thread_inserted = 1;

	/*
	 * Now insert the link record.
	 */
	buildrecord(attrp, nextCNID, 0, encoding, &bto->data, &datalen);
	
	bto->data.hfsPlusFile.hl_prevLinkID = 0;
	bto->data.hfsPlusFile.hl_nextLinkID = nextlinkid;
	bto->data.hfsPlusFile.hl_linkReference = attrp->ca_linkref;

	/* For directory hard links, create alias in resource fork */
	if (descp->cd_flags & CD_ISDIR) {
		if ((result = cat_makealias(hfsmp, attrp->ca_linkref, &bto->data.hfsPlusFile))) {
			goto exit;
		}
		alias_allocated = 1;
	}
	btdata.bufferAddress = &bto->data;
	btdata.itemSize = datalen;
	btdata.itemCount = 1;
	
	bcopy(&bto->key, &bto->iterator.key, sizeof(bto->key));

	result = BTInsertRecord(fcb, &bto->iterator, &btdata, datalen);
	if (result) {
		if (result == btExists)
			result = EEXIST;
		goto exit;
	}
	if (linkfileid != NULL) {
		*linkfileid = nextCNID;
	}
exit:	
	if (result) {
		if (thread_inserted) {
			printf("hfs: cat_createlink: BTInsertRecord err=%d, vol=%s\n", MacToVFSError(result), hfsmp->vcbVN);

			buildthreadkey(nextCNID, 0, (CatalogKey *)&bto->iterator.key);
			if (BTDeleteRecord(fcb, &bto->iterator)) {
				printf("hfs: cat_createlink() failed to delete thread record on volume %s\n", hfsmp->vcbVN);
				hfs_mark_inconsistent(hfsmp, HFS_ROLLBACK_FAILED);
			}
		}
		if (alias_allocated && rsrcforkp->extents[0].startBlock != 0) {
			(void) BlockDeallocate(hfsmp, rsrcforkp->extents[0].startBlock,
					       rsrcforkp->extents[0].blockCount, 0);
			rsrcforkp->extents[0].startBlock = 0;
			rsrcforkp->extents[0].blockCount = 0;
		}
	}
	(void) BTFlushPath(fcb);
	FREE(bto, M_TEMP);

	return MacToVFSError(result);
}

/* Directory hard links are visible as aliases on pre-Leopard systems and 
 * as normal directories on Leopard or later.  All directory hard link aliases 
 * have the same resource fork content except for the three uniquely 
 * identifying values that are updated in the resource fork data when the alias 
 * is created.  The following array is the constant resource fork data used 
 * only for creating directory hard link aliases.
 */
static const char hfs_dirlink_alias_rsrc[] = {
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x9e, 0x00, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x00, 0x32, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x2b,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x9e, 0x00, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x32, 0x00, 0x00, 0x61, 0x6c, 0x69, 0x73,
	0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Constants for directory hard link alias */
enum {
	/* Size of resource fork data array for directory hard link alias */
	kHFSAliasSize                = 0x1d0,

	/* Volume type for ejectable devices like disk image */
	kHFSAliasVolTypeEjectable    = 0x5,

	/* Offset for volume create date, in Mac OS local time */
	kHFSAliasVolCreateDateOffset = 0x12a,

	/* Offset for the type of volume */
	kHFSAliasVolTypeOffset       = 0x130,

	/* Offset for folder ID of the parent directory of the directory inode */
	kHFSAliasParentIDOffset      = 0x132,

	/* Offset for folder ID of the directory inode */
	kHFSAliasTargetIDOffset	     = 0x176,
};

/* Create and write an alias that points at the directory represented by given
 * inode number on the same volume.  Directory hard links are visible as 
 * aliases in pre-Leopard systems and this function creates these aliases.  
 *
 * Note: This code is very specific to creating alias for the purpose 
 * of directory hard links only, and should not be generalized.
 */
static int
cat_makealias(struct hfsmount *hfsmp, u_int32_t inode_num, struct HFSPlusCatalogFile *crp)
{
	struct buf *bp;
	daddr64_t blkno;
	u_int32_t blkcount;
	int blksize;
	int sectorsize;
	int result;
	HFSPlusForkData *rsrcforkp;
	char *alias;
	uint32_t *valptr;

	rsrcforkp = &(crp->resourceFork);

	blksize = hfsmp->blockSize;
	blkcount = howmany(kHFSAliasSize, blksize);
	sectorsize = hfsmp->hfs_logical_block_size;
	bzero(rsrcforkp, sizeof(HFSPlusForkData));

	/* Allocate some disk space for the alias content. */
	result = BlockAllocate(hfsmp, 0, blkcount, blkcount, 
			       HFS_ALLOC_FORCECONTIG | HFS_ALLOC_METAZONE, 
	                       &rsrcforkp->extents[0].startBlock,
	                       &rsrcforkp->extents[0].blockCount);
	/* Did it fail with an out of space error? If so, re-try and allow journal flushing. */
	if (result == dskFulErr ) {	
		result = BlockAllocate(hfsmp, 0, blkcount, blkcount, 
			       HFS_ALLOC_FORCECONTIG | HFS_ALLOC_METAZONE | HFS_ALLOC_FLUSHTXN, 
	                       &rsrcforkp->extents[0].startBlock,
	                       &rsrcforkp->extents[0].blockCount);
	}
	if (result) {
		rsrcforkp->extents[0].startBlock = 0;
		goto exit;
	}

	/* Acquire a buffer cache block for our block. */
	blkno = ((u_int64_t)rsrcforkp->extents[0].startBlock * (u_int64_t)blksize) / sectorsize;
	blkno += hfsmp->hfsPlusIOPosOffset / sectorsize;

	bp = buf_getblk(hfsmp->hfs_devvp, blkno, roundup(kHFSAliasSize, hfsmp->hfs_logical_block_size), 0, 0, BLK_META);
	if (hfsmp->jnl) {
		journal_modify_block_start(hfsmp->jnl, bp);
	}

	/* Generate alias content */
	alias = (char *)buf_dataptr(bp);
	bzero(alias, buf_size(bp));
	bcopy(hfs_dirlink_alias_rsrc, alias, kHFSAliasSize);

	/* Set the volume create date, local time in Mac OS format */
	valptr = (uint32_t *)(alias + kHFSAliasVolCreateDateOffset);
	*valptr = OSSwapHostToBigInt32(hfsmp->localCreateDate);

	/* If the file system is on a virtual device like disk image, 
	 * update the volume type to be ejectable device.  
	 */
	if (hfsmp->hfs_flags & HFS_VIRTUAL_DEVICE) {
		*(uint16_t *)(alias + kHFSAliasVolTypeOffset) = 
		OSSwapHostToBigInt16(kHFSAliasVolTypeEjectable);
	}

	/* Set id of the parent of the target directory */
	valptr = (uint32_t *)(alias + kHFSAliasParentIDOffset);
	*valptr = OSSwapHostToBigInt32(hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid);

	/* Set id of the target directory */
	valptr = (uint32_t *)(alias + kHFSAliasTargetIDOffset);
	*valptr = OSSwapHostToBigInt32(inode_num);

	/* Write alias content to disk. */
	if (hfsmp->jnl) {
		journal_modify_block_end(hfsmp->jnl, bp, NULL, NULL);
	} else if ((result = buf_bwrite(bp))) {
		goto exit;
	}

	/* Finish initializing the fork data. */
	rsrcforkp->logicalSize = kHFSAliasSize;
	rsrcforkp->totalBlocks = rsrcforkp->extents[0].blockCount;

exit:
	if (result && rsrcforkp->extents[0].startBlock != 0) {
		(void) BlockDeallocate(hfsmp, rsrcforkp->extents[0].startBlock, rsrcforkp->extents[0].blockCount, 0);
		rsrcforkp->extents[0].startBlock = 0;
		rsrcforkp->extents[0].blockCount = 0;
		rsrcforkp->logicalSize = 0;
		rsrcforkp->totalBlocks = 0;
	}
	return (result);
}

/*
 * cat_deletelink - delete a link from the catalog
 */
int
cat_deletelink(struct hfsmount *hfsmp, struct cat_desc *descp)
{
	struct HFSPlusCatalogFile file;
	struct cat_attr cattr;
	uint32_t totalBlocks;
	int i;
	int result;

	bzero(&file, sizeof (file));
	bzero(&cattr, sizeof (cattr));
	cattr.ca_fileid = descp->cd_cnid;

	/* Directory links have alias content to remove. */
	if (descp->cd_flags & CD_ISDIR) {
		FCB * fcb;
		BTreeIterator * iterator;
		struct FSBufferDescriptor btdata;
	
		fcb = hfsmp->hfs_catalog_cp->c_datafork;
	
		/* Borrow the btcb iterator since we have an exclusive catalog lock. */	
		iterator = &((BTreeControlBlockPtr)(fcb->ff_sysfileinfo))->iterator;
		iterator->hint.nodeNum = 0;
	
		if ((result = buildkey(hfsmp, descp, (HFSPlusCatalogKey *)&iterator->key, 0))) {
			goto exit;
		}
		BDINIT(btdata, &file);
	
		if ((result = BTSearchRecord(fcb, iterator, &btdata, NULL, NULL))) {
			goto exit;
		}
	}

	result = cat_delete(hfsmp, descp, &cattr);
	
	if ((result == 0) && 
	    (descp->cd_flags & CD_ISDIR) && 
	    (file.recordType == kHFSPlusFileRecord)) {

		totalBlocks = file.resourceFork.totalBlocks;

		for (i = 0; (i < 8) && (totalBlocks > 0); i++) {
			if ((file.resourceFork.extents[i].blockCount == 0) &&
			    (file.resourceFork.extents[i].startBlock == 0)) {
				break;
			}

			(void) BlockDeallocate(hfsmp, 
				file.resourceFork.extents[i].startBlock, 
				file.resourceFork.extents[i].blockCount, 0);

			totalBlocks -= file.resourceFork.extents[i].blockCount;
			file.resourceFork.extents[i].startBlock = 0;
			file.resourceFork.extents[i].blockCount = 0;
		}
	}
exit:	
	return (result);
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
	int reached_eof;
};

static int
getentriesattr_callback(const CatalogKey *key, const CatalogRecord *rec,
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
#if CONFIG_HFS_STD
	case kHFSFolderRecord:
	case kHFSFileRecord:
#endif
		if (parentcnid != state->dir_cnid) {
			state->error = ENOENT;
			state->reached_eof = 1;
			return (0);	/* stop */
		}
		break;
	default:
		state->error = ENOENT;
		return (0);	/* stop */
	}

	/* Hide the private system directories and journal files */
	if (parentcnid == kHFSRootFolderID) {
		if (rec->recordType == kHFSPlusFolderRecord) {
			if (rec->hfsPlusFolder.folderID == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid ||
			    rec->hfsPlusFolder.folderID == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
			    	list->skipentries++;
				return (1);	/* continue */
			}
		}
		if ((hfsmp->jnl || ((HFSTOVCB(hfsmp)->vcbAtrb & kHFSVolumeJournaledMask) && (hfsmp->hfs_flags & HFS_READ_ONLY))) &&
		    (rec->recordType == kHFSPlusFileRecord) &&
		    ((rec->hfsPlusFile.fileID == hfsmp->hfs_jnlfileid) ||
		     (rec->hfsPlusFile.fileID == hfsmp->hfs_jnlinfoblkid))) {
			list->skipentries++;
			return (1);	/* continue */
		}
	}

	cep = &list->entry[list->realentries++];
 
	if (state->stdhfs == 0) {
		getbsdattr(hfsmp, (const struct HFSPlusCatalogFile *)rec, &cep->ce_attr);
		builddesc((const HFSPlusCatalogKey *)key, getcnid(rec), 0, getencoding(rec),
				isadir(rec), &cep->ce_desc);

		if (rec->recordType == kHFSPlusFileRecord) {
			cep->ce_datasize = rec->hfsPlusFile.dataFork.logicalSize;
			cep->ce_datablks = rec->hfsPlusFile.dataFork.totalBlocks;
			cep->ce_rsrcsize = rec->hfsPlusFile.resourceFork.logicalSize;
			cep->ce_rsrcblks = rec->hfsPlusFile.resourceFork.totalBlocks;

			/* Save link reference for later processing. */
			if ((SWAP_BE32(rec->hfsPlusFile.userInfo.fdType) == kHardLinkFileType) &&
					(SWAP_BE32(rec->hfsPlusFile.userInfo.fdCreator) == kHFSPlusCreator)) {
				cep->ce_attr.ca_linkref = rec->hfsPlusFile.bsdInfo.special.iNodeNum;
			} else if ((rec->hfsPlusFile.flags & kHFSHasLinkChainMask) && 
					(SWAP_BE32(rec->hfsPlusFile.userInfo.fdType) == kHFSAliasType) && 
					(SWAP_BE32(rec->hfsPlusFile.userInfo.fdCreator) == kHFSAliasCreator)) {
				cep->ce_attr.ca_linkref = rec->hfsPlusFile.bsdInfo.special.iNodeNum;
			}
		}
	}
#if CONFIG_HFS_STD
	else {
		struct HFSPlusCatalogFile cnoderec;
		HFSPlusCatalogKey * pluskey;
		u_int32_t encoding;

		promoteattr(hfsmp, rec, &cnoderec);
		getbsdattr(hfsmp, &cnoderec, &cep->ce_attr);

		MALLOC(pluskey, HFSPlusCatalogKey *, sizeof(HFSPlusCatalogKey), M_TEMP, M_WAITOK);
		promotekey(hfsmp, (const HFSCatalogKey *)key, pluskey, &encoding);
		builddesc(pluskey, getcnid(rec), 0, encoding, isadir(rec), &cep->ce_desc);
		FREE(pluskey, M_TEMP);

		if (rec->recordType == kHFSFileRecord) {
			int blksize = HFSTOVCB(hfsmp)->blockSize;

			cep->ce_datasize = rec->hfsFile.dataLogicalSize;
			cep->ce_datablks = rec->hfsFile.dataPhysicalSize / blksize;
			cep->ce_rsrcsize = rec->hfsFile.rsrcLogicalSize;
			cep->ce_rsrcblks = rec->hfsFile.rsrcPhysicalSize / blksize;
		}
	}
#endif

	return (list->realentries < list->maxentries);
}

/*
 * Pack a cat_entrylist buffer with attributes from the catalog
 *
 * Note: index is zero relative
 */
int
cat_getentriesattr(struct hfsmount *hfsmp, directoryhint_t *dirhint, struct cat_entrylist *ce_list, int *reachedeof)
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
	int reached_eof = 0;

	ce_list->realentries = 0;

	fcb = GetFileControlBlock(HFSTOVCB(hfsmp)->catalogRefNum);
	std_hfs = (HFSTOVCB(hfsmp)->vcbSigWord == kHFSSigWord);
	parentcnid = dirhint->dh_desc.cd_parentcnid;

	bzero (&state, sizeof(struct readattr_state));

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
				/*
				* Note: the index may now point to EOF if the directory
				* was modified in between system calls. We will return
				* ENOENT from cat_findposition if this is the case, and
				* when we bail out with an error, our caller (hfs_readdirattr_internal)
				* will suppress the error and indicate EOF to its caller.
				*/
				result = MacToVFSError(result);
				goto exit;
			}
		}
	}

	/* Fill list with entries starting at iterator->key. */
	result = BTIterateRecords(fcb, kBTreeNextRecord, iterator,
			(IterateCallBackProcPtr)getentriesattr_callback, &state);

	if (state.error) {
		result = state.error;
		reached_eof = state.reached_eof;
	}
	else if (ce_list->realentries == 0) {
		result = ENOENT;
		reached_eof = 1;
	}
	else {
		result = MacToVFSError(result);
	}

	if (std_hfs)
		goto exit;

	/*
	 *  Resolve any hard links.
	 */
	for (i = 0; i < (int)ce_list->realentries; ++i) {
		struct FndrFileInfo *fip;
		struct cat_entry *cep;
		struct HFSPlusCatalogFile filerec;
		int isdirlink = 0;
		int isfilelink = 0;

		cep = &ce_list->entry[i];
		if (cep->ce_attr.ca_linkref == 0)
			continue;
		
		/* Note: Finder info is still in Big Endian */
		fip = (struct FndrFileInfo *)&cep->ce_attr.ca_finderinfo;

		if (S_ISREG(cep->ce_attr.ca_mode) &&
		    (SWAP_BE32(fip->fdType) == kHardLinkFileType) &&
		    (SWAP_BE32(fip->fdCreator) == kHFSPlusCreator)) {
			isfilelink = 1;
		}
		if (S_ISREG(cep->ce_attr.ca_mode) &&
		    (SWAP_BE32(fip->fdType) == kHFSAliasType) &&
		    (SWAP_BE32(fip->fdCreator) == kHFSAliasCreator) &&
		    (cep->ce_attr.ca_recflags & kHFSHasLinkChainMask)) {
			isdirlink = 1;
		}
		if (isfilelink || isdirlink) {
			if (cat_resolvelink(hfsmp, cep->ce_attr.ca_linkref, isdirlink, &filerec) != 0)
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
	*reachedeof = reached_eof;
	return MacToVFSError(result);
}

#define SMALL_DIRENTRY_SIZE  (int)(sizeof(struct dirent) - (MAXNAMLEN + 1) + 8)

/*
 * Callback to pack directory entries.
 * Called with packdirentry_state for each item in a directory.
 */

/* Hard link information collected during cat_getdirentries. */
struct linkinfo {
	u_int32_t       link_ref;
	user_addr_t  dirent_addr;
};
typedef struct linkinfo linkinfo_t;

/* State information for the getdirentries_callback function. */
struct packdirentry_state {
	int            cbs_flags;		/* VNODE_READDIR_* flags */
	u_int32_t      cbs_parentID;
	u_int32_t      cbs_index;
	uio_t	       cbs_uio;
	ExtendedVCB *  cbs_hfsmp;
	int            cbs_result;
	int32_t        cbs_nlinks;
	int32_t        cbs_maxlinks;
	linkinfo_t *   cbs_linkinfo;
	struct cat_desc * cbs_desc;
	u_int8_t        * cbs_namebuf;
	/*
	 * The following fields are only used for NFS readdir, which
	 * uses the next file id as the seek offset of each entry.
	 */
	struct direntry * cbs_direntry;
	struct direntry * cbs_prevdirentry;
	u_int32_t      cbs_previlinkref;
	Boolean        cbs_hasprevdirentry;
	Boolean        cbs_eof;
};

/*
 * getdirentries callback for HFS Plus directories.
 */
static int
getdirentries_callback(const CatalogKey *ckp, const CatalogRecord *crp,
                 struct packdirentry_state *state)
{
	struct hfsmount *hfsmp;
	const CatalogName *cnp;
	cnid_t curID;
	OSErr result;
	struct dirent catent;
	struct direntry * entry = NULL;
	time_t itime;
	u_int32_t ilinkref = 0;
	u_int32_t curlinkref = 0;
	cnid_t  cnid;
	int hide = 0;
	u_int8_t type = DT_UNKNOWN;
	u_int8_t is_mangled = 0;
	u_int8_t is_link = 0;
	u_int8_t *nameptr;
	user_addr_t uiobase = USER_ADDR_NULL;
	size_t namelen = 0;
	size_t maxnamelen;
	size_t uiosize = 0;
	caddr_t uioaddr;
	Boolean stop_after_pack = false;
	
	hfsmp = state->cbs_hfsmp;
	curID = ckp->hfsPlus.parentID;

	/* We're done when parent directory changes */
	if (state->cbs_parentID != curID) {
		/*
		 * If the parent ID is different from curID this means we've hit
		 * the EOF for the directory.  To help future callers, we mark
		 * the cbs_eof boolean.  However, we should only mark the EOF 
		 * boolean if we're about to return from this function. 
		 *
		 * This is because this callback function does its own uiomove
		 * to get the data to userspace.  If we set the boolean before determining
		 * whether or not the current entry has enough room to write its
		 * data to userland, we could fool the callers of this catalog function
		 * into thinking they've hit EOF earlier than they really would have.
		 * In that case, we'd know that we have more entries to process and
		 * send to userland, but we didn't have enough room.  
		 * 
		 * To be safe, we mark cbs_eof here ONLY for the cases where we know we're 
		 * about to return and won't write any new data back
		 * to userland.  In the stop_after_pack case, we'll set this boolean
		 * regardless, so it's slightly safer to let that logic mark the boolean,
		 * especially since it's closer to the return of this function.
		 */		 
			
		if (state->cbs_flags & VNODE_READDIR_EXTENDED) {
			/* The last record has not been returned yet, so we 
			 * want to stop after packing the last item 
			 */
			if (state->cbs_hasprevdirentry) { 
				stop_after_pack = true;
			} else {
				state->cbs_eof = true;
				state->cbs_result = ENOENT;
				return (0);	/* stop */
			}				
		} else {
			state->cbs_eof = true;
			state->cbs_result = ENOENT;
			return (0);	/* stop */
		}
	}

	if (state->cbs_flags & VNODE_READDIR_EXTENDED) {
		entry = state->cbs_direntry;
		nameptr = (u_int8_t *)&entry->d_name[0];
		if (state->cbs_flags & VNODE_READDIR_NAMEMAX) {
			/*
			 * The NFS server sometimes needs to make filenames fit in
			 * NAME_MAX bytes (since its client may not be able to
			 * handle a longer name).  In that case, NFS will ask us
			 * to mangle the name to keep it short enough.
			 */
			maxnamelen = NAME_MAX + 1;
		} else {
			maxnamelen = sizeof(entry->d_name);
		}
	} else {
		nameptr = (u_int8_t *)&catent.d_name[0];
		maxnamelen = sizeof(catent.d_name);
	}

	if ((state->cbs_flags & VNODE_READDIR_EXTENDED) && stop_after_pack) {
		/* The last item returns a non-zero invalid cookie */
		cnid = INT_MAX;		
	} else {
		switch(crp->recordType) {
		case kHFSPlusFolderRecord:
			type = DT_DIR;
			cnid = crp->hfsPlusFolder.folderID;
			/* Hide our private system directories. */
			if (curID == kHFSRootFolderID) {
				if (cnid == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid ||
				    cnid == hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid) {
					hide = 1;
				}
			}
			break;
		case kHFSPlusFileRecord:
			itime = to_bsd_time(crp->hfsPlusFile.createDate);
			type = MODE_TO_DT(crp->hfsPlusFile.bsdInfo.fileMode);
			cnid = crp->hfsPlusFile.fileID;
			/*
			 * When a hardlink link is encountered save its link ref.
			 */
			if ((SWAP_BE32(crp->hfsPlusFile.userInfo.fdType) == kHardLinkFileType) &&
				(SWAP_BE32(crp->hfsPlusFile.userInfo.fdCreator) == kHFSPlusCreator) &&
				((itime == (time_t)hfsmp->hfs_itime) ||
				 (itime == (time_t)hfsmp->hfs_metadata_createdate))) {
				/* If link ref is inode's file id then use it directly. */
				if (crp->hfsPlusFile.flags & kHFSHasLinkChainMask) {
					cnid = crp->hfsPlusFile.hl_linkReference;
				} else {
					ilinkref = crp->hfsPlusFile.hl_linkReference;
				}
				is_link =1;
			} else if ((SWAP_BE32(crp->hfsPlusFile.userInfo.fdType) == kHFSAliasType) &&
				(SWAP_BE32(crp->hfsPlusFile.userInfo.fdCreator) == kHFSAliasCreator) &&
				(crp->hfsPlusFile.flags & kHFSHasLinkChainMask) &&
				(crp->hfsPlusFile.hl_linkReference >= kHFSFirstUserCatalogNodeID) &&
				((itime == (time_t)hfsmp->hfs_itime) ||
				 (itime == (time_t)hfsmp->hfs_metadata_createdate))) {
				/* A directory's link resolves to a directory. */
				type = DT_DIR;
				/* A directory's link ref is always inode's file id. */
				cnid = crp->hfsPlusFile.hl_linkReference;
				is_link = 1;
			}
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

		cnp = (const CatalogName*) &ckp->hfsPlus.nodeName;

		namelen = cnp->ustr.length;
		/*
		 * For MacRoman encoded names, assume that its ascii and
		 * convert it directly in an attempt to avoid the more
		 * expensive utf8_encodestr conversion.
		 */
		if ((namelen < maxnamelen) && (crp->hfsPlusFile.textEncoding == 0)) {
			int i;
			u_int16_t ch;
			const u_int16_t *chp;

			chp = &cnp->ustr.unicode[0];
			for (i = 0; i < (int)namelen; ++i) {
				ch = *chp++;
				if (ch > 0x007f || ch == 0x0000) {
					/* Perform expensive utf8_encodestr conversion */
					goto encodestr;
				}
				nameptr[i] = (ch == '/') ? ':' : (u_int8_t)ch;
			}
			nameptr[namelen] = '\0';
			result = 0;
		} else {
encodestr:
			result = utf8_encodestr(cnp->ustr.unicode, namelen * sizeof(UniChar),
						nameptr, &namelen, maxnamelen, ':', 0);
		}

		/* Check result returned from encoding the filename to utf8 */
		if (result == ENAMETOOLONG) {
			/* 
			 * If we were looking at a catalog record for a hardlink (not the inode),
			 * then we want to use its link ID as opposed to the inode ID for 
			 * a mangled name.  For all other cases, they are the same.  Note that
			 * due to the way directory hardlinks are implemented, the actual link
			 * is going to be counted as a file record, so we can catch both
			 * with is_link.
			 */
			cnid_t linkid = cnid;
			if (is_link) {
				linkid =  crp->hfsPlusFile.fileID;
			}

			result = ConvertUnicodeToUTF8Mangled(cnp->ustr.length * sizeof(UniChar),
							     cnp->ustr.unicode, maxnamelen,
							     (ByteCount*)&namelen, nameptr, linkid);		
			is_mangled = 1;
		}
	}

	if (state->cbs_flags & VNODE_READDIR_EXTENDED) {
		/*
		 * The index is 1 relative and includes "." and ".."
		 *
		 * Also stuff the cnid in the upper 32 bits of the cookie.
		 * The cookie is stored to the previous entry, which will
		 * be packed and copied this time
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
	if (ilinkref || state->cbs_previlinkref) {
		uiobase = uio_curriovbase(state->cbs_uio);
	}
	/* If this entry won't fit then we're done */
	if ((uiosize > (user_size_t)uio_resid(state->cbs_uio)) ||
	    (ilinkref != 0 && state->cbs_nlinks == state->cbs_maxlinks)) {
		return (0);	/* stop */
	}

	if (!(state->cbs_flags & VNODE_READDIR_EXTENDED) || state->cbs_hasprevdirentry) {
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
				state->cbs_desc->cd_namelen = 0;
			}
#if 0
			state->cbs_desc->cd_encoding = xxxx;
#endif
			if (!is_mangled) {
				state->cbs_desc->cd_namelen = namelen;
				bcopy(nameptr, state->cbs_namebuf, namelen + 1);
			} else {
				/* Store unmangled name for the directory hint else it will 
				 * restart readdir at the last location again 
				 */
				u_int8_t *new_nameptr;
				size_t bufsize;
				size_t tmp_namelen = 0;
			
				cnp = (const CatalogName *)&ckp->hfsPlus.nodeName;
				bufsize = 1 + utf8_encodelen(cnp->ustr.unicode,
				                             cnp->ustr.length * sizeof(UniChar),
				                             ':', 0);
				MALLOC(new_nameptr, u_int8_t *, bufsize, M_TEMP, M_WAITOK);
				result = utf8_encodestr(cnp->ustr.unicode,
				                        cnp->ustr.length * sizeof(UniChar),
				                        new_nameptr, &tmp_namelen, bufsize, ':', 0);
			
				state->cbs_desc->cd_namelen = tmp_namelen;
				bcopy(new_nameptr, state->cbs_namebuf, tmp_namelen + 1);
			
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

	/* Fill the direntry to be used the next time */
	if (state->cbs_flags & VNODE_READDIR_EXTENDED) {	
		if (stop_after_pack) {
			state->cbs_eof = true;
			return (0);	/* stop */
		}
		entry->d_type = type;
		entry->d_namlen = namelen;
		entry->d_reclen = EXT_DIRENT_LEN(namelen);
		if (hide) {
			/* File number = 0 means skip entry */
			entry->d_fileno = 0;  
		} else {
			entry->d_fileno = cnid;
		}
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

#if CONFIG_HFS_STD
/*
 * getdirentries callback for standard HFS (non HFS+) directories.
 */
static int
getdirentries_std_callback(const CatalogKey *ckp, const CatalogRecord *crp,
                           struct packdirentry_state *state)
{
	struct hfsmount *hfsmp;
	const CatalogName *cnp;
	cnid_t curID;
	OSErr result;
	struct dirent catent;
	cnid_t  cnid;
	u_int8_t type = DT_UNKNOWN;
	u_int8_t *nameptr;
	size_t namelen = 0;
	size_t maxnamelen;
	size_t uiosize = 0;
	caddr_t uioaddr;
	
	hfsmp = state->cbs_hfsmp;

	curID = ckp->hfs.parentID;

	/* We're done when parent directory changes */
	if (state->cbs_parentID != curID) {
		state->cbs_result = ENOENT;
		return (0);	/* stop */
	}

	nameptr = (u_int8_t *)&catent.d_name[0];
	maxnamelen = sizeof(catent.d_name);

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

	cnp = (const CatalogName*) ckp->hfs.nodeName;
	result = hfs_to_utf8(hfsmp, cnp->pstr, maxnamelen, (ByteCount *)&namelen, nameptr);
	/*
	 * When an HFS name cannot be encoded with the current
	 * volume encoding we use MacRoman as a fallback.
	 */
	if (result) {
		result = mac_roman_to_utf8(cnp->pstr, maxnamelen, (ByteCount *)&namelen, nameptr);
	}
	catent.d_type = type;
	catent.d_namlen = namelen;
	catent.d_reclen = uiosize = STD_DIRENT_LEN(namelen);
	catent.d_fileno = cnid;
	uioaddr = (caddr_t) &catent;

	/* If this entry won't fit then we're done */
	if (uiosize > (user_size_t)uio_resid(state->cbs_uio)) {
		return (0);	/* stop */
	}

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
			state->cbs_desc->cd_namelen = 0;
		}
		state->cbs_desc->cd_namelen = namelen;
		bcopy(nameptr, state->cbs_namebuf, namelen + 1);
	}

	/* Continue iteration if there's room */
	return (state->cbs_result == 0  && uio_resid(state->cbs_uio) >= SMALL_DIRENTRY_SIZE);
}
#endif

/*
 * Pack a uio buffer with directory entries from the catalog
 */
int
cat_getdirentries(struct hfsmount *hfsmp, u_int32_t entrycnt, directoryhint_t *dirhint,
				  uio_t uio, int flags, int * items, int * eofflag)
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
	int extended;
	
	extended = flags & VNODE_READDIR_EXTENDED;
	
	if (extended && (hfsmp->hfs_flags & HFS_STANDARD)) {
		return (ENOTSUP);
	}
	fcb = hfsmp->hfs_catalog_cp->c_datafork;

	/*
	 * Get a buffer for link info array, btree iterator and a direntry:
	 */
	maxlinks = MIN(entrycnt, (u_int32_t)(uio_resid(uio) / SMALL_DIRENTRY_SIZE));
	bufsize = MAXPATHLEN + (maxlinks * sizeof(linkinfo_t)) + sizeof(*iterator);
	if (extended) {
		bufsize += 2*sizeof(struct direntry);
	}
	MALLOC(buffer, void *, bufsize, M_TEMP, M_WAITOK);
	bzero(buffer, bufsize);

	state.cbs_flags = flags;
	state.cbs_hasprevdirentry = false;
	state.cbs_previlinkref = 0;
	state.cbs_nlinks = 0;
	state.cbs_maxlinks = maxlinks;
	state.cbs_linkinfo = (linkinfo_t *)((char *)buffer + MAXPATHLEN);
	/*
	 * We need to set cbs_eof to false regardless of whether or not the
	 * control flow is actually in the extended case, since we use this
	 * field to track whether or not we've returned EOF from the iterator function.
	 */
	state.cbs_eof = false;
	
	iterator = (BTreeIterator *) ((char *)state.cbs_linkinfo + (maxlinks * sizeof(linkinfo_t)));
	key = (CatalogKey *)&iterator->key;
	have_key = 0;
	index = dirhint->dh_index + 1;
	if (extended) {
		state.cbs_direntry = (struct direntry *)((char *)iterator + sizeof(BTreeIterator));
		state.cbs_prevdirentry = state.cbs_direntry + 1;
	}
	/*
	 * Attempt to build a key from cached filename
	 */
	if (dirhint->dh_desc.cd_namelen != 0) {
		if (buildkey(hfsmp, &dirhint->dh_desc, (HFSPlusCatalogKey *)key, 0) == 0) {
			iterator->hint.nodeNum = dirhint->dh_desc.cd_hint;
			have_key = 1;
		}
	}

	if (index == 0 && dirhint->dh_threadhint != 0) {
		/*
		 * Position the iterator at the directory's thread record.
		 * (i.e. just before the first entry)
		 */
		buildthreadkey(dirhint->dh_desc.cd_parentcnid, (hfsmp->hfs_flags & HFS_STANDARD), key);
		iterator->hint.nodeNum = dirhint->dh_threadhint;
		iterator->hint.index = 0;
		have_key = 1;
	}

	/*
	 * If the last entry wasn't cached then position the btree iterator
	 */
	if (!have_key) {
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
		if (index == 0) {
			dirhint->dh_threadhint = iterator->hint.nodeNum;
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
				if (result == ENOENT) {
					/*
					 * ENOENT means we've hit the EOF.
					 * suppress the error, and set the eof flag.
					 */
					result = 0;
					dirhint->dh_desc.cd_flags |= CD_EOF;
					*eofflag = 1;
				}
				goto cleanup;
			}
		}
	}

	state.cbs_index = index;
	state.cbs_hfsmp = hfsmp;
	state.cbs_uio = uio;
	state.cbs_desc = &dirhint->dh_desc;
	state.cbs_namebuf = (u_int8_t *)buffer;
	state.cbs_result = 0;
	state.cbs_parentID = dirhint->dh_desc.cd_parentcnid;

	/* Use a temporary buffer to hold intermediate descriptor names. */
	if (dirhint->dh_desc.cd_namelen > 0 && dirhint->dh_desc.cd_nameptr != NULL) {
		bcopy(dirhint->dh_desc.cd_nameptr, buffer, dirhint->dh_desc.cd_namelen+1);
		if (dirhint->dh_desc.cd_flags & CD_HASBUF) {
			dirhint->dh_desc.cd_flags &= ~CD_HASBUF;
			vfs_removename((const char *)dirhint->dh_desc.cd_nameptr);
		}
	}
	dirhint->dh_desc.cd_nameptr = (u_int8_t *)buffer;

	enum BTreeIterationOperations op;
	if (extended && index != 0 && have_key)
		op = kBTreeCurrentRecord;
	else
		op = kBTreeNextRecord;

	/*
	 * Process as many entries as possible starting at iterator->key.
	 */
	if ((hfsmp->hfs_flags & HFS_STANDARD) == 0) {
		/* HFS+ */
		result = BTIterateRecords(fcb, op, iterator,
	                          (IterateCallBackProcPtr)getdirentries_callback, &state);
	
		/* For extended calls, every call to getdirentries_callback() 
		 * transfers the previous directory entry found to the user 
		 * buffer.  Therefore when BTIterateRecords reaches the end of 
		 * Catalog BTree, call getdirentries_callback() again with 
		 * dummy values to copy the last directory entry stored in 
		 * packdirentry_state 
		 */
		if (extended && (result == fsBTRecordNotFoundErr)) {
			CatalogKey ckp;
			CatalogRecord crp;

			bzero(&ckp, sizeof(ckp));
			bzero(&crp, sizeof(crp));

			result = getdirentries_callback(&ckp, &crp, &state);
		}
	}
#if CONFIG_HFS_STD
	else {
		/* HFS (standard) */
		result = BTIterateRecords(fcb, op, iterator,
	                          (IterateCallBackProcPtr)getdirentries_std_callback, &state);
	}
#endif

	/* Note that state.cbs_index is still valid on errors */
	*items = state.cbs_index - index;
	index = state.cbs_index;

	/*
	 * Also note that cbs_eof is set in all cases if we ever hit EOF
	 * during the enumeration by the catalog callback.  Mark the directory's hint
	 * descriptor as having hit EOF.
	 */

	if (state.cbs_eof) {
		dirhint->dh_desc.cd_flags |= CD_EOF;
		*eofflag = 1;
	}
	
	/* Finish updating the catalog iterator. */
	dirhint->dh_desc.cd_hint = iterator->hint.nodeNum;
	dirhint->dh_desc.cd_flags |= CD_DECOMPOSED;
	dirhint->dh_index = index - 1;
	
	/* Fix up the name. */
	if (dirhint->dh_desc.cd_namelen > 0) {
		dirhint->dh_desc.cd_nameptr = (const u_int8_t *)vfs_addname((char *)buffer, dirhint->dh_desc.cd_namelen, 0, 0);
		dirhint->dh_desc.cd_flags |= CD_HASBUF;
	} else {
		dirhint->dh_desc.cd_nameptr = NULL;
		dirhint->dh_desc.cd_namelen = 0;
	}
	
	/*
	 * Post process any hard links to get the real file id.
	 */
	if (state.cbs_nlinks > 0) {
		ino_t fileid = 0;
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
				if (extended) {
					ino64_t fileid_64 = (ino64_t)fileid;
					(void) copyout(&fileid_64, address, sizeof(fileid_64));
				} else {
					(void) copyout(&fileid, address, sizeof(fileid));
				}
			} else /* system space */ {
				if (extended) {
					ino64_t fileid_64 = (ino64_t)fileid;
					bcopy(&fileid_64, (void*) CAST_DOWN(caddr_t, address), sizeof(fileid_64));
				} else {
					bcopy(&fileid, (void*) CAST_DOWN(caddr_t, address), sizeof(fileid));
				}
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
	cnid_t curID = 0;

	if ((state->hfsmp->hfs_flags & HFS_STANDARD) == 0) {
		curID = ckp->hfsPlus.parentID;
	}
#if CONFIG_HFS_STD
	else {
		curID = ckp->hfs.parentID;
	}
#endif

	/* Make sure parent directory didn't change */
	if (state->parentID != curID) {
		/*
		 * The parent ID is different from curID this means we've hit
		 * the EOF for the directory.
		 */
		state->error = ENOENT;
		return (0);  /* stop */
	}

	/* Count this entry */
	switch(crp->recordType) {
	case kHFSPlusFolderRecord:
	case kHFSPlusFileRecord:
#if CONFIG_HFS_STD
	case kHFSFolderRecord:
	case kHFSFileRecord:
#endif
		++state->count;
		break;
	default:
		printf("hfs: cat_findposition: invalid record type %d in dir %d\n",
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

		result = UnicodeBinaryCompare (str1, length1, str2, length2);
	}

	return result;
}


#if CONFIG_HFS_STD
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
#endif


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
	int std_hfs = (hfsmp->hfs_flags & HFS_STANDARD);
	int utf8_flags = UTF_ESCAPE_ILLEGAL;
	int result = 0;
	size_t unicodeBytes = 0;
	
	if (std_hfs == 0) {
		retry = 0;
	}

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

#if CONFIG_HFS_STD
	/*
	 * For HFS volumes convert to an HFS compatible key
	 *
	 * XXX need to save the encoding that succeeded
	 */
	if (std_hfs) {
		HFSCatalogKey hfskey;

		bzero(&hfskey, sizeof(hfskey));
		hfskey.keyLength = kHFSCatalogKeyMinimumLength;
		hfskey.parentID = key->parentID;
		hfskey.nodeName[0] = 0;
		if (key->nodeName.length > 0) {
			int res;
			if ((res = unicode_to_hfs(HFSTOVCB(hfsmp),
				key->nodeName.length * 2,
				key->nodeName.unicode,
				&hfskey.nodeName[0], retry)) != 0) {
				if (res != ENAMETOOLONG)
					res = EINVAL;

				return res;
			}
			hfskey.keyLength += hfskey.nodeName[0];
		}
		bcopy(&hfskey, key, sizeof(hfskey));
	}
#endif

	return (0);
 }


/*
 * Resolve hard link reference to obtain the inode record.
 */
int
cat_resolvelink(struct hfsmount *hfsmp, u_int32_t linkref, int isdirlink, struct HFSPlusCatalogFile *recp)
{
	FSBufferDescriptor btdata;
	struct BTreeIterator *iterator;
	struct cat_desc idesc;
	char inodename[32];
	cnid_t parentcnid;
	int result = 0;

	BDINIT(btdata, recp);

	if (isdirlink) {
		MAKE_DIRINODE_NAME(inodename, sizeof(inodename), (unsigned int)linkref);
		parentcnid = hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid;
	} else {
		MAKE_INODE_NAME(inodename, sizeof(inodename), (unsigned int)linkref);
		parentcnid = hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid;
	}

	/* Get space for iterator */	
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	/* Build a descriptor for private dir. */	
	idesc.cd_parentcnid = parentcnid;
	idesc.cd_nameptr = (const u_int8_t *)inodename;
	idesc.cd_namelen = strlen(inodename);
	idesc.cd_flags = 0;
	idesc.cd_hint = 0;
	idesc.cd_encoding = 0;
	(void) buildkey(hfsmp, &idesc, (HFSPlusCatalogKey *)&iterator->key, 0);

	result = BTSearchRecord(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), iterator,
				&btdata, NULL, NULL);

	if (result == 0) {
		/* Make sure there's a reference */
		if (recp->hl_linkCount == 0)
			recp->hl_linkCount = 2;
	} else {
		printf("hfs: cat_resolvelink: can't find inode=%s on vol=%s\n", inodename, hfsmp->vcbVN);
	}

	FREE(iterator, M_TEMP);

	return (result ? ENOENT : 0);
}

/*
 * Resolve hard link reference to obtain the inode number.
 */
static int
resolvelinkid(struct hfsmount *hfsmp, u_int32_t linkref, ino_t *ino)
{
	struct HFSPlusCatalogFile record;
	int error;

	/*
	 * Since we know resolvelinkid is only called from
	 * cat_getdirentries, we can assume that only file
	 * hardlinks need to be resolved (cat_getdirentries
	 * can resolve directory hardlinks in place).
	 */
	error = cat_resolvelink(hfsmp, linkref, 0, &record);
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
	u_int16_t	datasize;
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

#if CONFIG_HFS_STD
	case kHFSFileThreadRecord:
	case kHFSFolderThreadRecord:
		keyp = (CatalogKey *)((char *)&recp->hfsThread.reserved + 6);
		keyp->hfs.keyLength = kHFSCatalogKeyMinimumLength + keyp->hfs.nodeName[0];
		bcopy(keyp, key, keyp->hfs.keyLength + 1);
		break;
#endif

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
 *
 * The key's parent id is the only part of the key expected to be used by the caller.
 * The name portion of the key may not always be valid (ie in the case of a hard link).
 */
int
cat_getkeyplusattr(struct hfsmount *hfsmp, cnid_t cnid, CatalogKey * key, struct cat_attr *attrp)
{
	int result;

	result = getkey(hfsmp, cnid, key);
       
	if (result == 0) {
		result = cat_lookupbykey(hfsmp, key, 0, 0, 0, NULL, attrp, NULL, NULL);
	}
	/*
	 * Check for a raw file hardlink inode.
	 * Fix up the parent id in the key if necessary.
	 * Only hard links created by Mac OS X 10.5 or later can be resolved here.
	 */
	if ((result == 0) &&
	    (key->hfsPlus.parentID == hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid) &&
	    (attrp->ca_recflags & kHFSHasLinkChainMask)) {
		cnid_t nextlinkid = 0;
		cnid_t prevlinkid = 0;
		struct cat_desc linkdesc;

		/*
		 * Pick up the first link in the chain and get a descriptor for it.
		 * This allows blind bulk access checks to work for hardlinks.
		 */
		if ((cat_lookup_siblinglinks(hfsmp, cnid, &prevlinkid,  &nextlinkid) == 0) &&
		    (nextlinkid != 0)) {
			if (cat_findname(hfsmp, nextlinkid, &linkdesc) == 0) {
				key->hfsPlus.parentID = linkdesc.cd_parentcnid;
				cat_releasedesc(&linkdesc);
			}
		}	
	}
	return MacToVFSError(result);
}


/*
 * buildrecord - build a default catalog directory or file record
 */
static void
buildrecord(struct cat_attr *attrp, cnid_t cnid, int std_hfs, u_int32_t encoding,
            CatalogRecord *crp, u_int32_t *recordSize)
{
	int type = attrp->ca_mode & S_IFMT;
	u_int32_t createtime = to_hfs_time(attrp->ca_itime);

	if (std_hfs == 0) {
		struct HFSPlusBSDInfo * bsdp = NULL;

		if (type == S_IFDIR) {
			crp->recordType = kHFSPlusFolderRecord;
			crp->hfsPlusFolder.flags = attrp->ca_recflags;
			crp->hfsPlusFolder.valence = 0;
			crp->hfsPlusFolder.folderID = cnid;	
			crp->hfsPlusFolder.createDate = createtime;
			crp->hfsPlusFolder.contentModDate = createtime;
			crp->hfsPlusFolder.attributeModDate = createtime;
			crp->hfsPlusFolder.accessDate = createtime;
			crp->hfsPlusFolder.backupDate = 0;
			crp->hfsPlusFolder.textEncoding = encoding;
			crp->hfsPlusFolder.folderCount = 0;
			bcopy(attrp->ca_finderinfo, &crp->hfsPlusFolder.userInfo, 32);
			bsdp = &crp->hfsPlusFolder.bsdInfo;
			bsdp->special.linkCount = 1;
			*recordSize = sizeof(HFSPlusCatalogFolder);
		} else {
			crp->recordType = kHFSPlusFileRecord;
			crp->hfsPlusFile.flags = attrp->ca_recflags;
			crp->hfsPlusFile.reserved1 = 0;
			crp->hfsPlusFile.fileID = cnid;
			crp->hfsPlusFile.createDate = createtime;
			crp->hfsPlusFile.contentModDate = createtime;
			crp->hfsPlusFile.accessDate = createtime;
			crp->hfsPlusFile.attributeModDate = createtime;
			crp->hfsPlusFile.backupDate = 0;
			crp->hfsPlusFile.textEncoding = encoding;
			crp->hfsPlusFile.reserved2 = 0;
			bcopy(attrp->ca_finderinfo, &crp->hfsPlusFile.userInfo, 32);
			bsdp = &crp->hfsPlusFile.bsdInfo;
			/* BLK/CHR need to save the device info */
			if (type == S_IFBLK || type == S_IFCHR) {
				bsdp->special.rawDevice = attrp->ca_rdev;
			} else {
				bsdp->special.linkCount = 1;
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
#if CONFIG_HFS_STD
	else {
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
	}
#endif

}


/*
 * builddesc - build a cnode descriptor from an HFS+ key
 */
static int
builddesc(const HFSPlusCatalogKey *key, cnid_t cnid, u_int32_t hint, u_int32_t encoding,
	int isdir, struct cat_desc *descp)
{
	int result = 0;
	unsigned char * nameptr;
	size_t bufsize;
	size_t utf8len;
	unsigned char tmpbuff[128];

	/* guess a size... */
	bufsize = (3 * key->nodeName.length) + 1;
	if (bufsize >= sizeof(tmpbuff) - 1) {
	    MALLOC(nameptr, unsigned char *, bufsize, M_TEMP, M_WAITOK);
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
		MALLOC(nameptr, unsigned char *, bufsize, M_TEMP, M_WAITOK);

		result = utf8_encodestr(key->nodeName.unicode,
		                        key->nodeName.length * sizeof(UniChar),
		                        nameptr, (size_t *)&utf8len,
		                        bufsize, ':', 0);
	}
	descp->cd_parentcnid = key->parentID;
	descp->cd_nameptr = (const u_int8_t *)vfs_addname((char *)nameptr, utf8len, 0, 0);
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
		if (isDirectory) {
			attrp->ca_mode = S_IFDIR | (hfsmp->hfs_dir_mask & ACCESSPERMS);
		} else {
			attrp->ca_mode = S_IFREG | (hfsmp->hfs_file_mask & ACCESSPERMS);
		}
		attrp->ca_linkcount = 1;
		attrp->ca_rdev = 0;
	} else {
		attrp->ca_linkcount = 1;  /* may be overridden below */
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
		case S_IFIFO:
		case S_IFSOCK:
		case S_IFDIR:
		case S_IFREG:
			/* Pick up the hard link count */
			if (bsd->special.linkCount > 0)
				attrp->ca_linkcount = bsd->special.linkCount;
			break;
		}

		/*
		 *  Override the permissions as determined by the mount auguments
		 *  in ALMOST the same way unset permissions are treated but keep
		 *  track of whether or not the file or folder is hfs locked
		 *  by leaving the h_pflags field unchanged from what was unpacked
		 *  out of the catalog.
		 */
		/*
		 * This code was used to do UID translation with MNT_IGNORE_OWNERS
		 * (aka MNT_UNKNOWNPERMISSIONS) at the HFS layer.  It's largely done
		 * at the VFS layer, so there is no need to do it here now; this also
		 * allows VFS to let root see the real UIDs.
		 *
		 * if (((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS) {
		 * 	attrp->ca_uid = hfsmp->hfs_uid;
		 * 	attrp->ca_gid = hfsmp->hfs_gid;
		 * }
		 */
	}

	if (isDirectory) {
		if (!S_ISDIR(attrp->ca_mode)) {
			attrp->ca_mode &= ~S_IFMT;
			attrp->ca_mode |= S_IFDIR;
		}
		attrp->ca_entries = ((const HFSPlusCatalogFolder *)crp)->valence;
		attrp->ca_dircount = ((hfsmp->hfs_flags & HFS_FOLDERCOUNT) && (attrp->ca_recflags & kHFSHasFolderCountMask)) ?
					     ((const HFSPlusCatalogFolder *)crp)->folderCount : 0;
			
		/* Keep UF_HIDDEN bit in sync with Finder Info's invisible bit */
		if (((const HFSPlusCatalogFolder *)crp)->userInfo.frFlags & OSSwapHostToBigConstInt16(kFinderInvisibleMask))
			attrp->ca_flags |= UF_HIDDEN;
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
		/* Keep UF_HIDDEN bit in sync with Finder Info's invisible bit */
		if (crp->userInfo.fdFlags & OSSwapHostToBigConstInt16(kFinderInvisibleMask))
			attrp->ca_flags |= UF_HIDDEN;
		/* get total blocks (both forks) */
		attrp->ca_blocks = crp->dataFork.totalBlocks + crp->resourceFork.totalBlocks;

		/* On HFS+ the ThreadExists flag must always be set. */
		if ((hfsmp->hfs_flags & HFS_STANDARD) == 0)
			attrp->ca_recflags |= kHFSThreadExistsMask;

		/* Pick up the hardlink first link, if any. */
		attrp->ca_firstlink = (attrp->ca_recflags & kHFSHasLinkChainMask) ? crp->hl_firstLinkID : 0;
	}
	
	attrp->ca_fileid = crp->fileID;

	bcopy(&crp->userInfo, attrp->ca_finderinfo, 32);
}

#if CONFIG_HFS_STD
/*
 * promotekey - promote hfs key to hfs plus key
 *
 */
static void
promotekey(struct hfsmount *hfsmp, const HFSCatalogKey *hfskey,
           HFSPlusCatalogKey *keyp, u_int32_t *encoding)
{
	hfs_to_unicode_func_t hfs_get_unicode = hfsmp->hfs_get_unicode;
	u_int32_t uniCount;
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
	u_int32_t blocksize = HFSTOVCB(hfsmp)->blockSize;

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
 * promoteattr - promote standard hfs catalog attributes to hfs plus
 *
 */
static void
promoteattr(struct hfsmount *hfsmp, const CatalogRecord *dataPtr, struct HFSPlusCatalogFile *crp)
{
	u_int32_t blocksize = HFSTOVCB(hfsmp)->blockSize;

	if (dataPtr->recordType == kHFSFolderRecord) {
		const struct HFSCatalogFolder * folder;

		folder = (const struct HFSCatalogFolder *) dataPtr;
		crp->recordType       = kHFSPlusFolderRecord;
		crp->flags            = folder->flags;
		crp->fileID           = folder->folderID;
		crp->createDate       = LocalToUTC(folder->createDate);
		crp->contentModDate   = LocalToUTC(folder->modifyDate);
		crp->backupDate       = LocalToUTC(folder->backupDate);
		crp->reserved1        = folder->valence;
		crp->reserved2        = 0;
		bcopy(&folder->userInfo, &crp->userInfo, 32);
	} else /* file */ {
		const struct HFSCatalogFile * file;

		file = (const struct HFSCatalogFile *) dataPtr;
		crp->recordType       = kHFSPlusFileRecord;
		crp->flags            = file->flags;
		crp->fileID           = file->fileID;
		crp->createDate       = LocalToUTC(file->createDate);
		crp->contentModDate   = LocalToUTC(file->modifyDate);
		crp->backupDate       = LocalToUTC(file->backupDate);
		crp->reserved1        = 0;
		crp->reserved2        = 0;
		bcopy(&file->userInfo, &crp->userInfo, 16);
		bcopy(&file->finderInfo, &crp->finderInfo, 16);
		crp->dataFork.totalBlocks = file->dataPhysicalSize / blocksize;
		crp->resourceFork.totalBlocks = file->rsrcPhysicalSize / blocksize;
	}
	crp->textEncoding = 0;
	crp->attributeModDate = crp->contentModDate;
	crp->accessDate = crp->contentModDate;
	bzero(&crp->bsdInfo, sizeof(HFSPlusBSDInfo));
}
#endif

/*
 * Build a catalog node thread record from a catalog key
 * and return the size of the record.
 */
static int
buildthread(void *keyp, void *recp, int std_hfs, int directory)
{
	int size = 0;

	if (std_hfs == 0) {
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

		/* HFS Plus has variable sized thread records */
		size -= (sizeof(rec->nodeName.unicode) -
			  (rec->nodeName.length * sizeof(UniChar)));

	}
#if CONFIG_HFS_STD
	else {
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

	} 
#endif

	return (size);
}

/*
 * Build a catalog node thread key.
 */
static void
buildthreadkey(HFSCatalogNodeID parentID, int std_hfs, CatalogKey *key)
{
	if (std_hfs == 0) {
		key->hfsPlus.keyLength = kHFSPlusCatalogKeyMinimumLength;
		key->hfsPlus.parentID = parentID;
		key->hfsPlus.nodeName.length = 0;
	}
#if CONFIG_HFS_STD
	else {
		key->hfs.keyLength = kHFSCatalogKeyMinimumLength;
		key->hfs.reserved = 0;
		key->hfs.parentID = parentID;
		key->hfs.nodeName[0] = 0;
	}
#endif

}

/*
 * Extract the text encoding from a catalog node record.
 */
static u_int32_t 
getencoding(const CatalogRecord *crp)
{
	u_int32_t encoding;

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

#if CONFIG_HFS_STD
	case kHFSFolderRecord:
		cnid = crp->hfsFolder.folderID;
		break;
	case kHFSFileRecord:
		cnid = crp->hfsFile.fileID;
		break;
#endif

	case kHFSPlusFolderRecord:
		cnid = crp->hfsPlusFolder.folderID;
		break;
	case kHFSPlusFileRecord:
		cnid = crp->hfsPlusFile.fileID;
		break;
	default:
		printf("hfs: getcnid: unknown recordType=%d\n", crp->recordType);
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

#if CONFIG_HFS_STD
	case kHFSFileThreadRecord:
	case kHFSFolderThreadRecord:
		cnid = recp->hfsThread.parentID;
		break;
#endif

	case kHFSPlusFileThreadRecord:
	case kHFSPlusFolderThreadRecord:
		cnid = recp->hfsPlusThread.parentID;
		break;
	default:
		panic("hfs: getparentcnid: unknown recordType (crp @ %p)\n", recp);
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
	if (crp->recordType == kHFSPlusFolderRecord) {
		return 1;
	}
#if CONFIG_HFS_STD
	if (crp->recordType == kHFSFolderRecord) {
		return 1;
	}
#endif

	return 0;
}

/*
 * cat_lookup_dirlink - lookup a catalog record for directory hard link 
 * (not inode) using catalog record id.  Note that this function does 
 * NOT resolve directory hard link to its directory inode and return 
 * the link record.
 *
 * Note: The caller is responsible for releasing the output catalog 
 * descriptor (when supplied outdescp is non-null).
 */
int
cat_lookup_dirlink(struct hfsmount *hfsmp, cnid_t dirlink_id, 
		u_int8_t forktype, struct cat_desc *outdescp, 
		struct cat_attr *attrp, struct cat_fork *forkp)
{
	struct BTreeIterator *iterator = NULL;
	FSBufferDescriptor btdata;
	u_int16_t datasize;
	CatalogKey *keyp;
	CatalogRecord *recp = NULL;
	int error;

	/* No directory hard links on standard HFS */
	if (hfsmp->vcbSigWord == kHFSSigWord) {
		return ENOTSUP;
	}

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		return ENOMEM;
	}
	bzero(iterator, sizeof(*iterator));
	buildthreadkey(dirlink_id, 1, (CatalogKey *)&iterator->key);

	MALLOC(recp, CatalogRecord *, sizeof(CatalogRecord), M_TEMP, M_WAITOK);
	if (recp == NULL) {
		error = ENOMEM;
		goto out;
	}
	BDINIT(btdata, recp);

	error = BTSearchRecord(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), iterator,
				&btdata, &datasize, iterator);
	if (error) {
		goto out;
	}
	/* Directory hard links are catalog file record */
	if (recp->recordType != kHFSPlusFileThreadRecord) {
		error = ENOENT;
		goto out;
	}

	keyp = (CatalogKey *)&recp->hfsPlusThread.reserved;
	keyp->hfsPlus.keyLength = kHFSPlusCatalogKeyMinimumLength +
				  (keyp->hfsPlus.nodeName.length * 2);
	if (forktype == kHFSResourceForkType) {
		/* Lookup resource fork for directory hard link */
		error = cat_lookupbykey(hfsmp, keyp, HFS_LOOKUP_HARDLINK, 0, true, outdescp, attrp, forkp, NULL);
	} else {
		/* Lookup data fork, if any, for directory hard link */
		error = cat_lookupbykey(hfsmp, keyp, HFS_LOOKUP_HARDLINK, 0, false, outdescp, attrp, forkp, NULL);
	}
	if (error) {
		printf ("hfs: cat_lookup_dirlink(): Error looking up file record for id=%u (error=%d)\n", dirlink_id, error);
		hfs_mark_inconsistent(hfsmp, HFS_INCONSISTENCY_DETECTED);
		goto out;
	}
	/* Just for sanity, make sure that id in catalog record and thread record match */
	if ((outdescp != NULL) && (dirlink_id != outdescp->cd_cnid)) {
		printf ("hfs: cat_lookup_dirlink(): Requested cnid=%u != found_cnid=%u\n", dirlink_id, outdescp->cd_cnid);
		hfs_mark_inconsistent(hfsmp, HFS_INCONSISTENCY_DETECTED);
		error = ENOENT;
	}

out:
	if (recp) {
		FREE(recp, M_TEMP);
	}
	FREE(iterator, M_TEMP);

	return MacToVFSError(error);
}

/*
 * cnode_update_dirlink - update the catalog node for directory hard link 
 * described by descp using the data from attrp and forkp.
 */
int
cat_update_dirlink(struct hfsmount *hfsmp, u_int8_t forktype, 
		struct cat_desc *descp, struct cat_attr *attrp, struct cat_fork *forkp)
{
	if (forktype == kHFSResourceForkType) {
		return cat_update_internal(hfsmp, true, descp, attrp, NULL, forkp);
	} else {
		return cat_update_internal(hfsmp, true, descp, attrp, forkp, NULL);
	} 
}

void hfs_fork_copy(struct cat_fork *dst, const struct cat_fork *src,
				   HFSPlusExtentDescriptor *extents)
{
	/* Copy everything but the extents into the dest fork */
	memcpy(dst, src, offsetof(struct cat_fork, cf_extents));
	/* Then copy the supplied extents into the fork */
	memcpy(dst->cf_extents, extents, sizeof(HFSPlusExtentRecord));
}
