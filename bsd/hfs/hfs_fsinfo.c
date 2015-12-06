/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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

#include <sys/cprotect.h>
#include <sys/xattr.h>
#include <sys/utfconv.h>
#include <libkern/OSByteOrder.h>
#include <kern/kalloc.h>
#include <sys/stat.h>

#include "hfs.h"
#include "hfs_fsctl.h"
#include "hfs_endian.h"
#include "hfscommon/headers/BTreesInternal.h"
#include "hfscommon/headers/BTreesPrivate.h"
#include "hfscommon/headers/FileMgrInternal.h"

#include <hfs/hfs_cprotect.h>


union HFSPlusRecord {
	HFSPlusCatalogFolder folder_record;
	HFSPlusCatalogFile file_record;
	HFSPlusCatalogThread thread_record;
	HFSPlusExtentRecord extent_record;
	HFSPlusAttrRecord attr_record;
}; 
typedef union HFSPlusRecord HFSPlusRecord;

union HFSPlusKey {
	HFSPlusExtentKey extent_key;
	HFSPlusAttrKey attr_key;
};
typedef union HFSPlusKey HFSPlusKey;

typedef enum traverse_btree_flag {
	
	//If set, extents btree will also be traversed along with catalog btree, so grab correct locks upfront
	TRAVERSE_BTREE_EXTENTS = 1,

	// Getting content-protection attributes, allocate enough space to accomodate the records.
	TRAVERSE_BTREE_XATTR_CPROTECT = 2,
	
} traverse_btree_flag_t;



static errno_t hfs_fsinfo_metadata_blocks(struct hfsmount *hfsmp, struct hfs_fsinfo_metadata *fsinfo);
static errno_t hfs_fsinfo_metadata_extents(struct hfsmount *hfsmp, struct hfs_fsinfo_metadata *fsinfo);
static errno_t hfs_fsinfo_metadata_percentfree(struct hfsmount *hfsmp, struct hfs_fsinfo_metadata *fsinfo);
static errno_t fsinfo_file_extent_count_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);
static errno_t fsinfo_file_extent_size_catalog_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);
static errno_t fsinfo_file_extent_size_overflow_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);
static errno_t fsinfo_file_size_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);
static errno_t fsinfo_dir_valence_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);
static errno_t fsinfo_name_size_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);
static errno_t fsinfo_xattr_size_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);
static errno_t traverse_btree(struct hfsmount *hfsmp, uint32_t btree_fileID, traverse_btree_flag_t flags, void *fsinfo,
		int (*callback)(struct hfsmount *, HFSPlusKey *, HFSPlusRecord *, void *));
static errno_t hfs_fsinfo_free_extents(struct hfsmount *hfsmp, struct hfs_fsinfo_data *fsinfo);
static void fsinfo_free_extents_callback(void *data, off_t free_extent_size);
#if CONFIG_PROTECT
static errno_t fsinfo_cprotect_count_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);
#endif
static errno_t fsinfo_symlink_size_callback(struct hfsmount *hfsmp, HFSPlusKey *key, HFSPlusRecord *record, void *data);

/* 
 * Entry function for all the fsinfo requests from hfs_vnop_ioctl() 
 * Depending on the type of request, this function will call the 
 * appropriate sub-function and return success or failure back to 
 * the caller.
 */
__private_extern__
errno_t hfs_get_fsinfo(struct hfsmount *hfsmp, void *a_data)
{
	int error = 0;
	hfs_fsinfo *fsinfo_union;
	uint32_t request_type;
	uint32_t header_len = sizeof(hfs_fsinfo_header_t);

	fsinfo_union = (hfs_fsinfo *)a_data;
	request_type = fsinfo_union->header.request_type;

	// Zero out output fields to fsinfo_union, keep the user input fields intact.
	bzero((char *)fsinfo_union + header_len, sizeof(hfs_fsinfo) - header_len);

	switch (request_type) {
		case HFS_FSINFO_METADATA_BLOCKS_INFO:
			error = hfs_fsinfo_metadata_blocks(hfsmp, &(fsinfo_union->metadata));
			break;

		case HFS_FSINFO_METADATA_EXTENTS:
			error = hfs_fsinfo_metadata_extents(hfsmp, &(fsinfo_union->metadata));
			break;

		case HFS_FSINFO_METADATA_PERCENTFREE:
			error = hfs_fsinfo_metadata_percentfree(hfsmp, &(fsinfo_union->metadata));
			break;

		case HFS_FSINFO_FILE_EXTENT_COUNT:
			/* Traverse catalog btree and invoke callback for all records */
			error = traverse_btree(hfsmp, kHFSCatalogFileID, TRAVERSE_BTREE_EXTENTS, &(fsinfo_union->data), fsinfo_file_extent_count_callback);
			break;

		case HFS_FSINFO_FILE_EXTENT_SIZE:
			/* Traverse the catalog btree first */
			error = traverse_btree(hfsmp, kHFSCatalogFileID, 0, &(fsinfo_union->data), &fsinfo_file_extent_size_catalog_callback);
			if (error) {
				break;
			}
			/* Traverse the overflow extents btree now */
			error = traverse_btree(hfsmp, kHFSExtentsFileID, 0, &(fsinfo_union->data), &fsinfo_file_extent_size_overflow_callback);
			break;

		case HFS_FSINFO_FILE_SIZE:
			/* Traverse catalog btree and invoke callback for all records */
			error = traverse_btree(hfsmp, kHFSCatalogFileID, 0, &(fsinfo_union->data), &fsinfo_file_size_callback);
			break;

		case HFS_FSINFO_DIR_VALENCE:
			/* Traverse catalog btree and invoke callback for all records */
			error = traverse_btree(hfsmp, kHFSCatalogFileID, 0, &(fsinfo_union->data), &fsinfo_dir_valence_callback);
			break;

		case HFS_FSINFO_NAME_SIZE:
			/* Traverse catalog btree and invoke callback for all records */
			error = traverse_btree(hfsmp, kHFSCatalogFileID, 0, &(fsinfo_union->name), &fsinfo_name_size_callback);
			break;

		case HFS_FSINFO_XATTR_SIZE:
			/* Traverse attribute btree and invoke callback for all records */
			error = traverse_btree(hfsmp, kHFSAttributesFileID, 0, &(fsinfo_union->data), &fsinfo_xattr_size_callback);
			break;

		case HFS_FSINFO_FREE_EXTENTS:
			error = hfs_fsinfo_free_extents(hfsmp, &(fsinfo_union->data));
			break;

		case HFS_FSINFO_SYMLINK_SIZE:
			/* Traverse catalog btree and invoke callback for all records */
			error = traverse_btree(hfsmp, kHFSCatalogFileID, 0, &(fsinfo_union->data), &fsinfo_symlink_size_callback);
			break;

#if CONFIG_PROTECT
		case HFS_FSINFO_FILE_CPROTECT_COUNT:
			/* Traverse attribute btree and invoke callback for all records */
			error = traverse_btree(hfsmp, kHFSAttributesFileID, TRAVERSE_BTREE_XATTR_CPROTECT, &(fsinfo_union->cprotect), &fsinfo_cprotect_count_callback);
			break;
#endif

		default:
			return ENOTSUP;
	};

	return error;
}

/* 
 * This function provides information about total number of allocation blocks 
 * for each individual metadata file.
 */
static errno_t
hfs_fsinfo_metadata_blocks(struct hfsmount *hfsmp, struct hfs_fsinfo_metadata *fsinfo)
{
	int lockflags = 0;
	int ret_lockflags = 0;

	/* 
	 * Getting number of allocation blocks for all metadata files 
	 * should be a relatively quick operation, so we grab locks for all
	 * the btrees at the same time
	 */
	lockflags = SFL_CATALOG | SFL_EXTENTS | SFL_BITMAP | SFL_ATTRIBUTE;
	ret_lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_SHARED_LOCK);

	/* Get information about all the btrees */
	fsinfo->extents    = hfsmp->hfs_extents_cp->c_datafork->ff_blocks;
	fsinfo->catalog    = hfsmp->hfs_catalog_cp->c_datafork->ff_blocks;
	fsinfo->allocation = hfsmp->hfs_allocation_cp->c_datafork->ff_blocks;
	if (hfsmp->hfs_attribute_cp)
		fsinfo->attribute  = hfsmp->hfs_attribute_cp->c_datafork->ff_blocks;
	else
		fsinfo->attribute = 0;

	/* Done with btrees, give up the locks */
	hfs_systemfile_unlock(hfsmp, ret_lockflags);

	/* Get information about journal file */
	fsinfo->journal = howmany(hfsmp->jnl_size, hfsmp->blockSize);

	return 0;
}

/* 
 * Helper function to count the number of valid extents in a file fork structure
 */
static uint32_t
hfs_count_extents_fp(struct filefork *ff)
{
	int i;
	uint32_t count = 0;
	for (i = 0; i < kHFSPlusExtentDensity; i++) {
		if (ff->ff_data.cf_extents[i].blockCount == 0) {
			break;
		}
		count++;
	}
	return count;
}


/* 
 * This is a helper function that counts the total number of valid 
 * extents in all the overflow extent records for given fileID 
 * in overflow extents btree
 */
static errno_t
hfs_count_overflow_extents(struct hfsmount *hfsmp, uint32_t fileID, uint32_t *num_extents)
{
	int error;
	FCB *fcb;
	struct BTreeIterator *iterator = NULL;
	FSBufferDescriptor btdata;
	HFSPlusExtentKey *extentKey;
	HFSPlusExtentRecord extentData;
	uint32_t extent_count = 0;
	int i;

	fcb = VTOF(hfsmp->hfs_extents_vp);
	MALLOC(iterator, struct BTreeIterator *, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK | M_ZERO);
	
	extentKey = (HFSPlusExtentKey *) &iterator->key;	
	extentKey->keyLength = kHFSPlusExtentKeyMaximumLength;
	extentKey->forkType = kHFSDataForkType;
	extentKey->fileID = fileID;
	extentKey->startBlock = 0;

	btdata.bufferAddress = &extentData;
	btdata.itemSize = sizeof(HFSPlusExtentRecord);
	btdata.itemCount = 1;

	/* Search for overflow extent record */
	error = BTSearchRecord(fcb, iterator, &btdata, NULL, iterator);
	
	/*
	 * We used startBlock of zero, so we will not find any records and errors
	 * are expected.  It will also position the iterator just before the first 
	 * overflow extent record for given fileID (if any). 
	 */
	if (error && error != fsBTRecordNotFoundErr && error != fsBTEndOfIterationErr)
			goto out;
	error = 0;

	for (;;) {
		
		if (msleep(NULL, NULL, PINOD | PCATCH,
				   "hfs_fsinfo", NULL) == EINTR) {
			error = EINTR;
			break;
		}
		
		error = BTIterateRecord(fcb, kBTreeNextRecord, iterator, &btdata, NULL);
		if (error != 0) {
			/* These are expected errors, so mask them */
			if (error == fsBTRecordNotFoundErr || error == fsBTEndOfIterationErr) {
				error = 0;
			}
			break;
		}

		/* If we encounter different fileID, stop the iteration */
		if (extentKey->fileID != fileID) {
			break;
		}
		
		if (extentKey->forkType != kHFSDataForkType)
			break;
		
		/* This is our record of interest; only count the datafork extents. */
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			if (extentData[i].blockCount == 0) {
				break;
			}
			extent_count++;
		}
	}

out:
	FREE(iterator, M_TEMP);

	if (error == 0) {
		*num_extents = extent_count;
	}
	return MacToVFSError(error);
}

/*
 * This function provides information about total number of extents (including 
 * extents from overflow extents btree, if any) for each individual metadata 
 * file.
 */
static errno_t
hfs_fsinfo_metadata_extents(struct hfsmount *hfsmp, struct hfs_fsinfo_metadata *fsinfo)
{
	int error = 0;
	int lockflags = 0;
	int ret_lockflags = 0;
	uint32_t overflow_count;

	/*
	 * Counting the number of extents for all metadata files should
	 * be a relatively quick operation, so we grab locks for all the
	 * btrees at the same time
	 */
	lockflags = SFL_CATALOG | SFL_EXTENTS | SFL_BITMAP | SFL_ATTRIBUTE;
	ret_lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_SHARED_LOCK);

	/* Get number of extents for extents overflow btree */
	fsinfo->extents = hfs_count_extents_fp(hfsmp->hfs_extents_cp->c_datafork);

	/* Get number of extents for catalog btree */
	fsinfo->catalog = hfs_count_extents_fp(hfsmp->hfs_catalog_cp->c_datafork);
	if (fsinfo->catalog >= kHFSPlusExtentDensity) {
		error = hfs_count_overflow_extents(hfsmp, kHFSCatalogFileID, &overflow_count);
		if (error) {
			goto out;
		}
		fsinfo->catalog += overflow_count;
	}

	/* Get number of extents for allocation file */
	fsinfo->allocation = hfs_count_extents_fp(hfsmp->hfs_allocation_cp->c_datafork);
	if (fsinfo->allocation >= kHFSPlusExtentDensity) {
		error = hfs_count_overflow_extents(hfsmp, kHFSAllocationFileID, &overflow_count);
		if (error) {
			goto out;
		}
		fsinfo->allocation += overflow_count;
	}

	/*
	 * Get number of extents for attribute btree.
	 *	hfs_attribute_cp might be NULL.
	 */
	if (hfsmp->hfs_attribute_cp) {
		fsinfo->attribute = hfs_count_extents_fp(hfsmp->hfs_attribute_cp->c_datafork);
		if (fsinfo->attribute >= kHFSPlusExtentDensity) {
			error = hfs_count_overflow_extents(hfsmp, kHFSAttributesFileID, &overflow_count);
			if (error) {
				goto out;
			}
			fsinfo->attribute += overflow_count;
		}
	}
	/* Journal always has one extent */
	fsinfo->journal = 1;
out:
	hfs_systemfile_unlock(hfsmp, ret_lockflags);
	return error;
}

/* 
 * Helper function to calculate percentage i.e. X is what percent of Y?
 */
static inline uint32_t 
hfs_percent(uint32_t X, uint32_t Y)
{
	return (X * 100ll) / Y;
}

/*
 * This function provides percentage of free nodes vs total nodes for each 
 * individual metadata btrees, i.e. for catalog, overflow extents and 
 * attributes btree.  This information is not applicable for allocation 
 * file and journal file.
 */
static errno_t
hfs_fsinfo_metadata_percentfree(struct hfsmount *hfsmp, struct hfs_fsinfo_metadata *fsinfo)
{
	int lockflags = 0;
	int ret_lockflags = 0;
	BTreeControlBlockPtr btreePtr;
	uint32_t free_nodes, total_nodes;

	/*
	 * Getting total and used nodes for all metadata btrees should 
	 * be a relatively quick operation, so we grab locks for all the
	 * btrees at the same time
	 */
	lockflags = SFL_CATALOG | SFL_EXTENTS | SFL_BITMAP | SFL_ATTRIBUTE;
	ret_lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_SHARED_LOCK);
	
	/* Overflow extents btree */
	btreePtr = VTOF(hfsmp->hfs_extents_vp)->fcbBTCBPtr;
	total_nodes = btreePtr->totalNodes;
	free_nodes = btreePtr->freeNodes;
	fsinfo->extents = hfs_percent(free_nodes, total_nodes);

	/* Catalog btree */
	btreePtr = VTOF(hfsmp->hfs_catalog_vp)->fcbBTCBPtr;
	total_nodes = btreePtr->totalNodes;
	free_nodes = btreePtr->freeNodes;
	fsinfo->catalog = hfs_percent(free_nodes, total_nodes);

	/* Attributes btree */
	if (hfsmp->hfs_attribute_vp) {
		btreePtr = VTOF(hfsmp->hfs_attribute_vp)->fcbBTCBPtr;
		total_nodes = btreePtr->totalNodes;
		free_nodes = btreePtr->freeNodes;
		fsinfo->attribute = hfs_percent(free_nodes, total_nodes);
	}

	hfs_systemfile_unlock(hfsmp, ret_lockflags);
	return 0;
}

/* 
 * Helper function to calculate log base 2 for given number 
 */
static inline int 
hfs_log2(uint64_t entry) 
{
	return (63 - __builtin_clzll(entry|1));
}

/*
 * Helper function to account for input entry into the data 
 * array based on its log base 2 value
 */
__private_extern__
void hfs_fsinfo_data_add(struct hfs_fsinfo_data *fsinfo, uint64_t entry)
{
	/* 
	 * From hfs_fsctl.h - 
	 *
	 * hfs_fsinfo_data is generic data structure to aggregate information like sizes 
	 * or counts in buckets of power of 2.  Each bucket represents a range of values 
	 * that is determined based on its index in the array.  Specifically, buckets[i] 
	 * represents values that are greater than or equal to 2^(i-1) and less than 2^i, 
	 * except the last bucket which represents range greater than or equal to 2^(i-1)
	 *
	 * The current maximum number of buckets is 41, so we can represent range from
	 * 0 up to 1TB in increments of power of 2, and then a catch-all bucket of 
	 * anything that is greater than or equal to 1TB.
	 *
	 * For example, 
	 * bucket[0]  -> greater than or equal to 0 and less than 1
	 * bucket[1]  -> greater than or equal to 1 and less than 2
	 * bucket[10] -> greater than or equal to 2^(10-1) = 512 and less than 2^10 = 1024
	 * bucket[20] -> greater than or equal to 2^(20-1) = 512KB and less than 2^20 = 1MB
	 * bucket[41] -> greater than or equal to 2^(41-1) = 1TB
	 */
	uint32_t bucket;

	if (entry) {
		/* 
		 * Calculate log base 2 value for the entry.
		 * Account for this value in the appropriate bucket.
		 * The last bucket is a catch-all bucket of
		 * anything that is greater than or equal to 1TB
		 */
		bucket = MIN(hfs_log2(entry) + 1, HFS_FSINFO_DATA_MAX_BUCKETS-1);
		++fsinfo->bucket[bucket];
	} else {
		/* Entry is zero, so account it in 0th offset */
		fsinfo->bucket[0]++;
	}
}

/* 
 * Function to traverse all the records of a btree and then call caller-provided 
 * callback function for every record found.  The type of btree is chosen based 
 * on the fileID provided by the caller.  This fuction grabs the correct locks 
 * depending on the type of btree it will be traversing and flags provided 
 * by the caller.
 *
 * Note: It might drop and reacquire the locks during execution.
 */
static errno_t
traverse_btree(struct hfsmount *hfsmp, uint32_t btree_fileID, traverse_btree_flag_t flags,
			   void *fsinfo, int (*callback)(struct hfsmount *, HFSPlusKey *, HFSPlusRecord *, void *))
{
	int error = 0;
	int lockflags = 0;
	int ret_lockflags = 0;
	FCB *fcb;
	struct BTreeIterator *iterator = NULL;
	struct FSBufferDescriptor btdata;
	int btree_operation;
	HFSPlusRecord record;
	HFSPlusKey *key;
	uint64_t start, timeout_abs;

	switch(btree_fileID) {
		case kHFSExtentsFileID: 
			fcb = VTOF(hfsmp->hfs_extents_vp);
			lockflags = SFL_EXTENTS;
			break;
		case kHFSCatalogFileID:
			fcb = VTOF(hfsmp->hfs_catalog_vp);
			lockflags = SFL_CATALOG;
			break;
		case kHFSAttributesFileID:
			// Attributes file doesn’t exist, There are no records to iterate.
			if (hfsmp->hfs_attribute_vp == NULL)
				return error;
			fcb = VTOF(hfsmp->hfs_attribute_vp);
			lockflags = SFL_ATTRIBUTE;
			break;

		default:
			return EINVAL;
	}

	MALLOC(iterator, struct BTreeIterator *, sizeof(struct BTreeIterator), M_TEMP, M_WAITOK | M_ZERO);

	/* The key is initialized to zero because we are traversing entire btree */
	key = (HFSPlusKey *)&iterator->key;

	if (flags & TRAVERSE_BTREE_EXTENTS) {
		lockflags |= SFL_EXTENTS;
	}

	btdata.bufferAddress = &record;
	btdata.itemSize = sizeof(HFSPlusRecord);
	btdata.itemCount = 1;

	/* Lock btree for duration of traversal */
	ret_lockflags = hfs_systemfile_lock(hfsmp, lockflags, HFS_SHARED_LOCK);
	btree_operation = kBTreeFirstRecord;

	nanoseconds_to_absolutetime(HFS_FSINFO_MAX_LOCKHELD_TIME, &timeout_abs);
	start = mach_absolute_time();

	while (1) {

		if (msleep(NULL, NULL, PINOD | PCATCH,
				   "hfs_fsinfo", NULL) == EINTR) {
			error = EINTR;
			break;
		}

		error = BTIterateRecord(fcb, btree_operation, iterator, &btdata, NULL);
		if (error != 0) {
			if (error == fsBTRecordNotFoundErr || error == fsBTEndOfIterationErr) {
				error = 0;
			}
			break;
		}
		/* Lookup next btree record on next call to BTIterateRecord() */
		btree_operation = kBTreeNextRecord;

		/* Call our callback function and stop iteration if there are any errors */
		error = callback(hfsmp, key, &record, fsinfo);
		if (error) {
			break;
		}

		/* let someone else use the tree after we've processed over HFS_FSINFO_MAX_LOCKHELD_TIME */
		if ((mach_absolute_time() - start) >= timeout_abs) {

			/* release b-tree locks and let someone else get the lock */
			hfs_systemfile_unlock (hfsmp, ret_lockflags);

			/* add tsleep here to force context switch and fairness */
			tsleep((caddr_t)hfsmp, PRIBIO, "hfs_fsinfo", 1);

			/*
			 * re-acquire the locks in the same way that we wanted them originally.
			 * note: it is subtle but worth pointing out that in between the time that we
			 * released and now want to re-acquire these locks that the b-trees may have shifted
			 * slightly but significantly. For example, the catalog or other b-tree could have grown
			 * past 8 extents and now requires the extents lock to be held in order to be safely
			 * manipulated. We can't be sure of the state of the b-tree from where we last left off.
			 */

			ret_lockflags = hfs_systemfile_lock (hfsmp, lockflags, HFS_SHARED_LOCK);

			/*
			 * It's highly likely that the search key we stashed away before dropping lock
			 * no longer points to an existing item.  Iterator's IterateRecord is able to
			 * re-position itself and process the next record correctly.  With lock dropped,
			 * there might be records missed for statistic gathering, which is ok. The
			 * point is to get aggregate values.
			 */

			start = mach_absolute_time();

			/* loop back around and get another record */
		}
	}

	hfs_systemfile_unlock(hfsmp, ret_lockflags);
	FREE (iterator, M_TEMP);
	return MacToVFSError(error);
}

/* 
 * Callback function to get distribution of number of extents 
 * for all user files in given file system.  Note that this only 
 * accounts for data fork, no resource fork. 
 */
static errno_t
fsinfo_file_extent_count_callback(struct hfsmount *hfsmp, 
		__unused HFSPlusKey *key, HFSPlusRecord *record, void *data)
{
	int i;
	int error = 0;
	uint32_t num_extents = 0;
	uint32_t num_overflow = 0;
	uint32_t blockCount;

	if (record->file_record.recordType == kHFSPlusFileRecord) {
		/* Count total number of extents for this file */
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			blockCount = record->file_record.dataFork.extents[i].blockCount;
			if (blockCount == 0) {
				break;
			}
			num_extents++;
		}
		/* This file has overflow extent records, so search overflow btree */
		if (num_extents >= kHFSPlusExtentDensity) {
			/* The caller also hold extents overflow btree lock */
			error = hfs_count_overflow_extents(hfsmp, record->file_record.fileID, &num_overflow);
			if (error) {
				goto out;
			}
			num_extents += num_overflow;
		}
		hfs_fsinfo_data_add(data, num_extents);
	}
out:
	return error;
}

/* 
 * Callback function to get distribution of individual extent sizes
 * (in bytes) for all user files in given file system from catalog 
 * btree only.  Note that this only accounts for data fork, no resource 
 * fork. 
 */
static errno_t fsinfo_file_extent_size_catalog_callback(__unused struct hfsmount *hfsmp,
		__unused HFSPlusKey *key, HFSPlusRecord *record, void *data)
{
	int i;
	uint32_t blockCount;
	uint64_t extent_size;

	if (record->file_record.recordType == kHFSPlusFileRecord) {
		/* Traverse through all valid extents */
		for (i = 0; i < kHFSPlusExtentDensity; i++) {
			blockCount = record->file_record.dataFork.extents[i].blockCount;
			if (blockCount == 0) {
				break;
			}
			extent_size = hfs_blk_to_bytes(blockCount, hfsmp->blockSize);
			hfs_fsinfo_data_add(data, extent_size);
		}
	}
	return 0;
}

/* 
 * Callback function to get distribution of individual extent sizes
 * (in bytes) for all user files in given file system from overflow 
 * extents btree only.  Note that this only accounts for data fork, 
 * no resource fork. 
 */
static errno_t fsinfo_file_extent_size_overflow_callback(__unused struct hfsmount *hfsmp,
		HFSPlusKey *key, HFSPlusRecord *record, void *data)
{
	int i;
	uint32_t blockCount;
	uint64_t extent_size;

	if (key->extent_key.fileID >= kHFSFirstUserCatalogNodeID) {
		// Only count the data fork extents.
		if (key->extent_key.forkType == kHFSDataForkType) {
			for (i = 0; i < kHFSPlusExtentDensity; i++) {
				blockCount = record->extent_record[i].blockCount;
				if (blockCount == 0) {
					break;
				}
				extent_size = hfs_blk_to_bytes(blockCount, hfsmp->blockSize);
				hfs_fsinfo_data_add(data, extent_size);
			}
		}
	}
	return 0;
}

/* 
 * Callback function to get distribution of file sizes (in bytes) 
 * for all user files in given file system.  Note that this only 
 * accounts for data fork, no resource fork. 
 */
static errno_t fsinfo_file_size_callback(__unused struct hfsmount *hfsmp,
		__unused HFSPlusKey *key, HFSPlusRecord *record, void *data)
{
	if (record->file_record.recordType == kHFSPlusFileRecord) {
		/* Record of interest, account for the size in the bucket */
		hfs_fsinfo_data_add(data, record->file_record.dataFork.logicalSize);
	}
	return 0;
}

/*
 * Callback function to get distribution of directory valence 
 * for all directories in the given file system.
 */
static errno_t fsinfo_dir_valence_callback(__unused struct hfsmount *hfsmp,
		__unused HFSPlusKey *key, HFSPlusRecord *record, void *data)
{
	if (record->folder_record.recordType == kHFSPlusFolderRecord) {
		hfs_fsinfo_data_add(data, record->folder_record.valence);
	}
	return 0;
}

/* 
 * Callback function to get distribution of number of unicode 
 * characters in name for all files and directories for a given 
 * file system.
 */
static errno_t fsinfo_name_size_callback(__unused struct hfsmount *hfsmp,
		__unused HFSPlusKey *key, HFSPlusRecord *record, void *data)
{
	struct hfs_fsinfo_name *fsinfo = (struct hfs_fsinfo_name *)data;
	uint32_t length;

	if ((record->folder_record.recordType == kHFSPlusFolderThreadRecord) ||
	    (record->folder_record.recordType == kHFSPlusFileThreadRecord)) {
		length = record->thread_record.nodeName.length;
		/* Make sure that the nodeName is bounded, otherwise return error */
		if (length > kHFSPlusMaxFileNameChars) {
			return EIO;
		}
		
		// sanity check for a name length of zero, which isn't valid on disk.
		if (length == 0)
			return EIO;
		
		/* Round it down to nearest multiple of 5 to match our buckets granularity */
		length = (length - 1)/ 5;
		/* Account this value into our bucket */
		fsinfo->bucket[length]++;
	}
	return 0;
}

/* 
 * Callback function to get distribution of size of all extended 
 * attributes for a given file system.
 */
static errno_t fsinfo_xattr_size_callback(__unused struct hfsmount *hfsmp,
		__unused HFSPlusKey *key, HFSPlusRecord *record, void *data)
{
	if (record->attr_record.recordType == kHFSPlusAttrInlineData) {
		/* Inline attribute */
		hfs_fsinfo_data_add(data, record->attr_record.attrData.attrSize);
	} else if (record->attr_record.recordType == kHFSPlusAttrForkData) {
		/* Larger attributes with extents information */
		hfs_fsinfo_data_add(data, record->attr_record.forkData.theFork.logicalSize);
	}
	return 0;
}


/*
 * Callback function to get distribution of free space extents for a given file system.
 */
static void fsinfo_free_extents_callback(void *data, off_t free_extent_size)
{
	// Assume a minimum of 4 KB block size
	hfs_fsinfo_data_add(data, free_extent_size / 4096);
}

/*
 * Function to get distribution of free space extents for a given file system.
 */
static errno_t hfs_fsinfo_free_extents(struct hfsmount *hfsmp, struct hfs_fsinfo_data *fsinfo)
{
	return hfs_find_free_extents(hfsmp, &fsinfo_free_extents_callback, fsinfo);
}

/*
 * Callback function to get distribution of symblock link sizes (in bytes)
 * for all user files in given file system.  Note that this only
 * accounts for data fork, no resource fork.
 */
static errno_t fsinfo_symlink_size_callback(__unused struct hfsmount *hfsmp,
									 __unused HFSPlusKey *key, HFSPlusRecord *record, void *data)
{
	if (record->file_record.recordType == kHFSPlusFileRecord) {
		/* Record of interest, account for the size in the bucket */
		if (S_ISLNK(record->file_record.bsdInfo.fileMode))
			hfs_fsinfo_data_add((struct hfs_fsinfo_data *)data, record->file_record.dataFork.logicalSize);
	}
	return 0;
}

#if CONFIG_PROTECT
/*
 * Callback function to get total number of files/directories
 * for each content protection class
 */
static int fsinfo_cprotect_count_callback(struct hfsmount *hfsmp, HFSPlusKey *key,
										  HFSPlusRecord *record, void *data)
{
	struct hfs_fsinfo_cprotect *fsinfo = (struct hfs_fsinfo_cprotect *)data;
	static const uint16_t cp_xattrname_utf16[] = CONTENT_PROTECTION_XATTR_NAME_CHARS;
	/*
	 * NOTE: cp_xattrname_utf16_len is the number of UTF-16 code units in
	 * the EA name string.
	 */
	static const size_t cp_xattrname_utf16_len = sizeof(cp_xattrname_utf16)/2;
	struct cp_xattr_v5 *xattr;
	size_t xattr_len = sizeof(struct cp_xattr_v5);
	struct cprotect cp_entry;
	struct cprotect *cp_entryp = &cp_entry;
	int error = 0;

	/* Content protect xattrs are inline attributes only, so skip all others */
	if (record->attr_record.recordType != kHFSPlusAttrInlineData)
		return 0;

	/* We only look at content protection xattrs */
	if ((key->attr_key.attrNameLen != cp_xattrname_utf16_len) ||
		(bcmp(key->attr_key.attrName, cp_xattrname_utf16, 2 * cp_xattrname_utf16_len))) {
		return 0;
	}

	xattr = (struct cp_xattr_v5 *)((void *)(record->attr_record.attrData.attrData));
	error = cp_read_xattr_v5(hfsmp, xattr, xattr_len, (cprotect_t *)&cp_entryp,
							 CP_GET_XATTR_BASIC_INFO);
	if (error)
		return 0;

	/* No key present, skip this record */
	if (!ISSET(cp_entry.cp_flags, CP_HAS_A_KEY))
		return 0;

	/* Now account for the persistent class */
	switch (CP_CLASS(cp_entry.cp_pclass)) {
		case PROTECTION_CLASS_A:
			fsinfo->class_A++;
			break;
		case PROTECTION_CLASS_B:
			fsinfo->class_B++;
			break;
		case PROTECTION_CLASS_C:
			fsinfo->class_C++;
			break;
		case PROTECTION_CLASS_D:
			fsinfo->class_D++;
			break;
		case PROTECTION_CLASS_E:
			fsinfo->class_E++;
			break;
		case PROTECTION_CLASS_F:
			fsinfo->class_F++;
			break;
	};

	return 0;
}
#endif
