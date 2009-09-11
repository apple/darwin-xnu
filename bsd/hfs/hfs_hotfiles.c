/*
 * Copyright (c) 2003-2008 Apple Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/ubc.h>
#include <sys/ubc_internal.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/kauth.h>

#include <hfs/hfs.h>
#include <hfs/hfs_endian.h>
#include <hfs/hfs_format.h>
#include <hfs/hfs_mount.h>
#include <hfs/hfs_hotfiles.h>

#include "hfscommon/headers/BTreeScanner.h"


#define HFC_DEBUG  0
#define HFC_VERBOSE 0


/*
 * Minimum post Tiger base time.
 * Thu Mar 31 17:00:00 2005
 */
#define HFC_MIN_BASE_TIME   0x424c8f00L

/*
 * Hot File List (runtime).
 */
typedef struct hotfileinfo {
	u_int32_t  hf_fileid;
	u_int32_t  hf_temperature;
	u_int32_t  hf_blocks;
} hotfileinfo_t;

typedef struct hotfilelist {
	u_int32_t     hfl_magic;
	u_int32_t     hfl_version;
	time_t        hfl_duration;    /* duration of sample period */
	int           hfl_count;       /* count of hot files recorded */
	int           hfl_next;        /* next file to move */
	int           hfl_totalblocks; /* total hot file blocks */
	int           hfl_reclaimblks; /* blocks to reclaim in HFV */
	u_int32_t     hfl_spare[2];
	hotfileinfo_t hfl_hotfile[1];  /* array of hot files */
} hotfilelist_t;


/*
 * Hot File Entry (runtime).
 */
typedef struct hotfile_entry {
	struct  hotfile_entry  *left;
	struct  hotfile_entry  *right;
	u_int32_t  fileid;
	u_int32_t  temperature;
	u_int32_t  blocks;
} hotfile_entry_t;

/*
 * Hot File Recording Data (runtime).
 */
typedef struct hotfile_data {
	struct hfsmount *hfsmp;
	long             refcount;
	int		 activefiles;  /* active number of hot files */
	u_int32_t	 threshold;
	u_int32_t	 maxblocks;
	hotfile_entry_t	*rootentry;
	hotfile_entry_t	*freelist;
	hotfile_entry_t	*coldest;
	hotfile_entry_t	 entries[1];
} hotfile_data_t;

static int  hfs_recording_start (struct hfsmount *);
static int  hfs_recording_stop (struct hfsmount *);


/*
 * Hot File Data recording functions (in-memory binary tree).
 */
static void              hf_insert (hotfile_data_t *, hotfile_entry_t *);
static void              hf_delete (hotfile_data_t *, u_int32_t, u_int32_t);
static hotfile_entry_t * hf_coldest (hotfile_data_t *);
static hotfile_entry_t * hf_getnewentry (hotfile_data_t *);
static void              hf_getsortedlist (hotfile_data_t *, hotfilelist_t *);

#if HFC_DEBUG
static hotfile_entry_t * hf_lookup (hotfile_data_t *, u_int32_t, u_int32_t);
static void  hf_maxdepth(hotfile_entry_t *, int, int *);
static void  hf_printtree (hotfile_entry_t *);
#endif

/*
 * Hot File misc support functions.
 */
static int  hotfiles_collect (struct hfsmount *);
static int  hotfiles_age (struct hfsmount *);
static int  hotfiles_adopt (struct hfsmount *);
static int  hotfiles_evict (struct hfsmount *, vfs_context_t);
static int  hotfiles_refine (struct hfsmount *);
static int  hotextents(struct hfsmount *, HFSPlusExtentDescriptor *);
static int  hfs_addhotfile_internal(struct vnode *);


/*
 * Hot File Cluster B-tree (on disk) functions.
 */
static int  hfc_btree_create (struct hfsmount *, unsigned int, unsigned int);
static int  hfc_btree_open (struct hfsmount *, struct vnode **);
static int  hfc_btree_close (struct hfsmount *, struct vnode *);
static int  hfc_comparekeys (HotFileKey *, HotFileKey *);


char hfc_tag[] = "CLUSTERED HOT FILES B-TREE     ";


/*
 *========================================================================
 *                       HOT FILE INTERFACE ROUTINES
 *========================================================================
 */

/*
 * Start recording the hotest files on a file system.
 *
 * Requires that the hfc_mutex be held.
 */
static int
hfs_recording_start(struct hfsmount *hfsmp)
{
	hotfile_data_t *hotdata;
	struct timeval tv;
	int maxentries;
	size_t size;
	int i;
	int error;

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) ||
	    (hfsmp->jnl == NULL) ||
	    (hfsmp->hfs_flags & HFS_METADATA_ZONE) == 0) {
		return (EPERM);
	}
	if (HFSTOVCB(hfsmp)->freeBlocks < (2 * (u_int32_t)hfsmp->hfs_hotfile_maxblks)) {
		return (ENOSPC);
	}
	if (hfsmp->hfc_stage != HFC_IDLE) {
		return (EBUSY);
	}
	hfsmp->hfc_stage = HFC_BUSY;

	/*
	 * Dump previous recording data.
	 */
	if (hfsmp->hfc_recdata) {
		void * tmp;

		tmp = hfsmp->hfc_recdata;
		hfsmp->hfc_recdata = NULL;
		FREE(tmp, M_TEMP);
	}

	microtime(&tv);  /* Times are base on GMT time. */

	/*
	 * On first startup check for suspended recording.
	 */
	if (hfsmp->hfc_timebase == 0 &&
	    hfc_btree_open(hfsmp, &hfsmp->hfc_filevp) == 0) {
		HotFilesInfo hotfileinfo;

		if ((BTGetUserData(VTOF(hfsmp->hfc_filevp), &hotfileinfo,
		                   sizeof(hotfileinfo)) == 0) &&
		    (SWAP_BE32 (hotfileinfo.magic) == HFC_MAGIC) &&
		    (SWAP_BE32 (hotfileinfo.timeleft) > 0) &&
		    (SWAP_BE32 (hotfileinfo.timebase) > 0)) {
			hfsmp->hfc_maxfiles = SWAP_BE32 (hotfileinfo.maxfilecnt);
			hfsmp->hfc_timeout = SWAP_BE32 (hotfileinfo.timeleft) + tv.tv_sec ;
			hfsmp->hfc_timebase = SWAP_BE32 (hotfileinfo.timebase);
			/* Fix up any bogus timebase values. */
			if (hfsmp->hfc_timebase < HFC_MIN_BASE_TIME) {
				hfsmp->hfc_timebase = hfsmp->hfc_timeout - HFC_DEFAULT_DURATION;
			}
#if HFC_VERBOSE
			printf("hfs: Resume recording hot files on %s (%d secs left)\n",
				hfsmp->vcbVN, SWAP_BE32 (hotfileinfo.timeleft));
#endif
		} else {
			hfsmp->hfc_maxfiles = HFC_DEFAULT_FILE_COUNT;
			hfsmp->hfc_timebase = tv.tv_sec + 1;
			hfsmp->hfc_timeout = hfsmp->hfc_timebase + HFC_DEFAULT_DURATION;
		}
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
	} else {
		struct cat_attr cattr;
		u_int32_t cnid;

		/*
		 * Make sure a btree file exists.
		 */
		cnid = GetFileInfo(HFSTOVCB(hfsmp), kRootDirID, HFC_FILENAME, &cattr, NULL);
		if ((cnid == 0) &&
		    !S_ISREG(cattr.ca_mode) &&
		    (error = hfc_btree_create(hfsmp, HFSTOVCB(hfsmp)->blockSize, HFC_DEFAULT_FILE_COUNT))) {
			hfsmp->hfc_stage = HFC_IDLE;
			wakeup((caddr_t)&hfsmp->hfc_stage);
			return (error);
		}
#if HFC_VERBOSE
		printf("hfs: begin recording hot files on %s\n", hfsmp->vcbVN);
#endif
		hfsmp->hfc_maxfiles = HFC_DEFAULT_FILE_COUNT;
		hfsmp->hfc_timeout = tv.tv_sec + HFC_DEFAULT_DURATION;

		/* Reset time base.  */
		if (hfsmp->hfc_timebase == 0) {
			hfsmp->hfc_timebase = tv.tv_sec + 1;
		} else {
			time_t cumulativebase;

			cumulativebase = hfsmp->hfc_timeout - (HFC_CUMULATIVE_CYCLES * HFC_DEFAULT_DURATION);
			hfsmp->hfc_timebase = MAX(hfsmp->hfc_timebase, cumulativebase);
		}
	}

	if ((hfsmp->hfc_maxfiles == 0) ||
	    (hfsmp->hfc_maxfiles > HFC_MAXIMUM_FILE_COUNT)) {
		hfsmp->hfc_maxfiles = HFC_DEFAULT_FILE_COUNT;
	}
	maxentries = hfsmp->hfc_maxfiles;

	size = sizeof(hotfile_data_t) + (maxentries * sizeof(hotfile_entry_t));
	MALLOC(hotdata, hotfile_data_t *, size, M_TEMP, M_WAITOK);
	if (hotdata == NULL) {
		hfsmp->hfc_recdata = NULL;
		hfsmp->hfc_stage = HFC_IDLE;
		wakeup((caddr_t)&hfsmp->hfc_stage);
		return(ENOMEM);
	}

	bzero(hotdata, size);

	for (i = 1; i < maxentries ; i++)
		hotdata->entries[i-1].right = &hotdata->entries[i];
	
	hotdata->freelist = &hotdata->entries[0];
	/* 
	 * Establish minimum temperature and maximum file size.
	 */
	hotdata->threshold = HFC_MINIMUM_TEMPERATURE;
	hotdata->maxblocks = HFC_MAXIMUM_FILESIZE / HFSTOVCB(hfsmp)->blockSize;
	hotdata->hfsmp = hfsmp;
	
	hfsmp->hfc_recdata = hotdata;
	hfsmp->hfc_stage = HFC_RECORDING;
	wakeup((caddr_t)&hfsmp->hfc_stage);
	return (0);
}

/*
 * Stop recording the hotest files on a file system.
 *
 * Requires that the hfc_mutex be held.
 */
static int
hfs_recording_stop(struct hfsmount *hfsmp)
{
	hotfile_data_t *hotdata;
	hotfilelist_t  *listp;
	struct timeval tv;
	size_t  size;
	enum hfc_stage newstage = HFC_IDLE;
	int  error;

	if (hfsmp->hfc_stage != HFC_RECORDING)
		return (EPERM);

	hfsmp->hfc_stage = HFC_BUSY;

	hotfiles_collect(hfsmp);


	/*
	 * Convert hot file data into a simple file id list....
	 *
	 * then dump the sample data
	 */
#if HFC_VERBOSE
	printf("hfs: end of hot file recording on %s\n", hfsmp->vcbVN);
#endif
	hotdata = (hotfile_data_t *)hfsmp->hfc_recdata;
	if (hotdata == NULL)
		return (0);
	hfsmp->hfc_recdata = NULL;
	hfsmp->hfc_stage = HFC_EVALUATION;
	wakeup((caddr_t)&hfsmp->hfc_stage);

#if HFC_VERBOSE
	printf("hfs:   curentries: %d\n", hotdata->activefiles);
#endif
	/*
	 * If no hot files recorded then we're done.
	 */
	if (hotdata->rootentry == NULL) {
		error = 0;
		goto out;
	}

	/* Open the B-tree file for writing... */
	if (hfsmp->hfc_filevp)
		panic("hfs_recording_stop: hfc_filevp exists (vp = %p)", hfsmp->hfc_filevp);

	error = hfc_btree_open(hfsmp, &hfsmp->hfc_filevp);
	if (error) {
		goto out;
	}

	/*
	 * Age the previous set of clustered hot files.
	 */
	error = hotfiles_age(hfsmp);
	if (error) {
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
		goto out;
	}

	/*
	 * Create a sorted list of hotest files.
	 */
	size = sizeof(hotfilelist_t);
	size += sizeof(hotfileinfo_t) * (hotdata->activefiles - 1);
	MALLOC(listp, hotfilelist_t *, size, M_TEMP, M_WAITOK);
	if (listp == NULL) {
		error = ENOMEM;
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
		goto out;
	}

	bzero(listp, size);

	hf_getsortedlist(hotdata, listp);	/* NOTE: destroys hot file tree! */
	microtime(&tv);
	listp->hfl_duration = tv.tv_sec - hfsmp->hfc_timebase;
	hfsmp->hfc_recdata = listp;

	/*
	 * Account for duplicates.
	 */
	error = hotfiles_refine(hfsmp);
	if (error) {
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
		goto out;
	}

	/*
	 * Compute the amount of space to reclaim...
	 */
	if (listp->hfl_totalblocks > hfsmp->hfs_hotfile_freeblks) {
		listp->hfl_reclaimblks =
			MIN(listp->hfl_totalblocks, hfsmp->hfs_hotfile_maxblks) -
			hfsmp->hfs_hotfile_freeblks;
#if HFC_VERBOSE
		printf("hfs_recording_stop: need to reclaim %d blocks\n", listp->hfl_reclaimblks);
#endif
		if (listp->hfl_reclaimblks)
			newstage = HFC_EVICTION;
		else
			newstage = HFC_ADOPTION;
	} else {
		newstage = HFC_ADOPTION;
	}
	
	if (newstage == HFC_ADOPTION && listp->hfl_totalblocks == 0) {
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
		newstage = HFC_IDLE;
	}
out:
#if HFC_VERBOSE
	if (newstage == HFC_EVICTION)
		printf("hfs: evicting coldest files\n");
	else if (newstage == HFC_ADOPTION)
		printf("hfs: adopting hotest files\n");
#endif
	FREE(hotdata, M_TEMP);

	hfsmp->hfc_stage = newstage;
	wakeup((caddr_t)&hfsmp->hfc_stage);
	return (error);
}

/*
 * Suspend recording the hotest files on a file system.
 */
__private_extern__
int
hfs_recording_suspend(struct hfsmount *hfsmp)
{
	HotFilesInfo hotfileinfo;
	hotfile_data_t *hotdata = NULL;
	struct timeval tv;
	int  error;

	if (hfsmp->hfc_stage == HFC_DISABLED)
		return (0);

	lck_mtx_lock(&hfsmp->hfc_mutex);

	/*
	 * XXX NOTE
	 * A suspend can occur during eval/evict/adopt stage.
	 * In that case we would need to write out info and
	 * flush our HFBT vnode. Currently we just bail.
	 */

	hotdata = (hotfile_data_t *)hfsmp->hfc_recdata;
	if (hotdata == NULL || hfsmp->hfc_stage != HFC_RECORDING) {
		error = 0;
		goto out;
	}
	hfsmp->hfc_stage = HFC_BUSY;

#if HFC_VERBOSE
	printf("hfs: suspend hot file recording on %s\n", hfsmp->vcbVN);
#endif
	error = hfc_btree_open(hfsmp, &hfsmp->hfc_filevp);
	if (error) {
		printf("hfs_recording_suspend: err %d opening btree\n", error);
		goto out;
	}

	if (hfs_start_transaction(hfsmp) != 0) {
	    error = EINVAL;
	    goto out;
	}
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK) != 0) {
		error = EPERM;
		goto end_transaction;
	}

	microtime(&tv);
	hotfileinfo.magic       = SWAP_BE32 (HFC_MAGIC);
	hotfileinfo.version     = SWAP_BE32 (HFC_VERSION);
	hotfileinfo.duration    = SWAP_BE32 (HFC_DEFAULT_DURATION);
	hotfileinfo.timebase    = SWAP_BE32 (hfsmp->hfc_timebase);
	hotfileinfo.timeleft    = SWAP_BE32 (hfsmp->hfc_timeout - tv.tv_sec);
	hotfileinfo.threshold   = SWAP_BE32 (hotdata->threshold);
	hotfileinfo.maxfileblks = SWAP_BE32 (hotdata->maxblocks);
	hotfileinfo.maxfilecnt  = SWAP_BE32 (HFC_DEFAULT_FILE_COUNT);
	strlcpy((char *)hotfileinfo.tag, hfc_tag, sizeof hotfileinfo.tag);
	(void) BTSetUserData(VTOF(hfsmp->hfc_filevp), &hotfileinfo, sizeof(hotfileinfo));

	hfs_unlock(VTOC(hfsmp->hfc_filevp));

end_transaction:
	hfs_end_transaction(hfsmp);

out:
	if (hfsmp->hfc_filevp) {
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
	}
	if (hotdata) {
		FREE(hotdata, M_TEMP);
		hfsmp->hfc_recdata = NULL;
	}
	hfsmp->hfc_stage = HFC_DISABLED;
	wakeup((caddr_t)&hfsmp->hfc_stage);

	lck_mtx_unlock(&hfsmp->hfc_mutex);
	return (error);
}


/*
 *
 */
__private_extern__
int
hfs_recording_init(struct hfsmount *hfsmp)
{
	CatalogKey * keyp;
	CatalogRecord * datap;
	u_int32_t  dataSize;
	HFSPlusCatalogFile *filep;
	BTScanState scanstate;
	BTreeIterator * iterator = NULL;
	FSBufferDescriptor  record;
	HotFileKey * key;
	filefork_t * filefork;
	u_int32_t  data;
	struct cat_attr cattr;
	u_int32_t  cnid;
	int error = 0;

	int inserted = 0;  /* debug variables */
	int filecount = 0;

	/*
	 * For now, only the boot volume is supported.
	 */
	if ((vfs_flags(HFSTOVFS(hfsmp)) & MNT_ROOTFS) == 0) {
		hfsmp->hfc_stage = HFC_DISABLED;
		return (EPERM);
	}

	/*
	 * Tracking of hot files requires up-to-date access times.
	 * So if access time updates are disabled, then we disable
	 * hot files, too.
	 */
	if (vfs_flags(HFSTOVFS(hfsmp)) & MNT_NOATIME) {
		hfsmp->hfc_stage = HFC_DISABLED;
		return EPERM;
	}
	
	/*
	 * If the Hot File btree exists then metadata zone is ready.
	 */
	cnid = GetFileInfo(HFSTOVCB(hfsmp), kRootDirID, HFC_FILENAME, &cattr, NULL);
	if (cnid != 0 && S_ISREG(cattr.ca_mode)) {
		if (hfsmp->hfc_stage == HFC_DISABLED)
			hfsmp->hfc_stage = HFC_IDLE;
		return (0);
	}
	error = hfc_btree_create(hfsmp, HFSTOVCB(hfsmp)->blockSize, HFC_DEFAULT_FILE_COUNT);
	if (error) {
#if HFC_VERBOSE
		printf("hfs: Error %d creating hot file b-tree on %s \n", error, hfsmp->vcbVN);
#endif
		return (error);
	}
	/*
	 * Open the Hot File B-tree file for writing.
	 */
	if (hfsmp->hfc_filevp)
		panic("hfs_recording_init: hfc_filevp exists (vp = %p)", hfsmp->hfc_filevp);
	error = hfc_btree_open(hfsmp, &hfsmp->hfc_filevp);
	if (error) {
#if HFC_VERBOSE
		printf("hfs: Error %d opening hot file b-tree on %s \n", error, hfsmp->vcbVN);
#endif
		return (error);
	}
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		error = ENOMEM;
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
		goto out2;
	}
	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;
	key->keyLength = HFC_KEYLENGTH;

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;
#if HFC_VERBOSE
	printf("hfs: Evaluating space for \"%s\" metadata zone...\n", HFSTOVCB(hfsmp)->vcbVN);
#endif
	/*
	 * Get ready to scan the Catalog file.
	 */
	error = BTScanInitialize(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), 0, 0, 0,
	                       kCatSearchBufferSize, &scanstate);
	if (error) {
		printf("hfs_recording_init: err %d BTScanInit\n", error);
		goto out2;
	}

	/*
	 * The writes to Hot File B-tree file are journaled.
	 */
	if (hfs_start_transaction(hfsmp) != 0) {
	    error = EINVAL;
	    goto out1;
	} 
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK) != 0) {
		error = EPERM;
		goto out0;
	}
	filefork = VTOF(hfsmp->hfc_filevp);

	/*
	 * Visit all the catalog btree leaf records.
	 */
	for (;;) {
		error = BTScanNextRecord(&scanstate, 0, (void **)&keyp, (void **)&datap, &dataSize);
		if (error) {
			if (error == btNotFound)
				error = 0;
			else
				printf("hfs_recording_init: err %d BTScanNext\n", error);
			break;
		}
		if ((datap->recordType != kHFSPlusFileRecord) ||
		    (dataSize != sizeof(HFSPlusCatalogFile))) {
			continue;
		}
		filep = (HFSPlusCatalogFile *)datap;
		filecount++;
		if (filep->dataFork.totalBlocks == 0) {
			continue;
		}
		/*
		 * Any file that has blocks inside the hot file
		 * space is recorded for later eviction.
		 *
		 * For now, resource forks are ignored.
		 */
		if (!hotextents(hfsmp, &filep->dataFork.extents[0])) {
			continue;
		}
		cnid = filep->fileID;

		/* Skip over journal files. */
		if (cnid == hfsmp->hfs_jnlfileid || cnid == hfsmp->hfs_jnlinfoblkid) {
			continue;
		}
		/*
		 * XXX - need to skip quota files as well.
		 */

		/* Insert a hot file entry. */
		key->keyLength   = HFC_KEYLENGTH;
		key->temperature = HFC_MINIMUM_TEMPERATURE;
		key->fileID      = cnid;
		key->forkType    = 0;
		data = 0x3f3f3f3f;
		error = BTInsertRecord(filefork, iterator, &record, record.itemSize);
		if (error) {
			printf("hfs_recording_init: BTInsertRecord failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}

		/* Insert the corresponding thread record. */
		key->keyLength = HFC_KEYLENGTH;
		key->temperature = HFC_LOOKUPTAG;
		key->fileID = cnid;
		key->forkType = 0;
		data = HFC_MINIMUM_TEMPERATURE;
		error = BTInsertRecord(filefork, iterator, &record, record.itemSize);
		if (error) {
			printf("hfs_recording_init: BTInsertRecord failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}
		inserted++;
	}
	(void) BTFlushPath(filefork);
	hfs_unlock(VTOC(hfsmp->hfc_filevp));

out0:
	hfs_end_transaction(hfsmp);
#if HFC_VERBOSE
	printf("hfs: %d files identified out of %d\n", inserted, filecount);
#endif
	
out1:
	(void) BTScanTerminate(&scanstate, &data, &data, &data);
out2:	
	if (iterator)
		FREE(iterator, M_TEMP);
	if (hfsmp->hfc_filevp) {
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
	}
	if (error == 0)
		hfsmp->hfc_stage = HFC_IDLE;

	return (error);
}

/*
 * Use sync to perform ocassional background work.
 */
__private_extern__
int
hfs_hotfilesync(struct hfsmount *hfsmp, vfs_context_t ctx)
{
	if (hfsmp->hfc_stage) {
		struct timeval tv;

		lck_mtx_lock(&hfsmp->hfc_mutex);

		switch (hfsmp->hfc_stage) {
		case HFC_IDLE:
			(void) hfs_recording_start(hfsmp);
			break;
	
		case HFC_RECORDING:
			microtime(&tv);
			if (tv.tv_sec > hfsmp->hfc_timeout)
				(void) hfs_recording_stop(hfsmp);
			break;
	
		case HFC_EVICTION:
			(void) hotfiles_evict(hfsmp, ctx);
			break;
	
		case HFC_ADOPTION:
			(void) hotfiles_adopt(hfsmp);
			break;
		default:
			break;
		}

		lck_mtx_unlock(&hfsmp->hfc_mutex);
	}
	return (0);
}

/*
 * Add a hot file to the recording list.
 *
 * This can happen when a hot file gets reclaimed or at the
 * end of the recording period for any active hot file.
 *
 * NOTE: Since both the data and resource fork can  be hot,
 * there can be two entries for the same file id.
 *
 * Note: the cnode is locked on entry.
 */
__private_extern__
int
hfs_addhotfile(struct vnode *vp)
{
	hfsmount_t *hfsmp;
	int error;

	hfsmp = VTOHFS(vp);
	if (hfsmp->hfc_stage != HFC_RECORDING)
		return (0);

	lck_mtx_lock(&hfsmp->hfc_mutex);
	error = hfs_addhotfile_internal(vp);
	lck_mtx_unlock(&hfsmp->hfc_mutex);
	return (error);
}

static int
hfs_addhotfile_internal(struct vnode *vp)
{
	hotfile_data_t *hotdata;
	hotfile_entry_t *entry;
	hfsmount_t *hfsmp;
	cnode_t *cp;
	filefork_t *ffp;
	u_int32_t temperature;

	hfsmp = VTOHFS(vp);
	if (hfsmp->hfc_stage != HFC_RECORDING)
		return (0);

	if ((!vnode_isreg(vp) && !vnode_islnk(vp)) || vnode_issystem(vp)) {
		return (0);
	}
	/* Skip resource forks for now. */
	if (VNODE_IS_RSRC(vp)) {
		return (0);
	}
	if ((hotdata = (hotfile_data_t *)hfsmp->hfc_recdata) == NULL) {
		return (0);
	}
	ffp = VTOF(vp);
	cp = VTOC(vp);

	if ((ffp->ff_bytesread == 0) ||
	    (ffp->ff_blocks == 0) ||
	    (ffp->ff_size == 0) ||
	    (ffp->ff_blocks > hotdata->maxblocks) ||
	    (cp->c_flag & (C_DELETED | C_NOEXISTS)) ||
	    (cp->c_flags & UF_NODUMP) ||
	    (cp->c_atime < hfsmp->hfc_timebase)) {
		return (0);
	}

	temperature = ffp->ff_bytesread / ffp->ff_size;
	if (temperature < hotdata->threshold) {
		return (0);
	}
	/*
	 * If there is room or this file is hotter than
	 * the coldest one then add it to the list.
	 *
	 */
	if ((hotdata->activefiles < hfsmp->hfc_maxfiles) ||
	    (hotdata->coldest == NULL) ||
	    (temperature > hotdata->coldest->temperature)) {
		++hotdata->refcount;
		entry = hf_getnewentry(hotdata);
		entry->temperature = temperature;
		entry->fileid = cp->c_fileid;
		entry->blocks = ffp->ff_blocks;
		hf_insert(hotdata, entry);
		--hotdata->refcount;
	}

	return (0);
}

/*
 * Remove a hot file from the recording list.
 *
 * This can happen when a hot file becomes
 * an active vnode (active hot files are
 * not kept in the recording list until the
 * end of the recording period).
 *
 * Note: the cnode is locked on entry.
 */
__private_extern__
int
hfs_removehotfile(struct vnode *vp)
{
	hotfile_data_t *hotdata;
	hfsmount_t *hfsmp;
	cnode_t *cp;
	filefork_t *ffp;
	u_int32_t temperature;

	hfsmp = VTOHFS(vp);
	if (hfsmp->hfc_stage != HFC_RECORDING)
		return (0);

	if ((!vnode_isreg(vp) && !vnode_islnk(vp)) || vnode_issystem(vp)) {
		return (0);
	}

	ffp = VTOF(vp);
	cp = VTOC(vp);

	if ((ffp->ff_bytesread == 0) || (ffp->ff_blocks == 0) ||
	    (ffp->ff_size == 0) || (cp->c_atime < hfsmp->hfc_timebase)) {
		return (0);
	}

	lck_mtx_lock(&hfsmp->hfc_mutex);
	if (hfsmp->hfc_stage != HFC_RECORDING)
		goto out;
	if ((hotdata = (hotfile_data_t *)hfsmp->hfc_recdata) == NULL)
		goto out;

	temperature = ffp->ff_bytesread / ffp->ff_size;
	if (temperature < hotdata->threshold)
		goto out;

	if (hotdata->coldest && (temperature >= hotdata->coldest->temperature)) {
		++hotdata->refcount;
		hf_delete(hotdata, VTOC(vp)->c_fileid, temperature);
		--hotdata->refcount;
	}
out:
	lck_mtx_unlock(&hfsmp->hfc_mutex);
	return (0);
}


/*
 *========================================================================
 *                     HOT FILE MAINTENANCE ROUTINES
 *========================================================================
 */

static int
hotfiles_collect_callback(struct vnode *vp, __unused void *cargs)
{
        if ((vnode_isreg(vp) || vnode_islnk(vp)) && !vnode_issystem(vp))
	        (void) hfs_addhotfile_internal(vp);

	return (VNODE_RETURNED);
}

/*
 * Add all active hot files to the recording list.
 */
static int
hotfiles_collect(struct hfsmount *hfsmp)
{
	struct mount *mp = HFSTOVFS(hfsmp);

	if (vfs_busy(mp, LK_NOWAIT))
		return (0);

	/*
	 * hotfiles_collect_callback will be called for each vnode
	 * hung off of this mount point
	 * the vnode will be
	 * properly referenced and unreferenced around the callback
	 */
	vnode_iterate(mp, 0, hotfiles_collect_callback, (void *)NULL);

	vfs_unbusy(mp);

	return (0);
}


/*
 * Update the data of a btree record
 * This is called from within BTUpdateRecord.
 */
static int
update_callback(const HotFileKey *key, u_int32_t *data, u_int32_t *state)
{
	if (key->temperature == HFC_LOOKUPTAG)
		*data = *state;
	return (0);
}

/*
 * Identify files already in hot area.
 */
static int
hotfiles_refine(struct hfsmount *hfsmp)
{
	BTreeIterator * iterator = NULL;
	struct mount *mp;
	filefork_t * filefork;
	hotfilelist_t  *listp;
	FSBufferDescriptor  record;
	HotFileKey * key;
	u_int32_t  data;
	int  i;
	int  error = 0;


	if ((listp = (hotfilelist_t  *)hfsmp->hfc_recdata) == NULL)
		return (0);	

	mp = HFSTOVFS(hfsmp);

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		error = ENOMEM;
		goto out;
	}
	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;

	if (hfs_start_transaction(hfsmp) != 0) {
	    error = EINVAL;
	    goto out;
	} 
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK) != 0) {
		error = EPERM;
		goto out1;
	}
	filefork = VTOF(hfsmp->hfc_filevp);

	for (i = 0; i < listp->hfl_count; ++i) {
		/*
		 * Check if entry (thread) is already in hot area.
		 */
		key->keyLength = HFC_KEYLENGTH;
		key->temperature = HFC_LOOKUPTAG;
		key->fileID = listp->hfl_hotfile[i].hf_fileid;
		key->forkType = 0;
		(void) BTInvalidateHint(iterator);
		if (BTSearchRecord(filefork, iterator, &record, NULL, iterator) != 0) {
			continue;  /* not in hot area, so skip */
		}

		/*
		 * Update thread entry with latest temperature.
		 */
		error = BTUpdateRecord(filefork, iterator,
				(IterateCallBackProcPtr)update_callback,
				&listp->hfl_hotfile[i].hf_temperature);
		if (error) {
			printf("hfs: hotfiles_refine: BTUpdateRecord failed %d (file %d)\n", error, key->fileID);
			error = MacToVFSError(error);
		//	break;
		}
		/*
		 * Re-key entry with latest temperature.
		 */
		key->keyLength = HFC_KEYLENGTH;
		key->temperature = data;
		key->fileID = listp->hfl_hotfile[i].hf_fileid;
		key->forkType = 0;
		/* Pick up record data. */
		(void) BTInvalidateHint(iterator);
		(void) BTSearchRecord(filefork, iterator, &record, NULL, iterator);
		error = BTDeleteRecord(filefork, iterator);
		if (error) {
			printf("hfs: hotfiles_refine: BTDeleteRecord failed %d (file %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}
		key->keyLength = HFC_KEYLENGTH;
		key->temperature = listp->hfl_hotfile[i].hf_temperature;
		key->fileID = listp->hfl_hotfile[i].hf_fileid;
		key->forkType = 0;
		error = BTInsertRecord(filefork, iterator, &record, record.itemSize);
		if (error) {
			printf("hfs: hotfiles_refine: BTInsertRecord failed %d (file %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}

		/*
		 * Invalidate this entry in the list.
		 */
		listp->hfl_hotfile[i].hf_temperature = 0;
		listp->hfl_totalblocks -= listp->hfl_hotfile[i].hf_blocks;
		
	} /* end for */

	(void) BTFlushPath(filefork);
	hfs_unlock(VTOC(hfsmp->hfc_filevp));

out1:
	hfs_end_transaction(hfsmp);
out:
	if (iterator)
		FREE(iterator, M_TEMP);	
	return (error);
}

/*
 * Move new hot files into hot area.
 *
 * Requires that the hfc_mutex be held.
 */
static int
hotfiles_adopt(struct hfsmount *hfsmp)
{
	BTreeIterator * iterator = NULL;
	struct vnode *vp;
	filefork_t * filefork;
	hotfilelist_t  *listp;
	FSBufferDescriptor  record;
	HotFileKey * key;
	u_int32_t  data;
	enum hfc_stage stage;
	int  fileblocks;
	int  blksmoved;
	int  i;
	int  last;
	int  error = 0;
	int  startedtrans = 0;

	if ((listp = (hotfilelist_t  *)hfsmp->hfc_recdata) == NULL)
		return (0);	

	if (hfsmp->hfc_stage != HFC_ADOPTION) {
		return (EBUSY);
	}
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK) != 0) {
		return (EPERM);
	}

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		hfs_unlock(VTOC(hfsmp->hfc_filevp));
		return (ENOMEM);
	}

	stage = hfsmp->hfc_stage;
	hfsmp->hfc_stage = HFC_BUSY;

	blksmoved = 0;
	last = listp->hfl_next + HFC_FILESPERSYNC;
	if (last > listp->hfl_count)
		last = listp->hfl_count;

	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;
	key->keyLength = HFC_KEYLENGTH;

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;

	filefork = VTOF(hfsmp->hfc_filevp);

	for (i = listp->hfl_next; (i < last) && (blksmoved < HFC_BLKSPERSYNC); ++i) {
		/*
		 * Skip invalid entries (already in hot area).
		 */
		if (listp->hfl_hotfile[i].hf_temperature == 0) {
				listp->hfl_next++;
				continue;
		}
		/*
		 * Acquire a vnode for this file.
		 */
		error = hfs_vget(hfsmp, listp->hfl_hotfile[i].hf_fileid, &vp, 0);
		if (error) {
			if (error == ENOENT) {
				error = 0;
				listp->hfl_next++;
				continue;  /* stale entry, go to next */
			}
			break;
		}
		if (!vnode_isreg(vp) && !vnode_islnk(vp)) {
			printf("hfs: hotfiles_adopt: huh, not a file %d (%d)\n", listp->hfl_hotfile[i].hf_fileid, VTOC(vp)->c_cnid);
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			listp->hfl_hotfile[i].hf_temperature = 0;
			listp->hfl_next++;
			continue;  /* stale entry, go to next */
		}
		if (hotextents(hfsmp, &VTOF(vp)->ff_extents[0])) {
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			listp->hfl_hotfile[i].hf_temperature = 0;
			listp->hfl_next++;
			listp->hfl_totalblocks -= listp->hfl_hotfile[i].hf_blocks;
			continue;  /* stale entry, go to next */
		}
		fileblocks = VTOF(vp)->ff_blocks;
		if (fileblocks > hfsmp->hfs_hotfile_freeblks) {
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			listp->hfl_next++;
			listp->hfl_totalblocks -= fileblocks;
			continue;  /* entry too big, go to next */
		}
		
		if ((blksmoved > 0) &&
		    (blksmoved + fileblocks) > HFC_BLKSPERSYNC) {
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			break;  /* adopt this entry the next time around */
		}
		if (VTOC(vp)->c_desc.cd_nameptr)
			data = *(const u_int32_t *)(VTOC(vp)->c_desc.cd_nameptr);
		else
			data = 0x3f3f3f3f;

		error = hfs_relocate(vp, hfsmp->hfs_hotfile_start, kauth_cred_get(), current_proc());
		hfs_unlock(VTOC(vp));
		vnode_put(vp);
		if (error) {
			/* Move on to next item. */
			listp->hfl_next++;
			continue;
		}
		/* Keep hot file free space current. */
		hfsmp->hfs_hotfile_freeblks -= fileblocks;
		listp->hfl_totalblocks -= fileblocks;
		
		/* Insert hot file entry */
		key->keyLength   = HFC_KEYLENGTH;
		key->temperature = listp->hfl_hotfile[i].hf_temperature;
		key->fileID      = listp->hfl_hotfile[i].hf_fileid;
		key->forkType    = 0;

		/* Start a new transaction before calling BTree code. */
		if (hfs_start_transaction(hfsmp) != 0) {
		    error = EINVAL;
		    break;
		}
		startedtrans = 1;

		error = BTInsertRecord(filefork, iterator, &record, record.itemSize);
		if (error) {
			printf("hfs: hotfiles_adopt: BTInsertRecord failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			stage = HFC_IDLE;
			break;
		}

		/* Insert thread record */
		key->keyLength = HFC_KEYLENGTH;
		key->temperature = HFC_LOOKUPTAG;
		key->fileID = listp->hfl_hotfile[i].hf_fileid;
		key->forkType = 0;
		data = listp->hfl_hotfile[i].hf_temperature;
		error = BTInsertRecord(filefork, iterator, &record, record.itemSize);
		if (error) {
			printf("hfs: hotfiles_adopt: BTInsertRecord failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			stage = HFC_IDLE;
			break;
		}
		(void) BTFlushPath(filefork);

		/* Transaction complete. */
		if (startedtrans) {
		    hfs_end_transaction(hfsmp);
		    startedtrans = 0;
		}

		blksmoved += fileblocks;
		listp->hfl_next++;
		if (listp->hfl_next >= listp->hfl_count) {
			break;
		}
		if (hfsmp->hfs_hotfile_freeblks <= 0) {
#if HFC_VERBOSE
			printf("hfs: hotfiles_adopt: free space exhausted (%d)\n", hfsmp->hfs_hotfile_freeblks);
#endif
			break;
		}
	} /* end for */

#if HFC_VERBOSE
	printf("hfs: hotfiles_adopt: [%d] adopted %d blocks (%d left)\n", listp->hfl_next, blksmoved, listp->hfl_totalblocks);
#endif
	/* Finish any outstanding transactions. */
	if (startedtrans) {
		(void) BTFlushPath(filefork);
		hfs_end_transaction(hfsmp);
		startedtrans = 0;
	}
	hfs_unlock(VTOC(hfsmp->hfc_filevp));

	if ((listp->hfl_next >= listp->hfl_count) || (hfsmp->hfs_hotfile_freeblks <= 0)) {
#if HFC_VERBOSE
		printf("hfs: hotfiles_adopt: all done relocating %d files\n", listp->hfl_count);
		printf("hfs: hotfiles_adopt: %d blocks free in hot file band\n", hfsmp->hfs_hotfile_freeblks);
#endif
		stage = HFC_IDLE;
	}
	FREE(iterator, M_TEMP);

	if (stage != HFC_ADOPTION && hfsmp->hfc_filevp) {
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
	}
	hfsmp->hfc_stage = stage;
	wakeup((caddr_t)&hfsmp->hfc_stage);
	return (error);
}

/*
 * Reclaim space by evicting the coldest files.
 *
 * Requires that the hfc_mutex be held.
 */
static int
hotfiles_evict(struct hfsmount *hfsmp, vfs_context_t ctx)
{
	BTreeIterator * iterator = NULL;
	struct vnode *vp;
	HotFileKey * key;
	filefork_t * filefork;
	hotfilelist_t  *listp;
	enum hfc_stage stage;
	u_int32_t savedtemp;
	int  blksmoved;
	int  filesmoved;
	int  fileblocks;
	int  error = 0;
	int  startedtrans = 0;
	int  bt_op;

	if (hfsmp->hfc_stage != HFC_EVICTION) {
		return (EBUSY);
	}

	if ((listp = (hotfilelist_t  *)hfsmp->hfc_recdata) == NULL)
		return (0);	

	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK) != 0) {
		return (EPERM);
	}

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		hfs_unlock(VTOC(hfsmp->hfc_filevp));
		return (ENOMEM);
	}

	stage = hfsmp->hfc_stage;
	hfsmp->hfc_stage = HFC_BUSY;

	filesmoved = blksmoved = 0;
	bt_op = kBTreeFirstRecord;

	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;

	filefork = VTOF(hfsmp->hfc_filevp);

	while (listp->hfl_reclaimblks > 0 &&
	       blksmoved < HFC_BLKSPERSYNC &&
	       filesmoved < HFC_FILESPERSYNC) {

		/*
		 * Obtain the first record (ie the coldest one).
		 */
		if (BTIterateRecord(filefork, bt_op, iterator, NULL, NULL) != 0) {
#if HFC_VERBOSE
			printf("hfs: hotfiles_evict: no more records\n");
#endif
			error = 0;
			stage = HFC_ADOPTION;
			break;
		}
		if (key->keyLength != HFC_KEYLENGTH) {
			printf("hfs: hotfiles_evict: invalid key length %d\n", key->keyLength);
			error = EFTYPE;
			break;
		}		
		if (key->temperature == HFC_LOOKUPTAG) {
#if HFC_VERBOSE
			printf("hfs: hotfiles_evict: ran into thread records\n");
#endif
			error = 0;
			stage = HFC_ADOPTION;
			break;
		}
		/*
		 * Aquire the vnode for this file.
		 */
		error = hfs_vget(hfsmp, key->fileID, &vp, 0);
		if (error) {
			if (error == ENOENT) {
				goto delete;  /* stale entry, go to next */
			} else {
				printf("hfs: hotfiles_evict: err %d getting file %d\n",
				       error, key->fileID);
			}
			break;
		}
		if (!vnode_isreg(vp) && !vnode_islnk(vp)) {
			printf("hfs: hotfiles_evict: huh, not a file %d\n", key->fileID);
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			goto delete;  /* invalid entry, go to next */
		}
		fileblocks = VTOF(vp)->ff_blocks;
		if ((blksmoved > 0) &&
		    (blksmoved + fileblocks) > HFC_BLKSPERSYNC) {
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			break;
		}
		/*
		 * Make sure file is in the hot area.
		 */
		if (!hotextents(hfsmp, &VTOF(vp)->ff_extents[0])) {
#if HFC_VERBOSE
			printf("hfs: hotfiles_evict: file %d isn't hot!\n", key->fileID);
#endif
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			goto delete;  /* stale entry, go to next */
		}
		
		/*
		 * Relocate file out of hot area.
		 */
		error = hfs_relocate(vp, HFSTOVCB(hfsmp)->nextAllocation, vfs_context_ucred(ctx), vfs_context_proc(ctx));
		if (error) {
			printf("hfs: hotfiles_evict: err %d relocating file %d\n", error, key->fileID);
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			bt_op = kBTreeNextRecord;
			goto next;  /* go to next */
		}

		//
		// We do not believe that this call to hfs_fsync() is
		// necessary and it causes a journal transaction
		// deadlock so we are removing it.
		//
		// (void) hfs_fsync(vp, MNT_WAIT, 0, p);

		hfs_unlock(VTOC(vp));
		vnode_put(vp);

		hfsmp->hfs_hotfile_freeblks += fileblocks;
		listp->hfl_reclaimblks -= fileblocks;
		if (listp->hfl_reclaimblks < 0)
			listp->hfl_reclaimblks = 0;
		blksmoved += fileblocks;
		filesmoved++;
delete:
		/* Start a new transaction before calling BTree code. */
		if (hfs_start_transaction(hfsmp) != 0) {
		    error = EINVAL;
		    break;
		}
		startedtrans = 1;

		error = BTDeleteRecord(filefork, iterator);
		if (error) {
			error = MacToVFSError(error);
			break;
		}
		savedtemp = key->temperature;
		key->temperature = HFC_LOOKUPTAG;
		error = BTDeleteRecord(filefork, iterator);
		if (error) {
			error = MacToVFSError(error);
			break;
		}
		key->temperature = savedtemp;
next:
		(void) BTFlushPath(filefork);

		/* Transaction complete. */
		if (startedtrans) {
			hfs_end_transaction(hfsmp);
			startedtrans = 0;
		}

	} /* end while */

#if HFC_VERBOSE
	printf("hfs: hotfiles_evict: moved %d files (%d blks, %d to go)\n", filesmoved, blksmoved, listp->hfl_reclaimblks);
#endif
	/* Finish any outstanding transactions. */
	if (startedtrans) {
		(void) BTFlushPath(filefork);
		hfs_end_transaction(hfsmp);
		startedtrans = 0;
	}
	hfs_unlock(VTOC(hfsmp->hfc_filevp));

	/*
	 * Move to next stage when finished.
	 */
	if (listp->hfl_reclaimblks <= 0) {
		stage = HFC_ADOPTION;
#if HFC_VERBOSE
		printf("hfs: hotfiles_evict: %d blocks free in hot file band\n", hfsmp->hfs_hotfile_freeblks);
#endif
	}
	FREE(iterator, M_TEMP);	
	hfsmp->hfc_stage = stage;
	wakeup((caddr_t)&hfsmp->hfc_stage);
	return (error);
}

/*
 * Age the existing records in the hot files b-tree.
 */
static int
hotfiles_age(struct hfsmount *hfsmp)
{
	BTreeInfoRec  btinfo;
	BTreeIterator * iterator = NULL;
	BTreeIterator * prev_iterator;
	FSBufferDescriptor  record;
	FSBufferDescriptor  prev_record;
	HotFileKey * key;
	HotFileKey * prev_key;
	filefork_t * filefork;
	u_int32_t  data;
	u_int32_t  prev_data;
	u_int32_t  newtemp;
	int  error;
	int  i;
	int  numrecs;
	int  aged = 0;
	u_int16_t  reclen;


	MALLOC(iterator, BTreeIterator *, 2 * sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		error = ENOMEM;
		goto out2;
	}
	bzero(iterator, 2 * sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;

	prev_iterator = &iterator[1];
	prev_key = (HotFileKey*) &prev_iterator->key;

	record.bufferAddress = &data;
	record.itemSize = sizeof(data);
	record.itemCount = 1;
	prev_record.bufferAddress = &prev_data;
	prev_record.itemSize = sizeof(prev_data);
	prev_record.itemCount = 1;

	/*
	 * Capture b-tree changes inside a transaction
	 */
	if (hfs_start_transaction(hfsmp) != 0) {
	    error = EINVAL;
	    goto out2;
	} 
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK) != 0) {
		error = EPERM;
		goto out1;
	}
	filefork = VTOF(hfsmp->hfc_filevp);

	error = BTGetInformation(filefork, 0, &btinfo);
	if (error) {
		error = MacToVFSError(error);
		goto out;
	}
	if (btinfo.numRecords < 2) {
		error = 0;
		goto out;
	}
	
	/* Only want 1st half of leaf records */
	numrecs = (btinfo.numRecords /= 2) - 1;

	error = BTIterateRecord(filefork, kBTreeFirstRecord, iterator, &record, &reclen);
	if (error) {
		printf("hfs_agehotfiles: BTIterateRecord: %d\n", error);
		error = MacToVFSError(error);
		goto out;
	}
	bcopy(iterator, prev_iterator, sizeof(BTreeIterator));
	prev_data = data;

	for (i = 0; i < numrecs; ++i) {
		error = BTIterateRecord(filefork, kBTreeNextRecord, iterator, &record, &reclen);
		if (error == 0) {
			if (key->temperature < prev_key->temperature) {
				printf("hfs_agehotfiles: out of order keys!\n");
				error = EFTYPE;
				break;
			}
			if (reclen != sizeof(data)) {
				printf("hfs_agehotfiles: invalid record length %d\n", reclen);
				error = EFTYPE;
				break;
			}
			if (key->keyLength != HFC_KEYLENGTH) {
				printf("hfs_agehotfiles: invalid key length %d\n", key->keyLength);
				error = EFTYPE;
				break;
			}
		} else if ((error == fsBTEndOfIterationErr || error == fsBTRecordNotFoundErr) &&
		    (i == (numrecs - 1))) {
			error = 0;
		} else if (error) {
			printf("hfs_agehotfiles: %d of %d BTIterateRecord: %d\n", i, numrecs, error);
			error = MacToVFSError(error);
			break;
		}
		if (prev_key->temperature == HFC_LOOKUPTAG) {
#if HFC_VERBOSE	
			printf("hfs_agehotfiles: ran into thread record\n");
#endif
			error = 0;
			break;
		}
		error = BTDeleteRecord(filefork, prev_iterator);
		if (error) {
			printf("hfs_agehotfiles: BTDeleteRecord failed %d (file %d)\n", error, prev_key->fileID);
			error = MacToVFSError(error);
			break;
		}
		
		/* Age by halving the temperature (floor = 4) */
		newtemp = MAX(prev_key->temperature >> 1, 4);
		prev_key->temperature = newtemp;
	
		error = BTInsertRecord(filefork, prev_iterator, &prev_record, prev_record.itemSize);
		if (error) {
			printf("hfs_agehotfiles: BTInsertRecord failed %d (file %d)\n", error, prev_key->fileID);
			error = MacToVFSError(error);
			break;
		}
		++aged;
		/*
		 * Update thread entry with latest temperature.
		 */
		prev_key->temperature = HFC_LOOKUPTAG;
		error = BTUpdateRecord(filefork, prev_iterator,
				(IterateCallBackProcPtr)update_callback,
				&newtemp);
		if (error) {
			printf("hfs_agehotfiles: %d of %d BTUpdateRecord failed %d (file %d, %d)\n",
				i, numrecs, error, prev_key->fileID, newtemp);
			error = MacToVFSError(error);
		//	break;
		}

		bcopy(iterator, prev_iterator, sizeof(BTreeIterator));
		prev_data = data;

	} /* end for */

#if HFC_VERBOSE	
	if (error == 0)
		printf("hfs_agehotfiles: aged %d records out of %d\n", aged, btinfo.numRecords);
#endif
	(void) BTFlushPath(filefork);
out:
	hfs_unlock(VTOC(hfsmp->hfc_filevp));
out1:
	hfs_end_transaction(hfsmp);
out2:
	if (iterator)
		FREE(iterator, M_TEMP);	
	return (error);
}

/*
 * Return true if any blocks (or all blocks if all is true)
 * are contained in the hot file region.
 */
static int
hotextents(struct hfsmount *hfsmp, HFSPlusExtentDescriptor * extents)
{
	u_int32_t  b1, b2;
	int  i;
	int  inside = 0;

	for (i = 0; i < kHFSPlusExtentDensity; ++i) {
		b1 = extents[i].startBlock;
		if (b1 == 0)
			break;
		b2 = b1 + extents[i].blockCount - 1;
		if ((b1 >= hfsmp->hfs_hotfile_start &&
		     b2 <= hfsmp->hfs_hotfile_end) ||
		    (b1 < hfsmp->hfs_hotfile_end && 
		     b2 > hfsmp->hfs_hotfile_end)) {
			inside = 1;
			break;
		}
	}
	return (inside);
}


/*
 *========================================================================
 *                       HOT FILE B-TREE ROUTINES
 *========================================================================
 */

/*
 * Open the hot files b-tree for writing.
 *
 * On successful exit the vnode has a reference but not an iocount.
 */
static int
hfc_btree_open(struct hfsmount *hfsmp, struct vnode **vpp)
{
	proc_t p;
	struct vnode *vp;
	struct cat_desc  cdesc;
	struct cat_attr  cattr;
	struct cat_fork  cfork;
	static char filename[] = HFC_FILENAME;
	int  error;
	int  retry = 0;
	int lockflags;

	*vpp = NULL;
	p = current_proc();

	bzero(&cdesc, sizeof(cdesc));
	cdesc.cd_parentcnid = kRootDirID;
	cdesc.cd_nameptr = (const u_int8_t *)filename;
	cdesc.cd_namelen = strlen(filename);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	error = cat_lookup(hfsmp, &cdesc, 0, &cdesc, &cattr, &cfork, NULL);

	hfs_systemfile_unlock(hfsmp, lockflags);

	if (error) {
		printf("hfs: hfc_btree_open: cat_lookup error %d\n", error);
		return (error);
	}
again:
	cdesc.cd_flags |= CD_ISMETA;
	error = hfs_getnewvnode(hfsmp, NULL, NULL, &cdesc, 0, &cattr, &cfork, &vp);
	if (error) {
		printf("hfs: hfc_btree_open: hfs_getnewvnode error %d\n", error);
		cat_releasedesc(&cdesc);
		return (error);
	}
	if (!vnode_issystem(vp)) {
#if HFC_VERBOSE
		printf("hfs: hfc_btree_open: file has UBC, try again\n");
#endif
		hfs_unlock(VTOC(vp));
		vnode_recycle(vp);
		vnode_put(vp);
		if (retry++ == 0)
			goto again;
		else
			return (EBUSY);
	}

	/* Open the B-tree file for writing... */
	error = BTOpenPath(VTOF(vp), (KeyCompareProcPtr) hfc_comparekeys);	
	if (error) {
		printf("hfs: hfc_btree_open: BTOpenPath error %d\n", error);
		error = MacToVFSError(error);
	}

	hfs_unlock(VTOC(vp));
	if (error == 0) {
		*vpp = vp;
		vnode_ref(vp);  /* keep a reference while its open */
	}
	vnode_put(vp);

	if (!vnode_issystem(vp))
		panic("hfs: hfc_btree_open: not a system file (vp = %p)", vp);

	return (error);
}

/*
 * Close the hot files b-tree.
 *
 * On entry the vnode has a reference.
 */
static int
hfc_btree_close(struct hfsmount *hfsmp, struct vnode *vp)
{
	proc_t p = current_proc();
	int  error = 0;


	if (hfsmp->jnl) {
	    hfs_journal_flush(hfsmp);
	}

	if (vnode_get(vp) == 0) {
		error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK);
		if (error == 0) {
			(void) hfs_fsync(vp, MNT_WAIT, 0, p);
			error = BTClosePath(VTOF(vp));
			hfs_unlock(VTOC(vp));
		}
		vnode_rele(vp);
		vnode_recycle(vp);
		vnode_put(vp);
	}
	
	return (error);
}

/*
 *  Create a hot files btree file.
 *
 */
static int
hfc_btree_create(struct hfsmount *hfsmp, unsigned int nodesize, unsigned int entries)
{
	struct vnode *dvp = NULL;
	struct vnode *vp = NULL;
	struct cnode *cp = NULL;
	vfs_context_t ctx = vfs_context_current();
	struct vnode_attr va;
	struct componentname cname;
	static char filename[] = HFC_FILENAME;
	int  error;

	if (hfsmp->hfc_filevp)
		panic("hfs: hfc_btree_create: hfc_filevp exists (vp = %p)", hfsmp->hfc_filevp);

	error = VFS_ROOT(HFSTOVFS(hfsmp), &dvp, ctx);
	if (error) {
		return (error);
	}
	cname.cn_nameiop = CREATE;
	cname.cn_flags = ISLASTCN;
	cname.cn_context = ctx;
	cname.cn_pnbuf = filename;
	cname.cn_pnlen = sizeof(filename);
	cname.cn_nameptr = filename;
	cname.cn_namelen = strlen(filename);
	cname.cn_hash = 0;
	cname.cn_consume = 0;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_type, VREG);
	VATTR_SET(&va, va_mode, S_IFREG | S_IRUSR | S_IWUSR);
	VATTR_SET(&va, va_uid, 0);
	VATTR_SET(&va, va_gid, 0);

	/* call ourselves directly, ignore the higher-level VFS file creation code */
	error = VNOP_CREATE(dvp, &vp, &cname, &va, ctx);
	if (error) {
		printf("hfs: error %d creating HFBT on %s\n", error, HFSTOVCB(hfsmp)->vcbVN);
		goto out;
	}
	if (dvp) {
		vnode_put(dvp);
		dvp = NULL;
	}
	if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK))) {
		goto out;
	}
	cp = VTOC(vp);

	/* Don't use non-regular files or files with links. */
	if (!vnode_isreg(vp) || cp->c_linkcount != 1) {
		error = EFTYPE;
		goto out;
	}

	printf("hfs: created HFBT on %s\n", HFSTOVCB(hfsmp)->vcbVN);

	if (VTOF(vp)->ff_size < nodesize) {
		caddr_t  buffer;
		u_int16_t *index;
		u_int16_t  offset;
		BTNodeDescriptor  *ndp;
		BTHeaderRec  *bthp;
		HotFilesInfo *hotfileinfo;
		int  nodecnt;
		int  filesize;
		int  entirespernode;

		/*
		 * Mark it invisible (truncate will pull these changes).
		 */
		((FndrFileInfo *)&cp->c_finderinfo[0])->fdFlags |=
			SWAP_BE16 (kIsInvisible + kNameLocked);

		if (kmem_alloc(kernel_map, (vm_offset_t *)&buffer, nodesize)) {
			error = ENOMEM;
			goto out;
		}	
		bzero(buffer, nodesize);
		index = (u_int16_t *)buffer;
	
		entirespernode = (nodesize - sizeof(BTNodeDescriptor) - 2) /
				 (sizeof(HotFileKey) + 6);
		nodecnt = 2 + howmany(entries * 2, entirespernode);
		nodecnt = roundup(nodecnt, 8);
		filesize = nodecnt * nodesize;
	
		/* FILL IN THE NODE DESCRIPTOR:  */
		ndp = (BTNodeDescriptor *)buffer;
		ndp->kind = kBTHeaderNode;
		ndp->numRecords = SWAP_BE16 (3);
		offset = sizeof(BTNodeDescriptor);
		index[(nodesize / 2) - 1] = SWAP_BE16 (offset);
	
		/* FILL IN THE HEADER RECORD:  */
		bthp = (BTHeaderRec *)((u_int8_t *)buffer + offset);
		bthp->nodeSize     = SWAP_BE16 (nodesize);
		bthp->totalNodes   = SWAP_BE32 (filesize / nodesize);
		bthp->freeNodes    = SWAP_BE32 (nodecnt - 1);
		bthp->clumpSize    = SWAP_BE32 (filesize);
		bthp->btreeType    = kUserBTreeType; /* non-metadata */
		bthp->attributes  |= SWAP_BE32 (kBTBigKeysMask);
		bthp->maxKeyLength = SWAP_BE16 (HFC_KEYLENGTH);
		offset += sizeof(BTHeaderRec);
		index[(nodesize / 2) - 2] = SWAP_BE16 (offset);
	
		/* FILL IN THE USER RECORD:  */
		hotfileinfo = (HotFilesInfo *)((u_int8_t *)buffer + offset);
		hotfileinfo->magic       = SWAP_BE32 (HFC_MAGIC);
		hotfileinfo->version     = SWAP_BE32 (HFC_VERSION);
		hotfileinfo->duration    = SWAP_BE32 (HFC_DEFAULT_DURATION);
		hotfileinfo->timebase    = 0;
		hotfileinfo->timeleft    = 0;
		hotfileinfo->threshold   = SWAP_BE32 (HFC_MINIMUM_TEMPERATURE);
		hotfileinfo->maxfileblks = SWAP_BE32 (HFC_MAXIMUM_FILESIZE / HFSTOVCB(hfsmp)->blockSize);
		hotfileinfo->maxfilecnt  = SWAP_BE32 (HFC_DEFAULT_FILE_COUNT);
		strlcpy((char *)hotfileinfo->tag, hfc_tag,
			sizeof hotfileinfo->tag);
		offset += kBTreeHeaderUserBytes;
		index[(nodesize / 2) - 3] = SWAP_BE16 (offset);
	
		/* FILL IN THE MAP RECORD (only one node in use). */
		*((u_int8_t *)buffer + offset) = 0x80;
		offset += nodesize - sizeof(BTNodeDescriptor) - sizeof(BTHeaderRec)
				   - kBTreeHeaderUserBytes - (4 * sizeof(int16_t));
		index[(nodesize / 2) - 4] = SWAP_BE16 (offset);

		vnode_setnoflush(vp);
		error = hfs_truncate(vp, (off_t)filesize, IO_NDELAY, 0, 0, ctx);
		if (error) {
			printf("hfs: error %d growing HFBT on %s\n", error, HFSTOVCB(hfsmp)->vcbVN);
			goto out;
		}
		cp->c_flag |= C_ZFWANTSYNC;
		cp->c_zftimeout = 1;
		
		if (error == 0) {
			struct vnop_write_args args;
			uio_t auio;

			auio = uio_create(1, 0, UIO_SYSSPACE, UIO_WRITE);
			uio_addiov(auio, (uintptr_t)buffer, nodesize);

			args.a_desc = &vnop_write_desc;
			args.a_vp = vp;
			args.a_uio = auio;
			args.a_ioflag = 0;
			args.a_context = ctx;

			hfs_unlock(cp);
			cp = NULL;

			error = hfs_vnop_write(&args);
			if (error)
				printf("hfs: error %d writing HFBT on %s\n", error, HFSTOVCB(hfsmp)->vcbVN);

			uio_free(auio);
		}
		kmem_free(kernel_map, (vm_offset_t)buffer, nodesize);
	}
out:
	if (dvp) {
		vnode_put(dvp);
	}
	if (vp) {
		if (cp)
			hfs_unlock(cp);
		vnode_recycle(vp);
		vnode_put(vp);
	}
	return (error);
}

/*
 * Compare two hot file b-tree keys.
 *
 * Result:   +n  search key > trial key
 *            0  search key = trial key
 *           -n  search key < trial key
 */
static int
hfc_comparekeys(HotFileKey *searchKey, HotFileKey *trialKey)
{
	/*
	 * Compared temperatures first.
	 */
	if (searchKey->temperature == trialKey->temperature) {
		/*
		 * Temperatures are equal so compare file ids.
		 */
		if (searchKey->fileID == trialKey->fileID) {
			/*
			 * File ids are equal so compare fork types.
			 */
			if (searchKey->forkType == trialKey->forkType) {
				return (0);
			} else if (searchKey->forkType > trialKey->forkType) {
				return (1);
			}
		} else if (searchKey->fileID > trialKey->fileID) {
			return (1);
		}
	} else if (searchKey->temperature > trialKey->temperature) {
		return (1);
	}
	
	return (-1);
}


/*
 *========================================================================
 *               HOT FILE DATA COLLECTING ROUTINES
 *========================================================================
 */

/*
 * Lookup a hot file entry in the tree.
 */
#if HFC_DEBUG
static hotfile_entry_t *
hf_lookup(hotfile_data_t *hotdata, u_int32_t fileid, u_int32_t temperature)
{
	hotfile_entry_t *entry = hotdata->rootentry;

	while (entry &&
	       entry->temperature != temperature &&
	       entry->fileid != fileid) {

		if (temperature > entry->temperature)
			entry = entry->right;
		else if (temperature < entry->temperature)
			entry = entry->left;
		else if (fileid > entry->fileid)
			entry = entry->right;
		else
			entry = entry->left;
	}
	return (entry);
}
#endif

/*
 * Insert a hot file entry into the tree.
 */
static void
hf_insert(hotfile_data_t *hotdata, hotfile_entry_t *newentry) 
{
	hotfile_entry_t *entry = hotdata->rootentry;
	u_int32_t fileid = newentry->fileid;
	u_int32_t temperature = newentry->temperature;

	if (entry == NULL) {
		hotdata->rootentry = newentry;
		hotdata->coldest = newentry;
		hotdata->activefiles++;
		return;
	}

	while (entry) {
		if (temperature > entry->temperature) {
			if (entry->right)
				entry = entry->right;
			else {
				entry->right = newentry;
				break;
			}
		} else if (temperature < entry->temperature) {
			if (entry->left) 
				entry = entry->left;
			else {
			    	entry->left = newentry;
				break;
			}
		} else if (fileid > entry->fileid) { 
			if (entry->right)
				entry = entry->right;
			else {
	       			if (entry->fileid != fileid)
					entry->right = newentry;
				break;
			}
		} else { 
			if (entry->left) 
				entry = entry->left;
			else {
	       			if (entry->fileid != fileid)
			    		entry->left = newentry;
				break;
			}
		}
	}

	hotdata->activefiles++;
}

/*
 * Find the coldest entry in the tree.
 */
static hotfile_entry_t *
hf_coldest(hotfile_data_t *hotdata)
{
	hotfile_entry_t *entry = hotdata->rootentry;

	if (entry) {
		while (entry->left)
			entry = entry->left;
	}
	return (entry);
}

/*
 * Find the hottest entry in the tree.
 */
static hotfile_entry_t *
hf_hottest(hotfile_data_t *hotdata)
{
	hotfile_entry_t *entry = hotdata->rootentry;

	if (entry) {
		while (entry->right)
			entry = entry->right;
	}
	return (entry);
}

/*
 * Delete a hot file entry from the tree.
 */
static void
hf_delete(hotfile_data_t *hotdata, u_int32_t fileid, u_int32_t temperature)
{
	hotfile_entry_t *entry, *parent, *next;

	parent = NULL;
	entry = hotdata->rootentry;

	while (entry &&
	       entry->temperature != temperature &&
	       entry->fileid != fileid) {

		parent = entry;
		if (temperature > entry->temperature)
			entry = entry->right;
		else if (temperature < entry->temperature)
			entry = entry->left;
		else if (fileid > entry->fileid)
			entry = entry->right;
		else
			entry = entry->left;
	}

	if (entry) {
		/*
		 * Reorginize the sub-trees spanning from our entry.
		 */
		if ((next = entry->right)) {
			hotfile_entry_t *pnextl, *psub;
			/*
			 * Tree pruning: take the left branch of the
			 * current entry and place it at the lowest
			 * left branch of the current right branch 
			 */
			psub = next;
			
			/* Walk the Right/Left sub tree from current entry */
			while ((pnextl = psub->left))
				psub = pnextl;	
			
			/* Plug the old left tree to the new ->Right leftmost entry */	
			psub->left = entry->left;
	
		} else /* only left sub-tree, simple case */ {  
			next = entry->left;
		}
		/* 
		 * Now, plug the current entry sub tree to
		 * the good pointer of our parent entry.
		 */
		if (parent == NULL)
			hotdata->rootentry = next;
		else if (parent->left == entry)
			parent->left = next;
		else
			parent->right = next;	
		
		/* Place entry back on the free-list */
		entry->left = 0;
		entry->fileid = 0;
		entry->temperature = 0;

		entry->right = hotdata->freelist; 
		hotdata->freelist = entry; 		
		hotdata->activefiles--;
		
		if (hotdata->coldest == entry || hotdata->coldest == NULL) {
			hotdata->coldest = hf_coldest(hotdata);
		}

	}
}

/*
 * Get a free hot file entry.
 */
static hotfile_entry_t *
hf_getnewentry(hotfile_data_t *hotdata)
{
	hotfile_entry_t * entry;
	
	/*
	 * When the free list is empty then steal the coldest one
	 */
	if (hotdata->freelist == NULL) {
		entry = hf_coldest(hotdata);
		hf_delete(hotdata, entry->fileid, entry->temperature);
	}
	entry = hotdata->freelist;
	hotdata->freelist = entry->right;
	entry->right = 0;
	
	return (entry);
}


/*
 * Generate a sorted list of hot files (hottest to coldest).
 *
 * As a side effect, every node in the hot file tree will be
 * deleted (moved to the free list).
 */
static void
hf_getsortedlist(hotfile_data_t * hotdata, hotfilelist_t *sortedlist)
{
	int i = 0;
	hotfile_entry_t *entry;
	
	while ((entry = hf_hottest(hotdata)) != NULL) {
		sortedlist->hfl_hotfile[i].hf_fileid = entry->fileid;
		sortedlist->hfl_hotfile[i].hf_temperature = entry->temperature;
		sortedlist->hfl_hotfile[i].hf_blocks = entry->blocks;
		sortedlist->hfl_totalblocks += entry->blocks;
		++i;

		hf_delete(hotdata, entry->fileid, entry->temperature);
	}
	
	sortedlist->hfl_count = i;
	
#if HFC_VERBOSE
	printf("hfs: hf_getsortedlist returned %d entries\n", i);
#endif
}


#if HFC_DEBUG
static void
hf_maxdepth(hotfile_entry_t * root, int depth, int *maxdepth)
{
	if (root) {
		depth++;
		if (depth > *maxdepth)
			*maxdepth = depth;
		hf_maxdepth(root->left, depth, maxdepth);
		hf_maxdepth(root->right, depth, maxdepth);
	}
}

static void
hf_printtree(hotfile_entry_t * root)
{
	if (root) {
		hf_printtree(root->left);
		printf("hfs: temperature: % 8d, fileid %d\n", root->temperature, root->fileid);
		hf_printtree(root->right);
	}
}
#endif
