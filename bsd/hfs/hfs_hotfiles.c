/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/ubc.h>
#include <sys/vnode.h>

#include <hfs/hfs.h>
#include <hfs/hfs_endian.h>
#include <hfs/hfs_format.h>
#include <hfs/hfs_mount.h>
#include <hfs/hfs_hotfiles.h>

#include "hfscommon/headers/BTreeScanner.h"


#define HFC_DEBUG  0
#define HFC_VERBOSE 0



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



/*
 * Hot File Data recording functions (in-memory binary tree).
 */
static void              hf_insert (hotfile_data_t *, hotfile_entry_t *);
static void              hf_delete (hotfile_data_t *, u_int32_t, u_int32_t);
static hotfile_entry_t * hf_lookup (hotfile_data_t *, u_int32_t, u_int32_t);
static hotfile_entry_t * hf_coldest (hotfile_data_t *);
static hotfile_entry_t * hf_getnewentry (hotfile_data_t *);
static int               hf_getsortedlist (hotfile_data_t *, hotfilelist_t *);
static void              hf_printtree (hotfile_entry_t *);

/*
 * Hot File misc support functions.
 */
static int  hotfiles_collect (struct hfsmount *, struct proc *);
static int  hotfiles_age (struct hfsmount *, struct proc *);
static int  hotfiles_adopt (struct hfsmount *, struct proc *);
static int  hotfiles_evict (struct hfsmount *, struct proc *);
static int  hotfiles_refine (struct hfsmount *, struct proc *);
static int  hotextents(struct hfsmount *, HFSPlusExtentDescriptor *);

/*
 * Hot File Cluster B-tree (on disk) functions.
 */
static int  hfc_btree_create (struct hfsmount *, int, int);
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
 */
__private_extern__
int
hfs_recording_start(struct hfsmount *hfsmp, struct proc *p)
{
	hotfile_data_t *hotdata;
	int maxentries;
	size_t size;
	int i;
	int error;

	if ((hfsmp->hfs_flags & HFS_READ_ONLY) ||
	    (hfsmp->jnl == NULL) ||
	    (hfsmp->hfs_flags & HFS_METADATA_ZONE) == 0) {
		return (EPERM);
	}
	if (HFSTOVCB(hfsmp)->freeBlocks < (2 * hfsmp->hfs_hotfile_maxblks)) {
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
			hfsmp->hfc_timeout = SWAP_BE32 (hotfileinfo.timeleft) + time.tv_sec ;
			hfsmp->hfc_timebase = SWAP_BE32 (hotfileinfo.timebase);
#if HFC_VERBOSE
			printf("HFS: resume recording hot files (%d left)\n", SWAP_BE32 (hotfileinfo.timeleft));
#endif
		} else {
			hfsmp->hfc_maxfiles = HFC_DEFAULT_FILE_COUNT;
			hfsmp->hfc_timebase = time.tv_sec + 1;
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
		printf("HFS: begin recording hot files\n");
#endif
		hfsmp->hfc_maxfiles = HFC_DEFAULT_FILE_COUNT;
		hfsmp->hfc_timeout = time.tv_sec + HFC_DEFAULT_DURATION;

		/* Reset time base.  */
		if (hfsmp->hfc_timebase == 0) {
			hfsmp->hfc_timebase = time.tv_sec + 1;
		} else {
			u_int32_t cumulativebase;
			u_int32_t oldbase = hfsmp->hfc_timebase;

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
out:
	hfsmp->hfc_stage = HFC_RECORDING;
	wakeup((caddr_t)&hfsmp->hfc_stage);
	return (0);
}

/*
 * Stop recording the hotest files on a file system.
 */
__private_extern__
int
hfs_recording_stop(struct hfsmount *hfsmp, struct proc *p)
{
	hotfile_data_t *hotdata;
	hotfilelist_t  *listp;
	size_t  size;
	enum hfc_stage newstage = HFC_IDLE;
	void * tmp;
	int  error;


	if (hfsmp->hfc_stage != HFC_RECORDING)
		return (EPERM);

	hotfiles_collect(hfsmp, p);

	if (hfsmp->hfc_stage != HFC_RECORDING)
		return (0);

	hfsmp->hfc_stage = HFC_BUSY;

	/*
	 * Convert hot file data into a simple file id list....
	 *
	 * then dump the sample data
	 */
#if HFC_VERBOSE
	printf("HFS: end of hot file recording\n");
#endif
	hotdata = (hotfile_data_t *)hfsmp->hfc_recdata;
	if (hotdata == NULL)
		return (0);
	hfsmp->hfc_recdata = NULL;
	hfsmp->hfc_stage = HFC_EVALUATION;
	wakeup((caddr_t)&hfsmp->hfc_stage);

#if HFC_VERBOSE
	printf("  curentries: %d\n", hotdata->activefiles);
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
		panic("hfs_recording_stop: hfc_filevp exists (vp = 0x%08x)", hfsmp->hfc_filevp);

	error = hfc_btree_open(hfsmp, &hfsmp->hfc_filevp);
	if (error) {
		goto out;
	}

	/*
	 * Age the previous set of clustered hot files.
	 */
	error = hotfiles_age(hfsmp, p);
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
	bzero(listp, size);

	hf_getsortedlist(hotdata, listp);
	listp->hfl_duration = time.tv_sec - hfsmp->hfc_timebase;
	hfsmp->hfc_recdata = listp;

	/*
	 * Account for duplicates.
	 */
	error = hotfiles_refine(hfsmp, p);
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
		printf("HFS: evicting coldest files\n");
	else if (newstage == HFC_ADOPTION)
		printf("HFS: adopting hotest files\n");
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
hfs_recording_suspend(struct hfsmount *hfsmp, struct proc *p)
{
	HotFilesInfo hotfileinfo;
	hotfile_data_t *hotdata;
	int  error;

	if (hfsmp->hfc_stage != HFC_RECORDING)
		return (0);

	hotdata = (hotfile_data_t *)hfsmp->hfc_recdata;
	if (hotdata == NULL) {
		hfsmp->hfc_stage = HFC_DISABLED;
		return (0);
	}
	hfsmp->hfc_stage = HFC_BUSY;

#if HFC_VERBOSE
	printf("HFS: suspend hot file recording\n");
#endif
	error = hfc_btree_open(hfsmp, &hfsmp->hfc_filevp);
	if (error) {
		printf("hfs_recording_suspend: err %d opening btree\n", error);
		goto out;
	}

	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
		if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			error = EINVAL;
			goto out;
		}
	}
	vn_lock(hfsmp->hfc_filevp, LK_EXCLUSIVE | LK_RETRY, p);

	hotfileinfo.magic       = SWAP_BE32 (HFC_MAGIC);
	hotfileinfo.version     = SWAP_BE32 (HFC_VERSION);
	hotfileinfo.duration    = SWAP_BE32 (HFC_DEFAULT_DURATION);
	hotfileinfo.timebase    = SWAP_BE32 (hfsmp->hfc_timebase);
	hotfileinfo.timeleft    = SWAP_BE32 (hfsmp->hfc_timeout - time.tv_sec);
	hotfileinfo.threshold   = SWAP_BE32 (hotdata->threshold);
	hotfileinfo.maxfileblks = SWAP_BE32 (hotdata->maxblocks);
	hotfileinfo.maxfilecnt  = SWAP_BE32 (HFC_DEFAULT_FILE_COUNT);
	strcpy(hotfileinfo.tag, hfc_tag);
	(void) BTSetUserData(VTOF(hfsmp->hfc_filevp), &hotfileinfo, sizeof(hotfileinfo));

	(void) VOP_UNLOCK(hfsmp->hfc_filevp, 0, p);
	if (hfsmp->jnl) {
		journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);

	(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
	hfsmp->hfc_filevp = NULL;
out:
	FREE(hotdata, M_TEMP);

	hfsmp->hfc_stage = HFC_DISABLED;
	wakeup((caddr_t)&hfsmp->hfc_stage);
	return (error);
}

/*
 * Abort a hot file recording session.
 */
__private_extern__
int
hfs_recording_abort(struct hfsmount *hfsmp, struct proc *p)
{
	void * tmp;

	if (hfsmp->hfc_stage == HFC_DISABLED)
		return (0);
	
	if (hfsmp->hfc_stage == HFC_BUSY) {
		(void) tsleep((caddr_t)&hfsmp->hfc_stage, PINOD, "hfs_recording_abort", 0);
	}
	hfsmp->hfc_stage = HFC_BUSY;

	printf("HFS: terminate hot file recording\n");

	if (hfsmp->hfc_recdata) {
		tmp = hfsmp->hfc_recdata;
		hfsmp->hfc_recdata = NULL;
		FREE(tmp, M_TEMP);
	}
	hfsmp->hfc_stage = HFC_DISABLED;
	wakeup((caddr_t)&hfsmp->hfc_stage);
	return (0);
}

/*
 *
 */
__private_extern__
int
hfs_recording_init(struct hfsmount *hfsmp, struct proc *p)
{
	CatalogKey * keyp;
	CatalogRecord * datap;
	u_int32_t  dataSize;
	HFSPlusCatalogFile *filep;
	BTScanState scanstate;
	BTreeIterator * iterator;
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
	 * If the Hot File btree exists then metadata zone is ready.
	 */
	cnid = GetFileInfo(HFSTOVCB(hfsmp), kRootDirID, HFC_FILENAME, &cattr, NULL);
	if (cnid != 0 && S_ISREG(cattr.ca_mode)) {
		if (hfsmp->hfc_stage == HFC_DISABLED)
			hfsmp->hfc_stage = HFC_IDLE;
		return (0);
	}
	/*
	 * For now, only the boot volume is supported.
	 */
	if ((HFSTOVFS(hfsmp)->mnt_flag & MNT_ROOTFS) == 0) {
		hfsmp->hfs_flags &= ~HFS_METADATA_ZONE;
		return (EPERM);
	}
	error = hfc_btree_create(hfsmp, HFSTOVCB(hfsmp)->blockSize, HFC_DEFAULT_FILE_COUNT);
	if (error) {
		return (error);
	}
	/*
	 * Open the Hot File B-tree file for writing.
	 */
	if (hfsmp->hfc_filevp)
		panic("hfs_recording_init: hfc_filevp exists (vp = 0x%08x)", hfsmp->hfc_filevp);
	error = hfc_btree_open(hfsmp, &hfsmp->hfc_filevp);
	if (error) {
		return (error);
	}
	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;
	key->keyLength = HFC_KEYLENGTH;

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;
#if HFC_VERBOSE
	printf("Evaluating space for \"%s\" metadata zone...\n", HFSTOVCB(hfsmp)->vcbVN);
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
	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
		if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			error = EINVAL;
			goto out1;
		}
	} 
	vn_lock(hfsmp->hfc_filevp, LK_EXCLUSIVE | LK_RETRY, p);
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
		error = BTInsertRecord(filefork, iterator, &record, sizeof(data));
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
		error = BTInsertRecord(filefork, iterator, &record, sizeof(data));
		if (error) {
			printf("hfs_recording_init: BTInsertRecord failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}
		inserted++;
	}
	(void) BTFlushPath(filefork);
	(void) VOP_UNLOCK(hfsmp->hfc_filevp, 0, p);

	if (hfsmp->jnl) {
		journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);
#if HFC_VERBOSE
	printf("%d files identified out of %d\n", inserted, filecount);
#endif
	
out1:
	(void) BTScanTerminate(&scanstate, &data, &data, &data);
out2:	
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
hfs_hotfilesync(struct hfsmount *hfsmp, struct proc *p)
{
	if ((HFSTOVFS(hfsmp)->mnt_kern_flag & MNTK_UNMOUNT) == 0 && hfsmp->hfc_stage) {
		switch (hfsmp->hfc_stage) {
		case HFC_IDLE:
			(void) hfs_recording_start(hfsmp, p);
			break;
	
		case HFC_RECORDING:
			if (time.tv_sec > hfsmp->hfc_timeout)
				(void) hfs_recording_stop(hfsmp, p);
			break;
	
		case HFC_EVICTION:
			(void) hotfiles_evict(hfsmp, p);
			break;
	
		case HFC_ADOPTION:
			(void) hotfiles_adopt(hfsmp, p);
			break;
		}
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
 */
__private_extern__
int
hfs_addhotfile(struct vnode *vp)
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
	
	if (!(vp->v_type == VREG || vp->v_type == VLNK) ||
	     (vp->v_flag & (VSYSTEM | VSWAP))) {
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
 * Remove a hot file to the recording list.
 *
 * This can happen when a hot file becomes
 * an active vnode (active hot files are
 * not kept in the recording list until the
 * end of the recording period).
 *
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

	if (!(vp->v_type == VREG || vp->v_type == VLNK) ||
	     (vp->v_flag & (VSYSTEM | VSWAP))) {
		return (0);
	}
	if ((hotdata = (hotfile_data_t *)hfsmp->hfc_recdata) == NULL)
		return (0);

	ffp = VTOF(vp);
	cp = VTOC(vp);

	if ((ffp->ff_bytesread == 0) || (ffp->ff_blocks == 0) ||
	    (cp->c_atime < hfsmp->hfc_timebase)) {
		return (0);
	}

	temperature = ffp->ff_bytesread / ffp->ff_size;
	if (temperature < hotdata->threshold)
		return (0);

	if (hotdata->coldest && (temperature >= hotdata->coldest->temperature)) {
		++hotdata->refcount;
		hf_delete(hotdata, VTOC(vp)->c_fileid, temperature);
		--hotdata->refcount;
	}

	return (0);
}


/*
 *========================================================================
 *                     HOT FILE MAINTENANCE ROUTINES
 *========================================================================
 */

/*
 * Add all active hot files to the recording list.
 */
static int
hotfiles_collect(struct hfsmount *hfsmp, struct proc *p)
{
	struct mount *mp = HFSTOVFS(hfsmp);
	struct vnode *nvp, *vp;
	struct cnode *cp;
	int error;

	if (vfs_busy(mp, LK_NOWAIT, 0, p))
		return (0);
loop:
	simple_lock(&mntvnode_slock);
	for (vp = mp->mnt_vnodelist.lh_first; vp != NULL; vp = nvp) {
		if (vp->v_mount != mp) {
			simple_unlock(&mntvnode_slock);
			goto loop;
		}
		simple_lock(&vp->v_interlock);
		nvp = vp->v_mntvnodes.le_next;

		if ((vp->v_flag & VSYSTEM) ||
		    !(vp->v_type == VREG || vp->v_type == VLNK)) {
			simple_unlock(&vp->v_interlock);
			continue;
		}

		cp = VTOC(vp);
		if (cp == NULL || vp->v_flag & (VXLOCK|VORECLAIM)) {
			simple_unlock(&vp->v_interlock);
			continue;
		}

		simple_unlock(&mntvnode_slock);
		error = vget(vp, LK_EXCLUSIVE | LK_NOWAIT | LK_INTERLOCK, p);
		if (error) {
			if (error == ENOENT)
				goto loop;
			simple_lock(&mntvnode_slock);
			continue;
		}
		(void) hfs_addhotfile(vp);
		vput(vp);

		simple_lock(&mntvnode_slock);
	}

	simple_unlock(&mntvnode_slock);

	vfs_unbusy(mp, p);

	return (0);
}


/*
 * Update the data of a btree record
 * This is called from within BTUpdateRecord.
 */
static int
update_callback(const HotFileKey *key, u_int32_t *data, u_int16_t datalen, u_int32_t *state)
{
	if (key->temperature == HFC_LOOKUPTAG)
		*data = *state;
	return (0);
}

/*
 * Identify files already in hot area.
 */
static int
hotfiles_refine(struct hfsmount *hfsmp, struct proc *p)
{
	BTreeIterator * iterator;
	struct mount *mp;
	struct vnode *vp;
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
	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;

	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
		if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			error = EINVAL;
			goto out;
		}
	} 
	vn_lock(hfsmp->hfc_filevp, LK_EXCLUSIVE | LK_RETRY, p);
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
			printf("hotfiles_refine: BTUpdateRecord failed %d (file %d)\n", error, key->fileID);
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
			printf("hotfiles_refine: BTDeleteRecord failed %d (file %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}
		key->keyLength = HFC_KEYLENGTH;
		key->temperature = listp->hfl_hotfile[i].hf_temperature;
		key->fileID = listp->hfl_hotfile[i].hf_fileid;
		key->forkType = 0;
		error = BTInsertRecord(filefork, iterator, &record, sizeof(data));
		if (error) {
			printf("hotfiles_refine: BTInsertRecord failed %d (file %d)\n", error, key->fileID);
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
	(void) VOP_UNLOCK(hfsmp->hfc_filevp, 0, p);

	if (hfsmp->jnl) {
		journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);
out:
	FREE(iterator, M_TEMP);	
	return (error);
}

/*
 * Move new hot files into hot area.
 */
static int
hotfiles_adopt(struct hfsmount *hfsmp, struct proc *p)
{
	BTreeIterator * iterator;
	struct mount *mp;
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
	int  aquiredlock = 0;

	if ((listp = (hotfilelist_t  *)hfsmp->hfc_recdata) == NULL)
		return (0);	

	if (hfsmp->hfc_stage != HFC_ADOPTION) {
		return (EBUSY);
	}
	stage = hfsmp->hfc_stage;
	hfsmp->hfc_stage = HFC_BUSY;

	mp = HFSTOVFS(hfsmp);
	blksmoved = 0;
	last = listp->hfl_next + HFC_FILESPERSYNC;
	if (last > listp->hfl_count)
		last = listp->hfl_count;

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;
	key->keyLength = HFC_KEYLENGTH;

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;

	vn_lock(hfsmp->hfc_filevp, LK_EXCLUSIVE | LK_RETRY, p);
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
		error = VFS_VGET(mp, &listp->hfl_hotfile[i].hf_fileid, &vp);
		if (error) {
			if (error == ENOENT) {
				error = 0;
				listp->hfl_next++;
				continue;  /* stale entry, go to next */
			}
			break;
		}
		if (vp->v_type != VREG && vp->v_type != VLNK) {
			printf("hotfiles_adopt: huh, not a file %d (%d)\n", listp->hfl_hotfile[i].hf_fileid, VTOC(vp)->c_cnid);
			vput(vp);
			listp->hfl_hotfile[i].hf_temperature == 0;
			listp->hfl_next++;
			continue;  /* stale entry, go to next */
		}
		if (hotextents(hfsmp, &VTOF(vp)->ff_extents[0])) {
			vput(vp);
			listp->hfl_hotfile[i].hf_temperature == 0;
			listp->hfl_next++;
			listp->hfl_totalblocks -= listp->hfl_hotfile[i].hf_blocks;
			continue;  /* stale entry, go to next */
		}
		fileblocks = VTOF(vp)->ff_blocks;
		if (fileblocks > hfsmp->hfs_hotfile_freeblks) {
			vput(vp);
			listp->hfl_next++;
			listp->hfl_totalblocks -= fileblocks;
			continue;  /* entry too big, go to next */
		}
		
		if ((blksmoved > 0) &&
		    (blksmoved + fileblocks) > HFC_BLKSPERSYNC) {
			vput(vp);
			break;
		}
		/* Start a new transaction. */
		hfs_global_shared_lock_acquire(hfsmp);
		aquiredlock = 1;
		if (hfsmp->jnl) {
			if (journal_start_transaction(hfsmp->jnl) != 0) {
				error = EINVAL;
				vput(vp);
				break;
			}
			startedtrans = 1;
		} 

		error = hfs_relocate(vp, hfsmp->hfs_hotfile_start, p->p_ucred, p);
		vput(vp);
		if (error)
			break;
		
		/* Keep hot file free space current. */
		hfsmp->hfs_hotfile_freeblks -= fileblocks;
		listp->hfl_totalblocks -= fileblocks;
		
		/* Insert hot file entry */
		key->keyLength   = HFC_KEYLENGTH;
		key->temperature = listp->hfl_hotfile[i].hf_temperature;
		key->fileID      = listp->hfl_hotfile[i].hf_fileid;
		key->forkType    = 0;
		if (VTOC(vp)->c_desc.cd_nameptr)
			data = *(u_int32_t *)(VTOC(vp)->c_desc.cd_nameptr);
		else
			data = 0x3f3f3f3f;

		error = BTInsertRecord(filefork, iterator, &record, sizeof(data));
		if (error) {
			printf("hotfiles_adopt: BTInsertRecord failed %d (fileid %d)\n", error, key->fileID);
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
		error = BTInsertRecord(filefork, iterator, &record, sizeof(data));
		if (error) {
			printf("hotfiles_adopt: BTInsertRecord failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			stage = HFC_IDLE;
			break;
		}
		(void) BTFlushPath(filefork);

		/* Transaction complete. */
		if (startedtrans) {
			journal_end_transaction(hfsmp->jnl);
			startedtrans = 0;
		}
		hfs_global_shared_lock_release(hfsmp);
		aquiredlock = 0;

		blksmoved += fileblocks;
		listp->hfl_next++;
		if (listp->hfl_next >= listp->hfl_count) {
			break;
		}
		if (hfsmp->hfs_hotfile_freeblks <= 0) {
#if HFC_VERBOSE
			printf("hotfiles_adopt: free space exhausted (%d)\n", hfsmp->hfs_hotfile_freeblks);
#endif
			break;
		}
	} /* end for */

#if HFC_VERBOSE
	printf("hotfiles_adopt: [%d] adopted %d blocks (%d left)\n", listp->hfl_next, blksmoved, listp->hfl_totalblocks);
#endif
	/* Finish any outstanding transactions. */
	if (startedtrans) {
		(void) BTFlushPath(filefork);
		journal_end_transaction(hfsmp->jnl);
		startedtrans = 0;
	}
	if (aquiredlock) {
		hfs_global_shared_lock_release(hfsmp);
		aquiredlock = 0;
	}
	(void) VOP_UNLOCK(hfsmp->hfc_filevp, 0, p);

	if ((listp->hfl_next >= listp->hfl_count) || (hfsmp->hfs_hotfile_freeblks <= 0)) {
#if HFC_VERBOSE
		printf("hotfiles_adopt: all done relocating %d files\n", listp->hfl_count);
		printf("hotfiles_adopt: %d blocks free in hot file band\n", hfsmp->hfs_hotfile_freeblks);
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
 */
static int
hotfiles_evict(struct hfsmount *hfsmp, struct proc *p)
{
	BTreeIterator * iterator;
	struct mount *mp;
	struct vnode *vp;
	HotFileKey * key;
	filefork_t * filefork;
	hotfilelist_t  *listp;
	enum hfc_stage stage;
	int  blksmoved;
	int  filesmoved;
	int  fileblocks;
	int  error = 0;
	int  startedtrans = 0;
	int  aquiredlock = 0;

	if (hfsmp->hfc_stage != HFC_EVICTION) {
		return (EBUSY);
	}

	if ((listp = (hotfilelist_t  *)hfsmp->hfc_recdata) == NULL)
		return (0);	

	stage = hfsmp->hfc_stage;
	hfsmp->hfc_stage = HFC_BUSY;

	mp = HFSTOVFS(hfsmp);
	filesmoved = blksmoved = 0;

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;

	vn_lock(hfsmp->hfc_filevp, LK_EXCLUSIVE | LK_RETRY, p);
	filefork = VTOF(hfsmp->hfc_filevp);

	while (listp->hfl_reclaimblks > 0 &&
	       blksmoved < HFC_BLKSPERSYNC &&
	       filesmoved < HFC_FILESPERSYNC) {

		/*
		 * Obtain the first record (ie the coldest one).
		 */
		if (BTIterateRecord(filefork, kBTreeFirstRecord, iterator, NULL, NULL) != 0) {
#if HFC_VERBOSE
			printf("hotfiles_evict: no more records\n");
#endif
			error = 0;
			stage = HFC_ADOPTION;
			break;
		}
		if (key->keyLength != HFC_KEYLENGTH) {
			printf("hotfiles_evict: invalid key length %d\n", key->keyLength);
			error = EFTYPE;
			break;
		}		
		if (key->temperature == HFC_LOOKUPTAG) {
#if HFC_VERBOSE
			printf("hotfiles_evict: ran into thread records\n");
#endif
			error = 0;
			stage = HFC_ADOPTION;
			break;
		}
		/*
		 * Aquire the vnode for this file.
		 */
		error = VFS_VGET(mp, &key->fileID, &vp);

		/* Start a new transaction. */
		hfs_global_shared_lock_acquire(hfsmp);
		aquiredlock = 1;
		if (hfsmp->jnl) {
			if (journal_start_transaction(hfsmp->jnl) != 0) {
				if (error == 0)
					vput(vp);
				error = EINVAL;
				break;
			}
			startedtrans = 1;
		} 
		if (error) {
			if (error == ENOENT) {
				(void) BTDeleteRecord(filefork, iterator);
				key->temperature = HFC_LOOKUPTAG;
				(void) BTDeleteRecord(filefork, iterator);
				goto next;  /* stale entry, go to next */
			} else {
				printf("hotfiles_evict: err %d getting file %d (%d)\n",
				       error, key->fileID);
			}
			break;
		}
		if (vp->v_type != VREG && vp->v_type != VLNK) {
			printf("hotfiles_evict: huh, not a file %d\n", key->fileID);
			vput(vp);
			(void) BTDeleteRecord(filefork, iterator);
			key->temperature = HFC_LOOKUPTAG;
			(void) BTDeleteRecord(filefork, iterator);
			goto next;  /* invalid entry, go to next */
		}
		fileblocks = VTOF(vp)->ff_blocks;
		if ((blksmoved > 0) &&
		    (blksmoved + fileblocks) > HFC_BLKSPERSYNC) {
			vput(vp);
			break;
		}
		/*
		 * Make sure file is in the hot area.
		 */
		if (!hotextents(hfsmp, &VTOF(vp)->ff_extents[0])) {
#if HFC_VERBOSE
			printf("hotfiles_evict: file %d isn't hot!\n", key->fileID);
#endif
			vput(vp);
			(void) BTDeleteRecord(filefork, iterator);
			key->temperature = HFC_LOOKUPTAG;
			(void) BTDeleteRecord(filefork, iterator);
			goto next;  /* go to next */
		}
		
		/*
		 * Relocate file out of hot area.
		 */
		error = hfs_relocate(vp, HFSTOVCB(hfsmp)->nextAllocation, p->p_ucred, p);
		if (error) {
			/* XXX skip to next record here! */
			printf("hotfiles_evict: err % relocating file\n", error, key->fileID);
			vput(vp);
			break;
		}
		(void) VOP_FSYNC(vp, p->p_ucred, MNT_WAIT, p);

		vput(vp);

		hfsmp->hfs_hotfile_freeblks += fileblocks;
		listp->hfl_reclaimblks -= fileblocks;
		if (listp->hfl_reclaimblks < 0)
			listp->hfl_reclaimblks = 0;
		blksmoved += fileblocks;
		filesmoved++;

		error = BTDeleteRecord(filefork, iterator);
		if (error) {
			printf("hotfiles_evict: BTDeleteRecord failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}
		key->temperature = HFC_LOOKUPTAG;
		error = BTDeleteRecord(filefork, iterator);
		if (error) {
			printf("hotfiles_evict: BTDeleteRecord thread failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}
next:
		(void) BTFlushPath(filefork);

		/* Transaction complete. */
		if (startedtrans) {
			journal_end_transaction(hfsmp->jnl);
			startedtrans = 0;
		}
		hfs_global_shared_lock_release(hfsmp);
		aquiredlock = 0;

	} /* end while */

#if HFC_VERBOSE
	printf("hotfiles_evict: moved %d files (%d blks, %d to go)\n", filesmoved, blksmoved, listp->hfl_reclaimblks);
#endif
	/* Finish any outstanding transactions. */
	if (startedtrans) {
		(void) BTFlushPath(filefork);
		journal_end_transaction(hfsmp->jnl);
		startedtrans = 0;
	}
	if (aquiredlock) {
		hfs_global_shared_lock_release(hfsmp);
		aquiredlock = 0;
	}
	(void) VOP_UNLOCK(hfsmp->hfc_filevp, 0, p);

	/*
	 * Move to next stage when finished.
	 */
	if (listp->hfl_reclaimblks <= 0) {
		stage = HFC_ADOPTION;
#if HFC_VERBOSE
		printf("hotfiles_evict: %d blocks free in hot file band\n", hfsmp->hfs_hotfile_freeblks);
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
hotfiles_age(struct hfsmount *hfsmp, struct proc *p)
{
	BTreeInfoRec  btinfo;
	BTreeIterator * iterator;
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
	hfs_global_shared_lock_acquire(hfsmp);
	if (hfsmp->jnl) {
		if (journal_start_transaction(hfsmp->jnl) != 0) {
			hfs_global_shared_lock_release(hfsmp);
			error = EINVAL;
			goto out2;
		}
	} 
	vn_lock(hfsmp->hfc_filevp, LK_EXCLUSIVE | LK_RETRY, p);
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
	
		error = BTInsertRecord(filefork, prev_iterator, &prev_record, sizeof(data));
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
	(void) VOP_UNLOCK(hfsmp->hfc_filevp, 0, p);

	if (hfsmp->jnl) {
	//	hfs_flushvolumeheader(hfsmp, MNT_NOWAIT, 0);
		journal_end_transaction(hfsmp->jnl);
	}
	hfs_global_shared_lock_release(hfsmp);
out2:
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
 * On successful exit the vnode has a reference but is unlocked.
 */
static int
hfc_btree_open(struct hfsmount *hfsmp, struct vnode **vpp)
{
	struct proc *p;
	struct vnode *vp;
	struct cat_desc  cdesc = {0};
	struct cat_attr  cattr;
	struct cat_fork  cfork;
	static char filename[] = HFC_FILENAME;
	int  error;
	int  retry = 0;

	*vpp = NULL;
	p = current_proc();

	cdesc.cd_parentcnid = kRootDirID;
	cdesc.cd_nameptr = filename;
	cdesc.cd_namelen = strlen(filename);

	/* Lock catalog b-tree */
	error = hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_SHARED, p);
	if (error)
		return (error);

	error = cat_lookup(hfsmp, &cdesc, 0, &cdesc, &cattr, &cfork);

	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking(hfsmp, kHFSCatalogFileID, LK_RELEASE, p);

	if (error) {
		printf("hfc_btree_open: cat_lookup error %d\n", error);
		return (error);
	}
again:
	cdesc.cd_flags |= CD_ISMETA;
	error = hfs_getnewvnode(hfsmp, NULL, &cdesc, 0, &cattr, &cfork, &vp);
	if (error) {
		printf("hfc_btree_open: hfs_getnewvnode error %d\n", error);
		cat_releasedesc(&cdesc);
		return (error);
	}
	if ((vp->v_flag & VSYSTEM) == 0) {
#if HFC_VERBOSE
		printf("hfc_btree_open: file has UBC, try again\n");
#endif
		vput(vp);
		vgone(vp);
		if (retry++ == 0)
			goto again;
		else
			return (EBUSY);
	}

	/* Open the B-tree file for writing... */
	error = BTOpenPath(VTOF(vp), (KeyCompareProcPtr) hfc_comparekeys);	
	if (error) {
		printf("hfc_btree_open: BTOpenPath error %d\n", error);
		error = MacToVFSError(error);
	} else {
#if HFC_VERBOSE
		struct BTreeInfoRec btinfo;

		if (BTGetInformation(VTOF(vp), 0, &btinfo) == 0) {
			printf("btinfo: nodeSize %d\n", btinfo.nodeSize);
			printf("btinfo: maxKeyLength %d\n", btinfo.maxKeyLength);
			printf("btinfo: treeDepth %d\n", btinfo.treeDepth);
			printf("btinfo: numRecords %d\n", btinfo.numRecords);
			printf("btinfo: numNodes %d\n", btinfo.numNodes);
			printf("btinfo: numFreeNodes %d\n", btinfo.numFreeNodes);
		}
#endif
	}

	VOP_UNLOCK(vp, 0, p);	/* unlocked with a single reference */
	if (error)
		vrele(vp);
	else
		*vpp = vp;

	if ((vp->v_flag & VSYSTEM) == 0)
		panic("hfc_btree_open: not a system file (vp = 0x%08x)", vp);

	if (UBCINFOEXISTS(vp))
		panic("hfc_btree_open: has UBCInfo (vp = 0x%08x)", vp);

	return (error);
}

/*
 * Close the hot files b-tree.
 *
 * On entry the vnode is not locked but has a reference.
 */
static int
hfc_btree_close(struct hfsmount *hfsmp, struct vnode *vp)
{
	struct proc *p = current_proc();
	int  error;


	if (hfsmp->jnl) {
	    journal_flush(hfsmp->jnl);
	}

	if (vget(vp, LK_EXCLUSIVE, p) == 0) {
		(void) VOP_FSYNC(vp, NOCRED, MNT_WAIT, p);
		error = BTClosePath(VTOF(vp));
		if (error)
			printf("hfc_btree_close: BTClosePath error %d\n", error);
		vput(vp);
	}
	vrele(vp);
	vgone(vp);
	vp = NULL;
	
	return (0);
}

/*
 *  Create a hot files btree file.
 *
 */
static int
hfc_btree_create(struct hfsmount *hfsmp, int nodesize, int entries)
{
	struct proc *p;
	struct nameidata nd;
	struct vnode *vp;
	char path[128];
	int  error;


	if (hfsmp->hfc_filevp)
		panic("hfc_btree_create: hfc_filevp exists (vp = 0x%08x)", hfsmp->hfc_filevp);

	p = current_proc();
	snprintf(path, sizeof(path), "%s/%s",
	         hfsmp->hfs_mp->mnt_stat.f_mntonname, HFC_FILENAME);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, path, p);
	if ((error = vn_open(&nd, O_CREAT | FWRITE, S_IRUSR | S_IWUSR)) != 0) {
		return (error);
	}
	vp = nd.ni_vp;
	
	/* Don't use non-regular files or files with links. */
	if (vp->v_type != VREG || VTOC(vp)->c_nlink != 1) {
		error = EFTYPE;
		goto out;
	}

	printf("HFS: created HFBT on %s\n", HFSTOVCB(hfsmp)->vcbVN);

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
		((FndrFileInfo *)&VTOC(vp)->c_finderinfo[0])->fdFlags |=
			SWAP_BE16 (kIsInvisible + kNameLocked);

		if (kmem_alloc(kernel_map, (vm_offset_t *)&buffer, nodesize)) {
			error = ENOMEM;
			goto out;
		}	
		bzero(buffer, nodesize);
		index = (int16_t *)buffer;
	
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
		bthp = (BTHeaderRec *)((UInt8 *)buffer + offset);
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
		hotfileinfo = (HotFilesInfo *)((UInt8 *)buffer + offset);
		hotfileinfo->magic       = SWAP_BE32 (HFC_MAGIC);
		hotfileinfo->version     = SWAP_BE32 (HFC_VERSION);
		hotfileinfo->duration    = SWAP_BE32 (HFC_DEFAULT_DURATION);
		hotfileinfo->timebase    = 0;
		hotfileinfo->timeleft    = 0;
		hotfileinfo->threshold   = SWAP_BE32 (HFC_MINIMUM_TEMPERATURE);
		hotfileinfo->maxfileblks = SWAP_BE32 (HFC_MAXIMUM_FILESIZE / HFSTOVCB(hfsmp)->blockSize);
		hotfileinfo->maxfilecnt  = SWAP_BE32 (HFC_DEFAULT_FILE_COUNT);
		strcpy(hotfileinfo->tag, hfc_tag);
		offset += kBTreeHeaderUserBytes;
		index[(nodesize / 2) - 3] = SWAP_BE16 (offset);
	
		/* FILL IN THE MAP RECORD (only one node in use). */
		*((u_int8_t *)buffer + offset) = 0x80;
		offset += nodesize - sizeof(BTNodeDescriptor) - sizeof(BTHeaderRec)
				   - kBTreeHeaderUserBytes - (4 * sizeof(int16_t));
		index[(nodesize / 2) - 4] = SWAP_BE16 (offset);

		vp->v_flag |= VNOFLUSH;
		error = VOP_TRUNCATE(vp, (off_t)filesize, IO_NDELAY, NOCRED, p);
		if (error == 0) {
			struct iovec aiov;
			struct uio auio;

			auio.uio_iov = &aiov;
			auio.uio_iovcnt = 1;
			aiov.iov_base = buffer;
			aiov.iov_len = filesize;
			auio.uio_resid = nodesize;
			auio.uio_offset = (off_t)(0);
			auio.uio_segflg = UIO_SYSSPACE;
			auio.uio_rw = UIO_WRITE;
			auio.uio_procp = (struct proc *)0;
			error = VOP_WRITE(vp, &auio, 0, kernproc->p_ucred);
		}
		kmem_free(kernel_map, (vm_offset_t)buffer, nodesize);
	}
out:
	(void) VOP_UNLOCK(vp, 0, p);
	(void) vn_close(vp, FWRITE, kernproc->p_ucred, p);	
	vgone(vp);
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
 * Visit the tree in desending order.
 */
static void
hf_sortlist(hotfile_entry_t * root, int *index, hotfilelist_t *sortedlist)
{
	if (root) {
		int i;

		hf_sortlist(root->right, index, sortedlist);
		i = *index;
		++(*index);
		sortedlist->hfl_hotfile[i].hf_fileid = root->fileid;
		sortedlist->hfl_hotfile[i].hf_temperature = root->temperature;
		sortedlist->hfl_hotfile[i].hf_blocks = root->blocks;
		sortedlist->hfl_totalblocks += root->blocks;
		hf_sortlist(root->left, index, sortedlist);
	}
}

/*
 * Generate a sorted list of hot files.
 */
static int
hf_getsortedlist(hotfile_data_t * hotdata, hotfilelist_t *sortedlist)
{
	int index = 0;

	hf_sortlist(hotdata->rootentry, &index, sortedlist);

	sortedlist->hfl_count = hotdata->activefiles;
	
	return (index);
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
		printf("temperature: % 8d, fileid %d\n", root->temperature, root->fileid);
		hf_printtree(root->right);
	}
}
#endif
