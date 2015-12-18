/*
 * Copyright (c) 2003-2013 Apple Inc. All rights reserved.
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


//
// We cap the max temperature for non-system files to "MAX_NORMAL_TEMP"
// so that they will always have a lower temperature than system (aka 
// "auto-cached") files.  System files have MAX_NORMAL_TEMP added to
// their temperature which produces two bands of files (all non-system
// files will have a temp less than MAX_NORMAL_TEMP and all system
// files will have a temp greatern than MAX_NORMAL_TEMP).
//
// This puts non-system files on the left side of the hotfile btree 
// (and we start evicting from the left-side of the tree).  The idea is 
// that we will evict non-system files more aggressively since their
// working set changes much more dynamically than system files (which 
// are for the most part, static).
//
// NOTE: these values have to fit into a 32-bit int.  We use a
//       value of 1-billion which gives a pretty broad range
//       and yet should not run afoul of any sign issues.
//
#define MAX_NORMAL_TEMP    1000000000
#define HF_TEMP_RANGE      MAX_NORMAL_TEMP


//
// These used to be defines of the hard coded values.  But if
// we're on an cooperative fusion (CF) system we need to change 
// the values (which happens in hfs_recording_init()
// 
uint32_t hfc_default_file_count = 1000;
uint32_t hfc_default_duration   = (3600 * 60);
uint32_t hfc_max_file_count     = 5000;
uint64_t hfc_max_file_size      = (10 * 1024 * 1024);


/*
 * Hot File Recording Data (runtime).
 */
typedef struct hotfile_data {
	struct hfsmount *hfsmp;
	long             refcount;
	u_int32_t	 activefiles;  /* active number of hot files */
	u_int32_t	 threshold;
	u_int32_t	 maxblocks;
	hotfile_entry_t	*rootentry;
	hotfile_entry_t	*freelist;
	hotfile_entry_t	*coldest;
	hotfile_entry_t	 entries[1];
} hotfile_data_t;

static int  hfs_recording_start (struct hfsmount *);
static int  hfs_recording_stop (struct hfsmount *);

/* Hotfiles pinning routines */
static int hfs_getvnode_and_pin (struct hfsmount *hfsmp, uint32_t fileid, uint32_t *pinned);
static int hfs_pin_extent_record (struct hfsmount *hfsmp, HFSPlusExtentRecord extents, uint32_t *pinned);
static int hfs_pin_catalog_rec (struct hfsmount *hfsmp, HFSPlusCatalogFile *cfp, int rsrc);

/*
 * Hot File Data recording functions (in-memory binary tree).
 */
static int               hf_insert (hotfile_data_t *, hotfile_entry_t *);
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
static int  hotfiles_adopt (struct hfsmount *, vfs_context_t);
static int  hotfiles_evict (struct hfsmount *, vfs_context_t);
static int  hotfiles_refine (struct hfsmount *);
static int  hotextents(struct hfsmount *, HFSPlusExtentDescriptor *);
static int  hfs_addhotfile_internal(struct vnode *);
static int  hfs_hotfile_cur_freeblks(hfsmount_t *hfsmp);


/*
 * Hot File Cluster B-tree (on disk) functions.
 */
static int  hfc_btree_create (struct hfsmount *, unsigned int, unsigned int);
static int  hfc_btree_open (struct hfsmount *, struct vnode **);
static int  hfc_btree_open_ext(struct hfsmount *hfsmp, struct vnode **vpp, int ignore_btree_errs);
static int  hfc_btree_close (struct hfsmount *, struct vnode *);
static int  hfc_btree_delete_record(struct hfsmount *hfsmp, BTreeIterator *iterator, HotFileKey *key);
static int  hfc_btree_delete(struct hfsmount *hfsmp);
static int  hfc_comparekeys (HotFileKey *, HotFileKey *);


char hfc_tag[] = "CLUSTERED HOT FILES B-TREE     ";


/*
 *========================================================================
 *                       HOT FILE INTERFACE ROUTINES
 *========================================================================
 */

/*
 * Start recording the hottest files on a file system.
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
			if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
				if (hfsmp->hfs_hotfile_freeblks == 0) {
					hfsmp->hfs_hotfile_freeblks = hfsmp->hfs_hotfile_maxblks - SWAP_BE32 (hotfileinfo.usedblocks);
				}
				hfsmp->hfc_maxfiles = 0x7fffffff;
				printf("hfs: %s: %s: hotfile freeblocks: %d, max: %d\n", hfsmp->vcbVN, __FUNCTION__,
				       hfsmp->hfs_hotfile_freeblks, hfsmp->hfs_hotfile_maxblks);
			} else {
				hfsmp->hfc_maxfiles = SWAP_BE32 (hotfileinfo.maxfilecnt);
			}
			hfsmp->hfc_timebase = SWAP_BE32 (hotfileinfo.timebase);
			int timeleft = (int)SWAP_BE32(hotfileinfo.timeleft);
			if (timeleft < 0 || timeleft > (int)(HFC_DEFAULT_DURATION*2)) {
				// in case this field got botched, don't let it screw things up
				// printf("hfs: hotfiles: bogus looking timeleft: %d\n", timeleft);
				timeleft = HFC_DEFAULT_DURATION;
			}
			hfsmp->hfc_timeout = timeleft + tv.tv_sec ;
			/* Fix up any bogus timebase values. */
			if (hfsmp->hfc_timebase < HFC_MIN_BASE_TIME) {
				hfsmp->hfc_timebase = hfsmp->hfc_timeout - HFC_DEFAULT_DURATION;
			}
#if HFC_VERBOSE
			printf("hfs: Resume recording hot files on %s (%d secs left (%d); timeout %ld)\n",
			       hfsmp->vcbVN, SWAP_BE32 (hotfileinfo.timeleft), timeleft, hfsmp->hfc_timeout - tv.tv_sec);
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
		printf("hfs: begin recording hot files on %s (hotfile start/end block: %d - %d; max/free: %d/%d; maxfiles: %d)\n",
		       hfsmp->vcbVN,
		       hfsmp->hfs_hotfile_start, hfsmp->hfs_hotfile_end,
		       hfsmp->hfs_hotfile_maxblks, hfsmp->hfs_hotfile_freeblks, hfsmp->hfc_maxfiles);
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
	if (listp->hfl_totalblocks > hfs_hotfile_cur_freeblks(hfsmp)) {
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

static void
save_btree_user_info(struct hfsmount *hfsmp)
{
	HotFilesInfo hotfileinfo;
	struct timeval tv;

	microtime(&tv);
	hotfileinfo.magic       = SWAP_BE32 (HFC_MAGIC);
	hotfileinfo.version     = SWAP_BE32 (HFC_VERSION);
	hotfileinfo.duration    = SWAP_BE32 (HFC_DEFAULT_DURATION);
	hotfileinfo.timebase    = SWAP_BE32 (hfsmp->hfc_timebase);
	hotfileinfo.timeleft    = SWAP_BE32 (hfsmp->hfc_timeout - tv.tv_sec);
	hotfileinfo.threshold   = SWAP_BE32 (HFC_MINIMUM_TEMPERATURE);
	hotfileinfo.maxfileblks = SWAP_BE32 (HFC_MAXIMUM_FILESIZE / HFSTOVCB(hfsmp)->blockSize);
	if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
		hotfileinfo.usedblocks = SWAP_BE32 (hfsmp->hfs_hotfile_maxblks - hfs_hotfile_cur_freeblks(hfsmp));
#if HFC_VERBOSE
		printf("hfs: %s: saving usedblocks = %d (timeleft: %d; timeout %ld)\n", hfsmp->vcbVN, (hfsmp->hfs_hotfile_maxblks - hfsmp->hfs_hotfile_freeblks),
		       SWAP_BE32(hotfileinfo.timeleft), hfsmp->hfc_timeout);
#endif
	} else {
		hotfileinfo.maxfilecnt  = SWAP_BE32 (HFC_DEFAULT_FILE_COUNT);
	}
	strlcpy((char *)hotfileinfo.tag, hfc_tag, sizeof hotfileinfo.tag);
	(void) BTSetUserData(VTOF(hfsmp->hfc_filevp), &hotfileinfo, sizeof(hotfileinfo));
}

/*
 * Suspend recording the hotest files on a file system.
 */
int
hfs_recording_suspend(struct hfsmount *hfsmp)
{
	hotfile_data_t *hotdata = NULL;
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
	    goto out;
	}
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
		goto end_transaction;
	}

	save_btree_user_info(hfsmp);

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


static void
reset_file_ids(struct hfsmount *hfsmp, uint32_t *fileid_table, int num_ids)
{
	int i, error;

	for(i=0; i < num_ids; i++) {
		struct vnode *vp;

		error = hfs_vget(hfsmp, fileid_table[i], &vp, 0, 0);
		if (error) {
			if (error == ENOENT) {
				error = 0;
				continue;  /* stale entry, go to next */
			}
			continue;
		}

		// hfs_vget returns a locked cnode so no need to lock here

		if ((hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) && (VTOC(vp)->c_attr.ca_recflags & kHFSFastDevPinnedMask)) {
			error = hfs_pin_vnode(hfsmp, vp, HFS_UNPIN_IT, NULL, vfs_context_kernel());
		}

		/*
		 * The updates to the catalog must be journaled
		 */
		hfs_start_transaction(hfsmp);

		//
		// turn off _all_ the hotfile related bits since we're resetting state
		//
		if (VTOC(vp)->c_attr.ca_recflags & kHFSFastDevCandidateMask) {
			vnode_clearfastdevicecandidate(vp);
		}

		VTOC(vp)->c_attr.ca_recflags &= ~(kHFSFastDevPinnedMask|kHFSDoNotFastDevPinMask|kHFSFastDevCandidateMask|kHFSAutoCandidateMask);
		VTOC(vp)->c_flag |= C_MODIFIED;

		hfs_update(vp, 0);

		hfs_end_transaction(hfsmp);
		
		hfs_unlock(VTOC(vp));
		vnode_put(vp);
	}
}

static int
flag_hotfile(struct hfsmount *hfsmp, const char *filename)
{
	struct vnode *dvp = NULL, *fvp = NULL;
	vfs_context_t ctx = vfs_context_kernel();
	struct componentname cname;
	int  error=0;
	size_t fname_len;
	const char *orig_fname = filename;
	
	if (filename == NULL) {
		return EINVAL;
	}

	fname_len = strlen(filename);    // do NOT include the trailing '\0' so that we break out of the loop below
	
	error = VFS_ROOT(HFSTOVFS(hfsmp), &dvp, ctx);
	if (error) {
		return (error);
	}

	/* At this point, 'dvp' must be considered iocounted */
	const char *ptr;
	ptr = filename;

	while (ptr < (orig_fname + fname_len - 1)) {
		for(; ptr < (orig_fname + fname_len) && *ptr && *ptr != '/'; ptr++) {
			/* just keep advancing till we reach the end of the string or a slash */
		}

		cname.cn_nameiop = LOOKUP;
		cname.cn_flags = ISLASTCN;
		cname.cn_context = ctx;
		cname.cn_ndp = NULL;
		cname.cn_pnbuf = __DECONST(char *, orig_fname);
        cname.cn_nameptr = __DECONST(char *, filename);
		cname.cn_pnlen = fname_len;
		cname.cn_namelen = ptr - filename;
		cname.cn_hash = 0;
		cname.cn_consume = 0;

		error = VNOP_LOOKUP(dvp, &fvp, &cname, ctx);
		if (error) {
			/*
			 * If 'dvp' is non-NULL, then it has an iocount.  Make sure to release it
			 * before bailing out.  VNOP_LOOKUP could legitimately return ENOENT
			 * if the item didn't exist or if we raced with a delete.
			 */
			if (dvp) {
				vnode_put(dvp);
				dvp = NULL;
			}
			return error;
		}

		if (ptr < orig_fname + fname_len - 1) {
			//
			// we've got a multi-part pathname so drop the ref on the dir,
			// make dvp become what we just looked up, and advance over
			// the slash character in the pathname to get to the next part
			// of the component
			//
			vnode_put(dvp);
			dvp = fvp;
			fvp = NULL;

			filename = ++ptr;   // skip the slash character
		}
	}
	
	if (fvp == NULL) {
		error = ENOENT;
		goto out;
	}

	struct cnode *cp = VTOC(fvp);
	if ((error = hfs_lock(cp, HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT)) != 0) {
		goto out;
	}

	hfs_start_transaction(hfsmp);
	
	cp->c_attr.ca_recflags |= (kHFSFastDevCandidateMask|kHFSAutoCandidateMask);
	cp->c_flag |= C_MODIFIED;

	hfs_update(fvp, 0);

	hfs_end_transaction(hfsmp);

	hfs_unlock(cp);
	//printf("hfs: flagged /%s with the fast-dev-candidate|auto-candidate flags\n", filename);


out:
	if (fvp) {
		vnode_put(fvp);
		fvp = NULL;
	}

	if (dvp) {
		vnode_put(dvp);
		dvp = NULL;
	}

	return error;
}


static void
hfs_setup_default_cf_hotfiles(struct hfsmount *hfsmp)
{
	const char *system_default_hotfiles[] = {
		"usr",
		"System",
		"Applications",
		"private/var/db/dyld"
	};
	int i;

	for(i=0; i < (int)(sizeof(system_default_hotfiles)/sizeof(char *)); i++) {
		flag_hotfile(hfsmp, system_default_hotfiles[i]);
	}
}


#define NUM_FILE_RESET_IDS   4096    // so we allocate 16k to hold file-ids

static void
hfs_hotfile_reset(struct hfsmount *hfsmp)
{
	CatalogKey * keyp;
	CatalogRecord * datap;
	u_int32_t  dataSize;
	BTScanState scanstate;
	BTreeIterator * iterator = NULL;
	FSBufferDescriptor  record;
	u_int32_t  data;
	u_int32_t  cnid;
	int error = 0;
	uint32_t *fileids=NULL;
	int cur_id_index = 0;

	int cleared = 0;  /* debug variables */
	int filecount = 0;
	int dircount = 0;

#if HFC_VERBOSE
	printf("hfs: %s: %s\n", hfsmp->vcbVN, __FUNCTION__);
#endif

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		error = ENOMEM;
		goto out;
	}
	bzero(iterator, sizeof(*iterator));

	MALLOC(fileids, uint32_t *, NUM_FILE_RESET_IDS * sizeof(uint32_t), M_TEMP, M_WAITOK);
	if (fileids == NULL) {
		error = ENOMEM;
		goto out;
	}

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;

	/*
	 * Get ready to scan the Catalog file.
	 */
	error = BTScanInitialize(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), 0, 0, 0,
	                       kCatSearchBufferSize, &scanstate);
	if (error) {
		printf("hfs_hotfile_reset: err %d BTScanInit\n", error);
		goto out;
	}

	/*
	 * Visit all the catalog btree leaf records, clearing any that have the
	 * HotFileCached bit set.
	 */
	for (;;) {
		error = BTScanNextRecord(&scanstate, 0, (void **)&keyp, (void **)&datap, &dataSize);
		if (error) {
			if (error == btNotFound)
				error = 0;
			else
				printf("hfs_hotfile_reset: err %d BTScanNext\n", error);
			break;
		}

		if (datap->recordType == kHFSPlusFolderRecord && (dataSize == sizeof(HFSPlusCatalogFolder))) {
			HFSPlusCatalogFolder *dirp = (HFSPlusCatalogFolder *)datap;

			dircount++;
		
			if ((dirp->flags & (kHFSFastDevPinnedMask|kHFSDoNotFastDevPinMask|kHFSFastDevCandidateMask|kHFSAutoCandidateMask)) == 0) {
				continue;
			}

			cnid = dirp->folderID;
		} else if ((datap->recordType == kHFSPlusFileRecord) && (dataSize == sizeof(HFSPlusCatalogFile))) {
			HFSPlusCatalogFile *filep = (HFSPlusCatalogFile *)datap;   

			filecount++;

			/*
			 * If the file doesn't have any of the HotFileCached bits set, ignore it.
			 */
			if ((filep->flags & (kHFSFastDevPinnedMask|kHFSDoNotFastDevPinMask|kHFSFastDevCandidateMask|kHFSAutoCandidateMask)) == 0) {
				continue;
			}

			cnid = filep->fileID;
		} else {
			continue;
		}

		/* Skip over journal files. */
		if (cnid == hfsmp->hfs_jnlfileid || cnid == hfsmp->hfs_jnlinfoblkid) {
			continue;
		}

		//
		// Just record the cnid of the file for now.  We will modify it separately
		// because we can't modify the catalog while we're scanning it.
		//
		fileids[cur_id_index++] = cnid;
		if (cur_id_index >= NUM_FILE_RESET_IDS) {
			//
			// We're over the limit of file-ids so we have to terminate this
			// scan, go modify all the catalog records, then restart the scan.
			// This is required because it's not permissible to modify the
			// catalog while scanning it.
			//
			(void) BTScanTerminate(&scanstate, &data, &data, &data);

			reset_file_ids(hfsmp, fileids, cur_id_index);
			cleared += cur_id_index;
			cur_id_index = 0;

			// restart the scan
			error = BTScanInitialize(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), 0, 0, 0,
						 kCatSearchBufferSize, &scanstate);
			if (error) {
				printf("hfs_hotfile_reset: err %d BTScanInit\n", error);
				goto out;
			}
			continue;
		}
	}

	if (cur_id_index) {
		reset_file_ids(hfsmp, fileids, cur_id_index);
		cleared += cur_id_index;
		cur_id_index = 0;
	}

	printf("hfs: cleared HotFileCache related bits on %d files out of %d (dircount %d)\n", cleared, filecount, dircount);

	(void) BTScanTerminate(&scanstate, &data, &data, &data);

out:	
	if (fileids)
		FREE(fileids, M_TEMP);
	
	if (iterator)
		FREE(iterator, M_TEMP);

	//
	// If the hotfile btree exists, delete it.  We need to open
	// it to be able to delete it because we need the hfc_filevp
	// for deletion.
	//
	error = hfc_btree_open_ext(hfsmp, &hfsmp->hfc_filevp, 1);
	if (!error) {
		printf("hfs: hotfile_reset: deleting existing hotfile btree\n");
		hfc_btree_delete(hfsmp);
	}
	
	if (hfsmp->hfc_filevp) {
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
	}

	hfsmp->hfs_hotfile_blk_adjust = 0;
	hfsmp->hfs_hotfile_freeblks = hfsmp->hfs_hotfile_maxblks;
}


//
// This should ONLY be called by hfs_recording_init() and the special fsctl.
//
// We assume that the hotfile btree is already opened.
//
static int
hfs_hotfile_repin_files(struct hfsmount *hfsmp)
{
	BTreeIterator * iterator = NULL;
	HotFileKey * key;
	filefork_t * filefork;
	int  error = 0;
	int  bt_op;
	enum hfc_stage stage;
	uint32_t pinned_blocks;
	uint32_t num_files=0, nrsrc=0;
	uint32_t total_pinned=0;

	if (!(hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) || !hfsmp->hfc_filevp) {
		//
		// this is only meaningful if we're pinning hotfiles
		// (as opposed to the regular form of hotfiles that
		// get relocated to the hotfile zone)
		//
		return 0;
	}

#if HFC_VERBOSE
	printf("hfs: %s: %s\n", hfsmp->vcbVN, __FUNCTION__);
#endif
	
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
		return (EPERM);
	}


	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		hfs_unlock(VTOC(hfsmp->hfc_filevp));
		return (ENOMEM);
	}

	stage = hfsmp->hfc_stage;
	hfsmp->hfc_stage = HFC_BUSY;

	bt_op = kBTreeFirstRecord;

	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;

	filefork = VTOF(hfsmp->hfc_filevp);
	int lockflags;

	while (1) {

		lockflags = 0;
		/*
		 * Obtain the first record (ie the coldest one).
		 */
		if (BTIterateRecord(filefork, bt_op, iterator, NULL, NULL) != 0) {
			// no more records
			error = 0;
			break;
		}
		if (key->keyLength != HFC_KEYLENGTH) {
			// printf("hfs: hotfiles_repin_files: invalid key length %d\n", key->keyLength);
			error = EFTYPE;
			break;
		}		
		if (key->temperature == HFC_LOOKUPTAG) {
			// ran into thread records in the hotfile btree
			error = 0;
			break;
		}

        //
		// Just lookup the records in the catalog and pin the direct
		// mapped extents.  Faster than instantiating full vnodes
		// (and thereby thrashing the system vnode cache).
		//
		struct cat_desc fdesc;
		struct cat_attr attr;
		struct cat_fork fork;
        uint8_t forktype = 0;

		lockflags = hfs_systemfile_lock(hfsmp, (SFL_CATALOG | SFL_EXTENTS), HFS_SHARED_LOCK);
        /*
         * Snoop the cnode hash to find out if the item we want is in-core already.
         *
         * We largely expect this function to fail (the items we want are probably not in the hash).
         * we use the special variant which bails out as soon as it finds a vnode (even if it is
         * marked as open-unlinked or actually removed on-disk.  If we find a vnode, then we
         * release the systemfile locks and go through the pin-vnode path instead.
         */
        if (hfs_chash_snoop (hfsmp, key->fileID, 1, NULL, NULL) == 0) {
            pinned_blocks = 0;

            /* unlock immediately and go through the in-core path */
            hfs_systemfile_unlock(hfsmp, lockflags);
			lockflags = 0;

            error = hfs_getvnode_and_pin (hfsmp, key->fileID, &pinned_blocks);
            if (error) {
                /* if ENOENT, then it was deleted in the catalog. Remove from our hotfiles tracking */
                if (error == ENOENT) {
                    hfc_btree_delete_record(hfsmp, iterator, key);
                }
                /* other errors, just ignore and move on with life */
            }
            else { //!error
                total_pinned += pinned_blocks;
                num_files++;
            }

            goto next;
        }

        /* If we get here, we're still holding the systemfile locks */
		error = cat_idlookup(hfsmp, key->fileID, 1, 0, &fdesc, &attr, &fork);
		if (error) {
			//
			// this file system could have been mounted while booted from a
			// different partition and thus the hotfile btree would not have
			// been maintained.  thus a file that was hotfile cached could
			// have been deleted while booted from a different partition which
			// means we need to delete it from the hotfile btree.
			//
			// block accounting is taken care of at the end: we re-assign
			// hfsmp->hfs_hotfile_freeblks based on how many blocks we actually
			// pinned.
			//
			hfc_btree_delete_record(hfsmp, iterator, key);

			goto next;
		}

		if (fork.cf_size == 0) {
			// hmmm, the data is probably in the resource fork (aka a compressed file)
			error = cat_idlookup(hfsmp, key->fileID, 1, 1, &fdesc, &attr, &fork);
			if (error) {
				hfc_btree_delete_record(hfsmp, iterator, key);
				goto next;
			}
            forktype = 0xff;
			nrsrc++;
		}

		pinned_blocks = 0;

        /* Can't release the catalog /extents lock yet, we may need to go find the overflow blocks */
        error = hfs_pin_extent_record (hfsmp, fork.cf_extents, &pinned_blocks);
        if (error) {
            goto next;  //skip to next
        }
		/* add in the blocks from the inline 8 */
        total_pinned += pinned_blocks;
        pinned_blocks = 0;

        /* Could this file have overflow extents? */
        if (fork.cf_extents[kHFSPlusExtentDensity-1].startBlock) {
            /* better pin them, too */
            error = hfs_pin_overflow_extents (hfsmp, key->fileID, forktype, &pinned_blocks);
            if (error) {
				/* If we fail to pin all of the overflow extents, then just skip to the next file */
                goto next;
            }
        }

		num_files++;
        if (pinned_blocks) {
            /* now add in any overflow also */
            total_pinned += pinned_blocks;
        }

	next:
		if (lockflags) {
			hfs_systemfile_unlock(hfsmp, lockflags);
			lockflags = 0;
		}
		bt_op = kBTreeNextRecord;

	} /* end while */

#if HFC_VERBOSE
	printf("hfs: hotfiles_repin_files: re-pinned %d files (nrsrc %d, total pinned %d blks; freeblock %d, maxblocks %d, calculated free: %d)\n",
	       num_files, nrsrc, total_pinned, hfsmp->hfs_hotfile_freeblks, hfsmp->hfs_hotfile_maxblks,
	      hfsmp->hfs_hotfile_maxblks - total_pinned);
#endif
	//
	// make sure this is accurate based on how many blocks we actually pinned
	//
	hfsmp->hfs_hotfile_freeblks = hfsmp->hfs_hotfile_maxblks - total_pinned;

	hfs_unlock(VTOC(hfsmp->hfc_filevp));

	FREE(iterator, M_TEMP);	
	hfsmp->hfc_stage = stage;
	wakeup((caddr_t)&hfsmp->hfc_stage);
	return (error);
}

void
hfs_repin_hotfiles(struct hfsmount *hfsmp)
{
	int error, need_close;
	
	lck_mtx_lock(&hfsmp->hfc_mutex);

	if (hfsmp->hfc_filevp == NULL) {
		error = hfc_btree_open(hfsmp, &hfsmp->hfc_filevp);
		if (!error) {
			need_close = 1;
		} else {
			printf("hfs: failed to open the btree err=%d.  Unable to re-pin hotfiles.\n", error);
			lck_mtx_unlock(&hfsmp->hfc_mutex);
			return;
		}
	} else {
		need_close = 0;
	}

	hfs_pin_vnode(hfsmp, hfsmp->hfc_filevp, HFS_PIN_IT, NULL, vfs_context_kernel());
			
	hfs_hotfile_repin_files(hfsmp);

	if (need_close) {
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
	}

	lck_mtx_unlock(&hfsmp->hfc_mutex);
}

/*
 * For a given file ID, find and pin all of its overflow extents to the underlying CS
 * device.  Assumes that the extents overflow b-tree is locked for the duration of this call.
 *
 * Emit the number of blocks pinned in output argument 'pinned'
 *
 * Return success or failure (errno) in return value.
 *
 */
int hfs_pin_overflow_extents (struct hfsmount *hfsmp, uint32_t fileid,
                                     uint8_t forktype, uint32_t *pinned) {

    struct BTreeIterator *ext_iter = NULL;
    ExtentKey *ext_key_ptr = NULL;
    ExtentRecord ext_data;
    FSBufferDescriptor btRecord;
    uint16_t btRecordSize;
    int error = 0;

    uint32_t pinned_blocks = 0;


    MALLOC (ext_iter, struct BTreeIterator*, sizeof (struct BTreeIterator), M_TEMP, M_WAITOK);
    if (ext_iter == NULL) {
        return ENOMEM;
    }
    bzero (ext_iter, sizeof(*ext_iter));

    BTInvalidateHint (ext_iter);
    ext_key_ptr = (ExtentKey*)&ext_iter->key;
    btRecord.bufferAddress = &ext_data;
    btRecord.itemCount = 1;

    /*
     * This is like when you delete a file; we don't actually need most of the search machinery because
     * we are going to need all of the extent records that belong to this file (for a given fork type),
     * so we might as well use a straight-up iterator.
     *
     * Position the B-Tree iterator at the first record with this file ID
     */
    btRecord.itemSize = sizeof (HFSPlusExtentRecord);
    ext_key_ptr->hfsPlus.keyLength = kHFSPlusExtentKeyMaximumLength;
    ext_key_ptr->hfsPlus.forkType = forktype;
    ext_key_ptr->hfsPlus.pad = 0;
    ext_key_ptr->hfsPlus.fileID = fileid;
    ext_key_ptr->hfsPlus.startBlock = 0;

    error = BTSearchRecord (VTOF(hfsmp->hfs_extents_vp), ext_iter, &btRecord, &btRecordSize, ext_iter);
    if (error ==  btNotFound) {
        /* empty b-tree, so that's ok. we'll fall out during error check below. */
        error = 0;
    }

    while (1) {
        uint32_t found_fileid;
        uint32_t pblocks;

        error = BTIterateRecord (VTOF(hfsmp->hfs_extents_vp), kBTreeNextRecord, ext_iter, &btRecord, &btRecordSize);
        if (error) {
            /* swallow it if it's btNotFound, otherwise just bail out */
            if (error == btNotFound)
                error = 0;
            break;
        }

        found_fileid = ext_key_ptr->hfsPlus.fileID;
        /*
         * We only do one fork type at a time. So if either the fork-type doesn't
         * match what we are looking for (resource or data), OR the file id doesn't match
         * which indicates that there's nothing more with this file ID as the key, then bail out
         */
        if ((found_fileid != fileid) || (ext_key_ptr->hfsPlus.forkType != forktype))  {
            error = 0;
            break;
        }

        /* Otherwise, we now have an extent record. Process and pin all of the file extents. */
        pblocks = 0;
        error = hfs_pin_extent_record (hfsmp, ext_data.hfsPlus, &pblocks);

        if (error) {
            break;
        }
        pinned_blocks += pblocks;

        /* if 8th extent is empty, then bail out */
        if (ext_data.hfsPlus[kHFSPlusExtentDensity-1].startBlock == 0) {
            error = 0;
            break;
        }

    } // end extent-getting loop

    /* dump the iterator */
    FREE (ext_iter, M_TEMP);

    if (error == 0) {
        /*
         * In the event that the file has no overflow extents, pinned_blocks
         * will never be updated, so we'll properly export 0 pinned blocks to caller
         */
        *pinned = pinned_blocks;
    }

    return error;

}


static int
hfs_getvnode_and_pin (struct hfsmount *hfsmp, uint32_t fileid, uint32_t *pinned) {
    struct vnode *vp;
    int error = 0;
    *pinned = 0;
    uint32_t pblocks;

    /*
     * Acquire the vnode for this file.  This returns a locked cnode on success
     */
    error = hfs_vget(hfsmp, fileid, &vp, 0, 0);
    if (error) {
        /* It's possible the file was open-unlinked. In this case, we'll get ENOENT back. */
        return error;
    }

    /*
     * Symlinks that may have been inserted into the hotfile zone during a previous OS are now stuck
     * here.  We do not want to move them.
     */
    if (!vnode_isreg(vp)) {
        hfs_unlock(VTOC(vp));
        vnode_put(vp);
        return EPERM;
    }

    if (!(VTOC(vp)->c_attr.ca_recflags & kHFSFastDevPinnedMask)) {
        hfs_unlock(VTOC(vp));
        vnode_put(vp);
        return EINVAL;
    }

    error = hfs_pin_vnode(hfsmp, vp, HFS_PIN_IT, &pblocks, vfs_context_kernel());
    if (error == 0) {
        *pinned = pblocks;
    }

    hfs_unlock(VTOC(vp));
    vnode_put(vp);

    return error;

}

/*
 * Pins an HFS Extent record to the underlying CoreStorage.  Assumes that Catalog & Extents overflow
 * B-trees are held locked, as needed.
 *
 * Returns the number of blocks pinned in the output argument 'pinned'
 *
 * Returns error status (0 || errno) in return value.
 */
static int hfs_pin_extent_record (struct hfsmount *hfsmp, HFSPlusExtentRecord extents, uint32_t *pinned) {
    uint32_t pb = 0;
    int i;
    int error;

	if (pinned == NULL) {
		return EINVAL;
	}
    *pinned = 0;



	/* iterate through the extents */
	for ( i = 0; i < kHFSPlusExtentDensity; i++) {
		if (extents[i].startBlock == 0) {
			break;
		}

		error = hfs_pin_block_range (hfsmp, HFS_PIN_IT, extents[i].startBlock,
				extents[i].blockCount, vfs_context_kernel());

		if (error) {
			break;
		}
		pb += extents[i].blockCount;
	}

    *pinned = pb;

	return error;
}

/*
 * Consume an HFS Plus on-disk catalog record and pin its blocks
 * to the underlying CS devnode.
 *
 * NOTE: This is an important distinction!
 * This function takes in an HFSPlusCatalogFile* which is the actual
 * 200-some-odd-byte on-disk representation in the Catalog B-Tree (not
 * one of the run-time structs that we normally use.
 *
 * This assumes that the catalog and extents-overflow btrees
 * are locked, at least in shared mode
 */
static int hfs_pin_catalog_rec (struct hfsmount *hfsmp, HFSPlusCatalogFile *cfp, int rsrc) {
	uint32_t pinned_blocks = 0;
	HFSPlusForkData *forkdata;
	int error = 0;
	uint8_t forktype = 0;

	if (rsrc) {
        forkdata = &cfp->resourceFork;
		forktype = 0xff;
	}
	else {
		forkdata = &cfp->dataFork;
	}

	uint32_t pblocks = 0;

	/* iterate through the inline extents */
	error = hfs_pin_extent_record (hfsmp, forkdata->extents, &pblocks);
	if (error) {
        return error;
	}

	pinned_blocks += pblocks;
    pblocks = 0;

	/* it may have overflow extents */
	if (forkdata->extents[kHFSPlusExtentDensity-1].startBlock != 0) {
        error = hfs_pin_overflow_extents (hfsmp, cfp->fileID, forktype, &pblocks);
	}
    pinned_blocks += pblocks;

	hfsmp->hfs_hotfile_freeblks -= pinned_blocks;

	return error;
}


/*
 *
 */
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
	long starting_temp;

	int started_tr = 0;
	int started_scan = 0;

	int inserted = 0;  /* debug variables */
	int filecount = 0;
	int uncacheable = 0;

	/*
	 * For now, only the boot volume is supported.
	 */
	if ((vfs_flags(HFSTOVFS(hfsmp)) & MNT_ROOTFS) == 0) {
		hfsmp->hfc_stage = HFC_DISABLED;
		return (EPERM);
	}

	/* We grab the HFC mutex even though we're not fully mounted yet, just for orderliness */
	lck_mtx_lock (&hfsmp->hfc_mutex);

	/*
	 * Tracking of hot files requires up-to-date access times.
	 * So if access time updates are disabled, then we disable
	 * hot files, too.
	 */
	if (vfs_flags(HFSTOVFS(hfsmp)) & MNT_NOATIME) {
		hfsmp->hfc_stage = HFC_DISABLED;
		lck_mtx_unlock (&hfsmp->hfc_mutex);
		return EPERM;
	}
	
	//
	// Check if we've been asked to suspend operation
	//
	cnid = GetFileInfo(HFSTOVCB(hfsmp), kRootDirID, ".hotfile-suspend", &cattr, NULL);
	if (cnid != 0) {
		printf("hfs: %s: %s: hotfiles explicitly disabled!  remove /.hotfiles-suspend to re-enable\n", hfsmp->vcbVN, __FUNCTION__);
		hfsmp->hfc_stage = HFC_DISABLED;
		lck_mtx_unlock (&hfsmp->hfc_mutex);
		return EPERM;
	}

	//
	// Check if we've been asked to reset our state.
	//
	cnid = GetFileInfo(HFSTOVCB(hfsmp), kRootDirID, ".hotfile-reset", &cattr, NULL);
	if (cnid != 0) {
		hfs_hotfile_reset(hfsmp);
	}

	if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
		//
		// Cooperative Fusion (CF) systems use different constants 
		// than traditional hotfile systems.  These were picked after a bit of
		// experimentation - we can cache many more files on the
		// ssd in an CF system and we can do so more rapidly
		// so bump the limits considerably (and turn down the
		// duration so that it doesn't take weeks to adopt all
		// the files).
		//
		hfc_default_file_count = 20000;
		hfc_default_duration   = 300;    // 5min
		hfc_max_file_count     = 50000;
		hfc_max_file_size      = (512ULL * 1024ULL * 1024ULL);
	}

	/*
	 * If the Hot File btree exists then metadata zone is ready.
	 */
	cnid = GetFileInfo(HFSTOVCB(hfsmp), kRootDirID, HFC_FILENAME, &cattr, NULL);
	if (cnid != 0 && S_ISREG(cattr.ca_mode)) {
		int recreate = 0;
		
		if (hfsmp->hfc_stage == HFC_DISABLED)
			hfsmp->hfc_stage = HFC_IDLE;
		hfsmp->hfs_hotfile_freeblks = 0;

		if ((hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) && cattr.ca_blocks > 0) {
			//
			// make sure the hotfile btree is pinned
			//
			error = hfc_btree_open(hfsmp, &hfsmp->hfc_filevp);
			if (!error) {
				/* XXX: must fix hfs_pin_vnode too */
				hfs_pin_vnode(hfsmp, hfsmp->hfc_filevp, HFS_PIN_IT, NULL, vfs_context_kernel());
				
			} else {
				printf("hfs: failed to open the btree err=%d.  Recreating hotfile btree.\n", error);
				recreate = 1;
			}
			
			hfs_hotfile_repin_files(hfsmp);

			if (hfsmp->hfc_filevp) {
				(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
				hfsmp->hfc_filevp = NULL;
			}

		} else if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
			// hmmm, the hotfile btree is zero bytes long?  how odd.  let's recreate it.
			printf("hfs: hotfile btree is zero bytes long?!  recreating it.\n");
			recreate = 1;
		}

		if (!recreate) {
			/* don't forget to unlock the mutex */
			lck_mtx_unlock (&hfsmp->hfc_mutex);
			return (0);
		} else {
			//
			// open the hotfile btree file ignoring errors because
			// we need the vnode pointer for hfc_btree_delete() to
			// be able to do its work
			//
			error = hfc_btree_open_ext(hfsmp, &hfsmp->hfc_filevp, 1);
			if (!error) {
				// and delete it!
				error = hfc_btree_delete(hfsmp);
				(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
				hfsmp->hfc_filevp = NULL;
			}
		}
	}

	printf("hfs: %s: %s: creating the hotfile btree\n", hfsmp->vcbVN, __FUNCTION__);
	if (hfs_start_transaction(hfsmp) != 0) {
		lck_mtx_unlock (&hfsmp->hfc_mutex);
		return EINVAL;
	}

	/* B-tree creation must be journaled */
	started_tr = 1;

	error = hfc_btree_create(hfsmp, HFSTOVCB(hfsmp)->blockSize, HFC_DEFAULT_FILE_COUNT);
	if (error) {
#if HFC_VERBOSE
		printf("hfs: Error %d creating hot file b-tree on %s \n", error, hfsmp->vcbVN);
#endif
		goto recording_init_out;
	}

	hfs_end_transaction (hfsmp);
	started_tr = 0;
	/*
	 * Do a journal flush + flush track cache. We have to ensure that the async I/Os have been issued to the media
	 * before proceeding.
	 */
	hfs_flush (hfsmp, HFS_FLUSH_FULL);

	/* now re-start a new transaction */
	if (hfs_start_transaction (hfsmp) != 0) {
		lck_mtx_unlock (&hfsmp->hfc_mutex);
		return EINVAL;
	}
	started_tr = 1;

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
		goto recording_init_out;
	}

	/*
	 * This function performs work similar to namei; we must NOT hold the catalog lock while
	 * calling it. This will decorate catalog records as being pinning candidates. (no hotfiles work)
	 */
	hfs_setup_default_cf_hotfiles(hfsmp);

	/*
	 * now grab the hotfiles b-tree vnode/cnode lock first, as it is not classified as a systemfile.
	 */
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
		error = EPERM;
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		/* zero it out to avoid pinning later on */
		hfsmp->hfc_filevp = NULL;
		goto recording_init_out;
	}

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		error = ENOMEM;
		hfs_unlock (VTOC(hfsmp->hfc_filevp));
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		/* zero it out to avoid pinning */
		hfsmp->hfc_filevp = NULL;
		goto recording_init_out;
	}

	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;
	key->keyLength = HFC_KEYLENGTH;

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;

#if HFC_VERBOSE
	printf("hfs: Evaluating space for \"%s\" metadata zone... (freeblks %d)\n", HFSTOVCB(hfsmp)->vcbVN,
	       hfsmp->hfs_hotfile_freeblks);
#endif

	/*
	 * Get ready to scan the Catalog file. We explicitly do NOT grab the catalog lock because
	 * we're fully single-threaded at the moment (by virtue of being called during mount()),
	 * and if we have to grow the hotfile btree, then we would need to grab the catalog lock
	 * and if we take a shared lock here, it would deadlock (see <rdar://problem/21486585>)
	 *
	 * We already started a transaction so we should already be holding the journal lock at this point.
	 * Note that we have to hold the journal lock / start a txn BEFORE the systemfile locks.
	 */

	error = BTScanInitialize(VTOF(HFSTOVCB(hfsmp)->catalogRefNum), 0, 0, 0,
	                       kCatSearchBufferSize, &scanstate);
	if (error) {
		printf("hfs_recording_init: err %d BTScanInit\n", error);

		/* drop the systemfile locks */
		hfs_unlock(VTOC(hfsmp->hfc_filevp));

		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);

		/* zero it out to avoid pinning */
		hfsmp->hfc_filevp = NULL;
		goto recording_init_out;
	}

	started_scan = 1;

	filefork = VTOF(hfsmp->hfc_filevp);

	starting_temp = random() % HF_TEMP_RANGE;

	/*
	 * Visit all the catalog btree leaf records. We have to hold the catalog lock to do this.
	 *
	 * NOTE: The B-Tree scanner reads from the media itself. Under normal circumstances it would be
	 * fine to simply use b-tree routines to read blocks that correspond to b-tree nodes, because the
	 * block cache is going to ensure you always get the cached copy of a block (even if a journal
	 * txn has modified one of those blocks).  That is NOT true when
	 * using the scanner.  In particular, it will always read whatever is on-disk. So we have to ensure
	 * that the journal has flushed and that the async I/Os to the metadata files have been issued.
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

		if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
			if (filep->flags & kHFSDoNotFastDevPinMask) {
				uncacheable++;
			}

			//
			// If the file does not have the FastDevPinnedMask set, we
			// can ignore it and just go to the next record.
			//
			if ((filep->flags & kHFSFastDevPinnedMask) == 0) {
				continue;
			}
		} else if (filep->dataFork.totalBlocks == 0) {
			continue;
		}

		/*
		 * On a regular hdd, any file that has blocks inside
		 * the hot file space is recorded for later eviction.
		 *
		 * For now, resource forks are ignored.
		 *
		 * We don't do this on CF systems as there is no real
		 * hotfile area - we just pin/unpin blocks belonging to
		 * interesting files.
		 */
		if (!(hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) && !hotextents(hfsmp, &filep->dataFork.extents[0])) {
			continue;
		}
		cnid = filep->fileID;

		/* Skip over journal files and the hotfiles B-Tree file. */
		if (cnid == hfsmp->hfs_jnlfileid
			|| cnid == hfsmp->hfs_jnlinfoblkid
			|| cnid == VTOC(hfsmp->hfc_filevp)->c_fileid) {
			continue;
		}
		/*
		 * XXX - need to skip quota files as well.
		 */

		uint32_t temp;

		if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
			int rsrc = 0;

			temp = (uint32_t)starting_temp++;
			if (filep->flags & kHFSAutoCandidateMask) {
				temp += MAX_NORMAL_TEMP;
			}

			/* use the data fork by default */
			if (filep->dataFork.totalBlocks == 0) {
				/*
                 * but if empty, switch to rsrc as its likely
                 * a compressed file
                 */
				rsrc = 1;
			}

			error =  hfs_pin_catalog_rec (hfsmp, filep, rsrc);
			if (error)
				break;

		} else {
			temp = HFC_MINIMUM_TEMPERATURE;
		}

		/* Insert a hot file entry. */
		key->keyLength   = HFC_KEYLENGTH;
		key->temperature = temp;
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
		data = temp;
		error = BTInsertRecord(filefork, iterator, &record, record.itemSize);
		if (error) {
			printf("hfs_recording_init: BTInsertRecord failed %d (fileid %d)\n", error, key->fileID);
			error = MacToVFSError(error);
			break;
		}
		inserted++;
	} // end catalog iteration loop

	save_btree_user_info(hfsmp);
	(void) BTFlushPath(filefork);

recording_init_out:

	/* Unlock first, then pin after releasing everything else */
	if (hfsmp->hfc_filevp) {
		hfs_unlock (VTOC(hfsmp->hfc_filevp));
	}

	if (started_scan) {
		(void) BTScanTerminate (&scanstate, &data, &data, &data);
	}

	if (started_tr) {
		hfs_end_transaction(hfsmp);
	}

#if HFC_VERBOSE
	printf("hfs: %d files identified out of %d (freeblocks is now: %d)\n", inserted, filecount, hfsmp->hfs_hotfile_freeblks);
	if (uncacheable) {
		printf("hfs: %d files were marked as uncacheable\n", uncacheable);
	}
#endif
	
	if (iterator)
		FREE(iterator, M_TEMP);

	if (hfsmp->hfc_filevp) {
		if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
			hfs_pin_vnode(hfsmp, hfsmp->hfc_filevp, HFS_PIN_IT, NULL, vfs_context_kernel());
		}
		(void) hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
		hfsmp->hfc_filevp = NULL;
	}

	if (error == 0)
		hfsmp->hfc_stage = HFC_IDLE;

	/* Finally, unlock the HFC mutex */
	lck_mtx_unlock (&hfsmp->hfc_mutex);

	return (error);
}

/*
 * Use sync to perform ocassional background work.
 */
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
			(void) hotfiles_adopt(hfsmp, ctx);
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
hf_ignore_process(const char *pname, size_t maxlen)
{
	if (   strncmp(pname, "mds", maxlen) == 0
	    || strncmp(pname, "mdworker", maxlen) == 0
	    || strncmp(pname, "mds_stores", maxlen) == 0
	    || strncmp(pname, "makewhatis", maxlen) == 0) {
		return 1;
	}

	return 0;
	
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

	/* 
	 * Only regular files are eligible for hotfiles addition. 
	 * 
	 * Symlinks were previously added to the list and may exist in 
	 * extant hotfiles regions, but no new ones will be added, and no
	 * symlinks will now be relocated/evicted from the hotfiles region.
	 */
	if (!vnode_isreg(vp) || vnode_issystem(vp)) {
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

	if (cp->c_attr.ca_recflags & (kHFSFastDevPinnedMask|kHFSDoNotFastDevPinMask)) {
		// it's already a hotfile or can't be a hotfile...
		return 0;
	}

	if (vnode_isdir(vp) || vnode_issystem(vp) || (cp->c_flag & (C_DELETED | C_NOEXISTS))) {
		return 0;
	}

	if ((hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) && vnode_isfastdevicecandidate(vp)) {
		//
		// On cooperative fusion (CF) systems we have different criteria for whether something
		// can be pinned to the ssd.
		//
		if (cp->c_flag & (C_DELETED|C_NOEXISTS)) {
			//
			// dead files are definitely not worth caching
			//
			return 0;
		} else if (ffp->ff_blocks == 0 && !(cp->c_bsdflags & UF_COMPRESSED) && !(cp->c_attr.ca_recflags & kHFSFastDevCandidateMask)) {
			//
			// empty files aren't worth caching but compressed ones might be, as are 
			// newly created files that live in WorthCaching directories... 
			//
			return 0;
		}

		char pname[256];
		pname[0] = '\0';
		proc_selfname(pname, sizeof(pname));
		if (hf_ignore_process(pname, sizeof(pname))) {
			// ignore i/o's from certain system daemons 
			return 0;
		}

		temperature = cp->c_fileid;        // in memory we just keep it sorted by file-id
	} else {
		// the normal hard drive based hotfile checks
		if ((ffp->ff_bytesread == 0) ||
		    (ffp->ff_blocks == 0) ||
		    (ffp->ff_size == 0) ||
		    (ffp->ff_blocks > hotdata->maxblocks) ||
		    (cp->c_bsdflags & (UF_NODUMP | UF_COMPRESSED)) ||
		    (cp->c_atime < hfsmp->hfc_timebase)) {
			return (0);
		}

		temperature = ffp->ff_bytesread / ffp->ff_size;
		if (temperature < hotdata->threshold) {
			return (0);
		}
	}

	/*
	 * If there is room or this file is hotter than
	 * the coldest one then add it to the list.
	 *
	 */
	if ((hotdata->activefiles < hfsmp->hfc_maxfiles) ||
	    (hotdata->coldest == NULL) ||
	    (temperature >= hotdata->coldest->temperature)) {
		++hotdata->refcount;
		entry = hf_getnewentry(hotdata);
		entry->temperature = temperature;
		entry->fileid = cp->c_fileid;
		//
		// if ffp->ff_blocks is zero, it might be compressed so make sure we record
		// that there's at least one block.
		//
		entry->blocks = ffp->ff_blocks ? ffp->ff_blocks : 1;   
		if (hf_insert(hotdata, entry) == EEXIST) {
			// entry is already present, don't need to add it again
			entry->right = hotdata->freelist;
			hotdata->freelist = entry;
		}
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

	if ((!vnode_isreg(vp)) || vnode_issystem(vp)) {
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

int
hfs_hotfile_deleted(__unused struct vnode *vp)
{
#if 1
	return 0;
#else	
	//
	// XXXdbg - this code, while it would work, would introduce a huge inefficiency
	//          to deleting files as the way it's written would require us to open
	//          the hotfile btree on every open, delete two records in it and then
	//          close the hotfile btree (which involves more writes).
	//
	//          We actually can be lazy about deleting hotfile records for files
	//          that get deleted.  When it's time to evict things, if we encounter
	//          a record that references a dead file (i.e. a fileid which no
	//          longer exists), the eviction code will remove the records.  Likewise
	//          the code that scans the HotFile B-Tree at boot time to re-pin files
	//          will remove dead records.
	//

	hotfile_data_t *hotdata;
	hfsmount_t *hfsmp;
	cnode_t *cp;
	filefork_t *filefork;
	u_int32_t temperature;
	BTreeIterator * iterator = NULL;
	FSBufferDescriptor record;
	HotFileKey *key;
	u_int32_t data;
	int error=0;

	cp = VTOC(vp);
	if (cp == NULL || !(cp->c_attr.ca_recflags & kHFSFastDevPinnedMask)) {
		return 0;
	}

	hfsmp = VTOHFS(vp);
	if (!(hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN)) {
		return 0;
	}
	
	if (hfc_btree_open(hfsmp, &hfsmp->hfc_filevp) != 0 || hfsmp->hfc_filevp == NULL) {
		// either there is no hotfile info or it's damaged
		return EINVAL;
	}
	
	filefork = VTOF(hfsmp->hfc_filevp);
	if (filefork == NULL) {
		return 0;
	}

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		return ENOMEM;
	}	
	bzero(iterator, sizeof(*iterator));
	key = (HotFileKey*) &iterator->key;

	record.bufferAddress = &data;
	record.itemSize = sizeof(u_int32_t);
	record.itemCount = 1;

	key->keyLength = HFC_KEYLENGTH;
	key->temperature = HFC_LOOKUPTAG;
	key->fileID = cp->c_fileid;
	key->forkType = 0;

	lck_mtx_lock(&hfsmp->hfc_mutex);
	(void) BTInvalidateHint(iterator);
	if (BTSearchRecord(filefork, iterator, &record, NULL, iterator) == 0) {
		temperature = key->temperature;
		hfc_btree_delete_record(hfsmp, iterator, key);
	} else {
		//printf("hfs: hotfile_deleted: did not find fileid %d\n", cp->c_fileid);
		error = ENOENT;
	}

	if ((hotdata = (hotfile_data_t *)hfsmp->hfc_recdata) != NULL) {
		// just in case, also make sure it's removed from the in-memory list as well
		++hotdata->refcount;
		hf_delete(hotdata, cp->c_fileid, cp->c_fileid);
		--hotdata->refcount;
	}

	lck_mtx_unlock(&hfsmp->hfc_mutex);
	FREE(iterator, M_TEMP);

	hfc_btree_close(hfsmp, hfsmp->hfc_filevp);
	
	return error;
#endif
}

int
hfs_hotfile_adjust_blocks(struct vnode *vp, int64_t num_blocks)
{
	hfsmount_t *hfsmp;
	
	if (vp == NULL) {
		return 0;
	}

	hfsmp = VTOHFS(vp);

	if (!(hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) || num_blocks == 0 || vp == NULL) {
		return 0;
	}

	//
	// if file is not HotFileCached or it has the CanNotHotFile cache
	// bit set then there is nothing to do
	//
	if (!(VTOC(vp)->c_attr.ca_recflags & kHFSFastDevPinnedMask) || (VTOC(vp)->c_attr.ca_recflags & kHFSDoNotFastDevPinMask)) {
		// it's not a hot file or can't be one so don't bother tracking
		return 0;
	}
	
	OSAddAtomic(num_blocks, &hfsmp->hfs_hotfile_blk_adjust);

	return (0);
}

//
// Assumes hfsmp->hfc_mutex is LOCKED
//
static int
hfs_hotfile_cur_freeblks(hfsmount_t *hfsmp)
{
	if (hfsmp->hfc_stage < HFC_IDLE) {
		return 0;
	}
	
	int cur_blk_adjust = hfsmp->hfs_hotfile_blk_adjust;   // snap a copy of this value

	if (cur_blk_adjust) {
		OSAddAtomic(-cur_blk_adjust, &hfsmp->hfs_hotfile_blk_adjust);
		hfsmp->hfs_hotfile_freeblks += cur_blk_adjust;
	}

	return hfsmp->hfs_hotfile_freeblks;
}


/*
 *========================================================================
 *                     HOT FILE MAINTENANCE ROUTINES
 *========================================================================
 */

static int
hotfiles_collect_callback(struct vnode *vp, __unused void *cargs)
{
        if ((vnode_isreg(vp)) && !vnode_issystem(vp))
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

	if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
		// on ssd's we don't refine the temperature since the
		// replacement algorithm is simply random
		return 0;
	}

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
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
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
hotfiles_adopt(struct hfsmount *hfsmp, vfs_context_t ctx)
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
	//
	// all files in a given adoption phase have a temperature
	// that starts at a random value and then increases linearly.
	// the idea is that during eviction, files that were adopted
	// together will be evicted together
	//
	long starting_temp = random() % HF_TEMP_RANGE;
	long temp_adjust = 0;

	if ((listp = (hotfilelist_t  *)hfsmp->hfc_recdata) == NULL)
		return (0);	

	if (hfsmp->hfc_stage != HFC_ADOPTION) {
		return (EBUSY);
	}
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
		return (EPERM);
	}

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	if (iterator == NULL) {
		hfs_unlock(VTOC(hfsmp->hfc_filevp));
		return (ENOMEM);
	}

#if HFC_VERBOSE
		printf("hfs:%s: hotfiles_adopt: (hfl_next: %d, hotfile start/end block: %d - %d; max/free: %d/%d; maxfiles: %d)\n",
		       hfsmp->vcbVN,
		       listp->hfl_next,
		       hfsmp->hfs_hotfile_start, hfsmp->hfs_hotfile_end,
		       hfsmp->hfs_hotfile_maxblks, hfsmp->hfs_hotfile_freeblks, hfsmp->hfc_maxfiles);
#endif

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
		 * Skip entries that aren't going to work.
		 */
		if (listp->hfl_hotfile[i].hf_temperature == 0) {
			//printf("hfs: zero temp on file-id %d\n", listp->hfl_hotfile[i].hf_fileid);
			listp->hfl_next++;
			continue;
		}
		if (listp->hfl_hotfile[i].hf_fileid == VTOC(hfsmp->hfc_filevp)->c_fileid) {
			//printf("hfs: cannot adopt the hotfile b-tree itself! (file-id %d)\n", listp->hfl_hotfile[i].hf_fileid);
			listp->hfl_next++;
			continue;
		}
		if (listp->hfl_hotfile[i].hf_fileid < kHFSFirstUserCatalogNodeID) {
			//printf("hfs: cannot adopt system files (file-id %d)\n", listp->hfl_hotfile[i].hf_fileid);
			listp->hfl_next++;
			continue;
		}

		/*
		 * Acquire a vnode for this file.
		 */
		error = hfs_vget(hfsmp, listp->hfl_hotfile[i].hf_fileid, &vp, 0, 0);
		if (error) {
			//printf("failed to get fileid %d (err %d)\n", listp->hfl_hotfile[i].hf_fileid, error);
			if (error == ENOENT) {
				error = 0;
				listp->hfl_next++;
				continue;  /* stale entry, go to next */
			}
			break;
		}

		//printf("hfs: examining hotfile entry w/fileid %d, temp %d, blocks %d (HotFileCached: %s)\n",
		//       listp->hfl_hotfile[i].hf_fileid, listp->hfl_hotfile[i].hf_temperature,
		//       listp->hfl_hotfile[i].hf_blocks,
		//       (VTOC(vp)->c_attr.ca_recflags & kHFSFastDevPinnedMask) ? "YES" : "NO");

		if (!vnode_isreg(vp)) {
			/* Symlinks are ineligible for adoption into the hotfile zone.  */
			//printf("hfs: hotfiles_adopt: huh, not a file %d (%d)\n", listp->hfl_hotfile[i].hf_fileid, VTOC(vp)->c_cnid);
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			listp->hfl_hotfile[i].hf_temperature = 0;
			listp->hfl_next++;
			continue;  /* stale entry, go to next */
		}
		if (   (VTOC(vp)->c_flag & (C_DELETED | C_NOEXISTS))
		    || (!(hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) && hotextents(hfsmp, &VTOF(vp)->ff_extents[0]))
		    || (VTOC(vp)->c_attr.ca_recflags & (kHFSFastDevPinnedMask|kHFSDoNotFastDevPinMask))) {
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			listp->hfl_hotfile[i].hf_temperature = 0;
			listp->hfl_next++;
			listp->hfl_totalblocks -= listp->hfl_hotfile[i].hf_blocks;
			continue;  /* stale entry, go to next */
		}

		fileblocks = VTOF(vp)->ff_blocks;

		//
		// for CF, if the file is empty (and not compressed) or it is too large,
		// do not try to pin it.  (note: if fileblocks == 0 but the file is marked
		// as compressed, we may still be able to cache it).
		//
		if ((hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) &&
		    ((fileblocks == 0 && !(VTOC(vp)->c_bsdflags & UF_COMPRESSED)) ||
		     (unsigned int)fileblocks > (HFC_MAXIMUM_FILESIZE / (uint64_t)HFSTOVCB(hfsmp)->blockSize))) {
			// don't try to cache something too large or that's zero-bytes

			vnode_clearfastdevicecandidate(vp);    // turn off the fast-dev-candidate flag so we don't keep trying to cache it.

			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			listp->hfl_hotfile[i].hf_temperature = 0;
			listp->hfl_next++;
			listp->hfl_totalblocks -= listp->hfl_hotfile[i].hf_blocks;
			continue;  /* entry is too big, just carry on with the next guy */
		}

		//
		// If a file is not an autocandidate (i.e. it's a user-tagged file desirous of
		// being hotfile cached) but it is already bigger than 4 megs, don't bother
		// hotfile caching it.  Note that if a user tagged file starts small, gets
		// adopted and then grows over time we will allow it to grow bigger than 4 megs
		// which is intentional for things like the Mail or Photos database files which
		// grow slowly over time and benefit from being on the FastDevice.
		//
		if ((hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) &&
		    !(VTOC(vp)->c_attr.ca_recflags & kHFSAutoCandidateMask) && 
		    (VTOC(vp)->c_attr.ca_recflags & kHFSFastDevCandidateMask) && 
		    (unsigned int)fileblocks > ((4*1024*1024) / (uint64_t)HFSTOVCB(hfsmp)->blockSize)) {

			vnode_clearfastdevicecandidate(vp);    // turn off the fast-dev-candidate flag so we don't keep trying to cache it.

			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			listp->hfl_hotfile[i].hf_temperature = 0;
			listp->hfl_next++;
			listp->hfl_totalblocks -= listp->hfl_hotfile[i].hf_blocks;
			continue;  /* entry is too big, just carry on with the next guy */
		}

		if (fileblocks > hfs_hotfile_cur_freeblks(hfsmp)) {
			//
			// No room for this file.  Although eviction should have made space
			// it's best that we check here as well since writes to existing
			// hotfiles may have eaten up space since we performed eviction
			//
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			listp->hfl_next++;
			listp->hfl_totalblocks -= fileblocks;
			continue;  /* entry too big, go to next */
		}
		
		if ((blksmoved > 0) &&
		    (blksmoved + fileblocks) > HFC_BLKSPERSYNC) {
			//
			// we've done enough work, let's be nice to the system and
			// stop until the next iteration
			//
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			break;  /* adopt this entry the next time around */
		}
		if (VTOC(vp)->c_desc.cd_nameptr)
			data = *(const u_int32_t *)(VTOC(vp)->c_desc.cd_nameptr);
		else
			data = 0x3f3f3f3f;


		if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
			//
			// For CF we pin the blocks belonging to the file
			// to the "fast" (aka ssd) media
			//
			uint32_t pinned_blocks;

			if (vnode_isautocandidate(vp)) {
				VTOC(vp)->c_attr.ca_recflags |= kHFSAutoCandidateMask;
			}
			if (VTOC(vp)->c_attr.ca_recflags & kHFSAutoCandidateMask) {
				//
				// this moves auto-cached files to the higher tier 
				// of "temperatures" which means they are less likely
				// to get evicted (user selected hotfiles will get
				// evicted first in the theory that they change more
				// frequently compared to system files)
				//
				temp_adjust = MAX_NORMAL_TEMP;
			} else {
				temp_adjust = 0;
			}

			hfs_unlock(VTOC(vp));  // don't need an exclusive lock for this
			hfs_lock(VTOC(vp), HFS_SHARED_LOCK, HFS_LOCK_ALLOW_NOEXISTS);

			error = hfs_pin_vnode(hfsmp, vp, HFS_PIN_IT, &pinned_blocks, ctx);

			fileblocks = pinned_blocks;

			// go back to an exclusive lock since we're going to modify the cnode again
			hfs_unlock(VTOC(vp));
			hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
		} else {
			//
			// Old style hotfiles moves the data to the center (aka "hot")
			// region of the disk
			//
			error = hfs_relocate(vp, hfsmp->hfs_hotfile_start, kauth_cred_get(), current_proc());
		}

		if (!error) {
			VTOC(vp)->c_attr.ca_recflags |= kHFSFastDevPinnedMask;
			VTOC(vp)->c_flag |= C_MODIFIED;
		} else if ((hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) && error == EALREADY) {
			//
			// If hfs_pin_vnode() returned EALREADY then this file is not
			// ever able to be hotfile cached the normal way.  This can
			// happen with compressed files which have their data stored
			// in an extended attribute.  We flag them so that we won't
			// bother to try and hotfile cache them again the next time
			// they're read.
			//
			VTOC(vp)->c_attr.ca_recflags |= kHFSDoNotFastDevPinMask;
			VTOC(vp)->c_flag |= C_MODIFIED;
		}

		hfs_unlock(VTOC(vp));
		vnode_put(vp);
		if (error) {
#if HFC_VERBOSE
			if (error != EALREADY) {
				printf("hfs: hotfiles_adopt: could not relocate file %d (err %d)\n", listp->hfl_hotfile[i].hf_fileid, error);
			}
#endif

			if (last < listp->hfl_count) {
				last++;
			}
			/* Move on to next item. */
			listp->hfl_next++;
			continue;
		}
		/* Keep hot file free space current. */
		hfsmp->hfs_hotfile_freeblks -= fileblocks;
		listp->hfl_totalblocks -= fileblocks;
		
		/* Insert hot file entry */
		key->keyLength   = HFC_KEYLENGTH;

		if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
			//
			// The "temperature" for a CF hotfile is simply a random
			// number that we sequentially increment for each file in
			// the set of files we're currently adopting.  This has the
			// nice property that all of the files we pin to the ssd
			// in the current phase will sort together in the hotfile
			// btree.  When eviction time comes we will evict them
			// together as well.  This gives the eviction phase temporal
			// locality - things written together get evicted together
			// which is what ssd's like.
			//
			listp->hfl_hotfile[i].hf_temperature = (uint32_t)temp_adjust + starting_temp++;
		}

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
			int orig_error = error;
			error = MacToVFSError(error);
			printf("hfs: hotfiles_adopt:1: BTInsertRecord failed %d/%d (fileid %d)\n", error, orig_error, key->fileID);
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
			int orig_error = error;
			error = MacToVFSError(error);
			printf("hfs: hotfiles_adopt:2: BTInsertRecord failed %d/%d (fileid %d)\n", error, orig_error, key->fileID);
			stage = HFC_IDLE;
			break;
		} else {
			(void) BTFlushPath(filefork);
			blksmoved += fileblocks;
		}

		listp->hfl_next++;
		if (listp->hfl_next >= listp->hfl_count) {
			break;
		}

		/* Transaction complete. */
		if (startedtrans) {
		    hfs_end_transaction(hfsmp);
		    startedtrans = 0;
		}

		if (hfs_hotfile_cur_freeblks(hfsmp) <= 0) {
#if HFC_VERBOSE
			printf("hfs: hotfiles_adopt: free space exhausted (%d)\n", hfsmp->hfs_hotfile_freeblks);
#endif
			break;
		}
	} /* end for */

#if HFC_VERBOSE
	printf("hfs: hotfiles_adopt: [%d] adopted %d blocks (%d files left)\n", listp->hfl_next, blksmoved, listp->hfl_count - i);
#endif
	if (!startedtrans) {
		// start a txn so we'll save the btree summary info
		if (hfs_start_transaction(hfsmp) == 0) {
			startedtrans = 1;
		}
	}		

	/* Finish any outstanding transactions. */
	if (startedtrans) {
		save_btree_user_info(hfsmp);

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

	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
		return (EPERM);
	}

#if HFC_VERBOSE
		printf("hfs:%s: hotfiles_evict (hotfile start/end block: %d - %d; max/free: %d/%d; maxfiles: %d)\n",
		       hfsmp->vcbVN,
		       hfsmp->hfs_hotfile_start, hfsmp->hfs_hotfile_end,
		       hfsmp->hfs_hotfile_maxblks, hfsmp->hfs_hotfile_freeblks, hfsmp->hfc_maxfiles);
#endif

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

#if HFC_VERBOSE
	printf("hfs: hotfiles_evict: reclaim blks %d\n", listp->hfl_reclaimblks);
#endif
	
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

		// Jump straight to delete for some files...
		if (key->fileID == VTOC(hfsmp->hfc_filevp)->c_fileid
			|| key->fileID == hfsmp->hfs_jnlfileid
			|| key->fileID == hfsmp->hfs_jnlinfoblkid
			|| key->fileID < kHFSFirstUserCatalogNodeID) {
			goto delete;
		}

		/*
		 * Aquire the vnode for this file.
		 */
		error = hfs_vget(hfsmp, key->fileID, &vp, 0, 0);
		if (error) {
			if (error == ENOENT) {
				goto delete;  /* stale entry, go to next */
			} else {
				printf("hfs: hotfiles_evict: err %d getting file %d\n",
				       error, key->fileID);
			}
			break;
		}

		/* 
		 * Symlinks that may have been inserted into the hotfile zone during a previous OS are now stuck 
		 * here.  We do not want to move them. 
		 */
		if (!vnode_isreg(vp)) {
			//printf("hfs: hotfiles_evict: huh, not a file %d\n", key->fileID);
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
		if (!hotextents(hfsmp, &VTOF(vp)->ff_extents[0]) && !(VTOC(vp)->c_attr.ca_recflags & kHFSFastDevPinnedMask)) {
#if HFC_VERBOSE
			printf("hfs: hotfiles_evict: file %d isn't hot!\n", key->fileID);
#endif
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			goto delete;  /* stale entry, go to next */
		}
		
		/*
		 * Relocate file out of hot area.  On cooperative fusion (CF) that just 
		 * means un-pinning the data from the ssd.  For traditional hotfiles that means moving
		 * the file data out of the hot region of the disk.
		 */
		if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
			uint32_t pinned_blocks;
			
			hfs_unlock(VTOC(vp));  // don't need an exclusive lock for this
			hfs_lock(VTOC(vp), HFS_SHARED_LOCK, HFS_LOCK_ALLOW_NOEXISTS);

			error = hfs_pin_vnode(hfsmp, vp, HFS_UNPIN_IT, &pinned_blocks, ctx);
			fileblocks = pinned_blocks;

			if (!error) {
				// go back to an exclusive lock since we're going to modify the cnode again
				hfs_unlock(VTOC(vp));
				hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
			}
		} else {
			error = hfs_relocate(vp, HFSTOVCB(hfsmp)->nextAllocation, vfs_context_ucred(ctx), vfs_context_proc(ctx));
		}
		if (error) {
#if HFC_VERBOSE
			printf("hfs: hotfiles_evict: err %d relocating file %d\n", error, key->fileID);
#endif
			hfs_unlock(VTOC(vp));
			vnode_put(vp);
			bt_op = kBTreeNextRecord;
			goto next;  /* go to next */
		} else {
			VTOC(vp)->c_attr.ca_recflags &= ~kHFSFastDevPinnedMask;
			VTOC(vp)->c_flag |= C_MODIFIED;
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
		save_btree_user_info(hfsmp);

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


	if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
		//
		// hotfiles don't age on CF
		//
		return 0;
	}

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
	if (hfs_lock(VTOC(hfsmp->hfc_filevp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT) != 0) {
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
	return hfc_btree_open_ext(hfsmp, vpp, 0);
}

static int
hfc_btree_open_ext(struct hfsmount *hfsmp, struct vnode **vpp, int ignore_btree_errs)
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
	int newvnode_flags = 0;

	*vpp = NULL;
	p = current_proc();

	bzero(&cdesc, sizeof(cdesc));
	cdesc.cd_parentcnid = kRootDirID;
	cdesc.cd_nameptr = (const u_int8_t *)filename;
	cdesc.cd_namelen = strlen(filename);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	error = cat_lookup(hfsmp, &cdesc, 0, 0, &cdesc, &cattr, &cfork, NULL);

	hfs_systemfile_unlock(hfsmp, lockflags);

	if (error) {
		printf("hfs: hfc_btree_open: cat_lookup error %d\n", error);
		return (error);
	}
again:
	cdesc.cd_flags |= CD_ISMETA;
	error = hfs_getnewvnode(hfsmp, NULL, NULL, &cdesc, 0, &cattr, 
							&cfork, &vp, &newvnode_flags);
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
		if (!ignore_btree_errs) {
			printf("hfs: hfc_btree_open: BTOpenPath error %d; filesize %lld\n", error, VTOF(vp)->ff_size);
			error = MacToVFSError(error);
		} else {
			error = 0;
		}
	}

	hfs_unlock(VTOC(vp));
	if (error == 0) {
		*vpp = vp;
		vnode_ref(vp);  /* keep a reference while its open */
	}
	vnode_put(vp);

	if (!vnode_issystem(vp))
		panic("hfs: hfc_btree_open: not a system file (vp = %p)", vp);

	HotFilesInfo hotfileinfo;

	if (error == 0 && (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN)) {
		if ((BTGetUserData(VTOF(vp), &hotfileinfo, sizeof(hotfileinfo)) == 0) && (SWAP_BE32 (hotfileinfo.magic) == HFC_MAGIC)) {
			if (hfsmp->hfs_hotfile_freeblks == 0) {
				hfsmp->hfs_hotfile_freeblks = hfsmp->hfs_hotfile_maxblks - SWAP_BE32 (hotfileinfo.usedblocks);
			}

			hfs_hotfile_cur_freeblks(hfsmp);        // factors in any adjustments that happened at run-time
		}
	}
	
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
	    hfs_flush(hfsmp, HFS_FLUSH_JOURNAL);
	}

	if (vnode_get(vp) == 0) {
		error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT);
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

//
// Assumes that hfsmp->hfc_filevp points to the hotfile btree vnode
// (i.e. you called hfc_btree_open() ahead of time)
//
static int
hfc_btree_delete_record(struct hfsmount *hfsmp, BTreeIterator *iterator, HotFileKey *key)
{
	int error;
	filefork_t *filefork=VTOF(hfsmp->hfc_filevp);

	/* Start a new transaction before calling BTree code. */
	if (hfs_start_transaction(hfsmp) != 0) {
		return EINVAL;
	}

	error = BTDeleteRecord(filefork, iterator);
	if (error) {
		error = MacToVFSError(error);
		printf("hfs: failed to delete record for file-id %d : err %d\n", key->fileID, error);
		goto out;
	}

	int savedtemp;
	savedtemp = key->temperature;
	key->temperature = HFC_LOOKUPTAG;
	error = BTDeleteRecord(filefork, iterator);
	if (error) {
		error = MacToVFSError(error);
		printf("hfs:2: failed to delete record for file-id %d : err %d\n", key->fileID, error);
	}
	key->temperature = savedtemp;

	(void) BTFlushPath(filefork);

out:
	/* Transaction complete. */
	hfs_end_transaction(hfsmp);

	return error;
}

//
// You have to have already opened the hotfile btree so
// that hfsmp->hfc_filevp is filled in.
//
static int
hfc_btree_delete(struct hfsmount *hfsmp)
{
	struct vnode *dvp = NULL;
	vfs_context_t ctx = vfs_context_current();
	struct vnode_attr va;
	struct componentname cname;
	static char filename[] = HFC_FILENAME;
	int  error;

	error = VFS_ROOT(HFSTOVFS(hfsmp), &dvp, ctx);
	if (error) {
		return (error);
	}
	cname.cn_nameiop = DELETE;
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

	if (hfs_start_transaction(hfsmp) != 0) {
	    error = EINVAL;
	    goto out;
	} 

	/* call ourselves directly, ignore the higher-level VFS file creation code */
	error = VNOP_REMOVE(dvp, hfsmp->hfc_filevp, &cname, 0, ctx);
	if (error) {
		printf("hfs: error %d removing HFBT on %s\n", error, HFSTOVCB(hfsmp)->vcbVN);
	}

	hfs_end_transaction(hfsmp);

out:
	if (dvp) {
		vnode_put(dvp);
		dvp = NULL;
	}

	return 0;
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

	if (hfs_start_transaction(hfsmp) != 0) {
	    error = EINVAL;
	    goto out;
	} 

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
	if ((error = hfs_lock(VTOC(vp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT))) {
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

		if (kmem_alloc(kernel_map, (vm_offset_t *)&buffer, nodesize, VM_KERN_MEMORY_FILE)) {
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
		if (hfsmp->hfs_flags & HFS_CS_HOTFILE_PIN) {
			if (hfsmp->hfs_hotfile_freeblks == 0) {
				hfsmp->hfs_hotfile_freeblks = hfsmp->hfs_hotfile_maxblks;
			}
			hotfileinfo->usedblocks = SWAP_BE32 (hfsmp->hfs_hotfile_maxblks - hfsmp->hfs_hotfile_freeblks);
		} else {
			hotfileinfo->maxfilecnt  = SWAP_BE32 (HFC_DEFAULT_FILE_COUNT);
		}
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
		error = hfs_truncate(vp, (off_t)filesize, IO_NDELAY, 0, ctx);
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
	hfs_end_transaction(hfsmp);
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
static int
hf_insert(hotfile_data_t *hotdata, hotfile_entry_t *newentry) 
{
	hotfile_entry_t *entry = hotdata->rootentry;
	u_int32_t fileid = newentry->fileid;
	u_int32_t temperature = newentry->temperature;

	if (entry == NULL) {
		hotdata->rootentry = newentry;
		hotdata->coldest = newentry;
		hotdata->activefiles++;
		return 0;
	}

	while (entry) {
		if (temperature > entry->temperature) {
			if (entry->right) {
				entry = entry->right;
			} else {
				entry->right = newentry;
				break;
			}
		} else if (temperature < entry->temperature) {
			if (entry->left) {
				entry = entry->left;
			} else {
			    	entry->left = newentry;
				break;
			}
		} else if (fileid > entry->fileid) { 
			if (entry->right) {
				entry = entry->right;
			} else {
	       			if (entry->fileid != fileid)
					entry->right = newentry;
				break;
			}
		} else { 
			if (entry->left) {
				entry = entry->left;
			} else {
	       			if (entry->fileid != fileid) {
			    		entry->left = newentry;
				} else {
					return EEXIST;
				}
				break;
			}
		}
	}

	hotdata->activefiles++;
	return 0;
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
		 * Reorganize the sub-trees spanning from our entry.
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
	printf("hfs: hf_getsortedlist returning %d entries w/%d total blocks\n", i, sortedlist->hfl_totalblocks);
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
