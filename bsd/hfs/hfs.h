/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
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

#ifndef __HFS__
#define __HFS__

/* If set to 1, enables the code to allocate blocks from the start 
 * of the disk instead of the nextAllocation for sparse devices like 
 * sparse disk images or sparsebundle images.  The free extent cache 
 * for such volumes is also maintained based on the start block instead 
 * of number of contiguous allocation blocks.  These devices prefer 
 * allocation of blocks near the start of the disk to avoid the 
 * increasing the image size, but it can also result in file fragmentation. 
 */
#define HFS_SPARSE_DEV 1

#if DEBUG
#define HFS_CHECK_LOCK_ORDER 1
#endif

#define HFS_TMPDBG 0

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/quota.h>
#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/disk.h>
#include <kern/thread_call.h>

#include <kern/locks.h>

#include <vfs/vfs_journal.h>

#include <hfs/hfs_format.h>
#include <hfs/hfs_catalog.h>
#include <hfs/hfs_cnode.h>
#include <hfs/hfs_macos_defs.h>
#include <hfs/hfs_encodings.h>
#include <hfs/hfs_hotfiles.h>
#include <hfs/hfs_fsctl.h>

#if CONFIG_PROTECT
/* Forward declare the cprotect struct */
struct cprotect;


#endif

/*
 *	Just reported via MIG interface.
 */
#define VERSION_STRING	"hfs-2 (4-12-99)"

#define HFS_LINK_MAX	32767

#define HFS_MAX_DEFERED_ALLOC	(1024*1024)

// 400 megs is a "big" file (i.e. one that when deleted
// would touch enough data that we should break it into
// multiple separate transactions)
#define HFS_BIGFILE_SIZE (400LL * 1024LL * 1024LL)


enum { kMDBSize = 512 };				/* Size of I/O transfer to read entire MDB */

enum { kMasterDirectoryBlock = 2 };			/* MDB offset on disk in 512-byte blocks */
enum { kMDBOffset = kMasterDirectoryBlock * 512 };	/* MDB offset on disk in bytes */

#define kRootDirID kHFSRootFolderID


/* number of locked buffer caches to hold for b-tree meta data */
#define kMaxLockedMetaBuffers		32		

extern struct timezone gTimeZone;


/* How many free extents to cache per volume */
#define kMaxFreeExtents		10

/* The maximum time hfs locks can be held while performing hfs statistics gathering */
#define HFS_FSINFO_MAX_LOCKHELD_TIME	20 * 1000000ULL	/* at most 20 milliseconds. */

/*
 * HFS_MINFREE gives the minimum acceptable percentage
 * of file system blocks which may be free (but this
 * minimum will never exceed HFS_MAXRESERVE bytes). If
 * the free block count drops below this level only the
 * superuser may continue to allocate blocks.
 */
#define HFS_MINFREE		1
#define HFS_MAXRESERVE		((u_int64_t)(250*1024*1024))
#define HFS_BT_MAXRESERVE	((u_int64_t)(10*1024*1024))

/*
 * The system distinguishes between the desirable low-disk
 * notifiaction levels for root volumes and non-root volumes.
 * The various thresholds are computed as a fraction of the
 * volume size, all capped at a certain fixed level
 */
 
#define HFS_ROOTVERYLOWDISKTRIGGERFRACTION 5
#define HFS_ROOTVERYLOWDISKTRIGGERLEVEL ((u_int64_t)(512*1024*1024))
#define HFS_ROOTLOWDISKTRIGGERFRACTION 10
#define HFS_ROOTLOWDISKTRIGGERLEVEL ((u_int64_t)(1024*1024*1024))
#define HFS_ROOTLOWDISKSHUTOFFFRACTION 11
#define HFS_ROOTLOWDISKSHUTOFFLEVEL ((u_int64_t)(1024*1024*1024 + 250*1024*1024))

#define HFS_VERYLOWDISKTRIGGERFRACTION 1
#define HFS_VERYLOWDISKTRIGGERLEVEL ((u_int64_t)(100*1024*1024))
#define HFS_LOWDISKTRIGGERFRACTION 2
#define HFS_LOWDISKTRIGGERLEVEL ((u_int64_t)(150*1024*1024))
#define HFS_LOWDISKSHUTOFFFRACTION 3
#define HFS_LOWDISKSHUTOFFLEVEL ((u_int64_t)(200*1024*1024))

/* Internal Data structures*/

/* This structure describes the HFS specific mount structure data. */
typedef struct hfsmount {
	u_int32_t     hfs_flags;              /* see below */

	/* Physical Description */
	u_int32_t     hfs_logical_block_size;	/* Logical block size of the disk as reported by ioctl(DKIOCGETBLOCKSIZE), always a multiple of 512 */
	daddr64_t     hfs_logical_block_count;  /* Number of logical blocks on the disk, as reported by ioctl(DKIOCGETBLOCKCOUNT) */
	u_int64_t     hfs_logical_bytes;	/* Number of bytes on the disk device this HFS is mounted on (blockcount * blocksize) */
	/*
	 * Regarding the two AVH sector fields below: 
	 * Under normal circumstances, the filesystem's notion of the "right" location for the AVH is such that
	 * the partition and filesystem's are in sync.  However, during a filesystem resize, HFS proactively
	 * writes a new AVH at the end of the filesystem, assuming that the partition will be resized accordingly.
	 *
	 * However, it is not technically a corruption if the partition size is never modified.  As a result, we need
	 * to keep two copies of the AVH around "just in case" the partition size is not modified.
	 */
	daddr64_t	hfs_partition_avh_sector;	/* location of Alt VH w.r.t partition size */
	daddr64_t	hfs_fs_avh_sector;	/* location of Alt VH w.r.t filesystem size */

	u_int32_t     hfs_physical_block_size;	/* Physical block size of the disk as reported by ioctl(DKIOCGETPHYSICALBLOCKSIZE) */ 
	u_int32_t     hfs_log_per_phys;		/* Number of logical blocks per physical block size */

	/* Access to VFS and devices */
	struct mount		*hfs_mp;				/* filesystem vfs structure */
	struct vnode		*hfs_devvp;				/* block device mounted vnode */
	struct vnode *		hfs_extents_vp;
	struct vnode *		hfs_catalog_vp;
	struct vnode *		hfs_allocation_vp;
	struct vnode *		hfs_attribute_vp;
	struct vnode *		hfs_startup_vp;
	struct vnode *		hfs_attrdata_vp;   /* pseudo file */
	struct cnode *		hfs_extents_cp;
	struct cnode *		hfs_catalog_cp;
	struct cnode *		hfs_allocation_cp;
	struct cnode *		hfs_attribute_cp;
	struct cnode *		hfs_startup_cp;
	dev_t			hfs_raw_dev;			/* device mounted */
	u_int32_t		hfs_logBlockSize;		/* Size of buffer cache buffer for I/O */
	
	/* Default values for HFS standard and non-init access */
	uid_t         hfs_uid;            /* uid to set as owner of the files */
	gid_t         hfs_gid;            /* gid to set as owner of the files */
	mode_t        hfs_dir_mask;       /* mask to and with directory protection bits */
	mode_t        hfs_file_mask;      /* mask to and with file protection bits */
	u_int32_t        hfs_encoding;       /* Default encoding for non hfs+ volumes */	

	/* Persistent fields (on disk, dynamic) */
	time_t        hfs_mtime;          /* file system last modification time */
	u_int32_t     hfs_filecount;      /* number of files in file system */
	u_int32_t     hfs_dircount;       /* number of directories in file system */
	u_int32_t     freeBlocks;	  	  /* free allocation blocks */
	u_int32_t	  reclaimBlocks;	  /* number of blocks we are reclaiming during resize */
	u_int32_t	  tentativeBlocks;	  /* tentative allocation blocks -- see note below */
	u_int32_t     nextAllocation;	  /* start of next allocation search */
	u_int32_t     sparseAllocation;   /* start of allocations for sparse devices */
	u_int32_t     vcbNxtCNID;         /* next unused catalog node ID - protected by catalog lock */
	u_int32_t     vcbWrCnt;           /* file system write count */
	u_int64_t     encodingsBitmap;    /* in-use encodings */
	u_int16_t     vcbNmFls;           /* HFS Only - root dir file count */
	u_int16_t     vcbNmRtDirs;        /* HFS Only - root dir directory count */

	/* Persistent fields (on disk, static) */
	u_int16_t 			vcbSigWord;

	// Volume will be inconsistent if header is not flushed
	bool				hfs_header_dirty;

	// Volume header is dirty, but won't be inconsistent if not flushed
	bool				hfs_header_minor_change;

	u_int32_t 			vcbAtrb;
	u_int32_t 			vcbJinfoBlock;
	u_int32_t 			localCreateDate;/* volume create time from volume header (For HFS+, value is in local time) */
	time_t				hfs_itime;	/* file system creation time (creation date of the root folder) */
	time_t				hfs_btime;	/* file system last backup time */
	u_int32_t 			blockSize;	/* size of allocation blocks */
	u_int32_t 			totalBlocks;	/* total allocation blocks */
	u_int32_t			allocLimit;	/* Do not allocate this block or beyond */
	/*
	 * NOTE: When resizing a volume to make it smaller, allocLimit is set to the allocation
	 * block number which will contain the new alternate volume header.  At all other times,
	 * allocLimit is set to totalBlocks.  The allocation code uses allocLimit instead of
	 * totalBlocks to limit which blocks may be allocated, so that during a resize, we don't
	 * put new content into the blocks we're trying to truncate away.
	 */
	int32_t 			vcbClpSiz;
	u_int32_t     vcbFndrInfo[8];
	int16_t 			vcbVBMSt;		/* HFS only */
	int16_t 			vcbAlBlSt;		/* HFS only */

	/* vcb stuff */
	u_int8_t		 	vcbVN[256];		/* volume name in UTF-8 */
	u_int32_t	 		volumeNameEncodingHint;
	u_int32_t 			hfsPlusIOPosOffset;	/* Disk block where HFS+ starts */
	u_int32_t 			vcbVBMIOSize;		/* volume bitmap I/O size */
	
	/* cache of largest known free extents */
	u_int32_t			vcbFreeExtCnt;
	HFSPlusExtentDescriptor vcbFreeExt[kMaxFreeExtents];
	lck_spin_t			vcbFreeExtLock;
	
	/* Summary Table */
	u_int8_t			*hfs_summary_table; /* Each bit is 1 vcbVBMIOSize of bitmap, byte indexed */
	u_int32_t			hfs_summary_size;	/* number of BITS in summary table defined above (not bytes!) */
	u_int32_t			hfs_summary_bytes;	/* number of BYTES in summary table */
	
	u_int32_t 			scan_var;			/* For initializing the summary table */


	u_int32_t		reserveBlocks;		/* free block reserve */
	u_int32_t		loanedBlocks;		/* blocks on loan for delayed allocations */
	u_int32_t		lockedBlocks;		/* blocks reserved and locked */

	/*
	 * HFS+ Private system directories (two). Any access
	 * (besides looking at the cd_cnid) requires holding
	 * the Catalog File lock.
	 */
	struct cat_desc     hfs_private_desc[2];
	struct cat_attr     hfs_private_attr[2];

	u_int32_t		hfs_metadata_createdate;
	hfs_to_unicode_func_t	hfs_get_unicode;
	unicode_to_hfs_func_t	hfs_get_hfsname;
 
	/* Quota variables: */
	struct quotafile	hfs_qfiles[MAXQUOTAS];    /* quota files */

	/* Journaling variables: */
	struct journal      *jnl;           // the journal for this volume (if one exists)
	struct vnode        *jvp;           // device where the journal lives (may be equal to devvp)
	u_int32_t            jnl_start;     // start block of the journal file (so we don't delete it)
	u_int32_t            jnl_size;
	u_int32_t            hfs_jnlfileid;
	u_int32_t            hfs_jnlinfoblkid;
	lck_rw_t	     	 hfs_global_lock;
	thread_t			 hfs_global_lockowner;
	u_int32_t            hfs_transaction_nesting;

	/* Notification variables: */
	u_int32_t		hfs_notification_conditions;
	u_int32_t		hfs_freespace_notify_dangerlimit;
	u_int32_t		hfs_freespace_notify_warninglimit;
	u_int32_t		hfs_freespace_notify_desiredlevel;

	/* time mounted and last mounted mod time "snapshot" */
	time_t		hfs_mount_time;
	time_t 		hfs_last_mounted_mtime;

	/* Metadata allocation zone variables: */
	u_int32_t	hfs_metazone_start;
	u_int32_t	hfs_metazone_end;
	u_int32_t	hfs_hotfile_start;
	u_int32_t	hfs_hotfile_end;
        u_int32_t       hfs_min_alloc_start;
	u_int32_t       hfs_freed_block_count;
	u_int64_t       hfs_cs_hotfile_size;     // in bytes
	int		hfs_hotfile_freeblks;
	int             hfs_hotfile_blk_adjust;
	int		hfs_hotfile_maxblks;
	int		hfs_overflow_maxblks;
	int		hfs_catalog_maxblks;

	/* Hot File Clustering variables: */
	lck_mtx_t       hfc_mutex;      /* serialize hot file stages */
	enum hfc_stage  hfc_stage;      /* what are we up to... */
	time_t		hfc_timebase;   /* recording period start time */
	time_t		hfc_timeout;    /* recording period stop time */
	void *		hfc_recdata;    /* recording data (opaque) */
	uint32_t	hfc_maxfiles;   /* maximum files to track */
	struct vnode *  hfc_filevp;

#if HFS_SPARSE_DEV
	/* Sparse device variables: */
	struct vnode * hfs_backingfs_rootvp;
	u_int32_t      hfs_last_backingstatfs;
	u_int32_t      hfs_sparsebandblks;
	u_int64_t      hfs_backingfs_maxblocks;
#endif
	size_t         hfs_max_inline_attrsize;

	lck_mtx_t      hfs_mutex;      /* protects access to hfsmount data */

	uint32_t       hfs_syncers;	// Count of the number of syncers running
	enum {
		HFS_THAWED,
		HFS_WANT_TO_FREEZE,	// This state stops hfs_sync from starting
		HFS_FREEZING,		// We're in this state whilst we're flushing
		HFS_FROZEN			// Everything gets blocked in hfs_lock_global
	} hfs_freeze_state;
	union {
		/*
		 * When we're freezing (HFS_FREEZING) but not yet
		 * frozen (HFS_FROZEN), we record the freezing thread
		 * so that we stop other threads from taking locks,
		 * but allow the freezing thread. 
		 */
		const struct thread *hfs_freezing_thread;
		/*
		 * Once we have frozen (HFS_FROZEN), we record the
		 * process so that if it dies, we can automatically
		 * unfreeze. 
		 */
		proc_t hfs_freezing_proc;
	};

	thread_t		hfs_downgrading_thread; /* thread who's downgrading to rdonly */

	/* Resize variables: */
	u_int32_t		hfs_resize_blocksmoved;
	u_int32_t		hfs_resize_totalblocks;
	u_int32_t		hfs_resize_progress;
#if CONFIG_PROTECT
	/* Data Protection fields */
	cpx_t			hfs_resize_cpx;
	u_int16_t		hfs_running_cp_major_vers;
	uint32_t		default_cp_class; /* default effective class value */
	uint64_t		cproot_flags;
	uint8_t			cp_crypto_generation; 
	uint8_t			hfs_cp_lock_state;  /* per-mount device lock state info */ 
#if HFS_TMPDBG
#if !SECURE_KERNEL
	boolean_t		hfs_cp_verbose;
#endif
#endif

#endif

	/* Per mount cnode hash variables: */
	lck_mtx_t      hfs_chash_mutex;	/* protects access to cnode hash table */
	u_long         hfs_cnodehash;	/* size of cnode hash table - 1 */
	LIST_HEAD(cnodehashhead, cnode) *hfs_cnodehashtbl;	/* base of cnode hash */
					
	/* Per mount fileid hash variables  (protected by catalog lock!) */
	u_long hfs_idhash; /* size of cnid/fileid hash table -1 */
	LIST_HEAD(idhashhead, cat_preflightid) *hfs_idhashtbl; /* base of ID hash */

    // Records the oldest outstanding sync request
    struct timeval	hfs_sync_req_oldest;

    // Records whether a sync has been queued or is in progress
	boolean_t		hfs_sync_incomplete;

	thread_call_t   hfs_syncer;	       // removeable devices get sync'ed by this guy

    /* Records the syncer thread so that we can avoid the syncer
       queing more syncs. */
    thread_t		hfs_syncer_thread;

    // Not currently used except for debugging purposes
	uint32_t        hfs_active_threads;

	enum {
		// These are indices into the array below

		// Tentative ranges can be claimed back at any time
		HFS_TENTATIVE_BLOCKS	= 0,

		// Locked ranges cannot be claimed back, but the allocation
		// won't have been written to disk yet
		HFS_LOCKED_BLOCKS		= 1,
	};
	// These lists are not sorted like a range list usually is
	struct rl_head hfs_reserved_ranges[2];
} hfsmount_t;

/*
 * HFS_META_DELAY is a duration (in usecs) used for triggering the 
 * hfs_syncer() routine. We will back off if writes are in 
 * progress, but...
 * HFS_MAX_META_DELAY is the maximum time we will allow the
 * syncer to be delayed.
 */
enum {
    HFS_META_DELAY     = 100  * 1000,	// 0.1 secs
    HFS_MAX_META_DELAY = 5000 * 1000	// 5 secs
};

typedef hfsmount_t  ExtendedVCB;

/* Aliases for legacy (Mac OS 9) field names */
#define vcbLsMod           hfs_mtime
#define vcbVolBkUp         hfs_btime
#define extentsRefNum      hfs_extents_vp
#define catalogRefNum      hfs_catalog_vp
#define allocationsRefNum  hfs_allocation_vp
#define vcbFilCnt          hfs_filecount
#define vcbDirCnt          hfs_dircount

static inline void MarkVCBDirty(hfsmount_t *hfsmp)
{ 
	hfsmp->hfs_header_dirty = true;
}

static inline void MarkVCBClean(hfsmount_t *hfsmp)
{
	hfsmp->hfs_header_dirty = false;
	hfsmp->hfs_header_minor_change = false;
}

static inline bool IsVCBDirty(ExtendedVCB *vcb)
{
	return vcb->hfs_header_minor_change || vcb->hfs_header_dirty;
}

// Header is changed but won't be inconsistent if we don't write it
static inline void hfs_note_header_minor_change(hfsmount_t *hfsmp)
{
	hfsmp->hfs_header_minor_change = true;
}

// Must header be flushed for volume to be consistent?
static inline bool hfs_header_needs_flushing(hfsmount_t *hfsmp)
{
	return (hfsmp->hfs_header_dirty
			|| ISSET(hfsmp->hfs_catalog_cp->c_flag, C_MODIFIED)
			|| ISSET(hfsmp->hfs_extents_cp->c_flag, C_MODIFIED)
			|| (hfsmp->hfs_attribute_cp
				&& ISSET(hfsmp->hfs_attribute_cp->c_flag, C_MODIFIED))
			|| (hfsmp->hfs_allocation_cp
				&& ISSET(hfsmp->hfs_allocation_cp->c_flag, C_MODIFIED))
			|| (hfsmp->hfs_startup_cp
				&& ISSET(hfsmp->hfs_startup_cp->c_flag, C_MODIFIED)));
}

/*
 * There are two private directories in HFS+.
 *
 * One contains inodes for files that are hardlinked or open/unlinked.
 * The other contains inodes for directories that are hardlinked.
 */
enum privdirtype {FILE_HARDLINKS, DIR_HARDLINKS};

#define HFS_ALLOCATOR_SCAN_INFLIGHT	0x0001  	/* scan started */
#define HFS_ALLOCATOR_SCAN_COMPLETED 0x0002		/* initial scan was completed */

/* HFS mount point flags */
#define HFS_READ_ONLY             0x00001
#define HFS_UNKNOWN_PERMS         0x00002
#define HFS_WRITEABLE_MEDIA       0x00004
#define HFS_CLEANED_ORPHANS       0x00008
#define HFS_X                     0x00010
#define HFS_CASE_SENSITIVE        0x00020
#define HFS_STANDARD              0x00040
#define HFS_METADATA_ZONE         0x00080
#define HFS_FRAGMENTED_FREESPACE  0x00100
#define HFS_NEED_JNL_RESET        0x00200
#define HFS_HAS_SPARSE_DEVICE     0x00400
#define HFS_RESIZE_IN_PROGRESS    0x00800
#define HFS_QUOTAS                0x01000
#define HFS_CREATING_BTREE        0x02000
/* When set, do not update nextAllocation in the mount structure */
#define HFS_SKIP_UPDATE_NEXT_ALLOCATION 0x04000	
/* When set, the file system supports extent-based extended attributes */
#define HFS_XATTR_EXTENTS         0x08000	
#define	HFS_FOLDERCOUNT           0x10000
/* When set, the file system exists on a virtual device, like disk image */
#define HFS_VIRTUAL_DEVICE        0x20000
/* When set, we're in hfs_changefs, so hfs_sync should do nothing. */
#define HFS_IN_CHANGEFS           0x40000
/* When set, we are in process of downgrading or have downgraded to read-only, 
 * so hfs_start_transaction should return EROFS.
 */
#define HFS_RDONLY_DOWNGRADE      0x80000
#define HFS_DID_CONTIG_SCAN      0x100000
#define HFS_UNMAP                0x200000
#define HFS_SSD                  0x400000
#define HFS_SUMMARY_TABLE        0x800000
#define HFS_CS                  0x1000000
#define HFS_CS_METADATA_PIN     0x2000000
#define HFS_CS_HOTFILE_PIN      0x4000000	/* cooperative fusion (enables a hotfile variant) */
#define HFS_FEATURE_BARRIER     0x8000000	/* device supports barrier-only flush */
#define HFS_CS_SWAPFILE_PIN    0x10000000

/* Macro to update next allocation block in the HFS mount structure.  If 
 * the HFS_SKIP_UPDATE_NEXT_ALLOCATION is set, do not update 
 * nextAllocation block.
 */
#define HFS_UPDATE_NEXT_ALLOCATION(hfsmp, new_nextAllocation)			\
	{								\
		if ((hfsmp->hfs_flags & HFS_SKIP_UPDATE_NEXT_ALLOCATION) == 0)\
			hfsmp->nextAllocation = new_nextAllocation;	\
	}								\

/* Macro for incrementing and decrementing the folder count in a cnode 
 * attribute only if the HFS_FOLDERCOUNT bit is set in the mount flags 
 * and kHFSHasFolderCount bit is set in the cnode flags.  Currently these 
 * bits are only set for case sensitive HFS+ volumes.
 */
#define INC_FOLDERCOUNT(hfsmp, cattr) 				\
	if ((hfsmp->hfs_flags & HFS_FOLDERCOUNT) &&		\
	    (cattr.ca_recflags & kHFSHasFolderCountMask)) { 	\
		cattr.ca_dircount++;				\
	}							\

#define DEC_FOLDERCOUNT(hfsmp, cattr) 				\
	if ((hfsmp->hfs_flags & HFS_FOLDERCOUNT) &&		\
	    (cattr.ca_recflags & kHFSHasFolderCountMask) && 	\
	    (cattr.ca_dircount > 0)) { 				\
		cattr.ca_dircount--;				\
	}							\

typedef struct filefork FCB;

/*
 * Macros for creating item names for our special/private directories.
 */
#define MAKE_INODE_NAME(name, size, linkno) \
	    (void) snprintf((name), size, "%s%d", HFS_INODE_PREFIX, (linkno))
#define HFS_INODE_PREFIX_LEN	5

#define MAKE_DIRINODE_NAME(name, size, linkno) \
	    (void) snprintf((name), size, "%s%d", HFS_DIRINODE_PREFIX, (linkno))
#define HFS_DIRINODE_PREFIX_LEN   4

#define MAKE_DELETED_NAME(NAME, size, FID) \
	    (void) snprintf((NAME), size, "%s%d", HFS_DELETE_PREFIX, (FID))
#define HFS_DELETE_PREFIX_LEN	4


#define HFS_AVERAGE_NAME_SIZE	22
#define AVERAGE_HFSDIRENTRY_SIZE  (8+HFS_AVERAGE_NAME_SIZE+4)

#define STD_DIRENT_LEN(namlen) \
	((sizeof(struct dirent) - (NAME_MAX+1)) + (((namlen)+1 + 3) &~ 3))

#define EXT_DIRENT_LEN(namlen) \
	((sizeof(struct direntry) + (namlen) - (MAXPATHLEN-1) + 7) & ~7)


enum { kHFSPlusMaxFileNameBytes = kHFSPlusMaxFileNameChars * 3 };


/* macro to determine if hfs or hfsplus */
#define ISHFSPLUS(VCB) ((VCB)->vcbSigWord == kHFSPlusSigWord)
#define ISHFS(VCB) ((VCB)->vcbSigWord == kHFSSigWord)


/*
 * Various ways to acquire a VFS mount point pointer:
 */
#define VTOVFS(VP)  vnode_mount((VP))
#define HFSTOVFS(HFSMP) ((HFSMP)->hfs_mp)
#define VCBTOVFS(VCB)   HFSTOVFS(VCB)

/*
 * Various ways to acquire an HFS mount point pointer:
 */
#define VTOHFS(VP)  ((struct hfsmount *)vfs_fsprivate(vnode_mount((VP))))
#define	VFSTOHFS(MP)  ((struct hfsmount *)vfs_fsprivate((MP)))
#define VCBTOHFS(VCB) (VCB)
#define FCBTOHFS(FCB)  ((struct hfsmount *)vfs_fsprivate(vnode_mount((FCB)->ff_cp->c_vp)))

/*
 * Various ways to acquire a VCB (legacy) pointer:
 */
#define VTOVCB(VP)       VTOHFS(VP)
#define VFSTOVCB(MP)     VFSTOHFS(MP)
#define HFSTOVCB(HFSMP)  (HFSMP)
#define FCBTOVCB(FCB)    FCBTOHFS(FCB)


#define E_NONE	0
#define kHFSBlockSize 512

/*
 * Macros for getting the MDB/VH sector and offset
 */
#define HFS_PRI_SECTOR(blksize)          (1024 / (blksize))
#define HFS_PRI_OFFSET(blksize)          ((blksize) > 1024 ? 1024 : 0)

#define HFS_ALT_SECTOR(blksize, blkcnt)  (((blkcnt) - 1) - (512 / (blksize)))
#define HFS_ALT_OFFSET(blksize)          ((blksize) > 1024 ? (blksize) - 1024 : 0)

/* Convert the logical sector number to be aligned on physical block size boundary.  
 * We are assuming the partition is a multiple of physical block size.
 */
#define HFS_PHYSBLK_ROUNDDOWN(sector_num, log_per_phys)	((sector_num / log_per_phys) * log_per_phys)

/*
 * HFS specific fcntl()'s
 */
#define HFS_GET_BOOT_INFO   (FCNTL_FS_SPECIFIC_BASE + 0x00004)
#define HFS_SET_BOOT_INFO   (FCNTL_FS_SPECIFIC_BASE + 0x00005)
/* See HFSIOC_EXT_BULKACCESS and friends for HFS specific fsctls*/



/*
 *	This is the straight GMT conversion constant:
 *	00:00:00 January 1, 1970 - 00:00:00 January 1, 1904
 *	(3600 * 24 * ((365 * (1970 - 1904)) + (((1970 - 1904) / 4) + 1)))
 */
#define MAC_GMT_FACTOR		2082844800UL

static inline __attribute__((const))
off_t hfs_blk_to_bytes(uint32_t blk, uint32_t blk_size)
{
	return (off_t)blk * blk_size; 		// Avoid the overflow
}

/*
 * For now, we use EIO to indicate consistency issues.  It is safe to
 * return or assign an error value to HFS_EINCONSISTENT but it is
 * *not* safe to compare against it because EIO can be generated for
 * other reasons.  We take advantage of the fact that == has
 * left-to-right associativity and so any uses of:
 *
 *    if (error == HFS_EINCONSISTENT)
 *
 * will produce a compiler warning: "comparison between pointer and
 * integer".
 *
 * Note that not everwhere is consistent with the use of
 * HFS_EINCONSISTENT.  Some places return EINVAL, EIO directly or
 * other error codes.
 */
#define HFS_EINCONSISTENT		(void *)0 == (void *)0 ? EIO : EIO

/*****************************************************************************
	FUNCTION PROTOTYPES 
******************************************************************************/

/*****************************************************************************
	hfs_vnop_xxx functions from different files 
******************************************************************************/
int hfs_vnop_readdirattr(struct vnop_readdirattr_args *);  /* in hfs_attrlist.c */
int hfs_vnop_getattrlistbulk(struct vnop_getattrlistbulk_args *);  /* in hfs_attrlist.c */

int hfs_vnop_inactive(struct vnop_inactive_args *);        /* in hfs_cnode.c */
int hfs_vnop_reclaim(struct vnop_reclaim_args *);          /* in hfs_cnode.c */

int hfs_set_backingstore (struct vnode *vp, int val);				/* in hfs_cnode.c */
int hfs_is_backingstore (struct vnode *vp, int *val);		/* in hfs_cnode.c */

int hfs_vnop_link(struct vnop_link_args *);                /* in hfs_link.c */

int hfs_vnop_lookup(struct vnop_lookup_args *);            /* in hfs_lookup.c */

int hfs_vnop_search(struct vnop_searchfs_args *);          /* in hfs_search.c */

int hfs_vnop_read(struct vnop_read_args *);           /* in hfs_readwrite.c */
int hfs_vnop_write(struct vnop_write_args *);         /* in hfs_readwrite.c */
int hfs_vnop_ioctl(struct vnop_ioctl_args *);         /* in hfs_readwrite.c */
int hfs_vnop_select(struct vnop_select_args *);       /* in hfs_readwrite.c */
int hfs_vnop_strategy(struct vnop_strategy_args *);   /* in hfs_readwrite.c */
int hfs_vnop_allocate(struct vnop_allocate_args *);   /* in hfs_readwrite.c */
int hfs_vnop_pagein(struct vnop_pagein_args *);       /* in hfs_readwrite.c */
int hfs_vnop_pageout(struct vnop_pageout_args *);     /* in hfs_readwrite.c */
int hfs_vnop_bwrite(struct vnop_bwrite_args *);       /* in hfs_readwrite.c */
int hfs_vnop_blktooff(struct vnop_blktooff_args *);   /* in hfs_readwrite.c */
int hfs_vnop_offtoblk(struct vnop_offtoblk_args *);   /* in hfs_readwrite.c */
int hfs_vnop_blockmap(struct vnop_blockmap_args *);   /* in hfs_readwrite.c */
errno_t hfs_flush_invalid_ranges(vnode_t vp);		  /* in hfs_readwrite.c */

int hfs_vnop_getxattr(struct vnop_getxattr_args *);        /* in hfs_xattr.c */
int hfs_vnop_setxattr(struct vnop_setxattr_args *);        /* in hfs_xattr.c */
int hfs_vnop_removexattr(struct vnop_removexattr_args *);  /* in hfs_xattr.c */
int hfs_vnop_listxattr(struct vnop_listxattr_args *);      /* in hfs_xattr.c */
#if NAMEDSTREAMS
extern int hfs_vnop_getnamedstream(struct vnop_getnamedstream_args*);
extern int hfs_vnop_makenamedstream(struct vnop_makenamedstream_args*);
extern int hfs_vnop_removenamedstream(struct vnop_removenamedstream_args*);
#endif


/*****************************************************************************
	Functions from MacOSStubs.c
******************************************************************************/
time_t to_bsd_time(u_int32_t hfs_time);

u_int32_t to_hfs_time(time_t bsd_time);


/*****************************************************************************
	Functions from hfs_encodinghint.c
******************************************************************************/
u_int32_t hfs_pickencoding(const u_int16_t *src, int len);

u_int32_t hfs_getencodingbias(void);

void hfs_setencodingbias(u_int32_t bias);


/*****************************************************************************
	Functions from hfs_encodings.c
******************************************************************************/
void hfs_converterinit(void);

int hfs_relconverter (u_int32_t encoding);

int hfs_getconverter(u_int32_t encoding, hfs_to_unicode_func_t *get_unicode,
		     unicode_to_hfs_func_t *get_hfsname);

#if CONFIG_HFS_STD
int hfs_to_utf8(ExtendedVCB *vcb, const Str31 hfs_str, ByteCount maxDstLen,
		ByteCount *actualDstLen, unsigned char* dstStr);

int utf8_to_hfs(ExtendedVCB *vcb, ByteCount srcLen, const unsigned char* srcStr,
		Str31 dstStr);

int mac_roman_to_utf8(const Str31 hfs_str, ByteCount maxDstLen, ByteCount *actualDstLen,
		unsigned char* dstStr);

int utf8_to_mac_roman(ByteCount srcLen, const unsigned char* srcStr, Str31 dstStr);

int mac_roman_to_unicode(const Str31 hfs_str, UniChar *uni_str, u_int32_t maxCharLen, u_int32_t *usedCharLen);

int unicode_to_hfs(ExtendedVCB *vcb, ByteCount srcLen, u_int16_t* srcStr, Str31 dstStr, int retry);
#endif

/*****************************************************************************
	Functions from hfs_notifications.c
******************************************************************************/
void hfs_generate_volume_notifications(struct hfsmount *hfsmp);


/*****************************************************************************
	Functions from hfs_readwrite.c
******************************************************************************/
extern int  hfs_relocate(struct  vnode *, u_int32_t, kauth_cred_t, struct  proc *);

/* flags for hfs_pin_block_range() and hfs_pin_vnode() */
#define HFS_PIN_IT       0x0001
#define HFS_UNPIN_IT     0x0002
#define HFS_TEMP_PIN     0x0004
#define HFS_EVICT_PIN    0x0008
#define HFS_DATALESS_PIN 0x0010

//
// pin/un-pin an explicit range of blocks to the "fast" (usually ssd) device
//
int hfs_pin_block_range(struct hfsmount *hfsmp, int pin_state, uint32_t start_block, uint32_t nblocks, vfs_context_t ctx);

//
// pin/un-pin all the extents belonging to a vnode.
// also, if it is non-null, "num_blocks_pinned" returns the number of blocks pin/unpinned by the function
//
int hfs_pin_vnode(struct hfsmount *hfsmp, struct vnode *vp, int pin_state, uint32_t *num_blocks_pinned, vfs_context_t ctx);


int hfs_pin_overflow_extents (struct hfsmount *hfsmp, uint32_t fileid, uint8_t forktype, uint32_t *pinned);
                                     

/* Flags for HFS truncate */
#define HFS_TRUNCATE_SKIPTIMES  	0x00000002 /* implied by skipupdate; it is a subset */
											

extern int hfs_truncate(struct vnode *, off_t, int, int, vfs_context_t);

extern int hfs_release_storage (struct hfsmount *hfsmp, struct filefork *datafork, 
								struct filefork *rsrcfork,  u_int32_t fileid);

extern int hfs_prepare_release_storage (struct hfsmount *hfsmp, struct vnode *vp);

extern int hfs_bmap(struct vnode *, daddr_t, struct vnode **, daddr64_t *, unsigned int *);

extern errno_t hfs_ubc_setsize(vnode_t vp, off_t len, bool have_cnode_lock);


/*****************************************************************************
	Functions from hfs_resize.c 
******************************************************************************/
int hfs_extendfs(struct hfsmount *hfsmp, u_int64_t newsize, vfs_context_t context);
int hfs_truncatefs(struct hfsmount *hfsmp, u_int64_t newsize, vfs_context_t context);


/*****************************************************************************
	Functions from hfs_vfsops.c
******************************************************************************/
int hfs_mountroot(mount_t mp, vnode_t rvp, vfs_context_t context);

/* used as a callback by the journaling code */
extern void hfs_sync_metadata(void *arg);

extern int hfs_vget(struct hfsmount *, cnid_t, struct vnode **, int, int);

extern void hfs_setencodingbits(struct hfsmount *hfsmp, u_int32_t encoding);

enum volop {VOL_UPDATE, VOL_MKDIR, VOL_RMDIR, VOL_MKFILE, VOL_RMFILE};
extern int hfs_volupdate(struct hfsmount *hfsmp, enum volop op, int inroot);

enum {
	HFS_FVH_WAIT					= 0x0001,
	HFS_FVH_WRITE_ALT				= 0x0002,
	HFS_FVH_FLUSH_IF_DIRTY			= 0x0004,
};
typedef uint32_t hfs_flush_volume_header_options_t;
int hfs_flushvolumeheader(struct hfsmount *hfsmp, hfs_flush_volume_header_options_t);

extern int  hfs_extendfs(struct hfsmount *, u_int64_t, vfs_context_t);
extern int  hfs_truncatefs(struct hfsmount *, u_int64_t, vfs_context_t);
extern int  hfs_resize_progress(struct hfsmount *, u_int32_t *);

/* If a runtime corruption is detected, mark the volume inconsistent 
 * bit in the volume attributes.
 */

typedef enum {
	HFS_INCONSISTENCY_DETECTED,

	// Used when unable to rollback an operation that failed
	HFS_ROLLBACK_FAILED,

	// Used when the latter part of an operation failed, but we chose not to roll back
	HFS_OP_INCOMPLETE,

	// Used when someone told us to force an fsck on next mount
	HFS_FSCK_FORCED,
} hfs_inconsistency_reason_t;

void hfs_mark_inconsistent(struct hfsmount *hfsmp,
						   hfs_inconsistency_reason_t reason);

void hfs_scan_blocks (struct hfsmount *hfsmp);

/*****************************************************************************
	Functions from hfs_vfsutils.c
******************************************************************************/
u_int32_t BestBlockSizeFit(u_int32_t allocationBlockSize,
                               u_int32_t blockSizeLimit,
                               u_int32_t baseMultiple);

#if CONFIG_HFS_STD
OSErr	hfs_MountHFSVolume(struct hfsmount *hfsmp, HFSMasterDirectoryBlock *mdb,
		struct proc *p);
#endif
OSErr	hfs_MountHFSPlusVolume(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
		off_t embeddedOffset, u_int64_t disksize, struct proc *p, void *args, kauth_cred_t cred);

OSErr hfs_ValidateHFSPlusVolumeHeader(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp);

extern int hfsUnmount(struct hfsmount *hfsmp, struct proc *p);

extern bool overflow_extents(struct filefork *fp);

extern int hfs_owner_rights(struct hfsmount *hfsmp, uid_t cnode_uid, kauth_cred_t cred,
		struct proc *p, int invokesuperuserstatus);

extern int check_for_tracked_file(struct vnode *vp, time_t ctime, uint64_t op_type, void *arg);
extern int check_for_dataless_file(struct vnode *vp, uint64_t op_type);
extern int hfs_generate_document_id(struct hfsmount *hfsmp, uint32_t *docid);
extern void hfs_pin_fs_metadata(struct hfsmount *hfsmp);

/* Return information about number of metadata blocks for volume */
extern int hfs_getinfo_metadata_blocks(struct hfsmount *hfsmp, struct hfsinfo_metadata *hinfo);

/*
 * Journal lock function prototypes
 */
int hfs_lock_global (struct hfsmount *hfsmp, enum hfs_locktype locktype);
void hfs_unlock_global (struct hfsmount *hfsmp);

/* HFS mount lock/unlock prototypes */
void hfs_lock_mount (struct hfsmount *hfsmp);
void hfs_unlock_mount (struct hfsmount *hfsmp);


/* HFS System file locking */
#define SFL_CATALOG     0x0001
#define SFL_EXTENTS     0x0002
#define SFL_BITMAP      0x0004
#define SFL_ATTRIBUTE   0x0008
#define SFL_STARTUP	0x0010
#define SFL_VM_PRIV	0x0020
#define SFL_VALIDMASK   (SFL_CATALOG | SFL_EXTENTS | SFL_BITMAP | SFL_ATTRIBUTE | SFL_STARTUP | SFL_VM_PRIV)

extern u_int32_t  GetFileInfo(ExtendedVCB *vcb, u_int32_t dirid, const char *name,
						   struct cat_attr *fattr, struct cat_fork *forkinfo);

extern void hfs_remove_orphans(struct hfsmount *);

u_int32_t GetLogicalBlockSize(struct vnode *vp);

extern u_int32_t hfs_freeblks(struct hfsmount * hfsmp, int wantreserve);

short MacToVFSError(OSErr err);

void hfs_metadatazone_init(struct hfsmount *hfsmp, int disable);

/* HFS directory hint functions. */
extern directoryhint_t * hfs_getdirhint(struct cnode *, int, int);
extern void  hfs_reldirhint(struct cnode *, directoryhint_t *);
extern void  hfs_reldirhints(struct cnode *, int);
extern void  hfs_insertdirhint(struct cnode *, directoryhint_t *);

extern int hfs_namecmp(const u_int8_t *str1, size_t len1, const u_int8_t *str2, size_t len2);

extern int     hfs_early_journal_init(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
			   void *_args, off_t embeddedOffset, daddr64_t mdb_offset,
			   HFSMasterDirectoryBlock *mdbp, kauth_cred_t cred);

extern int  hfs_virtualmetafile(struct cnode *);

extern int hfs_start_transaction(struct hfsmount *hfsmp);
extern int hfs_end_transaction(struct hfsmount *hfsmp);
extern void hfs_journal_lock(struct hfsmount *hfsmp);
extern void hfs_journal_unlock(struct hfsmount *hfsmp);
extern void hfs_syncer_lock(struct hfsmount *hfsmp);
extern void hfs_syncer_unlock(struct hfsmount *hfsmp);
extern void hfs_syncer_wait(struct hfsmount *hfsmp);
extern void hfs_syncer_wakeup(struct hfsmount *hfsmp);
extern void hfs_syncer_queue(thread_call_t syncer);
extern void hfs_sync_ejectable(struct hfsmount *hfsmp);

typedef enum hfs_flush_mode {
	HFS_FLUSH_JOURNAL,              // Flush journal
	HFS_FLUSH_JOURNAL_META,         // Flush journal and metadata blocks
	HFS_FLUSH_FULL,                 // Flush journal and does a cache flush
	HFS_FLUSH_CACHE,                // Flush track cache to media
	HFS_FLUSH_BARRIER,              // Barrier-only flush to ensure write order
	HFS_FLUSH_JOURNAL_BARRIER       // Flush journal with barrier
} hfs_flush_mode_t;

extern errno_t hfs_flush(struct hfsmount *hfsmp, hfs_flush_mode_t mode);

extern void hfs_trim_callback(void *arg, uint32_t extent_count, const dk_extent_t *extents);

/* Erase unused Catalog nodes due to <rdar://problem/6947811>. */
extern int hfs_erase_unused_nodes(struct hfsmount *hfsmp);

extern uint64_t hfs_usecs_to_deadline(uint64_t usecs);

extern int hfs_freeze(struct hfsmount *hfsmp);
extern int hfs_thaw(struct hfsmount *hfsmp, const struct proc *process);


/*****************************************************************************
	Functions from hfs_vnops.c
******************************************************************************/
int hfs_write_access(struct vnode *vp, kauth_cred_t cred, struct proc *p, Boolean considerFlags);

int hfs_chmod(struct vnode *vp, int mode, kauth_cred_t cred, struct proc *p);

int hfs_chown(struct vnode *vp, uid_t uid, gid_t gid, kauth_cred_t cred, struct proc *p);

#define  kMaxSecsForFsync	5
#define  HFS_SYNCTRANS		1
extern int hfs_btsync(struct vnode *vp, int sync_transaction);

extern void replace_desc(struct cnode *cp, struct cat_desc *cdp);

extern int hfs_vgetrsrc(struct hfsmount *hfsmp, struct vnode *vp,
						struct vnode **rvpp);

typedef enum {
	// Push all modifications to disk (including minor ones)
	HFS_UPDATE_FORCE = 0x01,
} hfs_update_options_t;

extern int hfs_update(struct vnode *, int options);

typedef enum hfs_sync_mode {
	HFS_FSYNC,
	HFS_FSYNC_FULL,
	HFS_FSYNC_BARRIER
} hfs_fsync_mode_t;

extern int hfs_fsync(struct vnode *, int, hfs_fsync_mode_t, struct proc *);

const struct cat_fork *
hfs_prepare_fork_for_update(filefork_t *ff,
							const struct cat_fork *cf,
							struct cat_fork *cf_buf,
							uint32_t block_size);

/*****************************************************************************
	Functions from hfs_xattr.c
******************************************************************************/

/* 
 * Maximum extended attribute size supported for all extended attributes except  
 * resource fork and finder info.
 */
#define HFS_XATTR_MAXSIZE	INT32_MAX

/* Number of bits used to represent maximum extended attribute size */
#define HFS_XATTR_SIZE_BITS	31

int  hfs_attrkeycompare(HFSPlusAttrKey *searchKey, HFSPlusAttrKey *trialKey);
int  hfs_buildattrkey(u_int32_t fileID, const char *attrname, HFSPlusAttrKey *key);
void hfs_xattr_init(struct hfsmount * hfsmp);
int file_attribute_exist(struct hfsmount *hfsmp, uint32_t fileID);
int init_attrdata_vnode(struct hfsmount *hfsmp);
int hfs_xattr_read(vnode_t vp, const char *name, void *data, size_t *size);
int hfs_getxattr_internal(cnode_t *, struct vnop_getxattr_args *,
                          struct hfsmount *, u_int32_t);
int hfs_xattr_write(vnode_t vp, const char *name, const void *data, size_t size);
int hfs_setxattr_internal(struct cnode *, const void *, size_t, 
                          struct vnop_setxattr_args *, struct hfsmount *, u_int32_t);
extern int hfs_removeallattr(struct hfsmount *hfsmp, u_int32_t fileid, 
							 bool *open_transaction);
extern int hfs_set_volxattr(struct hfsmount *hfsmp, unsigned int xattrtype, int state);



/*****************************************************************************
	Functions from hfs_link.c
******************************************************************************/

extern int  hfs_unlink(struct hfsmount *hfsmp, struct vnode *dvp, struct vnode *vp,
                       struct componentname *cnp, int skip_reserve);
extern int  hfs_lookup_siblinglinks(struct hfsmount *hfsmp, cnid_t linkfileid,
                           cnid_t *prevlinkid,  cnid_t *nextlinkid);
extern int  hfs_lookup_lastlink(struct hfsmount *hfsmp, cnid_t linkfileid,
                           cnid_t *nextlinkid, struct cat_desc *cdesc);
extern void  hfs_privatedir_init(struct hfsmount *, enum privdirtype);

extern void  hfs_savelinkorigin(cnode_t *cp, cnid_t parentcnid);
extern void  hfs_relorigins(struct cnode *cp);
extern void  hfs_relorigin(struct cnode *cp, cnid_t parentcnid);
extern int   hfs_haslinkorigin(cnode_t *cp);
extern cnid_t  hfs_currentparent(cnode_t *cp, bool have_lock);
extern cnid_t  hfs_currentcnid(cnode_t *cp);
errno_t hfs_first_link(hfsmount_t *hfsmp, cnode_t *cp, cnid_t *link_id);


/*****************************************************************************
	Functions from VolumeAllocation.c
 ******************************************************************************/
extern int hfs_isallocated(struct hfsmount *hfsmp, u_int32_t startingBlock, u_int32_t numBlocks);

extern int hfs_count_allocated(struct hfsmount *hfsmp, u_int32_t startBlock, 
		u_int32_t numBlocks, u_int32_t *alloc_count);

extern int hfs_isrbtree_active (struct hfsmount *hfsmp);

/*****************************************************************************
	Functions from hfs_fsinfo.c
 ******************************************************************************/
extern errno_t hfs_get_fsinfo(struct hfsmount *hfsmp, void *a_data);
extern void hfs_fsinfo_data_add(struct hfs_fsinfo_data *fsinfo, uint64_t entry);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* __HFS__ */
