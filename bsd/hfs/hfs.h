/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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

#ifndef __HFS__
#define __HFS__

#define HFS_SPARSE_DEV 1

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/queue.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/quota.h>
#include <sys/dirent.h>
#include <sys/event.h>

#include <vfs/vfs_journal.h>

#include <hfs/hfs_format.h>
#include <hfs/hfs_catalog.h>
#include <hfs/hfs_cnode.h>
#include <hfs/hfs_macos_defs.h>
#include <hfs/hfs_encodings.h>
#include <hfs/hfs_hotfiles.h>


struct uio;		// This is more effective than #include <sys/uio.h> in case KERNEL is undefined...
struct hfslockf;	/* For advisory locking */

/*
 *	Just reported via MIG interface.
 */
#define VERSION_STRING	"hfs-2 (4-12-99)"

#define HFS_LINK_MAX	32767

#define HFS_MAX_DEFERED_ALLOC	(1024*1024)

// 32 gigs is a "big" file (i.e. one that when deleted
// would touch enough data that we should break it into
// multiple separate transactions
#define HFS_BIGFILE_SIZE (32LL * 1024LL * 1024LL * 1024LL)


enum { kMDBSize = 512 };				/* Size of I/O transfer to read entire MDB */

enum { kMasterDirectoryBlock = 2 };			/* MDB offset on disk in 512-byte blocks */
enum { kMDBOffset = kMasterDirectoryBlock * 512 };	/* MDB offset on disk in bytes */

enum {
	kUnknownID = 0,
	kRootParID = 1,
	kRootDirID = 2
};

enum {
	kDataFork,
	kRsrcFork,
	kDirectory
};

/* number of locked buffer caches to hold for b-tree meta data */
#define kMaxLockedMetaBuffers		32		

/*
 *	File type and creator for symbolic links
 */
enum {
	kSymLinkFileType  = 0x736C6E6B,	/* 'slnk' */
	kSymLinkCreator   = 0x72686170	/* 'rhap' */
};


extern struct timezone gTimeZone;


/* How many free extents to cache per volume */
#define kMaxFreeExtents		10

/*
 * HFS_MINFREE gives the minimum acceptable percentage
 * of file system blocks which may be free (but this
 * minimum will never exceed HFS_MAXRESERVE bytes). If
 * the free block count drops below this level only the
 * superuser may continue to allocate blocks.
 */
#define HFS_MINFREE		1
#define HFS_MAXRESERVE		((u_int64_t)(250*1024*1024))

/*
 * The system distinguishes between the desirable low-disk
 * notifiaction levels for root volumes and non-root volumes.
 * The various thresholds are computed as a fraction of the
 * volume size, all capped at a certain fixed level
 */
 
#define HFS_ROOTLOWDISKTRIGGERFRACTION 5
#define HFS_ROOTLOWDISKTRIGGERLEVEL ((u_int64_t)(250*1024*1024))
#define HFS_ROOTLOWDISKSHUTOFFFRACTION 6
#define HFS_ROOTLOWDISKSHUTOFFLEVEL ((u_int64_t)(375*1024*1024))

#define HFS_LOWDISKTRIGGERFRACTION 1
#define HFS_LOWDISKTRIGGERLEVEL ((u_int64_t)(50*1024*1024))
#define HFS_LOWDISKSHUTOFFFRACTION 2
#define HFS_LOWDISKSHUTOFFLEVEL ((u_int64_t)(75*1024*1024))

/* Internal Data structures*/

struct vcb_t {
    u_int16_t 			vcbSigWord;
    int16_t 			vcbAtrb;
    int16_t			vcbFlags;
    int16_t 			vcbspare;
    u_int32_t 			vcbJinfoBlock;

    u_int32_t 			vcbCrDate;
    u_int32_t 			vcbLsMod;
    u_int32_t 			vcbVolBkUp;

    int32_t 			vcbFilCnt;
    int32_t 			vcbDirCnt;
    u_int32_t 			blockSize;	/* size of allocation blocks */
    u_int32_t 			totalBlocks;	/* total allocation blocks */
    u_int32_t 			freeBlocks;	/* free allocation blocks */
    u_int32_t 			nextAllocation;	/* start of next allocation search */
    int32_t 			vcbClpSiz;
    u_int32_t 			vcbNxtCNID;
	u_int32_t 		vcbCNIDGen;
	int32_t 		vcbWrCnt;

    int32_t 			vcbFndrInfo[8];

    u_int64_t 			encodingsBitmap;	/* HFS Plus only */

    u_int16_t 			vcbNmFls;		/* HFS only */
    u_int16_t 			vcbNmRtDirs;		/* HFS only */
    int16_t 			vcbVBMSt;		/* HFS only */
    int16_t 			vcbAlBlSt;		/* HFS only */

    struct vnode *		extentsRefNum;
    struct vnode *		catalogRefNum;
    struct vnode *		allocationsRefNum;

    u_int8_t		 	vcbVN[256];		/* volume name in UTF-8 */
    u_int32_t	 		volumeNameEncodingHint;
    u_int32_t 			hfsPlusIOPosOffset;	/* Disk block where HFS+ starts */
    u_int32_t 			vcbVBMIOSize;		/* volume bitmap I/O size */

    /* cache of largest known free extents */
    u_int32_t			vcbFreeExtCnt;
    HFSPlusExtentDescriptor vcbFreeExt[kMaxFreeExtents];

    u_int32_t		reserveBlocks;		/* free block reserve */
    u_int32_t		loanedBlocks;		/* blocks on loan for delayed allocations */

    u_int32_t 			localCreateDate;	/* creation times for HFS+ volumes are in local time */
    simple_lock_data_t	vcbSimpleLock;		/* simple lock to allow concurrent access to vcb data */
};
typedef struct vcb_t ExtendedVCB;


#define kHFS_DamagedVolume  0x1	/* This volume has errors, unmount dirty */

/* XXX */
#define MARK_VOLUMEDAMAGED(fcb) 

/*
 * NOTE: The code relies on being able to cast an ExtendedVCB* to a vfsVCB* in order
 *	 to gain access to the mount point pointer from a pointer
 *	 to an ExtendedVCB.  DO NOT INSERT OTHER FIELDS BEFORE THE vcb FIELD!!
 *
 * vcbFlags, vcbLsMod, vcbFilCnt, vcbDirCnt, vcbNxtCNID, etc
 * are locked by the hfs_lock simple lock.
 */
typedef struct vfsVCB {
    ExtendedVCB			vcb_vcb;
    struct hfsmount		*vcb_hfsmp;				/* Pointer to hfsmount structure */
} vfsVCB_t;



/* This structure describes the HFS specific mount structure data. */
typedef struct hfsmount {
	u_int32_t		hfs_flags;	/* see below */
	
	/* Physical Description */
	u_long				hfs_phys_block_count;	/* Num of PHYSICAL blocks of volume */
	u_long				hfs_phys_block_size;	/* Always a multiple of 512 */

	/* Access to VFS and devices */
	struct mount		*hfs_mp;				/* filesystem vfs structure */
	struct vnode		*hfs_devvp;				/* block device mounted vnode */
	dev_t				hfs_raw_dev;			/* device mounted */
	struct netexport	hfs_export;				/* Export information */
	u_int32_t			hfs_logBlockSize;		/* Size of buffer cache buffer for I/O */
	
	/* Default values for HFS standard and non-init access */
	uid_t				hfs_uid;				/* uid to set as owner of the files */
	gid_t				hfs_gid;				/* gid to set as owner of the files */
	mode_t				hfs_dir_mask;			/* mask to and with directory protection bits */
	mode_t				hfs_file_mask;			/* mask to and with file protection bits */
	u_long				hfs_encoding;			/* Defualt encoding for non hfs+ volumes */	

	/* HFS Specific */
	struct vfsVCB		hfs_vcb;
	struct cat_desc		hfs_privdir_desc;
	struct cat_attr		hfs_privdir_attr;
	u_int32_t		hfs_metadata_createdate;
	hfs_to_unicode_func_t	hfs_get_unicode;
	unicode_to_hfs_func_t	hfs_get_hfsname;
 
	/* Quota variables: */
	struct quotafile	hfs_qfiles[MAXQUOTAS];    /* quota files */

	/* Journaling variables: */
	void                *jnl;           // the journal for this volume (if one exists)
	struct vnode        *jvp;           // device where the journal lives (may be equal to devvp)
	u_int32_t            jnl_start;     // start block of the journal file (so we don't delete it)
	u_int32_t            jnl_size;
	u_int32_t            hfs_jnlfileid;
	u_int32_t            hfs_jnlinfoblkid;
	volatile int         readers;
	volatile int         blocker;
	
	/* Notification variables: */
	unsigned long		hfs_notification_conditions;
	u_int32_t		hfs_freespace_notify_warninglimit;
	u_int32_t		hfs_freespace_notify_desiredlevel;

	/* Metadata allocation zone variables: */
	u_int32_t	hfs_metazone_start;
	u_int32_t	hfs_metazone_end;
	u_int32_t	hfs_hotfile_start;
	u_int32_t	hfs_hotfile_end;
	int		hfs_hotfile_freeblks;
	int		hfs_hotfile_maxblks;
	int		hfs_overflow_maxblks;
	int		hfs_catalog_maxblks;

	/* Hot File Clustering variables: */
	enum hfc_stage  hfc_stage;      /* what are we up to... */
	time_t		hfc_timebase;   /* recording period start time */
	time_t		hfc_timeout;    /* recording period stop time */
	void *		hfc_recdata;    /* recording data (opaque) */
	int		hfc_maxfiles;   /* maximum files to track */
	struct vnode *  hfc_filevp;

#ifdef HFS_SPARSE_DEV
	/* Sparse device variables: */
	struct vnode * hfs_backingfs_rootvp;
	int            hfs_sparsebandblks;
#endif
} hfsmount_t;


/* HFS mount point flags */
#define HFS_READ_ONLY             0x001
#define HFS_UNKNOWN_PERMS         0x002
#define HFS_WRITEABLE_MEDIA       0x004
#define HFS_CLEANED_ORPHANS       0x008
#define HFS_X                     0x010
#define HFS_CASE_SENSITIVE        0x020
#define HFS_STANDARD              0x040
#define HFS_METADATA_ZONE         0x080
#define HFS_FRAGMENTED_FREESPACE  0x100
#define HFS_NEED_JNL_RESET        0x200

#ifdef HFS_SPARSE_DEV
#define HFS_HAS_SPARSE_DEVICE     0x400
#endif


#define hfs_global_shared_lock_acquire(hfsmp)    \
    do { \
       if (hfsmp->blocker) { \
	       tsleep((caddr_t)&hfsmp->blocker, PRIBIO, "journal_blocker", 0); \
           continue; \
	   } \
	   hfsmp->readers++; \
       break; \
	} while (1)

#define hfs_global_shared_lock_release(hfsmp)    \
    do { \
	    hfsmp->readers--; \
	    if (hfsmp->readers == 0) { \
	        wakeup((caddr_t)&hfsmp->readers); \
        } \
    } while (0)

#define hfs_global_exclusive_lock_acquire(hfsmp) \
    do { \
       if (hfsmp->blocker) { \
	       tsleep((caddr_t)&hfsmp->blocker, PRIBIO, "journal_blocker", 0); \
           continue; \
	   } \
       if (hfsmp->readers != 0) { \
	       tsleep((caddr_t)&hfsmp->readers, PRIBIO, "journal_enable/disble", 0); \
           continue; \
       } \
       hfsmp->blocker = 1; \
       break; \
	} while (1)
     
#define hfs_global_exclusive_lock_release(hfsmp) \
    hfsmp->blocker = 0; \
	wakeup((caddr_t)&hfsmp->blocker)

#define MAXHFSVNODELEN		31


typedef struct filefork FCB;


#define MAKE_INODE_NAME(name,linkno) \
	    (void) sprintf((name), "%s%d", HFS_INODE_PREFIX, (linkno))


/* structure to hold a "." or ".." directory entry (12 bytes) */
typedef struct hfsdotentry {
	u_int32_t	d_fileno;	/* unique file number */
	u_int16_t	d_reclen;	/* length of this structure */
	u_int8_t	d_type;		/* dirent file type */
	u_int8_t	d_namelen;	/* len of filename */
	char		d_name[4];	/* "." or ".." */
} hfsdotentry;

#define HFS_AVERAGE_NAME_SIZE	22
#define AVERAGE_HFSDIRENTRY_SIZE  (8+HFS_AVERAGE_NAME_SIZE+4)
#define MAX_HFSDIRENTRY_SIZE	sizeof(struct dirent)

#define DIRENTRY_SIZE(namlen) \
    ((sizeof(struct dirent) - (NAME_MAX+1)) + (((namlen)+1 + 3) &~ 3))



enum { kHFSPlusMaxFileNameBytes = kHFSPlusMaxFileNameChars * 3 };

enum { kdirentMaxNameBytes = NAME_MAX };


/* macro to determine if hfs or hfsplus */
#define ISHFSPLUS(VCB) ((VCB)->vcbSigWord == kHFSPlusSigWord)
#define ISHFS(VCB) ((VCB)->vcbSigWord == kHFSSigWord)


/*
 * Various ways to acquire a VFS mount point pointer:
 */
#define VTOVFS(VP) ((VP)->v_mount)
#define HFSTOVFS(HFSMP) ((HFSMP)->hfs_mp)
#define VCBTOVFS(VCB) (((struct vfsVCB *)(VCB))->vcb_hfsmp->hfs_mp)

/*
 * Various ways to acquire an HFS mount point pointer:
 */
#define VTOHFS(VP) ((struct hfsmount *)((VP)->v_mount->mnt_data))
#define	VFSTOHFS(MP) ((struct hfsmount *)(MP)->mnt_data)	
#define VCBTOHFS(VCB) (((struct vfsVCB *)(VCB))->vcb_hfsmp)
#define FCBTOHFS(FCB) ((struct hfsmount *)(FCB)->ff_cp->c_vp->v_mount->mnt_data)

/*
 * Various ways to acquire a VCB pointer:
 */
#define VTOVCB(VP) (&(((struct hfsmount *)((VP)->v_mount->mnt_data))->hfs_vcb.vcb_vcb))
#define VFSTOVCB(MP) (&(((struct hfsmount *)(MP)->mnt_data)->hfs_vcb.vcb_vcb))
#define HFSTOVCB(HFSMP) (&(HFSMP)->hfs_vcb.vcb_vcb)
#define FCBTOVCB(FCB) (&(((struct hfsmount *)((FCB)->ff_cp->c_vp->v_mount->mnt_data))->hfs_vcb.vcb_vcb))


#define HFS_KNOTE(vp, hint) KNOTE(&VTOC(vp)->c_knotes, (hint))


#define E_NONE	0
#define kHFSBlockSize 512

/*
 * Macros for getting the MDB/VH sector and offset
 */
#define HFS_PRI_SECTOR(blksize)          (1024 / (blksize))
#define HFS_PRI_OFFSET(blksize)          ((blksize) > 1024 ? 1024 : 0)

#define HFS_ALT_SECTOR(blksize, blkcnt)  (((blkcnt) - 1) - (512 / (blksize)))
#define HFS_ALT_OFFSET(blksize)          ((blksize) > 1024 ? (blksize) - 1024 : 0)

/*
 *	This is the straight GMT conversion constant:
 *	00:00:00 January 1, 1970 - 00:00:00 January 1, 1904
 *	(3600 * 24 * ((365 * (1970 - 1904)) + (((1970 - 1904) / 4) + 1)))
 */
#define MAC_GMT_FACTOR		2082844800UL


u_int32_t to_bsd_time(u_int32_t hfs_time);
u_int32_t to_hfs_time(u_int32_t bsd_time);

int hfs_flushvolumeheader(struct hfsmount *hfsmp, int waitfor, int altflush);
#define HFS_ALTFLUSH	1

extern int hfsUnmount(struct hfsmount *hfsmp, struct proc *p);


extern int hfs_getcnode(struct hfsmount *hfsmp, cnid_t cnid, struct cat_desc *descp,
			int wantrsrc, struct cat_attr *attrp, struct cat_fork *forkp,
			struct vnode **vpp);

extern int hfs_getnewvnode(struct hfsmount *hfsmp, struct cnode *cp,
                           struct cat_desc *descp, int wantrsrc, struct cat_attr *attrp,
                           struct cat_fork *forkp, struct vnode **vpp);

extern int hfs_metafilelocking(struct hfsmount *hfsmp, u_long fileID, u_int flags, struct proc *p);

extern u_int32_t hfs_freeblks(struct hfsmount * hfsmp, int wantreserve);

extern void hfs_remove_orphans(struct hfsmount *);


short MacToVFSError(OSErr err);

extern int hfs_owner_rights(struct hfsmount *hfsmp, uid_t cnode_uid, struct ucred *cred,
		struct proc *p, int invokesuperuserstatus);

u_long FindMetaDataDirectory(ExtendedVCB *vcb);

#define  kMaxSecsForFsync	5
#define  HFS_SYNCTRANS		1

extern int hfs_btsync(struct vnode *vp, int sync_transaction);
// used as a callback by the journaling code
extern void hfs_sync_metadata(void *arg);

short make_dir_entry(FCB **fileptr, char *name, u_int32_t fileID);


unsigned long BestBlockSizeFit(unsigned long allocationBlockSize,
                               unsigned long blockSizeLimit,
                               unsigned long baseMultiple);

OSErr	hfs_MountHFSVolume(struct hfsmount *hfsmp, HFSMasterDirectoryBlock *mdb,
		struct proc *p);
OSErr	hfs_MountHFSPlusVolume(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
		off_t embeddedOffset, u_int64_t disksize, struct proc *p, void *args);

extern int     hfs_early_journal_init(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
							   void *_args, int embeddedOffset, int mdb_offset,
							   HFSMasterDirectoryBlock *mdbp, struct ucred *cred);
extern u_long  GetFileInfo(ExtendedVCB *vcb, u_int32_t dirid, char *name,
					struct cat_attr *fattr, struct cat_fork *forkinfo);

int hfs_getconverter(u_int32_t encoding, hfs_to_unicode_func_t *get_unicode,
		     unicode_to_hfs_func_t *get_hfsname);

int hfs_relconverter(u_int32_t encoding);

int hfs_to_utf8(ExtendedVCB *vcb, Str31 hfs_str, ByteCount maxDstLen,
		ByteCount *actualDstLen, unsigned char* dstStr);

int utf8_to_hfs(ExtendedVCB *vcb, ByteCount srcLen, const unsigned char* srcStr,
		Str31 dstStr);

int mac_roman_to_utf8(Str31 hfs_str, ByteCount maxDstLen, ByteCount *actualDstLen,
		unsigned char* dstStr);

int utf8_to_mac_roman(ByteCount srcLen, const unsigned char* srcStr, Str31 dstStr);

u_int32_t hfs_pickencoding(const u_int16_t *src, int len);

enum volop {VOL_UPDATE, VOL_MKDIR, VOL_RMDIR, VOL_MKFILE, VOL_RMFILE};

extern int hfs_volupdate(struct hfsmount *hfsmp, enum volop op, int inroot);

extern void hfs_setencodingbits(struct hfsmount *hfsmp, u_int32_t encoding);


extern void replace_desc(struct cnode *cp, struct cat_desc *cdp);

extern int hfs_namecmp(const char *, size_t, const char *, size_t);

extern int  hfs_virtualmetafile(struct cnode *);

void hfs_generate_volume_notifications(struct hfsmount *hfsmp);


#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* __HFS__ */
