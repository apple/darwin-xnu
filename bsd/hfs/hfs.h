/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
/*	@(#)hfs.h		3.0
*
*	(c) 1990, 1992 NeXT Computer, Inc.  All Rights Reserved
*	(c) 1997-1999 Apple Computer, Inc.  All Rights Reserved
*
*	hfs.h -- constants, structures, function declarations. etc.
*			for Macintosh file system vfs.
*
*/

#ifndef __HFS__
#define __HFS__

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/queue.h>
#include <sys/attr.h>

#include <sys/dirent.h>

#include <hfs/hfs_format.h>
#include <hfs/hfs_macos_defs.h>
#include <hfs/hfs_encodings.h>
#include <hfs/rangelist.h>


struct uio;				// This is more effective than #include <sys/uio.h> in case KERNEL is undefined...
struct hfslockf;		// For advisory locking

/*
 *	Just reported via MIG interface.
 */
#define VERSION_STRING	"hfs-2 (4-12-99)"

#define HFS_LINK_MAX	32767

/*
 *	Set to force READ_ONLY.
 */
#define	FORCE_READONLY	0

enum { kMDBSize = 512 };				/* Size of I/O transfer to read entire MDB */

enum { kMasterDirectoryBlock = 2 };			/* MDB offset on disk in 512-byte blocks */
enum { kMDBOffset = kMasterDirectoryBlock * 512 };	/* MDB offset on disk in bytes */

enum {
	kUnknownID = 0,
	kRootParID = 1,
	kRootDirID = 2
};

enum {
	kUndefinedFork 	= 0,
	kDataFork,
	kRsrcFork,
	kDirectory,
	kSysFile,
	kDefault,
	kAnyFork
};

/* number of locked buffer caches to hold for b-tree meta data */
#define kMaxLockedMetaBuffers		32		

/*
 *	File type and creator for symbolic links
 */
enum {
	kSymLinkFileType	= 0x736C6E6B,	/* 'slnk' */
	kSymLinkCreator		= 0x72686170	/* 'rhap' */
};

#define BUFFERPTRLISTSIZE 25

extern char * gBufferAddress[BUFFERPTRLISTSIZE];
extern struct buf *gBufferHeaderPtr[BUFFERPTRLISTSIZE];
extern int gBufferListIndex;
extern  simple_lock_data_t gBufferPtrListLock;

extern struct timezone gTimeZone;

/* Flag values for bexpand: */
#define RELEASE_BUFFER 0x00000001


/* How many free extents to cache per volume */
#define kMaxFreeExtents		10

/* Internal Data structures*/

struct vcb_t {
    u_int16_t 			vcbSigWord;
    int16_t 			vcbAtrb;
    int16_t				vcbFlags;
    int16_t 			vcbVRefNum;

    u_int32_t 			vcbCrDate;
    u_int32_t 			vcbLsMod;
    u_int32_t 			vcbVolBkUp;
    u_int32_t 			checkedDate;		/* time of last disk check */

    int32_t 			vcbFilCnt;
    int32_t 			vcbDirCnt;
    u_int32_t 			blockSize;			/*	size of allocation blocks */
    u_int32_t 			totalBlocks;		/* total allocation blocks */
    u_int32_t 			freeBlocks;			/* free allocation blocks */
    u_int32_t 			nextAllocation;		/* start of next allocation search */
    int32_t 			vcbClpSiz;
    u_int32_t 			vcbNxtCNID;
	u_int32_t 			vcbCNIDGen;
	int32_t 			vcbWrCnt;

    int32_t 			vcbFndrInfo[8];

    u_int64_t 			encodingsBitmap;	/* HFS Plus only */

    u_int16_t 			vcbNmFls;			/* HFS only */
    u_int16_t 			vcbNmRtDirs;		/* HFS only */
    int16_t 			vcbVBMSt;			/* HFS only */
    int16_t 			vcbAlBlSt;			/* HFS only */

    struct vnode *		extentsRefNum;
    struct vnode *		catalogRefNum;
    struct vnode *		allocationsRefNum;

    u_int8_t		 	vcbVN[256];			/* volume name in UTF-8 */
    u_int32_t	 		volumeNameEncodingHint;
	u_int32_t			altIDSector;		/* location of alternate MDB/VH */
    u_int32_t 			hfsPlusIOPosOffset;	/*	Disk block where HFS+ starts */
    u_int32_t 			vcbVBMIOSize;		/* volume bitmap I/O size */
    char *	 			hintCachePtr;		/* volume heuristicHint cache */

	/* cache of largest known free extents */
	u_int32_t				vcbFreeExtCnt;
	HFSPlusExtentDescriptor vcbFreeExt[kMaxFreeExtents];

    u_int32_t 			localCreateDate;	/* creation times for HFS+ volumes are in local time */
    simple_lock_data_t	vcbSimpleLock;		/* simple lock to allow concurrent access to vcb data */
};
typedef struct vcb_t ExtendedVCB;


/* vcbFlags */
#define			kHFS_DamagedVolume			0x1	/* This volume has errors, unmount dirty */
#define 		MARK_VOLUMEDAMAGED(fcb)		FCBTOVCB((fcb))->vcbFlags |= kHFS_DamagedVolume;


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
	u_long				hfs_mount_flags;
	u_int8_t			hfs_fs_clean;			/* Whether contents have been flushed in clean state */
	u_int8_t			hfs_fs_ronly;			/* Whether this was mounted as read-initially  */
	u_int8_t			hfs_unknownpermissions;	/* Whether this was mounted with MNT_UNKNOWNPERMISSIONS */
	
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

	/* simple lock for shared meta renaming */
	simple_lock_data_t	hfs_renamelock;

	/* HFS Specific */
	struct vfsVCB		hfs_vcb;
	u_long			hfs_private_metadata_dir; /* private/hidden directory for unlinked files */
	u_int32_t		hfs_metadata_createdate;
	hfs_to_unicode_func_t	hfs_get_unicode;
	unicode_to_hfs_func_t	hfs_get_hfsname;
} hfsmount_t;

#define HFSPLUS_PRIVATE_DIR	\
        "\xE2\x90\x80\xE2\x90\x80\xE2\x90\x80\xE2\x90\x80HFS+ Private Data"


/*****************************************************************************
*
*	hfsnode structure
*
*
*
*****************************************************************************/

#define MAXHFSVNODELEN		31
typedef u_char FileNameStr[MAXHFSVNODELEN+1];

CIRCLEQ_HEAD(siblinghead, hfsnode)	;	/* Head of the sibling list */


struct  hfsnode {
	LIST_ENTRY(hfsnode) h_hash;		/* links on valid files */
	CIRCLEQ_ENTRY(hfsnode) h_sibling;	/* links on siblings */
	struct lock__bsd__	h_lock;		/* node lock. */
	union {
		struct hfslockf *hu_lockf;	/* Head of byte-level lock list. */
		void            *hu_sysdata;	/* private data for system files */
		char	hu_symlinkdata[4];	/* symbolic link (4 chars or less) */
		char	*hu_symlinkptr;		/* symbolic link pathname */
	} h_un;
	struct vnode *		h_vp;		/* vnode associated with this inode. */
	struct hfsfilemeta *	h_meta;		/* Ptr to file meta data */
	u_int16_t		h_nodeflags;	/* flags, see below */
	u_int8_t		h_type;		/* Type of info: dir, data, rsrc */
	int8_t 			fcbFlags;	/* FCB flags */
	struct rl_head	h_invalidranges;/* Areas of disk that should read back as zeroes */
	u_int64_t 		fcbEOF;		/* Logical length or EOF in bytes */
	u_int64_t 		fcbPLen;	/* Physical file length in bytes */
	u_int32_t 		fcbClmpSize;	/* Number of bytes per clump */
	HFSPlusExtentRecord	fcbExtents;	/* Extents of file */

#if HFS_DIAGNOSTIC
	u_int32_t		h_valid;	/* is the vnode reference valid */
#endif
};
#define	h_lockf		h_un.hu_lockf
#define	fcbBTCBPtr	h_un.hu_sysdata
#define	h_symlinkptr  h_un.hu_symlinkptr
#define	h_symlinkdata h_un.hu_symlinkdata

typedef struct hfsnode FCB;


typedef struct hfsfilemeta {
	struct	siblinghead h_siblinghead;		/* Head of the sibling list */
	simple_lock_data_t	h_siblinglock;		/* sibling list lock. */
	u_int32_t			h_metaflags;		/* IN_LONGNAME, etc */
	struct vnode		*h_devvp;			/* vnode for block I/O. */

	dev_t				h_dev;				/* Device associated with the inode. */
	u_int32_t			h_nodeID;			/* specific id of this node */
	u_int32_t			h_dirID;			/* Parent Directory ID */
	u_int32_t			h_hint;				/* Catalog hint */

	off_t				h_size;				/* Total physical size of object */
	u_int16_t			h_usecount;			/* How many siblings */
	u_int16_t			h_mode;				/* IFMT, permissions; see below. */
	u_int32_t			h_pflags;			/* Permission flags (NODUMP, IMMUTABLE, APPEND etc.) */
	u_int32_t			h_uid;				/* File owner. */
	u_int32_t			h_gid;				/* File group. */
	union {
	    dev_t		hu_rdev;	/* Special device info for this node */
	    u_int32_t		hu_indnodeno;	/* internal indirect node number (never exported) */
	} h_spun;
	u_int32_t			h_crtime;			/* BSD-format creation date in secs. */
	u_int32_t			h_atime;			/* BSD-format access date in secs. */
	u_int32_t			h_mtime;			/* BSD-format mod date in seconds */
	u_int32_t			h_ctime;			/* BSD-format status change date */
	u_int32_t			h_butime;			/* BSD-format last backup date in secs. */
	u_int16_t			h_nlink;			/* link count (aprox. for dirs) */
	u_short				h_namelen;			/* Length of name string */
	char *				h_namePtr;			/* Points the name of the file */
	FileNameStr			h_fileName;			/* CName of file */
} hfsfilemeta;
#define	h_rdev		h_spun.hu_rdev
#define	h_indnodeno	h_spun.hu_indnodeno

#define H_EXTENDSIZE(VP,BYTES)	((VP)->h_meta->h_size += (BYTES))
#define H_TRUNCSIZE(VP,BYTES)	((VP)->h_meta->h_size -= (BYTES))

#define MAKE_INODE_NAME(name,linkno) \
	    (void) sprintf((name), "%s%d", HFS_INODE_PREFIX, (linkno))


/*
 *	Macros for quick access to fields buried in the fcb inside an hfs node:
 */
#define H_FORKTYPE(HP)	((HP)->h_type)
#define H_FILEID(HP)	((HP)->h_meta->h_nodeID)
#define H_DIRID(HP)		((HP)->h_meta->h_dirID)
#define H_NAME(HP)		((HP)->h_meta->h_namePtr)
#define H_HINT(HP)		((HP)->h_meta->h_hint)
#define H_DEV(HP)		((HP)->h_meta->h_dev)

#define H_ISBIGLINK(HP) ((HP)->fcbEOF > 4)
#define H_SYMLINK(HP)   (H_ISBIGLINK((HP)) ? (HP)->h_symlinkptr : (HP)->h_symlinkdata)

/* These flags are kept in flags. */
#define IN_ACCESS		0x0001		/* Access time update request. */
#define IN_CHANGE		0x0002		/* Change time update request. */
#define IN_UPDATE		0x0004		/* Modification time update request. */
#define IN_MODIFIED 	0x0008		/* Node has been modified. */
#define IN_RENAME		0x0010		/* Node is being renamed. */
#define IN_SHLOCK		0x0020		/* File has shared lock. */
#define IN_EXLOCK		0x0040		/* File has exclusive lock. */
#define IN_BYCNID		0x0100		/* Dir was found by CNID */
#define IN_ALLOCATING	0x1000		/* vnode is in transit, wait or ignore */
#define IN_WANT			0x2000		/* Its being waited for */

/* These flags are kept in meta flags. */
#define IN_LONGNAME 	0x0400		/* File has long name buffer. */
#define IN_UNSETACCESS	0x0200		/* File has unset access. */
#define IN_DELETED	0x0800		/* File has been marked to be deleted */
#define IN_NOEXISTS	0x1000		/* File has been deleted, catalog entry is gone */
#if HFS_HARDLINKS
#define	IN_DATANODE	0x2000		/* File is a data node (hard-linked) */
#endif


/* File permissions stored in mode */
#define IEXEC			0000100		/* Executable. */
#define IWRITE			0000200		/* Writeable. */
#define IREAD			0000400		/* Readable. */
#define ISVTX			0001000		/* Sticky bit. */
#define ISGID			0002000		/* Set-gid. */
#define ISUID			0004000		/* Set-uid. */

/* File types */
#define IFMT			0170000		/* Mask of file type. */
#define IFIFO			0010000		/* Named pipe (fifo). */
#define IFCHR			0020000		/* Character device. */
#define IFDIR			0040000		/* Directory file. */
#define IFBLK			0060000		/* Block device. */
#define IFREG			0100000		/* Regular file. */
#define IFLNK			0120000		/* Symbolic link. */
#define IFSOCK			0140000		/* UNIX domain socket. */
#define IFWHT			0160000		/* Whiteout. */

/* Value to make sure vnode is real and defined */
#define HFS_VNODE_MAGIC 0x4846532b	/* 'HFS+' */

/* To test wether the forkType is a sibling type */
#define SIBLING_FORKTYPE(FORK) 	((FORK==kDataFork) || (FORK==kRsrcFork))

/*
 *	Write check macro
 */
#define	WRITE_CK(VNODE, FUNC_NAME)	{				\
    if ((VNODE)->v_mount->mnt_flag & MNT_RDONLY) {			\
        DBG_ERR(("%s: ATTEMPT TO WRITE A READONLY VOLUME\n", 	\
                 FUNC_NAME));	\
                     return(EROFS);							\
    }									\
}


/*
 *	hfsmount locking and unlocking.
 *
 *	mvl_lock_flags
 */
#define MVL_LOCKED    0x00000001	/* debug only */

#if	HFS_DIAGNOSTIC
#define MVL_LOCK(mvip)    {				\
    (simple_lock(&(mvip)->mvl_lock));			\
        (mvip)->mvl_flags |= MVL_LOCKED;			\
}

#define MVL_UNLOCK(mvip)    {				\
    if(((mvip)->mvl_flags & MVL_LOCKED) == 0) {		\
        panic("MVL_UNLOCK - hfsnode not locked");	\
    }							\
    (simple_unlock(&(mvip)->mvl_lock));			\
        (mvip)->mvl_flags &= ~MVL_LOCKED;			\
}
#else	/* HFS_DIAGNOSTIC */
#define MVL_LOCK(mvip)		(simple_lock(&(mvip)->mvl_lock))
#define MVL_UNLOCK(mvip)	(simple_unlock(&(mvip)->mvl_lock))
#endif	/* HFS_DIAGNOSTIC */


/* structure to hold a "." or ".." directory entry (12 bytes) */
typedef struct hfsdotentry {
	u_int32_t	d_fileno;	/* unique file number */
	u_int16_t	d_reclen;	/* length of this structure */
	u_int8_t	d_type;		/* dirent file type */
	u_int8_t	d_namelen;	/* len of filename */
	char		d_name[4];	/* "." or ".." */
} hfsdotentry;

#define AVERAGE_HFSDIRENTRY_SIZE  (8+22+4)
#define MAX_HFSDIRENTRY_SIZE	sizeof(struct dirent)

#define DIRENTRY_SIZE(namlen) \
    ((sizeof(struct dirent) - (NAME_MAX+1)) + (((namlen)+1 + 3) &~ 3))

enum {
	kCatNameIsAllocated 	= 0x1,			/* The name is malloc'd and is in cnm_nameptr */
	kCatNameIsMangled 		= 0x2,			/* The name is mangled */
	kCatNameUsesReserved 	= 0x4,			/* It overides the space reserved by cnm_namespace into cndu_extra, careful */
	kCatNameIsConsumed 		= 0x8,			/* The name has been already processed, no freeing or work is needed */
	kCatNameNoCopyName	 	= 0x10,			/* Dont copy the name */
	kCatNameMangleName	 	= 0x20			/* Mangle name if greater than passed in length */
};

/*
 * CatalogNameSpecifier is a structure that contains a name and possibly its form
 *
 * Special care needs to be taken with the flags, they can cause side effects.
 */
struct CatalogNameSpecifier {
	u_int16_t		cnm_flags;			/* See above */
	u_int16_t		cnm_length;			/* Length of the name */
	u_int32_t		cnm_parID;			/* ID of the parent directory */
	unsigned char	*cnm_nameptr;		/* If allocated, a ptr to the space, else NULL */
	unsigned char	cnm_namespace[MAXHFSVNODELEN+1]; /* Space where the name can be kept */
};
/*
 * NOTE IT IS REQUIRED that KMaxMangleNameLen >= MAXHFSVNODELEN
 * Also the total size of CatalogNameSpecifier should be less then cndu_extra, which
 * currently it easily is, this is not a requirement, just a nicety.
 *
 * The rules to how to store a name:
 * If its less than MAXHFSVNODELEN always store it in cnm_namespace.
 * If we can get by doing mangling then cnm_namespace
 * else allocate the space needed to cnm_nameptr.
 * This reflects what is done at vnode creation.
 */


enum {
	kCatalogFolderNode = 1,
	kCatalogFileNode = 2
};

/* 
 * CatalogNodeData has same layout as the on-disk HFS Plus file/dir records.
 * Classic hfs file/dir records are converted to match this layout.
 * 
 * The cnd_extra padding allows big hfs plus thread records (520 bytes max)
 * to be read onto this stucture during a cnid lookup.
 *
 * IMPORTANT!!!!!!
 * After declaring this structure, you must use the macro INIT_CATALOGDATA to prepare it
 * and CLEAN_CATALOGDATA after using it, to clean any allocated structures.
 *
 * If you do not need to have the name, then pass in kCatNameNoCopyName for flags
 */
struct CatalogNodeData {
	int16_t			cnd_type;
	u_int16_t		cnd_flags;
	u_int32_t		cnd_valence;	/* dirs only */
	u_int32_t		cnd_nodeID;
	u_int32_t		cnd_createDate;
	u_int32_t		cnd_contentModDate;
	u_int32_t		cnd_attributeModDate;
	u_int32_t		cnd_accessDate;
	u_int32_t		cnd_backupDate;
	u_int32_t 		cnd_ownerID;
	u_int32_t 		cnd_groupID;
	u_int8_t 		cnd_adminFlags;  /* super-user changeable flags */
	u_int8_t 		cnd_ownerFlags;  /* owner changeable flags */
	u_int16_t 		cnd_mode;        /* file type + permission bits */
	union {
	    u_int32_t	cndu_iNodeNum;   /* indirect links only */
	    u_int32_t	cndu_linkCount;  /* indirect nodes only */
	    u_int32_t 	cndu_rawDevice;  /* special files (FBLK and FCHR) only */
	} cnd_un;
	u_int8_t		cnd_finderInfo[32];
	u_int32_t 		cnd_textEncoding;
	u_int32_t		cnd_reserved;
	HFSPlusForkData	cnd_datafork;
	HFSPlusForkData	cnd_rsrcfork;
	u_int32_t	cnd_iNodeNumCopy;
	u_int32_t	cnd_linkCNID;	/* for hard links only */
	u_int8_t	cnd_extra[264];	/* make struct at least 520 bytes long */
	struct CatalogNameSpecifier		cnd_namespecifier;
};
typedef struct CatalogNodeData CatalogNodeData;

#define	cnd_iNodeNum		cnd_un.cndu_iNodeNum
#define	cnd_linkCount		cnd_un.cndu_linkCount
#define	cnd_rawDevice		cnd_un.cndu_rawDevice

#define	cnm_flags		cnd_namespecifier.cnm_flags
#define	cnm_length		cnd_namespecifier.cnm_length
#define	cnm_parID		cnd_namespecifier.cnm_parID
#define	cnm_nameptr		cnd_namespecifier.cnm_nameptr
#define	cnm_namespace		cnd_namespecifier.cnm_namespace

#define INIT_CATALOGDATA(C,F)	do { bzero(&((C)->cnd_namespecifier), sizeof(struct CatalogNameSpecifier)); (C)->cnm_flags=(F);}while(0);
#if HFS_DIAGNOSTIC
extern void debug_check_catalogdata(struct CatalogNodeData *cat);
#define CLEAN_CATALOGDATA(C)	do { debug_check_catalogdata(C); \
											if ((C)->cnm_flags & kCatNameIsAllocated) {\
											FREE((C)->cnm_nameptr, M_TEMP);\
											(C)->cnm_flags &= ~kCatNameIsAllocated;\
											(C)->cnm_nameptr = NULL;\
											}}while(0);
#else
#define CLEAN_CATALOGDATA(C)	do { if ((C)->cnm_flags & kCatNameIsAllocated) {\
											FREE((C)->cnm_nameptr, M_TEMP);\
											(C)->cnm_flags &= ~kCatNameIsAllocated;\
											(C)->cnm_nameptr = NULL;\
											}}while(0);
#endif

/* structure to hold a catalog record information */
/* Of everything you wanted to know about a catalog entry, file and directory */
typedef struct hfsCatalogInfo {
    CatalogNodeData 	nodeData;
    u_int32_t				hint;
} hfsCatalogInfo;

enum { kHFSPlusMaxFileNameBytes = kHFSPlusMaxFileNameChars * 3 };

enum { kdirentMaxNameBytes = NAME_MAX };

//	structure definition of the searchfs system trap for the search criterea.
struct directoryInfoSpec
{
	u_long				numFiles;
};

struct fileInfoSpec
{
	off_t				dataLogicalLength;
	off_t				dataPhysicalLength;
	off_t				resourceLogicalLength;
	off_t				resourcePhysicalLength;
};

struct searchinfospec
{
	u_char				name[kHFSPlusMaxFileNameBytes];
	u_long				nameLength;
	char				attributes;		// see IM:Files 2-100
	u_long				nodeID;
	u_long				parentDirID;
	struct timespec		creationDate;		
	struct timespec		modificationDate;		
	struct timespec		changeDate;	
	struct timespec		lastBackupDate;	
	u_long				finderInfo[8];
	uid_t				uid;	
	gid_t				gid;
	mode_t				mask;
    struct fileInfoSpec f;
	struct directoryInfoSpec d;
};
typedef struct searchinfospec searchinfospec_t;

#define HFSTIMES(hp, t1, t2) {						\
	if ((hp)->h_nodeflags & (IN_ACCESS | IN_CHANGE | IN_UPDATE)) {	\
		(hp)->h_nodeflags |= IN_MODIFIED;				\
		if ((hp)->h_nodeflags & IN_ACCESS) {			\
			(hp)->h_meta->h_atime = (t1)->tv_sec;			\
		};											\
		if ((hp)->h_nodeflags & IN_UPDATE) {			\
			(hp)->h_meta->h_mtime = (t2)->tv_sec;			\
		}											\
		if ((hp)->h_nodeflags & IN_CHANGE) {			\
			(hp)->h_meta->h_ctime = time.tv_sec;			\
		};											\
		(hp)->h_nodeflags &= ~(IN_ACCESS | IN_CHANGE | IN_UPDATE);	\
	}								\
}

/* This overlays the fid structure (see mount.h). */
struct hfsfid {
	u_int16_t hfsfid_len;	/* Length of structure. */
	u_int16_t hfsfid_pad;	/* Force 32-bit alignment. */
							/* The following data is filesystem-dependent, up to MAXFIDSZ (16) bytes: */
	u_int32_t hfsfid_cnid;	/* Catalog node ID. */
	u_int32_t hfsfid_gen;	/* Generation number (create date). */
};

/* macro to determine if hfs or hfsplus */
#define ISHFSPLUS(VCB) ((VCB)->vcbSigWord == kHFSPlusSigWord)
#define ISHFS(VCB) ((VCB)->vcbSigWord == kHFSSigWord)


/*
 * Various ways to acquire a VNode pointer:
 */
#define HTOV(HP) ((HP)->h_vp)

/*
 * Various ways to acquire an HFS Node pointer:
 */
#define VTOH(VP) ((struct hfsnode *)((VP)->v_data))
#define FCBTOH(FCB) ((struct hfsnode *)FCB)

/*
 * Various ways to acquire an FCB pointer:
 */
#define HTOFCB(HP) (HP)
#define VTOFCB(VP) ((FCB *)((VP)->v_data))		/* Should be the same as VTOH */

/*
 * Various ways to acquire a VFS mount point pointer:
 */
#define VTOVFS(VP) ((VP)->v_mount)
#define	HTOVFS(HP) ((HP)->h_vp->v_mount)
#define FCBTOVFS(FCB) ((FCB)->h_vp->v_mount)
#define HFSTOVFS(HFSMP) ((HFSMP)->hfs_mp)
#define VCBTOVFS(VCB) (((struct vfsVCB *)(VCB))->vcb_hfsmp->hfs_mp)

/*
 * Various ways to acquire an HFS mount point pointer:
 */
#define VTOHFS(VP) ((struct hfsmount *)((VP)->v_mount->mnt_data))
#define	HTOHFS(HP) ((struct hfsmount *)(HP)->h_vp->v_mount->mnt_data)
#define FCBTOHFS(FCB) ((struct hfsmount *)(FCB)->h_vp->v_mount->mnt_data)
#define	VFSTOHFS(MP) ((struct hfsmount *)(MP)->mnt_data)	
#define VCBTOHFS(VCB) (((struct vfsVCB *)(VCB))->vcb_hfsmp)

/*
 * Various ways to acquire a VCB pointer:
 */
#define VTOVCB(VP) (&(((struct hfsmount *)((VP)->v_mount->mnt_data))->hfs_vcb.vcb_vcb))
#define HTOVCB(HP) (&(((struct hfsmount *)((HP)->h_vp->v_mount->mnt_data))->hfs_vcb.vcb_vcb))
#define FCBTOVCB(FCB) (&(((struct hfsmount *)((FCB)->h_vp->v_mount->mnt_data))->hfs_vcb.vcb_vcb))
#define VFSTOVCB(MP) (&(((struct hfsmount *)(MP)->mnt_data)->hfs_vcb.vcb_vcb))
#define HFSTOVCB(HFSMP) (&(HFSMP)->hfs_vcb.vcb_vcb)


#define E_NONE	0
#define kHFSBlockSize 512
#define kHFSBlockShift 9	/* 2^9 = 512 */

#define IOBLKNOFORBLK(STARTINGBLOCK, BLOCKSIZEINBYTES) ((daddr_t)((STARTINGBLOCK) / ((BLOCKSIZEINBYTES) >> 9)))
#define IOBLKCNTFORBLK(STARTINGBLOCK, BYTESTOTRANSFER, BLOCKSIZEINBYTES) \
    ((int)(IOBLKNOFORBYTE(((STARTINGBLOCK) * 512) + (BYTESTOTRANSFER) - 1, (BLOCKSIZEINBYTES)) - \
           IOBLKNOFORBLK((STARTINGBLOCK), (BLOCKSIZEINBYTES)) + 1))
#define IOBYTECCNTFORBLK(STARTINGBLOCK, BYTESTOTRANSFER, BLOCKSIZEINBYTES) \
    (IOBLKCNTFORBLK((STARTINGBLOCK),(BYTESTOTRANSFER),(BLOCKSIZEINBYTES)) * (BLOCKSIZEINBYTES))
#define IOBYTEOFFSETFORBLK(STARTINGBLOCK, BLOCKSIZEINBYTES) \
    (((STARTINGBLOCK) * 512) - \
     (IOBLKNOFORBLK((STARTINGBLOCK), (BLOCKSIZEINBYTES)) * (BLOCKSIZEINBYTES)))

#define IOBLKNOFORBYTE(STARTINGBYTE, BLOCKSIZEINBYTES) ((daddr_t)((STARTINGBYTE) / (BLOCKSIZEINBYTES)))
#define IOBLKCNTFORBYTE(STARTINGBYTE, BYTESTOTRANSFER, BLOCKSIZEINBYTES) \
((int)(IOBLKNOFORBYTE((STARTINGBYTE) + (BYTESTOTRANSFER) - 1, (BLOCKSIZEINBYTES)) - \
           IOBLKNOFORBYTE((STARTINGBYTE), (BLOCKSIZEINBYTES)) + 1))
#define IOBYTECNTFORBYTE(STARTINGBYTE, BYTESTOTRANSFER, BLOCKSIZEINBYTES) \
    (IOBLKCNTFORBYTE((STARTINGBYTE),(BYTESTOTRANSFER),(BLOCKSIZEINBYTES)) * (BLOCKSIZEINBYTES))
#define IOBYTEOFFSETFORBYTE(STARTINGBYTE, BLOCKSIZEINBYTES) ((STARTINGBYTE) - (IOBLKNOFORBYTE((STARTINGBYTE), (BLOCKSIZEINBYTES)) * (BLOCKSIZEINBYTES)))

#define MAKE_VREFNUM(x)	((int32_t)((x) & 0xffff))
/*
 *	This is the straight GMT conversion constant:
 *	00:00:00 January 1, 1970 - 00:00:00 January 1, 1904
 *	(3600 * 24 * ((365 * (1970 - 1904)) + (((1970 - 1904) / 4) + 1)))
 */
#define MAC_GMT_FACTOR		2082844800UL

#define HFS_ATTR_CMN_LOOKUPMASK (ATTR_CMN_SCRIPT | ATTR_CMN_FNDRINFO | ATTR_CMN_NAMEDATTRCOUNT | ATTR_CMN_NAMEDATTRLIST)
#define HFS_ATTR_DIR_LOOKUPMASK (ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT)
#define HFS_ATTR_FILE_LOOKUPMASK (ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE | \
									ATTR_FILE_DATALENGTH | ATTR_FILE_DATAALLOCSIZE | ATTR_FILE_DATAEXTENTS | \
									ATTR_FILE_RSRCLENGTH | ATTR_FILE_RSRCALLOCSIZE | ATTR_FILE_RSRCEXTENTS)

u_int32_t to_bsd_time(u_int32_t hfs_time);
u_int32_t to_hfs_time(u_int32_t bsd_time);

int hfs_flushfiles(struct mount *mp, int flags);
short hfs_flushMDB(struct hfsmount *hfsmp, int waitfor);
short hfs_flushvolumeheader(struct hfsmount *hfsmp, int waitfor);

short hfs_getcatalog (ExtendedVCB *vcb, u_int32_t dirID, char *name, short len, hfsCatalogInfo *catInfo);
short hfsMoveRename (ExtendedVCB *vcb, u_int32_t oldDirID, char *oldName, u_int32_t newDirID, char *newName, u_int32_t *hint);
short hfsCreate (ExtendedVCB *vcb, u_int32_t dirID, char *name, int mode, u_int32_t tehint);
short hfsCreateFileID (ExtendedVCB *vcb, u_int32_t parentDirID, StringPtr name, u_int32_t catalogHint, u_int32_t *fileIDPtr);
short hfs_vcreate (ExtendedVCB *vcb, hfsCatalogInfo *catInfo, u_int8_t forkType, struct vnode **vpp);
short hfsDelete (ExtendedVCB *vcb, u_int32_t parentDirID, StringPtr name, short isfile, u_int32_t catalogHint);
short hfsUnmount(struct hfsmount *hfsmp, struct proc *p);

extern int hfs_metafilelocking(struct hfsmount *hfsmp, u_long fileID, u_int flags, struct proc *p);
extern int hasOverflowExtents(struct hfsnode *hp);

void hfs_set_metaname(char *, struct hfsfilemeta *, struct hfsmount *);

short MacToVFSError(OSErr err);
int hfs_owner_rights(struct vnode *vp, struct ucred *cred, struct proc *p, Boolean invokesuperuserstatus);

void CopyVNodeToCatalogNode (struct vnode *vp, struct CatalogNodeData *nodeData);
void CopyCatalogToHFSNode(struct hfsCatalogInfo *catalogInfo, struct hfsnode *hp);
u_long FindMetaDataDirectory(ExtendedVCB *vcb);


short make_dir_entry(FCB **fileptr, char *name, u_int32_t fileID);

int AttributeBlockSize(struct attrlist *attrlist);
void PackCommonAttributeBlock(struct attrlist *alist,
							  struct vnode *vp,
							  struct hfsCatalogInfo *catInfo,
							  void **attrbufptrptr,
							  void **varbufptrptr);
void PackVolAttributeBlock(struct attrlist *alist,
						   struct vnode *vp,
						   struct hfsCatalogInfo *catInfo,
						   void **attrbufptrptr,
						   void **varbufptrptr);
void PackFileDirAttributeBlock(struct attrlist *alist,
							   struct vnode *vp,
							   struct hfsCatalogInfo *catInfo,
							   void **attrbufptrptr,
							   void **varbufptrptr);
void PackForkAttributeBlock(struct attrlist *alist,
							struct vnode *vp,
							struct hfsCatalogInfo *catInfo,
							void **attrbufptrptr,
							void **varbufptrptr);
void PackAttributeBlock(struct attrlist *alist,
						struct vnode *vp,
						struct hfsCatalogInfo *catInfo,
						void **attrbufptrptr,
						void **varbufptrptr);
void PackCatalogInfoAttributeBlock (struct attrlist *alist,
						struct vnode * root_vp,
						struct hfsCatalogInfo *catInfo,
						void **attrbufptrptr,
						void **varbufptrptr);
void UnpackCommonAttributeBlock(struct attrlist *alist,
							  struct vnode *vp,
							  struct hfsCatalogInfo *catInfo,
							  void **attrbufptrptr,
							  void **varbufptrptr);
void UnpackAttributeBlock(struct attrlist *alist,
						struct vnode *vp,
						struct hfsCatalogInfo *catInfo,
						void **attrbufptrptr,
						void **varbufptrptr);
unsigned long BestBlockSizeFit(unsigned long allocationBlockSize,
                               unsigned long blockSizeLimit,
                               unsigned long baseMultiple);

OSErr	hfs_MountHFSVolume(struct hfsmount *hfsmp, HFSMasterDirectoryBlock *mdb,
		u_long sectors, struct proc *p);
OSErr	hfs_MountHFSPlusVolume(struct hfsmount *hfsmp, HFSPlusVolumeHeader *vhp,
		u_long embBlkOffset, u_long sectors, struct proc *p);
OSStatus  GetInitializedVNode(struct hfsmount *hfsmp, struct vnode **tmpvnode);

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

#endif /* __HFS__ */
