/*
 * Copyright (c) 2004-2015 Apple Computer, Inc. All rights reserved.
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

#ifndef _HFS_FSCTL_H_
#define _HFS_FSCTL_H_

#include <sys/appleapiopts.h>

#include <sys/param.h>
#include <sys/ioccom.h>
#include <sys/time.h>
#include <stdint.h>

#ifdef __APPLE_API_UNSTABLE

struct hfs_backingstoreinfo {
	int  signature;   /* == 3419115 */
	int  version;     /* version of this struct (1) */
	int  backingfd;   /* disk image file (on backing fs) */
	int  bandsize;    /* sparse disk image band size */
};


typedef char pathname_t[MAXPATHLEN];

struct hfs_journal_info {
	off_t	jstart;
	off_t	jsize;
};


// Will be deprecated and replaced by hfs_fsinfo
struct hfsinfo_metadata {
	uint32_t total;
	uint32_t extents;
	uint32_t catalog;
	uint32_t allocation;
	uint32_t attribute;
	uint32_t journal;
	uint32_t reserved[4];
};

/*
 * Flags for hfs_fsinfo_data structure
 */
#define HFS_FSINFO_CLASS_A      0x0001	/* Information for class A files requested */
#define HFS_FSINFO_CLASS_B      0x0002	/* Information for class B files requested */
#define HFS_FSINFO_CLASS_C      0x0004	/* Information for class C files requested */
#define HFS_FSINFO_CLASS_D      0x0008	/* Information for class D files requested */

/*
 * Maximum number of buckets to represent range from 0 to 1TB (2^40) in
 * increments of power of 2, and one catch-all bucket for anything that
 * is greater than 1TB
 */
#define HFS_FSINFO_DATA_MAX_BUCKETS     42

/*
 * Maximum number of buckets to represents percentage range from 0 to 100
 * in increments of 10.
 */
#define HFS_FSINFO_PERCENT_MAX_BUCKETS  10

/*
 * Maximum number of buckets to represent number of file/directory name characters
 * (range 1 to 255) in increments of 5.
 */
#define HFS_FSINFO_NAME_MAX_BUCKETS     51

/*
 * Version number to ensure that the caller and the kernel have same understanding
 * of the hfs_fsinfo_data structure.  This version needs to be bumped whenever the
 * number of buckets is changed.
 */
#define HFS_FSINFO_VERSION              1

/*
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
 *
 * Note that fsctls that populate this data structure can take long time to
 * execute as this operation can be I/O intensive (traversing btrees) and compute
 * intensive.
 *
 * WARNING: Any changes to this structure should also update version number to
 * ensure that the clients and kernel are reading/writing correctly.
 */

/* 
 * The header includes the user input fields.
 */
typedef struct hfs_fsinfo_header {
	uint32_t request_type;
	uint16_t version;
	uint16_t flags;
} hfs_fsinfo_header_t;

struct hfs_fsinfo_data {
	hfs_fsinfo_header_t header;
	uint32_t			bucket[HFS_FSINFO_DATA_MAX_BUCKETS];
};

/*
 * Structure to represent information about metadata files
 *
 * WARNING: Any changes to this structure should also update version number to
 * ensure that the clients and kernel are reading/writing correctly.
 */
struct hfs_fsinfo_metadata {
	hfs_fsinfo_header_t header;
	uint32_t			extents;
	uint32_t			catalog;
	uint32_t			allocation;
	uint32_t			attribute;
	uint32_t			journal;
};

/*
 * Structure to represent distribution of number of file name characters
 * in increments of 5s.  Each bucket represents a range of values that is
 * determined based on its index in the array.  So bucket[i] represents values
 * that are greater than or equal to (i*5) and less than ((i+1)*10).
 *
 * Since this structure represents range of file name characters and the
 * maximum number of unicode characters in HFS+ is 255, the maximum number
 * of buckets will be 52 [0..51].
 *
 * For example,
 * bucket[4] -> greater than or equal to 20 and less than 25 characters
 * bucket[51] -> equal to 255 characters
 *
 * WARNING: Any changes to this structure should also update version number to
 * ensure that the clients and kernel are reading/writing correctly.
 */
struct hfs_fsinfo_name {
	hfs_fsinfo_header_t	header;
	uint32_t			bucket[HFS_FSINFO_NAME_MAX_BUCKETS];
};

/*
 * Structure to represent information about content protection classes
 *
 * WARNING: Any changes to this structure should also update version number to
 * ensure that the clients and kernel are reading/writing correctly.
 */
struct hfs_fsinfo_cprotect {
	hfs_fsinfo_header_t	header;
	uint32_t class_A;
	uint32_t class_B;
	uint32_t class_C;
	uint32_t class_D;
	uint32_t class_E;
	uint32_t class_F;
};

/*
 * Union of all the different values returned by HFSIOC_FSINFO fsctl
 */
union hfs_fsinfo {
	hfs_fsinfo_header_t			header;
	struct hfs_fsinfo_data		data;
	struct hfs_fsinfo_metadata	metadata;
	struct hfs_fsinfo_name		name;
	struct hfs_fsinfo_cprotect cprotect;
};
typedef union hfs_fsinfo hfs_fsinfo;

/*
 * Type of FSINFO requested, specified by the caller in request_type field
 */
enum {
	/* Information about number of allocation blocks for each metadata file, returns struct hfs_fsinfo_metadata */
	HFS_FSINFO_METADATA_BLOCKS_INFO	= 1,
	
	/* Information about number of extents for each metadata file, returns struct hfs_fsinfo_metadata */
	HFS_FSINFO_METADATA_EXTENTS		= 2,
	
	/* Information about percentage of free nodes vs used nodes in metadata btrees, returns struct hfs_fsinfo_metadata */
	HFS_FSINFO_METADATA_PERCENTFREE	= 3,
	
	/* Distribution of number of extents for data files (data fork, no rsrc fork, no xattr), returns struct hfs_fsinfo_data */
	HFS_FSINFO_FILE_EXTENT_COUNT	= 4,
	
	/* Distribution of extent sizes for data files (data fork, no rsrc fork, no xattr), returns struct hfs_fsinfo_data */
	HFS_FSINFO_FILE_EXTENT_SIZE		= 5,
	
	/* Distribution of file sizes for data files (data fork, no rsrc fork, no xattr), returns struct hfs_fsinfo_data */
	HFS_FSINFO_FILE_SIZE			= 6,

	/* Distribution of valence for all directories, returns struct hfs_fsinfo_data */
	HFS_FSINFO_DIR_VALENCE			= 7,
	
	/* Distribution of file/directory name size in unicode characters, returns struct hfs_fsinfo_name */
	HFS_FSINFO_NAME_SIZE			= 8,
	
	/* Distribution of extended attribute sizes, returns hfs_fsinfo_data */
	HFS_FSINFO_XATTR_SIZE			= 9,
	
	/* Distribution of free space for the entire file system, returns struct hfs_fsinfo_data */
	HFS_FSINFO_FREE_EXTENTS			= 10,

	/* Information about number of files belonging to each class, returns hfs_fsinfo_cprotect */
	HFS_FSINFO_FILE_CPROTECT_COUNT	= 11,

	/*
	 * Distribution of symbolic link sizes for data files (data fork, no rsrc fork, no xattr),
	 * returns struct hfs_fsinfo_data
	 */
	HFS_FSINFO_SYMLINK_SIZE			= 12,
};


/* HFS FS CONTROL COMMANDS */

#define HFSIOC_RESIZE_PROGRESS  _IOR('h', 1, u_int32_t)
#define HFS_RESIZE_PROGRESS  IOCBASECMD(HFSIOC_RESIZE_PROGRESS)

#define HFSIOC_RESIZE_VOLUME  _IOW('h', 2, u_int64_t)
#define HFS_RESIZE_VOLUME  IOCBASECMD(HFSIOC_RESIZE_VOLUME)

#define HFSIOC_CHANGE_NEXT_ALLOCATION  _IOWR('h', 3, u_int32_t)
#define HFS_CHANGE_NEXT_ALLOCATION  IOCBASECMD(HFSIOC_CHANGE_NEXT_ALLOCATION)
/* Magic value for next allocation to use with fcntl to set next allocation
 * to zero and never update it again on new block allocation.
 */
#define HFS_NO_UPDATE_NEXT_ALLOCATION 	0xffffFFFF

#define HFSIOC_GETCREATETIME  _IOR('h', 4, time_t)
#define HFS_GETCREATETIME  IOCBASECMD(HFSIOC_GETCREATETIME)

#define HFSIOC_SETBACKINGSTOREINFO  _IOW('h', 7, struct hfs_backingstoreinfo)
#define HFS_SETBACKINGSTOREINFO  IOCBASECMD(HFSIOC_SETBACKINGSTOREINFO)

#define HFSIOC_CLRBACKINGSTOREINFO  _IO('h', 8)
#define HFS_CLRBACKINGSTOREINFO  IOCBASECMD(HFSIOC_CLRBACKINGSTOREINFO)

#define HFSIOC_BULKACCESS _IOW('h', 9, struct user32_access_t)
#define HFS_BULKACCESS_FSCTL IOCBASECMD(HFSIOC_BULKACCESS)

/* Unsupported - Previously used to enable/disable ACLs */
#define HFSIOC_UNSUPPORTED  _IOW('h', 10, int32_t)

#define HFSIOC_PREV_LINK  _IOWR('h', 11, u_int32_t)
#define HFS_PREV_LINK  IOCBASECMD(HFSIOC_PREV_LINK)

#define HFSIOC_NEXT_LINK  _IOWR('h', 12, u_int32_t)
#define HFS_NEXT_LINK  IOCBASECMD(HFSIOC_NEXT_LINK)

#define HFSIOC_GETPATH  _IOWR('h', 13, pathname_t)
#define HFS_GETPATH  IOCBASECMD(HFSIOC_GETPATH)
/* By default, the path returned by HFS_GETPATH is an absolute path, 
 * i.e. it also contains the mount point of the volume on which the 
 * fileID exists.  If the following bit is set, the path returned is
 * relative to the root of the volume.
 */
#define HFS_GETPATH_VOLUME_RELATIVE	0x1

/* Enable/disable extent-based extended attributes */
#define HFSIOC_SET_XATTREXTENTS_STATE  _IOW('h', 14, u_int32_t)
#define HFS_SET_XATTREXTENTS_STATE  IOCBASECMD(HFSIOC_SET_XATTREXTENTS_STATE)

#define HFSIOC_EXT_BULKACCESS _IOW('h', 15, struct user32_ext_access_t)
#define HFS_EXT_BULKACCESS_FSCTL IOCBASECMD(HFSIOC_EXT_BULKACCESS)

#define HFSIOC_MARK_BOOT_CORRUPT _IO('h', 16)
#define HFS_MARK_BOOT_CORRUPT IOCBASECMD(HFSIOC_MARK_BOOT_CORRUPT)

#define HFSIOC_GET_JOURNAL_INFO	_IOR('h', 17, struct hfs_journal_info)
#define	HFS_FSCTL_GET_JOURNAL_INFO	IOCBASECMD(HFSIOC_GET_JOURNAL_INFO)

#define HFSIOC_SET_VERY_LOW_DISK _IOW('h', 20, u_int32_t)
#define HFS_FSCTL_SET_VERY_LOW_DISK IOCBASECMD(HFSIOC_SET_VERY_LOW_DISK)

#define HFSIOC_SET_LOW_DISK _IOW('h', 21, u_int32_t)
#define HFS_FSCTL_SET_LOW_DISK IOCBASECMD(HFSIOC_SET_LOW_DISK)

#define HFSIOC_SET_DESIRED_DISK _IOW('h', 22, u_int32_t)
#define HFS_FSCTL_SET_DESIRED_DISK IOCBASECMD(HFSIOC_SET_DESIRED_DISK)

#define HFSIOC_SET_ALWAYS_ZEROFILL _IOW('h', 23, int32_t)
#define HFS_SET_ALWAYS_ZEROFILL IOCBASECMD(HFSIOC_SET_ALWAYS_ZEROFILL)

#define HFSIOC_VOLUME_STATUS  _IOR('h', 24, u_int32_t)
#define HFS_VOLUME_STATUS  IOCBASECMD(HFSIOC_VOLUME_STATUS)

/* Disable metadata zone for given volume */
#define HFSIOC_DISABLE_METAZONE	_IO('h', 25)
#define HFS_DISABLE_METAZONE	IOCBASECMD(HFSIOC_DISABLE_METAZONE)

/* Change the next CNID value */
#define HFSIOC_CHANGE_NEXTCNID	_IOWR('h', 26, u_int32_t)
#define HFS_CHANGE_NEXTCNID		IOCBASECMD(HFSIOC_CHANGE_NEXTCNID)
	
/* Get the low disk space values */
#define	HFSIOC_GET_VERY_LOW_DISK	_IOR('h', 27, u_int32_t)
#define	HFS_FSCTL_GET_VERY_LOW_DISK	IOCBASECMD(HFSIOC_GET_VERY_LOW_DISK)

#define	HFSIOC_GET_LOW_DISK	_IOR('h', 28, u_int32_t)
#define	HFS_FSCTL_GET_LOW_DISK	IOCBASECMD(HFSIOC_GET_LOW_DISK)

#define	HFSIOC_GET_DESIRED_DISK	_IOR('h', 29, u_int32_t)
#define	HFS_FSCTL_GET_DESIRED_DISK	IOCBASECMD(HFSIOC_GET_DESIRED_DISK)

/* 30 was HFSIOC_GET_WRITE_GEN_COUNTER and is now deprecated */

/* 31 was HFSIOC_GET_DOCUMENT_ID and is now deprecated */

/* revisiond only uses this when something transforms in a way the kernel can't track such as "foo.rtf" -> "foo.rtfd" */
#define HFSIOC_TRANSFER_DOCUMENT_ID  _IOW('h', 32, u_int32_t)
#define HFS_TRANSFER_DOCUMENT_ID  IOCBASECMD(HFSIOC_TRANSFER_DOCUMENT_ID)


/* 
 * XXX: Will be deprecated and replaced by HFSIOC_GET_FSINFO
 *
 * Get information about number of file system allocation blocks used by metadata 
 * files on the volume, including individual btrees and journal file.  The caller 
 * can determine the size of file system allocation block using value returned as 
 * f_bsize by statfs(2).
 */
#define HFSIOC_FSINFO_METADATA_BLOCKS  _IOWR('h', 38, struct hfsinfo_metadata)
#define HFS_FSINFO_METADATA_BLOCKS     IOCBASECMD(HFSIOC_FSINFO_METADATA_BLOCKS)

/* Send TRIMs for all free blocks to the underlying device */
#define HFSIOC_CS_FREESPACE_TRIM _IOWR('h', 39, u_int32_t)
#define HFS_CS_FREESPACE_TRIM    IOCBASECMD(HFSIOC_CS_FREESPACE_TRIM)

/* Get file system information for the given volume */
#define HFSIOC_GET_FSINFO        _IOWR('h', 45, hfs_fsinfo)
#define HFS_GET_FSINFO           IOCBASECMD(HFSIOC_GET_FSINFO)

#endif /* __APPLE_API_UNSTABLE */

#endif /* ! _HFS_FSCTL_H_ */
