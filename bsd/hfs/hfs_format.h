/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#ifndef __HFS_FORMAT__
#define __HFS_FORMAT__

#include <sys/appleapiopts.h>

/*
 * hfs_format.c
 *
 * This file describes the on-disk format for HFS and HFS Plus volumes.
 * The HFS Plus volume format is desciibed in detail in Apple Technote 1150.
 *
 * http://developer.apple.com/technotes/tn/tn1150.html
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/* some on-disk hfs structures have 68K alignment (misaligned) */
#pragma options align=mac68k

/* Signatures used to differentiate between HFS and HFS Plus volumes */
enum {
	kHFSSigWord		= 0x4244,	/* 'BD' in ASCII */
	kHFSPlusSigWord		= 0x482B,	/* 'H+' in ASCII */
	kHFSJSigWord		= 0x484a,	/* 'HJ' in ASCII */
	kHFSPlusVersion		= 0x0004,	/* will change as format changes */
						/* version 4 shipped with Mac OS 8.1 */
	kHFSPlusMountVersion	= 0x31302E30,	/* '10.0' for Mac OS X */
	kHFSJMountVersion	= 0x4846534a	/* 'HFSJ' for journaled HFS+ on OS X */
};


#ifdef __APPLE_API_PRIVATE
/*
 * Mac OS X has a special directory for linked and unlinked files (HFS Plus only).
 * This directory and its contents are never exported from the filesystem under
 * Mac OS X.
 *
 * To make this folder name sort last,  it has embedded null prefix.
 * (0xC0, 0x80 in UTF-8)
 */
#define HFSPLUSMETADATAFOLDER  "\xC0\x80\xC0\x80\xC0\x80\xC0\x80HFS+ Private Data"

/*
 * Files in the HFS Private Data folder have one of the following prefixes
 * followed by a decimal number (no leading zeros).  For indirect nodes this
 * number is a 32 bit random number.  For unlinked (deleted) files that are
 * still open, the number is the file ID for that file.
 *
 * e.g.  iNode7182000 and temp3296
 */
#define HFS_INODE_PREFIX	"iNode"
#define HFS_DELETE_PREFIX	"temp"

#endif /* __APPLE_API_PRIVATE */

/*
 * Indirect link files (hard links) have the following type/creator.
 */
enum {
	kHardLinkFileType = 0x686C6E6B,  /* 'hlnk' */
	kHFSPlusCreator   = 0x6866732B   /* 'hfs+' */
};


/* Unicode strings are used for HFS Plus file and folder names */
struct HFSUniStr255 {
	u_int16_t	length;		/* number of unicode characters */
	u_int16_t	unicode[255];	/* unicode characters */
};
typedef struct HFSUniStr255 HFSUniStr255;
typedef const HFSUniStr255 *ConstHFSUniStr255Param;

enum {
	kHFSMaxVolumeNameChars		= 27,
	kHFSMaxFileNameChars		= 31,
	kHFSPlusMaxFileNameChars	= 255
};


/* Extent overflow file data structures */

/* HFS Extent key */
struct HFSExtentKey {
	u_int8_t 	keyLength;	/* length of key, excluding this field */
	u_int8_t 	forkType;	/* 0 = data fork, FF = resource fork */
	u_int32_t 	fileID;		/* file ID */
	u_int16_t 	startBlock;	/* first file allocation block number in this extent */
};
typedef struct HFSExtentKey HFSExtentKey;

/* HFS Plus Extent key */
struct HFSPlusExtentKey {
	u_int16_t 	keyLength;		/* length of key, excluding this field */
	u_int8_t 	forkType;		/* 0 = data fork, FF = resource fork */
	u_int8_t 	pad;			/* make the other fields align on 32-bit boundary */
	u_int32_t 	fileID;			/* file ID */
	u_int32_t 	startBlock;		/* first file allocation block number in this extent */
};
typedef struct HFSPlusExtentKey HFSPlusExtentKey;

/* Number of extent descriptors per extent record */
enum {
	kHFSExtentDensity	= 3,
	kHFSPlusExtentDensity	= 8
};

/* HFS extent descriptor */
struct HFSExtentDescriptor {
	u_int16_t 	startBlock;		/* first allocation block */
	u_int16_t 	blockCount;		/* number of allocation blocks */
};
typedef struct HFSExtentDescriptor HFSExtentDescriptor;

/* HFS Plus extent descriptor */
struct HFSPlusExtentDescriptor {
	u_int32_t 	startBlock;		/* first allocation block */
	u_int32_t 	blockCount;		/* number of allocation blocks */
};
typedef struct HFSPlusExtentDescriptor HFSPlusExtentDescriptor;

/* HFS extent record */
typedef HFSExtentDescriptor HFSExtentRecord[3];

/* HFS Plus extent record */
typedef HFSPlusExtentDescriptor HFSPlusExtentRecord[8];


/* Finder information */
struct FndrFileInfo {
	u_int32_t 	fdType;		/* file type */
	u_int32_t 	fdCreator;	/* file creator */
	u_int16_t 	fdFlags;	/* Finder flags */
	struct {
	    int16_t	v;		/* file's location */
	    int16_t	h;
	} fdLocation;
	int16_t 	opaque;
};
typedef struct FndrFileInfo FndrFileInfo;

struct FndrDirInfo {
	struct {			/* folder's window rectangle */
	    int16_t	top;
	    int16_t	left;
	    int16_t	bottom;
	    int16_t	right;
	} frRect;
	unsigned short 	frFlags;	/* Finder flags */
	struct {
	    u_int16_t	v;		/* folder's location */
	    u_int16_t	h;
	} frLocation;
	int16_t 	opaque;
};
typedef struct FndrDirInfo FndrDirInfo;

struct FndrOpaqueInfo {
	int8_t opaque[16];
};
typedef struct FndrOpaqueInfo FndrOpaqueInfo;


/* HFS Plus Fork data info - 80 bytes */
struct HFSPlusForkData {
	u_int64_t 		logicalSize;	/* fork's logical size in bytes */
	u_int32_t 		clumpSize;	/* fork's clump size in bytes */
	u_int32_t 		totalBlocks;	/* total blocks used by this fork */
	HFSPlusExtentRecord 	extents;	/* initial set of extents */
};
typedef struct HFSPlusForkData HFSPlusForkData;


/* Mac OS X has 16 bytes worth of "BSD" info.
 *
 * Note:  Mac OS 9 implementations and applications
 * should preserve, but not change, this information.
 */
struct HFSPlusBSDInfo {
	u_int32_t 	ownerID;	/* user or group ID of file/folder owner */
	u_int32_t 	groupID;	/* additional user of group ID */
	u_int8_t 	adminFlags;	/* super-user changeable flags */
	u_int8_t 	ownerFlags;	/* owner changeable flags */
	u_int16_t 	fileMode;	/* file type and permission bits */
	union {
	    u_int32_t	iNodeNum;	/* indirect node number (hard links only) */
	    u_int32_t	linkCount;	/* links that refer to this indirect node */
	    u_int32_t	rawDevice;	/* special file device (FBLK and FCHR only) */
	} special;
};
typedef struct HFSPlusBSDInfo HFSPlusBSDInfo;


/* Catalog file data structures */

enum {
	kHFSRootParentID		= 1,	/* Parent ID of the root folder */
	kHFSRootFolderID		= 2,	/* Folder ID of the root folder */
	kHFSExtentsFileID		= 3,	/* File ID of the extents file */
	kHFSCatalogFileID		= 4,	/* File ID of the catalog file */
	kHFSBadBlockFileID		= 5,	/* File ID of the bad allocation block file */
	kHFSAllocationFileID		= 6,	/* File ID of the allocation file (HFS Plus only) */
	kHFSStartupFileID		= 7,	/* File ID of the startup file (HFS Plus only) */
	kHFSAttributesFileID		= 8,	/* File ID of the attribute file (HFS Plus only) */
	kHFSBogusExtentFileID		= 15,	/* Used for exchanging extents in extents file */
	kHFSFirstUserCatalogNodeID	= 16
};

/* HFS catalog key */
struct HFSCatalogKey {
	u_int8_t 	keyLength;		/* key length (in bytes) */
	u_int8_t 	reserved;		/* reserved (set to zero) */
	u_int32_t 	parentID;		/* parent folder ID */
	u_char 		nodeName[kHFSMaxFileNameChars + 1]; /* catalog node name */
};
typedef struct HFSCatalogKey HFSCatalogKey;

/* HFS Plus catalog key */
struct HFSPlusCatalogKey {
	u_int16_t 		keyLength;	/* key length (in bytes) */
	u_int32_t 		parentID;	/* parent folder ID */
	HFSUniStr255 		nodeName;	/* catalog node name */
};
typedef struct HFSPlusCatalogKey HFSPlusCatalogKey;

/* Catalog record types */
enum {
	/* HFS Catalog Records */
	kHFSFolderRecord		= 0x0100,	/* Folder record */
	kHFSFileRecord			= 0x0200,	/* File record */
	kHFSFolderThreadRecord		= 0x0300,	/* Folder thread record */
	kHFSFileThreadRecord		= 0x0400,	/* File thread record */

	/* HFS Plus Catalog Records */
	kHFSPlusFolderRecord		= 1,		/* Folder record */
	kHFSPlusFileRecord		= 2,		/* File record */
	kHFSPlusFolderThreadRecord	= 3,		/* Folder thread record */
	kHFSPlusFileThreadRecord	= 4		/* File thread record */
};


/* Catalog file record flags */
enum {
	kHFSFileLockedBit	= 0x0000,	/* file is locked and cannot be written to */
	kHFSFileLockedMask	= 0x0001,
	kHFSThreadExistsBit	= 0x0001,	/* a file thread record exists for this file */
	kHFSThreadExistsMask	= 0x0002
};


/* HFS catalog folder record - 70 bytes */
struct HFSCatalogFolder {
	int16_t 		recordType;		/* == kHFSFolderRecord */
	u_int16_t 		flags;			/* folder flags */
	u_int16_t 		valence;		/* folder valence */
	u_int32_t		folderID;		/* folder ID */
	u_int32_t 		createDate;		/* date and time of creation */
	u_int32_t 		modifyDate;		/* date and time of last modification */
	u_int32_t 		backupDate;		/* date and time of last backup */
	FndrDirInfo 		userInfo;		/* Finder information */
	FndrOpaqueInfo		finderInfo;		/* additional Finder information */
	u_int32_t 		reserved[4];		/* reserved - initialized as zero */
};
typedef struct HFSCatalogFolder HFSCatalogFolder;

/* HFS Plus catalog folder record - 88 bytes */
struct HFSPlusCatalogFolder {
	int16_t 		recordType;		/* == kHFSPlusFolderRecord */
	u_int16_t 		flags;			/* file flags */
	u_int32_t 		valence;		/* folder's valence (limited to 2^16 in Mac OS) */
	u_int32_t 		folderID;		/* folder ID */
	u_int32_t 		createDate;		/* date and time of creation */
	u_int32_t 		contentModDate;		/* date and time of last content modification */
	u_int32_t 		attributeModDate;	/* date and time of last attribute modification */
	u_int32_t 		accessDate;		/* date and time of last access (MacOS X only) */
	u_int32_t 		backupDate;		/* date and time of last backup */
	HFSPlusBSDInfo		bsdInfo;		/* permissions (for MacOS X) */
	FndrDirInfo 		userInfo;		/* Finder information */
	FndrOpaqueInfo	 	finderInfo;		/* additional Finder information */
	u_int32_t 		textEncoding;		/* hint for name conversions */
	u_int32_t 		reserved;		/* reserved - initialized as zero */
};
typedef struct HFSPlusCatalogFolder HFSPlusCatalogFolder;

/* HFS catalog file record - 102 bytes */
struct HFSCatalogFile {
	int16_t 		recordType;		/* == kHFSFileRecord */
	u_int8_t 		flags;			/* file flags */
	int8_t 			fileType;		/* file type (unused ?) */
	FndrFileInfo 		userInfo;		/* Finder information */
	u_int32_t 		fileID;			/* file ID */
	u_int16_t 		dataStartBlock;		/* not used - set to zero */
	int32_t 		dataLogicalSize;	/* logical EOF of data fork */
	int32_t 		dataPhysicalSize;	/* physical EOF of data fork */
	u_int16_t		rsrcStartBlock;		/* not used - set to zero */
	int32_t			rsrcLogicalSize;	/* logical EOF of resource fork */
	int32_t			rsrcPhysicalSize;	/* physical EOF of resource fork */
	u_int32_t		createDate;		/* date and time of creation */
	u_int32_t		modifyDate;		/* date and time of last modification */
	u_int32_t		backupDate;		/* date and time of last backup */
	FndrOpaqueInfo		finderInfo;		/* additional Finder information */
	u_int16_t		clumpSize;		/* file clump size (not used) */
	HFSExtentRecord		dataExtents;		/* first data fork extent record */
	HFSExtentRecord		rsrcExtents;		/* first resource fork extent record */
	u_int32_t		reserved;		/* reserved - initialized as zero */
};
typedef struct HFSCatalogFile HFSCatalogFile;

/* HFS Plus catalog file record - 248 bytes */
struct HFSPlusCatalogFile {
	int16_t 		recordType;		/* == kHFSPlusFileRecord */
	u_int16_t 		flags;			/* file flags */
	u_int32_t 		reserved1;		/* reserved - initialized as zero */
	u_int32_t 		fileID;			/* file ID */
	u_int32_t 		createDate;		/* date and time of creation */
	u_int32_t 		contentModDate;		/* date and time of last content modification */
	u_int32_t 		attributeModDate;	/* date and time of last attribute modification */
	u_int32_t 		accessDate;		/* date and time of last access (MacOS X only) */
	u_int32_t 		backupDate;		/* date and time of last backup */
	HFSPlusBSDInfo 		bsdInfo;		/* permissions (for MacOS X) */
	FndrFileInfo 		userInfo;		/* Finder information */
	FndrOpaqueInfo	 	finderInfo;		/* additional Finder information */
	u_int32_t 		textEncoding;		/* hint for name conversions */
	u_int32_t 		reserved2;		/* reserved - initialized as zero */

	/* Note: these start on double long (64 bit) boundry */
	HFSPlusForkData 	dataFork;		/* size and block data for data fork */
	HFSPlusForkData 	resourceFork;		/* size and block data for resource fork */
};
typedef struct HFSPlusCatalogFile HFSPlusCatalogFile;

/* HFS catalog thread record - 46 bytes */
struct HFSCatalogThread {
	int16_t 	recordType;		/* == kHFSFolderThreadRecord or kHFSFileThreadRecord */
	int32_t 	reserved[2];		/* reserved - initialized as zero */
	u_int32_t 	parentID;		/* parent ID for this catalog node */
	u_char 		nodeName[kHFSMaxFileNameChars + 1]; /* name of this catalog node */
};
typedef struct HFSCatalogThread HFSCatalogThread;

/* HFS Plus catalog thread record -- 264 bytes */
struct HFSPlusCatalogThread {
	int16_t 	recordType;		/* == kHFSPlusFolderThreadRecord or kHFSPlusFileThreadRecord */
	int16_t 	reserved;		/* reserved - initialized as zero */
	u_int32_t 	parentID;		/* parent ID for this catalog node */
	HFSUniStr255 	nodeName;		/* name of this catalog node (variable length) */
};
typedef struct HFSPlusCatalogThread HFSPlusCatalogThread;

#ifdef __APPLE_API_UNSTABLE
/*
  	These are the types of records in the attribute B-tree.  The values were
  	chosen so that they wouldn't conflict with the catalog record types.
*/
enum {
	kHFSPlusAttrInlineData	= 0x10,		/* if size <  kAttrOverflowSize */
	kHFSPlusAttrForkData	= 0x20,		/* if size >= kAttrOverflowSize */
	kHFSPlusAttrExtents	= 0x30		/* overflow extents for large attributes */
};


/*
  	HFSPlusAttrInlineData
  	For small attributes, whose entire value is stored within this one
  	B-tree record.
  	There would not be any other records for this attribute.
*/
struct HFSPlusAttrInlineData {
	u_int32_t 	recordType;		/* == kHFSPlusAttrInlineData*/
	u_int32_t 	reserved;
	u_int32_t 	logicalSize;		/* size in bytes of userData*/
	u_int8_t 	userData[2];		/* variable length; space allocated is a multiple of 2 bytes*/
};
typedef struct HFSPlusAttrInlineData HFSPlusAttrInlineData;


/*
  	HFSPlusAttrForkData
  	For larger attributes, whose value is stored in allocation blocks.
  	If the attribute has more than 8 extents, there will be additonal
  	records (of type HFSPlusAttrExtents) for this attribute.
*/
struct HFSPlusAttrForkData {
	u_int32_t 	recordType;		/* == kHFSPlusAttrForkData*/
	u_int32_t 	reserved;
	HFSPlusForkData theFork;		/* size and first extents of value*/
};
typedef struct HFSPlusAttrForkData HFSPlusAttrForkData;

/*
  	HFSPlusAttrExtents
  	This record contains information about overflow extents for large,
  	fragmented attributes.
*/
struct HFSPlusAttrExtents {
	u_int32_t 		recordType;	/* == kHFSPlusAttrExtents*/
	u_int32_t 		reserved;
	HFSPlusExtentRecord	extents;	/* additional extents*/
};
typedef struct HFSPlusAttrExtents HFSPlusAttrExtents;

/*	A generic Attribute Record*/
union HFSPlusAttrRecord {
	u_int32_t 		recordType;
	HFSPlusAttrInlineData 	inlineData;
	HFSPlusAttrForkData 	forkData;
	HFSPlusAttrExtents 	overflowExtents;
};
typedef union HFSPlusAttrRecord HFSPlusAttrRecord;

/* Key and node lengths */
enum {
	kHFSPlusExtentKeyMaximumLength = sizeof(HFSPlusExtentKey) - sizeof(u_int16_t),
	kHFSExtentKeyMaximumLength	= sizeof(HFSExtentKey) - sizeof(u_int8_t),
	kHFSPlusCatalogKeyMaximumLength = sizeof(HFSPlusCatalogKey) - sizeof(u_int16_t),
	kHFSPlusCatalogKeyMinimumLength = kHFSPlusCatalogKeyMaximumLength - sizeof(HFSUniStr255) + sizeof(u_int16_t),
	kHFSCatalogKeyMaximumLength	= sizeof(HFSCatalogKey) - sizeof(u_int8_t),
	kHFSCatalogKeyMinimumLength	= kHFSCatalogKeyMaximumLength - (kHFSMaxFileNameChars + 1) + sizeof(u_int8_t),
	kHFSPlusCatalogMinNodeSize	= 4096,
	kHFSPlusExtentMinNodeSize	= 512,
	kHFSPlusAttrMinNodeSize		= 4096
};
#endif /* __APPLE_API_UNSTABLE */

/* HFS and HFS Plus volume attribute bits */
enum {
							/* Bits 0-6 are reserved (always cleared by MountVol call) */
	kHFSVolumeHardwareLockBit	= 7,		/* volume is locked by hardware */
	kHFSVolumeUnmountedBit		= 8,		/* volume was successfully unmounted */
	kHFSVolumeSparedBlocksBit	= 9,		/* volume has bad blocks spared */
	kHFSVolumeNoCacheRequiredBit = 10,		/* don't cache volume blocks (i.e. RAM or ROM disk) */
	kHFSBootVolumeInconsistentBit = 11,		/* boot volume is inconsistent (System 7.6 and later) */
	kHFSCatalogNodeIDsReusedBit = 12,
	kHFSVolumeJournaledBit = 13,			/* this volume has a journal on it */
							/* Bit 14 is reserved for future use */
	kHFSVolumeSoftwareLockBit	= 15,		/* volume is locked by software */

	kHFSVolumeHardwareLockMask	= 1 << kHFSVolumeHardwareLockBit,
	kHFSVolumeUnmountedMask		= 1 << kHFSVolumeUnmountedBit,
	kHFSVolumeSparedBlocksMask	= 1 << kHFSVolumeSparedBlocksBit,
	kHFSVolumeNoCacheRequiredMask = 1 << kHFSVolumeNoCacheRequiredBit,
	kHFSBootVolumeInconsistentMask = 1 << kHFSBootVolumeInconsistentBit,
	kHFSCatalogNodeIDsReusedMask = 1 << kHFSCatalogNodeIDsReusedBit,
	kHFSVolumeJournaledMask	= 1 << kHFSVolumeJournaledBit,
	kHFSVolumeSoftwareLockMask	= 1 << kHFSVolumeSoftwareLockBit,
	kHFSMDBAttributesMask		= 0x8380
};


/* HFS Master Directory Block - 162 bytes */
/* Stored at sector #2 (3rd sector) and second-to-last sector. */
struct HFSMasterDirectoryBlock {
	u_int16_t 		drSigWord;	/* == kHFSSigWord */
	u_int32_t 		drCrDate;	/* date and time of volume creation */
	u_int32_t 		drLsMod;	/* date and time of last modification */
	u_int16_t 		drAtrb;		/* volume attributes */
	u_int16_t 		drNmFls;	/* number of files in root folder */
	u_int16_t 		drVBMSt;	/* first block of volume bitmap */
	u_int16_t 		drAllocPtr;	/* start of next allocation search */
	u_int16_t 		drNmAlBlks;	/* number of allocation blocks in volume */
	u_int32_t 		drAlBlkSiz;	/* size (in bytes) of allocation blocks */
	u_int32_t 		drClpSiz;	/* default clump size */
	u_int16_t 		drAlBlSt;	/* first allocation block in volume */
	u_int32_t 		drNxtCNID;	/* next unused catalog node ID */
	u_int16_t 		drFreeBks;	/* number of unused allocation blocks */
	u_char 			drVN[kHFSMaxVolumeNameChars + 1];  /* volume name */
	u_int32_t 		drVolBkUp;	/* date and time of last backup */
	u_int16_t 		drVSeqNum;	/* volume backup sequence number */
	u_int32_t 		drWrCnt;	/* volume write count */
	u_int32_t 		drXTClpSiz;	/* clump size for extents overflow file */
	u_int32_t 		drCTClpSiz;	/* clump size for catalog file */
	u_int16_t 		drNmRtDirs;	/* number of directories in root folder */
	u_int32_t 		drFilCnt;	/* number of files in volume */
	u_int32_t 		drDirCnt;	/* number of directories in volume */
	u_int32_t 		drFndrInfo[8];	/* information used by the Finder */
	u_int16_t 		drEmbedSigWord;	/* embedded volume signature (formerly drVCSize) */
	HFSExtentDescriptor	drEmbedExtent;	/* embedded volume location and size (formerly drVBMCSize and drCtlCSize) */
	u_int32_t		drXTFlSize;	/* size of extents overflow file */
	HFSExtentRecord		drXTExtRec;	/* extent record for extents overflow file */
	u_int32_t 		drCTFlSize;	/* size of catalog file */
	HFSExtentRecord 	drCTExtRec;	/* extent record for catalog file */
};
typedef struct HFSMasterDirectoryBlock	HFSMasterDirectoryBlock;


/* HFS Plus Volume Header - 512 bytes */
/* Stored at sector #2 (3rd sector) and second-to-last sector. */
struct HFSPlusVolumeHeader {
	u_int16_t 	signature;		/* == kHFSPlusSigWord */
	u_int16_t 	version;		/* == kHFSPlusVersion */
	u_int32_t 	attributes;		/* volume attributes */
	u_int32_t 	lastMountedVersion;	/* implementation version which last mounted volume */
//XXXdbg	u_int32_t 	reserved;		/* reserved - initialized as zero */
	u_int32_t 	journalInfoBlock;	/* block addr of journal info (if volume is journaled, zero otherwise) */

	u_int32_t 	createDate;		/* date and time of volume creation */
	u_int32_t 	modifyDate;		/* date and time of last modification */
	u_int32_t 	backupDate;		/* date and time of last backup */
	u_int32_t 	checkedDate;		/* date and time of last disk check */

	u_int32_t 	fileCount;		/* number of files in volume */
	u_int32_t 	folderCount;		/* number of directories in volume */

	u_int32_t 	blockSize;		/* size (in bytes) of allocation blocks */
	u_int32_t 	totalBlocks;		/* number of allocation blocks in volume (includes this header and VBM*/
	u_int32_t 	freeBlocks;		/* number of unused allocation blocks */

	u_int32_t 	nextAllocation;		/* start of next allocation search */
	u_int32_t 	rsrcClumpSize;		/* default resource fork clump size */
	u_int32_t 	dataClumpSize;		/* default data fork clump size */
	u_int32_t 	nextCatalogID;		/* next unused catalog node ID */

	u_int32_t 	writeCount;		/* volume write count */
	u_int64_t 	encodingsBitmap;	/* which encodings have been use  on this volume */

	u_int8_t 	finderInfo[32];		/* information used by the Finder */

	HFSPlusForkData	 allocationFile;	/* allocation bitmap file */
	HFSPlusForkData  extentsFile;		/* extents B-tree file */
	HFSPlusForkData  catalogFile;		/* catalog B-tree file */
	HFSPlusForkData  attributesFile;	/* extended attributes B-tree file */
	HFSPlusForkData	 startupFile;		/* boot file (secondary loader) */
};
typedef struct HFSPlusVolumeHeader HFSPlusVolumeHeader;


/* B-tree structures */

enum BTreeKeyLimits{
	kMaxKeyLength	= 520
};

union BTreeKey{
	u_int8_t	length8;
	u_int16_t	length16;
	u_int8_t	rawData [kMaxKeyLength+2];
};
typedef union BTreeKey BTreeKey;

/* BTNodeDescriptor -- Every B-tree node starts with these fields. */
struct BTNodeDescriptor {
	u_int32_t	fLink;			/* next node at this level*/
	u_int32_t 	bLink;			/* previous node at this level*/
	int8_t 		kind;			/* kind of node (leaf, index, header, map)*/
	u_int8_t 	height;			/* zero for header, map; child is one more than parent*/
	u_int16_t 	numRecords;		/* number of records in this node*/
	u_int16_t 	reserved;		/* reserved - initialized as zero */
};
typedef struct BTNodeDescriptor BTNodeDescriptor;

/* Constants for BTNodeDescriptor kind */
enum {
	kBTLeafNode	= -1,
	kBTIndexNode	= 0,
	kBTHeaderNode	= 1,
	kBTMapNode	= 2
};

/* BTHeaderRec -- The first record of a B-tree header node */
struct BTHeaderRec {
	u_int16_t	treeDepth;		/* maximum height (usually leaf nodes) */
	u_int32_t 	rootNode;		/* node number of root node */
	u_int32_t 	leafRecords;		/* number of leaf records in all leaf nodes */
	u_int32_t 	firstLeafNode;		/* node number of first leaf node */
	u_int32_t 	lastLeafNode;		/* node number of last leaf node */
	u_int16_t 	nodeSize;		/* size of a node, in bytes */
	u_int16_t 	maxKeyLength;		/* reserved */
	u_int32_t 	totalNodes;		/* total number of nodes in tree */
	u_int32_t 	freeNodes;		/* number of unused (free) nodes in tree */
	u_int16_t 	reserved1;		/* unused */
	u_int32_t 	clumpSize;		/* reserved */
	u_int8_t 	btreeType;		/* reserved */
	u_int8_t 	reserved2;		/* reserved */
	u_int32_t 	attributes;		/* persistent attributes about the tree */
	u_int32_t 	reserved3[16];		/* reserved */
};
typedef struct BTHeaderRec BTHeaderRec;

/* Constants for BTHeaderRec attributes */
enum {
	kBTBadCloseMask		 = 0x00000001,	/* reserved */
	kBTBigKeysMask		 = 0x00000002,	/* key length field is 16 bits */
	kBTVariableIndexKeysMask = 0x00000004	/* keys in index nodes are variable length */
};

/* JournalInfoBlock - Structure that describes where our journal lives */
struct JournalInfoBlock {
	u_int32_t	flags;
    	u_int32_t       device_signature[8];  // signature used to locate our device.
	u_int64_t       offset;               // byte offset to the journal on the device
	u_int64_t       size;                 // size in bytes of the journal
	u_int32_t 	reserved[32];
};
typedef struct JournalInfoBlock JournalInfoBlock;

enum {
    kJIJournalInFSMask          = 0x00000001,
    kJIJournalOnOtherDeviceMask = 0x00000002,
    kJIJournalNeedInitMask      = 0x00000004
};


#pragma options align=reset

#ifdef __cplusplus
}
#endif

#endif /* __HFS_FORMAT__ */
