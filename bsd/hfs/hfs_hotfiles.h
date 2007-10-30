/*
 * Copyright (c) 2003, 2005 Apple Computer, Inc. All rights reserved.
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
#ifndef __HFS_HOTFILES__
#define __HFS_HOTFILES__

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE


#define HFC_FILENAME	".hotfiles.btree"


/*
 * Temperature measurement constraints.
 */
#define HFC_DEFAULT_FILE_COUNT	 1000
#define HFC_DEFAULT_DURATION   	 (3600 * 60)
#define HFC_CUMULATIVE_CYCLES	 3
#define HFC_MAXIMUM_FILE_COUNT	 5000
#define HFC_MAXIMUM_FILESIZE	 (10 * 1024 * 1024)
#define HFC_MINIMUM_TEMPERATURE  24


/*
 * Sync constraints.
 */
#define HFC_BLKSPERSYNC    300
#define HFC_FILESPERSYNC   50


/*
 * Hot file clustering stages.
 */
enum hfc_stage {
	HFC_DISABLED,
	HFC_IDLE,
	HFC_BUSY,
	HFC_RECORDING,
	HFC_EVALUATION,
	HFC_EVICTION,
	HFC_ADOPTION,
};


/* 
 * B-tree file key format (on-disk).
 */
struct HotFileKey {
	u_int16_t 	keyLength;	/* length of key, excluding this field */
	u_int8_t 	forkType;	/* 0 = data fork, FF = resource fork */
	u_int8_t 	pad;		/* make the other fields align on 32-bit boundary */
	u_int32_t 	temperature;	/* temperature recorded */
	u_int32_t 	fileID;		/* file ID */
};
typedef struct HotFileKey HotFileKey;

#define HFC_LOOKUPTAG   0xFFFFFFFF
#define HFC_KEYLENGTH	(sizeof(HotFileKey) - sizeof(u_int16_t))

/* 
 * B-tree header node user info (on-disk).
 */
struct HotFilesInfo {
	u_int32_t	magic;
	u_int32_t	version;
	u_int32_t	duration;    /* duration of sample period (secs) */
	u_int32_t	timebase;    /* start of recording period (GMT time in secs) */
	u_int32_t	timeleft;    /* time remaining in recording period (secs) */
	u_int32_t	threshold;
	u_int32_t	maxfileblks;
	u_int32_t	maxfilecnt;
	u_int8_t	tag[32];
};
typedef struct HotFilesInfo HotFilesInfo;

#define HFC_MAGIC	0xFF28FF26
#define HFC_VERSION	1


struct hfsmount;
struct proc;
struct vnode;

/*
 * Hot File interface functions.
 */
int  hfs_hotfilesync (struct hfsmount *, vfs_context_t ctx);

int  hfs_recording_init(struct hfsmount *);
int  hfs_recording_suspend (struct hfsmount *);

int  hfs_addhotfile (struct vnode *);
int  hfs_removehotfile (struct vnode *);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* __HFS_HOTFILES__ */
