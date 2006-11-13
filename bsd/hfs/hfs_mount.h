/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1997-2002 Apple Computer, Inc. All Rights Reserved
 *
 */

#ifndef _HFS_MOUNT_H_
#define _HFS_MOUNT_H_

#include <sys/appleapiopts.h>

#include <sys/mount.h>
#include <sys/time.h>

/*
 * Arguments to mount HFS-based filesystems
 */

#define OVERRIDE_UNKNOWN_PERMISSIONS 0

#define UNKNOWNUID ((uid_t)99)
#define UNKNOWNGID ((gid_t)99)
#define UNKNOWNPERMISSIONS (S_IRWXU | S_IROTH | S_IXOTH)		/* 705 */

#ifdef __APPLE_API_UNSTABLE
struct hfs_mount_args {
#ifndef KERNEL
	char	*fspec;			/* block special device to mount */
#endif
	uid_t	hfs_uid;		/* uid that owns hfs files (standard HFS only) */
	gid_t	hfs_gid;		/* gid that owns hfs files (standard HFS only) */
	mode_t	hfs_mask;		/* mask to be applied for hfs perms  (standard HFS only) */
	uint32_t hfs_encoding;		/* encoding for this volume (standard HFS only) */
	struct	timezone hfs_timezone;	/* user time zone info (standard HFS only) */
	int		flags;			/* mounting flags, see below */
	int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
	int		journal_flags;          /* flags to pass to journal_open/create */
	int		journal_disable;        /* don't use journaling (potentially dangerous) */
};

#define HFSFSMNT_NOXONFILES	0x1	/* disable execute permissions for files */
#define HFSFSMNT_WRAPPER	0x2	/* mount HFS wrapper (if it exists) */
#define HFSFSMNT_EXTENDED_ARGS  0x4     /* indicates new fields after "flags" are valid */

/*
 * Sysctl values for HFS
 */
#define HFS_ENCODINGBIAS	1	    /* encoding matching CJK bias */
#define HFS_EXTEND_FS		2
#define HFS_ENCODINGHINT	3	    /* guess encoding for string */
#define HFS_ENABLE_JOURNALING   0x082969
#define HFS_DISABLE_JOURNALING  0x031272
#define HFS_GET_JOURNAL_INFO    0x6a6e6c69
#define HFS_SET_PKG_EXTENSIONS  0x121031

#endif /* __APPLE_API_UNSTABLE */

#endif /* ! _HFS_MOUNT_H_ */
