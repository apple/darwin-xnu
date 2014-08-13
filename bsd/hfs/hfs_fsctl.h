/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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

#define HFSIOC_GET_WRITE_GEN_COUNTER  _IOR('h', 30, u_int32_t)
#define HFS_GET_WRITE_GEN_COUNTER  IOCBASECMD(HFSIOC_GET_WRITE_GEN_COUNTER)

/* revisiond uses this to allocate a doc-id for files from Cab and earlier systems that are marked tracked but don't have a doc-id */
#define HFS_DOCUMENT_ID_ALLOCATE	0x1

#define HFSIOC_GET_DOCUMENT_ID  _IOR('h', 31, u_int32_t)
#define HFS_GET_DOCUMENT_ID  IOCBASECMD(HFSIOC_GET_DOCUMENT_ID)

/* revisiond only uses this when something transforms in a way the kernel can't track such as "foo.rtf" -> "foo.rtfd" */
#define HFSIOC_TRANSFER_DOCUMENT_ID  _IOW('h', 32, u_int32_t)
#define HFS_TRANSFER_DOCUMENT_ID  IOCBASECMD(HFSIOC_TRANSFER_DOCUMENT_ID)

#endif /* __APPLE_API_UNSTABLE */

#endif /* ! _HFS_FSCTL_H_ */
