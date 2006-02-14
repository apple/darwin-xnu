/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#ifndef _HFS_FSCTL_H_
#define _HFS_FSCTL_H_

#include <sys/appleapiopts.h>

#include <sys/ioccom.h>
#include <sys/time.h>


#ifdef __APPLE_API_UNSTABLE

struct hfs_backingstoreinfo {
	int  signature;   /* == 3419115 */
	int  version;     /* version of this struct (1) */
	int  backingfd;   /* disk image file (on backing fs) */
	int  bandsize;    /* sparse disk image band size */
};


/* HFS FS CONTROL COMMANDS */

#define HFSIOC_RESIZE_VOLUME  _IOW('h', 2, u_int64_t)
#define HFS_RESIZE_VOLUME  IOCBASECMD(HFSIOC_RESIZE_VOLUME)

#define HFSIOC_CHANGE_NEXT_ALLOCATION  _IOWR('h', 3, u_int32_t)
#define HFS_CHANGE_NEXT_ALLOCATION  IOCBASECMD(HFSIOC_CHANGE_NEXT_ALLOCATION)

#define HFSIOC_GETCREATETIME  _IOR('h', 4, time_t)
#define HFS_GETCREATETIME  IOCBASECMD(HFSIOC_GETCREATETIME)

#define HFSIOC_SETBACKINGSTOREINFO  _IOW('h', 7, struct hfs_backingstoreinfo)
#define HFS_SETBACKINGSTOREINFO  IOCBASECMD(HFSIOC_SETBACKINGSTOREINFO)

#define HFSIOC_CLRBACKINGSTOREINFO  _IO('h', 8)
#define HFS_CLRBACKINGSTOREINFO  IOCBASECMD(HFSIOC_CLRBACKINGSTOREINFO)

#define HFSIOC_SETACLSTATE  _IOW('h', 10, int32_t)
#define HFS_SETACLSTATE  IOCBASECMD(HFSIOC_SETACLSTATE)

#endif /* __APPLE_API_UNSTABLE */


#endif /* ! _HFS_FSCTL_H_ */
