/*
 * Copyright (c) 1998-2002 Apple Computer, Inc. All rights reserved.
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

#ifndef	_SYS_DISK_H_
#define	_SYS_DISK_H_

#include <sys/ioctl.h>
#include <sys/types.h>

typedef struct
{
    char path[128];
} dk_firmware_path_t;

#define DKIOCEJECT                   _IO('d', 21)
#define DKIOCSYNCHRONIZECACHE        _IO('d', 22)

#define DKIOCGETBLOCKSIZE            _IOR('d', 24, u_int32_t)
#define DKIOCGETBLOCKCOUNT           _IOR('d', 25, u_int64_t)
#define DKIOCGETBLOCKCOUNT32         _IOR('d', 25, u_int32_t)
#define DKIOCGETFIRMWAREPATH         _IOR('d', 28, dk_firmware_path_t)

#define DKIOCISFORMATTED             _IOR('d', 23, u_int32_t)
#define DKIOCISWRITABLE              _IOR('d', 29, u_int32_t)

#define DKIOCGETMAXBLOCKCOUNTREAD    _IOR('d', 64, u_int64_t)
#define DKIOCGETMAXBLOCKCOUNTWRITE   _IOR('d', 65, u_int64_t)
#define DKIOCGETMAXBYTECOUNTREAD         _IOR('d', 70, u_int64_t)
#define DKIOCGETMAXBYTECOUNTWRITE        _IOR('d', 71, u_int64_t)
#define DKIOCGETMAXSEGMENTCOUNTREAD  _IOR('d', 66, u_int64_t)
#define DKIOCGETMAXSEGMENTCOUNTWRITE _IOR('d', 67, u_int64_t)
#define DKIOCGETMAXSEGMENTBYTECOUNTREAD  _IOR('d', 68, u_int64_t)
#define DKIOCGETMAXSEGMENTBYTECOUNTWRITE _IOR('d', 69, u_int64_t)

#ifdef KERNEL
#define DKIOCSETBLOCKSIZE            _IOW('d', 24, u_int32_t)
#endif /* KERNEL */

#endif	/* _SYS_DISK_H_ */
