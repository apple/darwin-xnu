/*
 * Copyright (c) 2004-2005 Apple Computer, Inc. All rights reserved.
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

#ifndef _SYS_XATTR_H_
#define _SYS_XATTR_H_

#include <sys/types.h>

/* Options for pathname based xattr calls */
#define XATTR_NOFOLLOW   0x0001     /* Don't follow symbolic links */

/* Options for setxattr calls */
#define XATTR_CREATE     0x0002     /* set the value, fail if attr already exists */
#define XATTR_REPLACE    0x0004     /* set the value, fail if attr does not exist */

/* Set this to bypass authorization checking (eg. if doing auth-related work) */
#define XATTR_NOSECURITY 0x0008

#define	XATTR_MAXNAMELEN   127

#define	XATTR_FINDERINFO_NAME	  "com.apple.FinderInfo"

#define	XATTR_RESOURCEFORK_NAME	  "com.apple.ResourceFork"


#ifdef KERNEL
__BEGIN_DECLS
int  xattr_protected(const char *);
int  xattr_validatename(const char *);
__END_DECLS
#endif /* KERNEL */

#ifndef KERNEL
__BEGIN_DECLS

ssize_t getxattr(const char *path, const char *name, void *value, size_t size, u_int32_t position, int options);

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size, u_int32_t position, int options);

int setxattr(const char *path, const char *name, const void *value, size_t size, u_int32_t position, int options);

int fsetxattr(int fd, const char *name, const void *value, size_t size, u_int32_t position, int options);

int removexattr(const char *path, const char *name, int options);

int fremovexattr(int fd, const char *name, int options);

ssize_t listxattr(const char *path, char *namebuff, size_t size, int options);
 
ssize_t flistxattr(int fd, char *namebuff, size_t size, int options);

__END_DECLS
#endif /* KERNEL */

#endif /* _SYS_XATTR_H_ */
