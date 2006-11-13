/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#ifndef __VOLFS_VOLFS_H__
#define __VOLFS_VOLFS_H__

#include  <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
struct volfs_mntdata
{
	struct vnode *volfs_rootvp;
};

/*
 * Volfs vnodes exist only for the root, which allows for the enumeration
 * of all volfs accessible filesystems, and for the filesystems which
 * volfs handles.
 */
#define VOLFS_ROOT	1	/* This volfs vnode represents root of volfs */
#define	VOLFS_FSNODE	2	/* This volfs vnode represents a file system */

struct volfs_vndata
{
	int		vnode_type;
	unsigned int	nodeID;	/* the dev entry of a file system */
	struct mount *	fs_mount;
	fsid_t	fs_fsid;
};

#define MAXVLFSNAMLEN	24	/* max length is really 10, pad to 24 since
				 * some of the math depends on VLFSDIRENTLEN
				 * being a power of 2 */
#define VLFSDIRENTLEN	(MAXVLFSNAMLEN + sizeof(u_int32_t) + sizeof(u_int16_t) + sizeof(u_int8_t) + sizeof(u_int8_t))

#define ROOT_DIRID	2

#define MAXPLCENTRIES 250
#define PLCHASHSIZE 128


#define VTOVL(VP) ((struct volfs_vndata *)((VP)->v_data))

#define PRINTIT kprintf


#endif /* __APPLE_API_PRIVATE */
#endif /* __VOLFS_VOLFS_H__ */
