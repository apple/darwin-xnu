/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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
#ifndef _HFS_BTREEIO_H_
#define _HFS_BTREEIO_H_

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE

#include "hfs.h"
#include "hfscommon/headers/BTreesInternal.h"

/* BTree accessor routines */
extern OSStatus SetBTreeBlockSize(FileReference vp, ByteCount blockSize, 
				ItemCount minBlockCount);

extern OSStatus GetBTreeBlock(FileReference vp, u_int32_t blockNum, 
				GetBlockOptions options, BlockDescriptor *block);

extern OSStatus ReleaseBTreeBlock(FileReference vp, BlockDescPtr blockPtr, 
				ReleaseBlockOptions options);

extern OSStatus ExtendBTreeFile(FileReference vp, FSSize minEOF, FSSize maxEOF);

extern void ModifyBlockStart(FileReference vp, BlockDescPtr blockPtr);

int hfs_create_attr_btree(struct hfsmount *hfsmp, u_int32_t nodesize, u_int32_t nodecnt);

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* ! _HFS_BTREEIO_H_ */
