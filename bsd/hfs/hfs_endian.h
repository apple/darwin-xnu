/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#ifndef __HFS_ENDIAN_H__
#define __HFS_ENDIAN_H__

#include <sys/appleapiopts.h>

#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
/*
 * hfs_endian.h
 *
 * This file prototypes endian swapping routines for the HFS/HFS Plus
 * volume format.
 */
#include "hfs.h"
#include "hfscommon/headers/BTreesInternal.h"
#include <libkern/OSByteOrder.h>

/*********************/
/* BIG ENDIAN Macros */
/*********************/
#define SWAP_BE16(__a) 							OSSwapBigToHostInt16 (__a)
#define SWAP_BE32(__a) 							OSSwapBigToHostInt32 (__a)
#define SWAP_BE64(__a) 							OSSwapBigToHostInt64 (__a)

#if BYTE_ORDER == BIG_ENDIAN
    
    /* HFS is always big endian, no swapping needed */
    #define SWAP_HFS_PLUS_FORK_DATA(__a)

/************************/
/* LITTLE ENDIAN Macros */
/************************/
#elif BYTE_ORDER == LITTLE_ENDIAN

    #define SWAP_HFS_PLUS_FORK_DATA(__a)			hfs_swap_HFSPlusForkData ((__a))

#else
#warning Unknown byte order
#error
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants for the "unswap" argument to hfs_swap_BTNode:
 */
enum HFSBTSwapDirection {
	kSwapBTNodeBigToHost		=	0,
	kSwapBTNodeHostToBig		=	1,

	/*
	 * kSwapBTNodeHeaderRecordOnly is used to swap just the header record
	 * of a header node from big endian (on disk) to host endian (in memory).
	 * It does not swap the node descriptor (forward/backward links, record
	 * count, etc.).  It assumes the header record is at offset 0x000E.
	 *
	 * Since HFS Plus doesn't have fixed B-tree node sizes, we have to read
	 * the header record to determine the actual node size for that tree
	 * before we can set up the B-tree control block.  We read it initially
	 * as 512 bytes, then re-read it once we know the correct node size.  Since
	 * we may not have read the entire header node the first time, we can't
	 * swap the record offsets, other records, or do most sanity checks.
	 */
	kSwapBTNodeHeaderRecordOnly	=	3
};

int  hfs_swap_BTNode (BlockDescriptor *src, vnode_t vp, enum HFSBTSwapDirection direction);

#ifdef __cplusplus
}
#endif

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* __HFS_FORMAT__ */
