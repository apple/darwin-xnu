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
#include <architecture/byte_order.h>

/*********************/
/* BIG ENDIAN Macros */
/*********************/
#if BYTE_ORDER == BIG_ENDIAN

    /* HFS is always big endian, make swaps into no-ops */
    #define SWAP_BE16(__a) (__a)
    #define SWAP_BE32(__a) (__a)
    #define SWAP_BE64(__a) (__a)
    
    /* HFS is always big endian, no swapping needed */
    #define SWAP_HFS_PLUS_FORK_DATA(__a)
    #define SWAP_BT_NODE(__a, __b, __c, __d)

/************************/
/* LITTLE ENDIAN Macros */
/************************/
#elif BYTE_ORDER == LITTLE_ENDIAN

    /* HFS is always big endian, make swaps actually swap */
    #define SWAP_BE16(__a) 							NXSwapBigShortToHost (__a)
    #define SWAP_BE32(__a) 							NXSwapBigLongToHost (__a)
    #define SWAP_BE64(__a) 							NXSwapBigLongLongToHost (__a)
    
    #define SWAP_HFS_PLUS_FORK_DATA(__a)			hfs_swap_HFSPlusForkData ((__a))
    #define SWAP_BT_NODE(__a, __b, __c, __d)	hfs_swap_BTNode ((__a), (__b), (__c), (__d))

#else
#warning Unknown byte order
#error
#endif

#ifdef __cplusplus
extern "C" {
#endif

void hfs_swap_HFSPlusForkData (HFSPlusForkData *src);
int  hfs_swap_BTNode (BlockDescriptor *src, int isHFSPlus, HFSCatalogNodeID fileID, int unswap);

#ifdef __cplusplus
}
#endif

#endif /* __APPLE_API_PRIVATE */
#endif /* KERNEL */
#endif /* __HFS_FORMAT__ */
