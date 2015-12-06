/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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
#ifndef HFS_KDEBUG_H_
#define HFS_KDEBUG_H_

#include <sys/kdebug.h>

/*
 * KERNEL_DEBUG related definitions for HFS.
 *
 * NOTE: The Class DBG_FSYSTEM = 3, and Subclass DBG_HFS = 8, so these
 * debug codes are of the form 0x0308nnnn.
 */
#define HFSDBG_CODE(code)	FSDBG_CODE(DBG_HFS, code)

enum {
	HFSDBG_WRITE        		= FSDBG_CODE(DBG_FSRW, 0),    /* 0x3010000 */
	HFSDBG_TRUNCATE     		= FSDBG_CODE(DBG_FSRW, 7),    /* 0x301001C */
	HFSDBG_READ         		= FSDBG_CODE(DBG_FSRW, 12),   /* 0x3010030 */
	HFSDBG_GETNEWVNODE  		= FSDBG_CODE(DBG_FSRW, 37),   /* 0x3010094 */
	HFSDBG_UPDATE       		= FSDBG_CODE(DBG_FSRW, 8192), /* 0x3018000 */
	HFSDBG_UNMAP_FREE    		= HFSDBG_CODE(0),	/* 0x03080000 */
	HFSDBG_UNMAP_ALLOC    		= HFSDBG_CODE(1),	/* 0x03080004 */
	HFSDBG_UNMAP_CALLBACK		= HFSDBG_CODE(2),	/* 0x03080008 */
	/* 0x0308000C is unused */
	HFSDBG_BLOCK_ALLOCATE		= HFSDBG_CODE(4),	/* 0x03080010 */
	HFSDBG_BLOCK_DEALLOCATE		= HFSDBG_CODE(5),	/* 0x03080014 */
	HFSDBG_READ_BITMAP_BLOCK	= HFSDBG_CODE(6),	/* 0x03080018 */
	HFSDBG_RELEASE_BITMAP_BLOCK	= HFSDBG_CODE(7),	/* 0x0308001C */
	HFSDBG_FIND_CONTIG_BITMAP	= HFSDBG_CODE(8),	/* 0x03080020 */
	HFSDBG_ALLOC_ANY_BITMAP		= HFSDBG_CODE(9),	/* 0x03080024 */
	HFSDBG_ALLOC_FIND_KNOWN		= HFSDBG_CODE(10),	/* 0x03080028 */
	HFSDBG_MARK_ALLOC_BITMAP	= HFSDBG_CODE(11),	/* 0x0308002C */
	HFSDBG_MARK_FREE_BITMAP		= HFSDBG_CODE(12),	/* 0x03080030 */
	HFSDBG_BLOCK_FIND_CONTIG	= HFSDBG_CODE(13),	/* 0x03080034 */
	HFSDBG_IS_ALLOCATED   		= HFSDBG_CODE(14),	/* 0x03080038 */
	/* 0x0308003C is unused */
	HFSDBG_RESET_EXTENT_CACHE	= HFSDBG_CODE(16),	/* 0x03080040 */
	HFSDBG_REMOVE_EXTENT_CACHE	= HFSDBG_CODE(17),	/* 0x03080044 */
	HFSDBG_ADD_EXTENT_CACHE		= HFSDBG_CODE(18),	/* 0x03080048 */
	HFSDBG_READ_BITMAP_RANGE	= HFSDBG_CODE(19),	/* 0x0308004C */
	HFSDBG_RELEASE_SCAN_BITMAP	= HFSDBG_CODE(20),	/* 0x03080050 */
	HFSDBG_SYNCER        		= HFSDBG_CODE(21),	/* 0x03080054 */
	HFSDBG_SYNCER_TIMED   		= HFSDBG_CODE(22),	/* 0x03080058 */
	HFSDBG_UNMAP_SCAN    		= HFSDBG_CODE(23),	/* 0x0308005C */	
	HFSDBG_UNMAP_SCAN_TRIM   	= HFSDBG_CODE(24),	/* 0x03080060 */
};

/*
    Parameters logged by the above tracepoints: 
---------------------------------------------------------------------------------------------------------------------------------
    CODE    EVENT NAME                  DBG_FUNC_START arg1, arg2, arg3, arg4, arg5 ... DBG_FUNC_END arg1, arg2, arg3, arg4, arg5
                                        DBG_FUNC_NONE  arg1, arg2, arg3, arg4, arg5
---------------------------------------------------------------------------------------------------------------------------------
0x3010000   HFSDBG_WRITE                offset, uio_resid, ff_size, filebytes, 0 ... uio_offset, uio_resid, ff_size, filebytes, 0
                                        offset, uio_resid, ff_size, filebytes, 0
0x301001C   HFSDBG_TRUNCATE             length, ff_size, filebytes, 0, 0 ... length, ff_size, filebytes, retval, 0
                                        length, ff_size, filebytes, 0, 0
0x3010030   HFSDBG_READ                 uio_offset, uio_resid, filesize, filebytes, 0 ... uio_offset, uio_resid, filesize, filebytes, 0 
0x3010094   HFSDBG_GETNEWVNODE          c_vp, c_rsrc_vp, 0, 0, 0 
0x3018000   HFSDBG_UPDATE               vp, tstate, 0, 0, 0 ... vp, tstate, error, 0/-1, 0
    0       HFSDBG_UNMAP_FREE           startBlock, blockCount, 0, 0, 0 ... err, 0, 0, 0, 0
    1       HFSDBG_UNMAP_ALLOC          startBlock, blockCount, 0, 0, 0 ... err, 0, 0, 0, 0
    2       HFSDBG_UNMAP_CALLBACK       0, extentCount, 0, 0, 0 ... 0, 0, 0, 0, 0
    3       unused 
    4       HFSDBG_BLOCK_ALLOCATE       startBlock, minBlocks, maxBlocks, flags, 0 ... err, actualStartBlock, actualBlockCount, 0, 0
    5       HFSDBG_BLOCK_DEALLOCATE     startBlock, blockCount, flags, 0, 0 ... err, 0, 0, 0, 0
    6       HFSDBG_READ_BITMAP_BLOCK    startBlock, 0, 0, 0, 0 ... err, 0, 0, 0, 0
    7       HFSDBG_RELEASE_BITMAP_BLOCK dirty, 0, 0, 0, 0 ... 0, 0, 0, 0, 0
    8       HFSDBG_FIND_CONTIG_BITMAP	startBlock, minBlocks, maxBlocks, useMeta, 0 ... err, actualStartBlock, actualBlockCount, 0, 0
    9       HFSDBG_ALLOC_ANY_BITMAP     startBlock, endBlock,  maxBlocks, useMeta, 0 ... err, actualStartBlock, actualBlockCount, 0, 0
    10      HFSDBG_ALLOC_FIND_KNOWN		0, 0, maxBlocks, 0, 0 ... err, actualStartBlock, actualBlockCount, 0, 0
    11      HFSDBG_MARK_ALLOC_BITMAP    startBlock, blockCount, flags, 0, 0 ... err, 0, 0, 0, 0
    12      HFSDBG_MARK_FREE_BITMAP     startBlock, blockCount, valid, 0, 0 ... err, 0, 0, 0, 0
    13      HFSDBG_BLOCK_FIND_CONTIG    startBlock, endBlock, minBlocks, maxBlocks, 0 ... err, actualStartBlock, actualBlockCount, 0, 0
    14      HFSDBG_IS_ALLOCATED         startBlock, blockCount, stop, 0, 0 ... err, 0, actualBlockCount, 0, 0
    15      unused
    16      HFSDBG_RESET_EXTENT_CACHE   0, 0, 0, 0, 0 ... 0, 0, 0, 0, 0
    17      HFSDBG_REMOVE_EXTENT_CACHE  startBlock, blockCount, vcbFreeExtCnt, 0, 0 ... 0, 0, vcbFreeExtCnt, extentsRemoved, 0
    18      HFSDBG_ADD_EXTENT_CACHE     startBlock, blockCount, vcbFreeExtCnt, 0, 0 ... 0, 0, vcbFreeExtCnt, retval, 0
    19      HFSDBG_READ_BITMAP_RANGE    startBlock, iosize, 0, 0, 0 ... err, 0, 0, 0, 0 
    20      HFSDBG_RELEASE_SCAN_BITMAP  0, 0, 0, 0, 0 ... 0, 0, 0, 0, 0
    21      HFSDBG_SYNCER               hfsmp, now, mnt_last_write_completed_timestamp, mnt_pending_write_size, 0 ... err, deadline, 0, 0, 0
    22      HFSDBG_SYNCER_TIMED         now, last_write_completed, hfs_mp->mnt_last_write_issued_timestamp, mnt_pending_write_size, 0 ... now, mnt_last_write_completed_timestamp, mnt_last_write_issued_timestamp, hfs_mp->mnt_pending_write_size, 0 
    23      HFSDBG_UNMAP_SCAN           hfs_raw_dev, 0, 0, 0, 0 ... hfs_raw_dev, error, 0, 0, 0
    24      HFSDBG_UNMAP_TRIM           hfs_raw_dev, 0, 0, 0, 0 ... hfs_raw_dev, error, 0, 0, 0  
*/

#endif // HFS_KDEBUG_H_
