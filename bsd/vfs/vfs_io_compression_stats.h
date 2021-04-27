/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#ifndef _MISCFS_SPECFS_IO_COMPRESSION_STATS_H_
#define _MISCFS_SPECFS_IO_COMPRESSION_STATS_H_

#include <sys/buf_internal.h>
#include <sys/vnode.h>

void io_compression_stats_init(void);
void io_compression_stats(buf_t bp);

#define IO_COMPRESSION_STATS_DEFAULT_BLOCK_SIZE (4 * 1024)
#define IO_COMPRESSION_STATS_MIN_BLOCK_SIZE (4 * 1024)
#define IO_COMPRESSION_STATS_MAX_BLOCK_SIZE (1024 * 1024 * 1024)

#if IO_COMPRESSION_STATS_DEBUG
#define io_compression_stats_dbg(fmt, ...) \
	printf("%s: " fmt "\n", __func__, ## __VA_ARGS__)
#else
#define io_compression_stats_dbg(fmt, ...)
#endif

/* iocs_store_buffer: Buffer that captures the stats of vnode being reclaimed */
struct iocs_store_buffer {
	void*                   buffer;
	uint32_t                current_position;
	uint32_t                marked_point;
};

#define IOCS_STORE_BUFFER_NUM_SLOTS 10000
#define IOCS_STORE_BUFFER_SIZE (IOCS_STORE_BUFFER_NUM_SLOTS * (sizeof(struct iocs_store_buffer_entry)))

/* Notify user when the buffer is 80% full */
#define IOCS_STORE_BUFFER_NOTIFY_AT ((IOCS_STORE_BUFFER_SIZE * 8) / 10)

/* Wait for the buffer to be 10% more full before notifying again */
#define IOCS_STORE_BUFFER_NOTIFICATION_INTERVAL (IOCS_STORE_BUFFER_SIZE / 10)

#endif
