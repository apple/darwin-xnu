/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef log_mem_h
#define log_mem_h

#include <stddef.h>
#include <stdint.h>

/*
 * A simple allocator on a top of a plain byte array. Primarily intended to
 * support OS kernel logging in order to avoid dependency to VM.
 */
typedef struct logmem_s {
	lck_spin_t *lm_lock;
	uint8_t     *lm_mem;
	uint8_t     *lm_mem_map;
	size_t      lm_cap_order;
	size_t      lm_min_order;
	size_t      lm_max_order;
	uint32_t    lm_cnt_allocations;
	uint32_t    lm_cnt_failed_size;
	uint32_t    lm_cnt_failed_full;
	uint32_t    lm_cnt_free;
} logmem_t;

/*
 * Static initializer for global instances of logmem. Size order defines the
 * total amount of logmem memory, the min and max order set the minimum and the
 * maximum size respectively of the memory allocatable by the given logmem.
 * Local or dynamically allocated instances of logmem should not be initialized
 * by this macro.
 */
#define LOGMEM_STATIC_INIT(name, size_order, min_order, max_order) \
    SIMPLE_LOCK_DECLARE(name##_lck, 0); \
    logmem_t name = { \
	.lm_lock = (lck_spin_t *)&name##_lck, \
	.lm_mem = (uint8_t[(1 << (size_order))]){ 0 }, \
	.lm_mem_map = (uint8_t[MAX(1, (1 << ((size_order) - (min_order) + 1)) / 8)]){ 0 }, \
	.lm_cap_order = (size_order), \
	.lm_max_order = (max_order), \
	.lm_min_order = (min_order), \
	.lm_cnt_free = (1 << (size_order)) \
    };

/*
 * Allocates memory from a respective logmem. Returns a pointer to the beginning
 * of the allocated block. The resulting size of the allocated block is equal or
 * bigger than the size passed in during the call.
 */
void *logmem_alloc(logmem_t *, size_t *);

/*
 * Frees memory previously allocated by logmem_alloc(). The caller must call
 * logmem_free() with exact pointer and size value returned by logmem_alloc().
 */
void logmem_free(logmem_t *, void *, size_t);

/*
 * Returns the maximum memory size allocatable by the logmem.
 */
size_t logmem_max_size(const logmem_t *);

#endif /* log_mem_h */
