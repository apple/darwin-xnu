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

#include <stdbool.h>
#include <stdint.h>
#include <kern/assert.h>
#include <kern/locks.h>
#include <os/atomic_private.h>

#include "log_mem.h"

#define BLOCK_INVALID ((size_t)-1)
#define BLOCK_LEVEL_BASE(level) ((1 << (level)) - 1)
#define BLOCK_SIZE(level) (1 << (level))
#define BLOCK_PARENT(b) (((b) % 2 == 0) ? ((b) >> 1) - 1 : ((b) >> 1))
#define BLOCK_LCHILD(b) (((b) << 1) + 1)
#define BLOCK_BUDDY(b) (((b) & 0x1) ? (b) + 1 : (b) - 1)
#define BLOCK_INDEX(lm, l, a, s) \
    (BLOCK_LEVEL_BASE(l) + ((uintptr_t)(a) - (uintptr_t)(lm)->lm_mem) / (s))

#define BITMAP_BUCKET_SIZE (8 * sizeof(((logmem_t *)0)->lm_mem_map[0]))
#define BITMAP_BUCKET(i) ((i) / BITMAP_BUCKET_SIZE)
#define BITMAP_BIT(i) (1 << (BITMAP_BUCKET_SIZE - ((i) % BITMAP_BUCKET_SIZE) - 1))

static bool
bitmap_get(logmem_t *lm, size_t block)
{
	return lm->lm_mem_map[BITMAP_BUCKET(block)] & BITMAP_BIT(block);
}

static void
bitmap_set(logmem_t *lm, size_t block)
{
	lm->lm_mem_map[BITMAP_BUCKET(block)] |= BITMAP_BIT(block);
}

static void
bitmap_clear(logmem_t *lm, size_t block)
{
	lm->lm_mem_map[BITMAP_BUCKET(block)] &= ~BITMAP_BIT(block);
}

static void
bitmap_reserve_root(logmem_t *lm, size_t block)
{
	const size_t top_block = BLOCK_LEVEL_BASE(lm->lm_cap_order - lm->lm_max_order);

	for (ssize_t next = BLOCK_PARENT(block); next >= top_block; next = BLOCK_PARENT(next)) {
		/*
		 * If the rest of the root path is already marked as
		 * allocated we are done.
		 */
		if (bitmap_get(lm, next)) {
			break;
		}
		bitmap_set(lm, next);
	}
}

static void
bitmap_release_root(logmem_t *lm, size_t block)
{
	const size_t top_block = BLOCK_LEVEL_BASE(lm->lm_cap_order - lm->lm_max_order);
	int buddy_allocated = 0;

	while (block > top_block) {
		buddy_allocated = bitmap_get(lm, BLOCK_BUDDY(block));
		block = BLOCK_PARENT(block);
		/*
		 * If there is another allocation within the parent subtree
		 * in place we cannot mark the rest of the root path as free.
		 */
		if (buddy_allocated) {
			break;
		}
		bitmap_clear(lm, block);
	}
}

static void
bitmap_update_subtree(logmem_t *lm, size_t level, size_t block, void (*fun)(logmem_t *, size_t))
{
	const size_t lcount = lm->lm_cap_order - lm->lm_min_order - level + 1;

	for (size_t l = 0, n = 1; l < lcount; l++, n <<= 1) {
		for (int i = 0; i < n; i++) {
			fun(lm, block + i);
		}
		block = BLOCK_LCHILD(block);
	}
}

static void
bitmap_release_subtree(logmem_t *lm, size_t level, size_t block)
{
	bitmap_update_subtree(lm, level, block, bitmap_clear);
}

static void
bitmap_reserve_subtree(logmem_t *lm, size_t level, size_t block)
{
	bitmap_update_subtree(lm, level, block, bitmap_set);
}

static size_t
block_size_level(logmem_t *lm, size_t amount)
{
	for (size_t l = lm->lm_min_order; l <= lm->lm_max_order; l++) {
		if (amount <= BLOCK_SIZE(l)) {
			return lm->lm_cap_order - l;
		}
	}
	return BLOCK_INVALID;
}

static size_t
block_locate(logmem_t *lm, void *addr, size_t amount, size_t *block)
{
	size_t level = block_size_level(lm, amount);
	if (level != BLOCK_INVALID) {
		*block = BLOCK_INDEX(lm, level, addr, amount);
	}
	return level;
}

static size_t
block_reserve(logmem_t *lm, size_t level)
{
	assert(level != BLOCK_INVALID);

	const size_t base = BLOCK_LEVEL_BASE(level);
	const size_t end = base + BLOCK_SIZE(level);

	lck_spin_lock(lm->lm_lock);
	for (size_t block = base; block < end; block++) {
		if (!bitmap_get(lm, block)) {
			bitmap_reserve_root(lm, block);
			bitmap_reserve_subtree(lm, level, block);
			lck_spin_unlock(lm->lm_lock);
			return block - base;
		}
	}
	lck_spin_unlock(lm->lm_lock);

	return BLOCK_INVALID;
}

void *
logmem_alloc(logmem_t *lm, size_t *amount)
{
	assert(amount);

	os_atomic_inc(&lm->lm_cnt_allocations, relaxed);

	if (*amount == 0 || *amount > BLOCK_SIZE(lm->lm_max_order)) {
		os_atomic_inc(&lm->lm_cnt_failed_size, relaxed);
		return NULL;
	}

	size_t level = block_size_level(lm, *amount);
	size_t block = block_reserve(lm, level);

	if (block == BLOCK_INVALID) {
		os_atomic_inc(&lm->lm_cnt_failed_full, relaxed);
		return NULL;
	}

	*amount = BLOCK_SIZE(lm->lm_cap_order - level);
	os_atomic_sub(&lm->lm_cnt_free, (uint32_t)*amount, relaxed);

	return &lm->lm_mem[block * *amount];
}

void
logmem_free(logmem_t *lm, void *addr, size_t amount)
{
	assert(addr);
	assert(amount > 0 && ((amount & (amount - 1)) == 0));

	size_t block = BLOCK_INVALID;
	size_t level = block_locate(lm, addr, amount, &block);
	assert(level != BLOCK_INVALID);
	assert(block != BLOCK_INVALID);

	lck_spin_lock(lm->lm_lock);
	bitmap_release_root(lm, block);
	bitmap_release_subtree(lm, level, block);
	lck_spin_unlock(lm->lm_lock);

	os_atomic_add(&lm->lm_cnt_free, (uint32_t)amount, relaxed);
}

size_t
logmem_max_size(const logmem_t *lm)
{
	return BLOCK_SIZE(lm->lm_max_order);
}
