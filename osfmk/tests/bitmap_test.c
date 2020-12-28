/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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


#if DEVELOPMENT || DEBUG

#include <tests/xnupost.h>
#include <kern/kalloc.h>
#include <kern/bits.h>

extern void dump_bitmap_next(bitmap_t *map, uint nbits);
extern void dump_bitmap_lsb(bitmap_t *map, uint nbits);
extern void test_bitmap(void);
extern kern_return_t bitmap_post_test(void);

void
dump_bitmap_next(bitmap_t *map, uint nbits)
{
	for (int i = bitmap_first(map, nbits); i >= 0; i = bitmap_next(map, i)) {
		printf(" %d", i);
	}
	printf("\n");
}

void
dump_bitmap_lsb(bitmap_t *map, uint nbits)
{
	for (int i = bitmap_lsb_first(map, nbits); i >= 0; i = bitmap_lsb_next(map, nbits, i)) {
		printf(" %d", i);
	}
	printf("\n");
}

#ifdef NOTDEF
#ifdef assert
#undef assert
#endif
#define assert(x)       T_ASSERT(x, NULL)
#endif

void
test_bitmap(void)
{
	uint start = 60;
	for (uint nbits = start; nbits <= 192; nbits++) {
		bitmap_t *map = bitmap_alloc(nbits);

		for (uint i = 0; i < nbits; i++) {
			bitmap_set(map, i);
		}

		int expected_result = nbits - 1;
		for (int i = bitmap_first(map, nbits); i >= 0; i = bitmap_next(map, i)) {
			assert(i == expected_result);
			expected_result--;
		}
		assert(expected_result == -1);

		expected_result = 0;
		for (int i = bitmap_lsb_first(map, nbits); i >= 0; i = bitmap_lsb_next(map, nbits, i)) {
			assert(i == expected_result);
			expected_result++;
		}
		assert(expected_result == (int)nbits);

		for (uint i = 0; i < nbits; i++) {
			bitmap_clear(map, i);
		}
		assert(bitmap_first(map, nbits) == -1);
		assert(bitmap_lsb_first(map, nbits) == -1);

		bitmap_free(map, nbits);
	}
}

kern_return_t
bitmap_post_test(void)
{
	test_bitmap();

	kern_return_t ret = KERN_SUCCESS;

	T_ASSERT(ret == KERN_SUCCESS, NULL);

	return ret;
}
#endif
