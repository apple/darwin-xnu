/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <strings.h>

#include <mach/mach_init.h>

#include "kxld_array.h"
#include "kxld_test.h"
#include "kxld_util.h"

#define kNumStorageTestItems (u_int) (4 * PAGE_SIZE / sizeof(u_int))

int
main(int argc __unused, char *argv[] __unused)
{
	kern_return_t rval = KERN_FAILURE;
	KXLDArray array;
	u_int *item = 0;
	u_int test_num = 0;
	u_int idx = 0;
	u_int titems = 0;
	u_int storageTestItems[kNumStorageTestItems];
	u_int i = 0;

	bzero(&array, sizeof(array));

	kxld_set_logging_callback(kxld_test_log);
	kxld_set_logging_callback_data("kxld_array_test", NULL);

	kxld_log(0, 0, "%d: Initialize", ++test_num);

	titems = PAGE_SIZE / sizeof(u_int);
	rval = kxld_array_init(&array, sizeof(u_int), titems);
	assert(rval == KERN_SUCCESS);
	assert(array.nitems == titems);

	kxld_log(0, 0, "%d: Get item", ++test_num);
	idx = 0;
	item = kxld_array_get_item(&array, idx);
	assert(item);
	assert(item == kxld_array_get_slot(&array, idx));

	idx = titems - 1;
	item = kxld_array_get_item(&array, idx);
	assert(item);
	assert(item == kxld_array_get_slot(&array, idx));

	idx = titems;
	item = kxld_array_get_item(&array, idx);
	assert(!item);
	/* We allocated the max number of items that could be stored in a page,
	 * so get_slot() and get_item() are equivalent.
	 */
	assert(item == kxld_array_get_slot(&array, idx));

	kxld_log(0, 0, "%d: Resize", ++test_num);

	titems = 2 * PAGE_SIZE / sizeof(u_int) + 100;
	rval = kxld_array_resize(&array, titems);
	assert(rval == KERN_SUCCESS);
	assert(array.nitems == titems);

	kxld_log(0, 0, "%d: Get more items", ++test_num);
	idx = 0;
	item = kxld_array_get_item(&array, idx);
	assert(item);
	assert(item == kxld_array_get_slot(&array, idx));

	idx = titems - 1;
	item = kxld_array_get_item(&array, idx);
	assert(item);
	assert(item == kxld_array_get_slot(&array, idx));

	idx = titems;
	item = kxld_array_get_item(&array, idx);
	assert(!item);
	/* We allocated fewer items than could fit in a page, so get_slot() will
	 * return items even when get_item() does not.  See below for details.
	 */
	assert(item != kxld_array_get_slot(&array, idx));

	kxld_log(0, 0, "%d: Clear and attempt to get an item", ++test_num);
	(void) kxld_array_clear(&array);
	item = kxld_array_get_item(&array, 0);
	assert(!item);

	kxld_log(0, 0, "%d: Get slot", ++test_num);
	/* The array allocates its internal storage in pages. Because get_slot()
	 * fetches items based on the allocated size, not the logical size, we
	 * calculate the max items get_slot() can retrieve based on page size.
	 */
	titems = (u_int) (round_page(titems * sizeof(u_int)) / sizeof(u_int));
	assert(!item);
	item = kxld_array_get_slot(&array, 0);
	assert(item);
	item = kxld_array_get_slot(&array, titems - 1);
	assert(item);
	item = kxld_array_get_slot(&array, titems);
	assert(!item);

	kxld_log(0, 0, "%d: Reinitialize", ++test_num);

	titems = kNumStorageTestItems;
	rval = kxld_array_init(&array, sizeof(u_int), titems);
	assert(rval == KERN_SUCCESS);
	assert(array.nitems == titems);

	kxld_log(0, 0, "%d: Storage test - %d insertions and finds",
	    ++test_num, kNumStorageTestItems);
	for (i = 0; i < titems; ++i) {
		item = kxld_array_get_item(&array, i);
		assert(item);

		*item = (u_int) (random() % UINT_MAX);
		storageTestItems[i] = *item;
	}

	for (i = 0; i < titems; ++i) {
		item = kxld_array_get_item(&array, i);
		assert(item);
		assert(*item == storageTestItems[i]);
	}

	(void) kxld_array_deinit(&array);

	kxld_log(0, 0, " ");
	kxld_log(0, 0, "All tests passed!  Now check for memory leaks...");

	kxld_print_memory_report();

	return 0;
}
