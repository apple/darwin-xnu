/*
 * Copyright (c) 2017-2018 Apple Inc. All rights reserved.
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

#include <netinet/in_stat.h>

#define IN_STAT_ACTIVITY_GRANULARITY            8       /* 8 sec granularity */
#define IN_STAT_ACTIVITY_TIME_SEC_SHIFT         3       /* 8 sec per bit */
#define IN_STAT_ACTIVITY_BITMAP_TOTAL_SIZE      ((uint64_t) 128)
#define IN_STAT_ACTIVITY_BITMAP_FIELD_SIZE      ((uint64_t) 64)
#define IN_STAT_ACTIVITY_TOTAL_TIME             ((uint64_t) (8 * 128))
#define IN_STAT_SET_MOST_SIGNIFICANT_BIT        ((u_int64_t )0x8000000000000000)

void
in_stat_set_activity_bitmap(activity_bitmap_t *activity, uint64_t now)
{
	uint64_t elapsed_time, slot;
	uint64_t *bitmap;
	if (activity->start == 0) {
		// Align all activity maps
		activity->start = now - (now % IN_STAT_ACTIVITY_GRANULARITY);
	}
	elapsed_time = now - activity->start;

	slot = elapsed_time >> IN_STAT_ACTIVITY_TIME_SEC_SHIFT;
	if (slot < IN_STAT_ACTIVITY_BITMAP_TOTAL_SIZE) {
		if (slot < IN_STAT_ACTIVITY_BITMAP_FIELD_SIZE) {
			bitmap = &activity->bitmap[0];
		} else {
			bitmap = &activity->bitmap[1];
			slot -= IN_STAT_ACTIVITY_BITMAP_FIELD_SIZE;
		}
		*bitmap |= (((u_int64_t) 1) << slot);
	} else {
		if (slot >= (IN_STAT_ACTIVITY_BITMAP_TOTAL_SIZE * 2)) {
			activity->start = now - IN_STAT_ACTIVITY_TOTAL_TIME;
			activity->bitmap[0] = activity->bitmap[1] = 0;
		} else {
			uint64_t shift =
			    slot - (IN_STAT_ACTIVITY_BITMAP_TOTAL_SIZE - 1);
			/*
			 * Move the start time and bitmap forward to
			 * cover the lost time
			 */
			activity->start +=
			    (shift << IN_STAT_ACTIVITY_TIME_SEC_SHIFT);
			if (shift > IN_STAT_ACTIVITY_BITMAP_FIELD_SIZE) {
				activity->bitmap[0] = activity->bitmap[1];
				activity->bitmap[1] = 0;
				shift -= IN_STAT_ACTIVITY_BITMAP_FIELD_SIZE;
				if (shift == IN_STAT_ACTIVITY_BITMAP_FIELD_SIZE) {
					activity->bitmap[0] = 0;
				} else {
					activity->bitmap[0] >>= shift;
				}
			} else {
				uint64_t mask_lower, tmp;
				uint64_t b1_low, b0_high;

				/*
				 * generate a mask with all of lower
				 * 'shift' bits set
				 */
				tmp = (((uint64_t)1) << (shift - 1));
				mask_lower = ((tmp - 1) ^ tmp);
				activity->bitmap[0] >>= shift;
				b1_low = (activity->bitmap[1] & mask_lower);

				b0_high = (b1_low <<
				    (IN_STAT_ACTIVITY_BITMAP_FIELD_SIZE -
				    shift));
				activity->bitmap[0] |= b0_high;
				activity->bitmap[1] >>= shift;
			}
		}
		activity->bitmap[1] |= IN_STAT_SET_MOST_SIGNIFICANT_BIT;
	}
}
