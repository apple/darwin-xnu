/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#ifndef _COMMPAGE_H
#define _COMMPAGE_H

#ifdef  PRIVATE

#define _COMM_PAGE32_SIGNATURE_STRING           "commpage 32-bit"
#define _COMM_PAGE64_SIGNATURE_STRING           "commpage 64-bit"

typedef volatile struct commpage_timeofday_data {
	uint64_t        TimeStamp_tick;
	uint64_t        TimeStamp_sec;
	uint64_t        TimeStamp_frac;
	uint64_t        Ticks_scale;
	uint64_t        Ticks_per_sec;
} new_commpage_timeofday_data_t;

/*!
 * @macro COMM_PAGE_SLOT_TYPE
 *
 * @brief
 * Macro that expands to the proper type for a pointer to a commpage slot,
 * to be used in a local variable declaration.
 *
 * @description
 * Usage is something like:
 * <code>
 *     COMM_PAGE_SLOT_TYPE(uint64_t) slot = COMM_PAGE_SLOT(uint64_t, FOO);
 * </code>
 *
 * @param type   The scalar base type for the slot.
 */
#if __has_feature(address_sanitizer)
#define COMM_PAGE_SLOT_TYPE(type_t)     type_t __attribute__((address_space(1))) volatile *
#else
#define COMM_PAGE_SLOT_TYPE(type_t)     type_t volatile *
#endif

/*!
 * @macro COMM_PAGE_SLOT
 *
 * @brief
 * Macro that expands to the properly typed address for a commpage slot.
 *
 * @param type   The scalar base type for the slot.
 * @param name   The slot name, without its @c _COMM_PAGE_ prefix.
 */
#define COMM_PAGE_SLOT(type_t, name)    ((COMM_PAGE_SLOT_TYPE(type_t))_COMM_PAGE_##name)

/*!
 * @macro COMM_PAGE_READ
 *
 * @brief
 * Performs a single read from the commpage in a way that doesn't trip
 * address sanitizers.
 *
 * @description
 * Typical use looks like this:
 * <code>
 *     uint64_t foo_value = COMM_PAGE_READ(uint64_t, FOO);
 * </code>
 *
 * @param type   The scalar base type for the slot.
 * @param name   The slot name, without its @c _COMM_PAGE_ prefix.
 */
#define COMM_PAGE_READ(type_t, slot)    (*(COMM_PAGE_SLOT(type_t, slot)))

#endif

#endif
