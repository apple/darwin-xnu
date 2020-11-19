/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

/*
 *	Obtains cache physical layout information required for way/set
 *	data cache maintenance operations.
 *
 *	$0: Data cache level, starting from 0
 *	$1: Output register for set increment
 *	$2: Output register for last valid set
 *	$3: Output register for way increment
 */
.macro GET_CACHE_CONFIG
	lsl		$0, $0, #1
	mcr		p15, 2, $0, c0, c0, 0				// Select appropriate cache
	isb											// Synchronize context

	mrc		p15, 1, $0, c0, c0, 0
	ubfx	$1, $0, #3, #10						// extract number of ways - 1
	mov		$2, $1
	add		$1, $1, #1							// calculate number of ways

	mov		$0, #31
	and		$2, $2, $1
	cmp		$2, #0
	addne	$0, $0, #1
	clz		$1, $1
	sub		$0, $0, $1

	mov 	$1, #32								// calculate way increment
	sub		$3, $1, $0
	mov		$1, #1
	lsl		$3, $1, $3

	mrc		p15, 1, $0, c0, c0, 0
	ubfx	$1, $0, #0, #3						// extract log2(line size) - 4
	add		$1, $1, #4							// calculate log2(line size)
	mov		$2, #1
	lsl		$1, $2, $1							// calculate set increment

	ubfx	$2, $0, #13, #15					// extract number of sets - 1
	add		$2, $2, #1							// calculate number of sets
	mul		$2, $1, $2							// calculate last valid set
.endmacro

/*
 *	Detects the presence of an L2 cache and returns 1 if implemented,
 *	zero otherwise.
 *
 *	$0: Output register
 */
.macro HAS_L2_CACHE
	mrc		p15, 1, $0, c0, c0, 1
	ubfx	$0, $0, #3, #3						// extract L2 cache Ctype
	cmp		$0, #0x1
	movls	$0, #0
	movhi	$0, #1
.endmacro