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

#ifndef _PRNG_ENTROPY_H_
#define _PRNG_ENTROPY_H_

__BEGIN_DECLS

#ifdef XNU_KERNEL_PRIVATE

// The below three definitions are utilized when the kernel is in
// "normal" operation, that is when we are *not* interested in collecting
// entropy.

// Indicates the number of bytes in the entropy buffer
#define ENTROPY_BUFFER_BYTE_SIZE 32

// Indicates the number of uint32_t's in the entropy buffer
#define ENTROPY_BUFFER_SIZE (ENTROPY_BUFFER_BYTE_SIZE / sizeof(uint32_t))

// Mask applied to EntropyData.sample_count to get an
// index suitable for storing the next sample in
// EntropyData.buffer. Note that ENTROPY_BUFFER_SIZE must be a power
// of two for the following mask calculation to be valid.
#define ENTROPY_BUFFER_INDEX_MASK (ENTROPY_BUFFER_SIZE - 1)

typedef struct entropy_data {
	/*
	 * TODO: Should sample_count be volatile?  Are we exposed to any races that
	 * we care about if it is not?
	 */

	// At 32 bits, this counter can overflow. Since we're primarily
	// interested in the delta from one read to the next, we don't
	// worry about this too much.
	uint32_t sample_count;

	// We point to either a static array when operating normally or
	// a dynamically allocated array when we wish to collect entropy
	// data. This decision is based on the presence of the boot
	// argument "ebsz".
	uint32_t *buffer;

	// The entropy buffer size in bytes. This must be a power of 2.
	uint32_t buffer_size;

	// The mask used to index into the entropy buffer for storing
	// the next entropy sample.
	uint32_t buffer_index_mask;

	// The mask used to include the previous entropy buffer contents
	// when updating the entropy buffer. When in entropy collection
	// mode this is set to zero so that we can gather the raw entropy.
	// In normal operation this is set to (uint32_t) -1.
	uint32_t ror_mask;
} entropy_data_t;

extern entropy_data_t EntropyData;

/* Trace codes for DBG_SEC_KERNEL: */
#define ENTROPY_READ(n) SECURITYDBG_CODE(DBG_SEC_KERNEL, n) /* n: 0 .. 3 */

#endif /* XNU_KERNEL_PRIVATE */

void entropy_buffer_init(void);

__END_DECLS

#endif /* _PRNG_ENTROPY_H_ */
