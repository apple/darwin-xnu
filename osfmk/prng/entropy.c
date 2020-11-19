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

#include <kern/zalloc.h>
#include <pexpert/pexpert.h>
#include <prng/entropy.h>
#include <crypto/entropy/diag_entropy_sysctl.h>
#include <machine/machine_routines.h>

// Use a static buffer when the entropy collection boot arg is not present and before the
// RNG has been initialized.
static uint32_t entropy_buffer[ENTROPY_BUFFER_SIZE];

entropy_data_t EntropyData = {
	.sample_count = 0,
	.buffer = entropy_buffer,
	.buffer_size = ENTROPY_BUFFER_SIZE,
	.buffer_index_mask = ENTROPY_BUFFER_SIZE - 1,
	.ror_mask = -1
};

void
entropy_buffer_init(void)
{
	uint32_t ebsz = 0;
	uint32_t *bp;

	if (PE_parse_boot_argn("ebsz", &ebsz, sizeof(ebsz))) {
		if (((ebsz & (ebsz - 1)) != 0) || (ebsz < 32)) {
			panic("entropy_buffer_init: entropy buffer size must be a power of 2 and >= 32\n");
		}

		register_entropy_sysctl();

		bp = zalloc_permanent(sizeof(uint32_t) * ebsz, ZALIGN(uint32_t));

		boolean_t interrupt_state = ml_set_interrupts_enabled(FALSE);
		EntropyData.buffer = bp;
		EntropyData.sample_count = 0;
		EntropyData.buffer_size = sizeof(uint32_t) * ebsz;
		EntropyData.buffer_index_mask = ebsz - 1;
		EntropyData.ror_mask = 0;
		ml_set_interrupts_enabled(interrupt_state);
	}
}
