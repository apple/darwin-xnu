/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
#include <i386/pmap.h>
#include <i386/proc_reg.h>
#include <IOKit/IOHibernatePrivate.h>

extern pd_entry_t BootstrapPTD[2048];

#define TWO_MEG_MASK 0xFFFFFFFFFFE00000ULL

#define DST_INDEX 2047UL

static char *dstPtr = (char *)(DST_INDEX << PDSHIFT);

// src is virtually mapped, not page aligned, 
// dst is a physical 4k page aligned ptr, len is one 4K page
// src & dst will not overlap

void 
hibernate_restore_phys_page(uint64_t src, uint64_t dst, uint32_t len, uint32_t procFlags)
{
	(void)procFlags;
	uint64_t * d;
	uint64_t * s;
	uint32_t idx;

	if (src == 0)
		return;

	if (dst < (uint64_t) (uintptr_t)dstPtr)
	{
		d = (uint64_t *) (uintptr_t)dst;
	}
	else
	{
		/* Outside 1-1 4G map so set up the mappings for the dest page using 2MB pages */
		BootstrapPTD[DST_INDEX] = (dst & TWO_MEG_MASK) | INTEL_PTE_PS | INTEL_PTE_VALID | INTEL_PTE_WRITE | INTEL_PTE_WRITE;
		
		/* Invalidate the page tables for this */
		invlpg((uintptr_t) dstPtr);

		/* Mask off the offset from the 2MB window */
		dst &= ~TWO_MEG_MASK;
		d = (uint64_t *) (dstPtr + dst);
	}
	s = (uint64_t *) (uintptr_t)src;
	for (idx = 0; idx < (len / (uint32_t)sizeof(uint64_t)); idx++) 
		d[idx] = s[idx];
}
