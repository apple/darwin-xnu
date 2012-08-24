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

#include <i386/pal_hibernate.h>

extern pd_entry_t BootPTD[2048];

// src is virtually mapped, not page aligned, 
// dst is a physical 4k page aligned ptr, len is one 4K page
// src & dst will not overlap

uintptr_t 
hibernate_restore_phys_page(uint64_t src, uint64_t dst, uint32_t len, uint32_t procFlags)
{
	(void)procFlags;
	uint64_t * d;
	uint64_t * s;
	uint32_t idx;

	if (src == 0)
		return (uintptr_t)dst;

	d = (uint64_t *)pal_hib_map(DEST_COPY_AREA, dst);
	s = (uint64_t *) (uintptr_t)src;

	for (idx = 0; idx < (len / (uint32_t)sizeof(uint64_t)); idx++) 
		d[idx] = s[idx];

	return (uintptr_t)d;
}
#undef hibprintf

void hibprintf(const char *fmt, ...);

uintptr_t
pal_hib_map(uintptr_t virt, uint64_t phys)
{
    uintptr_t index;

    switch (virt)
    {
	case DEST_COPY_AREA:
	case SRC_COPY_AREA:
	case COPY_PAGE_AREA:
	case BITMAP_AREA:
	case IMAGE_AREA:
	case IMAGE2_AREA:
	    break;
	default:
	    asm("cli;hlt;");
	    break;
    }

    index = (virt >> I386_LPGSHIFT);
    virt += (uintptr_t)(phys & I386_LPGMASK);
    phys  = ((phys & ~((uint64_t)I386_LPGMASK)) | INTEL_PTE_PS  | INTEL_PTE_VALID | INTEL_PTE_WRITE);
    BootPTD[index] = phys;
    invlpg(virt);
    BootPTD[index + 1] = (phys + I386_LPGBYTES);
    invlpg(virt + I386_LPGBYTES);

    return (virt);
}

void hibernateRestorePALState(uint32_t *arg)
{
    (void)arg;
}

void
pal_hib_patchup(void)
{
}
