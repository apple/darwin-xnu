/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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
/**
 * i386/x86_64 specific definitions for hibernation platform abstraction layer.
 */

#ifndef _I386_PAL_HIBERNATE_H
#define _I386_PAL_HIBERNATE_H

__BEGIN_DECLS

#define HIB_MAP_SIZE    (2*I386_LPGBYTES)
#define DEST_COPY_AREA  (4*GB - HIB_MAP_SIZE) /*4GB - 2*2m */
#define SRC_COPY_AREA   (DEST_COPY_AREA - HIB_MAP_SIZE)
#define COPY_PAGE_AREA  (SRC_COPY_AREA  - HIB_MAP_SIZE)
#define BITMAP_AREA     (COPY_PAGE_AREA - HIB_MAP_SIZE)
#define IMAGE_AREA      (BITMAP_AREA    - HIB_MAP_SIZE)
#define IMAGE2_AREA     (IMAGE_AREA     - HIB_MAP_SIZE)
#define SCRATCH_AREA    (IMAGE2_AREA    - HIB_MAP_SIZE)
#define WKDM_AREA       (SCRATCH_AREA   - HIB_MAP_SIZE)

#define HIB_BASE segHIBB
#define HIB_ENTRYPOINT acpi_wake_prot_entry

/*!
 * @typedef     pal_hib_map_type_t
 * @discussion  Parameter to pal_hib_map used to signify which memory region to map.
 */
typedef uintptr_t pal_hib_map_type_t;

/*!
 * @struct      pal_hib_ctx
 * @discussion  x86_64-specific PAL context; see pal_hib_ctx_t for details.
 */
struct pal_hib_ctx {
	char reserved;
};

__END_DECLS

#endif /* _I386_PAL_HIBERNATE_H */
