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
#ifndef _I386_PAL_HIBERNATE_H
#define _I386_PAL_HIBERNATE_H

#define HIB_PTES		(4*GB - 1*I386_LPGBYTES) /*4GB - 2m */
#define DEST_COPY_AREA	(HIB_PTES + 1*I386_PGBYTES)
#define SRC_COPY_AREA	(HIB_PTES + 2*I386_PGBYTES)
#define COPY_PAGE_AREA	(HIB_PTES + 3*I386_PGBYTES)

#define HIB_BASE sectINITPTB
#define HIB_ENTRYPOINT acpi_wake_prot_entry

void pal_hib_window_setup(ppnum_t page);
uintptr_t pal_hib_map(uintptr_t v, uint64_t p);
void hibernateRestorePALState(uint32_t *src);
void pal_hib_patchup(void);
#define PAL_HIBERNATE_MAGIC_1 0xfeedfacedeadbeef 
#define PAL_HIBERNATE_MAGIC_2 0x41b312133714 
#endif /* _I386_PAL_HIBERNATE_H */
