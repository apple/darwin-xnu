/*
 * Copyright (c) 2013-2015 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include "trace_internal.h"
#include <mach-o/loader.h>
#include <string.h>

static bool
_os_trace_addr_in_text_segment_32(const void *dso, const void *addr)
{
	const struct mach_header *mhp = (const struct mach_header *) dso;
	const struct segment_command *sgp = (const struct segment_command *)(const void *)((const char *)mhp + sizeof(struct mach_header));

	for (uint32_t i = 0; i < mhp->ncmds; i++) {
		if (sgp->cmd == LC_SEGMENT) {
			if (strncmp(sgp->segname, SEG_TEXT, sizeof(sgp->segname)) == 0) {
				return (uintptr_t)addr >= (sgp->vmaddr) && (uintptr_t)addr < (sgp->vmaddr + sgp->vmsize);
			}
		}
		sgp = (const struct segment_command *)(const void *)((const char *)sgp + sgp->cmdsize);
	}

	return false;
}

static bool
_os_trace_addr_in_text_segment_64(const void *dso, const void *addr)
{
	const struct mach_header_64 *mhp = (const struct mach_header_64 *) dso;
	const struct segment_command_64 *sgp = (const struct segment_command_64 *)(const void *)((const char *)mhp + sizeof(struct mach_header_64));

	for (uint32_t i = 0; i < mhp->ncmds; i++) {
		if (sgp->cmd == LC_SEGMENT_64) {
			if (strncmp(sgp->segname, SEG_TEXT, sizeof(sgp->segname)) == 0) {
				return (uintptr_t)addr >= (sgp->vmaddr) && (uintptr_t)addr < (sgp->vmaddr + sgp->vmsize);
			}
		}
		sgp = (const struct segment_command_64 *)(const void *)((const char *)sgp + sgp->cmdsize);
	}

	return false;
}

bool
_os_trace_addr_in_text_segment(const void *dso, const void *addr)
{
	const struct mach_header *mhp = (const struct mach_header *) dso;
	bool retval = false;

	switch (mhp->magic) {
	case MH_MAGIC:
		retval = _os_trace_addr_in_text_segment_32(dso, addr);
		break;

	case MH_MAGIC_64:
		retval = _os_trace_addr_in_text_segment_64(dso, addr);
		break;

	default:
		retval = false;
		break;
	}

	return retval;
}
