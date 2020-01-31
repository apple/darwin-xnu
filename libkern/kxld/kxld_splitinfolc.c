/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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
#include <string.h>
#include <mach-o/loader.h>
#include <sys/types.h>

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_util.h"
#include "kxld_splitinfolc.h"

/*******************************************************************************
*******************************************************************************/
void
kxld_splitinfolc_init_from_macho(KXLDsplitinfolc *splitinfolc, struct linkedit_data_command *src)
{
	check(splitinfolc);
	check(src);

	splitinfolc->cmdsize = src->cmdsize;
	splitinfolc->dataoff = src->dataoff;
	splitinfolc->datasize = src->datasize;
	splitinfolc->has_splitinfolc = TRUE;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_splitinfolc_clear(KXLDsplitinfolc *splitinfolc)
{
	bzero(splitinfolc, sizeof(*splitinfolc));
}

/*******************************************************************************
*******************************************************************************/
u_long
kxld_splitinfolc_get_macho_header_size(void)
{
	return sizeof(struct linkedit_data_command);
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_splitinfolc_export_macho(const KXLDsplitinfolc *splitinfolc,
    splitKextLinkInfo *linked_object,
    u_long *header_offset,
    u_long header_size,
    u_long *data_offset,
    u_long size)
{
	kern_return_t       rval = KERN_FAILURE;
	struct linkedit_data_command *splitinfolc_hdr = NULL;
	u_char *            buf;

	check(splitinfolc);
	check(linked_object);
	check(header_offset);
	check(data_offset);

	buf = (u_char *)(linked_object->linkedKext);
	require_action(sizeof(*splitinfolc_hdr) <= header_size - *header_offset,
	    finish,
	    rval = KERN_FAILURE);
	splitinfolc_hdr = (struct linkedit_data_command *)((void *)(buf + *header_offset));
	*header_offset += sizeof(*splitinfolc_hdr);

	if (buf + *data_offset > buf + size) {
		kxld_log(kKxldLogLinking, kKxldLogErr,
		    "\n OVERFLOW! linkedKext %p to %p (%lu) copy %p to %p (%u) <%s>",
		    (void *) buf,
		    (void *) (buf + size),
		    size,
		    (void *) (buf + *data_offset),
		    (void *) (buf + *data_offset + splitinfolc->datasize),
		    splitinfolc->datasize,
		    __func__);
		goto finish;
	}

	// copy in the split info reloc data from kextExecutable. For example dataoff
	// in LC_SEGMENT_SPLIT_INFO load command points to the reloc data in the
	// __LINKEDIT segment.  In this case 65768 into the kextExecutable file is
	// the split seg reloc info (for 920 bytes)
//    Load command 9
//    cmd LC_SEGMENT_SPLIT_INFO
//    cmdsize 16
//    dataoff 65768
//    datasize 920


	memcpy(buf + *data_offset, linked_object->kextExecutable + splitinfolc->dataoff, splitinfolc->datasize);

#if SPLIT_KEXTS_DEBUG
	u_char *dataPtr = buf + *data_offset;

	kxld_log(kKxldLogLinking, kKxldLogErr,
	    "\n\n linkedKext %p to %p (%lu) copy %p to %p (%u) <%s>",
	    (void *) buf,
	    (void *) (buf + size),
	    size,
	    (void *) (dataPtr),
	    (void *) (dataPtr + splitinfolc->datasize),
	    splitinfolc->datasize,
	    __func__);

	if (*(dataPtr + 0) != 0x7F) {
		kxld_log(kKxldLogLinking, kKxldLogErr,
		    "\n\n bad LC_SEGMENT_SPLIT_INFO: 0x%02X %02X %02X %02X %02X %02X %02X %02X at %p (buf %p + %lu) <%s>",
		    *(dataPtr + 0),
		    *(dataPtr + 1),
		    *(dataPtr + 2),
		    *(dataPtr + 3),
		    *(dataPtr + 4),
		    *(dataPtr + 5),
		    *(dataPtr + 6),
		    *(dataPtr + 7),
		    (void *) dataPtr,
		    (void *) buf,
		    *data_offset, __func__);
	}
#endif

	// update the load command header
	splitinfolc_hdr->cmd = LC_SEGMENT_SPLIT_INFO;
	splitinfolc_hdr->cmdsize = (uint32_t) sizeof(*splitinfolc_hdr);
	splitinfolc_hdr->dataoff = (uint32_t)(*data_offset);
	splitinfolc_hdr->datasize = splitinfolc->datasize;

	*data_offset += splitinfolc->datasize;

	rval = KERN_SUCCESS;

finish:
	return rval;
}
