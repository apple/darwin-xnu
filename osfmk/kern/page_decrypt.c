/*
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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

#include <debug.h>

#include <kern/page_decrypt.h>
#include <kern/task.h>
#include <machine/commpage.h>

static dsmos_page_transform_hook_t dsmos_hook = NULL;

void
dsmos_page_transform_hook(dsmos_page_transform_hook_t hook)
{
	printf("DSMOS has arrived\n");
	/* set the hook now - new callers will run with it */
	dsmos_hook = hook;
}

int
dsmos_page_transform(const void* from, void *to, unsigned long long src_offset, void *ops)
{
	static boolean_t first_wait = TRUE;

	if (dsmos_hook == NULL) {
		if (first_wait) {
			first_wait = FALSE;
			printf("Waiting for DSMOS...\n");
		}
		return KERN_ABORTED;
	}
	return (*dsmos_hook)(from, to, src_offset, ops);
}


text_crypter_create_hook_t text_crypter_create = NULL;
void
text_crypter_create_hook_set(text_crypter_create_hook_t hook)
{
	text_crypter_create = hook;
}
