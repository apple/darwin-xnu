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


#include <kern/page_decrypt.h>
#include <kern/task.h>
#include <machine/commpage.h>

/*#include <sys/kernel.h> */
extern int hz;			/* system clock's frequency */

/* #include <sys/proc.h> */
extern int	tsleep(void *chan, int pri, const char *wmesg, int timo);

/* #include <sys/param.h> */
#define	PZERO	22		/* No longer magic, shouldn't be here.  XXX */

static int _dsmos_wait_for_callback(const void*,void*);

static dsmos_page_transform_hook_t dsmos_hook = _dsmos_wait_for_callback;

int
_dsmos_wait_for_callback(const void* from, void *to)
{
/*	printf("%s\n", __FUNCTION__); */
	while (dsmos_hook == NULL || dsmos_hook == _dsmos_wait_for_callback)
		tsleep(&dsmos_hook, PZERO, "dsmos", hz / 10);

	return (*dsmos_hook) (from, to);
}

void
dsmos_page_transform_hook(dsmos_page_transform_hook_t hook)
{
/*	printf("%s\n", __FUNCTION__); */

	/* set the hook now - new callers will run with it */
	dsmos_hook = hook;
}

int
dsmos_page_transform(const void* from, void *to)
{
/*	printf("%s\n", __FUNCTION__); */
	if (dsmos_hook == NULL)
		return KERN_FAILURE;
	return (*dsmos_hook) (from, to);
}

