/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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

#include <stdint.h>
#include <machine/cpu_capabilities.h>
#include <sys/kdebug.h>
#include <sys/errno.h>

#define CLASS_MASK      0xff000000
#define CLASS_OFFSET    24
#define SUBCLASS_MASK   0x00ff0000
#define SUBCLASS_OFFSET 16

#define EXTRACT_CLASS(debugid)          ((uint8_t)(((debugid) & CLASS_MASK) >> CLASS_OFFSET))
#define EXTRACT_SUBCLASS(debugid)       ( (uint8_t) ( ((debugid) & SUBCLASS_MASK) >> SUBCLASS_OFFSET ) )

extern int __kdebug_trace64(uint32_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

int
kdebug_trace(uint32_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
	uint8_t code_class;
	volatile uint32_t *kdebug_enable_address = (volatile uint32_t *)(uintptr_t)(_COMM_PAGE_KDEBUG_ENABLE);

	/*
	 * This filtering is also done in the kernel, but we also do it here so that errors
	 * are returned in all cases, not just when the system call is actually performed.
	 */
	code_class = EXTRACT_CLASS(code);
	switch (code_class) {
		case DBG_TRACE:
			errno = EPERM;
			return -1;
	}

	if (*kdebug_enable_address == 0) {
		return 0;
	}
	
	return __kdebug_trace64(code, arg1, arg2, arg3, arg4);
}
