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
#include <stdlib.h>
#include <machine/cpu_capabilities.h>
#include <sys/kdebug.h>
#include <sys/errno.h>

extern int __kdebug_trace64(uint32_t code, uint64_t arg1, uint64_t arg2,
                            uint64_t arg3, uint64_t arg4);
extern uint64_t __kdebug_trace_string(uint32_t debugid, uint64_t str_id,
                                      const char *str);

/* Returns non-zero if tracing is enabled. */
static int
kdebug_enabled(void)
{
	volatile uint32_t *kdebug_enable_address =
	    (volatile uint32_t *)(uintptr_t)(_COMM_PAGE_KDEBUG_ENABLE);

	if (*kdebug_enable_address == 0) {
		return 0;
	}

	return 1;
}

static int
kdebug_validate_debugid(uint32_t debugid)
{
	uint8_t debugid_class;

	/*
	 * This filtering is also done in the kernel, but we also do it here so
	 * that errors are returned in all cases, not just when the system call
	 * is actually performed.
	 */
	debugid_class = KDBG_EXTRACT_CLASS(debugid);
	switch (debugid_class) {
		case DBG_TRACE:
			return EPERM;
	}

	return 0;
}

int
kdebug_trace(uint32_t debugid, uint64_t arg1, uint64_t arg2, uint64_t arg3,
             uint64_t arg4)
{
	int err;

	if (!kdebug_enabled()) {
		return 0;
	}

	if ((err = kdebug_validate_debugid(debugid)) != 0) {
		errno = err;
		return -1;
	}

	return __kdebug_trace64(debugid, arg1, arg2, arg3, arg4);
}

uint64_t
kdebug_trace_string(uint32_t debugid, uint64_t str_id, const char *str)
{
	int err;

	if (!kdebug_enabled()) {
		return 0;
	}

	if ((int64_t)str_id == -1) {
		errno = EINVAL;
		return (uint64_t)-1;
	}

	if (str_id == 0 && str == NULL) {
		errno = EINVAL;
		return (uint64_t)-1;
	}

	if ((err = kdebug_validate_debugid(debugid)) != 0) {
		errno = err;
		return (uint64_t)-1;
	}

	return __kdebug_trace_string(debugid, str_id, str);
}
