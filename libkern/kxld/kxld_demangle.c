/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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

#if !KERNEL

#include <stdlib.h>

/* This demangler is part of the C++ ABI.  We don't include it directly from
 * <cxxabi.h> so that we can avoid using C++ in the kernel linker.
 */
extern char *
__cxa_demangle(const char* __mangled_name, char* __output_buffer,
    size_t* __length, int* __status);

#endif /* !KERNEL */

#include "kxld_demangle.h"

/*******************************************************************************
*******************************************************************************/
const char *
kxld_demangle(const char *str, char **buffer __unused, size_t *length __unused)
{
#if KERNEL
	return str;
#else
	const char *rval = NULL;
	char *demangled = NULL;
	int status;

	rval = str;

	if (!buffer || !length) {
		goto finish;
	}

	/* Symbol names in the symbol table have an extra '_' prepended to them,
	 * so we skip the first character to make the demangler happy.
	 */
	demangled = __cxa_demangle(str + 1, *buffer, length, &status);
	if (!demangled || status) {
		goto finish;
	}

	*buffer = demangled;
	rval = demangled;
finish:
	return rval;
#endif
}
