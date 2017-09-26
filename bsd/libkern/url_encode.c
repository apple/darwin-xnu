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

#include <libkern/libkern.h>

static int
hex2int(int c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	return 0;
}

static bool
isprint(int ch)
{
	return ch >= 0x20 && ch <= 0x7e;
}

/*
 * In-place decode of URL percent-encoded str
 */
void
url_decode(char *str)
{
	if (!str) {
		return;
	}

	while (*str) {
		if (*str == '%') {
			char c = 0;
			char *esc = str++; /* remember the start of the escape sequence */

			if (*str) {
				c += hex2int(*str++);
			}
			if (*str) {
				c = (c << 4) + hex2int(*str++);
			}

			if (isprint(c)) {
				/* overwrite the '%' with the new char, and bump the rest of the
				 * string down a few characters */
				*esc++ = c;
				str = memmove(esc, str, strlen(str)+1);
			}
		} else {
			str++;
		}
	}
}
