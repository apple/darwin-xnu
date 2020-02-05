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
#include <sys/errno.h>
#include <stdint.h>

extern void   *secure_memset(void *, int, size_t);

/*
 * The memset_s function copies the value c into the first n bytes
 * pointed by s. No more than smax bytes will be copied.
 *
 * In contrast to the memset function, calls to memset_s will never
 * be ''optimised away'' by a compiler, ensuring the memory copy
 * even if s is not accessed anymore after this call.
 */
int
memset_s(void *s, size_t smax, int c, size_t n)
{
	int err = 0;

	if (s == NULL) {
		return EINVAL;
	}
	if (smax > RSIZE_MAX) {
		return E2BIG;
	}
	if (n > smax) {
		n = smax;
		err = EOVERFLOW;
	}

	/*
	 * secure_memset is defined in assembly, we therefore
	 * expect that the compiler will not inline the call.
	 */
	secure_memset(s, c, n);

	return err;
}

int
timingsafe_bcmp(const void *b1, const void *b2, size_t n)
{
	const unsigned char *p1 = b1, *p2 = b2;
	unsigned char ret = 0;

	for (; n > 0; n--) {
		ret |= *p1++ ^ *p2++;
	}

	/* map zero to zero and nonzero to one */
	return (ret + 0xff) >> 8;
}
