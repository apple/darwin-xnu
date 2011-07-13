/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#include <sys/cdefs.h>

#if __DARWIN_UNIX03

#include <sys/mman.h>
#include <mach/vm_param.h>
#include <errno.h>

void *__mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off);

/*
 * mmap stub, with preemptory failures due to extra parameter checking
 * mandated for conformance.
 *
 * This is for UNIX03 only.
 */
void *
mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
	/*
	 * Preemptory failures:
	 * 
	 * o	off is not a multiple of the page size
	 * o	flags does not contain either MAP_PRIVATE or MAP_SHARED
	 * o	len is zero
	 */
	extern void cthread_set_errno_self(int);
	if ((off & PAGE_MASK) ||
	    (((flags & MAP_PRIVATE) != MAP_PRIVATE) &&
	     ((flags & MAP_SHARED) != MAP_SHARED)) ||
	    (len == 0)) {
		cthread_set_errno_self(EINVAL);
		return(MAP_FAILED);
	}

	return(__mmap(addr, len, prot, flags, fildes, off));
}

#endif /* __DARWIN_UNIX03 */
