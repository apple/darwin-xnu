/*
 * Copyright (c) 2005-2007 Apple Computer, Inc. All rights reserved.
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

/*
 * DTrace kalloc emulation.
 *
 * This is a subset of kalloc functionality, to allow dtrace
 * specific allocation to be accounted for separately from the
 * general kalloc pool.
 *
 * Note that allocations greater than dalloc_max still go into
 * the kalloc.large bucket, as it seems impossible to emulate
 * that functionality in the bsd kern.
 */

#include <stdarg.h>
#include <string.h>
#include <sys/malloc.h>
#include <sys/dtrace.h>
#include <kern/zalloc.h>

#if defined(DTRACE_MEMORY_ZONES)

#define DTRACE_ALLOC_MINSIZE 16

vm_size_t dtrace_alloc_max;
vm_size_t dtrace_alloc_max_prerounded;
int first_d_zone = -1;
struct zone *d_zone[16];
static const char *d_zone_name[16] = {
	"dtrace.1",		"dtrace.2",
	"dtrace.4",		"dtrace.8",
	"dtrace.16",		"dtrace.32",
	"dtrace.64",		"dtrace.128",
	"dtrace.256",		"dtrace.512",
	"dtrace.1024",		"dtrace.2048",
	"dtrace.4096",		"dtrace.8192",
	"dtrace.16384",		"dtrace.32768"
};

unsigned long d_zone_max[16] = {
      1024,		/*      1 Byte  */
      1024,		/*      2 Byte  */
      1024,		/*      4 Byte  */
      1024,		/*      8 Byte  */
      1024,		/*     16 Byte  */
      4096,		/*     32 Byte  */
      4096,		/*     64 Byte  */
      4096,		/*    128 Byte  */
      4096,		/*    256 Byte  */
      1024,		/*    512 Byte  */
      1024,		/*   1024 Byte  */
      1024,		/*   2048 Byte  */
      1024,		/*   4096 Byte  */
      4096,		/*   8192 Byte  */
      64,		/*  16384 Byte  */
      64,		/*  32768 Byte  */
};

void dtrace_alloc_init(void)
{
	vm_size_t size;
	int i;

	if (PAGE_SIZE < 16*1024)
		dtrace_alloc_max = 16*1024;
	else
		dtrace_alloc_max = PAGE_SIZE;
	dtrace_alloc_max_prerounded = dtrace_alloc_max / 2 + 1;

	/*
	 *	Allocate a zone for each size we are going to handle.
	 *	We specify non-paged memory.
	 */
	for (i = 0, size = 1; size < dtrace_alloc_max; i++, size <<= 1) {
		if (size < DTRACE_ALLOC_MINSIZE) {
			d_zone[i] = NULL;
			continue;
		}
		if (size == DTRACE_ALLOC_MINSIZE) {
			first_d_zone = i;
		}
		d_zone[i] = zinit(size, d_zone_max[i] * size, size, d_zone_name[i]);
	}
}

void *dtrace_alloc(vm_size_t size)
{
	int zindex;
	vm_size_t allocsize;

	/*
	 * If size is too large for a zone, then use kmem_alloc.
	 * (We use kmem_alloc instead of kmem_alloc_wired so that
	 * krealloc can use kmem_realloc.)
	 */

	if (size >= dtrace_alloc_max_prerounded) {
		return _MALLOC(size, M_TEMP, M_WAITOK);
	}

	/* compute the size of the block that we will actually allocate */
	allocsize = DTRACE_ALLOC_MINSIZE;
	zindex = first_d_zone;
	while (allocsize < size) {
		allocsize <<= 1;
		zindex++;
	}

	return(zalloc_canblock(d_zone[zindex], TRUE));
}

void dtrace_free(void *data, vm_size_t size)
{
	int zindex;
	vm_size_t freesize;

	if (size >= dtrace_alloc_max_prerounded) {
		_FREE(data, M_TEMP);
		return;
	}

	/* compute the size of the block that we actually allocated from */
	freesize = DTRACE_ALLOC_MINSIZE;
	zindex = first_d_zone;
	while (freesize < size) {
		freesize <<= 1;
		zindex++;
	}

	/* free to the appropriate zone */
	zfree(d_zone[zindex], data);
}

#endif /* DTRACE_MEMORY_ZONES */
