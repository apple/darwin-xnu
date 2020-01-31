/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <string.h>
#include <pexpert/pexpert.h>
#include <kern/copyout_shim.h>

#if (DEVELOPMENT || DEBUG)
#define UNUSED_IN_RELEASE(x)
#else
//supress compiler warnings about unused variables
#define UNUSED_IN_RELEASE(x) (void)(x)
#endif /* (DEVELOPMENT || DEBUG) */


#if (DEVELOPMENT || DEBUG)
copyout_shim_fn_t copyout_shim_fn = NULL;
unsigned co_src_flags = 0;
#endif

kern_return_t
register_copyout_shim(void (*fn)(const void *, user_addr_t, vm_size_t, unsigned co_src), unsigned types)
{
#if (DEVELOPMENT || DEBUG)
	int copyout_shim_enabled = 0;

	if (!fn) {
		/* unregistration is always allowed */
		copyout_shim_fn = NULL;
		return KERN_SUCCESS;
	}

	if (copyout_shim_fn) {
		//need to unregister first before registering a new one.
		return KERN_FAILURE;
	}

	if (!PE_parse_boot_argn("enable_copyout_shim", &copyout_shim_enabled, sizeof(copyout_shim_enabled)) || !copyout_shim_enabled) {
		return KERN_FAILURE;
	}


	co_src_flags = types;
	copyout_shim_fn = fn;
	return KERN_SUCCESS;
#else
	UNUSED_IN_RELEASE(fn);
	UNUSED_IN_RELEASE(types);
	return KERN_FAILURE;
#endif
}

void *
cos_kernel_unslide(const void *ptr)
{
#if (DEVELOPMENT || DEBUG)
	return (void *)(VM_KERNEL_UNSLIDE(ptr));
#else
	UNUSED_IN_RELEASE(ptr);
	return NULL;
#endif
}

void *
cos_kernel_reslide(const void *ptr)
{
#if (DEVELOPMENT || DEBUG)
	return (void *)(VM_KERNEL_SLIDE(ptr));
#else
	UNUSED_IN_RELEASE(ptr);
	return NULL;
#endif
}
