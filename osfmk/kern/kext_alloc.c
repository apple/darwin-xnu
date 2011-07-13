/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/kext_alloc.h>
#include <kern/misc_protos.h>

#include <mach/host_priv_server.h>
#include <mach/kern_return.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/vm_types.h>

#include <mach-o/loader.h>
#include <libkern/kernel_mach_header.h>


vm_map_t g_kext_map = 0;
static mach_vm_offset_t kext_alloc_base = 0;
static mach_vm_offset_t kext_alloc_max = 0;

/*
 * On x86_64 systems, kernel extension text must remain within 2GB of the
 * kernel's text segment.  To ensure this happens, we snag 2GB of kernel VM
 * as early as possible for kext allocations.
 */
void 
kext_alloc_init(void)
{
#if __x86_64__
    kern_return_t rval = 0;
    kernel_segment_command_t *text = NULL;
    mach_vm_offset_t text_end, text_start;
    mach_vm_size_t text_size;
    mach_vm_size_t kext_alloc_size;

    /* Determine the start of the kernel's __TEXT segment and determine the
     * lower bound of the allocated submap for kext allocations.
     */

    text = getsegbyname(SEG_TEXT);
    text_start = vm_map_trunc_page(text->vmaddr);
    text_start &= ~((512ULL * 1024 * 1024 * 1024) - 1);
    text_end = vm_map_round_page(text->vmaddr + text->vmsize);
    text_size = text_end - text_start;

    kext_alloc_base = KEXT_ALLOC_BASE(text_end);
    kext_alloc_size = KEXT_ALLOC_SIZE(text_size);
    kext_alloc_max = kext_alloc_base + kext_alloc_size;

    /* Allocate the subblock of the kernel map */

    rval = kmem_suballoc(kernel_map, (vm_offset_t *) &kext_alloc_base, 
			 kext_alloc_size, /* pageable */ TRUE,
			 VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE,
			 &g_kext_map);
    if (rval != KERN_SUCCESS) {
	    panic("kext_alloc_init: kmem_suballoc failed 0x%x\n", rval);
    }

    if ((kext_alloc_base + kext_alloc_size) > kext_alloc_max) {
        panic("kext_alloc_init: failed to get first 2GB\n");
    }

    if (kernel_map->min_offset > kext_alloc_base) {
	    kernel_map->min_offset = kext_alloc_base;
    }

    printf("kext submap [0x%llx - 0x%llx], kernel text [0x%llx - 0x%llx]\n",
	   kext_alloc_base, kext_alloc_max, text->vmaddr,
	   text->vmaddr + text->vmsize);
#else
    g_kext_map = kernel_map;
    kext_alloc_base = VM_MIN_KERNEL_ADDRESS;
    kext_alloc_max = VM_MAX_KERNEL_ADDRESS;
#endif /* __x86_64__ */
}

kern_return_t
kext_alloc(vm_offset_t *_addr, vm_size_t size, boolean_t fixed)
{
    kern_return_t rval = 0;
    mach_vm_offset_t addr = (fixed) ? *_addr : kext_alloc_base;
    int flags = (fixed) ? VM_FLAGS_FIXED : VM_FLAGS_ANYWHERE;
 
    /* Allocate the kext virtual memory */
    rval = mach_vm_allocate(g_kext_map, &addr, size, flags);
    if (rval != KERN_SUCCESS) {
        printf("vm_allocate failed - %d\n", rval);
        goto finish;
    }

    /* Check that the memory is reachable by kernel text */
    if ((addr + size) > kext_alloc_max) {
        kext_free((vm_offset_t)addr, size);
        goto finish;
    }

    *_addr = (vm_offset_t)addr;
    rval = KERN_SUCCESS;

finish:
    return rval;
}

void 
kext_free(vm_offset_t addr, vm_size_t size)
{
    kern_return_t rval;

    rval = mach_vm_deallocate(g_kext_map, addr, size);
    assert(rval == KERN_SUCCESS);
}

