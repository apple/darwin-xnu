/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#if ALTERNATE_DEBUGGER

/*
 *
 *  The alternate debugger feature is enabled by setting the boot arg "alternate_debugger_init"
 *  to the size of memory that should be set aside for the debugger.  The boot arg
 *  "alternate_debugger_init_pages" is used to allocate more vmpages that the alternate debugger
 *  may use to do additional VA->PA mappings. The boot-arg "alternate_debugger_pause_for_load_at_boot"
 *  will halt the system so that the debugger can be loaded early in the boot cycle -- once the
 *  alternate debugger code is loaded, a register must be set to a 1 to continue the boot process.
 *
 *  Here's an example:
 *  nvram boot-arg="alternate_debugger_init=0x800000 alternate_debugger_init_pages=0x8000 alternate_debugger_pause_for_load_at_boot=1"
 *
 *  The low memory global lgAltDebugger will contain the address of the allocated memory for
 *  the alternate debugger.  On arm64, the address of this low memory global is 0xffffff8000002048.
 *
 *  At any point after the low memory global is non-zero, Astris may be used to halt the cpu
 *  and load the alternate debugger:
 *
 *  If no alternate debugger is given, but alternate_debugger_init has been specified, and the
 *  kernel debugger is entered, the string ">MT<" is printed and normal processing continues.
 *
 *  Anytime the alternate debugger is entered, the osversion string is modified to start with "ALT"
 *  so that panic reports can clearly indicated that some kernel poking may have occurred, and
 *  the panic should be weighted accordingly.
 *
 */

#include <arm64/alternate_debugger.h>

#include <kern/kalloc.h>
#include <arm64/lowglobals.h>
#include <arm/caches_internal.h>
#include <kern/cpu_data.h>
#include <arm/pmap.h>
#include <pexpert/pexpert.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <libkern/version.h>

void kprintf(const char *fmt, ...);


static mach_vm_address_t alt_code;
static mach_vm_size_t    alt_size;
static mach_vm_address_t alt_pages;
static mach_vm_size_t    alt_pages_size;

typedef void (*t_putc_fn)(char c);
typedef void (*t_call_altdbg_fn)(mach_vm_size_t size, mach_vm_address_t pages, mach_vm_size_t pages_size, t_putc_fn putc_address );

// used as a temporary alternate debugger until another is loaded
extern void alternate_debugger_just_return(__unused mach_vm_size_t size, __unused mach_vm_address_t pages, __unused mach_vm_size_t pages_size, t_putc_fn putc_address);
extern void *alternate_debugger_just_return_end;

// public entry to the alternate debugger
void
alternate_debugger_enter(void)
{
	if (alt_code != 0) {
		disable_preemption();

		printf("########## Going to call ALTERNATE DEBUGGER\n");

		// make sure it isn't in the cache
		assert((alt_size & 0xFFFFFFFF00000000) == 0);
		flush_dcache(alt_code, (unsigned int)alt_size, 0);

		// set the code to execute
		pmap_protect(kernel_map->pmap, alt_code, alt_code + alt_size, VM_PROT_READ | VM_PROT_EXECUTE);

		// black-spot the OS version for any panic reports that occur because of entering the alternate debugger
		if (*osversion) {
			memcpy(osversion, "ALT", 3);        // Version set, stomp on the begining of it
		} else {
			strncpy(osversion, "ALT - Version Not Set Yet", OSVERSIZE);
		}

		kprintf("########## Calling ALTERNATE DEBUGGER (size %lld, pages 0x%llx, pages_size 0x%llx, putc %p\n", alt_size, alt_pages, alt_pages_size, &consdebug_putc_unbuffered);
		((t_call_altdbg_fn)alt_code)(alt_size, alt_pages, alt_pages_size, &consdebug_putc_unbuffered);
		kprintf("########## Returned from calling ALTERNATE DEBUGGER\n");

		enable_preemption();
	}
}

// public entry to check boot args and init accordingly
void
alternate_debugger_init(void)
{
	// use the alternate debugger
	if (PE_parse_boot_argn("alternate_debugger_init", (void*)&alt_size, sizeof(alt_size))) {
		vm_offset_t     alt_va = 0;

		kprintf("########## ALTERNATE_DEBUGGER\n");

		PE_parse_boot_argn("alternate_debugger_init_pages", (void*)&alt_pages_size, sizeof(alt_pages_size));

		alt_size = vm_map_round_page(alt_size,
		    VM_MAP_PAGE_MASK(kernel_map));
		alt_pages_size = vm_map_round_page(alt_pages_size,
		    VM_MAP_PAGE_MASK(kernel_map));

		kern_return_t kr = KERN_SUCCESS;
		kr = kmem_alloc_contig(kernel_map, &alt_va, alt_size, VM_MAP_PAGE_MASK(kernel_map), 0, 0, KMA_NOPAGEWAIT | KMA_KOBJECT | KMA_LOMEM, VM_KERN_MEMORY_DIAG);
		if (kr != KERN_SUCCESS) {
			kprintf("########## ALTERNATE_DEBUGGER FAILED kmem_alloc_contig with %d\n", kr);
			alt_va = 0;
		} else {
			if (alt_pages_size) {
				alt_pages = (vm_offset_t) kalloc((vm_size_t) alt_pages_size);
			}
		}

		kprintf("########## Initializing ALTERNATE DEBUGGER : [alloc size 0x%llx @0x%lx] [pages_size 0x%llx @0x%llx] -- lowmem pointer at %p\n",
		    alt_size, alt_va, alt_pages_size, alt_pages, &lowGlo.lgAltDebugger );

		if (alt_va) {
			uintptr_t just_return_size = (uintptr_t)&alternate_debugger_just_return_end - (uintptr_t)&alternate_debugger_just_return;
			assert(just_return_size <= alt_size); // alt_size is page-rounded, just_return_size should be much less than a page.
			// install a simple return vector
			memcpy((void*)alt_va, &alternate_debugger_just_return, just_return_size);

			// code is ready, enable the pointers to it
			lowGlo.lgAltDebugger = alt_code = alt_va;

#if 1
			// DEBUG for BRING-UP testing
			unsigned int alt_init_test;
			if (PE_parse_boot_argn("alternate_debugger_pause_for_load_at_boot", &alt_init_test, sizeof(alt_init_test))) {
				// debug!!
				kprintf("########## Waiting for ALTERNATE DEBUGGER to load (in file %s).... to continue, set register to 1", __FILE__ );
				volatile int ii = 0;
				while (!ii) {
					;
				}
				kprintf("\n");
				alternate_debugger_enter();
			}
#endif
		}
	}
}

#endif /* ALTERNATE_DEBUGGER */
