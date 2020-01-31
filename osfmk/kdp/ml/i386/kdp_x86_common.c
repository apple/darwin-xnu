/*
 * Copyright (c) 2008-2016 Apple Inc. All rights reserved.
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

#include <sys/errno.h>

#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <libsa/types.h>

#include <vm/vm_map.h>
#include <i386/pmap.h>
#include <i386/pmap_internal.h> /* pmap_pde */
#include <i386/mp.h>
#include <i386/misc_protos.h>
#include <i386/pio.h>
#include <i386/proc_reg.h>

#include <i386/pmap_internal.h>

#include <kdp/kdp_internal.h>
#include <kdp/kdp_core.h>
#include <kdp/ml/i386/kdp_x86_common.h>
#include <mach/vm_map.h>

#include <vm/vm_protos.h>
#include <vm/vm_kern.h>

#include <machine/pal_routines.h>
#include <libkern/kernel_mach_header.h>

// #define KDP_VM_READ_DEBUG 1
// #define KDP_VM_WRITE_DEBUG 1

/*
 * A (potentially valid) physical address is not a kernel address
 * i.e. it'a a user address.
 */
#define IS_PHYS_ADDR(addr)              IS_USERADDR64_CANONICAL(addr)

boolean_t kdp_read_io;
boolean_t kdp_trans_off;

pmap_paddr_t kdp_vtophys(pmap_t pmap, vm_offset_t va);

pmap_t kdp_pmap = 0;

kdp_jtag_coredump_t kdp_jtag_coredump;

pmap_paddr_t
kdp_vtophys(
	pmap_t pmap,
	vm_offset_t va)
{
	pmap_paddr_t    pa;
	ppnum_t pp;

	pp = pmap_find_phys(pmap, va);
	if (!pp) {
		return 0;
	}

	pa = ((pmap_paddr_t)pp << PAGE_SHIFT) | (va & PAGE_MASK);

	return pa;
}

mach_vm_size_t
kdp_machine_vm_read( mach_vm_address_t src, caddr_t dst, mach_vm_size_t len)
{
	addr64_t cur_virt_src = PAL_KDP_ADDR((addr64_t)src);
	addr64_t cur_virt_dst = PAL_KDP_ADDR((addr64_t)(intptr_t)dst);
	addr64_t cur_phys_dst, cur_phys_src;
	mach_vm_size_t resid = len;
	mach_vm_size_t cnt = 0, cnt_src, cnt_dst;
	pmap_t src_pmap = kernel_pmap;

#ifdef KDP_VM_READ_DEBUG
	printf("kdp_vm_read: src %llx dst %p len %llx\n", src, (void *)dst, len);
#endif

	if (kdp_trans_off && IS_PHYS_ADDR(src)) {
		kdp_readphysmem64_req_t rq;
		mach_vm_size_t ret;

		rq.address = src;
		rq.nbytes = (uint32_t)len;
		ret = kdp_machine_phys_read(&rq, dst, KDP_CURRENT_LCPU);
		return ret;
	}

/* If a different pmap has been specified with kdp_pmap, use it to translate the
 * source (cur_virt_src); otherwise, the source is translated using the
 * kernel_pmap.
 */
	if (kdp_pmap) {
		src_pmap = kdp_pmap;
	}

	while (resid != 0) {
		if (!(cur_phys_src = kdp_vtophys(src_pmap,
		    cur_virt_src))) {
			goto exit;
		}

/* Always translate the destination buffer using the kernel_pmap */
		if (!(cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst))) {
			goto exit;
		}

		/* Validate physical page numbers unless kdp_read_io is set */
		if (kdp_read_io == FALSE) {
			if (!pmap_valid_page(i386_btop(cur_phys_dst)) || !pmap_valid_page(i386_btop(cur_phys_src))) {
				goto exit;
			}
		}

/* Get length left on page */
		cnt_src = PAGE_SIZE - (cur_phys_src & PAGE_MASK);
		cnt_dst = PAGE_SIZE - (cur_phys_dst & PAGE_MASK);
		if (cnt_src > cnt_dst) {
			cnt = cnt_dst;
		} else {
			cnt = cnt_src;
		}
		if (cnt > resid) {
			cnt = resid;
		}

/* Do a physical copy */
		if (EFAULT == ml_copy_phys(cur_phys_src,
		    cur_phys_dst,
		    (vm_size_t)cnt)) {
			goto exit;
		}
		cur_virt_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}
exit:
	return len - resid;
}

mach_vm_size_t
kdp_machine_phys_read(kdp_readphysmem64_req_t *rq, caddr_t dst,
    uint16_t lcpu)
{
	mach_vm_address_t src = rq->address;
	mach_vm_size_t    len = rq->nbytes;

	addr64_t cur_virt_dst;
	addr64_t cur_phys_dst, cur_phys_src;
	mach_vm_size_t resid = len;
	mach_vm_size_t cnt = 0, cnt_src, cnt_dst;

	if ((lcpu != KDP_CURRENT_LCPU) && (lcpu != cpu_number())) {
		return (mach_vm_size_t)
		       kdp_x86_xcpu_invoke(lcpu, (kdp_x86_xcpu_func_t)kdp_machine_phys_read, rq, dst);
	}

#ifdef KDP_VM_READ_DEBUG
	printf("kdp_phys_read: src %llx dst %p len %llx\n", src, (void *)dst, len);
#endif

	cur_virt_dst = (addr64_t)(intptr_t)dst;
	cur_phys_src = (addr64_t)src;

	while (resid != 0) {
		if (!(cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst))) {
			goto exit;
		}

/* Get length left on page */
		cnt_src = PAGE_SIZE - (cur_phys_src & PAGE_MASK);
		cnt_dst = PAGE_SIZE - (cur_phys_dst & PAGE_MASK);
		if (cnt_src > cnt_dst) {
			cnt = cnt_dst;
		} else {
			cnt = cnt_src;
		}
		if (cnt > resid) {
			cnt = resid;
		}

		/* Do a physical copy; use ml_copy_phys() in the event this is
		 * a short read with potential side effects.
		 */
		if (EFAULT == ml_copy_phys(cur_phys_src,
		    cur_phys_dst,
		    (vm_size_t)cnt)) {
			goto exit;
		}
		cur_phys_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}
exit:
	return len - resid;
}

/*
 *
 */
mach_vm_size_t
kdp_machine_vm_write( caddr_t src, mach_vm_address_t dst, mach_vm_size_t len)
{
	addr64_t cur_virt_src, cur_virt_dst;
	addr64_t cur_phys_src, cur_phys_dst;
	unsigned resid, cnt, cnt_src, cnt_dst;

#ifdef KDP_VM_WRITE_DEBUG
	printf("kdp_vm_write: src %p dst %llx len %llx - %08X %08X\n", (void *)src, dst, len, ((unsigned int *)src)[0], ((unsigned int *)src)[1]);
#endif

	cur_virt_src = PAL_KDP_ADDR((addr64_t)(intptr_t)src);
	cur_virt_dst = PAL_KDP_ADDR((addr64_t)dst);

	resid = (unsigned)len;

	while (resid != 0) {
		if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0) {
			goto exit;
		}

		if ((cur_phys_src = kdp_vtophys(kernel_pmap, cur_virt_src)) == 0) {
			goto exit;
		}

		/* Copy as many bytes as possible without crossing a page */
		cnt_src = (unsigned)(PAGE_SIZE - (cur_phys_src & PAGE_MASK));
		cnt_dst = (unsigned)(PAGE_SIZE - (cur_phys_dst & PAGE_MASK));

		if (cnt_src > cnt_dst) {
			cnt = cnt_dst;
		} else {
			cnt = cnt_src;
		}
		if (cnt > resid) {
			cnt = resid;
		}

		if (EFAULT == ml_copy_phys(cur_phys_src, cur_phys_dst, cnt)) {
			goto exit;              /* Copy stuff over */
		}
		cur_virt_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}
exit:
	return len - resid;
}

/*
 *
 */
mach_vm_size_t
kdp_machine_phys_write(kdp_writephysmem64_req_t *rq, caddr_t src,
    uint16_t lcpu)
{
	mach_vm_address_t dst = rq->address;
	mach_vm_size_t    len = rq->nbytes;
	addr64_t cur_virt_src;
	addr64_t cur_phys_src, cur_phys_dst;
	unsigned resid, cnt, cnt_src, cnt_dst;

	if ((lcpu != KDP_CURRENT_LCPU) && (lcpu != cpu_number())) {
		return (mach_vm_size_t)
		       kdp_x86_xcpu_invoke(lcpu, (kdp_x86_xcpu_func_t)kdp_machine_phys_write, rq, src);
	}

#ifdef KDP_VM_WRITE_DEBUG
	printf("kdp_phys_write: src %p dst %llx len %llx - %08X %08X\n", (void *)src, dst, len, ((unsigned int *)src)[0], ((unsigned int *)src)[1]);
#endif

	cur_virt_src = (addr64_t)(intptr_t)src;
	cur_phys_dst = (addr64_t)dst;

	resid = (unsigned)len;

	while (resid != 0) {
		if ((cur_phys_src = kdp_vtophys(kernel_pmap, cur_virt_src)) == 0) {
			goto exit;
		}

		/* Copy as many bytes as possible without crossing a page */
		cnt_src = (unsigned)(PAGE_SIZE - (cur_phys_src & PAGE_MASK));
		cnt_dst = (unsigned)(PAGE_SIZE - (cur_phys_dst & PAGE_MASK));

		if (cnt_src > cnt_dst) {
			cnt = cnt_dst;
		} else {
			cnt = cnt_src;
		}
		if (cnt > resid) {
			cnt = resid;
		}

		if (EFAULT == ml_copy_phys(cur_phys_src, cur_phys_dst, cnt)) {
			goto exit;              /* Copy stuff over */
		}
		cur_virt_src += cnt;
		cur_phys_dst += cnt;
		resid -= cnt;
	}

exit:
	return len - resid;
}

int
kdp_machine_ioport_read(kdp_readioport_req_t *rq, caddr_t data, uint16_t lcpu)
{
	uint16_t addr = rq->address;
	uint16_t size = rq->nbytes;

	if ((lcpu != KDP_CURRENT_LCPU) && (lcpu != cpu_number())) {
		return (int) kdp_x86_xcpu_invoke(lcpu, (kdp_x86_xcpu_func_t)kdp_machine_ioport_read, rq, data);
	}

	switch (size) {
	case 1:
		*((uint8_t *) data)  = inb(addr);
		break;
	case 2:
		*((uint16_t *) data) = inw(addr);
		break;
	case 4:
		*((uint32_t *) data) = inl(addr);
		break;
	default:
		return KDPERR_BADFLAVOR;
	}

	return KDPERR_NO_ERROR;
}

int
kdp_machine_ioport_write(kdp_writeioport_req_t *rq, caddr_t data, uint16_t lcpu)
{
	uint16_t addr = rq->address;
	uint16_t size = rq->nbytes;

	if ((lcpu != KDP_CURRENT_LCPU) && (lcpu != cpu_number())) {
		return (int) kdp_x86_xcpu_invoke(lcpu, (kdp_x86_xcpu_func_t)kdp_machine_ioport_write, rq, data);
	}

	switch (size) {
	case 1:
		outb(addr, *((uint8_t *) data));
		break;
	case 2:
		outw(addr, *((uint16_t *) data));
		break;
	case 4:
		outl(addr, *((uint32_t *) data));
		break;
	default:
		return KDPERR_BADFLAVOR;
	}

	return KDPERR_NO_ERROR;
}

int
kdp_machine_msr64_read(kdp_readmsr64_req_t *rq, caddr_t data, uint16_t lcpu)
{
	uint64_t *value = (uint64_t *) data;
	uint32_t msr    = rq->address;

	if ((lcpu != KDP_CURRENT_LCPU) && (lcpu != cpu_number())) {
		return (int) kdp_x86_xcpu_invoke(lcpu, (kdp_x86_xcpu_func_t)kdp_machine_msr64_read, rq, data);
	}

	*value = rdmsr64(msr);
	return KDPERR_NO_ERROR;
}

int
kdp_machine_msr64_write(kdp_writemsr64_req_t *rq, caddr_t data, uint16_t lcpu)
{
	uint64_t *value = (uint64_t *) data;
	uint32_t msr    = rq->address;

	if ((lcpu != KDP_CURRENT_LCPU) && (lcpu != cpu_number())) {
		return (int) kdp_x86_xcpu_invoke(lcpu, (kdp_x86_xcpu_func_t)kdp_machine_msr64_write, rq, data);
	}

	wrmsr64(msr, *value);
	return KDPERR_NO_ERROR;
}

pt_entry_t *debugger_ptep;
vm_map_offset_t debugger_window_kva;

/* Establish a pagetable window that can be remapped on demand.
 * This is utilized by the debugger to address regions outside
 * the physical map.
 */

void
kdp_map_debug_pagetable_window(void)
{
	vm_map_entry_t e;
	kern_return_t kr;

	kr = vm_map_find_space(kernel_map,
	    &debugger_window_kva,
	    PAGE_SIZE, 0,
	    0,
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_OSFMK,
	    &e);

	if (kr != KERN_SUCCESS) {
		panic("%s: vm_map_find_space failed with %d\n", __FUNCTION__, kr);
	}

	vm_map_unlock(kernel_map);

	debugger_ptep = pmap_pte(kernel_pmap, debugger_window_kva);

	if (debugger_ptep == NULL) {
		pmap_expand(kernel_pmap, debugger_window_kva, PMAP_EXPAND_OPTIONS_NONE);
		debugger_ptep = pmap_pte(kernel_pmap, debugger_window_kva);
	}
}

/* initialize kdp_jtag_coredump with data needed for JTAG coredump extraction */

void
kdp_jtag_coredump_init(void)
{
	kdp_jtag_coredump.version                   = (uint64_t) KDP_JTAG_COREDUMP_VERSION_1;
	kdp_jtag_coredump.kernel_map_start          = (uint64_t) kernel_map->min_offset;
	kdp_jtag_coredump.kernel_map_end            = (uint64_t) kernel_map->max_offset;
	kdp_jtag_coredump.kernel_pmap_pml4          = (uint64_t) kernel_pmap->pm_pml4;
	kdp_jtag_coredump.pmap_memory_regions       = (uint64_t) &pmap_memory_regions;
	kdp_jtag_coredump.pmap_memory_region_count  = (uint64_t) pmap_memory_region_count;
	kdp_jtag_coredump.pmap_memory_region_t_size = (uint64_t) sizeof(pmap_memory_region_t);
	kdp_jtag_coredump.physmap_base              = (uint64_t) &physmap_base;

	/* update signature last so that JTAG can trust that structure has valid data */
	kdp_jtag_coredump.signature                 = (uint64_t) KDP_JTAG_COREDUMP_SIGNATURE;
}

void
kdp_machine_init(void)
{
	if (debug_boot_arg == 0) {
		return;
	}

	kdp_map_debug_pagetable_window();
	kdp_jtag_coredump_init();
}
