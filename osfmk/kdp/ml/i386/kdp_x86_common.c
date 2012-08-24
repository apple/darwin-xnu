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

boolean_t kdp_read_io;
boolean_t kdp_trans_off;

static addr64_t kdp_vtophys(pmap_t pmap, addr64_t va);

int kern_dump_pmap_traverse_preflight_callback(vm_map_offset_t start,
											   vm_map_offset_t end,
											   void *context);
int kern_dump_pmap_traverse_send_callback(vm_map_offset_t start,
										  vm_map_offset_t end,
										  void *context);

pmap_t kdp_pmap = 0;

static addr64_t
kdp_vtophys(
	pmap_t pmap,
	addr64_t va)
{
	addr64_t    pa;
	ppnum_t pp;

	pp = pmap_find_phys(pmap, va);
	if(!pp) return 0;
        
	pa = ((addr64_t)pp << 12) | (va & 0x0000000000000FFFULL);

	return(pa);
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

	if (kdp_trans_off) {
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
	if (kdp_pmap)
		src_pmap = kdp_pmap;

	while (resid != 0) {
		if (!(cur_phys_src = kdp_vtophys(src_pmap,
			    cur_virt_src)))
			goto exit;

/* Always translate the destination buffer using the kernel_pmap */
		if(!(cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)))
			goto exit;

		/* Validate physical page numbers unless kdp_read_io is set */
		if (kdp_read_io == FALSE)
			if (!pmap_valid_page(i386_btop(cur_phys_dst)) || !pmap_valid_page(i386_btop(cur_phys_src)))
				goto exit;

/* Get length left on page */
		cnt_src = PAGE_SIZE - (cur_phys_src & PAGE_MASK);
		cnt_dst = PAGE_SIZE - (cur_phys_dst & PAGE_MASK);
		if (cnt_src > cnt_dst)
			cnt = cnt_dst;
		else
			cnt = cnt_src;
		if (cnt > resid) 
			cnt = resid;

/* Do a physical copy */
		ml_copy_phys(cur_phys_src, cur_phys_dst, (vm_size_t)cnt);

		cur_virt_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}
exit:
	return (len - resid);
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

		if(!(cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)))
			goto exit;

/* Get length left on page */
		cnt_src = PAGE_SIZE - (cur_phys_src & PAGE_MASK);
		cnt_dst = PAGE_SIZE - (cur_phys_dst & PAGE_MASK);
		if (cnt_src > cnt_dst)
			cnt = cnt_dst;
		else
			cnt = cnt_src;
		if (cnt > resid) 
			cnt = resid;

	/* Do a physical copy; use ml_copy_phys() in the event this is
	 * a short read with potential side effects.
	 */
		ml_copy_phys(cur_phys_src, cur_phys_dst, (vm_size_t)cnt);
		cur_phys_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}
exit:
	return (len - resid);
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
		if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0) 
			goto exit;

		if ((cur_phys_src = kdp_vtophys(kernel_pmap, cur_virt_src)) == 0) 
			goto exit;

		/* Copy as many bytes as possible without crossing a page */
		cnt_src = (unsigned)(PAGE_SIZE - (cur_phys_src & PAGE_MASK));
		cnt_dst = (unsigned)(PAGE_SIZE - (cur_phys_dst & PAGE_MASK));

		if (cnt_src > cnt_dst)
			cnt = cnt_dst;
		else
			cnt = cnt_src;
		if (cnt > resid) 
			cnt = resid;

		ml_copy_phys(cur_phys_src, cur_phys_dst, cnt);		/* Copy stuff over */

		cur_virt_src +=cnt;
		cur_virt_dst +=cnt;
		resid -= cnt;
	}
exit:
	return (len - resid);
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
		if ((cur_phys_src = kdp_vtophys(kernel_pmap, cur_virt_src)) == 0) 
			goto exit;

		/* Copy as many bytes as possible without crossing a page */
		cnt_src = (unsigned)(PAGE_SIZE - (cur_phys_src & PAGE_MASK));
		cnt_dst = (unsigned)(PAGE_SIZE - (cur_phys_dst & PAGE_MASK));

		if (cnt_src > cnt_dst)
			cnt = cnt_dst;
		else
			cnt = cnt_src;
		if (cnt > resid) 
			cnt = resid;

		ml_copy_phys(cur_phys_src, cur_phys_dst, cnt);		/* Copy stuff over */

		cur_virt_src +=cnt;
		cur_phys_dst +=cnt;
		resid -= cnt;
	}

exit:
	return (len - resid);
}

int
kdp_machine_ioport_read(kdp_readioport_req_t *rq, caddr_t data, uint16_t lcpu)
{
	uint16_t addr = rq->address;
	uint16_t size = rq->nbytes;

	if ((lcpu != KDP_CURRENT_LCPU) && (lcpu != cpu_number())) {
		return (int) kdp_x86_xcpu_invoke(lcpu, (kdp_x86_xcpu_func_t)kdp_machine_ioport_read, rq, data);
        }

        switch (size)
	{
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
		break;
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

	switch (size)
	{
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
		break;
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

int
pmap_traverse_present_mappings(pmap_t pmap,
							   vm_map_offset_t start,
							   vm_map_offset_t end,
							   pmap_traverse_callback callback,
							   void *context)
{
	int ret = KERN_SUCCESS;
	vm_map_offset_t vcurstart, vcur;
	boolean_t lastvavalid = FALSE;

	/* Assumes pmap is locked, or being called from the kernel debugger */
	
	if (start > end) {
		return (KERN_INVALID_ARGUMENT);
	}

	if (start & PAGE_MASK_64) {
		return (KERN_INVALID_ARGUMENT);
	}

	for (vcur = vcurstart = start; (ret == KERN_SUCCESS) && (vcur < end); ) {
		ppnum_t ppn = pmap_find_phys(pmap, vcur);

		if (ppn != 0 && !pmap_valid_page(ppn)) {
			/* not something we want */
			ppn = 0;
		}

		if (ppn != 0) {
			if (!lastvavalid) {
				/* Start of a new virtual region */
				vcurstart = vcur;
				lastvavalid = TRUE;
			}
		} else {
			if (lastvavalid) {
				/* end of a virtual region */
				
				ret = callback(vcurstart, vcur, context);

				lastvavalid = FALSE;
			}

			/* Try to skip by 2MB if possible */
			if (((vcur & PDMASK) == 0) && cpu_64bit) {
				pd_entry_t *pde;

				pde = pmap_pde(pmap, vcur);
				if (0 == pde || ((*pde & INTEL_PTE_VALID) == 0)) {
					/* Make sure we wouldn't overflow */
					if (vcur < (end - NBPD)) {
						vcur += NBPD;
						continue;
					}
				}
			}
		}
		
		vcur += PAGE_SIZE_64;
	}
	
	if ((ret == KERN_SUCCESS)
		&& lastvavalid) {
		/* send previous run */

		ret = callback(vcurstart, vcur, context);
	}
	return (ret);
}

struct kern_dump_preflight_context {
	uint32_t	region_count;
	uint64_t	dumpable_bytes;
};

struct kern_dump_send_context {
	uint64_t	hoffset;
	uint64_t	foffset;
	uint64_t	header_size;
};

int
kern_dump_pmap_traverse_preflight_callback(vm_map_offset_t start,
										   vm_map_offset_t end,
										   void *context)
{
	struct kern_dump_preflight_context *kdc = (struct kern_dump_preflight_context *)context;
	int ret = KERN_SUCCESS;

	kdc->region_count++;
	kdc->dumpable_bytes += (end - start);

	return (ret);
}

int
kern_dump_pmap_traverse_send_callback(vm_map_offset_t start,
									  vm_map_offset_t end,
									  void *context)
{
	struct kern_dump_send_context *kdc = (struct kern_dump_send_context *)context;
	int ret = KERN_SUCCESS;
	kernel_segment_command_t sc;
	vm_size_t size = (vm_size_t)(end - start);

	if (kdc->hoffset + sizeof(sc) > kdc->header_size) {
		return (KERN_NO_SPACE);
	}

	/*
	 *	Fill in segment command structure.
	 */
    
	sc.cmd = LC_SEGMENT_KERNEL;
	sc.cmdsize = sizeof(kernel_segment_command_t);
	sc.segname[0] = 0;
	sc.vmaddr = (vm_address_t)start;
	sc.vmsize = size;
	sc.fileoff = (vm_address_t)kdc->foffset;
	sc.filesize = size;
	sc.maxprot = VM_PROT_READ;
	sc.initprot = VM_PROT_READ;
	sc.nsects = 0;
	sc.flags = 0;

	if ((ret = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(kdc->hoffset) , &kdc->hoffset)) < 0) { 
		printf ("kdp_send_crashdump_pkt failed with error %d\n", ret);
		goto out;
	} 
    
	if ((ret = kdp_send_crashdump_data (KDP_DATA, NULL, sizeof(kernel_segment_command_t) , (caddr_t) &sc)) < 0) {
		printf ("kdp_send_crashdump_data failed with error %d\n", ret);
		goto out;
	}
	
	kdc->hoffset += sizeof(kernel_segment_command_t);

	if ((ret = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(kdc->foffset) , &kdc->foffset)) < 0) {
		printf ("kdp_send_crashdump_pkt failed with error %d\n", ret);
		goto out;
	}
		
	if ((ret = kdp_send_crashdump_data (KDP_DATA, NULL, (unsigned int)size, (caddr_t)(uintptr_t)start)) < 0)	{
		printf ("kdp_send_crashdump_data failed with error %d\n", ret);
		goto out;
	}
	
	kdc->foffset += size;

out:
	return (ret);
}

int
kern_dump(void)
{
	int			ret;
	struct kern_dump_preflight_context kdc_preflight;
	struct kern_dump_send_context kdc_send;
	uint32_t	segment_count;
	size_t		command_size = 0, header_size = 0, tstate_size = 0;
	uint64_t	hoffset = 0, foffset = 0;
	kernel_mach_header_t	mh;


	kdc_preflight.region_count = 0;
	kdc_preflight.dumpable_bytes = 0;

	ret = pmap_traverse_present_mappings(kernel_pmap,
										 VM_MIN_KERNEL_AND_KEXT_ADDRESS,
										 VM_MAX_KERNEL_ADDRESS,
										 kern_dump_pmap_traverse_preflight_callback,
										 &kdc_preflight);
	if (ret) {
		printf("pmap traversal failed: %d\n", ret);
		return (ret);
	}

	printf("Kernel dump region count: %u\n", kdc_preflight.region_count);
	printf("Kernel dump byte count: %llu\n", kdc_preflight.dumpable_bytes);
			
	segment_count = kdc_preflight.region_count;

	tstate_size = sizeof(struct thread_command) + kern_collectth_state_size();

	command_size = segment_count * sizeof(kernel_segment_command_t) +
				tstate_size;

	header_size = command_size + sizeof(kernel_mach_header_t);

	/*
	 *	Set up Mach-O header for currently executing kernel.
	 */
	printf ("Generated Mach-O header size was %lu\n", header_size);

	mh.magic = _mh_execute_header.magic;
	mh.cputype = _mh_execute_header.cputype;;
	mh.cpusubtype = _mh_execute_header.cpusubtype;
	mh.filetype = MH_CORE;
	mh.ncmds = segment_count + 1 /* thread */;
	mh.sizeofcmds = (uint32_t)command_size;
	mh.flags = 0;
#if defined(__LP64__)
	mh.reserved = 0;
#endif

	hoffset = 0;	/* offset into header */
	foffset = (uint32_t)round_page(header_size);	/* offset into file */

	/* Transmit the Mach-O MH_CORE header, and seek forward past the 
	 * area reserved for the segment and thread commands 
	 * to begin data transmission 
	 */
	if ((ret = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(hoffset) , &hoffset)) < 0) { 
		printf ("kdp_send_crashdump_pkt failed with error %d\n", ret);
		goto out;
	} 
	if ((ret = kdp_send_crashdump_data (KDP_DATA, NULL, sizeof(kernel_mach_header_t), (caddr_t) &mh) < 0)) {
		printf ("kdp_send_crashdump_data failed with error %d\n", ret);
		goto out;
	}

	hoffset += sizeof(kernel_mach_header_t);

	if ((ret = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(foffset) , &foffset) < 0)) {
		printf ("kdp_send_crashdump_pkt failed with error %d\n", ret);
		goto out;
	}

	printf ("Transmitting kernel state, please wait: ");

	kdc_send.hoffset = hoffset;
	kdc_send.foffset = foffset;
	kdc_send.header_size = header_size;

	ret = pmap_traverse_present_mappings(kernel_pmap,
										 VM_MIN_KERNEL_AND_KEXT_ADDRESS,
										 VM_MAX_KERNEL_ADDRESS,
										 kern_dump_pmap_traverse_send_callback,
										 &kdc_send);
	if (ret) {
		kprintf("pmap traversal failed: %d\n", ret);
		return (ret);
	}

	/* Reload mutated offsets */
	hoffset = kdc_send.hoffset;
	foffset = kdc_send.foffset;

	/*
	 * Now send out the LC_THREAD load command, with the thread information
	 * for the current activation.
	 */
	if (tstate_size > 0) {
		char tstate[tstate_size];

		kern_collectth_state (current_thread(), tstate, tstate_size);

		if ((ret = kdp_send_crashdump_pkt (KDP_SEEK, NULL, sizeof(hoffset), &hoffset)) < 0) { 
			printf ("kdp_send_crashdump_pkt failed with error %d\n", ret);
			goto out;
		}
		
		if ((ret = kdp_send_crashdump_data (KDP_DATA, NULL, tstate_size, tstate)) < 0) {
			printf ("kdp_send_crashdump_data failed with error %d\n", ret);
			goto out;
		}

		hoffset += tstate_size;
	}

	/* last packet */
	if ((ret = kdp_send_crashdump_pkt (KDP_EOF, NULL, 0, ((void *) 0))) < 0)
	{
		printf ("kdp_send_crashdump_pkt failed with error %d\n", ret);
		goto out;
	}	

out:
	return (ret);
}


pt_entry_t *debugger_ptep;
vm_map_offset_t debugger_window_kva;

/* Establish a pagetable window that can be remapped on demand.
 * This is utilized by the debugger to address regions outside
 * the physical map.
 */

void
kdp_machine_init(void) {
	if (debug_boot_arg == 0)
		return;

	vm_map_entry_t e;
	kern_return_t kr = vm_map_find_space(kernel_map,
	    &debugger_window_kva,
	    PAGE_SIZE, 0,
	    VM_MAKE_TAG(VM_MEMORY_IOKIT), &e);

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

