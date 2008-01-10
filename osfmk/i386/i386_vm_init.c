/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989, 1988 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <platforms.h>
#include <mach_kdb.h>

#include <mach/i386/vm_param.h>

#include <string.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/misc_protos.h>
#include <kern/cpu_data.h>
#include <kern/processor.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <i386/pmap.h>
#include <i386/ipl.h>
#include <i386/misc_protos.h>
#include <i386/mp_slave_boot.h>
#include <i386/cpuid.h>
#include <mach/thread_status.h>
#include <pexpert/i386/efi.h>
#include "i386_lowmem.h"

vm_size_t	mem_size = 0; 
vm_offset_t	first_avail = 0;/* first after page tables */
vm_offset_t	last_addr;

uint64_t	max_mem;        /* Size of physical memory (bytes), adjusted by maxmem */
uint64_t        mem_actual;
uint64_t	sane_size = 0;  /* Memory size to use for defaults calculations */

#define MAXBOUNCEPOOL	(128 * 1024 * 1024)
#define MAXLORESERVE	( 32 * 1024 * 1024)

extern int bsd_mbuf_cluster_reserve(void);


uint32_t	bounce_pool_base = 0;
uint32_t	bounce_pool_size = 0;

static void	reserve_bouncepool(uint32_t);


pmap_paddr_t	avail_start, avail_end;
vm_offset_t	virtual_avail, virtual_end;
static pmap_paddr_t	avail_remaining;
vm_offset_t     static_memory_end = 0;

#include	<mach-o/loader.h>
vm_offset_t	edata, etext, end;

/*
 * _mh_execute_header is the mach_header for the currently executing
 * 32 bit kernel
 */
extern struct mach_header _mh_execute_header;
void *sectTEXTB; int sectSizeTEXT;
void *sectDATAB; int sectSizeDATA;
void *sectOBJCB; int sectSizeOBJC;
void *sectLINKB; int sectSizeLINK;
void *sectPRELINKB; int sectSizePRELINK;
void *sectHIBB; int sectSizeHIB;

extern void *getsegdatafromheader(struct mach_header *, const char *, int *);
extern struct segment_command *getsegbyname(const char *);
extern struct section *firstsect(struct segment_command *);
extern struct section *nextsect(struct segment_command *, struct section *);


void
i386_macho_zerofill(void)
{
	struct segment_command	*sgp;
	struct section		*sp;

	sgp = getsegbyname("__DATA");
	if (sgp) {
		sp = firstsect(sgp);
		if (sp) {
			do {
				if ((sp->flags & S_ZEROFILL))
					bzero((char *) sp->addr, sp->size);
			} while ((sp = nextsect(sgp, sp)));
		}
	}

	return;
}

/*
 * Basic VM initialization.
 */
void
i386_vm_init(uint64_t	maxmem,
	     boolean_t	IA32e,
	     boot_args	*args)
{
	pmap_memory_region_t *pmptr;
        pmap_memory_region_t *prev_pmptr;
	EfiMemoryRange *mptr;
        unsigned int mcount;
        unsigned int msize;
	ppnum_t fap;
	unsigned int i;
	unsigned int safeboot;
	ppnum_t maxpg = 0;
        uint32_t pmap_type;
	uint32_t maxbouncepoolsize;
	uint32_t maxloreserve;
	uint32_t maxdmaaddr;

	/*
	 * Now retrieve addresses for end, edata, and etext 
	 * from MACH-O headers.
	 */

	sectTEXTB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__TEXT", &sectSizeTEXT);
	sectDATAB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__DATA", &sectSizeDATA);
	sectOBJCB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__OBJC", &sectSizeOBJC);
	sectLINKB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__LINKEDIT", &sectSizeLINK);
	sectHIBB = (void *)getsegdatafromheader(
		&_mh_execute_header, "__HIB", &sectSizeHIB);
	sectPRELINKB = (void *) getsegdatafromheader(
		&_mh_execute_header, "__PRELINK", &sectSizePRELINK);

	etext = (vm_offset_t) sectTEXTB + sectSizeTEXT;
	edata = (vm_offset_t) sectDATAB + sectSizeDATA;

	vm_set_page_size();

	/*
	 * Compute the memory size.
	 */

	if ((1 == vm_himemory_mode) || PE_parse_boot_arg("-x", &safeboot)) {
	        maxpg = 1 << (32 - I386_PGSHIFT);
	}
	avail_remaining = 0;
	avail_end = 0;
	pmptr = pmap_memory_regions;
        prev_pmptr = 0;
	pmap_memory_region_count = pmap_memory_region_current = 0;
	fap = (ppnum_t) i386_btop(first_avail);

	mptr = (EfiMemoryRange *)args->MemoryMap;
        if (args->MemoryMapDescriptorSize == 0)
	        panic("Invalid memory map descriptor size");
        msize = args->MemoryMapDescriptorSize;
        mcount = args->MemoryMapSize / msize;

#define FOURGIG 0x0000000100000000ULL

	for (i = 0; i < mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize)) {
	        ppnum_t base, top;

		if (pmap_memory_region_count >= PMAP_MEMORY_REGIONS_SIZE) {
		        kprintf("WARNING: truncating memory region count at %d\n", pmap_memory_region_count);
			break;
		}
		base = (ppnum_t) (mptr->PhysicalStart >> I386_PGSHIFT);
		top = (ppnum_t) ((mptr->PhysicalStart) >> I386_PGSHIFT) + mptr->NumberOfPages - 1;

		switch (mptr->Type) {
		case kEfiLoaderCode:
		case kEfiLoaderData:
		case kEfiBootServicesCode:
		case kEfiBootServicesData:
		case kEfiConventionalMemory:
		        /*
			 * Consolidate usable memory types into one.
			 */
		        pmap_type = kEfiConventionalMemory;
		        sane_size += (uint64_t)(mptr->NumberOfPages << I386_PGSHIFT);
			break;

		case kEfiRuntimeServicesCode:
		case kEfiRuntimeServicesData:
		case kEfiACPIReclaimMemory:
		case kEfiACPIMemoryNVS:
		case kEfiPalCode:
			/*
			 * sane_size should reflect the total amount of physical ram
			 * in the system, not just the amount that is available for
			 * the OS to use
			 */
		        sane_size += (uint64_t)(mptr->NumberOfPages << I386_PGSHIFT);
			/* fall thru */

		case kEfiUnusableMemory:
		case kEfiMemoryMappedIO:
		case kEfiMemoryMappedIOPortSpace:
		case kEfiReservedMemoryType:
		default:
		        pmap_type = mptr->Type;
		}

		kprintf("EFI region: type = %d/%d,  base = 0x%x,  top = 0x%x\n", mptr->Type, pmap_type, base, top);

		if (maxpg) {
		        if (base >= maxpg)
				break;
		        top = (top > maxpg) ? maxpg : top;
		}

		/*
		 * handle each region
		 */
		if (kEfiACPIMemoryNVS == pmap_type) {
		        prev_pmptr = 0;
			continue;
		} else if ((mptr->Attribute & EFI_MEMORY_RUNTIME) == EFI_MEMORY_RUNTIME ||
			   pmap_type != kEfiConventionalMemory) {
		        prev_pmptr = 0;
			continue;
		} else {
		        /*
			 * Usable memory region
			 */
		        if (top < I386_LOWMEM_RESERVED) {
			        prev_pmptr = 0;
				continue;
			}
			if (top < fap) {
			        /*
				 * entire range below first_avail
			         * salvage some low memory pages
				 * we use some very low memory at startup
				 * mark as already allocated here
				 */
			        if (base >= I386_LOWMEM_RESERVED)
				        pmptr->base = base;
				else
				        pmptr->base = I386_LOWMEM_RESERVED;
				/*
				 * mark as already mapped
				 */
				pmptr->alloc = pmptr->end = top;
				pmptr->type = pmap_type;
			}
			else if ( (base < fap) && (top > fap) ) {
			        /*
				 * spans first_avail
				 * put mem below first avail in table but
				 * mark already allocated
				 */
			        pmptr->base = base;
				pmptr->alloc = pmptr->end = (fap - 1);
				pmptr->type = pmap_type;
				/*
				 * we bump these here inline so the accounting
				 * below works correctly
				 */
				pmptr++;
				pmap_memory_region_count++;
				pmptr->alloc = pmptr->base = fap;
				pmptr->type = pmap_type;
				pmptr->end = top;
			}
			else {
			        /*
				 * entire range useable
				 */
			        pmptr->alloc = pmptr->base = base;
				pmptr->type = pmap_type;
				pmptr->end = top;
			}

			if (i386_ptob(pmptr->end) > avail_end )
			        avail_end = i386_ptob(pmptr->end);

			avail_remaining += (pmptr->end - pmptr->base);

			/*
			 * Consolidate contiguous memory regions, if possible
			 */
			if (prev_pmptr &&
			    pmptr->type == prev_pmptr->type &&
			    pmptr->base == pmptr->alloc &&
			    pmptr->base == (prev_pmptr->end + 1)) {
			        prev_pmptr->end = pmptr->end;
			} else {
			        pmap_memory_region_count++;
				prev_pmptr = pmptr;
				pmptr++;
			}
		}
	}


#ifdef PRINT_PMAP_MEMORY_TABLE
	{
        unsigned int j;
        pmap_memory_region_t *p = pmap_memory_regions;
        vm_offset_t region_start, region_end;
        vm_offset_t efi_start, efi_end;
        for (j=0;j<pmap_memory_region_count;j++, p++) {
            kprintf("type %d base 0x%x alloc 0x%x top 0x%x\n", p->type,
                    p->base << I386_PGSHIFT, p->alloc << I386_PGSHIFT, p->end << I386_PGSHIFT);
            region_start = p->base << I386_PGSHIFT;
            region_end = (p->end << I386_PGSHIFT) - 1;
            mptr = args->MemoryMap;
            for (i=0; i<mcount; i++, mptr = (EfiMemoryRange *)(((vm_offset_t)mptr) + msize)) {
                if (mptr->Type != kEfiLoaderCode &&
                    mptr->Type != kEfiLoaderData &&
                    mptr->Type != kEfiBootServicesCode &&
                    mptr->Type != kEfiBootServicesData &&
                    mptr->Type != kEfiConventionalMemory) {
                efi_start = (vm_offset_t)mptr->PhysicalStart;
                efi_end = efi_start + ((vm_offset_t)mptr->NumberOfPages << I386_PGSHIFT) - 1;
                if ((efi_start >= region_start && efi_start <= region_end) ||
                    (efi_end >= region_start && efi_end <= region_end)) {
                    kprintf(" *** Overlapping region with EFI runtime region %d\n", i);
                }
                }
                
            }
        }
	}
#endif

	avail_start = first_avail;
	mem_actual = sane_size;

#define MEG		(1024*1024)

	/*
	 * For user visible memory size, round up to 128 Mb - accounting for the various stolen memory
	 * not reported by EFI.
	 */

	sane_size = (sane_size + 128 * MEG - 1) & ~((uint64_t)(128 * MEG - 1));

	/*
	 * if user set maxmem, reduce memory sizes
	 */
	if ( (maxmem > (uint64_t)first_avail) && (maxmem < sane_size)) {
		ppnum_t discarded_pages  = (sane_size - maxmem) >> I386_PGSHIFT;
		sane_size                = maxmem;
		if (avail_remaining > discarded_pages)
			avail_remaining -= discarded_pages;
		else
			avail_remaining = 0;
	}

	/*
	 * mem_size is only a 32 bit container... follow the PPC route
	 * and pin it to a 2 Gbyte maximum
	 */
	if (sane_size > (FOURGIG >> 1))
	        mem_size = (vm_size_t)(FOURGIG >> 1);
	else
	        mem_size = (vm_size_t)sane_size;
	max_mem = sane_size;

	kprintf("Physical memory %d MB\n", sane_size/MEG);

	if (!PE_parse_boot_arg("max_valid_dma_addr", &maxdmaaddr))
	        max_valid_dma_address = 1024ULL * 1024ULL * 4096ULL;
	else
	        max_valid_dma_address = ((uint64_t) maxdmaaddr) * 1024ULL * 1024ULL;

	if (!PE_parse_boot_arg("maxbouncepool", &maxbouncepoolsize))
	        maxbouncepoolsize = MAXBOUNCEPOOL;
	else
	        maxbouncepoolsize = maxbouncepoolsize * (1024 * 1024);

	/*
	 * bsd_mbuf_cluster_reserve depends on sane_size being set
	 * in order to correctly determine the size of the mbuf pool
	 * that will be reserved
	 */
	if (!PE_parse_boot_arg("maxloreserve", &maxloreserve))
	        maxloreserve = MAXLORESERVE + bsd_mbuf_cluster_reserve();
	else
	        maxloreserve = maxloreserve * (1024 * 1024);


	if (avail_end >= max_valid_dma_address) {
	        if (maxbouncepoolsize)
		        reserve_bouncepool(maxbouncepoolsize);

		if (maxloreserve)
			vm_lopage_poolsize = maxloreserve / PAGE_SIZE;
	}

	/*
	 *	Initialize kernel physical map.
	 *	Kernel virtual address starts at VM_KERNEL_MIN_ADDRESS.
	 */
	pmap_bootstrap(0, IA32e);
}


unsigned int
pmap_free_pages(void)
{
	return avail_remaining;
}


boolean_t
pmap_next_page(
	       ppnum_t *pn)
{
	
	if (avail_remaining) while (pmap_memory_region_current < pmap_memory_region_count) {
	        if (pmap_memory_regions[pmap_memory_region_current].alloc ==
		    pmap_memory_regions[pmap_memory_region_current].end) {
		        pmap_memory_region_current++;
			continue;
		}
		*pn = pmap_memory_regions[pmap_memory_region_current].alloc++;
		avail_remaining--;

		return TRUE;
	}
	return FALSE;
}


boolean_t
pmap_valid_page(
	ppnum_t pn)
{
        unsigned int i;
	pmap_memory_region_t *pmptr = pmap_memory_regions;

	assert(pn);
	for (i = 0; i < pmap_memory_region_count; i++, pmptr++) {
                if ( (pn >= pmptr->base) && (pn <= pmptr->end) && pmptr->type == kEfiConventionalMemory )
	                return TRUE;
	}
	return FALSE;
}


static void
reserve_bouncepool(uint32_t bounce_pool_wanted)
{
	pmap_memory_region_t *pmptr  = pmap_memory_regions;
	pmap_memory_region_t *lowest = NULL;
        unsigned int i;
	unsigned int pages_needed;

	pages_needed = bounce_pool_wanted / PAGE_SIZE;

	for (i = 0; i < pmap_memory_region_count; i++, pmptr++) {
	        if ( (pmptr->type == kEfiConventionalMemory) && ((pmptr->end - pmptr->alloc) >= pages_needed) ) {
		        if ( (lowest == NULL) || (pmptr->alloc < lowest->alloc) )
			        lowest = pmptr;
		}
	}
	if ( (lowest != NULL) ) {
	        bounce_pool_base = lowest->alloc * PAGE_SIZE;
		bounce_pool_size = bounce_pool_wanted;

		lowest->alloc += pages_needed;
		avail_remaining -= pages_needed;
	}
}
