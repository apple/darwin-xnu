/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
#include <himem.h>

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
#include <i386/pio.h>
#include <i386/misc_protos.h>
#include <i386/mp_slave_boot.h>
#include <i386/cpuid.h>
#ifdef __MACHO__
#include <mach/thread_status.h>
#endif

vm_size_t	mem_size = 0; 
vm_offset_t	first_avail = 0;/* first after page tables */
vm_offset_t	last_addr;

uint64_t        max_mem;
uint64_t        sane_size = 0; /* we are going to use the booter memory
				  table info to construct this */

pmap_paddr_t     avail_start, avail_end;
vm_offset_t	virtual_avail, virtual_end;
pmap_paddr_t	avail_remaining;
vm_offset_t     static_memory_end = 0;

#ifndef __MACHO__
extern char	edata, end;
#endif

#ifdef __MACHO__
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
#endif

/*
 * Basic VM initialization.
 */
void
i386_vm_init(unsigned int maxmem, KernelBootArgs_t *args)
{
	pmap_memory_region_t *pmptr;
	MemoryRange *mptr;
	ppnum_t fap;
	unsigned int i;
	ppnum_t maxpg = (maxmem >> I386_PGSHIFT);

#ifdef	__MACHO__
	/* Now retrieve addresses for end, edata, and etext 
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
#endif
#ifndef	__MACHO__
	/*
	 * Zero the BSS.
	 */

	bzero((char *)&edata,(unsigned)(&end - &edata));
#endif

	/*
	 * Initialize the pic prior to any possible call to an spl.
	 */

	set_cpu_model();
	vm_set_page_size();

	/*
	 * Compute the memory size.
	 */

	avail_remaining = 0;
	avail_end = 0;
	pmptr = pmap_memory_regions;
	pmap_memory_region_count = pmap_memory_region_current = 0;
	fap = (ppnum_t) i386_btop(first_avail);
	mptr = args->memoryMap;

#ifdef PAE
#define FOURGIG 0x0000000100000000ULL
	for (i=0; i < args->memoryMapCount; i++,mptr++) {
	  ppnum_t base, top;

	  base = (ppnum_t) (mptr->base >> I386_PGSHIFT);
	  top = (ppnum_t) ((mptr->base + mptr->length) >> I386_PGSHIFT) - 1;

	  if (maxmem) {
	    if (base >= maxpg) break;
	    top = (top > maxpg)? maxpg : top;
	  }

	  if (kMemoryRangeUsable != mptr->type) continue;
	  sane_size += (uint64_t)(mptr->length);
#ifdef DEVICES_HANDLE_64BIT_IO  /* XXX enable else clause  when I/O to high memory works */
	  if (top < fap) {
	    /* entire range below first_avail */
	    continue;
	  } else if (mptr->base >= FOURGIG) {
	    /* entire range above 4GB (pre PAE) */
	    continue;
	  } else if ( (base < fap) &&
		      (top > fap)) {
	    /* spans first_avail */
	    /*  put mem below first avail in table but
		mark already allocated */
	    pmptr->base = base;
	    pmptr->alloc = pmptr->end = (fap - 1);
            pmptr->type = mptr->type;
	    /* we bump these here inline so the accounting below works
	       correctly */
	    pmptr++;
	    pmap_memory_region_count++;
	    pmptr->alloc = pmptr->base = fap;
            pmptr->type = mptr->type;
	    pmptr->end = top;
	  } else if ( (mptr->base < FOURGIG) &&
		      ((mptr->base+mptr->length) > FOURGIG) ) {
	    /* spans across 4GB (pre PAE) */
	    pmptr->alloc = pmptr->base = base;
            pmptr->type = mptr->type;
	    pmptr->end = (FOURGIG >> I386_PGSHIFT) - 1;
	  } else {
	    /* entire range useable */
	    pmptr->alloc = pmptr->base = base;
            pmptr->type = mptr->type;
	    pmptr->end = top;
	  }
#else
	  if (top < fap) {
	    /* entire range below first_avail */
	    continue;
	  } else if ( (base < fap) &&
		      (top > fap)) {
	    /* spans first_avail */
	    pmptr->alloc = pmptr->base = fap;
            pmptr->type = mptr->type;
	    pmptr->end = top;
	  } else {
	    /* entire range useable */
	    pmptr->alloc = pmptr->base = base;
            pmptr->type = mptr->type;
	    pmptr->end = top;
	  }
#endif
	  if (i386_ptob(pmptr->end) > avail_end ) {
	    avail_end = i386_ptob(pmptr->end);
	  }
	  avail_remaining += (pmptr->end - pmptr->base);
	  pmap_memory_region_count++;
	  pmptr++;
	}
#else  /* non PAE follows */
#define FOURGIG 0x0000000100000000ULL
	for (i=0; i < args->memoryMapCount; i++,mptr++) {
	  ppnum_t base, top;

	  base = (ppnum_t) (mptr->base >> I386_PGSHIFT);
	  top = (ppnum_t) ((mptr->base + mptr->length) >> I386_PGSHIFT) - 1;

	  if (maxmem) {
	    if (base >= maxpg) break;
	    top = (top > maxpg)? maxpg : top;
	  }

	  if (kMemoryRangeUsable != mptr->type) continue;

          // save other regions
          if (kMemoryRangeNVS == mptr->type) {
              // Mark this as a memory range (for hibernation),
              // but don't count as usable memory
              pmptr->base = base;
              pmptr->end = ((mptr->base + mptr->length + I386_PGBYTES - 1) >> I386_PGSHIFT) - 1;
              pmptr->alloc = pmptr->end;
              pmptr->type = mptr->type;
              kprintf("NVS region: 0x%x ->0x%x\n", pmptr->base, pmptr->end);
          } else if (kMemoryRangeUsable != mptr->type) {
              continue;
          } else {
              // Usable memory region
	  sane_size += (uint64_t)(mptr->length);
	  if (top < fap) {
	    /* entire range below first_avail */
	    /* salvage some low memory pages */
	    /* we use some very low memory at startup */
	    /* mark as already allocated here */
	    pmptr->base = 0x18; /* PAE and HIB use below this */
	    pmptr->alloc = pmptr->end = top;  /* mark as already mapped */
	    pmptr->type = mptr->type;
	  } else if (mptr->base >= FOURGIG) {
	    /* entire range above 4GB (pre PAE) */
	    continue;
	  } else if ( (base < fap) &&
		      (top > fap)) {
	    /* spans first_avail */
	    /*  put mem below first avail in table but
		mark already allocated */
	    pmptr->base = base;
	    pmptr->alloc = pmptr->end = (fap - 1);
            pmptr->type = mptr->type;
	    /* we bump these here inline so the accounting below works
	       correctly */
	    pmptr++;
	    pmap_memory_region_count++;
	    pmptr->alloc = pmptr->base = fap;
            pmptr->type = mptr->type;
	    pmptr->end = top;
	  } else if ( (mptr->base < FOURGIG) &&
		      ((mptr->base+mptr->length) > FOURGIG) ) {
	    /* spans across 4GB (pre PAE) */
	    pmptr->alloc = pmptr->base = base;
            pmptr->type = mptr->type;
	    pmptr->end = (FOURGIG >> I386_PGSHIFT) - 1;
	  } else {
	    /* entire range useable */
	    pmptr->alloc = pmptr->base = base;
            pmptr->type = mptr->type;
	    pmptr->end = top;
	  }

	  if (i386_ptob(pmptr->end) > avail_end ) {
	    avail_end = i386_ptob(pmptr->end);
	  }

	  avail_remaining += (pmptr->end - pmptr->base);
	  pmap_memory_region_count++;
	  pmptr++;
	  }
	}
#endif

#ifdef PRINT_PMAP_MEMORY_TABLE
 {
   unsigned int j;
  pmap_memory_region_t *p = pmap_memory_regions;
   for (j=0;j<pmap_memory_region_count;j++, p++) {
     kprintf("%d base 0x%x alloc 0x%x top 0x%x\n",j,
	     p->base, p->alloc, p->end);
   }
 }
#endif

	avail_start = first_avail;

	if (maxmem) {  /* if user set maxmem try to use it */
	  uint64_t  tmp = (uint64_t)maxmem;
	  /* can't set below first_avail or above actual memory */
	  if ( (maxmem > first_avail) && (tmp < sane_size) ) {
	    sane_size = tmp;
	    avail_end = maxmem;
	  }
	}
	// round up to a megabyte - mostly accounting for the
	// low mem madness
	sane_size += ( 0x100000ULL - 1);
	sane_size &=  ~0xFFFFFULL;

#ifndef PAE
	if (sane_size < FOURGIG)
	  mem_size = (unsigned long) sane_size;
	else
	  mem_size = (unsigned long) (FOURGIG >> 1);
#else
	  mem_size = (unsigned long) sane_size;
#endif

	max_mem = sane_size;

	/* now make sane size sane */
#define MIN(a,b)	(((a)<(b))?(a):(b))
#define MEG		(1024*1024)
	sane_size = MIN(sane_size, 256*MEG);

	kprintf("Physical memory %d MB\n",
		mem_size/MEG);

	/*
	 *	Initialize kernel physical map.
	 *	Kernel virtual address starts at VM_KERNEL_MIN_ADDRESS.
	 */
	pmap_bootstrap(0);


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

	while (pmap_memory_region_current < pmap_memory_region_count) {
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
  for (i=0; i<pmap_memory_region_count; i++, pmptr++) {
    if ( (pn >= pmptr->base) && (pn <= pmptr->end) ) {
        if (pmptr->type == kMemoryRangeUsable)
            return TRUE;
        else
            return FALSE;
    }
  }
  return FALSE;
}
