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

#include <cpus.h>
#include <platforms.h>
#include <mach_kdb.h>
#include <himem.h>
#include <fast_idle.h>

#include <mach/i386/vm_param.h>

#include <string.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <mach/machine.h>
#include <mach/time_value.h>
#include <kern/etap_macros.h>
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
#ifdef __MACHO__
#include <mach/boot_info.h>
#include <mach/thread_status.h>
#endif

vm_size_t	mem_size = 0; 
vm_offset_t	first_addr = 0;	/* set by start.s - keep out of bss */
vm_offset_t	first_avail = 0;/* first after page tables */
vm_offset_t	last_addr;

uint64_t        max_mem;
uint64_t        sane_size;

vm_offset_t	avail_start, avail_end;
vm_offset_t	virtual_avail, virtual_end;
vm_offset_t	hole_start, hole_end;
vm_offset_t	avail_next;
unsigned int	avail_remaining;

/* parameters passed from bootstrap loader */
int		cnvmem = 0;		/* must be in .data section */
int		extmem = 0;

#ifndef __MACHO__
extern char	edata, end;
#endif

#ifdef __MACHO__
#include	<mach-o/loader.h>
vm_offset_t	edata, etext, end;

extern struct mach_header _mh_execute_header;
void *sectTEXTB; int sectSizeTEXT;
void *sectDATAB; int sectSizeDATA;
void *sectOBJCB; int sectSizeOBJC;
void *sectLINKB; int sectSizeLINK;
void *sectPRELINKB; int sectSizePRELINK;

#endif

/*
 * Basic VM initialization.
 */
void
i386_vm_init(unsigned int maxmem, KernelBootArgs_t *args)
{
	int i,j;			/* Standard index vars. */
	vm_size_t	bios_hole_size;	

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

	/* Now copy over various boot args bits.. */
	cnvmem = args->convmem;
	extmem = args->extmem;

	/*
	 * Initialize the pic prior to any possible call to an spl.
	 */

	set_cpu_model();
	vm_set_page_size();

	/*
	 * Initialize the Event Trace Analysis Package
	 * Static Phase: 1 of 2
	 */
	etap_init_phase1();

	/*
	 * Compute the memory size.
	 */

#if NCPUS > 1
	/* First two pages are used to boot the other cpus. */
	/* TODO - reclaim pages after all cpus have booted */

	first_addr = MP_FIRST_ADDR;
#else
	first_addr = 0x1000;
#endif

	/* BIOS leaves data in low memory */
	last_addr = 1024*1024 + extmem*1024;

	/* extended memory starts at 1MB */
       
	bios_hole_size = 1024*1024 - trunc_page((vm_offset_t)(1024 * cnvmem));

	/*
	 *	Initialize for pmap_free_pages and pmap_next_page.
	 *	These guys should be page-aligned.
	 */

	hole_start = trunc_page((vm_offset_t)(1024 * cnvmem));
	hole_end = round_page((vm_offset_t)first_avail);

	/*
	 * compute mem_size
	 */

	/*
	 * We're currently limited to 512 MB max physical memory.
	 */
#define M	(1024*1024)
#define MAXMEM	(512*M)
	if ((maxmem == 0) && (last_addr - bios_hole_size > MAXMEM)) {
		printf("Physical memory %d MB, "\
			"maximum usable memory limited to %d MB\n",
			(last_addr - bios_hole_size)/M, MAXMEM/M);
		maxmem = MAXMEM;
	}

	if (maxmem != 0) {
	    if (maxmem < (last_addr) - bios_hole_size)
		last_addr = maxmem + bios_hole_size;
	}

	first_addr = round_page(first_addr);
	last_addr = trunc_page(last_addr);
	mem_size = last_addr - bios_hole_size;

	max_mem = (uint64_t)mem_size;
	sane_size = max_mem;

	avail_start = first_addr;
	avail_end = last_addr;
	avail_next = avail_start;

#if	NCPUS > 1
	interrupt_stack_alloc();
#endif	/* NCPUS > 1 */

	/*
	 *	Initialize kernel physical map.
	 *	Kernel virtual address starts at VM_KERNEL_MIN_ADDRESS.
	 */
	pmap_bootstrap(0);

	avail_remaining = atop((avail_end - avail_start) -
			       (hole_end - hole_start));
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
	if (avail_next == avail_end) 
		return FALSE;

	/* skip the hole */

	if (avail_next == hole_start)
		avail_next = hole_end;

	*pn = (ppnum_t)i386_btop(avail_next);
	avail_next += PAGE_SIZE;
	avail_remaining--;

	return TRUE;
}

boolean_t
pmap_valid_page(
	vm_offset_t x)
{
	return ((avail_start <= x) && (x < avail_end));
}
