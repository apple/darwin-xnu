/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * @APPLE_FREE_COPYRIGHT@
 */

#include <mach_debug.h>
#include <mach_kdb.h>
#include <mach_kdp.h>
#include <debug.h>
#include <cpus.h>

#include <mach/vm_types.h>
#include <mach/vm_param.h>
#include <mach/thread_status.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/cpu_number.h>

#include <ppc/proc_reg.h>
#include <ppc/Firmware.h>
#include <ppc/boot.h>
#include <ppc/misc_protos.h>
#include <ppc/pmap.h>
#include <ppc/pmap_internals.h>
#include <ppc/mem.h>
#include <ppc/mappings.h>
#include <ppc/exception.h>
#include <ppc/mp.h>

#ifdef	__MACHO__
#include <mach-o/mach_header.h>
#endif

extern unsigned int intstack[];	/* declared in start.s */
extern unsigned int intstack_top_ss;	/* declared in start.s */

vm_offset_t mem_size;	/* Size of actual physical memory present
						   minus any performance buffer and possibly limited
						   by mem_limit in bytes */
vm_offset_t mem_actual;	/* The "One True" physical memory size 
						   actually, it's the highest physical address + 1 */
						  

mem_region_t pmap_mem_regions[PMAP_MEM_REGION_MAX];
int	 pmap_mem_regions_count = 0;	/* No non-contiguous memory regions */

mem_region_t free_regions[FREE_REGION_MAX];
int	     free_regions_count;

#ifndef __MACHO__  
extern unsigned long etext;
#endif

unsigned int avail_remaining = 0;
vm_offset_t first_avail;
vm_offset_t static_memory_end;
extern vm_offset_t avail_next;

#ifdef __MACHO__
extern struct mach_header _mh_execute_header;
vm_offset_t sectTEXTB;
int sectSizeTEXT;
vm_offset_t sectDATAB;
int sectSizeDATA;
vm_offset_t sectOBJCB;
int sectSizeOBJC;
vm_offset_t sectLINKB;
int sectSizeLINK;
vm_offset_t sectKLDB;
int sectSizeKLD;

vm_offset_t end, etext, edata;
#endif

extern unsigned long exception_entry;
extern unsigned long exception_end;


void ppc_vm_init(unsigned int mem_limit, boot_args *args)
{
	unsigned int htabmask;
	unsigned int i, j, batsize, kmapsize;
	vm_offset_t  addr;
	int boot_task_end_offset;
	const char *cpus;
	mapping		*mp;
	vm_offset_t first_phys_avail;
	vm_offset_t		sizeadj, oldstart;

#ifdef __MACHO__
	/* Now retrieve addresses for end, edata, and etext 
	 * from MACH-O headers.
	 */
	sectTEXTB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__TEXT", &sectSizeTEXT);
	sectDATAB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__DATA", &sectSizeDATA);
	sectOBJCB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__OBJC", &sectSizeOBJC);
	sectLINKB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__LINKEDIT", &sectSizeLINK);
	sectKLDB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__KLD", &sectSizeKLD);

	etext = (vm_offset_t) sectTEXTB + sectSizeTEXT;
	edata = (vm_offset_t) sectDATAB + sectSizeDATA;
	end = round_page(getlastaddr());					/* Force end to next page */
#if DEBUG
	kprintf("sectTEXT: %x, size: %x\n", sectTEXTB, sectSizeTEXT);
	kprintf("sectDATA: %x, size: %x\n", sectDATAB, sectSizeDATA);
	kprintf("sectOBJC: %x, size: %x\n", sectOBJCB, sectSizeOBJC);
	kprintf("sectLINK: %x, size: %x\n", sectLINKB, sectSizeLINK);
	kprintf("sectKLD:  %x, size: %x\n", sectKLDB, sectSizeKLD);
	kprintf("end: %x\n", end);
#endif
#endif /* __MACHO__ */

/* Stitch valid memory regions together - they may be contiguous
 * even though they're not already glued together
 */
	mem_actual = mem_actual = args->PhysicalDRAM[0].base + args->PhysicalDRAM[0].size;	/* Initialize to the first region size */
	addr = 0;											/* temp use as pointer to previous memory region... */
	for (i = 1; i < kMaxDRAMBanks; i++) {
	  	
		if (args->PhysicalDRAM[i].size == 0) continue;	/* If region is empty, skip it */
		
	  	if((args->PhysicalDRAM[i].base + args->PhysicalDRAM[i].size) > mem_actual) {	/* New high? */
			mem_actual = args->PhysicalDRAM[i].base + args->PhysicalDRAM[i].size;	/* Take the high bid */
		}
		
		if (args->PhysicalDRAM[i].base ==				/* Does the end of the last hit the start of the next? */
		  args->PhysicalDRAM[addr].base +
		  args->PhysicalDRAM[addr].size) {
			kprintf("region 0x%08x size 0x%08x joining region 0x%08x size 0x%08x\n",
			  args->PhysicalDRAM[addr].base, args->PhysicalDRAM[addr].size,
			  args->PhysicalDRAM[i].base, args->PhysicalDRAM[i].size);
			
			args->PhysicalDRAM[addr].size += args->PhysicalDRAM[i].size;	/* Join them */
			args->PhysicalDRAM[i].size = 0;
			continue;
		}
		/* This is now last non-zero region to compare against */
		addr = i;
	}

	/* Go through the list of memory regions passed in via the args
	 * and copy valid entries into the pmap_mem_regions table, adding
	 * further calculated entries.
	 */
	
	pmap_mem_regions_count = 0;
	mem_size = 0;   /* Will use to total memory found so far */

	for (i = 0; i < kMaxDRAMBanks; i++) {
		if (args->PhysicalDRAM[i].size == 0)
			continue;

		/* The following should only happen if memory size has
		   been artificially reduced with -m */
		if (mem_limit > 0 &&
		    mem_size + args->PhysicalDRAM[i].size > mem_limit)
			args->PhysicalDRAM[i].size = mem_limit - mem_size;

		/* We've found a region, tally memory */

		pmap_mem_regions[pmap_mem_regions_count].start =
			args->PhysicalDRAM[i].base;
		pmap_mem_regions[pmap_mem_regions_count].end =
			args->PhysicalDRAM[i].base +
			args->PhysicalDRAM[i].size;

		/* Regions must be provided in ascending order */
		assert ((pmap_mem_regions_count == 0) ||
			pmap_mem_regions[pmap_mem_regions_count].start >
			pmap_mem_regions[pmap_mem_regions_count-1].start);

		if (pmap_mem_regions_count > 0) {		
			/* we add on any pages not in the first memory
			 * region to the avail_remaining count. The first
			 * memory region is used for mapping everything for
			 * bootup and is taken care of specially.
			 */
			avail_remaining +=
				args->PhysicalDRAM[i].size / PPC_PGBYTES;
		}
		
		/* Keep track of how much memory we've found */

		mem_size += args->PhysicalDRAM[i].size;

		/* incremement number of regions found */
		pmap_mem_regions_count++;
	}

	kprintf("mem_size: %d M\n",mem_size / (1024 * 1024));

	/* 
	 * Initialize the pmap system, using space above `first_avail'
	 * for the necessary data structures.
	 * NOTE : assume that we'll have enough space mapped in already
	 */

	first_phys_avail = static_memory_end;
	first_avail = adjust_bat_limit(first_phys_avail, 0, FALSE, FALSE);
	
	kmapsize = (round_page(exception_end) - trunc_page(exception_entry)) +	/* Get size we will map later */
		(round_page(sectTEXTB+sectSizeTEXT) - trunc_page(sectTEXTB)) +
		(round_page(sectDATAB+sectSizeDATA) - trunc_page(sectDATAB)) +
		(round_page(sectOBJCB+sectSizeOBJC) - trunc_page(sectOBJCB)) +
		(round_page(sectLINKB+sectSizeLINK) - trunc_page(sectLINKB)) +
		(round_page(sectKLDB+sectSizeKLD) - trunc_page(sectKLDB)) +
		(round_page(static_memory_end) - trunc_page(end));

	pmap_bootstrap(mem_size,&first_avail,&first_phys_avail, kmapsize);

#ifdef	__MACHO__
#if DEBUG
	kprintf("Mapping memory:\n");
	kprintf("   exception vector: %08X, %08X - %08X\n", trunc_page(exception_entry), 
		trunc_page(exception_entry), round_page(exception_end));
	kprintf("          sectTEXTB: %08X, %08X - %08X\n", trunc_page(sectTEXTB), 
		trunc_page(sectTEXTB), round_page(sectTEXTB+sectSizeTEXT));
	kprintf("          sectDATAB: %08X, %08X - %08X\n", trunc_page(sectDATAB), 
		trunc_page(sectDATAB), round_page(sectDATAB+sectSizeDATA));
	kprintf("          sectOBJCB: %08X, %08X - %08X\n", trunc_page(sectOBJCB), 
		trunc_page(sectOBJCB), round_page(sectOBJCB+sectSizeOBJC));
	kprintf("          sectLINKB: %08X, %08X - %08X\n", trunc_page(sectLINKB), 
		trunc_page(sectLINKB), round_page(sectLINKB+sectSizeLINK));
	kprintf("           sectKLDB: %08X, %08X - %08X\n", trunc_page(sectKLDB), 
		trunc_page(sectKLDB), round_page(sectKLDB+sectSizeKLD));
	kprintf("                end: %08X, %08X - %08X\n", trunc_page(end), 
		trunc_page(end), static_memory_end);
#endif /* DEBUG */
	pmap_map(trunc_page(exception_entry), trunc_page(exception_entry), 
		round_page(exception_end), VM_PROT_READ|VM_PROT_EXECUTE);
	pmap_map(trunc_page(sectTEXTB), trunc_page(sectTEXTB), 
		round_page(sectTEXTB+sectSizeTEXT), VM_PROT_READ|VM_PROT_EXECUTE);
	pmap_map(trunc_page(sectDATAB), trunc_page(sectDATAB), 
		round_page(sectDATAB+sectSizeDATA), VM_PROT_READ|VM_PROT_WRITE);
	pmap_map(trunc_page(sectOBJCB), trunc_page(sectOBJCB), 
		round_page(sectOBJCB+sectSizeOBJC), VM_PROT_READ|VM_PROT_WRITE);


       /* The KLD and LINKEDIT segments are unloaded in toto after boot completes,
        * but via ml_static_mfree(), through IODTFreeLoaderInfo(). Hence, we have
        * to map both segments page-by-page.
        */
	for (addr = trunc_page(sectKLDB);
             addr < round_page(sectKLDB+sectSizeKLD);
             addr += PAGE_SIZE) {

            pmap_enter(kernel_pmap, addr, addr, VM_PROT_READ|VM_PROT_WRITE, TRUE);
	}

	for (addr = trunc_page(sectLINKB);
             addr < round_page(sectLINKB+sectSizeLINK);
             addr += PAGE_SIZE) {

            pmap_enter(kernel_pmap, addr, addr, VM_PROT_READ|VM_PROT_WRITE, TRUE);
	}

/*
 *	We need to map the remainder page-by-page because some of this will
 *	be released later, but not all.  Ergo, no block mapping here 
 */
	for(addr = trunc_page(end); addr < round_page(static_memory_end); addr += PAGE_SIZE) {
		pmap_enter(kernel_pmap, addr, addr, VM_PROT_READ|VM_PROT_WRITE, TRUE);
	}
#endif /* __MACHO__ */

#if DEBUG
	for (i=0 ; i < free_regions_count; i++) {
		kprintf("Free region start 0x%08x end 0x%08x\n",
		       free_regions[i].start,free_regions[i].end);
	}
#endif

	/* Initialize shadow IBATs */
	shadow_BAT.IBATs[0].upper=BAT_INVALID;
	shadow_BAT.IBATs[0].lower=BAT_INVALID;
	shadow_BAT.IBATs[1].upper=BAT_INVALID;
	shadow_BAT.IBATs[1].lower=BAT_INVALID;
	shadow_BAT.IBATs[2].upper=BAT_INVALID;
	shadow_BAT.IBATs[2].lower=BAT_INVALID;
	shadow_BAT.IBATs[3].upper=BAT_INVALID;
	shadow_BAT.IBATs[3].lower=BAT_INVALID;

	LoadIBATs((unsigned int *)&shadow_BAT.IBATs[0]);		/* Load up real IBATs from shadows */

	/* Initialize shadow DBATs */
	shadow_BAT.DBATs[0].upper=BAT_INVALID;
	shadow_BAT.DBATs[0].lower=BAT_INVALID;
	shadow_BAT.DBATs[1].upper=BAT_INVALID;
	shadow_BAT.DBATs[1].lower=BAT_INVALID;
	mfdbatu(shadow_BAT.DBATs[2].upper,2);
	mfdbatl(shadow_BAT.DBATs[2].lower,2);
	mfdbatu(shadow_BAT.DBATs[3].upper,3);
	mfdbatl(shadow_BAT.DBATs[3].lower,3);

	LoadDBATs((unsigned int *)&shadow_BAT.DBATs[0]);		/* Load up real DBATs from shadows */

	sync();isync();
#if DEBUG
	for(i=0; i<4; i++) kprintf("DBAT%1d: %08X %08X\n", 
		i, shadow_BAT.DBATs[i].upper, shadow_BAT.DBATs[i].lower);
	for(i=0; i<4; i++) kprintf("IBAT%1d: %08X %08X\n", 
		i, shadow_BAT.IBATs[i].upper, shadow_BAT.IBATs[i].lower);
#endif
}

void ppc_vm_cpu_init(
	struct per_proc_info *proc_info)
{
	hash_table_init(hash_table_base, hash_table_size);

	LoadIBATs((unsigned int *)&shadow_BAT.IBATs[0]);
	LoadDBATs((unsigned int *)&shadow_BAT.DBATs[0]);

	sync();isync();
}
