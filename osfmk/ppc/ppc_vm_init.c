/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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
#include <ppc/mem.h>
#include <ppc/mappings.h>
#include <ppc/exception.h>
#include <ppc/mp.h>
#include <ppc/lowglobals.h>

#include <mach-o/mach_header.h>

extern const char version[];
extern const char version_variant[];

extern unsigned int intstack[];			/* declared in aligned_data.s */
extern unsigned int intstack_top_ss;	/* declared in aligned_data.s */

addr64_t hash_table_base;				/* Hash table base */
unsigned int hash_table_size;			/* Hash table size */
vm_offset_t taproot_addr;				/* (BRINGUP) */
unsigned int taproot_size;				/* (BRINGUP) */
unsigned int serialmode;				/* Serial mode keyboard and console control */
extern int disableConsoleOutput;

struct shadowBAT shadow_BAT;

/*
 *	NOTE: mem_size is bogus on large memory machines.  We will pin it to 0x80000000 if there is more than 2 GB
 *	This is left only for compatibility and max_mem should be used.
 */
vm_offset_t mem_size;					/* Size of actual physical memory present
										   minus any performance buffer and possibly limited
										   by mem_limit in bytes */
uint64_t	mem_actual;					/* The "One True" physical memory size 
						  				   actually, it's the highest physical address + 1 */
uint64_t	max_mem;					/* Size of physical memory (bytes), adjusted by maxmem */
uint64_t	sane_size;					/* Memory size to use for defaults calculations */
						  

mem_region_t pmap_mem_regions[PMAP_MEM_REGION_MAX + 1];
int	 pmap_mem_regions_count = 0;		/* Assume no non-contiguous memory regions */

unsigned int avail_remaining = 0;
vm_offset_t first_avail;
vm_offset_t static_memory_end;
addr64_t vm_last_addr = VM_MAX_KERNEL_ADDRESS;	/* Highest kernel virtual address known to the VM system */

extern struct mach_header _mh_execute_header;
vm_offset_t sectTEXTB;
int sectSizeTEXT;
vm_offset_t sectDATAB;
int sectSizeDATA;
vm_offset_t sectLINKB;
int sectSizeLINK;
vm_offset_t sectKLDB;
int sectSizeKLD;

vm_offset_t end, etext, edata;

extern unsigned long exception_entry;
extern unsigned long exception_end;


void ppc_vm_init(uint64_t mem_limit, boot_args *args)
{
	unsigned int htabmask;
	unsigned int i, j, batsize, kmapsize, pvr;
	vm_offset_t  addr, ioAddr, videoAddr;
	int boot_task_end_offset;
	const char *cpus;
	mapping		*mp;
	vm_offset_t		sizeadj, oldstart;
	unsigned int *xtaproot, bank_shift;
	uint64_t	cbsize, xhid0;


/*
 *	Invalidate all shadow BATs
 */

	/* Initialize shadow IBATs */
	shadow_BAT.IBATs[0].upper=BAT_INVALID;
	shadow_BAT.IBATs[0].lower=BAT_INVALID;
	shadow_BAT.IBATs[1].upper=BAT_INVALID;
	shadow_BAT.IBATs[1].lower=BAT_INVALID;
	shadow_BAT.IBATs[2].upper=BAT_INVALID;
	shadow_BAT.IBATs[2].lower=BAT_INVALID;
	shadow_BAT.IBATs[3].upper=BAT_INVALID;
	shadow_BAT.IBATs[3].lower=BAT_INVALID;

	/* Initialize shadow DBATs */
	shadow_BAT.DBATs[0].upper=BAT_INVALID;
	shadow_BAT.DBATs[0].lower=BAT_INVALID;
	shadow_BAT.DBATs[1].upper=BAT_INVALID;
	shadow_BAT.DBATs[1].lower=BAT_INVALID;
	shadow_BAT.DBATs[2].upper=BAT_INVALID;
	shadow_BAT.DBATs[2].lower=BAT_INVALID;
	shadow_BAT.DBATs[3].upper=BAT_INVALID;
	shadow_BAT.DBATs[3].lower=BAT_INVALID;


	/*
	 * Go through the list of memory regions passed in via the boot_args
	 * and copy valid entries into the pmap_mem_regions table, adding
	 * further calculated entries.
	 *
	 * boot_args version 1 has address instead of page numbers
	 * in the PhysicalDRAM banks, set bank_shift accordingly.
	 */
	
	bank_shift = 0;
	if (args->Version == kBootArgsVersion1) bank_shift = 12;
	
	pmap_mem_regions_count = 0;
	max_mem = 0;   															/* Will use to total memory found so far */
	mem_actual = 0;															/* Actual size of memory */
	
	if (mem_limit == 0) mem_limit = 0xFFFFFFFFFFFFFFFFULL;					/* If there is no set limit, use all */
	
	for (i = 0; i < kMaxDRAMBanks; i++) {									/* Look at all of the banks */
		
		cbsize = (uint64_t)args->PhysicalDRAM[i].size << (12 - bank_shift);	/* Remember current size */
		
		if (!cbsize) continue;												/* Skip if the bank is empty */
		
		mem_actual = mem_actual + cbsize;									/* Get true memory size */

		if(mem_limit == 0) continue;										/* If we hit restriction, just keep counting */

		if (cbsize > mem_limit) cbsize = mem_limit;							/* Trim to max allowed */
		max_mem += cbsize;													/* Total up what we have so far */
		mem_limit = mem_limit - cbsize;										/* Calculate amount left to do */
		
		pmap_mem_regions[pmap_mem_regions_count].mrStart  = args->PhysicalDRAM[i].base >> bank_shift;	/* Set the start of the bank */
		pmap_mem_regions[pmap_mem_regions_count].mrAStart = pmap_mem_regions[pmap_mem_regions_count].mrStart;		/* Set the start of allocatable area */
		pmap_mem_regions[pmap_mem_regions_count].mrEnd    = ((uint64_t)args->PhysicalDRAM[i].base >> bank_shift) + (cbsize >> 12) - 1;	/* Set the end address of bank */
		pmap_mem_regions[pmap_mem_regions_count].mrAEnd   = pmap_mem_regions[pmap_mem_regions_count].mrEnd;	/* Set the end address of allocatable area */

		/* Regions must be provided in ascending order */
		assert ((pmap_mem_regions_count == 0) ||
			pmap_mem_regions[pmap_mem_regions_count].mrStart >
			pmap_mem_regions[pmap_mem_regions_count-1].mrStart);

		pmap_mem_regions_count++;											/* Count this region */
	}
	
	mem_size = (unsigned int)max_mem;										/* Get size of memory */
	if(max_mem > 0x0000000080000000ULL) mem_size = 0x80000000;				/* Pin at 2 GB */

	sane_size = max_mem;													/* Calculate a sane value to use for init */
	if(sane_size > (addr64_t)(VM_MAX_KERNEL_ADDRESS + 1)) 
		sane_size = (addr64_t)(VM_MAX_KERNEL_ADDRESS + 1);					/* If flush with ram, use addressible portion */


/* 
 * Initialize the pmap system, using space above `first_avail'
 * for the necessary data structures.
 * NOTE : assume that we'll have enough space mapped in already
 */

	first_avail = static_memory_end;

/* Now retrieve addresses for end, edata, and etext 
 * from MACH-O headers.
 */
	sectTEXTB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__TEXT", &sectSizeTEXT);
	sectDATAB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__DATA", &sectSizeDATA);
	sectLINKB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__LINKEDIT", &sectSizeLINK);
	sectKLDB = (vm_offset_t)getsegdatafromheader(
		&_mh_execute_header, "__KLD", &sectSizeKLD);

	etext = (vm_offset_t) sectTEXTB + sectSizeTEXT;
	edata = (vm_offset_t) sectDATAB + sectSizeDATA;
	end = round_page_32(getlastaddr());					/* Force end to next page */
	
	kmapsize = (round_page_32(exception_end) - trunc_page_32(exception_entry)) +	/* Get size we will map later */
		(round_page_32(sectTEXTB+sectSizeTEXT) - trunc_page_32(sectTEXTB)) +
		(round_page_32(sectDATAB+sectSizeDATA) - trunc_page_32(sectDATAB)) +
		(round_page_32(sectLINKB+sectSizeLINK) - trunc_page_32(sectLINKB)) +
		(round_page_32(sectKLDB+sectSizeKLD) - trunc_page_32(sectKLDB)) +
		(round_page_32(static_memory_end) - trunc_page_32(end));

	pmap_bootstrap(max_mem, &first_avail, kmapsize);

	pmap_map(trunc_page_32(exception_entry), trunc_page_32(exception_entry), 
		round_page_32(exception_end), VM_PROT_READ|VM_PROT_EXECUTE);

	pmap_map(trunc_page_32(sectTEXTB), trunc_page_32(sectTEXTB), 
		round_page_32(sectTEXTB+sectSizeTEXT), VM_PROT_READ|VM_PROT_EXECUTE);

	pmap_map(trunc_page_32(sectDATAB), trunc_page_32(sectDATAB), 
		round_page_32(sectDATAB+sectSizeDATA), VM_PROT_READ|VM_PROT_WRITE);

/* The KLD and LINKEDIT segments are unloaded in toto after boot completes,
* but via ml_static_mfree(), through IODTFreeLoaderInfo(). Hence, we have
* to map both segments page-by-page.
*/
	
	for (addr = trunc_page_32(sectKLDB);
             addr < round_page_32(sectKLDB+sectSizeKLD);
             addr += PAGE_SIZE) {

            pmap_enter(kernel_pmap, addr, addr>>12, 
			VM_PROT_READ|VM_PROT_WRITE, 
			VM_WIMG_USE_DEFAULT, TRUE);

	}

	for (addr = trunc_page_32(sectLINKB);
             addr < round_page_32(sectLINKB+sectSizeLINK);
             addr += PAGE_SIZE) {

           pmap_enter(kernel_pmap, addr, addr>>12, 
			VM_PROT_READ|VM_PROT_WRITE, 
			VM_WIMG_USE_DEFAULT, TRUE);

	}

	pmap_enter(kernel_pmap, &sharedPage, (unsigned int)&sharedPage >> 12,	/* Make sure the sharedPage is mapped */
		VM_PROT_READ|VM_PROT_WRITE, 
		VM_WIMG_USE_DEFAULT, TRUE);

	pmap_enter(kernel_pmap, &lowGlo, (unsigned int)&lowGlo >> 12,			/* Make sure the low memory globals are mapped */
		VM_PROT_READ|VM_PROT_WRITE, 
		VM_WIMG_USE_DEFAULT, TRUE);
		
/*
 *	We need to map the remainder page-by-page because some of this will
 *	be released later, but not all.  Ergo, no block mapping here 
 */

	for(addr = trunc_page_32(end); addr < round_page_32(static_memory_end); addr += PAGE_SIZE) {

		pmap_enter(kernel_pmap, addr, addr>>12, 
			VM_PROT_READ|VM_PROT_WRITE, 
			VM_WIMG_USE_DEFAULT, TRUE);

	}

	MapUserAddressSpaceInit();			/* Go initialize copy in/out */

/*
 *	At this point, there is enough mapped memory and all hw mapping structures are
 *	allocated and initialized.  Here is where we turn on translation for the
 *	VERY first time....
 *
 *	NOTE: Here is where our very first interruption will happen.
 *
 */

	hw_start_trans();					/* Start translating */

#if 0
	GratefulDebInit((bootBumbleC *)&(args->Video));	/* Initialize the GratefulDeb debugger */
#endif


	printf_init();						/* Init this in case we need debugger */
	panic_init();						/* Init this in case we need debugger */
	PE_init_kprintf(TRUE);				/* Note on PPC we only call this after VM is set up */

	kprintf("kprintf initialized\n");

	serialmode = 0;						/* Assume normal keyboard and console */
	if(PE_parse_boot_arg("serial", &serialmode)) {		/* Do we want a serial keyboard and/or console? */
		kprintf("Serial mode specified: %08X\n", serialmode);
	}
	if(serialmode & 1) {				/* Start serial if requested */
		(void)switch_to_serial_console();	/* Switch into serial mode */
		disableConsoleOutput = FALSE;	/* Allow printfs to happen */
	}
	
	kprintf("max_mem: %ld M\n", (unsigned long)(max_mem >> 20));
	kprintf("version_variant = %s\n", version_variant);
	kprintf("version         = %s\n\n", version);
	__asm__ ("mfpvr %0" : "=r" (pvr));
	kprintf("proc version    = %08x\n", pvr);
	if(per_proc_info[0].pf.Available & pf64Bit) {	/* 64-bit processor? */
		xhid0 = hid0get64();			/* Get the hid0 */
		if(xhid0 & (1ULL << (63 - 19))) kprintf("Time base is externally clocked\n");
		else kprintf("Time base is internally clocked\n");
	}


	taproot_size = PE_init_taproot(&taproot_addr);	/* (BRINGUP) See if there is a taproot */
	if(taproot_size) {					/* (BRINGUP) */
		kprintf("TapRoot card configured to use vaddr = %08X, size = %08X\n", taproot_addr, taproot_size);
		bcopy_nc((void *)version, (void *)(taproot_addr + 16), strlen(version));	/* (BRINGUP) Pass it our kernel version */
		__asm__ volatile("eieio");		/* (BRINGUP) */
		xtaproot = (unsigned int *)taproot_addr;	/* (BRINGUP) */
		xtaproot[0] = 1;				/* (BRINGUP) */
		__asm__ volatile("eieio");		/* (BRINGUP) */
	}

	PE_create_console();				/* create the console for verbose or pretty mode */

	/* setup console output */
	PE_init_printf(FALSE);

#if DEBUG
	printf("\n\n\nThis program was compiled using gcc %d.%d for powerpc\n",
	       __GNUC__,__GNUC_MINOR__);


	/* Processor version information */
	{       
		unsigned int pvr;
		__asm__ ("mfpvr %0" : "=r" (pvr));
		printf("processor version register : %08X\n", pvr);
	}

	kprintf("Args at %08X\n", args);
	for (i = 0; i < pmap_mem_regions_count; i++) {
			printf("DRAM at %08X size %08X\n",
			       args->PhysicalDRAM[i].base,
			       args->PhysicalDRAM[i].size);
	}
#endif /* DEBUG */

#if DEBUG
	kprintf("Mapped memory:\n");
	kprintf("   exception vector: %08X, %08X - %08X\n", trunc_page_32(exception_entry), 
		trunc_page_32(exception_entry), round_page_32(exception_end));
	kprintf("          sectTEXTB: %08X, %08X - %08X\n", trunc_page_32(sectTEXTB), 
		trunc_page_32(sectTEXTB), round_page_32(sectTEXTB+sectSizeTEXT));
	kprintf("          sectDATAB: %08X, %08X - %08X\n", trunc_page_32(sectDATAB), 
		trunc_page_32(sectDATAB), round_page_32(sectDATAB+sectSizeDATA));
	kprintf("          sectLINKB: %08X, %08X - %08X\n", trunc_page_32(sectLINKB), 
		trunc_page_32(sectLINKB), round_page_32(sectLINKB+sectSizeLINK));
	kprintf("           sectKLDB: %08X, %08X - %08X\n", trunc_page_32(sectKLDB), 
		trunc_page_32(sectKLDB), round_page_32(sectKLDB+sectSizeKLD));
	kprintf("                end: %08X, %08X - %08X\n", trunc_page_32(end), 
		trunc_page_32(end), static_memory_end);

#endif

	return;
}

void ppc_vm_cpu_init(
	struct per_proc_info *proc_info)
{
	hw_setup_trans();									/* Set up hardware needed for translation */
	hw_start_trans();									/* Start translating */
}
