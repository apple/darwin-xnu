/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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


#include <mach/vm_types.h>
#include <mach/vm_param.h>
#include <mach/thread_status.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/cpu_number.h>

#include <ppc/proc_reg.h>
#include <ppc/boot.h>
#include <ppc/misc_protos.h>
#include <ppc/pmap.h>
#include <ppc/pmap_internals.h>
#include <ppc/mem.h>
#include <ppc/exception.h>
#include <ppc/gdb_defs.h>
#include <ppc/POWERMAC/video_board.h>
#include <ppc/POWERMAC/video_pdm.h>

#ifdef	__MACHO__
#include <mach-o/mach_header.h>
#endif

/* External references */

extern unsigned int intstack[];	/* declared in start.s */
extern unsigned int intstack_top_ss;	/* declared in start.s */
#if	MACH_KGDB
extern unsigned int gdbstackptr;	/* declared in start.s */
extern unsigned int gdbstack_top_ss;	/* declared in start.s */
#endif	/* MACH_KGDB */

/* Stuff declared in kern/bootstrap.c which we may need to initialise */

extern vm_offset_t     boot_start;
extern vm_size_t       boot_size;
extern vm_offset_t     boot_region_desc;
extern vm_size_t       boot_region_count;
extern int             boot_thread_state_flavor;
extern thread_state_t  boot_thread_state;
extern unsigned int    boot_thread_state_count;

/* Trap handling function prototypes */

extern void thandler(void);	/* trap handler */
extern void ihandler(void);	/* interrupt handler */
extern void shandler(void);	/* syscall handler */
extern void gdbhandler(void);	/* debugger handler */
extern void fpu_switch(void);	/* fp handler */
extern void atomic_switch_trap(void);	/* fast path atomic thread switch */

/* definitions */

struct ppc_thread_state boot_task_thread_state;





#if 1 /* TODO NMGS - vm_map_steal_memory shouldn't use these - remove */
vm_offset_t avail_start;
vm_offset_t avail_end;
#endif 
unsigned int avail_remaining = 0;
vm_offset_t first_avail;

/*
 * Mach-O Support 
 */


#ifdef __MACHO__
extern struct mach_header _mh_execute_header;
void *sectTEXTB;
int sectSizeTEXT;
void *sectDATAB;
int sectSizeDATA;
void *sectOBJCB;
int sectSizeOBJC;
void *sectLINKB;
int sectSizeLINK;

vm_offset_t end, etext, edata;
#define	ETEXT	etext
#endif



void ppc_vm_init(unsigned int memory_size, boot_args *args)
{
	unsigned int htabmask;
	unsigned int i;
	vm_offset_t  addr;
	int boot_task_end_offset;
#if	NCPUS > 1
	const char *cpus;
#endif	/* NCPUS > 1 */

	printf("mem_size = %d M\n",memory_size / (1024 * 1024));

#ifdef __MACHO__
	/* Now retrieve addresses for end, edata, and etext 
	 * from MACH-O headers.
	 */


	etext = (vm_offset_t) sectTEXTB + sectSizeTEXT;
	edata = (vm_offset_t) sectDATAB + sectSizeDATA;
	end = getlastaddr();
#endif

	/* Stitch valid memory regions together - they may be contiguous
	 * even though they're not already glued together
	 */

	/* Go through the list of memory regions passed in via the args
	 * and copy valid entries into the pmap_mem_regions table, adding
	 * further calculated entries.
	 */
	
	
	/* Initialise the pmap system, using space above `first_avail'*/

#ifndef	__MACHO__
	free_regions[free_regions_count].start =
	  	round_page((unsigned int)&_ExceptionVectorsEnd -
			   (unsigned int)&_ExceptionVectorsStart);
#else
	/* On MACH-O generated kernels, the Exception Vectors
	 * are already mapped and loaded at 0 -- no relocation
	 * or freeing of memory is needed
	 */

	free_regions[free_regions_count].start = round_page((unsigned int)&_ExceptionVectorsEnd) + 4096;
#endif

	/* If we are on a PDM machine memory at 1M might be used
	 * for video. TODO NMGS call video driver to do this
	 * somehow
	 */


	/* For PowerMac, first_avail is set to above the bootstrap task.
         * TODO NMGS - different screen modes - might free mem?
         */

	first_avail = round_page(args->first_avail);


	/* map in the exception vectors */
	/*
	 * map the kernel text, data and bss. Don't forget other regions too
	 */
	for (i = 0; i < args->kern_info.region_count; i++) {
#if	MACH_KDB
		if (args->kern_info.regions[i].prot == VM_PROT_NONE &&
		    i == args->kern_info.region_count - 1) {
			/* assume that's the kernel symbol table */
			kern_sym_start = args->kern_info.regions[i].addr;
			kern_sym_size = args->kern_info.regions[i].size;
			printf("kernel symbol table at 0x%x size 0x%x\n",
			       kern_sym_start, kern_sym_size);
			args->kern_info.regions[i].prot |=
				(VM_PROT_WRITE|VM_PROT_READ);
		}
#endif	/* MACH_KDB */

#ifdef __MACHO__
		/* Skip the VECTORS segment */
		if (args->kern_info.regions[i].addr == 0)
			continue;
#endif

	boot_region_count = args->task_info.region_count;
	boot_size = 0;
	boot_task_end_offset = 0;
	/* Map bootstrap task pages 1-1 so that user_bootstrap can find it */
	for (i = 0; i < boot_region_count; i++) {
		if (args->task_info.regions[i].mapped) {
			/* kernel requires everything page aligned */
#if DEBUG
			printf("mapping virt 0x%08x to phys 0x%08x end 0x%x, prot=0x%b\n",
				 ppc_trunc_page(args->task_info.base_addr + 
					args->task_info.regions[i].offset),
				 ppc_trunc_page(args->task_info.base_addr + 
					args->task_info.regions[i].offset),
				 ppc_round_page(args->task_info.base_addr + 
					args->task_info.regions[i].offset +
					args->task_info.regions[i].size),
				 args->task_info.regions[i].prot,
				 "\x10\1READ\2WRITE\3EXEC");
#endif /* DEBUG */

			(void)pmap_map(
				  ppc_trunc_page(args->task_info.base_addr + 
				      args->task_info.regions[i].offset),
			          ppc_trunc_page(args->task_info.base_addr + 
				      args->task_info.regions[i].offset),
			          ppc_round_page(args->task_info.base_addr +
				      args->task_info.regions[i].offset +
				      args->task_info.regions[i].size),
			          args->task_info.regions[i].prot);

			/* Count the size of mapped space */
			boot_size += args->task_info.regions[i].size;

			/* There may be an overlapping physical page
			 * mapped to two different virtual addresses
			 */
			if (boot_task_end_offset >
			    args->task_info.regions[i].offset) {
				boot_size -= boot_task_end_offset - 
					args->task_info.regions[i].offset;
#if DEBUG
				printf("WARNING - bootstrap overlaps regions\n");
#endif /* DEBUG */
			}

			boot_task_end_offset =
				args->task_info.regions[i].offset +
				args->task_info.regions[i].size;
		}
	}

	if (boot_region_count) {

		/* Add a new region to the bootstrap task for it's stack */
		args->task_info.regions[boot_region_count].addr =
			BOOT_STACK_BASE;
		args->task_info.regions[boot_region_count].size =
			BOOT_STACK_SIZE;
		args->task_info.regions[boot_region_count].mapped = FALSE;
		boot_region_count++;
		
		boot_start        = args->task_info.base_addr;
		boot_region_desc  = (vm_offset_t) args->task_info.regions;
		/* TODO NMGS need to put param info onto top of boot stack */
		boot_task_thread_state.r1   = BOOT_STACK_PTR-0x100;
		boot_task_thread_state.srr0 = args->task_info.entry;
		boot_task_thread_state.srr1 =
			MSR_MARK_SYSCALL(MSR_EXPORT_MASK_SET);
		
		boot_thread_state_flavor = PPC_THREAD_STATE;
		boot_thread_state_count  = PPC_THREAD_STATE_COUNT;
		boot_thread_state        =
			(thread_state_t)&boot_task_thread_state;
	}



}

