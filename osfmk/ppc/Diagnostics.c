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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */

/*
 *	Author: Bill Angell, Apple
 *	Date:	9/auht-aught
 *
 * Random diagnostics
 */


#include <kern/machine.h>
#include <kern/processor.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <ppc/exception.h>
#include <ppc/Firmware.h>
#include <ppc/low_trace.h>
#include <ppc/db_low_trace.h>
#include <ppc/mappings.h>
#include <ppc/pmap.h>
#include <ppc/mem.h>
#include <ppc/savearea.h>
#include <ppc/Diagnostics.h>
#include <ppc/machine_cpu.h>
#include <pexpert/pexpert.h>
#include <console/video_console.h>
#include <ppc/trap.h>

extern struct vc_info vinfo;

kern_return_t testPerfTrap(int trapno, struct savearea *ss, 
	unsigned int dsisr, addr64_t dar);

int diagCall(struct savearea *save) {

	union {
		unsigned long long tbase;
		unsigned int tb[2];
	} ttt, adj;
	natural_t tbu, tbu2, tbl;
	struct per_proc_info *per_proc;					/* Area for my per_proc address */
	int cpu, ret;
	unsigned int tstrt, tend, temp, temp2;
	addr64_t src, snk;
	uint64_t scom, hid1, hid4, srrwrk, stat;
	scomcomm sarea;

	if(!(dgWork.dgFlags & enaDiagSCs)) return 0;	/* If not enabled, cause an exception */

	switch(save->save_r3) {							/* Select the routine */
	
/*
 *		Adjust the timebase for drift recovery testing
 */
		case dgAdjTB:								/* Adjust the timebase */

			adj.tb[0] = 0;							/* Clear high part */
			adj.tb[1] = save->save_r4;				/* Set low order */
			if(adj.tb[1] & 0x80000000) adj.tb[0] = 0xFFFFFFFF;	/* Propagate sign bit */
						
			do {									/* Read current time */
				asm volatile("	mftbu %0" : "=r" (tbu));
				asm volatile("	mftb %0" : "=r" (tbl));
				asm volatile("	mftbu %0" : "=r" (tbu2));
			} while (tbu != tbu2);
			
			ttt.tb[0] = tbu;						/* Set high */
			ttt.tb[1] = tbl;						/* Set low */
			
			ttt.tbase = ttt.tbase + adj.tbase;		/* Increment or decrement the TB */
			
			tbu = ttt.tb[0];						/* Save in regular variable */
			tbl = ttt.tb[1];						/* Save in regular variable */

			mttb(0);								/* Set low to keep from ticking */
			mttbu(tbu);								/* Set adjusted high */
			mttb(tbl);								/* Set adjusted low */
			
			return -1;								/* Return no AST checking... */
			
/*
 *		Return physical address of a page
 */
		case dgLRA:
		
			save->save_r3 = pmap_find_phys(current_act()->map->pmap, save->save_r4);	/* Get read address */
			
			return -1;								/* Return no AST checking... */
			
/*
 *		Copy physical to virtual
 */
		case dgpcpy:
		
		
#if 1
			src = (save->save_r4 << 32) | (0x00000000FFFFFFFFULL & save->save_r5);	/* Merge into 64-bit */
			snk = (save->save_r6 << 32) | (0x00000000FFFFFFFFULL & save->save_r7);	/* Merge into 64-bit */
			save->save_r3 = copypv(src, snk, save->save_r8, save->save_r9);	/* Copy the physical page */
#endif			
			return 1;								/* Return and check for ASTs... */
			
/*
 *		Read/Write physical memory
 */
		case dgprw:
		
			src = (save->save_r5 << 32) | (0x00000000FFFFFFFFULL & save->save_r6);	/* Merge into 64-bit */
			
			switch(save->save_r4) {					/* Select the actual function */

				case 0:
					save->save_r3 = (uint64_t)ml_phys_read_byte((unsigned int)src);
					break;
			
				case 1:
					save->save_r3 = (uint64_t)ml_phys_read_byte_64(src);
					break;
				
				case 2:
					save->save_r3 = (uint64_t)ml_phys_read((unsigned int)src);
					break;
				
				case 3:
					save->save_r3 = (uint64_t)ml_phys_read_64(src);
					break;

				case 4:
					ml_phys_write_byte((unsigned int)src, (unsigned int)save->save_r7);
					break;
			
				case 5:
					ml_phys_write_byte_64(src, (unsigned int)save->save_r7);
					break;
				
				case 6:
					ml_phys_write((unsigned int)src, (unsigned int)save->save_r7);
					break;
				
				case 7:
					ml_phys_write_64(src, (unsigned int)save->save_r7);
					break;
			}

			return 1;								/* Return and check for ASTs... */
			
			
/*
 *		Soft reset processor
 */
		case dgreset:
		
			cpu = save->save_r4;					/* Get the requested CPU number */
			
			if(cpu >= NCPUS) {						/* Check for bogus cpu */
				save->save_r3 = KERN_FAILURE;		/* Set failure */
				return 1;
			}
		
			if(!machine_slot[cpu].running) return KERN_FAILURE;	/* It is not running */	

			per_proc = &per_proc_info[cpu];			/* Point to the processor */
			
			(void)PE_cpu_start(per_proc->cpu_id, 
						per_proc->start_paddr, (vm_offset_t)per_proc);
			
			save->save_r3 = KERN_SUCCESS;			/* Set scuuess */

			return 1;								/* Return and check for ASTs... */

/*
 *		Force cache flush
 */
		case dgFlush:
		
			cacheInit();							/* Blow cache */
			return 1;								/* Return and check for ASTs... */

/*
 *		various hack tests
 */
		case dgtest:
		
			if(save->save_r4) perfTrapHook = testPerfTrap;
			else perfTrapHook = 0;

			return 1;								/* Return and check for ASTs... */
			
		

/*
 *		Create a physical block map into the current task
 *		Don't bother to check for any errors.
 *		parms - vaddr, paddr, size, prot, attributes
 */
		case dgBMphys:
					
			pmap_map_block(current_act()->map->pmap, (addr64_t)save->save_r4,	/* Map in the block */ 
				save->save_r5, save->save_r6, save->save_r7, save->save_r8, 0);

			return 1;								/* Return and check for ASTs... */
		

/*
 *		Remove any mapping from the current task
 *		Don't bother to check for any errors.
 *		parms - vaddr
 */
		case dgUnMap:
		
			(void)mapping_remove(current_act()->map->pmap, save->save_r4);	/* Remove mapping */
			return 1;								/* Return and check for ASTs... */
	
			
/*
 *		Allows direct control of alignment handling.
 *
 *		The bottom bit of the parameter is used to set the control bit, enaNotifyEM.
 */
		case dgAlign:
		
			temp = dgWork.dgFlags;				/* Save the old values */
			
			temp2 = (save->save_r4 & 1) << (31 - enaNotifyEMb);	/* Move parms into flag format */
			dgWork.dgFlags = (temp & ~enaNotifyEM) | temp2;	/* Set the flag */
		
			save->save_r3 = (temp >> (31 - enaNotifyEMb)) & 1;	/* Return the original */
			
			return 1;								/* Return and check for ASTs... */
			
/*
 *		Return info for boot screen
 */
		case dgBootScreen:
			
			ml_set_interrupts_enabled(1);
			(void)copyout((char *)&vinfo, CAST_DOWN(char *, save->save_r4), sizeof(struct vc_info));	/* Copy out the video info */ 
			ml_set_interrupts_enabled(0);
			return 1;								/* Return and check for ASTs... */
			
/*
 *		Don't return info for boot screen
 */
		case dgCPNull:
			
			ml_set_interrupts_enabled(1);
			(void)copyout((char *)&vinfo, CAST_DOWN(char *, save->save_r4), 0);	/* Copy out nothing */
			ml_set_interrupts_enabled(0);
			return 1;								/* Return and check for ASTs... */
			
/*
 *		Test machine check handler - only on 64-bit machines
 */
		case dgmck:
			if(!(per_proc_info[0].pf.Available & pf64Bit)) return 0;	/* Leave if not correct machine */

			fwEmMck(save->save_r4, save->save_r5, save->save_r6, save->save_r7, save->save_r8, save->save_r9);	/* Start injecting */ 

			return -1;								/* Return and don't check for ASTs... */

/*
 *		Set 64-bit on or off - only on 64-bit machines
 */
		case dg64:
			if(!(per_proc_info[0].pf.Available & pf64Bit)) return 0;	/* Leave if not correct machine */

			srrwrk = save->save_srr1 >> 63;			/* Save the old 64-bit bit */
			
			save->save_srr1 = (save->save_srr1 & 0x7FFFFFFFFFFFFFFFULL) | (save->save_r4 << 63);	/* Set the requested mode */
			save->save_r3 = srrwrk;					/* Return the old value */

			return -1;								/* Return and don't check for ASTs... */
		
/*
 *		Test the probe read function
 */

		case dgProbeRead:
		
			src = (save->save_r4 << 32) | (0x00000000FFFFFFFFULL & save->save_r5);	/* Merge into 64-bit */
			save->save_r3 = ml_probe_read_64(src, &temp);	/* Try the address */
			save->save_r4 = temp;					/* Return the data */
			return -1;								/* Regurn and don't check for ASTs */
		
/*
 *		Do perf monitor stuff
 */

		case dgPerfMon:
		
			setPmon(save->save_r4, save->save_r5);	/* Go load up MMCR0 and MMCR1 */
			return -1;								/* Regurn and don't check for ASTs */

/*
 *		Map a page
 *		Don't bother to check for any errors.
 *		parms - vaddr, paddr, prot, attributes
 */
		case dgMapPage:
					
			(void)mapping_map(current_act()->map->pmap, /* Map in the page */ 
				(addr64_t)(((save->save_r5 & 0xFFFFFFFF) << 32) | (save->save_r5 & 0xFFFFFFFF)), save->save_r6, 0, 1, VM_PROT_READ|VM_PROT_WRITE);

			return -1;								/* Return and check for ASTs... */
		
/*
 *		SCOM interface
 *		parms - pointer to scomcomm
 */
		case dgScom:
					
			ret = copyin((unsigned int)(save->save_r4), &sarea, sizeof(scomcomm));	/* Get the data */
			if(ret) return 0;						/* Copyin failed - return an exception */
			
			sarea.scomstat = 0xFFFFFFFFFFFFFFFFULL;	/* Clear status */
			cpu = cpu_number();						/* Get us */
			
			if((sarea.scomcpu < NCPUS) && machine_slot[sarea.scomcpu].running) {
				if(sarea.scomcpu == cpu) {			/* Is it us? */
					if(sarea.scomfunc) {			/* Are we writing */
						sarea.scomstat = ml_scom_write(sarea.scomreg, sarea.scomdata);	/* Write scom */
					}
					else {
						sarea.scomstat = ml_scom_read(sarea.scomreg, &sarea.scomdata);	/* Read scom */
					}
				}
				else {									/* Otherwise, tell the other processor */
					(void)cpu_signal(sarea.scomcpu, SIGPcpureq, CPRQscom ,(unsigned int)&sarea);	/* Ask him to do this */
					(void)hw_cpu_sync((unsigned long)&sarea.scomstat, LockTimeOut);	/* Wait for the other processor to get its temperature */
				}
			}

			ret = copyout(&sarea, (unsigned int)(save->save_r4), sizeof(scomcomm));	/* Get the data */
			if(ret) return 0;						/* Copyin failed - return an exception */
	
			return -1;								/* Return and check for ASTs... */
		

		default:									/* Handle invalid ones */
			return 0;								/* Return an exception */
		
	}

};

kern_return_t testPerfTrap(int trapno, struct savearea *ss, 
	unsigned int dsisr, addr64_t dar) {

	if(trapno != T_ALIGNMENT) return KERN_FAILURE;

	kprintf("alignment exception at %08X, srr1 = %08X, dsisr = %08X, dar = %08X\n", ss->save_srr0,
		ss->save_srr1, dsisr, dar);
		
	return KERN_SUCCESS;

}
