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

#include <debug.h>
#include <mach_ldebug.h>
#include <mach_kdb.h>
#include <mach_kdp.h>

#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <machine/machine_routines.h>
#include <ppc/boot.h>
#include <ppc/proc_reg.h>
#include <ppc/misc_protos.h>
#include <ppc/pmap.h>
#include <ppc/new_screen.h>
#include <ppc/exception.h>
#include <ppc/Firmware.h>
#include <ppc/savearea.h>
#include <ppc/low_trace.h>
#include <ppc/Diagnostics.h>
#include <ppc/mem.h>
#include <ppc/mappings.h>

#include <pexpert/pexpert.h>

extern unsigned int intstack_top_ss;	/* declared in start.s */
extern unsigned int debstackptr;		/* declared in start.s */
extern unsigned int debstack_top_ss;	/* declared in start.s */

int pc_trace_buf[1024] = {0};
int pc_trace_cnt = 1024;

extern unsigned int extPatchMCK;
extern unsigned int extPatch32;
extern unsigned int hwulckPatch_isync;
extern unsigned int hwulckPatch_eieio;
extern unsigned int hwulckbPatch_isync;
extern unsigned int hwulckbPatch_eieio;
extern unsigned int mulckPatch_isync;
extern unsigned int mulckPatch_eieio;
extern unsigned int sulckPatch_isync;
extern unsigned int sulckPatch_eieio;
extern unsigned int retfsectPatch_eieio;
extern unsigned int retfsectPatch_isync;

int forcenap = 0;

patch_entry_t patch_table[PATCH_TABLE_SIZE] = {
	&extPatch32,			0x60000000, PATCH_FEATURE,		PatchExt32,
	&extPatchMCK,			0x60000000, PATCH_PROCESSOR,	CPU_SUBTYPE_POWERPC_970,
	&hwulckPatch_isync,		0x60000000, PATCH_FEATURE,		PatchLwsync,
	&hwulckPatch_eieio,		0x7c2004ac, PATCH_FEATURE,		PatchLwsync,
	&hwulckbPatch_isync,		0x60000000, PATCH_FEATURE,		PatchLwsync,
	&hwulckbPatch_eieio,		0x7c2004ac, PATCH_FEATURE,		PatchLwsync,
	&mulckPatch_isync,		0x60000000, PATCH_FEATURE,		PatchLwsync,
	&mulckPatch_eieio,		0x7c2004ac, PATCH_FEATURE,		PatchLwsync,
	&sulckPatch_isync,		0x60000000, PATCH_FEATURE,		PatchLwsync,
	&sulckPatch_eieio,		0x7c2004ac, PATCH_FEATURE,		PatchLwsync,
#if	!MACH_LDEBUG
	&retfsectPatch_isync,	0x60000000, PATCH_FEATURE,		PatchLwsync,
	&retfsectPatch_eieio,	0x7c2004ac, PATCH_FEATURE,		PatchLwsync
#else
	0,						0,			PATCH_INVALID, 		0,
	0,						0,			PATCH_INVALID, 		0
#endif
	};

void ppc_init(boot_args *args)
{
	int i;
	unsigned long *src,*dst;
	char *str;
	unsigned long	addr, videoAddr;
	unsigned int	maxmem;
	uint64_t		xmaxmem, newhid;
	unsigned int	cputrace;
	unsigned int	novmx, fhrdl1;
	extern vm_offset_t static_memory_end;
	thread_t		thread;
	mapping *mp;
	
	/*
	 * Setup per_proc info for first cpu.
	 */

	per_proc_info[0].cpu_number = 0;
	per_proc_info[0].cpu_flags = 0;
	per_proc_info[0].istackptr = 0;	/* we're on the interrupt stack */
	per_proc_info[0].intstack_top_ss = intstack_top_ss;
	per_proc_info[0].debstackptr = debstackptr;
	per_proc_info[0].debstack_top_ss = debstack_top_ss;
	per_proc_info[0].interrupts_enabled = 0;
	per_proc_info[0].pp_preemption_count = -1;
	per_proc_info[0].pp_simple_lock_count = 0;
	per_proc_info[0].pp_interrupt_level = 0;
	per_proc_info[0].need_ast = (unsigned int)&need_ast[0];
	per_proc_info[0].FPU_owner = 0;
	per_proc_info[0].VMX_owner = 0;
	mp = (mapping *)per_proc_info[0].ppCIOmp;
	mp->mpFlags = 0x01000000 | mpSpecial | 1;
	mp->mpSpace = invalSpace;

	machine_slot[0].is_cpu = TRUE;

	thread_bootstrap();

	thread = current_act();
	thread->mact.curctx = &thread->mact.facctx;
	thread->mact.facctx.facAct = thread;
	thread->mact.cioSpace = invalSpace;					/* Initialize copyin/out space to invalid */
	thread->mact.preemption_count = 1;

	cpu_init();

	/*
	 * Setup some processor related structures to satisfy funnels.
	 * Must be done before using unparallelized device drivers.
	 */
	processor_ptr[0] = &processor_array[0];
	master_cpu = 0;
	master_processor = cpu_to_processor(master_cpu);

	static_memory_end = round_page_32(args->topOfKernelData);;
      
	PE_init_platform(FALSE, args);				/* Get platform expert set up */

	if (!PE_parse_boot_arg("novmx", &novmx)) novmx=0;	/* Special run without VMX? */
	if(novmx) {									/* Yeah, turn it off */
		for(i = 0; i < NCPUS; i++) {			/* Cycle through all potential processors */
			per_proc_info[i].pf.Available &= ~pfAltivec;	/* Turn off Altivec available */
		}
		__asm__ volatile("mtsprg 2,%0" : : "r" (per_proc_info[0].pf.Available));	/* Set live value */
	}

	if (!PE_parse_boot_arg("fn", &forcenap)) forcenap = 0;	/* If force nap not set, make 0 */
	else {
		if(forcenap < 2) forcenap = forcenap + 1;			/* Else set 1 for off, 2 for on */
		else forcenap = 0;									/* Clear for error case */
	}
	
	if (!PE_parse_boot_arg("diag", &dgWork.dgFlags)) dgWork.dgFlags=0;	/* Set diagnostic flags */
	if(dgWork.dgFlags & enaExpTrace) trcWork.traceMask = 0xFFFFFFFF;	/* If tracing requested, enable it */

	if(PE_parse_boot_arg("ctrc", &cputrace)) {							/* See if tracing is limited to a specific cpu */
		trcWork.traceMask = (trcWork.traceMask & 0xFFFFFFF0) | (cputrace & 0xF);	/* Limit to 4 */
	}

	if(!PE_parse_boot_arg("tb", &trcWork.traceSize)) {	/* See if non-default trace buffer size */
#if DEBUG
		trcWork.traceSize = 32;					/* Default 32 page trace table for DEBUG */
#else
		trcWork.traceSize = 8;					/* Default 8 page trace table for RELEASE */
#endif
	}

	if(trcWork.traceSize < 1) trcWork.traceSize = 1;	/* Minimum size of 1 page */
	if(trcWork.traceSize > 256) trcWork.traceSize = 256;	/* Maximum size of 256 pages */
	trcWork.traceSize = trcWork.traceSize * 4096;		/* Change page count to size */

	if (!PE_parse_boot_arg("maxmem", &maxmem))
		xmaxmem=0;
	else
		xmaxmem = (uint64_t)maxmem * (1024 * 1024);

/*   
 * VM initialization, after this we're using page tables...
 */

	ppc_vm_init(xmaxmem, args);
	
	if(per_proc_info[0].pf.Available & pf64Bit) {		/* Are we on a 64-bit machine */
		if(PE_parse_boot_arg("fhrdl1", &fhrdl1)) {		/* Have they supplied "Force Hardware Recovery of Data cache level 1 errors? */
			newhid = per_proc_info[0].pf.pfHID5;		/* Get the old HID5 */
			if(fhrdl1 < 2) {
				newhid &= 0xFFFFFFFFFFFFDFFFULL;		/* Clear the old one */
				newhid |= (fhrdl1 ^ 1) << 13;			/* Set new value to enable machine check recovery */
				for(i = 0; i < NCPUS; i++)	per_proc_info[i].pf.pfHID5 = newhid;	/* Set all shadows */
				hid5set64(newhid);						/* Set the hid for this processir */
			}
		}
	}
	
	
	PE_init_platform(TRUE, args);
	
	machine_startup(args);
}

ppc_init_cpu(
	struct per_proc_info *proc_info)
{
	int i;

	proc_info->cpu_flags &= ~SleepState;

	if(!(proc_info->next_savearea)) 		/* Do we have a savearea set up already? */
		proc_info->next_savearea = (uint64_t)save_get_init();	/* Get a savearea  */
	
	cpu_init();
	
	ppc_vm_cpu_init(proc_info);

	ml_thrm_init();							/* Start thermal monitoring on this processor */

	slave_main();
}
