/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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

#include <debug.h>
#include <mach_ldebug.h>
#include <mach_kdb.h>
#include <mach_kdp.h>

#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/startup.h>
#include <machine/machine_routines.h>
#include <ppc/boot.h>
#include <ppc/proc_reg.h>
#include <ppc/misc_protos.h>
#include <ppc/pmap.h>
#include <ppc/new_screen.h>
#include <ppc/exception.h>
#include <ppc/asm.h>
#include <ppc/Firmware.h>
#include <ppc/savearea.h>
#include <ppc/low_trace.h>
#include <ppc/Diagnostics.h>
#include <ppc/cpu_internal.h>
#include <ppc/mem.h>
#include <ppc/mappings.h>
#include <ppc/locks.h>
#include <kern/pms.h>
#include <ppc/rtclock.h>

#include <pexpert/pexpert.h>

extern unsigned int mckFlags;
extern vm_offset_t	intstack;
extern vm_offset_t	debstack;  

extern unsigned int extPatchMCK;
extern unsigned int extPatch32;
extern unsigned int hwulckPatch_isync;
extern unsigned int hwulckPatch_eieio;
extern unsigned int hwulckbPatch_isync;
extern unsigned int hwulckbPatch_eieio;
extern unsigned int mulckPatch_isync;
extern unsigned int mulckPatch_eieio;
extern unsigned int mulckePatch_isync;
extern unsigned int mulckePatch_eieio;
extern unsigned int sulckPatch_isync;
extern unsigned int sulckPatch_eieio;
extern unsigned int rwlesPatch_isync;
extern unsigned int rwlesPatch_eieio;
extern unsigned int rwldPatch_isync;
extern unsigned int rwldPatch_eieio;
extern unsigned int bcopy_nop_if_32bit;
extern unsigned int bcopy_nc_nop_if_32bit;
extern unsigned int memcpy_nop_if_32bit;
extern unsigned int xsum_nop_if_32bit;
extern unsigned int uft_nop_if_32bit;
extern unsigned int uft_uaw_nop_if_32bit;
extern unsigned int uft_cuttrace;

int forcenap = 0;
int wcte = 0;				/* Non-cache gather timer disabled */

int debug_task;

patch_entry_t patch_table[] = {
	{&extPatch32,			0x60000000, PATCH_FEATURE,		PatchExt32},
	{&extPatchMCK,			0x60000000, PATCH_PROCESSOR,	CPU_SUBTYPE_POWERPC_970},
	{&hwulckPatch_isync,	0x60000000, PATCH_FEATURE,		PatchLwsync},
	{&hwulckPatch_eieio,	0x7c2004ac, PATCH_FEATURE,		PatchLwsync},
	{&hwulckbPatch_isync,   0x60000000, PATCH_FEATURE,		PatchLwsync},
	{&hwulckbPatch_eieio,   0x7c2004ac, PATCH_FEATURE,		PatchLwsync},
	{&mulckPatch_isync,		0x60000000, PATCH_FEATURE,		PatchLwsync},
	{&mulckPatch_eieio,		0x7c2004ac, PATCH_FEATURE,		PatchLwsync},
	{&mulckePatch_isync,	0x60000000, PATCH_FEATURE,		PatchLwsync},
	{&mulckePatch_eieio,	0x7c2004ac, PATCH_FEATURE,		PatchLwsync},
	{&sulckPatch_isync,		0x60000000, PATCH_FEATURE,		PatchLwsync},
	{&sulckPatch_eieio,		0x7c2004ac, PATCH_FEATURE,		PatchLwsync},
	{&rwlesPatch_isync,		0x60000000, PATCH_FEATURE,		PatchLwsync},
	{&rwlesPatch_eieio,		0x7c2004ac, PATCH_FEATURE,		PatchLwsync},
	{&rwldPatch_isync,		0x60000000, PATCH_FEATURE,		PatchLwsync},
	{&rwldPatch_eieio,		0x7c2004ac, PATCH_FEATURE,		PatchLwsync},
	{&bcopy_nop_if_32bit,	0x60000000, PATCH_FEATURE,		PatchExt32},
	{&bcopy_nc_nop_if_32bit,0x60000000, PATCH_FEATURE,		PatchExt32},
	{&memcpy_nop_if_32bit,	0x60000000, PATCH_FEATURE,		PatchExt32},
	{&xsum_nop_if_32bit,	0x60000000,	PATCH_FEATURE,		PatchExt32},
	{&uft_nop_if_32bit,		0x60000000,	PATCH_FEATURE,		PatchExt32},
	{&uft_uaw_nop_if_32bit,	0x60000000,	PATCH_FEATURE,		PatchExt32},
	{&uft_cuttrace,			0x60000000,	PATCH_FEATURE,		PatchExt32},
    {NULL,                  0x00000000, PATCH_END_OF_TABLE, 0}
	};


/*
 * Forward definition
 */
void	ppc_init(
			boot_args	*args);

void	ppc_init_cpu(
			struct per_proc_info *proc_info);

	
/*
 *		Routine:		ppc_init
 *		Function:
 */
void
ppc_init(
		boot_args *args)
{
	unsigned int		maxmem;
	uint64_t			xmaxmem;
	uint64_t			newhid;
	unsigned int		cputrace;
	unsigned int		novmx;
	unsigned int		mcksoft;
	thread_t			thread;
	mapping_t			*mp;
	uint64_t 			scdata;


	/*
	 * Setup per_proc info for first cpu.
	 */

	BootProcInfo.cpu_number = 0;
	BootProcInfo.cpu_flags = 0;
	BootProcInfo.istackptr = 0;							/* we're on the interrupt stack */
	BootProcInfo.intstack_top_ss = (vm_offset_t)&intstack + INTSTACK_SIZE - FM_SIZE;
	BootProcInfo.debstack_top_ss = (vm_offset_t)&debstack + KERNEL_STACK_SIZE - FM_SIZE;
	BootProcInfo.debstackptr = BootProcInfo.debstack_top_ss;
	BootProcInfo.interrupts_enabled = 0;
	BootProcInfo.pending_ast = AST_NONE;
	BootProcInfo.FPU_owner = NULL;
	BootProcInfo.VMX_owner = NULL;
	BootProcInfo.pp_cbfr = console_per_proc_alloc(TRUE);
	BootProcInfo.rtcPop = EndOfAllTime;
	BootProcInfo.pp2ndPage = (addr64_t)(uintptr_t)&BootProcInfo;	/* Initial physical address of the second page */

 	BootProcInfo.pms.pmsStamp = 0;						/* Dummy transition time */
 	BootProcInfo.pms.pmsPop = EndOfAllTime;				/* Set the pop way into the future */
 	
 	BootProcInfo.pms.pmsState = pmsParked;				/* Park the power stepper */
	BootProcInfo.pms.pmsCSetCmd = pmsCInit;				/* Set dummy initial hardware state */
	
	mp = (mapping_t *)BootProcInfo.ppUMWmp;
	mp->mpFlags = 0x01000000 | mpLinkage | mpPerm | 1;
	mp->mpSpace = invalSpace;

	pmsInit();											/* Initialize the stepper */

	thread_bootstrap();

	thread = current_thread();
	thread->machine.curctx = &thread->machine.facctx;
	thread->machine.facctx.facAct = thread;
	thread->machine.umwSpace = invalSpace;				/* Initialize user memory window space to invalid */
	thread->machine.preemption_count = 1;

	cpu_bootstrap();
	cpu_init();

	master_cpu = 0;
	processor_bootstrap();

	timer_start(&thread->system_timer, mach_absolute_time());
	PROCESSOR_DATA(master_processor, kernel_timer) =
				PROCESSOR_DATA(master_processor, thread_timer) = &thread->system_timer;

	static_memory_end = round_page(args->topOfKernelData);;
      
	PE_init_platform(FALSE, args);						/* Get platform expert set up */

	if (!PE_parse_boot_arg("novmx", &novmx)) novmx=0;	/* Special run without VMX? */
	if(novmx) {											/* Yeah, turn it off */
		BootProcInfo.pf.Available &= ~pfAltivec;		/* Turn off Altivec available */
		__asm__ volatile("mtsprg 2,%0" : : "r" (BootProcInfo.pf.Available));	/* Set live value */
	}

	if (!PE_parse_boot_arg("fn", &forcenap)) forcenap = 0;	/* If force nap not set, make 0 */
	else {
		if(forcenap < 2) forcenap = forcenap + 1;		/* Else set 1 for off, 2 for on */
		else forcenap = 0;								/* Clear for error case */
	}
	
	if (!PE_parse_boot_arg("pmsx", &pmsExperimental)) pmsExperimental = 0;	/* Check if we should start in experimental power management stepper mode */
	if (!PE_parse_boot_arg("lcks", &LcksOpts)) LcksOpts = 0;	/* Set lcks options */
	if (!PE_parse_boot_arg("diag", &dgWork.dgFlags)) dgWork.dgFlags = 0;	/* Set diagnostic flags */
	if(dgWork.dgFlags & enaExpTrace) trcWork.traceMask = 0xFFFFFFFF;	/* If tracing requested, enable it */

	if(PE_parse_boot_arg("ctrc", &cputrace)) {			/* See if tracing is limited to a specific cpu */
		trcWork.traceMask = (trcWork.traceMask & 0xFFFFFFF0) | (cputrace & 0xF);	/* Limit to 4 */
	}

	if(!PE_parse_boot_arg("tb", &trcWork.traceSize)) {	/* See if non-default trace buffer size */
#if DEBUG
		trcWork.traceSize = 32;							/* Default 32 page trace table for DEBUG */
#else
		trcWork.traceSize = 8;							/* Default 8 page trace table for RELEASE */
#endif
	}

	if(trcWork.traceSize < 1) trcWork.traceSize = 1;	/* Minimum size of 1 page */
	if(trcWork.traceSize > 256) trcWork.traceSize = 256;	/* Maximum size of 256 pages */
	trcWork.traceSize = trcWork.traceSize * 4096;		/* Change page count to size */

	if (!PE_parse_boot_arg("maxmem", &maxmem))
		xmaxmem=0;
	else
		xmaxmem = (uint64_t)maxmem * (1024 * 1024);

	if (!PE_parse_boot_arg("wcte", &wcte)) wcte = 0;	/* If write combine timer enable not supplied, make 1 */
	else wcte = (wcte != 0);							/* Force to 0 or 1 */

	if (!PE_parse_boot_arg("mcklog", &mckFlags)) mckFlags = 0;	/* If machine check flags not specified, clear */
	else if(mckFlags > 1) mckFlags = 0;					/* If bogus, clear */
    
    if (!PE_parse_boot_arg("ht_shift", &hash_table_shift))  /* should we use a non-default hash table size? */
        hash_table_shift = 0;                           /* no, use default size */

	/*   
	 * VM initialization, after this we're using page tables...
	 */

	ppc_vm_init(xmaxmem, args);
	
	if(BootProcInfo.pf.Available & pf64Bit) {			/* Are we on a 64-bit machine */
		
		if(!wcte) {
			(void)ml_scom_read(GUSModeReg << 8, &scdata);	/* Get GUS mode register */
			scdata = scdata | GUSMstgttoff;					/* Disable the NCU store gather timer */
			(void)ml_scom_write(GUSModeReg << 8, scdata);	/* Get GUS mode register */
		}
		
		if(PE_parse_boot_arg("mcksoft", &mcksoft)) {	/* Have they supplied "machine check software recovery? */
			newhid = BootProcInfo.pf.pfHID5;			/* Get the old HID5 */
			if(mcksoft < 2) {
				newhid &= 0xFFFFFFFFFFFFDFFFULL;		/* Clear the old one */
				newhid |= (mcksoft & 1) << 13;			/* Set new value to enable machine check recovery */
				BootProcInfo.pf.pfHID5 = newhid;		/* Set the new one */
				hid5set64(newhid);						/* Set the hid for this processir */
			}
		}
	}
		
	machine_startup();
}

/*
 *		Routine:		ppc_init_cpu
 *		Function:
 */
void
ppc_init_cpu(
		struct per_proc_info	*proc_info) 
{
	uint64_t scdata;

	proc_info->cpu_flags &= ~SleepState;

	if((BootProcInfo.pf.Available & pf64Bit) && !wcte) {	/* Should we disable the store gather timer? */
		(void)ml_scom_read(GUSModeReg << 8, &scdata);	/* Get GUS mode register */
		scdata = scdata | GUSMstgttoff;					/* Disable the NCU store gather timer */
		(void)ml_scom_write(GUSModeReg << 8, scdata);	/* Get GUS mode register */
	}

	cpu_init();
	
	slave_main();
}
