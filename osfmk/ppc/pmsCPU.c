/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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
#include <ppc/machine_routines.h>
#include <ppc/machine_cpu.h>
#include <ppc/exception.h>
#include <ppc/misc_protos.h>
#include <ppc/Firmware.h>
#include <ppc/pmap.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <kern/pms.h>
#include <ppc/savearea.h>
#include <ppc/Diagnostics.h>
#include <kern/processor.h>


static void pmsCPURemote(uint32_t nstep);


pmsDef pmsDefault[] = {
	{
		.pmsLimit = century,							/* We can normally stay here for 100 years */
		.pmsStepID = pmsIdle,							/* Unique identifier to this step */
		.pmsSetCmd = 0,									/* Dummy platform power level */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsIdle,								/* We stay here */
		.pmsNext = pmsNorm								/* Next step */
	},
	{
		.pmsLimit = century,							/* We can normally stay here for 100 years */
		.pmsStepID = pmsNorm,							/* Unique identifier to this step */
		.pmsSetCmd = 0,									/* Dummy platform power level */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsIdle,								/* Down to idle */
		.pmsNext = pmsNorm								/* Next step */
	},
	{
		.pmsLimit = century,							/* We can normally stay here for 100 years */
		.pmsStepID = pmsNormHigh,						/* Unique identifier to this step */
		.pmsSetCmd = 0,									/* Dummy platform power level */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsIdle,								/* Down to idle */
		.pmsNext = pmsNormHigh							/* Next step */
	},
	{
		.pmsLimit = century,							/* We can normally stay here for 100 years */
		.pmsStepID = pmsBoost,							/* Unique identifier to this step */
		.pmsSetCmd = 0,									/* Dummy platform power level */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsIdle,								/* Step down */
		.pmsNext = pmsBoost								/* Next step */
	},	
	{	
		.pmsLimit = century,							/* We can normally stay here for 100 years */
		.pmsStepID = pmsLow,							/* Unique identifier to this step */
		.pmsSetCmd = 0,									/* Dummy platform power level */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsLow,								/* We always stay here */
		.pmsNext = pmsLow								/* We always stay here */
	},	
	{	
		.pmsLimit = century,							/* We can normally stay here for 100 years */
		.pmsStepID = pmsHigh,							/* Unique identifier to this step */
		.pmsSetCmd = 0,									/* Dummy platform power level */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsHigh,								/* We always stay here */
		.pmsNext = pmsHigh								/* We always stay here */
	},	
	{	
		.pmsLimit = 0,									/* Time doesn't matter for a prepare for change */
		.pmsStepID = pmsPrepCng,						/* Unique identifier to this step */
		.pmsSetCmd = pmsParkIt,							/* Force us to be parked */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsPrepCng,							/* We always stay here */
		.pmsNext = pmsPrepCng							/* We always stay here */
	},	
	{	
		.pmsLimit = 0,									/* Time doesn't matter for a prepare for sleep */
		.pmsStepID = pmsPrepSleep,						/* Unique identifier to this step */
		.pmsSetCmd = pmsParkIt,							/* Force us to be parked */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsPrepSleep,						/* We always stay here */
		.pmsNext = pmsPrepSleep							/* We always stay here */
	},	
	{	
		.pmsLimit = 0,									/* Time doesn't matter for a prepare for sleep */
		.pmsStepID = pmsOverTemp,						/* Unique identifier to this step */
		.pmsSetCmd = 0,									/* Dummy platform power level */
		.sf.pmsSetFuncInd = 0,							/* Dummy platform set function */
		.pmsDown = pmsOverTemp,							/* We always stay here */
		.pmsNext = pmsOverTemp							/* We always stay here */
	}	
};



/*
 *	This is where the CPU part of the stepper code lives.   
 *
 *	It also contains the "hacked kext" experimental code.  This is/was used for
 *	experimentation and bringup.  It should neither live long nor prosper.
 *
 */

/*
 *	Set the processor frequency and stuff
 */

void pmsCPUSet(uint32_t sel) {
	int nfreq;
	struct per_proc_info *pp;

	pp = getPerProc();									/* Get our per_proc */

	if(!((sel ^ pp->pms.pmsCSetCmd) & pmsCPU)) return;	/* If there aren't any changes, bail now... */

	nfreq = (sel & pmsCPU) >> 16;						/* Isolate the new frequency */
	
	switch(pp->pf.pfPowerModes & pmType) {				/* Figure out what type to do */
	
		case pmDFS:										/* This is a DFS machine */
			ml_set_processor_speed_dfs(nfreq);			/* Yes, set it */
			break;
	
		case pmDualPLL:
			ml_set_processor_speed_dpll(nfreq);			/* THIS IS COMPLETELY UNTESTED!!! */
			break;

		case pmPowerTune:								/* This is a PowerTune machine */
			ml_set_processor_speed_powertune(nfreq);	/* Diddle the deal */
			break;
			
		default:										/* Not this time dolt!!! */
			panic("pmsCPUSet: unsupported power manager type: %08X\n", pp->pf.pfPowerModes);
			break;
	
	}
	
}

/*
 *	This code configures the initial step tables.  It should be called after the timebase frequency is initialized.
 */

void pmsCPUConf(void) {

	int i;
	kern_return_t ret;
	pmsSetFunc_t pmsDfltFunc[pmsSetFuncMax];			/* List of functions for the external power control to use */

	for(i = 0; i < pmsSetFuncMax; i++) pmsDfltFunc[i] = NULL;	/* Clear this */


	ret = pmsBuild((pmsDef *)&pmsDefault, sizeof(pmsDefault), pmsDfltFunc, 0, (pmsQueryFunc_t)0);	/* Configure the default stepper */

	if(ret != KERN_SUCCESS) {							/* Some screw up? */
		panic("pmsCPUConf: initial stepper table build failed, ret = %08X\n", ret);	/* Squeal */
	}
	
	pmsSetStep(pmsHigh, 1);								/* Slew to high speed */
	pmsPark();											/* Then park */
	return;
}

/*
 * Machine-dependent initialization
 */
void
pmsCPUMachineInit(void)
{
	return;
}

/*
 *	This function should be called once for each processor to force the
 *	processor to the correct voltage and frequency.
 */
 
void pmsCPUInit(void) {

	int cpu;

	cpu = cpu_number();									/* Who are we? */
	
	kprintf("************ Initializing stepper hardware, cpu %d ******************\n", cpu);	/* (BRINGUP) */
	
	pmsSetStep(pmsHigh, 1);								/* Slew to high speed */
	pmsPark();											/* Then park */

	kprintf("************ Stepper hardware initialized, cpu %d ******************\n", cpu);	/* (BRINGUP) */
}

extern uint32_t hid1get(void);

uint32_t
pmsCPUQuery(void)
{
	uint32_t result;
	struct per_proc_info *pp;
	uint64_t scdata;

	pp = getPerProc();									/* Get our per_proc */

	switch(pp->pf.pfPowerModes & pmType) {				/* Figure out what type to do */
	
		case pmDFS:										/* This is a DFS machine */
			result = hid1get();							/* Get HID1 */
			result = (result >> 6) & 0x00030000;		/* Isolate the DFS bits */
			break;
			
		case pmPowerTune:								/* This is a PowerTune machine */		
			(void)ml_scom_read(PowerTuneStatusReg, &scdata);	/* Get the current power level */
			result = (scdata >> (32 + 8)) & 0x00030000;	/* Shift the data to align with the set command */
			break;
			
		default:										/* Query not supported for this kind */
			result = 0;									/* Return highest if not supported */
			break;
	
	}

	return result;
}

/*
 *	These are not implemented for PPC.
 */
void pmsCPUYellowFlag(void) {
}

void pmsCPUGreenFlag(void) {
}

uint32_t pmsCPUPackageQuery(void)
{
    	/* multi-core CPUs are not supported. */
    	return(~(uint32_t)0);
}

/*
 *	Broadcast a change to all processors including ourselves.
 *	This must transition before broadcasting because we may block and end up on a different processor.
 *
 *	This will block until all processors have transitioned, so
 *	obviously, this can block.
 *
 *	Called with interruptions disabled.
 *
 */
 
void pmsCPURun(uint32_t nstep) {

	pmsRunLocal(nstep);								/* If we aren't parking (we are already parked), transition ourselves */
	(void)cpu_broadcast(&pmsBroadcastWait, pmsCPURemote, nstep);	/* Tell everyone else to do it too */

	return;
	
}

/*
 *	Receive a broadcast and react.
 *	This is called from the interprocessor signal handler.
 *	We wake up the initiator after we are finished.
 *
 */
	
static void pmsCPURemote(uint32_t nstep) {

	pmsRunLocal(nstep);								/* Go set the step */
	if(!hw_atomic_sub(&pmsBroadcastWait, 1)) {		/* Drop the wait count */
		thread_wakeup((event_t)&pmsBroadcastWait);	/* If we were the last, wake up the signaller */
	}
	return;
}	

/*
 *	Control the Power Management Stepper.
 *	Called from user state by the superuser via a ppc system call.
 *	Interruptions disabled.
 *
 */
int pmsCntrl(struct savearea *save) {
	save->save_r3 = pmsControl(save->save_r3, (user_addr_t)(uintptr_t)save->save_r4, save->save_r5);
	return 1;
}



