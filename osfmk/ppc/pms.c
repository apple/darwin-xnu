/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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
#include <ppc/proc_reg.h>
#include <ppc/pms.h>
#include <ppc/savearea.h>
#include <ppc/exception.h>
#include <kern/processor.h>

extern int real_ncpus;

static uint32_t pmsSyncrolator = 0;					/* Only one control operation at a time please */
uint32_t pmsBroadcastWait = 0;						/* Number of outstanding broadcasts */

int pmsInstalled = 0;								/* Power Management Stepper can run and has table installed */
int pmsExperimental = 0;							/* Power Management Stepper in experimental mode */
decl_simple_lock_data(,pmsBuildLock)				/* Make sure only one guy can replace table  at the same time */

static pmsDef *altDpmsTab = 0;						/* Alternate step definition table */
static uint32_t altDpmsTabSize = 0;					/* Size of alternate step definition table */

pmsDef pmsDummy = {									/* This is the dummy step for initialization.  All it does is to park */
	.pmsLimit = 0,									/* Time doesn't matter for a park */
	.pmsStepID = pmsMaxStates - 1,					/* Use the very last ID number for the dummy */
	.pmsSetCmd = pmsParkIt,							/* Force us to be parked */
	.sf.pmsSetFuncInd = 0,							/* No platform call for this one */
	.pmsDown = pmsPrepSleep,						/* We always park */
	.pmsNext = pmsPrepSleep							/* We always park */
};

pmsStat pmsStatsd[4][pmsMaxStates];					/* Generate enough statistics blocks for 4 processors */

pmsCtl pmsCtls = {									/* Power Management Stepper control */
	.pmsStats = &pmsStatsd
};

pmsSetFunc_t pmsFuncTab[pmsSetFuncMax] = {0};		/* This is the function index table */
pmsQueryFunc_t pmsQueryFunc = 0;					/* Pointer to pmsQuery function */
uint32_t pmsPlatformData = 0;						/* Data provided by and passed to platform functions */


/*
 *	Do any initialization needed
 */
 
void pmsInit(void) {

	int i;
	
	simple_lock_init(&pmsBuildLock, 0);				/* Initialize the build lock */
	for(i = 0; i < pmsMaxStates; i++) pmsCtls.pmsDefs[i] = &pmsDummy;	/* Initialize the table to dummy steps */

	return;
}


/*
 *	Start the power management stepper on all processors
 *
 *	All processors must be parked.  This should be called when the hardware
 *	is ready to step.  Probably only at boot and after wake from sleep.
 *
 */
 
 void pmsStart(void) {

 	boolean_t	intr;

	if(!pmsInstalled) return;						/* We can't do this if no table installed */

	intr = ml_set_interrupts_enabled(FALSE);		/* No interruptions in here */
	pmsRun(pmsStartUp);								/* Start running the stepper everywhere */
	(void)ml_set_interrupts_enabled(intr);			/* Restore interruptions */

	return;
 
 }
 

/*
 *	Park the stepper execution.  This will force the stepper on this
 *	processor to abandon its current step and stop.  No changes to the
 *	hardware state is made and any previous step is lost.
 *	
 *	This is used as the initial state at startup and when the step table
 *	is being changed.
 *
 */
 
void pmsPark(void) {

	boolean_t	intr;

	if(!pmsInstalled) return;						/* We can't do this if no table installed */

	intr = ml_set_interrupts_enabled(FALSE);		/* No interruptions in here */
	pmsSetStep(pmsParked, 0);						/* Park the stepper */
	(void)ml_set_interrupts_enabled(intr);			/* Restore interruptions */
	
	return;

}
 

/*
 *	Steps down to a lower power.
 *	Interrupts must be off...
 */

void pmsDown(void) {

	struct per_proc_info *pp;
	uint32_t nstate;
	
	pp = getPerProc();								/* Get our per_proc */
	
	if(!pmsInstalled || pp->pms.pmsState == pmsParked) return;		/* No stepping if parked or not installed */
	
	nstate = pmsCtls.pmsDefs[pp->pms.pmsState]->pmsDown;	/* Get the downward step */
	pmsSetStep(nstate, 0);							/* Step to it */
	return;
}


/*
 *	Steps up to a higher power.  The "timer" parameter is true if the
 *	step was driven due to the pms timer expiring.
 *
 *	Interrupts must be off...
 */
 
void pmsStep(int timer) {

	struct per_proc_info *pp;
	uint32_t nstate;
	int dir;
	
	pp = getPerProc();								/* Get our per_proc */

	if(!pmsInstalled || pp->pms.pmsState == pmsParked) return;	/* No stepping if parked or not installed */
	
	nstate = pmsCtls.pmsDefs[pp->pms.pmsState]->pmsNext;	/* Assume a normal step */
	dir = 1;										/* A normal step is a step up */
	
	if(timer && (pmsCtls.pmsDefs[pp->pms.pmsState]->pmsSetCmd == pmsDelay)) {	/* If the timer expired and we are in a delay step, use the delay branch */
		nstate = pmsCtls.pmsDefs[pp->pms.pmsState]->pmsTDelay;	/* Get the delayed step */
		dir = 0;									/* Delayed steps are a step down for accounting purposes. */
	}

	pmsSetStep(nstate, dir);						/* Step to it  */
	return;
}


/*
 *	Set a specific step
 *
 *	We do not do statistics if exiting park
 *	Interrupts must be off...
 *
 */

void pmsSetStep(uint32_t nstep, int dir) {

	struct per_proc_info *pp;
	uint32_t pstate, ret, nCSetCmd, mCSetCmd;
	pmsDef *pnstate, *pcstate;
	uint64_t tb, nt, dur;
	int cpu, frompark;

	pp = getPerProc();								/* Get our per_proc */
	cpu = cpu_number();								/* Get our processor */
	
	while(1) {										/* Keep stepping until we get a delay */
		
		if(pp->pms.pmsCSetCmd & pmsMustCmp) {		/* Do we have to finish the delay before changing? */
			while(mach_absolute_time() < pp->pms.pmsPop);	/* Yes, spin here... */
		}
		
		if((nstep == pmsParked) || ((uint32_t)pmsCtls.pmsDefs[nstep]->pmsSetCmd == pmsParkIt)) {	/* Are we parking? */
			
			tb = mach_absolute_time();				/* What time is it? */
			pp->pms.pmsStamp = tb;					/* Show transition now */
			pp->pms.pmsPop = HalfwayToForever;		/* Set the pop way into the future */
			pp->pms.pmsState = pmsParked;			/* Make sure we are parked */
			setTimerReq();							/* Cancel our timer if going */
			return;
		}

		pnstate = pmsCtls.pmsDefs[nstep];			/* Point to the state definition */ 
		pstate = pp->pms.pmsState;					/* Save the current step */
		pp->pms.pmsState = nstep;					/* Set the current to the next step */

		if(pnstate->pmsSetCmd != pmsDelay) {		/* If this is not a delayed state, change the actual hardware now */
			if(pnstate->pmsSetCmd & pmsCngCPU) pmsCPUSet(pnstate->pmsSetCmd);	/* We have some CPU work to do... */
			if((uint32_t)pnstate->sf.pmsSetFunc) pnstate->sf.pmsSetFunc(pnstate->pmsSetCmd, cpu, pmsPlatformData);	/* Tell the platform to set power mode */
	
			mCSetCmd = pnstate->pmsSetCmd & (pmsCngXClk | pmsCngCPU | pmsCngVolt);	/* Isolate just the change flags */
			mCSetCmd = (mCSetCmd - (mCSetCmd >> 7)) | pmsSync | pmsMustCmp | pmsPowerID;	/* Form mask of bits that come from new command */
			nCSetCmd = pp->pms.pmsCSetCmd & ~mCSetCmd;	/* Clear changing bits */
			nCSetCmd = nCSetCmd | (pnstate->pmsSetCmd & mCSetCmd);	/* Flip on the changing bits and the always copy bits */
	
			pp->pms.pmsCSetCmd = nCSetCmd;			/* Set it for real */
		}
	
		tb = mach_absolute_time();					/* What time is it? */
		pp->pms.pmsPop = tb + pnstate->pmsLimit;	/* Set the next pop */
	
		if((pnstate->pmsSetCmd != pmsDelay) && (pp->pms.pmsCSetCmd & pmsSync) && (pnstate->pmsLimit != 0)) {	/* Is this a synchronous command with a delay? */
			while(mach_absolute_time() < pp->pms.pmsPop);	/* Yes, spin here and wait it out... */
		}

/*
 *		Gather some statistics
 */
	  
		dur = tb - pp->pms.pmsStamp;				/* Get the amount of time we were in the old step */
		pp->pms.pmsStamp = tb;						/* Set the new timestamp */
		if(!(pstate == pmsParked)) {				/* Only take stats if we were not parked */
			pcstate = pmsCtls.pmsDefs[pstate];		/* Get the previous step */
			pmsCtls.pmsStats[cpu][pcstate->pmsStepID].stTime[dir] += dur;	/* Accumulate the total time in the old step */	
			pmsCtls.pmsStats[cpu][pcstate->pmsStepID].stCnt[dir] += 1;	/* Count transitions */
		}

/*
 *		See if we are done chaining steps
 */
 
		if((pnstate->pmsSetCmd == pmsDelay) 
			|| (!(pp->pms.pmsCSetCmd & pmsSync) && (pnstate->pmsLimit != 0))) {	/* Is this not syncronous and a non-zero delay or a delayed step? */
			setTimerReq();							/* Start the timers ticking */
			break;									/* We've stepped as far as we're going to... */
		}
		
		nstep = pnstate->pmsNext;					/* Chain on to the next */
	}

	return;

}

/*
 *	Either park the stepper or force the step on a parked stepper for local processor only
 *
 */
 
void pmsRunLocal(uint32_t nstep) {

	struct per_proc_info *pp;
	uint32_t cstate, ret, lastState;
	pmsDef *pnstate, *pcstate;
	uint64_t tb, nt, dur;
	int cpu, i, j;
	boolean_t	intr;

	if(!pmsInstalled) return;						/* Ignore this if no step programs installed... */

	intr = ml_set_interrupts_enabled(FALSE);		/* No interruptions in here */

	pp = getPerProc();								/* Get our per_proc */

	if(nstep == pmsStartUp) {						/* Should we start up? */
		pmsCPUInit();								/* Get us up to full with high voltage and park */
		nstep = pmsNormHigh;						/* Change request to transition to normal high */
	}

	lastState = pp->pms.pmsState;					/* Remember if we are parked now */

	pmsSetStep(nstep, 1);							/* Step to the new state */
	
	if((lastState == pmsParked) && (pp->pms.pmsState != pmsParked)) {	/* Did we just unpark? */
		cpu = cpu_number();							/* Get our processor */
		for(i = 0; i < pmsMaxStates; i++) {			/* Step through the steps and clear the statistics since we were parked */
			pmsCtls.pmsStats[cpu][i].stTime[0] = 0;	/* Clear accumulated time - downward */	
			pmsCtls.pmsStats[cpu][i].stTime[1] = 0;	/* Clear accumulated time - forward */	
			pmsCtls.pmsStats[cpu][i].stCnt[0] = 0;	/* Clear transition count - downward */
			pmsCtls.pmsStats[cpu][i].stCnt[1] = 0;	/* Clear transition count - forward */
		}
	}

	(void)ml_set_interrupts_enabled(intr);			/* Restore interruptions */

	return;

}

/*
 *	Control the Power Management Stepper.
 *	Called from user state by the superuser via a ppc system call.
 *	Interruptions disabled.
 *
 */

int pmsCntrl(struct savearea *save) {

	uint32_t request, nstep, reqsize, result, presult;
	int ret, cpu;
	kern_return_t kret;
	pmsDef *ndefs;
	struct per_proc_info *pp;

	pp = getPerProc();								/* Get our per_proc */
	cpu = cpu_number();								/* Get our processor */
	
	if(!is_suser()) {								/* We are better than most, */
		save->save_r3 = KERN_FAILURE;				/* so we will only talk to the superuser. */
		return 1;									/* Turn up our noses, say "harrumph," and walk away... */
	}
	
	if(save->save_r3 >= pmsCFree) {					/* Can we understand the request? */
		save->save_r3 = KERN_INVALID_ARGUMENT;		/* What language are these guys talking in, anyway? */
		return 1;									/* Cock head like a confused puppy and run away... */
	}
	
	request = (int)save->save_r3;					/* Remember the request */
	reqsize = (uint32_t)save->save_r5;				/* Get the size of the config table */

	if(request == pmsCQuery) {						/* Are we just checking? */
		result = pmsCPUquery() & pmsCPU;			/* Get the processor data and make sure there is no slop */
		presult = 0;								/* Assume nothing */
		if((uint32_t)pmsQueryFunc) presult = pmsQueryFunc(cpu, pmsPlatformData);	/* Go get the platform state */
		result = result | (presult & (pmsXClk | pmsVoltage | pmsPowerID));	/* Merge the platform state with no slop */
		save->save_r3 = result;						/* Tell 'em... */
		return 1;
	}
	
	if(request == pmsCExperimental) {				/* Enter experimental mode? */
	
		if(pmsInstalled || (pmsExperimental & 1)) {	/* Are we already running or in experimental? */
			save->save_r3 = KERN_FAILURE;			/* Fail, since we are already running */
			return 1;
		}
		
		pmsExperimental |= 1;						/* Flip us into experimental but don't change other flags */
		
		pmsCPUConf();								/* Configure for this machine */
		pmsStart();									/* Start stepping */
		save->save_r3 = KERN_SUCCESS;				/* We are victorious... */
		return 1;
	
	}

	if(request == pmsCCnfg) {						/* Do some up-front checking before we commit to doing this */
		if((reqsize > (pmsMaxStates * sizeof(pmsDef))) || (reqsize < (pmsFree * sizeof(pmsDef)))) {	/* Check that the size is reasonable */
			save->save_r3 = KERN_NO_SPACE;			/* Tell them that they messed up */
			return 1;								/* l8r... */
		}
	}


/*
 *	We are committed after here.  If there are any errors detected, we shouldn't die, but we
 *	will be stuck in park.
 *
 *	Also, we can possibly end up on another processor after the broadcast.
 *
 */
 		
	if(!hw_compare_and_store(0, 1, &pmsSyncrolator)) {	/* Are we already doing this? */
		save->save_r3 = KERN_RESOURCE_SHORTAGE;		/* Tell them that we are already busy and to try again */
		return 1;									/* G'wan away and don't bother me... */
	}
	save->save_r3 = KERN_SUCCESS;					/* Assume success */

//	NOTE:  We will block in the following code until everyone has finished the prepare

	pmsRun(pmsPrepCng);								/* Get everyone parked and in a proper state for step table changes, including me */
	
	if(request == pmsCPark) {						/* Is all we're supposed to do park? */
		pmsSyncrolator = 0;							/* Free us up */
		return 1;									/* Well, then we're done... */
	}
	
	switch(request) {								/* Select the routine */

		case pmsCStart:								/* Starts normal steppping */
			nstep = pmsNormHigh;					/* Set the request */
			break;

		case pmsCFLow:								/* Forces low power */
			nstep = pmsLow;							/* Set request */
			break;

		case pmsCFHigh:								/* Forces high power */
			nstep = pmsHigh;						/* Set request */
			break;

		case pmsCCnfg:								/* Loads new stepper program */
			
			if(!(ndefs = (pmsDef *)kalloc(reqsize))) {	/* Get memory for the whole thing */
				save->save_r3 = KERN_INVALID_ADDRESS;	/* Return invalid address */
				pmsSyncrolator = 0;					/* Free us up */
				return 1;							/* All done... */
			}
			
			ret = copyin((user_addr_t)((unsigned int)(save->save_r4)), (void *)ndefs, reqsize);	/* Get the new config table */
			if(ret) {								/* Hmmm, something went wrong with the copyin */
				save->save_r3 = KERN_INVALID_ADDRESS;	/* Return invalid address */
				kfree((vm_offset_t)ndefs, reqsize);	/* Free up the copied in data */
				pmsSyncrolator = 0;					/* Free us up */
				return 1;							/* All done... */
			}

			kret = pmsBuild(ndefs, reqsize, 0, 0, 0);	/* Go build and replace the tables.  Make sure we keep the old platform stuff */
			if(kret) {								/* Hmmm, something went wrong with the compilation */
				save->save_r3 = kret;				/* Pass back the passed back return code */
				kfree((vm_offset_t)ndefs, reqsize);	/* Free up the copied in data */
				pmsSyncrolator = 0;					/* Free us up */
				return 1;							/* All done... */
			}

			nstep = pmsNormHigh;					/* Set the request */
			break;

		default:
			panic("pmsCntrl: stepper control is so very, very confused = %08X\n", request);
	
	}

	pmsRun(nstep);									/* Get everyone into step */
	pmsSyncrolator = 0;								/* Free us up */
	return 1;										/* All done... */

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
 
void pmsRun(uint32_t nstep) {

	pmsRunLocal(nstep);								/* If we aren't parking (we are already parked), transition ourselves */
	(void)cpu_broadcast(&pmsBroadcastWait, pmsRemote, nstep);	/* Tell everyone else to do it too */

	return;
	
}

/*
 *	Receive a broadcast and react.
 *	This is called from the interprocessor signal handler.
 *	We wake up the initiator after we are finished.
 *
 */
	
void pmsRemote(uint32_t nstep) {

	pmsRunLocal(nstep);								/* Go set the step */
	if(!hw_atomic_sub(&pmsBroadcastWait, 1)) {		/* Drop the wait count */
		thread_wakeup((event_t)&pmsBroadcastWait);	/* If we were the last, wake up the signaller */
	}
	return;
}	


/*
 *	Build the tables needed for the stepper.  This includes both the step definitions and the step control table.
 *
 *	We most absolutely need to be parked before this happens because we're gonna change the table.
 *	We're going to have to be pretty complete about checking for errors.
 *	Also, a copy is always made because we don't want to be crippled by not being able to change
 *	the table or description formats.
 *
 *	We pass in a table of external functions and the new stepper def uses the corresponding 
 *	indexes rather than actual function addresses.  This is done so that a proper table can be
 *	built with the control syscall.  It can't supply addresses, so the index has to do.  We
 *	internalize the table so our caller does not need to keep it.  Note that passing in a 0
 *	will use the current function table.  Also note that entry 0 is reserved and must be 0,
 *	we will check and fail the build.
 *
 *	The platformData parameter is a 32-bit word of data that is passed unaltered to the set function.
 *
 *	The queryFunc parameter is the address of a function that will return the current state of the platform.
 *	The format of the data returned is the same as the platform specific portions of pmsSetCmd, i.e., pmsXClk,
 *	pmsVoltage, and any part of pmsPowerID that is maintained by the platform hardware (an example would be
 *	the values of the gpios that correspond to pmsPowerID).  The value should be constructed by querying
 *	hardware rather than returning a value cached by software. One of the intents of this function is to 
 *	help recover lost or determine initial power states.
 *
 */
 
kern_return_t pmsBuild(pmsDef *pd, uint32_t pdsize, pmsSetFunc_t *functab, uint32_t platformData, pmsQueryFunc_t queryFunc) {

	int steps, newsize, i, cstp, nstps, oldAltSize, xdsply;
	uint32_t setf;
	uint64_t nlimit;
	pmsDef *newpd, *oldAlt;
	boolean_t intr;

	xdsply = (pmsExperimental & 3) != 0;			/* Turn on kprintfs if requested or in experimental mode */

	if(pdsize % sizeof(pmsDef)) return KERN_INVALID_ARGUMENT;	/* Length not multiple of definition size */
	
	steps = pdsize / sizeof(pmsDef);				/* Get the number of steps supplied */

	if((steps >= pmsMaxStates) || (steps < pmsFree))	/* Complain if too big or too small */
			return KERN_INVALID_ARGUMENT;			/* Squeak loudly!!! */
			
	if((uint32_t)functab && (uint32_t)functab[0])	/* Verify that if they supplied a new function table, entry 0 is 0 */
		return KERN_INVALID_ARGUMENT;				/* Fail because they didn't reserve entry 0 */
			
	if(xdsply) kprintf("\n  StepID   Down   Next    HWSel  HWfun                Limit\n");

	for(i = 0; i < steps; i++) {					/* Step through and verify the definitions */

		if(xdsply) kprintf("  %6d %6d %6d %08X %6d %20lld\n", pd[i].pmsStepID, pd[i].pmsDown, 
			pd[i].pmsNext, pd[i].pmsSetCmd,
			pd[i].sf.pmsSetFuncInd, pd[i].pmsLimit);

		if((pd[i].pmsLimit != 0) && (pd[i].pmsLimit < 100ULL)) {
			if(xdsply) kprintf("error step %3d: pmsLimit too small/n", i);
			return KERN_INVALID_ARGUMENT;	/* Has to be 100µS or more */
		}
		
		if((pd[i].pmsLimit != 0xFFFFFFFFFFFFFFFFULL) && (pd[i].pmsLimit > (HalfwayToForever / 1000ULL))) {
			if(xdsply) kprintf("error step %3d: pmsLimit too big\n", i);
			return KERN_INVALID_ARGUMENT;			/* Can't be too big */
		}
		
		if(pd[i].pmsStepID != i) {
			if(xdsply) kprintf("error step %3d: step ID does not match (%d)\n", i, pd[i].pmsStepID);
			return KERN_INVALID_ARGUMENT;	/* ID must match */
		}

		if(pd[i].sf.pmsSetFuncInd >= pmsSetFuncMax) {
			if(xdsply) kprintf("error step %3d: function invalid (%d)\n", i, pd[i].sf.pmsSetFuncInd);
			return KERN_INVALID_ARGUMENT;	/* Fail if this function is not in the table */
		}
		
		if((pd[i].pmsDown != pmsParked) && pd[i].pmsDown >= steps) {
			if(xdsply) kprintf("error step %3d: pmsDown out of range (%d)\n", i, pd[i].pmsDown);
			return KERN_INVALID_ARGUMENT;	/* Step down must be in the table or park */
		}
		
		if((pd[i].pmsNext != pmsParked) && pd[i].pmsNext >= steps) {
			if(xdsply) kprintf("error step %3d: pmsNext out of range (%d)\n", i, pd[i].pmsNext);
			return KERN_INVALID_ARGUMENT;	/* Step up must be in the table or park */
		}
		
		if((pd[i].pmsSetCmd == pmsDelay) && (pd[i].pmsTDelay >= steps)) {
			if(xdsply) kprintf("error step %3d: pmsTDelay out of range (%d)\n", i, pd[i].pmsTDelay);
			return KERN_INVALID_ARGUMENT;	/* Delayed step must be in the table */
		}
		
		if((pd[i].pmsSetCmd == pmsDelay) && (pd[i].pmsLimit == 0xFFFFFFFFFFFFFFFFULL)) {
			if(xdsply) kprintf("error step %3d: delay time limit must not be infinite\n", i);
			return KERN_INVALID_ARGUMENT;	/* Delayed step must have a time limit */
		}
		
	}
	
/*
 *	Verify that there are no infinite synchronous forward loops in the table
 */
 
	if(xdsply) kprintf("\nInitial scan passed, start in loop check\n");
	for(i = 0; i < steps; i++) {					/* Start with each step. Inefficient, but who cares */
 
		cstp = i;									/* Set starting point */
		nstps = 0;									/* Initialize chain length counter */
		while(1) {									/* Do until we hit the end */
			if(pd[cstp].pmsSetCmd == pmsParkIt) break;	/* Parking always terminates a chain so no endless loop here */
			if(pd[cstp].pmsSetCmd == pmsDelay) break;	/* Delayed steps always terminate a chain so no endless loop here */
			if((pd[cstp].pmsLimit != 0) && ((pd[cstp].pmsSetCmd & pmsSync) != pmsSync)) break;	/* If time limit is not 0 and not synchrouous, no endless loop */
			if(pd[cstp].pmsNext == pmsParked) break;	/* If the next step is parked, no endless loop */
			
 			cstp = pd[cstp].pmsNext;				/* Chain to the next */
 			nstps = nstps + 1;						/* Count this step */
 			if(nstps >= steps) {					/* We've stepped for more steps than we have, must be an endless loop! */
				if(xdsply) kprintf("error step %3d: infinite pmsNext loop\n", i);
		 		return KERN_INVALID_ARGUMENT;		/* Suggest to our caller that they can't program... */
 			}
 		}
	}
	
	if((pmsExperimental & 4) && (pmsInstalled) && ((uint32_t)functab != 0)) {	/* If we are already initted and experimental is locked in, and we are doing first */
		if(xdsply) kprintf("Experimental locked, ignoring driver pmsBuild\n");
		return KERN_RESOURCE_SHORTAGE;				/* Just ignore the request. */
	}
	
	
	
/*
 *	Well, things look ok, let's do it to it...
 */

	if(xdsply) kprintf("Loop check passed, building and installing table\n");

	newsize = steps * sizeof(pmsDef);				/* Get the size needed for the definition blocks */

	if(!(newpd = (pmsDef *)kalloc(newsize))) {		/* Get memory for the whole thing */
		return KERN_RESOURCE_SHORTAGE;				/* No storage... */
	}
	
	bzero((void *)newpd, newsize);					/* Make it pretty */
	
/*
 *	Ok, this is it, finish intitializing, switch the tables, and pray...
 *	We want no interruptions at all and we need to lock the table.  Everybody should be parked,
 *	so no one should ever touch this.  The lock is to keep multiple builders safe.  It probably
 *	will never ever happen, but paranoia is a good thing...
 */
 
	intr = ml_set_interrupts_enabled(FALSE);		/* No interruptions in here */
	simple_lock(&pmsBuildLock);						/* Lock out everyone... */
	
	if(platformData) pmsPlatformData = platformData;	/* Remember the platform data word passed in if any was... */
	if((uint32_t)queryFunc) pmsQueryFunc = queryFunc;	/* Remember the query function passed in, if it was... */
	
	oldAlt = altDpmsTab;							/* Remember any old alternate we had */
	oldAltSize = altDpmsTabSize;					/* Remember its size */

	altDpmsTab = newpd;								/* Point to the new table */
	altDpmsTabSize = newsize;						/* Set the size */
	
	if((uint32_t)functab) {							/* Did we get a new function table? */
		for(i = 0; i < pmsSetFuncMax; i++) pmsFuncTab[i] = functab[i];	/* Copy in the new table */
	}

	for(i = 0; i < pmsMaxStates; i++) pmsCtls.pmsDefs[i] = &pmsDummy;	/* Initialize the table to point to the dummy step */

	for(i = 0; i < steps; i++) {					/* Replace the step table entries */
		if(pd[i].pmsLimit == 0xFFFFFFFFFFFFFFFFULL) nlimit = century;	/* Default to 100 years */
		else nlimit = pd[i].pmsLimit;				/* Otherwise use what was supplied */
		
		nanoseconds_to_absolutetime(nlimit * 1000ULL, &newpd[i].pmsLimit);	/* Convert microseconds to nanoseconds and then to ticks */
	
		setf = pd[i].sf.pmsSetFuncInd;					/* Make convienient */
		newpd[i].sf.pmsSetFunc = pmsFuncTab[setf];		/* Replace the index with the function address */
	 
		newpd[i].pmsStepID  = pd[i].pmsStepID;		/* Set the step ID */ 
		newpd[i].pmsSetCmd  = pd[i].pmsSetCmd;		/* Set the hardware selector ID */
		newpd[i].pmsDown    = pd[i].pmsDown;		/* Set the downward step */
		newpd[i].pmsNext    = pd[i].pmsNext;		/* Set the next setp */
		newpd[i].pmsTDelay  = pd[i].pmsTDelay;		/* Set the delayed setp */
		pmsCtls.pmsDefs[i]  = &newpd[i];			/* Copy it in */
	}
	
	pmsCtlp = (uint32_t)&pmsCtls;					/* Point to the new pms table */
	
 	pmsInstalled = 1;								/* The stepper has been born or born again... */

	simple_unlock(&pmsBuildLock);					/* Free play! */
	(void)ml_set_interrupts_enabled(intr);			/* Interrupts back the way there were */

	if((uint32_t)oldAlt) kfree((vm_offset_t)oldAlt, oldAltSize);	/* If we already had an alternate, free it */

	if(xdsply) kprintf("Stepper table installed\n");
	
	return KERN_SUCCESS;							/* We're in fate's hands now... */
}
