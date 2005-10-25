/*
 * Copyright (c) 2004-2005 Apple Computer, Inc. All rights reserved.
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

#ifdef KERNEL_PRIVATE

#ifndef _PPC_PMS_H_
#define _PPC_PMS_H_

#define pmsMaxStates 64
#define HalfwayToForever 0x7FFFFFFFFFFFFFFFULL
#define century 790560000000000ULL

typedef void (*pmsSetFunc_t)(uint32_t, uint32_t, uint32_t);	/* Function used to set hardware power state */
typedef uint32_t (*pmsQueryFunc_t)(uint32_t, uint32_t);	/* Function used to query hardware power state */

typedef struct pmsStat {
	uint64_t	stTime[2];			/* Total time until switch to next step */
	uint32_t	stCnt[2];			/* Number of times switched to next step */
} pmsStat;

typedef struct pmsDef {
	uint64_t	pmsLimit;			/* Max time in this state in microseconds */
	uint32_t	pmsStepID;			/* Unique ID for this step */
	uint32_t	pmsSetCmd;			/* Command to select power state */
#define pmsCngXClk  0x80000000		/* Change external clock */
#define pmsXUnk   	0x7F			/* External clock unknown  */
#define pmsXClk     0x7F000000		/* External clock frequency */
#define pmsCngCPU   0x00800000		/* Change CPU parameters */
#define pmsSync     0x00400000		/* Make changes synchronously, i.e., spin until delay finished */
#define pmsMustCmp  0x00200000		/* Delay must complete before next change */
#define pmsCPU      0x001F0000		/* CPU frequency */
#define pmsCPUUnk	0x1F			/* CPU frequency unknown */
#define pmsCngVolt  0x00008000		/* Change voltage */
#define pmsVoltage  0x00007F00		/* Voltage */
#define pmsVoltUnk	0x7F			/* Voltage unknown */
#define pmsPowerID  0x000000FF		/* Identify power state to HW */

/*	Special commands - various things */
#define pmsDelay    0xFFFFFFFD		/* Delayed step, no processor or platform changes.  Timer expiration causes transition to pmsTDelay */
#define pmsParkIt	0xFFFFFFFF		/* Enters the parked state.  No processor or platform changes.  Timers cancelled */
#define pmsCInit	((pmsXUnk << 24) | (pmsCPUUnk << 16) | (pmsVoltUnk << 8))	/* Initial current set command value */
/*	Note:  pmsSetFuncInd is an index into a table of function pointers and pmsSetFunc is the address
 *	of a function.  Initially, when you create a step table, this field is set as an index into
 *	a table of function addresses that gets passed as a parameter to pmsBuild.  When pmsBuild
 *	internalizes the step and function tables, it converts the index to the function address.
 */
	union sf {
		pmsSetFunc_t	pmsSetFunc;	/* Function used to set platform power state */
		uint32_t	pmsSetFuncInd;	/* Index to function in function table */
	} sf;

	uint32_t	pmsDown;			/* Next state if going lower */
	uint32_t	pmsNext;			/* Normal next state */
	uint32_t	pmsTDelay;			/* State if command was pmsDelay and timer expired */
} pmsDef;

typedef struct pmsCtl {
	pmsStat		(*pmsStats)[pmsMaxStates];	/* Pointer to statistics information, 0 if not enabled */
	pmsDef		*pmsDefs[pmsMaxStates];	/* Indexed pointers to steps */
} pmsCtl;

/*
 *	Note that this block is in the middle of the per_proc and the size (32 bytes)
 *	can't be changed without moving it.
 */

typedef struct pmsd {
	uint32_t	pmsState;			/* Current power management state */
	uint32_t	pmsCSetCmd;			/* Current select command */
	uint64_t	pmsPop;				/* Time of next step */
	uint64_t	pmsStamp;			/* Time of transition to current state */
	uint64_t	pmsTime;			/* Total time in this state */
} pmsd;

/*
 *	Required power management step programs
 */
 
enum {
	pmsIdle      = 0,				/* Power state in idle loop */
	pmsNorm      = 1,				/* Normal step - usually low power */
	pmsNormHigh  = 2,				/* Highest power in normal step */
	pmsBoost     = 3,				/* Boost/overdrive step */
	pmsLow       = 4,				/* Lowest non-idle power state, no transitions */
	pmsHigh      = 5,				/* Power step for full on, no transitions */
	pmsPrepCng   = 6,				/* Prepare for step table change */
	pmsPrepSleep = 7,				/* Prepare for sleep */
	pmsOverTemp  = 8,				/* Machine is too hot */
	pmsEnterNorm = 9,				/* Enter into the normal step program */
	pmsFree      = 10,				/* First available empty step */
	pmsStartUp   = 0xFFFFFFFE,		/* Start stepping */
	pmsParked    = 0xFFFFFFFF		/* Power parked - used when changing stepping table */
};

/*
 *	Power Management Stepper Control requests
 */
 
enum {
	pmsCPark = 0,					/* Parks the stepper */
	pmsCStart = 1,					/* Starts normal steppping */
	pmsCFLow = 2,					/* Forces low power */
	pmsCFHigh = 3,					/* Forces high power */
	pmsCCnfg = 4,					/* Loads new stepper program */
	pmsCQuery = 5,					/* Query current step and state */
	pmsCExperimental = 6,			/* Enter experimental mode */
	pmsCFree = 7					/* Next control command to be assigned */
};

extern pmsCtl pmsCtls;				/* Power Management Stepper control */
extern uint32_t pmsCtlp;
extern uint32_t pmsBroadcastWait;	/* Number of outstanding broadcasts */
extern pmsDef pmsDefault[];
extern int pmsInstalled;
extern int pmsExperimental;

#define pmsSetFuncMax 32
extern pmsSetFunc_t pmsFuncTab[pmsSetFuncMax];
extern pmsQueryFunc_t pmsQueryFunc;
extern uint32_t pmsPlatformData;

extern int pmsCntrl(struct savearea *save);
extern void pmsInit(void);
extern void pmsStep(int timer);
extern void pmsDown(void);
extern void pmsSetStep(uint32_t nstep, int dir);
extern void pmsRemote(uint32_t nstep);
extern void pmsCPUSet(uint32_t sel);
extern uint32_t pmsCPUquery(void);
extern void pmsCPUConf(void);
extern void pmsCPUInit(void);

#ifdef __cplusplus
extern "C" {
#endif

extern kern_return_t pmsBuild(pmsDef *pd, uint32_t pdsize, pmsSetFunc_t *functab, uint32_t platformData, pmsQueryFunc_t queryFunc);
extern void pmsRun(uint32_t nstep);
extern void pmsRunLocal(uint32_t nstep);
extern void pmsPark(void);
extern void pmsStart(void);

#ifdef __cplusplus
}
#endif

#endif /* _PPC_PMS_H_ */
#endif /* KERNEL_PRIVATE */
