/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
#ifndef _I386_PMCPU_H_
#define _I386_PMCPU_H_

#include <kern/pms.h>

#ifndef ASSEMBLER

typedef enum { C1, C2, C3, C4, Hlt, C3Res, All, Cnum } pm_Cstate_t;
typedef struct pmStats {
	uint64_t	pmNapCnt[Cnum];		/* Total nap calls for states */
	uint64_t	pmNapTime[Cnum];	/* Total nap time for states */
	uint64_t	pmNapC2HPET;		/* Total nap time for C2 using HPET for stats */
	uint64_t	pmNapC4HPET;		/* Total nap time for C4 using HPET for stats */
	uint64_t	pmNapHPETPops;		/* Number of times we detect HPET popping */
	uint64_t	pmHPETRupt;		/* Number of HPET interruptions */
	uint32_t	pmCurC3Res;		/* Current value of the C3 residency timer */
	uint32_t	pmLastApic;		/* Last value of apic timer */
	uint32_t	pmNewApic;		/* New value of apic timer */
	uint64_t	pmHpetTim;		/* Time to next interrupt in HPET ticks */
	uint64_t	pmHpetCmp;		/* HPET comparator */
	uint64_t	pmHpetCfg;		/* HPET configuration */
	uint64_t	pmLSNs;			/* (TEST) Last set nanotime */
	uint64_t	pmLLHpet;		/* (TEST) Last loaded HPET */
} pmStats_t;

#define MAX_PSTATES	32			/* architectural limit */

typedef enum { Cn1, Cn2, Cn3, Cn4, Cnmax } Cstate_number_t;
typedef struct {
	Cstate_number_t	number;
	uint32_t	hint;
} Cstate_hint_t;


struct pmData {
	uint8_t pad[93];
};
typedef struct 	pmData pmData_t;

#define pmNapHalt	0x00000010
#define pmNapC1		0x00000008
#define pmNapC2		0x00000004
#define pmNapC3		0x00000002
#define pmNapC4		0x00000001
#define pmNapMask	0x000000FF

#define cfgAdr 		0xCF8
#define cfgDat 		0xCFC
#define lpcCfg 		(0x80000000 | (0 << 16) | (31 << 11) | (0 << 8))

/*
 * Dispatch table for functions that get installed when the power
 * management KEXT loads.
 */
typedef struct
{
    /*
     * The following are the stepper table interfaces.
     */
    void	(*pmsCPUMachineInit)(void);
    void	(*pmsCPUInit)(void);
    void	(*pmsCPUSet)(uint32_t sel);
    void	(*pmsCPUConf)(void);
    void	(*pmsCPURun)(uint32_t nstep);
    uint32_t	(*pmsCPUQuery)(void);
    uint32_t	(*pmsCPUPackageQuery)(void);
    void	(*pmsCPUYellowFlag)(void);
    void	(*pmsCPUGreenFlag)(void);
    kern_return_t	(*pmsCPULoadVIDTable)(uint16_t *tablep, int nstates);
    kern_return_t	(*pmsCPUSetPStateLimit)(uint32_t limit);

    /*
     * The following are the 'C' State interfaces.
     */
    void	(*cstateInit)(void);
    void	(*cstateMachineIdle)(uint32_t napCtl);
    kern_return_t	(*cstateTableSet)(Cstate_hint_t *tablep, unsigned int nstates);
    uint32_t	(*cstateNapPolicy)(uint32_t forcenap, uint32_t napCtl);
} pmDispatch_t;

typedef struct {
    uint32_t		PState;
    uint32_t		PLimit;
    uint16_t		VIDTable[MAX_PSTATES];
    uint32_t		VIDTableCount;
    Cstate_hint_t	CStates[Cnmax];
    uint32_t		CStatesCount;
} pmInitState_t;

typedef struct {
    void	(*Park)(void);
    void	(*Run)(uint32_t nstep);
    void	(*RunLocal)(uint32_t nstep);
    void	(*SetStep)(uint32_t nstep, int dir);
    void	(*NapPolicy)(void);
    kern_return_t	(*Build)(pmsDef *pd, uint32_t pdsize, pmsSetFunc_t *functab, uint32_t platformData, pmsQueryFunc_t queryFunc);
    pmStats_t	*(*Stats)(void);
    pmsd	*(*StepperData)(void);
    uint64_t	*(*HPETAddr)(void);
    pmInitState_t	*InitState;
    void	(*resetPop)(void);
} pmCallBacks_t;

extern pmDispatch_t	*pmDispatch;

extern uint32_t		maxBusDelay;
extern uint32_t		C4C2SnoopDelay;
extern uint32_t		forcenap;

void power_management_init(void);
void machine_nap_policy(void);
kern_return_t Cstate_table_set(Cstate_hint_t *tablep, unsigned int nstates);
void machine_idle_cstate(void);
void pmRegister(pmDispatch_t *cpuFuncs, pmCallBacks_t *callbacks);
void pmUnRegister(pmDispatch_t *cpuFuncs);

#endif /* ASSEMBLER */
#endif /* _I386_PMCPU_H_ */
#endif /* KERNEL_PRIVATE */
