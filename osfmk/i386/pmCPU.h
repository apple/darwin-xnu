/*
 * Copyright (c) 2006-2007 Apple Inc. All rights reserved.
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
#ifdef KERNEL_PRIVATE
#ifndef _I386_PMCPU_H_
#define _I386_PMCPU_H_

#include <kern/pms.h>
#include <i386/cpu_topology.h>

#ifndef ASSEMBLER

#define MAX_PSTATES	32			/* architectural limit */

typedef enum
{
    Cn1, Cn2, Cn3, Cn4, Cn5, Cn6, CnHlt, Cn0, CnRun, Cnmax
} Cstate_number_t;

typedef struct
{
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
 * This value should be changed each time that pmDsipatch_t or pmCallBacks_t
 * changes.
 */
#define PM_DISPATCH_VERSION	7

/*
 * Dispatch table for functions that get installed when the power
 * management KEXT loads.
 */
typedef struct
{
    /*
     * The following are the stepper table interfaces.
     */
    int			(*pmCPUStateInit)(void);
    void		(*pmsInit)(void);
    void		(*pmsStart)(void);
    void		(*pmsPark)(void);
    kern_return_t	(*pmsCPUSetPStateLimit)(uint32_t limit);

    /*
     * The following are legacy stepper interfaces.
     */
    void		(*pmsRun)(uint32_t nstep);
    kern_return_t	(*pmsBuild)(pmsDef *pd, uint32_t pdsize, pmsSetFunc_t *functab, uint32_t platformData, pmsQueryFunc_t queryFunc);
    kern_return_t	(*pmsCPULoadVIDTable)(uint16_t *tablep, int nstates);

    /*
     * The following are the 'C' State interfaces.
     */
    void		(*cstateInit)(void);
    uint64_t		(*cstateMachineIdle)(uint64_t maxIdleDuration);
    kern_return_t	(*cstateTableSet)(Cstate_hint_t *tablep, unsigned int nstates);
    uint64_t		(*GetDeadline)(x86_lcpu_t *lcpu);
    uint64_t		(*SetDeadline)(x86_lcpu_t *lcpu, uint64_t);
    void		(*Deadline)(x86_lcpu_t *lcpu);
    boolean_t		(*exitIdle)(x86_lcpu_t *lcpu);
    void		(*markCPURunning)(x86_lcpu_t *lcpu);
    void		(*HPETInterrupt)(void);
    int			(*pmCPUControl)(uint32_t cmd, void *datap);
    void		(*pmCPUHalt)(void);
    uint64_t		(*getMaxSnoop)(void);
    void		(*setMaxBusDelay)(uint64_t time);
    uint64_t		(*getMaxBusDelay)(void);
    void		(*pmCPUSafeMode)(x86_lcpu_t *lcpu, uint32_t flags);
} pmDispatch_t;

typedef struct {
    uint32_t		PState;
    uint32_t		PLimit;
    uint16_t		VIDTable[MAX_PSTATES];
    uint32_t		VIDTableCount;
    Cstate_hint_t	CStates[Cnmax];
    uint32_t		CStatesCount;
    uint64_t		maxBusDelay;
} pmInitState_t;

typedef struct {
    uint64_t		*(*HPETAddr)(void);
    pmInitState_t	*InitState;
    int			(*setRTCPop)(uint64_t time);
    void		(*resyncDeadlines)(void);
    void		(*initComplete)(void);
    x86_lcpu_t		*(*GetLCPU)(int cpu);
    x86_core_t		*(*GetCore)(int cpu);
    x86_pkg_t		*(*GetPackage)(int cpu);
    x86_lcpu_t		*(*GetMyLCPU)(void);
    x86_core_t		*(*GetMyCore)(void);
    x86_pkg_t		*(*GetMyPackage)(void);
    uint32_t		CoresPerPkg;
    x86_pkg_t		*(*GetPkgRoot)(void);
    void		(*LockCPUTopology)(int lock);
    boolean_t		(*GetHibernate)(int cpu);
    processor_t		(*LCPUtoProcessor)(int lcpu);
} pmCallBacks_t;

extern pmDispatch_t	*pmDispatch;

extern uint32_t		forcenap;

void power_management_init(void);
void machine_nap_policy(void);
kern_return_t Cstate_table_set(Cstate_hint_t *tablep, unsigned int nstates);
void machine_idle_cstate(boolean_t halted);
void pmKextRegister(uint32_t version, pmDispatch_t *cpuFuncs,
		    pmCallBacks_t *callbacks);
void pmUnRegister(pmDispatch_t *cpuFuncs);
void pmCPUStateInit(void);
uint64_t pmCPUGetDeadline(struct cpu_data *cpu);
uint64_t pmCPUSetDeadline(struct cpu_data *cpu, uint64_t deadline);
void pmCPUDeadline(struct cpu_data *cpu);
boolean_t pmCPUExitIdle(struct cpu_data *cpu);
void pmCPUMarkRunning(struct cpu_data *cpu);
void pmHPETInterrupt(void);
int pmCPUControl(uint32_t cmd, void *datap);
void pmCPUHalt(uint32_t reason);

#define PM_HALT_NORMAL		0		/* normal halt path */
#define PM_HALT_DEBUG		1		/* debug code wants to halt */
#define PM_HALT_PANIC		2		/* panic code wants to halt */

void pmSafeMode(x86_lcpu_t *lcpu, uint32_t flags);

#define PM_SAFE_FL_NORMAL	0x00000001	/* put CPU into "normal" power mode */
#define PM_SAFE_FL_SAFE		0x00000002	/* put CPU into a "safe" power mode */
#define PM_SAFE_FL_PAUSE	0x00000010	/* pause execution on the CPU */
#define PM_SAFE_FL_RESUME	0x00000020	/* resume execution on the CPU */

extern int pmsafe_debug;

#endif /* ASSEMBLER */

#endif /* _I386_PMCPU_H_ */
#endif /* KERNEL_PRIVATE */
