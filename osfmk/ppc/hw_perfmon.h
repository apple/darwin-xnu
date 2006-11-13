/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#ifndef _HW_PERFMON_H_
#define _HW_PERFMON_H_

#ifndef __ppc__
#error This file is only useful on PowerPC.
#endif

#define MAX_CPUPMC_COUNT  8

#define PMC_1    0
#define PMC_2    1
#define PMC_3    2
#define PMC_4    3
#define PMC_5    4
#define PMC_6    5
#define PMC_7    6
#define PMC_8    7

/* these actions can be combined and simultaneously performed with a single call to perfmon_control() */
typedef enum {
	PPC_PERFMON_CLEAR_COUNTERS =   0x0002,
	PPC_PERFMON_START_COUNTERS =   0x0004,
	PPC_PERFMON_STOP_COUNTERS  =   0x0008,
	PPC_PERFMON_READ_COUNTERS  =   0x0010,
	PPC_PERFMON_WRITE_COUNTERS =   0x0020
} perfmon_multi_action_t;

/* these actions can not be combined and each requires a separate call to perfmon_control() */
typedef enum {
	PPC_PERFMON_ENABLE =           0x00010000,
	PPC_PERFMON_DISABLE =          0x00020000,
	PPC_PERFMON_SET_EVENT =        0x00030000,
	PPC_PERFMON_SET_THRESHOLD =    0x00040000,
	PPC_PERFMON_SET_TBSEL =        0x00050000,
	PPC_PERFMON_SET_EVENT_FUNC =   0x00060000,
	PPC_PERFMON_ENABLE_PMI_BRKPT = 0x00070000
} perfmon_single_action_t;

/* used to select byte lane and speculative events (currently 970 only) */
typedef enum {                        /* SPECSEL[0:1]  TD_CP_DBGxSEL[0:1]  TTM3SEL[0:1]  TTM1SEL[0:1]  TTM0SEL[0:1] */
	PPC_PERFMON_FUNC_FPU =         0,   /*           00                  00            00            00            00 */
	PPC_PERFMON_FUNC_ISU =         1,   /*           00                  00            00            00            01 */
	PPC_PERFMON_FUNC_IFU =         2,   /*           00                  00            00            00            10 */
	PPC_PERFMON_FUNC_VMX =         3,   /*           00                  00            00            00            11 */
	PPC_PERFMON_FUNC_IDU =        64,   /*           00                  01            00            00            00 */
	PPC_PERFMON_FUNC_GPS =        76,   /*           00                  01            00            11            00 */
	PPC_PERFMON_FUNC_LSU0 =      128,   /*           00                  10            00            00            00 */
	PPC_PERFMON_FUNC_LSU1A =     192,   /*           00                  11            00            00            00 */
	PPC_PERFMON_FUNC_LSU1B =     240,   /*           00                  11            11            00            00 */
	PPC_PERFMON_FUNC_SPECA =     256,   /*           01                  00            00            00            00 */
	PPC_PERFMON_FUNC_SPECB =     512,   /*           10                  00            00            00            00 */
	PPC_PERFMON_FUNC_SPECC =     768,   /*           11                  00            00            00            00 */
} perfmon_functional_unit_t;

#ifdef MACH_KERNEL_PRIVATE
int perfmon_acquire_facility(task_t task);
int perfmon_release_facility(task_t task);

extern int perfmon_disable(thread_t thr_act);
extern int perfmon_init(void);
extern int perfmon_control(struct savearea *save);
extern int perfmon_handle_pmi(struct savearea *ssp);

/* perfmonFlags */
#define PERFMONFLAG_BREAKPOINT_FOR_PMI     0x1

#endif /* MACH_KERNEL_PRIVATE */

/* 
 * From user space:
 * 
 * int perfmon_control(thread_t thread, perfmon_action_t action, int pmc, u_int32_t val, u_int64_t *pmcs);
 * 
 * r3: thread
 * r4: action
 * r5: pmc
 * r6: event/threshold/tbsel/count
 * r7: pointer to space for PMC counts: uint64_t[MAX_CPUPMC_COUNT]
 *
 * perfmon_control(thread, PPC_PERFMON_CLEAR_COUNTERS, 0, 0, NULL);
 * perfmon_control(thread, PPC_PERFMON_START_COUNTERS, 0, 0, NULL);
 * perfmon_control(thread, PPC_PERFMON_STOP_COUNTERS, 0, 0, NULL);
 * perfmon_control(thread, PPC_PERFMON_READ_COUNTERS, 0, 0, uint64_t *pmcs);
 * perfmon_control(thread, PPC_PERFMON_WRITE_COUNTERS, 0, 0, uint64_t *pmcs);
 * perfmon_control(thread, PPC_PERFMON_ENABLE, 0, 0, NULL);
 * perfmon_control(thread, PPC_PERFMON_DISABLE, 0, 0, NULL);
 * perfmon_control(thread, PPC_PERFMON_SET_EVENT, int pmc, int event, NULL);
 * perfmon_control(thread, PPC_PERFMON_SET_THRESHOLD, 0, int threshold, NULL);
 * perfmon_control(thread, PPC_PERFMON_SET_TBSEL, 0, int tbsel, NULL);
 * perfmon_control(thread, PPC_PERFMON_SET_EVENT_FUNC, 0, perfmon_functional_unit_t func, NULL);
 * perfmon_control(thread, PPC_PERFMON_ENABLE_PMI_BRKPT, 0, boolean_t enable, NULL);
 *
 */

#endif /* _HW_PERFMON_H_ */
