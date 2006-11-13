/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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
 
#ifndef _HW_PERFMON_MMCR_H_
#define _HW_PERFMON_MMCR_H_

#ifndef __ppc__
#error This file is only useful on PowerPC.
#endif

typedef struct {
	uint32_t disable_counters_always : 1;     /*     0: disable counters */
	uint32_t disable_counters_supervisor : 1; /*     1: disable counters (supervisor) */
	uint32_t disable_counters_user : 1;       /*     2: disable counters (user) */
	uint32_t disable_counters_marked : 1;     /*     3: disable counters (marked bit == 1) */
	uint32_t disable_counters_unmarked : 1;   /*     4: disable counters (marked bit == 0) */
	uint32_t enable_pmi : 1;                  /*     5: performance monitor interrupt enable */
	uint32_t on_pmi_stop_counting : 1;        /*     6: disable counters (pmi) */
	uint32_t timebase_bit_selector : 2;       /*   7-8: TBL bit for TB events */
	uint32_t enable_timebase_pmi : 1;         /*     9: enable pmi on TBL bit transition */
	uint32_t threshold_value : 6;             /* 10-15: threshold value */
	uint32_t enable_pmi_on_pmc1 : 1;          /*    16: enable pmi on pmc1 overflow */
	uint32_t enable_pmi_on_pmcn : 1;          /*    17: enable pmi on any pmc except pmc1 overflow */
	uint32_t enable_pmi_trigger : 1;          /*    18: enable triggering of pmcn by pmc1 overflow */
	uint32_t pmc1_event : 7;                  /* 19-25: pmc1 event select */
	uint32_t pmc2_event : 6;                  /* 26-31: pmc2 event select */
} ppc32_mmcr0_bits_t;

typedef union {
	uint32_t value;
	ppc32_mmcr0_bits_t field;
} ppc32_mmcr0_reg_t;

typedef struct {
	uint32_t pmc3_event : 5;
	uint32_t pmc4_event : 5;
	uint32_t pmc5_event : 5;
	uint32_t pmc6_event : 6;
	uint32_t /*reserved*/ : 11;
} ppc32_mmcr1_bits_t;

typedef union {
	uint32_t value;
	ppc32_mmcr1_bits_t field;
} ppc32_mmcr1_reg_t;

typedef struct {
	uint32_t threshold_multiplier : 1;
	uint32_t /*reserved*/ : 31;
} ppc32_mmcr2_bits_t;

typedef union {
	uint32_t value;
	ppc32_mmcr2_bits_t field;
} ppc32_mmcr2_reg_t;

typedef struct {
	uint32_t /* reserved */ : 32;             /*  0-31: reserved */
	uint32_t disable_counters_always : 1;     /*    32: disable counters */
	uint32_t disable_counters_supervisor : 1; /*    33: disable counters (supervisor) */
	uint32_t disable_counters_user : 1;       /*    34: disable counters (user) */
	uint32_t disable_counters_marked : 1;     /*    35: disable counters (marked bit == 1) */
	uint32_t disable_counters_unmarked : 1;   /*    36: disable counters (marked bit == 0) */
	uint32_t enable_pmi : 1;                  /*    37: performance monitor interrupt enable */
	uint32_t on_pmi_stop_counting : 1;        /*    38: disable counters (pmi) */
	uint32_t timebase_bit_selector : 2;       /* 39-40: TBL bit for timebase events */
	uint32_t enable_timebase_pmi : 1;         /*    41: enable pmi on TBL bit transition */
	uint32_t threshold_value : 6;             /* 42-47: threshold value */
	uint32_t enable_pmi_on_pmc1 : 1;          /*    48: enable pmi on pmc1 overflow */
	uint32_t enable_pmi_on_pmcn : 1;          /*    49: enable pmi on any pmc except pmc1 overflow */
	uint32_t enable_pmi_trigger : 1;          /*    50: enable triggering of pmcn by pmc1 overflow */
	uint32_t pmc1_event : 5;                  /* 51-55: pmc1 event select */
	uint32_t perfmon_event_occurred : 1;      /*    56: performance monitor event has occurred */
	uint32_t /* reserved */ : 1;              /*    57: reserved */
	uint32_t pmc2_event : 5;                  /* 58-62: pmc2 event select */
	uint32_t disable_counters_hypervisor : 1; /*    63: disable counters (hypervisor) */
} ppc64_mmcr0_bits_t;

typedef union {
	uint64_t value;
	ppc64_mmcr0_bits_t field;
} ppc64_mmcr0_reg_t;

typedef struct {
	uint32_t ttm0_select : 2;                 /*   0-1: FPU/ISU/IFU/VMX unit select */
	uint32_t /* reserved */ : 1;              /*     2: reserved */
	uint32_t ttm1_select : 2;                 /*   3-4: IDU/ISU/ISU unit select */
	uint32_t /* reserved */ : 1;              /*     5: reserved */
	uint32_t ttm2_select : 2;                 /*   6-7: IFU/LSU0 unit select */
	uint32_t /* reserved */ : 1;              /*     8: reserved */
	uint32_t ttm3_select : 2;                 /*  9-10: LSU1 select */
	uint32_t /* reserved */ : 1;              /*    11: reserved */
	uint32_t lane0_select : 2;                /* 12-13: Byte lane 0 unit select (TD_CP_DBG0SEL) */
	uint32_t lane1_select : 2;                /* 14-15: Byte lane 1 unit select (TD_CP_DBG1SEL) */
	uint32_t lane2_select : 2;                /* 16-17: Byte lane 2 unit select (TD_CP_DBG2SEL) */
	uint32_t lane3_select : 2;                /* 18-19: Byte lane 3 unit select (TD_CP_DBG3SEL) */
	uint32_t /* reserved */ : 4;              /* 20-23: reserved */
	uint32_t pmc1_adder_lane_select : 1;      /*    24: PMC1 Event Adder Lane Select (PMC1_ADDER_SELECT) */
	uint32_t pmc2_adder_lane_select : 1;      /*    25: PMC2 Event Adder Lane Select (PMC2_ADDER_SELECT) */
	uint32_t pmc6_adder_lane_select : 1;      /*    26: PMC6 Event Adder Lane Select (PMC6_ADDER_SELECT) */
	uint32_t pmc5_adder_lane_select : 1;      /*    27: PMC5 Event Adder Lane Select (PMC5_ADDER_SELECT) */
	uint32_t pmc8_adder_lane_select : 1;      /*    28: PMC8 Event Adder Lane Select (PMC8_ADDER_SELECT) */
	uint32_t pmc7_adder_lane_select : 1;      /*    29: PMC7 Event Adder Lane Select (PMC7_ADDER_SELECT) */
	uint32_t pmc3_adder_lane_select : 1;      /*    30: PMC3 Event Adder Lane Select (PMC3_ADDER_SELECT) */
	uint32_t pmc4_adder_lane_select : 1;      /*    31: PMC4 Event Adder Lane Select (PMC4_ADDER_SELECT) */
	uint32_t pmc3_event : 5;                  /* 32-36: pmc3 event select */
	uint32_t pmc4_event : 5;                  /* 37-41: pmc4 event select */
	uint32_t pmc5_event : 5;                  /* 42-46: pmc5 event select */
	uint32_t pmc6_event : 5;                  /* 47-51: pmc6 event select */
	uint32_t pmc7_event : 5;                  /* 52-56: pmc7 event select */
	uint32_t pmc8_event : 5;                  /* 57-61: pmc8 event select */
	uint32_t speculative_event : 2;           /* 62-63: SPeCulative count event SELector */
} ppc64_mmcr1_bits_t;

typedef union {
	uint64_t value;
	ppc64_mmcr1_bits_t field;
} ppc64_mmcr1_reg_t;

typedef struct {
	uint32_t /* reserved */ : 32;             /*  0-31: reserved */
	uint32_t siar_sdar_same_instruction : 1;  /*    32: SIAR and SDAR are from same instruction */
	uint32_t disable_counters_pmc1_pmc4 : 1;  /*    33: disable counters PMC1-PMC4 */
	uint32_t disable_counters_pmc5_pmc8 : 1;  /*    34: disable counters PMC5-PMC8 */
	uint32_t problem_state_siar : 1;          /*    35: MSR[PR] bit when SIAR set */
	uint32_t hypervisor_state_siar : 1;       /*    36: MSR[HV] bit when SIAR set */
	uint32_t /* reserved */ : 3;              /* 37-39: reserved */
	uint32_t threshold_start_event : 3;       /* 40-42: threshold start event */
	uint32_t threshold_end_event : 3;         /* 43-45: threshold end event */
	uint32_t /* reserved */ : 3;              /* 46-48: reserved */
	uint32_t imr_select : 1;                  /*    49: imr select */
	uint32_t imr_mark : 2;                    /* 50-51: imr mark */
	uint32_t imr_mask : 4;                    /* 52-55: imr mask */
	uint32_t imr_match : 4;                   /* 56-59: imr match */
	uint32_t disable_counters_tags_inactive : 1; /* 60: disable counters in tags inactive mode */
	uint32_t disable_counters_tags_active : 1; /*   61: disable counters in tags active mode */
	uint32_t disable_counters_wait_state : 1; /*    62: freeze counters in wait state (CNTL[31]=0) */
	uint32_t sample_enable : 1;               /*    63: sampling enabled */
} ppc64_mmcra_bits_t;

typedef union {
	uint64_t value;
	ppc64_mmcra_bits_t field;
} ppc64_mmcra_reg_t;

/* PPC_PERFMON_FUNC_* values are taken apart to fill in the appropriate configuration bitfields: */
typedef struct {
	uint32_t /* reserved */ : 22;
	uint32_t SPECSEL : 2;
	uint32_t TD_CP_DBGxSEL : 2;
	uint32_t TTM3SEL : 2;
	uint32_t TTM1SEL : 2;
	uint32_t TTM0SEL : 2;
} ppc_func_bits_t;

typedef union {
	uint32_t value;
	ppc_func_bits_t field;
} ppc_func_unit_t;

#endif /* _HW_PERFMON_MMCR_H_ */
