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
 *	File:	mach/ppc/processor_info.h
 *
 *	Data structure definitions for ppc specific processor control
 */


#ifndef	_MACH_PPC_PROCESSOR_INFO_H_
#define _MACH_PPC_PROCESSOR_INFO_H_

#include <mach/machine.h>

/* processor_control command operations */
#define PROCESSOR_PM_SET_REGS     1     /* Set Performance Monitor Registers  */
#define PROCESSOR_PM_SET_MMCR     2     /* Set Monitor Mode Controls Registers  */
#define PROCESSOR_PM_CLR_PMC      3     /* Clear Performance Monitor Counter Registers */

/* 
 * Performance Monitor Register structures
 */

typedef union {
	unsigned int word;
	struct {
	        unsigned int dis	: 1;
		unsigned int dp 	: 1;
		unsigned int du 	: 1;
	        unsigned int dms	: 1;
	        unsigned int dmr	: 1;
	        unsigned int reserved3	: 1;        /* enint         */
	        unsigned int reserved4	: 1;        /* discount      */
	        unsigned int reserved5	: 2;        /* rtcselect     */
	        unsigned int reserved6	: 1;        /* intonbittrans */
	        unsigned int threshold	: 6;
	        unsigned int reserved7	: 1;        /* pmc1intcontrol */
	        unsigned int reserved8	: 1;        /* pmcintcontrol  */
	        unsigned int reserved9	: 1;        /* pmctrigger     */
	        unsigned int pmc1select	: 7;
	        unsigned int pmc2select	: 6;
	}bits;
}mmcr0_t;

typedef union {
	unsigned int word;
	struct {
	        unsigned int pmc3select	: 5;
	        unsigned int pmc4select	: 5;
	        unsigned int reserved	: 22;
	}bits;
}mmcr1_t;

typedef union {
	unsigned int word;
	struct {
	        unsigned int threshmult	 : 1;
	        unsigned int reserved	 : 31;
	}bits;
}mmcr2_t;

typedef union {
	unsigned int word;
	struct {
	        unsigned int ov : 1;        /* overflow value */
	        unsigned int cv : 31;       /* countervalue */
	}bits;
}pmcn_t;



/* Processor Performance Monitor Registers definitions */

struct processor_pm_regs {
      union {
	mmcr0_t mmcr0;
        mmcr1_t mmcr1;
        mmcr2_t mmcr2;
      }u;
      pmcn_t pmc[2];
};

typedef struct processor_pm_regs processor_pm_regs_data_t;
typedef struct processor_pm_regs *processor_pm_regs_t;
#define PROCESSOR_PM_REGS_COUNT \
        (sizeof(processor_pm_regs_data_t) / sizeof (unsigned int))

#define PROCESSOR_PM_REGS_COUNT_POWERPC_750 \
            (PROCESSOR_PM_REGS_COUNT * 2 )

#define PROCESSOR_PM_REGS_COUNT_POWERPC_7400 \
            (PROCESSOR_PM_REGS_COUNT * 3 )

typedef unsigned int processor_temperature_data_t;
typedef unsigned int *processor_temperature_t;

#define PROCESSOR_TEMPERATURE_COUNT 1

union processor_control_data {
        processor_pm_regs_data_t cmd_pm_regs[3];
};

struct processor_control_cmd {
    integer_t      cmd_op;
    cpu_type_t     cmd_cpu_type;
    cpu_subtype_t  cmd_cpu_subtype;
    union processor_control_data u;
};

typedef struct processor_control_cmd   processor_control_cmd_data_t;
typedef struct processor_control_cmd   *processor_control_cmd_t;
#define cmd_pm_regs u.cmd_pm_regs;
#define cmd_pm_ctls u.cmd_pm_ctls;

#define PROCESSOR_CONTROL_CMD_COUNT \
    (((sizeof(processor_control_cmd_data_t)) - \
      (sizeof(union processor_control_data))) / sizeof (integer_t))

     /* x should be a processor_pm_regs_t */
#define PERFMON_MMCR0(x)    ((x)[0].u.mmcr0.word)
#define PERFMON_PMC1(x)     ((x)[0].pmc[0].word)
#define PERFMON_PMC2(x)     ((x)[0].pmc[1].word)
#define PERFMON_MMCR1(x)    ((x)[1].u.mmcr1.word)
#define PERFMON_PMC3(x)     ((x)[1].pmc[0].word)
#define PERFMON_PMC4(x)     ((x)[1].pmc[1].word)
#define PERFMON_MMCR2(x)    ((x)[2].u.mmcr2.word)

#define PERFMON_DIS(x)           ((x)[0].u.mmcr0.bits.dis)
#define PERFMON_DP(x)            ((x)[0].u.mmcr0.bits.dp)
#define PERFMON_DU(x)            ((x)[0].u.mmcr0.bits.du)
#define PERFMON_DMS(x)           ((x)[0].u.mmcr0.bits.dms)
#define PERFMON_DMR(x)           ((x)[0].u.mmcr0.bits.dmr)
#define PERFMON_THRESHOLD(x)     ((x)[0].u.mmcr0.bits.threshold)
#define PERFMON_PMC1SELECT(x)    ((x)[0].u.mmcr0.bits.pmc1select)
#define PERFMON_PMC2SELECT(x)    ((x)[0].u.mmcr0.bits.pmc2select)
#define PERFMON_PMC3SELECT(x)    ((x)[1].u.mmcr1.bits.pmc3select)
#define PERFMON_PMC4SELECT(x)    ((x)[1].u.mmcr1.bits.pmc4select)
#define PERFMON_THRESHMULT(x)    ((x)[2].u.mmcr2.bits.threshmult)
#define PERFMON_PMC1_CV(x)       ((x)[0].u.pmc[0].bits.cv)
#define PERFMON_PMC2_CV(x)       ((x)[0].u.pmc[1].bits.cv)
#define PERFMON_PMC3_CV(x)       ((x)[1].u.pmc[0].bits.cv)
#define PERFMON_PMC4_CV(x)       ((x)[1].u.pmc[1].bits.cv)

#endif	/* _MACH_PPC_PROCESSOR_INFO_H_ */

