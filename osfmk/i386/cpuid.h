/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

/*
 * x86 CPU identification
 *
 * TODO : Add TI/Thomson processors
 */

#ifndef _MACHINE_CPUID_H_
#define _MACHINE_CPUID_H_

#define	CPUID_VID_SIZE		12
#define	CPUID_VID_INTEL		"GenuineIntel"
#define	CPUID_VID_UMC		"UMC UMC UMC "
#define	CPUID_VID_AMD		"AuthenticAMD"
#define	CPUID_VID_CYRIX		"CyrixInstead"
#define	CPUID_VID_NEXTGEN	"NexGenDriven"

#define	CPUID_FEATURE_FPU    0x00000001	/* Floating point unit on-chip */
#define	CPUID_FEATURE_VME    0x00000002	/* Virtual Mode Extension */
#define	CPUID_FEATURE_IOB    0x00000004	/* I/O Breakpoints */
#define	CPUID_FEATURE_PSE    0x00000008	/* Page Size Extension */
#define	CPUID_FEATURE_TSC    0x00000010	/* Time Stamp Counter */
#define	CPUID_FEATURE_MSR    0x00000020	/* Model Specific Registers */
#define	CPUID_FEATURE_MCE    0x00000080	/* Machine Check Exception */
#define	CPUID_FEATURE_CX8    0x00000100	/* CMPXCHG8B */
#define	CPUID_FEATURE_APIC   0x00000200	/* On-chip APIC */
#define	CPUID_FEATURE_MTRR   0x00001000	/* Memory Type Range Register */
#define	CPUID_FEATURE_PGE    0x00002000	/* Page Global Enable */
#define	CPUID_FEATURE_MCA    0x00004000	/* Machine Check Architecture */
#define	CPUID_FEATURE_CMOV   0x00008000	/* Conditional Move Instruction */

#define	CPUID_TYPE_OEM		    0x0	/* Original processor */
#define	CPUID_TYPE_OVERDRIVE	    0x1	/* Overdrive processor */
#define	CPUID_TYPE_DUAL		    0x2	/* Can be used as dual processor */
#define	CPUID_TYPE_RESERVED	    0x3	/* Reserved */

#define	CPUID_FAMILY_386	    0x3	/* Intel 386 (not part of CPUID) */
#define	CPUID_FAMILY_486	    0x4	/* Intel 486 */
#define	CPUID_FAMILY_P5		    0x5	/* Intel Pentium */
#define	CPUID_FAMILY_PPRO	    0x6	/* Intel Pentium Pro */

#define	CPUID_MODEL_I386_DX	    0x0	/* Intel 386 (not part of CPUID) */

#define	CPUID_MODEL_I486_DX	    0x0	/* Intel 486DX */
#define	CPUID_MODEL_I486_DX_S	    0x1	/* Intel 486DX-S */
#define	CPUID_MODEL_I486_SX	    0x2	/* Intel 486SX */
#define	CPUID_MODEL_I486_DX2	    0x3	/* Intel 486DX2 */
#define	CPUID_MODEL_I486_SL	    0x4	/* Intel 486SL */
#define	CPUID_MODEL_I486_SX2	    0x5	/* Intel 486SX2 */
#define	CPUID_MODEL_I486_DX2WB	    0x7	/* Intel 486DX2WB */
#define	CPUID_MODEL_I486_DX4	    0x8	/* Intel 486DX4 */
#define	CPUID_MODEL_I486_DX4WB	    0x9	/* Intel 486DX4WB */

#define	CPUID_MODEL_AM486_DX	    0x1	/* AMD 486DX */
#define	CPUID_MODEL_AM486_DX2	    0x3	/* AMD 486DX2 */
#define	CPUID_MODEL_AM486_DX2WB	    0x7	/* AMD 486DX2WB */
#define	CPUID_MODEL_AM486_DX4	    0x8	/* AMD 486DX4 */
#define	CPUID_MODEL_AM486_DX4WB	    0x9	/* AMD 486DX4WB */
#define	CPUID_MODEL_AM486_5X86	    0xE	/* AMD 5x86 */
#define	CPUID_MODEL_AM486_5X86WB    0xF	/* AMD 5x86WB */

#define	CPUID_MODEL_CYRIX5X86	    0x9	/* CYRIX 5X86 */

#define	CPUID_MODEL_UMC5SD	    0x1	/* UMC U5SD */
#define	CPUID_MODEL_UMC5S	    0x2	/* UMC U5S */
#define	CPUID_MODEL_UMC486_DX2	    0x3	/* UMC U486_DX2 */
#define	CPUID_MODEL_UMC486_SX2	    0x5	/* UMC U486_SX2 */

#define	CPUID_MODEL_P5A		    0x0	/* Intel P5 60/66 Step A */
#define	CPUID_MODEL_P5		    0x1	/* Intel P5 60/66 */
#define	CPUID_MODEL_P54		    0x2	/* Intel P5 75/80/100/120/133/166 */
#define	CPUID_MODEL_P24T	    0x3	/* Intel P5 Overdrive 63/83 */

#define	CPUID_MODEL_P6		    0x1	/* Intel P6 */
#define	CPUID_MODEL_PII		    0x3	/* Intel PII */

#define	CPUID_CACHE_SIZE	16	/* Number of descriptor vales */
#define	CPUID_CACHE_VALID	 4	/* Index of descriptor validity */

#define	CPUID_CACHE_NULL	   0x00	/* NULL */
#define	CPUID_CACHE_ITLB_4K	   0x01	/* Instruction TLB, 4K pages */
#define	CPUID_CACHE_ITLB_4M	   0x02	/* Instruction TLB, 4M pages */
#define	CPUID_CACHE_DTLB_4K	   0x03	/* Data TLB, 4K pages */
#define	CPUID_CACHE_DTLB_4M	   0x04	/* Data TLB, 4M pages */
#define	CPUID_CACHE_ICACHE_8K	   0x06	/* Instruction cache, 8K */
#define	CPUID_CACHE_DCACHE_8K	   0x0A	/* Data cache, 8K */
#define	CPUID_CACHE_UCACHE_128K	   0x41	/* Unified cache, 128K */
#define	CPUID_CACHE_UCACHE_256K	   0x42	/* Unified cache, 256K */
#define	CPUID_CACHE_UCACHE_512K	   0x43	/* Unified cache, 512K */

#ifndef ASSEMBLER
#include <mach/machine.h>

extern unsigned int	cpuid_value;
extern unsigned char	cpuid_type;
extern unsigned char	cpuid_family;
extern unsigned char	cpuid_model;
extern unsigned char	cpuid_stepping;
extern unsigned int	cpuid_feature;
extern char		cpuid_vid[];
extern unsigned char	cpuid_cache[];

/*
 * Product ID arrays per vendor
 */
struct cpuid_product {
    unsigned char		type;		/* CPU type */
    unsigned char		family;		/* CPU family */
    unsigned char		model;		/* CPU model */
    unsigned int		delay;		/* 1MHz Delay (scale 1000) */
    unsigned int		*frequency;	/* Frequency array */
    char			*name;		/* Model name */
};

/*
 * Vendor ID structure
 */
struct cpuid_name {
    char			*name;		/* Vendor ID name */
    struct cpuid_product	*product;	/* product array */
    unsigned int		size;		/* #elements in product array */
};

/*
 * Cache ID description structure
 */
struct cpuid_cache_desc {
    unsigned char		value;		/* Descriptor value */
    char			*description;	/* Cache description */
};

/*
 * External declarations
 */
extern cpu_type_t	cpuid_cputype(int);
extern void		cpuid_cpu_display(char *, int);
extern void		cpuid_cache_display(char *, int);

#endif /* ASSEMBLER */
#endif /* _MACHINE_CPUID_H_ */
