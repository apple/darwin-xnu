/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
 */

#ifndef _MACHINE_CPUID_H_
#define _MACHINE_CPUID_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE

#define	CPUID_VID_SIZE		12
#define	CPUID_VID_INTEL		"GenuineIntel"
#define	CPUID_VID_UMC		"UMC UMC UMC "
#define	CPUID_VID_AMD		"AuthenticAMD"
#define	CPUID_VID_CYRIX		"CyrixInstead"
#define	CPUID_VID_NEXTGEN	"NexGenDriven"

#define	CPUID_FEATURE_FPU    0x00000001	/* Floating point unit on-chip */
#define	CPUID_FEATURE_VME    0x00000002	/* Virtual Mode Extension */
#define	CPUID_FEATURE_DE     0x00000004	/* Debugging Extension */
#define	CPUID_FEATURE_PSE    0x00000008	/* Page Size Extension */
#define	CPUID_FEATURE_TSC    0x00000010	/* Time Stamp Counter */
#define	CPUID_FEATURE_MSR    0x00000020	/* Model Specific Registers */
#define CPUID_FEATURE_PAE    0x00000040 /* Physical Address Extension */
#define	CPUID_FEATURE_MCE    0x00000080	/* Machine Check Exception */
#define	CPUID_FEATURE_CX8    0x00000100	/* CMPXCHG8B */
#define	CPUID_FEATURE_APIC   0x00000200	/* On-chip APIC */
#define CPUID_FEATURE_SEP    0x00000800 /* Fast System Call */
#define	CPUID_FEATURE_MTRR   0x00001000	/* Memory Type Range Register */
#define	CPUID_FEATURE_PGE    0x00002000	/* Page Global Enable */
#define	CPUID_FEATURE_MCA    0x00004000	/* Machine Check Architecture */
#define	CPUID_FEATURE_CMOV   0x00008000	/* Conditional Move Instruction */
#define CPUID_FEATURE_PAT    0x00010000 /* Page Attribute Table */
#define CPUID_FEATURE_PSE36  0x00020000 /* 36-bit Page Size Extension */
#define CPUID_FEATURE_PSN    0x00040000 /* Processor Serial Number */
#define CPUID_FEATURE_CLFSH  0x00080000 /* CLFLUSH Instruction supported */
#define CPUID_FEATURE_DS     0x00200000 /* Debug Store */
#define CPUID_FEATURE_ACPI   0x00400000 /* Thermal Monitor, SW-controlled clock */
#define CPUID_FEATURE_MMX    0x00800000 /* MMX supported */
#define CPUID_FEATURE_FXSR   0x01000000 /* Fast floating point save/restore */
#define CPUID_FEATURE_SSE    0x02000000 /* Streaming SIMD extensions */
#define CPUID_FEATURE_SSE2   0x04000000 /* Streaming SIMD extensions 2 */
#define CPUID_FEATURE_SS     0x08000000 /* Self-Snoop */
#define CPUID_FEATURE_HTT    0x10000000 /* Hyper-Threading Technology */
#define CPUID_FEATURE_TM     0x20000000 /* Thermal Monitor */

#define	CPUID_TYPE_OEM		    0x0	/* Original processor */
#define	CPUID_TYPE_OVERDRIVE	    0x1	/* Overdrive processor */
#define	CPUID_TYPE_DUAL		    0x2	/* Can be used as dual processor */
#define	CPUID_TYPE_RESERVED	    0x3	/* Reserved */

#define	CPUID_FAMILY_386	    0x3	/* Intel 386 (not part of CPUID) */
#define	CPUID_FAMILY_486	    0x4	/* Intel 486 */
#define	CPUID_FAMILY_P5		    0x5	/* Intel Pentium */
#define	CPUID_FAMILY_PPRO	    0x6	/* Intel Pentium Pro, II, III */
#define CPUID_FAMILY_PENTIUM4       0xF /* Intel Pentium 4 */

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
#define CPUID_MODEL_P65             0x5 /* Intel PII/Xeon/Celeron model 5 */
#define CPUID_MODEL_P66             0x6 /* Intel Celeron model 6 */
#define CPUID_MODEL_P67             0x7 /* Intel PIII/Xeon model 7 */
#define CPUID_MODEL_P68             0x8 /* Intel PIII/Xeon/Celeron model 8 */
#define CPUID_MODEL_P6A             0xA /* Intel PIII Xeon model A */
#define CPUID_MODEL_P6B             0xB /* Intel PIII model B */

#define	CPUID_CACHE_SIZE	16	/* Number of descriptor vales */

#define	CPUID_CACHE_NULL	   0x00	/* NULL */
#define	CPUID_CACHE_ITLB_4K	   0x01	/* Instruction TLB, 4K pages */
#define	CPUID_CACHE_ITLB_4M	   0x02	/* Instruction TLB, 4M pages */
#define	CPUID_CACHE_DTLB_4K	   0x03	/* Data TLB, 4K pages */
#define	CPUID_CACHE_DTLB_4M	   0x04	/* Data TLB, 4M pages */
#define	CPUID_CACHE_ICACHE_8K	   0x06	/* Instruction cache, 8K */
#define	CPUID_CACHE_ICACHE_16K	   0x08	/* Instruction cache, 16K */
#define	CPUID_CACHE_DCACHE_8K	   0x0A	/* Data cache, 8K */
#define	CPUID_CACHE_DCACHE_16K	   0x0C	/* Data cache, 16K */
#define	CPUID_CACHE_UCACHE_128K	   0x41	/* 2nd-level cache, 128K */
#define	CPUID_CACHE_UCACHE_256K	   0x42	/* 2nd-level cache, 256K */
#define	CPUID_CACHE_UCACHE_512K	   0x43	/* 2nd-level cache, 512K */
#define	CPUID_CACHE_UCACHE_1M	   0x44	/* 2nd-level cache, 1M */
#define	CPUID_CACHE_UCACHE_2M	   0x45	/* 2nd-level cache, 2M */
#define CPUID_CACHE_ITLB_64        0x50 /* Instruction TLB, 64 entries */
#define CPUID_CACHE_ITLB_128       0x51 /* Instruction TLB, 128 entries */
#define CPUID_CACHE_ITLB_256       0x52 /* Instruction TLB, 256 entries */
#define CPUID_CACHE_DTLB_64        0x5B /* Data TLB, 64 entries */
#define CPUID_CACHE_DTLB_128       0x5C /* Data TLB, 128 entries */
#define CPUID_CACHE_DTLB_256       0x5D /* Data TLB, 256 entries */
#define	CPUID_CACHE_DCACHE_8K_64   0x66	/* Data cache, 8K, 64 byte line size */
#define	CPUID_CACHE_DCACHE_16K_64  0x67 /* Data cache, 16K, 64 byte line size */
#define	CPUID_CACHE_DCACHE_32K_64  0x68 /* Data cache, 32K, 64 byte line size */
#define CPUID_CACHE_TRACE_12K      0x70 /* Trace cache 12K-uop, 8-way */
#define CPUID_CACHE_TRACE_16K      0x71 /* Trace cache 16K-uop, 8-way */
#define CPUID_CACHE_TRACE_32K      0x72 /* Trace cache 32K-uop, 8-way */
#define	CPUID_CACHE_UCACHE_128K_64 0x79 /* 2nd-level, 128K, 8-way, 64 bytes */
#define	CPUID_CACHE_UCACHE_256K_64 0x7A /* 2nd-level, 256K, 8-way, 64 bytes */
#define	CPUID_CACHE_UCACHE_512K_64 0x7B /* 2nd-level, 512K, 8-way, 64 bytes */
#define	CPUID_CACHE_UCACHE_1M_64   0x7C /* 2nd-level, 1M, 8-way, 64 bytes */
#define CPUID_CACHE_UCACHE_256K_32 0x82 /* 2nd-level, 256K, 8-way, 32 bytes */
#define CPUID_CACHE_UCACHE_512K_32 0x83 /* 2nd-level, 512K, 8-way, 32 bytes */
#define CPUID_CACHE_UCACHE_1M_32   0x84 /* 2nd-level, 1M, 8-way, 32 bytes */
#define CPUID_CACHE_UCACHE_2M_32   0x85 /* 2nd-level, 2M, 8-way, 32 bytes */

#ifndef ASSEMBLER
#include <stdint.h>
#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <mach/machine.h>


static inline void
do_cpuid(uint32_t selector, uint32_t *data)
{
	asm("cpuid"
		: "=a" (data[0]),
		  "=b" (data[1]),
		  "=c" (data[2]),
		  "=d" (data[3])
		: "a"(selector));
}

/*
 * Cache ID descriptor structure.
 * Note: description string absent in kernel.
 */
typedef enum { Lnone, L1I, L1D, L2U, LCACHE_MAX } cache_type_t ; 
typedef struct {
	unsigned char	value;          /* Descriptor value */
	cache_type_t 	type;           /* Cache type */
	unsigned int 	size;           /* Cache size */
	unsigned int 	linesize;       /* Cache line size */
#ifdef KERNEL
	char         	*description;   /* Cache description */
#endif /* KERNEL */
} cpuid_cache_desc_t;  

#ifdef KERNEL
#define CACHE_DESC(value,type,size,linesize,text) \
	{ value, type, size, linesize, text }
#else
#define CACHE_DESC(value,type,size,linesize,text) \
	{ value, type, size, linesize }
#endif /* KERNEL */

/* Physical CPU info */
typedef struct {
	char		cpuid_vendor[16];
	char		cpuid_brand_string[48];

	uint32_t	cpuid_value;
	cpu_type_t	cpuid_type;
	uint8_t		cpuid_family;
	uint8_t		cpuid_model;
	uint8_t		cpuid_extmodel;
	uint8_t		cpuid_extfamily;
	uint8_t		cpuid_stepping;
	uint32_t	cpuid_features;
	uint32_t	cpuid_signature;
	uint8_t   	cpuid_brand; 
	
	uint32_t	cache_size[LCACHE_MAX];
	uint32_t	cache_linesize;

	char            model_string[64];  /* sanitized model string */
	uint8_t		cache_info[64];    /* list of cache descriptors */

} i386_cpu_info_t;


/*
 * External declarations
 */
extern cpu_type_t	cpuid_cputype(int);
extern void		cpuid_cpu_display(char *, int);
extern void		cpuid_features_display(char *, int);
extern char *		cpuid_get_feature_names(uint32_t, char *, unsigned);

extern uint32_t		cpuid_features(void);
extern uint32_t		cpuid_family(void);

extern char *		cpuid_intel_get_model_name(uint8_t, uint8_t,
						   uint8_t, uint32_t);

extern i386_cpu_info_t	*cpuid_info(void);

extern uint32_t		cpuid_feature;	/* XXX obsolescent */
#endif /* ASSEMBLER */

#endif /* __APPLE_API_PRIVATE */
#endif /* _MACHINE_CPUID_H_ */
