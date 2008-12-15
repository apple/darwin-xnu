/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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

#define	CPUID_VID_INTEL		"GenuineIntel"
#define	CPUID_VID_AMD		"AuthenticAMD"

#define CPUID_STRING_UNKNOWN    "Unknown CPU Typ"

#define _Bit(n)			(1ULL << n)
#define _HBit(n)		(1ULL << ((n)+32))

/*
 * The CPUID_FEATURE_XXX values define 64-bit values
 * returned in %ecx:%edx to a CPUID request with %eax of 1: 
 */
#define	CPUID_FEATURE_FPU     _Bit(0)	/* Floating point unit on-chip */
#define	CPUID_FEATURE_VME     _Bit(1)	/* Virtual Mode Extension */
#define	CPUID_FEATURE_DE      _Bit(2)	/* Debugging Extension */
#define	CPUID_FEATURE_PSE     _Bit(3)	/* Page Size Extension */
#define	CPUID_FEATURE_TSC     _Bit(4)	/* Time Stamp Counter */
#define	CPUID_FEATURE_MSR     _Bit(5)	/* Model Specific Registers */
#define CPUID_FEATURE_PAE     _Bit(6)	/* Physical Address Extension */
#define	CPUID_FEATURE_MCE     _Bit(7)	/* Machine Check Exception */
#define	CPUID_FEATURE_CX8     _Bit(8)	/* CMPXCHG8B */
#define	CPUID_FEATURE_APIC    _Bit(9)	/* On-chip APIC */
#define CPUID_FEATURE_SEP     _Bit(11)	/* Fast System Call */
#define	CPUID_FEATURE_MTRR    _Bit(12)	/* Memory Type Range Register */
#define	CPUID_FEATURE_PGE     _Bit(13)	/* Page Global Enable */
#define	CPUID_FEATURE_MCA     _Bit(14)	/* Machine Check Architecture */
#define	CPUID_FEATURE_CMOV    _Bit(15)	/* Conditional Move Instruction */
#define CPUID_FEATURE_PAT     _Bit(16)	/* Page Attribute Table */
#define CPUID_FEATURE_PSE36   _Bit(17)	/* 36-bit Page Size Extension */
#define CPUID_FEATURE_PSN     _Bit(18)	/* Processor Serial Number */
#define CPUID_FEATURE_CLFSH   _Bit(19)	/* CLFLUSH Instruction supported */
#define CPUID_FEATURE_DS      _Bit(21)	/* Debug Store */
#define CPUID_FEATURE_ACPI    _Bit(22)	/* Thermal monitor and Clock Ctrl */
#define CPUID_FEATURE_MMX     _Bit(23)	/* MMX supported */
#define CPUID_FEATURE_FXSR    _Bit(24)	/* Fast floating pt save/restore */
#define CPUID_FEATURE_SSE     _Bit(25)	/* Streaming SIMD extensions */
#define CPUID_FEATURE_SSE2    _Bit(26)	/* Streaming SIMD extensions 2 */
#define CPUID_FEATURE_SS      _Bit(27)	/* Self-Snoop */
#define CPUID_FEATURE_HTT     _Bit(28)	/* Hyper-Threading Technology */
#define CPUID_FEATURE_TM      _Bit(29)	/* Thermal Monitor (TM1) */
#define CPUID_FEATURE_PBE     _Bit(31)	/* Pend Break Enable */

#define CPUID_FEATURE_SSE3    _HBit(0)	/* Streaming SIMD extensions 3 */
#define CPUID_FEATURE_MONITOR _HBit(3)	/* Monitor/mwait */
#define CPUID_FEATURE_DSCPL   _HBit(4)	/* Debug Store CPL */
#define CPUID_FEATURE_VMX     _HBit(5)	/* VMX */
#define CPUID_FEATURE_SMX     _HBit(6)	/* SMX */
#define CPUID_FEATURE_EST     _HBit(7)	/* Enhanced SpeedsTep (GV3) */
#define CPUID_FEATURE_TM2     _HBit(8)	/* Thermal Monitor 2 */
#define CPUID_FEATURE_SSSE3   _HBit(9)	/* Supplemental SSE3 instructions */
#define CPUID_FEATURE_CID     _HBit(10)	/* L1 Context ID */
#define CPUID_FEATURE_CX16    _HBit(13)	/* CmpXchg16b instruction */
#define CPUID_FEATURE_xTPR    _HBit(14)	/* Send Task PRiority msgs */
#define CPUID_FEATURE_PDCM    _HBit(15)	/* Perf/Debug Capability MSR */
#define CPUID_FEATURE_DCA     _HBit(18)	/* Direct Cache Access */
#define CPUID_FEATURE_SSE4_1  _HBit(19)	/* Streaming SIMD extensions 4.1 */
#define CPUID_FEATURE_SSE4_2  _HBit(20)	/* Streaming SIMD extensions 4.2 */
#define CPUID_FEATURE_xAPIC   _HBit(21)	/* Extended APIC Mode */
#define CPUID_FEATURE_POPCNT  _HBit(23)	/* POPCNT instruction */

/*
 * The CPUID_EXTFEATURE_XXX values define 64-bit values
 * returned in %ecx:%edx to a CPUID request with %eax of 0x80000001: 
 */
#define CPUID_EXTFEATURE_SYSCALL   _Bit(11)	/* SYSCALL/sysret */
#define CPUID_EXTFEATURE_XD	   _Bit(20)	/* eXecute Disable */
#define CPUID_EXTFEATURE_EM64T	   _Bit(29)	/* Extended Mem 64 Technology */

#define CPUID_EXTFEATURE_LAHF	   _HBit(20)	/* LAFH/SAHF instructions */

#define	CPUID_CACHE_SIZE	16	/* Number of descriptor vales */

#define	CPUID_CACHE_NULL	   0x00	/* NULL */
#define	CPUID_CACHE_ITLB_4K_32_4   0x01	/* Inst TLB: 4K pages, 32 ents, 4-way */
#define	CPUID_CACHE_ITLB_4M_2	   0x02	/* Inst TLB: 4M pages, 2 ents */
#define	CPUID_CACHE_DTLB_4K_64_4   0x03	/* Data TLB: 4K pages, 64 ents, 4-way */
#define	CPUID_CACHE_DTLB_4M_8_4	   0x04	/* Data TLB: 4M pages, 8 ents, 4-way */
#define	CPUID_CACHE_DTLB_4M_32_4   0x05	/* Data TLB: 4M pages, 32 ents, 4-way */
#define	CPUID_CACHE_L1I_8K	   0x06	/* Icache: 8K */
#define	CPUID_CACHE_L1I_16K	   0x08	/* Icache: 16K */
#define	CPUID_CACHE_L1I_32K	   0x09	/* Icache: 32K, 4-way, 64 bytes */
#define	CPUID_CACHE_L1D_8K	   0x0A	/* Dcache: 8K */
#define	CPUID_CACHE_L1D_16K        0x0C	/* Dcache: 16K */
#define	CPUID_CACHE_L1D_16K_4_32   0x0D /* Dcache: 16K, 4-way, 64 byte, ECC */
#define CPUID_CACHE_L2_256K_8_64   0x21 /* L2: 256K, 8-way, 64 bytes */
#define CPUID_CACHE_L3_512K        0x22 /* L3: 512K */
#define CPUID_CACHE_L3_1M          0x23 /* L3: 1M */
#define CPUID_CACHE_L3_2M          0x25 /* L3: 2M */
#define CPUID_CACHE_L3_4M          0x29 /* L3: 4M */
#define CPUID_CACHE_L1D_32K_8      0x2C /* Dcache: 32K, 8-way, 64 byte */
#define CPUID_CACHE_L1I_32K_8      0x30 /* Icache: 32K, 8-way */
#define CPUID_CACHE_L2_128K_S4     0x39 /* L2: 128K, 4-way, sectored */
#define CPUID_CACHE_L2_128K_S2     0x3B /* L2: 128K, 2-way, sectored */
#define CPUID_CACHE_L2_256K_S4     0x3C /* L2: 256K, 4-way, sectored */
#define CPUID_CACHE_NOCACHE        0x40 /* No 2nd level or 3rd-level cache */
#define	CPUID_CACHE_L2_128K	   0x41	/* L2: 128K */
#define	CPUID_CACHE_L2_256K	   0x42	/* L2: 256K */
#define	CPUID_CACHE_L2_512K	   0x43	/* L2: 512K */
#define	CPUID_CACHE_L2_1M_4	   0x44	/* L2: 1M, 4-way */
#define	CPUID_CACHE_L2_2M_4	   0x45	/* L2: 2M, 4-way */
#define CPUID_CACHE_L3_4M_4_64     0x46 /* L3:  4M,  4-way, 64 bytes */
#define CPUID_CACHE_L3_8M_8_64     0x47 /* L3:  8M,  8-way, 64 bytes*/
#define CPUID_CACHE_L2_3M_12_64    0x48 /* L3:  3M,  8-way, 64 bytes*/
#define CPUID_CACHE_L2_4M_16_64    0x49 /* L2:  4M, 16-way, 64 bytes */
#define CPUID_CACHE_L2_6M_12_64    0x4A /* L2:  6M, 12-way, 64 bytes */
#define CPUID_CACHE_L2_8M_16_64    0x4B /* L2:  8M, 16-way, 64 bytes */
#define CPUID_CACHE_L2_12M_12_64   0x4C /* L2: 12M, 12-way, 64 bytes */
#define CPUID_CACHE_L2_16M_16_64   0x4D /* L2: 16M, 16-way, 64 bytes */
#define CPUID_CACHE_L2_6M_24_64    0x4E /* L2:  6M, 24-way, 64 bytes */
#define CPUID_CACHE_ITLB_64        0x50 /* Inst TLB: 64 entries */
#define CPUID_CACHE_ITLB_128       0x51 /* Inst TLB: 128 entries */
#define CPUID_CACHE_ITLB_256       0x52 /* Inst TLB: 256 entries */
#define CPUID_CACHE_ITLB_4M2M_7    0x55 /* Inst TLB: 4M/2M, 7 entries */
#define CPUID_CACHE_DTLB_4M_16_4   0x56 /* Data TLB: 4M, 16 entries, 4-way */
#define CPUID_CACHE_DTLB_4K_16_4   0x57 /* Data TLB: 4K, 16 entries, 4-way */
#define CPUID_CACHE_DTLB_4M2M_32_4 0x5A /* Data TLB: 4M/2M, 32 entries */
#define CPUID_CACHE_DTLB_64        0x5B /* Data TLB: 64 entries */
#define CPUID_CACHE_DTLB_128       0x5C /* Data TLB: 128 entries */
#define CPUID_CACHE_DTLB_256       0x5D /* Data TLB: 256 entries */
#define	CPUID_CACHE_L1D_16K_8_64   0x60 /* Data cache: 16K, 8-way, 64 bytes */
#define	CPUID_CACHE_L1D_8K_4_64    0x66 /* Data cache:  8K, 4-way, 64 bytes */
#define	CPUID_CACHE_L1D_16K_4_64   0x67 /* Data cache: 16K, 4-way, 64 bytes */
#define	CPUID_CACHE_L1D_32K_4_64   0x68 /* Data cache: 32K, 4-way, 64 bytes */
#define CPUID_CACHE_TRACE_12K_8    0x70 /* Trace cache 12K-uop, 8-way */
#define CPUID_CACHE_TRACE_16K_8    0x71 /* Trace cache 16K-uop, 8-way */
#define CPUID_CACHE_TRACE_32K_8    0x72 /* Trace cache 32K-uop, 8-way */
#define	CPUID_CACHE_L2_1M_4_64     0x78 /* L2:   1M, 4-way, 64 bytes */
#define	CPUID_CACHE_L2_128K_8_64_2 0x79 /* L2: 128K, 8-way, 64b, 2 lines/sec */
#define	CPUID_CACHE_L2_256K_8_64_2 0x7A /* L2: 256K, 8-way, 64b, 2 lines/sec */
#define	CPUID_CACHE_L2_512K_8_64_2 0x7B /* L2: 512K, 8-way, 64b, 2 lines/sec */
#define	CPUID_CACHE_L2_1M_8_64_2   0x7C /* L2:   1M, 8-way, 64b, 2 lines/sec */
#define	CPUID_CACHE_L2_2M_8_64     0x7D /* L2:   2M, 8-way, 64 bytes */
#define	CPUID_CACHE_L2_512K_2_64   0x7F /* L2: 512K, 2-way, 64 bytes */
#define CPUID_CACHE_L2_256K_8_32   0x82 /* L2: 256K, 8-way, 32 bytes */
#define CPUID_CACHE_L2_512K_8_32   0x83 /* L2: 512K, 8-way, 32 bytes */
#define CPUID_CACHE_L2_1M_8_32     0x84 /* L2:   1M, 8-way, 32 bytes */
#define CPUID_CACHE_L2_2M_8_32     0x85 /* L2:   2M, 8-way, 32 bytes */
#define CPUID_CACHE_L2_512K_4_64   0x86 /* L2: 512K, 4-way, 64 bytes */
#define CPUID_CACHE_L2_1M_8_64     0x87 /* L2:   1M, 8-way, 64 bytes */
#define CPUID_CACHE_ITLB_4K_128_4  0xB0 /* ITLB: 4KB, 128 entries, 4-way */
#define CPUID_CACHE_ITLB_4M_4_4    0xB1 /* ITLB: 4MB,   4 entries, 4-way, or  */
#define CPUID_CACHE_ITLB_2M_8_4    0xB1 /* ITLB: 2MB,   8 entries, 4-way, or  */
#define CPUID_CACHE_ITLB_4M_8      0xB1 /* ITLB: 4MB,   8 entries */
#define CPUID_CACHE_ITLB_4K_64_4   0xB2 /* ITLB: 4KB,  64 entries, 4-way */
#define CPUID_CACHE_DTLB_4K_128_4  0xB3 /* DTLB: 4KB, 128 entries, 4-way */
#define CPUID_CACHE_DTLB_4K_256_4  0xB4 /* DTLB: 4KB, 256 entries, 4-way */
#define CPUID_CACHE_2TLB_4K_512_4  0xB4 /* 2nd-level TLB: 4KB, 512, 4-way */
#define CPUID_CACHE_L3_512K_4_64   0xD0 /* L3: 512KB, 4-way, 64 bytes */
#define CPUID_CACHE_L3_1M_4_64     0xD1 /* L3:    1M, 4-way, 64 bytes */
#define CPUID_CACHE_L3_2M_4_64     0xD2 /* L3:    2M, 4-way, 64 bytes */
#define CPUID_CACHE_L3_1M_8_64     0xD6 /* L3:    1M, 8-way, 64 bytes */
#define CPUID_CACHE_L3_2M_8_64     0xD7 /* L3:    2M, 8-way, 64 bytes */
#define CPUID_CACHE_L3_4M_8_64     0xD8 /* L3:    4M, 8-way, 64 bytes */
#define CPUID_CACHE_L3_1M5_12_64   0xDC /* L3:  1.5M, 12-way, 64 bytes */
#define CPUID_CACHE_L3_3M_12_64    0xDD /* L3:    3M, 12-way, 64 bytes */
#define CPUID_CACHE_L3_6M_12_64    0xDE /* L3:    6M, 12-way, 64 bytes */
#define CPUID_CACHE_L3_2M_16_64    0xE2 /* L3:    2M, 16-way, 64 bytes */
#define CPUID_CACHE_L3_4M_16_64    0xE3 /* L3:    4M, 16-way, 64 bytes */
#define CPUID_CACHE_L3_8M_16_64    0xE4 /* L3:    8M, 16-way, 64 bytes */
#define CPUID_CACHE_PREFETCH_64    0xF0 /* 64-Byte Prefetching */
#define CPUID_CACHE_PREFETCH_128   0xF1 /* 128-Byte Prefetching */

#define CPUID_MWAIT_EXTENSION	_Bit(0)	/* enumeration of WMAIT extensions */
#define CPUID_MWAIT_BREAK	_Bit(1)	/* interrupts are break events	   */

#define CPUID_MODEL_YONAH	14
#define CPUID_MODEL_MEROM	15
#define CPUID_MODEL_PENRYN	23
#define CPUID_MODEL_NEHALEM	26

#ifndef ASSEMBLER
#include <stdint.h>
#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <mach/machine.h>


typedef enum { eax, ebx, ecx, edx } cpuid_register_t;
static inline void
cpuid(uint32_t *data)
{
	asm("cpuid"
		: "=a" (data[eax]),
		  "=b" (data[ebx]),
		  "=c" (data[ecx]),
		  "=d" (data[edx])
		: "a"  (data[eax]),
		  "b"  (data[ebx]),
		  "c"  (data[ecx]),
		  "d"  (data[edx]));
}
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
 * Cache ID descriptor structure, used to parse CPUID leaf 2.
 * Note: not used in kernel.
 */
typedef enum { Lnone, L1I, L1D, L2U, L3U, LCACHE_MAX } cache_type_t ; 
typedef struct {
	unsigned char	value;          /* Descriptor value */
	cache_type_t 	type;           /* Cache type */
	unsigned int 	size;           /* Cache size */
	unsigned int 	linesize;       /* Cache line size */
#ifdef KERNEL
	const char	*description;   /* Cache description */
#endif /* KERNEL */
} cpuid_cache_desc_t;  

#ifdef KERNEL
#define CACHE_DESC(value,type,size,linesize,text) \
	{ value, type, size, linesize, text }
#else
#define CACHE_DESC(value,type,size,linesize,text) \
	{ value, type, size, linesize }
#endif /* KERNEL */

/* Physical CPU info - this is exported out of the kernel (kexts), so be wary of changes */
typedef struct {
	char		cpuid_vendor[16];
	char		cpuid_brand_string[48];
	const char	*cpuid_model_string;

	cpu_type_t	cpuid_type;					/* this is *not* a cpu_type_t in our <mach/machine.h> */
	uint8_t		cpuid_family;
	uint8_t		cpuid_model;
	uint8_t		cpuid_extmodel;
	uint8_t		cpuid_extfamily;
	uint8_t		cpuid_stepping;
	uint64_t	cpuid_features;
	uint64_t	cpuid_extfeatures;
	uint32_t	cpuid_signature;
	uint8_t   	cpuid_brand; 
	
	uint32_t	cache_size[LCACHE_MAX];
	uint32_t	cache_linesize;

	uint8_t		cache_info[64];    /* list of cache descriptors */

	uint32_t	cpuid_cores_per_package;
	uint32_t	cpuid_logical_per_package;
	uint32_t	cache_sharing[LCACHE_MAX];
	uint32_t	cache_partitions[LCACHE_MAX];

	cpu_type_t	cpuid_cpu_type;			/* <mach/machine.h> */
	cpu_subtype_t	cpuid_cpu_subtype;		/* <mach/machine.h> */	

	/* Monitor/mwait Leaf: */
	uint32_t	cpuid_mwait_linesize_min;
	uint32_t	cpuid_mwait_linesize_max;
	uint32_t	cpuid_mwait_extensions;
	uint32_t	cpuid_mwait_sub_Cstates;

	/* Thermal and Power Management Leaf: */
	boolean_t	cpuid_thermal_sensor;
	boolean_t	cpuid_thermal_dynamic_acceleration;
	uint32_t	cpuid_thermal_thresholds;
	boolean_t	cpuid_thermal_ACNT_MCNT;

	/* Architectural Performance Monitoring Leaf: */
	uint8_t		cpuid_arch_perf_version;
	uint8_t		cpuid_arch_perf_number;
	uint8_t		cpuid_arch_perf_width;
	uint8_t		cpuid_arch_perf_events_number;
	uint32_t	cpuid_arch_perf_events;
	uint8_t		cpuid_arch_perf_fixed_number;
	uint8_t		cpuid_arch_perf_fixed_width;
	
	/* Cache details: */
	uint32_t	cpuid_cache_linesize;
	uint32_t	cpuid_cache_L2_associativity;
	uint32_t	cpuid_cache_size;

	/* Virtual and physical address aize: */
	uint32_t	cpuid_address_bits_physical;
	uint32_t	cpuid_address_bits_virtual;

	uint32_t	cpuid_microcode_version;

	/* Numbers of tlbs per processor */
	uint32_t	cpuid_itlb_small;
	uint32_t	cpuid_dtlb_small;
	uint32_t	cpuid_itlb_large;
	uint32_t	cpuid_dtlb_large;

	uint32_t	core_count;
	uint32_t	thread_count;

} i386_cpu_info_t;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * External declarations
 */
extern cpu_type_t	cpuid_cputype(void);
extern cpu_subtype_t	cpuid_cpusubtype(void);
extern void		cpuid_cpu_display(const char *);
extern void		cpuid_feature_display(const char *);
extern void		cpuid_extfeature_display(const char *);
extern char *		cpuid_get_feature_names(uint64_t, char *, unsigned);
extern char *		cpuid_get_extfeature_names(uint64_t, char *, unsigned);

extern uint64_t		cpuid_features(void);
extern uint64_t		cpuid_extfeatures(void);
extern uint32_t		cpuid_family(void);
	
extern void		cpuid_get_info(i386_cpu_info_t *info_p);
extern i386_cpu_info_t	*cpuid_info(void);

extern void		cpuid_set_info(void);

#ifdef __cplusplus
}
#endif

#endif /* ASSEMBLER */

#endif /* __APPLE_API_PRIVATE */
#endif /* _MACHINE_CPUID_H_ */
