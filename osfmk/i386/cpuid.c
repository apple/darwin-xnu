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
 * @OSF_COPYRIGHT@
 */
#include <platforms.h>
#include <mach_kdb.h>
#include <pexpert/pexpert.h>

#include "cpuid.h"
#if MACH_KDB
#include <i386/db_machdep.h>
#include <ddb/db_aout.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_variables.h>
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_expr.h>
#endif

#define min(a,b) ((a) < (b) ? (a) : (b))
#define quad(hi,lo)	(((uint64_t)(hi)) << 32 | (lo))

#define bit(n)		(1UL << (n))
#define bitmask(h,l)	((bit(h)|(bit(h)-1)) & ~(bit(l)-1))
#define bitfield(x,h,l)	(((x) & bitmask(h,l)) >> l)

/*
 * CPU identification routines.
 *
 * Note that this code assumes a processor that supports the
 * 'cpuid' instruction.
 */

static unsigned int	cpuid_maxcpuid;

static i386_cpu_info_t	*cpuid_cpu_infop = NULL;
static i386_cpu_info_t	cpuid_cpu_info;

uint32_t		cpuid_feature;		/* XXX obsolescent for compat */

/*
 * We only identify Intel CPUs here.  Adding support
 * for others would be straightforward.
 */
static void	set_cpu_generic(i386_cpu_info_t *);
static void	set_cpu_intel(i386_cpu_info_t *);
static void	set_cpu_amd(i386_cpu_info_t *);
static void	set_cpu_nsc(i386_cpu_info_t *);
static void	set_cpu_unknown(i386_cpu_info_t *);

struct {
	const char	*vendor;
	void		(* func)(i386_cpu_info_t *);
} cpu_vendors[] = {
	{CPUID_VID_INTEL,	set_cpu_intel},
	{CPUID_VID_AMD,         set_cpu_amd},
	{CPUID_VID_NSC,         set_cpu_nsc},
	{0,			set_cpu_unknown}
};

void
cpuid_get_info(i386_cpu_info_t *info_p)
{
	uint32_t	cpuid_result[4];
	int		i;

	bzero((void *)info_p, sizeof(i386_cpu_info_t));

	/* do cpuid 0 to get vendor */
	do_cpuid(0, cpuid_result);
	cpuid_maxcpuid = cpuid_result[eax];
	bcopy((char *)&cpuid_result[ebx], &info_p->cpuid_vendor[0], 4); /* ug */
	bcopy((char *)&cpuid_result[ecx], &info_p->cpuid_vendor[8], 4);
	bcopy((char *)&cpuid_result[edx], &info_p->cpuid_vendor[4], 4);
	info_p->cpuid_vendor[12] = 0;

	/* look up vendor */
	for (i = 0; ; i++) {
		if ((cpu_vendors[i].vendor == 0) ||
		    (!strcmp(cpu_vendors[i].vendor, info_p->cpuid_vendor))) {
			cpu_vendors[i].func(info_p);
			break;
		}
	}
}

/*
 * Cache descriptor table. Each row has the form:
 *	   (descriptor_value,		cache,	size,		linesize,
 * 				description)
 * Note: the CACHE_DESC macro does not expand description text in the kernel.
 */
static cpuid_cache_desc_t cpuid_cache_desc_tab[] = {
CACHE_DESC(CPUID_CACHE_ITLB_4K, 	Lnone,	0,		0, \
	"Instruction TLB, 4K, pages 4-way set associative, 64 entries"),
CACHE_DESC(CPUID_CACHE_ITLB_4M, 	Lnone,	0,		0, \
	"Instruction TLB, 4M, pages 4-way set associative, 2 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_4K, 	Lnone,	0,		0, \
	"Data TLB, 4K pages, 4-way set associative, 64 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_4M, 	Lnone,	0,		0, \
	"Data TLB, 4M pages, 4-way set associative, 8 entries"),
CACHE_DESC(CPUID_CACHE_ITLB_64, 	Lnone,	0,		0, \
	"Instruction TLB, 4K and 2M or 4M pages, 64 entries"),
CACHE_DESC(CPUID_CACHE_ITLB_128, 	Lnone,	0,		0, \
	"Instruction TLB, 4K and 2M or 4M pages, 128 entries"),
CACHE_DESC(CPUID_CACHE_ITLB_256, 	Lnone,	0,		0, \
	"Instruction TLB, 4K and 2M or 4M pages, 256 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_64,		Lnone,	0,		0, \
	"Data TLB, 4K and 4M pages, 64 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_128,	Lnone,	0,		0, \
	"Data TLB, 4K and 4M pages, 128 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_256,	Lnone,	0,		0, \
	"Data TLB, 4K and 4M pages, 256 entries"),
CACHE_DESC(CPUID_CACHE_ITLB_4K_128_4,      Lnone,  0,              0, \
        "Instruction TLB, 4K pages, 4-way set associative, 128 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_4K_128_4,      Lnone,  0,              0, \
        "Data TLB, 4K pages, 4-way set associative, 128 entries"),
CACHE_DESC(CPUID_CACHE_ICACHE_8K,	L1I,	8*1024, 	32, \
	"Instruction L1 cache, 8K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_8K,	L1D,	8*1024, 	32, \
	"Data L1 cache, 8K, 2-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_ICACHE_16K,	L1I,	16*1024,	 32, \
	"Instruction L1 cache, 16K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_16K,	L1D,	16*1024, 	32, \
	"Data L1 cache, 16K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_8K_4_64,	L1D,	8*1024,		64, \
	"Data L1 cache, 8K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_16K_4_64,	L1D,	16*1024,	64, \
	"Data L1 cache, 16K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_32K_4_64,	L1D,	32*1024,	64, \
	"Data L1 cache, 32K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_32K,      L1D,    32*1024,        64, \
        "Data L1 cache, 32K, 8-way set assocative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_ICACHE_32K,      L1I,    32*1024,        64, \
        "Instruction L1 cache, 32K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_16K_8_64,    L1D,    16*1024,        64, \
        "Data L1 cache, 16K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_TRACE_12K_8,	L1I,	12*1024,	64, \
	"Trace cache, 12K-uop, 8-way set associative"),
CACHE_DESC(CPUID_CACHE_TRACE_16K_8,	L1I,	16*1024,	64, \
	"Trace cache, 16K-uop, 8-way set associative"),
CACHE_DESC(CPUID_CACHE_TRACE_32K_8,	L1I,	32*1024,	64, \
	"Trace cache, 32K-uop, 8-way set associative"),
CACHE_DESC(CPUID_CACHE_L2_128K,	L2U,	128*1024,	32, \
	"Unified L2 cache, 128K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_256K,	L2U,	128*1024,	32, \
	"Unified L2 cache, 256K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_512K,	L2U,	512*1024,	32, \
	"Unified L2 cache, 512K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_1M_4,	L2U,	1*1024*1024,	32, \
	"Unified L2 cache, 1M, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_2M_4,	L2U,	2*1024*1024,	32, \
	"Unified L2 cache, 2M, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_4M_16_64,	L2U,	4*1024*1024,	64, \
	"Unified L2 cache, 4M, 16-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_128K_8_64_2,	L2U,	128*1024,	64, \
	"Unified L2 cache, 128K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_256K_8_64_2,	L2U,	256*1024,	64, \
	"Unified L2 cache, 256K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_512K_8_64_2,	L2U,	512*1024,	64, \
	"Unified L2 cache, 512K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_1M_8_64_2,	L2U,	1*1024*1024,	64, \
	"Unified L2 cache, 1M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_256K_8_32,	L2U,	256*1024,	32, \
	"Unified L2 cache, 256K, 8-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_512K_8_32,	L2U,	512*1024,	32, \
	"Unified L2 cache, 512K, 8-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_1M_8_32,	L2U,	1*1024*1024,	32, \
	"Unified L2 cache, 1M, 8-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_2M_8_32,	L2U,	2*1024*1024,	32, \
	"Unified L2 cache, 2M, 8-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_L2_1M_4_64,  L2U,    1*1024*1024,    64, \
        "Unified L2 cache, 1M, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_2M_8_64,    L2U,    2*1024*1024,    64, \
        "Unified L2 cache, 2M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_512K_2_64,L2U,    512*1024,       64, \
        "Unified L2 cache, 512K, 2-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_512K_4_64,L2U,    512*1024,       64, \
        "Unified L2 cache, 512K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_1M_8_64,  L2U,    1*1024*1024,    64, \
        "Unified L2 cache, 1M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_128K_S4,  L2U,    128*1024,       64, \
        "Unified L2 sectored cache, 128K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_128K_S2,  L2U,    128*1024,       64, \
        "Unified L2 sectored cache, 128K, 2-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L2_256K_S4,  L2U,    256*1024,       64, \
        "Unified L2 sectored cache, 256K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L3_512K,    L3U,    512*1024,       64, \
        "Unified L3 cache, 512K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L3_1M,      L3U,    1*1024*1024,    64, \
        "Unified L3 cache, 1M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L3_2M,      L3U,    2*1024*1024,    64, \
        "Unified L3 cache, 2M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L3_4M,      L3U,    4*1024*1024,    64, \
        "Unified L3 cache, 4M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_PREFETCH_64,     Lnone,  0,              0,  \
        "64-Byte Prefetching"),
CACHE_DESC(CPUID_CACHE_PREFETCH_128,    Lnone,  0,              0,  \
        "128-Byte Prefetching"),
CACHE_DESC(CPUID_CACHE_NOCACHE, Lnone, 0, 0, \
        "No L2 cache or, if valid L2 cache, no L3 cache"),
CACHE_DESC(CPUID_CACHE_NULL, Lnone, 0, 0, \
	(char *)0),
};

static const char * get_intel_model_string( i386_cpu_info_t * info_p, cpu_type_t* type, cpu_subtype_t* subtype)
{
	*type = CPU_TYPE_X86;
	*subtype = CPU_SUBTYPE_X86_ARCH1;

    /* check for brand id string */
    switch(info_p->cpuid_brand) {
        case CPUID_BRAND_UNSUPPORTED:
            /* brand ID not supported; use alternate method. */
            switch(info_p->cpuid_family) {
                case CPUID_FAMILY_486:
                    return "Intel 486";
                case CPUID_FAMILY_586:
                    return "Intel Pentium";
                case CPUID_FAMILY_686:
                    switch(info_p->cpuid_model) {
                        case CPUID_MODEL_P6:
                            return "Intel Pentium Pro";
                        case CPUID_MODEL_PII:
                            return "Intel Pentium II";
                        case CPUID_MODEL_P65:
                        case CPUID_MODEL_P66:
                            return "Intel Celeron";
                        case CPUID_MODEL_P67:
                        case CPUID_MODEL_P68:
                        case CPUID_MODEL_P6A:
                        case CPUID_MODEL_P6B:
                            return "Intel Pentium III";
                        case CPUID_MODEL_PM9:
                        case CPUID_MODEL_PMD:
                            return "Intel Pentium M";
                        default:
                            return "Unknown Intel P6 Family";
                    }
                case CPUID_FAMILY_EXTENDED:
                    switch (info_p->cpuid_extfamily) {
                        case CPUID_EXTFAMILY_PENTIUM4:
			    *subtype = CPU_SUBTYPE_PENTIUM_4;
                            return "Intel Pentium 4";
						default:
		                    return "Unknown Intel Extended Family";
                    }
                default:
                    return "Unknown Intel Family";
            }
            break;
        case CPUID_BRAND_CELERON_1:
        case CPUID_BRAND_CELERON_A:
        case CPUID_BRAND_CELERON_14:
            return "Intel Celeron";
        case CPUID_BRAND_PENTIUM_III_2:
        case CPUID_BRAND_PENTIUM_III_4:
            return "Pentium III";
        case CPUID_BRAND_PIII_XEON:
			if (info_p->cpuid_signature == 0x6B1) {
				return "Intel Celeron";
			} else {
				return "Intel Pentium III Xeon";
			}
        case CPUID_BRAND_PENTIUM_III_M:
            return "Mobile Intel Pentium III-M";
        case CPUID_BRAND_M_CELERON_7:
        case CPUID_BRAND_M_CELERON_F:
        case CPUID_BRAND_M_CELERON_13:
        case CPUID_BRAND_M_CELERON_17:
            return "Mobile Intel Celeron";
        case CPUID_BRAND_PENTIUM4_8:
        case CPUID_BRAND_PENTIUM4_9:
	    *subtype = CPU_SUBTYPE_PENTIUM_4;
            return "Intel Pentium 4";
        case CPUID_BRAND_XEON:
            return "Intel Xeon";
        case CPUID_BRAND_XEON_MP:
            return "Intel Xeon MP";
        case CPUID_BRAND_PENTIUM4_M:
			if (info_p->cpuid_signature == 0xF13) {
				return "Intel Xeon";
			} else {
				*subtype = CPU_SUBTYPE_PENTIUM_4;
				return "Mobile Intel Pentium 4";
			}
        case CPUID_BRAND_CELERON_M:
            return "Intel Celeron M";
        case CPUID_BRAND_PENTIUM_M:
            return "Intel Pentium M";
        case CPUID_BRAND_MOBILE_15:
        case CPUID_BRAND_MOBILE_17:
            return "Mobile Intel";
    }        
    return "Unknown Intel";
}

static void set_intel_cache_info( i386_cpu_info_t * info_p )
{
	uint32_t	cpuid_result[4];
        uint32_t        l1d_cache_linesize = 0;
	unsigned int	i;
	unsigned int	j;

	/* get processor cache descriptor info */
	do_cpuid(2, cpuid_result);
	for (j = 0; j < 4; j++) {
		if ((cpuid_result[j] >> 31) == 1) 	/* bit31 is validity */
			continue;
		((uint32_t *) info_p->cache_info)[j] = cpuid_result[j];
	}
	/* first byte gives number of cpuid calls to get all descriptors */
	for (i = 1; i < info_p->cache_info[0]; i++) {
		if (i*16 > sizeof(info_p->cache_info))
			break;
		do_cpuid(2, cpuid_result);
		for (j = 0; j < 4; j++) {
			if ((cpuid_result[j] >> 31) == 1) 
				continue;
			((uint32_t *) info_p->cache_info)[4*i+j] =
				cpuid_result[j];
		}
	}

	/* decode the descriptors looking for L1/L2/L3 size info */
	for (i = 1; i < sizeof(info_p->cache_info); i++) {
		cpuid_cache_desc_t	*descp;
		uint8_t			desc = info_p->cache_info[i];

		if (desc == CPUID_CACHE_NULL)
			continue;
		for (descp = cpuid_cache_desc_tab;
			descp->value != CPUID_CACHE_NULL; descp++) {
			if (descp->value != desc)
				continue;
			info_p->cache_size[descp->type] = descp->size;
			if (descp->type == L2U)
				info_p->cache_linesize = descp->linesize;
                        if (descp->type == L1D)
                                l1d_cache_linesize = descp->linesize;
			break;
		}
	}
	/* For P-IIIs, L2 could be 256k or 512k but we can't tell */ 
	if (info_p->cache_size[L2U] == 0 &&
	    info_p->cpuid_family == 0x6 && info_p->cpuid_model == 0xb) {
		info_p->cache_size[L2U] = 256*1024;
		info_p->cache_linesize = 32;
	}
        /* If we have no L2 cache, use the L1 data cache line size */
        if (info_p->cache_size[L2U] == 0)
            info_p->cache_linesize = l1d_cache_linesize;

	/*
	 * Get cache sharing info if available.
	 */
	do_cpuid(0, cpuid_result);
	if (cpuid_result[eax] >= 4) {
		uint32_t	reg[4];
		uint32_t	index;
		for (index = 0;; index++) {
			/*
			 * Scan making calls for cpuid with %eax = 4
			 * to get info about successive cache levels
			 * until a null type is returned.
			 */
			cache_type_t	type = Lnone;
			uint32_t	cache_type;
			uint32_t	cache_level;
			uint32_t	cache_sharing;

			reg[eax] = 4;		/* cpuid request 4 */
			reg[ecx] = index;	/* index starting at 0 */
			cpuid(reg);
//kprintf("cpuid(4) index=%d eax=%p\n", index, reg[eax]);
			cache_type = bitfield(reg[eax], 4, 0);
			if (cache_type == 0)
				break;		/* done with cache info */
			cache_level   = bitfield(reg[eax],  7,  5);
			cache_sharing = bitfield(reg[eax], 25, 14);
			info_p->cpuid_cores_per_package = 
					bitfield(reg[eax], 31, 26) + 1;
			switch (cache_level) {
			case 1:
				type = cache_type == 1 ? L1D :
				       cache_type == 2 ? L1I :
							 Lnone;
				break;
			case 2:
				type = cache_type == 3 ? L2U :
							 Lnone;
				break;
			case 3:
				type = cache_type == 3 ? L3U :
							 Lnone;
			}
			if (type != Lnone)
				info_p->cache_sharing[type] = cache_sharing + 1;
		} 
	}
}

static void set_cpu_intel( i386_cpu_info_t * info_p )
{
    set_cpu_generic(info_p);
    set_intel_cache_info(info_p);
    info_p->cpuid_model_string = get_intel_model_string(info_p, &info_p->cpuid_cpu_type, &info_p->cpuid_cpu_subtype);
}

static const char * get_amd_model_string( i386_cpu_info_t * info_p, cpu_type_t* type, cpu_subtype_t* subtype )
{
	*type = CPU_TYPE_X86;
	*subtype = CPU_SUBTYPE_X86_ARCH1;

    /* check for brand id string */
    switch (info_p->cpuid_family)
    {
        case CPUID_FAMILY_486:
            switch (info_p->cpuid_model) {
                case CPUID_MODEL_AM486_DX:
                case CPUID_MODEL_AM486_DX2:
                case CPUID_MODEL_AM486_DX2WB:
                case CPUID_MODEL_AM486_DX4:
                case CPUID_MODEL_AM486_DX4WB:
                    return "Am486";
                case CPUID_MODEL_AM486_5X86:
                case CPUID_MODEL_AM486_5X86WB:
                    return "Am5x86";
            }
            break;
        case CPUID_FAMILY_586:
            switch (info_p->cpuid_model) {
                case CPUID_MODEL_K5M0:
                case CPUID_MODEL_K5M1:
                case CPUID_MODEL_K5M2:
                case CPUID_MODEL_K5M3:
                    return "AMD-K5";
                case CPUID_MODEL_K6M6:
                case CPUID_MODEL_K6M7:
                    return "AMD-K6";
                case CPUID_MODEL_K6_2:
                    return "AMD-K6-2";
                case CPUID_MODEL_K6_III:
                    return "AMD-K6-III";
            }
            break;
        case CPUID_FAMILY_686:
            switch (info_p->cpuid_model) {
                case CPUID_MODEL_ATHLON_M1:
                case CPUID_MODEL_ATHLON_M2:
                case CPUID_MODEL_ATHLON_M4:
                case CPUID_MODEL_ATHLON_M6:
                case CPUID_MODEL_ATHLON_M8:
                case CPUID_MODEL_ATHLON_M10:
                    return "AMD Athlon";
                case CPUID_MODEL_DURON_M3:
                case CPUID_MODEL_DURON_M7:
                    return "AMD Duron";
                default:
                    return "Unknown AMD Athlon";
            }
        case CPUID_FAMILY_EXTENDED:
            switch (info_p->cpuid_model) {
                case CPUID_MODEL_ATHLON64:
                    return "AMD Athlon 64";
                case CPUID_MODEL_OPTERON:
                    return "AMD Opteron";
                default:
                    return "Unknown AMD-64";
            }
    }
    return "Unknown AMD";
}

static void set_amd_cache_info( i386_cpu_info_t * info_p )
{
    uint32_t	cpuid_result[4];

    /* It would make sense to fill in info_p->cache_info with complete information
     * on the TLBs and data cache associativity, lines, etc, either by mapping
     * to the Intel tags (if possible), or replacing cache_info with a generic
     * mechanism.  But right now, nothing makes use of that information (that I know
     * of).
     */

    /* L1 Cache and TLB Information */
    do_cpuid(0x80000005, cpuid_result);
    
    /* EAX: TLB Information for 2-Mbyte and 4-MByte Pages */
    /* (ignore) */
    
    /* EBX: TLB Information for 4-Kbyte Pages */
    /* (ignore) */
    
    /* ECX: L1 Data Cache Information */
    info_p->cache_size[L1D] = ((cpuid_result[ecx] >> 24) & 0xFF) * 1024;
    info_p->cache_linesize = (cpuid_result[ecx] & 0xFF);
    
    /* EDX: L1 Instruction Cache Information */
    info_p->cache_size[L1I] = ((cpuid_result[edx] >> 24) & 0xFF) * 1024;

    /* L2 Cache Information */
    do_cpuid(0x80000006, cpuid_result);
    
    /* EAX: L2 TLB Information for 2-Mbyte and 4-Mbyte Pages */
    /* (ignore) */
    
    /* EBX: L2 TLB Information for 4-Kbyte Pages */
    /* (ignore) */
    
    /* ECX: L2 Cache Information */
    info_p->cache_size[L2U] = ((cpuid_result[ecx] >> 16) & 0xFFFF) * 1024;
    if (info_p->cache_size[L2U] > 0)
        info_p->cache_linesize = cpuid_result[ecx] & 0xFF;
}

static void set_cpu_amd( i386_cpu_info_t * info_p )
{
    set_cpu_generic(info_p);
    set_amd_cache_info(info_p);
    info_p->cpuid_model_string = get_amd_model_string(info_p, &info_p->cpuid_cpu_type, &info_p->cpuid_cpu_subtype);
}

static void set_cpu_nsc( i386_cpu_info_t * info_p )
{
    set_cpu_generic(info_p);
    set_amd_cache_info(info_p);

    /* check for brand id string */
    if (info_p->cpuid_family == CPUID_FAMILY_586 && info_p->cpuid_model == CPUID_MODEL_GX1) {
        info_p->cpuid_model_string = "AMD Geode GX1";
    } else if (info_p->cpuid_family == CPUID_FAMILY_586 && info_p->cpuid_model == CPUID_MODEL_GX2) {
        info_p->cpuid_model_string = "AMD Geode GX";
    } else {
        info_p->cpuid_model_string = "Unknown National Semiconductor";
    }
    info_p->cpuid_cpu_type = CPU_TYPE_X86;
    info_p->cpuid_cpu_subtype = CPU_SUBTYPE_X86_ARCH1;
}

static void
set_cpu_generic(i386_cpu_info_t *info_p)
{
	uint32_t	cpuid_result[4];
	uint32_t	max_extid;
        char            str[128], *p;

	/* get extended cpuid results */
	do_cpuid(0x80000000, cpuid_result);
	max_extid = cpuid_result[eax];

	/* check to see if we can get brand string */
	if (max_extid >= 0x80000004) {
		/*
		 * The brand string 48 bytes (max), guaranteed to
		 * be NUL terminated.
		 */
		do_cpuid(0x80000002, cpuid_result);
		bcopy((char *)cpuid_result, &str[0], 16);
		do_cpuid(0x80000003, cpuid_result);
		bcopy((char *)cpuid_result, &str[16], 16);
		do_cpuid(0x80000004, cpuid_result);
		bcopy((char *)cpuid_result, &str[32], 16);
		for (p = str; *p != '\0'; p++) {
			if (*p != ' ') break;
		}
		strncpy(info_p->cpuid_brand_string,
			p, sizeof(info_p->cpuid_brand_string)-1);
		info_p->cpuid_brand_string[sizeof(info_p->cpuid_brand_string)-1] = '\0';

                if (!strcmp(info_p->cpuid_brand_string, CPUID_STRING_UNKNOWN)) {
                    /*
                     * This string means we have a BIOS-programmable brand string,
                     * and the BIOS couldn't figure out what sort of CPU we have.
                     */
                    info_p->cpuid_brand_string[0] = '\0';
                }
	}
    
	/* get processor signature and decode */
	do_cpuid(1, cpuid_result);
	info_p->cpuid_signature = cpuid_result[eax];
	info_p->cpuid_stepping  = bitfield(cpuid_result[eax],  3,  0);
	info_p->cpuid_model     = bitfield(cpuid_result[eax],  7,  4);
	info_p->cpuid_family    = bitfield(cpuid_result[eax], 11,  8);
	info_p->cpuid_type      = bitfield(cpuid_result[eax], 13, 12);
	info_p->cpuid_extmodel  = bitfield(cpuid_result[eax], 19, 16);
	info_p->cpuid_extfamily = bitfield(cpuid_result[eax], 27, 20);
	info_p->cpuid_brand     = bitfield(cpuid_result[ebx],  7,  0);
	info_p->cpuid_logical_per_package =
				  bitfield(cpuid_result[ebx], 23, 16);
	info_p->cpuid_features  = quad(cpuid_result[ecx], cpuid_result[edx]);

	if (max_extid >= 0x80000001) {
		do_cpuid(0x80000001, cpuid_result);
		info_p->cpuid_extfeatures =
				quad(cpuid_result[ecx], cpuid_result[edx]);
	}

	return;
}

static void
set_cpu_unknown(__unused i386_cpu_info_t *info_p)
{
    info_p->cpuid_model_string = "Unknown";
}


static struct {
	uint64_t	mask;
	const char	*name;
} feature_map[] = {
	{CPUID_FEATURE_FPU,   "FPU",},
	{CPUID_FEATURE_VME,   "VME",},
	{CPUID_FEATURE_DE,    "DE",},
	{CPUID_FEATURE_PSE,   "PSE",},
	{CPUID_FEATURE_TSC,   "TSC",},
	{CPUID_FEATURE_MSR,   "MSR",},
	{CPUID_FEATURE_PAE,   "PAE",},
	{CPUID_FEATURE_MCE,   "MCE",},
	{CPUID_FEATURE_CX8,   "CX8",},
	{CPUID_FEATURE_APIC,  "APIC",},
	{CPUID_FEATURE_SEP,   "SEP",},
	{CPUID_FEATURE_MTRR,  "MTRR",},
	{CPUID_FEATURE_PGE,   "PGE",},
	{CPUID_FEATURE_MCA,   "MCA",},
	{CPUID_FEATURE_CMOV,  "CMOV",},
	{CPUID_FEATURE_PAT,   "PAT",},
	{CPUID_FEATURE_PSE36, "PSE36",},
	{CPUID_FEATURE_PSN,   "PSN",},
	{CPUID_FEATURE_CLFSH, "CLFSH",},
	{CPUID_FEATURE_DS,    "DS",},
	{CPUID_FEATURE_ACPI,  "ACPI",},
	{CPUID_FEATURE_MMX,   "MMX",},
	{CPUID_FEATURE_FXSR,  "FXSR",},
	{CPUID_FEATURE_SSE,   "SSE",},
	{CPUID_FEATURE_SSE2,  "SSE2",},
	{CPUID_FEATURE_SS,    "SS",},
	{CPUID_FEATURE_HTT,   "HTT",},
	{CPUID_FEATURE_TM,    "TM",},
	{CPUID_FEATURE_SSE3,    "SSE3"},
	{CPUID_FEATURE_MONITOR, "MON"},
	{CPUID_FEATURE_DSCPL,   "DSCPL"},
	{CPUID_FEATURE_VMX,     "VMX"},
	{CPUID_FEATURE_SMX,     "SMX"},
	{CPUID_FEATURE_EST,     "EST"},
	{CPUID_FEATURE_TM2,     "TM2"},
	{CPUID_FEATURE_MNI,     "MNI"},
	{CPUID_FEATURE_CID,     "CID"},
	{CPUID_FEATURE_CX16,    "CX16"},
	{CPUID_FEATURE_xTPR,    "TPR"},
	{CPUID_FEATURE_PDCM,    "PDCM"},
	{CPUID_FEATURE_DCA,     "DCA"},
	{CPUID_FEATURE_SSE4_1,  "SSE4.1"},
	{CPUID_FEATURE_SSE4_2,  "SSE4.2"},
	{CPUID_FEATURE_POPCNT,  "POPCNT"},
	{0, 0}
},
extfeature_map[] = {
	{CPUID_EXTFEATURE_SYSCALL, "SYSCALL"},
	{CPUID_EXTFEATURE_XD,      "XD"},
	{CPUID_EXTFEATURE_EM64T,   "EM64T"},
	{CPUID_EXTFEATURE_LAHF,    "LAHF"},
	{0, 0}
};

i386_cpu_info_t	*
cpuid_info(void)
{
	/* Set-up the cpuid_indo stucture lazily */
	if (cpuid_cpu_infop == NULL) {
		cpuid_get_info(&cpuid_cpu_info);
		cpuid_cpu_infop = &cpuid_cpu_info;
	}
	return cpuid_cpu_infop;
}

char *
cpuid_get_feature_names(uint64_t features, char *buf, unsigned buf_len)
{
	int	len = -1;
	char	*p = buf;
	int	i;

	for (i = 0; feature_map[i].mask != 0; i++) {
		if ((features & feature_map[i].mask) == 0)
			continue;
		if (len > 0)
			*p++ = ' ';
		len = min(strlen(feature_map[i].name), (buf_len-1) - (p-buf));
		if (len == 0)
			break;
		bcopy(feature_map[i].name, p, len);
		p += len;
	}
	*p = '\0';
	return buf;
}

char *
cpuid_get_extfeature_names(uint64_t extfeatures, char *buf, unsigned buf_len)
{
	int	len = -1;
	char	*p = buf;
	int	i;

	for (i = 0; extfeature_map[i].mask != 0; i++) {
		if ((extfeatures & extfeature_map[i].mask) == 0)
			continue;
		if (len > 0)
			*p++ = ' ';
		len = min(strlen(extfeature_map[i].name), (buf_len-1)-(p-buf));
		if (len == 0)
			break;
		bcopy(extfeature_map[i].name, p, len);
		p += len;
	}
	*p = '\0';
	return buf;
}

void
cpuid_feature_display(
	const char	*header)
{
	char	buf[256];

	kprintf("%s: %s\n", header,
		  cpuid_get_feature_names(cpuid_features(),
						buf, sizeof(buf)));
	if (cpuid_features() & CPUID_FEATURE_HTT) {
#define s_if_plural(n)	((n > 1) ? "s" : "")
		kprintf("  HTT: %d core%s per package;"
			     " %d logical cpu%s per package\n",
			cpuid_cpu_info.cpuid_cores_per_package,
			s_if_plural(cpuid_cpu_info.cpuid_cores_per_package),
			cpuid_cpu_info.cpuid_logical_per_package,
			s_if_plural(cpuid_cpu_info.cpuid_logical_per_package));
	}
}

void
cpuid_extfeature_display(
	const char	*header)
{
	char	buf[256];

	kprintf("%s: %s\n", header,
		  cpuid_get_extfeature_names(cpuid_extfeatures(),
						buf, sizeof(buf)));
}

void
cpuid_cpu_display(
	const char	*header)
{
    if (cpuid_info()->cpuid_brand_string[0] != '\0') {
	kprintf("%s: %s\n", header, cpuid_cpu_info.cpuid_brand_string);
    }
}

unsigned int
cpuid_family(void)
{
	return cpuid_info()->cpuid_family;
}

cpu_type_t
cpuid_cputype(void)
{
	return cpuid_info()->cpuid_cpu_type;
}

cpu_subtype_t
cpuid_cpusubtype(void)
{
	return cpuid_info()->cpuid_cpu_subtype;
}

uint64_t
cpuid_features(void)
{
	static int checked = 0;
	char	fpu_arg[16] = { 0 };

	(void) cpuid_info();
	if (!checked) {
		    /* check for boot-time fpu limitations */
			if (PE_parse_boot_arg("_fpu", &fpu_arg[0])) {
				printf("limiting fpu features to: %s\n", fpu_arg);
				if (!strncmp("387", fpu_arg, sizeof "387") || !strncmp("mmx", fpu_arg, sizeof "mmx")) {
					printf("no sse or sse2\n");
					cpuid_cpu_info.cpuid_features &= ~(CPUID_FEATURE_SSE | CPUID_FEATURE_SSE2 | CPUID_FEATURE_FXSR);
				} else if (!strncmp("sse", fpu_arg, sizeof "sse")) {
					printf("no sse2\n");
					cpuid_cpu_info.cpuid_features &= ~(CPUID_FEATURE_SSE2);
				}
			}
			checked = 1;
	}
	return cpuid_cpu_info.cpuid_features;
}

uint64_t
cpuid_extfeatures(void)
{
	return cpuid_info()->cpuid_extfeatures;
}
 
void
cpuid_set_info(void)
{
	cpuid_get_info(&cpuid_cpu_info);
}

#if MACH_KDB

/*
 *	Display the cpuid
 * *		
 *	cp
 */
void 
db_cpuid(__unused db_expr_t addr,
	 __unused int have_addr,
	 __unused db_expr_t count,
	 __unused char *modif)
{

	uint32_t        i, mid;
	uint32_t        cpid[4];

	do_cpuid(0, cpid);	/* Get the first cpuid which is the number of
				 * basic ids */
	db_printf("%08X - %08X %08X %08X %08X\n",
		0, cpid[eax], cpid[ebx], cpid[ecx], cpid[edx]);

	mid = cpid[eax];	/* Set the number */
	for (i = 1; i <= mid; i++) {	/* Dump 'em out */
		do_cpuid(i, cpid);	/* Get the next */
		db_printf("%08X - %08X %08X %08X %08X\n",
			i, cpid[eax], cpid[ebx], cpid[ecx], cpid[edx]);
	}
	db_printf("\n");

	do_cpuid(0x80000000, cpid);	/* Get the first extended cpuid which
					 * is the number of extended ids */
	db_printf("%08X - %08X %08X %08X %08X\n",
		0x80000000, cpid[eax], cpid[ebx], cpid[ecx], cpid[edx]);

	mid = cpid[eax];	/* Set the number */
	for (i = 0x80000001; i <= mid; i++) {	/* Dump 'em out */
		do_cpuid(i, cpid);	/* Get the next */
		db_printf("%08X - %08X %08X %08X %08X\n",
			i, cpid[eax], cpid[ebx], cpid[ecx], cpid[edx]);
	}
}

#endif
