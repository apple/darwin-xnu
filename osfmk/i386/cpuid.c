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
/*
 * @OSF_COPYRIGHT@
 */

#include <pexpert/pexpert.h>

#include "cpuid.h"

#define min(a,b) ((a) < (b) ? (a) : (b))

/*
 * CPU identification routines.
 *
 * Note that this code assumes a processor that supports the
 * 'cpuid' instruction.
 */

static unsigned int	cpuid_maxcpuid;

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
	cpuid_maxcpuid = cpuid_result[0];
	bcopy((char *)&cpuid_result[1], &info_p->cpuid_vendor[0], 4); /* ugh */
	bcopy((char *)&cpuid_result[2], &info_p->cpuid_vendor[8], 4);
	bcopy((char *)&cpuid_result[3], &info_p->cpuid_vendor[4], 4);
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
CACHE_DESC(CPUID_CACHE_ITLB_128_4,      Lnone,  0,              0, \
        "Instruction TLB, 4K pages, 4-way set associative, 128 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_128_4,      Lnone,  0,              0, \
        "Data TLB, 4K pages, 4-way set associative, 128 entries"),
CACHE_DESC(CPUID_CACHE_ICACHE_8K,	L1I,	8*1024, 	32, \
	"Instruction L1 cache, 8K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_8K,	L1D,	8*1024, 	32, \
	"Data L1 cache, 8K, 2-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_ICACHE_16K,	L1I,	16*1024,	 32, \
	"Instruction L1 cache, 16K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_16K,	L1D,	16*1024, 	32, \
	"Data L1 cache, 16K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_8K_64,	L1D,	8*1024,		64, \
	"Data L1 cache, 8K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_16K_64,	L1D,	16*1024,	64, \
	"Data L1 cache, 16K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_32K_64,	L1D,	32*1024,	64, \
	"Data L1 cache, 32K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_32K,      L1D,    32*1024,        64, \
        "Data L1 cache, 32K, 8-way set assocative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_ICACHE_32K,      L1I,    32*1024,        64, \
        "Instruction L1 cache, 32K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_DCACHE_16K_8,    L1D,    16*1024,        64, \
        "Data L1 cache, 16K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_TRACE_12K,	L1I,	12*1024,	64, \
	"Trace cache, 12K-uop, 8-way set associative"),
CACHE_DESC(CPUID_CACHE_TRACE_16K,	L1I,	16*1024,	64, \
	"Trace cache, 16K-uop, 8-way set associative"),
CACHE_DESC(CPUID_CACHE_TRACE_32K,	L1I,	32*1024,	64, \
	"Trace cache, 32K-uop, 8-way set associative"),
CACHE_DESC(CPUID_CACHE_UCACHE_128K,	L2U,	128*1024,	32, \
	"Unified L2 cache, 128K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_256K,	L2U,	128*1024,	32, \
	"Unified L2 cache, 256K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_512K,	L2U,	512*1024,	32, \
	"Unified L2 cache, 512K, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_1M,	L2U,	1*1024*1024,	32, \
	"Unified L2 cache, 1M, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_2M,	L2U,	2*1024*1024,	32, \
	"Unified L2 cache, 2M, 4-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_128K_64,	L2U,	128*1024,	64, \
	"Unified L2 cache, 128K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_256K_64,	L2U,	256*1024,	64, \
	"Unified L2 cache, 256K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_512K_64,	L2U,	512*1024,	64, \
	"Unified L2 cache, 512K, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_1M_64,	L2U,	1*1024*1024,	64, \
	"Unified L2 cache, 1M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_256K_32,	L2U,	256*1024,	32, \
	"Unified L2 cache, 256K, 8-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_512K_32,	L2U,	512*1024,	32, \
	"Unified L2 cache, 512K, 8-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_1M_32,	L2U,	1*1024*1024,	32, \
	"Unified L2 cache, 1M, 8-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_2M_32,	L2U,	2*1024*1024,	32, \
	"Unified L2 cache, 2M, 8-way set associative, 32byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_1M_64_4,  L2U,    1*1024*1024,    64, \
        "Unified L2 cache, 1M, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_2M_64,    L2U,    2*1024*1024,    64, \
        "Unified L2 cache, 2M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_512K_64_2,L2U,    512*1024,       64, \
        "Unified L2 cache, 512K, 2-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_512K_64_4,L2U,    512*1024,       64, \
        "Unified L2 cache, 512K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_1M_64_8,  L2U,    1*1024*1024,    64, \
        "Unified L2 cache, 1M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_128K_S4,  L2U,    128*1024,       64, \
        "Unified L2 sectored cache, 128K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_128K_S2,  L2U,    128*1024,       64, \
        "Unified L2 sectored cache, 128K, 2-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_UCACHE_256K_S4,  L2U,    256*1024,       64, \
        "Unified L2 sectored cache, 256K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L3CACHE_512K,    L3U,    512*1024,       64, \
        "Unified L3 cache, 512K, 4-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L3CACHE_1M,      L3U,    1*1024*1024,    64, \
        "Unified L3 cache, 1M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L3CACHE_2M,      L3U,    2*1024*1024,    64, \
        "Unified L3 cache, 2M, 8-way set associative, 64byte line size"),
CACHE_DESC(CPUID_CACHE_L3CACHE_4M,      L3U,    4*1024*1024,    64, \
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

static const char * get_intel_model_string( i386_cpu_info_t * info_p )
{
    /* check for brand id */
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
                case CPUID_FAMILY_ITANIUM:
                    return "Intel Itanium";
                case CPUID_FAMILY_EXTENDED:
                    switch (info_p->cpuid_extfamily) {
                        case CPUID_EXTFAMILY_PENTIUM4:
                            return "Intel Pentium 4";
                        case CPUID_EXTFAMILY_ITANIUM2:
                            return "Intel Itanium 2";
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
            if (info_p->cpuid_signature == 0x6B1)
                return "Intel Celeron";
            else
                return "Intel Pentium III Xeon";
        case CPUID_BRAND_PENTIUM_III_M:
            return "Mobile Intel Pentium III-M";
        case CPUID_BRAND_M_CELERON_7:
        case CPUID_BRAND_M_CELERON_F:
        case CPUID_BRAND_M_CELERON_13:
        case CPUID_BRAND_M_CELERON_17:
            return "Mobile Intel Celeron";
        case CPUID_BRAND_PENTIUM4_8:
        case CPUID_BRAND_PENTIUM4_9:
            return "Intel Pentium 4";
        case CPUID_BRAND_XEON:
            return "Intel Xeon";
        case CPUID_BRAND_XEON_MP:
            return "Intel Xeon MP";
        case CPUID_BRAND_PENTIUM4_M:
            if (info_p->cpuid_signature == 0xF13)
                return "Intel Xeon";
            else
                return "Mobile Intel Pentium 4";
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
}

static void set_cpu_intel( i386_cpu_info_t * info_p )
{
    set_cpu_generic(info_p);
    set_intel_cache_info(info_p);
    info_p->cpuid_model_string = get_intel_model_string(info_p);
}

static const char * get_amd_model_string( i386_cpu_info_t * info_p )
{
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
    info_p->cache_size[L1D] = ((cpuid_result[2] >> 24) & 0xFF) * 1024;
    info_p->cache_linesize = (cpuid_result[2] & 0xFF);
    
    /* EDX: L1 Instruction Cache Information */
    info_p->cache_size[L1I] = ((cpuid_result[3] >> 24) & 0xFF) * 1024;

    /* L2 Cache Information */
    do_cpuid(0x80000006, cpuid_result);
    
    /* EAX: L2 TLB Information for 2-Mbyte and 4-Mbyte Pages */
    /* (ignore) */
    
    /* EBX: L2 TLB Information for 4-Kbyte Pages */
    /* (ignore) */
    
    /* ECX: L2 Cache Information */
    info_p->cache_size[L2U] = ((cpuid_result[2] >> 16) & 0xFFFF) * 1024;
    if (info_p->cache_size[L2U] > 0)
        info_p->cache_linesize = cpuid_result[2] & 0xFF;
}

static void set_cpu_amd( i386_cpu_info_t * info_p )
{
    set_cpu_generic(info_p);
    set_amd_cache_info(info_p);
    info_p->cpuid_model_string = get_amd_model_string(info_p);
}

static void set_cpu_nsc( i386_cpu_info_t * info_p )
{
    set_cpu_generic(info_p);
    set_amd_cache_info(info_p);

    if (info_p->cpuid_family == CPUID_FAMILY_586 && info_p->cpuid_model == CPUID_MODEL_GX1)
        info_p->cpuid_model_string = "AMD Geode GX1";
    else if (info_p->cpuid_family == CPUID_FAMILY_586 && info_p->cpuid_model == CPUID_MODEL_GX2)
        info_p->cpuid_model_string = "AMD Geode GX";
    else
        info_p->cpuid_model_string = "Unknown National Semiconductor";
}

static void
set_cpu_generic(i386_cpu_info_t *info_p)
{
	uint32_t	cpuid_result[4];
	uint32_t	max_extid;
        char            str[128], *p;

	/* get extended cpuid results */
	do_cpuid(0x80000000, cpuid_result);
	max_extid = cpuid_result[0];

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
	info_p->cpuid_signature =  cpuid_result[0];
	info_p->cpuid_stepping  =  cpuid_result[0]        & 0x0f;
	info_p->cpuid_model     = (cpuid_result[0] >> 4)  & 0x0f;
	info_p->cpuid_family    = (cpuid_result[0] >> 8)  & 0x0f;
	info_p->cpuid_type      = (cpuid_result[0] >> 12) & 0x03;
	info_p->cpuid_extmodel  = (cpuid_result[0] >> 16) & 0x0f;
	info_p->cpuid_extfamily = (cpuid_result[0] >> 20) & 0xff;
	info_p->cpuid_brand     =  cpuid_result[1]        & 0xff;
	info_p->cpuid_features  =  cpuid_result[3];

	return;
}

static void
set_cpu_unknown(__unused i386_cpu_info_t *info_p)
{
    info_p->cpuid_model_string = "Unknown";
}


static struct {
	uint32_t	mask;
	const char	*name;
} feature_names[] = {
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
	{0, 0}
};

char *
cpuid_get_feature_names(uint32_t feature, char *buf, unsigned buf_len)
{
	int	i;
	int	len;
	char	*p = buf;

	for (i = 0; feature_names[i].mask != 0; i++) {
		if ((feature & feature_names[i].mask) == 0)
			continue;
		if (i > 0)
			*p++ = ' ';
		len = min(strlen(feature_names[i].name), (buf_len-1) - (p-buf));
		if (len == 0)
			break;
		bcopy(feature_names[i].name, p, len);
		p += len;
	}
	*p = '\0';
	return buf;
}

void
cpuid_feature_display(
	const char	*header,
	__unused int	my_cpu)
{
	char	buf[256];

	printf("%s: %s\n", header,
		  cpuid_get_feature_names(cpuid_features(), buf, sizeof(buf)));
}

void
cpuid_cpu_display(
	const char	*header,
	__unused int	my_cpu)
{
    if (cpuid_cpu_info.cpuid_brand_string[0] != '\0') {
	printf("%s: %s\n", header,
               cpuid_cpu_info.cpuid_brand_string);
    }
}

unsigned int
cpuid_family(void)
{
	return cpuid_cpu_info.cpuid_family;
}

unsigned int
cpuid_features(void)
{
	static int checked = 0;
	char	fpu_arg[16] = { 0 };
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

i386_cpu_info_t	*
cpuid_info(void)
{
	return &cpuid_cpu_info;
}

/* XXX for temporary compatibility */
void
set_cpu_model(void)
{
	cpuid_get_info(&cpuid_cpu_info);
	cpuid_feature = cpuid_cpu_info.cpuid_features;	/* XXX compat */
}

