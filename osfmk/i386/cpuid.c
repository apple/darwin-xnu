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

/*
 * Values from http://einstein.et.tudelft.nl/~offerman/chiplist.html
 * (dated 18 Oct 1995)
 */

#include <kern/misc_protos.h>
#include <i386/cpuid.h>

/*
 * Generic product array (before CPUID)
 */
unsigned int cpuid_i386_freq[] = { 12, 16, 20, 25, 33, 0 };
unsigned int cpuid_i486_freq[] = { 20, 25, 33, 50, 0 };

struct cpuid_product cpuid_generic[] = {
    {
	0,		CPUID_FAMILY_386,	0,
	80,	cpuid_i386_freq,		"i386"
    },
    {
	0,		CPUID_FAMILY_486,	0,
	240,	cpuid_i486_freq,		"i486"
    },
};

/*
 * INTEL product array
 */
unsigned int cpuid_i486_dx_freq[] = { 20, 25, 33, 0 };
unsigned int cpuid_i486_dx_s_freq[] = { 50, 0 };
unsigned int cpuid_i486_sx_freq[] = { 16, 20, 25, 33, 0 };
unsigned int cpuid_i486_dx2_freq[] = { 32, 40, 50, 66, 0 };
unsigned int cpuid_i486_sl_freq[] = { 25, 33, 0 };
unsigned int cpuid_i486_sx2_freq[] = { 50, 0 };
unsigned int cpuid_i486_dx2wb_freq[] = { 50, 66, 0 };
unsigned int cpuid_i486_dx4_freq[] = { 90, 100, 0 };

unsigned int cpuid_i486_dx2wb_od_freq[] = { 32, 40, 50, 66, 0 };
unsigned int cpuid_i486_dx4_od_freq[] = { 75, 99, 0 };

unsigned int cpuid_p5_freq[] = { 60, 66, 0 };
unsigned int cpuid_p54_freq[] = { 60, 66, 75, 90, 100, 120, 133, 166, 200, 0 };

unsigned int cpuid_p24t_freq[] = { 25, 33, 0 };
unsigned int cpuid_p24ct_freq[] = { 63, 83, 0 };

unsigned int cpuid_pii_freq[] = { 300, 0 };

struct cpuid_product cpuid_intel[] = {
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_486,	CPUID_MODEL_I486_DX,
	240,	cpuid_i486_dx_freq,		"Intel 486DX"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_486,	CPUID_MODEL_I486_DX_S,
	240,	cpuid_i486_dx_s_freq,		"Intel 486DX-S"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_486,	CPUID_MODEL_I486_SX,
	240,	cpuid_i486_sx_freq,		"Intel 486SX"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_486,	CPUID_MODEL_I486_DX2,
	240,	cpuid_i486_dx2_freq,		"Intel 486DX2"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_486,	CPUID_MODEL_I486_SL,
	240,	cpuid_i486_sl_freq,		"Intel 486SL"
    },
    {  
	CPUID_TYPE_OEM,		CPUID_FAMILY_486,	CPUID_MODEL_I486_SX2,
	240,	cpuid_i486_sx2_freq,		"Intel 486SX2"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_486,	CPUID_MODEL_I486_DX2WB,
	240,	cpuid_i486_dx2wb_freq,		"Intel 486DX2WB"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_486,	CPUID_MODEL_I486_DX4,
	240,	cpuid_i486_dx4_freq,		"Intel 486DX4"
    },
    {
	CPUID_TYPE_OVERDRIVE,	CPUID_FAMILY_486,	CPUID_MODEL_I486_DX2,
	240,	cpuid_i486_dx2_freq,		"Intel 486DX2 OverDrive"
    },
    {
	CPUID_TYPE_OVERDRIVE,	CPUID_FAMILY_486,	CPUID_MODEL_I486_DX2WB,
	240,	cpuid_i486_dx2wb_od_freq,	"Intel 486DX2WB OverDrive"
    },
    {
	CPUID_TYPE_OVERDRIVE,	CPUID_FAMILY_486,	CPUID_MODEL_I486_DX4,
	240,	cpuid_i486_dx4_od_freq,		"Intel 486DX4 OverDrive"
    },
    {
	CPUID_TYPE_OVERDRIVE,	CPUID_FAMILY_P5,	CPUID_MODEL_P24T,
	208,	cpuid_p24t_freq,		"Intel Pentium P24T OverDrive"
    },
    {
	CPUID_TYPE_OVERDRIVE,	CPUID_FAMILY_P5,	CPUID_MODEL_P54,
	207,	cpuid_p24ct_freq,		"Intel Pentium P24CT OverDrive"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_P5,	CPUID_MODEL_P5A,
	207,	cpuid_p5_freq,			"Intel Pentium P5 rev A"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_P5,	CPUID_MODEL_P5,
	207,	cpuid_p5_freq,			"Intel Pentium P5"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_P5,	CPUID_MODEL_P54,
	207,	cpuid_p54_freq,			"Intel Pentium P54"
    },
    {
	CPUID_TYPE_OEM,		CPUID_FAMILY_PPRO,	CPUID_MODEL_PII,
	480,	cpuid_pii_freq,			"Intel Pentium II"
    }
};
unsigned int cpuid_intel_size = sizeof (cpuid_intel) / sizeof (cpuid_intel[0]);

/*
 * AMD product arrays
 */
unsigned int cpuid_am486_dx_freq[] = { 33, 40, 0 };
unsigned int cpuid_am486_dx2_freq[] = { 50, 66, 80, 99, 0 };
unsigned int cpuid_am486_dx4_freq[] = { 99, 120, 133, 0 };
unsigned int cpuid_am486_dx4wb_freq[] = { 99, 120, 133, 0 };

/*
 * UMC product array 
 */
unsigned int cpuid_u5sd_freq[] = { 25, 33, 40, 0 };
unsigned int cpuid_u5s_freq[] = { 25, 33, 40, 0 };

/*
 * Vendor ID array
 */
struct cpuid_name cpuid_name[] = {
    {	CPUID_VID_INTEL,
	cpuid_intel,	sizeof (cpuid_intel) / sizeof (cpuid_intel[0])
    },
    {	CPUID_VID_UMC,
	(struct cpuid_product *)0,
    },
    {	CPUID_VID_AMD,
	(struct cpuid_product *)0,
    },
    {	CPUID_VID_CYRIX,
	(struct cpuid_product *)0,
    },
    {	CPUID_VID_NEXTGEN,
	(struct cpuid_product *)0
    },
    {	"",
	cpuid_generic,	sizeof (cpuid_generic) / sizeof (cpuid_generic[0])
    },
    {	(char *)0,
    }
};

/*
 * Feature Flag values
 */
char *cpuid_flag[] = {
    "FPU",	/* Floating point unit on-chip */
    "VME",	/* Virtual Mode Extension */
    "DE",	/* Debugging Extension */
    "PSE",	/* Page Size Extension */
    "TSC",	/* Time Stamp Counter */
    "MSR",	/* Model Specific Registers */
    "PAE",	/* Physical Address Extension */
    "MCE",	/* Machine Check Exception */
    "CX8",	/* CMPXCHG8 Instruction sSupported */
    "APIC",	/* Local APIC Supported */
    "(bit 10)",
    "(bit 11)",
    "MTRR",	/* Machine Type Range Register */
    "PGE",	/* Page Global Enable */
    "MCA",	/* Machine Check Architecture */
    "CMOV",	/* Conditional Move Instruction Supported */
    "(bit 16)",
    "(bit 17)",
    "(bit 18)",
    "(bit 19)",
    "(bit 20)",
    "(bit 21)",
    "(bit 22)",
    "MMX",	/* Supports MMX instructions */
    "(bit 24)",
    "(bit 25)",
    "(bit 26)",
    "(bit 27)",
    "(bit 28)",
    "(bit 29)",
    "(bit 30)",
    "(bit 31)",
};

/*
 * Cache description array
 */
struct cpuid_cache_desc cpuid_cache_desc[] = {
    {	CPUID_CACHE_ITLB_4K,
	"Instruction TBL, 4K, pages 4-way set associative, 64 entries"
    },
    {	CPUID_CACHE_ITLB_4M,
	"Instruction TBL, 4M, pages 4-way set associative, 4 entries"
    },
    {	CPUID_CACHE_DTLB_4K,
	"Data TBL, 4K pages, 4-way set associative, 64 entries"
    },
    {	CPUID_CACHE_DTLB_4M,
	"Data TBL, 4M pages, 4-way set associative, 4 entries"
    },
    {	CPUID_CACHE_ICACHE_8K,
	"Instruction L1 cache, 8K, 4-way set associative, 32byte line size"
    },
    {	CPUID_CACHE_DCACHE_8K,
	"Data L1 cache, 8K, 2-way set associative, 32byte line size"
    },
    {	CPUID_CACHE_UCACHE_128K,
	"Unified L2 cache, 128K, 4-way set associative, 32byte line size"
    },
    {	CPUID_CACHE_UCACHE_256K,
	"Unified L2 cache, 256K, 4-way set associative, 32byte line size"
    },
    {	CPUID_CACHE_UCACHE_512K,
	"Unified L2 cache, 512K, 4-way set associative, 32byte line size"
    },
    {	CPUID_CACHE_NULL,
	(char *)0
    }
};
    
/*
 * CPU identification
 */
unsigned int	cpuid_value;
unsigned char	cpuid_type;
unsigned char	cpuid_family;
unsigned char	cpuid_model;
unsigned char	cpuid_stepping;
unsigned int	cpuid_feature;
char		cpuid_vid[CPUID_VID_SIZE + 1];
unsigned char	cpuid_cache[CPUID_CACHE_SIZE];

/*
 * Return correct CPU_TYPE
 */
/*ARGSUSED*/
cpu_type_t
cpuid_cputype(
    int my_cpu)
{
#ifndef MACH_BSD	/* FIXME  - add more family/chip types */
    switch (cpuid_family) {
    case CPUID_FAMILY_PPRO:
	return (CPU_TYPE_PENTIUMPRO);
    case CPUID_FAMILY_P5:
	return (CPU_TYPE_PENTIUM);
    case CPUID_FAMILY_486:
	return (CPU_TYPE_I486);
    default:
	break;
    }
#endif
    return (CPU_TYPE_I386);
}

/*
 * Display processor signature
 */
/*ARGSUSED*/
void
cpuid_cpu_display(
    char *header,
    int my_cpu)
{
    struct cpuid_name *name;
    unsigned int i;
    unsigned int *freq;
    unsigned int mhz;
    unsigned int feature;
    char **flag;
    extern unsigned int delaycount;

    /*
     * Identify vendor ID
     */
    for (name = cpuid_name; name->name != (char *)0; name++) {
	char *p = name->name;
	char *q = cpuid_vid;
	while (*p == *q && *p != 0) {
	    p++;
	    q++;
	}
	if (*p == '\0' && *q == '\0')
	    break;
    }
    if (name->name == (char *)0) {
	printf("Unrecognized processor vendor id = '%s'\n", cpuid_vid);
	return;
    }

    /*
     * Identify Product ID
     */
    for (i = 0; i < name->size; i++)
	if (name->product[i].type == cpuid_type &&
	    name->product[i].family == cpuid_family &&
	    name->product[i].model == cpuid_model)
	    break;
    if (i == name->size) {
	printf("%s processor (type = 0x%x, family = 0x%x, model = 0x%x)\n",
	       "Unrecognized", cpuid_type, cpuid_family, cpuid_model);
	return;
    }

    /*
     * Look for frequency and adjust it to known values
     */
    mhz = (1000 * delaycount) / name->product[i].delay;
    for (freq = name->product[i].frequency; *freq != 0; freq++)
	if (*freq >= mhz)
	    break;
    if (*freq == 0)
	mhz = *(freq - 1);
    else if (freq == name->product[i].frequency)
	mhz = *freq;
    else if (*freq - mhz > mhz - *(freq - 1))
	mhz = *(freq - 1);
    else if (*freq != mhz)
	mhz = *freq;

    /*
     * Display product and frequency
     */
    printf("%s: %s at %d MHz (signature = %d/%d/%d/%d)\n",
	   header, name->product[i].name, mhz, cpuid_type,
	   cpuid_family, cpuid_model, cpuid_stepping);

    /*
     * Display feature (if any)
     */
    if (cpuid_feature) {
	i = 0;
	flag = cpuid_flag;
	for (feature = cpuid_feature; feature != 0; feature >>= 1) {
	    if (feature & 1)
		if (i == 0) {
		    printf("%s: %s", header, *flag);
		    i = 1;
		} else 
		    printf(", %s", *flag);
	    flag++;
	}
	printf("\n");
    }
}

/*
 * Display processor configuration information
 */
/*ARGSUSED*/
void
cpuid_cache_display(
    char *header,
    int my_cpu)
{
    struct cpuid_cache_desc *desc;
    unsigned int i;

    if (cpuid_cache[CPUID_CACHE_VALID] == 1)
	for (i = 0; i < CPUID_CACHE_SIZE; i++) {
	    if (i != CPUID_CACHE_VALID || cpuid_cache[i] == CPUID_CACHE_NULL)
		continue;
	    for (desc = cpuid_cache_desc;
		 desc->description != (char *)0; desc++)
		if (desc->value == cpuid_cache[i])
		    break;
	    if (desc->description != (char *)0)
		printf("%s: %s\n", header, desc->description);
	}
}
