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
static void	set_cpu_intel(i386_cpu_info_t *);
static void	set_cpu_unknown(i386_cpu_info_t *);

struct {
	char	*vendor;
	void	(* func)(i386_cpu_info_t *);
} cpu_vendors[] = {
	{CPUID_VID_INTEL,	set_cpu_intel},
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
 * A useful model name string takes some decoding.
 */
char *
cpuid_intel_get_model_name(
	uint8_t		brand,
	uint8_t		family,
	uint8_t		model,
	uint32_t	signature)
{
	/* check for brand id */
	switch(brand) {
	    case 0:
		/* brand ID not supported; use alternate method. */
		switch(family) {
		    case CPUID_FAMILY_486:
			return "486";
		    case CPUID_FAMILY_P5:
			return "Pentium";
		    case CPUID_FAMILY_PPRO:
			switch(model) {
			    case CPUID_MODEL_P6:
				return "Pentium Pro";
			    case CPUID_MODEL_PII:
				return "Pentium II";
			    case CPUID_MODEL_P65:
			    case CPUID_MODEL_P66:
				return "Celeron";
			    case CPUID_MODEL_P67:
			    case CPUID_MODEL_P68:
			    case CPUID_MODEL_P6A:
			    case CPUID_MODEL_P6B:
				return "Pentium III";
			    default:
				return "Unknown P6 Family";
			}
		    case CPUID_FAMILY_PENTIUM4:
			return "Pentium 4";
		    default:
			return "Unknown Family";
   		}
	    case 0x01:
		return "Celeron";
	    case 0x02:
	    case 0x04:
		return "Pentium III";
	    case 0x03:
		if (signature == 0x6B1)
			return "Celeron";
		else
			return "Pentium III Xeon";
	    case 0x06:
		return "Mobile Pentium III";
	    case 0x07:
		return "Mobile Celeron";
	    case 0x08:
		if (signature >= 0xF20)
			return "Genuine Intel";
		else
			return "Pentium 4";
	    case 0x09:
		return "Pentium 4";
	    case 0x0b:
		return "Xeon";
	    case 0x0e:
	    case 0x0f:
		return "Mobile Pentium 4";
	    default:
		return "Unknown Pentium";
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
	"Instruction TLB, 4M, pages 4-way set associative, 4 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_4K, 	Lnone,	0,		0, \
	"Data TLB, 4K pages, 4-way set associative, 64 entries"),
CACHE_DESC(CPUID_CACHE_DTLB_4M, 	Lnone,	0,		0, \
	"Data TLB, 4M pages, 4-way set associative, 4 entries"),
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
CACHE_DESC(CPUID_CACHE_TRACE_12K,	L1I,	12*1024,	64, \
	"Trace cache, 12K-uop, 8-way set associative"),
CACHE_DESC(CPUID_CACHE_TRACE_12K,	L1I,	16*1024,	64, \
	"Trace cache, 16K-uop, 8-way set associative"),
CACHE_DESC(CPUID_CACHE_TRACE_12K,	L1I,	32*1024,	64, \
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
CACHE_DESC(CPUID_CACHE_NULL, Lnone, 0, 0, \
	(char *)0),
};

static void
set_cpu_intel(i386_cpu_info_t *info_p)
{
	uint32_t	cpuid_result[4];
	uint32_t	max_extid;
        char            str[128], *p;
	char		*model;
	int		i;
	int		j;

	/* get extended cpuid results */
	do_cpuid(0x80000000, cpuid_result);
	max_extid = cpuid_result[0];

	/* check to see if we can get brand string */
	if (max_extid > 0x80000000) {
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

	/* decode family/model/type */
	switch (info_p->cpuid_type) {
	    case CPUID_TYPE_OVERDRIVE:
		strcat(info_p->model_string, "Overdrive ");
		break;
	    case CPUID_TYPE_DUAL:
		strcat(info_p->model_string, "Dual ");
		break;
	}
	strcat(info_p->model_string,
	       cpuid_intel_get_model_name(info_p->cpuid_brand,
					  info_p->cpuid_family,
					  info_p->cpuid_model,
					  info_p->cpuid_signature));
	info_p->model_string[sizeof(info_p->model_string)-1] = '\0';

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
			break;
		}
	}
	/* For P-IIIs, L2 could be 256k or 512k but we can't tell */ 
	if (info_p->cache_size[L2U] == 0 &&
	    info_p->cpuid_family == 0x6 && info_p->cpuid_model == 0xb) {
		info_p->cache_size[L2U] = 256*1024;
		info_p->cache_linesize = 32;
	}

	return;
}

static void
set_cpu_unknown(i386_cpu_info_t *info_p)
{
	strcat(info_p->model_string, "Unknown");
}


static struct {
	uint32_t	mask;
	char		*name;
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
	char	*header,
	int	my_cpu)
{
	char	buf[256];

	printf("%s: %s\n", header,
		  cpuid_get_feature_names(cpuid_features(), buf, sizeof(buf)));
}

void
cpuid_cpu_display(
	char	*header,
	int	my_cpu)
{
	printf("%s: %s\n", header,
		(cpuid_cpu_info.cpuid_brand_string[0] != '\0') ?
			cpuid_cpu_info.cpuid_brand_string :
			cpuid_cpu_info.model_string);
}

unsigned int
cpuid_family(void)
{
	return cpuid_cpu_info.cpuid_family;
}

unsigned int
cpuid_features(void)
{
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

