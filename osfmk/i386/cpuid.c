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
#include <platforms.h>
#include <mach_kdb.h>
#include <vm/vm_page.h>
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
 */

static i386_cpu_info_t	*cpuid_cpu_infop = NULL;
static i386_cpu_info_t	cpuid_cpu_info;

/* this function is Intel-specific */
static void
cpuid_set_cache_info( i386_cpu_info_t * info_p )
{
	uint32_t	cpuid_result[4];
	uint32_t	reg[4];
	uint32_t	index;
	uint32_t	linesizes[LCACHE_MAX];
	unsigned int	i;
	unsigned int	j;
	boolean_t	cpuid_deterministic_supported = FALSE;

	bzero( linesizes, sizeof(linesizes) );

	/* Get processor cache descriptor info using leaf 2.  We don't use
	 * this internally, but must publish it for KEXTs.
	 */
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

	/*
	 * Get cache info using leaf 4, the "deterministic cache parameters."
	 * Most processors Mac OS X supports implement this flavor of CPUID.
	 * Loop over each cache on the processor.
	 */
	do_cpuid(0, cpuid_result);
	if (cpuid_result[eax] >= 4)
		cpuid_deterministic_supported = TRUE;

	for (index = 0; cpuid_deterministic_supported; index++) {
		cache_type_t	type = Lnone;
		uint32_t	cache_type;
		uint32_t	cache_level;
		uint32_t	cache_sharing;
		uint32_t	cache_linesize;
		uint32_t	cache_sets;
		uint32_t	cache_associativity;
		uint32_t	cache_size;
		uint32_t	cache_partitions;
		uint32_t	colors;
		
		reg[eax] = 4;		/* cpuid request 4 */
		reg[ecx] = index;	/* index starting at 0 */
		cpuid(reg);
//kprintf("cpuid(4) index=%d eax=%p\n", index, reg[eax]);
		cache_type = bitfield(reg[eax], 4, 0);
		if (cache_type == 0)
			break;		/* no more caches */
		cache_level  		= bitfield(reg[eax],  7,  5);
		cache_sharing	 	= bitfield(reg[eax], 25, 14) + 1;
		info_p->cpuid_cores_per_package 
					= bitfield(reg[eax], 31, 26) + 1;
		cache_linesize		= bitfield(reg[ebx], 11,  0) + 1;
		cache_partitions	= bitfield(reg[ebx], 21, 12) + 1;
		cache_associativity	= bitfield(reg[ebx], 31, 22) + 1;
		cache_sets 		= bitfield(reg[ecx], 31,  0) + 1;
				
		/* Map type/levels returned by CPUID into cache_type_t */
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
			break;
		default:
			type = Lnone;
		}
		
		/* The total size of a cache is:
		 *	( linesize * sets * associativity )
		 */
		if (type != Lnone) {
			cache_size = cache_linesize * cache_sets * cache_associativity;
			info_p->cache_size[type] = cache_size;
			info_p->cache_sharing[type] = cache_sharing;
			info_p->cache_partitions[type] = cache_partitions;
			linesizes[type] = cache_linesize;
			
			/* Compute the number of page colors for this cache,
			 * which is:
			 *	( linesize * sets ) / page_size
			 *
			 * To help visualize this, consider two views of a
			 * physical address.  To the cache, it is composed
			 * of a line offset, a set selector, and a tag.
			 * To VM, it is composed of a page offset, a page
			 * color, and other bits in the pageframe number:
			 *
			 *           +-----------------+---------+--------+
			 *  cache:   |       tag       |   set   | offset |
			 *           +-----------------+---------+--------+
			 *
			 *           +-----------------+-------+----------+
			 *  VM:      |    don't care   | color | pg offset|
			 *           +-----------------+-------+----------+
			 *
			 * The color is those bits in (set+offset) not covered
			 * by the page offset.
			 */
			 colors = ( cache_linesize * cache_sets ) >> 12;
			 
			 if ( colors > vm_cache_geometry_colors )
				vm_cache_geometry_colors = colors;
		}
	} 
	
	/*
	 * If deterministic cache parameters are not available, use
	 * something else
	 */
	if (info_p->cpuid_cores_per_package == 0) {
		info_p->cpuid_cores_per_package = 1;

		/* cpuid define in 1024 quantities */
		info_p->cache_size[L2U] = info_p->cpuid_cache_size * 1024;
		info_p->cache_sharing[L2U] = 1;
		info_p->cache_partitions[L2U] = 1;

		linesizes[L2U] = info_p->cpuid_cache_linesize;
	}
	
	/*
	 * What linesize to publish?  We use the L2 linesize if any,
	 * else the L1D.
	 */
	if ( linesizes[L2U] )
		info_p->cache_linesize = linesizes[L2U];
	else if (linesizes[L1D])
		info_p->cache_linesize = linesizes[L1D];
	else panic("no linesize");
}

static void
cpuid_set_generic_info(i386_cpu_info_t *info_p)
{
	uint32_t	cpuid_reg[4];
	uint32_t	max_extid;
        char            str[128], *p;

	/* do cpuid 0 to get vendor */
	do_cpuid(0, cpuid_reg);
	bcopy((char *)&cpuid_reg[ebx], &info_p->cpuid_vendor[0], 4); /* ug */
	bcopy((char *)&cpuid_reg[ecx], &info_p->cpuid_vendor[8], 4);
	bcopy((char *)&cpuid_reg[edx], &info_p->cpuid_vendor[4], 4);
	info_p->cpuid_vendor[12] = 0;

	/* get extended cpuid results */
	do_cpuid(0x80000000, cpuid_reg);
	max_extid = cpuid_reg[eax];

	/* check to see if we can get brand string */
	if (max_extid >= 0x80000004) {
		/*
		 * The brand string 48 bytes (max), guaranteed to
		 * be NUL terminated.
		 */
		do_cpuid(0x80000002, cpuid_reg);
		bcopy((char *)cpuid_reg, &str[0], 16);
		do_cpuid(0x80000003, cpuid_reg);
		bcopy((char *)cpuid_reg, &str[16], 16);
		do_cpuid(0x80000004, cpuid_reg);
		bcopy((char *)cpuid_reg, &str[32], 16);
		for (p = str; *p != '\0'; p++) {
			if (*p != ' ') break;
		}
		strlcpy(info_p->cpuid_brand_string,
			p, sizeof(info_p->cpuid_brand_string));

                if (!strncmp(info_p->cpuid_brand_string, CPUID_STRING_UNKNOWN,
			     min(sizeof(info_p->cpuid_brand_string),
				 strlen(CPUID_STRING_UNKNOWN) + 1))) {
                    /*
                     * This string means we have a firmware-programmable brand string,
                     * and the firmware couldn't figure out what sort of CPU we have.
                     */
                    info_p->cpuid_brand_string[0] = '\0';
                }
	}
    
	/* Get cache and addressing info. */
	if (max_extid >= 0x80000006) {
		do_cpuid(0x80000006, cpuid_reg);
		info_p->cpuid_cache_linesize   = bitfield(cpuid_reg[ecx], 7, 0);
		info_p->cpuid_cache_L2_associativity =
						 bitfield(cpuid_reg[ecx],15,12);
		info_p->cpuid_cache_size       = bitfield(cpuid_reg[ecx],31,16);
		do_cpuid(0x80000008, cpuid_reg);
		info_p->cpuid_address_bits_physical =
						 bitfield(cpuid_reg[eax], 7, 0);
		info_p->cpuid_address_bits_virtual =
						 bitfield(cpuid_reg[eax],15, 8);
	}

	/* get processor signature and decode */
	do_cpuid(1, cpuid_reg);
	info_p->cpuid_signature = cpuid_reg[eax];
	info_p->cpuid_stepping  = bitfield(cpuid_reg[eax],  3,  0);
	info_p->cpuid_model     = bitfield(cpuid_reg[eax],  7,  4);
	info_p->cpuid_family    = bitfield(cpuid_reg[eax], 11,  8);
	info_p->cpuid_type      = bitfield(cpuid_reg[eax], 13, 12);
	info_p->cpuid_extmodel  = bitfield(cpuid_reg[eax], 19, 16);
	info_p->cpuid_extfamily = bitfield(cpuid_reg[eax], 27, 20);
	info_p->cpuid_brand     = bitfield(cpuid_reg[ebx],  7,  0);
	info_p->cpuid_features  = quad(cpuid_reg[ecx], cpuid_reg[edx]);

	/* Fold extensions into family/model */
	if (info_p->cpuid_family == 0x0f)
		info_p->cpuid_family += info_p->cpuid_extfamily;
	if (info_p->cpuid_family == 0x0f || info_p->cpuid_family== 0x06)
		info_p->cpuid_model += (info_p->cpuid_extmodel << 4);

	if (info_p->cpuid_features & CPUID_FEATURE_HTT)
		info_p->cpuid_logical_per_package =
				bitfield(cpuid_reg[ebx], 23, 16);
	else
		info_p->cpuid_logical_per_package = 1;

	if (max_extid >= 0x80000001) {
		do_cpuid(0x80000001, cpuid_reg);
		info_p->cpuid_extfeatures =
				quad(cpuid_reg[ecx], cpuid_reg[edx]);
	}

	if (info_p->cpuid_extfeatures && CPUID_FEATURE_MONITOR) {
		/*
		 * Extract the Monitor/Mwait Leaf info:
		 */
		do_cpuid(5, cpuid_reg);
		info_p->cpuid_mwait_linesize_min = cpuid_reg[eax];
		info_p->cpuid_mwait_linesize_max = cpuid_reg[ebx];
		info_p->cpuid_mwait_extensions   = cpuid_reg[ecx];
		info_p->cpuid_mwait_sub_Cstates  = cpuid_reg[edx];

		/*
		 * And the thermal and Power Leaf while we're at it:
		 */
		do_cpuid(6, cpuid_reg);
		info_p->cpuid_thermal_sensor =
					bitfield(cpuid_reg[eax], 0, 0);
		info_p->cpuid_thermal_dynamic_acceleration =
					bitfield(cpuid_reg[eax], 1, 1);
		info_p->cpuid_thermal_thresholds =
					bitfield(cpuid_reg[ebx], 3, 0);
		info_p->cpuid_thermal_ACNT_MCNT =
					bitfield(cpuid_reg[ecx], 0, 0);

		/*
		 * And the Architectural Performance Monitoring Leaf:
		 */
		do_cpuid(0xa, cpuid_reg);
		info_p->cpuid_arch_perf_version =
					bitfield(cpuid_reg[eax], 7, 0);
		info_p->cpuid_arch_perf_number =
					bitfield(cpuid_reg[eax],15, 8);
		info_p->cpuid_arch_perf_width =
					bitfield(cpuid_reg[eax],23,16);
		info_p->cpuid_arch_perf_events_number =
					bitfield(cpuid_reg[eax],31,24);
		info_p->cpuid_arch_perf_events =
					cpuid_reg[ebx];
		info_p->cpuid_arch_perf_fixed_number =
					bitfield(cpuid_reg[edx], 4, 0);
		info_p->cpuid_arch_perf_fixed_width =
					bitfield(cpuid_reg[edx],12, 5);

	}

	return;
}

void
cpuid_set_info(void)
{
	bzero((void *)&cpuid_cpu_info, sizeof(cpuid_cpu_info));

	cpuid_set_generic_info(&cpuid_cpu_info);

	/* verify we are running on a supported CPU */
	if ((strncmp(CPUID_VID_INTEL, cpuid_cpu_info.cpuid_vendor,
		     min(strlen(CPUID_STRING_UNKNOWN) + 1,
			 sizeof(cpuid_cpu_info.cpuid_vendor)))) ||
	   (cpuid_cpu_info.cpuid_family != 6) ||
	   (cpuid_cpu_info.cpuid_model < 13))
		panic("Unsupported CPU");

	cpuid_cpu_info.cpuid_cpu_type = CPU_TYPE_X86;
	cpuid_cpu_info.cpuid_cpu_subtype = CPU_SUBTYPE_X86_ARCH1;

	cpuid_set_cache_info(&cpuid_cpu_info);

	cpuid_cpu_info.cpuid_model_string = ""; /* deprecated */
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
	{CPUID_FEATURE_SSSE3,   "SSSE3"},
	{CPUID_FEATURE_CID,     "CID"},
	{CPUID_FEATURE_CX16,    "CX16"},
	{CPUID_FEATURE_xTPR,    "TPR"},
	{CPUID_FEATURE_PDCM,    "PDCM"},
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
		cpuid_set_info();
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


#if CONFIG_NO_KPRINTF_STRINGS
void
cpuid_feature_display(
	__unused const char	*header)
{
}

void
cpuid_extfeature_display(
	__unused const char	*header)
{
}

void
cpuid_cpu_display(
	__unused const char	*header)
{
}
#else /* CONFIG_NO_KPRINTF_STRINGS */
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
    if (cpuid_cpu_info.cpuid_brand_string[0] != '\0') {
	kprintf("%s: %s\n", header, cpuid_cpu_info.cpuid_brand_string);
    }
}
#endif /* !CONFIG_NO_KPRINTF_STRINGS */

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
				if (!strncmp("387", fpu_arg, sizeof("387")) || !strncmp("mmx", fpu_arg, sizeof("mmx"))) {
					printf("no sse or sse2\n");
					cpuid_cpu_info.cpuid_features &= ~(CPUID_FEATURE_SSE | CPUID_FEATURE_SSE2 | CPUID_FEATURE_FXSR);
				} else if (!strncmp("sse", fpu_arg, sizeof("sse"))) {
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
