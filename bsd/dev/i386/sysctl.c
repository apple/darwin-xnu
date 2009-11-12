/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <string.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <i386/cpuid.h>
#include <i386/tsc.h>

static int
_i386_cpu_info SYSCTL_HANDLER_ARGS
{
    __unused struct sysctl_oid *unused_oidp = oidp;
    void *ptr = arg1;
    int value;

    if (arg2 == -1) {
        ptr = *(void **)ptr;
        arg2 = 0;
    }

    if (arg2 == 0 && ((char *)ptr)[0] == '\0') {
        return ENOENT;
    }

    if (arg2 == sizeof(uint8_t)) {
	value = (uint32_t) *(uint8_t *)ptr;
	ptr = &value;
	arg2 = sizeof(uint32_t);
    }
    return SYSCTL_OUT(req, ptr, arg2 ? (size_t) arg2 : strlen((char *)ptr)+1);
}

static int
i386_cpu_info SYSCTL_HANDLER_ARGS
{
    void *ptr = (uint8_t *)cpuid_info() + (uintptr_t)arg1;
    return _i386_cpu_info(oidp, ptr, arg2, req);
}

static int
i386_cpu_info_nonzero SYSCTL_HANDLER_ARGS
{
    void *ptr = (uint8_t *)cpuid_info() + (uintptr_t)arg1;
    int value = *(uint32_t *)ptr;

    if (value == 0)
        return ENOENT;

    return _i386_cpu_info(oidp, ptr, arg2, req);
}
static int
cpu_mwait SYSCTL_HANDLER_ARGS
{
    i386_cpu_info_t *cpu_info = cpuid_info();
    void *ptr = (uint8_t *)cpu_info->cpuid_mwait_leafp + (uintptr_t)arg1;
    if (cpu_info->cpuid_mwait_leafp == NULL)
        return ENOENT;
    return _i386_cpu_info(oidp, ptr, arg2, req);
}

static int
cpu_thermal SYSCTL_HANDLER_ARGS
{
    i386_cpu_info_t *cpu_info = cpuid_info();
    void *ptr = (uint8_t *)cpu_info->cpuid_thermal_leafp + (uintptr_t)arg1;
    if (cpu_info->cpuid_thermal_leafp == NULL)
        return ENOENT;
    return _i386_cpu_info(oidp, ptr, arg2, req);
}

static int
cpu_arch_perf SYSCTL_HANDLER_ARGS
{
    i386_cpu_info_t *cpu_info = cpuid_info();
    void *ptr = (uint8_t *)cpu_info->cpuid_arch_perf_leafp + (uintptr_t)arg1;
    if (cpu_info->cpuid_arch_perf_leafp == NULL)
        return ENOENT;
    return _i386_cpu_info(oidp, ptr, arg2, req);
}

static int
cpu_features SYSCTL_HANDLER_ARGS
{
    __unused struct sysctl_oid *unused_oidp = oidp;
    __unused void *unused_arg1 = arg1;
    __unused int unused_arg2 = arg2; 
    char buf[256];

    buf[0] = '\0';
    cpuid_get_feature_names(cpuid_features(), buf, sizeof(buf));

    return SYSCTL_OUT(req, buf, strlen(buf) + 1);
}

static int
cpu_extfeatures SYSCTL_HANDLER_ARGS
{
    __unused struct sysctl_oid *unused_oidp = oidp;
    __unused void *unused_arg1 = arg1;
    __unused int unused_arg2 = arg2; 
    char buf[256];

    buf[0] = '\0';
    cpuid_get_extfeature_names(cpuid_extfeatures(), buf, sizeof(buf));

    return SYSCTL_OUT(req, buf, strlen(buf) + 1);
}

static int
cpu_logical_per_package SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	i386_cpu_info_t *cpu_info = cpuid_info();

	if (!(cpuid_features() & CPUID_FEATURE_HTT))
		return ENOENT;

	return SYSCTL_OUT(req, &cpu_info->cpuid_logical_per_package,
			  sizeof(cpu_info->cpuid_logical_per_package));
}

static int
cpu_flex_ratio_desired SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	i386_cpu_info_t *cpu_info = cpuid_info();

	if (cpu_info->cpuid_model != 26)
		return ENOENT;

	return SYSCTL_OUT(req, &flex_ratio, sizeof(flex_ratio));
}

static int
cpu_flex_ratio_min SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	i386_cpu_info_t *cpu_info = cpuid_info();

	if (cpu_info->cpuid_model != 26)
		return ENOENT;

	return SYSCTL_OUT(req, &flex_ratio_min, sizeof(flex_ratio_min));
}

static int
cpu_flex_ratio_max SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	i386_cpu_info_t *cpu_info = cpuid_info();

	if (cpu_info->cpuid_model != 26)
		return ENOENT;

	return SYSCTL_OUT(req, &flex_ratio_max, sizeof(flex_ratio_max));
}

SYSCTL_NODE(_machdep, OID_AUTO, cpu, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"CPU info");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, max_basic, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_max_basic),sizeof(uint32_t),
	    i386_cpu_info, "IU", "Max Basic Information value");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, max_ext, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_max_ext), sizeof(uint32_t),
	    i386_cpu_info, "IU", "Max Extended Function Information value");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, vendor, CTLTYPE_STRING | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_vendor), 0,
	    i386_cpu_info, "A", "CPU vendor");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand_string, CTLTYPE_STRING | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_brand_string), 0,
	    i386_cpu_info, "A", "CPU brand string");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, family, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_family), sizeof(uint8_t),
	    i386_cpu_info, "I", "CPU family");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, model, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_model), sizeof(uint8_t),
	    i386_cpu_info, "I", "CPU model");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extmodel, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_extmodel), sizeof(uint8_t),
	    i386_cpu_info, "I", "CPU extended model");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfamily, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_extfamily), sizeof(uint8_t),
	    i386_cpu_info, "I", "CPU extended family");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, stepping, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_stepping), sizeof(uint8_t),
	    i386_cpu_info, "I", "CPU stepping");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, feature_bits, CTLTYPE_QUAD | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_features), sizeof(uint64_t),
	    i386_cpu_info, "IU", "CPU features");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfeature_bits, CTLTYPE_QUAD | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_extfeatures), sizeof(uint64_t),
	    i386_cpu_info, "IU", "CPU extended features");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, signature, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_signature), sizeof(uint32_t),
	    i386_cpu_info, "I", "CPU signature");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_brand), sizeof(uint8_t),
	    i386_cpu_info, "I", "CPU brand");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, features, CTLTYPE_STRING | CTLFLAG_RD, 
	    0, 0,
	    cpu_features, "A", "CPU feature names");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfeatures, CTLTYPE_STRING | CTLFLAG_RD, 
	    0, 0,
	    cpu_extfeatures, "A", "CPU extended feature names");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, logical_per_package,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    0, 0,
	    cpu_logical_per_package, "I", "CPU logical cpus per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, cores_per_package,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_cores_per_package),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "CPU cores per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, microcode_version,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_microcode_version),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "Microcode version number");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, mwait, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"mwait");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, linesize_min,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_mwait_leaf_t, linesize_min),
	    sizeof(uint32_t),
	    cpu_mwait, "I", "Monitor/mwait minimum line size");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, linesize_max,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_mwait_leaf_t, linesize_max),
	    sizeof(uint32_t),
	    cpu_mwait, "I", "Monitor/mwait maximum line size");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, extensions,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_mwait_leaf_t, extensions),
	    sizeof(uint32_t),
	    cpu_mwait, "I", "Monitor/mwait extensions");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, sub_Cstates,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_mwait_leaf_t, sub_Cstates),
	    sizeof(uint32_t),
	    cpu_mwait, "I", "Monitor/mwait sub C-states");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, thermal, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"thermal");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, sensor,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_thermal_leaf_t, sensor),
	    sizeof(boolean_t),
	    cpu_thermal, "I", "Thermal sensor present");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, dynamic_acceleration,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_thermal_leaf_t, dynamic_acceleration),
	    sizeof(boolean_t),
	    cpu_thermal, "I", "Dynamic Acceleration Technology (Turbo Mode)");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, thresholds,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_thermal_leaf_t, thresholds),
	    sizeof(uint32_t),
	    cpu_thermal, "I", "Number of interrupt thresholds");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, ACNT_MCNT,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_thermal_leaf_t, ACNT_MCNT),
	    sizeof(boolean_t),
	    cpu_thermal, "I", "ACNT_MCNT capability");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, arch_perf, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"arch_perf");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, version,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_arch_perf_leaf_t, version),
	    sizeof(uint8_t),
	    cpu_arch_perf, "I", "Architectural Performance Version Number");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, number,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_arch_perf_leaf_t, number),
	    sizeof(uint8_t),
	    cpu_arch_perf, "I", "Number of counters per logical cpu");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, width,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_arch_perf_leaf_t, width),
	    sizeof(uint8_t),
	    cpu_arch_perf, "I", "Bit width of counters");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, events_number,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_arch_perf_leaf_t, events_number),
	    sizeof(uint8_t),
	    cpu_arch_perf, "I", "Number of monitoring events");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, events,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_arch_perf_leaf_t, events),
	    sizeof(uint32_t),
	    cpu_arch_perf, "I", "Bit vector of events");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, fixed_number,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_arch_perf_leaf_t, fixed_number),
	    sizeof(uint8_t),
	    cpu_arch_perf, "I", "Number of fixed-function counters");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, fixed_width,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(cpuid_arch_perf_leaf_t, fixed_width),
	    sizeof(uint8_t),
	    cpu_arch_perf, "I", "Bit-width of fixed-function counters");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, cache, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"cache");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, linesize,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_cache_linesize),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "Cacheline size");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, L2_associativity,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_cache_L2_associativity),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "L2 cache associativity");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, size,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_cache_size),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "Cache size (in Kbytes)");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, tlb, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"tlb");
SYSCTL_NODE(_machdep_cpu_tlb, OID_AUTO, inst, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"inst");
SYSCTL_NODE(_machdep_cpu_tlb, OID_AUTO, data, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"data");

SYSCTL_PROC(_machdep_cpu_tlb_inst, OID_AUTO, small,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t,
			     cpuid_tlb[TLB_INST][TLB_SMALL][0]),
	    sizeof(uint32_t),
	    i386_cpu_info_nonzero, "I",
	    "Number of small page instruction TLBs");

SYSCTL_PROC(_machdep_cpu_tlb_data, OID_AUTO, small,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t,
			     cpuid_tlb[TLB_DATA][TLB_SMALL][0]),
	    sizeof(uint32_t),
	    i386_cpu_info_nonzero, "I",
	    "Number of small page data TLBs (1st level)");

SYSCTL_PROC(_machdep_cpu_tlb_data, OID_AUTO, small_level1,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t,
			     cpuid_tlb[TLB_DATA][TLB_SMALL][1]),
	    sizeof(uint32_t),
	    i386_cpu_info_nonzero, "I",
	    "Number of small page data TLBs (2nd level)");

SYSCTL_PROC(_machdep_cpu_tlb_inst, OID_AUTO, large,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t,
			     cpuid_tlb[TLB_INST][TLB_LARGE][0]),
	    sizeof(uint32_t),
	    i386_cpu_info_nonzero, "I",
	    "Number of large page instruction TLBs");

SYSCTL_PROC(_machdep_cpu_tlb_data, OID_AUTO, large,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t,
			     cpuid_tlb[TLB_DATA][TLB_LARGE][0]),
	    sizeof(uint32_t),
	    i386_cpu_info_nonzero, "I",
	    "Number of large page data TLBs (1st level)");

SYSCTL_PROC(_machdep_cpu_tlb_data, OID_AUTO, large_level1,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t,
			     cpuid_tlb[TLB_DATA][TLB_LARGE][1]),
	    sizeof(uint32_t),
	    i386_cpu_info_nonzero, "I",
	    "Number of large page data TLBs (2nd level)");

SYSCTL_PROC(_machdep_cpu_tlb, OID_AUTO, shared,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_stlb),
	    sizeof(uint32_t),
	    i386_cpu_info_nonzero, "I",
	    "Number of shared TLBs");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, address_bits, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"address_bits");

SYSCTL_PROC(_machdep_cpu_address_bits, OID_AUTO, physical,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_address_bits_physical),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "Number of physical address bits");

SYSCTL_PROC(_machdep_cpu_address_bits, OID_AUTO, virtual,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_address_bits_virtual),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "Number of virtual address bits");


SYSCTL_PROC(_machdep_cpu, OID_AUTO, core_count,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, core_count),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "Number of enabled cores per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, thread_count,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, thread_count),
	    sizeof(uint32_t),
	    i386_cpu_info, "I", "Number of enabled threads per package");

SYSCTL_NODE(_machdep_cpu, OID_AUTO, flex_ratio, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"Flex ratio");

SYSCTL_PROC(_machdep_cpu_flex_ratio, OID_AUTO, desired,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    0, 0,
	    cpu_flex_ratio_desired, "I", "Flex ratio desired (0 disabled)");

SYSCTL_PROC(_machdep_cpu_flex_ratio, OID_AUTO, min,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    0, 0,
	    cpu_flex_ratio_min, "I", "Flex ratio min (efficiency)");

SYSCTL_PROC(_machdep_cpu_flex_ratio, OID_AUTO, max,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    0, 0,
	    cpu_flex_ratio_max, "I", "Flex ratio max (non-turbo)");

uint64_t pmap_pv_hashlist_walks;
uint64_t pmap_pv_hashlist_cnts;
uint32_t pmap_pv_hashlist_max;
uint32_t pmap_kernel_text_ps = PAGE_SIZE;

/*extern struct sysctl_oid_list sysctl__machdep_pmap_children;*/

SYSCTL_NODE(_machdep, OID_AUTO, pmap, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"PMAP info");

SYSCTL_QUAD    (_machdep_pmap, OID_AUTO, hashwalks, CTLFLAG_RD | CTLFLAG_KERN, &pmap_pv_hashlist_walks, "");
SYSCTL_QUAD    (_machdep_pmap, OID_AUTO, hashcnts, CTLFLAG_RD | CTLFLAG_KERN, &pmap_pv_hashlist_cnts, "");
SYSCTL_INT     (_machdep_pmap, OID_AUTO, hashmax, CTLFLAG_RD | CTLFLAG_KERN, &pmap_pv_hashlist_max, 0, "");
SYSCTL_INT     (_machdep_pmap, OID_AUTO, kernel_text_ps, CTLFLAG_RD | CTLFLAG_KERN, &pmap_kernel_text_ps, 0, "");

SYSCTL_NODE(_machdep, OID_AUTO, memmap, CTLFLAG_RD|CTLFLAG_LOCKED, NULL, "physical memory map");

uint64_t firmware_Conventional_bytes = 0;
uint64_t firmware_RuntimeServices_bytes = 0;
uint64_t firmware_ACPIReclaim_bytes = 0;
uint64_t firmware_ACPINVS_bytes = 0;
uint64_t firmware_PalCode_bytes = 0;
uint64_t firmware_Reserved_bytes = 0;
uint64_t firmware_Unusable_bytes = 0;
uint64_t firmware_other_bytes = 0;

SYSCTL_QUAD(_machdep_memmap, OID_AUTO, Conventional, CTLFLAG_RD|CTLFLAG_LOCKED, &firmware_Conventional_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, RuntimeServices, CTLFLAG_RD|CTLFLAG_LOCKED, &firmware_RuntimeServices_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, ACPIReclaim, CTLFLAG_RD|CTLFLAG_LOCKED, &firmware_ACPIReclaim_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, ACPINVS, CTLFLAG_RD|CTLFLAG_LOCKED, &firmware_ACPINVS_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, PalCode, CTLFLAG_RD|CTLFLAG_LOCKED, &firmware_PalCode_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, Reserved, CTLFLAG_RD|CTLFLAG_LOCKED, &firmware_Reserved_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, Unusable, CTLFLAG_RD|CTLFLAG_LOCKED, &firmware_Unusable_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, Other, CTLFLAG_RD|CTLFLAG_LOCKED, &firmware_other_bytes, "");
