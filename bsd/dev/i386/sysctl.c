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
hw_cpu_sysctl SYSCTL_HANDLER_ARGS
{
    __unused struct sysctl_oid *unused_oidp = oidp;
    i386_cpu_info_t *cpu_info = cpuid_info();
    void *ptr = (uint8_t *)cpu_info + (uint32_t)arg1;
    int value;

    if (arg2 == -1) {
        ptr = *(char **)ptr;
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
hw_cpu_features SYSCTL_HANDLER_ARGS
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
hw_cpu_extfeatures SYSCTL_HANDLER_ARGS
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
hw_cpu_logical_per_package SYSCTL_HANDLER_ARGS
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

SYSCTL_NODE(_machdep, OID_AUTO, cpu, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"CPU info");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, vendor, CTLTYPE_STRING | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_vendor), 0,
	    hw_cpu_sysctl, "A", "CPU vendor");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand_string, CTLTYPE_STRING | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_brand_string), 0,
	    hw_cpu_sysctl, "A", "CPU brand string");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, family, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_family), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU family");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, model, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_model), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU model");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extmodel, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_extmodel), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU extended model");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfamily, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_extfamily), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU extended family");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, stepping, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_stepping), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU stepping");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, feature_bits, CTLTYPE_QUAD | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_features), sizeof(uint64_t),
	    hw_cpu_sysctl, "I", "CPU features");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfeature_bits, CTLTYPE_QUAD | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_extfeatures), sizeof(uint64_t),
	    hw_cpu_sysctl, "I", "CPU extended features");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, signature, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_signature), sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "CPU signature");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand, CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_brand), sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "CPU brand");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, features, CTLTYPE_STRING | CTLFLAG_RD, 
	    0, 0,
	    hw_cpu_features, "A", "CPU feature names");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfeatures, CTLTYPE_STRING | CTLFLAG_RD, 
	    0, 0,
	    hw_cpu_extfeatures, "A", "CPU extended feature names");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, logical_per_package,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    0, 0,
	    hw_cpu_logical_per_package, "I", "CPU logical cpus per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, cores_per_package,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_cores_per_package),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "CPU cores per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, microcode_version,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_microcode_version),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Microcode version number");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, mwait, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"mwait");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, linesize_min,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_mwait_linesize_min),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Monitor/mwait minimum line size");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, linesize_max,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_mwait_linesize_max),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Monitor/mwait maximum line size");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, extensions,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_mwait_extensions),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Monitor/mwait extensions");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, sub_Cstates,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_mwait_sub_Cstates),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Monitor/mwait sub C-states");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, thermal, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"thermal");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, sensor,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_thermal_sensor),
	    sizeof(boolean_t),
	    hw_cpu_sysctl, "I", "Thermal sensor present");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, dynamic_acceleration,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_thermal_dynamic_acceleration),
	    sizeof(boolean_t),
	    hw_cpu_sysctl, "I", "Dynamic Acceleration Technology");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, thresholds,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_thermal_thresholds),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of interrupt thresholds");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, ACNT_MCNT,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_thermal_ACNT_MCNT),
	    sizeof(boolean_t),
	    hw_cpu_sysctl, "I", "ACNT_MCNT capability");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, arch_perf, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"arch_perf");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, version,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_arch_perf_version),
	    sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "Architectural Performance Version Number");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, number,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_arch_perf_number),
	    sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "Number of counters per logical cpu");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, width,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_arch_perf_width),
	    sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "Bit width of counters");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, events_number,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_arch_perf_events_number),
	    sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "Number of monitoring events");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, events,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_arch_perf_events),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Bit vector of events");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, fixed_number,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_arch_perf_fixed_number),
	    sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "Number of fixed-function counters");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, fixed_width,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_arch_perf_fixed_width),
	    sizeof(uint8_t),
	    hw_cpu_sysctl, "I", "Bit-width of fixed-function counters");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, cache, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"cache");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, linesize,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_cache_linesize),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Cacheline size");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, L2_associativity,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_cache_L2_associativity),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "L2 cache associativity");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, size,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_cache_size),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Cache size (in Kbytes)");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, tlb, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"tlb");

SYSCTL_PROC(_machdep_cpu_tlb, OID_AUTO, inst_small,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_itlb_small),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of small page instruction TLBs");

SYSCTL_PROC(_machdep_cpu_tlb, OID_AUTO, data_small,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_dtlb_small),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of small page data TLBs");

SYSCTL_PROC(_machdep_cpu_tlb, OID_AUTO, inst_large,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_itlb_large),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of large page instruction TLBs");

SYSCTL_PROC(_machdep_cpu_tlb, OID_AUTO, data_large,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_dtlb_large),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of large page data TLBs");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, address_bits, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"address_bits");

SYSCTL_PROC(_machdep_cpu_address_bits, OID_AUTO, physical,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_address_bits_physical),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of physical address bits");

SYSCTL_PROC(_machdep_cpu_address_bits, OID_AUTO, virtual,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, cpuid_address_bits_virtual),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of virtual address bits");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, core_count,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, core_count),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of enabled cores per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, thread_count,
	    CTLTYPE_INT | CTLFLAG_RD, 
	    (void *)offsetof(i386_cpu_info_t, thread_count),
	    sizeof(uint32_t),
	    hw_cpu_sysctl, "I", "Number of enabled threads per package");


uint64_t pmap_pv_hashlist_walks;
uint64_t pmap_pv_hashlist_cnts;
uint32_t pmap_pv_hashlist_max;

/*extern struct sysctl_oid_list sysctl__machdep_pmap_children;*/

SYSCTL_NODE(_machdep, OID_AUTO, pmap, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"PMAP info");

SYSCTL_QUAD    (_machdep_pmap, OID_AUTO, hashwalks, CTLFLAG_RD | CTLFLAG_KERN, &pmap_pv_hashlist_walks, "");
SYSCTL_QUAD    (_machdep_pmap, OID_AUTO, hashcnts, CTLFLAG_RD | CTLFLAG_KERN, &pmap_pv_hashlist_cnts, "");
SYSCTL_INT     (_machdep_pmap, OID_AUTO, hashmax, CTLFLAG_RD | CTLFLAG_KERN, &pmap_pv_hashlist_max, 0, "");
