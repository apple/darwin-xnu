/*
 * Copyright (c) 2003-2020 Apple Inc. All rights reserved.
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
#include <i386/rtclock_protos.h>
#include <i386/machine_routines.h>
#include <i386/pal_routines.h>
#include <i386/ucode.h>
#include <kern/clock.h>
#include <libkern/libkern.h>
#include <i386/lapic.h>
#include <i386/mp.h>
#include <kern/kalloc.h>


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
	return SYSCTL_OUT(req, ptr, arg2 ? (size_t) arg2 : strlen((char *)ptr) + 1);
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

	if (value == 0) {
		return ENOENT;
	}

	return _i386_cpu_info(oidp, ptr, arg2, req);
}
static int
cpu_mwait SYSCTL_HANDLER_ARGS
{
	i386_cpu_info_t *cpu_info = cpuid_info();
	void *ptr = (uint8_t *)cpu_info->cpuid_mwait_leafp + (uintptr_t)arg1;
	if (cpu_info->cpuid_mwait_leafp == NULL) {
		return ENOENT;
	}
	return _i386_cpu_info(oidp, ptr, arg2, req);
}

static int
cpu_thermal SYSCTL_HANDLER_ARGS
{
	i386_cpu_info_t *cpu_info = cpuid_info();
	void *ptr = (uint8_t *)cpu_info->cpuid_thermal_leafp + (uintptr_t)arg1;
	if (cpu_info->cpuid_thermal_leafp == NULL) {
		return ENOENT;
	}
	return _i386_cpu_info(oidp, ptr, arg2, req);
}

static int
cpu_arch_perf SYSCTL_HANDLER_ARGS
{
	i386_cpu_info_t *cpu_info = cpuid_info();
	void *ptr = (uint8_t *)cpu_info->cpuid_arch_perf_leafp + (uintptr_t)arg1;
	if (cpu_info->cpuid_arch_perf_leafp == NULL) {
		return ENOENT;
	}
	return _i386_cpu_info(oidp, ptr, arg2, req);
}

static int
cpu_xsave SYSCTL_HANDLER_ARGS
{
	i386_cpu_info_t *cpu_info = cpuid_info();
	void *ptr = (uint8_t *)cpu_info->cpuid_xsave_leafp + (uintptr_t)arg1;
	if (cpu_info->cpuid_xsave_leafp == NULL) {
		return ENOENT;
	}
	return _i386_cpu_info(oidp, ptr, arg2, req);
}


static int
cpu_features SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	char buf[512];

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
	char buf[512];

	buf[0] = '\0';
	cpuid_get_extfeature_names(cpuid_extfeatures(), buf, sizeof(buf));

	return SYSCTL_OUT(req, buf, strlen(buf) + 1);
}

static int
cpu_leaf7_features SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	char buf[512];

	uint64_t    leaf7_features = cpuid_info()->cpuid_leaf7_features;
	uint64_t    leaf7_extfeatures = cpuid_info()->cpuid_leaf7_extfeatures;
	if (leaf7_features == 0 && leaf7_extfeatures == 0) {
		return ENOENT;
	}

	buf[0] = '\0';
	cpuid_get_leaf7_feature_names(leaf7_features, buf, sizeof(buf));
	if (leaf7_extfeatures != 0) {
		strlcat(buf, " ", sizeof(buf));
		cpuid_get_leaf7_extfeature_names(leaf7_extfeatures, buf + strlen(buf),
		    (unsigned int)(sizeof(buf) - strlen(buf)));
	}

	return SYSCTL_OUT(req, buf, strlen(buf) + 1);
}

static int
cpu_logical_per_package SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	i386_cpu_info_t *cpu_info = cpuid_info();

	if (!(cpuid_features() & CPUID_FEATURE_HTT)) {
		return ENOENT;
	}

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

	if (cpu_info->cpuid_model != 26) {
		return ENOENT;
	}

	return SYSCTL_OUT(req, &flex_ratio, sizeof(flex_ratio));
}

static int
cpu_flex_ratio_min SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	i386_cpu_info_t *cpu_info = cpuid_info();

	if (cpu_info->cpuid_model != 26) {
		return ENOENT;
	}

	return SYSCTL_OUT(req, &flex_ratio_min, sizeof(flex_ratio_min));
}

static int
cpu_flex_ratio_max SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;
	i386_cpu_info_t *cpu_info = cpuid_info();

	if (cpu_info->cpuid_model != 26) {
		return ENOENT;
	}

	return SYSCTL_OUT(req, &flex_ratio_max, sizeof(flex_ratio_max));
}

static int
cpu_ucode_update SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t addr;
	int error;

	/* Can't update microcode from within a VM. */

	if (cpuid_features() & CPUID_FEATURE_VMM) {
		return ENODEV;
	}

	if (req->newptr == USER_ADDR_NULL) {
		return EINVAL;
	}

	error = SYSCTL_IN(req, &addr, sizeof(addr));
	if (error) {
		return error;
	}

	return ucode_interface(addr);
}

extern uint64_t panic_restart_timeout;
static int
panic_set_restart_timeout(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new_value = 0, old_value = 0, changed = 0, error;
	uint64_t nstime;

	if (panic_restart_timeout) {
		absolutetime_to_nanoseconds(panic_restart_timeout, &nstime);
		old_value = (int)MIN(nstime / NSEC_PER_SEC, INT_MAX);
	}

	error = sysctl_io_number(req, old_value, sizeof(old_value), &new_value, &changed);
	if (error == 0 && changed) {
		if (new_value >= 0) {
			nanoseconds_to_absolutetime(((uint64_t)new_value) * NSEC_PER_SEC, &panic_restart_timeout);
		} else {
			error = EDOM;
		}
	}
	return error;
}

/*
 * Populates the {CPU, vector, latency} triple for the maximum observed primary
 * interrupt latency
 */
static int
misc_interrupt_latency_max(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int changed = 0, error;
	char buf[128];
	buf[0] = '\0';

	interrupt_populate_latency_stats(buf, sizeof(buf));

	error = sysctl_io_string(req, buf, sizeof(buf), 0, &changed);

	if (error == 0 && changed) {
		interrupt_reset_latency_stats();
	}

	return error;
}

#if DEVELOPMENT || DEBUG
/*
 * Populates a string with each CPU's tsc synch delta.
 */
static int
x86_cpu_tsc_deltas(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int err;
	uint32_t ncpus = ml_wait_max_cpus();
	uint32_t buflen = (2 /* hex digits */ * sizeof(uint64_t) + 3 /* for "0x" + " " */) * ncpus + 1;
	char *buf = kalloc(buflen);

	cpu_data_tsc_sync_deltas_string(buf, buflen, 0, ncpus - 1);

	err = sysctl_io_string(req, buf, buflen, 0, 0);

	kfree(buf, buflen);

	return err;
}

/*
 * Triggers a machine-check exception - for a suitably configured kernel only.
 */
extern void mca_exception_panic(void);
static int
misc_machine_check_panic(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int changed = 0, error;
	char buf[128];
	buf[0] = '\0';

	error = sysctl_io_string(req, buf, sizeof(buf), 0, &changed);

	if (error == 0 && changed) {
		mca_exception_panic();
	}
	return error;
}

/*
 * Triggers a non-responsive processor timeout panic - for a suitably configured kernel only.
 */
static uint64_t kernel_timeout_spin = 0;
static int
misc_kernel_timeout_spin(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	uint64_t        old_value;
	uint64_t        new_value;
	int changed = 0, error;
	char buf[128];
	buf[0] = '\0';

	absolutetime_to_nanoseconds(kernel_timeout_spin, &old_value);

	error = sysctl_io_number(req, old_value, sizeof(uint64_t), &new_value, &changed);
	if (error == 0 && changed) {
		nanoseconds_to_absolutetime(((uint64_t)new_value), &kernel_timeout_spin);
		kernel_spin(kernel_timeout_spin);
	}
	return error;
}
#endif /* DEVELOPMENT || DEBUG */


SYSCTL_NODE(_machdep, OID_AUTO, cpu, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "CPU info");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, max_basic, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_max_basic), sizeof(uint32_t),
    i386_cpu_info, "IU", "Max Basic Information value");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, max_ext, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_max_ext), sizeof(uint32_t),
    i386_cpu_info, "IU", "Max Extended Function Information value");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, vendor, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_vendor), 0,
    i386_cpu_info, "A", "CPU vendor");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand_string, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_brand_string), 0,
    i386_cpu_info, "A", "CPU brand string");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, family, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_family), sizeof(uint8_t),
    i386_cpu_info, "I", "CPU family");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, model, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_model), sizeof(uint8_t),
    i386_cpu_info, "I", "CPU model");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extmodel, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_extmodel), sizeof(uint8_t),
    i386_cpu_info, "I", "CPU extended model");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfamily, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_extfamily), sizeof(uint8_t),
    i386_cpu_info, "I", "CPU extended family");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, stepping, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_stepping), sizeof(uint8_t),
    i386_cpu_info, "I", "CPU stepping");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, feature_bits, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_features), sizeof(uint64_t),
    i386_cpu_info, "IU", "CPU features");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, leaf7_feature_bits,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_leaf7_features),
    sizeof(uint64_t),
    i386_cpu_info_nonzero, "IU", "CPU Leaf7 features [EBX ECX]");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, leaf7_feature_bits_edx,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_leaf7_extfeatures),
    sizeof(uint32_t),
    i386_cpu_info_nonzero, "IU", "CPU Leaf7 features [EDX]");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfeature_bits, CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_extfeatures), sizeof(uint64_t),
    i386_cpu_info, "IU", "CPU extended features");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, signature, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_signature), sizeof(uint32_t),
    i386_cpu_info, "I", "CPU signature");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand, CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_brand), sizeof(uint8_t),
    i386_cpu_info, "I", "CPU brand");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, features, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0,
    cpu_features, "A", "CPU feature names");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, leaf7_features,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0,
    cpu_leaf7_features, "A", "CPU Leaf7 feature names");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, extfeatures, CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0,
    cpu_extfeatures, "A", "CPU extended feature names");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, logical_per_package,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0,
    cpu_logical_per_package, "I", "CPU logical cpus per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, cores_per_package,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_cores_per_package),
    sizeof(uint32_t),
    i386_cpu_info, "I", "CPU cores per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, microcode_version,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_microcode_version),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Microcode version number");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, processor_flag,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_processor_flag),
    sizeof(uint32_t),
    i386_cpu_info, "I", "CPU processor flag");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, mwait, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "mwait");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, linesize_min,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_mwait_leaf_t, linesize_min),
    sizeof(uint32_t),
    cpu_mwait, "I", "Monitor/mwait minimum line size");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, linesize_max,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_mwait_leaf_t, linesize_max),
    sizeof(uint32_t),
    cpu_mwait, "I", "Monitor/mwait maximum line size");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, extensions,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_mwait_leaf_t, extensions),
    sizeof(uint32_t),
    cpu_mwait, "I", "Monitor/mwait extensions");

SYSCTL_PROC(_machdep_cpu_mwait, OID_AUTO, sub_Cstates,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_mwait_leaf_t, sub_Cstates),
    sizeof(uint32_t),
    cpu_mwait, "I", "Monitor/mwait sub C-states");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, thermal, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "thermal");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, sensor,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, sensor),
    sizeof(boolean_t),
    cpu_thermal, "I", "Thermal sensor present");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, dynamic_acceleration,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, dynamic_acceleration),
    sizeof(boolean_t),
    cpu_thermal, "I", "Dynamic Acceleration Technology (Turbo Mode)");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, invariant_APIC_timer,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, invariant_APIC_timer),
    sizeof(boolean_t),
    cpu_thermal, "I", "Invariant APIC Timer");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, thresholds,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, thresholds),
    sizeof(uint32_t),
    cpu_thermal, "I", "Number of interrupt thresholds");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, ACNT_MCNT,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, ACNT_MCNT),
    sizeof(boolean_t),
    cpu_thermal, "I", "ACNT_MCNT capability");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, core_power_limits,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, core_power_limits),
    sizeof(boolean_t),
    cpu_thermal, "I", "Power Limit Notifications at a Core Level");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, fine_grain_clock_mod,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, fine_grain_clock_mod),
    sizeof(boolean_t),
    cpu_thermal, "I", "Fine Grain Clock Modulation");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, package_thermal_intr,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, package_thermal_intr),
    sizeof(boolean_t),
    cpu_thermal, "I", "Package Thermal interrupt and Status");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, hardware_feedback,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, hardware_feedback),
    sizeof(boolean_t),
    cpu_thermal, "I", "Hardware Coordination Feedback");

SYSCTL_PROC(_machdep_cpu_thermal, OID_AUTO, energy_policy,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_thermal_leaf_t, energy_policy),
    sizeof(boolean_t),
    cpu_thermal, "I", "Energy Efficient Policy Support");

SYSCTL_NODE(_machdep_cpu, OID_AUTO, xsave, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "xsave");

SYSCTL_PROC(_machdep_cpu_xsave, OID_AUTO, extended_state,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *) 0,
    sizeof(cpuid_xsave_leaf_t),
    cpu_xsave, "IU", "XSAVE Extended State Main Leaf");

SYSCTL_PROC(_machdep_cpu_xsave, OID_AUTO, extended_state1,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *) sizeof(cpuid_xsave_leaf_t),
    sizeof(cpuid_xsave_leaf_t),
    cpu_xsave, "IU", "XSAVE Extended State Sub-leaf 1");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, arch_perf, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "arch_perf");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, version,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_arch_perf_leaf_t, version),
    sizeof(uint8_t),
    cpu_arch_perf, "I", "Architectural Performance Version Number");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, number,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_arch_perf_leaf_t, number),
    sizeof(uint8_t),
    cpu_arch_perf, "I", "Number of counters per logical cpu");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, width,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_arch_perf_leaf_t, width),
    sizeof(uint8_t),
    cpu_arch_perf, "I", "Bit width of counters");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, events_number,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_arch_perf_leaf_t, events_number),
    sizeof(uint8_t),
    cpu_arch_perf, "I", "Number of monitoring events");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, events,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_arch_perf_leaf_t, events),
    sizeof(uint32_t),
    cpu_arch_perf, "I", "Bit vector of events");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, fixed_number,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_arch_perf_leaf_t, fixed_number),
    sizeof(uint8_t),
    cpu_arch_perf, "I", "Number of fixed-function counters");

SYSCTL_PROC(_machdep_cpu_arch_perf, OID_AUTO, fixed_width,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(cpuid_arch_perf_leaf_t, fixed_width),
    sizeof(uint8_t),
    cpu_arch_perf, "I", "Bit-width of fixed-function counters");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, cache, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "cache");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, linesize,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_cache_linesize),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Cacheline size");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, L2_associativity,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_cache_L2_associativity),
    sizeof(uint32_t),
    i386_cpu_info, "I", "L2 cache associativity");

SYSCTL_PROC(_machdep_cpu_cache, OID_AUTO, size,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_cache_size),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Cache size (in Kbytes)");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, tlb, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "tlb");
SYSCTL_NODE(_machdep_cpu_tlb, OID_AUTO, inst, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "inst");
SYSCTL_NODE(_machdep_cpu_tlb, OID_AUTO, data, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "data");

SYSCTL_PROC(_machdep_cpu_tlb_inst, OID_AUTO, small,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t,
    cpuid_tlb[TLB_INST][TLB_SMALL][0]),
    sizeof(uint32_t),
    i386_cpu_info_nonzero, "I",
    "Number of small page instruction TLBs");

SYSCTL_PROC(_machdep_cpu_tlb_data, OID_AUTO, small,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t,
    cpuid_tlb[TLB_DATA][TLB_SMALL][0]),
    sizeof(uint32_t),
    i386_cpu_info_nonzero, "I",
    "Number of small page data TLBs (1st level)");

SYSCTL_PROC(_machdep_cpu_tlb_data, OID_AUTO, small_level1,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t,
    cpuid_tlb[TLB_DATA][TLB_SMALL][1]),
    sizeof(uint32_t),
    i386_cpu_info_nonzero, "I",
    "Number of small page data TLBs (2nd level)");

SYSCTL_PROC(_machdep_cpu_tlb_inst, OID_AUTO, large,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t,
    cpuid_tlb[TLB_INST][TLB_LARGE][0]),
    sizeof(uint32_t),
    i386_cpu_info_nonzero, "I",
    "Number of large page instruction TLBs");

SYSCTL_PROC(_machdep_cpu_tlb_data, OID_AUTO, large,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t,
    cpuid_tlb[TLB_DATA][TLB_LARGE][0]),
    sizeof(uint32_t),
    i386_cpu_info_nonzero, "I",
    "Number of large page data TLBs (1st level)");

SYSCTL_PROC(_machdep_cpu_tlb_data, OID_AUTO, large_level1,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t,
    cpuid_tlb[TLB_DATA][TLB_LARGE][1]),
    sizeof(uint32_t),
    i386_cpu_info_nonzero, "I",
    "Number of large page data TLBs (2nd level)");

SYSCTL_PROC(_machdep_cpu_tlb, OID_AUTO, shared,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_stlb),
    sizeof(uint32_t),
    i386_cpu_info_nonzero, "I",
    "Number of shared TLBs");


SYSCTL_NODE(_machdep_cpu, OID_AUTO, address_bits, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "address_bits");

SYSCTL_PROC(_machdep_cpu_address_bits, OID_AUTO, physical,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_address_bits_physical),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Number of physical address bits");

SYSCTL_PROC(_machdep_cpu_address_bits, OID_AUTO, virtual,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_address_bits_virtual),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Number of virtual address bits");


SYSCTL_PROC(_machdep_cpu, OID_AUTO, core_count,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, core_count),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Number of enabled cores per package");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, thread_count,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, thread_count),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Number of enabled threads per package");

SYSCTL_NODE(_machdep_cpu, OID_AUTO, flex_ratio, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Flex ratio");

SYSCTL_PROC(_machdep_cpu_flex_ratio, OID_AUTO, desired,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0,
    cpu_flex_ratio_desired, "I", "Flex ratio desired (0 disabled)");

SYSCTL_PROC(_machdep_cpu_flex_ratio, OID_AUTO, min,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0,
    cpu_flex_ratio_min, "I", "Flex ratio min (efficiency)");

SYSCTL_PROC(_machdep_cpu_flex_ratio, OID_AUTO, max,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0,
    cpu_flex_ratio_max, "I", "Flex ratio max (non-turbo)");

SYSCTL_PROC(_machdep_cpu, OID_AUTO, ucupdate,
    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED, 0, 0,
    cpu_ucode_update, "S", "Microcode update interface");

SYSCTL_NODE(_machdep_cpu, OID_AUTO, tsc_ccc, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "TSC/CCC frequency information");

SYSCTL_PROC(_machdep_cpu_tsc_ccc, OID_AUTO, numerator,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_tsc_leaf.numerator),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Numerator of TSC/CCC ratio");

SYSCTL_PROC(_machdep_cpu_tsc_ccc, OID_AUTO, denominator,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(i386_cpu_info_t, cpuid_tsc_leaf.denominator),
    sizeof(uint32_t),
    i386_cpu_info, "I", "Denominator of TSC/CCC ratio");

static const uint32_t apic_timer_vector = (LAPIC_DEFAULT_INTERRUPT_BASE + LAPIC_TIMER_INTERRUPT);
static const uint32_t apic_IPI_vector = (LAPIC_DEFAULT_INTERRUPT_BASE + LAPIC_INTERPROCESSOR_INTERRUPT);

SYSCTL_NODE(_machdep, OID_AUTO, vectors, CTLFLAG_RD | CTLFLAG_LOCKED, 0,
    "Interrupt vector assignments");

SYSCTL_UINT(_machdep_vectors, OID_AUTO, timer, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, __DECONST(uint32_t *, &apic_timer_vector), 0, "");
SYSCTL_UINT(_machdep_vectors, OID_AUTO, IPI, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, __DECONST(uint32_t *, &apic_IPI_vector), 0, "");

uint64_t pmap_pv_hashlist_walks;
uint64_t pmap_pv_hashlist_cnts;
uint32_t pmap_pv_hashlist_max;
uint32_t pmap_kernel_text_ps = PAGE_SIZE;
extern uint32_t pv_hashed_kern_low_water_mark;

/*extern struct sysctl_oid_list sysctl__machdep_pmap_children;*/

SYSCTL_NODE(_machdep, OID_AUTO, pmap, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "PMAP info");

SYSCTL_QUAD(_machdep_pmap, OID_AUTO, hashwalks, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &pmap_pv_hashlist_walks, "");
SYSCTL_QUAD(_machdep_pmap, OID_AUTO, hashcnts, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &pmap_pv_hashlist_cnts, "");
SYSCTL_INT(_machdep_pmap, OID_AUTO, hashmax, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &pmap_pv_hashlist_max, 0, "");
SYSCTL_INT(_machdep_pmap, OID_AUTO, kernel_text_ps, CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED, &pmap_kernel_text_ps, 0, "");
SYSCTL_INT(_machdep_pmap, OID_AUTO, kern_pv_reserve, CTLFLAG_RW | CTLFLAG_KERN | CTLFLAG_LOCKED, &pv_hashed_kern_low_water_mark, 0, "");

SYSCTL_NODE(_machdep, OID_AUTO, memmap, CTLFLAG_RD | CTLFLAG_LOCKED, NULL, "physical memory map");

uint64_t firmware_Conventional_bytes = 0;
uint64_t firmware_RuntimeServices_bytes = 0;
uint64_t firmware_ACPIReclaim_bytes = 0;
uint64_t firmware_ACPINVS_bytes = 0;
uint64_t firmware_PalCode_bytes = 0;
uint64_t firmware_Reserved_bytes = 0;
uint64_t firmware_Unusable_bytes = 0;
uint64_t firmware_other_bytes = 0;

SYSCTL_QUAD(_machdep_memmap, OID_AUTO, Conventional, CTLFLAG_RD | CTLFLAG_LOCKED, &firmware_Conventional_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, RuntimeServices, CTLFLAG_RD | CTLFLAG_LOCKED, &firmware_RuntimeServices_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, ACPIReclaim, CTLFLAG_RD | CTLFLAG_LOCKED, &firmware_ACPIReclaim_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, ACPINVS, CTLFLAG_RD | CTLFLAG_LOCKED, &firmware_ACPINVS_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, PalCode, CTLFLAG_RD | CTLFLAG_LOCKED, &firmware_PalCode_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, Reserved, CTLFLAG_RD | CTLFLAG_LOCKED, &firmware_Reserved_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, Unusable, CTLFLAG_RD | CTLFLAG_LOCKED, &firmware_Unusable_bytes, "");
SYSCTL_QUAD(_machdep_memmap, OID_AUTO, Other, CTLFLAG_RD | CTLFLAG_LOCKED, &firmware_other_bytes, "");

SYSCTL_NODE(_machdep, OID_AUTO, tsc, CTLFLAG_RD | CTLFLAG_LOCKED, NULL, "Timestamp counter parameters");

SYSCTL_QUAD(_machdep_tsc, OID_AUTO, frequency,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tscFreq, "");

extern uint32_t deep_idle_rebase;
SYSCTL_UINT(_machdep_tsc, OID_AUTO, deep_idle_rebase,
    CTLFLAG_RD | CTLFLAG_LOCKED, &deep_idle_rebase, 0, "");
SYSCTL_QUAD(_machdep_tsc, OID_AUTO, at_boot,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tsc_at_boot, "");
SYSCTL_QUAD(_machdep_tsc, OID_AUTO, rebase_abs_time,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tsc_rebase_abs_time, "");
#if DEVELOPMENT || DEBUG
SYSCTL_PROC(_machdep_tsc, OID_AUTO, synch_deltas,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, x86_cpu_tsc_deltas, "A", "TSC synch deltas");
#endif

SYSCTL_NODE(_machdep_tsc, OID_AUTO, nanotime,
    CTLFLAG_RD | CTLFLAG_LOCKED, NULL, "TSC to ns conversion");
SYSCTL_QUAD(_machdep_tsc_nanotime, OID_AUTO, tsc_base,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    __DECONST(uint64_t *, &pal_rtc_nanotime_info.tsc_base), "");
SYSCTL_QUAD(_machdep_tsc_nanotime, OID_AUTO, ns_base,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    __DECONST(uint64_t *, &pal_rtc_nanotime_info.ns_base), "");
SYSCTL_UINT(_machdep_tsc_nanotime, OID_AUTO, scale,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    __DECONST(uint32_t *, &pal_rtc_nanotime_info.scale), 0, "");
SYSCTL_UINT(_machdep_tsc_nanotime, OID_AUTO, shift,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    __DECONST(uint32_t *, &pal_rtc_nanotime_info.shift), 0, "");
SYSCTL_UINT(_machdep_tsc_nanotime, OID_AUTO, generation,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    __DECONST(uint32_t *, &pal_rtc_nanotime_info.generation), 0, "");

SYSCTL_NODE(_machdep, OID_AUTO, misc, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Miscellaneous x86 kernel parameters");

#if (DEVELOPMENT || DEBUG)
extern uint32_t mp_interrupt_watchdog_events;
SYSCTL_UINT(_machdep_misc, OID_AUTO, interrupt_watchdog_events,
    CTLFLAG_RW | CTLFLAG_LOCKED, &mp_interrupt_watchdog_events, 0, "");

extern int insnstream_force_cacheline_mismatch;
SYSCTL_INT(_machdep_misc, OID_AUTO, insnstream_force_clmismatch,
    CTLFLAG_RW | CTLFLAG_LOCKED, &insnstream_force_cacheline_mismatch, 0, "");
#endif


SYSCTL_PROC(_machdep_misc, OID_AUTO, panic_restart_timeout,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0,
    panic_set_restart_timeout, "I", "Panic restart timeout in seconds");

SYSCTL_PROC(_machdep_misc, OID_AUTO, interrupt_latency_max,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0,
    misc_interrupt_latency_max, "A", "Maximum Interrupt latency");

extern boolean_t is_x2apic;
SYSCTL_INT(_machdep, OID_AUTO, x2apic_enabled,
    CTLFLAG_KERN | CTLFLAG_RD | CTLFLAG_LOCKED,
    &is_x2apic, 0, "");

#if DEVELOPMENT || DEBUG
SYSCTL_PROC(_machdep_misc, OID_AUTO, machine_check_panic,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0,
    misc_machine_check_panic, "A", "Machine-check exception test");

SYSCTL_PROC(_machdep_misc, OID_AUTO, kernel_timeout_spin,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, sizeof(kernel_timeout_spin),
    misc_kernel_timeout_spin, "Q", "Kernel timeout panic test");

SYSCTL_QUAD(_machdep, OID_AUTO, reportphyreadabs,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &reportphyreaddelayabs, "");
SYSCTL_QUAD(_machdep, OID_AUTO, reportphywriteabs,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &reportphywritedelayabs, "");
SYSCTL_QUAD(_machdep, OID_AUTO, tracephyreadabs,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tracephyreaddelayabs, "");
SYSCTL_QUAD(_machdep, OID_AUTO, tracephywriteabs,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tracephywritedelayabs, "");
SYSCTL_INT(_machdep, OID_AUTO, reportphyreadosbt,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &reportphyreadosbt, 0, "");
SYSCTL_INT(_machdep, OID_AUTO, reportphywriteosbt,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &reportphywriteosbt, 0, "");
SYSCTL_INT(_machdep, OID_AUTO, phyreaddelaypanic,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &phyreadpanic, 0, "");
SYSCTL_INT(_machdep, OID_AUTO, phywritedelaypanic,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &phywritepanic, 0, "");
#if DEVELOPMENT || DEBUG
extern uint64_t simulate_stretched_io;
SYSCTL_QUAD(_machdep, OID_AUTO, sim_stretched_io_ns,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &simulate_stretched_io, "");
#endif

extern int pmap_pagezero_mitigation;
extern int pmap_asserts_enabled, pmap_asserts_traced;
/* On DEV/DEBUG kernels, clear this to disable the SMAP emulation
 * (address space disconnect) for pagezero-less processes.
 */
SYSCTL_INT(_machdep, OID_AUTO, pmap_pagezero_mitigation,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &pmap_pagezero_mitigation, 0, "");
/* Toggle pmap assertions */
SYSCTL_INT(_machdep, OID_AUTO, pmap_asserts,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &pmap_asserts_enabled, 0, "");
/* Transform pmap assertions into kernel trace terminations */
SYSCTL_INT(_machdep, OID_AUTO, pmap_asserts_traced,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &pmap_asserts_traced, 0, "");

static int
misc_svisor_read(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	uint64_t new_value = 0, old_value = 0;
	int changed = 0, error;

	error = sysctl_io_number(req, old_value, sizeof(uint64_t), &new_value, &changed);
	if ((error == 0) && changed) {
		volatile uint32_t *raddr = (uint32_t *) new_value;
		printf("Supervisor: value at 0x%llx is 0x%x\n", new_value, *raddr);
	}
	return error;
}

SYSCTL_PROC(_machdep_misc, OID_AUTO, misc_svisor_read,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0,
    misc_svisor_read, "I", "supervisor mode read");

#endif /* DEVELOPMENT || DEBUG */

extern void timer_queue_trace_cpu(int);
static int
misc_timer_queue_trace(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int changed = 0, error;
	char buf[128];
	buf[0] = '\0';

	error = sysctl_io_string(req, buf, sizeof(buf), 0, &changed);

	if (error == 0 && changed) {
		timer_queue_trace_cpu(0);
	}
	return error;
}

SYSCTL_PROC(_machdep_misc, OID_AUTO, timer_queue_trace,
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0,
    misc_timer_queue_trace, "A", "Cut timer queue tracepoint");

extern long NMI_count;
extern void NMI_cpus(void);
static int
misc_nmis(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new = 0, old = 0, changed = 0, error;

	old = (int)MIN(NMI_count, INT_MAX);

	error = sysctl_io_number(req, old, sizeof(int), &new, &changed);
	if (error == 0 && changed) {
		NMI_cpus();
	}

	return error;
}

SYSCTL_PROC(_machdep_misc, OID_AUTO, nmis,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0,
    misc_nmis, "I", "Report/increment NMI count");

/* Parameters related to timer coalescing tuning, to be replaced
 * with a dedicated systemcall in the future.
 */
/* Enable processing pending timers in the context of any other interrupt */
SYSCTL_INT(_kern, OID_AUTO, interrupt_timer_coalescing_enabled,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &interrupt_timer_coalescing_enabled, 0, "");
/* Upon entering idle, process pending timers with HW deadlines
 * this far in the future.
 */
SYSCTL_INT(_kern, OID_AUTO, timer_coalesce_idle_entry_hard_deadline_max,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &idle_entry_timer_processing_hdeadline_threshold, 0, "");

/* Track potentially expensive eager timer evaluations on QoS tier
 * switches.
 */
extern uint32_t ml_timer_eager_evaluations;

SYSCTL_INT(_machdep, OID_AUTO, eager_timer_evaluations,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &ml_timer_eager_evaluations, 0, "");

extern uint64_t ml_timer_eager_evaluation_max;

SYSCTL_QUAD(_machdep, OID_AUTO, eager_timer_evaluation_max,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &ml_timer_eager_evaluation_max, "");
extern uint64_t x86_isr_fp_simd_use;
SYSCTL_QUAD(_machdep, OID_AUTO, x86_fp_simd_isr_uses,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &x86_isr_fp_simd_use, "");
#if DEVELOPMENT || DEBUG

extern int plctrace_enabled;

SYSCTL_INT(_machdep, OID_AUTO, pltrace,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &plctrace_enabled, 0, "");

/* Intentionally not declared as volatile here: */
extern int mmiotrace_enabled;

SYSCTL_INT(_machdep, OID_AUTO, MMIOtrace,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &mmiotrace_enabled, 0, "");

extern int fpsimd_fault_popc;
SYSCTL_INT(_machdep, OID_AUTO, fpsimd_fault_popc,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &fpsimd_fault_popc, 0, "");

volatile int stop_spinning;
static int
spin_in_the_kernel(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int new = 0, old = 0, changed = 0, error;

	error = sysctl_io_number(req, old, sizeof(int), &new, &changed);
	if (error == 0 && changed) {
		stop_spinning = FALSE;
		while (stop_spinning == FALSE) {
			__builtin_ia32_pause();
		}
	} else if (error == 0) {
		stop_spinning = TRUE;
	}

	return error;
}

SYSCTL_PROC(_machdep_misc, OID_AUTO, spin_forever,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0,
    spin_in_the_kernel, "I", "Spin forever");


extern int traptrace_enabled;
SYSCTL_INT(_machdep_misc, OID_AUTO, traptrace_enabled,
    CTLFLAG_KERN | CTLFLAG_RW | CTLFLAG_LOCKED,
    &traptrace_enabled, 0, "Enabled/disable trap trace");

#endif /* DEVELOPMENT || DEBUG */
