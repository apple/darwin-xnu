/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
 */
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <machine/machine_routines.h>

#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <arm/cpuid.h>
#include <libkern/libkern.h>

extern uint64_t wake_abstime;
extern int      lck_mtx_adaptive_spin_mode;

static
SYSCTL_QUAD(_machdep, OID_AUTO, wake_abstime,
    CTLFLAG_RD, &wake_abstime,
    "Absolute Time at the last wakeup");

static int
sysctl_time_since_reset SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t return_value = ml_get_time_since_reset();
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}

SYSCTL_PROC(_machdep, OID_AUTO, time_since_reset,
    CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_time_since_reset, "I",
    "Continuous time since last SOC boot/wake started");

static int
sysctl_wake_conttime SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t return_value = ml_get_conttime_wake_time();
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}

SYSCTL_PROC(_machdep, OID_AUTO, wake_conttime,
    CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_wake_conttime, "I",
    "Continuous Time at the last wakeup");


/*
 * For source compatibility, here's some machdep.cpu mibs that
 * use host_info() to simulate reasonable answers.
 */

SYSCTL_NODE(_machdep, OID_AUTO, cpu, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "CPU info");

static int
arm_host_info SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;

	host_basic_info_data_t hinfo;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
#define BSD_HOST        1
	kern_return_t kret = host_info((host_t)BSD_HOST,
	    HOST_BASIC_INFO, (host_info_t)&hinfo, &count);
	if (KERN_SUCCESS != kret) {
		return EINVAL;
	}

	if (sizeof(uint32_t) != arg2) {
		panic("size mismatch");
	}

	uintptr_t woffset = (uintptr_t)arg1 / sizeof(uint32_t);
	uint32_t datum = *(uint32_t *)(((uint32_t *)&hinfo) + woffset);
	return SYSCTL_OUT(req, &datum, sizeof(datum));
}

/*
 * machdep.cpu.cores_per_package
 *
 * x86: derived from CPUID data.
 * ARM: how many physical cores we have in the AP; aka hw.physicalcpu_max
 */
static
SYSCTL_PROC(_machdep_cpu, OID_AUTO, cores_per_package,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(host_basic_info_data_t, physical_cpu_max),
    sizeof(integer_t),
    arm_host_info, "I", "CPU cores per package");

/*
 * machdep.cpu.core_count
 *
 * x86: derived from CPUID data.
 * ARM: # active physical cores in the AP; aka hw.physicalcpu
 */
static
SYSCTL_PROC(_machdep_cpu, OID_AUTO, core_count,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(host_basic_info_data_t, physical_cpu),
    sizeof(integer_t),
    arm_host_info, "I", "Number of enabled cores per package");

/*
 * machdep.cpu.logical_per_package
 *
 * x86: derived from CPUID data. Returns ENOENT if HTT bit not set, but
 *      most x64 CPUs have that, so assume it's available.
 * ARM: total # logical cores in the AP; aka hw.logicalcpu_max
 */
static
SYSCTL_PROC(_machdep_cpu, OID_AUTO, logical_per_package,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(host_basic_info_data_t, logical_cpu_max),
    sizeof(integer_t),
    arm_host_info, "I", "CPU logical cpus per package");

/*
 * machdep.cpu.thread_count
 *
 * x86: derived from CPUID data.
 * ARM: # active logical cores in the AP; aka hw.logicalcpu
 */
static
SYSCTL_PROC(_machdep_cpu, OID_AUTO, thread_count,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    (void *)offsetof(host_basic_info_data_t, logical_cpu),
    sizeof(integer_t),
    arm_host_info, "I", "Number of enabled threads per package");

/*
 * machdep.cpu.brand_string
 *
 * x86: derived from CPUID data.
 * ARM: cons something up from the CPUID register. Could include cpufamily
 *	here and map it to a "marketing" name, but there's no obvious need;
 *      the value is already exported via the commpage. So keep it simple.
 */
static int
make_brand_string SYSCTL_HANDLER_ARGS
{
	__unused struct sysctl_oid *unused_oidp = oidp;
	__unused void *unused_arg1 = arg1;
	__unused int unused_arg2 = arg2;

	const char *impl;

	switch (cpuid_info()->arm_info.arm_implementor) {
	case CPU_VID_APPLE:
		impl = "Apple";
		break;
	case CPU_VID_ARM:
		impl = "ARM";
		break;
	default:
		impl = "ARM architecture";
		break;
	}
	char buf[80];
	snprintf(buf, sizeof(buf), "%s processor", impl);
	return SYSCTL_OUT(req, buf, strlen(buf) + 1);
}

SYSCTL_PROC(_machdep_cpu, OID_AUTO, brand_string,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, make_brand_string, "A", "CPU brand string");

static
SYSCTL_INT(_machdep, OID_AUTO, lck_mtx_adaptive_spin_mode,
    CTLFLAG_RW, &lck_mtx_adaptive_spin_mode, 0,
    "Enable adaptive spin behavior for kernel mutexes");


#if DEVELOPMENT || DEBUG
extern uint64_t TLockTimeOut;
SYSCTL_QUAD(_machdep, OID_AUTO, tlto,
    CTLFLAG_RW | CTLFLAG_LOCKED, &TLockTimeOut,
    "Ticket spinlock timeout (MATUs): use with care");

static int
sysctl_sysreg_vbar_el1 SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t return_value = __builtin_arm_rsr64("VBAR_EL1");
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}

/*
 * machdep.cpu.sysreg_vbar_el1
 *
 * ARM64: Vector Base Address Register.
 * Read from the current CPU's system registers.
 */
SYSCTL_PROC(_machdep_cpu, OID_AUTO, sysreg_vbar_el1,
    CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_sysreg_vbar_el1, "Q",
    "VBAR_EL1 register on the current CPU");

static int
sysctl_sysreg_mair_el1 SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t return_value = __builtin_arm_rsr64("MAIR_EL1");
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}

/*
 * machdep.cpu.sysreg_mair_el1
 *
 * ARM64: Memory Attribute Indirection Register.
 * Read from the current CPU's system registers.
 */
SYSCTL_PROC(_machdep_cpu, OID_AUTO, sysreg_mair_el1,
    CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_sysreg_mair_el1, "Q",
    "MAIR_EL1 register on the current CPU");

static int
sysctl_sysreg_ttbr1_el1 SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t return_value = __builtin_arm_rsr64("TTBR1_EL1");
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}

/*
 * machdep.cpu.sysreg_ttbr1_el1
 *
 * ARM64: Translation table base register 1.
 * Read from the current CPU's system registers.
 */
SYSCTL_PROC(_machdep_cpu, OID_AUTO, sysreg_ttbr1_el1,
    CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_sysreg_ttbr1_el1, "Q",
    "TTBR1_EL1 register on the current CPU");

static int
sysctl_sysreg_sctlr_el1 SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t return_value = __builtin_arm_rsr64("SCTLR_EL1");
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}

/*
 * machdep.cpu.sysreg_sctlr_el1
 *
 * ARM64: System Control Register.
 * Read from the current CPU's system registers.
 */
SYSCTL_PROC(_machdep_cpu, OID_AUTO, sysreg_sctlr_el1,
    CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_sysreg_sctlr_el1, "Q",
    "SCTLR_EL1 register on the current CPU");

static int
sysctl_sysreg_tcr_el1 SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t return_value = __builtin_arm_rsr64("TCR_EL1");
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}

/*
 * machdep.cpu.sysreg_tcr_el1
 *
 * ARM64: Translation Control Register.
 * Read from the current CPU's system registers.
 */
SYSCTL_PROC(_machdep_cpu, OID_AUTO, sysreg_tcr_el1,
    CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_sysreg_tcr_el1, "Q",
    "TCR_EL1 register on the current CPU");

static int
sysctl_sysreg_id_aa64mmfr0_el1 SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, oidp)
	uint64_t return_value = __builtin_arm_rsr64("ID_AA64MMFR0_EL1");
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}

/*
 * machdep.cpu.sysreg_id_aa64mmfr0_el1
 *
 * ARM64: AArch64 Memory Model Feature Register 0.
 * Read from the current CPU's system registers.
 */
SYSCTL_PROC(_machdep_cpu, OID_AUTO, sysreg_id_aa64mmfr0_el1,
    CTLFLAG_RD | CTLTYPE_QUAD | CTLFLAG_LOCKED,
    0, 0, sysctl_sysreg_id_aa64mmfr0_el1, "Q",
    "ID_AA64MMFR0_EL1 register on the current CPU");

#endif
