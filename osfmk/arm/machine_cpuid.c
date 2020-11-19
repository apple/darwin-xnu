/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#include <arm/cpuid.h>
#include <arm/cpuid_internal.h>
#include <machine/atomic.h>
#include <machine/machine_cpuid.h>
#include <arm/cpu_data_internal.h>

static arm_mvfp_info_t cpuid_mvfp_info;
static arm_debug_info_t cpuid_debug_info;

uint32_t
machine_read_midr(void)
{
#if __arm__
	uint32_t midr = __builtin_arm_mrc(15, 0, 0, 0, 0);
#else
	uint64_t midr;
	__asm__ volatile ("mrs	%0, MIDR_EL1"  : "=r" (midr));
#endif
	return (uint32_t)midr;
}

uint32_t
machine_read_clidr(void)
{
#if __arm__
	uint32_t clidr = __builtin_arm_mrc(15, 1, 0, 0, 1);
#else
	uint64_t clidr;
	__asm__ volatile ("mrs	%0, CLIDR_EL1"  : "=r" (clidr));
#endif
	return (uint32_t)clidr;
}

uint32_t
machine_read_ccsidr(void)
{
#if __arm__
	uint32_t ccsidr = __builtin_arm_mrc(15, 1, 0, 0, 0);
#else
	uint64_t ccsidr;
	__asm__ volatile ("mrs	%0, CCSIDR_EL1"  : "=r" (ccsidr));
#endif
	return (uint32_t)ccsidr;
}

#if __arm__
arm_isa_feat1_reg
machine_read_isa_feat1(void)
{
	arm_isa_feat1_reg isa;
	isa.value = __builtin_arm_mrc(15, 0, 0, 2, 1);
	return isa;
}
#endif // __arm__

void
machine_write_csselr(csselr_cache_level level, csselr_cache_type type)
{
#if __arm__
	uint32_t csselr = (uint32_t)level | (uint32_t)type;
	__builtin_arm_mcr(15, 2, csselr, 0, 0, 0);
#else
	uint64_t csselr = (uint64_t)level | (uint64_t)type;
	__asm__ volatile ("msr	CSSELR_EL1, %0"  : : "r" (csselr));
#endif
	__builtin_arm_isb(ISB_SY);
}

void
machine_do_debugid(void)
{
#if __arm__
	arm_cpuid_id_dfr0 id_dfr0;
	arm_debug_dbgdidr dbgdidr;

	/* read CPUID ID_DFR0 */
	id_dfr0.value = __builtin_arm_mrc(15, 0, 0, 1, 2);
	/* read DBGDIDR */
	dbgdidr.value = __builtin_arm_mrc(14, 0, 0, 0, 0);

	cpuid_debug_info.coprocessor_core_debug = id_dfr0.debug_feature.coprocessor_core_debug != 0;
	cpuid_debug_info.memory_mapped_core_debug = (id_dfr0.debug_feature.memory_mapped_core_debug != 0)
	    && (getCpuDatap()->cpu_debug_interface_map != 0);

	if (cpuid_debug_info.coprocessor_core_debug || cpuid_debug_info.memory_mapped_core_debug) {
		cpuid_debug_info.num_watchpoint_pairs = dbgdidr.debug_id.wrps + 1;
		cpuid_debug_info.num_breakpoint_pairs = dbgdidr.debug_id.brps + 1;
	}
#else
	arm_cpuid_id_aa64dfr0_el1 id_dfr0;

	/* read ID_AA64DFR0_EL1 */
	__asm__ volatile ("mrs %0, ID_AA64DFR0_EL1" : "=r"(id_dfr0.value));

	if (id_dfr0.debug_feature.debug_arch_version) {
		cpuid_debug_info.num_watchpoint_pairs = id_dfr0.debug_feature.wrps + 1;
		cpuid_debug_info.num_breakpoint_pairs = id_dfr0.debug_feature.brps + 1;
	}
#endif
}

arm_debug_info_t *
machine_arm_debug_info(void)
{
	return &cpuid_debug_info;
}

void
machine_do_mvfpid()
{
#if __arm__
	arm_mvfr0_info_t        arm_mvfr0_info;
	arm_mvfr1_info_t        arm_mvfr1_info;

	__asm__ volatile ("vmrs	%0, mvfr0" :"=r"(arm_mvfr0_info.value));
	__asm__ volatile ("vmrs	%0, mvfr1" :"=r"(arm_mvfr1_info.value));

	cpuid_mvfp_info.neon = arm_mvfr1_info.bits.SP;
	cpuid_mvfp_info.neon_hpfp = arm_mvfr1_info.bits.HPFP;
#else
	cpuid_mvfp_info.neon = 1;
	cpuid_mvfp_info.neon_hpfp = 1;
#if defined(__ARM_ARCH_8_2__)
	cpuid_mvfp_info.neon_fp16 = 1;
#endif /* defined(__ARM_ARCH_8_2__) */
#endif /* __arm__ */
}

arm_mvfp_info_t *
machine_arm_mvfp_info(void)
{
	return &cpuid_mvfp_info;
}
