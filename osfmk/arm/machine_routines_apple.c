/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <pexpert/pexpert.h>
#if __arm64__
#include <pexpert/arm64/board_config.h>
#endif /* __arm64__ */

#include <arm/cpuid_internal.h>
#include <arm/pmap.h>
#include <arm/proc_reg.h>
#include <machine/machine_cpuid.h>
#include <machine/machine_routines.h>


#if __arm64__

void configure_misc_apple_boot_args(void);
void configure_misc_apple_regs(void);

void
configure_misc_apple_boot_args(void)
{
}

void
configure_misc_apple_regs(void)
{
}

#endif /* __arm64__ */

#if HAS_APPLE_PAC

#if HAS_PARAVIRTUALIZED_PAC
static uint64_t vmapple_default_rop_pid;
static uint64_t vmapple_default_jop_pid;

static inline void
vmapple_pac_get_default_keys()
{
	static bool initialized = false;
	if (os_atomic_xchg(&initialized, true, relaxed)) {
		return;
	}

	const uint64_t fn = VMAPPLE_PAC_GET_DEFAULT_KEYS;
	asm volatile (
                "mov	x0, %[fn]"      "\n"
                "hvc	#0"             "\n"
                "str	x2, %[b_key]"   "\n"
                "str	x3, %[el0_key]" "\n"
                : [b_key] "=m"(vmapple_default_rop_pid),
                  [el0_key] "=m"(vmapple_default_jop_pid)
                : [fn] "r"(fn)
                : "x0", "x1", "x2", "x3", "x4"
        );
}

#endif /* HAS_PARAVIRTUALIZED_PAC */

/**
 * Returns the default ROP key.
 */
uint64_t
ml_default_rop_pid(void)
{
#if HAS_PARAVIRTUALIZED_PAC
	vmapple_pac_get_default_keys();
	return vmapple_default_rop_pid;
#else
	return 0;
#endif /* HAS_PARAVIRTUALIZED_PAC */
}

/**
 * Returns the default JOP key.
 */
uint64_t
ml_default_jop_pid(void)
{
#if HAS_PARAVIRTUALIZED_PAC
	vmapple_pac_get_default_keys();
	return vmapple_default_jop_pid;
#else
	return 0;
#endif /* HAS_PARAVIRTUALIZED_PAC */
}
#endif /* HAS_APPLE_PAC */
