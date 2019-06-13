/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
/*
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 *	File:		arm/commpage/commpage.c
 *	Purpose:	Set up and export a RO/RW page
 */
#include <libkern/section_keywords.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/vm_map.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <ipc/ipc_port.h>
#include <arm/cpuid.h>		/* for cpuid_info() & cache_info() */
#include <arm/rtclock.h>
#include <libkern/OSAtomic.h>
#include <stdatomic.h>

#include <sys/kdebug.h>

#if CONFIG_ATM
#include <atm/atm_internal.h>
#endif

static void commpage_init_cpu_capabilities( void );
static int commpage_cpus( void );

SECURITY_READ_ONLY_LATE(vm_address_t)	commPagePtr=0;
SECURITY_READ_ONLY_LATE(vm_address_t)	sharedpage_rw_addr = 0;
SECURITY_READ_ONLY_LATE(uint32_t)	_cpu_capabilities = 0;

/* For sysctl access from BSD side */
extern int	gARMv81Atomics;
extern int	gARMv8Crc32;

void
commpage_populate(
	void)
{
	uint16_t	c2;
	int cpufamily;

	sharedpage_rw_addr = pmap_create_sharedpage();
	commPagePtr = (vm_address_t)_COMM_PAGE_BASE_ADDRESS;

	*((uint16_t*)(_COMM_PAGE_VERSION+_COMM_PAGE_RW_OFFSET)) = (uint16_t) _COMM_PAGE_THIS_VERSION;

	commpage_init_cpu_capabilities();
	commpage_set_timestamp(0, 0, 0, 0, 0);

	if (_cpu_capabilities & kCache32)
		c2 = 32;
	else if (_cpu_capabilities & kCache64)
		c2 = 64;
	else if (_cpu_capabilities & kCache128)
		c2 = 128;
	else
		c2 = 0;

	*((uint16_t*)(_COMM_PAGE_CACHE_LINESIZE+_COMM_PAGE_RW_OFFSET)) = c2;
	*((uint32_t*)(_COMM_PAGE_SPIN_COUNT+_COMM_PAGE_RW_OFFSET)) = 1;

	commpage_update_active_cpus();
	cpufamily = cpuid_get_cpufamily();

	/* machine_info valid after ml_get_max_cpus() */
	*((uint8_t*)(_COMM_PAGE_PHYSICAL_CPUS+_COMM_PAGE_RW_OFFSET)) = (uint8_t) machine_info.physical_cpu_max;
	*((uint8_t*)(_COMM_PAGE_LOGICAL_CPUS+_COMM_PAGE_RW_OFFSET))= (uint8_t) machine_info.logical_cpu_max;
	*((uint64_t*)(_COMM_PAGE_MEMORY_SIZE+_COMM_PAGE_RW_OFFSET)) = machine_info.max_mem;
	*((uint32_t*)(_COMM_PAGE_CPUFAMILY+_COMM_PAGE_RW_OFFSET)) = (uint32_t)cpufamily;
	*((uint32_t*)(_COMM_PAGE_DEV_FIRM+_COMM_PAGE_RW_OFFSET)) = (uint32_t)PE_i_can_has_debugger(NULL);
	*((uint8_t*)(_COMM_PAGE_USER_TIMEBASE+_COMM_PAGE_RW_OFFSET)) = user_timebase_allowed();
	*((uint8_t*)(_COMM_PAGE_CONT_HWCLOCK+_COMM_PAGE_RW_OFFSET)) = user_cont_hwclock_allowed();
	*((uint8_t*)(_COMM_PAGE_KERNEL_PAGE_SHIFT+_COMM_PAGE_RW_OFFSET)) = (uint8_t) page_shift;

#if __arm64__
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_32+_COMM_PAGE_RW_OFFSET)) = (uint8_t) page_shift_user32;
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_64+_COMM_PAGE_RW_OFFSET)) = (uint8_t) SIXTEENK_PAGE_SHIFT;
#elif (__ARM_ARCH_7K__ >= 2) && defined(PLATFORM_WatchOS)
	/* enforce 16KB alignment for watch targets with new ABI */
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_32+_COMM_PAGE_RW_OFFSET)) = (uint8_t) SIXTEENK_PAGE_SHIFT;
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_64+_COMM_PAGE_RW_OFFSET)) = (uint8_t) SIXTEENK_PAGE_SHIFT;
#else /* __arm64__ */
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_32+_COMM_PAGE_RW_OFFSET)) = (uint8_t) PAGE_SHIFT;
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_64+_COMM_PAGE_RW_OFFSET)) = (uint8_t) PAGE_SHIFT;
#endif /* __arm64__ */

	commpage_update_timebase();
	commpage_update_mach_continuous_time(0);

	clock_sec_t secs;
	clock_usec_t microsecs;
	clock_get_boottime_microtime(&secs, &microsecs);
	commpage_update_boottime(secs * USEC_PER_SEC + microsecs);

	/* 
	 * set commpage approximate time to zero for initialization. 
	 * scheduler shall populate correct value before running user thread
	 */
	*((uint64_t *)(_COMM_PAGE_APPROX_TIME+ _COMM_PAGE_RW_OFFSET)) = 0;
#ifdef CONFIG_MACH_APPROXIMATE_TIME
	*((uint8_t *)(_COMM_PAGE_APPROX_TIME_SUPPORTED+_COMM_PAGE_RW_OFFSET)) = 1;
#else
	*((uint8_t *)(_COMM_PAGE_APPROX_TIME_SUPPORTED+_COMM_PAGE_RW_OFFSET)) = 0;
#endif

	commpage_update_kdebug_state();

#if CONFIG_ATM
	commpage_update_atm_diagnostic_config(atm_get_diagnostic_config());
#endif

}

struct mu {
	uint64_t m;				// magic number
	int32_t a;				// add indicator
	int32_t s;				// shift amount
};

void
commpage_set_timestamp(
	uint64_t	tbr, 
	uint64_t	secs,
	uint64_t	frac,
	uint64_t	scale,
	uint64_t	tick_per_sec)
{
	new_commpage_timeofday_data_t *commpage_timeofday_datap;

	if (commPagePtr == 0)
		return;

	commpage_timeofday_datap =  (new_commpage_timeofday_data_t *)(_COMM_PAGE_NEWTIMEOFDAY_DATA+_COMM_PAGE_RW_OFFSET);

	commpage_timeofday_datap->TimeStamp_tick = 0x0ULL;

#if	(__ARM_ARCH__ >= 7)
	__asm__ volatile("dmb ish");
#endif
	commpage_timeofday_datap->TimeStamp_sec = secs;
	commpage_timeofday_datap->TimeStamp_frac = frac;
	commpage_timeofday_datap->Ticks_scale = scale;
	commpage_timeofday_datap->Ticks_per_sec = tick_per_sec;

#if	(__ARM_ARCH__ >= 7)
	__asm__ volatile("dmb ish");
#endif
	commpage_timeofday_datap->TimeStamp_tick = tbr;
}

/*
 * Update _COMM_PAGE_MEMORY_PRESSURE.  Called periodically from vm's compute_memory_pressure()
 */

void
commpage_set_memory_pressure(
    unsigned int    pressure )
{
	if (commPagePtr == 0)
		return;
	*((uint32_t *)(_COMM_PAGE_MEMORY_PRESSURE+_COMM_PAGE_RW_OFFSET)) = pressure;
}

/*
 * Update _COMM_PAGE_SPIN_COUNT.  We might want to reduce when running on a battery, etc.
 */

void
commpage_set_spin_count(
        unsigned int    count )
{
        if (count == 0)     /* we test for 0 after decrement, not before */
            count = 1;

	if (commPagePtr == 0)
		return;
	*((uint32_t *)(_COMM_PAGE_SPIN_COUNT+_COMM_PAGE_RW_OFFSET)) = count;
}

/*
 * Determine number of CPUs on this system.
 */
static int
commpage_cpus( void )
{
	int cpus;

	cpus = ml_get_max_cpus();	// NB: this call can block

	if (cpus == 0)
		panic("commpage cpus==0");
	if (cpus > 0xFF)
		cpus = 0xFF;

	return cpus;
}

vm_address_t
_get_commpage_priv_address(void)
{
	return sharedpage_rw_addr;
}

/*
 * Initialize _cpu_capabilities vector
 */
static void
commpage_init_cpu_capabilities( void )
{
	uint32_t bits;
	int cpus;
	ml_cpu_info_t cpu_info;

	bits = 0;
	ml_cpu_get_info(&cpu_info);

	switch (cpu_info.cache_line_size) {
		case 128:
			bits |= kCache128;
			break;
		case 64:
			bits |= kCache64;
			break;
		case 32:
			bits |= kCache32;
			break;
		default:
			break;
	}
	cpus = commpage_cpus();

	if (cpus == 1)
		bits |= kUP;

	bits |= (cpus << kNumCPUsShift);

	bits |= kFastThreadLocalStorage;        // TPIDRURO for TLS

#if	__ARM_VFP__
	bits |= kHasVfp;
	arm_mvfp_info_t *mvfp_info = arm_mvfp_info();
	if (mvfp_info->neon)
		bits |= kHasNeon;
	if (mvfp_info->neon_hpfp)
		bits |= kHasNeonHPFP;
	if (mvfp_info->neon_fp16)
		bits |= kHasNeonFP16;
#endif
#if defined(__arm64__)
	bits |= kHasFMA;
#endif
#if	__ARM_ENABLE_WFE_
#ifdef __arm64__
	if (arm64_wfe_allowed()) {
		bits |= kHasEvent;
	}
#else
	bits |= kHasEvent;
#endif
#endif
#if __ARM_V8_CRYPTO_EXTENSIONS__ 
	bits |= kHasARMv8Crypto;
#endif
#ifdef __arm64__
	uint64_t isar0 = __builtin_arm_rsr64("ID_AA64ISAR0_EL1");
	if ((isar0 & ID_AA64ISAR0_EL1_ATOMIC_MASK) == ID_AA64ISAR0_EL1_ATOMIC_8_1) {
		bits |= kHasARMv81Atomics;
		gARMv81Atomics = 1;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_CRC32_MASK) == ID_AA64ISAR0_EL1_CRC32_EN) {
		bits |= kHasARMv8Crc32;
		gARMv8Crc32 = 1;
	}
#endif
	_cpu_capabilities = bits;

	*((uint32_t *)(_COMM_PAGE_CPU_CAPABILITIES+_COMM_PAGE_RW_OFFSET)) = _cpu_capabilities;
}

/*
 * Updated every time a logical CPU goes offline/online
 */
void
commpage_update_active_cpus(void)
{
        if (!commPagePtr)
                return;
	*((uint8_t *)(_COMM_PAGE_ACTIVE_CPUS+_COMM_PAGE_RW_OFFSET)) = processor_avail_count;
}

/*
 * Update the commpage bits for mach_absolute_time and mach_continuous_time (for userspace)
 */
void
commpage_update_timebase(void)
{
	if (commPagePtr) {
		*((uint64_t*)(_COMM_PAGE_TIMEBASE_OFFSET+_COMM_PAGE_RW_OFFSET)) = rtclock_base_abstime;
	}
}

/*
 * Update the commpage with current kdebug state. This currently has bits for
 * global trace state, and typefilter enablement. It is likely additional state
 * will be tracked in the future.
 *
 * INVARIANT: This value will always be 0 if global tracing is disabled. This
 * allows simple guard tests of "if (*_COMM_PAGE_KDEBUG_ENABLE) { ... }"
 */
void
commpage_update_kdebug_state(void)
{
	if (commPagePtr)
		*((volatile uint32_t*)(_COMM_PAGE_KDEBUG_ENABLE+_COMM_PAGE_RW_OFFSET)) = kdebug_commpage_state();
}

/* Ditto for atm_diagnostic_config */
void
commpage_update_atm_diagnostic_config(uint32_t diagnostic_config)
{
	if (commPagePtr)
		*((volatile uint32_t*)(_COMM_PAGE_ATM_DIAGNOSTIC_CONFIG+_COMM_PAGE_RW_OFFSET)) = diagnostic_config;
}

/*
 * Update the commpage data with the state of multiuser mode for
 * this device. Allowing various services in userspace to avoid
 * IPC in the (more common) non-multiuser environment.
 */
void
commpage_update_multiuser_config(uint32_t multiuser_config)
{
	if (commPagePtr)
		*((volatile uint32_t *)(_COMM_PAGE_MULTIUSER_CONFIG+_COMM_PAGE_RW_OFFSET)) = multiuser_config;
}

/*
 * update the commpage data for 
 * last known value of mach_absolute_time()
 */

void
commpage_update_mach_approximate_time(uint64_t abstime)
{
#ifdef CONFIG_MACH_APPROXIMATE_TIME
	uintptr_t approx_time_base = (uintptr_t)(_COMM_PAGE_APPROX_TIME + _COMM_PAGE_RW_OFFSET);
	uint64_t saved_data;

	if (commPagePtr) {
		saved_data = atomic_load_explicit((_Atomic uint64_t *)approx_time_base,
			memory_order_relaxed);
		if (saved_data < abstime) {
			/* ignoring the success/fail return value assuming that
			 * if the value has been updated since we last read it,
			 * "someone" has a newer timestamp than us and ours is
			 * now invalid. */
			atomic_compare_exchange_strong_explicit((_Atomic uint64_t *)approx_time_base, 
				&saved_data, abstime, memory_order_relaxed, memory_order_relaxed);
		}
	}
#else
#pragma unused (abstime)
#endif
}

/*
 * update the commpage data's total system sleep time for 
 * userspace call to mach_continuous_time()
 */
void
commpage_update_mach_continuous_time(uint64_t sleeptime)
{
	if (commPagePtr) {
#ifdef __arm64__
		*((uint64_t *)(_COMM_PAGE_CONT_TIMEBASE + _COMM_PAGE_RW_OFFSET)) = sleeptime;
#else
		uint64_t *c_time_base = (uint64_t *)(_COMM_PAGE_CONT_TIMEBASE + _COMM_PAGE_RW_OFFSET);
		uint64_t old;
		do {
			old = *c_time_base;
		} while(!OSCompareAndSwap64(old, sleeptime, c_time_base));
#endif /* __arm64__ */
	}
}

/*
 * update the commpage's value for the boot time
 */
void
commpage_update_boottime(uint64_t value)
{
	if (commPagePtr) {
#ifdef __arm64__
		*((uint64_t *)(_COMM_PAGE_BOOTTIME_USEC + _COMM_PAGE_RW_OFFSET)) = value;
#else
		uint64_t *cp = (uint64_t *)(_COMM_PAGE_BOOTTIME_USEC + _COMM_PAGE_RW_OFFSET);
		uint64_t old_value;
		do {
			old_value = *cp;
		} while (!OSCompareAndSwap64(old_value, value, cp));
#endif /* __arm64__ */
	}
}


/*
 * After this counter has incremented, all running CPUs are guaranteed to
 * have quiesced, i.e. executed serially dependent memory barriers.
 * This is only tracked for CPUs running in userspace, therefore only useful
 * outside the kernel.
 *
 * Note that you can't know which side of those barriers your read was from,
 * so you have to observe 2 increments in order to ensure that you saw a
 * serially dependent barrier chain across all running CPUs.
 */
uint64_t
commpage_increment_cpu_quiescent_counter(void)
{
	if (!commPagePtr)
		return 0;

	uint64_t old_gen;

	_Atomic uint64_t *sched_gen = (_Atomic uint64_t *)(_COMM_PAGE_CPU_QUIESCENT_COUNTER +
	                                                   _COMM_PAGE_RW_OFFSET);
	/*
	 * On 32bit architectures, double-wide atomic load or stores are a CAS,
	 * so the atomic increment is the most efficient way to increment the
	 * counter.
	 *
	 * On 64bit architectures however, because the update is synchronized by
	 * the cpu mask, relaxed loads and stores is more efficient.
	 */
#if __LP64__
	old_gen = atomic_load_explicit(sched_gen, memory_order_relaxed);
	atomic_store_explicit(sched_gen, old_gen + 1, memory_order_relaxed);
#else
	old_gen = atomic_fetch_add_explicit(sched_gen, 1, memory_order_relaxed);
#endif
	return old_gen;
}

