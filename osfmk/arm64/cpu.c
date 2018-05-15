/*
 * Copyright (c) 2007-2016 Apple Inc. All rights reserved.
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
 *	File:	arm64/cpu.c
 *
 *	cpu specific routines
 */

#include <pexpert/arm64/board_config.h>
#include <kern/kalloc.h>
#include <kern/machine.h>
#include <kern/cpu_number.h>
#include <kern/thread.h>
#include <kern/timer_queue.h>
#include <arm/cpu_data.h>
#include <arm/cpuid.h>
#include <arm/caches_internal.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>
#include <arm/misc_protos.h>
#include <arm/machine_cpu.h>
#include <arm/rtclock.h>
#include <arm64/proc_reg.h>
#include <mach/processor_info.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <pexpert/arm/protos.h>
#include <pexpert/device_tree.h>
#include <sys/kdebug.h>
#include <arm/machine_routines.h>

#include <machine/atomic.h>

#include <san/kasan.h>

#if KPC
#include <kern/kpc.h>
#endif

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

extern boolean_t	idle_enable;
extern uint64_t		wake_abstime;

#if WITH_CLASSIC_S2R
void sleep_token_buffer_init(void);
#endif


extern uintptr_t resume_idle_cpu;
extern uintptr_t start_cpu;

#if __ARM_KERNEL_PROTECT__
extern void exc_vectors_table;
#endif /* __ARM_KERNEL_PROTECT__ */

extern void __attribute__((noreturn)) arm64_prepare_for_sleep(void);
extern void arm64_force_wfi_clock_gate(void);
#if (defined(APPLECYCLONE) || defined(APPLETYPHOON))
// <rdar://problem/15827409> CPU1 Stuck in WFIWT Because of MMU Prefetch
extern void cyclone_typhoon_prepare_for_wfi(void);
extern void cyclone_typhoon_return_from_wfi(void);
#endif


vm_address_t   start_cpu_paddr;

sysreg_restore_t sysreg_restore __attribute__((section("__DATA, __const"))) = {
	.tcr_el1 = TCR_EL1_BOOT,
};


// wfi - wfi mode
//  0 : disabled
//  1 : normal
//  2 : overhead simulation (delay & flags)
static int wfi = 1;

#if DEVELOPMENT || DEBUG

// wfi_flags
//  1 << 0 : flush L1s
//  1 << 1 : flush TLBs
static int wfi_flags = 0;

// wfi_delay - delay ticks after wfi exit
static uint64_t wfi_delay = 0;

#endif /* DEVELOPMENT || DEBUG */

#if __ARM_GLOBAL_SLEEP_BIT__
volatile boolean_t arm64_stall_sleep = TRUE;
#endif

#if WITH_CLASSIC_S2R
/*
 * These must be aligned to avoid issues with calling bcopy_phys on them before
 * we are done with pmap initialization.
 */
static const uint8_t __attribute__ ((aligned(8))) suspend_signature[] = {'X', 'S', 'O', 'M', 'P', 'S', 'U', 'S'};
static const uint8_t __attribute__ ((aligned(8))) running_signature[] = {'X', 'S', 'O', 'M', 'N', 'N', 'U', 'R'};
#endif

#if WITH_CLASSIC_S2R
static vm_offset_t sleepTokenBuffer = (vm_offset_t)NULL;
#endif
static boolean_t coresight_debug_enabled = FALSE;


static void
configure_coresight_registers(cpu_data_t *cdp)
{
	uint64_t	addr;
	int		i;

	assert(cdp);

	/*
	 * ARMv8 coresight registers are optional. If the device tree did not
	 * provide cpu_regmap_paddr, assume that coresight registers are not
	 * supported.
	 */
	if (cdp->cpu_regmap_paddr) {
		for (i = 0; i < CORESIGHT_REGIONS; ++i) {
			/* Skip CTI; these registers are debug-only (they are
			 * not present on production hardware), and there is
			 * at least one known Cyclone errata involving CTI
			 * (rdar://12802966).  We have no known clients that
			 * need the kernel to unlock CTI, so it is safer
			 * to avoid doing the access.
			 */
			if (i == CORESIGHT_CTI)
				continue;
			/* Skip debug-only registers on production chips */
			if (((i == CORESIGHT_ED) || (i == CORESIGHT_UTT)) && !coresight_debug_enabled)
				continue;

			if (!cdp->coresight_base[i]) {
				addr = cdp->cpu_regmap_paddr + CORESIGHT_OFFSET(i);
				cdp->coresight_base[i] = (vm_offset_t)ml_io_map(addr, CORESIGHT_SIZE);

				/*
				 * At this point, failing to io map the
				 * registers is considered as an error.
				 */
				if (!cdp->coresight_base[i]) {
					panic("unable to ml_io_map coresight regions");
				}
			}
			/* Unlock EDLAR, CTILAR, PMLAR */
			if (i != CORESIGHT_UTT)
				*(volatile uint32_t *)(cdp->coresight_base[i] + ARM_DEBUG_OFFSET_DBGLAR) = ARM_DBG_LOCK_ACCESS_KEY;
		}
	}
}


/*
 *	Routine:	cpu_bootstrap
 *	Function:
 */
void
cpu_bootstrap(void)
{
}

/*
 *	Routine:	cpu_sleep
 *	Function:
 */
void
cpu_sleep(void)
{
	cpu_data_t     *cpu_data_ptr = getCpuDatap();

	pmap_switch_user_ttb(kernel_pmap);
	cpu_data_ptr->cpu_active_thread = current_thread();
	cpu_data_ptr->cpu_reset_handler = (uintptr_t) start_cpu_paddr;
	cpu_data_ptr->cpu_flags |= SleepState;
	cpu_data_ptr->cpu_user_debug = NULL;
#if KPC
	kpc_idle();
#endif /* KPC */
#if MONOTONIC
	mt_cpu_down(cpu_data_ptr);
#endif /* MONOTONIC */

	CleanPoC_Dcache();

	PE_cpu_machine_quiesce(cpu_data_ptr->cpu_id);

}

/*
 *	Routine:	cpu_idle
 *	Function:
 */
void __attribute__((noreturn))
cpu_idle(void)
{
	cpu_data_t     *cpu_data_ptr = getCpuDatap();
	uint64_t	new_idle_timeout_ticks = 0x0ULL, lastPop;

	if ((!idle_enable) || (cpu_data_ptr->cpu_signal & SIGPdisabled))
		Idle_load_context();
	if (!SetIdlePop())
		Idle_load_context();
	lastPop = cpu_data_ptr->rtcPop;

	pmap_switch_user_ttb(kernel_pmap);
	cpu_data_ptr->cpu_active_thread = current_thread();
	if (cpu_data_ptr->cpu_user_debug)
		arm_debug_set(NULL);
	cpu_data_ptr->cpu_user_debug = NULL;

	if (cpu_data_ptr->cpu_idle_notify)
		((processor_idle_t) cpu_data_ptr->cpu_idle_notify) (cpu_data_ptr->cpu_id, TRUE, &new_idle_timeout_ticks);

	if (cpu_data_ptr->idle_timer_notify != 0) {
		if (new_idle_timeout_ticks == 0x0ULL) {
			/* turn off the idle timer */
			cpu_data_ptr->idle_timer_deadline = 0x0ULL;
		} else {
			/* set the new idle timeout */
			clock_absolutetime_interval_to_deadline(new_idle_timeout_ticks, &cpu_data_ptr->idle_timer_deadline);
		}
		timer_resync_deadlines();
		if (cpu_data_ptr->rtcPop != lastPop)
			SetIdlePop();
	}

#if KPC
	kpc_idle();
#endif
#if MONOTONIC
	mt_cpu_idle(cpu_data_ptr);
#endif /* MONOTONIC */

	if (wfi) {
		platform_cache_idle_enter();

#if DEVELOPMENT || DEBUG
		// When simulating wfi overhead,
		// force wfi to clock gating only
		if (wfi == 2) {
			arm64_force_wfi_clock_gate();
		}
#endif /* DEVELOPMENT || DEBUG */

#if defined(APPLECYCLONE) || defined(APPLETYPHOON)
		// <rdar://problem/15827409> CPU1 Stuck in WFIWT Because of MMU Prefetch
		cyclone_typhoon_prepare_for_wfi();
#endif
		__builtin_arm_dsb(DSB_SY);
		__builtin_arm_wfi();

#if defined(APPLECYCLONE) || defined(APPLETYPHOON)
		// <rdar://problem/15827409> CPU1 Stuck in WFIWT Because of MMU Prefetch
		cyclone_typhoon_return_from_wfi();
#endif

#if DEVELOPMENT || DEBUG
		// Handle wfi overhead simulation
		if (wfi == 2) {
			uint64_t deadline;

			// Calculate wfi delay deadline
			clock_absolutetime_interval_to_deadline(wfi_delay, &deadline);

			// Flush L1 caches
			if ((wfi_flags & 1) != 0) {
				InvalidatePoU_Icache();
				FlushPoC_Dcache();
			}

			// Flush TLBs
			if ((wfi_flags & 2) != 0) {
				flush_core_tlb();
			}

			// Wait for the ballance of the wfi delay
			clock_delay_until(deadline);
		}
#endif /* DEVELOPMENT || DEBUG */

		platform_cache_idle_exit();
	}

	ClearIdlePop(TRUE);

	cpu_idle_exit();
}

/*
 *	Routine:	cpu_idle_exit
 *	Function:
 */
void
cpu_idle_exit(void)
{
	uint64_t	new_idle_timeout_ticks = 0x0ULL;
	cpu_data_t     *cpu_data_ptr = getCpuDatap();

	assert(exception_stack_pointer() != 0);

	/* Back from WFI, unlock OSLAR and EDLAR. */
	configure_coresight_registers(cpu_data_ptr);

#if KPC
	kpc_idle_exit();
#endif

#if MONOTONIC
	mt_cpu_run(cpu_data_ptr);
#endif /* MONOTONIC */

	pmap_switch_user_ttb(cpu_data_ptr->cpu_active_thread->map->pmap);

	if (cpu_data_ptr->cpu_idle_notify)
		((processor_idle_t) cpu_data_ptr->cpu_idle_notify) (cpu_data_ptr->cpu_id, FALSE, &new_idle_timeout_ticks);

	if (cpu_data_ptr->idle_timer_notify != 0) {
		if (new_idle_timeout_ticks == 0x0ULL) {
			/* turn off the idle timer */
			cpu_data_ptr->idle_timer_deadline = 0x0ULL;
		} else {
			/* set the new idle timeout */
			clock_absolutetime_interval_to_deadline(new_idle_timeout_ticks, &cpu_data_ptr->idle_timer_deadline);
		}
		timer_resync_deadlines();
	}

	Idle_load_context();
}

void
cpu_init(void)
{
	cpu_data_t     *cdp = getCpuDatap();
	arm_cpu_info_t *cpu_info_p;

	assert(exception_stack_pointer() != 0);

	if (cdp->cpu_type != CPU_TYPE_ARM64) {

		cdp->cpu_type = CPU_TYPE_ARM64;

		timer_call_queue_init(&cdp->rtclock_timer.queue);
		cdp->rtclock_timer.deadline = EndOfAllTime;

		if (cdp == &BootCpuData) {
			do_cpuid();
			do_cacheid();
			do_mvfpid();
		} else {
			/*
			 * We initialize non-boot CPUs here; the boot CPU is
			 * dealt with as part of pmap_bootstrap.
			 */
			pmap_cpu_data_init();
		}
		/* ARM_SMP: Assuming identical cpu */
		do_debugid();

		cpu_info_p = cpuid_info();

		/* switch based on CPU's reported architecture */
		switch (cpu_info_p->arm_info.arm_arch) {
		case CPU_ARCH_ARMv8:
			cdp->cpu_subtype = CPU_SUBTYPE_ARM64_V8;
			break;
		default:
			//cdp->cpu_subtype = CPU_SUBTYPE_ARM64_ALL;
			/* this panic doesn't work this early in startup */
			panic("Unknown CPU subtype...");
			break;
		}

		cdp->cpu_threadtype = CPU_THREADTYPE_NONE;
	}
	cdp->cpu_stat.irq_ex_cnt_wake = 0;
	cdp->cpu_stat.ipi_cnt_wake = 0;
	cdp->cpu_stat.timer_cnt_wake = 0;
	cdp->cpu_running = TRUE;
	cdp->cpu_sleep_token_last = cdp->cpu_sleep_token;
	cdp->cpu_sleep_token = 0x0UL;
#if KPC
	kpc_idle_exit();
#endif /* KPC */
#if MONOTONIC
	mt_cpu_up(cdp);
#endif /* MONOTONIC */
}

cpu_data_t *
cpu_data_alloc(boolean_t is_boot_cpu)
{
	cpu_data_t		*cpu_data_ptr = NULL;

	if (is_boot_cpu)
		cpu_data_ptr = &BootCpuData;
	else {
		void	*irq_stack = NULL;
		void	*exc_stack = NULL;
		void	*fiq_stack = NULL;

		if ((kmem_alloc(kernel_map, (vm_offset_t *)&cpu_data_ptr, sizeof(cpu_data_t), VM_KERN_MEMORY_CPU)) != KERN_SUCCESS)
			goto cpu_data_alloc_error;

		bzero((void *)cpu_data_ptr, sizeof(cpu_data_t));

		if ((irq_stack = kalloc(INTSTACK_SIZE)) == 0)
			goto cpu_data_alloc_error;
		cpu_data_ptr->intstack_top = (vm_offset_t)irq_stack + INTSTACK_SIZE ;
		cpu_data_ptr->istackptr = cpu_data_ptr->intstack_top;

		if ((exc_stack = kalloc(PAGE_SIZE)) == 0)
			goto cpu_data_alloc_error;
		cpu_data_ptr->excepstack_top = (vm_offset_t)exc_stack + PAGE_SIZE ;
		cpu_data_ptr->excepstackptr = cpu_data_ptr->excepstack_top;

		if ((fiq_stack = kalloc(PAGE_SIZE)) == 0)
			goto cpu_data_alloc_error;
		cpu_data_ptr->fiqstack_top = (vm_offset_t)fiq_stack + PAGE_SIZE ;
		cpu_data_ptr->fiqstackptr = cpu_data_ptr->fiqstack_top;
	}

	cpu_data_ptr->cpu_processor = cpu_processor_alloc(is_boot_cpu);
	if (cpu_data_ptr->cpu_processor == (struct processor *)NULL)
		goto cpu_data_alloc_error;

	return cpu_data_ptr;

cpu_data_alloc_error:
	panic("cpu_data_alloc() failed\n");
	return (cpu_data_t *)NULL;
}


void
cpu_data_free(cpu_data_t *cpu_data_ptr)
{
        if (cpu_data_ptr == &BootCpuData)
                return;

	cpu_processor_free( cpu_data_ptr->cpu_processor);
	kfree( (void *)(cpu_data_ptr->intstack_top - INTSTACK_SIZE), INTSTACK_SIZE);
	kfree( (void *)(cpu_data_ptr->fiqstack_top - PAGE_SIZE), PAGE_SIZE);
	kmem_free(kernel_map, (vm_offset_t)cpu_data_ptr, sizeof(cpu_data_t));
}

void
cpu_data_init(cpu_data_t *cpu_data_ptr)
{
	uint32_t i;

	cpu_data_ptr->cpu_flags = 0;
	cpu_data_ptr->interrupts_enabled = 0;
	cpu_data_ptr->cpu_int_state = 0;
	cpu_data_ptr->cpu_pending_ast = AST_NONE;
	cpu_data_ptr->cpu_cache_dispatch = (void *) 0;
	cpu_data_ptr->rtcPop = EndOfAllTime;
	cpu_data_ptr->rtclock_datap = &RTClockData;
	cpu_data_ptr->cpu_user_debug = NULL;


	cpu_data_ptr->cpu_base_timebase = 0;
	cpu_data_ptr->cpu_idle_notify = (void *) 0;
	cpu_data_ptr->cpu_idle_latency = 0x0ULL;
	cpu_data_ptr->cpu_idle_pop = 0x0ULL;
	cpu_data_ptr->cpu_reset_type = 0x0UL;
	cpu_data_ptr->cpu_reset_handler = 0x0UL;
	cpu_data_ptr->cpu_reset_assist = 0x0UL;
	cpu_data_ptr->cpu_regmap_paddr = 0x0ULL;
	cpu_data_ptr->cpu_phys_id = 0x0UL;
	cpu_data_ptr->cpu_l2_access_penalty = 0;
	cpu_data_ptr->cpu_cluster_type = CLUSTER_TYPE_SMP;
	cpu_data_ptr->cpu_cluster_id = 0;
	cpu_data_ptr->cpu_l2_id = 0;
	cpu_data_ptr->cpu_l2_size = 0;
	cpu_data_ptr->cpu_l3_id = 0;
	cpu_data_ptr->cpu_l3_size = 0;

	cpu_data_ptr->cpu_signal = SIGPdisabled;

#if DEBUG || DEVELOPMENT
	cpu_data_ptr->failed_xcall = NULL;
	cpu_data_ptr->failed_signal = 0;
	cpu_data_ptr->failed_signal_count = 0;
#endif

	cpu_data_ptr->cpu_get_fiq_handler = NULL;
	cpu_data_ptr->cpu_tbd_hardware_addr = NULL;
	cpu_data_ptr->cpu_tbd_hardware_val = NULL;
	cpu_data_ptr->cpu_get_decrementer_func = NULL;
	cpu_data_ptr->cpu_set_decrementer_func = NULL;
	cpu_data_ptr->cpu_sleep_token = ARM_CPU_ON_SLEEP_PATH;
	cpu_data_ptr->cpu_sleep_token_last = 0x00000000UL;
	cpu_data_ptr->cpu_xcall_p0 = NULL;
	cpu_data_ptr->cpu_xcall_p1 = NULL;

	for (i = 0; i < CORESIGHT_REGIONS; ++i) {
		cpu_data_ptr->coresight_base[i] = 0;
	}

	pmap_cpu_data_t * pmap_cpu_data_ptr = &cpu_data_ptr->cpu_pmap_cpu_data;

	pmap_cpu_data_ptr->cpu_user_pmap = (struct pmap *) NULL;
	pmap_cpu_data_ptr->cpu_user_pmap_stamp = 0;
	pmap_cpu_data_ptr->cpu_number = PMAP_INVALID_CPU_NUM;

	for (i = 0; i < (sizeof(pmap_cpu_data_ptr->cpu_asid_high_bits) / sizeof(*pmap_cpu_data_ptr->cpu_asid_high_bits)); i++) {
		pmap_cpu_data_ptr->cpu_asid_high_bits[i] = 0;
	}
	cpu_data_ptr->halt_status = CPU_NOT_HALTED;
#if __ARM_KERNEL_PROTECT__
	cpu_data_ptr->cpu_exc_vectors = (vm_offset_t)&exc_vectors_table;
#endif /* __ARM_KERNEL_PROTECT__ */
}

kern_return_t
cpu_data_register(cpu_data_t *cpu_data_ptr)
{
	int	cpu = cpu_data_ptr->cpu_number;

#if KASAN
	for (int i = 0; i < CPUWINDOWS_MAX; i++) {
		kasan_notify_address_nopoison(pmap_cpu_windows_copy_addr(cpu, i), PAGE_SIZE);
	}
#endif

	CpuDataEntries[cpu].cpu_data_vaddr = cpu_data_ptr;
	CpuDataEntries[cpu].cpu_data_paddr = (void *)ml_vtophys( (vm_offset_t)cpu_data_ptr);
	return KERN_SUCCESS;

}

kern_return_t
cpu_start(int cpu)
{
	cpu_data_t *cpu_data_ptr = CpuDataEntries[cpu].cpu_data_vaddr;

	kprintf("cpu_start() cpu: %d\n", cpu);

	if (cpu == cpu_number()) {
		cpu_machine_init();
		configure_coresight_registers(cpu_data_ptr);
	} else {
		thread_t first_thread;

		cpu_data_ptr->cpu_reset_handler = (vm_offset_t) start_cpu_paddr;

		cpu_data_ptr->cpu_pmap_cpu_data.cpu_user_pmap = NULL;

		if (cpu_data_ptr->cpu_processor->next_thread != THREAD_NULL)
			first_thread = cpu_data_ptr->cpu_processor->next_thread;
		else
			first_thread = cpu_data_ptr->cpu_processor->idle_thread;
		cpu_data_ptr->cpu_active_thread = first_thread;
		first_thread->machine.CpuDatap = cpu_data_ptr;

		configure_coresight_registers(cpu_data_ptr);

		flush_dcache((vm_offset_t)&CpuDataEntries[cpu], sizeof(cpu_data_entry_t), FALSE);
		flush_dcache((vm_offset_t)cpu_data_ptr, sizeof(cpu_data_t), FALSE);
		(void) PE_cpu_start(cpu_data_ptr->cpu_id, (vm_offset_t)NULL, (vm_offset_t)NULL);
	}

	return KERN_SUCCESS;
}


void
cpu_timebase_init(boolean_t from_boot)
{
	cpu_data_t *cdp = getCpuDatap();

	if (cdp->cpu_get_fiq_handler == NULL) {
		cdp->cpu_get_fiq_handler = rtclock_timebase_func.tbd_fiq_handler;
		cdp->cpu_get_decrementer_func = rtclock_timebase_func.tbd_get_decrementer;
		cdp->cpu_set_decrementer_func = rtclock_timebase_func.tbd_set_decrementer;
		cdp->cpu_tbd_hardware_addr = (void *)rtclock_timebase_addr;
		cdp->cpu_tbd_hardware_val = (void *)rtclock_timebase_val;
	}

	if (!from_boot && (cdp == &BootCpuData)) {
		/*
		 * When we wake from sleep, we have no guarantee about the state
		 * of the hardware timebase.  It may have kept ticking across sleep, or
		 * it may have reset.
		 *
		 * To deal with this, we calculate an offset to the clock that will
		 * produce a timebase value wake_abstime at the point the boot
		 * CPU calls cpu_timebase_init on wake.
		 *
		 * This ensures that mach_absolute_time() stops ticking across sleep.
		 */
		rtclock_base_abstime = wake_abstime - ml_get_hwclock();
	}

	cdp->cpu_decrementer = 0x7FFFFFFFUL;
	cdp->cpu_timebase = 0x0UL;
	cdp->cpu_base_timebase = rtclock_base_abstime;
}

int
cpu_cluster_id(void)
{
	return (getCpuDatap()->cpu_cluster_id);
}

__attribute__((noreturn))
void
ml_arm_sleep(void)
{
	cpu_data_t		*cpu_data_ptr = getCpuDatap();

	if (cpu_data_ptr == &BootCpuData) {
		cpu_data_t      *target_cdp;
		int		cpu;
		int		max_cpu;

		max_cpu = ml_get_max_cpu_number();
		for (cpu=0; cpu <= max_cpu; cpu++) {
			target_cdp = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;

			if ((target_cdp == NULL) || (target_cdp == cpu_data_ptr))
				continue;

			while (target_cdp->cpu_sleep_token != ARM_CPU_ON_SLEEP_PATH);
		}

		/*
		 * Now that the other cores have entered the sleep path, set
		 * the abstime value we'll use when we resume.
		 */
		wake_abstime = ml_get_timebase();
	} else {
		CleanPoU_Dcache();
	}

	cpu_data_ptr->cpu_sleep_token = ARM_CPU_ON_SLEEP_PATH;

	if (cpu_data_ptr == &BootCpuData) {
#if WITH_CLASSIC_S2R
		// Classic suspend to RAM writes the suspend signature into the
		// sleep token buffer so that iBoot knows that it's on the warm
		// boot (wake) path (as opposed to the cold boot path). Newer SoC
		// do not go through SecureROM/iBoot on the warm boot path. The
		// reconfig engine script brings the CPU out of reset at the kernel's
		// reset vector which points to the warm boot initialization code.
		if(sleepTokenBuffer != (vm_offset_t) NULL) {
			platform_cache_shutdown();
			bcopy((const void *)suspend_signature, (void *)sleepTokenBuffer, sizeof(SleepToken));
		}
		else {
			panic("No sleep token buffer");
		}
#endif

#if __ARM_GLOBAL_SLEEP_BIT__
		/* Allow other CPUs to go to sleep. */
		arm64_stall_sleep = FALSE;
		__builtin_arm_dmb(DMB_ISH);
#endif

		/* Architectural debug state: <rdar://problem/12390433>:
		 * 	Grab debug lock EDLAR and clear bit 0 in EDPRCR,
		 * 	tell debugger to not prevent power gating .
		 */
		if (cpu_data_ptr->coresight_base[CORESIGHT_ED]) {
			*(volatile uint32_t *)(cpu_data_ptr->coresight_base[CORESIGHT_ED] + ARM_DEBUG_OFFSET_DBGLAR) = ARM_DBG_LOCK_ACCESS_KEY;
			*(volatile uint32_t *)(cpu_data_ptr->coresight_base[CORESIGHT_ED] + ARM_DEBUG_OFFSET_DBGPRCR) = 0;
		}

#if MONOTONIC
		mt_sleep();
#endif /* MONOTONIC */
		/* ARM64-specific preparation */
		arm64_prepare_for_sleep();
	} else {
#if __ARM_GLOBAL_SLEEP_BIT__
		/*
		 * With the exception of the CPU revisions listed above, our ARM64 CPUs have a
		 * global register to manage entering deep sleep, as opposed to a per-CPU
		 * register.  We cannot update this register until all CPUs are ready to enter
		 * deep sleep, because if a CPU executes WFI outside of the deep sleep context
		 * (by idling), it will hang (due to the side effects of enabling deep sleep),
		 * which can hang the sleep process or cause memory corruption on wake.
		 *
		 * To avoid these issues, we'll stall on this global value, which CPU0 will
		 * manage.
		 */
		while (arm64_stall_sleep) {
			__builtin_arm_wfe();
		}
#endif
		CleanPoU_DcacheRegion((vm_offset_t) cpu_data_ptr, sizeof(cpu_data_t));

		/* Architectural debug state: <rdar://problem/12390433>:
		 * 	Grab debug lock EDLAR and clear bit 0 in EDPRCR,
		 * 	tell debugger to not prevent power gating .
		 */
		if (cpu_data_ptr->coresight_base[CORESIGHT_ED]) {
			*(volatile uint32_t *)(cpu_data_ptr->coresight_base[CORESIGHT_ED] + ARM_DEBUG_OFFSET_DBGLAR) = ARM_DBG_LOCK_ACCESS_KEY;
			*(volatile uint32_t *)(cpu_data_ptr->coresight_base[CORESIGHT_ED] + ARM_DEBUG_OFFSET_DBGPRCR) = 0;
		}

		/* ARM64-specific preparation */
		arm64_prepare_for_sleep();
	}
}

void
cpu_machine_idle_init(boolean_t from_boot)
{
	static vm_address_t	resume_idle_cpu_paddr = (vm_address_t)NULL;
	cpu_data_t		*cpu_data_ptr	= getCpuDatap();

	if (from_boot) {
		unsigned long	jtag = 0;
		int		wfi_tmp = 1;
 		uint32_t	production = 1;
 		DTEntry		entry;

		if (PE_parse_boot_argn("jtag", &jtag, sizeof (jtag))) {
			if (jtag != 0)
				idle_enable = FALSE;
			else
				idle_enable = TRUE;
		} else
			idle_enable = TRUE;

		PE_parse_boot_argn("wfi", &wfi_tmp, sizeof (wfi_tmp));

		// bits 7..0 give the wfi type
		switch (wfi_tmp & 0xff) {
		case 0 :
			// disable wfi
			wfi = 0;
			break;

#if DEVELOPMENT || DEBUG
		case 2 :
			// wfi overhead simulation
			// 31..16 - wfi delay is us
			// 15..8  - flags
			// 7..0   - 2
			wfi = 2;
			wfi_flags = (wfi_tmp >> 8) & 0xFF;
			nanoseconds_to_absolutetime(((wfi_tmp >> 16) & 0xFFFF) * NSEC_PER_MSEC, &wfi_delay);
			break;
#endif /* DEVELOPMENT || DEBUG */

		case 1 :
		default :
			// do nothing
			break;
		}

		ResetHandlerData.assist_reset_handler = 0;
		ResetHandlerData.cpu_data_entries = ml_static_vtop((vm_offset_t)CpuDataEntries);

#ifdef MONITOR
		monitor_call(MONITOR_SET_ENTRY, (uintptr_t)ml_static_vtop((vm_offset_t)&LowResetVectorBase), 0, 0);
#elif !defined(NO_MONITOR)
#error MONITOR undefined, WFI power gating may not operate correctly
#endif /* MONITOR */

		// Determine if we are on production or debug chip
		if (kSuccess == DTLookupEntry(NULL, "/chosen", &entry)) {
			unsigned int	size;
			void		*prop;

			if (kSuccess == DTGetProperty(entry, "effective-production-status-ap", &prop, &size))
				if (size == 4)
					bcopy(prop, &production, size);
		}
		if (!production) {
#if defined(APPLE_ARM64_ARCH_FAMILY)
			// Enable coresight debug registers on debug-fused chips
			coresight_debug_enabled = TRUE;
#endif
		}

		start_cpu_paddr = ml_static_vtop((vm_offset_t)&start_cpu);
		resume_idle_cpu_paddr = ml_static_vtop((vm_offset_t)&resume_idle_cpu);
	}

#if WITH_CLASSIC_S2R
	if (cpu_data_ptr == &BootCpuData) {
		static addr64_t SleepToken_low_paddr = (addr64_t)NULL;
		if (sleepTokenBuffer != (vm_offset_t) NULL) {
			SleepToken_low_paddr = ml_vtophys(sleepTokenBuffer);
		}
		else {
			panic("No sleep token buffer");
		}

		bcopy_phys((addr64_t)ml_static_vtop((vm_offset_t)running_signature),
		           SleepToken_low_paddr, sizeof(SleepToken));
		flush_dcache((vm_offset_t)SleepToken, sizeof(SleepToken), TRUE);
	};
#endif

	cpu_data_ptr->cpu_reset_handler = resume_idle_cpu_paddr;
	clean_dcache((vm_offset_t)cpu_data_ptr, sizeof(cpu_data_t), FALSE);
}

_Atomic uint32_t cpu_idle_count = 0;

void
machine_track_platform_idle(boolean_t entry)
{
	if (entry)
		(void)__c11_atomic_fetch_add(&cpu_idle_count, 1, __ATOMIC_RELAXED);
	else
		(void)__c11_atomic_fetch_sub(&cpu_idle_count, 1, __ATOMIC_RELAXED);
}

#if WITH_CLASSIC_S2R
void
sleep_token_buffer_init(void)
{
	cpu_data_t	*cpu_data_ptr = getCpuDatap();
	DTEntry		entry;
	size_t		size;
	void		**prop;

	if ((cpu_data_ptr == &BootCpuData) && (sleepTokenBuffer == (vm_offset_t) NULL)) {
		/* Find the stpage node in the device tree */
		if (kSuccess != DTLookupEntry(0, "stram", &entry))
			return;

		if (kSuccess != DTGetProperty(entry, "reg", (void **)&prop, (unsigned int *)&size))
			return;

		/* Map the page into the kernel space */
		sleepTokenBuffer = ml_io_map(((vm_offset_t *)prop)[0], ((vm_size_t *)prop)[1]);
	}
}
#endif

