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
 *	File:	arm/cpu.c
 *
 *	cpu specific routines
 */

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
#include <arm/proc_reg.h>
#include <mach/processor_info.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <pexpert/arm/board_config.h>
#include <pexpert/arm/protos.h>
#include <sys/kdebug.h>

#include <machine/atomic.h>

#if KPC
#include <kern/kpc.h>
#endif

extern unsigned int resume_idle_cpu;
extern unsigned int start_cpu;

unsigned int   start_cpu_paddr;

extern boolean_t        idle_enable;
extern unsigned int     real_ncpus;
extern uint64_t         wake_abstime;

extern void* wfi_inst;
unsigned wfi_fast = 1;
unsigned patch_to_nop = 0xe1a00000;

void    *LowExceptionVectorsAddr;
#define IOS_STATE               (((vm_offset_t)LowExceptionVectorsAddr + 0x80))
#define IOS_STATE_SIZE  (0x08UL)
static const uint8_t suspend_signature[] = {'X', 'S', 'O', 'M', 'P', 'S', 'U', 'S'};
static const uint8_t running_signature[] = {'X', 'S', 'O', 'M', 'N', 'N', 'U', 'R'};

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
	cpu_data_ptr->cpu_reset_handler = (vm_offset_t) start_cpu_paddr;
	cpu_data_ptr->cpu_flags |= SleepState;
	cpu_data_ptr->cpu_user_debug = NULL;

	CleanPoC_Dcache();

	PE_cpu_machine_quiesce(cpu_data_ptr->cpu_id);
}

_Atomic uint32_t cpu_idle_count = 0;

/*
 *	Routine:	cpu_idle
 *	Function:
 */
void __attribute__((noreturn))
cpu_idle(void)
{
	cpu_data_t     *cpu_data_ptr = getCpuDatap();
	uint64_t        new_idle_timeout_ticks = 0x0ULL, lastPop;

	if ((!idle_enable) || (cpu_data_ptr->cpu_signal & SIGPdisabled)) {
		Idle_load_context();
	}
	if (!SetIdlePop()) {
		Idle_load_context();
	}
	lastPop = cpu_data_ptr->rtcPop;

	pmap_switch_user_ttb(kernel_pmap);
	cpu_data_ptr->cpu_active_thread = current_thread();
	if (cpu_data_ptr->cpu_user_debug) {
		arm_debug_set(NULL);
	}
	cpu_data_ptr->cpu_user_debug = NULL;

	if (cpu_data_ptr->cpu_idle_notify) {
		((processor_idle_t) cpu_data_ptr->cpu_idle_notify)(cpu_data_ptr->cpu_id, TRUE, &new_idle_timeout_ticks);
	}

	if (cpu_data_ptr->idle_timer_notify != 0) {
		if (new_idle_timeout_ticks == 0x0ULL) {
			/* turn off the idle timer */
			cpu_data_ptr->idle_timer_deadline = 0x0ULL;
		} else {
			/* set the new idle timeout */
			clock_absolutetime_interval_to_deadline(new_idle_timeout_ticks, &cpu_data_ptr->idle_timer_deadline);
		}
		timer_resync_deadlines();
		if (cpu_data_ptr->rtcPop != lastPop) {
			SetIdlePop();
		}
	}

#if KPC
	kpc_idle();
#endif

	platform_cache_idle_enter();
	cpu_idle_wfi((boolean_t) wfi_fast);
	platform_cache_idle_exit();

	ClearIdlePop(TRUE);
	cpu_idle_exit(FALSE);
}

/*
 *	Routine:	cpu_idle_exit
 *	Function:
 */
void
cpu_idle_exit(boolean_t from_reset __unused)
{
	uint64_t        new_idle_timeout_ticks = 0x0ULL;
	cpu_data_t     *cpu_data_ptr = getCpuDatap();

#if KPC
	kpc_idle_exit();
#endif


	pmap_set_pmap(cpu_data_ptr->cpu_active_thread->map->pmap, current_thread());

	if (cpu_data_ptr->cpu_idle_notify) {
		((processor_idle_t) cpu_data_ptr->cpu_idle_notify)(cpu_data_ptr->cpu_id, FALSE, &new_idle_timeout_ticks);
	}

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

	if (cdp->cpu_type != CPU_TYPE_ARM) {
		cdp->cpu_type = CPU_TYPE_ARM;

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
		case CPU_ARCH_ARMv4T:
		case CPU_ARCH_ARMv5T:
			cdp->cpu_subtype = CPU_SUBTYPE_ARM_V4T;
			break;
		case CPU_ARCH_ARMv5TE:
		case CPU_ARCH_ARMv5TEJ:
			if (cpu_info_p->arm_info.arm_implementor == CPU_VID_INTEL) {
				cdp->cpu_subtype = CPU_SUBTYPE_ARM_XSCALE;
			} else {
				cdp->cpu_subtype = CPU_SUBTYPE_ARM_V5TEJ;
			}
			break;
		case CPU_ARCH_ARMv6:
			cdp->cpu_subtype = CPU_SUBTYPE_ARM_V6;
			break;
		case CPU_ARCH_ARMv7:
			cdp->cpu_subtype = CPU_SUBTYPE_ARM_V7;
			break;
		case CPU_ARCH_ARMv7f:
			cdp->cpu_subtype = CPU_SUBTYPE_ARM_V7F;
			break;
		case CPU_ARCH_ARMv7s:
			cdp->cpu_subtype = CPU_SUBTYPE_ARM_V7S;
			break;
		case CPU_ARCH_ARMv7k:
			cdp->cpu_subtype = CPU_SUBTYPE_ARM_V7K;
			break;
		default:
			cdp->cpu_subtype = CPU_SUBTYPE_ARM_ALL;
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
}

void
cpu_stack_alloc(cpu_data_t *cpu_data_ptr)
{
	vm_offset_t             irq_stack = 0;
	vm_offset_t             fiq_stack = 0;

	kern_return_t kr = kernel_memory_allocate(kernel_map, &irq_stack,
	    INTSTACK_SIZE + (2 * PAGE_SIZE),
	    PAGE_MASK,
	    KMA_GUARD_FIRST | KMA_GUARD_LAST | KMA_KSTACK | KMA_KOBJECT,
	    VM_KERN_MEMORY_STACK);
	if (kr != KERN_SUCCESS) {
		panic("Unable to allocate cpu interrupt stack\n");
	}

	cpu_data_ptr->intstack_top = irq_stack + PAGE_SIZE + INTSTACK_SIZE;
	cpu_data_ptr->istackptr = cpu_data_ptr->intstack_top;

	kr = kernel_memory_allocate(kernel_map, &fiq_stack,
	    FIQSTACK_SIZE + (2 * PAGE_SIZE),
	    PAGE_MASK,
	    KMA_GUARD_FIRST | KMA_GUARD_LAST | KMA_KSTACK | KMA_KOBJECT,
	    VM_KERN_MEMORY_STACK);
	if (kr != KERN_SUCCESS) {
		panic("Unable to allocate cpu exception stack\n");
	}

	cpu_data_ptr->fiqstack_top = fiq_stack + PAGE_SIZE + FIQSTACK_SIZE;
	cpu_data_ptr->fiqstackptr = cpu_data_ptr->fiqstack_top;
}

void
cpu_data_free(cpu_data_t *cpu_data_ptr)
{
	if (cpu_data_ptr == &BootCpuData) {
		return;
	}

	cpu_processor_free( cpu_data_ptr->cpu_processor);
	(kfree)((void *)(cpu_data_ptr->intstack_top - INTSTACK_SIZE), INTSTACK_SIZE);
	(kfree)((void *)(cpu_data_ptr->fiqstack_top - FIQSTACK_SIZE), FIQSTACK_SIZE);
	kmem_free(kernel_map, (vm_offset_t)cpu_data_ptr, sizeof(cpu_data_t));
}

void
cpu_data_init(cpu_data_t *cpu_data_ptr)
{
	uint32_t i = 0;

	cpu_data_ptr->cpu_flags = 0;
#if     __arm__
	cpu_data_ptr->cpu_exc_vectors = (vm_offset_t)&ExceptionVectorsTable;
#endif
	cpu_data_ptr->interrupts_enabled = 0;
	cpu_data_ptr->cpu_int_state = 0;
	cpu_data_ptr->cpu_pending_ast = AST_NONE;
	cpu_data_ptr->cpu_cache_dispatch = (void *) 0;
	cpu_data_ptr->rtcPop = EndOfAllTime;
	cpu_data_ptr->rtclock_datap = &RTClockData;
	cpu_data_ptr->cpu_user_debug = NULL;
	cpu_data_ptr->cpu_base_timebase_low = 0;
	cpu_data_ptr->cpu_base_timebase_high = 0;
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

#if     __ARM_SMP__ && defined(ARMA7)
	cpu_data_ptr->cpu_CLWFlush_req = 0x0ULL;
	cpu_data_ptr->cpu_CLWFlush_last = 0x0ULL;
	cpu_data_ptr->cpu_CLWClean_req = 0x0ULL;
	cpu_data_ptr->cpu_CLWClean_last = 0x0ULL;
	cpu_data_ptr->cpu_CLW_active = 0x1UL;
#endif

	pmap_cpu_data_t * pmap_cpu_data_ptr = &cpu_data_ptr->cpu_pmap_cpu_data;

	pmap_cpu_data_ptr->cpu_user_pmap = (struct pmap *) NULL;
	pmap_cpu_data_ptr->cpu_user_pmap_stamp = 0;
	pmap_cpu_data_ptr->cpu_number = PMAP_INVALID_CPU_NUM;

	for (i = 0; i < (sizeof(pmap_cpu_data_ptr->cpu_asid_high_bits) / sizeof(*pmap_cpu_data_ptr->cpu_asid_high_bits)); i++) {
		pmap_cpu_data_ptr->cpu_asid_high_bits[i] = 0;
	}
	cpu_data_ptr->halt_status = CPU_NOT_HALTED;
}

kern_return_t
cpu_data_register(cpu_data_t *cpu_data_ptr)
{
	int cpu;

	cpu = OSIncrementAtomic((SInt32*)&real_ncpus);
	if (real_ncpus > MAX_CPUS) {
		return KERN_FAILURE;
	}

	cpu_data_ptr->cpu_number = cpu;
	CpuDataEntries[cpu].cpu_data_vaddr = cpu_data_ptr;
	CpuDataEntries[cpu].cpu_data_paddr = (void *)ml_vtophys((vm_offset_t)cpu_data_ptr);
	return KERN_SUCCESS;
}

kern_return_t
cpu_start(int cpu)
{
	kprintf("cpu_start() cpu: %d\n", cpu);
	if (cpu == cpu_number()) {
		cpu_machine_init();
		return KERN_SUCCESS;
	} else {
#if     __ARM_SMP__
		cpu_data_t      *cpu_data_ptr;
		thread_t        first_thread;

		cpu_data_ptr = CpuDataEntries[cpu].cpu_data_vaddr;
		cpu_data_ptr->cpu_reset_handler = (vm_offset_t) start_cpu_paddr;

		cpu_data_ptr->cpu_pmap_cpu_data.cpu_user_pmap = NULL;

		if (cpu_data_ptr->cpu_processor->next_thread != THREAD_NULL) {
			first_thread = cpu_data_ptr->cpu_processor->next_thread;
		} else {
			first_thread = cpu_data_ptr->cpu_processor->idle_thread;
		}
		cpu_data_ptr->cpu_active_thread = first_thread;
		first_thread->machine.CpuDatap = cpu_data_ptr;

		flush_dcache((vm_offset_t)&CpuDataEntries[cpu], sizeof(cpu_data_entry_t), FALSE);
		flush_dcache((vm_offset_t)cpu_data_ptr, sizeof(cpu_data_t), FALSE);
		(void) PE_cpu_start(cpu_data_ptr->cpu_id, (vm_offset_t)NULL, (vm_offset_t)NULL);
		return KERN_SUCCESS;
#else
		return KERN_FAILURE;
#endif
	}
}

void
cpu_timebase_init(boolean_t from_boot __unused)
{
	cpu_data_t *cdp = getCpuDatap();

	if (cdp->cpu_get_fiq_handler == NULL) {
		cdp->cpu_get_fiq_handler = rtclock_timebase_func.tbd_fiq_handler;
		cdp->cpu_get_decrementer_func = rtclock_timebase_func.tbd_get_decrementer;
		cdp->cpu_set_decrementer_func = rtclock_timebase_func.tbd_set_decrementer;
		cdp->cpu_tbd_hardware_addr = (void *)rtclock_timebase_addr;
		cdp->cpu_tbd_hardware_val = (void *)rtclock_timebase_val;
	}
	cdp->cpu_decrementer = 0x7FFFFFFFUL;
	cdp->cpu_timebase_low = 0x0UL;
	cdp->cpu_timebase_high = 0x0UL;

#if __arm__ && (__BIGGEST_ALIGNMENT__ > 4)
	/* For the newer ARMv7k ABI where 64-bit types are 64-bit aligned, but pointers
	 * are 32-bit. */
	cdp->cpu_base_timebase_low = rtclock_base_abstime_low;
	cdp->cpu_base_timebase_high = rtclock_base_abstime_high;
#else
	*((uint64_t *) &cdp->cpu_base_timebase_low) = rtclock_base_abstime;
#endif
}


__attribute__((noreturn))
void
ml_arm_sleep(void)
{
	cpu_data_t     *cpu_data_ptr = getCpuDatap();

	if (cpu_data_ptr == &BootCpuData) {
		cpu_data_t      *target_cdp;
		unsigned int    cpu;

		for (cpu = 0; cpu < MAX_CPUS; cpu++) {
			target_cdp = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;
			if (target_cdp == (cpu_data_t *)NULL) {
				break;
			}

			if (target_cdp == cpu_data_ptr) {
				continue;
			}

			while (target_cdp->cpu_sleep_token != ARM_CPU_ON_SLEEP_PATH) {
				;
			}
		}

		/* Now that the other cores have entered the sleep path, set
		 * the abstime fixup we'll use when we resume.*/
		rtclock_base_abstime = ml_get_timebase();
		wake_abstime = rtclock_base_abstime;
	} else {
		platform_cache_disable();
		CleanPoU_Dcache();
	}
	cpu_data_ptr->cpu_sleep_token = ARM_CPU_ON_SLEEP_PATH;
#if     __ARM_SMP__ && defined(ARMA7)
	cpu_data_ptr->cpu_CLWFlush_req = 0;
	cpu_data_ptr->cpu_CLWClean_req = 0;
	__builtin_arm_dmb(DMB_ISH);
	cpu_data_ptr->cpu_CLW_active = 0;
#endif
	if (cpu_data_ptr == &BootCpuData) {
		platform_cache_disable();
		platform_cache_shutdown();
		bcopy((const void *)suspend_signature, (void *)(IOS_STATE), IOS_STATE_SIZE);
	} else {
		CleanPoC_DcacheRegion((vm_offset_t) cpu_data_ptr, sizeof(cpu_data_t));
	}

	__builtin_arm_dsb(DSB_SY);
	while (TRUE) {
#if     __ARM_ENABLE_WFE_
		__builtin_arm_wfe();
#endif
	} /* Spin */
}

void
cpu_machine_idle_init(boolean_t from_boot)
{
	static const unsigned int       *BootArgs_paddr = (unsigned int *)NULL;
	static const unsigned int       *CpuDataEntries_paddr = (unsigned int *)NULL;
	static unsigned int             resume_idle_cpu_paddr = (unsigned int)NULL;
	cpu_data_t                      *cpu_data_ptr = getCpuDatap();

	if (from_boot) {
		unsigned int    jtag = 0;
		unsigned int    wfi;


		if (PE_parse_boot_argn("jtag", &jtag, sizeof(jtag))) {
			if (jtag != 0) {
				idle_enable = FALSE;
			} else {
				idle_enable = TRUE;
			}
		} else {
			idle_enable = TRUE;
		}

		if (!PE_parse_boot_argn("wfi", &wfi, sizeof(wfi))) {
			wfi = 1;
		}

		if (wfi == 0) {
			bcopy_phys((addr64_t)ml_static_vtop((vm_offset_t)&patch_to_nop),
			    (addr64_t)ml_static_vtop((vm_offset_t)&wfi_inst), sizeof(unsigned));
		}
		if (wfi == 2) {
			wfi_fast = 0;
		}

		LowExceptionVectorsAddr = (void *)ml_io_map(ml_vtophys((vm_offset_t)gPhysBase), PAGE_SIZE);

		/* Copy Exception Vectors low, but don't touch the sleep token */
		bcopy((void *)&ExceptionLowVectorsBase, (void *)LowExceptionVectorsAddr, 0x90);
		bcopy(((void *)(((vm_offset_t)&ExceptionLowVectorsBase) + 0xA0)), ((void *)(((vm_offset_t)LowExceptionVectorsAddr) + 0xA0)), ARM_PGBYTES - 0xA0);

		start_cpu_paddr = ml_static_vtop((vm_offset_t)&start_cpu);

		BootArgs_paddr = (unsigned int *)ml_static_vtop((vm_offset_t)BootArgs);
		bcopy_phys((addr64_t)ml_static_vtop((vm_offset_t)&BootArgs_paddr),
		    (addr64_t)((unsigned int)(gPhysBase) +
		    ((unsigned int)&(ResetHandlerData.boot_args) - (unsigned int)&ExceptionLowVectorsBase)),
		    4);

		CpuDataEntries_paddr = (unsigned int *)ml_static_vtop((vm_offset_t)CpuDataEntries);
		bcopy_phys((addr64_t)ml_static_vtop((vm_offset_t)&CpuDataEntries_paddr),
		    (addr64_t)((unsigned int)(gPhysBase) +
		    ((unsigned int)&(ResetHandlerData.cpu_data_entries) - (unsigned int)&ExceptionLowVectorsBase)),
		    4);

		CleanPoC_DcacheRegion((vm_offset_t) phystokv(gPhysBase), PAGE_SIZE);

		resume_idle_cpu_paddr = (unsigned int)ml_static_vtop((vm_offset_t)&resume_idle_cpu);
	}

	if (cpu_data_ptr == &BootCpuData) {
		bcopy(((const void *)running_signature), (void *)(IOS_STATE), IOS_STATE_SIZE);
	}
	;

	cpu_data_ptr->cpu_reset_handler = resume_idle_cpu_paddr;
	clean_dcache((vm_offset_t)cpu_data_ptr, sizeof(cpu_data_t), FALSE);
}

void
machine_track_platform_idle(boolean_t entry)
{
	if (entry) {
		(void)__c11_atomic_fetch_add(&cpu_idle_count, 1, __ATOMIC_RELAXED);
	} else {
		(void)__c11_atomic_fetch_sub(&cpu_idle_count, 1, __ATOMIC_RELAXED);
	}
}
