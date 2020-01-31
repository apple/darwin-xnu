/*
 * Copyright (c) 2007-2019 Apple Inc. All rights reserved.
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
#include <debug.h>

#include <types.h>

#include <mach/mach_types.h>
#include <mach/thread_status.h>
#include <mach/vm_types.h>

#include <kern/kern_types.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/misc_protos.h>
#include <kern/mach_param.h>
#include <kern/spl.h>
#include <kern/machine.h>
#include <kern/kalloc.h>
#include <kern/kpc.h>

#include <arm/proc_reg.h>
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <arm/cpuid.h>

#include <vm/vm_map.h>
#include <vm/vm_protos.h>

#include <sys/kdebug.h>

extern int      debug_task;

zone_t		ads_zone;		/* zone for debug_state area */

/*
 * Routine:	consider_machine_collect
 *
 */
void
consider_machine_collect(void)
{
	pmap_gc();
}

/*
 * Routine:	consider_machine_adjust
 *
 */
void
consider_machine_adjust(void)
{
}

/*
 * Routine:	machine_switch_context
 *
 */
thread_t
machine_switch_context(
		       thread_t old,
		       thread_continue_t continuation,
		       thread_t new)
{
	thread_t retval;
	cpu_data_t	*cpu_data_ptr;

#define machine_switch_context_kprintf(x...)	/* kprintf("machine_switch_con
						 * text: " x) */

	cpu_data_ptr = getCpuDatap();
	if (old == new)
		panic("machine_switch_context");

	kpc_off_cpu(old);

	pmap_set_pmap(new->map->pmap, new);

	new->machine.CpuDatap = cpu_data_ptr;

#if __SMP__
	/* TODO: Should this be ordered? */
	old->machine.machine_thread_flags &= ~MACHINE_THREAD_FLAGS_ON_CPU;
	new->machine.machine_thread_flags |= MACHINE_THREAD_FLAGS_ON_CPU;
#endif /* __SMP__ */

	machine_switch_context_kprintf("old= %x contination = %x new = %x\n", old, continuation, new);
	retval = Switch_context(old, continuation, new);
	assert(retval != NULL);

	return retval;
}

/*
 * Routine:	machine_thread_create
 *
 */
kern_return_t
machine_thread_create(
		      thread_t thread,
#if	!__ARM_USER_PROTECT__
		      __unused
#endif
		      task_t task)
{

#define machine_thread_create_kprintf(x...)	/* kprintf("machine_thread_create: " x) */

	machine_thread_create_kprintf("thread = %x\n", thread);

	if (current_thread() != thread) {
		thread->machine.CpuDatap = (cpu_data_t *)0;
	}
	thread->machine.preemption_count = 0;
	thread->machine.cthread_self = 0;
	thread->machine.cthread_data = 0;
#if	__ARM_USER_PROTECT__
	{
	struct pmap *new_pmap = vm_map_pmap(task->map);

	thread->machine.kptw_ttb = ((unsigned int) kernel_pmap->ttep) | TTBR_SETUP;
	thread->machine.asid = new_pmap->asid;
	if (new_pmap->tte_index_max == NTTES) {
		thread->machine.uptw_ttc = 2;
		thread->machine.uptw_ttb = ((unsigned int) new_pmap->ttep) | TTBR_SETUP;
	} else {
		thread->machine.uptw_ttc = 1;
		thread->machine.uptw_ttb = ((unsigned int) new_pmap->ttep ) | TTBR_SETUP;
	}
	}
#endif
	machine_thread_state_initialize(thread);

	return (KERN_SUCCESS);
}

/*
 * Routine:	machine_thread_destroy
 *
 */
void
machine_thread_destroy(
		       thread_t thread)
{

        if (thread->machine.DebugData != NULL) {
		if (thread->machine.DebugData == getCpuDatap()->cpu_user_debug)
			arm_debug_set(NULL);
		zfree(ads_zone, thread->machine.DebugData);
	}
}


/*
 * Routine:	machine_thread_init
 *
 */
void
machine_thread_init(void)
{
	ads_zone = zinit(sizeof(arm_debug_state_t),
					 THREAD_CHUNK * (sizeof(arm_debug_state_t)),
					 THREAD_CHUNK * (sizeof(arm_debug_state_t)),
					 "arm debug state");
}


/*
 * Routine:	get_useraddr
 *
 */
user_addr_t
get_useraddr()
{
	return (current_thread()->machine.PcbData.pc);
}

/*
 * Routine:	machine_stack_detach
 *
 */
vm_offset_t
machine_stack_detach(
		     thread_t thread)
{
	vm_offset_t     stack;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_DETACH),
		     (uintptr_t)thread_tid(thread), thread->priority, thread->sched_pri, 0, 0);

	stack = thread->kernel_stack;
	thread->kernel_stack = 0;
	thread->machine.kstackptr = 0;

	return (stack);
}


/*
 * Routine:	machine_stack_attach
 *
 */
void
machine_stack_attach(
		     thread_t thread,
		     vm_offset_t stack)
{
	struct arm_saved_state *savestate;

#define machine_stack_attach_kprintf(x...)	/* kprintf("machine_stack_attach: " x) */

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_ATTACH),
		     (uintptr_t)thread_tid(thread), thread->priority, thread->sched_pri, 0, 0);

	thread->kernel_stack = stack;
	thread->machine.kstackptr = stack + kernel_stack_size - sizeof(struct thread_kernel_state);
	thread_initialize_kernel_state(thread);
	savestate = (struct arm_saved_state *) thread->machine.kstackptr;

	savestate->lr = (uint32_t) thread_continue;
	savestate->sp = thread->machine.kstackptr;
	savestate->r[7] = 0x0UL;
	savestate->r[9] = (uint32_t) NULL;
	savestate->cpsr = PSR_SVC_MODE | PSR_INTMASK;
	machine_stack_attach_kprintf("thread = %x pc = %x, sp = %x\n", thread, savestate->lr, savestate->sp);
}


/*
 * Routine:	machine_stack_handoff
 *
 */
void
machine_stack_handoff(
		      thread_t old,
		      thread_t new)
{
	vm_offset_t     stack;
	cpu_data_t	*cpu_data_ptr;

	kpc_off_cpu(old);

	stack = machine_stack_detach(old);
	cpu_data_ptr = getCpuDatap();
	new->kernel_stack = stack;
	new->machine.kstackptr = stack + kernel_stack_size - sizeof(struct thread_kernel_state);
	if (stack == old->reserved_stack) {
		assert(new->reserved_stack);
		old->reserved_stack = new->reserved_stack;
		new->reserved_stack = stack;
	}

	pmap_set_pmap(new->map->pmap, new);
	new->machine.CpuDatap = cpu_data_ptr;

#if __SMP__
	/* TODO: Should this be ordered? */
	old->machine.machine_thread_flags &= ~MACHINE_THREAD_FLAGS_ON_CPU;
	new->machine.machine_thread_flags |= MACHINE_THREAD_FLAGS_ON_CPU;
#endif /* __SMP__ */

	machine_set_current_thread(new);
	thread_initialize_kernel_state(new);

	return;
}


/*
 * Routine:	call_continuation
 *
 */
void
call_continuation(
		  thread_continue_t continuation,
		  void *parameter,
		  wait_result_t wresult, 
		  boolean_t enable_interrupts)
{
#define call_continuation_kprintf(x...)	/* kprintf("call_continuation_kprintf:
					 *  " x) */

	call_continuation_kprintf("thread = %x continuation = %x, stack = %x\n", current_thread(), continuation, current_thread()->machine.kstackptr);
	Call_continuation(continuation, parameter, wresult, enable_interrupts);
}

void arm_debug_set(arm_debug_state_t *debug_state)
{
	/* If this CPU supports the memory-mapped debug interface, use it, otherwise
	 * attempt the Extended CP14 interface.  The two routines need to be kept in sync,
	 * functionality-wise.
	 */
	struct cpu_data *cpu_data_ptr;
	arm_debug_info_t *debug_info = arm_debug_info();
	boolean_t       intr;

	intr = ml_set_interrupts_enabled(FALSE);
	cpu_data_ptr = getCpuDatap();

	// Set current user debug
	cpu_data_ptr->cpu_user_debug = debug_state;

	if (debug_info->memory_mapped_core_debug) {
		int i;
		uintptr_t debug_map = cpu_data_ptr->cpu_debug_interface_map;

		// unlock debug registers
		*(volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGLAR) = ARM_DBG_LOCK_ACCESS_KEY;

		// read DBGPRSR to clear the sticky power-down bit (necessary to access debug registers)
		*(volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGPRSR);

		// enable monitor mode (needed to set and use debug registers)
		*(volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGDSCR) |= ARM_DBGDSCR_MDBGEN;

		// first turn off all breakpoints/watchpoints
		for (i = 0; i < 16; i++) {
			((volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGBCR))[i] = 0;
			((volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGWCR))[i] = 0;
		}

		// if (debug_state == NULL) disable monitor mode
		if (debug_state == NULL) {
			*(volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGDSCR) &= ~ARM_DBGDSCR_MDBGEN;
		} else {
			for (i = 0; i < 16; i++) {
				((volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGBVR))[i] = debug_state->bvr[i];
				((volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGBCR))[i] = debug_state->bcr[i];
				((volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGWVR))[i] = debug_state->wvr[i];
				((volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGWCR))[i] = debug_state->wcr[i];
			}
		}	    

		// lock debug registers
		*(volatile uint32_t *)(debug_map + ARM_DEBUG_OFFSET_DBGLAR) = 0;

    } else if (debug_info->coprocessor_core_debug) {
		arm_debug_set_cp14(debug_state);
	}

	(void) ml_set_interrupts_enabled(intr);

	return;
}

/*
 * Duplicate one arm_debug_state_t to another.  "all" parameter
 * is ignored in the case of ARM -- Is this the right assumption?
 */
void
copy_debug_state(
		arm_debug_state_t *src,
		arm_debug_state_t *target,
		__unused boolean_t all)
{
	bcopy(src, target, sizeof(arm_debug_state_t));
}

kern_return_t
machine_thread_set_tsd_base(
	thread_t			thread,
	mach_vm_offset_t	tsd_base)
{

	if (thread->task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	if (tsd_base & 0x3) {
		return KERN_INVALID_ARGUMENT;
	}

	if (tsd_base > UINT32_MAX)
		tsd_base = 0ULL;

	thread->machine.cthread_self = tsd_base;

	/* For current thread, make the TSD base active immediately */
	if (thread == current_thread()) {

		mp_disable_preemption();
		__asm__ volatile(
			"mrc    p15, 0, r6, c13, c0, 3\n"
			"and	r6, r6, #3\n"
			"orr	r6, r6, %0\n"
			"mcr	p15, 0, r6, c13, c0, 3\n"
			:		/* output */
			: "r"((uint32_t)tsd_base)	/* input */
			: "r6"		/* clobbered register */
			);
		mp_enable_preemption();

	}

	return KERN_SUCCESS;
}

void
machine_tecs(__unused thread_t thr)
{
}

int
machine_csv(__unused cpuvn_e cve)
{
	return 0;
}
