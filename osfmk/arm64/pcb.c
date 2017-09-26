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

#if MONOTONIC
#include <kern/monotonic.h>
#endif /* MONOTONIC */

#include <machine/atomic.h>
#include <arm64/proc_reg.h>
#include <arm64/machine_machdep.h>
#include <arm/cpu_data_internal.h>
#include <arm/machdep_call.h>
#include <arm/misc_protos.h>
#include <arm/cpuid.h>

#include <vm/vm_map.h>
#include <vm/vm_protos.h>

#include <sys/kdebug.h>

#define USER_SS_ZONE_ALLOC_SIZE (0x4000)

extern int debug_task;

zone_t ads_zone;     /* zone for debug_state area */
zone_t user_ss_zone; /* zone for user arm_context_t allocations */

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
	pmap_t          new_pmap;
	cpu_data_t	*cpu_data_ptr;

#define machine_switch_context_kprintf(x...)	/* kprintf("machine_switch_con
						 * text: " x) */

	cpu_data_ptr = getCpuDatap();
	if (old == new)
		panic("machine_switch_context");

	kpc_off_cpu(old);


	new_pmap = new->map->pmap;
	if (old->map->pmap != new_pmap)
		pmap_switch(new_pmap);

	new->machine.CpuDatap = cpu_data_ptr;

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
		      task_t task)
{
	arm_context_t *thread_user_ss = NULL;
	kern_return_t result = KERN_SUCCESS;

#define machine_thread_create_kprintf(x...)	/* kprintf("machine_thread_create: " x) */

	machine_thread_create_kprintf("thread = %x\n", thread);

	if (current_thread() != thread) {
		thread->machine.CpuDatap = (cpu_data_t *)0;
	}
	thread->machine.preemption_count = 0;
	thread->machine.cthread_self = 0;
	thread->machine.cthread_data = 0;


	if (task != kernel_task) {
		/* If this isn't a kernel thread, we'll have userspace state. */
		thread->machine.contextData = (arm_context_t *)zalloc(user_ss_zone);

		if (!thread->machine.contextData) {
			return KERN_FAILURE;
		}

		thread->machine.upcb = &thread->machine.contextData->ss;
		thread->machine.uNeon = &thread->machine.contextData->ns;

		if (task_has_64BitAddr(task)) {
			thread->machine.upcb->ash.flavor = ARM_SAVED_STATE64;
			thread->machine.upcb->ash.count = ARM_SAVED_STATE64_COUNT;
			thread->machine.uNeon->nsh.flavor = ARM_NEON_SAVED_STATE64;
			thread->machine.uNeon->nsh.count = ARM_NEON_SAVED_STATE64_COUNT;
		} else {
			thread->machine.upcb->ash.flavor = ARM_SAVED_STATE32;
			thread->machine.upcb->ash.count = ARM_SAVED_STATE32_COUNT;
			thread->machine.uNeon->nsh.flavor = ARM_NEON_SAVED_STATE32;
			thread->machine.uNeon->nsh.count = ARM_NEON_SAVED_STATE32_COUNT;
		}
	} else {
		thread->machine.upcb = NULL;
		thread->machine.uNeon = NULL;
		thread->machine.contextData = NULL;
	}

	bzero(&thread->machine.perfctrl_state, sizeof(thread->machine.perfctrl_state));

	result = machine_thread_state_initialize(thread);

	if (result != KERN_SUCCESS) {
		thread_user_ss = thread->machine.contextData;
		thread->machine.upcb = NULL;
		thread->machine.uNeon = NULL;
		thread->machine.contextData = NULL;
		zfree(user_ss_zone, thread_user_ss);
	}

	return result;
}

/*
 * Routine:	machine_thread_destroy
 *
 */
void
machine_thread_destroy(
		       thread_t thread)
{
	arm_context_t *thread_user_ss;

	if (thread->machine.contextData) {
		/* Disassociate the user save state from the thread before we free it. */
		thread_user_ss = thread->machine.contextData;
		thread->machine.upcb = NULL;
		thread->machine.uNeon = NULL;
		thread->machine.contextData = NULL;
		zfree(user_ss_zone, thread_user_ss);
	}

        if (thread->machine.DebugData != NULL) {
		if (thread->machine.DebugData == getCpuDatap()->cpu_user_debug) {
			arm_debug_set(NULL);
		}

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

	/*
	 * Create a zone for the user save state.  At the time this zone was created,
	 * the user save state was 848 bytes, and the matching kalloc zone was 1024
	 * bytes, which would result in significant amounts of wasted space if we
	 * simply used kalloc to allocate the user saved state.
	 *
	 * 0x4000 has been chosen as the allocation size, as it results in 272 bytes
	 * of wasted space per chunk, which should correspond to 19 allocations.
	 */
	user_ss_zone = zinit(sizeof(arm_context_t),
	                     CONFIG_THREAD_MAX * (sizeof(arm_context_t)),
	                     USER_SS_ZONE_ALLOC_SIZE,
	                     "user save state");
}


/*
 * Routine:	get_useraddr
 *
 */
user_addr_t
get_useraddr()
{
	return (get_saved_state_pc(current_thread()->machine.upcb));
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
	struct arm_context *context;
	struct arm_saved_state64 *savestate;

#define machine_stack_attach_kprintf(x...)	/* kprintf("machine_stack_attach: " x) */

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_ATTACH),
		     (uintptr_t)thread_tid(thread), thread->priority, thread->sched_pri, 0, 0);

	thread->kernel_stack = stack;
	thread->machine.kstackptr = stack + kernel_stack_size - sizeof(struct thread_kernel_state);
	thread_initialize_kernel_state(thread);

	machine_stack_attach_kprintf("kstackptr: %lx\n", (vm_address_t)thread->machine.kstackptr);

	context = &((thread_kernel_state_t) thread->machine.kstackptr)->machine;
	savestate = saved_state64(&context->ss);
	savestate->fp = 0;
	savestate->lr = (uintptr_t)thread_continue;
	savestate->sp = thread->machine.kstackptr;
	savestate->cpsr = PSR64_KERNEL_DEFAULT;
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
	pmap_t          new_pmap;
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


	new_pmap = new->map->pmap;
	if (old->map->pmap != new_pmap)
		pmap_switch(new_pmap);

	new->machine.CpuDatap = cpu_data_ptr;
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
		  wait_result_t wresult)
{
#define call_continuation_kprintf(x...)	/* kprintf("call_continuation_kprintf:" x) */

	call_continuation_kprintf("thread = %p continuation = %p, stack = %p\n", current_thread(), continuation, current_thread()->machine.kstackptr);
	Call_continuation(continuation, parameter, wresult, current_thread()->machine.kstackptr);
}

void arm_debug_set32(arm_debug_state_t *debug_state)
{
	struct cpu_data 	*cpu_data_ptr;
	arm_debug_info_t 	*debug_info = arm_debug_info();
	volatile uint64_t	state;
	boolean_t       	intr, set_mde = 0;
	arm_debug_state_t 	off_state;
	uint32_t 			i;

	intr = ml_set_interrupts_enabled(FALSE);
	cpu_data_ptr = getCpuDatap();

	// Set current user debug
	cpu_data_ptr->cpu_user_debug = debug_state;

	if (NULL == debug_state) {
		bzero(&off_state, sizeof(off_state));
		debug_state = &off_state;
	}

	switch (debug_info->num_breakpoint_pairs) {
	case 16:
		__asm__ volatile("msr DBGBVR15_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[15]));
		__asm__ volatile("msr DBGBCR15_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[15]));
	case 15:
		__asm__ volatile("msr DBGBVR14_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[14]));
		__asm__ volatile("msr DBGBCR14_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[14]));
	case 14:
		__asm__ volatile("msr DBGBVR13_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[13]));
		__asm__ volatile("msr DBGBCR13_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[13]));
	case 13:
		__asm__ volatile("msr DBGBVR12_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[12]));
		__asm__ volatile("msr DBGBCR12_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[12]));
	case 12:
		__asm__ volatile("msr DBGBVR11_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[11]));
		__asm__ volatile("msr DBGBCR11_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[11]));
	case 11:
		__asm__ volatile("msr DBGBVR10_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[10]));
		__asm__ volatile("msr DBGBCR10_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[10]));
	case 10:
		__asm__ volatile("msr DBGBVR9_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[9]));
		__asm__ volatile("msr DBGBCR9_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[9]));
	case 9:
		__asm__ volatile("msr DBGBVR8_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[8]));
		__asm__ volatile("msr DBGBCR8_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[8]));
	case 8:
		__asm__ volatile("msr DBGBVR7_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[7]));
		__asm__ volatile("msr DBGBCR7_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[7]));
	case 7:
		__asm__ volatile("msr DBGBVR6_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[6]));
		__asm__ volatile("msr DBGBCR6_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[6]));
	case 6:
		__asm__ volatile("msr DBGBVR5_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[5]));
		__asm__ volatile("msr DBGBCR5_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[5]));
	case 5:
		__asm__ volatile("msr DBGBVR4_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[4]));
		__asm__ volatile("msr DBGBCR4_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[4]));
	case 4:
		__asm__ volatile("msr DBGBVR3_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[3]));
		__asm__ volatile("msr DBGBCR3_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[3]));
	case 3:
		__asm__ volatile("msr DBGBVR2_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[2]));
		__asm__ volatile("msr DBGBCR2_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[2]));
	case 2:
		__asm__ volatile("msr DBGBVR1_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[1]));
		__asm__ volatile("msr DBGBCR1_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[1]));
	case 1:
		__asm__ volatile("msr DBGBVR0_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bvr[0]));
		__asm__ volatile("msr DBGBCR0_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.bcr[0]));
	default:
		break;
	}

	switch (debug_info->num_watchpoint_pairs) {
	case 16:
		__asm__ volatile("msr DBGWVR15_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[15]));
		__asm__ volatile("msr DBGWCR15_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[15]));
	case 15:
		__asm__ volatile("msr DBGWVR14_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[14]));
		__asm__ volatile("msr DBGWCR14_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[14]));
	case 14:
		__asm__ volatile("msr DBGWVR13_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[13]));
		__asm__ volatile("msr DBGWCR13_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[13]));
	case 13:
		__asm__ volatile("msr DBGWVR12_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[12]));
		__asm__ volatile("msr DBGWCR12_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[12]));
	case 12:
		__asm__ volatile("msr DBGWVR11_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[11]));
		__asm__ volatile("msr DBGWCR11_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[11]));
	case 11:
		__asm__ volatile("msr DBGWVR10_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[10]));
		__asm__ volatile("msr DBGWCR10_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[10]));
	case 10:
		__asm__ volatile("msr DBGWVR9_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[9]));
		__asm__ volatile("msr DBGWCR9_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[9]));
	case 9:
		__asm__ volatile("msr DBGWVR8_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[8]));
		__asm__ volatile("msr DBGWCR8_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[8]));
	case 8:
		__asm__ volatile("msr DBGWVR7_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[7]));
		__asm__ volatile("msr DBGWCR7_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[7]));
	case 7:
		__asm__ volatile("msr DBGWVR6_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[6]));
		__asm__ volatile("msr DBGWCR6_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[6]));
	case 6:
		__asm__ volatile("msr DBGWVR5_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[5]));
		__asm__ volatile("msr DBGWCR5_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[5]));
	case 5:
		__asm__ volatile("msr DBGWVR4_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[4]));
		__asm__ volatile("msr DBGWCR4_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[4]));
	case 4:
		__asm__ volatile("msr DBGWVR3_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[3]));
		__asm__ volatile("msr DBGWCR3_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[3]));
	case 3:
		__asm__ volatile("msr DBGWVR2_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[2]));
		__asm__ volatile("msr DBGWCR2_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[2]));
	case 2:
		__asm__ volatile("msr DBGWVR1_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[1]));
		__asm__ volatile("msr DBGWCR1_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[1]));
	case 1:
		__asm__ volatile("msr DBGWVR0_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wvr[0]));
		__asm__ volatile("msr DBGWCR0_EL1, %0" : : "r"((uint64_t)debug_state->uds.ds32.wcr[0]));
	default:
		break;
	}

	for (i = 0; i < debug_info->num_breakpoint_pairs; i++) {
		if (0 != debug_state->uds.ds32.bcr[i]) {
			set_mde = 1;
			break;
		}
	}

	for (i = 0; i < debug_info->num_watchpoint_pairs; i++) {
		if (0 != debug_state->uds.ds32.wcr[i]) {
			set_mde = 1;
			break;
		}
	}

	/*
	 * Breakpoint/Watchpoint Enable
	 */
	if (set_mde) {

		__asm__ volatile("mrs %0, MDSCR_EL1" : "=r"(state));
		state |= 0x8000; // MDSCR_EL1[MDE]
		__asm__ volatile("msr MDSCR_EL1, %0" : : "r"(state));

	} else {

		__asm__ volatile("mrs %0, MDSCR_EL1" : "=r"(state));
		state &= ~0x8000;
		__asm__ volatile("msr MDSCR_EL1, %0" : : "r"(state));

	}
		
	/*
	 * Software debug single step enable
	 */
	if (debug_state->uds.ds32.mdscr_el1 & 0x1) {

		__asm__ volatile("mrs %0, MDSCR_EL1" : "=r"(state));
		state = (state & ~0x8000) | 0x1; // ~MDE | SS : no brk/watch while single stepping (which we've set)
		__asm__ volatile("msr MDSCR_EL1, %0" : : "r"(state));

		set_saved_state_cpsr((current_thread()->machine.upcb), 
			get_saved_state_cpsr((current_thread()->machine.upcb)) | PSR64_SS);

	} else {

		__asm__ volatile("mrs %0, MDSCR_EL1" : "=r"(state));
		state &= ~0x1;
		__asm__ volatile("msr MDSCR_EL1, %0" : : "r"(state));

#if SINGLE_STEP_RETIRE_ERRATA
		// Workaround for radar 20619637
		__builtin_arm_isb(ISB_SY);
#endif
	}

	(void) ml_set_interrupts_enabled(intr);

	return;
}

void arm_debug_set64(arm_debug_state_t *debug_state)
{
	struct cpu_data 	*cpu_data_ptr;
	arm_debug_info_t 	*debug_info = arm_debug_info();
	volatile uint64_t	state;
	boolean_t       	intr, set_mde = 0;
	arm_debug_state_t 	off_state;
	uint32_t 			i;

	intr = ml_set_interrupts_enabled(FALSE);
	cpu_data_ptr = getCpuDatap();

	// Set current user debug
	cpu_data_ptr->cpu_user_debug = debug_state;

	if (NULL == debug_state) {
		bzero(&off_state, sizeof(off_state));
		debug_state = &off_state;
	}

	switch (debug_info->num_breakpoint_pairs) {
	case 16:
		__asm__ volatile("msr DBGBVR15_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[15]));
		__asm__ volatile("msr DBGBCR15_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[15]));
	case 15:
		__asm__ volatile("msr DBGBVR14_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[14]));
		__asm__ volatile("msr DBGBCR14_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[14]));
	case 14:
		__asm__ volatile("msr DBGBVR13_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[13]));
		__asm__ volatile("msr DBGBCR13_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[13]));
	case 13:
		__asm__ volatile("msr DBGBVR12_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[12]));
		__asm__ volatile("msr DBGBCR12_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[12]));
	case 12:
		__asm__ volatile("msr DBGBVR11_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[11]));
		__asm__ volatile("msr DBGBCR11_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[11]));
	case 11:
		__asm__ volatile("msr DBGBVR10_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[10]));
		__asm__ volatile("msr DBGBCR10_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[10]));
	case 10:
		__asm__ volatile("msr DBGBVR9_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[9]));
		__asm__ volatile("msr DBGBCR9_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[9]));
	case 9:
		__asm__ volatile("msr DBGBVR8_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[8]));
		__asm__ volatile("msr DBGBCR8_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[8]));
	case 8:
		__asm__ volatile("msr DBGBVR7_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[7]));
		__asm__ volatile("msr DBGBCR7_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[7]));
	case 7:
		__asm__ volatile("msr DBGBVR6_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[6]));
		__asm__ volatile("msr DBGBCR6_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[6]));
	case 6:
		__asm__ volatile("msr DBGBVR5_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[5]));
		__asm__ volatile("msr DBGBCR5_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[5]));
	case 5:
		__asm__ volatile("msr DBGBVR4_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[4]));
		__asm__ volatile("msr DBGBCR4_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[4]));
	case 4:
		__asm__ volatile("msr DBGBVR3_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[3]));
		__asm__ volatile("msr DBGBCR3_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[3]));
	case 3:
		__asm__ volatile("msr DBGBVR2_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[2]));
		__asm__ volatile("msr DBGBCR2_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[2]));
	case 2:
		__asm__ volatile("msr DBGBVR1_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[1]));
		__asm__ volatile("msr DBGBCR1_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[1]));
	case 1:
		__asm__ volatile("msr DBGBVR0_EL1, %0" : : "r"(debug_state->uds.ds64.bvr[0]));
		__asm__ volatile("msr DBGBCR0_EL1, %0" : : "r"(debug_state->uds.ds64.bcr[0]));
	default:
		break;
	}

	switch (debug_info->num_watchpoint_pairs) {
	case 16:
		__asm__ volatile("msr DBGWVR15_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[15]));
		__asm__ volatile("msr DBGWCR15_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[15]));
	case 15:
		__asm__ volatile("msr DBGWVR14_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[14]));
		__asm__ volatile("msr DBGWCR14_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[14]));
	case 14:
		__asm__ volatile("msr DBGWVR13_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[13]));
		__asm__ volatile("msr DBGWCR13_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[13]));
	case 13:
		__asm__ volatile("msr DBGWVR12_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[12]));
		__asm__ volatile("msr DBGWCR12_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[12]));
	case 12:
		__asm__ volatile("msr DBGWVR11_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[11]));
		__asm__ volatile("msr DBGWCR11_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[11]));
	case 11:
		__asm__ volatile("msr DBGWVR10_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[10]));
		__asm__ volatile("msr DBGWCR10_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[10]));
	case 10:
		__asm__ volatile("msr DBGWVR9_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[9]));
		__asm__ volatile("msr DBGWCR9_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[9]));
	case 9:
		__asm__ volatile("msr DBGWVR8_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[8]));
		__asm__ volatile("msr DBGWCR8_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[8]));
	case 8:
		__asm__ volatile("msr DBGWVR7_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[7]));
		__asm__ volatile("msr DBGWCR7_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[7]));
	case 7:
		__asm__ volatile("msr DBGWVR6_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[6]));
		__asm__ volatile("msr DBGWCR6_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[6]));
	case 6:
		__asm__ volatile("msr DBGWVR5_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[5]));
		__asm__ volatile("msr DBGWCR5_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[5]));
	case 5:
		__asm__ volatile("msr DBGWVR4_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[4]));
		__asm__ volatile("msr DBGWCR4_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[4]));
	case 4:
		__asm__ volatile("msr DBGWVR3_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[3]));
		__asm__ volatile("msr DBGWCR3_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[3]));
	case 3:
		__asm__ volatile("msr DBGWVR2_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[2]));
		__asm__ volatile("msr DBGWCR2_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[2]));
	case 2:
		__asm__ volatile("msr DBGWVR1_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[1]));
		__asm__ volatile("msr DBGWCR1_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[1]));
	case 1:
		__asm__ volatile("msr DBGWVR0_EL1, %0" : : "r"(debug_state->uds.ds64.wvr[0]));
		__asm__ volatile("msr DBGWCR0_EL1, %0" : : "r"(debug_state->uds.ds64.wcr[0]));
	default:
		break;
	}

	for (i = 0; i < debug_info->num_breakpoint_pairs; i++) {
		if (0 != debug_state->uds.ds64.bcr[i]) {
			set_mde = 1;
			break;
		}
	}

	for (i = 0; i < debug_info->num_watchpoint_pairs; i++) {
		if (0 != debug_state->uds.ds64.wcr[i]) {
			set_mde = 1;
			break;
		}
	}

	/*
	 * Breakpoint/Watchpoint Enable
	 */
	if (set_mde) {

		__asm__ volatile("mrs %0, MDSCR_EL1" : "=r"(state));
		state |= 0x8000; // MDSCR_EL1[MDE]
		__asm__ volatile("msr MDSCR_EL1, %0" : : "r"(state));

	}
		
	/*
	 * Software debug single step enable
	 */
	if (debug_state->uds.ds64.mdscr_el1 & 0x1) {

		__asm__ volatile("mrs %0, MDSCR_EL1" : "=r"(state));
		state = (state & ~0x8000) | 0x1; // ~MDE | SS : no brk/watch while single stepping (which we've set)
		__asm__ volatile("msr MDSCR_EL1, %0" : : "r"(state));

		set_saved_state_cpsr((current_thread()->machine.upcb), 
			get_saved_state_cpsr((current_thread()->machine.upcb)) | PSR64_SS);

	} else {

		__asm__ volatile("mrs %0, MDSCR_EL1" : "=r"(state));
		state &= ~0x1;
		__asm__ volatile("msr MDSCR_EL1, %0" : : "r"(state));

#if SINGLE_STEP_RETIRE_ERRATA
		// Workaround for radar 20619637
		__builtin_arm_isb(ISB_SY);
#endif
	}

	(void) ml_set_interrupts_enabled(intr);

	return;
}

void arm_debug_set(arm_debug_state_t *debug_state)
{
	if (debug_state) {
		switch (debug_state->dsh.flavor) {
		case ARM_DEBUG_STATE32:
			arm_debug_set32(debug_state);
			break;
		case ARM_DEBUG_STATE64:
			arm_debug_set64(debug_state);
			break;
		default:
			panic("arm_debug_set");
			break;
		}
	} else {
		if (thread_is_64bit(current_thread()))
			arm_debug_set64(debug_state);
		else
			arm_debug_set32(debug_state);
	}
}

#define VM_MAX_ADDRESS32          ((vm_address_t) 0x80000000)
boolean_t
debug_legacy_state_is_valid(arm_legacy_debug_state_t *debug_state)
{
	arm_debug_info_t 	*debug_info = arm_debug_info();
	uint32_t i;
	for (i = 0; i < debug_info->num_breakpoint_pairs; i++) {
		if (0 != debug_state->bcr[i] && VM_MAX_ADDRESS32 <= debug_state->bvr[i])
			return FALSE;
	}

	for (i = 0; i < debug_info->num_watchpoint_pairs; i++) {
		if (0 != debug_state->wcr[i] && VM_MAX_ADDRESS32 <= debug_state->wvr[i])
			return FALSE;
	}
	return TRUE;
}

boolean_t
debug_state_is_valid32(arm_debug_state32_t *debug_state)
{
	arm_debug_info_t 	*debug_info = arm_debug_info();
	uint32_t i;
	for (i = 0; i < debug_info->num_breakpoint_pairs; i++) {
		if (0 != debug_state->bcr[i] && VM_MAX_ADDRESS32 <= debug_state->bvr[i])
			return FALSE;
	}

	for (i = 0; i < debug_info->num_watchpoint_pairs; i++) {
		if (0 != debug_state->wcr[i] && VM_MAX_ADDRESS32 <= debug_state->wvr[i])
			return FALSE;
	}
	return TRUE;
}

boolean_t
debug_state_is_valid64(arm_debug_state64_t *debug_state)
{
	arm_debug_info_t 	*debug_info = arm_debug_info();
	uint32_t i;
	for (i = 0; i < debug_info->num_breakpoint_pairs; i++) {
		if (0 != debug_state->bcr[i] && MACH_VM_MAX_ADDRESS <= debug_state->bvr[i])
			return FALSE;
	}

	for (i = 0; i < debug_info->num_watchpoint_pairs; i++) {
		if (0 != debug_state->wcr[i] && MACH_VM_MAX_ADDRESS <= debug_state->wvr[i])
			return FALSE;
	}
	return TRUE;
}

/*
 * Duplicate one arm_debug_state_t to another.  "all" parameter
 * is ignored in the case of ARM -- Is this the right assumption?
 */
void
copy_legacy_debug_state(
		arm_legacy_debug_state_t *src,
		arm_legacy_debug_state_t *target,
		__unused boolean_t all)
{
	bcopy(src, target, sizeof(arm_legacy_debug_state_t));
}

void
copy_debug_state32(
		arm_debug_state32_t *src,
		arm_debug_state32_t *target,
		__unused boolean_t all)
{
	bcopy(src, target, sizeof(arm_debug_state32_t));
}

void
copy_debug_state64(
		arm_debug_state64_t *src,
		arm_debug_state64_t *target,
		__unused boolean_t all)
{
	bcopy(src, target, sizeof(arm_debug_state64_t));
}

kern_return_t
machine_thread_set_tsd_base(
	thread_t			thread,
	mach_vm_offset_t	tsd_base)
{

	if (thread->task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	if (tsd_base & MACHDEP_CPUNUM_MASK) {
		return KERN_INVALID_ARGUMENT;
	}

	if (thread_is_64bit(thread)) {
		if (tsd_base > vm_map_max(thread->map))
			tsd_base = 0ULL;
	} else {
		if (tsd_base > UINT32_MAX)
			tsd_base = 0ULL;
	}

	thread->machine.cthread_self = tsd_base;

	/* For current thread, make the TSD base active immediately */
	if (thread == current_thread()) {
		uint64_t cpunum, tpidrro_el0;

		mp_disable_preemption();
		tpidrro_el0 = get_tpidrro();
		cpunum = tpidrro_el0 & (MACHDEP_CPUNUM_MASK);
		set_tpidrro(tsd_base | cpunum);
		mp_enable_preemption();

	}

	return KERN_SUCCESS;
}
