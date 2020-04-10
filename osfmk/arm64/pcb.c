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
 * Routine: consider_machine_collect
 *
 */
void
consider_machine_collect(void)
{
	pmap_gc();
}

/*
 * Routine: consider_machine_adjust
 *
 */
void
consider_machine_adjust(void)
{
}


/*
 * Routine: machine_switch_context
 *
 */
thread_t
machine_switch_context(thread_t old,
                       thread_continue_t continuation,
                       thread_t new)
{
	thread_t retval;
	pmap_t       new_pmap;
	cpu_data_t * cpu_data_ptr;

#define machine_switch_context_kprintf(x...) \
	/* kprintf("machine_switch_context: " x) */

	cpu_data_ptr = getCpuDatap();
	if (old == new)
		panic("machine_switch_context");

	kpc_off_cpu(old);



	new_pmap = new->map->pmap;
	if (old->map->pmap != new_pmap)
		pmap_switch(new_pmap);


	new->machine.CpuDatap = cpu_data_ptr;

	/* TODO: Should this be ordered? */
	old->machine.machine_thread_flags &= ~MACHINE_THREAD_FLAGS_ON_CPU;
	new->machine.machine_thread_flags |= MACHINE_THREAD_FLAGS_ON_CPU;

	machine_switch_context_kprintf("old= %x contination = %x new = %x\n", old, continuation, new);

	retval = Switch_context(old, continuation, new);
	assert(retval != NULL);

	return retval;
}

boolean_t
machine_thread_on_core(thread_t thread)
{
	return thread->machine.machine_thread_flags & MACHINE_THREAD_FLAGS_ON_CPU;
}

/*
 * Routine: machine_thread_create
 *
 */
kern_return_t
machine_thread_create(thread_t thread,
                      task_t task)
{
	arm_context_t *thread_user_ss = NULL;
	kern_return_t result = KERN_SUCCESS;

#define machine_thread_create_kprintf(x...) \
	/* kprintf("machine_thread_create: " x) */

	machine_thread_create_kprintf("thread = %x\n", thread);

	if (current_thread() != thread) {
		thread->machine.CpuDatap = (cpu_data_t *)0;
	}
	thread->machine.preemption_count = 0;
	thread->machine.cthread_self = 0;
#if defined(HAS_APPLE_PAC)
	thread->machine.rop_pid = task->rop_pid;
	thread->machine.disable_user_jop = task->disable_user_jop;
#endif


	if (task != kernel_task) {
		/* If this isn't a kernel thread, we'll have userspace state. */
		thread->machine.contextData = (arm_context_t *)zalloc(user_ss_zone);

		if (!thread->machine.contextData) {
			result = KERN_FAILURE;
			goto done;
		}

		thread->machine.upcb = &thread->machine.contextData->ss;
		thread->machine.uNeon = &thread->machine.contextData->ns;

		if (task_has_64Bit_data(task)) {
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

done:
	if (result != KERN_SUCCESS) {
		thread_user_ss = thread->machine.contextData;

		if (thread_user_ss) {
			thread->machine.upcb = NULL;
			thread->machine.uNeon = NULL;
			thread->machine.contextData = NULL;
			zfree(user_ss_zone, thread_user_ss);
		}
	}

	return result;
}

/*
 * Routine: machine_thread_destroy
 *
 */
void
machine_thread_destroy(thread_t thread)
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
 * Routine: machine_thread_init
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
 * Routine: get_useraddr
 *
 */
user_addr_t
get_useraddr()
{
	return (get_saved_state_pc(current_thread()->machine.upcb));
}

/*
 * Routine: machine_stack_detach
 *
 */
vm_offset_t
machine_stack_detach(thread_t thread)
{
	vm_offset_t stack;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_DETACH),
	             (uintptr_t)thread_tid(thread), thread->priority, thread->sched_pri, 0, 0);

	stack = thread->kernel_stack;
	thread->kernel_stack = 0;
	thread->machine.kstackptr = 0;

	return (stack);
}


/*
 * Routine: machine_stack_attach
 *
 */
void
machine_stack_attach(thread_t thread,
                     vm_offset_t stack)
{
	struct arm_context *context;
	struct arm_saved_state64 *savestate;
	uint32_t current_el;

#define machine_stack_attach_kprintf(x...) \
	/* kprintf("machine_stack_attach: " x) */

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_ATTACH),
	             (uintptr_t)thread_tid(thread), thread->priority, thread->sched_pri, 0, 0);

	thread->kernel_stack = stack;
	thread->machine.kstackptr = stack + kernel_stack_size - sizeof(struct thread_kernel_state);
	thread_initialize_kernel_state(thread);

	machine_stack_attach_kprintf("kstackptr: %lx\n", (vm_address_t)thread->machine.kstackptr);

	current_el = (uint32_t) __builtin_arm_rsr64("CurrentEL");
	context = &((thread_kernel_state_t) thread->machine.kstackptr)->machine;
	savestate = saved_state64(&context->ss);
	savestate->fp = 0;
	savestate->sp = thread->machine.kstackptr;
#if defined(HAS_APPLE_PAC)
	/* Sign the initial kernel stack saved state */
	const uint32_t default_cpsr = PSR64_KERNEL_DEFAULT & ~PSR64_MODE_EL_MASK;
	asm volatile (
		"mov	x0, %[ss]"				"\n"

		"mov	x1, xzr"				"\n"
		"str	x1, [x0, %[SS64_PC]]"			"\n"

		"mov	x2, %[default_cpsr_lo]"			"\n"
		"movk	x2, %[default_cpsr_hi], lsl #16"	"\n"
		"mrs	x3, CurrentEL"				"\n"
		"orr	w2, w2, w3"				"\n"
		"str	w2, [x0, %[SS64_CPSR]]"			"\n"

		"adrp	x3, _thread_continue@page"		"\n"
		"add	x3, x3, _thread_continue@pageoff"	"\n"
		"str	x3, [x0, %[SS64_LR]]"			"\n"

		"mov	x4, xzr"				"\n"
		"mov	x5, xzr"				"\n"
		"stp	x4, x5, [x0, %[SS64_X16]]"		"\n"

		"mov	x6, lr"					"\n"
		"bl	_ml_sign_thread_state"			"\n"
		"mov	lr, x6"					"\n"
		:
		: [ss]			"r"(&context->ss),
		  [default_cpsr_lo]	"M"(default_cpsr & 0xFFFF),
		  [default_cpsr_hi]	"M"(default_cpsr >> 16),
		  [SS64_X16]		"i"(offsetof(struct arm_saved_state, ss_64.x[16])),
		  [SS64_PC]		"i"(offsetof(struct arm_saved_state, ss_64.pc)),
		  [SS64_CPSR]		"i"(offsetof(struct arm_saved_state, ss_64.cpsr)),
		  [SS64_LR]		"i"(offsetof(struct arm_saved_state, ss_64.lr))
		: "x0", "x1", "x2", "x3", "x4", "x5", "x6"
	);
#else
	savestate->lr = (uintptr_t)thread_continue;
	savestate->cpsr = (PSR64_KERNEL_DEFAULT & ~PSR64_MODE_EL_MASK) | current_el;
#endif /* defined(HAS_APPLE_PAC) */
	machine_stack_attach_kprintf("thread = %p pc = %llx, sp = %llx\n", thread, savestate->lr, savestate->sp);
}


/*
 * Routine: machine_stack_handoff
 *
 */
void
machine_stack_handoff(thread_t old,
                      thread_t new)
{
	vm_offset_t  stack;
	pmap_t       new_pmap;
	cpu_data_t * cpu_data_ptr;

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

	/* TODO: Should this be ordered? */
	old->machine.machine_thread_flags &= ~MACHINE_THREAD_FLAGS_ON_CPU;
	new->machine.machine_thread_flags |= MACHINE_THREAD_FLAGS_ON_CPU;

	machine_set_current_thread(new);
	thread_initialize_kernel_state(new);

	return;
}


/*
 * Routine: call_continuation
 *
 */
void
call_continuation(thread_continue_t continuation,
                  void *parameter,
                  wait_result_t wresult,
                  boolean_t enable_interrupts)
{
#define call_continuation_kprintf(x...) \
	/* kprintf("call_continuation_kprintf:" x) */

	call_continuation_kprintf("thread = %p continuation = %p, stack = %p\n", current_thread(), continuation, current_thread()->machine.kstackptr);
	Call_continuation(continuation, parameter, wresult, enable_interrupts);
}

#define SET_DBGBCRn(n, value, accum) \
	__asm__ volatile( \
		"msr DBGBCR" #n "_EL1, %[val]\n" \
		"orr %[result], %[result], %[val]\n" \
		: [result] "+r"(accum) : [val] "r"((value)))

#define SET_DBGBVRn(n, value) \
	__asm__ volatile("msr DBGBVR" #n "_EL1, %0" : : "r"(value))

#define SET_DBGWCRn(n, value, accum) \
	__asm__ volatile( \
		"msr DBGWCR" #n "_EL1, %[val]\n" \
		"orr %[result], %[result], %[val]\n" \
		: [result] "+r"(accum) : [val] "r"((value)))

#define SET_DBGWVRn(n, value) \
	__asm__ volatile("msr DBGWVR" #n "_EL1, %0" : : "r"(value))

void arm_debug_set32(arm_debug_state_t *debug_state)
{
	struct cpu_data *  cpu_data_ptr;
	arm_debug_info_t * debug_info    = arm_debug_info();
	boolean_t          intr, set_mde = 0;
	arm_debug_state_t  off_state;
	uint32_t           i;
	uint64_t           all_ctrls = 0;

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
		SET_DBGBVRn(15, (uint64_t)debug_state->uds.ds32.bvr[15]);
		SET_DBGBCRn(15, (uint64_t)debug_state->uds.ds32.bcr[15], all_ctrls);
	case 15:
		SET_DBGBVRn(14, (uint64_t)debug_state->uds.ds32.bvr[14]);
		SET_DBGBCRn(14, (uint64_t)debug_state->uds.ds32.bcr[14], all_ctrls);
	case 14:
		SET_DBGBVRn(13, (uint64_t)debug_state->uds.ds32.bvr[13]);
		SET_DBGBCRn(13, (uint64_t)debug_state->uds.ds32.bcr[13], all_ctrls);
	case 13:
		SET_DBGBVRn(12, (uint64_t)debug_state->uds.ds32.bvr[12]);
		SET_DBGBCRn(12, (uint64_t)debug_state->uds.ds32.bcr[12], all_ctrls);
	case 12:
		SET_DBGBVRn(11, (uint64_t)debug_state->uds.ds32.bvr[11]);
		SET_DBGBCRn(11, (uint64_t)debug_state->uds.ds32.bcr[11], all_ctrls);
	case 11:
		SET_DBGBVRn(10, (uint64_t)debug_state->uds.ds32.bvr[10]);
		SET_DBGBCRn(10, (uint64_t)debug_state->uds.ds32.bcr[10], all_ctrls);
	case 10:
		SET_DBGBVRn(9, (uint64_t)debug_state->uds.ds32.bvr[9]);
		SET_DBGBCRn(9, (uint64_t)debug_state->uds.ds32.bcr[9], all_ctrls);
	case 9:
		SET_DBGBVRn(8, (uint64_t)debug_state->uds.ds32.bvr[8]);
		SET_DBGBCRn(8, (uint64_t)debug_state->uds.ds32.bcr[8], all_ctrls);
	case 8:
		SET_DBGBVRn(7, (uint64_t)debug_state->uds.ds32.bvr[7]);
		SET_DBGBCRn(7, (uint64_t)debug_state->uds.ds32.bcr[7], all_ctrls);
	case 7:
		SET_DBGBVRn(6, (uint64_t)debug_state->uds.ds32.bvr[6]);
		SET_DBGBCRn(6, (uint64_t)debug_state->uds.ds32.bcr[6], all_ctrls);
	case 6:
		SET_DBGBVRn(5, (uint64_t)debug_state->uds.ds32.bvr[5]);
		SET_DBGBCRn(5, (uint64_t)debug_state->uds.ds32.bcr[5], all_ctrls);
	case 5:
		SET_DBGBVRn(4, (uint64_t)debug_state->uds.ds32.bvr[4]);
		SET_DBGBCRn(4, (uint64_t)debug_state->uds.ds32.bcr[4], all_ctrls);
	case 4:
		SET_DBGBVRn(3, (uint64_t)debug_state->uds.ds32.bvr[3]);
		SET_DBGBCRn(3, (uint64_t)debug_state->uds.ds32.bcr[3], all_ctrls);
	case 3:
		SET_DBGBVRn(2, (uint64_t)debug_state->uds.ds32.bvr[2]);
		SET_DBGBCRn(2, (uint64_t)debug_state->uds.ds32.bcr[2], all_ctrls);
	case 2:
		SET_DBGBVRn(1, (uint64_t)debug_state->uds.ds32.bvr[1]);
		SET_DBGBCRn(1, (uint64_t)debug_state->uds.ds32.bcr[1], all_ctrls);
	case 1:
		SET_DBGBVRn(0, (uint64_t)debug_state->uds.ds32.bvr[0]);
		SET_DBGBCRn(0, (uint64_t)debug_state->uds.ds32.bcr[0], all_ctrls);
	default:
		break;
	}

	switch (debug_info->num_watchpoint_pairs) {
	case 16:
		SET_DBGWVRn(15, (uint64_t)debug_state->uds.ds32.wvr[15]);
		SET_DBGWCRn(15, (uint64_t)debug_state->uds.ds32.wcr[15], all_ctrls);
	case 15:
		SET_DBGWVRn(14, (uint64_t)debug_state->uds.ds32.wvr[14]);
		SET_DBGWCRn(14, (uint64_t)debug_state->uds.ds32.wcr[14], all_ctrls);
	case 14:
		SET_DBGWVRn(13, (uint64_t)debug_state->uds.ds32.wvr[13]);
		SET_DBGWCRn(13, (uint64_t)debug_state->uds.ds32.wcr[13], all_ctrls);
	case 13:
		SET_DBGWVRn(12, (uint64_t)debug_state->uds.ds32.wvr[12]);
		SET_DBGWCRn(12, (uint64_t)debug_state->uds.ds32.wcr[12], all_ctrls);
	case 12:
		SET_DBGWVRn(11, (uint64_t)debug_state->uds.ds32.wvr[11]);
		SET_DBGWCRn(11, (uint64_t)debug_state->uds.ds32.wcr[11], all_ctrls);
	case 11:
		SET_DBGWVRn(10, (uint64_t)debug_state->uds.ds32.wvr[10]);
		SET_DBGWCRn(10, (uint64_t)debug_state->uds.ds32.wcr[10], all_ctrls);
	case 10:
		SET_DBGWVRn(9, (uint64_t)debug_state->uds.ds32.wvr[9]);
		SET_DBGWCRn(9, (uint64_t)debug_state->uds.ds32.wcr[9], all_ctrls);
	case 9:
		SET_DBGWVRn(8, (uint64_t)debug_state->uds.ds32.wvr[8]);
		SET_DBGWCRn(8, (uint64_t)debug_state->uds.ds32.wcr[8], all_ctrls);
	case 8:
		SET_DBGWVRn(7, (uint64_t)debug_state->uds.ds32.wvr[7]);
		SET_DBGWCRn(7, (uint64_t)debug_state->uds.ds32.wcr[7], all_ctrls);
	case 7:
		SET_DBGWVRn(6, (uint64_t)debug_state->uds.ds32.wvr[6]);
		SET_DBGWCRn(6, (uint64_t)debug_state->uds.ds32.wcr[6], all_ctrls);
	case 6:
		SET_DBGWVRn(5, (uint64_t)debug_state->uds.ds32.wvr[5]);
		SET_DBGWCRn(5, (uint64_t)debug_state->uds.ds32.wcr[5], all_ctrls);
	case 5:
		SET_DBGWVRn(4, (uint64_t)debug_state->uds.ds32.wvr[4]);
		SET_DBGWCRn(4, (uint64_t)debug_state->uds.ds32.wcr[4], all_ctrls);
	case 4:
		SET_DBGWVRn(3, (uint64_t)debug_state->uds.ds32.wvr[3]);
		SET_DBGWCRn(3, (uint64_t)debug_state->uds.ds32.wcr[3], all_ctrls);
	case 3:
		SET_DBGWVRn(2, (uint64_t)debug_state->uds.ds32.wvr[2]);
		SET_DBGWCRn(2, (uint64_t)debug_state->uds.ds32.wcr[2], all_ctrls);
	case 2:
		SET_DBGWVRn(1, (uint64_t)debug_state->uds.ds32.wvr[1]);
		SET_DBGWCRn(1, (uint64_t)debug_state->uds.ds32.wcr[1], all_ctrls);
	case 1:
		SET_DBGWVRn(0, (uint64_t)debug_state->uds.ds32.wvr[0]);
		SET_DBGWCRn(0, (uint64_t)debug_state->uds.ds32.wcr[0], all_ctrls);
	default:
		break;
	}

#if defined(CONFIG_KERNEL_INTEGRITY)
	if ((all_ctrls & (ARM_DBG_CR_MODE_CONTROL_PRIVILEGED | ARM_DBG_CR_HIGHER_MODE_ENABLE)) != 0) {
		panic("sorry, self-hosted debug is not supported: 0x%llx", all_ctrls);
	}
#endif

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
		update_mdscr(0, 0x8000); // MDSCR_EL1[MDE]
	} else {
		update_mdscr(0x8000, 0);
	}

	/*
	 * Software debug single step enable
	 */
	if (debug_state->uds.ds32.mdscr_el1 & 0x1) {
		update_mdscr(0x8000, 1); // ~MDE | SS : no brk/watch while single stepping (which we've set)

		mask_saved_state_cpsr(current_thread()->machine.upcb, PSR64_SS, 0);
	} else {

		update_mdscr(0x1, 0);

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
	struct cpu_data *  cpu_data_ptr;
	arm_debug_info_t * debug_info    = arm_debug_info();
	boolean_t          intr, set_mde = 0;
	arm_debug_state_t  off_state;
	uint32_t           i;
	uint64_t           all_ctrls = 0;

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
		SET_DBGBVRn(15, debug_state->uds.ds64.bvr[15]);
		SET_DBGBCRn(15, (uint64_t)debug_state->uds.ds64.bcr[15], all_ctrls);
	case 15:
		SET_DBGBVRn(14, debug_state->uds.ds64.bvr[14]);
		SET_DBGBCRn(14, (uint64_t)debug_state->uds.ds64.bcr[14], all_ctrls);
	case 14:
		SET_DBGBVRn(13, debug_state->uds.ds64.bvr[13]);
		SET_DBGBCRn(13, (uint64_t)debug_state->uds.ds64.bcr[13], all_ctrls);
	case 13:
		SET_DBGBVRn(12, debug_state->uds.ds64.bvr[12]);
		SET_DBGBCRn(12, (uint64_t)debug_state->uds.ds64.bcr[12], all_ctrls);
	case 12:
		SET_DBGBVRn(11, debug_state->uds.ds64.bvr[11]);
		SET_DBGBCRn(11, (uint64_t)debug_state->uds.ds64.bcr[11], all_ctrls);
	case 11:
		SET_DBGBVRn(10, debug_state->uds.ds64.bvr[10]);
		SET_DBGBCRn(10, (uint64_t)debug_state->uds.ds64.bcr[10], all_ctrls);
	case 10:
		SET_DBGBVRn(9, debug_state->uds.ds64.bvr[9]);
		SET_DBGBCRn(9, (uint64_t)debug_state->uds.ds64.bcr[9], all_ctrls);
	case 9:
		SET_DBGBVRn(8, debug_state->uds.ds64.bvr[8]);
		SET_DBGBCRn(8, (uint64_t)debug_state->uds.ds64.bcr[8], all_ctrls);
	case 8:
		SET_DBGBVRn(7, debug_state->uds.ds64.bvr[7]);
		SET_DBGBCRn(7, (uint64_t)debug_state->uds.ds64.bcr[7], all_ctrls);
	case 7:
		SET_DBGBVRn(6, debug_state->uds.ds64.bvr[6]);
		SET_DBGBCRn(6, (uint64_t)debug_state->uds.ds64.bcr[6], all_ctrls);
	case 6:
		SET_DBGBVRn(5, debug_state->uds.ds64.bvr[5]);
		SET_DBGBCRn(5, (uint64_t)debug_state->uds.ds64.bcr[5], all_ctrls);
	case 5:
		SET_DBGBVRn(4, debug_state->uds.ds64.bvr[4]);
		SET_DBGBCRn(4, (uint64_t)debug_state->uds.ds64.bcr[4], all_ctrls);
	case 4:
		SET_DBGBVRn(3, debug_state->uds.ds64.bvr[3]);
		SET_DBGBCRn(3, (uint64_t)debug_state->uds.ds64.bcr[3], all_ctrls);
	case 3:
		SET_DBGBVRn(2, debug_state->uds.ds64.bvr[2]);
		SET_DBGBCRn(2, (uint64_t)debug_state->uds.ds64.bcr[2], all_ctrls);
	case 2:
		SET_DBGBVRn(1, debug_state->uds.ds64.bvr[1]);
		SET_DBGBCRn(1, (uint64_t)debug_state->uds.ds64.bcr[1], all_ctrls);
	case 1:
		SET_DBGBVRn(0, debug_state->uds.ds64.bvr[0]);
		SET_DBGBCRn(0, (uint64_t)debug_state->uds.ds64.bcr[0], all_ctrls);
	default:
		break;
	}

	switch (debug_info->num_watchpoint_pairs) {
	case 16:
		SET_DBGWVRn(15, debug_state->uds.ds64.wvr[15]);
		SET_DBGWCRn(15, (uint64_t)debug_state->uds.ds64.wcr[15], all_ctrls);
	case 15:
		SET_DBGWVRn(14, debug_state->uds.ds64.wvr[14]);
		SET_DBGWCRn(14, (uint64_t)debug_state->uds.ds64.wcr[14], all_ctrls);
	case 14:
		SET_DBGWVRn(13, debug_state->uds.ds64.wvr[13]);
		SET_DBGWCRn(13, (uint64_t)debug_state->uds.ds64.wcr[13], all_ctrls);
	case 13:
		SET_DBGWVRn(12, debug_state->uds.ds64.wvr[12]);
		SET_DBGWCRn(12, (uint64_t)debug_state->uds.ds64.wcr[12], all_ctrls);
	case 12:
		SET_DBGWVRn(11, debug_state->uds.ds64.wvr[11]);
		SET_DBGWCRn(11, (uint64_t)debug_state->uds.ds64.wcr[11], all_ctrls);
	case 11:
		SET_DBGWVRn(10, debug_state->uds.ds64.wvr[10]);
		SET_DBGWCRn(10, (uint64_t)debug_state->uds.ds64.wcr[10], all_ctrls);
	case 10:
		SET_DBGWVRn(9, debug_state->uds.ds64.wvr[9]);
		SET_DBGWCRn(9, (uint64_t)debug_state->uds.ds64.wcr[9], all_ctrls);
	case 9:
		SET_DBGWVRn(8, debug_state->uds.ds64.wvr[8]);
		SET_DBGWCRn(8, (uint64_t)debug_state->uds.ds64.wcr[8], all_ctrls);
	case 8:
		SET_DBGWVRn(7, debug_state->uds.ds64.wvr[7]);
		SET_DBGWCRn(7, (uint64_t)debug_state->uds.ds64.wcr[7], all_ctrls);
	case 7:
		SET_DBGWVRn(6, debug_state->uds.ds64.wvr[6]);
		SET_DBGWCRn(6, (uint64_t)debug_state->uds.ds64.wcr[6], all_ctrls);
	case 6:
		SET_DBGWVRn(5, debug_state->uds.ds64.wvr[5]);
		SET_DBGWCRn(5, (uint64_t)debug_state->uds.ds64.wcr[5], all_ctrls);
	case 5:
		SET_DBGWVRn(4, debug_state->uds.ds64.wvr[4]);
		SET_DBGWCRn(4, (uint64_t)debug_state->uds.ds64.wcr[4], all_ctrls);
	case 4:
		SET_DBGWVRn(3, debug_state->uds.ds64.wvr[3]);
		SET_DBGWCRn(3, (uint64_t)debug_state->uds.ds64.wcr[3], all_ctrls);
	case 3:
		SET_DBGWVRn(2, debug_state->uds.ds64.wvr[2]);
		SET_DBGWCRn(2, (uint64_t)debug_state->uds.ds64.wcr[2], all_ctrls);
	case 2:
		SET_DBGWVRn(1, debug_state->uds.ds64.wvr[1]);
		SET_DBGWCRn(1, (uint64_t)debug_state->uds.ds64.wcr[1], all_ctrls);
	case 1:
		SET_DBGWVRn(0, debug_state->uds.ds64.wvr[0]);
		SET_DBGWCRn(0, (uint64_t)debug_state->uds.ds64.wcr[0], all_ctrls);
	default:
		break;
	}

#if defined(CONFIG_KERNEL_INTEGRITY)
	if ((all_ctrls & (ARM_DBG_CR_MODE_CONTROL_PRIVILEGED | ARM_DBG_CR_HIGHER_MODE_ENABLE)) != 0) {
		panic("sorry, self-hosted debug is not supported: 0x%llx", all_ctrls);
	}
#endif

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
		update_mdscr(0, 0x8000); // MDSCR_EL1[MDE]
	}

	/*
	 * Software debug single step enable
	 */
	if (debug_state->uds.ds64.mdscr_el1 & 0x1) {

		update_mdscr(0x8000, 1); // ~MDE | SS : no brk/watch while single stepping (which we've set)

		mask_saved_state_cpsr(current_thread()->machine.upcb, PSR64_SS, 0);
	} else {

		update_mdscr(0x1, 0);

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
		if (thread_is_64bit_data(current_thread()))
			arm_debug_set64(debug_state);
		else
			arm_debug_set32(debug_state);
	}
}

#define VM_MAX_ADDRESS32          ((vm_address_t) 0x80000000)
boolean_t
debug_legacy_state_is_valid(arm_legacy_debug_state_t *debug_state)
{
	arm_debug_info_t *debug_info = arm_debug_info();
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
	arm_debug_info_t *debug_info = arm_debug_info();
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
	arm_debug_info_t *debug_info = arm_debug_info();
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
copy_legacy_debug_state(arm_legacy_debug_state_t * src,
                        arm_legacy_debug_state_t * target,
                        __unused boolean_t         all)
{
	bcopy(src, target, sizeof(arm_legacy_debug_state_t));
}

void
copy_debug_state32(arm_debug_state32_t * src,
                   arm_debug_state32_t * target,
                   __unused boolean_t    all)
{
	bcopy(src, target, sizeof(arm_debug_state32_t));
}

void
copy_debug_state64(arm_debug_state64_t * src,
                   arm_debug_state64_t * target,
                   __unused boolean_t    all)
{
	bcopy(src, target, sizeof(arm_debug_state64_t));
}

kern_return_t
machine_thread_set_tsd_base(thread_t         thread,
                            mach_vm_offset_t tsd_base)
{
	if (thread->task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	if (tsd_base & MACHDEP_CPUNUM_MASK) {
		return KERN_INVALID_ARGUMENT;
	}

	if (thread_is_64bit_addr(thread)) {
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

void
machine_tecs(__unused thread_t thr)
{
}

int
machine_csv(__unused cpuvn_e cve)
{
	return 0;
}
