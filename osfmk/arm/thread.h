/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#ifndef _ARM_THREAD_H_
#define _ARM_THREAD_H_

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/arm/vm_types.h>
#include <mach/thread_status.h>

#ifdef MACH_KERNEL_PRIVATE
#include <arm/cpu_data.h>
#include <arm/proc_reg.h>
#include <os/base.h>
#endif

struct perfcontrol_state {
	uint64_t opaque[8] __attribute__((aligned(8)));
};

/*
 * Maps state flavor to number of words in the state:
 */
extern unsigned int _MachineStateCount[];

#ifdef MACH_KERNEL_PRIVATE
#if __arm64__
typedef arm_kernel_context_t machine_thread_kernel_state;
#else
typedef struct arm_saved_state machine_thread_kernel_state;
#endif
#include <kern/thread_kernel_state.h>

struct machine_thread {
#if __ARM_USER_PROTECT__
	unsigned int              uptw_ttb;
	unsigned int              kptw_ttb;
	unsigned int              asid;
#else
	unsigned int              reserved0;
	unsigned int              reserved1;
	unsigned int              reserved2;
#endif

#if __arm64__
	arm_context_t *           contextData;             /* allocated user context */
	arm_saved_state_t *       XNU_PTRAUTH_SIGNED_PTR("machine_thread.upcb") upcb;   /* pointer to user GPR state */
	arm_neon_saved_state_t *  uNeon;                   /* pointer to user VFP state */
	arm_saved_state_t *       kpcb;                    /* pointer to kernel GPR state */
	void *                    reserved3;
	long                      reserved4;
	uint64_t                  recover_far;
#elif __arm__
	struct arm_saved_state    PcbData;
#else
#error Unknown arch
#endif

#if defined(__arm__) && defined(__ARM_VFP__)
	// for packing reasons chtread_self and DebugData
	// are inside the the PcbData when __ARM_VFP__ is set
#define DebugData    PcbData.VFPpadding_DebugData
#define cthread_self PcbData.VFPpadding_cthread_self
#else
	arm_debug_state_t        *DebugData;
	vm_address_t              cthread_self;               /* for use of cthread package */
#endif

#if __arm64__
	uint32_t                  recover_esr;
#endif /* __arm64__ */

	vm_offset_t               kstackptr;                  /* top of kernel stack */
	struct perfcontrol_state  perfctrl_state;
#if __arm64__
	uint64_t                  energy_estimate_nj;
#endif
	uint64_t                  reserved5;

#if INTERRUPT_MASKED_DEBUG
	uint64_t                  intmask_timestamp;          /* timestamp of when interrupts were manually masked */
	uint64_t                  inthandler_timestamp;       /* timestamp of when interrupt handler started */
	unsigned int              int_type;                   /* interrupt type of the interrupt that was processed */
	uintptr_t                 int_handler_addr;           /* slid, ptrauth-stripped virtual address of the interrupt handler */
	uintptr_t                 int_vector;                 /* IOInterruptVector */
#endif

#if __arm64__ && defined(CONFIG_XNUPOST)
	volatile expected_fault_handler_t  expected_fault_handler;
	volatile uintptr_t                 expected_fault_addr;
#endif

	uint64_t                  reserved6;
	vm_offset_t               pcpu_data_base;
	struct cpu_data *         CpuDatap;               /* current per cpu data */
	unsigned int              preemption_count;       /* preemption count */
#if __arm64__
	uint16_t                  exception_trace_code;
#endif
	uint8_t                   reserved7;
#if defined(HAS_APPLE_PAC)
	uint8_t                   disable_user_jop;
	uint64_t                  rop_pid;
	uint64_t                  jop_pid;
#else
	uint8_t                   reserved8;
	uint64_t                  reserved9;
	uint64_t                  reserved10;
#endif
};
#endif

extern struct arm_saved_state *    get_user_regs(thread_t);
extern struct arm_saved_state *    find_user_regs(thread_t);
extern struct arm_saved_state *    find_kern_regs(thread_t);
extern struct arm_vfpsaved_state * find_user_vfp(thread_t);
#if defined(__arm__)
extern arm_debug_state_t *         find_debug_state(thread_t);
#elif defined(__arm64__)
extern arm_debug_state32_t *       find_debug_state32(thread_t);
extern arm_debug_state32_t *       find_or_allocate_debug_state32(thread_t);
extern arm_debug_state64_t *       find_debug_state64(thread_t);
extern arm_debug_state64_t *       find_or_allocate_debug_state64(thread_t);
extern arm_neon_saved_state_t *    get_user_neon_regs(thread_t);
#else
#error unknown arch
#endif

#define FIND_PERFCONTROL_STATE(th) (&th->machine.perfctrl_state)

#ifdef MACH_KERNEL_PRIVATE
#if __ARM_VFP__
extern void vfp_state_initialize(struct arm_vfpsaved_state *vfp_state);
extern void vfp_save(struct arm_vfpsaved_state *vfp_ss);
extern void vfp_load(struct arm_vfpsaved_state *vfp_ss);
#endif /* __ARM_VFP__ */
extern void arm_debug_set(arm_debug_state_t *debug_state);
#if defined(__arm64__)
extern void arm_debug_set32(arm_debug_state_t *debug_state);
extern void arm_debug_set64(arm_debug_state_t *debug_state);
#endif
#endif /* MACH_KERNEL_PRIVATE */

extern void *act_thread_csave(void);
extern void act_thread_catt(void *ctx);
extern void act_thread_cfree(void *ctx);


/*
 * Return address of the function that called current function, given
 * address of the first parameter of current function.
 */
#define GET_RETURN_PC(addr) (__builtin_return_address(0))

#endif /* _ARM_THREAD_H_ */
