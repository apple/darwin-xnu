/*
 * Copyright (c) 2012-2016 Apple Inc. All rights reserved.
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

#include <arm/caches_internal.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <arm/thread.h>
#include <arm/rtclock.h>
#include <arm/trap.h> /* for IS_ARM_GDB_TRAP() et al */
#include <arm64/proc_reg.h>
#include <arm64/machine_machdep.h>
#include <arm64/monotonic.h>
#include <arm64/instructions.h>

#include <kern/debug.h>
#include <kern/thread.h>
#include <mach/exception.h>
#include <mach/arm/traps.h>
#include <mach/vm_types.h>
#include <mach/machine/thread_status.h>

#include <machine/atomic.h>
#include <machine/limits.h>

#include <pexpert/arm/protos.h>

#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_fault.h>
#include <vm/vm_kern.h>

#include <sys/errno.h>
#include <sys/kdebug.h>
#include <kperf/kperf.h>

#include <kern/policy_internal.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif

#include <prng/entropy.h>



#ifndef __arm64__
#error Should only be compiling for arm64.
#endif

#define TEST_CONTEXT32_SANITY(context) \
	(context->ss.ash.flavor == ARM_SAVED_STATE32 && context->ss.ash.count == ARM_SAVED_STATE32_COUNT && \
	 context->ns.nsh.flavor == ARM_NEON_SAVED_STATE32 && context->ns.nsh.count == ARM_NEON_SAVED_STATE32_COUNT)

#define TEST_CONTEXT64_SANITY(context) \
	(context->ss.ash.flavor == ARM_SAVED_STATE64 && context->ss.ash.count == ARM_SAVED_STATE64_COUNT && \
	 context->ns.nsh.flavor == ARM_NEON_SAVED_STATE64 && context->ns.nsh.count == ARM_NEON_SAVED_STATE64_COUNT)

#define ASSERT_CONTEXT_SANITY(context) \
	assert(TEST_CONTEXT32_SANITY(context) || TEST_CONTEXT64_SANITY(context))


#define COPYIN(src, dst, size)                           \
	(PSR64_IS_KERNEL(get_saved_state_cpsr(state))) ? \
	copyin_kern(src, dst, size) :                    \
	copyin(src, dst, size)

#define COPYOUT(src, dst, size)                          \
	(PSR64_IS_KERNEL(get_saved_state_cpsr(state))) ? \
	copyout_kern(src, dst, size)                   : \
	copyout(src, dst, size)

// Below is for concatenating a string param to a string literal
#define STR1(x) #x
#define STR(x) STR1(x)

#define ARM64_KDBG_CODE_KERNEL (0 << 8)
#define ARM64_KDBG_CODE_USER   (1 << 8)
#define ARM64_KDBG_CODE_GUEST  (2 << 8)

_Static_assert(ARM64_KDBG_CODE_GUEST <= KDBG_CODE_MAX, "arm64 KDBG trace codes out of range");
_Static_assert(ARM64_KDBG_CODE_GUEST <= UINT16_MAX, "arm64 KDBG trace codes out of range");

void panic_with_thread_kernel_state(const char *msg, arm_saved_state_t *ss) __abortlike;

void sleh_synchronous_sp1(arm_context_t *, uint32_t, vm_offset_t) __abortlike;
void sleh_synchronous(arm_context_t *, uint32_t, vm_offset_t);
void sleh_irq(arm_saved_state_t *);
void sleh_fiq(arm_saved_state_t *);
void sleh_serror(arm_context_t *context, uint32_t esr, vm_offset_t far);
void sleh_invalid_stack(arm_context_t *context, uint32_t esr, vm_offset_t far) __dead2;

static void sleh_interrupt_handler_prologue(arm_saved_state_t *, unsigned int type);
static void sleh_interrupt_handler_epilogue(void);

static void handle_svc(arm_saved_state_t *);
static void handle_mach_absolute_time_trap(arm_saved_state_t *);
static void handle_mach_continuous_time_trap(arm_saved_state_t *);

static void handle_msr_trap(arm_saved_state_t *state, uint32_t esr);

extern kern_return_t arm_fast_fault(pmap_t, vm_map_address_t, vm_prot_t, bool, bool);

static void handle_uncategorized(arm_saved_state_t *);
static void handle_kernel_breakpoint(arm_saved_state_t *, uint32_t) __dead2;
static void handle_breakpoint(arm_saved_state_t *, uint32_t) __dead2;

typedef void (*abort_inspector_t)(uint32_t, fault_status_t *, vm_prot_t *);
static void inspect_instruction_abort(uint32_t, fault_status_t *, vm_prot_t *);
static void inspect_data_abort(uint32_t, fault_status_t *, vm_prot_t *);

static int is_vm_fault(fault_status_t);
static int is_translation_fault(fault_status_t);
static int is_alignment_fault(fault_status_t);

typedef void (*abort_handler_t)(arm_saved_state_t *, uint32_t, vm_offset_t, fault_status_t, vm_prot_t, vm_offset_t, expected_fault_handler_t);
static void handle_user_abort(arm_saved_state_t *, uint32_t, vm_offset_t, fault_status_t, vm_prot_t, vm_offset_t, expected_fault_handler_t);
static void handle_kernel_abort(arm_saved_state_t *, uint32_t, vm_offset_t, fault_status_t, vm_prot_t, vm_offset_t, expected_fault_handler_t);

static void handle_pc_align(arm_saved_state_t *ss) __dead2;
static void handle_sp_align(arm_saved_state_t *ss) __dead2;
static void handle_sw_step_debug(arm_saved_state_t *ss) __dead2;
static void handle_wf_trap(arm_saved_state_t *ss) __dead2;
static void handle_fp_trap(arm_saved_state_t *ss, uint32_t esr) __dead2;

static void handle_watchpoint(vm_offset_t fault_addr) __dead2;

static void handle_abort(arm_saved_state_t *, uint32_t, vm_offset_t, vm_offset_t, abort_inspector_t, abort_handler_t, expected_fault_handler_t);

static void handle_user_trapped_instruction32(arm_saved_state_t *, uint32_t esr) __dead2;

static void handle_simd_trap(arm_saved_state_t *, uint32_t esr) __dead2;

extern void mach_kauth_cred_uthread_update(void);
void   mach_syscall_trace_exit(unsigned int retval, unsigned int call_number);

struct uthread;
struct proc;

typedef uint32_t arm64_instr_t;

extern void
unix_syscall(struct arm_saved_state * regs, thread_t thread_act,
    struct uthread * uthread, struct proc * proc);

extern void
mach_syscall(struct arm_saved_state*);

#if CONFIG_DTRACE
extern kern_return_t dtrace_user_probe(arm_saved_state_t* regs);
extern boolean_t dtrace_tally_fault(user_addr_t);

/*
 * Traps for userland processing. Can't include bsd/sys/fasttrap_isa.h, so copy
 * and paste the trap instructions
 * over from that file. Need to keep these in sync!
 */
#define FASTTRAP_ARM32_INSTR 0xe7ffdefc
#define FASTTRAP_THUMB32_INSTR 0xdefc
#define FASTTRAP_ARM64_INSTR 0xe7eeee7e

#define FASTTRAP_ARM32_RET_INSTR 0xe7ffdefb
#define FASTTRAP_THUMB32_RET_INSTR 0xdefb
#define FASTTRAP_ARM64_RET_INSTR 0xe7eeee7d

/* See <rdar://problem/4613924> */
perfCallback tempDTraceTrapHook = NULL; /* Pointer to DTrace fbt trap hook routine */
#endif


#if CONFIG_PGTRACE
extern boolean_t pgtrace_enabled;
#endif

#if HAS_TWO_STAGE_SPR_LOCK
#ifdef CONFIG_XNUPOST
extern volatile vm_offset_t spr_lock_test_addr;
extern volatile uint32_t spr_lock_exception_esr;
#endif
#endif

#if INTERRUPT_MASKED_DEBUG
extern boolean_t interrupt_masked_debug;
#endif

extern void arm64_thread_exception_return(void) __dead2;

#if defined(APPLETYPHOON)
#define CPU_NAME "Typhoon"
#elif defined(APPLETWISTER)
#define CPU_NAME "Twister"
#elif defined(APPLEHURRICANE)
#define CPU_NAME "Hurricane"
#elif defined(APPLELIGHTNING)
#define CPU_NAME "Lightning"
#else
#define CPU_NAME "Unknown"
#endif

#if (CONFIG_KERNEL_INTEGRITY && defined(KERNEL_INTEGRITY_WT))
#define ESR_WT_SERROR(esr) (((esr) & 0xffffff00) == 0xbf575400)
#define ESR_WT_REASON(esr) ((esr) & 0xff)

#define WT_REASON_NONE           0
#define WT_REASON_INTEGRITY_FAIL 1
#define WT_REASON_BAD_SYSCALL    2
#define WT_REASON_NOT_LOCKED     3
#define WT_REASON_ALREADY_LOCKED 4
#define WT_REASON_SW_REQ         5
#define WT_REASON_PT_INVALID     6
#define WT_REASON_PT_VIOLATION   7
#define WT_REASON_REG_VIOLATION  8
#endif

#if defined(HAS_IPI)
void cpu_signal_handler(void);
extern unsigned int gFastIPI;
#endif /* defined(HAS_IPI) */

static arm_saved_state64_t *original_faulting_state = NULL;

TUNABLE(bool, fp_exceptions_enabled, "-fp_exceptions", false);

extern vm_offset_t static_memory_end;

static inline int
is_vm_fault(fault_status_t status)
{
	switch (status) {
	case FSC_TRANSLATION_FAULT_L0:
	case FSC_TRANSLATION_FAULT_L1:
	case FSC_TRANSLATION_FAULT_L2:
	case FSC_TRANSLATION_FAULT_L3:
	case FSC_ACCESS_FLAG_FAULT_L1:
	case FSC_ACCESS_FLAG_FAULT_L2:
	case FSC_ACCESS_FLAG_FAULT_L3:
	case FSC_PERMISSION_FAULT_L1:
	case FSC_PERMISSION_FAULT_L2:
	case FSC_PERMISSION_FAULT_L3:
		return TRUE;
	default:
		return FALSE;
	}
}

static inline int
is_translation_fault(fault_status_t status)
{
	switch (status) {
	case FSC_TRANSLATION_FAULT_L0:
	case FSC_TRANSLATION_FAULT_L1:
	case FSC_TRANSLATION_FAULT_L2:
	case FSC_TRANSLATION_FAULT_L3:
		return TRUE;
	default:
		return FALSE;
	}
}

static inline int
is_permission_fault(fault_status_t status)
{
	switch (status) {
	case FSC_PERMISSION_FAULT_L1:
	case FSC_PERMISSION_FAULT_L2:
	case FSC_PERMISSION_FAULT_L3:
		return TRUE;
	default:
		return FALSE;
	}
}

static inline int
is_alignment_fault(fault_status_t status)
{
	return status == FSC_ALIGNMENT_FAULT;
}

static inline int
is_parity_error(fault_status_t status)
{
	switch (status) {
	case FSC_SYNC_PARITY:
	case FSC_ASYNC_PARITY:
	case FSC_SYNC_PARITY_TT_L1:
	case FSC_SYNC_PARITY_TT_L2:
	case FSC_SYNC_PARITY_TT_L3:
		return TRUE;
	default:
		return FALSE;
	}
}

static inline unsigned
__ror(unsigned value, unsigned shift)
{
	return ((unsigned)(value) >> (unsigned)(shift)) |
	       (unsigned)(value) << ((unsigned)(sizeof(unsigned) * CHAR_BIT) - (unsigned)(shift));
}

__dead2
static void
arm64_implementation_specific_error(arm_saved_state_t *state, uint32_t esr, vm_offset_t far)
{
#if defined(APPLE_ARM64_ARCH_FAMILY)
	uint64_t fed_err_sts, mmu_err_sts, lsu_err_sts;
#if defined(NO_ECORE)
	uint64_t l2c_err_sts, l2c_err_adr, l2c_err_inf;

	mmu_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_MMU_ERR_STS));
	l2c_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_STS));
	l2c_err_adr = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_ADR));
	l2c_err_inf = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_INF));
	lsu_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_LSU_ERR_STS));
	fed_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_FED_ERR_STS));

	panic_plain("Unhandled " CPU_NAME
	    " implementation specific error. state=%p esr=%#x far=%p\n"
	    "\tlsu_err_sts:%p, fed_err_sts:%p, mmu_err_sts:%p\n"
	    "\tl2c_err_sts:%p, l2c_err_adr:%p, l2c_err_inf:%p\n",
	    state, esr, (void *)far,
	    (void *)lsu_err_sts, (void *)fed_err_sts, (void *)mmu_err_sts,
	    (void *)l2c_err_sts, (void *)l2c_err_adr, (void *)l2c_err_inf);

#elif defined(HAS_MIGSTS)
	uint64_t l2c_err_sts, l2c_err_adr, l2c_err_inf, mpidr, migsts;

	mpidr = __builtin_arm_rsr64("MPIDR_EL1");
	migsts = __builtin_arm_rsr64(STR(ARM64_REG_MIGSTS_EL1));
	mmu_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_MMU_ERR_STS));
	l2c_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_STS));
	l2c_err_adr = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_ADR));
	l2c_err_inf = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_INF));
	lsu_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_LSU_ERR_STS));
	fed_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_FED_ERR_STS));

	panic_plain("Unhandled " CPU_NAME
	    " implementation specific error. state=%p esr=%#x far=%p p-core?%d migsts=%p\n"
	    "\tlsu_err_sts:%p, fed_err_sts:%p, mmu_err_sts:%p\n"
	    "\tl2c_err_sts:%p, l2c_err_adr:%p, l2c_err_inf:%p\n",
	    state, esr, (void *)far, !!(mpidr & MPIDR_PNE), (void *)migsts,
	    (void *)lsu_err_sts, (void *)fed_err_sts, (void *)mmu_err_sts,
	    (void *)l2c_err_sts, (void *)l2c_err_adr, (void *)l2c_err_inf);
#else // !defined(NO_ECORE) && !defined(HAS_MIGSTS)
	uint64_t llc_err_sts, llc_err_adr, llc_err_inf, mpidr;
#if defined(HAS_DPC_ERR)
	uint64_t dpc_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_DPC_ERR_STS));
#endif // defined(HAS_DPC_ERR)

	mpidr = __builtin_arm_rsr64("MPIDR_EL1");

	if (mpidr & MPIDR_PNE) {
		mmu_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_MMU_ERR_STS));
		lsu_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_LSU_ERR_STS));
		fed_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_FED_ERR_STS));
	} else {
		mmu_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_E_MMU_ERR_STS));
		lsu_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_E_LSU_ERR_STS));
		fed_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_E_FED_ERR_STS));
	}

	llc_err_sts = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_STS));
	llc_err_adr = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_ADR));
	llc_err_inf = __builtin_arm_rsr64(STR(ARM64_REG_L2C_ERR_INF));

	panic_plain("Unhandled " CPU_NAME
	    " implementation specific error. state=%p esr=%#x far=%p p-core?%d"
#if defined(HAS_DPC_ERR)
	    " dpc_err_sts:%p"
#endif
	    "\n"
	    "\tlsu_err_sts:%p, fed_err_sts:%p, mmu_err_sts:%p\n"
	    "\tllc_err_sts:%p, llc_err_adr:%p, llc_err_inf:%p\n",
	    state, esr, (void *)far, !!(mpidr & MPIDR_PNE),
#if defined(HAS_DPC_ERR)
	    (void *)dpc_err_sts,
#endif
	    (void *)lsu_err_sts, (void *)fed_err_sts, (void *)mmu_err_sts,
	    (void *)llc_err_sts, (void *)llc_err_adr, (void *)llc_err_inf);
#endif
#else // !defined(APPLE_ARM64_ARCH_FAMILY)
#pragma unused (state, esr, far)
	panic_plain("Unhandled implementation specific error\n");
#endif
}

#if CONFIG_KERNEL_INTEGRITY
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
static void
kernel_integrity_error_handler(uint32_t esr, vm_offset_t far)
{
#if defined(KERNEL_INTEGRITY_WT)
#if (DEVELOPMENT || DEBUG)
	if (ESR_WT_SERROR(esr)) {
		switch (ESR_WT_REASON(esr)) {
		case WT_REASON_INTEGRITY_FAIL:
			panic_plain("Kernel integrity, violation in frame 0x%016lx.", far);
		case WT_REASON_BAD_SYSCALL:
			panic_plain("Kernel integrity, bad syscall.");
		case WT_REASON_NOT_LOCKED:
			panic_plain("Kernel integrity, not locked.");
		case WT_REASON_ALREADY_LOCKED:
			panic_plain("Kernel integrity, already locked.");
		case WT_REASON_SW_REQ:
			panic_plain("Kernel integrity, software request.");
		case WT_REASON_PT_INVALID:
			panic_plain("Kernel integrity, encountered invalid TTE/PTE while "
			    "walking 0x%016lx.", far);
		case WT_REASON_PT_VIOLATION:
			panic_plain("Kernel integrity, violation in mapping 0x%016lx.",
			    far);
		case WT_REASON_REG_VIOLATION:
			panic_plain("Kernel integrity, violation in system register %d.",
			    (unsigned) far);
		default:
			panic_plain("Kernel integrity, unknown (esr=0x%08x).", esr);
		}
	}
#else
	if (ESR_WT_SERROR(esr)) {
		panic_plain("SError esr: 0x%08x far: 0x%016lx.", esr, far);
	}
#endif
#endif
}
#pragma clang diagnostic pop
#endif

static void
arm64_platform_error(arm_saved_state_t *state, uint32_t esr, vm_offset_t far)
{
	cpu_data_t *cdp = getCpuDatap();

#if CONFIG_KERNEL_INTEGRITY
	kernel_integrity_error_handler(esr, far);
#endif

	if (PE_handle_platform_error(far)) {
		return;
	} else if (cdp->platform_error_handler != NULL) {
		cdp->platform_error_handler(cdp->cpu_id, far);
	} else {
		arm64_implementation_specific_error(state, esr, far);
	}
}

void
panic_with_thread_kernel_state(const char *msg, arm_saved_state_t *ss)
{
	boolean_t ss_valid;

	ss_valid = is_saved_state64(ss);
	arm_saved_state64_t *state = saved_state64(ss);

	os_atomic_cmpxchg(&original_faulting_state, NULL, state, seq_cst);

	panic_plain("%s at pc 0x%016llx, lr 0x%016llx (saved state: %p%s)\n"
	    "\t  x0: 0x%016llx  x1:  0x%016llx  x2:  0x%016llx  x3:  0x%016llx\n"
	    "\t  x4: 0x%016llx  x5:  0x%016llx  x6:  0x%016llx  x7:  0x%016llx\n"
	    "\t  x8: 0x%016llx  x9:  0x%016llx  x10: 0x%016llx  x11: 0x%016llx\n"
	    "\t  x12: 0x%016llx x13: 0x%016llx  x14: 0x%016llx  x15: 0x%016llx\n"
	    "\t  x16: 0x%016llx x17: 0x%016llx  x18: 0x%016llx  x19: 0x%016llx\n"
	    "\t  x20: 0x%016llx x21: 0x%016llx  x22: 0x%016llx  x23: 0x%016llx\n"
	    "\t  x24: 0x%016llx x25: 0x%016llx  x26: 0x%016llx  x27: 0x%016llx\n"
	    "\t  x28: 0x%016llx fp:  0x%016llx  lr:  0x%016llx  sp:  0x%016llx\n"
	    "\t  pc:  0x%016llx cpsr: 0x%08x         esr: 0x%08x          far: 0x%016llx\n",
	    msg, state->pc, state->lr, ss, (ss_valid ? "" : " INVALID"),
	    state->x[0], state->x[1], state->x[2], state->x[3],
	    state->x[4], state->x[5], state->x[6], state->x[7],
	    state->x[8], state->x[9], state->x[10], state->x[11],
	    state->x[12], state->x[13], state->x[14], state->x[15],
	    state->x[16], state->x[17], state->x[18], state->x[19],
	    state->x[20], state->x[21], state->x[22], state->x[23],
	    state->x[24], state->x[25], state->x[26], state->x[27],
	    state->x[28], state->fp, state->lr, state->sp,
	    state->pc, state->cpsr, state->esr, state->far);
}

void
sleh_synchronous_sp1(arm_context_t *context, uint32_t esr, vm_offset_t far __unused)
{
	esr_exception_class_t  class = ESR_EC(esr);
	arm_saved_state_t    * state = &context->ss;

	switch (class) {
	case ESR_EC_UNCATEGORIZED:
	{
		uint32_t instr = *((uint32_t*)get_saved_state_pc(state));
		if (IS_ARM_GDB_TRAP(instr)) {
			DebuggerCall(EXC_BREAKPOINT, state);
		}
	}
		OS_FALLTHROUGH; // panic if we return from the debugger
	default:
		panic_with_thread_kernel_state("Synchronous exception taken while SP1 selected", state);
	}
}

#if defined(HAS_TWO_STAGE_SPR_LOCK) && defined(CONFIG_XNUPOST)
static bool
handle_msr_write_from_xnupost(arm_saved_state_t *state, uint32_t esr)
{
	user_addr_t pc = get_saved_state_pc(state);
	if ((spr_lock_test_addr != 0) && (pc == spr_lock_test_addr)) {
		spr_lock_exception_esr = esr;
		set_saved_state_pc(state, pc + 4);
		return true;
	}

	return false;
}
#endif

__attribute__((noreturn))
void
thread_exception_return()
{
	thread_t thread = current_thread();
	if (thread->machine.exception_trace_code != 0) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, thread->machine.exception_trace_code) | DBG_FUNC_END, 0, 0, 0, 0, 0);
		thread->machine.exception_trace_code = 0;
	}

	arm64_thread_exception_return();
	__builtin_unreachable();
}

/*
 * check whether task vtimers are running and set thread and CPU BSD AST
 *
 * must be called with interrupts masked so updates of fields are atomic
 * must be emitted inline to avoid generating an FBT probe on the exception path
 *
 */
__attribute__((__always_inline__))
static inline void
task_vtimer_check(thread_t thread)
{
	if (__improbable(thread->task->vtimers)) {
		thread->ast |= AST_BSD;
		thread->machine.CpuDatap->cpu_pending_ast |= AST_BSD;
	}
}

void
sleh_synchronous(arm_context_t *context, uint32_t esr, vm_offset_t far)
{
	esr_exception_class_t  class   = ESR_EC(esr);
	arm_saved_state_t    * state   = &context->ss;
	vm_offset_t            recover = 0;
	thread_t               thread  = current_thread();
#if MACH_ASSERT
	int                    preemption_level = get_preemption_level();
#endif
	expected_fault_handler_t expected_fault_handler = NULL;
#ifdef CONFIG_XNUPOST
	expected_fault_handler_t saved_expected_fault_handler = NULL;
	uintptr_t saved_expected_fault_addr = 0;
#endif /* CONFIG_XNUPOST */

	ASSERT_CONTEXT_SANITY(context);

	task_vtimer_check(thread);

#if CONFIG_DTRACE
	/*
	 * Handle kernel DTrace probes as early as possible to minimize the likelihood
	 * that this path will itself trigger a DTrace probe, which would lead to infinite
	 * probe recursion.
	 */
	if (__improbable((class == ESR_EC_UNCATEGORIZED) && tempDTraceTrapHook &&
	    (tempDTraceTrapHook(EXC_BAD_INSTRUCTION, state, 0, 0) == KERN_SUCCESS))) {
		return;
	}
#endif
	bool is_user = PSR64_IS_USER(get_saved_state_cpsr(state));

	/*
	 * Use KERNEL_DEBUG_CONSTANT_IST here to avoid producing tracepoints
	 * that would disclose the behavior of PT_DENY_ATTACH processes.
	 */
	if (is_user) {
		thread->machine.exception_trace_code = (uint16_t)(ARM64_KDBG_CODE_USER | class);
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, thread->machine.exception_trace_code) | DBG_FUNC_START,
		    esr, far, get_saved_state_pc(state), 0, 0);
	} else {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, ARM64_KDBG_CODE_KERNEL | class) | DBG_FUNC_START,
		    esr, VM_KERNEL_ADDRHIDE(far), VM_KERNEL_UNSLIDE(get_saved_state_pc(state)), 0, 0);
	}

	if (__improbable(ESR_INSTR_IS_2BYTES(esr))) {
		/*
		 * We no longer support 32-bit, which means no 2-byte
		 * instructions.
		 */
		if (is_user) {
			panic("Exception on 2-byte instruction, "
			    "context=%p, esr=%#x, far=%p",
			    context, esr, (void *)far);
		} else {
			panic_with_thread_kernel_state("Exception on 2-byte instruction", state);
		}
	}

	/* Don't run exception handler with recover handler set in case of double fault */
	if (thread->recover) {
		recover = thread->recover;
		thread->recover = (vm_offset_t)NULL;
	}

#ifdef CONFIG_XNUPOST
	if (thread->machine.expected_fault_handler != NULL) {
		saved_expected_fault_handler = thread->machine.expected_fault_handler;
		saved_expected_fault_addr = thread->machine.expected_fault_addr;

		thread->machine.expected_fault_handler = NULL;
		thread->machine.expected_fault_addr = 0;

		if (saved_expected_fault_addr == far) {
			expected_fault_handler = saved_expected_fault_handler;
		}
	}
#endif /* CONFIG_XNUPOST */

	/* Inherit the interrupt masks from previous context */
	if (SPSR_INTERRUPTS_ENABLED(get_saved_state_cpsr(state))) {
		ml_set_interrupts_enabled(TRUE);
	}

	switch (class) {
	case ESR_EC_SVC_64:
		if (!is_saved_state64(state) || !is_user) {
			panic("Invalid SVC_64 context");
		}

		handle_svc(state);
		break;

	case ESR_EC_DABORT_EL0:
		handle_abort(state, esr, far, recover, inspect_data_abort, handle_user_abort, expected_fault_handler);
		break;

	case ESR_EC_MSR_TRAP:
		handle_msr_trap(state, esr);
		break;


	case ESR_EC_IABORT_EL0:
		handle_abort(state, esr, far, recover, inspect_instruction_abort, handle_user_abort, expected_fault_handler);
		break;

	case ESR_EC_IABORT_EL1:
#ifdef CONFIG_XNUPOST
		if ((expected_fault_handler != NULL) && expected_fault_handler(state)) {
			break;
		}
#endif /* CONFIG_XNUPOST */

		panic_with_thread_kernel_state("Kernel instruction fetch abort", state);

	case ESR_EC_PC_ALIGN:
		handle_pc_align(state);
		__builtin_unreachable();

	case ESR_EC_DABORT_EL1:
		handle_abort(state, esr, far, recover, inspect_data_abort, handle_kernel_abort, expected_fault_handler);
		break;

	case ESR_EC_UNCATEGORIZED:
		assert(!ESR_ISS(esr));

#if defined(HAS_TWO_STAGE_SPR_LOCK) && defined(CONFIG_XNUPOST)
		if (handle_msr_write_from_xnupost(state, esr)) {
			break;
		}
#endif
		handle_uncategorized(&context->ss);
		break;

	case ESR_EC_SP_ALIGN:
		handle_sp_align(state);
		__builtin_unreachable();

	case ESR_EC_BKPT_AARCH32:
		handle_breakpoint(state, esr);
		__builtin_unreachable();

	case ESR_EC_BRK_AARCH64:
		if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
			handle_kernel_breakpoint(state, esr);
		} else {
			handle_breakpoint(state, esr);
		}
		__builtin_unreachable();

	case ESR_EC_BKPT_REG_MATCH_EL0:
		if (FSC_DEBUG_FAULT == ISS_SSDE_FSC(esr)) {
			handle_breakpoint(state, esr);
		}
		panic("Unsupported Class %u event code. state=%p class=%u esr=%u far=%p",
		    class, state, class, esr, (void *)far);
		__builtin_unreachable();

	case ESR_EC_BKPT_REG_MATCH_EL1:
		panic_with_thread_kernel_state("Hardware Breakpoint Debug exception from kernel. Panic (by design)", state);
		__builtin_unreachable();

	case ESR_EC_SW_STEP_DEBUG_EL0:
		if (FSC_DEBUG_FAULT == ISS_SSDE_FSC(esr)) {
			handle_sw_step_debug(state);
		}
		panic("Unsupported Class %u event code. state=%p class=%u esr=%u far=%p",
		    class, state, class, esr, (void *)far);
		__builtin_unreachable();

	case ESR_EC_SW_STEP_DEBUG_EL1:
		panic_with_thread_kernel_state("Software Step Debug exception from kernel. Panic (by design)", state);
		__builtin_unreachable();

	case ESR_EC_WATCHPT_MATCH_EL0:
		if (FSC_DEBUG_FAULT == ISS_SSDE_FSC(esr)) {
			handle_watchpoint(far);
		}
		panic("Unsupported Class %u event code. state=%p class=%u esr=%u far=%p",
		    class, state, class, esr, (void *)far);
		__builtin_unreachable();

	case ESR_EC_WATCHPT_MATCH_EL1:
		/*
		 * If we hit a watchpoint in kernel mode, probably in a copyin/copyout which we don't want to
		 * abort.  Turn off watchpoints and keep going; we'll turn them back on in return_from_exception..
		 */
		if (FSC_DEBUG_FAULT == ISS_SSDE_FSC(esr)) {
			arm_debug_set(NULL);
			break; /* return to first level handler */
		}
		panic("Unsupported Class %u event code. state=%p class=%u esr=%u far=%p",
		    class, state, class, esr, (void *)far);
		__builtin_unreachable();

	case ESR_EC_TRAP_SIMD_FP:
		handle_simd_trap(state, esr);
		__builtin_unreachable();

	case ESR_EC_ILLEGAL_INSTR_SET:
		if (EXCB_ACTION_RERUN !=
		    ex_cb_invoke(EXCB_CLASS_ILLEGAL_INSTR_SET, far)) {
			// instruction is not re-executed
			panic("Illegal instruction set exception. state=%p class=%u esr=%u far=%p spsr=0x%x",
			    state, class, esr, (void *)far, get_saved_state_cpsr(state));
		}
		// must clear this fault in PSR to re-run
		mask_saved_state_cpsr(state, 0, PSR64_IL);
		break;

	case ESR_EC_MCR_MRC_CP15_TRAP:
	case ESR_EC_MCRR_MRRC_CP15_TRAP:
	case ESR_EC_MCR_MRC_CP14_TRAP:
	case ESR_EC_LDC_STC_CP14_TRAP:
	case ESR_EC_MCRR_MRRC_CP14_TRAP:
		handle_user_trapped_instruction32(state, esr);
		__builtin_unreachable();

	case ESR_EC_WFI_WFE:
		// Use of WFI or WFE instruction when they have been disabled for EL0
		handle_wf_trap(state);
		__builtin_unreachable();

	case ESR_EC_FLOATING_POINT_64:
		handle_fp_trap(state, esr);
		__builtin_unreachable();

	default:
		panic("Unsupported synchronous exception. state=%p class=%u esr=%u far=%p",
		    state, class, esr, (void *)far);
		__builtin_unreachable();
	}

#ifdef CONFIG_XNUPOST
	if (saved_expected_fault_handler != NULL) {
		thread->machine.expected_fault_handler = saved_expected_fault_handler;
		thread->machine.expected_fault_addr = saved_expected_fault_addr;
	}
#endif /* CONFIG_XNUPOST */

	if (recover) {
		thread->recover = recover;
	}
	if (is_user) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, thread->machine.exception_trace_code) | DBG_FUNC_END,
		    esr, far, get_saved_state_pc(state), 0, 0);
		thread->machine.exception_trace_code = 0;
	} else {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, ARM64_KDBG_CODE_KERNEL | class) | DBG_FUNC_END,
		    esr, VM_KERNEL_ADDRHIDE(far), VM_KERNEL_UNSLIDE(get_saved_state_pc(state)), 0, 0);
	}
#if MACH_ASSERT
	if (preemption_level != get_preemption_level()) {
		panic("synchronous exception changed preemption level from %d to %d", preemption_level, get_preemption_level());
	}
#endif
}

/*
 * Uncategorized exceptions are a catch-all for general execution errors.
 * ARM64_TODO: For now, we assume this is for undefined instruction exceptions.
 */
static void
handle_uncategorized(arm_saved_state_t *state)
{
	exception_type_t           exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr     = 0;

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));

#if CONFIG_DTRACE

	if (PSR64_IS_USER64(get_saved_state_cpsr(state))) {
		/*
		 * For a 64bit user process, we care about all 4 bytes of the
		 * instr.
		 */
		if (instr == FASTTRAP_ARM64_INSTR || instr == FASTTRAP_ARM64_RET_INSTR) {
			if (dtrace_user_probe(state) == KERN_SUCCESS) {
				return;
			}
		}
	} else if (PSR64_IS_USER32(get_saved_state_cpsr(state))) {
		/*
		 * For a 32bit user process, we check for thumb mode, in
		 * which case we only care about a 2 byte instruction length.
		 * For non-thumb mode, we care about all 4 bytes of the instructin.
		 */
		if (get_saved_state_cpsr(state) & PSR64_MODE_USER32_THUMB) {
			if (((uint16_t)instr == FASTTRAP_THUMB32_INSTR) ||
			    ((uint16_t)instr == FASTTRAP_THUMB32_RET_INSTR)) {
				if (dtrace_user_probe(state) == KERN_SUCCESS) {
					return;
				}
			}
		} else {
			if ((instr == FASTTRAP_ARM32_INSTR) ||
			    (instr == FASTTRAP_ARM32_RET_INSTR)) {
				if (dtrace_user_probe(state) == KERN_SUCCESS) {
					return;
				}
			}
		}
	}

#endif /* CONFIG_DTRACE */

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		if (IS_ARM_GDB_TRAP(instr)) {
			boolean_t interrupt_state;
			exception = EXC_BREAKPOINT;

			interrupt_state = ml_set_interrupts_enabled(FALSE);

			/* Save off the context here (so that the debug logic
			 * can see the original state of this thread).
			 */
			current_thread()->machine.kpcb = state;

			/* Hop into the debugger (typically either due to a
			 * fatal exception, an explicit panic, or a stackshot
			 * request.
			 */
			DebuggerCall(exception, state);

			(void) ml_set_interrupts_enabled(interrupt_state);
			return;
		} else {
			panic("Undefined kernel instruction: pc=%p instr=%x\n", (void*)get_saved_state_pc(state), instr);
		}
	}

	/*
	 * Check for GDB breakpoint via illegal opcode.
	 */
	if (IS_ARM_GDB_TRAP(instr)) {
		exception = EXC_BREAKPOINT;
		codes[0] = EXC_ARM_BREAKPOINT;
		codes[1] = instr;
	} else {
		codes[1] = instr;
	}

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

#if __has_feature(ptrauth_calls)
static const uint16_t ptrauth_brk_comment_base = 0xc470;

static inline bool
brk_comment_is_ptrauth(uint16_t comment)
{
	return comment >= ptrauth_brk_comment_base &&
	       comment <= ptrauth_brk_comment_base + ptrauth_key_asdb;
}

static inline const char *
brk_comment_to_ptrauth_key(uint16_t comment)
{
	switch (comment - ptrauth_brk_comment_base) {
	case ptrauth_key_asia:
		return "IA";
	case ptrauth_key_asib:
		return "IB";
	case ptrauth_key_asda:
		return "DA";
	case ptrauth_key_asdb:
		return "DB";
	default:
		__builtin_unreachable();
	}
}
#endif /* __has_feature(ptrauth_calls) */

static void
handle_kernel_breakpoint(arm_saved_state_t *state, uint32_t esr)
{
	uint16_t comment = ISS_BRK_COMMENT(esr);

#if __has_feature(ptrauth_calls)
	if (brk_comment_is_ptrauth(comment)) {
		const char *msg_fmt = "Break 0x%04X instruction exception from kernel. Ptrauth failure with %s key resulted in 0x%016llx";
		char msg[strlen(msg_fmt)
		- strlen("0x%04X") + strlen("0xFFFF")
		- strlen("%s") + strlen("IA")
		- strlen("0x%016llx") + strlen("0xFFFFFFFFFFFFFFFF")
		+ 1];
		const char *key = brk_comment_to_ptrauth_key(comment);
		snprintf(msg, sizeof(msg), msg_fmt, comment, key, saved_state64(state)->x[16]);

		panic_with_thread_kernel_state(msg, state);
	}
#endif /* __has_feature(ptrauth_calls) */

	const char *msg_fmt = "Break 0x%04X instruction exception from kernel. Panic (by design)";
	char msg[strlen(msg_fmt) - strlen("0x%04X") + strlen("0xFFFF") + 1];
	snprintf(msg, sizeof(msg), msg_fmt, comment);

	panic_with_thread_kernel_state(msg, state);
}

static void
handle_breakpoint(arm_saved_state_t *state, uint32_t esr __unused)
{
	exception_type_t           exception = EXC_BREAKPOINT;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_BREAKPOINT};
	mach_msg_type_number_t     numcodes  = 2;

#if __has_feature(ptrauth_calls) && !__ARM_ARCH_8_6__
	if (ESR_EC(esr) == ESR_EC_BRK_AARCH64 &&
	    brk_comment_is_ptrauth(ISS_BRK_COMMENT(esr))) {
		exception |= EXC_PTRAUTH_BIT;
	}
#endif /* __has_feature(ptrauth_calls) && !__ARM_ARCH_8_6__ */

	codes[1] = get_saved_state_pc(state);
	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_watchpoint(vm_offset_t fault_addr)
{
	exception_type_t           exception = EXC_BREAKPOINT;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_DA_DEBUG};
	mach_msg_type_number_t     numcodes  = 2;

	codes[1] = fault_addr;
	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_abort(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr, vm_offset_t recover,
    abort_inspector_t inspect_abort, abort_handler_t handler, expected_fault_handler_t expected_fault_handler)
{
	fault_status_t fault_code;
	vm_prot_t      fault_type;

	inspect_abort(ESR_ISS(esr), &fault_code, &fault_type);
	handler(state, esr, fault_addr, fault_code, fault_type, recover, expected_fault_handler);
}

static void
inspect_instruction_abort(uint32_t iss, fault_status_t *fault_code, vm_prot_t *fault_type)
{
	getCpuDatap()->cpu_stat.instr_ex_cnt++;
	*fault_code = ISS_IA_FSC(iss);
	*fault_type = (VM_PROT_READ | VM_PROT_EXECUTE);
}

static void
inspect_data_abort(uint32_t iss, fault_status_t *fault_code, vm_prot_t *fault_type)
{
	getCpuDatap()->cpu_stat.data_ex_cnt++;
	*fault_code = ISS_DA_FSC(iss);

	/*
	 * Cache maintenance operations always report faults as write access.
	 * Change these to read access, unless they report a permission fault.
	 * Only certain cache maintenance operations (e.g. 'dc ivac') require write
	 * access to the mapping, but if a cache maintenance operation that only requires
	 * read access generates a permission fault, then we will not be able to handle
	 * the fault regardless of whether we treat it as a read or write fault.
	 */
	if ((iss & ISS_DA_WNR) && (!(iss & ISS_DA_CM) || is_permission_fault(*fault_code))) {
		*fault_type = (VM_PROT_READ | VM_PROT_WRITE);
	} else {
		*fault_type = (VM_PROT_READ);
	}
}

#if __has_feature(ptrauth_calls)
static inline bool
fault_addr_bit(vm_offset_t fault_addr, unsigned int bit)
{
	return (bool)((fault_addr >> bit) & 1);
}

/**
 * Determines whether a fault address taken at EL0 contains a PAC error code
 * corresponding to the specified kind of ptrauth key.
 */
static bool
user_fault_addr_matches_pac_error_code(vm_offset_t fault_addr, bool data_key)
{
	bool instruction_tbi = !(get_tcr() & TCR_TBID0_TBI_DATA_ONLY);
	bool tbi = data_key || __improbable(instruction_tbi);
	unsigned int poison_shift;
	if (tbi) {
		poison_shift = 53;
	} else {
		poison_shift = 61;
	}

	/* PAC error codes are always in the form key_number:NOT(key_number) */
	bool poison_bit_1 = fault_addr_bit(fault_addr, poison_shift);
	bool poison_bit_2 = fault_addr_bit(fault_addr, poison_shift + 1);
	return poison_bit_1 != poison_bit_2;
}
#endif /* __has_feature(ptrauth_calls) */

static void
handle_pc_align(arm_saved_state_t *ss)
{
	exception_type_t exc;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;

	if (!PSR64_IS_USER(get_saved_state_cpsr(ss))) {
		panic_with_thread_kernel_state("PC alignment exception from kernel.", ss);
	}

	exc = EXC_BAD_ACCESS;
#if __has_feature(ptrauth_calls)
	if (user_fault_addr_matches_pac_error_code(get_saved_state_pc(ss), false)) {
		exc |= EXC_PTRAUTH_BIT;
	}
#endif /* __has_feature(ptrauth_calls) */

	codes[0] = EXC_ARM_DA_ALIGN;
	codes[1] = get_saved_state_pc(ss);

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_sp_align(arm_saved_state_t *ss)
{
	exception_type_t exc;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;

	if (!PSR64_IS_USER(get_saved_state_cpsr(ss))) {
		panic_with_thread_kernel_state("SP alignment exception from kernel.", ss);
	}

	exc = EXC_BAD_ACCESS;
#if __has_feature(ptrauth_calls)
	if (user_fault_addr_matches_pac_error_code(get_saved_state_sp(ss), true)) {
		exc |= EXC_PTRAUTH_BIT;
	}
#endif /* __has_feature(ptrauth_calls) */

	codes[0] = EXC_ARM_SP_ALIGN;
	codes[1] = get_saved_state_sp(ss);

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_wf_trap(arm_saved_state_t *state)
{
	exception_type_t exc;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;
	uint32_t instr = 0;

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));

	exc = EXC_BAD_INSTRUCTION;
	codes[0] = EXC_ARM_UNDEFINED;
	codes[1] = instr;

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_fp_trap(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t exc = EXC_ARITHMETIC;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;
	uint32_t instr = 0;

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		panic_with_thread_kernel_state("Floating point exception from kernel", state);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));
	codes[1] = instr;

	/* The floating point trap flags are only valid if TFV is set. */
	if (!fp_exceptions_enabled) {
		exc = EXC_BAD_INSTRUCTION;
		codes[0] = EXC_ARM_UNDEFINED;
	} else if (!(esr & ISS_FP_TFV)) {
		codes[0] = EXC_ARM_FP_UNDEFINED;
	} else if (esr & ISS_FP_UFF) {
		codes[0] = EXC_ARM_FP_UF;
	} else if (esr & ISS_FP_OFF) {
		codes[0] = EXC_ARM_FP_OF;
	} else if (esr & ISS_FP_IOF) {
		codes[0] = EXC_ARM_FP_IO;
	} else if (esr & ISS_FP_DZF) {
		codes[0] = EXC_ARM_FP_DZ;
	} else if (esr & ISS_FP_IDF) {
		codes[0] = EXC_ARM_FP_ID;
	} else if (esr & ISS_FP_IXF) {
		codes[0] = EXC_ARM_FP_IX;
	} else {
		panic("Unrecognized floating point exception, state=%p, esr=%#x", state, esr);
	}

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}



/*
 * handle_alignment_fault_from_user:
 *   state: Saved state
 *
 * Attempts to deal with an alignment fault from userspace (possibly by
 * emulating the faulting instruction).  If emulation failed due to an
 * unservicable fault, the ESR for that fault will be stored in the
 * recovery_esr field of the thread by the exception code.
 *
 * Returns:
 *   -1:     Emulation failed (emulation of state/instr not supported)
 *   0:      Successfully emulated the instruction
 *   EFAULT: Emulation failed (probably due to permissions)
 *   EINVAL: Emulation failed (probably due to a bad address)
 */
static int
handle_alignment_fault_from_user(arm_saved_state_t *state, kern_return_t *vmfr)
{
	int ret = -1;

#pragma unused (state)
#pragma unused (vmfr)

	return ret;
}


static void
handle_sw_step_debug(arm_saved_state_t *state)
{
	thread_t thread = current_thread();
	exception_type_t exc;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;

	if (!PSR64_IS_USER(get_saved_state_cpsr(state))) {
		panic_with_thread_kernel_state("SW_STEP_DEBUG exception from kernel.", state);
	}

	// Disable single step and unmask interrupts (in the saved state, anticipating next exception return)
	if (thread->machine.DebugData != NULL) {
		thread->machine.DebugData->uds.ds64.mdscr_el1 &= ~0x1;
	} else {
		panic_with_thread_kernel_state("SW_STEP_DEBUG exception thread DebugData is NULL.", state);
	}

	mask_saved_state_cpsr(thread->machine.upcb, 0, PSR64_SS | DAIF_IRQF | DAIF_FIQF);

	// Special encoding for gdb single step event on ARM
	exc = EXC_BREAKPOINT;
	codes[0] = 1;
	codes[1] = 0;

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

static void
set_saved_state_pc_to_recovery_handler(arm_saved_state_t *iss, vm_offset_t recover)
{
#if defined(HAS_APPLE_PAC)
	thread_t thread = current_thread();
	const uintptr_t disc = ptrauth_blend_discriminator(&thread->recover, PAC_DISCRIMINATOR_RECOVER);
	const char *panic_msg = "Illegal thread->recover value %p";

	MANIPULATE_SIGNED_THREAD_STATE(iss,
	    // recover = (vm_offset_t)ptrauth_auth_data((void *)recover, ptrauth_key_function_pointer,
	    //     ptrauth_blend_discriminator(&thread->recover, PAC_DISCRIMINATOR_RECOVER));
	    "mov	x1, %[recover]		\n"
	    "mov	x6, %[disc]		\n"
	    "autia	x1, x6			\n"
	    // if (recover != (vm_offset_t)ptrauth_strip((void *)recover, ptrauth_key_function_pointer)) {
	    "mov	x6, x1			\n"
	    "xpaci	x6			\n"
	    "cmp	x1, x6			\n"
	    "beq	1f			\n"
	    //         panic("Illegal thread->recover value %p", (void *)recover);
	    "mov	x0, %[panic_msg]	\n"
	    "bl		_panic			\n"
	    // }
	    "1:					\n"
	    "str	x1, [x0, %[SS64_PC]]	\n",
	    [recover]     "r"(recover),
	    [disc]        "r"(disc),
	    [panic_msg]   "r"(panic_msg)
	    );
#else
	set_saved_state_pc(iss, recover);
#endif
}

static void
handle_user_abort(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr,
    fault_status_t fault_code, vm_prot_t fault_type, vm_offset_t recover, expected_fault_handler_t expected_fault_handler)
{
	exception_type_t           exc      = EXC_BAD_ACCESS;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t     numcodes = 2;
	thread_t                   thread   = current_thread();

	(void)esr;
	(void)expected_fault_handler;

	if (ml_at_interrupt_context()) {
		panic_with_thread_kernel_state("Apparently on interrupt stack when taking user abort!\n", state);
	}

	thread->iotier_override = THROTTLE_LEVEL_NONE; /* Reset IO tier override before handling abort from userspace */

	if (is_vm_fault(fault_code)) {
		kern_return_t   result = KERN_FAILURE;
		vm_map_t        map = thread->map;
		vm_offset_t     vm_fault_addr = fault_addr;

		assert(map != kernel_map);

		if (!(fault_type & VM_PROT_EXECUTE)) {
			vm_fault_addr = tbi_clear(fault_addr);
		}

#if CONFIG_DTRACE
		if (thread->t_dtrace_inprobe) { /* Executing under dtrace_probe? */
			if (dtrace_tally_fault(vm_fault_addr)) { /* Should a user mode fault under dtrace be ignored? */
				if (recover) {
					thread->machine.recover_esr = esr;
					thread->machine.recover_far = vm_fault_addr;
					set_saved_state_pc_to_recovery_handler(state, recover);
				} else {
					panic_with_thread_kernel_state("copyin/out has no recovery point", state);
				}
				return;
			} else {
				panic_with_thread_kernel_state("Unexpected UMW page fault under dtrace_probe", state);
			}
		}
#else
		(void)recover;
#endif

#if CONFIG_PGTRACE
		if (pgtrace_enabled) {
			/* Check to see if trace bit is set */
			result = pmap_pgtrace_fault(map->pmap, fault_addr, state);
			if (result == KERN_SUCCESS) {
				return;
			}
		}
#endif

		/* check to see if it is just a pmap ref/modify fault */

		if ((result != KERN_SUCCESS) && !is_translation_fault(fault_code)) {
			result = arm_fast_fault(map->pmap,
			    vm_fault_addr,
			    fault_type, (fault_code == FSC_ACCESS_FLAG_FAULT_L3), TRUE);
		}
		if (result != KERN_SUCCESS) {
			{
				/* We have to fault the page in */
				result = vm_fault(map, vm_fault_addr, fault_type,
				    /* change_wiring */ FALSE, VM_KERN_MEMORY_NONE, THREAD_ABORTSAFE,
				    /* caller_pmap */ NULL, /* caller_pmap_addr */ 0);
			}
		}
		if (result == KERN_SUCCESS || result == KERN_ABORTED) {
			return;
		}

		/*
		 * vm_fault() should never return KERN_FAILURE for page faults from user space.
		 * If it does, we're leaking preemption disables somewhere in the kernel.
		 */
		if (__improbable(result == KERN_FAILURE)) {
			panic("vm_fault() KERN_FAILURE from user fault on thread %p", thread);
		}

		codes[0] = result;
	} else if (is_alignment_fault(fault_code)) {
		kern_return_t vmfkr = KERN_SUCCESS;
		thread->machine.recover_esr = 0;
		thread->machine.recover_far = 0;
		int result = handle_alignment_fault_from_user(state, &vmfkr);
		if (result == 0) {
			/* Successfully emulated, or instruction
			 * copyin() for decode/emulation failed.
			 * Continue, or redrive instruction.
			 */
			thread_exception_return();
		} else if (((result == EFAULT) || (result == EINVAL)) &&
		    (thread->machine.recover_esr == 0)) {
			/*
			 * If we didn't actually take a fault, but got one of
			 * these errors, then we failed basic sanity checks of
			 * the fault address.  Treat this as an invalid
			 * address.
			 */
			codes[0] = KERN_INVALID_ADDRESS;
		} else if ((result == EFAULT) &&
		    (thread->machine.recover_esr)) {
			/*
			 * Since alignment aborts are prioritized
			 * ahead of translation aborts, the misaligned
			 * atomic emulation flow may have triggered a
			 * VM pagefault, which the VM could not resolve.
			 * Report the VM fault error in codes[]
			 */

			codes[0] = vmfkr;
			assertf(vmfkr != KERN_SUCCESS, "Unexpected vmfkr 0x%x", vmfkr);
			/* Cause ESR_EC to reflect an EL0 abort */
			thread->machine.recover_esr &= ~ESR_EC_MASK;
			thread->machine.recover_esr |= (ESR_EC_DABORT_EL0 << ESR_EC_SHIFT);
			set_saved_state_esr(thread->machine.upcb, thread->machine.recover_esr);
			set_saved_state_far(thread->machine.upcb, thread->machine.recover_far);
			fault_addr = thread->machine.recover_far;
		} else {
			/* This was just an unsupported alignment
			 * exception. Misaligned atomic emulation
			 * timeouts fall in this category.
			 */
			codes[0] = EXC_ARM_DA_ALIGN;
		}
	} else if (is_parity_error(fault_code)) {
#if defined(APPLE_ARM64_ARCH_FAMILY)
		if (fault_code == FSC_SYNC_PARITY) {
			arm64_platform_error(state, esr, fault_addr);
			return;
		}
#else
		panic("User parity error.");
#endif
	} else {
		codes[0] = KERN_FAILURE;
	}

	codes[1] = fault_addr;
#if __has_feature(ptrauth_calls)
	bool is_data_abort = (ESR_EC(esr) == ESR_EC_DABORT_EL0);
	if (user_fault_addr_matches_pac_error_code(fault_addr, is_data_abort)) {
		exc |= EXC_PTRAUTH_BIT;
	}
#endif /* __has_feature(ptrauth_calls) */
	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

#if __ARM_PAN_AVAILABLE__
static int
is_pan_fault(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr, fault_status_t fault_code)
{
	// PAN (Privileged Access Never) fault occurs for data read/write in EL1 to
	// virtual address that is readable/writeable from both EL1 and EL0

	// To check for PAN fault, we evaluate if the following conditions are true:
	// 1. This is a permission fault
	// 2. PAN is enabled
	// 3. AT instruction (on which PAN has no effect) on the same faulting address
	// succeeds

	vm_offset_t pa;

	if (!(is_permission_fault(fault_code) && get_saved_state_cpsr(state) & PSR64_PAN)) {
		return FALSE;
	}

	if (esr & ISS_DA_WNR) {
		pa = mmu_kvtop_wpreflight(fault_addr);
	} else {
		pa = mmu_kvtop(fault_addr);
	}
	return (pa)? TRUE: FALSE;
}
#endif

static void
handle_kernel_abort(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr,
    fault_status_t fault_code, vm_prot_t fault_type, vm_offset_t recover, expected_fault_handler_t expected_fault_handler)
{
	thread_t thread = current_thread();
	(void)esr;

#ifndef CONFIG_XNUPOST
	(void)expected_fault_handler;
#endif /* CONFIG_XNUPOST */

#if CONFIG_DTRACE
	if (is_vm_fault(fault_code) && thread->t_dtrace_inprobe) { /* Executing under dtrace_probe? */
		if (dtrace_tally_fault(fault_addr)) { /* Should a fault under dtrace be ignored? */
			/*
			 * Point to next instruction, or recovery handler if set.
			 */
			if (recover) {
				thread->machine.recover_esr = esr;
				thread->machine.recover_far = fault_addr;
				set_saved_state_pc_to_recovery_handler(state, recover);
			} else {
				add_saved_state_pc(state, 4);
			}
			return;
		} else {
			panic_with_thread_kernel_state("Unexpected page fault under dtrace_probe", state);
		}
	}
#endif

#if !CONFIG_PGTRACE /* This will be moved next to pgtrace fault evaluation */
	if (ml_at_interrupt_context()) {
		panic_with_thread_kernel_state("Unexpected abort while on interrupt stack.", state);
	}
#endif

	if (is_vm_fault(fault_code)) {
		kern_return_t result = KERN_FAILURE;
		vm_map_t      map;
		int           interruptible;

		/*
		 * Ensure no faults in the physical aperture. This could happen if
		 * a page table is incorrectly allocated from the read only region
		 * when running with KTRR.
		 */

#ifdef CONFIG_XNUPOST
		if (expected_fault_handler && expected_fault_handler(state)) {
			return;
		}
#endif /* CONFIG_XNUPOST */

		if (fault_addr >= gVirtBase && fault_addr < static_memory_end) {
			panic_with_thread_kernel_state("Unexpected fault in kernel static region\n", state);
		}

		if (VM_KERNEL_ADDRESS(fault_addr) || thread == THREAD_NULL) {
			map = kernel_map;
			interruptible = THREAD_UNINT;
		} else {
			map = thread->map;
			interruptible = THREAD_ABORTSAFE;
		}

#if CONFIG_PGTRACE
		if (pgtrace_enabled) {
			/* Check to see if trace bit is set */
			result = pmap_pgtrace_fault(map->pmap, fault_addr, state);
			if (result == KERN_SUCCESS) {
				return;
			}
		}

		if (ml_at_interrupt_context()) {
			panic_with_thread_kernel_state("Unexpected abort while on interrupt stack.", state);
		}
#endif

		/* check to see if it is just a pmap ref/modify fault */
		if (!is_translation_fault(fault_code)) {
			result = arm_fast_fault(map->pmap,
			    fault_addr,
			    fault_type, (fault_code == FSC_ACCESS_FLAG_FAULT_L3), FALSE);
			if (result == KERN_SUCCESS) {
				return;
			}
		}

		if (result != KERN_PROTECTION_FAILURE) {
			/*
			 *  We have to "fault" the page in.
			 */
			result = vm_fault(map, fault_addr, fault_type,
			    /* change_wiring */ FALSE, VM_KERN_MEMORY_NONE, interruptible,
			    /* caller_pmap */ NULL, /* caller_pmap_addr */ 0);
		}

		if (result == KERN_SUCCESS) {
			return;
		}

		/*
		 *  If we have a recover handler, invoke it now.
		 */
		if (recover) {
			thread->machine.recover_esr = esr;
			thread->machine.recover_far = fault_addr;
			set_saved_state_pc_to_recovery_handler(state, recover);
			return;
		}

#if __ARM_PAN_AVAILABLE__
		if (is_pan_fault(state, esr, fault_addr, fault_code)) {
			panic_with_thread_kernel_state("Privileged access never abort.", state);
		}
#endif

#if CONFIG_PGTRACE
	} else if (ml_at_interrupt_context()) {
		panic_with_thread_kernel_state("Unexpected abort while on interrupt stack.", state);
#endif
	} else if (is_alignment_fault(fault_code)) {
		if (recover) {
			thread->machine.recover_esr = esr;
			thread->machine.recover_far = fault_addr;
			set_saved_state_pc_to_recovery_handler(state, recover);
			return;
		}
		panic_with_thread_kernel_state("Unaligned kernel data abort.", state);
	} else if (is_parity_error(fault_code)) {
#if defined(APPLE_ARM64_ARCH_FAMILY)
		if (fault_code == FSC_SYNC_PARITY) {
			arm64_platform_error(state, esr, fault_addr);
			return;
		}
#else
		panic_with_thread_kernel_state("Kernel parity error.", state);
#endif
	} else {
		kprintf("Unclassified kernel abort (fault_code=0x%x)\n", fault_code);
	}

	panic_with_thread_kernel_state("Kernel data abort.", state);
}

extern void syscall_trace(struct arm_saved_state * regs);

static void
handle_svc(arm_saved_state_t *state)
{
	int      trap_no = get_saved_state_svc_number(state);
	thread_t thread  = current_thread();
	struct   proc *p;

#define handle_svc_kprintf(x...) /* kprintf("handle_svc: " x) */

#define TRACE_SYSCALL 1
#if TRACE_SYSCALL
	syscall_trace(state);
#endif

	thread->iotier_override = THROTTLE_LEVEL_NONE; /* Reset IO tier override before handling SVC from userspace */

	if (trap_no == (int)PLATFORM_SYSCALL_TRAP_NO) {
		platform_syscall(state);
		panic("Returned from platform_syscall()?");
	}

	mach_kauth_cred_uthread_update();

	if (trap_no < 0) {
		if (trap_no == MACH_ARM_TRAP_ABSTIME) {
			handle_mach_absolute_time_trap(state);
			return;
		} else if (trap_no == MACH_ARM_TRAP_CONTTIME) {
			handle_mach_continuous_time_trap(state);
			return;
		}

		/* Counting perhaps better in the handler, but this is how it's been done */
		thread->syscalls_mach++;
		mach_syscall(state);
	} else {
		/* Counting perhaps better in the handler, but this is how it's been done */
		thread->syscalls_unix++;
		p = get_bsdthreadtask_info(thread);

		assert(p);

		unix_syscall(state, thread, (struct uthread*)thread->uthread, p);
	}
}

static void
handle_mach_absolute_time_trap(arm_saved_state_t *state)
{
	uint64_t now = mach_absolute_time();
	saved_state64(state)->x[0] = now;
}

static void
handle_mach_continuous_time_trap(arm_saved_state_t *state)
{
	uint64_t now = mach_continuous_time();
	saved_state64(state)->x[0] = now;
}

__attribute__((noreturn))
static void
handle_msr_trap(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t           exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr     = 0;

	if (!is_saved_state64(state)) {
		panic("MSR/MRS trap (ESR 0x%x) from 32-bit state\n", esr);
	}

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		panic("MSR/MRS trap (ESR 0x%x) from kernel\n", esr);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));
	codes[1] = instr;

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}


static void
handle_user_trapped_instruction32(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t           exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr;

	if (is_saved_state64(state)) {
		panic("ESR (0x%x) for instruction trapped from U32, but saved state is 64-bit.", esr);
	}

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		panic("ESR (0x%x) for instruction trapped from U32, actually came from kernel?", esr);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));
	codes[1] = instr;

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_simd_trap(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t           exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr     = 0;

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		panic("ESR (0x%x) for SIMD trap from userland, actually came from kernel?", esr);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));
	codes[1] = instr;

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

void
sleh_irq(arm_saved_state_t *state)
{
	uint64_t     timestamp                = 0;
	uint32_t     old_entropy_data         = 0;
	uint32_t     old_entropy_sample_count = 0;
	size_t       entropy_index            = 0;
	uint32_t *   entropy_data_ptr         = NULL;
	cpu_data_t * cdp __unused             = getCpuDatap();
#if MACH_ASSERT
	int preemption_level = get_preemption_level();
#endif


	sleh_interrupt_handler_prologue(state, DBG_INTR_TYPE_OTHER);

#if USE_APPLEARMSMP
	PE_handle_ext_interrupt();
#else
	/* Run the registered interrupt handler. */
	cdp->interrupt_handler(cdp->interrupt_target,
	    cdp->interrupt_refCon,
	    cdp->interrupt_nub,
	    cdp->interrupt_source);
#endif

	/* We use interrupt timing as an entropy source. */
	timestamp = ml_get_timebase();

	/*
	 * The buffer index is subject to races, but as these races should only
	 * result in multiple CPUs updating the same location, the end result
	 * should be that noise gets written into the entropy buffer.  As this
	 * is the entire point of the entropy buffer, we will not worry about
	 * these races for now.
	 */
	old_entropy_sample_count = EntropyData.sample_count;
	EntropyData.sample_count += 1;

	entropy_index = old_entropy_sample_count & EntropyData.buffer_index_mask;
	entropy_data_ptr = EntropyData.buffer + entropy_index;

	/* Mix the timestamp data and the old data together. */
	old_entropy_data = *entropy_data_ptr;
	*entropy_data_ptr = (uint32_t)timestamp ^ (__ror(old_entropy_data, 9) & EntropyData.ror_mask);

	sleh_interrupt_handler_epilogue();
#if MACH_ASSERT
	if (preemption_level != get_preemption_level()) {
		panic("irq handler %p changed preemption level from %d to %d", cdp->interrupt_handler, preemption_level, get_preemption_level());
	}
#endif
}

void
sleh_fiq(arm_saved_state_t *state)
{
	unsigned int type   = DBG_INTR_TYPE_UNKNOWN;
#if MACH_ASSERT
	int preemption_level = get_preemption_level();
#endif

#if MONOTONIC_FIQ
	uint64_t pmcr0 = 0, upmsr = 0;
#endif /* MONOTONIC_FIQ */

#if defined(HAS_IPI)
	boolean_t    is_ipi = FALSE;
	uint64_t     ipi_sr = 0;

	if (gFastIPI) {
		MRS(ipi_sr, ARM64_REG_IPI_SR);

		if (ipi_sr & 1) {
			is_ipi = TRUE;
		}
	}

	if (is_ipi) {
		type = DBG_INTR_TYPE_IPI;
	} else
#endif /* defined(HAS_IPI) */
#if MONOTONIC_FIQ
	if (mt_pmi_pending(&pmcr0, &upmsr)) {
		type = DBG_INTR_TYPE_PMI;
	} else
#endif /* MONOTONIC_FIQ */
	if (ml_get_timer_pending()) {
		type = DBG_INTR_TYPE_TIMER;
	}

	sleh_interrupt_handler_prologue(state, type);

#if defined(HAS_IPI)
	if (is_ipi) {
		/*
		 * Order is important here: we must ack the IPI by writing IPI_SR
		 * before we call cpu_signal_handler().  Otherwise, there will be
		 * a window between the completion of pending-signal processing in
		 * cpu_signal_handler() and the ack during which a newly-issued
		 * IPI to this CPU may be lost.  ISB is required to ensure the msr
		 * is retired before execution of cpu_signal_handler().
		 */
		MSR(ARM64_REG_IPI_SR, ipi_sr);
		__builtin_arm_isb(ISB_SY);
		cpu_signal_handler();
	} else
#endif /* defined(HAS_IPI) */
#if MONOTONIC_FIQ
	if (type == DBG_INTR_TYPE_PMI) {
		INTERRUPT_MASKED_DEBUG_START(mt_fiq, DBG_INTR_TYPE_PMI);
		mt_fiq(getCpuDatap(), pmcr0, upmsr);
		INTERRUPT_MASKED_DEBUG_END();
	} else
#endif /* MONOTONIC_FIQ */
	{
		/*
		 * We don't know that this is a timer, but we don't have insight into
		 * the other interrupts that go down this path.
		 */

		cpu_data_t *cdp = getCpuDatap();

		cdp->cpu_decrementer = -1; /* Large */

		/*
		 * ARM64_TODO: whether we're coming from userland is ignored right now.
		 * We can easily thread it through, but not bothering for the
		 * moment (AArch32 doesn't either).
		 */
		INTERRUPT_MASKED_DEBUG_START(rtclock_intr, DBG_INTR_TYPE_TIMER);
		rtclock_intr(TRUE);
		INTERRUPT_MASKED_DEBUG_END();
	}

	sleh_interrupt_handler_epilogue();
#if MACH_ASSERT
	if (preemption_level != get_preemption_level()) {
		panic("fiq type %u changed preemption level from %d to %d", type, preemption_level, get_preemption_level());
	}
#endif
}

void
sleh_serror(arm_context_t *context, uint32_t esr, vm_offset_t far)
{
	task_vtimer_check(current_thread());

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_SERR_ARM, 0) | DBG_FUNC_START,
	    esr, VM_KERNEL_ADDRHIDE(far));
	arm_saved_state_t *state = &context->ss;
#if MACH_ASSERT
	int preemption_level = get_preemption_level();
#endif

	ASSERT_CONTEXT_SANITY(context);
	arm64_platform_error(state, esr, far);
#if MACH_ASSERT
	if (preemption_level != get_preemption_level()) {
		panic("serror changed preemption level from %d to %d", preemption_level, get_preemption_level());
	}
#endif
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_SERR_ARM, 0) | DBG_FUNC_END,
	    esr, VM_KERNEL_ADDRHIDE(far));
}

void
mach_syscall_trace_exit(unsigned int retval,
    unsigned int call_number)
{
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) |
	    DBG_FUNC_END, retval, 0, 0, 0, 0);
}

__attribute__((noreturn))
void
thread_syscall_return(kern_return_t error)
{
	thread_t thread;
	struct arm_saved_state *state;

	thread = current_thread();
	state = get_user_regs(thread);

	assert(is_saved_state64(state));
	saved_state64(state)->x[0] = error;

#if MACH_ASSERT
	kern_allocation_name_t
	prior __assert_only = thread_get_kernel_state(thread)->allocation_name;
	assertf(prior == NULL, "thread_set_allocation_name(\"%s\") not cleared", kern_allocation_get_name(prior));
#endif /* MACH_ASSERT */

	if (kdebug_enable) {
		/* Invert syscall number (negative for a mach syscall) */
		mach_syscall_trace_exit(error, (-1) * get_saved_state_svc_number(state));
	}

	thread_exception_return();
}

void
syscall_trace(
	struct arm_saved_state * regs __unused)
{
	/* kprintf("syscall: %d\n", saved_state64(regs)->x[16]);  */
}

static void
sleh_interrupt_handler_prologue(arm_saved_state_t *state, unsigned int type)
{
	bool is_user = PSR64_IS_USER(get_saved_state_cpsr(state));

	task_vtimer_check(current_thread());

	uint64_t pc = is_user ? get_saved_state_pc(state) :
	    VM_KERNEL_UNSLIDE(get_saved_state_pc(state));

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_START,
	    0, pc, is_user, type);

#if CONFIG_TELEMETRY
	if (telemetry_needs_record) {
		telemetry_mark_curthread((boolean_t)is_user, FALSE);
	}
#endif /* CONFIG_TELEMETRY */
}

static void
sleh_interrupt_handler_epilogue(void)
{
#if KPERF
	kperf_interrupt();
#endif /* KPERF */
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_END);
}

void
sleh_invalid_stack(arm_context_t *context, uint32_t esr __unused, vm_offset_t far __unused)
{
	thread_t thread = current_thread();
	vm_offset_t kernel_stack_bottom, sp;

	sp = get_saved_state_sp(&context->ss);
	kernel_stack_bottom = round_page(thread->machine.kstackptr) - KERNEL_STACK_SIZE;

	if ((sp < kernel_stack_bottom) && (sp >= (kernel_stack_bottom - PAGE_SIZE))) {
		panic_with_thread_kernel_state("Invalid kernel stack pointer (probable overflow).", &context->ss);
	}

	panic_with_thread_kernel_state("Invalid kernel stack pointer (probable corruption).", &context->ss);
}

