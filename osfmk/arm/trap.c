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
#include <kern/debug.h>
#include <mach_kdp.h>
#include <machine/endian.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/vm_prot.h>
#include <mach/vm_types.h>
#include <mach/mach_traps.h>

#include <mach/exception.h>
#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <mach/message.h>
#include <mach/machine/thread_status.h>

#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_fault.h>
#include <vm/vm_kern.h>

#include <kern/ast.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/sched_prim.h>

#include <sys/kdebug.h>
#include <kperf/kperf.h>

#include <arm/trap.h>
#include <arm/caches_internal.h>
#include <arm/cpu_data_internal.h>
#include <arm/machdep_call.h>
#include <arm/machine_routines.h>
#include <arm/misc_protos.h>
#include <arm/setjmp.h>
#include <arm/proc_reg.h>

/*
 * External function prototypes.
 */
#include <kern/syscall_sw.h>
#include <kern/host.h>
#include <kern/processor.h>


#if CONFIG_DTRACE
extern kern_return_t dtrace_user_probe(arm_saved_state_t* regs, unsigned int instr);
extern boolean_t dtrace_tally_fault(user_addr_t);

/* Traps for userland processing. Can't include bsd/sys/fasttrap_isa.h, so copy and paste the trap instructions
 *  over from that file. Need to keep these in sync! */
#define FASTTRAP_ARM_INSTR 0xe7ffdefc
#define FASTTRAP_THUMB_INSTR 0xdefc

#define FASTTRAP_ARM_RET_INSTR 0xe7ffdefb
#define FASTTRAP_THUMB_RET_INSTR 0xdefb

/* See <rdar://problem/4613924> */
perfCallback tempDTraceTrapHook = NULL; /* Pointer to DTrace fbt trap hook routine */
#endif

#define COPYIN(dst, src, size)                                  \
	((regs->cpsr & PSR_MODE_MASK) != PSR_USER_MODE) ?       \
	        copyin_kern(dst, src, size)                     \
	:                                                       \
	        copyin(dst, src, size)

#define COPYOUT(src, dst, size)                                 \
	((regs->cpsr & PSR_MODE_MASK) != PSR_USER_MODE) ?       \
	        copyout_kern(src, dst, size)                    \
	:                                                       \
	        copyout(src, dst, size)

/* Second-level exception handlers forward declarations */
void            sleh_undef(struct arm_saved_state *, struct arm_vfpsaved_state *);
void            sleh_abort(struct arm_saved_state *, int);
static kern_return_t sleh_alignment(struct arm_saved_state *);
static void panic_with_thread_kernel_state(const char *msg, arm_saved_state_t *regs);

int             sleh_alignment_count = 0;
int             trap_on_alignment_fault = 0;

/*
 *	Routine:        sleh_undef
 *	Function:       Second level exception handler for undefined exception
 */

void
sleh_undef(struct arm_saved_state * regs, struct arm_vfpsaved_state * vfp_ss __unused)
{
	exception_type_t exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t code[2] = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t codeCnt = 2;
	thread_t        thread = current_thread();
	vm_offset_t     recover;

	recover = thread->recover;
	thread->recover = 0;

	getCpuDatap()->cpu_stat.undef_ex_cnt++;

	/* Inherit the interrupt masks from previous */
	if (!(regs->cpsr & PSR_INTMASK)) {
		ml_set_interrupts_enabled(TRUE);
	}

#if CONFIG_DTRACE
	if (tempDTraceTrapHook) {
		if (tempDTraceTrapHook(exception, regs, 0, 0) == KERN_SUCCESS) {
			/*
			 * If it succeeds, we are done...
			 */
			goto exit;
		}
	}

	/* Check to see if we've hit a userland probe */
	if ((regs->cpsr & PSR_MODE_MASK) == PSR_USER_MODE) {
		if (regs->cpsr & PSR_TF) {
			uint16_t instr = 0;

			if (COPYIN((user_addr_t)(regs->pc), (char *)&instr, (vm_size_t)(sizeof(uint16_t))) != KERN_SUCCESS) {
				goto exit;
			}

			if (instr == FASTTRAP_THUMB_INSTR || instr == FASTTRAP_THUMB_RET_INSTR) {
				if (dtrace_user_probe(regs, instr) == KERN_SUCCESS) {
					/* If it succeeds, we are done... */
					goto exit;
				}
			}
		} else {
			uint32_t instr = 0;

			if (COPYIN((user_addr_t)(regs->pc), (char *)&instr, (vm_size_t)(sizeof(uint32_t))) != KERN_SUCCESS) {
				goto exit;
			}

			if (instr == FASTTRAP_ARM_INSTR || instr == FASTTRAP_ARM_RET_INSTR) {
				if (dtrace_user_probe(regs, instr) == KERN_SUCCESS) {
					/* If it succeeds, we are done... */
					goto exit;
				}
			}
		}
	}
#endif /* CONFIG_DTRACE */


	if (regs->cpsr & PSR_TF) {
		unsigned short instr = 0;

		if (COPYIN((user_addr_t)(regs->pc), (char *)&instr, (vm_size_t)(sizeof(unsigned short))) != KERN_SUCCESS) {
			goto exit;
		}

		if (IS_THUMB32(instr)) {
			unsigned int instr32;

			instr32 = (instr << 16);

			if (COPYIN((user_addr_t)(((unsigned short *) (regs->pc)) + 1), (char *)&instr, (vm_size_t)(sizeof(unsigned short))) != KERN_SUCCESS) {
				goto exit;
			}

			instr32 |= instr;
			code[1] = instr32;

#if     __ARM_VFP__
			if (IS_THUMB_VFP(instr32)) {
				/* We no longer manage FPEXC beyond bootstrap, so verify that VFP is still enabled. */
				if (!get_vfp_enabled()) {
					panic("VFP was disabled (thumb); VFP should always be enabled");
				}
			}
#endif
		} else {
			/* I don't believe we have any 16 bit VFP instructions, so just set code[1]. */
			code[1] = instr;

			if (IS_THUMB_GDB_TRAP(instr)) {
				exception = EXC_BREAKPOINT;
				code[0] = EXC_ARM_BREAKPOINT;
			}
		}
	} else {
		uint32_t instr = 0;

		if (COPYIN((user_addr_t)(regs->pc), (char *)&instr, (vm_size_t)(sizeof(uint32_t))) != KERN_SUCCESS) {
			goto exit;
		}

		code[1] = instr;
#if     __ARM_VFP__
		if (IS_ARM_VFP(instr)) {
			/* We no longer manage FPEXC beyond bootstrap, so verify that VFP is still enabled. */
			if (!get_vfp_enabled()) {
				panic("VFP was disabled (arm); VFP should always be enabled");
			}
		}
#endif

		if (IS_ARM_GDB_TRAP(instr)) {
			exception = EXC_BREAKPOINT;
			code[0] = EXC_ARM_BREAKPOINT;
		}
	}

	if (!((regs->cpsr & PSR_MODE_MASK) == PSR_USER_MODE)) {
		boolean_t       intr;

		intr = ml_set_interrupts_enabled(FALSE);

		if (exception == EXC_BREAKPOINT) {
			/* Save off the context here (so that the debug logic
			 * can see the original state of this thread).
			 */
			vm_offset_t kstackptr = current_thread()->machine.kstackptr;
			copy_signed_thread_state((arm_saved_state_t *)kstackptr, regs);

			DebuggerCall(exception, regs);
			(void) ml_set_interrupts_enabled(intr);
			goto exit;
		}
		panic_with_thread_kernel_state("undefined kernel instruction", regs);

		(void) ml_set_interrupts_enabled(intr);
	} else {
		exception_triage(exception, code, codeCnt);
		/* NOTREACHED */
	}

exit:
	if (recover) {
		thread->recover = recover;
	}
}

/*
 *	Routine:	sleh_abort
 *	Function:	Second level exception handler for abort(Pref/Data)
 */

void
sleh_abort(struct arm_saved_state * regs, int type)
{
	int             status;
	int             debug_status = 0;
	int             spsr;
	int             exc = EXC_BAD_ACCESS;
	mach_exception_data_type_t codes[2];
	vm_map_t        map;
	vm_map_address_t vaddr;
	vm_map_address_t fault_addr;
	vm_prot_t       fault_type;
	kern_return_t   result;
	vm_offset_t     recover;
	thread_t        thread = current_thread();
	boolean_t               intr;

	recover = thread->recover;
	thread->recover = 0;

	status = regs->fsr & FSR_MASK;
	spsr = regs->cpsr;

	/* The DSFR/IFSR.ExT bit indicates "IMPLEMENTATION DEFINED" classification.
	 * Allow a platform-level error handler to decode it.
	 */
	if ((regs->fsr) & FSR_EXT) {
		cpu_data_t      *cdp = getCpuDatap();

		if (cdp->platform_error_handler != (platform_error_handler_t) NULL) {
			(*(platform_error_handler_t)cdp->platform_error_handler)(cdp->cpu_id, 0);
			/* If a platform error handler is registered, expect it to panic, not fall through */
			panic("Unexpected return from platform_error_handler");
		}
	}

	/* Done with asynchronous handling; re-enable here so that subsequent aborts are taken as early as possible. */
	reenable_async_aborts();

	if (ml_at_interrupt_context()) {
#if CONFIG_DTRACE
		if (!(thread->t_dtrace_inprobe))
#endif /* CONFIG_DTRACE */
		{
			panic_with_thread_kernel_state("sleh_abort at interrupt context", regs);
		}
	}

	fault_addr = vaddr = regs->far;

	if (type == T_DATA_ABT) {
		getCpuDatap()->cpu_stat.data_ex_cnt++;
	} else { /* T_PREFETCH_ABT */
		getCpuDatap()->cpu_stat.instr_ex_cnt++;
		fault_type = VM_PROT_READ | VM_PROT_EXECUTE;
	}

	if (status == FSR_DEBUG) {
		debug_status = arm_debug_read_dscr() & ARM_DBGDSCR_MOE_MASK;
	}

	/* Inherit the interrupt masks from previous */
	if (!(spsr & PSR_INTMASK)) {
		ml_set_interrupts_enabled(TRUE);
	}

	if (type == T_DATA_ABT) {
		/*
		 * Now that interrupts are reenabled, we can perform any needed
		 * copyin operations.
		 *
		 * Because we have reenabled interrupts, any instruction copy
		 * must be a copyin, even on UP systems.
		 */

		if (regs->fsr & DFSR_WRITE) {
			fault_type = (VM_PROT_READ | VM_PROT_WRITE);
			/* Cache operations report faults as write access, change these to read access */
			/* Cache operations are invoked from arm mode for now */
			if (!(regs->cpsr & PSR_TF)) {
				unsigned int ins = 0;

				if (COPYIN((user_addr_t)(regs->pc), (char *)&ins, (vm_size_t)(sizeof(unsigned int))) != KERN_SUCCESS) {
					goto exit;
				}

				if (arm_mcr_cp15(ins) || arm_mcrr_cp15(ins)) {
					fault_type = VM_PROT_READ;
				}
			}
		} else {
			fault_type = VM_PROT_READ;
			/*
			 * DFSR is not getting the "write" bit set
			 * when a swp instruction is encountered (even when it is
			 * a write fault.
			 */
			if (!(regs->cpsr & PSR_TF)) {
				unsigned int ins = 0;

				if (COPYIN((user_addr_t)(regs->pc), (char *)&ins, (vm_size_t)(sizeof(unsigned int))) != KERN_SUCCESS) {
					goto exit;
				}

				if ((ins & ARM_SWP_MASK) == ARM_SWP) {
					fault_type = VM_PROT_WRITE;
				}
			}
		}
	}

	if ((spsr & PSR_MODE_MASK) != PSR_USER_MODE) {
		/* Fault in kernel mode */

		if ((status == FSR_DEBUG)
		    && ((debug_status == ARM_DBGDSCR_MOE_ASYNC_WATCHPOINT) || (debug_status == ARM_DBGDSCR_MOE_SYNC_WATCHPOINT))
		    && (recover != 0) && (getCpuDatap()->cpu_user_debug != 0)) {
			/* If we hit a watchpoint in kernel mode, probably in a copyin/copyout which we don't want to
			 * abort.  Turn off watchpoints and keep going; we'll turn them back on in load_and_go_user.
			 */
			arm_debug_set(NULL);
			goto exit;
		}

		if ((type == T_PREFETCH_ABT) || (status == FSR_DEBUG)) {
			intr = ml_set_interrupts_enabled(FALSE);
			if (status == FSR_DEBUG) {
				DebuggerCall(EXC_BREAKPOINT, regs);
				(void) ml_set_interrupts_enabled(intr);
				goto exit;
			}
			panic_with_thread_kernel_state("prefetch abort in kernel mode", regs);

			(void) ml_set_interrupts_enabled(intr);
		} else if (TEST_FSR_VMFAULT(status)) {
#if CONFIG_DTRACE
			if (thread->t_dtrace_inprobe) {  /* Executing under dtrace_probe? */
				if (dtrace_tally_fault(fault_addr)) { /* Should a fault under dtrace be ignored? */
					/* Point to next instruction */
					regs->pc += ((regs->cpsr & PSR_TF) && !IS_THUMB32(*((uint16_t*) (regs->pc)))) ? 2 : 4;
					goto exit;
				} else {
					intr = ml_set_interrupts_enabled(FALSE);
					panic_with_thread_kernel_state("Unexpected page fault under dtrace_probe", regs);

					(void) ml_set_interrupts_enabled(intr);

					goto exit;
				}
			}
#endif

			if (VM_KERNEL_ADDRESS(vaddr) || thread == THREAD_NULL) {
				map = kernel_map;
			} else {
				map = thread->map;
			}

			if (!TEST_FSR_TRANSLATION_FAULT(status)) {
				/* check to see if it is just a pmap ref/modify fault */
				result = arm_fast_fault(map->pmap, trunc_page(fault_addr), fault_type, (status == FSR_PACCESS), FALSE);
				if (result == KERN_SUCCESS) {
					goto exit;
				}
			}

			/*
			 *  We have to "fault" the page in.
			 */
			result = vm_fault(map, fault_addr,
			    fault_type,
			    FALSE /* change_wiring */, VM_KERN_MEMORY_NONE,
			    (map == kernel_map) ? THREAD_UNINT : THREAD_ABORTSAFE, NULL, 0);

			if (result == KERN_SUCCESS) {
				goto exit;
			} else {
				/*
				 *  If we have a recover handler, invoke it now.
				 */
				if (recover != 0) {
					regs->pc = (register_t) (recover & ~0x1);
					regs->cpsr = (regs->cpsr & ~PSR_TF) | ((recover & 0x1) << PSR_TFb);
					goto exit;
				}
			}
		} else if ((status & FSR_ALIGN_MASK) == FSR_ALIGN) {
			result = sleh_alignment(regs);
			if (result == KERN_SUCCESS) {
				goto exit;
			} else {
				intr = ml_set_interrupts_enabled(FALSE);

				panic_with_thread_kernel_state("unaligned kernel data access", regs);

				(void) ml_set_interrupts_enabled(intr);

				goto exit;
			}
		}
		intr = ml_set_interrupts_enabled(FALSE);

		panic_plain("kernel abort type %d at pc 0x%08x, lr 0x%08x: fault_type=0x%x, fault_addr=0x%x\n"
		    "r0:   0x%08x  r1: 0x%08x  r2: 0x%08x  r3: 0x%08x\n"
		    "r4:   0x%08x  r5: 0x%08x  r6: 0x%08x  r7: 0x%08x\n"
		    "r8:   0x%08x  r9: 0x%08x r10: 0x%08x r11: 0x%08x\n"
		    "r12:  0x%08x  sp: 0x%08x  lr: 0x%08x  pc: 0x%08x\n"
		    "cpsr: 0x%08x fsr: 0x%08x far: 0x%08x\n",
		    type, regs->pc, regs->lr, fault_type, fault_addr,
		    regs->r[0], regs->r[1], regs->r[2], regs->r[3],
		    regs->r[4], regs->r[5], regs->r[6], regs->r[7],
		    regs->r[8], regs->r[9], regs->r[10], regs->r[11],
		    regs->r[12], regs->sp, regs->lr, regs->pc,
		    regs->cpsr, regs->fsr, regs->far);
	}
	/* Fault in user mode */

	if (TEST_FSR_VMFAULT(status)) {
		map = thread->map;

#if CONFIG_DTRACE
		if (thread->t_dtrace_inprobe) {  /* Executing under dtrace_probe? */
			if (dtrace_tally_fault(fault_addr)) { /* Should a user mode fault under dtrace be ignored? */
				if (recover) {
					regs->pc = recover;
				} else {
					intr = ml_set_interrupts_enabled(FALSE);

					panic_with_thread_kernel_state("copyin/out has no recovery point", regs);

					(void) ml_set_interrupts_enabled(intr);
				}
				goto exit;
			} else {
				intr = ml_set_interrupts_enabled(FALSE);

				panic_with_thread_kernel_state("Unexpected UMW page fault under dtrace_probe", regs);

				(void) ml_set_interrupts_enabled(intr);

				goto exit;
			}
		}
#endif

		if (!TEST_FSR_TRANSLATION_FAULT(status)) {
			/* check to see if it is just a pmap ref/modify fault */
			result = arm_fast_fault(map->pmap, trunc_page(fault_addr), fault_type, (status == FSR_PACCESS), TRUE);
			if (result == KERN_SUCCESS) {
				goto exception_return;
			}
		}

		/*
		 * We have to "fault" the page in.
		 */
		result = vm_fault(map, fault_addr, fault_type,
		    FALSE /* change_wiring */, VM_KERN_MEMORY_NONE,
		    THREAD_ABORTSAFE, NULL, 0);
		if (result == KERN_SUCCESS || result == KERN_ABORTED) {
			goto exception_return;
		}

		/*
		 * KERN_FAILURE here means preemption was disabled when we called vm_fault.
		 * That should never happen for a page fault from user space.
		 */
		if (__improbable(result == KERN_FAILURE)) {
			panic("vm_fault() KERN_FAILURE from user fault on thread %p", thread);
		}

		codes[0] = result;
	} else if ((status & FSR_ALIGN_MASK) == FSR_ALIGN) {
		if (sleh_alignment(regs) == KERN_SUCCESS) {
			goto exception_return;
		}
		codes[0] = EXC_ARM_DA_ALIGN;
	} else if (status == FSR_DEBUG) {
		exc = EXC_BREAKPOINT;
		codes[0] = EXC_ARM_DA_DEBUG;
	} else if ((status == FSR_SDOM) || (status == FSR_PDOM)) {
		panic_with_thread_kernel_state("Unexpected domain fault", regs);
	} else {
		codes[0] = KERN_FAILURE;
	}

	codes[1] = vaddr;
	exception_triage(exc, codes, 2);
	/* NOTREACHED */

exception_return:
	if (recover) {
		thread->recover = recover;
	}
	thread_exception_return();
	/* NOTREACHED */

exit:
	if (recover) {
		thread->recover = recover;
	}
	return;
}


/*
 *	Routine:        sleh_alignment
 *	Function:       Second level exception handler for alignment data fault
 */

static kern_return_t
sleh_alignment(struct arm_saved_state * regs)
{
	unsigned int    status;
	unsigned int    ins = 0;
	unsigned int    rd_index;
	unsigned int    base_index;
	unsigned int    paddr;
	void           *src;
	unsigned int    reg_list;
	unsigned int    pre;
	unsigned int    up;
	unsigned int    write_back;
	kern_return_t   rc = KERN_SUCCESS;

	getCpuDatap()->cpu_stat.unaligned_cnt++;

	/* Do not try to emulate in modified execution states */
	if (regs->cpsr & (PSR_EF | PSR_JF)) {
		return KERN_NOT_SUPPORTED;
	}

	/* Disallow emulation of kernel instructions */
	if ((regs->cpsr & PSR_MODE_MASK) != PSR_USER_MODE) {
		return KERN_NOT_SUPPORTED;
	}


#define ALIGN_THRESHOLD 1024
	if ((sleh_alignment_count++ & (ALIGN_THRESHOLD - 1)) ==
	    (ALIGN_THRESHOLD - 1)) {
		kprintf("sleh_alignment: %d more alignment faults: %d total\n",
		    ALIGN_THRESHOLD, sleh_alignment_count);
	}

	if ((trap_on_alignment_fault != 0)
	    && (sleh_alignment_count % trap_on_alignment_fault == 0)) {
		return KERN_NOT_SUPPORTED;
	}

	status = regs->fsr;
	paddr = regs->far;

	if (regs->cpsr & PSR_TF) {
		unsigned short ins16 = 0;

		/* Get aborted instruction */
#if     __ARM_SMP__ || __ARM_USER_PROTECT__
		if (COPYIN((user_addr_t)(regs->pc), (char *)&ins16, (vm_size_t)(sizeof(uint16_t))) != KERN_SUCCESS) {
			/* Failed to fetch instruction, return success to re-drive the exception */
			return KERN_SUCCESS;
		}
#else
		ins16 = *(unsigned short *) (regs->pc);
#endif

		/*
		 * Map multi-word Thumb loads and stores to their ARM
		 * equivalents.
		 * Don't worry about single-word instructions, since those are
		 * handled in hardware.
		 */

		reg_list = ins16 & 0xff;
		if (reg_list == 0) {
			return KERN_NOT_SUPPORTED;
		}

		if (((ins16 & THUMB_STR_1_MASK) == THUMB_LDMIA) ||
		    ((ins16 & THUMB_STR_1_MASK) == THUMB_STMIA)) {
			base_index = (ins16 >> 8) & 0x7;
			ins = 0xE8800000 | (base_index << 16) | reg_list;
			if ((ins16 & THUMB_STR_1_MASK) == THUMB_LDMIA) {
				ins |= (1 << 20);
			}
			if (((ins16 & THUMB_STR_1_MASK) == THUMB_STMIA) ||
			    !(reg_list & (1 << base_index))) {
				ins |= (1 << 21);
			}
		} else if ((ins16 & THUMB_PUSH_MASK) == THUMB_POP) {
			unsigned int    r = (ins16 >> 8) & 1;
			ins = 0xE8BD0000 | (r << 15) | reg_list;
		} else if ((ins16 & THUMB_PUSH_MASK) == THUMB_PUSH) {
			unsigned int    r = (ins16 >> 8) & 1;
			ins = 0xE92D0000 | (r << 14) | reg_list;
		} else {
			return KERN_NOT_SUPPORTED;
		}
	} else {
		/* Get aborted instruction */
#if     __ARM_SMP__ || __ARM_USER_PROTECT__
		if (COPYIN((user_addr_t)(regs->pc), (char *)&ins, (vm_size_t)(sizeof(unsigned int))) != KERN_SUCCESS) {
			/* Failed to fetch instruction, return success to re-drive the exception */
			return KERN_SUCCESS;
		}
#else
		ins = *(unsigned int *) (regs->pc);
#endif
	}

	/* Don't try to emulate unconditional instructions */
	if ((ins & 0xF0000000) == 0xF0000000) {
		return KERN_NOT_SUPPORTED;
	}

	pre = (ins >> 24) & 1;
	up = (ins >> 23) & 1;
	reg_list = ins & 0xffff;
	write_back = (ins >> 21) & 1;
	base_index = (ins >> 16) & 0xf;

	if ((ins & ARM_BLK_MASK) == ARM_STM) {  /* STM or LDM */
		int             reg_count = 0;
		int             waddr;

		for (rd_index = 0; rd_index < 16; rd_index++) {
			if (reg_list & (1 << rd_index)) {
				reg_count++;
			}
		}

		paddr = regs->r[base_index];

		switch (ins & (ARM_POST_INDEXING | ARM_INCREMENT)) {
		/* Increment after */
		case ARM_INCREMENT:
			waddr = paddr + reg_count * 4;
			break;

		/* Increment before */
		case ARM_POST_INDEXING | ARM_INCREMENT:
			waddr = paddr + reg_count * 4;
			paddr += 4;
			break;

		/* Decrement after */
		case 0:
			waddr = paddr - reg_count * 4;
			paddr = waddr + 4;
			break;

		/* Decrement before */
		case ARM_POST_INDEXING:
			waddr = paddr - reg_count * 4;
			paddr = waddr;
			break;

		default:
			waddr = 0;
		}

		for (rd_index = 0; rd_index < 16; rd_index++) {
			if (reg_list & (1 << rd_index)) {
				src = &regs->r[rd_index];

				if ((ins & (1 << 20)) == 0) {   /* STM */
					rc = COPYOUT(src, paddr, 4);
				} else { /* LDM */
					rc = COPYIN(paddr, src, 4);
				}

				if (rc != KERN_SUCCESS) {
					break;
				}

				paddr += 4;
			}
		}

		paddr = waddr;
	} else {
		rc = 1;
	}

	if (rc == KERN_SUCCESS) {
		if (regs->cpsr & PSR_TF) {
			regs->pc += 2;
		} else {
			regs->pc += 4;
		}

		if (write_back) {
			regs->r[base_index] = paddr;
		}
	}
	return rc;
}


#ifndef NO_KDEBUG
/* XXX quell warnings */
void            syscall_trace(struct arm_saved_state * regs);
void            syscall_trace_exit(unsigned int, unsigned int);
void            mach_syscall_trace(struct arm_saved_state * regs, unsigned int call_number);
void            mach_syscall_trace_exit(unsigned int retval, unsigned int call_number);
void            interrupt_trace(struct arm_saved_state * regs);
void            interrupt_trace_exit(void);

/* called from the fleh_swi handler, if TRACE_SYSCALL is enabled */
void
syscall_trace(
	struct arm_saved_state * regs)
{
	kprintf("syscall: %d\n", regs->r[12]);
}

void
syscall_trace_exit(
	unsigned int r0,
	unsigned int r1)
{
	kprintf("syscall exit: 0x%x 0x%x\n", r0, r1);
}

void
mach_syscall_trace(
	struct arm_saved_state * regs,
	unsigned int call_number)
{
	int             i, argc;
	int             kdarg[3] = {0, 0, 0};

	argc = mach_trap_table[call_number].mach_trap_arg_count;

	if (argc > 3) {
		argc = 3;
	}

	for (i = 0; i < argc; i++) {
		kdarg[i] = (int) regs->r[i];
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_START,
	    kdarg[0], kdarg[1], kdarg[2], 0, 0);
}

void
mach_syscall_trace_exit(
	unsigned int retval,
	unsigned int call_number)
{
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_END,
	    retval, 0, 0, 0, 0);
}

void
interrupt_trace(
	struct arm_saved_state * regs)
{
#define UMODE(rp)       (((rp)->cpsr & PSR_MODE_MASK) == PSR_USER_MODE)

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_START,
	    0, UMODE(regs) ? regs->pc : VM_KERNEL_UNSLIDE(regs->pc),
	    UMODE(regs), 0, 0);
}

void
interrupt_trace_exit(
	void)
{
#if KPERF
	kperf_interrupt();
#endif /* KPERF */
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_END);
}
#endif

/* XXX quell warnings */
void interrupt_stats(void);

/* This is called from locore.s directly. We only update per-processor interrupt counters in this function */
void
interrupt_stats(void)
{
	SCHED_STATS_INTERRUPT(current_processor());
}

__dead2
static void
panic_with_thread_kernel_state(const char *msg, struct arm_saved_state *regs)
{
	panic_plain("%s at pc 0x%08x, lr 0x%08x (saved state:%p)\n"
	    "r0:   0x%08x  r1: 0x%08x  r2: 0x%08x  r3: 0x%08x\n"
	    "r4:   0x%08x  r5: 0x%08x  r6: 0x%08x  r7: 0x%08x\n"
	    "r8:   0x%08x  r9: 0x%08x r10: 0x%08x r11: 0x%08x\n"
	    "r12:  0x%08x  sp: 0x%08x  lr: 0x%08x  pc: 0x%08x\n"
	    "cpsr: 0x%08x fsr: 0x%08x far: 0x%08x\n",
	    msg, regs->pc, regs->lr, regs,
	    regs->r[0], regs->r[1], regs->r[2], regs->r[3],
	    regs->r[4], regs->r[5], regs->r[6], regs->r[7],
	    regs->r[8], regs->r[9], regs->r[10], regs->r[11],
	    regs->r[12], regs->sp, regs->lr, regs->pc,
	    regs->cpsr, regs->fsr, regs->far);
}
