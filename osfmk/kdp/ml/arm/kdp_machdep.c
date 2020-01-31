/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/exception_types.h>
#include <arm/exception.h>
#include <arm/pmap.h>
#include <arm/proc_reg.h>
#include <arm/thread.h>
#include <arm/trap.h>
#include <arm/cpu_data_internal.h>
#include <kdp/kdp_internal.h>
#include <kern/debug.h>
#include <IOKit/IOPlatformExpert.h>
#include <kern/kalloc.h>
#include <libkern/OSAtomic.h>
#include <vm/vm_map.h>


#define KDP_TEST_HARNESS 0
#if KDP_TEST_HARNESS
#define dprintf(x) kprintf x
#else
#define dprintf(x) do {} while (0)
#endif

void            halt_all_cpus(boolean_t);
void kdp_call(void);
int kdp_getc(void);
int machine_trace_thread(thread_t thread,
    char * tracepos,
    char * tracebound,
    int nframes,
    boolean_t user_p,
    boolean_t trace_fp,
    uint32_t * thread_trace_flags);
int machine_trace_thread64(thread_t thread,
    char * tracepos,
    char * tracebound,
    int nframes,
    boolean_t user_p,
    boolean_t trace_fp,
    uint32_t * thread_trace_flags,
    uint64_t *sp);

void kdp_trap(unsigned int, struct arm_saved_state * saved_state);

extern vm_offset_t machine_trace_thread_get_kva(vm_offset_t cur_target_addr, vm_map_t map, uint32_t *thread_trace_flags);
extern void machine_trace_thread_clear_validation_cache(void);
extern vm_map_t kernel_map;

#if CONFIG_KDP_INTERACTIVE_DEBUGGING
void
kdp_exception(
	unsigned char * pkt, int * len, unsigned short * remote_port, unsigned int exception, unsigned int code, unsigned int subcode)
{
	struct {
		kdp_exception_t pkt;
		kdp_exc_info_t exc;
	} aligned_pkt;

	kdp_exception_t * rq = (kdp_exception_t *)&aligned_pkt;

	bcopy((char *)pkt, (char *)rq, sizeof(*rq));
	rq->hdr.request = KDP_EXCEPTION;
	rq->hdr.is_reply = 0;
	rq->hdr.seq = kdp.exception_seq;
	rq->hdr.key = 0;
	rq->hdr.len = sizeof(*rq) + sizeof(kdp_exc_info_t);

	rq->n_exc_info = 1;
	rq->exc_info[0].cpu = 0;
	rq->exc_info[0].exception = exception;
	rq->exc_info[0].code = code;
	rq->exc_info[0].subcode = subcode;

	rq->hdr.len += rq->n_exc_info * sizeof(kdp_exc_info_t);

	bcopy((char *)rq, (char *)pkt, rq->hdr.len);

	kdp.exception_ack_needed = TRUE;

	*remote_port = kdp.exception_port;
	*len = rq->hdr.len;
}

boolean_t
kdp_exception_ack(unsigned char * pkt, int len)
{
	kdp_exception_ack_t aligned_pkt;
	kdp_exception_ack_t * rq = (kdp_exception_ack_t *)&aligned_pkt;

	if ((unsigned)len < sizeof(*rq)) {
		return FALSE;
	}

	bcopy((char *)pkt, (char *)rq, sizeof(*rq));

	if (!rq->hdr.is_reply || rq->hdr.request != KDP_EXCEPTION) {
		return FALSE;
	}

	dprintf(("kdp_exception_ack seq %x %x\n", rq->hdr.seq, kdp.exception_seq));

	if (rq->hdr.seq == kdp.exception_seq) {
		kdp.exception_ack_needed = FALSE;
		kdp.exception_seq++;
	}
	return TRUE;
}

static void
kdp_getintegerstate(char * out_state)
{
#if defined(__arm__)
	struct arm_thread_state thread_state;
	struct arm_saved_state *saved_state;

	saved_state = kdp.saved_state;

	bzero((char *) &thread_state, sizeof(struct arm_thread_state));

	saved_state_to_thread_state32(saved_state, &thread_state);

	bcopy((char *) &thread_state, (char *) out_state, sizeof(struct arm_thread_state));
#elif defined(__arm64__)
	struct arm_thread_state64 thread_state64;
	arm_saved_state_t *saved_state;

	saved_state = kdp.saved_state;
	assert(is_saved_state64(saved_state));

	bzero((char *) &thread_state64, sizeof(struct arm_thread_state64));

	saved_state_to_thread_state64(saved_state, &thread_state64);

	bcopy((char *) &thread_state64, (char *) out_state, sizeof(struct arm_thread_state64));
#else
#error Unknown architecture.
#endif
}

kdp_error_t
kdp_machine_read_regs(__unused unsigned int cpu, unsigned int flavor, char * data, int * size)
{
	switch (flavor) {
#if defined(__arm__)
	case ARM_THREAD_STATE:
		dprintf(("kdp_readregs THREAD_STATE\n"));
		kdp_getintegerstate(data);
		*size = ARM_THREAD_STATE_COUNT * sizeof(int);
		return KDPERR_NO_ERROR;
#elif defined(__arm64__)
	case ARM_THREAD_STATE64:
		dprintf(("kdp_readregs THREAD_STATE64\n"));
		kdp_getintegerstate(data);
		*size = ARM_THREAD_STATE64_COUNT * sizeof(int);
		return KDPERR_NO_ERROR;
#endif

	case ARM_VFP_STATE:
		dprintf(("kdp_readregs THREAD_FPSTATE\n"));
		bzero((char *) data, sizeof(struct arm_vfp_state));
		*size = ARM_VFP_STATE_COUNT * sizeof(int);
		return KDPERR_NO_ERROR;

	default:
		dprintf(("kdp_readregs bad flavor %d\n"));
		return KDPERR_BADFLAVOR;
	}
}

static void
kdp_setintegerstate(char * state_in)
{
#if defined(__arm__)
	struct arm_thread_state thread_state;
	struct arm_saved_state *saved_state;

	bcopy((char *) state_in, (char *) &thread_state, sizeof(struct arm_thread_state));
	saved_state = kdp.saved_state;

	thread_state32_to_saved_state(&thread_state, saved_state);
#elif defined(__arm64__)
	struct arm_thread_state64 thread_state64;
	struct arm_saved_state *saved_state;

	bcopy((char *) state_in, (char *) &thread_state64, sizeof(struct arm_thread_state64));
	saved_state = kdp.saved_state;
	assert(is_saved_state64(saved_state));

	thread_state64_to_saved_state(&thread_state64, saved_state);
#else
#error Unknown architecture.
#endif
}

kdp_error_t
kdp_machine_write_regs(__unused unsigned int cpu, unsigned int flavor, char * data, __unused int * size)
{
	switch (flavor) {
#if defined(__arm__)
	case ARM_THREAD_STATE:
		dprintf(("kdp_writeregs THREAD_STATE\n"));
		kdp_setintegerstate(data);
		return KDPERR_NO_ERROR;
#elif defined(__arm64__)
	case ARM_THREAD_STATE64:
		dprintf(("kdp_writeregs THREAD_STATE64\n"));
		kdp_setintegerstate(data);
		return KDPERR_NO_ERROR;
#endif

	case ARM_VFP_STATE:
		dprintf(("kdp_writeregs THREAD_FPSTATE\n"));
		return KDPERR_NO_ERROR;

	default:
		dprintf(("kdp_writeregs bad flavor %d\n"));
		return KDPERR_BADFLAVOR;
	}
}

void
kdp_machine_hostinfo(kdp_hostinfo_t * hostinfo)
{
	hostinfo->cpus_mask = 1;
	hostinfo->cpu_type = slot_type(0);
	hostinfo->cpu_subtype = slot_subtype(0);
}

__attribute__((noreturn))
void
kdp_panic(const char * msg)
{
	printf("kdp panic: %s\n", msg);
	while (1) {
	}
	;
}

int
kdp_intr_disbl(void)
{
	return splhigh();
}

void
kdp_intr_enbl(int s)
{
	splx(s);
}

void
kdp_us_spin(int usec)
{
	delay(usec / 100);
}

void
kdp_call(void)
{
	Debugger("inline call to debugger(machine_startup)");
}

int
kdp_getc(void)
{
	return cnmaygetc();
}

void
kdp_machine_get_breakinsn(uint8_t * bytes, uint32_t * size)
{
	*(uint32_t *)bytes = GDB_TRAP_INSTR1;
	*size = sizeof(uint32_t);
}

void
kdp_sync_cache(void)
{
}

int
kdp_machine_ioport_read(kdp_readioport_req_t * rq, caddr_t data, uint16_t lcpu)
{
#pragma unused(rq, data, lcpu)
	return 0;
}

int
kdp_machine_ioport_write(kdp_writeioport_req_t * rq, caddr_t data, uint16_t lcpu)
{
#pragma unused(rq, data, lcpu)
	return 0;
}

int
kdp_machine_msr64_read(kdp_readmsr64_req_t *rq, caddr_t data, uint16_t lcpu)
{
#pragma unused(rq, data, lcpu)
	return 0;
}

int
kdp_machine_msr64_write(kdp_writemsr64_req_t *rq, caddr_t data, uint16_t lcpu)
{
#pragma unused(rq, data, lcpu)
	return 0;
}
#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */

void
kdp_trap(unsigned int exception, struct arm_saved_state * saved_state)
{
	handle_debugger_trap(exception, 0, 0, saved_state);

#if defined(__arm__)
	if (saved_state->cpsr & PSR_TF) {
		unsigned short instr = *((unsigned short *)(saved_state->pc));
		if ((instr == (GDB_TRAP_INSTR1 & 0xFFFF)) || (instr == (GDB_TRAP_INSTR2 & 0xFFFF))) {
			saved_state->pc += 2;
		}
	} else {
		unsigned int instr = *((unsigned int *)(saved_state->pc));
		if ((instr == GDB_TRAP_INSTR1) || (instr == GDB_TRAP_INSTR2)) {
			saved_state->pc += 4;
		}
	}

#elif defined(__arm64__)
	assert(is_saved_state64(saved_state));

	uint32_t instr = *((uint32_t *)get_saved_state_pc(saved_state));

	/*
	 * As long as we are using the arm32 trap encoding to handling
	 * traps to the debugger, we should identify both variants and
	 * increment for both of them.
	 */
	if ((instr == GDB_TRAP_INSTR1) || (instr == GDB_TRAP_INSTR2)) {
		set_saved_state_pc(saved_state, get_saved_state_pc(saved_state) + 4);
	}
#else
#error Unknown architecture.
#endif
}

#define ARM32_LR_OFFSET 4
#define ARM64_LR_OFFSET 8

/*
 * Since sizeof (struct thread_snapshot) % 4 == 2
 * make sure the compiler does not try to use word-aligned
 * access to this data, which can result in alignment faults
 * that can't be emulated in KDP context.
 */
typedef uint32_t uint32_align2_t __attribute__((aligned(2)));

int
machine_trace_thread(thread_t thread,
    char * tracepos,
    char * tracebound,
    int nframes,
    boolean_t user_p,
    boolean_t trace_fp,
    uint32_t * thread_trace_flags)
{
	uint32_align2_t * tracebuf = (uint32_align2_t *)tracepos;

	vm_size_t framesize = (trace_fp ? 2 : 1) * sizeof(uint32_t);

	vm_offset_t stacklimit        = 0;
	vm_offset_t stacklimit_bottom = 0;
	int framecount                = 0;
	uint32_t short_fp             = 0;
	vm_offset_t fp                = 0;
	vm_offset_t pc, sp;
	vm_offset_t prevfp            = 0;
	uint32_t prevlr               = 0;
	struct arm_saved_state * state;
	vm_offset_t kern_virt_addr = 0;
	vm_map_t bt_vm_map            = VM_MAP_NULL;

	nframes = (tracebound > tracepos) ? MIN(nframes, (int)((tracebound - tracepos) / framesize)) : 0;
	if (!nframes) {
		return 0;
	}
	framecount = 0;

	if (user_p) {
		/* Examine the user savearea */
		state = get_user_regs(thread);
		stacklimit = VM_MAX_ADDRESS;
		stacklimit_bottom = VM_MIN_ADDRESS;

		/* Fake up a stack frame for the PC */
		*tracebuf++ = (uint32_t)get_saved_state_pc(state);
		if (trace_fp) {
			*tracebuf++ = (uint32_t)get_saved_state_sp(state);
		}
		framecount++;
		bt_vm_map = thread->task->map;
	} else {
#if defined(__arm64__)
		panic("Attempted to trace kernel thread_t %p as a 32-bit context", thread);
		return 0;
#elif defined(__arm__)
		/* kstackptr may not always be there, so recompute it */
		state = &thread_get_kernel_state(thread)->machine;

		stacklimit = VM_MAX_KERNEL_ADDRESS;
		stacklimit_bottom = VM_MIN_KERNEL_ADDRESS;
		bt_vm_map = kernel_map;
#else
#error Unknown architecture.
#endif
	}

	/* Get the frame pointer */
	fp = get_saved_state_fp(state);

	/* Fill in the current link register */
	prevlr = (uint32_t)get_saved_state_lr(state);
	pc = get_saved_state_pc(state);
	sp = get_saved_state_sp(state);

	if (!user_p && !prevlr && !fp && !sp && !pc) {
		return 0;
	}

	if (!user_p) {
		/* This is safe since we will panic above on __arm64__ if !user_p */
		prevlr = (uint32_t)VM_KERNEL_UNSLIDE(prevlr);
	}

	for (; framecount < nframes; framecount++) {
		*tracebuf++ = prevlr;
		if (trace_fp) {
			*tracebuf++ = (uint32_t)fp;
		}

		/* Invalid frame */
		if (!fp) {
			break;
		}
		/* Unaligned frame */
		if (fp & 0x0000003) {
			break;
		}
		/* Frame is out of range, maybe a user FP while doing kernel BT */
		if (fp > stacklimit) {
			break;
		}
		if (fp < stacklimit_bottom) {
			break;
		}
		/* Stack grows downward */
		if (fp < prevfp) {
			boolean_t prev_in_interrupt_stack = FALSE;

			if (!user_p) {
				/*
				 * As a special case, sometimes we are backtracing out of an interrupt
				 * handler, and the stack jumps downward because of the memory allocation
				 * pattern during early boot due to KASLR.
				 */
				int cpu;
				int max_cpu = ml_get_max_cpu_number();

				for (cpu = 0; cpu <= max_cpu; cpu++) {
					cpu_data_t      *target_cpu_datap;

					target_cpu_datap = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;
					if (target_cpu_datap == (cpu_data_t *)NULL) {
						continue;
					}

					if (prevfp >= (target_cpu_datap->intstack_top - INTSTACK_SIZE) && prevfp < target_cpu_datap->intstack_top) {
						prev_in_interrupt_stack = TRUE;
						break;
					}

#if defined(__arm__)
					if (prevfp >= (target_cpu_datap->fiqstack_top - FIQSTACK_SIZE) && prevfp < target_cpu_datap->fiqstack_top) {
						prev_in_interrupt_stack = TRUE;
						break;
					}
#elif defined(__arm64__)
					if (prevfp >= (target_cpu_datap->excepstack_top - EXCEPSTACK_SIZE) && prevfp < target_cpu_datap->excepstack_top) {
						prev_in_interrupt_stack = TRUE;
						break;
					}
#endif
				}
			}

			if (!prev_in_interrupt_stack) {
				/* Corrupt frame pointer? */
				break;
			}
		}
		/* Assume there's a saved link register, and read it */
		kern_virt_addr = machine_trace_thread_get_kva(fp + ARM32_LR_OFFSET, bt_vm_map, thread_trace_flags);

		if (!kern_virt_addr) {
			if (thread_trace_flags) {
				*thread_trace_flags |= kThreadTruncatedBT;
			}
			break;
		}

		prevlr = *(uint32_t *)kern_virt_addr;
		if (!user_p) {
			/* This is safe since we will panic above on __arm64__ if !user_p */
			prevlr = (uint32_t)VM_KERNEL_UNSLIDE(prevlr);
		}

		prevfp = fp;

		/*
		 * Next frame; read the fp value into short_fp first
		 * as it is 32-bit.
		 */
		kern_virt_addr = machine_trace_thread_get_kva(fp, bt_vm_map, thread_trace_flags);

		if (kern_virt_addr) {
			short_fp = *(uint32_t *)kern_virt_addr;
			fp = (vm_offset_t) short_fp;
		} else {
			fp = 0;
			if (thread_trace_flags) {
				*thread_trace_flags |= kThreadTruncatedBT;
			}
		}
	}
	/* Reset the target pmap */
	machine_trace_thread_clear_validation_cache();
	return (int)(((char *)tracebuf) - tracepos);
}

int
machine_trace_thread64(thread_t thread,
    char * tracepos,
    char * tracebound,
    int nframes,
    boolean_t user_p,
    boolean_t trace_fp,
    uint32_t * thread_trace_flags,
    uint64_t *sp_out)
{
#pragma unused(sp_out)
#if defined(__arm__)
#pragma unused(thread, tracepos, tracebound, nframes, user_p, trace_fp, thread_trace_flags)
	return 0;
#elif defined(__arm64__)

	uint64_t * tracebuf = (uint64_t *)tracepos;
	vm_size_t framesize = (trace_fp ? 2 : 1) * sizeof(uint64_t);

	vm_offset_t stacklimit        = 0;
	vm_offset_t stacklimit_bottom = 0;
	int framecount                = 0;
	vm_offset_t fp                = 0;
	vm_offset_t pc                = 0;
	vm_offset_t sp                = 0;
	vm_offset_t prevfp            = 0;
	uint64_t prevlr               = 0;
	struct arm_saved_state * state;
	vm_offset_t kern_virt_addr    = 0;
	vm_map_t bt_vm_map            = VM_MAP_NULL;

	const boolean_t is_64bit_addr = thread_is_64bit_addr(thread);

	nframes = (tracebound > tracepos) ? MIN(nframes, (int)((tracebound - tracepos) / framesize)) : 0;
	if (!nframes) {
		return 0;
	}
	framecount = 0;

	if (user_p) {
		/* Examine the user savearea */
		state = thread->machine.upcb;
		stacklimit = (is_64bit_addr) ? MACH_VM_MAX_ADDRESS : VM_MAX_ADDRESS;
		stacklimit_bottom = (is_64bit_addr) ? MACH_VM_MIN_ADDRESS : VM_MIN_ADDRESS;

		/* Fake up a stack frame for the PC */
		*tracebuf++ = get_saved_state_pc(state);
		if (trace_fp) {
			*tracebuf++ = get_saved_state_sp(state);
		}
		framecount++;
		bt_vm_map = thread->task->map;
	} else {
		/* kstackptr may not always be there, so recompute it */
		state = &thread_get_kernel_state(thread)->machine.ss;
		stacklimit = VM_MAX_KERNEL_ADDRESS;
		stacklimit_bottom = VM_MIN_KERNEL_ADDRESS;
		bt_vm_map = kernel_map;
	}

	/* Get the frame pointer */
	fp = get_saved_state_fp(state);

	/* Fill in the current link register */
	prevlr = get_saved_state_lr(state);
	pc = get_saved_state_pc(state);
	sp = get_saved_state_sp(state);

	if (!user_p && !prevlr && !fp && !sp && !pc) {
		return 0;
	}

	if (!user_p) {
		prevlr = VM_KERNEL_UNSLIDE(prevlr);
	}

	for (; framecount < nframes; framecount++) {
		*tracebuf++ = prevlr;
		if (trace_fp) {
			*tracebuf++ = fp;
		}

		/* Invalid frame */
		if (!fp) {
			break;
		}
		/*
		 * Unaligned frame; given that the stack register must always be
		 * 16-byte aligned, we are assured 8-byte alignment of the saved
		 * frame pointer and link register.
		 */
		if (fp & 0x0000007) {
			break;
		}
		/* Frame is out of range, maybe a user FP while doing kernel BT */
		if (fp > stacklimit) {
			break;
		}
		if (fp < stacklimit_bottom) {
			break;
		}
		/* Stack grows downward */
		if (fp < prevfp) {
			boolean_t switched_stacks = FALSE;

			if (!user_p) {
				/*
				 * As a special case, sometimes we are backtracing out of an interrupt
				 * handler, and the stack jumps downward because of the memory allocation
				 * pattern during early boot due to KASLR.
				 */
				int cpu;
				int max_cpu = ml_get_max_cpu_number();

				for (cpu = 0; cpu <= max_cpu; cpu++) {
					cpu_data_t      *target_cpu_datap;

					target_cpu_datap = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;
					if (target_cpu_datap == (cpu_data_t *)NULL) {
						continue;
					}

					if (prevfp >= (target_cpu_datap->intstack_top - INTSTACK_SIZE) && prevfp < target_cpu_datap->intstack_top) {
						switched_stacks = TRUE;
						break;
					}
#if defined(__arm__)
					if (prevfp >= (target_cpu_datap->fiqstack_top - FIQSTACK_SIZE) && prevfp < target_cpu_datap->fiqstack_top) {
						switched_stacks = TRUE;
						break;
					}
#elif defined(__arm64__)
					if (prevfp >= (target_cpu_datap->excepstack_top - EXCEPSTACK_SIZE) && prevfp < target_cpu_datap->excepstack_top) {
						switched_stacks = TRUE;
						break;
					}
#endif
				}

			}

			if (!switched_stacks) {
				/* Corrupt frame pointer? */
				break;
			}
		}

		/* Assume there's a saved link register, and read it */
		kern_virt_addr = machine_trace_thread_get_kva(fp + ARM64_LR_OFFSET, bt_vm_map, thread_trace_flags);

		if (!kern_virt_addr) {
			if (thread_trace_flags) {
				*thread_trace_flags |= kThreadTruncatedBT;
			}
			break;
		}

		prevlr = *(uint64_t *)kern_virt_addr;
		if (!user_p) {
			prevlr = VM_KERNEL_UNSLIDE(prevlr);
		}

		prevfp = fp;
		/* Next frame */
		kern_virt_addr = machine_trace_thread_get_kva(fp, bt_vm_map, thread_trace_flags);

		if (kern_virt_addr) {
			fp = *(uint64_t *)kern_virt_addr;
		} else {
			fp = 0;
			if (thread_trace_flags) {
				*thread_trace_flags |= kThreadTruncatedBT;
			}
		}
	}
	/* Reset the target pmap */
	machine_trace_thread_clear_validation_cache();
	return (int)(((char *)tracebuf) - tracepos);
#else
#error Unknown architecture.
#endif
}

void
kdp_ml_enter_debugger(void)
{
	__asm__ volatile (".long 0xe7ffdefe");
}
