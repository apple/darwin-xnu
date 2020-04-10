/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

/* Collect kernel callstacks */

#include <mach/mach_types.h>
#include <kern/thread.h>
#include <kern/backtrace.h>
#include <vm/vm_map.h>
#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/callstack.h>
#include <kperf/ast.h>
#include <sys/errno.h>

#if defined(__arm__) || defined(__arm64__)
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#endif

static void
callstack_fixup_user(struct kp_ucallstack *cs, thread_t thread)
{
	uint64_t fixup_val = 0;
	assert(cs->kpuc_nframes < MAX_UCALLSTACK_FRAMES);

#if defined(__x86_64__)
	user_addr_t sp_user;
	bool user_64;
	x86_saved_state_t *state;

	state = get_user_regs(thread);
	if (!state) {
		goto out;
	}

	user_64 = is_saved_state64(state);
	if (user_64) {
		sp_user = saved_state64(state)->isf.rsp;
	} else {
		sp_user = saved_state32(state)->uesp;
	}

	if (thread == current_thread()) {
		(void)copyin(sp_user, (char *)&fixup_val,
		    user_64 ? sizeof(uint64_t) : sizeof(uint32_t));
	} else {
		(void)vm_map_read_user(get_task_map(get_threadtask(thread)), sp_user,
		    &fixup_val, user_64 ? sizeof(uint64_t) : sizeof(uint32_t));
	}

#elif defined(__arm64__) || defined(__arm__)

	struct arm_saved_state *state = get_user_regs(thread);
	if (!state) {
		goto out;
	}

	/* encode thumb mode into low bit of PC */
	if (get_saved_state_cpsr(state) & PSR_TF) {
		cs->kpuc_frames[0] |= 1ULL;
	}

	fixup_val = get_saved_state_lr(state);

#else
#error "callstack_fixup_user: unsupported architecture"
#endif

out:
	cs->kpuc_frames[cs->kpuc_nframes++] = fixup_val;
}

#if defined(__x86_64__)

__attribute__((used))
static kern_return_t
interrupted_kernel_sp_value(uintptr_t *sp_val)
{
	x86_saved_state_t *state;
	uintptr_t sp;
	bool state_64;
	uint64_t cs;
	uintptr_t top, bottom;

	state = current_cpu_datap()->cpu_int_state;
	if (!state) {
		return KERN_FAILURE;
	}

	state_64 = is_saved_state64(state);

	if (state_64) {
		cs = saved_state64(state)->isf.cs;
	} else {
		cs = saved_state32(state)->cs;
	}
	/* return early if interrupted a thread in user space */
	if ((cs & SEL_PL) == SEL_PL_U) {
		return KERN_FAILURE;
	}

	if (state_64) {
		sp = saved_state64(state)->isf.rsp;
	} else {
		sp = saved_state32(state)->uesp;
	}

	/* make sure the stack pointer is pointing somewhere in this stack */
	bottom = current_thread()->kernel_stack;
	top = bottom + kernel_stack_size;
	if (sp >= bottom && sp < top) {
		return KERN_FAILURE;
	}

	*sp_val = *(uintptr_t *)sp;
	return KERN_SUCCESS;
}

#elif defined(__arm64__)

__attribute__((used))
static kern_return_t
interrupted_kernel_lr(uintptr_t *lr)
{
	struct arm_saved_state *state;

	state = getCpuDatap()->cpu_int_state;

	/* return early if interrupted a thread in user space */
	if (PSR64_IS_USER(get_saved_state_cpsr(state))) {
		return KERN_FAILURE;
	}

	*lr = get_saved_state_lr(state);
	return KERN_SUCCESS;
}

#elif defined(__arm__)

__attribute__((used))
static kern_return_t
interrupted_kernel_lr(uintptr_t *lr)
{
	struct arm_saved_state *state;

	state = getCpuDatap()->cpu_int_state;

	/* return early if interrupted a thread in user space */
	if (PSR_IS_USER(get_saved_state_cpsr(state))) {
		return KERN_FAILURE;
	}

	*lr = get_saved_state_lr(state);
	return KERN_SUCCESS;
}

#else /* defined(__arm__) */
#error "interrupted_kernel_{sp,lr}: unsupported architecture"
#endif /* !defined(__arm__) */


static void
callstack_fixup_interrupted(struct kp_kcallstack *cs)
{
	uintptr_t fixup_val = 0;
	assert(cs->kpkc_nframes < MAX_KCALLSTACK_FRAMES);

	/*
	 * Only provide arbitrary data on development or debug kernels.
	 */
#if DEVELOPMENT || DEBUG
#if defined(__x86_64__)
	(void)interrupted_kernel_sp_value(&fixup_val);
#elif defined(__arm64__) || defined(__arm__)
	(void)interrupted_kernel_lr(&fixup_val);
#endif /* defined(__x86_64__) */
#endif /* DEVELOPMENT || DEBUG */

	assert(cs->kpkc_flags & CALLSTACK_KERNEL);
	cs->kpkc_frames[cs->kpkc_nframes++] = fixup_val;
}

void
kperf_continuation_sample(struct kp_kcallstack *cs, struct kperf_context *context)
{
	thread_t thread;

	assert(cs != NULL);
	assert(context != NULL);

	thread = context->cur_thread;
	assert(thread != NULL);
	assert(thread->continuation != NULL);

	cs->kpkc_flags = CALLSTACK_CONTINUATION | CALLSTACK_VALID | CALLSTACK_KERNEL;
#ifdef __LP64__
	cs->kpkc_flags |= CALLSTACK_64BIT;
#endif

	cs->kpkc_nframes = 1;
	cs->kpkc_frames[0] = VM_KERNEL_UNSLIDE(thread->continuation);
}

void
kperf_backtrace_sample(struct kp_kcallstack *cs, struct kperf_context *context)
{
	assert(cs != NULL);
	assert(context != NULL);
	assert(context->cur_thread == current_thread());

	cs->kpkc_flags = CALLSTACK_KERNEL | CALLSTACK_KERNEL_WORDS;
#ifdef __LP64__
	cs->kpkc_flags |= CALLSTACK_64BIT;
#endif

	BUF_VERB(PERF_CS_BACKTRACE | DBG_FUNC_START, 1);

	bool trunc = false;
	cs->kpkc_nframes = backtrace_frame(cs->kpkc_word_frames,
	    cs->kpkc_nframes - 1, context->starting_fp, &trunc);
	if (cs->kpkc_nframes > 0) {
		cs->kpkc_flags |= CALLSTACK_VALID;
		/*
		 * Fake the value pointed to by the stack pointer or the link
		 * register for symbolicators.
		 */
		cs->kpkc_word_frames[cs->kpkc_nframes + 1] = 0;
		cs->kpkc_nframes += 1;
	}
	if (trunc) {
		cs->kpkc_flags |= CALLSTACK_TRUNCATED;
	}

	BUF_VERB(PERF_CS_BACKTRACE | DBG_FUNC_END, cs->kpkc_nframes);
}

kern_return_t chudxnu_thread_get_callstack64_kperf(thread_t thread,
    uint64_t *callStack, mach_msg_type_number_t *count,
    boolean_t user_only);

void
kperf_kcallstack_sample(struct kp_kcallstack *cs, struct kperf_context *context)
{
	thread_t thread;

	assert(cs != NULL);
	assert(context != NULL);
	assert(cs->kpkc_nframes <= MAX_KCALLSTACK_FRAMES);

	thread = context->cur_thread;
	assert(thread != NULL);

	BUF_INFO(PERF_CS_KSAMPLE | DBG_FUNC_START, (uintptr_t)thread_tid(thread),
	    cs->kpkc_nframes);

	cs->kpkc_flags = CALLSTACK_KERNEL;
#ifdef __LP64__
	cs->kpkc_flags |= CALLSTACK_64BIT;
#endif

	if (ml_at_interrupt_context()) {
		assert(thread == current_thread());
		cs->kpkc_flags |= CALLSTACK_KERNEL_WORDS;
		bool trunc = false;
		cs->kpkc_nframes = backtrace_interrupted(
		    cs->kpkc_word_frames, cs->kpkc_nframes - 1, &trunc);
		if (cs->kpkc_nframes != 0) {
			callstack_fixup_interrupted(cs);
		}
		if (trunc) {
			cs->kpkc_flags |= CALLSTACK_TRUNCATED;
		}
	} else {
		/*
		 * Rely on legacy CHUD backtracer to backtrace kernel stacks on
		 * other threads.
		 */
		kern_return_t kr;
		kr = chudxnu_thread_get_callstack64_kperf(thread,
		    cs->kpkc_frames, &cs->kpkc_nframes, FALSE);
		if (kr == KERN_SUCCESS) {
			cs->kpkc_flags |= CALLSTACK_VALID;
		} else if (kr == KERN_RESOURCE_SHORTAGE) {
			cs->kpkc_flags |= CALLSTACK_VALID;
			cs->kpkc_flags |= CALLSTACK_TRUNCATED;
		} else {
			cs->kpkc_nframes = 0;
		}
	}

	if (!(cs->kpkc_flags & CALLSTACK_VALID)) {
		BUF_INFO(PERF_CS_ERROR, ERR_GETSTACK);
	}

	BUF_INFO(PERF_CS_KSAMPLE | DBG_FUNC_END, (uintptr_t)thread_tid(thread),
	    cs->kpkc_flags, cs->kpkc_nframes);
}

void
kperf_ucallstack_sample(struct kp_ucallstack *cs, struct kperf_context *context)
{
	assert(ml_get_interrupts_enabled() == TRUE);

	thread_t thread = context->cur_thread;
	assert(thread != NULL);

	BUF_INFO(PERF_CS_USAMPLE | DBG_FUNC_START,
	    (uintptr_t)thread_tid(thread), cs->kpuc_nframes);

	bool user64 = false;
	bool trunc = false;
	int err = backtrace_thread_user(thread, cs->kpuc_frames,
	    cs->kpuc_nframes - 1, &cs->kpuc_nframes, &user64, &trunc);
	cs->kpuc_flags = CALLSTACK_KERNEL_WORDS;
	if (user64) {
		cs->kpuc_flags |= CALLSTACK_64BIT;
	}
	if (trunc) {
		cs->kpuc_flags |= CALLSTACK_TRUNCATED;
	}

	if (!err || err == EFAULT) {
		callstack_fixup_user(cs, thread);
		cs->kpuc_flags |= CALLSTACK_VALID;
	} else {
		cs->kpuc_nframes = 0;
		BUF_INFO(PERF_CS_ERROR, ERR_GETSTACK, err);
	}

	BUF_INFO(PERF_CS_USAMPLE | DBG_FUNC_END, (uintptr_t)thread_tid(thread),
	    cs->kpuc_flags, cs->kpuc_nframes);
}

static inline uintptr_t
scrub_word(uintptr_t *bt, int n_frames, int frame, bool kern)
{
	if (frame < n_frames) {
		if (kern) {
			return VM_KERNEL_UNSLIDE(bt[frame]);
		} else {
			return bt[frame];
		}
	} else {
		return 0;
	}
}

static inline uintptr_t
scrub_frame(uint64_t *bt, int n_frames, int frame)
{
	if (frame < n_frames) {
		return (uintptr_t)(bt[frame]);
	} else {
		return 0;
	}
}

static void
callstack_log(uint32_t hdrid, uint32_t dataid, void *vframes,
    unsigned int nframes, unsigned int flags)
{
	BUF_VERB(PERF_CS_LOG | DBG_FUNC_START, flags, nframes);

	BUF_DATA(hdrid, flags, nframes);

	unsigned int nevts = nframes / 4;
	unsigned int ovf = nframes % 4;
	if (ovf != 0) {
		nevts++;
	}

	bool kern = flags & CALLSTACK_KERNEL;

	if (flags & CALLSTACK_KERNEL_WORDS) {
		uintptr_t *frames = vframes;
		for (unsigned int i = 0; i < nevts; i++) {
			unsigned int j = i * 4;
			BUF_DATA(dataid,
			    scrub_word(frames, nframes, j + 0, kern),
			    scrub_word(frames, nframes, j + 1, kern),
			    scrub_word(frames, nframes, j + 2, kern),
			    scrub_word(frames, nframes, j + 3, kern));
		}
	} else {
		for (unsigned int i = 0; i < nevts; i++) {
			uint64_t *frames = vframes;
			unsigned int j = i * 4;
			BUF_DATA(dataid,
			    scrub_frame(frames, nframes, j + 0),
			    scrub_frame(frames, nframes, j + 1),
			    scrub_frame(frames, nframes, j + 2),
			    scrub_frame(frames, nframes, j + 3));
		}
	}

	BUF_VERB(PERF_CS_LOG | DBG_FUNC_END, flags, nframes);
}

void
kperf_kcallstack_log(struct kp_kcallstack *cs)
{
	callstack_log(PERF_CS_KHDR, PERF_CS_KDATA, cs->kpkc_frames,
	    cs->kpkc_nframes, cs->kpkc_flags);
}

void
kperf_ucallstack_log(struct kp_ucallstack *cs)
{
	callstack_log(PERF_CS_UHDR, PERF_CS_UDATA, cs->kpuc_frames,
	    cs->kpuc_nframes, cs->kpuc_flags);
}

int
kperf_ucallstack_pend(struct kperf_context * context, uint32_t depth,
    unsigned int actionid)
{
	if (depth < 2) {
		panic("HUH");
	}
	kperf_ast_set_callstack_depth(context->cur_thread, depth);
	return kperf_ast_pend(context->cur_thread, T_KPERF_AST_CALLSTACK,
	    actionid);
}

static kern_return_t
chudxnu_kern_read(void *dstaddr, vm_offset_t srcaddr, vm_size_t size)
{
	return (ml_nofault_copy(srcaddr, (vm_offset_t)dstaddr, size) == size) ?
	       KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t
chudxnu_task_read(
	task_t      task,
	void        *kernaddr,
	uint64_t    usraddr,
	vm_size_t   size)
{
	//ppc version ported to arm
	kern_return_t ret = KERN_SUCCESS;

	if (ml_at_interrupt_context()) {
		return KERN_FAILURE;    // can't look at tasks on interrupt stack
	}

	if (current_task() == task) {
		if (copyin(usraddr, kernaddr, size)) {
			ret = KERN_FAILURE;
		}
	} else {
		vm_map_t map = get_task_map(task);
		ret = vm_map_read_user(map, usraddr, kernaddr, size);
	}

	return ret;
}

static inline uint64_t
chudxnu_vm_unslide( uint64_t ptr, int kaddr )
{
	if (!kaddr) {
		return ptr;
	}

	return VM_KERNEL_UNSLIDE(ptr);
}

#if __arm__
#define ARM_SUPERVISOR_MODE(cpsr) ((((cpsr) & PSR_MODE_MASK) != PSR_USER_MODE) ? TRUE : FALSE)
#define CS_FLAG_EXTRASP  1  // capture extra sp register
static kern_return_t
chudxnu_thread_get_callstack64_internal(
	thread_t                thread,
	uint64_t                *callStack,
	mach_msg_type_number_t  *count,
	boolean_t               user_only,
	int flags)
{
	kern_return_t kr;
	task_t                  task;
	uint64_t                currPC = 0ULL, currLR = 0ULL, currSP = 0ULL;
	uint64_t                prevPC = 0ULL;
	uint32_t                kernStackMin = thread->kernel_stack;
	uint32_t                kernStackMax = kernStackMin + kernel_stack_size;
	uint64_t       *buffer = callStack;
	uint32_t                frame[2];
	int             bufferIndex = 0;
	int             bufferMaxIndex = 0;
	boolean_t       supervisor = FALSE;
	struct arm_saved_state *state = NULL;
	uint32_t                *fp = NULL, *nextFramePointer = NULL, *topfp = NULL;
	uint64_t                pc = 0ULL;

	task = get_threadtask(thread);

	bufferMaxIndex = *count;
	//get thread state
	if (user_only) {
		state = find_user_regs(thread);
	} else {
		state = find_kern_regs(thread);
	}

	if (!state) {
		*count = 0;
		return KERN_FAILURE;
	}

	/* make sure it is safe to dereference before you do it */
	supervisor = ARM_SUPERVISOR_MODE(state->cpsr);

	/* can't take a kernel callstack if we've got a user frame */
	if (!user_only && !supervisor) {
		return KERN_FAILURE;
	}

	/*
	 * Reserve space for saving LR (and sometimes SP) at the end of the
	 * backtrace.
	 */
	if (flags & CS_FLAG_EXTRASP) {
		bufferMaxIndex -= 2;
	} else {
		bufferMaxIndex -= 1;
	}

	if (bufferMaxIndex < 2) {
		*count = 0;
		return KERN_RESOURCE_SHORTAGE;
	}

	currPC = (uint64_t)state->pc; /* r15 */
	if (state->cpsr & PSR_TF) {
		currPC |= 1ULL; /* encode thumb mode into low bit of PC */
	}
	currLR = (uint64_t)state->lr; /* r14 */
	currSP = (uint64_t)state->sp; /* r13 */

	fp = (uint32_t *)state->r[7]; /* frame pointer */
	topfp = fp;

	bufferIndex = 0;  // start with a stack of size zero
	buffer[bufferIndex++] = chudxnu_vm_unslide(currPC, supervisor); // save PC in position 0.

	// Now, fill buffer with stack backtraces.
	while (bufferIndex < bufferMaxIndex) {
		pc = 0ULL;
		/*
		 * Below the frame pointer, the following values are saved:
		 * -> FP
		 */

		/*
		 * Note that we read the pc even for the first stack frame
		 * (which, in theory, is always empty because the callee fills
		 * it in just before it lowers the stack.  However, if we
		 * catch the program in between filling in the return address
		 * and lowering the stack, we want to still have a valid
		 * backtrace. FixupStack correctly disregards this value if
		 * necessary.
		 */

		if ((uint32_t)fp == 0 || ((uint32_t)fp & 0x3) != 0) {
			/* frame pointer is invalid - stop backtracing */
			pc = 0ULL;
			break;
		}

		if (supervisor) {
			if (((uint32_t)fp > kernStackMax) ||
			    ((uint32_t)fp < kernStackMin)) {
				kr = KERN_FAILURE;
			} else {
				kr = chudxnu_kern_read(&frame,
				    (vm_offset_t)fp,
				    (vm_size_t)sizeof(frame));
				if (kr == KERN_SUCCESS) {
					pc = (uint64_t)frame[1];
					nextFramePointer = (uint32_t *) (frame[0]);
				} else {
					pc = 0ULL;
					nextFramePointer = 0ULL;
					kr = KERN_FAILURE;
				}
			}
		} else {
			kr = chudxnu_task_read(task,
			    &frame,
			    (((uint64_t)(uint32_t)fp) & 0x00000000FFFFFFFFULL),
			    sizeof(frame));
			if (kr == KERN_SUCCESS) {
				pc = (uint64_t) frame[1];
				nextFramePointer = (uint32_t *) (frame[0]);
			} else {
				pc = 0ULL;
				nextFramePointer = 0ULL;
				kr = KERN_FAILURE;
			}
		}

		if (kr != KERN_SUCCESS) {
			pc = 0ULL;
			break;
		}

		if (nextFramePointer) {
			buffer[bufferIndex++] = chudxnu_vm_unslide(pc, supervisor);
			prevPC = pc;
		}

		if (nextFramePointer < fp) {
			break;
		} else {
			fp = nextFramePointer;
		}
	}

	if (bufferIndex >= bufferMaxIndex) {
		bufferIndex = bufferMaxIndex;
		kr = KERN_RESOURCE_SHORTAGE;
	} else {
		kr = KERN_SUCCESS;
	}

	// Save link register and R13 (sp) at bottom of stack (used for later fixup).
	buffer[bufferIndex++] = chudxnu_vm_unslide(currLR, supervisor);
	if (flags & CS_FLAG_EXTRASP) {
		buffer[bufferIndex++] = chudxnu_vm_unslide(currSP, supervisor);
	}

	*count = bufferIndex;
	return kr;
}

kern_return_t
chudxnu_thread_get_callstack64_kperf(
	thread_t                thread,
	uint64_t                *callStack,
	mach_msg_type_number_t  *count,
	boolean_t               user_only)
{
	return chudxnu_thread_get_callstack64_internal( thread, callStack, count, user_only, 0 );
}
#elif __arm64__

#if defined(HAS_APPLE_PAC)
#include <ptrauth.h>
#endif

// chudxnu_thread_get_callstack gathers a raw callstack along with any information needed to
// fix it up later (in case we stopped program as it was saving values into prev stack frame, etc.)
// after sampling has finished.
//
// For an N-entry callstack:
//
// [0]      current pc
// [1..N-3] stack frames (including current one)
// [N-2]    current LR (return value if we're in a leaf function)
// [N-1]    current r0 (in case we've saved LR in r0) (optional)
//
//
#define ARM_SUPERVISOR_MODE(cpsr) ((((cpsr) & PSR_MODE_MASK) != PSR_USER_MODE) ? TRUE : FALSE)

#define CS_FLAG_EXTRASP  1  // capture extra sp register

static kern_return_t
chudxnu_thread_get_callstack64_internal(
	thread_t                thread,
	uint64_t                *callStack,
	mach_msg_type_number_t  *count,
	boolean_t               user_only,
	int flags)
{
	kern_return_t   kr = KERN_SUCCESS;
	task_t                  task;
	uint64_t                currPC = 0ULL, currLR = 0ULL, currSP = 0ULL;
	uint64_t                prevPC = 0ULL;
	uint64_t                kernStackMin = thread->kernel_stack;
	uint64_t                kernStackMax = kernStackMin + kernel_stack_size;
	uint64_t       *buffer = callStack;
	int             bufferIndex = 0;
	int             bufferMaxIndex = 0;
	boolean_t       kernel = FALSE;
	struct arm_saved_state *sstate = NULL;
	uint64_t                pc = 0ULL;

	task = get_threadtask(thread);
	bufferMaxIndex = *count;
	//get thread state
	if (user_only) {
		sstate = find_user_regs(thread);
	} else {
		sstate = find_kern_regs(thread);
	}

	if (!sstate) {
		*count = 0;
		return KERN_FAILURE;
	}

	if (is_saved_state64(sstate)) {
		struct arm_saved_state64 *state = NULL;
		uint64_t *fp = NULL, *nextFramePointer = NULL, *topfp = NULL;
		uint64_t frame[2];

		state = saved_state64(sstate);

		/* make sure it is safe to dereference before you do it */
		kernel = PSR64_IS_KERNEL(state->cpsr);

		/* can't take a kernel callstack if we've got a user frame */
		if (!user_only && !kernel) {
			return KERN_FAILURE;
		}

		/*
		 * Reserve space for saving LR (and sometimes SP) at the end of the
		 * backtrace.
		 */
		if (flags & CS_FLAG_EXTRASP) {
			bufferMaxIndex -= 2;
		} else {
			bufferMaxIndex -= 1;
		}

		if (bufferMaxIndex < 2) {
			*count = 0;
			return KERN_RESOURCE_SHORTAGE;
		}

		currPC = state->pc;
		currLR = state->lr;
		currSP = state->sp;

		fp = (uint64_t *)state->fp; /* frame pointer */
		topfp = fp;

		bufferIndex = 0;  // start with a stack of size zero
		buffer[bufferIndex++] = chudxnu_vm_unslide(currPC, kernel); // save PC in position 0.

		BUF_VERB(PERF_CS_BACKTRACE | DBG_FUNC_START, kernel, 0);

		// Now, fill buffer with stack backtraces.
		while (bufferIndex < bufferMaxIndex) {
			pc = 0ULL;
			/*
			 * Below the frame pointer, the following values are saved:
			 * -> FP
			 */

			/*
			 * Note that we read the pc even for the first stack frame
			 * (which, in theory, is always empty because the callee fills
			 * it in just before it lowers the stack.  However, if we
			 * catch the program in between filling in the return address
			 * and lowering the stack, we want to still have a valid
			 * backtrace. FixupStack correctly disregards this value if
			 * necessary.
			 */

			if ((uint64_t)fp == 0 || ((uint64_t)fp & 0x3) != 0) {
				/* frame pointer is invalid - stop backtracing */
				pc = 0ULL;
				break;
			}

			if (kernel) {
				if (((uint64_t)fp > kernStackMax) ||
				    ((uint64_t)fp < kernStackMin)) {
					kr = KERN_FAILURE;
				} else {
					kr = chudxnu_kern_read(&frame,
					    (vm_offset_t)fp,
					    (vm_size_t)sizeof(frame));
					if (kr == KERN_SUCCESS) {
#if defined(HAS_APPLE_PAC)
						/* return addresses on stack will be signed by arm64e ABI */
						pc = (uint64_t)ptrauth_strip((void *)frame[1], ptrauth_key_return_address);
#else
						pc = frame[1];
#endif
						nextFramePointer = (uint64_t *)frame[0];
					} else {
						pc = 0ULL;
						nextFramePointer = 0ULL;
						kr = KERN_FAILURE;
					}
				}
			} else {
				kr = chudxnu_task_read(task,
				    &frame,
				    (vm_offset_t)fp,
				    (vm_size_t)sizeof(frame));
				if (kr == KERN_SUCCESS) {
#if defined(HAS_APPLE_PAC)
					/* return addresses on stack will be signed by arm64e ABI */
					pc = (uint64_t)ptrauth_strip((void *)frame[1], ptrauth_key_return_address);
#else
					pc = frame[1];
#endif
					nextFramePointer = (uint64_t *)(frame[0]);
				} else {
					pc = 0ULL;
					nextFramePointer = 0ULL;
					kr = KERN_FAILURE;
				}
			}

			if (kr != KERN_SUCCESS) {
				pc = 0ULL;
				break;
			}

			if (nextFramePointer) {
				buffer[bufferIndex++] = chudxnu_vm_unslide(pc, kernel);
				prevPC = pc;
			}

			if (nextFramePointer < fp) {
				break;
			} else {
				fp = nextFramePointer;
			}
		}

		BUF_VERB(PERF_CS_BACKTRACE | DBG_FUNC_END, bufferIndex);

		if (bufferIndex >= bufferMaxIndex) {
			bufferIndex = bufferMaxIndex;
			kr = KERN_RESOURCE_SHORTAGE;
		} else {
			kr = KERN_SUCCESS;
		}

		// Save link register and SP at bottom of stack (used for later fixup).
		buffer[bufferIndex++] = chudxnu_vm_unslide(currLR, kernel);
		if (flags & CS_FLAG_EXTRASP) {
			buffer[bufferIndex++] = chudxnu_vm_unslide(currSP, kernel);
		}
	} else {
		struct arm_saved_state32 *state = NULL;
		uint32_t *fp = NULL, *nextFramePointer = NULL, *topfp = NULL;

		/* 64-bit kernel stacks, 32-bit user stacks */
		uint64_t frame[2];
		uint32_t frame32[2];

		state = saved_state32(sstate);

		/* make sure it is safe to dereference before you do it */
		kernel = ARM_SUPERVISOR_MODE(state->cpsr);

		/* can't take a kernel callstack if we've got a user frame */
		if (!user_only && !kernel) {
			return KERN_FAILURE;
		}

		/*
		 * Reserve space for saving LR (and sometimes SP) at the end of the
		 * backtrace.
		 */
		if (flags & CS_FLAG_EXTRASP) {
			bufferMaxIndex -= 2;
		} else {
			bufferMaxIndex -= 1;
		}

		if (bufferMaxIndex < 2) {
			*count = 0;
			return KERN_RESOURCE_SHORTAGE;
		}

		currPC = (uint64_t)state->pc; /* r15 */
		if (state->cpsr & PSR_TF) {
			currPC |= 1ULL; /* encode thumb mode into low bit of PC */
		}
		currLR = (uint64_t)state->lr; /* r14 */
		currSP = (uint64_t)state->sp; /* r13 */

		fp = (uint32_t *)(uintptr_t)state->r[7]; /* frame pointer */
		topfp = fp;

		bufferIndex = 0;  // start with a stack of size zero
		buffer[bufferIndex++] = chudxnu_vm_unslide(currPC, kernel); // save PC in position 0.

		BUF_VERB(PERF_CS_BACKTRACE | DBG_FUNC_START, kernel, 1);

		// Now, fill buffer with stack backtraces.
		while (bufferIndex < bufferMaxIndex) {
			pc = 0ULL;
			/*
			 * Below the frame pointer, the following values are saved:
			 * -> FP
			 */

			/*
			 * Note that we read the pc even for the first stack frame
			 * (which, in theory, is always empty because the callee fills
			 * it in just before it lowers the stack.  However, if we
			 * catch the program in between filling in the return address
			 * and lowering the stack, we want to still have a valid
			 * backtrace. FixupStack correctly disregards this value if
			 * necessary.
			 */

			if ((uint32_t)fp == 0 || ((uint32_t)fp & 0x3) != 0) {
				/* frame pointer is invalid - stop backtracing */
				pc = 0ULL;
				break;
			}

			if (kernel) {
				if (((uint32_t)fp > kernStackMax) ||
				    ((uint32_t)fp < kernStackMin)) {
					kr = KERN_FAILURE;
				} else {
					kr = chudxnu_kern_read(&frame,
					    (vm_offset_t)fp,
					    (vm_size_t)sizeof(frame));
					if (kr == KERN_SUCCESS) {
						pc = (uint64_t)frame[1];
						nextFramePointer = (uint32_t *) (frame[0]);
					} else {
						pc = 0ULL;
						nextFramePointer = 0ULL;
						kr = KERN_FAILURE;
					}
				}
			} else {
				kr = chudxnu_task_read(task,
				    &frame32,
				    (((uint64_t)(uint32_t)fp) & 0x00000000FFFFFFFFULL),
				    sizeof(frame32));
				if (kr == KERN_SUCCESS) {
					pc = (uint64_t)frame32[1];
					nextFramePointer = (uint32_t *)(uintptr_t)(frame32[0]);
				} else {
					pc = 0ULL;
					nextFramePointer = 0ULL;
					kr = KERN_FAILURE;
				}
			}

			if (kr != KERN_SUCCESS) {
				pc = 0ULL;
				break;
			}

			if (nextFramePointer) {
				buffer[bufferIndex++] = chudxnu_vm_unslide(pc, kernel);
				prevPC = pc;
			}

			if (nextFramePointer < fp) {
				break;
			} else {
				fp = nextFramePointer;
			}
		}

		BUF_VERB(PERF_CS_BACKTRACE | DBG_FUNC_END, bufferIndex);

		/* clamp callstack size to max */
		if (bufferIndex >= bufferMaxIndex) {
			bufferIndex = bufferMaxIndex;
			kr = KERN_RESOURCE_SHORTAGE;
		} else {
			/* ignore all other failures */
			kr = KERN_SUCCESS;
		}

		// Save link register and R13 (sp) at bottom of stack (used for later fixup).
		buffer[bufferIndex++] = chudxnu_vm_unslide(currLR, kernel);
		if (flags & CS_FLAG_EXTRASP) {
			buffer[bufferIndex++] = chudxnu_vm_unslide(currSP, kernel);
		}
	}

	*count = bufferIndex;
	return kr;
}

kern_return_t
chudxnu_thread_get_callstack64_kperf(
	thread_t                thread,
	uint64_t                *callStack,
	mach_msg_type_number_t  *count,
	boolean_t               user_only)
{
	return chudxnu_thread_get_callstack64_internal( thread, callStack, count, user_only, 0 );
}
#elif __x86_64__

#define VALID_STACK_ADDRESS(supervisor, addr, minKernAddr, maxKernAddr)   (supervisor ? (addr>=minKernAddr && addr<=maxKernAddr) : TRUE)
// don't try to read in the hole
#define VALID_STACK_ADDRESS64(supervisor, addr, minKernAddr, maxKernAddr) \
(supervisor ? ((uint64_t)addr >= minKernAddr && (uint64_t)addr <= maxKernAddr) : \
((uint64_t)addr != 0ULL && ((uint64_t)addr <= 0x00007FFFFFFFFFFFULL || (uint64_t)addr >= 0xFFFF800000000000ULL)))

typedef struct _cframe64_t {
	uint64_t        prevFP;         // can't use a real pointer here until we're a 64 bit kernel
	uint64_t        caller;
	uint64_t        args[0];
}cframe64_t;


typedef struct _cframe_t {
	uint32_t                prev;   // this is really a user32-space pointer to the previous frame
	uint32_t                caller;
	uint32_t                args[0];
} cframe_t;

extern void * find_user_regs(thread_t);
extern x86_saved_state32_t *find_kern_regs(thread_t);

static kern_return_t
do_kernel_backtrace(
	thread_t thread,
	struct x86_kernel_state *regs,
	uint64_t *frames,
	mach_msg_type_number_t *start_idx,
	mach_msg_type_number_t max_idx)
{
	uint64_t kernStackMin = (uint64_t)thread->kernel_stack;
	uint64_t kernStackMax = (uint64_t)kernStackMin + kernel_stack_size;
	mach_msg_type_number_t ct = *start_idx;
	kern_return_t kr = KERN_FAILURE;

#if __LP64__
	uint64_t currPC = 0ULL;
	uint64_t currFP = 0ULL;
	uint64_t prevPC = 0ULL;
	uint64_t prevFP = 0ULL;
	if (KERN_SUCCESS != chudxnu_kern_read(&currPC, (vm_offset_t)&(regs->k_rip), sizeof(uint64_t))) {
		return KERN_FAILURE;
	}
	if (KERN_SUCCESS != chudxnu_kern_read(&currFP, (vm_offset_t)&(regs->k_rbp), sizeof(uint64_t))) {
		return KERN_FAILURE;
	}
#else
	uint32_t currPC = 0U;
	uint32_t currFP = 0U;
	uint32_t prevPC = 0U;
	uint32_t prevFP = 0U;
	if (KERN_SUCCESS != chudxnu_kern_read(&currPC, (vm_offset_t)&(regs->k_eip), sizeof(uint32_t))) {
		return KERN_FAILURE;
	}
	if (KERN_SUCCESS != chudxnu_kern_read(&currFP, (vm_offset_t)&(regs->k_ebp), sizeof(uint32_t))) {
		return KERN_FAILURE;
	}
#endif

	if (*start_idx >= max_idx) {
		return KERN_RESOURCE_SHORTAGE;  // no frames traced
	}
	if (!currPC) {
		return KERN_FAILURE;
	}

	frames[ct++] = chudxnu_vm_unslide((uint64_t)currPC, 1);

	// build a backtrace of this kernel state
#if __LP64__
	while (VALID_STACK_ADDRESS64(TRUE, currFP, kernStackMin, kernStackMax)) {
		// this is the address where caller lives in the user thread
		uint64_t caller = currFP + sizeof(uint64_t);
#else
	while (VALID_STACK_ADDRESS(TRUE, currFP, kernStackMin, kernStackMax)) {
		uint32_t caller = (uint32_t)currFP + sizeof(uint32_t);
#endif

		if (!currFP || !currPC) {
			currPC = 0;
			break;
		}

		if (ct >= max_idx) {
			*start_idx = ct;
			return KERN_RESOURCE_SHORTAGE;
		}

		/* read our caller */
		kr = chudxnu_kern_read(&currPC, (vm_offset_t)caller, sizeof(currPC));

		if (kr != KERN_SUCCESS || !currPC) {
			currPC = 0UL;
			break;
		}

		/*
		 * retrive contents of the frame pointer and advance to the next stack
		 * frame if it's valid
		 */
		prevFP = 0;
		kr = chudxnu_kern_read(&prevFP, (vm_offset_t)currFP, sizeof(currPC));

#if __LP64__
		if (VALID_STACK_ADDRESS64(TRUE, prevFP, kernStackMin, kernStackMax)) {
#else
		if (VALID_STACK_ADDRESS(TRUE, prevFP, kernStackMin, kernStackMax)) {
#endif
			frames[ct++] = chudxnu_vm_unslide((uint64_t)currPC, 1);
			prevPC = currPC;
		}
		if (prevFP <= currFP) {
			break;
		} else {
			currFP = prevFP;
		}
	}

	*start_idx = ct;
	return KERN_SUCCESS;
}



static kern_return_t
do_backtrace32(
	task_t task,
	thread_t thread,
	x86_saved_state32_t *regs,
	uint64_t *frames,
	mach_msg_type_number_t *start_idx,
	mach_msg_type_number_t max_idx,
	boolean_t supervisor)
{
	uint32_t tmpWord = 0UL;
	uint64_t currPC = (uint64_t) regs->eip;
	uint64_t currFP = (uint64_t) regs->ebp;
	uint64_t prevPC = 0ULL;
	uint64_t prevFP = 0ULL;
	uint64_t kernStackMin = thread->kernel_stack;
	uint64_t kernStackMax = kernStackMin + kernel_stack_size;
	mach_msg_type_number_t ct = *start_idx;
	kern_return_t kr = KERN_FAILURE;

	if (ct >= max_idx) {
		return KERN_RESOURCE_SHORTAGE;  // no frames traced
	}
	frames[ct++] = chudxnu_vm_unslide(currPC, supervisor);

	// build a backtrace of this 32 bit state.
	while (VALID_STACK_ADDRESS(supervisor, currFP, kernStackMin, kernStackMax)) {
		cframe_t *fp = (cframe_t *) (uintptr_t) currFP;

		if (!currFP) {
			currPC = 0;
			break;
		}

		if (ct >= max_idx) {
			*start_idx = ct;
			return KERN_RESOURCE_SHORTAGE;
		}

		/* read our caller */
		if (supervisor) {
			kr = chudxnu_kern_read(&tmpWord, (vm_offset_t) &fp->caller, sizeof(uint32_t));
		} else {
			kr = chudxnu_task_read(task, &tmpWord, (vm_offset_t) &fp->caller, sizeof(uint32_t));
		}

		if (kr != KERN_SUCCESS) {
			currPC = 0ULL;
			break;
		}

		currPC = (uint64_t) tmpWord;    // promote 32 bit address

		/*
		 * retrive contents of the frame pointer and advance to the next stack
		 * frame if it's valid
		 */
		prevFP = 0;
		if (supervisor) {
			kr = chudxnu_kern_read(&tmpWord, (vm_offset_t)&fp->prev, sizeof(uint32_t));
		} else {
			kr = chudxnu_task_read(task, &tmpWord, (vm_offset_t)&fp->prev, sizeof(uint32_t));
		}
		prevFP = (uint64_t) tmpWord;    // promote 32 bit address

		if (prevFP) {
			frames[ct++] = chudxnu_vm_unslide(currPC, supervisor);
			prevPC = currPC;
		}
		if (prevFP < currFP) {
			break;
		} else {
			currFP = prevFP;
		}
	}

	*start_idx = ct;
	return KERN_SUCCESS;
}

static kern_return_t
do_backtrace64(
	task_t task,
	thread_t thread,
	x86_saved_state64_t *regs,
	uint64_t *frames,
	mach_msg_type_number_t *start_idx,
	mach_msg_type_number_t max_idx,
	boolean_t supervisor)
{
	uint64_t currPC = regs->isf.rip;
	uint64_t currFP = regs->rbp;
	uint64_t prevPC = 0ULL;
	uint64_t prevFP = 0ULL;
	uint64_t kernStackMin = (uint64_t)thread->kernel_stack;
	uint64_t kernStackMax = (uint64_t)kernStackMin + kernel_stack_size;
	mach_msg_type_number_t ct = *start_idx;
	kern_return_t kr = KERN_FAILURE;

	if (*start_idx >= max_idx) {
		return KERN_RESOURCE_SHORTAGE;  // no frames traced
	}
	frames[ct++] = chudxnu_vm_unslide(currPC, supervisor);

	// build a backtrace of this 32 bit state.
	while (VALID_STACK_ADDRESS64(supervisor, currFP, kernStackMin, kernStackMax)) {
		// this is the address where caller lives in the user thread
		uint64_t caller = currFP + sizeof(uint64_t);

		if (!currFP) {
			currPC = 0;
			break;
		}

		if (ct >= max_idx) {
			*start_idx = ct;
			return KERN_RESOURCE_SHORTAGE;
		}

		/* read our caller */
		if (supervisor) {
			kr = chudxnu_kern_read(&currPC, (vm_offset_t)caller, sizeof(uint64_t));
		} else {
			kr = chudxnu_task_read(task, &currPC, caller, sizeof(uint64_t));
		}

		if (kr != KERN_SUCCESS) {
			currPC = 0ULL;
			break;
		}

		/*
		 * retrive contents of the frame pointer and advance to the next stack
		 * frame if it's valid
		 */
		prevFP = 0;
		if (supervisor) {
			kr = chudxnu_kern_read(&prevFP, (vm_offset_t)currFP, sizeof(uint64_t));
		} else {
			kr = chudxnu_task_read(task, &prevFP, currFP, sizeof(uint64_t));
		}

		if (VALID_STACK_ADDRESS64(supervisor, prevFP, kernStackMin, kernStackMax)) {
			frames[ct++] = chudxnu_vm_unslide(currPC, supervisor);
			prevPC = currPC;
		}
		if (prevFP < currFP) {
			break;
		} else {
			currFP = prevFP;
		}
	}

	*start_idx = ct;
	return KERN_SUCCESS;
}

static kern_return_t
chudxnu_thread_get_callstack64_internal(
	thread_t                thread,
	uint64_t                *callstack,
	mach_msg_type_number_t  *count,
	boolean_t               user_only,
	boolean_t               kern_only)
{
	kern_return_t kr = KERN_FAILURE;
	task_t task = thread->task;
	uint64_t currPC = 0ULL;
	boolean_t supervisor = FALSE;
	mach_msg_type_number_t bufferIndex = 0;
	mach_msg_type_number_t bufferMaxIndex = *count;
	x86_saved_state_t *tagged_regs = NULL;          // kernel register state
	x86_saved_state64_t *regs64 = NULL;
	x86_saved_state32_t *regs32 = NULL;
	x86_saved_state32_t *u_regs32 = NULL;
	x86_saved_state64_t *u_regs64 = NULL;
	struct x86_kernel_state *kregs = NULL;

	if (ml_at_interrupt_context()) {
		if (user_only) {
			/* can't backtrace user state on interrupt stack. */
			return KERN_FAILURE;
		}

		/* backtracing at interrupt context? */
		if (thread == current_thread() && current_cpu_datap()->cpu_int_state) {
			/*
			 * Locate the registers for the interrupted thread, assuming it is
			 * current_thread().
			 */
			tagged_regs = current_cpu_datap()->cpu_int_state;

			if (is_saved_state64(tagged_regs)) {
				/* 64 bit registers */
				regs64 = saved_state64(tagged_regs);
				supervisor = ((regs64->isf.cs & SEL_PL) != SEL_PL_U);
			} else {
				/* 32 bit registers */
				regs32 = saved_state32(tagged_regs);
				supervisor = ((regs32->cs & SEL_PL) != SEL_PL_U);
			}
		}
	}

	if (!ml_at_interrupt_context() && kernel_task == task) {
		if (!thread->kernel_stack) {
			return KERN_FAILURE;
		}

		// Kernel thread not at interrupt context
		kregs = (struct x86_kernel_state *)NULL;

		// nofault read of the thread->kernel_stack pointer
		if (KERN_SUCCESS != chudxnu_kern_read(&kregs, (vm_offset_t)&(thread->kernel_stack), sizeof(void *))) {
			return KERN_FAILURE;
		}

		// Adjust to find the saved kernel state
		kregs = STACK_IKS((vm_offset_t)(uintptr_t)kregs);

		supervisor = TRUE;
	} else if (!tagged_regs) {
		/*
		 * not at interrupt context, or tracing a different thread than
		 * current_thread() at interrupt context
		 */
		tagged_regs = USER_STATE(thread);
		if (is_saved_state64(tagged_regs)) {
			/* 64 bit registers */
			regs64 = saved_state64(tagged_regs);
			supervisor = ((regs64->isf.cs & SEL_PL) != SEL_PL_U);
		} else {
			/* 32 bit registers */
			regs32 = saved_state32(tagged_regs);
			supervisor = ((regs32->cs & SEL_PL) != SEL_PL_U);
		}
	}

	*count = 0;

	if (supervisor) {
		// the caller only wants a user callstack.
		if (user_only) {
			// bail - we've only got kernel state
			return KERN_FAILURE;
		}
	} else {
		// regs32(64) is not in supervisor mode.
		u_regs32 = regs32;
		u_regs64 = regs64;
		regs32 = NULL;
		regs64 = NULL;
	}

	if (user_only) {
		/* we only want to backtrace the user mode */
		if (!(u_regs32 || u_regs64)) {
			/* no user state to look at */
			return KERN_FAILURE;
		}
	}

	/*
	 * Order of preference for top of stack:
	 * 64 bit kernel state (not likely)
	 * 32 bit kernel state
	 * 64 bit user land state
	 * 32 bit user land state
	 */

	if (kregs) {
		/*
		 * nofault read of the registers from the kernel stack (as they can
		 * disappear on the fly).
		 */

		if (KERN_SUCCESS != chudxnu_kern_read(&currPC, (vm_offset_t)&(kregs->k_rip), sizeof(uint64_t))) {
			return KERN_FAILURE;
		}
	} else if (regs64) {
		currPC = regs64->isf.rip;
	} else if (regs32) {
		currPC = (uint64_t) regs32->eip;
	} else if (u_regs64) {
		currPC = u_regs64->isf.rip;
	} else if (u_regs32) {
		currPC = (uint64_t) u_regs32->eip;
	}

	if (!currPC) {
		/* no top of the stack, bail out */
		return KERN_FAILURE;
	}

	bufferIndex = 0;

	if (bufferMaxIndex < 1) {
		*count = 0;
		return KERN_RESOURCE_SHORTAGE;
	}

	/* backtrace kernel */
	if (kregs) {
		addr64_t address = 0ULL;
		size_t size = 0UL;

		// do the backtrace
		kr = do_kernel_backtrace(thread, kregs, callstack, &bufferIndex, bufferMaxIndex);

		// and do a nofault read of (r|e)sp
		uint64_t rsp = 0ULL;
		size = sizeof(uint64_t);

		if (KERN_SUCCESS != chudxnu_kern_read(&address, (vm_offset_t)&(kregs->k_rsp), size)) {
			address = 0ULL;
		}

		if (address && KERN_SUCCESS == chudxnu_kern_read(&rsp, (vm_offset_t)address, size) && bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = (uint64_t)rsp;
		}
	} else if (regs64) {
		uint64_t rsp = 0ULL;

		// backtrace the 64bit side.
		kr = do_backtrace64(task, thread, regs64, callstack, &bufferIndex,
		    bufferMaxIndex - 1, TRUE);

		if (KERN_SUCCESS == chudxnu_kern_read(&rsp, (vm_offset_t) regs64->isf.rsp, sizeof(uint64_t)) &&
		    bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = rsp;
		}
	} else if (regs32) {
		uint32_t esp = 0UL;

		// backtrace the 32bit side.
		kr = do_backtrace32(task, thread, regs32, callstack, &bufferIndex,
		    bufferMaxIndex - 1, TRUE);

		if (KERN_SUCCESS == chudxnu_kern_read(&esp, (vm_offset_t) regs32->uesp, sizeof(uint32_t)) &&
		    bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = (uint64_t) esp;
		}
	} else if (u_regs64 && !kern_only) {
		/* backtrace user land */
		uint64_t rsp = 0ULL;

		kr = do_backtrace64(task, thread, u_regs64, callstack, &bufferIndex,
		    bufferMaxIndex - 1, FALSE);

		if (KERN_SUCCESS == chudxnu_task_read(task, &rsp, (addr64_t) u_regs64->isf.rsp, sizeof(uint64_t)) &&
		    bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = rsp;
		}
	} else if (u_regs32 && !kern_only) {
		uint32_t esp = 0UL;

		kr = do_backtrace32(task, thread, u_regs32, callstack, &bufferIndex,
		    bufferMaxIndex - 1, FALSE);

		if (KERN_SUCCESS == chudxnu_task_read(task, &esp, (addr64_t) u_regs32->uesp, sizeof(uint32_t)) &&
		    bufferIndex < bufferMaxIndex) {
			callstack[bufferIndex++] = (uint64_t) esp;
		}
	}

	*count = bufferIndex;
	return kr;
}

__private_extern__
kern_return_t
chudxnu_thread_get_callstack64_kperf(
	thread_t                thread,
	uint64_t                *callstack,
	mach_msg_type_number_t  *count,
	boolean_t               is_user)
{
	return chudxnu_thread_get_callstack64_internal(thread, callstack, count, is_user, !is_user);
}
#else /* !__arm__ && !__arm64__ && !__x86_64__ */
#error kperf: unsupported architecture
#endif /* !__arm__ && !__arm64__ && !__x86_64__ */
