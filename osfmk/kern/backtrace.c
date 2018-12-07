/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include <stddef.h>
#include <stdint.h>

#include <kern/assert.h>
#include <kern/backtrace.h>
#include <kern/thread.h>
#include <sys/errno.h>
#include <vm/vm_map.h>

#if defined(__arm__) || defined(__arm64__)
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#endif



uint32_t __attribute__((noinline))
backtrace(uintptr_t *bt, uint32_t max_frames)
{
	return backtrace_frame(bt, max_frames, __builtin_frame_address(0));
}

/*
 * This function captures a backtrace from the current stack and returns the
 * number of frames captured, limited by max_frames and starting at start_frame.
 * It's fast because it does no checking to make sure there isn't bad data.
 * Since it's only called from threads that we're going to keep executing,
 * if there's bad data we were going to die eventually.  If this function is
 * inlined, it doesn't record the frame of the function it's inside (because
 * there's no stack frame).
 */
uint32_t __attribute__((noinline,not_tail_called))
backtrace_frame(uintptr_t *bt, uint32_t max_frames, void *start_frame)
{
	thread_t thread = current_thread();
	uintptr_t *fp;
	uint32_t frame_index = 0;
	uintptr_t top, bottom;
	bool in_valid_stack;

	assert(bt != NULL);
	assert(max_frames > 0);

	fp = start_frame;
	bottom = thread->kernel_stack;
	top = bottom + kernel_stack_size;

#define IN_STK_BOUNDS(__addr) \
	(((uintptr_t)(__addr) >= (uintptr_t)bottom) && \
	((uintptr_t)(__addr) < (uintptr_t)top))

	in_valid_stack = IN_STK_BOUNDS(fp);

	if (!in_valid_stack) {
		fp = NULL;
	}

	while (fp != NULL && frame_index < max_frames) {
		uintptr_t *next_fp = (uintptr_t *)*fp;
		uintptr_t ret_addr = *(fp + 1); /* return address is one word higher than frame pointer */

		/*
		 * If the frame pointer is 0, backtracing has reached the top of
		 * the stack and there is no return address.  Some stacks might not
		 * have set this up, so bounds check, as well.
		 */
		in_valid_stack = IN_STK_BOUNDS(next_fp);

		if (next_fp == NULL || !in_valid_stack)
		{
			break;
		}

		bt[frame_index++] = ret_addr;

		/* stacks grow down; backtracing should be moving to higher addresses */
		if (next_fp <= fp) {
			break;
		}
		fp = next_fp;
	}

	return frame_index;
#undef IN_STK_BOUNDS
}

#if defined(__x86_64__)

static kern_return_t
interrupted_kernel_pc_fp(uintptr_t *pc, uintptr_t *fp)
{
	x86_saved_state_t *state;
	bool state_64;
	uint64_t cs;

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
		*pc = saved_state64(state)->isf.rip;
		*fp = saved_state64(state)->rbp;
	} else {
		*pc = saved_state32(state)->eip;
		*fp = saved_state32(state)->ebp;
	}
	return KERN_SUCCESS;
}

#elif defined(__arm64__)

static kern_return_t
interrupted_kernel_pc_fp(uintptr_t *pc, uintptr_t *fp)
{
	struct arm_saved_state *state;
	bool state_64;

	state = getCpuDatap()->cpu_int_state;
	if (!state) {
		return KERN_FAILURE;
	}
	state_64 = is_saved_state64(state);

	/* return early if interrupted a thread in user space */
	if (PSR64_IS_USER(get_saved_state_cpsr(state))) {
		return KERN_FAILURE;
	}

	*pc = get_saved_state_pc(state);
	*fp = get_saved_state_fp(state);
	return KERN_SUCCESS;
}

#elif defined(__arm__)

static kern_return_t
interrupted_kernel_pc_fp(uintptr_t *pc, uintptr_t *fp)
{
	struct arm_saved_state *state;

	state = getCpuDatap()->cpu_int_state;
	if (!state) {
		return KERN_FAILURE;
	}

	/* return early if interrupted a thread in user space */
	if (PSR_IS_USER(get_saved_state_cpsr(state))) {
		return KERN_FAILURE;
	}

	*pc = get_saved_state_pc(state);
	*fp = get_saved_state_fp(state);
	return KERN_SUCCESS;
}

#else /* defined(__arm__) */
#error "interrupted_kernel_pc_fp: unsupported architecture"
#endif /* !defined(__arm__) */

uint32_t
backtrace_interrupted(uintptr_t *bt, uint32_t max_frames)
{
	uintptr_t pc;
	uintptr_t fp;
	kern_return_t kr;

	assert(bt != NULL);
	assert(max_frames > 0);
	assert(ml_at_interrupt_context() == TRUE);

	kr = interrupted_kernel_pc_fp(&pc, &fp);
	if (kr != KERN_SUCCESS) {
		return 0;
	}

	bt[0] = pc;
	if (max_frames == 1) {
		return 1;
	}

	return backtrace_frame(bt + 1, max_frames - 1, (void *)fp) + 1;
}

int
backtrace_user(uintptr_t *bt, uint32_t max_frames, uint32_t *frames_out,
	bool *user_64_out)
{
	return backtrace_thread_user(current_thread(), bt, max_frames, frames_out,
		user_64_out);
}

int
backtrace_thread_user(void *thread, uintptr_t *bt, uint32_t max_frames,
	uint32_t *frames_out, bool *user_64_out)
{
	bool user_64;
	uintptr_t pc, fp, next_fp;
	vm_map_t map = NULL, old_map = NULL;
	uint32_t frame_index = 0;
	int err = 0;
	size_t frame_size;

	assert(bt != NULL);
	assert(max_frames > 0);
	assert(frames_out != NULL);
	assert(user_64_out != NULL);

#if defined(__x86_64__)

	/* don't allow a malformed user stack to copyin arbitrary kernel data */
#define INVALID_USER_FP(FP) ((FP) == 0 || !IS_USERADDR64_CANONICAL((FP)))

	x86_saved_state_t *state = get_user_regs(thread);

	if (!state) {
		return EINVAL;
	}

	user_64 = is_saved_state64(state);
	if (user_64) {
		pc = saved_state64(state)->isf.rip;
		fp = saved_state64(state)->rbp;
	} else {
		pc = saved_state32(state)->eip;
		fp = saved_state32(state)->ebp;
	}

#elif defined(__arm64__)

	/* ARM expects stack frames to be aligned to 16 bytes */
#define INVALID_USER_FP(FP) ((FP) == 0 || ((FP) & 0x3UL) != 0UL)

	struct arm_saved_state *state = get_user_regs(thread);
	if (!state) {
		return EINVAL;
	}

	user_64 = is_saved_state64(state);
	pc = get_saved_state_pc(state);
	fp = get_saved_state_fp(state);

#elif defined(__arm__)

	/* ARM expects stack frames to be aligned to 16 bytes */
#define INVALID_USER_FP(FP) ((FP) == 0 || ((FP) & 0x3UL) != 0UL)

	struct arm_saved_state *state = get_user_regs(thread);
	if (!state) {
		return EINVAL;
	}

	user_64 = false;
	pc = get_saved_state_pc(state);
	fp = get_saved_state_fp(state);

#else /* defined(__arm__) */
#error "backtrace_thread_user: unsupported architecture"
#endif /* !defined(__arm__) */

	if (max_frames == 0) {
		goto out;
	}

	bt[frame_index++] = pc;

	if (frame_index >= max_frames) {
		goto out;
	}

	if (INVALID_USER_FP(fp)) {
		goto out;
	}

	assert(ml_get_interrupts_enabled() == TRUE);
	if (!ml_get_interrupts_enabled()) {
		return EINVAL;
	}

	union {
		struct {
			uint64_t fp;
			uint64_t ret;
		} u64;
		struct {
			uint32_t fp;
			uint32_t ret;
		} u32;
	} frame;

	frame_size = 2 * (user_64 ? sizeof(uint64_t) : sizeof(uint32_t));

	/* switch to the correct map, for copyin */
	if (thread != current_thread()) {
		map = get_task_map_reference(get_threadtask(thread));
		if (map == NULL) {
			return EINVAL;
		}
		old_map = vm_map_switch(map);
	} else {
		map = NULL;
	}

	while (fp != 0 && frame_index < max_frames) {
		err = copyin(fp, (char *)&frame, frame_size);
		if (err) {
			goto out;
		}

		next_fp = user_64 ? frame.u64.fp : frame.u32.fp;

		if (INVALID_USER_FP(next_fp)) {
			break;
		}

		uintptr_t ret_addr = user_64 ? frame.u64.ret : frame.u32.ret;
		bt[frame_index++] = ret_addr;

		/* stacks grow down; backtracing should be moving to higher addresses */
		if (next_fp <= fp) {
			break;
		}
		fp = next_fp;
	}

out:
	if (map) {
		(void)vm_map_switch(old_map);
		vm_map_deallocate(map);
	}

	*user_64_out = user_64;
	*frames_out = frame_index;
	return err;
#undef INVALID_USER_FP
}
