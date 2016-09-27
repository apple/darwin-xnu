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

#include <chud/chud_xnu.h>
#include <mach/mach_types.h>
#include <kern/thread.h>
#include <kern/backtrace.h>
#include <vm/vm_map.h>
#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/callstack.h>
#include <kperf/ast.h>
#include <sys/errno.h>


static void
callstack_fixup_user(struct callstack *cs, thread_t thread)
{
	uint64_t fixup_val = 0;
	assert(cs->nframes < MAX_CALLSTACK_FRAMES);

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

#else
#error "callstack_fixup_user: unsupported architecture"
#endif

out:
	cs->frames[cs->nframes++] = fixup_val;
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

#else /* defined(__arm__) */
#error "interrupted_kernel_{sp,lr}: unsupported architecture"
#endif /* !defined(__arm__) */


static void
callstack_fixup_interrupted(struct callstack *cs)
{
	uintptr_t fixup_val = 0;
	assert(cs->nframes < MAX_CALLSTACK_FRAMES);

	/*
	 * Only provide arbitrary data on development or debug kernels.
	 */
#if DEVELOPMENT || DEBUG
#if defined(__x86_64__)
	(void)interrupted_kernel_sp_value(&fixup_val);
#endif /* defined(__x86_64__) */
#endif /* DEVELOPMENT || DEBUG */

	cs->frames[cs->nframes++] = fixup_val ?
		VM_KERNEL_UNSLIDE_OR_PERM(fixup_val) : 0;
}

void
kperf_continuation_sample(struct callstack *cs, struct kperf_context *context)
{
	thread_t thread;

	assert(cs != NULL);
	assert(context != NULL);

	thread = context->cur_thread;
	assert(thread != NULL);
	assert(thread->continuation != NULL);

	cs->flags = CALLSTACK_CONTINUATION | CALLSTACK_VALID | CALLSTACK_KERNEL;
#ifdef __LP64__
	cs->flags |= CALLSTACK_64BIT;
#endif

	cs->nframes = 1;
	cs->frames[0] = VM_KERNEL_UNSLIDE(thread->continuation);
}

void
kperf_backtrace_sample(struct callstack *cs, struct kperf_context *context)
{
	assert(cs != NULL);
	assert(context != NULL);
	assert(context->cur_thread == current_thread());

	cs->flags = CALLSTACK_KERNEL | CALLSTACK_KERNEL_WORDS;
#ifdef __LP64__
	cs->flags |= CALLSTACK_64BIT;
#endif

	BUF_VERB(PERF_CS_BACKTRACE | DBG_FUNC_START, 1);

	cs->nframes = backtrace_frame((uintptr_t *)&(cs->frames), cs->nframes - 1,
	                              context->starting_fp);
	if (cs->nframes > 0) {
		cs->flags |= CALLSTACK_VALID;
		/*
		 * Fake the value pointed to by the stack pointer or the link
		 * register for symbolicators.
		 */
		cs->frames[cs->nframes + 1] = 0;
		cs->nframes += 1;
	}

	BUF_VERB(PERF_CS_BACKTRACE | DBG_FUNC_END, cs->nframes);
}

void
kperf_kcallstack_sample(struct callstack *cs, struct kperf_context *context)
{
	thread_t thread;

	assert(cs != NULL);
	assert(context != NULL);
	assert(cs->nframes <= MAX_CALLSTACK_FRAMES);

	thread = context->cur_thread;
	assert(thread != NULL);

	BUF_INFO(PERF_CS_KSAMPLE | DBG_FUNC_START, (uintptr_t)thread_tid(thread),
		cs->nframes);

	cs->flags = CALLSTACK_KERNEL;

#ifdef __LP64__
	cs->flags |= CALLSTACK_64BIT;
#endif

	if (ml_at_interrupt_context()) {
		assert(thread == current_thread());
		cs->flags |= CALLSTACK_KERNEL_WORDS;
		cs->nframes = backtrace_interrupted((uintptr_t *)cs->frames,
			cs->nframes - 1);
		if (cs->nframes != 0) {
			callstack_fixup_interrupted(cs);
		}
	} else {
		/*
		 * Rely on legacy CHUD backtracer to backtrace kernel stacks on
		 * other threads.
		 */
		kern_return_t kr;
		kr = chudxnu_thread_get_callstack64_kperf(thread, cs->frames,
			&cs->nframes, FALSE);
		if (kr == KERN_SUCCESS) {
			cs->flags |= CALLSTACK_VALID;
		} else if (kr == KERN_RESOURCE_SHORTAGE) {
			cs->flags |= CALLSTACK_VALID;
			cs->flags |= CALLSTACK_TRUNCATED;
		} else {
			cs->nframes = 0;
		}
	}

	if (cs->nframes == 0) {
		BUF_INFO(PERF_CS_ERROR, ERR_GETSTACK);
	}

	BUF_INFO(PERF_CS_KSAMPLE | DBG_FUNC_END, (uintptr_t)thread_tid(thread), cs->flags, cs->nframes);
}

void
kperf_ucallstack_sample(struct callstack *cs, struct kperf_context *context)
{
	thread_t thread;
	bool user_64 = false;
	int err;

	assert(cs != NULL);
	assert(context != NULL);
	assert(cs->nframes <= MAX_CALLSTACK_FRAMES);
	assert(ml_get_interrupts_enabled() == TRUE);

	thread = context->cur_thread;
	assert(thread != NULL);

	BUF_INFO(PERF_CS_USAMPLE | DBG_FUNC_START, (uintptr_t)thread_tid(thread),
		cs->nframes);

	cs->flags = 0;

	err = backtrace_thread_user(thread, (uintptr_t *)cs->frames,
		cs->nframes - 1, &cs->nframes, &user_64);
	cs->flags |= CALLSTACK_KERNEL_WORDS;
	if (user_64) {
		cs->flags |= CALLSTACK_64BIT;
	}

	if (!err || err == EFAULT) {
		callstack_fixup_user(cs, thread);
		cs->flags |= CALLSTACK_VALID;
	} else {
		cs->nframes = 0;
		BUF_INFO(PERF_CS_ERROR, ERR_GETSTACK, err);
	}

	BUF_INFO(PERF_CS_USAMPLE | DBG_FUNC_END, (uintptr_t)thread_tid(thread),
		cs->flags, cs->nframes);
}

static inline uintptr_t
scrub_kernel_frame(uintptr_t *bt, int n_frames, int frame)
{
	if (frame < n_frames) {
		return VM_KERNEL_UNSLIDE(bt[frame]);
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
callstack_log(struct callstack *cs, uint32_t hcode, uint32_t dcode)
{
	BUF_VERB(PERF_CS_LOG | DBG_FUNC_START, cs->flags, cs->nframes);

	/* framing information for the stack */
	BUF_DATA(hcode, cs->flags, cs->nframes);

	/* how many batches of 4 */
	unsigned int n = cs->nframes / 4;
	unsigned int ovf = cs->nframes % 4;
	if (ovf != 0) {
		n++;
	}

	if (cs->flags & CALLSTACK_KERNEL_WORDS) {
		for (unsigned int i = 0; i < n; i++) {
			unsigned int j = i * 4;
			BUF_DATA(dcode,
				scrub_kernel_frame((uintptr_t *)cs->frames, cs->nframes, j + 0),
				scrub_kernel_frame((uintptr_t *)cs->frames, cs->nframes, j + 1),
				scrub_kernel_frame((uintptr_t *)cs->frames, cs->nframes, j + 2),
				scrub_kernel_frame((uintptr_t *)cs->frames, cs->nframes, j + 3));
		}
	} else {
		for (unsigned int i = 0; i < n; i++) {
			unsigned int j = i * 4;
			BUF_DATA(dcode,
				scrub_frame(cs->frames, cs->nframes, j + 0),
				scrub_frame(cs->frames, cs->nframes, j + 1),
				scrub_frame(cs->frames, cs->nframes, j + 2),
				scrub_frame(cs->frames, cs->nframes, j + 3));
		}
	}

	BUF_VERB(PERF_CS_LOG | DBG_FUNC_END, cs->flags, cs->nframes);
}

void
kperf_kcallstack_log( struct callstack *cs )
{
	callstack_log(cs, PERF_CS_KHDR, PERF_CS_KDATA);
}

void
kperf_ucallstack_log( struct callstack *cs )
{
	callstack_log(cs, PERF_CS_UHDR, PERF_CS_UDATA);
}

int
kperf_ucallstack_pend(struct kperf_context * context, uint32_t depth)
{
	int did_pend = kperf_ast_pend(context->cur_thread, T_KPERF_AST_CALLSTACK);
	kperf_ast_set_callstack_depth(context->cur_thread, depth);

	return did_pend;
}
