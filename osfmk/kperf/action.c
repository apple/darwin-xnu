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

/*
 * Called from a trigger. Actually takes the data from the different
 * modules and puts them in a buffer
 */

#include <mach/mach_types.h>
#include <machine/machine_routines.h>
#include <kern/kalloc.h>
#include <kern/debug.h> /* panic */
#include <kern/thread.h>
#include <sys/errno.h>
#include <sys/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>

#include <kperf/action.h>
#include <kperf/ast.h>
#include <kperf/buffer.h>
#include <kperf/callstack.h>
#include <kperf/context.h>
#include <kperf/kdebug_trigger.h>
#include <kperf/kperf.h>
#include <kperf/kperf_kpc.h>
#include <kperf/kperf_timer.h>
#include <kperf/pet.h>
#include <kperf/sample.h>
#include <kperf/thread_samplers.h>

#define ACTION_MAX (32)

/* the list of different actions to take */
struct action {
	uint32_t sample;
	uint32_t ucallstack_depth;
	uint32_t kcallstack_depth;
	uint32_t userdata;
	int pid_filter;
};

/* the list of actions */
static unsigned int actionc = 0;
static struct action *actionv = NULL;

/* should emit tracepoint on context switch */
int kperf_kdebug_cswitch = 0;

bool
kperf_action_has_non_system(unsigned int actionid)
{
	if (actionid > actionc) {
		return false;
	}

	if (actionv[actionid - 1].sample & ~SAMPLER_SYS_MEM) {
		return true;
	} else {
		return false;
	}
}

bool
kperf_action_has_task(unsigned int actionid)
{
	if (actionid > actionc) {
		return false;
	}

	return actionv[actionid - 1].sample & SAMPLER_TASK_MASK;
}

bool
kperf_action_has_thread(unsigned int actionid)
{
	if (actionid > actionc) {
		return false;
	}

	return actionv[actionid - 1].sample & SAMPLER_THREAD_MASK;
}

static void
kperf_system_memory_log(void)
{
	BUF_DATA(PERF_MI_SYS_DATA, (uintptr_t)vm_page_free_count,
	    (uintptr_t)vm_page_wire_count, (uintptr_t)vm_page_external_count,
	    (uintptr_t)(vm_page_active_count + vm_page_inactive_count +
	    vm_page_speculative_count));
	BUF_DATA(PERF_MI_SYS_DATA_2, (uintptr_t)vm_page_anonymous_count,
	    (uintptr_t)vm_page_internal_count,
	    (uintptr_t)vm_pageout_vminfo.vm_pageout_compressions,
	    (uintptr_t)VM_PAGE_COMPRESSOR_COUNT);
}

static void
kperf_sample_user_internal(struct kperf_usample *sbuf,
    struct kperf_context *context, unsigned int actionid,
    unsigned int sample_what)
{
	if (sample_what & SAMPLER_USTACK) {
		kperf_ucallstack_sample(&sbuf->ucallstack, context);
	}
	if (sample_what & SAMPLER_TH_DISPATCH) {
		kperf_thread_dispatch_sample(&sbuf->th_dispatch, context);
	}
	if (sample_what & SAMPLER_TH_INFO) {
		kperf_thread_info_sample(&sbuf->th_info, context);
	}

	boolean_t intren = ml_set_interrupts_enabled(FALSE);

	/*
	 * No userdata or sample_flags for this one.
	 */
	BUF_DATA(PERF_GEN_EVENT | DBG_FUNC_START, sample_what, actionid);

	if (sample_what & SAMPLER_USTACK) {
		kperf_ucallstack_log(&sbuf->ucallstack);
	}
	if (sample_what & SAMPLER_TH_DISPATCH) {
		kperf_thread_dispatch_log(&sbuf->th_dispatch);
	}
	if (sample_what & SAMPLER_TH_INFO) {
		kperf_thread_info_log(&sbuf->th_info);
	}

	BUF_DATA(PERF_GEN_EVENT | DBG_FUNC_END, sample_what);

	ml_set_interrupts_enabled(intren);
}

void
kperf_sample_user(struct kperf_usample *sbuf, struct kperf_context *context,
    unsigned int actionid, unsigned int sample_flags)
{
	if (actionid == 0 || actionid > actionc) {
		return;
	}

	unsigned int sample_what = actionv[actionid - 1].sample;
	unsigned int ucallstack_depth = actionv[actionid - 1].ucallstack_depth;

	/* callstacks should be explicitly ignored */
	if (sample_flags & SAMPLE_FLAG_EMPTY_CALLSTACK) {
		sample_what &= ~(SAMPLER_KSTACK | SAMPLER_USTACK);
	}
	if (sample_flags & SAMPLE_FLAG_ONLY_SYSTEM) {
		sample_what &= SAMPLER_SYS_MEM;
	}
	assert((sample_flags & (SAMPLE_FLAG_THREAD_ONLY | SAMPLE_FLAG_TASK_ONLY))
	    != (SAMPLE_FLAG_THREAD_ONLY | SAMPLE_FLAG_TASK_ONLY));
	if (sample_flags & SAMPLE_FLAG_THREAD_ONLY) {
		sample_what &= SAMPLER_THREAD_MASK;
	}
	if (sample_flags & SAMPLE_FLAG_TASK_ONLY) {
		sample_what &= SAMPLER_TASK_MASK;
	}

	if (sample_what == 0) {
		return;
	}

	sbuf->ucallstack.kpuc_nframes = ucallstack_depth ?:
	    MAX_UCALLSTACK_FRAMES;

	kperf_sample_user_internal(sbuf, context, actionid, sample_what);
}

static kern_return_t
kperf_sample_internal(struct kperf_sample *sbuf,
    struct kperf_context *context,
    unsigned sample_what, unsigned sample_flags,
    unsigned actionid, unsigned ucallstack_depth)
{
	int pended_ucallstack = 0;
	int pended_th_dispatch = 0;
	bool on_idle_thread = false;
	uint32_t userdata = actionid;
	bool task_only = false;

	if (sample_what == 0) {
		return SAMPLE_CONTINUE;
	}

	/* callstacks should be explicitly ignored */
	if (sample_flags & SAMPLE_FLAG_EMPTY_CALLSTACK) {
		sample_what &= ~(SAMPLER_KSTACK | SAMPLER_USTACK);
	}

	if (sample_flags & SAMPLE_FLAG_ONLY_SYSTEM) {
		sample_what &= SAMPLER_SYS_MEM;
	}

	assert((sample_flags & (SAMPLE_FLAG_THREAD_ONLY | SAMPLE_FLAG_TASK_ONLY))
	    != (SAMPLE_FLAG_THREAD_ONLY | SAMPLE_FLAG_TASK_ONLY));
	if (sample_flags & SAMPLE_FLAG_THREAD_ONLY) {
		sample_what &= SAMPLER_THREAD_MASK;
	}
	if (sample_flags & SAMPLE_FLAG_TASK_ONLY) {
		task_only = true;
		sample_what &= SAMPLER_TASK_MASK;
	}

	if (!task_only) {
		context->cur_thread->kperf_pet_gen = kperf_pet_gen;
	}
	bool is_kernel = (context->cur_pid == 0);

	if (actionid && actionid <= actionc) {
		sbuf->kcallstack.kpkc_nframes =
		    actionv[actionid - 1].kcallstack_depth;
	} else {
		sbuf->kcallstack.kpkc_nframes = MAX_KCALLSTACK_FRAMES;
	}

	ucallstack_depth = ucallstack_depth ?: MAX_UCALLSTACK_FRAMES;
	sbuf->kcallstack.kpkc_flags = 0;
	sbuf->usample.ucallstack.kpuc_flags = 0;

	if (sample_what & SAMPLER_TH_INFO) {
		kperf_thread_info_sample(&sbuf->th_info, context);

		if (!(sample_flags & SAMPLE_FLAG_IDLE_THREADS)) {
			if (sbuf->th_info.kpthi_runmode & 0x40) {
				on_idle_thread = true;
				goto log_sample;
			}
		}
	}

	if (sample_what & SAMPLER_TH_SNAPSHOT) {
		kperf_thread_snapshot_sample(&(sbuf->th_snapshot), context);
	}
	if (sample_what & SAMPLER_TH_SCHEDULING) {
		kperf_thread_scheduling_sample(&(sbuf->th_scheduling), context);
	}
	if (sample_what & SAMPLER_KSTACK) {
		if (sample_flags & SAMPLE_FLAG_CONTINUATION) {
			kperf_continuation_sample(&(sbuf->kcallstack), context);
		} else if (sample_flags & SAMPLE_FLAG_NON_INTERRUPT) {
			/* outside of interrupt context, backtrace the current thread */
			kperf_backtrace_sample(&(sbuf->kcallstack), context);
		} else {
			kperf_kcallstack_sample(&(sbuf->kcallstack), context);
		}
	}
	if (sample_what & SAMPLER_TK_SNAPSHOT) {
		kperf_task_snapshot_sample(context->cur_task, &(sbuf->tk_snapshot));
	}

	if (!is_kernel) {
		if (sample_what & SAMPLER_MEMINFO) {
			kperf_meminfo_sample(context->cur_task, &(sbuf->meminfo));
		}

		if (sample_flags & SAMPLE_FLAG_PEND_USER) {
			if (sample_what & SAMPLER_USTACK) {
				pended_ucallstack = kperf_ucallstack_pend(context,
				    ucallstack_depth, actionid);
			}

			if (sample_what & SAMPLER_TH_DISPATCH) {
				pended_th_dispatch =
				    kperf_thread_dispatch_pend(context, actionid);
			}
		}
	}

	if (sample_what & SAMPLER_PMC_THREAD) {
		kperf_kpc_thread_sample(&(sbuf->kpcdata), sample_what);
	} else if (sample_what & SAMPLER_PMC_CPU) {
		kperf_kpc_cpu_sample(&(sbuf->kpcdata), sample_what);
	}

log_sample:
	/* lookup the user tag, if any */
	if (actionid && (actionid <= actionc)) {
		userdata = actionv[actionid - 1].userdata;
	}

	/* avoid logging if this sample only pended samples */
	if (sample_flags & SAMPLE_FLAG_PEND_USER &&
	    !(sample_what & ~(SAMPLER_USTACK | SAMPLER_TH_DISPATCH))) {
		return SAMPLE_CONTINUE;
	}

	/* stash the data into the buffer
	 * interrupts off to ensure we don't get split
	 */
	boolean_t enabled = ml_set_interrupts_enabled(FALSE);

	BUF_DATA(PERF_GEN_EVENT | DBG_FUNC_START, sample_what,
	    actionid, userdata, sample_flags);

	if (sample_flags & SAMPLE_FLAG_SYSTEM) {
		if (sample_what & SAMPLER_SYS_MEM) {
			kperf_system_memory_log();
		}
	}
	if (on_idle_thread) {
		goto log_sample_end;
	}

	if (sample_what & SAMPLER_TH_INFO) {
		kperf_thread_info_log(&sbuf->th_info);
	}
	if (sample_what & SAMPLER_TH_SCHEDULING) {
		kperf_thread_scheduling_log(&(sbuf->th_scheduling));
	}
	if (sample_what & SAMPLER_TH_SNAPSHOT) {
		kperf_thread_snapshot_log(&(sbuf->th_snapshot));
	}
	if (sample_what & SAMPLER_KSTACK) {
		kperf_kcallstack_log(&sbuf->kcallstack);
	}
	if (sample_what & SAMPLER_TH_INSCYC) {
		kperf_thread_inscyc_log(context);
	}
	if (sample_what & SAMPLER_TK_SNAPSHOT) {
		kperf_task_snapshot_log(&(sbuf->tk_snapshot));
	}
	if (sample_what & SAMPLER_TK_INFO) {
		kperf_task_info_log(context);
	}

	/* dump user stuff */
	if (!is_kernel) {
		/* dump meminfo */
		if (sample_what & SAMPLER_MEMINFO) {
			kperf_meminfo_log(&(sbuf->meminfo));
		}

		if (sample_flags & SAMPLE_FLAG_PEND_USER) {
			if (pended_ucallstack) {
				BUF_INFO(PERF_CS_UPEND);
			}

			if (pended_th_dispatch) {
				BUF_INFO(PERF_TI_DISPPEND);
			}
		}
	}

	if (sample_what & SAMPLER_PMC_CONFIG) {
		kperf_kpc_config_log(&(sbuf->kpcdata));
	}
	if (sample_what & SAMPLER_PMC_THREAD) {
		kperf_kpc_thread_log(&(sbuf->kpcdata));
	} else if (sample_what & SAMPLER_PMC_CPU) {
		kperf_kpc_cpu_log(&(sbuf->kpcdata));
	}

log_sample_end:
	BUF_DATA(PERF_GEN_EVENT | DBG_FUNC_END, sample_what, on_idle_thread ? 1 : 0);

	/* intrs back on */
	ml_set_interrupts_enabled(enabled);

	return SAMPLE_CONTINUE;
}

/* Translate actionid into sample bits and take a sample */
kern_return_t
kperf_sample(struct kperf_sample *sbuf,
    struct kperf_context *context,
    unsigned actionid, unsigned sample_flags)
{
	/* work out what to sample, if anything */
	if ((actionid > actionc) || (actionid == 0)) {
		return SAMPLE_SHUTDOWN;
	}

	/* check the pid filter against the context's current pid.
	 * filter pid == -1 means any pid
	 */
	int pid_filter = actionv[actionid - 1].pid_filter;
	if ((pid_filter != -1) && (pid_filter != context->cur_pid)) {
		return SAMPLE_CONTINUE;
	}

	/* the samplers to run */
	unsigned int sample_what = actionv[actionid - 1].sample;
	unsigned int ucallstack_depth = actionv[actionid - 1].ucallstack_depth;

	/* do the actual sample operation */
	return kperf_sample_internal(sbuf, context, sample_what,
	           sample_flags, actionid, ucallstack_depth);
}

void
kperf_kdebug_handler(uint32_t debugid, uintptr_t *starting_fp)
{
	uint32_t sample_flags = SAMPLE_FLAG_PEND_USER;
	struct kperf_sample *sample = NULL;
	kern_return_t kr = KERN_SUCCESS;
	int s;

	if (!kperf_kdebug_should_trigger(debugid)) {
		return;
	}

	BUF_VERB(PERF_KDBG_HNDLR | DBG_FUNC_START, debugid);

	thread_t thread = current_thread();
	task_t task = get_threadtask(thread);
	struct kperf_context ctx = {
		.cur_thread = thread,
		.cur_task = task,
		.cur_pid = task_pid(task),
		.trigger_type = TRIGGER_TYPE_KDEBUG,
		.trigger_id = 0,
	};

	s = ml_set_interrupts_enabled(0);

	sample = kperf_intr_sample_buffer();

	if (!ml_at_interrupt_context()) {
		sample_flags |= SAMPLE_FLAG_NON_INTERRUPT;
		ctx.starting_fp = starting_fp;
	}

	kr = kperf_sample(sample, &ctx, kperf_kdebug_get_action(), sample_flags);

	ml_set_interrupts_enabled(s);
	BUF_VERB(PERF_KDBG_HNDLR | DBG_FUNC_END, kr);
}

/*
 * This function allocates >2.3KB of the stack.  Prevent the compiler from
 * inlining this function into ast_taken and ensure the stack memory is only
 * allocated for the kperf AST.
 */
__attribute__((noinline))
void
kperf_thread_ast_handler(thread_t thread)
{
	uint32_t ast = thread->kperf_ast;

	BUF_INFO(PERF_AST_HNDLR | DBG_FUNC_START, thread, ast);

	struct kperf_usample sbuf = {};

	task_t task = get_threadtask(thread);

	if (task_did_exec(task) || task_is_exec_copy(task)) {
		BUF_INFO(PERF_AST_HNDLR | DBG_FUNC_END, SAMPLE_CONTINUE);
		return;
	}

	struct kperf_context ctx = {
		.cur_thread = thread,
		.cur_task = task,
		.cur_pid = task_pid(task),
	};

	unsigned int sample_what = 0;
	if (ast & T_KPERF_AST_DISPATCH) {
		sample_what |= SAMPLER_TH_DISPATCH;
	}
	if (ast & T_KPERF_AST_CALLSTACK) {
		/* TH_INFO for backwards compatibility */
		sample_what |= SAMPLER_USTACK | SAMPLER_TH_INFO;
	}

	sbuf.ucallstack.kpuc_nframes =
	    T_KPERF_GET_CALLSTACK_DEPTH(ast) ?: MAX_UCALLSTACK_FRAMES;
	unsigned int actionid = T_KPERF_GET_ACTIONID(ast);
	kperf_sample_user_internal(&sbuf, &ctx, actionid, sample_what);

	BUF_INFO(PERF_AST_HNDLR | DBG_FUNC_END);
}

int
kperf_ast_pend(thread_t thread, uint32_t set_flags, unsigned int set_actionid)
{
	if (thread != current_thread()) {
		panic("kperf: pending AST to non-current thread");
	}

	uint32_t ast = thread->kperf_ast;
	unsigned int actionid = T_KPERF_GET_ACTIONID(ast);
	uint32_t flags = ast & T_KPERF_AST_ALL;

	if ((flags | set_flags) != flags || actionid != set_actionid) {
		ast &= ~T_KPERF_SET_ACTIONID(actionid);
		ast |= T_KPERF_SET_ACTIONID(set_actionid);
		ast |= set_flags;

		thread->kperf_ast = ast;

		/* set the actual AST */
		act_set_kperf(thread);
		return 1;
	}

	return 0;
}

void
kperf_ast_set_callstack_depth(thread_t thread, uint32_t depth)
{
	uint32_t ast = thread->kperf_ast;
	uint32_t existing_depth = T_KPERF_GET_CALLSTACK_DEPTH(ast);
	if (existing_depth < depth) {
		ast &= ~T_KPERF_SET_CALLSTACK_DEPTH(existing_depth);
		ast |= T_KPERF_SET_CALLSTACK_DEPTH(depth);
		thread->kperf_ast = ast;
	}
}

int
kperf_kdbg_cswitch_get(void)
{
	return kperf_kdebug_cswitch;
}

int
kperf_kdbg_cswitch_set(int newval)
{
	kperf_kdebug_cswitch = newval;
	kperf_on_cpu_update();

	return 0;
}

/*
 * Action configuration
 */
unsigned int
kperf_action_get_count(void)
{
	return actionc;
}

int
kperf_action_set_samplers(unsigned actionid, uint32_t samplers)
{
	if ((actionid > actionc) || (actionid == 0)) {
		return EINVAL;
	}

	/* disallow both CPU and thread counters to be sampled in the same
	 * action */
	if ((samplers & SAMPLER_PMC_THREAD) && (samplers & SAMPLER_PMC_CPU)) {
		return EINVAL;
	}

	actionv[actionid - 1].sample = samplers;

	return 0;
}

int
kperf_action_get_samplers(unsigned actionid, uint32_t *samplers_out)
{
	if ((actionid > actionc)) {
		return EINVAL;
	}

	if (actionid == 0) {
		*samplers_out = 0; /* "NULL" action */
	} else {
		*samplers_out = actionv[actionid - 1].sample;
	}

	return 0;
}

int
kperf_action_set_userdata(unsigned actionid, uint32_t userdata)
{
	if ((actionid > actionc) || (actionid == 0)) {
		return EINVAL;
	}

	actionv[actionid - 1].userdata = userdata;

	return 0;
}

int
kperf_action_get_userdata(unsigned actionid, uint32_t *userdata_out)
{
	if ((actionid > actionc)) {
		return EINVAL;
	}

	if (actionid == 0) {
		*userdata_out = 0; /* "NULL" action */
	} else {
		*userdata_out = actionv[actionid - 1].userdata;
	}

	return 0;
}

int
kperf_action_set_filter(unsigned actionid, int pid)
{
	if ((actionid > actionc) || (actionid == 0)) {
		return EINVAL;
	}

	actionv[actionid - 1].pid_filter = pid;

	return 0;
}

int
kperf_action_get_filter(unsigned actionid, int *pid_out)
{
	if ((actionid > actionc)) {
		return EINVAL;
	}

	if (actionid == 0) {
		*pid_out = -1; /* "NULL" action */
	} else {
		*pid_out = actionv[actionid - 1].pid_filter;
	}

	return 0;
}

void
kperf_action_reset(void)
{
	for (unsigned int i = 0; i < actionc; i++) {
		kperf_action_set_samplers(i + 1, 0);
		kperf_action_set_userdata(i + 1, 0);
		kperf_action_set_filter(i + 1, -1);
		kperf_action_set_ucallstack_depth(i + 1, MAX_UCALLSTACK_FRAMES);
		kperf_action_set_kcallstack_depth(i + 1, MAX_KCALLSTACK_FRAMES);
	}
}

int
kperf_action_set_count(unsigned count)
{
	struct action *new_actionv = NULL, *old_actionv = NULL;
	unsigned old_count;

	/* easy no-op */
	if (count == actionc) {
		return 0;
	}

	/* TODO: allow shrinking? */
	if (count < actionc) {
		return EINVAL;
	}

	/* cap it for good measure */
	if (count > ACTION_MAX) {
		return EINVAL;
	}

	/* creating the action arror for the first time. create a few
	 * more things, too.
	 */
	if (actionc == 0) {
		int r;
		if ((r = kperf_init())) {
			return r;
		}
	}

	/* create a new array */
	new_actionv = kalloc_tag(count * sizeof(*new_actionv), VM_KERN_MEMORY_DIAG);
	if (new_actionv == NULL) {
		return ENOMEM;
	}

	old_actionv = actionv;
	old_count = actionc;

	if (old_actionv != NULL) {
		memcpy(new_actionv, actionv, actionc * sizeof(*actionv));
	}

	memset(&(new_actionv[actionc]), 0, (count - old_count) * sizeof(*actionv));

	for (unsigned int i = old_count; i < count; i++) {
		new_actionv[i].pid_filter = -1;
		new_actionv[i].ucallstack_depth = MAX_UCALLSTACK_FRAMES;
		new_actionv[i].kcallstack_depth = MAX_KCALLSTACK_FRAMES;
	}

	actionv = new_actionv;
	actionc = count;

	if (old_actionv != NULL) {
		kfree(old_actionv, old_count * sizeof(*actionv));
	}

	return 0;
}

int
kperf_action_set_ucallstack_depth(unsigned action_id, uint32_t depth)
{
	if ((action_id > actionc) || (action_id == 0)) {
		return EINVAL;
	}

	if (depth > MAX_UCALLSTACK_FRAMES) {
		return EINVAL;
	}
	if (depth < 2) {
		return EINVAL;
	}

	actionv[action_id - 1].ucallstack_depth = depth;

	return 0;
}

int
kperf_action_set_kcallstack_depth(unsigned action_id, uint32_t depth)
{
	if ((action_id > actionc) || (action_id == 0)) {
		return EINVAL;
	}

	if (depth > MAX_KCALLSTACK_FRAMES) {
		return EINVAL;
	}
	if (depth < 1) {
		return EINVAL;
	}

	actionv[action_id - 1].kcallstack_depth = depth;

	return 0;
}

int
kperf_action_get_ucallstack_depth(unsigned action_id, uint32_t * depth_out)
{
	if ((action_id > actionc)) {
		return EINVAL;
	}

	assert(depth_out);

	if (action_id == 0) {
		*depth_out = MAX_UCALLSTACK_FRAMES;
	} else {
		*depth_out = actionv[action_id - 1].ucallstack_depth;
	}

	return 0;
}

int
kperf_action_get_kcallstack_depth(unsigned action_id, uint32_t * depth_out)
{
	if ((action_id > actionc)) {
		return EINVAL;
	}

	assert(depth_out);

	if (action_id == 0) {
		*depth_out = MAX_KCALLSTACK_FRAMES;
	} else {
		*depth_out = actionv[action_id - 1].kcallstack_depth;
	}

	return 0;
}
