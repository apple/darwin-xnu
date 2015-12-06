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
// #include <libkern/libkern.h>
#include <kern/kalloc.h>
#include <kern/debug.h> /* panic */
#include <kern/thread.h>
#include <sys/errno.h>

#include <chud/chud_xnu.h>
#include <kperf/kperf.h>

#include <kperf/buffer.h>
#include <kperf/timetrigger.h>
#include <kperf/threadinfo.h>
#include <kperf/callstack.h>
#include <kperf/sample.h>
#include <kperf/action.h>
#include <kperf/context.h>
#include <kperf/ast.h>
#include <kperf/kperf_kpc.h>

#define ACTION_MAX 32

/* the list of different actions to take */
struct action
{
	uint32_t sample;
	uint32_t userdata;
	int pid_filter;
};

/* the list of actions */
static unsigned actionc = 0;
static struct action *actionv = NULL;

/* manage callbacks from system */

/* callback set for kdebug */
static int kperf_kdbg_callback_set = 0;
/* whether to record callstacks on kdebug events */
static int kdebug_callstacks = 0;
/* the action ID to trigger on signposts */
static int kperf_signpost_action = 0;

/* callback set for context-switch */
int kperf_cswitch_callback_set = 0;
/* should emit tracepoint on context switch */
static int kdebug_cswitch = 0;
/* the action ID to trigger on context switches */
static int kperf_cswitch_action = 0;

/* indirect hooks to play nice with CHUD for the transition to kperf */
kern_return_t chudxnu_kdebug_callback_enter(chudxnu_kdebug_callback_func_t fn);
kern_return_t chudxnu_kdebug_callback_cancel(void);

/* Do the real work! */
/* this can be called in any context ... right? */
static kern_return_t
kperf_sample_internal(struct kperf_sample *sbuf,
                      struct kperf_context *context,
                      unsigned sample_what, unsigned sample_flags,
                      unsigned actionid)
{
	boolean_t enabled;
	int did_ucallstack = 0, did_tinfo_extra = 0;
	uint32_t userdata;

	/* not much point continuing here, but what to do ? return
	 * Shutdown? cut a tracepoint and continue?
	 */
	if (sample_what == 0) {
		return SAMPLE_CONTINUE;
	}

	int is_kernel = (context->cur_pid == 0);

	sbuf->kcallstack.nframes = 0;
	sbuf->kcallstack.flags = CALLSTACK_VALID;
	sbuf->ucallstack.nframes = 0;
	sbuf->ucallstack.flags = CALLSTACK_VALID;

	/* an event occurred. Sample everything and dump it in a
	 * buffer.
	 */

	/* collect data from samplers */
	if (sample_what & SAMPLER_TINFO) {
		kperf_threadinfo_sample(&sbuf->threadinfo, context);

		/* See if we should drop idle thread samples */
		if (!(sample_flags & SAMPLE_FLAG_IDLE_THREADS)) {
			if (sbuf->threadinfo.runmode & 0x40) {
				return SAMPLE_CONTINUE;
			}
		}
	}

	if ((sample_what & SAMPLER_KSTACK) && !(sample_flags & SAMPLE_FLAG_EMPTY_CALLSTACK)) {
		kperf_kcallstack_sample(&(sbuf->kcallstack), context);
	}

	/* sensitive ones */
	if (!is_kernel) {
		if (sample_what & SAMPLER_MEMINFO) {
			kperf_meminfo_sample(&(sbuf->meminfo), context);
		}

		if (sample_flags & SAMPLE_FLAG_PEND_USER) {
			if ((sample_what & SAMPLER_USTACK)
			    && !(sample_flags & SAMPLE_FLAG_EMPTY_CALLSTACK))
			{
				did_ucallstack = kperf_ucallstack_pend(context);
			}

			if (sample_what & SAMPLER_TINFOEX) {
				did_tinfo_extra = kperf_threadinfo_extra_pend(context);
			}
		} else {
			if ((sample_what & SAMPLER_USTACK)
			    && !(sample_flags & SAMPLE_FLAG_EMPTY_CALLSTACK))
			{
				kperf_ucallstack_sample(&(sbuf->ucallstack), context);
			}

			if (sample_what & SAMPLER_TINFOEX) {
				kperf_threadinfo_extra_sample(&(sbuf->tinfo_ex),
				                              context);
			}
		}
	}

	if (sample_what & SAMPLER_PMC_THREAD) {
		kperf_kpc_thread_sample(&(sbuf->kpcdata), sample_what);
	} else if (sample_what & SAMPLER_PMC_CPU) {
		kperf_kpc_cpu_sample(&(sbuf->kpcdata), sample_what);
	}

	/* lookup the user tag, if any */
	if (actionid && (actionid <= actionc)) {
		userdata = actionv[actionid - 1].userdata;
	} else {
		userdata = actionid;
	}

	/* stash the data into the buffer
	 * interrupts off to ensure we don't get split
	 */
	enabled = ml_set_interrupts_enabled(FALSE);

	BUF_DATA(PERF_GEN_EVENT | DBG_FUNC_START, sample_what,
	         actionid, userdata, sample_flags);

	/* dump threadinfo */
	if (sample_what & SAMPLER_TINFO) {
		kperf_threadinfo_log( &sbuf->threadinfo );
	}

	/* dump kcallstack */
	if (sample_what & SAMPLER_KSTACK) {
		kperf_kcallstack_log( &sbuf->kcallstack );
	}

	/* dump user stuff */
	if (!is_kernel) {
		/* dump meminfo */
		if (sample_what & SAMPLER_MEMINFO) {
			kperf_meminfo_log(&(sbuf->meminfo));
		}

		if (sample_flags & SAMPLE_FLAG_PEND_USER) {
			if (did_ucallstack) {
				BUF_INFO1(PERF_CS_UPEND, 0);
			}

			if (did_tinfo_extra) {
				BUF_INFO1(PERF_TI_XPEND, 0);
			}
		} else {
			if (sample_what & SAMPLER_USTACK) {
				kperf_ucallstack_log(&(sbuf->ucallstack));
			}

			if (sample_what & SAMPLER_TINFOEX) {
				kperf_threadinfo_extra_log(&(sbuf->tinfo_ex));
			}
		}
	}

	if (sample_what & SAMPLER_PMC_THREAD) {
		kperf_kpc_thread_log(&(sbuf->kpcdata));
	} else if (sample_what & SAMPLER_PMC_CPU) {
		kperf_kpc_cpu_log(&(sbuf->kpcdata));
	}

	BUF_DATA1(PERF_GEN_EVENT | DBG_FUNC_END, sample_what);

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
	unsigned sample_what = 0;
	int pid_filter;

	/* work out what to sample, if anything */
	if ((actionid > actionc) || (actionid == 0)) {
		return SAMPLE_SHUTDOWN;
	}

	/* check the pid filter against the context's current pid.
	 * filter pid == -1 means any pid
	 */
	pid_filter = actionv[actionid - 1].pid_filter;
	if ((pid_filter != -1) && (pid_filter != context->cur_pid)) {
		return SAMPLE_CONTINUE;
	}

	/* the samplers to run */
	sample_what = actionv[actionid - 1].sample;

	/* do the actual sample operation */
	return kperf_sample_internal(sbuf, context, sample_what,
	                             sample_flags, actionid);
}

/* ast callback on a thread */
void
kperf_thread_ast_handler(thread_t thread)
{
	int r;
	uint32_t t_chud;
	unsigned sample_what = 0;
	/* we know we're on a thread, so let's do stuff */
	task_t task = NULL;

	BUF_INFO1(PERF_AST_HNDLR | DBG_FUNC_START, thread);

	/* use ~2kb of the stack for the sample, should be ok since we're in the ast */
	struct kperf_sample sbuf;
	memset(&sbuf, 0, sizeof(struct kperf_sample));

	/* make a context, take a sample */
	struct kperf_context ctx;
	ctx.cur_thread = thread;
	ctx.cur_pid = -1;

	task = chudxnu_task_for_thread(thread);
	if (task) {
		ctx.cur_pid = chudxnu_pid_for_task(task);
	}

	/* decode the chud bits so we know what to sample */
	t_chud = kperf_get_thread_bits(thread);

	if (t_chud & T_AST_NAME) {
		sample_what |= SAMPLER_TINFOEX;
	}

	if (t_chud & T_AST_CALLSTACK) {
		sample_what |= SAMPLER_USTACK;
		sample_what |= SAMPLER_TINFO;
	}

	/* do the sample, just of the user stuff */
	r = kperf_sample_internal(&sbuf, &ctx, sample_what, 0, 0);

	BUF_INFO1(PERF_AST_HNDLR | DBG_FUNC_END, r);
}

/* register AST bits */
int
kperf_ast_pend(thread_t cur_thread, uint32_t check_bits,
               uint32_t set_bits)
{
	/* pend on the thread */
	uint32_t t_chud, set_done = 0;

	/* can only pend on the current thread */
	if (cur_thread != chudxnu_current_thread()) {
		panic("pending to non-current thread");
	}

	/* get our current bits */
	t_chud = kperf_get_thread_bits(cur_thread);

	/* see if it's already been done or pended */
	if (!(t_chud & check_bits)) {
		/* set the bit on the thread */
		t_chud |= set_bits;
		kperf_set_thread_bits(cur_thread, t_chud);

		/* set the actual AST */
		kperf_set_thread_ast(cur_thread);

		set_done = 1;
	}

	return set_done;
}

/*
 * kdebug callback & stack management
 */

#define IS_END(debugid)           ((debugid & 3) == DBG_FUNC_END)
#define IS_MIG(debugid)           (IS_END(debugid) && ((debugid & 0xff000000U) == KDBG_CLASS_ENCODE((unsigned)DBG_MIG, 0U)))
#define IS_MACH_SYSCALL(debugid)  (IS_END(debugid) && (KDBG_CLASS_DECODE(debugid) == KDBG_CLASS_ENCODE(DBG_MACH, DBG_MACH_EXCP_SC)))
#define IS_VM_FAULT(debugid)      (IS_END(debugid) && (KDBG_CLASS_DECODE(debugid) == KDBG_CLASS_ENCODE(DBG_MACH, DBG_MACH_VM)))
#define IS_BSD_SYSCTLL(debugid)   (IS_END(debugid) && (KDBG_CLASS_DECODE(debugid) == KDBG_CLASS_ENCODE(DBG_BSD, DBG_BSD_EXCP_SC)))
#define IS_APPS_SIGNPOST(debugid) (KDBG_CLASS_DECODE(debugid) == KDBG_CLASS_ENCODE(DBG_APPS, DBG_MACH_CHUD))
#define IS_MACH_SIGNPOST(debugid) (KDBG_CLASS_DECODE(debugid) == KDBG_CLASS_ENCODE(DBG_MACH, DBG_MACH_CHUD))
#define IS_ENERGYTRACE(debugid)   ((debugid & 0xff000000U) == KDBG_CLASS_ENCODE((unsigned)DBG_ENERGYTRACE, 0U))

void
kperf_kdebug_callback(uint32_t debugid)
{
	int cur_pid = 0;
	task_t task = NULL;

	if (!kdebug_callstacks && !kperf_signpost_action) {
		return;
	}

	/* if we're looking at a kperf tracepoint, don't recurse */
	if ((debugid & 0xff000000) == KDBG_CLASS_ENCODE(DBG_PERF, 0)) {
		return;
	}

	/* ensure interrupts are already off thanks to kdebug */
	if (ml_get_interrupts_enabled()) {
		return;
	}

	/* make sure we're not being called recursively.  */
#if NOTYET
	if (kperf_kdbg_recurse(KPERF_RECURSE_IN)) {
		return;
	}
#endif

	/* check the happy list of trace codes */
	if(!(IS_MIG(debugid)
	     || IS_MACH_SYSCALL(debugid)
	     || IS_VM_FAULT(debugid)
	     || IS_BSD_SYSCTLL(debugid)
	     || IS_MACH_SIGNPOST(debugid)
	     || IS_ENERGYTRACE(debugid)
	     || IS_APPS_SIGNPOST(debugid)))
	{
		return;
	}

	/* check for kernel */
	thread_t thread = chudxnu_current_thread();
	task = chudxnu_task_for_thread(thread);
	if (task) {
		cur_pid = chudxnu_pid_for_task(task);
	}
	if (!cur_pid) {
		return;
	}

	if (kdebug_callstacks) {
		/* dicing with death */
		BUF_INFO2(PERF_KDBG_HNDLR, debugid, cur_pid);

		/* pend the AST */
		kperf_ast_pend( thread, T_AST_CALLSTACK, T_AST_CALLSTACK );
	}

	if (kperf_signpost_action && (IS_MACH_SIGNPOST(debugid)
	    || IS_APPS_SIGNPOST(debugid)))
	{
#if NOTYET
		/* make sure we're not being called recursively.  */
		if(kperf_kdbg_recurse(KPERF_RECURSE_IN)) {
			return;
		}
#endif

		/* setup a context */
		struct kperf_context ctx;
		struct kperf_sample *intbuf = NULL;
		BUF_INFO2(PERF_SIGNPOST_HNDLR | DBG_FUNC_START, debugid, cur_pid);

		ctx.cur_thread = thread;
		ctx.cur_pid = cur_pid;
		ctx.trigger_type = TRIGGER_TYPE_TRACE;
		ctx.trigger_id = 0;

		/* CPU sample buffer -- only valid with interrupts off (above)
		* Technically this isn't true -- tracepoints can, and often
		* are, cut from interrupt handlers, but none of those tracepoints
		* should make it this far.
		*/
		intbuf = kperf_intr_sample_buffer();

		/* do the sample */
		kperf_sample(intbuf, &ctx, kperf_signpost_action,
		             SAMPLE_FLAG_PEND_USER);

		BUF_INFO2(PERF_SIGNPOST_HNDLR | DBG_FUNC_END, debugid, cur_pid);
#if NOTYET
		/* no longer recursive */
		kperf_kdbg_recurse(KPERF_RECURSE_OUT);
#endif
	}
}

static void
kperf_kdbg_callback_update(void)
{
	unsigned old_callback_set = kperf_kdbg_callback_set;

	/* compute new callback state */
	kperf_kdbg_callback_set = kdebug_callstacks || kperf_signpost_action;

	if (old_callback_set && !kperf_kdbg_callback_set) {
		/* callback should no longer be set */
		chudxnu_kdebug_callback_cancel();
	} else if (!old_callback_set && kperf_kdbg_callback_set) {
		/* callback must now be set */
		chudxnu_kdebug_callback_enter(NULL);
	}
}

int
kperf_kdbg_get_stacks(void)
{
	return kdebug_callstacks;
}

int
kperf_kdbg_set_stacks(int newval)
{
	kdebug_callstacks = newval;
	kperf_kdbg_callback_update();

	return 0;
}

int
kperf_signpost_action_get(void)
{
	return kperf_signpost_action;
}

int
kperf_signpost_action_set(int newval)
{
	kperf_signpost_action = newval;
	kperf_kdbg_callback_update();

	return 0;
}

/*
 * Thread switch
 */

/* called from context switch handler */
void
kperf_switch_context(__unused thread_t old, thread_t new)
{
	task_t task = get_threadtask(new);
	int pid = chudxnu_pid_for_task(task);

	/* cut a tracepoint to tell us what the new thread's PID is
	 * for Instruments
	 */
	BUF_DATA2(PERF_TI_CSWITCH, thread_tid(new), pid);

	/* trigger action after counters have been updated */
	if (kperf_cswitch_action) {
		struct kperf_sample sbuf;
		struct kperf_context ctx;
		int r;

		BUF_DATA1(PERF_CSWITCH_HNDLR | DBG_FUNC_START, 0);

		ctx.cur_pid = 0;
		ctx.cur_thread = old;

		/* get PID for context */
		task_t old_task = chudxnu_task_for_thread(ctx.cur_thread);
		if (old_task) {
			ctx.cur_pid = chudxnu_pid_for_task(old_task);
		}

		ctx.trigger_type = TRIGGER_TYPE_CSWITCH;
		ctx.trigger_id = 0;

		r = kperf_sample(&sbuf, &ctx, kperf_cswitch_action,
			             SAMPLE_FLAG_PEND_USER);

		BUF_INFO1(PERF_CSWITCH_HNDLR | DBG_FUNC_END, r);
	}
}

static void
kperf_cswitch_callback_update(void)
{
	unsigned old_callback_set = kperf_cswitch_callback_set;

	unsigned new_callback_set = kdebug_cswitch || kperf_cswitch_action;

	if (old_callback_set && !new_callback_set) {
		kperf_cswitch_callback_set = 0;
	} else if (!old_callback_set && new_callback_set) {
		kperf_cswitch_callback_set = 1;
	} else {
		return;
	}

	kperf_kpc_cswitch_callback_update();
}

int
kperf_kdbg_cswitch_get(void)
{
	return kdebug_cswitch;
}

int
kperf_kdbg_cswitch_set(int newval)
{
	kdebug_cswitch = newval;
	kperf_cswitch_callback_update();

	return 0;
}

int
kperf_cswitch_action_get(void)
{
	return kperf_cswitch_action;
}

int
kperf_cswitch_action_set(int newval)
{
	kperf_cswitch_action = newval;
	kperf_cswitch_callback_update();

	return 0;
}

/*
 * Action configuration
 */
unsigned
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

int
kperf_action_set_count(unsigned count)
{
	struct action *new_actionv = NULL, *old_actionv = NULL;
	unsigned old_count, i;

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
		r = kperf_init();

		if (r != 0) {
			return r;
		}
	}

	/* create a new array */
	new_actionv = kalloc(count * sizeof(*new_actionv));
	if (new_actionv == NULL) {
		return ENOMEM;
	}

	old_actionv = actionv;
	old_count = actionc;

	if (old_actionv != NULL) {
		memcpy(new_actionv, actionv, actionc * sizeof(*actionv));
	}

	memset(&(new_actionv[actionc]), 0, (count - old_count) * sizeof(*actionv));

	for (i = old_count; i < count; i++) {
		new_actionv[i].pid_filter = -1;
	}

	actionv = new_actionv;
	actionc = count;

	if (old_actionv != NULL) {
		kfree(old_actionv, old_count * sizeof(*actionv));
	}

	return 0;
}
