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

#ifndef KPERF_H
#define KPERF_H

#include <kern/thread.h>
#include <kern/locks.h>

extern lck_grp_t kperf_lck_grp;

/* the trigger types supported by kperf */
#define TRIGGER_TYPE_TIMER  (0)
#define TRIGGER_TYPE_PMI    (1)
#define TRIGGER_TYPE_KDEBUG (2)

/* helpers to get and set AST flags on a thread */
uint32_t kperf_get_thread_flags(thread_t thread);
void kperf_set_thread_flags(thread_t thread, uint32_t flags);

/*
 * Get and set dirtiness of thread, so kperf can track whether the thread
 * has been dispatched since it last looked.
 */
boolean_t kperf_thread_get_dirty(thread_t thread);
void kperf_thread_set_dirty(thread_t thread, boolean_t dirty);

/* possible states of kperf sampling */
#define KPERF_SAMPLING_OFF      (0)
#define KPERF_SAMPLING_ON       (1)
#define KPERF_SAMPLING_SHUTDOWN (2)

/*
 * Initialize kperf.  Must be called before use and can be called multiple times.
 */
extern int kperf_init(void);

/* get and set sampling status */
extern unsigned kperf_sampling_status(void);
extern int kperf_sampling_enable(void);
extern int kperf_sampling_disable(void);

/* get a per-CPU sample buffer */
struct kperf_sample *kperf_intr_sample_buffer(void);

/*
 * kperf AST handler
 */
extern __attribute__((noinline)) void kperf_thread_ast_handler(thread_t thread);

/*
 * thread on core callback
 */

/* controls whether the callback is called on context switch */
extern boolean_t kperf_on_cpu_active;

/* update whether the callback is set */
void kperf_on_cpu_update(void);

/* handle a thread being switched on */
void kperf_on_cpu_internal(thread_t thread, thread_continue_t continuation,
                           uintptr_t *starting_fp);

/* for scheduler threads switching threads on */
static inline void
kperf_on_cpu(thread_t thread, thread_continue_t continuation,
             uintptr_t *starting_fp)
{
	if (__improbable(kperf_on_cpu_active)) {
		kperf_on_cpu_internal(thread, continuation, starting_fp);
	}
}

/*
 * kdebug callback
 */

/* controls whether the kdebug callback is called */
extern boolean_t kperf_kdebug_active;

/* handle the kdebug event */
void kperf_kdebug_callback_internal(uint32_t debugid);

/* handle a kdebug event */
void kperf_kdebug_handler(uint32_t debugid, uintptr_t *starting_fp);

/* called inside of kernel_debug_internal */
static inline void
kperf_kdebug_callback(uint32_t debugid, uintptr_t *starting_fp)
{
	if (__improbable(kperf_kdebug_active)) {
		kperf_kdebug_handler(debugid, starting_fp);
	}
}

/*
 * Used by ktrace to reset kperf.  ktrace_lock must be held.
 */
extern void kperf_reset(void);

/* get and set whether we're recording stacks on interesting kdebug events */
extern int kperf_kdbg_get_stacks(void);
extern int kperf_kdbg_set_stacks(int);

extern int kperf_kdebug_cswitch;

#if DEVELOPMENT || DEBUG
extern _Atomic long long kperf_pending_ipis;
#endif /* DEVELOPMENT || DEBUG */

/* get and set whether to output tracepoints on context-switch */
extern int kperf_kdbg_cswitch_get(void);
extern int kperf_kdbg_cswitch_set(int newval);

/* given a task port, find out its pid */
int kperf_port_to_pid(mach_port_name_t portname);

#endif /* !defined(KPERF_H) */
