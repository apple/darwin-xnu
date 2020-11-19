/*
 * Copyright (c) 1993-1995, 1999-2008 Apple Inc. All rights reserved.
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
 * The timer_call system is responsible for manipulating timers that call
 * callbacks at a given deadline (with or without some leeway for coalescing).
 *
 * Call timer_call_setup once on a timer_call structure to register the callback
 * function and a context parameter that's passed to it (param0).
 *
 * To arm the timer to fire at a deadline, call any of the timer_call_enter
 * functions.  If the function used accepts a parameter, it will be passed to
 * the callback function when it fires.
 *
 * If the timer needs to be cancelled (like if the timer_call has been armed but
 * now needs to be deallocated), call timer_call_cancel.
 */

#ifndef _KERN_TIMER_CALL_H_
#define _KERN_TIMER_CALL_H_

#include <mach/mach_types.h>
#include <kern/kern_types.h>

#ifdef XNU_KERNEL_PRIVATE

#include <kern/simple_lock.h>

#ifdef MACH_KERNEL_PRIVATE
#include <kern/queue.h>
#include <kern/priority_queue.h>
#include <kern/mpqueue.h>

extern boolean_t mach_timer_coalescing_enabled;
extern void timer_call_queue_init(mpqueue_head_t *);
#endif /* MACH_KERNEL_PRIVATE */

#if XNU_TARGET_OS_OSX
#define TIMER_TRACE     1
#endif

typedef void            *timer_call_param_t;
typedef void            (*timer_call_func_t)(
	timer_call_param_t      param0,
	timer_call_param_t      param1);

typedef struct timer_call {
	uint64_t                                tc_soft_deadline;
	decl_simple_lock_data(, tc_lock);          /* protects tc_queue */
	struct priority_queue_entry_deadline    tc_pqlink;
	queue_head_t                            *tc_queue;
	queue_chain_t                           tc_qlink;
	timer_call_func_t                       tc_func;
	timer_call_param_t                      tc_param0;
	timer_call_param_t                      tc_param1;
	uint64_t                                tc_ttd; /* Time to deadline at creation */
#if TIMER_TRACE
	uint64_t                                tc_entry_time;
#endif
	uint32_t                                tc_flags;
	/* this field is locked by the lock in the object tc_queue points at */
	bool                                    tc_async_dequeue;
} timer_call_data_t, *timer_call_t;

#define EndOfAllTime            0xFFFFFFFFFFFFFFFFULL


/*
 * Flags to alter the default timer/timeout coalescing behavior
 * on a per-timer_call basis.
 *
 * The SYS urgency classes indicate that the timer_call is not
 * directly related to the current thread at the time the timer_call
 * is entered, so it is ignored in the calculation entirely (only
 * the subclass specified is used).
 *
 * The USER flags indicate that both the current thread scheduling and QoS
 * attributes, in addition to the per-timer_call urgency specification,
 * are used to establish coalescing behavior.
 */
#define TIMER_CALL_SYS_NORMAL           TIMEOUT_URGENCY_SYS_NORMAL
#define TIMER_CALL_SYS_CRITICAL         TIMEOUT_URGENCY_SYS_CRITICAL
#define TIMER_CALL_SYS_BACKGROUND       TIMEOUT_URGENCY_SYS_BACKGROUND

#define TIMER_CALL_USER_MASK            TIMEOUT_URGENCY_USER_MASK
#define TIMER_CALL_USER_NORMAL          TIMEOUT_URGENCY_USER_NORMAL
#define TIMER_CALL_USER_CRITICAL        TIMEOUT_URGENCY_USER_CRITICAL
#define TIMER_CALL_USER_BACKGROUND      TIMEOUT_URGENCY_USER_BACKGROUND

#define TIMER_CALL_URGENCY_MASK         TIMEOUT_URGENCY_MASK

/*
 * Indicate that a specific leeway value is being provided (otherwise
 * the leeway parameter is ignored).  This supplied value can currently
 * only be used to extend the leeway calculated internally from the
 * urgency class provided.
 */
#define TIMER_CALL_LEEWAY               TIMEOUT_URGENCY_LEEWAY

/*
 * Non-migratable timer_call
 */
#define TIMER_CALL_LOCAL                TIMEOUT_URGENCY_FIRST_AVAIL
#define TIMER_CALL_RATELIMITED          TIMEOUT_URGENCY_RATELIMITED
extern boolean_t        timer_call_enter(
	timer_call_t    call,
	uint64_t        deadline,
	uint32_t        flags);

extern boolean_t        timer_call_enter1(
	timer_call_t            call,
	timer_call_param_t      param1,
	uint64_t                deadline,
	uint32_t                flags);

extern boolean_t        timer_call_enter_with_leeway(
	timer_call_t            call,
	timer_call_param_t      param1,
	uint64_t                deadline,
	uint64_t                leeway,
	uint32_t                flags,
	boolean_t               ratelimited);

extern boolean_t        timer_call_cancel(
	timer_call_t    call);

extern void             timer_call_setup(
	timer_call_t            call,
	timer_call_func_t       func,
	timer_call_param_t      param0);

extern int timer_get_user_idle_level(void);
extern kern_return_t timer_set_user_idle_level(int ilevel);

#define NUM_LATENCY_QOS_TIERS (6)
typedef struct {
	uint32_t powergate_latency_abstime;

	uint32_t idle_entry_timer_processing_hdeadline_threshold_abstime;
	uint32_t interrupt_timer_coalescing_ilat_threshold_abstime;
	uint32_t timer_resort_threshold_abstime;

	int32_t timer_coalesce_rt_shift;
	int32_t timer_coalesce_bg_shift;
	int32_t timer_coalesce_kt_shift;
	int32_t timer_coalesce_fp_shift;
	int32_t timer_coalesce_ts_shift;

	uint64_t timer_coalesce_rt_abstime_max;
	uint64_t timer_coalesce_bg_abstime_max;
	uint64_t timer_coalesce_kt_abstime_max;
	uint64_t timer_coalesce_fp_abstime_max;
	uint64_t timer_coalesce_ts_abstime_max;

	uint32_t latency_qos_scale[NUM_LATENCY_QOS_TIERS];
	uint64_t latency_qos_abstime_max[NUM_LATENCY_QOS_TIERS];
	boolean_t latency_tier_rate_limited[NUM_LATENCY_QOS_TIERS];
} timer_coalescing_priority_params_t;
extern timer_coalescing_priority_params_t tcoal_prio_params;

/*
 * Initialize the timer call subsystem during system startup.
 */
extern void timer_call_init(void);

#if MACH_KERNEL_PRIVATE

/*
 * Handle deadlines in the past.
 */
uint64_t timer_call_past_deadline_timer_handle(uint64_t deadline,
    uint64_t ctime);

/*
 * Running timers are only active for a given CPU when a non-idle thread
 * is running.
 */

enum running_timer {
	RUNNING_TIMER_QUANTUM,
#if KPERF
	RUNNING_TIMER_KPERF,
#endif /* KPERF */
	RUNNING_TIMER_MAX,
};

/*
 * Get the earliest active deadline for this processor.
 */
uint64_t running_timers_deadline(processor_t processor);

/*
 * Run the expire handler to process any timers past their deadline.  Returns
 * true if any timer was processed, and false otherwise.
 */
bool running_timers_expire(processor_t processor, uint64_t now);

/*
 * Set up a new deadline for the given running timer on the processor, but don't
 * synchronize it with the hardware.  A subsequent call to running_timers_sync
 * is necessary.  This allows thread_dispatch to batch all of the setup and only
 * set the decrementer once.
 */
void running_timer_setup(processor_t processor, enum running_timer timer,
    void *param, uint64_t deadline, uint64_t now);

/*
 * Synchronize the state of any running timers that have been set up with the
 * hardware.
 */
void running_timers_sync(void);

/*
 * Enter a new deadline for the given running timer on the processor and put it
 * into effect.
 */
void running_timer_enter(processor_t processor, enum running_timer timer,
    void *param, uint64_t deadline, uint64_t now);

/*
 * Clear the deadline and parameters for the given running timer on the
 * processor.
 */
void running_timer_clear(processor_t processor, enum running_timer timer);

/*
 * Cancel a running timer on the processor.
 */
void running_timer_cancel(processor_t processor, enum running_timer timer);

/*
 * Activate the running timers for the given, current processor.  Should only be
 * called by thread_dispatch.
 */
void running_timers_activate(processor_t processor);

/*
 * Deactivate the running timers for the given, current processor.  Should only
 * be called by thread_dispatch.
 */
void running_timers_deactivate(processor_t processor);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* XNU_KERNEL_PRIVATE */

#endif /* _KERN_TIMER_CALL_H_ */
