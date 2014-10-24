/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	sched_prim.c
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1986
 *
 *	Scheduling primitives
 *
 */

#include <debug.h>

#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/policy.h>
#include <mach/sync_policy.h>
#include <mach/thread_act.h>

#include <machine/machine_routines.h>
#include <machine/sched_param.h>
#include <machine/machine_cpu.h>
#include <machine/machlimits.h>

#ifdef CONFIG_MACH_APPROXIMATE_TIME
#include <machine/commpage.h>
#endif

#include <kern/kern_types.h>
#include <kern/clock.h>
#include <kern/counters.h>
#include <kern/cpu_number.h>
#include <kern/cpu_data.h>
#include <kern/debug.h>
#include <kern/macro_help.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/sfi.h>
#include <kern/syscall_subr.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/wait_queue.h>
#include <kern/ledger.h>
#include <kern/timer_queue.h>

#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>

#include <mach/sdt.h>

#include <sys/kdebug.h>

#include <kern/pms.h>

#if defined(CONFIG_TELEMETRY) && defined(CONFIG_SCHED_TIMESHARE_CORE)
#include <kern/telemetry.h>
#endif

struct rt_queue	rt_runq;
#define RT_RUNQ		((processor_t)-1)
decl_simple_lock_data(static,rt_lock);

#if defined(CONFIG_SCHED_FAIRSHARE_CORE)
static struct fairshare_queue	fs_runq;
#define FS_RUNQ		((processor_t)-2)
decl_simple_lock_data(static,fs_lock);
#endif /* CONFIG_SCHED_FAIRSHARE_CORE */

#define		DEFAULT_PREEMPTION_RATE		100		/* (1/s) */
int			default_preemption_rate = DEFAULT_PREEMPTION_RATE;

#define		DEFAULT_BG_PREEMPTION_RATE	400		/* (1/s) */
int			default_bg_preemption_rate = DEFAULT_BG_PREEMPTION_RATE;

#define		MAX_UNSAFE_QUANTA			800
int			max_unsafe_quanta = MAX_UNSAFE_QUANTA;

#define		MAX_POLL_QUANTA				2
int			max_poll_quanta = MAX_POLL_QUANTA;

#define		SCHED_POLL_YIELD_SHIFT		4		/* 1/16 */
int			sched_poll_yield_shift = SCHED_POLL_YIELD_SHIFT;

uint64_t	max_poll_computation;

uint64_t	max_unsafe_computation;
uint64_t	sched_safe_duration;

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

uint32_t	std_quantum;
uint32_t	min_std_quantum;
uint32_t	bg_quantum;

uint32_t	std_quantum_us;
uint32_t	bg_quantum_us;

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

uint32_t	thread_depress_time;
uint32_t	default_timeshare_computation;
uint32_t	default_timeshare_constraint;

uint32_t	max_rt_quantum;
uint32_t	min_rt_quantum;

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

unsigned	sched_tick;
uint32_t	sched_tick_interval;
#if defined(CONFIG_TELEMETRY)
uint32_t	sched_telemetry_interval;
#endif /* CONFIG_TELEMETRY */

uint32_t	sched_pri_shift = INT8_MAX;
uint32_t	sched_background_pri_shift = INT8_MAX;
uint32_t	sched_combined_fgbg_pri_shift = INT8_MAX;
uint32_t	sched_fixed_shift;
uint32_t	sched_use_combined_fgbg_decay = 0;

uint32_t	sched_decay_usage_age_factor = 1; /* accelerate 5/8^n usage aging */

/* Allow foreground to decay past default to resolve inversions */
#define DEFAULT_DECAY_BAND_LIMIT ((BASEPRI_FOREGROUND - BASEPRI_DEFAULT) + 2)
int 		sched_pri_decay_band_limit = DEFAULT_DECAY_BAND_LIMIT;

/* Defaults for timer deadline profiling */
#define TIMER_DEADLINE_TRACKING_BIN_1_DEFAULT 2000000 /* Timers with deadlines <=
							* 2ms */
#define TIMER_DEADLINE_TRACKING_BIN_2_DEFAULT 5000000 /* Timers with deadlines
							  <= 5ms */

uint64_t timer_deadline_tracking_bin_1;
uint64_t timer_deadline_tracking_bin_2;

thread_t sched_maintenance_thread;

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

#if defined(CONFIG_SCHED_TRADITIONAL)

static boolean_t sched_traditional_use_pset_runqueue = FALSE;

__attribute__((always_inline))
static inline run_queue_t runq_for_processor(processor_t processor)
{
	if (sched_traditional_use_pset_runqueue)
		return &processor->processor_set->pset_runq;
	else
		return &processor->runq;
}

__attribute__((always_inline))
static inline void runq_consider_incr_bound_count(processor_t processor, thread_t thread)
{
	if (thread->bound_processor == PROCESSOR_NULL)
		return;
    
	assert(thread->bound_processor == processor);
    
	if (sched_traditional_use_pset_runqueue)
		processor->processor_set->pset_runq_bound_count++;
    
	processor->runq_bound_count++;
}

__attribute__((always_inline))
static inline void runq_consider_decr_bound_count(processor_t processor, thread_t thread)
{
	if (thread->bound_processor == PROCESSOR_NULL)
		return;
    
	assert(thread->bound_processor == processor);
    
	if (sched_traditional_use_pset_runqueue)
		processor->processor_set->pset_runq_bound_count--;
    
	processor->runq_bound_count--;
}

#endif /* CONFIG_SCHED_TRADITIONAL */

uint64_t	sched_one_second_interval;

uint32_t	sched_run_count, sched_share_count, sched_background_count;
uint32_t	sched_load_average, sched_mach_factor;

/* Forwards */

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

static void load_shift_init(void);
static void preempt_pri_init(void);

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

static thread_t	thread_select(
					thread_t			thread,
					processor_t			processor,
					ast_t				reason);

#if CONFIG_SCHED_IDLE_IN_PLACE
static thread_t	thread_select_idle(
					thread_t			thread,
					processor_t			processor);
#endif

thread_t	processor_idle(
					thread_t			thread,
					processor_t			processor);

ast_t
csw_check_locked(	processor_t		processor,
					processor_set_t	pset,
					ast_t			check_reason);

#if defined(CONFIG_SCHED_TRADITIONAL)

static thread_t	steal_thread(
					processor_set_t		pset);

static thread_t	steal_thread_disabled(
					processor_set_t		pset) __attribute__((unused));


static thread_t	steal_processor_thread(
					processor_t			processor);

static void		thread_update_scan(void);

static void processor_setrun(
				 processor_t			processor,
				 thread_t			thread,
				 integer_t			options);

static boolean_t
processor_enqueue(
				  processor_t		processor,
				  thread_t		thread,
				  integer_t		options);

static boolean_t
processor_queue_remove(
					   processor_t			processor,
					   thread_t		thread);

static boolean_t	processor_queue_empty(processor_t		processor);

static ast_t		processor_csw_check(processor_t processor);

static boolean_t	processor_queue_has_priority(processor_t		processor,
											int				priority,
											boolean_t		gte);

static boolean_t	should_current_thread_rechoose_processor(processor_t			processor);

static int     sched_traditional_processor_runq_count(processor_t   processor);

static boolean_t	sched_traditional_with_pset_runqueue_processor_queue_empty(processor_t		processor);

static uint64_t     sched_traditional_processor_runq_stats_count_sum(processor_t   processor);

static uint64_t		sched_traditional_with_pset_runqueue_processor_runq_stats_count_sum(processor_t   processor);

static int      sched_traditional_processor_bound_count(processor_t processor);

#endif


#if defined(CONFIG_SCHED_TRADITIONAL)

static void
sched_traditional_processor_init(processor_t processor);

static void
sched_traditional_pset_init(processor_set_t pset);

static void
sched_traditional_with_pset_runqueue_init(void);

#endif

static void
sched_realtime_init(void);

static void
sched_realtime_timebase_init(void);

static void
sched_timer_deadline_tracking_init(void);

#if defined(CONFIG_SCHED_TRADITIONAL)

static sched_mode_t
sched_traditional_initial_thread_sched_mode(task_t parent_task);

static thread_t
sched_traditional_choose_thread(
                                processor_t     processor,
                                int             priority,
                       __unused ast_t           reason);

#endif

#if	DEBUG
extern int debug_task;
#define TLOG(a, fmt, args...) if(debug_task & a) kprintf(fmt, ## args)
#else
#define TLOG(a, fmt, args...) do {} while (0)
#endif

__assert_only static
boolean_t	thread_runnable(
				thread_t		thread);

/*
 *	State machine
 *
 * states are combinations of:
 *  R	running
 *  W	waiting (or on wait queue)
 *  N	non-interruptible
 *  O	swapped out
 *  I	being swapped in
 *
 * init	action 
 *	assert_wait thread_block    clear_wait 		swapout	swapin
 *
 * R	RW, RWN	    R;   setrun	    -	       		-
 * RN	RWN	    RN;  setrun	    -	       		-
 *
 * RW		    W		    R	       		-
 * RWN		    WN		    RN	       		-
 *
 * W				    R;   setrun		WO
 * WN				    RN;  setrun		-
 *
 * RO				    -			-	R
 *
 */

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
int8_t		sched_load_shifts[NRQS];
int		sched_preempt_pri[NRQBM];
#endif /* CONFIG_SCHED_TIMESHARE_CORE */


#if defined(CONFIG_SCHED_TRADITIONAL)

const struct sched_dispatch_table sched_traditional_dispatch = {
	.init                                           = sched_traditional_init,
	.timebase_init                                  = sched_traditional_timebase_init,
	.processor_init                                 = sched_traditional_processor_init,
	.pset_init                                      = sched_traditional_pset_init,
	.maintenance_continuation                       = sched_traditional_maintenance_continue,
	.choose_thread                                  = sched_traditional_choose_thread,
	.steal_thread                                   = steal_thread,
	.compute_priority                               = compute_priority,
	.choose_processor                               = choose_processor,
	.processor_enqueue                              = processor_enqueue,
	.processor_queue_shutdown                       = processor_queue_shutdown,
	.processor_queue_remove                         = processor_queue_remove,
	.processor_queue_empty                          = processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = processor_csw_check,
	.processor_queue_has_priority                   = processor_queue_has_priority,
	.initial_quantum_size                           = sched_traditional_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_traditional_initial_thread_sched_mode,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_traditional_quantum_expire,
	.should_current_thread_rechoose_processor       = should_current_thread_rechoose_processor,
	.processor_runq_count                           = sched_traditional_processor_runq_count,
	.processor_runq_stats_count_sum                 = sched_traditional_processor_runq_stats_count_sum,
	.fairshare_init                                 = sched_traditional_fairshare_init,
	.fairshare_runq_count                           = sched_traditional_fairshare_runq_count,
	.fairshare_runq_stats_count_sum                 = sched_traditional_fairshare_runq_stats_count_sum,
	.fairshare_enqueue                              = sched_traditional_fairshare_enqueue,
	.fairshare_dequeue                              = sched_traditional_fairshare_dequeue,
	.fairshare_queue_remove                         = sched_traditional_fairshare_queue_remove,
	.processor_bound_count                          = sched_traditional_processor_bound_count,
	.thread_update_scan                             = thread_update_scan,
	.direct_dispatch_to_idle_processors             = TRUE,
};

const struct sched_dispatch_table sched_traditional_with_pset_runqueue_dispatch = {
	.init                                           = sched_traditional_with_pset_runqueue_init,
	.timebase_init                                  = sched_traditional_timebase_init,
	.processor_init                                 = sched_traditional_processor_init,
	.pset_init                                      = sched_traditional_pset_init,
	.maintenance_continuation                       = sched_traditional_maintenance_continue,
	.choose_thread                                  = sched_traditional_choose_thread,
	.steal_thread                                   = steal_thread,
	.compute_priority                               = compute_priority,
	.choose_processor                               = choose_processor,
	.processor_enqueue                              = processor_enqueue,
	.processor_queue_shutdown                       = processor_queue_shutdown,
	.processor_queue_remove                         = processor_queue_remove,
	.processor_queue_empty                          = sched_traditional_with_pset_runqueue_processor_queue_empty,
	.priority_is_urgent                             = priority_is_urgent,
	.processor_csw_check                            = processor_csw_check,
	.processor_queue_has_priority                   = processor_queue_has_priority,
	.initial_quantum_size                           = sched_traditional_initial_quantum_size,
	.initial_thread_sched_mode                      = sched_traditional_initial_thread_sched_mode,
	.can_update_priority                            = can_update_priority,
	.update_priority                                = update_priority,
	.lightweight_update_priority                    = lightweight_update_priority,
	.quantum_expire                                 = sched_traditional_quantum_expire,
	.should_current_thread_rechoose_processor       = should_current_thread_rechoose_processor,
	.processor_runq_count                           = sched_traditional_processor_runq_count,
	.processor_runq_stats_count_sum                 = sched_traditional_with_pset_runqueue_processor_runq_stats_count_sum,
	.fairshare_init                                 = sched_traditional_fairshare_init,
	.fairshare_runq_count                           = sched_traditional_fairshare_runq_count,
	.fairshare_runq_stats_count_sum                 = sched_traditional_fairshare_runq_stats_count_sum,
	.fairshare_enqueue                              = sched_traditional_fairshare_enqueue,
	.fairshare_dequeue                              = sched_traditional_fairshare_dequeue,
	.fairshare_queue_remove                         = sched_traditional_fairshare_queue_remove,
	.processor_bound_count                          = sched_traditional_processor_bound_count,
	.thread_update_scan                             = thread_update_scan,
	.direct_dispatch_to_idle_processors             = FALSE,
};

#endif

const struct sched_dispatch_table *sched_current_dispatch = NULL;

/*
 * Statically allocate a buffer to hold the longest possible
 * scheduler description string, as currently implemented.
 * bsd/kern/kern_sysctl.c has a corresponding definition in bsd/
 * to export to userspace via sysctl(3). If either version
 * changes, update the other.
 *
 * Note that in addition to being an upper bound on the strings
 * in the kernel, it's also an exact parameter to PE_get_default(),
 * which interrogates the device tree on some platforms. That
 * API requires the caller know the exact size of the device tree
 * property, so we need both a legacy size (32) and the current size
 * (48) to deal with old and new device trees. The device tree property
 * is similarly padded to a fixed size so that the same kernel image
 * can run on multiple devices with different schedulers configured
 * in the device tree.
 */
#define SCHED_STRING_MAX_LENGTH (48)

char sched_string[SCHED_STRING_MAX_LENGTH];
static enum sched_enum _sched_enum __attribute__((used)) = sched_enum_unknown;

/* Global flag which indicates whether Background Stepper Context is enabled */
static int cpu_throttle_enabled = 1;

void
sched_init(void)
{
	char sched_arg[SCHED_STRING_MAX_LENGTH] = { '\0' };

	/* Check for runtime selection of the scheduler algorithm */
	if (!PE_parse_boot_argn("sched", sched_arg, sizeof (sched_arg))) {
		/* If no boot-args override, look in device tree */
		if (!PE_get_default("kern.sched", sched_arg,
							SCHED_STRING_MAX_LENGTH)) {
			sched_arg[0] = '\0';
		}
	}

	
	if (!PE_parse_boot_argn("sched_pri_decay_limit", &sched_pri_decay_band_limit, sizeof(sched_pri_decay_band_limit))) {
		/* No boot-args, check in device tree */
		if (!PE_get_default("kern.sched_pri_decay_limit",
							&sched_pri_decay_band_limit,
							sizeof(sched_pri_decay_band_limit))) {
			/* Allow decay all the way to normal limits */
			sched_pri_decay_band_limit = DEFAULT_DECAY_BAND_LIMIT;
		}
	}

	kprintf("Setting scheduler priority decay band limit %d\n", sched_pri_decay_band_limit);

	if (strlen(sched_arg) > 0) {
		if (0) {
			/* Allow pattern below */
#if defined(CONFIG_SCHED_TRADITIONAL)
		} else if (0 == strcmp(sched_arg, kSchedTraditionalString)) {
			sched_current_dispatch = &sched_traditional_dispatch;
			_sched_enum = sched_enum_traditional;
			strlcpy(sched_string, kSchedTraditionalString, sizeof(sched_string));
		} else if (0 == strcmp(sched_arg, kSchedTraditionalWithPsetRunqueueString)) {
			sched_current_dispatch = &sched_traditional_with_pset_runqueue_dispatch;
			_sched_enum = sched_enum_traditional_with_pset_runqueue;
			strlcpy(sched_string, kSchedTraditionalWithPsetRunqueueString, sizeof(sched_string));
#endif
#if defined(CONFIG_SCHED_PROTO)
		} else if (0 == strcmp(sched_arg, kSchedProtoString)) {
			sched_current_dispatch = &sched_proto_dispatch;
			_sched_enum = sched_enum_proto;
			strlcpy(sched_string, kSchedProtoString, sizeof(sched_string));
#endif
#if defined(CONFIG_SCHED_GRRR)
		} else if (0 == strcmp(sched_arg, kSchedGRRRString)) {
			sched_current_dispatch = &sched_grrr_dispatch;
			_sched_enum = sched_enum_grrr;
			strlcpy(sched_string, kSchedGRRRString, sizeof(sched_string));
#endif
#if defined(CONFIG_SCHED_MULTIQ)
		} else if (0 == strcmp(sched_arg, kSchedMultiQString)) {
			sched_current_dispatch = &sched_multiq_dispatch;
			_sched_enum = sched_enum_multiq;
			strlcpy(sched_string, kSchedMultiQString, sizeof(sched_string));
		} else if (0 == strcmp(sched_arg, kSchedDualQString)) {
			sched_current_dispatch = &sched_dualq_dispatch;
			_sched_enum = sched_enum_dualq;
			strlcpy(sched_string, kSchedDualQString, sizeof(sched_string));
#endif
		} else {
#if defined(CONFIG_SCHED_TRADITIONAL)
			printf("Unrecognized scheduler algorithm: %s\n", sched_arg);
			printf("Scheduler: Using instead: %s\n", kSchedTraditionalWithPsetRunqueueString);

			sched_current_dispatch = &sched_traditional_with_pset_runqueue_dispatch;
			_sched_enum = sched_enum_traditional_with_pset_runqueue;
			strlcpy(sched_string, kSchedTraditionalWithPsetRunqueueString, sizeof(sched_string));
#else
			panic("Unrecognized scheduler algorithm: %s", sched_arg);
#endif
		}
		kprintf("Scheduler: Runtime selection of %s\n", sched_string);
	} else {
#if   defined(CONFIG_SCHED_MULTIQ)
		sched_current_dispatch = &sched_multiq_dispatch;
		_sched_enum = sched_enum_multiq;
		strlcpy(sched_string, kSchedMultiQString, sizeof(sched_string));
#elif defined(CONFIG_SCHED_TRADITIONAL)
		sched_current_dispatch = &sched_traditional_with_pset_runqueue_dispatch;
		_sched_enum = sched_enum_traditional_with_pset_runqueue;
		strlcpy(sched_string, kSchedTraditionalWithPsetRunqueueString, sizeof(sched_string));
#elif defined(CONFIG_SCHED_PROTO)
		sched_current_dispatch = &sched_proto_dispatch;
		_sched_enum = sched_enum_proto;
		strlcpy(sched_string, kSchedProtoString, sizeof(sched_string));
#elif defined(CONFIG_SCHED_GRRR)
		sched_current_dispatch = &sched_grrr_dispatch;
		_sched_enum = sched_enum_grrr;
		strlcpy(sched_string, kSchedGRRRString, sizeof(sched_string));
#else
#error No default scheduler implementation
#endif
		kprintf("Scheduler: Default of %s\n", sched_string);
	}
	
	SCHED(init)();
	SCHED(fairshare_init)();
	sched_realtime_init();
	ast_init();
	sched_timer_deadline_tracking_init();

	SCHED(pset_init)(&pset0);
	SCHED(processor_init)(master_processor);
}

void
sched_timebase_init(void)
{
	uint64_t	abstime;
	
	clock_interval_to_absolutetime_interval(1, NSEC_PER_SEC, &abstime);
	sched_one_second_interval = abstime;
	
	SCHED(timebase_init)();
	sched_realtime_timebase_init();
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

void
sched_traditional_init(void)
{
	/*
	 * Calculate the timeslicing quantum
	 * in us.
	 */
	if (default_preemption_rate < 1)
		default_preemption_rate = DEFAULT_PREEMPTION_RATE;
	std_quantum_us = (1000 * 1000) / default_preemption_rate;

	printf("standard timeslicing quantum is %d us\n", std_quantum_us);

	if (default_bg_preemption_rate < 1)
		default_bg_preemption_rate = DEFAULT_BG_PREEMPTION_RATE;
	bg_quantum_us = (1000 * 1000) / default_bg_preemption_rate;

	printf("standard background quantum is %d us\n", bg_quantum_us);

	load_shift_init();
	preempt_pri_init();
	sched_tick = 0;
}

void
sched_traditional_timebase_init(void)
{
	uint64_t	abstime;
	uint32_t	shift;

	/* standard timeslicing quantum */
	clock_interval_to_absolutetime_interval(
							std_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	std_quantum = (uint32_t)abstime;

	/* smallest remaining quantum (250 us) */
	clock_interval_to_absolutetime_interval(250, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_std_quantum = (uint32_t)abstime;

	/* quantum for background tasks */
	clock_interval_to_absolutetime_interval(
							bg_quantum_us, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	bg_quantum = (uint32_t)abstime;

	/* scheduler tick interval */
	clock_interval_to_absolutetime_interval(USEC_PER_SEC >> SCHED_TICK_SHIFT,
													NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	sched_tick_interval = (uint32_t)abstime;

	/*
	 * Compute conversion factor from usage to
	 * timesharing priorities with 5/8 ** n aging.
	 */
	abstime = (abstime * 5) / 3;
	for (shift = 0; abstime > BASEPRI_DEFAULT; ++shift)
		abstime >>= 1;
	sched_fixed_shift = shift;

	max_unsafe_computation = ((uint64_t)max_unsafe_quanta) * std_quantum;
	sched_safe_duration = 2 * ((uint64_t)max_unsafe_quanta) * std_quantum;
	
	max_poll_computation = ((uint64_t)max_poll_quanta) * std_quantum;
	thread_depress_time = 1 * std_quantum;
	default_timeshare_computation = std_quantum / 2;
	default_timeshare_constraint = std_quantum;

#if defined(CONFIG_TELEMETRY)
	/* interval for high frequency telemetry */
	clock_interval_to_absolutetime_interval(10, NSEC_PER_MSEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	sched_telemetry_interval = (uint32_t)abstime;
#endif
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */


#if defined(CONFIG_SCHED_TRADITIONAL)

static void
sched_traditional_processor_init(processor_t processor)
{
	if (!sched_traditional_use_pset_runqueue) {
		run_queue_init(&processor->runq);
	}
	processor->runq_bound_count = 0;
}

static void
sched_traditional_pset_init(processor_set_t pset)
{
	if (sched_traditional_use_pset_runqueue) {
		run_queue_init(&pset->pset_runq);
	}
	pset->pset_runq_bound_count = 0;
}

static void
sched_traditional_with_pset_runqueue_init(void)
{
	sched_traditional_init();
	sched_traditional_use_pset_runqueue = TRUE;
}

#endif /* CONFIG_SCHED_TRADITIONAL */

#if defined(CONFIG_SCHED_FAIRSHARE_CORE)
void
sched_traditional_fairshare_init(void)
{
	simple_lock_init(&fs_lock, 0);
	
	fs_runq.count = 0;
	queue_init(&fs_runq.queue);
}
#endif /* CONFIG_SCHED_FAIRSHARE_CORE */

static void
sched_realtime_init(void)
{
	simple_lock_init(&rt_lock, 0);

	rt_runq.count = 0;
	queue_init(&rt_runq.queue);
}

static void
sched_realtime_timebase_init(void)
{
	uint64_t abstime;

	/* smallest rt computaton (50 us) */
	clock_interval_to_absolutetime_interval(50, NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	min_rt_quantum = (uint32_t)abstime;

	/* maximum rt computation (50 ms) */
	clock_interval_to_absolutetime_interval(
		50, 1000*NSEC_PER_USEC, &abstime);
	assert((abstime >> 32) == 0 && (uint32_t)abstime != 0);
	max_rt_quantum = (uint32_t)abstime;

}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

/*
 * Set up values for timeshare
 * loading factors.
 */
static void
load_shift_init(void)
{
	int8_t		k, *p = sched_load_shifts;
	uint32_t	i, j;

	uint32_t	sched_decay_penalty = 1;

	if (PE_parse_boot_argn("sched_decay_penalty", &sched_decay_penalty, sizeof (sched_decay_penalty))) {
		kprintf("Overriding scheduler decay penalty %u\n", sched_decay_penalty);
	}

	if (PE_parse_boot_argn("sched_decay_usage_age_factor", &sched_decay_usage_age_factor, sizeof (sched_decay_usage_age_factor))) {
		kprintf("Overriding scheduler decay usage age factor %u\n", sched_decay_usage_age_factor);
	}

	if (PE_parse_boot_argn("sched_use_combined_fgbg_decay", &sched_use_combined_fgbg_decay, sizeof (sched_use_combined_fgbg_decay))) {
		kprintf("Overriding schedule fg/bg decay calculation: %u\n", sched_use_combined_fgbg_decay);
	}

	if (sched_decay_penalty == 0) {
		/*
		 * There is no penalty for timeshare threads for using too much
		 * CPU, so set all load shifts to INT8_MIN. Even under high load,
		 * sched_pri_shift will be >INT8_MAX, and there will be no
		 * penalty applied to threads (nor will sched_usage be updated per
		 * thread).
		 */
		for (i = 0; i < NRQS; i++) {
			sched_load_shifts[i] = INT8_MIN;
		}

		return;
	}

	*p++ = INT8_MIN; *p++ = 0;

	/*
	 * For a given system load "i", the per-thread priority
	 * penalty per quantum of CPU usage is ~2^k priority
	 * levels. "sched_decay_penalty" can cause more
	 * array entries to be filled with smaller "k" values
	 */
	for (i = 2, j = 1 << sched_decay_penalty, k = 1; i < NRQS; ++k) {
		for (j <<= 1; (i < j) && (i < NRQS); ++i)
			*p++ = k;
	}
}

static void
preempt_pri_init(void)
{
	int		i, *p = sched_preempt_pri;

	for (i = BASEPRI_FOREGROUND; i < MINPRI_KERNEL; ++i)
		setbit(i, p);

	for (i = BASEPRI_PREEMPT; i <= MAXPRI; ++i)
		setbit(i, p);
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

/*
 *	Thread wait timer expiration.
 */
void
thread_timer_expire(
	void			*p0,
	__unused void	*p1)
{
	thread_t		thread = p0;
	spl_t			s;

	s = splsched();
	thread_lock(thread);
	if (--thread->wait_timer_active == 0) {
		if (thread->wait_timer_is_set) {
			thread->wait_timer_is_set = FALSE;
			clear_wait_internal(thread, THREAD_TIMED_OUT);
		}
	}
	thread_unlock(thread);
	splx(s);
}

/*
 *	thread_unblock:
 *
 *	Unblock thread on wake up.
 *
 *	Returns TRUE if the thread is still running.
 *
 *	Thread must be locked.
 */
boolean_t
thread_unblock(
	thread_t		thread,
	wait_result_t	wresult)
{
	boolean_t		result = FALSE;
	thread_t		cthread = current_thread();
	uint32_t		new_run_count;

	/*
	 *	Set wait_result.
	 */
	thread->wait_result = wresult;

	/*
	 *	Cancel pending wait timer.
	 */
	if (thread->wait_timer_is_set) {
		if (timer_call_cancel(&thread->wait_timer))
			thread->wait_timer_active--;
		thread->wait_timer_is_set = FALSE;
	}

	/*
	 *	Update scheduling state: not waiting,
	 *	set running.
	 */
	thread->state &= ~(TH_WAIT|TH_UNINT);

	if (!(thread->state & TH_RUN)) {
		thread->state |= TH_RUN;

		(*thread->sched_call)(SCHED_CALL_UNBLOCK, thread);

		/*
		 *	Update run counts.
		 */
		new_run_count = sched_run_incr(thread);
		if (thread->sched_mode == TH_MODE_TIMESHARE) {
			sched_share_incr(thread);

			if (thread->sched_flags & TH_SFLAG_THROTTLED)
				sched_background_incr(thread);
		}
	}
	else {
		/*
		 *	Signal if idling on another processor.
		 */
#if CONFIG_SCHED_IDLE_IN_PLACE
		if (thread->state & TH_IDLE) {
			processor_t		processor = thread->last_processor;

			if (processor != current_processor())
				machine_signal_idle(processor);
		}
#else
		assert((thread->state & TH_IDLE) == 0);
#endif

		new_run_count = sched_run_count; /* updated in thread_select_idle() */
		result = TRUE;
	}

	/*
	 * Calculate deadline for real-time threads.
	 */
	if (thread->sched_mode == TH_MODE_REALTIME) {
		uint64_t		ctime;

		ctime = mach_absolute_time();
		thread->realtime.deadline = thread->realtime.constraint + ctime;
	}

	/*
	 * Clear old quantum, fail-safe computation, etc.
	 */
	thread->quantum_remaining = 0;
	thread->computation_metered = 0;
	thread->reason = AST_NONE;

	/* Obtain power-relevant interrupt and "platform-idle exit" statistics.
	 * We also account for "double hop" thread signaling via
	 * the thread callout infrastructure.
	 * DRK: consider removing the callout wakeup counters in the future
	 * they're present for verification at the moment.
	 */
	boolean_t aticontext, pidle;
	ml_get_power_state(&aticontext, &pidle);

	if (__improbable(aticontext && !(thread_get_tag_internal(thread) & THREAD_TAG_CALLOUT))) {
		ledger_credit(thread->t_ledger, task_ledgers.interrupt_wakeups, 1);
		DTRACE_SCHED2(iwakeup, struct thread *, thread, struct proc *, thread->task->bsd_info);

		uint64_t ttd = PROCESSOR_DATA(current_processor(), timer_call_ttd);

		if (ttd) {
			if (ttd <= timer_deadline_tracking_bin_1)
				thread->thread_timer_wakeups_bin_1++;
			else
				if (ttd <= timer_deadline_tracking_bin_2)
					thread->thread_timer_wakeups_bin_2++;
		}

		if (pidle) {
			ledger_credit(thread->t_ledger, task_ledgers.platform_idle_wakeups, 1);
		}

	} else if (thread_get_tag_internal(cthread) & THREAD_TAG_CALLOUT) {
		if (cthread->callout_woken_from_icontext) {
			ledger_credit(thread->t_ledger, task_ledgers.interrupt_wakeups, 1);
			thread->thread_callout_interrupt_wakeups++;
			if (cthread->callout_woken_from_platform_idle) {
				ledger_credit(thread->t_ledger, task_ledgers.platform_idle_wakeups, 1);
				thread->thread_callout_platform_idle_wakeups++;
			}
			
			cthread->callout_woke_thread = TRUE;
		}
	}
	
	if (thread_get_tag_internal(thread) & THREAD_TAG_CALLOUT) {
		thread->callout_woken_from_icontext = aticontext;
		thread->callout_woken_from_platform_idle = pidle;
		thread->callout_woke_thread = FALSE;
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_MAKE_RUNNABLE) | DBG_FUNC_NONE,
		(uintptr_t)thread_tid(thread), thread->sched_pri, thread->wait_result, new_run_count, 0);

	DTRACE_SCHED2(wakeup, struct thread *, thread, struct proc *, thread->task->bsd_info);

	return (result);
}

/*
 *	Routine:	thread_go
 *	Purpose:
 *		Unblock and dispatch thread.
 *	Conditions:
 *		thread lock held, IPC locks may be held.
 *		thread must have been pulled from wait queue under same lock hold.
 *  Returns:
 *		KERN_SUCCESS - Thread was set running
 *		KERN_NOT_WAITING - Thread was not waiting
 */
kern_return_t
thread_go(
	thread_t		thread,
	wait_result_t	wresult)
{
	assert(thread->at_safe_point == FALSE);
	assert(thread->wait_event == NO_EVENT64);
	assert(thread->wait_queue == WAIT_QUEUE_NULL);

	if ((thread->state & (TH_WAIT|TH_TERMINATE)) == TH_WAIT) {
		if (!thread_unblock(thread, wresult))
			thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);

		return (KERN_SUCCESS);
	}

	return (KERN_NOT_WAITING);
}

/*
 *	Routine:	thread_mark_wait_locked
 *	Purpose:
 *		Mark a thread as waiting.  If, given the circumstances,
 *		it doesn't want to wait (i.e. already aborted), then
 *		indicate that in the return value.
 *	Conditions:
 *		at splsched() and thread is locked.
 */
__private_extern__
wait_result_t
thread_mark_wait_locked(
	thread_t			thread,
	wait_interrupt_t 	interruptible)
{
	boolean_t		at_safe_point;

	assert(thread == current_thread());

	/*
	 *	The thread may have certain types of interrupts/aborts masked
	 *	off.  Even if the wait location says these types of interrupts
	 *	are OK, we have to honor mask settings (outer-scoped code may
	 *	not be able to handle aborts at the moment).
	 */
	if (interruptible > (thread->options & TH_OPT_INTMASK))
		interruptible = thread->options & TH_OPT_INTMASK;

	at_safe_point = (interruptible == THREAD_ABORTSAFE);

	if (	interruptible == THREAD_UNINT			||
			!(thread->sched_flags & TH_SFLAG_ABORT)	||
			(!at_safe_point &&
				(thread->sched_flags & TH_SFLAG_ABORTSAFELY))) {

		if ( !(thread->state & TH_TERMINATE))
			DTRACE_SCHED(sleep);

		thread->state |= (interruptible) ? TH_WAIT : (TH_WAIT | TH_UNINT);
		thread->at_safe_point = at_safe_point;
		return (thread->wait_result = THREAD_WAITING);
	}
	else
	if (thread->sched_flags & TH_SFLAG_ABORTSAFELY)
		thread->sched_flags &= ~TH_SFLAG_ABORTED_MASK;

	return (thread->wait_result = THREAD_INTERRUPTED);
}

/*
 *	Routine:	thread_interrupt_level
 *	Purpose:
 *	        Set the maximum interruptible state for the
 *		current thread.  The effective value of any
 *		interruptible flag passed into assert_wait
 *		will never exceed this.
 *
 *		Useful for code that must not be interrupted,
 *		but which calls code that doesn't know that.
 *	Returns:
 *		The old interrupt level for the thread.
 */
__private_extern__ 
wait_interrupt_t
thread_interrupt_level(
	wait_interrupt_t new_level)
{
	thread_t thread = current_thread();
	wait_interrupt_t result = thread->options & TH_OPT_INTMASK;

	thread->options = (thread->options & ~TH_OPT_INTMASK) | (new_level & TH_OPT_INTMASK);

	return result;
}

/*
 * Check to see if an assert wait is possible, without actually doing one.
 * This is used by debug code in locks and elsewhere to verify that it is
 * always OK to block when trying to take a blocking lock (since waiting
 * for the actual assert_wait to catch the case may make it hard to detect
 * this case.
 */
boolean_t
assert_wait_possible(void)
{

	thread_t thread;

#if	DEBUG
	if(debug_mode) return TRUE;		/* Always succeed in debug mode */
#endif
	
	thread = current_thread();

	return (thread == NULL || wait_queue_assert_possible(thread));
}

/*
 *	assert_wait:
 *
 *	Assert that the current thread is about to go to
 *	sleep until the specified event occurs.
 */
wait_result_t
assert_wait(
	event_t				event,
	wait_interrupt_t	interruptible)
{
	register wait_queue_t	wq;
	register int		index;

	if(event == NO_EVENT)
		panic("assert_wait() called with NO_EVENT");

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
		VM_KERNEL_UNSLIDE(event), 0, 0, 0, 0);

	index = wait_hash(event);
	wq = &wait_queues[index];
	return wait_queue_assert_wait(wq, event, interruptible, 0);
}

wait_result_t
assert_wait_timeout(
	event_t				event,
	wait_interrupt_t	interruptible,
	uint32_t			interval,
	uint32_t			scale_factor)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	wait_queue_t		wqueue;
	uint64_t			deadline;
	spl_t				s;

	if(event == NO_EVENT)
		panic("assert_wait_timeout() called with NO_EVENT");

	wqueue = &wait_queues[wait_hash(event)];

	s = splsched();
	wait_queue_lock(wqueue);
	thread_lock(thread);

	clock_interval_to_deadline(interval, scale_factor, &deadline);
	
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
		VM_KERNEL_UNSLIDE(event), interruptible, deadline, 0, 0);
	
	wresult = wait_queue_assert_wait64_locked(wqueue, CAST_DOWN(event64_t, event),
						  interruptible, 
						  TIMEOUT_URGENCY_SYS_NORMAL,
						  deadline, 0,
						  thread);

	thread_unlock(thread);
	wait_queue_unlock(wqueue);
	splx(s);

	return (wresult);
}

wait_result_t
assert_wait_timeout_with_leeway(
	event_t				event,
	wait_interrupt_t	interruptible,
	wait_timeout_urgency_t	urgency,
	uint32_t			interval,
	uint32_t			leeway,
	uint32_t			scale_factor)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	wait_queue_t		wqueue;
	uint64_t			deadline;
	uint64_t			abstime;
	uint64_t			slop;
	uint64_t			now;
	spl_t				s;

	now = mach_absolute_time();
	clock_interval_to_absolutetime_interval(interval, scale_factor, &abstime);
	deadline = now + abstime;

	clock_interval_to_absolutetime_interval(leeway, scale_factor, &slop);

	if(event == NO_EVENT)
		panic("assert_wait_timeout_with_leeway() called with NO_EVENT");

	wqueue = &wait_queues[wait_hash(event)];

	s = splsched();
	wait_queue_lock(wqueue);
	thread_lock(thread);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
		VM_KERNEL_UNSLIDE(event), interruptible, deadline, 0, 0);
	
	wresult = wait_queue_assert_wait64_locked(wqueue, CAST_DOWN(event64_t, event),
						  interruptible,
						  urgency, deadline, slop,
						  thread);

	thread_unlock(thread);
	wait_queue_unlock(wqueue);
	splx(s);

	return (wresult);
}

wait_result_t
assert_wait_deadline(
	event_t				event,
	wait_interrupt_t	interruptible,
	uint64_t			deadline)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	wait_queue_t		wqueue;
	spl_t				s;

	assert(event != NO_EVENT);
	wqueue = &wait_queues[wait_hash(event)];

	s = splsched();
	wait_queue_lock(wqueue);
	thread_lock(thread);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
		VM_KERNEL_UNSLIDE(event), interruptible, deadline, 0, 0);

	wresult = wait_queue_assert_wait64_locked(wqueue, CAST_DOWN(event64_t,event),
						  interruptible, 
						  TIMEOUT_URGENCY_SYS_NORMAL, deadline, 0,
						  thread);

	thread_unlock(thread);
	wait_queue_unlock(wqueue);
	splx(s);

	return (wresult);
}

wait_result_t
assert_wait_deadline_with_leeway(
	event_t				event,
	wait_interrupt_t	interruptible,
	wait_timeout_urgency_t	urgency,
	uint64_t			deadline,
	uint64_t			leeway)
{
	thread_t			thread = current_thread();
	wait_result_t		wresult;
	wait_queue_t		wqueue;
	spl_t				s;

	if(event == NO_EVENT)
		panic("assert_wait_deadline_with_leeway() called with NO_EVENT");

	wqueue = &wait_queues[wait_hash(event)];

	s = splsched();
	wait_queue_lock(wqueue);
	thread_lock(thread);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED, MACH_WAIT)|DBG_FUNC_NONE,
		VM_KERNEL_UNSLIDE(event), interruptible, deadline, 0, 0);

	wresult = wait_queue_assert_wait64_locked(wqueue, CAST_DOWN(event64_t,event),
						  interruptible, 
						  urgency, deadline, leeway,
						  thread);

	thread_unlock(thread);
	wait_queue_unlock(wqueue);
	splx(s);

	return (wresult);
}

/*
 * thread_isoncpu:
 *
 * Return TRUE if a thread is running on a processor such that an AST
 * is needed to pull it out of userspace execution, or if executing in
 * the kernel, bring to a context switch boundary that would cause
 * thread state to be serialized in the thread PCB.
 * 
 * Thread locked, returns the same way. While locked, fields
 * like "state" cannot change. "runq" can change only from set to unset.
 */
static inline boolean_t
thread_isoncpu(thread_t thread)
{
	/* Not running or runnable */
	if (!(thread->state & TH_RUN))
		return (FALSE);

	/* Waiting on a runqueue, not currently running */
	/* TODO: This is invalid - it can get dequeued without thread lock, but not context switched. */
	if (thread->runq != PROCESSOR_NULL)
		return (FALSE);

	/*
	 * Thread must be running on a processor, or
	 * about to run, or just did run. In all these
	 * cases, an AST to the processor is needed
	 * to guarantee that the thread is kicked out
	 * of userspace and the processor has
	 * context switched (and saved register state).
	 */
	return (TRUE);
}

/*
 * thread_stop:
 *
 * Force a preemption point for a thread and wait
 * for it to stop running on a CPU. If a stronger
 * guarantee is requested, wait until no longer
 * runnable. Arbitrates access among
 * multiple stop requests. (released by unstop)
 *
 * The thread must enter a wait state and stop via a
 * separate means.
 *
 * Returns FALSE if interrupted.
 */
boolean_t
thread_stop(
	thread_t		thread,
	boolean_t	until_not_runnable)
{
	wait_result_t	wresult;
	spl_t			s = splsched();
	boolean_t		oncpu;

	wake_lock(thread);
	thread_lock(thread);

	while (thread->state & TH_SUSP) {
		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			wresult = thread_block(THREAD_CONTINUE_NULL);

		if (wresult != THREAD_AWAKENED)
			return (FALSE);

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread->state |= TH_SUSP;

	while ((oncpu = thread_isoncpu(thread)) ||
		   (until_not_runnable && (thread->state & TH_RUN))) {
		processor_t		processor;
		
		if (oncpu) {
			assert(thread->state & TH_RUN);
			processor = thread->chosen_processor;
			cause_ast_check(processor);
		}

		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_ABORTSAFE);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			wresult = thread_block(THREAD_CONTINUE_NULL);

		if (wresult != THREAD_AWAKENED) {
			thread_unstop(thread);
			return (FALSE);
		}

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
	
	/*
	 * We return with the thread unlocked. To prevent it from
	 * transitioning to a runnable state (or from TH_RUN to
	 * being on the CPU), the caller must ensure the thread
	 * is stopped via an external means (such as an AST)
	 */

	return (TRUE);
}

/*
 * thread_unstop:
 *
 * Release a previous stop request and set
 * the thread running if appropriate.
 *
 * Use only after a successful stop operation.
 */
void
thread_unstop(
	thread_t	thread)
{
	spl_t		s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	if ((thread->state & (TH_RUN|TH_WAIT|TH_SUSP)) == TH_SUSP) {
		thread->state &= ~TH_SUSP;
		thread_unblock(thread, THREAD_AWAKENED);

		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
	}
	else
	if (thread->state & TH_SUSP) {
		thread->state &= ~TH_SUSP;

		if (thread->wake_active) {
			thread->wake_active = FALSE;
			thread_unlock(thread);

			thread_wakeup(&thread->wake_active);
			wake_unlock(thread);
			splx(s);

			return;
		}
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
}

/*
 * thread_wait:
 *
 * Wait for a thread to stop running. (non-interruptible)
 *
 */
void
thread_wait(
	thread_t	thread,
	boolean_t	until_not_runnable)
{
	wait_result_t	wresult;
	boolean_t 	oncpu;
	processor_t	processor;
	spl_t		s = splsched();

	wake_lock(thread);
	thread_lock(thread);

	/*
	 * Wait until not running on a CPU.  If stronger requirement
	 * desired, wait until not runnable.  Assumption: if thread is
	 * on CPU, then TH_RUN is set, so we're not waiting in any case
	 * where the original, pure "TH_RUN" check would have let us 
	 * finish.
	 */
	while ((oncpu = thread_isoncpu(thread)) ||
			(until_not_runnable && (thread->state & TH_RUN))) {

		if (oncpu) {
			assert(thread->state & TH_RUN);
			processor = thread->chosen_processor;
			cause_ast_check(processor);
		}

		thread->wake_active = TRUE;
		thread_unlock(thread);

		wresult = assert_wait(&thread->wake_active, THREAD_UNINT);
		wake_unlock(thread);
		splx(s);

		if (wresult == THREAD_WAITING)
			thread_block(THREAD_CONTINUE_NULL);

		s = splsched();
		wake_lock(thread);
		thread_lock(thread);
	}

	thread_unlock(thread);
	wake_unlock(thread);
	splx(s);
}

/*
 *	Routine: clear_wait_internal
 *
 *		Clear the wait condition for the specified thread.
 *		Start the thread executing if that is appropriate.
 *	Arguments:
 *		thread		thread to awaken
 *		result		Wakeup result the thread should see
 *	Conditions:
 *		At splsched
 *		the thread is locked.
 *	Returns:
 *		KERN_SUCCESS		thread was rousted out a wait
 *		KERN_FAILURE		thread was waiting but could not be rousted
 *		KERN_NOT_WAITING	thread was not waiting
 */
__private_extern__ kern_return_t
clear_wait_internal(
	thread_t		thread,
	wait_result_t	wresult)
{
	wait_queue_t	wq = thread->wait_queue;
	uint32_t	i = LockTimeOut;

	do {
		if (wresult == THREAD_INTERRUPTED && (thread->state & TH_UNINT))
			return (KERN_FAILURE);

		if (wq != WAIT_QUEUE_NULL) {
			if (wait_queue_lock_try(wq)) {
				wait_queue_pull_thread_locked(wq, thread, TRUE);
				/* wait queue unlocked, thread still locked */
			}
			else {
				thread_unlock(thread);
				delay(1);

				thread_lock(thread);
				if (wq != thread->wait_queue)
					return (KERN_NOT_WAITING);

				continue;
			}
		}

		return (thread_go(thread, wresult));
	} while ((--i > 0) || machine_timeout_suspended());

	panic("clear_wait_internal: deadlock: thread=%p, wq=%p, cpu=%d\n",
		  thread, wq, cpu_number());

	return (KERN_FAILURE);
}


/*
 *	clear_wait:
 *
 *	Clear the wait condition for the specified thread.  Start the thread
 *	executing if that is appropriate.
 *
 *	parameters:
 *	  thread		thread to awaken
 *	  result		Wakeup result the thread should see
 */
kern_return_t
clear_wait(
	thread_t		thread,
	wait_result_t	result)
{
	kern_return_t ret;
	spl_t		s;

	s = splsched();
	thread_lock(thread);
	ret = clear_wait_internal(thread, result);
	thread_unlock(thread);
	splx(s);
	return ret;
}


/*
 *	thread_wakeup_prim:
 *
 *	Common routine for thread_wakeup, thread_wakeup_with_result,
 *	and thread_wakeup_one.
 *
 */
kern_return_t
thread_wakeup_prim(
	event_t			event,
	boolean_t		one_thread,
	wait_result_t		result)
{
	return (thread_wakeup_prim_internal(event, one_thread, result, -1));
}


kern_return_t
thread_wakeup_prim_internal(
	event_t			event,
	boolean_t		one_thread,
	wait_result_t		result,
	int			priority)
{
	register wait_queue_t	wq;
	register int			index;

	if(event == NO_EVENT)
		panic("thread_wakeup_prim() called with NO_EVENT");

	index = wait_hash(event);
	wq = &wait_queues[index];
	if (one_thread)
		return (wait_queue_wakeup_one(wq, event, result, priority));
	else
	    return (wait_queue_wakeup_all(wq, event, result));
}

/*
 *	thread_bind:
 *
 *	Force the current thread to execute on the specified processor.
 *	Takes effect after the next thread_block().
 *
 *	Returns the previous binding.  PROCESSOR_NULL means
 *	not bound.
 *
 *	XXX - DO NOT export this to users - XXX
 */
processor_t
thread_bind(
	processor_t		processor)
{
	thread_t		self = current_thread();
	processor_t		prev;
	spl_t			s;

	s = splsched();
	thread_lock(self);

	/* <rdar://problem/15102234> */
	assert(self->sched_pri < BASEPRI_RTQUEUES);

	prev = self->bound_processor;
	self->bound_processor = processor;

	thread_unlock(self);
	splx(s);

	return (prev);
}

/* Invoked prior to idle entry to determine if, on SMT capable processors, an SMT
 * rebalancing opportunity exists when a core is (instantaneously) idle, but
 * other SMT-capable cores may be over-committed. TODO: some possible negatives:
 * IPI thrash if this core does not remain idle following the load balancing ASTs
 * Idle "thrash", when IPI issue is followed by idle entry/core power down
 * followed by a wakeup shortly thereafter.
 */

/* Invoked with pset locked, returns with pset unlocked */
#if (DEVELOPMENT || DEBUG)
int sched_smt_balance = 1;
#endif

static void
sched_SMT_balance(processor_t cprocessor, processor_set_t cpset) {
	processor_t ast_processor = NULL;

#if (DEVELOPMENT || DEBUG)
	if (__improbable(sched_smt_balance == 0))
		goto smt_balance_exit;
#endif
	
	assert(cprocessor == current_processor());
	if (cprocessor->is_SMT == FALSE)
		goto smt_balance_exit;

	processor_t sib_processor = cprocessor->processor_secondary ? cprocessor->processor_secondary : cprocessor->processor_primary;

	/* Determine if both this processor and its sibling are idle,
	 * indicating an SMT rebalancing opportunity.
	 */
	if (sib_processor->state != PROCESSOR_IDLE)
		goto smt_balance_exit;

	processor_t sprocessor;

	sprocessor = (processor_t)queue_first(&cpset->active_queue);

	while (!queue_end(&cpset->active_queue, (queue_entry_t)sprocessor)) {
		if ((sprocessor->state == PROCESSOR_RUNNING) &&
		    (sprocessor->processor_primary != sprocessor) &&
		    (sprocessor->processor_primary->state == PROCESSOR_RUNNING) &&
		    (sprocessor->current_pri < BASEPRI_RTQUEUES) &&
		    ((cpset->pending_AST_cpu_mask & (1U << sprocessor->cpu_id)) == 0)) {
			assert(sprocessor != cprocessor);
			ast_processor = sprocessor;
			break;
		}
		sprocessor = (processor_t)queue_next((queue_entry_t)sprocessor);
	}

smt_balance_exit:
	pset_unlock(cpset);

	if (ast_processor) {
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_SMT_BALANCE), ast_processor->cpu_id, ast_processor->state, ast_processor->processor_primary->state, 0, 0);
		cause_ast_check(ast_processor);
	}
}

/*
 *	thread_select:
 *
 *	Select a new thread for the current processor to execute.
 *
 *	May select the current thread, which must be locked.
 */
static thread_t
thread_select(
	thread_t			thread,
	processor_t			processor,
	ast_t				reason)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			new_thread = THREAD_NULL;

	assert(processor == current_processor());

	do {
		/*
		 *	Update the priority.
		 */
		if (SCHED(can_update_priority)(thread))
			SCHED(update_priority)(thread);
		
		processor->current_pri = thread->sched_pri;
		processor->current_thmode = thread->sched_mode;
		processor->current_sfi_class = thread->sfi_class;

		pset_lock(pset);

		assert(processor->state != PROCESSOR_OFF_LINE);

		if (processor->processor_primary != processor) {
			/*
			 * Should this secondary SMT processor attempt to find work? For pset runqueue systems,
			 * we should look for work only under the same conditions that choose_processor()
			 * would have assigned work, which is when all primary processors have been assigned work.
			 *
			 * An exception is that bound threads are dispatched to a processor without going through
			 * choose_processor(), so in those cases we should continue trying to dequeue work.
			 */
			if (!SCHED(processor_bound_count)(processor) && !queue_empty(&pset->idle_queue) && !rt_runq.count) {
				goto idle;
			}
		}

		simple_lock(&rt_lock);

		/*
		 *	Test to see if the current thread should continue
		 *	to run on this processor.  Must be runnable, and not
		 *	bound to a different processor, nor be in the wrong
		 *	processor set.
		 */
		if (((thread->state & ~TH_SUSP) == TH_RUN) &&
		    (thread->sched_pri >= BASEPRI_RTQUEUES     || processor->processor_primary == processor) &&
		    (thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == processor)      &&
		    (thread->affinity_set == AFFINITY_SET_NULL || thread->affinity_set->aset_pset == pset)) {
			if (thread->sched_pri >= BASEPRI_RTQUEUES && first_timeslice(processor)) {
				if (rt_runq.count > 0) {
					thread_t next_rt;

					next_rt = (thread_t)queue_first(&rt_runq.queue);
					if (next_rt->realtime.deadline < processor->deadline &&
					   (next_rt->bound_processor == PROCESSOR_NULL || next_rt->bound_processor == processor)) {
						thread = (thread_t)dequeue_head(&rt_runq.queue);
						thread->runq = PROCESSOR_NULL;
						SCHED_STATS_RUNQ_CHANGE(&rt_runq.runq_stats, rt_runq.count);
						rt_runq.count--;
					}
				}

				simple_unlock(&rt_lock);

				processor->deadline = thread->realtime.deadline;

				pset_unlock(pset);

				return (thread);
			}

			if ((thread->sched_mode != TH_MODE_FAIRSHARE || SCHED(fairshare_runq_count)() == 0) && (rt_runq.count == 0 || BASEPRI_RTQUEUES < thread->sched_pri) && (new_thread = SCHED(choose_thread)(processor, thread->sched_mode == TH_MODE_FAIRSHARE ? MINPRI : thread->sched_pri, reason)) == THREAD_NULL) {

				simple_unlock(&rt_lock);

				/* This thread is still the highest priority runnable (non-idle) thread */

				processor->deadline = UINT64_MAX;

				pset_unlock(pset);

				return (thread);
			}
		}

		if (new_thread != THREAD_NULL ||
				(SCHED(processor_queue_has_priority)(processor, rt_runq.count == 0 ? IDLEPRI : BASEPRI_RTQUEUES, TRUE) &&
					 (new_thread = SCHED(choose_thread)(processor, MINPRI, reason)) != THREAD_NULL)) {
				simple_unlock(&rt_lock);

				processor->deadline = UINT64_MAX;
				pset_unlock(pset);

				return (new_thread);
		}

		if (rt_runq.count > 0) {
			thread_t next_rt = (thread_t)queue_first(&rt_runq.queue);

			if (__probable((next_rt->bound_processor == NULL || (next_rt->bound_processor == processor)))) {
				thread = (thread_t)dequeue_head(&rt_runq.queue);

				thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&rt_runq.runq_stats, rt_runq.count);
				rt_runq.count--;

				simple_unlock(&rt_lock);

				processor->deadline = thread->realtime.deadline;
				pset_unlock(pset);

				return (thread);
			}
		}

		simple_unlock(&rt_lock);

		/* No realtime threads and no normal threads on the per-processor
		 * runqueue. Finally check for global fairshare threads.
		 */
		if ((new_thread = SCHED(fairshare_dequeue)()) != THREAD_NULL) {

			processor->deadline = UINT64_MAX;
			pset_unlock(pset);
			
			return (new_thread);
		}
			
		processor->deadline = UINT64_MAX;

		/*
		 *	No runnable threads, attempt to steal
		 *	from other processors.
		 */
		new_thread = SCHED(steal_thread)(pset);
		if (new_thread != THREAD_NULL) {
			return (new_thread);
		}

		/*
		 *	If other threads have appeared, shortcut
		 *	around again.
		 */
		if (!SCHED(processor_queue_empty)(processor) || rt_runq.count > 0 || SCHED(fairshare_runq_count)() > 0)
			continue;

		pset_lock(pset);

	idle:
		/*
		 *	Nothing is runnable, so set this processor idle if it
		 *	was running.
		 */
		if (processor->state == PROCESSOR_RUNNING) {
			remqueue((queue_entry_t)processor);
			processor->state = PROCESSOR_IDLE;

			if (processor->processor_primary == processor) {
				enqueue_head(&pset->idle_queue, (queue_entry_t)processor);
			}
			else {
				enqueue_head(&pset->idle_secondary_queue, (queue_entry_t)processor);
			}
		}

		/* Invoked with pset locked, returns with pset unlocked */
		sched_SMT_balance(processor, pset);

#if CONFIG_SCHED_IDLE_IN_PLACE
		/*
		 *	Choose idle thread if fast idle is not possible.
		 */
		if (processor->processor_primary != processor)
			return (processor->idle_thread);

		if ((thread->state & (TH_IDLE|TH_TERMINATE|TH_SUSP)) || !(thread->state & TH_WAIT) || thread->wake_active || thread->sched_pri >= BASEPRI_RTQUEUES)
			return (processor->idle_thread);

		/*
		 *	Perform idling activities directly without a
		 *	context switch.  Return dispatched thread,
		 *	else check again for a runnable thread.
		 */
		new_thread = thread_select_idle(thread, processor);

#else /* !CONFIG_SCHED_IDLE_IN_PLACE */
		
		/*
		 * Do a full context switch to idle so that the current
		 * thread can start running on another processor without
		 * waiting for the fast-idled processor to wake up.
		 */
		return (processor->idle_thread);

#endif /* !CONFIG_SCHED_IDLE_IN_PLACE */

	} while (new_thread == THREAD_NULL);

	return (new_thread);
}

#if CONFIG_SCHED_IDLE_IN_PLACE
/*
 *	thread_select_idle:
 *
 *	Idle the processor using the current thread context.
 *
 *	Called with thread locked, then dropped and relocked.
 */
static thread_t
thread_select_idle(
	thread_t		thread,
	processor_t		processor)
{
	thread_t		new_thread;
	uint64_t		arg1, arg2;
	int			urgency;

	if (thread->sched_mode == TH_MODE_TIMESHARE) {
		if (thread->sched_flags & TH_SFLAG_THROTTLED)
			sched_background_decr(thread);

		sched_share_decr(thread);
	}
	sched_run_decr(thread);

	thread->state |= TH_IDLE;
	processor->current_pri = IDLEPRI;
	processor->current_thmode = TH_MODE_NONE;
	processor->current_sfi_class = SFI_CLASS_KERNEL;

	/* Reload precise timing global policy to thread-local policy */
	thread->precise_user_kernel_time = use_precise_user_kernel_time(thread);
	
	thread_unlock(thread);

	/*
	 *	Switch execution timing to processor idle thread.
	 */
	processor->last_dispatch = mach_absolute_time();

#ifdef CONFIG_MACH_APPROXIMATE_TIME
	commpage_update_mach_approximate_time(processor->last_dispatch);
#endif

	thread->last_run_time = processor->last_dispatch;
	thread_timer_event(processor->last_dispatch, &processor->idle_thread->system_timer);
	PROCESSOR_DATA(processor, kernel_timer) = &processor->idle_thread->system_timer;

	/*
	 *	Cancel the quantum timer while idling.
	 */
	timer_call_cancel(&processor->quantum_timer);
	processor->timeslice = 0;

	(*thread->sched_call)(SCHED_CALL_BLOCK, thread);

	thread_tell_urgency(THREAD_URGENCY_NONE, 0, 0, NULL);

	/*
	 *	Enable interrupts and perform idling activities.  No
	 *	preemption due to TH_IDLE being set.
	 */
	spllo(); new_thread = processor_idle(thread, processor);

	/*
	 *	Return at splsched.
	 */
	(*thread->sched_call)(SCHED_CALL_UNBLOCK, thread);

	thread_lock(thread);

	/*
	 *	If awakened, switch to thread timer and start a new quantum.
	 *	Otherwise skip; we will context switch to another thread or return here.
	 */
	if (!(thread->state & TH_WAIT)) {
		processor->last_dispatch = mach_absolute_time();
		thread_timer_event(processor->last_dispatch, &thread->system_timer);
		PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

		thread_quantum_init(thread);
		processor->quantum_end = processor->last_dispatch + thread->quantum_remaining;
		timer_call_enter1(&processor->quantum_timer, thread, processor->quantum_end, TIMER_CALL_SYS_CRITICAL | TIMER_CALL_LOCAL);
		processor->timeslice = 1;

		thread->computation_epoch = processor->last_dispatch;
	}

	thread->state &= ~TH_IDLE;

	/*
	 * If we idled in place, simulate a context switch back
	 * to the original priority of the thread so that the
	 * platform layer cannot distinguish this from a true
	 * switch to the idle thread.
	 */

	urgency = thread_get_urgency(thread, &arg1, &arg2);

	thread_tell_urgency(urgency, arg1, arg2, new_thread);

	sched_run_incr(thread);
	if (thread->sched_mode == TH_MODE_TIMESHARE) {
		sched_share_incr(thread);

		if (thread->sched_flags & TH_SFLAG_THROTTLED)
			sched_background_incr(thread);
	}

	return (new_thread);
}
#endif /* CONFIG_SCHED_IDLE_IN_PLACE */

#if defined(CONFIG_SCHED_TRADITIONAL) 
static thread_t
sched_traditional_choose_thread(
                                processor_t     processor,
                                int             priority,
                       __unused ast_t           reason)
{
	thread_t thread;
	
	thread = choose_thread_from_runq(processor, runq_for_processor(processor), priority);
	if (thread != THREAD_NULL) {
		runq_consider_decr_bound_count(processor, thread);
	}
	
	return thread;
}

#endif /* defined(CONFIG_SCHED_TRADITIONAL)  */

#if defined(CONFIG_SCHED_TRADITIONAL)

/*
 *	choose_thread_from_runq:
 *
 *	Locate a thread to execute from the processor run queue
 *	and return it.  Only choose a thread with greater or equal
 *	priority.
 *
 *	Associated pset must be locked.  Returns THREAD_NULL
 *	on failure.
 */
thread_t
choose_thread_from_runq(
	processor_t		processor,
	run_queue_t		rq,
	int				priority)
{
	queue_t			queue = rq->queues + rq->highq;
	int				pri = rq->highq, count = rq->count;
	thread_t		thread;

	while (count > 0 && pri >= priority) {
		thread = (thread_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			if (thread->bound_processor == PROCESSOR_NULL ||
							thread->bound_processor == processor) {
				remqueue((queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
				rq->count--;
				if (SCHED(priority_is_urgent)(pri)) {
					rq->urgency--; assert(rq->urgency >= 0);
				}
				if (queue_empty(queue)) {
					if (pri != IDLEPRI)
						clrbit(MAXPRI - pri, rq->bitmap);
					rq->highq = MAXPRI - ffsbit(rq->bitmap);
				}

				return (thread);
			}
			count--;

			thread = (thread_t)queue_next((queue_entry_t)thread);
		}

		queue--; pri--;
	}

	return (THREAD_NULL);
}

#endif /* defined(CONFIG_SCHED_TRADITIONAL) */

/*
 *	Perform a context switch and start executing the new thread.
 *
 *	Returns FALSE on failure, and the thread is re-dispatched.
 *
 *	Called at splsched.
 */

/*
 * thread_invoke
 *
 * "self" is what is currently running on the processor,
 * "thread" is the new thread to context switch to
 * (which may be the same thread in some cases)
 */
static boolean_t
thread_invoke(
	thread_t			self,
	thread_t			thread,
	ast_t				reason)
{
	thread_continue_t	continuation = self->continuation;
	void			*parameter = self->parameter;
	processor_t		processor;
	uint64_t		ctime = mach_absolute_time();

#ifdef CONFIG_MACH_APPROXIMATE_TIME
	commpage_update_mach_approximate_time(ctime);
#endif

	if (__improbable(get_preemption_level() != 0)) {
		int pl = get_preemption_level();
		panic("thread_invoke: preemption_level %d, possible cause: %s",
		    pl, (pl < 0 ? "unlocking an unlocked mutex or spinlock" :
			"blocking while holding a spinlock, or within interrupt context"));
	}

	assert(self == current_thread());
	assert(self->runq == PROCESSOR_NULL);

#if defined(CONFIG_SCHED_TIMESHARE_CORE)
	sched_traditional_consider_maintenance(ctime);
#endif /* CONFIG_SCHED_TIMESHARE_CORE */	
	
	/*
	 * Mark thread interruptible.
	 */
	thread_lock(thread);
	thread->state &= ~TH_UNINT;

	assert(thread_runnable(thread));
	assert(thread->bound_processor == PROCESSOR_NULL || thread->bound_processor == current_processor());
	assert(thread->runq == PROCESSOR_NULL);

	/* Reload precise timing global policy to thread-local policy */
	thread->precise_user_kernel_time = use_precise_user_kernel_time(thread);
	
	/* Update SFI class based on other factors */
	thread->sfi_class = sfi_thread_classify(thread);

	/*
	 * Allow time constraint threads to hang onto
	 * a stack.
	 */
	if ((self->sched_mode == TH_MODE_REALTIME) && !self->reserved_stack)
		self->reserved_stack = self->kernel_stack;

	if (continuation != NULL) {
		if (!thread->kernel_stack) {
			/*
			 * If we are using a privileged stack,
			 * check to see whether we can exchange it with
			 * that of the other thread.
			 */
			if (self->kernel_stack == self->reserved_stack && !thread->reserved_stack)
				goto need_stack;

			/*
			 * Context switch by performing a stack handoff.
			 */
			continuation = thread->continuation;
			parameter = thread->parameter;

			processor = current_processor();
			processor->active_thread = thread;
			processor->current_pri = thread->sched_pri;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class;
			if (thread->last_processor != processor && thread->last_processor != NULL) {
				if (thread->last_processor->processor_set != processor->processor_set)
					thread->ps_switch++;
				thread->p_switch++;
			}
			thread->last_processor = processor;
			thread->c_switch++;
			ast_context(thread);
			thread_unlock(thread);

			self->reason = reason;

			processor->last_dispatch = ctime;
			self->last_run_time = ctime;
			thread_timer_event(ctime, &thread->system_timer);
			PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

			/*
			 * Since non-precise user/kernel time doesn't update the state timer
			 * during privilege transitions, synthesize an event now.
			 */
			if (!thread->precise_user_kernel_time) {
				timer_switch(PROCESSOR_DATA(processor, current_state),
							ctime,
							 PROCESSOR_DATA(processor, current_state));
			}
	
			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED, MACH_STACK_HANDOFF)|DBG_FUNC_NONE,
				self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

			if ((thread->chosen_processor != processor) && (thread->chosen_processor != PROCESSOR_NULL)) {
				KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_MOVED)|DBG_FUNC_NONE,
						(uintptr_t)thread_tid(thread), (uintptr_t)thread->chosen_processor->cpu_id, 0, 0, 0);
			}

			DTRACE_SCHED2(off__cpu, struct thread *, thread, struct proc *, thread->task->bsd_info);

			SCHED_STATS_CSW(processor, self->reason, self->sched_pri, thread->sched_pri);

			TLOG(1, "thread_invoke: calling stack_handoff\n");
			stack_handoff(self, thread);

			DTRACE_SCHED(on__cpu);

			thread_dispatch(self, thread);

			thread->continuation = thread->parameter = NULL;

			counter(c_thread_invoke_hits++);

			(void) spllo();

			assert(continuation);
			call_continuation(continuation, parameter, thread->wait_result);
			/*NOTREACHED*/
		}
		else if (thread == self) {
			/* same thread but with continuation */
			ast_context(self);
			counter(++c_thread_invoke_same);
			thread_unlock(self);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
				self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

			self->continuation = self->parameter = NULL;

			(void) spllo();

			call_continuation(continuation, parameter, self->wait_result);
			/*NOTREACHED*/
		}
	}
	else {
		/*
		 * Check that the other thread has a stack
		 */
		if (!thread->kernel_stack) {
need_stack:
			if (!stack_alloc_try(thread)) {
				counter(c_thread_invoke_misses++);
				thread_unlock(thread);
				thread_stack_enqueue(thread);
				return (FALSE);
			}
		}
		else if (thread == self) {
			ast_context(self);
			counter(++c_thread_invoke_same);
			thread_unlock(self);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
				self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

			return (TRUE);
		}
	}

	/*
	 * Context switch by full context save.
	 */
	processor = current_processor();
	processor->active_thread = thread;
	processor->current_pri = thread->sched_pri;
	processor->current_thmode = thread->sched_mode;
	processor->current_sfi_class = thread->sfi_class;
	if (thread->last_processor != processor && thread->last_processor != NULL) {
		if (thread->last_processor->processor_set != processor->processor_set)
			thread->ps_switch++;
		thread->p_switch++;
	}
	thread->last_processor = processor;
	thread->c_switch++;
	ast_context(thread);
	thread_unlock(thread);

	counter(c_thread_invoke_csw++);

	assert(self->runq == PROCESSOR_NULL);
	self->reason = reason;

	processor->last_dispatch = ctime;
	self->last_run_time = ctime;
	thread_timer_event(ctime, &thread->system_timer);
	PROCESSOR_DATA(processor, kernel_timer) = &thread->system_timer;

	/*
	 * Since non-precise user/kernel time doesn't update the state timer
	 * during privilege transitions, synthesize an event now.
	 */
	if (!thread->precise_user_kernel_time) {
		timer_switch(PROCESSOR_DATA(processor, current_state),
					ctime,
					 PROCESSOR_DATA(processor, current_state));
	}
	
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
		self->reason, (uintptr_t)thread_tid(thread), self->sched_pri, thread->sched_pri, 0);

	if ((thread->chosen_processor != processor) && (thread->chosen_processor != NULL)) {
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_MOVED)|DBG_FUNC_NONE,
				(uintptr_t)thread_tid(thread), (uintptr_t)thread->chosen_processor->cpu_id, 0, 0, 0);
	}

	DTRACE_SCHED2(off__cpu, struct thread *, thread, struct proc *, thread->task->bsd_info);

	SCHED_STATS_CSW(processor, self->reason, self->sched_pri, thread->sched_pri);

	/*
	 * This is where we actually switch register context,
	 * and address space if required.  We will next run
	 * as a result of a subsequent context switch.
	 */
	assert(continuation == self->continuation);
	thread = machine_switch_context(self, continuation, thread);
	assert(self == current_thread());
	TLOG(1,"thread_invoke: returning machine_switch_context: self %p continuation %p thread %p\n", self, continuation, thread);

	DTRACE_SCHED(on__cpu);

	/*
	 * We have been resumed and are set to run.
	 */
	thread_dispatch(thread, self);

	if (continuation) {
		self->continuation = self->parameter = NULL;

		(void) spllo();

		call_continuation(continuation, parameter, self->wait_result);
		/*NOTREACHED*/
	}

	return (TRUE);
}

/*
 *	thread_dispatch:
 *
 *	Handle threads at context switch.  Re-dispatch other thread
 *	if still running, otherwise update run state and perform
 *	special actions.  Update quantum for other thread and begin
 *	the quantum for ourselves.
 *
 *     "self" is our new current thread that we have context switched
 *     to, "thread" is the old thread that we have switched away from.
 *
 *	Called at splsched.
 */
void
thread_dispatch(
	thread_t		thread,
	thread_t		self)
{
	processor_t		processor = self->last_processor;

	if (thread != THREAD_NULL) {
		/*
		 *	If blocked at a continuation, discard
		 *	the stack.
		 */
		if (thread->continuation != NULL && thread->kernel_stack != 0)
			stack_free(thread);

		if (!(thread->state & TH_IDLE)) {
			int64_t consumed;
			int64_t remainder = 0;

			if (processor->quantum_end > processor->last_dispatch)
				remainder = processor->quantum_end -
				    processor->last_dispatch;

			consumed = thread->quantum_remaining - remainder;

			if ((thread->reason & AST_LEDGER) == 0) {
				/*
				 * Bill CPU time to both the task and
				 * the individual thread.
				 */
				ledger_credit(thread->t_ledger,
				    task_ledgers.cpu_time, consumed);
				ledger_credit(thread->t_threadledger,
				    thread_ledgers.cpu_time, consumed);
#ifdef CONFIG_BANK
				if (thread->t_bankledger) {
					ledger_credit(thread->t_bankledger,
				    		bank_ledgers.cpu_time,
						(consumed - thread->t_deduct_bank_ledger_time));

				}
				thread->t_deduct_bank_ledger_time =0;
#endif
			}

			wake_lock(thread);
			thread_lock(thread);

			/*
			 *	Compute remainder of current quantum.
			 */
			if (first_timeslice(processor) &&
			    processor->quantum_end > processor->last_dispatch)
				thread->quantum_remaining = (uint32_t)remainder;
			else
				thread->quantum_remaining = 0;

			if (thread->sched_mode == TH_MODE_REALTIME) {
				/*
				 *	Cancel the deadline if the thread has
				 *	consumed the entire quantum.
				 */
				if (thread->quantum_remaining == 0) {
					thread->realtime.deadline = UINT64_MAX;
				}
			} else {
#if defined(CONFIG_SCHED_TRADITIONAL)
				/*
				 *	For non-realtime threads treat a tiny
				 *	remaining quantum as an expired quantum
				 *	but include what's left next time.
				 */
				if (thread->quantum_remaining < min_std_quantum) {
					thread->reason |= AST_QUANTUM;
					thread->quantum_remaining += SCHED(initial_quantum_size)(thread);
				}
#endif
			}

			/*
			 *	If we are doing a direct handoff then
			 *	take the remainder of the quantum.
			 */
			if ((thread->reason & (AST_HANDOFF|AST_QUANTUM)) == AST_HANDOFF) {
				self->quantum_remaining = thread->quantum_remaining;
				thread->reason |= AST_QUANTUM;
				thread->quantum_remaining = 0;
			} else {
#if defined(CONFIG_SCHED_MULTIQ)
				if (sched_groups_enabled && thread->sched_group == self->sched_group) {
					/* TODO: Remove tracepoint */
					KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
					    MACHDBG_CODE(DBG_MACH_SCHED, MACH_QUANTUM_HANDOFF) | DBG_FUNC_NONE,
					    self->reason, (uintptr_t)thread_tid(thread),
					    self->quantum_remaining, thread->quantum_remaining, 0);

					self->quantum_remaining = thread->quantum_remaining;
					thread->quantum_remaining = 0;
					/*  TODO: Should we set AST_QUANTUM here? */
				}
#endif /* defined(CONFIG_SCHED_MULTIQ) */
			}

			thread->computation_metered += (processor->last_dispatch - thread->computation_epoch);

			if ((thread->rwlock_count != 0) && !(LcksOpts & disLkRWPrio)) {
				integer_t priority;

				priority = thread->sched_pri;

				if (priority < thread->priority)
					priority = thread->priority;
				if (priority < BASEPRI_BACKGROUND)
					priority = BASEPRI_BACKGROUND;

				if ((thread->sched_pri < priority) || !(thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
					KERNEL_DEBUG_CONSTANT(
						MACHDBG_CODE(DBG_MACH_SCHED, MACH_RW_PROMOTE) | DBG_FUNC_NONE,
						(uintptr_t)thread_tid(thread), thread->sched_pri, thread->priority, priority, 0);

					thread->sched_flags |= TH_SFLAG_RW_PROMOTED;

					if (thread->sched_pri < priority)
						set_sched_pri(thread, priority);
				}
			}

			if (!(thread->state & TH_WAIT)) {
				/*
				 *	Still running.
				 */
				if (thread->reason & AST_QUANTUM)
					thread_setrun(thread, SCHED_TAILQ);
				else
				if (thread->reason & AST_PREEMPT)
					thread_setrun(thread, SCHED_HEADQ);
				else
					thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);

				thread->reason = AST_NONE;

				KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
					MACHDBG_CODE(DBG_MACH_SCHED,MACH_DISPATCH) | DBG_FUNC_NONE,
					(uintptr_t)thread_tid(thread), thread->reason, thread->state, sched_run_count, 0);
				
				if (thread->wake_active) {
					thread->wake_active = FALSE;
					thread_unlock(thread);

					thread_wakeup(&thread->wake_active);
				}
				else
					thread_unlock(thread);

				wake_unlock(thread);
			}
			else {
				/*
				 *	Waiting.
				 */
				boolean_t should_terminate = FALSE;
				uint32_t new_run_count;

				/* Only the first call to thread_dispatch
				 * after explicit termination should add
				 * the thread to the termination queue
				 */
				if ((thread->state & (TH_TERMINATE|TH_TERMINATE2)) == TH_TERMINATE) {
					should_terminate = TRUE;
					thread->state |= TH_TERMINATE2;
				}

				thread->state &= ~TH_RUN;
				thread->chosen_processor = PROCESSOR_NULL;

				if (thread->sched_mode == TH_MODE_TIMESHARE) {
					if (thread->sched_flags & TH_SFLAG_THROTTLED)
						sched_background_decr(thread);

					sched_share_decr(thread);
				}
				new_run_count = sched_run_decr(thread);

				if ((thread->state & (TH_WAIT | TH_TERMINATE)) == TH_WAIT) {
					if (thread->reason & AST_SFI) {
						thread->wait_sfi_begin_time = processor->last_dispatch;
					}
				}

				KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
					MACHDBG_CODE(DBG_MACH_SCHED,MACH_DISPATCH) | DBG_FUNC_NONE,
					(uintptr_t)thread_tid(thread), thread->reason, thread->state, new_run_count, 0);

				(*thread->sched_call)(SCHED_CALL_BLOCK, thread);

				if (thread->wake_active) {
					thread->wake_active = FALSE;
					thread_unlock(thread);

					thread_wakeup(&thread->wake_active);
				}
				else
					thread_unlock(thread);

				wake_unlock(thread);

				if (should_terminate)
					thread_terminate_enqueue(thread);
			}
		}
	}

	if (!(self->state & TH_IDLE)) {
		uint64_t        arg1, arg2;
		int             urgency;
		ast_t			new_ast;

		thread_lock(self);
		new_ast = sfi_thread_needs_ast(self, NULL);
		thread_unlock(self);

		if (new_ast != AST_NONE) {
			ast_on(new_ast);
		}

		urgency = thread_get_urgency(self, &arg1, &arg2);

		thread_tell_urgency(urgency, arg1, arg2, self);
		
		/*
		 *	Get a new quantum if none remaining.
		 */
		if (self->quantum_remaining == 0) {
			thread_quantum_init(self);
		}

		/*
		 *	Set up quantum timer and timeslice.
		 */
		processor->quantum_end = processor->last_dispatch + self->quantum_remaining;
		timer_call_enter1(&processor->quantum_timer, self, processor->quantum_end, TIMER_CALL_SYS_CRITICAL | TIMER_CALL_LOCAL);

		processor->timeslice = 1;

		self->computation_epoch = processor->last_dispatch;
	}
	else {
		timer_call_cancel(&processor->quantum_timer);
		processor->timeslice = 0;

		thread_tell_urgency(THREAD_URGENCY_NONE, 0, 0, NULL);
	}
}

/*
 *	thread_block_reason:
 *
 *	Forces a reschedule, blocking the caller if a wait
 *	has been asserted.
 *
 *	If a continuation is specified, then thread_invoke will
 *	attempt to discard the thread's kernel stack.  When the
 *	thread resumes, it will execute the continuation function
 *	on a new kernel stack.
 */
counter(mach_counter_t  c_thread_block_calls = 0;)
 
wait_result_t
thread_block_reason(
	thread_continue_t	continuation,
	void				*parameter,
	ast_t				reason)
{
	register thread_t		self = current_thread();
	register processor_t	processor;
	register thread_t		new_thread;
	spl_t					s;

	counter(++c_thread_block_calls);

	s = splsched();

	processor = current_processor();

	/* If we're explicitly yielding, force a subsequent quantum */
	if (reason & AST_YIELD)
		processor->timeslice = 0;

	/* We're handling all scheduling AST's */
	ast_off(AST_SCHEDULING);

	self->continuation = continuation;
	self->parameter = parameter;

	if (self->state & ~(TH_RUN | TH_IDLE)) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_BLOCK), 
			reason, VM_KERNEL_UNSLIDE(continuation), 0, 0, 0);
	}

	do {
		thread_lock(self);
		new_thread = thread_select(self, processor, reason);
		thread_unlock(self);
	} while (!thread_invoke(self, new_thread, reason));

	splx(s);

	return (self->wait_result);
}

/*
 *	thread_block:
 *
 *	Block the current thread if a wait has been asserted.
 */
wait_result_t
thread_block(
	thread_continue_t	continuation)
{
	return thread_block_reason(continuation, NULL, AST_NONE);
}

wait_result_t
thread_block_parameter(
	thread_continue_t	continuation,
	void				*parameter)
{
	return thread_block_reason(continuation, parameter, AST_NONE);
}

/*
 *	thread_run:
 *
 *	Switch directly from the current thread to the
 *	new thread, handing off our quantum if appropriate.
 *
 *	New thread must be runnable, and not on a run queue.
 *
 *	Called at splsched.
 */
int
thread_run(
	thread_t			self,
	thread_continue_t	continuation,
	void				*parameter,
	thread_t			new_thread)
{
	ast_t		handoff = AST_HANDOFF;

	self->continuation = continuation;
	self->parameter = parameter;

	while (!thread_invoke(self, new_thread, handoff)) {
		processor_t		processor = current_processor();

		thread_lock(self);
		new_thread = thread_select(self, processor, AST_NONE);
		thread_unlock(self);
		handoff = AST_NONE;
	}

	return (self->wait_result);
}

/*
 *	thread_continue:
 *
 *	Called at splsched when a thread first receives
 *	a new stack after a continuation.
 */
void
thread_continue(
	register thread_t	thread)
{
	register thread_t		self = current_thread();
	register thread_continue_t	continuation;
	register void			*parameter;

	DTRACE_SCHED(on__cpu);

	continuation = self->continuation;
	parameter = self->parameter;

	thread_dispatch(thread, self);

	self->continuation = self->parameter = NULL;

	if (thread != THREAD_NULL)
		(void)spllo();

 TLOG(1, "thread_continue: calling call_continuation \n");
	call_continuation(continuation, parameter, self->wait_result);
	/*NOTREACHED*/
}

void
thread_quantum_init(thread_t thread)
{
	if (thread->sched_mode == TH_MODE_REALTIME) {
		thread->quantum_remaining = thread->realtime.computation;
	} else {
		thread->quantum_remaining = SCHED(initial_quantum_size)(thread);
	}
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

uint32_t
sched_traditional_initial_quantum_size(thread_t thread)
{
	if ((thread == THREAD_NULL) || !(thread->sched_flags & TH_SFLAG_THROTTLED))
		return std_quantum;
	else
		return bg_quantum;
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

#if defined(CONFIG_SCHED_TRADITIONAL)

static sched_mode_t
sched_traditional_initial_thread_sched_mode(task_t parent_task)
{
	if (parent_task == kernel_task)
		return TH_MODE_FIXED;
	else
		return TH_MODE_TIMESHARE;
}

#endif /* CONFIG_SCHED_TRADITIONAL */

/*
 *	run_queue_init:
 *
 *	Initialize a run queue before first use.
 */
void
run_queue_init(
	run_queue_t		rq)
{
	int				i;

	rq->highq = IDLEPRI;
	for (i = 0; i < NRQBM; i++)
		rq->bitmap[i] = 0;
	setbit(MAXPRI - IDLEPRI, rq->bitmap);
	rq->urgency = rq->count = 0;
	for (i = 0; i < NRQS; i++)
		queue_init(&rq->queues[i]);
}

#if defined(CONFIG_SCHED_FAIRSHARE_CORE)
int
sched_traditional_fairshare_runq_count(void)
{
	return fs_runq.count;
}

uint64_t
sched_traditional_fairshare_runq_stats_count_sum(void)
{
	return fs_runq.runq_stats.count_sum;
}

void
sched_traditional_fairshare_enqueue(thread_t thread)
{
	queue_t				queue = &fs_runq.queue;
	
	simple_lock(&fs_lock);
	
	enqueue_tail(queue, (queue_entry_t)thread);
	
	thread->runq = FS_RUNQ;
	SCHED_STATS_RUNQ_CHANGE(&fs_runq.runq_stats, fs_runq.count);
	fs_runq.count++;
	
	simple_unlock(&fs_lock);	
}

thread_t
sched_traditional_fairshare_dequeue(void)
{
	thread_t thread;
	
	simple_lock(&fs_lock);
	if (fs_runq.count > 0) {
		thread = (thread_t)dequeue_head(&fs_runq.queue);
		
		thread->runq = PROCESSOR_NULL;
		SCHED_STATS_RUNQ_CHANGE(&fs_runq.runq_stats, fs_runq.count);
		fs_runq.count--;
		
		simple_unlock(&fs_lock);
		
		return (thread);
	}
	simple_unlock(&fs_lock);		

	return THREAD_NULL;
}

boolean_t
sched_traditional_fairshare_queue_remove(thread_t thread)
{
	queue_t			q;

	simple_lock(&fs_lock);
	q = &fs_runq.queue;
	
	if (FS_RUNQ == thread->runq) {
		remqueue((queue_entry_t)thread);
		SCHED_STATS_RUNQ_CHANGE(&fs_runq.runq_stats, fs_runq.count);
		fs_runq.count--;
		
		thread->runq = PROCESSOR_NULL;
		simple_unlock(&fs_lock);
		return (TRUE);
	}
	else {
		/*
		 *	The thread left the run queue before we could
		 * 	lock the run queue.
		 */
		assert(thread->runq == PROCESSOR_NULL);
		simple_unlock(&fs_lock);
		return (FALSE);
	}	
}

#endif /* CONFIG_SCHED_FAIRSHARE_CORE */

/*
 *	run_queue_dequeue:
 *
 *	Perform a dequeue operation on a run queue,
 *	and return the resulting thread.
 *
 *	The run queue must be locked (see thread_run_queue_remove()
 *	for more info), and not empty.
 */
thread_t
run_queue_dequeue(
	run_queue_t		rq,
	integer_t		options)
{
	thread_t		thread;
	queue_t			queue = rq->queues + rq->highq;

	if (options & SCHED_HEADQ) {
		thread = (thread_t)dequeue_head(queue);
	}
	else {
		thread = (thread_t)dequeue_tail(queue);
	}

	thread->runq = PROCESSOR_NULL;
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count--;
	if (SCHED(priority_is_urgent)(rq->highq)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}
	if (queue_empty(queue)) {
		if (rq->highq != IDLEPRI)
			clrbit(MAXPRI - rq->highq, rq->bitmap);
		rq->highq = MAXPRI - ffsbit(rq->bitmap);
	}

	return (thread);
}

/*
 *	run_queue_enqueue:
 *
 *	Perform a enqueue operation on a run queue.
 *
 *	The run queue must be locked (see thread_run_queue_remove()
 *	for more info).
 */
boolean_t
run_queue_enqueue(
							  run_queue_t		rq,
							  thread_t			thread,
							  integer_t		options)
{
	queue_t			queue = rq->queues + thread->sched_pri;
	boolean_t		result = FALSE;
	
	if (queue_empty(queue)) {
		enqueue_tail(queue, (queue_entry_t)thread);
		
		setbit(MAXPRI - thread->sched_pri, rq->bitmap);
		if (thread->sched_pri > rq->highq) {
			rq->highq = thread->sched_pri;
			result = TRUE;
		}
	} else {
		if (options & SCHED_TAILQ)
			enqueue_tail(queue, (queue_entry_t)thread);
		else
			enqueue_head(queue, (queue_entry_t)thread);
	}
	if (SCHED(priority_is_urgent)(thread->sched_pri))
		rq->urgency++;
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count++;
	
	return (result);
	
}

/*
 *	run_queue_remove:
 *
 *	Remove a specific thread from a runqueue.
 *
 *	The run queue must be locked.
 */
void
run_queue_remove(
				  run_queue_t		rq,
				  thread_t			thread)
{

	remqueue((queue_entry_t)thread);
	SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
	rq->count--;
	if (SCHED(priority_is_urgent)(thread->sched_pri)) {
		rq->urgency--; assert(rq->urgency >= 0);
	}
	
	if (queue_empty(rq->queues + thread->sched_pri)) {
		/* update run queue status */
		if (thread->sched_pri != IDLEPRI)
			clrbit(MAXPRI - thread->sched_pri, rq->bitmap);
		rq->highq = MAXPRI - ffsbit(rq->bitmap);
	}
	
	thread->runq = PROCESSOR_NULL;
}

/*
 *	fairshare_setrun:
 *
 *	Dispatch a thread for round-robin execution.
 *
 *	Thread must be locked.  Associated pset must
 *	be locked, and is returned unlocked.
 */
static void
fairshare_setrun(
				  processor_t			processor,
				  thread_t			thread)
{
	processor_set_t		pset = processor->processor_set;
		
	thread->chosen_processor = processor;

	SCHED(fairshare_enqueue)(thread);
	
	pset_unlock(pset);

	if (processor != current_processor())
		machine_signal_idle(processor);


}

/*
 *	realtime_queue_insert:
 *
 *	Enqueue a thread for realtime execution.
 */
static boolean_t
realtime_queue_insert(
	thread_t			thread)
{
	queue_t				queue = &rt_runq.queue;
	uint64_t			deadline = thread->realtime.deadline;
	boolean_t			preempt = FALSE;

	simple_lock(&rt_lock);

	if (queue_empty(queue)) {
		enqueue_tail(queue, (queue_entry_t)thread);
		preempt = TRUE;
	}
	else {
		register thread_t	entry = (thread_t)queue_first(queue);

		while (TRUE) {
			if (	queue_end(queue, (queue_entry_t)entry)	||
						deadline < entry->realtime.deadline		) {
				entry = (thread_t)queue_prev((queue_entry_t)entry);
				break;
			}

			entry = (thread_t)queue_next((queue_entry_t)entry);
		}

		if ((queue_entry_t)entry == queue)
			preempt = TRUE;

		insque((queue_entry_t)thread, (queue_entry_t)entry);
	}

	thread->runq = RT_RUNQ;
	SCHED_STATS_RUNQ_CHANGE(&rt_runq.runq_stats, rt_runq.count);
	rt_runq.count++;

	simple_unlock(&rt_lock);

	return (preempt);
}

/*
 *	realtime_setrun:
 *
 *	Dispatch a thread for realtime execution.
 *
 *	Thread must be locked.  Associated pset must
 *	be locked, and is returned unlocked.
 */
static void
realtime_setrun(
	processor_t			processor,
	thread_t			thread)
{
	processor_set_t		pset = processor->processor_set;
	ast_t				preempt;

	boolean_t do_signal_idle = FALSE, do_cause_ast = FALSE;

	thread->chosen_processor = processor;

	/* <rdar://problem/15102234> */
	assert(thread->bound_processor == PROCESSOR_NULL);

	/*
	 *	Dispatch directly onto idle processor.
	 */
	if ( (thread->bound_processor == processor)
		&& processor->state == PROCESSOR_IDLE) {
		remqueue((queue_entry_t)processor);
		enqueue_tail(&pset->active_queue, (queue_entry_t)processor);

		processor->next_thread = thread;
		processor->current_pri = thread->sched_pri;
		processor->current_thmode = thread->sched_mode;
		processor->current_sfi_class = thread->sfi_class;
		processor->deadline = thread->realtime.deadline;
		processor->state = PROCESSOR_DISPATCHING;

		if (processor != current_processor()) {
			if (!(pset->pending_AST_cpu_mask & (1U << processor->cpu_id))) {
				/* cleared on exit from main processor_idle() loop */
				pset->pending_AST_cpu_mask |= (1U << processor->cpu_id);
				do_signal_idle = TRUE;
			}
		}
		pset_unlock(pset);

		if (do_signal_idle) {
			machine_signal_idle(processor);
		}
		return;
	}

	if (processor->current_pri < BASEPRI_RTQUEUES)
		preempt = (AST_PREEMPT | AST_URGENT);
	else if (thread->realtime.deadline < processor->deadline)
		preempt = (AST_PREEMPT | AST_URGENT);
	else
		preempt = AST_NONE;

	realtime_queue_insert(thread);

	if (preempt != AST_NONE) {
		if (processor->state == PROCESSOR_IDLE) {
			remqueue((queue_entry_t)processor);
			enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
			processor->next_thread = THREAD_NULL;
			processor->current_pri = thread->sched_pri;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class;
			processor->deadline = thread->realtime.deadline;
			processor->state = PROCESSOR_DISPATCHING;
			if (processor == current_processor()) {
				ast_on(preempt);
			} else {
				if (!(pset->pending_AST_cpu_mask & (1U << processor->cpu_id))) {
					/* cleared on exit from main processor_idle() loop */
					pset->pending_AST_cpu_mask |= (1U << processor->cpu_id);
					do_signal_idle = TRUE;
				}
			}
		} else if (processor->state == PROCESSOR_DISPATCHING) {
			if ((processor->next_thread == THREAD_NULL) && ((processor->current_pri < thread->sched_pri) || (processor->deadline > thread->realtime.deadline))) {
				processor->current_pri = thread->sched_pri;
				processor->current_thmode = thread->sched_mode;
				processor->current_sfi_class = thread->sfi_class;
				processor->deadline = thread->realtime.deadline;
			}
		} else {
			if (processor == current_processor()) {
				ast_on(preempt);
			} else {
				if (!(pset->pending_AST_cpu_mask & (1U << processor->cpu_id))) {
					/* cleared after IPI causes csw_check() to be called */
					pset->pending_AST_cpu_mask |= (1U << processor->cpu_id);
					do_cause_ast = TRUE;
				}
			}
		}
	} else {
		/* Selected processor was too busy, just keep thread enqueued and let other processors drain it naturally. */
	}

	pset_unlock(pset);

	if (do_signal_idle) {
		machine_signal_idle(processor);
	} else if (do_cause_ast) {
		cause_ast_check(processor);
	}
}


#if defined(CONFIG_SCHED_TIMESHARE_CORE)

boolean_t
priority_is_urgent(int priority)
{
	return testbit(priority, sched_preempt_pri) ? TRUE : FALSE;
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

#if defined(CONFIG_SCHED_TRADITIONAL)
/*
 *	processor_enqueue:
 *
 *	Enqueue thread on a processor run queue.  Thread must be locked,
 *	and not already be on a run queue.
 *
 *	Returns TRUE if a preemption is indicated based on the state
 *	of the run queue.
 *
 *	The run queue must be locked (see thread_run_queue_remove()
 *	for more info).
 */
static boolean_t
processor_enqueue(
	processor_t		processor,
	thread_t		thread,
	integer_t		options)
{
	run_queue_t		rq = runq_for_processor(processor);
	boolean_t		result;
	
	result = run_queue_enqueue(rq, thread, options);
	thread->runq = processor;
	runq_consider_incr_bound_count(processor, thread);

	return (result);
}

#endif /* CONFIG_SCHED_TRADITIONAL */

/*
 *	processor_setrun:
 *
 *	Dispatch a thread for execution on a
 *	processor.
 *
 *	Thread must be locked.  Associated pset must
 *	be locked, and is returned unlocked.
 */
static void
processor_setrun(
	processor_t			processor,
	thread_t			thread,
	integer_t			options)
{
	processor_set_t		pset = processor->processor_set;
	ast_t				preempt;
	enum { eExitIdle, eInterruptRunning, eDoNothing } ipi_action = eDoNothing;

	boolean_t do_signal_idle = FALSE, do_cause_ast = FALSE;

	thread->chosen_processor = processor;

	/*
	 *	Dispatch directly onto idle processor.
	 */
	if ( (SCHED(direct_dispatch_to_idle_processors) ||
		  thread->bound_processor == processor)
		&& processor->state == PROCESSOR_IDLE) {
		remqueue((queue_entry_t)processor);
		enqueue_tail(&pset->active_queue, (queue_entry_t)processor);

		processor->next_thread = thread;
		processor->current_pri = thread->sched_pri;
		processor->current_thmode = thread->sched_mode;
		processor->current_sfi_class = thread->sfi_class;
		processor->deadline = UINT64_MAX;
		processor->state = PROCESSOR_DISPATCHING;

		if (!(pset->pending_AST_cpu_mask & (1U << processor->cpu_id))) {
			/* cleared on exit from main processor_idle() loop */
			pset->pending_AST_cpu_mask |= (1U << processor->cpu_id);
			do_signal_idle = TRUE;
		}

		pset_unlock(pset);
		if (do_signal_idle) {
			machine_signal_idle(processor);
		}

		return;
	}

	/*
	 *	Set preemption mode.
	 */
	if (SCHED(priority_is_urgent)(thread->sched_pri) && thread->sched_pri > processor->current_pri)
		preempt = (AST_PREEMPT | AST_URGENT);
	else if(processor->active_thread && thread_eager_preemption(processor->active_thread))
		preempt = (AST_PREEMPT | AST_URGENT);
	else if ((thread->sched_mode == TH_MODE_TIMESHARE) && (thread->sched_pri < thread->priority)) {
		if(SCHED(priority_is_urgent)(thread->priority) && thread->sched_pri > processor->current_pri) {
			preempt = (options & SCHED_PREEMPT)? AST_PREEMPT: AST_NONE;
		} else {
			preempt = AST_NONE;
		}
	} else
		preempt = (options & SCHED_PREEMPT)? AST_PREEMPT: AST_NONE;

	SCHED(processor_enqueue)(processor, thread, options);

	if (preempt != AST_NONE) {
		if (processor->state == PROCESSOR_IDLE) {
			remqueue((queue_entry_t)processor);
			enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
			processor->next_thread = THREAD_NULL;
			processor->current_pri = thread->sched_pri;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class;
			processor->deadline = UINT64_MAX;
			processor->state = PROCESSOR_DISPATCHING;

			ipi_action = eExitIdle;
		} else if ( processor->state == PROCESSOR_DISPATCHING) {
			if ((processor->next_thread == THREAD_NULL) && (processor->current_pri < thread->sched_pri)) {
				processor->current_pri = thread->sched_pri;
				processor->current_thmode = thread->sched_mode;
				processor->current_sfi_class = thread->sfi_class;
				processor->deadline = UINT64_MAX;
			}
		} else if (	(processor->state == PROCESSOR_RUNNING		||
				 processor->state == PROCESSOR_SHUTDOWN)		&&
				(thread->sched_pri >= processor->current_pri	||
				processor->current_thmode == TH_MODE_FAIRSHARE)) {
			ipi_action = eInterruptRunning;
		}
	} else {
		/*
		 * New thread is not important enough to preempt what is running, but
		 * special processor states may need special handling
		 */
		if (processor->state == PROCESSOR_SHUTDOWN		&&
			thread->sched_pri >= processor->current_pri	) {
			ipi_action = eInterruptRunning;
		} else if (	processor->state == PROCESSOR_IDLE	&&
					processor != current_processor()	) {
			remqueue((queue_entry_t)processor);
			enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
			processor->next_thread = THREAD_NULL;
			processor->current_pri = thread->sched_pri;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class;
			processor->deadline = UINT64_MAX;
			processor->state = PROCESSOR_DISPATCHING;

			ipi_action = eExitIdle;
		}
	}

	switch (ipi_action) {
		case eDoNothing:
			break;
		case eExitIdle:
			if (processor == current_processor()) {
				if (csw_check_locked(processor, pset, AST_NONE) != AST_NONE)
					ast_on(preempt);
			} else {
				if (!(pset->pending_AST_cpu_mask & (1U << processor->cpu_id))) {
					/* cleared on exit from main processor_idle() loop */
					pset->pending_AST_cpu_mask |= (1U << processor->cpu_id);
					do_signal_idle = TRUE;
				}
			}
			break;
		case eInterruptRunning:
			if (processor == current_processor()) {
				if (csw_check_locked(processor, pset, AST_NONE) != AST_NONE)
					ast_on(preempt);
			} else {
				if (!(pset->pending_AST_cpu_mask & (1U << processor->cpu_id))) {
					/* cleared after IPI causes csw_check() to be called */
					pset->pending_AST_cpu_mask |= (1U << processor->cpu_id);
					do_cause_ast = TRUE;
				}
			}
			break;
	}

	pset_unlock(pset);

	if (do_signal_idle) {
		machine_signal_idle(processor);
	} else if (do_cause_ast) {
		cause_ast_check(processor);
	}
}

#if defined(CONFIG_SCHED_TRADITIONAL)

static boolean_t
processor_queue_empty(processor_t		processor)
{
	return runq_for_processor(processor)->count == 0;
	
}

static boolean_t
sched_traditional_with_pset_runqueue_processor_queue_empty(processor_t		processor)
{
	processor_set_t pset = processor->processor_set;
	int count = runq_for_processor(processor)->count;

	/*
	 * The pset runq contains the count of all runnable threads
	 * for all processors in the pset. However, for threads that
	 * are bound to another processor, the current "processor"
	 * is not eligible to execute the thread. So we only
	 * include bound threads that our bound to the current
	 * "processor". This allows the processor to idle when the
	 * count of eligible threads drops to 0, even if there's
	 * a runnable thread bound to a different processor in the
	 * shared runq.
	 */

	count -= pset->pset_runq_bound_count;
	count += processor->runq_bound_count;

	return count == 0;
}

static ast_t
processor_csw_check(processor_t processor)
{
	run_queue_t		runq;
	boolean_t		has_higher;

	assert(processor->active_thread != NULL);
	
	runq = runq_for_processor(processor);
	if (first_timeslice(processor)) {
		has_higher = (runq->highq > processor->current_pri);
	} else {
		has_higher = (runq->highq >= processor->current_pri);
	}
	if (has_higher) {
		if (runq->urgency > 0)
			return (AST_PREEMPT | AST_URGENT);
		
		if (processor->active_thread && thread_eager_preemption(processor->active_thread))
			return (AST_PREEMPT | AST_URGENT);

		return AST_PREEMPT;
	}

	return AST_NONE;
}

static boolean_t
processor_queue_has_priority(processor_t		processor,
							 int				priority,
							 boolean_t			gte)
{
	if (gte)
		return runq_for_processor(processor)->highq >= priority;
	else
		return runq_for_processor(processor)->highq > priority;
}

static boolean_t
should_current_thread_rechoose_processor(processor_t			processor)
{
	return (processor->current_pri < BASEPRI_RTQUEUES
			&& processor->processor_primary != processor);
}

static int
sched_traditional_processor_runq_count(processor_t   processor)
{
	return runq_for_processor(processor)->count;
}

static uint64_t
sched_traditional_processor_runq_stats_count_sum(processor_t   processor)
{
	return runq_for_processor(processor)->runq_stats.count_sum;
}

static uint64_t
sched_traditional_with_pset_runqueue_processor_runq_stats_count_sum(processor_t   processor)
{
	if (processor->cpu_id == processor->processor_set->cpu_set_low)
		return runq_for_processor(processor)->runq_stats.count_sum;
	else
		return 0ULL;
}

static int
sched_traditional_processor_bound_count(processor_t   processor)
{
	return processor->runq_bound_count;
}

#endif /* CONFIG_SCHED_TRADITIONAL */

/*
 *	choose_next_pset:
 *
 *	Return the next sibling pset containing
 *	available processors.
 *
 *	Returns the original pset if none other is
 *	suitable.
 */
static processor_set_t
choose_next_pset(
	processor_set_t		pset)
{
	processor_set_t		nset = pset;

	do {
		nset = next_pset(nset);
	} while (nset->online_processor_count < 1 && nset != pset);

	return (nset);
}

/*
 *	choose_processor:
 *
 *	Choose a processor for the thread, beginning at
 *	the pset.  Accepts an optional processor hint in
 *	the pset.
 *
 *	Returns a processor, possibly from a different pset.
 *
 *	The thread must be locked.  The pset must be locked,
 *	and the resulting pset is locked on return.
 */
processor_t
choose_processor(
	processor_set_t		pset,
	processor_t			processor,
	thread_t			thread)
{
	processor_set_t		nset, cset = pset;
	
	/*
	 * Prefer the hinted processor, when appropriate.
	 */

	/* Fold last processor hint from secondary processor to its primary */
	if (processor != PROCESSOR_NULL) {
		processor = processor->processor_primary;
	}

	/*
	 * Only consult platform layer if pset is active, which
	 * it may not be in some cases when a multi-set system
	 * is going to sleep.
	 */
	if (pset->online_processor_count) {
		if ((processor == PROCESSOR_NULL) || (processor->processor_set == pset && processor->state == PROCESSOR_IDLE)) {
			processor_t mc_processor = machine_choose_processor(pset, processor);
			if (mc_processor != PROCESSOR_NULL)
				processor = mc_processor->processor_primary;
		}
	}

	/*
	 * At this point, we may have a processor hint, and we may have
	 * an initial starting pset. If the hint is not in the pset, or
	 * if the hint is for a processor in an invalid state, discard
	 * the hint.
	 */
	if (processor != PROCESSOR_NULL) {
		if (processor->processor_set != pset) {
			processor = PROCESSOR_NULL;
		} else {
			switch (processor->state) {
				case PROCESSOR_START:
				case PROCESSOR_SHUTDOWN:
				case PROCESSOR_OFF_LINE:
					/*
					 * Hint is for a processor that cannot support running new threads.
					 */
					processor = PROCESSOR_NULL;
					break;
				case PROCESSOR_IDLE:
					/*
					 * Hint is for an idle processor. Assume it is no worse than any other
					 * idle processor. The platform layer had an opportunity to provide
					 * the "least cost idle" processor above.
					 */
					return (processor);
					break;
				case PROCESSOR_RUNNING:
				case PROCESSOR_DISPATCHING:
					/*
					 * Hint is for an active CPU. This fast-path allows
					 * realtime threads to preempt non-realtime threads
					 * to regain their previous executing processor.
					 */
					if ((thread->sched_pri >= BASEPRI_RTQUEUES) &&
						(processor->current_pri < BASEPRI_RTQUEUES))
						return (processor);

					/* Otherwise, use hint as part of search below */
					break;
				default:
					processor = PROCESSOR_NULL;
					break;
			}
		}
	}

	/*
	 * Iterate through the processor sets to locate
	 * an appropriate processor. Seed results with
	 * a last-processor hint, if available, so that
	 * a search must find something strictly better
	 * to replace it.
	 *
	 * A primary/secondary pair of SMT processors are
	 * "unpaired" if the primary is busy but its
	 * corresponding secondary is idle (so the physical
	 * core has full use of its resources).
	 */

	integer_t lowest_priority = MAXPRI + 1;
	integer_t lowest_unpaired_primary_priority = MAXPRI + 1;
	integer_t lowest_count = INT_MAX;
	uint64_t  furthest_deadline = 1;
	processor_t lp_processor = PROCESSOR_NULL;
	processor_t lp_unpaired_primary_processor = PROCESSOR_NULL;
	processor_t lp_unpaired_secondary_processor = PROCESSOR_NULL;
	processor_t lc_processor = PROCESSOR_NULL;
	processor_t fd_processor = PROCESSOR_NULL;

	if (processor != PROCESSOR_NULL) {
		/* All other states should be enumerated above. */
		assert(processor->state == PROCESSOR_RUNNING || processor->state == PROCESSOR_DISPATCHING);

		lowest_priority = processor->current_pri;
		lp_processor = processor;

		if (processor->current_pri >= BASEPRI_RTQUEUES) {
			furthest_deadline = processor->deadline;
			fd_processor = processor;
		}

		lowest_count = SCHED(processor_runq_count)(processor);
		lc_processor = processor;
	}

	do {

		/*
		 * Choose an idle processor, in pset traversal order
		 */
		if (!queue_empty(&cset->idle_queue))
			return ((processor_t)queue_first(&cset->idle_queue));

		/*
		 * Otherwise, enumerate active and idle processors to find candidates
		 * with lower priority/etc.
		 */

		processor = (processor_t)queue_first(&cset->active_queue);
		while (!queue_end(&cset->active_queue, (queue_entry_t)processor)) {

			integer_t cpri = processor->current_pri;
			if (cpri < lowest_priority) {
				lowest_priority = cpri;
				lp_processor = processor;
			}

			if ((cpri >= BASEPRI_RTQUEUES) && (processor->deadline > furthest_deadline)) {
				furthest_deadline = processor->deadline;
				fd_processor = processor;
			}

			integer_t ccount = SCHED(processor_runq_count)(processor);
			if (ccount < lowest_count) {
				lowest_count = ccount;
				lc_processor = processor;
			}

			processor = (processor_t)queue_next((queue_entry_t)processor);
		}

		/*
		 * For SMT configs, these idle secondary processors must have active primary. Otherwise
		 * the idle primary would have short-circuited the loop above
		 */
		processor = (processor_t)queue_first(&cset->idle_secondary_queue);
		while (!queue_end(&cset->idle_secondary_queue, (queue_entry_t)processor)) {
			processor_t cprimary = processor->processor_primary;

			/* If the primary processor is offline or starting up, it's not a candidate for this path */
			if (cprimary->state == PROCESSOR_RUNNING || cprimary->state == PROCESSOR_DISPATCHING) {
				integer_t primary_pri = cprimary->current_pri;

				if (primary_pri < lowest_unpaired_primary_priority) {
					lowest_unpaired_primary_priority = primary_pri;
					lp_unpaired_primary_processor = cprimary;
					lp_unpaired_secondary_processor = processor;
				}
			}

			processor = (processor_t)queue_next((queue_entry_t)processor);
		}


		if (thread->sched_pri >= BASEPRI_RTQUEUES) {

			/*
			 * For realtime threads, the most important aspect is
			 * scheduling latency, so we attempt to assign threads
			 * to good preemption candidates (assuming an idle primary
			 * processor was not available above).
			 */

			if (thread->sched_pri > lowest_unpaired_primary_priority) {
				/* Move to end of active queue so that the next thread doesn't also pick it */
				remqueue((queue_entry_t)lp_unpaired_primary_processor);
				enqueue_tail(&cset->active_queue, (queue_entry_t)lp_unpaired_primary_processor);
				return lp_unpaired_primary_processor;
			}
			if (thread->sched_pri > lowest_priority) {
				/* Move to end of active queue so that the next thread doesn't also pick it */
				remqueue((queue_entry_t)lp_processor);
				enqueue_tail(&cset->active_queue, (queue_entry_t)lp_processor);
				return lp_processor;
			}
			if (thread->realtime.deadline < furthest_deadline)
				return fd_processor;

			/*
			 * If all primary and secondary CPUs are busy with realtime
			 * threads with deadlines earlier than us, move on to next
			 * pset.
			 */
		}
		else {

			if (thread->sched_pri > lowest_unpaired_primary_priority) {
				/* Move to end of active queue so that the next thread doesn't also pick it */
				remqueue((queue_entry_t)lp_unpaired_primary_processor);
				enqueue_tail(&cset->active_queue, (queue_entry_t)lp_unpaired_primary_processor);
				return lp_unpaired_primary_processor;
			}
			if (thread->sched_pri > lowest_priority) {
				/* Move to end of active queue so that the next thread doesn't also pick it */
				remqueue((queue_entry_t)lp_processor);
				enqueue_tail(&cset->active_queue, (queue_entry_t)lp_processor);
				return lp_processor;
			}

			/*
			 * If all primary processor in this pset are running a higher
			 * priority thread, move on to next pset. Only when we have
			 * exhausted this search do we fall back to other heuristics.
			 */
		}

		/*
		 * Move onto the next processor set.
		 */
		nset = next_pset(cset);

		if (nset != pset) {
			pset_unlock(cset);

			cset = nset;
			pset_lock(cset);
		}
	} while (nset != pset);

	/*
	 * Make sure that we pick a running processor,
	 * and that the correct processor set is locked.
	 * Since we may have unlock the candidate processor's
	 * pset, it may have changed state.
	 *
	 * All primary processors are running a higher priority
	 * thread, so the only options left are enqueuing on
	 * the secondary processor that would perturb the least priority
	 * primary, or the least busy primary.
	 */
	do {

		/* lowest_priority is evaluated in the main loops above */
		if (lp_unpaired_secondary_processor != PROCESSOR_NULL) {
			processor = lp_unpaired_secondary_processor;
			lp_unpaired_secondary_processor = PROCESSOR_NULL;
		} else if (lc_processor != PROCESSOR_NULL) {
			processor = lc_processor;
			lc_processor = PROCESSOR_NULL;
		} else {
			/*
			 * All processors are executing higher
			 * priority threads, and the lowest_count
			 * candidate was not usable
			 */
			processor = master_processor;
		}

		/*
		 * Check that the correct processor set is
		 * returned locked.
		 */
		if (cset != processor->processor_set) {
			pset_unlock(cset);
			cset = processor->processor_set;
			pset_lock(cset);
		}

		/*
		 * We must verify that the chosen processor is still available.
		 * master_processor is an exception, since we may need to preempt
		 * a running thread on it during processor shutdown (for sleep),
		 * and that thread needs to be enqueued on its runqueue to run
		 * when the processor is restarted.
		 */
		if (processor != master_processor && (processor->state == PROCESSOR_SHUTDOWN || processor->state == PROCESSOR_OFF_LINE))
			processor = PROCESSOR_NULL;

	} while (processor == PROCESSOR_NULL);

	return (processor);
}

/*
 *	thread_setrun:
 *
 *	Dispatch thread for execution, onto an idle
 *	processor or run queue, and signal a preemption
 *	as appropriate.
 *
 *	Thread must be locked.
 */
void
thread_setrun(
	thread_t			thread,
	integer_t			options)
{
	processor_t			processor;
	processor_set_t		pset;

	assert(thread_runnable(thread));
	
	/*
	 *	Update priority if needed.
	 */
	if (SCHED(can_update_priority)(thread))
		SCHED(update_priority)(thread);

	thread->sfi_class = sfi_thread_classify(thread);

	assert(thread->runq == PROCESSOR_NULL);

	if (thread->bound_processor == PROCESSOR_NULL) {
		/*
		 *	Unbound case.
		 */
		if (thread->affinity_set != AFFINITY_SET_NULL) {
			/*
			 * Use affinity set policy hint.
			 */
			pset = thread->affinity_set->aset_pset;
			pset_lock(pset);

			processor = SCHED(choose_processor)(pset, PROCESSOR_NULL, thread);

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR)|DBG_FUNC_NONE,
									  (uintptr_t)thread_tid(thread), (uintptr_t)-1, processor->cpu_id, processor->state, 0);
		}
		else
		if (thread->last_processor != PROCESSOR_NULL) {
			/*
			 *	Simple (last processor) affinity case.
			 */
			processor = thread->last_processor;
			pset = processor->processor_set;
			pset_lock(pset);
			processor = SCHED(choose_processor)(pset, processor, thread);

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR)|DBG_FUNC_NONE,
								  (uintptr_t)thread_tid(thread), thread->last_processor->cpu_id, processor->cpu_id, processor->state, 0);
		}
		else {
			/*
			 *	No Affinity case:
			 *
			 *	Utilitize a per task hint to spread threads
			 *	among the available processor sets.
			 */
			task_t		task = thread->task;

			pset = task->pset_hint;
			if (pset == PROCESSOR_SET_NULL)
				pset = current_processor()->processor_set;

			pset = choose_next_pset(pset);
			pset_lock(pset);

			processor = SCHED(choose_processor)(pset, PROCESSOR_NULL, thread);
			task->pset_hint = processor->processor_set;

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR)|DBG_FUNC_NONE,
									  (uintptr_t)thread_tid(thread), (uintptr_t)-1, processor->cpu_id, processor->state, 0);
		}
	}
	else {
		/*
		 *	Bound case:
		 *
		 *	Unconditionally dispatch on the processor.
		 */
		processor = thread->bound_processor;
		pset = processor->processor_set;
		pset_lock(pset);

		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_CHOOSE_PROCESSOR)|DBG_FUNC_NONE,
							  (uintptr_t)thread_tid(thread), (uintptr_t)-2, processor->cpu_id, processor->state, 0);
	}

	/*
	 *	Dispatch the thread on the choosen processor.
	 *	TODO: This should be based on sched_mode, not sched_pri
	 */
	if (thread->sched_pri >= BASEPRI_RTQUEUES)
		realtime_setrun(processor, thread);
	else if (thread->sched_mode == TH_MODE_FAIRSHARE)
		fairshare_setrun(processor, thread);
	else
		processor_setrun(processor, thread, options);
}

processor_set_t
task_choose_pset(
	task_t		task)
{
	processor_set_t		pset = task->pset_hint;

	if (pset != PROCESSOR_SET_NULL)
		pset = choose_next_pset(pset);

	return (pset);
}

#if defined(CONFIG_SCHED_TRADITIONAL)

/*
 *	processor_queue_shutdown:
 *
 *	Shutdown a processor run queue by
 *	re-dispatching non-bound threads.
 *
 *	Associated pset must be locked, and is
 *	returned unlocked.
 */
void
processor_queue_shutdown(
	processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	run_queue_t			rq = runq_for_processor(processor);
	queue_t				queue = rq->queues + rq->highq;
	int					pri = rq->highq, count = rq->count;
	thread_t			next, thread;
	queue_head_t		tqueue;

	queue_init(&tqueue);
	
	while (count > 0) {
		thread = (thread_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			next = (thread_t)queue_next((queue_entry_t)thread);

			if (thread->bound_processor == PROCESSOR_NULL) {
				remqueue((queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
				runq_consider_decr_bound_count(processor, thread);
				rq->count--;
				if (SCHED(priority_is_urgent)(pri)) {
					rq->urgency--; assert(rq->urgency >= 0);
				}
				if (queue_empty(queue)) {
					if (pri != IDLEPRI)
						clrbit(MAXPRI - pri, rq->bitmap);
					rq->highq = MAXPRI - ffsbit(rq->bitmap);
				}

				enqueue_tail(&tqueue, (queue_entry_t)thread);
			}
			count--;

			thread = next;
		}

		queue--; pri--;
	}

	pset_unlock(pset);

	while ((thread = (thread_t)dequeue_head(&tqueue)) != THREAD_NULL) {
		thread_lock(thread);

		thread_setrun(thread, SCHED_TAILQ);

		thread_unlock(thread);
	}
}

#endif /* CONFIG_SCHED_TRADITIONAL */

/*
 *	Check for a preemption point in
 *	the current context.
 *
 *	Called at splsched with thread locked.
 */
ast_t
csw_check(
	processor_t		processor,
	ast_t			check_reason)
{
	processor_set_t	pset = processor->processor_set;
	ast_t			result;

	pset_lock(pset);

	/* If we were sent a remote AST and interrupted a running processor, acknowledge it here with pset lock held */
	pset->pending_AST_cpu_mask &= ~(1U << processor->cpu_id);

	result = csw_check_locked(processor, pset, check_reason);

	pset_unlock(pset);

	return result;
}

/*
 * Check for preemption at splsched with
 * pset and thread locked
 */
ast_t
csw_check_locked(
	processor_t		processor,
	processor_set_t	pset __unused,
	ast_t			check_reason)
{
	ast_t			result;
	thread_t		thread = processor->active_thread;

	if (first_timeslice(processor)) {
		if (rt_runq.count > 0)
			return (check_reason | AST_PREEMPT | AST_URGENT);
	}
	else {
		if (rt_runq.count > 0) {
			if (BASEPRI_RTQUEUES > processor->current_pri)
				return (check_reason | AST_PREEMPT | AST_URGENT);
			else
				return (check_reason | AST_PREEMPT);
		}
	}

	result = SCHED(processor_csw_check)(processor);
	if (result != AST_NONE)
		return (check_reason | result);

	if (SCHED(should_current_thread_rechoose_processor)(processor))
		return (check_reason | AST_PREEMPT);
	
	if (thread->state & TH_SUSP)
		return (check_reason | AST_PREEMPT);

	/*
	 * Current thread may not need to be preempted, but maybe needs
	 * an SFI wait?
	 */
	result = sfi_thread_needs_ast(thread, NULL);
	if (result != AST_NONE)
		return (check_reason | result);

	return (AST_NONE);
}

/*
 *	set_sched_pri:
 *
 *	Set the scheduled priority of the specified thread.
 *
 *	This may cause the thread to change queues.
 *
 *	Thread must be locked.
 */
void
set_sched_pri(
	thread_t		thread,
	int			priority)
{
	boolean_t		removed = thread_run_queue_remove(thread);
	int curgency, nurgency;
	uint64_t urgency_param1, urgency_param2;
	thread_t cthread = current_thread();

	if (thread == cthread) {
		curgency = thread_get_urgency(thread, &urgency_param1, &urgency_param2);
	}
	
	thread->sched_pri = priority;

	if (thread == cthread) {
		nurgency = thread_get_urgency(thread, &urgency_param1, &urgency_param2);
/* set_sched_pri doesn't alter RT params. We expect direct base priority/QoS
 * class alterations from user space to occur relatively infrequently, hence
 * those are lazily handled. QoS classes have distinct priority bands, and QoS
 * inheritance is expected to involve priority changes.
 */
		if (nurgency != curgency) {
			thread_tell_urgency(nurgency, urgency_param1, urgency_param2, thread);
		}
	}

	if (removed)
		thread_setrun(thread, SCHED_PREEMPT | SCHED_TAILQ);
	else
	if (thread->state & TH_RUN) {
		processor_t		processor = thread->last_processor;

		if (thread == current_thread()) {
			ast_t			preempt;

			processor->current_pri = priority;
			processor->current_thmode = thread->sched_mode;
			processor->current_sfi_class = thread->sfi_class = sfi_thread_classify(thread);
			if ((preempt = csw_check(processor, AST_NONE)) != AST_NONE)
				ast_on(preempt);
		}
		else
		if (	processor != PROCESSOR_NULL						&&
				processor->active_thread == thread	)
			cause_ast_check(processor);
	}
}

#if		0

static void
run_queue_check(
	run_queue_t		rq,
	thread_t		thread)
{
	queue_t			q;
	queue_entry_t	qe;

	if (rq != thread->runq)
		panic("run_queue_check: thread runq");

	if (thread->sched_pri > MAXPRI || thread->sched_pri < MINPRI)
		panic("run_queue_check: thread sched_pri");

	q = &rq->queues[thread->sched_pri];
	qe = queue_first(q);
	while (!queue_end(q, qe)) {
		if (qe == (queue_entry_t)thread)
			return;

		qe = queue_next(qe);
	}

	panic("run_queue_check: end");
}

#endif	/* DEBUG */

#if defined(CONFIG_SCHED_TRADITIONAL)

/*
 * Locks the runqueue itself.
 *
 * Thread must be locked.
 */
static boolean_t
processor_queue_remove(
					   processor_t			processor,
					   thread_t		thread)
{
	void *			rqlock;
	run_queue_t		rq;
	
	rqlock = &processor->processor_set->sched_lock;
	rq = runq_for_processor(processor);

	simple_lock(rqlock);
	if (processor == thread->runq) {
		/*
		 *	Thread is on a run queue and we have a lock on
		 *	that run queue.
		 */
		runq_consider_decr_bound_count(processor, thread);
		run_queue_remove(rq, thread);
	}
	else {
		/*
		 *	The thread left the run queue before we could
		 * 	lock the run queue.
		 */
		assert(thread->runq == PROCESSOR_NULL);
		processor = PROCESSOR_NULL;
	}
	
	simple_unlock(rqlock);

	return (processor != PROCESSOR_NULL);
}

#endif /* CONFIG_SCHED_TRADITIONAL */


/*
 *	thread_run_queue_remove:
 *
 *	Remove a thread from its current run queue and
 *	return TRUE if successful.
 *
 *	Thread must be locked.
 *
 *	If thread->runq is PROCESSOR_NULL, the thread will not re-enter the
 *	run queues because the caller locked the thread.  Otherwise
 *	the thread is on a run queue, but could be chosen for dispatch
 *	and removed by another processor under a different lock, which
 *	will set thread->runq to PROCESSOR_NULL.
 *
 *	Hence the thread select path must not rely on anything that could
 *	be changed under the thread lock after calling this function,
 *	most importantly thread->sched_pri.
 */
boolean_t
thread_run_queue_remove(
                        thread_t        thread)
{
	boolean_t removed = FALSE;
	processor_t processor = thread->runq;

	if ((thread->state & (TH_RUN|TH_WAIT)) == TH_WAIT) {
		/* Thread isn't runnable */
		assert(thread->runq == PROCESSOR_NULL);
		return FALSE;
	}

	if (processor == PROCESSOR_NULL) {
		/*
		 * The thread is either not on the runq,
		 * or is in the midst of being removed from the runq.
		 *
		 * runq is set to NULL under the pset lock, not the thread
		 * lock, so the thread may still be in the process of being dequeued
		 * from the runq. It will wait in invoke for the thread lock to be
		 * dropped.
		 */

		return FALSE;
	}

	if (thread->sched_mode == TH_MODE_FAIRSHARE) {
		return SCHED(fairshare_queue_remove)(thread);
	}
	
	if (thread->sched_pri < BASEPRI_RTQUEUES) {
		return SCHED(processor_queue_remove)(processor, thread);
	}

	simple_lock(&rt_lock);

	if (thread->runq != PROCESSOR_NULL) {
		/*
		 *	Thread is on a run queue and we have a lock on
		 *	that run queue.
		 */

		assert(thread->runq == RT_RUNQ);

		remqueue((queue_entry_t)thread);
		SCHED_STATS_RUNQ_CHANGE(&rt_runq.runq_stats, rt_runq.count);
		rt_runq.count--;

		thread->runq = PROCESSOR_NULL;

		removed = TRUE;
	}

	simple_unlock(&rt_lock);

	return (removed);
}

#if defined(CONFIG_SCHED_TRADITIONAL)

/*
 *	steal_processor_thread:
 *
 *	Locate a thread to steal from the processor and
 *	return it.
 *
 *	Associated pset must be locked.  Returns THREAD_NULL
 *	on failure.
 */
static thread_t
steal_processor_thread(
	processor_t		processor)
{
	run_queue_t		rq = runq_for_processor(processor);
	queue_t			queue = rq->queues + rq->highq;
	int				pri = rq->highq, count = rq->count;
	thread_t		thread;

	while (count > 0) {
		thread = (thread_t)queue_first(queue);
		while (!queue_end(queue, (queue_entry_t)thread)) {
			if (thread->bound_processor == PROCESSOR_NULL) {
				remqueue((queue_entry_t)thread);

				thread->runq = PROCESSOR_NULL;
				SCHED_STATS_RUNQ_CHANGE(&rq->runq_stats, rq->count);
				runq_consider_decr_bound_count(processor, thread);
				rq->count--;
				if (SCHED(priority_is_urgent)(pri)) {
					rq->urgency--; assert(rq->urgency >= 0);
				}
				if (queue_empty(queue)) {
					if (pri != IDLEPRI)
						clrbit(MAXPRI - pri, rq->bitmap);
					rq->highq = MAXPRI - ffsbit(rq->bitmap);
				}

				return (thread);
			}
			count--;

			thread = (thread_t)queue_next((queue_entry_t)thread);
		}

		queue--; pri--;
	}

	return (THREAD_NULL);
}

/*
 *	Locate and steal a thread, beginning
 *	at the pset.
 *
 *	The pset must be locked, and is returned
 *	unlocked.
 *
 *	Returns the stolen thread, or THREAD_NULL on
 *	failure.
 */
static thread_t
steal_thread(
	processor_set_t		pset)
{
	processor_set_t		nset, cset = pset;
	processor_t			processor;
	thread_t			thread;

	do {
		processor = (processor_t)queue_first(&cset->active_queue);
		while (!queue_end(&cset->active_queue, (queue_entry_t)processor)) {
			if (runq_for_processor(processor)->count > 0) {
				thread = steal_processor_thread(processor);
				if (thread != THREAD_NULL) {
					remqueue((queue_entry_t)processor);
					enqueue_tail(&cset->active_queue, (queue_entry_t)processor);

					pset_unlock(cset);

					return (thread);
				}
			}

			processor = (processor_t)queue_next((queue_entry_t)processor);
		}

		nset = next_pset(cset);

		if (nset != pset) {
			pset_unlock(cset);

			cset = nset;
			pset_lock(cset);
		}
	} while (nset != pset);

	pset_unlock(cset);

	return (THREAD_NULL);
}

static thread_t	steal_thread_disabled(
					processor_set_t		pset)
{
	pset_unlock(pset);

	return (THREAD_NULL);
}

#endif /* CONFIG_SCHED_TRADITIONAL */


void
sys_override_cpu_throttle(int flag)
{
	if (flag == CPU_THROTTLE_ENABLE)
		cpu_throttle_enabled = 1;
	if (flag == CPU_THROTTLE_DISABLE)
		cpu_throttle_enabled = 0;
}

int
thread_get_urgency(thread_t thread, uint64_t *arg1, uint64_t *arg2)
{
	if (thread == NULL || (thread->state & TH_IDLE)) {
		*arg1 = 0;
		*arg2 = 0;

		return (THREAD_URGENCY_NONE);
	} else if (thread->sched_mode == TH_MODE_REALTIME) {
		*arg1 = thread->realtime.period;
		*arg2 = thread->realtime.deadline;

		return (THREAD_URGENCY_REAL_TIME);
	} else if (cpu_throttle_enabled &&
		   ((thread->sched_pri <= MAXPRI_THROTTLE) && (thread->priority <= MAXPRI_THROTTLE)))  {
		/*
		 * Background urgency applied when thread priority is MAXPRI_THROTTLE or lower and thread is not promoted
		 * TODO: Use TH_SFLAG_THROTTLED instead?
		 */
		*arg1 = thread->sched_pri;
		*arg2 = thread->priority;

		return (THREAD_URGENCY_BACKGROUND);
	} else {
		/* For otherwise unclassified threads, report throughput QoS
		 * parameters
		 */
		*arg1 = thread->effective_policy.t_through_qos;
		*arg2 = thread->task->effective_policy.t_through_qos;
		
		return (THREAD_URGENCY_NORMAL);
	}
}


/*
 *	This is the processor idle loop, which just looks for other threads
 *	to execute.  Processor idle threads invoke this without supplying a
 *	current thread to idle without an asserted wait state.
 *
 *	Returns a the next thread to execute if dispatched directly.
 */

#if 0
#define IDLE_KERNEL_DEBUG_CONSTANT(...) KERNEL_DEBUG_CONSTANT(__VA_ARGS__)
#else
#define IDLE_KERNEL_DEBUG_CONSTANT(...) do { } while(0)
#endif

thread_t
processor_idle(
	thread_t			thread,
	processor_t			processor)
{
	processor_set_t		pset = processor->processor_set;
	thread_t			new_thread;
	int					state;
	(void)splsched();

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_START, 
		(uintptr_t)thread_tid(thread), 0, 0, 0, 0);

	SCHED_STATS_CPU_IDLE_START(processor);

	timer_switch(&PROCESSOR_DATA(processor, system_state),
									mach_absolute_time(), &PROCESSOR_DATA(processor, idle_state));
	PROCESSOR_DATA(processor, current_state) = &PROCESSOR_DATA(processor, idle_state);

	while (1) {
		if (processor->state != PROCESSOR_IDLE) /* unsafe, but worst case we loop around once */
			break;
		if (pset->pending_AST_cpu_mask & (1U << processor->cpu_id))
			break;
		if (rt_runq.count)
			break;
#if CONFIG_SCHED_IDLE_IN_PLACE
		if (thread != THREAD_NULL) {
			/* Did idle-in-place thread wake up */
			if ((thread->state & (TH_WAIT|TH_SUSP)) != TH_WAIT || thread->wake_active)
				break;
		}
#endif

		IDLE_KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), rt_runq.count, SCHED(processor_runq_count)(processor), -1, 0);

		machine_track_platform_idle(TRUE);

		machine_idle();

		machine_track_platform_idle(FALSE);

		(void)splsched();

		IDLE_KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_NONE, (uintptr_t)thread_tid(thread), rt_runq.count, SCHED(processor_runq_count)(processor), -2, 0);

		if (!SCHED(processor_queue_empty)(processor)) {
			/* Secondary SMT processors respond to directed wakeups
			 * exclusively. Some platforms induce 'spurious' SMT wakeups.
			 */
			if (processor->processor_primary == processor)
					break;
		}
	}

	timer_switch(&PROCESSOR_DATA(processor, idle_state),
									mach_absolute_time(), &PROCESSOR_DATA(processor, system_state));
	PROCESSOR_DATA(processor, current_state) = &PROCESSOR_DATA(processor, system_state);

	pset_lock(pset);

	/* If we were sent a remote AST and came out of idle, acknowledge it here with pset lock held */
	pset->pending_AST_cpu_mask &= ~(1U << processor->cpu_id);

	state = processor->state;
	if (state == PROCESSOR_DISPATCHING) {
		/*
		 *	Commmon case -- cpu dispatched.
		 */
		new_thread = processor->next_thread;
		processor->next_thread = THREAD_NULL;
		processor->state = PROCESSOR_RUNNING;

		if ((new_thread != THREAD_NULL) && (SCHED(processor_queue_has_priority)(processor, new_thread->sched_pri, FALSE)					||
											(rt_runq.count > 0 && BASEPRI_RTQUEUES >= new_thread->sched_pri))	) {
   			/* Something higher priority has popped up on the runqueue - redispatch this thread elsewhere */
			processor->current_pri = IDLEPRI;
			processor->current_thmode = TH_MODE_FIXED;
			processor->current_sfi_class = SFI_CLASS_KERNEL;
			processor->deadline = UINT64_MAX;

			pset_unlock(pset);

			thread_lock(new_thread);
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_REDISPATCH), (uintptr_t)thread_tid(new_thread), new_thread->sched_pri, rt_runq.count, 0, 0);
			thread_setrun(new_thread, SCHED_HEADQ);
			thread_unlock(new_thread);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, 
				(uintptr_t)thread_tid(thread), state, 0, 0, 0);

			return (THREAD_NULL);
		}

		pset_unlock(pset);

		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, 
			(uintptr_t)thread_tid(thread), state, (uintptr_t)thread_tid(new_thread), 0, 0);
			
		return (new_thread);
	}
	else
	if (state == PROCESSOR_IDLE) {
		remqueue((queue_entry_t)processor);

		processor->state = PROCESSOR_RUNNING;
		processor->current_pri = IDLEPRI;
		processor->current_thmode = TH_MODE_FIXED;
		processor->current_sfi_class = SFI_CLASS_KERNEL;
		processor->deadline = UINT64_MAX;
		enqueue_tail(&pset->active_queue, (queue_entry_t)processor);
	}
	else
	if (state == PROCESSOR_SHUTDOWN) {
		/*
		 *	Going off-line.  Force a
		 *	reschedule.
		 */
		if ((new_thread = processor->next_thread) != THREAD_NULL) {
			processor->next_thread = THREAD_NULL;
			processor->current_pri = IDLEPRI;
			processor->current_thmode = TH_MODE_FIXED;
			processor->current_sfi_class = SFI_CLASS_KERNEL;
			processor->deadline = UINT64_MAX;

			pset_unlock(pset);

			thread_lock(new_thread);
			thread_setrun(new_thread, SCHED_HEADQ);
			thread_unlock(new_thread);

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, 
				(uintptr_t)thread_tid(thread), state, 0, 0, 0);
		
			return (THREAD_NULL);
		}
	}

	pset_unlock(pset);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		MACHDBG_CODE(DBG_MACH_SCHED,MACH_IDLE) | DBG_FUNC_END, 
		(uintptr_t)thread_tid(thread), state, 0, 0, 0);
		
	return (THREAD_NULL);
}

/*
 *	Each processor has a dedicated thread which
 *	executes the idle loop when there is no suitable
 *	previous context.
 */
void
idle_thread(void)
{
	processor_t		processor = current_processor();
	thread_t		new_thread;

	new_thread = processor_idle(THREAD_NULL, processor);
	if (new_thread != THREAD_NULL) {
		thread_run(processor->idle_thread, (thread_continue_t)idle_thread, NULL, new_thread);
		/*NOTREACHED*/
	}

	thread_block((thread_continue_t)idle_thread);
	/*NOTREACHED*/
}

kern_return_t
idle_thread_create(
	processor_t		processor)
{
	kern_return_t	result;
	thread_t		thread;
	spl_t			s;

	result = kernel_thread_create((thread_continue_t)idle_thread, NULL, MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		return (result);

	s = splsched();
	thread_lock(thread);
	thread->bound_processor = processor;
	processor->idle_thread = thread;
	thread->sched_pri = thread->priority = IDLEPRI;
	thread->state = (TH_RUN | TH_IDLE);
	thread->options |= TH_OPT_IDLE_THREAD;
	thread_unlock(thread);
	splx(s);

	thread_deallocate(thread);

	return (KERN_SUCCESS);
}

/*
 * sched_startup:
 *
 * Kicks off scheduler services.
 *
 * Called at splsched.
 */
void
sched_startup(void)
{
	kern_return_t	result;
	thread_t		thread;

	result = kernel_thread_start_priority((thread_continue_t)sched_init_thread,
	    (void *)SCHED(maintenance_continuation), MAXPRI_KERNEL, &thread);
	if (result != KERN_SUCCESS)
		panic("sched_startup");

	thread_deallocate(thread);

	/*
	 * Yield to the sched_init_thread once, to
	 * initialize our own thread after being switched
	 * back to.
	 *
	 * The current thread is the only other thread
	 * active at this point.
	 */
	thread_block(THREAD_CONTINUE_NULL);
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

static volatile uint64_t 		sched_maintenance_deadline;
#if defined(CONFIG_TELEMETRY)
static volatile uint64_t		sched_telemetry_deadline = 0;
#endif
static uint64_t				sched_tick_last_abstime;
static uint64_t				sched_tick_delta;
uint64_t				sched_tick_max_delta;
/*
 *	sched_init_thread:
 *
 *	Perform periodic bookkeeping functions about ten
 *	times per second.
 */
void
sched_traditional_maintenance_continue(void)
{
	uint64_t	sched_tick_ctime, late_time;

	sched_tick_ctime = mach_absolute_time();	

	if (__improbable(sched_tick_last_abstime == 0)) {
		sched_tick_last_abstime = sched_tick_ctime;
		late_time = 0;
		sched_tick_delta = 1;
	} else {
		late_time = sched_tick_ctime - sched_tick_last_abstime;
		sched_tick_delta = late_time / sched_tick_interval;
		/* Ensure a delta of 1, since the interval could be slightly
		 * smaller than the sched_tick_interval due to dispatch
		 * latencies.
		 */
		sched_tick_delta = MAX(sched_tick_delta, 1);

		/* In the event interrupt latencies or platform
		 * idle events that advanced the timebase resulted
		 * in periods where no threads were dispatched,
		 * cap the maximum "tick delta" at SCHED_TICK_MAX_DELTA
		 * iterations.
		 */
		sched_tick_delta = MIN(sched_tick_delta, SCHED_TICK_MAX_DELTA);

		sched_tick_last_abstime = sched_tick_ctime;
		sched_tick_max_delta = MAX(sched_tick_delta, sched_tick_max_delta);
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_MAINTENANCE)|DBG_FUNC_START,
						  sched_tick_delta,
						  late_time,
						  0,
						  0,
						  0);

	/* Add a number of pseudo-ticks corresponding to the elapsed interval
	 * This could be greater than 1 if substantial intervals where
	 * all processors are idle occur, which rarely occurs in practice.
	 */
	
	sched_tick += sched_tick_delta;

	/*
	 *  Compute various averages.
	 */
	compute_averages(sched_tick_delta);

	/*
	 *  Scan the run queues for threads which
	 *  may need to be updated.
	 */
	SCHED(thread_update_scan)();

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_MAINTENANCE)|DBG_FUNC_END,
						  sched_pri_shift,
						  sched_background_pri_shift,
						  0,
						  0,
						  0);

	assert_wait((event_t)sched_traditional_maintenance_continue, THREAD_UNINT);
	thread_block((thread_continue_t)sched_traditional_maintenance_continue);
	/*NOTREACHED*/
}

static uint64_t sched_maintenance_wakeups;

/*
 * Determine if the set of routines formerly driven by a maintenance timer
 * must be invoked, based on a deadline comparison. Signals the scheduler
 * maintenance thread on deadline expiration. Must be invoked at an interval
 * lower than the "sched_tick_interval", currently accomplished by
 * invocation via the quantum expiration timer and at context switch time.
 * Performance matters: this routine reuses a timestamp approximating the
 * current absolute time received from the caller, and should perform
 * no more than a comparison against the deadline in the common case.
 */
void
sched_traditional_consider_maintenance(uint64_t ctime) {
	uint64_t ndeadline, deadline = sched_maintenance_deadline;

	if (__improbable(ctime >= deadline)) {
		if (__improbable(current_thread() == sched_maintenance_thread))
			return;
		OSMemoryBarrier();

		ndeadline = ctime + sched_tick_interval;

		if (__probable(__sync_bool_compare_and_swap(&sched_maintenance_deadline, deadline, ndeadline))) {
			thread_wakeup((event_t)sched_traditional_maintenance_continue);
			sched_maintenance_wakeups++;
		}
	}

#if defined(CONFIG_TELEMETRY)
	/*
	 * Windowed telemetry is driven by the scheduler.  It should be safe
	 * to call compute_telemetry_windowed() even when windowed telemetry
	 * is disabled, but we should try to avoid doing extra work for no
	 * reason.
	 */
	if (telemetry_window_enabled) {
		deadline = sched_telemetry_deadline;

		if (__improbable(ctime >= deadline)) {
			ndeadline = ctime + sched_telemetry_interval;

			if (__probable(__sync_bool_compare_and_swap(&sched_telemetry_deadline, deadline, ndeadline))) {
				compute_telemetry_windowed();
			}
		}
	}
#endif /* CONFIG_TELEMETRY */
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

void
sched_init_thread(void (*continuation)(void))
{
	thread_block(THREAD_CONTINUE_NULL);

	sched_maintenance_thread = current_thread();
	continuation();

	/*NOTREACHED*/
}

#if defined(CONFIG_SCHED_TIMESHARE_CORE)

/*
 *	thread_update_scan / runq_scan:
 *
 *	Scan the run queues to account for timesharing threads 
 *	which need to be updated.
 *
 *	Scanner runs in two passes.  Pass one squirrels likely
 *	threads away in an array, pass two does the update.
 *
 *	This is necessary because the run queue is locked for
 *	the candidate scan, but	the thread is locked for the update.
 *
 *	Array should be sized to make forward progress, without
 *	disabling preemption for long periods.
 */

#define	THREAD_UPDATE_SIZE		128

static thread_t		thread_update_array[THREAD_UPDATE_SIZE];
static int			thread_update_count = 0;

/* Returns TRUE if thread was added, FALSE if thread_update_array is full */
boolean_t
thread_update_add_thread(thread_t thread)
{
	if (thread_update_count == THREAD_UPDATE_SIZE)
		return (FALSE);

	thread_update_array[thread_update_count++] = thread;
	thread_reference_internal(thread);
	return (TRUE);
}

void
thread_update_process_threads(void)
{
	while (thread_update_count > 0) {
		spl_t   s;
		thread_t thread = thread_update_array[--thread_update_count];
		thread_update_array[thread_update_count] = THREAD_NULL;

		s = splsched();
		thread_lock(thread);
		if (!(thread->state & (TH_WAIT)) && (SCHED(can_update_priority)(thread))) {
			SCHED(update_priority)(thread);
		}
		thread_unlock(thread);
		splx(s);

		thread_deallocate(thread);
	}
}

/*
 *	Scan a runq for candidate threads.
 *
 *	Returns TRUE if retry is needed.
 */
boolean_t
runq_scan(
	run_queue_t				runq)
{
	register int			count;
	register queue_t		q;
	register thread_t		thread;

	if ((count = runq->count) > 0) {
	    q = runq->queues + runq->highq;
		while (count > 0) {
			queue_iterate(q, thread, thread_t, links) {
				if (		thread->sched_stamp != sched_tick		&&
						(thread->sched_mode == TH_MODE_TIMESHARE)	) {
					if (thread_update_add_thread(thread) == FALSE)
						return (TRUE);
				}

				count--;
			}

			q--;
		}
	}

	return (FALSE);
}

#endif /* CONFIG_SCHED_TIMESHARE_CORE */

#if defined(CONFIG_SCHED_TRADITIONAL)

static void
thread_update_scan(void)
{
	boolean_t			restart_needed = FALSE;
	processor_t			processor = processor_list;
	processor_set_t		pset;
	thread_t			thread;
	spl_t				s;

	do {
		do {
			/*
			 * TODO: in sched_traditional_use_pset_runqueue case,
			 *  avoid scanning the same runq multiple times
			 */
			pset = processor->processor_set;

			s = splsched();
			pset_lock(pset);

			restart_needed = runq_scan(runq_for_processor(processor));

			pset_unlock(pset);
			splx(s);

			if (restart_needed)
				break;

			thread = processor->idle_thread;
			if (thread != THREAD_NULL && thread->sched_stamp != sched_tick) {
				if (thread_update_add_thread(thread) == FALSE) {
					restart_needed = TRUE;
					break;
				}
			}
		} while ((processor = processor->processor_list) != NULL);

		/* Ok, we now have a collection of candidates -- fix them. */
		thread_update_process_threads();
	} while (restart_needed);
}

#endif /* CONFIG_SCHED_TRADITIONAL */

boolean_t
thread_eager_preemption(thread_t thread) 
{
	return ((thread->sched_flags & TH_SFLAG_EAGERPREEMPT) != 0);
}

void
thread_set_eager_preempt(thread_t thread) 
{
	spl_t x;
	processor_t p;
	ast_t ast = AST_NONE;

	x = splsched();
	p = current_processor();

	thread_lock(thread);
	thread->sched_flags |= TH_SFLAG_EAGERPREEMPT;

	if (thread == current_thread()) {

		ast = csw_check(p, AST_NONE);
		thread_unlock(thread);
		if (ast != AST_NONE) {
			(void) thread_block_reason(THREAD_CONTINUE_NULL, NULL, ast);
		}
	} else {
		p = thread->last_processor;

		if (p != PROCESSOR_NULL	&& p->state == PROCESSOR_RUNNING &&
			p->active_thread == thread) {
			cause_ast_check(p);
		}
		
		thread_unlock(thread);
	}

	splx(x);
}

void
thread_clear_eager_preempt(thread_t thread) 
{
	spl_t x;

	x = splsched();
	thread_lock(thread);

	thread->sched_flags &= ~TH_SFLAG_EAGERPREEMPT;
	
	thread_unlock(thread);
	splx(x);
}
/*
 * Scheduling statistics
 */
void
sched_stats_handle_csw(processor_t processor, int reasons, int selfpri, int otherpri)
{
	struct processor_sched_statistics *stats;
	boolean_t to_realtime = FALSE;
	
	stats = &processor->processor_data.sched_stats;
	stats->csw_count++;

	if (otherpri >= BASEPRI_REALTIME) {
		stats->rt_sched_count++;
		to_realtime = TRUE;
	}

	if ((reasons & AST_PREEMPT) != 0) {
		stats->preempt_count++;

		if (selfpri >= BASEPRI_REALTIME) {
			stats->preempted_rt_count++;
		} 

		if (to_realtime) {
			stats->preempted_by_rt_count++;
		}

	}
}

void
sched_stats_handle_runq_change(struct runq_stats *stats, int old_count) 
{
	uint64_t timestamp = mach_absolute_time();

	stats->count_sum += (timestamp - stats->last_change_timestamp) * old_count;
	stats->last_change_timestamp = timestamp;
}

/*
 *     For calls from assembly code
 */
#undef thread_wakeup
void
thread_wakeup(
       event_t         x);

void
thread_wakeup(
       event_t         x)
{
       thread_wakeup_with_result(x, THREAD_AWAKENED);
}

boolean_t
preemption_enabled(void)
{
	return (get_preemption_level() == 0 && ml_get_interrupts_enabled());
}

__assert_only static boolean_t
thread_runnable(
	thread_t	thread)
{
	return ((thread->state & (TH_RUN|TH_WAIT)) == TH_RUN);
}

static void
sched_timer_deadline_tracking_init(void) {
	nanoseconds_to_absolutetime(TIMER_DEADLINE_TRACKING_BIN_1_DEFAULT, &timer_deadline_tracking_bin_1);
	nanoseconds_to_absolutetime(TIMER_DEADLINE_TRACKING_BIN_2_DEFAULT, &timer_deadline_tracking_bin_2);
}
