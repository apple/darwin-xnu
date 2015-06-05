/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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
#include <kern/assert.h>
#include <kern/clock.h>
#include <kern/debug.h>
#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/kern_types.h>
#include <kern/machine.h>
#include <kern/simple_lock.h>
#include <kern/misc_protos.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/sfi.h>
#include <kern/timer_call.h>
#include <kern/wait_queue.h>
#include <kern/ledger.h>
#include <kern/coalition.h>

#include <pexpert/pexpert.h>

#include <libkern/kernel_mach_header.h>

#include <sys/kdebug.h>

#define SFI_DEBUG 0

#if SFI_DEBUG
#define dprintf(...) kprintf(__VA_ARGS__)
#else
#define dprintf(...) do { } while(0)
#endif

#ifdef MACH_BSD
extern sched_call_t workqueue_get_sched_callback(void);
#endif /* MACH_BSD */

/*
 * SFI (Selective Forced Idle) operates by enabling a global
 * timer on the SFI window interval. When it fires, all processors
 * running a thread that should be SFI-ed are sent an AST.
 * As threads become runnable while in their "off phase", they
 * are placed on a deferred ready queue. When a per-class
 * "on timer" fires, the ready threads for that class are
 * re-enqueued for running. As an optimization to avoid spurious
 * wakeups, the timer may be lazily programmed.
 */

/*
 * The "sfi_lock" simple lock guards access to static configuration
 * parameters (as specified by userspace), dynamic state changes
 * (as updated by the timer event routine), and timer data structures.
 * Since it can be taken with interrupts disabled in some cases, all
 * uses should be taken with interrupts disabled at splsched(). The
 * "sfi_lock" also guards the "sfi_wait_class" field of thread_t, and
 * must only be accessed with it held.
 *
 * When an "on timer" fires, we must deterministically be able to drain
 * the wait queue, since if any threads are added to the queue afterwards,
 * they may never get woken out of SFI wait. So sfi_lock must be
 * taken before the wait queue's own spinlock.
 *
 * The wait queue will take the thread's scheduling lock. We may also take
 * the thread_lock directly to update the "sfi_class" field and determine
 * if the thread should block in the wait queue, but the lock will be
 * released before doing so.
 *
 * The pset lock may also be taken, but not while any other locks are held.
 *
 * splsched ---> sfi_lock ---> wait_queue ---> thread_lock
 *        \  \              \__ thread_lock (*)
 *         \  \__ pset_lock
 *          \
 *           \__ thread_lock
 */

decl_simple_lock_data(static,sfi_lock);
static timer_call_data_t        sfi_timer_call_entry;
volatile boolean_t	sfi_is_enabled;

boolean_t sfi_window_is_set;
uint64_t sfi_window_usecs;
uint64_t sfi_window_interval;
uint64_t sfi_next_off_deadline;

typedef struct {
	sfi_class_id_t	class_id;
	thread_continue_t	class_continuation;
	const char *	class_name;
	const char *	class_ledger_name;
} sfi_class_registration_t;

/*
 * To add a new SFI class:
 *
 * 1) Raise MAX_SFI_CLASS_ID in mach/sfi_class.h
 * 2) Add a #define for it to mach/sfi_class.h. It need not be inserted in order of restrictiveness.
 * 3) Add a call to SFI_CLASS_REGISTER below
 * 4) Augment sfi_thread_classify to categorize threads as early as possible for as restrictive as possible.
 * 5) Modify thermald to use the SFI class
 */

static inline void _sfi_wait_cleanup(sched_call_t callback);

#define SFI_CLASS_REGISTER(class_id, ledger_name)					\
extern char compile_time_assert_ ## class_id[SFI_CLASS_ ## class_id < MAX_SFI_CLASS_ID ? 1 : -1];  \
void __attribute__((noinline,noreturn)) SFI_ ## class_id ## _THREAD_IS_WAITING(void *callback, wait_result_t wret __unused); \
void SFI_ ## class_id ## _THREAD_IS_WAITING(void *callback, wait_result_t wret __unused) \
{																		\
	_sfi_wait_cleanup(callback);										\
	thread_exception_return();											\
}																		\
																		\
sfi_class_registration_t SFI_ ## class_id ## _registration __attribute__((section("__DATA,__sfi_class_reg"),used)) = { SFI_CLASS_ ## class_id, SFI_ ## class_id ## _THREAD_IS_WAITING, "SFI_CLASS_" # class_id, "SFI_CLASS_" # ledger_name };

/* SFI_CLASS_UNSPECIFIED not included here */
SFI_CLASS_REGISTER(MAINTENANCE,               MAINTENANCE)
SFI_CLASS_REGISTER(DARWIN_BG,                 DARWIN_BG)
SFI_CLASS_REGISTER(APP_NAP,                   APP_NAP)
SFI_CLASS_REGISTER(MANAGED_FOCAL,             MANAGED)
SFI_CLASS_REGISTER(MANAGED_NONFOCAL,          MANAGED)
SFI_CLASS_REGISTER(UTILITY,                   UTILITY)
SFI_CLASS_REGISTER(DEFAULT_FOCAL,             DEFAULT)
SFI_CLASS_REGISTER(DEFAULT_NONFOCAL,          DEFAULT)
SFI_CLASS_REGISTER(LEGACY_FOCAL,              LEGACY)
SFI_CLASS_REGISTER(LEGACY_NONFOCAL,           LEGACY)
SFI_CLASS_REGISTER(USER_INITIATED_FOCAL,      USER_INITIATED)
SFI_CLASS_REGISTER(USER_INITIATED_NONFOCAL,   USER_INITIATED)
SFI_CLASS_REGISTER(USER_INTERACTIVE_FOCAL,    USER_INTERACTIVE)
SFI_CLASS_REGISTER(USER_INTERACTIVE_NONFOCAL, USER_INTERACTIVE)
SFI_CLASS_REGISTER(KERNEL,                    OPTED_OUT)
SFI_CLASS_REGISTER(OPTED_OUT,                 OPTED_OUT)

struct sfi_class_state {
	uint64_t	off_time_usecs;
	uint64_t	off_time_interval;

	timer_call_data_t	on_timer;
	boolean_t			on_timer_programmed;

	boolean_t	class_sfi_is_enabled;
	volatile boolean_t	class_in_on_phase;

	struct wait_queue	wait_queue;	/* threads in ready state */
	thread_continue_t	continuation;

	const char *	class_name;
	const char *	class_ledger_name;
};

/* Static configuration performed in sfi_early_init() */
struct sfi_class_state sfi_classes[MAX_SFI_CLASS_ID];

int sfi_enabled_class_count;

static void sfi_timer_global_off(
	timer_call_param_t      param0,
	timer_call_param_t      param1);

static void sfi_timer_per_class_on(
	timer_call_param_t      param0,
	timer_call_param_t      param1);

static sfi_class_registration_t *
sfi_get_registration_data(unsigned long *count)
{
	unsigned long sectlen = 0;
	void *sectdata;

	sectdata = getsectdatafromheader(&_mh_execute_header, "__DATA", "__sfi_class_reg", &sectlen);
	if (sectdata) {

		if (sectlen % sizeof(sfi_class_registration_t) != 0) {
			/* corrupt data? */
			panic("__sfi_class_reg section has invalid size %lu", sectlen);
			__builtin_unreachable();
		}

		*count = sectlen / sizeof(sfi_class_registration_t);
		return (sfi_class_registration_t *)sectdata;
	} else {
		panic("__sfi_class_reg section not found");
		__builtin_unreachable();
	}
}

/* Called early in boot, when kernel is single-threaded */
void sfi_early_init(void)
{
	unsigned long i, count;
	sfi_class_registration_t *registrations;

	registrations = sfi_get_registration_data(&count);
	for (i=0; i < count; i++) {
		sfi_class_id_t class_id = registrations[i].class_id;

		assert(class_id < MAX_SFI_CLASS_ID); /* should be caught at compile-time */
		if (class_id < MAX_SFI_CLASS_ID) {
			if (sfi_classes[class_id].continuation != NULL) {
				panic("Duplicate SFI registration for class 0x%x", class_id);
			}
			sfi_classes[class_id].class_sfi_is_enabled = FALSE;
			sfi_classes[class_id].class_in_on_phase = TRUE;
			sfi_classes[class_id].continuation = registrations[i].class_continuation;
			sfi_classes[class_id].class_name = registrations[i].class_name;
			sfi_classes[class_id].class_ledger_name = registrations[i].class_ledger_name;
		}
	}
}

void sfi_init(void)
{
	sfi_class_id_t i;
	kern_return_t kret;

	simple_lock_init(&sfi_lock, 0);
	timer_call_setup(&sfi_timer_call_entry, sfi_timer_global_off, NULL);
	sfi_window_is_set = FALSE;
	sfi_enabled_class_count = 0;
	sfi_is_enabled = FALSE;

	for (i = 0; i < MAX_SFI_CLASS_ID; i++) {
		/* If the class was set up in sfi_early_init(), initialize remaining fields */
		if (sfi_classes[i].continuation) {
			timer_call_setup(&sfi_classes[i].on_timer, sfi_timer_per_class_on, (void *)(uintptr_t)i);
			sfi_classes[i].on_timer_programmed = FALSE;
			
			kret = wait_queue_init(&sfi_classes[i].wait_queue, SYNC_POLICY_FIFO);
			assert(kret == KERN_SUCCESS);
		} else {
			/* The only allowed gap is for SFI_CLASS_UNSPECIFIED */
			if(i != SFI_CLASS_UNSPECIFIED) {
				panic("Gap in registered SFI classes");
			}
		}
	}
}

/* Can be called before sfi_init() by task initialization, but after sfi_early_init() */
sfi_class_id_t
sfi_get_ledger_alias_for_class(sfi_class_id_t class_id)
{
	sfi_class_id_t i;
	const char *ledger_name = NULL;

	ledger_name = sfi_classes[class_id].class_ledger_name;

	/* Find the first class in the registration table with this ledger name */
	if (ledger_name) {
		for (i = SFI_CLASS_UNSPECIFIED + 1; i < class_id; i++) {
			if (0 == strcmp(sfi_classes[i].class_ledger_name, ledger_name)) {
				dprintf("sfi_get_ledger_alias_for_class(0x%x) -> 0x%x\n", class_id, i);
				return i;
			}
		}

		/* This class is the primary one for the ledger, so there is no alias */
		dprintf("sfi_get_ledger_alias_for_class(0x%x) -> 0x%x\n", class_id, SFI_CLASS_UNSPECIFIED);
		return SFI_CLASS_UNSPECIFIED;
	}

	/* We are permissive on SFI class lookup failures. In sfi_init(), we assert more */
	return SFI_CLASS_UNSPECIFIED;
}

int
sfi_ledger_entry_add(ledger_template_t template, sfi_class_id_t class_id)
{
	const char *ledger_name = NULL;

	ledger_name = sfi_classes[class_id].class_ledger_name;

	dprintf("sfi_ledger_entry_add(%p, 0x%x) -> %s\n", template, class_id, ledger_name);
	return ledger_entry_add(template, ledger_name, "sfi", "MATUs");
}

static void sfi_timer_global_off(
	timer_call_param_t      param0 __unused,
	timer_call_param_t      param1 __unused)
{
	uint64_t	now = mach_absolute_time();
	sfi_class_id_t	i;
	processor_set_t	pset, nset;
	processor_t		processor;
	uint32_t		needs_cause_ast_mask = 0x0;
	spl_t		s;

	s = splsched();

	simple_lock(&sfi_lock);
	if (!sfi_is_enabled) {
		/* If SFI has been disabled, let all "on" timers drain naturally */
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_OFF_TIMER) | DBG_FUNC_NONE, 1, 0, 0, 0, 0);

		simple_unlock(&sfi_lock);
		splx(s);
		return;
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_OFF_TIMER) | DBG_FUNC_START, 0, 0, 0, 0, 0);

	/* First set all configured classes into the off state, and program their "on" timer */
	for (i = 0; i < MAX_SFI_CLASS_ID; i++) {
		if (sfi_classes[i].class_sfi_is_enabled) {
			uint64_t on_timer_deadline;
			
			sfi_classes[i].class_in_on_phase = FALSE;
			sfi_classes[i].on_timer_programmed = TRUE;

			/* Push out on-timer */
			on_timer_deadline = now + sfi_classes[i].off_time_interval;
			timer_call_enter1(&sfi_classes[i].on_timer, NULL, on_timer_deadline, TIMER_CALL_SYS_CRITICAL);
		} else {
			/* If this class no longer needs SFI, make sure the timer is cancelled */
			sfi_classes[i].class_in_on_phase = TRUE;
			if (sfi_classes[i].on_timer_programmed) {
				sfi_classes[i].on_timer_programmed = FALSE;
				timer_call_cancel(&sfi_classes[i].on_timer);
			}
		}
	}
	simple_unlock(&sfi_lock);

	/* Iterate over processors, call cause_ast_check() on ones running a thread that should be in an off phase */
	processor = processor_list;
	pset = processor->processor_set;
	
	pset_lock(pset);
	
	do {
		nset = processor->processor_set;
		if (nset != pset) {
			pset_unlock(pset);
			pset = nset;
			pset_lock(pset);
		}

		/* "processor" and its pset are locked */
		if (processor->state == PROCESSOR_RUNNING) {
			if (AST_NONE != sfi_processor_needs_ast(processor)) {
				needs_cause_ast_mask |= (1U << processor->cpu_id);
			}
		}
	} while ((processor = processor->processor_list) != NULL);

	pset_unlock(pset);

	processor = processor_list;
	do {
		if (needs_cause_ast_mask & (1U << processor->cpu_id)) {
			if (processor == current_processor())
				ast_on(AST_SFI);
			else
				cause_ast_check(processor);
		}
	} while ((processor = processor->processor_list) != NULL);

	/* Re-arm timer if still enabled */
	simple_lock(&sfi_lock);
	if (sfi_is_enabled) {
		clock_deadline_for_periodic_event(sfi_window_interval,
										  now,
										  &sfi_next_off_deadline);
		timer_call_enter1(&sfi_timer_call_entry,
						  NULL,
						  sfi_next_off_deadline,
						  TIMER_CALL_SYS_CRITICAL);
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_OFF_TIMER) | DBG_FUNC_END, 0, 0, 0, 0, 0);

	simple_unlock(&sfi_lock);

	splx(s);
}

static void sfi_timer_per_class_on(
	timer_call_param_t      param0,
	timer_call_param_t      param1 __unused)
{
	sfi_class_id_t sfi_class_id = (sfi_class_id_t)(uintptr_t)param0;
	struct sfi_class_state	*sfi_class = &sfi_classes[sfi_class_id];
	kern_return_t	kret;
	spl_t		s;

	s = splsched();

	simple_lock(&sfi_lock);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_ON_TIMER) | DBG_FUNC_START, sfi_class_id, 0, 0, 0, 0);

	/*
	 * Any threads that may have accumulated in the ready queue for this class should get re-enqueued.
	 * Since we have the sfi_lock held and have changed "class_in_on_phase", we expect
	 * no new threads to be put on this wait queue until the global "off timer" has fired.
	 */
	sfi_class->class_in_on_phase = TRUE;
	kret = wait_queue_wakeup64_all(&sfi_class->wait_queue,
								   CAST_EVENT64_T(sfi_class_id),
								   THREAD_AWAKENED);
	assert(kret == KERN_SUCCESS || kret == KERN_NOT_WAITING);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_ON_TIMER) | DBG_FUNC_END, 0, 0, 0, 0, 0);

	simple_unlock(&sfi_lock);

	splx(s);
}


kern_return_t sfi_set_window(uint64_t window_usecs)
{
	uint64_t	interval, deadline;
	uint64_t	now = mach_absolute_time();
	sfi_class_id_t	i;
	spl_t		s;
	uint64_t	largest_class_off_interval = 0;

	if (window_usecs < MIN_SFI_WINDOW_USEC)
		window_usecs = MIN_SFI_WINDOW_USEC;

	if (window_usecs > UINT32_MAX)
		return (KERN_INVALID_ARGUMENT);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_SET_WINDOW), window_usecs, 0, 0, 0, 0);

	clock_interval_to_absolutetime_interval((uint32_t)window_usecs, NSEC_PER_USEC, &interval);
	deadline = now + interval;

	s = splsched();

	simple_lock(&sfi_lock);

	/* Check that we are not bringing in the SFI window smaller than any class */
	for (i = 0; i < MAX_SFI_CLASS_ID; i++) {
		if (sfi_classes[i].class_sfi_is_enabled) {
			largest_class_off_interval = MAX(largest_class_off_interval, sfi_classes[i].off_time_interval);
		}
	}

	/*
	 * Off window must be strictly greater than all enabled classes,
	 * otherwise threads would build up on ready queue and never be able to run.
	 */
	if (interval <= largest_class_off_interval) {
		simple_unlock(&sfi_lock);
		splx(s);
		return (KERN_INVALID_ARGUMENT);
	}

	/*
	 * If the new "off" deadline is further out than the current programmed timer,
	 * just let the current one expire (and the new cadence will be established thereafter).
	 * If the new "off" deadline is nearer than the current one, bring it in, so we
	 * can start the new behavior sooner. Note that this may cause the "off" timer to
	 * fire before some of the class "on" timers have fired.
	 */
	sfi_window_usecs = window_usecs;
	sfi_window_interval = interval;
	sfi_window_is_set = TRUE;

	if (sfi_enabled_class_count == 0) {
		/* Can't program timer yet */
	} else if (!sfi_is_enabled) {
		sfi_is_enabled = TRUE;
		sfi_next_off_deadline = deadline;
		timer_call_enter1(&sfi_timer_call_entry,
						  NULL,
						  sfi_next_off_deadline,
						  TIMER_CALL_SYS_CRITICAL);		
	} else if (deadline >= sfi_next_off_deadline) {
		sfi_next_off_deadline = deadline;
	} else {
		sfi_next_off_deadline = deadline;
		timer_call_enter1(&sfi_timer_call_entry,
						  NULL,
						  sfi_next_off_deadline,
						  TIMER_CALL_SYS_CRITICAL);		
	}

	simple_unlock(&sfi_lock);
	splx(s);

	return (KERN_SUCCESS);
}

kern_return_t sfi_window_cancel(void)
{
	spl_t		s;

	s = splsched();

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_CANCEL_WINDOW), 0, 0, 0, 0, 0);

	/* Disable globals so that global "off-timer" is not re-armed */
	simple_lock(&sfi_lock);
	sfi_window_is_set = FALSE;
	sfi_window_usecs = 0;
	sfi_window_interval = 0;
	sfi_next_off_deadline = 0;
	sfi_is_enabled = FALSE;
	simple_unlock(&sfi_lock);

	splx(s);

	return (KERN_SUCCESS);
}


kern_return_t sfi_get_window(uint64_t *window_usecs)
{
	spl_t		s;
	uint64_t	off_window_us;

	s = splsched();
	simple_lock(&sfi_lock);

	off_window_us = sfi_window_usecs;

	simple_unlock(&sfi_lock);
	splx(s);

	*window_usecs = off_window_us;

	return (KERN_SUCCESS);
}


kern_return_t sfi_set_class_offtime(sfi_class_id_t class_id, uint64_t offtime_usecs)
{
	uint64_t	interval;
	spl_t		s;
	uint64_t	off_window_interval;

	if (offtime_usecs < MIN_SFI_WINDOW_USEC)
		offtime_usecs = MIN_SFI_WINDOW_USEC;

	if (class_id == SFI_CLASS_UNSPECIFIED || class_id >= MAX_SFI_CLASS_ID)
		return (KERN_INVALID_ARGUMENT);

	if (offtime_usecs > UINT32_MAX)
		return (KERN_INVALID_ARGUMENT);

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_SET_CLASS_OFFTIME), offtime_usecs, class_id, 0, 0, 0);

	clock_interval_to_absolutetime_interval((uint32_t)offtime_usecs, NSEC_PER_USEC, &interval);

	s = splsched();

	simple_lock(&sfi_lock);
	off_window_interval = sfi_window_interval;

	/* Check that we are not bringing in class off-time larger than the SFI window */
	if (off_window_interval && (interval >= off_window_interval)) {
		simple_unlock(&sfi_lock);
		splx(s);
		return (KERN_INVALID_ARGUMENT);
	}

	/* We never re-program the per-class on-timer, but rather just let it expire naturally */
	if (!sfi_classes[class_id].class_sfi_is_enabled) {
		sfi_enabled_class_count++;
	}
	sfi_classes[class_id].off_time_usecs = offtime_usecs;
	sfi_classes[class_id].off_time_interval = interval;
	sfi_classes[class_id].class_sfi_is_enabled = TRUE;

	if (sfi_window_is_set && !sfi_is_enabled) {
		/* start global off timer */
		sfi_is_enabled = TRUE;
		sfi_next_off_deadline = mach_absolute_time() + sfi_window_interval;
		timer_call_enter1(&sfi_timer_call_entry,
						  NULL,
						  sfi_next_off_deadline,
						  TIMER_CALL_SYS_CRITICAL);		
	}

	simple_unlock(&sfi_lock);

	splx(s);

	return (KERN_SUCCESS);
}

kern_return_t sfi_class_offtime_cancel(sfi_class_id_t class_id)
{
	spl_t		s;

	if (class_id == SFI_CLASS_UNSPECIFIED || class_id >= MAX_SFI_CLASS_ID)
		return (KERN_INVALID_ARGUMENT);

	s = splsched();

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_CANCEL_CLASS_OFFTIME), class_id, 0, 0, 0, 0);

	simple_lock(&sfi_lock);

	/* We never re-program the per-class on-timer, but rather just let it expire naturally */
	if (sfi_classes[class_id].class_sfi_is_enabled) {
		sfi_enabled_class_count--;
	}
	sfi_classes[class_id].off_time_usecs = 0;
	sfi_classes[class_id].off_time_interval = 0;
	sfi_classes[class_id].class_sfi_is_enabled = FALSE;

	if (sfi_enabled_class_count == 0) {
		sfi_is_enabled = FALSE;
	}

	simple_unlock(&sfi_lock);

	splx(s);

	return (KERN_SUCCESS);
}

kern_return_t sfi_get_class_offtime(sfi_class_id_t class_id, uint64_t *offtime_usecs)
{
	uint64_t	off_time_us;
	spl_t		s;

	if (class_id == SFI_CLASS_UNSPECIFIED || class_id >= MAX_SFI_CLASS_ID)
		return (0);

	s = splsched();

	simple_lock(&sfi_lock);
	off_time_us = sfi_classes[class_id].off_time_usecs;
	simple_unlock(&sfi_lock);

	splx(s);

	*offtime_usecs = off_time_us;

	return (KERN_SUCCESS);
}

/*
 * sfi_thread_classify and sfi_processor_active_thread_classify perform the critical
 * role of quickly categorizing a thread into its SFI class so that an AST_SFI can be
 * set. As the thread is unwinding to userspace, sfi_ast() performs full locking
 * and determines whether the thread should enter an SFI wait state. Because of
 * the inherent races between the time the AST is set and when it is evaluated,
 * thread classification can be inaccurate (but should always be safe). This is
 * especially the case for sfi_processor_active_thread_classify, which must
 * classify the active thread on a remote processor without taking the thread lock.
 * When in doubt, classification should err on the side of *not* classifying a
 * thread at all, and wait for the thread itself to either hit a quantum expiration
 * or block inside the kernel.
 */

/*
 * Thread must be locked. Ultimately, the real decision to enter
 * SFI wait happens at the AST boundary.
 */
sfi_class_id_t sfi_thread_classify(thread_t thread)
{
	task_t task = thread->task;
	boolean_t is_kernel_thread = (task == kernel_task);
	sched_mode_t thmode = thread->sched_mode;
	int latency_qos = proc_get_effective_task_policy(task, TASK_POLICY_LATENCY_QOS);
	int task_role = proc_get_effective_task_policy(task, TASK_POLICY_ROLE);
	int thread_bg = proc_get_effective_thread_policy(thread, TASK_POLICY_DARWIN_BG);
	int managed_task = proc_get_effective_task_policy(task, TASK_POLICY_SFI_MANAGED);
	int thread_qos = proc_get_effective_thread_policy(thread, TASK_POLICY_QOS);
	boolean_t focal = FALSE;

	/* kernel threads never reach the user AST boundary, and are in a separate world for SFI */
	if (is_kernel_thread) {
		return SFI_CLASS_KERNEL;
	}

	if (thread_qos == THREAD_QOS_MAINTENANCE)
		return SFI_CLASS_MAINTENANCE;

	if (thread_bg || thread_qos == THREAD_QOS_BACKGROUND) {
		return SFI_CLASS_DARWIN_BG;
	}

	if (latency_qos != 0) {
		int latency_qos_wtf = latency_qos - 1;

		if ((latency_qos_wtf >= 4) && (latency_qos_wtf <= 5)) {
			return SFI_CLASS_APP_NAP;
		}
	}

	/*
	 * Realtime and fixed priority threads express their duty cycle constraints
	 * via other mechanisms, and are opted out of (most) forms of SFI
	 */
	if (thmode == TH_MODE_REALTIME || thmode == TH_MODE_FIXED || task_role == TASK_GRAPHICS_SERVER) {
		return SFI_CLASS_OPTED_OUT;
	}

	/*
	 * Threads with unspecified, legacy, or user-initiated QOS class can be individually managed.
	 */

	switch (task_role) {
		case TASK_CONTROL_APPLICATION:
		case TASK_FOREGROUND_APPLICATION:
			focal = TRUE;
			break;

		case TASK_BACKGROUND_APPLICATION:
		case TASK_DEFAULT_APPLICATION:
		case TASK_UNSPECIFIED:
			/* Focal if in coalition with foreground app */
			if (coalition_focal_task_count(thread->task->coalition) > 0)
				focal = TRUE;
			break;

		default:
			break;
	}

	if (managed_task) {
		switch (thread_qos) {
		case THREAD_QOS_UNSPECIFIED:
		case THREAD_QOS_LEGACY:
		case THREAD_QOS_USER_INITIATED:
			if (focal)
				return SFI_CLASS_MANAGED_FOCAL;
			else
				return SFI_CLASS_MANAGED_NONFOCAL;
		default:
			break;
		}
	}

	if (thread_qos == THREAD_QOS_UTILITY)
		return SFI_CLASS_UTILITY;

	/*
	 * Classify threads in non-managed tasks
	 */
	if (focal) {
		switch (thread_qos) {
		case THREAD_QOS_USER_INTERACTIVE:
			return SFI_CLASS_USER_INTERACTIVE_FOCAL;
		case THREAD_QOS_USER_INITIATED:
			return SFI_CLASS_USER_INITIATED_FOCAL;
		case THREAD_QOS_LEGACY:
			return SFI_CLASS_LEGACY_FOCAL;
		default:
			return SFI_CLASS_DEFAULT_FOCAL;
		}
	} else {
		switch (thread_qos) {
		case THREAD_QOS_USER_INTERACTIVE:
			return SFI_CLASS_USER_INTERACTIVE_NONFOCAL;
		case THREAD_QOS_USER_INITIATED:
			return SFI_CLASS_USER_INITIATED_NONFOCAL;
		case THREAD_QOS_LEGACY:
			return SFI_CLASS_LEGACY_NONFOCAL;
		default:
			return SFI_CLASS_DEFAULT_NONFOCAL;
		}
	}
}

/*
 * pset must be locked.
 */
sfi_class_id_t sfi_processor_active_thread_classify(processor_t processor)
{
	return processor->current_sfi_class;
}

/*
 * thread must be locked. This is inherently racy, with the intent that
 * at the AST boundary, it will be fully evaluated whether we need to
 * perform an AST wait
 */
ast_t sfi_thread_needs_ast(thread_t thread, sfi_class_id_t *out_class)
{
	sfi_class_id_t class_id;

	class_id = sfi_thread_classify(thread);

	if (out_class)
		*out_class = class_id;

	/* No lock taken, so a stale value may be used. */
	if (!sfi_classes[class_id].class_in_on_phase)
		return AST_SFI;
	else
		return AST_NONE;
}

/*
 * pset must be locked. We take the SFI class for
 * the currently running thread which is cached on
 * the processor_t, and assume it is accurate. In the
 * worst case, the processor will get an IPI and be asked
 * to evaluate if the current running thread at that
 * later point in time should be in an SFI wait.
 */
ast_t sfi_processor_needs_ast(processor_t processor)
{
	sfi_class_id_t class_id;

	class_id = sfi_processor_active_thread_classify(processor);

	/* No lock taken, so a stale value may be used. */
	if (!sfi_classes[class_id].class_in_on_phase)
		return AST_SFI;
	else
		return AST_NONE;

}

static inline void _sfi_wait_cleanup(sched_call_t callback) {
	thread_t self = current_thread();
	sfi_class_id_t current_sfi_wait_class = SFI_CLASS_UNSPECIFIED;
	int64_t sfi_wait_time, sfi_wait_begin = 0;

	spl_t s = splsched();
	thread_lock(self);
	if (callback) {
		thread_sched_call(self, callback);
	}
	sfi_wait_begin = self->wait_sfi_begin_time;
	thread_unlock(self);

	simple_lock(&sfi_lock);
	sfi_wait_time = mach_absolute_time() - sfi_wait_begin;
	current_sfi_wait_class = self->sfi_wait_class;
	self->sfi_wait_class = SFI_CLASS_UNSPECIFIED;
	simple_unlock(&sfi_lock);
	splx(s);
	assert(SFI_CLASS_UNSPECIFIED < current_sfi_wait_class < MAX_SFI_CLASS_ID);
	ledger_credit(self->task->ledger, task_ledgers.sfi_wait_times[current_sfi_wait_class], sfi_wait_time);
}

/*
 * Called at AST context to fully evaluate if the current thread
 * (which is obviously running) should instead block in an SFI wait.
 * We must take the sfi_lock to check whether we are in the "off" period
 * for the class, and if so, block.
 */
void sfi_ast(thread_t thread)
{
	sfi_class_id_t class_id;
	spl_t		s;
	struct sfi_class_state	*sfi_class;
	wait_result_t	waitret;
	boolean_t	did_wait = FALSE;
	uint64_t	tid;
	thread_continue_t	continuation;
	sched_call_t	workq_callback = workqueue_get_sched_callback();
	boolean_t	did_clear_wq = FALSE;

	s = splsched();

	simple_lock(&sfi_lock);

	if (!sfi_is_enabled) {
		/*
		 * SFI is not enabled, or has recently been disabled.
		 * There is no point putting this thread on a deferred ready
		 * queue, even if it were classified as needing it, since
		 * SFI will truly be off at the next global off timer
		 */
		simple_unlock(&sfi_lock);
		splx(s);

		return;
	}

	thread_lock(thread);
	thread->sfi_class = class_id = sfi_thread_classify(thread);
	tid = thread_tid(thread);

	/*
	 * Once the sfi_lock is taken and the thread's ->sfi_class field is updated, we
	 * are committed to transitioning to whatever state is indicated by "->class_in_on_phase".
	 * If another thread tries to call sfi_reevaluate() after this point, it will take the
	 * sfi_lock and see the thread in this wait state. If another thread calls
	 * sfi_reevaluate() before this point, it would see a runnable thread and at most
	 * attempt to send an AST to this processor, but we would have the most accurate
	 * classification.
	 */

	/* Optimistically clear workq callback while thread is already locked */
	if (workq_callback && (thread->sched_call == workq_callback)) {
		thread_sched_call(thread, NULL);
		did_clear_wq = TRUE;
	}
	thread_unlock(thread);

	sfi_class = &sfi_classes[class_id];
	if (!sfi_class->class_in_on_phase) {
		/* Need to block thread in wait queue */
		KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_THREAD_DEFER), tid, class_id, 0, 0, 0);

		waitret = wait_queue_assert_wait64(&sfi_class->wait_queue,
						   CAST_EVENT64_T(class_id),
						   THREAD_INTERRUPTIBLE,
						   0);
		if (waitret == THREAD_WAITING) {
			thread->sfi_wait_class = class_id;
			did_wait = TRUE;
			continuation = sfi_class->continuation;
		} else {
			/* thread may be exiting already, all other errors are unexpected */
			assert(waitret == THREAD_INTERRUPTED);
		}
	}
	simple_unlock(&sfi_lock);
	
	splx(s);

	if (did_wait) {
		thread_block_reason(continuation, did_clear_wq ? workq_callback : NULL, AST_SFI);
	} else {
		if (did_clear_wq) {
			s = splsched();
			thread_lock(thread);
			thread_sched_call(thread, workq_callback);
			thread_unlock(thread);
			splx(s);
		}
	}
}

/*
 * Thread must be unlocked
 * May be called with coalition, task, or thread mutex held
 */
void sfi_reevaluate(thread_t thread)
{
	kern_return_t kret;
	spl_t		s;
	sfi_class_id_t class_id, current_class_id;
	ast_t		sfi_ast;

	s = splsched();

	simple_lock(&sfi_lock);

	thread_lock(thread);
	sfi_ast = sfi_thread_needs_ast(thread, &class_id);
	thread->sfi_class = class_id;

	/*
	 * This routine chiefly exists to boost threads out of an SFI wait
	 * if their classification changes before the "on" timer fires.
	 *
	 * If we calculate that a thread is in a different ->sfi_wait_class
	 * than we think it should be (including no-SFI-wait), we need to
	 * correct that:
	 *
	 * If the thread is in SFI wait and should not be (or should be waiting
	 * on a different class' "on" timer), we wake it up. If needed, the
	 * thread may immediately block again in the different SFI wait state.
	 *
	 * If the thread is not in an SFI wait state and it should be, we need
	 * to get that thread's attention, possibly by sending an AST to another
	 * processor.
	 */

	if ((current_class_id = thread->sfi_wait_class) != SFI_CLASS_UNSPECIFIED) {

		thread_unlock(thread); /* not needed anymore */

		assert(current_class_id < MAX_SFI_CLASS_ID);

		if ((sfi_ast == AST_NONE) || (class_id != current_class_id)) {
			struct sfi_class_state	*sfi_class = &sfi_classes[current_class_id];

			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SFI, SFI_WAIT_CANCELED), thread_tid(thread), current_class_id, class_id, 0, 0);

			kret = wait_queue_wakeup64_thread(&sfi_class->wait_queue,
											  CAST_EVENT64_T(current_class_id),
											  thread,
											  THREAD_AWAKENED);
			assert(kret == KERN_SUCCESS || kret == KERN_NOT_WAITING);
		}
	} else {
		/*
		 * Thread's current SFI wait class is not set, and because we
		 * have the sfi_lock, it won't get set.
		 */

		if ((thread->state & (TH_RUN | TH_IDLE)) == TH_RUN) {
			if (sfi_ast != AST_NONE) {
				if (thread == current_thread())
					ast_on(sfi_ast);
				else {
					processor_t             processor = thread->last_processor;
					
					if (processor != PROCESSOR_NULL &&
						processor->state == PROCESSOR_RUNNING &&
						processor->active_thread == thread) {
						cause_ast_check(processor);
					} else {
						/*
						 * Runnable thread that's not on a CPU currently. When a processor
						 * does context switch to it, the AST will get set based on whether
						 * the thread is in its "off time".
						 */
					}
				}
			}
		}

		thread_unlock(thread);
	}

	simple_unlock(&sfi_lock);
	splx(s);
}
