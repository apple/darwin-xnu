/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <kern/kalloc.h>
#include <kern/kern_types.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <machine/machine_cpu.h>

#include <pmc/pmc.h>

#include <libkern/OSAtomic.h>

#if defined(__i386__) || defined(__x86_64__)
#include <i386/mp.h>
#endif

#if CONFIG_COUNTERS

/* various debug logging enable */
#undef DEBUG_COUNTERS

typedef uint8_t pmc_state_event_t;

#define PMC_STATE_EVENT_START				0
#define PMC_STATE_EVENT_STOP				1
#define PMC_STATE_EVENT_FREE				2
#define PMC_STATE_EVENT_INTERRUPT			3
#define PMC_STATE_EVENT_END_OF_INTERRUPT	4
#define PMC_STATE_EVENT_CONTEXT_IN			5
#define PMC_STATE_EVENT_CONTEXT_OUT			6
#define PMC_STATE_EVENT_LOAD_FINISHED		7
#define PMC_STATE_EVENT_STORE_FINISHED		8

/* PMC spin timeouts */
#define PMC_SPIN_THRESHOLD	10	/* Number of spins to allow before checking mach_absolute_time() */
#define PMC_SPIN_TIMEOUT_US	10	/* Time in microseconds before the spin causes an assert */

uint64_t pmc_spin_timeout_count = 0;	/* Number of times where a PMC spin loop causes a timeout */

#ifdef DEBUG_COUNTERS
#	include <pexpert/pexpert.h>
#	define COUNTER_DEBUG(...) \
	do { \
		kprintf("[%s:%s][%u] ", __FILE__, __PRETTY_FUNCTION__, cpu_number()); \
		kprintf(__VA_ARGS__); \
	} while(0)

#	define PRINT_PERF_MON(x)	\
	do { \
		kprintf("perfmon: %p (obj: %p refCt: %u switchable: %u)\n", \
			x, x->object, x->useCount, \
			x->methods.supports_context_switching ? \
			x->methods.supports_context_switching(x->object) : 0); \
	} while(0)

static const char const * pmc_state_state_name(pmc_state_t state) {
	switch (PMC_STATE_STATE(state)) {
		case PMC_STATE_STATE_INVALID:
			return "INVALID";
		case PMC_STATE_STATE_STOP:
			return "STOP";
		case PMC_STATE_STATE_CAN_RUN:
			return "CAN_RUN";
		case PMC_STATE_STATE_LOAD:
			return "LOAD";
		case PMC_STATE_STATE_RUN:
			return "RUN";
		case PMC_STATE_STATE_STORE:
			return "STORE";
		case PMC_STATE_STATE_INTERRUPT:
			return "INTERRUPT";
		case PMC_STATE_STATE_DEALLOC:
			return "DEALLOC";
		default:
			return "UNKNOWN";
	}
}

static const char const * pmc_state_event_name(pmc_state_event_t event) {
	switch (event) {
		case PMC_STATE_EVENT_START:
			return "START";
		case PMC_STATE_EVENT_STOP:
			return "STOP";
		case PMC_STATE_EVENT_FREE:
			return "FREE";
		case PMC_STATE_EVENT_INTERRUPT:
			return "INTERRUPT";
		case PMC_STATE_EVENT_END_OF_INTERRUPT:
			return "END OF INTERRUPT";
		case PMC_STATE_EVENT_CONTEXT_IN:
			return "CONTEXT IN";
		case PMC_STATE_EVENT_CONTEXT_OUT:
			return "CONTEXT OUT";
		case PMC_STATE_EVENT_LOAD_FINISHED:
			return "LOAD_FINISHED";
		case PMC_STATE_EVENT_STORE_FINISHED:
			return "STORE_FINISHED";
		default:
			return "UNKNOWN";
	}
}

#	define PMC_STATE_FORMAT	"<%s, %u, %s%s%s>"
#	define PMC_STATE_ARGS(x)	pmc_state_state_name(x), PMC_STATE_CONTEXT_COUNT(x), ((PMC_STATE_FLAGS(x) & PMC_STATE_FLAGS_INTERRUPTING) ? "I" : ""), \
					((PMC_STATE_FLAGS(x) & PMC_STATE_FLAGS_STOPPING) ? "S" : ""), ((PMC_STATE_FLAGS(x) & PMC_STATE_FLAGS_DEALLOCING) ? "D" : "")
#else
#	define COUNTER_DEBUG(...)
#	define PRINT_PERF_MON(x)
#	define PMC_STATE_FORMAT
#	define PMC_STATE_ARGS(x)
#endif

/*!struct
 * pmc_config is the data behind a pmc_config_t.
 * @member object A pointer to an instance of IOPerformanceCounterConfiguration
 * @member method A pointer to a method to call to handle PMI.
 * @member interrupt_after_value Cause a PMI after the counter counts this many
 * events.
 * @member refCon Passed to the @method method as the refCon argument.
 */
struct pmc_config {
	pmc_config_object_t object;
	volatile pmc_interrupt_method_t method;
	uint64_t interrupt_after_value;
	void *refCon;
};

/*
 * Allocation Zones
 * 
 * Two allocation zones - Perf zone small and Perf zone big.
 * Each zone has associated maximums, defined below.
 * The small zone is the max of the smallest allocation objects (all sizes on
 * K64):
 *	perf_monitor_t - 48 bytes
 *		perf_monitor_methods_t - 28 bytes
 *	pmc_reservation_t - 48 bytes
 *  pmc_config_t - 32 bytes
 * perf_small_zone unit size is (on K64) 48 bytes
 * perf_small_zone max count must be max number of perf monitors, plus (max
 * number of reservations * 2). The "*2" is because each reservation has a
 * pmc_config_t within.
 *
 * Big zone is max of the larger allocation units
 *	pmc_t - 144 bytes
 *		pmc_methods_t - 116 bytes
 * perf_big_zone unit size is (on K64) 144 bytes
 * perf_big_zone max count is the max number of PMCs we support.
 */

static zone_t perf_small_zone = NULL;
#define MAX_PERF_SMALLS		(256 + 8196 + 8196)
#define PERF_SMALL_UNIT_SZ	(MAX(MAX(sizeof(struct perf_monitor), \
	sizeof(struct pmc_reservation)), sizeof(struct pmc_config))) 

static zone_t perf_big_zone = NULL;
#define MAX_PERF_BIGS		(1024)
#define PERF_BIG_UNIT_SZ	(sizeof(struct pmc))

/*
 * Locks and Lock groups
 */
static lck_grp_t *pmc_lock_grp = LCK_GRP_NULL;
static lck_grp_attr_t *pmc_lock_grp_attr;
static lck_attr_t *pmc_lock_attr;

/* PMC tracking queue locks */
static lck_spin_t perf_monitor_queue_spin;		/* protects adding and removing from queue */
static lck_spin_t perf_counters_queue_spin;		/* protects adding and removing from queue */

/* Reservation tracking queues lock */
static lck_spin_t reservations_spin;

/*
 * Tracking queues
 *
 * Keeps track of registered perf monitors and perf counters
 */
static queue_t perf_monitors_queue = NULL;
static volatile uint32_t perf_monitors_count = 0U;

static queue_t perf_counters_queue = NULL;
static volatile uint32_t perf_counters_count = 0U;

/* 
 * Reservation queues
 *
 * Keeps track of all system, task, and thread-level reservations (both active and
 * inactive).
 *
 * We track them all here (rather than in their respective task or thread only)
 * so that we can inspect our tracking data directly (rather than peeking at
 * every task and thread) to determine if/when a new reservation would
 * constitute a conflict.
 */
static queue_t system_reservations = NULL;
static volatile uint32_t system_reservation_count = 0U;

static queue_t task_reservations = NULL;
static volatile uint32_t task_reservation_count = 0U;

static queue_t thread_reservations = NULL;
static volatile uint32_t thread_reservation_count = 0U;


#if XNU_KERNEL_PRIVATE

/*
 * init_pmc_locks creates and initializes all the locks and lock groups and lock
 * attributes required for the pmc sub-system.
 */
static void init_pmc_locks(void) {
	pmc_lock_attr = lck_attr_alloc_init();
	assert(pmc_lock_attr);

	pmc_lock_grp_attr = lck_grp_attr_alloc_init();
	assert(pmc_lock_grp_attr);

	pmc_lock_grp = lck_grp_alloc_init("pmc", pmc_lock_grp_attr);
	assert(pmc_lock_grp);

	lck_spin_init(&perf_monitor_queue_spin, pmc_lock_grp, pmc_lock_attr);
	lck_spin_init(&perf_counters_queue_spin, pmc_lock_grp, pmc_lock_attr);

	lck_spin_init(&reservations_spin, pmc_lock_grp, pmc_lock_attr);
}

/*
 * init_pmc_zones initializes the allocation zones used by the pmc subsystem
 */
static void init_pmc_zones(void) {
	perf_small_zone = zinit(PERF_SMALL_UNIT_SZ, 
		MAX_PERF_SMALLS * PERF_SMALL_UNIT_SZ, MAX_PERF_SMALLS, 
		"pmc.small zone");

	assert(perf_small_zone);

	perf_big_zone = zinit(PERF_BIG_UNIT_SZ,
		MAX_PERF_BIGS * PERF_BIG_UNIT_SZ, MAX_PERF_BIGS, 
		"pmc.big zone");

	assert(perf_big_zone);
}

/*
 * init_pmc_queues allocates and initializes the tracking queues for
 * registering and reserving individual pmcs and perf monitors.
 */
static void init_pmc_queues(void) {
	perf_monitors_queue = (queue_t)kalloc(sizeof(queue_t));
	assert(perf_monitors_queue);

	queue_init(perf_monitors_queue);

	perf_counters_queue = (queue_t)kalloc(sizeof(queue_t));
	assert(perf_counters_queue);

	queue_init(perf_counters_queue);

	system_reservations = (queue_t)kalloc(sizeof(queue_t));
	assert(system_reservations);

	queue_init(system_reservations);

	task_reservations = (queue_t)kalloc(sizeof(queue_t));
	assert(task_reservations);

	queue_init(task_reservations);

	thread_reservations = (queue_t)kalloc(sizeof(queue_t));
	assert(thread_reservations);

	queue_init(thread_reservations);
}

/*
 * pmc_bootstrap brings up all the necessary infrastructure required to use the
 * pmc sub-system.
 */
__private_extern__
void pmc_bootstrap(void) {
	/* build our alloc zones */
	init_pmc_zones();

	/* build the locks */
	init_pmc_locks();

	/* build our tracking queues */
	init_pmc_queues();
}

#endif /* XNU_KERNEL_PRIVATE */

/*
 * Perf Monitor Internals
 */

static perf_monitor_t perf_monitor_alloc(void) {
	/* perf monitors come from the perf small zone */
	return (perf_monitor_t)zalloc(perf_small_zone);
}

static void perf_monitor_free(void *pm) {
	zfree(perf_small_zone, pm);
}

static void perf_monitor_init(perf_monitor_t pm) {
	assert(pm);

	pm->object = NULL;

	bzero(&(pm->methods), sizeof(perf_monitor_methods_t));

	pm->useCount = 1;	/* initial retain count of 1, for caller */

	pm->link.next = pm->link.prev = (queue_entry_t)NULL;
}

/*
 * perf_monitor_dequeue removes the given perf_monitor_t from the
 * perf_monitor_queue, thereby unregistering it with the system.
 */
static void perf_monitor_dequeue(perf_monitor_t pm) {
	lck_spin_lock(&perf_monitor_queue_spin);
	
	/* 
	 * remove the @pm object from the @perf_monitor_queue queue (it is of type
	 * <perf_monitor_t> and has a field called @link that is the queue_link_t
	 */
	queue_remove(perf_monitors_queue, pm, perf_monitor_t, link);

	perf_monitors_count--;

	lck_spin_unlock(&perf_monitor_queue_spin);
}

/*
 * perf_monitor_enqueue adds the given perf_monitor_t to the perf_monitor_queue,
 * thereby registering it for use with the system.
 */
static void perf_monitor_enqueue(perf_monitor_t pm) {
	lck_spin_lock(&perf_monitor_queue_spin);

	queue_enter(perf_monitors_queue, pm, perf_monitor_t, link);

	perf_monitors_count++;

	lck_spin_unlock(&perf_monitor_queue_spin);
}

/*
 * perf_monitor_reference increments the reference count for the given
 * perf_monitor_t.
 */
static void perf_monitor_reference(perf_monitor_t pm) {
	assert(pm);

	OSIncrementAtomic(&(pm->useCount));
}

/*
 * perf_monitor_deallocate decrements the reference count for the given
 * perf_monitor_t.  If the reference count hits 0, the object is released back
 * to the perf_small_zone via a call to perf_monitor_free().
 */
static void perf_monitor_deallocate(perf_monitor_t pm) {
	assert(pm);

	/* If we just removed the last reference count */
	if(1 == OSDecrementAtomic(&(pm->useCount))) {
		/* Free the object */
		perf_monitor_free(pm);
	}
}

/*
 * perf_monitor_find attempts to find a perf_monitor_t that corresponds to the
 * given C++ object pointer that was used when registering with the subsystem.
 *
 * If found, the method returns the perf_monitor_t with an extra reference 
 * placed on the object (or NULL if not
 * found).
 *
 * NOTE: Caller must use perf_monitor_deallocate to remove the extra reference after
 * calling perf_monitor_find.
 */
static perf_monitor_t perf_monitor_find(perf_monitor_object_t monitor) {
	assert(monitor);
	perf_monitor_t element = NULL;
	perf_monitor_t found = NULL;

	lck_spin_lock(&perf_monitor_queue_spin);
	
	queue_iterate(perf_monitors_queue, element, perf_monitor_t, link) {
		if(element && element->object == monitor) {
			/* We found it - reference the object. */
			perf_monitor_reference(element);
			found = element;
			break;
		}
	}

	lck_spin_unlock(&perf_monitor_queue_spin);

	return found;
}

/*
 * perf_monitor_add_pmc adds a newly registered PMC to the perf monitor it is
 * aassociated with.
 */
static void perf_monitor_add_pmc(perf_monitor_t pm, pmc_t pmc __unused) {
	assert(pm);
	assert(pmc);

	/* Today, we merely add a reference count now that a new pmc is attached */
	perf_monitor_reference(pm);
}

/*
 * perf_monitor_remove_pmc removes a newly *un*registered PMC from the perf
 * monitor it is associated with.
 */
static void perf_monitor_remove_pmc(perf_monitor_t pm, pmc_t pmc __unused) {
	assert(pm);
	assert(pmc);

	/* Today, we merely remove a reference count now that the pmc is detached */
	perf_monitor_deallocate(pm);
}

/*
 * Perf Counter internals
 */

static pmc_t pmc_alloc(void) {
	return (pmc_t)zalloc(perf_big_zone);
}

static void pmc_free(void *pmc) {
	zfree(perf_big_zone, pmc);
}

/*
 * pmc_init initializes a newly allocated pmc_t
 */
static void pmc_init(pmc_t pmc) {
	assert(pmc);

	pmc->object = NULL;
	pmc->monitor = NULL;

	bzero(&pmc->methods, sizeof(pmc_methods_t));

	/* One reference for the caller */
	pmc->useCount = 1;
}

/*
 * pmc_reference increments the reference count of the given pmc_t
 */
static void pmc_reference(pmc_t pmc) {
	assert(pmc);

	OSIncrementAtomic(&(pmc->useCount));
}

/*
 * pmc_deallocate decrements the reference count of the given pmc_t. If the
 * reference count hits zero, the given pmc_t is deallocated and released back
 * to the allocation zone.
 */
static void pmc_deallocate(pmc_t pmc) {
	assert(pmc);

	/* If we just removed the last reference count */
	if(1 == OSDecrementAtomic(&(pmc->useCount))) {
		/* Free the pmc */
		pmc_free(pmc);
	}
}

/*
 * pmc_dequeue removes the given, newly *un*registered pmc from the
 * perf_counters_queue.
 */
static void pmc_dequeue(pmc_t pmc) {
	lck_spin_lock(&perf_counters_queue_spin);

	queue_remove(perf_counters_queue, pmc, pmc_t, link);

	perf_counters_count--;

	lck_spin_unlock(&perf_counters_queue_spin);
}

/*
 * pmc_enqueue adds the given, newly registered pmc to the perf_counters_queue
 */
static void pmc_enqueue(pmc_t pmc) {
	lck_spin_lock(&perf_counters_queue_spin);

	queue_enter(perf_counters_queue, pmc, pmc_t, link);

	perf_counters_count++;

	lck_spin_unlock(&perf_counters_queue_spin);
}

/*
 * pmc_find attempts to locate a pmc_t that was registered with the given
 * pmc_object_t pointer.  If found, it returns the pmc_t with an extra reference
 * which must be dropped by the caller by calling pmc_deallocate().
 */
static pmc_t pmc_find(pmc_object_t object) {
	assert(object);

	lck_spin_lock(&perf_counters_queue_spin);
	
	pmc_t element = NULL;
	pmc_t found = NULL;

	queue_iterate(perf_counters_queue, element, pmc_t, link) {
		if(element && element->object == object) {
			pmc_reference(element);

			found = element;
			break;
		}
	}

	lck_spin_unlock(&perf_counters_queue_spin);

	return found;
}

/*
 * Config internals
 */

/* Allocate a pmc_config_t */
static pmc_config_t pmc_config_alloc(pmc_t pmc __unused) {
	return (pmc_config_t)zalloc(perf_small_zone);
}

/* Free a pmc_config_t, and underlying pmc_config_object_t (if needed) */
static void pmc_config_free(pmc_t pmc, pmc_config_t config) {
	assert(pmc);
	assert(config);

	if(config->object) {
		pmc->methods.free_config(pmc->object, config->object);
		config->object = NULL;
	}

	zfree(perf_small_zone, config);
}

static kern_return_t pmc_open(pmc_t pmc) {
	assert(pmc);
	assert(pmc->object);
	assert(pmc->open_object);

	return pmc->methods.open(pmc->object, pmc->open_object);
}

static kern_return_t pmc_close(pmc_t pmc) {
	assert(pmc);
	assert(pmc->object);
	assert(pmc->open_object);

	return pmc->methods.close(pmc->object, pmc->open_object);
}

/*
 * Reservation Internals
 */

static kern_return_t pmc_internal_reservation_set_pmc(pmc_reservation_t resv, pmc_t pmc);
static void pmc_internal_reservation_store(pmc_reservation_t reservation);
static void pmc_internal_reservation_load(pmc_reservation_t reservation);

static pmc_reservation_t reservation_alloc(void) {
	/* pmc reservations come from the perf small zone */
	return (pmc_reservation_t)zalloc(perf_small_zone);
}

/*
 * reservation_free deallocates and releases all resources associated with the
 * given pmc_reservation_t.  This includes freeing the config used to create the
 * reservation, decrementing the reference count for the pmc used to create the
 * reservation, and deallocating the reservation's memory.
 */
static void reservation_free(pmc_reservation_t resv) {
	/* Free config */
	if(resv->config) {
		assert(resv->pmc);

		pmc_free_config(resv->pmc, resv->config);

		resv->config = NULL;
	}

	/* release PMC */
	(void)pmc_internal_reservation_set_pmc(resv, NULL);

	/* Free reservation */
	zfree(perf_small_zone, resv);
}

/*
 * reservation_init initializes a newly created reservation.
 */
static void reservation_init(pmc_reservation_t resv) {
	assert(resv);

	resv->pmc = NULL;
	resv->config = NULL;
	resv->value = 0ULL;

	resv->flags = 0U;
	resv->state = PMC_STATE(PMC_STATE_STATE_STOP, 0, 0);
	resv->active_last_context_in = 0U;

	/*
	 * Since this member is a union, we only need to set either the task 
	 * or thread to NULL.
	 */
	resv->task = TASK_NULL;
}

/*
 * pmc_internal_reservation_set_pmc sets the pmc associated with the reservation object. If
 * there was one set already, it is deallocated (reference is dropped) before
 * the new one is set.  This methods increases the reference count of the given
 * pmc_t.
 *
 * NOTE: It is okay to pass NULL as the pmc_t - this will have the effect of
 * dropping the reference on any previously set pmc, and setting the reservation
 * to having no pmc set.
 */
static kern_return_t pmc_internal_reservation_set_pmc(pmc_reservation_t resv, pmc_t pmc) {
	assert(resv);

	if(resv->pmc) {
		(void)pmc_close(resv->pmc);
		pmc_deallocate(resv->pmc);
		resv->pmc = NULL;
	}

	resv->pmc = pmc;

	if(resv->pmc) {
		pmc_reference(resv->pmc);
		if(KERN_SUCCESS != pmc_open(resv->pmc)) {
			pmc_deallocate(resv->pmc);
			resv->pmc = NULL;

			return KERN_FAILURE;
		}
	}

	return KERN_SUCCESS;
}

/* 
 * Used to place reservation into one of the system, task, and thread queues
 * Assumes the queue's spin lock is already held.
 */
static void pmc_internal_reservation_enqueue(queue_t queue, pmc_reservation_t resv) {
	assert(queue);
	assert(resv);

	queue_enter(queue, resv, pmc_reservation_t, link);
}

static void pmc_internal_reservation_dequeue(queue_t queue, pmc_reservation_t resv) {
	assert(queue);
	assert(resv);

	queue_remove(queue, resv, pmc_reservation_t, link);
}

/* Returns TRUE if the reservation applies to the current execution context */
static boolean_t pmc_internal_reservation_matches_context(pmc_reservation_t resv) {
	boolean_t ret = FALSE;
	assert(resv);

	if(PMC_FLAG_IS_SYSTEM_SCOPE(resv->flags)) {
		ret = TRUE;
	} else if(PMC_FLAG_IS_TASK_SCOPE(resv->flags)) {
		if(current_task() == resv->task) {
			ret = TRUE;
		}
	} else if(PMC_FLAG_IS_THREAD_SCOPE(resv->flags)) {
		if(current_thread() == resv->thread) {
			ret = TRUE;
		}
	}

	return ret;
}

/*
 * pmc_accessible_core_count returns the number of logical cores that can access
 * a given @pmc.  0 means every core in the system.
 */
static uint32_t pmc_accessible_core_count(pmc_t pmc) {
	assert(pmc);

	uint32_t *cores = NULL;
	size_t coreCt = 0UL;

	if(KERN_SUCCESS != pmc->methods.accessible_cores(pmc->object,
		&cores, &coreCt)) {
		coreCt = 0U;
	}

	return (uint32_t)coreCt;
}

/* spin lock for the queue must already be held */
/*
 * This method will inspect the task/thread of the reservation to see if it
 * matches the new incoming one (for thread/task reservations only).  Will only
 * return TRUE if the task/thread matches.
 */
static boolean_t pmc_internal_reservation_queue_contains_pmc(queue_t queue, pmc_reservation_t
resv) {
	assert(queue);
	assert(resv);

	boolean_t ret = FALSE;
	pmc_reservation_t tmp = NULL;

	queue_iterate(queue, tmp, pmc_reservation_t, link) {
		if(tmp) {
			if(tmp->pmc == resv->pmc) {
				/* PMC matches - make sure scope matches first */
				switch(PMC_FLAG_SCOPE(tmp->flags)) {
					case PMC_FLAG_SCOPE_SYSTEM:
						/*
						 * Found a reservation in system queue with same pmc - always a
						 * conflict.
						 */
						ret = TRUE;
						break;
					case PMC_FLAG_SCOPE_THREAD:
						/*
						 * Found one in thread queue with the same PMC as the
						 * argument. Only a conflict if argument scope isn't
						 * thread or system, or the threads match.
						 */
						ret = (PMC_FLAG_SCOPE(resv->flags) != PMC_FLAG_SCOPE_THREAD) || 
							(tmp->thread == resv->thread);

						if(!ret) {
							/*
							 * so far, no conflict - check that the pmc that is
							 * being reserved isn't accessible from more than
							 * one core, if it is, we need to say it's already
							 * taken.
							 */
							if(1 != pmc_accessible_core_count(tmp->pmc)) {
								ret = TRUE;
							}
						}
						break;
					case PMC_FLAG_SCOPE_TASK:
						/* 
						 * Follow similar semantics for task scope.
						 */

						ret = (PMC_FLAG_SCOPE(resv->flags) != PMC_FLAG_SCOPE_TASK) ||
							(tmp->task == resv->task);
						if(!ret) {
							/*
							 * so far, no conflict - check that the pmc that is
							 * being reserved isn't accessible from more than
							 * one core, if it is, we need to say it's already
							 * taken.
							 */
							if(1 != pmc_accessible_core_count(tmp->pmc)) {
								ret = TRUE;
							}
						}

						break;
				}

				if(ret) break;
			}
		}
	}

	return ret;
}

/*
 * pmc_internal_reservation_validate_for_pmc returns TRUE if the given reservation can be 
 * added to its target queue without createing conflicts (target queue is 
 * determined by the reservation's scope flags). Further, this method returns
 * FALSE if any level contains a reservation for a PMC that can be accessed from
 * more than just 1 core, and the given reservation also wants the same PMC.
 */
static boolean_t pmc_internal_reservation_validate_for_pmc(pmc_reservation_t resv) {
	assert(resv);
	boolean_t ret = TRUE;

	if(pmc_internal_reservation_queue_contains_pmc(system_reservations, resv) ||
		pmc_internal_reservation_queue_contains_pmc(task_reservations, resv) ||
		pmc_internal_reservation_queue_contains_pmc(thread_reservations, resv)) {
		ret = FALSE;
	}

	return ret;
}

static void pmc_internal_update_thread_flag(thread_t thread, boolean_t newFlag) {
	assert(thread);

	/* See if this thread needs it's PMC flag set */
	pmc_reservation_t tmp = NULL;

	if(!newFlag) {
		/*
		 * If the parent task just dropped its reservation, iterate the thread
		 * reservations to see if we need to keep the pmc flag set for the given
		 * thread or not.
		 */
		lck_spin_lock(&reservations_spin);
	
		queue_iterate(thread_reservations, tmp, pmc_reservation_t, link) {
			if(tmp->thread == thread) {
				newFlag = TRUE;
				break;
			}
		}

		lck_spin_unlock(&reservations_spin);
	}

	if(newFlag) {
		OSBitOrAtomic(THREAD_PMC_FLAG, &thread->t_chud);
	} else {
		OSBitAndAtomic(~(THREAD_PMC_FLAG), &thread->t_chud);
	}
}

/* 
 * This operation is (worst case) O(N*M) where N is number of threads in the
 * given task, and M is the number of thread reservations in our system.
 */
static void pmc_internal_update_task_flag(task_t task, boolean_t newFlag) {
	assert(task);
	thread_t thread = NULL;

	if(newFlag) {
		OSBitOrAtomic(TASK_PMC_FLAG, &task->t_chud);
	} else {
		OSBitAndAtomic(~(TASK_PMC_FLAG), &task->t_chud);
	}

	task_lock(task);

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		/* propagate the task's mask down to each thread  */
		pmc_internal_update_thread_flag(thread, newFlag);
	}

	task_unlock(task);
}

/*
 * pmc_internal_reservation_add adds a reservation to the global tracking queues after
 * ensuring there are no reservation conflicts.  To do this, it takes all the
 * spin locks for all the queue (to ensure no other core goes and adds a
 * reservation for the same pmc to a queue that has already been checked).
 */
static boolean_t pmc_internal_reservation_add(pmc_reservation_t resv) {
	assert(resv);

	boolean_t ret = FALSE;

	/* always lock all three in the same order */
	lck_spin_lock(&reservations_spin);

	/* Check if the reservation can be added without conflicts */
	if(pmc_internal_reservation_validate_for_pmc(resv)) {
		ret = TRUE;
	}

	if(ret) {
		/* add reservation to appropriate scope */
		switch(PMC_FLAG_SCOPE(resv->flags)) {

			/* System-wide counter */
			case PMC_FLAG_SCOPE_SYSTEM:
				/* Simply add it to the system queue */
				pmc_internal_reservation_enqueue(system_reservations, resv);
				system_reservation_count++;
				
				lck_spin_unlock(&reservations_spin);

				break;

			/* Task-switched counter */
			case PMC_FLAG_SCOPE_TASK:
				assert(resv->task);

				/* Not only do we enqueue it in our local queue for tracking */
				pmc_internal_reservation_enqueue(task_reservations, resv);
				task_reservation_count++;

				lck_spin_unlock(&reservations_spin);

				/* update the task mask, and propagate it to existing threads */
				pmc_internal_update_task_flag(resv->task, TRUE);
				break;

			/* Thread-switched counter */
			case PMC_FLAG_SCOPE_THREAD:
				assert(resv->thread);

				/*
				 * Works the same as a task-switched counter, only at
				 * thread-scope
				 */

				pmc_internal_reservation_enqueue(thread_reservations, resv);
				thread_reservation_count++;

				lck_spin_unlock(&reservations_spin);
				
				pmc_internal_update_thread_flag(resv->thread, TRUE);
				break;
			}
	} else {
		lck_spin_unlock(&reservations_spin);
	}			
	
	return ret;
}

static void pmc_internal_reservation_broadcast(pmc_reservation_t reservation, void (*action_func)(void *)) {
	uint32_t * cores;
	size_t core_cnt;
	
	/* Get the list of accessible cores */
	if (KERN_SUCCESS == pmc_get_accessible_core_list(reservation->pmc, &cores, &core_cnt)) {
		boolean_t intrs_enabled = ml_set_interrupts_enabled(FALSE);

		/* Fast case: the PMC is only accessible from one core and we happen to be on it */
		if (core_cnt == 1 && cores[0] == (uint32_t)cpu_number()) {
			action_func(reservation);
		} else {
			/* Call action_func on every accessible core */
#if defined(__i386__) || defined(__x86_64__)
			size_t ii;
			cpumask_t mask = 0;
			
			/* Build a mask for the accessible cores */
			if (core_cnt > 0) {
				for (ii = 0; ii < core_cnt; ii++) {
					mask |= cpu_to_cpumask(cores[ii]);
				}
			} else {
				/* core_cnt = 0 really means all cpus */
				mask = CPUMASK_ALL;
			}
			
			/* Have each core run pmc_internal_reservation_stop_cpu asynchronously. */
			mp_cpus_call(mask, ASYNC, action_func, reservation);
#else
#error pmc_reservation_interrupt needs an inter-processor method invocation mechanism for this architecture
#endif
		}

		ml_set_interrupts_enabled(intrs_enabled);
	}
	
}

/*
 * pmc_internal_reservation_remove removes the given reservation from the appropriate
 * reservation queue according to its scope. 
 *
 * NOTE: The scope flag must have been set for this method to function.
 */
static void pmc_internal_reservation_remove(pmc_reservation_t resv) {
	assert(resv);

	/*
	 * Due to the way the macros are written, we can't just blindly queue-remove
	 * the reservation without knowing which queue it's in. We figure this out
	 * using the reservation's scope flags.
	 */

	switch(PMC_FLAG_SCOPE(resv->flags)) {

		case PMC_FLAG_SCOPE_SYSTEM:
			lck_spin_lock(&reservations_spin);
			pmc_internal_reservation_dequeue(system_reservations, resv);
			system_reservation_count--;
			lck_spin_unlock(&reservations_spin);
			break;

		case PMC_FLAG_SCOPE_TASK:
			
			/* Lock the global spin lock */
			lck_spin_lock(&reservations_spin);

			/* remove from the global queue */
			pmc_internal_reservation_dequeue(task_reservations, resv);
			task_reservation_count--;

			/* unlock the global */
			lck_spin_unlock(&reservations_spin);

			/* Recalculate task's counter mask */
			pmc_internal_update_task_flag(resv->task, FALSE);
			break;

		case PMC_FLAG_SCOPE_THREAD:
			lck_spin_lock(&reservations_spin);

			pmc_internal_reservation_dequeue(thread_reservations, resv);
			thread_reservation_count--;

			lck_spin_unlock(&reservations_spin);

			/* recalculate the thread's counter mask */
			pmc_internal_update_thread_flag(resv->thread, FALSE);

			break;
	}
}

/* Reservation State Machine
 *
 * The PMC subsystem uses a 3-tuple of state information packed into a 32-bit quantity and a 
 * set of 9 events to provide MP-safe bookkeeping and control flow.  The 3-tuple is comprised 
 * of a state, a count of active contexts, and a set of modifier flags.  A state machine defines
 * the possible transitions at each event point given the current 3-tuple.  Atomicity is handled
 * by reading the current 3-tuple, applying the transformations indicated by the state machine
 * and then attempting to OSCompareAndSwap the transformed value.  If the OSCompareAndSwap fails,
 * the process is repeated until either the OSCompareAndSwap succeeds or not valid transitions are
 * available.
 *
 * The state machine is described using tuple notation for the current state and a related notation
 * for describing the transformations.  For concisness, the flag and state names are abbreviated as
 * follows:
 * 
 * states:
 * S = STOP
 * CR = CAN_RUN
 * L = LOAD
 * R = RUN
 * ST = STORE
 * I = INTERRUPT
 * D = DEALLOC
 *
 * flags:
 *
 * S = STOPPING
 * D = DEALLOCING
 * I = INTERRUPTING
 *
 * The tuple notation is formed from the following pattern:
 *
 * tuple = < state, active-context-count, flags >
 * state = S | CR | L | R | ST | I | D
 * active-context-count = 0 | >0 | 1 | >1
 * flags = flags flag | blank
 * flag = S | D | I
 *
 * The transform notation is similar, but only describes the modifications made to the current state.
 * The notation is formed from the following pattern:
 * 
 * transform = < state, active-context-count, flags >
 * state = S | CR | L | R | ST | I | D
 * active-context-count = + | - | blank
 * flags = flags flag | flags !flag | blank
 * flag = S | D | I
 *
 * And now for the state machine:
 * State		Start		Stop		Free		Interrupt		End Interrupt		Context In		Context Out	Load Finished		Store Finished
 * <CR, 0, >				<S, , >		<D, , >			<L, +, >
 * <D, 0, >
 * <D, 1, D>									< , -, !D>
 * <D, >1, D>									< , -, >
 * <I, 0, D>									<D, , !D>
 * <I, 0, S>	< , , !S>				< , , !SD>		<S, , !S>
 * <I, 0, >					< , , S>	< , , D>	<CR, , >
 * <L, 1, D>									<ST, -, >
 * <L, 1, ID>									<ST, -, >
 * <L, 1, IS>							< , , !SD>	<ST, -, >
 * <L, 1, S>	< , , !S>				< , , !SD>		<ST, -, >
 * <L, 1, >					< , , S>	< , , D>	< , , IS>							< , +, >	<R, , >
 * <L, >1, D>									< , -, >		<R, -, >
 * <L, >1, ID>									< , -, >		<R, -, >
 * <L, >1, IS>							< , , !SD>	< , -, >		<R, -, >
 * <L, >1, S>	< , , !S>				< , , !SD>		< , -, >		<R, -, >
 * <L, >1, >				< , , S>	< , , D>	< , , IS>							< , +, >		< , -, >		<R, , >
 * <R, 1, D>									<ST, -, >
 * <R, 1, ID>									<ST, -, >
 * <R, 1, IS>							< , , !SD>	<ST, -, >
 * <R, 1, S>	< , , !S>				< , , !SD>		<ST, -, >
 * <R, 1, >					< , , S>	< , , D>	< , , IS>							< , +, >	<ST, -, >
 * <R, >1, D>									< , -, >
 * <R, >1, ID>									< , -, >
 * <R, >1, IS>							< , , !SD>	< , -, >
 * <R, >1, S>	< , , !S>				< , , !SD>		< , -, >
 * <R, >1, >				< , , S>	< , , D>	< , , IS>							< , +, >		< , -, >
 * <S, 0, >		<CR, , >				<D, , >
 * <S, 1, ID>									<I, -, !I>
 * <S, 1, IS>							< , , !SD>	<I, -, !I>
 * <S, 1, S>	< , , !S>				<D, , !SD>		< , -, !S>
 * <S, 1, >					< , , S>	<D, , D>	<L, +, >		<CR, -, >
 * <S, >1, ID>									< , -, >
 * <S, >1, IS>							< , , !SD>	< , -, >
 * <S, >1, S>	< , , !S>				<D, , !SD>		< , -, >
 * <S, >1, >				< , , S>	<D, , D>		<L, +, >		< , -, >
 * <ST, 0, D>									<D, , !D>
 * <ST, 0, ID>									<I, , !I>
 * <ST, 0, IS>							< , , !SD>	<I, , !I>
 * <ST, 0, S>	< , , !S>				< , , !SD>		<S, , !S>
 * <ST, 0, >				< , , S>	< , , D>	< , , IS>							< , +, >		<CR, , >
 * <ST, >0, D>									< , -, >							<D, , >
 * <ST, >0, ID>								< , -, >							<S, , >
 * <ST, >0, IS>							< , , !SD>										< , -, >			<S, , >
 * <ST, >0, S>	< , , !S>				< , , !SD>		< , -, >							<S, , >
 * <ST, >0, >				< , , S>	< , , D>	< , , IS>							< , +, >		< , -, >			<L, , >
 */

static uint32_t pmc_internal_reservation_next_state(uint32_t current_state, pmc_state_event_t event) {
	uint32_t new_state = PMC_STATE(PMC_STATE_STATE_INVALID, 0, 0);
	
	switch (event) {
		case PMC_STATE_EVENT_START:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_INTERRUPT, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_STOPPING):
					new_state = PMC_STATE_MODIFY(current_state, 0, 0, PMC_STATE_FLAGS_STOPPING);
					break;
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) == 0) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_CAN_RUN, 0, 0, 0);
					}
					break;
			}
			break;
		case PMC_STATE_EVENT_STOP:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_CAN_RUN, 0, 0):
					new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_STOP, 0, 0, 0);
					break;
				case PMC_STATE(PMC_STATE_STATE_INTERRUPT, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, 0):
					new_state = PMC_STATE_MODIFY(current_state, 0, PMC_STATE_FLAGS_STOPPING, 0);
					break;
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) > 0) {
						new_state = PMC_STATE_MODIFY(current_state, 0, PMC_STATE_FLAGS_STOPPING, 0);
					}
					break;
			}
			break;
		case PMC_STATE_EVENT_FREE:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_CAN_RUN, 0, 0):
					new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_DEALLOC, 0, 0, 0);
					break;
				case PMC_STATE(PMC_STATE_STATE_INTERRUPT, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_STOPPING):
					new_state = PMC_STATE_MODIFY(current_state, 0, PMC_STATE_FLAGS_DEALLOCING, PMC_STATE_FLAGS_STOPPING);
					break;
				case PMC_STATE(PMC_STATE_STATE_INTERRUPT, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, 0):
					new_state = PMC_STATE_MODIFY(current_state, 0, PMC_STATE_FLAGS_DEALLOCING, 0);
					break;
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, PMC_STATE_FLAGS_STOPPING):
					new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_DEALLOC, 0, PMC_STATE_FLAGS_DEALLOCING, PMC_STATE_FLAGS_STOPPING);
					break;
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) > 0) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_DEALLOC, 0, PMC_STATE_FLAGS_DEALLOCING, 0);
					} else {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_DEALLOC, 0, 0, 0);
					}
					break;
			}
			break;
		case PMC_STATE_EVENT_INTERRUPT:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, 0):
					new_state = PMC_STATE_MODIFY(current_state, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING, 0);
					break;
			}
			break;
		case PMC_STATE_EVENT_END_OF_INTERRUPT:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_INTERRUPT, 0, PMC_STATE_FLAGS_DEALLOCING):
					new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_DEALLOC, 0, 0, PMC_STATE_FLAGS_DEALLOCING);
					break;
				case PMC_STATE(PMC_STATE_STATE_INTERRUPT, 0, PMC_STATE_FLAGS_STOPPING):
					new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_STOP, 0, 0, PMC_STATE_FLAGS_STOPPING);
					break;
				case PMC_STATE(PMC_STATE_STATE_INTERRUPT, 0, 0):
					new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_CAN_RUN, 0, 0, 0);
					break;
			}
			break;
		case PMC_STATE_EVENT_CONTEXT_IN:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_CAN_RUN, 0, 0):
					new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_LOAD, 1, 0, 0);
					break;
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, 0):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, 0):
					new_state = PMC_STATE_MODIFY(current_state, 1, 0, 0);
					break;
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) > 0) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_LOAD, 1, 0, 0);
					}
					break;
			}
			break;
		case PMC_STATE_EVENT_CONTEXT_OUT:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_DEALLOC, 0, PMC_STATE_FLAGS_DEALLOCING):
					if (PMC_STATE_CONTEXT_COUNT(current_state) > 1) {
						new_state = PMC_STATE_MODIFY(current_state, -1, 0, PMC_STATE_FLAGS_DEALLOCING);
					} else {
						new_state = PMC_STATE_MODIFY(current_state, -1, 0, 0);
					}					
					break;
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) > 1) {
						new_state = PMC_STATE_MODIFY(current_state, -1, 0, 0);
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_RUN, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) == 1) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_STORE, -1, 0, 0);
					} else {
						new_state = PMC_STATE_MODIFY(current_state, -1, 0, 0);
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
					if (PMC_STATE_CONTEXT_COUNT(current_state) == 1) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_INTERRUPT, -1, 0, PMC_STATE_FLAGS_INTERRUPTING);
					} else {
						new_state = PMC_STATE_MODIFY(current_state, -1, 0, 0);
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, PMC_STATE_FLAGS_STOPPING):
					if (PMC_STATE_CONTEXT_COUNT(current_state) == 1) {
						new_state = PMC_STATE_MODIFY(current_state, -1, 0, PMC_STATE_FLAGS_STOPPING);
					} else {
						new_state = PMC_STATE_MODIFY(current_state, -1, 0, 0);
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_STOP, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) > 0) {
						if (PMC_STATE_CONTEXT_COUNT(current_state) == 1) {
							new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_CAN_RUN, -1, 0, 0);
						} else {
							new_state = PMC_STATE_MODIFY(current_state, -1, 0, 0);
						}
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) > 0) {
						new_state = PMC_STATE_MODIFY(current_state, -1, 0, 0);
					}
					break;
			}
			break;
		case PMC_STATE_EVENT_LOAD_FINISHED:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, PMC_STATE_FLAGS_STOPPING):
					if (PMC_STATE_CONTEXT_COUNT(current_state) > 1) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_RUN, -1, 0, 0);
					} else {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_STORE, -1, 0, 0);
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_LOAD, 0, 0):
					new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_RUN, 0, 0, 0);
					break;
			}
			break;
		case PMC_STATE_EVENT_STORE_FINISHED:
			switch (current_state & ~(PMC_STATE_CONTEXT_COUNT_MASK)) {
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_DEALLOCING):
					if (PMC_STATE_CONTEXT_COUNT(current_state) == 0) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_DEALLOC, 0, 0, PMC_STATE_FLAGS_DEALLOCING);
					} else {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_DEALLOC, 0, 0, 0);
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_DEALLOCING):
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_INTERRUPTING | PMC_STATE_FLAGS_STOPPING):
					if (PMC_STATE_CONTEXT_COUNT(current_state) == 0) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_INTERRUPT, 0, 0, PMC_STATE_FLAGS_INTERRUPTING);
					} else {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_STOP, 0, 0, 0);
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, PMC_STATE_FLAGS_STOPPING):
					if (PMC_STATE_CONTEXT_COUNT(current_state) == 0) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_STOP, 0, 0, PMC_STATE_FLAGS_STOPPING);
					} else {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_STOP, 0, 0, 0);
					}
					break;
				case PMC_STATE(PMC_STATE_STATE_STORE, 0, 0):
					if (PMC_STATE_CONTEXT_COUNT(current_state) == 0) {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_CAN_RUN, 0, 0, 0);
					} else {
						new_state = PMC_STATE_MOVE(current_state, PMC_STATE_STATE_LOAD, 0, 0, 0);
					}
					break;
			}
			break;
	}
	
	return new_state;
}

static uint32_t pmc_internal_reservation_move_for_event(pmc_reservation_t reservation, pmc_state_event_t event, pmc_state_t *old_state_out) {
	pmc_state_t oldState;
	pmc_state_t newState;

	assert(reservation);
	
	/* Determine what state change, if any, we need to do.  Keep trying until either we succeed doing a transition
	 * or the there is no valid move.
	 */	
	do {
		oldState = reservation->state;
		newState = pmc_internal_reservation_next_state(oldState, event);
	} while (newState != PMC_STATE_INVALID && !OSCompareAndSwap(oldState, newState, &(reservation->state)));
	
	if (newState != PMC_STATE_INVALID) {
		COUNTER_DEBUG("Moved reservation %p from state "PMC_STATE_FORMAT" to state "PMC_STATE_FORMAT" for event %s\n", reservation, PMC_STATE_ARGS(oldState), PMC_STATE_ARGS(newState), pmc_state_event_name(event));
	} else {
		COUNTER_DEBUG("No valid moves for reservation %p in state "PMC_STATE_FORMAT" for event %s\n", reservation, PMC_STATE_ARGS(oldState), pmc_state_event_name(event));
	}
	
	if (old_state_out != NULL) {
		*old_state_out = oldState;
	}
	
	return newState;
}
					
static void pmc_internal_reservation_context_out(pmc_reservation_t reservation) {
	assert(reservation);
	pmc_state_t newState;
	pmc_state_t oldState;

	/* Clear that the this reservation was active when this cpu did its last context in */
	OSBitAndAtomic(~(1U << cpu_number()), &(reservation->active_last_context_in));
	
	/* Move the state machine */
	if (PMC_STATE_INVALID == (newState = pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_CONTEXT_OUT, &oldState))) {
		return;
	}
	
	/* Do any actions required based on the state change */
	if (PMC_STATE_STATE(newState) == PMC_STATE_STATE_STORE && PMC_STATE_STATE(oldState) != PMC_STATE_STATE_STORE) {
		/* Just moved into STORE, so store the reservation. */
		pmc_internal_reservation_store(reservation);
	} else if (PMC_STATE_STATE(newState) == PMC_STATE_STATE_DEALLOC && PMC_STATE_CONTEXT_COUNT(newState) == 0 && PMC_STATE_FLAGS(newState) == 0) {
		/* Wakeup any thread blocking for this reservation to hit <DEALLOC, 0, > */
		thread_wakeup((event_t)reservation);
	}
	
}

static void pmc_internal_reservation_context_in(pmc_reservation_t reservation) {
	assert(reservation);
	pmc_state_t oldState;
	pmc_state_t newState;
	
	/* Move the state machine */
	if (PMC_STATE_INVALID == (newState = pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_CONTEXT_IN, &oldState))) {
		return;
	}

	/* Mark that the reservation was active when this cpu did its last context in */
	OSBitOrAtomic(1U << cpu_number(), &(reservation->active_last_context_in));
		
	/* Do any actions required based on the state change */
	if (PMC_STATE_STATE(newState) == PMC_STATE_STATE_LOAD && PMC_STATE_STATE(oldState) != PMC_STATE_STATE_LOAD) {
		/* Just moved into LOAD, so load the reservation. */
		pmc_internal_reservation_load(reservation);
	}
	
}

static void pmc_internal_reservation_store(pmc_reservation_t reservation) {
	assert(reservation);
	assert(PMC_STATE_STATE(reservation->state) == PMC_STATE_STATE_STORE);
	
	assert(reservation->pmc);
	assert(reservation->config);

	pmc_state_t newState;
	kern_return_t ret = KERN_SUCCESS;
	
	pmc_t store_pmc = reservation->pmc;
	pmc_object_t store_pmc_obj = store_pmc->object;
	perf_monitor_t store_pm = store_pmc->monitor;

	/* 
	 * Instruct the Perf Monitor that contains this counter to turn 
	 * off the global disable for this counter.
	 */
	ret = store_pm->methods.disable_counters(store_pm->object, &store_pmc_obj, 1);
	if(KERN_SUCCESS != ret) {
		COUNTER_DEBUG(" [error] disable_counters: 0x%x\n", ret);
		return;
	}

	/* Instruct the counter to disable itself */
	ret = store_pmc->methods.disable(store_pmc_obj);
	if(KERN_SUCCESS != ret) {
		COUNTER_DEBUG("  [error] disable: 0x%x\n", ret);
	}

	/*
	 * At this point, we're off the hardware, so we don't have to
	 * set_on_hardare(TRUE) if anything fails from here on.
	 */

	/* store the counter value into the reservation's stored count */
	ret = store_pmc->methods.get_count(store_pmc_obj, &reservation->value);
	if(KERN_SUCCESS != ret) {
		COUNTER_DEBUG("  [error] get_count: 0x%x\n", ret);
		return;
	}
		
	/* Advance the state machine now that the STORE is finished */
	if (PMC_STATE_INVALID == (newState = pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_STORE_FINISHED, NULL))) {
		return;
	}

	/* Do any actions required based on the state change */
	if (PMC_STATE_STATE(newState) == PMC_STATE_STATE_LOAD) {
		/* Just moved into LOAD, so load the reservation. */
		pmc_internal_reservation_load(reservation);
	} else if (PMC_STATE_STATE(newState) == PMC_STATE_STATE_DEALLOC && PMC_STATE_CONTEXT_COUNT(newState) == 0 && PMC_STATE_FLAGS(newState) == 0) {
		/* Wakeup any thread blocking for this reservation to hit <DEALLOC, 0, > */
		thread_wakeup((event_t)reservation);
	}
	
}

static void pmc_internal_reservation_load(pmc_reservation_t reservation) {
	assert(reservation);
	assert(PMC_STATE_STATE(reservation->state) == PMC_STATE_STATE_LOAD);

	pmc_state_t newState;
	kern_return_t ret = KERN_SUCCESS;

	assert(reservation->pmc);
	assert(reservation->config);
	
	pmc_t load_pmc = reservation->pmc;
	pmc_object_t load_pmc_obj = load_pmc->object;
	perf_monitor_t load_pm = load_pmc->monitor;

	/* Set the control register up with the stored configuration */
	ret = load_pmc->methods.set_config(load_pmc_obj, reservation->config->object);
	if(KERN_SUCCESS != ret) {
		COUNTER_DEBUG("  [error] set_config: 0x%x\n", ret);
		return;
	}

	/* load the counter value */
	ret = load_pmc->methods.set_count(load_pmc_obj, reservation->value);
	if(KERN_SUCCESS != ret) {
		COUNTER_DEBUG("  [error] set_count: 0x%x\n", ret);
		return;
	}

	/* Locally enable the counter */
	ret = load_pmc->methods.enable(load_pmc_obj);
	if(KERN_SUCCESS != ret) {
		COUNTER_DEBUG("  [error] enable: 0x%x\n", ret);
		return;
	}

	/*
	 * Instruct the Perf Monitor containing the pmc to enable the
	 * counter.
	 */
	ret = load_pm->methods.enable_counters(load_pm->object, &load_pmc_obj, 1);
	if(KERN_SUCCESS != ret) {
		COUNTER_DEBUG("  [error] enable_counters: 0x%x\n", ret);
		/* not on the hardware. */
		return;
	}
	
	/* Advance the state machine now that the STORE is finished */
	if (PMC_STATE_INVALID == (newState = pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_LOAD_FINISHED, NULL))) {
		return;
	}

	/* Do any actions required based on the state change */
	if (PMC_STATE_STATE(newState) == PMC_STATE_STATE_STORE) {
		/* Just moved into STORE, so store the reservation. */
		pmc_internal_reservation_store(reservation);
	}
	
}

static void pmc_internal_reservation_start_cpu(void * arg) {
	pmc_reservation_t reservation = (pmc_reservation_t)arg;
	
	assert(reservation);
	
	if (pmc_internal_reservation_matches_context(reservation)) {
		/* We are in context, but the reservation may have already had the context_in method run.  Attempt
		 * to set this cpu's bit in the active_last_context_in mask.  If we set it, call context_in.
		 */
		uint32_t oldMask = OSBitOrAtomic(1U << cpu_number(), &(reservation->active_last_context_in));
		
		if ((oldMask & (1U << cpu_number())) == 0) {
			COUNTER_DEBUG("Starting already in-context reservation %p for cpu %d\n", reservation, cpu_number());
			
			pmc_internal_reservation_context_in(reservation);
		}
	}
}

static void pmc_internal_reservation_stop_cpu(void * arg) {
	pmc_reservation_t reservation = (pmc_reservation_t)arg;
	
	assert(reservation);
	
	if (pmc_internal_reservation_matches_context(reservation)) {
		COUNTER_DEBUG("Stopping in-context reservation %p for cpu %d\n", reservation, cpu_number());

		pmc_internal_reservation_context_out(reservation);
	}
}	

/*!fn
 * pmc_reservation_interrupt is called when a PMC reservation which was setup
 * with an interrupt threshold counts the requested number of events. When the
 * underlying counter hits the threshold, an interrupt is generated, and this
 * method is called. This method marks the reservation as stopped, and passes
 * control off to the user-registered callback method, along with the
 * reservation (so that the user can, for example, write a 0 to the counter, and
 * restart the reservation).
 * This method assumes the reservation has a valid pmc_config_t within.
 *
 * @param target The pmc_reservation_t that caused the interrupt.
 * @param refCon User specified reference constant.
 */
static void pmc_reservation_interrupt(void *target, void *refCon) {
	pmc_reservation_t reservation = (pmc_reservation_t)target;
	pmc_state_t newState;
	uint64_t timeout;
	uint32_t spins;

	assert(reservation);

	/* Move the state machine */
	if (PMC_STATE_INVALID == pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_INTERRUPT, NULL)) {
		return;
	}

	/* A valid state move has been made, but won't be picked up until a context switch occurs.  To cause matching
	 * contexts that are currently running to update, we do an inter-processor message to run pmc_internal_reservation_stop_cpu
	 * on every cpu that can access the PMC.
	 */
	pmc_internal_reservation_broadcast(reservation, pmc_internal_reservation_stop_cpu);
			
	/* Spin waiting for the state to turn to INTERRUPT */
	nanoseconds_to_absolutetime(PMC_SPIN_TIMEOUT_US * 1000, &timeout);
	timeout += mach_absolute_time();
	spins = 0;
	while (PMC_STATE_STATE(reservation->state) != PMC_STATE_STATE_INTERRUPT) {
		/* Assert if this takes longer than PMC_SPIN_TIMEOUT_US */
		if (++spins > PMC_SPIN_THRESHOLD) {
			if (mach_absolute_time() > timeout) {
				pmc_spin_timeout_count++;
				assert(0);
			}
		}

		cpu_pause();
	}
			
	assert(reservation->config);
	assert(reservation->config->method);			
		
	/* Call the registered callback handler */
#if DEBUG_COUNTERS
	uint64_t start = mach_absolute_time();
#endif /* DEBUG */
	
	(void)reservation->config->method(reservation, refCon);
	
#if DEBUG_COUNTERS
	uint64_t end = mach_absolute_time();
	if((end - start) > 5000ULL) {
		kprintf("%s - user method %p took %llu ns\n", __FUNCTION__, 
				reservation->config->method, (end - start));
	}
#endif
	
	/* Move the state machine */
	if (PMC_STATE_INVALID == (newState = pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_END_OF_INTERRUPT, NULL))) {
		return;
	}
	
	/* Do any post-move actions necessary */
	if (PMC_STATE_STATE(newState) == PMC_STATE_STATE_CAN_RUN) {
		pmc_internal_reservation_broadcast(reservation, pmc_internal_reservation_start_cpu);
	} else if (PMC_STATE_STATE(newState) == PMC_STATE_STATE_DEALLOC && PMC_STATE_CONTEXT_COUNT(newState) == 0 && PMC_STATE_FLAGS(newState) == 0) {
		/* Wakeup any thread blocking for this reservation to hit <DEALLOC, 0, > */
		thread_wakeup((event_t)reservation);
	}
}	

/*
 * Apple-private KPI for Apple kext's (IOProfileFamily) only
 */

#if 0
#pragma mark -
#pragma mark IOProfileFamily private KPI
#endif

/*
 * perf_monitor_register registers a new Performance Monitor, and its associated
 * callback methods.  The given perf_monitor_object_t is the first argument to
 * each callback when they are called.
 */
kern_return_t perf_monitor_register(perf_monitor_object_t monitor,
	perf_monitor_methods_t *methods) {

	COUNTER_DEBUG("registering perf monitor %p\n", monitor);

	if(!monitor || !methods) {
		return KERN_INVALID_ARGUMENT;
	}

	/* Protect against out-of-date driver kexts */
	if(MACH_PERFMON_METHODS_VERSION != methods->perf_monitor_methods_version) {
		return KERN_INVALID_ARGUMENT;
	}

	/* All methods are required */
	if(!methods->supports_context_switching || !methods->enable_counters ||
		!methods->disable_counters) {
		return KERN_INVALID_ARGUMENT;
	}

	/* prevent dupes. */
	perf_monitor_t dupe = perf_monitor_find(monitor);
	if(dupe) {
		COUNTER_DEBUG("Duplicate registration for %p\n", monitor);
		perf_monitor_deallocate(dupe);
		return KERN_FAILURE;
	}

	perf_monitor_t pm = perf_monitor_alloc();
	if(!pm) {
		return KERN_RESOURCE_SHORTAGE;
	}

	/* initialize the object */
	perf_monitor_init(pm);

	/* copy in the registration info */
	pm->object = monitor;
	memcpy(&(pm->methods), methods, sizeof(perf_monitor_methods_t));

	/* place it in the tracking queue */
	perf_monitor_enqueue(pm);

	/* debug it */
	PRINT_PERF_MON(pm);

	return KERN_SUCCESS;
}

/*
 * perf_monitor_unregister unregisters a previously registered Perf Monitor,
 * looking it up by reference pointer (the same that was used in
 * perf_monitor_register()).
 */
kern_return_t perf_monitor_unregister(perf_monitor_object_t monitor) {
	kern_return_t ret = KERN_FAILURE;

	COUNTER_DEBUG("unregistering perf monitor %p\n", monitor);

	if(!monitor) {
		return KERN_INVALID_ARGUMENT;
	}

	perf_monitor_t pm = perf_monitor_find(monitor);
	if(pm) {
		/* Remove it from the queue. */
		perf_monitor_dequeue(pm);

		/* drop extra retain from find */
		perf_monitor_deallocate(pm);

		/* and release the object */
		perf_monitor_deallocate(pm);

		ret = KERN_SUCCESS;
	} else {
		COUNTER_DEBUG("could not find a registered pm that matches!\n");
	}

	return ret;
}

/*
 * pmc_register registers a new PMC for use with the pmc subsystem. Each PMC is
 * associated with a Perf Monitor.  Perf Monitors are looked up by the reference
 * pointer that was used to previously register them. 
 *
 * PMCs are registered with a reference pointer (@pmc_object), and a set of
 * callback methods.  When the given callback methods are called from xnu, the
 * first argument will always be the reference pointer used to register the PMC.
 *
 * NOTE: @monitor must have been successfully registered via
 * perf_monitor_register before this method will succeed.
 */
kern_return_t pmc_register(perf_monitor_object_t monitor, pmc_object_t pmc_object,
	pmc_methods_t *methods, void *object) {

	COUNTER_DEBUG("%p %p\n", monitor, pmc_object);

	if(!monitor || !pmc_object || !methods || !object) {
		return KERN_INVALID_ARGUMENT;
	}

	/* Prevent version mismatches */
	if(MACH_PMC_METHODS_VERSION != methods->pmc_methods_version) {
		COUNTER_DEBUG("version mismatch\n");
		return KERN_INVALID_ARGUMENT;
	}

	/* All methods are required. */
	if(!methods->create_config || 
		!methods->free_config ||
		!methods->config_set_value || 
		!methods->config_set_threshold || 
		!methods->config_set_handler ||
		!methods->set_config || 
		!methods->get_monitor || 
		!methods->get_name ||
		!methods->accessible_from_core || 
		!methods->accessible_cores ||
		!methods->get_count || 
		!methods->set_count ||
		!methods->disable ||
		!methods->enable ||
		!methods->open || 
		!methods->close) {
		return KERN_INVALID_ARGUMENT;
	}

	/* make sure this perf monitor object is already registered */
	/*
	 * NOTE: this adds a reference to the parent, so we'll have to drop it in
	 * any failure code paths from here on out.
	 */
	perf_monitor_t pm = perf_monitor_find(monitor);
	if(!pm) {
		COUNTER_DEBUG("Could not find perf monitor for %p\n", monitor);
		return KERN_INVALID_ARGUMENT;
	}

	/* make a new pmc */
	pmc_t pmc = pmc_alloc();
	if(!pmc) {
		/* drop the extra reference from perf_monitor_find() */
		perf_monitor_deallocate(pm);
		return KERN_RESOURCE_SHORTAGE;
	}

	/* init it */
	pmc_init(pmc);

	pmc->object = pmc_object;
	pmc->open_object = object;

	/* copy the callbacks in */
	memcpy(&(pmc->methods), methods, sizeof(pmc_methods_t));

	pmc->monitor = pm;

	perf_monitor_add_pmc(pmc->monitor, pmc);

	/* enqueue it in our tracking queue */
	pmc_enqueue(pmc);

	/* drop extra reference from perf_monitor_find() */
	perf_monitor_deallocate(pm);

	return KERN_SUCCESS;
}

/*
 * pmc_unregister unregisters a previously registered PMC, looking it up by
 * reference point to *both* the Perf Monitor it was created with, and the PMC's
 * reference pointer itself.
 */
kern_return_t pmc_unregister(perf_monitor_object_t monitor, pmc_object_t pmc_object) {
	COUNTER_DEBUG("%p %p\n", monitor, pmc_object);

	if(!monitor || !pmc_object) {
		return KERN_INVALID_ARGUMENT;
	}

	pmc_t pmc = pmc_find(pmc_object);
	if(!pmc) {
		COUNTER_DEBUG("Could not find a matching pmc.\n");
		return KERN_FAILURE;
	}

	/* remove it from the global queue */
	pmc_dequeue(pmc);

	perf_monitor_remove_pmc(pmc->monitor, pmc);

	/* remove extra reference count from pmc_find() */
	pmc_deallocate(pmc);

	/* dealloc the pmc */
	pmc_deallocate(pmc);

	return KERN_SUCCESS;
}

#if 0
#pragma mark -
#pragma mark KPI
#endif

/*
 * Begin in-kernel and in-kext KPI methods
 */

/*
 * pmc_create_config creates a new configuration area from a given @pmc.
 *
 * NOTE: This method is not interrupt safe.
 */
kern_return_t pmc_create_config(pmc_t pmc, pmc_config_t *config) {
	pmc_config_t tmp = NULL;

	if(!pmc || !config) {
		return KERN_INVALID_ARGUMENT;
	}

	pmc_reference(pmc);

	tmp = pmc_config_alloc(pmc);
	if(tmp) {
		tmp->object = pmc->methods.create_config(pmc->object);

		if(!tmp->object) {
			pmc_config_free(pmc, tmp);
			tmp = NULL;
		} else {
			tmp->interrupt_after_value = 0ULL;
			tmp->method = NULL;
			tmp->refCon = NULL;
		}
	}

	pmc_deallocate(pmc);

	if(!tmp) {
		return KERN_RESOURCE_SHORTAGE;
	}

	*config = tmp;

	return KERN_SUCCESS;
}

/*
 * pmc_free_config frees a configuration area created from a given @pmc
 *
 * NOTE: This method is not interrupt safe.
 */
void pmc_free_config(pmc_t pmc, pmc_config_t config) {
	assert(pmc);
	assert(config);

	pmc_reference(pmc);

	pmc_config_free(pmc, config);

	pmc_deallocate(pmc);
}

/*
 * pmc_config_set_value sets up configuration area key-value pairs.  These pairs
 * are to be either pre-known, or looked up via CoreProfile.framework.
 *
 * NOTE: This method is not interrupt safe.
 */
kern_return_t pmc_config_set_value(pmc_t pmc, pmc_config_t config,
	uint8_t id, uint64_t value) {

	kern_return_t ret = KERN_INVALID_ARGUMENT;
	
	if(!pmc || !config) {
		return ret;
	}

	pmc_reference(pmc);

	ret = pmc->methods.config_set_value(config->object, id, value);

	pmc_deallocate(pmc);

	return ret;
}

/*
 * pmc_config_set_interrupt_threshold modifies a config object, instructing
 * the pmc that it should generate a call to the given pmc_interrupt_method_t
 * after the counter counts @threshold events.
 *
 * PMC Threshold handler methods will have the pmc_reservation_t that generated the interrupt
 * as the first argument when the interrupt handler is invoked, and the given
 * @refCon (which may be NULL) as the second.
 *
 * See pmc_interrupt_method_t.
 *
 * NOTE: This method is not interrupt safe.
 */
kern_return_t pmc_config_set_interrupt_threshold(pmc_t pmc, pmc_config_t config, 
	uint64_t threshold, pmc_interrupt_method_t method, void *refCon) {
	kern_return_t ret = KERN_INVALID_ARGUMENT;

	if(!config || !pmc) {
		return ret;
	}
	
	assert(config);
	assert(pmc);

	pmc_reference(pmc);

	do {
		/*
		 * We have a minor annoyance to side-step here. The driver layer expects
		 * the config to never change once a reservation has been taken out with
		 * it.  However, in order to have the PMI method have the reservation as
		 * the first argument (in order to allow the user-method to, for
		 * example, write a 0 to it, and restart it), we need to create the
		 * pmc_reservation_t before setting it up in the config object.
		 * We overcome this by caching the method in the pmc_config_t stand-in,
		 * and mutating the pmc_config_object_t just before returning a
		 * reservation (in pmc_reserve() and friends, below).
		 */

		/* might as well stash this away too. */
		config->interrupt_after_value = threshold;
		config->method = method;
		config->refCon = refCon;

		ret = KERN_SUCCESS;

	}while(0);

	pmc_deallocate(pmc);

	return ret;
}

/*
 * pmc_get_pmc_list returns an allocated list of pmc_t's, as well as the number
 * of pmc_t's returned. Callers should free this list with a call to
 * pmc_free_pmc_list().
 *
 * NOTE: This method is not interrupt safe.
 */
kern_return_t pmc_get_pmc_list(pmc_t **pmcs, size_t *pmcCount) {
	pmc_t *array = NULL;
	pmc_t pmc = NULL;
	size_t count = 0UL;
	
	do {
		/* Copy down (to the stack) the count of perf counters */
		vm_size_t size = perf_counters_count;

		/* Allocate that sized chunk */
		array = (pmc_t *)kalloc(sizeof(pmc_t) * size);
		if(!array) {
			return KERN_RESOURCE_SHORTAGE;
		}

		/* Take the spin lock */
		lck_spin_lock(&perf_counters_queue_spin);

		/* verify the size didn't change while we were allocating */
		if(size != perf_counters_count) {
			/*
			 * queue size has changed between alloc and now - go back and
			 * make another pass.
			 */

			/* drop the lock */
			lck_spin_unlock(&perf_counters_queue_spin);

			/* free the block */
			kfree(array, sizeof(pmc_t) * size);
			array = NULL;
		}

		/* if we get here, and array is NULL, we try again. */
	}while(!array);

	/* copy the bits out */
	queue_iterate(perf_counters_queue, pmc, pmc_t, link) {
		if(pmc) {
			/* copy out the pointer */
			array[count++] = pmc;
		}
	}

	lck_spin_unlock(&perf_counters_queue_spin);

	/* return the list and the size */
	*pmcs = array;
	*pmcCount = count;

	return KERN_SUCCESS;
}

/*
 * pmc_free_pmc_list frees an array of pmc_t that has been returned from
 * pmc_get_pmc_list.
 * 
 * NOTE: This method is not interrupt safe.
 */
void pmc_free_pmc_list(pmc_t *pmcs, size_t pmcCount) {
	if(pmcs && pmcCount) {
		COUNTER_DEBUG("pmcs: %p pmcCount: %lu\n", pmcs, pmcCount);

		kfree(pmcs, pmcCount * sizeof(pmc_t));
	}
}

kern_return_t pmc_find_by_name(const char *name, pmc_t **pmcs, size_t *pmcCount) {
	kern_return_t ret = KERN_INVALID_ARGUMENT;

	if(!name || !pmcs || !pmcCount) {
		return ret;
	}

	pmc_t *list = NULL;
	size_t count = 0UL;

	if(KERN_SUCCESS == (ret = pmc_get_pmc_list(&list, &count))) {
		size_t matchCount = 0UL, ii = 0UL, swapPtr = 0UL;
		size_t len = strlen(name);

		for(ii = 0UL; ii < count; ii++) {
			const char *pmcName = pmc_get_name(list[ii]);

			if(strlen(pmcName) < len) {
				/*
				 * If the pmc name is shorter than the requested match, it's no 
				 * match, as we're looking for the most specific match(es).
				 */
				continue;
			}

			if(0 == strncmp(name, pmcName, len)) {
				pmc_t temp = list[ii];
				
				// move matches to the head of the array.
				list[ii] = list[swapPtr];
				list[swapPtr] = temp;
				swapPtr++;

				// keep a count of the matches
				matchCount++;
			}
		}

		if(matchCount) {
			/*
			 * If we have matches, they are all at the head of the array, so
			 * just allocate enough space for @matchCount pmc_t's, and copy the
			 * head of the array to the new allocation.  Then free the old
			 * allocation.
			 */

			pmc_t *result = (pmc_t *)kalloc(sizeof(pmc_t) * matchCount);
			if(result) {
				// copy the matches
				memcpy(result, list, sizeof(pmc_t) * matchCount);

				ret = KERN_SUCCESS;
			}

			pmc_free_pmc_list(list, count);

			if(!result) {
				*pmcs = NULL;
				*pmcCount = 0UL;
				return KERN_RESOURCE_SHORTAGE;
			}

			*pmcs = result;
			*pmcCount = matchCount;
		} else {
			*pmcs = NULL;
			*pmcCount = 0UL;
		}
	}

	return ret;
}

/*
 * pmc_get_name returns a pointer (not copied) to the human-readable name of the
 * given pmc.
 *
 * NOTE: Driver authors must take care to not allocate during this method, as
 * this method *IS* interrupt safe.
 */
const char *pmc_get_name(pmc_t pmc) {
	assert(pmc);

	const char *name = pmc->methods.get_name(pmc->object);

	return name;
}

/*
 * pmc_get_accessible_core_list returns a pointer to an array of logical core
 * numbers (as well as the size of that array) that represent the local cores
 * (hardware threads) from which the given @pmc can be accessed directly.
 *
 * NOTE: This method is interrupt safe.
 */
kern_return_t pmc_get_accessible_core_list(pmc_t pmc, uint32_t **logicalCores,
	size_t *logicalCoreCt) {

	kern_return_t ret = KERN_INVALID_ARGUMENT;

	if(!pmc || !logicalCores || !logicalCoreCt) {
		return ret;
	}

	ret = pmc->methods.accessible_cores(pmc->object, logicalCores, logicalCoreCt);

	return ret;
}

/*
 * pmc_accessible_from_core will return TRUE if the given @pmc is directly
 * (e.g., hardware) readable from the given logical core.
 *
 * NOTE: This method is interrupt safe.
 */
boolean_t pmc_accessible_from_core(pmc_t pmc, uint32_t logicalCore) {
	boolean_t ret = FALSE;

	assert(pmc);

	ret = pmc->methods.accessible_from_core(pmc->object, logicalCore);

	return ret;
}

static boolean_t pmc_reservation_setup_pmi(pmc_reservation_t resv, pmc_config_t config) {
	assert(resv);
	assert(resv->pmc);
	assert(config);
	assert(config->object);

	/* If there's no PMI to setup, return success */
	if(config->interrupt_after_value && config->method) {

		/* set the threshold */
		kern_return_t ret = resv->pmc->methods.config_set_threshold(config->object,
			config->interrupt_after_value);

		if(KERN_SUCCESS != ret) {
			/*
			 * This is the most useful error message here, as this only happens
			 * as a result of pmc_reserve*()
			 */
			COUNTER_DEBUG("Failed to set threshold for pmc %p\n", resv->pmc);
			return FALSE;
		}

		if(KERN_SUCCESS != resv->pmc->methods.config_set_handler(config->object, 
			(void *)resv, &pmc_reservation_interrupt, config->refCon)) {

			COUNTER_DEBUG("Failed to set handler for pmc %p\n", resv->pmc);
			return FALSE;
		}
	}

	return TRUE;
}

/*
 * pmc_reserve will attempt to reserve the given @pmc, with a given
 * configuration object, for counting system-wide. This method will fail with
 * KERN_FAILURE if the given pmc is already reserved at any scope.
 *
 * This method consumes the given configuration object if it returns
 * KERN_SUCCESS. Any other return value indicates the caller
 * must free the config object via pmc_free_config().
 *
 * NOTE: This method is NOT interrupt safe.
 */
kern_return_t pmc_reserve(pmc_t pmc, pmc_config_t config,
	pmc_reservation_t *reservation) {

	if(!pmc || !config || !reservation) {
		return KERN_INVALID_ARGUMENT;
	}

	pmc_reservation_t resv = reservation_alloc();
	if(!resv) {
		return KERN_RESOURCE_SHORTAGE;
	}

	reservation_init(resv);

	resv->flags |= PMC_FLAG_SCOPE_SYSTEM;
	resv->config = config;

	if(KERN_SUCCESS != pmc_internal_reservation_set_pmc(resv, pmc)) {
		resv->config = NULL;
		return KERN_FAILURE;
	}
	
	/* enqueue reservation in proper place */
	if(!pmc_internal_reservation_add(resv) || !pmc_reservation_setup_pmi(resv, config)) {
		/* Prevent free of config object */
		resv->config = NULL;
		
		reservation_free(resv);
		return KERN_FAILURE;
	}

	/* Here's where we setup the PMI method (if needed) */
	
	*reservation = resv;

	return KERN_SUCCESS;
}

/*
 * pmc_reserve_task will attempt to reserve the given @pmc with a given
 * configuration object, for counting when the given @task is running on any
 * logical core that can directly access the given @pmc.  This method will fail
 * with KERN_FAILURE if the given pmc is already reserved at either system or
 * thread scope.  
 *
 * This method consumes the given configuration object if it returns
 * KERN_SUCCESS. Any other return value indicates the caller
 * must free the config object via pmc_free_config().
 *
 * NOTE: You can reserve the same pmc for N different tasks concurrently.
 * NOTE: This method is NOT interrupt safe.
 */
kern_return_t pmc_reserve_task(pmc_t pmc, pmc_config_t config, 
	task_t task, pmc_reservation_t *reservation) {

	if(!pmc || !config || !reservation || !task) {
		return KERN_INVALID_ARGUMENT;
	}

	if(!pmc->monitor->methods.supports_context_switching(pmc->monitor->object)) {
		COUNTER_DEBUG("pmc %p cannot be context switched!\n", pmc);
		return KERN_INVALID_ARGUMENT;
	}

	pmc_reservation_t resv = reservation_alloc();
	if(!resv) {
		return KERN_RESOURCE_SHORTAGE;
	}

	reservation_init(resv);

	resv->flags |= PMC_FLAG_SCOPE_TASK;
	resv->task = task;

	resv->config = config;

	if(KERN_SUCCESS != pmc_internal_reservation_set_pmc(resv, pmc)) {
		resv->config = NULL;
		return KERN_FAILURE;
	}
	
	/* enqueue reservation in proper place */
	if(!pmc_internal_reservation_add(resv) || !pmc_reservation_setup_pmi(resv, config)) {
		/* Prevent free of config object */
		resv->config = NULL;

		reservation_free(resv);
		return KERN_FAILURE;
	}

	*reservation = resv;

	return KERN_SUCCESS;
}

/*
 * pmc_reserve_thread will attempt to reserve the given @pmc with a given
 * configuration object, for counting when the given @thread is running on any
 * logical core that can directly access the given @pmc.  This method will fail
 * with KERN_FAILURE if the given pmc is already reserved at either system or
 * task scope.  
 *
 * This method consumes the given configuration object if it returns
 * KERN_SUCCESS. Any other return value indicates the caller
 * must free the config object via pmc_free_config().
 *
 * NOTE: You can reserve the same pmc for N different threads concurrently.
 * NOTE: This method is NOT interrupt safe.
 */
kern_return_t pmc_reserve_thread(pmc_t pmc, pmc_config_t config, 
	thread_t thread, pmc_reservation_t *reservation) {
	if(!pmc || !config || !reservation || !thread) {
		return KERN_INVALID_ARGUMENT;
	}

	if(!pmc->monitor->methods.supports_context_switching(pmc->monitor->object)) {
		COUNTER_DEBUG("pmc %p cannot be context switched!\n", pmc);
		return KERN_INVALID_ARGUMENT;
	}

	pmc_reservation_t resv = reservation_alloc();
	if(!resv) {
		return KERN_RESOURCE_SHORTAGE;
	}

	reservation_init(resv);

	resv->flags |= PMC_FLAG_SCOPE_THREAD;
	resv->thread = thread;

	resv->config = config;

	if(KERN_SUCCESS != pmc_internal_reservation_set_pmc(resv, pmc)) {
		resv->config = NULL;
		return KERN_FAILURE;
	}
	
	/* enqueue reservation in proper place */
	if(!pmc_internal_reservation_add(resv) || !pmc_reservation_setup_pmi(resv, config)) {
		/* Prevent free of config object */
		resv->config = NULL;

		reservation_free(resv);
		return KERN_FAILURE;
	}

	*reservation = resv;

	return KERN_SUCCESS;
}

/*
 * pmc_reservation_start instructs the given reservation to start counting as
 * soon as possible. 
 *
 * NOTE: This method is interrupt safe.
 */
kern_return_t pmc_reservation_start(pmc_reservation_t reservation) {
	pmc_state_t newState;

	if(!reservation) {
		return KERN_INVALID_ARGUMENT;
	}

	/* Move the state machine */
	if (PMC_STATE_INVALID == (newState = pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_START, NULL))) {
		return KERN_FAILURE;
	}
	
	/* If we are currently in an interrupt, don't bother to broadcast since it won't do anything now and the interrupt will
	 * broadcast right before it leaves
	 */
	if (PMC_STATE_STATE(newState) != PMC_STATE_STATE_INTERRUPT) {	
		/* A valid state move has been made, but won't be picked up until a context switch occurs.  To cause matching
		 * contexts that are currently running to update, we do an inter-processor message to run pmc_internal_reservation_start_cpu
		 * on every cpu that can access the PMC.
		 */
		pmc_internal_reservation_broadcast(reservation, pmc_internal_reservation_start_cpu);
	}
	
	return KERN_SUCCESS;			 
}

/*
 * pmc_reservation_stop instructs the given reservation to stop counting as
 * soon as possible.  When this method returns, the pmc will be marked as stopping
 * and subsequent calls to pmc_reservation_start will succeed.  This does not mean
 * that the pmc hardware has _actually_ stopped running.  Assuming no other changes
 * to the reservation state, the pmc hardware _will_ stop shortly.
 *
 */
kern_return_t pmc_reservation_stop(pmc_reservation_t reservation) {
	pmc_state_t newState;

	if(!reservation) {
		return KERN_INVALID_ARGUMENT;
	}
	
	/* Move the state machine */
	if (PMC_STATE_INVALID == (newState = pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_STOP, NULL))) {
		return KERN_FAILURE;
	}
	
	/* If we are currently in an interrupt, don't bother to broadcast since it won't do anything now and the interrupt will
	 * broadcast right before it leaves.  Similarly, if we just moved directly to STOP, don't bother broadcasting.
	 */
	if (PMC_STATE_STATE(newState) != PMC_STATE_STATE_INTERRUPT && PMC_STATE_STATE(newState) != PMC_STATE_STATE_STOP) {	
		/* A valid state move has been made, but won't be picked up until a context switch occurs.  To cause matching
			 * contexts that are currently running to update, we do an inter-processor message to run pmc_internal_reservation_stop_cpu
		 * on every cpu that can access the PMC.
		 */
		
		pmc_internal_reservation_broadcast(reservation, pmc_internal_reservation_stop_cpu);
	}
	
	return KERN_SUCCESS;
}

/*
 * pmc_reservation_read will read the event count associated with a reservation.
 * If the caller is current executing in a context that both a) matches the
 * reservation's context, and b) can access the reservation's pmc directly, the
 * value will be read from hardware.  Otherwise, this returns the reservation's
 * stored value.
 *
 * NOTE: This method is interrupt safe.
 * NOTE: When not on the interrupt stack, this method may block.
 */
kern_return_t pmc_reservation_read(pmc_reservation_t reservation, uint64_t *value) {
	kern_return_t ret = KERN_FAILURE;
	uint64_t timeout;
	uint32_t spins;

	if(!reservation || !value) {
		return KERN_INVALID_ARGUMENT;
	}

	nanoseconds_to_absolutetime(PMC_SPIN_TIMEOUT_US * 1000, &timeout);
	timeout += mach_absolute_time();
	spins = 0;
	do {
		uint32_t state = reservation->state;
		
		if((PMC_STATE_STATE(state) == PMC_STATE_STATE_RUN)) {
			/* Attempt read from hardware via drivers. */

			assert(reservation->pmc);

			ret = reservation->pmc->methods.get_count(reservation->pmc->object, value);
			
			break;
		} else if ((PMC_STATE_STATE(state) == PMC_STATE_STATE_STORE) ||
				   (PMC_STATE_STATE(state) == PMC_STATE_STATE_LOAD)) {
			/* Spin */
			/* Assert if this takes longer than PMC_SPIN_TIMEOUT_US */
			if (++spins > PMC_SPIN_THRESHOLD) {
				if (mach_absolute_time() > timeout) {
					pmc_spin_timeout_count++;
					assert(0);
				}
			}

			cpu_pause();
		} else {
			break;
		}
	} while (1);

	/* If the direct hardware read failed (for whatever reason) */
	if(KERN_SUCCESS != ret) {
		/* Read stored value */
		*value = reservation->value;
	}

	return KERN_SUCCESS;
}

/*
 * pmc_reservation_write will write the event count associated with a reservation.
 * If the caller is current executing in a context that both a) matches the
 * reservation's context, and b) can access the reservation's pmc directly, the
 * value will be written to hardware.  Otherwise, this writes the reservation's
 * stored value.
 *
 * NOTE: This method is interrupt safe.
 * NOTE: When not on the interrupt stack, this method may block.
 */
kern_return_t pmc_reservation_write(pmc_reservation_t reservation, uint64_t value) {
	kern_return_t ret = KERN_FAILURE;
	uint64_t timeout;
	uint32_t spins;

	if(!reservation) {
		return KERN_INVALID_ARGUMENT;
	}

	nanoseconds_to_absolutetime(PMC_SPIN_TIMEOUT_US * 1000, &timeout);
	timeout += mach_absolute_time();
	spins = 0;
	do {
		uint32_t state = reservation->state;
		
		if((PMC_STATE_STATE(state) == PMC_STATE_STATE_RUN)) {
				/* Write to hardware via drivers. */
			assert(reservation->pmc);

			ret = reservation->pmc->methods.set_count(reservation->pmc->object, value);
			break;
		} else if ((PMC_STATE_STATE(state) == PMC_STATE_STATE_STORE) ||
				   (PMC_STATE_STATE(state) == PMC_STATE_STATE_LOAD)) {
			/* Spin */
			/* Assert if this takes longer than PMC_SPIN_TIMEOUT_US */
			if (++spins > PMC_SPIN_THRESHOLD) {
				if (mach_absolute_time() > timeout) {
					pmc_spin_timeout_count++;
					assert(0);
				}
			}

			cpu_pause();
		} else {
			break;
		}
	} while (1);
	
	if(KERN_SUCCESS != ret) {
		/* Write stored value */
		reservation->value = value;
	}

	return KERN_SUCCESS;
}

/* 
 * pmc_reservation_free releases a reservation and all associated resources.
 *
 * NOTE: This method is NOT interrupt safe.
 */
kern_return_t pmc_reservation_free(pmc_reservation_t reservation) {
	pmc_state_t newState;
	
	if(!reservation) {
		return KERN_INVALID_ARGUMENT;
	}
	
	/* Move the state machine */
	if (PMC_STATE_INVALID == (newState = pmc_internal_reservation_move_for_event(reservation, PMC_STATE_EVENT_FREE, NULL))) {
		return KERN_FAILURE;
	}

	/* If we didn't move directly to DEALLOC, help things along */	
	if (PMC_STATE_STATE(newState) != PMC_STATE_STATE_DEALLOC) {	
		/* A valid state move has been made, but won't be picked up until a context switch occurs.  To cause matching
		 * contexts that are currently running to update, we do an inter-processor message to run pmc_internal_reservation_stop_cpu
		 * on every cpu that can access the PMC.
		 */
		pmc_internal_reservation_broadcast(reservation, pmc_internal_reservation_stop_cpu);
	}

	/* Block until the reservation hits the <DEALLOC, 0, > state */
	while (!(PMC_STATE_STATE(reservation->state) == PMC_STATE_STATE_DEALLOC && PMC_STATE_CONTEXT_COUNT(reservation->state) == 0 && PMC_STATE_FLAGS(reservation->state) == 0)) {
		assert_wait((event_t)reservation, THREAD_UNINT);
		thread_block(THREAD_CONTINUE_NULL);
	}

	/* remove from queues */
	pmc_internal_reservation_remove(reservation);
		
	/* free reservation */
	reservation_free(reservation);

	return KERN_SUCCESS;
}

/*
 * pmc_context_switch performs all context switching necessary to save all pmc
 * state associated with @oldThread (and the task to which @oldThread belongs),
 * as well as to restore all pmc state associated with @newThread (and the task
 * to which @newThread belongs).
 *
 * NOTE: This method IS interrupt safe.
 */
boolean_t pmc_context_switch(thread_t oldThread, thread_t newThread) {
	pmc_reservation_t resv = NULL;
	uint32_t cpuNum = cpu_number();

	/* Out going thread: save pmc state */
	lck_spin_lock(&reservations_spin);

	/* interate over any reservations */
	queue_iterate(thread_reservations, resv, pmc_reservation_t, link) {
		if(resv && oldThread == resv->thread) {

			/* check if we can read the associated pmc from this core. */
			if(pmc_accessible_from_core(resv->pmc, cpuNum)) {
				/* save the state At this point, if it fails, it fails. */
				(void)pmc_internal_reservation_context_out(resv);
			}
		}
	}
	
	queue_iterate(task_reservations, resv, pmc_reservation_t, link) {
		if(resv && resv->task == oldThread->task) {
			if(pmc_accessible_from_core(resv->pmc, cpuNum)) {
				(void)pmc_internal_reservation_context_out(resv);
			}
		}
	}
	
	/* Incoming task: restore */

	queue_iterate(thread_reservations, resv, pmc_reservation_t, link) {
		if(resv && resv->thread == newThread) {
			if(pmc_accessible_from_core(resv->pmc, cpuNum)) {
				(void)pmc_internal_reservation_context_in(resv);
			}
		}
	}
	

	queue_iterate(task_reservations, resv, pmc_reservation_t, link) {
		if(resv && resv->task == newThread->task) {
			if(pmc_accessible_from_core(resv->pmc, cpuNum)) {
				(void)pmc_internal_reservation_context_in(resv);
			}
		}
	}
	
	lck_spin_unlock(&reservations_spin);

	return TRUE;
}

#else /* !CONFIG_COUNTERS */

#if 0
#pragma mark -
#pragma mark Dummy functions
#endif

/*
 * In the case that someone has chosen not to include the PMC KPI in some
 * configuration, we still have exports for kexts, so we'll need to define stub
 * methods that return failures.
 */
kern_return_t perf_monitor_register(perf_monitor_object_t monitor __unused,
	perf_monitor_methods_t *methods __unused) {
	return KERN_FAILURE;
}

kern_return_t perf_monitor_unregister(perf_monitor_object_t monitor __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_register(perf_monitor_object_t monitor __unused, 
	pmc_object_t pmc __unused, pmc_methods_t *methods __unused, void *object __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_unregister(perf_monitor_object_t monitor __unused,
	pmc_object_t pmc __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_create_config(pmc_t pmc __unused, 
	pmc_config_t *config __unused) {
	return KERN_FAILURE;
}

void pmc_free_config(pmc_t pmc __unused, pmc_config_t config __unused) {
}

kern_return_t pmc_config_set_value(pmc_t pmc __unused, 
	pmc_config_t config __unused, uint8_t id __unused, 
	uint64_t value __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_config_set_interrupt_threshold(pmc_t pmc __unused, 
	pmc_config_t config __unused, uint64_t threshold __unused, 
	pmc_interrupt_method_t method __unused, void *refCon __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_get_pmc_list(pmc_t **pmcs __unused, size_t *pmcCount __unused) {
	return KERN_FAILURE;
}

void pmc_free_pmc_list(pmc_t *pmcs __unused, size_t pmcCount __unused) {
}

kern_return_t pmc_find_by_name(const char *name __unused, pmc_t **pmcs __unused, 
	size_t *pmcCount __unused) {
	return KERN_FAILURE;
}

const char *pmc_get_name(pmc_t pmc __unused) {
	return "";
}

kern_return_t pmc_get_accessible_core_list(pmc_t pmc __unused, 
	uint32_t **logicalCores __unused, size_t *logicalCoreCt __unused) {
	return KERN_FAILURE;
}

boolean_t pmc_accessible_from_core(pmc_t pmc __unused, 
	uint32_t logicalCore __unused) {
	return FALSE;
}

kern_return_t pmc_reserve(pmc_t pmc __unused, 
	pmc_config_t config __unused, pmc_reservation_t *reservation __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_reserve_task(pmc_t pmc __unused, 
	pmc_config_t config __unused, task_t task __unused, 
	pmc_reservation_t *reservation __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_reserve_thread(pmc_t pmc __unused, 
	pmc_config_t config __unused, thread_t thread __unused, 
	pmc_reservation_t *reservation __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_reservation_start(pmc_reservation_t reservation __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_reservation_stop(pmc_reservation_t reservation __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_reservation_read(pmc_reservation_t reservation __unused, 
	uint64_t *value __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_reservation_write(pmc_reservation_t reservation __unused, 
	uint64_t value __unused) {
	return KERN_FAILURE;
}

kern_return_t pmc_reservation_free(pmc_reservation_t reservation __unused) {
	return KERN_FAILURE;
}


#endif /* !CONFIG_COUNTERS */
