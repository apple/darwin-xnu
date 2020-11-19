/*
 * Copyright (c) 2016-2020 Apple Inc. All rights reserved.
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
#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/zalloc.h>
#include <kern/task.h>
#include <kern/machine.h>
#include <kern/coalition.h>
#include <sys/errno.h>
#include <kern/queue.h>
#include <kern/locks.h>
#include <kern/thread_group.h>
#include <kern/sched_clutch.h>

#if CONFIG_THREAD_GROUPS

#define CACHELINE_SIZE (1 << MMU_CLINE)

struct thread_group {
	uint64_t                tg_id;
	char                    tg_name[THREAD_GROUP_MAXNAME];
	struct os_refcnt        tg_refcount;
	uint32_t                tg_flags;
	cluster_type_t          tg_recommendation;
	queue_chain_t           tg_queue_chain;
#if CONFIG_SCHED_CLUTCH
	struct sched_clutch     tg_sched_clutch;
#endif /* CONFIG_SCHED_CLUTCH */
	// 16 bytes of padding here
	uint8_t                 tg_machine_data[] __attribute__((aligned(CACHELINE_SIZE)));
} __attribute__((aligned(8)));

static SECURITY_READ_ONLY_LATE(zone_t) tg_zone;
static uint32_t tg_count;
static queue_head_t tg_queue;
static LCK_GRP_DECLARE(tg_lck_grp, "thread_group");
static LCK_MTX_DECLARE(tg_lock, &tg_lck_grp);
static LCK_SPIN_DECLARE(tg_flags_update_lock, &tg_lck_grp);

static uint64_t tg_next_id = 0;
static uint32_t tg_size;
static uint32_t tg_machine_data_size;
static struct thread_group *tg_system;
static struct thread_group *tg_background;
static struct thread_group *tg_adaptive;
static struct thread_group *tg_vm;
static struct thread_group *tg_io_storage;
static struct thread_group *tg_perf_controller;
int tg_set_by_bankvoucher;

static bool thread_group_retain_try(struct thread_group *tg);

/*
 * Initialize thread groups at boot
 */
void
thread_group_init(void)
{
	// Get thread group structure extension from EDT or boot-args (which can override EDT)
	if (!PE_parse_boot_argn("kern.thread_group_extra_bytes", &tg_machine_data_size, sizeof(tg_machine_data_size))) {
		if (!PE_get_default("kern.thread_group_extra_bytes", &tg_machine_data_size, sizeof(tg_machine_data_size))) {
			tg_machine_data_size = 8;
		}
	}

	// Check if thread group can be set by voucher adoption from EDT or boot-args (which can override EDT)
	if (!PE_parse_boot_argn("kern.thread_group_set_by_bankvoucher", &tg_set_by_bankvoucher, sizeof(tg_set_by_bankvoucher))) {
		if (!PE_get_default("kern.thread_group_set_by_bankvoucher", &tg_set_by_bankvoucher, sizeof(tg_set_by_bankvoucher))) {
			tg_set_by_bankvoucher = 1;
		}
	}

	tg_size = sizeof(struct thread_group) + tg_machine_data_size;
	if (tg_size % CACHELINE_SIZE) {
		tg_size += CACHELINE_SIZE - (tg_size % CACHELINE_SIZE);
	}
	tg_machine_data_size = tg_size - sizeof(struct thread_group);
	// printf("tg_size=%d(%lu+%d)\n", tg_size, sizeof(struct thread_group), tg_machine_data_size);
	assert(offsetof(struct thread_group, tg_machine_data) % CACHELINE_SIZE == 0);
	tg_zone = zone_create("thread_groups", tg_size, ZC_NOENCRYPT | ZC_ALIGNMENT_REQUIRED);

	queue_head_init(tg_queue);
	tg_system = thread_group_create_and_retain();
	thread_group_set_name(tg_system, "system");
	tg_background = thread_group_create_and_retain();
	thread_group_set_name(tg_background, "background");
	tg_adaptive = thread_group_create_and_retain();
	thread_group_set_name(tg_adaptive, "adaptive");
	tg_vm = thread_group_create_and_retain();
	thread_group_set_name(tg_vm, "VM");
	tg_io_storage = thread_group_create_and_retain();
	thread_group_set_name(tg_io_storage, "io storage");
	tg_perf_controller = thread_group_create_and_retain();
	thread_group_set_name(tg_perf_controller, "perf_controller");

	/*
	 * If CLPC is disabled, it would recommend SMP for all thread groups.
	 * In that mode, the scheduler would like to restrict the kernel thread
	 * groups to the E-cluster while all other thread groups are run on the
	 * P-cluster. To identify the kernel thread groups, mark them with a
	 * special flag THREAD_GROUP_FLAGS_SMP_RESTRICT which is looked at by
	 * recommended_pset_type().
	 */
	tg_system->tg_flags |= THREAD_GROUP_FLAGS_SMP_RESTRICT;
	tg_vm->tg_flags |= THREAD_GROUP_FLAGS_SMP_RESTRICT;
	tg_io_storage->tg_flags |= THREAD_GROUP_FLAGS_SMP_RESTRICT;
	tg_perf_controller->tg_flags |= THREAD_GROUP_FLAGS_SMP_RESTRICT;
}

#if CONFIG_SCHED_CLUTCH
/*
 * sched_clutch_for_thread
 *
 * The routine provides a back linkage from the thread to the
 * sched_clutch it belongs to. This relationship is based on the
 * thread group membership of the thread. Since that membership is
 * changed from the thread context with the thread lock held, this
 * linkage should be looked at only with the thread lock held or
 * when the thread cannot be running (for eg. the thread is in the
 * runq and being removed as part of thread_select().
 */
sched_clutch_t
sched_clutch_for_thread(thread_t thread)
{
	assert(thread->thread_group != NULL);
	return &(thread->thread_group->tg_sched_clutch);
}

sched_clutch_t
sched_clutch_for_thread_group(struct thread_group *thread_group)
{
	return &(thread_group->tg_sched_clutch);
}

/*
 * Translate the TG flags to a priority boost for the sched_clutch.
 * This priority boost will apply to the entire clutch represented
 * by the thread group.
 */
static void
sched_clutch_update_tg_flags(sched_clutch_t clutch, uint8_t flags)
{
	sched_clutch_tg_priority_t sc_tg_pri = 0;
	if (flags & THREAD_GROUP_FLAGS_UI_APP) {
		sc_tg_pri = SCHED_CLUTCH_TG_PRI_HIGH;
	} else if (flags & THREAD_GROUP_FLAGS_EFFICIENT) {
		sc_tg_pri = SCHED_CLUTCH_TG_PRI_LOW;
	} else {
		sc_tg_pri = SCHED_CLUTCH_TG_PRI_MED;
	}
	os_atomic_store(&clutch->sc_tg_priority, sc_tg_pri, relaxed);
}

#endif /* CONFIG_SCHED_CLUTCH */

/*
 * Use a spinlock to protect all thread group flag updates.
 * The lock should not have heavy contention since these flag updates should
 * be infrequent. If this lock has contention issues, it should be changed to
 * a per thread-group lock.
 *
 * The lock protects the flags field in the thread_group structure. It is also
 * held while doing callouts to CLPC to reflect these flag changes.
 */

void
thread_group_flags_update_lock(void)
{
	lck_spin_lock_grp(&tg_flags_update_lock, &tg_lck_grp);
}

void
thread_group_flags_update_unlock(void)
{
	lck_spin_unlock(&tg_flags_update_lock);
}

/*
 * Inform platform code about already existing thread groups
 * or ask it to free state for all thread groups
 */
void
thread_group_resync(boolean_t create)
{
	struct thread_group *tg;

	lck_mtx_lock(&tg_lock);
	qe_foreach_element(tg, &tg_queue, tg_queue_chain) {
		if (create) {
			machine_thread_group_init(tg);
		} else {
			machine_thread_group_deinit(tg);
		}
	}
	lck_mtx_unlock(&tg_lock);
}

/*
 * Create new thread group and add new reference to it.
 */
struct thread_group *
thread_group_create_and_retain(void)
{
	struct thread_group *tg;

	tg = (struct thread_group *)zalloc(tg_zone);
	if (tg == NULL) {
		panic("thread group zone over commit");
	}
	assert((uintptr_t)tg % CACHELINE_SIZE == 0);
	bzero(tg, sizeof(struct thread_group));

#if CONFIG_SCHED_CLUTCH
	/*
	 * The clutch scheduler maintains a bunch of runqs per thread group. For
	 * each thread group it maintains a sched_clutch structure. The lifetime
	 * of that structure is tied directly to the lifetime of the thread group.
	 */
	sched_clutch_init_with_thread_group(&(tg->tg_sched_clutch), tg);

	/*
	 * Since the thread group flags are used to determine any priority promotions
	 * for the threads in the thread group, initialize them to 0.
	 */
	sched_clutch_update_tg_flags(&(tg->tg_sched_clutch), 0);

#endif /* CONFIG_SCHED_CLUTCH */

	lck_mtx_lock(&tg_lock);
	tg->tg_id = tg_next_id++;
	tg->tg_recommendation = CLUSTER_TYPE_SMP; // no recommendation yet
	os_ref_init(&tg->tg_refcount, NULL);
	tg_count++;
	enqueue_tail(&tg_queue, &tg->tg_queue_chain);
	lck_mtx_unlock(&tg_lock);

	// call machine layer init before this thread group becomes visible
	machine_thread_group_init(tg);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NEW), tg->tg_id);

	return tg;
}

/*
 * Point newly created thread to its home thread group
 */
void
thread_group_init_thread(thread_t t, task_t task)
{
	struct thread_group *tg = task_coalition_get_thread_group(task);
	t->thread_group = tg;
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_SET),
	    THREAD_GROUP_INVALID, tg->tg_id, (uintptr_t)thread_tid(t));
}

/*
 * Set thread group name
 */
void
thread_group_set_name(__unused struct thread_group *tg, __unused const char *name)
{
	if (name == NULL) {
		return;
	}
	if (!thread_group_retain_try(tg)) {
		return;
	}
	if (tg->tg_name[0] == '\0') {
		strncpy(&tg->tg_name[0], name, THREAD_GROUP_MAXNAME);
#if defined(__LP64__)
		KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NAME),
		    tg->tg_id,
		    *(uint64_t*)(void*)&tg->tg_name[0],
		    *(uint64_t*)(void*)&tg->tg_name[sizeof(uint64_t)]
		    );
#else /* defined(__LP64__) */
		KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NAME),
		    tg->tg_id,
		    *(uint32_t*)(void*)&tg->tg_name[0],
		    *(uint32_t*)(void*)&tg->tg_name[sizeof(uint32_t)]
		    );
#endif /* defined(__LP64__) */
	}
	thread_group_release(tg);
}

void
thread_group_set_flags(struct thread_group *tg, uint64_t flags)
{
	thread_group_flags_update_lock();
	thread_group_set_flags_locked(tg, flags);
	thread_group_flags_update_unlock();
}

void
thread_group_clear_flags(struct thread_group *tg, uint64_t flags)
{
	thread_group_flags_update_lock();
	thread_group_clear_flags_locked(tg, flags);
	thread_group_flags_update_unlock();
}

/*
 * Set thread group flags and perform related actions.
 * The tg_flags_update_lock should be held.
 * Currently supported flags are:
 * - THREAD_GROUP_FLAGS_EFFICIENT
 * - THREAD_GROUP_FLAGS_UI_APP
 */

void
thread_group_set_flags_locked(struct thread_group *tg, uint64_t flags)
{
	if ((flags & THREAD_GROUP_FLAGS_VALID) != flags) {
		panic("thread_group_set_flags: Invalid flags %llu", flags);
	}

	if ((tg->tg_flags & flags) == flags) {
		return;
	}

	__kdebug_only uint64_t old_flags = tg->tg_flags;
	tg->tg_flags |= flags;
	machine_thread_group_flags_update(tg, tg->tg_flags);
#if CONFIG_SCHED_CLUTCH
	sched_clutch_update_tg_flags(&(tg->tg_sched_clutch), tg->tg_flags);
#endif /* CONFIG_SCHED_CLUTCH */
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FLAGS),
	    tg->tg_id, tg->tg_flags, old_flags);
}

/*
 * Clear thread group flags and perform related actions
 * The tg_flags_update_lock should be held.
 * Currently supported flags are:
 * - THREAD_GROUP_FLAGS_EFFICIENT
 * - THREAD_GROUP_FLAGS_UI_APP
 */

void
thread_group_clear_flags_locked(struct thread_group *tg, uint64_t flags)
{
	if ((flags & THREAD_GROUP_FLAGS_VALID) != flags) {
		panic("thread_group_clear_flags: Invalid flags %llu", flags);
	}

	if ((tg->tg_flags & flags) == 0) {
		return;
	}

	__kdebug_only uint64_t old_flags = tg->tg_flags;
	tg->tg_flags &= ~flags;
#if CONFIG_SCHED_CLUTCH
	sched_clutch_update_tg_flags(&(tg->tg_sched_clutch), tg->tg_flags);
#endif /* CONFIG_SCHED_CLUTCH */
	machine_thread_group_flags_update(tg, tg->tg_flags);
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FLAGS),
	    tg->tg_id, tg->tg_flags, old_flags);
}



/*
 * Find thread group with specified name and put new reference to it.
 */
struct thread_group *
thread_group_find_by_name_and_retain(char *name)
{
	struct thread_group *result = NULL;

	if (name == NULL) {
		return NULL;
	}

	if (strncmp("system", name, THREAD_GROUP_MAXNAME) == 0) {
		return thread_group_retain(tg_system);
	} else if (strncmp("background", name, THREAD_GROUP_MAXNAME) == 0) {
		return thread_group_retain(tg_background);
	} else if (strncmp("adaptive", name, THREAD_GROUP_MAXNAME) == 0) {
		return thread_group_retain(tg_adaptive);
	} else if (strncmp("perf_controller", name, THREAD_GROUP_MAXNAME) == 0) {
		return thread_group_retain(tg_perf_controller);
	}

	struct thread_group *tg;
	lck_mtx_lock(&tg_lock);
	qe_foreach_element(tg, &tg_queue, tg_queue_chain) {
		if (strncmp(tg->tg_name, name, THREAD_GROUP_MAXNAME) == 0 &&
		    thread_group_retain_try(tg)) {
			result = tg;
			break;
		}
	}
	lck_mtx_unlock(&tg_lock);
	return result;
}

/*
 * Find thread group with specified ID and add new reference to it.
 */
struct thread_group *
thread_group_find_by_id_and_retain(uint64_t id)
{
	struct thread_group *tg = NULL;
	struct thread_group *result = NULL;

	switch (id) {
	case THREAD_GROUP_SYSTEM:
		result = tg_system;
		thread_group_retain(tg_system);
		break;
	case THREAD_GROUP_BACKGROUND:
		result = tg_background;
		thread_group_retain(tg_background);
		break;
	case THREAD_GROUP_ADAPTIVE:
		result = tg_adaptive;
		thread_group_retain(tg_adaptive);
		break;
	case THREAD_GROUP_VM:
		result = tg_vm;
		thread_group_retain(tg_vm);
		break;
	case THREAD_GROUP_IO_STORAGE:
		result = tg_io_storage;
		thread_group_retain(tg_io_storage);
		break;
	case THREAD_GROUP_PERF_CONTROLLER:
		result = tg_perf_controller;
		thread_group_retain(tg_perf_controller);
		break;
	default:
		lck_mtx_lock(&tg_lock);
		qe_foreach_element(tg, &tg_queue, tg_queue_chain) {
			if (tg->tg_id == id && thread_group_retain_try(tg)) {
				result = tg;
				break;
			}
		}
		lck_mtx_unlock(&tg_lock);
	}
	return result;
}

/*
 * Add new reference to specified thread group
 */
struct thread_group *
thread_group_retain(struct thread_group *tg)
{
	os_ref_retain(&tg->tg_refcount);
	return tg;
}

/*
 * Similar to thread_group_retain, but fails for thread groups with a
 * zero reference count. Returns true if retained successfully.
 */
static bool
thread_group_retain_try(struct thread_group *tg)
{
	return os_ref_retain_try(&tg->tg_refcount);
}

/*
 * Drop a reference to specified thread group
 */
void
thread_group_release(struct thread_group *tg)
{
	if (os_ref_release(&tg->tg_refcount) == 0) {
		lck_mtx_lock(&tg_lock);
		tg_count--;
		remqueue(&tg->tg_queue_chain);
		lck_mtx_unlock(&tg_lock);
		static_assert(THREAD_GROUP_MAXNAME >= (sizeof(uint64_t) * 2), "thread group name is too short");
		static_assert(__alignof(struct thread_group) >= __alignof(uint64_t), "thread group name is not 8 bytes aligned");
#if defined(__LP64__)
		KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NAME_FREE),
		    tg->tg_id,
		    *(uint64_t*)(void*)&tg->tg_name[0],
		    *(uint64_t*)(void*)&tg->tg_name[sizeof(uint64_t)]
		    );
#else /* defined(__LP64__) */
		KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NAME_FREE),
		    tg->tg_id,
		    *(uint32_t*)(void*)&tg->tg_name[0],
		    *(uint32_t*)(void*)&tg->tg_name[sizeof(uint32_t)]
		    );
#endif /* defined(__LP64__) */
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FREE), tg->tg_id);
#if CONFIG_SCHED_CLUTCH
		sched_clutch_destroy(&(tg->tg_sched_clutch));
#endif /* CONFIG_SCHED_CLUTCH */
		machine_thread_group_deinit(tg);
		zfree(tg_zone, tg);
	}
}

/*
 * Get thread's current thread group
 */
inline struct thread_group *
thread_group_get(thread_t t)
{
	return t->thread_group;
}

struct thread_group *
thread_group_get_home_group(thread_t t)
{
	return task_coalition_get_thread_group(t->task);
}

#if CONFIG_SCHED_AUTO_JOIN

/*
 * thread_set_thread_group_auto_join()
 *
 * Sets the thread group of a thread based on auto-join rules.
 *
 * Preconditions:
 * - Thread must not be part of a runq (freshly made runnable threads or terminating only)
 * - Thread must be locked by the caller already
 */
static void
thread_set_thread_group_auto_join(thread_t t, struct thread_group *tg, __unused struct thread_group *old_tg)
{
	assert(t->runq == PROCESSOR_NULL);
	t->thread_group = tg;

	/*
	 * If the thread group is being changed for the current thread, callout to
	 * CLPC to update the thread's information at that layer. This makes sure CLPC
	 * has consistent state when the current thread is going off-core.
	 */
	if (t == current_thread()) {
		uint64_t ctime = mach_approximate_time();
		uint64_t arg1, arg2;
		machine_thread_going_on_core(t, thread_get_urgency(t, &arg1, &arg2), 0, 0, ctime);
		machine_switch_perfcontrol_state_update(THREAD_GROUP_UPDATE, ctime, PERFCONTROL_CALLOUT_WAKE_UNSAFE, t);
	}
}

#endif /* CONFIG_SCHED_AUTO_JOIN */

/*
 * thread_set_thread_group_explicit()
 *
 * Sets the thread group of a thread based on default non auto-join rules.
 *
 * Preconditions:
 * - Thread must be the current thread
 * - Caller must not have the thread locked
 * - Interrupts must be disabled
 */
static void
thread_set_thread_group_explicit(thread_t t, struct thread_group *tg, __unused struct thread_group *old_tg)
{
	assert(t == current_thread());
	/*
	 * In the clutch scheduler world, the runq membership of the thread
	 * is based on its thread group membership and its scheduling bucket.
	 * In order to synchronize with the priority (and therefore bucket)
	 * getting updated concurrently, it is important to perform the
	 * thread group change also under the thread lock.
	 */
	thread_lock(t);
	t->thread_group = tg;

#if CONFIG_SCHED_CLUTCH
	sched_clutch_t old_clutch = (old_tg) ? &(old_tg->tg_sched_clutch) : NULL;
	sched_clutch_t new_clutch = (tg) ? &(tg->tg_sched_clutch) : NULL;
	if (SCHED_CLUTCH_THREAD_ELIGIBLE(t)) {
		sched_clutch_thread_clutch_update(t, old_clutch, new_clutch);
	}
#endif /* CONFIG_SCHED_CLUTCH */

	thread_unlock(t);

	uint64_t ctime = mach_approximate_time();
	uint64_t arg1, arg2;
	machine_thread_going_on_core(t, thread_get_urgency(t, &arg1, &arg2), 0, 0, ctime);
	machine_switch_perfcontrol_state_update(THREAD_GROUP_UPDATE, ctime, 0, t);
}

/*
 * thread_set_thread_group()
 *
 * Overrides the current home thread group with an override group. However,
 * an adopted work interval overrides the override. Does not take a reference
 * on the group, so caller must guarantee group lifetime lasts as long as the
 * group is set.
 *
 * The thread group is set according to a hierarchy:
 *
 * 1) work interval specified group (explicit API)
 * 2) Auto-join thread group (wakeup tracking for special work intervals)
 * 3) bank voucher carried group (implicitly set)
 * 4) coalition default thread group (ambient)
 */
static void
thread_set_thread_group(thread_t t, struct thread_group *tg, bool auto_join)
{
	struct thread_group *home_tg = thread_group_get_home_group(t);
	struct thread_group *old_tg = NULL;

	if (tg == NULL) {
		/* when removing an override, revert to home group */
		tg = home_tg;
	}

	spl_t s = splsched();

	old_tg = t->thread_group;

	if (old_tg != tg) {
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_SET),
		    t->thread_group ? t->thread_group->tg_id : 0,
		    tg->tg_id, (uintptr_t)thread_tid(t), home_tg->tg_id);

		/*
		 * Based on whether this is a change due to auto-join, the join does
		 * different things and has different expectations.
		 */
		if (auto_join) {
#if CONFIG_SCHED_AUTO_JOIN
			/*
			 * set thread group with auto-join rules. This has the
			 * implicit assumption that the thread lock is already held.
			 * Also this could happen to any thread (current or thread
			 * being context switched).
			 */
			thread_set_thread_group_auto_join(t, tg, old_tg);
#else /* CONFIG_SCHED_AUTO_JOIN */
			panic("Auto-Join unsupported on this platform");
#endif /* CONFIG_SCHED_AUTO_JOIN */
		} else {
			/*
			 * set thread group with the explicit join rules. This has
			 * the implicit assumption that the thread is not locked. Also
			 * this would be done only to the current thread.
			 */
			thread_set_thread_group_explicit(t, tg, old_tg);
		}
	}

	splx(s);
}

void
thread_group_set_bank(thread_t t, struct thread_group *tg)
{
	/* work interval group overrides any bank override group */
	if (t->th_work_interval) {
		return;
	}

	/* boot arg disables groups in bank */
	if (tg_set_by_bankvoucher == FALSE) {
		return;
	}

	thread_set_thread_group(t, tg, false);
}

/*
 * thread_set_work_interval_thread_group()
 *
 * Sets the thread's group to the work interval thread group.
 * If auto_join == true, thread group is being overriden through scheduler
 * auto-join policies.
 *
 * Preconditions for auto-join case:
 * - t is not current_thread and t should be locked.
 * - t should not be running on a remote core; thread context switching is a valid state for this.
 */
void
thread_set_work_interval_thread_group(thread_t t, struct thread_group *tg, bool auto_join)
{
	if (tg == NULL) {
		/*
		 * when removing a work interval override, fall back
		 * to the current voucher override.
		 *
		 * In the auto_join case, the thread is already locked by the caller so
		 * its unsafe to get the thread group from the current voucher (since
		 * that might require taking task lock and ivac lock). However, the
		 * auto-join policy does not allow threads to switch thread groups based
		 * on voucher overrides.
		 *
		 * For the normal case, lookup the thread group from the currently adopted
		 * voucher and use that as the fallback tg.
		 */

		if (auto_join == false) {
			tg = thread_get_current_voucher_thread_group(t);
		}
	}

	thread_set_thread_group(t, tg, auto_join);
}

inline cluster_type_t
thread_group_recommendation(struct thread_group *tg)
{
	if (tg == NULL) {
		return CLUSTER_TYPE_SMP;
	} else {
		return tg->tg_recommendation;
	}
}

inline uint64_t
thread_group_get_id(struct thread_group *tg)
{
	return tg->tg_id;
}

uint32_t
thread_group_count(void)
{
	return tg_count;
}

/*
 * Can only be called while tg cannot be destroyed
 */
inline const char*
thread_group_get_name(struct thread_group *tg)
{
	return tg->tg_name;
}

inline void *
thread_group_get_machine_data(struct thread_group *tg)
{
	return &tg->tg_machine_data;
}

inline uint32_t
thread_group_machine_data_size(void)
{
	return tg_machine_data_size;
}

kern_return_t
thread_group_iterate_stackshot(thread_group_iterate_fn_t callout, void *arg)
{
	struct thread_group *tg;
	int i = 0;
	qe_foreach_element(tg, &tg_queue, tg_queue_chain) {
		if (tg == NULL || !ml_validate_nofault((vm_offset_t)tg, sizeof(struct thread_group))) {
			return KERN_FAILURE;
		}
		callout(arg, i, tg);
		i++;
	}
	return KERN_SUCCESS;
}

void
thread_group_join_io_storage(void)
{
	struct thread_group *tg = thread_group_find_by_id_and_retain(THREAD_GROUP_IO_STORAGE);
	assert(tg != NULL);
	thread_set_thread_group(current_thread(), tg, false);
}

void
thread_group_join_perf_controller(void)
{
	struct thread_group *tg = thread_group_find_by_id_and_retain(THREAD_GROUP_PERF_CONTROLLER);
	assert(tg != NULL);
	thread_set_thread_group(current_thread(), tg, false);
}

void
thread_group_vm_add(void)
{
	assert(tg_vm != NULL);
	thread_set_thread_group(current_thread(), thread_group_find_by_id_and_retain(THREAD_GROUP_VM), false);
}

uint64_t
kdp_thread_group_get_flags(struct thread_group *tg)
{
	return tg->tg_flags;
}

/*
 * Returns whether the thread group is restricted to the E-cluster when CLPC is
 * turned off.
 */
boolean_t
thread_group_smp_restricted(struct thread_group *tg)
{
	if (tg->tg_flags & THREAD_GROUP_FLAGS_SMP_RESTRICT) {
		return true;
	} else {
		return false;
	}
}

void
thread_group_update_recommendation(struct thread_group *tg, cluster_type_t new_recommendation)
{
	/*
	 * Since the tg->tg_recommendation field is read by CPUs trying to determine
	 * where a thread/thread group needs to be placed, it is important to use
	 * atomic operations to update the recommendation.
	 */
	os_atomic_store(&tg->tg_recommendation, new_recommendation, relaxed);
}

#if CONFIG_SCHED_EDGE

int sched_edge_restrict_ut = 1;
int sched_edge_restrict_bg = 1;

void
sched_perfcontrol_thread_group_recommend(__unused void *machine_data, __unused cluster_type_t new_recommendation)
{
	struct thread_group *tg = (struct thread_group *)((uintptr_t)machine_data - offsetof(struct thread_group, tg_machine_data));
	/*
	 * CLUSTER_TYPE_SMP was used for some debugging support when CLPC dynamic control was turned off.
	 * In more recent implementations, CLPC simply recommends "P-spill" when dynamic control is turned off. So it should
	 * never be recommending CLUSTER_TYPE_SMP for thread groups.
	 */
	assert(new_recommendation != CLUSTER_TYPE_SMP);
	/*
	 * The Edge scheduler expects preferred cluster recommendations for each QoS level within a TG. Until the new CLPC
	 * routine is being called, fake out the call from the old CLPC interface.
	 */
	uint32_t tg_bucket_preferred_cluster[TH_BUCKET_SCHED_MAX] = {0};
	/*
	 * For all buckets higher than UT, apply the recommendation to the thread group bucket
	 */
	for (sched_bucket_t bucket = TH_BUCKET_FIXPRI; bucket < TH_BUCKET_SHARE_UT; bucket++) {
		tg_bucket_preferred_cluster[bucket] = (new_recommendation == pset_type_for_id(0)) ? 0 : 1;
	}
	/* For UT & BG QoS, set the recommendation only if they havent been restricted via sysctls */
	if (!sched_edge_restrict_ut) {
		tg_bucket_preferred_cluster[TH_BUCKET_SHARE_UT] = (new_recommendation == pset_type_for_id(0)) ? 0 : 1;
	}
	if (!sched_edge_restrict_bg) {
		tg_bucket_preferred_cluster[TH_BUCKET_SHARE_BG] = (new_recommendation == pset_type_for_id(0)) ? 0 : 1;
	}
	sched_perfcontrol_preferred_cluster_options_t options = 0;
	if (new_recommendation == CLUSTER_TYPE_P) {
		options |= SCHED_PERFCONTROL_PREFERRED_CLUSTER_MIGRATE_RUNNING;
	}
	sched_edge_tg_preferred_cluster_change(tg, tg_bucket_preferred_cluster, options);
}

void
sched_perfcontrol_edge_matrix_get(sched_clutch_edge *edge_matrix, bool *edge_request_bitmap, uint64_t flags, uint64_t matrix_order)
{
	sched_edge_matrix_get(edge_matrix, edge_request_bitmap, flags, matrix_order);
}

void
sched_perfcontrol_edge_matrix_set(sched_clutch_edge *edge_matrix, bool *edge_changes_bitmap, uint64_t flags, uint64_t matrix_order)
{
	sched_edge_matrix_set(edge_matrix, edge_changes_bitmap, flags, matrix_order);
}

void
sched_perfcontrol_thread_group_preferred_clusters_set(void *machine_data, uint32_t tg_preferred_cluster,
    uint32_t overrides[PERFCONTROL_CLASS_MAX], sched_perfcontrol_preferred_cluster_options_t options)
{
	struct thread_group *tg = (struct thread_group *)((uintptr_t)machine_data - offsetof(struct thread_group, tg_machine_data));
	uint32_t tg_bucket_preferred_cluster[TH_BUCKET_SCHED_MAX] = {
		[TH_BUCKET_FIXPRI]   = (overrides[PERFCONTROL_CLASS_ABOVEUI] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_ABOVEUI] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_FG] = (overrides[PERFCONTROL_CLASS_UI] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_UI] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_IN] = (overrides[PERFCONTROL_CLASS_UI] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_UI] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_DF] = (overrides[PERFCONTROL_CLASS_NONUI] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_NONUI] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_UT] = (overrides[PERFCONTROL_CLASS_UTILITY] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_UTILITY] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_BG] = (overrides[PERFCONTROL_CLASS_BACKGROUND] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_BACKGROUND] : tg_preferred_cluster,
	};
	sched_edge_tg_preferred_cluster_change(tg, tg_bucket_preferred_cluster, options);
}

#else /* CONFIG_SCHED_EDGE */

void
sched_perfcontrol_thread_group_recommend(__unused void *machine_data, __unused cluster_type_t new_recommendation)
{
	struct thread_group *tg = (struct thread_group *)((uintptr_t)machine_data - offsetof(struct thread_group, tg_machine_data));
	SCHED(thread_group_recommendation_change)(tg, new_recommendation);
}

void
sched_perfcontrol_edge_matrix_get(__unused sched_clutch_edge *edge_matrix, __unused bool *edge_request_bitmap, __unused uint64_t flags, __unused uint64_t matrix_order)
{
}

void
sched_perfcontrol_edge_matrix_set(__unused sched_clutch_edge *edge_matrix, __unused bool *edge_changes_bitmap, __unused uint64_t flags, __unused uint64_t matrix_order)
{
}

void
sched_perfcontrol_thread_group_preferred_clusters_set(__unused void *machine_data, __unused uint32_t tg_preferred_cluster,
    __unused uint32_t overrides[PERFCONTROL_CLASS_MAX], __unused sched_perfcontrol_preferred_cluster_options_t options)
{
}

#endif /* CONFIG_SCHED_EDGE */

#endif /* CONFIG_THREAD_GROUPS */
