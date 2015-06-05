/*
 * Copyright (c) 2013 Apple Computer, Inc. All rights reserved.
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

#include <kern/kern_types.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>

#include <kern/coalition.h>
#include <kern/host.h>
#include <kern/ledger.h>
#include <kern/kalloc.h>
#include <kern/mach_param.h> /* for TASK_CHUNK */
#include <kern/task.h>
#include <kern/zalloc.h>
#include <kern/sfi.h>

#include <libkern/OSAtomic.h>

#include <mach/coalition_notification_server.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>

#include <sys/errno.h>

/* defined in task.c */
extern ledger_template_t task_ledger_template;

/*
 * Coalition zone needs limits. We expect there will be as many coalitions as
 * tasks (same order of magnitude), so use the task zone's limits.
 * */
#define CONFIG_COALITION_MAX CONFIG_TASK_MAX
#define COALITION_CHUNK TASK_CHUNK

int unrestrict_coalition_syscalls;

lck_attr_t coalitions_lck_attr;
lck_grp_t coalitions_lck_grp;
lck_grp_attr_t coalitions_lck_grp_attr;

/* coalitions_list_lock protects coalition_count, coalitions queue, next_coalition_id. */
decl_lck_mtx_data(static,coalitions_list_lock);
static uint64_t coalition_count;
static uint64_t coalition_next_id = 1;
static queue_head_t coalitions;

coalition_t default_coalition;

zone_t coalition_zone;

struct coalition {
	uint64_t id;			/* monotonically increasing */

	ledger_t ledger;
	uint64_t bytesread;
	uint64_t byteswritten;
	uint64_t gpu_time;

	/*
	 * Count the length of time this coalition had at least one active task.
	 * This can be a 'denominator' to turn e.g. cpu_time to %cpu.
	 * */
	uint64_t last_became_nonempty_time;
	uint64_t time_nonempty;

	uint64_t task_count;		/* Count of tasks that have started in this coalition */
	uint64_t dead_task_count;	/* Count of tasks that have exited in this coalition; subtract from task_count to get count of "active" */
	queue_head_t tasks;		/* List of active tasks in the coalition */

	queue_chain_t coalitions;	/* global list of coalitions */

	decl_lck_mtx_data(,lock)	/* Coalition lock. */

	uint32_t ref_count;		/* Number of references to the memory containing this struct */
	uint32_t active_count;		/* Number of members of (tasks in) the coalition, plus vouchers referring to the coalition */

	unsigned int privileged : 1;	/* Members of this coalition may create and manage coalitions and may posix_spawn processes into selected coalitions */

	/* ast? */

	/* voucher */

	/* state of the coalition */
	unsigned int termrequested : 1;		/* launchd has requested termination when coalition becomes empty */
	unsigned int terminated : 1;		/* coalition became empty and spawns are now forbidden */
	unsigned int reaped : 1;		/* reaped, invisible to userspace, but waiting for ref_count to go to zero */
	unsigned int notified : 1;		/* no-more-processes notification was sent via special port */

	uint32_t focal_tasks_count;     /* count of TASK_FOREGROUND_APPLICATION tasks in the coalition */
	uint32_t non_focal_tasks_count; /* count of TASK_BACKGROUND_APPLICATION tasks in the coalition */
};

#define coalition_lock(c) do{ lck_mtx_lock(&c->lock); }while(0)
#define coalition_unlock(c) do{ lck_mtx_unlock(&c->lock); }while(0)

static void
coalition_notify_user(uint64_t id, uint32_t flags)
{
	mach_port_t user_port;
	kern_return_t kr;

	kr = host_get_coalition_port(host_priv_self(), &user_port);
	if ((kr != KERN_SUCCESS) || !IPC_PORT_VALID(user_port)) {
		return;
	}

	coalition_notification(user_port, id, flags);
}

/*
 * coalition_find_by_id_internal
 * Returns: Coalition object with specified id, NOT referenced.
 *          If not found, returns COALITION_NULL.
 * Condition: coalitions_list_lock must be LOCKED.
 */
static coalition_t
coalition_find_by_id_internal(uint64_t coal_id)
{
	if (coal_id == 0) {
		return COALITION_NULL;
	}

	lck_mtx_assert(&coalitions_list_lock, LCK_MTX_ASSERT_OWNED);
	coalition_t coal;
	queue_iterate(&coalitions, coal, coalition_t, coalitions) {
		if (coal->id == coal_id) {
			return coal;
		}
	}
	return COALITION_NULL;
}

kern_return_t
coalition_resource_usage_internal(coalition_t coal, struct coalition_resource_usage *cru_out)
{
	kern_return_t kr;
	ledger_amount_t credit, debit;

	ledger_t sum_ledger = ledger_instantiate(task_ledger_template, LEDGER_CREATE_ACTIVE_ENTRIES);
	if (sum_ledger == LEDGER_NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	coalition_lock(coal);

	/*
	 * Start with the coalition's ledger, which holds the totals from all
	 * the dead tasks.
	 */
	ledger_rollup(sum_ledger, coal->ledger);
	uint64_t bytesread = coal->bytesread;
	uint64_t byteswritten = coal->byteswritten;
	uint64_t gpu_time = coal->gpu_time;

	/*
	 * Add to that all the active tasks' ledgers. Tasks cannot deallocate
	 * out from under us, since we hold the coalition lock.
	 */
	task_t task;
	queue_iterate(&coal->tasks, task, task_t, coalition_tasks) {
		ledger_rollup(sum_ledger, task->ledger);
		bytesread += task->task_io_stats->disk_reads.size;
		byteswritten += task->task_io_stats->total_io.size - task->task_io_stats->disk_reads.size;
		gpu_time += task_gpu_utilisation(task);
	}

	/* collect information from the coalition itself */
	cru_out->tasks_started = coal->task_count;
	cru_out->tasks_exited = coal->dead_task_count;

	uint64_t time_nonempty = coal->time_nonempty;
	uint64_t last_became_nonempty_time = coal->last_became_nonempty_time;

	coalition_unlock(coal);

	/* Copy the totals out of sum_ledger */
	kr = ledger_get_entries(sum_ledger, task_ledgers.cpu_time,
			&credit, &debit);
	if (kr != KERN_SUCCESS) {
		credit = 0;
	}
	cru_out->cpu_time = credit;

	kr = ledger_get_entries(sum_ledger, task_ledgers.interrupt_wakeups,
			&credit, &debit);
	if (kr != KERN_SUCCESS) {
		credit = 0;
	}
	cru_out->interrupt_wakeups = credit;

	kr = ledger_get_entries(sum_ledger, task_ledgers.platform_idle_wakeups,
			&credit, &debit);
	if (kr != KERN_SUCCESS) {
		credit = 0;
	}
	cru_out->platform_idle_wakeups = credit;

	cru_out->bytesread = bytesread;
	cru_out->byteswritten = byteswritten;
	cru_out->gpu_time = gpu_time;

	ledger_dereference(sum_ledger);
	sum_ledger = LEDGER_NULL;

	if (last_became_nonempty_time) {
		time_nonempty += mach_absolute_time() - last_became_nonempty_time;
	}
	absolutetime_to_nanoseconds(time_nonempty, &cru_out->time_nonempty);

	return KERN_SUCCESS;
}

/*
 * coalition_create_internal
 * Returns: New coalition object, referenced for the caller and unlocked.
 * Condition: coalitions_list_lock must be UNLOCKED.
 */
kern_return_t
coalition_create_internal(coalition_t *out, boolean_t privileged)
{
	struct coalition *new_coal = (struct coalition *)zalloc(coalition_zone);
	if (new_coal == COALITION_NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}
	bzero(new_coal, sizeof(*new_coal));

	new_coal->ledger = ledger_instantiate(task_ledger_template, LEDGER_CREATE_ACTIVE_ENTRIES);
	if (new_coal->ledger == NULL) {
		zfree(coalition_zone, new_coal);
		return KERN_RESOURCE_SHORTAGE;
	}

	/* One for caller, one for coalitions list */
	new_coal->ref_count = 2;

	new_coal->privileged = privileged ? TRUE : FALSE;

	lck_mtx_init(&new_coal->lock, &coalitions_lck_grp, &coalitions_lck_attr);
	queue_init(&new_coal->tasks);

	lck_mtx_lock(&coalitions_list_lock);
	new_coal->id = coalition_next_id++;
	coalition_count++;
	queue_enter(&coalitions, new_coal, coalition_t, coalitions);
	lck_mtx_unlock(&coalitions_list_lock);

#if COALITION_DEBUG
	printf("%s: new coal id %llu\n", __func__, new_coal->id);
#endif

	*out = new_coal;
	return KERN_SUCCESS;
}

/*
 * coalition_release
 * Condition: coalition must be UNLOCKED.
 * */
void
coalition_release(coalition_t coal)
{
	boolean_t do_dealloc = FALSE;

	/* TODO: This can be done with atomics. */
	coalition_lock(coal);
	coal->ref_count--;
	if (coal->ref_count == 0) {
		do_dealloc = TRUE;
	}
#if COALITION_DEBUG
	uint32_t rc = coal->ref_count;
#endif /* COALITION_DEBUG */

	coalition_unlock(coal);

#if COALITION_DEBUG
	printf("%s: coal %llu ref_count-- -> %u%s\n", __func__, coal->id, rc,
			do_dealloc ? ", will deallocate now" : "");
#endif /* COALITION_DEBUG */

	if (do_dealloc) {
		assert(coal->termrequested);
		assert(coal->terminated);
		assert(coal->active_count == 0);
		assert(coal->reaped);
		assert(coal->focal_tasks_count == 0);
		assert(coal->non_focal_tasks_count == 0);

		ledger_dereference(coal->ledger);
		lck_mtx_destroy(&coal->lock, &coalitions_lck_grp);
		zfree(coalition_zone, coal);
	}
}

/*
 * coalition_find_by_id
 * Returns: Coalition object with specified id, referenced.
 * Condition: coalitions_list_lock must be UNLOCKED.
 */
coalition_t
coalition_find_by_id(uint64_t cid)
{
	if (cid == 0) {
		return COALITION_NULL;
	}

	lck_mtx_lock(&coalitions_list_lock);

	coalition_t coal = coalition_find_by_id_internal(cid);
	if (coal == COALITION_NULL) {
		lck_mtx_unlock(&coalitions_list_lock);
		return COALITION_NULL;
	}

	coalition_lock(coal);

	if (coal->reaped) {
		coalition_unlock(coal);
		lck_mtx_unlock(&coalitions_list_lock);
		return COALITION_NULL;
	}

	if (coal->ref_count == 0) {
		panic("resurrecting coalition %p id %llu, active_count = %u\n",
				coal, coal->id, coal->active_count);
	}
	coal->ref_count++;
#if COALITION_DEBUG
	uint32_t rc = coal->ref_count;
#endif

	coalition_unlock(coal);
	lck_mtx_unlock(&coalitions_list_lock);

#if COALITION_DEBUG
	printf("%s: coal %llu ref_count++ -> %u\n", __func__, coal->id, rc);
#endif
	return coal;
}

/*
 * coalition_find_and_activate_by_id
 * Returns: Coalition object with specified id, referenced, and activated.
 * Condition: coalitions_list_lock must be UNLOCKED.
 * This is the function to use when putting a 'new' thing into a coalition,
 * like posix_spawn of an XPC service by launchd.
 * See also coalition_extend_active.
 */
coalition_t
coalition_find_and_activate_by_id(uint64_t cid)
{
	if (cid == 0) {
		return COALITION_NULL;
	}

	lck_mtx_lock(&coalitions_list_lock);

	coalition_t coal = coalition_find_by_id_internal(cid);
	if (coal == COALITION_NULL) {
		lck_mtx_unlock(&coalitions_list_lock);
		return COALITION_NULL;
	}

	coalition_lock(coal);

	if (coal->reaped || coal->terminated) {
		/* Too late to put something new into this coalition, it's
		 * already on its way out the door */
		coalition_unlock(coal);
		lck_mtx_unlock(&coalitions_list_lock);
		return COALITION_NULL;
	}

	if (coal->ref_count == 0) {
		panic("resurrecting coalition %p id %llu, active_count = %u\n",
				coal, coal->id, coal->active_count);
	}

	coal->ref_count++;
	coal->active_count++;

#if COALITION_DEBUG
	uint32_t rc = coal->ref_count;
	uint32_t ac = coal->active_count;
#endif

	coalition_unlock(coal);
	lck_mtx_unlock(&coalitions_list_lock);

#if COALITION_DEBUG
	printf("%s: coal %llu ref_count++ -> %u, active_count++ -> %u\n",
			__func__, coal->id, rc, ac);
#endif
	return coal;
}

uint64_t
coalition_id(coalition_t coal)
{
	return coal->id;
}

uint64_t
task_coalition_id(task_t task)
{
	return task->coalition->id;
}

boolean_t
coalition_is_privileged(coalition_t coal)
{
	return coal->privileged || unrestrict_coalition_syscalls;
}

boolean_t
task_is_in_privileged_coalition(task_t task)
{
	return task->coalition->privileged || unrestrict_coalition_syscalls;
}

/*
 * coalition_get_ledger
 * Returns: Coalition's ledger, NOT referenced.
 * Condition: Caller must have a coalition reference.
 */
ledger_t
coalition_get_ledger(coalition_t coal)
{
	return coal->ledger;
}

/*
 * This is the function to use when you already hold an activation on the
 * coalition, and want to extend it to a second activation owned by a new
 * object, like when a task in the coalition calls fork(). This is analogous
 * to taking a second reference when you already hold one.
 * See also coalition_find_and_activate_by_id.
 */
kern_return_t
coalition_extend_active(coalition_t coal)
{
	coalition_lock(coal);

	if (coal->reaped) {
		panic("cannot make a reaped coalition active again");
	}

	if (coal->terminated) {
		coalition_unlock(coal);
		return KERN_TERMINATED;
	}

	assert(coal->active_count > 0);
	coal->active_count++;

	coalition_unlock(coal);
	return KERN_SUCCESS;
}

void
coalition_remove_active(coalition_t coal)
{
	coalition_lock(coal);

	assert(!coal->reaped);
	assert(coal->active_count > 0);

	coal->active_count--;

	boolean_t do_notify = FALSE;
	uint64_t notify_id = 0;
	uint32_t notify_flags = 0;
	if (coal->termrequested && coal->active_count == 0) {
		/* We only notify once, when active_count reaches zero.
		 * We just decremented, so if it reached zero, we mustn't have
		 * notified already.
		 */
		assert(!coal->terminated);
		coal->terminated = TRUE;

		assert(!coal->notified);

		coal->notified = TRUE;
		do_notify = TRUE;
		notify_id = coal->id;
		notify_flags = 0;
	}

	coalition_unlock(coal);

	if (do_notify) {
		coalition_notify_user(notify_id, notify_flags);
	}
}

/* Used for kernel_task, launchd, launchd's early boot tasks... */
kern_return_t
coalition_default_adopt_task(task_t task)
{
	kern_return_t kr;
	kr = coalition_adopt_task(default_coalition, task);
	if (kr != KERN_SUCCESS) {
		panic("failed to adopt task %p into default coalition: %d", task, kr);
	}
	return kr;
}

/*
 * coalition_adopt_task
 * Condition: Coalition must be referenced and unlocked. Will fail if coalition
 * is already terminated.
 */
kern_return_t
coalition_adopt_task(coalition_t coal, task_t task)
{
	if (task->coalition) {
		return KERN_ALREADY_IN_SET;
	}

	coalition_lock(coal);

	if (coal->reaped || coal->terminated) {
		coalition_unlock(coal);
		return KERN_TERMINATED;
	}

	coal->active_count++;

	coal->ref_count++;
	task->coalition = coal;

	queue_enter(&coal->tasks, task, task_t, coalition_tasks);
	coal->task_count++;

	if(coal->task_count < coal->dead_task_count) {
		panic("%s: coalition %p id %llu task_count < dead_task_count", __func__, coal, coal->id);
	}

	/* If moving from 0->1 active tasks */
	if (coal->task_count - coal->dead_task_count == 1) {
		coal->last_became_nonempty_time = mach_absolute_time();
	}

#if COALITION_DEBUG
	uint32_t rc = coal->ref_count;
#endif

	coalition_unlock(coal);

#if COALITION_DEBUG
	if (rc) {
		printf("%s: coal %llu ref_count++ -> %u\n", __func__, coal->id, rc);
	}
#endif
	return KERN_SUCCESS;
}

/*
 * coalition_remove_task
 * Condition: task must be referenced and UNLOCKED; task's coalition must be UNLOCKED
 */
kern_return_t
coalition_remove_task(task_t task)
{
	coalition_t coal = task->coalition;
	assert(coal);

	coalition_lock(coal);

	queue_remove(&coal->tasks, task, task_t, coalition_tasks);
	coal->dead_task_count++;

	if(coal->task_count < coal->dead_task_count) {
		panic("%s: coalition %p id %llu task_count < dead_task_count", __func__, coal, coal->id);
	}

	/* If moving from 1->0 active tasks */
	if (coal->task_count - coal->dead_task_count == 0) {
		uint64_t last_time_nonempty = mach_absolute_time() - coal->last_became_nonempty_time;
		coal->last_became_nonempty_time = 0;
		coal->time_nonempty += last_time_nonempty;
	}

	ledger_rollup(coal->ledger, task->ledger);
	coal->bytesread += task->task_io_stats->disk_reads.size;
	coal->byteswritten += task->task_io_stats->total_io.size - task->task_io_stats->disk_reads.size;
	coal->gpu_time += task_gpu_utilisation(task);

	coalition_unlock(coal);

	coalition_remove_active(coal);
	return KERN_SUCCESS;
}

/*
 * coalition_terminate_internal
 * Condition: Coalition must be referenced and UNLOCKED.
 */
kern_return_t
coalition_request_terminate_internal(coalition_t coal)
{
	if (coal == default_coalition) {
		return KERN_DEFAULT_SET;
	}

	coalition_lock(coal);

	if (coal->reaped) {
		coalition_unlock(coal);
		return KERN_INVALID_NAME;
	}

	if (coal->terminated || coal->termrequested) {
		coalition_unlock(coal);
		return KERN_TERMINATED;
	}

	coal->termrequested = TRUE;

	boolean_t do_notify = FALSE;
	uint64_t note_id = 0;
	uint32_t note_flags = 0;

	if (coal->active_count == 0) {
		/*
		 * We only notify once, when active_count reaches zero.
		 * We just decremented, so if it reached zero, we mustn't have
		 * notified already.
		 */
		assert(!coal->terminated);
		coal->terminated = TRUE;

		assert(!coal->notified);

		coal->notified = TRUE;
		do_notify = TRUE;
		note_id = coal->id;
		note_flags = 0;
	}

	coalition_unlock(coal);

	if (do_notify) {
		coalition_notify_user(note_id, note_flags);
	}

	return KERN_SUCCESS;
}

/*
 * coalition_reap_internal
 * Condition: Coalition must be referenced and UNLOCKED.
 */
kern_return_t
coalition_reap_internal(coalition_t coal)
{
	if (coal == default_coalition) {
		return KERN_DEFAULT_SET;
	}

	coalition_lock(coal);
	if (coal->reaped) {
		coalition_unlock(coal);
		return KERN_TERMINATED;
	}
	if (!coal->terminated) {
		coalition_unlock(coal);
		return KERN_FAILURE;
	}
	assert(coal->termrequested);
	if (coal->active_count > 0) {
		coalition_unlock(coal);
		return KERN_FAILURE;
	}

	coal->reaped = TRUE;

	/* Caller, launchd, and coalitions list should each have a reference */
	assert(coal->ref_count > 2);

	coalition_unlock(coal);

	lck_mtx_lock(&coalitions_list_lock);
	coalition_count--;
	queue_remove(&coalitions, coal, coalition_t, coalitions);
	lck_mtx_unlock(&coalitions_list_lock);

	/* Release the list's reference and launchd's reference. */
	coalition_release(coal);
	coalition_release(coal);

	return KERN_SUCCESS;
}

void
coalition_init(void)
{
	coalition_zone = zinit(
			sizeof(struct coalition),
			CONFIG_COALITION_MAX * sizeof(struct coalition),
			COALITION_CHUNK * sizeof(struct coalition),
			"coalitions");
	zone_change(coalition_zone, Z_NOENCRYPT, TRUE);
	queue_init(&coalitions);

	if (!PE_parse_boot_argn("unrestrict_coalition_syscalls", &unrestrict_coalition_syscalls,
		sizeof (unrestrict_coalition_syscalls))) {
		unrestrict_coalition_syscalls = 0;
	}

	lck_grp_attr_setdefault(&coalitions_lck_grp_attr);
	lck_grp_init(&coalitions_lck_grp, "coalition", &coalitions_lck_grp_attr);
	lck_attr_setdefault(&coalitions_lck_attr);
	lck_mtx_init(&coalitions_list_lock, &coalitions_lck_grp, &coalitions_lck_attr);

	init_task_ledgers();

	kern_return_t kr = coalition_create_internal(&default_coalition, TRUE);
	if (kr != KERN_SUCCESS) {
		panic("%s: could not create default coalition: %d", __func__, kr);
	}
	/* "Leak" our reference to the global object */
}

/* coalition focal tasks */
uint32_t coalition_adjust_focal_task_count(coalition_t coal, int count)
{
	return hw_atomic_add(&coal->focal_tasks_count, count);
}

uint32_t coalition_focal_task_count(coalition_t coal)
{
	return coal->focal_tasks_count;
}

uint32_t coalition_adjust_non_focal_task_count(coalition_t coal, int count)
{
	return hw_atomic_add(&coal->non_focal_tasks_count, count);
}

uint32_t coalition_non_focal_task_count(coalition_t coal)
{
	return coal->non_focal_tasks_count;
}

/* Call sfi_reevaluate() for every thread in the coalition */
void coalition_sfi_reevaluate(coalition_t coal, task_t updated_task) {
	task_t task;
	thread_t thread;

	coalition_lock(coal);

	queue_iterate(&coal->tasks, task, task_t, coalition_tasks) {

		/* Skip the task we're doing this on behalf of - it's already updated */
		if (task == updated_task)
			continue;

		task_lock(task);

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
				sfi_reevaluate(thread);
		}
		task_unlock(task);
	}
	coalition_unlock(coal);
}

