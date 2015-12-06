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
#include <kern/kalloc.h>
#include <kern/ledger.h>
#include <kern/mach_param.h> /* for TASK_CHUNK */
#include <kern/task.h>
#include <kern/zalloc.h>

#include <libkern/OSAtomic.h>

#include <mach/coalition_notification_server.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>

#include <sys/errno.h>

/*
 * BSD interface functions
 */
int coalitions_get_list(int type, struct procinfo_coalinfo *coal_list, int list_sz);
boolean_t coalition_is_leader(task_t task, int coal_type, coalition_t *coal);
int coalition_get_task_count(coalition_t coal);
uint64_t coalition_get_page_count(coalition_t coal, int *ntasks);
int coalition_get_pid_list(coalition_t coal, uint32_t rolemask, int sort_order,
				  int *pid_list, int list_sz);

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
static queue_head_t coalitions_q;

coalition_t init_coalition[COALITION_NUM_TYPES];

zone_t coalition_zone;

static const char *coal_type_str(int type)
{
	switch(type) {
	case COALITION_TYPE_RESOURCE:
		return "RESOURCE";
	case COALITION_TYPE_JETSAM:
		return "JETSAM";
	default:
		return "<unknown>";
	}
}

struct coalition_type {
	int type;
	int has_default;
	/*
	 * init
	 * pre-condition: coalition just allocated (unlocked), unreferenced,
	 *                type field set
	 */
	kern_return_t (*init)(coalition_t coal, boolean_t privileged);

	/*
	 * dealloc
	 * pre-condition: coalition unlocked
	 * pre-condition: coalition refcount=0, active_count=0,
	 *                termrequested=1, terminated=1, reaped=1
	 */
	void          (*dealloc)(coalition_t coal);

	/*
	 * adopt_task
	 * pre-condition: coalition locked
	 * pre-condition: coalition !repead and !terminated
	 */
	kern_return_t (*adopt_task)(coalition_t coal, task_t task);

	/*
	 * remove_task
	 * pre-condition: coalition locked
	 * pre-condition: task has been removed from coalition's task list
	 */
	kern_return_t (*remove_task)(coalition_t coal, task_t task);

	/*
	 * set_taskrole
	 * pre-condition: coalition locked
	 * pre-condition: task added to coalition's task list,
	 *                active_count >= 1 (at least the given task is active)
	 */
	kern_return_t (*set_taskrole)(coalition_t coal, task_t task, int role);

	/*
	 * get_taskrole
	 * pre-condition: coalition locked
	 * pre-condition: task added to coalition's task list,
	 *                active_count >= 1 (at least the given task is active)
	 */
	int (*get_taskrole)(coalition_t coal, task_t task);

	/*
	 * iterate_tasks
	 * pre-condition: coalition locked
	 */
	void (*iterate_tasks)(coalition_t coal, void *ctx, void (*callback)(coalition_t, void *, task_t));
};

/*
 * COALITION_TYPE_RESOURCE
 */

static kern_return_t i_coal_resource_init(coalition_t coal, boolean_t privileged);
static void          i_coal_resource_dealloc(coalition_t coal);
static kern_return_t i_coal_resource_adopt_task(coalition_t coal, task_t task);
static kern_return_t i_coal_resource_remove_task(coalition_t coal, task_t task);
static kern_return_t i_coal_resource_set_taskrole(coalition_t coal,
						 task_t task, int role);
static int           i_coal_resource_get_taskrole(coalition_t coal, task_t task);
static void          i_coal_resource_iterate_tasks(coalition_t coal, void *ctx,
						   void (*callback)(coalition_t, void *, task_t));

struct i_resource_coalition {
	ledger_t ledger;
	uint64_t bytesread;
	uint64_t byteswritten;
	uint64_t gpu_time;

	uint64_t task_count;      /* tasks that have started in this coalition */
	uint64_t dead_task_count; /* tasks that have exited in this coalition;
				     subtract from task_count to get count
				     of "active" tasks */
	/*
	 * Count the length of time this coalition had at least one active task.
	 * This can be a 'denominator' to turn e.g. cpu_time to %cpu.
	 * */
	uint64_t last_became_nonempty_time;
	uint64_t time_nonempty;

	queue_head_t tasks;         /* List of active tasks in the coalition */
};

/*
 * COALITION_TYPE_JETSAM
 */

static kern_return_t i_coal_jetsam_init(coalition_t coal, boolean_t privileged);
static void          i_coal_jetsam_dealloc(coalition_t coal);
static kern_return_t i_coal_jetsam_adopt_task(coalition_t coal, task_t task);
static kern_return_t i_coal_jetsam_remove_task(coalition_t coal, task_t task);
static kern_return_t i_coal_jetsam_set_taskrole(coalition_t coal,
					       task_t task, int role);
static int           i_coal_jetsam_get_taskrole(coalition_t coal, task_t task);
static void          i_coal_jetsam_iterate_tasks(coalition_t coal, void *ctx,
						 void (*callback)(coalition_t, void *, task_t));

struct i_jetsam_coalition {
	task_t       leader;
	queue_head_t extensions;
	queue_head_t services;
	queue_head_t other;
};


/*
 * main coalition structure
 */
struct coalition {
	uint64_t id;                /* monotonically increasing */
	uint32_t type;
	uint32_t ref_count;         /* Number of references to the memory containing this struct */
	uint32_t active_count;      /* Number of members of (tasks in) the
				       coalition, plus vouchers referring
				       to the coalition */
	uint32_t focal_task_count;   /* Number of TASK_FOREGROUND_APPLICATION tasks in the coalition */
	uint32_t nonfocal_task_count; /* Number of TASK_BACKGROUND_APPLICATION tasks in the coalition */

	/* coalition flags */
	uint32_t privileged : 1;    /* Members of this coalition may create
				       and manage coalitions and may posix_spawn
				       processes into selected coalitions */
	/* ast? */
	/* voucher */
	uint32_t termrequested : 1; /* launchd has requested termination when coalition becomes empty */
	uint32_t terminated : 1;    /* coalition became empty and spawns are now forbidden */
	uint32_t reaped : 1;        /* reaped, invisible to userspace, but waiting for ref_count to go to zero */
	uint32_t notified : 1;      /* no-more-processes notification was sent via special port */
#if defined(DEVELOPMENT) || defined(DEBUG)
	uint32_t should_notify : 1; /* should this coalition send notifications (default: yes) */
#endif

	queue_chain_t coalitions;   /* global list of coalitions */

	decl_lck_mtx_data(,lock)    /* Coalition lock. */

	/* put coalition type-specific structures here */
	union {
		struct i_resource_coalition  r;
		struct i_jetsam_coalition    j;
	};
};

/*
 * register different coalition types:
 * these must be kept in the order specified in coalition.h
 */
static const struct coalition_type
s_coalition_types[COALITION_NUM_TYPES] = {
	{
		COALITION_TYPE_RESOURCE,
		1,
		i_coal_resource_init,
		i_coal_resource_dealloc,
		i_coal_resource_adopt_task,
		i_coal_resource_remove_task,
		i_coal_resource_set_taskrole,
		i_coal_resource_get_taskrole,
		i_coal_resource_iterate_tasks,
	},
	{
		COALITION_TYPE_JETSAM,
		1,
		i_coal_jetsam_init,
		i_coal_jetsam_dealloc,
		i_coal_jetsam_adopt_task,
		i_coal_jetsam_remove_task,
		i_coal_jetsam_set_taskrole,
		i_coal_jetsam_get_taskrole,
		i_coal_jetsam_iterate_tasks,
	},
};

#define coal_call(coal, func, ...) \
	(s_coalition_types[(coal)->type].func)(coal, ## __VA_ARGS__)


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
 *
 * COALITION_TYPE_RESOURCE
 *
 */
static kern_return_t
i_coal_resource_init(coalition_t coal, boolean_t privileged)
{
	(void)privileged;
	assert(coal && coal->type == COALITION_TYPE_RESOURCE);
	coal->r.ledger = ledger_instantiate(task_ledger_template,
					    LEDGER_CREATE_ACTIVE_ENTRIES);
	if (coal->r.ledger == NULL)
		return KERN_RESOURCE_SHORTAGE;

	queue_init(&coal->r.tasks);

	return KERN_SUCCESS;
}

static void
i_coal_resource_dealloc(coalition_t coal)
{
	assert(coal && coal->type == COALITION_TYPE_RESOURCE);
	ledger_dereference(coal->r.ledger);
}

static kern_return_t
i_coal_resource_adopt_task(coalition_t coal, task_t task)
{
	struct i_resource_coalition *cr;

	assert(coal && coal->type == COALITION_TYPE_RESOURCE);
	assert(queue_empty(&task->task_coalition[COALITION_TYPE_RESOURCE]));

	cr = &coal->r;
	cr->task_count++;

	if (cr->task_count < cr->dead_task_count) {
		panic("%s: coalition %p id:%llu type:%s task_count(%llu) < dead_task_count(%llu)",
		      __func__, coal, coal->id, coal_type_str(coal->type),
		      cr->task_count, cr->dead_task_count);
	}

	/* If moving from 0->1 active tasks */
	if (cr->task_count - cr->dead_task_count == 1) {
		cr->last_became_nonempty_time = mach_absolute_time();
	}

	/* put the task on the coalition's list of tasks */
	enqueue_tail(&cr->tasks, &task->task_coalition[COALITION_TYPE_RESOURCE]);

	coal_dbg("Added PID:%d to id:%llu, task_count:%llu, dead_count:%llu, nonempty_time:%llu",
		 task_pid(task), coal->id, cr->task_count, cr->dead_task_count,
		 cr->last_became_nonempty_time);

	return KERN_SUCCESS;
}

static kern_return_t
i_coal_resource_remove_task(coalition_t coal, task_t task)
{
	struct i_resource_coalition *cr;

	assert(coal && coal->type == COALITION_TYPE_RESOURCE);
	assert(task->coalition[COALITION_TYPE_RESOURCE] == coal);
	assert(!queue_empty(&task->task_coalition[COALITION_TYPE_RESOURCE]));

	/*
	 * handle resource coalition accounting rollup for dead tasks
	 */
	cr = &coal->r;

	cr->dead_task_count++;

	if (cr->task_count < cr->dead_task_count) {
		panic("%s: coalition %p id:%llu type:%s task_count(%llu) < dead_task_count(%llu)",
		      __func__, coal, coal->id, coal_type_str(coal->type), cr->task_count, cr->dead_task_count);
	}

	/* If moving from 1->0 active tasks */
	if (cr->task_count - cr->dead_task_count == 0) {
		uint64_t last_time_nonempty = mach_absolute_time() - cr->last_became_nonempty_time;
		cr->last_became_nonempty_time = 0;
		cr->time_nonempty += last_time_nonempty;
	}

	ledger_rollup(cr->ledger, task->ledger);
	cr->bytesread += task->task_io_stats->disk_reads.size;
	cr->byteswritten += task->task_io_stats->total_io.size - task->task_io_stats->disk_reads.size;
	cr->gpu_time += task_gpu_utilisation(task);

	/* remove the task from the coalition's list */
	remqueue(&task->task_coalition[COALITION_TYPE_RESOURCE]);
	queue_chain_init(task->task_coalition[COALITION_TYPE_RESOURCE]);

	coal_dbg("removed PID:%d from id:%llu, task_count:%llu, dead_count:%llu",
		 task_pid(task), coal->id, cr->task_count, cr->dead_task_count);

	return KERN_SUCCESS;
}

static kern_return_t
i_coal_resource_set_taskrole(__unused coalition_t coal,
			    __unused task_t task, __unused int role)
{
	return KERN_SUCCESS;
}

static int
i_coal_resource_get_taskrole(__unused coalition_t coal, __unused task_t task)
{
	task_t t;

	assert(coal && coal->type == COALITION_TYPE_RESOURCE);

	qe_foreach_element(t, &coal->r.tasks, task_coalition[COALITION_TYPE_RESOURCE]) {
		if (t == task)
			return COALITION_TASKROLE_UNDEF;
	}

	return -1;
}

static void
i_coal_resource_iterate_tasks(coalition_t coal, void *ctx, void (*callback)(coalition_t, void *, task_t))
{
	task_t t;
	assert(coal && coal->type == COALITION_TYPE_RESOURCE);

	qe_foreach_element(t, &coal->r.tasks, task_coalition[COALITION_TYPE_RESOURCE])
		callback(coal, ctx, t);
}

kern_return_t
coalition_resource_usage_internal(coalition_t coal, struct coalition_resource_usage *cru_out)
{
	kern_return_t kr;
	ledger_amount_t credit, debit;

	if (coal->type != COALITION_TYPE_RESOURCE)
		return KERN_INVALID_ARGUMENT;

	ledger_t sum_ledger = ledger_instantiate(task_ledger_template, LEDGER_CREATE_ACTIVE_ENTRIES);
	if (sum_ledger == LEDGER_NULL)
		return KERN_RESOURCE_SHORTAGE;

	coalition_lock(coal);

	/*
	 * Start with the coalition's ledger, which holds the totals from all
	 * the dead tasks.
	 */
	ledger_rollup(sum_ledger, coal->r.ledger);
	uint64_t bytesread = coal->r.bytesread;
	uint64_t byteswritten = coal->r.byteswritten;
	uint64_t gpu_time = coal->r.gpu_time;
	int64_t cpu_time_billed_to_me = 0;
	int64_t cpu_time_billed_to_others = 0;

	kr = ledger_get_balance(sum_ledger, task_ledgers.cpu_time_billed_to_me, (int64_t *)&cpu_time_billed_to_me);
	if (kr != KERN_SUCCESS || cpu_time_billed_to_me < 0) {
#if DEVELOPMENT || DEBUG
		printf("ledger_get_balance failed or ledger negative in coalition_resource_usage_internal: %lld\n", cpu_time_billed_to_me);
#endif /* DEVELOPMENT || DEBUG */
		cpu_time_billed_to_me = 0;
	}

	kr = ledger_get_balance(sum_ledger, task_ledgers.cpu_time_billed_to_others, (int64_t *)&cpu_time_billed_to_others);
	if (kr != KERN_SUCCESS || cpu_time_billed_to_others < 0) {
#if DEVELOPMENT || DEBUG
		printf("ledger_get_balance failed or ledger negative in coalition_resource_usage_internal: %lld\n", cpu_time_billed_to_others);
#endif /* DEVELOPMENT || DEBUG */
		cpu_time_billed_to_others = 0;
	}

	/*
	 * Add to that all the active tasks' ledgers. Tasks cannot deallocate
	 * out from under us, since we hold the coalition lock.
	 * Do not use the on-behalf of cpu time from ledger for live tasks, since
	 * it will not have cpu time for active linkages between tasks.
	 */
	task_t task;
	qe_foreach_element(task, &coal->r.tasks, task_coalition[COALITION_TYPE_RESOURCE]) {
		ledger_rollup(sum_ledger, task->ledger);
		bytesread += task->task_io_stats->disk_reads.size;
		byteswritten += task->task_io_stats->total_io.size - task->task_io_stats->disk_reads.size;
		gpu_time += task_gpu_utilisation(task);
		cpu_time_billed_to_me += (int64_t)bank_billed_time(task->bank_context);
		cpu_time_billed_to_others += (int64_t)bank_serviced_time(task->bank_context);
	}

	/* collect information from the coalition itself */
	cru_out->tasks_started = coal->r.task_count;
	cru_out->tasks_exited = coal->r.dead_task_count;

	uint64_t time_nonempty = coal->r.time_nonempty;
	uint64_t last_became_nonempty_time = coal->r.last_became_nonempty_time;

	coalition_unlock(coal);

	/* Copy the totals out of sum_ledger */
	kr = ledger_get_entries(sum_ledger, task_ledgers.cpu_time,
			&credit, &debit);
	if (kr != KERN_SUCCESS) {
		credit = 0;
	}
	cru_out->cpu_time = credit;
	cru_out->cpu_time_billed_to_me = (uint64_t)cpu_time_billed_to_me;
	cru_out->cpu_time_billed_to_others = (uint64_t)cpu_time_billed_to_others;

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
 *
 * COALITION_TYPE_JETSAM
 *
 */
static kern_return_t
i_coal_jetsam_init(coalition_t coal, boolean_t privileged)
{
	assert(coal && coal->type == COALITION_TYPE_JETSAM);
	(void)privileged;

	coal->j.leader= TASK_NULL;
	queue_head_init(coal->j.extensions);
	queue_head_init(coal->j.services);
	queue_head_init(coal->j.other);

	return KERN_SUCCESS;
}

static void
i_coal_jetsam_dealloc(__unused coalition_t coal)
{
	assert(coal && coal->type == COALITION_TYPE_JETSAM);

	/* the coalition should be completely clear at this point */
	assert(queue_empty(&coal->j.extensions));
	assert(queue_empty(&coal->j.services));
	assert(queue_empty(&coal->j.other));
	assert(coal->j.leader == TASK_NULL);
}

static kern_return_t
i_coal_jetsam_adopt_task(coalition_t coal, task_t task)
{
	struct i_jetsam_coalition *cj;
	assert(coal && coal->type == COALITION_TYPE_JETSAM);

	cj = &coal->j;

	assert(queue_empty(&task->task_coalition[COALITION_TYPE_JETSAM]));

	/* put each task initially in the "other" list */
	enqueue_tail(&cj->other, &task->task_coalition[COALITION_TYPE_JETSAM]);
	coal_dbg("coalition %lld adopted PID:%d as UNDEF",
		 coal->id, task_pid(task));

	return KERN_SUCCESS;
}

static kern_return_t
i_coal_jetsam_remove_task(coalition_t coal, task_t task)
{
	assert(coal && coal->type == COALITION_TYPE_JETSAM);
	assert(task->coalition[COALITION_TYPE_JETSAM] == coal);

	coal_dbg("removing PID:%d from coalition id:%lld",
		 task_pid(task), coal->id);

	if (task == coal->j.leader) {
		coal->j.leader = NULL;
		coal_dbg("    PID:%d was the leader!", task_pid(task));
	} else {
		assert(!queue_empty(&task->task_coalition[COALITION_TYPE_JETSAM]));
	}

	/* remove the task from the specific coalition role queue */
	remqueue(&task->task_coalition[COALITION_TYPE_JETSAM]);
	queue_chain_init(task->task_coalition[COALITION_TYPE_RESOURCE]);

	return KERN_SUCCESS;
}

static kern_return_t
i_coal_jetsam_set_taskrole(coalition_t coal, task_t task, int role)
{
	struct i_jetsam_coalition *cj;
	queue_t q = NULL;
	assert(coal && coal->type == COALITION_TYPE_JETSAM);
	assert(task->coalition[COALITION_TYPE_JETSAM] == coal);

	cj = &coal->j;

	switch (role) {
	case COALITION_TASKROLE_LEADER:
		coal_dbg("setting PID:%d as LEADER of %lld",
			 task_pid(task), coal->id);
		if (cj->leader != TASK_NULL) {
			/* re-queue the exiting leader onto the "other" list */
			coal_dbg("    re-queue existing leader (%d) as OTHER",
				 task_pid(cj->leader));
			re_queue_tail(&cj->other, &cj->leader->task_coalition[COALITION_TYPE_JETSAM]);
		}
		/*
		 * remove the task from the "other" list
		 * (where it was put by default)
		 */
		remqueue(&task->task_coalition[COALITION_TYPE_JETSAM]);
		queue_chain_init(task->task_coalition[COALITION_TYPE_JETSAM]);

		/* set the coalition leader */
		cj->leader = task;
		break;
	case COALITION_TASKROLE_UNDEF:
		coal_dbg("setting PID:%d as UNDEF in %lld",
			 task_pid(task), coal->id);
		q = (queue_t)&cj->other;
		break;
	case COALITION_TASKROLE_XPC:
		coal_dbg("setting PID:%d as XPC in %lld",
			 task_pid(task), coal->id);
		q = (queue_t)&cj->services;
		break;
	case COALITION_TASKROLE_EXT:
		coal_dbg("setting PID:%d as EXT in %lld",
			 task_pid(task), coal->id);
		q = (queue_t)&cj->extensions;
		break;
	default:
		panic("%s: invalid role(%d) for task", __func__, role);
		return KERN_INVALID_ARGUMENT;
	}

	if (q != NULL)
		re_queue_tail(q, &task->task_coalition[COALITION_TYPE_JETSAM]);

	return KERN_SUCCESS;
}

static int
i_coal_jetsam_get_taskrole(coalition_t coal, task_t task)
{
	struct i_jetsam_coalition *cj;
	task_t t;

	assert(coal && coal->type == COALITION_TYPE_JETSAM);
	assert(task->coalition[COALITION_TYPE_JETSAM] == coal);

	cj = &coal->j;

	if (task == cj->leader)
		return COALITION_TASKROLE_LEADER;

	qe_foreach_element(t, &cj->services, task_coalition[COALITION_TYPE_JETSAM]) {
		if (t == task)
			return COALITION_TASKROLE_XPC;
	}

	qe_foreach_element(t, &cj->extensions, task_coalition[COALITION_TYPE_JETSAM]) {
		if (t == task)
			return COALITION_TASKROLE_EXT;
	}

	qe_foreach_element(t, &cj->other, task_coalition[COALITION_TYPE_JETSAM]) {
		if (t == task)
			return COALITION_TASKROLE_UNDEF;
	}

	/* task not in the coalition?! */
	return -1;
}

static void
i_coal_jetsam_iterate_tasks(coalition_t coal, void *ctx, void (*callback)(coalition_t, void *, task_t))
{
	struct i_jetsam_coalition *cj;
	task_t t;

	assert(coal && coal->type == COALITION_TYPE_JETSAM);

	cj = &coal->j;

	if (cj->leader)
		callback(coal, ctx, cj->leader);

	qe_foreach_element(t, &cj->services, task_coalition[COALITION_TYPE_JETSAM])
		callback(coal, ctx, t);

	qe_foreach_element(t, &cj->extensions, task_coalition[COALITION_TYPE_JETSAM])
		callback(coal, ctx, t);

	qe_foreach_element(t, &cj->other, task_coalition[COALITION_TYPE_JETSAM])
		callback(coal, ctx, t);
}


/*
 *
 * Main Coalition implementation
 *
 */

/*
 * coalition_create_internal
 * Returns: New coalition object, referenced for the caller and unlocked.
 * Condition: coalitions_list_lock must be UNLOCKED.
 */
kern_return_t
coalition_create_internal(int type, boolean_t privileged, coalition_t *out)
{
	kern_return_t kr;
	struct coalition *new_coal;

	if (type < 0 || type > COALITION_TYPE_MAX)
		return KERN_INVALID_ARGUMENT;

	new_coal = (struct coalition *)zalloc(coalition_zone);
	if (new_coal == COALITION_NULL)
		return KERN_RESOURCE_SHORTAGE;
	bzero(new_coal, sizeof(*new_coal));

	new_coal->type = type;

	/* initialize type-specific resources */
	kr = coal_call(new_coal, init, privileged);
	if (kr != KERN_SUCCESS) {
		zfree(coalition_zone, new_coal);
		return kr;
	}

	/* One for caller, one for coalitions list */
	new_coal->ref_count = 2;

	new_coal->privileged = privileged ? TRUE : FALSE;
#if defined(DEVELOPMENT) || defined(DEBUG)
	new_coal->should_notify = 1;
#endif

	lck_mtx_init(&new_coal->lock, &coalitions_lck_grp, &coalitions_lck_attr);

	lck_mtx_lock(&coalitions_list_lock);
	new_coal->id = coalition_next_id++;
	coalition_count++;
	enqueue_tail(&coalitions_q, &new_coal->coalitions);
	lck_mtx_unlock(&coalitions_list_lock);

	coal_dbg("id:%llu, type:%s", new_coal->id, coal_type_str(new_coal->type));

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
	/* TODO: This can be done with atomics. */
	coalition_lock(coal);
	coal->ref_count--;

#if COALITION_DEBUG
	uint32_t rc = coal->ref_count;
	uint32_t ac = coal->active_count;
#endif /* COALITION_DEBUG */

	coal_dbg("id:%llu type:%s ref_count:%u active_count:%u%s",
		 coal->id, coal_type_str(coal->type), rc, ac,
		 rc <= 0 ? ", will deallocate now" : "");

	if (coal->ref_count > 0) {
		coalition_unlock(coal);
		return;
	}

	assert(coal->termrequested);
	assert(coal->terminated);
	assert(coal->active_count == 0);
	assert(coal->reaped);
	assert(coal->focal_task_count == 0);
	assert(coal->nonfocal_task_count == 0);

	coal_call(coal, dealloc);

	coalition_unlock(coal);

	lck_mtx_destroy(&coal->lock, &coalitions_lck_grp);

	zfree(coalition_zone, coal);
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
	qe_foreach_element(coal, &coalitions_q, coalitions) {
		if (coal->id == coal_id) {
			return coal;
		}
	}
	return COALITION_NULL;
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
		panic("resurrecting coalition %p id:%llu type:%s, active_count:%u\n",
				coal, coal->id, coal_type_str(coal->type), coal->active_count);
	}
	coal->ref_count++;
#if COALITION_DEBUG
	uint32_t rc = coal->ref_count;
#endif

	coalition_unlock(coal);
	lck_mtx_unlock(&coalitions_list_lock);

	coal_dbg("id:%llu type:%s ref_count:%u",
		 coal->id, coal_type_str(coal->type), rc);

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
		panic("resurrecting coalition %p id:%llu type:%s, active_count:%u\n",
				coal, coal->id, coal_type_str(coal->type), coal->active_count);
	}

	coal->ref_count++;
	coal->active_count++;

#if COALITION_DEBUG
	uint32_t rc = coal->ref_count;
	uint32_t ac = coal->active_count;
#endif

	coalition_unlock(coal);
	lck_mtx_unlock(&coalitions_list_lock);

	coal_dbg("id:%llu type:%s ref_count:%u, active_count:%u",
		 coal->id, coal_type_str(coal->type), rc, ac);

	return coal;
}

uint64_t
coalition_id(coalition_t coal)
{
	return coal->id;
}

void
task_coalition_ids(task_t task, uint64_t ids[COALITION_NUM_TYPES])
{
	int i;
	for (i = 0; i < COALITION_NUM_TYPES; i++) {
		if (task->coalition[i])
			ids[i] = task->coalition[i]->id;
		else
			ids[i] = 0;
	}
}

void
task_coalition_roles(task_t task, int roles[COALITION_NUM_TYPES])
{
	int i;
	memset(roles, 0, COALITION_NUM_TYPES * sizeof(roles[0]));

	for (i = 0; i < COALITION_NUM_TYPES; i++) {
		if (task->coalition[i]) {
			coalition_lock(task->coalition[i]);
			roles[i] = coal_call(task->coalition[i],
					     get_taskrole, task);
			coalition_unlock(task->coalition[i]);
		} else {
			roles[i] = -1;
		}
	}
}


int
coalition_type(coalition_t coal)
{
	return coal->type;
}

boolean_t
coalition_is_privileged(coalition_t coal)
{
	return coal->privileged || unrestrict_coalition_syscalls;
}

boolean_t
task_is_in_privileged_coalition(task_t task, int type)
{
	if (type < 0 || type > COALITION_TYPE_MAX)
		return FALSE;
	if (unrestrict_coalition_syscalls)
		return TRUE;
	if (!task->coalition[type])
		return FALSE;
	return task->coalition[type]->privileged;
}

void task_coalition_update_gpu_stats(task_t task, uint64_t gpu_ns_delta)
{
	coalition_t coal;

	assert(task != TASK_NULL);
	if (gpu_ns_delta == 0)
		return;

	coal = task->coalition[COALITION_TYPE_RESOURCE];
	assert(coal != COALITION_NULL);

	coalition_lock(coal);
	coal->r.gpu_time += gpu_ns_delta;
	coalition_unlock(coal);
}

uint32_t task_coalition_adjust_focal_count(task_t task, int count)
{
	coalition_t coal;
	uint32_t ret;

	/*
	 * For now: only use the resource coalition. Perhaps in the
	 * future we may combine all coalition types, or even make
	 * a special coalition type just for this.
	 */
	coal = task->coalition[COALITION_TYPE_RESOURCE];
	assert(coal != COALITION_NULL);

	ret = hw_atomic_add(&coal->focal_task_count, count);

	/* catch underflow */
	assert(ret != UINT32_MAX);
	return ret;
}

uint32_t task_coalition_focal_count(task_t task)
{
	coalition_t coal;
	coal = task->coalition[COALITION_TYPE_RESOURCE];
	assert(coal != COALITION_NULL);

	return coal->focal_task_count;
}

uint32_t task_coalition_adjust_nonfocal_count(task_t task, int count)
{
	coalition_t coal;
	uint32_t ret;

	/*
	 * For now: only use the resource coalition. Perhaps in the
	 * future we may combine all coalition types, or even make
	 * a special coalition type just for this.
	 */
	coal = task->coalition[COALITION_TYPE_RESOURCE];
	assert(coal != COALITION_NULL);

	ret = hw_atomic_add(&coal->nonfocal_task_count, count);

	/* catch underflow */
	assert(ret != UINT32_MAX);
	return ret;
}

uint32_t task_coalition_nonfocal_count(task_t task)
{
	coalition_t coal;
	coal = task->coalition[COALITION_TYPE_RESOURCE];
	assert(coal != COALITION_NULL);

	return coal->nonfocal_task_count;
}

void coalition_for_each_task(coalition_t coal, void *ctx,
			     void (*callback)(coalition_t, void *, task_t))
{
	assert(coal != COALITION_NULL);

	coal_dbg("iterating tasks in coalition %p id:%llu type:%s, active_count:%u",
		 coal, coal->id, coal_type_str(coal->type), coal->active_count);

	coalition_lock(coal);

	coal_call(coal, iterate_tasks, ctx, callback);

	coalition_unlock(coal);
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
#if defined(DEVELOPMENT) || defined(DEBUG)
		do_notify = coal->should_notify;
#else
		do_notify = TRUE;
#endif
		notify_id = coal->id;
		notify_flags = 0;
	}

#if COALITION_DEBUG
	uint64_t cid = coal->id;
	uint32_t rc = coal->ref_count;
	int      ac = coal->active_count;
	int      ct = coal->type;
#endif
	coalition_unlock(coal);

	coal_dbg("id:%llu type:%s ref_count:%u, active_count:%u,%s",
		 cid, coal_type_str(ct), rc, ac, do_notify ? " NOTIFY" : " ");

	if (do_notify) {
		coalition_notify_user(notify_id, notify_flags);
	}
}

/* Used for kernel_task, launchd, launchd's early boot tasks... */
kern_return_t
coalitions_adopt_init_task(task_t task)
{
	kern_return_t kr;
	kr = coalitions_adopt_task(init_coalition, task);
	if (kr != KERN_SUCCESS) {
		panic("failed to adopt task %p into default coalition: %d", task, kr);
	}
	return kr;
}

/*
 * coalition_adopt_task_internal
 * Condition: Coalition must be referenced and unlocked. Will fail if coalition
 * is already terminated.
 */
static kern_return_t
coalition_adopt_task_internal(coalition_t coal, task_t task)
{
	kern_return_t kr;

	if (task->coalition[coal->type]) {
		return KERN_ALREADY_IN_SET;
	}

	coalition_lock(coal);

	if (coal->reaped || coal->terminated) {
		coalition_unlock(coal);
		return KERN_TERMINATED;
	}

	kr = coal_call(coal, adopt_task, task);
	if (kr != KERN_SUCCESS)
		goto out_unlock;

	coal->active_count++;

	coal->ref_count++;

	task->coalition[coal->type] = coal;

out_unlock:
#if COALITION_DEBUG
	(void)coal; /* need expression after label */
	uint64_t cid = coal->id;
	uint32_t rc = coal->ref_count;
	uint32_t ct = coal->type;
#endif
	coalition_unlock(coal);

	coal_dbg("task:%d, id:%llu type:%s ref_count:%u, kr=%d",
		 task_pid(task), cid, coal_type_str(ct), rc, kr);
	return kr;
}

static kern_return_t
coalition_remove_task_internal(task_t task, int type)
{
	kern_return_t kr;

	coalition_t coal = task->coalition[type];

	if (!coal)
		return KERN_SUCCESS;

	assert(coal->type == (uint32_t)type);

	coalition_lock(coal);

	kr = coal_call(coal, remove_task, task);

#if COALITION_DEBUG
	uint64_t cid = coal->id;
	uint32_t rc = coal->ref_count;
	int      ac = coal->active_count;
	int      ct = coal->type;
#endif
	coalition_unlock(coal);

	coal_dbg("id:%llu type:%s ref_count:%u, active_count:%u, kr=%d",
		 cid, coal_type_str(ct), rc, ac, kr);

	coalition_remove_active(coal);

	return kr;
}

/*
 * coalitions_adopt_task
 * Condition: All coalitions must be referenced and unlocked.
 * Will fail if any coalition is already terminated.
 */
kern_return_t
coalitions_adopt_task(coalition_t *coals, task_t task)
{
	int i;
	kern_return_t kr;

	if (!coals || coals[COALITION_TYPE_RESOURCE] == COALITION_NULL)
		return KERN_INVALID_ARGUMENT;

	/* verify that the incoming coalitions are what they say they are */
	for (i = 0; i < COALITION_NUM_TYPES; i++)
		if (coals[i] && coals[i]->type != (uint32_t)i)
			return KERN_INVALID_ARGUMENT;

	for (i = 0; i < COALITION_NUM_TYPES; i++) {
		kr = KERN_SUCCESS;
		if (coals[i])
			kr = coalition_adopt_task_internal(coals[i], task);
		if (kr != KERN_SUCCESS) {
			/* dis-associate any coalitions that just adopted this task */
			while (--i >= 0) {
				if (task->coalition[i])
					coalition_remove_task_internal(task, i);
			}
			break;
		}
	}
	return kr;
}

/*
 * coalitions_remove_task
 * Condition: task must be referenced and UNLOCKED; all task's coalitions must be UNLOCKED
 */
kern_return_t
coalitions_remove_task(task_t task)
{
	kern_return_t kr;
	int i;

	for (i = 0; i < COALITION_NUM_TYPES; i++) {
		kr = coalition_remove_task_internal(task, i);
		assert(kr == KERN_SUCCESS);
	}

	return kr;
}

/*
 * task_release_coalitions
 * helper function to release references to all coalitions in which
 * 'task' is a member.
 */
void
task_release_coalitions(task_t task)
{
	int i;
	for (i = 0; i < COALITION_NUM_TYPES; i++) {
		if (task->coalition[i])
			coalition_release(task->coalition[i]);
	}
}

/*
 * coalitions_set_roles
 * for each type of coalition, if the task is a member of a coalition of
 * that type (given in the coalitions parameter) then set the role of
 * the task within that that coalition.
 */
kern_return_t coalitions_set_roles(coalition_t coalitions[COALITION_NUM_TYPES],
				   task_t task, int roles[COALITION_NUM_TYPES])
{
	kern_return_t kr = KERN_SUCCESS;
	int i;

	for (i = 0; i < COALITION_NUM_TYPES; i++) {
		if (!coalitions[i])
			continue;
		coalition_lock(coalitions[i]);
		kr = coal_call(coalitions[i], set_taskrole, task, roles[i]);
		coalition_unlock(coalitions[i]);
		assert(kr == KERN_SUCCESS);
	}

	return kr;
}

/*
 * coalition_terminate_internal
 * Condition: Coalition must be referenced and UNLOCKED.
 */
kern_return_t
coalition_request_terminate_internal(coalition_t coal)
{
	assert(coal->type >= 0 && coal->type <= COALITION_TYPE_MAX);

	if (coal == init_coalition[coal->type]) {
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
		 * We just set termrequested to zero. If the active count
		 * was already at zero (tasks died before we could request
		 * a termination notification), we should notify.
		 */
		assert(!coal->terminated);
		coal->terminated = TRUE;

		assert(!coal->notified);

		coal->notified = TRUE;
#if defined(DEVELOPMENT) || defined(DEBUG)
		do_notify = coal->should_notify;
#else
		do_notify = TRUE;
#endif
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
	assert(coal->type <= COALITION_TYPE_MAX);

	if (coal == init_coalition[coal->type]) {
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
	remqueue(&coal->coalitions);
	lck_mtx_unlock(&coalitions_list_lock);

	/* Release the list's reference and launchd's reference. */
	coalition_release(coal);
	coalition_release(coal);

	return KERN_SUCCESS;
}

#if defined(DEVELOPMENT) || defined(DEBUG)
int coalition_should_notify(coalition_t coal)
{
	int should;
	if (!coal)
		return -1;
	coalition_lock(coal);
	should = coal->should_notify;
	coalition_unlock(coal);

	return should;
}

void coalition_set_notify(coalition_t coal, int notify)
{
	if (!coal)
		return;
	coalition_lock(coal);
	coal->should_notify = !!notify;
	coalition_unlock(coal);
}
#endif

void
coalitions_init(void)
{
	kern_return_t kr;
	int i;
	const struct coalition_type *ctype;

	coalition_zone = zinit(
			sizeof(struct coalition),
			CONFIG_COALITION_MAX * sizeof(struct coalition),
			COALITION_CHUNK * sizeof(struct coalition),
			"coalitions");
	zone_change(coalition_zone, Z_NOENCRYPT, TRUE);
	queue_head_init(coalitions_q);

	if (!PE_parse_boot_argn("unrestrict_coalition_syscalls", &unrestrict_coalition_syscalls,
		sizeof (unrestrict_coalition_syscalls))) {
		unrestrict_coalition_syscalls = 0;
	}

	lck_grp_attr_setdefault(&coalitions_lck_grp_attr);
	lck_grp_init(&coalitions_lck_grp, "coalition", &coalitions_lck_grp_attr);
	lck_attr_setdefault(&coalitions_lck_attr);
	lck_mtx_init(&coalitions_list_lock, &coalitions_lck_grp, &coalitions_lck_attr);

	init_task_ledgers();

	for (i = 0, ctype = &s_coalition_types[0]; i < COALITION_NUM_TYPES; ctype++, i++) {
		/* verify the entry in the global coalition types array */
		if (ctype->type != i ||
		    !ctype->init ||
		    !ctype->dealloc ||
		    !ctype->adopt_task ||
		    !ctype->remove_task) {
			panic("%s: Malformed coalition type %s(%d) in slot for type:%s(%d)",
			      __func__, coal_type_str(ctype->type), ctype->type, coal_type_str(i), i);
		}
		if (!ctype->has_default)
			continue;
		kr = coalition_create_internal(ctype->type, TRUE, &init_coalition[ctype->type]);
		if (kr != KERN_SUCCESS)
			panic("%s: could not create init %s coalition: kr:%d",
			      __func__, coal_type_str(i), kr);
	}

	/* "Leak" our reference to the global object */
}

/*
 * BSD Kernel interface functions
 *
 */
static void coalition_fill_procinfo(struct coalition *coal,
				    struct procinfo_coalinfo *coalinfo)
{
	coalinfo->coalition_id = coal->id;
	coalinfo->coalition_type = coal->type;
	coalinfo->coalition_tasks = coalition_get_task_count(coal);
}


int coalitions_get_list(int type, struct procinfo_coalinfo *coal_list, int list_sz)
{
	int ncoals = 0;
	struct coalition *coal;

	lck_mtx_lock(&coalitions_list_lock);
	qe_foreach_element(coal, &coalitions_q, coalitions) {
		if (!coal->reaped && (type < 0 || type == (int)coal->type)) {
			if (coal_list && ncoals < list_sz)
				coalition_fill_procinfo(coal, &coal_list[ncoals]);
			++ncoals;
		}
	}
	lck_mtx_unlock(&coalitions_list_lock);

	return ncoals;
}

/*
 * Jetsam coalition interface
 *
 */
boolean_t coalition_is_leader(task_t task, int coal_type, coalition_t *coal)
{
	coalition_t c;
	boolean_t ret;

	if (coal) /* handle the error cases gracefully */
		*coal = COALITION_NULL;

	if (!task)
		return FALSE;

	if (coal_type > COALITION_TYPE_MAX)
		return FALSE;

	c = task->coalition[coal_type];
	if (!c)
		return FALSE;

	assert((int)c->type == coal_type);

	coalition_lock(c);

	if (coal)
		*coal = c;

	ret = FALSE;
	if (c->type == COALITION_TYPE_JETSAM && c->j.leader == task)
		ret = TRUE;

	coalition_unlock(c);

	return ret;
}


int coalition_get_task_count(coalition_t coal)
{
	int ntasks = 0;
	struct queue_entry *qe;
	if (!coal)
		return 0;

	coalition_lock(coal);
	switch (coal->type) {
	case COALITION_TYPE_RESOURCE:
		qe_foreach(qe, &coal->r.tasks)
			ntasks++;
		break;
	case COALITION_TYPE_JETSAM:
		if (coal->j.leader)
			ntasks++;
		qe_foreach(qe, &coal->j.other)
			ntasks++;
		qe_foreach(qe, &coal->j.extensions)
			ntasks++;
		qe_foreach(qe, &coal->j.services)
			ntasks++;
		break;
	default:
		break;
	}
	coalition_unlock(coal);

	return ntasks;
}


static uint64_t i_get_list_footprint(queue_t list, int type, int *ntasks)
{
	task_t task;
	uint64_t bytes = 0;

	qe_foreach_element(task, list, task_coalition[type]) {
		bytes += get_task_phys_footprint(task);
		coal_dbg("    [%d] task_pid:%d, type:%d, footprint:%lld",
			 *ntasks, task_pid(task), type, bytes);
		*ntasks += 1;
	}

	return bytes;
}

uint64_t coalition_get_page_count(coalition_t coal, int *ntasks)
{
	uint64_t bytes = 0;
	int num_tasks = 0;

	if (ntasks)
		*ntasks = 0;
	if (!coal)
		return bytes;

	coalition_lock(coal);

	switch (coal->type) {
	case COALITION_TYPE_RESOURCE:
		bytes += i_get_list_footprint(&coal->r.tasks, COALITION_TYPE_RESOURCE, &num_tasks);
		break;
	case COALITION_TYPE_JETSAM:
		if (coal->j.leader) {
			bytes += get_task_phys_footprint(coal->j.leader);
			num_tasks = 1;
		}
		bytes += i_get_list_footprint(&coal->j.extensions, COALITION_TYPE_JETSAM, &num_tasks);
		bytes += i_get_list_footprint(&coal->j.services, COALITION_TYPE_JETSAM, &num_tasks);
		bytes += i_get_list_footprint(&coal->j.other, COALITION_TYPE_JETSAM, &num_tasks);
		break;
	default:
		break;
	}

	coalition_unlock(coal);

	if (ntasks)
		*ntasks = num_tasks;

	return bytes / PAGE_SIZE_64;
}

struct coal_sort_s {
	int pid;
	int usr_order;
	uint64_t bytes;
};

/*
 * return < 0 for a < b
 *          0 for a == b
 *        > 0 for a > b
 */
typedef int (*cmpfunc_t)(const void *a, const void *b);

extern void
qsort(void *a, size_t n, size_t es, cmpfunc_t cmp);

static int dflt_cmp(const void *a, const void *b)
{
	const struct coal_sort_s *csA = (const struct coal_sort_s *)a;
	const struct coal_sort_s *csB = (const struct coal_sort_s *)b;

	/*
	 * if both A and B are equal, use a memory descending sort
	 */
	if (csA->usr_order == csB->usr_order)
		return (int)((int64_t)csB->bytes - (int64_t)csA->bytes);

	/* otherwise, return the relationship between user specified orders */
	return (csA->usr_order - csB->usr_order);
}

static int mem_asc_cmp(const void *a, const void *b)
{
	const struct coal_sort_s *csA = (const struct coal_sort_s *)a;
	const struct coal_sort_s *csB = (const struct coal_sort_s *)b;

	return (int)((int64_t)csA->bytes - (int64_t)csB->bytes);
}

static int mem_dec_cmp(const void *a, const void *b)
{
	const struct coal_sort_s *csA = (const struct coal_sort_s *)a;
	const struct coal_sort_s *csB = (const struct coal_sort_s *)b;

	return (int)((int64_t)csB->bytes - (int64_t)csA->bytes);
}

static int usr_asc_cmp(const void *a, const void *b)
{
	const struct coal_sort_s *csA = (const struct coal_sort_s *)a;
	const struct coal_sort_s *csB = (const struct coal_sort_s *)b;

	return (csA->usr_order - csB->usr_order);
}

static int usr_dec_cmp(const void *a, const void *b)
{
	const struct coal_sort_s *csA = (const struct coal_sort_s *)a;
	const struct coal_sort_s *csB = (const struct coal_sort_s *)b;

	return (csB->usr_order - csA->usr_order);
}

/* avoid dynamic allocation in this path */
#define MAX_SORTED_PIDS  80

static int coalition_get_sort_list(coalition_t coal, int sort_order, queue_t list,
				   struct coal_sort_s *sort_array, int array_sz)
{
	int ntasks = 0;
	task_t task;

	assert(sort_array != NULL);

	if (array_sz <= 0)
		return 0;

	if (!list) {
		/*
		 * this function will only be called with a NULL
		 * list for JETSAM-type coalitions, and is intended
		 * to investigate the leader process
		 */
		if (coal->type != COALITION_TYPE_JETSAM ||
		    coal->j.leader == TASK_NULL)
			return 0;
		sort_array[0].pid = task_pid(coal->j.leader);
		switch (sort_order) {
		case COALITION_SORT_DEFAULT:
			sort_array[0].usr_order = 0;
			/* fall-through */
		case COALITION_SORT_MEM_ASC:
		case COALITION_SORT_MEM_DEC:
			sort_array[0].bytes = get_task_phys_footprint(coal->j.leader);
			break;
		case COALITION_SORT_USER_ASC:
		case COALITION_SORT_USER_DEC:
			sort_array[0].usr_order = 0;
			break;
		default:
			break;
		}
		return 1;
	}

	qe_foreach_element(task, list, task_coalition[coal->type]) {
		if (ntasks >= array_sz) {
			printf("WARNING: more than %d pids in coalition %llu\n",
			       MAX_SORTED_PIDS, coal->id);
			break;
		}

		sort_array[ntasks].pid = task_pid(task);

		switch (sort_order) {
		case COALITION_SORT_DEFAULT:
			sort_array[ntasks].usr_order = 0;
			/* fall-through */
		case COALITION_SORT_MEM_ASC:
		case COALITION_SORT_MEM_DEC:
			sort_array[ntasks].bytes = get_task_phys_footprint(task);
			break;
		case COALITION_SORT_USER_ASC:
		case COALITION_SORT_USER_DEC:
			sort_array[ntasks].usr_order = 0;
			break;
		default:
			break;
		}

		ntasks++;
	}

	return ntasks;
}

int coalition_get_pid_list(coalition_t coal, uint32_t rolemask, int sort_order,
			   int *pid_list, int list_sz)
{
	struct i_jetsam_coalition *cj;
	int ntasks = 0;
	cmpfunc_t cmp_func = NULL;
	struct coal_sort_s sort_array[MAX_SORTED_PIDS] = { {0,0,0} }; /* keep to < 2k */

	if (!coal ||
	    !(rolemask & COALITION_ROLEMASK_ALLROLES) ||
	    !pid_list || list_sz < 1) {
		coal_dbg("Invalid parameters: coal:%p, type:%d, rolemask:0x%x, "
			 "pid_list:%p, list_sz:%d", coal, coal ? coal->type : -1,
			 rolemask, pid_list, list_sz);
		return -EINVAL;
	}

	switch (sort_order) {
	case COALITION_SORT_NOSORT:
		cmp_func = NULL;
		break;
	case COALITION_SORT_DEFAULT:
		cmp_func = dflt_cmp;
		break;
	case COALITION_SORT_MEM_ASC:
		cmp_func = mem_asc_cmp;
		break;
	case COALITION_SORT_MEM_DEC:
		cmp_func = mem_dec_cmp;
		break;
	case COALITION_SORT_USER_ASC:
		cmp_func = usr_asc_cmp;
		break;
	case COALITION_SORT_USER_DEC:
		cmp_func = usr_dec_cmp;
		break;
	default:
		return -ENOTSUP;
	}

	coalition_lock(coal);

	if (coal->type == COALITION_TYPE_RESOURCE) {
		ntasks += coalition_get_sort_list(coal, sort_order, &coal->r.tasks,
						  sort_array, MAX_SORTED_PIDS);
		goto unlock_coal;
	}

	cj = &coal->j;

	if (rolemask & COALITION_ROLEMASK_UNDEF)
		ntasks += coalition_get_sort_list(coal, sort_order, &cj->other,
						  sort_array + ntasks,
						  MAX_SORTED_PIDS - ntasks);

	if (rolemask & COALITION_ROLEMASK_XPC)
		ntasks += coalition_get_sort_list(coal, sort_order, &cj->services,
						  sort_array + ntasks,
						  MAX_SORTED_PIDS - ntasks);

	if (rolemask & COALITION_ROLEMASK_EXT)
		ntasks += coalition_get_sort_list(coal, sort_order, &cj->extensions,
						  sort_array + ntasks,
						  MAX_SORTED_PIDS - ntasks);

	if (rolemask & COALITION_ROLEMASK_LEADER)
		ntasks += coalition_get_sort_list(coal, sort_order, NULL,
						  sort_array + ntasks,
						  MAX_SORTED_PIDS - ntasks);

unlock_coal:
	coalition_unlock(coal);

	/* sort based on the chosen criterion (no sense sorting 1 item) */
	if (cmp_func && ntasks > 1)
		qsort(sort_array, ntasks, sizeof(struct coal_sort_s), cmp_func);

	for (int i = 0; i < ntasks; i++) {
		if (i >= list_sz)
			break;
		coal_dbg(" [%d] PID:%d, footprint:%lld, usr_order:%d",
			 i, sort_array[i].pid, sort_array[i].bytes,
			 sort_array[i].usr_order);
		pid_list[i] = sort_array[i].pid;
	}

	return ntasks;
}
