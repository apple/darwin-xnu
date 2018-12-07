/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	processor.c: processor and processor_set manipulation routines.
 */

#include <mach/boolean.h>
#include <mach/policy.h>
#include <mach/processor.h>
#include <mach/processor_info.h>
#include <mach/vm_param.h>
#include <kern/cpu_number.h>
#include <kern/host.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/sched.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/ipc_host.h>
#include <kern/ipc_tt.h>
#include <ipc/ipc_port.h>
#include <kern/kalloc.h>

#include <security/mac_mach_internal.h>

#if defined(CONFIG_XNUPOST)

#include <tests/xnupost.h>

#endif /* CONFIG_XNUPOST */

/*
 * Exported interface
 */
#include <mach/mach_host_server.h>
#include <mach/processor_set_server.h>

struct processor_set	pset0;
struct pset_node		pset_node0;
decl_simple_lock_data(static,pset_node_lock)

queue_head_t			tasks;
queue_head_t			terminated_tasks;	/* To be used ONLY for stackshot. */
queue_head_t			corpse_tasks;
int						tasks_count;
int						terminated_tasks_count;
queue_head_t			threads;
int						threads_count;
decl_lck_mtx_data(,tasks_threads_lock)
decl_lck_mtx_data(,tasks_corpse_lock)

processor_t				processor_list;
unsigned int			processor_count;
static processor_t		processor_list_tail;
decl_simple_lock_data(,processor_list_lock)

uint32_t				processor_avail_count;

processor_t		master_processor;
int 			master_cpu = 0;
boolean_t		sched_stats_active = FALSE;

processor_t		processor_array[MAX_SCHED_CPUS] = { 0 };

#if defined(CONFIG_XNUPOST)
kern_return_t ipi_test(void);
extern void arm64_ipi_test(void);

kern_return_t
ipi_test()
{
#if __arm64__
	processor_t p;

	for (p = processor_list; p != NULL; p = p->processor_list) {
		thread_bind(p);
		thread_block(THREAD_CONTINUE_NULL);
		kprintf("Running IPI test on cpu %d\n", p->cpu_id);
		arm64_ipi_test();
	}

	/* unbind thread from specific cpu */
	thread_bind(PROCESSOR_NULL);
	thread_block(THREAD_CONTINUE_NULL);

	T_PASS("Done running IPI tests");
#else
	T_PASS("Unsupported platform. Not running IPI tests");

#endif /* __arm64__ */

	return KERN_SUCCESS;
}
#endif /* defined(CONFIG_XNUPOST) */


void
processor_bootstrap(void)
{
	pset_init(&pset0, &pset_node0);
	pset_node0.psets = &pset0;

	simple_lock_init(&pset_node_lock, 0);

	queue_init(&tasks);
	queue_init(&terminated_tasks);
	queue_init(&threads);
	queue_init(&corpse_tasks);

	simple_lock_init(&processor_list_lock, 0);

	master_processor = cpu_to_processor(master_cpu);

	processor_init(master_processor, master_cpu, &pset0);
}

/*
 *	Initialize the given processor for the cpu
 *	indicated by cpu_id, and assign to the
 *	specified processor set.
 */
void
processor_init(
	processor_t			processor,
	int					cpu_id,
	processor_set_t		pset)
{
	spl_t		s;

	if (processor != master_processor) {
		/* Scheduler state for master_processor initialized in sched_init() */
		SCHED(processor_init)(processor);
	}

	assert(cpu_id < MAX_SCHED_CPUS);

	processor->state = PROCESSOR_OFF_LINE;
	processor->active_thread = processor->next_thread = processor->idle_thread = THREAD_NULL;
	processor->processor_set = pset;
	processor_state_update_idle(processor);
	processor->starting_pri = MINPRI;
	processor->cpu_id = cpu_id;
	timer_call_setup(&processor->quantum_timer, thread_quantum_expire, processor);
	processor->quantum_end = UINT64_MAX;
	processor->deadline = UINT64_MAX;
	processor->first_timeslice = FALSE;
	processor->processor_primary = processor; /* no SMT relationship known at this point */
	processor->processor_secondary = NULL;
	processor->is_SMT = FALSE;
	processor->is_recommended = (pset->recommended_bitmask & (1ULL << cpu_id)) ? TRUE : FALSE;
	processor->processor_self = IP_NULL;
	processor_data_init(processor);
	processor->processor_list = NULL;
	processor->cpu_quiesce_state = CPU_QUIESCE_COUNTER_NONE;
	processor->cpu_quiesce_last_checkin = 0;

	s = splsched();
	pset_lock(pset);
	bit_set(pset->cpu_bitmask, cpu_id);
	if (pset->cpu_set_count++ == 0)
		pset->cpu_set_low = pset->cpu_set_hi = cpu_id;
	else {
		pset->cpu_set_low = (cpu_id < pset->cpu_set_low)? cpu_id: pset->cpu_set_low;
		pset->cpu_set_hi = (cpu_id > pset->cpu_set_hi)? cpu_id: pset->cpu_set_hi;
	}
	pset_unlock(pset);
	splx(s);

	simple_lock(&processor_list_lock);
	if (processor_list == NULL)
		processor_list = processor;
	else
		processor_list_tail->processor_list = processor;
	processor_list_tail = processor;
	processor_count++;
	processor_array[cpu_id] = processor;
	simple_unlock(&processor_list_lock);
}

void
processor_set_primary(
	processor_t		processor,
	processor_t		primary)
{
	assert(processor->processor_primary == primary || processor->processor_primary == processor);
	/* Re-adjust primary point for this (possibly) secondary processor */
	processor->processor_primary = primary;

	assert(primary->processor_secondary == NULL || primary->processor_secondary == processor);
	if (primary != processor) {
		/* Link primary to secondary, assumes a 2-way SMT model
		 * We'll need to move to a queue if any future architecture
		 * requires otherwise.
		 */
		assert(processor->processor_secondary == NULL);
		primary->processor_secondary = processor;
		/* Mark both processors as SMT siblings */
		primary->is_SMT = TRUE;
		processor->is_SMT = TRUE;

		processor_set_t pset = processor->processor_set;
		atomic_bit_clear(&pset->primary_map, processor->cpu_id, memory_order_relaxed);
	}
}

processor_set_t
processor_pset(
	processor_t	processor)
{
	return (processor->processor_set);
}

void
processor_state_update_idle(processor_t processor)
{
    processor->current_pri = IDLEPRI;
    processor->current_sfi_class = SFI_CLASS_KERNEL;
    processor->current_recommended_pset_type = PSET_SMP;
    processor->current_perfctl_class = PERFCONTROL_CLASS_IDLE;
}

void
processor_state_update_from_thread(processor_t processor, thread_t thread)
{
    processor->current_pri = thread->sched_pri;
    processor->current_sfi_class = thread->sfi_class;
    processor->current_recommended_pset_type = recommended_pset_type(thread);
    processor->current_perfctl_class = thread_get_perfcontrol_class(thread);
}

void
processor_state_update_explicit(processor_t processor, int pri, sfi_class_id_t sfi_class, 
	pset_cluster_type_t pset_type, perfcontrol_class_t perfctl_class)
{
    processor->current_pri = pri;
    processor->current_sfi_class = sfi_class;
    processor->current_recommended_pset_type = pset_type;
    processor->current_perfctl_class = perfctl_class;
}

pset_node_t
pset_node_root(void)
{
	return &pset_node0;
}

processor_set_t
pset_create(
	pset_node_t			node)
{
	/* some schedulers do not support multiple psets */
	if (SCHED(multiple_psets_enabled) == FALSE)
		return processor_pset(master_processor);

	processor_set_t		*prev, pset = kalloc(sizeof (*pset));

	if (pset != PROCESSOR_SET_NULL) {
		pset_init(pset, node);

		simple_lock(&pset_node_lock);

		prev = &node->psets;
		while (*prev != PROCESSOR_SET_NULL)
			prev = &(*prev)->pset_list;

		*prev = pset;

		simple_unlock(&pset_node_lock);
	}

	return (pset);
}

/*
 *	Find processor set in specified node with specified cluster_id.
 *	Returns default_pset if not found.
 */
processor_set_t
pset_find(
	uint32_t cluster_id,
	processor_set_t default_pset)
{
	simple_lock(&pset_node_lock);
	pset_node_t node = &pset_node0;
	processor_set_t pset = NULL;

	do {
		pset = node->psets;
		while (pset != NULL) {
			if (pset->pset_cluster_id == cluster_id)
				break;
			pset = pset->pset_list;
		}
	} while ((node = node->node_list) != NULL);
	simple_unlock(&pset_node_lock);
	if (pset == NULL)
		return default_pset;
	return (pset);
}

/*
 *	Initialize the given processor_set structure.
 */
void
pset_init(
	processor_set_t		pset,
	pset_node_t			node)
{
	if (pset != &pset0) {
		/* Scheduler state for pset0 initialized in sched_init() */
		SCHED(pset_init)(pset);
		SCHED(rt_init)(pset);
	}

	pset->online_processor_count = 0;
	pset->load_average = 0;
	pset->cpu_set_low = pset->cpu_set_hi = 0;
	pset->cpu_set_count = 0;
	pset->last_chosen = -1;
	pset->cpu_bitmask = 0;
	pset->recommended_bitmask = ~0ULL;
	pset->primary_map = ~0ULL;
	pset->cpu_state_map[PROCESSOR_OFF_LINE] = ~0ULL;
	for (uint i = PROCESSOR_SHUTDOWN; i < PROCESSOR_STATE_LEN; i++) {
		pset->cpu_state_map[i] = 0;
	}
	pset->pending_AST_cpu_mask = 0;
#if defined(CONFIG_SCHED_DEFERRED_AST)
	pset->pending_deferred_AST_cpu_mask = 0;
#endif
	pset->pending_spill_cpu_mask = 0;
	pset_lock_init(pset);
	pset->pset_self = IP_NULL;
	pset->pset_name_self = IP_NULL;
	pset->pset_list = PROCESSOR_SET_NULL;
	pset->node = node;
	pset->pset_cluster_type = PSET_SMP;
	pset->pset_cluster_id = 0;
}

kern_return_t
processor_info_count(
	processor_flavor_t		flavor,
	mach_msg_type_number_t	*count)
{
	switch (flavor) {

	case PROCESSOR_BASIC_INFO:
		*count = PROCESSOR_BASIC_INFO_COUNT;
		break;

	case PROCESSOR_CPU_LOAD_INFO:
		*count = PROCESSOR_CPU_LOAD_INFO_COUNT;
		break;

	default:
		return (cpu_info_count(flavor, count));
	}

	return (KERN_SUCCESS);
}


kern_return_t
processor_info(
	processor_t	processor,
	processor_flavor_t		flavor,
	host_t					*host,
	processor_info_t		info,
	mach_msg_type_number_t	*count)
{
	int	cpu_id, state;
	kern_return_t	result;

	if (processor == PROCESSOR_NULL)
		return (KERN_INVALID_ARGUMENT);

	cpu_id = processor->cpu_id;

	switch (flavor) {

	case PROCESSOR_BASIC_INFO:
	{
		processor_basic_info_t		basic_info;

		if (*count < PROCESSOR_BASIC_INFO_COUNT)
			return (KERN_FAILURE);

		basic_info = (processor_basic_info_t) info;
		basic_info->cpu_type = slot_type(cpu_id);
		basic_info->cpu_subtype = slot_subtype(cpu_id);
		state = processor->state;
		if (state == PROCESSOR_OFF_LINE)
			basic_info->running = FALSE;
		else
			basic_info->running = TRUE;
		basic_info->slot_num = cpu_id;
		if (processor == master_processor) 
			basic_info->is_master = TRUE;
		else
			basic_info->is_master = FALSE;

		*count = PROCESSOR_BASIC_INFO_COUNT;
		*host = &realhost;

	    return (KERN_SUCCESS);
	}

	case PROCESSOR_CPU_LOAD_INFO:
	{
		processor_cpu_load_info_t	cpu_load_info;
		timer_t		idle_state;
		uint64_t	idle_time_snapshot1, idle_time_snapshot2;
		uint64_t	idle_time_tstamp1, idle_time_tstamp2;

		/*
		 * We capture the accumulated idle time twice over
		 * the course of this function, as well as the timestamps
		 * when each were last updated. Since these are
		 * all done using non-atomic racy mechanisms, the
		 * most we can infer is whether values are stable.
		 * timer_grab() is the only function that can be
		 * used reliably on another processor's per-processor
		 * data.
		 */

		if (*count < PROCESSOR_CPU_LOAD_INFO_COUNT)
			return (KERN_FAILURE);

		cpu_load_info = (processor_cpu_load_info_t) info;
		if (precise_user_kernel_time) {
			cpu_load_info->cpu_ticks[CPU_STATE_USER] =
							(uint32_t)(timer_grab(&PROCESSOR_DATA(processor, user_state)) / hz_tick_interval);
			cpu_load_info->cpu_ticks[CPU_STATE_SYSTEM] =
							(uint32_t)(timer_grab(&PROCESSOR_DATA(processor, system_state)) / hz_tick_interval);
		} else {
			uint64_t tval = timer_grab(&PROCESSOR_DATA(processor, user_state)) +
				timer_grab(&PROCESSOR_DATA(processor, system_state));

			cpu_load_info->cpu_ticks[CPU_STATE_USER] = (uint32_t)(tval / hz_tick_interval);
			cpu_load_info->cpu_ticks[CPU_STATE_SYSTEM] = 0;
		}

		idle_state = &PROCESSOR_DATA(processor, idle_state);
		idle_time_snapshot1 = timer_grab(idle_state);
		idle_time_tstamp1 = idle_state->tstamp;

		/*
		 * Idle processors are not continually updating their
		 * per-processor idle timer, so it may be extremely
		 * out of date, resulting in an over-representation
		 * of non-idle time between two measurement
		 * intervals by e.g. top(1). If we are non-idle, or
		 * have evidence that the timer is being updated
		 * concurrently, we consider its value up-to-date.
		 */
		if (PROCESSOR_DATA(processor, current_state) != idle_state) {
			cpu_load_info->cpu_ticks[CPU_STATE_IDLE] =
							(uint32_t)(idle_time_snapshot1 / hz_tick_interval);
		} else if ((idle_time_snapshot1 != (idle_time_snapshot2 = timer_grab(idle_state))) ||
				   (idle_time_tstamp1 != (idle_time_tstamp2 = idle_state->tstamp))){
			/* Idle timer is being updated concurrently, second stamp is good enough */
			cpu_load_info->cpu_ticks[CPU_STATE_IDLE] =
							(uint32_t)(idle_time_snapshot2 / hz_tick_interval);
		} else {
			/*
			 * Idle timer may be very stale. Fortunately we have established
			 * that idle_time_snapshot1 and idle_time_tstamp1 are unchanging
			 */
			idle_time_snapshot1 += mach_absolute_time() - idle_time_tstamp1;
				
			cpu_load_info->cpu_ticks[CPU_STATE_IDLE] =
				(uint32_t)(idle_time_snapshot1 / hz_tick_interval);
		}

		cpu_load_info->cpu_ticks[CPU_STATE_NICE] = 0;

	    *count = PROCESSOR_CPU_LOAD_INFO_COUNT;
	    *host = &realhost;

	    return (KERN_SUCCESS);
	}

	default:
	    result = cpu_info(flavor, cpu_id, info, count);
	    if (result == KERN_SUCCESS)
			*host = &realhost;		   

	    return (result);
	}
}

kern_return_t
processor_start(
	processor_t			processor)
{
	processor_set_t		pset;
	thread_t			thread;   
	kern_return_t		result;
	spl_t				s;

	if (processor == PROCESSOR_NULL || processor->processor_set == PROCESSOR_SET_NULL)
		return (KERN_INVALID_ARGUMENT);

	if (processor == master_processor) {
		processor_t		prev;

		prev = thread_bind(processor);
		thread_block(THREAD_CONTINUE_NULL);

		result = cpu_start(processor->cpu_id);

		thread_bind(prev);

		return (result);
	}

	s = splsched();
	pset = processor->processor_set;
	pset_lock(pset);
	if (processor->state != PROCESSOR_OFF_LINE) {
		pset_unlock(pset);
		splx(s);

		return (KERN_FAILURE);
	}

	pset_update_processor_state(pset, processor, PROCESSOR_START);
	pset_unlock(pset);
	splx(s);

	/*
	 *	Create the idle processor thread.
	 */
	if (processor->idle_thread == THREAD_NULL) {
		result = idle_thread_create(processor);
		if (result != KERN_SUCCESS) {
			s = splsched();
			pset_lock(pset);
			pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
			pset_unlock(pset);
			splx(s);

			return (result);
		}
	}

	/*
	 *	If there is no active thread, the processor
	 *	has never been started.  Create a dedicated
	 *	start up thread.
	 */
	if (	processor->active_thread == THREAD_NULL		&&
			processor->next_thread == THREAD_NULL		) {
		result = kernel_thread_create((thread_continue_t)processor_start_thread, NULL, MAXPRI_KERNEL, &thread);
		if (result != KERN_SUCCESS) {
			s = splsched();
			pset_lock(pset);
			pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
			pset_unlock(pset);
			splx(s);

			return (result);
		}

		s = splsched();
		thread_lock(thread);
		thread->bound_processor = processor;
		processor->next_thread = thread;
		thread->state = TH_RUN;
		thread->last_made_runnable_time = mach_absolute_time();
		thread_unlock(thread);
		splx(s);

		thread_deallocate(thread);
	}

	if (processor->processor_self == IP_NULL)
		ipc_processor_init(processor);

	result = cpu_start(processor->cpu_id);
	if (result != KERN_SUCCESS) {
		s = splsched();
		pset_lock(pset);
		pset_update_processor_state(pset, processor, PROCESSOR_OFF_LINE);
		pset_unlock(pset);
		splx(s);

		return (result);
	}

	ipc_processor_enable(processor);

	return (KERN_SUCCESS);
}

kern_return_t
processor_exit(
	processor_t	processor)
{
	if (processor == PROCESSOR_NULL)
		return(KERN_INVALID_ARGUMENT);

	return(processor_shutdown(processor));
}

kern_return_t
processor_control(
	processor_t		processor,
	processor_info_t	info,
	mach_msg_type_number_t	count)
{
	if (processor == PROCESSOR_NULL)
		return(KERN_INVALID_ARGUMENT);

	return(cpu_control(processor->cpu_id, info, count));
}
	    
kern_return_t
processor_set_create(
	__unused host_t		host,
	__unused processor_set_t	*new_set,
	__unused processor_set_t	*new_name)
{
	return(KERN_FAILURE);
}

kern_return_t
processor_set_destroy(
	__unused processor_set_t	pset)
{
	return(KERN_FAILURE);
}

kern_return_t
processor_get_assignment(
	processor_t	processor,
	processor_set_t	*pset)
{
	int state;

	if (processor == PROCESSOR_NULL)
		return(KERN_INVALID_ARGUMENT);

	state = processor->state;
	if (state == PROCESSOR_SHUTDOWN || state == PROCESSOR_OFF_LINE)
		return(KERN_FAILURE);

	*pset = &pset0;

	return(KERN_SUCCESS);
}

kern_return_t
processor_set_info(
	processor_set_t		pset,
	int			flavor,
	host_t			*host,
	processor_set_info_t	info,
	mach_msg_type_number_t	*count)
{
	if (pset == PROCESSOR_SET_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (flavor == PROCESSOR_SET_BASIC_INFO) {
		processor_set_basic_info_t	basic_info;

		if (*count < PROCESSOR_SET_BASIC_INFO_COUNT)
			return(KERN_FAILURE);

		basic_info = (processor_set_basic_info_t) info;
		basic_info->processor_count = processor_avail_count;
		basic_info->default_policy = POLICY_TIMESHARE;

		*count = PROCESSOR_SET_BASIC_INFO_COUNT;
		*host = &realhost;
		return(KERN_SUCCESS);
	}
	else if (flavor == PROCESSOR_SET_TIMESHARE_DEFAULT) {
		policy_timeshare_base_t	ts_base;

		if (*count < POLICY_TIMESHARE_BASE_COUNT)
			return(KERN_FAILURE);

		ts_base = (policy_timeshare_base_t) info;
		ts_base->base_priority = BASEPRI_DEFAULT;

		*count = POLICY_TIMESHARE_BASE_COUNT;
		*host = &realhost;
		return(KERN_SUCCESS);
	}
	else if (flavor == PROCESSOR_SET_FIFO_DEFAULT) {
		policy_fifo_base_t		fifo_base;

		if (*count < POLICY_FIFO_BASE_COUNT)
			return(KERN_FAILURE);

		fifo_base = (policy_fifo_base_t) info;
		fifo_base->base_priority = BASEPRI_DEFAULT;

		*count = POLICY_FIFO_BASE_COUNT;
		*host = &realhost;
		return(KERN_SUCCESS);
	}
	else if (flavor == PROCESSOR_SET_RR_DEFAULT) {
		policy_rr_base_t		rr_base;

		if (*count < POLICY_RR_BASE_COUNT)
			return(KERN_FAILURE);

		rr_base = (policy_rr_base_t) info;
		rr_base->base_priority = BASEPRI_DEFAULT;
		rr_base->quantum = 1;

		*count = POLICY_RR_BASE_COUNT;
		*host = &realhost;
		return(KERN_SUCCESS);
	}
	else if (flavor == PROCESSOR_SET_TIMESHARE_LIMITS) {
		policy_timeshare_limit_t	ts_limit;

		if (*count < POLICY_TIMESHARE_LIMIT_COUNT)
			return(KERN_FAILURE);

		ts_limit = (policy_timeshare_limit_t) info;
		ts_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_TIMESHARE_LIMIT_COUNT;
		*host = &realhost;
		return(KERN_SUCCESS);
	}
	else if (flavor == PROCESSOR_SET_FIFO_LIMITS) {
		policy_fifo_limit_t		fifo_limit;

		if (*count < POLICY_FIFO_LIMIT_COUNT)
			return(KERN_FAILURE);

		fifo_limit = (policy_fifo_limit_t) info;
		fifo_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_FIFO_LIMIT_COUNT;
		*host = &realhost;
		return(KERN_SUCCESS);
	}
	else if (flavor == PROCESSOR_SET_RR_LIMITS) {
		policy_rr_limit_t		rr_limit;

		if (*count < POLICY_RR_LIMIT_COUNT)
			return(KERN_FAILURE);

		rr_limit = (policy_rr_limit_t) info;
		rr_limit->max_priority = MAXPRI_KERNEL;

		*count = POLICY_RR_LIMIT_COUNT;
		*host = &realhost;
		return(KERN_SUCCESS);
	}
	else if (flavor == PROCESSOR_SET_ENABLED_POLICIES) {
		int				*enabled;

		if (*count < (sizeof(*enabled)/sizeof(int)))
			return(KERN_FAILURE);

		enabled = (int *) info;
		*enabled = POLICY_TIMESHARE | POLICY_RR | POLICY_FIFO;

		*count = sizeof(*enabled)/sizeof(int);
		*host = &realhost;
		return(KERN_SUCCESS);
	}


	*host = HOST_NULL;
	return(KERN_INVALID_ARGUMENT);
}

/*
 *	processor_set_statistics
 *
 *	Returns scheduling statistics for a processor set. 
 */
kern_return_t 
processor_set_statistics(
	processor_set_t         pset,
	int                     flavor,
	processor_set_info_t    info,
	mach_msg_type_number_t	*count)
{
	if (pset == PROCESSOR_SET_NULL || pset != &pset0)
		return (KERN_INVALID_PROCESSOR_SET);

	if (flavor == PROCESSOR_SET_LOAD_INFO) {
		processor_set_load_info_t     load_info;

		if (*count < PROCESSOR_SET_LOAD_INFO_COUNT)
			return(KERN_FAILURE);

		load_info = (processor_set_load_info_t) info;

		load_info->mach_factor = sched_mach_factor;
		load_info->load_average = sched_load_average;

		load_info->task_count = tasks_count;
		load_info->thread_count = threads_count;

		*count = PROCESSOR_SET_LOAD_INFO_COUNT;
		return(KERN_SUCCESS);
	}

	return(KERN_INVALID_ARGUMENT);
}

/*
 *	processor_set_max_priority:
 *
 *	Specify max priority permitted on processor set.  This affects
 *	newly created and assigned threads.  Optionally change existing
 * 	ones.
 */
kern_return_t
processor_set_max_priority(
	__unused processor_set_t	pset,
	__unused int			max_priority,
	__unused boolean_t		change_threads)
{
	return (KERN_INVALID_ARGUMENT);
}

/*
 *	processor_set_policy_enable:
 *
 *	Allow indicated policy on processor set.
 */

kern_return_t
processor_set_policy_enable(
	__unused processor_set_t	pset,
	__unused int			policy)
{
	return (KERN_INVALID_ARGUMENT);
}

/*
 *	processor_set_policy_disable:
 *
 *	Forbid indicated policy on processor set.  Time sharing cannot
 *	be forbidden.
 */
kern_return_t
processor_set_policy_disable(
	__unused processor_set_t	pset,
	__unused int			policy,
	__unused boolean_t		change_threads)
{
	return (KERN_INVALID_ARGUMENT);
}

/*
 *	processor_set_things:
 *
 *	Common internals for processor_set_{threads,tasks}
 */
kern_return_t
processor_set_things(
	processor_set_t	pset,
	void **thing_list,
	mach_msg_type_number_t *count,
	int type)
{
	unsigned int i;
	task_t task;
	thread_t thread;

	task_t *task_list;
	unsigned int actual_tasks;
	vm_size_t task_size, task_size_needed;

	thread_t *thread_list;
	unsigned int actual_threads;
	vm_size_t thread_size, thread_size_needed;

	void *addr, *newaddr;
	vm_size_t size, size_needed;

	if (pset == PROCESSOR_SET_NULL || pset != &pset0)
		return (KERN_INVALID_ARGUMENT);

	task_size = 0;
	task_size_needed = 0;
	task_list = NULL;
	actual_tasks = 0;

	thread_size = 0;
	thread_size_needed = 0;
	thread_list = NULL;
	actual_threads = 0;

	for (;;) {
		lck_mtx_lock(&tasks_threads_lock);

		/* do we have the memory we need? */
		if (type == PSET_THING_THREAD)
			thread_size_needed = threads_count * sizeof(void *);
#if !CONFIG_MACF
		else
#endif
			task_size_needed = tasks_count * sizeof(void *);

		if (task_size_needed <= task_size &&
		    thread_size_needed <= thread_size)
			break;

		/* unlock and allocate more memory */
		lck_mtx_unlock(&tasks_threads_lock);

		/* grow task array */
		if (task_size_needed > task_size) {
			if (task_size != 0)
				kfree(task_list, task_size);

			assert(task_size_needed > 0);
			task_size = task_size_needed;

			task_list = (task_t *)kalloc(task_size);
			if (task_list == NULL) {
				if (thread_size != 0)
					kfree(thread_list, thread_size);
				return (KERN_RESOURCE_SHORTAGE);
			}
		}

		/* grow thread array */
		if (thread_size_needed > thread_size) {
			if (thread_size != 0)
				kfree(thread_list, thread_size);

			assert(thread_size_needed > 0);
			thread_size = thread_size_needed;

			thread_list = (thread_t *)kalloc(thread_size);
			if (thread_list == 0) {
				if (task_size != 0)
					kfree(task_list, task_size);
				return (KERN_RESOURCE_SHORTAGE);
			}
		}
	}

	/* OK, have memory and the list locked */

	/* If we need it, get the thread list */
	if (type == PSET_THING_THREAD) {
		for (thread = (thread_t)queue_first(&threads);
		     !queue_end(&threads, (queue_entry_t)thread);
		     thread = (thread_t)queue_next(&thread->threads)) {
#if defined(SECURE_KERNEL)
			if (thread->task != kernel_task) {
#endif
				thread_reference_internal(thread);
				thread_list[actual_threads++] = thread;
#if defined(SECURE_KERNEL)
			}
#endif
		}
	}
#if !CONFIG_MACF
	  else {
#endif
		/* get a list of the tasks */
		for (task = (task_t)queue_first(&tasks);
		     !queue_end(&tasks, (queue_entry_t)task);
		     task = (task_t)queue_next(&task->tasks)) {
#if defined(SECURE_KERNEL)
			if (task != kernel_task) {
#endif
				task_reference_internal(task);
				task_list[actual_tasks++] = task;
#if defined(SECURE_KERNEL)
			}
#endif
		}
#if !CONFIG_MACF
	}
#endif

	lck_mtx_unlock(&tasks_threads_lock);

#if CONFIG_MACF
	unsigned int j, used;

	/* for each task, make sure we are allowed to examine it */
	for (i = used = 0; i < actual_tasks; i++) {
		if (mac_task_check_expose_task(task_list[i])) {
			task_deallocate(task_list[i]);
			continue;
		}
		task_list[used++] = task_list[i];
	}
	actual_tasks = used;
	task_size_needed = actual_tasks * sizeof(void *);

	if (type == PSET_THING_THREAD) {

		/* for each thread (if any), make sure it's task is in the allowed list */
		for (i = used = 0; i < actual_threads; i++) {
			boolean_t found_task = FALSE;

			task = thread_list[i]->task;
			for (j = 0; j < actual_tasks; j++) {
				if (task_list[j] == task) {
					found_task = TRUE;
					break;
				}
			}
			if (found_task)
				thread_list[used++] = thread_list[i];
			else
				thread_deallocate(thread_list[i]);
		}
		actual_threads = used;
		thread_size_needed = actual_threads * sizeof(void *);

		/* done with the task list */
		for (i = 0; i < actual_tasks; i++)
			task_deallocate(task_list[i]);
		kfree(task_list, task_size);
		task_size = 0;
		actual_tasks = 0;
		task_list = NULL;
	}
#endif

	if (type == PSET_THING_THREAD) {
		if (actual_threads == 0) {
			/* no threads available to return */
			assert(task_size == 0);
			if (thread_size != 0)
				kfree(thread_list, thread_size);
			*thing_list = NULL;
			*count = 0;
			return KERN_SUCCESS;
		}
		size_needed = actual_threads * sizeof(void *);
		size = thread_size;
		addr = thread_list;
	} else {
		if (actual_tasks == 0) {
			/* no tasks available to return */
			assert(thread_size == 0);
			if (task_size != 0)
				kfree(task_list, task_size);
			*thing_list = NULL;
			*count = 0;
			return KERN_SUCCESS;
		} 
		size_needed = actual_tasks * sizeof(void *);
		size = task_size;
		addr = task_list;
	}

	/* if we allocated too much, must copy */
	if (size_needed < size) {
		newaddr = kalloc(size_needed);
		if (newaddr == 0) {
			for (i = 0; i < actual_tasks; i++) {
				if (type == PSET_THING_THREAD)
					thread_deallocate(thread_list[i]);
				else
					task_deallocate(task_list[i]);
			}
			if (size)
				kfree(addr, size);
			return (KERN_RESOURCE_SHORTAGE);
		}

		bcopy((void *) addr, (void *) newaddr, size_needed);
		kfree(addr, size);

		addr = newaddr;
		size = size_needed;
	}

	*thing_list = (void **)addr;
	*count = (unsigned int)size / sizeof(void *);

	return (KERN_SUCCESS);
}


/*
 *	processor_set_tasks:
 *
 *	List all tasks in the processor set.
 */
kern_return_t
processor_set_tasks(
	processor_set_t		pset,
	task_array_t		*task_list,
	mach_msg_type_number_t	*count)
{
	kern_return_t ret;
	mach_msg_type_number_t i;

	ret = processor_set_things(pset, (void **)task_list, count, PSET_THING_TASK);
	if (ret != KERN_SUCCESS)
		return ret;

	/* do the conversion that Mig should handle */
	for (i = 0; i < *count; i++)
		(*task_list)[i] = (task_t)convert_task_to_port((*task_list)[i]);
	return KERN_SUCCESS;
}

/*
 *	processor_set_threads:
 *
 *	List all threads in the processor set.
 */
#if defined(SECURE_KERNEL)
kern_return_t
processor_set_threads(
	__unused processor_set_t		pset,
	__unused thread_array_t		*thread_list,
	__unused mach_msg_type_number_t	*count)
{
    return KERN_FAILURE;
}
#elif defined(CONFIG_EMBEDDED)
kern_return_t
processor_set_threads(
	__unused processor_set_t		pset,
	__unused thread_array_t		*thread_list,
	__unused mach_msg_type_number_t	*count)
{
    return KERN_NOT_SUPPORTED;
}
#else
kern_return_t
processor_set_threads(
	processor_set_t		pset,
	thread_array_t		*thread_list,
	mach_msg_type_number_t	*count)
{
	kern_return_t ret;
	mach_msg_type_number_t i;

	ret = processor_set_things(pset, (void **)thread_list, count, PSET_THING_THREAD);
	if (ret != KERN_SUCCESS)
		return ret;

	/* do the conversion that Mig should handle */
	for (i = 0; i < *count; i++)
		(*thread_list)[i] = (thread_t)convert_thread_to_port((*thread_list)[i]);
	return KERN_SUCCESS;
}
#endif

/*
 *	processor_set_policy_control
 *
 *	Controls the scheduling attributes governing the processor set.
 *	Allows control of enabled policies, and per-policy base and limit
 *	priorities.
 */
kern_return_t
processor_set_policy_control(
	__unused processor_set_t		pset,
	__unused int				flavor,
	__unused processor_set_info_t	policy_info,
	__unused mach_msg_type_number_t	count,
	__unused boolean_t			change)
{
	return (KERN_INVALID_ARGUMENT);
}

#undef pset_deallocate
void pset_deallocate(processor_set_t pset);
void
pset_deallocate(
__unused processor_set_t	pset)
{
	return;
}

#undef pset_reference
void pset_reference(processor_set_t pset);
void
pset_reference(
__unused processor_set_t	pset)
{
	return;
}

pset_cluster_type_t
recommended_pset_type(thread_t thread)
{
	(void)thread;
	return PSET_SMP;
}
