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
 *	host.c
 *
 *	Non-ipc host functions.
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/host_info.h>
#include <mach/host_special_ports.h>
#include <mach/kern_return.h>
#include <mach/machine.h>
#include <mach/port.h>
#include <mach/processor_info.h>
#include <mach/vm_param.h>
#include <mach/processor.h>
#include <mach/mach_host_server.h>
#include <mach/host_priv_server.h>
#include <mach/vm_map.h>
#include <mach/task_info.h>

#include <machine/commpage.h>
#include <machine/cpu_capabilities.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/host.h>
#include <kern/host_statistics.h>
#include <kern/ipc_host.h>
#include <kern/misc_protos.h>
#include <kern/sched.h>
#include <kern/processor.h>
#include <kern/mach_node.h>	// mach_node_port_changed()

#include <vm/vm_map.h>
#include <vm/vm_purgeable_internal.h>
#include <vm/vm_pageout.h>


#if CONFIG_ATM
#include <atm/atm_internal.h>
#endif

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#endif

#include <pexpert/pexpert.h>

host_data_t realhost;

vm_extmod_statistics_data_t host_extmod_statistics;

kern_return_t
host_processors(host_priv_t host_priv, processor_array_t * out_array, mach_msg_type_number_t * countp)
{
	processor_t processor, *tp;
	void * addr;
	unsigned int count, i;

	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_ARGUMENT);

	assert(host_priv == &realhost);

	count = processor_count;
	assert(count != 0);

	addr = kalloc((vm_size_t)(count * sizeof(mach_port_t)));
	if (addr == 0)
		return (KERN_RESOURCE_SHORTAGE);

	tp = (processor_t *)addr;
	*tp++ = processor = processor_list;

	if (count > 1) {
		simple_lock(&processor_list_lock);

		for (i = 1; i < count; i++)
			*tp++ = processor = processor->processor_list;

		simple_unlock(&processor_list_lock);
	}

	*countp = count;
	*out_array = (processor_array_t)addr;

	/* do the conversion that Mig should handle */
	tp = (processor_t *)addr;
	for (i = 0; i < count; i++)
		((mach_port_t *)tp)[i] = (mach_port_t)convert_processor_to_port(tp[i]);

	return (KERN_SUCCESS);
}

kern_return_t
host_info(host_t host, host_flavor_t flavor, host_info_t info, mach_msg_type_number_t * count)
{
	if (host == HOST_NULL)
		return (KERN_INVALID_ARGUMENT);

	switch (flavor) {
	case HOST_BASIC_INFO: {
		host_basic_info_t basic_info;
		int master_id;

		/*
		 *	Basic information about this host.
		 */
		if (*count < HOST_BASIC_INFO_OLD_COUNT)
			return (KERN_FAILURE);

		basic_info = (host_basic_info_t)info;

		basic_info->memory_size = machine_info.memory_size;
		basic_info->max_cpus = machine_info.max_cpus;
		basic_info->avail_cpus = processor_avail_count;
		master_id = master_processor->cpu_id;
		basic_info->cpu_type = slot_type(master_id);
		basic_info->cpu_subtype = slot_subtype(master_id);

		if (*count >= HOST_BASIC_INFO_COUNT) {
			basic_info->cpu_threadtype = slot_threadtype(master_id);
			basic_info->physical_cpu = machine_info.physical_cpu;
			basic_info->physical_cpu_max = machine_info.physical_cpu_max;
			basic_info->logical_cpu = machine_info.logical_cpu;
			basic_info->logical_cpu_max = machine_info.logical_cpu_max;
			basic_info->max_mem = machine_info.max_mem;

			*count = HOST_BASIC_INFO_COUNT;
		} else {
			*count = HOST_BASIC_INFO_OLD_COUNT;
		}

		return (KERN_SUCCESS);
	}

	case HOST_SCHED_INFO: {
		host_sched_info_t sched_info;
		uint32_t quantum_time;
		uint64_t quantum_ns;

		/*
		 *	Return scheduler information.
		 */
		if (*count < HOST_SCHED_INFO_COUNT)
			return (KERN_FAILURE);

		sched_info = (host_sched_info_t)info;

		quantum_time = SCHED(initial_quantum_size)(THREAD_NULL);
		absolutetime_to_nanoseconds(quantum_time, &quantum_ns);

		sched_info->min_timeout = sched_info->min_quantum = (uint32_t)(quantum_ns / 1000 / 1000);

		*count = HOST_SCHED_INFO_COUNT;

		return (KERN_SUCCESS);
	}

	case HOST_RESOURCE_SIZES: {
		/*
		 * Return sizes of kernel data structures
		 */
		if (*count < HOST_RESOURCE_SIZES_COUNT)
			return (KERN_FAILURE);

		/* XXX Fail until ledgers are implemented */
		return (KERN_INVALID_ARGUMENT);
	}

	case HOST_PRIORITY_INFO: {
		host_priority_info_t priority_info;

		if (*count < HOST_PRIORITY_INFO_COUNT)
			return (KERN_FAILURE);

		priority_info = (host_priority_info_t)info;

		priority_info->kernel_priority = MINPRI_KERNEL;
		priority_info->system_priority = MINPRI_KERNEL;
		priority_info->server_priority = MINPRI_RESERVED;
		priority_info->user_priority = BASEPRI_DEFAULT;
		priority_info->depress_priority = DEPRESSPRI;
		priority_info->idle_priority = IDLEPRI;
		priority_info->minimum_priority = MINPRI_USER;
		priority_info->maximum_priority = MAXPRI_RESERVED;

		*count = HOST_PRIORITY_INFO_COUNT;

		return (KERN_SUCCESS);
	}

	/*
	 * Gestalt for various trap facilities.
	 */
	case HOST_MACH_MSG_TRAP:
	case HOST_SEMAPHORE_TRAPS: {
		*count = 0;
		return (KERN_SUCCESS);
	}

	case HOST_CAN_HAS_DEBUGGER: {
		host_can_has_debugger_info_t can_has_debugger_info;

		if (*count < HOST_CAN_HAS_DEBUGGER_COUNT)
			return (KERN_FAILURE);

		can_has_debugger_info = (host_can_has_debugger_info_t)info;
		can_has_debugger_info->can_has_debugger = PE_i_can_has_debugger(NULL);
		*count = HOST_CAN_HAS_DEBUGGER_COUNT;

		return KERN_SUCCESS;
	}

	case HOST_VM_PURGABLE: {
		if (*count < HOST_VM_PURGABLE_COUNT)
			return (KERN_FAILURE);

		vm_purgeable_stats((vm_purgeable_info_t)info, NULL);

		*count = HOST_VM_PURGABLE_COUNT;
		return (KERN_SUCCESS);
	}

	case HOST_DEBUG_INFO_INTERNAL: {
#if DEVELOPMENT || DEBUG
		if (*count < HOST_DEBUG_INFO_INTERNAL_COUNT)
			return (KERN_FAILURE);

		host_debug_info_internal_t debug_info = (host_debug_info_internal_t)info;
		bzero(debug_info, sizeof(host_debug_info_internal_data_t));
		*count = HOST_DEBUG_INFO_INTERNAL_COUNT;

#if CONFIG_COALITIONS
		debug_info->config_coalitions = 1;
#endif
		debug_info->config_bank = 1;
#if CONFIG_ATM
		debug_info->config_atm = 1;
#endif
#if CONFIG_CSR
		debug_info->config_csr = 1;
#endif
		return (KERN_SUCCESS);
#else /* DEVELOPMENT || DEBUG */
		return (KERN_NOT_SUPPORTED);
#endif
	}

	default: return (KERN_INVALID_ARGUMENT);
	}
}

kern_return_t
host_statistics(host_t host, host_flavor_t flavor, host_info_t info, mach_msg_type_number_t * count)
{
	uint32_t i;

	if (host == HOST_NULL)
		return (KERN_INVALID_HOST);

	switch (flavor) {
	case HOST_LOAD_INFO: {
		host_load_info_t load_info;

		if (*count < HOST_LOAD_INFO_COUNT)
			return (KERN_FAILURE);

		load_info = (host_load_info_t)info;

		bcopy((char *)avenrun, (char *)load_info->avenrun, sizeof avenrun);
		bcopy((char *)mach_factor, (char *)load_info->mach_factor, sizeof mach_factor);

		*count = HOST_LOAD_INFO_COUNT;
		return (KERN_SUCCESS);
	}

	case HOST_VM_INFO: {
		processor_t processor;
		vm_statistics64_t stat;
		vm_statistics64_data_t host_vm_stat;
		vm_statistics_t stat32;
		mach_msg_type_number_t original_count;

		if (*count < HOST_VM_INFO_REV0_COUNT)
			return (KERN_FAILURE);

		processor = processor_list;
		stat = &PROCESSOR_DATA(processor, vm_stat);
		host_vm_stat = *stat;

		if (processor_count > 1) {
			simple_lock(&processor_list_lock);

			while ((processor = processor->processor_list) != NULL) {
				stat = &PROCESSOR_DATA(processor, vm_stat);

				host_vm_stat.zero_fill_count += stat->zero_fill_count;
				host_vm_stat.reactivations += stat->reactivations;
				host_vm_stat.pageins += stat->pageins;
				host_vm_stat.pageouts += stat->pageouts;
				host_vm_stat.faults += stat->faults;
				host_vm_stat.cow_faults += stat->cow_faults;
				host_vm_stat.lookups += stat->lookups;
				host_vm_stat.hits += stat->hits;
			}

			simple_unlock(&processor_list_lock);
		}

		stat32 = (vm_statistics_t)info;

		stat32->free_count = VM_STATISTICS_TRUNCATE_TO_32_BIT(vm_page_free_count + vm_page_speculative_count);
		stat32->active_count = VM_STATISTICS_TRUNCATE_TO_32_BIT(vm_page_active_count);

		if (vm_page_local_q) {
			for (i = 0; i < vm_page_local_q_count; i++) {
				struct vpl * lq;

				lq = &vm_page_local_q[i].vpl_un.vpl;

				stat32->active_count += VM_STATISTICS_TRUNCATE_TO_32_BIT(lq->vpl_count);
			}
		}
		stat32->inactive_count = VM_STATISTICS_TRUNCATE_TO_32_BIT(vm_page_inactive_count);
#if CONFIG_EMBEDDED
		stat32->wire_count = VM_STATISTICS_TRUNCATE_TO_32_BIT(vm_page_wire_count);
#else
		stat32->wire_count = VM_STATISTICS_TRUNCATE_TO_32_BIT(vm_page_wire_count + vm_page_throttled_count + vm_lopage_free_count);
#endif
		stat32->zero_fill_count = VM_STATISTICS_TRUNCATE_TO_32_BIT(host_vm_stat.zero_fill_count);
		stat32->reactivations = VM_STATISTICS_TRUNCATE_TO_32_BIT(host_vm_stat.reactivations);
		stat32->pageins = VM_STATISTICS_TRUNCATE_TO_32_BIT(host_vm_stat.pageins);
		stat32->pageouts = VM_STATISTICS_TRUNCATE_TO_32_BIT(host_vm_stat.pageouts);
		stat32->faults = VM_STATISTICS_TRUNCATE_TO_32_BIT(host_vm_stat.faults);
		stat32->cow_faults = VM_STATISTICS_TRUNCATE_TO_32_BIT(host_vm_stat.cow_faults);
		stat32->lookups = VM_STATISTICS_TRUNCATE_TO_32_BIT(host_vm_stat.lookups);
		stat32->hits = VM_STATISTICS_TRUNCATE_TO_32_BIT(host_vm_stat.hits);

		/*
		 * Fill in extra info added in later revisions of the
		 * vm_statistics data structure.  Fill in only what can fit
		 * in the data structure the caller gave us !
		 */
		original_count = *count;
		*count = HOST_VM_INFO_REV0_COUNT; /* rev0 already filled in */
		if (original_count >= HOST_VM_INFO_REV1_COUNT) {
			/* rev1 added "purgeable" info */
			stat32->purgeable_count = VM_STATISTICS_TRUNCATE_TO_32_BIT(vm_page_purgeable_count);
			stat32->purges = VM_STATISTICS_TRUNCATE_TO_32_BIT(vm_page_purged_count);
			*count = HOST_VM_INFO_REV1_COUNT;
		}

		if (original_count >= HOST_VM_INFO_REV2_COUNT) {
			/* rev2 added "speculative" info */
			stat32->speculative_count = VM_STATISTICS_TRUNCATE_TO_32_BIT(vm_page_speculative_count);
			*count = HOST_VM_INFO_REV2_COUNT;
		}

		/* rev3 changed some of the fields to be 64-bit*/

		return (KERN_SUCCESS);
	}

	case HOST_CPU_LOAD_INFO: {
		processor_t processor;
		host_cpu_load_info_t cpu_load_info;

		if (*count < HOST_CPU_LOAD_INFO_COUNT)
			return (KERN_FAILURE);

#define GET_TICKS_VALUE(state, ticks)                                                      \
	MACRO_BEGIN cpu_load_info->cpu_ticks[(state)] += (uint32_t)(ticks / hz_tick_interval); \
	MACRO_END
#define GET_TICKS_VALUE_FROM_TIMER(processor, state, timer)                            \
	MACRO_BEGIN GET_TICKS_VALUE(state, timer_grab(&PROCESSOR_DATA(processor, timer))); \
	MACRO_END

		cpu_load_info = (host_cpu_load_info_t)info;
		cpu_load_info->cpu_ticks[CPU_STATE_USER] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_SYSTEM] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_IDLE] = 0;
		cpu_load_info->cpu_ticks[CPU_STATE_NICE] = 0;

		simple_lock(&processor_list_lock);

		for (processor = processor_list; processor != NULL; processor = processor->processor_list) {
			timer_t idle_state;
			uint64_t idle_time_snapshot1, idle_time_snapshot2;
			uint64_t idle_time_tstamp1, idle_time_tstamp2;

			/* See discussion in processor_info(PROCESSOR_CPU_LOAD_INFO) */

			GET_TICKS_VALUE_FROM_TIMER(processor, CPU_STATE_USER, user_state);
			if (precise_user_kernel_time) {
				GET_TICKS_VALUE_FROM_TIMER(processor, CPU_STATE_SYSTEM, system_state);
			} else {
				/* system_state may represent either sys or user */
				GET_TICKS_VALUE_FROM_TIMER(processor, CPU_STATE_USER, system_state);
			}

			idle_state = &PROCESSOR_DATA(processor, idle_state);
			idle_time_snapshot1 = timer_grab(idle_state);
			idle_time_tstamp1 = idle_state->tstamp;

			if (PROCESSOR_DATA(processor, current_state) != idle_state) {
				/* Processor is non-idle, so idle timer should be accurate */
				GET_TICKS_VALUE_FROM_TIMER(processor, CPU_STATE_IDLE, idle_state);
			} else if ((idle_time_snapshot1 != (idle_time_snapshot2 = timer_grab(idle_state))) ||
			           (idle_time_tstamp1 != (idle_time_tstamp2 = idle_state->tstamp))) {
				/* Idle timer is being updated concurrently, second stamp is good enough */
				GET_TICKS_VALUE(CPU_STATE_IDLE, idle_time_snapshot2);
			} else {
				/*
				 * Idle timer may be very stale. Fortunately we have established
				 * that idle_time_snapshot1 and idle_time_tstamp1 are unchanging
				 */
				idle_time_snapshot1 += mach_absolute_time() - idle_time_tstamp1;

				GET_TICKS_VALUE(CPU_STATE_IDLE, idle_time_snapshot1);
			}
		}
		simple_unlock(&processor_list_lock);

		*count = HOST_CPU_LOAD_INFO_COUNT;

		return (KERN_SUCCESS);
	}

	case HOST_EXPIRED_TASK_INFO: {
		if (*count < TASK_POWER_INFO_COUNT) {
			return (KERN_FAILURE);
		}

		task_power_info_t tinfo1 = (task_power_info_t)info;
		task_power_info_v2_t tinfo2 = (task_power_info_v2_t)info;

		tinfo1->task_interrupt_wakeups = dead_task_statistics.task_interrupt_wakeups;
		tinfo1->task_platform_idle_wakeups = dead_task_statistics.task_platform_idle_wakeups;

		tinfo1->task_timer_wakeups_bin_1 = dead_task_statistics.task_timer_wakeups_bin_1;

		tinfo1->task_timer_wakeups_bin_2 = dead_task_statistics.task_timer_wakeups_bin_2;

		tinfo1->total_user = dead_task_statistics.total_user_time;
		tinfo1->total_system = dead_task_statistics.total_system_time;
		if (*count < TASK_POWER_INFO_V2_COUNT) {
			*count = TASK_POWER_INFO_COUNT;
		}
		else if (*count >= TASK_POWER_INFO_V2_COUNT) {
			tinfo2->gpu_energy.task_gpu_utilisation = dead_task_statistics.task_gpu_ns;
#if defined(__arm__) || defined(__arm64__)
			tinfo2->task_energy = dead_task_statistics.task_energy;
			tinfo2->task_ptime = dead_task_statistics.total_ptime;
			tinfo2->task_pset_switches = dead_task_statistics.total_pset_switches;
#endif
			*count = TASK_POWER_INFO_V2_COUNT;
		}

		return (KERN_SUCCESS);
	}
	default: return (KERN_INVALID_ARGUMENT);
	}
}

extern uint32_t c_segment_pages_compressed;

kern_return_t
host_statistics64(host_t host, host_flavor_t flavor, host_info64_t info, mach_msg_type_number_t * count)
{
	uint32_t i;

	if (host == HOST_NULL)
		return (KERN_INVALID_HOST);

	switch (flavor) {
	case HOST_VM_INFO64: /* We were asked to get vm_statistics64 */
	{
		processor_t processor;
		vm_statistics64_t stat;
		vm_statistics64_data_t host_vm_stat;
		mach_msg_type_number_t original_count;
		unsigned int local_q_internal_count;
		unsigned int local_q_external_count;

		if (*count < HOST_VM_INFO64_REV0_COUNT)
			return (KERN_FAILURE);

		processor = processor_list;
		stat = &PROCESSOR_DATA(processor, vm_stat);
		host_vm_stat = *stat;

		if (processor_count > 1) {
			simple_lock(&processor_list_lock);

			while ((processor = processor->processor_list) != NULL) {
				stat = &PROCESSOR_DATA(processor, vm_stat);

				host_vm_stat.zero_fill_count += stat->zero_fill_count;
				host_vm_stat.reactivations += stat->reactivations;
				host_vm_stat.pageins += stat->pageins;
				host_vm_stat.pageouts += stat->pageouts;
				host_vm_stat.faults += stat->faults;
				host_vm_stat.cow_faults += stat->cow_faults;
				host_vm_stat.lookups += stat->lookups;
				host_vm_stat.hits += stat->hits;
				host_vm_stat.compressions += stat->compressions;
				host_vm_stat.decompressions += stat->decompressions;
				host_vm_stat.swapins += stat->swapins;
				host_vm_stat.swapouts += stat->swapouts;
			}

			simple_unlock(&processor_list_lock);
		}

		stat = (vm_statistics64_t)info;

		stat->free_count = vm_page_free_count + vm_page_speculative_count;
		stat->active_count = vm_page_active_count;

		local_q_internal_count = 0;
		local_q_external_count = 0;
		if (vm_page_local_q) {
			for (i = 0; i < vm_page_local_q_count; i++) {
				struct vpl * lq;

				lq = &vm_page_local_q[i].vpl_un.vpl;

				stat->active_count += lq->vpl_count;
				local_q_internal_count += lq->vpl_internal_count;
				local_q_external_count += lq->vpl_external_count;
			}
		}
		stat->inactive_count = vm_page_inactive_count;
#if CONFIG_EMBEDDED
		stat->wire_count = vm_page_wire_count;
#else
		stat->wire_count = vm_page_wire_count + vm_page_throttled_count + vm_lopage_free_count;
#endif
		stat->zero_fill_count = host_vm_stat.zero_fill_count;
		stat->reactivations = host_vm_stat.reactivations;
		stat->pageins = host_vm_stat.pageins;
		stat->pageouts = host_vm_stat.pageouts;
		stat->faults = host_vm_stat.faults;
		stat->cow_faults = host_vm_stat.cow_faults;
		stat->lookups = host_vm_stat.lookups;
		stat->hits = host_vm_stat.hits;

		stat->purgeable_count = vm_page_purgeable_count;
		stat->purges = vm_page_purged_count;

		stat->speculative_count = vm_page_speculative_count;

		/*
		 * Fill in extra info added in later revisions of the
		 * vm_statistics data structure.  Fill in only what can fit
		 * in the data structure the caller gave us !
		 */
		original_count = *count;
		*count = HOST_VM_INFO64_REV0_COUNT; /* rev0 already filled in */
		if (original_count >= HOST_VM_INFO64_REV1_COUNT) {
			/* rev1 added "throttled count" */
			stat->throttled_count = vm_page_throttled_count;
			/* rev1 added "compression" info */
			stat->compressor_page_count = VM_PAGE_COMPRESSOR_COUNT;
			stat->compressions = host_vm_stat.compressions;
			stat->decompressions = host_vm_stat.decompressions;
			stat->swapins = host_vm_stat.swapins;
			stat->swapouts = host_vm_stat.swapouts;
			/* rev1 added:
			 * "external page count"
			 * "anonymous page count"
			 * "total # of pages (uncompressed) held in the compressor"
			 */
			stat->external_page_count = (vm_page_pageable_external_count + local_q_external_count);
			stat->internal_page_count = (vm_page_pageable_internal_count + local_q_internal_count);
			stat->total_uncompressed_pages_in_compressor = c_segment_pages_compressed;
			*count = HOST_VM_INFO64_REV1_COUNT;
		}

		return (KERN_SUCCESS);
	}

	case HOST_EXTMOD_INFO64: /* We were asked to get vm_statistics64 */
	{
		vm_extmod_statistics_t out_extmod_statistics;

		if (*count < HOST_EXTMOD_INFO64_COUNT)
			return (KERN_FAILURE);

		out_extmod_statistics = (vm_extmod_statistics_t)info;
		*out_extmod_statistics = host_extmod_statistics;

		*count = HOST_EXTMOD_INFO64_COUNT;

		return (KERN_SUCCESS);
	}

	default: /* If we didn't recognize the flavor, send to host_statistics */
		return (host_statistics(host, flavor, (host_info_t)info, count));
	}
}

/*
 * Get host statistics that require privilege.
 * None for now, just call the un-privileged version.
 */
kern_return_t
host_priv_statistics(host_priv_t host_priv, host_flavor_t flavor, host_info_t info, mach_msg_type_number_t * count)
{
	return (host_statistics((host_t)host_priv, flavor, info, count));
}

kern_return_t
set_sched_stats_active(boolean_t active)
{
	sched_stats_active = active;
	return (KERN_SUCCESS);
}

kern_return_t
get_sched_statistics(struct _processor_statistics_np * out, uint32_t * count)
{
	processor_t processor;

	if (!sched_stats_active) {
		return (KERN_FAILURE);
	}

	simple_lock(&processor_list_lock);

	if (*count < (processor_count + 1) * sizeof(struct _processor_statistics_np)) { /* One for RT */
		simple_unlock(&processor_list_lock);
		return (KERN_FAILURE);
	}

	processor = processor_list;
	while (processor) {
		struct processor_sched_statistics * stats = &processor->processor_data.sched_stats;

		out->ps_cpuid = processor->cpu_id;
		out->ps_csw_count = stats->csw_count;
		out->ps_preempt_count = stats->preempt_count;
		out->ps_preempted_rt_count = stats->preempted_rt_count;
		out->ps_preempted_by_rt_count = stats->preempted_by_rt_count;
		out->ps_rt_sched_count = stats->rt_sched_count;
		out->ps_interrupt_count = stats->interrupt_count;
		out->ps_ipi_count = stats->ipi_count;
		out->ps_timer_pop_count = stats->timer_pop_count;
		out->ps_runq_count_sum = SCHED(processor_runq_stats_count_sum)(processor);
		out->ps_idle_transitions = stats->idle_transitions;
		out->ps_quantum_timer_expirations = stats->quantum_timer_expirations;

		out++;
		processor = processor->processor_list;
	}

	*count = (uint32_t)(processor_count * sizeof(struct _processor_statistics_np));

	simple_unlock(&processor_list_lock);

	/* And include RT Queue information */
	bzero(out, sizeof(*out));
	out->ps_cpuid = (-1);
	out->ps_runq_count_sum = SCHED(rt_runq_count_sum)();
	out++;
	*count += (uint32_t)sizeof(struct _processor_statistics_np);

	return (KERN_SUCCESS);
}

kern_return_t
host_page_size(host_t host, vm_size_t * out_page_size)
{
	if (host == HOST_NULL)
		return (KERN_INVALID_ARGUMENT);

	*out_page_size = PAGE_SIZE;

	return (KERN_SUCCESS);
}

/*
 *	Return kernel version string (more than you ever
 *	wanted to know about what version of the kernel this is).
 */
extern char version[];

kern_return_t
host_kernel_version(host_t host, kernel_version_t out_version)
{
	if (host == HOST_NULL)
		return (KERN_INVALID_ARGUMENT);

	(void)strncpy(out_version, version, sizeof(kernel_version_t));

	return (KERN_SUCCESS);
}

/*
 *	host_processor_sets:
 *
 *	List all processor sets on the host.
 */
kern_return_t
host_processor_sets(host_priv_t host_priv, processor_set_name_array_t * pset_list, mach_msg_type_number_t * count)
{
	void * addr;

	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_ARGUMENT);

	/*
	 *	Allocate memory.  Can be pageable because it won't be
	 *	touched while holding a lock.
	 */

	addr = kalloc((vm_size_t)sizeof(mach_port_t));
	if (addr == 0)
		return (KERN_RESOURCE_SHORTAGE);

	/* do the conversion that Mig should handle */
	*((ipc_port_t *)addr) = convert_pset_name_to_port(&pset0);

	*pset_list = (processor_set_array_t)addr;
	*count = 1;

	return (KERN_SUCCESS);
}

/*
 *	host_processor_set_priv:
 *
 *	Return control port for given processor set.
 */
kern_return_t
host_processor_set_priv(host_priv_t host_priv, processor_set_t pset_name, processor_set_t * pset)
{
	if (host_priv == HOST_PRIV_NULL || pset_name == PROCESSOR_SET_NULL) {
		*pset = PROCESSOR_SET_NULL;

		return (KERN_INVALID_ARGUMENT);
	}

	*pset = pset_name;

	return (KERN_SUCCESS);
}

/*
 *	host_processor_info
 *
 *	Return info about the processors on this host.  It will return
 *	the number of processors, and the specific type of info requested
 *	in an OOL array.
 */
kern_return_t
host_processor_info(host_t host,
                    processor_flavor_t flavor,
                    natural_t * out_pcount,
                    processor_info_array_t * out_array,
                    mach_msg_type_number_t * out_array_count)
{
	kern_return_t result;
	processor_t processor;
	host_t thost;
	processor_info_t info;
	unsigned int icount, tcount;
	unsigned int pcount, i;
	vm_offset_t addr;
	vm_size_t size, needed;
	vm_map_copy_t copy;

	if (host == HOST_NULL)
		return (KERN_INVALID_ARGUMENT);

	result = processor_info_count(flavor, &icount);
	if (result != KERN_SUCCESS)
		return (result);

	pcount = processor_count;
	assert(pcount != 0);

	needed = pcount * icount * sizeof(natural_t);
	size = vm_map_round_page(needed, VM_MAP_PAGE_MASK(ipc_kernel_map));
	result = kmem_alloc(ipc_kernel_map, &addr, size, VM_KERN_MEMORY_IPC);
	if (result != KERN_SUCCESS)
		return (KERN_RESOURCE_SHORTAGE);

	info = (processor_info_t)addr;
	processor = processor_list;
	tcount = icount;

	result = processor_info(processor, flavor, &thost, info, &tcount);
	if (result != KERN_SUCCESS) {
		kmem_free(ipc_kernel_map, addr, size);
		return (result);
	}

	if (pcount > 1) {
		for (i = 1; i < pcount; i++) {
			simple_lock(&processor_list_lock);
			processor = processor->processor_list;
			simple_unlock(&processor_list_lock);

			info += icount;
			tcount = icount;
			result = processor_info(processor, flavor, &thost, info, &tcount);
			if (result != KERN_SUCCESS) {
				kmem_free(ipc_kernel_map, addr, size);
				return (result);
			}
		}
	}

	if (size != needed)
		bzero((char *)addr + needed, size - needed);

	result = vm_map_unwire(ipc_kernel_map, vm_map_trunc_page(addr, VM_MAP_PAGE_MASK(ipc_kernel_map)),
	                       vm_map_round_page(addr + size, VM_MAP_PAGE_MASK(ipc_kernel_map)), FALSE);
	assert(result == KERN_SUCCESS);
	result = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)addr, (vm_map_size_t)needed, TRUE, &copy);
	assert(result == KERN_SUCCESS);

	*out_pcount = pcount;
	*out_array = (processor_info_array_t)copy;
	*out_array_count = pcount * icount;

	return (KERN_SUCCESS);
}

/*
 *      Kernel interface for setting a special port.
 */
kern_return_t
kernel_set_special_port(host_priv_t host_priv, int id, ipc_port_t port)
{
	ipc_port_t old_port;

#if !MACH_FLIPC
    if (id == HOST_NODE_PORT)
        return (KERN_NOT_SUPPORTED);
#endif

	host_lock(host_priv);
	old_port = host_priv->special[id];
	host_priv->special[id] = port;
	host_unlock(host_priv);

#if MACH_FLIPC
    if (id == HOST_NODE_PORT)
		mach_node_port_changed();
#endif

	if (IP_VALID(old_port))
		ipc_port_release_send(old_port);
	return (KERN_SUCCESS);
}

/*
 *      Kernel interface for retrieving a special port.
 */
kern_return_t
kernel_get_special_port(host_priv_t host_priv, int id, ipc_port_t * portp)
{
        host_lock(host_priv);
        *portp = host_priv->special[id];
        host_unlock(host_priv);
        return (KERN_SUCCESS);
}

/*
 *      User interface for setting a special port.
 *
 *      Only permits the user to set a user-owned special port
 *      ID, rejecting a kernel-owned special port ID.
 *
 *      A special kernel port cannot be set up using this
 *      routine; use kernel_set_special_port() instead.
 */
kern_return_t
host_set_special_port(host_priv_t host_priv, int id, ipc_port_t port)
{
	if (host_priv == HOST_PRIV_NULL || id <= HOST_MAX_SPECIAL_KERNEL_PORT || id > HOST_MAX_SPECIAL_PORT)
		return (KERN_INVALID_ARGUMENT);

#if CONFIG_MACF
	if (mac_task_check_set_host_special_port(current_task(), id, port) != 0)
		return (KERN_NO_ACCESS);
#endif

	return (kernel_set_special_port(host_priv, id, port));
}

/*
 *      User interface for retrieving a special port.
 *
 *      Note that there is nothing to prevent a user special
 *      port from disappearing after it has been discovered by
 *      the caller; thus, using a special port can always result
 *      in a "port not valid" error.
 */

kern_return_t
host_get_special_port(host_priv_t host_priv, __unused int node, int id, ipc_port_t * portp)
{
	ipc_port_t port;

	if (host_priv == HOST_PRIV_NULL || id == HOST_SECURITY_PORT || id > HOST_MAX_SPECIAL_PORT || id < 0)
		return (KERN_INVALID_ARGUMENT);

	host_lock(host_priv);
	port = realhost.special[id];
	*portp = ipc_port_copy_send(port);
	host_unlock(host_priv);

	return (KERN_SUCCESS);
}

/*
 *	host_get_io_master
 *
 *	Return the IO master access port for this host.
 */
kern_return_t
host_get_io_master(host_t host, io_master_t * io_masterp)
{
	if (host == HOST_NULL)
		return (KERN_INVALID_ARGUMENT);

	return (host_get_io_master_port(host_priv_self(), io_masterp));
}

host_t
host_self(void)
{
	return (&realhost);
}

host_priv_t
host_priv_self(void)
{
	return (&realhost);
}

host_security_t
host_security_self(void)
{
	return (&realhost);
}

kern_return_t
host_set_atm_diagnostic_flag(host_priv_t host_priv, uint32_t diagnostic_flag)
{
	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_ARGUMENT);

	assert(host_priv == &realhost);

#if CONFIG_ATM
	return (atm_set_diagnostic_config(diagnostic_flag));
#else
	(void)diagnostic_flag;
	return (KERN_NOT_SUPPORTED);
#endif
}

kern_return_t
host_set_multiuser_config_flags(host_priv_t host_priv, uint32_t multiuser_config)
{
#if CONFIG_EMBEDDED
	if (host_priv == HOST_PRIV_NULL)
		return (KERN_INVALID_ARGUMENT);

	assert(host_priv == &realhost);

	/*
	 * Always enforce that the multiuser bit is set
	 * if a value is written to the commpage word.
	 */
	commpage_update_multiuser_config(multiuser_config | kIsMultiUserDevice);
	return (KERN_SUCCESS);
#else
	(void)host_priv;
	(void)multiuser_config;
	return (KERN_NOT_SUPPORTED);
#endif
}
