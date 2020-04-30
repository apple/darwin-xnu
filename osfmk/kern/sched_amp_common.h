/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#ifndef _KERN_SCHED_AMP_COMMON_H_
#define _KERN_SCHED_AMP_COMMON_H_

#if __AMP__

/* Routine to initialize processor sets on AMP platforms */
void sched_amp_init(void);

/*
 * The AMP scheduler uses spill/steal/rebalance logic to make sure the most appropriate threads
 * are scheduled on the P/E clusters. Here are the definitions of those terms:
 *
 * - Spill:     Spill threads from an overcommited P-cluster onto the E-cluster. This is needed to make sure
 *              that high priority P-recommended threads experience low scheduling latency in the presence of
 *              lots of P-recommended threads.
 *
 * - Steal:     From an E-core, steal a thread from the P-cluster to provide low scheduling latency for
 *              P-recommended threads.
 *
 * - Rebalance: Once a P-core goes idle, check if the E-cores are running any P-recommended threads and
 *              bring it back to run on its recommended cluster type.
 */

/* Spill logic */
int sched_amp_spill_threshold(processor_set_t pset);
void pset_signal_spill(processor_set_t pset, int spilled_thread_priority);
bool pset_should_accept_spilled_thread(processor_set_t pset, int spilled_thread_priority);
bool should_spill_to_ecores(processor_set_t nset, thread_t thread);
void sched_amp_check_spill(processor_set_t pset, thread_t thread);

/* Steal logic */
int sched_amp_steal_threshold(processor_set_t pset, bool spill_pending);
bool sched_amp_steal_thread_enabled(processor_set_t pset);

/* Rebalance logic */
void sched_amp_balance(processor_t cprocessor, processor_set_t cpset);

/* IPI policy */
sched_ipi_type_t sched_amp_ipi_policy(processor_t dst, thread_t thread, boolean_t dst_idle, sched_ipi_event_t event);

/* AMP realtime runq management */
rt_queue_t sched_amp_rt_runq(processor_set_t pset);
void sched_amp_rt_init(processor_set_t pset);
void sched_amp_rt_queue_shutdown(processor_t processor);
void sched_amp_rt_runq_scan(sched_update_scan_context_t scan_context);
int64_t sched_amp_rt_runq_count_sum(void);

uint32_t sched_amp_qos_max_parallelism(int qos, uint64_t options);
void sched_amp_bounce_thread_group_from_ecores(processor_set_t pset, struct thread_group *tg);

#endif /* __AMP__ */

#endif /* _KERN_SCHED_AMP_COMMON_H_ */
