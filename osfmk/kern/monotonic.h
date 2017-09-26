/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
#ifndef KERN_MONOTONIC_H
#define KERN_MONOTONIC_H

#include <stdbool.h>
#include <stdint.h>

extern bool mt_debug;
extern _Atomic uint64_t mt_pmis;
extern _Atomic uint64_t mt_retrograde;

void mt_fixed_counts(uint64_t *counts);
void mt_cur_thread_fixed_counts(uint64_t *counts);
void mt_cur_task_fixed_counts(uint64_t *counts);
uint64_t mt_cur_cpu_instrs(void);
uint64_t mt_cur_cpu_cycles(void);
uint64_t mt_cur_thread_instrs(void);
uint64_t mt_cur_thread_cycles(void);

#if MACH_KERNEL_PRIVATE

#include <kern/thread.h>
#include <kern/task.h>
#include <stdbool.h>

#if defined(__arm__) || defined(__arm64__)
#include <arm/cpu_data_internal.h>
#elif defined(__x86_64__)
#include <i386/cpu_data.h>
#else /* !defined(__arm__) && !defined(__arm64__) && !defined(__x86_64__) */
#error unsupported architecture
#endif /* !defined(__arm__) && !defined(__arm64__) && !defined(__x86_64__) */

void mt_init(void);
void mt_update_fixed_counts(void);
void mt_update_task(task_t task, thread_t thread);
bool mt_update_thread(thread_t thread);
int mt_fixed_thread_counts(thread_t thread, uint64_t *counts_out);
int mt_fixed_task_counts(task_t task, uint64_t *counts_out);

/*
 * Called when a thread is switching off-core or expires its quantum.
 */
void mt_sched_update(thread_t thread);

/*
 * Called when a thread is terminating to save its counters into the task.  The
 * task lock must be held and the thread should be removed from the task's
 * thread list in that same critical section.
 */
void mt_terminate_update(task_t task, thread_t thread);

/*
 * Called when a core receives a PMI.
 */
void mt_cpu_pmi(cpu_data_t *cpu, uint64_t pmsr);
uint64_t mt_cpu_update_count(cpu_data_t *cpu, unsigned int ctr);

/*
 * Called when a core is idling and exiting from idle.
 */
void mt_cpu_idle(cpu_data_t *cpu);
void mt_cpu_run(cpu_data_t *cpu);

/*
 * Called when a core is shutting down or powering up.
 */
void mt_cpu_down(cpu_data_t *cpu);
void mt_cpu_up(cpu_data_t *cpu);

/*
 * Called while single-threaded when the system is going to sleep and waking up.
 */
void mt_sleep(void);
void mt_wake(void);

/*
 * Private API for the performance controller callout.
 */
void mt_perfcontrol(uint64_t *instrs, uint64_t *cycles);

/*
 * Private API for stackshot.
 */
void mt_stackshot_thread(thread_t thread, uint64_t *instrs, uint64_t *cycles);
void mt_stackshot_task(task_t task, uint64_t *instrs, uint64_t *cycles);

#endif /* MACH_KERNEL_PRIVATE */

#endif /* !defined(KERN_MONOTONIC_H) */
