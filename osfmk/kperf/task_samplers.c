/*
 * Copyright (c) 2016 Apple Computer, Inc. All rights reserved.
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

#include <kperf/task_samplers.h>
#include <kperf/context.h>
#include <kperf/buffer.h>
#include <kern/thread.h>

#include <kern/task.h>

extern boolean_t memorystatus_proc_is_dirty_unsafe(void *v);

void
kperf_task_snapshot_sample(struct kperf_task_snapshot *tksn,
                           struct kperf_context *ctx)
{
	thread_t thread;
	task_t task;

	BUF_INFO(PERF_TK_SNAP_SAMPLE | DBG_FUNC_START);

	assert(tksn != NULL);
	assert(ctx != NULL);

	thread = ctx->cur_thread;
	task = get_threadtask(thread);

	tksn->kptksn_flags = 0;
	if (task->effective_policy.tep_darwinbg) {
		tksn->kptksn_flags |= KPERF_TASK_FLAG_DARWIN_BG;
	}
	if (task->requested_policy.trp_role == TASK_FOREGROUND_APPLICATION) {
		tksn->kptksn_flags |= KPERF_TASK_FLAG_FOREGROUND;
	}
	if (task->requested_policy.trp_boosted == 1) {
		tksn->kptksn_flags |= KPERF_TASK_FLAG_BOOSTED;
	}
#if CONFIG_MEMORYSTATUS
	if (memorystatus_proc_is_dirty_unsafe(task->bsd_info)) {
		tksn->kptksn_flags |= KPERF_TASK_FLAG_DIRTY;
	}
#endif

	tksn->kptksn_suspend_count = task->suspend_count;
	tksn->kptksn_pageins = task->pageins;
	tksn->kptksn_user_time_in_terminated_threads = task->total_user_time;
	tksn->kptksn_system_time_in_terminated_threads = task->total_system_time;

	BUF_INFO(PERF_TK_SNAP_SAMPLE | DBG_FUNC_END);
}

void
kperf_task_snapshot_log(struct kperf_task_snapshot *tksn)
{
	assert(tksn != NULL);

#if defined(__LP64__)
	BUF_DATA(PERF_TK_SNAP_DATA, tksn->kptksn_flags,
	         ENCODE_UPPER_64(tksn->kptksn_suspend_count) |
	         ENCODE_LOWER_64(tksn->kptksn_pageins),
	         tksn->kptksn_user_time_in_terminated_threads,
	         tksn->kptksn_system_time_in_terminated_threads);
#else
	BUF_DATA(PERF_TK_SNAP_DATA1_32, UPPER_32(tksn->kptksn_flags),
	                                LOWER_32(tksn->kptksn_flags),
	                                tksn->kptksn_suspend_count,
	                                tksn->kptksn_pageins);
	BUF_DATA(PERF_TK_SNAP_DATA2_32, UPPER_32(tksn->kptksn_user_time_in_terminated_threads),
	                                LOWER_32(tksn->kptksn_user_time_in_terminated_threads),
	                                UPPER_32(tksn->kptksn_system_time_in_terminated_threads),
	                                LOWER_32(tksn->kptksn_system_time_in_terminated_threads));
#endif /* defined(__LP64__) */
}
