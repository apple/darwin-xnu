/*
 * Copyright (c) 2014 Apple Computer, Inc. All rights reserved.
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

#ifndef _WORKQUEUE_INTERNAL_H_
#define _WORKQUEUE_INTERNAL_H_

// Sometimes something gets passed a bucket number and we need a way to express
// that it's actually the event manager.  Use the (0)th bucket for that.
#define WORKQ_THREAD_QOS_MIN        (THREAD_QOS_MAINTENANCE)
#define WORKQ_THREAD_QOS_MAX        (THREAD_QOS_LAST)
#define WORKQ_THREAD_QOS_CLEANUP    (THREAD_QOS_LEGACY)
#define WORKQ_THREAD_QOS_ABOVEUI    (THREAD_QOS_LAST)
#define WORKQ_THREAD_QOS_MANAGER    (THREAD_QOS_LAST + 1) // outside of MIN/MAX

#define WORKQ_NUM_QOS_BUCKETS       (WORKQ_THREAD_QOS_MAX - 1)  // MT/BG shared
#define WORKQ_NUM_BUCKETS           (WORKQ_NUM_QOS_BUCKETS + 1) // + mgr

/* These definitions are only available to the kext, to avoid bleeding
 * constants and types across the boundary to the userspace library.
 */
#ifdef KERNEL
#pragma mark wq structs

/* These defines come from kern/thread.h but are XNU_KERNEL_PRIVATE so do not get
 * exported to kernel extensions.
 */
#define SCHED_CALL_BLOCK 0x1
#define SCHED_CALL_UNBLOCK 0x2

/* old workq priority scheme */

#define WORKQUEUE_HIGH_PRIOQUEUE    0       /* high priority queue */
#define WORKQUEUE_DEFAULT_PRIOQUEUE 1       /* default priority queue */
#define WORKQUEUE_LOW_PRIOQUEUE     2       /* low priority queue */
#define WORKQUEUE_BG_PRIOQUEUE      3       /* background priority queue */

/* wq_max_constrained_threads = max(64, N_CPU * WORKQUEUE_CONSTRAINED_FACTOR)
 * This used to be WORKQ_NUM_BUCKETS + 1 when NUM_BUCKETS was 4, yielding
 * N_CPU * 5. When NUM_BUCKETS changed, we decided that the limit should
 * not change. So the factor is now always 5.
 */
#define WORKQUEUE_CONSTRAINED_FACTOR 5

#if BSD_KERNEL_PRIVATE
#include <kern/priority_queue.h>
#include <kern/thread_call.h>
#include <kern/turnstile.h>
#include <mach/kern_return.h>
#include <sys/queue.h>
#include <sys/kernel_types.h>

/* struct uthread::uu_workq_flags */
#define UT_WORKQ_NEW                   0x01 /* First return to userspace */
#define UT_WORKQ_RUNNING               0x02 /* On thrunlist, not parked. */
#define UT_WORKQ_DYING                 0x04 /* Thread is being killed */
#define UT_WORKQ_OVERCOMMIT            0x08 /* Overcommit thread. */
#define UT_WORKQ_OUTSIDE_QOS           0x10 /* Thread should avoid send QoS changes to kernel */
#define UT_WORKQ_IDLE_CLEANUP          0x20 /* Thread is removing its voucher or stack */
#define UT_WORKQ_EARLY_BOUND           0x40 /* Thread has been bound early */
#define UT_WORKQ_CPUPERCENT            0x80 /* Thread has CPU percent policy active */

typedef union workq_threadreq_param_s {
	struct {
		uint16_t trp_flags;
		uint8_t trp_pri;
		uint8_t trp_pol;
		uint32_t trp_cpupercent: 8,
		    trp_refillms: 24;
	};
	uint64_t trp_value;
} workq_threadreq_param_t;

#define TRP_PRIORITY            0x1
#define TRP_POLICY                      0x2
#define TRP_CPUPERCENT          0x4
#define TRP_RELEASED            0x8000

typedef struct workq_threadreq_s {
	union {
		struct priority_queue_entry tr_entry;
		thread_t tr_binding_thread;
	};
	uint32_t     tr_flags;
	uint8_t      tr_state;
	thread_qos_t tr_qos;
	uint16_t     tr_count;
} *workq_threadreq_t;

TAILQ_HEAD(threadreq_head, workq_threadreq_s);

#define TR_STATE_IDLE           0  /* request isn't in flight       */
#define TR_STATE_NEW            1  /* request is being initiated    */
#define TR_STATE_QUEUED         2  /* request is being queued       */
#define TR_STATE_BINDING        4  /* request is preposted for bind */

#define TR_FLAG_KEVENT                  0x01
#define TR_FLAG_WORKLOOP                0x02
#define TR_FLAG_OVERCOMMIT              0x04
#define TR_FLAG_WL_PARAMS               0x08
#define TR_FLAG_WL_OUTSIDE_QOS  0x10

#if defined(__LP64__)
typedef unsigned __int128 wq_thactive_t;
#else
typedef uint64_t wq_thactive_t;
#endif

typedef enum {
	WQ_EXITING                  = 0x0001,
	WQ_PROC_SUSPENDED           = 0x0002,
	WQ_DEATH_CALL_SCHEDULED     = 0x0004,

	WQ_DELAYED_CALL_SCHEDULED   = 0x0010,
	WQ_DELAYED_CALL_PENDED      = 0x0020,
	WQ_IMMEDIATE_CALL_SCHEDULED = 0x0040,
	WQ_IMMEDIATE_CALL_PENDED    = 0x0080,
} workq_state_flags_t;

TAILQ_HEAD(workq_uthread_head, uthread);

struct workqueue {
	thread_call_t   wq_delayed_call;
	thread_call_t   wq_immediate_call;
	thread_call_t   wq_death_call;
	struct turnstile *wq_turnstile;

	lck_spin_t      wq_lock;

	uint64_t        wq_thread_call_last_run;
	struct os_refcnt wq_refcnt;
	workq_state_flags_t _Atomic wq_flags;
	uint32_t        wq_fulfilled;
	uint32_t        wq_creations;
	uint32_t        wq_timer_interval;
	uint32_t        wq_event_manager_priority;
	uint32_t        wq_reqcount;  /* number of elements on the wq_*_reqlists */
	uint16_t        wq_thdying_count;
	uint16_t        wq_threads_scheduled;
	uint16_t        wq_constrained_threads_scheduled;
	uint16_t        wq_nthreads;
	uint16_t        wq_thidlecount;
	uint16_t        wq_thscheduled_count[WORKQ_NUM_BUCKETS]; // incl. manager

	_Atomic wq_thactive_t wq_thactive;
	_Atomic uint64_t wq_lastblocked_ts[WORKQ_NUM_QOS_BUCKETS];

	struct proc    *wq_proc;
	struct uthread *wq_creator;
	thread_t wq_turnstile_updater; // thread doing a turnstile_update_ineritor
	struct workq_uthread_head wq_thrunlist;
	struct workq_uthread_head wq_thnewlist;
	struct workq_uthread_head wq_thidlelist;

	struct priority_queue wq_overcommit_queue;
	struct priority_queue wq_constrained_queue;
	struct priority_queue wq_special_queue;
	workq_threadreq_t wq_event_manager_threadreq;
};

static_assert(offsetof(struct workqueue, wq_lock) >= sizeof(struct queue_entry),
    "Make sure workq_deallocate_enqueue can cast the workqueue");

#define WORKQUEUE_MAXTHREADS            512
#define WQ_STALLED_WINDOW_USECS         200
#define WQ_REDUCE_POOL_WINDOW_USECS     5000000
#define WQ_MAX_TIMER_INTERVAL_USECS     50000

#pragma mark definitions

struct kqrequest;
uint32_t _get_pwq_state_kdp(proc_t p);

void workq_exit(struct proc *p);
void workq_mark_exiting(struct proc *p);

bool workq_is_exiting(struct proc *p);

struct turnstile *workq_turnstile(struct proc *p);

void workq_thread_set_max_qos(struct proc *p, struct kqrequest *kqr);

void workq_thread_terminate(struct proc *p, struct uthread *uth);

#define WORKQ_THREADREQ_SET_AST_ON_FAILURE  0x01
#define WORKQ_THREADREQ_ATTEMPT_REBIND      0x02
#define WORKQ_THREADREQ_CAN_CREATE_THREADS  0x04
#define WORKQ_THREADREQ_CREATOR_TRANSFER    0x08
#define WORKQ_THREADREQ_CREATOR_SYNC_UPDATE 0x10

// called with the kq req lock held
bool workq_kern_threadreq_initiate(struct proc *p, struct kqrequest *kqr,
    struct turnstile *ts, thread_qos_t qos, int flags);

// called with the kq req lock held
void workq_kern_threadreq_modify(struct proc *p, struct kqrequest *kqr,
    thread_qos_t qos, int flags);

// called with the kq req lock held
void workq_kern_threadreq_update_inheritor(struct proc *p, struct kqrequest *kqr,
    thread_t owner, struct turnstile *ts, turnstile_update_flags_t flags);

void workq_kern_threadreq_lock(struct proc *p);
void workq_kern_threadreq_unlock(struct proc *p);

void workq_kern_threadreq_redrive(struct proc *p, int flags);

enum workq_set_self_flags {
	WORKQ_SET_SELF_QOS_FLAG = 0x1,
	WORKQ_SET_SELF_VOUCHER_FLAG = 0x2,
	WORKQ_SET_SELF_FIXEDPRIORITY_FLAG = 0x4,
	WORKQ_SET_SELF_TIMESHARE_FLAG = 0x8,
	WORKQ_SET_SELF_WQ_KEVENT_UNBIND = 0x10,
};

void workq_proc_suspended(struct proc *p);
void workq_proc_resumed(struct proc *p);

#endif // BSD_KERNEL_PRIVATE

void workq_init(void);

#endif // KERNEL

#endif // _WORKQUEUE_INTERNAL_H_
