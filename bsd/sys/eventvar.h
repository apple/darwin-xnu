/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1999,2000 Jonathan Lemon <jlemon@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/sys/sys/eventvar.h,v 1.1.2.2 2000/07/18 21:49:12 jlemon Exp $
 */

#ifndef _SYS_EVENTVAR_H_
#define _SYS_EVENTVAR_H_

#include <sys/event.h>
#include <sys/select.h>
#include <kern/kern_types.h>
#include <kern/waitq.h>

#if defined(XNU_KERNEL_PRIVATE)

typedef int (*kevent_callback_t)(struct kqueue *, struct kevent_internal_s *, void *);
typedef void (*kqueue_continue_t)(struct kqueue *, void *, int);

#include <stdint.h>
#include <kern/locks.h>
#include <mach/thread_policy.h>
#include <pthread/workqueue_internal.h>

/*
 * Lock ordering:
 *
 * The kqueue locking order can follow a few different patterns:
 *
 * Standard file-based kqueues (from above):
 *     proc fd lock -> kq lock -> kq-waitq-set lock -> thread lock
 *
 * WorkQ/WorkLoop kqueues (from above):
 *     proc fd lock -> kq lock -> kq-request lock -> pthread kext locks -> thread lock
 *
 * Whenever kqueues interact with source locks, it drops all of its own
 * locks in exchange for a use-reference on the knote used to synchronize
 * with the source code. When those sources post events from below, they
 * have the following lock hierarchy.
 *
 * Standard file-based kqueues (from below):
 *     XXX lock -> kq lock -> kq-waitq-set lock -> thread lock
 * Standard file-based kqueues with non-kq-aware sources (from below):
 *     XXX lock -> kq-waitq-set lock -> thread lock
 *
 * WorkQ/WorkLoop kqueues (from below):
 *     XXX lock -> kq lock -> kq-request lock -> pthread kext locks -> thread lock
 * WorkQ/WorkLoop kqueues with non-kq-aware sources (from below):
 *     XXX -> kq-waitq-set lock -> kq-request lock -> pthread kext locks -> thread lock
 */

#define KQEXTENT	256		/* linear growth by this amount */

struct knote_lock_ctx {
	struct knote                       *knlc_knote;
	thread_t                            knlc_thread;
	// TODO: knlc_turnstile
	TAILQ_HEAD(, knote_lock_ctx)        knlc_head;
	union {
		LIST_ENTRY(knote_lock_ctx)      knlc_le;
		TAILQ_ENTRY(knote_lock_ctx)     knlc_tqe;
	};
#if DEBUG || DEVELOPMENT
#define KNOTE_LOCK_CTX_UNLOCKED 0
#define KNOTE_LOCK_CTX_LOCKED   1
#define KNOTE_LOCK_CTX_WAITING  2
	int knlc_state;
#endif
};
LIST_HEAD(knote_locks, knote_lock_ctx);

#if DEBUG || DEVELOPMENT
/*
 * KNOTE_LOCK_CTX(name) is a convenience macro to define a knote lock context on
 * the stack named `name`. In development kernels, it uses tricks to make sure
 * not locks was still held when exiting the C-scope that contains this context.
 */
__attribute__((noinline,not_tail_called))
void knote_lock_ctx_chk(struct knote_lock_ctx *ctx);
#define KNOTE_LOCK_CTX(n) \
		struct knote_lock_ctx n __attribute__((cleanup(knote_lock_ctx_chk))); \
		n.knlc_state = KNOTE_LOCK_CTX_UNLOCKED
#else
#define KNOTE_LOCK_CTX(n) \
		struct knote_lock_ctx n
#endif

/*
 * kqueue - common core definition of a kqueue
 *
 *          No real structures are allocated of this type. They are
 *          either kqfile objects or kqworkq objects - each of which is
 *          derived from this definition.
 */
struct kqueue {
	struct {
		struct waitq_set    kq_wqs;       /* private waitq set */
		lck_spin_t          kq_lock;      /* kqueue lock */
		uint16_t            kq_state;     /* state of the kq */
		uint16_t            kq_level;     /* nesting level of the kq */
		uint32_t            kq_count;     /* number of queued events */
		struct proc        *kq_p;         /* process containing kqueue */
		struct knote_locks  kq_knlocks;   /* list of knote locks held */
		lck_spin_t          kq_reqlock;   /* kqueue request lock */
	}; /* make sure struct padding is put before kq_queue */
	struct kqtailq      kq_queue[0];      /* variable array of queues */
};

#define KQ_SEL            0x001  /* select was recorded for kq */
#define KQ_SLEEP          0x002  /* thread is waiting for events */
#define KQ_PROCWAIT       0x004  /* thread waiting for processing */
#define KQ_KEV32          0x008  /* kq is used with 32-bit events */
#define KQ_KEV64          0x010  /* kq is used with 64-bit events */
#define KQ_KEV_QOS        0x020  /* kq events carry QoS info */
#define KQ_WORKQ          0x040  /* KQ is bound to process workq */
#define KQ_WORKLOOP       0x080  /* KQ is part of a workloop */
#define KQ_PROCESSING     0x100  /* KQ is being processed */
#define KQ_DRAIN          0x200  /* kq is draining */
#define KQ_WAKEUP         0x400  /* kq awakened while processing */
#define KQ_DYNAMIC        0x800  /* kqueue is dynamically managed */
/*
 * kqfile - definition of a typical kqueue opened as a file descriptor
 *          via the kqueue() system call.
 *
 *          Adds selinfo support to the base kqueue definition, as these
 *          fds can be fed into select().
 */
struct kqfile {
	struct kqueue       kqf_kqueue;     /* common kqueue core */
	struct kqtailq      kqf_queue;      /* queue of woken up knotes */
	struct kqtailq      kqf_suppressed; /* suppression queue */
	struct selinfo      kqf_sel;        /* parent select/kqueue info */
};

#define kqf_wqs      kqf_kqueue.kq_wqs
#define kqf_lock     kqf_kqueue.kq_lock
#define kqf_state    kqf_kqueue.kq_state
#define kqf_level    kqf_kqueue.kq_level
#define kqf_count    kqf_kqueue.kq_count
#define kqf_p        kqf_kqueue.kq_p

#define QOS_INDEX_KQFILE   0          /* number of qos levels in a file kq */

/*
 * kqrequest - per-QoS thread request status
 */
struct kqrequest {
	struct workq_threadreq_s kqr_req;      /* used when request oustanding */
	struct kqtailq   kqr_suppressed;       /* Per-QoS suppression queues */
	thread_t         kqr_thread;           /* thread to satisfy request */
	uint8_t          kqr_state;            /* KQ/workq interaction state */
#define KQWL_STAYACTIVE_FIRED_BIT     (1 << 0)
	uint8_t          kqr_wakeup_indexes;   /* QoS/override levels that woke */
	uint16_t         kqr_dsync_waiters;    /* number of dispatch sync waiters */
	kq_index_t       kqr_stayactive_qos;   /* max QoS of statyactive knotes */
	kq_index_t       kqr_override_index;   /* highest wakeup override index */
	kq_index_t       kqr_qos_index;        /* QoS for the thread request */
};


#define KQR_WORKLOOP                 0x01   /* owner is a workloop */
#define KQR_THREQUESTED              0x02	/* thread has been requested from workq */
#define KQR_WAKEUP                   0x04	/* wakeup called during processing */
#define KQR_THOVERCOMMIT             0x08   /* overcommit needed for thread requests */
#define KQR_R2K_NOTIF_ARMED          0x10   /* ast notifications armed */
#define KQR_ALLOCATED_TURNSTILE      0x20   /* kqwl_turnstile is allocated */

/*
 * WorkQ kqueues need to request threads to service the triggered
 * knotes in the queue.  These threads are brought up on a
 * effective-requested-QoS basis. Knotes are segregated based on
 * that value - calculated by computing max(event-QoS, kevent-QoS).
 * Only one servicing thread is requested at a time for all the
 * knotes at a given effective-requested-QoS.
 */

#if !defined(KQWQ_QOS_MANAGER)
#define KQWQ_QOS_MANAGER (THREAD_QOS_LAST)
#endif

#if !defined(KQWQ_NBUCKETS)
#define KQWQ_NBUCKETS    (KQWQ_QOS_MANAGER + 1)
#endif

/*
 * kqworkq - definition of a private kqueue used to coordinate event
 *           handling for pthread work queues.
 *
 *           These have per-qos processing queues and state to coordinate with
 *           the pthread kext to ask for threads at corresponding pthread priority
 *           values.
 */
struct kqworkq {
	struct kqueue    kqwq_kqueue;
	struct kqtailq   kqwq_queue[KQWQ_NBUCKETS];       /* array of queues */
	struct kqrequest kqwq_request[KQWQ_NBUCKETS];     /* per-QoS request states */
};

#define kqwq_wqs     kqwq_kqueue.kq_wqs
#define kqwq_lock    kqwq_kqueue.kq_lock
#define kqwq_state   kqwq_kqueue.kq_state
#define kqwq_level   kqwq_kqueue.kq_level
#define kqwq_count   kqwq_kqueue.kq_count
#define kqwq_p       kqwq_kqueue.kq_p

/*
 * WorkLoop kqueues need to request a thread to service the triggered
 * knotes in the queue.  The thread is brought up on a
 * effective-requested-QoS basis. Knotes are segregated based on
 * that value. Once a request is made, it cannot be undone.  If
 * events with higher QoS arrive after, they are stored in their
 * own queues and an override applied to the original request based
 * on the delta between the two QoS values.
 */

/*
 * "Stay-active" knotes are held in a separate bucket that indicates
 * special handling required. They are kept separate because the
 * wakeups issued to them don't have context to tell us where to go
 * to find and process them. All processing of them happens at the
 * highest QoS. Unlike WorkQ kqueues, there is no special singular
 * "manager thread" for a process. We simply request a servicing
 * thread at the higest known QoS when these are woken (or override
 * an existing request to that).
 */
#define KQWL_BUCKET_STAYACTIVE (THREAD_QOS_LAST)

#if !defined(KQWL_NBUCKETS)
#define KQWL_NBUCKETS    (KQWL_BUCKET_STAYACTIVE + 1)
#endif

/*
 * kqworkloop - definition of a private kqueue used to coordinate event
 *              handling for pthread workloops.
 *
 *              Workloops vary from workqs in that only a single thread is ever
 *              requested to service a workloop at a time.  But unlike workqs,
 *              workloops may be "owned" by user-space threads that are
 *              synchronously draining an event off the workloop. In those cases,
 *              any overrides have to be applied to the owner until it relinqueshes
 *              ownership.
 *
 *      NOTE:   "lane" support is TBD.
 */
struct kqworkloop {
	struct kqueue    kqwl_kqueue;                     /* queue of events */
	struct kqtailq   kqwl_queue[KQWL_NBUCKETS];       /* array of queues */
	struct kqrequest kqwl_request;                    /* thread request state */
	lck_mtx_t        kqwl_statelock;                  /* state/debounce lock */
	thread_t         kqwl_owner;                      /* current [sync] owner thread */
	uint32_t         kqwl_retains;                    /* retain references */
	kqueue_id_t      kqwl_dynamicid;                  /* dynamic identity */
	uint64_t         kqwl_params;                     /* additional parameters */
	struct turnstile *kqwl_turnstile;                 /* turnstile for sync IPC/waiters */
	SLIST_ENTRY(kqworkloop) kqwl_hashlink;            /* linkage for search list */
#if CONFIG_WORKLOOP_DEBUG
#define KQWL_HISTORY_COUNT 32
#define KQWL_HISTORY_WRITE_ENTRY(kqwl, ...) ({ \
		struct kqworkloop *__kqwl = (kqwl); \
		unsigned int __index = os_atomic_inc_orig(&__kqwl->kqwl_index, relaxed); \
		__kqwl->kqwl_history[__index % KQWL_HISTORY_COUNT] = \
				(struct kqwl_history)__VA_ARGS__; \
	})
	struct kqwl_history {
		thread_t updater;  /* Note: updates can be reordered */
		thread_t servicer;
		thread_t old_owner;
		thread_t new_owner;

		uint64_t kev_ident;
		int16_t  error;
		uint16_t kev_flags;
		uint32_t kev_fflags;

		uint64_t kev_mask;
		uint64_t kev_value;
		uint64_t in_value;
	} kqwl_history[KQWL_HISTORY_COUNT];
	unsigned int kqwl_index;
#endif // CONFIG_WORKLOOP_DEBUG
};

typedef union {
	struct kqueue	    *kq;
	struct kqworkq      *kqwq;
	struct kqfile       *kqf;
	struct kqworkloop   *kqwl;
} __attribute__((transparent_union)) kqueue_t;

SLIST_HEAD(kqlist, kqworkloop);

#define kqwl_wqs     kqwl_kqueue.kq_wqs
#define kqwl_lock    kqwl_kqueue.kq_lock
#define kqwl_state   kqwl_kqueue.kq_state
#define kqwl_level   kqwl_kqueue.kq_level
#define kqwl_count   kqwl_kqueue.kq_count
#define kqwl_p       kqwl_kqueue.kq_p

#define KQ_WORKLOOP_RETAINS_MAX UINT32_MAX

extern void kqueue_threadreq_unbind(struct proc *p, struct kqrequest *kqr);

// called with the kq req held
#define KQUEUE_THREADERQ_BIND_NO_INHERITOR_UPDATE 0x1
extern void kqueue_threadreq_bind(struct proc *p, workq_threadreq_t req,
		thread_t thread, unsigned int flags);

// called with the wq lock held
extern void kqueue_threadreq_bind_prepost(struct proc *p, workq_threadreq_t req, thread_t thread);

// called with no lock held
extern void kqueue_threadreq_bind_commit(struct proc *p, thread_t thread);

extern void kqueue_threadreq_cancel(struct proc *p, workq_threadreq_t req);

// lock not held as kqwl_params is immutable after creation
extern workq_threadreq_param_t kqueue_threadreq_workloop_param(workq_threadreq_t req);

extern struct kqueue *kqueue_alloc(struct proc *, unsigned int);
extern void kqueue_dealloc(struct kqueue *);

extern void knotes_dealloc(struct proc *);
extern void kqworkloops_dealloc(struct proc *);

extern int kevent_register(struct kqueue *, struct kevent_internal_s *,
		struct knote_lock_ctx *);
extern int kqueue_scan(struct kqueue *, kevent_callback_t, kqueue_continue_t,
		void *, struct filt_process_s *, struct timeval *, struct proc *);
extern int kqueue_stat(struct kqueue *, void *, int, proc_t);

#endif /* XNU_KERNEL_PRIVATE */

#endif /* !_SYS_EVENTVAR_H_ */
