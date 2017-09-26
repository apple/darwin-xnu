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
/*-
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
#include <sys/pthread_shims.h>
#include <mach/thread_policy.h>

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

/*
 * kqueue - common core definition of a kqueue
 *
 *          No real structures are allocated of this type. They are
 *          either kqfile objects or kqworkq objects - each of which is
 *          derived from this definition.
 */
struct kqueue {
	struct waitq_set    kq_wqs;       /* private waitq set */
	lck_spin_t          kq_lock;      /* kqueue lock */
	uint16_t            kq_state;     /* state of the kq */
	uint16_t            kq_level;     /* nesting level of the kq */
	uint32_t            kq_count;     /* number of queued events */
	struct proc         *kq_p;        /* process containing kqueue */
	struct kqtailq      kq_queue[1];  /* variable array of kqtailq structs */
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
#define KQ_NO_WQ_THREAD   0x1000 /* kq will not have workqueue threads dynamically created */
/*
 * kqfile - definition of a typical kqueue opened as a file descriptor
 *          via the kqueue() system call.
 *
 *          Adds selinfo support to the base kqueue definition, as these
 *          fds can be fed into select().
 */
struct kqfile {
	struct kqueue       kqf_kqueue;     /* common kqueue core */
	struct kqtailq      kqf_suppressed; /* suppression queue */
	struct selinfo      kqf_sel;        /* parent select/kqueue info */
};

#define kqf_wqs      kqf_kqueue.kq_wqs
#define kqf_lock     kqf_kqueue.kq_lock
#define kqf_state    kqf_kqueue.kq_state
#define kqf_level    kqf_kqueue.kq_level
#define kqf_count    kqf_kqueue.kq_count
#define kqf_p        kqf_kqueue.kq_p
#define kqf_queue    kqf_kqueue.kq_queue

#define QOS_INDEX_KQFILE   0          /* number of qos levels in a file kq */

struct kqr_bound {
	struct kqtailq   kqrb_suppressed;     /* Per-QoS suppression queues */
	thread_t         kqrb_thread;         /* thread to satisfy request */
};

/*
 * kqrequest - per-QoS thread request status
 */
struct kqrequest {
#if 0
	union {
		struct kqr_bound kqru_bound;       /* used when thread is bound */
		struct workq_threadreq_s kqru_req; /* used when request oustanding */
	} kqr_u;
#define kqr_suppressed kqr_u.kqru_bound.kqrb_suppressed
#define kqr_thread     kqr_u.kqru_bound.kqrb_thread
#define kqr_req        kqr_u.kqru_req
#else
	struct kqr_bound kqr_bound;            /* used when thread is bound */
	struct workq_threadreq_s kqr_req;      /* used when request oustanding */
#define kqr_suppressed kqr_bound.kqrb_suppressed
#define kqr_thread     kqr_bound.kqrb_thread
#endif
	uint8_t          kqr_state;                    /* KQ/workq interaction state */
	uint8_t          kqr_wakeup_indexes;           /* QoS/override levels that woke */
	uint16_t         kqr_dsync_waiters:13,         /* number of dispatch sync waiters */
	                 kqr_dsync_owner_qos:3;        /* Qos override on dispatch sync owner */
	uint16_t         kqr_sync_suppress_count;      /* number of suppressed sync ipc knotes */
	kq_index_t       kqr_stayactive_qos:3,         /* max QoS of statyactive knotes */
	                 kqr_owner_override_is_sync:1, /* sync owner has sync ipc override */
	                 kqr_override_index:3,         /* highest wakeup override index */
	                 kqr_has_sync_override:1;      /* Qos/override at UI is sync ipc override */

	/* set under both the kqlock and the filt_wllock */
	kq_index_t       :0;                           /* prevent bitfields coalescing <rdar://problem/31854115> */
	kq_index_t       kqr_qos_index:4,              /* QoS for the thread request */
	                 kqr_dsync_waiters_qos:4;      /* override from dispatch sync waiters */
};


#define KQR_PROCESSING	             0x01	/* requested thread is running the q */
#define KQR_THREQUESTED              0x02	/* thread has been requested from workq */
#define KQR_WAKEUP                   0x04	/* wakeup called during processing */
#define KQR_BOUND                    0x08       /* servicing thread is bound */
#define KQR_THOVERCOMMIT             0x20       /* overcommit needed for thread requests */
#define KQR_DRAIN                    0x40       /* cancel initiated - drain fulfill */
#define KQR_R2K_NOTIF_ARMED          0x80       /* ast notifications armed */
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

#if !defined(KQWQ_NQOS)
#define KQWQ_NQOS    (KQWQ_QOS_MANAGER + 1)
#endif

/*
 * Workq thread start out a particular effective-requested-QoS, but
 * additional events processed by the filters may represent
 * backlogged events that may themselves have a higher requested-QoS.
 * To represent this, the filter may apply an override to a knote's
 * requested QoS.
 *
 * We further segregate these overridden knotes into different buckets
 * by <requested, override> grouping. This allows easy matching of
 * knotes to process vs. the highest workq thread override applied.
 *
 * Only certain override patterns need to be supported. A knote
 * cannot have an effective-requested-QoS of UNSPECIFIED - because
 * the kevent->qos (when canonicalized) will always be above that
 * or indicate manager.  And we don't allow an override to specify
 * manager.  This results in the following buckets being needed:
 *
 *                  Effective-Requested QoS
 *           MAINT  BG    UTIL  DEFAULT UINIT UINTER MANAGER
 * override:
 * MAINT      0
 * BG         1      6
 * UTILITY    2      7     11
 * DEFAULT    3      8     12    15
 * UINIT      4      9     13    16     18
 * UINTER     5     10     14    17     19     20
 *                                                    21
 */
#if !defined(KQWQ_NBUCKETS)
#define KQWQ_NBUCKETS 22
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
	struct kqtailq   kqwq_queuecont[KQWQ_NBUCKETS-1]; /* continue array of queues */
	struct kqrequest kqwq_request[KQWQ_NQOS];         /* per-QoS request states */
	lck_spin_t       kqwq_reqlock;                    /* kqueue request lock */
};

#define kqwq_wqs     kqwq_kqueue.kq_wqs
#define kqwq_lock    kqwq_kqueue.kq_lock
#define kqwq_state   kqwq_kqueue.kq_state
#define kqwq_level   kqwq_kqueue.kq_level
#define kqwq_count   kqwq_kqueue.kq_count
#define kqwq_p       kqwq_kqueue.kq_p
#define kqwq_queue   kqwq_kqueue.kq_queue

#define kqwq_req_lock(kqwq)    lck_spin_lock(&kqwq->kqwq_reqlock)
#define kqwq_req_unlock(kqwq)  lck_spin_unlock(&kqwq->kqwq_reqlock)
#define kqwq_req_held(kqwq)    LCK_SPIN_ASSERT(&kqwq->kqwq_reqlock, LCK_ASSERT_OWNED)

#define KQWQ_THMANAGER    0x10      /* expect manager thread to run the queue */

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
	struct kqtailq   kqwl_queuecont[KQWL_NBUCKETS-1]; /* continue array of queues */
	struct kqrequest kqwl_request;                    /* thread request state */
	lck_spin_t       kqwl_reqlock;                    /* kqueue request lock */
	lck_mtx_t        kqwl_statelock;                  /* state/debounce lock */
	thread_t         kqwl_owner;                      /* current [sync] owner thread */
	uint32_t         kqwl_retains;                    /* retain references */
	kqueue_id_t      kqwl_dynamicid;                  /* dynamic identity */
	SLIST_ENTRY(kqworkloop) kqwl_hashlink;            /* linkage for search list */
};

SLIST_HEAD(kqlist, kqworkloop);

#define kqwl_wqs     kqwl_kqueue.kq_wqs
#define kqwl_lock    kqwl_kqueue.kq_lock
#define kqwl_state   kqwl_kqueue.kq_state
#define kqwl_level   kqwl_kqueue.kq_level
#define kqwl_count   kqwl_kqueue.kq_count
#define kqwl_p       kqwl_kqueue.kq_p
#define kqwl_queue   kqwl_kqueue.kq_queue

#define kqwl_req_lock(kqwl)    lck_spin_lock(&kqwl->kqwl_reqlock)
#define kqwl_req_unlock(kqwl)  lck_spin_unlock(&kqwl->kqwl_reqlock)
#define kqwl_req_held(kqwl)    LCK_SPIN_ASSERT(&kqwl->kqwl_reqlock, LCK_ASSERT_OWNED)

#define KQ_WORKLOOP_RETAINS_MAX UINT32_MAX

extern int workloop_fulfill_threadreq(struct proc *p, workq_threadreq_t req, thread_t thread, int flags);

extern struct kqueue *kqueue_alloc(struct proc *, unsigned int);
extern void kqueue_dealloc(struct kqueue *);

extern void knotes_dealloc(struct proc *);

extern void kevent_register(struct kqueue *, struct kevent_internal_s *, struct proc *);
extern int kqueue_scan(struct kqueue *, kevent_callback_t, kqueue_continue_t,
		       void *, struct filt_process_s *, struct timeval *, struct proc *);
extern int kqueue_stat(struct kqueue *, void *, int, proc_t);

#endif /* XNU_KERNEL_PRIVATE */

#endif /* !_SYS_EVENTVAR_H_ */




