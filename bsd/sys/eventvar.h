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

#include <kern/locks.h>
#include <mach/thread_policy.h>

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

#define KQ_SEL          0x001		/* select was recorded for kq */
#define KQ_SLEEP        0x002		/* thread is waiting for events */
#define KQ_PROCWAIT     0x004		/* thread waiting for processing */
#define KQ_KEV32        0x008		/* kq is used with 32-bit events */
#define KQ_KEV64        0x010		/* kq is used with 64-bit events */
#define KQ_KEV_QOS      0x020		/* kq events carry QoS info */
#define KQ_WORKQ        0x040		/* KQ is bould to process workq */
#define KQ_PROCESSING   0x080		/* KQ is being processed */
#define KQ_DRAIN        0x100		/* kq is draining */
#define KQ_WAKEUP       0x200       /* kq awakened while processing */

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
 * kqrequest - per-QoS thread request status
 */
struct kqrequest {
	struct kqtailq   kqr_suppressed;      /* Per-QoS suppression queues */
	thread_t         kqr_thread;          /* thread to satisfy request */
	uint8_t          kqr_state;           /* KQ/workq interaction state */
	uint8_t          kqr_override_delta;  /* current override delta */
};

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

#define kqwq_req_lock(kqwq)    (lck_spin_lock(&kqwq->kqwq_reqlock))
#define kqwq_req_unlock(kqwq)  (lck_spin_unlock(&kqwq->kqwq_reqlock))
#define kqwq_req_held(kqwq)    (lck_spin_held(&kqwq->kqwq_reqlock))

#define KQWQ_PROCESSING	  0x01		/* running the kq in workq mode */
#define KQWQ_THREQUESTED  0x02		/* thread requested from workq */
#define KQWQ_THMANAGER    0x04      /* expect manager thread to run the queue */
#define KQWQ_HOOKCALLED	  0x10		/* hook called during processing */
#define KQWQ_WAKEUP       0x20		/* wakeup called during processing */

extern struct kqueue *kqueue_alloc(struct proc *, unsigned int);
extern void kqueue_dealloc(struct kqueue *);

typedef int (*kevent_callback_t)(struct kqueue *, struct kevent_internal_s *, void *);
typedef void (*kqueue_continue_t)(struct kqueue *, void *, int);

extern void kevent_register(struct kqueue *, struct kevent_internal_s *, struct proc *);
extern int kqueue_scan(struct kqueue *, kevent_callback_t, kqueue_continue_t,
		       void *, struct filt_process_s *, struct timeval *, struct proc *);
extern int kqueue_stat(struct kqueue *, void *, int, proc_t);

#endif /* XNU_KERNEL_PRIVATE */

#endif /* !_SYS_EVENTVAR_H_ */




