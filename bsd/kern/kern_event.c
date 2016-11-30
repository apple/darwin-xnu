/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 *
 */
/*-
 * Copyright (c) 1999,2000,2001 Jonathan Lemon <jlemon@FreeBSD.org>
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
 */
/*
 *	@(#)kern_event.c       1.0 (3/31/2000)
 */
#include <stdint.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/malloc.h>
#include <sys/unistd.h>
#include <sys/file_internal.h>
#include <sys/fcntl.h>
#include <sys/select.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/eventvar.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/sysproto.h>
#include <sys/user.h>
#include <sys/vnode_internal.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/codesign.h>
#include <sys/pthread_shims.h>

#include <kern/locks.h>
#include <kern/clock.h>
#include <kern/policy_internal.h>
#include <kern/thread_call.h>
#include <kern/sched_prim.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>

#include <libkern/libkern.h>
#include "net/net_str_id.h"

#include <mach/task.h>

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

/*
 * JMM - this typedef needs to be unified with pthread_priority_t
 *       and mach_msg_priority_t. It also needs to be the same type
 *       everywhere.
 */
typedef int32_t qos_t;

MALLOC_DEFINE(M_KQUEUE, "kqueue", "memory for kqueue system");

#define	KQ_EVENT	NO_EVENT64

static inline void kqlock(struct kqueue *kq);
static inline void kqunlock(struct kqueue *kq);

static int kqlock2knoteuse(struct kqueue *kq, struct knote *kn);
static int kqlock2knotedrop(struct kqueue *kq, struct knote *kn);
static int kqlock2knotedetach(struct kqueue *kq, struct knote *kn);
static int knoteuse2kqlock(struct kqueue *kq, struct knote *kn, int defer_drop);

static int kqueue_read(struct fileproc *fp, struct uio *uio,
    int flags, vfs_context_t ctx);
static int kqueue_write(struct fileproc *fp, struct uio *uio,
    int flags, vfs_context_t ctx);
static int kqueue_ioctl(struct fileproc *fp, u_long com, caddr_t data,
    vfs_context_t ctx);
static int kqueue_select(struct fileproc *fp, int which, void *wq_link_id,
    vfs_context_t ctx);
static int kqueue_close(struct fileglob *fg, vfs_context_t ctx);
static int kqueue_kqfilter(struct fileproc *fp, struct knote *kn,
	vfs_context_t ctx);
static int kqueue_drain(struct fileproc *fp, vfs_context_t ctx);

static const struct fileops kqueueops = {
	.fo_type = DTYPE_KQUEUE,
	.fo_read = kqueue_read,
	.fo_write = kqueue_write,
	.fo_ioctl = kqueue_ioctl,
	.fo_select = kqueue_select,
	.fo_close = kqueue_close,
	.fo_kqfilter = kqueue_kqfilter,
	.fo_drain = kqueue_drain,
};

static int kevent_internal(struct proc *p, int fd, 
			   user_addr_t changelist, int nchanges,
			   user_addr_t eventlist, int nevents, 
			   user_addr_t data_out, uint64_t data_available,
			   unsigned int flags, user_addr_t utimeout,
			   kqueue_continue_t continuation,
			   int32_t *retval);
static int kevent_copyin(user_addr_t *addrp, struct kevent_internal_s *kevp,
			 struct proc *p, unsigned int flags);
static int kevent_copyout(struct kevent_internal_s *kevp, user_addr_t *addrp,
			  struct proc *p, unsigned int flags);
char * kevent_description(struct kevent_internal_s *kevp, char *s, size_t n);

static void kqueue_interrupt(struct kqueue *kq);
static int kevent_callback(struct kqueue *kq, struct kevent_internal_s *kevp,
			   void *data);
static void kevent_continue(struct kqueue *kq, void *data, int error);
static void kqueue_scan_continue(void *contp, wait_result_t wait_result);
static int kqueue_process(struct kqueue *kq, kevent_callback_t callback, void *callback_data,
                          struct filt_process_s *process_data, kq_index_t servicer_qos_index,
                          int *countp, struct proc *p);
static int kqueue_begin_processing(struct kqueue *kq, kq_index_t qos_index, unsigned int flags);
static void kqueue_end_processing(struct kqueue *kq, kq_index_t qos_index, unsigned int flags);
static struct kqtailq *kqueue_get_base_queue(struct kqueue *kq, kq_index_t qos_index);
static struct kqtailq *kqueue_get_high_queue(struct kqueue *kq, kq_index_t qos_index);
static int kqueue_queue_empty(struct kqueue *kq, kq_index_t qos_index);

static struct kqtailq *kqueue_get_suppressed_queue(struct kqueue *kq, kq_index_t qos_index);

static void kqworkq_request_thread(struct kqworkq *kqwq, kq_index_t qos_index);
static void kqworkq_request_help(struct kqworkq *kqwq, kq_index_t qos_index, uint32_t type);
static void kqworkq_update_override(struct kqworkq *kqwq, kq_index_t qos_index, kq_index_t override_index);
static void kqworkq_bind_thread(struct kqworkq *kqwq, kq_index_t qos_index, thread_t thread, unsigned int flags);
static void kqworkq_unbind_thread(struct kqworkq *kqwq, kq_index_t qos_index, thread_t thread, unsigned int flags);
static struct kqrequest *kqworkq_get_request(struct kqworkq *kqwq, kq_index_t qos_index);


static int knote_process(struct knote *kn, kevent_callback_t callback, void *callback_data,
			 struct filt_process_s *process_data, struct proc *p);
#if 0
static void knote_put(struct knote *kn);
#endif

static int knote_fdadd(struct knote *kn, struct proc *p);
static void knote_fdremove(struct knote *kn, struct proc *p);
static struct knote *knote_fdfind(struct kqueue *kq, struct kevent_internal_s *kev, struct proc *p);

static void knote_drop(struct knote *kn, struct proc *p);
static struct knote *knote_alloc(void);
static void knote_free(struct knote *kn);

static void knote_activate(struct knote *kn);
static void knote_deactivate(struct knote *kn);

static void knote_enable(struct knote *kn);
static void knote_disable(struct knote *kn);

static int knote_enqueue(struct knote *kn);
static void knote_dequeue(struct knote *kn);

static void knote_suppress(struct knote *kn);
static void knote_unsuppress(struct knote *kn);
static void knote_wakeup(struct knote *kn);

static kq_index_t knote_get_queue_index(struct knote *kn);
static struct kqtailq *knote_get_queue(struct knote *kn);
static struct kqtailq *knote_get_suppressed_queue(struct knote *kn);
static kq_index_t knote_get_req_index(struct knote *kn);
static kq_index_t knote_get_qos_index(struct knote *kn);
static void knote_set_qos_index(struct knote *kn, kq_index_t qos_index);
static kq_index_t knote_get_qos_override_index(struct knote *kn);
static void knote_set_qos_override_index(struct knote *kn, kq_index_t qos_index);

static int filt_fileattach(struct knote *kn);
static struct filterops file_filtops = {
	.f_isfd = 1,
	.f_attach = filt_fileattach,
};

static void filt_kqdetach(struct knote *kn);
static int filt_kqueue(struct knote *kn, long hint);
static int filt_kqtouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_kqprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
static struct filterops kqread_filtops = {
	.f_isfd = 1,
	.f_detach = filt_kqdetach,
	.f_event = filt_kqueue,
	.f_touch = filt_kqtouch,
	.f_process = filt_kqprocess,
};

/* placeholder for not-yet-implemented filters */
static int filt_badattach(struct knote *kn);
static struct filterops bad_filtops = {
	.f_attach = filt_badattach,
};

static int filt_procattach(struct knote *kn);
static void filt_procdetach(struct knote *kn);
static int filt_proc(struct knote *kn, long hint);
static int filt_proctouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_procprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
static struct filterops proc_filtops = {
	.f_attach = filt_procattach,
	.f_detach = filt_procdetach,
	.f_event = filt_proc,
	.f_touch = filt_proctouch,
	.f_process = filt_procprocess,
};

#if CONFIG_MEMORYSTATUS
extern struct filterops memorystatus_filtops;
#endif /* CONFIG_MEMORYSTATUS */

extern struct filterops fs_filtops;

extern struct filterops sig_filtops;

/* Timer filter */
static int filt_timerattach(struct knote *kn);
static void filt_timerdetach(struct knote *kn);
static int filt_timer(struct knote *kn, long hint);
static int filt_timertouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_timerprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
static struct filterops timer_filtops = {
	.f_attach = filt_timerattach,
	.f_detach = filt_timerdetach,
	.f_event = filt_timer,
	.f_touch = filt_timertouch,
	.f_process = filt_timerprocess,
};

/* Helpers */
static void filt_timerexpire(void *knx, void *param1);
static int filt_timervalidate(struct knote *kn);
static void filt_timerupdate(struct knote *kn, int num_fired);
static void filt_timercancel(struct knote *kn);

#define	TIMER_RUNNING		0x1
#define	TIMER_CANCELWAIT	0x2

static lck_mtx_t _filt_timerlock;
static void filt_timerlock(void);
static void filt_timerunlock(void);

static zone_t knote_zone;
static zone_t kqfile_zone;
static zone_t kqworkq_zone;

#define	KN_HASH(val, mask)	(((val) ^ (val >> 8)) & (mask))

#if 0
extern struct filterops aio_filtops;
#endif

/* Mach portset filter */
extern struct filterops machport_filtops;

/* User filter */
static int filt_userattach(struct knote *kn);
static void filt_userdetach(struct knote *kn);
static int filt_user(struct knote *kn, long hint);
static int filt_usertouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_userprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
static struct filterops user_filtops = {
	.f_attach = filt_userattach,
	.f_detach = filt_userdetach,
	.f_event = filt_user,
	.f_touch = filt_usertouch,
	.f_process = filt_userprocess,
};

static lck_spin_t _filt_userlock;
static void filt_userlock(void);
static void filt_userunlock(void);

extern struct filterops pipe_rfiltops;
extern struct filterops pipe_wfiltops;
extern struct filterops ptsd_kqops;
extern struct filterops soread_filtops;
extern struct filterops sowrite_filtops;
extern struct filterops sock_filtops;
extern struct filterops soexcept_filtops;
extern struct filterops spec_filtops;
extern struct filterops bpfread_filtops;
extern struct filterops necp_fd_rfiltops;
extern struct filterops skywalk_channel_rfiltops;
extern struct filterops skywalk_channel_wfiltops;
extern struct filterops fsevent_filtops;
extern struct filterops vnode_filtops;

/*
 *
 * Rules for adding new filters to the system:
 * Public filters:
 * - Add a new "EVFILT_" option value to bsd/sys/event.h (typically a negative value)
 *   in the exported section of the header
 * - Update the EVFILT_SYSCOUNT value to reflect the new addition
 * - Add a filterops to the sysfilt_ops array. Public filters should be added at the end 
 *   of the Public Filters section in the array.
 * Private filters:
 * - Add a new "EVFILT_" value to bsd/sys/event.h (typically a positive value)
 *   in the XNU_KERNEL_PRIVATE section of the header
 * - Update the EVFILTID_MAX value to reflect the new addition
 * - Add a filterops to the sysfilt_ops. Private filters should be added at the end of 
 *   the Private filters section of the array. 
 */
static struct filterops *sysfilt_ops[EVFILTID_MAX] = {
	/* Public Filters */
	[~EVFILT_READ] 					= &file_filtops,
	[~EVFILT_WRITE] 				= &file_filtops,
	[~EVFILT_AIO] 					= &bad_filtops,
	[~EVFILT_VNODE] 				= &file_filtops,
	[~EVFILT_PROC] 					= &proc_filtops,
	[~EVFILT_SIGNAL] 				= &sig_filtops,
	[~EVFILT_TIMER] 				= &timer_filtops,
	[~EVFILT_MACHPORT] 				= &machport_filtops,
	[~EVFILT_FS] 					= &fs_filtops,
	[~EVFILT_USER] 					= &user_filtops,
									  &bad_filtops,
									  &bad_filtops,
	[~EVFILT_SOCK] 					= &file_filtops,
#if CONFIG_MEMORYSTATUS
	[~EVFILT_MEMORYSTATUS] 			= &memorystatus_filtops,
#else
	[~EVFILT_MEMORYSTATUS] 			= &bad_filtops,
#endif
	[~EVFILT_EXCEPT] 				= &file_filtops,

	/* Private filters */
	[EVFILTID_KQREAD] 				= &kqread_filtops,
	[EVFILTID_PIPE_R] 				= &pipe_rfiltops,
	[EVFILTID_PIPE_W] 				= &pipe_wfiltops,
	[EVFILTID_PTSD] 				= &ptsd_kqops,
	[EVFILTID_SOREAD] 				= &soread_filtops,
	[EVFILTID_SOWRITE] 				= &sowrite_filtops,
	[EVFILTID_SCK] 					= &sock_filtops,
	[EVFILTID_SOEXCEPT] 			= &soexcept_filtops,
	[EVFILTID_SPEC] 				= &spec_filtops,
	[EVFILTID_BPFREAD] 				= &bpfread_filtops,
	[EVFILTID_NECP_FD] 				= &necp_fd_rfiltops,
	[EVFILTID_FSEVENT] 				= &fsevent_filtops,
	[EVFILTID_VN] 					= &vnode_filtops
};

/* waitq prepost callback */
void waitq_set__CALLING_PREPOST_HOOK__(void *kq_hook, void *knote_hook, int qos);

#ifndef _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG
#define _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG 0x02000000 /* pthread event manager bit */
#endif
#ifndef _PTHREAD_PRIORITY_OVERCOMMIT_FLAG
#define _PTHREAD_PRIORITY_OVERCOMMIT_FLAG    0x80000000 /* request overcommit threads */
#endif
#ifndef _PTHREAD_PRIORITY_QOS_CLASS_MASK
#define _PTHREAD_PRIORITY_QOS_CLASS_MASK    0x003fff00  /* QoS class mask */
#endif
#ifndef _PTHREAD_PRIORITY_QOS_CLASS_SHIFT_32
#define _PTHREAD_PRIORITY_QOS_CLASS_SHIFT_32 8
#endif

static inline
qos_t canonicalize_kevent_qos(qos_t qos)
{
	unsigned long canonical;

	/* preserve manager and overcommit flags in this case */
	canonical = pthread_priority_canonicalize(qos, FALSE);
	return (qos_t)canonical;
}

static inline
kq_index_t qos_index_from_qos(qos_t qos, boolean_t propagation)
{
	kq_index_t qos_index;
	unsigned long flags = 0;

	qos_index = (kq_index_t)thread_qos_from_pthread_priority(
				(unsigned long)qos, &flags);
	
	if (!propagation && (flags & _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG))
		return KQWQ_QOS_MANAGER;

	return qos_index;
}

static inline
qos_t qos_from_qos_index(kq_index_t qos_index)
{
	if (qos_index == KQWQ_QOS_MANAGER)
		return  _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG;

	if (qos_index == 0)
		return 0; /* Unspecified */

	/* Should have support from pthread kext support */
	return (1 << (qos_index - 1 + 
	              _PTHREAD_PRIORITY_QOS_CLASS_SHIFT_32));
}

static inline
kq_index_t qos_index_for_servicer(int qos_class, thread_t thread, int flags)
{
	kq_index_t qos_index;

	if (flags & KEVENT_FLAG_WORKQ_MANAGER)
		return KQWQ_QOS_MANAGER;

	/* 
	 * If the caller didn't pass in a class (legacy pthread kext)
	 * the we use the thread policy QoS of the current thread.
	 */
	assert(qos_class != -1);
	if (qos_class == -1)
		qos_index = proc_get_thread_policy(thread,
		                                   TASK_POLICY_ATTRIBUTE,
		                                   TASK_POLICY_QOS);
	else
		qos_index = (kq_index_t)qos_class;

	assert(qos_index > 0 && qos_index < KQWQ_NQOS);

	return qos_index;
}

/*
 * kqueue/note lock implementations
 *
 *	The kqueue lock guards the kq state, the state of its queues,
 *	and the kqueue-aware status and use counts of individual knotes.
 *
 *	The kqueue workq lock is used to protect state guarding the
 *	interaction of the kqueue with the workq.  This state cannot
 *	be guarded by the kq lock - as it needs to be taken when we
 *	already have the waitq set lock held (during the waitq hook
 *	callback).  It might be better to use the waitq lock itself
 *	for this, but the IRQ requirements make that difficult).
 *
 *	Knote flags, filter flags, and associated data are protected
 *	by the underlying object lock - and are only ever looked at
 *	by calling the filter to get a [consistent] snapshot of that
 *	data.
 */
lck_grp_attr_t * kq_lck_grp_attr;
lck_grp_t * kq_lck_grp;
lck_attr_t * kq_lck_attr;

static inline void
kqlock(struct kqueue *kq)
{
	lck_spin_lock(&kq->kq_lock);
}

static inline void
kqunlock(struct kqueue *kq)
{
	lck_spin_unlock(&kq->kq_lock);
}


/*
 * Convert a kq lock to a knote use referece.
 *
 *	If the knote is being dropped, or has
 *  vanished, we can't get a use reference.
 *  Just return with it still locked.
 *
 *	- kq locked at entry
 *	- unlock on exit if we get the use reference
 */
static int
kqlock2knoteuse(struct kqueue *kq, struct knote *kn)
{
	if (kn->kn_status & (KN_DROPPING | KN_VANISHED))
		return (0);

	assert(kn->kn_status & KN_ATTACHED);
	kn->kn_inuse++;
	kqunlock(kq);
	return (1);
}


/*
 * Convert from a knote use reference back to kq lock.
 *
 *	Drop a use reference and wake any waiters if
 *	this is the last one.
 *
 *  If someone is trying to drop the knote, but the
 *  caller has events they must deliver, take 
 *  responsibility for the drop later - and wake the
 *  other attempted dropper in a manner that informs
 *  him of the transfer of responsibility.
 *
 *	The exit return indicates if the knote is still alive
 *  (or if not, the other dropper has been given the green
 *  light to drop it).
 *
 *  The kqueue lock is re-taken unconditionally.
 */
static int
knoteuse2kqlock(struct kqueue *kq, struct knote *kn, int steal_drop)
{
	int dropped = 0;

	kqlock(kq);
	if (--kn->kn_inuse == 0) {

		if ((kn->kn_status & KN_ATTACHING) != 0) {
			kn->kn_status &= ~KN_ATTACHING;
		}

		if ((kn->kn_status & KN_USEWAIT) != 0) {
			wait_result_t result;

			/* If we need to, try and steal the drop */
			if (kn->kn_status & KN_DROPPING) {
				if (steal_drop && !(kn->kn_status & KN_STOLENDROP)) {
					kn->kn_status |= KN_STOLENDROP;
				} else {
					dropped = 1;
				}
			}

			/* wakeup indicating if ANY USE stole the drop */
			result = (kn->kn_status & KN_STOLENDROP) ?
			         THREAD_RESTART : THREAD_AWAKENED;

			kn->kn_status &= ~KN_USEWAIT;
			waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,
					   CAST_EVENT64_T(&kn->kn_status),
					   result,
					   WAITQ_ALL_PRIORITIES);
		} else {
			/* should have seen use-wait if dropping with use refs */
			assert((kn->kn_status & (KN_DROPPING|KN_STOLENDROP)) == 0);
		}

	} else if (kn->kn_status & KN_DROPPING) {
		/* not the last ref but want to steal a drop if present */
		if (steal_drop && ((kn->kn_status & KN_STOLENDROP) == 0)) {
			kn->kn_status |= KN_STOLENDROP;

			/* but we now have to wait to be the last ref */
			kn->kn_status |= KN_USEWAIT;
			waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
					    CAST_EVENT64_T(&kn->kn_status),
					    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
			kqunlock(kq);
			thread_block(THREAD_CONTINUE_NULL);
			kqlock(kq);
		} else {
			dropped = 1;
		}
	}

	return (!dropped);
}

/*
 * Convert a kq lock to a knote use reference
 * (for the purpose of detaching AND vanishing it).
 *
 *	If the knote is being dropped, we can't get
 *	a detach reference, so wait for the knote to
 *  finish dropping before returning.
 *
 *  If the knote is being used for other purposes,
 *  we cannot detach it until those uses are done
 *  as well. Again, just wait for them to finish
 *  (caller will start over at lookup).
 *
 *	- kq locked at entry
 *	- unlocked on exit 
 */
static int
kqlock2knotedetach(struct kqueue *kq, struct knote *kn)
{
	if ((kn->kn_status & KN_DROPPING) || kn->kn_inuse) {
		/* have to wait for dropper or current uses to go away */
		kn->kn_status |= KN_USEWAIT;
		waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
		                    CAST_EVENT64_T(&kn->kn_status),
		                    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
		kqunlock(kq);
		thread_block(THREAD_CONTINUE_NULL);
		return (0);
	}
	assert((kn->kn_status & KN_VANISHED) == 0);
	assert(kn->kn_status & KN_ATTACHED);
	kn->kn_status &= ~KN_ATTACHED;
	kn->kn_status |= KN_VANISHED;
	kn->kn_inuse++;
	kqunlock(kq);
	return (1);
}

/*
 * Convert a kq lock to a knote drop reference.
 *
 *	If the knote is in use, wait for the use count
 *	to subside.  We first mark our intention to drop
 *	it - keeping other users from "piling on."
 *	If we are too late, we have to wait for the
 *	other drop to complete.
 *
 *	- kq locked at entry
 *	- always unlocked on exit.
 *	- caller can't hold any locks that would prevent
 *	  the other dropper from completing.
 */
static int
kqlock2knotedrop(struct kqueue *kq, struct knote *kn)
{
	int oktodrop;
	wait_result_t result;

	oktodrop = ((kn->kn_status & (KN_DROPPING | KN_ATTACHING)) == 0);
	/* if another thread is attaching, they will become the dropping thread */
	kn->kn_status |= KN_DROPPING;
	knote_unsuppress(kn);
	knote_dequeue(kn);
	if (oktodrop) {
		if (kn->kn_inuse == 0) {
			kqunlock(kq);
			return (oktodrop);
		}
	}
	kn->kn_status |= KN_USEWAIT;
	waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
			    CAST_EVENT64_T(&kn->kn_status),
			    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
	kqunlock(kq);
	result = thread_block(THREAD_CONTINUE_NULL);
	/* THREAD_RESTART == another thread stole the knote drop */
	return (result == THREAD_AWAKENED);
}

#if 0
/*
 * Release a knote use count reference.
 */
static void
knote_put(struct knote *kn)
{
	struct kqueue *kq = knote_get_kq(kn);

	kqlock(kq);
	if (--kn->kn_inuse == 0) {
		if ((kn->kn_status & KN_USEWAIT) != 0) {
			kn->kn_status &= ~KN_USEWAIT;
			waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,
					   CAST_EVENT64_T(&kn->kn_status),
					   THREAD_AWAKENED,
					   WAITQ_ALL_PRIORITIES);
		}
	}
	kqunlock(kq);
}
#endif

static int
filt_fileattach(struct knote *kn)
{
	return (fo_kqfilter(kn->kn_fp, kn, vfs_context_current()));
}

#define	f_flag f_fglob->fg_flag
#define	f_msgcount f_fglob->fg_msgcount
#define	f_cred f_fglob->fg_cred
#define	f_ops f_fglob->fg_ops
#define	f_offset f_fglob->fg_offset
#define	f_data f_fglob->fg_data

static void
filt_kqdetach(struct knote *kn)
{
	struct kqfile *kqf = (struct kqfile *)kn->kn_fp->f_data;
	struct kqueue *kq = &kqf->kqf_kqueue;

	kqlock(kq);
	KNOTE_DETACH(&kqf->kqf_sel.si_note, kn);
	kqunlock(kq);
}

/*ARGSUSED*/
static int
filt_kqueue(struct knote *kn, __unused long hint)
{
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;
	int count;

	count = kq->kq_count;
	return (count > 0);
}

static int
filt_kqtouch(struct knote *kn, struct kevent_internal_s *kev)
{
#pragma unused(kev)
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;
	int res;

	kqlock(kq);
	kn->kn_data = kq->kq_count;
	if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0)
		kn->kn_udata = kev->udata;
	res = (kn->kn_data > 0);

	kqunlock(kq);

	return res;
}

static int
filt_kqprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev)
{
#pragma unused(data)
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;
	int res;

	kqlock(kq);
	kn->kn_data = kq->kq_count;
	res = (kn->kn_data > 0);
	if (res) {
		*kev = kn->kn_kevent;
		if (kn->kn_flags & EV_CLEAR)
			kn->kn_data = 0;
	}
	kqunlock(kq);

	return res;
}

static int
filt_procattach(struct knote *kn)
{
	struct proc *p;

	assert(PID_MAX < NOTE_PDATAMASK);

	if ((kn->kn_sfflags & (NOTE_TRACK | NOTE_TRACKERR | NOTE_CHILD)) != 0) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = ENOTSUP;
		return 0;
	}

	p = proc_find(kn->kn_id);
	if (p == NULL) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = ESRCH;
		return 0;
	}

	const int NoteExitStatusBits = NOTE_EXIT | NOTE_EXITSTATUS;

	if ((kn->kn_sfflags & NoteExitStatusBits) == NoteExitStatusBits)
		do {
			pid_t selfpid = proc_selfpid();

			if (p->p_ppid == selfpid)
				break;	/* parent => ok */

			if ((p->p_lflag & P_LTRACED) != 0 &&
			    (p->p_oppid == selfpid))
				break;	/* parent-in-waiting => ok */

			proc_rele(p);
			kn->kn_flags = EV_ERROR;
			kn->kn_data = EACCES;
			return 0;
		} while (0);

	proc_klist_lock();

	kn->kn_ptr.p_proc = p;		/* store the proc handle */

	KNOTE_ATTACH(&p->p_klist, kn);

	proc_klist_unlock();

	proc_rele(p);

	/*
	 * only captures edge-triggered events after this point
	 * so it can't already be fired.
	 */
	return (0);
}


/*
 * The knote may be attached to a different process, which may exit,
 * leaving nothing for the knote to be attached to.  In that case,
 * the pointer to the process will have already been nulled out.
 */
static void
filt_procdetach(struct knote *kn)
{
	struct proc *p;

	proc_klist_lock();

	p = kn->kn_ptr.p_proc;
	if (p != PROC_NULL) {
		kn->kn_ptr.p_proc = PROC_NULL;
		KNOTE_DETACH(&p->p_klist, kn);
	}

	proc_klist_unlock();
}

static int
filt_proc(struct knote *kn, long hint)
{
	u_int event;

	/* ALWAYS CALLED WITH proc_klist_lock */

	/*
	 * Note: a lot of bits in hint may be obtained from the knote
	 * To free some of those bits, see <rdar://problem/12592988> Freeing up
	 * bits in hint for filt_proc
	 *
	 * mask off extra data
	 */
	event = (u_int)hint & NOTE_PCTRLMASK;

	/*
	 * termination lifecycle events can happen while a debugger
	 * has reparented a process, in which case notifications
	 * should be quashed except to the tracing parent. When
	 * the debugger reaps the child (either via wait4(2) or
	 * process exit), the child will be reparented to the original
	 * parent and these knotes re-fired.
	 */
	if (event & NOTE_EXIT) {
		if ((kn->kn_ptr.p_proc->p_oppid != 0)
		    && (knote_get_kq(kn)->kq_p->p_pid != kn->kn_ptr.p_proc->p_ppid)) {
			/*
			 * This knote is not for the current ptrace(2) parent, ignore.
			 */
			return 0;
		}
	}					

	/*
	 * if the user is interested in this event, record it.
	 */
	if (kn->kn_sfflags & event)
		kn->kn_fflags |= event;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	if ((event == NOTE_REAP) || ((event == NOTE_EXIT) && !(kn->kn_sfflags & NOTE_REAP))) {
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
	}
#pragma clang diagnostic pop


	/*
	 * The kernel has a wrapper in place that returns the same data
	 * as is collected here, in kn_data.  Any changes to how 
	 * NOTE_EXITSTATUS and NOTE_EXIT_DETAIL are collected
	 * should also be reflected in the proc_pidnoteexit() wrapper.
	 */
	if (event == NOTE_EXIT) {
		kn->kn_data = 0;
		if ((kn->kn_sfflags & NOTE_EXITSTATUS) != 0) {
			kn->kn_fflags |= NOTE_EXITSTATUS;
			kn->kn_data |= (hint & NOTE_PDATAMASK);
		}
		if ((kn->kn_sfflags & NOTE_EXIT_DETAIL) != 0) {
			kn->kn_fflags |= NOTE_EXIT_DETAIL;
			if ((kn->kn_ptr.p_proc->p_lflag &
			     P_LTERM_DECRYPTFAIL) != 0) {
				kn->kn_data |= NOTE_EXIT_DECRYPTFAIL; 
			}
			if ((kn->kn_ptr.p_proc->p_lflag &
			     P_LTERM_JETSAM) != 0) {
				kn->kn_data |= NOTE_EXIT_MEMORY;
				switch (kn->kn_ptr.p_proc->p_lflag & P_JETSAM_MASK) {
				case P_JETSAM_VMPAGESHORTAGE:
					kn->kn_data |= NOTE_EXIT_MEMORY_VMPAGESHORTAGE;
					break;
				case P_JETSAM_VMTHRASHING:
					kn->kn_data |= NOTE_EXIT_MEMORY_VMTHRASHING;
					break;
				case P_JETSAM_FCTHRASHING:
					kn->kn_data |= NOTE_EXIT_MEMORY_FCTHRASHING;
					break;
				case P_JETSAM_VNODE:
					kn->kn_data |= NOTE_EXIT_MEMORY_VNODE;
					break;
				case P_JETSAM_HIWAT:
					kn->kn_data |= NOTE_EXIT_MEMORY_HIWAT;
					break;
				case P_JETSAM_PID:
					kn->kn_data |= NOTE_EXIT_MEMORY_PID;
					break;
				case P_JETSAM_IDLEEXIT:
					kn->kn_data |= NOTE_EXIT_MEMORY_IDLE;
					break;
				}
			}
			if ((kn->kn_ptr.p_proc->p_csflags &
			     CS_KILLED) != 0) {
				kn->kn_data |= NOTE_EXIT_CSERROR;
			}
		}
	}

	/* if we have any matching state, activate the knote */
	return (kn->kn_fflags != 0);
}

static int
filt_proctouch(struct knote *kn, struct kevent_internal_s *kev)
{
	int res;

	proc_klist_lock();

	/* accept new filter flags and mask off output events no long interesting */
	kn->kn_sfflags = kev->fflags;
	if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0)
		kn->kn_udata = kev->udata;

	/* restrict the current results to the (smaller?) set of new interest */
	/*
	 * For compatibility with previous implementations, we leave kn_fflags
	 * as they were before.
	 */
	//kn->kn_fflags &= kn->kn_sfflags;

	res = (kn->kn_fflags != 0);

	proc_klist_unlock();

	return res;
}

static int
filt_procprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev)
{
#pragma unused(data)
	int res;

	proc_klist_lock();
	res = (kn->kn_fflags != 0);
	if (res) {
		*kev = kn->kn_kevent;
		kn->kn_flags |= EV_CLEAR;	/* automatically set */
		kn->kn_fflags = 0;
		kn->kn_data = 0;
	}
	proc_klist_unlock();
	return res;
}

/*
 * filt_timervalidate - process data from user
 *
 *	Converts to either interval or deadline format.
 *
 *	The saved-data field in the knote contains the
 *	time value.  The saved filter-flags indicates
 *	the unit of measurement.
 *
 *	After validation, either the saved-data field
 *	contains the interval in absolute time, or ext[0]
 *	contains the expected deadline. If that deadline
 *	is in the past, ext[0] is 0.
 *
 *	Returns EINVAL for unrecognized units of time.
 *
 *	Timer filter lock is held.
 *
 */
static int
filt_timervalidate(struct knote *kn)
{
	uint64_t multiplier;
	uint64_t raw = 0;

	switch (kn->kn_sfflags & (NOTE_SECONDS|NOTE_USECONDS|NOTE_NSECONDS)) {
	case NOTE_SECONDS:
		multiplier = NSEC_PER_SEC;
		break;
	case NOTE_USECONDS:
		multiplier = NSEC_PER_USEC;
		break;
	case NOTE_NSECONDS:
		multiplier = 1;
		break;
	case 0: /* milliseconds (default) */
		multiplier = NSEC_PER_SEC / 1000;
		break;
	default:
		return (EINVAL);
	}

	/* transform the slop delta(leeway) in kn_ext[1] if passed to same time scale */
	if(kn->kn_sfflags & NOTE_LEEWAY){
		nanoseconds_to_absolutetime((uint64_t)kn->kn_ext[1] * multiplier, &raw);
		kn->kn_ext[1] = raw;
	}

	nanoseconds_to_absolutetime((uint64_t)kn->kn_sdata * multiplier, &raw);

	kn->kn_ext[0] = 0;
	kn->kn_sdata = 0;

	if (kn->kn_sfflags & NOTE_ABSOLUTE) {
		clock_sec_t seconds;
		clock_nsec_t nanoseconds;
		uint64_t now;

		clock_get_calendar_nanotime(&seconds, &nanoseconds);
		nanoseconds_to_absolutetime((uint64_t)seconds * NSEC_PER_SEC +
		    nanoseconds, &now);

		/* if time is in the future */
		if (now < raw) {
			raw -= now;

			if (kn->kn_sfflags & NOTE_MACH_CONTINUOUS_TIME) {
				clock_continuoustime_interval_to_deadline(raw,
				    &kn->kn_ext[0]);
			} else {
				clock_absolutetime_interval_to_deadline(raw,
				    &kn->kn_ext[0]);
			}
		}
	} else {
		kn->kn_sdata = raw;
	}

	return (0);
}

/*
 * filt_timerupdate - compute the next deadline
 *
 * 	Repeating timers store their interval in kn_sdata. Absolute
 * 	timers have already calculated the deadline, stored in ext[0].
 *
 * 	On return, the next deadline (or zero if no deadline is needed)
 * 	is stored in kn_ext[0].
 *
 * 	Timer filter lock is held.
 */
static void
filt_timerupdate(struct knote *kn, int num_fired)
{
	assert(num_fired > 0);

	/* if there's no interval, deadline is just in kn_ext[0] */
	if (kn->kn_sdata == 0)
		return;

	/* if timer hasn't fired before, fire in interval nsecs */
	if (kn->kn_ext[0] == 0) {
		assert(num_fired == 1);
		if (kn->kn_sfflags & NOTE_MACH_CONTINUOUS_TIME) {
			clock_continuoustime_interval_to_deadline(kn->kn_sdata,
			    &kn->kn_ext[0]);
		} else {
			clock_absolutetime_interval_to_deadline(kn->kn_sdata,
			    &kn->kn_ext[0]);
		}
	} else {
		/*
		 * If timer has fired before, schedule the next pop
		 * relative to the last intended deadline.
		 *
		 * We could check for whether the deadline has expired,
		 * but the thread call layer can handle that.
		 * 
		 * Go forward an additional number of periods, in the case the
		 * timer fired multiple times while the system was asleep.
		 */
		kn->kn_ext[0] += (kn->kn_sdata * num_fired);
	}
}

/*
 * filt_timerexpire - the timer callout routine
 *
 * Just propagate the timer event into the knote
 * filter routine (by going through the knote
 * synchronization point).  Pass a hint to
 * indicate this is a real event, not just a
 * query from above.
 */
static void
filt_timerexpire(void *knx, __unused void *spare)
{
	struct klist timer_list;
	struct knote *kn = knx;

	filt_timerlock();

	kn->kn_hookid &= ~TIMER_RUNNING;

	/* no "object" for timers, so fake a list */
	SLIST_INIT(&timer_list);
	SLIST_INSERT_HEAD(&timer_list, kn, kn_selnext);
	KNOTE(&timer_list, 1);

	/* if someone is waiting for timer to pop */
	if (kn->kn_hookid & TIMER_CANCELWAIT) {
		struct kqueue *kq = knote_get_kq(kn);
		waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,
				   CAST_EVENT64_T(&kn->kn_hook),
				   THREAD_AWAKENED,
				   WAITQ_ALL_PRIORITIES);
	}

	filt_timerunlock();
}

/*
 * Cancel a running timer (or wait for the pop).
 * Timer filter lock is held.
 */
static void
filt_timercancel(struct knote *kn)
{
	struct kqueue *kq = knote_get_kq(kn);
	thread_call_t callout = kn->kn_hook;
	boolean_t cancelled;

	if (kn->kn_hookid & TIMER_RUNNING) {
		/* cancel the callout if we can */
		cancelled = thread_call_cancel(callout);
		if (cancelled) {
			kn->kn_hookid &= ~TIMER_RUNNING;
		} else {
			/* we have to wait for the expire routine.  */
			kn->kn_hookid |= TIMER_CANCELWAIT;
			waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
					    CAST_EVENT64_T(&kn->kn_hook),
					    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
			filt_timerunlock();
			thread_block(THREAD_CONTINUE_NULL);
			filt_timerlock();
			assert((kn->kn_hookid & TIMER_RUNNING) == 0);
		}
	}
}

/*
 * Allocate a thread call for the knote's lifetime, and kick off the timer.
 */
static int
filt_timerattach(struct knote *kn)
{
	thread_call_t callout;
	int error;
	int res;

	callout = thread_call_allocate(filt_timerexpire, kn);
	if (NULL == callout) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = ENOMEM;
		return 0;
	}

	filt_timerlock();
	error = filt_timervalidate(kn);
	if (error != 0) {
		filt_timerunlock();
		thread_call_free(callout);
		kn->kn_flags = EV_ERROR;
		kn->kn_data = error;
		return 0;
	}

	kn->kn_hook = (void*)callout;
	kn->kn_hookid = 0;

	/* absolute=EV_ONESHOT */
	if (kn->kn_sfflags & NOTE_ABSOLUTE)
		kn->kn_flags |= EV_ONESHOT;

	filt_timerupdate(kn, 1);
	if (kn->kn_ext[0]) {
		kn->kn_flags |= EV_CLEAR;
		unsigned int timer_flags = 0;
		if (kn->kn_sfflags & NOTE_CRITICAL)
			timer_flags |= THREAD_CALL_DELAY_USER_CRITICAL;
		else if (kn->kn_sfflags & NOTE_BACKGROUND)
			timer_flags |= THREAD_CALL_DELAY_USER_BACKGROUND;
		else
			timer_flags |= THREAD_CALL_DELAY_USER_NORMAL;

		if (kn->kn_sfflags & NOTE_LEEWAY)
			timer_flags |= THREAD_CALL_DELAY_LEEWAY;
		if (kn->kn_sfflags & NOTE_MACH_CONTINUOUS_TIME)
			timer_flags |= THREAD_CALL_CONTINUOUS;

		thread_call_enter_delayed_with_leeway(callout, NULL,
				kn->kn_ext[0], kn->kn_ext[1], timer_flags);

		kn->kn_hookid |= TIMER_RUNNING;
	} else {
		/* fake immediate */
		kn->kn_data = 1;
	}

	res = (kn->kn_data > 0);

	filt_timerunlock();

	return res;
}

/*
 * Shut down the timer if it's running, and free the callout.
 */
static void
filt_timerdetach(struct knote *kn)
{
	thread_call_t callout;

	filt_timerlock();

	callout = (thread_call_t)kn->kn_hook;
	filt_timercancel(kn);

	filt_timerunlock();

	thread_call_free(callout);
}


static int filt_timer_num_fired(struct knote *kn)
{
	/* by default we fire a timer once */
	int num_fired = 1;

	/*
	 * When the time base is mach_continuous_time, we have to calculate
	 * the number of times the timer fired while we were asleep.
	 */
	if ((kn->kn_sfflags & NOTE_MACH_CONTINUOUS_TIME) &&
	    (kn->kn_sdata  != 0) &&
	    (kn->kn_ext[0] != 0))
	{
		const uint64_t now = mach_continuous_time();
		// time for timer to fire (right now) is kn_ext[0]
		// kn_sdata is period for timer to fire
		assert(now >= kn->kn_ext[0]);
		assert(kn->kn_sdata > 0);

		const uint64_t overrun_ticks = now - kn->kn_ext[0];
		const uint64_t kn_sdata = kn->kn_sdata;

		if (overrun_ticks < kn_sdata) {
			num_fired = 1;
		} else if (overrun_ticks < (kn_sdata << 1)) {
			num_fired = 2;
		} else {
			num_fired = (overrun_ticks / kn_sdata) + 1;
		}
	}

	return num_fired;
}

/*
 * filt_timer - post events to a timer knote
 *
 * Count the timer fire and re-arm as requested.
 * This always crosses the threshold of interest,
 * so always return an indication that the knote
 * should be activated (if not already).
 */
static int
filt_timer(
	struct knote *kn, 
	long hint)
{
#pragma unused(hint)

	/* real timer pop -- timer lock held by filt_timerexpire */
	int num_fired = filt_timer_num_fired(kn);
	kn->kn_data += num_fired;

	if (((kn->kn_hookid & TIMER_CANCELWAIT) == 0) &&
	    ((kn->kn_flags & EV_ONESHOT) == 0)) {
		/* evaluate next time to fire */
		filt_timerupdate(kn, num_fired);

		if (kn->kn_ext[0]) {
			unsigned int timer_flags = 0;

			/* keep the callout and re-arm */
			if (kn->kn_sfflags & NOTE_CRITICAL)
				timer_flags |= THREAD_CALL_DELAY_USER_CRITICAL;
			else if (kn->kn_sfflags & NOTE_BACKGROUND)
				timer_flags |= THREAD_CALL_DELAY_USER_BACKGROUND;
			else
				timer_flags |= THREAD_CALL_DELAY_USER_NORMAL;

			if (kn->kn_sfflags & NOTE_LEEWAY)
				timer_flags |= THREAD_CALL_DELAY_LEEWAY;

			thread_call_enter_delayed_with_leeway(kn->kn_hook, NULL,
					kn->kn_ext[0], kn->kn_ext[1], timer_flags);

			kn->kn_hookid |= TIMER_RUNNING;
		}
	}
	return (1);
}



/*
 * filt_timertouch - update timer knote with new user input
 *
 * Cancel and restart the timer based on new user data. When
 * the user picks up a knote, clear the count of how many timer
 * pops have gone off (in kn_data).
 */
static int
filt_timertouch(
	struct knote *kn,
	struct kevent_internal_s *kev)
{
	int error;
	int res;

	filt_timerlock();

	/* cancel current call */
	filt_timercancel(kn);

	/* capture the new values used to compute deadline */
	kn->kn_sdata = kev->data;
	kn->kn_sfflags = kev->fflags;
	kn->kn_ext[0] = kev->ext[0];
	kn->kn_ext[1] = kev->ext[1];

	if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0)
		kn->kn_udata = kev->udata;

	/* recalculate deadline */
	error = filt_timervalidate(kn);
	if (error) {
		/* no way to report error, so mark it in the knote */
		filt_timerunlock();
		kn->kn_flags |= EV_ERROR;
		kn->kn_data = error;
		return 1;
	}

	/* start timer if necessary */
	filt_timerupdate(kn, 1);

	if (kn->kn_ext[0]) {
		unsigned int timer_flags = 0;
		if (kn->kn_sfflags & NOTE_CRITICAL)
			timer_flags |= THREAD_CALL_DELAY_USER_CRITICAL;
		else if (kn->kn_sfflags & NOTE_BACKGROUND)
			timer_flags |= THREAD_CALL_DELAY_USER_BACKGROUND;
		else
			timer_flags |= THREAD_CALL_DELAY_USER_NORMAL;

		if (kn->kn_sfflags & NOTE_LEEWAY)
			timer_flags |= THREAD_CALL_DELAY_LEEWAY;

		thread_call_enter_delayed_with_leeway(kn->kn_hook, NULL,
				kn->kn_ext[0], kn->kn_ext[1], timer_flags);

		kn->kn_hookid |= TIMER_RUNNING;
	} else {
		/* pretend the timer has fired */
		kn->kn_data = 1;
	}

	/* capture if already fired */
	res = (kn->kn_data > 0);

	filt_timerunlock();

	return res;
}

/*
 * filt_timerprocess - query state of knote and snapshot event data
 *
 * Determine if the timer has fired in the past, snapshot the state
 * of the kevent for returning to user-space, and clear pending event
 * counters for the next time.
 */
static int
filt_timerprocess(
	struct knote *kn,
	__unused struct filt_process_s *data,
	struct kevent_internal_s *kev)
{
	filt_timerlock();

	/* user-query */
	if (kn->kn_data == 0) {
		filt_timerunlock();
		return 0;
	}

	/*
	 * Copy out the interesting kevent state,
	 * but don't leak out the raw time calculations.
	 */
	*kev = kn->kn_kevent;
	kev->ext[0] = 0;
	/* kev->ext[1] = 0;  JMM - shouldn't we hide this too? */

	/*
	 * reset the timer pop count in kn_data
	 * and (optionally) clear the fflags.
	 */
	kn->kn_data = 0;
	if (kn->kn_flags & EV_CLEAR)
		kn->kn_fflags = 0;

	filt_timerunlock();
	return 1;
}

static void
filt_timerlock(void)
{
	lck_mtx_lock(&_filt_timerlock);
}

static void
filt_timerunlock(void)
{
	lck_mtx_unlock(&_filt_timerlock);
}

static void
filt_userlock(void)
{
	lck_spin_lock(&_filt_userlock);
}

static void
filt_userunlock(void)
{
	lck_spin_unlock(&_filt_userlock);
}

static int
filt_userattach(struct knote *kn)
{
	/* EVFILT_USER knotes are not attached to anything in the kernel */
	/* Cant discover this knote until after attach - so no lock needed */
	kn->kn_hook = NULL;
	if (kn->kn_fflags & NOTE_TRIGGER) {
		kn->kn_hookid = 1;
	} else {
		kn->kn_hookid = 0;
	}
	return (kn->kn_hookid);
}

static void
filt_userdetach(__unused struct knote *kn)
{
	/* EVFILT_USER knotes are not attached to anything in the kernel */
}

static int
filt_user(
	__unused struct knote *kn,
	__unused long hint)
{
	panic("filt_user");
	return 0;
}

static int
filt_usertouch(
	struct knote *kn,
	struct kevent_internal_s *kev)
{
	uint32_t ffctrl;
	int fflags;
	int active;

	filt_userlock();

	ffctrl = kev->fflags & NOTE_FFCTRLMASK;
	fflags = kev->fflags & NOTE_FFLAGSMASK;
	switch (ffctrl) {
	case NOTE_FFNOP:
		break;
	case NOTE_FFAND:
		kn->kn_sfflags &= fflags;
		break;
	case NOTE_FFOR:
		kn->kn_sfflags |= fflags;
		break;
	case NOTE_FFCOPY:
		kn->kn_sfflags = fflags;
		break;
	}
	kn->kn_sdata = kev->data;

	if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0)
		kn->kn_udata = kev->udata;

	if (kev->fflags & NOTE_TRIGGER) {
		kn->kn_hookid = 1;
	}
	active = kn->kn_hookid;

	filt_userunlock();

	return (active);
}

static int
filt_userprocess(
	struct knote *kn,
	__unused struct filt_process_s *data,
	struct kevent_internal_s *kev)
{
	filt_userlock();

	if (kn->kn_hookid == 0) {
		filt_userunlock();
		return 0;
	}

	*kev = kn->kn_kevent;
	kev->fflags = (volatile UInt32)kn->kn_sfflags;
	kev->data = kn->kn_sdata;
	if (kn->kn_flags & EV_CLEAR) {
		kn->kn_hookid = 0;
		kn->kn_data = 0;
		kn->kn_fflags = 0;
	}
	filt_userunlock();

	return 1;
}

/*
 * JMM - placeholder for not-yet-implemented filters
 */
static int
filt_badattach(__unused struct knote *kn)
{
	kn->kn_flags |= EV_ERROR;
	kn->kn_data = ENOTSUP;
	return 0;
}

struct kqueue *
kqueue_alloc(struct proc *p, unsigned int flags)
{
	struct filedesc *fdp = p->p_fd;
	struct kqueue *kq = NULL;
	int policy;
	void *hook;
	uint64_t kq_addr_offset;

	if (flags & KEVENT_FLAG_WORKQ) {
		struct kqworkq *kqwq;
		int i;

		kqwq = (struct kqworkq *)zalloc(kqworkq_zone);
		if (kqwq == NULL)
			return NULL;

		kq = &kqwq->kqwq_kqueue;
		bzero(kqwq, sizeof (struct kqworkq));

		kqwq->kqwq_state = KQ_WORKQ;

		for (i = 0; i < KQWQ_NBUCKETS; i++) {
			TAILQ_INIT(&kq->kq_queue[i]);
		}
		for (i = 0; i < KQWQ_NQOS; i++) {
			TAILQ_INIT(&kqwq->kqwq_request[i].kqr_suppressed);
		}

		lck_spin_init(&kqwq->kqwq_reqlock, kq_lck_grp, kq_lck_attr);
		policy = SYNC_POLICY_FIFO;
		hook = (void *)kqwq;
		
	} else {
		struct kqfile *kqf;
		
		kqf = (struct kqfile *)zalloc(kqfile_zone);
		if (kqf == NULL)
			return NULL;

		kq = &kqf->kqf_kqueue;
		bzero(kqf, sizeof (struct kqfile));
		TAILQ_INIT(&kq->kq_queue[0]);
		TAILQ_INIT(&kqf->kqf_suppressed);
		
		policy = SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST;
		hook = NULL;

	}

	waitq_set_init(&kq->kq_wqs, policy, NULL, hook);
	lck_spin_init(&kq->kq_lock, kq_lck_grp, kq_lck_attr);
	kq->kq_p = p;

	if (fdp->fd_knlistsize < 0) {
		proc_fdlock(p);
		if (fdp->fd_knlistsize < 0)
			fdp->fd_knlistsize = 0;	/* this process has had a kq */
		proc_fdunlock(p);
	}

	kq_addr_offset = ((uintptr_t)kq - (uintptr_t)VM_MIN_KERNEL_AND_KEXT_ADDRESS);
	/* Assert that the address can be pointer compacted for use with knote */
	assert(kq_addr_offset < (uint64_t)(1ull << KNOTE_KQ_BITSIZE));
	return (kq);
}

/*
 * kqueue_dealloc - detach all knotes from a kqueue and free it
 *
 * 	We walk each list looking for knotes referencing this
 *	this kqueue.  If we find one, we try to drop it.  But
 *	if we fail to get a drop reference, that will wait
 *	until it is dropped.  So, we can just restart again
 *	safe in the assumption that the list will eventually
 *	not contain any more references to this kqueue (either
 *	we dropped them all, or someone else did).
 *
 *	Assumes no new events are being added to the kqueue.
 *	Nothing locked on entry or exit.
 */
void
kqueue_dealloc(struct kqueue *kq)
{
	struct proc *p;
	struct filedesc *fdp;
	struct knote *kn;
	int i;

	if (kq == NULL)
		return;

	p = kq->kq_p;
	fdp = p->p_fd;

	proc_fdlock(p);
	for (i = 0; i < fdp->fd_knlistsize; i++) {
		kn = SLIST_FIRST(&fdp->fd_knlist[i]);
		while (kn != NULL) {
			if (kq == knote_get_kq(kn)) {
				kqlock(kq);
				proc_fdunlock(p);
				/* drop it ourselves or wait */
				if (kqlock2knotedrop(kq, kn)) {
					knote_drop(kn, p);
				}
				proc_fdlock(p);
				/* start over at beginning of list */
				kn = SLIST_FIRST(&fdp->fd_knlist[i]);
				continue;
			}
			kn = SLIST_NEXT(kn, kn_link);
		}
	}
	if (fdp->fd_knhashmask != 0) {
		for (i = 0; i < (int)fdp->fd_knhashmask + 1; i++) {
			kn = SLIST_FIRST(&fdp->fd_knhash[i]);
			while (kn != NULL) {
				if (kq == knote_get_kq(kn)) {
					kqlock(kq);
					proc_fdunlock(p);
					/* drop it ourselves or wait */
					if (kqlock2knotedrop(kq, kn)) {
						knote_drop(kn, p);
					}
					proc_fdlock(p);
					/* start over at beginning of list */
					kn = SLIST_FIRST(&fdp->fd_knhash[i]);
					continue;
				}
				kn = SLIST_NEXT(kn, kn_link);
			}
		}
	}
	proc_fdunlock(p);

	/*
	 * waitq_set_deinit() remove the KQ's waitq set from
	 * any select sets to which it may belong.
	 */
	waitq_set_deinit(&kq->kq_wqs);
	lck_spin_destroy(&kq->kq_lock, kq_lck_grp);

	if (kq->kq_state & KQ_WORKQ) {
		struct kqworkq *kqwq = (struct kqworkq *)kq;

		lck_spin_destroy(&kqwq->kqwq_reqlock, kq_lck_grp);
		zfree(kqworkq_zone, kqwq);
	} else {
		struct kqfile *kqf = (struct kqfile *)kq;

		zfree(kqfile_zone, kqf);
	}
}

int
kqueue_body(struct proc *p, fp_allocfn_t fp_zalloc, void *cra, int32_t *retval)
{
	struct kqueue *kq;
	struct fileproc *fp;
	int fd, error;

	error = falloc_withalloc(p,
	    &fp, &fd, vfs_context_current(), fp_zalloc, cra);
	if (error) {
		return (error);
	}

	kq = kqueue_alloc(p, 0);
	if (kq == NULL) {
		fp_free(p, fd, fp);
		return (ENOMEM);
	}

	fp->f_flag = FREAD | FWRITE;
	fp->f_ops = &kqueueops;
	fp->f_data = kq;

	proc_fdlock(p);
	*fdflags(p, fd) |= UF_EXCLOSE;
	procfdtbl_releasefd(p, fd, NULL);
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);

	*retval = fd;
	return (error);
}

int
kqueue(struct proc *p, __unused struct kqueue_args *uap, int32_t *retval)
{
	return (kqueue_body(p, fileproc_alloc_init, NULL, retval));
}

static int
kevent_copyin(user_addr_t *addrp, struct kevent_internal_s *kevp, struct proc *p,
    unsigned int flags)
{
	int advance;
	int error;

	if (flags & KEVENT_FLAG_LEGACY32) {
		bzero(kevp, sizeof (*kevp));

		if (IS_64BIT_PROCESS(p)) {
			struct user64_kevent kev64;

			advance = sizeof (kev64);
			error = copyin(*addrp, (caddr_t)&kev64, advance);
			if (error)
				return (error);
			kevp->ident = kev64.ident;
			kevp->filter = kev64.filter;
			kevp->flags = kev64.flags;
			kevp->udata = kev64.udata;
			kevp->fflags = kev64.fflags;
			kevp->data = kev64.data;
		} else {
			struct user32_kevent kev32;

			advance = sizeof (kev32);
			error = copyin(*addrp, (caddr_t)&kev32, advance);
			if (error)
				return (error);
			kevp->ident = (uintptr_t)kev32.ident;
			kevp->filter = kev32.filter;
			kevp->flags = kev32.flags;
			kevp->udata = CAST_USER_ADDR_T(kev32.udata);
			kevp->fflags = kev32.fflags;
			kevp->data = (intptr_t)kev32.data;
		}
	} else if (flags & KEVENT_FLAG_LEGACY64) {
		struct kevent64_s kev64;

		bzero(kevp, sizeof (*kevp));

		advance = sizeof (struct kevent64_s);
		error = copyin(*addrp, (caddr_t)&kev64, advance);
		if (error)
			return(error);
		kevp->ident = kev64.ident;
		kevp->filter = kev64.filter;
		kevp->flags = kev64.flags;
		kevp->udata = kev64.udata;
		kevp->fflags = kev64.fflags;
		kevp->data = kev64.data;
		kevp->ext[0] = kev64.ext[0];
		kevp->ext[1] = kev64.ext[1];
		
	} else {
		struct kevent_qos_s kevqos;

		bzero(kevp, sizeof (*kevp));

		advance = sizeof (struct kevent_qos_s);
		error = copyin(*addrp, (caddr_t)&kevqos, advance);
		if (error)
			return error;
		kevp->ident = kevqos.ident;
		kevp->filter = kevqos.filter;
		kevp->flags = kevqos.flags;
		kevp->qos = kevqos.qos;
//		kevp->xflags = kevqos.xflags;
		kevp->udata = kevqos.udata;
		kevp->fflags = kevqos.fflags;
		kevp->data = kevqos.data;
		kevp->ext[0] = kevqos.ext[0];
		kevp->ext[1] = kevqos.ext[1];
		kevp->ext[2] = kevqos.ext[2];
		kevp->ext[3] = kevqos.ext[3];
	}
	if (!error)
		*addrp += advance;
	return (error);
}

static int
kevent_copyout(struct kevent_internal_s *kevp, user_addr_t *addrp, struct proc *p,
    unsigned int flags)
{
	user_addr_t addr = *addrp;
	int advance;
	int error;

	/* 
	 * fully initialize the differnt output event structure
	 * types from the internal kevent (and some universal
	 * defaults for fields not represented in the internal
	 * form).
	 */
	if (flags & KEVENT_FLAG_LEGACY32) {
		assert((flags & KEVENT_FLAG_STACK_EVENTS) == 0);

		if (IS_64BIT_PROCESS(p)) {
			struct user64_kevent kev64;

			advance = sizeof (kev64);
			bzero(&kev64, advance);
			
			/*
			 * deal with the special case of a user-supplied
			 * value of (uintptr_t)-1.
			 */
			kev64.ident = (kevp->ident == (uintptr_t)-1) ?
				(uint64_t)-1LL : (uint64_t)kevp->ident;

			kev64.filter = kevp->filter;
			kev64.flags = kevp->flags;
			kev64.fflags = kevp->fflags;
			kev64.data = (int64_t) kevp->data;
			kev64.udata = kevp->udata;
			error = copyout((caddr_t)&kev64, addr, advance);
		} else {
			struct user32_kevent kev32;

			advance = sizeof (kev32);
			bzero(&kev32, advance);
			kev32.ident = (uint32_t)kevp->ident;
			kev32.filter = kevp->filter;
			kev32.flags = kevp->flags;
			kev32.fflags = kevp->fflags;
			kev32.data = (int32_t)kevp->data;
			kev32.udata = kevp->udata;
			error = copyout((caddr_t)&kev32, addr, advance);
		}
	} else if (flags & KEVENT_FLAG_LEGACY64) {
		struct kevent64_s kev64;

		advance = sizeof (struct kevent64_s);
		if (flags & KEVENT_FLAG_STACK_EVENTS) {
			addr -= advance;
		}
		bzero(&kev64, advance);
		kev64.ident = kevp->ident;
		kev64.filter = kevp->filter;
		kev64.flags = kevp->flags;
		kev64.fflags = kevp->fflags;
		kev64.data = (int64_t) kevp->data;
		kev64.udata = kevp->udata;
		kev64.ext[0] = kevp->ext[0];
		kev64.ext[1] = kevp->ext[1];
		error = copyout((caddr_t)&kev64, addr, advance);
	} else {
		struct kevent_qos_s kevqos;
	   
		advance = sizeof (struct kevent_qos_s);
		if (flags & KEVENT_FLAG_STACK_EVENTS) {
			addr -= advance;
		}
		bzero(&kevqos, advance);
		kevqos.ident = kevp->ident;
		kevqos.filter = kevp->filter;
		kevqos.flags = kevp->flags;
		kevqos.qos = kevp->qos;
		kevqos.udata = kevp->udata;
		kevqos.fflags = kevp->fflags;
		kevqos.xflags = 0;
		kevqos.data = (int64_t) kevp->data;
		kevqos.ext[0] = kevp->ext[0];
		kevqos.ext[1] = kevp->ext[1];
		kevqos.ext[2] = kevp->ext[2];
		kevqos.ext[3] = kevp->ext[3];
		error = copyout((caddr_t)&kevqos, addr, advance);
	}
	if (!error) {
		if (flags & KEVENT_FLAG_STACK_EVENTS)
			*addrp = addr;
		else
			*addrp = addr + advance;
	}
	return (error);
}

static int
kevent_get_data_size(struct proc *p, 
                     uint64_t data_available,
                     unsigned int flags,
                     user_size_t *residp)
{
	user_size_t resid;
	int error = 0;

	if (data_available != USER_ADDR_NULL) {
		if (flags & KEVENT_FLAG_KERNEL) {
			resid = *(user_size_t *)(uintptr_t)data_available;
		} else if (IS_64BIT_PROCESS(p)) {
			user64_size_t usize;
			error = copyin((user_addr_t)data_available, &usize, sizeof(usize));
			resid = (user_size_t)usize;
		} else {
			user32_size_t usize;
			error = copyin((user_addr_t)data_available, &usize, sizeof(usize));
			resid = (user_size_t)usize;
		}
		if (error)
			return(error);
	} else {
		resid = 0;
	}
	*residp = resid;
	return 0;
}

static int
kevent_put_data_size(struct proc *p, 
                     uint64_t data_available,
                     unsigned int flags,
                     user_size_t resid)
{
	int error = 0;

	if (data_available) {
		if (flags & KEVENT_FLAG_KERNEL) {
			*(user_size_t *)(uintptr_t)data_available = resid;
		} else if (IS_64BIT_PROCESS(p)) {
			user64_size_t usize = (user64_size_t)resid;
			error = copyout(&usize, (user_addr_t)data_available, sizeof(usize));
		} else {
			user32_size_t usize = (user32_size_t)resid;
			error = copyout(&usize, (user_addr_t)data_available, sizeof(usize));
		}
	}
	return error;
}

/*
 * kevent_continue - continue a kevent syscall after blocking
 *
 *	assume we inherit a use count on the kq fileglob.
 */

__attribute__((noreturn))
static void
kevent_continue(__unused struct kqueue *kq, void *data, int error)
{
	struct _kevent *cont_args;
	struct fileproc *fp;
	uint64_t data_available;
	user_size_t data_size;
	user_size_t data_resid;
	unsigned int flags;
	int32_t *retval;
	int noutputs;
	int fd;
	struct proc *p = current_proc();

	cont_args = (struct _kevent *)data;
	data_available = cont_args->data_available;
	flags = cont_args->process_data.fp_flags;
	data_size = cont_args->process_data.fp_data_size;
	data_resid = cont_args->process_data.fp_data_resid;
	noutputs = cont_args->eventout;
	retval = cont_args->retval;
	fd = cont_args->fd;
	fp = cont_args->fp;

	if (fp != NULL)
		fp_drop(p, fd, fp, 0);

	/* don't abandon other output just because of residual copyout failures */
	if (error == 0 && data_available && data_resid != data_size) {
		(void)kevent_put_data_size(p, data_available, flags, data_resid);
	}

	/* don't restart after signals... */
	if (error == ERESTART)
		error = EINTR;
	else if (error == EWOULDBLOCK)
		error = 0;
	if (error == 0)
		*retval = noutputs;
	unix_syscall_return(error);
}

/*
 * kevent - [syscall] register and wait for kernel events
 *
 */
int
kevent(struct proc *p, struct kevent_args *uap, int32_t *retval)
{
	unsigned int flags = KEVENT_FLAG_LEGACY32;

	return kevent_internal(p,
	                       uap->fd,
	                       uap->changelist, uap->nchanges,
	                       uap->eventlist, uap->nevents,
	                       0ULL, 0ULL,
	                       flags,
	                       uap->timeout,
	                       kevent_continue,
	                       retval);
}

int
kevent64(struct proc *p, struct kevent64_args *uap, int32_t *retval)
{
	unsigned int flags;

	/* restrict to user flags and set legacy64 */
	flags = uap->flags & KEVENT_FLAG_USER;
	flags |= KEVENT_FLAG_LEGACY64;

	return kevent_internal(p,
	                       uap->fd,
	                       uap->changelist, uap->nchanges,
	                       uap->eventlist, uap->nevents,
	                       0ULL, 0ULL,
	                       flags,
	                       uap->timeout,
	                       kevent_continue,
	                       retval);
}

int
kevent_qos(struct proc *p, struct kevent_qos_args *uap, int32_t *retval)
{
	/* restrict to user flags */
	uap->flags &= KEVENT_FLAG_USER;

	return kevent_internal(p,
	                       uap->fd,
	                       uap->changelist, uap->nchanges,
	                       uap->eventlist,	uap->nevents,
	                       uap->data_out, (uint64_t)uap->data_available,
	                       uap->flags,
	                       0ULL,
	                       kevent_continue,
	                       retval);
}

int 
kevent_qos_internal(struct proc *p, int fd, 
		    user_addr_t changelist, int nchanges,
		    user_addr_t eventlist, int nevents,
		    user_addr_t data_out, user_size_t *data_available,
		    unsigned int flags, 
		    int32_t *retval) 
{
	return kevent_internal(p,
	                       fd,
	                       changelist, nchanges,
	                       eventlist, nevents,
	                       data_out, (uint64_t)data_available,
	                       (flags | KEVENT_FLAG_KERNEL),
	                       0ULL,
	                       NULL,
	                       retval);
}
 
static int
kevent_get_timeout(struct proc *p,
		   user_addr_t utimeout,
		   unsigned int flags,
		   struct timeval *atvp)
{
	struct timeval atv;
	int error = 0;

	if (flags & KEVENT_FLAG_IMMEDIATE) {
		getmicrouptime(&atv);
	} else if (utimeout != USER_ADDR_NULL) {
		struct timeval rtv;
		if (flags & KEVENT_FLAG_KERNEL) {
			struct timespec *tsp = (struct timespec *)utimeout;
			TIMESPEC_TO_TIMEVAL(&rtv, tsp);
		} else if (IS_64BIT_PROCESS(p)) {
			struct user64_timespec ts;
			error = copyin(utimeout, &ts, sizeof(ts));
			if ((ts.tv_sec & 0xFFFFFFFF00000000ull) != 0)
				error = EINVAL;
			else
				TIMESPEC_TO_TIMEVAL(&rtv, &ts);
		} else {
			struct user32_timespec ts;
			error = copyin(utimeout, &ts, sizeof(ts));
			TIMESPEC_TO_TIMEVAL(&rtv, &ts);
		}
		if (error)
			return (error);
		if (itimerfix(&rtv))
			return (EINVAL);
		getmicrouptime(&atv);
		timevaladd(&atv, &rtv);
	} else {
		/* wait forever value */
		atv.tv_sec = 0;
		atv.tv_usec = 0;
	}
	*atvp = atv;
	return 0;
}

static int
kevent_set_kq_mode(struct kqueue *kq, unsigned int flags)
{
	/* each kq should only be used for events of one type */
	kqlock(kq);
	if (kq->kq_state & (KQ_KEV32 | KQ_KEV64 | KQ_KEV_QOS)) {
		if (flags & KEVENT_FLAG_LEGACY32) {
			if ((kq->kq_state & KQ_KEV32) == 0) {
				kqunlock(kq);
				return EINVAL;
			}
		} else if (kq->kq_state & KQ_KEV32) {
			kqunlock(kq);
			return EINVAL;
		}
	} else if (flags & KEVENT_FLAG_LEGACY32) {
		kq->kq_state |= KQ_KEV32;
	} else {
		/* JMM - set KQ_KEVQOS when we are ready for exclusive */
		kq->kq_state |= KQ_KEV64;
	}
	kqunlock(kq);
	return 0;
}

static int
kevent_get_kq(struct proc *p, int fd, unsigned int flags, struct fileproc **fpp, struct kqueue **kqp)
{
	struct fileproc *fp = NULL;
	struct kqueue *kq;
	int error;

	if (flags & KEVENT_FLAG_WORKQ) {
		/*
		 * use the private kq associated with the proc workq.
		 * Just being a thread within the process (and not
		 * being the exit/exec thread) is enough to hold a
		 * reference on this special kq.
		 */
		kq = p->p_wqkqueue;
		if (kq == NULL) {
			struct kqueue *alloc_kq = kqueue_alloc(p, KEVENT_FLAG_WORKQ);
			if (alloc_kq == NULL)
				return ENOMEM;

			proc_fdlock(p);
			if (p->p_wqkqueue == NULL) {
				kq = p->p_wqkqueue = alloc_kq;
				proc_fdunlock(p);
			} else {
				proc_fdunlock(p);
				kq = p->p_wqkqueue;
				kqueue_dealloc(alloc_kq);
			}
		}
	} else {
		/* get a usecount for the kq itself */
		if ((error = fp_getfkq(p, fd, &fp, &kq)) != 0)
			return (error);
	}
	if ((error = kevent_set_kq_mode(kq, flags)) != 0) {
		/* drop the usecount */
		if (fp != NULL)
			fp_drop(p, fd, fp, 0);
		return error;
	} 

	*fpp = fp;
	*kqp = kq;
	return 0;
}


static int
kevent_internal(struct proc *p, 
		int fd,
		user_addr_t changelist, int nchanges,
		user_addr_t ueventlist, int nevents,
		user_addr_t data_out, uint64_t data_available,
		unsigned int flags, 
		user_addr_t utimeout,
		kqueue_continue_t continuation,
		int32_t *retval)
{
	struct _kevent *cont_args;
	uthread_t ut;
	struct kqueue *kq;
	struct fileproc *fp = NULL;
	struct kevent_internal_s kev;
	int error, noutputs;
	struct timeval atv;
	user_size_t data_size;
	user_size_t data_resid;

	/* Don't allow user-space threads to process output events from the workq kq */
	if ((flags & (KEVENT_FLAG_WORKQ | KEVENT_FLAG_KERNEL)) == KEVENT_FLAG_WORKQ &&
	    !(flags & KEVENT_FLAG_ERROR_EVENTS) && nevents > 0)
		return EINVAL;

	/* prepare to deal with stack-wise allocation of out events */
	if (flags & KEVENT_FLAG_STACK_EVENTS) {
		int scale = ((flags & KEVENT_FLAG_LEGACY32) ? 
			     (IS_64BIT_PROCESS(p) ? sizeof(struct user64_kevent) :
			                            sizeof(struct user32_kevent)) :
			     ((flags & KEVENT_FLAG_LEGACY64) ? sizeof(struct kevent64_s) :
			                                       sizeof(struct kevent_qos_s)));
		ueventlist += nevents * scale;
	}

	/* convert timeout to absolute - if we have one (and not immediate) */
	error = kevent_get_timeout(p, utimeout, flags, &atv);
	if (error)
		return error;
	
	/* copyin initial value of data residual from data_available */
	error = kevent_get_data_size(p, data_available, flags, &data_size);
	if (error)
		return error;

	/* get the kq we are going to be working on */
	error = kevent_get_kq(p, fd, flags, &fp, &kq);
	if (error)
		return error;

	/* register all the change requests the user provided... */
	noutputs = 0;
	while (nchanges > 0 && error == 0) {
		error = kevent_copyin(&changelist, &kev, p, flags);
		if (error)
			break;

		/* Make sure user doesn't pass in any system flags */
		kev.flags &= ~EV_SYSFLAGS;

		kevent_register(kq, &kev, p);

		if (nevents > 0 &&
		    ((kev.flags & EV_ERROR) || (kev.flags & EV_RECEIPT))) {
			if (kev.flags & EV_RECEIPT) {
				kev.flags |= EV_ERROR;
				kev.data = 0;
			}
			error = kevent_copyout(&kev, &ueventlist, p, flags);
			if (error == 0) {
				nevents--;
				noutputs++;
			}
		} else if (kev.flags & EV_ERROR) {
			error = kev.data;
		}
		nchanges--;
	}

	/* short-circuit the scan if we only want error events */
	if (flags & KEVENT_FLAG_ERROR_EVENTS)
		nevents = 0;

	/* process pending events */
	if (nevents > 0 && noutputs == 0 && error == 0) {

		/* store the continuation/completion data in the uthread */
		ut = (uthread_t)get_bsdthread_info(current_thread());
		cont_args = &ut->uu_kevent.ss_kevent;
		cont_args->fp = fp;
		cont_args->fd = fd;
		cont_args->retval = retval;
		cont_args->eventlist = ueventlist;
		cont_args->eventcount = nevents;
		cont_args->eventout = noutputs;
		cont_args->data_available = data_available;
		cont_args->process_data.fp_fd = fd;
		cont_args->process_data.fp_flags = flags;
		cont_args->process_data.fp_data_out = data_out;
		cont_args->process_data.fp_data_size = data_size;
		cont_args->process_data.fp_data_resid = data_size;

		error = kqueue_scan(kq, kevent_callback,
		                    continuation, cont_args,
		                    &cont_args->process_data,
		                    &atv, p);

		/* process remaining outputs */
		noutputs = cont_args->eventout;
		data_resid = cont_args->process_data.fp_data_resid;

		/* copyout residual data size value (if it needs to be copied out) */
		/* don't abandon other output just because of residual copyout failures */
		if (error == 0 && data_available && data_resid != data_size) {
			(void)kevent_put_data_size(p, data_available, flags, data_resid);
		}
	}

	/* don't restart after signals... */
	if (error == ERESTART)
		error = EINTR;
	else if (error == EWOULDBLOCK)
		error = 0;
	if (error == 0)
		*retval = noutputs;
	if (fp != NULL)
		fp_drop(p, fd, fp, 0);
	return (error);
}


/*
 * kevent_callback - callback for each individual event
 *
 * called with nothing locked
 * caller holds a reference on the kqueue
 */
static int
kevent_callback(__unused struct kqueue *kq, struct kevent_internal_s *kevp,
    void *data)
{
	struct _kevent *cont_args;
	int error;

	cont_args = (struct _kevent *)data;
	assert(cont_args->eventout < cont_args->eventcount);

	/*
	 * Copy out the appropriate amount of event data for this user.
	 */
	error = kevent_copyout(kevp, &cont_args->eventlist, current_proc(),
			       cont_args->process_data.fp_flags);

	/*
	 * If there isn't space for additional events, return
	 * a harmless error to stop the processing here
	 */
	if (error == 0 && ++cont_args->eventout == cont_args->eventcount)
		error = EWOULDBLOCK;
	return (error);
}

/*
 * kevent_description - format a description of a kevent for diagnostic output
 *
 * called with a 256-byte string buffer
 */

char *
kevent_description(struct kevent_internal_s *kevp, char *s, size_t n)
{
	snprintf(s, n,
	    "kevent="
	    "{.ident=%#llx, .filter=%d, .flags=%#x, .udata=%#llx, .fflags=%#x, .data=%#llx, .ext[0]=%#llx, .ext[1]=%#llx}",
	    kevp->ident,
	    kevp->filter,
	    kevp->flags,
	    kevp->udata,
	    kevp->fflags,
	    kevp->data,
	    kevp->ext[0],
	    kevp->ext[1] );

	return (s);
}

/*
 * kevent_register - add a new event to a kqueue
 *
 *	Creates a mapping between the event source and
 *	the kqueue via a knote data structure.
 *
 *	Because many/most the event sources are file
 *	descriptor related, the knote is linked off
 *	the filedescriptor table for quick access.
 *
 *	called with nothing locked
 *	caller holds a reference on the kqueue
 */

void
kevent_register(struct kqueue *kq, struct kevent_internal_s *kev,
    __unused struct proc *ctxp)
{
	struct proc *p = kq->kq_p;
	struct filterops *fops;
	struct knote *kn = NULL;
	int result = 0;
	int error = 0;

	if (kev->filter < 0) {
		if (kev->filter + EVFILT_SYSCOUNT < 0) {
			error = EINVAL;
			goto out;
		}
		fops = sysfilt_ops[~kev->filter];	/* to 0-base index */
	} else {
		error = EINVAL;
		goto out;
	}

	/* restrict EV_VANISHED to adding udata-specific dispatch kevents */
	if ((kev->flags & EV_VANISHED) &&
	    (kev->flags & (EV_ADD | EV_DISPATCH2)) != (EV_ADD | EV_DISPATCH2)) {
		error = EINVAL;
		goto out;
	}

	/* Simplify the flags - delete and disable overrule */
	if (kev->flags & EV_DELETE)
		kev->flags &= ~EV_ADD;
	if (kev->flags & EV_DISABLE)
		kev->flags &= ~EV_ENABLE;

restart:

	proc_fdlock(p);

	/* find the matching knote from the fd tables/hashes */
	kn = knote_fdfind(kq, kev, p);

	if (kn == NULL) {
		if (kev->flags & EV_ADD) {
			struct fileproc *fp = NULL;

			/* grab a file reference for the new knote */
			if (fops->f_isfd) {
				if ((error = fp_lookup(p, kev->ident, &fp, 1)) != 0) {
					proc_fdunlock(p);
					goto out;
				}
			}

			kn = knote_alloc();
			if (kn == NULL) {
				proc_fdunlock(p);
				error = ENOMEM;
				if (fp != NULL)
					fp_drop(p, kev->ident, fp, 0);
				goto out;
			}

			kn->kn_fp = fp;
			knote_set_kq(kn,kq);
			kn->kn_filtid = ~kev->filter;
			kn->kn_inuse = 1;  /* for f_attach() */
			kn->kn_status = KN_ATTACHING | KN_ATTACHED;

			/* was vanish support requested */
			if (kev->flags & EV_VANISHED) {
				kev->flags &= ~EV_VANISHED;
				kn->kn_status |= KN_REQVANISH;
			}

			/* snapshot matching/dispatching protcol flags into knote */
			if (kev->flags & EV_DISPATCH)
				kn->kn_status |= KN_DISPATCH;
			if (kev->flags & EV_UDATA_SPECIFIC)
				kn->kn_status |= KN_UDATA_SPECIFIC;

			/*
			 * copy the kevent state into knote
			 * protocol is that fflags and data
			 * are saved off, and cleared before
			 * calling the attach routine.
			 */
			kn->kn_kevent = *kev;
			kn->kn_sfflags = kev->fflags;
			kn->kn_sdata = kev->data;
			kn->kn_fflags = 0;
			kn->kn_data = 0;

			/* invoke pthread kext to convert kevent qos to thread qos */
			if (kq->kq_state & KQ_WORKQ) {
				kn->kn_qos = canonicalize_kevent_qos(kn->kn_qos);
				knote_set_qos_index(kn, qos_index_from_qos(kn->kn_qos, FALSE));
				knote_set_qos_override_index(kn, QOS_INDEX_KQFILE);
				assert(knote_get_qos_index(kn) < KQWQ_NQOS);
			} else {
				knote_set_qos_index(kn, QOS_INDEX_KQFILE);
				knote_set_qos_override_index(kn, QOS_INDEX_KQFILE);
			}

			/* before anyone can find it */
			if (kev->flags & EV_DISABLE)
				knote_disable(kn);

			/* Add the knote for lookup thru the fd table */
			error = knote_fdadd(kn, p);
			proc_fdunlock(p);

			if (error) {
				knote_free(kn);
				if (fp != NULL)
					fp_drop(p, kev->ident, fp, 0);
				goto out;
			}

			/* fp reference count now applies to knote */

			/* call filter attach routine */
			result = fops->f_attach(kn);

			/*
			 * Trade knote use count for kq lock.
			 * Cannot be dropped because we held
			 * KN_ATTACHING throughout.
			 */
			knoteuse2kqlock(kq, kn, 1);

			if (kn->kn_flags & EV_ERROR) {
				/*
				 * Failed to attach correctly, so drop.
				 * All other possible users/droppers
				 * have deferred to us.  Save the error
				 * to return to our caller.
				 */
				kn->kn_status &= ~KN_ATTACHED;
				kn->kn_status |= KN_DROPPING;
				error = kn->kn_data;
				kqunlock(kq);
				knote_drop(kn, p);
				goto out;
			}

			/* end "attaching" phase - now just attached */
			kn->kn_status &= ~KN_ATTACHING;

			if (kn->kn_status & KN_DROPPING) {
				/*
				 * Attach succeeded, but someone else
				 * deferred their drop - now we have
				 * to do it for them.
				 */
				kqunlock(kq);
				knote_drop(kn, p);
				goto out;
			}

			/*
			 * If the attach routine indicated that an
			 * event is already fired, activate the knote.
			 */
			if (result)
				knote_activate(kn);

		} else {
			proc_fdunlock(p);
			error = ENOENT;
			goto out;
		}

	} else {
		/* existing knote - get kqueue lock */
		kqlock(kq);
		proc_fdunlock(p);

		if ((kn->kn_status & (KN_DROPPING | KN_ATTACHING)) != 0) {
			/*
			 * The knote is not in a stable state, wait for that
			 * transition to complete and then redrive the lookup.
			 */
			kn->kn_status |= KN_USEWAIT;
			waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
			                    CAST_EVENT64_T(&kn->kn_status),
			                    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
			kqunlock(kq);
			thread_block(THREAD_CONTINUE_NULL);
			goto restart;
		}

		if (kev->flags & EV_DELETE) {

			/*
			 * If attempting to delete a disabled dispatch2 knote,
			 * we must wait for the knote to be re-enabled (unless
			 * it is being re-enabled atomically here).
			 */
			if ((kev->flags & EV_ENABLE) == 0 &&
			    (kn->kn_status & (KN_DISPATCH2 | KN_DISABLED)) ==
			                     (KN_DISPATCH2 | KN_DISABLED)) {
				kn->kn_status |= KN_DEFERDELETE;
				kqunlock(kq);
				error = EINPROGRESS;
			} else if (kqlock2knotedrop(kq, kn)) {
				knote_drop(kn, p);
			} else {
				/*
				 * The kqueue is unlocked, it's not being
				 * dropped, and kqlock2knotedrop returned 0:
				 * this means that someone stole the drop of
				 * the knote from us.
				 */
				error = EINPROGRESS;
			}
			goto out;
		}

		/*
		 * If we are re-enabling a deferred-delete knote,
		 * just enable it now and avoid calling the
		 * filter touch routine (it has delivered its
		 * last event already).
		 */
		if ((kev->flags & EV_ENABLE) &&
		    (kn->kn_status & KN_DEFERDELETE)) {
			assert(kn->kn_status & KN_DISABLED);
			knote_activate(kn);
			knote_enable(kn);
			kqunlock(kq);
			goto out;
		}

		/*
		 * If we are disabling, do it before unlocking and
		 * calling the touch routine (so no processing can
		 * see the new kevent state before the disable is
		 * applied).
		 */
		if (kev->flags & EV_DISABLE)
			knote_disable(kn);

		/*
		 * Convert the kqlock to a use reference on the
		 * knote so we can call the filter touch routine.
		 */
		if (kqlock2knoteuse(kq, kn)) {

			/*
			 * Call touch routine to notify filter of changes
			 * in filter values (and to re-determine if any
			 * events are fired).
			 */
			result = knote_fops(kn)->f_touch(kn, kev);

			/* Get the kq lock back (don't defer droppers). */
			if (!knoteuse2kqlock(kq, kn, 0)) {
				kqunlock(kq);
				goto out;
			}

			/* Activate it if the touch routine said to */
			if (result)
				knote_activate(kn);
		}

		/* Enable the knote if called for */
		if (kev->flags & EV_ENABLE)
			knote_enable(kn);

	}

	/* still have kqlock held and knote is valid */
	kqunlock(kq);

 out:
	/* output local errors through the kevent */
	if (error) {
		kev->flags |= EV_ERROR;
		kev->data = error;
	}
}


/*
 * knote_process - process a triggered event
 *
 *	Validate that it is really still a triggered event
 *	by calling the filter routines (if necessary).  Hold
 *	a use reference on the knote to avoid it being detached.
 *
 *	If it is still considered triggered, we will have taken
 *	a copy of the state under the filter lock.  We use that
 *	snapshot to dispatch the knote for future processing (or
 *	not, if this was a lost event).
 *
 *	Our caller assures us that nobody else can be processing
 *	events from this knote during the whole operation. But
 *	others can be touching or posting events to the knote
 *	interspersed with our processing it.
 *
 *	caller holds a reference on the kqueue.
 *	kqueue locked on entry and exit - but may be dropped
 */
static int
knote_process(struct knote *kn,	
	kevent_callback_t callback,
	void *callback_data,
	struct filt_process_s *process_data,
	struct proc *p)
{
	struct kevent_internal_s kev;
	struct kqueue *kq = knote_get_kq(kn);
	int result = 0;
	int error = 0;

	bzero(&kev, sizeof(kev));

	/*
	 * Must be active or stayactive
	 * Must be queued and not disabled/suppressed
	 */
	assert(kn->kn_status & KN_QUEUED);
	assert(kn->kn_status & (KN_ACTIVE|KN_STAYACTIVE));
	assert(!(kn->kn_status & (KN_DISABLED|KN_SUPPRESSED|KN_DROPPING)));

	/*
	 * For deferred-drop or vanished events, we just create a fake
	 * event to acknowledge end-of-life.  Otherwise, we call the
	 * filter's process routine to snapshot the kevent state under
	 * the filter's locking protocol.
	 */
	if (kn->kn_status & (KN_DEFERDELETE | KN_VANISHED)) {
		/* create fake event */
		kev.filter = kn->kn_filter;
		kev.ident = kn->kn_id;
		kev.qos = kn->kn_qos;
		kev.flags = (kn->kn_status & KN_DEFERDELETE) ? 
		            EV_DELETE : EV_VANISHED;
		kev.flags |= (EV_DISPATCH2 | EV_ONESHOT);
		kev.udata = kn->kn_udata;
		result = 1;

		knote_suppress(kn);
	} else {

		/* deactivate - so new activations indicate a wakeup */
		knote_deactivate(kn);

		/* suppress knotes to avoid returning the same event multiple times in a single call. */
		knote_suppress(kn);

		/* convert lock to a knote use reference */
		if (!kqlock2knoteuse(kq, kn))
			panic("dropping knote found on queue\n");

		/* call out to the filter to process with just a ref */
		result = knote_fops(kn)->f_process(kn, process_data, &kev);

		/*
		 * convert our reference back to a lock. accept drop
		 * responsibility from others if we've committed to
		 * delivering event data.
		 */
		if (!knoteuse2kqlock(kq, kn, result)) {
			/* knote dropped */
			kn = NULL;
		}
	}

	if (kn != NULL) {
		/*
		 * Determine how to dispatch the knote for future event handling.
		 * not-fired: just return (do not callout, leave deactivated).
		 * One-shot:  If dispatch2, enter deferred-delete mode (unless this is
		 *            is the deferred delete event delivery itself).  Otherwise,
		 *            drop it.
		 * stolendrop:We took responsibility for someone else's drop attempt.
		 *            treat this just like one-shot and prepare to turn it back
		 *            into a deferred delete if required.
		 * Dispatch:  don't clear state, just mark it disabled.
		 * Cleared:   just leave it deactivated.
		 * Others:    re-activate as there may be more events to handle.
		 *            This will not wake up more handlers right now, but
		 *            at the completion of handling events it may trigger
		 *            more handler threads (TODO: optimize based on more than
		 *            just this one event being detected by the filter).
		 */

		if (result == 0)
			return (EJUSTRETURN);

		if ((kev.flags & EV_ONESHOT) || (kn->kn_status & KN_STOLENDROP)) {
			if ((kn->kn_status & (KN_DISPATCH2 | KN_DEFERDELETE)) == KN_DISPATCH2) {
				/* defer dropping non-delete oneshot dispatch2 events */
				kn->kn_status |= KN_DEFERDELETE;
				knote_disable(kn);

				/* if we took over another's drop clear those flags here */
				if (kn->kn_status & KN_STOLENDROP) {
					assert(kn->kn_status & KN_DROPPING);
					/*
					 * the knote will be dropped when the
					 * deferred deletion occurs
					 */
					kn->kn_status &= ~(KN_DROPPING|KN_STOLENDROP);
				}
			} else if (kn->kn_status & KN_STOLENDROP) {
				/* We now own the drop of the knote. */
				assert(kn->kn_status & KN_DROPPING);
				knote_unsuppress(kn);
				kqunlock(kq);
				knote_drop(kn, p);
				kqlock(kq);
			} else if (kqlock2knotedrop(kq, kn)) {
				/* just EV_ONESHOT, _not_ DISPATCH2 */
				knote_drop(kn, p);
				kqlock(kq);
			}
		} else if (kn->kn_status & KN_DISPATCH) {
			/* disable all dispatch knotes */
			knote_disable(kn);
		} else if ((kev.flags & EV_CLEAR) == 0) {
			/* re-activate in case there are more events */
			knote_activate(kn);
		}
	}

	/*
	 * callback to handle each event as we find it.
	 * If we have to detach and drop the knote, do
	 * it while we have the kq unlocked.
	 */
	if (result) {
		kqunlock(kq);
		error = (callback)(kq, &kev, callback_data);
		kqlock(kq);
	}
	return (error);
}


/*
 * Return 0 to indicate that processing should proceed,
 * -1 if there is nothing to process.
 *
 * Called with kqueue locked and returns the same way,
 * but may drop lock temporarily.
 */
static int
kqworkq_begin_processing(struct kqworkq *kqwq, kq_index_t qos_index, int flags)
{
	struct kqrequest *kqr;
	thread_t self = current_thread();
	__assert_only struct uthread *ut = get_bsdthread_info(self);
	thread_t thread;

	assert(kqwq->kqwq_state & KQ_WORKQ);
	assert(qos_index < KQWQ_NQOS);

	kqwq_req_lock(kqwq);
	kqr = kqworkq_get_request(kqwq, qos_index);

	thread = kqr->kqr_thread;

	/* manager skips buckets that haven't ask for its help */
	if (flags & KEVENT_FLAG_WORKQ_MANAGER) {

		/* If nothing for manager to do, just return */
		if ((kqr->kqr_state & KQWQ_THMANAGER) == 0) {
			assert(kqr->kqr_thread != self);
			kqwq_req_unlock(kqwq);
			return -1;
		}

		/* bind manager thread from this time on */
		kqworkq_bind_thread(kqwq, qos_index, self, flags);

	} else {
		/* must have been bound by now */
		assert(thread == self);
		assert(ut->uu_kqueue_bound == qos_index);
		assert((ut->uu_kqueue_flags & flags) == ut->uu_kqueue_flags);
	}

	/* nobody else should still be processing */
	assert(kqr->kqr_state & KQWQ_THREQUESTED);
	assert((kqr->kqr_state & KQWQ_PROCESSING) == 0);
		   
	/* anything left to process? */
	if (kqueue_queue_empty(&kqwq->kqwq_kqueue, qos_index)) {
		kqwq_req_unlock(kqwq);
		return -1;
	}

	/* convert to processing mode */
	/* reset workq triggers and thread requests - maybe processing */
	kqr->kqr_state &= ~(KQWQ_HOOKCALLED | KQWQ_WAKEUP);
	kqr->kqr_state |= KQWQ_PROCESSING;
	kqwq_req_unlock(kqwq);
	return 0;
}

/*
 * Return 0 to indicate that processing should proceed,
 * -1 if there is nothing to process.
 *
 * Called with kqueue locked and returns the same way,
 * but may drop lock temporarily.
 * May block.
 */
static int
kqueue_begin_processing(struct kqueue *kq, kq_index_t qos_index, unsigned int flags)
{
	struct kqtailq *suppressq;

	if (kq->kq_state & KQ_WORKQ)
		return kqworkq_begin_processing((struct kqworkq *)kq, qos_index, flags);

	assert(qos_index == QOS_INDEX_KQFILE);

	/* wait to become the exclusive processing thread */
	for (;;) {
		if (kq->kq_state & KQ_DRAIN)
			return -1;

		if ((kq->kq_state & KQ_PROCESSING) == 0)
			break;

		/* if someone else is processing the queue, wait */
		kq->kq_state |= KQ_PROCWAIT;
		suppressq = kqueue_get_suppressed_queue(kq, qos_index);
		waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
		                    CAST_EVENT64_T(suppressq),
		                    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
		
		kqunlock(kq);
		thread_block(THREAD_CONTINUE_NULL);
		kqlock(kq);
	}

	/* Nobody else processing */

	/* clear pre-posts and KQ_WAKEUP now, in case we bail early */
	waitq_set_clear_preposts(&kq->kq_wqs);
	kq->kq_state &= ~KQ_WAKEUP;
		   
	/* anything left to process? */
	if (kqueue_queue_empty(kq, qos_index))
		return -1;

	/* convert to processing mode */
	kq->kq_state |= KQ_PROCESSING;

	return 0;
}

/*
 *	kqworkq_end_processing - Complete the processing of a workq kqueue
 *
 *	We may have to request new threads.
 *	This can happen there are no waiting processing threads and:
 *	- there were active events we never got to (count > 0)
 *	- we pended waitq hook callouts during processing
 *	- we pended wakeups while processing (or unsuppressing)
 *
 *	Called with kqueue lock held.
 */
static void
kqworkq_end_processing(struct kqworkq *kqwq, kq_index_t qos_index, int flags)
{
#pragma unused(flags)

	struct kqueue *kq = &kqwq->kqwq_kqueue;
	struct kqtailq *suppressq = kqueue_get_suppressed_queue(kq, qos_index);

	thread_t self = current_thread();
	__assert_only struct uthread *ut = get_bsdthread_info(self);
	struct knote *kn;
	struct kqrequest *kqr;
	int queued_events;
	uint16_t pended;
	thread_t thread;

	assert(kqwq->kqwq_state & KQ_WORKQ);
	assert(qos_index < KQWQ_NQOS);

	/* leave early if we are not even processing */
	kqwq_req_lock(kqwq);
	kqr = kqworkq_get_request(kqwq, qos_index);
	thread = kqr->kqr_thread;

	if (flags & KEVENT_FLAG_WORKQ_MANAGER) {
		assert(ut->uu_kqueue_bound == KQWQ_QOS_MANAGER);
		assert(ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ_MANAGER);

		/* if this bucket didn't need manager help, bail */
		if ((kqr->kqr_state & KQWQ_THMANAGER) == 0) {
			assert(thread != self);
			kqwq_req_unlock(kqwq);
			return;
		}

		assert(kqr->kqr_state & KQWQ_THREQUESTED);

		/* unbound bucket - see if still needs servicing */
		if (thread == THREAD_NULL) {
			assert((kqr->kqr_state & KQWQ_PROCESSING) == 0);
			assert(TAILQ_EMPTY(suppressq));
		} else {
			assert(thread == self);
		}

	} else {
		assert(thread == self);
		assert(ut->uu_kqueue_bound == qos_index);
		assert((ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ_MANAGER) == 0);
	}

	kqwq_req_unlock(kqwq);

	/* Any events queued before we put suppressed ones back? */
	queued_events = !kqueue_queue_empty(kq, qos_index);

	/*
	 * Return suppressed knotes to their original state.
	 * For workq kqueues, suppressed ones that are still
	 * truly active (not just forced into the queue) will
	 * set flags we check below to see if anything got
	 * woken up.
	 */
	while ((kn = TAILQ_FIRST(suppressq)) != NULL) {
		assert(kn->kn_status & KN_SUPPRESSED);
		knote_unsuppress(kn);
	}

	kqwq_req_lock(kqwq);

	/* Determine if wakeup-type events were pended during servicing */
	pended = (kqr->kqr_state & (KQWQ_HOOKCALLED | KQWQ_WAKEUP));

	/* unbind thread thread */
	kqworkq_unbind_thread(kqwq, qos_index, self, flags);

	/* Indicate that we are done processing */
	kqr->kqr_state &= ~(KQWQ_PROCESSING | \
	                    KQWQ_THREQUESTED | KQWQ_THMANAGER);

	/*
	 * request a new thread if events have happened
	 * (not just putting stay-active events back).
	 */
	if ((queued_events || pended) &&
	    !kqueue_queue_empty(kq, qos_index)) {
		kqworkq_request_thread(kqwq, qos_index);
	}

	kqwq_req_unlock(kqwq);
}

/*
 * Called with kqueue lock held.
 */
static void
kqueue_end_processing(struct kqueue *kq, kq_index_t qos_index, unsigned int flags)
{
	struct knote *kn;
	struct kqtailq *suppressq;
	int procwait;

	if (kq->kq_state & KQ_WORKQ) {
		kqworkq_end_processing((struct kqworkq *)kq, qos_index, flags);
		return;
	}

	assert(qos_index == QOS_INDEX_KQFILE);

	/*
	 * Return suppressed knotes to their original state.
	 * For workq kqueues, suppressed ones that are still
	 * truly active (not just forced into the queue) will
	 * set flags we check below to see if anything got
	 * woken up.
	 */
	suppressq = kqueue_get_suppressed_queue(kq, qos_index);
	while ((kn = TAILQ_FIRST(suppressq)) != NULL) {
		assert(kn->kn_status & KN_SUPPRESSED);
		knote_unsuppress(kn);
	}

	procwait = (kq->kq_state & KQ_PROCWAIT);
	kq->kq_state &= ~(KQ_PROCESSING | KQ_PROCWAIT);

	if (procwait) {
		/* first wake up any thread already waiting to process */
		waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,
		                   CAST_EVENT64_T(suppressq),
		                   THREAD_AWAKENED,
		                   WAITQ_ALL_PRIORITIES);
	}		
}

/*
 *	kevent_qos_internal_bind - bind thread to processing kqueue
 *
 *	Indicates that the provided thread will be responsible for
 *	servicing the particular QoS class index specified in the
 *	parameters. Once the binding is done, any overrides that may
 *	be associated with the cooresponding events can be applied.
 *
 *	This should be called as soon as the thread identity is known,
 *	preferably while still at high priority during creation.
 *
 *  - caller holds a reference on the kqueue.
 *	- the thread MUST call kevent_qos_internal after being bound
 *	  or the bucket of events may never be delivered.  
 *	- Nothing locked (may take mutex or block).
 */

int
kevent_qos_internal_bind(
	struct proc *p,
	int qos_class,
	thread_t thread,
	unsigned int flags)
{
	struct fileproc *fp = NULL;
	struct kqueue *kq = NULL;
	struct kqworkq *kqwq;
	struct kqrequest *kqr;
	struct uthread *ut;
	kq_index_t qos_index;
	int res = 0;

	assert(thread != THREAD_NULL);
	assert(flags & KEVENT_FLAG_WORKQ);

	if (thread == THREAD_NULL ||
	    (flags & KEVENT_FLAG_WORKQ) == 0) {
		return EINVAL;
	}

	ut = get_bsdthread_info(thread);

	/* find the kqueue */
	res = kevent_get_kq(p, -1, flags, &fp, &kq);
	assert(fp == NULL);
	if (res)
		return res;

	/* get the qos index we're going to service */
	qos_index = qos_index_for_servicer(qos_class, thread, flags);
	
	/* No need to bind the manager thread to any bucket */
	if (qos_index == KQWQ_QOS_MANAGER) {
		assert(ut->uu_kqueue_bound == 0);
		ut->uu_kqueue_bound = qos_index;
		ut->uu_kqueue_flags = flags;
		return 0;
	}

	kqlock(kq);
	assert(kq->kq_state & KQ_WORKQ);
	
	kqwq = (struct kqworkq *)kq;
	kqr = kqworkq_get_request(kqwq, qos_index);

	kqwq_req_lock(kqwq);

	/* 
	 * A (non-emergency) request should have been made
	 * and nobody should already be servicing this bucket.
	 */
	assert(kqr->kqr_state & KQWQ_THREQUESTED);
	assert((kqr->kqr_state & KQWQ_THMANAGER) == 0);
	assert((kqr->kqr_state & KQWQ_PROCESSING) == 0);

	/* Is this is an extraneous bind? */
	if (thread == kqr->kqr_thread) {
		assert(ut->uu_kqueue_bound == qos_index);
		goto out;
	}

	/* nobody else bound and we're not bound elsewhere */
	assert(ut->uu_kqueue_bound == 0);
	assert(ut->uu_kqueue_flags == 0);
	assert(kqr->kqr_thread == THREAD_NULL);

	/* Don't bind if there is a conflict */
	if (kqr->kqr_thread != THREAD_NULL ||
	    (kqr->kqr_state & KQWQ_THMANAGER)) {
		res = EINPROGRESS;
		goto out;
	}

	/* finally bind the thread */
	kqr->kqr_thread = thread;
	ut->uu_kqueue_bound = qos_index;
	ut->uu_kqueue_flags = flags;

	/* add any pending overrides to the thread */
	if (kqr->kqr_override_delta) {
		thread_add_ipc_override(thread, qos_index + kqr->kqr_override_delta);
	}

out:
	kqwq_req_unlock(kqwq);
	kqunlock(kq);

	return res;
}

/*
 *	kevent_qos_internal_unbind - unbind thread from processing kqueue
 *
 *	End processing the per-QoS bucket of events and allow other threads
 *	to be requested for future servicing.  
 *
 *	caller holds a reference on the kqueue.
 *	thread is the current thread.
 */

int
kevent_qos_internal_unbind(
	struct proc *p,
	int qos_class,
	thread_t thread,
	unsigned int flags)
{
	struct kqueue *kq;
	struct uthread *ut;
	struct fileproc *fp = NULL;
	kq_index_t qos_index;
	kq_index_t end_index;
	int res;

	assert(flags & KEVENT_FLAG_WORKQ);
	assert(thread == current_thread());

	if (thread == THREAD_NULL ||
	    (flags & KEVENT_FLAG_WORKQ) == 0)
		return EINVAL;
	    
	/* get the kq */
	res = kevent_get_kq(p, -1, flags, &fp, &kq);
	assert(fp == NULL);
	if (res)
		return res;

	assert(kq->kq_state & KQ_WORKQ);

	/* get the index we have been servicing */
	qos_index = qos_index_for_servicer(qos_class, thread, flags);

	ut = get_bsdthread_info(thread);

	/* early out if we were already unbound - or never bound */
	if (ut->uu_kqueue_bound != qos_index) {
		__assert_only struct kqworkq *kqwq = (struct kqworkq *)kq;
		__assert_only struct kqrequest *kqr = kqworkq_get_request(kqwq, qos_index);

		assert(ut->uu_kqueue_bound == 0);
		assert(ut->uu_kqueue_flags == 0);
		assert(kqr->kqr_thread != thread);
		return EALREADY;
	}

	/* unbind from all the buckets we might own */
	end_index = (qos_index == KQWQ_QOS_MANAGER) ? 
	            0 : qos_index;
	kqlock(kq);
	do {
		kqueue_end_processing(kq, qos_index, flags);
	} while (qos_index-- > end_index);
	kqunlock(kq);

	/* indicate that we are done processing in the uthread */
	ut->uu_kqueue_bound = 0;
	ut->uu_kqueue_flags = 0;

	return 0;
}

/*
 * kqueue_process - process the triggered events in a kqueue
 *
 *	Walk the queued knotes and validate that they are
 *	really still triggered events by calling the filter
 *	routines (if necessary).  Hold a use reference on
 *	the knote to avoid it being detached. For each event
 *	that is still considered triggered, invoke the
 *	callback routine provided.
 *
 *	caller holds a reference on the kqueue.
 *	kqueue locked on entry and exit - but may be dropped
 *	kqueue list locked (held for duration of call)
 */

static int
kqueue_process(struct kqueue *kq,
    kevent_callback_t callback,
    void *callback_data,
    struct filt_process_s *process_data,
    kq_index_t servicer_qos_index,
    int *countp,
    struct proc *p)
{
	unsigned int flags = process_data ? process_data->fp_flags : 0;
	kq_index_t start_index, end_index, i;
	struct knote *kn;
	int nevents = 0;
	int error = 0;

	/*
	 * Based on the native QoS of the servicer,
	 * determine the range of QoSes that need checking
	 */
	start_index = servicer_qos_index;
	end_index = (start_index == KQWQ_QOS_MANAGER) ? 0 : start_index;
	
	i = start_index;

	do {
		if (kqueue_begin_processing(kq, i, flags) == -1) {
			*countp = 0;
			/* Nothing to process */
			continue;
		}

		/*
		 * loop through the enqueued knotes, processing each one and
		 * revalidating those that need it. As they are processed,
		 * they get moved to the inprocess queue (so the loop can end).
		 */
		error = 0;

		struct kqtailq *base_queue = kqueue_get_base_queue(kq, i);
		struct kqtailq *queue = kqueue_get_high_queue(kq, i);
		do {
			while (error == 0 &&
			       (kn = TAILQ_FIRST(queue)) != NULL) {
				/* Process the knote */
				error = knote_process(kn, callback, callback_data, process_data, p);
				if (error == EJUSTRETURN)
					error = 0;
				else
					nevents++;

				/* break out if no more space for additional events */
				if (error == EWOULDBLOCK) {
					if ((kq->kq_state & KQ_WORKQ) == 0)
						kqueue_end_processing(kq, i, flags);
					error = 0;
					goto out;
				}
			}
		} while (error == 0 && queue-- > base_queue);

		/* let somebody else process events if we're not in workq mode */
		if ((kq->kq_state & KQ_WORKQ) == 0)
			kqueue_end_processing(kq, i, flags);

	} while (i-- > end_index);

out:
	*countp = nevents;
	return (error);
}

static void
kqueue_scan_continue(void *data, wait_result_t wait_result)
{
	thread_t self = current_thread();
	uthread_t ut = (uthread_t)get_bsdthread_info(self);
	struct _kqueue_scan * cont_args = &ut->uu_kevent.ss_kqueue_scan;
	struct kqueue *kq = (struct kqueue *)data;
	struct filt_process_s *process_data = cont_args->process_data;
	int error;
	int count;

	/* convert the (previous) wait_result to a proper error */
	switch (wait_result) {
	case THREAD_AWAKENED: {
		kqlock(kq);
	retry:
		error = kqueue_process(kq, cont_args->call, cont_args->data, 
		                       process_data, cont_args->servicer_qos_index,
		                       &count, current_proc());
		if (error == 0 && count == 0) {
			if (kq->kq_state & KQ_WAKEUP)
				goto retry;
			waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
					    KQ_EVENT, THREAD_ABORTSAFE,
					    cont_args->deadline);
			kq->kq_state |= KQ_SLEEP;
			kqunlock(kq);
			thread_block_parameter(kqueue_scan_continue, kq);
			/* NOTREACHED */
		}
		kqunlock(kq);
		} break;
	case THREAD_TIMED_OUT:
		error = EWOULDBLOCK;
		break;
	case THREAD_INTERRUPTED:
		error = EINTR;
		break;
	case THREAD_RESTART:
		error = EBADF;
		break;
	default:
		panic("%s: - invalid wait_result (%d)", __func__,
		    wait_result);
		error = 0;
	}

	/* call the continuation with the results */
	assert(cont_args->cont != NULL);
	(cont_args->cont)(kq, cont_args->data, error);
}


/*
 * kqueue_scan - scan and wait for events in a kqueue
 *
 *	Process the triggered events in a kqueue.
 *
 *	If there are no events triggered arrange to
 *	wait for them. If the caller provided a
 *	continuation routine, then kevent_scan will
 *	also.
 *
 *	The callback routine must be valid.
 *	The caller must hold a use-count reference on the kq.
 */

int
kqueue_scan(struct kqueue *kq,
	    kevent_callback_t callback,
	    kqueue_continue_t continuation,
	    void *callback_data,
	    struct filt_process_s *process_data,
	    struct timeval *atvp,
	    struct proc *p)
{
	thread_continue_t cont = THREAD_CONTINUE_NULL;
	kq_index_t servicer_qos_index;
	unsigned int flags;
	uint64_t deadline;
	int error;
	int first;
	int fd;

	assert(callback != NULL);

	/*
	 * Determine which QoS index we are servicing
	 */
	flags = (process_data) ? process_data->fp_flags : 0;
	fd = (process_data) ? process_data->fp_fd : -1;
	servicer_qos_index = (kq->kq_state & KQ_WORKQ) ?
	    qos_index_for_servicer(fd, current_thread(), flags) :
	    QOS_INDEX_KQFILE;

	first = 1;
	for (;;) {
		wait_result_t wait_result;
		int count;

		/*
		 * Make a pass through the kq to find events already
		 * triggered.
		 */
		kqlock(kq);
		error = kqueue_process(kq, callback, callback_data,
		                       process_data, servicer_qos_index,
		                       &count, p);
		if (error || count)
			break; /* lock still held */

		/* looks like we have to consider blocking */
		if (first) {
			first = 0;
			/* convert the timeout to a deadline once */
			if (atvp->tv_sec || atvp->tv_usec) {
				uint64_t now;

				clock_get_uptime(&now);
				nanoseconds_to_absolutetime((uint64_t)atvp->tv_sec * NSEC_PER_SEC +
							    atvp->tv_usec * (long)NSEC_PER_USEC,
							    &deadline);
				if (now >= deadline) {
					/* non-blocking call */
					error = EWOULDBLOCK;
					break; /* lock still held */
				}
				deadline -= now;
				clock_absolutetime_interval_to_deadline(deadline, &deadline);
			} else {
				deadline = 0; 	/* block forever */
			}

			if (continuation) {
				uthread_t ut = (uthread_t)get_bsdthread_info(current_thread());
				struct _kqueue_scan *cont_args = &ut->uu_kevent.ss_kqueue_scan;

				cont_args->call = callback;
				cont_args->cont = continuation;
				cont_args->deadline = deadline;
				cont_args->data = callback_data;
				cont_args->process_data = process_data;
				cont_args->servicer_qos_index = servicer_qos_index;
				cont = kqueue_scan_continue;
			}
		}

		/* If awakened during processing, try again */
		if (kq->kq_state & KQ_WAKEUP) {
			kqunlock(kq);
			continue;
		}

		/* go ahead and wait */
		waitq_assert_wait64_leeway((struct waitq *)&kq->kq_wqs,
					   KQ_EVENT, THREAD_ABORTSAFE,
					   TIMEOUT_URGENCY_USER_NORMAL,
					   deadline, TIMEOUT_NO_LEEWAY);
		kq->kq_state |= KQ_SLEEP;
		kqunlock(kq);
		wait_result = thread_block_parameter(cont, kq);
		/* NOTREACHED if (continuation != NULL) */

		switch (wait_result) {
		case THREAD_AWAKENED:
			continue;
		case THREAD_TIMED_OUT:
			return EWOULDBLOCK;
		case THREAD_INTERRUPTED:
			return EINTR;
		case THREAD_RESTART:
			return EBADF;
		default:
			panic("%s: - bad wait_result (%d)", __func__,
			    wait_result);
			error = 0;
		}
	}
	kqunlock(kq);
	return (error);
}


/*
 * XXX
 * This could be expanded to call kqueue_scan, if desired.
 */
/*ARGSUSED*/
static int
kqueue_read(__unused struct fileproc *fp,
    __unused struct uio *uio,
    __unused int flags,
    __unused vfs_context_t ctx)
{
	return (ENXIO);
}

/*ARGSUSED*/
static int
kqueue_write(__unused struct fileproc *fp,
    __unused struct uio *uio,
    __unused int flags,
    __unused vfs_context_t ctx)
{
	return (ENXIO);
}

/*ARGSUSED*/
static int
kqueue_ioctl(__unused struct fileproc *fp,
    __unused u_long com,
    __unused caddr_t data,
    __unused vfs_context_t ctx)
{
	return (ENOTTY);
}

/*ARGSUSED*/
static int
kqueue_select(struct fileproc *fp, int which, void *wq_link_id,
    __unused vfs_context_t ctx)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;
	struct kqtailq *queue;
	struct kqtailq *suppressq;
	struct knote *kn;
	int retnum = 0;

	if (which != FREAD)
		return (0);

	kqlock(kq);

	assert((kq->kq_state & KQ_WORKQ) == 0);

	/*
	 * If this is the first pass, link the wait queue associated with the
	 * the kqueue onto the wait queue set for the select().  Normally we
	 * use selrecord() for this, but it uses the wait queue within the
	 * selinfo structure and we need to use the main one for the kqueue to
	 * catch events from KN_STAYQUEUED sources. So we do the linkage manually.
	 * (The select() call will unlink them when it ends).
	 */
	if (wq_link_id != NULL) {
		thread_t cur_act = current_thread();
		struct uthread * ut = get_bsdthread_info(cur_act);

		kq->kq_state |= KQ_SEL;
		waitq_link((struct waitq *)&kq->kq_wqs, ut->uu_wqset,
			   WAITQ_SHOULD_LOCK, (uint64_t *)wq_link_id);

		/* always consume the reserved link object */
		waitq_link_release(*(uint64_t *)wq_link_id);
		*(uint64_t *)wq_link_id = 0;

		/*
		 * selprocess() is expecting that we send it back the waitq
		 * that was just added to the thread's waitq set. In order
		 * to not change the selrecord() API (which is exported to
		 * kexts), we pass this value back through the
		 * void *wq_link_id pointer we were passed. We need to use
		 * memcpy here because the pointer may not be properly aligned
		 * on 32-bit systems.
		 */
		void *wqptr = &kq->kq_wqs;
		memcpy(wq_link_id, (void *)&wqptr, sizeof(void *));
	}

	if (kqueue_begin_processing(kq, QOS_INDEX_KQFILE, 0) == -1) {
		kqunlock(kq);
		return (0);
	}

	queue = kqueue_get_base_queue(kq, QOS_INDEX_KQFILE);
	if (!TAILQ_EMPTY(queue)) {
		/*
		 * there is something queued - but it might be a
		 * KN_STAYACTIVE knote, which may or may not have
		 * any events pending.  Otherwise, we have to walk
		 * the list of knotes to see, and peek at the
		 * (non-vanished) stay-active ones to be really sure.
		 */
		while ((kn = (struct knote *)TAILQ_FIRST(queue)) != NULL) {
			if (kn->kn_status & KN_ACTIVE) {
				retnum = 1;
				goto out;
			}
			assert(kn->kn_status & KN_STAYACTIVE);
			knote_suppress(kn);
		}

		/*
		 * There were no regular events on the queue, so take
		 * a deeper look at the stay-queued ones we suppressed.
		 */
		suppressq = kqueue_get_suppressed_queue(kq, QOS_INDEX_KQFILE);
		while ((kn = (struct knote *)TAILQ_FIRST(suppressq)) != NULL) {
			unsigned peek = 1;

			/* If didn't vanish while suppressed - peek at it */
			if (kqlock2knoteuse(kq, kn)) {

				peek = knote_fops(kn)->f_peek(kn);

				/* if it dropped while getting lock - move on */
				if (!knoteuse2kqlock(kq, kn, 0))
					continue;
			}

			/* unsuppress it */
			knote_unsuppress(kn);

			/* has data or it has to report a vanish */
			if (peek > 0) {
				retnum = 1;
				goto out;
			}
		}
	}

out:
	kqueue_end_processing(kq, QOS_INDEX_KQFILE, 0);
	kqunlock(kq);
	return (retnum);
}

/*
 * kqueue_close -
 */
/*ARGSUSED*/
static int
kqueue_close(struct fileglob *fg, __unused vfs_context_t ctx)
{
	struct kqfile *kqf = (struct kqfile *)fg->fg_data;

	assert((kqf->kqf_state & KQ_WORKQ) == 0);
	kqueue_dealloc(&kqf->kqf_kqueue);
	fg->fg_data = NULL;
	return (0);
}

/*ARGSUSED*/
/*
 * The callers has taken a use-count reference on this kqueue and will donate it
 * to the kqueue we are being added to.  This keeps the kqueue from closing until
 * that relationship is torn down.
 */
static int
kqueue_kqfilter(__unused struct fileproc *fp, struct knote *kn, __unused vfs_context_t ctx)
{
	struct kqfile *kqf = (struct kqfile *)kn->kn_fp->f_data;
	struct kqueue *kq = &kqf->kqf_kqueue;
	struct kqueue *parentkq = knote_get_kq(kn);

	assert((kqf->kqf_state & KQ_WORKQ) == 0);

	if (parentkq == kq ||
	    kn->kn_filter != EVFILT_READ) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = EINVAL;
		return 0;
	}

	/*
	 * We have to avoid creating a cycle when nesting kqueues
	 * inside another.  Rather than trying to walk the whole
	 * potential DAG of nested kqueues, we just use a simple
	 * ceiling protocol.  When a kqueue is inserted into another,
	 * we check that the (future) parent is not already nested
	 * into another kqueue at a lower level than the potenial
	 * child (because it could indicate a cycle).  If that test
	 * passes, we just mark the nesting levels accordingly.
	 */

	kqlock(parentkq);
	if (parentkq->kq_level > 0 &&
	    parentkq->kq_level < kq->kq_level)
	{
		kqunlock(parentkq);
		kn->kn_flags = EV_ERROR;
		kn->kn_data = EINVAL;
		return 0;
	} else {
		/* set parent level appropriately */
		if (parentkq->kq_level == 0)
			parentkq->kq_level = 2;
		if (parentkq->kq_level < kq->kq_level + 1)
			parentkq->kq_level = kq->kq_level + 1;
		kqunlock(parentkq);

		kn->kn_filtid = EVFILTID_KQREAD;
		kqlock(kq);
		KNOTE_ATTACH(&kqf->kqf_sel.si_note, kn);
		/* indicate nesting in child, if needed */
		if (kq->kq_level == 0)
			kq->kq_level = 1;

		int count = kq->kq_count;
		kqunlock(kq);
		return (count > 0);
	}
}

/*
 * kqueue_drain - called when kq is closed
 */
/*ARGSUSED*/
static int
kqueue_drain(struct fileproc *fp, __unused vfs_context_t ctx)
{
	struct kqueue *kq = (struct kqueue *)fp->f_fglob->fg_data;

	assert((kq->kq_state & KQ_WORKQ) == 0);

	kqlock(kq);
	kq->kq_state |= KQ_DRAIN;
	kqueue_interrupt(kq);
	kqunlock(kq);
	return (0);
}

/*ARGSUSED*/
int
kqueue_stat(struct kqueue *kq, void *ub, int isstat64, proc_t p)
{
	assert((kq->kq_state & KQ_WORKQ) == 0);

	kqlock(kq);
	if (isstat64 != 0) {
		struct stat64 *sb64 = (struct stat64 *)ub;

		bzero((void *)sb64, sizeof(*sb64));
		sb64->st_size = kq->kq_count;
		if (kq->kq_state & KQ_KEV_QOS)
			sb64->st_blksize = sizeof(struct kevent_qos_s);
		else if (kq->kq_state & KQ_KEV64)
			sb64->st_blksize = sizeof(struct kevent64_s);
		else if (IS_64BIT_PROCESS(p))
			sb64->st_blksize = sizeof(struct user64_kevent);
		else
			sb64->st_blksize = sizeof(struct user32_kevent);
		sb64->st_mode = S_IFIFO;
	} else {
		struct stat *sb = (struct stat *)ub;

		bzero((void *)sb, sizeof(*sb));
		sb->st_size = kq->kq_count;
		if (kq->kq_state & KQ_KEV_QOS)
			sb->st_blksize = sizeof(struct kevent_qos_s);
		else if (kq->kq_state & KQ_KEV64)
			sb->st_blksize = sizeof(struct kevent64_s);
		else if (IS_64BIT_PROCESS(p))
			sb->st_blksize = sizeof(struct user64_kevent);
		else
			sb->st_blksize = sizeof(struct user32_kevent);
		sb->st_mode = S_IFIFO;
	}
	kqunlock(kq);
	return (0);
}


/*
 * Interact with the pthread kext to request a servicing there.
 * Eventually, this will request threads at specific QoS levels.
 * For now, it only requests a dispatch-manager-QoS thread, and
 * only one-at-a-time.
 *
 * - Caller holds the workq request lock
 *
 * - May be called with the kqueue's wait queue set locked,
 *   so cannot do anything that could recurse on that.
 */
static void
kqworkq_request_thread(
	struct kqworkq *kqwq, 
	kq_index_t qos_index)
{
	struct kqrequest *kqr;

	assert(kqwq->kqwq_state & KQ_WORKQ);
	assert(qos_index < KQWQ_NQOS);

	kqr = kqworkq_get_request(kqwq, qos_index);

	/* 
	 * If we have already requested a thread, and it hasn't
	 * started processing yet, there's no use hammering away
	 * on the pthread kext.
	 */
	if (kqr->kqr_state & KQWQ_THREQUESTED)
		return;

	assert(kqr->kqr_thread == THREAD_NULL);

	/* request additional workq threads if appropriate */
	if (pthread_functions != NULL &&
	    pthread_functions->workq_reqthreads != NULL) {
		unsigned int flags = KEVENT_FLAG_WORKQ;

		/* Compute a priority based on qos_index. */
		struct workq_reqthreads_req_s request = {
			.priority = qos_from_qos_index(qos_index),
			.count = 1
		};

		thread_t wqthread;
		wqthread = (*pthread_functions->workq_reqthreads)(kqwq->kqwq_p, 1, &request);
		kqr->kqr_state |= KQWQ_THREQUESTED;

		/* Have we been switched to the emergency/manager thread? */
		if (wqthread == (thread_t)-1) {
			flags |= KEVENT_FLAG_WORKQ_MANAGER;
			wqthread = THREAD_NULL;
		} else if (qos_index == KQWQ_QOS_MANAGER)
			flags |= KEVENT_FLAG_WORKQ_MANAGER;

		/* bind the thread */
		kqworkq_bind_thread(kqwq, qos_index, wqthread, flags);
	}
}

/*
 * If we aren't already busy processing events [for this QoS],
 * request workq thread support as appropriate.
 *
 * TBD - for now, we don't segregate out processing by QoS.
 *
 * - May be called with the kqueue's wait queue set locked,
 *   so cannot do anything that could recurse on that.
 */
static void
kqworkq_request_help(
	struct kqworkq *kqwq, 
	kq_index_t qos_index,
	uint32_t type)
{
	struct kqrequest *kqr;

	/* convert to thread qos value */
	assert(qos_index < KQWQ_NQOS);
	
	kqwq_req_lock(kqwq);
	kqr = kqworkq_get_request(kqwq, qos_index);

	/*
	 * If someone is processing the queue, just mark what type
	 * of attempt this was (from a kq wakeup or from a waitq hook).
	 * They'll be noticed at the end of servicing and a new thread
	 * will be requested at that point.
	 */
	if (kqr->kqr_state & KQWQ_PROCESSING) {
		kqr->kqr_state |= type;
		kqwq_req_unlock(kqwq);
		return;
	}

	kqworkq_request_thread(kqwq, qos_index);
	kqwq_req_unlock(kqwq);
}

/*
 * These arrays described the low and high qindexes for a given qos_index.
 * The values come from the chart in <sys/eventvar.h> (must stay in sync).
 */
static kq_index_t _kq_base_index[KQWQ_NQOS] = {0, 0, 6, 11, 15, 18, 20, 21};
static kq_index_t _kq_high_index[KQWQ_NQOS] = {0, 5, 10, 14, 17, 19, 20, 21};

static struct kqtailq *
kqueue_get_base_queue(struct kqueue *kq, kq_index_t qos_index)
{
	assert(qos_index < KQWQ_NQOS);
	return &kq->kq_queue[_kq_base_index[qos_index]];
}

static struct kqtailq *
kqueue_get_high_queue(struct kqueue *kq, kq_index_t qos_index)
{
	assert(qos_index < KQWQ_NQOS);
	return &kq->kq_queue[_kq_high_index[qos_index]];
}

static int
kqueue_queue_empty(struct kqueue *kq, kq_index_t qos_index)
{
	struct kqtailq *base_queue = kqueue_get_base_queue(kq, qos_index);
	struct kqtailq *queue = kqueue_get_high_queue(kq, qos_index);

	do {
		if (!TAILQ_EMPTY(queue))
			return 0;
	} while (queue-- > base_queue);
	return 1;
}

static struct kqtailq *
kqueue_get_suppressed_queue(struct kqueue *kq, kq_index_t qos_index)
{
	if (kq->kq_state & KQ_WORKQ) {
		struct kqworkq *kqwq = (struct kqworkq *)kq;
		struct kqrequest *kqr;

		kqr = kqworkq_get_request(kqwq, qos_index);
		return &kqr->kqr_suppressed;
	} else {
		struct kqfile *kqf = (struct kqfile *)kq;
		return &kqf->kqf_suppressed;
	}
}

static kq_index_t
knote_get_queue_index(struct knote *kn)
{
	kq_index_t override_index = knote_get_qos_override_index(kn);
	kq_index_t qos_index = knote_get_qos_index(kn);
	struct kqueue *kq = knote_get_kq(kn);
	kq_index_t res;

	if ((kq->kq_state & KQ_WORKQ) == 0) {
		assert(qos_index == 0);
		assert(override_index == 0);
	}
	res = _kq_base_index[qos_index];
	if (override_index > qos_index)
		res += override_index - qos_index;

	assert(res <= _kq_high_index[qos_index]);
	return res;
}

static struct kqtailq *
knote_get_queue(struct knote *kn)
{
	kq_index_t qindex = knote_get_queue_index(kn);

	return &(knote_get_kq(kn))->kq_queue[qindex];
}

static struct kqtailq *
knote_get_suppressed_queue(struct knote *kn)
{
	kq_index_t qos_index = knote_get_qos_index(kn);
	struct kqueue *kq = knote_get_kq(kn);

	return kqueue_get_suppressed_queue(kq, qos_index);
}

static kq_index_t
knote_get_req_index(struct knote *kn)
{
	return kn->kn_req_index;
}

static kq_index_t
knote_get_qos_index(struct knote *kn)
{
	return kn->kn_qos_index;
}

static void
knote_set_qos_index(struct knote *kn, kq_index_t qos_index)
{
	struct kqueue *kq = knote_get_kq(kn);

	assert(qos_index < KQWQ_NQOS);
	assert((kn->kn_status & KN_QUEUED) == 0);

	if (kq->kq_state & KQ_WORKQ)
		assert(qos_index > QOS_INDEX_KQFILE);
	else
		assert(qos_index == QOS_INDEX_KQFILE);

	/* always set requested */
	kn->kn_req_index = qos_index;

	/* only adjust in-use qos index when not suppressed */
	if ((kn->kn_status & KN_SUPPRESSED) == 0)
		kn->kn_qos_index = qos_index;
}

static kq_index_t
knote_get_qos_override_index(struct knote *kn)
{
	return kn->kn_qos_override;
}

static void
knote_set_qos_override_index(struct knote *kn, kq_index_t override_index)
{
	struct kqueue *kq = knote_get_kq(kn);
	kq_index_t qos_index = knote_get_qos_index(kn);

	assert((kn->kn_status & KN_QUEUED) == 0);

	if (override_index == KQWQ_QOS_MANAGER)
		assert(qos_index == KQWQ_QOS_MANAGER);
	else 
		assert(override_index < KQWQ_QOS_MANAGER);

	kn->kn_qos_override = override_index;

	/* 
	 * If this is a workq kqueue, apply the override to the 
	 * workq servicing thread.  
	 */
	if (kq->kq_state & KQ_WORKQ)  {
		struct kqworkq *kqwq = (struct kqworkq *)kq;

		assert(qos_index > QOS_INDEX_KQFILE);
		kqworkq_update_override(kqwq, qos_index, override_index);
	}
}

static void
kqworkq_update_override(struct kqworkq *kqwq, kq_index_t qos_index, kq_index_t override_index)
{
	struct kqrequest *kqr;
	kq_index_t new_delta;
	kq_index_t old_delta;

	new_delta = (override_index > qos_index) ?
	            override_index - qos_index : 0;

	kqr = kqworkq_get_request(kqwq, qos_index);

	kqwq_req_lock(kqwq);
	old_delta = kqr->kqr_override_delta;

	if (new_delta > old_delta) {
		thread_t wqthread = kqr->kqr_thread;

		/* store the new override delta */
		kqr->kqr_override_delta = new_delta;

		/* apply the override to [incoming?] servicing thread */
		if (wqthread) {
			/* only apply if non-manager */
		    if ((kqr->kqr_state & KQWQ_THMANAGER) == 0) {
				if (old_delta)
					thread_update_ipc_override(wqthread, override_index);
				else
					thread_add_ipc_override(wqthread, override_index);
			}
		}
	}
	kqwq_req_unlock(kqwq);
}

/* called with the kqworkq lock held */
static void
kqworkq_bind_thread(
	struct kqworkq *kqwq,
	kq_index_t qos_index,
	thread_t thread,
	unsigned int flags)
{
	struct kqrequest *kqr = kqworkq_get_request(kqwq, qos_index);
	thread_t old_thread = kqr->kqr_thread;
	struct uthread *ut;

	assert(kqr->kqr_state & KQWQ_THREQUESTED);

	/* If no identity yet, just set flags as needed */
	if (thread == THREAD_NULL) {
		assert(old_thread == THREAD_NULL);

		/* emergency or unindetified */
		if (flags & KEVENT_FLAG_WORKQ_MANAGER) {
			assert((kqr->kqr_state & KQWQ_THMANAGER) == 0);
			kqr->kqr_state |= KQWQ_THMANAGER;
		}
		return;
	}

	/* Known thread identity */
	ut = get_bsdthread_info(thread);

	/* 
	 * If this is a manager, and the manager request bit is
	 * not set, assure no other thread is bound. If the bit
	 * is set, make sure the old thread is us (or not set).
	 */
	if (flags & KEVENT_FLAG_WORKQ_MANAGER) {
		if ((kqr->kqr_state & KQWQ_THMANAGER) == 0) {
			assert(old_thread == THREAD_NULL);
			kqr->kqr_state |= KQWQ_THMANAGER;
		} else if (old_thread == THREAD_NULL) {
			kqr->kqr_thread = thread;
			ut->uu_kqueue_bound = KQWQ_QOS_MANAGER;
			ut->uu_kqueue_flags = (KEVENT_FLAG_WORKQ | 
			                       KEVENT_FLAG_WORKQ_MANAGER);
		} else {
			assert(thread == old_thread);
			assert(ut->uu_kqueue_bound == KQWQ_QOS_MANAGER);
			assert(ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ_MANAGER);
		}
		return;
	}

	/* Just a normal one-queue servicing thread */
	assert(old_thread == THREAD_NULL);
	assert((kqr->kqr_state & KQWQ_THMANAGER) == 0);

	kqr->kqr_thread = thread;
	
	/* apply an ipc QoS override if one is needed */
	if (kqr->kqr_override_delta)
		thread_add_ipc_override(thread, qos_index + kqr->kqr_override_delta);

	/* indicate that we are processing in the uthread */
	ut->uu_kqueue_bound = qos_index;
	ut->uu_kqueue_flags = flags;
}

/* called with the kqworkq lock held */
static void
kqworkq_unbind_thread(
	struct kqworkq *kqwq,
	kq_index_t qos_index,
	thread_t thread, 
	__unused unsigned int flags)
{
	struct kqrequest *kqr = kqworkq_get_request(kqwq, qos_index);
	kq_index_t override = 0;

	assert(thread == current_thread());

	/* 
	 * If there is an override, drop it from the current thread
	 * and then we are free to recompute (a potentially lower)
	 * minimum override to apply to the next thread request.
	 */
	if (kqr->kqr_override_delta) {
		struct kqtailq *base_queue = kqueue_get_base_queue(&kqwq->kqwq_kqueue, qos_index);
		struct kqtailq *queue = kqueue_get_high_queue(&kqwq->kqwq_kqueue, qos_index);

		/* if not bound to a manager thread, drop the current ipc override */
		if ((kqr->kqr_state & KQWQ_THMANAGER) == 0) {
			assert(thread == kqr->kqr_thread);
			thread_drop_ipc_override(thread);
		}

		/* recompute the new override */
		do {
			if (!TAILQ_EMPTY(queue)) {
				override = queue - base_queue;
				break;
			}
		} while (queue-- > base_queue);
	}

	/* unbind the thread and apply the new override */
	kqr->kqr_thread = THREAD_NULL;
	kqr->kqr_override_delta = override;
}

struct kqrequest *
kqworkq_get_request(struct kqworkq *kqwq, kq_index_t qos_index)
{
	assert(qos_index < KQWQ_NQOS);
	return &kqwq->kqwq_request[qos_index];
}

void
knote_adjust_qos(struct knote *kn, qos_t new_qos, qos_t new_override)
{
	if (knote_get_kq(kn)->kq_state & KQ_WORKQ) {
		kq_index_t new_qos_index;
		kq_index_t new_override_index;
		kq_index_t servicer_qos_index;

		new_qos_index = qos_index_from_qos(new_qos, FALSE);
		new_override_index = qos_index_from_qos(new_override, TRUE);

		/* make sure the servicer qos acts as a floor */
		servicer_qos_index = qos_index_from_qos(kn->kn_qos, FALSE);
		if (servicer_qos_index > new_qos_index)
			new_qos_index = servicer_qos_index;
		if (servicer_qos_index > new_override_index)
			new_override_index = servicer_qos_index;

		kqlock(knote_get_kq(kn));
		if (new_qos_index != knote_get_req_index(kn) ||
		    new_override_index != knote_get_qos_override_index(kn)) {
			if (kn->kn_status & KN_QUEUED) {
				knote_dequeue(kn);
				knote_set_qos_index(kn, new_qos_index);
				knote_set_qos_override_index(kn, new_override_index);
				knote_enqueue(kn);
				knote_wakeup(kn);
			} else {
				knote_set_qos_index(kn, new_qos_index);
				knote_set_qos_override_index(kn, new_override_index);
			}
		}
		kqunlock(knote_get_kq(kn));
	}
}

static void
knote_wakeup(struct knote *kn)
{
	struct kqueue *kq = knote_get_kq(kn);

	if (kq->kq_state & KQ_WORKQ) {
		/* request a servicing thread */
		struct kqworkq *kqwq = (struct kqworkq *)kq;
		kq_index_t qos_index = knote_get_qos_index(kn);

		kqworkq_request_help(kqwq, qos_index, KQWQ_WAKEUP);

	} else {
		struct kqfile *kqf = (struct kqfile *)kq;

		/* flag wakeups during processing */
		if (kq->kq_state & KQ_PROCESSING)
			kq->kq_state |= KQ_WAKEUP;

		/* wakeup a thread waiting on this queue */
		if (kq->kq_state & (KQ_SLEEP | KQ_SEL)) {
			kq->kq_state &= ~(KQ_SLEEP | KQ_SEL);
			waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,
			                   KQ_EVENT,
			                   THREAD_AWAKENED,
			                   WAITQ_ALL_PRIORITIES);
		}

		/* wakeup other kqueues/select sets we're inside */
		KNOTE(&kqf->kqf_sel.si_note, 0);
	}
}
	
/*
 * Called with the kqueue locked
 */
static void
kqueue_interrupt(struct kqueue *kq)
{
	assert((kq->kq_state & KQ_WORKQ) == 0);

	/* wakeup sleeping threads */
	if ((kq->kq_state & (KQ_SLEEP | KQ_SEL)) != 0) {
		kq->kq_state &= ~(KQ_SLEEP | KQ_SEL);
		(void)waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,
		                         KQ_EVENT,
		                         THREAD_RESTART,
		                         WAITQ_ALL_PRIORITIES);
	}

	/* wakeup threads waiting their turn to process */
	if (kq->kq_state & KQ_PROCWAIT) {
		struct kqtailq *suppressq;

		assert(kq->kq_state & KQ_PROCESSING);

		kq->kq_state &= ~KQ_PROCWAIT;
		suppressq = kqueue_get_suppressed_queue(kq, QOS_INDEX_KQFILE);
		(void)waitq_wakeup64_all((struct waitq *)&kq->kq_wqs, 
		                         CAST_EVENT64_T(suppressq),
		                         THREAD_RESTART,
		                         WAITQ_ALL_PRIORITIES);
	}
}

/*
 * Called back from waitq code when no threads waiting and the hook was set.
 *
 * Interrupts are likely disabled and spin locks are held - minimal work
 * can be done in this context!!!
 *
 * JMM - in the future, this will try to determine which knotes match the
 * wait queue wakeup and apply these wakeups against those knotes themselves.
 * For now, all the events dispatched this way are dispatch-manager handled,
 * so hard-code that for now.
 */
void
waitq_set__CALLING_PREPOST_HOOK__(void *kq_hook, void *knote_hook, int qos)
{
#pragma unused(knote_hook, qos)

	struct kqworkq *kqwq = (struct kqworkq *)kq_hook;

	assert(kqwq->kqwq_state & KQ_WORKQ);
	kqworkq_request_help(kqwq, KQWQ_QOS_MANAGER, KQWQ_HOOKCALLED);
}

void
klist_init(struct klist *list)
{
	SLIST_INIT(list);
}


/*
 * Query/Post each knote in the object's list
 *
 *	The object lock protects the list. It is assumed
 *	that the filter/event routine for the object can
 *	determine that the object is already locked (via
 *	the hint) and not deadlock itself.
 *
 *	The object lock should also hold off pending
 *	detach/drop operations.  But we'll prevent it here
 *	too (by taking a use reference) - just in case.
 */
void
knote(struct klist *list, long hint)
{
	struct knote *kn;

	SLIST_FOREACH(kn, list, kn_selnext) {
		struct kqueue *kq = knote_get_kq(kn);

		kqlock(kq);

		/* If we can get a use reference - deliver event */
		if (kqlock2knoteuse(kq, kn)) {
			int result;

			/* call the event with only a use count */
			result = knote_fops(kn)->f_event(kn, hint);

			/* if its not going away and triggered */
			if (knoteuse2kqlock(kq, kn, 0) && result)
				knote_activate(kn);
			/* kq lock held */
		}
		kqunlock(kq);
	}
}

/*
 * attach a knote to the specified list.  Return true if this is the first entry.
 * The list is protected by whatever lock the object it is associated with uses.
 */
int
knote_attach(struct klist *list, struct knote *kn)
{
	int ret = SLIST_EMPTY(list);
	SLIST_INSERT_HEAD(list, kn, kn_selnext);
	return (ret);
}

/*
 * detach a knote from the specified list.  Return true if that was the last entry.
 * The list is protected by whatever lock the object it is associated with uses.
 */
int
knote_detach(struct klist *list, struct knote *kn)
{
	SLIST_REMOVE(list, kn, knote, kn_selnext);
	return (SLIST_EMPTY(list));
}

/*
 * knote_vanish - Indicate that the source has vanished
 *
 * If the knote has requested EV_VANISHED delivery,
 * arrange for that. Otherwise, deliver a NOTE_REVOKE
 * event for backward compatibility.
 *
 * The knote is marked as having vanished, but is not
 * actually detached from the source in this instance.
 * The actual detach is deferred until the knote drop.
 *
 * Our caller already has the object lock held. Calling
 * the detach routine would try to take that lock
 * recursively - which likely is not supported.
 */
void
knote_vanish(struct klist *list)
{
	struct knote *kn;
	struct knote *kn_next;

	SLIST_FOREACH_SAFE(kn, list, kn_selnext, kn_next) {
		struct kqueue *kq = knote_get_kq(kn);
		int result;

		kqlock(kq);
		if ((kn->kn_status & KN_DROPPING) == 0) {

			/* If EV_VANISH supported - prepare to deliver one */
			if (kn->kn_status & KN_REQVANISH) {
				kn->kn_status |= KN_VANISHED;
				knote_activate(kn);

			} else if (kqlock2knoteuse(kq, kn)) {
				/* call the event with only a use count */
				result = knote_fops(kn)->f_event(kn, NOTE_REVOKE);
				
				/* if its not going away and triggered */
				if (knoteuse2kqlock(kq, kn, 0) && result)
					knote_activate(kn);
				/* lock held again */
			}
		}
		kqunlock(kq);
	}
}

/*
 * For a given knote, link a provided wait queue directly with the kqueue.
 * Wakeups will happen via recursive wait queue support.  But nothing will move
 * the knote to the active list at wakeup (nothing calls knote()).  Instead,
 * we permanently enqueue them here.
 *
 * kqueue and knote references are held by caller.
 * waitq locked by caller.
 *
 * caller provides the wait queue link structure.
 */
int
knote_link_waitq(struct knote *kn, struct waitq *wq, uint64_t *reserved_link)
{
	struct kqueue *kq = knote_get_kq(kn);
	kern_return_t kr;

	kr = waitq_link(wq, &kq->kq_wqs, WAITQ_ALREADY_LOCKED, reserved_link);
	if (kr == KERN_SUCCESS) {
		knote_markstayactive(kn);
		return (0);
	} else {
		return (EINVAL);
	}
}

/*
 * Unlink the provided wait queue from the kqueue associated with a knote.
 * Also remove it from the magic list of directly attached knotes.
 *
 * Note that the unlink may have already happened from the other side, so
 * ignore any failures to unlink and just remove it from the kqueue list.
 *
 * On success, caller is responsible for the link structure
 */
int
knote_unlink_waitq(struct knote *kn, struct waitq *wq)
{
	struct kqueue *kq = knote_get_kq(kn);
	kern_return_t kr;

	kr = waitq_unlink(wq, &kq->kq_wqs);
	knote_clearstayactive(kn);
	return ((kr != KERN_SUCCESS) ? EINVAL : 0);
}

/*
 * remove all knotes referencing a specified fd
 *
 * Essentially an inlined knote_remove & knote_drop
 * when we know for sure that the thing is a file
 *
 * Entered with the proc_fd lock already held.
 * It returns the same way, but may drop it temporarily.
 */
void
knote_fdclose(struct proc *p, int fd, int force)
{
	struct klist *list;
	struct knote *kn;

restart:
	list = &p->p_fd->fd_knlist[fd];
	SLIST_FOREACH(kn, list, kn_link) {
		struct kqueue *kq = knote_get_kq(kn);

		kqlock(kq);

		if (kq->kq_p != p)
			panic("%s: proc mismatch (kq->kq_p=%p != p=%p)",
			    __func__, kq->kq_p, p);

		/*
		 * If the knote supports EV_VANISHED delivery,
		 * transition it to vanished mode (or skip over
		 * it if already vanished).
		 */
		if (!force && (kn->kn_status & KN_REQVANISH)) {

			if ((kn->kn_status & KN_VANISHED) == 0) {
				proc_fdunlock(p);

				/* get detach reference (also marks vanished) */
				if (kqlock2knotedetach(kq, kn)) {

					/* detach knote and drop fp use reference */
					knote_fops(kn)->f_detach(kn);
					if (knote_fops(kn)->f_isfd)
						fp_drop(p, kn->kn_id, kn->kn_fp, 0);

					/* activate it if it's still in existence */
					if (knoteuse2kqlock(kq, kn, 0)) {
						knote_activate(kn);
					}
					kqunlock(kq);
				}
				proc_fdlock(p);
				goto restart;
			} else {
				kqunlock(kq);
				continue;
			}
		}

		proc_fdunlock(p);

		/*
		 * Convert the kq lock to a drop ref.
		 * If we get it, go ahead and drop it.
		 * Otherwise, we waited for the blocking
		 * condition to complete. Either way,
		 * we dropped the fdlock so start over.
		 */
		if (kqlock2knotedrop(kq, kn)) {
			knote_drop(kn, p);
		}

		proc_fdlock(p);
		goto restart;
	}
}

/* 
 * knote_fdadd - Add knote to the fd table for process
 *
 * All file-based filters associate a list of knotes by file
 * descriptor index. All other filters hash the knote by ident.
 *
 * May have to grow the table of knote lists to cover the
 * file descriptor index presented.
 *
 * proc_fdlock held on entry (and exit) 
 */
static int
knote_fdadd(struct knote *kn, struct proc *p)
{
	struct filedesc *fdp = p->p_fd;
	struct klist *list = NULL;

	if (! knote_fops(kn)->f_isfd) {
		if (fdp->fd_knhashmask == 0)
			fdp->fd_knhash = hashinit(CONFIG_KN_HASHSIZE, M_KQUEUE,
			    &fdp->fd_knhashmask);
		list = &fdp->fd_knhash[KN_HASH(kn->kn_id, fdp->fd_knhashmask)];
	} else {
		if ((u_int)fdp->fd_knlistsize <= kn->kn_id) {
			u_int size = 0;

			if (kn->kn_id >= (uint64_t)p->p_rlimit[RLIMIT_NOFILE].rlim_cur
			    || kn->kn_id >= (uint64_t)maxfiles)
				return (EINVAL);

			/* have to grow the fd_knlist */
			size = fdp->fd_knlistsize;
			while (size <= kn->kn_id)
				size += KQEXTENT;

			if (size >= (UINT_MAX/sizeof(struct klist *)))
				return (EINVAL);

			MALLOC(list, struct klist *,
			    size * sizeof(struct klist *), M_KQUEUE, M_WAITOK);
			if (list == NULL)
				return (ENOMEM);

			bcopy((caddr_t)fdp->fd_knlist, (caddr_t)list,
			    fdp->fd_knlistsize * sizeof(struct klist *));
			bzero((caddr_t)list +
			    fdp->fd_knlistsize * sizeof(struct klist *),
			    (size - fdp->fd_knlistsize) * sizeof(struct klist *));
			FREE(fdp->fd_knlist, M_KQUEUE);
			fdp->fd_knlist = list;
			fdp->fd_knlistsize = size;
		}
		list = &fdp->fd_knlist[kn->kn_id];
	}
	SLIST_INSERT_HEAD(list, kn, kn_link);
	return (0);
}

/* 
 * knote_fdremove - remove a knote from the fd table for process
 *
 * If the filter is file-based, remove based on fd index.
 * Otherwise remove from the hash based on the ident.
 *
 * proc_fdlock held on entry (and exit)
 */
static void
knote_fdremove(struct knote *kn, struct proc *p)
{
	struct filedesc *fdp = p->p_fd;
	struct klist *list = NULL;

	if (knote_fops(kn)->f_isfd) {
		assert ((u_int)fdp->fd_knlistsize > kn->kn_id);
		list = &fdp->fd_knlist[kn->kn_id];
	} else {
		list = &fdp->fd_knhash[KN_HASH(kn->kn_id, fdp->fd_knhashmask)];
	}
	SLIST_REMOVE(list, kn, knote, kn_link);
}

/* 
 * knote_fdfind - lookup a knote in the fd table for process
 *
 * If the filter is file-based, lookup based on fd index.
 * Otherwise use a hash based on the ident.
 *
 * Matching is based on kq, filter, and ident. Optionally,
 * it may also be based on the udata field in the kevent -
 * allowing multiple event registration for the file object
 * per kqueue.
 *
 * proc_fdlock held on entry (and exit)
 */
static struct knote *
knote_fdfind(struct kqueue *kq,
             struct kevent_internal_s *kev,
             struct proc *p)
{
	struct filedesc *fdp = p->p_fd;
	struct klist *list = NULL;
	struct knote *kn = NULL;
	struct filterops *fops;
	
	fops = sysfilt_ops[~kev->filter];	/* to 0-base index */

	/* 
	 * determine where to look for the knote
	 */
	if (fops->f_isfd) {
		/* fd-based knotes are linked off the fd table */
		if (kev->ident < (u_int)fdp->fd_knlistsize) {
			list = &fdp->fd_knlist[kev->ident];
		}
	} else if (fdp->fd_knhashmask != 0) {
		/* hash non-fd knotes here too */
		list = &fdp->fd_knhash[KN_HASH((u_long)kev->ident, fdp->fd_knhashmask)];
	}

	/*
	 * scan the selected list looking for a match
	 */
	if (list != NULL) {
		SLIST_FOREACH(kn, list, kn_link) {
			if (kq == knote_get_kq(kn) &&
			    kev->ident == kn->kn_id && 
			    kev->filter == kn->kn_filter) {
				if (kev->flags & EV_UDATA_SPECIFIC) {
					if ((kn->kn_status & KN_UDATA_SPECIFIC) &&
					    kev->udata == kn->kn_udata) {
						break; /* matching udata-specific knote */
					}
				} else if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0) {
					break; /* matching non-udata-specific knote */
				}
			}
		}
	}
	return kn;
}

/*
 * knote_drop - disconnect and drop the knote
 *
 * Called with the kqueue unlocked and holding a
 * "drop reference" on the knote in question.
 * This reference is most often aquired thru a call
 * to kqlock2knotedrop(). But it can also be acquired
 * through stealing a drop reference via a call to
 * knoteuse2knotedrop() or during the initial attach
 * of the knote.
 *
 * The knote may have already been detached from
 * (or not yet attached to) its source object.
 */
static void
knote_drop(struct knote *kn, __unused struct proc *ctxp)
{
	struct kqueue *kq = knote_get_kq(kn);
	struct proc *p = kq->kq_p;
	int needswakeup;

	/* We have to have a dropping reference on the knote */
	assert(kn->kn_status & KN_DROPPING);

	/* If we are attached, disconnect from the source first */
	if (kn->kn_status & KN_ATTACHED) {
		knote_fops(kn)->f_detach(kn);
	}

	proc_fdlock(p);

	/* Remove the source from the appropriate hash */
	knote_fdremove(kn, p);

	/* trade fdlock for kq lock */
	kqlock(kq);
	proc_fdunlock(p);

	/* determine if anyone needs to know about the drop */
	assert((kn->kn_status & (KN_SUPPRESSED | KN_QUEUED)) == 0);
	needswakeup = (kn->kn_status & KN_USEWAIT);
	kqunlock(kq);

	if (needswakeup)
		waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,
				   CAST_EVENT64_T(&kn->kn_status),
				   THREAD_RESTART,
				   WAITQ_ALL_PRIORITIES);

	if (knote_fops(kn)->f_isfd && ((kn->kn_status & KN_VANISHED) == 0))
		fp_drop(p, kn->kn_id, kn->kn_fp, 0);

	knote_free(kn);
}

/* called with kqueue lock held */
static void
knote_activate(struct knote *kn)
{
	if (kn->kn_status & KN_ACTIVE)
		return;

	kn->kn_status |= KN_ACTIVE;
	if (knote_enqueue(kn))
		knote_wakeup(kn);
}

/* called with kqueue lock held */
static void
knote_deactivate(struct knote *kn)
{
	kn->kn_status &= ~KN_ACTIVE;
	if ((kn->kn_status & KN_STAYACTIVE) == 0)
		knote_dequeue(kn);
}

/* called with kqueue lock held */
static void
knote_enable(struct knote *kn)
{
	if ((kn->kn_status & KN_DISABLED) == 0)
		return;

	kn->kn_status &= ~KN_DISABLED;
	if (knote_enqueue(kn))
		knote_wakeup(kn);
}

/* called with kqueue lock held */
static void
knote_disable(struct knote *kn)
{
	if (kn->kn_status & KN_DISABLED)
		return;

	kn->kn_status |= KN_DISABLED;
	knote_dequeue(kn);
}

/* called with kqueue lock held */
static void
knote_suppress(struct knote *kn)
{
	struct kqtailq *suppressq;

	if (kn->kn_status & KN_SUPPRESSED)
		return;

	knote_dequeue(kn);
	kn->kn_status |= KN_SUPPRESSED;
	suppressq = knote_get_suppressed_queue(kn);
	TAILQ_INSERT_TAIL(suppressq, kn, kn_tqe);
}

/* called with kqueue lock held */
static void
knote_unsuppress(struct knote *kn)
{
	struct kqtailq *suppressq;

	if ((kn->kn_status & KN_SUPPRESSED) == 0)
		return;

	kn->kn_status &= ~KN_SUPPRESSED;
	suppressq = knote_get_suppressed_queue(kn);
	TAILQ_REMOVE(suppressq, kn, kn_tqe);

	/* udate in-use qos to equal requested qos */
	kn->kn_qos_index = kn->kn_req_index;

	/* don't wakeup if unsuppressing just a stay-active knote */
	if (knote_enqueue(kn) &&
	    (kn->kn_status & KN_ACTIVE))
		knote_wakeup(kn);
}

/* called with kqueue lock held */
static int
knote_enqueue(struct knote *kn)
{
	if ((kn->kn_status & (KN_ACTIVE | KN_STAYACTIVE)) == 0 ||
	    (kn->kn_status & (KN_DISABLED | KN_SUPPRESSED | KN_DROPPING)))
		return 0;

	if ((kn->kn_status & KN_QUEUED) == 0) {
		struct kqtailq *queue = knote_get_queue(kn);
		struct kqueue *kq = knote_get_kq(kn);

		TAILQ_INSERT_TAIL(queue, kn, kn_tqe);
		kn->kn_status |= KN_QUEUED;
		kq->kq_count++;
		return 1;
	}
	return ((kn->kn_status & KN_STAYACTIVE) != 0);
}


/* called with kqueue lock held */
static void
knote_dequeue(struct knote *kn)
{
	struct kqueue *kq = knote_get_kq(kn);
	struct kqtailq *queue;

	if ((kn->kn_status & KN_QUEUED) == 0)
		return;

	queue = knote_get_queue(kn);
	TAILQ_REMOVE(queue, kn, kn_tqe);
	kn->kn_status &= ~KN_QUEUED;
	kq->kq_count--;
}

void
knote_init(void)
{
	knote_zone = zinit(sizeof(struct knote), 8192*sizeof(struct knote),
	                   8192, "knote zone");

	kqfile_zone = zinit(sizeof(struct kqfile), 8192*sizeof(struct kqfile),
	                    8192, "kqueue file zone");

	kqworkq_zone = zinit(sizeof(struct kqworkq), 8192*sizeof(struct kqworkq),
	                    8192, "kqueue workq zone");

	/* allocate kq lock group attribute and group */
	kq_lck_grp_attr = lck_grp_attr_alloc_init();

	kq_lck_grp = lck_grp_alloc_init("kqueue",  kq_lck_grp_attr);

	/* Allocate kq lock attribute */
	kq_lck_attr = lck_attr_alloc_init();

	/* Initialize the timer filter lock */
	lck_mtx_init(&_filt_timerlock, kq_lck_grp, kq_lck_attr);

	/* Initialize the user filter lock */
	lck_spin_init(&_filt_userlock, kq_lck_grp, kq_lck_attr);

#if CONFIG_MEMORYSTATUS
	/* Initialize the memorystatus list lock */
	memorystatus_kevent_init(kq_lck_grp, kq_lck_attr);
#endif
}
SYSINIT(knote, SI_SUB_PSEUDO, SI_ORDER_ANY, knote_init, NULL)

struct filterops *
knote_fops(struct knote *kn)
{
	return sysfilt_ops[kn->kn_filtid];
}

static struct knote *
knote_alloc(void)
{
	return ((struct knote *)zalloc(knote_zone));
}

static void
knote_free(struct knote *kn)
{
	zfree(knote_zone, kn);
}

#if SOCKETS
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/kern_event.h>
#include <sys/malloc.h>
#include <sys/sys_domain.h>
#include <sys/syslog.h>

#ifndef ROUNDUP64
#define	ROUNDUP64(x) P2ROUNDUP((x), sizeof (u_int64_t))
#endif

#ifndef ADVANCE64
#define	ADVANCE64(p, n) (void*)((char *)(p) + ROUNDUP64(n))
#endif

static lck_grp_attr_t *kev_lck_grp_attr;
static lck_attr_t *kev_lck_attr;
static lck_grp_t *kev_lck_grp;
static decl_lck_rw_data(,kev_lck_data);
static lck_rw_t *kev_rwlock = &kev_lck_data;

static int kev_attach(struct socket *so, int proto, struct proc *p);
static int kev_detach(struct socket *so);
static int kev_control(struct socket *so, u_long cmd, caddr_t data,
    struct ifnet *ifp, struct proc *p);
static lck_mtx_t * event_getlock(struct socket *, int);
static int event_lock(struct socket *, int, void *);
static int event_unlock(struct socket *, int, void *);

static int event_sofreelastref(struct socket *);
static void kev_delete(struct kern_event_pcb *);

static struct pr_usrreqs event_usrreqs = {
	.pru_attach =		kev_attach,
	.pru_control =		kev_control,
	.pru_detach =		kev_detach,
	.pru_soreceive =	soreceive,
};

static struct protosw eventsw[] = {
{
	.pr_type =		SOCK_RAW,
	.pr_protocol =		SYSPROTO_EVENT,
	.pr_flags =		PR_ATOMIC,
	.pr_usrreqs =		&event_usrreqs,
	.pr_lock =		event_lock,
	.pr_unlock =		event_unlock,
	.pr_getlock =		event_getlock,
}
};

__private_extern__ int kevt_getstat SYSCTL_HANDLER_ARGS;
__private_extern__ int kevt_pcblist SYSCTL_HANDLER_ARGS;

SYSCTL_NODE(_net_systm, OID_AUTO, kevt,
	CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Kernel event family");

struct kevtstat kevtstat;
SYSCTL_PROC(_net_systm_kevt, OID_AUTO, stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
    kevt_getstat, "S,kevtstat", "");

SYSCTL_PROC(_net_systm_kevt, OID_AUTO, pcblist,
	CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
	kevt_pcblist, "S,xkevtpcb", "");

static lck_mtx_t *
event_getlock(struct socket *so, int locktype)
{
#pragma unused(locktype)
	struct kern_event_pcb *ev_pcb = (struct kern_event_pcb *)so->so_pcb;

	if (so->so_pcb != NULL)  {
		if (so->so_usecount < 0)
			panic("%s: so=%p usecount=%d lrh= %s\n", __func__,
			    so, so->so_usecount, solockhistory_nr(so));
			/* NOTREACHED */
	} else {
		panic("%s: so=%p NULL NO so_pcb %s\n", __func__,
		    so, solockhistory_nr(so));
		/* NOTREACHED */
	}
	return (&ev_pcb->evp_mtx);
}

static int
event_lock(struct socket *so, int refcount, void *lr)
{
	void *lr_saved;

	if (lr == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = lr;

	if (so->so_pcb != NULL) {
		lck_mtx_lock(&((struct kern_event_pcb *)so->so_pcb)->evp_mtx);
	} else  {
		panic("%s: so=%p NO PCB! lr=%p lrh= %s\n", __func__,
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	}

	if (so->so_usecount < 0) {
		panic("%s: so=%p so_pcb=%p lr=%p ref=%d lrh= %s\n", __func__,
		    so, so->so_pcb, lr_saved, so->so_usecount,
		    solockhistory_nr(so));
		/* NOTREACHED */
	}

	if (refcount)
		so->so_usecount++;

	so->lock_lr[so->next_lock_lr] = lr_saved;
	so->next_lock_lr = (so->next_lock_lr+1) % SO_LCKDBG_MAX;
	return (0);
}

static int
event_unlock(struct socket *so, int refcount, void *lr)
{
	void *lr_saved;
	lck_mtx_t *mutex_held;

	if (lr == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = lr;

	if (refcount)
		so->so_usecount--;

	if (so->so_usecount < 0) {
		panic("%s: so=%p usecount=%d lrh= %s\n", __func__,
		    so, so->so_usecount, solockhistory_nr(so));
		/* NOTREACHED */
	}
	if (so->so_pcb == NULL) {
		panic("%s: so=%p NO PCB usecount=%d lr=%p lrh= %s\n", __func__,
		    so, so->so_usecount, (void *)lr_saved,
		    solockhistory_nr(so));
		/* NOTREACHED */
	}
	mutex_held = (&((struct kern_event_pcb *)so->so_pcb)->evp_mtx);

	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
	so->unlock_lr[so->next_unlock_lr] = lr_saved;
	so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;

	if (so->so_usecount == 0) {
		VERIFY(so->so_flags & SOF_PCBCLEARING);
		event_sofreelastref(so);
	} else {
		lck_mtx_unlock(mutex_held);
	}

	return (0);
}

static int
event_sofreelastref(struct socket *so)
{
	struct kern_event_pcb *ev_pcb = (struct kern_event_pcb *)so->so_pcb;

	lck_mtx_assert(&(ev_pcb->evp_mtx), LCK_MTX_ASSERT_OWNED);

	so->so_pcb = NULL;

	/*
	 * Disable upcall in the event another thread is in kev_post_msg()
	 * appending record to the receive socket buffer, since sbwakeup()
	 * may release the socket lock otherwise.
	 */
	so->so_rcv.sb_flags &= ~SB_UPCALL;
	so->so_snd.sb_flags &= ~SB_UPCALL;
	so->so_event = sonullevent;
	lck_mtx_unlock(&(ev_pcb->evp_mtx));

	lck_mtx_assert(&(ev_pcb->evp_mtx), LCK_MTX_ASSERT_NOTOWNED);
	lck_rw_lock_exclusive(kev_rwlock);
	LIST_REMOVE(ev_pcb, evp_link);
	kevtstat.kes_pcbcount--;
	kevtstat.kes_gencnt++;
	lck_rw_done(kev_rwlock);
	kev_delete(ev_pcb);

	sofreelastref(so, 1);
	return (0);
}

static int event_proto_count = (sizeof (eventsw) / sizeof (struct protosw));

static
struct kern_event_head kern_event_head;

static u_int32_t static_event_id = 0;

#define	EVPCB_ZONE_MAX		65536
#define	EVPCB_ZONE_NAME		"kerneventpcb"
static struct zone *ev_pcb_zone;

/*
 * Install the protosw's for the NKE manager.  Invoked at extension load time
 */
void
kern_event_init(struct domain *dp)
{
	struct protosw *pr;
	int i;

	VERIFY(!(dp->dom_flags & DOM_INITIALIZED));
	VERIFY(dp == systemdomain);

	kev_lck_grp_attr = lck_grp_attr_alloc_init();
	if (kev_lck_grp_attr == NULL) {
		panic("%s: lck_grp_attr_alloc_init failed\n", __func__);
		/* NOTREACHED */
	}

	kev_lck_grp = lck_grp_alloc_init("Kernel Event Protocol",
	    kev_lck_grp_attr);
	if (kev_lck_grp == NULL) {
		panic("%s: lck_grp_alloc_init failed\n", __func__);
		/* NOTREACHED */
	}

	kev_lck_attr = lck_attr_alloc_init();
	if (kev_lck_attr == NULL) {
		panic("%s: lck_attr_alloc_init failed\n", __func__);
		/* NOTREACHED */
	}

	lck_rw_init(kev_rwlock, kev_lck_grp, kev_lck_attr);
	if (kev_rwlock == NULL) {
		panic("%s: lck_mtx_alloc_init failed\n", __func__);
		/* NOTREACHED */
	}

	for (i = 0, pr = &eventsw[0]; i < event_proto_count; i++, pr++)
		net_add_proto(pr, dp, 1);

	ev_pcb_zone = zinit(sizeof(struct kern_event_pcb),
	    EVPCB_ZONE_MAX * sizeof(struct kern_event_pcb), 0, EVPCB_ZONE_NAME);
	if (ev_pcb_zone == NULL) {
		panic("%s: failed allocating ev_pcb_zone", __func__);
		/* NOTREACHED */
	}
	zone_change(ev_pcb_zone, Z_EXPAND, TRUE);
	zone_change(ev_pcb_zone, Z_CALLERACCT, TRUE);
}

static int
kev_attach(struct socket *so, __unused int proto, __unused struct proc *p)
{
	int error = 0;
	struct kern_event_pcb *ev_pcb;

	error = soreserve(so, KEV_SNDSPACE, KEV_RECVSPACE);
	if (error != 0)
		return (error);

	if ((ev_pcb = (struct kern_event_pcb *)zalloc(ev_pcb_zone)) == NULL) {
		return (ENOBUFS);
	}
	bzero(ev_pcb, sizeof(struct kern_event_pcb));
	lck_mtx_init(&ev_pcb->evp_mtx, kev_lck_grp, kev_lck_attr);

	ev_pcb->evp_socket = so;
	ev_pcb->evp_vendor_code_filter = 0xffffffff;

	so->so_pcb = (caddr_t) ev_pcb;
	lck_rw_lock_exclusive(kev_rwlock);
	LIST_INSERT_HEAD(&kern_event_head, ev_pcb, evp_link);
	kevtstat.kes_pcbcount++;
	kevtstat.kes_gencnt++;
	lck_rw_done(kev_rwlock);

	return (error);
}

static void
kev_delete(struct kern_event_pcb *ev_pcb)
{
	VERIFY(ev_pcb != NULL);
	lck_mtx_destroy(&ev_pcb->evp_mtx, kev_lck_grp);
	zfree(ev_pcb_zone, ev_pcb);
}

static int
kev_detach(struct socket *so)
{
	struct kern_event_pcb *ev_pcb = (struct kern_event_pcb *) so->so_pcb;

	if (ev_pcb != NULL) {
		soisdisconnected(so);
		so->so_flags |= SOF_PCBCLEARING;
	}

	return (0);
}

/*
 * For now, kev_vendor_code and mbuf_tags use the same
 * mechanism.
 */
errno_t kev_vendor_code_find(
	const char	*string,
	u_int32_t 	*out_vendor_code)
{
	if (strlen(string) >= KEV_VENDOR_CODE_MAX_STR_LEN) {
		return (EINVAL);
	}
	return (net_str_id_find_internal(string, out_vendor_code,
	    NSI_VENDOR_CODE, 1));
}

errno_t
kev_msg_post(struct kev_msg *event_msg)
{
	mbuf_tag_id_t min_vendor, max_vendor;

	net_str_id_first_last(&min_vendor, &max_vendor, NSI_VENDOR_CODE);

	if (event_msg == NULL)
		return (EINVAL);

	/* 
	 * Limit third parties to posting events for registered vendor codes
	 * only
	 */
	if (event_msg->vendor_code < min_vendor ||
	    event_msg->vendor_code > max_vendor) {
		OSIncrementAtomic64((SInt64 *)&kevtstat.kes_badvendor);
		return (EINVAL);
	}
	return (kev_post_msg(event_msg));
}

int
kev_post_msg(struct kev_msg *event_msg)
{
	struct mbuf *m, *m2;
	struct kern_event_pcb *ev_pcb;
	struct kern_event_msg *ev;
	char *tmp;
	u_int32_t total_size;
	int i;

	/* Verify the message is small enough to fit in one mbuf w/o cluster */
	total_size = KEV_MSG_HEADER_SIZE;

	for (i = 0; i < 5; i++) {
		if (event_msg->dv[i].data_length == 0)
			break;
		total_size += event_msg->dv[i].data_length;
	}

	if (total_size > MLEN) {
		OSIncrementAtomic64((SInt64 *)&kevtstat.kes_toobig);
		return (EMSGSIZE);
	}

	m = m_get(M_DONTWAIT, MT_DATA);
	if (m == 0) {
		OSIncrementAtomic64((SInt64 *)&kevtstat.kes_nomem);
		return (ENOMEM);
	}
	ev = mtod(m, struct kern_event_msg *);
	total_size = KEV_MSG_HEADER_SIZE;

	tmp = (char *) &ev->event_data[0];
	for (i = 0; i < 5; i++) {
		if (event_msg->dv[i].data_length == 0)
			break;

		total_size += event_msg->dv[i].data_length;
		bcopy(event_msg->dv[i].data_ptr, tmp,
		    event_msg->dv[i].data_length);
		tmp += event_msg->dv[i].data_length;
	}

	ev->id = ++static_event_id;
	ev->total_size   = total_size;
	ev->vendor_code  = event_msg->vendor_code;
	ev->kev_class    = event_msg->kev_class;
	ev->kev_subclass = event_msg->kev_subclass;
	ev->event_code   = event_msg->event_code;

	m->m_len = total_size;
	lck_rw_lock_shared(kev_rwlock);
	for (ev_pcb = LIST_FIRST(&kern_event_head);
	    ev_pcb;
	    ev_pcb = LIST_NEXT(ev_pcb, evp_link)) {
		lck_mtx_lock(&ev_pcb->evp_mtx);
		if (ev_pcb->evp_socket->so_pcb == NULL) {
			lck_mtx_unlock(&ev_pcb->evp_mtx);
			continue;
		}
		if (ev_pcb->evp_vendor_code_filter != KEV_ANY_VENDOR) {
			if (ev_pcb->evp_vendor_code_filter != ev->vendor_code) {
				lck_mtx_unlock(&ev_pcb->evp_mtx);
				continue;
			}

			if (ev_pcb->evp_class_filter != KEV_ANY_CLASS) {
				if (ev_pcb->evp_class_filter != ev->kev_class) {
					lck_mtx_unlock(&ev_pcb->evp_mtx);
					continue;
				}

				if ((ev_pcb->evp_subclass_filter !=
				    KEV_ANY_SUBCLASS) &&
				    (ev_pcb->evp_subclass_filter !=
				    ev->kev_subclass)) {
					lck_mtx_unlock(&ev_pcb->evp_mtx);
					continue;
				}
			}
		}

		m2 = m_copym(m, 0, m->m_len, M_NOWAIT);
		if (m2 == 0) {
			OSIncrementAtomic64((SInt64 *)&kevtstat.kes_nomem);
			m_free(m);
			lck_mtx_unlock(&ev_pcb->evp_mtx);
			lck_rw_done(kev_rwlock);
			return (ENOMEM);
		}
		if (sbappendrecord(&ev_pcb->evp_socket->so_rcv, m2)) {
			/*
			 * We use "m" for the socket stats as it would be
			 * unsafe to use "m2"
			 */
			so_inc_recv_data_stat(ev_pcb->evp_socket,
			    1, m->m_len, MBUF_TC_BE);

			sorwakeup(ev_pcb->evp_socket);
			OSIncrementAtomic64((SInt64 *)&kevtstat.kes_posted);
		} else {
			OSIncrementAtomic64((SInt64 *)&kevtstat.kes_fullsock);
		}
		lck_mtx_unlock(&ev_pcb->evp_mtx);
	}
	m_free(m);
	lck_rw_done(kev_rwlock);

	return (0);
}

static int
kev_control(struct socket *so,
    u_long cmd,
    caddr_t data,
    __unused struct ifnet *ifp,
    __unused struct proc *p)
{
	struct kev_request *kev_req = (struct kev_request *) data;
	struct kern_event_pcb  *ev_pcb;
	struct kev_vendor_code *kev_vendor;
	u_int32_t  *id_value = (u_int32_t *) data;

	switch (cmd) {
		case SIOCGKEVID:
			*id_value = static_event_id;
			break;
		case SIOCSKEVFILT:
			ev_pcb = (struct kern_event_pcb *) so->so_pcb;
			ev_pcb->evp_vendor_code_filter = kev_req->vendor_code;
			ev_pcb->evp_class_filter = kev_req->kev_class;
			ev_pcb->evp_subclass_filter  = kev_req->kev_subclass;
			break;
		case SIOCGKEVFILT:
			ev_pcb = (struct kern_event_pcb *) so->so_pcb;
			kev_req->vendor_code = ev_pcb->evp_vendor_code_filter;
			kev_req->kev_class   = ev_pcb->evp_class_filter;
			kev_req->kev_subclass = ev_pcb->evp_subclass_filter;
			break;
		case SIOCGKEVVENDOR:
			kev_vendor = (struct kev_vendor_code *)data;
			/* Make sure string is NULL terminated */
			kev_vendor->vendor_string[KEV_VENDOR_CODE_MAX_STR_LEN-1] = 0;
			return (net_str_id_find_internal(kev_vendor->vendor_string,
			    &kev_vendor->vendor_code, NSI_VENDOR_CODE, 0));
		default:
			return (ENOTSUP);
	}

	return (0);
}

int
kevt_getstat SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;

	lck_rw_lock_shared(kev_rwlock);

	if (req->newptr != USER_ADDR_NULL) {
		error = EPERM;
		goto done;
	}
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(struct kevtstat);
		goto done;
	}

	error = SYSCTL_OUT(req, &kevtstat,
	    MIN(sizeof(struct kevtstat), req->oldlen));
done:
	lck_rw_done(kev_rwlock);

	return (error);
}

__private_extern__ int
kevt_pcblist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;
	int n, i;
	struct xsystmgen xsg;
	void *buf = NULL;
	size_t item_size = ROUNDUP64(sizeof (struct xkevtpcb)) +
		ROUNDUP64(sizeof (struct xsocket_n)) +
		2 * ROUNDUP64(sizeof (struct xsockbuf_n)) +
		ROUNDUP64(sizeof (struct xsockstat_n));
	struct kern_event_pcb  *ev_pcb;

	buf = _MALLOC(item_size, M_TEMP, M_WAITOK | M_ZERO);
	if (buf == NULL)
		return (ENOMEM);

	lck_rw_lock_shared(kev_rwlock);

	n = kevtstat.kes_pcbcount;

	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = (n + n/8) * item_size;
		goto done;
	}
	if (req->newptr != USER_ADDR_NULL) {
		error = EPERM;
		goto done;
	}
	bzero(&xsg, sizeof (xsg));
	xsg.xg_len = sizeof (xsg);
	xsg.xg_count = n;
	xsg.xg_gen = kevtstat.kes_gencnt;
	xsg.xg_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xsg, sizeof (xsg));
	if (error) {
		goto done;
	}
	/*
	 * We are done if there is no pcb
	 */
	if (n == 0) {
		goto done;
	}

	i = 0;
	for (i = 0, ev_pcb = LIST_FIRST(&kern_event_head);
	    i < n && ev_pcb != NULL;
	    i++, ev_pcb = LIST_NEXT(ev_pcb, evp_link)) {
		struct xkevtpcb *xk = (struct xkevtpcb *)buf;
		struct xsocket_n *xso = (struct xsocket_n *)
			ADVANCE64(xk, sizeof (*xk));
		struct xsockbuf_n *xsbrcv = (struct xsockbuf_n *)
			ADVANCE64(xso, sizeof (*xso));
		struct xsockbuf_n *xsbsnd = (struct xsockbuf_n *)
			ADVANCE64(xsbrcv, sizeof (*xsbrcv));
		struct xsockstat_n *xsostats = (struct xsockstat_n *)
			ADVANCE64(xsbsnd, sizeof (*xsbsnd));

		bzero(buf, item_size);

		lck_mtx_lock(&ev_pcb->evp_mtx);

		xk->kep_len = sizeof(struct xkevtpcb);
		xk->kep_kind = XSO_EVT;
		xk->kep_evtpcb = (uint64_t)VM_KERNEL_ADDRPERM(ev_pcb);
		xk->kep_vendor_code_filter = ev_pcb->evp_vendor_code_filter;
		xk->kep_class_filter = ev_pcb->evp_class_filter;
		xk->kep_subclass_filter = ev_pcb->evp_subclass_filter;

		sotoxsocket_n(ev_pcb->evp_socket, xso);
		sbtoxsockbuf_n(ev_pcb->evp_socket ?
			&ev_pcb->evp_socket->so_rcv : NULL, xsbrcv);
		sbtoxsockbuf_n(ev_pcb->evp_socket ?
			&ev_pcb->evp_socket->so_snd : NULL, xsbsnd);
		sbtoxsockstat_n(ev_pcb->evp_socket, xsostats);

		lck_mtx_unlock(&ev_pcb->evp_mtx);

		error = SYSCTL_OUT(req, buf, item_size);
	}

	if (error == 0) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		bzero(&xsg, sizeof (xsg));
		xsg.xg_len = sizeof (xsg);
		xsg.xg_count = n;
		xsg.xg_gen = kevtstat.kes_gencnt;
		xsg.xg_sogen = so_gencnt;
		error = SYSCTL_OUT(req, &xsg, sizeof (xsg));
		if (error) {
			goto done;
		}
	}

done:
	lck_rw_done(kev_rwlock);

	return (error);
}

#endif /* SOCKETS */


int
fill_kqueueinfo(struct kqueue *kq, struct kqueue_info * kinfo)
{
	struct vinfo_stat * st;

	st = &kinfo->kq_stat;

	st->vst_size = kq->kq_count;
	if (kq->kq_state & KQ_KEV_QOS)
		st->vst_blksize = sizeof(struct kevent_qos_s);
	else if (kq->kq_state & KQ_KEV64)
		st->vst_blksize = sizeof(struct kevent64_s);
	else
		st->vst_blksize = sizeof(struct kevent);
	st->vst_mode = S_IFIFO;

	/* flags exported to libproc as PROC_KQUEUE_* (sys/proc_info.h) */
#define PROC_KQUEUE_MASK (KQ_SEL|KQ_SLEEP|KQ_KEV32|KQ_KEV64|KQ_KEV_QOS)
	kinfo->kq_state = kq->kq_state & PROC_KQUEUE_MASK;

	return (0);
}


void
knote_markstayactive(struct knote *kn)
{
	kqlock(knote_get_kq(kn));
	kn->kn_status |= KN_STAYACTIVE;

	/* handle all stayactive knotes on the manager */
	if (knote_get_kq(kn)->kq_state & KQ_WORKQ)
		knote_set_qos_index(kn, KQWQ_QOS_MANAGER);

	knote_activate(kn);
	kqunlock(knote_get_kq(kn));
}

void
knote_clearstayactive(struct knote *kn)
{
	kqlock(knote_get_kq(kn));
	kn->kn_status &= ~KN_STAYACTIVE;
	knote_deactivate(kn);
	kqunlock(knote_get_kq(kn));
}

static unsigned long
kevent_extinfo_emit(struct kqueue *kq, struct knote *kn, struct kevent_extinfo *buf,
		unsigned long buflen, unsigned long nknotes)
{
	struct kevent_internal_s *kevp;
	for (; kn; kn = SLIST_NEXT(kn, kn_link)) {
		if (kq == knote_get_kq(kn)) {
			if (nknotes < buflen) {
				struct kevent_extinfo *info = &buf[nknotes];
				struct kevent_qos_s kevqos;

				kqlock(kq);
				kevp = &(kn->kn_kevent);

				bzero(&kevqos, sizeof(kevqos));
				kevqos.ident = kevp->ident;
				kevqos.filter = kevp->filter;
				kevqos.flags = kevp->flags;
				kevqos.fflags = kevp->fflags;
				kevqos.data = (int64_t) kevp->data;
				kevqos.udata = kevp->udata;
				kevqos.ext[0] = kevp->ext[0];
				kevqos.ext[1] = kevp->ext[1];

				memcpy(&info->kqext_kev, &kevqos, sizeof(info->kqext_kev));
				info->kqext_sdata = kn->kn_sdata;
				info->kqext_status = kn->kn_status;
				info->kqext_sfflags = kn->kn_sfflags;

				kqunlock(kq);
			}

			/* we return total number of knotes, which may be more than requested */
			nknotes++;
		}
	}

	return nknotes;
}

int
pid_kqueue_extinfo(proc_t p, struct kqueue *kq, user_addr_t ubuf,
		uint32_t bufsize, int32_t *retval)
{
	struct knote *kn;
	int i;
	int err = 0;
	struct filedesc *fdp = p->p_fd;
	unsigned long nknotes = 0;
	unsigned long buflen = bufsize / sizeof(struct kevent_extinfo);
	struct kevent_extinfo *kqext = NULL;

	/* arbitrary upper limit to cap kernel memory usage, copyout size, etc. */
	buflen = min(buflen, PROC_PIDFDKQUEUE_KNOTES_MAX);

	kqext = kalloc(buflen * sizeof(struct kevent_extinfo));
	if (kqext == NULL) {
		err = ENOMEM;
		goto out;
	}
	bzero(kqext, buflen * sizeof(struct kevent_extinfo));

	proc_fdlock(p);

	for (i = 0; i < fdp->fd_knlistsize; i++) {
		kn = SLIST_FIRST(&fdp->fd_knlist[i]);
		nknotes = kevent_extinfo_emit(kq, kn, kqext, buflen, nknotes);
	}

	if (fdp->fd_knhashmask != 0) {
		for (i = 0; i < (int)fdp->fd_knhashmask + 1; i++) {
			kn = SLIST_FIRST(&fdp->fd_knhash[i]);
			nknotes = kevent_extinfo_emit(kq, kn, kqext, buflen, nknotes);
		}
	}

	proc_fdunlock(p);

	assert(bufsize >= sizeof(struct kevent_extinfo) * min(buflen, nknotes));
	err = copyout(kqext, ubuf, sizeof(struct kevent_extinfo) * min(buflen, nknotes));

 out:
	if (kqext) {
		kfree(kqext, buflen * sizeof(struct kevent_extinfo));
		kqext = NULL;
	}

	if (!err) {
		*retval = min(nknotes, PROC_PIDFDKQUEUE_KNOTES_MAX);
	}
	return err;
}

static unsigned long
kevent_udatainfo_emit(struct kqueue *kq, struct knote *kn, uint64_t *buf,
		unsigned long buflen, unsigned long nknotes)
{
	struct kevent_internal_s *kevp;
	for (; kn; kn = SLIST_NEXT(kn, kn_link)) {
		if (kq == knote_get_kq(kn)) {
			if (nknotes < buflen) {
				kqlock(kq);
				kevp = &(kn->kn_kevent);
				buf[nknotes] = kevp->udata;
				kqunlock(kq);
			}

			/* we return total number of knotes, which may be more than requested */
			nknotes++;
		}
	}

	return nknotes;
}

int
pid_kqueue_udatainfo(proc_t p, struct kqueue *kq, uint64_t *buf,
		uint32_t bufsize)
{
	struct knote *kn;
	int i;
	struct filedesc *fdp = p->p_fd;
	unsigned long nknotes = 0;
	unsigned long buflen = bufsize / sizeof(uint64_t);

	proc_fdlock(p);

	for (i = 0; i < fdp->fd_knlistsize; i++) {
		kn = SLIST_FIRST(&fdp->fd_knlist[i]);
		nknotes = kevent_udatainfo_emit(kq, kn, buf, buflen, nknotes);
	}

	if (fdp->fd_knhashmask != 0) {
		for (i = 0; i < (int)fdp->fd_knhashmask + 1; i++) {
			kn = SLIST_FIRST(&fdp->fd_knhash[i]);
			nknotes = kevent_udatainfo_emit(kq, kn, buf, buflen, nknotes);
		}
	}

	proc_fdunlock(p);
	return (int)nknotes;
}

