/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
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
#include <stdatomic.h>

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
#include <sys/kdebug.h>
#include <sys/reason.h>
#include <os/reason_private.h>

#include <kern/locks.h>
#include <kern/clock.h>
#include <kern/cpu_data.h>
#include <kern/policy_internal.h>
#include <kern/thread_call.h>
#include <kern/sched_prim.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/ast.h>
#include <kern/thread.h>
#include <kern/kcdata.h>

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>

#include "net/net_str_id.h"

#include <mach/task.h>
#include <libkern/section_keywords.h>

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

extern thread_t	port_name_to_thread(mach_port_name_t	port_name); /* osfmk/kern/ipc_tt.h   */
extern mach_port_name_t ipc_entry_name_mask(mach_port_name_t name); /* osfmk/ipc/ipc_entry.h */

#define KEV_EVTID(code) BSDDBG_CODE(DBG_BSD_KEVENT, (code))

/*
 * JMM - this typedef needs to be unified with pthread_priority_t
 *       and mach_msg_priority_t. It also needs to be the same type
 *       everywhere.
 */
typedef int32_t qos_t;

MALLOC_DEFINE(M_KQUEUE, "kqueue", "memory for kqueue system");

#define	KQ_EVENT	NO_EVENT64

#define KNUSE_NONE       0x0
#define KNUSE_STEAL_DROP 0x1
#define KNUSE_BOOST      0x2
static int kqlock2knoteuse(struct kqueue *kq, struct knote *kn, int flags);
static int kqlock2knotedrop(struct kqueue *kq, struct knote *kn);
static int kqlock2knotedetach(struct kqueue *kq, struct knote *kn, int flags);
static int knoteuse2kqlock(struct kqueue *kq, struct knote *kn, int flags);

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
		struct kevent_internal_s *kev, vfs_context_t ctx);
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

static void kevent_put_kq(struct proc *p, kqueue_id_t id, struct fileproc *fp, struct kqueue *kq);
static int kevent_internal(struct proc *p,
			   kqueue_id_t id, kqueue_id_t *id_out,
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
                          struct filt_process_s *process_data, int *countp, struct proc *p);
static struct kqtailq *kqueue_get_base_queue(struct kqueue *kq, kq_index_t qos_index);
static struct kqtailq *kqueue_get_high_queue(struct kqueue *kq, kq_index_t qos_index);
static int kqueue_queue_empty(struct kqueue *kq, kq_index_t qos_index);

static struct kqtailq *kqueue_get_suppressed_queue(struct kqueue *kq, kq_index_t qos_index);

static void kqworkq_request_thread(struct kqworkq *kqwq, kq_index_t qos_index);
static void kqworkq_request_help(struct kqworkq *kqwq, kq_index_t qos_index);
static void kqworkq_update_override(struct kqworkq *kqwq, kq_index_t qos_index, kq_index_t override_index);
static void kqworkq_bind_thread_impl(struct kqworkq *kqwq, kq_index_t qos_index, thread_t thread, unsigned int flags);
static void kqworkq_unbind_thread(struct kqworkq *kqwq, kq_index_t qos_index, thread_t thread, unsigned int flags);
static struct kqrequest *kqworkq_get_request(struct kqworkq *kqwq, kq_index_t qos_index);

enum {
	KQWL_UO_NONE = 0,
	KQWL_UO_OLD_OVERRIDE_IS_SYNC_UI = 0x1,
	KQWL_UO_NEW_OVERRIDE_IS_SYNC_UI = 0x2,
	KQWL_UO_UPDATE_SUPPRESS_SYNC_COUNTERS = 0x4,
	KQWL_UO_UPDATE_OVERRIDE_LAZY = 0x8
};

static void kqworkloop_update_override(struct kqworkloop *kqwl, kq_index_t qos_index, kq_index_t override_index, uint32_t flags);
static void kqworkloop_bind_thread_impl(struct kqworkloop *kqwl, thread_t thread, unsigned int flags);
static void kqworkloop_unbind_thread(struct kqworkloop *kqwl, thread_t thread, unsigned int flags);
static inline kq_index_t kqworkloop_combined_qos(struct kqworkloop *kqwl, boolean_t *);
static void kqworkloop_update_suppress_sync_count(struct kqrequest *kqr, uint32_t flags);
enum {
	KQWL_UTQ_NONE,
	/*
	 * The wakeup qos is the qos of QUEUED knotes.
	 *
	 * This QoS is accounted for with the events override in the
	 * kqr_override_index field. It is raised each time a new knote is queued at
	 * a given QoS. The kqr_wakeup_indexes field is a superset of the non empty
	 * knote buckets and is recomputed after each event delivery.
	 */
	KQWL_UTQ_UPDATE_WAKEUP_QOS,
	KQWL_UTQ_UPDATE_STAYACTIVE_QOS,
	KQWL_UTQ_RECOMPUTE_WAKEUP_QOS,
	/*
	 * The wakeup override is for suppressed knotes that have fired again at
	 * a higher QoS than the one for which they are suppressed already.
	 * This override is cleared when the knote suppressed list becomes empty.
	 */
	KQWL_UTQ_UPDATE_WAKEUP_OVERRIDE,
	KQWL_UTQ_RESET_WAKEUP_OVERRIDE,
	/*
	 * The async QoS is the maximum QoS of an event enqueued on this workloop in
	 * userland. It is copied from the only EVFILT_WORKLOOP knote with
	 * a NOTE_WL_THREAD_REQUEST bit set allowed on this workloop. If there is no
	 * such knote, this QoS is 0.
	 */
	KQWL_UTQ_SET_ASYNC_QOS,
	/*
	 * The sync waiters QoS is the maximum QoS of any thread blocked on an
	 * EVFILT_WORKLOOP knote marked with the NOTE_WL_SYNC_WAIT bit.
	 * If there is no such knote, this QoS is 0.
	 */
	KQWL_UTQ_SET_SYNC_WAITERS_QOS,
	KQWL_UTQ_REDRIVE_EVENTS,
};
static void kqworkloop_update_threads_qos(struct kqworkloop *kqwl, int op, kq_index_t qos);
static void kqworkloop_request_help(struct kqworkloop *kqwl, kq_index_t qos_index);

static int knote_process(struct knote *kn, kevent_callback_t callback, void *callback_data,
			 struct filt_process_s *process_data, struct proc *p);
#if 0
static void knote_put(struct knote *kn);
#endif

static int kq_add_knote(struct kqueue *kq, struct knote *kn,
		struct kevent_internal_s *kev, struct proc *p, int *knoteuse_flags);
static struct knote *kq_find_knote_and_kq_lock(struct kqueue *kq, struct kevent_internal_s *kev, bool is_fd, struct proc *p);
static void kq_remove_knote(struct kqueue *kq, struct knote *kn, struct proc *p, kn_status_t *kn_status, uint16_t *kq_state);

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
static kq_index_t knote_get_req_index(struct knote *kn);
static kq_index_t knote_get_qos_index(struct knote *kn);
static void knote_set_qos_index(struct knote *kn, kq_index_t qos_index);
static kq_index_t knote_get_qos_override_index(struct knote *kn);
static kq_index_t knote_get_sync_qos_override_index(struct knote *kn);
static void knote_set_qos_override_index(struct knote *kn, kq_index_t qos_index, boolean_t override_is_sync);
static void knote_set_qos_overcommit(struct knote *kn);

static int filt_fileattach(struct knote *kn, struct kevent_internal_s *kev);
SECURITY_READ_ONLY_EARLY(static struct filterops) file_filtops = {
	.f_isfd = 1,
	.f_attach = filt_fileattach,
};

static void filt_kqdetach(struct knote *kn);
static int filt_kqueue(struct knote *kn, long hint);
static int filt_kqtouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_kqprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
SECURITY_READ_ONLY_EARLY(static struct filterops) kqread_filtops = {
	.f_isfd = 1,
	.f_detach = filt_kqdetach,
	.f_event = filt_kqueue,
	.f_touch = filt_kqtouch,
	.f_process = filt_kqprocess,
};

/* placeholder for not-yet-implemented filters */
static int filt_badattach(struct knote *kn, struct kevent_internal_s *kev);
SECURITY_READ_ONLY_EARLY(static struct filterops) bad_filtops = {
	.f_attach = filt_badattach,
};

static int filt_procattach(struct knote *kn, struct kevent_internal_s *kev);
static void filt_procdetach(struct knote *kn);
static int filt_proc(struct knote *kn, long hint);
static int filt_proctouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_procprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
SECURITY_READ_ONLY_EARLY(static struct filterops) proc_filtops = {
	.f_attach = filt_procattach,
	.f_detach = filt_procdetach,
	.f_event = filt_proc,
	.f_touch = filt_proctouch,
	.f_process = filt_procprocess,
};

#if CONFIG_MEMORYSTATUS
extern const struct filterops memorystatus_filtops;
#endif /* CONFIG_MEMORYSTATUS */

extern const struct filterops fs_filtops;

extern const struct filterops sig_filtops;

static zone_t knote_zone;
static zone_t kqfile_zone;
static zone_t kqworkq_zone;
static zone_t kqworkloop_zone;

#define	KN_HASH(val, mask)	(((val) ^ (val >> 8)) & (mask))

/* Mach portset filter */
extern const struct filterops machport_filtops;

/* User filter */
static int filt_userattach(struct knote *kn, struct kevent_internal_s *kev);
static void filt_userdetach(struct knote *kn);
static int filt_user(struct knote *kn, long hint);
static int filt_usertouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_userprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
SECURITY_READ_ONLY_EARLY(static struct filterops) user_filtops = {
	.f_attach = filt_userattach,
	.f_detach = filt_userdetach,
	.f_event = filt_user,
	.f_touch = filt_usertouch,
	.f_process = filt_userprocess,
};

static lck_spin_t _filt_userlock;
static void filt_userlock(void);
static void filt_userunlock(void);

/* Workloop filter */
static bool filt_wlneeds_boost(struct kevent_internal_s *kev);
static int filt_wlattach(struct knote *kn, struct kevent_internal_s *kev);
static int filt_wlpost_attach(struct knote *kn, struct  kevent_internal_s *kev);
static void filt_wldetach(struct knote *kn);
static int filt_wlevent(struct knote *kn, long hint);
static int filt_wltouch(struct knote *kn, struct kevent_internal_s *kev);
static int filt_wldrop_and_unlock(struct knote *kn, struct kevent_internal_s *kev);
static int filt_wlprocess(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);
SECURITY_READ_ONLY_EARLY(static struct filterops) workloop_filtops = {
	.f_needs_boost = filt_wlneeds_boost,
	.f_attach = filt_wlattach,
	.f_post_attach = filt_wlpost_attach,
	.f_detach = filt_wldetach,
	.f_event = filt_wlevent,
	.f_touch = filt_wltouch,
	.f_drop_and_unlock = filt_wldrop_and_unlock,
	.f_process = filt_wlprocess,
};

extern const struct filterops pipe_rfiltops;
extern const struct filterops pipe_wfiltops;
extern const struct filterops ptsd_kqops;
extern const struct filterops ptmx_kqops;
extern const struct filterops soread_filtops;
extern const struct filterops sowrite_filtops;
extern const struct filterops sock_filtops;
extern const struct filterops soexcept_filtops;
extern const struct filterops spec_filtops;
extern const struct filterops bpfread_filtops;
extern const struct filterops necp_fd_rfiltops;
extern const struct filterops fsevent_filtops;
extern const struct filterops vnode_filtops;
extern const struct filterops tty_filtops;

const static struct filterops timer_filtops;

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
SECURITY_READ_ONLY_EARLY(static struct filterops *) sysfilt_ops[EVFILTID_MAX] = {
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

	[~EVFILT_WORKLOOP]              = &workloop_filtops,

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
	[EVFILTID_VN] 					= &vnode_filtops,
	[EVFILTID_TTY]					= &tty_filtops,
	[EVFILTID_PTMX]					= &ptmx_kqops,
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

static inline __kdebug_only
uintptr_t
kqr_thread_id(struct kqrequest *kqr)
{
	return (uintptr_t)thread_tid(kqr->kqr_thread);
}

static inline
boolean_t is_workqueue_thread(thread_t thread)
{
	return (thread_get_tag(thread) & THREAD_TAG_WORKQUEUE);
}

static inline
void knote_canonicalize_kevent_qos(struct knote *kn)
{
	struct kqueue *kq = knote_get_kq(kn);
	unsigned long canonical;

	if ((kq->kq_state & (KQ_WORKQ | KQ_WORKLOOP)) == 0)
		return;

	/* preserve manager and overcommit flags in this case */
	canonical = pthread_priority_canonicalize(kn->kn_qos, FALSE);
	kn->kn_qos = (qos_t)canonical;
}

static inline
kq_index_t qos_index_from_qos(struct knote *kn, qos_t qos, boolean_t propagation)
{
	struct kqueue *kq = knote_get_kq(kn);
	kq_index_t qos_index;
	unsigned long flags = 0;

	if ((kq->kq_state & (KQ_WORKQ | KQ_WORKLOOP)) == 0)
		return QOS_INDEX_KQFILE;

	qos_index = (kq_index_t)thread_qos_from_pthread_priority(
				(unsigned long)qos, &flags);
	
	if (kq->kq_state & KQ_WORKQ) {
		/* workq kqueues support requesting a manager thread (non-propagation) */
		if (!propagation && (flags & _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG))
			return KQWQ_QOS_MANAGER;
	}

	return qos_index;
}

static inline
qos_t qos_from_qos_index(kq_index_t qos_index)
{
	/* should only happen for KQ_WORKQ */
	if (qos_index == KQWQ_QOS_MANAGER) 
		return  _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG;

	if (qos_index == 0)
		return THREAD_QOS_UNSPECIFIED;

	/* Should have support from pthread kext support */
	return (1 << (qos_index - 1 + 
	              _PTHREAD_PRIORITY_QOS_CLASS_SHIFT_32));
}

/* kqr lock must be held */
static inline
unsigned long pthread_priority_for_kqrequest(
	struct kqrequest *kqr,
	kq_index_t qos_index)
{
	unsigned long priority = qos_from_qos_index(qos_index);
	if (kqr->kqr_state & KQR_THOVERCOMMIT) {
		priority |= _PTHREAD_PRIORITY_OVERCOMMIT_FLAG;
	}
	return priority;
}

static inline
kq_index_t qos_index_for_servicer(int qos_class, thread_t thread, int flags)
{
#pragma unused(thread)
	kq_index_t qos_index;

	if (flags & KEVENT_FLAG_WORKQ_MANAGER)
		return KQWQ_QOS_MANAGER;

	qos_index = (kq_index_t)qos_class;
	assert(qos_index > 0 && qos_index < KQWQ_QOS_MANAGER);

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
kqlock_held(__assert_only struct kqueue *kq)
{
	LCK_SPIN_ASSERT(&kq->kq_lock, LCK_ASSERT_OWNED);
}

static inline void
kqunlock(struct kqueue *kq)
{
	lck_spin_unlock(&kq->kq_lock);
}

static inline void
knhash_lock(proc_t p)
{
	lck_mtx_lock(&p->p_fd->fd_knhashlock);
}

static inline void
knhash_unlock(proc_t p)
{
	lck_mtx_unlock(&p->p_fd->fd_knhashlock);
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
kqlock2knoteuse(struct kqueue *kq, struct knote *kn, int flags)
{
	if (kn->kn_status & (KN_DROPPING | KN_VANISHED))
		return (0);

	assert(kn->kn_status & KN_ATTACHED);
	kn->kn_inuse++;
	if (flags & KNUSE_BOOST) {
		set_thread_rwlock_boost();
	}
	kqunlock(kq);
	return (1);
}

/*
 *	- kq locked at entry
 *	- kq unlocked at exit
 */
__disable_tail_calls
static wait_result_t
knoteusewait(struct kqueue *kq, struct knote *kn)
{
	kn->kn_status |= KN_USEWAIT;
	waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
			CAST_EVENT64_T(&kn->kn_status),
			THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
	kqunlock(kq);
	return thread_block(THREAD_CONTINUE_NULL);
}

static bool
knoteuse_needs_boost(struct knote *kn, struct kevent_internal_s *kev)
{
	if (knote_fops(kn)->f_needs_boost) {
		return knote_fops(kn)->f_needs_boost(kev);
	}
	return false;
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
knoteuse2kqlock(struct kqueue *kq, struct knote *kn, int flags)
{
	int dropped = 0;
	int steal_drop = (flags & KNUSE_STEAL_DROP);

	kqlock(kq);
	if (flags & KNUSE_BOOST) {
		clear_thread_rwlock_boost();
	}

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
			knoteusewait(kq, kn);
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
kqlock2knotedetach(struct kqueue *kq, struct knote *kn, int flags)
{
	if ((kn->kn_status & KN_DROPPING) || kn->kn_inuse) {
		/* have to wait for dropper or current uses to go away */
		knoteusewait(kq, kn);
		return (0);
	}
	assert((kn->kn_status & KN_VANISHED) == 0);
	assert(kn->kn_status & KN_ATTACHED);
	kn->kn_status &= ~KN_ATTACHED;
	kn->kn_status |= KN_VANISHED;
	if (flags & KNUSE_BOOST) {
		clear_thread_rwlock_boost();
	}
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
	result = knoteusewait(kq, kn);
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
filt_fileattach(struct knote *kn, struct kevent_internal_s *kev)
{
	return (fo_kqfilter(kn->kn_fp, kn, kev, vfs_context_current()));
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

#pragma mark EVFILT_PROC

static int
filt_procattach(struct knote *kn, __unused struct kevent_internal_s *kev)
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


#pragma mark EVFILT_TIMER


/*
 * Values stored in the knote at rest (using Mach absolute time units)
 *
 * kn->kn_hook          where the thread_call object is stored
 * kn->kn_ext[0]        next deadline or 0 if immediate expiration
 * kn->kn_ext[1]        leeway value
 * kn->kn_sdata         interval timer: the interval
 *                      absolute/deadline timer: 0
 * kn->kn_data          fire count
 */

static lck_mtx_t _filt_timerlock;

static void filt_timerlock(void)   { lck_mtx_lock(&_filt_timerlock);   }
static void filt_timerunlock(void) { lck_mtx_unlock(&_filt_timerlock); }

static inline void filt_timer_assert_locked(void)
{
	LCK_MTX_ASSERT(&_filt_timerlock, LCK_MTX_ASSERT_OWNED);
}

/* state flags stored in kn_hookid */
#define	TIMER_RUNNING           0x1
#define	TIMER_CANCELWAIT        0x2

/*
 * filt_timervalidate - process data from user
 *
 * Sets up the deadline, interval, and leeway from the provided user data
 *
 * Input:
 *      kn_sdata        timer deadline or interval time
 *      kn_sfflags      style of timer, unit of measurement
 *
 * Output:
 *      kn_sdata        either interval in abstime or 0 if non-repeating timer
 *      ext[0]          fire deadline in abs/cont time
 *                      (or 0 if NOTE_ABSOLUTE and deadline is in past)
 *
 * Returns:
 *      EINVAL          Invalid user data parameters
 *
 * Called with timer filter lock held.
 */
static int
filt_timervalidate(struct knote *kn)
{
	/*
	 * There are 4 knobs that need to be chosen for a timer registration:
	 *
	 * A) Units of time (what is the time duration of the specified number)
	 *      Absolute and interval take:
	 *              NOTE_SECONDS, NOTE_USECONDS, NOTE_NSECONDS, NOTE_MACHTIME
	 *      Defaults to milliseconds if not specified
	 *
	 * B) Clock epoch (what is the zero point of the specified number)
	 *      For interval, there is none
	 *      For absolute, defaults to the gettimeofday/calendar epoch
	 *      With NOTE_MACHTIME, uses mach_absolute_time()
	 *      With NOTE_MACHTIME and NOTE_MACH_CONTINUOUS_TIME, uses mach_continuous_time()
	 *
	 * C) The knote's behavior on delivery
	 *      Interval timer causes the knote to arm for the next interval unless one-shot is set
	 *      Absolute is a forced one-shot timer which deletes on delivery
	 *      TODO: Add a way for absolute to be not forced one-shot
	 *
	 * D) Whether the time duration is relative to now or absolute
	 *      Interval fires at now + duration when it is set up
	 *      Absolute fires at now + difference between now walltime and passed in walltime
	 *      With NOTE_MACHTIME it fires at an absolute MAT or MCT.
	 *
	 * E) Whether the timer continues to tick across sleep
	 *      By default all three do not.
	 *      For interval and absolute, NOTE_MACH_CONTINUOUS_TIME causes them to tick across sleep
	 *      With NOTE_ABSOLUTE | NOTE_MACHTIME | NOTE_MACH_CONTINUOUS_TIME:
	 *              expires when mach_continuous_time() is > the passed in value.
	 */

	filt_timer_assert_locked();

	uint64_t multiplier;

	boolean_t use_abstime = FALSE;

	switch (kn->kn_sfflags & (NOTE_SECONDS|NOTE_USECONDS|NOTE_NSECONDS|NOTE_MACHTIME)) {
	case NOTE_SECONDS:
		multiplier = NSEC_PER_SEC;
		break;
	case NOTE_USECONDS:
		multiplier = NSEC_PER_USEC;
		break;
	case NOTE_NSECONDS:
		multiplier = 1;
		break;
	case NOTE_MACHTIME:
		multiplier = 0;
		use_abstime = TRUE;
		break;
	case 0: /* milliseconds (default) */
		multiplier = NSEC_PER_SEC / 1000;
		break;
	default:
		return (EINVAL);
	}

	/* transform the leeway in kn_ext[1] to same time scale */
	if (kn->kn_sfflags & NOTE_LEEWAY) {
		uint64_t leeway_abs;

		if (use_abstime) {
			leeway_abs = (uint64_t)kn->kn_ext[1];
		} else  {
			uint64_t leeway_ns;
			if (os_mul_overflow((uint64_t)kn->kn_ext[1], multiplier, &leeway_ns))
				return (ERANGE);

			nanoseconds_to_absolutetime(leeway_ns, &leeway_abs);
		}

		kn->kn_ext[1] = leeway_abs;
	}

	if (kn->kn_sfflags & NOTE_ABSOLUTE) {
		uint64_t deadline_abs;

		if (use_abstime) {
			deadline_abs = (uint64_t)kn->kn_sdata;
		} else {
			uint64_t calendar_deadline_ns;

			if (os_mul_overflow((uint64_t)kn->kn_sdata, multiplier, &calendar_deadline_ns))
				return (ERANGE);

			/* calendar_deadline_ns is in nanoseconds since the epoch */

			clock_sec_t seconds;
			clock_nsec_t nanoseconds;

			/*
			 * Note that the conversion through wall-time is only done once.
			 *
			 * If the relationship between MAT and gettimeofday changes,
			 * the underlying timer does not update.
			 *
			 * TODO: build a wall-time denominated timer_call queue
			 * and a flag to request DTRTing with wall-time timers
			 */
			clock_get_calendar_nanotime(&seconds, &nanoseconds);

			uint64_t calendar_now_ns = (uint64_t)seconds * NSEC_PER_SEC + nanoseconds;

			/* if deadline is in the future */
			if (calendar_now_ns < calendar_deadline_ns) {
				uint64_t interval_ns = calendar_deadline_ns - calendar_now_ns;
				uint64_t interval_abs;

				nanoseconds_to_absolutetime(interval_ns, &interval_abs);

				/*
				 * Note that the NOTE_MACH_CONTINUOUS_TIME flag here only
				 * causes the timer to keep ticking across sleep, but
				 * it does not change the calendar timebase.
				 */

				if (kn->kn_sfflags & NOTE_MACH_CONTINUOUS_TIME)
					clock_continuoustime_interval_to_deadline(interval_abs,
					                                          &deadline_abs);
				else
					clock_absolutetime_interval_to_deadline(interval_abs,
					                                        &deadline_abs);
			} else {
				deadline_abs = 0; /* cause immediate expiration */
			}
		}

		kn->kn_ext[0] = deadline_abs;
		kn->kn_sdata  = 0;       /* NOTE_ABSOLUTE is non-repeating */
	} else if (kn->kn_sdata < 0) {
		/*
		 * Negative interval timers fire immediately, once.
		 *
		 * Ideally a negative interval would be an error, but certain clients
		 * pass negative values on accident, and expect an event back.
		 *
		 * In the old implementation the timer would repeat with no delay
		 * N times until mach_absolute_time() + (N * interval) underflowed,
		 * then it would wait ~forever by accidentally arming a timer for the far future.
		 *
		 * We now skip the power-wasting hot spin phase and go straight to the idle phase.
		 */

		kn->kn_sdata  = 0;      /* non-repeating */
		kn->kn_ext[0] = 0;      /* expire immediately */
	} else {
		uint64_t interval_abs = 0;

		if (use_abstime) {
			interval_abs = (uint64_t)kn->kn_sdata;
		} else {
			uint64_t interval_ns;
			if (os_mul_overflow((uint64_t)kn->kn_sdata, multiplier, &interval_ns))
				return (ERANGE);

			nanoseconds_to_absolutetime(interval_ns, &interval_abs);
		}

		uint64_t deadline = 0;

		if (kn->kn_sfflags & NOTE_MACH_CONTINUOUS_TIME)
			clock_continuoustime_interval_to_deadline(interval_abs, &deadline);
		else
			clock_absolutetime_interval_to_deadline(interval_abs, &deadline);

		kn->kn_sdata  = interval_abs;   /* default to a repeating timer */
		kn->kn_ext[0] = deadline;
	}

	return (0);
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

		kn->kn_hookid &= ~TIMER_CANCELWAIT;
	}

	filt_timerunlock();
}

/*
 * Cancel a running timer (or wait for the pop).
 * Timer filter lock is held.
 * May drop and retake the timer filter lock.
 */
static void
filt_timercancel(struct knote *kn)
{
	filt_timer_assert_locked();

	assert((kn->kn_hookid & TIMER_CANCELWAIT) == 0);

	/* if no timer, then we're good */
	if ((kn->kn_hookid & TIMER_RUNNING) == 0)
		return;

	thread_call_t callout = (thread_call_t)kn->kn_hook;

	/* cancel the callout if we can */
	if (thread_call_cancel(callout)) {
		kn->kn_hookid &= ~TIMER_RUNNING;
		return;
	}

	/* cancel failed, we have to wait for the in-flight expire routine */

	kn->kn_hookid |= TIMER_CANCELWAIT;

	struct kqueue *kq = knote_get_kq(kn);

	waitq_assert_wait64((struct waitq *)&kq->kq_wqs,
	                    CAST_EVENT64_T(&kn->kn_hook),
	                    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);

	filt_timerunlock();
	thread_block(THREAD_CONTINUE_NULL);
	filt_timerlock();

	assert((kn->kn_hookid & TIMER_CANCELWAIT) == 0);
	assert((kn->kn_hookid & TIMER_RUNNING) == 0);
}

static void
filt_timerarm(struct knote *kn)
{
	filt_timer_assert_locked();

	assert((kn->kn_hookid & TIMER_RUNNING) == 0);

	thread_call_t callout = (thread_call_t)kn->kn_hook;

	uint64_t deadline = kn->kn_ext[0];
	uint64_t leeway   = kn->kn_ext[1];

	int filter_flags = kn->kn_sfflags;
	unsigned int timer_flags = 0;

	if (filter_flags & NOTE_CRITICAL)
		timer_flags |= THREAD_CALL_DELAY_USER_CRITICAL;
	else if (filter_flags & NOTE_BACKGROUND)
		timer_flags |= THREAD_CALL_DELAY_USER_BACKGROUND;
	else
		timer_flags |= THREAD_CALL_DELAY_USER_NORMAL;

	if (filter_flags & NOTE_LEEWAY)
		timer_flags |= THREAD_CALL_DELAY_LEEWAY;

	if (filter_flags & NOTE_MACH_CONTINUOUS_TIME)
		timer_flags |= THREAD_CALL_CONTINUOUS;

	thread_call_enter_delayed_with_leeway(callout, NULL,
	                                      deadline, leeway,
	                                      timer_flags);

	kn->kn_hookid |= TIMER_RUNNING;
}

/*
 * Does this knote need a timer armed for it, or should it be ready immediately?
 */
static boolean_t
filt_timer_is_ready(struct knote *kn)
{
	uint64_t now;

	if (kn->kn_sfflags & NOTE_MACH_CONTINUOUS_TIME)
		now = mach_continuous_time();
	else
		now = mach_absolute_time();

	uint64_t deadline = kn->kn_ext[0];

	if (deadline < now)
		return TRUE;
	else
		return FALSE;
}

/*
 * Allocate a thread call for the knote's lifetime, and kick off the timer.
 */
static int
filt_timerattach(struct knote *kn, __unused struct kevent_internal_s *kev)
{
	thread_call_t callout;
	int error;

	callout = thread_call_allocate_with_options(filt_timerexpire,
	                (thread_call_param_t)kn, THREAD_CALL_PRIORITY_HIGH,
	                THREAD_CALL_OPTIONS_ONCE);

	if (NULL == callout) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = ENOMEM;
		return 0;
	}

	filt_timerlock();

	if ((error = filt_timervalidate(kn)) != 0) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data  = error;
		filt_timerunlock();

		__assert_only boolean_t freed = thread_call_free(callout);
		assert(freed);
		return 0;
	}

	kn->kn_hook = (void*)callout;
	kn->kn_hookid = 0;
	kn->kn_flags |= EV_CLEAR;

	/* NOTE_ABSOLUTE implies EV_ONESHOT */
	if (kn->kn_sfflags & NOTE_ABSOLUTE)
		kn->kn_flags |= EV_ONESHOT;

	boolean_t timer_ready = FALSE;

	if ((timer_ready = filt_timer_is_ready(kn))) {
		/* cause immediate expiration */
		kn->kn_data = 1;
	} else {
		filt_timerarm(kn);
	}

	filt_timerunlock();

	return timer_ready;
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

	__assert_only boolean_t freed = thread_call_free(callout);
	assert(freed);
}

/*
 * filt_timerevent - post events to a timer knote
 *
 * Called in the context of filt_timerexpire with
 * the filt_timerlock held
 */
static int
filt_timerevent(struct knote *kn, __unused long hint)
{
	filt_timer_assert_locked();

	kn->kn_data = 1;
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

	filt_timerlock();

	/*
	 * cancel current call - drops and retakes lock
	 * TODO: not safe against concurrent touches?
	 */
	filt_timercancel(kn);

	/* clear if the timer had previously fired, the user no longer wants to see it */
	kn->kn_data = 0;

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
		kn->kn_flags |= EV_ERROR;
		kn->kn_data = error;
		filt_timerunlock();
		return 1;
	}

	boolean_t timer_ready = FALSE;

	if ((timer_ready = filt_timer_is_ready(kn))) {
		/* cause immediate expiration */
		kn->kn_data = 1;
	} else {
		filt_timerarm(kn);
	}

	filt_timerunlock();

	return timer_ready;
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

	if (kn->kn_data == 0 || (kn->kn_hookid & TIMER_CANCELWAIT)) {
		/*
		 * kn_data = 0:
		 * The timer hasn't yet fired, so there's nothing to deliver
		 * TIMER_CANCELWAIT:
		 * touch is in the middle of canceling the timer,
		 * so don't deliver or re-arm anything
		 *
		 * This can happen if a touch resets a timer that had fired
		 * without being processed
		 */
		filt_timerunlock();
		return 0;
	}

	if (kn->kn_sdata != 0 && ((kn->kn_flags & EV_ERROR) == 0)) {
		/*
		 * This is a 'repeating' timer, so we have to emit
		 * how many intervals expired between the arm
		 * and the process.
		 *
		 * A very strange style of interface, because
		 * this could easily be done in the client...
		 */

		/* The timer better have had expired... */
		assert((kn->kn_hookid & TIMER_RUNNING) == 0);

		uint64_t now;

		if (kn->kn_sfflags & NOTE_MACH_CONTINUOUS_TIME)
			now = mach_continuous_time();
		else
			now = mach_absolute_time();

		uint64_t first_deadline = kn->kn_ext[0];
		uint64_t interval_abs   = kn->kn_sdata;
		uint64_t orig_arm_time  = first_deadline - interval_abs;

		assert(now > orig_arm_time);
		assert(now > first_deadline);

		uint64_t elapsed = now - orig_arm_time;

		uint64_t num_fired = elapsed / interval_abs;

		/*
		 * To reach this code, we must have seen the timer pop
		 * and be in repeating mode, so therefore it must have been
		 * more than 'interval' time since the attach or last
		 * successful touch.
		 *
		 * An unsuccessful touch would:
		 * disarm the timer
		 * clear kn_data
		 * clear kn_sdata
		 * set EV_ERROR
		 * all of which will prevent this code from running.
		 */
		assert(num_fired > 0);

		/* report how many intervals have elapsed to the user */
		kn->kn_data = (int64_t) num_fired;

		/* We only need to re-arm the timer if it's not about to be destroyed */
		if ((kn->kn_flags & EV_ONESHOT) == 0) {
			/* fire at the end of the next interval */
			uint64_t new_deadline = first_deadline + num_fired * interval_abs;

			assert(new_deadline > now);

			kn->kn_ext[0] = new_deadline;

			filt_timerarm(kn);
		}
	}

	/*
	 * Copy out the interesting kevent state,
	 * but don't leak out the raw time calculations.
	 *
	 * TODO: potential enhancements - tell the user about:
	 *      - deadline to which this timer thought it was expiring
	 *      - return kn_sfflags in the fflags field so the client can know
	 *        under what flags the timer fired
	 */
	*kev = kn->kn_kevent;
	kev->ext[0] = 0;
	/* kev->ext[1] = 0;  JMM - shouldn't we hide this too? */

	/* we have delivered the event, reset the timer pop count */
	kn->kn_data = 0;

	filt_timerunlock();
	return 1;
}

SECURITY_READ_ONLY_EARLY(static struct filterops) timer_filtops = {
	.f_attach   = filt_timerattach,
	.f_detach   = filt_timerdetach,
	.f_event    = filt_timerevent,
	.f_touch    = filt_timertouch,
	.f_process  = filt_timerprocess,
};


#pragma mark EVFILT_USER


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
filt_userattach(struct knote *kn, __unused struct kevent_internal_s *kev)
{
	/* EVFILT_USER knotes are not attached to anything in the kernel */
	/* Cant discover this knote until after attach - so no lock needed */
	kn->kn_hook = NULL;
	if (kn->kn_sfflags & NOTE_TRIGGER) {
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

#pragma mark EVFILT_WORKLOOP

#if DEBUG || DEVELOPMENT
/*
 * see src/queue_internal.h in libdispatch
 */
#define DISPATCH_QUEUE_ENQUEUED 0x1ull
#endif

static inline void
filt_wllock(struct kqworkloop *kqwl)
{
	lck_mtx_lock(&kqwl->kqwl_statelock);
}

static inline void
filt_wlunlock(struct kqworkloop *kqwl)
{
	lck_mtx_unlock(&kqwl->kqwl_statelock);
}

static inline void
filt_wlheld(__assert_only struct kqworkloop *kqwl)
{
	LCK_MTX_ASSERT(&kqwl->kqwl_statelock, LCK_MTX_ASSERT_OWNED);
}

#define WL_OWNER_SUSPENDED    ((thread_t)(~0ull))  /* special owner when suspended */

static inline bool
filt_wlowner_is_valid(thread_t owner)
{
	return owner != THREAD_NULL && owner != WL_OWNER_SUSPENDED;
}

static inline bool
filt_wlshould_end_ownership(struct kqworkloop *kqwl,
		struct kevent_internal_s *kev, int error)
{
	thread_t owner = kqwl->kqwl_owner;
	return (error == 0 || error == ESTALE) &&
			(kev->fflags & NOTE_WL_END_OWNERSHIP) &&
			(owner == current_thread() || owner == WL_OWNER_SUSPENDED);
}

static inline bool
filt_wlshould_update_ownership(struct kevent_internal_s *kev, int error)
{
	return error == 0 && (kev->fflags & NOTE_WL_DISCOVER_OWNER) &&
			kev->ext[EV_EXTIDX_WL_ADDR];
}

static inline bool
filt_wlshould_set_async_qos(struct kevent_internal_s *kev, int error,
		kq_index_t async_qos)
{
	if (error != 0) {
		return false;
	}
	if (async_qos != THREAD_QOS_UNSPECIFIED) {
		return true;
	}
	if ((kev->fflags & NOTE_WL_THREAD_REQUEST) && (kev->flags & EV_DELETE)) {
		/* see filt_wlprocess() */
		return true;
	}
	return false;
}

__result_use_check
static int
filt_wlupdateowner(struct kqworkloop *kqwl, struct kevent_internal_s *kev,
		int error, kq_index_t async_qos)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;
	thread_t cur_owner, new_owner, extra_thread_ref = THREAD_NULL;
	kq_index_t cur_override = THREAD_QOS_UNSPECIFIED;
	kq_index_t old_owner_override = THREAD_QOS_UNSPECIFIED;
	boolean_t ipc_override_is_sync = false;
	boolean_t old_owner_override_is_sync = false;
	int action = KQWL_UTQ_NONE;

	filt_wlheld(kqwl);

	/*
	 * The owner is only changed under both the filt_wllock and the
	 * kqwl_req_lock. Looking at it with either one held is fine.
	 */
	cur_owner = kqwl->kqwl_owner;
	if (filt_wlshould_end_ownership(kqwl, kev, error)) {
		new_owner = THREAD_NULL;
	} else if (filt_wlshould_update_ownership(kev, error)) {
		/*
		 * Decipher the owner port name, and translate accordingly.
		 * The low 2 bits were borrowed for other flags, so mask them off.
		 */
		uint64_t udata = kev->ext[EV_EXTIDX_WL_VALUE];
		mach_port_name_t new_owner_name = (mach_port_name_t)udata & ~0x3;
		if (new_owner_name != MACH_PORT_NULL) {
			new_owner_name = ipc_entry_name_mask(new_owner_name);
		}

		if (MACH_PORT_VALID(new_owner_name)) {
			new_owner = port_name_to_thread(new_owner_name);
			if (new_owner == THREAD_NULL)
				return EOWNERDEAD;
			extra_thread_ref = new_owner;
		} else if (new_owner_name == MACH_PORT_DEAD) {
			new_owner = WL_OWNER_SUSPENDED;
		} else {
			/*
			 * We never want to learn a new owner that is NULL.
			 * Ownership should be ended with END_OWNERSHIP.
			 */
			new_owner = cur_owner;
		}
	} else {
		new_owner = cur_owner;
	}

	if (filt_wlshould_set_async_qos(kev, error, async_qos)) {
		action = KQWL_UTQ_SET_ASYNC_QOS;
	}
	if (cur_owner == new_owner && action == KQWL_UTQ_NONE) {
		goto out;
	}

	kqwl_req_lock(kqwl);

	/* If already tracked as servicer, don't track as owner */
	if ((kqr->kqr_state & KQR_BOUND) && new_owner == kqr->kqr_thread) {
		kqwl->kqwl_owner = new_owner = THREAD_NULL;
	}

	if (cur_owner != new_owner) {
		kqwl->kqwl_owner = new_owner;
		if (new_owner == extra_thread_ref) {
			/* we just transfered this ref to kqwl_owner */
			extra_thread_ref = THREAD_NULL;
		}
		cur_override = kqworkloop_combined_qos(kqwl, &ipc_override_is_sync);
		old_owner_override = kqr->kqr_dsync_owner_qos;
		old_owner_override_is_sync = kqr->kqr_owner_override_is_sync;

		if (filt_wlowner_is_valid(new_owner)) {
			/* override it before we drop the old */
			if (cur_override != THREAD_QOS_UNSPECIFIED) {
				thread_add_ipc_override(new_owner, cur_override);
			}
			if (ipc_override_is_sync) {
				thread_add_sync_ipc_override(new_owner);
			}
			/* Update the kqr to indicate that owner has sync ipc override */
			kqr->kqr_dsync_owner_qos = cur_override;
			kqr->kqr_owner_override_is_sync = ipc_override_is_sync;
			thread_starts_owning_workloop(new_owner);
			if ((kqr->kqr_state & (KQR_THREQUESTED | KQR_BOUND)) == KQR_THREQUESTED) {
				if (action == KQWL_UTQ_NONE) {
					action = KQWL_UTQ_REDRIVE_EVENTS;
				}
			}
		} else if (new_owner == THREAD_NULL) {
			kqr->kqr_dsync_owner_qos = THREAD_QOS_UNSPECIFIED;
			kqr->kqr_owner_override_is_sync = false;
			if ((kqr->kqr_state & (KQR_THREQUESTED | KQR_WAKEUP)) == KQR_WAKEUP) {
				if (action == KQWL_UTQ_NONE) {
					action = KQWL_UTQ_REDRIVE_EVENTS;
				}
			}
		}
	}

	if (action != KQWL_UTQ_NONE) {
		kqworkloop_update_threads_qos(kqwl, action, async_qos);
	}

	kqwl_req_unlock(kqwl);

	/* Now that we are unlocked, drop the override and ref on old owner */
	if (new_owner != cur_owner && filt_wlowner_is_valid(cur_owner)) {
		if (old_owner_override != THREAD_QOS_UNSPECIFIED) {
			thread_drop_ipc_override(cur_owner);
		}
		if (old_owner_override_is_sync) {
			thread_drop_sync_ipc_override(cur_owner);
		}
		thread_ends_owning_workloop(cur_owner);
		thread_deallocate(cur_owner);
	}

out:
	if (extra_thread_ref) {
		thread_deallocate(extra_thread_ref);
	}
	return error;
}

static int
filt_wldebounce(
	struct kqworkloop *kqwl,
	struct kevent_internal_s *kev,
	int default_result)
{
	user_addr_t addr = CAST_USER_ADDR_T(kev->ext[EV_EXTIDX_WL_ADDR]);
	uint64_t udata;
	int error;

	/* we must have the workloop state mutex held */
	filt_wlheld(kqwl);

	/* Do we have a debounce address to work with? */
	if (addr) {
		uint64_t kdata = kev->ext[EV_EXTIDX_WL_VALUE];
		uint64_t mask = kev->ext[EV_EXTIDX_WL_MASK];

		error = copyin_word(addr, &udata, sizeof(udata));
		if (error) {
			return error;
		}

		/* update state as copied in */
		kev->ext[EV_EXTIDX_WL_VALUE] = udata;

		/* If the masked bits don't match, reject it as stale */
		if ((udata & mask) != (kdata & mask)) {
			return ESTALE;
		}

#if DEBUG || DEVELOPMENT
		if ((kev->fflags & NOTE_WL_THREAD_REQUEST) && !(kev->flags & EV_DELETE)) {
			if ((udata & DISPATCH_QUEUE_ENQUEUED) == 0 &&
					(udata >> 48) != 0 && (udata >> 48) != 0xffff) {
				panic("kevent: workloop %#016llx is not enqueued "
						"(kev:%p dq_state:%#016llx)", kev->udata, kev, udata);
			}
		}
#endif
	}

	return default_result;
}

/*
 * Remembers the last updated that came in from userspace for debugging reasons.
 * - fflags is mirrored from the userspace kevent
 * - ext[i, i != VALUE] is mirrored from the userspace kevent
 * - ext[VALUE] is set to what the kernel loaded atomically
 * - data is set to the error if any
 */
static inline void
filt_wlremember_last_update(
	__assert_only struct kqworkloop *kqwl,
	struct knote *kn,
	struct kevent_internal_s *kev,
	int error)
{
	filt_wlheld(kqwl);
	kn->kn_fflags = kev->fflags;
	kn->kn_data = error;
	memcpy(kn->kn_ext, kev->ext, sizeof(kev->ext));
}

/*
 * Return which operations on EVFILT_WORKLOOP need to be protected against
 * knoteusewait() causing priority inversions.
 */
static bool
filt_wlneeds_boost(struct kevent_internal_s *kev)
{
	if (kev == NULL) {
		/*
		 * this is an f_process() usecount, and it can cause a drop to wait
		 */
		return true;
	}
	if (kev->fflags & NOTE_WL_THREAD_REQUEST) {
		/*
		 * All operations on thread requests may starve drops or re-attach of
		 * the same knote, all of them need boosts. None of what we do under
		 * thread-request usecount holds blocks anyway.
		 */
		return true;
	}
	if (kev->fflags & NOTE_WL_SYNC_WAIT) {
		/*
		 * this may call filt_wlwait() and we don't want to hold any boost when
		 * woken up, this would cause background threads contending on
		 * dispatch_sync() to wake up at 64 and be preempted immediately when
		 * this drops.
		 */
		return false;
	}

	/*
	 * SYNC_WAIT knotes when deleted don't need to be rushed, there's no
	 * detach/reattach race with these ever. In addition to this, when the
	 * SYNC_WAIT knote is dropped, the caller is no longer receiving the
	 * workloop overrides if any, and we'd rather schedule other threads than
	 * him, he's not possibly stalling anything anymore.
	 */
	return (kev->flags & EV_DELETE) == 0;
}

static int
filt_wlattach(struct knote *kn, struct kevent_internal_s *kev)
{
	struct kqueue *kq = knote_get_kq(kn);
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	int error = 0;
	kq_index_t qos_index = 0;

	if ((kq->kq_state & KQ_WORKLOOP) == 0) {
		error = ENOTSUP;
		goto out;
	}

#if DEVELOPMENT || DEBUG
	if (kev->ident == 0 && kev->udata == 0 && kev->fflags == 0) {
		struct kqrequest *kqr = &kqwl->kqwl_request;

		kqwl_req_lock(kqwl);
		kev->fflags = 0;
		if (kqr->kqr_dsync_waiters) {
			kev->fflags |= NOTE_WL_SYNC_WAIT;
		}
		if (kqr->kqr_qos_index) {
			kev->fflags |= NOTE_WL_THREAD_REQUEST;
		}
		if (kqwl->kqwl_owner == WL_OWNER_SUSPENDED) {
			kev->ext[0] = ~0ull;
		} else {
			kev->ext[0] = thread_tid(kqwl->kqwl_owner);
		}
		kev->ext[1] = thread_tid(kqwl->kqwl_request.kqr_thread);
		kev->ext[2] = thread_owned_workloops_count(current_thread());
		kev->ext[3] = kn->kn_kevent.ext[3];
		kqwl_req_unlock(kqwl);
		error = EBUSY;
		goto out;
	}
#endif

	/* Some simple validation */
	int command = (kn->kn_sfflags & NOTE_WL_COMMANDS_MASK);
	switch (command) {
	case NOTE_WL_THREAD_REQUEST:
		if (kn->kn_id != kqwl->kqwl_dynamicid) {
			error = EINVAL;
			goto out;
		}
		qos_index = qos_index_from_qos(kn, kn->kn_qos, FALSE);
		if (qos_index < THREAD_QOS_MAINTENANCE ||
				qos_index > THREAD_QOS_USER_INTERACTIVE) {
			error = ERANGE;
			goto out;
		}
		break;
	case NOTE_WL_SYNC_WAIT:
	case NOTE_WL_SYNC_WAKE:
		if (kq->kq_state & KQ_NO_WQ_THREAD) {
			error = ENOTSUP;
			goto out;
		}
		if (kn->kn_id == kqwl->kqwl_dynamicid) {
			error = EINVAL;
			goto out;
		}
		if ((kn->kn_flags & EV_DISABLE) == 0) {
			error = EINVAL;
			goto out;
		}
		if (kn->kn_sfflags & NOTE_WL_END_OWNERSHIP) {
			error = EINVAL;
			goto out;
		}
		break;
	default:
		error = EINVAL;
		goto out;
	}

	filt_wllock(kqwl);
	kn->kn_hook = NULL;

	if (command == NOTE_WL_THREAD_REQUEST && kqwl->kqwl_request.kqr_qos_index) {
		/*
		 * There already is a thread request, and well, you're only allowed
		 * one per workloop, so fail the attach.
		 *
		 * Note: kqr_qos_index is always set with the wllock held, so we
		 * don't need to take the kqr lock.
		 */
		error = EALREADY;
	} else {
		/* Make sure user and kernel are in agreement on important state */
		error = filt_wldebounce(kqwl, kev, 0);
	}

	error = filt_wlupdateowner(kqwl, kev, error, qos_index);
	filt_wlunlock(kqwl);
out:
	if (error) {
		kn->kn_flags |= EV_ERROR;
		/* If userland wants ESTALE to be hidden, fail the attach anyway */
		if (error == ESTALE && (kn->kn_sfflags & NOTE_WL_IGNORE_ESTALE)) {
			error = 0;
		}
		kn->kn_data = error;
		return 0;
	}

	/* Just attaching the thread request successfully will fire it */
	return command == NOTE_WL_THREAD_REQUEST;
}

__attribute__((noinline,not_tail_called))
static int
filt_wlwait(struct kqworkloop           *kqwl,
            struct knote                *kn,
            struct kevent_internal_s    *kev)
{
	filt_wlheld(kqwl);
	assert((kn->kn_sfflags & NOTE_WL_SYNC_WAKE) == 0);

	/*
	 * Hint to the wakeup side that this thread is waiting.  Also used by
	 * stackshot for waitinfo.
	 */
	kn->kn_hook = current_thread();

	thread_set_pending_block_hint(current_thread(), kThreadWaitWorkloopSyncWait);

	wait_result_t wr = assert_wait(kn, THREAD_ABORTSAFE);

	if (wr == THREAD_WAITING) {
		kq_index_t qos_index = qos_index_from_qos(kn, kev->qos, TRUE);
		struct kqrequest *kqr = &kqwl->kqwl_request;

		thread_t thread_to_handoff = THREAD_NULL; /* holds +1 thread ref */

		thread_t kqwl_owner = kqwl->kqwl_owner;
		if (filt_wlowner_is_valid(kqwl_owner)) {
			thread_reference(kqwl_owner);
			thread_to_handoff = kqwl_owner;
		}

		kqwl_req_lock(kqwl);

		if (qos_index) {
			assert(kqr->kqr_dsync_waiters < UINT16_MAX);
			kqr->kqr_dsync_waiters++;
			if (qos_index > kqr->kqr_dsync_waiters_qos) {
				kqworkloop_update_threads_qos(kqwl,
						KQWL_UTQ_SET_SYNC_WAITERS_QOS, qos_index);
			}
		}

		if ((kqr->kqr_state & KQR_BOUND) && thread_to_handoff == THREAD_NULL) {
			assert(kqr->kqr_thread != THREAD_NULL);
			thread_t servicer = kqr->kqr_thread;

			thread_reference(servicer);
			thread_to_handoff = servicer;
		}

		kqwl_req_unlock(kqwl);

		filt_wlunlock(kqwl);

		/* TODO: use continuation based blocking <rdar://problem/31299584> */

		/* consume a refcount on thread_to_handoff, then thread_block() */
		wr = thread_handoff(thread_to_handoff);
		thread_to_handoff = THREAD_NULL;

		filt_wllock(kqwl);

		/* clear waiting state (only one waiting thread - so no race) */
		assert(kn->kn_hook == current_thread());

		if (qos_index) {
			kqwl_req_lock(kqwl);
			assert(kqr->kqr_dsync_waiters > 0);
			if (--kqr->kqr_dsync_waiters == 0) {
				assert(kqr->kqr_dsync_waiters_qos);
				kqworkloop_update_threads_qos(kqwl,
						KQWL_UTQ_SET_SYNC_WAITERS_QOS, 0);
			}
			kqwl_req_unlock(kqwl);
		}
	}

	kn->kn_hook = NULL;

	switch (wr) {
	case THREAD_AWAKENED:
		return 0;
	case THREAD_INTERRUPTED:
		return EINTR;
	case THREAD_RESTART:
		return ECANCELED;
	default:
		panic("filt_wlattach: unexpected wait result %d", wr);
		return EINVAL;
	}
}

/* called in stackshot context to report the thread responsible for blocking this thread */
void
kdp_workloop_sync_wait_find_owner(__assert_only thread_t thread,
                                  event64_t event,
                                  thread_waitinfo_t *waitinfo)
{
	struct knote *kn = (struct knote*) event;
	assert(kdp_is_in_zone(kn, "knote zone"));

	assert(kn->kn_hook == thread);

	struct kqueue *kq = knote_get_kq(kn);
	assert(kdp_is_in_zone(kq, "kqueue workloop zone"));
	assert(kq->kq_state & KQ_WORKLOOP);

	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	struct kqrequest *kqr = &kqwl->kqwl_request;

	thread_t kqwl_owner = kqwl->kqwl_owner;
	thread_t servicer = kqr->kqr_thread;

	if (kqwl_owner == WL_OWNER_SUSPENDED) {
		waitinfo->owner = STACKSHOT_WAITOWNER_SUSPENDED;
	} else if (kqwl_owner != THREAD_NULL) {
		assert(kdp_is_in_zone(kqwl_owner, "threads"));

		waitinfo->owner = thread_tid(kqwl->kqwl_owner);
	} else if (servicer != THREAD_NULL) {
		assert(kdp_is_in_zone(servicer, "threads"));

		waitinfo->owner = thread_tid(servicer);
	} else if (kqr->kqr_state & KQR_THREQUESTED) {
		waitinfo->owner = STACKSHOT_WAITOWNER_THREQUESTED;
	} else {
		waitinfo->owner = 0;
	}

	waitinfo->context = kqwl->kqwl_dynamicid;

	return;
}

/*
 * Takes kqueue locked, returns locked, may drop in the middle and/or block for a while
 */
static int
filt_wlpost_attach(struct knote *kn, struct  kevent_internal_s *kev)
{
	struct kqueue *kq = knote_get_kq(kn);
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	int error = 0;

	if (kev->fflags & NOTE_WL_SYNC_WAIT) {
		if (kqlock2knoteuse(kq, kn, KNUSE_NONE)) {
			filt_wllock(kqwl);
			/* if the wake has already preposted, don't wait */
			if ((kn->kn_sfflags & NOTE_WL_SYNC_WAKE) == 0)
				error = filt_wlwait(kqwl, kn, kev);
			filt_wlunlock(kqwl);
			knoteuse2kqlock(kq, kn, KNUSE_NONE);
		}
	}
	return error;
}

static void
filt_wldetach(__assert_only struct knote *kn)
{
	assert(knote_get_kq(kn)->kq_state & KQ_WORKLOOP);

	/*
	 * Thread requests have nothing to detach.
	 * Sync waiters should have been aborted out
	 * and drop their refs before we could drop/
	 * detach their knotes.
	 */
	assert(kn->kn_hook == NULL);
}

static int
filt_wlevent(
	__unused struct knote *kn,
	__unused long hint)
{
	panic("filt_wlevent");
	return 0;
}

static int
filt_wlvalidate_kev_flags(struct knote *kn, struct kevent_internal_s *kev)
{
	int new_commands = kev->fflags & NOTE_WL_COMMANDS_MASK;
	int sav_commands = kn->kn_sfflags & NOTE_WL_COMMANDS_MASK;
	int error = 0;

	switch (new_commands) {
	case NOTE_WL_THREAD_REQUEST:
		/* thread requests can only update themselves */
		if (sav_commands != new_commands)
			error = EINVAL;
		break;

	case NOTE_WL_SYNC_WAIT:
		if (kev->fflags & NOTE_WL_END_OWNERSHIP)
			error = EINVAL;
		/* FALLTHROUGH */
	case NOTE_WL_SYNC_WAKE:
		/* waits and wakes can update themselves or their counterparts */
		if (!(sav_commands & (NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE)))
			error = EINVAL;
		if (kev->fflags & NOTE_WL_UPDATE_QOS)
			error = EINVAL;
		if ((kev->flags & (EV_ENABLE | EV_DELETE)) == EV_ENABLE)
			error = EINVAL;
		if (kev->flags & EV_DELETE) {
			/*
			 * Really this is not supported: there is absolutely no reason
			 * whatsoever to want to fail the drop of a NOTE_WL_SYNC_WAIT knote.
			 */
			if (kev->ext[EV_EXTIDX_WL_ADDR] && kev->ext[EV_EXTIDX_WL_MASK]) {
				error = EINVAL;
			}
		}
		break;

	default:
		error = EINVAL;
	}
	if ((kev->flags & EV_DELETE) && (kev->fflags & NOTE_WL_DISCOVER_OWNER)) {
		error = EINVAL;
	}
	return error;
}

static int
filt_wltouch(
	struct knote *kn,
	struct kevent_internal_s *kev)
{
	struct kqueue *kq = knote_get_kq(kn);
	int error = 0;
	struct kqworkloop *kqwl;

	assert(kq->kq_state & KQ_WORKLOOP);
	kqwl = (struct kqworkloop *)kq;

	error = filt_wlvalidate_kev_flags(kn, kev);
	if (error) {
		goto out;
	}

	filt_wllock(kqwl);

	/* Make sure user and kernel are in agreement on important state */
	error = filt_wldebounce(kqwl, kev, 0);
	if (error) {
		error = filt_wlupdateowner(kqwl, kev, error, 0);
		goto out_unlock;
	}

	int new_command = kev->fflags & NOTE_WL_COMMANDS_MASK;
	switch (new_command) {
	case NOTE_WL_THREAD_REQUEST:
		assert(kqwl->kqwl_request.kqr_qos_index != THREAD_QOS_UNSPECIFIED);
		break;

	case NOTE_WL_SYNC_WAIT:
		/*
		 * we need to allow waiting several times on the same knote because
		 * of EINTR. If it's already woken though, it won't block.
		 */
		break;

	case NOTE_WL_SYNC_WAKE:
		if (kn->kn_sfflags & NOTE_WL_SYNC_WAKE) {
			/* disallow waking the same knote twice */
			error = EALREADY;
			goto out_unlock;
		}
		if (kn->kn_hook) {
			thread_wakeup_thread((event_t)kn, (thread_t)kn->kn_hook);
		}
		break;

	default:
		error = EINVAL;
		goto out_unlock;
	}

	/*
	 * Save off any additional fflags/data we just accepted
	 * But only keep the last round of "update" bits we acted on which helps
	 * debugging a lot.
	 */
	kn->kn_sfflags &= ~NOTE_WL_UPDATES_MASK;
	kn->kn_sfflags |= kev->fflags;
	kn->kn_sdata = kev->data;

	kq_index_t qos_index = THREAD_QOS_UNSPECIFIED;

	if (kev->fflags & NOTE_WL_UPDATE_QOS) {
		qos_t qos = pthread_priority_canonicalize(kev->qos, FALSE);

		if (kn->kn_qos != qos) {
			qos_index = qos_index_from_qos(kn, qos, FALSE);
			if (qos_index == THREAD_QOS_UNSPECIFIED) {
				error = ERANGE;
				goto out_unlock;
			}
			kqlock(kq);
			if (kn->kn_status & KN_QUEUED) {
				knote_dequeue(kn);
				knote_set_qos_index(kn, qos_index);
				knote_enqueue(kn);
				knote_wakeup(kn);
			} else {
				knote_set_qos_index(kn, qos_index);
			}
			kn->kn_qos = qos;
			kqunlock(kq);
		}
	}

	error = filt_wlupdateowner(kqwl, kev, 0, qos_index);
	if (error) {
		goto out_unlock;
	}

	if (new_command == NOTE_WL_SYNC_WAIT) {
		/* if the wake has already preposted, don't wait */
		if ((kn->kn_sfflags & NOTE_WL_SYNC_WAKE) == 0)
			error = filt_wlwait(kqwl, kn, kev);
	}

out_unlock:
	filt_wlremember_last_update(kqwl, kn, kev, error);
	filt_wlunlock(kqwl);
out:
	if (error) {
		if (error == ESTALE && (kev->fflags & NOTE_WL_IGNORE_ESTALE)) {
			/* If userland wants ESTALE to be hidden, do not activate */
			return 0;
		}
		kev->flags |= EV_ERROR;
		kev->data = error;
		return 0;
	}
	/* Just touching the thread request successfully will fire it */
	return new_command == NOTE_WL_THREAD_REQUEST;
}

static int
filt_wldrop_and_unlock(
	struct knote *kn,
	struct kevent_internal_s *kev)
{
	struct kqueue *kq = knote_get_kq(kn);
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	int error = 0, knoteuse_flags = KNUSE_NONE;

	kqlock_held(kq);

	assert(kev->flags & EV_DELETE);
	assert(kq->kq_state & KQ_WORKLOOP);

	error = filt_wlvalidate_kev_flags(kn, kev);
	if (error) {
		goto out;
	}

	if (kn->kn_sfflags & NOTE_WL_THREAD_REQUEST) {
		knoteuse_flags |= KNUSE_BOOST;
	}

	/* take a usecount to allow taking the filt_wllock */
	if (!kqlock2knoteuse(kq, kn, knoteuse_flags)) {
		/* knote is being dropped already */
		error = EINPROGRESS;
		goto out;
	}

	filt_wllock(kqwl);

	/*
	 * Make sure user and kernel are in agreement on important state
	 *
	 * Userland will modify bits to cause this to fail for the touch / drop
	 * race case (when a drop for a thread request quiescing comes in late after
	 * the workloop has been woken up again).
	 */
	error = filt_wldebounce(kqwl, kev, 0);

	if (!knoteuse2kqlock(kq, kn, knoteuse_flags)) {
		/* knote is no longer alive */
		error = EINPROGRESS;
		goto out_unlock;
	}

	if (!error && (kn->kn_sfflags & NOTE_WL_THREAD_REQUEST) && kn->kn_inuse) {
		/*
		 * There is a concurrent drop or touch happening, we can't resolve this,
		 * userland has to redrive.
		 *
		 * The race we're worried about here is the following:
		 *
		 *   f_touch               |  f_drop_and_unlock
		 * ------------------------+--------------------------------------------
		 *                         | kqlock()
		 *                         | kqlock2knoteuse()
		 *                         | filt_wllock()
		 *                         | debounces successfully
		 *  kqlock()               |
		 *  kqlock2knoteuse        |
		 *  filt_wllock() <BLOCKS> |
		 *                         | knoteuse2kqlock()
		 *                         | filt_wlunlock()
		 *                         | kqlock2knotedrop() <BLOCKS, WAKES f_touch>
		 *  debounces successfully |
		 *  filt_wlunlock()        |
		 *  caller WAKES f_drop    |
		 *                         | performs drop, but f_touch should have won
		 *
		 * So if the usecount is not 0 here, we need to wait for it to drop and
		 * redrive the whole logic (including looking up the knote again).
		 */
		filt_wlunlock(kqwl);
		knoteusewait(kq, kn);
		return ERESTART;
	}

	/*
	 * If error is 0 this will set kqr_qos_index to THREAD_QOS_UNSPECIFIED
	 *
	 * If error is 0 or ESTALE this may drop ownership and cause a thread
	 * request redrive, however the kqlock is held which prevents f_process() to
	 * run until we did the drop for real.
	 */
	error = filt_wlupdateowner(kqwl, kev, error, 0);
	if (error) {
		goto out_unlock;
	}

	if ((kn->kn_sfflags & (NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE)) ==
			NOTE_WL_SYNC_WAIT) {
		/*
		 * When deleting a SYNC_WAIT knote that hasn't been woken up
		 * explicitly, issue a wake up.
		 */
		kn->kn_sfflags |= NOTE_WL_SYNC_WAKE;
		if (kn->kn_hook) {
			thread_wakeup_thread((event_t)kn, (thread_t)kn->kn_hook);
		}
	}

out_unlock:
	filt_wlremember_last_update(kqwl, kn, kev, error);
	filt_wlunlock(kqwl);

out:
	if (error == 0) {
		/* If nothing failed, do the regular knote drop. */
		if (kqlock2knotedrop(kq, kn)) {
			knote_drop(kn, current_proc());
		} else {
			error = EINPROGRESS;
		}
	} else {
		kqunlock(kq);
	}
	if (error == ESTALE && (kev->fflags & NOTE_WL_IGNORE_ESTALE)) {
		error = 0;
	}
	if (error == EINPROGRESS) {
		/*
		 * filt_wlprocess() makes sure that no event can be delivered for
		 * NOTE_WL_THREAD_REQUEST knotes once a drop is happening, and
		 * NOTE_WL_SYNC_* knotes are never fired.
		 *
		 * It means that EINPROGRESS is about a state that userland cannot
		 * observe for this filter (an event being delivered concurrently from
		 * a drop), so silence the error.
		 */
		error = 0;
	}
	return error;
}

static int
filt_wlprocess(
	struct knote *kn,
	__unused struct filt_process_s *data,
	struct kevent_internal_s *kev)
{
	struct kqueue *kq = knote_get_kq(kn);
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	struct kqrequest *kqr = &kqwl->kqwl_request;
	int rc = 0;

	assert(kq->kq_state & KQ_WORKLOOP);

	/* only thread requests should get here */
	assert(kn->kn_sfflags & NOTE_WL_THREAD_REQUEST);
	if (kn->kn_sfflags & NOTE_WL_THREAD_REQUEST) {
		filt_wllock(kqwl);
		assert(kqr->kqr_qos_index != THREAD_QOS_UNSPECIFIED);
		if (kqwl->kqwl_owner) {
			/*
			 * <rdar://problem/33584321> userspace sometimes due to events being
			 * delivered but not triggering a drain session can cause a process
			 * of the thread request knote.
			 *
			 * When that happens, the automatic deactivation due to process
			 * would swallow the event, so we have to activate the knote again.
			 */
			kqlock(kq);
			knote_activate(kn);
			kqunlock(kq);
		} else if (kqr->kqr_qos_index) {
#if DEBUG || DEVELOPMENT
			user_addr_t addr = CAST_USER_ADDR_T(kn->kn_ext[EV_EXTIDX_WL_ADDR]);
			task_t t = current_task();
			uint64_t val;
			if (addr && task_is_active(t) && !task_is_halting(t) &&
					copyin_word(addr, &val, sizeof(val)) == 0 &&
					val && (val & DISPATCH_QUEUE_ENQUEUED) == 0 &&
					(val >> 48) != 0 && (val >> 48) != 0xffff) {
				panic("kevent: workloop %#016llx is not enqueued "
						"(kn:%p dq_state:%#016llx kev.dq_state:%#016llx)",
						kn->kn_udata, kn, val,
						kn->kn_ext[EV_EXTIDX_WL_VALUE]);
			}
#endif
			*kev = kn->kn_kevent;
			kev->fflags = kn->kn_sfflags;
			kev->data = kn->kn_sdata;
			kev->qos = kn->kn_qos;
			rc = 1;
		}
		filt_wlunlock(kqwl);
	}
	return rc;
}

#pragma mark kevent / knotes

/*
 * JMM - placeholder for not-yet-implemented filters
 */
static int
filt_badattach(__unused struct knote *kn, __unused struct kevent_internal_s *kev)
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
	void *hook = NULL;
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
			kqwq->kqwq_request[i].kqr_qos_index = i;
		}

		lck_spin_init(&kqwq->kqwq_reqlock, kq_lck_grp, kq_lck_attr);
		policy = SYNC_POLICY_FIFO;
		hook = (void *)kqwq;
		
	} else if (flags & KEVENT_FLAG_WORKLOOP) {
		struct kqworkloop *kqwl;
		int i;

		kqwl = (struct kqworkloop *)zalloc(kqworkloop_zone);
		if (kqwl == NULL)
			return NULL;

		bzero(kqwl, sizeof (struct kqworkloop));

		kqwl->kqwl_state = KQ_WORKLOOP | KQ_DYNAMIC;
		kqwl->kqwl_retains = 1; /* donate a retain to creator */

		kq = &kqwl->kqwl_kqueue;
		for (i = 0; i < KQWL_NBUCKETS; i++) {
			TAILQ_INIT(&kq->kq_queue[i]);
		}
		TAILQ_INIT(&kqwl->kqwl_request.kqr_suppressed);

		lck_spin_init(&kqwl->kqwl_reqlock, kq_lck_grp, kq_lck_attr);
		lck_mtx_init(&kqwl->kqwl_statelock, kq_lck_grp, kq_lck_attr);

		policy = SYNC_POLICY_FIFO;
		if (flags & KEVENT_FLAG_WORKLOOP_NO_WQ_THREAD) {
			policy |= SYNC_POLICY_PREPOST;
			kq->kq_state |= KQ_NO_WQ_THREAD;
		} else {
			hook = (void *)kqwl;
		}
		
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
 * knotes_dealloc - detach all knotes for the process and drop them
 *
 * 		Called with proc_fdlock held.
 * 		Returns with it locked.
 * 		May drop it temporarily.
 * 		Process is in such a state that it will not try to allocate
 *		any more knotes during this process (stopped for exit or exec).
 */
void
knotes_dealloc(proc_t p)
{
	struct filedesc *fdp = p->p_fd;
	struct kqueue *kq;
	struct knote *kn;
	struct  klist *kn_hash = NULL;
	int i;

	/* Close all the fd-indexed knotes up front */
	if (fdp->fd_knlistsize > 0) {
		for (i = 0; i < fdp->fd_knlistsize; i++) {
			while ((kn = SLIST_FIRST(&fdp->fd_knlist[i])) != NULL) {
				kq = knote_get_kq(kn);
				kqlock(kq);
				proc_fdunlock(p);
				/* drop it ourselves or wait */
				if (kqlock2knotedrop(kq, kn)) {
					knote_drop(kn, p);
				}
				proc_fdlock(p);
			}
		}
		/* free the table */
		FREE(fdp->fd_knlist, M_KQUEUE);
		fdp->fd_knlist = NULL;
	}
	fdp->fd_knlistsize = -1;

	knhash_lock(p);
	proc_fdunlock(p);

	/* Clean out all the hashed knotes as well */
	if (fdp->fd_knhashmask != 0) {
		for (i = 0; i <= (int)fdp->fd_knhashmask; i++) {
			while ((kn = SLIST_FIRST(&fdp->fd_knhash[i])) != NULL) {
				kq = knote_get_kq(kn);
				kqlock(kq);
				knhash_unlock(p);
				/* drop it ourselves or wait */
				if (kqlock2knotedrop(kq, kn)) {
					knote_drop(kn, p);
				}
				knhash_lock(p);
			}
		}
		kn_hash = fdp->fd_knhash;
		fdp->fd_knhashmask = 0;
		fdp->fd_knhash = NULL;
	}

	knhash_unlock(p);

	/* free the kn_hash table */
	if (kn_hash)
		FREE(kn_hash, M_KQUEUE);

	proc_fdlock(p);
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
 *
 * Workloop kqueues cant get here unless all the knotes
 * are already gone and all requested threads have come
 * and gone (cancelled or arrived).
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

	if ((kq->kq_state & KQ_WORKLOOP) == 0) {
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
		knhash_lock(p);
		proc_fdunlock(p);

		if (fdp->fd_knhashmask != 0) {
			for (i = 0; i < (int)fdp->fd_knhashmask + 1; i++) {
				kn = SLIST_FIRST(&fdp->fd_knhash[i]);
				while (kn != NULL) {
					if (kq == knote_get_kq(kn)) {
						kqlock(kq);
						knhash_unlock(p);
						/* drop it ourselves or wait */
						if (kqlock2knotedrop(kq, kn)) {
							knote_drop(kn, p);
						}
						knhash_lock(p);
						/* start over at beginning of list */
						kn = SLIST_FIRST(&fdp->fd_knhash[i]);
						continue;
					}
					kn = SLIST_NEXT(kn, kn_link);
				}
			}
		}
		knhash_unlock(p);
	}

	if (kq->kq_state & KQ_WORKLOOP) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;
		struct kqrequest *kqr = &kqwl->kqwl_request;
		thread_t cur_owner = kqwl->kqwl_owner;

		assert(TAILQ_EMPTY(&kqwl->kqwl_request.kqr_suppressed));
		if (filt_wlowner_is_valid(cur_owner)) {
			/*
			 * If the kqueue had an owner that prevented the thread request to
			 * go through, then no unbind happened, and we may have lingering
			 * overrides to drop.
			 */
			if (kqr->kqr_dsync_owner_qos != THREAD_QOS_UNSPECIFIED) {
				thread_drop_ipc_override(cur_owner);
				kqr->kqr_dsync_owner_qos = THREAD_QOS_UNSPECIFIED;
			}

			if (kqr->kqr_owner_override_is_sync) {
				thread_drop_sync_ipc_override(cur_owner);
				kqr->kqr_owner_override_is_sync = 0;
			}
			thread_ends_owning_workloop(cur_owner);
			thread_deallocate(cur_owner);
			kqwl->kqwl_owner = THREAD_NULL;
		}
	}

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
	} else if (kq->kq_state & KQ_WORKLOOP) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;

		assert(kqwl->kqwl_retains == 0);
		lck_spin_destroy(&kqwl->kqwl_reqlock, kq_lck_grp);
		lck_mtx_destroy(&kqwl->kqwl_statelock, kq_lck_grp);
		zfree(kqworkloop_zone, kqwl);
	} else {
		struct kqfile *kqf = (struct kqfile *)kq;

		zfree(kqfile_zone, kqf);
	}
}

static inline void
kqueue_retain(struct kqueue *kq)
{
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	uint32_t previous;

	if ((kq->kq_state & KQ_DYNAMIC) == 0)
		return;

	previous = OSIncrementAtomic(&kqwl->kqwl_retains);
	if (previous == KQ_WORKLOOP_RETAINS_MAX)
		panic("kq(%p) retain overflow", kq);

	if (previous == 0)
		panic("kq(%p) resurrection", kq);
}

#define KQUEUE_CANT_BE_LAST_REF  0
#define KQUEUE_MIGHT_BE_LAST_REF 1

static inline int
kqueue_release(struct kqueue *kq, __assert_only int possibly_last)
{
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;

	if ((kq->kq_state & KQ_DYNAMIC) == 0) {
		return 0;
	}

	assert(kq->kq_state & KQ_WORKLOOP); /* for now */
	uint32_t refs = OSDecrementAtomic(&kqwl->kqwl_retains);
	if (__improbable(refs == 0)) {
		panic("kq(%p) over-release", kq);
	}
	if (refs == 1) {
		assert(possibly_last);
	}
	return refs == 1;
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

	kevent_put_kq(p, fd, fp, kq);

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
	                       (kqueue_id_t)uap->fd, NULL,
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
	                       (kqueue_id_t)uap->fd, NULL,
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
	                       (kqueue_id_t)uap->fd, NULL,
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
	                       (kqueue_id_t)fd, NULL,
	                       changelist, nchanges,
	                       eventlist, nevents,
	                       data_out, (uint64_t)data_available,
	                       (flags | KEVENT_FLAG_KERNEL),
	                       0ULL,
	                       NULL,
	                       retval);
}

int
kevent_id(struct proc *p, struct kevent_id_args *uap, int32_t *retval)
{
	/* restrict to user flags */
	uap->flags &= KEVENT_FLAG_USER;

	return kevent_internal(p,
	                       (kqueue_id_t)uap->id, NULL,
	                       uap->changelist, uap->nchanges,
	                       uap->eventlist,	uap->nevents,
	                       uap->data_out, (uint64_t)uap->data_available,
	                       (uap->flags | KEVENT_FLAG_DYNAMIC_KQUEUE),
	                       0ULL,
	                       kevent_continue,
	                       retval);
}

int
kevent_id_internal(struct proc *p, kqueue_id_t *id,
		    user_addr_t changelist, int nchanges,
		    user_addr_t eventlist, int nevents,
		    user_addr_t data_out, user_size_t *data_available,
		    unsigned int flags, 
		    int32_t *retval) 
{
	return kevent_internal(p,
	                       *id, id,
	                       changelist, nchanges,
	                       eventlist, nevents,
	                       data_out, (uint64_t)data_available,
	                       (flags | KEVENT_FLAG_KERNEL | KEVENT_FLAG_DYNAMIC_KQUEUE),
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
	} else if (flags & KEVENT_FLAG_LEGACY64) {
		kq->kq_state |= KQ_KEV64;
	} else {
		kq->kq_state |= KQ_KEV_QOS;
	}
	kqunlock(kq);
	return 0;
}

#define	KQ_HASH(val, mask)  (((val) ^ (val >> 8)) & (mask))
#define CONFIG_KQ_HASHSIZE  CONFIG_KN_HASHSIZE

static inline void
kqhash_lock(proc_t p)
{
	lck_mtx_lock_spin_always(&p->p_fd->fd_kqhashlock);
}

static inline void
kqhash_lock_held(__assert_only proc_t p)
{
	LCK_MTX_ASSERT(&p->p_fd->fd_kqhashlock, LCK_MTX_ASSERT_OWNED);
}

static inline void
kqhash_unlock(proc_t p)
{
	lck_mtx_unlock(&p->p_fd->fd_kqhashlock);
}

static void
kqueue_hash_init_if_needed(proc_t p)
{
	struct filedesc *fdp = p->p_fd;

	kqhash_lock_held(p);

	if (__improbable(fdp->fd_kqhash == NULL)) {
		struct kqlist *alloc_hash;
		u_long alloc_mask;

		kqhash_unlock(p);
		alloc_hash = hashinit(CONFIG_KQ_HASHSIZE, M_KQUEUE, &alloc_mask);
		kqhash_lock(p);

		/* See if we won the race */
		if (fdp->fd_kqhashmask == 0) {
			fdp->fd_kqhash = alloc_hash;
			fdp->fd_kqhashmask = alloc_mask;
		} else {
			kqhash_unlock(p);
			FREE(alloc_hash, M_KQUEUE);
			kqhash_lock(p);
		}
	}
}

/*
 * Called with the kqhash_lock() held
 */
static void
kqueue_hash_insert(
	struct proc *p,
	kqueue_id_t id,
	struct kqueue *kq)
{
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	struct filedesc *fdp = p->p_fd;
	struct kqlist *list;

	/* should hold the kq hash lock */
	kqhash_lock_held(p);

	if ((kq->kq_state & KQ_DYNAMIC) == 0) {
		assert(kq->kq_state & KQ_DYNAMIC);
		return;
	}

	/* only dynamically allocate workloop kqs for now */
	assert(kq->kq_state & KQ_WORKLOOP);
	assert(fdp->fd_kqhash);

	kqwl->kqwl_dynamicid = id;

	list = &fdp->fd_kqhash[KQ_HASH(id, fdp->fd_kqhashmask)];
	SLIST_INSERT_HEAD(list, kqwl, kqwl_hashlink);
}

/* Called with kqhash_lock held */
static void
kqueue_hash_remove(
	struct proc *p,
	struct kqueue *kq)
{
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	struct filedesc *fdp = p->p_fd;
	struct kqlist *list;

	/* should hold the kq hash lock */
	kqhash_lock_held(p);

	if ((kq->kq_state & KQ_DYNAMIC) == 0) {
		assert(kq->kq_state & KQ_DYNAMIC);
		return;
	}
	assert(kq->kq_state & KQ_WORKLOOP); /* for now */
	list = &fdp->fd_kqhash[KQ_HASH(kqwl->kqwl_dynamicid, fdp->fd_kqhashmask)];
	SLIST_REMOVE(list, kqwl, kqworkloop, kqwl_hashlink);
}

/* Called with kqhash_lock held */
static struct kqueue *
kqueue_hash_lookup(struct proc *p, kqueue_id_t id)
{
	struct filedesc *fdp = p->p_fd;
	struct kqlist *list;
	struct kqworkloop *kqwl;

	/* should hold the kq hash lock */
	kqhash_lock_held(p);

	if (fdp->fd_kqhashmask == 0) return NULL;

	list = &fdp->fd_kqhash[KQ_HASH(id, fdp->fd_kqhashmask)];
	SLIST_FOREACH(kqwl, list, kqwl_hashlink) {
		if (kqwl->kqwl_dynamicid == id) {
			struct kqueue *kq = (struct kqueue *)kqwl;

			assert(kq->kq_state & KQ_DYNAMIC);
			assert(kq->kq_state & KQ_WORKLOOP); /* for now */
			return kq;
		}
	}
	return NULL;
}

static inline void
kqueue_release_last(struct proc *p, struct kqueue *kq)
{
	if (kq->kq_state & KQ_DYNAMIC) {
		kqhash_lock(p);
		if (kqueue_release(kq, KQUEUE_MIGHT_BE_LAST_REF)) {
			kqueue_hash_remove(p, kq);
			kqhash_unlock(p);
			kqueue_dealloc(kq);
		} else {
			kqhash_unlock(p);
		}
	}
}

static struct kqueue *
kevent_get_bound_kq(__assert_only struct proc *p, thread_t thread,
                    unsigned int kev_flags, unsigned int kq_flags)
{
	struct kqueue *kq;
	struct uthread *ut = get_bsdthread_info(thread);

	assert(p == get_bsdthreadtask_info(thread));

	if (!(ut->uu_kqueue_flags & kev_flags))
		return NULL;

	kq = ut->uu_kqueue_bound;
	if (!kq)
		return NULL;

	if (!(kq->kq_state & kq_flags))
		return NULL;

	return kq;
}

static int
kevent_get_kq(struct proc *p, kqueue_id_t id, unsigned int flags, struct fileproc **fpp, int *fdp, struct kqueue **kqp)
{
	struct filedesc *descp = p->p_fd;
	struct fileproc *fp = NULL;
	struct kqueue *kq;
	int fd = 0;
	int error = 0;

	/* Was the workloop flag passed?  Then it is for sure only a workloop */
	if (flags & KEVENT_FLAG_DYNAMIC_KQUEUE) {
		assert(flags & KEVENT_FLAG_WORKLOOP);
		if (id == (kqueue_id_t)-1 &&
		    (flags & KEVENT_FLAG_KERNEL) &&
		    (flags & KEVENT_FLAG_WORKLOOP)) {

			assert(is_workqueue_thread(current_thread()));

			/*
			 * when kevent_id_internal is called from within the
			 * kernel, and the passed 'id' value is '-1' then we
			 * look for the currently bound workloop kq.
			 *
			 * Until pthread kext avoids calling in to kevent_id_internal
			 * for threads whose fulfill is canceled, calling in unbound
			 * can't be fatal.
			 */
			kq = kevent_get_bound_kq(p, current_thread(),
			                         KEVENT_FLAG_WORKLOOP, KQ_WORKLOOP);
			if (kq) {
				kqueue_retain(kq);
			} else {
				struct uthread *ut = get_bsdthread_info(current_thread());

				/* If thread is unbound due to cancel, just return an error */
				if (ut->uu_kqueue_flags == KEVENT_FLAG_WORKLOOP_CANCELED) {
					ut->uu_kqueue_flags = 0;
					error = ECANCELED;
				} else {
					panic("Unbound thread called kevent_internal with id=-1"
					      " uu_kqueue_flags:0x%x, uu_kqueue_bound:%p",
					      ut->uu_kqueue_flags, ut->uu_kqueue_bound);
				}
			}

			*fpp = NULL;
			*fdp = 0;
			*kqp = kq;
			return error;
		}

		/* try shortcut on kq lookup for bound threads */
		kq = kevent_get_bound_kq(p, current_thread(), KEVENT_FLAG_WORKLOOP, KQ_WORKLOOP);
		if (kq != NULL && ((struct kqworkloop *)kq)->kqwl_dynamicid == id) {

			if (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST) {
				error = EEXIST;
				kq = NULL;
				goto out;
			}

			/* retain a reference while working with this kq. */
			assert(kq->kq_state & KQ_DYNAMIC);
			kqueue_retain(kq);
			error = 0;
			goto out;
		}

		/* look for the kq on the hash table */
		kqhash_lock(p);
		kq = kqueue_hash_lookup(p, id);
		if (kq == NULL) {
			kqhash_unlock(p);

			if (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST) {
				error = ENOENT;
				goto out;
			}

			struct kqueue *alloc_kq;
			alloc_kq = kqueue_alloc(p, flags);
			if (alloc_kq) {
				kqhash_lock(p);
				kqueue_hash_init_if_needed(p);
				kq = kqueue_hash_lookup(p, id);
				if (kq == NULL) {
					/* insert our new one */
					kq = alloc_kq;
					kqueue_hash_insert(p, id, kq);
					kqhash_unlock(p);
				} else {
					/* lost race, retain existing workloop */
					kqueue_retain(kq);
					kqhash_unlock(p);
					kqueue_release(alloc_kq, KQUEUE_MIGHT_BE_LAST_REF);
					kqueue_dealloc(alloc_kq);
				}
			} else {
				error = ENOMEM;
				goto out;
			}
		} else {

			if (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST) {
				kqhash_unlock(p);
				kq = NULL;
				error =  EEXIST;
				goto out;
			}

			/* retain a reference while working with this kq. */
			assert(kq->kq_state & KQ_DYNAMIC);
			kqueue_retain(kq);
			kqhash_unlock(p);
		}
		
	} else if (flags & KEVENT_FLAG_WORKQ) {
		/* must already exist for bound threads. */
		if (flags & KEVENT_FLAG_KERNEL) {
			assert(descp->fd_wqkqueue != NULL);
		}

		/*
		 * use the private kq associated with the proc workq.
		 * Just being a thread within the process (and not
		 * being the exit/exec thread) is enough to hold a
		 * reference on this special kq.
		 */
		kq = descp->fd_wqkqueue;
		if (kq == NULL) {
			struct kqueue *alloc_kq = kqueue_alloc(p, KEVENT_FLAG_WORKQ);
			if (alloc_kq == NULL)
				return ENOMEM;

			knhash_lock(p);
			if (descp->fd_wqkqueue == NULL) {
				kq = descp->fd_wqkqueue = alloc_kq;
				knhash_unlock(p);
			} else {
				knhash_unlock(p);
				kq = descp->fd_wqkqueue;
				kqueue_dealloc(alloc_kq);
			}
		}
	} else {
		/* get a usecount for the kq itself */
		fd = (int)id;
		if ((error = fp_getfkq(p, fd, &fp, &kq)) != 0)
			return (error);
	}
	if ((error = kevent_set_kq_mode(kq, flags)) != 0) {
		/* drop the usecount */
		if (fp != NULL)
			fp_drop(p, fd, fp, 0);
		return error;
	} 

out:
	*fpp = fp;
	*fdp = fd;
	*kqp = kq;
	
	return error;
}

static void
kevent_put_kq(
	struct proc *p,
	kqueue_id_t id,
	struct fileproc *fp,
	struct kqueue *kq)
{
	kqueue_release_last(p, kq);
	if (fp != NULL) {
		assert((kq->kq_state & KQ_WORKQ) == 0);
		fp_drop(p, (int)id, fp, 0);
	}
}

static uint64_t
kevent_workloop_serial_no_copyin(proc_t p, uint64_t workloop_id)
{
	uint64_t serial_no = 0;
	user_addr_t addr;
	int rc;

	if (workloop_id == 0 || p->p_dispatchqueue_serialno_offset == 0) {
		return 0;
	}
	addr = (user_addr_t)(workloop_id + p->p_dispatchqueue_serialno_offset);

	if (proc_is64bit(p)) {
		rc = copyin(addr, (caddr_t)&serial_no, sizeof(serial_no));
	} else {
		uint32_t serial_no32 = 0;
		rc = copyin(addr, (caddr_t)&serial_no32, sizeof(serial_no32));
		serial_no = serial_no32;
	}
	return rc == 0 ? serial_no : 0;
}

int
kevent_exit_on_workloop_ownership_leak(thread_t thread)
{
	proc_t p = current_proc();
	struct filedesc *fdp = p->p_fd;
	kqueue_id_t workloop_id = 0;
	os_reason_t reason;
	mach_vm_address_t addr;
	uint32_t reason_size;

	kqhash_lock(p);
	if (fdp->fd_kqhashmask > 0) {
		for (uint32_t i = 0; i < fdp->fd_kqhashmask + 1; i++) {
			struct kqworkloop *kqwl;

			SLIST_FOREACH(kqwl, &fdp->fd_kqhash[i], kqwl_hashlink) {
				struct kqueue *kq = &kqwl->kqwl_kqueue;
				if ((kq->kq_state & KQ_DYNAMIC) && kqwl->kqwl_owner == thread) {
					workloop_id = kqwl->kqwl_dynamicid;
					break;
				}
			}
		}
	}
	kqhash_unlock(p);
	assert(workloop_id);

	reason = os_reason_create(OS_REASON_LIBSYSTEM,
			OS_REASON_LIBSYSTEM_CODE_WORKLOOP_OWNERSHIP_LEAK);
	if (reason == OS_REASON_NULL) {
		goto out;
	}

	reason->osr_flags |= OS_REASON_FLAG_GENERATE_CRASH_REPORT;
	reason_size = 2 * sizeof(uint64_t);
	reason_size = kcdata_estimate_required_buffer_size(2, reason_size);
	if (os_reason_alloc_buffer(reason, reason_size) != 0) {
		goto out;
	}

	struct kcdata_descriptor *kcd = &reason->osr_kcd_descriptor;

	if (kcdata_get_memory_addr(kcd, EXIT_REASON_WORKLOOP_ID,
			sizeof(workloop_id), &addr) == KERN_SUCCESS) {
		kcdata_memcpy(kcd, addr, &workloop_id, sizeof(workloop_id));
	}

	uint64_t serial_no = kevent_workloop_serial_no_copyin(p, workloop_id);
	if (serial_no && kcdata_get_memory_addr(kcd, EXIT_REASON_DISPATCH_QUEUE_NO,
			sizeof(serial_no), &addr) == KERN_SUCCESS) {
		kcdata_memcpy(kcd, addr, &serial_no, sizeof(serial_no));
	}

out:
#if DEVELOPMENT || DEBUG
	psignal_try_thread_with_reason(p, thread, SIGABRT, reason);
	return 0;
#else
	return exit_with_reason(p, W_EXITCODE(0, SIGKILL), (int *)NULL,
			FALSE, FALSE, 0, reason);
#endif
}


static int
kevent_servicer_detach_preflight(thread_t thread, unsigned int flags, struct kqueue *kq)
{
	int error = 0;
	struct kqworkloop *kqwl;
	struct uthread *ut;
	struct kqrequest *kqr;

	if (!(flags & KEVENT_FLAG_WORKLOOP) || !(kq->kq_state & KQ_WORKLOOP))
		return EINVAL;

	/* only kq created with KEVENT_FLAG_WORKLOOP_NO_WQ_THREAD from userspace can have attached threads */
	if (!(kq->kq_state & KQ_NO_WQ_THREAD))
		return EINVAL;

	/* allow detach only on not wq threads */
	if (is_workqueue_thread(thread))
		return EINVAL;

	/* check that the current thread is bound to the requested wq */
	ut = get_bsdthread_info(thread);
	if (ut->uu_kqueue_bound != kq)
		return EINVAL;

	kqwl = (struct kqworkloop *)kq;
	kqwl_req_lock(kqwl);
	kqr = &kqwl->kqwl_request;

	/* check that the wq is bound to the thread */
	if ((kqr->kqr_state & KQR_BOUND) == 0  || (kqr->kqr_thread != thread))
		error = EINVAL;

	kqwl_req_unlock(kqwl);

	return error;
}

static void
kevent_servicer_detach_thread(struct proc *p, kqueue_id_t id, thread_t thread,
		unsigned int flags, struct kqueue *kq)
{
	struct kqworkloop *kqwl;
	struct uthread *ut;

	assert((flags & KEVENT_FLAG_WORKLOOP) && (kq->kq_state & KQ_WORKLOOP));

	/* allow detach only on not wqthreads threads */
	assert(!is_workqueue_thread(thread));

	/* only kq created with KEVENT_FLAG_WORKLOOP_NO_WQ_THREAD from userspace can have attached threads */
	assert(kq->kq_state & KQ_NO_WQ_THREAD);

	/* check that the current thread is bound to the requested kq */
	ut = get_bsdthread_info(thread);
	assert(ut->uu_kqueue_bound == kq);

	kqwl = (struct kqworkloop *)kq;

	kqlock(kq);

	/* unbind the thread.
	 * unbind itself checks if still processing and ends it.
	 */
	kqworkloop_unbind_thread(kqwl, thread, flags);

	kqunlock(kq);

	kevent_put_kq(p, id, NULL, kq);

	return;
}

static int
kevent_servicer_attach_thread(thread_t thread, unsigned int flags, struct kqueue *kq)
{
	int error = 0;
	struct kqworkloop *kqwl;
	struct uthread *ut;
	struct kqrequest *kqr;

	if (!(flags & KEVENT_FLAG_WORKLOOP) || !(kq->kq_state & KQ_WORKLOOP))
		return EINVAL;

	/* only kq created with KEVENT_FLAG_WORKLOOP_NO_WQ_THREAD from userspace can have attached threads*/
	if (!(kq->kq_state & KQ_NO_WQ_THREAD))
		return EINVAL;

	/* allow attach only on not wqthreads */
	if (is_workqueue_thread(thread))
		return EINVAL;

	/* check that the thread is not already bound */
	ut = get_bsdthread_info(thread);
	if (ut->uu_kqueue_bound != NULL)
		return EINVAL;

	assert(ut->uu_kqueue_flags == 0);

	kqlock(kq);
	kqwl = (struct kqworkloop *)kq;
	kqwl_req_lock(kqwl);
	kqr = &kqwl->kqwl_request;

	/* check that the kqueue is not already bound */
	if (kqr->kqr_state & (KQR_BOUND | KQR_THREQUESTED | KQR_DRAIN)) {
		error = EINVAL;
		goto out;
	}

	assert(kqr->kqr_thread == NULL);
	assert((kqr->kqr_state & KQR_PROCESSING) == 0);

	kqr->kqr_state |= KQR_THREQUESTED;
	kqr->kqr_qos_index = THREAD_QOS_UNSPECIFIED;
	kqr->kqr_override_index = THREAD_QOS_UNSPECIFIED;
	kqr->kqr_dsync_owner_qos = THREAD_QOS_UNSPECIFIED;
	kqr->kqr_owner_override_is_sync = 0;

	kqworkloop_bind_thread_impl(kqwl, thread, KEVENT_FLAG_WORKLOOP);

	/* get a ref on the wlkq on behalf of the attached thread */
	kqueue_retain(kq);

out:
	kqwl_req_unlock(kqwl);
	kqunlock(kq);

	return error;
}

static inline
boolean_t kevent_args_requesting_events(unsigned int flags, int nevents)
{
	return (!(flags & KEVENT_FLAG_ERROR_EVENTS) && nevents > 0);
}

static int
kevent_internal(struct proc *p,
		kqueue_id_t id, kqueue_id_t *id_out,
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
	int fd = 0;
	struct kevent_internal_s kev;
	int error, noutputs;
	struct timeval atv;
	user_size_t data_size;
	user_size_t data_resid;
	thread_t thread = current_thread();

	/* Don't allow user-space threads to process output events from the workq kqs */
	if (((flags & (KEVENT_FLAG_WORKQ | KEVENT_FLAG_KERNEL)) == KEVENT_FLAG_WORKQ) &&
	    kevent_args_requesting_events(flags, nevents))
		return EINVAL;

	/* restrict dynamic kqueue allocation to workloops (for now) */
	if ((flags & (KEVENT_FLAG_DYNAMIC_KQUEUE | KEVENT_FLAG_WORKLOOP)) == KEVENT_FLAG_DYNAMIC_KQUEUE)
		return EINVAL;

	if ((flags & (KEVENT_FLAG_WORKLOOP)) && (flags & (KEVENT_FLAG_WORKQ)))
                return EINVAL;

	if (flags & (KEVENT_FLAG_WORKLOOP_SERVICER_ATTACH | KEVENT_FLAG_WORKLOOP_SERVICER_DETACH |
	    KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST | KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST | KEVENT_FLAG_WORKLOOP_NO_WQ_THREAD)) {

		/* allowed only on workloops when calling kevent_id from user-space */
		if (!(flags & KEVENT_FLAG_WORKLOOP) || (flags & KEVENT_FLAG_KERNEL) || !(flags & KEVENT_FLAG_DYNAMIC_KQUEUE))
			return EINVAL;

		/* cannot attach and detach simultaneously*/
		if ((flags & KEVENT_FLAG_WORKLOOP_SERVICER_ATTACH) && (flags & KEVENT_FLAG_WORKLOOP_SERVICER_DETACH))
			return EINVAL;

		/* cannot ask for events and detach */
		if ((flags & KEVENT_FLAG_WORKLOOP_SERVICER_DETACH) && kevent_args_requesting_events(flags, nevents))
			return EINVAL;

	}

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
	error = kevent_get_kq(p, id, flags, &fp, &fd, &kq);
	if (error)
		return error;

	/* only bound threads can receive events on workloops */
	if ((flags & KEVENT_FLAG_WORKLOOP) && kevent_args_requesting_events(flags, nevents)) {
		ut = (uthread_t)get_bsdthread_info(thread);
		if (ut->uu_kqueue_bound != kq) {
			error = EXDEV;
			goto out;
		}

	}

	/* attach the current thread if necessary */
	if (flags & KEVENT_FLAG_WORKLOOP_SERVICER_ATTACH) {
		error = kevent_servicer_attach_thread(thread, flags, kq);
		if (error)
			goto out;
	}
	else {
		/* before processing events and committing to the system call, return an error if the thread cannot be detached when requested */
		if (flags & KEVENT_FLAG_WORKLOOP_SERVICER_DETACH) {
			error = kevent_servicer_detach_preflight(thread, flags, kq);
			if (error)
				goto out;
		}
	}

	if (id_out && kq && (flags & KEVENT_FLAG_WORKLOOP)) {
		assert(kq->kq_state & KQ_WORKLOOP);
		struct kqworkloop *kqwl;
		kqwl = (struct kqworkloop *)kq;
		*id_out = kqwl->kqwl_dynamicid;
	}

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
		ut = (uthread_t)get_bsdthread_info(thread);
		cont_args = &ut->uu_kevent.ss_kevent;
		cont_args->fp = fp;
		cont_args->fd = fd;
		cont_args->retval = retval;
		cont_args->eventlist = ueventlist;
		cont_args->eventcount = nevents;
		cont_args->eventout = noutputs;
		cont_args->data_available = data_available;
		cont_args->process_data.fp_fd = (int)id;
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

	/* detach the current thread if necessary */
	if (flags & KEVENT_FLAG_WORKLOOP_SERVICER_DETACH) {
		assert(fp == NULL);
		kevent_servicer_detach_thread(p, id, thread, flags, kq);
	}

out:
	kevent_put_kq(p, id, fp, kq);

	/* don't restart after signals... */
	if (error == ERESTART)
		error = EINTR;
	else if (error == EWOULDBLOCK)
		error = 0;
	if (error == 0)
		*retval = noutputs;
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
	const struct filterops *fops;
	struct knote *kn = NULL;
	int result = 0;
	int error = 0;
	unsigned short kev_flags = kev->flags;
	int knoteuse_flags = KNUSE_NONE;

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

	if (kq->kq_state & KQ_WORKLOOP) {
		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_REGISTER),
		              ((struct kqworkloop *)kq)->kqwl_dynamicid,
		              kev->udata, kev->flags, kev->filter);
	} else if (kq->kq_state & KQ_WORKQ) {
		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_REGISTER),
		              0, kev->udata, kev->flags, kev->filter);
	} else {
		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQ_REGISTER),
		              VM_KERNEL_UNSLIDE_OR_PERM(kq),
		              kev->udata, kev->flags, kev->filter);
	}

restart:

	/* find the matching knote from the fd tables/hashes */
	kn = kq_find_knote_and_kq_lock(kq, kev, fops->f_isfd, p);

	if (kn == NULL) {
		if (kev->flags & EV_ADD) {
			struct fileproc *knote_fp = NULL;

			/* grab a file reference for the new knote */
			if (fops->f_isfd) {
				if ((error = fp_lookup(p, kev->ident, &knote_fp, 0)) != 0) {
					goto out;
				}
			}

			kn = knote_alloc();
			if (kn == NULL) {
				error = ENOMEM;
				if (knote_fp != NULL)
					fp_drop(p, kev->ident, knote_fp, 0);
				goto out;
			}

			kn->kn_fp = knote_fp;
			knote_set_kq(kn, kq);
			kqueue_retain(kq); /* retain a kq ref */
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
			knote_canonicalize_kevent_qos(kn);
			knote_set_qos_index(kn, qos_index_from_qos(kn, kn->kn_qos, FALSE));

			/* before anyone can find it */
			if (kev->flags & EV_DISABLE) {
				/*
				 * do this before anyone can find it,
				 * this can't call knote_disable() because it expects having
				 * the kqlock held
				 */
				kn->kn_status |= KN_DISABLED;
			}

			/* Add the knote for lookup thru the fd table */
			error = kq_add_knote(kq, kn, kev, p, &knoteuse_flags);
			if (error) {
				(void)kqueue_release(kq, KQUEUE_CANT_BE_LAST_REF);
				knote_free(kn);
				if (knote_fp != NULL)
					fp_drop(p, kev->ident, knote_fp, 0);

				if (error == ERESTART) {
					error = 0;
					goto restart;
				}
				goto out;
			}

			/* fp reference count now applies to knote */
			/* rwlock boost is now held */

			/* call filter attach routine */
			result = fops->f_attach(kn, kev);

			/*
			 * Trade knote use count for kq lock.
			 * Cannot be dropped because we held
			 * KN_ATTACHING throughout.
			 */
			knoteuse2kqlock(kq, kn, KNUSE_STEAL_DROP | knoteuse_flags);

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

			/* Mark the thread request overcommit - if appropos */
			knote_set_qos_overcommit(kn);

			/*
			 * If the attach routine indicated that an
			 * event is already fired, activate the knote.
			 */
			if (result)
				knote_activate(kn);

			if (knote_fops(kn)->f_post_attach) {
				error = knote_fops(kn)->f_post_attach(kn, kev);
				if (error) {
					kqunlock(kq);
					goto out;
				}
			}

		} else {
			if ((kev_flags & (EV_ADD | EV_DELETE)) == (EV_ADD | EV_DELETE) &&
					(kq->kq_state & KQ_WORKLOOP)) {
				/*
				 * For workloops, understand EV_ADD|EV_DELETE as a "soft" delete
				 * that doesn't care about ENOENT, so just pretend the deletion
				 * happened.
				 */
			} else {
				error = ENOENT;
			}
			goto out;
		}

	} else {
		/* existing knote: kqueue lock already taken by kq_find_knote_and_kq_lock */

		if ((kn->kn_status & (KN_DROPPING | KN_ATTACHING)) != 0) {
			/*
			 * The knote is not in a stable state, wait for that
			 * transition to complete and then redrive the lookup.
			 */
			knoteusewait(kq, kn);
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
			} else if (knote_fops(kn)->f_drop_and_unlock) {
				/*
				 * The filter has requested to handle EV_DELETE events
				 *
				 * ERESTART means the kevent has to be re-evaluated
				 */
				error = knote_fops(kn)->f_drop_and_unlock(kn, kev);
				if (error == ERESTART) {
					error = 0;
					goto restart;
				}
			} else if (kqlock2knotedrop(kq, kn)) {
				/* standard/default EV_DELETE path */
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
		if (knoteuse_needs_boost(kn, kev)) {
			knoteuse_flags |= KNUSE_BOOST;
		}
		if (kqlock2knoteuse(kq, kn, knoteuse_flags)) {
			/*
			 * Call touch routine to notify filter of changes
			 * in filter values (and to re-determine if any
			 * events are fired).
			 */
			result = knote_fops(kn)->f_touch(kn, kev);

			/* Get the kq lock back (don't defer droppers). */
			if (!knoteuse2kqlock(kq, kn, knoteuse_flags)) {
				kqunlock(kq);
				goto out;
			}

			/* Handle errors during touch routine */
			if (kev->flags & EV_ERROR) {
				error = kev->data;
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

	if (kq->kq_state & KQ_WORKLOOP) {
		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_PROCESS),
		              ((struct kqworkloop *)kq)->kqwl_dynamicid,
		              kn->kn_udata, kn->kn_status | (kn->kn_id << 32),
		              kn->kn_filtid);
	} else if (kq->kq_state & KQ_WORKQ) {
		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_PROCESS),
		              0, kn->kn_udata, kn->kn_status | (kn->kn_id << 32),
		              kn->kn_filtid);
	} else {
		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQ_PROCESS),
		              VM_KERNEL_UNSLIDE_OR_PERM(kq), kn->kn_udata,
		              kn->kn_status | (kn->kn_id << 32), kn->kn_filtid);
	}

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
		int flags = KNUSE_NONE;
		/* deactivate - so new activations indicate a wakeup */
		knote_deactivate(kn);

		/* suppress knotes to avoid returning the same event multiple times in a single call. */
		knote_suppress(kn);

		if (knoteuse_needs_boost(kn, NULL)) {
			flags |= KNUSE_BOOST;
		}
		/* convert lock to a knote use reference */
		if (!kqlock2knoteuse(kq, kn, flags))
			panic("dropping knote found on queue\n");

		/* call out to the filter to process with just a ref */
		result = knote_fops(kn)->f_process(kn, process_data, &kev);
		if (result) flags |= KNUSE_STEAL_DROP;

		/*
		 * convert our reference back to a lock. accept drop
		 * responsibility from others if we've committed to
		 * delivering event data.
		 */
		if (!knoteuse2kqlock(kq, kn, flags)) {
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

	assert(kqwq->kqwq_state & KQ_WORKQ);
	assert(qos_index < KQWQ_NQOS);

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_PROCESS_BEGIN) | DBG_FUNC_START,
	              flags, qos_index);

	kqwq_req_lock(kqwq);

	kqr = kqworkq_get_request(kqwq, qos_index);

	/* manager skips buckets that haven't asked for its help */
	if (flags & KEVENT_FLAG_WORKQ_MANAGER) {

		/* If nothing for manager to do, just return */
		if ((kqr->kqr_state & KQWQ_THMANAGER) == 0) {
			KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_PROCESS_BEGIN) | DBG_FUNC_END,
			                        0, kqr->kqr_state);
			kqwq_req_unlock(kqwq);
			return -1;
		}
		/* bind manager thread from this time on */
		kqworkq_bind_thread_impl(kqwq, qos_index, self, flags);

	} else {
		/* We should already be bound to this kqueue */
		assert(kqr->kqr_state & KQR_BOUND);
		assert(kqr->kqr_thread == self);
		assert(ut->uu_kqueue_bound == (struct kqueue *)kqwq);
		assert(ut->uu_kqueue_qos_index == qos_index);
		assert((ut->uu_kqueue_flags & flags) == ut->uu_kqueue_flags);
	}

	/*
	 * we should have been requested to be here
	 * and nobody else should still be processing
	 */
	assert(kqr->kqr_state & KQR_WAKEUP);
	assert(kqr->kqr_state & KQR_THREQUESTED);
	assert((kqr->kqr_state & KQR_PROCESSING) == 0);

	/* reset wakeup trigger to catch new events after we start processing */
	kqr->kqr_state &= ~KQR_WAKEUP;

	/* convert to processing mode */
	kqr->kqr_state |= KQR_PROCESSING;

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_PROCESS_BEGIN) | DBG_FUNC_END,
	              kqr_thread_id(kqr), kqr->kqr_state);

	kqwq_req_unlock(kqwq);
	return 0;
}

static inline bool
kqworkloop_is_processing_on_current_thread(struct kqworkloop *kqwl)
{
	struct kqueue *kq = &kqwl->kqwl_kqueue;

	kqlock_held(kq);

	if (kq->kq_state & KQ_PROCESSING) {
		/*
		 * KQ_PROCESSING is unset with the kqlock held, and the kqr thread is
		 * never modified while KQ_PROCESSING is set, meaning that peeking at
		 * its value is safe from this context.
		 */
		return kqwl->kqwl_request.kqr_thread == current_thread();
	}
	return false;
}

static void
kqworkloop_acknowledge_events(struct kqworkloop *kqwl, boolean_t clear_ipc_override)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;
	struct knote *kn, *tmp;

	kqlock_held(&kqwl->kqwl_kqueue);

	TAILQ_FOREACH_SAFE(kn, &kqr->kqr_suppressed, kn_tqe, tmp) {
		/*
		 * If a knote that can adjust QoS is disabled because of the automatic
		 * behavior of EV_DISPATCH, the knotes should stay suppressed so that
		 * further overrides keep pushing.
		 */
		if (knote_fops(kn)->f_adjusts_qos && (kn->kn_status & KN_DISABLED) &&
				(kn->kn_status & (KN_STAYACTIVE | KN_DROPPING)) == 0 &&
				(kn->kn_flags & (EV_DISPATCH | EV_DISABLE)) == EV_DISPATCH) {
			/*
			 * When called from unbind, clear the sync ipc override on the knote
			 * for events which are delivered.
			 */
			if (clear_ipc_override) {
				knote_adjust_sync_qos(kn, THREAD_QOS_UNSPECIFIED, FALSE);
			}
			continue;
		}
		knote_unsuppress(kn);
	}
}

static int
kqworkloop_begin_processing(struct kqworkloop *kqwl,
		__assert_only unsigned int flags)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;
	struct kqueue *kq = &kqwl->kqwl_kqueue;

	kqlock_held(kq);

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_PROCESS_BEGIN) | DBG_FUNC_START,
	              kqwl->kqwl_dynamicid, flags, 0);

	kqwl_req_lock(kqwl);

	/* nobody else should still be processing */
	assert((kqr->kqr_state & KQR_PROCESSING) == 0);
	assert((kq->kq_state & KQ_PROCESSING) == 0);

	kqr->kqr_state |= KQR_PROCESSING | KQR_R2K_NOTIF_ARMED;
	kq->kq_state |= KQ_PROCESSING;

	kqwl_req_unlock(kqwl);

	kqworkloop_acknowledge_events(kqwl, FALSE);

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_PROCESS_BEGIN) | DBG_FUNC_END,
	              kqwl->kqwl_dynamicid, flags, 0);

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

	kqlock_held(kq);

	if (kq->kq_state & KQ_WORKQ) {
		return kqworkq_begin_processing((struct kqworkq *)kq, qos_index, flags);
	} else if (kq->kq_state & KQ_WORKLOOP) {
		return kqworkloop_begin_processing((struct kqworkloop*)kq, flags);
	}

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQ_PROCESS_BEGIN) | DBG_FUNC_START,
	              VM_KERNEL_UNSLIDE_OR_PERM(kq), flags);

	assert(qos_index == QOS_INDEX_KQFILE);

	/* wait to become the exclusive processing thread */
	for (;;) {
		if (kq->kq_state & KQ_DRAIN) {
			KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQ_PROCESS_BEGIN) | DBG_FUNC_END,
			              VM_KERNEL_UNSLIDE_OR_PERM(kq), 2);
			return -1;
		}

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
	if (kqueue_queue_empty(kq, qos_index)) {
		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQ_PROCESS_BEGIN) | DBG_FUNC_END,
		              VM_KERNEL_UNSLIDE_OR_PERM(kq), 1);
		return -1;
	}

	/* convert to processing mode */
	kq->kq_state |= KQ_PROCESSING;

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQ_PROCESS_BEGIN) | DBG_FUNC_END,
	              VM_KERNEL_UNSLIDE_OR_PERM(kq));

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
	struct uthread *ut = get_bsdthread_info(self);
	struct knote *kn;
	struct kqrequest *kqr;
	thread_t thread;

	assert(kqwq->kqwq_state & KQ_WORKQ);
	assert(qos_index < KQWQ_NQOS);

	/* Are we really bound to this kqueue? */
	if (ut->uu_kqueue_bound != kq) {
		assert(ut->uu_kqueue_bound == kq);
		return;
	}

	kqr = kqworkq_get_request(kqwq, qos_index);

	kqwq_req_lock(kqwq);

	/* Do we claim to be manager? */
	if (flags & KEVENT_FLAG_WORKQ_MANAGER) {

		/* bail if not bound that way */
		if (ut->uu_kqueue_qos_index != KQWQ_QOS_MANAGER ||
		    (ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ_MANAGER) == 0) {
			assert(ut->uu_kqueue_qos_index == KQWQ_QOS_MANAGER);
			assert(ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ_MANAGER);
			kqwq_req_unlock(kqwq);
			return;
		}

		/* bail if this request wasn't already getting manager help */
		if ((kqr->kqr_state & KQWQ_THMANAGER) == 0 ||
		    (kqr->kqr_state & KQR_PROCESSING) == 0) {
			kqwq_req_unlock(kqwq);
			return;
		}
	} else {
		if (ut->uu_kqueue_qos_index != qos_index ||
		    (ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ_MANAGER)) {
			assert(ut->uu_kqueue_qos_index == qos_index);
			assert((ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ_MANAGER) == 0);
			kqwq_req_unlock(kqwq);
			return;
		}
	}

	assert(kqr->kqr_state & KQR_BOUND);
	thread = kqr->kqr_thread;
	assert(thread == self);

	assert(kqr->kqr_state & KQR_PROCESSING);

	/* If we didn't drain the whole queue, re-mark a wakeup being needed */
	if (!kqueue_queue_empty(kq, qos_index))
		kqr->kqr_state |= KQR_WAKEUP;

	kqwq_req_unlock(kqwq);

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

	/* Indicate that we are done processing this request */
	kqr->kqr_state &= ~KQR_PROCESSING;

	/*
	 * Drop our association with this one request and its
	 * override on us.
	 */
	kqworkq_unbind_thread(kqwq, qos_index, thread, flags);

	/*
	 * request a new thread if we didn't process the whole
	 * queue or real events have happened (not just putting
	 * stay-active events back).
	 */
	if (kqr->kqr_state & KQR_WAKEUP) {
		if (kqueue_queue_empty(kq, qos_index)) {
			kqr->kqr_state &= ~KQR_WAKEUP;
		} else {
			kqworkq_request_thread(kqwq, qos_index);
		}
	}
	kqwq_req_unlock(kqwq);
}

static void
kqworkloop_end_processing(struct kqworkloop *kqwl, int nevents,
		unsigned int flags)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;
	struct kqueue *kq = &kqwl->kqwl_kqueue;

	kqlock_held(kq);

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_PROCESS_END) | DBG_FUNC_START,
			kqwl->kqwl_dynamicid, flags, 0);

	if ((kq->kq_state & KQ_NO_WQ_THREAD) && nevents == 0 &&
			(flags & KEVENT_FLAG_IMMEDIATE) == 0) {
		/*
		 * <rdar://problem/31634014> We may soon block, but have returned no
		 * kevents that need to be kept supressed for overriding purposes.
		 *
		 * It is hence safe to acknowledge events and unsuppress everything, so
		 * that if we block we can observe all events firing.
		 */
		kqworkloop_acknowledge_events(kqwl, TRUE);
	}

	kqwl_req_lock(kqwl);

	assert(kqr->kqr_state & KQR_PROCESSING);
	assert(kq->kq_state & KQ_PROCESSING);

	kq->kq_state &= ~KQ_PROCESSING;
	kqr->kqr_state &= ~KQR_PROCESSING;
	kqworkloop_update_threads_qos(kqwl, KQWL_UTQ_RECOMPUTE_WAKEUP_QOS, 0);

	kqwl_req_unlock(kqwl);

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_PROCESS_END) | DBG_FUNC_END,
			kqwl->kqwl_dynamicid, flags, 0);
}

/*
 * Called with kqueue lock held.
 */
static void
kqueue_end_processing(struct kqueue *kq, kq_index_t qos_index,
		int nevents, unsigned int flags)
{
	struct knote *kn;
	struct kqtailq *suppressq;
	int procwait;

	kqlock_held(kq);

	assert((kq->kq_state & KQ_WORKQ) == 0);

	if (kq->kq_state & KQ_WORKLOOP) {
		return kqworkloop_end_processing((struct kqworkloop *)kq, nevents, flags);
	}

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQ_PROCESS_END),
	              VM_KERNEL_UNSLIDE_OR_PERM(kq), flags);

	assert(qos_index == QOS_INDEX_KQFILE);

	/*
	 * Return suppressed knotes to their original state.
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
 *	kqwq_internal_bind - bind thread to processing workq kqueue
 *
 *	Determines if the provided thread will be responsible for
 *	servicing the particular QoS class index specified in the
 *	parameters. Once the binding is done, any overrides that may
 *	be associated with the cooresponding events can be applied.
 *
 *	This should be called as soon as the thread identity is known,
 *	preferably while still at high priority during creation.
 *
 *  - caller holds a reference on the process (and workq kq)
 *	- the thread MUST call kevent_qos_internal after being bound
 *	  or the bucket of events may never be delivered.  
 *	- Nothing locked
 *    (unless this is a synchronous bind, then the request is locked)
 */
static int
kqworkq_internal_bind(
	struct proc *p,
	kq_index_t qos_index,
	thread_t thread,
	unsigned int flags)
{
	struct kqueue *kq;
	struct kqworkq *kqwq;
	struct kqrequest *kqr;
	struct uthread *ut = get_bsdthread_info(thread);

	/* If no process workq, can't be our thread. */
	kq = p->p_fd->fd_wqkqueue;

	if (kq == NULL)
		return 0;

	assert(kq->kq_state & KQ_WORKQ);
	kqwq = (struct kqworkq *)kq;

	/*
	 * No need to bind the manager thread to any specific
	 * bucket, but still claim the thread.
	 */
	if (qos_index == KQWQ_QOS_MANAGER) {
		assert(ut->uu_kqueue_bound == NULL);
		assert(flags & KEVENT_FLAG_WORKQ_MANAGER);
		ut->uu_kqueue_bound = kq;
		ut->uu_kqueue_qos_index = qos_index;
		ut->uu_kqueue_flags = flags;

		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_BIND),
		              thread_tid(thread), flags, qos_index);

		return 1;
	}

	/*
	 * If this is a synchronous bind callback, the request
	 * lock is already held, so just do the bind.
	 */
	if (flags & KEVENT_FLAG_SYNCHRONOUS_BIND) {
		kqwq_req_held(kqwq);
		/* strip out synchronout bind flag */
		flags &= ~KEVENT_FLAG_SYNCHRONOUS_BIND;
		kqworkq_bind_thread_impl(kqwq, qos_index, thread, flags);
		return 1;
	}

	/*
	 * check the request that corresponds to our qos_index
	 * to see if there is an outstanding request.
	 */
	kqr = kqworkq_get_request(kqwq, qos_index);
	assert(kqr->kqr_qos_index == qos_index);
	kqwq_req_lock(kqwq);

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_BIND),
	              thread_tid(thread), flags, qos_index, kqr->kqr_state);

	if ((kqr->kqr_state & KQR_THREQUESTED) &&
	    (kqr->kqr_state & KQR_PROCESSING) == 0) {

		if ((kqr->kqr_state & KQR_BOUND) &&
		    thread == kqr->kqr_thread) {
			/* duplicate bind - claim the thread */
			assert(ut->uu_kqueue_bound == kq);
			assert(ut->uu_kqueue_qos_index == qos_index);
			kqwq_req_unlock(kqwq);
			return 1;
		}
		if ((kqr->kqr_state & (KQR_BOUND | KQWQ_THMANAGER)) == 0) {
			/* ours to bind to */
			kqworkq_bind_thread_impl(kqwq, qos_index, thread, flags);
			kqwq_req_unlock(kqwq);
			return 1;
		}
	}
	kqwq_req_unlock(kqwq);
	return 0;
}

static void
kqworkloop_bind_thread_impl(struct kqworkloop *kqwl,
                            thread_t thread,
                            __assert_only unsigned int flags)
{
	assert(flags & KEVENT_FLAG_WORKLOOP);

	/* the request object must be locked */
	kqwl_req_held(kqwl);

	struct kqrequest *kqr = &kqwl->kqwl_request;
	struct uthread *ut = get_bsdthread_info(thread);
	boolean_t ipc_override_is_sync;
	kq_index_t qos_index = kqworkloop_combined_qos(kqwl, &ipc_override_is_sync);

	/* nobody else bound so finally bind (as a workloop) */
	assert(kqr->kqr_state & KQR_THREQUESTED);
	assert((kqr->kqr_state & (KQR_BOUND | KQR_PROCESSING)) == 0);
	assert(thread != kqwl->kqwl_owner);

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_BIND),
	              kqwl->kqwl_dynamicid, (uintptr_t)thread_tid(thread),
	              qos_index,
	              (uintptr_t)(((uintptr_t)kqr->kqr_override_index << 16) |
	              (((uintptr_t)kqr->kqr_state) << 8) |
	              ((uintptr_t)ipc_override_is_sync)));

	kqr->kqr_state |= KQR_BOUND | KQR_R2K_NOTIF_ARMED;
	kqr->kqr_thread = thread;

	/* bind the workloop to the uthread */
	ut->uu_kqueue_bound = (struct kqueue *)kqwl;
	ut->uu_kqueue_flags = flags;
	ut->uu_kqueue_qos_index = qos_index;
	assert(ut->uu_kqueue_override_is_sync == 0);
	ut->uu_kqueue_override_is_sync = ipc_override_is_sync;
	if (qos_index) {
		thread_add_ipc_override(thread, qos_index);
	}
	if (ipc_override_is_sync) {
		thread_add_sync_ipc_override(thread);
	}
}

/*
 *  workloop_fulfill_threadreq - bind thread to processing workloop
 *
 * The provided thread will be responsible for delivering events
 * associated with the given kqrequest.  Bind it and get ready for
 * the thread to eventually arrive.
 *
 * If WORKLOOP_FULFILL_THREADREQ_SYNC is specified, the callback
 * within the context of the pthread_functions->workq_threadreq
 * callout.  In this case, the request structure is already locked.
 */
int
workloop_fulfill_threadreq(struct proc *p,
                           workq_threadreq_t req,
                           thread_t thread,
                           int flags)
{
	int sync = (flags & WORKLOOP_FULFILL_THREADREQ_SYNC);
	int cancel = (flags & WORKLOOP_FULFILL_THREADREQ_CANCEL);
	struct kqrequest *kqr;
	struct kqworkloop *kqwl;

	kqwl = (struct kqworkloop *)((uintptr_t)req -
	                             offsetof(struct kqworkloop, kqwl_request) -
	                             offsetof(struct kqrequest, kqr_req));
	kqr = &kqwl->kqwl_request;

	/* validate we're looking at something valid */
	if (kqwl->kqwl_p != p ||
	    (kqwl->kqwl_state & KQ_WORKLOOP) == 0) {
		assert(kqwl->kqwl_p == p);
		assert(kqwl->kqwl_state & KQ_WORKLOOP);
		return EINVAL;
	}
	
	if (!sync)
		kqwl_req_lock(kqwl);

	/* Should be a pending request */
	if ((kqr->kqr_state & KQR_BOUND) ||
	    (kqr->kqr_state & KQR_THREQUESTED) == 0) {

		assert((kqr->kqr_state & KQR_BOUND) == 0);
		assert(kqr->kqr_state & KQR_THREQUESTED);
		if (!sync)
			kqwl_req_unlock(kqwl);
		return EINPROGRESS;
	}

	assert((kqr->kqr_state & KQR_DRAIN) == 0);

	/*
	 * Is it a cancel indication from pthread.
	 * If so, we must be exiting/exec'ing. Forget
	 * our pending request.
	 */
	if (cancel) {
		kqr->kqr_state &= ~KQR_THREQUESTED;
		kqr->kqr_state |= KQR_DRAIN;
	} else {
		/* do the actual bind? */
		kqworkloop_bind_thread_impl(kqwl, thread, KEVENT_FLAG_WORKLOOP);
	}

	if (!sync)
		kqwl_req_unlock(kqwl);

	if (cancel)
		kqueue_release_last(p, &kqwl->kqwl_kqueue); /* may dealloc kq */

	return 0;
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
	kq_index_t qos_index;

	assert(flags & KEVENT_FLAG_WORKQ);

	if (thread == THREAD_NULL || (flags & KEVENT_FLAG_WORKQ) == 0) {
		return EINVAL;
	}

	/* get the qos index we're going to service */
	qos_index = qos_index_for_servicer(qos_class, thread, flags);

	if (kqworkq_internal_bind(p, qos_index, thread, flags))
		return 0;

	return EINPROGRESS;
}


static void
kqworkloop_internal_unbind(
	struct proc *p,
	thread_t thread,
	unsigned int flags)
{
	struct kqueue *kq;
	struct kqworkloop *kqwl;
	struct uthread *ut = get_bsdthread_info(thread);

	assert(ut->uu_kqueue_bound != NULL);
	kq = ut->uu_kqueue_bound;
	assert(kq->kq_state & KQ_WORKLOOP);
	kqwl = (struct kqworkloop *)kq;

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_UNBIND),
	              kqwl->kqwl_dynamicid, (uintptr_t)thread_tid(thread),
	              flags, 0);

	if (!(kq->kq_state & KQ_NO_WQ_THREAD)) {
		assert(is_workqueue_thread(thread));

		kqlock(kq);
		kqworkloop_unbind_thread(kqwl, thread, flags);
		kqunlock(kq);

		/* If last reference, dealloc the workloop kq */
		kqueue_release_last(p, kq);
	} else {
		assert(!is_workqueue_thread(thread));
		kevent_servicer_detach_thread(p, kqwl->kqwl_dynamicid, thread, flags, kq);
	}
}

static void
kqworkq_internal_unbind(
	struct proc *p,
	kq_index_t qos_index,
	thread_t thread,
	unsigned int flags)
{
	struct kqueue *kq;
	struct kqworkq *kqwq;
	struct uthread *ut;
	kq_index_t end_index;

	assert(thread == current_thread());
	ut = get_bsdthread_info(thread);

	kq = p->p_fd->fd_wqkqueue;
	assert(kq->kq_state & KQ_WORKQ);
	assert(ut->uu_kqueue_bound == kq);

	kqwq = (struct kqworkq *)kq;

	/* end servicing any requests we might own */
	end_index = (qos_index == KQWQ_QOS_MANAGER) ? 
	    0 : qos_index;
	kqlock(kq);

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_UNBIND),
	              (uintptr_t)thread_tid(thread), flags, qos_index);

	do {
		kqworkq_end_processing(kqwq, qos_index, flags);
	} while (qos_index-- > end_index);

	ut->uu_kqueue_bound = NULL;
	ut->uu_kqueue_qos_index = 0;
	ut->uu_kqueue_flags = 0;

	kqunlock(kq);
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
#pragma unused(qos_class)

	struct uthread *ut;
	struct kqueue *kq;
	unsigned int bound_flags;
	bool check_flags;

	ut = get_bsdthread_info(thread);
	if (ut->uu_kqueue_bound == NULL) {
		/* early out if we are already unbound */
		assert(ut->uu_kqueue_flags == 0);
		assert(ut->uu_kqueue_qos_index == 0);
		assert(ut->uu_kqueue_override_is_sync == 0);
		return EALREADY;
	}

	assert(flags & (KEVENT_FLAG_WORKQ | KEVENT_FLAG_WORKLOOP));
	assert(thread == current_thread());

	check_flags = flags & KEVENT_FLAG_UNBIND_CHECK_FLAGS;

	/* Get the kqueue we started with */
	kq = ut->uu_kqueue_bound;
	assert(kq != NULL);
	assert(kq->kq_state & (KQ_WORKQ | KQ_WORKLOOP));

	/* get flags and QoS parameters we started with */
	bound_flags = ut->uu_kqueue_flags;

	/* Unbind from the class of workq */
	if (kq->kq_state & KQ_WORKQ) {
		if (check_flags && !(flags & KEVENT_FLAG_WORKQ)) {
			return EINVAL;
		}

		kqworkq_internal_unbind(p, ut->uu_kqueue_qos_index, thread, bound_flags);
	} else {
		if (check_flags && !(flags & KEVENT_FLAG_WORKLOOP)) {
			return EINVAL;
		}

		kqworkloop_internal_unbind(p, thread, bound_flags);
	}

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
    int *countp,
    struct proc *p)
{
	unsigned int flags = process_data ? process_data->fp_flags : 0;
	struct uthread *ut = get_bsdthread_info(current_thread());
	kq_index_t start_index, end_index, i;
	struct knote *kn;
	int nevents = 0;
	int error = 0;

	/*
	 * Based on the mode of the kqueue and the bound QoS of the servicer,
	 * determine the range of thread requests that need checking
	 */
	if (kq->kq_state & KQ_WORKQ) {
		if (flags & KEVENT_FLAG_WORKQ_MANAGER) {
			start_index = KQWQ_QOS_MANAGER;
		} else if (ut->uu_kqueue_bound != kq) {
			return EJUSTRETURN;
		} else {
			start_index = ut->uu_kqueue_qos_index;
		}

		/* manager services every request in a workq kqueue */
		assert(start_index > 0 && start_index <= KQWQ_QOS_MANAGER);
		end_index = (start_index == KQWQ_QOS_MANAGER) ? 0 : start_index;

	} else if (kq->kq_state & KQ_WORKLOOP) {
		if (ut->uu_kqueue_bound != kq)
			return EJUSTRETURN;

		/*
		 * Single request servicing
		 * we want to deliver all events, regardless of the QOS
		 */
		start_index = end_index = THREAD_QOS_UNSPECIFIED;
	} else {
		start_index = end_index = QOS_INDEX_KQFILE;
	}
	
	i = start_index;

	do {
		if (kqueue_begin_processing(kq, i, flags) == -1) {
			*countp = 0;
			/* Nothing to process */
			continue;
		}

		/*
		 * loop through the enqueued knotes associated with this request,
		 * processing each one. Each request may have several queues
		 * of knotes to process (depending on the type of kqueue) so we
		 * have to loop through all the queues as long as we have additional
		 * space.
		 */
		error = 0;

		struct kqtailq *base_queue = kqueue_get_base_queue(kq, i);
		struct kqtailq *queue = kqueue_get_high_queue(kq, i);
		do {
			while (error == 0 && (kn = TAILQ_FIRST(queue)) != NULL) {
				error = knote_process(kn, callback, callback_data, process_data, p);
				if (error == EJUSTRETURN) {
					error = 0;
				} else {
					nevents++;
				}
				/* error is EWOULDBLOCK when the out event array is full */
			}
		} while (error == 0 && queue-- > base_queue);

		if ((kq->kq_state & KQ_WORKQ) == 0) {
			kqueue_end_processing(kq, i, nevents, flags);
		}

		if (error == EWOULDBLOCK) {
			/* break out if no more space for additional events */
			error = 0;
			break;
		}
	} while (i-- > end_index);

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
		                       process_data, &count, current_proc());
		if (error == 0 && count == 0) {
			if (kq->kq_state & KQ_DRAIN) {
				kqunlock(kq);
				goto drain;
			}

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
	drain:
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
		                       process_data, &count, p);
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
				cont = kqueue_scan_continue;
			}
		}

		if (kq->kq_state & KQ_DRAIN) {
			kqunlock(kq);
			return EBADF;
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

			assert(!knoteuse_needs_boost(kn, NULL));

			/* If didn't vanish while suppressed - peek at it */
			if (kqlock2knoteuse(kq, kn, KNUSE_NONE)) {
				peek = knote_fops(kn)->f_peek(kn);

				/* if it dropped while getting lock - move on */
				if (!knoteuse2kqlock(kq, kn, KNUSE_NONE))
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
	kqueue_end_processing(kq, QOS_INDEX_KQFILE, retnum, 0);
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
kqueue_kqfilter(__unused struct fileproc *fp, struct knote *kn,
		__unused struct kevent_internal_s *kev, __unused vfs_context_t ctx)
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

	assert(kqr->kqr_state & KQR_WAKEUP);

	/* 
	 * If we have already requested a thread, and it hasn't
	 * started processing yet, there's no use hammering away
	 * on the pthread kext.
	 */
	if (kqr->kqr_state & KQR_THREQUESTED)
		return;

	assert((kqr->kqr_state & KQR_BOUND) == 0);

	/* request additional workq threads if appropriate */
	if (pthread_functions != NULL &&
	    pthread_functions->workq_reqthreads != NULL) {
		unsigned int flags = KEVENT_FLAG_WORKQ;
		unsigned long priority;
		thread_t wqthread;

		/* Compute the appropriate pthread priority */
		priority = qos_from_qos_index(qos_index);

#if 0
		/* JMM - for now remain compatible with old invocations */
		/* set the over-commit flag on the request if needed */
		if (kqr->kqr_state & KQR_THOVERCOMMIT)
			priority |= _PTHREAD_PRIORITY_OVERCOMMIT_FLAG;
#endif /* 0 */

		/* Compute a priority based on qos_index. */
		struct workq_reqthreads_req_s request = {
			.priority = priority,
			.count = 1
		};

		/* mark that we are making a request */
		kqr->kqr_state |= KQR_THREQUESTED;
		if (qos_index == KQWQ_QOS_MANAGER)
			kqr->kqr_state |= KQWQ_THMANAGER;

		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWQ_THREQUEST),
		              0, qos_index,
		              (((uintptr_t)kqr->kqr_override_index << 8) |
		               (uintptr_t)kqr->kqr_state));
		wqthread = (*pthread_functions->workq_reqthreads)(kqwq->kqwq_p, 1, &request);

		/* We've been switched to the emergency/manager thread */
		if (wqthread == (thread_t)-1) {
			assert(qos_index != KQWQ_QOS_MANAGER);
			kqr->kqr_state |= KQWQ_THMANAGER;
			return;
		}

		/*
		 * bind the returned thread identity
		 * This goes away when we switch to synchronous callback
		 * binding from the pthread kext.
		 */
		if (wqthread != NULL) {
			kqworkq_bind_thread_impl(kqwq, qos_index, wqthread, flags);
		}
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
	kq_index_t qos_index)
{
	struct kqrequest *kqr;

	/* convert to thread qos value */
	assert(qos_index < KQWQ_NQOS);
	
	kqwq_req_lock(kqwq);
	kqr = kqworkq_get_request(kqwq, qos_index);

	if ((kqr->kqr_state & KQR_WAKEUP) == 0) {
		/* Indicate that we needed help from this request */
		kqr->kqr_state |= KQR_WAKEUP;

		/* Go assure a thread request has been made */
		kqworkq_request_thread(kqwq, qos_index);
	}
	kqwq_req_unlock(kqwq);
}

static void
kqworkloop_threadreq_impl(struct kqworkloop *kqwl, kq_index_t qos_index)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;
	unsigned long pri = pthread_priority_for_kqrequest(kqr, qos_index);
	int op, ret;

	assert((kqr->kqr_state & (KQR_THREQUESTED | KQR_BOUND)) == KQR_THREQUESTED);

	/*
	 * New-style thread request supported. Provide
	 * the pthread kext a pointer to a workq_threadreq_s
	 * structure for its use until a corresponding
	 * workloop_fulfill_threqreq callback.
	 */
	if (current_proc() == kqwl->kqwl_kqueue.kq_p) {
		op = WORKQ_THREADREQ_WORKLOOP_NO_THREAD_CALL;
	} else {
		op = WORKQ_THREADREQ_WORKLOOP;
	}
again:
	ret = (*pthread_functions->workq_threadreq)(kqwl->kqwl_p, &kqr->kqr_req,
			WORKQ_THREADREQ_WORKLOOP, pri, 0);
	switch (ret) {
	case ENOTSUP:
		assert(op == WORKQ_THREADREQ_WORKLOOP_NO_THREAD_CALL);
		op = WORKQ_THREADREQ_WORKLOOP;
		goto again;

	case ECANCELED:
	case EINVAL:
		/*
		 * Process is shutting down or exec'ing.
		 * All the kqueues are going to be cleaned up
		 * soon. Forget we even asked for a thread -
		 * and make sure we don't ask for more.
		 */
		kqueue_release((struct kqueue *)kqwl, KQUEUE_CANT_BE_LAST_REF);
		kqr->kqr_state &= ~KQR_THREQUESTED;
		kqr->kqr_state |= KQR_DRAIN;
		break;

	case EAGAIN:
		assert(op == WORKQ_THREADREQ_WORKLOOP_NO_THREAD_CALL);
		act_set_astkevent(current_thread(), AST_KEVENT_REDRIVE_THREADREQ);
		break;

	default:
		assert(ret == 0);
	}
}

static void
kqworkloop_threadreq_modify(struct kqworkloop *kqwl, kq_index_t qos_index)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;
	unsigned long pri = pthread_priority_for_kqrequest(kqr, qos_index);
	int ret, op = WORKQ_THREADREQ_CHANGE_PRI_NO_THREAD_CALL;

	assert((kqr->kqr_state & (KQR_THREQUESTED | KQR_BOUND)) == KQR_THREQUESTED);

	if (current_proc() == kqwl->kqwl_kqueue.kq_p) {
		op = WORKQ_THREADREQ_CHANGE_PRI_NO_THREAD_CALL;
	} else {
		op = WORKQ_THREADREQ_CHANGE_PRI;
	}
again:
	ret = (*pthread_functions->workq_threadreq_modify)(kqwl->kqwl_p,
			&kqr->kqr_req, op, pri, 0);
	switch (ret) {
	case ENOTSUP:
		assert(op == WORKQ_THREADREQ_CHANGE_PRI_NO_THREAD_CALL);
		op = WORKQ_THREADREQ_CHANGE_PRI;
		goto again;

	case EAGAIN:
		assert(op == WORKQ_THREADREQ_WORKLOOP_NO_THREAD_CALL);
		act_set_astkevent(current_thread(), AST_KEVENT_REDRIVE_THREADREQ);
		break;

	case ECANCELED:
	case EINVAL:
	case 0:
		break;

	default:
		assert(ret == 0);
	}
}

/*
 * Interact with the pthread kext to request a servicing thread.
 * This will request a single thread at the highest QoS level
 * for which there is work (whether that was the requested QoS
 * for an event or an override applied to a lower-QoS request).
 *
 * - Caller holds the workloop request lock
 *
 * - May be called with the kqueue's wait queue set locked,
 *   so cannot do anything that could recurse on that.
 */
static void
kqworkloop_request_thread(struct kqworkloop *kqwl, kq_index_t qos_index)
{
	struct kqrequest *kqr;

	assert(kqwl->kqwl_state & KQ_WORKLOOP);

	kqr = &kqwl->kqwl_request;

	assert(kqwl->kqwl_owner == THREAD_NULL);
	assert((kqr->kqr_state & KQR_BOUND) == 0);
	assert((kqr->kqr_state & KQR_THREQUESTED) == 0);
	assert(!(kqwl->kqwl_kqueue.kq_state & KQ_NO_WQ_THREAD));

	/* If we're draining thread requests, just bail */
	if (kqr->kqr_state & KQR_DRAIN)
		return;

	if (pthread_functions != NULL &&
			pthread_functions->workq_threadreq != NULL) {
		/*
		 * set request state flags, etc... before calling pthread
		 * This assures they are set before a possible synchronous
		 * callback to workloop_fulfill_threadreq().
		 */
		kqr->kqr_state |= KQR_THREQUESTED;

		/* Add a thread request reference on the kqueue. */
		kqueue_retain((struct kqueue *)kqwl);

		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_THREQUEST),
		              kqwl->kqwl_dynamicid,
		              0, qos_index, kqr->kqr_state);
		kqworkloop_threadreq_impl(kqwl, qos_index);
	} else {
		panic("kqworkloop_request_thread");
		return;
	}
}

static void
kqworkloop_update_sync_override_state(struct kqworkloop *kqwl, boolean_t sync_ipc_override)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;
	kqwl_req_lock(kqwl);
	kqr->kqr_has_sync_override = sync_ipc_override;
	kqwl_req_unlock(kqwl);

}

static inline kq_index_t
kqworkloop_combined_qos(struct kqworkloop *kqwl, boolean_t *ipc_override_is_sync)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;
	kq_index_t override;

	*ipc_override_is_sync = FALSE;
	override = MAX(MAX(kqr->kqr_qos_index, kqr->kqr_override_index),
					kqr->kqr_dsync_waiters_qos);

	if (kqr->kqr_sync_suppress_count > 0 || kqr->kqr_has_sync_override) {
		*ipc_override_is_sync = TRUE;
		override = THREAD_QOS_USER_INTERACTIVE;
	}
	return override;
}

static inline void
kqworkloop_request_fire_r2k_notification(struct kqworkloop *kqwl)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;

	kqwl_req_held(kqwl);

	if (kqr->kqr_state & KQR_R2K_NOTIF_ARMED) {
		assert(kqr->kqr_state & KQR_BOUND);
		assert(kqr->kqr_thread);

		kqr->kqr_state &= ~KQR_R2K_NOTIF_ARMED;
		act_set_astkevent(kqr->kqr_thread, AST_KEVENT_RETURN_TO_KERNEL);
	}
}

static void
kqworkloop_update_threads_qos(struct kqworkloop *kqwl, int op, kq_index_t qos)
{
	const uint8_t KQWL_STAYACTIVE_FIRED_BIT = (1 << 0);

	struct kqrequest *kqr = &kqwl->kqwl_request;
	boolean_t old_ipc_override_is_sync = FALSE;
	kq_index_t old_qos = kqworkloop_combined_qos(kqwl, &old_ipc_override_is_sync);
	struct kqueue *kq = &kqwl->kqwl_kqueue;
	bool static_thread = (kq->kq_state & KQ_NO_WQ_THREAD);
	kq_index_t i;

	/* must hold the kqr lock */
	kqwl_req_held(kqwl);

	switch (op) {
	case KQWL_UTQ_UPDATE_WAKEUP_QOS:
		if (qos == KQWL_BUCKET_STAYACTIVE) {
			/*
			 * the KQWL_BUCKET_STAYACTIVE is not a QoS bucket, we only remember
			 * a high watermark (kqr_stayactive_qos) of any stay active knote
			 * that was ever registered with this workloop.
			 *
			 * When waitq_set__CALLING_PREPOST_HOOK__() wakes up any stay active
			 * knote, we use this high-watermark as a wakeup-index, and also set
			 * the magic KQWL_BUCKET_STAYACTIVE bit to make sure we remember
			 * there is at least one stay active knote fired until the next full
			 * processing of this bucket.
			 */
			kqr->kqr_wakeup_indexes |= KQWL_STAYACTIVE_FIRED_BIT;
			qos = kqr->kqr_stayactive_qos;
			assert(qos);
			assert(!static_thread);
		}
		if (kqr->kqr_wakeup_indexes & (1 << qos)) {
			assert(kqr->kqr_state & KQR_WAKEUP);
			break;
		}

		kqr->kqr_wakeup_indexes |= (1 << qos);
		kqr->kqr_state |= KQR_WAKEUP;
		kqworkloop_request_fire_r2k_notification(kqwl);
		goto recompute_async;

	case KQWL_UTQ_UPDATE_STAYACTIVE_QOS:
		assert(qos);
		if (kqr->kqr_stayactive_qos < qos) {
			kqr->kqr_stayactive_qos = qos;
			if (kqr->kqr_wakeup_indexes & KQWL_STAYACTIVE_FIRED_BIT) {
				assert(kqr->kqr_state & KQR_WAKEUP);
				kqr->kqr_wakeup_indexes |= (1 << qos);
				goto recompute_async;
			}
		}
		break;

	case KQWL_UTQ_RECOMPUTE_WAKEUP_QOS:
		kqlock_held(kq); // to look at kq_queues
		kqr->kqr_has_sync_override = FALSE;
		i = KQWL_BUCKET_STAYACTIVE;
		if (TAILQ_EMPTY(&kqr->kqr_suppressed)) {
			kqr->kqr_override_index = THREAD_QOS_UNSPECIFIED;
		}
		if (!TAILQ_EMPTY(&kq->kq_queue[i]) &&
				(kqr->kqr_wakeup_indexes & KQWL_STAYACTIVE_FIRED_BIT)) {
			/*
			 * If the KQWL_STAYACTIVE_FIRED_BIT is set, it means a stay active
			 * knote may have fired, so we need to merge in kqr_stayactive_qos.
			 *
			 * Unlike other buckets, this one is never empty but could be idle.
			 */
			kqr->kqr_wakeup_indexes &= KQWL_STAYACTIVE_FIRED_BIT;
			kqr->kqr_wakeup_indexes |= (1 << kqr->kqr_stayactive_qos);
		} else {
			kqr->kqr_wakeup_indexes = 0;
		}
		for (i = THREAD_QOS_UNSPECIFIED + 1; i < KQWL_BUCKET_STAYACTIVE; i++) {
			if (!TAILQ_EMPTY(&kq->kq_queue[i])) {
				kqr->kqr_wakeup_indexes |= (1 << i);
				struct knote *kn = TAILQ_FIRST(&kqwl->kqwl_kqueue.kq_queue[i]);
				if (i == THREAD_QOS_USER_INTERACTIVE &&
				    kn->kn_qos_override_is_sync) {
					kqr->kqr_has_sync_override = TRUE;
				}
			}
		}
		if (kqr->kqr_wakeup_indexes) {
			kqr->kqr_state |= KQR_WAKEUP;
			kqworkloop_request_fire_r2k_notification(kqwl);
		} else {
			kqr->kqr_state &= ~KQR_WAKEUP;
		}
		assert(qos == THREAD_QOS_UNSPECIFIED);
		goto recompute_async;

	case KQWL_UTQ_RESET_WAKEUP_OVERRIDE:
		kqr->kqr_override_index = THREAD_QOS_UNSPECIFIED;
		assert(qos == THREAD_QOS_UNSPECIFIED);
		goto recompute_async;

	case KQWL_UTQ_UPDATE_WAKEUP_OVERRIDE:
	recompute_async:
		/*
		 * When modifying the wakeup QoS or the async override QoS, we always
		 * need to maintain our invariant that kqr_override_index is at least as
		 * large as the highest QoS for which an event is fired.
		 *
		 * However this override index can be larger when there is an overriden
		 * suppressed knote pushing on the kqueue.
		 */
		if (kqr->kqr_wakeup_indexes > (1 << qos)) {
			qos = fls(kqr->kqr_wakeup_indexes) - 1; /* fls is 1-based */
		}
		if (kqr->kqr_override_index < qos) {
			kqr->kqr_override_index = qos;
		}
		break;

	case KQWL_UTQ_REDRIVE_EVENTS:
		break;

	case KQWL_UTQ_SET_ASYNC_QOS:
		filt_wlheld(kqwl);
		kqr->kqr_qos_index = qos;
		break;

	case KQWL_UTQ_SET_SYNC_WAITERS_QOS:
		filt_wlheld(kqwl);
		kqr->kqr_dsync_waiters_qos = qos;
		break;

	default:
		panic("unknown kqwl thread qos update operation: %d", op);
	}

	boolean_t new_ipc_override_is_sync = FALSE;
	kq_index_t new_qos = kqworkloop_combined_qos(kqwl, &new_ipc_override_is_sync);
	thread_t kqwl_owner = kqwl->kqwl_owner;
	thread_t servicer = kqr->kqr_thread;
	__assert_only int ret;

	/*
	 * Apply the diffs to the owner if applicable
	 */
	if (filt_wlowner_is_valid(kqwl_owner)) {
#if 0
		/* JMM - need new trace hooks for owner overrides */
		KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_THADJUST),
				kqwl->kqwl_dynamicid,
				(kqr->kqr_state & KQR_BOUND) ? thread_tid(kqwl_owner) : 0,
				(kqr->kqr_qos_index << 8) | new_qos,
				(kqr->kqr_override_index << 8) | kqr->kqr_state);
#endif
		if (new_qos == kqr->kqr_dsync_owner_qos) {
			// nothing to do
		} else if (kqr->kqr_dsync_owner_qos == THREAD_QOS_UNSPECIFIED) {
			thread_add_ipc_override(kqwl_owner, new_qos);
		} else if (new_qos == THREAD_QOS_UNSPECIFIED) {
			thread_drop_ipc_override(kqwl_owner);
		} else /* kqr->kqr_dsync_owner_qos != new_qos */ {
			thread_update_ipc_override(kqwl_owner, new_qos);
		}
		kqr->kqr_dsync_owner_qos = new_qos;

		if (new_ipc_override_is_sync &&
			!kqr->kqr_owner_override_is_sync) {
			thread_add_sync_ipc_override(kqwl_owner);
		} else if (!new_ipc_override_is_sync &&
			kqr->kqr_owner_override_is_sync) {
			thread_drop_sync_ipc_override(kqwl_owner);
		}
		kqr->kqr_owner_override_is_sync = new_ipc_override_is_sync;
	}

	/*
	 * apply the diffs to the servicer
	 */
	if (static_thread) {
		/*
		 * Statically bound thread
		 *
		 * These threads don't participates in QoS overrides today, just wakeup
		 * the thread blocked on this kqueue if a new event arrived.
		 */

		switch (op) {
		case KQWL_UTQ_UPDATE_WAKEUP_QOS:
		case KQWL_UTQ_UPDATE_STAYACTIVE_QOS:
		case KQWL_UTQ_RECOMPUTE_WAKEUP_QOS:
			break;

		case KQWL_UTQ_RESET_WAKEUP_OVERRIDE:
		case KQWL_UTQ_UPDATE_WAKEUP_OVERRIDE:
		case KQWL_UTQ_REDRIVE_EVENTS:
		case KQWL_UTQ_SET_ASYNC_QOS:
		case KQWL_UTQ_SET_SYNC_WAITERS_QOS:
			panic("should never be called");
			break;
		}

		kqlock_held(kq);

		if ((kqr->kqr_state & KQR_BOUND) && (kqr->kqr_state & KQR_WAKEUP)) {
			assert(servicer && !is_workqueue_thread(servicer));
			if (kq->kq_state & (KQ_SLEEP | KQ_SEL)) {
				kq->kq_state &= ~(KQ_SLEEP | KQ_SEL);
				waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,	KQ_EVENT,
						THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
			}
		}
	} else if ((kqr->kqr_state & KQR_THREQUESTED) == 0) {
		/*
		 * No servicer, nor thread-request
		 *
		 * Make a new thread request, unless there is an owner (or the workloop
		 * is suspended in userland) or if there is no asynchronous work in the
		 * first place.
		 */

		if (kqwl_owner == THREAD_NULL && (kqr->kqr_state & KQR_WAKEUP)) {
			kqworkloop_request_thread(kqwl, new_qos);
		}
	} else if ((kqr->kqr_state & KQR_BOUND) == 0 &&
			(kqwl_owner || (kqr->kqr_state & KQR_WAKEUP) == 0)) {
		/*
		 * No servicer, thread request in flight we want to cancel
		 *
		 * We just got rid of the last knote of the kqueue or noticed an owner
		 * with a thread request still in flight, take it back.
		 */
		ret = (*pthread_functions->workq_threadreq_modify)(kqwl->kqwl_p,
				&kqr->kqr_req, WORKQ_THREADREQ_CANCEL, 0, 0);
		if (ret == 0) {
			kqr->kqr_state &= ~KQR_THREQUESTED;
			kqueue_release(kq, KQUEUE_CANT_BE_LAST_REF);
		}
	} else {
		boolean_t qos_changed = FALSE;

		/*
		 * Servicer or request is in flight
		 *
		 * Just apply the diff to the servicer or the thread request
		 */
		if (kqr->kqr_state & KQR_BOUND) {
			servicer = kqr->kqr_thread;
			struct uthread *ut = get_bsdthread_info(servicer);
			if (ut->uu_kqueue_qos_index != new_qos) {
				if (ut->uu_kqueue_qos_index == THREAD_QOS_UNSPECIFIED) {
					thread_add_ipc_override(servicer, new_qos);
				} else if (new_qos == THREAD_QOS_UNSPECIFIED) {
					thread_drop_ipc_override(servicer);
				} else /* ut->uu_kqueue_qos_index != new_qos */ {
					thread_update_ipc_override(servicer, new_qos);
				}
				ut->uu_kqueue_qos_index = new_qos;
				qos_changed = TRUE;
			}

			if (new_ipc_override_is_sync != ut->uu_kqueue_override_is_sync) {
				if (new_ipc_override_is_sync &&
				    !ut->uu_kqueue_override_is_sync) {
					thread_add_sync_ipc_override(servicer);
				} else if (!new_ipc_override_is_sync &&
					ut->uu_kqueue_override_is_sync) {
					thread_drop_sync_ipc_override(servicer);
				}
				ut->uu_kqueue_override_is_sync = new_ipc_override_is_sync;
				qos_changed = TRUE;
			}
		} else if (old_qos != new_qos) {
			assert(new_qos);
			kqworkloop_threadreq_modify(kqwl, new_qos);
			qos_changed = TRUE;
		}
		if (qos_changed) {
			servicer = kqr->kqr_thread;
			KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KQWL_THADJUST),
				kqwl->kqwl_dynamicid,
				(kqr->kqr_state & KQR_BOUND) ? thread_tid(servicer) : 0,
				(kqr->kqr_qos_index << 16) | (new_qos << 8) | new_ipc_override_is_sync,
				(kqr->kqr_override_index << 8) | kqr->kqr_state);
		}
	}
}

static void
kqworkloop_request_help(struct kqworkloop *kqwl, kq_index_t qos_index)
{
	/* convert to thread qos value */
	assert(qos_index < KQWL_NBUCKETS);

	kqwl_req_lock(kqwl);
	kqworkloop_update_threads_qos(kqwl, KQWL_UTQ_UPDATE_WAKEUP_QOS, qos_index);
	kqwl_req_unlock(kqwl);
}

/*
 * These arrays described the low and high qindexes for a given qos_index.
 * The values come from the chart in <sys/eventvar.h> (must stay in sync).
 */
static kq_index_t _kqwq_base_index[KQWQ_NQOS] = {0, 0, 6, 11, 15, 18, 20, 21};
static kq_index_t _kqwq_high_index[KQWQ_NQOS] = {0, 5, 10, 14, 17, 19, 20, 21};

static struct kqtailq *
kqueue_get_base_queue(struct kqueue *kq, kq_index_t qos_index)
{
	if (kq->kq_state & KQ_WORKQ) {
		assert(qos_index < KQWQ_NQOS);
		return &kq->kq_queue[_kqwq_base_index[qos_index]];
	} else if (kq->kq_state & KQ_WORKLOOP) {
		assert(qos_index < KQWL_NBUCKETS);
		return &kq->kq_queue[qos_index];
	} else {
		assert(qos_index == QOS_INDEX_KQFILE);
		return &kq->kq_queue[QOS_INDEX_KQFILE];
	}
}

static struct kqtailq *
kqueue_get_high_queue(struct kqueue *kq, kq_index_t qos_index)
{
	if (kq->kq_state & KQ_WORKQ) {
		assert(qos_index < KQWQ_NQOS);
		return &kq->kq_queue[_kqwq_high_index[qos_index]];
	} else if (kq->kq_state & KQ_WORKLOOP) {
		assert(qos_index < KQWL_NBUCKETS);
		return &kq->kq_queue[KQWL_BUCKET_STAYACTIVE];
	} else {
		assert(qos_index == QOS_INDEX_KQFILE);
		return &kq->kq_queue[QOS_INDEX_KQFILE];
	}
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
    struct kqtailq *res;
	struct kqrequest *kqr;

	if (kq->kq_state & KQ_WORKQ) {
		struct kqworkq *kqwq = (struct kqworkq *)kq;

		kqr = kqworkq_get_request(kqwq, qos_index);
		res = &kqr->kqr_suppressed;
	} else if (kq->kq_state & KQ_WORKLOOP) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;

		kqr = &kqwl->kqwl_request;
		res = &kqr->kqr_suppressed;
	} else {
		struct kqfile *kqf = (struct kqfile *)kq;
		res = &kqf->kqf_suppressed;
	}
	return res;
}

static kq_index_t
knote_get_queue_index(struct knote *kn)
{
	kq_index_t override_index = knote_get_qos_override_index(kn);
	kq_index_t qos_index = knote_get_qos_index(kn);
	struct kqueue *kq = knote_get_kq(kn);
	kq_index_t res;

	if (kq->kq_state & KQ_WORKQ) {
		res = _kqwq_base_index[qos_index];
		if (override_index > qos_index)
			res += override_index - qos_index;
		assert(res <= _kqwq_high_index[qos_index]);
	} else if (kq->kq_state & KQ_WORKLOOP) {
		res = MAX(override_index, qos_index);
		assert(res < KQWL_NBUCKETS);
	} else {
		assert(qos_index == QOS_INDEX_KQFILE);
		assert(override_index == QOS_INDEX_KQFILE);
		res = QOS_INDEX_KQFILE;
	}
	return res;
}

static struct kqtailq *
knote_get_queue(struct knote *kn)
{
	kq_index_t qindex = knote_get_queue_index(kn);

	return &(knote_get_kq(kn))->kq_queue[qindex];
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

	if (kq->kq_state & KQ_WORKQ) {
		assert(qos_index > THREAD_QOS_UNSPECIFIED);
	} else if (kq->kq_state & KQ_WORKLOOP) {
		/* XXX this policy decision shouldn't be here */
		if (qos_index == THREAD_QOS_UNSPECIFIED)
			qos_index = THREAD_QOS_LEGACY;
	} else
		qos_index = QOS_INDEX_KQFILE;

	/* always set requested */
	kn->kn_req_index = qos_index;

	/* only adjust in-use qos index when not suppressed */
	if ((kn->kn_status & KN_SUPPRESSED) == 0)
		kn->kn_qos_index = qos_index;
}

static void
knote_set_qos_overcommit(struct knote *kn)
{
	struct kqueue *kq = knote_get_kq(kn);
	struct kqrequest *kqr;

	/* turn overcommit on for the appropriate thread request? */
	if (kn->kn_qos & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG) {
		if (kq->kq_state & KQ_WORKQ) {
			kq_index_t qos_index = knote_get_qos_index(kn);
			struct kqworkq *kqwq = (struct kqworkq *)kq;

			kqr = kqworkq_get_request(kqwq, qos_index);

			kqwq_req_lock(kqwq);
			kqr->kqr_state |= KQR_THOVERCOMMIT;
			kqwq_req_unlock(kqwq);
		} else if (kq->kq_state & KQ_WORKLOOP) {
			struct kqworkloop *kqwl = (struct kqworkloop *)kq;

			kqr = &kqwl->kqwl_request;

			kqwl_req_lock(kqwl);
			kqr->kqr_state |= KQR_THOVERCOMMIT;
			kqwl_req_unlock(kqwl);
		}
	}
}

static kq_index_t
knote_get_qos_override_index(struct knote *kn)
{
	return kn->kn_qos_override;
}

static void
knote_set_qos_override_index(struct knote *kn, kq_index_t override_index,
		boolean_t override_is_sync)
{
	struct kqueue *kq = knote_get_kq(kn);
	kq_index_t qos_index = knote_get_qos_index(kn);
	kq_index_t old_override_index = knote_get_qos_override_index(kn);
	boolean_t old_override_is_sync = kn->kn_qos_override_is_sync;
	uint32_t flags = 0;

	assert((kn->kn_status & KN_QUEUED) == 0);

	if (override_index == KQWQ_QOS_MANAGER) {
		assert(qos_index == KQWQ_QOS_MANAGER);
	} else {
		assert(override_index < KQWQ_QOS_MANAGER);
	}

	kn->kn_qos_override = override_index;
	kn->kn_qos_override_is_sync = override_is_sync;

	/*
	 * If this is a workq/workloop kqueue, apply the override to the
	 * servicing thread.
	 */
	if (kq->kq_state & KQ_WORKQ)  {
		struct kqworkq *kqwq = (struct kqworkq *)kq;

		assert(qos_index > THREAD_QOS_UNSPECIFIED);
		kqworkq_update_override(kqwq, qos_index, override_index);
	} else if (kq->kq_state & KQ_WORKLOOP) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;

		if ((kn->kn_status & KN_SUPPRESSED) == KN_SUPPRESSED) {
			flags = flags | KQWL_UO_UPDATE_SUPPRESS_SYNC_COUNTERS;

			if (override_index == THREAD_QOS_USER_INTERACTIVE
					&& override_is_sync) {
				flags = flags | KQWL_UO_NEW_OVERRIDE_IS_SYNC_UI;
			}

			if (old_override_index == THREAD_QOS_USER_INTERACTIVE
					&& old_override_is_sync) {
				flags = flags | KQWL_UO_OLD_OVERRIDE_IS_SYNC_UI;
			}
		}

		assert(qos_index > THREAD_QOS_UNSPECIFIED);
		kqworkloop_update_override(kqwl, qos_index, override_index, flags);
	}
}

static kq_index_t
knote_get_sync_qos_override_index(struct knote *kn)
{
	return kn->kn_qos_sync_override;
}

static void
kqworkq_update_override(struct kqworkq *kqwq, kq_index_t qos_index, kq_index_t override_index)
{
	struct kqrequest *kqr;
	kq_index_t old_override_index;

	if (override_index <= qos_index) {
		return;
	}

	kqr = kqworkq_get_request(kqwq, qos_index);

	kqwq_req_lock(kqwq);
	old_override_index = kqr->kqr_override_index;
	if (override_index > MAX(kqr->kqr_qos_index, old_override_index)) {
		kqr->kqr_override_index = override_index;

		/* apply the override to [incoming?] servicing thread */
		if (kqr->kqr_state & KQR_BOUND) {
			thread_t wqthread = kqr->kqr_thread;

			/* only apply if non-manager */
			assert(wqthread);
		    if ((kqr->kqr_state & KQWQ_THMANAGER) == 0) {
				if (old_override_index)
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
kqworkq_bind_thread_impl(
	struct kqworkq *kqwq,
	kq_index_t qos_index,
	thread_t thread,
	unsigned int flags)
{
	/* request lock must be held */
	kqwq_req_held(kqwq);

	struct kqrequest *kqr = kqworkq_get_request(kqwq, qos_index);
	assert(kqr->kqr_state & KQR_THREQUESTED);

	if (qos_index == KQWQ_QOS_MANAGER)
		flags |= KEVENT_FLAG_WORKQ_MANAGER;

	struct uthread *ut = get_bsdthread_info(thread);

	/* 
	 * If this is a manager, and the manager request bit is
	 * not set, assure no other thread is bound. If the bit
	 * is set, make sure the old thread is us (or not set).
	 */
	if (flags & KEVENT_FLAG_WORKQ_MANAGER) {
		if ((kqr->kqr_state & KQR_BOUND) == 0) {
			kqr->kqr_state |= (KQR_BOUND | KQWQ_THMANAGER);
			TAILQ_INIT(&kqr->kqr_suppressed);
			kqr->kqr_thread = thread;
			ut->uu_kqueue_bound = (struct kqueue *)kqwq;
			ut->uu_kqueue_qos_index = KQWQ_QOS_MANAGER;
			ut->uu_kqueue_flags = (KEVENT_FLAG_WORKQ | 
			                       KEVENT_FLAG_WORKQ_MANAGER);
		} else {
			assert(kqr->kqr_state & KQR_BOUND);
			assert(thread == kqr->kqr_thread);
			assert(ut->uu_kqueue_bound == (struct kqueue *)kqwq);
			assert(ut->uu_kqueue_qos_index == KQWQ_QOS_MANAGER);
			assert(ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ_MANAGER);
		}
		return;
	}

	/* Just a normal one-queue servicing thread */
	assert(kqr->kqr_state & KQR_THREQUESTED);
	assert(kqr->kqr_qos_index == qos_index);

	if ((kqr->kqr_state & KQR_BOUND) == 0) {
		kqr->kqr_state |= KQR_BOUND;
		TAILQ_INIT(&kqr->kqr_suppressed);
		kqr->kqr_thread = thread;

		/* apply an ipc QoS override if one is needed */
		if (kqr->kqr_override_index) {
			assert(kqr->kqr_qos_index);
			assert(kqr->kqr_override_index > kqr->kqr_qos_index);
			assert(thread_get_ipc_override(thread) == THREAD_QOS_UNSPECIFIED);
			thread_add_ipc_override(thread, kqr->kqr_override_index);
		}

		/* indicate that we are processing in the uthread */
		ut->uu_kqueue_bound = (struct kqueue *)kqwq;
		ut->uu_kqueue_qos_index = qos_index;
		ut->uu_kqueue_flags = flags;
	} else {
		/*
		 * probably syncronously bound AND post-request bound
		 * this logic can go away when we get rid of post-request bind
		 */
		assert(kqr->kqr_state & KQR_BOUND);
		assert(thread == kqr->kqr_thread);
		assert(ut->uu_kqueue_bound == (struct kqueue *)kqwq);
		assert(ut->uu_kqueue_qos_index == qos_index);
		assert((ut->uu_kqueue_flags & flags) == flags);
	}
}

static void
kqworkloop_update_override(
	struct kqworkloop *kqwl,
	kq_index_t qos_index,
	kq_index_t override_index,
	uint32_t flags)
{
	struct kqrequest *kqr = &kqwl->kqwl_request;

	kqwl_req_lock(kqwl);

	/* Do not override on attached threads */
	if (kqr->kqr_state & KQR_BOUND) {
		assert(kqr->kqr_thread);

		if (kqwl->kqwl_kqueue.kq_state & KQ_NO_WQ_THREAD) {
			kqwl_req_unlock(kqwl);
			assert(!is_workqueue_thread(kqr->kqr_thread));
			return;
		}
	}

	/* Update sync ipc counts on kqr for suppressed knotes */
	if (flags & KQWL_UO_UPDATE_SUPPRESS_SYNC_COUNTERS) {
		kqworkloop_update_suppress_sync_count(kqr, flags);
	}

	if ((flags & KQWL_UO_UPDATE_OVERRIDE_LAZY) == 0) {
		kqworkloop_update_threads_qos(kqwl, KQWL_UTQ_UPDATE_WAKEUP_OVERRIDE,
			MAX(qos_index, override_index));
	}
	kqwl_req_unlock(kqwl);
}

static void
kqworkloop_update_suppress_sync_count(
	struct kqrequest *kqr,
	uint32_t flags)
{
	if (flags & KQWL_UO_NEW_OVERRIDE_IS_SYNC_UI) {
		kqr->kqr_sync_suppress_count++;
	}

	if (flags & KQWL_UO_OLD_OVERRIDE_IS_SYNC_UI) {
		assert(kqr->kqr_sync_suppress_count > 0);
		kqr->kqr_sync_suppress_count--;
	}
}

/*
 *	kqworkloop_unbind_thread - Unbind the servicer thread of a workloop kqueue
 *
 *	It will end the processing phase in case it was still processing:
 *
 *	We may have to request a new thread for not KQ_NO_WQ_THREAD workloop.
 *	This can happen if :
 *	- there were active events at or above our QoS we never got to (count > 0)
 *	- we pended waitq hook callouts during processing
 *	- we pended wakeups while processing (or unsuppressing)
 *
 *	Called with kqueue lock held.
 */

static void
kqworkloop_unbind_thread(
	struct kqworkloop *kqwl,
	thread_t thread,
	__unused unsigned int flags)
{
	struct kqueue *kq = &kqwl->kqwl_kqueue;
	struct kqrequest *kqr = &kqwl->kqwl_request;

	kqlock_held(kq);

	assert((kq->kq_state & KQ_PROCESSING) == 0);
	if (kq->kq_state & KQ_PROCESSING) {
		return;
	}

	/*
	 * Forcing the KQ_PROCESSING flag allows for QoS updates because of
	 * unsuppressing knotes not to be applied until the eventual call to
	 * kqworkloop_update_threads_qos() below.
	 */
	kq->kq_state |= KQ_PROCESSING;
	kqworkloop_acknowledge_events(kqwl, TRUE);
	kq->kq_state &= ~KQ_PROCESSING;

	kqwl_req_lock(kqwl);

	/* deal with extraneous unbinds in release kernels */
	assert((kqr->kqr_state & (KQR_BOUND | KQR_PROCESSING)) == KQR_BOUND);
	if ((kqr->kqr_state & (KQR_BOUND | KQR_PROCESSING)) != KQR_BOUND) {
		kqwl_req_unlock(kqwl);
		return;
	}

	assert(thread == current_thread());
	assert(kqr->kqr_thread == thread);
	if (kqr->kqr_thread != thread) {
		kqwl_req_unlock(kqwl);
	    return;
	}

	struct uthread *ut = get_bsdthread_info(thread);
	kq_index_t old_qos_index = ut->uu_kqueue_qos_index;
	boolean_t ipc_override_is_sync = ut->uu_kqueue_override_is_sync;
	ut->uu_kqueue_bound = NULL;
	ut->uu_kqueue_qos_index = 0;
	ut->uu_kqueue_override_is_sync = 0;
	ut->uu_kqueue_flags = 0;

	/* unbind the servicer thread, drop overrides */
	kqr->kqr_thread = NULL;
	kqr->kqr_state &= ~(KQR_BOUND | KQR_THREQUESTED | KQR_R2K_NOTIF_ARMED);
	kqworkloop_update_threads_qos(kqwl, KQWL_UTQ_RECOMPUTE_WAKEUP_QOS, 0);

	kqwl_req_unlock(kqwl);

	/*
	 * Drop the override on the current thread last, after the call to
	 * kqworkloop_update_threads_qos above.
	 */
	if (old_qos_index) {
		thread_drop_ipc_override(thread);
	}
	if (ipc_override_is_sync) {
		thread_drop_sync_ipc_override(thread);
	}
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
	kq_index_t override_index = 0;

	/* request lock must be held */
	kqwq_req_held(kqwq);

	assert(thread == current_thread());

	if ((kqr->kqr_state & KQR_BOUND) == 0) {
		assert(kqr->kqr_state & KQR_BOUND);
		return;
	}

	assert(kqr->kqr_thread == thread);
	assert(TAILQ_EMPTY(&kqr->kqr_suppressed));

	/* 
	 * If there is an override, drop it from the current thread
	 * and then we are free to recompute (a potentially lower)
	 * minimum override to apply to the next thread request.
	 */
	if (kqr->kqr_override_index) {
		struct kqtailq *base_queue = kqueue_get_base_queue(&kqwq->kqwq_kqueue, qos_index);
		struct kqtailq *queue = kqueue_get_high_queue(&kqwq->kqwq_kqueue, qos_index);

		/* if not bound to a manager thread, drop the current ipc override */
		if ((kqr->kqr_state & KQWQ_THMANAGER) == 0) {
			thread_drop_ipc_override(thread);
		}

		/* recompute the new override */
		do {
			if (!TAILQ_EMPTY(queue)) {
				override_index = queue - base_queue + qos_index;
				break;
			}
		} while (queue-- > base_queue);
	}

	/* Mark it unbound */
	kqr->kqr_thread = NULL;
	kqr->kqr_state &= ~(KQR_BOUND | KQR_THREQUESTED | KQWQ_THMANAGER);

	/* apply the new override */
	if (override_index > kqr->kqr_qos_index) {
		kqr->kqr_override_index = override_index;
	} else {
		kqr->kqr_override_index = THREAD_QOS_UNSPECIFIED;
	}
}

struct kqrequest *
kqworkq_get_request(struct kqworkq *kqwq, kq_index_t qos_index)
{
	assert(qos_index < KQWQ_NQOS);
	return &kqwq->kqwq_request[qos_index];
}

void
knote_adjust_qos(struct knote *kn, qos_t new_qos, qos_t new_override, kq_index_t sync_override_index)
{
	struct kqueue *kq = knote_get_kq(kn);
	boolean_t override_is_sync = FALSE;

	if (kq->kq_state & (KQ_WORKQ | KQ_WORKLOOP)) {
		kq_index_t new_qos_index;
		kq_index_t new_override_index;
		kq_index_t servicer_qos_index;

		new_qos_index = qos_index_from_qos(kn, new_qos, FALSE);
		new_override_index = qos_index_from_qos(kn, new_override, TRUE);

		/* make sure the servicer qos acts as a floor */
		servicer_qos_index = qos_index_from_qos(kn, kn->kn_qos, FALSE);
		if (servicer_qos_index > new_qos_index)
			new_qos_index = servicer_qos_index;
		if (servicer_qos_index > new_override_index)
			new_override_index = servicer_qos_index;
		if (sync_override_index >= new_override_index) {
			new_override_index = sync_override_index;
			override_is_sync = TRUE;
		}

		kqlock(kq);
		if (new_qos_index != knote_get_req_index(kn) ||
		    new_override_index != knote_get_qos_override_index(kn) ||
		    override_is_sync != kn->kn_qos_override_is_sync) {
			if (kn->kn_status & KN_QUEUED) {
				knote_dequeue(kn);
				knote_set_qos_index(kn, new_qos_index);
				knote_set_qos_override_index(kn, new_override_index, override_is_sync);
				knote_enqueue(kn);
				knote_wakeup(kn);
			} else {
				knote_set_qos_index(kn, new_qos_index);
				knote_set_qos_override_index(kn, new_override_index, override_is_sync);
			}
		}
		kqunlock(kq);
	}
}

void
knote_adjust_sync_qos(struct knote *kn, kq_index_t sync_qos, boolean_t lock_kq)
{
	struct kqueue *kq = knote_get_kq(kn);
	kq_index_t old_sync_override;
	kq_index_t qos_index = knote_get_qos_index(kn);
	uint32_t flags = 0;

	/* Tracking only happens for UI qos */
	if (sync_qos != THREAD_QOS_USER_INTERACTIVE &&
		sync_qos != THREAD_QOS_UNSPECIFIED) {
		return;
	}

	if (lock_kq)
		kqlock(kq);

	if (kq->kq_state & KQ_WORKLOOP) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;

		old_sync_override = knote_get_sync_qos_override_index(kn);
		if (old_sync_override != sync_qos) {
			kn->kn_qos_sync_override = sync_qos;

			/* update sync ipc counters for suppressed knotes */
			if ((kn->kn_status & KN_SUPPRESSED) == KN_SUPPRESSED) {
				flags = flags | KQWL_UO_UPDATE_SUPPRESS_SYNC_COUNTERS;

				/* Do not recalculate kqwl override, it would be done later */
				flags = flags | KQWL_UO_UPDATE_OVERRIDE_LAZY;

				if (sync_qos == THREAD_QOS_USER_INTERACTIVE) {
					flags = flags | KQWL_UO_NEW_OVERRIDE_IS_SYNC_UI;
				}

				if (old_sync_override == THREAD_QOS_USER_INTERACTIVE) {
					flags = flags | KQWL_UO_OLD_OVERRIDE_IS_SYNC_UI;
				}

				kqworkloop_update_override(kqwl, qos_index, sync_qos,
					flags);
			}

		}
	}
	if (lock_kq)
		kqunlock(kq);
}

static void
knote_wakeup(struct knote *kn)
{
	struct kqueue *kq = knote_get_kq(kn);
	kq_index_t qos_index = knote_get_qos_index(kn);

	kqlock_held(kq);

	if (kq->kq_state & KQ_WORKQ) {
		/* request a servicing thread */
		struct kqworkq *kqwq = (struct kqworkq *)kq;

		kqworkq_request_help(kqwq, qos_index);

	} else if (kq->kq_state & KQ_WORKLOOP) {
		/* request a servicing thread */
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;

		if (kqworkloop_is_processing_on_current_thread(kqwl)) {
			/*
			 * kqworkloop_end_processing() will perform the required QoS
			 * computations when it unsets the processing mode.
			 */
			return;
		}
		kqworkloop_request_help(kqwl, qos_index);
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

	struct kqueue *kq = (struct kqueue *)kq_hook;

	if (kq->kq_state & KQ_WORKQ) {
		struct kqworkq *kqwq = (struct kqworkq *)kq;

		kqworkq_request_help(kqwq, KQWQ_QOS_MANAGER);

	} else if (kq->kq_state & KQ_WORKLOOP) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;

		kqworkloop_request_help(kqwl, KQWL_BUCKET_STAYACTIVE);
	}
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

		assert(!knoteuse_needs_boost(kn, NULL));

		/* If we can get a use reference - deliver event */
		if (kqlock2knoteuse(kq, kn, KNUSE_NONE)) {
			int result;

			/* call the event with only a use count */
			result = knote_fops(kn)->f_event(kn, hint);

			/* if its not going away and triggered */
			if (knoteuse2kqlock(kq, kn, KNUSE_NONE) && result)
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

		assert(!knoteuse_needs_boost(kn, NULL));

		if ((kn->kn_status & KN_DROPPING) == 0) {
			/* If EV_VANISH supported - prepare to deliver one */
			if (kn->kn_status & KN_REQVANISH) {
				kn->kn_status |= KN_VANISHED;
				knote_activate(kn);

			} else if (kqlock2knoteuse(kq, kn, KNUSE_NONE)) {
				/* call the event with only a use count */
				result = knote_fops(kn)->f_event(kn, NOTE_REVOKE);

				/* if its not going away and triggered */
				if (knoteuse2kqlock(kq, kn, KNUSE_NONE) && result)
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

				assert(!knoteuse_needs_boost(kn, NULL));

				/* get detach reference (also marks vanished) */
				if (kqlock2knotedetach(kq, kn, KNUSE_NONE)) {
					/* detach knote and drop fp use reference */
					knote_fops(kn)->f_detach(kn);
					if (knote_fops(kn)->f_isfd)
						fp_drop(p, kn->kn_id, kn->kn_fp, 0);

					/* activate it if it's still in existence */
					if (knoteuse2kqlock(kq, kn, KNUSE_NONE)) {
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
 * fd_knhashlock or fdlock held on entry (and exit)
 */
static struct knote *
knote_fdfind(struct kqueue *kq,
             struct kevent_internal_s *kev,
	     bool is_fd,
             struct proc *p)
{
	struct filedesc *fdp = p->p_fd;
	struct klist *list = NULL;
	struct knote *kn = NULL;

	/* 
	 * determine where to look for the knote
	 */
	if (is_fd) {
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
 * kq_add_knote- Add knote to the fd table for process
 * while checking for duplicates.
 *
 * All file-based filters associate a list of knotes by file
 * descriptor index. All other filters hash the knote by ident.
 *
 * May have to grow the table of knote lists to cover the
 * file descriptor index presented.
 *
 * fd_knhashlock and fdlock unheld on entry (and exit).
 *
 * Takes a rwlock boost if inserting the knote is successful.
 */
static int
kq_add_knote(struct kqueue *kq, struct knote *kn,
             struct kevent_internal_s *kev,
             struct proc *p, int *knoteuse_flags)
{
	struct filedesc *fdp = p->p_fd;
	struct klist *list = NULL;
	int ret = 0;
	bool is_fd = knote_fops(kn)->f_isfd;

	if (is_fd)
		proc_fdlock(p);
	else
		knhash_lock(p);

	if (knote_fdfind(kq, kev, is_fd, p) != NULL) {
		/* found an existing knote: we can't add this one */
		ret = ERESTART;
		goto out_locked;
	}

	/* knote was not found: add it now */
	if (!is_fd) {
		if (fdp->fd_knhashmask == 0) {
			u_long size = 0;

			list = hashinit(CONFIG_KN_HASHSIZE, M_KQUEUE,
						  &size);
			if (list == NULL) {
				ret = ENOMEM;
				goto out_locked;
			}

			fdp->fd_knhash = list;
			fdp->fd_knhashmask = size;
		}

		list = &fdp->fd_knhash[KN_HASH(kn->kn_id, fdp->fd_knhashmask)];
		SLIST_INSERT_HEAD(list, kn, kn_link);
		ret = 0;
		goto out_locked;

	} else {
		/* knote is fd based */

		if ((u_int)fdp->fd_knlistsize <= kn->kn_id) {
			u_int size = 0;

			if (kn->kn_id >= (uint64_t)p->p_rlimit[RLIMIT_NOFILE].rlim_cur
			    || kn->kn_id >= (uint64_t)maxfiles) {
				ret = EINVAL;
				goto out_locked;
			}
			/* have to grow the fd_knlist */
			size = fdp->fd_knlistsize;
			while (size <= kn->kn_id)
				size += KQEXTENT;

			if (size >= (UINT_MAX/sizeof(struct klist *))) {
				ret = EINVAL;
				goto out_locked;
			}

			MALLOC(list, struct klist *,
			    size * sizeof(struct klist *), M_KQUEUE, M_WAITOK);
			if (list == NULL) {
				ret = ENOMEM;
				goto out_locked;
			}

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
		SLIST_INSERT_HEAD(list, kn, kn_link);
		ret = 0;
		goto out_locked;

	}

out_locked:
	if (ret == 0 && knoteuse_needs_boost(kn, kev)) {
		set_thread_rwlock_boost();
		*knoteuse_flags = KNUSE_BOOST;
	} else {
		*knoteuse_flags = KNUSE_NONE;
	}
	if (is_fd)
		proc_fdunlock(p);
	else
		knhash_unlock(p);

	return ret;
}

/*
 * kq_remove_knote - remove a knote from the fd table for process
 * and copy kn_status an kq_state while holding kqlock and
 * fd table locks.
 *
 * If the filter is file-based, remove based on fd index.
 * Otherwise remove from the hash based on the ident.
 *
 * fd_knhashlock and fdlock unheld on entry (and exit).
 */
static void
kq_remove_knote(struct kqueue *kq, struct knote *kn, struct proc *p,
	kn_status_t *kn_status, uint16_t *kq_state)
{
	struct filedesc *fdp = p->p_fd;
	struct klist *list = NULL;
	bool is_fd;

	is_fd = knote_fops(kn)->f_isfd;

	if (is_fd)
		proc_fdlock(p);
	else
		knhash_lock(p);

	if (is_fd) {
		assert ((u_int)fdp->fd_knlistsize > kn->kn_id);
		list = &fdp->fd_knlist[kn->kn_id];
	} else {
		list = &fdp->fd_knhash[KN_HASH(kn->kn_id, fdp->fd_knhashmask)];
	}
	SLIST_REMOVE(list, kn, knote, kn_link);

	kqlock(kq);
	*kn_status = kn->kn_status;
	*kq_state = kq->kq_state;
	kqunlock(kq);

	if (is_fd)
		proc_fdunlock(p);
	else
		knhash_unlock(p);
}

/*
 * kq_find_knote_and_kq_lock - lookup a knote in the fd table for process
 * and, if the knote is found, acquires the kqlock while holding the fd table lock/spinlock.
 *
 * fd_knhashlock or fdlock unheld on entry (and exit)
 */

static struct knote *
kq_find_knote_and_kq_lock(struct kqueue *kq,
             struct kevent_internal_s *kev,
	     bool is_fd,
             struct proc *p)
{
	struct knote * ret;

	if (is_fd)
		proc_fdlock(p);
	else
		knhash_lock(p);

	ret = knote_fdfind(kq, kev, is_fd, p);

	if (ret) {
		kqlock(kq);
	}

	if (is_fd)
		proc_fdunlock(p);
	else
		knhash_unlock(p);

	return ret;
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
	kn_status_t kn_status;
	uint16_t kq_state;

	/* If we are attached, disconnect from the source first */
	if (kn->kn_status & KN_ATTACHED) {
		knote_fops(kn)->f_detach(kn);
	}

	/* Remove the source from the appropriate hash */
	kq_remove_knote(kq, kn, p, &kn_status, &kq_state);

	/*
	 * If a kqueue_dealloc is happening in parallel for the kq
	 * pointed by the knote the kq could be aready deallocated
	 * at this point.
	 * Do not access the kq after the kq_remove_knote if it is
	 * not a KQ_DYNAMIC.
	 */

	/* determine if anyone needs to know about the drop */
	assert((kn_status & (KN_DROPPING | KN_SUPPRESSED | KN_QUEUED)) == KN_DROPPING);

	/*
	 * If KN_USEWAIT is set, some other thread was trying to drop the kn.
	 * Or it was in kqueue_dealloc, so the kqueue_dealloc did not happen
	 * because that thread was waiting on this wake, or it was a drop happening
	 * because of a kevent_register that takes a reference on the kq, and therefore
	 * the kq cannot be deallocated in parallel.
	 *
	 * It is safe to access kq->kq_wqs if needswakeup is set.
	 */
	if (kn_status & KN_USEWAIT)
		waitq_wakeup64_all((struct waitq *)&kq->kq_wqs,
				   CAST_EVENT64_T(&kn->kn_status),
				   THREAD_RESTART,
				   WAITQ_ALL_PRIORITIES);

	if (knote_fops(kn)->f_isfd && ((kn->kn_status & KN_VANISHED) == 0))
		fp_drop(p, kn->kn_id, kn->kn_fp, 0);

	knote_free(kn);

	/*
	 * release reference on dynamic kq (and free if last).
	 * Will only be last if this is from fdfree, etc...
	 * because otherwise processing thread has reference.
	 */
	if (kq_state & KQ_DYNAMIC)
		kqueue_release_last(p, kq);
}

/* called with kqueue lock held */
static void
knote_activate(struct knote *kn)
{
	if (kn->kn_status & KN_ACTIVE)
		return;

	KDBG_FILTERED(KEV_EVTID(BSD_KEVENT_KNOTE_ACTIVATE),
	              kn->kn_udata, kn->kn_status | (kn->kn_id << 32),
	              kn->kn_filtid);

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

	if (kn->kn_status & KN_SUPPRESSED) {
		/* Clear the sync qos on the knote */
		knote_adjust_sync_qos(kn, THREAD_QOS_UNSPECIFIED, FALSE);

		/*
		 * it is possible for userland to have knotes registered for a given
		 * workloop `wl_orig` but really handled on another workloop `wl_new`.
		 *
		 * In that case, rearming will happen from the servicer thread of
		 * `wl_new` which if `wl_orig` is no longer being serviced, would cause
		 * this knote to stay suppressed forever if we only relied on
		 * kqworkloop_acknowledge_events to be called by `wl_orig`.
		 *
		 * However if we see the KQ_PROCESSING bit on `wl_orig` set, we can't
		 * unsuppress because that would mess with the processing phase of
		 * `wl_orig`, however it also means kqworkloop_acknowledge_events()
		 * will be called.
		 */
		struct kqueue *kq = knote_get_kq(kn);
		if ((kq->kq_state & KQ_PROCESSING) == 0) {
			knote_unsuppress(kn);
		}
	} else if (knote_enqueue(kn)) {
		knote_wakeup(kn);
	}
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
	struct kqueue *kq = knote_get_kq(kn);

	kqlock_held(kq);

	if (kn->kn_status & KN_SUPPRESSED)
		return;

	knote_dequeue(kn);
	kn->kn_status |= KN_SUPPRESSED;
	suppressq = kqueue_get_suppressed_queue(kq, knote_get_qos_index(kn));
	TAILQ_INSERT_TAIL(suppressq, kn, kn_tqe);

	if ((kq->kq_state & KQ_WORKLOOP) &&
	     knote_get_qos_override_index(kn) == THREAD_QOS_USER_INTERACTIVE &&
	     kn->kn_qos_override_is_sync) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;
		/* update the sync qos override counter for suppressed knotes */
		kqworkloop_update_override(kqwl, knote_get_qos_index(kn),
			knote_get_qos_override_index(kn),
			(KQWL_UO_UPDATE_SUPPRESS_SYNC_COUNTERS | KQWL_UO_NEW_OVERRIDE_IS_SYNC_UI));
	}
}

/* called with kqueue lock held */
static void
knote_unsuppress(struct knote *kn)
{
	struct kqtailq *suppressq;
	struct kqueue *kq = knote_get_kq(kn);

	kqlock_held(kq);

	if ((kn->kn_status & KN_SUPPRESSED) == 0)
		return;

	/* Clear the sync qos on the knote */
	knote_adjust_sync_qos(kn, THREAD_QOS_UNSPECIFIED, FALSE);

	kn->kn_status &= ~KN_SUPPRESSED;
	suppressq = kqueue_get_suppressed_queue(kq, knote_get_qos_index(kn));
	TAILQ_REMOVE(suppressq, kn, kn_tqe);

	/* udate in-use qos to equal requested qos */
	kn->kn_qos_index = kn->kn_req_index;

	/* don't wakeup if unsuppressing just a stay-active knote */
	if (knote_enqueue(kn) && (kn->kn_status & KN_ACTIVE)) {
		knote_wakeup(kn);
	}

	if ((kq->kq_state & KQ_WORKLOOP) && !(kq->kq_state & KQ_NO_WQ_THREAD) &&
	     knote_get_qos_override_index(kn) == THREAD_QOS_USER_INTERACTIVE &&
	     kn->kn_qos_override_is_sync) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;

		/* update the sync qos override counter for suppressed knotes */
		kqworkloop_update_override(kqwl, knote_get_qos_index(kn),
			knote_get_qos_override_index(kn),
			(KQWL_UO_UPDATE_SUPPRESS_SYNC_COUNTERS | KQWL_UO_OLD_OVERRIDE_IS_SYNC_UI));
	}

	if (TAILQ_EMPTY(suppressq) && (kq->kq_state & KQ_WORKLOOP) &&
			!(kq->kq_state & KQ_NO_WQ_THREAD)) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;
		if (kqworkloop_is_processing_on_current_thread(kqwl)) {
			/*
			 * kqworkloop_end_processing() will perform the required QoS
			 * computations when it unsets the processing mode.
			 */
		} else {
			kqwl_req_lock(kqwl);
			kqworkloop_update_threads_qos(kqwl, KQWL_UTQ_RESET_WAKEUP_OVERRIDE, 0);
			kqwl_req_unlock(kqwl);
		}
	}
}

/* called with kqueue lock held */
static void
knote_update_sync_override_state(struct knote *kn)
{
	struct kqtailq *queue = knote_get_queue(kn);
	struct kqueue *kq = knote_get_kq(kn);

	if (!(kq->kq_state & KQ_WORKLOOP) ||
	    knote_get_queue_index(kn) != THREAD_QOS_USER_INTERACTIVE)
		return;

	/* Update the sync ipc state on workloop */
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	boolean_t sync_ipc_override = FALSE;
	if (!TAILQ_EMPTY(queue)) {
		struct knote *kn_head = TAILQ_FIRST(queue);
		if (kn_head->kn_qos_override_is_sync)
			sync_ipc_override = TRUE;
	}
	kqworkloop_update_sync_override_state(kqwl, sync_ipc_override);
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

		kqlock_held(kq);
		/* insert at head for sync ipc waiters */
		if (kn->kn_qos_override_is_sync) {
			TAILQ_INSERT_HEAD(queue, kn, kn_tqe);
		} else {
			TAILQ_INSERT_TAIL(queue, kn, kn_tqe);
		}
		kn->kn_status |= KN_QUEUED;
		kq->kq_count++;
		knote_update_sync_override_state(kn);
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

	kqlock_held(kq);

	if ((kn->kn_status & KN_QUEUED) == 0)
		return;

	queue = knote_get_queue(kn);
	TAILQ_REMOVE(queue, kn, kn_tqe);
	kn->kn_status &= ~KN_QUEUED;
	kq->kq_count--;
	knote_update_sync_override_state(kn);
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

	kqworkloop_zone = zinit(sizeof(struct kqworkloop), 8192*sizeof(struct kqworkloop),
	                    8192, "kqueue workloop zone");

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

const struct filterops *
knote_fops(struct knote *kn)
{
	return sysfilt_ops[kn->kn_filtid];
}

static struct knote *
knote_alloc(void)
{
	struct knote *kn;
	kn = ((struct knote *)zalloc(knote_zone));
	*kn = (struct knote) { .kn_qos_override = 0, .kn_qos_sync_override = 0, .kn_qos_override_is_sync = 0 };
	return kn;
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
event_getlock(struct socket *so, int flags)
{
#pragma unused(flags)
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

	if (refcount) {
		so->so_usecount--;
	}
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

	LCK_MTX_ASSERT(mutex_held, LCK_MTX_ASSERT_OWNED);
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

	LCK_MTX_ASSERT(&(ev_pcb->evp_mtx), LCK_MTX_ASSERT_OWNED);

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

	LCK_MTX_ASSERT(&(ev_pcb->evp_mtx), LCK_MTX_ASSERT_NOTOWNED);
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

	m = m_get(M_WAIT, MT_DATA);
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

		m2 = m_copym(m, 0, m->m_len, M_WAIT);
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
	st->vst_ino = (kq->kq_state & KQ_DYNAMIC) ?
		((struct kqworkloop *)kq)->kqwl_dynamicid : 0;

	/* flags exported to libproc as PROC_KQUEUE_* (sys/proc_info.h) */
#define PROC_KQUEUE_MASK (KQ_SEL|KQ_SLEEP|KQ_KEV32|KQ_KEV64|KQ_KEV_QOS|KQ_WORKQ|KQ_WORKLOOP)
	kinfo->kq_state = kq->kq_state & PROC_KQUEUE_MASK;

	return (0);
}

static int
fill_kqueue_dyninfo(struct kqueue *kq, struct kqueue_dyninfo *kqdi)
{
	struct kqworkloop *kqwl = (struct kqworkloop *)kq;
	struct kqrequest *kqr = &kqwl->kqwl_request;
	int err;

	if ((kq->kq_state & KQ_WORKLOOP) == 0) {
		return EINVAL;
	}

	if ((err = fill_kqueueinfo(kq, &kqdi->kqdi_info))) {
		return err;
	}

	kqwl_req_lock(kqwl);

	if (kqr->kqr_thread) {
		kqdi->kqdi_servicer = thread_tid(kqr->kqr_thread);
	}

	if (kqwl->kqwl_owner == WL_OWNER_SUSPENDED) {
		kqdi->kqdi_owner = ~0ull;
	} else {
		kqdi->kqdi_owner = thread_tid(kqwl->kqwl_owner);
	}

	kqdi->kqdi_request_state = kqr->kqr_state;
	kqdi->kqdi_async_qos = kqr->kqr_qos_index;
	kqdi->kqdi_events_qos = kqr->kqr_override_index;
	kqdi->kqdi_sync_waiters = kqr->kqr_dsync_waiters;
	kqdi->kqdi_sync_waiter_qos = kqr->kqr_dsync_waiters_qos;

	kqwl_req_unlock(kqwl);

	return 0;
}


void
knote_markstayactive(struct knote *kn)
{
	struct kqueue *kq = knote_get_kq(kn);

	kqlock(kq);
	kn->kn_status |= KN_STAYACTIVE;

	/*
	 * Making a knote stay active is a property of the knote that must be
	 * established before it is fully attached.
	 */
	assert(kn->kn_status & KN_ATTACHING);

	/* handle all stayactive knotes on the (appropriate) manager */
	if (kq->kq_state & KQ_WORKQ) {
		knote_set_qos_index(kn, KQWQ_QOS_MANAGER);
	} else if (kq->kq_state & KQ_WORKLOOP) {
		struct kqworkloop *kqwl = (struct kqworkloop *)kq;
		kqwl_req_lock(kqwl);
		assert(kn->kn_req_index && kn->kn_req_index < THREAD_QOS_LAST);
		kqworkloop_update_threads_qos(kqwl, KQWL_UTQ_UPDATE_STAYACTIVE_QOS,
				kn->kn_req_index);
		kqwl_req_unlock(kqwl);
		knote_set_qos_index(kn, KQWL_BUCKET_STAYACTIVE);
	}

	knote_activate(kn);
	kqunlock(kq);
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
	for (; kn; kn = SLIST_NEXT(kn, kn_link)) {
		if (kq == knote_get_kq(kn)) {
			if (nknotes < buflen) {
				struct kevent_extinfo *info = &buf[nknotes];
				struct kevent_internal_s *kevp = &kn->kn_kevent;

				kqlock(kq);

				info->kqext_kev = (struct kevent_qos_s){
					.ident = kevp->ident,
					.filter = kevp->filter,
					.flags = kevp->flags,
					.fflags = kevp->fflags,
					.data = (int64_t)kevp->data,
					.udata = kevp->udata,
					.ext[0] = kevp->ext[0],
					.ext[1] = kevp->ext[1],
					.ext[2] = kevp->ext[2],
					.ext[3] = kevp->ext[3],
					.qos = kn->kn_req_index,
				};
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
kevent_copyout_proc_dynkqids(void *proc, user_addr_t ubuf, uint32_t ubufsize,
		int32_t *nkqueues_out)
{
	proc_t p = (proc_t)proc;
	struct filedesc *fdp = p->p_fd;
	unsigned int nkqueues = 0;
	unsigned long ubuflen = ubufsize / sizeof(kqueue_id_t);
	size_t buflen, bufsize;
	kqueue_id_t *kq_ids = NULL;
	int err = 0;

	assert(p != NULL);

	if (ubuf == USER_ADDR_NULL && ubufsize != 0) {
		err = EINVAL;
		goto out;
	}

	buflen = min(ubuflen, PROC_PIDDYNKQUEUES_MAX);

	if (ubuflen != 0) {
		if (os_mul_overflow(sizeof(kqueue_id_t), buflen, &bufsize)) {
			err = ERANGE;
			goto out;
		}
		kq_ids = kalloc(bufsize);
		assert(kq_ids != NULL);
	}

	kqhash_lock(p);

	if (fdp->fd_kqhashmask > 0) {
		for (uint32_t i = 0; i < fdp->fd_kqhashmask + 1; i++) {
			struct kqworkloop *kqwl;

			SLIST_FOREACH(kqwl, &fdp->fd_kqhash[i], kqwl_hashlink) {
				/* report the number of kqueues, even if they don't all fit */
				if (nkqueues < buflen) {
					kq_ids[nkqueues] = kqwl->kqwl_dynamicid;
				}
				nkqueues++;
			}
		}
	}

	kqhash_unlock(p);

	if (kq_ids) {
		size_t copysize;
		if (os_mul_overflow(sizeof(kqueue_id_t), min(ubuflen, nkqueues), &copysize)) {
			err = ERANGE;
			goto out;
		}

		assert(ubufsize >= copysize);
		err = copyout(kq_ids, ubuf, copysize);
	}

out:
	if (kq_ids) {
		kfree(kq_ids, bufsize);
	}

	if (!err) {
		*nkqueues_out = (int)min(nkqueues, PROC_PIDDYNKQUEUES_MAX);
	}
	return err;
}

int
kevent_copyout_dynkqinfo(void *proc, kqueue_id_t kq_id, user_addr_t ubuf,
		uint32_t ubufsize, int32_t *size_out)
{
	proc_t p = (proc_t)proc;
	struct kqueue *kq;
	int err = 0;
	struct kqueue_dyninfo kqdi = { };

	assert(p != NULL);

	if (ubufsize < sizeof(struct kqueue_info)) {
		return ENOBUFS;
	}

	kqhash_lock(p);
	kq = kqueue_hash_lookup(p, kq_id);
	if (!kq) {
		kqhash_unlock(p);
		return ESRCH;
	}
	kqueue_retain(kq);
	kqhash_unlock(p);

	/*
	 * backward compatibility: allow the argument to this call to only be
	 * a struct kqueue_info
	 */
	if (ubufsize >= sizeof(struct kqueue_dyninfo)) {
		ubufsize = sizeof(struct kqueue_dyninfo);
		err = fill_kqueue_dyninfo(kq, &kqdi);
	} else {
		ubufsize = sizeof(struct kqueue_info);
		err = fill_kqueueinfo(kq, &kqdi.kqdi_info);
	}
	if (err == 0 && (err = copyout(&kqdi, ubuf, ubufsize)) == 0) {
		*size_out = ubufsize;
	}
	kqueue_release_last(p, kq);
	return err;
}

int
kevent_copyout_dynkqextinfo(void *proc, kqueue_id_t kq_id, user_addr_t ubuf,
		uint32_t ubufsize, int32_t *nknotes_out)
{
	proc_t p = (proc_t)proc;
	struct kqueue *kq;
	int err;

	assert(p != NULL);

	kqhash_lock(p);
	kq = kqueue_hash_lookup(p, kq_id);
	if (!kq) {
		kqhash_unlock(p);
		return ESRCH;
	}
	kqueue_retain(kq);
	kqhash_unlock(p);

	err = pid_kqueue_extinfo(p, kq, ubuf, ubufsize, nknotes_out);
	kqueue_release_last(p, kq);
	return err;
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
	proc_fdunlock(p);

	if (fdp->fd_knhashmask != 0) {
		for (i = 0; i < (int)fdp->fd_knhashmask + 1; i++) {
			kqhash_lock(p);
			kn = SLIST_FIRST(&fdp->fd_knhash[i]);
			nknotes = kevent_extinfo_emit(kq, kn, kqext, buflen, nknotes);
			kqhash_unlock(p);
		}
	}

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

static unsigned int
klist_copy_udata(struct klist *list, uint64_t *buf,
		unsigned int buflen, unsigned int nknotes)
{
	struct kevent_internal_s *kev;
	struct knote *kn;
	SLIST_FOREACH(kn, list, kn_link) {
		if (nknotes < buflen) {
			struct kqueue *kq = knote_get_kq(kn);
			kqlock(kq);
			kev = &(kn->kn_kevent);
			buf[nknotes] = kev->udata;
			kqunlock(kq);
		}
		/* we return total number of knotes, which may be more than requested */
		nknotes++;
	}

	return nknotes;
}

static unsigned int
kqlist_copy_dynamicids(__assert_only proc_t p, struct kqlist *list,
		uint64_t *buf, unsigned int buflen, unsigned int nids)
{
	kqhash_lock_held(p);
	struct kqworkloop *kqwl;
	SLIST_FOREACH(kqwl, list, kqwl_hashlink) {
		if (nids < buflen) {
			buf[nids] = kqwl->kqwl_dynamicid;
		}
		nids++;
	}
	return nids;
}

int
kevent_proc_copy_uptrs(void *proc, uint64_t *buf, int bufsize)
{
	proc_t p = (proc_t)proc;
	struct filedesc *fdp = p->p_fd;
	unsigned int nuptrs = 0;
	unsigned long buflen = bufsize / sizeof(uint64_t);

	if (buflen > 0) {
		assert(buf != NULL);
	}

	proc_fdlock(p);
	for (int i = 0; i < fdp->fd_knlistsize; i++) {
		nuptrs = klist_copy_udata(&fdp->fd_knlist[i], buf, buflen, nuptrs);
	}
	knhash_lock(p);
	proc_fdunlock(p);
	if (fdp->fd_knhashmask != 0) {
		for (int i = 0; i < (int)fdp->fd_knhashmask + 1; i++) {
			nuptrs = klist_copy_udata(&fdp->fd_knhash[i], buf, buflen, nuptrs);
		}
	}
	knhash_unlock(p);

	kqhash_lock(p);
	if (fdp->fd_kqhashmask != 0) {
		for (int i = 0; i < (int)fdp->fd_kqhashmask + 1; i++) {
			nuptrs = kqlist_copy_dynamicids(p, &fdp->fd_kqhash[i], buf, buflen,
					nuptrs);
		}
	}
	kqhash_unlock(p);

	return (int)nuptrs;
}

static void
kevent_redrive_proc_thread_request(proc_t p)
{
	__assert_only int ret;
	ret = (*pthread_functions->workq_threadreq)(p, NULL, WORKQ_THREADREQ_REDRIVE, 0, 0);
	assert(ret == 0 || ret == ECANCELED);
}

static void
kevent_set_return_to_kernel_user_tsd(proc_t p, thread_t thread)
{
	uint64_t ast_addr;
	bool proc_is_64bit = !!(p->p_flag & P_LP64);
	size_t user_addr_size = proc_is_64bit ? 8 : 4;
	uint32_t ast_flags32 = 0;
	uint64_t ast_flags64 = 0;
	struct uthread *ut = get_bsdthread_info(thread);

	if (ut->uu_kqueue_bound != NULL) {
		if (ut->uu_kqueue_flags & KEVENT_FLAG_WORKLOOP) {
			ast_flags64 |= R2K_WORKLOOP_PENDING_EVENTS;
		} else if (ut->uu_kqueue_flags & KEVENT_FLAG_WORKQ) {
			ast_flags64 |= R2K_WORKQ_PENDING_EVENTS;
		}
	}

	if (ast_flags64 == 0) {
		return;
	}

	if (!(p->p_flag & P_LP64)) {
		ast_flags32 = (uint32_t)ast_flags64;
		assert(ast_flags64 < 0x100000000ull);
	}

	ast_addr = thread_rettokern_addr(thread);
	if (ast_addr == 0) {
		return;
	}

	if (copyout((proc_is_64bit ? (void *)&ast_flags64 : (void *)&ast_flags32),
	            (user_addr_t)ast_addr,
	            user_addr_size) != 0) {
		printf("pid %d (tid:%llu): copyout of return_to_kernel ast flags failed with "
		       "ast_addr = %llu\n", p->p_pid, thread_tid(current_thread()), ast_addr);
	}
}

void
kevent_ast(thread_t thread, uint16_t bits)
{
	proc_t p = current_proc();

	if (bits & AST_KEVENT_REDRIVE_THREADREQ) {
		kevent_redrive_proc_thread_request(p);
	}
	if (bits & AST_KEVENT_RETURN_TO_KERNEL) {
		kevent_set_return_to_kernel_user_tsd(p, thread);
	}
}

#if DEVELOPMENT || DEBUG

#define KEVENT_SYSCTL_BOUND_ID 1

static int
kevent_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	uintptr_t type = (uintptr_t)arg1;
	uint64_t bound_id = 0;
	struct uthread *ut;
	struct kqueue *kq;

	if (type != KEVENT_SYSCTL_BOUND_ID) {
		return EINVAL;
	}

	if (req->newptr) {
		return EINVAL;
	}

	ut = get_bsdthread_info(current_thread());
	if (!ut) {
		return EFAULT;
	}

	kq = ut->uu_kqueue_bound;
	if (kq) {
		if (kq->kq_state & KQ_WORKLOOP) {
			bound_id = ((struct kqworkloop *)kq)->kqwl_dynamicid;
		} else if (kq->kq_state & KQ_WORKQ) {
			bound_id = -1;
		}
	}

	return sysctl_io_number(req, bound_id, sizeof(bound_id), NULL, NULL);
}

SYSCTL_NODE(_kern, OID_AUTO, kevent, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
		"kevent information");

SYSCTL_PROC(_kern_kevent, OID_AUTO, bound_id,
		CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED,
		(void *)KEVENT_SYSCTL_BOUND_ID,
		sizeof(kqueue_id_t), kevent_sysctl, "Q",
		"get the ID of the bound kqueue");

#endif /* DEVELOPMENT || DEBUG */
