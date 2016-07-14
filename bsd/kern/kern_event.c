/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
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
#include <kern/thread_call.h>
#include <kern/sched_prim.h>
#include <kern/waitq.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>

#include <libkern/libkern.h>
#include "net/net_str_id.h"

#include <mach/task.h>

#if VM_PRESSURE_EVENTS
#include <kern/vm_pressure.h>
#endif

#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif

MALLOC_DEFINE(M_KQUEUE, "kqueue", "memory for kqueue system");

#define	KQ_EVENT	NO_EVENT64

static inline void kqlock(struct kqueue *kq);
static inline void kqunlock(struct kqueue *kq);

static int kqlock2knoteuse(struct kqueue *kq, struct knote *kn);
static int kqlock2knoteusewait(struct kqueue *kq, struct knote *kn);
static int kqlock2knotedrop(struct kqueue *kq, struct knote *kn);
static int knoteuse2kqlock(struct kqueue *kq, struct knote *kn);

static void kqueue_wakeup(struct kqueue *kq, int closed);
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
			   user_addr_t data_out, user_size_t *data_available,
			   unsigned int flags, user_addr_t utimeout,
			   kqueue_continue_t continuation,
			   int32_t *retval);
static int kevent_copyin(user_addr_t *addrp, struct kevent_internal_s *kevp,
			 struct proc *p, unsigned int flags);
static int kevent_copyout(struct kevent_internal_s *kevp, user_addr_t *addrp,
			  struct proc *p, unsigned int flags);
char * kevent_description(struct kevent_internal_s *kevp, char *s, size_t n);

static int kevent_callback(struct kqueue *kq, struct kevent_internal_s *kevp,
			   void *data);
static void kevent_continue(struct kqueue *kq, void *data, int error);
static void kqueue_scan_continue(void *contp, wait_result_t wait_result);
static int kqueue_process(struct kqueue *kq, kevent_callback_t callback,
			  void *data, int *countp, struct proc *p);
static int kqueue_begin_processing(struct kqueue *kq);
static void kqueue_end_processing(struct kqueue *kq);
static int knote_process(struct knote *kn, kevent_callback_t callback,
			 void *data, struct kqtailq *inprocessp, struct proc *p);
static void knote_put(struct knote *kn);
static int knote_fdpattach(struct knote *kn, struct filedesc *fdp,
			   struct proc *p);
static void knote_drop(struct knote *kn, struct proc *p);
static void knote_activate(struct knote *kn, int);
static void knote_deactivate(struct knote *kn);
static void knote_enqueue(struct knote *kn);
static void knote_dequeue(struct knote *kn);
static struct knote *knote_alloc(void);
static void knote_free(struct knote *kn);

static int filt_fileattach(struct knote *kn);
static struct filterops file_filtops = {
	.f_isfd = 1,
	.f_attach = filt_fileattach,
};

static void filt_kqdetach(struct knote *kn);
static int filt_kqueue(struct knote *kn, long hint);
static struct filterops kqread_filtops = {
	.f_isfd = 1,
	.f_detach = filt_kqdetach,
	.f_event = filt_kqueue,
};

/* placeholder for not-yet-implemented filters */
static int filt_badattach(struct knote *kn);
static struct filterops bad_filtops = {
	.f_attach = filt_badattach,
};

static int filt_procattach(struct knote *kn);
static void filt_procdetach(struct knote *kn);
static int filt_proc(struct knote *kn, long hint);
static struct filterops proc_filtops = {
	.f_attach = filt_procattach,
	.f_detach = filt_procdetach,
	.f_event = filt_proc,
};

#if VM_PRESSURE_EVENTS
static int filt_vmattach(struct knote *kn);
static void filt_vmdetach(struct knote *kn);
static int filt_vm(struct knote *kn, long hint);
static struct filterops vm_filtops = {
	.f_attach = filt_vmattach,
	.f_detach = filt_vmdetach,
	.f_event = filt_vm,
};
#endif /* VM_PRESSURE_EVENTS */

#if CONFIG_MEMORYSTATUS
extern struct filterops memorystatus_filtops;
#endif /* CONFIG_MEMORYSTATUS */

extern struct filterops fs_filtops;

extern struct filterops sig_filtops;

/* Timer filter */
static int filt_timerattach(struct knote *kn);
static void filt_timerdetach(struct knote *kn);
static int filt_timer(struct knote *kn, long hint);
static void filt_timertouch(struct knote *kn, struct kevent_internal_s *kev,
    long type);
static struct filterops timer_filtops = {
	.f_attach = filt_timerattach,
	.f_detach = filt_timerdetach,
	.f_event = filt_timer,
	.f_touch = filt_timertouch,
};

/* Helpers */
static void filt_timerexpire(void *knx, void *param1);
static int filt_timervalidate(struct knote *kn);
static void filt_timerupdate(struct knote *kn);
static void filt_timercancel(struct knote *kn);

#define	TIMER_RUNNING		0x1
#define	TIMER_CANCELWAIT	0x2

static lck_mtx_t _filt_timerlock;
static void filt_timerlock(void);
static void filt_timerunlock(void);

static zone_t knote_zone;

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
static void filt_usertouch(struct knote *kn, struct kevent_internal_s *kev,
    long type);
static struct filterops user_filtops = {
	.f_attach = filt_userattach,
	.f_detach = filt_userdetach,
	.f_event = filt_user,
	.f_touch = filt_usertouch,
};

/*
 * Table for all system-defined filters.
 */
static struct filterops *sysfilt_ops[] = {
	&file_filtops,			/* EVFILT_READ */
	&file_filtops,			/* EVFILT_WRITE */
#if 0
	&aio_filtops,			/* EVFILT_AIO */
#else
	&bad_filtops,			/* EVFILT_AIO */
#endif
	&file_filtops,			/* EVFILT_VNODE */
	&proc_filtops,			/* EVFILT_PROC */
	&sig_filtops,			/* EVFILT_SIGNAL */
	&timer_filtops,			/* EVFILT_TIMER */
	&machport_filtops,		/* EVFILT_MACHPORT */
	&fs_filtops,			/* EVFILT_FS */
	&user_filtops,			/* EVFILT_USER */
	&bad_filtops,			/* unused */
#if VM_PRESSURE_EVENTS
	&vm_filtops,			/* EVFILT_VM */
#else
	&bad_filtops,			/* EVFILT_VM */
#endif
	&file_filtops,			/* EVFILT_SOCK */
#if CONFIG_MEMORYSTATUS
	&memorystatus_filtops,  /* EVFILT_MEMORYSTATUS */
#else
	&bad_filtops,			/* EVFILT_MEMORYSTATUS */
#endif
};

/*
 * kqueue/note lock attributes and implementations
 *
 *	kqueues have locks, while knotes have use counts
 *	Most of the knote state is guarded by the object lock.
 *	the knote "inuse" count and status use the kqueue lock.
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
 *	If the knote is being dropped, we can't get
 *	a use reference, so just return with it
 *	still locked.
 *	- kq locked at entry
 *	- unlock on exit if we get the use reference
 */
static int
kqlock2knoteuse(struct kqueue *kq, struct knote *kn)
{
	if (kn->kn_status & KN_DROPPING)
		return (0);
	kn->kn_inuse++;
	kqunlock(kq);
	return (1);
}

/*
 * Convert a kq lock to a knote use referece,
 * but wait for attach and drop events to complete.
 *
 *	If the knote is being dropped, we can't get
 *	a use reference, so just return with it
 *	still locked.
 *	- kq locked at entry
 *	- kq always unlocked on exit
 */
static int
kqlock2knoteusewait(struct kqueue *kq, struct knote *kn)
{
	if ((kn->kn_status & (KN_DROPPING | KN_ATTACHING)) != 0) {
		kn->kn_status |= KN_USEWAIT;
		waitq_assert_wait64((struct waitq *)kq->kq_wqs,
				    CAST_EVENT64_T(&kn->kn_status),
				    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
		kqunlock(kq);
		thread_block(THREAD_CONTINUE_NULL);
		return (0);
	}
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
 *	The exit return indicates if the knote is
 *	still alive - but the kqueue lock is taken
 *	unconditionally.
 */
static int
knoteuse2kqlock(struct kqueue *kq, struct knote *kn)
{
	kqlock(kq);
	if (--kn->kn_inuse == 0) {
		if ((kn->kn_status & KN_ATTACHING) != 0) {
			kn->kn_status &= ~KN_ATTACHING;
		}
		if ((kn->kn_status & KN_USEWAIT) != 0) {
			kn->kn_status &= ~KN_USEWAIT;
			waitq_wakeup64_all((struct waitq *)kq->kq_wqs,
					   CAST_EVENT64_T(&kn->kn_status),
					   THREAD_AWAKENED,
					   WAITQ_ALL_PRIORITIES);
		}
	}
	return ((kn->kn_status & KN_DROPPING) == 0);
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

	oktodrop = ((kn->kn_status & (KN_DROPPING | KN_ATTACHING)) == 0);
	kn->kn_status &= ~KN_STAYQUEUED;
	kn->kn_status |= KN_DROPPING;
	if (oktodrop) {
		if (kn->kn_inuse == 0) {
			kqunlock(kq);
			return (oktodrop);
		}
	}
	kn->kn_status |= KN_USEWAIT;
	waitq_assert_wait64((struct waitq *)kq->kq_wqs,
			    CAST_EVENT64_T(&kn->kn_status),
			    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
	kqunlock(kq);
	thread_block(THREAD_CONTINUE_NULL);
	return (oktodrop);
}

/*
 * Release a knote use count reference.
 */
static void
knote_put(struct knote *kn)
{
	struct kqueue *kq = kn->kn_kq;

	kqlock(kq);
	if (--kn->kn_inuse == 0) {
		if ((kn->kn_status & KN_USEWAIT) != 0) {
			kn->kn_status &= ~KN_USEWAIT;
			waitq_wakeup64_all((struct waitq *)kq->kq_wqs,
					   CAST_EVENT64_T(&kn->kn_status),
					   THREAD_AWAKENED,
					   WAITQ_ALL_PRIORITIES);
		}
	}
	kqunlock(kq);
}

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
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;

	kqlock(kq);
	KNOTE_DETACH(&kq->kq_sel.si_note, kn);
	kqunlock(kq);
}

/*ARGSUSED*/
static int
filt_kqueue(struct knote *kn, __unused long hint)
{
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;

	kn->kn_data = kq->kq_count;
	return (kn->kn_data > 0);
}

static int
filt_procattach(struct knote *kn)
{
	struct proc *p;

	assert(PID_MAX < NOTE_PDATAMASK);

	if ((kn->kn_sfflags & (NOTE_TRACK | NOTE_TRACKERR | NOTE_CHILD)) != 0)
		return (ENOTSUP);

	p = proc_find(kn->kn_id);
	if (p == NULL) {
		return (ESRCH);
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
			return (EACCES);
		} while (0);

	proc_klist_lock();

	kn->kn_flags |= EV_CLEAR;	/* automatically set */
	kn->kn_ptr.p_proc = p;		/* store the proc handle */

	KNOTE_ATTACH(&p->p_klist, kn);

	proc_klist_unlock();

	proc_rele(p);

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
	/*
	 * Note: a lot of bits in hint may be obtained from the knote
	 * To free some of those bits, see <rdar://problem/12592988> Freeing up
	 * bits in hint for filt_proc
	 */
	/* hint is 0 when called from above */
	if (hint != 0) {
		u_int event;

		/* ALWAYS CALLED WITH proc_klist_lock when (hint != 0) */

		/*
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
				&& (kn->kn_kq->kq_p->p_pid != kn->kn_ptr.p_proc->p_ppid)) {
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
					switch (kn->kn_ptr.p_proc->p_lflag &
					    P_JETSAM_MASK) {
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
	}

	/* atomic check, no locking need when called from above */
	return (kn->kn_fflags != 0);
}

#if VM_PRESSURE_EVENTS
/*
 * Virtual memory kevents
 *
 * author: Matt Jacobson [matthew_jacobson@apple.com]
 */

static int
filt_vmattach(struct knote *kn)
{
	/*
	 * The note will be cleared once the information has been flushed to
	 * the client. If there is still pressure, we will be re-alerted.
	 */
	kn->kn_flags |= EV_CLEAR;
	return (vm_knote_register(kn));
}

static void
filt_vmdetach(struct knote *kn)
{
	vm_knote_unregister(kn);
}

static int
filt_vm(struct knote *kn, long hint)
{
	/* hint == 0 means this is just an alive? check (always true) */
	if (hint != 0) {
		const pid_t pid = (pid_t)hint;
		if ((kn->kn_sfflags & NOTE_VM_PRESSURE) &&
		    (kn->kn_kq->kq_p->p_pid == pid)) {
			kn->kn_fflags |= NOTE_VM_PRESSURE;
		}
	}

	return (kn->kn_fflags != 0);
}
#endif /* VM_PRESSURE_EVENTS */

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

		if (raw < now) {
			/* time has already passed */
			kn->kn_ext[0] = 0;
		} else {
			raw -= now;
			clock_absolutetime_interval_to_deadline(raw,
			    &kn->kn_ext[0]);
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
filt_timerupdate(struct knote *kn)
{
	/* if there's no interval, deadline is just in kn_ext[0] */
	if (kn->kn_sdata == 0)
		return;

	/* if timer hasn't fired before, fire in interval nsecs */
	if (kn->kn_ext[0] == 0) {
		clock_absolutetime_interval_to_deadline(kn->kn_sdata,
		    &kn->kn_ext[0]);
	} else {
		/*
		 * If timer has fired before, schedule the next pop
		 * relative to the last intended deadline.
		 *
		 * We could check for whether the deadline has expired,
		 * but the thread call layer can handle that.
		 */
		kn->kn_ext[0] += kn->kn_sdata;
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
		struct kqueue *kq = kn->kn_kq;
		waitq_wakeup64_all((struct waitq *)kq->kq_wqs,
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
	struct kqueue *kq = kn->kn_kq;
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
			waitq_assert_wait64((struct waitq *)kq->kq_wqs,
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

	callout = thread_call_allocate(filt_timerexpire, kn);
	if (NULL == callout)
		return (ENOMEM);

	filt_timerlock();
	error = filt_timervalidate(kn);
	if (error != 0) {
		filt_timerunlock();
		thread_call_free(callout);
		return (error);
	}

	kn->kn_hook = (void*)callout;
	kn->kn_hookid = 0;

	/* absolute=EV_ONESHOT */
	if (kn->kn_sfflags & NOTE_ABSOLUTE)
		kn->kn_flags |= EV_ONESHOT;

	filt_timerupdate(kn);
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

		thread_call_enter_delayed_with_leeway(callout, NULL,
				kn->kn_ext[0], kn->kn_ext[1], timer_flags);

		kn->kn_hookid |= TIMER_RUNNING;
	} else {
		/* fake immediate */
		kn->kn_data = 1;
	}

	filt_timerunlock();
	return (0);
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



static int
filt_timer(struct knote *kn, long hint)
{
	int result;

	if (hint) {
		/* real timer pop -- timer lock held by filt_timerexpire */
		kn->kn_data++;

		if (((kn->kn_hookid & TIMER_CANCELWAIT) == 0) &&
				((kn->kn_flags & EV_ONESHOT) == 0)) {

			/* evaluate next time to fire */
			filt_timerupdate(kn);

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

	/* user-query */
	filt_timerlock();

	result = (kn->kn_data != 0);

	filt_timerunlock();

	return (result);
}


/*
 * filt_timertouch - update knote with new user input
 *
 * Cancel and restart the timer based on new user data. When
 * the user picks up a knote, clear the count of how many timer
 * pops have gone off (in kn_data).
 */
static void
filt_timertouch(struct knote *kn, struct kevent_internal_s *kev, long type)
{
	int error;
	filt_timerlock();

	switch (type) {
	case EVENT_REGISTER:
		/* cancel current call */
		filt_timercancel(kn);

		/* recalculate deadline */
		kn->kn_sdata = kev->data;
		kn->kn_sfflags = kev->fflags;
		kn->kn_ext[0] = kev->ext[0];
		kn->kn_ext[1] = kev->ext[1];

		error = filt_timervalidate(kn);
		if (error) {
			/* no way to report error, so mark it in the knote */
			kn->kn_flags |= EV_ERROR;
			kn->kn_data = error;
			break;
		}

		/* start timer if necessary */
		filt_timerupdate(kn);

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

		break;

	case EVENT_PROCESS:
		/* reset the timer pop count in kn_data */
		*kev = kn->kn_kevent;
		kev->ext[0] = 0;
		kn->kn_data = 0;
		if (kn->kn_flags & EV_CLEAR)
			kn->kn_fflags = 0;
		break;
	default:
		panic("%s: - invalid type (%ld)", __func__, type);
		break;
	}

	filt_timerunlock();
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

static int
filt_userattach(struct knote *kn)
{
	/* EVFILT_USER knotes are not attached to anything in the kernel */
	kn->kn_hook = NULL;
	if (kn->kn_fflags & NOTE_TRIGGER) {
		kn->kn_hookid = 1;
	} else {
		kn->kn_hookid = 0;
	}
	return (0);
}

static void
filt_userdetach(__unused struct knote *kn)
{
	/* EVFILT_USER knotes are not attached to anything in the kernel */
}

static int
filt_user(struct knote *kn, __unused long hint)
{
	return (kn->kn_hookid);
}

static void
filt_usertouch(struct knote *kn, struct kevent_internal_s *kev, long type)
{
	uint32_t ffctrl;
	switch (type) {
	case EVENT_REGISTER:
		if (kev->fflags & NOTE_TRIGGER) {
			kn->kn_hookid = 1;
		}

		ffctrl = kev->fflags & NOTE_FFCTRLMASK;
		kev->fflags &= NOTE_FFLAGSMASK;
		switch (ffctrl) {
		case NOTE_FFNOP:
			break;
		case NOTE_FFAND:
			OSBitAndAtomic(kev->fflags, &kn->kn_sfflags);
			break;
		case NOTE_FFOR:
			OSBitOrAtomic(kev->fflags, &kn->kn_sfflags);
			break;
		case NOTE_FFCOPY:
			kn->kn_sfflags = kev->fflags;
			break;
		}
		kn->kn_sdata = kev->data;
		break;
	case EVENT_PROCESS:
		*kev = kn->kn_kevent;
		kev->fflags = (volatile UInt32)kn->kn_sfflags;
		kev->data = kn->kn_sdata;
		if (kn->kn_flags & EV_CLEAR) {
			kn->kn_hookid = 0;
			kn->kn_data = 0;
			kn->kn_fflags = 0;
		}
		break;
	default:
		panic("%s: - invalid type (%ld)", __func__, type);
		break;
	}
}

/*
 * JMM - placeholder for not-yet-implemented filters
 */
static int
filt_badattach(__unused struct knote *kn)
{
	return (ENOTSUP);
}

struct kqueue *
kqueue_alloc(struct proc *p)
{
	struct filedesc *fdp = p->p_fd;
	struct kqueue *kq;

	MALLOC_ZONE(kq, struct kqueue *, sizeof (struct kqueue), M_KQUEUE,
	    M_WAITOK);
	if (kq != NULL) {
		struct waitq_set *wqs;

		wqs = waitq_set_alloc(SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST | SYNC_POLICY_DISABLE_IRQ);
		if (wqs != NULL) {
			bzero(kq, sizeof (struct kqueue));
			lck_spin_init(&kq->kq_lock, kq_lck_grp, kq_lck_attr);
			TAILQ_INIT(&kq->kq_head);
			kq->kq_wqs = wqs;
			kq->kq_p = p;
		} else {
			FREE_ZONE(kq, sizeof (struct kqueue), M_KQUEUE);
			kq = NULL;
		}
	}

	if (fdp->fd_knlistsize < 0) {
		proc_fdlock(p);
		if (fdp->fd_knlistsize < 0)
			fdp->fd_knlistsize = 0;	/* this process has had a kq */
		proc_fdunlock(p);
	}

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
			if (kq == kn->kn_kq) {
				kqlock(kq);
				proc_fdunlock(p);
				/* drop it ourselves or wait */
				if (kqlock2knotedrop(kq, kn)) {
					kn->kn_fop->f_detach(kn);
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
				if (kq == kn->kn_kq) {
					kqlock(kq);
					proc_fdunlock(p);
					/* drop it ourselves or wait */
					if (kqlock2knotedrop(kq, kn)) {
						kn->kn_fop->f_detach(kn);
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
	 * waitq_set_free() clears all preposts and also remove the KQ's
	 * waitq set from any select sets to which it may belong.
	 */
	waitq_set_free(kq->kq_wqs);
	kq->kq_wqs = NULL;
	lck_spin_destroy(&kq->kq_lock, kq_lck_grp);
	FREE_ZONE(kq, sizeof (struct kqueue), M_KQUEUE);
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

	kq = kqueue_alloc(p);
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
		kevp->udata = kevqos.udata;
		kevp->fflags = kevqos.fflags;
		kevp->data = kevqos.data;
		kevp->ext[0] = kevqos.ext[0];
		kevp->ext[1] = kevqos.ext[1];
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

	if (flags & KEVENT_FLAG_LEGACY32) {
		assert((flags & KEVENT_FLAG_STACK_EVENTS) == 0);

		if (IS_64BIT_PROCESS(p)) {
			struct user64_kevent kev64;

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
			advance = sizeof (kev64);
			error = copyout((caddr_t)&kev64, addr, advance);
		} else {
			struct user32_kevent kev32;

			kev32.ident = (uint32_t)kevp->ident;
			kev32.filter = kevp->filter;
			kev32.flags = kevp->flags;
			kev32.fflags = kevp->fflags;
			kev32.data = (int32_t)kevp->data;
			kev32.udata = kevp->udata;
			advance = sizeof (kev32);
			error = copyout((caddr_t)&kev32, addr, advance);
		}
	} else if (flags & KEVENT_FLAG_LEGACY64) {
		struct kevent64_s kev64;

		advance = sizeof (struct kevent64_s);
		if (flags & KEVENT_FLAG_STACK_EVENTS) {
			addr -= advance;
		}
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
	
		bzero(&kevqos, sizeof (struct kevent_qos_s));
		advance = sizeof (struct kevent_qos_s);
		if (flags & KEVENT_FLAG_STACK_EVENTS) {
			addr -= advance;
		}
		kevqos.ident = kevp->ident;
		kevqos.filter = kevp->filter;
		kevqos.flags = kevp->flags;
		kevqos.fflags = kevp->fflags;
		kevqos.data = (int64_t) kevp->data;
		kevqos.udata = kevp->udata;
		kevqos.ext[0] = kevp->ext[0];
		kevqos.ext[1] = kevp->ext[1];
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

/*
 * kevent_continue - continue a kevent syscall after blocking
 *
 *	assume we inherit a use count on the kq fileglob.
 */

static void
kevent_continue(__unused struct kqueue *kq, void *data, int error)
{
	struct _kevent *cont_args;
	struct fileproc *fp;
	int32_t *retval;
	int noutputs;
	int fd;
	struct proc *p = current_proc();

	cont_args = (struct _kevent *)data;
	noutputs = cont_args->eventout;
	retval = cont_args->retval;
	fd = cont_args->fd;
	fp = cont_args->fp;

	if (fp != NULL)
		fp_drop(p, fd, fp, 0);

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
	user_size_t usize = 0;
	user_size_t ssize;
	int error;

	/* restrict to user flags */
	uap->flags &= KEVENT_FLAG_USER;

	if (uap->data_available) {
		if (!IS_64BIT_PROCESS(p)) {
			uint32_t csize;

			error = copyin(uap->data_available, (caddr_t)&csize, sizeof(csize));
			if (error)
				return error;
			usize = csize;
		} else {
			uint64_t csize;
			error = copyin(uap->data_available, (caddr_t)&csize, sizeof(csize));
			if (error)
				return error;
			usize = csize;
		}
	}
	ssize = usize;

	error = kevent_internal(p,
				uap->fd,
				uap->changelist, uap->nchanges,
				uap->eventlist,	uap->nevents,
				uap->data_out, &usize,
				uap->flags,
				0ULL,
				kevent_continue,
				retval);

	if (error == 0 && uap->data_available && usize != ssize) {
		if (!IS_64BIT_PROCESS(p)) {
			uint32_t csize = (uint32_t)usize;

			error = copyout((caddr_t)&csize, uap->data_available, sizeof(csize));
		} else {
			error = copyout((caddr_t)&usize, uap->data_available, sizeof(usize));
		}
	}
	return error;
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
			       data_out, data_available,
			       flags,
			       0ULL,
			       NULL,
			       retval);
}
 
static int
kevent_internal(struct proc *p, 
		int fd,
		user_addr_t changelist, int nchanges,
		user_addr_t ueventlist, int nevents,
		user_addr_t data_out, user_size_t *data_available,
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
	int error = 0, noutputs;
	struct timeval atv;

#if 1
	/* temporarily ignore these fields */
	(void)data_out;
	(void)data_available;
#endif

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
	if (flags & KEVENT_FLAG_IMMEDIATE) {
		getmicrouptime(&atv);
	} else if (utimeout != USER_ADDR_NULL) {
		struct timeval rtv;
		if (IS_64BIT_PROCESS(p)) {
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

	if (flags & KEVENT_FLAG_WORKQ) {
		/*
		 * use the private kq associated with the proc workq.
		 * Just being a thread within the process (and not
		 * being the exit/exec thread) is enough to hold a
		 * reference on this special kq.
		 */
		kq = p->p_wqkqueue;
		if (kq == NULL) {
			struct kqueue *alloc_kq = kqueue_alloc(p);
			if (alloc_kq == NULL)
				return ENOMEM;

			proc_fdlock(p);
			if (p->p_wqkqueue == NULL) {
				/*
				 * The kq is marked as special -
				 * with unique interactions with
				 * the workq for this process.
				 */
				alloc_kq->kq_state |= KQ_WORKQ;
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

	/* each kq should only be used for events of one type */
	kqlock(kq);
	if (kq->kq_state & (KQ_KEV32 | KQ_KEV64 | KQ_KEV_QOS)) {
		if (flags & KEVENT_FLAG_LEGACY32) {
			if ((kq->kq_state & KQ_KEV32) == 0) {
				error = EINVAL;
				kqunlock(kq);
				goto errorout;
			}
		} else if (kq->kq_state & KQ_KEV32) {
			error = EINVAL;
			kqunlock(kq);
			goto errorout;
		}
	} else if (flags & KEVENT_FLAG_LEGACY32) {
		kq->kq_state |= KQ_KEV32;
	} else {
		/* JMM - set KQ_KEVQOS when we are ready for exclusive */
		kq->kq_state |= KQ_KEV64;
	}
	kqunlock(kq);

	/* register all the change requests the user provided... */
	noutputs = 0;
	while (nchanges > 0 && error == 0) {
		error = kevent_copyin(&changelist, &kev, p, flags);
		if (error)
			break;

		kev.flags &= ~EV_SYSFLAGS;
		error = kevent_register(kq, &kev, p);
		if ((error || (kev.flags & EV_RECEIPT)) && nevents > 0) {
			kev.flags = EV_ERROR;
			kev.data = error;
			error = kevent_copyout(&kev, &ueventlist, p, flags);
			if (error == 0) {
				nevents--;
				noutputs++;
			}
		}
		nchanges--;
	}

	/* short-circuit the scan if we only want error events */
	if (flags & KEVENT_FLAG_ERROR_EVENTS) 
		nevents = 0;

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
		cont_args->eventflags = flags;

		error = kqueue_scan(kq, kevent_callback,
		                    continuation, cont_args,
		                    &atv, p);

		noutputs = cont_args->eventout;
	}

	/* don't restart after signals... */
	if (error == ERESTART)
		error = EINTR;
	else if (error == EWOULDBLOCK)
		error = 0;
	if (error == 0)
		*retval = noutputs;
errorout:
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
			       cont_args->eventflags);

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

int
kevent_register(struct kqueue *kq, struct kevent_internal_s *kev,
    __unused struct proc *ctxp)
{
	struct proc *p = kq->kq_p;
	struct filedesc *fdp = p->p_fd;
	struct filterops *fops;
	struct fileproc *fp = NULL;
	struct knote *kn = NULL;
	struct klist *list;
	int error = 0;

	if (kev->filter < 0) {
		if (kev->filter + EVFILT_SYSCOUNT < 0)
			return (EINVAL);
		fops = sysfilt_ops[~kev->filter];	/* to 0-base index */
	} else {
		return (EINVAL);
	}

restart:
	/* this iocount needs to be dropped if it is not registered */
	list = NULL;
	proc_fdlock(p);

	/* 
	 * determine where to look for the knote
	 */
	if (fops->f_isfd) {
		if ((error = fp_lookup(p, kev->ident, &fp, 1)) != 0) {
			proc_fdunlock(p);
			return (error);
		}
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
			if (kq == kn->kn_kq &&
			    kev->ident == kn->kn_id && 
			    kev->filter == kn->kn_filter) {
				if (kev->flags & EV_UDATA_SPECIFIC) {
					if ((kn->kn_flags & EV_UDATA_SPECIFIC) &&
					    kev->udata == kn->kn_udata) {
						break; /* matching udata-specific knote */
					}
				} else if ((kn->kn_flags & EV_UDATA_SPECIFIC) == 0) {
					break; /* matching non-udata-specific knote */
				}
			}
		}
	}

	/*
	 * kn now contains the matching knote, or NULL if no match
	 */
	if (kn == NULL) {
		if ((kev->flags & (EV_ADD|EV_DELETE)) == EV_ADD) {
			kn = knote_alloc();
			if (kn == NULL) {
				proc_fdunlock(p);
				error = ENOMEM;
				goto done;
			}
			kn->kn_fp = fp;
			kn->kn_kq = kq;
			kn->kn_tq = &kq->kq_head;
			kn->kn_fop = fops;
			kn->kn_sfflags = kev->fflags;
			kn->kn_sdata = kev->data;
			kev->fflags = 0;
			kev->data = 0;
			kn->kn_kevent = *kev;
			kn->kn_inuse = 1;  /* for f_attach() */
			kn->kn_status = KN_ATTACHING;

			/* before anyone can find it */
			if (kev->flags & EV_DISABLE)
				kn->kn_status |= KN_DISABLED;

			error = knote_fdpattach(kn, fdp, p);
			proc_fdunlock(p);

			if (error) {
				knote_free(kn);
				goto done;
			}

			/*
			 * apply reference count to knote structure, and
			 * do not release it at the end of this routine.
			 */
			fp = NULL;

			error = fops->f_attach(kn);

			kqlock(kq);

			if (error != 0) {
				/*
				 * Failed to attach correctly, so drop.
				 * All other possible users/droppers
				 * have deferred to us.
				 */
				kn->kn_status |= KN_DROPPING;
				kqunlock(kq);
				knote_drop(kn, p);
				goto done;
			} else if (kn->kn_status & KN_DROPPING) {
				/*
				 * Attach succeeded, but someone else
				 * deferred their drop - now we have
				 * to do it for them (after detaching).
				 */
				kqunlock(kq);
				kn->kn_fop->f_detach(kn);
				knote_drop(kn, p);
				goto done;
			}
			kn->kn_status &= ~KN_ATTACHING;
			kqunlock(kq);
		} else {
			proc_fdunlock(p);
			error = ENOENT;
			goto done;
		}
	} else {
		/* existing knote - get kqueue lock */
		kqlock(kq);
		proc_fdunlock(p);

		if (kev->flags & EV_DELETE) {
			if ((kev->flags & EV_ENABLE) == 0 &&
			    (kev->flags & EV_DISPATCH2) == EV_DISPATCH2 &&
			    (kn->kn_status & KN_DISABLED) == KN_DISABLED) {
				/* mark for deferred drop */
				kn->kn_status |= KN_DEFERDROP;
				kqunlock(kq);
				error = EINPROGRESS;
			} else {
				knote_dequeue(kn);
				kn->kn_status |= KN_DISABLED;
				if (kqlock2knotedrop(kq, kn)) {
					kn->kn_fop->f_detach(kn);
					knote_drop(kn, p);
				} else {
					/* pretend we didn't find it */
					error = ENOENT;
				}
			}
			goto done;
		}

		/* update status flags for existing knote */
		if (kev->flags & EV_DISABLE) {
			knote_dequeue(kn);
			kn->kn_status |= KN_DISABLED;

		} else if ((kev->flags & EV_ENABLE) &&
			   (kn->kn_status & KN_DISABLED)) {
			kn->kn_status &= ~KN_DISABLED;

			/* handle deferred drop */
			if (kn->kn_status & KN_DEFERDROP) {
				kn->kn_status &= ~KN_DEFERDROP;
				kn->kn_flags |= (EV_DELETE | EV_ONESHOT);
				knote_activate(kn, 0);
				kqunlock(kq);
				goto done;
			}

			if (kn->kn_status & KN_ACTIVE) {
				/* force re-activate if previously active */
				knote_activate(kn, 1);
			}
		}

		/*
		 * The user may change some filter values after the
		 * initial EV_ADD, but doing so will not reset any
		 * filter which have already been triggered.
		 */
		kn->kn_kevent.udata = kev->udata;
		if (fops->f_isfd || fops->f_touch == NULL) {
			kn->kn_sfflags = kev->fflags;
			kn->kn_sdata = kev->data;
		}

		/*
		 * If somebody is in the middle of dropping this
		 * knote - go find/insert a new one.  But we have
		 * wait for this one to go away first. Attaches
		 * running in parallel may also drop/modify the
		 * knote.  Wait for those to complete as well and
		 * then start over if we encounter one.
		 */
		if (!kqlock2knoteusewait(kq, kn)) {
			/* kqueue, proc_fdlock both unlocked */
			goto restart;
		}

		/*
		 * Call touch routine to notify filter of changes
		 * in filter values.
		 */
		if (!fops->f_isfd && fops->f_touch != NULL)
			fops->f_touch(kn, kev, EVENT_REGISTER);
	}
	/* still have use ref on knote */

	/*
	 * Invoke the filter routine to see if it should be enqueued now.
	 */
#if 0
	if (kn->kn_fop->f_event(kn, 0)) {
#else
	/*
	 * JMM - temporary workaround until rdar://problem/19986199 
	 * This potentially results in extra wakeups for KN_STAYQUEUED event types,
	 * but waking up only truly active ones (yet trying below to determine
	 * active status, by invoking the filter routine, is having side-effects).
	 */
	if ((kn->kn_status & KN_STAYQUEUED) || kn->kn_fop->f_event(kn, 0)) {
#endif
		if (knoteuse2kqlock(kq, kn))
			knote_activate(kn, (kn->kn_status & KN_STAYQUEUED));
		kqunlock(kq);
	} else {
		knote_put(kn);
	}

done:
	if (fp != NULL)
		fp_drop(p, kev->ident, fp, 0);
	return (error);
}


/*
 * knote_process - process a triggered event
 *
 *	Validate that it is really still a triggered event
 *	by calling the filter routines (if necessary).  Hold
 *	a use reference on the knote to avoid it being detached.
 *	If it is still considered triggered, invoke the callback
 *	routine provided and move it to the provided inprocess
 *	queue.
 *
 *	caller holds a reference on the kqueue.
 *	kqueue locked on entry and exit - but may be dropped
 */
static int
knote_process(struct knote *kn,
    kevent_callback_t callback,
    void *data,
    struct kqtailq *inprocessp,
    struct proc *p)
{
	struct kqueue *kq = kn->kn_kq;
	struct kevent_internal_s kev;
	int touch;
	int result;
	int error;

	/*
	 * Determine the kevent state we want to return.
	 *
	 * Some event states need to be revalidated before returning
	 * them, others we take the snapshot at the time the event
	 * was enqueued.
	 *
	 * Events with non-NULL f_touch operations must be touched.
	 * Triggered events must fill in kev for the callback.
	 *
	 * Convert our lock to a use-count and call the event's
	 * filter routine(s) to update.
	 */
	if ((kn->kn_status & KN_DISABLED) != 0) {
		result = 0;
		touch = 0;
	} else {
		int revalidate;

		result = 1;
		revalidate = ((kn->kn_status & KN_STAYQUEUED) != 0 ||
		    (kn->kn_flags & EV_ONESHOT) == 0);
		touch = (!kn->kn_fop->f_isfd && kn->kn_fop->f_touch != NULL);

		if (revalidate || touch) {
			if (revalidate)
				knote_deactivate(kn);

			/* call the filter/touch routines with just a ref */
			if (kqlock2knoteuse(kq, kn)) {
				/* if we have to revalidate, call the filter */
				if (revalidate) {
					result = kn->kn_fop->f_event(kn, 0);
				}

				/*
				 * capture the kevent data - using touch if
				 * specified
				 */
				if (result && touch) {
					kn->kn_fop->f_touch(kn, &kev,
					    EVENT_PROCESS);
				}
				if (result && (kn->kn_status & KN_TOUCH))
					kn->kn_fop->f_touch(kn, &kev,
					    EVENT_PROCESS);

				/*
				 * convert back to a kqlock - bail if the knote
				 * went away
				 */
				if (!knoteuse2kqlock(kq, kn)) {
					return (EJUSTRETURN);
				} else if (result) {
					/*
					 * if revalidated as alive, make sure
					 * it's active
					 */
					knote_activate(kn, 0);

					/*
					 * capture all events that occurred
					 * during filter
					 */
					if (!touch) {
						kev = kn->kn_kevent;
					}

				} else if ((kn->kn_status & KN_STAYQUEUED) == 0) {
					/*
					 * was already dequeued, so just bail on
					 * this one
					 */
					return (EJUSTRETURN);
				}
			} else {
				return (EJUSTRETURN);
			}
		} else {
			kev = kn->kn_kevent;
		}
	}

	/* move knote onto inprocess queue */
	assert(kn->kn_tq == &kq->kq_head);
	TAILQ_REMOVE(&kq->kq_head, kn, kn_tqe);
	kn->kn_tq = inprocessp;
	TAILQ_INSERT_TAIL(inprocessp, kn, kn_tqe);

	/*
	 * Determine how to dispatch the knote for future event handling.
	 * not-fired: just return (do not callout).
	 * One-shot: If dispatch2, enter deferred-delete mode (unless this is
	 *           is the deferred delete event delivery itself).  Otherwise,
	 *           deactivate and drop it.
	 * Clear: deactivate and clear the state.
	 * Dispatch: don't clear state, just deactivate it and mark it disabled.
	 * All others: just leave where they are.
	 */

	if (result == 0) {
		return (EJUSTRETURN);
	} else if ((kn->kn_flags & EV_ONESHOT) != 0) {
		knote_deactivate(kn);
		if ((kn->kn_flags & (EV_DISPATCH2|EV_DELETE)) == EV_DISPATCH2) {
			/* defer dropping non-delete oneshot dispatch2 events */
			kn->kn_status |= (KN_DISABLED | KN_DEFERDROP);
			kqunlock(kq);
		} else if (kqlock2knotedrop(kq, kn)) {
			kn->kn_fop->f_detach(kn);
			knote_drop(kn, p);
		}
	} else if ((kn->kn_flags & (EV_CLEAR | EV_DISPATCH)) != 0) {
		if ((kn->kn_flags & EV_DISPATCH) != 0) {
			/* deactivate and disable all dispatch knotes */
			knote_deactivate(kn);
			kn->kn_status |= KN_DISABLED;
		} else if (!touch || kn->kn_fflags == 0) {
			/* only deactivate if nothing since the touch */
			knote_deactivate(kn);
		}
		if (!touch && (kn->kn_flags & EV_CLEAR) != 0) {
			/* manually clear non-touch knotes */
			kn->kn_data = 0;
			kn->kn_fflags = 0;
		}
		kqunlock(kq);
	} else {
		/*
		 * leave on inprocess queue.  We'll
		 * move all the remaining ones back
		 * the kq queue and wakeup any
		 * waiters when we are done.
		 */
		kqunlock(kq);
	}

	/* callback to handle each event as we find it */
	error = (callback)(kq, &kev, data);

	kqlock(kq);
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
kqueue_begin_processing(struct kqueue *kq)
{
	for (;;) {
		if (kq->kq_count == 0) {
			return (-1);
		}

		/* if someone else is processing the queue, wait */
		if (kq->kq_nprocess != 0) {
			waitq_assert_wait64((struct waitq *)kq->kq_wqs,
					    CAST_EVENT64_T(&kq->kq_nprocess),
					    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
			kq->kq_state |= KQ_PROCWAIT;
			kqunlock(kq);
			thread_block(THREAD_CONTINUE_NULL);
			kqlock(kq);
		} else {
			kq->kq_nprocess = 1;
			return (0);
		}
	}
}

/*
 * Called with kqueue lock held.
 */
static void
kqueue_end_processing(struct kqueue *kq)
{
	kq->kq_nprocess = 0;
	if (kq->kq_state & KQ_PROCWAIT) {
		kq->kq_state &= ~KQ_PROCWAIT;
		waitq_wakeup64_all((struct waitq *)kq->kq_wqs,
				   CAST_EVENT64_T(&kq->kq_nprocess),
				   THREAD_AWAKENED,
				   WAITQ_ALL_PRIORITIES);
	}
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
    void *data,
    int *countp,
    struct proc *p)
{
	struct kqtailq inprocess;
	struct knote *kn;
	int nevents;
	int error;

	TAILQ_INIT(&inprocess);

	if (kqueue_begin_processing(kq) == -1) {
		*countp = 0;
		/* Nothing to process */
		return (0);
	}

	/*
	 * Clear any pre-posted status from previous runs, so we
	 * only detect events that occur during this run.
	 */
	waitq_set_clear_preposts(kq->kq_wqs);

	/*
	 * loop through the enqueued knotes, processing each one and
	 * revalidating those that need it. As they are processed,
	 * they get moved to the inprocess queue (so the loop can end).
	 */
	error = 0;
	nevents = 0;

	while (error == 0 &&
	    (kn = TAILQ_FIRST(&kq->kq_head)) != NULL) {
		error = knote_process(kn, callback, data, &inprocess, p);
		if (error == EJUSTRETURN)
			error = 0;
		else
			nevents++;
	}

	/*
	 * With the kqueue still locked, move any knotes
	 * remaining on the inprocess queue back to the
	 * kq's queue and wake up any waiters.
	 */
	while ((kn = TAILQ_FIRST(&inprocess)) != NULL) {
		assert(kn->kn_tq == &inprocess);
		TAILQ_REMOVE(&inprocess, kn, kn_tqe);
		kn->kn_tq = &kq->kq_head;
		TAILQ_INSERT_TAIL(&kq->kq_head, kn, kn_tqe);
	}

	kqueue_end_processing(kq);

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
	int error;
	int count;

	/* convert the (previous) wait_result to a proper error */
	switch (wait_result) {
	case THREAD_AWAKENED:
		kqlock(kq);
		error = kqueue_process(kq, cont_args->call, cont_args, &count,
		    current_proc());
		if (error == 0 && count == 0) {
			waitq_assert_wait64((struct waitq *)kq->kq_wqs,
					    KQ_EVENT, THREAD_ABORTSAFE,
					    cont_args->deadline);
			kq->kq_state |= KQ_SLEEP;
			kqunlock(kq);
			thread_block_parameter(kqueue_scan_continue, kq);
			/* NOTREACHED */
		}
		kqunlock(kq);
		break;
	case THREAD_TIMED_OUT:
		error = EWOULDBLOCK;
		break;
	case THREAD_INTERRUPTED:
		error = EINTR;
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
	    void *data,
	    struct timeval *atvp,
	    struct proc *p)
{
	thread_continue_t cont = THREAD_CONTINUE_NULL;
	uint64_t deadline;
	int error;
	int first;

	assert(callback != NULL);

	first = 1;
	for (;;) {
		wait_result_t wait_result;
		int count;

		/*
		 * Make a pass through the kq to find events already
		 * triggered.
		 */
		kqlock(kq);
		error = kqueue_process(kq, callback, data, &count, p);
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
				cont_args->data = data;
				cont = kqueue_scan_continue;
			}
		}

		/* go ahead and wait */
		waitq_assert_wait64_leeway((struct waitq *)kq->kq_wqs,
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
			return (EWOULDBLOCK);
		case THREAD_INTERRUPTED:
			return (EINTR);
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
	struct knote *kn;
	struct kqtailq inprocessq;
	int retnum = 0;

	if (which != FREAD)
		return (0);

	TAILQ_INIT(&inprocessq);

	kqlock(kq);
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
		waitq_link((struct waitq *)kq->kq_wqs, ut->uu_wqset,
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
		memcpy(wq_link_id, (void *)&(kq->kq_wqs), sizeof(void *));
	}

	if (kqueue_begin_processing(kq) == -1) {
		kqunlock(kq);
		return (0);
	}

	if (kq->kq_count != 0) {
		/*
		 * there is something queued - but it might be a
		 * KN_STAYQUEUED knote, which may or may not have
		 * any events pending.  So, we have to walk the
		 * list of knotes to see, and peek at the stay-
		 * queued ones to be really sure.
		 */
		while ((kn = (struct knote *)TAILQ_FIRST(&kq->kq_head)) != NULL) {
			if ((kn->kn_status & KN_STAYQUEUED) == 0) {
				retnum = 1;
				goto out;
			}

			TAILQ_REMOVE(&kq->kq_head, kn, kn_tqe);
			TAILQ_INSERT_TAIL(&inprocessq, kn, kn_tqe);

			if (kqlock2knoteuse(kq, kn)) {
				unsigned peek;

				peek = kn->kn_fop->f_peek(kn);
				if (knoteuse2kqlock(kq, kn)) {
					if (peek > 0) {
						retnum = 1;
						goto out;
					}
				} else {
					retnum = 0;
				}
			}
		}
	}

out:
	/* Return knotes to active queue */
	while ((kn = TAILQ_FIRST(&inprocessq)) != NULL) {
		TAILQ_REMOVE(&inprocessq, kn, kn_tqe);
		kn->kn_tq = &kq->kq_head;
		TAILQ_INSERT_TAIL(&kq->kq_head, kn, kn_tqe);
	}

	kqueue_end_processing(kq);
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
	struct kqueue *kq = (struct kqueue *)fg->fg_data;

	kqueue_dealloc(kq);
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
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;
	struct kqueue *parentkq = kn->kn_kq;

	if (parentkq == kq ||
	    kn->kn_filter != EVFILT_READ)
		return (1);

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
		return (1);
	} else {
		/* set parent level appropriately */
		if (parentkq->kq_level == 0)
			parentkq->kq_level = 2;
		if (parentkq->kq_level < kq->kq_level + 1)
			parentkq->kq_level = kq->kq_level + 1;
		kqunlock(parentkq);

		kn->kn_fop = &kqread_filtops;
		kqlock(kq);
		KNOTE_ATTACH(&kq->kq_sel.si_note, kn);
		/* indicate nesting in child, if needed */
		if (kq->kq_level == 0)
			kq->kq_level = 1;
		kqunlock(kq);
		return (0);
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
	kqlock(kq);
	kqueue_wakeup(kq, 1);
	kqunlock(kq);
	return (0);
}

/*ARGSUSED*/
int
kqueue_stat(struct kqueue *kq, void *ub, int isstat64, proc_t p)
{
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
 * Called with the kqueue locked
 */
static void
kqueue_wakeup(struct kqueue *kq, int closed)
{
	wait_result_t res = THREAD_NOT_WAITING;

	if ((kq->kq_state & (KQ_SLEEP | KQ_SEL)) != 0 || kq->kq_nprocess > 0) {
		kq->kq_state &= ~(KQ_SLEEP | KQ_SEL);
		res = waitq_wakeup64_all((struct waitq *)kq->kq_wqs, KQ_EVENT,
					 (closed) ? THREAD_INTERRUPTED : THREAD_AWAKENED,
					 WAITQ_ALL_PRIORITIES);
	}

	/* request additional workq threads if appropriate */
	if (res == THREAD_NOT_WAITING && (kq->kq_state & KQ_WORKQ) &&
	    pthread_functions != NULL && pthread_functions->workq_reqthreads != NULL) {
		/*
		 * The special workq kq should be accumulating the counts of
		 * queued sources on a pthread_priority_t basis and we should
		 * be providing that here.  For now, just hard-code a single
		 * entry request at a fixed (default) QOS.
		 */
		struct workq_reqthreads_req_s request = { 
		                      .priority = 0x020004ff,  /* legacy event manager */
							  .count = kq->kq_count };
		thread_t wqthread;

		wqthread = (*pthread_functions->workq_reqthreads)(kq->kq_p, 1, &request);
		assert(wqthread == THREAD_NULL);
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
 *	too - just in case.
 */
void
knote(struct klist *list, long hint)
{
	struct knote *kn;

	SLIST_FOREACH(kn, list, kn_selnext) {
		struct kqueue *kq = kn->kn_kq;

		kqlock(kq);
		if (kqlock2knoteuse(kq, kn)) {
			int result;

			/* call the event with only a use count */
			result = kn->kn_fop->f_event(kn, hint);

			/* if its not going away and triggered */
			if (knoteuse2kqlock(kq, kn) && result)
				knote_activate(kn, 0);
			/* lock held again */
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
 * For a given knote, link a provided wait queue directly with the kqueue.
 * Wakeups will happen via recursive wait queue support.  But nothing will move
 * the knote to the active list at wakeup (nothing calls knote()).  Instead,
 * we permanently enqueue them here.
 *
 * kqueue and knote references are held by caller.
 *
 * caller provides the wait queue link structure.
 */
int
knote_link_waitq(struct knote *kn, struct waitq *wq, uint64_t *reserved_link)
{
	struct kqueue *kq = kn->kn_kq;
	kern_return_t kr;

	kr = waitq_link(wq, kq->kq_wqs, WAITQ_SHOULD_LOCK, reserved_link);
	if (kr == KERN_SUCCESS) {
		knote_markstayqueued(kn);
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
	struct kqueue *kq = kn->kn_kq;
	kern_return_t kr;

	kr = waitq_unlink(wq, kq->kq_wqs);
	knote_clearstayqueued(kn);
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
knote_fdclose(struct proc *p, int fd)
{
	struct filedesc *fdp = p->p_fd;
	struct klist *list;
	struct knote *kn;

	list = &fdp->fd_knlist[fd];
	while ((kn = SLIST_FIRST(list)) != NULL) {
		struct kqueue *kq = kn->kn_kq;

		if (kq->kq_p != p)
			panic("%s: proc mismatch (kq->kq_p=%p != p=%p)",
			    __func__, kq->kq_p, p);

		kqlock(kq);
		proc_fdunlock(p);

		/*
		 * Convert the lock to a drop ref.
		 * If we get it, go ahead and drop it.
		 * Otherwise, we waited for it to
		 * be dropped by the other guy, so
		 * it is safe to move on in the list.
		 */
		if (kqlock2knotedrop(kq, kn)) {
			kn->kn_fop->f_detach(kn);
			knote_drop(kn, p);
		}

		proc_fdlock(p);

		/* the fd tables may have changed - start over */
		list = &fdp->fd_knlist[fd];
	}
}

/* proc_fdlock held on entry (and exit) */
static int
knote_fdpattach(struct knote *kn, struct filedesc *fdp, struct proc *p)
{
	struct klist *list = NULL;

	if (! kn->kn_fop->f_isfd) {
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
 * should be called at spl == 0, since we don't want to hold spl
 * while calling fdrop and free.
 */
static void
knote_drop(struct knote *kn, __unused struct proc *ctxp)
{
	struct kqueue *kq = kn->kn_kq;
	struct proc *p = kq->kq_p;
	struct filedesc *fdp = p->p_fd;
	struct klist *list;
	int needswakeup;

	proc_fdlock(p);
	if (kn->kn_fop->f_isfd)
		list = &fdp->fd_knlist[kn->kn_id];
	else
		list = &fdp->fd_knhash[KN_HASH(kn->kn_id, fdp->fd_knhashmask)];

	SLIST_REMOVE(list, kn, knote, kn_link);
	kqlock(kq);
	knote_dequeue(kn);
	needswakeup = (kn->kn_status & KN_USEWAIT);
	kqunlock(kq);
	proc_fdunlock(p);

	if (needswakeup)
		waitq_wakeup64_all((struct waitq *)kq->kq_wqs,
				   CAST_EVENT64_T(&kn->kn_status),
				   THREAD_AWAKENED,
				   WAITQ_ALL_PRIORITIES);

	if (kn->kn_fop->f_isfd)
		fp_drop(p, kn->kn_id, kn->kn_fp, 0);

	knote_free(kn);
}

/* called with kqueue lock held */
static void
knote_activate(struct knote *kn, int force)
{
	struct kqueue *kq = kn->kn_kq;

	if (!force && (kn->kn_status & KN_ACTIVE))
		return;

	kn->kn_status |= KN_ACTIVE;
	knote_enqueue(kn);
	kqueue_wakeup(kq, 0);

	/* wake up the parent kq, too */
	KNOTE(&kq->kq_sel.si_note, 0);
}

/* called with kqueue lock held */
static void
knote_deactivate(struct knote *kn)
{
	kn->kn_status &= ~KN_ACTIVE;
	knote_dequeue(kn);
}

/* called with kqueue lock held */
static void
knote_enqueue(struct knote *kn)
{
	if ((kn->kn_status & (KN_QUEUED | KN_STAYQUEUED)) == KN_STAYQUEUED ||
	    (kn->kn_status & (KN_QUEUED | KN_STAYQUEUED | KN_DISABLED)) == 0) {
		struct kqtailq *tq = kn->kn_tq;
		struct kqueue *kq = kn->kn_kq;

		TAILQ_INSERT_TAIL(tq, kn, kn_tqe);
		kn->kn_status |= KN_QUEUED;
		kq->kq_count++;
	}
}

/* called with kqueue lock held */
static void
knote_dequeue(struct knote *kn)
{
	struct kqueue *kq = kn->kn_kq;

	if ((kn->kn_status & (KN_QUEUED | KN_STAYQUEUED)) == KN_QUEUED) {
		struct kqtailq *tq = kn->kn_tq;

		TAILQ_REMOVE(tq, kn, kn_tqe);
		kn->kn_tq = &kq->kq_head;
		kn->kn_status &= ~KN_QUEUED;
		kq->kq_count--;
	}
}

void
knote_init(void)
{
	knote_zone = zinit(sizeof(struct knote), 8192*sizeof(struct knote),
	    8192, "knote zone");

	/* allocate kq lock group attribute and group */
	kq_lck_grp_attr = lck_grp_attr_alloc_init();

	kq_lck_grp = lck_grp_alloc_init("kqueue",  kq_lck_grp_attr);

	/* Allocate kq lock attribute */
	kq_lck_attr = lck_attr_alloc_init();

	/* Initialize the timer filter lock */
	lck_mtx_init(&_filt_timerlock, kq_lck_grp, kq_lck_attr);

#if VM_PRESSURE_EVENTS
	/* Initialize the vm pressure list lock */
	vm_pressure_init(kq_lck_grp, kq_lck_attr);
#endif

#if CONFIG_MEMORYSTATUS
	/* Initialize the memorystatus list lock */
	memorystatus_kevent_init(kq_lck_grp, kq_lck_attr);
#endif
}
SYSINIT(knote, SI_SUB_PSEUDO, SI_ORDER_ANY, knote_init, NULL)

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
			    1, m->m_len, SO_TC_BE);

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
knote_markstayqueued(struct knote *kn)
{
	kqlock(kn->kn_kq);
	kn->kn_status |= KN_STAYQUEUED;
	knote_enqueue(kn);
	kqunlock(kn->kn_kq);
}

void
knote_clearstayqueued(struct knote *kn)
{
	kqlock(kn->kn_kq);
	kn->kn_status &= ~KN_STAYQUEUED;
	knote_dequeue(kn);
	kqunlock(kn->kn_kq);
}

static unsigned long
kevent_extinfo_emit(struct kqueue *kq, struct knote *kn, struct kevent_extinfo *buf,
		unsigned long buflen, unsigned long nknotes)
{
	struct kevent_qos_s kevqos;
	struct kevent_internal_s *kevp;
	for (; kn; kn = SLIST_NEXT(kn, kn_link)) {
		if (kq == kn->kn_kq) {
			if (nknotes < buflen) {
				struct kevent_extinfo *info = &buf[nknotes];

				kqlock(kq);
				bzero(&kevqos, sizeof(kevqos));
				kevp = &(kn->kn_kevent);

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

				/* status flags exported to userspace/libproc */
#define KQEXT_STATUS_MASK (KN_ACTIVE|KN_QUEUED|KN_DISABLED|KN_STAYQUEUED)
				info->kqext_status = kn->kn_status & KQEXT_STATUS_MASK;
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

	if (!err)
		*retval = nknotes;
	return err;
}
