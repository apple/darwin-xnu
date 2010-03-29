/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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

#include <kern/lock.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <kern/sched_prim.h>
#include <kern/zalloc.h>
#include <kern/assert.h>

#include <libkern/libkern.h>
#include "net/net_str_id.h"

MALLOC_DEFINE(M_KQUEUE, "kqueue", "memory for kqueue system");

#define KQ_EVENT NULL

static inline void kqlock(struct kqueue *kq);
static inline void kqunlock(struct kqueue *kq);

static int	kqlock2knoteuse(struct kqueue *kq, struct knote *kn);
static int	kqlock2knoteusewait(struct kqueue *kq, struct knote *kn);
static int	kqlock2knotedrop(struct kqueue *kq, struct knote *kn);
static int	knoteuse2kqlock(struct kqueue *kq, struct knote *kn);

static void 	kqueue_wakeup(struct kqueue *kq, int closed);
static int 	kqueue_read(struct fileproc *fp, struct uio *uio,
		    int flags, vfs_context_t ctx);
static int	kqueue_write(struct fileproc *fp, struct uio *uio,
		    int flags, vfs_context_t ctx);
static int	kqueue_ioctl(struct fileproc *fp, u_long com, caddr_t data,
		    vfs_context_t ctx);
static int 	kqueue_select(struct fileproc *fp, int which, void *wql, 
		    vfs_context_t ctx);
static int 	kqueue_close(struct fileglob *fg, vfs_context_t ctx);
static int 	kqueue_kqfilter(struct fileproc *fp, struct knote *kn, vfs_context_t ctx);
static int 	kqueue_drain(struct fileproc *fp, vfs_context_t ctx);
extern int	kqueue_stat(struct fileproc *fp, void  *ub, int isstat64, vfs_context_t ctx);

static struct fileops kqueueops = {
 	.fo_read = kqueue_read,
 	.fo_write = kqueue_write,
 	.fo_ioctl = kqueue_ioctl,
 	.fo_select = kqueue_select,
 	.fo_close = kqueue_close,
 	.fo_kqfilter = kqueue_kqfilter,
	.fo_drain = kqueue_drain,
};

static int kevent_internal(struct proc *p, int iskev64, user_addr_t changelist,
		int nchanges, user_addr_t eventlist, int nevents, int fd, 
		user_addr_t utimeout, unsigned int flags, int32_t *retval);
static int kevent_copyin(user_addr_t *addrp, struct kevent64_s *kevp, struct proc *p, int iskev64);
static int kevent_copyout(struct kevent64_s *kevp, user_addr_t *addrp, struct proc *p, int iskev64);
char * kevent_description(struct kevent64_s *kevp, char *s, size_t n);

static int	kevent_callback(struct kqueue *kq, struct kevent64_s *kevp, void *data);
static void	kevent_continue(struct kqueue *kq, void *data, int error);
static void	kqueue_scan_continue(void *contp, wait_result_t wait_result);
static int	kqueue_process(struct kqueue *kq, kevent_callback_t callback,
			       void *data, int *countp, struct proc *p);
static int	knote_process(struct knote *kn, kevent_callback_t callback,
			      void *data, struct kqtailq *inprocessp, struct proc *p);
static void	knote_put(struct knote *kn);
static int 	knote_fdpattach(struct knote *kn, struct filedesc *fdp, struct proc *p);
static void 	knote_drop(struct knote *kn, struct proc *p);
static void	knote_activate(struct knote *kn, int);
static void	knote_deactivate(struct knote *kn);
static void 	knote_enqueue(struct knote *kn);
static void 	knote_dequeue(struct knote *kn);
static struct 	knote *knote_alloc(void);
static void 	knote_free(struct knote *kn);

static int	filt_fileattach(struct knote *kn);
static struct filterops file_filtops = {
        .f_isfd = 1,
        .f_attach = filt_fileattach,
};

static void	filt_kqdetach(struct knote *kn);
static int	filt_kqueue(struct knote *kn, long hint);
static struct filterops kqread_filtops = {
        .f_isfd = 1,
        .f_detach = filt_kqdetach,
        .f_event = filt_kqueue,
};

/*
 * placeholder for not-yet-implemented filters
 */ 
static int	filt_badattach(struct knote *kn);
static struct filterops bad_filtops = {
        .f_attach = filt_badattach,
};

static int	filt_procattach(struct knote *kn);
static void	filt_procdetach(struct knote *kn);
static int	filt_proc(struct knote *kn, long hint);
static struct filterops proc_filtops = {
        .f_attach = filt_procattach,
        .f_detach = filt_procdetach,
        .f_event = filt_proc,
};

extern struct filterops fs_filtops;

extern struct filterops sig_filtops;

/* Timer filter */
static int	filt_timerattach(struct knote *kn);
static void	filt_timerdetach(struct knote *kn);
static int	filt_timer(struct knote *kn, long hint);
static void     filt_timertouch(struct knote *kn, struct kevent64_s *kev, 
		long type);
static struct filterops timer_filtops = {
        .f_attach = filt_timerattach,
        .f_detach = filt_timerdetach,
        .f_event = filt_timer,
        .f_touch = filt_timertouch,
};

/* Helpers */

static void	filt_timerexpire(void *knx, void *param1);
static int	filt_timervalidate(struct knote *kn);
static void	filt_timerupdate(struct knote *kn);
static void	filt_timercancel(struct knote *kn);

#define TIMER_RUNNING		0x1
#define TIMER_CANCELWAIT	0x2

static lck_mtx_t _filt_timerlock;
static void	filt_timerlock(void);
static void	filt_timerunlock(void);

static zone_t	knote_zone;

#define KN_HASH(val, mask)	(((val) ^ (val >> 8)) & (mask))

#if 0
extern struct filterops aio_filtops;
#endif

/* Mach portset filter */
extern struct filterops machport_filtops;

/* User filter */
static int      filt_userattach(struct knote *kn);
static void	filt_userdetach(struct knote *kn);
static int	filt_user(struct knote *kn, long hint);
static void     filt_usertouch(struct knote *kn, struct kevent64_s *kev, 
		long type);
static struct filterops user_filtops = {
        .f_attach = filt_userattach,
        .f_detach = filt_userdetach,
        .f_event = filt_user,
        .f_touch = filt_usertouch,
};

#if CONFIG_AUDIT
/* Audit session filter */
extern struct filterops audit_session_filtops;
#endif

/*
 * Table for for all system-defined filters.
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
#if CONFIG_AUDIT
	&audit_session_filtops,		/* EVFILT_SESSION */
#else
	&bad_filtops,
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
 *	
 *	- kq locked at entry
 *	- unlock on exit if we get the use reference
 */
static int
kqlock2knoteuse(struct kqueue *kq, struct knote *kn)
{
	if (kn->kn_status & KN_DROPPING)
		return 0;
	kn->kn_inuse++;
	kqunlock(kq);
	return 1;
 }

/* 
 * Convert a kq lock to a knote use referece,
 * but wait for attach and drop events to complete.
 *
 *	If the knote is being dropped, we can't get
 *	a use reference, so just return with it
 *	still locked.
 *	
 *	- kq locked at entry
 *	- kq always unlocked on exit
 */
static int
kqlock2knoteusewait(struct kqueue *kq, struct knote *kn)
{
	if ((kn->kn_status & (KN_DROPPING | KN_ATTACHING)) != 0) {
		kn->kn_status |= KN_USEWAIT;
		wait_queue_assert_wait((wait_queue_t)kq->kq_wqs, &kn->kn_status, THREAD_UNINT, 0);
		kqunlock(kq);
		thread_block(THREAD_CONTINUE_NULL);
		return 0;
	}
	kn->kn_inuse++;
	kqunlock(kq);
	return 1;
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
			wait_queue_wakeup_all((wait_queue_t)kq->kq_wqs, &kn->kn_status, THREAD_AWAKENED);
		}
	}
	return ((kn->kn_status & KN_DROPPING) == 0);
 }

/* 
 * Convert a kq lock to a knote drop referece.
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
	kn->kn_status |= KN_DROPPING;
	if (oktodrop) {
		if (kn->kn_inuse == 0) {
			kqunlock(kq);
			return oktodrop;
		}
	}
	kn->kn_status |= KN_USEWAIT;
	wait_queue_assert_wait((wait_queue_t)kq->kq_wqs, &kn->kn_status, THREAD_UNINT, 0);
	kqunlock(kq);
	thread_block(THREAD_CONTINUE_NULL);
	return oktodrop;
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
			wait_queue_wakeup_all((wait_queue_t)kq->kq_wqs, &kn->kn_status, THREAD_AWAKENED);
		}
	}
	kqunlock(kq);
 }

static int
filt_fileattach(struct knote *kn)
{
	
	return (fo_kqfilter(kn->kn_fp, kn, vfs_context_current()));
}

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data

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
		return(ENOTSUP);

	p = proc_find(kn->kn_id);
	if (p == NULL) {
		return (ESRCH);
	}

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
	/* hint is 0 when called from above */
	if (hint != 0) {
		u_int event;

		/* ALWAYS CALLED WITH proc_klist_lock when (hint != 0) */

		/*
		 * mask off extra data
		 */
		event = (u_int)hint & NOTE_PCTRLMASK;

		/*
		 * if the user is interested in this event, record it.
		 */
		if (kn->kn_sfflags & event)
			kn->kn_fflags |= event;

		if (event == NOTE_REAP || (event == NOTE_EXIT && !(kn->kn_sfflags & NOTE_REAP))) {
			kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		}
	}

	/* atomic check, no locking need when called from above */
	return (kn->kn_fflags != 0); 
}


/*
 * filt_timervalidate - process data from user
 * 	
 * 	Converts to either interval or deadline format.
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
	uint64_t raw;

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
		return EINVAL;
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

	return 0;
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
 *	Just propagate the timer event into the knote
 *	filter routine (by going through the knote
 *	synchronization point).  Pass a hint to
 *	indicate this is a real event, not just a
 *	query from above.
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
		wait_queue_wakeup_all((wait_queue_t)kq->kq_wqs, &kn->kn_hook, 
				THREAD_AWAKENED);
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
			wait_queue_assert_wait((wait_queue_t)kq->kq_wqs, 
					&kn->kn_hook, THREAD_UNINT, 0);
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
	if (error) {
		filt_timerunlock();
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
		thread_call_enter_delayed(callout, kn->kn_ext[0]);
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
				/* keep the callout and re-arm */
				thread_call_enter_delayed(kn->kn_hook, 
						kn->kn_ext[0]);
				kn->kn_hookid |= TIMER_RUNNING;
			}
		}

		return 1;
	} 

	/* user-query */
	filt_timerlock();

	result = (kn->kn_data != 0);

	filt_timerunlock();
	return result;
}


/*
 * filt_timertouch - update knote with new user input
 *
 * 	Cancel and restart the timer based on new user data. When
 * 	the user picks up a knote, clear the count of how many timer
 * 	pops have gone off (in kn_data).
 */
static void     
filt_timertouch(struct knote *kn, struct kevent64_s *kev, long type)
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
			thread_call_enter_delayed(kn->kn_hook, kn->kn_ext[0]);
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
		panic("filt_timertouch() - invalid type (%ld)", type);
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
	if (kn->kn_fflags & NOTE_TRIGGER || kn->kn_flags & EV_TRIGGER) {
		kn->kn_hookid = 1;
	} else {
		kn->kn_hookid = 0;
	}
        return 0;
}

static void
filt_userdetach(__unused struct knote *kn)
{
        /* EVFILT_USER knotes are not attached to anything in the kernel */
}

static int
filt_user(struct knote *kn, __unused long hint)
{
        return kn->kn_hookid;
}

static void
filt_usertouch(struct knote *kn, struct kevent64_s *kev, long type)
{
        int ffctrl;
        switch (type) {
        case EVENT_REGISTER:
                if (kev->fflags & NOTE_TRIGGER || kev->flags & EV_TRIGGER) {
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
                panic("filt_usertouch() - invalid type (%ld)", type);
                break;
        }
}

/*
 * JMM - placeholder for not-yet-implemented filters
 */ 
static int
filt_badattach(__unused struct knote *kn)
{
	return(ENOTSUP);
}


struct kqueue *
kqueue_alloc(struct proc *p)
{
	struct filedesc *fdp = p->p_fd;
	struct kqueue *kq;

	MALLOC_ZONE(kq, struct kqueue *, sizeof(struct kqueue), M_KQUEUE, M_WAITOK);
	if (kq != NULL) {
		wait_queue_set_t wqs;

		wqs = wait_queue_set_alloc(SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST);
		if (wqs != NULL) {
			bzero(kq, sizeof(struct kqueue));
			lck_spin_init(&kq->kq_lock, kq_lck_grp, kq_lck_attr);
			TAILQ_INIT(&kq->kq_head);
			kq->kq_wqs = wqs;
			kq->kq_p = p;
		} else {
			FREE_ZONE(kq, sizeof(struct kqueue), M_KQUEUE);
		}
	}

	if (fdp->fd_knlistsize < 0) {
		proc_fdlock(p);
		if (fdp->fd_knlistsize < 0)
			fdp->fd_knlistsize = 0;		/* this process has had a kq */
		proc_fdunlock(p);
	}

	return kq;
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
	struct proc *p = kq->kq_p;
	struct filedesc *fdp = p->p_fd;
	struct knote *kn;
	int i;

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
	 * before freeing the wait queue set for this kqueue,
	 * make sure it is unlinked from all its containing (select) sets.
	 */
	wait_queue_unlink_all((wait_queue_t)kq->kq_wqs);
	wait_queue_set_free(kq->kq_wqs);
	lck_spin_destroy(&kq->kq_lock, kq_lck_grp);
	FREE_ZONE(kq, sizeof(struct kqueue), M_KQUEUE);
}

int
kqueue(struct proc *p, __unused struct kqueue_args *uap, int32_t *retval)
{
	struct kqueue *kq;
	struct fileproc *fp;
	int fd, error;

	error = falloc(p, &fp, &fd, vfs_context_current());
	if (error) {
		return (error);
	}

	kq = kqueue_alloc(p);
	if (kq == NULL) {
		fp_free(p, fd, fp);
		return (ENOMEM);
	}

	fp->f_flag = FREAD | FWRITE;
	fp->f_type = DTYPE_KQUEUE;
	fp->f_ops = &kqueueops;
	fp->f_data = (caddr_t)kq;

	proc_fdlock(p);
	procfdtbl_releasefd(p, fd, NULL);
	fp_drop(p, fd, fp, 1);
	proc_fdunlock(p);

	*retval = fd;
	return (error);
}

static int
kevent_copyin(user_addr_t *addrp, struct kevent64_s *kevp, struct proc *p, int iskev64)
{
	int advance;
	int error;

	if (iskev64) {
		advance = sizeof(struct kevent64_s);
		error = copyin(*addrp, (caddr_t)kevp, advance);
	} else if (IS_64BIT_PROCESS(p)) {
		struct user64_kevent kev64;
		bzero(kevp, sizeof(struct kevent64_s));

		advance = sizeof(kev64);
		error = copyin(*addrp, (caddr_t)&kev64, advance);
		if (error)
			return error;
		kevp->ident = kev64.ident;
		kevp->filter = kev64.filter;
		kevp->flags = kev64.flags;
		kevp->fflags = kev64.fflags;
		kevp->data = kev64.data;
		kevp->udata = kev64.udata;
	} else {
		struct user32_kevent kev32;
		bzero(kevp, sizeof(struct kevent64_s));

		advance = sizeof(kev32);
		error = copyin(*addrp, (caddr_t)&kev32, advance);
		if (error)
			return error;
		kevp->ident = (uintptr_t)kev32.ident;
		kevp->filter = kev32.filter;
		kevp->flags = kev32.flags;
		kevp->fflags = kev32.fflags;
		kevp->data = (intptr_t)kev32.data;
		kevp->udata = CAST_USER_ADDR_T(kev32.udata);
	}
	if (!error)
		*addrp += advance;
	return error;
}

static int
kevent_copyout(struct kevent64_s *kevp, user_addr_t *addrp, struct proc *p, int iskev64)
{
	int advance;
	int error;

	if (iskev64) {
		advance = sizeof(struct kevent64_s);
		error = copyout((caddr_t)kevp, *addrp, advance);
	} else if (IS_64BIT_PROCESS(p)) {
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
		advance = sizeof(kev64);
		error = copyout((caddr_t)&kev64, *addrp, advance);
	} else {
		struct user32_kevent kev32;

		kev32.ident = (uint32_t)kevp->ident;
		kev32.filter = kevp->filter;
		kev32.flags = kevp->flags;
		kev32.fflags = kevp->fflags;
		kev32.data = (int32_t)kevp->data;
		kev32.udata = kevp->udata;
		advance = sizeof(kev32);
		error = copyout((caddr_t)&kev32, *addrp, advance);
	}
	if (!error)
		*addrp += advance;
	return error;
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
	return kevent_internal(p, 
			0, 
			uap->changelist,
			uap->nchanges,
			uap->eventlist,
			uap->nevents,
			uap->fd,
			uap->timeout,
			0, /* no flags from old kevent() call */
			retval);
}
  
int
kevent64(struct proc *p, struct kevent64_args *uap, int32_t *retval)
{
	return kevent_internal(p, 
			1, 
			uap->changelist,
			uap->nchanges,
			uap->eventlist,
			uap->nevents,
			uap->fd,
			uap->timeout,
			uap->flags,
			retval);
}

static int
kevent_internal(struct proc *p, int iskev64, user_addr_t changelist, 
		int nchanges, user_addr_t ueventlist, int nevents, int fd, 
		user_addr_t utimeout, __unused unsigned int flags, 
		int32_t *retval)
{
	struct _kevent *cont_args;
	uthread_t ut;
	struct kqueue *kq;
	struct fileproc *fp;
	struct kevent64_s kev;
	int error, noutputs;
	struct timeval atv;

	/* convert timeout to absolute - if we have one */
	if (utimeout != USER_ADDR_NULL) {
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
			return error;
		if (itimerfix(&rtv))
			return EINVAL;
		getmicrouptime(&atv);
		timevaladd(&atv, &rtv);
	} else {
		atv.tv_sec = 0;
		atv.tv_usec = 0;
	}

	/* get a usecount for the kq itself */
	if ((error = fp_getfkq(p, fd, &fp, &kq)) != 0)
		return(error);
	
	/* each kq should only be used for events of one type */
	kqlock(kq);
	if (kq->kq_state & (KQ_KEV32 | KQ_KEV64)) {
		if (((iskev64 && (kq->kq_state & KQ_KEV32)) ||
			(!iskev64 && (kq->kq_state & KQ_KEV64)))) {
			error = EINVAL;
			kqunlock(kq);
			goto errorout;
		}
	} else {
		kq->kq_state |= (iskev64 ? KQ_KEV64 : KQ_KEV32);
	}
	kqunlock(kq);

	/* register all the change requests the user provided... */
	noutputs = 0;
	while (nchanges > 0 && error == 0) {
		error = kevent_copyin(&changelist, &kev, p, iskev64);
		if (error)
			break;
				
		kev.flags &= ~EV_SYSFLAGS;
		error = kevent_register(kq, &kev, p);
		if ((error || (kev.flags & EV_RECEIPT)) && nevents > 0) {
			kev.flags = EV_ERROR;
			kev.data = error;
			error = kevent_copyout(&kev, &ueventlist, p, iskev64);
			if (error == 0) {
				nevents--;
				noutputs++;
			}
		}
		nchanges--;
	}

	/* store the continuation/completion data in the uthread */
	ut = (uthread_t)get_bsdthread_info(current_thread());
	cont_args = &ut->uu_kevent.ss_kevent;
	cont_args->fp = fp;
	cont_args->fd = fd;
	cont_args->retval = retval;
	cont_args->eventlist = ueventlist;
	cont_args->eventcount = nevents;
	cont_args->eventout = noutputs;
	cont_args->eventsize = iskev64;

	if (nevents > 0 && noutputs == 0 && error == 0)
		error = kqueue_scan(kq, kevent_callback,
				    kevent_continue, cont_args,
				    &atv, p);
	kevent_continue(kq, cont_args, error);

errorout:
	fp_drop(p, fd, fp, 0);
	return error;
}


/*
 * kevent_callback - callback for each individual event
 *
 *	called with nothing locked
 *	caller holds a reference on the kqueue
 */

static int
kevent_callback(__unused struct kqueue *kq, struct kevent64_s *kevp, 
		void *data)
{
	struct _kevent *cont_args;
	int error;
	int iskev64;

	cont_args = (struct _kevent *)data;
	assert(cont_args->eventout < cont_args->eventcount);

	iskev64 = cont_args->eventsize;

	/*
	 * Copy out the appropriate amount of event data for this user.
	 */
	error = kevent_copyout(kevp, &cont_args->eventlist, current_proc(), iskev64);

	/*
	 * If there isn't space for additional events, return
	 * a harmless error to stop the processing here
	 */
	if (error == 0 && ++cont_args->eventout == cont_args->eventcount)
			error = EWOULDBLOCK;
	return error;
}

/*
 * kevent_description - format a description of a kevent for diagnostic output
 *
 *      called with a 128-byte string buffer
 */

char *
kevent_description(struct kevent64_s *kevp, char *s, size_t n)
{
        snprintf(s, n,
                 "kevent="
                 "{.ident=%#llx, .filter=%d, .flags=%#x, .fflags=%#x, .data=%#llx, .udata=%#llx, .ext[0]=%#llx, .ext[1]=%#llx}",
                 kevp->ident,
                 kevp->filter,
                 kevp->flags,
                 kevp->fflags,
                 kevp->data,
                 kevp->udata,
		 kevp->ext[0],
		 kevp->ext[1]);
        return s;
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
kevent_register(struct kqueue *kq, struct kevent64_s *kev, __unused struct proc *ctxp)
{
	struct proc *p = kq->kq_p;
	struct filedesc *fdp = p->p_fd;
	struct filterops *fops;
	struct fileproc *fp = NULL;
	struct knote *kn = NULL;
	int error = 0;

	if (kev->filter < 0) {
		if (kev->filter + EVFILT_SYSCOUNT < 0)
			return (EINVAL);
		fops = sysfilt_ops[~kev->filter];	/* to 0-base index */
	} else {
		/*
		 * XXX
		 * filter attach routine is responsible for insuring that
		 * the identifier can be attached to it.
		 */
		printf("unknown filter: %d\n", kev->filter);
		return (EINVAL);
	}

 restart:
	/* this iocount needs to be dropped if it is not registered */
	proc_fdlock(p);
	if (fops->f_isfd && (error = fp_lookup(p, kev->ident, &fp, 1)) != 0) {
		proc_fdunlock(p);
		return(error);
	}

	if (fops->f_isfd) {
		/* fd-based knotes are linked off the fd table */
		if (kev->ident < (u_int)fdp->fd_knlistsize) {
			SLIST_FOREACH(kn, &fdp->fd_knlist[kev->ident], kn_link)
				if (kq == kn->kn_kq &&
				    kev->filter == kn->kn_filter)
					break;
		}
	} else {
		/* hash non-fd knotes here too */
		if (fdp->fd_knhashmask != 0) {
			struct klist *list;
			
			list = &fdp->fd_knhash[
			    KN_HASH((u_long)kev->ident, fdp->fd_knhashmask)];
			SLIST_FOREACH(kn, list, kn_link)
				if (kev->ident == kn->kn_id &&
				    kq == kn->kn_kq &&
				    kev->filter == kn->kn_filter)
					break;
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
			knote_dequeue(kn);
			kn->kn_status |= KN_DISABLED;
			if (kqlock2knotedrop(kq, kn)) {
				kn->kn_fop->f_detach(kn);
				knote_drop(kn, p);
			}
			goto done;
		}
			
		/* update status flags for existing knote */
		if (kev->flags & EV_DISABLE) {
			knote_dequeue(kn);
			kn->kn_status |= KN_DISABLED;
		} else if (kev->flags & EV_ENABLE) {
			kn->kn_status &= ~KN_DISABLED;
			if (kn->kn_status & KN_ACTIVE)
				knote_enqueue(kn);
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

		/* We may need to push some info down to a networked filesystem */
		if (kn->kn_filter == EVFILT_VNODE) {
			vnode_knoteupdate(kn);
		}
	}
	/* still have use ref on knote */

	/*
	 * If the knote is not marked to always stay enqueued,
	 * invoke the filter routine to see if it should be
	 * enqueued now.
	 */
	if ((kn->kn_status & KN_STAYQUEUED) == 0 && kn->kn_fop->f_event(kn, 0)) {
		if (knoteuse2kqlock(kq, kn))
			knote_activate(kn, 1);
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
knote_process(struct knote 	*kn,
	      kevent_callback_t callback,
	      void		*data, 
	      struct kqtailq	*inprocessp, 
	      struct proc 	*p)
{
	struct kqueue *kq = kn->kn_kq;
	struct kevent64_s kev;
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
		touch =	(!kn->kn_fop->f_isfd && kn->kn_fop->f_touch != NULL);

		if (revalidate || touch) {
			if (revalidate)
				knote_deactivate(kn);
			
			/* call the filter/touch routines with just a ref */
			if (kqlock2knoteuse(kq, kn)) {
			
				/* if we have to revalidate, call the filter */
				if (revalidate) {
					result = kn->kn_fop->f_event(kn, 0);
				}

				/* capture the kevent data - using touch if specified */
				if (result && touch) {
					kn->kn_fop->f_touch(kn, &kev, EVENT_PROCESS);
				}

				/* convert back to a kqlock - bail if the knote went away */
				if (!knoteuse2kqlock(kq, kn)) {
					return EJUSTRETURN;
				} else if (result) {
					/* if revalidated as alive, make sure it's active */
					if (!(kn->kn_status & KN_ACTIVE)) {
						knote_activate(kn, 0);
					}

					/* capture all events that occurred during filter */
					if (!touch) {
						kev = kn->kn_kevent;
					}

				} else if ((kn->kn_status & KN_STAYQUEUED) == 0) {
					/* was already dequeued, so just bail on this one */
					return EJUSTRETURN;
				}
			} else {
				return EJUSTRETURN;
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
	 * One-shot: deactivate it.
	 * Clear: deactivate and clear the state.
	 * Dispatch: don't clear state, just deactivate it and mark it disabled.
	 * All others: just leave where they are.
	 */

	if (result == 0) {
		return EJUSTRETURN;
	} else if ((kn->kn_flags & EV_ONESHOT) != 0) {
		knote_deactivate(kn);
		if (kqlock2knotedrop(kq, kn)) {
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
	return error;
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
 restart:
	if (kq->kq_count == 0) {
		*countp = 0;
		return 0;
	}

	/* if someone else is processing the queue, wait */
	if (hw_atomic_add(&kq->kq_nprocess, 1) != 1) {
	        hw_atomic_sub(&kq->kq_nprocess, 1);
		wait_queue_assert_wait((wait_queue_t)kq->kq_wqs, &kq->kq_nprocess, THREAD_UNINT, 0);
		kq->kq_state |= KQ_PROCWAIT;
		kqunlock(kq);
		thread_block(THREAD_CONTINUE_NULL);
		kqlock(kq);
		goto restart;
	}

	/*
	 * Clear any pre-posted status from previous runs, so we only
	 * detect events that occur during this run.
	 */
	wait_queue_sub_clearrefs(kq->kq_wqs);

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
	hw_atomic_sub(&kq->kq_nprocess, 1);
	if (kq->kq_state & KQ_PROCWAIT) {
		kq->kq_state &= ~KQ_PROCWAIT;
		wait_queue_wakeup_all((wait_queue_t)kq->kq_wqs, &kq->kq_nprocess, THREAD_AWAKENED);
	}

	*countp = nevents;
	return error;
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
		error = kqueue_process(kq, cont_args->call, cont_args, &count, current_proc());
		if (error == 0 && count == 0) {
			wait_queue_assert_wait((wait_queue_t)kq->kq_wqs, KQ_EVENT, 
					       THREAD_ABORTSAFE, cont_args->deadline); 
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
		panic("kevent_scan_cont() - invalid wait_result (%d)", wait_result);
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
							    atvp->tv_usec * NSEC_PER_USEC,
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
		wait_queue_assert_wait((wait_queue_t)kq->kq_wqs, KQ_EVENT, THREAD_ABORTSAFE, deadline);
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
		default:
			panic("kevent_scan - bad wait_result (%d)",
			      wait_result);
			error = 0;
		}
	}
	kqunlock(kq);
	return error;
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
kqueue_select(struct fileproc *fp, int which, void *wql, __unused vfs_context_t ctx)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;
	int again;

	if (which != FREAD)
		return 0;

	kqlock(kq);
	/* 
	 * If this is the first pass, link the wait queue associated with the
	 * the kqueue onto the wait queue set for the select().  Normally we
	 * use selrecord() for this, but it uses the wait queue within the
	 * selinfo structure and we need to use the main one for the kqueue to
	 * catch events from KN_STAYQUEUED sources. So we do the linkage manually.
	 * (The select() call will unlink them when it ends).
	 */
	if (wql != NULL) {
		thread_t	cur_act = current_thread();
		struct uthread * ut = get_bsdthread_info(cur_act);

		kq->kq_state |= KQ_SEL;
		wait_queue_link_noalloc((wait_queue_t)kq->kq_wqs, ut->uu_wqset,
					(wait_queue_link_t)wql);
	}

 retry:
	again = 0;
	if (kq->kq_count != 0) {
		struct knote *kn;

		/*
		 * there is something queued - but it might be a
		 * KN_STAYQUEUED knote, which may or may not have
		 * any events pending.  So, we have to walk the
		 * list of knotes to see, and peek at the stay-
		 * queued ones to be really sure.
		 */
		TAILQ_FOREACH(kn, &kq->kq_head, kn_tqe) {
			int retnum = 0;
			if ((kn->kn_status & KN_STAYQUEUED) == 0 ||
			    (retnum = kn->kn_fop->f_peek(kn)) > 0) {
				kqunlock(kq);
				return 1;
			}
			if (retnum < 0)
				again++;
		}
	}

	/*
	 * If we stumbled across a knote that couldn't be peeked at,
	 * we have to drop the kq lock and try again.
	 */
	if (again > 0) {
		kqunlock(kq);
		mutex_pause(0);
		kqlock(kq);
		goto retry;
	}

	kqunlock(kq);
	return 0;
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
	return 0;
}

/*ARGSUSED*/
int
kqueue_stat(struct fileproc *fp, void *ub, int isstat64,  __unused vfs_context_t ctx)
{

	struct kqueue *kq = (struct kqueue *)fp->f_data;
	if (isstat64 != 0) {
		struct stat64 *sb64 = (struct stat64 *)ub;

		bzero((void *)sb64, sizeof(*sb64));
		sb64->st_size = kq->kq_count;
		if (kq->kq_state & KQ_KEV64)
			sb64->st_blksize = sizeof(struct kevent64_s);
		else
			sb64->st_blksize = sizeof(struct kevent);
		sb64->st_mode = S_IFIFO;
	} else {
		struct stat *sb = (struct stat *)ub;

		bzero((void *)sb, sizeof(*sb));
		sb->st_size = kq->kq_count;
		if (kq->kq_state & KQ_KEV64)
			sb->st_blksize = sizeof(struct kevent64_s);
		else
			sb->st_blksize = sizeof(struct kevent);
		sb->st_mode = S_IFIFO;
	}

	return (0);
}

/*
 * Called with the kqueue locked
 */
static void
kqueue_wakeup(struct kqueue *kq, int closed)
{
	if ((kq->kq_state & (KQ_SLEEP | KQ_SEL)) != 0 || kq->kq_nprocess > 0) {
		kq->kq_state &= ~(KQ_SLEEP | KQ_SEL);
		wait_queue_wakeup_all((wait_queue_t)kq->kq_wqs, KQ_EVENT, 
				      (closed) ? THREAD_INTERRUPTED : THREAD_AWAKENED);
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
				knote_activate(kn, 1);
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
	return ret;
}

/*
 * detach a knote from the specified list.  Return true if that was the last entry.
 * The list is protected by whatever lock the object it is associated with uses.
 */
int
knote_detach(struct klist *list, struct knote *kn)
{
	SLIST_REMOVE(list, kn, knote, kn_selnext);
	return SLIST_EMPTY(list);
}

/*
 * For a given knote, link a provided wait queue directly with the kqueue.
 * Wakeups will happen via recursive wait queue support.  But nothing will move 
 * the knote to the active list at wakeup (nothing calls knote()).  Instead,
 * we permanently enqueue them here.
 *
 * kqueue and knote references are held by caller.
 */
int
knote_link_wait_queue(struct knote *kn, struct wait_queue *wq)
{
	struct kqueue *kq = kn->kn_kq;
	kern_return_t kr;

	kr = wait_queue_link(wq, kq->kq_wqs);
	if (kr == KERN_SUCCESS) {
		kqlock(kq);
		kn->kn_status |= KN_STAYQUEUED;
		knote_enqueue(kn);
		kqunlock(kq);
		return 0;
	} else {
		return ENOMEM;
	}
}

/*
 * Unlink the provided wait queue from the kqueue associated with a knote.
 * Also remove it from the magic list of directly attached knotes.
 *
 * Note that the unlink may have already happened from the other side, so
 * ignore any failures to unlink and just remove it from the kqueue list.
 */
void
knote_unlink_wait_queue(struct knote *kn, struct wait_queue *wq)
{
	struct kqueue *kq = kn->kn_kq;

	(void) wait_queue_unlink(wq, kq->kq_wqs);
	kqlock(kq);
	kn->kn_status &= ~KN_STAYQUEUED;
	knote_dequeue(kn);
	kqunlock(kq);
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
			panic("knote_fdclose: proc mismatch (kq->kq_p=%p != p=%p)", kq->kq_p, p);

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
knote_fdpattach(struct knote *kn, struct filedesc *fdp, __unused struct proc *p)
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

			/* have to grow the fd_knlist */
			size = fdp->fd_knlistsize;
			while (size <= kn->kn_id)
				size += KQEXTENT;
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
		wait_queue_wakeup_all((wait_queue_t)kq->kq_wqs, &kn->kn_status, THREAD_AWAKENED);

	if (kn->kn_fop->f_isfd)
		fp_drop(p, kn->kn_id, kn->kn_fp, 0);

	knote_free(kn);
}

/* called with kqueue lock held */
static void
knote_activate(struct knote *kn, int propagate)
{
	struct kqueue *kq = kn->kn_kq;

	kn->kn_status |= KN_ACTIVE;
	knote_enqueue(kn);
	kqueue_wakeup(kq, 0);

	/* this is a real event: wake up the parent kq, too */
	if (propagate)
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
	knote_zone = zinit(sizeof(struct knote), 8192*sizeof(struct knote), 8192, "knote zone");

	/* allocate kq lock group attribute and group */
	kq_lck_grp_attr= lck_grp_attr_alloc_init();

	kq_lck_grp = lck_grp_alloc_init("kqueue",  kq_lck_grp_attr);

	/* Allocate kq lock attribute */
	kq_lck_attr = lck_attr_alloc_init();

	/* Initialize the timer filter lock */
	lck_mtx_init(&_filt_timerlock, kq_lck_grp, kq_lck_attr);
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


static int kev_attach(struct socket *so, int proto, struct proc *p);
static int kev_detach(struct socket *so);
static int kev_control(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp, struct proc *p);

struct pr_usrreqs event_usrreqs = {
     pru_abort_notsupp, pru_accept_notsupp, kev_attach, pru_bind_notsupp, pru_connect_notsupp,
     pru_connect2_notsupp, kev_control, kev_detach, pru_disconnect_notsupp,
     pru_listen_notsupp, pru_peeraddr_notsupp, pru_rcvd_notsupp, pru_rcvoob_notsupp,
     pru_send_notsupp, pru_sense_null, pru_shutdown_notsupp, pru_sockaddr_notsupp,
     pru_sosend_notsupp, soreceive, pru_sopoll_notsupp
};

struct protosw eventsw[] = {
     {
	  .pr_type = SOCK_RAW,
	  .pr_domain = &systemdomain,
	  .pr_protocol = SYSPROTO_EVENT,
	  .pr_flags = PR_ATOMIC,
	  .pr_usrreqs = &event_usrreqs,
     }
};

static
struct kern_event_head kern_event_head;

static u_int32_t static_event_id = 0;
struct domain *sysdom = &systemdomain;
static lck_mtx_t *sys_mtx;

/*
 * Install the protosw's for the NKE manager.  Invoked at
 *  extension load time
 */
int
kern_event_init(void)
{
    int retval;

    if ((retval = net_add_proto(eventsw, &systemdomain)) != 0) {
    	    log(LOG_WARNING, "Can't install kernel events protocol (%d)\n", retval);
            return(retval);
	}
   
    /*
     * Use the domain mutex for all system event sockets
     */ 
    sys_mtx = sysdom->dom_mtx;
	
    return(KERN_SUCCESS);
}

static int
kev_attach(struct socket *so, __unused int proto, __unused struct proc *p)
{
     int error;
     struct kern_event_pcb  *ev_pcb;

     error = soreserve(so, KEV_SNDSPACE, KEV_RECVSPACE);
     if (error)
          return error;

     MALLOC(ev_pcb, struct kern_event_pcb *, sizeof(struct kern_event_pcb), M_PCB, M_WAITOK);
     if (ev_pcb == 0)
	  return ENOBUFS;

     ev_pcb->ev_socket = so;
     ev_pcb->vendor_code_filter = 0xffffffff;

     so->so_pcb = (caddr_t) ev_pcb;
     lck_mtx_lock(sys_mtx);
     LIST_INSERT_HEAD(&kern_event_head, ev_pcb, ev_link);
     lck_mtx_unlock(sys_mtx);

     return 0;
}


static int
kev_detach(struct socket *so)
{
     struct kern_event_pcb *ev_pcb = (struct kern_event_pcb *) so->so_pcb;

     if (ev_pcb != 0) {
		LIST_REMOVE(ev_pcb, ev_link);
		FREE(ev_pcb, M_PCB);
		so->so_pcb = 0;
		so->so_flags |= SOF_PCBCLEARING;
     }

     return 0;
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
		return EINVAL;
	}
	return net_str_id_find_internal(string, out_vendor_code, NSI_VENDOR_CODE, 1);
}

errno_t  kev_msg_post(struct kev_msg *event_msg)
{
	mbuf_tag_id_t	min_vendor, max_vendor;
	
	net_str_id_first_last(&min_vendor, &max_vendor, NSI_VENDOR_CODE);
	
	if (event_msg == NULL)
		return EINVAL;
	
	/* Limit third parties to posting events for registered vendor codes only */
	if (event_msg->vendor_code < min_vendor ||
		event_msg->vendor_code > max_vendor)
	{
		return EINVAL;
	}
	
	return kev_post_msg(event_msg);
}
	

int  kev_post_msg(struct kev_msg *event_msg)
{
     struct mbuf *m, *m2;
     struct kern_event_pcb  *ev_pcb;
     struct kern_event_msg  *ev;
     char              *tmp;
     u_int32_t     total_size;
     int               i;

	/* Verify the message is small enough to fit in one mbuf w/o cluster */
	total_size = KEV_MSG_HEADER_SIZE;
	
	for (i = 0; i < 5; i++) {
		if (event_msg->dv[i].data_length == 0)
			break;
		total_size += event_msg->dv[i].data_length;
	}
	
	if (total_size > MLEN) {
		return EMSGSIZE;
	}

     m = m_get(M_DONTWAIT, MT_DATA);
     if (m == 0)
	  return ENOBUFS;

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
     lck_mtx_lock(sys_mtx);
     for (ev_pcb = LIST_FIRST(&kern_event_head); 
	  ev_pcb; 
	  ev_pcb = LIST_NEXT(ev_pcb, ev_link)) {

	  if (ev_pcb->vendor_code_filter != KEV_ANY_VENDOR) {
	       if (ev_pcb->vendor_code_filter != ev->vendor_code)
		    continue;

	       if (ev_pcb->class_filter != KEV_ANY_CLASS) {
		    if (ev_pcb->class_filter != ev->kev_class)
			 continue;

		    if ((ev_pcb->subclass_filter != KEV_ANY_SUBCLASS) &&
			(ev_pcb->subclass_filter != ev->kev_subclass))
			 continue;
	       }
	  }

	  m2 = m_copym(m, 0, m->m_len, M_NOWAIT);
	  if (m2 == 0) {
	       m_free(m);
	 	   lck_mtx_unlock(sys_mtx);
	       return ENOBUFS;
	  }
	  /* the socket is already locked because we hold the sys_mtx here */
	  if (sbappendrecord(&ev_pcb->ev_socket->so_rcv, m2))
		  sorwakeup(ev_pcb->ev_socket);
     }

     m_free(m);
     lck_mtx_unlock(sys_mtx);
     return 0;
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
			ev_pcb->vendor_code_filter = kev_req->vendor_code;
			ev_pcb->class_filter     = kev_req->kev_class;
			ev_pcb->subclass_filter  = kev_req->kev_subclass;
			break;
		
		case SIOCGKEVFILT:
			ev_pcb = (struct kern_event_pcb *) so->so_pcb;
			kev_req->vendor_code = ev_pcb->vendor_code_filter;
			kev_req->kev_class   = ev_pcb->class_filter;
			kev_req->kev_subclass = ev_pcb->subclass_filter;
			break;
		
		case SIOCGKEVVENDOR:
			kev_vendor = (struct kev_vendor_code*)data;
			
			/* Make sure string is NULL terminated */
			kev_vendor->vendor_string[KEV_VENDOR_CODE_MAX_STR_LEN-1] = 0;
		
			return net_str_id_find_internal(kev_vendor->vendor_string, 
					&kev_vendor->vendor_code, NSI_VENDOR_CODE, 0);
		
		default:
			return ENOTSUP;
	}
	
	return 0;
}

#endif /* SOCKETS */


int
fill_kqueueinfo(struct kqueue *kq, struct kqueue_info * kinfo)
{
	struct vinfo_stat * st;

	/* No need for the funnel as fd is kept alive */
	
	st = &kinfo->kq_stat;

	st->vst_size = kq->kq_count;
	if (kq->kq_state & KQ_KEV64)
		st->vst_blksize = sizeof(struct kevent64_s);
	else
		st->vst_blksize = sizeof(struct kevent);
	st->vst_mode = S_IFIFO;
	if (kq->kq_state & KQ_SEL)
		kinfo->kq_state |=  PROC_KQUEUE_SELECT;
	if (kq->kq_state & KQ_SLEEP)
		kinfo->kq_state |= PROC_KQUEUE_SLEEP;

	return(0);
}

