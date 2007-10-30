/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <string.h>
#include <sys/proc_info.h>

#include <kern/lock.h>
#include <kern/clock.h>
#include <kern/thread_call.h>
#include <kern/sched_prim.h>
#include <kern/zalloc.h>
#include <kern/assert.h>

#include <libkern/libkern.h>
#include "kpi_mbuf_internal.h"

MALLOC_DEFINE(M_KQUEUE, "kqueue", "memory for kqueue system");

static inline void kqlock(struct kqueue *kq);
static inline void kqunlock(struct kqueue *kq);

static int	kqlock2knoteuse(struct kqueue *kq, struct knote *kn);
static int	kqlock2knoteusewait(struct kqueue *kq, struct knote *kn);
static int	kqlock2knotedrop(struct kqueue *kq, struct knote *kn);
static int	knoteuse2kqlock(struct kqueue *kq, struct knote *kn);

static void 	kqueue_wakeup(struct kqueue *kq);
static int 	kqueue_read(struct fileproc *fp, struct uio *uio,
		    int flags, vfs_context_t ctx);
static int	kqueue_write(struct fileproc *fp, struct uio *uio,
		    int flags, vfs_context_t ctx);
static int	kqueue_ioctl(struct fileproc *fp, u_long com, caddr_t data,
		    vfs_context_t ctx);
static int 	kqueue_select(struct fileproc *fp, int which, void *wql, 
		    vfs_context_t ctx);
static int 	kqueue_close(struct fileglob *fp, vfs_context_t ctx);
static int 	kqueue_kqfilter(struct fileproc *fp, struct knote *kn, vfs_context_t ctx);
extern int	kqueue_stat(struct fileproc *fp, void  *ub, int isstat64, vfs_context_t ctx);

static struct fileops kqueueops = {
	kqueue_read,
	kqueue_write,
	kqueue_ioctl,
	kqueue_select,
	kqueue_close,
	kqueue_kqfilter,
	0
};

static int kevent_copyin(user_addr_t *addrp, struct kevent *kevp, struct proc *p);
static int kevent_copyout(struct kevent *kevp, user_addr_t *addrp, struct proc *p);

static int	kevent_callback(struct kqueue *kq, struct kevent *kevp, void *data);
static void	kevent_continue(struct kqueue *kq, void *data, int error);
static void	kevent_scan_continue(void *contp, wait_result_t wait_result);
static int	kevent_process(struct kqueue *kq, kevent_callback_t callback,
			       void *data, int *countp, struct proc *p);
static void	knote_put(struct knote *kn);
static int 	knote_fdpattach(struct knote *kn, struct filedesc *fdp, struct proc *p);
static void 	knote_drop(struct knote *kn, struct proc *p);
static void	knote_activate(struct knote *kn);
static void	knote_deactivate(struct knote *kn);
static void 	knote_enqueue(struct knote *kn);
static void 	knote_dequeue(struct knote *kn);
static struct 	knote *knote_alloc(void);
static void 	knote_free(struct knote *kn);

static int	filt_fileattach(struct knote *kn);
static struct filterops file_filtops =
	{ 1, filt_fileattach, NULL, NULL };

static void	filt_kqdetach(struct knote *kn);
static int	filt_kqueue(struct knote *kn, long hint);
static struct filterops kqread_filtops =
	{ 1, NULL, filt_kqdetach, filt_kqueue };

/*
 * placeholder for not-yet-implemented filters
 */ 
static int	filt_badattach(struct knote *kn);
static struct filterops bad_filtops =
	{ 0, filt_badattach, 0 , 0 };

static int	filt_procattach(struct knote *kn);
static void	filt_procdetach(struct knote *kn);
static int	filt_proc(struct knote *kn, long hint);

static struct filterops proc_filtops =
	{ 0, filt_procattach, filt_procdetach, filt_proc };

extern struct filterops fs_filtops;

extern struct filterops sig_filtops;


/* Timer filter */
static int	filt_timercompute(struct knote *kn, uint64_t *abs_time);
static void	filt_timerexpire(void *knx, void *param1);
static int	filt_timerattach(struct knote *kn);
static void	filt_timerdetach(struct knote *kn);
static int	filt_timer(struct knote *kn, long hint);

static struct filterops timer_filtops =
	{ 0, filt_timerattach, filt_timerdetach, filt_timer };

/* to avoid arming timers that fire quicker than we can handle */
static uint64_t	filt_timerfloor = 0; 

static lck_mtx_t _filt_timerlock;
static void	filt_timerlock(void);
static void	filt_timerunlock(void);

static zone_t	knote_zone;

#define KN_HASH(val, mask)	(((val) ^ (val >> 8)) & (mask))

#if 0
extern struct filterops aio_filtops;
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
	&bad_filtops,			/* EVFILT_MACHPORT */
	&fs_filtops			/* EVFILT_FS */
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
 * Convert a kq lock to a knote use referece.
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
	if (!kqlock2knoteuse(kq, kn)) {
		kn->kn_status |= KN_DROPWAIT;
		assert_wait(&kn->kn_status, THREAD_UNINT);
		kqunlock(kq);
		thread_block(THREAD_CONTINUE_NULL);
		return 0;
	}
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
	if ((--kn->kn_inuse == 0) &&
	    (kn->kn_status & KN_USEWAIT)) {
		kn->kn_status &= ~KN_USEWAIT;
		thread_wakeup(&kn->kn_inuse);
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

	if ((kn->kn_status & KN_DROPPING) == 0) {
		kn->kn_status |= KN_DROPPING;
		if (kn->kn_inuse > 0) {
			kn->kn_status |= KN_USEWAIT;
			assert_wait(&kn->kn_inuse, THREAD_UNINT);
			kqunlock(kq);
			thread_block(THREAD_CONTINUE_NULL);
		} else
			kqunlock(kq);
		return 1;
	} else {
		kn->kn_status |= KN_DROPWAIT;
		assert_wait(&kn->kn_status, THREAD_UNINT);
		kqunlock(kq);
		thread_block(THREAD_CONTINUE_NULL);
		return 0;
	}
}
		
/* 
 * Release a knote use count reference.
 */
static void
knote_put(struct knote *kn)
{
	struct kqueue *kq = kn->kn_kq;

	kqlock(kq);
	if ((--kn->kn_inuse == 0) && 
	    (kn->kn_status & KN_USEWAIT)) {
		kn->kn_status &= ~KN_USEWAIT;
		thread_wakeup(&kn->kn_inuse);
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
	struct proc * p;

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

		/*
		 * If this is the last possible event for the
		 * knote, unlink this knote from the process
		 * before the process goes away.
		 */
		if (event == NOTE_REAP || (event == NOTE_EXIT && !(kn->kn_sfflags & NOTE_REAP))) {
			kn->kn_flags |= (EV_EOF | EV_ONESHOT);
			p = kn->kn_ptr.p_proc;
			if (p != PROC_NULL) {
				kn->kn_ptr.p_proc = PROC_NULL;
				KNOTE_DETACH(&p->p_klist, kn);
			}
			return (1);
		}

	}

	/* atomic check, no locking need when called from above */
	return (kn->kn_fflags != 0); 
}

/*
 * filt_timercompute - compute absolute timeout
 *
 *	The saved-data field in the knote contains the
 *	time value.  The saved filter-flags indicates
 *	the unit of measurement.
 *
 *	If the timeout is not absolute, adjust it for
 *	the current time.
 */
static int
filt_timercompute(struct knote *kn, uint64_t *abs_time)
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
	if (raw <= filt_timerfloor) {
		*abs_time = 0;
		return 0;
	}
	if ((kn->kn_sfflags & NOTE_ABSOLUTE) == NOTE_ABSOLUTE) {
		uint32_t seconds, nanoseconds;
		uint64_t now;

		clock_get_calendar_nanotime(&seconds, &nanoseconds);
		nanoseconds_to_absolutetime((uint64_t)seconds * NSEC_PER_SEC + nanoseconds,
					    &now);
		if (now >= raw + filt_timerfloor) {
			*abs_time = 0;
			return 0;
		}
		raw -= now;
	} 
	clock_absolutetime_interval_to_deadline(raw, abs_time);
	return 0;
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

	/* no "object" for timers, so fake a list */
	SLIST_INIT(&timer_list);
	SLIST_INSERT_HEAD(&timer_list, kn, kn_selnext); 
	KNOTE(&timer_list, 1);
}

/*
 * data contains amount of time to sleep, in milliseconds,
 * or a pointer to a timespec structure.
 */ 
static int
filt_timerattach(struct knote *kn)
{
	thread_call_t callout;
	uint64_t deadline;
	int error;

	error = filt_timercompute(kn, &deadline);
	if (error)
		return (error);

	if (deadline) {
		callout = thread_call_allocate(filt_timerexpire, kn);
		if (NULL == callout)
			return (ENOMEM);
	} else {  
		/* handle as immediate */
		kn->kn_sdata = 0;
		callout = NULL;
	}

	filt_timerlock();
	kn->kn_hook = (caddr_t)callout;

	/* absolute=EV_ONESHOT */
	if (kn->kn_sfflags & NOTE_ABSOLUTE)
		kn->kn_flags |= EV_ONESHOT; 

	if (deadline) {
		/* all others - if not faking immediate */
		kn->kn_flags |= EV_CLEAR;
		thread_call_enter_delayed(callout, deadline);
		kn->kn_hookid = 0;
	} else {
		/* fake immediate */
		kn->kn_hookid = 1;
	}
	filt_timerunlock();
	return (0);
}

static void
filt_timerdetach(struct knote *kn)
{
	thread_call_t callout;

	filt_timerlock();
	callout = (thread_call_t)kn->kn_hook;
	if (callout != NULL) {
		boolean_t cancelled;

		/* cancel the callout if we can */
		cancelled = thread_call_cancel(callout);
		if (cancelled) {
			/* got it, just free it */
			kn->kn_hook = NULL;
			filt_timerunlock();
			thread_call_free(callout);
			return;
		}
		/* we have to wait for the expire routine.  */
		kn->kn_hookid = -1;	/* we are detaching */
		assert_wait(&kn->kn_hook, THREAD_UNINT);
		filt_timerunlock();
		thread_block(THREAD_CONTINUE_NULL);
		assert(kn->kn_hook == NULL);
		return;
	}
	/* nothing to do */
	filt_timerunlock(); 
}



static int
filt_timer(struct knote *kn, __unused long hint)
{
	int result;
	
	if (hint) {
		/* real timer pop */
		thread_call_t callout;
		boolean_t detaching;

		filt_timerlock();
		
		kn->kn_data++;

		detaching = (kn->kn_hookid < 0);
		callout = (thread_call_t)kn->kn_hook;

		if (!detaching && (kn->kn_flags & EV_ONESHOT) == 0) {
			uint64_t deadline;
			int error;

			/* user input data may have changed - deal */
			error = filt_timercompute(kn, &deadline);
			if (error) {
				kn->kn_flags |= EV_ERROR;
				kn->kn_data = error;
			} else if (deadline == 0) {
				/* revert to fake immediate */
				kn->kn_flags &= ~EV_CLEAR;
				kn->kn_sdata = 0;
				kn->kn_hookid = 1;
			} else {
				/* keep the callout and re-arm */
				thread_call_enter_delayed(callout, deadline);
				filt_timerunlock();
				return 1;
			}
		}
		kn->kn_hook = NULL;
		filt_timerunlock();
		thread_call_free(callout);

		/* if someone is waiting for timer to pop */
		if (detaching)
			thread_wakeup(&kn->kn_hook);

		return 1;
	} 

	/* user-query */
	filt_timerlock();

	/* change fake timer to real if needed */
	while (kn->kn_hookid > 0 && kn->kn_sdata > 0) {
		int error;

		/* update the fake timer (make real) */
		kn->kn_hookid = 0;
		kn->kn_data = 0;
		filt_timerunlock();
		error = filt_timerattach(kn);
		filt_timerlock();
		if (error) {
			kn->kn_flags |= EV_ERROR;
			kn->kn_data = error;
			filt_timerunlock();
			return 1;
		}
	}

	/* if still fake, pretend it fired */
	if (kn->kn_hookid > 0)
		kn->kn_data = 1;

	result = (kn->kn_data != 0);
	filt_timerunlock();
	return result;
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
		bzero(kq, sizeof(struct kqueue));
		lck_spin_init(&kq->kq_lock, kq_lck_grp, kq_lck_attr);
		TAILQ_INIT(&kq->kq_head);
		TAILQ_INIT(&kq->kq_inprocess);
		kq->kq_p = p;
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
	lck_spin_destroy(&kq->kq_lock, kq_lck_grp);
	FREE_ZONE(kq, sizeof(struct kqueue), M_KQUEUE);
}

int
kqueue(struct proc *p, __unused struct kqueue_args *uap, register_t *retval)
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

int
kqueue_portset_np(__unused struct proc *p, 
				  __unused struct kqueue_portset_np_args *uap, 
				  __unused register_t *retval)
{
		/* JMM - Placeholder for now */
		return (ENOTSUP);
}

int
kqueue_from_portset_np(__unused struct proc *p, 
					   __unused struct kqueue_from_portset_np_args *uap, 
					   __unused register_t *retval)
{
		/* JMM - Placeholder for now */
		return (ENOTSUP);
}

static int
kevent_copyin(user_addr_t *addrp, struct kevent *kevp, struct proc *p)
{
	int advance;
	int error;

	if (IS_64BIT_PROCESS(p)) {
		struct user_kevent kev64;

		advance = sizeof(kev64);
		error = copyin(*addrp, (caddr_t)&kev64, advance);
		if (error)
			return error;
		kevp->ident = CAST_DOWN(uintptr_t, kev64.ident);
		kevp->filter = kev64.filter;
		kevp->flags = kev64.flags;
		kevp->fflags = kev64.fflags;
		kevp->data = CAST_DOWN(intptr_t, kev64.data);
		kevp->udata = kev64.udata;
	} else {
		/*
		 * compensate for legacy in-kernel kevent layout
		 * where the udata field is alredy 64-bit.
		 */
		advance = sizeof(*kevp) + sizeof(void *) - sizeof(user_addr_t);
		error = copyin(*addrp, (caddr_t)kevp, advance);
	}
	if (!error)
		*addrp += advance;
	return error;
}

static int
kevent_copyout(struct kevent *kevp, user_addr_t *addrp, struct proc *p)
{
	int advance;
	int error;

	if (IS_64BIT_PROCESS(p)) {
		struct user_kevent kev64;

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
		/*
		 * compensate for legacy in-kernel kevent layout
		 * where the udata field is alredy 64-bit.
		 */
		advance = sizeof(*kevp) + sizeof(void *) - sizeof(user_addr_t);
		error = copyout((caddr_t)kevp, *addrp, advance);
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
	register_t *retval;
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
kevent(struct proc *p, struct kevent_args *uap, register_t *retval)
{
	user_addr_t changelist = uap->changelist;
	user_addr_t ueventlist = uap->eventlist;
	int nchanges = uap->nchanges;
	int nevents = uap->nevents;
	int fd = uap->fd;

	struct _kevent *cont_args;
	uthread_t ut;
	struct kqueue *kq;
	struct fileproc *fp;
	struct kevent kev; 
	int error, noutputs;
	struct timeval atv;

	/* convert timeout to absolute - if we have one */
	if (uap->timeout != USER_ADDR_NULL) {
		struct timeval rtv;
		if ( IS_64BIT_PROCESS(p) ) {
			struct user_timespec ts;
			error = copyin( uap->timeout, &ts, sizeof(ts) );
			if ((ts.tv_sec & 0xFFFFFFFF00000000ull) != 0)
				error = EINVAL;
			else
				TIMESPEC_TO_TIMEVAL(&rtv, &ts);
		} else {
			struct timespec ts;
			error = copyin( uap->timeout, &ts, sizeof(ts) );
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

	/* register all the change requests the user provided... */
	noutputs = 0;
	while (nchanges > 0 && error == 0) {
		error = kevent_copyin(&changelist, &kev, p);
		if (error)
			break;
				
		kev.flags &= ~EV_SYSFLAGS;
		error = kevent_register(kq, &kev, p);
		if ((error || (kev.flags & EV_RECEIPT)) && nevents > 0) {
			kev.flags = EV_ERROR;
			kev.data = error;
			error = kevent_copyout(&kev, &ueventlist, p);
			if (error == 0) {
				nevents--;
				noutputs++;
			}
		}
		nchanges--;
	}

	/* store the continuation/completion data in the uthread */
	ut = (uthread_t)get_bsdthread_info(current_thread());
	cont_args = (struct _kevent *)&ut->uu_kevent.ss_kevent;
	cont_args->fp = fp;
	cont_args->fd = fd;
	cont_args->retval = retval;
	cont_args->eventlist = ueventlist;
	cont_args->eventcount = nevents;
	cont_args->eventout = noutputs;

	if (nevents > 0 && noutputs == 0 && error == 0)
		error = kevent_scan(kq, kevent_callback,
				    kevent_continue, cont_args,
				    &atv, p);
	kevent_continue(kq, cont_args, error);
	/* NOTREACHED */
	return error;
}


/*
 * kevent_callback - callback for each individual event
 *
 *	called with nothing locked
 *	caller holds a reference on the kqueue
 */

static int
kevent_callback(__unused struct kqueue *kq, struct kevent *kevp, void *data)
{
	struct _kevent *cont_args;
	int error;

	cont_args = (struct _kevent *)data;
	assert(cont_args->eventout < cont_args->eventcount);

	/*
	 * Copy out the appropriate amount of event data for this user.
	 */
	error = kevent_copyout(kevp, &cont_args->eventlist, current_proc());

	/*
	 * If there isn't space for additional events, return
	 * a harmless error to stop the processing here
	 */
	if (error == 0 && ++cont_args->eventout == cont_args->eventcount)
			error = EWOULDBLOCK;
	return error;
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
kevent_register(struct kqueue *kq, struct kevent *kev, __unused struct proc *ctxp)
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

	/* this iocount needs to be dropped if it is not registered */
	if (fops->f_isfd && (error = fp_lookup(p, kev->ident, &fp, 0)) != 0)
		return(error);

 restart:
	proc_fdlock(p);
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
			kn->kn_status = 0;

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

			/*
			 * If the attach fails here, we can drop it knowing
			 * that nobody else has a reference to the knote.
			 */
			if ((error = fops->f_attach(kn)) != 0) {
				knote_drop(kn, p);
				goto done;
			}
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
		 * If somebody is in the middle of dropping this
		 * knote - go find/insert a new one.  But we have
		 * wait for this one to go away first.
		 */
		if (!kqlock2knoteusewait(kq, kn))
			/* kqueue unlocked */
			goto restart;

		/*
		 * The user may change some filter values after the
		 * initial EV_ADD, but doing so will not reset any 
		 * filter which have already been triggered.
		 */
		kn->kn_sfflags = kev->fflags;
		kn->kn_sdata = kev->data;
		kn->kn_kevent.udata = kev->udata;
	}
			
	/* still have use ref on knote */
	if (kn->kn_fop->f_event(kn, 0)) {
		if (knoteuse2kqlock(kq, kn))
			knote_activate(kn);
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
 * kevent_process - process the triggered events in a kqueue
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
 */

static int
kevent_process(struct kqueue *kq,
	       kevent_callback_t callback,
	       void *data, 
	       int *countp,
	       struct proc *p)
{
	struct knote *kn;
	struct kevent kev;
	int nevents;
	int error;

 restart:
	if (kq->kq_count == 0) {
		*countp = 0;
		return 0;
	}

	/* if someone else is processing the queue, wait */
	if (!TAILQ_EMPTY(&kq->kq_inprocess)) {
		assert_wait(&kq->kq_inprocess, THREAD_UNINT);
		kq->kq_state |= KQ_PROCWAIT;
		kqunlock(kq);
		thread_block(THREAD_CONTINUE_NULL);
		kqlock(kq);
		goto restart;
	}

	error = 0;
	nevents = 0;
	while (error == 0 &&
	       (kn = TAILQ_FIRST(&kq->kq_head)) != NULL) {

		/*
		 * Take note off the active queue.
		 *
		 * Non-EV_ONESHOT events must be re-validated.
		 *
		 * Convert our lock to a use-count and call the event's
		 * filter routine to update.
		 *
		 * If the event is valid, or triggered while the kq
		 * is unlocked, move to the inprocess queue for processing.
		 */

		if ((kn->kn_flags & EV_ONESHOT) == 0) {
			int result;
			knote_deactivate(kn);

			if (kqlock2knoteuse(kq, kn)) {
				
				/* call the filter with just a ref */
				result = kn->kn_fop->f_event(kn, 0);

				/* if it's still alive, make sure it's active */
				if (knoteuse2kqlock(kq, kn) && result) {
					/* may have been reactivated in filter*/
					if (!(kn->kn_status & KN_ACTIVE)) {
						knote_activate(kn);
					}
				} else {
					continue;
				}
			} else {
				continue;
			}
		}

		/* knote is active: move onto inprocess queue */
		assert(kn->kn_tq == &kq->kq_head);
		TAILQ_REMOVE(&kq->kq_head, kn, kn_tqe);
		kn->kn_tq = &kq->kq_inprocess;
		TAILQ_INSERT_TAIL(&kq->kq_inprocess, kn, kn_tqe);

		/*
		 * Got a valid triggered knote with the kqueue
		 * still locked.  Snapshot the data, and determine
		 * how to dispatch the knote for future events.
		 */
		kev = kn->kn_kevent;

		/* now what happens to it? */
		if (kn->kn_flags & EV_ONESHOT) {
			knote_deactivate(kn);
			if (kqlock2knotedrop(kq, kn)) {
				kn->kn_fop->f_detach(kn);
				knote_drop(kn, p);
			}
		} else if (kn->kn_flags & EV_CLEAR) {
			knote_deactivate(kn);
			kn->kn_data = 0;
			kn->kn_fflags = 0;
			kqunlock(kq);
		} else {
			/*
			 * leave on in-process queue.  We'll
			 * move all the remaining ones back
			 * the kq queue and wakeup any
			 * waiters when we are done.
			 */
			kqunlock(kq);
		}

		/* callback to handle each event as we find it */
		error = (callback)(kq, &kev, data);
		nevents++;

		kqlock(kq);
	}

	/*
	 * With the kqueue still locked, move any knotes
	 * remaining on the in-process queue back to the
	 * kq's queue and wake up any waiters.
	 */
	while ((kn = TAILQ_FIRST(&kq->kq_inprocess)) != NULL) {
		assert(kn->kn_tq == &kq->kq_inprocess);
		TAILQ_REMOVE(&kq->kq_inprocess, kn, kn_tqe);
		kn->kn_tq = &kq->kq_head;
		TAILQ_INSERT_TAIL(&kq->kq_head, kn, kn_tqe);
	}
	if (kq->kq_state & KQ_PROCWAIT) {
		kq->kq_state &= ~KQ_PROCWAIT;
		thread_wakeup(&kq->kq_inprocess);
	}

	*countp = nevents;
	return error;
}


static void
kevent_scan_continue(void *data, wait_result_t wait_result)
{
	uthread_t ut = (uthread_t)get_bsdthread_info(current_thread());
	struct _kevent_scan * cont_args = &ut->uu_kevent.ss_kevent_scan;
	struct kqueue *kq = (struct kqueue *)data;
	int error;
	int count;

	/* convert the (previous) wait_result to a proper error */
	switch (wait_result) {
	case THREAD_AWAKENED:
		kqlock(kq);
		error = kevent_process(kq, cont_args->call, cont_args, &count, current_proc());
		if (error == 0 && count == 0) {
			assert_wait_deadline(kq, THREAD_ABORTSAFE, cont_args->deadline);
			kq->kq_state |= KQ_SLEEP;
			kqunlock(kq);
			thread_block_parameter(kevent_scan_continue, kq);
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
 * kevent_scan - scan and wait for events in a kqueue
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
kevent_scan(struct kqueue *kq, 
	    kevent_callback_t callback,
	    kevent_continue_t continuation,
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
		error = kevent_process(kq, callback, data, &count, p);
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
				struct _kevent_scan *cont_args = &ut->uu_kevent.ss_kevent_scan;
				
				cont_args->call = callback;
				cont_args->cont = continuation;
				cont_args->deadline = deadline;
				cont_args->data = data;
				cont = kevent_scan_continue;
			}
		}

		/* go ahead and wait */
		assert_wait_deadline(kq, THREAD_ABORTSAFE, deadline);
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
kqueue_select(struct fileproc *fp, int which, void *wql, vfs_context_t ctx)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;
	int retnum = 0;

	if (which == FREAD) {
		kqlock(kq);
                if (kq->kq_count) {
			retnum = 1;
		} else {
		        selrecord(vfs_context_proc(ctx), &kq->kq_sel, wql);
			kq->kq_state |= KQ_SEL;
		}
		kqunlock(kq);
	}
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

/*ARGSUSED*/
int
kqueue_stat(struct fileproc *fp, void *ub, int isstat64,  __unused vfs_context_t ctx)
{
	struct stat *sb = (struct stat *)0;	/* warning avoidance ; protected by isstat64 */
	struct stat64 * sb64 = (struct stat64 *)0;  /* warning avoidance ; protected by isstat64 */

	struct kqueue *kq = (struct kqueue *)fp->f_data;
	if (isstat64 != 0) {
		sb64 = (struct stat64 *)ub;
		bzero((void *)sb64, sizeof(*sb64));
		sb64->st_size = kq->kq_count;
		sb64->st_blksize = sizeof(struct kevent);
		sb64->st_mode = S_IFIFO;
	} else {
		sb = (struct stat *)ub;
		bzero((void *)sb, sizeof(*sb));
		sb->st_size = kq->kq_count;
		sb->st_blksize = sizeof(struct kevent);
		sb->st_mode = S_IFIFO;
	}

	return (0);
}

/*
 * Called with the kqueue locked
 */
static void
kqueue_wakeup(struct kqueue *kq)
{

	if (kq->kq_state & KQ_SLEEP) {
		kq->kq_state &= ~KQ_SLEEP;
		thread_wakeup(kq);
	}
	if (kq->kq_state & KQ_SEL) {
		kq->kq_state &= ~KQ_SEL;
		selwakeup(&kq->kq_sel);
	}
	KNOTE(&kq->kq_sel.si_note, 0);
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
 *	the hind) and not deadlock itself.
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
				knote_activate(kn);
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

	proc_fdlock(p);
	if (kn->kn_fop->f_isfd)
		list = &fdp->fd_knlist[kn->kn_id];
	else
		list = &fdp->fd_knhash[KN_HASH(kn->kn_id, fdp->fd_knhashmask)];

	SLIST_REMOVE(list, kn, knote, kn_link);
	kqlock(kq);
	knote_dequeue(kn);
	if (kn->kn_status & KN_DROPWAIT)
		thread_wakeup(&kn->kn_status);
	kqunlock(kq);
	proc_fdunlock(p);

	if (kn->kn_fop->f_isfd)
		fp_drop(p, kn->kn_id, kn->kn_fp, 0);

	knote_free(kn);
}

/* called with kqueue lock held */
static void
knote_activate(struct knote *kn)
{
	struct kqueue *kq = kn->kn_kq;

	kn->kn_status |= KN_ACTIVE;
	knote_enqueue(kn);
	kqueue_wakeup(kq);
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
	struct kqueue *kq = kn->kn_kq;

	if ((kn->kn_status & (KN_QUEUED | KN_DISABLED)) == 0) {
		struct kqtailq *tq = kn->kn_tq;

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

	//assert((kn->kn_status & KN_DISABLED) == 0);
	if ((kn->kn_status & KN_QUEUED) == KN_QUEUED) {
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
	  SOCK_RAW,	        &systemdomain,	SYSPROTO_EVENT,		PR_ATOMIC,
	  0,		0,		0,		0,
	  0,
	  0,		0,		0,		0,
#if __APPLE__
	  0,
#endif
	  &event_usrreqs,
	  0,		0,		0,
#if __APPLE__
	  {0, 0},	0,		{0}
#endif
     }
};

static
struct kern_event_head kern_event_head;

static u_long static_event_id = 0;
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
	return mbuf_tag_id_find_internal(string, out_vendor_code, 1);
}

errno_t  kev_msg_post(struct kev_msg *event_msg)
{
	mbuf_tag_id_t	min_vendor, max_vendor;
	
	mbuf_tag_id_first_last(&min_vendor, &max_vendor);
	
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
     unsigned long     total_size;
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
	u_long  *id_value = (u_long *) data;
	
	
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
			
			return mbuf_tag_id_find_internal(kev_vendor->vendor_string,
											 &kev_vendor->vendor_code, 0);
		
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
	st->vst_blksize = sizeof(struct kevent);
	st->vst_mode = S_IFIFO;
	if (kq->kq_state & KQ_SEL)
		kinfo->kq_state |=  PROC_KQUEUE_SELECT;
	if (kq->kq_state & KQ_SLEEP)
		kinfo->kq_state |= PROC_KQUEUE_SLEEP;

	return(0);
}

