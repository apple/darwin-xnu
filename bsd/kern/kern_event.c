/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/malloc.h> 
#include <sys/unistd.h>
#include <sys/file.h>
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

#include <kern/zalloc.h>

MALLOC_DEFINE(M_KQUEUE, "kqueue", "memory for kqueue system");

static int	kqueue_scan(struct file *fp, int maxevents,
		    struct kevent *ulistp, const struct timespec *timeout,
		    register_t *retval, struct proc *p);
static void 	kqueue_wakeup(struct kqueue *kq);

static int 	kqueue_read __P((struct file *fp, struct uio *uio,
		    struct ucred *cred, int flags, struct proc *p));
static int	kqueue_write __P((struct file *fp, struct uio *uio,
		    struct ucred *cred, int flags, struct proc *p));
static int	kqueue_ioctl __P((struct file *fp, u_long com, caddr_t data,
		    struct proc *p));
static int 	kqueue_select __P((struct file *fp, int which, void *wql, 
		    struct proc *p));
static int 	kqueue_close __P((struct file *fp, struct proc *p));
static int 	kqueue_kqfilter __P((struct file *fp, struct knote *kn, struct proc *p));

static struct fileops kqueueops = {
	kqueue_read,
	kqueue_write,
	kqueue_ioctl,
	kqueue_select,
	kqueue_close,
	kqueue_kqfilter
};

static void 	knote_fdpattach(struct knote *kn, struct filedesc *fdp);
static void 	knote_drop(struct knote *kn, struct proc *p);
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
 * JMM - placeholder for not-yet-implemented filters
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

#if 0
/* JMM - We don't implement these now */
static void	filt_timerexpire(void *knx);
static int	filt_timerattach(struct knote *kn);
static void	filt_timerdetach(struct knote *kn);
static int	filt_timer(struct knote *kn, long hint);

static struct filterops timer_filtops =
	{ 0, filt_timerattach, filt_timerdetach, filt_timer };

static int 		kq_ncallouts = 0;
static int 		kq_calloutmax = (4 * 1024);

SYSCTL_INT(_kern, OID_AUTO, kq_calloutmax, CTLFLAG_RW,
    &kq_calloutmax, 0, "Maximum number of callouts allocated for kqueue");
#endif /* 0 */

static zone_t	knote_zone;

#define KNOTE_ACTIVATE(kn) do { 					\
	kn->kn_status |= KN_ACTIVE;					\
	if ((kn->kn_status & (KN_QUEUED | KN_DISABLED)) == 0)		\
		knote_enqueue(kn);					\
} while(0)

#define	KN_HASHSIZE		64		/* XXX should be tunable */
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
#if 0
	&timer_filtops,			/* EVFILT_TIMER */
#else
	&bad_filtops,			/* EVFILT_TIMER */
#endif
	&bad_filtops,			/* EVFILT_MACHPORT */
	&fs_filtops		/* EVFILT_FS */
};

static int
filt_fileattach(struct knote *kn)
{
	
	return (fo_kqfilter(kn->kn_fp, kn, current_proc()));
}

static void
filt_kqdetach(struct knote *kn)
{
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;

	if (kq->kq_state & KQ_SEL)
	  return;

	KNOTE_DETACH(&kq->kq_sel.si_note, kn);
}

/*ARGSUSED*/
static int
filt_kqueue(struct knote *kn, long hint)
{
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;

	kn->kn_data = kq->kq_count;
	return (kn->kn_data > 0);
}

static int
filt_procattach(struct knote *kn)
{
	struct proc *p;

	p = pfind(kn->kn_id);
	if (p == NULL)
		return (ESRCH);
	if (! PRISON_CHECK(current_proc(), p))
		return (EACCES);

	kn->kn_ptr.p_proc = p;
	kn->kn_flags |= EV_CLEAR;		/* automatically set */

	/*
	 * internal flag indicating registration done by kernel
	 */
	if (kn->kn_flags & EV_FLAG1) {
		kn->kn_data = kn->kn_sdata;		/* ppid */
		kn->kn_fflags = NOTE_CHILD;
		kn->kn_flags &= ~EV_FLAG1;
	}

	/* XXX lock the proc here while adding to the list? */
	KNOTE_ATTACH(&p->p_klist, kn);

	return (0);
}

/*
 * The knote may be attached to a different process, which may exit,
 * leaving nothing for the knote to be attached to.  So when the process
 * exits, the knote is marked as DETACHED and also flagged as ONESHOT so
 * it will be deleted when read out.  However, as part of the knote deletion,
 * this routine is called, so a check is needed to avoid actually performing
 * a detach, because the original process does not exist any more.
 */
static void
filt_procdetach(struct knote *kn)
{
	struct proc *p = kn->kn_ptr.p_proc;

	if (kn->kn_status & KN_DETACHED)
		return;

	/* XXX locking?  this might modify another process. */
	KNOTE_DETACH(&p->p_klist, kn);
}

static int
filt_proc(struct knote *kn, long hint)
{
	u_int event;

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
	 * process is gone, so flag the event as finished.
	 */
	if (event == NOTE_EXIT) {
		kn->kn_status |= KN_DETACHED;
		kn->kn_flags |= (EV_EOF | EV_ONESHOT); 
		return (1);
	}

	/*
	 * process forked, and user wants to track the new process,
	 * so attach a new knote to it, and immediately report an
	 * event with the parent's pid.
	 */
	if ((event == NOTE_FORK) && (kn->kn_sfflags & NOTE_TRACK)) {
		struct kevent kev;
		int error;

		/*
		 * register knote with new process.
		 */
		kev.ident = hint & NOTE_PDATAMASK;	/* pid */
		kev.filter = kn->kn_filter;
		kev.flags = kn->kn_flags | EV_ADD | EV_ENABLE | EV_FLAG1;
		kev.fflags = kn->kn_sfflags;
		kev.data = kn->kn_id;			/* parent */
		kev.udata = kn->kn_kevent.udata;	/* preserve udata */
		error = kqueue_register(kn->kn_kq, &kev, NULL);
		if (error)
			kn->kn_fflags |= NOTE_TRACKERR;
	}

	return (kn->kn_fflags != 0);
}

#if 0
static void
filt_timerexpire(void *knx)
{
	struct knote *kn = knx;
	struct callout *calloutp;
	struct timeval tv;
	int tticks;

	kn->kn_data++;
	KNOTE_ACTIVATE(kn);

	if ((kn->kn_flags & EV_ONESHOT) == 0) {
		tv.tv_sec = kn->kn_sdata / 1000;
		tv.tv_usec = (kn->kn_sdata % 1000) * 1000;
		tticks = tvtohz(&tv);
		calloutp = (struct callout *)kn->kn_hook;
		callout_reset(calloutp, tticks, filt_timerexpire, kn);
	}
}

/*
 * data contains amount of time to sleep, in milliseconds
 */ 
static int
filt_timerattach(struct knote *kn)
{
	struct callout *calloutp;
	struct timeval tv;
	int tticks;

	if (kq_ncallouts >= kq_calloutmax)
		return (ENOMEM);
	kq_ncallouts++;

	tv.tv_sec = kn->kn_sdata / 1000;
	tv.tv_usec = (kn->kn_sdata % 1000) * 1000;
	tticks = tvtohz(&tv);

	kn->kn_flags |= EV_CLEAR;		/* automatically set */
	MALLOC(calloutp, struct callout *, sizeof(*calloutp),
	    M_KQUEUE, M_WAITOK);
	callout_init(calloutp);
	callout_reset(calloutp, tticks, filt_timerexpire, kn);
	kn->kn_hook = (caddr_t)calloutp;

	return (0);
}

static void
filt_timerdetach(struct knote *kn)
{
	struct callout *calloutp;

	calloutp = (struct callout *)kn->kn_hook;
	callout_stop(calloutp);
	FREE(calloutp, M_KQUEUE);
	kq_ncallouts--;
}

static int
filt_timer(struct knote *kn, long hint)
{

	return (kn->kn_data != 0);
}
#endif /* 0 */

/*
 * JMM - placeholder for not-yet-implemented filters
 */ 
static int
filt_badattach(struct knote *kn)
{
	return(EOPNOTSUPP);
}

#ifndef _SYS_SYSPROTO_H_
struct kqueue_args {
	int dummy;
};
#endif

int
kqueue(struct proc *p, struct kqueue_args *uap, register_t *retval)
{
	struct filedesc *fdp = p->p_fd;
	struct kqueue *kq;
	struct file *fp;
	int fd, error;

	error = falloc(p, &fp, &fd);
	if (error)
		return (error);
	fp->f_flag = FREAD | FWRITE;
	fp->f_type = DTYPE_KQUEUE;
	fp->f_ops = &kqueueops;
	kq = (struct kqueue *)_MALLOC(sizeof(struct kqueue), M_KQUEUE, M_WAITOK | M_ZERO);
	TAILQ_INIT(&kq->kq_head);
	fp->f_data = (caddr_t)kq;
	*retval = fd;
	if (fdp->fd_knlistsize < 0)
		fdp->fd_knlistsize = 0;		/* this process has a kq */
	kq->kq_fdp = fdp;
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct kqueue_portset_np_args {
	int	fd;
};
#endif
int
kqueue_portset_np(struct proc *p, struct kqueue_portset_np_args *uap, register_t *retval)
{
		/* JMM - Placeholder for now */
		return (EOPNOTSUPP);
}

#ifndef _SYS_SYSPROTO_H_
struct kqueue_from_portset_np_args {
	int	fd;
};
#endif
int
kqueue_from_portset_np(struct proc *p, struct kqueue_from_portset_np_args *uap, register_t *retval)
{
		/* JMM - Placeholder for now */
		return (EOPNOTSUPP);
}

#if !0
/* JMM - We don't implement this yet */
#define fhold(fp)
#define fdrop(fp, p)
#endif /* !0 */

#ifndef _SYS_SYSPROTO_H_
struct kevent_args {
	int	fd;
	const struct kevent *changelist;
	int	nchanges;
	struct	kevent *eventlist;
	int	nevents;
	const struct timespec *timeout;
};
#endif
int
kevent(struct proc *p, struct kevent_args *uap, register_t *retval)
{
	struct filedesc* fdp = p->p_fd;
	struct kqueue *kq;
	struct file *fp = NULL;
	struct timespec ts;
	int i, nerrors, error;

	if (uap->timeout != NULL) {
		error = copyin((caddr_t)uap->timeout, (caddr_t)&ts, sizeof(ts));
		if (error)
			goto done;
		uap->timeout = &ts;
	}

        if (((u_int)uap->fd) >= fdp->fd_nfiles ||
            (fp = fdp->fd_ofiles[uap->fd]) == NULL ||
	    (fp->f_type != DTYPE_KQUEUE))
		return (EBADF);

	fhold(fp);

	kq = (struct kqueue *)fp->f_data;
	nerrors = 0;

	while (uap->nchanges > 0) {
		int i;
		int n = uap->nchanges > KQ_NEVENTS ? KQ_NEVENTS : uap->nchanges;
		struct kevent kq_kev[n];

		error = copyin((caddr_t)uap->changelist, (caddr_t)kq_kev,
		    n * sizeof(struct kevent));
		if (error)
			goto done;
		for (i = 0; i < n; i++) {
			struct kevent *kevp = &kq_kev[i];

			kevp->flags &= ~EV_SYSFLAGS;
			error = kqueue_register(kq, kevp, p);
			if (error) {
				if (uap->nevents != 0) {
					kevp->flags = EV_ERROR;
					kevp->data = error;
					(void) copyout((caddr_t)kevp,
					    (caddr_t)uap->eventlist,
					    sizeof(*kevp));
					uap->eventlist++;
					uap->nevents--;
					nerrors++;
				} else {
					goto done;
				}
			}
		}
		uap->nchanges -= n;
		uap->changelist += n;
	}
	if (nerrors) {
        	*retval = nerrors;
		error = 0;
		goto done;
	}

	error = kqueue_scan(fp, uap->nevents, uap->eventlist, uap->timeout, retval, p);
done:
	if (fp != NULL)
		fdrop(fp, p);
	return (error);
}

int
kqueue_register(struct kqueue *kq, struct kevent *kev, struct proc *p)
{
	struct filedesc *fdp = kq->kq_fdp;
	struct filterops *fops;
	struct file *fp = NULL;
	struct knote *kn = NULL;
	int s, error = 0;

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

	if (fops->f_isfd) {
		/* validate descriptor */
		if ((u_int)kev->ident >= fdp->fd_nfiles ||
		    (fp = fdp->fd_ofiles[kev->ident]) == NULL)
			return (EBADF);
		fhold(fp);

		if (kev->ident < fdp->fd_knlistsize) {
			SLIST_FOREACH(kn, &fdp->fd_knlist[kev->ident], kn_link)
				if (kq == kn->kn_kq &&
				    kev->filter == kn->kn_filter)
					break;
		}
	} else {
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

	if (kn == NULL && ((kev->flags & EV_ADD) == 0)) {
		error = ENOENT;
		goto done;
	}

	/*
	 * kn now contains the matching knote, or NULL if no match
	 */
	if (kev->flags & EV_ADD) {

		if (kn == NULL) {
			kn = knote_alloc();
			if (kn == NULL) {
				error = ENOMEM;
				goto done;
			}
			kn->kn_fp = fp;
			kn->kn_kq = kq;
			kn->kn_fop = fops;

			/*
			 * apply reference count to knote structure, and
			 * do not release it at the end of this routine.
			 */
			fp = NULL;

			kn->kn_sfflags = kev->fflags;
			kn->kn_sdata = kev->data;
			kev->fflags = 0;
			kev->data = 0;
			kn->kn_kevent = *kev;

			knote_fdpattach(kn, fdp);
			if ((error = fops->f_attach(kn)) != 0) {
				knote_drop(kn, p);
				goto done;
			}
		} else {
			/*
			 * The user may change some filter values after the
			 * initial EV_ADD, but doing so will not reset any 
			 * filter which have already been triggered.
			 */
			kn->kn_sfflags = kev->fflags;
			kn->kn_sdata = kev->data;
			kn->kn_kevent.udata = kev->udata;
		}

		s = splhigh();
		if (kn->kn_fop->f_event(kn, 0))
			KNOTE_ACTIVATE(kn);
		splx(s);

	} else if (kev->flags & EV_DELETE) {
		kn->kn_fop->f_detach(kn);
		knote_drop(kn, p);
		goto done;
	}

	if ((kev->flags & EV_DISABLE) &&
	    ((kn->kn_status & KN_DISABLED) == 0)) {
		s = splhigh();
		kn->kn_status |= KN_DISABLED;
		splx(s);
	}

	if ((kev->flags & EV_ENABLE) && (kn->kn_status & KN_DISABLED)) {
		s = splhigh();
		kn->kn_status &= ~KN_DISABLED;
		if ((kn->kn_status & KN_ACTIVE) &&
		    ((kn->kn_status & KN_QUEUED) == 0))
			knote_enqueue(kn);
		splx(s);
	}

done:
	if (fp != NULL)
		fdrop(fp, p);
	return (error);
}

static int
kqueue_scan(struct file *fp, int maxevents, struct kevent *ulistp,
	const struct timespec *tsp, register_t *retval, struct proc *p)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;
	struct timeval atv, rtv, ttv;
	int s, count, timeout, error = 0;
	struct knote marker;

	count = maxevents;
	if (count == 0)
		goto done;

	if (tsp != NULL) {
		TIMESPEC_TO_TIMEVAL(&atv, tsp);
		if (itimerfix(&atv)) {
			error = EINVAL;
			goto done;
		}
		if (tsp->tv_sec == 0 && tsp->tv_nsec == 0)
			timeout = -1;
		else 
			timeout = atv.tv_sec > 24 * 60 * 60 ?
			    24 * 60 * 60 * hz : tvtohz(&atv);
		getmicrouptime(&rtv);
		timevaladd(&atv, &rtv);
	} else {
		atv.tv_sec = 0;
		atv.tv_usec = 0;
		timeout = 0;
	}
	goto start;

retry:
	if (atv.tv_sec || atv.tv_usec) {
		getmicrouptime(&rtv);
		if (timevalcmp(&rtv, &atv, >=))
			goto done;
		ttv = atv;
		timevalsub(&ttv, &rtv);
		timeout = ttv.tv_sec > 24 * 60 * 60 ?
			24 * 60 * 60 * hz : tvtohz(&ttv);
	}

start:
	s = splhigh();
	if (kq->kq_count == 0) {
		if (timeout < 0) { 
			error = EWOULDBLOCK;
		} else {
			kq->kq_state |= KQ_SLEEP;
			error = tsleep(kq, PSOCK | PCATCH, "kqread", timeout);
		}
		splx(s);
		if (error == 0)
			goto retry;
		/* don't restart after signals... */
		if (error == ERESTART)
			error = EINTR;
		else if (error == EWOULDBLOCK)
			error = 0;
		goto done;
	}

	/* JMM - This marker trick doesn't work with multiple threads */
	TAILQ_INSERT_TAIL(&kq->kq_head, &marker, kn_tqe); 
	while (count) {
		int maxkev = (count > KQ_NEVENTS) ? KQ_NEVENTS : count;
		struct kevent kq_kev[maxkev];
		struct kevent *kevp = kq_kev;
		struct knote *kn;
		int nkev = 0;

		while (nkev < maxkev) {
			kn = TAILQ_FIRST(&kq->kq_head);
			TAILQ_REMOVE(&kq->kq_head, kn, kn_tqe); 
			if (kn == &marker) {
				if (count == maxevents)
					goto retry;
				break;
			} else if (kn->kn_status & KN_DISABLED) {
				kn->kn_status &= ~KN_QUEUED;
				kq->kq_count--;
				continue;
			} else if ((kn->kn_flags & EV_ONESHOT) == 0 &&
				   kn->kn_fop->f_event(kn, 0) == 0) {
				kn->kn_status &= ~(KN_QUEUED | KN_ACTIVE);
				kq->kq_count--;
				continue;
			}

			*kevp = kn->kn_kevent;
			kevp++;
			nkev++;
			count--;

			if (kn->kn_flags & EV_ONESHOT) {
				kn->kn_status &= ~KN_QUEUED;
				kq->kq_count--;
				splx(s);
				kn->kn_fop->f_detach(kn);
				knote_drop(kn, p);
				s = splhigh();
			} else if (kn->kn_flags & EV_CLEAR) {
				kn->kn_data = 0;
				kn->kn_fflags = 0;
				kn->kn_status &= ~(KN_QUEUED | KN_ACTIVE);
				kq->kq_count--;
			} else {
				TAILQ_INSERT_TAIL(&kq->kq_head, kn, kn_tqe); 
			}
		}
		splx(s);
		error = copyout((caddr_t)kq_kev, (caddr_t)ulistp,
				sizeof(struct kevent) * nkev);
		if (kn == &marker)
			goto done;
		ulistp += nkev;
		s = splhigh();
		if (error)
			break;
	}
	TAILQ_REMOVE(&kq->kq_head, &marker, kn_tqe); 
	splx(s);
done:
        *retval = maxevents - count;
	return (error);
}

/*
 * XXX
 * This could be expanded to call kqueue_scan, if desired.
 */
/*ARGSUSED*/
static int
kqueue_read(struct file *fp, struct uio *uio, struct ucred *cred,
	int flags, struct proc *p)
{
	return (ENXIO);
}

/*ARGSUSED*/
static int
kqueue_write(struct file *fp, struct uio *uio, struct ucred *cred,
	 int flags, struct proc *p)
{
	return (ENXIO);
}

/*ARGSUSED*/
static int
kqueue_ioctl(struct file *fp, u_long com, caddr_t data, struct proc *p)
{
	return (ENOTTY);
}

/*ARGSUSED*/
static int
kqueue_select(struct file *fp, int which, void *wql, struct proc *p)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;
	int retnum = 0;
	int s = splnet();

	if (which == FREAD) {
                if (kq->kq_count) {
			retnum = 1;
		} else {
                        selrecord(p, &kq->kq_sel, wql);
			kq->kq_state |= KQ_SEL;
		}
	}
	splx(s);
	return (retnum);
}

/*ARGSUSED*/
static int
kqueue_close(struct file *fp, struct proc *p)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;
	struct filedesc *fdp = p->p_fd;
	struct knote **knp, *kn, *kn0;
	int i;

	for (i = 0; i < fdp->fd_knlistsize; i++) {
		knp = &SLIST_FIRST(&fdp->fd_knlist[i]);
		kn = *knp;
		while (kn != NULL) {
			kn0 = SLIST_NEXT(kn, kn_link);
			if (kq == kn->kn_kq) {
				kn->kn_fop->f_detach(kn);
				fdrop(kn->kn_fp, p);
				knote_free(kn);
				*knp = kn0;
			} else {
				knp = &SLIST_NEXT(kn, kn_link);
			}
			kn = kn0;
		}
	}
	if (fdp->fd_knhashmask != 0) {
		for (i = 0; i < fdp->fd_knhashmask + 1; i++) {
			knp = &SLIST_FIRST(&fdp->fd_knhash[i]);
			kn = *knp;
			while (kn != NULL) {
				kn0 = SLIST_NEXT(kn, kn_link);
				if (kq == kn->kn_kq) {
					kn->kn_fop->f_detach(kn);
		/* XXX non-fd release of kn->kn_ptr */
					knote_free(kn);
					*knp = kn0;
				} else {
					knp = &SLIST_NEXT(kn, kn_link);
				}
				kn = kn0;
			}
		}
	}
	_FREE(kq, M_KQUEUE);
	fp->f_data = NULL;

	return (0);
}

/*ARGSUSED*/
static int
kqueue_kqfilter(struct file *fp, struct knote *kn, struct proc *p)
{
	struct kqueue *kq = (struct kqueue *)kn->kn_fp->f_data;

	if (kn->kn_filter != EVFILT_READ || (kq->kq_state & KQ_SEL))
		return (1);

	kn->kn_fop = &kqread_filtops;
	KNOTE_ATTACH(&kq->kq_sel.si_note, kn);
	return (0);
}

/*ARGSUSED*/
int
kqueue_stat(struct file *fp, struct stat *st, struct proc *p)
{
	struct kqueue *kq = (struct kqueue *)fp->f_data;

	bzero((void *)st, sizeof(*st));
	st->st_size = kq->kq_count;
	st->st_blksize = sizeof(struct kevent);
	st->st_mode = S_IFIFO;
	return (0);
}

static void
kqueue_wakeup(struct kqueue *kq)
{

	if (kq->kq_state & KQ_SLEEP) {
		kq->kq_state &= ~KQ_SLEEP;
		wakeup(kq);
	}
	if (kq->kq_state & KQ_SEL) {
	  // kq->kq_state &= ~KQ_SEL; /* remove for now */
		selwakeup(&kq->kq_sel);
	} else
		KNOTE(&kq->kq_sel.si_note, 0);
}

void
klist_init(struct klist *list)
{
	SLIST_INIT(list);
}

/*
 * walk down a list of knotes, activating them if their event has triggered.
 */
void
knote(struct klist *list, long hint)
{
	struct knote *kn;

	SLIST_FOREACH(kn, list, kn_selnext)
		if (kn->kn_fop->f_event(kn, hint))
			KNOTE_ACTIVATE(kn);
}

/*
 * attach a knote to the specified list.  Return true if this is the first entry.
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
 */
int
knote_detach(struct klist *list, struct knote *kn)
{
	SLIST_REMOVE(list, kn, knote, kn_selnext);
	return SLIST_EMPTY(list);
}

/*
 * remove all knotes from a specified klist
 */
void
knote_remove(struct proc *p, struct klist *list)
{
	struct knote *kn;

	while ((kn = SLIST_FIRST(list)) != NULL) {
		kn->kn_fop->f_detach(kn);
		knote_drop(kn, p);
	}
}

/*
 * remove all knotes referencing a specified fd
 */
void
knote_fdclose(struct proc *p, int fd)
{
	struct filedesc *fdp = p->p_fd;
	struct klist *list = &fdp->fd_knlist[fd];

	knote_remove(p, list);
}

static void
knote_fdpattach(struct knote *kn, struct filedesc *fdp)
{
	struct klist *list;
	int size;

	if (! kn->kn_fop->f_isfd) {
		if (fdp->fd_knhashmask == 0)
			fdp->fd_knhash = hashinit(KN_HASHSIZE, M_KQUEUE,
			    &fdp->fd_knhashmask);
		list = &fdp->fd_knhash[KN_HASH(kn->kn_id, fdp->fd_knhashmask)];
		goto done;
	}

	if (fdp->fd_knlistsize <= kn->kn_id) {
		size = fdp->fd_knlistsize;
		while (size <= kn->kn_id)
			size += KQEXTENT;
		MALLOC(list, struct klist *,
		    size * sizeof(struct klist *), M_KQUEUE, M_WAITOK);
		bcopy((caddr_t)fdp->fd_knlist, (caddr_t)list,
		    fdp->fd_knlistsize * sizeof(struct klist *));
		bzero((caddr_t)list +
		    fdp->fd_knlistsize * sizeof(struct klist *),
		    (size - fdp->fd_knlistsize) * sizeof(struct klist *));
		if (fdp->fd_knlist != NULL)
			FREE(fdp->fd_knlist, M_KQUEUE);
		fdp->fd_knlistsize = size;
		fdp->fd_knlist = list;
	}
	list = &fdp->fd_knlist[kn->kn_id];
done:
	SLIST_INSERT_HEAD(list, kn, kn_link);
	kn->kn_status = 0;
}

/*
 * should be called at spl == 0, since we don't want to hold spl
 * while calling fdrop and free.
 */
static void
knote_drop(struct knote *kn, struct proc *p)
{
        struct filedesc *fdp = p->p_fd;
	struct klist *list;

	if (kn->kn_fop->f_isfd)
		list = &fdp->fd_knlist[kn->kn_id];
	else
		list = &fdp->fd_knhash[KN_HASH(kn->kn_id, fdp->fd_knhashmask)];

	SLIST_REMOVE(list, kn, knote, kn_link);
	if (kn->kn_status & KN_QUEUED)
		knote_dequeue(kn);
	if (kn->kn_fop->f_isfd)
		fdrop(kn->kn_fp, p);
	knote_free(kn);
}


static void
knote_enqueue(struct knote *kn)
{
	struct kqueue *kq = kn->kn_kq;
	int s = splhigh();

	KASSERT((kn->kn_status & KN_QUEUED) == 0, ("knote already queued"));

	TAILQ_INSERT_TAIL(&kq->kq_head, kn, kn_tqe); 
	kn->kn_status |= KN_QUEUED;
	kq->kq_count++;
	splx(s);
	kqueue_wakeup(kq);
}

static void
knote_dequeue(struct knote *kn)
{
	struct kqueue *kq = kn->kn_kq;
	int s = splhigh();

	KASSERT(kn->kn_status & KN_QUEUED, ("knote not queued"));

	TAILQ_REMOVE(&kq->kq_head, kn, kn_tqe); 
	kn->kn_status &= ~KN_QUEUED;
	kq->kq_count--;
	splx(s);
}

void
knote_init(void)
{
	knote_zone = zinit(sizeof(struct knote), 8192*sizeof(struct knote), 8192, "knote zone");
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
	zfree(knote_zone, (vm_offset_t)kn);
}

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/kern_event.h>
#include <sys/malloc.h>
#include <sys/sys_domain.h>
#include <sys/syslog.h>


int	raw_usrreq();
struct pr_usrreqs event_usrreqs;

struct protosw eventsw[] = {
     {
	  SOCK_RAW,	        &systemdomain,	SYSPROTO_EVENT,		PR_ATOMIC,
	  0,		0,		0,		0,
	  0,
	  0,		0,		0,		0,
	  0,		&event_usrreqs
     }
};

static
struct kern_event_head kern_event_head;

static u_long static_event_id = 0;

/*
 * Install the protosw's for the NKE manager.  Invoked at
 *  extension load time
 */
int
kern_event_init(void)
{
    int retval;

    if ((retval = net_add_proto(eventsw, &systemdomain)) == 0)
            return(KERN_SUCCESS);
    
    log(LOG_WARNING, "Can't install kernel events protocol (%d)\n", retval);
    return(retval);
}

int kev_attach(struct socket *so, int proto, struct proc *p)
{
     int error;
     struct kern_event_pcb  *ev_pcb;

     error = soreserve(so, KEV_SNDSPACE, KEV_RECVSPACE);
     if (error)
          return error;

     ev_pcb = _MALLOC(sizeof(struct kern_event_pcb), M_PCB, M_WAITOK);
     if (ev_pcb == 0)
	  return ENOBUFS;

     ev_pcb->ev_socket = so;
     ev_pcb->vendor_code_filter = 0xffffffff;

     so->so_pcb = (caddr_t) ev_pcb;
     LIST_INSERT_HEAD(&kern_event_head, ev_pcb, ev_link);

     return 0;
}


int kev_detach(struct socket *so)
{
     struct kern_event_pcb *ev_pcb = (struct kern_event_pcb *) so->so_pcb;

     if (ev_pcb != 0) {
          LIST_REMOVE(ev_pcb, ev_link);
          FREE(ev_pcb, M_PCB);
          so->so_pcb = 0;
     }

     return 0;
}


int  kev_post_msg(struct kev_msg *event_msg)
{
     struct mbuf *m, *m2;
     struct kern_event_pcb  *ev_pcb;
     struct kern_event_msg  *ev;
     char              *tmp;
     int               total_size;
     int               i;


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
	       return ENOBUFS;
	  }

	  sbappendrecord(&ev_pcb->ev_socket->so_rcv, m2);
	  sorwakeup(ev_pcb->ev_socket);
     }


     m_free(m);
     return 0;
}


int kev_control(so, cmd, data, ifp, p)
    struct socket *so;
    u_long cmd;
    caddr_t data;
    register struct ifnet *ifp;
    struct proc *p;
{
     struct kev_request *kev_req = (struct kev_request *) data;
     int  stat = 0;
     struct kern_event_pcb  *ev_pcb;
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

     default:
	  return EOPNOTSUPP;
     }

     return 0;
}


struct pr_usrreqs event_usrreqs = {
     pru_abort_notsupp, pru_accept_notsupp, kev_attach, pru_bind_notsupp, pru_connect_notsupp,
     pru_connect2_notsupp, kev_control, kev_detach, pru_disconnect_notsupp,
     pru_listen_notsupp, pru_peeraddr_notsupp, pru_rcvd_notsupp, pru_rcvoob_notsupp,
     pru_send_notsupp, pru_sense_null, pru_shutdown_notsupp, pru_sockaddr_notsupp,
     pru_sosend_notsupp, soreceive, sopoll
};



