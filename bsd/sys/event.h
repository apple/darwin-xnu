/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
 *
 *	$FreeBSD: src/sys/sys/event.h,v 1.5.2.5 2001/12/14 19:21:22 jlemon Exp $
 */

#ifndef _SYS_EVENT_H_
#define _SYS_EVENT_H_

#define EVFILT_READ		(-1)
#define EVFILT_WRITE		(-2)
#define EVFILT_AIO		(-3)	/* attached to aio requests */
#define EVFILT_VNODE		(-4)	/* attached to vnodes */
#define EVFILT_PROC		(-5)	/* attached to struct proc */
#define EVFILT_SIGNAL		(-6)	/* attached to struct proc */
#define EVFILT_TIMER		(-7)	/* timers */
#define EVFILT_MACHPORT		(-8)	/* Mach ports */
#define EVFILT_FS		(-9)	/* Filesystem events */

#define EVFILT_SYSCOUNT		9

struct kevent {
	uintptr_t	ident;		/* identifier for this event */
	short		filter;		/* filter for event */
	u_short		flags;
	u_int		fflags;
	intptr_t	data;
	void		*udata;		/* opaque user data identifier */
};

#define EV_SET(kevp, a, b, c, d, e, f) do {	\
	struct kevent *__kevp__ = (kevp);	\
	__kevp__->ident = (a);			\
	__kevp__->filter = (b);			\
	__kevp__->flags = (c);			\
	__kevp__->fflags = (d);			\
	__kevp__->data = (e);			\
	__kevp__->udata = (f);			\
} while(0)

/* actions */
#define EV_ADD		0x0001		/* add event to kq (implies enable) */
#define EV_DELETE	0x0002		/* delete event from kq */
#define EV_ENABLE	0x0004		/* enable event */
#define EV_DISABLE	0x0008		/* disable event (not reported) */

/* flags */
#define EV_ONESHOT	0x0010		/* only report one occurrence */
#define EV_CLEAR	0x0020		/* clear event state after reporting */

#define EV_SYSFLAGS	0xF000		/* reserved by system */
#define EV_FLAG1	0x2000		/* filter-specific flag */

/* returned values */
#define EV_EOF		0x8000		/* EOF detected */
#define EV_ERROR	0x4000		/* error, data contains errno */

/*
 * data/hint flags for EVFILT_{READ|WRITE}, shared with userspace
 */
#define NOTE_LOWAT	0x0001			/* low water mark */

/*
 * data/hint flags for EVFILT_VNODE, shared with userspace
 */
#define	NOTE_DELETE	0x0001			/* vnode was removed */
#define	NOTE_WRITE	0x0002			/* data contents changed */
#define	NOTE_EXTEND	0x0004			/* size increased */
#define	NOTE_ATTRIB	0x0008			/* attributes changed */
#define	NOTE_LINK	0x0010			/* link count changed */
#define	NOTE_RENAME	0x0020			/* vnode was renamed */
#define	NOTE_REVOKE	0x0040			/* vnode access was revoked */

/*
 * data/hint flags for EVFILT_PROC, shared with userspace
 */
#define	NOTE_EXIT	0x80000000		/* process exited */
#define	NOTE_FORK	0x40000000		/* process forked */
#define	NOTE_EXEC	0x20000000		/* process exec'd */
#define	NOTE_PCTRLMASK	0xf0000000		/* mask for hint bits */
#define	NOTE_PDATAMASK	0x000fffff		/* mask for pid */

/* additional flags for EVFILT_PROC */
#define	NOTE_TRACK	0x00000001		/* follow across forks */
#define	NOTE_TRACKERR	0x00000002		/* could not track child */
#define	NOTE_CHILD	0x00000004		/* am a child process */


#ifdef KERNEL_PRIVATE

#include <sys/queue.h> 

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_KQUEUE);
#endif

/*
 * Flag indicating hint is a signal.  Used by EVFILT_SIGNAL, and also
 * shared by EVFILT_PROC  (all knotes attached to p->p_klist)
 */
#define NOTE_SIGNAL	0x08000000

struct knote {
	/* JMM - line these up with wait_queue_link */
#if 0
	struct			wait_queue_link kn_wql;	 /* wait queue linkage */
#else
	SLIST_ENTRY(knote)	kn_selnext;	/* klist element chain */
	void		       *kn_type;	/* knote vs. thread */
	struct klist	       *kn_list;	/* pointer to list we are on */
	SLIST_ENTRY(knote)	kn_link;	/* members of kqueue */
	struct			kqueue *kn_kq;	/* which kqueue we are on */
#endif
	TAILQ_ENTRY(knote)	kn_tqe;		/* ...ready to process */
	union {
		struct		file *p_fp;	/* file data pointer */
		struct		proc *p_proc;	/* proc pointer */
	} kn_ptr;
	struct			filterops *kn_fop;
	int			kn_status;
	int			kn_sfflags;	/* saved filter flags */
	struct 			kevent kn_kevent;
	intptr_t		kn_sdata;	/* saved data field */
	caddr_t			kn_hook;
#define KN_ACTIVE	0x01			/* event has been triggered */
#define KN_QUEUED	0x02			/* event is on queue */
#define KN_DISABLED	0x04			/* event is disabled */
#define KN_DETACHED	0x08			/* knote is detached */

#define kn_id		kn_kevent.ident
#define kn_filter	kn_kevent.filter
#define kn_flags	kn_kevent.flags
#define kn_fflags	kn_kevent.fflags
#define kn_data		kn_kevent.data
#define kn_fp		kn_ptr.p_fp
};

struct filterops {
	int	f_isfd;		/* true if ident == filedescriptor */
	int	(*f_attach)	__P((struct knote *kn));
	void	(*f_detach)	__P((struct knote *kn));
	int	(*f_event)	__P((struct knote *kn, long hint));
};

struct proc;

SLIST_HEAD(klist, knote);
extern void	klist_init(struct klist *list);

#define KNOTE(list, hint)	knote(list, hint)
#define KNOTE_ATTACH(list, kn)	knote_attach(list, kn)
#define KNOTE_DETACH(list, kn)	knote_detach(list, kn)


extern void	knote(struct klist *list, long hint);
extern int	knote_attach(struct klist *list, struct knote *kn);
extern int	knote_detach(struct klist *list, struct knote *kn);
extern void	knote_remove(struct proc *p, struct klist *list);
extern void	knote_fdclose(struct proc *p, int fd);
extern int 	kqueue_register(struct kqueue *kq,
		    struct kevent *kev, struct proc *p);

#else 	/* !KERNEL_PRIVATE */

/*
 * This is currently visible to userland to work around broken
 * programs which pull in <sys/proc.h> or <sys/select.h>.
 */
#include <sys/queue.h> 
struct knote;
SLIST_HEAD(klist, knote);

#include <sys/cdefs.h>
struct timespec;

__BEGIN_DECLS
int     kqueue __P((void));
int     kevent __P((int kq, const struct kevent *changelist, int nchanges,
		    struct kevent *eventlist, int nevents,
		    const struct timespec *timeout));
__END_DECLS

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
#include <mach/mach.h>

__BEGIN_DECLS
mach_port_t	kqueue_portset_np __P((int kq));
int	kqueue_from_portset_np __P((mach_port_t portset));
__END_DECLS
#endif /* __APPLE_API_PRIVATE */

#endif /* !KERNEL_PRIVATE */

#endif /* !_SYS_EVENT_H_ */
