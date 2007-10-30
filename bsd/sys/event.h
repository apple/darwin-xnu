/*
 * Copyright (c) 2003-2005 Apple Computer, Inc. All rights reserved.
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

#include <machine/types.h>
#include <sys/cdefs.h>
#include <stdint.h>

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
#define EVFILT_THREADMARKER	EVFILT_SYSCOUNT /* Internal use only */

#pragma pack(4)

struct kevent {
	uintptr_t	ident;		/* identifier for this event */
	short		filter;		/* filter for event */
	unsigned short	flags;		/* general flags */
	unsigned int	fflags;		/* filter-specific flags */
	intptr_t	data;		/* filter-specific data */
#ifdef KERNEL_PRIVATE
	user_addr_t	udata;		/* opaque user data identifier */
#else
	void		*udata;		/* opaque user data identifier */
#endif
};

#ifdef KERNEL_PRIVATE

struct user_kevent {
	uint64_t	ident;		/* identifier for this event */
	short		filter;		/* filter for event */
	unsigned short	flags;		/* general flags */
	unsigned int	fflags;		/* filter-specific flags */
	int64_t		data;		/* filter-specific data */
	user_addr_t	udata;		/* opaque user data identifier */
};

#endif

#pragma pack()

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
#define EV_FLAG0	0x1000		/* filter-specific flag */
#define EV_FLAG1	0x2000		/* filter-specific flag */

/* returned values */
#define EV_EOF		0x8000		/* EOF detected */
#define EV_ERROR	0x4000		/* error, data contains errno */

/*
 * Filter specific flags for EVFILT_READ
 *
 * The default behavior for EVFILT_READ is to make the "read" determination
 * relative to the current file descriptor read pointer. The EV_POLL
 * flag indicates the determination should be made via poll(2) semantics
 * (which always returns true for regular files - regardless of the amount
 * of unread data in the file).
 *
 * On input, EV_OOBAND specifies that only OOB data should be looked for.
 * The returned data count is the number of bytes beyond the current OOB marker.
 *
 * On output, EV_OOBAND indicates that OOB data is present
 * If it was not specified as an input parameter, then the data count is the
 * number of bytes before the current OOB marker. If at the marker, the
 * data count indicates the number of bytes available after it.  In either
 * case, it's the amount of data one could expect to receive next.
 */
#define EV_POLL	EV_FLAG0
#define EV_OOBAND	EV_FLAG1

/*
 * data/hint fflags for EVFILT_{READ|WRITE}, shared with userspace
 *
 * The default behavior for EVFILT_READ is to make the determination
 * realtive to the current file descriptor read pointer.
 */
#define NOTE_LOWAT	0x00000001		/* low water mark */
/*
 * data/hint fflags for EVFILT_VNODE, shared with userspace
 */
#define	NOTE_DELETE	0x00000001		/* vnode was removed */
#define	NOTE_WRITE	0x00000002		/* data contents changed */
#define	NOTE_EXTEND	0x00000004		/* size increased */
#define	NOTE_ATTRIB	0x00000008		/* attributes changed */
#define	NOTE_LINK	0x00000010		/* link count changed */
#define	NOTE_RENAME	0x00000020		/* vnode was renamed */
#define	NOTE_REVOKE	0x00000040		/* vnode access was revoked */

/*
 * data/hint fflags for EVFILT_PROC, shared with userspace
 */
#define	NOTE_EXIT	0x80000000		/* process exited */
#define	NOTE_FORK	0x40000000		/* process forked */
#define	NOTE_EXEC	0x20000000		/* process exec'd */
#define	NOTE_PCTRLMASK	0xf0000000		/* mask for hint bits */
#define	NOTE_PDATAMASK	0x000fffff		/* mask for pid */

/*
 * data/hint fflags for EVFILT_TIMER, shared with userspace.
 * The default is a (repeating) interval timer with the data
 * specifying the timeout interval in milliseconds.
 *
 * All timeouts are implicitly EV_CLEAR events.
 */
#define NOTE_SECONDS	0x00000001		/* data is seconds         */
#define NOTE_USECONDS	0x00000002		/* data is microseconds    */
#define NOTE_NSECONDS	0x00000004		/* data is nanoseconds     */
#define NOTE_ABSOLUTE	0x00000008		/* absolute timeout        */
						/* ... implicit EV_ONESHOT */
 
/* additional flags for EVFILT_PROC */
#define	NOTE_TRACK	0x00000001		/* follow across forks */
#define	NOTE_TRACKERR	0x00000002		/* could not track child */
#define	NOTE_CHILD	0x00000004		/* am a child process */



#ifndef KERNEL
/* Temporay solution for BootX to use inode.h till kqueue moves to vfs layer */
#include <sys/queue.h> 
struct knote;
SLIST_HEAD(klist, knote);
#endif

#ifdef KERNEL

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

TAILQ_HEAD(kqtailq, knote);	/* a list of "queued" events */

struct knote {
	int		kn_inuse;	/* inuse count */
	struct kqtailq	*kn_tq;		/* pointer to tail queue */
	TAILQ_ENTRY(knote)	kn_tqe;		/* linkage for tail queue */
	struct kqueue	*kn_kq;	/* which kqueue we are on */
	SLIST_ENTRY(knote)	kn_link;	/* linkage for search list */
	SLIST_ENTRY(knote)	kn_selnext;	/* klist element chain */
	union {
		struct		fileproc *p_fp;	/* file data pointer */
		struct		proc *p_proc;	/* proc pointer */
	} kn_ptr;
	struct			filterops *kn_fop;
	int			kn_status;	/* status bits */
	int			kn_sfflags;	/* saved filter flags */
	struct 			kevent kn_kevent;
	caddr_t			kn_hook;
	int			kn_hookid;
	int64_t			kn_sdata;	/* saved data field */

#define KN_ACTIVE	0x01			/* event has been triggered */
#define KN_QUEUED	0x02			/* event is on queue */
#define KN_DISABLED	0x04			/* event is disabled */
#define KN_DROPPING	0x08			/* knote is being dropped */
#define KN_USEWAIT	0x10			/* wait for knote use */
#define KN_DROPWAIT	0x20			/* wait for knote drop */

#define kn_id		kn_kevent.ident
#define kn_filter	kn_kevent.filter
#define kn_flags	kn_kevent.flags
#define kn_fflags	kn_kevent.fflags
#define kn_data		kn_kevent.data
#define kn_fp		kn_ptr.p_fp
};

struct filterops {
	int	f_isfd;		/* true if ident == filedescriptor */
	int	(*f_attach)(struct knote *kn);
	void	(*f_detach)(struct knote *kn);
	int	(*f_event)(struct knote *kn, long hint);
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
extern void	knote_fdclose(struct proc *p, int fd);

#endif /* !KERNEL_PRIVATE */

#else 	/* KERNEL */


struct timespec;

__BEGIN_DECLS
int     kqueue(void);
int     kevent(int kq, const struct kevent *changelist, int nchanges,
		    struct kevent *eventlist, int nevents,
		    const struct timespec *timeout);
__END_DECLS


#ifdef PRIVATE
#include <mach/port.h>

__BEGIN_DECLS
mach_port_t	kqueue_portset_np(int kq);
int	kqueue_from_portset_np(mach_port_t portset);
__END_DECLS
#endif /* PRIVATE */

#endif /* KERNEL */


#endif /* !_SYS_EVENT_H_ */
