/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 */
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)user.h	8.2 (Berkeley) 9/23/93
 */

#ifndef	_SYS_USER_H_
#define	_SYS_USER_H_

#include <sys/appleapiopts.h>
#ifndef KERNEL
/* stuff that *used* to be included by user.h, or is now needed */
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#endif
#include <sys/resourcevar.h>
#ifdef KERNEL_PRIVATE
#include <sys/signalvar.h>
#endif
#include <sys/vm.h>		/* XXX */
#include <sys/sysctl.h>
 
#ifdef KERNEL
#ifdef __APPLE_API_PRIVATE
#include <sys/eventvar.h>

/*
 *	Per-thread U area.
 */
struct uthread {
	int	*uu_ar0;		/* address of users saved R0 */

	/* syscall parameters, results and catches */
	u_int64_t uu_arg[8]; /* arguments to current system call */
	int	*uu_ap;			/* pointer to arglist */
    int uu_rval[2];

	/* thread exception handling */
	int	uu_code;			/* ``code'' to trap */
	char uu_cursig;			/* p_cursig for exc. */
	/* support for select - across system calls */
	struct _select {
		u_int32_t	*ibits, *obits; /* bits to select on */
		uint	nbytes;	/* number of bytes in ibits and obits */
		wait_queue_set_t wqset;	 /* cached across select calls */
		size_t allocsize;		 /* ...size of select cache */
		u_int64_t abstime;
		int poll;
		int error;
		int count;
		char * wql;
	} uu_select;			/* saved state for select() */
	/* to support continuations */
	union {
		int uu_nfs_myiod;    /* saved state for nfsd */
		struct _kevent_scan {
			kevent_callback_t call; /* per-event callback */
			kevent_continue_t cont; /* whole call continuation */
			uint64_t deadline;	/* computed deadline for operation */
			void *data;		/* caller's private data */
		} ss_kevent_scan;		/* saved state for kevent_scan() */
		struct _kevent {
			struct _kevent_scan scan;/* space for the generic data */
			struct fileproc *fp;	 /* fileproc we hold iocount on */
			int fd;			 /* filedescriptor for kq */
			register_t *retval;	 /* place to store return val */
			user_addr_t eventlist;	 /* user-level event list address */
			int eventcount;	 	/* user-level event count */
			int eventout;		 /* number of events output */
		} ss_kevent;			 /* saved state for kevent() */
	} uu_state;
  /* internal support for continuation framework */
    int (*uu_continuation)(int);
    int uu_pri;
    int uu_timo;
	int uu_flag;
	struct proc * uu_proc;
	void * uu_userstate;
	sigset_t uu_siglist;				/* signals pending for the thread */
	sigset_t  uu_sigwait;				/*  sigwait on this thread*/
	sigset_t  uu_sigmask;				/* signal mask for the thread */
	sigset_t  uu_oldmask;				/* signal mask saved before sigpause */
	thread_t uu_act;
	sigset_t  uu_vforkmask;				/* saved signal mask during vfork */

	TAILQ_ENTRY(uthread) uu_list;		/* List of uthreads in proc */

	struct kaudit_record 		*uu_ar;		/* audit record */
	struct task*	uu_aio_task;			/* target task for async io */

  /* network support for dlil layer locking */
	u_int32_t	dlil_incremented_read;
	lck_mtx_t	*uu_mtx;

        int		uu_lowpri_delay;

	struct ucred	*uu_ucred;		/* per thread credential */
        int		uu_defer_reclaims;
        vnode_t		uu_vreclaims;

#ifdef JOE_DEBUG
        int		uu_iocount;
        int		uu_vpindex;
        void 	*	uu_vps[32];
#endif
};

typedef struct uthread * uthread_t;

/* Definition of uu_flag */
#define	UT_SAS_OLDMASK	0x00000001	/* need to restore mask before pause */
#define	UT_NO_SIGMASK	0x00000002	/* exited thread; invalid sigmask */
#define UT_NOTCANCELPT	0x00000004             /* not a cancelation point */
#define UT_CANCEL	0x00000008             /* thread marked for cancel */
#define UT_CANCELED	0x00000010            /* thread cancelled */
#define UT_CANCELDISABLE 0x00000020            /* thread cancel disabled */

#define	UT_VFORK	0x02000000	/* thread has vfork children */
#define	UT_SETUID	0x04000000	/* thread is settugid() */
#define UT_WASSETUID	0x08000000	/* thread was settugid() (in vfork) */

#endif /* __APPLE_API_PRIVATE */

#endif	/* KERNEL */

/*
 * Per process structure containing data that isn't needed in core
 * when the process isn't running (esp. when swapped out).
 * This structure may or may not be at the same kernel address
 * in all processes.
 */
 
struct	user {
  /* NOT USED ANYMORE */
};

#endif	/* !_SYS_USER_H_ */
