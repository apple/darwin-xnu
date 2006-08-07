/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)file.h	8.3 (Berkeley) 1/9/95
 */

#ifndef _SYS_FILE_INTERNAL_H_
#define	_SYS_FILE_INTERNAL_H_

#include <sys/appleapiopts.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>

#ifdef KERNEL
#include <sys/errno.h>
#include <sys/queue.h>
#include <sys/cdefs.h>
#include <sys/lock.h>
#include <sys/file.h>

struct proc;
struct uio;
struct knote;
#ifdef __APPLE_API_UNSTABLE

struct file;


/*
 * Kernel descriptor table.
 * One entry for each open kernel vnode and socket.
 */
struct fileproc {
	int32_t	f_flags;
	int32_t f_iocount;
	struct fileglob * f_fglob;
	void *	f_waddr;
};

#define FILEPROC_NULL (struct fileproc *)0

#define FP_INCREATE 	0x0001
#define FP_INCLOSE 	0x0002
#define FP_INSELECT	0x0004
#define FP_INCHRREAD	0x0008
#define FP_WRITTEN	0x0010
#define FP_CLOSING	0x0020
#define FP_WAITCLOSE	0x0040
#define FP_AIOISSUED	0x0080
#define FP_WAITEVENT	0x0100


/* defns of close_internal */
#define CLOSEINT_LOCKED     1
#define CLOSEINT_WAITONCLOSE 2
#define CLOSEINT_NOFDRELSE  4
#define CLOSEINT_NOFDNOREF  8

struct fileglob {
	LIST_ENTRY(fileglob) f_list;/* list of active files */
	LIST_ENTRY(fileglob) f_msglist;/* list of active files */
	int32_t	fg_flag;		/* see fcntl.h */
	int32_t	fg_type;		/* descriptor type */
	int32_t	fg_count;	/* reference count */
	int32_t	fg_msgcount;	/* references from message queue */
	struct	ucred *fg_cred;	/* credentials associated with descriptor */
	struct	fileops {
		int	(*fo_read)	__P((struct fileproc *fp, struct uio *uio,
					    struct ucred *cred, int flags,
					    struct proc *p));
		int	(*fo_write)	__P((struct fileproc *fp, struct uio *uio,
					    struct ucred *cred, int flags,
					    struct proc *p));
#define	FOF_OFFSET	0x00000001	/* offset supplied to vn_write */
#define FOF_PCRED	0x00000002	/* cred from proc, not current thread */
		int	(*fo_ioctl)	__P((struct fileproc *fp, u_long com,
					    caddr_t data, struct proc *p));
		int	(*fo_select)	__P((struct fileproc *fp, int which,
						void *wql, struct proc *p));
		int	(*fo_close)	__P((struct fileglob *fg, struct proc *p));
		int	(*fo_kqfilter)	__P((struct fileproc *fp, struct knote *kn,
					     struct proc *p));
		int	(*fo_drain)	(struct fileproc *fp, struct proc *p);
	} *fg_ops;
	off_t	fg_offset;
	caddr_t	fg_data;		/* vnode or socket or SHM or semaphore */
	lck_mtx_t fg_lock;
	int32_t fg_lflags;		/* file global flags */
	unsigned int fg_lockpc[4];
	unsigned int fg_unlockpc[4];
};

/* file types */
#define	DTYPE_VNODE	1	/* file */
#define	DTYPE_SOCKET	2	/* communications endpoint */
#define	DTYPE_PSXSHM	3	/* POSIX Shared memory */
#define	DTYPE_PSXSEM	4	/* POSIX Semaphores */
#define DTYPE_KQUEUE	5	/* kqueue */
#define	DTYPE_PIPE	6	/* pipe */
#define DTYPE_FSEVENTS	7	/* fsevents */

/* defines for fg_lflags */
#define FG_TERM 	0x01	/* the fileglob is terminating .. */
#define FG_INSMSGQ 	0x02	/* insert to msgqueue pending .. */
#define FG_WINSMSGQ	0x04 	/* wait for the fielglob is in msgque */
#define FG_RMMSGQ	0x08 	/* the fileglob is being removed from msgqueue */
#define FG_WRMMSGQ	0x10 	/* wait for the fileglob to  be removed from msgqueue */


#ifdef __APPLE_API_PRIVATE
LIST_HEAD(filelist, fileglob);
LIST_HEAD(fmsglist, fileglob);
extern struct filelist filehead;	/* head of list of open files */
extern struct fmsglist fmsghead;	/* head of list of open files */
extern int maxfiles;			/* kernel limit on number of open files */
extern int nfiles;			/* actual number of open files */
#endif /* __APPLE_API_PRIVATE */


__BEGIN_DECLS
int fo_read(struct fileproc *fp, struct uio *uio,
	struct ucred *cred, int flags, struct proc *p);
int fo_write(struct fileproc *fp, struct uio *uio,
	struct ucred *cred, int flags, struct proc *p);
int fo_ioctl(struct fileproc *fp, u_long com, caddr_t data,
	struct proc *p);
int fo_select(struct fileproc *fp, int which, void *wql,
	struct proc *p);
int fo_close(struct fileglob *fg, struct proc *p);
int fo_kqfilter(struct fileproc *fp, struct knote *kn,
	struct proc *p);
void fileproc_drain(proc_t, struct fileproc *);
void fp_setflags(proc_t, struct fileproc *, int);
void fp_clearflags(proc_t, struct fileproc *, int);
int fp_drop(struct proc *p, int fd, struct fileproc *fp, int locked);
int fp_drop_written(proc_t p, int fd, struct fileproc *fp);
int fp_drop_event(proc_t p, int fd, struct fileproc *fp);
int fp_free(struct proc * p, int fd, struct fileproc * fp);
struct kqueue;
int fp_getfkq(struct proc *p, int fd, struct fileproc **resultfp, struct kqueue  **resultkq);
struct psemnode;
int fp_getfpsem(struct proc *p, int fd, struct fileproc **resultfp, struct psemnode  **resultpsem);
struct vnode;
int fp_getfvp(struct proc *p, int fd, struct fileproc **resultfp, struct vnode  **resultvp);
struct socket;
int fp_getfsock(struct proc *p, int fd, struct fileproc **resultfp, struct socket  **results);
int fp_lookup(struct proc *p, int fd, struct fileproc **resultfp, int locked);
int close_internal(struct proc *p, int fd, struct fileproc *fp, int flags);
int closef_locked(struct fileproc *fp, struct fileglob *fg, struct proc *p);
void fg_insertuipc(struct fileglob * fg);
void fg_removeuipc(struct fileglob * fg);
__END_DECLS

#endif /* __APPLE_API_UNSTABLE */

#endif /* KERNEL */

#endif /* !_SYS_FILE_INTERNAL_H_ */
