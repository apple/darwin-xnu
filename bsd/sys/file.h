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

#ifndef _SYS_FILE_H_
#define	_SYS_FILE_H_

#include <sys/appleapiopts.h>
#include <sys/fcntl.h>
#include <sys/unistd.h>

#ifdef KERNEL
#include <sys/errno.h>
#include <sys/queue.h>
#include <sys/cdefs.h>

struct proc;
struct uio;
#ifdef __APPLE_API_UNSTABLE

/*
 * Kernel descriptor table.
 * One entry for each open kernel vnode and socket.
 */
struct file {
	LIST_ENTRY(file) f_list;/* list of active files */
	short	f_flag;		/* see fcntl.h */
#define	DTYPE_VNODE	1	/* file */
#define	DTYPE_SOCKET	2	/* communications endpoint */
#define	DTYPE_PSXSHM	3	/* POSIX Shared memory */
#define	DTYPE_PSXSEM	4	/* POSIX Semaphores */
	short	f_type;		/* descriptor type */
	short	f_count;	/* reference count */
	short	f_msgcount;	/* references from message queue */
	struct	ucred *f_cred;	/* credentials associated with descriptor */
	struct	fileops {
		int	(*fo_read)	__P((struct file *fp, struct uio *uio,
					    struct ucred *cred, int flags,
					    struct proc *p));
		int	(*fo_write)	__P((struct file *fp, struct uio *uio,
					    struct ucred *cred, int flags,
					    struct proc *p));
#define	FOF_OFFSET	1
		int	(*fo_ioctl)	__P((struct file *fp, u_long com,
					    caddr_t data, struct proc *p));
		int	(*fo_select)	__P((struct file *fp, int which,
						void *wql, struct proc *p));
		int	(*fo_close)	__P((struct file *fp, struct proc *p));
	} *f_ops;
	off_t	f_offset;
	caddr_t	f_data;		/* vnode or socket or SHM or semaphore */
};

#ifdef __APPLE_API_PRIVATE
LIST_HEAD(filelist, file);
extern struct filelist filehead;	/* head of list of open files */
extern int maxfiles;			/* kernel limit on number of open files */
extern int nfiles;			/* actual number of open files */
#endif /* __APPLE_API_PRIVATE */

__BEGIN_DECLS
int fref __P((struct file *));	/* take a reference on file pointer */
int frele __P((struct file *));	/* release a reference on file pointer */
int fcount __P((struct file *));	/* returns the reference count */

static __inline int fo_read __P((struct file *fp, struct uio *uio,
	struct ucred *cred, int flags, struct proc *p));
static __inline int fo_write __P((struct file *fp, struct uio *uio,
	struct ucred *cred, int flags, struct proc *p));
static __inline int fo_ioctl __P((struct file *fp, u_long com, caddr_t data,
	struct proc *p));
static __inline int fo_select __P((struct file *fp, int which, void *wql,
	struct proc *p));
static __inline int fo_close __P((struct file *fp, struct proc *p));

static __inline int
fo_read(struct file *fp, struct uio *uio, struct ucred *cred, int flags, struct proc *p)
{
	int error;

	if ((error = fref(fp)) == -1)
		return (EBADF);
	error = (*fp->f_ops->fo_read)(fp, uio, cred, flags, p);
	frele(fp);
	return (error);
}

static __inline int
fo_write(struct file *fp, struct uio *uio, struct ucred *cred, int flags, struct proc *p)
{
	int error;

	if ((error = fref(fp)) == -1)
		return (EBADF);
	error = (*fp->f_ops->fo_write)(fp, uio, cred, flags, p);
	frele(fp);
	return (error);
}

static __inline int 
fo_ioctl(struct file *fp, u_long com, caddr_t data, struct proc *p)
{
	int error;   

	if ((error = fref(fp)) == -1)
		return (EBADF);
	error = (*fp->f_ops->fo_ioctl)(fp, com, data, p);
	frele(fp);
	return (error);
}       

static __inline int
fo_select(struct file *fp, int which, void *wql, struct proc *p)
{       
	int error;

	error = (*fp->f_ops->fo_select)(fp, which, wql, p);
	return (error);
}

static __inline int
fo_close(struct file *fp, struct proc *p)
{       

	return ((*fp->f_ops->fo_close)(fp, p));
}
__END_DECLS

#endif /* __APPLE_API_UNSTABLE */

#endif /* KERNEL */

#endif /* !_SYS_FILE_H_ */
