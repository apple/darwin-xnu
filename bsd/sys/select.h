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
 */
/*
 * Copyright (c) 1992, 1993
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
 *	@(#)select.h	8.2 (Berkeley) 1/4/94
 */

#ifndef _SYS_SELECT_H_
#define	_SYS_SELECT_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>

#ifdef __APPLE_API_UNSTABLE

__BEGIN_DECLS

#ifdef KERNEL
#include <kern/wait_queue.h>
#endif

#include <sys/event.h>

/*
 * Used to maintain information about processes that wish to be
 * notified when I/O becomes possible.
 */
struct selinfo {
#ifdef KERNEL
	union {
		struct  wait_queue wait_queue;	/* wait_queue for wait/wakeup */
		struct klist note;		/* JMM - temporary separation */
	} si_u;
#define si_wait_queue si_u.wait_queue
#define si_note si_u.note
#else
	char  si_wait_queue[16];
#endif
	u_int	si_flags;		/* see below */
};

#define	SI_COLL		0x0001		/* collision occurred */
#define	SI_RECORDED	0x0004		/* select has been recorded */ 
#define	SI_INITED	0x0008		/* selinfo has been inited */ 
#define	SI_CLEAR	0x0010		/* selinfo has been cleared */ 

#ifdef KERNEL
struct proc;

void	selrecord __P((struct proc *selector, struct selinfo *, void *));
void	selwakeup __P((struct selinfo *));
void	selthreadclear __P((struct selinfo *));
#endif /* KERNEL */

__END_DECLS

#endif /* __APPLE_API_UNSTABLE */

#ifndef KERNEL
#include <sys/types.h>
#ifndef  __MWERKS__
#include <signal.h>
#endif /* __MWERKS__ */
#include <sys/time.h>

__BEGIN_DECLS
#ifndef  __MWERKS__
int	 pselect(int, fd_set *, fd_set *, fd_set *,
	    const struct timespec *, const sigset_t *);
#endif /* __MWERKS__ */
int	 select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
__END_DECLS
#endif /* ! KERNEL */

#endif /* !_SYS_SELECT_H_ */
