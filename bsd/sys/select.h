/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/_types.h>

/*
 * The time_t and suseconds_t types shall be defined as described in
 * <sys/types.h>
 * The sigset_t type shall be defined as described in <signal.h>
 * The timespec structure shall be defined as described in <time.h>
 */
#ifndef	_TIME_T
#define	_TIME_T
typedef	__darwin_time_t		time_t;
#endif

#ifndef _SUSECONDS_T
#define _SUSECONDS_T
typedef __darwin_suseconds_t	suseconds_t;
#endif

#ifndef _SIGSET_T
#define _SIGSET_T
typedef __darwin_sigset_t	sigset_t;
#endif

#ifndef _TIMESPEC
#define _TIMESPEC
struct timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif

/*
 * [XSI] The <sys/select.h> header shall define the fd_set type as a structure.
 * [XSI] FD_CLR, FD_ISSET, FD_SET, FD_ZERO may be declared as a function, or
 *	 defined as a macro, or both
 * [XSI] FD_SETSIZE shall be defined as a macro
 *
 * Note:	We use _FD_SET to protect all select related
 *		types and macros
 */
#ifndef _FD_SET
#define	_FD_SET

/*
 * Select uses bit masks of file descriptors in longs.  These macros
 * manipulate such bit fields (the filesystem macros use chars).  The
 * extra protection here is to permit application redefinition above
 * the default size.
 */
#ifndef	FD_SETSIZE
#define	FD_SETSIZE	1024
#endif

#define	__DARWIN_NBBY	8				/* bits in a byte */
#define __DARWIN_NFDBITS	(sizeof(__int32_t) * __DARWIN_NBBY) /* bits per mask */
#define	__DARWIN_howmany(x, y) (((x) + ((y) - 1)) / (y))	/* # y's == x bits? */

typedef	struct fd_set {
	__int32_t	fds_bits[__DARWIN_howmany(FD_SETSIZE, __DARWIN_NFDBITS)];
} fd_set;

#define	FD_SET(n, p)	((p)->fds_bits[(n)/__DARWIN_NFDBITS] |= (1<<((n) % __DARWIN_NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/__DARWIN_NFDBITS] &= ~(1<<((n) % __DARWIN_NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/__DARWIN_NFDBITS] & (1<<((n) % __DARWIN_NFDBITS)))
#if __GNUC__ > 3 || __GNUC__ == 3 && __GNUC_MINOR__ >= 3
/*
 * Use the built-in bzero function instead of the library version so that
 * we do not pollute the namespace or introduce prototype warnings.
 */
#define	FD_ZERO(p)	__builtin_bzero(p, sizeof(*(p)))
#else
#define	FD_ZERO(p)	bzero(p, sizeof(*(p)))
#endif
#ifndef _POSIX_C_SOURCE
#define	FD_COPY(f, t)	bcopy(f, t, sizeof(*(f)))
#endif	/* !_POSIX_C_SOURCE */

#endif	/* !_FD_SET */

#ifdef KERNEL
#ifdef KERNEL_PRIVATE
#include <kern/wait_queue.h>
#endif
#include <sys/kernel_types.h>

#include <sys/event.h>

/*
 * Used to maintain information about processes that wish to be
 * notified when I/O becomes possible.
 */
#ifdef KERNEL_PRIVATE
struct selinfo {
	struct  wait_queue si_wait_queue;	/* wait_queue for wait/wakeup */
	struct klist si_note;		/* JMM - temporary separation */
	u_int	si_flags;		/* see below */
};

#define	SI_COLL		0x0001		/* collision occurred */
#define	SI_RECORDED	0x0004		/* select has been recorded */ 
#define	SI_INITED	0x0008		/* selinfo has been inited */ 
#define	SI_CLEAR	0x0010		/* selinfo has been cleared */ 

#else
struct selinfo;
#endif

__BEGIN_DECLS

void	selrecord(proc_t selector, struct selinfo *, void *);
void	selwakeup(struct selinfo *);
void	selthreadclear(struct selinfo *);

__END_DECLS

#endif /* KERNEL */


#ifndef KERNEL
#ifndef _POSIX_C_SOURCE
#include <sys/types.h>
#ifndef  __MWERKS__
#include <signal.h>
#endif /* __MWERKS__ */
#include <sys/time.h>
#endif	/* !_POSIX_C_SOURCE */

__BEGIN_DECLS
#ifndef  __MWERKS__
int	 pselect(int, fd_set * __restrict, fd_set * __restrict,
		fd_set * __restrict, const struct timespec * __restrict,
		const sigset_t * __restrict);
#endif /* __MWERKS__ */
int	 select(int, fd_set * __restrict, fd_set * __restrict,
		fd_set * __restrict, struct timeval * __restrict);
__END_DECLS
#endif /* ! KERNEL */

#endif /* !_SYS_SELECT_H_ */
