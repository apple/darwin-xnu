/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1991, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)types.h	8.4 (Berkeley) 1/21/94
 */

#ifndef _SYS_TYPES_H_
#define	_SYS_TYPES_H_

#ifndef __ASSEMBLER__
#include <sys/cdefs.h>

/* Machine type dependent parameters. */
#include <machine/types.h>

#include <machine/ansi.h>
#include <machine/endian.h>

#ifndef _POSIX_SOURCE
typedef	unsigned char	u_char;
typedef	unsigned short	u_short;
typedef	unsigned int	u_int;
typedef	unsigned long	u_long;
typedef	unsigned short	ushort;		/* Sys V compatibility */
typedef	unsigned int	uint;		/* Sys V compatibility */
#endif

typedef	u_int64_t	u_quad_t;	/* quads */
typedef	int64_t		quad_t;
typedef	quad_t *	qaddr_t;

typedef	char *		caddr_t;	/* core address */
typedef	int32_t		daddr_t;	/* disk address */
typedef	int32_t		dev_t;		/* device number */
typedef	u_int32_t	fixpt_t;	/* fixed point number */
typedef	u_int32_t	gid_t;		/* group id */
typedef	u_int32_t	ino_t;		/* inode number */
typedef	long		key_t;		/* IPC key (for Sys V IPC) */
typedef	u_int16_t	mode_t;		/* permissions */
typedef	u_int16_t	nlink_t;	/* link count */
typedef	quad_t		off_t;		/* file offset */
typedef	int32_t		pid_t;		/* process id */
typedef quad_t		rlim_t;		/* resource limit */
typedef	int32_t		segsz_t;	/* segment size */
typedef	int32_t		swblk_t;	/* swap offset */
typedef	u_int32_t	uid_t;		/* user id */


#ifndef _POSIX_SOURCE
/* Major, minor numbers, dev_t's. */
#define	major(x)	((int32_t)(((u_int32_t)(x) >> 24) & 0xff))
#define	minor(x)	((int32_t)((x) & 0xffffff))
#define	makedev(x,y)	((dev_t)(((x) << 24) | (y)))
#endif

#ifndef	_BSD_CLOCK_T_DEFINED_
#define	_BSD_CLOCK_T_DEFINED_
typedef	_BSD_CLOCK_T_	clock_t;
#endif

#ifndef	_BSD_SIZE_T_DEFINED_
#define	_BSD_SIZE_T_DEFINED_
typedef	_BSD_SIZE_T_	size_t;
#endif

#ifndef	_BSD_SSIZE_T_DEFINED_
#define	_BSD_SSIZE_T_DEFINED_
typedef	_BSD_SSIZE_T_	ssize_t;
#endif

#ifndef	_BSD_TIME_T_DEFINED_
#define	_BSD_TIME_T_DEFINED_
typedef	_BSD_TIME_T_	time_t;
#endif

#ifndef _POSIX_SOURCE
#define	NBBY	8		/* number of bits in a byte */

/*
 * Select uses bit masks of file descriptors in longs.  These macros
 * manipulate such bit fields (the filesystem macros use chars).
 */
#ifndef	FD_SETSIZE
#define	FD_SETSIZE	1024
#endif

typedef int32_t	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#ifndef howmany
#define	howmany(x, y)	(((x) + ((y) - 1)) / (y))
#endif

typedef	struct fd_set {
	fd_mask	fds_bits[howmany(FD_SETSIZE, NFDBITS)];
} fd_set;

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define	FD_COPY(f, t)	bcopy(f, t, sizeof(*(f)))
#define	FD_ZERO(p)	bzero(p, sizeof(*(p)))

#if defined(__STDC__) && defined(KERNEL)
/*
 * Forward structure declarations for function prototypes.  We include the
 * common structures that cross subsystem boundaries here; others are mostly
 * used in the same place that the structure is defined.
 */
struct	proc;
struct	pgrp;
struct	ucred;
struct	rusage;
struct	file;
struct	buf;
struct	tty;
struct	uio;
#endif

#endif /* !_POSIX_SOURCE */
#endif /* __ASSEMBLER__ */

struct _pthread_handler_rec
{
	void           (*routine)(void *);  /* Routine to call */
	void           *arg;                 /* Argument to pass */
	struct _pthread_handler_rec *next;
};

#ifndef __POSIX_LIB__

#define __PTHREAD_SIZE__           596 
#define __PTHREAD_ATTR_SIZE__      36
#define __PTHREAD_MUTEXATTR_SIZE__ 8
#define __PTHREAD_MUTEX_SIZE__     40
#define __PTHREAD_CONDATTR_SIZE__  4
#define __PTHREAD_COND_SIZE__      24
#define __PTHREAD_ONCE_SIZE__      4


typedef struct _opaque_pthread_t { long sig; struct _pthread_handler_rec  *cleanup_stack; char opaque[__PTHREAD_SIZE__];} *pthread_t;

typedef struct _opaque_pthread_attr_t { long sig; char opaque[__PTHREAD_ATTR_SIZE__]; } pthread_attr_t;

typedef struct _opaque_pthread_mutexattr_t { long sig; char opaque[__PTHREAD_MUTEXATTR_SIZE__]; } pthread_mutexattr_t;

typedef struct _opaque_pthread_mutex_t { long sig; char opaque[__PTHREAD_MUTEX_SIZE__]; } pthread_mutex_t;

typedef struct _opaque_pthread_condattr_t { long sig; char opaque[__PTHREAD_CONDATTR_SIZE__]; } pthread_condattr_t;

typedef struct _opaque_pthread_cond_t { long sig;  char opaque[__PTHREAD_COND_SIZE__]; } pthread_cond_t;

typedef struct { long sig; char opaque[__PTHREAD_ONCE_SIZE__]; } pthread_once_t;

#endif /* __POSIX_LIB__ */

typedef unsigned long pthread_key_t;    /* Opaque 'pointer' */

#endif /* !_SYS_TYPES_H_ */
