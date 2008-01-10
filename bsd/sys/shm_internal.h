/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*	$NetBSD: shm.h,v 1.15 1994/06/29 06:45:17 cgd Exp $	*/

/*
 * Copyright (c) 1994 Adam Glass
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Adam Glass.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * As defined+described in "X/Open System Interfaces and Headers"
 *                         Issue 4, p. XXX
 */

#ifndef _SYS_SHM_INTERNALH_
#define _SYS_SHM_INTERNALH_

#include <sys/shm.h>
#include <sys/cdefs.h>

#include <machine/types.h>

#if __DARWIN_ALIGN_NATURAL
#pragma options align=natural
#endif

struct user_shmid_ds {
	struct ipc_perm shm_perm;	/* operation permission structure */
	user_size_t	shm_segsz;	/* size of segment in bytes */
	pid_t		shm_lpid;	/* PID of last shared memory op */
	pid_t		shm_cpid;	/* PID of creator */
	short		shm_nattch;	/* number of current attaches */
	time_t		shm_atime;	/* time of last shmat() */
	time_t		shm_dtime;	/* time of last shmdt() */
	time_t		shm_ctime;	/* time of last change by shmctl() */
	user_addr_t	shm_internal;	/* reserved for kernel use */
};

#if __DARWIN_ALIGN_NATURAL
#pragma options align=reset
#endif

/*
 * System 5 style catch-all structure for shared memory constants that
 * might be of interest to user programs.  Also part of the ipcs interface.
 * Note: use of user_ssize_t intentional: permits 32 bit ipcs to provide
 * information about 64 bit programs shared segments.
 * Note 2: user_ssize_t is not that useful if it's not 64-bit,
 * so let's use int64_t explicitely...
 */
struct shminfo {
	int64_t	shmmax;		/* max shm segment size (bytes) */
	int64_t	shmmin;		/* min shm segment size (bytes) */
	int64_t	shmmni;		/* max number of shm identifiers */
	int64_t	shmseg;		/* max shm segments per process */
	int64_t	shmall;		/* max amount of shm (pages) */
};

#ifdef KERNEL
extern struct shminfo shminfo;
extern struct user_shmid_ds *shmsegs;

struct proc;

__BEGIN_DECLS

void	shmexit(struct proc *);
int	shmfork(struct proc *, struct proc *);
__private_extern__ void	shmexec(struct proc *);

__END_DECLS

#endif /* kernel */

#endif /* !_SYS_SHM_INTERNALH_ */
