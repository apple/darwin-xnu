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

#ifndef KERNEL
/* stuff that *used* to be included by user.h, or is now needed */
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ucred.h>
#include <sys/uio.h>
#endif
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/vm.h>		/* XXX */
#include <sys/sysctl.h>
 
#ifdef KERNEL
/*
 *	Per-thread U area.
 *
 *	It is likely that this structure contains no fields that must be
 *	saved between system calls.
 *
 * WARNING:  IF THE SIZE OF THIS STRUCT CHANGES YOU MUST CHANGE THE
 *           CONSTANT IN struct thread_act.bsd_space
 */
struct uthread {
	int	*uu_ar0;		/* address of users saved R0 */

	/* syscall parameters, results and catches */
	int	uu_arg[8];		/* arguments to current system call */
	int	*uu_ap;			/* pointer to arglist */
    int uu_rval[2];

	/* thread exception handling */
	int	uu_code;			/* ``code'' to trap */
	char uu_cursig;				/* p_cursig for exc. */
	int  uu_sig;				/* p_sig for exc. */

	/* support for syscalls which use continuations */
	union {
		struct _select {
			u_int32_t	*ibits, *obits; /* bits to select on */
			uint	nbytes;	/* number of bytes in ibits and obits */
			struct	timeval atv;
			int	poll;
			int error;
		} ss_select;			/* saved state for select() */
		struct _wait {
			int	f;
		} ss_wait;			/* saved state for wait?() */
	  struct _owait {
		int pid;
		int *status;
		int options;
		struct rusage *rusage;
	  } ss_owait;
	  int uu_nfs_myiod;    /* saved state for nfsd */
	} uu_state;

  /* internal support for continuation framework */
    int (*uu_continuation)(int);
    int uu_pri;
    int uu_timo;

};
typedef struct uthread * uthread_t;
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
