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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)resource.h	8.2 (Berkeley) 1/4/94
 */

#ifndef _SYS_RESOURCE_H_
#define	_SYS_RESOURCE_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>
#include <sys/_types.h>


/* [XSI] The timeval structure shall be defined as described in
 * <sys/time.h>
 *
 * NB: We use __darwin_time_t and __darwin_suseconds_t here to avoid
 * improperly exposing time_t and suseconds_t into the namespace.
 */
#ifndef _TIMEVAL
#define _TIMEVAL
struct timeval {
	__darwin_time_t		tv_sec;		/* seconds */
	__darwin_suseconds_t	tv_usec;	/* and microseconds */
};
#endif

/* The id_t type shall be defined as described in <sys/types.h> */
#ifndef _ID_T
#define _ID_T
typedef __darwin_id_t	id_t;		/* can hold pid_t, gid_t, or uid_t */
#endif


/*
 * Resource limit type (low 63 bits, excluding the sign bit)
 */
typedef __int64_t	rlim_t;


/*****
 * PRIORITY
 */

/*
 * Possible values of the first parameter to getpriority()/setpriority(),
 * used to indicate the type of the second parameter.
 */
#define	PRIO_PROCESS	0		/* Second argument is a PID */
#define	PRIO_PGRP	1		/* Second argument is a GID */
#define	PRIO_USER	2		/* Second argument is a UID */

#ifndef _POSIX_C_SOURCE
/*
 * Range limitations for the value of the third parameter to setpriority().
 */
#define	PRIO_MIN	-20
#define	PRIO_MAX	20
#endif	/* !_POSIX_C_SOURCE */



/*****
 * RESOURCE USAGE
 */

/*
 * Possible values of the first parameter to getrusage(), used to indicate
 * the scope of the information to be returned.
 */
#define	RUSAGE_SELF	0		/* Current process information */
#define	RUSAGE_CHILDREN	-1		/* Current process' children */

/*
 * A structure representing an accounting of resource utilization.  The
 * address of an instance of this structure is the second parameter to
 * getrusage().
 *
 * Note: All values other than ru_utime and ru_stime are implementaiton
 *       defined and subject to change in a future release.  Their use
 *       is discouraged for standards compliant programs.
 */
struct	rusage {
	struct timeval ru_utime;	/* user time used */
	struct timeval ru_stime;	/* system time used */
#ifdef _POSIX_C_SOURCE
	long	ru_opaque[14];		/* implementation defined */
#else	/* !_POSIX_C_SOURCE */
	/*
	 * Informational aliases for source compatibility with programs
	 * that need more information than that provided by standards,
	 * and which do not mind being OS-dependent.
	 */
	long	ru_maxrss;		/* max resident set size */
#define	ru_first	ru_ixrss	/* internal: ruadd() range start */
	long	ru_ixrss;		/* integral shared memory size */
	long	ru_idrss;		/* integral unshared data " */
	long	ru_isrss;		/* integral unshared stack " */
	long	ru_minflt;		/* page reclaims */
	long	ru_majflt;		/* page faults */
	long	ru_nswap;		/* swaps */
	long	ru_inblock;		/* block input operations */
	long	ru_oublock;		/* block output operations */
	long	ru_msgsnd;		/* messages sent */
	long	ru_msgrcv;		/* messages received */
	long	ru_nsignals;		/* signals received */
	long	ru_nvcsw;		/* voluntary context switches */
	long	ru_nivcsw;		/* involuntary " */
#define	ru_last		ru_nivcsw	/* internal: ruadd() range end */
#endif	/* !_POSIX_C_SOURCE */
};



// LP64todo - should this move?
#ifdef KERNEL
#include <machine/types.h>	/* user_time_t */

/* LP64 version of struct timeval.  time_t is a long and must grow when 
 * we're dealing with a 64-bit process.
 * WARNING - keep in sync with struct timeval
 */

#if __DARWIN_ALIGN_NATURAL
#pragma options align=natural
#endif

struct user_rusage_timeval {
	user_time_t		tv_sec;		/* seconds */
	__darwin_suseconds_t	tv_usec;	/* and microseconds */
};	
struct	user_rusage {
	struct user_rusage_timeval ru_utime;	/* user time used */
	struct user_rusage_timeval ru_stime;	/* system time used */
	user_long_t	ru_maxrss;		/* max resident set size */
	user_long_t	ru_ixrss;		/* integral shared memory size */
	user_long_t	ru_idrss;		/* integral unshared data " */
	user_long_t	ru_isrss;		/* integral unshared stack " */
	user_long_t	ru_minflt;		/* page reclaims */
	user_long_t	ru_majflt;		/* page faults */
	user_long_t	ru_nswap;		/* swaps */
	user_long_t	ru_inblock;		/* block input operations */
	user_long_t	ru_oublock;		/* block output operations */
	user_long_t	ru_msgsnd;		/* messages sent */
	user_long_t	ru_msgrcv;		/* messages received */
	user_long_t	ru_nsignals;	/* signals received */
	user_long_t	ru_nvcsw;		/* voluntary context switches */
	user_long_t	ru_nivcsw;		/* involuntary " */
};

#if __DARWIN_ALIGN_NATURAL
#pragma options align=reset
#endif

#endif // KERNEL


/*****
 * RESOURCE LIMITS
 */

/*
 * Symbolic constants for resource limits; since all limits are representable
 * as a type rlim_t, we are permitted to define RLIM_SAVED_* in terms of
 * RLIM_INFINITY.
 */
#define	RLIM_INFINITY	(((__uint64_t)1 << 63) - 1)	/* no limit */
#define	RLIM_SAVED_MAX	RLIM_INFINITY	/* Unrepresentable hard limit */
#define	RLIM_SAVED_CUR	RLIM_INFINITY	/* Unrepresentable soft limit */

/*
 * Possible values of the first parameter to getrlimit()/setrlimit(), to
 * indicate for which resource the operation is being performed.
 */
#define	RLIMIT_CPU	0		/* cpu time per process, in ms */
#define	RLIMIT_FSIZE	1		/* file size */
#define	RLIMIT_DATA	2		/* data segment size */
#define	RLIMIT_STACK	3		/* stack size */
#define	RLIMIT_CORE	4		/* core file size */
#define	RLIMIT_AS	5		/* address space (resident set size) */
#ifndef _POSIX_C_SOURCE
#define	RLIMIT_RSS	RLIMIT_AS	/* source compatibility alias */
#define	RLIMIT_MEMLOCK	6		/* locked-in-memory address space */
#define	RLIMIT_NPROC	7		/* number of processes */
#endif	/* !_POSIX_C_SOURCE */
#define	RLIMIT_NOFILE	8		/* number of open files */
#ifndef _POSIX_C_SOURCE
#define	RLIM_NLIMITS	9		/* total number of resource limits */
#endif	/* !_POSIX_C_SOURCE */

/*
 * A structure representing a resource limit.  The address of an instance
 * of this structure is the second parameter to getrlimit()/setrlimit().
 */
struct rlimit {
	rlim_t	rlim_cur;		/* current (soft) limit */
	rlim_t	rlim_max;		/* maximum value for rlim_cur */
};


#ifndef KERNEL

__BEGIN_DECLS
int	getpriority(int, id_t);
int	getrlimit(int, struct rlimit *);
int	getrusage(int, struct rusage *);
int	setpriority(int, id_t, int);
int	setrlimit(int, const struct rlimit *);
__END_DECLS

#endif	/* !KERNEL */
#endif	/* !_SYS_RESOURCE_H_ */
