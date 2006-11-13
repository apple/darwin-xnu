/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
 *	@(#)time.h	8.2 (Berkeley) 7/10/94
 */

#ifndef _SYS_TIME_H_
#define _SYS_TIME_H_

#include <sys/cdefs.h>
#include <sys/_types.h>

#ifndef	_TIME_T
#define	_TIME_T
typedef	__darwin_time_t	time_t;
#endif

#ifndef _SUSECONDS_T
#define _SUSECONDS_T
typedef __darwin_suseconds_t	suseconds_t;
#endif


/*
 * Structure returned by gettimeofday(2) system call,
 * and used in other calls.
 */
#ifndef _TIMEVAL
#define _TIMEVAL
struct timeval {
	time_t		tv_sec;		/* seconds */
	suseconds_t	tv_usec;	/* and microseconds */
};
#endif	/* _TIMEVAL */

/*
 * Structure used as a parameter by getitimer(2) and setitimer(2) system
 * calls.
 */
struct	itimerval {
	struct	timeval it_interval;	/* timer interval */
	struct	timeval it_value;	/* current value */
};

/*
 * Names of the interval timers, and structure
 * defining a timer setting.
 */
#define	ITIMER_REAL	0
#define	ITIMER_VIRTUAL	1
#define	ITIMER_PROF	2


/*
 * [XSI] The fd_set type shall be defined as described in <sys/select.h>.
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

__BEGIN_DECLS
typedef	struct fd_set {
	__int32_t	fds_bits[__DARWIN_howmany(FD_SETSIZE, __DARWIN_NFDBITS)];
} fd_set;
__END_DECLS

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


#ifndef _POSIX_C_SOURCE
/*
 * Structure defined by POSIX.4 to be like a timeval.
 */
#ifndef _TIMESPEC
#define _TIMESPEC
struct timespec {
	time_t	tv_sec;		/* seconds */
	long	tv_nsec;	/* and nanoseconds */
};

#ifdef KERNEL
// LP64todo - should this move?
#include <machine/types.h>	/* user_time_t */

/* LP64 version of struct timeval.  time_t is a long and must grow when 
 * we're dealing with a 64-bit process.
 * WARNING - keep in sync with struct timeval
 */
#if __DARWIN_ALIGN_NATURAL
#pragma options align=natural
#endif

struct user_timeval {
	user_time_t	tv_sec;		/* seconds */
	suseconds_t	tv_usec;	/* and microseconds */
};	

struct	user_itimerval {
	struct	user_timeval it_interval;	/* timer interval */
	struct	user_timeval it_value;		/* current value */
};

/* LP64 version of struct timespec.  time_t is a long and must grow when 
 * we're dealing with a 64-bit process.
 * WARNING - keep in sync with struct timespec
 */
struct user_timespec {
	user_time_t	tv_sec;		/* seconds */
	int32_t	tv_nsec;	/* and nanoseconds */
};

#if __DARWIN_ALIGN_NATURAL
#pragma options align=reset
#endif

#endif // KERNEL
#endif

#define	TIMEVAL_TO_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#define	TIMESPEC_TO_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};
#define	DST_NONE	0	/* not on dst */
#define	DST_USA		1	/* USA style dst */
#define	DST_AUST	2	/* Australian style dst */
#define	DST_WET		3	/* Western European dst */
#define	DST_MET		4	/* Middle European dst */
#define	DST_EET		5	/* Eastern European dst */
#define	DST_CAN		6	/* Canada */

/* Operations on timevals. */
#define	timerclear(tvp)		(tvp)->tv_sec = (tvp)->tv_usec = 0
#define	timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#define	timercmp(tvp, uvp, cmp)						\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#define	timeradd(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;	\
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)

#define timevalcmp(l, r, cmp)   timercmp(l, r, cmp) /* freebsd */

/*
 * Getkerninfo clock information structure
 */
struct clockinfo {
	int	hz;		/* clock frequency */
	int	tick;		/* micro-seconds per hz tick */
	int	tickadj;	/* clock skew rate for adjtime() */
	int	stathz;		/* statistics clock frequency */
	int	profhz;		/* profiling clock frequency */
};
#endif /* ! _POSIX_C_SOURCE */


#ifdef KERNEL

#ifndef _POSIX_C_SOURCE
__BEGIN_DECLS
void	microtime(struct timeval *tv);
void	microuptime(struct timeval *tv);
#define getmicrotime(a)		microtime(a)
#define getmicrouptime(a)	microuptime(a)
void	nanotime(struct timespec *ts);
void	nanouptime(struct timespec *ts);
#define getnanotime(a)		nanotime(a)
#define getnanouptime(a)	nanouptime(a)
void	timevaladd(struct timeval *t1, struct timeval *t2);
void	timevalsub(struct timeval *t1, struct timeval *t2);
void	timevalfix(struct timeval *t1);
#ifdef	BSD_KERNEL_PRIVATE
time_t	boottime_sec(void);
void	inittodr(time_t base);
int	itimerfix(struct timeval *tv);
int	itimerdecr(struct itimerval *itp, int usec);
#endif /* BSD_KERNEL_PRIVATE */

__END_DECLS

#endif /* ! _POSIX_C_SOURCE */

#else /* !KERNEL */

__BEGIN_DECLS

#ifndef _POSIX_C_SOURCE
#include <time.h>

int	adjtime(const struct timeval *, struct timeval *);
int	futimes(int, const struct timeval *);
int	settimeofday(const struct timeval *, const struct timezone *);
#endif /* ! _POSIX_C_SOURCE */

int	getitimer(int, struct itimerval *);
int	gettimeofday(struct timeval * __restrict, struct timezone * __restrict);
int	select(int, fd_set * __restrict, fd_set * __restrict,
		fd_set * __restrict, struct timeval * __restrict);
int	setitimer(int, const struct itimerval * __restrict,
		struct itimerval * __restrict);
int	utimes(const char *, const struct timeval *);

__END_DECLS

#endif /* !KERNEL */

#endif /* !_SYS_TIME_H_ */
