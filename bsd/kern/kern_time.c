/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
 *	@(#)kern_time.c	8.4 (Berkeley) 5/26/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/time.h>

#include <sys/mount_internal.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>

#include <kern/clock.h>
#include <kern/task.h>
#include <kern/thread_call.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#define HZ	100	/* XXX */

/* simple lock used to access timezone, tz structure */
lck_spin_t * tz_slock;
lck_grp_t * tz_slock_grp;
lck_attr_t * tz_slock_attr;
lck_grp_attr_t	*tz_slock_grp_attr;

static void		setthetime(
					struct timeval	*tv);

void time_zone_slock_init(void) __attribute__((section("__TEXT, initcode")));

/* 
 * Time of day and interval timer support.
 *
 * These routines provide the kernel entry points to get and set
 * the time-of-day and per-process interval timers.  Subroutines
 * here provide support for adding and subtracting timeval structures
 * and decrementing interval timers, optionally reloading the interval
 * timers when they expire.
 */
/* ARGSUSED */
int
gettimeofday(
__unused	struct proc	*p,
			struct gettimeofday_args *uap, 
			int32_t *retval)
{
	int error = 0;
	struct timezone ltz; /* local copy */

	if (uap->tp) {
		clock_sec_t		secs;
		clock_usec_t	usecs;

		clock_gettimeofday(&secs, &usecs);
		retval[0] = secs;
		retval[1] = usecs;
	}
	
	if (uap->tzp) {
		lck_spin_lock(tz_slock);
		ltz = tz;
		lck_spin_unlock(tz_slock);

		error = copyout((caddr_t)&ltz, CAST_USER_ADDR_T(uap->tzp), sizeof (tz));
	}

	return (error);
}

/*
 * XXX Y2038 bug because of setthetime() argument
 */
/* ARGSUSED */
int
settimeofday(__unused struct proc *p, struct settimeofday_args  *uap, __unused int32_t *retval)
{
	struct timeval atv;
	struct timezone atz;
	int error;

	bzero(&atv, sizeof(atv));

#if CONFIG_MACF
	error = mac_system_check_settime(kauth_cred_get());
	if (error)
		return (error);
#endif
#ifndef CONFIG_EMBEDDED
	if ((error = suser(kauth_cred_get(), &p->p_acflag)))
		return (error);
#endif
	/* Verify all parameters before changing time */
	if (uap->tv) {
		if (IS_64BIT_PROCESS(p)) {
			struct user64_timeval user_atv;
			error = copyin(uap->tv, &user_atv, sizeof(user_atv));
			atv.tv_sec = user_atv.tv_sec;
			atv.tv_usec = user_atv.tv_usec;
		} else {
			struct user32_timeval user_atv;
			error = copyin(uap->tv, &user_atv, sizeof(user_atv));
			atv.tv_sec = user_atv.tv_sec;
			atv.tv_usec = user_atv.tv_usec;
		}
		if (error)
			return (error);
	}
	if (uap->tzp && (error = copyin(uap->tzp, (caddr_t)&atz, sizeof(atz))))
		return (error);
	if (uap->tv) {
		timevalfix(&atv);
		if (atv.tv_sec < 0 || (atv.tv_sec == 0 && atv.tv_usec < 0))
			return (EPERM);
		setthetime(&atv);
	}
	if (uap->tzp) {
		lck_spin_lock(tz_slock);
		tz = atz;
		lck_spin_unlock(tz_slock);
	}
	return (0);
}

static void
setthetime(
	struct timeval	*tv)
{
	clock_set_calendar_microtime(tv->tv_sec, tv->tv_usec);
}

/*
 * XXX Y2038 bug because of clock_adjtime() first argument
 */
/* ARGSUSED */
int
adjtime(struct proc *p, struct adjtime_args *uap, __unused int32_t *retval)
{
	struct timeval atv;
	int error;

#if CONFIG_MACF
	error = mac_system_check_settime(kauth_cred_get());
	if (error)
		return (error);
#endif
	if ((error = suser(kauth_cred_get(), &p->p_acflag)))
		return (error);
	if (IS_64BIT_PROCESS(p)) {
		struct user64_timeval user_atv;
		error = copyin(uap->delta, &user_atv, sizeof(user_atv));
		atv.tv_sec = user_atv.tv_sec;
		atv.tv_usec = user_atv.tv_usec;
	} else {
		struct user32_timeval user_atv;
		error = copyin(uap->delta, &user_atv, sizeof(user_atv));
		atv.tv_sec = user_atv.tv_sec;
		atv.tv_usec = user_atv.tv_usec;
	}
	if (error)
		return (error);
		
	/*
	 * Compute the total correction and the rate at which to apply it.
	 */
	clock_adjtime(&atv.tv_sec, &atv.tv_usec);

	if (uap->olddelta) {
		if (IS_64BIT_PROCESS(p)) {
			struct user64_timeval user_atv;
			user_atv.tv_sec = atv.tv_sec;
			user_atv.tv_usec = atv.tv_usec;
			error = copyout(&user_atv, uap->olddelta, sizeof(user_atv));
		} else {
			struct user32_timeval user_atv;
			user_atv.tv_sec = atv.tv_sec;
			user_atv.tv_usec = atv.tv_usec;
			error = copyout(&user_atv, uap->olddelta, sizeof(user_atv));
		}
	}

	return (0);
}

/*
 *	Verify the calendar value.  If negative,
 *	reset to zero (the epoch).
 */
void
inittodr(
	__unused time_t	base)
{
	struct timeval	tv;

	/*
	 * Assertion:
	 * The calendar has already been
	 * set up from the platform clock.
	 *
	 * The value returned by microtime()
	 * is gotten from the calendar.
	 */
	microtime(&tv);

	if (tv.tv_sec < 0 || tv.tv_usec < 0) {
		printf ("WARNING: preposterous time in Real Time Clock");
		tv.tv_sec = 0;		/* the UNIX epoch */
		tv.tv_usec = 0;
		setthetime(&tv);
		printf(" -- CHECK AND RESET THE DATE!\n");
	}
}

time_t
boottime_sec(void)
{
	clock_sec_t		secs;
	clock_nsec_t	nanosecs;

	clock_get_boottime_nanotime(&secs, &nanosecs);
	return (secs);
}

/*
 * Get value of an interval timer.  The process virtual and
 * profiling virtual time timers are kept internally in the
 * way they are specified externally: in time until they expire.
 *
 * The real time interval timer expiration time (p_rtime)
 * is kept as an absolute time rather than as a delta, so that
 * it is easy to keep periodic real-time signals from drifting.
 *
 * The real time timer is processed by a callout routine.
 * Since a callout may be delayed in real time due to
 * other processing in the system, it is possible for the real
 * time callout routine (realitexpire, given below), to be delayed
 * in real time past when it is supposed to occur.  It does not
 * suffice, therefore, to reload the real time .it_value from the
 * real time .it_interval.  Rather, we compute the next time in
 * absolute time when the timer should go off.
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *	copyout:EFAULT			Bad address
 */
/* ARGSUSED */
int
getitimer(struct proc *p, struct getitimer_args *uap, __unused int32_t *retval)
{
	struct itimerval aitv;

	if (uap->which > ITIMER_PROF)
		return(EINVAL);

	bzero(&aitv, sizeof(aitv));

	proc_spinlock(p);
	switch (uap->which) {

	case ITIMER_REAL:
		/*
		 * If time for real time timer has passed return 0,
		 * else return difference between current time and
		 * time for the timer to go off.
		 */
		aitv = p->p_realtimer;
		if (timerisset(&p->p_rtime)) {
			struct timeval		now;

			microuptime(&now);
			if (timercmp(&p->p_rtime, &now, <))
				timerclear(&aitv.it_value);
			else {
				aitv.it_value = p->p_rtime;
				timevalsub(&aitv.it_value, &now);
			}
		}
		else
			timerclear(&aitv.it_value);
		break;

	case ITIMER_VIRTUAL:
		aitv = p->p_vtimer_user;
		break;

	case ITIMER_PROF:
		aitv = p->p_vtimer_prof;
		break;
	}

	proc_spinunlock(p);

	if (IS_64BIT_PROCESS(p)) {
		struct user64_itimerval user_itv;
		user_itv.it_interval.tv_sec = aitv.it_interval.tv_sec;
		user_itv.it_interval.tv_usec = aitv.it_interval.tv_usec;
		user_itv.it_value.tv_sec = aitv.it_value.tv_sec;
		user_itv.it_value.tv_usec = aitv.it_value.tv_usec;
		return (copyout((caddr_t)&user_itv, uap->itv, sizeof (user_itv)));
	} else {
		struct user32_itimerval user_itv;
		user_itv.it_interval.tv_sec = aitv.it_interval.tv_sec;
		user_itv.it_interval.tv_usec = aitv.it_interval.tv_usec;
		user_itv.it_value.tv_sec = aitv.it_value.tv_sec;
		user_itv.it_value.tv_usec = aitv.it_value.tv_usec;
		return (copyout((caddr_t)&user_itv, uap->itv, sizeof (user_itv)));
	}
}

/*
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *	copyin:EFAULT			Bad address
 *	getitimer:EINVAL		Invalid argument
 *	getitimer:EFAULT		Bad address
 */
/* ARGSUSED */
int
setitimer(struct proc *p, struct setitimer_args *uap, int32_t *retval)
{
	struct itimerval aitv;
	user_addr_t itvp;
	int error;

	bzero(&aitv, sizeof(aitv));

	if (uap->which > ITIMER_PROF)
		return (EINVAL);
	if ((itvp = uap->itv)) {
		if (IS_64BIT_PROCESS(p)) {
			struct user64_itimerval user_itv;
			if ((error = copyin(itvp, (caddr_t)&user_itv, sizeof (user_itv))))
				return (error);
			aitv.it_interval.tv_sec = user_itv.it_interval.tv_sec;
			aitv.it_interval.tv_usec = user_itv.it_interval.tv_usec;
			aitv.it_value.tv_sec = user_itv.it_value.tv_sec;
			aitv.it_value.tv_usec = user_itv.it_value.tv_usec;
		} else { 
			struct user32_itimerval user_itv;
			if ((error = copyin(itvp, (caddr_t)&user_itv, sizeof (user_itv))))
				return (error);
			aitv.it_interval.tv_sec = user_itv.it_interval.tv_sec;
			aitv.it_interval.tv_usec = user_itv.it_interval.tv_usec;
			aitv.it_value.tv_sec = user_itv.it_value.tv_sec;
			aitv.it_value.tv_usec = user_itv.it_value.tv_usec;
		}
	}
	if ((uap->itv = uap->oitv) && (error = getitimer(p, (struct getitimer_args *)uap, retval)))
		return (error);
	if (itvp == 0)
		return (0);
	if (itimerfix(&aitv.it_value) || itimerfix(&aitv.it_interval))
		return (EINVAL);

	switch (uap->which) {

	case ITIMER_REAL:
		proc_spinlock(p);
		if (timerisset(&aitv.it_value)) {
			microuptime(&p->p_rtime);
			timevaladd(&p->p_rtime, &aitv.it_value);
			p->p_realtimer = aitv;
			if (!thread_call_enter_delayed(p->p_rcall, tvtoabstime(&p->p_rtime)))
				p->p_ractive++;
		} else  {
			timerclear(&p->p_rtime);
			p->p_realtimer = aitv;
			if (thread_call_cancel(p->p_rcall))
				p->p_ractive--;
		}
		proc_spinunlock(p);

		break;


	case ITIMER_VIRTUAL:
		if (timerisset(&aitv.it_value))
			task_vtimer_set(p->task, TASK_VTIMER_USER);
	else
			task_vtimer_clear(p->task, TASK_VTIMER_USER);

		proc_spinlock(p);
		p->p_vtimer_user = aitv;
		proc_spinunlock(p);
		break;

	case ITIMER_PROF:
		if (timerisset(&aitv.it_value))
			task_vtimer_set(p->task, TASK_VTIMER_PROF);
		else
			task_vtimer_clear(p->task, TASK_VTIMER_PROF);

		proc_spinlock(p);
		p->p_vtimer_prof = aitv;
		proc_spinunlock(p);
		break;
	}

	return (0);
}

/*
 * Real interval timer expired:
 * send process whose timer expired an alarm signal.
 * If time is not set up to reload, then just return.
 * Else compute next time timer should go off which is > current time.
 * This is where delay in processing this timeout causes multiple
 * SIGALRM calls to be compressed into one.
 */
void
realitexpire(
	struct proc	*p)
{
	struct proc *r;
	struct timeval	t;

	r = proc_find(p->p_pid);

	proc_spinlock(p);

	if (--p->p_ractive > 0 || r != p) {
		proc_spinunlock(p);

		if (r != NULL)
			proc_rele(r);
		return;
	}
	
	if (!timerisset(&p->p_realtimer.it_interval)) {
		timerclear(&p->p_rtime);
		proc_spinunlock(p);

		psignal(p, SIGALRM);
		proc_rele(p);
		return;
	}

	microuptime(&t);
	timevaladd(&p->p_rtime, &p->p_realtimer.it_interval);
	if (timercmp(&p->p_rtime, &t, <=)) {
		if ((p->p_rtime.tv_sec + 2) >= t.tv_sec) {
			for (;;) {
				timevaladd(&p->p_rtime, &p->p_realtimer.it_interval);
				if (timercmp(&p->p_rtime, &t, >))
					break;
			}
		}
		else {
			p->p_rtime = p->p_realtimer.it_interval;
			timevaladd(&p->p_rtime, &t);
		}
	}

	if (!thread_call_enter_delayed(p->p_rcall, tvtoabstime(&p->p_rtime)))
		p->p_ractive++;
	proc_spinunlock(p);

	psignal(p, SIGALRM);
	proc_rele(p);
}

/*
 * Check that a proposed value to load into the .it_value or
 * .it_interval part of an interval timer is acceptable.
 */
int
itimerfix(
	struct timeval *tv)
{

	if (tv->tv_sec < 0 || tv->tv_sec > 100000000 ||
	    tv->tv_usec < 0 || tv->tv_usec >= 1000000)
		return (EINVAL);
	return (0);
}

/*
 * Decrement an interval timer by a specified number
 * of microseconds, which must be less than a second,
 * i.e. < 1000000.  If the timer expires, then reload
 * it.  In this case, carry over (usec - old value) to
 * reduce the value reloaded into the timer so that
 * the timer does not drift.  This routine assumes
 * that it is called in a context where the timers
 * on which it is operating cannot change in value.
 */
int
itimerdecr(proc_t p,
	struct itimerval *itp, int usec)
{

	proc_spinlock(p);
	
	if (itp->it_value.tv_usec < usec) {
		if (itp->it_value.tv_sec == 0) {
			/* expired, and already in next interval */
			usec -= itp->it_value.tv_usec;
			goto expire;
		}
		itp->it_value.tv_usec += 1000000;
		itp->it_value.tv_sec--;
	}
	itp->it_value.tv_usec -= usec;
	usec = 0;
	if (timerisset(&itp->it_value)) {
		proc_spinunlock(p);
		return (1);
	}
	/* expired, exactly at end of interval */
expire:
	if (timerisset(&itp->it_interval)) {
		itp->it_value = itp->it_interval;
		if (itp->it_value.tv_sec > 0) {
		itp->it_value.tv_usec -= usec;
		if (itp->it_value.tv_usec < 0) {
			itp->it_value.tv_usec += 1000000;
			itp->it_value.tv_sec--;
			}
		}
	} else
		itp->it_value.tv_usec = 0;		/* sec is already 0 */
	proc_spinunlock(p);
	return (0);
}

/*
 * Add and subtract routines for timevals.
 * N.B.: subtract routine doesn't deal with
 * results which are before the beginning,
 * it just gets very confused in this case.
 * Caveat emptor.
 */
void
timevaladd(
	struct timeval *t1,
	struct timeval *t2)
{

	t1->tv_sec += t2->tv_sec;
	t1->tv_usec += t2->tv_usec;
	timevalfix(t1);
}
void
timevalsub(
	struct timeval *t1,
	struct timeval *t2)
{

	t1->tv_sec -= t2->tv_sec;
	t1->tv_usec -= t2->tv_usec;
	timevalfix(t1);
}
void
timevalfix(
	struct timeval *t1)
{

	if (t1->tv_usec < 0) {
		t1->tv_sec--;
		t1->tv_usec += 1000000;
	}
	if (t1->tv_usec >= 1000000) {
		t1->tv_sec++;
		t1->tv_usec -= 1000000;
	}
}

/*
 * Return the best possible estimate of the time in the timeval
 * to which tvp points.
 */
void
microtime(
	struct timeval	*tvp)
{
	clock_sec_t		tv_sec;
	clock_usec_t	tv_usec;

	clock_get_calendar_microtime(&tv_sec, &tv_usec);

	tvp->tv_sec = tv_sec;
	tvp->tv_usec = tv_usec;
}

void
microuptime(
	struct timeval	*tvp)
{
	clock_sec_t		tv_sec;
	clock_usec_t	tv_usec;

	clock_get_system_microtime(&tv_sec, &tv_usec);

	tvp->tv_sec = tv_sec;
	tvp->tv_usec = tv_usec;
}

/*
 * Ditto for timespec.
 */
void
nanotime(
	struct timespec *tsp)
{
	clock_sec_t		tv_sec;
	clock_nsec_t	tv_nsec;

	clock_get_calendar_nanotime(&tv_sec, &tv_nsec);

	tsp->tv_sec = tv_sec;
	tsp->tv_nsec = tv_nsec;
}

void
nanouptime(
	struct timespec *tsp)
{
	clock_sec_t		tv_sec;
	clock_nsec_t	tv_nsec;

	clock_get_system_nanotime(&tv_sec, &tv_nsec);

	tsp->tv_sec = tv_sec;
	tsp->tv_nsec = tv_nsec;
}

uint64_t
tvtoabstime(
	struct timeval	*tvp)
{
	uint64_t	result, usresult;

	clock_interval_to_absolutetime_interval(
						tvp->tv_sec, NSEC_PER_SEC, &result);
	clock_interval_to_absolutetime_interval(
						tvp->tv_usec, NSEC_PER_USEC, &usresult);

	return (result + usresult);
}
void
time_zone_slock_init(void)
{
	/* allocate lock group attribute and group */
	tz_slock_grp_attr = lck_grp_attr_alloc_init();

	tz_slock_grp =  lck_grp_alloc_init("tzlock", tz_slock_grp_attr);

	/* Allocate lock attribute */
	tz_slock_attr = lck_attr_alloc_init();

	/* Allocate the spin lock */
	tz_slock = lck_spin_alloc_init(tz_slock_grp, tz_slock_attr);
}
