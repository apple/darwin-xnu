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

#include <sys/param.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include <sys/mount.h>

#include <kern/cpu_number.h>

#include <kern/clock.h>

#define HZ	100	/* XXX */

struct timeval		time;

/* 
 * Time of day and interval timer support.
 *
 * These routines provide the kernel entry points to get and set
 * the time-of-day and per-process interval timers.  Subroutines
 * here provide support for adding and subtracting timeval structures
 * and decrementing interval timers, optionally reloading the interval
 * timers when they expire.
 */
struct gettimeofday_args{
	struct timeval *tp;
	struct timezone *tzp;
};
/* ARGSUSED */
int
gettimeofday(p, uap, retval)
	struct proc *p;
	register struct gettimeofday_args *uap;
	register_t *retval;
{
	struct timeval atv;
	int error = 0;

	if (uap->tp) {
		microtime(&atv);
		if (error = copyout((caddr_t)&atv, (caddr_t)uap->tp,
			sizeof (atv)))
			return(error);
	}
	
	if (uap->tzp)
		error = copyout((caddr_t)&tz, (caddr_t)uap->tzp,
		    sizeof (tz));

	return(error);
}

struct settimeofday_args {
	struct timeval *tv;
	struct timezone *tzp;
};
/* ARGSUSED */
int
settimeofday(p, uap, retval)
	struct proc *p;
	struct settimeofday_args  *uap;
	register_t *retval;
{
	struct timeval atv;
	struct timezone atz;
	int error, s;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	/* Verify all parameters before changing time. */
	if (uap->tv && (error = copyin((caddr_t)uap->tv,
	    (caddr_t)&atv, sizeof(atv))))
		return (error);
	if (uap->tzp && (error = copyin((caddr_t)uap->tzp,
	    (caddr_t)&atz, sizeof(atz))))
		return (error);
	if (uap->tv)
		setthetime(&atv);
	if (uap->tzp)
		tz = atz;
	return (0);
}

setthetime(tv)
	struct timeval *tv;
{
	mach_timespec_t	now;
	long delta;
	int s;

	now.tv_sec = tv->tv_sec;
	now.tv_nsec = tv->tv_usec * NSEC_PER_USEC;

	clock_set_calendar_value(now);
	delta = tv->tv_sec - time.tv_sec;
	boottime.tv_sec += delta;
#if NFSCLIENT || NFSSERVER
	lease_updatetime(delta);
#endif
	s = splhigh();
	microtime(&time);
	splx(s);
}

int	tickadj = 240000 / (60 * HZ);	/* "standard" clock skew, us./tick */
int	tickdelta;			/* current clock skew, us. per tick */
long	timedelta;			/* unapplied time correction, us. */
long	bigadj = 1000000;		/* use 10x skew above bigadj us. */

struct adjtime_args {
	struct timeval *delta;
	struct timeval *olddelta;
};
/* ARGSUSED */
int
adjtime(p, uap, retval)
	struct proc *p;
	register struct adjtime_args *uap;
	register_t *retval;
{
	struct timeval atv, oatv;
	register long ndelta;
	int s, error;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	if(error = copyin((caddr_t)uap->delta, (caddr_t)&atv,
		sizeof (struct timeval)))
		return(error);
		
	ndelta = atv.tv_sec * 1000000 + atv.tv_usec;
	if (timedelta == 0)
		if (ndelta > bigadj)
			tickdelta = 10 * tickadj;
		else
			tickdelta = tickadj;
	if (ndelta % tickdelta)
		ndelta = ndelta / tickdelta * tickdelta;

	s = splclock();
	if (uap->olddelta) {
		oatv.tv_sec = timedelta / 1000000;
		oatv.tv_usec = timedelta % 1000000;
	}
	timedelta = ndelta;
	splx(s);

	if (uap->olddelta)
		(void) copyout((caddr_t)&oatv, (caddr_t)uap->olddelta,
			sizeof (struct timeval));
	return(0);
}

#define SECDAY          ((unsigned)(24*60*60))          /* seconds per day */
#define SECYR           ((unsigned)(365*SECDAY))        /* per common year */
#define YRREF           70      /* UNIX time referenced to 1970 */

/*
 * Initialze the time of day register. 
 * Trust the RTC except for the case where it is set before 
 * the UNIX epoch. In that case use the the UNIX epoch.
 * The argument passed in is ignored.
 */
void
inittodr(base)
	time_t base;
{
	/*
	 * Initialize the calendar by
	 * reading the BBC, if not already set.
	 */
	clock_initialize_calendar();

	/*
	 * The value returned by microtime()
	 * is gotten from the calendar.
	 */
	microtime(&time);

	/*
	 * This variable still exists to keep
	 * 'w' happy.  It should only be considered
	 * an approximation.
	 */
	boottime.tv_sec = time.tv_sec;
	boottime.tv_usec = 0;

	/*
	 * If the RTC does not have acceptable value, i.e. time before
	 * the UNIX epoch, set it to the UNIX epoch
	 */
	if (time.tv_sec < 0) {
		printf ("WARNING: preposterous time in Real Time Clock");
		time.tv_sec = 0;	/* the UNIX epoch */
		time.tv_usec = 0;
		setthetime(&time);
		boottime = time;
		printf(" -- CHECK AND RESET THE DATE!\n");
	}

	return;
}

/*
 * Get value of an interval timer.  The process virtual and
 * profiling virtual time timers are kept in the u. area, since
 * they can be swapped out.  These are kept internally in the
 * way they are specified externally: in time until they expire.
 *
 * The real time interval timer is kept in the process table slot
 * for the process, and its value (it_value) is kept as an
 * absolute time rather than as a delta, so that it is easy to keep
 * periodic real-time signals from drifting.
 *
 * Virtual time timers are processed in the hardclock() routine of
 * kern_clock.c.  The real time timer is processed by a timeout
 * routine, called from the softclock() routine.  Since a callout
 * may be delayed in real time due to interrupt processing in the system,
 * it is possible for the real time timeout routine (realitexpire, given below),
 * to be delayed in real time past when it is supposed to occur.  It
 * does not suffice, therefore, to reload the real timer .it_value from the
 * real time timers .it_interval.  Rather, we compute the next time in
 * absolute time the timer should go off.
 */
 
struct getitimer_args {
	u_int	which;
	struct itimerval *itv;
}; 
/* ARGSUSED */
int
getitimer(p, uap, retval)
	struct proc *p;
	register struct getitimer_args *uap;
	register_t *retval;
{
	struct itimerval aitv;
	int s;

	if (uap->which > ITIMER_PROF)
		return(EINVAL);
	
	s = splclock();
	if (uap->which == ITIMER_REAL) {
		/*
		 * Convert from absoulte to relative time in .it_value
		 * part of real time timer.  If time for real time timer
		 * has passed return 0, else return difference between
		 * current time and time for the timer to go off.
		 */
		aitv = p->p_realtimer;
		if (timerisset(&aitv.it_value))
			if (timercmp(&aitv.it_value, &time, <))
				timerclear(&aitv.it_value);
			else
				timevalsub(&aitv.it_value, &time);
	} else
		aitv =p->p_stats->p_timer[uap->which];
	splx(s);
	return(copyout((caddr_t)&aitv, (caddr_t)uap->itv,
	    sizeof (struct itimerval)));
}

struct setitimer_args {
	u_int	which;
	struct	itimerval *itv;
	struct	itimerval *oitv;
};
/* ARGSUSED */
int
setitimer(p, uap, retval)
	struct proc *p;
	register struct setitimer_args *uap;
	register_t *retval;
{
	struct itimerval aitv;
	register struct itimerval *itvp;
	int s, error;

	if (uap->which > ITIMER_PROF)
		return(EINVAL);
	itvp = uap->itv;
	if (itvp && (error = copyin((caddr_t)itvp, (caddr_t)&aitv,
	    sizeof(struct itimerval))))
		return (error);
	if ((uap->itv = uap->oitv) &&
	    (error = getitimer(p, uap, retval)))
		return (error);
	if (itvp == 0)
		return (0);
	if (itimerfix(&aitv.it_value) || itimerfix(&aitv.it_interval))
		return (EINVAL);
	s = splclock();
	if (uap->which == ITIMER_REAL) {
		untimeout(realitexpire, (caddr_t)p);
		if (timerisset(&aitv.it_value)) {
			timevaladd(&aitv.it_value, &time);
			timeout(realitexpire, (caddr_t)p, hzto(&aitv.it_value));
		}
		p->p_realtimer = aitv;
	} else
		p->p_stats->p_timer[uap->which] = aitv;
	splx(s);
	return(0); /* To insure good return value on success */
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
realitexpire(arg)
	void *arg;
{
	register struct proc *p;
	int s;
	boolean_t 	funnel_state;

	funnel_state = thread_funnel_set(kernel_flock,TRUE);

	p = (struct proc *)arg;
	psignal(p, SIGALRM);
	if (!timerisset(&p->p_realtimer.it_interval)) {
		timerclear(&p->p_realtimer.it_value);
                (void) thread_funnel_set(kernel_flock, FALSE);
		return;
	}
	
	/*
	 * If the time's way off, don't try to compensate by getting
	 * there incrementally.
	 */
	s = splclock();
	if (p->p_realtimer.it_value.tv_sec < time.tv_sec - 10) {
		p->p_realtimer.it_value = time;
		timeout(realitexpire, (caddr_t)p,
			hzto(&p->p_realtimer.it_value));
		splx(s);
                (void) thread_funnel_set(kernel_flock, FALSE);
		return;
		
	}
	splx(s);

	for (;;) {
		s = splclock();
		timevaladd(&p->p_realtimer.it_value,
		    &p->p_realtimer.it_interval);
		if (timercmp(&p->p_realtimer.it_value, &time, >)) {
			timeout(realitexpire, (caddr_t)p,
			    hzto(&p->p_realtimer.it_value));
			splx(s);
                        (void) thread_funnel_set(kernel_flock, FALSE);
			return;
		}
		splx(s);
	}
        
	(void) thread_funnel_set(kernel_flock, FALSE);
}

/*
 * Check that a proposed value to load into the .it_value or
 * .it_interval part of an interval timer is acceptable, and
 * fix it to have at least minimal value (i.e. if it is less
 * than the resolution of the clock, round it up.)
 */
int
itimerfix(tv)
	struct timeval *tv;
{

	if (tv->tv_sec < 0 || tv->tv_sec > 100000000 ||
	    tv->tv_usec < 0 || tv->tv_usec >= 1000000)
		return (EINVAL);
	if (tv->tv_sec == 0 && tv->tv_usec != 0 && tv->tv_usec < tick)
		tv->tv_usec = tick;
	return (0);
}

/*
 * Decrement an interval timer by a specified number
 * of microseconds, which must be less than a second,
 * i.e. < 1000000.  If the timer expires, then reload
 * it.  In this case, carry over (usec - old value) to
 * reducint the value reloaded into the timer so that
 * the timer does not drift.  This routine assumes
 * that it is called in a context where the timers
 * on which it is operating cannot change in value.
 */
int
itimerdecr(itp, usec)
	register struct itimerval *itp;
	int usec;
{

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
	if (timerisset(&itp->it_value))
		return (1);
	/* expired, exactly at end of interval */
expire:
	if (timerisset(&itp->it_interval)) {
		itp->it_value = itp->it_interval;
		itp->it_value.tv_usec -= usec;
		if (itp->it_value.tv_usec < 0) {
			itp->it_value.tv_usec += 1000000;
			itp->it_value.tv_sec--;
		}
	} else
		itp->it_value.tv_usec = 0;		/* sec is already 0 */
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
timevaladd(t1, t2)
	struct timeval *t1, *t2;
{

	t1->tv_sec += t2->tv_sec;
	t1->tv_usec += t2->tv_usec;
	timevalfix(t1);
}
void
timevalsub(t1, t2)
	struct timeval *t1, *t2;
{

	t1->tv_sec -= t2->tv_sec;
	t1->tv_usec -= t2->tv_usec;
	timevalfix(t1);
}
void
timevalfix(t1)
	struct timeval *t1;
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
microtime(struct timeval * tvp)
{
	mach_timespec_t		now = clock_get_calendar_value();

	tvp->tv_sec = now.tv_sec;
	tvp->tv_usec = now.tv_nsec / NSEC_PER_USEC;
}
