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
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)kern_clock.c	8.5 (Berkeley) 1/21/94
 */
/*
 * HISTORY
 */

#include <machine/spl.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/dkstat.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/resource.h>
#include <sys/proc.h>
#include <sys/vm.h>

#ifdef GPROF
#include <sys/gmon.h>
#endif

#include <kern/thread.h>
#include <kern/ast.h>
#include <kern/assert.h>
#include <mach/boolean.h>

#include <kern/thread_call.h>

/*
 * Clock handling routines.
 *
 * This code is written to operate with two timers which run
 * independently of each other. The main clock, running at hz
 * times per second, is used to do scheduling and timeout calculations.
 * The second timer does resource utilization estimation statistically
 * based on the state of the machine phz times a second. Both functions
 * can be performed by a single clock (ie hz == phz), however the 
 * statistics will be much more prone to errors. Ideally a machine
 * would have separate clocks measuring time spent in user state, system
 * state, interrupt state, and idle state. These clocks would allow a non-
 * approximate measure of resource utilization.
 */

/*
 * The hz hardware interval timer.
 * We update the events relating to real time.
 * If this timer is also being used to gather statistics,
 * we run through the statistics gathering routine as well.
 */

int bsd_hardclockinit = 0;
/*ARGSUSED*/
void
bsd_hardclock(usermode, pc, numticks)
	boolean_t usermode;
	caddr_t pc;
	int numticks;
{
	register struct proc *p;
	register int s;
	int ticks = numticks;
	extern int tickdelta;
	extern long timedelta;
	register thread_t	thread;
	int nusecs = numticks * tick;

	if (!bsd_hardclockinit)
		return;

	thread = current_thread();

	/*
	 * Charge the time out based on the mode the cpu is in.
	 * Here again we fudge for the lack of proper interval timers
	 * assuming that the current state has been around at least
	 * one tick.
	 */
	p = (struct proc *)current_proc();
	if (p && ((p->p_flag & P_WEXIT) == NULL)) {
	if (usermode) {		
		if (p) {
			if (p->p_stats && p->p_stats->p_prof.pr_scale) {
				p->p_flag |= P_OWEUPC;
                                ast_on(AST_BSD);
			}
		}

		/*
		 * CPU was in user state.  Increment
		 * user time counter, and process process-virtual time
		 * interval timer. 
		 */
		if (p->p_stats && 
		timerisset(&p->p_stats->p_timer[ITIMER_VIRTUAL].it_value) &&
		itimerdecr(&p->p_stats->p_timer[ITIMER_VIRTUAL],  nusecs) == 0) {
                        extern void psignal_vtalarm(struct proc *);
                        
			/* does psignal(p, SIGVTALRM) in a thread context */
                        thread_call_func((thread_call_func_t)psignal_vtalarm, p, FALSE);
                }
	}

	/*
	 * If the cpu is currently scheduled to a process, then
	 * charge it with resource utilization for a tick, updating
	 * statistics which run in (user+system) virtual time,
	 * such as the cpu time limit and profiling timers.
	 * This assumes that the current process has been running
	 * the entire last tick.
	 */
	if (p && !(is_thread_idle(thread)))
	{		
		if (p->p_limit && (p->p_limit->pl_rlimit[RLIMIT_CPU].rlim_cur != RLIM_INFINITY)) {
		    time_value_t	sys_time, user_time;

		    thread_read_times(thread, &user_time, &sys_time);
		    if ((sys_time.seconds + user_time.seconds + 1) >
		        p->p_limit->pl_rlimit[RLIMIT_CPU].rlim_cur) {
                            extern void psignal_xcpu(struct proc *);
                        
                            /* does psignal(p, SIGXCPU) in a thread context */
                            thread_call_func((thread_call_func_t)psignal_xcpu, p, FALSE);

                            if (p->p_limit->pl_rlimit[RLIMIT_CPU].rlim_cur <
                                p->p_limit->pl_rlimit[RLIMIT_CPU].rlim_max)
                                    p->p_limit->pl_rlimit[RLIMIT_CPU].rlim_cur += 5;
			}
		}
		if (timerisset(&p->p_stats->p_timer[ITIMER_PROF].it_value) &&
		    itimerdecr(&p->p_stats->p_timer[ITIMER_PROF], nusecs) == 0) {
                            extern void psignal_sigprof(struct proc *);
                        
                            /* does psignal(p, SIGPROF) in a thread context */
                            thread_call_func((thread_call_func_t)psignal_sigprof, p, FALSE);
                }
	}

	/*
	 * Increment the time-of-day, and schedule
	 * processing of the callouts at a very low cpu priority,
	 * so we don't keep the relatively high clock interrupt
	 * priority any longer than necessary.
	 */

	/*
	 * Gather the statistics.
	 */
	gatherstats(usermode, pc);

	}
	if (timedelta != 0) {
		register delta;
		clock_res_t nsdelta = tickdelta * NSEC_PER_USEC;

		if (timedelta < 0) {
			delta = ticks - tickdelta;
			timedelta += tickdelta;
			nsdelta = -nsdelta;
		} else {
			delta = ticks + tickdelta;
			timedelta -= tickdelta;
		}
		clock_adjust_calendar(nsdelta);
	}
	microtime(&time);
}

/*
 * Gather statistics on resource utilization.
 *
 * We make a gross assumption: that the system has been in the
 * state it is in (user state, kernel state, interrupt state,
 * or idle state) for the entire last time interval, and
 * update statistics accordingly.
 */
/*ARGSUSED*/
void
gatherstats(usermode, pc)
	boolean_t usermode;
	caddr_t pc;
{
	register int cpstate, s;
	struct proc *proc =current_proc();
#ifdef GPROF
    struct gmonparam *p = &_gmonparam;
#endif

	/*
	 * Determine what state the cpu is in.
	 */
	if (usermode) {
		/*
		 * CPU was in user state.
		 */
		if (proc->p_nice > NZERO)
			cpstate = CP_NICE;
		else
			cpstate = CP_USER;
	} else {
		/*
		 * CPU was in system state.  If profiling kernel
		 * increment a counter.  If no process is running
		 * then this is a system tick if we were running
		 * at a non-zero IPL (in a driver).  If a process is running,
		 * then we charge it with system time even if we were
		 * at a non-zero IPL, since the system often runs
		 * this way during processing of system calls.
		 * This is approximate, but the lack of true interval
		 * timers makes doing anything else difficult.
		 */
		cpstate = CP_SYS;
		if (is_thread_idle(current_thread()))
			cpstate = CP_IDLE;
#ifdef GPROF
		if (p->state == GMON_PROF_ON) {
			s = pc - p->lowpc;
			if (s < p->textsize) {
				s /= (HISTFRACTION * sizeof(*p->kcount));
				p->kcount[s]++;
			}
		}
#endif
	}
	/*
	 * We maintain statistics shown by user-level statistics
	 * programs:  the amount of time in each cpu state, and
	 * the amount of time each of DK_NDRIVE ``drives'' is busy.
	 */
	cp_time[cpstate]++;
	for (s = 0; s < DK_NDRIVE; s++)
		if (dk_busy & (1 << s))
			dk_time[s]++;
}


/*
 * Kernel timeout services.
 */

/*
 *	Set a timeout.
 *
 *	fcn:		function to call
 *	param:		parameter to pass to function
 *	interval:	timeout interval, in hz.
 */
void
timeout(
	timeout_fcn_t			fcn,
	void					*param,
	int						interval)
{
	uint64_t		deadline;

	clock_interval_to_deadline(interval, NSEC_PER_SEC / hz, &deadline);
	thread_call_func_delayed((thread_call_func_t)fcn, param, deadline);
}

/*
 * Cancel a timeout.
 */
void
untimeout(
	register timeout_fcn_t		fcn,
	register void				*param)
{
	thread_call_func_cancel((thread_call_func_t)fcn, param, FALSE);
}



/*
 * Compute number of hz until specified time.
 * Used to compute third argument to timeout() from an
 * absolute time.
 */
hzto(tv)
	struct timeval *tv;
{
	register long ticks;
	register long sec;
	int s = splhigh();
	
	/*
	 * If number of milliseconds will fit in 32 bit arithmetic,
	 * then compute number of milliseconds to time and scale to
	 * ticks.  Otherwise just compute number of hz in time, rounding
	 * times greater than representible to maximum value.
	 *
	 * Delta times less than 25 days can be computed ``exactly''.
	 * Maximum value for any timeout in 10ms ticks is 250 days.
	 */
	sec = tv->tv_sec - time.tv_sec;
	if (sec <= 0x7fffffff / 1000 - 1000)
		ticks = ((tv->tv_sec - time.tv_sec) * 1000 +
			(tv->tv_usec - time.tv_usec) / 1000)
				/ (tick / 1000);
	else if (sec <= 0x7fffffff / hz)
		ticks = sec * hz;
	else
		ticks = 0x7fffffff;
	splx(s);
	return (ticks);
}

#if 0 /* [ */
/*
 * Convert ticks to a timeval
 */
ticks_to_timeval(ticks, tvp)
	register long ticks;
	struct timeval *tvp;
{
	tvp->tv_sec = ticks/hz;
	tvp->tv_usec = (ticks%hz) * tick;
	asert(tvp->tv_usec < 1000000);
}
#endif /* ] */

/*
 * Return information about system clocks.
 */
int
sysctl_clockrate(where, sizep)
	register char *where;
	size_t *sizep;
{
	struct clockinfo clkinfo;

	/*
	 * Construct clockinfo structure.
	 */
	clkinfo.hz = hz;
	clkinfo.tick = tick;
	clkinfo.profhz = hz;
	clkinfo.stathz = hz;
	return sysctl_rdstruct(where, sizep, NULL, &clkinfo, sizeof(clkinfo));
}


/*
 * Compute number of ticks in the specified amount of time.
 */
int
tvtohz(tv)
	struct timeval *tv;
{
	register unsigned long ticks;
	register long sec, usec;

	/*
	 * If the number of usecs in the whole seconds part of the time
	 * difference fits in a long, then the total number of usecs will
	 * fit in an unsigned long.  Compute the total and convert it to
	 * ticks, rounding up and adding 1 to allow for the current tick
	 * to expire.  Rounding also depends on unsigned long arithmetic
	 * to avoid overflow.
	 *
	 * Otherwise, if the number of ticks in the whole seconds part of
	 * the time difference fits in a long, then convert the parts to
	 * ticks separately and add, using similar rounding methods and
	 * overflow avoidance.  This method would work in the previous
	 * case but it is slightly slower and assumes that hz is integral.
	 *
	 * Otherwise, round the time difference down to the maximum
	 * representable value.
	 *
	 * If ints have 32 bits, then the maximum value for any timeout in
	 * 10ms ticks is 248 days.
	 */
	sec = tv->tv_sec;
	usec = tv->tv_usec;
	if (usec < 0) {
		sec--;
		usec += 1000000;
	}
	if (sec < 0) {
#ifdef DIAGNOSTIC
		if (usec > 0) {
			sec++;
			usec -= 1000000;
		}
		printf("tvotohz: negative time difference %ld sec %ld usec\n",
		       sec, usec);
#endif
		ticks = 1;
	} else if (sec <= LONG_MAX / 1000000)
		ticks = (sec * 1000000 + (unsigned long)usec + (tick - 1))
			/ tick + 1;
	else if (sec <= LONG_MAX / hz)
		ticks = sec * hz
			+ ((unsigned long)usec + (tick - 1)) / tick + 1;
	else
		ticks = LONG_MAX;
	if (ticks > INT_MAX)
		ticks = INT_MAX;
	return ((int)ticks);
}


/*
 * Start profiling on a process.
 *
 * Kernel profiling passes kernel_proc which never exits and hence
 * keeps the profile clock running constantly.
 */
void
startprofclock(p)
	register struct proc *p;
{
	if ((p->p_flag & P_PROFIL) == 0)
		p->p_flag |= P_PROFIL;
}

/*
 * Stop profiling on a process.
 */
void
stopprofclock(p)
	register struct proc *p;
{
	if (p->p_flag & P_PROFIL)
		p->p_flag &= ~P_PROFIL;
}

void
bsd_uprofil(struct time_value *syst, unsigned int pc)
{
struct proc *p = current_proc();
int		ticks;
struct timeval	*tv;
struct timeval st;

	if (p == NULL)
	        return;
	if ( !(p->p_flag & P_PROFIL))
	        return;

	st.tv_sec = syst->seconds;
	st.tv_usec = syst->microseconds;

	tv = &(p->p_stats->p_ru.ru_stime);

	ticks = ((tv->tv_sec - st.tv_sec) * 1000 +
		(tv->tv_usec - st.tv_usec) / 1000) /
		(tick / 1000);
	if (ticks)
		addupc_task(p, pc, ticks);
}

void
get_procrustime(time_value_t *tv)
{
	struct proc *p = current_proc();
	struct timeval st;

	if (p == NULL) 
		return;
	if ( !(p->p_flag & P_PROFIL))
	        return;

	st = p->p_stats->p_ru.ru_stime;
	
	tv->seconds = st.tv_sec;
	tv->microseconds = st.tv_usec;
}
