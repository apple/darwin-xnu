/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/file_internal.h>
#include <sys/vnode.h>
#include <sys/kernel.h>

#include <machine/spl.h>

#include <kern/queue.h>
#include <sys/lock.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/ast.h>

#include <kern/cpu_number.h>
#include <vm/vm_kern.h>

#include <kern/task.h>
#include <mach/time_value.h>
#include <kern/lock.h>

#include <sys/systm.h>			/* for unix_syscall_return() */
#include <libkern/OSAtomic.h>

extern boolean_t thread_should_abort(thread_t);	/* XXX */
extern void compute_averunnable(void *);	/* XXX */



static void
_sleep_continue( __unused void *parameter, wait_result_t wresult)
{
	struct proc *p = current_proc();
	thread_t self  = current_thread();
	struct uthread * ut;
	int sig, catch;
	int error = 0;
	int dropmutex, spinmutex;

	ut = get_bsdthread_info(self);
	catch     = ut->uu_pri & PCATCH;
	dropmutex = ut->uu_pri & PDROP;
	spinmutex = ut->uu_pri & PSPIN;

	switch (wresult) {
		case THREAD_TIMED_OUT:
			error = EWOULDBLOCK;
			break;
		case THREAD_AWAKENED:
			/*
			 * Posix implies any signal should be delivered
			 * first, regardless of whether awakened due
			 * to receiving event.
			 */
			if (!catch)
				break;
			/* else fall through */
		case THREAD_INTERRUPTED:
			if (catch) {
				if (thread_should_abort(self)) {
					error = EINTR;
				} else if (SHOULDissignal(p,ut)) {
					if ((sig = CURSIG(p)) != 0) {
						if (p->p_sigacts->ps_sigintr & sigmask(sig))
							error = EINTR;
						else
							error = ERESTART;
					}
					if (thread_should_abort(self)) {
						error = EINTR;
					}
				} else if( (ut->uu_flag & ( UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL) {
                                        /* due to thread cancel */
                                        error = EINTR;
                                }
			}  else
				error = EINTR;
			break;
	}

	if (error == EINTR || error == ERESTART)
		act_set_astbsd(self);

	if (ut->uu_mtx && !dropmutex) {
		if (spinmutex)
			lck_mtx_lock_spin(ut->uu_mtx);
		else
			lck_mtx_lock(ut->uu_mtx);
	}
	ut->uu_wchan = NULL;
	ut->uu_wmesg = NULL;

	unix_syscall_return((*ut->uu_continuation)(error));
}

/*
 * Give up the processor till a wakeup occurs
 * on chan, at which time the process
 * enters the scheduling queue at priority pri.
 * The most important effect of pri is that when
 * pri<=PZERO a signal cannot disturb the sleep;
 * if pri>PZERO signals will be processed.
 * If pri&PCATCH is set, signals will cause sleep
 * to return 1, rather than longjmp.
 * Callers of this routine must be prepared for
 * premature return, and check that the reason for
 * sleeping has gone away.
 *
 * if msleep was the entry point, than we have a mutex to deal with
 *
 * The mutex is unlocked before the caller is blocked, and
 * relocked before msleep returns unless the priority includes the PDROP
 * flag... if PDROP is specified, _sleep returns with the mutex unlocked
 * regardless of whether it actually blocked or not.
 */

static int
_sleep(
	caddr_t		chan,
	int		pri,
	const char	*wmsg,
	u_int64_t	abstime,
	int		(*continuation)(int),
        lck_mtx_t	*mtx)
{
	struct proc *p;
	thread_t self = current_thread();
	struct uthread * ut;
	int sig, catch = pri & PCATCH;
	int dropmutex  = pri & PDROP;
	int spinmutex  = pri & PSPIN;
	int wait_result;
	int error = 0;

	ut = get_bsdthread_info(self);

	p = current_proc();
	p->p_priority = pri & PRIMASK;
	/* It can still block in proc_exit() after the teardown. */
	if (p->p_stats != NULL)
		OSIncrementAtomicLong(&p->p_stats->p_ru.ru_nvcsw);

	/* set wait message & channel */
	ut->uu_wchan = chan;
	ut->uu_wmesg = wmsg ? wmsg : "unknown";

	if (mtx != NULL && chan != NULL && (thread_continue_t)continuation == THREAD_CONTINUE_NULL) {

		if (abstime)
			wait_result = lck_mtx_sleep_deadline(mtx, (dropmutex) ? LCK_SLEEP_UNLOCK : 0,
							     chan, (catch) ? THREAD_ABORTSAFE : THREAD_UNINT, abstime);
		else
			wait_result = lck_mtx_sleep(mtx, (dropmutex) ? LCK_SLEEP_UNLOCK : 0,
							     chan, (catch) ? THREAD_ABORTSAFE : THREAD_UNINT);
	}
	else {
		if (chan != NULL)
			assert_wait_deadline(chan, (catch) ? THREAD_ABORTSAFE : THREAD_UNINT, abstime);
		if (mtx)
			lck_mtx_unlock(mtx);
		if (catch) {
			if (SHOULDissignal(p,ut)) {
				if ((sig = CURSIG(p)) != 0) {
					if (clear_wait(self, THREAD_INTERRUPTED) == KERN_FAILURE)
						goto block;
					if (p->p_sigacts->ps_sigintr & sigmask(sig))
						error = EINTR;
					else
						error = ERESTART;
					if (mtx && !dropmutex) {
						if (spinmutex)
							lck_mtx_lock_spin(mtx);
						else
							lck_mtx_lock(mtx);
					}
					goto out;
				}
			}
			if (thread_should_abort(self)) {
				if (clear_wait(self, THREAD_INTERRUPTED) == KERN_FAILURE)
					goto block;
				error = EINTR;

				if (mtx && !dropmutex) {
					if (spinmutex)
						lck_mtx_lock_spin(mtx);
					else
						lck_mtx_lock(mtx);
				}
				goto out;
			}
		}		


block:
		if ((thread_continue_t)continuation != THREAD_CONTINUE_NULL) {
		        ut->uu_continuation = continuation;
			ut->uu_pri  = pri;
			ut->uu_timo = abstime? 1: 0;
			ut->uu_mtx  = mtx;
			(void) thread_block(_sleep_continue);
			/* NOTREACHED */
		}
		
		wait_result = thread_block(THREAD_CONTINUE_NULL);

		if (mtx && !dropmutex) {
			if (spinmutex)
				lck_mtx_lock_spin(mtx);
			else
				lck_mtx_lock(mtx);
		}
	}

	switch (wait_result) {
		case THREAD_TIMED_OUT:
			error = EWOULDBLOCK;
			break;
		case THREAD_AWAKENED:
			/*
			 * Posix implies any signal should be delivered
			 * first, regardless of whether awakened due
			 * to receiving event.
			 */
			if (!catch)
				break;
			/* else fall through */
		case THREAD_INTERRUPTED:
			if (catch) {
				if (thread_should_abort(self)) {
					error = EINTR;
				} else if (SHOULDissignal(p, ut)) {
					if ((sig = CURSIG(p)) != 0) {
						if (p->p_sigacts->ps_sigintr & sigmask(sig))
							error = EINTR;
						else
							error = ERESTART;
					}
					if (thread_should_abort(self)) {
						error = EINTR;
					}
				} else if( (ut->uu_flag & ( UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL) {
                                        /* due to thread cancel */
                                        error = EINTR;
                                }
			}  else
				error = EINTR;
			break;
	}
out:
	if (error == EINTR || error == ERESTART)
		act_set_astbsd(self);
	ut->uu_wchan = NULL;
	ut->uu_wmesg = NULL;

	return (error);
}

int
sleep(
	void	*chan,
	int		pri)
{
	return _sleep((caddr_t)chan, pri, (char *)NULL, 0, (int (*)(int))0, (lck_mtx_t *)0);
}

int
msleep0(
	void		*chan,
	lck_mtx_t	*mtx,
	int		pri,
	const char	*wmsg,
	int		timo,
	int		(*continuation)(int))
{
	u_int64_t	abstime = 0;

	if (timo)
		clock_interval_to_deadline(timo, NSEC_PER_SEC / hz, &abstime);

	return _sleep((caddr_t)chan, pri, wmsg, abstime, continuation, mtx);
}

int
msleep(
	void		*chan,
	lck_mtx_t	*mtx,
	int		pri,
	const char	*wmsg,
	struct timespec		*ts)
{
	u_int64_t	abstime = 0;

	if (ts && (ts->tv_sec || ts->tv_nsec)) {
		nanoseconds_to_absolutetime((uint64_t)ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec,  &abstime );
		clock_absolutetime_interval_to_deadline( abstime, &abstime );
	}

	return _sleep((caddr_t)chan, pri, wmsg, abstime, (int (*)(int))0, mtx);
}

int
msleep1(
	void		*chan,
	lck_mtx_t	*mtx,
	int		pri,
	const char	*wmsg,
	u_int64_t	abstime)
{
	return _sleep((caddr_t)chan, pri, wmsg, abstime, (int (*)(int))0, mtx);
}

int
tsleep(
	void		*chan,
	int		pri,
	const char	*wmsg,
	int		timo)
{
	u_int64_t	abstime = 0;

	if (timo)
		clock_interval_to_deadline(timo, NSEC_PER_SEC / hz, &abstime);
	return _sleep((caddr_t)chan, pri, wmsg, abstime, (int (*)(int))0, (lck_mtx_t *)0);
}

int
tsleep0(
	void		*chan,
	int		pri,
	const char	*wmsg,
	int		timo,
	int		(*continuation)(int))
{			
	u_int64_t	abstime = 0;

	if (timo)
		clock_interval_to_deadline(timo, NSEC_PER_SEC / hz, &abstime);
	return _sleep((caddr_t)chan, pri, wmsg, abstime, continuation, (lck_mtx_t *)0);
}

int
tsleep1(
	void		*chan,
	int		pri,
	const char	*wmsg,
	u_int64_t	abstime,
	int		(*continuation)(int))
{			
	return _sleep((caddr_t)chan, pri, wmsg, abstime, continuation, (lck_mtx_t *)0);
}

/*
 * Wake up all processes sleeping on chan.
 */
void
wakeup(void *chan)
{
	thread_wakeup_prim((caddr_t)chan, FALSE, THREAD_AWAKENED);
}

/*
 * Wake up the first process sleeping on chan.
 *
 * Be very sure that the first process is really
 * the right one to wakeup.
 */
void
wakeup_one(caddr_t chan)
{
	thread_wakeup_prim((caddr_t)chan, TRUE, THREAD_AWAKENED);
}

/*
 * Compute the priority of a process when running in user mode.
 * Arrange to reschedule if the resulting priority is better
 * than that of the current process.
 */
void
resetpriority(struct proc *p)
{
	(void)task_importance(p->task, -p->p_nice);
}

struct loadavg averunnable =
	{ {0, 0, 0}, FSCALE };		/* load average, of runnable procs */
/*
 * Constants for averages over 1, 5, and 15 minutes
 * when sampling at 5 second intervals.
 */
static fixpt_t cexp[3] = {
    (fixpt_t)(0.9200444146293232 * FSCALE),    /* exp(-1/12) */
    (fixpt_t)(0.9834714538216174 * FSCALE),    /* exp(-1/60) */
    (fixpt_t)(0.9944598480048967 * FSCALE),    /* exp(-1/180) */
};

void
compute_averunnable(void *arg)
{
	unsigned int		nrun = *(unsigned int *)arg;
	struct loadavg		*avg = &averunnable;
	int		i;

    for (i = 0; i < 3; i++)
        avg->ldavg[i] = (cexp[i] * avg->ldavg[i] +
            nrun * FSCALE * (FSCALE - cexp[i])) >> FSHIFT;
}
