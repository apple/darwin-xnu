/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/kernel.h>
#include <sys/buf.h>

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

#if KTRACE
#include <sys/uio.h>
#include <sys/ktrace.h>
#endif 

static void
_sleep_continue(void)
{
	register struct proc *p;
	register thread_t self = current_act();
	struct uthread * ut;
	int sig, catch;
	int error = 0;

	ut = get_bsdthread_info(self);
	catch = ut->uu_pri & PCATCH;
	p = current_proc();

	switch (get_thread_waitresult(self)) {
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
					if (sig = CURSIG(p)) {
						if (p->p_sigacts->ps_sigintr & sigmask(sig))
							error = EINTR;
						else
							error = ERESTART;
					}
					if (thread_should_abort(self)) {
						error = EINTR;
					}
				}
			}  else
				error = EINTR;
			break;
	}

	if (error == EINTR || error == ERESTART)
		act_set_astbsd(self);

	if (ut->uu_timo)
		thread_cancel_timer();

#if KTRACE
	if (KTRPOINT(p, KTR_CSW))
		ktrcsw(p->p_tracep, 0, 0, -1);
#endif

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
 */

static int
_sleep(
	caddr_t		chan,
	int			pri,
	char		*wmsg,
	u_int64_t	abstime,
	int			(*continuation)(int))
{
	register struct proc *p;
	register thread_t self = current_act();
	struct uthread * ut;
	int sig, catch = pri & PCATCH;
	int sigttblock = pri & PTTYBLOCK;
	int wait_result;
	int error = 0;
	spl_t	s;

	s = splhigh();

	ut = get_bsdthread_info(self);
	
	p = current_proc();
#if KTRACE
	if (KTRPOINT(p, KTR_CSW))
		ktrcsw(p->p_tracep, 1, 0, -1);
#endif	
	p->p_priority = pri & PRIMASK;
		
	if (chan != NULL)
		assert_wait_prim(chan, NULL, abstime,
							(catch) ? THREAD_ABORTSAFE : THREAD_UNINT);
	else
	if (abstime != 0)
		thread_set_timer_deadline(abstime);

	/*
	 * We start our timeout
	 * before calling CURSIG, as we could stop there, and a wakeup
	 * or a SIGCONT (or both) could occur while we were stopped.
	 * A SIGCONT would cause us to be marked as SSLEEP
	 * without resuming us, thus we must be ready for sleep
	 * when CURSIG is called.  If the wakeup happens while we're
	 * stopped, p->p_wchan will be 0 upon return from CURSIG.
	 */
	if (catch) {
		if (SHOULDissignal(p,ut)) {
			if (sig = CURSIG(p)) {
				if (clear_wait(self, THREAD_INTERRUPTED) == KERN_FAILURE)
					goto block;
				/* if SIGTTOU or SIGTTIN then block till SIGCONT */
				if (sigttblock && ((sig == SIGTTOU) || (sig == SIGTTIN))) {
					p->p_flag |= P_TTYSLEEP;
					/* reset signal bits */
					clear_procsiglist(p, sig);
					assert_wait(&p->p_siglist, THREAD_ABORTSAFE);
					/* assert wait can block and SIGCONT should be checked */
					if (p->p_flag & P_TTYSLEEP)
						thread_block(THREAD_CONTINUE_NULL);
					/* return with success */
					error = 0;
					goto out;
				}
				if (p->p_sigacts->ps_sigintr & sigmask(sig))
					error = EINTR;
				else
					error = ERESTART;
				goto out;
			}
		}
		if (thread_should_abort(self)) {
			if (clear_wait(self, THREAD_INTERRUPTED) == KERN_FAILURE)
				goto block;
			error = EINTR;
			goto out;
		}
		if (get_thread_waitresult(self) != THREAD_WAITING) {
			/*already happened */
			goto out;
		}
	}

block:

	splx(s);
	p->p_stats->p_ru.ru_nvcsw++;

	if ((thread_continue_t)continuation != THREAD_CONTINUE_NULL ) {
	  ut->uu_continuation = continuation;
	  ut->uu_pri = pri;
	  ut->uu_timo = abstime? 1: 0;
	  (void) thread_block(_sleep_continue);
	  /* NOTREACHED */
	}

	wait_result = thread_block(THREAD_CONTINUE_NULL);

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
				} else if (SHOULDissignal(p,ut)) {
					if (sig = CURSIG(p)) {
						if (p->p_sigacts->ps_sigintr & sigmask(sig))
							error = EINTR;
						else
							error = ERESTART;
					}
					if (thread_should_abort(self)) {
						error = EINTR;
					}
				}
			}  else
				error = EINTR;
			break;
	}
out:
	if (error == EINTR || error == ERESTART)
		act_set_astbsd(self);
	if (abstime)
		thread_cancel_timer();
	(void) splx(s);
#if KTRACE
	if (KTRPOINT(p, KTR_CSW))
		ktrcsw(p->p_tracep, 0, 0, -1);
#endif
	return (error);
}

int
sleep(
	void	*chan,
	int		pri)
{
	return _sleep((caddr_t)chan, pri, (char *)NULL, 0, (int (*)(int))0);
}

int
tsleep(
	void	*chan,
	int		pri,
	char	*wmsg,
	int		timo)
{
	u_int64_t	abstime = 0;

	if (timo)
		clock_interval_to_deadline(timo, NSEC_PER_SEC / hz, &abstime);
	return _sleep((caddr_t)chan, pri, wmsg, abstime, (int (*)(int))0);
}

int
tsleep0(
	void	*chan,
	int		pri,
	char	*wmsg,
	int		timo,
	int		(*continuation)(int))
{			
	u_int64_t	abstime = 0;

	if (timo)
		clock_interval_to_deadline(timo, NSEC_PER_SEC / hz, &abstime);
	return _sleep((caddr_t)chan, pri, wmsg, abstime, continuation);
}

int
tsleep1(
	void		*chan,
	int			pri,
	char		*wmsg,
	u_int64_t	abstime,
	int			(*continuation)(int))
{			
	return _sleep((caddr_t)chan, pri, wmsg, abstime, continuation);
}

/*
 * Wake up all processes sleeping on chan.
 */
void
wakeup(chan)
	register void *chan;
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
wakeup_one(chan)
	register caddr_t chan;
{
	thread_wakeup_prim((caddr_t)chan, TRUE, THREAD_AWAKENED);
}

/*
 * Compute the priority of a process when running in user mode.
 * Arrange to reschedule if the resulting priority is better
 * than that of the current process.
 */
void
resetpriority(p)
	register struct proc *p;
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
compute_averunnable(
	register int	nrun)
{
	register int		i;
	struct loadavg		*avg = &averunnable;

    for (i = 0; i < 3; i++)
        avg->ldavg[i] = (cexp[i] * avg->ldavg[i] +
            nrun * FSCALE * (FSCALE - cexp[i])) >> FSHIFT;
}
