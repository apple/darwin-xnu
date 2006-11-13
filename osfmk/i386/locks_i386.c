/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 *	File:	kern/lock.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Locking primitives implementation
 */

#include <mach_kdb.h>
#include <mach_ldebug.h>

#include <kern/lock.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/sched_prim.h>
#include <kern/xpr.h>
#include <kern/debug.h>
#include <string.h>

#if	MACH_KDB
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_sym.h>
#include <ddb/db_print.h>
#endif	/* MACH_KDB */

#ifdef __ppc__
#include <ppc/Firmware.h>
#endif

#include <sys/kdebug.h>

#define	LCK_RW_LCK_EXCLUSIVE_CODE	0x100
#define	LCK_RW_LCK_EXCLUSIVE1_CODE	0x101
#define	LCK_RW_LCK_SHARED_CODE		0x102
#define	LCK_RW_LCK_SH_TO_EX_CODE	0x103
#define	LCK_RW_LCK_SH_TO_EX1_CODE	0x104
#define	LCK_RW_LCK_EX_TO_SH_CODE	0x105


#define	ANY_LOCK_DEBUG	(USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

unsigned int LcksOpts=0;
unsigned int lock_wait_time[2] = { (unsigned int)-1, 100 } ;

/* Forwards */

#if	MACH_KDB
void	db_print_simple_lock(
			simple_lock_t	addr);

void	db_print_mutex(
			mutex_t		* addr);
#endif	/* MACH_KDB */


#if	USLOCK_DEBUG
/*
 *	Perform simple lock checks.
 */
int	uslock_check = 1;
int	max_lock_loops	= 100000000;
decl_simple_lock_data(extern , printf_lock)
decl_simple_lock_data(extern , panic_lock)
#if	MACH_KDB
decl_simple_lock_data(extern , kdb_lock)
#endif	/* MACH_KDB */
#endif	/* USLOCK_DEBUG */


/*
 *	We often want to know the addresses of the callers
 *	of the various lock routines.  However, this information
 *	is only used for debugging and statistics.
 */
typedef void	*pc_t;
#define	INVALID_PC	((void *) VM_MAX_KERNEL_ADDRESS)
#define	INVALID_THREAD	((void *) VM_MAX_KERNEL_ADDRESS)
#if	ANY_LOCK_DEBUG
#define	OBTAIN_PC(pc,l)	((pc) = (void *) GET_RETURN_PC(&(l)))
#define DECL_PC(pc)	pc_t pc;
#else	/* ANY_LOCK_DEBUG */
#define DECL_PC(pc)
#ifdef	lint
/*
 *	Eliminate lint complaints about unused local pc variables.
 */
#define	OBTAIN_PC(pc,l)	++pc
#else	/* lint */
#define	OBTAIN_PC(pc,l)
#endif	/* lint */
#endif	/* USLOCK_DEBUG */


/*
 *	Portable lock package implementation of usimple_locks.
 */

#if	USLOCK_DEBUG
#define	USLDBG(stmt)	stmt
void		usld_lock_init(usimple_lock_t, unsigned short);
void		usld_lock_pre(usimple_lock_t, pc_t);
void		usld_lock_post(usimple_lock_t, pc_t);
void		usld_unlock(usimple_lock_t, pc_t);
void		usld_lock_try_pre(usimple_lock_t, pc_t);
void		usld_lock_try_post(usimple_lock_t, pc_t);
int		usld_lock_common_checks(usimple_lock_t, char *);
#else	/* USLOCK_DEBUG */
#define	USLDBG(stmt)
#endif	/* USLOCK_DEBUG */

/*
 *      Routine:        lck_spin_alloc_init
 */
lck_spin_t *
lck_spin_alloc_init(
	lck_grp_t	*grp,
	lck_attr_t	*attr)
{
	lck_spin_t	*lck;

	if ((lck = (lck_spin_t *)kalloc(sizeof(lck_spin_t))) != 0)
		lck_spin_init(lck, grp, attr);

	return(lck);
}

/*
 *      Routine:        lck_spin_free
 */
void
lck_spin_free(
	lck_spin_t	*lck,
	lck_grp_t	*grp)
{
	lck_spin_destroy(lck, grp);
	kfree(lck, sizeof(lck_spin_t));
}

/*
 *      Routine:        lck_spin_init
 */
void
lck_spin_init(
	lck_spin_t	*lck,
	lck_grp_t	*grp,
	__unused lck_attr_t	*attr)
{
	usimple_lock_init((usimple_lock_t) lck, 0);
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_SPIN);
}

/*
 *      Routine:        lck_spin_destroy
 */
void
lck_spin_destroy(
	lck_spin_t	*lck,
	lck_grp_t	*grp)
{
	if (lck->lck_spin_data[0] == LCK_SPIN_TAG_DESTROYED)
		return;
	lck->lck_spin_data[0] = LCK_SPIN_TAG_DESTROYED;
	lck_grp_lckcnt_decr(grp, LCK_TYPE_SPIN);
	lck_grp_deallocate(grp);
	return;
}

/*
 *      Routine:        lck_spin_lock
 */
void
lck_spin_lock(
	lck_spin_t	*lck)
{
	usimple_lock((usimple_lock_t) lck);
}

/*
 *      Routine:        lck_spin_unlock
 */
void
lck_spin_unlock(
	lck_spin_t	*lck)
{
	usimple_unlock((usimple_lock_t) lck);
}


/*
 *      Routine:        lck_spin_try_lock
 */
boolean_t
lck_spin_try_lock(
	lck_spin_t	*lck)
{
	usimple_lock_try((usimple_lock_t) lck);
}

/*
 *	Initialize a usimple_lock.
 *
 *	No change in preemption state.
 */
void
usimple_lock_init(
	usimple_lock_t	l,
	__unused unsigned short	tag)
{
#ifndef	MACHINE_SIMPLE_LOCK
	USLDBG(usld_lock_init(l, tag));
	hw_lock_init(&l->interlock);
#else
	simple_lock_init((simple_lock_t)l,tag);
#endif
}


/*
 *	Acquire a usimple_lock.
 *
 *	Returns with preemption disabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
usimple_lock(
	usimple_lock_t	l)
{
#ifndef	MACHINE_SIMPLE_LOCK
	pc_t		pc = NULL;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_pre(l, pc));

	if(!hw_lock_to(&l->interlock, LockTimeOut))	/* Try to get the lock with a timeout */ 
		panic("simple lock deadlock detection - l=%08X, cpu=%d, ret=%08X", l, cpu_number(), pc);

	USLDBG(usld_lock_post(l, pc));
#else
	simple_lock((simple_lock_t)l);
#endif
}


/*
 *	Release a usimple_lock.
 *
 *	Returns with preemption enabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
usimple_unlock(
	usimple_lock_t	l)
{
#ifndef	MACHINE_SIMPLE_LOCK
	DECL_PC(pc);

	OBTAIN_PC(pc, l);
	USLDBG(usld_unlock(l, pc));
	hw_lock_unlock(&l->interlock);
#else
	simple_unlock_rwmb((simple_lock_t)l);
#endif
}


/*
 *	Conditionally acquire a usimple_lock.
 *
 *	On success, returns with preemption disabled.
 *	On failure, returns with preemption in the same state
 *	as when first invoked.  Note that the hw_lock routines
 *	are responsible for maintaining preemption state.
 *
 *	XXX No stats are gathered on a miss; I preserved this
 *	behavior from the original assembly-language code, but
 *	doesn't it make sense to log misses?  XXX
 */
unsigned int
usimple_lock_try(
	usimple_lock_t	l)
{
#ifndef	MACHINE_SIMPLE_LOCK
	DECL_PC(pc);
	unsigned int	success;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_try_pre(l, pc));
	if ((success = hw_lock_try(&l->interlock))) {
		USLDBG(usld_lock_try_post(l, pc));
	}
	return success;
#else
	return(simple_lock_try((simple_lock_t)l));
#endif
}

#if	USLOCK_DEBUG
/*
 *	States of a usimple_lock.  The default when initializing
 *	a usimple_lock is setting it up for debug checking.
 */
#define	USLOCK_CHECKED		0x0001		/* lock is being checked */
#define	USLOCK_TAKEN		0x0002		/* lock has been taken */
#define	USLOCK_INIT		0xBAA0		/* lock has been initialized */
#define	USLOCK_INITIALIZED	(USLOCK_INIT|USLOCK_CHECKED)
#define	USLOCK_CHECKING(l)	(uslock_check &&			\
				 ((l)->debug.state & USLOCK_CHECKED))

/*
 *	Trace activities of a particularly interesting lock.
 */
void	usl_trace(usimple_lock_t, int, pc_t, const char *);


/*
 *	Initialize the debugging information contained
 *	in a usimple_lock.
 */
void
usld_lock_init(
	usimple_lock_t	l,
	__unused unsigned short	tag)
{
	if (l == USIMPLE_LOCK_NULL)
		panic("lock initialization:  null lock pointer");
	l->lock_type = USLOCK_TAG;
	l->debug.state = uslock_check ? USLOCK_INITIALIZED : 0;
	l->debug.lock_cpu = l->debug.unlock_cpu = 0;
	l->debug.lock_pc = l->debug.unlock_pc = INVALID_PC;
	l->debug.lock_thread = l->debug.unlock_thread = INVALID_THREAD;
	l->debug.duration[0] = l->debug.duration[1] = 0;
	l->debug.unlock_cpu = l->debug.unlock_cpu = 0;
	l->debug.unlock_pc = l->debug.unlock_pc = INVALID_PC;
	l->debug.unlock_thread = l->debug.unlock_thread = INVALID_THREAD;
}


/*
 *	These checks apply to all usimple_locks, not just
 *	those with USLOCK_CHECKED turned on.
 */
int
usld_lock_common_checks(
	usimple_lock_t	l,
	char		*caller)
{
	if (l == USIMPLE_LOCK_NULL)
		panic("%s:  null lock pointer", caller);
	if (l->lock_type != USLOCK_TAG)
		panic("%s:  0x%x is not a usimple lock", caller, (integer_t) l);
	if (!(l->debug.state & USLOCK_INIT))
		panic("%s:  0x%x is not an initialized lock",
		      caller, (integer_t) l);
	return USLOCK_CHECKING(l);
}


/*
 *	Debug checks on a usimple_lock just before attempting
 *	to acquire it.
 */
/* ARGSUSED */
void
usld_lock_pre(
	usimple_lock_t	l,
	pc_t		pc)
{
	char	caller[] = "usimple_lock";


	if (!usld_lock_common_checks(l, caller))
		return;

/*
 *	Note that we have a weird case where we are getting a lock when we are]
 *	in the process of putting the system to sleep. We are running with no
 *	current threads, therefore we can't tell if we are trying to retake a lock
 *	we have or someone on the other processor has it.  Therefore we just
 *	ignore this test if the locking thread is 0.
 */

	if ((l->debug.state & USLOCK_TAKEN) && l->debug.lock_thread &&
	    l->debug.lock_thread == (void *) current_thread()) {
		printf("%s:  lock 0x%x already locked (at 0x%x) by",
		      caller, (integer_t) l, l->debug.lock_pc);
		printf(" current thread 0x%x (new attempt at pc 0x%x)\n",
		       l->debug.lock_thread, pc);
		panic(caller);
	}
	mp_disable_preemption();
	usl_trace(l, cpu_number(), pc, caller);
	mp_enable_preemption();
}


/*
 *	Debug checks on a usimple_lock just after acquiring it.
 *
 *	Pre-emption has been disabled at this point,
 *	so we are safe in using cpu_number.
 */
void
usld_lock_post(
	usimple_lock_t	l,
	pc_t		pc)
{
	register int	mycpu;
	char	caller[] = "successful usimple_lock";


	if (!usld_lock_common_checks(l, caller))
		return;

	if (!((l->debug.state & ~USLOCK_TAKEN) == USLOCK_INITIALIZED))
		panic("%s:  lock 0x%x became uninitialized",
		      caller, (integer_t) l);
	if ((l->debug.state & USLOCK_TAKEN))
		panic("%s:  lock 0x%x became TAKEN by someone else",
		      caller, (integer_t) l);

	mycpu = cpu_number();
	l->debug.lock_thread = (void *)current_thread();
	l->debug.state |= USLOCK_TAKEN;
	l->debug.lock_pc = pc;
	l->debug.lock_cpu = mycpu;

	usl_trace(l, mycpu, pc, caller);
}


/*
 *	Debug checks on a usimple_lock just before
 *	releasing it.  Note that the caller has not
 *	yet released the hardware lock.
 *
 *	Preemption is still disabled, so there's
 *	no problem using cpu_number.
 */
void
usld_unlock(
	usimple_lock_t	l,
	pc_t		pc)
{
	register int	mycpu;
	char	caller[] = "usimple_unlock";


	if (!usld_lock_common_checks(l, caller))
		return;

	mycpu = cpu_number();

	if (!(l->debug.state & USLOCK_TAKEN))
		panic("%s:  lock 0x%x hasn't been taken",
		      caller, (integer_t) l);
	if (l->debug.lock_thread != (void *) current_thread())
		panic("%s:  unlocking lock 0x%x, owned by thread 0x%x",
		      caller, (integer_t) l, l->debug.lock_thread);
	if (l->debug.lock_cpu != mycpu) {
		printf("%s:  unlocking lock 0x%x on cpu 0x%x",
		       caller, (integer_t) l, mycpu);
		printf(" (acquired on cpu 0x%x)\n", l->debug.lock_cpu);
		panic(caller);
	}
	usl_trace(l, mycpu, pc, caller);

	l->debug.unlock_thread = l->debug.lock_thread;
	l->debug.lock_thread = INVALID_PC;
	l->debug.state &= ~USLOCK_TAKEN;
	l->debug.unlock_pc = pc;
	l->debug.unlock_cpu = mycpu;
}


/*
 *	Debug checks on a usimple_lock just before
 *	attempting to acquire it.
 *
 *	Preemption isn't guaranteed to be disabled.
 */
void
usld_lock_try_pre(
	usimple_lock_t	l,
	pc_t		pc)
{
	char	caller[] = "usimple_lock_try";

	if (!usld_lock_common_checks(l, caller))
		return;
	mp_disable_preemption();
	usl_trace(l, cpu_number(), pc, caller);
	mp_enable_preemption();
}


/*
 *	Debug checks on a usimple_lock just after
 *	successfully attempting to acquire it.
 *
 *	Preemption has been disabled by the
 *	lock acquisition attempt, so it's safe
 *	to use cpu_number.
 */
void
usld_lock_try_post(
	usimple_lock_t	l,
	pc_t		pc)
{
	register int	mycpu;
	char	caller[] = "successful usimple_lock_try";

	if (!usld_lock_common_checks(l, caller))
		return;

	if (!((l->debug.state & ~USLOCK_TAKEN) == USLOCK_INITIALIZED))
		panic("%s:  lock 0x%x became uninitialized",
		      caller, (integer_t) l);
	if ((l->debug.state & USLOCK_TAKEN))
		panic("%s:  lock 0x%x became TAKEN by someone else",
		      caller, (integer_t) l);

	mycpu = cpu_number();
	l->debug.lock_thread = (void *) current_thread();
	l->debug.state |= USLOCK_TAKEN;
	l->debug.lock_pc = pc;
	l->debug.lock_cpu = mycpu;

	usl_trace(l, mycpu, pc, caller);
}


/*
 *	For very special cases, set traced_lock to point to a
 *	specific lock of interest.  The result is a series of
 *	XPRs showing lock operations on that lock.  The lock_seq
 *	value is used to show the order of those operations.
 */
usimple_lock_t		traced_lock;
unsigned int		lock_seq;

void
usl_trace(
	usimple_lock_t	l,
	int		mycpu,
	pc_t		pc,
	const char *	op_name)
{
	if (traced_lock == l) {
		XPR(XPR_SLOCK,
		    "seq %d, cpu %d, %s @ %x\n",
		    (integer_t) lock_seq, (integer_t) mycpu,
		    (integer_t) op_name, (integer_t) pc, 0);
		lock_seq++;
	}
}


#endif	/* USLOCK_DEBUG */

/*
 *	Routine:	lock_alloc
 *	Function:
 *		Allocate a lock for external users who cannot
 *		hard-code the structure definition into their
 *		objects.
 *		For now just use kalloc, but a zone is probably
 *		warranted.
 */
lock_t *
lock_alloc(
	boolean_t	can_sleep,
	unsigned short	tag,
	unsigned short	tag1)
{
	lock_t		*l;

	if ((l = (lock_t *)kalloc(sizeof(lock_t))) != 0)
	  lock_init(l, can_sleep, tag, tag1);
	return(l);
}

/*
 *	Routine:	lock_free
 *	Function:
 *		Free a lock allocated for external users.
 *		For now just use kfree, but a zone is probably
 *		warranted.
 */
void
lock_free(
	lock_t		*l)
{
	kfree(l, sizeof(lock_t));
}

	  
/*
 *	Routine:	lock_init
 *	Function:
 *		Initialize a lock; required before use.
 *		Note that clients declare the "struct lock"
 *		variables and then initialize them, rather
 *		than getting a new one from this module.
 */
void
lock_init(
	lock_t		*l,
	boolean_t	can_sleep,
	__unused unsigned short	tag,
	unsigned short	tag1)
{
	(void) memset((void *) l, 0, sizeof(lock_t));

	simple_lock_init(&l->interlock, tag1);
	l->want_write = FALSE;
	l->want_upgrade = FALSE;
	l->read_count = 0;
	l->can_sleep = can_sleep;
}


/*
 *	Sleep locks.  These use the same data structure and algorithm
 *	as the spin locks, but the process sleeps while it is waiting
 *	for the lock.  These work on uniprocessor systems.
 */

#define DECREMENTER_TIMEOUT 1000000

void
lock_write(
	register lock_t	* l)
{
        register int	   i;
	boolean_t          lock_miss = FALSE;
#if	MACH_LDEBUG
	int		   decrementer;
#endif	/* MACH_LDEBUG */

	simple_lock(&l->interlock);

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */

	/*
	 *	Try to acquire the want_write bit.
	 */
	while (l->want_write) {
		if (!lock_miss) {
			lock_miss = TRUE;
		}

		i = lock_wait_time[l->can_sleep ? 1 : 0];
		if (i != 0) {
			simple_unlock(&l->interlock);
#if	MACH_LDEBUG
			if (!--decrementer)
				Debugger("timeout - want_write");
#endif	/* MACH_LDEBUG */
			while (--i != 0 && l->want_write)
				continue;
			simple_lock(&l->interlock);
		}

		if (l->can_sleep && l->want_write) {
			l->waiting = TRUE;
			thread_sleep_simple_lock((event_t) l,
					simple_lock_addr(l->interlock),
					THREAD_UNINT);
			/* interlock relocked */
		}
	}
	l->want_write = TRUE;

	/* Wait for readers (and upgrades) to finish */

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */
	while ((l->read_count != 0) || l->want_upgrade) {
		if (!lock_miss) {
			lock_miss = TRUE;
		}

		i = lock_wait_time[l->can_sleep ? 1 : 0];
		if (i != 0) {
			simple_unlock(&l->interlock);
#if	MACH_LDEBUG
			if (!--decrementer)
				Debugger("timeout - wait for readers");
#endif	/* MACH_LDEBUG */
			while (--i != 0 && (l->read_count != 0 ||
					    l->want_upgrade))
				continue;
			simple_lock(&l->interlock);
		}

		if (l->can_sleep && (l->read_count != 0 || l->want_upgrade)) {
			l->waiting = TRUE;
			thread_sleep_simple_lock((event_t) l,
				simple_lock_addr(l->interlock),
				THREAD_UNINT);
			/* interlock relocked */
		}
	}

	simple_unlock(&l->interlock);
}

void
lock_done(
	register lock_t	* l)
{
	boolean_t	  do_wakeup = FALSE;


	simple_lock(&l->interlock);

	if (l->read_count != 0) {
		l->read_count--;
	}
	else	
		if (l->want_upgrade) {
			l->want_upgrade = FALSE;
		}
	else {
		l->want_write = FALSE;
	}

	/*
	 *	There is no reason to wakeup a waiting thread
	 *	if the read-count is non-zero.  Consider:
	 *		we must be dropping a read lock
	 *		threads are waiting only if one wants a write lock
	 *		if there are still readers, they can't proceed
	 */

	if (l->waiting && (l->read_count == 0)) {
		l->waiting = FALSE;
		do_wakeup = TRUE;
	}

	simple_unlock(&l->interlock);

	if (do_wakeup)
		thread_wakeup((event_t) l);
}

void
lock_read(
	register lock_t	* l)
{
	register int	    i;
#if	MACH_LDEBUG
	int		   decrementer;
#endif	/* MACH_LDEBUG */

	simple_lock(&l->interlock);

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */
	while (l->want_write || l->want_upgrade) {
		i = lock_wait_time[l->can_sleep ? 1 : 0];

		if (i != 0) {
			simple_unlock(&l->interlock);
#if	MACH_LDEBUG
			if (!--decrementer)
				Debugger("timeout - wait no writers");
#endif	/* MACH_LDEBUG */
			while (--i != 0 && (l->want_write || l->want_upgrade))
				continue;
			simple_lock(&l->interlock);
		}

		if (l->can_sleep && (l->want_write || l->want_upgrade)) {
			l->waiting = TRUE;
			thread_sleep_simple_lock((event_t) l,
					simple_lock_addr(l->interlock),
					THREAD_UNINT);
			/* interlock relocked */
		}
	}

	l->read_count++;

	simple_unlock(&l->interlock);
}


/*
 *	Routine:	lock_read_to_write
 *	Function:
 *		Improves a read-only lock to one with
 *		write permission.  If another reader has
 *		already requested an upgrade to a write lock,
 *		no lock is held upon return.
 *
 *		Returns TRUE if the upgrade *failed*.
 */

boolean_t
lock_read_to_write(
	register lock_t	* l)
{
	register int	    i;
	boolean_t	    do_wakeup = FALSE;
#if	MACH_LDEBUG
	int		   decrementer;
#endif	/* MACH_LDEBUG */

	simple_lock(&l->interlock);

	l->read_count--;	

	if (l->want_upgrade) {
		/*
		 *	Someone else has requested upgrade.
		 *	Since we've released a read lock, wake
		 *	him up.
		 */
		if (l->waiting && (l->read_count == 0)) {
			l->waiting = FALSE;
			do_wakeup = TRUE;
		}

		simple_unlock(&l->interlock);

		if (do_wakeup)
			thread_wakeup((event_t) l);
		return (TRUE);
	}

	l->want_upgrade = TRUE;

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */
	while (l->read_count != 0) {
		i = lock_wait_time[l->can_sleep ? 1 : 0];

		if (i != 0) {
			simple_unlock(&l->interlock);
#if	MACH_LDEBUG
			if (!--decrementer)
				Debugger("timeout - read_count");
#endif	/* MACH_LDEBUG */
			while (--i != 0 && l->read_count != 0)
				continue;
			simple_lock(&l->interlock);
		}

		if (l->can_sleep && l->read_count != 0) {
			l->waiting = TRUE;
			thread_sleep_simple_lock((event_t) l,
					simple_lock_addr(l->interlock),
					THREAD_UNINT);
			/* interlock relocked */
		}
	}

	simple_unlock(&l->interlock);

	return (FALSE);
}

void
lock_write_to_read(
	register lock_t	* l)
{
	boolean_t	   do_wakeup = FALSE;

	simple_lock(&l->interlock);

	l->read_count++;
	if (l->want_upgrade)
		l->want_upgrade = FALSE;
	else
	 	l->want_write = FALSE;

	if (l->waiting) {
		l->waiting = FALSE;
		do_wakeup = TRUE;
	}

	simple_unlock(&l->interlock);

	if (do_wakeup)
		thread_wakeup((event_t) l);
}


#if	0	/* Unused */
/*
 *	Routine:	lock_try_write
 *	Function:
 *		Tries to get a write lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */

boolean_t
lock_try_write(
	register lock_t	* l)
{
	pc_t		   pc;

	simple_lock(&l->interlock);

	if (l->want_write || l->want_upgrade || l->read_count) {
		/*
		 *	Can't get lock.
		 */
		simple_unlock(&l->interlock);
		return(FALSE);
	}

	/*
	 *	Have lock.
	 */

	l->want_write = TRUE;

	simple_unlock(&l->interlock);

	return(TRUE);
}

/*
 *	Routine:	lock_try_read
 *	Function:
 *		Tries to get a read lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */

boolean_t
lock_try_read(
	register lock_t	* l)
{
	pc_t		   pc;

	simple_lock(&l->interlock);

	if (l->want_write || l->want_upgrade) {
		simple_unlock(&l->interlock);
		return(FALSE);
	}

	l->read_count++;

	simple_unlock(&l->interlock);

	return(TRUE);
}
#endif		/* Unused */


/*
 *      Routine:        lck_rw_alloc_init
 */
lck_rw_t *
lck_rw_alloc_init(
	lck_grp_t	*grp,
	lck_attr_t	*attr) {
	lck_rw_t	*lck;

	if ((lck = (lck_rw_t *)kalloc(sizeof(lck_rw_t))) != 0)
		lck_rw_init(lck, grp, attr);
		
	return(lck);
}

/*
 *      Routine:        lck_rw_free
 */
void
lck_rw_free(
	lck_rw_t	*lck,
	lck_grp_t	*grp) {
	lck_rw_destroy(lck, grp);
	kfree(lck, sizeof(lck_rw_t));
}

/*
 *      Routine:        lck_rw_init
 */
void
lck_rw_init(
	lck_rw_t	*lck,
	lck_grp_t	*grp,
	__unused lck_attr_t	*attr) {

	hw_lock_init(&lck->interlock);
	lck->want_write = FALSE;
	lck->want_upgrade = FALSE;
	lck->read_count = 0;
	lck->can_sleep = TRUE;
	lck->lck_rw_tag = 0;

	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_RW);
}

/*
 *      Routine:        lck_rw_destroy
 */
void
lck_rw_destroy(
	lck_rw_t	*lck,
	lck_grp_t	*grp) {
	if (lck->lck_rw_tag == LCK_RW_TAG_DESTROYED)
		return;
	lck->lck_rw_tag = LCK_RW_TAG_DESTROYED;
	lck_grp_lckcnt_decr(grp, LCK_TYPE_RW);
	lck_grp_deallocate(grp);
	return;
}

/*
 *	Sleep locks.  These use the same data structure and algorithm
 *	as the spin locks, but the process sleeps while it is waiting
 *	for the lock.  These work on uniprocessor systems.
 */

#define DECREMENTER_TIMEOUT 1000000


/*
 * We need to disable interrupts while holding the mutex interlock
 * to prevent an IPI intervening.
 * Hence, local helper functions lck_interlock_lock()/lck_interlock_unlock().
 */
static boolean_t
lck_interlock_lock(lck_rw_t *lck)
{
	boolean_t	istate;

	istate = ml_set_interrupts_enabled(FALSE);	
	hw_lock_lock(&lck->interlock);

	return istate;
}

static void
lck_interlock_unlock(lck_rw_t *lck, boolean_t istate)
{               
	hw_lock_unlock(&lck->interlock);
	ml_set_interrupts_enabled(istate);
}

/*
 *      Routine:        lck_rw_lock_exclusive
 */
void
lck_rw_lock_exclusive(
	lck_rw_t	*lck)
{
	int	   i;
	boolean_t		lock_miss = FALSE;
	wait_result_t	res;
#if	MACH_LDEBUG
	int				decrementer;
#endif	/* MACH_LDEBUG */
	boolean_t	istate;

	istate = lck_interlock_lock(lck);

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */

	/*
	 *	Try to acquire the want_write bit.
	 */
	while (lck->want_write) {
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE_CODE) | DBG_FUNC_START, (int)lck, 0, 0, 0, 0);

		if (!lock_miss) {
			lock_miss = TRUE;
		}

		i = lock_wait_time[lck->can_sleep ? 1 : 0];
		if (i != 0) {
			lck_interlock_unlock(lck, istate);
#if	MACH_LDEBUG
			if (!--decrementer)
				Debugger("timeout - want_write");
#endif	/* MACH_LDEBUG */
			while (--i != 0 && lck->want_write)
				continue;
			istate = lck_interlock_lock(lck);
		}

		if (lck->can_sleep && lck->want_write) {
			lck->waiting = TRUE;
			res = assert_wait((event_t) lck, THREAD_UNINT);
			if (res == THREAD_WAITING) {
				lck_interlock_unlock(lck, istate);
				res = thread_block(THREAD_CONTINUE_NULL);
				istate = lck_interlock_lock(lck);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE_CODE) | DBG_FUNC_END, (int)lck, res, 0, 0, 0);
	}
	lck->want_write = TRUE;

	/* Wait for readers (and upgrades) to finish */

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */
	while ((lck->read_count != 0) || lck->want_upgrade) {
		if (!lock_miss) {
			lock_miss = TRUE;
		}

		i = lock_wait_time[lck->can_sleep ? 1 : 0];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE1_CODE) | DBG_FUNC_START,
			     (int)lck, lck->read_count, lck->want_upgrade, i, 0);

		if (i != 0) {
			lck_interlock_unlock(lck, istate);
#if	MACH_LDEBUG
			if (!--decrementer)
				Debugger("timeout - wait for readers");
#endif	/* MACH_LDEBUG */
			while (--i != 0 && (lck->read_count != 0 ||
					    lck->want_upgrade))
				continue;
			istate = lck_interlock_lock(lck);
		}

		if (lck->can_sleep && (lck->read_count != 0 || lck->want_upgrade)) {
			lck->waiting = TRUE;
			res = assert_wait((event_t) lck, THREAD_UNINT);
			if (res == THREAD_WAITING) {
				lck_interlock_unlock(lck, istate);
				res = thread_block(THREAD_CONTINUE_NULL);
				istate = lck_interlock_lock(lck);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE1_CODE) | DBG_FUNC_END,
			     (int)lck, lck->read_count, lck->want_upgrade, res, 0);
	}

	lck_interlock_unlock(lck, istate);
}


/*
 *      Routine:        lck_rw_done
 */
lck_rw_type_t
lck_rw_done(
	lck_rw_t	*lck)
{
	boolean_t	do_wakeup = FALSE;
	lck_rw_type_t	lck_rw_type;
	boolean_t	istate;


	istate = lck_interlock_lock(lck);

	if (lck->read_count != 0) {
		lck_rw_type = LCK_RW_TYPE_SHARED;
		lck->read_count--;
	}
	else {	
		lck_rw_type = LCK_RW_TYPE_EXCLUSIVE;
		if (lck->want_upgrade) 
			lck->want_upgrade = FALSE;
		else 
			lck->want_write = FALSE;
	}

	/*
	 *	There is no reason to wakeup a waiting thread
	 *	if the read-count is non-zero.  Consider:
	 *		we must be dropping a read lock
	 *		threads are waiting only if one wants a write lock
	 *		if there are still readers, they can't proceed
	 */

	if (lck->waiting && (lck->read_count == 0)) {
		lck->waiting = FALSE;
		do_wakeup = TRUE;
	}

	lck_interlock_unlock(lck, istate);

	if (do_wakeup)
		thread_wakeup((event_t) lck);
	return(lck_rw_type);
}




/*
 *	Routine:	lck_rw_unlock
 */
void
lck_rw_unlock(
	lck_rw_t	*lck,
	lck_rw_type_t	lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED)
		lck_rw_unlock_shared(lck);
	else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE)
		lck_rw_unlock_exclusive(lck);
	else
		panic("lck_rw_unlock(): Invalid RW lock type: %d\n", lck_rw_type);
}


/*
 *	Routine:	lck_rw_unlock_shared
 */
void
lck_rw_unlock_shared(
	lck_rw_t	*lck)
{
	lck_rw_type_t	ret;

	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_SHARED)
		panic("lck_rw_unlock(): lock held in mode: %d\n", ret);
}


/*
 *	Routine:	lck_rw_unlock_exclusive
 */
void
lck_rw_unlock_exclusive(
	lck_rw_t	*lck)
{
	lck_rw_type_t	ret;

	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_EXCLUSIVE)
		panic("lck_rw_unlock_exclusive(): lock held in mode: %d\n", ret);
}


/*
 *	Routine:	lck_rw_lock
 */
void
lck_rw_lock(
	lck_rw_t	*lck,
	lck_rw_type_t	lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED)
		lck_rw_lock_shared(lck);
	else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE)
		lck_rw_lock_exclusive(lck);
	else
		panic("lck_rw_lock(): Invalid RW lock type: %x\n", lck_rw_type);
}


/*
 *	Routine:	lck_rw_lock_shared
 */
void
lck_rw_lock_shared(
	lck_rw_t	*lck)
{
	int		i;
	wait_result_t      res;
#if	MACH_LDEBUG
	int		decrementer;
#endif	/* MACH_LDEBUG */
	boolean_t	istate;

	istate = lck_interlock_lock(lck);

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */
	while (lck->want_write || lck->want_upgrade) {
		i = lock_wait_time[lck->can_sleep ? 1 : 0];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_CODE) | DBG_FUNC_START,
			     (int)lck, lck->want_write, lck->want_upgrade, i, 0);

		if (i != 0) {
			lck_interlock_unlock(lck, istate);
#if	MACH_LDEBUG
			if (!--decrementer)
				Debugger("timeout - wait no writers");
#endif	/* MACH_LDEBUG */
			while (--i != 0 && (lck->want_write || lck->want_upgrade))
				continue;
			istate = lck_interlock_lock(lck);
		}

		if (lck->can_sleep && (lck->want_write || lck->want_upgrade)) {
			lck->waiting = TRUE;
			res = assert_wait((event_t) lck, THREAD_UNINT);
			if (res == THREAD_WAITING) {
				lck_interlock_unlock(lck, istate);
				res = thread_block(THREAD_CONTINUE_NULL);
				istate = lck_interlock_lock(lck);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_CODE) | DBG_FUNC_END,
			     (int)lck, lck->want_write, lck->want_upgrade, res, 0);
	}

	lck->read_count++;

	lck_interlock_unlock(lck, istate);
}


/*
 *	Routine:	lck_rw_lock_shared_to_exclusive
 *	Function:
 *		Improves a read-only lock to one with
 *		write permission.  If another reader has
 *		already requested an upgrade to a write lock,
 *		no lock is held upon return.
 *
 *		Returns TRUE if the upgrade *failed*.
 */

boolean_t
lck_rw_lock_shared_to_exclusive(
	lck_rw_t	*lck)
{
	int	    i;
	boolean_t	    do_wakeup = FALSE;
	wait_result_t      res;
#if	MACH_LDEBUG
	int		   decrementer;
#endif	/* MACH_LDEBUG */
	boolean_t	istate;

	istate = lck_interlock_lock(lck);

	lck->read_count--;	

	if (lck->want_upgrade) {
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_START,
			     (int)lck, lck->read_count, lck->want_upgrade, 0, 0);

		/*
		 *	Someone else has requested upgrade.
		 *	Since we've released a read lock, wake
		 *	him up.
		 */
		if (lck->waiting && (lck->read_count == 0)) {
			lck->waiting = FALSE;
			do_wakeup = TRUE;
		}

		lck_interlock_unlock(lck, istate);

		if (do_wakeup)
			thread_wakeup((event_t) lck);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_END,
			     (int)lck, lck->read_count, lck->want_upgrade, 0, 0);

		return (TRUE);
	}

	lck->want_upgrade = TRUE;

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */
	while (lck->read_count != 0) {
		i = lock_wait_time[lck->can_sleep ? 1 : 0];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX1_CODE) | DBG_FUNC_START,
			     (int)lck, lck->read_count, i, 0, 0);

		if (i != 0) {
			lck_interlock_unlock(lck, istate);
#if	MACH_LDEBUG
			if (!--decrementer)
				Debugger("timeout - read_count");
#endif	/* MACH_LDEBUG */
			while (--i != 0 && lck->read_count != 0)
				continue;
			istate = lck_interlock_lock(lck);
		}

		if (lck->can_sleep && lck->read_count != 0) {
			lck->waiting = TRUE;
			res = assert_wait((event_t) lck, THREAD_UNINT);
			if (res == THREAD_WAITING) {
				lck_interlock_unlock(lck, istate);
				res = thread_block(THREAD_CONTINUE_NULL);
				istate = lck_interlock_lock(lck);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX1_CODE) | DBG_FUNC_END,
			     (int)lck, lck->read_count, 0, 0, 0);
	}

	lck_interlock_unlock(lck, istate);

	return (FALSE);
}

/*
 *      Routine:        lck_rw_lock_exclusive_to_shared
 */
void
lck_rw_lock_exclusive_to_shared(
	lck_rw_t	*lck)
{
	boolean_t	do_wakeup = FALSE;
	boolean_t	istate;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_START,
			     (int)lck, lck->want_write, lck->want_upgrade, 0, 0);

	istate = lck_interlock_lock(lck);

	lck->read_count++;
	if (lck->want_upgrade)
		lck->want_upgrade = FALSE;
	else
	 	lck->want_write = FALSE;

	if (lck->waiting) {
		lck->waiting = FALSE;
		do_wakeup = TRUE;
	}

	lck_interlock_unlock(lck, istate);

	if (do_wakeup)
		thread_wakeup((event_t) lck);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_END,
			     (int)lck, lck->want_write, lck->want_upgrade, lck->read_count, 0);

}


/*
 *      Routine:        lck_rw_try_lock
 */
boolean_t
lck_rw_try_lock(
	lck_rw_t	*lck,
	lck_rw_type_t	lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED)
		return(lck_rw_try_lock_shared(lck));
	else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE)
		return(lck_rw_try_lock_exclusive(lck));
	else
		panic("lck_rw_try_lock(): Invalid rw lock type: %x\n", lck_rw_type);
	return(FALSE);
}

/*
 *	Routine:	lck_rw_try_lock_exclusive
 *	Function:
 *		Tries to get a write lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */

boolean_t
lck_rw_try_lock_exclusive(
	lck_rw_t	*lck)
{
	boolean_t	istate;

	istate = lck_interlock_lock(lck);

	if (lck->want_write || lck->want_upgrade || lck->read_count) {
		/*
		 *	Can't get lock.
		 */
		lck_interlock_unlock(lck, istate);
		return(FALSE);
	}

	/*
	 *	Have lock.
	 */

	lck->want_write = TRUE;

	lck_interlock_unlock(lck, istate);

	return(TRUE);
}

/*
 *	Routine:	lck_rw_try_lock_shared
 *	Function:
 *		Tries to get a read lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */

boolean_t
lck_rw_try_lock_shared(
	lck_rw_t	*lck)
{
	boolean_t	istate;

	istate = lck_interlock_lock(lck);

	if (lck->want_write || lck->want_upgrade) {
		lck_interlock_unlock(lck, istate);
		return(FALSE);
	}

	lck->read_count++;

	lck_interlock_unlock(lck, istate);

	return(TRUE);
}

/*
 *      Routine:        lck_mtx_alloc_init
 */
lck_mtx_t *
lck_mtx_alloc_init(
	lck_grp_t	*grp,
	lck_attr_t	*attr)
{
	lck_mtx_t	*lck;

	if ((lck = (lck_mtx_t *)kalloc(sizeof(lck_mtx_t))) != 0)
		lck_mtx_init(lck, grp, attr);
		
	return(lck);
}

/*
 *      Routine:        lck_mtx_free
 */
void
lck_mtx_free(
	lck_mtx_t	*lck,
	lck_grp_t	*grp)
{
	lck_mtx_destroy(lck, grp);
	kfree(lck, sizeof(lck_mtx_t));
}

/*
 *      Routine:        lck_mtx_ext_init
 */
static void
lck_mtx_ext_init(
	lck_mtx_ext_t	*lck,
	lck_grp_t	*grp,
	lck_attr_t	*attr)
{
	lck->lck_mtx.lck_mtx_ilk = 0;
	lck->lck_mtx.lck_mtx_locked = 0;
	lck->lck_mtx.lck_mtx_waiters = 0;
	lck->lck_mtx.lck_mtx_pri = 0;
	lck->lck_mtx_attr = 0;

	if ((attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck->lck_mtx_deb.pc = 0;
		lck->lck_mtx_deb.thread = 0;
		lck->lck_mtx_deb.type = MUTEX_TAG;
		lck->lck_mtx_attr |= LCK_MTX_ATTR_DEBUG;
	}

	lck->lck_mtx_grp = grp;
}

/*
 *      Routine:        lck_mtx_init
 */
void
lck_mtx_init(
	lck_mtx_t	*lck,
	lck_grp_t	*grp,
	lck_attr_t	*attr)
{
	lck_mtx_ext_t	*lck_ext;

	if ((attr != LCK_ATTR_NULL) && ((attr->lck_attr_val) & LCK_ATTR_DEBUG)) {
		if ((lck_ext = (lck_mtx_ext_t *)kalloc(sizeof(lck_mtx_ext_t))) != 0) {
			lck_mtx_ext_init(lck_ext, grp, attr);	
			lck->lck_mtx_tag = LCK_MTX_TAG_INDIRECT;
			lck->lck_mtx_ptr = lck_ext;
		}
	} else {
		lck->lck_mtx_ilk = 0;
		lck->lck_mtx_locked = 0;
		lck->lck_mtx_waiters = 0;
		lck->lck_mtx_pri = 0;
	}
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_MTX);
}

/*
 *      Routine:        lck_mtx_destroy
 */
void
lck_mtx_destroy(
	lck_mtx_t	*lck,
	lck_grp_t	*grp)
{
	boolean_t lck_is_indirect;
	
	if (lck->lck_mtx_tag == LCK_MTX_TAG_DESTROYED)
		return;
	lck_is_indirect = (lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT);
	lck->lck_mtx_tag = LCK_MTX_TAG_DESTROYED;
	if (lck_is_indirect)
		kfree(lck->lck_mtx_ptr, sizeof(lck_mtx_ext_t));
	lck_grp_lckcnt_decr(grp, LCK_TYPE_MTX);
	lck_grp_deallocate(grp);
	return;
}

/*
 *      Routine:        lck_mtx_assert
 */
void
lck_mtx_assert(
	__unused lck_mtx_t	*lck,
	__unused unsigned int	type)
{
}

#if	MACH_KDB

void	db_show_one_lock(lock_t  *);

void
db_show_one_lock(
	lock_t  *lock)
{
	db_printf("Read_count = 0x%x, %swant_upgrade, %swant_write, ",
		  lock->read_count,
		  lock->want_upgrade ? "" : "!",
		  lock->want_write ? "" : "!");
	db_printf("%swaiting, %scan_sleep\n", 
		  lock->waiting ? "" : "!", lock->can_sleep ? "" : "!");
	db_printf("Interlock:\n");
	db_show_one_simple_lock((db_expr_t)simple_lock_addr(lock->interlock),
			TRUE, (db_expr_t)0, (char *)0);
}

#endif	/* MACH_KDB */

/*
 * The C portion of the mutex package.  These routines are only invoked
 * if the optimized assembler routines can't do the work.
 */

/*
 *	Routine:	lock_alloc
 *	Function:
 *		Allocate a mutex for external users who cannot
 *		hard-code the structure definition into their
 *		objects.
 *		For now just use kalloc, but a zone is probably
 *		warranted.
 */
mutex_t *
mutex_alloc(
	unsigned short	tag)
{
	mutex_t		*m;

	if ((m = (mutex_t *)kalloc(sizeof(mutex_t))) != 0)
	  mutex_init(m, tag);
	return(m);
}

/*
 *	Routine:	mutex_free
 *	Function:
 *		Free a mutex allocated for external users.
 *		For now just use kfree, but a zone is probably
 *		warranted.
 */
void
mutex_free(
	mutex_t		*m)
{
	kfree(m, sizeof(mutex_t));
}

/*
 *	Routine:	_mutex_assert
 */
void
_mutex_assert (
	mutex_t		*mutex,
	unsigned int	what)
{

	thread_t	thread = current_thread();
	thread_t	holder;

        if (panicstr != NULL)
	        return;

	holder = (thread_t) mutex->lck_mtx.lck_mtx_locked;

	switch (what) {
	case MA_OWNED:
	        if (thread != holder)
		        panic("mutex %x not owned\n", mutex);
		break;

        case MA_NOTOWNED:
	        if (thread == holder)
		        panic("mutex %x owned\n", mutex);
	        break;
	}

}

#if	MACH_KDB
/*
 * Routines to print out simple_locks and mutexes in a nicely-formatted
 * fashion.
 */

char *simple_lock_labels =	"ENTRY    ILK THREAD   DURATION CALLER";
char *mutex_labels =		"ENTRY    LOCKED WAITERS   THREAD CALLER";

void
db_show_one_simple_lock (
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		* modif)
{
	simple_lock_t	saddr = (simple_lock_t)addr;

	if (saddr == (simple_lock_t)0 || !have_addr) {
		db_error ("No simple_lock\n");
	}
#if	USLOCK_DEBUG
	else if (saddr->lock_type != USLOCK_TAG)
		db_error ("Not a simple_lock\n");
#endif	/* USLOCK_DEBUG */

	db_printf ("%s\n", simple_lock_labels);
	db_print_simple_lock (saddr);
}

void
db_print_simple_lock (
	simple_lock_t	addr)
{

	db_printf ("%08x %3d", addr, *hw_lock_addr(addr->interlock));
#if	USLOCK_DEBUG
	db_printf (" %08x", addr->debug.lock_thread);
	db_printf (" %08x ", addr->debug.duration[1]);
	db_printsym ((int)addr->debug.lock_pc, DB_STGY_ANY);
#endif	/* USLOCK_DEBUG */
	db_printf ("\n");
}

void
db_show_one_mutex (
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		* modif)
{
	mutex_t		* maddr = (mutex_t *)addr;

	if (maddr == (mutex_t *)0 || !have_addr)
		db_error ("No mutex\n");
#if	MACH_LDEBUG
	else if (maddr->type != MUTEX_TAG)
		db_error ("Not a mutex\n");
#endif	/* MACH_LDEBUG */

	db_printf ("%s\n", mutex_labels);
	db_print_mutex (maddr);
}

void
db_print_mutex (
	mutex_t		* addr)
{
	db_printf ("%08x %6d %7d",
		   addr, *addr, addr->lck_mtx.lck_mtx_waiters);
#if	MACH_LDEBUG
	db_printf (" %08x ", addr->thread);
	db_printsym (addr->pc, DB_STGY_ANY);
#endif	/* MACH_LDEBUG */
	db_printf ("\n");
}

#endif	/* MACH_KDB */
