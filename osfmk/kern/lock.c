/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <cpus.h>
#include <mach_kdb.h>
#include <mach_ldebug.h>

#include <kern/lock.h>
#include <kern/etap_macros.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
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
#include <ppc/POWERMAC/mp/MPPlugIn.h>
#endif

#include <sys/kdebug.h>

#define	ANY_LOCK_DEBUG	(USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

/*
 *	Some portions of the lock debugging code must run with
 *	interrupts disabled.  This can be machine-dependent,
 *	but we don't have any good hooks for that at the moment.
 *	If your architecture is different, add a machine-dependent
 *	ifdef here for these macros.		XXX
 */

#define	DISABLE_INTERRUPTS(s)	s = ml_set_interrupts_enabled(FALSE)
#define	ENABLE_INTERRUPTS(s)	(void)ml_set_interrupts_enabled(s)

#if	NCPUS > 1
/* Time we loop without holding the interlock. 
 * The former is for when we cannot sleep, the latter
 * for when our thread can go to sleep (loop less)
 * we shouldn't retake the interlock at all frequently
 * if we cannot go to sleep, since it interferes with
 * any other processors. In particular, 100 is too small
 * a number for powerpc MP systems because of cache
 * coherency issues and differing lock fetch times between
 * the processors
 */
unsigned int lock_wait_time[2] = { (unsigned int)-1, 100 } ;
#else	/* NCPUS > 1 */

	/*
	 *	It is silly to spin on a uni-processor as if we
	 *	thought something magical would happen to the
	 *	want_write bit while we are executing.
	 */

unsigned int lock_wait_time[2] = { 0, 0 };
#endif	/* NCPUS > 1 */

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
#if	MACH_KDB && NCPUS > 1
decl_simple_lock_data(extern , kdb_lock)
#endif	/* MACH_KDB && NCPUS >1 */
#endif	/* USLOCK_DEBUG */


/*
 *	We often want to know the addresses of the callers
 *	of the various lock routines.  However, this information
 *	is only used for debugging and statistics.
 */
typedef void	*pc_t;
#define	INVALID_PC	((void *) VM_MAX_KERNEL_ADDRESS)
#define	INVALID_THREAD	((void *) VM_MAX_KERNEL_ADDRESS)
#if	ANY_LOCK_DEBUG || ETAP_LOCK_TRACE
#define	OBTAIN_PC(pc,l)	((pc) = (void *) GET_RETURN_PC(&(l)))
#else	/* ANY_LOCK_DEBUG || ETAP_LOCK_TRACE */
#ifdef	lint
/*
 *	Eliminate lint complaints about unused local pc variables.
 */
#define	OBTAIN_PC(pc,l)	++pc
#else	/* lint */
#define	OBTAIN_PC(pc,l)
#endif	/* lint */
#endif	/* USLOCK_DEBUG || ETAP_LOCK_TRACE */


/* #ifndef	USIMPLE_LOCK_CALLS
 * The i386 production version of usimple_locks isn't ready yet.
 */
/*
 *	Portable lock package implementation of usimple_locks.
 */

#if     ETAP_LOCK_TRACE
#define	ETAPCALL(stmt)	stmt
void		etap_simplelock_init(simple_lock_t, etap_event_t);
void		etap_simplelock_unlock(simple_lock_t);
void		etap_simplelock_hold(simple_lock_t, pc_t, etap_time_t);
etap_time_t	etap_simplelock_miss(simple_lock_t);

void		etap_mutex_init(mutex_t*, etap_event_t);
void		etap_mutex_unlock(mutex_t*);
void		etap_mutex_hold(mutex_t*, pc_t, etap_time_t);
etap_time_t	etap_mutex_miss(mutex_t*);
#else   /* ETAP_LOCK_TRACE */
#define	ETAPCALL(stmt)
#endif  /* ETAP_LOCK_TRACE */

#if	USLOCK_DEBUG
#define	USLDBG(stmt)	stmt
void		usld_lock_init(usimple_lock_t, etap_event_t);
void		usld_lock_pre(usimple_lock_t, pc_t);
void		usld_lock_post(usimple_lock_t, pc_t);
void		usld_unlock(usimple_lock_t, pc_t);
void		usld_lock_try_pre(usimple_lock_t, pc_t);
void		usld_lock_try_post(usimple_lock_t, pc_t);
void		usld_lock_held(usimple_lock_t);
void		usld_lock_none_held(void);
int		usld_lock_common_checks(usimple_lock_t, char *);
#else	/* USLOCK_DEBUG */
#define	USLDBG(stmt)
#endif	/* USLOCK_DEBUG */

/*
 *	Initialize a usimple_lock.
 *
 *	No change in preemption state.
 */
void
usimple_lock_init(
	usimple_lock_t	l,
	etap_event_t	event)
{
	USLDBG(usld_lock_init(l, event));
	ETAPCALL(etap_simplelock_init((l),(event)));
	hw_lock_init(&l->interlock);
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
	int i;
	pc_t		pc;
#if	ETAP_LOCK_TRACE
	etap_time_t	start_wait_time;
	int		no_miss_info = 0;
#endif	/* ETAP_LOCK_TRACE */
#if	USLOCK_DEBUG
	int		count = 0;
#endif 	/* USLOCK_DEBUG */

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_pre(l, pc));
#if	ETAP_LOCK_TRACE
	ETAP_TIME_CLEAR(start_wait_time);
#endif	/* ETAP_LOCK_TRACE */

	if(!hw_lock_to(&l->interlock, LockTimeOut))	/* Try to get the lock with a timeout */ 
		panic("simple lock deadlock detection - l=%08X, cpu=%d, ret=%08X", l, cpu_number(), pc);

	ETAPCALL(etap_simplelock_hold(l, pc, start_wait_time));
	USLDBG(usld_lock_post(l, pc));
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
	pc_t	pc;

//	checkNMI();										/* (TEST/DEBUG) */
		
	OBTAIN_PC(pc, l);
	USLDBG(usld_unlock(l, pc));
	ETAPCALL(etap_simplelock_unlock(l));
	hw_lock_unlock(&l->interlock);
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
	pc_t		pc;
	unsigned int	success;
	etap_time_t	zero_time;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_try_pre(l, pc));
	if (success = hw_lock_try(&l->interlock)) {
		USLDBG(usld_lock_try_post(l, pc));
		ETAP_TIME_CLEAR(zero_time);
		ETAPCALL(etap_simplelock_hold(l, pc, zero_time));
	}
	return success;
}

#if ETAP_LOCK_TRACE
void
simple_lock_no_trace(
	simple_lock_t	l)
{
	pc_t		pc;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_pre(l, pc));
	while (!hw_lock_try(&l->interlock)) {
		while (hw_lock_held(&l->interlock)) {
			/*
			 *	Spin watching the lock value in cache,
			 *	without consuming external bus cycles.
			 *	On most SMP architectures, the atomic
			 *	instruction(s) used by hw_lock_try
			 *	cost much, much more than an ordinary
			 *	memory read.
			 */
		}
	}
	USLDBG(usld_lock_post(l, pc));
}

void
simple_unlock_no_trace(
	simple_lock_t	l)
{
	pc_t	pc;

	OBTAIN_PC(pc, l);
	USLDBG(usld_unlock(l, pc));
	hw_lock_unlock(&l->interlock);
}

int
simple_lock_try_no_trace(
	simple_lock_t	l)
{
	pc_t		pc;
	unsigned int	success;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_try_pre(l, pc));
	if (success = hw_lock_try(&l->interlock)) {
		USLDBG(usld_lock_try_post(l, pc));
	}
	return success;
}
#endif	/* ETAP_LOCK_TRACE */


#if	USLOCK_DEBUG
/*
 *	Verify that the lock is locked and owned by
 *	the current thread.
 */
void
usimple_lock_held(
	usimple_lock_t	l)
{
	usld_lock_held(l);
}


/*
 *	Verify that no usimple_locks are held by
 *	this processor.  Typically used in a
 *	trap handler when returning to user mode
 *	or in a path known to relinquish the processor.
 */
void
usimple_lock_none_held(void)
{
	usld_lock_none_held();
}
#endif	/* USLOCK_DEBUG */


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
 *	Maintain a per-cpu stack of acquired usimple_locks.
 */
void	usl_stack_push(usimple_lock_t, int);
void	usl_stack_pop(usimple_lock_t, int);

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
	etap_event_t	type)
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
	char		*caller = "usimple_lock";


#if 0
	printf("*** %08X %08X %04X %02X %08X %02X %08X - %s\n", /* (TEST/DEBUG) */
		l->debug.lock_pc,
		l->debug.lock_thread,
		l->debug.state,
		l->debug.lock_cpu,
		l->debug.unlock_thread,
		l->debug.unlock_cpu,
		l->debug.unlock_pc,
		caller);
#endif

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
	char		*caller = "successful usimple_lock";


#if 0
	printf("*** %08X %08X %04X %02X %08X %02X %08X - %s\n", /* (TEST/DEBUG) */
		l->debug.lock_pc,
		l->debug.lock_thread,
		l->debug.state,
		l->debug.lock_cpu,
		l->debug.unlock_thread,
		l->debug.unlock_cpu,
		l->debug.unlock_pc,
		caller);
#endif

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

	usl_stack_push(l, mycpu);
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
	char		*caller = "usimple_unlock";


#if 0
	printf("*** %08X %08X %04X %02X %08X %02X %08X - %s\n", /* (TEST/DEBUG) */
		l->debug.lock_pc,
		l->debug.lock_thread,
		l->debug.state,
		l->debug.lock_cpu,
		l->debug.unlock_thread,
		l->debug.unlock_cpu,
		l->debug.unlock_pc,
		caller);
#endif

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
	usl_stack_pop(l, mycpu);

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
	char		*caller = "usimple_lock_try";

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
	char		*caller = "successful usimple_lock_try";

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

#if 0
	printf("*** %08X %08X %04X %02X %08X %02X %08X - %s\n", /* (TEST/DEBUG) */
		l->debug.lock_pc,
		l->debug.lock_thread,
		l->debug.state,
		l->debug.lock_cpu,
		l->debug.unlock_thread,
		l->debug.unlock_cpu,
		l->debug.unlock_pc,
		caller);
#endif

	usl_stack_push(l, mycpu);
	usl_trace(l, mycpu, pc, caller);
}


/*
 *	Determine whether the lock in question is owned
 *	by the current thread.
 */
void
usld_lock_held(
	usimple_lock_t	l)
{
	char		*caller = "usimple_lock_held";


#if 0
	printf("*** %08X %08X %04X %02X %08X %02X %08X - %s\n", /* (TEST/DEBUG) */
		l->debug.lock_pc,
		l->debug.lock_thread,
		l->debug.state,
		l->debug.lock_cpu,
		l->debug.unlock_thread,
		l->debug.unlock_cpu,
		l->debug.unlock_pc,
		caller);
#endif

	if (!usld_lock_common_checks(l, caller))
		return;

	if (!(l->debug.state & USLOCK_TAKEN))
		panic("%s:  lock 0x%x hasn't been taken",
		      caller, (integer_t) l);
	if (l->debug.lock_thread != (void *) current_thread())
		panic("%s:  lock 0x%x is owned by thread 0x%x", caller,
		      (integer_t) l, (integer_t) l->debug.lock_thread);

	/*
	 *	The usimple_lock is active, so preemption
	 *	is disabled and the current cpu should
	 *	match the one recorded at lock acquisition time.
	 */
	if (l->debug.lock_cpu != cpu_number())
		panic("%s:  current cpu 0x%x isn't acquiring cpu 0x%x",
		      caller, cpu_number(), (integer_t) l->debug.lock_cpu);
}


/*
 *	Per-cpu stack of currently active usimple_locks.
 *	Requires spl protection so that interrupt-level
 *	locks plug-n-play with their thread-context friends.
 */
#define	USLOCK_STACK_DEPTH	20
usimple_lock_t	uslock_stack[NCPUS][USLOCK_STACK_DEPTH];
unsigned int	uslock_stack_index[NCPUS];
boolean_t	uslock_stack_enabled = FALSE;


/*
 *	Record a usimple_lock just acquired on
 *	the current processor.
 *
 *	Preemption has been disabled by lock
 *	acquisition, so it's safe to use the cpu number
 *	specified by the caller.
 */
void
usl_stack_push(
	usimple_lock_t	l,
	int		mycpu)
{
	boolean_t	s;

	if (uslock_stack_enabled == FALSE)
		return;

	DISABLE_INTERRUPTS(s);
	assert(uslock_stack_index[mycpu] >= 0);
	assert(uslock_stack_index[mycpu] < USLOCK_STACK_DEPTH);
	if (uslock_stack_index[mycpu] >= USLOCK_STACK_DEPTH) {
		printf("usl_stack_push (cpu 0x%x):  too many locks (%d)",
		       mycpu, uslock_stack_index[mycpu]);
		printf(" disabling stacks\n");
		uslock_stack_enabled = FALSE;
		ENABLE_INTERRUPTS(s);
		return;
	}
	uslock_stack[mycpu][uslock_stack_index[mycpu]] = l;
	uslock_stack_index[mycpu]++;
	ENABLE_INTERRUPTS(s);
}


/*
 *	Eliminate the entry for a usimple_lock
 *	that had been active on the current processor.
 *
 *	Preemption has been disabled by lock
 *	acquisition, and we haven't yet actually
 *	released the hardware lock associated with
 *	this usimple_lock, so it's safe to use the
 *	cpu number supplied by the caller.
 */
void
usl_stack_pop(
	usimple_lock_t	l,
	int		mycpu)
{
	unsigned int	i, index;
	boolean_t	s;

	if (uslock_stack_enabled == FALSE)
		return;

	DISABLE_INTERRUPTS(s);
	assert(uslock_stack_index[mycpu] > 0);
	assert(uslock_stack_index[mycpu] <= USLOCK_STACK_DEPTH);
	if (uslock_stack_index[mycpu] == 0) {
		printf("usl_stack_pop (cpu 0x%x):  not enough locks (%d)",
		       mycpu, uslock_stack_index[mycpu]);
		printf(" disabling stacks\n");
		uslock_stack_enabled = FALSE;
		ENABLE_INTERRUPTS(s);
		return;
	}
	index = --uslock_stack_index[mycpu];
	for (i = 0; i <= index; ++i) {
		if (uslock_stack[mycpu][i] == l) {
			if (i != index)
				uslock_stack[mycpu][i] =
					uslock_stack[mycpu][index];
			ENABLE_INTERRUPTS(s);
			return;
		}
	}
	ENABLE_INTERRUPTS(s);
	panic("usl_stack_pop:  can't find usimple_lock 0x%x", l);
}


/*
 *	Determine whether any usimple_locks are currently held.
 *
 *	Caller's preemption state is uncertain.  If
 *	preemption has been disabled, this check is accurate.
 *	Otherwise, this check is just a guess.  We do the best
 *	we can by disabling scheduler interrupts, so at least
 *	the check is accurate w.r.t. whatever cpu we're running
 *	on while in this routine.
 */
void
usld_lock_none_held()
{
	register int	mycpu;
	boolean_t	s;
	unsigned int	locks_held;
	char		*caller = "usimple_lock_none_held";

	DISABLE_INTERRUPTS(s);
	mp_disable_preemption();
	mycpu = cpu_number();
	locks_held = uslock_stack_index[mycpu];
	mp_enable_preemption();
	ENABLE_INTERRUPTS(s);
	if (locks_held > 0)
		panic("%s:  no locks should be held (0x%x locks held)",
		      caller, (integer_t) locks_held);
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



#if	MACH_KDB
#define	printf	kdbprintf
void	db_show_all_slocks(void);
void
db_show_all_slocks(void)
{
	unsigned int	i, index;
	int		mycpu = cpu_number();
	usimple_lock_t	l;

	if (uslock_stack_enabled == FALSE) {
		printf("Lock stack not enabled\n");
		return;
	}

#if	0
	if (!mach_slocks_init)
		iprintf("WARNING: simple locks stack may not be accurate\n");
#endif
	assert(uslock_stack_index[mycpu] >= 0);
	assert(uslock_stack_index[mycpu] <= USLOCK_STACK_DEPTH);
	index = uslock_stack_index[mycpu];
	for (i = 0; i < index; ++i) {
		l = uslock_stack[mycpu][i];
		iprintf("%d: ", i);
		db_printsym((vm_offset_t)l, DB_STGY_ANY);
		if (l->debug.lock_pc != INVALID_PC) {
			printf(" locked by ");
			db_printsym((int)l->debug.lock_pc, DB_STGY_PROC);
		}
		printf("\n");
	}
}
#endif	/* MACH_KDB */

#endif	/* USLOCK_DEBUG */

/* #endif	USIMPLE_LOCK_CALLS */

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
	etap_event_t	event,
	etap_event_t	i_event)
{
	lock_t		*l;

	if ((l = (lock_t *)kalloc(sizeof(lock_t))) != 0)
	  lock_init(l, can_sleep, event, i_event);
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
	kfree((vm_offset_t)l, sizeof(lock_t));
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
	etap_event_t	event,
	etap_event_t	i_event)
{
	(void) memset((void *) l, 0, sizeof(lock_t));

#if     ETAP_LOCK_TRACE
	etap_event_table_assign(&l->u.event_table_chain, event);
	l->u.s.start_list = SD_ENTRY_NULL;
#endif  /* ETAP_LOCK_TRACE */

	simple_lock_init(&l->interlock, i_event);
	l->want_write = FALSE;
	l->want_upgrade = FALSE;
	l->read_count = 0;
	l->can_sleep = can_sleep;

#if     ETAP_LOCK_ACCUMULATE
	l->cbuff_write = etap_cbuff_reserve(lock_event_table(l));
	if (l->cbuff_write != CBUFF_ENTRY_NULL) {
		l->cbuff_write->event    = event;
		l->cbuff_write->instance = (unsigned long) l;
		l->cbuff_write->kind     = WRITE_LOCK;
	}
	l->cbuff_read = CBUFF_ENTRY_NULL;
#endif  /* ETAP_LOCK_ACCUMULATE */
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
	start_data_node_t  entry     = {0};
	boolean_t          lock_miss = FALSE;
	unsigned short	   dynamic   = 0;
	unsigned short     trace     = 0;
	etap_time_t	   total_time;
	etap_time_t	   stop_wait_time;
	pc_t		   pc;
#if	MACH_LDEBUG
	int		   decrementer;
#endif	/* MACH_LDEBUG */


	ETAP_STAMP(lock_event_table(l), trace, dynamic);
	ETAP_CREATE_ENTRY(entry, trace);
	MON_ASSIGN_PC(entry->start_pc, pc, trace);

	simple_lock(&l->interlock);

	/*
         *  Link the new start_list entry
         */
	ETAP_LINK_ENTRY(l, entry, trace);

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */

	/*
	 *	Try to acquire the want_write bit.
	 */
	while (l->want_write) {
		if (!lock_miss) {
			ETAP_CONTENTION_TIMESTAMP(entry, trace);
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
			ETAP_SET_REASON(current_thread(),
					BLOCKED_ON_COMPLEX_LOCK);
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
			ETAP_CONTENTION_TIMESTAMP(entry,trace);
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
                        ETAP_SET_REASON(current_thread(),
                                        BLOCKED_ON_COMPLEX_LOCK);
			thread_sleep_simple_lock((event_t) l,
				simple_lock_addr(l->interlock),
				THREAD_UNINT);
			/* interlock relocked */
		}
	}

	/*
	 *  do not collect wait data if either the lock
	 *  was free or no wait traces are enabled.
	 */

	if (lock_miss && ETAP_CONTENTION_ENABLED(trace)) {
		ETAP_TIMESTAMP(stop_wait_time);
		ETAP_TOTAL_TIME(total_time,
				stop_wait_time,
				entry->start_wait_time);
		CUM_WAIT_ACCUMULATE(l->cbuff_write, total_time, dynamic, trace);
		MON_DATA_COLLECT(l,
				 entry,
				 total_time,
				 WRITE_LOCK,
				 MON_CONTENTION,
				 trace);
	}

	simple_unlock(&l->interlock);

	/*
	 *  Set start hold time if some type of hold tracing is enabled.
	 *
	 *  Note: if the stop_wait_time was already stamped, use
	 *      it as the start_hold_time instead of doing an
	 *      expensive bus access.
	 *
	 */

	if (lock_miss && ETAP_CONTENTION_ENABLED(trace))
		ETAP_COPY_START_HOLD_TIME(entry, stop_wait_time, trace);
	else
		ETAP_DURATION_TIMESTAMP(entry, trace);

}

void
lock_done(
	register lock_t	* l)
{
	boolean_t	  do_wakeup = FALSE;
	start_data_node_t entry;
	unsigned short    dynamic   = 0;
	unsigned short    trace     = 0;
	etap_time_t	  stop_hold_time;
	etap_time_t	  total_time;
	unsigned long     lock_kind;
	pc_t		  pc;


	ETAP_STAMP(lock_event_table(l), trace, dynamic);

	simple_lock(&l->interlock);

	if (l->read_count != 0) {
		l->read_count--;
		lock_kind = READ_LOCK;
	}
	else	
		if (l->want_upgrade) {
			l->want_upgrade = FALSE;
			lock_kind = WRITE_LOCK;
		}
	else {
		l->want_write = FALSE;
		lock_kind = WRITE_LOCK;
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
        /*
         *  Collect hold data if hold tracing is
         *  enabled.
         */

        /*
         *  NOTE: All complex locks whose tracing was on when the
         *  lock was acquired will have an entry in the start_data
         *  list.
         */

	ETAP_UNLINK_ENTRY(l,entry);
	if (ETAP_DURATION_ENABLED(trace) && entry != SD_ENTRY_NULL) {
		ETAP_TIMESTAMP (stop_hold_time);
		ETAP_TOTAL_TIME (total_time,
				 stop_hold_time,
				 entry->start_hold_time);

		if (lock_kind & WRITE_LOCK)
			CUM_HOLD_ACCUMULATE (l->cbuff_write,
					     total_time,
					     dynamic,
					     trace);
		else {
			CUM_READ_ENTRY_RESERVE(l,l->cbuff_read,trace);
			CUM_HOLD_ACCUMULATE (l->cbuff_read,
					     total_time,
					     dynamic,
					     trace);
		}
		MON_ASSIGN_PC(entry->end_pc,pc,trace);
		MON_DATA_COLLECT(l,entry,
			         total_time,
				 lock_kind,
				 MON_DURATION,
				 trace);
	}

	simple_unlock(&l->interlock);

	ETAP_DESTROY_ENTRY(entry);

	if (do_wakeup)
		thread_wakeup((event_t) l);
}

void
lock_read(
	register lock_t	* l)
{
	register int	    i;
	start_data_node_t   entry     = {0};
	boolean_t           lock_miss = FALSE;
	unsigned short      dynamic   = 0;
	unsigned short      trace     = 0;
	etap_time_t	    total_time;
	etap_time_t	    stop_wait_time;
        pc_t		    pc;
#if	MACH_LDEBUG
	int		   decrementer;
#endif	/* MACH_LDEBUG */

	ETAP_STAMP(lock_event_table(l), trace, dynamic);
	ETAP_CREATE_ENTRY(entry, trace);
	MON_ASSIGN_PC(entry->start_pc, pc, trace);

	simple_lock(&l->interlock);

	/*
	 *  Link the new start_list entry
	 */
	ETAP_LINK_ENTRY(l,entry,trace);

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */
	while (l->want_write || l->want_upgrade) {
		if (!lock_miss) {
			ETAP_CONTENTION_TIMESTAMP(entry, trace);
			lock_miss = TRUE;
		}

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

	/*
	 *  Do not collect wait data if the lock was free
	 *  or if no wait traces are enabled.
	 */

	if (lock_miss && ETAP_CONTENTION_ENABLED(trace)) {
		ETAP_TIMESTAMP(stop_wait_time);
		ETAP_TOTAL_TIME(total_time,
				stop_wait_time,
				entry->start_wait_time);
		CUM_READ_ENTRY_RESERVE(l, l->cbuff_read, trace);
		CUM_WAIT_ACCUMULATE(l->cbuff_read, total_time, dynamic, trace);
		MON_DATA_COLLECT(l,
				 entry,
				 total_time,
				 READ_LOCK,
				 MON_CONTENTION,
				 trace);
	}
	simple_unlock(&l->interlock);

	/*
	 *  Set start hold time if some type of hold tracing is enabled.
	 *
	 *  Note: if the stop_wait_time was already stamped, use
	 *        it instead of doing an expensive bus access.
	 *
	 */

	if (lock_miss && ETAP_CONTENTION_ENABLED(trace))
		ETAP_COPY_START_HOLD_TIME(entry, stop_wait_time, trace);
	else
		ETAP_DURATION_TIMESTAMP(entry,trace);
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
	start_data_node_t   entry     = {0};
	boolean_t           lock_miss = FALSE;
	unsigned short      dynamic   = 0;
	unsigned short      trace     = 0;
	etap_time_t	    total_time;
	etap_time_t	    stop_time;
	pc_t		    pc;
#if	MACH_LDEBUG
	int		   decrementer;
#endif	/* MACH_LDEBUG */


	ETAP_STAMP(lock_event_table(l), trace, dynamic);

	simple_lock(&l->interlock);

	l->read_count--;	

	/*
	 *  Since the read lock is lost whether the write lock
	 *  is acquired or not, read hold data is collected here.
	 *  This, of course, is assuming some type of hold
	 *  tracing is enabled.
	 *
	 *  Note: trace is set to zero if the entry does not exist.
	 */

	ETAP_FIND_ENTRY(l, entry, trace);

	if (ETAP_DURATION_ENABLED(trace)) {
		ETAP_TIMESTAMP(stop_time);
		ETAP_TOTAL_TIME(total_time, stop_time, entry->start_hold_time);
		CUM_HOLD_ACCUMULATE(l->cbuff_read, total_time, dynamic, trace);
		MON_ASSIGN_PC(entry->end_pc, pc, trace);
		MON_DATA_COLLECT(l,
				 entry,
				 total_time,
				 READ_LOCK,
				 MON_DURATION,
				 trace);
	}

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

		ETAP_UNLINK_ENTRY(l, entry);
		simple_unlock(&l->interlock);
		ETAP_DESTROY_ENTRY(entry);

		if (do_wakeup)
			thread_wakeup((event_t) l);
		return (TRUE);
	}

	l->want_upgrade = TRUE;

	MON_ASSIGN_PC(entry->start_pc, pc, trace);

#if	MACH_LDEBUG
	decrementer = DECREMENTER_TIMEOUT;
#endif	/* MACH_LDEBUG */
	while (l->read_count != 0) {
	        if (!lock_miss) {
			ETAP_CONTENTION_TIMESTAMP(entry, trace);
			lock_miss = TRUE;
		}

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

	/*
	 *  do not collect wait data if the lock was free
	 *  or if no wait traces are enabled.
	 */

	if (lock_miss && ETAP_CONTENTION_ENABLED(trace)) {
		ETAP_TIMESTAMP (stop_time);
		ETAP_TOTAL_TIME(total_time, stop_time, entry->start_wait_time);
		CUM_WAIT_ACCUMULATE(l->cbuff_write, total_time, dynamic, trace);
		MON_DATA_COLLECT(l,
				 entry,
				 total_time,
				 WRITE_LOCK,
				 MON_CONTENTION,
				 trace);
	}

	simple_unlock(&l->interlock);

	/*
	 *  Set start hold time if some type of hold tracing is enabled
	 *
	 *  Note: if the stop_time was already stamped, use
	 *        it as the new start_hold_time instead of doing
	 *        an expensive VME access.
	 *
	 */

	if (lock_miss && ETAP_CONTENTION_ENABLED(trace))
		ETAP_COPY_START_HOLD_TIME(entry, stop_time, trace);
	else
		ETAP_DURATION_TIMESTAMP(entry, trace);

	return (FALSE);
}

void
lock_write_to_read(
	register lock_t	* l)
{
	boolean_t	   do_wakeup = FALSE;
	start_data_node_t  entry   = {0};
	unsigned short	   dynamic = 0;
	unsigned short     trace   = 0;
	etap_time_t        stop_hold_time;
	etap_time_t	   total_time;
	pc_t		   pc;

        ETAP_STAMP(lock_event_table(l), trace,dynamic);

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

        /*
         *  Since we are switching from a write lock to a read lock,
         *  the write lock data is stored and the read lock data
         *  collection begins.
         *
         *  Note: trace is set to zero if the entry does not exist.
         */

        ETAP_FIND_ENTRY(l, entry, trace);

        if (ETAP_DURATION_ENABLED(trace)) {
            ETAP_TIMESTAMP (stop_hold_time);
            ETAP_TOTAL_TIME(total_time, stop_hold_time, entry->start_hold_time);
            CUM_HOLD_ACCUMULATE(l->cbuff_write, total_time, dynamic, trace);
            MON_ASSIGN_PC(entry->end_pc, pc, trace);
            MON_DATA_COLLECT(l,
			     entry,
			     total_time,
			     WRITE_LOCK,
			     MON_DURATION,
			     trace);
        }

	simple_unlock(&l->interlock);

        /*
         *  Set start hold time if some type of hold tracing is enabled
         *
         *  Note: if the stop_hold_time was already stamped, use
         *        it as the new start_hold_time instead of doing
         *        an expensive bus access.
         *
         */

        if (ETAP_DURATION_ENABLED(trace))
		ETAP_COPY_START_HOLD_TIME(entry, stop_hold_time, trace);
        else
		ETAP_DURATION_TIMESTAMP(entry, trace);

        MON_ASSIGN_PC(entry->start_pc, pc, trace);

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
	start_data_node_t  entry = {0};
	unsigned short     trace = 0;
	pc_t		   pc;

        ETAP_STAMP(lock_event_table(l), trace, trace);
        ETAP_CREATE_ENTRY(entry, trace);

	simple_lock(&l->interlock);

	if (l->want_write || l->want_upgrade || l->read_count) {
		/*
		 *	Can't get lock.
		 */
		simple_unlock(&l->interlock);
		ETAP_DESTROY_ENTRY(entry);
		return(FALSE);
	}

	/*
	 *	Have lock.
	 */

	l->want_write = TRUE;

        ETAP_LINK_ENTRY(l, entry, trace);

	simple_unlock(&l->interlock);

        MON_ASSIGN_PC(entry->start_pc, pc, trace);
        ETAP_DURATION_TIMESTAMP(entry, trace);

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
	start_data_node_t  entry = {0};
	unsigned short     trace = 0;
	pc_t		   pc;

        ETAP_STAMP(lock_event_table(l), trace, trace);
        ETAP_CREATE_ENTRY(entry, trace);

	simple_lock(&l->interlock);

	if (l->want_write || l->want_upgrade) {
		simple_unlock(&l->interlock);
                ETAP_DESTROY_ENTRY(entry);
		return(FALSE);
	}

	l->read_count++;

        ETAP_LINK_ENTRY(l, entry, trace);

	simple_unlock(&l->interlock);

        MON_ASSIGN_PC(entry->start_pc, pc, trace);
        ETAP_DURATION_TIMESTAMP(entry, trace);

	return(TRUE);
}
#endif		/* Unused */

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
	etap_event_t	event)
{
	mutex_t		*m;

	if ((m = (mutex_t *)kalloc(sizeof(mutex_t))) != 0)
	  mutex_init(m, event);
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
	kfree((vm_offset_t)m, sizeof(mutex_t));
}

/*
 * mutex_lock_wait
 *
 * Invoked in order to wait on contention.
 *
 * Called with the interlock locked and
 * returns it unlocked.
 */
void
mutex_lock_wait (
	mutex_t			*mutex,
	thread_act_t	holder)
{
	thread_t		thread, self = current_thread();
#if		!defined(i386)
	integer_t		priority;
	spl_t			s = splsched();

	priority = self->last_processor->current_pri;
	if (priority < self->priority)
		priority = self->priority;
	if (priority > MINPRI_KERNEL)
		priority = MINPRI_KERNEL;
	else
	if (priority < BASEPRI_DEFAULT)
		priority = BASEPRI_DEFAULT;

	thread = holder->thread;
	assert(thread->top_act == holder);	/* XXX */
	thread_lock(thread);
	if (mutex->promoted_pri == 0)
		thread->promotions++;
	if (thread->priority < MINPRI_KERNEL) {
		thread->sched_mode |= TH_MODE_PROMOTED;
		if (	mutex->promoted_pri < priority	&&
				thread->sched_pri < priority		) {
			KERNEL_DEBUG_CONSTANT(
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_PROMOTE) | DBG_FUNC_NONE,
					thread->sched_pri, priority, (int)thread, (int)mutex, 0);

			set_sched_pri(thread, priority);
		}
	}
	thread_unlock(thread);
	splx(s);

	if (mutex->promoted_pri < priority)
		mutex->promoted_pri = priority;
#endif

	if (self->pending_promoter[self->pending_promoter_index] == NULL) {
		self->pending_promoter[self->pending_promoter_index] = mutex;
		mutex->waiters++;
	}
	else
	if (self->pending_promoter[self->pending_promoter_index] != mutex) {
		self->pending_promoter[++self->pending_promoter_index] = mutex;
		mutex->waiters++;
	}

	assert_wait(mutex, THREAD_UNINT);
	interlock_unlock(&mutex->interlock);

	thread_block(THREAD_CONTINUE_NULL);
}

/*
 * mutex_lock_acquire
 *
 * Invoked on acquiring the mutex when there is
 * contention.
 *
 * Returns the current number of waiters.
 *
 * Called with the interlock locked.
 */
int
mutex_lock_acquire(
	mutex_t			*mutex)
{
	thread_t		thread = current_thread();

	if (thread->pending_promoter[thread->pending_promoter_index] == mutex) {
		thread->pending_promoter[thread->pending_promoter_index] = NULL;
		if (thread->pending_promoter_index > 0)
			thread->pending_promoter_index--;
		mutex->waiters--;
	}

#if		!defined(i386)
	if (mutex->waiters > 0) {
		integer_t		priority = mutex->promoted_pri;
		spl_t			s = splsched();

		thread_lock(thread);
		thread->promotions++;
		if (thread->priority < MINPRI_KERNEL) {
			thread->sched_mode |= TH_MODE_PROMOTED;
			if (thread->sched_pri < priority) {
				KERNEL_DEBUG_CONSTANT(
					MACHDBG_CODE(DBG_MACH_SCHED,MACH_PROMOTE) | DBG_FUNC_NONE,
						thread->sched_pri, priority, 0, (int)mutex, 0);

				set_sched_pri(thread, priority);
			}
		}
		thread_unlock(thread);
		splx(s);
	}
	else
		mutex->promoted_pri = 0;
#endif

	return (mutex->waiters);
}

/*
 * mutex_unlock_wakeup
 *
 * Invoked on unlock when there is contention.
 *
 * Called with the interlock locked.
 */
void
mutex_unlock_wakeup (
	mutex_t			*mutex,
	thread_act_t	holder)
{
#if		!defined(i386)
	thread_t		thread = current_thread();

	if (thread->top_act != holder)
		panic("mutex_unlock_wakeup: mutex %x holder %x\n", mutex, holder);

	if (thread->promotions > 0) {
		spl_t		s = splsched();

		thread_lock(thread);
		if (	--thread->promotions == 0				&&
				(thread->sched_mode & TH_MODE_PROMOTED)		) {
			thread->sched_mode &= ~TH_MODE_PROMOTED;
			if (thread->sched_mode & TH_MODE_ISDEPRESSED) {
				KERNEL_DEBUG_CONSTANT(
					MACHDBG_CODE(DBG_MACH_SCHED,MACH_DEMOTE) | DBG_FUNC_NONE,
						  thread->sched_pri, DEPRESSPRI, 0, (int)mutex, 0);

				set_sched_pri(thread, DEPRESSPRI);
			}
			else {
				if (thread->priority < thread->sched_pri) {
					KERNEL_DEBUG_CONSTANT(
						MACHDBG_CODE(DBG_MACH_SCHED,MACH_DEMOTE) |
															DBG_FUNC_NONE,
							thread->sched_pri, thread->priority,
									0, (int)mutex, 0);
				}

				compute_priority(thread, FALSE);
			}
		}
		thread_unlock(thread);
		splx(s);
	}
#endif

	assert(mutex->waiters > 0);
	thread_wakeup_one(mutex);
}

/*
 * mutex_pause: Called by former callers of simple_lock_pause().
 */

void
mutex_pause(void)
{
	wait_result_t wait_result;

	wait_result = assert_wait_timeout( 1, THREAD_UNINT);
	assert(wait_result == THREAD_WAITING);

	ETAP_SET_REASON(current_thread(), BLOCKED_ON_MUTEX_LOCK);

	wait_result = thread_block(THREAD_CONTINUE_NULL);
	assert(wait_result == THREAD_TIMED_OUT);
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
		   addr, *hw_lock_addr(addr->locked), addr->waiters);
#if	MACH_LDEBUG
	db_printf (" %08x ", addr->thread);
	db_printsym (addr->pc, DB_STGY_ANY);
#endif	/* MACH_LDEBUG */
	db_printf ("\n");
}
#endif	/* MACH_KDB */

#if	MACH_LDEBUG
extern void	meter_simple_lock (
			simple_lock_t	l);
extern void	meter_simple_unlock (
			simple_lock_t	l);
extern void	cyctm05_stamp (
			unsigned long	* start);
extern void	cyctm05_diff (
			unsigned long	* start,
			unsigned long	* end,
			unsigned long	* diff);

#if 0
simple_lock_data_t	loser;
#endif

void
meter_simple_lock(
		simple_lock_t	lp)
{
#if 0
	cyctm05_stamp (lp->duration);
#endif
}

int			long_simple_lock_crash;
int			long_simple_lock_time = 0x600;
/*
 *	This is pretty gawd-awful.  XXX
 */
decl_simple_lock_data(extern,kd_tty)

void
meter_simple_unlock(
		simple_lock_t	lp)
{
#if 0
	unsigned long	stime[2], etime[2], delta[2];

	if (lp == &kd_tty)			/* XXX */
		return;				/* XXX */

	stime[0] = lp->duration[0];
	stime[1] = lp->duration[1];

	cyctm05_stamp (etime);

	if (etime[1] < stime[1])		/* XXX */
		return;				/* XXX */

	cyctm05_diff (stime, etime, delta);

	if (delta[1] >= 0x10000)		/* XXX */
		return;				/* XXX */

	lp->duration[0] = delta[0];
	lp->duration[1] = delta[1];

	if (loser.duration[1] < lp->duration[1])
		loser = *lp;

	assert (!long_simple_lock_crash || delta[1] < long_simple_lock_time);
#endif
}
#endif	/* MACH_LDEBUG */


#if ETAP_LOCK_TRACE

/*
 *  ==============================================================
 *  ETAP hook when initializing a usimple_lock.  May be invoked
 *  from the portable lock package or from an optimized machine-
 *  dependent implementation.
 *  ==============================================================
 */

void
etap_simplelock_init (
	simple_lock_t	l,
	etap_event_t	event)
{
	ETAP_CLEAR_TRACE_DATA(l);
	etap_event_table_assign(&l->u.event_table_chain, event);

#if    ETAP_LOCK_ACCUMULATE
        /* reserve an entry in the cumulative buffer */
        l->cbuff_entry = etap_cbuff_reserve(lock_event_table(l));
        /* initialize the entry if one was returned  */
        if (l->cbuff_entry != CBUFF_ENTRY_NULL) {
                l->cbuff_entry->event    = event;
                l->cbuff_entry->instance = (unsigned long) l;
                l->cbuff_entry->kind     = SPIN_LOCK;
        }
#endif  /* ETAP_LOCK_ACCUMULATE */
}


void
etap_simplelock_unlock(
	simple_lock_t	l)
{
        unsigned short	dynamic = 0;
        unsigned short	trace   = 0;
        etap_time_t	total_time;
        etap_time_t	stop_hold_time;
        pc_t		pc;

	OBTAIN_PC(pc, l);
        ETAP_STAMP(lock_event_table(l), trace, dynamic);

        /*
         *  Calculate & collect hold time data only if
         *  the hold tracing was enabled throughout the
         *  whole operation.  This prevents collection of
         *  bogus data caused by mid-operation trace changes.
         *
         */

	if (ETAP_DURATION_ENABLED(trace) && ETAP_WHOLE_OP(l)) {
		ETAP_TIMESTAMP (stop_hold_time);
		ETAP_TOTAL_TIME(total_time, stop_hold_time,
				l->u.s.start_hold_time);
		CUM_HOLD_ACCUMULATE(l->cbuff_entry, total_time, dynamic, trace);
		MON_ASSIGN_PC(l->end_pc, pc, trace);
		MON_DATA_COLLECT(l,
				 l,
				 total_time,
				 SPIN_LOCK,
				 MON_DURATION,
				 trace);
	}
        ETAP_CLEAR_TRACE_DATA(l);
}

/*  ========================================================================
 *  Since the the simple_lock() routine is machine dependant, it must always
 *  be coded in assembly.  The two hook routines below are used to collect
 *  lock_stat data.
 *  ========================================================================
 */

/*
 *  ROUTINE:    etap_simplelock_miss()
 *
 *  FUNCTION:   This spin lock routine is called upon the first
 *              spin (miss) of the lock.
 *
 *              A timestamp is taken at the beginning of the wait period,
 *              if wait tracing is enabled.
 *
 *
 *  PARAMETERS:
 *              - lock address.
 *              - timestamp address.
 *
 *  RETURNS:    Wait timestamp value.  The timestamp value is later used
 *              by etap_simplelock_hold().
 *
 *  NOTES:      This routine is NOT ALWAYS called.  The lock may be free
 *              (never spinning).  For this reason the pc is collected in
 *              etap_simplelock_hold().
 *
 */
etap_time_t
etap_simplelock_miss (
	simple_lock_t	l)

{
        unsigned short trace     = 0;
        unsigned short dynamic   = 0;
	etap_time_t    start_miss_time;

        ETAP_STAMP(lock_event_table(l), trace, dynamic);

        if (trace & ETAP_CONTENTION)
		ETAP_TIMESTAMP(start_miss_time);

	return(start_miss_time);
}

/*
 *  ROUTINE:    etap_simplelock_hold()
 *
 *  FUNCTION:   This spin lock routine is ALWAYS called once the lock
 *              is acquired.  Here, the contention time is calculated and
 *              the start hold time is stamped.
 *
 *  PARAMETERS:
 *              - lock address.
 *              - PC of the calling function.
 *              - start wait timestamp.
 *
 */

void
etap_simplelock_hold (
	simple_lock_t	l,
	pc_t		pc,
	etap_time_t	start_hold_time)
{
        unsigned short 	dynamic = 0;
        unsigned short 	trace   = 0;
        etap_time_t	total_time;
        etap_time_t	stop_hold_time;

        ETAP_STAMP(lock_event_table(l), trace, dynamic);

        MON_ASSIGN_PC(l->start_pc, pc, trace);

        /* do not collect wait data if lock was free */
        if (ETAP_TIME_IS_ZERO(start_hold_time) && (trace & ETAP_CONTENTION)) {
		ETAP_TIMESTAMP(stop_hold_time);
		ETAP_TOTAL_TIME(total_time,
                                stop_hold_time,
                                start_hold_time);
                CUM_WAIT_ACCUMULATE(l->cbuff_entry, total_time, dynamic, trace);
		MON_DATA_COLLECT(l,
				 l,
				 total_time,
				 SPIN_LOCK,
				 MON_CONTENTION,
				 trace);
		ETAP_COPY_START_HOLD_TIME(&l->u.s, stop_hold_time, trace);
        }
        else
		ETAP_DURATION_TIMESTAMP(&l->u.s, trace);
}

void
etap_mutex_init (
	mutex_t		*l,
	etap_event_t	event)
{
	ETAP_CLEAR_TRACE_DATA(l);
	etap_event_table_assign(&l->u.event_table_chain, event);

#if	ETAP_LOCK_ACCUMULATE
        /* reserve an entry in the cumulative buffer */
        l->cbuff_entry = etap_cbuff_reserve(lock_event_table(l));
        /* initialize the entry if one was returned  */
        if (l->cbuff_entry != CBUFF_ENTRY_NULL) {
		l->cbuff_entry->event    = event;
		l->cbuff_entry->instance = (unsigned long) l;
		l->cbuff_entry->kind     = MUTEX_LOCK;
	}
#endif  /* ETAP_LOCK_ACCUMULATE */
}

etap_time_t
etap_mutex_miss (
	mutex_t	   *l)
{
        unsigned short	trace       = 0;
        unsigned short	dynamic     = 0;
	etap_time_t	start_miss_time;

        ETAP_STAMP(lock_event_table(l), trace, dynamic);

        if (trace & ETAP_CONTENTION)
		ETAP_TIMESTAMP(start_miss_time);
	else
		ETAP_TIME_CLEAR(start_miss_time);

	return(start_miss_time);
}

void
etap_mutex_hold (
	mutex_t		*l,
	pc_t		pc,
	etap_time_t	start_hold_time)
{
        unsigned short 	dynamic = 0;
        unsigned short 	trace   = 0;
        etap_time_t	total_time;
        etap_time_t	stop_hold_time;

        ETAP_STAMP(lock_event_table(l), trace, dynamic);

        MON_ASSIGN_PC(l->start_pc, pc, trace);

        /* do not collect wait data if lock was free */
        if (!ETAP_TIME_IS_ZERO(start_hold_time) && (trace & ETAP_CONTENTION)) {
		ETAP_TIMESTAMP(stop_hold_time);
		ETAP_TOTAL_TIME(total_time,
				stop_hold_time,
				start_hold_time);
		CUM_WAIT_ACCUMULATE(l->cbuff_entry, total_time, dynamic, trace);
		MON_DATA_COLLECT(l,
				 l,
				 total_time,
				 MUTEX_LOCK,
				 MON_CONTENTION,
				 trace);
		ETAP_COPY_START_HOLD_TIME(&l->u.s, stop_hold_time, trace);
        }
        else
		ETAP_DURATION_TIMESTAMP(&l->u.s, trace);
}

void
etap_mutex_unlock(
	mutex_t		*l)
{
        unsigned short	dynamic = 0;
        unsigned short	trace   = 0;
        etap_time_t	total_time;
        etap_time_t	stop_hold_time;
        pc_t		pc;

	OBTAIN_PC(pc, l);
        ETAP_STAMP(lock_event_table(l), trace, dynamic);

        /*
         *  Calculate & collect hold time data only if
         *  the hold tracing was enabled throughout the
         *  whole operation.  This prevents collection of
         *  bogus data caused by mid-operation trace changes.
         *
         */

        if (ETAP_DURATION_ENABLED(trace) && ETAP_WHOLE_OP(l)) {
		ETAP_TIMESTAMP(stop_hold_time);
		ETAP_TOTAL_TIME(total_time, stop_hold_time,
				l->u.s.start_hold_time);
		CUM_HOLD_ACCUMULATE(l->cbuff_entry, total_time, dynamic, trace);
		MON_ASSIGN_PC(l->end_pc, pc, trace);
		MON_DATA_COLLECT(l,
				 l,
				 total_time,
				 MUTEX_LOCK,
				 MON_DURATION,
				 trace);
        }
        ETAP_CLEAR_TRACE_DATA(l);
}

#endif  /* ETAP_LOCK_TRACE */
