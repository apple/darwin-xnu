/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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

#define LOCK_PRIVATE 1

#include <mach_ldebug.h>

#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <string.h>

#include <i386/machine_routines.h> /* machine_timeout_suspended() */
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <i386/mp.h>
#include <machine/atomic.h>
#include <sys/kdebug.h>
#include <i386/locks_i386_inlines.h>

#if	CONFIG_DTRACE
#define DTRACE_RW_SHARED	0x0	//reader
#define DTRACE_RW_EXCL		0x1	//writer
#define DTRACE_NO_FLAG		0x0	//not applicable
#endif /* CONFIG_DTRACE */

#define	LCK_RW_LCK_EXCLUSIVE_CODE	0x100
#define	LCK_RW_LCK_EXCLUSIVE1_CODE	0x101
#define	LCK_RW_LCK_SHARED_CODE		0x102
#define	LCK_RW_LCK_SH_TO_EX_CODE	0x103
#define	LCK_RW_LCK_SH_TO_EX1_CODE	0x104
#define	LCK_RW_LCK_EX_TO_SH_CODE	0x105

#define LCK_RW_LCK_EX_WRITER_SPIN_CODE	0x106
#define LCK_RW_LCK_EX_WRITER_WAIT_CODE	0x107
#define LCK_RW_LCK_EX_READER_SPIN_CODE	0x108
#define LCK_RW_LCK_EX_READER_WAIT_CODE	0x109
#define LCK_RW_LCK_SHARED_SPIN_CODE	0x110
#define LCK_RW_LCK_SHARED_WAIT_CODE	0x111
#define LCK_RW_LCK_SH_TO_EX_SPIN_CODE	0x112
#define LCK_RW_LCK_SH_TO_EX_WAIT_CODE	0x113


#define	ANY_LOCK_DEBUG	(USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

unsigned int LcksOpts=0;

#if DEVELOPMENT || DEBUG
unsigned int LckDisablePreemptCheck = 0;
#endif

/* Forwards */

#if	USLOCK_DEBUG
/*
 *	Perform simple lock checks.
 */
int	uslock_check = 1;
int	max_lock_loops	= 100000000;
decl_simple_lock_data(extern , printf_lock);
decl_simple_lock_data(extern , panic_lock);
#endif	/* USLOCK_DEBUG */

extern unsigned int not_in_kdp;

/*
 *	We often want to know the addresses of the callers
 *	of the various lock routines.  However, this information
 *	is only used for debugging and statistics.
 */
typedef void	*pc_t;
#define	INVALID_PC	((void *) VM_MAX_KERNEL_ADDRESS)
#define	INVALID_THREAD	((void *) VM_MAX_KERNEL_ADDRESS)
#if	ANY_LOCK_DEBUG
#define	OBTAIN_PC(pc)	((pc) = GET_RETURN_PC())
#define DECL_PC(pc)	pc_t pc;
#else	/* ANY_LOCK_DEBUG */
#define DECL_PC(pc)
#ifdef	lint
/*
 *	Eliminate lint complaints about unused local pc variables.
 */
#define	OBTAIN_PC(pc)	++pc
#else	/* lint */
#define	OBTAIN_PC(pc)
#endif	/* lint */
#endif	/* USLOCK_DEBUG */

/*
 * atomic exchange API is a low level abstraction of the operations
 * to atomically read, modify, and write a pointer.  This abstraction works
 * for both Intel and ARMv8.1 compare and exchange atomic instructions as
 * well as the ARM exclusive instructions.
 *
 * atomic_exchange_begin() - begin exchange and retrieve current value
 * atomic_exchange_complete() - conclude an exchange
 * atomic_exchange_abort() - cancel an exchange started with atomic_exchange_begin()
 */
static uint32_t
atomic_exchange_begin32(uint32_t *target, uint32_t *previous, enum memory_order ord)
{
	uint32_t	val;

	(void)ord;			// Memory order not used
	val = os_atomic_load(target, relaxed);
	*previous = val;
	return val;
}

static boolean_t
atomic_exchange_complete32(uint32_t *target, uint32_t previous, uint32_t newval, enum memory_order ord)
{
	return __c11_atomic_compare_exchange_strong((_Atomic uint32_t *)target, &previous, newval, ord, memory_order_relaxed);
}

static void
atomic_exchange_abort(void) { }

static boolean_t
atomic_test_and_set32(uint32_t *target, uint32_t test_mask, uint32_t set_mask, enum memory_order ord, boolean_t wait)
{
	uint32_t	value, prev;

	for ( ; ; ) {
		value = atomic_exchange_begin32(target, &prev, ord);
		if (value & test_mask) {
			if (wait)
				cpu_pause();
			else
				atomic_exchange_abort();
			return FALSE;
		}
		value |= set_mask;
		if (atomic_exchange_complete32(target, prev, value, ord))
			return TRUE;
	}
}

inline boolean_t
hw_atomic_test_and_set32(uint32_t *target, uint32_t test_mask, uint32_t set_mask, enum memory_order ord, boolean_t wait)
{
	return atomic_test_and_set32(target, test_mask, set_mask, ord, wait);
}

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
 * Forward definitions
 */

static void lck_rw_lock_shared_gen(lck_rw_t *lck);
static void lck_rw_lock_exclusive_gen(lck_rw_t *lck);
static boolean_t lck_rw_lock_shared_to_exclusive_success(lck_rw_t *lck);
static boolean_t lck_rw_lock_shared_to_exclusive_failure(lck_rw_t *lck, uint32_t prior_lock_state);
static void lck_rw_lock_exclusive_to_shared_gen(lck_rw_t *lck, uint32_t prior_lock_state);
static lck_rw_type_t lck_rw_done_gen(lck_rw_t *lck, uint32_t prior_lock_state);
void lck_rw_clear_promotions_x86(thread_t thread);
static boolean_t lck_rw_held_read_or_upgrade(lck_rw_t *lock);
static boolean_t lck_rw_grab_want(lck_rw_t *lock);
static boolean_t lck_rw_grab_shared(lck_rw_t *lock);
static void lck_mtx_unlock_wakeup_tail(lck_mtx_t *mutex, uint32_t state, boolean_t indirect);
static void lck_mtx_interlock_lock(lck_mtx_t *mutex, uint32_t *new_state);
static void lck_mtx_interlock_lock_clear_flags(lck_mtx_t *mutex, uint32_t and_flags, uint32_t *new_state);
static int lck_mtx_interlock_try_lock(lck_mtx_t *mutex, uint32_t *new_state);
static int lck_mtx_interlock_try_lock_set_flags(lck_mtx_t *mutex, uint32_t or_flags, uint32_t *new_state);
static boolean_t lck_mtx_lock_wait_interlock_to_clear(lck_mtx_t *lock, uint32_t *new_state);
static boolean_t lck_mtx_try_lock_wait_interlock_to_clear(lck_mtx_t *lock, uint32_t *new_state);


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
	if (grp) {
		lck_grp_reference(grp);
		lck_grp_lckcnt_incr(grp, LCK_TYPE_SPIN);
	}
}

/*
 *      Routine:        lck_spin_destroy
 */
void
lck_spin_destroy(
	lck_spin_t	*lck,
	lck_grp_t	*grp)
{
	if (lck->interlock == LCK_SPIN_TAG_DESTROYED)
		return;
	lck->interlock = LCK_SPIN_TAG_DESTROYED;
	if (grp) {
		lck_grp_lckcnt_decr(grp, LCK_TYPE_SPIN);
		lck_grp_deallocate(grp);
	}
	return;
}

/*
 *      Routine:        lck_spin_lock
 */
void
lck_spin_lock_grp(
	lck_spin_t	*lck,
	lck_grp_t	*grp)
{
#pragma unused(grp)
	usimple_lock((usimple_lock_t) lck, grp);
}

void
lck_spin_lock(
	lck_spin_t	*lck)
{
	usimple_lock((usimple_lock_t) lck, NULL);
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

boolean_t
lck_spin_try_lock_grp(
	lck_spin_t	*lck,
	lck_grp_t	*grp)
{
#pragma unused(grp)
	boolean_t lrval = (boolean_t)usimple_lock_try((usimple_lock_t) lck, grp);
#if	DEVELOPMENT || DEBUG
	if (lrval) {
		pltrace(FALSE);
	}
#endif
	return(lrval);
}


/*
 *      Routine:        lck_spin_try_lock
 */
boolean_t
lck_spin_try_lock(
	lck_spin_t	*lck)
{
	boolean_t lrval = (boolean_t)usimple_lock_try((usimple_lock_t) lck, LCK_GRP_NULL);
#if	DEVELOPMENT || DEBUG
	if (lrval) {
		pltrace(FALSE);
	}
#endif
	return(lrval);
}

/*
 *	Routine:	lck_spin_assert
 */
void
lck_spin_assert(lck_spin_t *lock, unsigned int type)
{
	thread_t thread, holder;
	uintptr_t state;

	if (__improbable(type != LCK_ASSERT_OWNED && type != LCK_ASSERT_NOTOWNED)) {
		panic("lck_spin_assert(): invalid arg (%u)", type);
	}

	state = lock->interlock;
	holder = (thread_t)state;
	thread = current_thread();
	if (type == LCK_ASSERT_OWNED) {
		if (__improbable(holder == THREAD_NULL)) {
			panic("Lock not owned %p = %lx", lock, state);
		}
		if (__improbable(holder != thread)) {
			panic("Lock not owned by current thread %p = %lx", lock, state);
		}
	} else if (type == LCK_ASSERT_NOTOWNED) {
		if (__improbable(holder != THREAD_NULL)) {
			if (holder == thread) {
				panic("Lock owned by current thread %p = %lx", lock, state);
			}
		}
	}
}

/*
 *      Routine: kdp_lck_spin_is_acquired
 *      NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 *      Returns: TRUE if lock is acquired.
 */
boolean_t
kdp_lck_spin_is_acquired(lck_spin_t *lck) {
	if (not_in_kdp) {
		panic("panic: spinlock acquired check done outside of kernel debugger");
	}
	return (lck->interlock != 0)? TRUE : FALSE;
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

volatile uint32_t spinlock_owner_cpu = ~0;
volatile usimple_lock_t spinlock_timed_out;

uint32_t spinlock_timeout_NMI(uintptr_t thread_addr) {
	uint32_t i;

	for (i = 0; i < real_ncpus; i++) {
		if ((cpu_data_ptr[i] != NULL) && ((uintptr_t)cpu_data_ptr[i]->cpu_active_thread == thread_addr)) {
			spinlock_owner_cpu = i;
			if ((uint32_t) cpu_number() != i) {
				/* Cause NMI and panic on the owner's cpu */
				NMIPI_panic(cpu_to_cpumask(i), SPINLOCK_TIMEOUT);
			}
			break;
		}
	}

	return spinlock_owner_cpu;
}

/*
 *	Acquire a usimple_lock.
 *
 *	Returns with preemption disabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
(usimple_lock)(
	usimple_lock_t	l
	LCK_GRP_ARG(lck_grp_t *grp))
{
#ifndef	MACHINE_SIMPLE_LOCK
	DECL_PC(pc);

	OBTAIN_PC(pc);
	USLDBG(usld_lock_pre(l, pc));

	if(__improbable(hw_lock_to(&l->interlock, LockTimeOutTSC, grp) == 0))	{
		boolean_t uslock_acquired = FALSE;
		while (machine_timeout_suspended()) {
			enable_preemption();
			if ((uslock_acquired = hw_lock_to(&l->interlock, LockTimeOutTSC, grp)))
				break;
		}

		if (uslock_acquired == FALSE) {
			uint32_t lock_cpu;
			uintptr_t lowner = (uintptr_t)l->interlock.lock_data;
			spinlock_timed_out = l;
			lock_cpu = spinlock_timeout_NMI(lowner);
			panic("Spinlock acquisition timed out: lock=%p, lock owner thread=0x%lx, current_thread: %p, lock owner active on CPU 0x%x, current owner: 0x%lx, time: %llu",
			      l, lowner,  current_thread(), lock_cpu, (uintptr_t)l->interlock.lock_data, mach_absolute_time());
		}
	}
#if DEVELOPMENT || DEBUG
		pltrace(FALSE);
#endif

	USLDBG(usld_lock_post(l, pc));
#else
	simple_lock((simple_lock_t)l, grp);
#endif
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_ACQUIRE, l, 0, (uintptr_t)LCK_GRP_PROBEARG(grp));
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

	OBTAIN_PC(pc);
	USLDBG(usld_unlock(l, pc));
#if DEVELOPMENT || DEBUG
		pltrace(TRUE);
#endif
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
	usimple_lock_t	l,
	lck_grp_t *grp)
{
#ifndef	MACHINE_SIMPLE_LOCK
	unsigned int	success;
	DECL_PC(pc);

	OBTAIN_PC(pc);
	USLDBG(usld_lock_try_pre(l, pc));
	if ((success = hw_lock_try(&l->interlock, grp))) {
#if DEVELOPMENT || DEBUG
		pltrace(FALSE);
#endif
	USLDBG(usld_lock_try_post(l, pc));
	}
	return success;
#else
	return(simple_lock_try((simple_lock_t)l, grp));
#endif
}

/*
 * Acquire a usimple_lock while polling for pending cpu signals
 * and spinning on a lock.
 *
 */
unsigned int
(usimple_lock_try_lock_mp_signal_safe_loop_deadline)(usimple_lock_t l,
	uint64_t deadline
	LCK_GRP_ARG(lck_grp_t *grp))
{
	boolean_t istate = ml_get_interrupts_enabled();

	if (deadline < mach_absolute_time()) {
		return 0;
	}

	while (!simple_lock_try(l, grp)) {
		if (!istate)
			cpu_signal_handler(NULL);
		
		if (deadline < mach_absolute_time()) {
			return 0;
		}

		cpu_pause();
	}

	return 1;
}

void
(usimple_lock_try_lock_loop)(usimple_lock_t l
	LCK_GRP_ARG(lck_grp_t *grp))
{
	usimple_lock_try_lock_mp_signal_safe_loop_deadline(l, ULLONG_MAX, grp);
}

unsigned int
(usimple_lock_try_lock_mp_signal_safe_loop_duration)(usimple_lock_t l,
	uint64_t duration
	LCK_GRP_ARG(lck_grp_t *grp))
{
	uint64_t deadline;
	uint64_t base_at = mach_absolute_time();
	uint64_t duration_at;

	nanoseconds_to_absolutetime(duration, &duration_at);
	deadline = base_at + duration_at;
	if (deadline < base_at) {
		/* deadline has overflowed, make it saturate */
		deadline = ULLONG_MAX;
	}

	return usimple_lock_try_lock_mp_signal_safe_loop_deadline(l, deadline, grp);
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
		panic("%s:  %p is not a usimple lock, 0x%x", caller, l, l->lock_type);
	if (!(l->debug.state & USLOCK_INIT))
		panic("%s:  %p is not an initialized lock, 0x%x", caller, l, l->debug.state);
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
		printf("%s:  lock %p already locked (at %p) by",
		      caller, l, l->debug.lock_pc);
		printf(" current thread %p (new attempt at pc %p)\n",
		       l->debug.lock_thread, pc);
		panic("%s", caller);
	}
	mp_disable_preemption();
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
	int	mycpu;
	char	caller[] = "successful usimple_lock";


	if (!usld_lock_common_checks(l, caller))
		return;

	if (!((l->debug.state & ~USLOCK_TAKEN) == USLOCK_INITIALIZED))
		panic("%s:  lock %p became uninitialized",
		      caller, l);
	if ((l->debug.state & USLOCK_TAKEN))
		panic("%s:  lock 0x%p became TAKEN by someone else",
		      caller, l);

	mycpu = cpu_number();
	l->debug.lock_thread = (void *)current_thread();
	l->debug.state |= USLOCK_TAKEN;
	l->debug.lock_pc = pc;
	l->debug.lock_cpu = mycpu;
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
	int	mycpu;
	char	caller[] = "usimple_unlock";


	if (!usld_lock_common_checks(l, caller))
		return;

	mycpu = cpu_number();

	if (!(l->debug.state & USLOCK_TAKEN))
		panic("%s:  lock 0x%p hasn't been taken",
		      caller, l);
	if (l->debug.lock_thread != (void *) current_thread())
		panic("%s:  unlocking lock 0x%p, owned by thread %p",
		      caller, l, l->debug.lock_thread);
	if (l->debug.lock_cpu != mycpu) {
		printf("%s:  unlocking lock 0x%p on cpu 0x%x",
		       caller, l, mycpu);
		printf(" (acquired on cpu 0x%x)\n", l->debug.lock_cpu);
		panic("%s", caller);
	}

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
	__unused pc_t	pc)
{
	char	caller[] = "usimple_lock_try";

	if (!usld_lock_common_checks(l, caller))
		return;
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
	int	mycpu;
	char	caller[] = "successful usimple_lock_try";

	if (!usld_lock_common_checks(l, caller))
		return;

	if (!((l->debug.state & ~USLOCK_TAKEN) == USLOCK_INITIALIZED))
		panic("%s:  lock 0x%p became uninitialized",
		      caller, l);
	if ((l->debug.state & USLOCK_TAKEN))
		panic("%s:  lock 0x%p became TAKEN by someone else",
		      caller, l);

	mycpu = cpu_number();
	l->debug.lock_thread = (void *) current_thread();
	l->debug.state |= USLOCK_TAKEN;
	l->debug.lock_pc = pc;
	l->debug.lock_cpu = mycpu;
}
#endif	/* USLOCK_DEBUG */

/*
 *      Routine:        lck_rw_alloc_init
 */
lck_rw_t *
lck_rw_alloc_init(
	lck_grp_t	*grp,
	lck_attr_t	*attr) {
	lck_rw_t	*lck;

	if ((lck = (lck_rw_t *)kalloc(sizeof(lck_rw_t))) != 0) {
		bzero(lck, sizeof(lck_rw_t));
		lck_rw_init(lck, grp, attr);
	}

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
	lck_attr_t	*attr)
{
	lck_attr_t	*lck_attr = (attr != LCK_ATTR_NULL) ?
					attr : &LockDefaultLckAttr;

	hw_lock_byte_init(&lck->lck_rw_interlock);
	lck->lck_rw_want_write = FALSE;
	lck->lck_rw_want_upgrade = FALSE;
	lck->lck_rw_shared_count = 0;
	lck->lck_rw_can_sleep = TRUE;
	lck->lck_r_waiting = lck->lck_w_waiting = 0;
	lck->lck_rw_tag = 0;
	lck->lck_rw_priv_excl = ((lck_attr->lck_attr_val &
				LCK_ATTR_RW_SHARED_PRIORITY) == 0);

	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_RW);
}

/*
 *      Routine:        lck_rw_destroy
 */
void
lck_rw_destroy(
	lck_rw_t	*lck,
	lck_grp_t	*grp)
{
	if (lck->lck_rw_tag == LCK_RW_TAG_DESTROYED)
		return;
#if MACH_LDEBUG
	lck_rw_assert(lck, LCK_RW_ASSERT_NOTHELD);
#endif
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
 * We disable interrupts while holding the RW interlock to prevent an
 * interrupt from exacerbating hold time.
 * Hence, local helper functions lck_interlock_lock()/lck_interlock_unlock().
 */
static inline boolean_t
lck_interlock_lock(lck_rw_t *lck)
{
	boolean_t	istate;

	istate = ml_set_interrupts_enabled(FALSE);
	hw_lock_byte_lock(&lck->lck_rw_interlock);
	return istate;
}

static inline void
lck_interlock_unlock(lck_rw_t *lck, boolean_t istate)
{
	hw_lock_byte_unlock(&lck->lck_rw_interlock);
	ml_set_interrupts_enabled(istate);
}

/*
 * This inline is used when busy-waiting for an rw lock.
 * If interrupts were disabled when the lock primitive was called,
 * we poll the IPI handler for pending tlb flushes.
 * XXX This is a hack to avoid deadlocking on the pmap_system_lock.
 */
static inline void
lck_rw_lock_pause(boolean_t interrupts_enabled)
{
	if (!interrupts_enabled)
		handle_pending_TLB_flushes();
	cpu_pause();
}

static inline boolean_t
lck_rw_held_read_or_upgrade(lck_rw_t *lock)
{
	if (ordered_load(&lock->data) & (LCK_RW_SHARED_MASK | LCK_RW_INTERLOCK | LCK_RW_WANT_UPGRADE))
		return TRUE;
	return FALSE;
}

/*
 * compute the deadline to spin against when
 * waiting for a change of state on a lck_rw_t
 */
static inline uint64_t
lck_rw_deadline_for_spin(lck_rw_t *lck)
{
	if (lck->lck_rw_can_sleep) {
		if (lck->lck_r_waiting || lck->lck_w_waiting || lck->lck_rw_shared_count > machine_info.max_cpus) {
			/*
			 * there are already threads waiting on this lock... this
			 * implies that they have spun beyond their deadlines waiting for 
			 * the desired state to show up so we will not bother spinning at this time...
			 *   or
			 * the current number of threads sharing this lock exceeds our capacity to run them
			 * concurrently and since all states we're going to spin for require the rw_shared_count
			 * to be at 0, we'll not bother spinning since the latency for this to happen is
			 * unpredictable...
			 */
			return (mach_absolute_time());
		}
		return (mach_absolute_time() + MutexSpin);
	} else
		return (mach_absolute_time() + (100000LL * 1000000000LL));
}


/*
 * Spin while interlock is held.
 */

static inline void
lck_rw_interlock_spin(lck_rw_t *lock)
{
	while (ordered_load(&lock->data) & LCK_RW_INTERLOCK) {
		cpu_pause();
	}
}

static boolean_t
lck_rw_grab_want(lck_rw_t *lock)
{
	uint32_t	data, prev;

	for ( ; ; ) {
		data = atomic_exchange_begin32(&lock->data, &prev, memory_order_relaxed);
		if ((data & LCK_RW_INTERLOCK) == 0)
			break;
		atomic_exchange_abort();
		lck_rw_interlock_spin(lock);
	}
	if (data & LCK_RW_WANT_WRITE) {
		atomic_exchange_abort();
		return FALSE;
	}
	data |= LCK_RW_WANT_WRITE;
	return atomic_exchange_complete32(&lock->data, prev, data, memory_order_relaxed);
}

static boolean_t
lck_rw_grab_shared(lck_rw_t *lock)
{
	uint32_t	data, prev;

	for ( ; ; ) {
		data = atomic_exchange_begin32(&lock->data, &prev, memory_order_acquire_smp);
		if ((data & LCK_RW_INTERLOCK) == 0)
			break;
		atomic_exchange_abort();
		lck_rw_interlock_spin(lock);
	}
	if (data & (LCK_RW_WANT_WRITE | LCK_RW_WANT_UPGRADE)) {
		if (((data & LCK_RW_SHARED_MASK) == 0) || (data & LCK_RW_PRIV_EXCL)) {
			atomic_exchange_abort();
			return FALSE;
		}
	}
	data += LCK_RW_SHARED_READER;
	return atomic_exchange_complete32(&lock->data, prev, data, memory_order_acquire_smp);
}

/*
 *      Routine:        lck_rw_lock_exclusive
 */
static void
lck_rw_lock_exclusive_gen(
	lck_rw_t	*lck)
{
	__kdebug_only uintptr_t	trace_lck = unslide_for_kdebug(lck);
	uint64_t	deadline = 0;
	int		slept = 0;
	int		gotlock = 0;
	int		lockheld = 0;
	wait_result_t	res = 0;
	boolean_t	istate = -1;

#if	CONFIG_DTRACE
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_excl_spin, dtrace_rwl_excl_block, dtrace_ls_enabled= FALSE;
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
#endif

	/*
	 *	Try to acquire the lck_rw_want_write bit.
	 */
	while ( !lck_rw_grab_want(lck)) {

#if	CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] != 0);
			dtrace_rwl_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_excl_spin || dtrace_rwl_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lck->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif
		if (istate == -1)
			istate = ml_get_interrupts_enabled();

		deadline = lck_rw_deadline_for_spin(lck);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_SPIN_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

		while (((gotlock = lck_rw_grab_want(lck)) == 0) && mach_absolute_time() < deadline)
			lck_rw_lock_pause(istate);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_SPIN_CODE) | DBG_FUNC_END, trace_lck, 0, 0, gotlock, 0);

		if (gotlock)
			break;
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock exclusively
		 * check to see if we're allowed to do a thread_block
		 */
		if (lck->lck_rw_can_sleep) {

			istate = lck_interlock_lock(lck);

			if (lck->lck_rw_want_write) {

				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_WAIT_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

				lck->lck_w_waiting = TRUE;

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockWrite);
				res = assert_wait(RW_LOCK_WRITER_EVENT(lck),
						THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lck, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_WAIT_CODE) | DBG_FUNC_END, trace_lck, res, slept, 0, 0);
			} else {
				lck->lck_rw_want_write = TRUE;
				lck_interlock_unlock(lck, istate);
				break;
			}
		}
	}
	/*
	 * Wait for readers (and upgrades) to finish...
	 * the test for these conditions must be done simultaneously with
	 * a check of the interlock not being held since
	 * the rw_shared_count will drop to 0 first and then want_upgrade
	 * will be set to 1 in the shared_to_exclusive scenario... those
	 * adjustments are done behind the interlock and represent an
	 * atomic change in state and must be considered as such
	 * however, once we see the read count at 0, the want_upgrade not set
	 * and the interlock not held, we are safe to proceed
	 */
	while (lck_rw_held_read_or_upgrade(lck)) {

#if	CONFIG_DTRACE
		/*
		 * Either sleeping or spinning is happening, start
		 * a timing of our delay interval now.  If we set it
		 * to -1 we don't have accurate data so we cannot later
		 * decide to record a dtrace spin or sleep event.
		 */
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] != 0);
			dtrace_rwl_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_excl_spin || dtrace_rwl_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lck->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif
		if (istate == -1)
			istate = ml_get_interrupts_enabled();

		deadline = lck_rw_deadline_for_spin(lck);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_SPIN_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

		while ((lockheld = lck_rw_held_read_or_upgrade(lck)) && mach_absolute_time() < deadline)
			lck_rw_lock_pause(istate);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_SPIN_CODE) | DBG_FUNC_END, trace_lck, 0, 0, lockheld, 0);

		if ( !lockheld)
			break;
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock exclusively
		 * check to see if we're allowed to do a thread_block
		 */
		if (lck->lck_rw_can_sleep) {

			istate = lck_interlock_lock(lck);

			if (lck->lck_rw_shared_count != 0 || lck->lck_rw_want_upgrade) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_WAIT_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

				lck->lck_w_waiting = TRUE;

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockWrite);
				res = assert_wait(RW_LOCK_WRITER_EVENT(lck),
						THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lck, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_WAIT_CODE) | DBG_FUNC_END, trace_lck, res, slept, 0, 0);
			} else {
				lck_interlock_unlock(lck, istate);
				/*
				 * must own the lock now, since we checked for
				 * readers or upgrade owner behind the interlock
				 * no need for a call to 'lck_rw_held_read_or_upgrade'
				 */
				break;
			}
		}
	}

#if	CONFIG_DTRACE
	/*
	 * Decide what latencies we suffered that are Dtrace events.
	 * If we have set wait_interval, then we either spun or slept.
	 * At least we get out from under the interlock before we record
	 * which is the best we can do here to minimize the impact
	 * of the tracing.
	 * If we have set wait_interval to -1, then dtrace was not enabled when we
	 * started sleeping/spinning so we don't record this event.
	 */
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_SPIN, lck,
			    mach_absolute_time() - wait_interval, 1);
		} else {
			/*
			 * For the blocking case, we also record if when we blocked
			 * it was held for read or write, and how many readers.
			 * Notice that above we recorded this before we dropped
			 * the interlock so the count is accurate.
			 */
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lck, 1);
#endif
}

/*
 *      Routine:        lck_rw_done
 */

lck_rw_type_t lck_rw_done(lck_rw_t *lock)
{
	uint32_t	data, prev;

	for ( ; ; ) {
		data = atomic_exchange_begin32(&lock->data, &prev, memory_order_release_smp);
		if (data & LCK_RW_INTERLOCK) {		/* wait for interlock to clear */
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & LCK_RW_SHARED_MASK) {
			data -= LCK_RW_SHARED_READER;
			if ((data & LCK_RW_SHARED_MASK) == 0)	/* if reader count has now gone to 0, check for waiters */
				goto check_waiters;
		} else {					/* if reader count == 0, must be exclusive lock */
			if (data & LCK_RW_WANT_UPGRADE) {
				data &= ~(LCK_RW_WANT_UPGRADE);
			} else {
				if (data & LCK_RW_WANT_WRITE)
					data &= ~(LCK_RW_WANT_EXCL);
				else					/* lock is not 'owned', panic */
					panic("Releasing non-exclusive RW lock without a reader refcount!");
			}
check_waiters:
			if (prev & LCK_RW_W_WAITING) {
				data &= ~(LCK_RW_W_WAITING);
				if ((prev & LCK_RW_PRIV_EXCL) == 0)
					data &= ~(LCK_RW_R_WAITING);
			} else
				data &= ~(LCK_RW_R_WAITING);
		}
		if (atomic_exchange_complete32(&lock->data, prev, data, memory_order_release_smp))
			break;
		cpu_pause();
	}
	return lck_rw_done_gen(lock, prev);
}

/*
 *      Routine:        lck_rw_done_gen
 *
 *	called from lck_rw_done()
 *	prior_lock_state is the value in the 1st
 * 	word of the lock at the time of a successful
 *	atomic compare and exchange with the new value...
 * 	it represents the state of the lock before we
 *	decremented the rw_shared_count or cleared either
 * 	rw_want_upgrade or rw_want_write and
 *	the lck_x_waiting bits...  since the wrapper
 * 	routine has already changed the state atomically, 
 *	we just need to decide if we should
 *	wake up anyone and what value to return... we do
 *	this by examining the state of the lock before
 *	we changed it
 */
static lck_rw_type_t
lck_rw_done_gen(
	lck_rw_t        *lck,
	uint32_t        prior_lock_state)
{
	lck_rw_t        *fake_lck;
	lck_rw_type_t   lock_type;
	thread_t        thread;
	uint32_t        rwlock_count;

	thread = current_thread();
	rwlock_count = thread->rwlock_count--;
	fake_lck = (lck_rw_t *)&prior_lock_state;

	if (lck->lck_rw_can_sleep) {
		/*
		 * prior_lock state is a snapshot of the 1st word of the
		 * lock in question... we'll fake up a pointer to it
		 * and carefully not access anything beyond whats defined
		 * in the first word of a lck_rw_t
		 */

		if (fake_lck->lck_rw_shared_count <= 1) {
			if (fake_lck->lck_w_waiting) {
				thread_wakeup(RW_LOCK_WRITER_EVENT(lck));
			}

			if (!(fake_lck->lck_rw_priv_excl && fake_lck->lck_w_waiting) && fake_lck->lck_r_waiting) {
				thread_wakeup(RW_LOCK_READER_EVENT(lck));
			}
		}
#if MACH_LDEBUG
		if (rwlock_count == 0) {
			panic("rw lock count underflow for thread %p", thread);
		}
#endif
		/* Check if dropping the lock means that we need to unpromote */

		if ((rwlock_count == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
			/* sched_flags checked without lock, but will be rechecked while clearing */
			lck_rw_clear_promotion(thread, unslide_for_kdebug(lck));
		}
	}
	if (fake_lck->lck_rw_shared_count) {
		lock_type = LCK_RW_TYPE_SHARED;
	} else {
		lock_type = LCK_RW_TYPE_EXCLUSIVE;
	}

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE, lck, lock_type == LCK_RW_TYPE_SHARED ? 0 : 1);
#endif

	return lock_type;
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

	assertf(lck->lck_rw_shared_count > 0, "lck %p has shared_count=0x%x", lck, lck->lck_rw_shared_count);
	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_SHARED)
		panic("lck_rw_unlock_shared(): lock %p held in mode: %d\n", lck, ret);
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
lck_rw_lock_shared(lck_rw_t *lock)
{
	uint32_t	data, prev;

	current_thread()->rwlock_count++;
	for ( ; ; ) {
		data = atomic_exchange_begin32(&lock->data, &prev, memory_order_acquire_smp);
		if (data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE | LCK_RW_INTERLOCK)) {
			atomic_exchange_abort();
			if (lock->lck_rw_can_sleep) {
				lck_rw_lock_shared_gen(lock);
			} else {
				cpu_pause();
				continue;
			}
			break;
		}
		data += LCK_RW_SHARED_READER;
		if (atomic_exchange_complete32(&lock->data, prev, data, memory_order_acquire_smp))
			break;
		cpu_pause();
	}
#if	CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lock, DTRACE_RW_SHARED);
#endif	/* CONFIG_DTRACE */
	return;
}

/*
 *	Routine:	lck_rw_lock_shared_gen
 *	Function:
 *		assembly fast path code has determined that this lock
 *		is held exclusively... this is where we spin/block
 *		until we can acquire the lock in the shared mode
 */
static void
lck_rw_lock_shared_gen(
	lck_rw_t	*lck)
{
	__kdebug_only uintptr_t	trace_lck = unslide_for_kdebug(lck);
	uint64_t	deadline = 0;
	int		gotlock = 0;
	int		slept = 0;
	wait_result_t	res = 0;
	boolean_t	istate = -1;

#if	CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_shared_spin, dtrace_rwl_shared_block, dtrace_ls_enabled = FALSE;
#endif

	while ( !lck_rw_grab_shared(lck)) {

#if	CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_shared_spin = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_SPIN] != 0);
			dtrace_rwl_shared_block = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_shared_spin || dtrace_rwl_shared_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lck->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif
		if (istate == -1)
			istate = ml_get_interrupts_enabled();

		deadline = lck_rw_deadline_for_spin(lck);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_SPIN_CODE) | DBG_FUNC_START,
			     trace_lck, lck->lck_rw_want_write, lck->lck_rw_want_upgrade, 0, 0);

		while (((gotlock = lck_rw_grab_shared(lck)) == 0) && mach_absolute_time() < deadline)
			lck_rw_lock_pause(istate);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_SPIN_CODE) | DBG_FUNC_END,
			     trace_lck, lck->lck_rw_want_write, lck->lck_rw_want_upgrade, gotlock, 0);

		if (gotlock)
			break;
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock for read
		 * check to see if we're allowed to do a thread_block
		 */
		if (lck->lck_rw_can_sleep) {

			istate = lck_interlock_lock(lck);

			if ((lck->lck_rw_want_write || lck->lck_rw_want_upgrade) &&
			    ((lck->lck_rw_shared_count == 0) || lck->lck_rw_priv_excl)) {

				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_WAIT_CODE) | DBG_FUNC_START,
					     trace_lck, lck->lck_rw_want_write, lck->lck_rw_want_upgrade, 0, 0);

				lck->lck_r_waiting = TRUE;

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockRead);
				res = assert_wait(RW_LOCK_READER_EVENT(lck),
						THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lck, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_WAIT_CODE) | DBG_FUNC_END,
					     trace_lck, res, slept, 0, 0);
			} else {
				lck->lck_rw_shared_count++;
				lck_interlock_unlock(lck, istate);
				break;
			}
		}
	}

#if	CONFIG_DTRACE
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_SPIN, lck, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 0,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lck, 0);
#endif
}


/*
 *	Routine:	lck_rw_lock_exclusive
 */

void
lck_rw_lock_exclusive(lck_rw_t *lock)
{
	current_thread()->rwlock_count++;
	if (atomic_test_and_set32(&lock->data,
		(LCK_RW_SHARED_MASK | LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE | LCK_RW_INTERLOCK),
		LCK_RW_WANT_EXCL, memory_order_acquire_smp, FALSE)) {
#if	CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif	/* CONFIG_DTRACE */
	} else
		lck_rw_lock_exclusive_gen(lock);
}


/*
 *	Routine:	lck_rw_lock_shared_to_exclusive
 *
 *	False returned upon failure, in this case the shared lock is dropped.
 */

boolean_t
lck_rw_lock_shared_to_exclusive(lck_rw_t *lock)
{
	uint32_t	data, prev;

	for ( ; ; ) {
		data = atomic_exchange_begin32(&lock->data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & LCK_RW_WANT_UPGRADE) {
			data -= LCK_RW_SHARED_READER;
			if ((data & LCK_RW_SHARED_MASK) == 0)		/* we were the last reader */
				data &= ~(LCK_RW_W_WAITING);		/* so clear the wait indicator */
			if (atomic_exchange_complete32(&lock->data, prev, data, memory_order_acquire_smp))
				return lck_rw_lock_shared_to_exclusive_failure(lock, prev);
		} else {
			data |= LCK_RW_WANT_UPGRADE;		/* ask for WANT_UPGRADE */
			data -= LCK_RW_SHARED_READER;		/* and shed our read count */
			if (atomic_exchange_complete32(&lock->data, prev, data, memory_order_acquire_smp))
				break;
		}
		cpu_pause();
	}
						/* we now own the WANT_UPGRADE */
	if (data & LCK_RW_SHARED_MASK) 		/* check to see if all of the readers are drained */
		lck_rw_lock_shared_to_exclusive_success(lock);	/* if not, we need to go wait */
#if	CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lock, 0);
#endif
	return TRUE;
}


/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_failure
 *	Function:
 *		assembly fast path code has already dropped our read
 *		count and determined that someone else owns 'lck_rw_want_upgrade'
 *		if 'lck_rw_shared_count' == 0, its also already dropped 'lck_w_waiting'
 *		all we need to do here is determine if a wakeup is needed
 */
static boolean_t
lck_rw_lock_shared_to_exclusive_failure(
	lck_rw_t	*lck,
	uint32_t	prior_lock_state)
{
	lck_rw_t	*fake_lck;
	thread_t	thread = current_thread();
	uint32_t	rwlock_count;

	/* Check if dropping the lock means that we need to unpromote */
	rwlock_count = thread->rwlock_count--;
#if MACH_LDEBUG
	if (rwlock_count == 0) {
		panic("rw lock count underflow for thread %p", thread);
	}
#endif
	fake_lck = (lck_rw_t *)&prior_lock_state;

	if (fake_lck->lck_w_waiting && fake_lck->lck_rw_shared_count == 1) {
		/*
		 *	Someone else has requested upgrade.
		 *	Since we've released the read lock, wake
		 *	him up if he's blocked waiting
		 */
		thread_wakeup(RW_LOCK_WRITER_EVENT(lck));
	}

	if ((rwlock_count == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		/* sched_flags checked without lock, but will be rechecked while clearing */
		lck_rw_clear_promotion(thread, unslide_for_kdebug(lck));
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_NONE,
		     VM_KERNEL_UNSLIDE_OR_PERM(lck), lck->lck_rw_shared_count, lck->lck_rw_want_upgrade, 0, 0);

	return (FALSE);
}


/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_failure
 *	Function:
 *		assembly fast path code has already dropped our read
 *		count and successfully acquired 'lck_rw_want_upgrade'
 *		we just need to wait for the rest of the readers to drain
 *		and then we can return as the exclusive holder of this lock
 */
static boolean_t
lck_rw_lock_shared_to_exclusive_success(
	lck_rw_t	*lck)
{
	__kdebug_only uintptr_t	trace_lck = unslide_for_kdebug(lck);
	uint64_t	deadline = 0;
	int		slept = 0;
	int		still_shared = 0;
	wait_result_t	res;
	boolean_t	istate = -1;

#if	CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_shared_to_excl_spin, dtrace_rwl_shared_to_excl_block, dtrace_ls_enabled = FALSE;
#endif

	while (lck->lck_rw_shared_count != 0) {

#if	CONFIG_DTRACE
		if (dtrace_ls_initialized == FALSE) {
			dtrace_ls_initialized = TRUE;
			dtrace_rwl_shared_to_excl_spin = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN] != 0);
			dtrace_rwl_shared_to_excl_block = (lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK] != 0);
			dtrace_ls_enabled = dtrace_rwl_shared_to_excl_spin || dtrace_rwl_shared_to_excl_block;
			if (dtrace_ls_enabled) {
				/*
				 * Either sleeping or spinning is happening,
				 *  start a timing of our delay interval now.
				 */
				readers_at_sleep = lck->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif
		if (istate == -1)
			istate = ml_get_interrupts_enabled();

		deadline = lck_rw_deadline_for_spin(lck);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_SPIN_CODE) | DBG_FUNC_START,
			     trace_lck, lck->lck_rw_shared_count, 0, 0, 0);

		while ((still_shared = lck->lck_rw_shared_count) && mach_absolute_time() < deadline)
			lck_rw_lock_pause(istate);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_SPIN_CODE) | DBG_FUNC_END,
			     trace_lck, lck->lck_rw_shared_count, 0, 0, 0);

		if ( !still_shared)
			break;
		/*
		 * if we get here, the deadline has expired w/o
		 * the rw_shared_count having drained to 0
		 * check to see if we're allowed to do a thread_block
		 */
		if (lck->lck_rw_can_sleep) {

			istate = lck_interlock_lock(lck);

			if (lck->lck_rw_shared_count != 0) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_WAIT_CODE) | DBG_FUNC_START,
					     trace_lck, lck->lck_rw_shared_count, 0, 0, 0);

				lck->lck_w_waiting = TRUE;

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockUpgrade);
				res = assert_wait(RW_LOCK_WRITER_EVENT(lck),
						THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lck, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_WAIT_CODE) | DBG_FUNC_END,
					     trace_lck, res, slept, 0, 0);
			} else {
				lck_interlock_unlock(lck, istate);
				break;
			}
		}
	}
#if	CONFIG_DTRACE
	/*
	 * We infer whether we took the sleep/spin path above by checking readers_at_sleep.
	 */
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN, lck, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lck, 1);
#endif
	return (TRUE);
}

/*
 *	Routine:	lck_rw_lock_exclusive_to_shared
 */

void lck_rw_lock_exclusive_to_shared(lck_rw_t *lock)
{
	uint32_t	data, prev;

	for ( ; ; ) {
		data = atomic_exchange_begin32(&lock->data, &prev, memory_order_release_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);	/* wait for interlock to clear */
			continue;
		}
		data += LCK_RW_SHARED_READER;
		if (data & LCK_RW_WANT_UPGRADE)
			data &= ~(LCK_RW_WANT_UPGRADE);
		else
			data &= ~(LCK_RW_WANT_EXCL);
		if (!((prev & LCK_RW_W_WAITING) && (prev & LCK_RW_PRIV_EXCL)))
			data &= ~(LCK_RW_W_WAITING);
		if (atomic_exchange_complete32(&lock->data, prev, data, memory_order_release_smp))
			break;
		cpu_pause();
	}
	return lck_rw_lock_exclusive_to_shared_gen(lock, prev);
}


/*
 *      Routine:        lck_rw_lock_exclusive_to_shared_gen
 * 	Function:
 *		assembly fast path has already dropped
 *		our exclusive state and bumped lck_rw_shared_count
 *		all we need to do here is determine if anyone
 *		needs to be awakened.
 */
static void
lck_rw_lock_exclusive_to_shared_gen(
	lck_rw_t	*lck,
	uint32_t	prior_lock_state)
{
	__kdebug_only uintptr_t	trace_lck = unslide_for_kdebug(lck);
	lck_rw_t		*fake_lck;

	fake_lck = (lck_rw_t *)&prior_lock_state;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_START,
			     trace_lck, fake_lck->lck_rw_want_write, fake_lck->lck_rw_want_upgrade, 0, 0);

	/*
	 * don't wake up anyone waiting to take the lock exclusively
	 * since we hold a read count... when the read count drops to 0,
	 * the writers will be woken.
	 *
	 * wake up any waiting readers if we don't have any writers waiting,
	 * or the lock is NOT marked as rw_priv_excl (writers have privilege)
	 */
	if (!(fake_lck->lck_rw_priv_excl && fake_lck->lck_w_waiting) && fake_lck->lck_r_waiting)
		thread_wakeup(RW_LOCK_READER_EVENT(lck));

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_END,
			     trace_lck, lck->lck_rw_want_write, lck->lck_rw_want_upgrade, lck->lck_rw_shared_count, 0);

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, lck, 0);
#endif
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
 *	Routine:	lck_rw_try_lock_shared
 */

boolean_t lck_rw_try_lock_shared(lck_rw_t *lock)
{
	uint32_t	data, prev;

	for ( ; ; ) {
		data = atomic_exchange_begin32(&lock->data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) {
			atomic_exchange_abort();
			return FALSE;			/* lock is busy */
		}
		data += LCK_RW_SHARED_READER;		/* Increment reader refcount */
		if (atomic_exchange_complete32(&lock->data, prev, data, memory_order_acquire_smp))
			break;
		cpu_pause();
	}
	current_thread()->rwlock_count++;
	/* There is a 3 instr window where preemption may not notice rwlock_count after cmpxchg */
#if	CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, lock, DTRACE_RW_SHARED);
#endif	/* CONFIG_DTRACE */
	return TRUE;
}


/*
 *	Routine:	lck_rw_try_lock_exclusive
 */

boolean_t lck_rw_try_lock_exclusive(lck_rw_t *lock)
{
	uint32_t	data, prev;

	for ( ; ; ) {
		data = atomic_exchange_begin32(&lock->data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & (LCK_RW_SHARED_MASK | LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) {
			atomic_exchange_abort();
			return FALSE;				/* can't get it */
		}
		data |= LCK_RW_WANT_EXCL;
		if (atomic_exchange_complete32(&lock->data, prev, data, memory_order_acquire_smp))
			break;
		cpu_pause();
	}

	current_thread()->rwlock_count++;
#if	CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif	/* CONFIG_DTRACE */
	return TRUE;
}


void
lck_rw_assert(
	lck_rw_t	*lck,
	unsigned int	type)
{
	switch (type) {
	case LCK_RW_ASSERT_SHARED:
		if (lck->lck_rw_shared_count != 0) {
			return;
		}
		break;
	case LCK_RW_ASSERT_EXCLUSIVE:
		if ((lck->lck_rw_want_write ||
		     lck->lck_rw_want_upgrade) &&
		    lck->lck_rw_shared_count == 0) {
			return;
		}
		break;
	case LCK_RW_ASSERT_HELD:
		if (lck->lck_rw_want_write ||
		    lck->lck_rw_want_upgrade ||
		    lck->lck_rw_shared_count != 0) {
			return;
		}
		break;
	case LCK_RW_ASSERT_NOTHELD:
		if (!(lck->lck_rw_want_write ||
			  lck->lck_rw_want_upgrade ||
			  lck->lck_rw_shared_count != 0)) {
			return;
		}
		break;
	default:
		break;
	}

	panic("rw lock (%p)%s held (mode=%u), first word %08x\n", lck, (type == LCK_RW_ASSERT_NOTHELD ? "" : " not"), type, *(uint32_t *)lck);
}

/* On return to userspace, this routine is called if the rwlock_count is somehow imbalanced */
#if MACH_LDEBUG
__dead2
#endif
void
lck_rw_clear_promotions_x86(thread_t thread)
{
#if MACH_LDEBUG
	/* It's fatal to leave a RW lock locked and return to userspace */
	panic("%u rw lock(s) held on return to userspace for thread %p", thread->rwlock_count, thread);
#else
	/* Paper over the issue */
	thread->rwlock_count = 0;
	lck_rw_clear_promotion(thread, 0);
#endif
}

boolean_t
lck_rw_lock_yield_shared(lck_rw_t *lck, boolean_t force_yield)
{
	lck_rw_assert(lck, LCK_RW_ASSERT_SHARED);

	if (lck->lck_rw_want_write || lck->lck_rw_want_upgrade || force_yield) {
		lck_rw_unlock_shared(lck);
		mutex_pause(2);
		lck_rw_lock_shared(lck);
		return TRUE;
	}

	return FALSE;
}

/*
 * Routine: kdp_lck_rw_lock_is_acquired_exclusive
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 */
boolean_t
kdp_lck_rw_lock_is_acquired_exclusive(lck_rw_t *lck) {
	if (not_in_kdp) {
		panic("panic: rw lock exclusive check done outside of kernel debugger");
	}
	return ((lck->lck_rw_want_upgrade || lck->lck_rw_want_write) && (lck->lck_rw_shared_count == 0)) ? TRUE : FALSE;
}

/*
 * Slow path routines for lck_mtx locking and unlocking functions.
 *
 * These functions were previously implemented in x86 assembly,
 * and some optimizations are in place in this c code to obtain a compiled code
 * as performant and compact as the assembly version.
 *
 * To avoid to inline these functions on the fast path, all functions directly called by
 * the fast paths have the __attribute__((noinline)) specified. Also they are all implemented
 * in such a way the fast path can tail call into them. In this way the return address
 * does not need to be pushed on the caller stack and stack optimization can happen on the caller.
 *
 * Slow path code is structured in such a way there are no calls to functions that will return
 * on the context of the caller function, i.e. all functions called are or tail call functions
 * or inline functions. The number of arguments of the tail call functions are less then six,
 * so that they can be passed over registers and do not need to be pushed on stack.
 * This allows the compiler to not create a stack frame for the functions.
 *
 * __improbable and __probable are used to compile the slow path code in such a way
 * the fast path case will be on a sequence of instructions with as less jumps as possible,
 * to make this case the most optimized even if falling through the slow path.
 */

/*
 * Intel lock invariants:
 *
 * lck_mtx_waiters: contains the count of threads currently in the mutex waitqueue
 *
 * The lock owner is promoted to the max priority of all its waiters only if it
 * was a lower priority when it acquired or was an owner when a waiter waited.
 * Max priority is capped at MAXPRI_PROMOTE.
 *
 * The last waiter will not be promoted as it is woken up, but the last
 * lock owner may not have been the last thread to have been woken up depending on the
 * luck of the draw.  Therefore a last-owner may still have the promoted-on-wakeup
 * flag set.
 *
 * TODO: Figure out an algorithm for stopping a lock holder which is already at the right
 *       priority from dropping priority in the future without having to take thread lock
 *       on acquire.
 */

#ifdef	MUTEX_ZONE
extern zone_t lck_mtx_zone;
#endif

/*
 *      Routine:        lck_mtx_alloc_init
 */
lck_mtx_t *
lck_mtx_alloc_init(
	lck_grp_t	*grp,
	lck_attr_t	*attr)
{
	lck_mtx_t	*lck;
#ifdef	MUTEX_ZONE
	if ((lck = (lck_mtx_t *)zalloc(lck_mtx_zone)) != 0)
		lck_mtx_init(lck, grp, attr);
#else
	if ((lck = (lck_mtx_t *)kalloc(sizeof(lck_mtx_t))) != 0)
		lck_mtx_init(lck, grp, attr);
#endif
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
#ifdef	MUTEX_ZONE
	zfree(lck_mtx_zone, lck);
#else
	kfree(lck, sizeof(lck_mtx_t));
#endif
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
	bzero((void *)lck, sizeof(lck_mtx_ext_t));

	if ((attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck->lck_mtx_deb.type = MUTEX_TAG;
		lck->lck_mtx_attr |= LCK_MTX_ATTR_DEBUG;
	}

	lck->lck_mtx_grp = grp;

	if (grp->lck_grp_attr & LCK_GRP_ATTR_STAT)
		lck->lck_mtx_attr |= LCK_MTX_ATTR_STAT;

	lck->lck_mtx.lck_mtx_is_ext = 1;
	lck->lck_mtx.lck_mtx_pad32 = 0xFFFFFFFF;
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
	lck_attr_t	*lck_attr;

	if (attr != LCK_ATTR_NULL)
		lck_attr = attr;
	else
		lck_attr = &LockDefaultLckAttr;

	if ((lck_attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		if ((lck_ext = (lck_mtx_ext_t *)kalloc(sizeof(lck_mtx_ext_t))) != 0) {
			lck_mtx_ext_init(lck_ext, grp, lck_attr);
			lck->lck_mtx_tag = LCK_MTX_TAG_INDIRECT;
			lck->lck_mtx_ptr = lck_ext;
		}
	} else {
		lck->lck_mtx_owner = 0;
		lck->lck_mtx_state = 0;
	}
	lck->lck_mtx_pad32 = 0xFFFFFFFF;
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_MTX);
}

/*
 *      Routine:        lck_mtx_init_ext
 */
void
lck_mtx_init_ext(
	lck_mtx_t	*lck,
	lck_mtx_ext_t	*lck_ext,
	lck_grp_t	*grp,
	lck_attr_t	*attr)
{
	lck_attr_t	*lck_attr;

	if (attr != LCK_ATTR_NULL)
		lck_attr = attr;
	else
		lck_attr = &LockDefaultLckAttr;

	if ((lck_attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck_mtx_ext_init(lck_ext, grp, lck_attr);
		lck->lck_mtx_tag = LCK_MTX_TAG_INDIRECT;
		lck->lck_mtx_ptr = lck_ext;
	} else {
		lck->lck_mtx_owner = 0;
		lck->lck_mtx_state = 0;
	}
	lck->lck_mtx_pad32 = 0xFFFFFFFF;

	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_MTX);
}

static void
lck_mtx_lock_mark_destroyed(
	lck_mtx_t *mutex,
	boolean_t indirect)
{
	uint32_t state;

	if (indirect) {
		/* convert to destroyed state */
		ordered_store_mtx_state_release(mutex, LCK_MTX_TAG_DESTROYED);
		return;
	}

	state = ordered_load_mtx_state(mutex);
	lck_mtx_interlock_lock(mutex, &state);

	ordered_store_mtx_state_release(mutex, LCK_MTX_TAG_DESTROYED);

	enable_preemption();
}

/*
 *      Routine:        lck_mtx_destroy
 */
void
lck_mtx_destroy(
	lck_mtx_t	*lck,
	lck_grp_t	*grp)
{
	boolean_t indirect;

	if (lck->lck_mtx_tag == LCK_MTX_TAG_DESTROYED)
		return;
#if MACH_LDEBUG
	lck_mtx_assert(lck, LCK_MTX_ASSERT_NOTOWNED);
#endif
	indirect = (lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT);

	lck_mtx_lock_mark_destroyed(lck, indirect);

	if (indirect)
		kfree(lck->lck_mtx_ptr, sizeof(lck_mtx_ext_t));
	lck_grp_lckcnt_decr(grp, LCK_TYPE_MTX);
	lck_grp_deallocate(grp);
	return;
}


#if DEVELOPMENT | DEBUG
__attribute__((noinline))
void
lck_mtx_owner_check_panic(
	lck_mtx_t       *lock)
{
	thread_t owner = (thread_t)lock->lck_mtx_owner;
	panic("Mutex unlock attempted from non-owner thread. Owner=%p lock=%p", owner, lock);
}
#endif

__attribute__((always_inline))
static boolean_t
get_indirect_mutex(
	lck_mtx_t       **lock,
	uint32_t	*state)
{
	*lock = &((*lock)->lck_mtx_ptr->lck_mtx);
	*state = ordered_load_mtx_state(*lock);
	return TRUE;
}

/*
 * Routine: 	lck_mtx_unlock_slow
 *
 * Unlocks a mutex held by current thread.
 *
 * It will wake up waiters if necessary.
 *
 * Interlock can be held.
 */
__attribute__((noinline))
void
lck_mtx_unlock_slow(
	lck_mtx_t	*lock)
{
	thread_t	thread;
	uint32_t	state, prev;
	boolean_t	indirect = FALSE;

	state = ordered_load_mtx_state(lock);

	/* Is this an indirect mutex? */
	if (__improbable(state == LCK_MTX_TAG_INDIRECT)) {
		indirect = get_indirect_mutex(&lock, &state);
	}

	thread = current_thread();

#if DEVELOPMENT | DEBUG
	thread_t owner = (thread_t)lock->lck_mtx_owner;
	if(__improbable(owner != thread))
		lck_mtx_owner_check_panic(lock);
#endif

	/* check if it is held as a spinlock */
	if (__improbable((state & LCK_MTX_MLOCKED_MSK) == 0))
		goto unlock;

	lck_mtx_interlock_lock_clear_flags(lock, LCK_MTX_MLOCKED_MSK, &state);

unlock:
	/* preemption disabled, interlock held and mutex not held */

	/* clear owner */
	ordered_store_mtx_owner(lock, 0);
	/* keep original state in prev for later evaluation */
	prev = state;

	if (__improbable(state & LCK_MTX_WAITERS_MSK)) {
#if     MACH_LDEBUG
		if (thread)
			thread->mutex_count--;
#endif
		return lck_mtx_unlock_wakeup_tail(lock, state, indirect);
	}

	/* release interlock, promotion and clear spin flag */
	state &= (~(LCK_MTX_ILOCKED_MSK | LCK_MTX_SPIN_MSK));
	ordered_store_mtx_state_release(lock, state);		/* since I own the interlock, I don't need an atomic update */

#if	MACH_LDEBUG
	/* perform lock statistics after drop to prevent delay */
	if (thread)
		thread->mutex_count--;		/* lock statistic */
#endif	/* MACH_LDEBUG */

	/* re-enable preemption */
	lck_mtx_unlock_finish_inline(lock, FALSE);

	return;
}

#define	LCK_MTX_LCK_WAIT_CODE		0x20
#define	LCK_MTX_LCK_WAKEUP_CODE		0x21
#define	LCK_MTX_LCK_SPIN_CODE		0x22
#define	LCK_MTX_LCK_ACQUIRE_CODE	0x23
#define LCK_MTX_LCK_DEMOTE_CODE		0x24

/*
 * Routine:    lck_mtx_unlock_wakeup_tail
 *
 * Invoked on unlock when there is
 * contention, i.e. the assembly routine sees
 * that mutex->lck_mtx_waiters != 0
 *
 * neither the mutex or interlock is held
 *
 * Note that this routine might not be called if there are pending
 * waiters which have previously been woken up, and they didn't
 * end up boosting the old owner.
 *
 * assembly routine previously did the following to mutex:
 * (after saving the state in prior_lock_state)
 *      decremented lck_mtx_waiters if nonzero
 *
 * This function needs to be called as a tail call
 * to optimize the compiled code.
 */
__attribute__((noinline))
static void
lck_mtx_unlock_wakeup_tail (
	lck_mtx_t	*mutex,
	uint32_t        state,
	boolean_t	indirect)
{
	struct turnstile *ts;

	__kdebug_only uintptr_t	trace_lck = unslide_for_kdebug(mutex);
	kern_return_t did_wake;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAKEUP_CODE) | DBG_FUNC_START,
		trace_lck, 0, mutex->lck_mtx_waiters, 0, 0);

	ts = turnstile_prepare((uintptr_t)mutex, NULL, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);

	if (mutex->lck_mtx_waiters > 1) {
		/* WAITQ_PROMOTE_ON_WAKE will call turnstile_update_inheritor on the wokenup thread */
		did_wake = waitq_wakeup64_one(&ts->ts_waitq, CAST_EVENT64_T(LCK_MTX_EVENT(mutex)), THREAD_AWAKENED, WAITQ_PROMOTE_ON_WAKE);
	} else {
		did_wake = waitq_wakeup64_one(&ts->ts_waitq, CAST_EVENT64_T(LCK_MTX_EVENT(mutex)), THREAD_AWAKENED, WAITQ_ALL_PRIORITIES);
		turnstile_update_inheritor(ts, NULL, TURNSTILE_IMMEDIATE_UPDATE);
	}
	assert(did_wake == KERN_SUCCESS);

	turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	turnstile_complete((uintptr_t)mutex, NULL, NULL, TURNSTILE_KERNEL_MUTEX);

	state -= LCK_MTX_WAITER;
        state &= (~(LCK_MTX_SPIN_MSK | LCK_MTX_ILOCKED_MSK));
	ordered_store_mtx_state_release(mutex, state);

	assert(current_thread()->turnstile != NULL);

	turnstile_cleanup();

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAKEUP_CODE) | DBG_FUNC_END,
                 trace_lck, 0, mutex->lck_mtx_waiters, 0, 0);

	lck_mtx_unlock_finish_inline(mutex, indirect);
}

/*
 * Routine: 	lck_mtx_lock_acquire_x86
 *
 * Invoked on acquiring the mutex when there is
 * contention (i.e. the assembly routine sees that
 * that mutex->lck_mtx_waiters != 0
 *
 * mutex is owned...  interlock is held... preemption is disabled
 */
__attribute__((always_inline))
static void
lck_mtx_lock_acquire_inline(
	lck_mtx_t	*mutex,
	struct turnstile *ts)
{
	__kdebug_only uintptr_t	trace_lck = unslide_for_kdebug(mutex);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_ACQUIRE_CODE) | DBG_FUNC_START,
		     trace_lck, 0, mutex->lck_mtx_waiters, 0, 0);

	thread_t thread = (thread_t)mutex->lck_mtx_owner;       /* faster than current_thread() */
	assert(thread->waiting_for_mutex == NULL);

	if (mutex->lck_mtx_waiters > 0) {
		if (ts == NULL) {
			ts = turnstile_prepare((uintptr_t)mutex, NULL, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);
		}

		turnstile_update_inheritor(ts, thread, (TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_THREAD));
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);
	}

	if (ts != NULL) {
		turnstile_complete((uintptr_t)mutex, NULL, NULL, TURNSTILE_KERNEL_MUTEX);
	}

	assert(current_thread()->turnstile != NULL);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_ACQUIRE_CODE) | DBG_FUNC_END,
		     trace_lck, 0, mutex->lck_mtx_waiters, 0, 0);
}

void
lck_mtx_lock_acquire_x86(
	lck_mtx_t	*mutex)
{
	return lck_mtx_lock_acquire_inline(mutex, NULL);
}

/*
 * Tail call helpers for lock functions that perform
 * lck_mtx_lock_acquire followed by the caller's finish routine, to optimize
 * the caller's compiled code.
 */

__attribute__((noinline))
static void
lck_mtx_lock_acquire_tail(
	lck_mtx_t	*mutex,
	boolean_t	indirect,
	struct turnstile *ts)
{
	lck_mtx_lock_acquire_inline(mutex, ts);
	lck_mtx_lock_finish_inline_with_cleanup(mutex, ordered_load_mtx_state(mutex), indirect);
}

__attribute__((noinline))
static boolean_t
lck_mtx_try_lock_acquire_tail(
	lck_mtx_t	*mutex)
{
	lck_mtx_lock_acquire_inline(mutex, NULL);
	lck_mtx_try_lock_finish_inline(mutex, ordered_load_mtx_state(mutex));

	return TRUE;
}

__attribute__((noinline))
static void
lck_mtx_convert_spin_acquire_tail(
	lck_mtx_t	*mutex)
{
	lck_mtx_lock_acquire_inline(mutex, NULL);
	lck_mtx_convert_spin_finish_inline(mutex, ordered_load_mtx_state(mutex));
}

boolean_t
lck_mtx_ilk_unlock(
	lck_mtx_t       *mutex)
{
	lck_mtx_ilk_unlock_inline(mutex, ordered_load_mtx_state(mutex));
	return TRUE;
}

static inline void
lck_mtx_interlock_lock_set_and_clear_flags(
	lck_mtx_t *mutex,
	uint32_t xor_flags,
	uint32_t and_flags,
	uint32_t *new_state)
{
	uint32_t state, prev;
	state = *new_state;

	for ( ; ; ) {
		/* have to wait for interlock to clear */
		while (__improbable(state & (LCK_MTX_ILOCKED_MSK | xor_flags))) {
			cpu_pause();
			state = ordered_load_mtx_state(mutex);
		}
		prev = state;                                   /* prev contains snapshot for exchange */
		state |= LCK_MTX_ILOCKED_MSK | xor_flags;       /* pick up interlock */
		state &= ~and_flags;                    	/* clear flags */

		disable_preemption();
		if (os_atomic_cmpxchg(&mutex->lck_mtx_state, prev, state, acquire))
			break;
		enable_preemption();
		cpu_pause();
		state = ordered_load_mtx_state(mutex);
	}
	*new_state = state;
	return;
}

static inline void
lck_mtx_interlock_lock_clear_flags(
	lck_mtx_t *mutex,
	uint32_t and_flags,
	uint32_t *new_state)
{
	return lck_mtx_interlock_lock_set_and_clear_flags(mutex, 0, and_flags, new_state);
}

static inline void
lck_mtx_interlock_lock(
	lck_mtx_t *mutex,
	uint32_t *new_state)
{
	return lck_mtx_interlock_lock_set_and_clear_flags(mutex, 0, 0, new_state);
}

static inline int
lck_mtx_interlock_try_lock_set_flags(
	lck_mtx_t *mutex,
	uint32_t or_flags,
	uint32_t *new_state)
{
	uint32_t state, prev;
	state = *new_state;

	/* have to wait for interlock to clear */
	if (state & (LCK_MTX_ILOCKED_MSK | or_flags)) {
		return 0;
	}
	prev = state;					/* prev contains snapshot for exchange */
	state |= LCK_MTX_ILOCKED_MSK | or_flags;	/* pick up interlock */
	disable_preemption();
	if (os_atomic_cmpxchg(&mutex->lck_mtx_state, prev, state, acquire)) {
			*new_state = state;
			return 1;
	}

	enable_preemption();
	return 0;
}

static inline int
lck_mtx_interlock_try_lock(
	lck_mtx_t *mutex,
	uint32_t *new_state)
{
	return lck_mtx_interlock_try_lock_set_flags(mutex, 0, new_state);
}

static inline int
lck_mtx_interlock_try_lock_disable_interrupts(
	lck_mtx_t *mutex,
	boolean_t *istate)
{
	uint32_t	state;

	*istate = ml_set_interrupts_enabled(FALSE);
	state = ordered_load_mtx_state(mutex);

	if (lck_mtx_interlock_try_lock(mutex, &state)) {
		return 1;
	} else {
		ml_set_interrupts_enabled(*istate);
		return 0;
	}
}

static inline void
lck_mtx_interlock_unlock_enable_interrupts(
	lck_mtx_t *mutex,
	boolean_t istate)
{
	lck_mtx_ilk_unlock(mutex);
	ml_set_interrupts_enabled(istate);
}

__attribute__((noinline))
static void
lck_mtx_lock_contended(
	lck_mtx_t       *lock,
	boolean_t indirect,
	boolean_t *first_miss)
{
	lck_mtx_spinwait_ret_type_t ret;
	uint32_t state;
	thread_t thread;
	struct turnstile *ts = NULL;

try_again:

	if (indirect) {
		lck_grp_mtx_update_miss((struct _lck_mtx_ext_*)lock, first_miss);
	}

	ret = lck_mtx_lock_spinwait_x86(lock);
	state = ordered_load_mtx_state(lock);
	switch (ret) {
	case LCK_MTX_SPINWAIT_NO_SPIN:
		/*
		 * owner not on core, lck_mtx_lock_spinwait_x86 didn't even
		 * try to spin.
		 */
		if (indirect) {
			lck_grp_mtx_update_direct_wait((struct _lck_mtx_ext_*)lock);
		}

		/* just fall through case LCK_MTX_SPINWAIT_SPUN */
	case LCK_MTX_SPINWAIT_SPUN:
		/*
		 * mutex not acquired but lck_mtx_lock_spinwait_x86 tried to spin
		 * interlock not held
		 */
		lck_mtx_interlock_lock(lock, &state);
		assert(state & LCK_MTX_ILOCKED_MSK);

		if (state & LCK_MTX_MLOCKED_MSK) {
			if (indirect) {
				lck_grp_mtx_update_wait((struct _lck_mtx_ext_*)lock, first_miss);
			}
			lck_mtx_lock_wait_x86(lock, &ts);
			/*
			 * interlock is not held here.
			 */
			goto try_again;
		} else {

			/* grab the mutex */
			state |= LCK_MTX_MLOCKED_MSK;
			ordered_store_mtx_state_release(lock, state);
			thread = current_thread();
			ordered_store_mtx_owner(lock, (uintptr_t)thread);
#if     MACH_LDEBUG
			if (thread) {
				thread->mutex_count++;
			}
#endif  /* MACH_LDEBUG */
		}

		break;
	case LCK_MTX_SPINWAIT_ACQUIRED:
		/*
		 * mutex has been acquired by lck_mtx_lock_spinwait_x86
		 * interlock is held and preemption disabled
		 * owner is set and mutex marked as locked
		 * statistics updated too
		 */
		break;
	default:
		panic("lck_mtx_lock_spinwait_x86 returned %d for mutex %p\n", ret, lock);
	}

	/*
	 * interlock is already acquired here
	 */

	/* mutex has been acquired */
	thread = (thread_t)lock->lck_mtx_owner;
	if (state & LCK_MTX_WAITERS_MSK) {
		/*
		 * lck_mtx_lock_acquire_tail will call
		 * turnstile_complete.
		 */
		return lck_mtx_lock_acquire_tail(lock, indirect, ts);
	}

	if (ts != NULL) {
		turnstile_complete((uintptr_t)lock, NULL, NULL, TURNSTILE_KERNEL_MUTEX);
	}

	assert(current_thread()->turnstile != NULL);

	/* release the interlock */
	lck_mtx_lock_finish_inline_with_cleanup(lock, ordered_load_mtx_state(lock), indirect);
}

/*
 * Helper noinline functions for calling
 * panic to optimize compiled code.
 */

__attribute__((noinline)) __abortlike
static void
lck_mtx_destroyed(
	lck_mtx_t       *lock)
{
	panic("trying to interlock destroyed mutex (%p)", lock);
}

__attribute__((noinline))
static boolean_t
lck_mtx_try_destroyed(
	lck_mtx_t       *lock)
{
	panic("trying to interlock destroyed mutex (%p)", lock);
	return FALSE;
}

__attribute__((always_inline))
static boolean_t
lck_mtx_lock_wait_interlock_to_clear(
	lck_mtx_t       *lock,
	uint32_t*        new_state)
{
	uint32_t state;

	for ( ; ; ) {
		cpu_pause();
		state = ordered_load_mtx_state(lock);
		if (!(state & (LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK))) {
			*new_state = state;
			return TRUE;
		}
		if (state & LCK_MTX_MLOCKED_MSK) {
			/* if it is held as mutex, just fail */
			return FALSE;
		}
	}
}

__attribute__((always_inline))
static boolean_t
lck_mtx_try_lock_wait_interlock_to_clear(
	lck_mtx_t       *lock,
	uint32_t*        new_state)
{
	uint32_t state;

	for ( ; ; ) {
		cpu_pause();
		state = ordered_load_mtx_state(lock);
		if (state & (LCK_MTX_MLOCKED_MSK | LCK_MTX_SPIN_MSK)) {
			/* if it is held as mutex or spin, just fail */
			return FALSE;
		}
		if (!(state & LCK_MTX_ILOCKED_MSK)) {
			*new_state = state;
			return TRUE;
		}
	}
}

/*
 * Routine:	lck_mtx_lock_slow
 *
 * Locks a mutex for current thread.
 * If the lock is contended this function might
 * sleep.
 *
 * Called with interlock not held.
 */
__attribute__((noinline))
void
lck_mtx_lock_slow(
	lck_mtx_t       *lock)
{
	boolean_t	indirect = FALSE;
	uint32_t	state;
	int		first_miss = 0;

	state = ordered_load_mtx_state(lock);

	/* is the interlock or mutex held */
	if (__improbable(state & ((LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK)))) {
		/*
		 * Note: both LCK_MTX_TAG_DESTROYED and LCK_MTX_TAG_INDIRECT
		 * have LCK_MTX_ILOCKED_MSK and LCK_MTX_MLOCKED_MSK
		 * set in state (state == lck_mtx_tag)
		 */


		/* is the mutex already held and not indirect */
		if (__improbable(!(state & LCK_MTX_ILOCKED_MSK))){
			/* no, must have been the mutex */
			return lck_mtx_lock_contended(lock, indirect, &first_miss);
		}

		/* check to see if it is marked destroyed */
		if (__improbable(state == LCK_MTX_TAG_DESTROYED)) {
			lck_mtx_destroyed(lock);
		}

		/* Is this an indirect mutex? */
		if (__improbable(state == LCK_MTX_TAG_INDIRECT)) {
			indirect = get_indirect_mutex(&lock, &state);

			first_miss = 0;
			lck_grp_mtx_update_held((struct _lck_mtx_ext_*)lock);

			if (state & LCK_MTX_SPIN_MSK) {
				 /* M_SPIN_MSK was set, so M_ILOCKED_MSK must also be present */
				assert(state & LCK_MTX_ILOCKED_MSK);
				lck_grp_mtx_update_miss((struct _lck_mtx_ext_*)lock, &first_miss);
			}
		}

		if (!lck_mtx_lock_wait_interlock_to_clear(lock, &state)) {
			return lck_mtx_lock_contended(lock, indirect, &first_miss);
		}
	}

	/* no - can't be INDIRECT, DESTROYED or locked */
	while (__improbable(!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_MLOCKED_MSK, &state))) {
		if (!lck_mtx_lock_wait_interlock_to_clear(lock, &state)) {
			return lck_mtx_lock_contended(lock, indirect, &first_miss);
		}
	}

	/* lock and interlock acquired */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;		/* lock statistic */
	}
#endif
	/*
	 * Check if there are waiters to
	 * inherit their priority.
	 */
	if (__improbable(state & LCK_MTX_WAITERS_MSK)) {
		return lck_mtx_lock_acquire_tail(lock, indirect, NULL);
	}

	/* release the interlock */
	lck_mtx_lock_finish_inline(lock, ordered_load_mtx_state(lock), indirect);

	return;
}

__attribute__((noinline))
boolean_t
lck_mtx_try_lock_slow(
	lck_mtx_t       *lock)
{
	boolean_t       indirect = FALSE;
	uint32_t        state;
	int             first_miss = 0;

	state = ordered_load_mtx_state(lock);

	/* is the interlock or mutex held */
	if (__improbable(state & ((LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK)))) {
		/*
		 * Note: both LCK_MTX_TAG_DESTROYED and LCK_MTX_TAG_INDIRECT
		 * have LCK_MTX_ILOCKED_MSK and LCK_MTX_MLOCKED_MSK
		 * set in state (state == lck_mtx_tag)
		 */

		/* is the mutex already held and not indirect */
		if (__improbable(!(state & LCK_MTX_ILOCKED_MSK))){
			return FALSE;
		}

		/* check to see if it is marked destroyed */
		if (__improbable(state == LCK_MTX_TAG_DESTROYED)) {
			lck_mtx_try_destroyed(lock);
		}

		/* Is this an indirect mutex? */
		if (__improbable(state == LCK_MTX_TAG_INDIRECT)) {
			indirect = get_indirect_mutex(&lock, &state);

			first_miss = 0;
			lck_grp_mtx_update_held((struct _lck_mtx_ext_*)lock);
		}

		if (!lck_mtx_try_lock_wait_interlock_to_clear(lock, &state)) {
			if (indirect)
				lck_grp_mtx_update_miss((struct _lck_mtx_ext_*)lock, &first_miss);
			return FALSE;
		}
	}

	/* no - can't be INDIRECT, DESTROYED or locked */
	while (__improbable(!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_MLOCKED_MSK, &state))) {
		if (!lck_mtx_try_lock_wait_interlock_to_clear(lock, &state)) {
			if (indirect)
				lck_grp_mtx_update_miss((struct _lck_mtx_ext_*)lock, &first_miss);
			return FALSE;
		}
	}

	/* lock and interlock acquired */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;		/* lock statistic */
	}
#endif
	/*
	 * Check if there are waiters to
	 * inherit their priority.
	 */
	if (__improbable(state & LCK_MTX_WAITERS_MSK)) {
		return lck_mtx_try_lock_acquire_tail(lock);
	}

	/* release the interlock */
	lck_mtx_try_lock_finish_inline(lock, ordered_load_mtx_state(lock));

	return TRUE;

}

__attribute__((noinline))
void
lck_mtx_lock_spin_slow(
	lck_mtx_t	*lock)
{
	boolean_t       indirect = FALSE;
	uint32_t        state;
	int             first_miss = 0;

	state = ordered_load_mtx_state(lock);

	/* is the interlock or mutex held */
	if (__improbable(state & ((LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK)))) {
		/*
		 * Note: both LCK_MTX_TAG_DESTROYED and LCK_MTX_TAG_INDIRECT
		 * have LCK_MTX_ILOCKED_MSK and LCK_MTX_MLOCKED_MSK
		 * set in state (state == lck_mtx_tag)
		 */


		/* is the mutex already held and not indirect */
		if (__improbable(!(state & LCK_MTX_ILOCKED_MSK))){
			/* no, must have been the mutex */
			return lck_mtx_lock_contended(lock, indirect, &first_miss);
		}

		/* check to see if it is marked destroyed */
		if (__improbable(state == LCK_MTX_TAG_DESTROYED)) {
			lck_mtx_destroyed(lock);
		}

		/* Is this an indirect mutex? */
		if (__improbable(state == LCK_MTX_TAG_INDIRECT)) {
			indirect = get_indirect_mutex(&lock, &state);

			first_miss = 0;
			lck_grp_mtx_update_held((struct _lck_mtx_ext_*)lock);

			if (state & LCK_MTX_SPIN_MSK) {
				 /* M_SPIN_MSK was set, so M_ILOCKED_MSK must also be present */
				assert(state & LCK_MTX_ILOCKED_MSK);
				lck_grp_mtx_update_miss((struct _lck_mtx_ext_*)lock, &first_miss);
			}
		}

		if (!lck_mtx_lock_wait_interlock_to_clear(lock, &state)) {
			return lck_mtx_lock_contended(lock, indirect, &first_miss);
		}
	}

	/* no - can't be INDIRECT, DESTROYED or locked */
	while (__improbable(!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_SPIN_MSK, &state) )) {
		if (!lck_mtx_lock_wait_interlock_to_clear(lock, &state)) {
			return lck_mtx_lock_contended(lock, indirect, &first_miss);
		}
	}

	/* lock as spinlock and interlock acquired */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;          /* lock statistic */
	}
#endif

#if	CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN_ACQUIRE, lock, 0);
#endif
	/* return with the interlock held and preemption disabled */
	return;
}

__attribute__((noinline))
boolean_t
lck_mtx_try_lock_spin_slow(
	lck_mtx_t       *lock)
{
	boolean_t       indirect = FALSE;
	uint32_t        state;
	int             first_miss = 0;

	state = ordered_load_mtx_state(lock);

	/* is the interlock or mutex held */
	if (__improbable(state & ((LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK)))) {
		/*
		 * Note: both LCK_MTX_TAG_DESTROYED and LCK_MTX_TAG_INDIRECT
		 * have LCK_MTX_ILOCKED_MSK and LCK_MTX_MLOCKED_MSK
		 * set in state (state == lck_mtx_tag)
		 */

		/* is the mutex already held and not indirect */
		if (__improbable(!(state & LCK_MTX_ILOCKED_MSK))){
			return FALSE;
		}

		/* check to see if it is marked destroyed */
		if (__improbable(state == LCK_MTX_TAG_DESTROYED)) {
			lck_mtx_try_destroyed(lock);
		}

		/* Is this an indirect mutex? */
		if (__improbable(state == LCK_MTX_TAG_INDIRECT)) {
			indirect = get_indirect_mutex(&lock, &state);

			first_miss = 0;
			lck_grp_mtx_update_held((struct _lck_mtx_ext_*)lock);
		}

		if (!lck_mtx_try_lock_wait_interlock_to_clear(lock, &state)) {
			if (indirect)
				lck_grp_mtx_update_miss((struct _lck_mtx_ext_*)lock, &first_miss);
			return FALSE;
		}
	}

	/* no - can't be INDIRECT, DESTROYED or locked */
	while (__improbable(!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_SPIN_MSK, &state))) {
		if (!lck_mtx_try_lock_wait_interlock_to_clear(lock, &state)) {
			if (indirect)
				lck_grp_mtx_update_miss((struct _lck_mtx_ext_*)lock, &first_miss);
			return FALSE;
		}
	}

	/* lock and interlock acquired */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;		/* lock statistic */
	}
#endif

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, lock, 0);
#endif
	return TRUE;

}

__attribute__((noinline))
void
lck_mtx_convert_spin(
	lck_mtx_t 	*lock)
{
	uint32_t state;

	state = ordered_load_mtx_state(lock);

	/* Is this an indirect mutex? */
	if (__improbable(state == LCK_MTX_TAG_INDIRECT)) {
		/* If so, take indirection */
		get_indirect_mutex(&lock, &state);
	}

	assertf((thread_t)lock->lck_mtx_owner == current_thread(), "lock %p not owned by thread %p (current owner %p)", lock, current_thread(), (thread_t)lock->lck_mtx_owner );

	if (__improbable(state & LCK_MTX_MLOCKED_MSK)) {
		/* already owned as a mutex, just return */
		return;
	}

	assert(get_preemption_level() > 0);
	assert(state & LCK_MTX_ILOCKED_MSK);
	assert(state & LCK_MTX_SPIN_MSK);

	/*
	 * Check if there are waiters to
	 * inherit their priority.
	 */
	if (__improbable(state & LCK_MTX_WAITERS_MSK)) {
		return lck_mtx_convert_spin_acquire_tail(lock);
	}

	lck_mtx_convert_spin_finish_inline(lock, ordered_load_mtx_state(lock));

	return;
}

static inline boolean_t
lck_mtx_lock_grab_mutex(
	lck_mtx_t 	*lock)
{
	uint32_t state;

	state = ordered_load_mtx_state(lock);

	if (!lck_mtx_interlock_try_lock_set_flags(lock, LCK_MTX_MLOCKED_MSK, &state)) {
		return FALSE;
	}

	/* lock and interlock acquired */

	thread_t thread = current_thread();
	/* record owner of mutex */
	ordered_store_mtx_owner(lock, (uintptr_t)thread);

#if MACH_LDEBUG
	if (thread) {
		thread->mutex_count++;		/* lock statistic */
	}
#endif
	return TRUE;
}

__attribute__((noinline))
void
lck_mtx_assert(
	lck_mtx_t 	*lock,
	unsigned int 	type)
{
	thread_t thread, owner;
	uint32_t state;

	thread = current_thread();
	state = ordered_load_mtx_state(lock);

	if (state == LCK_MTX_TAG_INDIRECT) {
		get_indirect_mutex(&lock, &state);
	}

	owner = (thread_t)lock->lck_mtx_owner;

	if (type == LCK_MTX_ASSERT_OWNED) {
		if (owner != thread || !(state & (LCK_MTX_ILOCKED_MSK | LCK_MTX_MLOCKED_MSK)))
			panic("mutex (%p) not owned\n", lock);
	} else {
		assert (type == LCK_MTX_ASSERT_NOTOWNED);
		if (owner == thread)
			panic("mutex (%p) owned\n", lock);
	}
}

/*
 * Routine: 	lck_mtx_lock_spinwait_x86
 *
 * Invoked trying to acquire a mutex when there is contention but
 * the holder is running on another processor. We spin for up to a maximum
 * time waiting for the lock to be released.
 *
 * Called with the interlock unlocked.
 * returns LCK_MTX_SPINWAIT_ACQUIRED if mutex acquired
 * returns LCK_MTX_SPINWAIT_SPUN if we spun
 * returns LCK_MTX_SPINWAIT_NO_SPIN if we didn't spin due to the holder not running
 */
__attribute__((noinline))
lck_mtx_spinwait_ret_type_t
lck_mtx_lock_spinwait_x86(
	lck_mtx_t	*mutex)
{
	__kdebug_only uintptr_t	trace_lck = unslide_for_kdebug(mutex);
	thread_t	holder;
	uint64_t	overall_deadline;
	uint64_t	check_owner_deadline;
	uint64_t	cur_time;
	lck_mtx_spinwait_ret_type_t		retval = LCK_MTX_SPINWAIT_SPUN;
	int		loopcount = 0;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_START,
		     trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(mutex->lck_mtx_owner), mutex->lck_mtx_waiters, 0, 0);

	cur_time = mach_absolute_time();
	overall_deadline = cur_time + MutexSpin;
	check_owner_deadline = cur_time;

	/*
	 * Spin while:
	 *   - mutex is locked, and
	 *   - its locked as a spin lock, and
	 *   - owner is running on another processor, and
	 *   - owner (processor) is not idling, and
	 *   - we haven't spun for long enough.
	 */
	do {
		if (__probable(lck_mtx_lock_grab_mutex(mutex))) {
			retval = LCK_MTX_SPINWAIT_ACQUIRED;
			break;
		}
		cur_time = mach_absolute_time();

		if (cur_time >= overall_deadline)
			break;

		if (cur_time >= check_owner_deadline && mutex->lck_mtx_owner) {
			boolean_t	istate;

			/*
			 * We will repeatedly peek at the state of the lock while spinning,
			 * and we will acquire the interlock to do so.
			 * The thread that will unlock the mutex will also need to acquire
			 * the interlock, and we want to avoid to slow it down.
			 * To avoid to get an interrupt while holding the interlock
			 * and increase the time we are holding it, we
			 * will try to acquire the interlock with interrupts disabled.
			 * This is safe because it is a "try_lock", if we can't acquire
			 * the interlock we re-enable the interrupts and fail, so it is
			 * ok to call it even if the interlock was already held.
			*/
			if (lck_mtx_interlock_try_lock_disable_interrupts(mutex, &istate)) {

				if ((holder = (thread_t) mutex->lck_mtx_owner) != NULL) {

					if ( !(holder->machine.specFlags & OnProc) ||
					     (holder->state & TH_IDLE)) {

						lck_mtx_interlock_unlock_enable_interrupts(mutex, istate);

						if (loopcount == 0)
							retval = LCK_MTX_SPINWAIT_NO_SPIN;
						break;
					}
				}
				lck_mtx_interlock_unlock_enable_interrupts(mutex, istate);

				check_owner_deadline = cur_time + (MutexSpin / 4);
			}
		}
		cpu_pause();

		loopcount++;

	} while (TRUE);

#if	CONFIG_DTRACE
	/*
	 * We've already kept a count via overall_deadline of how long we spun.
	 * If dtrace is active, then we compute backwards to decide how
	 * long we spun.
	 *
	 * Note that we record a different probe id depending on whether
	 * this is a direct or indirect mutex.  This allows us to 
	 * penalize only lock groups that have debug/stats enabled
	 * with dtrace processing if desired.
	 */
	if (__probable(mutex->lck_mtx_is_ext == 0)) {
		LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN, mutex,
			mach_absolute_time() - (overall_deadline - MutexSpin));
	} else {
		LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_SPIN, mutex,
			mach_absolute_time() - (overall_deadline - MutexSpin));
	}
	/* The lockstat acquire event is recorded by the assembly code beneath us. */
#endif

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_END,
		     trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(mutex->lck_mtx_owner), mutex->lck_mtx_waiters, retval, 0);

	return retval;
}



/*
 * Routine: 	lck_mtx_lock_wait_x86
 *
 * Invoked in order to wait on contention.
 *
 * Called with the interlock locked and
 * preemption disabled...
 * returns it unlocked and with preemption enabled
 *
 * lck_mtx_waiters is 1:1 with a wakeup needing to occur.
 *      A runnable waiter can exist between wait and acquire
 *      without a waiters count being set.
 *      This allows us to never make a spurious wakeup call.
 *
 * Priority:
 *      This avoids taking the thread lock if the owning thread is the same priority.
 *      This optimizes the case of same-priority threads contending on a lock.
 *      However, that allows the owning thread to drop in priority while holding the lock,
 *      because there is no state that the priority change can notice that
 *      says that the targeted thread holds a contended mutex.
 *
 *      One possible solution: priority changes could look for some atomic tag
 *      on the thread saying 'holding contended lock', and then set up a promotion.
 *      Needs a story for dropping that promotion - the last contended unlock
 *      has to notice that this has happened.
 */
__attribute__((noinline))
void
lck_mtx_lock_wait_x86 (
	lck_mtx_t	*mutex,
	struct turnstile **ts)
{
	thread_t self = current_thread();

#if	CONFIG_DTRACE
	uint64_t sleep_start = 0;

	if (lockstat_probemap[LS_LCK_MTX_LOCK_BLOCK] || lockstat_probemap[LS_LCK_MTX_EXT_LOCK_BLOCK]) {
		sleep_start = mach_absolute_time();
	}
#endif
	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(mutex);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_START,
	             trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(mutex->lck_mtx_owner),
	             mutex->lck_mtx_waiters, 0, 0);

	assert(self->waiting_for_mutex == NULL);
	self->waiting_for_mutex = mutex;
	mutex->lck_mtx_waiters++;

	thread_t holder = (thread_t)mutex->lck_mtx_owner;
	assert(holder != NULL);

	/*
	 * lck_mtx_lock_wait_x86 might be called on a loop. Call prepare just once and reuse
	 * the same turnstile while looping, the matching turnstile compleate will be called
	 * by lck_mtx_lock_contended when finally acquiring the lock.
	 */
	if (*ts == NULL) {
		*ts = turnstile_prepare((uintptr_t)mutex, NULL, TURNSTILE_NULL, TURNSTILE_KERNEL_MUTEX);
	}

	struct turnstile *turnstile = *ts;
	thread_set_pending_block_hint(self, kThreadWaitKernelMutex);
	turnstile_update_inheritor(turnstile, holder, (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

	waitq_assert_wait64(&turnstile->ts_waitq, CAST_EVENT64_T(LCK_MTX_EVENT(mutex)), THREAD_UNINT | THREAD_WAIT_NOREPORT_USER, TIMEOUT_WAIT_FOREVER);

	lck_mtx_ilk_unlock(mutex);

	turnstile_update_inheritor_complete(turnstile, TURNSTILE_INTERLOCK_NOT_HELD);

	thread_block(THREAD_CONTINUE_NULL);

	self->waiting_for_mutex = NULL;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_END,
	             trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(mutex->lck_mtx_owner),
	             mutex->lck_mtx_waiters, 0, 0);

#if	CONFIG_DTRACE
	/*
	 * Record the Dtrace lockstat probe for blocking, block time
	 * measured from when we were entered.
	 */
	if (sleep_start) {
		if (mutex->lck_mtx_is_ext == 0) {
			LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_BLOCK, mutex,
			    mach_absolute_time() - sleep_start);
		} else {
			LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_BLOCK, mutex,
			    mach_absolute_time() - sleep_start);
		}
	}
#endif
}

/*
 *      Routine: kdp_lck_mtx_lock_spin_is_acquired
 *      NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 *      Returns: TRUE if lock is acquired.
 */
boolean_t
kdp_lck_mtx_lock_spin_is_acquired(lck_mtx_t	*lck)
{
	if (not_in_kdp) {
		panic("panic: kdp_lck_mtx_lock_spin_is_acquired called outside of kernel debugger");
	}

	if (lck->lck_mtx_ilocked || lck->lck_mtx_mlocked) {
		return TRUE;
	}

	return FALSE;
}

void
kdp_lck_mtx_find_owner(__unused struct waitq * waitq, event64_t event, thread_waitinfo_t * waitinfo)
{
	lck_mtx_t * mutex = LCK_EVENT_TO_MUTEX(event);
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(mutex);
	thread_t holder   = (thread_t)mutex->lck_mtx_owner;
	waitinfo->owner   = thread_tid(holder);
}

void
kdp_rwlck_find_owner(__unused struct waitq * waitq, event64_t event, thread_waitinfo_t * waitinfo)
{
	lck_rw_t *rwlck = NULL;
	switch(waitinfo->wait_type) {
		case kThreadWaitKernelRWLockRead:
			rwlck = READ_EVENT_TO_RWLOCK(event);
			break;
		case kThreadWaitKernelRWLockWrite:
		case kThreadWaitKernelRWLockUpgrade:
			rwlck = WRITE_EVENT_TO_RWLOCK(event);
			break;
		default:
			panic("%s was called with an invalid blocking type", __FUNCTION__);
			break;
	}
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(rwlck);
	waitinfo->owner = 0;
}
