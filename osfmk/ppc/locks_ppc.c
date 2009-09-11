/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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

#include <mach_kdb.h>
#include <mach_ldebug.h>

#include <kern/kalloc.h>
#include <kern/lock.h>
#include <kern/locks.h>
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
#endif

#include <sys/kdebug.h>

/*
 * We need only enough declarations from the BSD-side to be able to
 * test if our probe is active, and to call __dtrace_probe().  Setting
 * NEED_DTRACE_DEFS gets a local copy of those definitions pulled in.
 *
 * Note that if CONFIG_DTRACE is off, the include file below stubs out
 * the code hooks here.
 */
#if	CONFIG_DTRACE
#define NEED_DTRACE_DEFS
#include <../bsd/sys/lockstat.h>
#endif

#define	LCK_RW_LCK_EXCLUSIVE_CODE	0x100
#define	LCK_RW_LCK_EXCLUSIVE1_CODE	0x101
#define	LCK_RW_LCK_SHARED_CODE		0x102
#define	LCK_RW_LCK_SH_TO_EX_CODE	0x103
#define	LCK_RW_LCK_SH_TO_EX1_CODE	0x104
#define	LCK_RW_LCK_EX_TO_SH_CODE	0x105


#define	ANY_LOCK_DEBUG	(USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

unsigned int lock_wait_time[2] = { (unsigned int)-1, 0 } ;

/* Forwards */


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
#else	/* ANY_LOCK_DEBUG */
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
int		usld_lock_common_checks(usimple_lock_t, const char *);
#else	/* USLOCK_DEBUG */
#define	USLDBG(stmt)
#endif	/* USLOCK_DEBUG */

/*
 *      Routine:        lck_spin_alloc_init
 */
lck_spin_t *
lck_spin_alloc_init(
	lck_grp_t	*grp,
	lck_attr_t	*attr) {
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
	lck_grp_t	*grp) {
	lck_spin_destroy(lck, grp);
	kfree((void *)lck, sizeof(lck_spin_t));
}

/*
 *      Routine:        lck_spin_init
 */
void
lck_spin_init(
	lck_spin_t		*lck,
	lck_grp_t		*grp,
	__unused lck_attr_t	*attr) {

	lck->interlock = 0;
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_SPIN);
}

/*
 *      Routine:        lck_spin_destroy
 */
void
lck_spin_destroy(
	lck_spin_t	*lck,
	lck_grp_t	*grp) {
	if (lck->interlock == LCK_SPIN_TAG_DESTROYED)
		return;
	lck->interlock = LCK_SPIN_TAG_DESTROYED;
	lck_grp_lckcnt_decr(grp, LCK_TYPE_SPIN);
	lck_grp_deallocate(grp);
}

/*
 *	Initialize a usimple_lock.
 *
 *	No change in preemption state.
 */
void
usimple_lock_init(
	usimple_lock_t	l,
	unsigned short	tag)
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
	pc_t		pc;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_pre(l, pc));

	if(!hw_lock_to(&l->interlock, LockTimeOut))	/* Try to get the lock with a timeout */ 
		panic("simple lock deadlock detection - l=%p, cpu=%d, ret=%p", l, cpu_number(), pc);

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
	pc_t	pc;

	OBTAIN_PC(pc, l);
	USLDBG(usld_unlock(l, pc));
	sync();
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
	pc_t		pc;
	unsigned int	success;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_try_pre(l, pc));
	success = hw_lock_try(&l->interlock);
	if (success)
		USLDBG(usld_lock_try_post(l, pc));
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
usld_lock_common_checks(usimple_lock_t l, const char *caller)
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
	const char *caller = "usimple_lock";

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
		printf("%s:  lock 0x%x already locked (at %p) by",
		      caller, (integer_t) l, l->debug.lock_pc);
		printf(" current thread %p (new attempt at pc %p)\n",
		       l->debug.lock_thread, pc);
		panic("%s", caller);
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
	int mycpu;
	const char *caller = "successful usimple_lock";


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
	int mycpu;
	const char *caller = "usimple_unlock";


	if (!usld_lock_common_checks(l, caller))
		return;

	mycpu = cpu_number();

	if (!(l->debug.state & USLOCK_TAKEN))
		panic("%s:  lock 0x%x hasn't been taken",
		      caller, (integer_t) l);
	if (l->debug.lock_thread != (void *) current_thread())
		panic("%s:  unlocking lock 0x%x, owned by thread %p",
		      caller, (integer_t) l, l->debug.lock_thread);
	if (l->debug.lock_cpu != mycpu) {
		printf("%s:  unlocking lock 0x%x on cpu 0x%x",
		       caller, (integer_t) l, mycpu);
		printf(" (acquired on cpu 0x%x)\n", l->debug.lock_cpu);
		panic("%s", caller);
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
	const char *caller = "usimple_lock_try";

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
	int mycpu;
	const char *caller = "successful usimple_lock_try";

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
 * The C portion of the shared/exclusive locks package.
 */

/*
 * Forward definition 
 */

void lck_rw_lock_exclusive_gen(
	lck_rw_t	*lck);

lck_rw_type_t lck_rw_done_gen(
	lck_rw_t	*lck);

void
lck_rw_lock_shared_gen(
	lck_rw_t	*lck);

boolean_t
lck_rw_lock_shared_to_exclusive_gen(
	lck_rw_t	*lck);

void
lck_rw_lock_exclusive_to_shared_gen(
	lck_rw_t	*lck);

boolean_t
lck_rw_try_lock_exclusive_gen(
	lck_rw_t	*lck);

boolean_t
lck_rw_try_lock_shared_gen(
	lck_rw_t	*lck);

void lck_rw_ext_init(
	lck_rw_ext_t	*lck,
	lck_grp_t	*grp,
	lck_attr_t	*attr);

void lck_rw_ext_backtrace(
	lck_rw_ext_t	*lck);

void lck_rw_lock_exclusive_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck);

lck_rw_type_t lck_rw_done_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck);

void
lck_rw_lock_shared_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck);

boolean_t
lck_rw_lock_shared_to_exclusive_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck);

void
lck_rw_lock_exclusive_to_shared_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck);

boolean_t
lck_rw_try_lock_exclusive_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck);

boolean_t
lck_rw_try_lock_shared_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck);

void
lck_rw_ilk_lock(
	lck_rw_t	*lck);

void
lck_rw_ilk_unlock(
	lck_rw_t	*lck);

void
lck_rw_check_type(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck);

void
lck_rw_assert_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck,
	unsigned int	type);

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
	boolean_t		can_sleep,
	__unused unsigned short	tag,
	__unused unsigned short	tag1)
{
	lock_t		*lck;

	if ((lck = (lock_t *)kalloc(sizeof(lock_t))) != 0)
	  lock_init(lck, can_sleep, tag, tag1);
	return(lck);
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
	lock_t			*lck,
	boolean_t		can_sleep,
	__unused unsigned short	tag,
	__unused unsigned short	tag1)
{
	if (!can_sleep)
		panic("lock_init: sleep mode must be set to TRUE\n");

	(void) memset((void *) lck, 0, sizeof(lock_t));
#if	MACH_LDEBUG
	lck->lck_rw_deb.type = RW_TAG;
	lck->lck_rw_attr |= (LCK_RW_ATTR_DEBUG|LCK_RW_ATTR_DIS_THREAD|LCK_RW_ATTR_DIS_MYLOCK);
	lck->lck_rw.lck_rw_priv_excl = TRUE;
#else
	lck->lck_rw_priv_excl = TRUE;
#endif

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
	lock_t	*lck)
{
	kfree((void *)lck, sizeof(lock_t));
}

#if	MACH_LDEBUG
void
lock_write(
	lock_t	*lck)
{
	lck_rw_lock_exclusive_ext((lck_rw_ext_t *)lck, (lck_rw_t *)lck);
}

void
lock_done(
	lock_t	*lck)
{
	(void)lck_rw_done_ext((lck_rw_ext_t *)lck, (lck_rw_t *)lck);
}

void
lock_read(
	lock_t	*lck)
{
	lck_rw_lock_shared_ext((lck_rw_ext_t *)lck, (lck_rw_t *)lck);
}

boolean_t
lock_read_to_write(
	lock_t	*lck)
{
	return(lck_rw_lock_shared_to_exclusive_ext((lck_rw_ext_t *)lck, (lck_rw_t *)lck));
}

void
lock_write_to_read(
	register lock_t	*lck)
{
	lck_rw_lock_exclusive_to_shared_ext((lck_rw_ext_t *)lck, (lck_rw_t *)lck);
}
#endif

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
	kfree((void *)lck, sizeof(lck_rw_t));
}

/*
 *      Routine:        lck_rw_init
 */
void
lck_rw_init(
	lck_rw_t		*lck,
	lck_grp_t		*grp,
	lck_attr_t		*attr) {
	lck_rw_ext_t	*lck_ext;
	lck_attr_t	*lck_attr;

	if (attr != LCK_ATTR_NULL)
		lck_attr = attr;
	else
		lck_attr = &LockDefaultLckAttr;

	if ((lck_attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		if ((lck_ext = (lck_rw_ext_t *)kalloc(sizeof(lck_rw_ext_t))) != 0) {
			lck_rw_ext_init(lck_ext, grp, lck_attr);	
			lck->lck_rw_tag = LCK_RW_TAG_INDIRECT;
			lck->lck_rw_ptr = lck_ext;
		}
	} else {
		(void) memset((void *) lck, 0, sizeof(lck_rw_t));
		if ((lck_attr->lck_attr_val)  & LCK_ATTR_RW_SHARED_PRIORITY)
			lck->lck_rw_priv_excl = FALSE;
		else
			lck->lck_rw_priv_excl = TRUE;
	}

	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_RW);
}

/*
 *      Routine:        lck_rw_ext_init
 */
void
lck_rw_ext_init(
	lck_rw_ext_t	*lck,
	lck_grp_t	*grp,
	lck_attr_t	*attr) {

	bzero((void *)lck, sizeof(lck_rw_ext_t));
	if ((attr->lck_attr_val)  & LCK_ATTR_RW_SHARED_PRIORITY)
		lck->lck_rw.lck_rw_priv_excl = FALSE;
	else
		lck->lck_rw.lck_rw_priv_excl = TRUE;

	if ((attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck->lck_rw_deb.type = RW_TAG;
		lck->lck_rw_attr |= LCK_RW_ATTR_DEBUG;
	}

	lck->lck_rw_grp = grp;

	if (grp->lck_grp_attr & LCK_GRP_ATTR_STAT)
		 lck->lck_rw_attr |= LCK_RW_ATTR_STAT;
}

/*
 *      Routine:        lck_rw_destroy
 */
void
lck_rw_destroy(
	lck_rw_t	*lck,
	lck_grp_t	*grp) {
	boolean_t lck_is_indirect;
	
	if (lck->lck_rw_tag == LCK_RW_TAG_DESTROYED)
		return;
	lck_is_indirect = (lck->lck_rw_tag == LCK_RW_TAG_INDIRECT);
	lck->lck_rw_tag = LCK_RW_TAG_DESTROYED;
	if (lck_is_indirect)
		kfree((void *)lck->lck_rw_ptr, sizeof(lck_rw_ext_t));

	lck_grp_lckcnt_decr(grp, LCK_TYPE_RW);
	lck_grp_deallocate(grp);
	return;
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
		panic("lck_rw_lock(): Invalid RW lock type: %d\n", lck_rw_type);
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
 *      Routine:        lck_rw_lock_exclusive_gen
 */
void
lck_rw_lock_exclusive_gen(
	lck_rw_t	*lck)
{
	int	   i;
	wait_result_t	res;
#if	CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int slept = 0;
	int readers_at_sleep;
#endif

	lck_rw_ilk_lock(lck);
#if	CONFIG_DTRACE
	readers_at_sleep = lck->lck_rw_shared_cnt;
#endif

	/*
	 *	Try to acquire the lck_rw_want_excl bit.
	 */
	while (lck->lck_rw_want_excl) {
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE_CODE) | DBG_FUNC_START, (int)lck, 0, 0, 0, 0);

#if	CONFIG_DTRACE
		if ((lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] || lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK]) && wait_interval == 0) {
			wait_interval = mach_absolute_time();
		} else {
			wait_interval = -1;
		}
#endif

		i = lock_wait_time[1];
		if (i != 0) {
			lck_rw_ilk_unlock(lck);
			while (--i != 0 && lck->lck_rw_want_excl)
				continue;
			lck_rw_ilk_lock(lck);
		}

		if (lck->lck_rw_want_excl) {
			lck->lck_rw_waiting = TRUE;
			res = assert_wait((event_t)(((unsigned int*)lck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
			if (res == THREAD_WAITING) {
				lck_rw_ilk_unlock(lck);
				res = thread_block(THREAD_CONTINUE_NULL);
#if	CONFIG_DTRACE
				slept = 1;
#endif
				lck_rw_ilk_lock(lck);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE_CODE) | DBG_FUNC_END, (int)lck, res, 0, 0, 0);
	}
	lck->lck_rw_want_excl = TRUE;

	/* Wait for readers (and upgrades) to finish */

	while ((lck->lck_rw_shared_cnt != 0) || lck->lck_rw_want_upgrade) {

		i = lock_wait_time[1];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE1_CODE) | DBG_FUNC_START,
			     (int)lck, lck->lck_rw_shared_cnt, lck->lck_rw_want_upgrade, i, 0);
#if	CONFIG_DTRACE
		if ((lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] || lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK]) && wait_interval == 0) {
			wait_interval = mach_absolute_time();
		} else {
			wait_interval = (unsigned) -1;
		}
#endif

		if (i != 0) {
			lck_rw_ilk_unlock(lck);
			while (--i != 0 && (lck->lck_rw_shared_cnt != 0 ||
					    lck->lck_rw_want_upgrade))
				continue;
			lck_rw_ilk_lock(lck);
		}

		if (lck->lck_rw_shared_cnt != 0 || lck->lck_rw_want_upgrade) {
			lck->lck_rw_waiting = TRUE;
			res = assert_wait((event_t)(((unsigned int*)lck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
			if (res == THREAD_WAITING) {
				lck_rw_ilk_unlock(lck);
				res = thread_block(THREAD_CONTINUE_NULL);
#if	CONFIG_DTRACE
				slept = 1;
#endif
				lck_rw_ilk_lock(lck);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE1_CODE) | DBG_FUNC_END,
			     (int)lck, lck->lck_rw_shared_cnt, lck->lck_rw_want_upgrade, res, 0);
	}

	lck_rw_ilk_unlock(lck);
#if	CONFIG_DTRACE
	/*
	 * Decide what latencies we suffered that are Dtrace events.
	 * If we have set wait_interval, then we either spun or slept.
	 * At least we get out from under the interlock before we record
	 * which is the best we can do here to minimize the impact
	 * of the tracing.
	 */
	if (wait_interval != 0 && wait_interval != (unsigned) -1) {
		if (slept == 0) {
			LOCKSTAT_RECORD2(LS_LCK_RW_LOCK_EXCL_SPIN, lck,
			    mach_absolute_time() - wait_interval, 1);
		} else {
			/*
			 * For the blocking case, we also record if when we blocked
			 * it was held for read or write, and how many readers.
			 * Notice that above we recorded this before we dropped
			 * the interlock so the count is accurate.
			 */
			LOCKSTAT_RECORD4(LS_LCK_RW_LOCK_EXCL_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lck, 1);
#endif
}


/*
 *      Routine:        lck_rw_done_gen
 */
lck_rw_type_t
lck_rw_done_gen(
	lck_rw_t	*lck)
{
	boolean_t	do_wakeup = FALSE;
	lck_rw_type_t	lck_rw_type;


	lck_rw_ilk_lock(lck);

	if (lck->lck_rw_shared_cnt != 0) {
		lck_rw_type = LCK_RW_TYPE_SHARED;
		lck->lck_rw_shared_cnt--;
	}
	else {	
		lck_rw_type = LCK_RW_TYPE_EXCLUSIVE;
		if (lck->lck_rw_want_upgrade) 
			lck->lck_rw_want_upgrade = FALSE;
		else 
			lck->lck_rw_want_excl = FALSE;
	}

	/*
	 *	There is no reason to wakeup a lck_rw_waiting thread
	 *	if the read-count is non-zero.  Consider:
	 *		we must be dropping a read lock
	 *		threads are waiting only if one wants a write lock
	 *		if there are still readers, they can't proceed
	 */

	if (lck->lck_rw_waiting && (lck->lck_rw_shared_cnt == 0)) {
		lck->lck_rw_waiting = FALSE;
		do_wakeup = TRUE;
	}

	lck_rw_ilk_unlock(lck);

	if (do_wakeup)
		thread_wakeup((event_t)(((unsigned int*)lck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))));
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE, lck, lck_rw_type);
	return(lck_rw_type);
}


/*
 *	Routine:	lck_rw_lock_shared_gen
 */
void
lck_rw_lock_shared_gen(
	lck_rw_t	*lck)
{
	int		i;
	wait_result_t      res;
#if	CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int slept = 0;
	int readers_at_sleep;
#endif

	lck_rw_ilk_lock(lck);
#if	CONFIG_DTRACE
	readers_at_sleep = lck->lck_rw_shared_cnt;
#endif

	while ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
	        ((lck->lck_rw_shared_cnt == 0) || (lck->lck_rw_priv_excl))) {
		i = lock_wait_time[1];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_CODE) | DBG_FUNC_START,
			     (int)lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, i, 0);
#if	CONFIG_DTRACE
		if ((lockstat_probemap[LS_LCK_RW_LOCK_SHARED_SPIN] || lockstat_probemap[LS_LCK_RW_LOCK_SHARED_BLOCK]) && wait_interval == 0) {
			wait_interval = mach_absolute_time();
		} else {
			wait_interval = (unsigned) -1;
		}
#endif

		if (i != 0) {
			lck_rw_ilk_unlock(lck);
			while (--i != 0 && 
			       (lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
			       ((lck->lck_rw_shared_cnt == 0) || (lck->lck_rw_priv_excl)))
				continue;
			lck_rw_ilk_lock(lck);
		}

		if ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    ((lck->lck_rw_shared_cnt == 0) || (lck->lck_rw_priv_excl))) {
			lck->lck_rw_waiting = TRUE;
			res = assert_wait((event_t)(((unsigned int*)lck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
			if (res == THREAD_WAITING) {
				lck_rw_ilk_unlock(lck);
				res = thread_block(THREAD_CONTINUE_NULL);
#if	CONFIG_DTRACE
				slept = 1;
#endif
				lck_rw_ilk_lock(lck);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_CODE) | DBG_FUNC_END,
			     (int)lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, res, 0);
	}

	lck->lck_rw_shared_cnt++;

	lck_rw_ilk_unlock(lck);
#if	CONFIG_DTRACE
	if (wait_interval != 0 && wait_interval != (unsigned) -1) {
		if (slept == 0) {
			LOCKSTAT_RECORD2(LS_LCK_RW_LOCK_SHARED_SPIN, lck, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD4(LS_LCK_RW_LOCK_SHARED_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 0,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lck, 0);
#endif
}


/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_gen
 *	Function:
 *		Improves a read-only lock to one with
 *		write permission.  If another reader has
 *		already requested an upgrade to a write lock,
 *		no lock is held upon return.
 *
 *		Returns FALSE if the upgrade *failed*.
 */

boolean_t
lck_rw_lock_shared_to_exclusive_gen(
	lck_rw_t	*lck)
{
	int	    i;
	boolean_t	    do_wakeup = FALSE;
	wait_result_t      res;
#if	CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int slept = 0;
	int readers_at_sleep = 0;
#endif

	lck_rw_ilk_lock(lck);

	lck->lck_rw_shared_cnt--;	

	if (lck->lck_rw_want_upgrade) {
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_START,
			     (int)lck, lck->lck_rw_shared_cnt, lck->lck_rw_want_upgrade, 0, 0);

		/*
		 *	Someone else has requested upgrade.
		 *	Since we've released a read lock, wake
		 *	him up.
		 */
		if (lck->lck_rw_waiting && (lck->lck_rw_shared_cnt == 0)) {
			lck->lck_rw_waiting = FALSE;
			do_wakeup = TRUE;
		}

		lck_rw_ilk_unlock(lck);

		if (do_wakeup)
			thread_wakeup((event_t)(((unsigned int*)lck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))));

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_END,
			     (int)lck, lck->lck_rw_shared_cnt, lck->lck_rw_want_upgrade, 0, 0);

		return (FALSE);
	}

	lck->lck_rw_want_upgrade = TRUE;

	while (lck->lck_rw_shared_cnt != 0) {
		i = lock_wait_time[1];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX1_CODE) | DBG_FUNC_START,
			     (int)lck, lck->lck_rw_shared_cnt, i, 0, 0);

#if	CONFIG_DTRACE
		readers_at_sleep = lck->lck_rw_shared_cnt;
		if ((lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN] || lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK]) && wait_interval == 0) {
			wait_interval = mach_absolute_time();
		} else {
			wait_interval = (unsigned) -1;
		}
#endif
		if (i != 0) {
			lck_rw_ilk_unlock(lck);
			while (--i != 0 && lck->lck_rw_shared_cnt != 0)
				continue;
			lck_rw_ilk_lock(lck);
		}

		if (lck->lck_rw_shared_cnt != 0) {
			lck->lck_rw_waiting = TRUE;
			res = assert_wait((event_t)(((unsigned int*)lck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
			if (res == THREAD_WAITING) {
				lck_rw_ilk_unlock(lck);
				res = thread_block(THREAD_CONTINUE_NULL);
#if	CONFIG_DTRACE
				slept = 1;
#endif
				lck_rw_ilk_lock(lck);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX1_CODE) | DBG_FUNC_END,
			     (int)lck, lck->lck_rw_shared_cnt, 0, 0, 0);
	}

	lck_rw_ilk_unlock(lck);

#if	CONFIG_DTRACE
	/*
	 * We infer if we took a sleep or spin path by whether readers_at_sleep
	 * was set.
	 */
	if (wait_interval != 0 && wait_interval != (unsigned) -1 && readers_at_sleep) {
		if (slept == 0) {
			LOCKSTAT_RECORD2(LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN, lck, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD4(LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
#endif

	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lck, 1);
	return (TRUE);
}

/*
 *      Routine:        lck_rw_lock_exclusive_to_shared_gen
 */
void
lck_rw_lock_exclusive_to_shared_gen(
	lck_rw_t	*lck)
{
	boolean_t	   do_wakeup = FALSE;

	lck_rw_ilk_lock(lck);

	lck->lck_rw_shared_cnt++;
	if (lck->lck_rw_want_upgrade)
		lck->lck_rw_want_upgrade = FALSE;
	else
	 	lck->lck_rw_want_excl = FALSE;

	if (lck->lck_rw_waiting) {
		lck->lck_rw_waiting = FALSE;
		do_wakeup = TRUE;
	}

	lck_rw_ilk_unlock(lck);

	if (do_wakeup)
		thread_wakeup((event_t)(((unsigned int*)lck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))));

	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, lck, 0);
}


/*
 *	Routine:	lck_rw_try_lock_exclusive_gen
 *	Function:
 *		Tries to get a write lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */

boolean_t
lck_rw_try_lock_exclusive_gen(
	lck_rw_t	*lck)
{
	lck_rw_ilk_lock(lck);

	if (lck->lck_rw_want_excl || lck->lck_rw_want_upgrade || lck->lck_rw_shared_cnt) {
		/*
		 *	Can't get lock.
		 */
		lck_rw_ilk_unlock(lck);
		return(FALSE);
	}

	/*
	 *	Have lock.
	 */

	lck->lck_rw_want_excl = TRUE;

	lck_rw_ilk_unlock(lck);

	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, lck, 1);
	return(TRUE);
}

/*
 *	Routine:	lck_rw_try_lock_shared_gen
 *	Function:
 *		Tries to get a read lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */

boolean_t
lck_rw_try_lock_shared_gen(
	lck_rw_t	*lck)
{
	lck_rw_ilk_lock(lck);

	if ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
	    ((lck->lck_rw_shared_cnt == 0) || (lck->lck_rw_priv_excl))) {
		lck_rw_ilk_unlock(lck);
		return(FALSE);
	}

	lck->lck_rw_shared_cnt++;

	lck_rw_ilk_unlock(lck);

	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, lck, 0);
	return(TRUE);
}


/*
 *	Routine:	lck_rw_ext_backtrace
 */
void
lck_rw_ext_backtrace(
	lck_rw_ext_t	*lck)
{
	unsigned int *stackptr, *stackptr_prev;
	unsigned int frame;

	__asm__ volatile("mr %0,r1" : "=r" (stackptr)); 
	frame = 0;
	while (frame < LCK_FRAMES_MAX) {
		stackptr_prev = stackptr;
		stackptr = ( unsigned int *)*stackptr;
		if ( (((unsigned int)stackptr_prev) - ((unsigned int)stackptr)) > 8192)
			break;
		lck->lck_rw_deb.stack[frame] = *(stackptr+2); 
		frame++;
	}
	while (frame < LCK_FRAMES_MAX) {
		lck->lck_rw_deb.stack[frame] = 0;
		frame++;
	}
}


/*
 *      Routine:        lck_rw_lock_exclusive_ext
 */
void
lck_rw_lock_exclusive_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck)
{
	int				i;
	wait_result_t	res;
	boolean_t		lock_miss = FALSE;
	boolean_t		lock_wait = FALSE;
	boolean_t		lock_stat;
#if	CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int slept = 0;
	int readers_at_sleep;
#endif

	lck_rw_check_type(lck, rlck);

	if ( ((lck->lck_rw_attr & (LCK_RW_ATTR_DEBUG|LCK_RW_ATTR_DIS_MYLOCK)) == LCK_RW_ATTR_DEBUG) 
	     && (lck->lck_rw_deb.thread == current_thread()))
		panic("rw lock (%p) recursive lock attempt\n", rlck);

	lck_rw_ilk_lock(&lck->lck_rw);
#if	CONFIG_DTRACE
	readers_at_sleep = lck->lck_rw.lck_rw_shared_cnt;
#endif

	lock_stat = (lck->lck_rw_attr & LCK_RW_ATTR_STAT) ? TRUE : FALSE;

	if (lock_stat)
		lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_util_cnt++;

	/*
	 *	Try to acquire the lck_rw.lck_rw_want_excl bit.
	 */
	while (lck->lck_rw.lck_rw_want_excl) {
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE_CODE) | DBG_FUNC_START, (int)rlck, 0, 0, 0, 0);

		if (lock_stat && !lock_miss) {
			lock_miss = TRUE;
			lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt++;
		}
#if	CONFIG_DTRACE
		if ((lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] || lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK]) && wait_interval == 0) {
			wait_interval = mach_absolute_time();
		} else {
			wait_interval = (unsigned) -1;
		}
#endif

		i = lock_wait_time[1];
		if (i != 0) {
			lck_rw_ilk_unlock(&lck->lck_rw);
			while (--i != 0 && lck->lck_rw.lck_rw_want_excl)
				continue;
			lck_rw_ilk_lock(&lck->lck_rw);
		}

		if (lck->lck_rw.lck_rw_want_excl) {
			lck->lck_rw.lck_rw_waiting = TRUE;
			res = assert_wait((event_t)(((unsigned int*)rlck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
			if (res == THREAD_WAITING) {
				if (lock_stat && !lock_wait) {
					lock_wait = TRUE;
					lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cnt++;
				}
				lck_rw_ilk_unlock(&lck->lck_rw);
				res = thread_block(THREAD_CONTINUE_NULL);
#if	CONFIG_DTRACE
				slept = 1;
#endif
				lck_rw_ilk_lock(&lck->lck_rw);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE_CODE) | DBG_FUNC_END, (int)rlck, res, 0, 0, 0);
	}
	lck->lck_rw.lck_rw_want_excl = TRUE;

	/* Wait for readers (and upgrades) to finish */

	while ((lck->lck_rw.lck_rw_shared_cnt != 0) || lck->lck_rw.lck_rw_want_upgrade) {
		i = lock_wait_time[1];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE1_CODE) | DBG_FUNC_START,
			     (int)rlck, lck->lck_rw.lck_rw_shared_cnt, lck->lck_rw.lck_rw_want_upgrade, i, 0);
#if	CONFIG_DTRACE
		if ((lockstat_probemap[LS_LCK_RW_LOCK_EXCL_SPIN] || lockstat_probemap[LS_LCK_RW_LOCK_EXCL_BLOCK]) && wait_interval == 0) {
			wait_interval = mach_absolute_time();
		} else {
			wait_interval = (unsigned) -1;
		}
#endif

		if (lock_stat && !lock_miss) {
			lock_miss = TRUE;
			lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt++;
		}

		if (i != 0) {
			lck_rw_ilk_unlock(&lck->lck_rw);
			while (--i != 0 && (lck->lck_rw.lck_rw_shared_cnt != 0 ||
					    lck->lck_rw.lck_rw_want_upgrade))
				continue;
			lck_rw_ilk_lock(&lck->lck_rw);
		}

		if (lck->lck_rw.lck_rw_shared_cnt != 0 || lck->lck_rw.lck_rw_want_upgrade) {
			lck->lck_rw.lck_rw_waiting = TRUE;
			res = assert_wait((event_t)(((unsigned int*)rlck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
			if (res == THREAD_WAITING) {
				if (lock_stat && !lock_wait) {
					lock_wait = TRUE;
					lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cnt++;
				}
				lck_rw_ilk_unlock(&lck->lck_rw);
				res = thread_block(THREAD_CONTINUE_NULL);
#if	CONFIG_DTRACE
				slept = 1;
#endif
				lck_rw_ilk_lock(&lck->lck_rw);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EXCLUSIVE1_CODE) | DBG_FUNC_END,
			     (int)rlck, lck->lck_rw.lck_rw_shared_cnt, lck->lck_rw.lck_rw_want_upgrade, res, 0);
	}

	lck->lck_rw_deb.pc_excl = __builtin_return_address(0);
	if (LcksOpts & enaLkExtStck)
		lck_rw_ext_backtrace(lck);
	lck->lck_rw_deb.thread = current_thread();

	lck_rw_ilk_unlock(&lck->lck_rw);
#if	CONFIG_DTRACE
	/*
	 * Decide what latencies we suffered that are Dtrace events.
	 * If we have set wait_interval, then we either spun or slept.
	 * At least we get out from under the interlock before we record
	 * which is the best we can do here to minimize the impact
	 * of the tracing.
	 */
	if (wait_interval != 0 && wait_interval != (unsigned) -1) {
		if (slept == 0) {
			LOCKSTAT_RECORD2(LS_LCK_RW_LOCK_EXCL_SPIN, lck,
			    mach_absolute_time() - wait_interval, 1);
		} else {
			/*
			 * For the blocking case, we also record if when we blocked
			 * it was held for read or write, and how many readers.
			 * Notice that above we recorded this before we dropped
			 * the interlock so the count is accurate.
			 */
			LOCKSTAT_RECORD4(LS_LCK_RW_LOCK_EXCL_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lck, 1);
#endif
}


/*
 *      Routine:        lck_rw_done_ext
 */
lck_rw_type_t
lck_rw_done_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck)
{
	boolean_t	do_wakeup = FALSE;
	lck_rw_type_t	lck_rw_type;


	lck_rw_check_type(lck, rlck);

	lck_rw_ilk_lock(&lck->lck_rw);

	if (lck->lck_rw.lck_rw_shared_cnt != 0) {
		lck_rw_type = LCK_RW_TYPE_SHARED;
		lck->lck_rw.lck_rw_shared_cnt--;
	}
	else {	
		lck_rw_type = LCK_RW_TYPE_EXCLUSIVE;
		if (lck->lck_rw.lck_rw_want_upgrade) 
			lck->lck_rw.lck_rw_want_upgrade = FALSE;
		else if (lck->lck_rw.lck_rw_want_excl)
			lck->lck_rw.lck_rw_want_excl = FALSE;
		else
			panic("rw lock (%p) bad state (0x%08X) on attempt to release a shared or exlusive right\n",
				  rlck, lck->lck_rw.lck_rw_tag);
		if (lck->lck_rw_deb.thread == THREAD_NULL)
			panic("rw lock (%p) not held\n",
			      rlck);
		else if ( ((lck->lck_rw_attr & (LCK_RW_ATTR_DEBUG|LCK_RW_ATTR_DIS_THREAD)) == LCK_RW_ATTR_DEBUG) 
			 && (lck->lck_rw_deb.thread != current_thread()))
			panic("rw lock (%p) unlocked by non-owner(%p), current owner(%p)\n",
				  rlck, current_thread(), lck->lck_rw_deb.thread);
		lck->lck_rw_deb.thread = THREAD_NULL;
	}

	if (lck->lck_rw_attr & LCK_RW_ATTR_DEBUG)
		lck->lck_rw_deb.pc_done = __builtin_return_address(0);

	/*
	 *	There is no reason to wakeup a waiting thread
	 *	if the read-count is non-zero.  Consider:
	 *		we must be dropping a read lock
	 *		threads are waiting only if one wants a write lock
	 *		if there are still readers, they can't proceed
	 */

	if (lck->lck_rw.lck_rw_waiting && (lck->lck_rw.lck_rw_shared_cnt == 0)) {
		lck->lck_rw.lck_rw_waiting = FALSE;
		do_wakeup = TRUE;
	}

	lck_rw_ilk_unlock(&lck->lck_rw);

	if (do_wakeup)
		thread_wakeup((event_t)(((unsigned int*)rlck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))));
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE, lck, lck_rw_type);
	return(lck_rw_type);
}


/*
 *	Routine:	lck_rw_lock_shared_ext
 */
void
lck_rw_lock_shared_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck)
{
	int				i;
	wait_result_t	res;
	boolean_t		lock_miss = FALSE;
	boolean_t		lock_wait = FALSE;
	boolean_t		lock_stat;
#if	CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int slept = 0;
	int readers_at_sleep;
#endif

	lck_rw_check_type(lck, rlck);

	lck_rw_ilk_lock(&lck->lck_rw);
#if	CONFIG_DTRACE
	readers_at_sleep = lck->lck_rw.lck_rw_shared_cnt;
#endif

	lock_stat = (lck->lck_rw_attr & LCK_RW_ATTR_STAT) ? TRUE : FALSE;

	if (lock_stat)
		lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_util_cnt++;

	while ((lck->lck_rw.lck_rw_want_excl || lck->lck_rw.lck_rw_want_upgrade) &&
	       ((lck->lck_rw.lck_rw_shared_cnt == 0) || (lck->lck_rw.lck_rw_priv_excl))) {
		i = lock_wait_time[1];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_CODE) | DBG_FUNC_START,
			     (int)rlck, lck->lck_rw.lck_rw_want_excl, lck->lck_rw.lck_rw_want_upgrade, i, 0);
#if	CONFIG_DTRACE
		if ((lockstat_probemap[LS_LCK_RW_LOCK_SHARED_SPIN] || lockstat_probemap[LS_LCK_RW_LOCK_SHARED_BLOCK]) && wait_interval == 0) {
			wait_interval = mach_absolute_time();
		} else {
			wait_interval = (unsigned) -1;
		}
#endif

		if (lock_stat && !lock_miss) {
			lock_miss = TRUE;
			lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt++;
		}

		if (i != 0) {
			lck_rw_ilk_unlock(&lck->lck_rw);
			while (--i != 0 && 
			       (lck->lck_rw.lck_rw_want_excl || lck->lck_rw.lck_rw_want_upgrade) &&
	       		       ((lck->lck_rw.lck_rw_shared_cnt == 0) || (lck->lck_rw.lck_rw_priv_excl)))
				continue;
			lck_rw_ilk_lock(&lck->lck_rw);
		}

		if ((lck->lck_rw.lck_rw_want_excl || lck->lck_rw.lck_rw_want_upgrade)  &&
		   ((lck->lck_rw.lck_rw_shared_cnt == 0) || (lck->lck_rw.lck_rw_priv_excl))) {
			lck->lck_rw.lck_rw_waiting = TRUE;
			res = assert_wait((event_t)(((unsigned int*)rlck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
			if (res == THREAD_WAITING) {
				if (lock_stat && !lock_wait) {
					lock_wait = TRUE;
					lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cnt++;
				}
				lck_rw_ilk_unlock(&lck->lck_rw);
				res = thread_block(THREAD_CONTINUE_NULL);
#if	CONFIG_DTRACE
				slept = 1;
#endif
				lck_rw_ilk_lock(&lck->lck_rw);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_CODE) | DBG_FUNC_END,
			     (int)rlck, lck->lck_rw.lck_rw_want_excl, lck->lck_rw.lck_rw_want_upgrade, res, 0);
	}

	lck->lck_rw.lck_rw_shared_cnt++;

	lck_rw_ilk_unlock(&lck->lck_rw);
#if	CONFIG_DTRACE
	if (wait_interval != 0 && wait_interval != (unsigned) -1) {
		if (slept == 0) {
			LOCKSTAT_RECORD2(LS_LCK_RW_LOCK_SHARED_SPIN, lck, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD4(LS_LCK_RW_LOCK_SHARED_BLOCK, lck,
			    mach_absolute_time() - wait_interval, 0,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lck, 0);
#endif
}


/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_ext
 *	Function:
 *		Improves a read-only lock to one with
 *		write permission.  If another reader has
 *		already requested an upgrade to a write lock,
 *		no lock is held upon return.
 *
 *		Returns FALSE if the upgrade *failed*.
 */

boolean_t
lck_rw_lock_shared_to_exclusive_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck)
{
	int	    i;
	boolean_t	    do_wakeup = FALSE;
	wait_result_t      res;
	boolean_t		lock_miss = FALSE;
	boolean_t		lock_wait = FALSE;
	boolean_t		lock_stat;
#if	CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int slept = 0;
#endif

	lck_rw_check_type(lck, rlck);

	if (lck->lck_rw_deb.thread == current_thread())
		panic("rw lock (%p) recursive lock attempt\n", rlck);

	lck_rw_ilk_lock(&lck->lck_rw);

	lock_stat = (lck->lck_rw_attr & LCK_RW_ATTR_STAT) ? TRUE : FALSE;

	if (lock_stat)
		lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_util_cnt++;

	lck->lck_rw.lck_rw_shared_cnt--;	

	if (lck->lck_rw.lck_rw_want_upgrade) {
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_START,
			     (int)rlck, lck->lck_rw.lck_rw_shared_cnt, lck->lck_rw.lck_rw_want_upgrade, 0, 0);

		/*
		 *	Someone else has requested upgrade.
		 *	Since we've released a read lock, wake
		 *	him up.
		 */
		if (lck->lck_rw.lck_rw_waiting && (lck->lck_rw.lck_rw_shared_cnt == 0)) {
			lck->lck_rw.lck_rw_waiting = FALSE;
			do_wakeup = TRUE;
		}

		lck_rw_ilk_unlock(&lck->lck_rw);

		if (do_wakeup)
			thread_wakeup((event_t)(((unsigned int*)rlck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))));

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_END,
			     (int)rlck, lck->lck_rw.lck_rw_shared_cnt, lck->lck_rw.lck_rw_want_upgrade, 0, 0);

		return (FALSE);
	}

	lck->lck_rw.lck_rw_want_upgrade = TRUE;

	while (lck->lck_rw.lck_rw_shared_cnt != 0) {
		i = lock_wait_time[1];

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX1_CODE) | DBG_FUNC_START,
			     (int)rlck, lck->lck_rw.lck_rw_shared_cnt, i, 0, 0);

		if (lock_stat && !lock_miss) {
			lock_miss = TRUE;
			lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt++;
		}
#if	CONFIG_DTRACE
		if ((lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN] || lockstat_probemap[LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK]) && wait_interval == 0) {
			wait_interval = mach_absolute_time();
		} else {
			wait_interval = (unsigned) -1;
		}
#endif

		if (i != 0) {
			lck_rw_ilk_unlock(&lck->lck_rw);
			while (--i != 0 && lck->lck_rw.lck_rw_shared_cnt != 0)
				continue;
			lck_rw_ilk_lock(&lck->lck_rw);
		}

		if (lck->lck_rw.lck_rw_shared_cnt != 0) {
			lck->lck_rw.lck_rw_waiting = TRUE;
			res = assert_wait((event_t)(((unsigned int*)rlck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
			if (res == THREAD_WAITING) {
				if (lock_stat && !lock_wait) {
					lock_wait = TRUE;
					lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cnt++;
				}
				lck_rw_ilk_unlock(&lck->lck_rw);
				res = thread_block(THREAD_CONTINUE_NULL);
#if	CONFIG_DTRACE
				slept = 1;
#endif
				lck_rw_ilk_lock(&lck->lck_rw);
			}
		}
		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX1_CODE) | DBG_FUNC_END,
			     (int)rlck, lck->lck_rw.lck_rw_shared_cnt, 0, 0, 0);
	}

	lck->lck_rw_deb.pc_excl = __builtin_return_address(0);
	if (LcksOpts & enaLkExtStck)
		lck_rw_ext_backtrace(lck);
	lck->lck_rw_deb.thread = current_thread();

	lck_rw_ilk_unlock(&lck->lck_rw);

#if	CONFIG_DTRACE
	/*
	 * If we've travelled a path with no spin or sleep, then wait_interval
	 * is still zero.
	 */
	if (wait_interval != 0 && wait_interval != (unsigned) -1) {
		if (slept == 0) {
			LOCKSTAT_RECORD2(LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN, lck, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD2(LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK, lck, mach_absolute_time() - wait_interval, 0);
		}
	}
#endif

	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lck, 1);

	return (TRUE);
}

/*
 *      Routine:        lck_rw_lock_exclusive_to_shared_ext
 */
void
lck_rw_lock_exclusive_to_shared_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck)
{
	boolean_t	   do_wakeup = FALSE;

	lck_rw_check_type(lck, rlck);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_START,
			     (int)rlck, lck->lck_rw.lck_rw_want_excl, lck->lck_rw.lck_rw_want_upgrade, 0, 0);

	lck_rw_ilk_lock(&lck->lck_rw);

	lck->lck_rw.lck_rw_shared_cnt++;
	if (lck->lck_rw.lck_rw_want_upgrade)
		lck->lck_rw.lck_rw_want_upgrade = FALSE;
	else if (lck->lck_rw.lck_rw_want_excl)
	 	lck->lck_rw.lck_rw_want_excl = FALSE;
	else
		panic("rw lock (%p) bad state (0x%08X) on attempt to release a shared or exlusive right\n",
			  rlck, lck->lck_rw.lck_rw_tag);
	if (lck->lck_rw_deb.thread == THREAD_NULL)
		panic("rw lock (%p) not held\n",
		      rlck);
	else if ( ((lck->lck_rw_attr & (LCK_RW_ATTR_DEBUG|LCK_RW_ATTR_DIS_THREAD)) == LCK_RW_ATTR_DEBUG) 
		  && (lck->lck_rw_deb.thread != current_thread()))
		panic("rw lock (%p) unlocked by non-owner(%p), current owner(%p)\n",
			  rlck, current_thread(), lck->lck_rw_deb.thread);

	lck->lck_rw_deb.thread = THREAD_NULL;

	if (lck->lck_rw.lck_rw_waiting) {
		lck->lck_rw.lck_rw_waiting = FALSE;
		do_wakeup = TRUE;
	}

	lck_rw_ilk_unlock(&lck->lck_rw);

	if (do_wakeup)
		thread_wakeup((event_t)(((unsigned int*)rlck)+((sizeof(lck_rw_t)-1)/sizeof(unsigned int))));

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_END,
			     (int)rlck, lck->lck_rw.lck_rw_want_excl, lck->lck_rw.lck_rw_want_upgrade, lck->lck_rw.lck_rw_shared_cnt, 0);

	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, lck, 0);
}


/*
 *	Routine:	lck_rw_try_lock_exclusive_ext
 *	Function:
 *		Tries to get a write lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */

boolean_t
lck_rw_try_lock_exclusive_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck)
{
	boolean_t		lock_stat;

	lck_rw_check_type(lck, rlck);

	lck_rw_ilk_lock(&lck->lck_rw);

	lock_stat = (lck->lck_rw_attr & LCK_RW_ATTR_STAT) ? TRUE : FALSE;

	if (lock_stat)
		lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_util_cnt++;

	if (lck->lck_rw.lck_rw_want_excl || lck->lck_rw.lck_rw_want_upgrade || lck->lck_rw.lck_rw_shared_cnt) {
		/*
		 *	Can't get lock.
		 */
		if (lock_stat) {
			lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt++;
		}
		lck_rw_ilk_unlock(&lck->lck_rw);
		return(FALSE);
	}

	/*
	 *	Have lock.
	 */

	lck->lck_rw.lck_rw_want_excl = TRUE;
	lck->lck_rw_deb.pc_excl = __builtin_return_address(0);
	if (LcksOpts & enaLkExtStck)
		lck_rw_ext_backtrace(lck);
	lck->lck_rw_deb.thread = current_thread();

	lck_rw_ilk_unlock(&lck->lck_rw);

	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, lck, 1);

	return(TRUE);
}

/*
 *	Routine:	lck_rw_try_lock_shared_ext
 *	Function:
 *		Tries to get a read lock.
 *
 *		Returns FALSE if the lock is not held on return.
 */

boolean_t
lck_rw_try_lock_shared_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck)
{
	boolean_t		lock_stat;

	lck_rw_check_type(lck, rlck);

	lck_rw_ilk_lock(&lck->lck_rw);

	lock_stat = (lck->lck_rw_attr & LCK_RW_ATTR_STAT) ? TRUE : FALSE;

	if (lock_stat)
		lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_util_cnt++;

	if ((lck->lck_rw.lck_rw_want_excl || lck->lck_rw.lck_rw_want_upgrade) &&
	    ((lck->lck_rw.lck_rw_shared_cnt == 0) || (lck->lck_rw.lck_rw_priv_excl))) {
		if (lock_stat) {
			lck->lck_rw_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt++;
		}
		lck_rw_ilk_unlock(&lck->lck_rw);
		return(FALSE);
	}

	lck->lck_rw.lck_rw_shared_cnt++;

	lck_rw_ilk_unlock(&lck->lck_rw);

	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, lck, 0);

	return(TRUE);
}

void
lck_rw_check_type(
	lck_rw_ext_t	*lck,
	lck_rw_t		*rlck)
{
	if (lck->lck_rw_deb.type != RW_TAG)
		panic("rw lock (%p) not a rw lock type (0x%08X)\n",rlck, lck->lck_rw_deb.type);
}

void
lck_rw_assert_ext(
	lck_rw_ext_t	*lck,
	lck_rw_t	*rlck,
	unsigned int	type)
{
	lck_rw_check_type(lck, rlck);

	switch (type) {
	case LCK_RW_ASSERT_SHARED:
		if (lck->lck_rw.lck_rw_shared_cnt != 0) {
			return;
		}
		break;
	case LCK_RW_ASSERT_EXCLUSIVE:
		if ((lck->lck_rw.lck_rw_want_excl ||
		     lck->lck_rw.lck_rw_want_upgrade) &&
		    lck->lck_rw.lck_rw_shared_cnt == 0) {
			return;
		}
		break;
	case LCK_RW_ASSERT_HELD:
		if (lck->lck_rw.lck_rw_want_excl ||
		    lck->lck_rw.lck_rw_want_upgrade ||
		    lck->lck_rw.lck_rw_shared_cnt != 0) {
			return;
		}
		break;
	default:
		break;
	}

	panic("rw lock (%p -> %p) not held (mode=%u)\n", rlck, lck, type);
}

void
lck_rw_assert(
	lck_rw_t	*lck,
	unsigned int	type)
{
	if (lck->lck_rw_tag != LCK_RW_TAG_INDIRECT) {
		switch (type) {
		case LCK_RW_ASSERT_SHARED:
			if (lck->lck_rw_shared_cnt != 0) {
				return;
			}
			break;
		case LCK_RW_ASSERT_EXCLUSIVE:
			if (lck->lck_rw_shared_cnt == 0 &&
			    (lck->lck_rw_want_excl ||
			     lck->lck_rw_want_upgrade)) {
				return;
			}
			break;
		case LCK_RW_ASSERT_HELD:
			if (lck->lck_rw_shared_cnt != 0 ||
			    lck->lck_rw_want_excl ||
			    lck->lck_rw_want_upgrade) {
				return;
			}
			break;
		default:
			break;
		}
		panic("rw lock (%p) not held (mode=%u)\n", lck, type);
	} else {
		lck_rw_assert_ext((lck_rw_ext_t *)lck->lck_rw_ptr,
				  (lck_rw_t *)lck,
				  type);
	}
}

/*
 * The C portion of the mutex package.  These routines are only invoked
 * if the optimized assembler routines can't do the work.
 */

/*
 * Forward definition 
 */

void lck_mtx_ext_init(
	lck_mtx_ext_t	*lck,
	lck_grp_t	*grp,
	lck_attr_t	*attr);

/*
 *      Routine:        lck_mtx_alloc_init
 */
lck_mtx_t *
lck_mtx_alloc_init(
	lck_grp_t	*grp,
	lck_attr_t	*attr) {
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
	lck_grp_t	*grp) {
	lck_mtx_destroy(lck, grp);
	kfree((void *)lck, sizeof(lck_mtx_t));
}

/*
 *      Routine:        lck_mtx_init
 */
void
lck_mtx_init(
	lck_mtx_t	*lck,
	lck_grp_t	*grp,
	lck_attr_t	*attr) {
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
		lck->lck_mtx_data = 0;
		lck->lck_mtx_waiters = 0;
		lck->lck_mtx_pri = 0;
	}
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
		lck->lck_mtx_data = 0;
		lck->lck_mtx_waiters = 0;
		lck->lck_mtx_pri = 0;
	}
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_MTX);
}

/*
 *      Routine:        lck_mtx_ext_init
 */
void
lck_mtx_ext_init(
	lck_mtx_ext_t	*lck,
	lck_grp_t	*grp,
	lck_attr_t	*attr) {

	bzero((void *)lck, sizeof(lck_mtx_ext_t));

	if ((attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck->lck_mtx_deb.type = MUTEX_TAG;
		lck->lck_mtx_attr |= LCK_MTX_ATTR_DEBUG;
	}

	lck->lck_mtx_grp = grp;

	if (grp->lck_grp_attr & LCK_GRP_ATTR_STAT)
		 lck->lck_mtx_attr |= LCK_MTX_ATTR_STAT;
}

/*
 *      Routine:        lck_mtx_destroy
 */
void
lck_mtx_destroy(
	lck_mtx_t	*lck,
	lck_grp_t	*grp) {
	boolean_t lck_is_indirect;
	
	if (lck->lck_mtx_tag == LCK_MTX_TAG_DESTROYED)
		return;
	lck_is_indirect = (lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT);
	lck->lck_mtx_tag = LCK_MTX_TAG_DESTROYED;
	if (lck_is_indirect)
		kfree((void *)lck->lck_mtx_ptr, sizeof(lck_mtx_ext_t));

	lck_grp_lckcnt_decr(grp, LCK_TYPE_MTX);
	lck_grp_deallocate(grp);
	return;
}


#if	MACH_KDB
/*
 * Routines to print out simple_locks and mutexes in a nicely-formatted
 * fashion.
 */

const char *simple_lock_labels = "ENTRY    ILK THREAD   DURATION CALLER";

void	db_print_simple_lock(
			simple_lock_t	addr);

void
db_show_one_simple_lock (db_expr_t addr, boolean_t have_addr,
			 __unused db_expr_t count,
			 __unused char *modif)
{
	simple_lock_t	saddr = (simple_lock_t)(unsigned long)addr;

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
db_show_one_lock(
	lock_t  *lock)
{
	db_printf("shared_count = 0x%x, %swant_upgrade, %swant_exclusive, ",
		  lock->lck_rw.lck_rw_shared_cnt,
		  lock->lck_rw.lck_rw_want_upgrade ? "" : "!",
		  lock->lck_rw.lck_rw_want_excl ? "" : "!");
	db_printf("%swaiting\n", 
		  lock->lck_rw.lck_rw_waiting ? "" : "!");
	db_printf("%sInterlock\n",
		  lock->lck_rw.lck_rw_interlock ? "" : "!");
}

#endif	/* MACH_KDB */

