/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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

#define ATOMIC_PRIVATE 1
#define LOCK_PRIVATE 1

#include <mach_ldebug.h>
#include <debug.h>

#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach_debug/lockgroup_info.h>

#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>
#include <string.h>


#include <sys/kdebug.h>

#if	CONFIG_DTRACE
/*
 * We need only enough declarations from the BSD-side to be able to
 * test if our probe is active, and to call __dtrace_probe().  Setting
 * NEED_DTRACE_DEFS gets a local copy of those definitions pulled in.
 */
#define NEED_DTRACE_DEFS
#include <../bsd/sys/lockstat.h>
#endif

#define	LCK_MTX_SLEEP_CODE		0
#define	LCK_MTX_SLEEP_DEADLINE_CODE	1
#define	LCK_MTX_LCK_WAIT_CODE		2
#define	LCK_MTX_UNLCK_WAKEUP_CODE	3

#if MACH_LDEBUG
#define ALIGN_TEST(p,t) do{if((uintptr_t)p&(sizeof(t)-1)) __builtin_trap();}while(0)
#else
#define ALIGN_TEST(p,t) do{}while(0)
#endif

/* Silence the volatile to _Atomic cast warning */
#define ATOMIC_CAST(t,p) ((_Atomic t*)(uintptr_t)(p))

/* Enforce program order of loads and stores. */
#define ordered_load(target, type) \
		__c11_atomic_load((_Atomic type *)(target), memory_order_relaxed)
#define ordered_store(target, type, value) \
		__c11_atomic_store((_Atomic type *)(target), value, memory_order_relaxed)

#define ordered_load_hw(lock)			ordered_load(&(lock)->lock_data, uintptr_t)
#define ordered_store_hw(lock, value)	ordered_store(&(lock)->lock_data, uintptr_t, (value))

#define NOINLINE		__attribute__((noinline))


static queue_head_t	lck_grp_queue;
static unsigned int	lck_grp_cnt;

decl_lck_mtx_data(static,lck_grp_lock)
static lck_mtx_ext_t lck_grp_lock_ext;

lck_grp_attr_t	LockDefaultGroupAttr;
lck_grp_t		LockCompatGroup;
lck_attr_t		LockDefaultLckAttr;

/*
 * Routine:	lck_mod_init
 */

void
lck_mod_init(
	void)
{
	/*
	 * Obtain "lcks" options:this currently controls lock statistics
	 */
	if (!PE_parse_boot_argn("lcks", &LcksOpts, sizeof (LcksOpts)))
		LcksOpts = 0;

	queue_init(&lck_grp_queue);
	
	/* 
	 * Need to bootstrap the LockCompatGroup instead of calling lck_grp_init() here. This avoids
	 * grabbing the lck_grp_lock before it is initialized.
	 */
	
	bzero(&LockCompatGroup, sizeof(lck_grp_t));
	(void) strncpy(LockCompatGroup.lck_grp_name, "Compatibility APIs", LCK_GRP_MAX_NAME);
	
	if (LcksOpts & enaLkStat)
		LockCompatGroup.lck_grp_attr = LCK_GRP_ATTR_STAT;
    else
		LockCompatGroup.lck_grp_attr = LCK_ATTR_NONE;
	
	LockCompatGroup.lck_grp_refcnt = 1;
	
	enqueue_tail(&lck_grp_queue, (queue_entry_t)&LockCompatGroup);
	lck_grp_cnt = 1;
	
	lck_grp_attr_setdefault(&LockDefaultGroupAttr);
	lck_attr_setdefault(&LockDefaultLckAttr);
	
	lck_mtx_init_ext(&lck_grp_lock, &lck_grp_lock_ext, &LockCompatGroup, &LockDefaultLckAttr);
	
}

/*
 * Routine:	lck_grp_attr_alloc_init
 */

lck_grp_attr_t	*
lck_grp_attr_alloc_init(
	void)
{
	lck_grp_attr_t	*attr;

	if ((attr = (lck_grp_attr_t *)kalloc(sizeof(lck_grp_attr_t))) != 0)
		lck_grp_attr_setdefault(attr);

	return(attr);
}


/*
 * Routine:	lck_grp_attr_setdefault
 */

void
lck_grp_attr_setdefault(
	lck_grp_attr_t	*attr)
{
	if (LcksOpts & enaLkStat)
		attr->grp_attr_val = LCK_GRP_ATTR_STAT;
	else
		attr->grp_attr_val = 0;
}


/*
 * Routine: 	lck_grp_attr_setstat
 */

void
lck_grp_attr_setstat(
	lck_grp_attr_t	*attr)
{
	(void)hw_atomic_or(&attr->grp_attr_val, LCK_GRP_ATTR_STAT);
}


/*
 * Routine: 	lck_grp_attr_free
 */

void
lck_grp_attr_free(
	lck_grp_attr_t	*attr)
{
	kfree(attr, sizeof(lck_grp_attr_t));
}


/*
 * Routine: lck_grp_alloc_init
 */

lck_grp_t *
lck_grp_alloc_init(
	const char*	grp_name,
	lck_grp_attr_t	*attr)
{
	lck_grp_t	*grp;

	if ((grp = (lck_grp_t *)kalloc(sizeof(lck_grp_t))) != 0)
		lck_grp_init(grp, grp_name, attr);

	return(grp);
}

/*
 * Routine: lck_grp_init
 */

void
lck_grp_init(lck_grp_t * grp, const char * grp_name, lck_grp_attr_t * attr)
{
	/* make sure locking infrastructure has been initialized */
	assert(lck_grp_cnt > 0);

	bzero((void *)grp, sizeof(lck_grp_t));

	(void)strlcpy(grp->lck_grp_name, grp_name, LCK_GRP_MAX_NAME);

	if (attr != LCK_GRP_ATTR_NULL)
		grp->lck_grp_attr = attr->grp_attr_val;
	else if (LcksOpts & enaLkStat)
		grp->lck_grp_attr = LCK_GRP_ATTR_STAT;
	else
		grp->lck_grp_attr = LCK_ATTR_NONE;

	grp->lck_grp_refcnt = 1;

	lck_mtx_lock(&lck_grp_lock);
	enqueue_tail(&lck_grp_queue, (queue_entry_t)grp);
	lck_grp_cnt++;
	lck_mtx_unlock(&lck_grp_lock);
}

/*
 * Routine: 	lck_grp_free
 */

void
lck_grp_free(
	lck_grp_t	*grp)
{
	lck_mtx_lock(&lck_grp_lock);
	lck_grp_cnt--;
	(void)remque((queue_entry_t)grp);
	lck_mtx_unlock(&lck_grp_lock);
	lck_grp_deallocate(grp);
}


/*
 * Routine: 	lck_grp_reference
 */

void
lck_grp_reference(
	lck_grp_t	*grp)
{
	(void)hw_atomic_add(&grp->lck_grp_refcnt, 1);
}


/*
 * Routine: 	lck_grp_deallocate
 */

void
lck_grp_deallocate(
	lck_grp_t	*grp)
{
	if (hw_atomic_sub(&grp->lck_grp_refcnt, 1) == 0)
	 	kfree(grp, sizeof(lck_grp_t));
}

/*
 * Routine:	lck_grp_lckcnt_incr
 */

void
lck_grp_lckcnt_incr(
	lck_grp_t	*grp,
	lck_type_t	lck_type)
{
	unsigned int	*lckcnt;

	switch (lck_type) {
	case LCK_TYPE_SPIN:
		lckcnt = &grp->lck_grp_spincnt;
		break;
	case LCK_TYPE_MTX:
		lckcnt = &grp->lck_grp_mtxcnt;
		break;
	case LCK_TYPE_RW:
		lckcnt = &grp->lck_grp_rwcnt;
		break;
	default:
		return panic("lck_grp_lckcnt_incr(): invalid lock type: %d\n", lck_type);
	}

	(void)hw_atomic_add(lckcnt, 1);
}

/*
 * Routine:	lck_grp_lckcnt_decr
 */

void
lck_grp_lckcnt_decr(
	lck_grp_t	*grp,
	lck_type_t	lck_type)
{
	unsigned int	*lckcnt;
	int		updated;

	switch (lck_type) {
	case LCK_TYPE_SPIN:
		lckcnt = &grp->lck_grp_spincnt;
		break;
	case LCK_TYPE_MTX:
		lckcnt = &grp->lck_grp_mtxcnt;
		break;
	case LCK_TYPE_RW:
		lckcnt = &grp->lck_grp_rwcnt;
		break;
	default:
		panic("lck_grp_lckcnt_decr(): invalid lock type: %d\n", lck_type);
		return;
	}

	updated = (int)hw_atomic_sub(lckcnt, 1);
	assert(updated >= 0);
}

/*
 * Routine:	lck_attr_alloc_init
 */

lck_attr_t *
lck_attr_alloc_init(
	void)
{
	lck_attr_t	*attr;

	if ((attr = (lck_attr_t *)kalloc(sizeof(lck_attr_t))) != 0)
		lck_attr_setdefault(attr);

	return(attr);
}


/*
 * Routine:	lck_attr_setdefault
 */

void
lck_attr_setdefault(
	lck_attr_t	*attr)
{
#if   __i386__ || __x86_64__
#if     !DEBUG
 	if (LcksOpts & enaLkDeb)
 		attr->lck_attr_val =  LCK_ATTR_DEBUG;
 	else
 		attr->lck_attr_val =  LCK_ATTR_NONE;
#else
 	attr->lck_attr_val =  LCK_ATTR_DEBUG;
#endif	/* !DEBUG */
#else
#error Unknown architecture.
#endif	/* __arm__ */
}


/*
 * Routine:	lck_attr_setdebug
 */
void
lck_attr_setdebug(
	lck_attr_t	*attr)
{
	(void)hw_atomic_or(&attr->lck_attr_val, LCK_ATTR_DEBUG);
}

/*
 * Routine:	lck_attr_setdebug
 */
void
lck_attr_cleardebug(
	lck_attr_t	*attr)
{
	(void)hw_atomic_and(&attr->lck_attr_val, ~LCK_ATTR_DEBUG);
}


/*
 * Routine:	lck_attr_rw_shared_priority
 */
void
lck_attr_rw_shared_priority(
	lck_attr_t	*attr)
{
	(void)hw_atomic_or(&attr->lck_attr_val, LCK_ATTR_RW_SHARED_PRIORITY);
}


/*
 * Routine:	lck_attr_free
 */
void
lck_attr_free(
	lck_attr_t	*attr)
{
	kfree(attr, sizeof(lck_attr_t));
}

/*
 * Routine:	hw_lock_init
 *
 *	Initialize a hardware lock.
 */
void
hw_lock_init(hw_lock_t lock)
{
	ordered_store_hw(lock, 0);
}

/*
 *	Routine: hw_lock_lock_contended
 *
 *	Spin until lock is acquired or timeout expires.
 *	timeout is in mach_absolute_time ticks.
 *	MACH_RT:  called with preemption disabled.
 */

#if	__SMP__
static unsigned int NOINLINE
hw_lock_lock_contended(hw_lock_t lock, uintptr_t data, uint64_t timeout, boolean_t do_panic)
{
	uint64_t	end = 0;
	uintptr_t	holder = lock->lock_data;
	int		i;

	if (timeout == 0)
		timeout = LOCK_PANIC_TIMEOUT;

	for ( ; ; ) {	
		for (i = 0; i < LOCK_SNOOP_SPINS; i++) {
			boolean_t	wait = FALSE;

			cpu_pause();
#if (!__ARM_ENABLE_WFE_) || (LOCK_PRETEST)
			holder = ordered_load_hw(lock);
			if (holder != 0)
				continue;
#endif
#if __ARM_ENABLE_WFE_
			wait = TRUE;	// Wait for event
#endif
			if (atomic_compare_exchange(&lock->lock_data, 0, data,
			    memory_order_acquire_smp, wait))
				return 1;
		}
		if (end == 0)
			end = ml_get_timebase() + timeout;
		else if (ml_get_timebase() >= end)
			break;
	}
	if (do_panic) {
		// Capture the actual time spent blocked, which may be higher than the timeout
		// if a misbehaving interrupt stole this thread's CPU time.
		panic("Spinlock timeout after %llu ticks, %p = %lx",
			(ml_get_timebase() - end + timeout), lock, holder);
	}
	return 0;
}
#endif	// __SMP__

/*
 *	Routine: hw_lock_lock
 *
 *	Acquire lock, spinning until it becomes available.
 *	MACH_RT:  also return with preemption disabled.
 */
void
hw_lock_lock(hw_lock_t lock)
{
	thread_t	thread;
	uintptr_t	state;

	thread = current_thread();
	disable_preemption_for_thread(thread);
	state = LCK_MTX_THREAD_TO_STATE(thread) | PLATFORM_LCK_ILOCK;
#if	__SMP__
#if	LOCK_PRETEST
	if (ordered_load_hw(lock))
		goto contended;
#endif	// LOCK_PRETEST
	if (atomic_compare_exchange(&lock->lock_data, 0, state,
					memory_order_acquire_smp, TRUE))
		return;
#if	LOCK_PRETEST
contended:
#endif	// LOCK_PRETEST
	hw_lock_lock_contended(lock, state, 0, TRUE);
#else	// __SMP__
	if (lock->lock_data)
		panic("Spinlock held %p", lock);
	lock->lock_data = state;
#endif	// __SMP__
	return;
}

/*
 *	Routine: hw_lock_to
 *
 *	Acquire lock, spinning until it becomes available or timeout.
 *	timeout is in mach_absolute_time ticks.
 *	MACH_RT:  also return with preemption disabled.
 */
unsigned int
hw_lock_to(hw_lock_t lock, uint64_t timeout)
{
	thread_t	thread;
	uintptr_t	state;

	thread = current_thread();
	disable_preemption_for_thread(thread);
	state = LCK_MTX_THREAD_TO_STATE(thread) | PLATFORM_LCK_ILOCK;
#if	__SMP__
#if	LOCK_PRETEST
	if (ordered_load_hw(lock))
		goto contended;
#endif	// LOCK_PRETEST
	if (atomic_compare_exchange(&lock->lock_data, 0, state,
					memory_order_acquire_smp, TRUE))
		return 1;
#if	LOCK_PRETEST
contended:
#endif	// LOCK_PRETEST
	return hw_lock_lock_contended(lock, state, timeout, FALSE);
#else	// __SMP__
	(void)timeout;
	if (ordered_load_hw(lock) == 0) {
		ordered_store_hw(lock, state);
		return 1;
	}
	return 0;
#endif	// __SMP__
}

/*
 *	Routine: hw_lock_try
 *	MACH_RT:  returns with preemption disabled on success.
 */
unsigned int
hw_lock_try(hw_lock_t lock)
{
	thread_t	thread = current_thread();
	int		success = 0;
#if	LOCK_TRY_DISABLE_INT
	long		intmask;

	intmask = disable_interrupts();
#else
	disable_preemption_for_thread(thread);
#endif	// LOCK_TRY_DISABLE_INT

#if	__SMP__
#if	LOCK_PRETEST
	if (ordered_load_hw(lock))
		goto failed;
#endif	// LOCK_PRETEST
	success = atomic_compare_exchange(&lock->lock_data, 0, LCK_MTX_THREAD_TO_STATE(thread) | PLATFORM_LCK_ILOCK,
					memory_order_acquire_smp, FALSE);
#else
	if (lock->lock_data == 0) {
		lock->lock_data = LCK_MTX_THREAD_TO_STATE(thread) | PLATFORM_LCK_ILOCK;
		success = 1;
	}
#endif	// __SMP__

#if	LOCK_TRY_DISABLE_INT
	if (success)
		disable_preemption_for_thread(thread);
#if	LOCK_PRETEST
failed:
#endif	// LOCK_PRETEST
	restore_interrupts(intmask);
#else
#if	LOCK_PRETEST
failed:
#endif	// LOCK_PRETEST
	if (!success)
		enable_preemption();
#endif	// LOCK_TRY_DISABLE_INT
	return success;
}

/*
 *	Routine: hw_lock_unlock
 *
 *	Unconditionally release lock.
 *	MACH_RT:  release preemption level.
 */
void
hw_lock_unlock(hw_lock_t lock)
{
	__c11_atomic_store((_Atomic uintptr_t *)&lock->lock_data, 0, memory_order_release_smp);
	enable_preemption();
}

/*
 *	RoutineL hw_lock_held
 *	MACH_RT:  doesn't change preemption state.
 *	N.B.  Racy, of course.
 */
unsigned int
hw_lock_held(hw_lock_t lock)
{
	return (ordered_load_hw(lock) != 0);
}

/*
 * Routine:	lck_spin_sleep
 */
wait_result_t
lck_spin_sleep(
        lck_spin_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible)
{
	wait_result_t	res;
 
	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK))
			lck_spin_lock(lck);
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		lck_spin_unlock(lck);

	return res;
}


/*
 * Routine:	lck_spin_sleep_deadline
 */
wait_result_t
lck_spin_sleep_deadline(
        lck_spin_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible,
	uint64_t		deadline)
{
	wait_result_t   res;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK))
			lck_spin_lock(lck);
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		lck_spin_unlock(lck);

	return res;
}


/*
 * Routine:	lck_mtx_clear_promoted
 *
 * Handle clearing of TH_SFLAG_PROMOTED,
 * adjusting thread priority as needed.
 *
 * Called with thread lock held
 */
static void
lck_mtx_clear_promoted (
	thread_t 			thread,
	__kdebug_only uintptr_t		trace_lck)
{
	thread->sched_flags &= ~TH_SFLAG_PROMOTED;

	if (thread->sched_flags & TH_SFLAG_RW_PROMOTED) {
		/* Thread still has a RW lock promotion */
	} else if (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) {
		KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_DEMOTE) | DBG_FUNC_NONE,
				thread->sched_pri, DEPRESSPRI, 0, trace_lck, 0);
		set_sched_pri(thread, DEPRESSPRI);
	} else {
		if (thread->base_pri < thread->sched_pri) {
			KERNEL_DEBUG_CONSTANT(
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_DEMOTE) | DBG_FUNC_NONE,
					thread->sched_pri, thread->base_pri, 0, trace_lck, 0);
		}
		thread_recompute_sched_pri(thread, FALSE);
	}
}


/*
 * Routine:	lck_mtx_sleep
 */
wait_result_t
lck_mtx_sleep(
        lck_mtx_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible)
{
	wait_result_t	res;
	thread_t		thread = current_thread();
 
	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_START,
		     VM_KERNEL_UNSLIDE_OR_PERM(lck), (int)lck_sleep_action, VM_KERNEL_UNSLIDE_OR_PERM(event), (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * We overload the RW lock promotion to give us a priority ceiling
		 * during the time that this thread is asleep, so that when it
		 * is re-awakened (and not yet contending on the mutex), it is
		 * runnable at a reasonably high priority.
		 */
		thread->rwlock_count++;
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if ((lck_sleep_action & LCK_SLEEP_SPIN))
				lck_mtx_lock_spin(lck);
			else
				lck_mtx_lock(lck);
		}
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		lck_mtx_unlock(lck);

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		if ((thread->rwlock_count-- == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
			/* sched_flags checked without lock, but will be rechecked while clearing */
			lck_rw_clear_promotion(thread);
		}
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}


/*
 * Routine:	lck_mtx_sleep_deadline
 */
wait_result_t
lck_mtx_sleep_deadline(
        lck_mtx_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible,
	uint64_t		deadline)
{
	wait_result_t   res;
	thread_t		thread = current_thread();

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_START,
		     VM_KERNEL_UNSLIDE_OR_PERM(lck), (int)lck_sleep_action, VM_KERNEL_UNSLIDE_OR_PERM(event), (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * See lck_mtx_sleep().
		 */
		thread->rwlock_count++;
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if ((lck_sleep_action & LCK_SLEEP_SPIN))
				lck_mtx_lock_spin(lck);
			else
				lck_mtx_lock(lck);
		}
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		lck_mtx_unlock(lck);

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		if ((thread->rwlock_count-- == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
			/* sched_flags checked without lock, but will be rechecked while clearing */
			lck_rw_clear_promotion(thread);
		}
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}

/*
 * Routine: 	lck_mtx_lock_wait
 *
 * Invoked in order to wait on contention.
 *
 * Called with the interlock locked and
 * returns it unlocked.
 */
void
lck_mtx_lock_wait (
	lck_mtx_t			*lck,
	thread_t			holder)
{
	thread_t		self = current_thread();
	lck_mtx_t		*mutex;
	__kdebug_only uintptr_t	trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);
	__kdebug_only uintptr_t	trace_holder = VM_KERNEL_UNSLIDE_OR_PERM(holder);
	integer_t		priority;
	spl_t			s = splsched();
#if	CONFIG_DTRACE
	uint64_t		sleep_start = 0;

	if (lockstat_probemap[LS_LCK_MTX_LOCK_BLOCK] || lockstat_probemap[LS_LCK_MTX_EXT_LOCK_BLOCK]) {
		sleep_start = mach_absolute_time();
	}
#endif

	if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)
		mutex = lck;
	else
		mutex = &lck->lck_mtx_ptr->lck_mtx;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_START, trace_lck, trace_holder, 0, 0, 0);

	priority = self->sched_pri;
	if (priority < self->base_pri)
		priority = self->base_pri;
	if (priority < BASEPRI_DEFAULT)
		priority = BASEPRI_DEFAULT;

	/* Do not promote past promotion ceiling */
	priority = MIN(priority, MAXPRI_PROMOTE);

	thread_lock(holder);
	if (mutex->lck_mtx_pri == 0) {
		holder->promotions++;
		holder->sched_flags |= TH_SFLAG_PROMOTED;
	}

	if (mutex->lck_mtx_pri < priority && holder->sched_pri < priority) {
		KERNEL_DEBUG_CONSTANT(
			MACHDBG_CODE(DBG_MACH_SCHED,MACH_PROMOTE) | DBG_FUNC_NONE,
					holder->sched_pri, priority, trace_holder, trace_lck, 0);
		set_sched_pri(holder, priority);
	}
	thread_unlock(holder);
	splx(s);

	if (mutex->lck_mtx_pri < priority)
		mutex->lck_mtx_pri = priority;
	if (self->pending_promoter[self->pending_promoter_index] == NULL) {
		self->pending_promoter[self->pending_promoter_index] = mutex;
		mutex->lck_mtx_waiters++;
	}
	else
	if (self->pending_promoter[self->pending_promoter_index] != mutex) {
		self->pending_promoter[++self->pending_promoter_index] = mutex;
		mutex->lck_mtx_waiters++;
	}

	assert_wait(LCK_MTX_EVENT(mutex), THREAD_UNINT);
	lck_mtx_ilk_unlock(mutex);

	thread_block(THREAD_CONTINUE_NULL);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
#if	CONFIG_DTRACE
	/*
	 * Record the Dtrace lockstat probe for blocking, block time
	 * measured from when we were entered.
	 */
	if (sleep_start) {
		if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT) {
			LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_BLOCK, lck,
			    mach_absolute_time() - sleep_start);
		} else {
			LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_BLOCK, lck,
			    mach_absolute_time() - sleep_start);
		}
	}
#endif
}

/*
 * Routine: 	lck_mtx_lock_acquire
 *
 * Invoked on acquiring the mutex when there is
 * contention.
 *
 * Returns the current number of waiters.
 *
 * Called with the interlock locked.
 */
int
lck_mtx_lock_acquire(
	lck_mtx_t		*lck)
{
	thread_t		thread = current_thread();
	lck_mtx_t		*mutex;
	integer_t		priority;
	spl_t			s;
	__kdebug_only uintptr_t	trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);

	if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)
		mutex = lck;
	else
		mutex = &lck->lck_mtx_ptr->lck_mtx;

	if (thread->pending_promoter[thread->pending_promoter_index] == mutex) {
		thread->pending_promoter[thread->pending_promoter_index] = NULL;
		if (thread->pending_promoter_index > 0)
			thread->pending_promoter_index--;
		mutex->lck_mtx_waiters--;
	}

	if (mutex->lck_mtx_waiters)
		priority = mutex->lck_mtx_pri;
	else {
		mutex->lck_mtx_pri = 0;
		priority = 0;
	}

	if (priority || thread->was_promoted_on_wakeup) {
		s = splsched();
		thread_lock(thread);

		if (priority) {
			thread->promotions++;
			thread->sched_flags |= TH_SFLAG_PROMOTED;
			if (thread->sched_pri < priority) {
				KERNEL_DEBUG_CONSTANT(
					MACHDBG_CODE(DBG_MACH_SCHED,MACH_PROMOTE) | DBG_FUNC_NONE,
							thread->sched_pri, priority, 0, trace_lck, 0);
				/* Do not promote past promotion ceiling */
				assert(priority <= MAXPRI_PROMOTE);
				set_sched_pri(thread, priority);
			}
		}
		if (thread->was_promoted_on_wakeup) {
			thread->was_promoted_on_wakeup = 0;
			if (thread->promotions == 0)
				lck_mtx_clear_promoted(thread, trace_lck);
		}

		thread_unlock(thread);
		splx(s);
	}

#if CONFIG_DTRACE
	if (lockstat_probemap[LS_LCK_MTX_LOCK_ACQUIRE] || lockstat_probemap[LS_LCK_MTX_EXT_LOCK_ACQUIRE]) {
		if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT) {
			LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, lck, 0);
		} else {
			LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_ACQUIRE, lck, 0);
		}
	}
#endif	
	return (mutex->lck_mtx_waiters);
}

/*
 * Routine: 	lck_mtx_unlock_wakeup
 *
 * Invoked on unlock when there is contention.
 *
 * Called with the interlock locked.
 */
void
lck_mtx_unlock_wakeup (
	lck_mtx_t			*lck,
	thread_t			holder)
{
	thread_t		thread = current_thread();
	lck_mtx_t		*mutex;
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);

	if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)
		mutex = lck;
	else
		mutex = &lck->lck_mtx_ptr->lck_mtx;

	if (thread != holder)
		panic("lck_mtx_unlock_wakeup: mutex %p holder %p\n", mutex, holder);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_START, trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(holder), 0, 0, 0);

	assert(mutex->lck_mtx_waiters > 0);
	if (mutex->lck_mtx_waiters > 1)
		thread_wakeup_one_with_pri(LCK_MTX_EVENT(lck), lck->lck_mtx_pri);
	else
		thread_wakeup_one(LCK_MTX_EVENT(lck));

	if (thread->promotions > 0) {
		spl_t		s = splsched();

		thread_lock(thread);
		if (--thread->promotions == 0 && (thread->sched_flags & TH_SFLAG_PROMOTED))
			lck_mtx_clear_promoted(thread, trace_lck);
		thread_unlock(thread);
		splx(s);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

void
lck_mtx_unlockspin_wakeup (
	lck_mtx_t			*lck)
{
	assert(lck->lck_mtx_waiters > 0);
	thread_wakeup_one(LCK_MTX_EVENT(lck));

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_NONE, VM_KERNEL_UNSLIDE_OR_PERM(lck), 0, 0, 1, 0);
#if CONFIG_DTRACE
	/*
	 * When there are waiters, we skip the hot-patch spot in the
	 * fastpath, so we record it here.
	 */
	LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, lck, 0);
#endif
}


/*
 * Routine: 	mutex_pause
 *
 * Called by former callers of simple_lock_pause().
 */
#define MAX_COLLISION_COUNTS	32
#define MAX_COLLISION 	8

unsigned int max_collision_count[MAX_COLLISION_COUNTS];

uint32_t collision_backoffs[MAX_COLLISION] = {
        10, 50, 100, 200, 400, 600, 800, 1000
};


void
mutex_pause(uint32_t collisions)
{
	wait_result_t wait_result;
	uint32_t	back_off;

	if (collisions >= MAX_COLLISION_COUNTS)
	        collisions = MAX_COLLISION_COUNTS - 1;
	max_collision_count[collisions]++;

	if (collisions >= MAX_COLLISION)
	        collisions = MAX_COLLISION - 1;
	back_off = collision_backoffs[collisions];

	wait_result = assert_wait_timeout((event_t)mutex_pause, THREAD_UNINT, back_off, NSEC_PER_USEC);
	assert(wait_result == THREAD_WAITING);

	wait_result = thread_block(THREAD_CONTINUE_NULL);
	assert(wait_result == THREAD_TIMED_OUT);
}


unsigned int mutex_yield_wait = 0;
unsigned int mutex_yield_no_wait = 0;

void
lck_mtx_yield(
	    lck_mtx_t	*lck)
{
	int	waiters;
	
#if DEBUG
	lck_mtx_assert(lck, LCK_MTX_ASSERT_OWNED);
#endif /* DEBUG */
	
	if (lck->lck_mtx_tag == LCK_MTX_TAG_INDIRECT)
	        waiters = lck->lck_mtx_ptr->lck_mtx.lck_mtx_waiters;
	else
	        waiters = lck->lck_mtx_waiters;

	if ( !waiters) {
	        mutex_yield_no_wait++;
	} else {
	        mutex_yield_wait++;
		lck_mtx_unlock(lck);
		mutex_pause(0);
		lck_mtx_lock(lck);
	}
}


/*
 * Routine:	lck_rw_sleep
 */
wait_result_t
lck_rw_sleep(
        lck_rw_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible)
{
	wait_result_t	res;
	lck_rw_type_t	lck_rw_type;
	thread_t		thread = current_thread();

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		/*
		 * Although we are dropping the RW lock, the intent in most cases
		 * is that this thread remains as an observer, since it may hold
		 * some secondary resource, but must yield to avoid deadlock. In
		 * this situation, make sure that the thread is boosted to the
		 * RW lock ceiling while blocked, so that it can re-acquire the
		 * RW lock at that priority.
		 */
		thread->rwlock_count++;
	}

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_rw_type = lck_rw_done(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if (!(lck_sleep_action & (LCK_SLEEP_SHARED|LCK_SLEEP_EXCLUSIVE)))
				lck_rw_lock(lck, lck_rw_type);
			else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE)
				lck_rw_lock_exclusive(lck);
			else
				lck_rw_lock_shared(lck);
		}
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		(void)lck_rw_done(lck);

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		if ((thread->rwlock_count-- == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
			/* sched_flags checked without lock, but will be rechecked while clearing */

			/* Only if the caller wanted the lck_rw_t returned unlocked should we drop to 0 */
			assert(lck_sleep_action & LCK_SLEEP_UNLOCK);

			lck_rw_clear_promotion(thread);
		}
	}

	return res;
}


/*
 * Routine:	lck_rw_sleep_deadline
 */
wait_result_t
lck_rw_sleep_deadline(
	lck_rw_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible,
	uint64_t		deadline)
{
	wait_result_t   res;
	lck_rw_type_t	lck_rw_type;
	thread_t		thread = current_thread();

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		thread->rwlock_count++;
	}

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_rw_type = lck_rw_done(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if (!(lck_sleep_action & (LCK_SLEEP_SHARED|LCK_SLEEP_EXCLUSIVE)))
				lck_rw_lock(lck, lck_rw_type);
			else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE)
				lck_rw_lock_exclusive(lck);
			else
				lck_rw_lock_shared(lck);
		}
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		(void)lck_rw_done(lck);

	if (lck_sleep_action & LCK_SLEEP_PROMOTED_PRI) {
		if ((thread->rwlock_count-- == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
			/* sched_flags checked without lock, but will be rechecked while clearing */

			/* Only if the caller wanted the lck_rw_t returned unlocked should we drop to 0 */
			assert(lck_sleep_action & LCK_SLEEP_UNLOCK);

			lck_rw_clear_promotion(thread);
		}
	}

	return res;
}

/*
 * Reader-writer lock promotion
 *
 * We support a limited form of reader-writer
 * lock promotion whose effects are:
 * 
 *   * Qualifying threads have decay disabled
 *   * Scheduler priority is reset to a floor of
 *     of their statically assigned priority
 *     or BASEPRI_BACKGROUND
 *
 * The rationale is that lck_rw_ts do not have
 * a single owner, so we cannot apply a directed
 * priority boost from all waiting threads
 * to all holding threads without maintaining
 * lists of all shared owners and all waiting
 * threads for every lock.
 *
 * Instead (and to preserve the uncontended fast-
 * path), acquiring (or attempting to acquire)
 * a RW lock in shared or exclusive lock increments
 * a per-thread counter. Only if that thread stops
 * making forward progress (for instance blocking
 * on a mutex, or being preempted) do we consult
 * the counter and apply the priority floor.
 * When the thread becomes runnable again (or in
 * the case of preemption it never stopped being
 * runnable), it has the priority boost and should
 * be in a good position to run on the CPU and
 * release all RW locks (at which point the priority
 * boost is cleared).
 *
 * Care must be taken to ensure that priority
 * boosts are not retained indefinitely, since unlike
 * mutex priority boosts (where the boost is tied
 * to the mutex lifecycle), the boost is tied
 * to the thread and independent of any particular
 * lck_rw_t. Assertions are in place on return
 * to userspace so that the boost is not held
 * indefinitely.
 *
 * The routines that increment/decrement the
 * per-thread counter should err on the side of
 * incrementing any time a preemption is possible
 * and the lock would be visible to the rest of the
 * system as held (so it should be incremented before
 * interlocks are dropped/preemption is enabled, or
 * before a CAS is executed to acquire the lock).
 *
 */

/*
 * lck_rw_clear_promotion: Undo priority promotions when the last RW
 * lock is released by a thread (if a promotion was active)
 */
void lck_rw_clear_promotion(thread_t thread)
{
	assert(thread->rwlock_count == 0);

	/* Cancel any promotions if the thread had actually blocked while holding a RW lock */
	spl_t s = splsched();

	thread_lock(thread);

	if (thread->sched_flags & TH_SFLAG_RW_PROMOTED) {
		thread->sched_flags &= ~TH_SFLAG_RW_PROMOTED;

		if (thread->sched_flags & TH_SFLAG_PROMOTED) {
			/* Thread still has a mutex promotion */
		} else if (thread->sched_flags & TH_SFLAG_DEPRESSED_MASK) {
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_RW_DEMOTE) | DBG_FUNC_NONE,
			                      (uintptr_t)thread_tid(thread), thread->sched_pri, DEPRESSPRI, 0, 0);

			set_sched_pri(thread, DEPRESSPRI);
		} else {
			KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED, MACH_RW_DEMOTE) | DBG_FUNC_NONE,
			                      (uintptr_t)thread_tid(thread), thread->sched_pri, thread->base_pri, 0, 0);

			thread_recompute_sched_pri(thread, FALSE);
		}
	}

	thread_unlock(thread);
	splx(s);
}

/*
 * Callout from context switch if the thread goes
 * off core with a positive rwlock_count
 *
 * Called at splsched with the thread locked
 */
void
lck_rw_set_promotion_locked(thread_t thread)
{
	if (LcksOpts & disLkRWPrio)
		return;

	integer_t priority;

	priority = thread->sched_pri;

	if (priority < thread->base_pri)
		priority = thread->base_pri;
	if (priority < BASEPRI_BACKGROUND)
		priority = BASEPRI_BACKGROUND;

	if ((thread->sched_pri < priority) ||
	    !(thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		KERNEL_DEBUG_CONSTANT(
		        MACHDBG_CODE(DBG_MACH_SCHED, MACH_RW_PROMOTE) | DBG_FUNC_NONE,
		        (uintptr_t)thread_tid(thread), thread->sched_pri,
		        thread->base_pri, priority, 0);

		thread->sched_flags |= TH_SFLAG_RW_PROMOTED;

		if (thread->sched_pri < priority)
			set_sched_pri(thread, priority);
	}
}

kern_return_t
host_lockgroup_info(
	host_t					host,
	lockgroup_info_array_t	*lockgroup_infop,
	mach_msg_type_number_t	*lockgroup_infoCntp)
{
	lockgroup_info_t	*lockgroup_info_base;
	lockgroup_info_t	*lockgroup_info;
	vm_offset_t			lockgroup_info_addr;
	vm_size_t			lockgroup_info_size;
	vm_size_t			lockgroup_info_vmsize;
	lck_grp_t			*lck_grp;
	unsigned int		i;
	vm_map_copy_t		copy;
	kern_return_t		kr;

	if (host == HOST_NULL)
		return KERN_INVALID_HOST;

	lck_mtx_lock(&lck_grp_lock);

	lockgroup_info_size = lck_grp_cnt * sizeof(*lockgroup_info);
	lockgroup_info_vmsize = round_page(lockgroup_info_size);
	kr = kmem_alloc_pageable(ipc_kernel_map,
						 &lockgroup_info_addr, lockgroup_info_vmsize, VM_KERN_MEMORY_IPC);
	if (kr != KERN_SUCCESS) {
		lck_mtx_unlock(&lck_grp_lock);
		return(kr);
	}

	lockgroup_info_base = (lockgroup_info_t *) lockgroup_info_addr;
	lck_grp = (lck_grp_t *)queue_first(&lck_grp_queue);
	lockgroup_info = lockgroup_info_base;

	for (i = 0; i < lck_grp_cnt; i++) {

		lockgroup_info->lock_spin_cnt = lck_grp->lck_grp_spincnt;
		lockgroup_info->lock_spin_util_cnt = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_util_cnt;
		lockgroup_info->lock_spin_held_cnt = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_held_cnt;
		lockgroup_info->lock_spin_miss_cnt = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_miss_cnt;
		lockgroup_info->lock_spin_held_max = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_held_max;
		lockgroup_info->lock_spin_held_cum = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_held_cum;

		lockgroup_info->lock_mtx_cnt = lck_grp->lck_grp_mtxcnt;
		lockgroup_info->lock_mtx_util_cnt = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_util_cnt;
		lockgroup_info->lock_mtx_held_cnt = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_cnt;
		lockgroup_info->lock_mtx_miss_cnt = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_miss_cnt;
		lockgroup_info->lock_mtx_wait_cnt = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_cnt;
		lockgroup_info->lock_mtx_held_max = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_max;
		lockgroup_info->lock_mtx_held_cum = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_cum;
		lockgroup_info->lock_mtx_wait_max = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_max;
		lockgroup_info->lock_mtx_wait_cum = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_cum;

		lockgroup_info->lock_rw_cnt = lck_grp->lck_grp_rwcnt;
		lockgroup_info->lock_rw_util_cnt = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_util_cnt;
		lockgroup_info->lock_rw_held_cnt = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_held_cnt;
		lockgroup_info->lock_rw_miss_cnt = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt;
		lockgroup_info->lock_rw_wait_cnt = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cnt;
		lockgroup_info->lock_rw_held_max = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_held_max;
		lockgroup_info->lock_rw_held_cum = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_held_cum;
		lockgroup_info->lock_rw_wait_max = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_max;
		lockgroup_info->lock_rw_wait_cum = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cum;

		(void) strncpy(lockgroup_info->lockgroup_name,lck_grp->lck_grp_name, LOCKGROUP_MAX_NAME);

		lck_grp = (lck_grp_t *)(queue_next((queue_entry_t)(lck_grp)));
		lockgroup_info++;
	}

	*lockgroup_infoCntp = lck_grp_cnt;
	lck_mtx_unlock(&lck_grp_lock);

	if (lockgroup_info_size != lockgroup_info_vmsize)
		bzero((char *)lockgroup_info, lockgroup_info_vmsize - lockgroup_info_size);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)lockgroup_info_addr,
			   (vm_map_size_t)lockgroup_info_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*lockgroup_infop = (lockgroup_info_t *) copy;

	return(KERN_SUCCESS);
}

/*
 * Atomic primitives, prototyped in kern/simple_lock.h
 * Noret versions are more efficient on some architectures
 */
	
uint32_t
hw_atomic_add(volatile uint32_t *dest, uint32_t delt)
{
	ALIGN_TEST(dest,uint32_t);
	return __c11_atomic_fetch_add(ATOMIC_CAST(uint32_t,dest), delt, memory_order_relaxed) + delt;
}

uint32_t
hw_atomic_sub(volatile uint32_t *dest, uint32_t delt)
{
	ALIGN_TEST(dest,uint32_t);
	return __c11_atomic_fetch_sub(ATOMIC_CAST(uint32_t,dest), delt, memory_order_relaxed) - delt;
}

uint32_t
hw_atomic_or(volatile uint32_t *dest, uint32_t mask)
{
	ALIGN_TEST(dest,uint32_t);
	return __c11_atomic_fetch_or(ATOMIC_CAST(uint32_t,dest), mask, memory_order_relaxed) | mask;
}

void
hw_atomic_or_noret(volatile uint32_t *dest, uint32_t mask)
{
	ALIGN_TEST(dest,uint32_t);
	__c11_atomic_fetch_or(ATOMIC_CAST(uint32_t,dest), mask, memory_order_relaxed);
}

uint32_t
hw_atomic_and(volatile uint32_t *dest, uint32_t mask)
{
	ALIGN_TEST(dest,uint32_t);
	return __c11_atomic_fetch_and(ATOMIC_CAST(uint32_t,dest), mask, memory_order_relaxed) & mask;
}

void
hw_atomic_and_noret(volatile uint32_t *dest, uint32_t mask)
{
	ALIGN_TEST(dest,uint32_t);
	__c11_atomic_fetch_and(ATOMIC_CAST(uint32_t,dest), mask, memory_order_relaxed);
}

uint32_t
hw_compare_and_store(uint32_t oldval, uint32_t newval, volatile uint32_t *dest)
{
	ALIGN_TEST(dest,uint32_t);
	return __c11_atomic_compare_exchange_strong(ATOMIC_CAST(uint32_t,dest), &oldval, newval,
			memory_order_acq_rel_smp, memory_order_relaxed);
}

