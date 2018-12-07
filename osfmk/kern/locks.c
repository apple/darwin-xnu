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
#include <libkern/section_keywords.h>
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

SECURITY_READ_ONLY_LATE(boolean_t) spinlock_timeout_panic = TRUE;

lck_grp_attr_t	LockDefaultGroupAttr;
lck_grp_t		LockCompatGroup;
lck_attr_t		LockDefaultLckAttr;

#if CONFIG_DTRACE && __SMP__
#if defined (__x86_64__)
uint64_t dtrace_spin_threshold = 500; // 500ns
#elif defined(__arm__) || defined(__arm64__)
uint64_t dtrace_spin_threshold = LOCK_PANIC_TIMEOUT / 1000000; // 500ns
#endif
#endif

uintptr_t
unslide_for_kdebug(void* object) {
	if (__improbable(kdebug_enable))
		return VM_KERNEL_UNSLIDE_OR_PERM(object);
	else
		return 0;
}

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


#if (DEVELOPMENT || DEBUG) && defined(__x86_64__)
	if (!PE_parse_boot_argn("-disable_mtx_chk", &LckDisablePreemptCheck, sizeof (LckDisablePreemptCheck)))
		LckDisablePreemptCheck = 0;
#endif /* (DEVELOPMENT || DEBUG) && defined(__x86_64__) */

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
#if __arm__ || __arm64__
	/* <rdar://problem/4404579>: Using LCK_ATTR_DEBUG here causes panic at boot time for arm */
	attr->lck_attr_val =  LCK_ATTR_NONE;
#elif __i386__ || __x86_64__
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
 *	timeout is in mach_absolute_time ticks. Called with
 *	preemption disabled.
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
#if CONFIG_DTRACE
	uint64_t begin;
	boolean_t dtrace_enabled = lockstat_probemap[LS_LCK_SPIN_LOCK_SPIN] != 0;
	if (__improbable(dtrace_enabled))
		begin = mach_absolute_time();
#endif
	for ( ; ; ) {	
		for (i = 0; i < LOCK_SNOOP_SPINS; i++) {
			cpu_pause();
#if (!__ARM_ENABLE_WFE_) || (LOCK_PRETEST)
			holder = ordered_load_hw(lock);
			if (holder != 0)
				continue;
#endif
			if (atomic_compare_exchange(&lock->lock_data, 0, data,
			    memory_order_acquire_smp, TRUE)) {
#if CONFIG_DTRACE
				if (__improbable(dtrace_enabled)) {
					uint64_t spintime = mach_absolute_time() - begin;
					if (spintime > dtrace_spin_threshold)
						LOCKSTAT_RECORD2(LS_LCK_SPIN_LOCK_SPIN, lock, spintime, dtrace_spin_threshold);
				}
#endif
				return 1;
			}
		}
		if (end == 0) {
			end = ml_get_timebase() + timeout;
		}
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

static inline void
hw_lock_lock_internal(hw_lock_t lock, thread_t thread)
{
	uintptr_t	state;

	state = LCK_MTX_THREAD_TO_STATE(thread) | PLATFORM_LCK_ILOCK;
#if	__SMP__

#if	LOCK_PRETEST
	if (ordered_load_hw(lock))
		goto contended;
#endif	// LOCK_PRETEST
	if (atomic_compare_exchange(&lock->lock_data, 0, state,
					memory_order_acquire_smp, TRUE)) {
		goto end;
	}
#if	LOCK_PRETEST
contended:
#endif	// LOCK_PRETEST
	hw_lock_lock_contended(lock, state, 0, spinlock_timeout_panic);
end:
#else	// __SMP__
	if (lock->lock_data)
		panic("Spinlock held %p", lock);
	lock->lock_data = state;
#endif	// __SMP__
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_ACQUIRE, lock, 0);
#endif
	return;
}

/*
 *	Routine: hw_lock_lock
 *
 *	Acquire lock, spinning until it becomes available,
 *	return with preemption disabled.
 */
void
hw_lock_lock(hw_lock_t lock)
{
	thread_t thread = current_thread();
	disable_preemption_for_thread(thread);
	hw_lock_lock_internal(lock, thread);
}

/*
 *	Routine: hw_lock_lock_nopreempt
 *
 *	Acquire lock, spinning until it becomes available.
 */
void
hw_lock_lock_nopreempt(hw_lock_t lock)
{
	thread_t thread = current_thread();
	if (__improbable(!preemption_disabled_for_thread(thread)))
		panic("Attempt to take no-preempt spinlock %p in preemptible context", lock);
	hw_lock_lock_internal(lock, thread);
}

/*
 *	Routine: hw_lock_to
 *
 *	Acquire lock, spinning until it becomes available or timeout.
 *	Timeout is in mach_absolute_time ticks, return with
 *	preemption disabled.
 */
unsigned int
hw_lock_to(hw_lock_t lock, uint64_t timeout)
{
	thread_t	thread;
	uintptr_t	state;
	unsigned int success = 0;

	thread = current_thread();
	disable_preemption_for_thread(thread);
	state = LCK_MTX_THREAD_TO_STATE(thread) | PLATFORM_LCK_ILOCK;
#if	__SMP__

#if	LOCK_PRETEST
	if (ordered_load_hw(lock))
		goto contended;
#endif	// LOCK_PRETEST
	if (atomic_compare_exchange(&lock->lock_data, 0, state,
					memory_order_acquire_smp, TRUE)) {
		success = 1;
		goto end;
	}
#if	LOCK_PRETEST
contended:
#endif	// LOCK_PRETEST
	success = hw_lock_lock_contended(lock, state, timeout, FALSE);
end:
#else	// __SMP__
	(void)timeout;
	if (ordered_load_hw(lock) == 0) {
		ordered_store_hw(lock, state);
		success = 1;
	}
#endif	// __SMP__
#if CONFIG_DTRACE
	if (success)
		LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_ACQUIRE, lock, 0);
#endif
	return success;
}

/*
 *	Routine: hw_lock_try
 *
 *	returns with preemption disabled on success.
 */
static inline unsigned int
hw_lock_try_internal(hw_lock_t lock, thread_t thread)
{
	int		success = 0;

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

#if	LOCK_PRETEST
failed:
#endif	// LOCK_PRETEST
#if CONFIG_DTRACE
	if (success)
		LOCKSTAT_RECORD(LS_LCK_SPIN_LOCK_ACQUIRE, lock, 0);
#endif
	return success;
}

unsigned int
hw_lock_try(hw_lock_t lock)
{
	thread_t thread = current_thread();
	disable_preemption_for_thread(thread);
	unsigned int success = hw_lock_try_internal(lock, thread);
	if (!success)
		enable_preemption();
	return success;
}

unsigned int
hw_lock_try_nopreempt(hw_lock_t lock)
{
	thread_t thread = current_thread();
	if (__improbable(!preemption_disabled_for_thread(thread)))
		panic("Attempt to test no-preempt spinlock %p in preemptible context", lock);
	return hw_lock_try_internal(lock, thread);
}

/*
 *	Routine: hw_lock_unlock
 *
 *	Unconditionally release lock, release preemption level.
 */
static inline void
hw_lock_unlock_internal(hw_lock_t lock)
{
	__c11_atomic_store((_Atomic uintptr_t *)&lock->lock_data, 0, memory_order_release_smp);
#if __arm__ || __arm64__
	// ARM tests are only for open-source exclusion
	set_event();
#endif	// __arm__ || __arm64__
#if	CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_UNLOCK_RELEASE, lock, 0);
#endif /* CONFIG_DTRACE */
}

void
hw_lock_unlock(hw_lock_t lock)
{
	hw_lock_unlock_internal(lock);
	enable_preemption();
}

void
hw_lock_unlock_nopreempt(hw_lock_t lock)
{
	if (__improbable(!preemption_disabled_for_thread(current_thread())))
		panic("Attempt to release no-preempt spinlock %p in preemptible context", lock);
	hw_lock_unlock_internal(lock);
}

/*
 *	Routine hw_lock_held, doesn't change preemption state.
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
			else if ((lck_sleep_action & LCK_SLEEP_SPIN_ALWAYS))
				lck_mtx_lock_spin_always(lck);
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
			lck_rw_clear_promotion(thread, unslide_for_kdebug(event));
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
			lck_rw_clear_promotion(thread, unslide_for_kdebug(event));
		}
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}

/*
 * Lock Boosting Invariants:
 *
 * The lock owner is always promoted to the max priority of all its waiters.
 * Max priority is capped at MAXPRI_PROMOTE.
 *
 * lck_mtx_pri being set implies that the lock owner is promoted to at least lck_mtx_pri
 *      This prevents the thread from dropping in priority while holding a mutex
 *      (note: Intel locks currently don't do this, to avoid thread lock churn)
 *
 * thread->promotions has a +1 for every mutex currently promoting the thread
 * and 1 for was_promoted_on_wakeup being set.
 * TH_SFLAG_PROMOTED is set on a thread whenever it has any promotions
 * from any mutex (i.e. thread->promotions != 0)
 *
 * was_promoted_on_wakeup is set on a thread which is woken up by a mutex when
 * it raises the priority of the woken thread to match lck_mtx_pri.
 * It can be set for multiple iterations of wait, fail to acquire, re-wait, etc
 * was_promoted_on_wakeup being set always implies a +1 promotions count.
 *
 * The last waiter is not given a promotion when it wakes up or acquires the lock.
 * When the last waiter is waking up, a new contender can always come in and
 * steal the lock without having to wait for the last waiter to make forward progress.
 *
 * lck_mtx_waiters has a +1 for every waiter currently between wait and acquire
 * This prevents us from asserting that every wakeup wakes up a thread.
 * This also causes excess thread_wakeup calls in the unlock path.
 * It can only be fooled into thinking there are more waiters than are
 * actually blocked, not less.
 * It does allows us to reduce the complexity of the lock state.
 *
 * This also means that a starved bg thread as the last waiter could end up
 * keeping the lock in the contended state for a long period of time, which
 * may keep lck_mtx_pri artificially high for a very long time even though
 * it is not participating or blocking anyone else.
 * Intel locks don't have this problem because they can go uncontended
 * as soon as there are no blocked threads involved.
 */

/*
 * Routine: lck_mtx_lock_wait
 *
 * Invoked in order to wait on contention.
 *
 * Called with the interlock locked and
 * returns it unlocked.
 *
 * Always aggressively sets the owning thread to promoted,
 * even if it's the same or higher priority
 * This prevents it from lowering its own priority while holding a lock
 *
 * TODO: Come up with a more efficient way to handle same-priority promotions
 *      <rdar://problem/30737670> ARM mutex contention logic could avoid taking the thread lock
 */
void
lck_mtx_lock_wait (
	lck_mtx_t			*lck,
	thread_t			holder)
{
	thread_t		self = current_thread();
	lck_mtx_t		*mutex;
	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(lck);

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

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_START,
	             trace_lck, (uintptr_t)thread_tid(thread), 0, 0, 0);

	spl_t s = splsched();
	thread_lock(holder);

	assert_promotions_invariant(holder);

	if ((holder->sched_flags & TH_SFLAG_DEPRESS) == 0)
		assert(holder->sched_pri >= mutex->lck_mtx_pri);

	integer_t priority = self->sched_pri;
	priority = MAX(priority, self->base_pri);
	priority = MAX(priority, BASEPRI_DEFAULT);
	priority = MIN(priority, MAXPRI_PROMOTE);

	if (mutex->lck_mtx_pri == 0) {
		/* This is the first promotion for this mutex */
		if (holder->promotions++ == 0) {
			/* This is the first promotion for holder */
			sched_thread_promote_to_pri(holder, priority, trace_lck);
		} else {
			/* Holder was previously promoted due to a different mutex, raise to match this one */
			sched_thread_update_promotion_to_pri(holder, priority, trace_lck);
		}
	} else {
		/* Holder was previously promoted due to this mutex, check if the pri needs to go up */
		sched_thread_update_promotion_to_pri(holder, priority, trace_lck);
	}

	assert(holder->promotions > 0);
	assert(holder->promotion_priority >= priority);

	if ((holder->sched_flags & TH_SFLAG_DEPRESS) == 0)
		assert(holder->sched_pri >= mutex->lck_mtx_pri);

	assert_promotions_invariant(holder);

	thread_unlock(holder);
	splx(s);

	if (mutex->lck_mtx_pri < priority)
		mutex->lck_mtx_pri = priority;

	if (self->waiting_for_mutex == NULL) {
		self->waiting_for_mutex = mutex;
		mutex->lck_mtx_waiters++;
	}

	assert(self->waiting_for_mutex == mutex);

	thread_set_pending_block_hint(self, kThreadWaitKernelMutex);
	assert_wait(LCK_MTX_EVENT(mutex), THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
	lck_mtx_ilk_unlock(mutex);

	thread_block(THREAD_CONTINUE_NULL);

	assert(mutex->lck_mtx_waiters > 0);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
#if	CONFIG_DTRACE
	/*
	 * Record the DTrace lockstat probe for blocking, block time
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

	if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)
		mutex = lck;
	else
		mutex = &lck->lck_mtx_ptr->lck_mtx;

	/*
	 * If waiting_for_mutex is set, then this thread was previously blocked waiting on this lock
	 * If it's un-set, then this thread stole the lock from another waiter.
	 */
	if (thread->waiting_for_mutex == mutex) {
		assert(mutex->lck_mtx_waiters > 0);

		thread->waiting_for_mutex = NULL;
		mutex->lck_mtx_waiters--;
	}

	assert(thread->waiting_for_mutex == NULL);

	if (mutex->lck_mtx_waiters > 0) {
		priority = mutex->lck_mtx_pri;
	} else {
		/* I was the last waiter, so the mutex is no longer promoted or contended */
		mutex->lck_mtx_pri = 0;
		priority = 0;
	}

	if (priority || thread->was_promoted_on_wakeup) {
		__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(lck);

		/*
		 * Note: was_promoted_on_wakeup can happen for multiple wakeups in a row without
		 * an intervening acquire if a thread keeps failing to acquire the lock
		 *
		 * If priority is true but not promoted on wakeup,
		 * then this is a lock steal of a promoted mutex, so it needs a ++ of promotions.
		 *
		 * If promoted on wakeup is true, but priority is not,
		 * then this is the last owner, and the last owner does not need a promotion.
		 */

		spl_t s = splsched();
		thread_lock(thread);

		assert_promotions_invariant(thread);

		if (thread->was_promoted_on_wakeup)
			assert(thread->promotions > 0);

		if (priority) {
			if (thread->promotions++ == 0) {
				/* This is the first promotion for holder */
				sched_thread_promote_to_pri(thread, priority, trace_lck);
			} else {
				/*
				 * Holder was previously promoted due to a different mutex, raise to match this one
				 * Or, this thread was promoted on wakeup but someone else later contended on mutex
				 * at higher priority before we got here
				 */
				sched_thread_update_promotion_to_pri(thread, priority, trace_lck);
			}
		}

		if (thread->was_promoted_on_wakeup) {
			thread->was_promoted_on_wakeup = 0;
			if (--thread->promotions == 0)
				sched_thread_unpromote(thread, trace_lck);
		}

		assert_promotions_invariant(thread);

		if (priority && (thread->sched_flags & TH_SFLAG_DEPRESS) == 0)
			assert(thread->sched_pri >= priority);

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
 *
 * TODO: the 'waiters' flag does not indicate waiters exist on the waitqueue,
 * it indicates waiters exist between wait and acquire.
 * This means that here we may do extra unneeded wakeups.
 */
void
lck_mtx_unlock_wakeup (
	lck_mtx_t			*lck,
	thread_t			holder)
{
	thread_t		thread = current_thread();
	lck_mtx_t		*mutex;
	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(lck);

	if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)
		mutex = lck;
	else
		mutex = &lck->lck_mtx_ptr->lck_mtx;

	if (thread != holder)
		panic("lck_mtx_unlock_wakeup: mutex %p holder %p\n", mutex, holder);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_START,
	             trace_lck, (uintptr_t)thread_tid(thread), 0, 0, 0);

	assert(mutex->lck_mtx_waiters > 0);
	assert(thread->was_promoted_on_wakeup == 0);
	assert(thread->waiting_for_mutex == NULL);

	/*
	 * The waiters count does not precisely match the number of threads on the waitqueue,
	 * therefore we cannot assert that we actually wake up a thread here
	 */
	if (mutex->lck_mtx_waiters > 1)
		thread_wakeup_one_with_pri(LCK_MTX_EVENT(lck), lck->lck_mtx_pri);
	else
		thread_wakeup_one(LCK_MTX_EVENT(lck));

	/* When mutex->lck_mtx_pri is set, it means means I as the owner have a promotion. */
	if (mutex->lck_mtx_pri) {
		spl_t s = splsched();
		thread_lock(thread);

		assert(thread->promotions > 0);

		assert_promotions_invariant(thread);

		if (--thread->promotions == 0)
			sched_thread_unpromote(thread, trace_lck);

		assert_promotions_invariant(thread);

		thread_unlock(thread);
		splx(s);
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

/*
 * Callout from the waitqueue code from inside thread_wakeup_one_with_pri
 * At splsched, thread is pulled from waitq, still locked, not on runqueue yet
 *
 * We always make sure to set the promotion flag, even if the thread is already at this priority,
 * so that it doesn't go down.
 */
void
lck_mtx_wakeup_adjust_pri(thread_t thread, integer_t priority)
{
	assert(priority <= MAXPRI_PROMOTE);
	assert(thread->waiting_for_mutex != NULL);

	__kdebug_only uintptr_t trace_lck = unslide_for_kdebug(thread->waiting_for_mutex);

	assert_promotions_invariant(thread);

	if (thread->was_promoted_on_wakeup) {
		/* Thread was previously promoted, but contended again */
		sched_thread_update_promotion_to_pri(thread, priority, trace_lck);
		return;
	}

	if (thread->promotions > 0 && priority <= thread->promotion_priority) {
		/*
		 * Thread is already promoted to the right level, no need to do more
		 * I can draft off of another promotion here, which is OK
		 * because I know the thread will soon run acquire to get its own promotion
		 */
		assert((thread->sched_flags & TH_SFLAG_PROMOTED) == TH_SFLAG_PROMOTED);
		return;
	}

	thread->was_promoted_on_wakeup = 1;

	if (thread->promotions++ == 0) {
		/* This is the first promotion for this thread */
		sched_thread_promote_to_pri(thread, priority, trace_lck);
	} else {
		/* Holder was previously promoted due to a different mutex, raise to match this one */
		sched_thread_update_promotion_to_pri(thread, priority, trace_lck);
	}

	assert_promotions_invariant(thread);
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

			lck_rw_clear_promotion(thread, unslide_for_kdebug(event));
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

			lck_rw_clear_promotion(thread, unslide_for_kdebug(event));
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
 *     or MINPRI_RWLOCK
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
void lck_rw_clear_promotion(thread_t thread, uintptr_t trace_obj)
{
	assert(thread->rwlock_count == 0);

	/* Cancel any promotions if the thread had actually blocked while holding a RW lock */
	spl_t s = splsched();
	thread_lock(thread);

	if (thread->sched_flags & TH_SFLAG_RW_PROMOTED)
		sched_thread_unpromote_reason(thread, TH_SFLAG_RW_PROMOTED, trace_obj);

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

	assert(thread->rwlock_count > 0);

	if (!(thread->sched_flags & TH_SFLAG_RW_PROMOTED))
		sched_thread_promote_reason(thread, TH_SFLAG_RW_PROMOTED, 0);
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

