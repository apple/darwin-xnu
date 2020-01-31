/*
 * Copyright (c) 2007-2017 Apple Inc. All rights reserved.
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
 * Mach Operating System Copyright (c) 1991,1990,1989,1988,1987 Carnegie
 * Mellon University All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright notice
 * and this permission notice appear in all copies of the software,
 * derivative works or modified versions, and any portions thereof, and that
 * both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" CONDITION.
 * CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR ANY DAMAGES
 * WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 * Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 * School of Computer Science Carnegie Mellon University Pittsburgh PA
 * 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon the
 * rights to redistribute these changes.
 */
/*
 *	File:	kern/lock.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Locking primitives implementation
 */

#define ATOMIC_PRIVATE 1
#define LOCK_PRIVATE 1

#include <mach_ldebug.h>

#include <kern/kalloc.h>
#include <kern/lock_stat.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/xpr.h>
#include <kern/debug.h>
#include <kern/kcdata.h>
#include <string.h>

#include <arm/cpu_data_internal.h>
#include <arm/proc_reg.h>
#include <arm/smp.h>
#include <machine/atomic.h>
#include <machine/machine_cpu.h>

#include <sys/kdebug.h>

#if CONFIG_DTRACE
#define DTRACE_RW_SHARED        0x0     //reader
#define DTRACE_RW_EXCL          0x1     //writer
#define DTRACE_NO_FLAG          0x0     //not applicable
#endif  /* CONFIG_DTRACE */

#define LCK_RW_LCK_EXCLUSIVE_CODE       0x100
#define LCK_RW_LCK_EXCLUSIVE1_CODE      0x101
#define LCK_RW_LCK_SHARED_CODE          0x102
#define LCK_RW_LCK_SH_TO_EX_CODE        0x103
#define LCK_RW_LCK_SH_TO_EX1_CODE       0x104
#define LCK_RW_LCK_EX_TO_SH_CODE        0x105


#define ANY_LOCK_DEBUG  (USLOCK_DEBUG || LOCK_DEBUG || MUTEX_DEBUG)

// Panic in tests that check lock usage correctness
// These are undesirable when in a panic or a debugger is runnning.
#define LOCK_CORRECTNESS_PANIC() (kernel_debugger_entry_count == 0)

unsigned int    LcksOpts = 0;

#define ADAPTIVE_SPIN_ENABLE 0x1

#if __SMP__
int lck_mtx_adaptive_spin_mode = ADAPTIVE_SPIN_ENABLE;
#else /* __SMP__ */
int lck_mtx_adaptive_spin_mode = 0;
#endif /* __SMP__ */

#define SPINWAIT_OWNER_CHECK_COUNT 4

typedef enum {
	SPINWAIT_ACQUIRED,     /* Got the lock. */
	SPINWAIT_INTERLOCK,    /* Got the interlock, no owner, but caller must finish acquiring the lock. */
	SPINWAIT_DID_SPIN,     /* Got the interlock, spun, but failed to get the lock. */
	SPINWAIT_DID_NOT_SPIN, /* Got the interlock, did not spin. */
} spinwait_result_t;

#if CONFIG_DTRACE && __SMP__
extern uint64_t dtrace_spin_threshold;
#endif

/* Forwards */


#if     USLOCK_DEBUG
/*
 *	Perform simple lock checks.
 */
int             uslock_check = 1;
int             max_lock_loops = 100000000;
decl_simple_lock_data(extern, printf_lock)
decl_simple_lock_data(extern, panic_lock)
#endif                          /* USLOCK_DEBUG */

extern unsigned int not_in_kdp;

/*
 *	We often want to know the addresses of the callers
 *	of the various lock routines.  However, this information
 *	is only used for debugging and statistics.
 */
typedef void   *pc_t;
#define INVALID_PC      ((void *) VM_MAX_KERNEL_ADDRESS)
#define INVALID_THREAD  ((void *) VM_MAX_KERNEL_ADDRESS)

#ifdef  lint
/*
 *	Eliminate lint complaints about unused local pc variables.
 */
#define OBTAIN_PC(pc, l) ++pc
#else                           /* lint */
#define OBTAIN_PC(pc, l)
#endif                          /* lint */


/*
 *	Portable lock package implementation of usimple_locks.
 */

#if     USLOCK_DEBUG
#define USLDBG(stmt)    stmt
void            usld_lock_init(usimple_lock_t, unsigned short);
void            usld_lock_pre(usimple_lock_t, pc_t);
void            usld_lock_post(usimple_lock_t, pc_t);
void            usld_unlock(usimple_lock_t, pc_t);
void            usld_lock_try_pre(usimple_lock_t, pc_t);
void            usld_lock_try_post(usimple_lock_t, pc_t);
int             usld_lock_common_checks(usimple_lock_t, const char *);
#else                           /* USLOCK_DEBUG */
#define USLDBG(stmt)
#endif                          /* USLOCK_DEBUG */

/*
 * Owner thread pointer when lock held in spin mode
 */
#define LCK_MTX_SPIN_TAG  0xfffffff0


#define interlock_lock(lock)    hw_lock_bit    ((hw_lock_bit_t*)(&(lock)->lck_mtx_data), LCK_ILOCK_BIT, LCK_GRP_NULL)
#define interlock_try(lock)             hw_lock_bit_try((hw_lock_bit_t*)(&(lock)->lck_mtx_data), LCK_ILOCK_BIT, LCK_GRP_NULL)
#define interlock_unlock(lock)  hw_unlock_bit  ((hw_lock_bit_t*)(&(lock)->lck_mtx_data), LCK_ILOCK_BIT)
#define lck_rw_ilk_lock(lock)   hw_lock_bit  ((hw_lock_bit_t*)(&(lock)->lck_rw_tag), LCK_RW_INTERLOCK_BIT, LCK_GRP_NULL)
#define lck_rw_ilk_unlock(lock) hw_unlock_bit((hw_lock_bit_t*)(&(lock)->lck_rw_tag), LCK_RW_INTERLOCK_BIT)

#define memory_barrier()        __c11_atomic_thread_fence(memory_order_acq_rel_smp)
#define load_memory_barrier()   __c11_atomic_thread_fence(memory_order_acquire_smp)
#define store_memory_barrier()  __c11_atomic_thread_fence(memory_order_release_smp)

// Enforce program order of loads and stores.
#define ordered_load(target, type) \
	        __c11_atomic_load((_Atomic type *)(target), memory_order_relaxed)
#define ordered_store(target, type, value) \
	        __c11_atomic_store((_Atomic type *)(target), value, memory_order_relaxed)

#define ordered_load_mtx(lock)                  ordered_load(&(lock)->lck_mtx_data, uintptr_t)
#define ordered_store_mtx(lock, value)  ordered_store(&(lock)->lck_mtx_data, uintptr_t, (value))
#define ordered_load_rw(lock)                   ordered_load(&(lock)->lck_rw_data, uint32_t)
#define ordered_store_rw(lock, value)   ordered_store(&(lock)->lck_rw_data, uint32_t, (value))
#define ordered_load_rw_owner(lock)             ordered_load(&(lock)->lck_rw_owner, thread_t)
#define ordered_store_rw_owner(lock, value)     ordered_store(&(lock)->lck_rw_owner, thread_t, (value))
#define ordered_load_hw(lock)                   ordered_load(&(lock)->lock_data, uintptr_t)
#define ordered_store_hw(lock, value)   ordered_store(&(lock)->lock_data, uintptr_t, (value))
#define ordered_load_bit(lock)                  ordered_load((lock), uint32_t)
#define ordered_store_bit(lock, value)  ordered_store((lock), uint32_t, (value))


// Prevent the compiler from reordering memory operations around this
#define compiler_memory_fence() __asm__ volatile ("" ::: "memory")

#define LOCK_PANIC_TIMEOUT      0xc00000
#define NOINLINE                __attribute__((noinline))


#if __arm__
#define interrupts_disabled(mask) (mask & PSR_INTMASK)
#else
#define interrupts_disabled(mask) (mask & DAIF_IRQF)
#endif


#if __arm__
#define enable_fiq()            __asm__ volatile ("cpsie  f" ::: "memory");
#define enable_interrupts()     __asm__ volatile ("cpsie if" ::: "memory");
#endif

/*
 * Forward declarations
 */

static void lck_rw_lock_shared_gen(lck_rw_t *lck);
static void lck_rw_lock_exclusive_gen(lck_rw_t *lck);
static boolean_t lck_rw_lock_shared_to_exclusive_success(lck_rw_t *lck);
static boolean_t lck_rw_lock_shared_to_exclusive_failure(lck_rw_t *lck, uint32_t prior_lock_state);
static void lck_rw_lock_exclusive_to_shared_gen(lck_rw_t *lck, uint32_t prior_lock_state);
static lck_rw_type_t lck_rw_done_gen(lck_rw_t *lck, uint32_t prior_lock_state);
static boolean_t lck_rw_grab(lck_rw_t *lock, int mode, boolean_t wait);

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
	uint32_t        val;

	val = load_exclusive32(target, ord);
	*previous = val;
	return val;
}

static boolean_t
atomic_exchange_complete32(uint32_t *target, uint32_t previous, uint32_t newval, enum memory_order ord)
{
	(void)previous;         // Previous not needed, monitor is held
	return store_exclusive32(target, newval, ord);
}

static void
atomic_exchange_abort(void)
{
	clear_exclusive();
}

static boolean_t
atomic_test_and_set32(uint32_t *target, uint32_t test_mask, uint32_t set_mask, enum memory_order ord, boolean_t wait)
{
	uint32_t                value, prev;

	for (;;) {
		value = atomic_exchange_begin32(target, &prev, ord);
		if (value & test_mask) {
			if (wait) {
				wait_for_event();       // Wait with monitor held
			} else {
				atomic_exchange_abort();        // Clear exclusive monitor
			}
			return FALSE;
		}
		value |= set_mask;
		if (atomic_exchange_complete32(target, prev, value, ord)) {
			return TRUE;
		}
	}
}

void
_disable_preemption(void)
{
	thread_t        thread = current_thread();
	unsigned int    count;

	count = thread->machine.preemption_count + 1;
	ordered_store(&thread->machine.preemption_count, unsigned int, count);
}

void
_enable_preemption(void)
{
	thread_t        thread = current_thread();
	long            state;
	unsigned int    count;
#if __arm__
#define INTERRUPT_MASK PSR_IRQF
#else   // __arm__
#define INTERRUPT_MASK DAIF_IRQF
#endif  // __arm__

	count = thread->machine.preemption_count;
	if (count == 0) {
		panic("Preemption count negative");     // Count will go negative when released
	}
	count--;
	if (count > 0) {
		goto update_count;                      // Preemption is still disabled, just update
	}
	state = get_interrupts();                       // Get interrupt state
	if (state & INTERRUPT_MASK) {
		goto update_count;                      // Interrupts are already masked, can't take AST here
	}
	disable_interrupts_noread();                    // Disable interrupts
	ordered_store(&thread->machine.preemption_count, unsigned int, count);
	if (thread->machine.CpuDatap->cpu_pending_ast & AST_URGENT) {
#if __arm__
#if __ARM_USER_PROTECT__
		uintptr_t up = arm_user_protect_begin(thread);
#endif  // __ARM_USER_PROTECT__
		enable_fiq();
#endif  // __arm__
		ast_taken_kernel();                     // Handle urgent AST
#if __arm__
#if __ARM_USER_PROTECT__
		arm_user_protect_end(thread, up, TRUE);
#endif  // __ARM_USER_PROTECT__
		enable_interrupts();
		return;                                 // Return early on arm only due to FIQ enabling
#endif  // __arm__
	}
	restore_interrupts(state);                      // Enable interrupts
	return;

update_count:
	ordered_store(&thread->machine.preemption_count, unsigned int, count);
	return;
}

int
get_preemption_level(void)
{
	return current_thread()->machine.preemption_count;
}

#if     __SMP__
static unsigned int
hw_lock_bit_to_contended(hw_lock_bit_t *lock, uint32_t mask, uint32_t timeout LCK_GRP_ARG(lck_grp_t *grp));
#endif

static inline unsigned int
hw_lock_bit_to_internal(hw_lock_bit_t *lock, unsigned int bit, uint32_t timeout LCK_GRP_ARG(lck_grp_t *grp))
{
	unsigned int success = 0;
	uint32_t        mask = (1 << bit);
#if     !__SMP__
	uint32_t        state;
#endif

#if     __SMP__
	if (__improbable(!atomic_test_and_set32(lock, mask, mask, memory_order_acquire, FALSE))) {
		success = hw_lock_bit_to_contended(lock, mask, timeout LCK_GRP_ARG(grp));
	} else {
		success = 1;
	}
#else   // __SMP__
	(void)timeout;
	state = ordered_load_bit(lock);
	if (!(mask & state)) {
		ordered_store_bit(lock, state | mask);
		success = 1;
	}
#endif  // __SMP__

	if (success) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
	}

	return success;
}

unsigned
int
(hw_lock_bit_to)(hw_lock_bit_t * lock, unsigned int bit, uint32_t timeout LCK_GRP_ARG(lck_grp_t *grp))
{
	_disable_preemption();
	return hw_lock_bit_to_internal(lock, bit, timeout LCK_GRP_ARG(grp));
}

#if     __SMP__
static unsigned int NOINLINE
hw_lock_bit_to_contended(hw_lock_bit_t *lock, uint32_t mask, uint32_t timeout LCK_GRP_ARG(lck_grp_t *grp))
{
	uint64_t        end = 0;
	int             i;
#if CONFIG_DTRACE || LOCK_STATS
	uint64_t begin = 0;
	boolean_t stat_enabled = lck_grp_spin_spin_enabled(lock LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LOCK_STATS */

#if LOCK_STATS || CONFIG_DTRACE
	if (__improbable(stat_enabled)) {
		begin = mach_absolute_time();
	}
#endif /* LOCK_STATS || CONFIG_DTRACE */
	for (;;) {
		for (i = 0; i < LOCK_SNOOP_SPINS; i++) {
			// Always load-exclusive before wfe
			// This grabs the monitor and wakes up on a release event
			if (atomic_test_and_set32(lock, mask, mask, memory_order_acquire, TRUE)) {
				goto end;
			}
		}
		if (end == 0) {
			end = ml_get_timebase() + timeout;
		} else if (ml_get_timebase() >= end) {
			break;
		}
	}
	return 0;
end:
#if CONFIG_DTRACE || LOCK_STATS
	if (__improbable(stat_enabled)) {
		lck_grp_spin_update_spin(lock LCK_GRP_ARG(grp), mach_absolute_time() - begin);
	}
	lck_grp_spin_update_miss(lock LCK_GRP_ARG(grp));
#endif /* CONFIG_DTRACE || LCK_GRP_STAT */

	return 1;
}
#endif  // __SMP__

void
(hw_lock_bit)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	if (hw_lock_bit_to(lock, bit, LOCK_PANIC_TIMEOUT, LCK_GRP_PROBEARG(grp))) {
		return;
	}
#if     __SMP__
	panic("hw_lock_bit(): timed out (%p)", lock);
#else
	panic("hw_lock_bit(): interlock held (%p)", lock);
#endif
}

void
(hw_lock_bit_nopreempt)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	if (__improbable(get_preemption_level() == 0)) {
		panic("Attempt to take no-preempt bitlock %p in preemptible context", lock);
	}
	if (hw_lock_bit_to_internal(lock, bit, LOCK_PANIC_TIMEOUT LCK_GRP_ARG(grp))) {
		return;
	}
#if     __SMP__
	panic("hw_lock_bit_nopreempt(): timed out (%p)", lock);
#else
	panic("hw_lock_bit_nopreempt(): interlock held (%p)", lock);
#endif
}

unsigned
int
(hw_lock_bit_try)(hw_lock_bit_t * lock, unsigned int bit LCK_GRP_ARG(lck_grp_t *grp))
{
	uint32_t        mask = (1 << bit);
#if     !__SMP__
	uint32_t        state;
#endif
	boolean_t       success = FALSE;

	_disable_preemption();
#if     __SMP__
	// TODO: consider weak (non-looping) atomic test-and-set
	success = atomic_test_and_set32(lock, mask, mask, memory_order_acquire, FALSE);
#else
	state = ordered_load_bit(lock);
	if (!(mask & state)) {
		ordered_store_bit(lock, state | mask);
		success = TRUE;
	}
#endif  // __SMP__
	if (!success) {
		_enable_preemption();
	}

	if (success) {
		lck_grp_spin_update_held(lock LCK_GRP_ARG(grp));
	}

	return success;
}

static inline void
hw_unlock_bit_internal(hw_lock_bit_t *lock, unsigned int bit)
{
	uint32_t        mask = (1 << bit);
#if     !__SMP__
	uint32_t        state;
#endif

#if     __SMP__
	__c11_atomic_fetch_and((_Atomic uint32_t *)lock, ~mask, memory_order_release);
	set_event();
#else   // __SMP__
	state = ordered_load_bit(lock);
	ordered_store_bit(lock, state & ~mask);
#endif  // __SMP__
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_SPIN_UNLOCK_RELEASE, lock, bit);
#endif
}

/*
 *	Routine:	hw_unlock_bit
 *
 *		Release spin-lock. The second parameter is the bit number to test and set.
 *		Decrement the preemption level.
 */
void
hw_unlock_bit(hw_lock_bit_t * lock, unsigned int bit)
{
	hw_unlock_bit_internal(lock, bit);
	_enable_preemption();
}

void
hw_unlock_bit_nopreempt(hw_lock_bit_t * lock, unsigned int bit)
{
	if (__improbable(get_preemption_level() == 0)) {
		panic("Attempt to release no-preempt bitlock %p in preemptible context", lock);
	}
	hw_unlock_bit_internal(lock, bit);
}

#if __SMP__
static inline boolean_t
interlock_try_disable_interrupts(
	lck_mtx_t *mutex,
	boolean_t *istate)
{
	*istate = ml_set_interrupts_enabled(FALSE);

	if (interlock_try(mutex)) {
		return 1;
	} else {
		ml_set_interrupts_enabled(*istate);
		return 0;
	}
}

static inline void
interlock_unlock_enable_interrupts(
	lck_mtx_t *mutex,
	boolean_t istate)
{
	interlock_unlock(mutex);
	ml_set_interrupts_enabled(istate);
}
#endif /* __SMP__ */

/*
 *      Routine:        lck_spin_alloc_init
 */
lck_spin_t     *
lck_spin_alloc_init(
	lck_grp_t * grp,
	lck_attr_t * attr)
{
	lck_spin_t     *lck;

	if ((lck = (lck_spin_t *) kalloc(sizeof(lck_spin_t))) != 0) {
		lck_spin_init(lck, grp, attr);
	}

	return lck;
}

/*
 *      Routine:        lck_spin_free
 */
void
lck_spin_free(
	lck_spin_t * lck,
	lck_grp_t * grp)
{
	lck_spin_destroy(lck, grp);
	kfree(lck, sizeof(lck_spin_t));
}

/*
 *      Routine:        lck_spin_init
 */
void
lck_spin_init(
	lck_spin_t * lck,
	lck_grp_t * grp,
	__unused lck_attr_t * attr)
{
	hw_lock_init(&lck->hwlock);
	lck->type = LCK_SPIN_TYPE;
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_SPIN);
	store_memory_barrier();
}

/*
 * arm_usimple_lock is a lck_spin_t without a group or attributes
 */
void inline
arm_usimple_lock_init(simple_lock_t lck, __unused unsigned short initial_value)
{
	lck->type = LCK_SPIN_TYPE;
	hw_lock_init(&lck->hwlock);
	store_memory_barrier();
}


/*
 *      Routine:        lck_spin_lock
 */
void
lck_spin_lock(lck_spin_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_lock(&lock->hwlock, LCK_GRP_NULL);
}

void
lck_spin_lock_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
#if     DEVELOPMENT || DEBUG
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_lock(&lock->hwlock, grp);
}

/*
 *      Routine:        lck_spin_lock_nopreempt
 */
void
lck_spin_lock_nopreempt(lck_spin_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_lock_nopreempt(&lock->hwlock, LCK_GRP_NULL);
}

void
lck_spin_lock_nopreempt_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
#if     DEVELOPMENT || DEBUG
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_lock_nopreempt(&lock->hwlock, grp);
}

/*
 *      Routine:        lck_spin_try_lock
 */
int
lck_spin_try_lock(lck_spin_t *lock)
{
	return hw_lock_try(&lock->hwlock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	return hw_lock_try(&lock->hwlock, grp);
}

/*
 *      Routine:        lck_spin_try_lock_nopreempt
 */
int
lck_spin_try_lock_nopreempt(lck_spin_t *lock)
{
	return hw_lock_try_nopreempt(&lock->hwlock, LCK_GRP_NULL);
}

int
lck_spin_try_lock_nopreempt_grp(lck_spin_t *lock, lck_grp_t *grp)
{
#pragma unused(grp)
	return hw_lock_try_nopreempt(&lock->hwlock, grp);
}

/*
 *      Routine:        lck_spin_unlock
 */
void
lck_spin_unlock(lck_spin_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if ((LCK_MTX_STATE_TO_THREAD(lock->lck_spin_data) != current_thread()) && LOCK_CORRECTNESS_PANIC()) {
		panic("Spinlock not owned by thread %p = %lx", lock, lock->lck_spin_data);
	}
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock type %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_unlock(&lock->hwlock);
}

/*
 *      Routine:        lck_spin_unlock_nopreempt
 */
void
lck_spin_unlock_nopreempt(lck_spin_t *lock)
{
#if     DEVELOPMENT || DEBUG
	if ((LCK_MTX_STATE_TO_THREAD(lock->lck_spin_data) != current_thread()) && LOCK_CORRECTNESS_PANIC()) {
		panic("Spinlock not owned by thread %p = %lx", lock, lock->lck_spin_data);
	}
	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock type %p", lock);
	}
#endif  // DEVELOPMENT || DEBUG
	hw_lock_unlock_nopreempt(&lock->hwlock);
}

/*
 *      Routine:        lck_spin_destroy
 */
void
lck_spin_destroy(
	lck_spin_t * lck,
	lck_grp_t * grp)
{
	if (lck->lck_spin_data == LCK_SPIN_TAG_DESTROYED) {
		return;
	}
	lck->lck_spin_data = LCK_SPIN_TAG_DESTROYED;
	lck_grp_lckcnt_decr(grp, LCK_TYPE_SPIN);
	lck_grp_deallocate(grp);
}

/*
 * Routine: kdp_lck_spin_is_acquired
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 */
boolean_t
kdp_lck_spin_is_acquired(lck_spin_t *lck)
{
	if (not_in_kdp) {
		panic("panic: spinlock acquired check done outside of kernel debugger");
	}
	return ((lck->lck_spin_data & ~LCK_SPIN_TAG_DESTROYED) != 0) ? TRUE:FALSE;
}

/*
 *	Initialize a usimple_lock.
 *
 *	No change in preemption state.
 */
void
usimple_lock_init(
	usimple_lock_t l,
	unsigned short tag)
{
#ifndef MACHINE_SIMPLE_LOCK
	USLDBG(usld_lock_init(l, tag));
	hw_lock_init(&l->lck_spin_data);
#else
	simple_lock_init((simple_lock_t) l, tag);
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
(usimple_lock)(
	usimple_lock_t l
	LCK_GRP_ARG(lck_grp_t *grp))
{
#ifndef MACHINE_SIMPLE_LOCK
	pc_t            pc;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_pre(l, pc));

	if (!hw_lock_to(&l->lck_spin_data, LockTimeOut, LCK_GRP_ARG(grp))) {      /* Try to get the lock
		                                                                   * with a timeout */
		panic("simple lock deadlock detection - l=%p, cpu=%d, ret=%p", &l, cpu_number(), pc);
	}

	USLDBG(usld_lock_post(l, pc));
#else
	simple_lock((simple_lock_t) l, LCK_GRP_PROBEARG(grp));
#endif
}


extern void     sync(void);

/*
 *	Release a usimple_lock.
 *
 *	Returns with preemption enabled.  Note
 *	that the hw_lock routines are responsible for
 *	maintaining preemption state.
 */
void
(usimple_unlock)(
	usimple_lock_t l)
{
#ifndef MACHINE_SIMPLE_LOCK
	pc_t            pc;

	OBTAIN_PC(pc, l);
	USLDBG(usld_unlock(l, pc));
	sync();
	hw_lock_unlock(&l->lck_spin_data);
#else
	simple_unlock((simple_lock_t)l);
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
unsigned
int
(usimple_lock_try)(
	usimple_lock_t l
	LCK_GRP_ARG(lck_grp_t *grp))
{
#ifndef MACHINE_SIMPLE_LOCK
	pc_t            pc;
	unsigned int    success;

	OBTAIN_PC(pc, l);
	USLDBG(usld_lock_try_pre(l, pc));
	if ((success = hw_lock_try(&l->lck_spin_data LCK_GRP_ARG(grp)))) {
		USLDBG(usld_lock_try_post(l, pc));
	}
	return success;
#else
	return simple_lock_try((simple_lock_t) l, grp);
#endif
}

#if     USLOCK_DEBUG
/*
 *	States of a usimple_lock.  The default when initializing
 *	a usimple_lock is setting it up for debug checking.
 */
#define USLOCK_CHECKED          0x0001  /* lock is being checked */
#define USLOCK_TAKEN            0x0002  /* lock has been taken */
#define USLOCK_INIT             0xBAA0  /* lock has been initialized */
#define USLOCK_INITIALIZED      (USLOCK_INIT|USLOCK_CHECKED)
#define USLOCK_CHECKING(l)      (uslock_check &&                        \
	                         ((l)->debug.state & USLOCK_CHECKED))

/*
 *	Trace activities of a particularly interesting lock.
 */
void            usl_trace(usimple_lock_t, int, pc_t, const char *);


/*
 *	Initialize the debugging information contained
 *	in a usimple_lock.
 */
void
usld_lock_init(
	usimple_lock_t l,
	__unused unsigned short tag)
{
	if (l == USIMPLE_LOCK_NULL) {
		panic("lock initialization:  null lock pointer");
	}
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
	usimple_lock_t l,
	const char *caller)
{
	if (l == USIMPLE_LOCK_NULL) {
		panic("%s:  null lock pointer", caller);
	}
	if (l->lock_type != USLOCK_TAG) {
		panic("%s:  0x%x is not a usimple lock", caller, (integer_t) l);
	}
	if (!(l->debug.state & USLOCK_INIT)) {
		panic("%s:  0x%x is not an initialized lock",
		    caller, (integer_t) l);
	}
	return USLOCK_CHECKING(l);
}


/*
 *	Debug checks on a usimple_lock just before attempting
 *	to acquire it.
 */
/* ARGSUSED */
void
usld_lock_pre(
	usimple_lock_t l,
	pc_t pc)
{
	const char     *caller = "usimple_lock";


	if (!usld_lock_common_checks(l, caller)) {
		return;
	}

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
	usimple_lock_t l,
	pc_t pc)
{
	int             mycpu;
	const char     *caller = "successful usimple_lock";


	if (!usld_lock_common_checks(l, caller)) {
		return;
	}

	if (!((l->debug.state & ~USLOCK_TAKEN) == USLOCK_INITIALIZED)) {
		panic("%s:  lock 0x%x became uninitialized",
		    caller, (integer_t) l);
	}
	if ((l->debug.state & USLOCK_TAKEN)) {
		panic("%s:  lock 0x%x became TAKEN by someone else",
		    caller, (integer_t) l);
	}

	mycpu = cpu_number();
	l->debug.lock_thread = (void *) current_thread();
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
	usimple_lock_t l,
	pc_t pc)
{
	int             mycpu;
	const char     *caller = "usimple_unlock";


	if (!usld_lock_common_checks(l, caller)) {
		return;
	}

	mycpu = cpu_number();

	if (!(l->debug.state & USLOCK_TAKEN)) {
		panic("%s:  lock 0x%x hasn't been taken",
		    caller, (integer_t) l);
	}
	if (l->debug.lock_thread != (void *) current_thread()) {
		panic("%s:  unlocking lock 0x%x, owned by thread %p",
		    caller, (integer_t) l, l->debug.lock_thread);
	}
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
	usimple_lock_t l,
	pc_t pc)
{
	const char     *caller = "usimple_lock_try";

	if (!usld_lock_common_checks(l, caller)) {
		return;
	}
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
	usimple_lock_t l,
	pc_t pc)
{
	int             mycpu;
	const char     *caller = "successful usimple_lock_try";

	if (!usld_lock_common_checks(l, caller)) {
		return;
	}

	if (!((l->debug.state & ~USLOCK_TAKEN) == USLOCK_INITIALIZED)) {
		panic("%s:  lock 0x%x became uninitialized",
		    caller, (integer_t) l);
	}
	if ((l->debug.state & USLOCK_TAKEN)) {
		panic("%s:  lock 0x%x became TAKEN by someone else",
		    caller, (integer_t) l);
	}

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
usimple_lock_t  traced_lock;
unsigned int    lock_seq;

void
usl_trace(
	usimple_lock_t l,
	int mycpu,
	pc_t pc,
	const char *op_name)
{
	if (traced_lock == l) {
		XPR(XPR_SLOCK,
		    "seq %d, cpu %d, %s @ %x\n",
		    (integer_t) lock_seq, (integer_t) mycpu,
		    (integer_t) op_name, (integer_t) pc, 0);
		lock_seq++;
	}
}


#endif                          /* USLOCK_DEBUG */

/*
 * The C portion of the shared/exclusive locks package.
 */

/*
 * compute the deadline to spin against when
 * waiting for a change of state on a lck_rw_t
 */
#if     __SMP__
static inline uint64_t
lck_rw_deadline_for_spin(lck_rw_t *lck)
{
	lck_rw_word_t   word;

	word.data = ordered_load_rw(lck);
	if (word.can_sleep) {
		if (word.r_waiting || word.w_waiting || (word.shared_count > machine_info.max_cpus)) {
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
			return mach_absolute_time();
		}
		return mach_absolute_time() + MutexSpin;
	} else {
		return mach_absolute_time() + (100000LL * 1000000000LL);
	}
}
#endif  // __SMP__

static boolean_t
lck_rw_drain_status(lck_rw_t *lock, uint32_t status_mask, boolean_t wait __unused)
{
#if     __SMP__
	uint64_t        deadline = 0;
	uint32_t        data;

	if (wait) {
		deadline = lck_rw_deadline_for_spin(lock);
	}

	for (;;) {
		data = load_exclusive32(&lock->lck_rw_data, memory_order_acquire_smp);
		if ((data & status_mask) == 0) {
			break;
		}
		if (wait) {
			wait_for_event();
		} else {
			clear_exclusive();
		}
		if (!wait || (mach_absolute_time() >= deadline)) {
			return FALSE;
		}
	}
	clear_exclusive();
	return TRUE;
#else
	uint32_t        data;

	data = ordered_load_rw(lock);
	if ((data & status_mask) == 0) {
		return TRUE;
	} else {
		return FALSE;
	}
#endif  // __SMP__
}

/*
 * Spin while interlock is held.
 */
static inline void
lck_rw_interlock_spin(lck_rw_t *lock)
{
#if __SMP__
	uint32_t        data;

	for (;;) {
		data = load_exclusive32(&lock->lck_rw_data, memory_order_relaxed);
		if (data & LCK_RW_INTERLOCK) {
			wait_for_event();
		} else {
			clear_exclusive();
			return;
		}
	}
#else
	panic("lck_rw_interlock_spin(): Interlock locked %p %x", lock, lock->lck_rw_data);
#endif
}

/*
 * We disable interrupts while holding the RW interlock to prevent an
 * interrupt from exacerbating hold time.
 * Hence, local helper functions lck_interlock_lock()/lck_interlock_unlock().
 */
static inline boolean_t
lck_interlock_lock(lck_rw_t *lck)
{
	boolean_t       istate;

	istate = ml_set_interrupts_enabled(FALSE);
	lck_rw_ilk_lock(lck);
	return istate;
}

static inline void
lck_interlock_unlock(lck_rw_t *lck, boolean_t istate)
{
	lck_rw_ilk_unlock(lck);
	ml_set_interrupts_enabled(istate);
}


#define LCK_RW_GRAB_WANT        0
#define LCK_RW_GRAB_SHARED      1

static boolean_t
lck_rw_grab(lck_rw_t *lock, int mode, boolean_t wait)
{
	uint64_t        deadline = 0;
	uint32_t        data, prev;
	boolean_t       do_exch;

#if __SMP__
	if (wait) {
		deadline = lck_rw_deadline_for_spin(lock);
	}
#else
	wait = FALSE;   // Don't spin on UP systems
#endif

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		do_exch = FALSE;
		if (mode == LCK_RW_GRAB_WANT) {
			if ((data & LCK_RW_WANT_EXCL) == 0) {
				data |= LCK_RW_WANT_EXCL;
				do_exch = TRUE;
			}
		} else {        // LCK_RW_GRAB_SHARED
			if (((data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) == 0) ||
			    (((data & LCK_RW_SHARED_MASK)) && ((data & LCK_RW_PRIV_EXCL) == 0))) {
				data += LCK_RW_SHARED_READER;
				do_exch = TRUE;
			}
		}
		if (do_exch) {
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				return TRUE;
			}
		} else {
			if (wait) {                                             // Non-waiting
				wait_for_event();
			} else {
				atomic_exchange_abort();
			}
			if (!wait || (mach_absolute_time() >= deadline)) {
				return FALSE;
			}
		}
	}
}


/*
 *      Routine:        lck_rw_alloc_init
 */
lck_rw_t *
lck_rw_alloc_init(
	lck_grp_t       *grp,
	lck_attr_t      *attr)
{
	lck_rw_t        *lck;

	if ((lck = (lck_rw_t *)kalloc(sizeof(lck_rw_t))) != 0) {
		lck_rw_init(lck, grp, attr);
	}

	return lck;
}

/*
 *      Routine:        lck_rw_free
 */
void
lck_rw_free(
	lck_rw_t        *lck,
	lck_grp_t       *grp)
{
	lck_rw_destroy(lck, grp);
	kfree(lck, sizeof(lck_rw_t));
}

/*
 *      Routine:        lck_rw_init
 */
void
lck_rw_init(
	lck_rw_t        *lck,
	lck_grp_t       *grp,
	lck_attr_t      *attr)
{
	if (attr == LCK_ATTR_NULL) {
		attr = &LockDefaultLckAttr;
	}
	memset(lck, 0, sizeof(lck_rw_t));
	lck->lck_rw_can_sleep = TRUE;
	if ((attr->lck_attr_val & LCK_ATTR_RW_SHARED_PRIORITY) == 0) {
		lck->lck_rw_priv_excl = TRUE;
	}

	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_RW);
}


/*
 *      Routine:        lck_rw_destroy
 */
void
lck_rw_destroy(
	lck_rw_t        *lck,
	lck_grp_t       *grp)
{
	if (lck->lck_rw_tag == LCK_RW_TAG_DESTROYED) {
		return;
	}
#if MACH_LDEBUG
	lck_rw_assert(lck, LCK_RW_ASSERT_NOTHELD);
#endif
	lck->lck_rw_tag = LCK_RW_TAG_DESTROYED;
	lck_grp_lckcnt_decr(grp, LCK_TYPE_RW);
	lck_grp_deallocate(grp);
	return;
}

/*
 *	Routine:	lck_rw_lock
 */
void
lck_rw_lock(
	lck_rw_t                *lck,
	lck_rw_type_t   lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		lck_rw_lock_shared(lck);
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		lck_rw_lock_exclusive(lck);
	} else {
		panic("lck_rw_lock(): Invalid RW lock type: %x", lck_rw_type);
	}
}

/*
 *	Routine:	lck_rw_lock_exclusive
 */
void
lck_rw_lock_exclusive(lck_rw_t *lock)
{
	thread_t        thread = current_thread();

	thread->rwlock_count++;
	if (atomic_test_and_set32(&lock->lck_rw_data,
	    (LCK_RW_SHARED_MASK | LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE | LCK_RW_INTERLOCK),
	    LCK_RW_WANT_EXCL, memory_order_acquire_smp, FALSE)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif  /* CONFIG_DTRACE */
	} else {
		lck_rw_lock_exclusive_gen(lock);
	}
#if MACH_ASSERT
	thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);
#endif
	ordered_store_rw_owner(lock, thread);
}

/*
 *	Routine:	lck_rw_lock_shared
 */
void
lck_rw_lock_shared(lck_rw_t *lock)
{
	uint32_t        data, prev;

	current_thread()->rwlock_count++;
	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE | LCK_RW_INTERLOCK)) {
			atomic_exchange_abort();
			lck_rw_lock_shared_gen(lock);
			break;
		}
		data += LCK_RW_SHARED_READER;
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
#if MACH_ASSERT
	thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);
#endif
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_ACQUIRE, lock, DTRACE_RW_SHARED);
#endif  /* CONFIG_DTRACE */
	return;
}

/*
 *	Routine:	lck_rw_lock_shared_to_exclusive
 */
boolean_t
lck_rw_lock_shared_to_exclusive(lck_rw_t *lock)
{
	uint32_t        data, prev;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
		}
		if (data & LCK_RW_WANT_UPGRADE) {
			data -= LCK_RW_SHARED_READER;
			if ((data & LCK_RW_SHARED_MASK) == 0) {         /* we were the last reader */
				data &= ~(LCK_RW_W_WAITING);            /* so clear the wait indicator */
			}
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				return lck_rw_lock_shared_to_exclusive_failure(lock, prev);
			}
		} else {
			data |= LCK_RW_WANT_UPGRADE;            /* ask for WANT_UPGRADE */
			data -= LCK_RW_SHARED_READER;           /* and shed our read count */
			if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
				break;
			}
		}
		cpu_pause();
	}
	/* we now own the WANT_UPGRADE */
	if (data & LCK_RW_SHARED_MASK) {        /* check to see if all of the readers are drained */
		lck_rw_lock_shared_to_exclusive_success(lock);  /* if not, we need to go wait */
	}
#if MACH_ASSERT
	thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);
#endif
	ordered_store_rw_owner(lock, current_thread());
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lock, 0);
#endif  /* CONFIG_DTRACE */
	return TRUE;
}


/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_failure
 *	Function:
 *		Fast path code has already dropped our read
 *		count and determined that someone else owns 'lck_rw_want_upgrade'
 *		if 'lck_rw_shared_count' == 0, its also already dropped 'lck_w_waiting'
 *		all we need to do here is determine if a wakeup is needed
 */
static boolean_t
lck_rw_lock_shared_to_exclusive_failure(
	lck_rw_t        *lck,
	uint32_t        prior_lock_state)
{
	thread_t        thread = current_thread();
	uint32_t        rwlock_count;

	/* Check if dropping the lock means that we need to unpromote */
	rwlock_count = thread->rwlock_count--;
#if MACH_LDEBUG
	if (rwlock_count == 0) {
		panic("rw lock count underflow for thread %p", thread);
	}
#endif
	if ((prior_lock_state & LCK_RW_W_WAITING) &&
	    ((prior_lock_state & LCK_RW_SHARED_MASK) == LCK_RW_SHARED_READER)) {
		/*
		 *	Someone else has requested upgrade.
		 *	Since we've released the read lock, wake
		 *	him up if he's blocked waiting
		 */
		thread_wakeup(LCK_RW_WRITER_EVENT(lck));
	}

	if ((rwlock_count == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		/* sched_flags checked without lock, but will be rechecked while clearing */
		lck_rw_clear_promotion(thread, unslide_for_kdebug(lck));
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_CODE) | DBG_FUNC_NONE,
	    VM_KERNEL_UNSLIDE_OR_PERM(lck), lck->lck_rw_shared_count, lck->lck_rw_want_upgrade, 0, 0);

	return FALSE;
}

/*
 *	Routine:	lck_rw_lock_shared_to_exclusive_success
 *	Function:
 *		assembly fast path code has already dropped our read
 *		count and successfully acquired 'lck_rw_want_upgrade'
 *		we just need to wait for the rest of the readers to drain
 *		and then we can return as the exclusive holder of this lock
 */
static boolean_t
lck_rw_lock_shared_to_exclusive_success(
	lck_rw_t        *lock)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	int                     slept = 0;
	lck_rw_word_t           word;
	wait_result_t           res;
	boolean_t               istate;
	boolean_t               not_shared;

#if     CONFIG_DTRACE
	uint64_t                wait_interval = 0;
	int                     readers_at_sleep = 0;
	boolean_t               dtrace_ls_initialized = FALSE;
	boolean_t               dtrace_rwl_shared_to_excl_spin, dtrace_rwl_shared_to_excl_block, dtrace_ls_enabled = FALSE;
#endif

	while (!lck_rw_drain_status(lock, LCK_RW_SHARED_MASK, FALSE)) {
		word.data = ordered_load_rw(lock);
#if     CONFIG_DTRACE
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
				readers_at_sleep = word.shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_SPIN_CODE) | DBG_FUNC_START,
		    trace_lck, word.shared_count, 0, 0, 0);

		not_shared = lck_rw_drain_status(lock, LCK_RW_SHARED_MASK, TRUE);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_SPIN_CODE) | DBG_FUNC_END,
		    trace_lck, lock->lck_rw_shared_count, 0, 0, 0);

		if (not_shared) {
			break;
		}

		/*
		 * if we get here, the spin deadline in lck_rw_wait_on_status()
		 * has expired w/o the rw_shared_count having drained to 0
		 * check to see if we're allowed to do a thread_block
		 */
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);

			word.data = ordered_load_rw(lock);
			if (word.shared_count != 0) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_WAIT_CODE) | DBG_FUNC_START,
				    trace_lck, word.shared_count, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockUpgrade);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SH_TO_EX_WAIT_CODE) | DBG_FUNC_END,
				    trace_lck, res, slept, 0, 0);
			} else {
				lck_interlock_unlock(lock, istate);
				break;
			}
		}
	}
#if     CONFIG_DTRACE
	/*
	 * We infer whether we took the sleep/spin path above by checking readers_at_sleep.
	 */
	if (dtrace_ls_enabled == TRUE) {
		if (slept == 0) {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_SPIN, lock, mach_absolute_time() - wait_interval, 0);
		} else {
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_BLOCK, lock,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE, lock, 1);
#endif
	return TRUE;
}


/*
 *	Routine:	lck_rw_lock_exclusive_to_shared
 */

void
lck_rw_lock_exclusive_to_shared(lck_rw_t *lock)
{
	uint32_t        data, prev;

	assertf(lock->lck_rw_owner == current_thread(), "state=0x%x, owner=%p", lock->lck_rw_data, lock->lck_rw_owner);
	ordered_store_rw_owner(lock, THREAD_NULL);
	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_release_smp);
		if (data & LCK_RW_INTERLOCK) {
#if __SMP__
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);    /* wait for interlock to clear */
			continue;
#else
			panic("lck_rw_lock_exclusive_to_shared(): Interlock locked (%p): %x", lock, data);
#endif // __SMP__
		}
		data += LCK_RW_SHARED_READER;
		if (data & LCK_RW_WANT_UPGRADE) {
			data &= ~(LCK_RW_WANT_UPGRADE);
		} else {
			data &= ~(LCK_RW_WANT_EXCL);
		}
		if (!((prev & LCK_RW_W_WAITING) && (prev & LCK_RW_PRIV_EXCL))) {
			data &= ~(LCK_RW_W_WAITING);
		}
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_release_smp)) {
			break;
		}
		cpu_pause();
	}
	return lck_rw_lock_exclusive_to_shared_gen(lock, prev);
}

/*
 *      Routine:        lck_rw_lock_exclusive_to_shared_gen
 *      Function:
 *		Fast path has already dropped
 *		our exclusive state and bumped lck_rw_shared_count
 *		all we need to do here is determine if anyone
 *		needs to be awakened.
 */
static void
lck_rw_lock_exclusive_to_shared_gen(
	lck_rw_t        *lck,
	uint32_t        prior_lock_state)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);
	lck_rw_word_t   fake_lck;

	/*
	 * prior_lock state is a snapshot of the 1st word of the
	 * lock in question... we'll fake up a pointer to it
	 * and carefully not access anything beyond whats defined
	 * in the first word of a lck_rw_t
	 */
	fake_lck.data = prior_lock_state;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_START,
	    trace_lck, fake_lck->want_excl, fake_lck->want_upgrade, 0, 0);

	/*
	 * don't wake up anyone waiting to take the lock exclusively
	 * since we hold a read count... when the read count drops to 0,
	 * the writers will be woken.
	 *
	 * wake up any waiting readers if we don't have any writers waiting,
	 * or the lock is NOT marked as rw_priv_excl (writers have privilege)
	 */
	if (!(fake_lck.priv_excl && fake_lck.w_waiting) && fake_lck.r_waiting) {
		thread_wakeup(LCK_RW_READER_EVENT(lck));
	}

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_TO_SH_CODE) | DBG_FUNC_END,
	    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, lck->lck_rw_shared_count, 0);

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_TO_SHARED_DOWNGRADE, lck, 0);
#endif
}


/*
 *      Routine:        lck_rw_try_lock
 */
boolean_t
lck_rw_try_lock(
	lck_rw_t                *lck,
	lck_rw_type_t   lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		return lck_rw_try_lock_shared(lck);
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		return lck_rw_try_lock_exclusive(lck);
	} else {
		panic("lck_rw_try_lock(): Invalid rw lock type: %x", lck_rw_type);
	}
	return FALSE;
}

/*
 *	Routine:	lck_rw_try_lock_shared
 */

boolean_t
lck_rw_try_lock_shared(lck_rw_t *lock)
{
	uint32_t        data, prev;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
#if __SMP__
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
#else
			panic("lck_rw_try_lock_shared(): Interlock locked (%p): %x", lock, data);
#endif
		}
		if (data & (LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) {
			atomic_exchange_abort();
			return FALSE;                                           /* lock is busy */
		}
		data += LCK_RW_SHARED_READER;                   /* Increment reader refcount */
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
#if MACH_ASSERT
	thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);
#endif
	current_thread()->rwlock_count++;
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE, lock, DTRACE_RW_SHARED);
#endif  /* CONFIG_DTRACE */
	return TRUE;
}


/*
 *	Routine:	lck_rw_try_lock_exclusive
 */

boolean_t
lck_rw_try_lock_exclusive(lck_rw_t *lock)
{
	uint32_t        data, prev;
	thread_t        thread;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_acquire_smp);
		if (data & LCK_RW_INTERLOCK) {
#if __SMP__
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
#else
			panic("lck_rw_try_lock_exclusive(): Interlock locked (%p): %x", lock, data);
#endif
		}
		if (data & (LCK_RW_SHARED_MASK | LCK_RW_WANT_EXCL | LCK_RW_WANT_UPGRADE)) {
			atomic_exchange_abort();
			return FALSE;
		}
		data |= LCK_RW_WANT_EXCL;
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_acquire_smp)) {
			break;
		}
		cpu_pause();
	}
	thread = current_thread();
	thread->rwlock_count++;
#if MACH_ASSERT
	thread_t owner = ordered_load_rw_owner(lock);
	assertf(owner == THREAD_NULL, "state=0x%x, owner=%p", ordered_load_rw(lock), owner);
#endif
	ordered_store_rw_owner(lock, thread);
#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE, lock, DTRACE_RW_EXCL);
#endif  /* CONFIG_DTRACE */
	return TRUE;
}


/*
 *	Routine:	lck_rw_unlock
 */
void
lck_rw_unlock(
	lck_rw_t                *lck,
	lck_rw_type_t   lck_rw_type)
{
	if (lck_rw_type == LCK_RW_TYPE_SHARED) {
		lck_rw_unlock_shared(lck);
	} else if (lck_rw_type == LCK_RW_TYPE_EXCLUSIVE) {
		lck_rw_unlock_exclusive(lck);
	} else {
		panic("lck_rw_unlock(): Invalid RW lock type: %d", lck_rw_type);
	}
}


/*
 *	Routine:	lck_rw_unlock_shared
 */
void
lck_rw_unlock_shared(
	lck_rw_t        *lck)
{
	lck_rw_type_t   ret;

	assertf(lck->lck_rw_owner == THREAD_NULL, "state=0x%x, owner=%p", lck->lck_rw_data, lck->lck_rw_owner);
	assertf(lck->lck_rw_shared_count > 0, "shared_count=0x%x", lck->lck_rw_shared_count);
	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_SHARED) {
		panic("lck_rw_unlock_shared(): lock %p held in mode: %d", lck, ret);
	}
}


/*
 *	Routine:	lck_rw_unlock_exclusive
 */
void
lck_rw_unlock_exclusive(
	lck_rw_t        *lck)
{
	lck_rw_type_t   ret;

	assertf(lck->lck_rw_owner == current_thread(), "state=0x%x, owner=%p", lck->lck_rw_data, lck->lck_rw_owner);
	ret = lck_rw_done(lck);

	if (ret != LCK_RW_TYPE_EXCLUSIVE) {
		panic("lck_rw_unlock_exclusive(): lock %p held in mode: %d", lck, ret);
	}
}


/*
 *      Routine:        lck_rw_lock_exclusive_gen
 */
static void
lck_rw_lock_exclusive_gen(
	lck_rw_t        *lock)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	lck_rw_word_t           word;
	int                     slept = 0;
	boolean_t               gotlock = 0;
	boolean_t               not_shared_or_upgrade = 0;
	wait_result_t           res = 0;
	boolean_t               istate;

#if     CONFIG_DTRACE
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_excl_spin, dtrace_rwl_excl_block, dtrace_ls_enabled = FALSE;
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
#endif

	/*
	 *	Try to acquire the lck_rw_want_excl bit.
	 */
	while (!lck_rw_grab(lock, LCK_RW_GRAB_WANT, FALSE)) {
#if     CONFIG_DTRACE
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
				readers_at_sleep = lock->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_SPIN_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

		gotlock = lck_rw_grab(lock, LCK_RW_GRAB_WANT, TRUE);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_SPIN_CODE) | DBG_FUNC_END, trace_lck, 0, 0, gotlock, 0);

		if (gotlock) {
			break;
		}
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock exclusively
		 * check to see if we're allowed to do a thread_block
		 */
		word.data = ordered_load_rw(lock);
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);
			word.data = ordered_load_rw(lock);

			if (word.want_excl) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_WAIT_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockWrite);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_WRITER_WAIT_CODE) | DBG_FUNC_END, trace_lck, res, slept, 0, 0);
			} else {
				word.want_excl = 1;
				ordered_store_rw(lock, word.data);
				lck_interlock_unlock(lock, istate);
				break;
			}
		}
	}
	/*
	 * Wait for readers (and upgrades) to finish...
	 */
	while (!lck_rw_drain_status(lock, LCK_RW_SHARED_MASK | LCK_RW_WANT_UPGRADE, FALSE)) {
#if     CONFIG_DTRACE
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
				readers_at_sleep = lock->lck_rw_shared_count;
				wait_interval = mach_absolute_time();
			}
		}
#endif

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_SPIN_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

		not_shared_or_upgrade = lck_rw_drain_status(lock, LCK_RW_SHARED_MASK | LCK_RW_WANT_UPGRADE, TRUE);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_SPIN_CODE) | DBG_FUNC_END, trace_lck, 0, 0, not_shared_or_upgrade, 0);

		if (not_shared_or_upgrade) {
			break;
		}
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock exclusively
		 * check to see if we're allowed to do a thread_block
		 */
		word.data = ordered_load_rw(lock);
		if (word.can_sleep) {
			istate = lck_interlock_lock(lock);
			word.data = ordered_load_rw(lock);

			if (word.shared_count != 0 || word.want_upgrade) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_WAIT_CODE) | DBG_FUNC_START, trace_lck, 0, 0, 0, 0);

				word.w_waiting = 1;
				ordered_store_rw(lock, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockWrite);
				res = assert_wait(LCK_RW_WRITER_EVENT(lock),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lock, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_EX_READER_WAIT_CODE) | DBG_FUNC_END, trace_lck, res, slept, 0, 0);
			} else {
				lck_interlock_unlock(lock, istate);
				/*
				 * must own the lock now, since we checked for
				 * readers or upgrade owner behind the interlock
				 * no need for a call to 'lck_rw_drain_status'
				 */
				break;
			}
		}
	}

#if     CONFIG_DTRACE
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
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_SPIN, lock,
			    mach_absolute_time() - wait_interval, 1);
		} else {
			/*
			 * For the blocking case, we also record if when we blocked
			 * it was held for read or write, and how many readers.
			 * Notice that above we recorded this before we dropped
			 * the interlock so the count is accurate.
			 */
			LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_BLOCK, lock,
			    mach_absolute_time() - wait_interval, 1,
			    (readers_at_sleep == 0 ? 1 : 0), readers_at_sleep);
		}
	}
	LOCKSTAT_RECORD(LS_LCK_RW_LOCK_EXCL_ACQUIRE, lock, 1);
#endif  /* CONFIG_DTRACE */
}

/*
 *      Routine:        lck_rw_done
 */

lck_rw_type_t
lck_rw_done(lck_rw_t *lock)
{
	uint32_t        data, prev;
	boolean_t       once = FALSE;

	for (;;) {
		data = atomic_exchange_begin32(&lock->lck_rw_data, &prev, memory_order_release_smp);
		if (data & LCK_RW_INTERLOCK) {          /* wait for interlock to clear */
#if __SMP__
			atomic_exchange_abort();
			lck_rw_interlock_spin(lock);
			continue;
#else
			panic("lck_rw_done(): Interlock locked (%p): %x", lock, data);
#endif // __SMP__
		}
		if (data & LCK_RW_SHARED_MASK) {        /* lock is held shared */
			assertf(lock->lck_rw_owner == THREAD_NULL, "state=0x%x, owner=%p", lock->lck_rw_data, lock->lck_rw_owner);
			data -= LCK_RW_SHARED_READER;
			if ((data & LCK_RW_SHARED_MASK) == 0) { /* if reader count has now gone to 0, check for waiters */
				goto check_waiters;
			}
		} else {                                        /* if reader count == 0, must be exclusive lock */
			if (data & LCK_RW_WANT_UPGRADE) {
				data &= ~(LCK_RW_WANT_UPGRADE);
			} else {
				if (data & LCK_RW_WANT_EXCL) {
					data &= ~(LCK_RW_WANT_EXCL);
				} else {                                /* lock is not 'owned', panic */
					panic("Releasing non-exclusive RW lock without a reader refcount!");
				}
			}
			if (!once) {
				// Only check for holder and clear it once
				assertf(lock->lck_rw_owner == current_thread(), "state=0x%x, owner=%p", lock->lck_rw_data, lock->lck_rw_owner);
				ordered_store_rw_owner(lock, THREAD_NULL);
				once = TRUE;
			}
check_waiters:
			/*
			 * test the original values to match what
			 * lck_rw_done_gen is going to do to determine
			 * which wakeups need to happen...
			 *
			 * if !(fake_lck->lck_rw_priv_excl && fake_lck->lck_w_waiting)
			 */
			if (prev & LCK_RW_W_WAITING) {
				data &= ~(LCK_RW_W_WAITING);
				if ((prev & LCK_RW_PRIV_EXCL) == 0) {
					data &= ~(LCK_RW_R_WAITING);
				}
			} else {
				data &= ~(LCK_RW_R_WAITING);
			}
		}
		if (atomic_exchange_complete32(&lock->lck_rw_data, prev, data, memory_order_release_smp)) {
			break;
		}
		cpu_pause();
	}
	return lck_rw_done_gen(lock, prev);
}

/*
 *      Routine:        lck_rw_done_gen
 *
 *	called from the assembly language wrapper...
 *	prior_lock_state is the value in the 1st
 *      word of the lock at the time of a successful
 *	atomic compare and exchange with the new value...
 *      it represents the state of the lock before we
 *	decremented the rw_shared_count or cleared either
 *      rw_want_upgrade or rw_want_write and
 *	the lck_x_waiting bits...  since the wrapper
 *      routine has already changed the state atomically,
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
	lck_rw_word_t   fake_lck;
	lck_rw_type_t   lock_type;
	thread_t                thread;
	uint32_t                rwlock_count;

	/*
	 * prior_lock state is a snapshot of the 1st word of the
	 * lock in question... we'll fake up a pointer to it
	 * and carefully not access anything beyond whats defined
	 * in the first word of a lck_rw_t
	 */
	fake_lck.data = prior_lock_state;

	if (fake_lck.shared_count <= 1) {
		if (fake_lck.w_waiting) {
			thread_wakeup(LCK_RW_WRITER_EVENT(lck));
		}

		if (!(fake_lck.priv_excl && fake_lck.w_waiting) && fake_lck.r_waiting) {
			thread_wakeup(LCK_RW_READER_EVENT(lck));
		}
	}
	if (fake_lck.shared_count) {
		lock_type = LCK_RW_TYPE_SHARED;
	} else {
		lock_type = LCK_RW_TYPE_EXCLUSIVE;
	}

	/* Check if dropping the lock means that we need to unpromote */
	thread = current_thread();
	rwlock_count = thread->rwlock_count--;
#if MACH_LDEBUG
	if (rwlock_count == 0) {
		panic("rw lock count underflow for thread %p", thread);
	}
#endif
	if ((rwlock_count == 1 /* field now 0 */) && (thread->sched_flags & TH_SFLAG_RW_PROMOTED)) {
		/* sched_flags checked without lock, but will be rechecked while clearing */
		lck_rw_clear_promotion(thread, unslide_for_kdebug(lck));
	}
#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_RW_DONE_RELEASE, lck, lock_type == LCK_RW_TYPE_SHARED ? 0 : 1);
#endif
	return lock_type;
}

/*
 *	Routine:	lck_rw_lock_shared_gen
 *	Function:
 *		Fast path code has determined that this lock
 *		is held exclusively... this is where we spin/block
 *		until we can acquire the lock in the shared mode
 */
static void
lck_rw_lock_shared_gen(
	lck_rw_t        *lck)
{
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lck);
	lck_rw_word_t           word;
	boolean_t               gotlock = 0;
	int                     slept = 0;
	wait_result_t           res = 0;
	boolean_t               istate;

#if     CONFIG_DTRACE
	uint64_t wait_interval = 0;
	int readers_at_sleep = 0;
	boolean_t dtrace_ls_initialized = FALSE;
	boolean_t dtrace_rwl_shared_spin, dtrace_rwl_shared_block, dtrace_ls_enabled = FALSE;
#endif /* CONFIG_DTRACE */

	while (!lck_rw_grab(lck, LCK_RW_GRAB_SHARED, FALSE)) {
#if     CONFIG_DTRACE
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

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_SPIN_CODE) | DBG_FUNC_START,
		    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, 0, 0);

		gotlock = lck_rw_grab(lck, LCK_RW_GRAB_SHARED, TRUE);

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_SPIN_CODE) | DBG_FUNC_END,
		    trace_lck, lck->lck_rw_want_excl, lck->lck_rw_want_upgrade, gotlock, 0);

		if (gotlock) {
			break;
		}
		/*
		 * if we get here, the deadline has expired w/o us
		 * being able to grab the lock for read
		 * check to see if we're allowed to do a thread_block
		 */
		if (lck->lck_rw_can_sleep) {
			istate = lck_interlock_lock(lck);

			word.data = ordered_load_rw(lck);
			if ((word.want_excl || word.want_upgrade) &&
			    ((word.shared_count == 0) || word.priv_excl)) {
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_WAIT_CODE) | DBG_FUNC_START,
				    trace_lck, word.want_excl, word.want_upgrade, 0, 0);

				word.r_waiting = 1;
				ordered_store_rw(lck, word.data);

				thread_set_pending_block_hint(current_thread(), kThreadWaitKernelRWLockRead);
				res = assert_wait(LCK_RW_READER_EVENT(lck),
				    THREAD_UNINT | THREAD_WAIT_NOREPORT_USER);
				lck_interlock_unlock(lck, istate);

				if (res == THREAD_WAITING) {
					res = thread_block(THREAD_CONTINUE_NULL);
					slept++;
				}
				KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_RW_LCK_SHARED_WAIT_CODE) | DBG_FUNC_END,
				    trace_lck, res, slept, 0, 0);
			} else {
				word.shared_count++;
				ordered_store_rw(lck, word.data);
				lck_interlock_unlock(lck, istate);
				break;
			}
		}
	}

#if     CONFIG_DTRACE
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
#endif  /* CONFIG_DTRACE */
}


void
lck_rw_assert(
	lck_rw_t                *lck,
	unsigned int    type)
{
	switch (type) {
	case LCK_RW_ASSERT_SHARED:
		if ((lck->lck_rw_shared_count != 0) &&
		    (lck->lck_rw_owner == THREAD_NULL)) {
			return;
		}
		break;
	case LCK_RW_ASSERT_EXCLUSIVE:
		if ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_shared_count == 0) &&
		    (lck->lck_rw_owner == current_thread())) {
			return;
		}
		break;
	case LCK_RW_ASSERT_HELD:
		if (lck->lck_rw_shared_count != 0) {
			return;         // Held shared
		}
		if ((lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_owner == current_thread())) {
			return;         // Held exclusive
		}
		break;
	case LCK_RW_ASSERT_NOTHELD:
		if ((lck->lck_rw_shared_count == 0) &&
		    !(lck->lck_rw_want_excl || lck->lck_rw_want_upgrade) &&
		    (lck->lck_rw_owner == THREAD_NULL)) {
			return;
		}
		break;
	default:
		break;
	}
	panic("rw lock (%p)%s held (mode=%u)", lck, (type == LCK_RW_ASSERT_NOTHELD ? "" : " not"), type);
}


/*
 * Routine: kdp_lck_rw_lock_is_acquired_exclusive
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 */
boolean_t
kdp_lck_rw_lock_is_acquired_exclusive(lck_rw_t *lck)
{
	if (not_in_kdp) {
		panic("panic: rw lock exclusive check done outside of kernel debugger");
	}
	return ((lck->lck_rw_want_upgrade || lck->lck_rw_want_excl) && (lck->lck_rw_shared_count == 0)) ? TRUE : FALSE;
}

/*
 * The C portion of the mutex package.  These routines are only invoked
 * if the optimized assembler routines can't do the work.
 */

/*
 * Forward declaration
 */

void
lck_mtx_ext_init(
	lck_mtx_ext_t * lck,
	lck_grp_t * grp,
	lck_attr_t * attr);

/*
 *      Routine:        lck_mtx_alloc_init
 */
lck_mtx_t      *
lck_mtx_alloc_init(
	lck_grp_t * grp,
	lck_attr_t * attr)
{
	lck_mtx_t      *lck;

	if ((lck = (lck_mtx_t *) kalloc(sizeof(lck_mtx_t))) != 0) {
		lck_mtx_init(lck, grp, attr);
	}

	return lck;
}

/*
 *      Routine:        lck_mtx_free
 */
void
lck_mtx_free(
	lck_mtx_t * lck,
	lck_grp_t * grp)
{
	lck_mtx_destroy(lck, grp);
	kfree(lck, sizeof(lck_mtx_t));
}

/*
 *      Routine:        lck_mtx_init
 */
void
lck_mtx_init(
	lck_mtx_t * lck,
	lck_grp_t * grp,
	lck_attr_t * attr)
{
#ifdef  BER_XXX
	lck_mtx_ext_t  *lck_ext;
#endif
	lck_attr_t     *lck_attr;

	if (attr != LCK_ATTR_NULL) {
		lck_attr = attr;
	} else {
		lck_attr = &LockDefaultLckAttr;
	}

#ifdef  BER_XXX
	if ((lck_attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		if ((lck_ext = (lck_mtx_ext_t *) kalloc(sizeof(lck_mtx_ext_t))) != 0) {
			lck_mtx_ext_init(lck_ext, grp, lck_attr);
			lck->lck_mtx_tag = LCK_MTX_TAG_INDIRECT;
			lck->lck_mtx_ptr = lck_ext;
			lck->lck_mtx_type = LCK_MTX_TYPE;
		}
	} else
#endif
	{
		lck->lck_mtx_ptr = NULL;                // Clear any padding in the union fields below
		lck->lck_mtx_waiters = 0;
		lck->lck_mtx_pri = 0;
		lck->lck_mtx_type = LCK_MTX_TYPE;
		ordered_store_mtx(lck, 0);
	}
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_MTX);
}

/*
 *      Routine:        lck_mtx_init_ext
 */
void
lck_mtx_init_ext(
	lck_mtx_t * lck,
	lck_mtx_ext_t * lck_ext,
	lck_grp_t * grp,
	lck_attr_t * attr)
{
	lck_attr_t     *lck_attr;

	if (attr != LCK_ATTR_NULL) {
		lck_attr = attr;
	} else {
		lck_attr = &LockDefaultLckAttr;
	}

	if ((lck_attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck_mtx_ext_init(lck_ext, grp, lck_attr);
		lck->lck_mtx_tag = LCK_MTX_TAG_INDIRECT;
		lck->lck_mtx_ptr = lck_ext;
		lck->lck_mtx_type = LCK_MTX_TYPE;
	} else {
		lck->lck_mtx_waiters = 0;
		lck->lck_mtx_pri = 0;
		lck->lck_mtx_type = LCK_MTX_TYPE;
		ordered_store_mtx(lck, 0);
	}
	lck_grp_reference(grp);
	lck_grp_lckcnt_incr(grp, LCK_TYPE_MTX);
}

/*
 *      Routine:        lck_mtx_ext_init
 */
void
lck_mtx_ext_init(
	lck_mtx_ext_t * lck,
	lck_grp_t * grp,
	lck_attr_t * attr)
{
	bzero((void *) lck, sizeof(lck_mtx_ext_t));

	lck->lck_mtx.lck_mtx_type = LCK_MTX_TYPE;

	if ((attr->lck_attr_val) & LCK_ATTR_DEBUG) {
		lck->lck_mtx_deb.type = MUTEX_TAG;
		lck->lck_mtx_attr |= LCK_MTX_ATTR_DEBUG;
	}
	lck->lck_mtx_grp = grp;

	if (grp->lck_grp_attr & LCK_GRP_ATTR_STAT) {
		lck->lck_mtx_attr |= LCK_MTX_ATTR_STAT;
	}
}

/* The slow versions */
static void lck_mtx_lock_contended(lck_mtx_t *lock, thread_t thread, boolean_t interlocked);
static boolean_t lck_mtx_try_lock_contended(lck_mtx_t *lock, thread_t thread);
static void lck_mtx_unlock_contended(lck_mtx_t *lock, thread_t thread, boolean_t interlocked);

/* The adaptive spin function */
static spinwait_result_t lck_mtx_lock_contended_spinwait_arm(lck_mtx_t *lock, thread_t thread, boolean_t interlocked);

/*
 *	Routine:	lck_mtx_verify
 *
 *	Verify if a mutex is valid
 */
static inline void
lck_mtx_verify(lck_mtx_t *lock)
{
	if (lock->lck_mtx_type != LCK_MTX_TYPE) {
		panic("Invalid mutex %p", lock);
	}
#if     DEVELOPMENT || DEBUG
	if (lock->lck_mtx_tag == LCK_MTX_TAG_DESTROYED) {
		panic("Mutex destroyed %p", lock);
	}
#endif  /* DEVELOPMENT || DEBUG */
}

/*
 *	Routine:	lck_mtx_check_preemption
 *
 *	Verify preemption is enabled when attempting to acquire a mutex.
 */

static inline void
lck_mtx_check_preemption(lck_mtx_t *lock)
{
#if     DEVELOPMENT || DEBUG
	int pl = get_preemption_level();

	if (pl != 0) {
		panic("Attempt to take mutex with preemption disabled. Lock=%p, level=%d", lock, pl);
	}
#else
	(void)lock;
#endif
}

/*
 *	Routine:	lck_mtx_lock
 */
void
lck_mtx_lock(lck_mtx_t *lock)
{
	thread_t        thread;

	lck_mtx_verify(lock);
	lck_mtx_check_preemption(lock);
	thread = current_thread();
	if (atomic_compare_exchange(&lock->lck_mtx_data, 0, LCK_MTX_THREAD_TO_STATE(thread),
	    memory_order_acquire_smp, FALSE)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
		return;
	}
	lck_mtx_lock_contended(lock, thread, FALSE);
}

/*
 *       This is the slow version of mutex locking.
 */
static void NOINLINE
lck_mtx_lock_contended(lck_mtx_t *lock, thread_t thread, boolean_t interlocked)
{
	thread_t                holding_thread;
	uintptr_t               state;
	int                     waiters = 0;
	spinwait_result_t       sw_res;

	/* Loop waiting until I see that the mutex is unowned */
	for (;;) {
		sw_res = lck_mtx_lock_contended_spinwait_arm(lock, thread, interlocked);
		interlocked = FALSE;

		switch (sw_res) {
		case SPINWAIT_ACQUIRED:
			goto done;
		case SPINWAIT_INTERLOCK:
			goto set_owner;
		default:
			break;
		}

		state = ordered_load_mtx(lock);
		holding_thread = LCK_MTX_STATE_TO_THREAD(state);
		if (holding_thread == NULL) {
			break;
		}
		ordered_store_mtx(lock, (state | LCK_ILOCK | ARM_LCK_WAITERS)); // Set waiters bit and wait
		lck_mtx_lock_wait(lock, holding_thread);
		/* returns interlock unlocked */
	}

set_owner:
	/* Hooray, I'm the new owner! */
	state = ordered_load_mtx(lock);

	if (state & ARM_LCK_WAITERS) {
		/* Skip lck_mtx_lock_acquire if there are no waiters. */
		waiters = lck_mtx_lock_acquire(lock);
	}

	state = LCK_MTX_THREAD_TO_STATE(thread);
	if (waiters != 0) {
		state |= ARM_LCK_WAITERS;
	}
#if __SMP__
	state |= LCK_ILOCK;                             // Preserve interlock
	ordered_store_mtx(lock, state); // Set ownership
	interlock_unlock(lock);                 // Release interlock, enable preemption
#else
	ordered_store_mtx(lock, state); // Set ownership
	enable_preemption();
#endif

done:
	load_memory_barrier();

#if CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
}

/*
 * Routine: lck_mtx_lock_spinwait_arm
 *
 * Invoked trying to acquire a mutex when there is contention but
 * the holder is running on another processor. We spin for up to a maximum
 * time waiting for the lock to be released.
 */
static spinwait_result_t
lck_mtx_lock_contended_spinwait_arm(lck_mtx_t *lock, thread_t thread, boolean_t interlocked)
{
	int                     has_interlock = (int)interlocked;
#if __SMP__
	__kdebug_only uintptr_t trace_lck = VM_KERNEL_UNSLIDE_OR_PERM(lock);
	thread_t                holder;
	uint64_t                overall_deadline;
	uint64_t                check_owner_deadline;
	uint64_t                cur_time;
	spinwait_result_t       retval = SPINWAIT_DID_SPIN;
	int                     loopcount = 0;
	uintptr_t               state;
	boolean_t               istate;

	if (__improbable(!(lck_mtx_adaptive_spin_mode & ADAPTIVE_SPIN_ENABLE))) {
		if (!has_interlock) {
			interlock_lock(lock);
		}

		return SPINWAIT_DID_NOT_SPIN;
	}

	state = ordered_load_mtx(lock);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_START,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(LCK_MTX_STATE_TO_THREAD(state)), lock->lck_mtx_waiters, 0, 0);

	cur_time = mach_absolute_time();
	overall_deadline = cur_time + MutexSpin;
	check_owner_deadline = cur_time;

	if (has_interlock) {
		istate = ml_get_interrupts_enabled();
	}

	/* Snoop the lock state */
	state = ordered_load_mtx(lock);

	/*
	 * Spin while:
	 *   - mutex is locked, and
	 *   - it's locked as a spin lock, and
	 *   - owner is running on another processor, and
	 *   - owner (processor) is not idling, and
	 *   - we haven't spun for long enough.
	 */
	do {
		if (!(state & LCK_ILOCK) || has_interlock) {
			if (!has_interlock) {
				has_interlock = interlock_try_disable_interrupts(lock, &istate);
			}

			if (has_interlock) {
				state = ordered_load_mtx(lock);
				holder = LCK_MTX_STATE_TO_THREAD(state);

				if (holder == NULL) {
					retval = SPINWAIT_INTERLOCK;

					if (istate) {
						ml_set_interrupts_enabled(istate);
					}

					break;
				}

				if (!(holder->machine.machine_thread_flags & MACHINE_THREAD_FLAGS_ON_CPU) ||
				    (holder->state & TH_IDLE)) {
					if (loopcount == 0) {
						retval = SPINWAIT_DID_NOT_SPIN;
					}

					if (istate) {
						ml_set_interrupts_enabled(istate);
					}

					break;
				}

				interlock_unlock_enable_interrupts(lock, istate);
				has_interlock = 0;
			}
		}

		cur_time = mach_absolute_time();

		if (cur_time >= overall_deadline) {
			break;
		}

		check_owner_deadline = cur_time + (MutexSpin / SPINWAIT_OWNER_CHECK_COUNT);

		if (cur_time < check_owner_deadline) {
			machine_delay_until(check_owner_deadline - cur_time, check_owner_deadline);
		}

		/* Snoop the lock state */
		state = ordered_load_mtx(lock);

		if (state == 0) {
			/* Try to grab the lock. */
			if (os_atomic_cmpxchg(&lock->lck_mtx_data,
			    0, LCK_MTX_THREAD_TO_STATE(thread), acquire)) {
				retval = SPINWAIT_ACQUIRED;
				break;
			}
		}

		loopcount++;
	} while (TRUE);

#if     CONFIG_DTRACE
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
	if (__probable(lock->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)) {
		LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN, lock,
		    mach_absolute_time() - (overall_deadline - MutexSpin));
	} else {
		LOCKSTAT_RECORD(LS_LCK_MTX_EXT_LOCK_SPIN, lock,
		    mach_absolute_time() - (overall_deadline - MutexSpin));
	}
	/* The lockstat acquire event is recorded by the caller. */
#endif

	state = ordered_load_mtx(lock);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_SPIN_CODE) | DBG_FUNC_END,
	    trace_lck, VM_KERNEL_UNSLIDE_OR_PERM(LCK_MTX_STATE_TO_THREAD(state)), lock->lck_mtx_waiters, retval, 0);
#else /* __SMP__ */
	/* Spinwaiting is not useful on UP systems. */
#pragma unused(lock, thread)
	int retval = SPINWAIT_DID_NOT_SPIN;
#endif /* __SMP__ */
	if ((!has_interlock) && (retval != SPINWAIT_ACQUIRED)) {
		/* We must own either the lock or the interlock on return. */
		interlock_lock(lock);
	}

	return retval;
}

/*
 *	Common code for mutex locking as spinlock
 */
static inline void
lck_mtx_lock_spin_internal(lck_mtx_t *lock, boolean_t allow_held_as_mutex)
{
	uintptr_t       state;

	interlock_lock(lock);
	state = ordered_load_mtx(lock);
	if (LCK_MTX_STATE_TO_THREAD(state)) {
		if (allow_held_as_mutex) {
			lck_mtx_lock_contended(lock, current_thread(), TRUE);
		} else {
			// "Always" variants can never block. If the lock is held and blocking is not allowed
			// then someone is mixing always and non-always calls on the same lock, which is
			// forbidden.
			panic("Attempting to block on a lock taken as spin-always %p", lock);
		}
		return;
	}
	state &= ARM_LCK_WAITERS;                                               // Preserve waiters bit
	state |= (LCK_MTX_SPIN_TAG | LCK_ILOCK);        // Add spin tag and maintain interlock
	ordered_store_mtx(lock, state);
	load_memory_barrier();

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_LOCK_SPIN_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
}

/*
 *	Routine:	lck_mtx_lock_spin
 */
void
lck_mtx_lock_spin(lck_mtx_t *lock)
{
	lck_mtx_check_preemption(lock);
	lck_mtx_lock_spin_internal(lock, TRUE);
}

/*
 *	Routine:	lck_mtx_lock_spin_always
 */
void
lck_mtx_lock_spin_always(lck_mtx_t *lock)
{
	lck_mtx_lock_spin_internal(lock, FALSE);
}

/*
 *	Routine:	lck_mtx_try_lock
 */
boolean_t
lck_mtx_try_lock(lck_mtx_t *lock)
{
	thread_t        thread = current_thread();

	lck_mtx_verify(lock);
	if (atomic_compare_exchange(&lock->lck_mtx_data, 0, LCK_MTX_THREAD_TO_STATE(thread),
	    memory_order_acquire_smp, FALSE)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_MTX_TRY_LOCK_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
		return TRUE;
	}
	return lck_mtx_try_lock_contended(lock, thread);
}

static boolean_t NOINLINE
lck_mtx_try_lock_contended(lck_mtx_t *lock, thread_t thread)
{
	thread_t        holding_thread;
	uintptr_t       state;
	int             waiters;

#if     __SMP__
	interlock_lock(lock);
	state = ordered_load_mtx(lock);
	holding_thread = LCK_MTX_STATE_TO_THREAD(state);
	if (holding_thread) {
		interlock_unlock(lock);
		return FALSE;
	}
#else
	disable_preemption_for_thread(thread);
	state = ordered_load_mtx(lock);
	if (state & LCK_ILOCK) {
		panic("Unexpected interlock set (%p)", lock);
	}
	holding_thread = LCK_MTX_STATE_TO_THREAD(state);
	if (holding_thread) {
		enable_preemption();
		return FALSE;
	}
	state |= LCK_ILOCK;
	ordered_store_mtx(lock, state);
#endif  // __SMP__
	waiters = lck_mtx_lock_acquire(lock);
	state = LCK_MTX_THREAD_TO_STATE(thread);
	if (waiters != 0) {
		state |= ARM_LCK_WAITERS;
	}
#if __SMP__
	state |= LCK_ILOCK;                             // Preserve interlock
	ordered_store_mtx(lock, state); // Set ownership
	interlock_unlock(lock);                 // Release interlock, enable preemption
#else
	ordered_store_mtx(lock, state); // Set ownership
	enable_preemption();
#endif
	load_memory_barrier();
	return TRUE;
}

static inline boolean_t
lck_mtx_try_lock_spin_internal(lck_mtx_t *lock, boolean_t allow_held_as_mutex)
{
	uintptr_t       state;

	if (!interlock_try(lock)) {
		return FALSE;
	}
	state = ordered_load_mtx(lock);
	if (LCK_MTX_STATE_TO_THREAD(state)) {
		// Lock is held as mutex
		if (allow_held_as_mutex) {
			interlock_unlock(lock);
		} else {
			// "Always" variants can never block. If the lock is held as a normal mutex
			// then someone is mixing always and non-always calls on the same lock, which is
			// forbidden.
			panic("Spin-mutex held as full mutex %p", lock);
		}
		return FALSE;
	}
	state &= ARM_LCK_WAITERS;                                               // Preserve waiters bit
	state |= (LCK_MTX_SPIN_TAG | LCK_ILOCK);        // Add spin tag and maintain interlock
	ordered_store_mtx(lock, state);
	load_memory_barrier();

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE, lock, 0);
#endif /* CONFIG_DTRACE */
	return TRUE;
}

/*
 *	Routine: lck_mtx_try_lock_spin
 */
boolean_t
lck_mtx_try_lock_spin(lck_mtx_t *lock)
{
	return lck_mtx_try_lock_spin_internal(lock, TRUE);
}

/*
 *	Routine: lck_mtx_try_lock_spin_always
 */
boolean_t
lck_mtx_try_lock_spin_always(lck_mtx_t *lock)
{
	return lck_mtx_try_lock_spin_internal(lock, FALSE);
}



/*
 *	Routine:	lck_mtx_unlock
 */
void
lck_mtx_unlock(lck_mtx_t *lock)
{
	thread_t        thread = current_thread();
	uintptr_t       state;
	boolean_t       ilk_held = FALSE;

	lck_mtx_verify(lock);

	state = ordered_load_mtx(lock);
	if (state & LCK_ILOCK) {
		if (LCK_MTX_STATE_TO_THREAD(state) == (thread_t)LCK_MTX_SPIN_TAG) {
			ilk_held = TRUE;        // Interlock is held by (presumably) this thread
		}
		goto slow_case;
	}
	// Locked as a mutex
	if (atomic_compare_exchange(&lock->lck_mtx_data, LCK_MTX_THREAD_TO_STATE(thread), 0,
	    memory_order_release_smp, FALSE)) {
#if     CONFIG_DTRACE
		LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, lock, 0);
#endif /* CONFIG_DTRACE */
		return;
	}
slow_case:
	lck_mtx_unlock_contended(lock, thread, ilk_held);
}

static void NOINLINE
lck_mtx_unlock_contended(lck_mtx_t *lock, thread_t thread, boolean_t ilk_held)
{
	uintptr_t       state;

	if (ilk_held) {
		state = ordered_load_mtx(lock);
	} else {
#if     __SMP__
		interlock_lock(lock);
		state = ordered_load_mtx(lock);
		if (thread != LCK_MTX_STATE_TO_THREAD(state)) {
			panic("lck_mtx_unlock(): Attempt to release lock not owned by thread (%p)", lock);
		}
#else
		disable_preemption_for_thread(thread);
		state = ordered_load_mtx(lock);
		if (state & LCK_ILOCK) {
			panic("lck_mtx_unlock(): Unexpected interlock set (%p)", lock);
		}
		if (thread != LCK_MTX_STATE_TO_THREAD(state)) {
			panic("lck_mtx_unlock(): Attempt to release lock not owned by thread (%p)", lock);
		}
		state |= LCK_ILOCK;
		ordered_store_mtx(lock, state);
#endif
		if (state & ARM_LCK_WAITERS) {
			lck_mtx_unlock_wakeup(lock, thread);
			state = ordered_load_mtx(lock);
		} else {
			assertf(lock->lck_mtx_pri == 0, "pri=0x%x", lock->lck_mtx_pri);
		}
	}
	state &= ARM_LCK_WAITERS;   /* Clear state, retain waiters bit */
#if __SMP__
	state |= LCK_ILOCK;
	ordered_store_mtx(lock, state);
	interlock_unlock(lock);
#else
	ordered_store_mtx(lock, state);
	enable_preemption();
#endif

#if     CONFIG_DTRACE
	LOCKSTAT_RECORD(LS_LCK_MTX_UNLOCK_RELEASE, lock, 0);
#endif /* CONFIG_DTRACE */
}

/*
 *	Routine:	lck_mtx_assert
 */
void
lck_mtx_assert(lck_mtx_t *lock, unsigned int type)
{
	thread_t        thread, holder;
	uintptr_t       state;

	state = ordered_load_mtx(lock);
	holder = LCK_MTX_STATE_TO_THREAD(state);
	if (holder == (thread_t)LCK_MTX_SPIN_TAG) {
		// Lock is held in spin mode, owner is unknown.
		return; // Punt
	}
	thread = current_thread();
	if (type == LCK_MTX_ASSERT_OWNED) {
		if (thread != holder) {
			panic("lck_mtx_assert(): mutex (%p) owned", lock);
		}
	} else if (type == LCK_MTX_ASSERT_NOTOWNED) {
		if (thread == holder) {
			panic("lck_mtx_assert(): mutex (%p) not owned", lock);
		}
	} else {
		panic("lck_mtx_assert(): invalid arg (%u)", type);
	}
}

/*
 *	Routine:	lck_mtx_ilk_unlock
 */
boolean_t
lck_mtx_ilk_unlock(lck_mtx_t *lock)
{
	interlock_unlock(lock);
	return TRUE;
}

/*
 *	Routine:	lck_mtx_convert_spin
 *
 *	Convert a mutex held for spin into a held full mutex
 */
void
lck_mtx_convert_spin(lck_mtx_t *lock)
{
	thread_t        thread = current_thread();
	uintptr_t       state;
	int                     waiters;

	state = ordered_load_mtx(lock);
	if (LCK_MTX_STATE_TO_THREAD(state) == thread) {
		return;         // Already owned as mutex, return
	}
	if ((state & LCK_ILOCK) == 0 || (LCK_MTX_STATE_TO_THREAD(state) != (thread_t)LCK_MTX_SPIN_TAG)) {
		panic("lck_mtx_convert_spin: Not held as spinlock (%p)", lock);
	}
	state &= ~(LCK_MTX_THREAD_MASK);                // Clear the spin tag
	ordered_store_mtx(lock, state);
	waiters = lck_mtx_lock_acquire(lock);   // Acquire to manage priority boosts
	state = LCK_MTX_THREAD_TO_STATE(thread);
	if (waiters != 0) {
		state |= ARM_LCK_WAITERS;
	}
#if __SMP__
	state |= LCK_ILOCK;
	ordered_store_mtx(lock, state);                 // Set ownership
	interlock_unlock(lock);                                 // Release interlock, enable preemption
#else
	ordered_store_mtx(lock, state);                 // Set ownership
	enable_preemption();
#endif
}


/*
 *      Routine:        lck_mtx_destroy
 */
void
lck_mtx_destroy(
	lck_mtx_t * lck,
	lck_grp_t * grp)
{
	if (lck->lck_mtx_type != LCK_MTX_TYPE) {
		panic("Destroying invalid mutex %p", lck);
	}
	if (lck->lck_mtx_tag == LCK_MTX_TAG_DESTROYED) {
		panic("Destroying previously destroyed lock %p", lck);
	}
	lck_mtx_assert(lck, LCK_MTX_ASSERT_NOTOWNED);
	lck->lck_mtx_tag = LCK_MTX_TAG_DESTROYED;
	lck_grp_lckcnt_decr(grp, LCK_TYPE_MTX);
	lck_grp_deallocate(grp);
	return;
}

/*
 *	Routine:	lck_spin_assert
 */
void
lck_spin_assert(lck_spin_t *lock, unsigned int type)
{
	thread_t        thread, holder;
	uintptr_t       state;

	if (lock->type != LCK_SPIN_TYPE) {
		panic("Invalid spinlock %p", lock);
	}

	state = lock->lck_spin_data;
	holder = (thread_t)(state & ~LCK_ILOCK);
	thread = current_thread();
	if (type == LCK_ASSERT_OWNED) {
		if (holder == 0) {
			panic("Lock not owned %p = %lx", lock, state);
		}
		if (holder != thread) {
			panic("Lock not owned by current thread %p = %lx", lock, state);
		}
		if ((state & LCK_ILOCK) == 0) {
			panic("Lock bit not set %p = %lx", lock, state);
		}
	} else if (type == LCK_ASSERT_NOTOWNED) {
		if (holder != 0) {
			if (holder == thread) {
				panic("Lock owned by current thread %p = %lx", lock, state);
			} else {
				panic("Lock %p owned by thread %p", lock, holder);
			}
		}
		if (state & LCK_ILOCK) {
			panic("Lock bit set %p = %lx", lock, state);
		}
	} else {
		panic("lck_spin_assert(): invalid arg (%u)", type);
	}
}

boolean_t
lck_rw_lock_yield_shared(lck_rw_t *lck, boolean_t force_yield)
{
	lck_rw_word_t   word;

	lck_rw_assert(lck, LCK_RW_ASSERT_SHARED);

	word.data = ordered_load_rw(lck);
	if (word.want_excl || word.want_upgrade || force_yield) {
		lck_rw_unlock_shared(lck);
		mutex_pause(2);
		lck_rw_lock_shared(lck);
		return TRUE;
	}

	return FALSE;
}

/*
 * Routine: kdp_lck_mtx_lock_spin_is_acquired
 * NOT SAFE: To be used only by kernel debugger to avoid deadlock.
 */
boolean_t
kdp_lck_mtx_lock_spin_is_acquired(lck_mtx_t *lck)
{
	uintptr_t       state;

	if (not_in_kdp) {
		panic("panic: spinlock acquired check done outside of kernel debugger");
	}
	state = ordered_load_mtx(lck);
	if (state == LCK_MTX_TAG_DESTROYED) {
		return FALSE;
	}
	if (LCK_MTX_STATE_TO_THREAD(state) || (state & LCK_ILOCK)) {
		return TRUE;
	}
	return FALSE;
}

void
kdp_lck_mtx_find_owner(__unused struct waitq * waitq, event64_t event, thread_waitinfo_t * waitinfo)
{
	lck_mtx_t * mutex = LCK_EVENT_TO_MUTEX(event);
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(mutex);
	uintptr_t state   = ordered_load_mtx(mutex);
	thread_t holder   = LCK_MTX_STATE_TO_THREAD(state);
	if ((uintptr_t)holder == (uintptr_t)LCK_MTX_SPIN_TAG) {
		waitinfo->owner = STACKSHOT_WAITOWNER_MTXSPIN;
	} else {
		assertf(state != (uintptr_t)LCK_MTX_TAG_DESTROYED, "state=0x%llx", (uint64_t)state);
		assertf(state != (uintptr_t)LCK_MTX_TAG_INDIRECT, "state=0x%llx", (uint64_t)state);
		waitinfo->owner = thread_tid(holder);
	}
}

void
kdp_rwlck_find_owner(__unused struct waitq * waitq, event64_t event, thread_waitinfo_t * waitinfo)
{
	lck_rw_t        *rwlck = NULL;
	switch (waitinfo->wait_type) {
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
	waitinfo->owner = thread_tid(rwlck->lck_rw_owner);
}
