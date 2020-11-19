/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#ifdef __x86_64__
#error This file is only needed on weakly-ordered systems!
#endif

#include <machine/atomic.h>
#include <machine/commpage.h>
#include <machine/machine_cpu.h>

#include <kern/sched_prim.h>
#include <kern/percpu.h>
#include <kern/ast.h>

#include <kern/cpu_quiesce.h>

/*
 * CPU quiescing generation counter implemented with a checkin mask
 *
 * A tri-state bitfield, with 2 bits for each processor:;
 * 1) 'checkin' bit, saying this processor has 'checked in', i.e. executed the acqrel barrier
 * 2) 'expected' bit, saying this processor is expected to check in, i.e. not idle.
 *
 * When a processor causes the 'expected' bits to equal the 'checkin' bits, which
 * indicates that all processors have executed the barrier, it ticks the algorithm
 * and resets the state.
 *
 * Idle CPUs won't check in, because they don't run, so the algorithm won't tick.
 * However, they can't do anything in userspace while idle, so we don't need
 * them to execute barriers, so we have them 'leave' the counter so that
 * they don't delay the tick while idle.
 *
 * This bitfield currently limits MAX_CPUS to 32 on LP64.
 * In the future, we can use double-wide atomics and int128 if we need 64 CPUS.
 *
 * The mask only guarantees ordering to code running in userspace.
 * We defer joining the counter until we actually reach userspace, allowing
 * processors that come out of idle and only run kernel code to avoid the overhead
 * of participation.
 *
 * We additionally defer updating the counter for a minimum interval to
 * reduce the frequency of executing the exclusive atomic operations.
 *
 * The longest delay between two checkins assuming that at least one processor
 * joins is <checkin delay> + (<thread quantum> * 2)
 */

typedef unsigned long checkin_mask_t;

static _Atomic checkin_mask_t cpu_quiescing_checkin_state;

static uint64_t cpu_checkin_last_commit;

struct cpu_quiesce {
	cpu_quiescent_state_t   state;
	uint64_t                last_checkin;
};

static struct cpu_quiesce PERCPU_DATA(cpu_quiesce);

#define CPU_CHECKIN_MIN_INTERVAL_US     4000 /* 4ms */
#define CPU_CHECKIN_MIN_INTERVAL_MAX_US USEC_PER_SEC /* 1s */
static uint64_t cpu_checkin_min_interval;
static uint32_t cpu_checkin_min_interval_us;

#if __LP64__
static_assert(MAX_CPUS <= 32);
#define CPU_CHECKIN_MASK        0x5555555555555555UL
#define CPU_EXPECTED_MASK       (~CPU_CHECKIN_MASK)
#else
/* Avoid double-wide CAS on 32-bit platforms by using a 32-bit state and mask */
static_assert(MAX_CPUS <= 16);
#define CPU_CHECKIN_MASK        0x55555555UL
#define CPU_EXPECTED_MASK       (~CPU_CHECKIN_MASK)
#endif

static_assert(CPU_CHECKIN_MASK == CPU_EXPECTED_MASK >> 1);

static inline checkin_mask_t
cpu_checked_in_bit(int cpuid)
{
	return 1UL << (2 * cpuid);
}

static inline checkin_mask_t
cpu_expected_bit(int cpuid)
{
	return 1UL << (2 * cpuid + 1);
}

void
cpu_quiescent_counter_init(void)
{
	assert(CPU_CHECKIN_MASK & cpu_checked_in_bit(MAX_CPUS));
	assert(CPU_EXPECTED_MASK & cpu_expected_bit(MAX_CPUS));
	assert((CPU_CHECKIN_MASK & cpu_expected_bit(MAX_CPUS)) == 0);
	assert((CPU_EXPECTED_MASK & cpu_checked_in_bit(MAX_CPUS)) == 0);

	cpu_quiescent_counter_set_min_interval_us(CPU_CHECKIN_MIN_INTERVAL_US);
}

void
cpu_quiescent_counter_set_min_interval_us(uint32_t new_value_us)
{
	/* clamp to something vaguely sane */
	if (new_value_us > CPU_CHECKIN_MIN_INTERVAL_MAX_US) {
		new_value_us = CPU_CHECKIN_MIN_INTERVAL_MAX_US;
	}

	cpu_checkin_min_interval_us = new_value_us;

	uint64_t abstime = 0;
	clock_interval_to_absolutetime_interval(cpu_checkin_min_interval_us,
	    NSEC_PER_USEC, &abstime);
	cpu_checkin_min_interval = abstime;
}

uint32_t
cpu_quiescent_counter_get_min_interval_us(void)
{
	return cpu_checkin_min_interval_us;
}


/*
 * Called when all running CPUs have checked in.
 *
 * The commpage increment is protected by the 'lock' of having caused the tick,
 * and it is published by the state reset release barrier.
 */
static void
cpu_quiescent_counter_commit(uint64_t ctime)
{
	__kdebug_only uint64_t          old_gen;
	__kdebug_only checkin_mask_t    old_state;

	old_gen = commpage_increment_cpu_quiescent_counter();

	cpu_checkin_last_commit = ctime;

	old_state = os_atomic_andnot(&cpu_quiescing_checkin_state, CPU_CHECKIN_MASK, release);

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_QUIESCENT_COUNTER), old_gen, old_state, ctime, 0);
}

/*
 * Have all the expected CPUs checked in?
 */
static bool
cpu_quiescent_counter_needs_commit(checkin_mask_t state)
{
	return (state & CPU_CHECKIN_MASK) == ((state & CPU_EXPECTED_MASK) >> 1);
}

/*
 * Called when a processor wants to start participating in the counter, e.g.
 * 1) when context switching away from the idle thread
 * 2) when coming up for the first time
 * 3) when coming up after a shutdown
 *
 * Called with interrupts disabled.
 */
void
cpu_quiescent_counter_join(__unused uint64_t ctime)
{
	struct cpu_quiesce *st = PERCPU_GET(cpu_quiesce);
	__assert_only int cpuid = cpu_number();

	assert(st->state == CPU_QUIESCE_COUNTER_NONE ||
	    st->state == CPU_QUIESCE_COUNTER_LEFT);

	assert((os_atomic_load(&cpu_quiescing_checkin_state, relaxed) &
	    (cpu_expected_bit(cpuid) | cpu_checked_in_bit(cpuid))) == 0);

	st->state = CPU_QUIESCE_COUNTER_PENDING_JOIN;

	/*
	 * Mark the processor to call cpu_quiescent_counter_ast before it
	 * ever returns to userspace.
	 */
	ast_on(AST_UNQUIESCE);
}

/*
 * Called with interrupts disabled from the userspace boundary at the AST_UNQUIESCE callback
 * It needs to acquire the counter to see data and the counter published by other CPUs.
 */
void
cpu_quiescent_counter_ast(void)
{
	struct cpu_quiesce *st = PERCPU_GET(cpu_quiesce);
	int cpuid = cpu_number();

	assert(st->state == CPU_QUIESCE_COUNTER_PENDING_JOIN);

	/* We had better not already be joined. */
	assert((os_atomic_load(&cpu_quiescing_checkin_state, relaxed) &
	    (cpu_expected_bit(cpuid) | cpu_checked_in_bit(cpuid))) == 0);

	/*
	 * No release barrier needed because we have no prior state to publish.
	 * Acquire barrier needed because we need this processor to see
	 * the latest counter value.
	 *
	 * The state may be in 'needs checkin' both before and after
	 * this atomic or.
	 *
	 * Additionally, if this is the first processor to come out of idle,
	 * it may need to kickstart the algorithm, otherwise it would
	 * stay in 'needs commit' perpetually with no processor assigned to
	 * actually do the commit.  To do that, the first processor only adds
	 * its expected bit.
	 */

	st->state = CPU_QUIESCE_COUNTER_JOINED;
	st->last_checkin = mach_absolute_time();

	checkin_mask_t old_mask, new_mask;
	os_atomic_rmw_loop(&cpu_quiescing_checkin_state, old_mask, new_mask, acquire, {
		if (old_mask == 0) {
		        new_mask = old_mask | cpu_expected_bit(cpuid);
		} else {
		        new_mask = old_mask | cpu_expected_bit(cpuid) | cpu_checked_in_bit(cpuid);
		}
	});
}

/*
 * Called when a processor no longer wants to participate in the counter,
 * i.e. when a processor is on its way to idle or shutdown.
 *
 * Called with interrupts disabled.
 *
 * The processor needs to remove itself from the expected mask, to allow the
 * algorithm to continue ticking without its participation.
 * However, it needs to ensure that anything it has done since the last time
 * it checked in has been published before the next tick is allowed to commit.
 */
void
cpu_quiescent_counter_leave(uint64_t ctime)
{
	struct cpu_quiesce *st = PERCPU_GET(cpu_quiesce);
	int cpuid = cpu_number();

	assert(st->state == CPU_QUIESCE_COUNTER_JOINED ||
	    st->state == CPU_QUIESCE_COUNTER_PENDING_JOIN);

	/* We no longer need the cpu_quiescent_counter_ast callback to be armed */
	ast_off(AST_UNQUIESCE);

	if (st->state == CPU_QUIESCE_COUNTER_PENDING_JOIN) {
		/* We never actually joined, so we don't have to do the work to leave. */
		st->state = CPU_QUIESCE_COUNTER_LEFT;
		return;
	}

	/* Leaving can't be deferred, even if we're within the min interval */
	st->last_checkin = ctime;

	checkin_mask_t mask = cpu_checked_in_bit(cpuid) | cpu_expected_bit(cpuid);

	checkin_mask_t orig_state = os_atomic_andnot_orig(&cpu_quiescing_checkin_state,
	    mask, acq_rel);

	assert((orig_state & cpu_expected_bit(cpuid)));

	st->state = CPU_QUIESCE_COUNTER_LEFT;

	if (cpu_quiescent_counter_needs_commit(orig_state)) {
		/*
		 * the old state indicates someone else was already doing a commit
		 * but hadn't finished yet.  We successfully inserted the acq_rel
		 * before they finished the commit by resetting the bitfield,
		 * so we're done here.
		 */
		return;
	}

	checkin_mask_t new_state = orig_state & ~mask;

	if (cpu_quiescent_counter_needs_commit(new_state)) {
		cpu_quiescent_counter_commit(ctime);
	}
}

/*
 * Called when a processor wants to check in to the counter
 * If it hasn't yet fully joined, it doesn't need to check in.
 *
 * Called with interrupts disabled.
 */
void
cpu_quiescent_counter_checkin(uint64_t ctime)
{
	struct cpu_quiesce *st = PERCPU_GET(cpu_quiesce);
	int cpuid = cpu_number();

	assert(st->state != CPU_QUIESCE_COUNTER_NONE);

	/* If we're not joined yet, we don't need to check in */
	if (__probable(st->state != CPU_QUIESCE_COUNTER_JOINED)) {
		return;
	}

	/* If we've checked in recently, we don't need to check in yet. */
	if (__probable((ctime - st->last_checkin) <= cpu_checkin_min_interval)) {
		return;
	}

	st->last_checkin = ctime;

	checkin_mask_t state = os_atomic_load(&cpu_quiescing_checkin_state, relaxed);

	assert((state & cpu_expected_bit(cpuid)));

	if (__probable((state & cpu_checked_in_bit(cpuid)))) {
		/*
		 * Processor has already checked in for this round, no need to
		 * acquire the cacheline exclusive.
		 */
		return;
	}

	checkin_mask_t orig_state = os_atomic_or_orig(&cpu_quiescing_checkin_state,
	    cpu_checked_in_bit(cpuid), acq_rel);

	checkin_mask_t new_state = orig_state | cpu_checked_in_bit(cpuid);

	if (cpu_quiescent_counter_needs_commit(new_state)) {
		assertf(!cpu_quiescent_counter_needs_commit(orig_state),
		    "old: 0x%lx, new: 0x%lx", orig_state, new_state);
		cpu_quiescent_counter_commit(ctime);
	}
}

#if MACH_ASSERT
/*
 * Called on all AST exits to userspace to assert this processor actually joined
 *
 * Called with interrupts disabled after the AST should have been handled
 */
void
cpu_quiescent_counter_assert_ast(void)
{
	struct cpu_quiesce *st = PERCPU_GET(cpu_quiesce);
	int cpuid = cpu_number();

	assert(st->state == CPU_QUIESCE_COUNTER_JOINED);

	checkin_mask_t state = os_atomic_load(&cpu_quiescing_checkin_state, relaxed);
	assert((state & cpu_expected_bit(cpuid)));
}
#endif /* MACH_ASSERT */
