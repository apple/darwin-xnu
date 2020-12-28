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
#define ATOMIC_PRIVATE 1
#define LOCK_PRIVATE 1

#include <stdint.h>
#include <kern/thread.h>
#include <machine/atomic.h>
#include <kern/locks.h>
#include <machine/machine_cpu.h>

#if defined(__x86_64__)
#include <i386/mp.h>
extern uint64_t LockTimeOutTSC;
#define TICKET_LOCK_PANIC_TIMEOUT LockTimeOutTSC
#endif

#if defined(__arm__) || defined(__arm64__)
extern uint64_t TLockTimeOut;
#define TICKET_LOCK_PANIC_TIMEOUT TLockTimeOut
#endif
/* "Ticket": A FIFO spinlock with constant backoff
 * cf. Algorithms for Scalable Synchronization on Shared-Memory Multiprocessors
 * by Mellor-Crumney and Scott, 1991
 */

/* TODO: proportional back-off based on desired-current ticket distance
 * This has the potential to considerably reduce snoop traffic
 * but must be tuned carefully
 * TODO: UP implementation.
 * Currently only used within the scheduler, where it is acquired with
 * interrupts masked, and consequently doesn't require a uniprocessor
 * implementation.
 * TODO: Evaluate a bias towards the performant clusters on
 * asymmetric efficient/performant multi-cluster systems, while
 * retaining the starvation-free property. A small intra-cluster bias may
 * be profitable for overall throughput
 */

void
lck_ticket_init(lck_ticket_t *tlock)
{
	memset(tlock, 0, sizeof(*tlock));
	/* Current ticket size limit--tickets can be trivially expanded
	 * to 16-bits if needed
	 */
	static_assert(MAX_CPUS < 256);

	__assert_only   lck_ticket_internal *tlocki = &tlock->tu;
	/* Verify alignment */
	__assert_only uintptr_t tcn = (uintptr_t) &tlocki->tcurnext;
	__assert_only uintptr_t tc = (uintptr_t) &tlocki->cticket;
	__assert_only uintptr_t tn = (uintptr_t) &tlocki->nticket;

	assert(((tcn & 3) == 0) && (tcn == tc) && (tn == (tc + 1)));
}

static void
tlock_mark_owned(lck_ticket_t *tlock, thread_t cthread)
{
	assert(tlock->lck_owner == 0);
	/* There is a small pre-emption disabled window (also interrupts masked
	 * for the pset lock) between the acquisition of the lock and the
	 * population of the advisory 'owner' thread field
	 * On architectures with a DCAS (ARM v8.1 or x86), conceivably we could
	 * populate the next ticket and the thread atomically, with
	 * possible overhead, potential loss of micro-architectural fwd progress
	 * properties of an unconditional fetch-add, and a 16 byte alignment requirement.
	 */
	__c11_atomic_store((_Atomic thread_t *)&tlock->lck_owner, cthread, __ATOMIC_RELAXED);
}

#if __arm__ || __arm64__
__unused static uint8_t
load_exclusive_acquire8(uint8_t *target)
{
	uint8_t value;
#if __arm__
	value = __builtin_arm_ldrex(target);
	__c11_atomic_thread_fence(__ATOMIC_ACQUIRE);
#else
	value = __builtin_arm_ldaex(target);    // ldaxr
	/* "Compiler barrier", no barrier instructions are emitted */
	atomic_signal_fence(memory_order_acquire);
#endif
	return value;
}
#endif

/* On contention, poll for ownership
 * Returns when the current ticket is observed equal to "mt"
 */
static void __attribute__((noinline))
tlock_contended(uint8_t *tp, uint8_t mt, lck_ticket_t *tlock, thread_t cthread)
{
	uint8_t cticket;
	uint64_t etime = 0, ctime = 0, stime = 0;

	assertf(tlock->lck_owner != (uintptr_t) cthread, "Recursive ticket lock, owner: %p, current thread: %p", (void *) tlock->lck_owner, (void *) cthread);

	for (;;) {
		for (int i = 0; i < LOCK_SNOOP_SPINS; i++) {
#if (__ARM_ENABLE_WFE_)
			if ((cticket = load_exclusive_acquire8(tp)) != mt) {
				wait_for_event();
			} else {
				/* Some micro-architectures may benefit
				 * from disarming the monitor.
				 * TODO: determine specific micro-architectures
				 * which benefit, modern CPUs may not
				 */
				os_atomic_clear_exclusive();
				tlock_mark_owned(tlock, cthread);
				return;
			}
#else /* !WFE */
#if defined(__x86_64__)
			__builtin_ia32_pause();
#endif /* x64 */
			if ((cticket = __c11_atomic_load((_Atomic uint8_t *) tp, __ATOMIC_SEQ_CST)) == mt) {
				tlock_mark_owned(tlock, cthread);
				return;
			}
#endif /* !WFE */
		}

		if (etime == 0) {
			stime = ml_get_timebase();
			etime = stime + TICKET_LOCK_PANIC_TIMEOUT;
		} else if ((ctime = ml_get_timebase()) >= etime) {
			break;
		}
	}
#if defined (__x86_64__)
	uintptr_t lowner = tlock->lck_owner;
	uint32_t ocpu = spinlock_timeout_NMI(lowner);
	panic("Ticket spinlock timeout; start: 0x%llx, end: 0x%llx, current: 0x%llx, lock: %p, *lock: 0x%x, waiting for 0x%x, pre-NMI owner: %p, current owner: %p, owner CPU: 0x%x", stime, etime, ctime, tp, *tp, mt, (void *) lowner, (void *) tlock->lck_owner, ocpu);
#else
	panic("Ticket spinlock timeout; start: 0x%llx, end: 0x%llx, current: 0x%llx, lock: %p, *lock: 0x%x, waiting for 0x%x, owner: %p", stime, etime, ctime, tp, *tp, mt, (void *) tlock->lck_owner);
#endif
}

void
lck_ticket_lock(lck_ticket_t *tlock)
{
	lck_ticket_internal *tlocki = &tlock->tu;
	thread_t cthread = current_thread();
	lck_ticket_internal tlocka;

	disable_preemption_for_thread(cthread);
	/* Atomically load both the current and next ticket, and increment the
	 * latter. Wrap of the ticket field is OK as long as the total
	 * number of contending CPUs is < maximum ticket
	 */
	tlocka.tcurnext = __c11_atomic_fetch_add((_Atomic uint16_t *)&tlocki->tcurnext, 1U << 8, __ATOMIC_ACQUIRE);

	/* Contention? branch to out of line contended block */
	if (__improbable(tlocka.cticket != tlocka.nticket)) {
		return tlock_contended(&tlocki->cticket, tlocka.nticket, tlock, cthread);
	}

	tlock_mark_owned(tlock, cthread);
}

void
lck_ticket_unlock(lck_ticket_t *tlock)
{
	lck_ticket_internal *tlocki = &tlock->tu;

	assertf(tlock->lck_owner == (uintptr_t) current_thread(), "Ticket unlock non-owned, owner: %p", (void *) tlock->lck_owner);

	__c11_atomic_store((_Atomic uintptr_t *)&tlock->lck_owner, 0, __ATOMIC_RELAXED);

#if defined(__x86_64__)
	/* Communicate desired release semantics to the compiler */
	__c11_atomic_thread_fence(__ATOMIC_RELEASE);
	/* '+ constraint indicates a read modify write */
	/* I have not yet located a c11 primitive which synthesizes an 'INC <MEM>',
	 * i.e. a specified-granule non-atomic memory read-modify-write.
	 */
	__asm__ volatile ("incb %0" : "+m"(tlocki->cticket) :: "cc");
#else /* !x86_64 */
	uint8_t cticket = __c11_atomic_load((_Atomic uint8_t *) &tlocki->cticket, __ATOMIC_RELAXED);
	cticket++;
	__c11_atomic_store((_Atomic uint8_t *) &tlocki->cticket, cticket, __ATOMIC_RELEASE);
#if __arm__
	set_event();
#endif  // __arm__
#endif /* !x86_64 */
	enable_preemption();
}

void
lck_ticket_assert_owned(__assert_only lck_ticket_t *tlock)
{
	assertf(__c11_atomic_load((_Atomic thread_t *)&tlock->lck_owner, __ATOMIC_RELAXED) == current_thread(), "lck_ticket_assert_owned: owner %p, current: %p", (void *) tlock->lck_owner, current_thread());
}
