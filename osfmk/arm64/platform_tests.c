/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

#include <mach_ldebug.h>

#define LOCK_PRIVATE 1

#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/xpr.h>
#include <kern/debug.h>
#include <string.h>
#include <tests/xnupost.h>

#if	MACH_KDB
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_sym.h>
#include <ddb/db_print.h>
#endif				/* MACH_KDB */

#include <sys/kdebug.h>
#include <sys/munge.h>
#include <machine/cpu_capabilities.h>
#include <arm/cpu_data_internal.h>

extern boolean_t arm_pan_enabled;
kern_return_t arm64_lock_test(void);
kern_return_t arm64_munger_test(void);
kern_return_t ex_cb_test(void);
kern_return_t arm64_pan_test(void);

// exception handler ignores this fault address during PAN test
#if __ARM_PAN_AVAILABLE__
vm_offset_t pan_test_addr;
#endif

#include <libkern/OSAtomic.h>
#define LOCK_TEST_ITERATIONS 50
static hw_lock_data_t 	lt_hw_lock;
static lck_spin_t 	lt_lck_spin_t;
static lck_mtx_t	lt_mtx;
static lck_rw_t		lt_rwlock;
static volatile uint32_t lt_counter = 0;
static volatile int 	lt_spinvolatile;
static volatile uint32_t lt_max_holders = 0;
static volatile uint32_t lt_upgrade_holders = 0;
static volatile uint32_t lt_max_upgrade_holders = 0;
static volatile uint32_t lt_num_holders = 0;
static volatile uint32_t lt_done_threads;
static volatile uint32_t lt_target_done_threads;
static volatile uint32_t lt_cpu_bind_id = 0;

static void
lt_note_another_blocking_lock_holder() 
{
	hw_lock_lock(&lt_hw_lock);
	lt_num_holders++;
	lt_max_holders = (lt_max_holders < lt_num_holders) ? lt_num_holders : lt_max_holders;
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_note_blocking_lock_release() 
{
	hw_lock_lock(&lt_hw_lock);
	lt_num_holders--;
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_spin_a_little_bit() 
{
	uint32_t i;
	
	for (i = 0; i < 10000; i++) {
		lt_spinvolatile++;
	}
}

static void
lt_sleep_a_little_bit() 
{
	delay(100);
}

static void
lt_grab_mutex() 
{
	lck_mtx_lock(&lt_mtx);
	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_counter++;
	lt_note_blocking_lock_release();
	lck_mtx_unlock(&lt_mtx);
}

static void
lt_grab_mutex_with_try()
{
	while(0 == lck_mtx_try_lock(&lt_mtx));
	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_counter++;
	lt_note_blocking_lock_release();
	lck_mtx_unlock(&lt_mtx);

}

static void
lt_grab_rw_exclusive()
{
	lck_rw_lock_exclusive(&lt_rwlock);
	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_counter++;
	lt_note_blocking_lock_release();
	lck_rw_done(&lt_rwlock);
}

static void
lt_grab_rw_exclusive_with_try()
{
	while(0 == lck_rw_try_lock_exclusive(&lt_rwlock)) {
		lt_sleep_a_little_bit();
	}

	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_counter++;
	lt_note_blocking_lock_release();
	lck_rw_done(&lt_rwlock);
}

/* Disabled until lt_grab_rw_shared() is fixed (rdar://30685840)
static void 
lt_grab_rw_shared()
{
	lck_rw_lock_shared(&lt_rwlock);
	lt_counter++;

	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_note_blocking_lock_release();

	lck_rw_done(&lt_rwlock);
}
*/

/* Disabled until lt_grab_rw_shared_with_try() is fixed (rdar://30685840)
static void 
lt_grab_rw_shared_with_try()
{
	while(0 == lck_rw_try_lock_shared(&lt_rwlock));
	lt_counter++;

	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_note_blocking_lock_release();

	lck_rw_done(&lt_rwlock);
}
*/

static void
lt_upgrade_downgrade_rw() 
{
	boolean_t upgraded, success;

	success = lck_rw_try_lock_shared(&lt_rwlock);
	if (!success) {
		lck_rw_lock_shared(&lt_rwlock);
	}

	lt_note_another_blocking_lock_holder();
	lt_sleep_a_little_bit();
	lt_note_blocking_lock_release();
	
	upgraded = lck_rw_lock_shared_to_exclusive(&lt_rwlock);
	if (!upgraded) {
		success = lck_rw_try_lock_exclusive(&lt_rwlock);

		if (!success) {
			lck_rw_lock_exclusive(&lt_rwlock);
		}
	}

	lt_upgrade_holders++;
	if (lt_upgrade_holders > lt_max_upgrade_holders) {
		lt_max_upgrade_holders = lt_upgrade_holders;
	}

	lt_counter++;
	lt_sleep_a_little_bit();

	lt_upgrade_holders--;
	
	lck_rw_lock_exclusive_to_shared(&lt_rwlock);

	lt_spin_a_little_bit();
	lck_rw_done(&lt_rwlock);
}

const int limit = 1000000;
static int lt_stress_local_counters[MAX_CPUS];

static void
lt_stress_hw_lock()
{
	int local_counter = 0;

	uint cpuid = current_processor()->cpu_id;

	kprintf("%s>cpu %d starting\n", __FUNCTION__, cpuid);

	hw_lock_lock(&lt_hw_lock);
	lt_counter++;
	local_counter++;
	hw_lock_unlock(&lt_hw_lock);

	while (lt_counter < lt_target_done_threads) {
		;
	}

	kprintf("%s>cpu %d started\n", __FUNCTION__, cpuid);

	while (lt_counter < limit) {
		spl_t s = splsched();
		hw_lock_lock(&lt_hw_lock);
		if (lt_counter < limit) {
			lt_counter++;
			local_counter++;
		}
		hw_lock_unlock(&lt_hw_lock);
		splx(s);
	}

	lt_stress_local_counters[cpuid] = local_counter;

	kprintf("%s>final counter %d cpu %d incremented the counter %d times\n", __FUNCTION__, lt_counter, cpuid, local_counter);
}

static void
lt_grab_hw_lock() 
{
	hw_lock_lock(&lt_hw_lock);
	lt_counter++;
	lt_spin_a_little_bit();
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_grab_hw_lock_with_try()
{
	while(0 == hw_lock_try(&lt_hw_lock));
	lt_counter++;
	lt_spin_a_little_bit();
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_grab_hw_lock_with_to()
{
	while(0 == hw_lock_to(&lt_hw_lock, LockTimeOut))
		mp_enable_preemption();
	lt_counter++;
	lt_spin_a_little_bit();
	hw_lock_unlock(&lt_hw_lock);
}

static void
lt_grab_spin_lock() 
{
	lck_spin_lock(&lt_lck_spin_t);
	lt_counter++;
	lt_spin_a_little_bit();
	lck_spin_unlock(&lt_lck_spin_t);
}

static void
lt_grab_spin_lock_with_try() 
{
	while(0 == lck_spin_try_lock(&lt_lck_spin_t));
	lt_counter++;
	lt_spin_a_little_bit();
	lck_spin_unlock(&lt_lck_spin_t);
}

static volatile boolean_t lt_thread_lock_grabbed;
static volatile boolean_t lt_thread_lock_success;

static void
lt_reset()
{
	lt_counter = 0;
	lt_max_holders = 0;
	lt_num_holders = 0;
	lt_max_upgrade_holders = 0;
	lt_upgrade_holders = 0;
	lt_done_threads = 0;
	lt_target_done_threads = 0;
	lt_cpu_bind_id = 0;

	OSMemoryBarrier();
}

static void
lt_trylock_hw_lock_with_to()
{
	OSMemoryBarrier();
	while (!lt_thread_lock_grabbed) {
		lt_sleep_a_little_bit();
		OSMemoryBarrier();
	}
	lt_thread_lock_success = hw_lock_to(&lt_hw_lock, 100);
	OSMemoryBarrier();
	mp_enable_preemption();
}

static void
lt_trylock_spin_try_lock()
{
	OSMemoryBarrier();
	while (!lt_thread_lock_grabbed) {
		lt_sleep_a_little_bit();
		OSMemoryBarrier();
	}
	lt_thread_lock_success = lck_spin_try_lock(&lt_lck_spin_t);
	OSMemoryBarrier();
}

static void
lt_trylock_thread(void *arg, wait_result_t wres __unused)
{
	void (*func)(void) = (void(*)(void))arg;

	func();

	OSIncrementAtomic((volatile SInt32*) &lt_done_threads);
}

static void
lt_start_trylock_thread(thread_continue_t func)
{
	thread_t thread;
	kern_return_t kr;

	kr = kernel_thread_start(lt_trylock_thread, func, &thread);
	assert(kr == KERN_SUCCESS);

	thread_deallocate(thread);
}

static void
lt_wait_for_lock_test_threads()
{
	OSMemoryBarrier();
	/* Spin to reduce dependencies */
	while (lt_done_threads < lt_target_done_threads) {
		lt_sleep_a_little_bit();
		OSMemoryBarrier();
	}
	OSMemoryBarrier();
}

static kern_return_t
lt_test_trylocks()
{
	boolean_t success; 
	
	/* 
	 * First mtx try lock succeeds, second fails.
	 */
	success = lck_mtx_try_lock(&lt_mtx);
	T_ASSERT_NOTNULL(success, "First mtx try lock");
	success = lck_mtx_try_lock(&lt_mtx);
	T_ASSERT_NULL(success, "Second mtx try lock for a locked mtx");
	lck_mtx_unlock(&lt_mtx);

	/*
	 * After regular grab, can't try lock.
	 */
	lck_mtx_lock(&lt_mtx);
	success = lck_mtx_try_lock(&lt_mtx);
	T_ASSERT_NULL(success, "try lock should fail after regular lck_mtx_lock");
	lck_mtx_unlock(&lt_mtx);

	/*
	 * Two shared try locks on a previously unheld rwlock suceed, and a 
	 * subsequent exclusive attempt fails.
	 */
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NOTNULL(success, "Two shared try locks on a previously unheld rwlock should succeed");
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NOTNULL(success, "Two shared try locks on a previously unheld rwlock should succeed");
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NULL(success, "exclusive lock attempt on previously held lock should fail");
	lck_rw_done(&lt_rwlock);
	lck_rw_done(&lt_rwlock);

	/*
	 * After regular shared grab, can trylock
	 * for shared but not for exclusive.
	 */
	lck_rw_lock_shared(&lt_rwlock);
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NOTNULL(success, "After regular shared grab another shared try lock should succeed.");
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NULL(success, "After regular shared grab an exclusive lock attempt should fail.");
	lck_rw_done(&lt_rwlock);
	lck_rw_done(&lt_rwlock);

	/*
	 * An exclusive try lock succeeds, subsequent shared and exclusive
	 * attempts fail.
	 */
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NOTNULL(success, "An exclusive try lock should succeed");
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NULL(success, "try lock in shared mode attempt after an exclusive grab should fail");
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NULL(success, "try lock in exclusive mode attempt after an exclusive grab should fail");
	lck_rw_done(&lt_rwlock);

	/*
	 * After regular exclusive grab, neither kind of trylock succeeds.
	 */
	lck_rw_lock_exclusive(&lt_rwlock);
	success = lck_rw_try_lock_shared(&lt_rwlock);
	T_ASSERT_NULL(success, "After regular exclusive grab, shared trylock should not succeed");
	success = lck_rw_try_lock_exclusive(&lt_rwlock);
	T_ASSERT_NULL(success, "After regular exclusive grab, exclusive trylock should not succeed");
	lck_rw_done(&lt_rwlock);

	/* 
	 * First spin lock attempts succeed, second attempts fail.
	 */
	success = hw_lock_try(&lt_hw_lock);
	T_ASSERT_NOTNULL(success, "First spin lock attempts should succeed");
	success = hw_lock_try(&lt_hw_lock);
	T_ASSERT_NULL(success, "Second attempt to spin lock should fail");
	hw_lock_unlock(&lt_hw_lock);
	
	hw_lock_lock(&lt_hw_lock);
	success = hw_lock_try(&lt_hw_lock);
	T_ASSERT_NULL(success, "After taking spin lock, trylock attempt should fail");
	hw_lock_unlock(&lt_hw_lock);

	lt_reset();
	lt_thread_lock_grabbed = false;
	lt_thread_lock_success = true;
	lt_target_done_threads = 1;
	OSMemoryBarrier();
	lt_start_trylock_thread(lt_trylock_hw_lock_with_to);
	success = hw_lock_to(&lt_hw_lock, 100);
	T_ASSERT_NOTNULL(success, "First spin lock with timeout should succeed");
	OSIncrementAtomic((volatile SInt32*)&lt_thread_lock_grabbed);
	lt_wait_for_lock_test_threads();
	T_ASSERT_NULL(lt_thread_lock_success, "Second spin lock with timeout should fail and timeout");
	hw_lock_unlock(&lt_hw_lock);

	lt_reset();
	lt_thread_lock_grabbed = false;
	lt_thread_lock_success = true;
	lt_target_done_threads = 1;
	OSMemoryBarrier();
	lt_start_trylock_thread(lt_trylock_hw_lock_with_to);
	hw_lock_lock(&lt_hw_lock);
	OSIncrementAtomic((volatile SInt32*)&lt_thread_lock_grabbed);
	lt_wait_for_lock_test_threads();
	T_ASSERT_NULL(lt_thread_lock_success, "after taking a spin lock, lock attempt with timeout should fail");
	hw_lock_unlock(&lt_hw_lock);

	success = lck_spin_try_lock(&lt_lck_spin_t);
	T_ASSERT_NOTNULL(success, "spin trylock of previously unheld lock should succeed");
	success = lck_spin_try_lock(&lt_lck_spin_t);
	T_ASSERT_NULL(success, "spin trylock attempt of previously held lock (with trylock) should fail");
	lck_spin_unlock(&lt_lck_spin_t);

	lt_reset();
	lt_thread_lock_grabbed = false;
	lt_thread_lock_success = true;
	lt_target_done_threads = 1;
	lt_start_trylock_thread(lt_trylock_spin_try_lock);
	lck_spin_lock(&lt_lck_spin_t);
	OSIncrementAtomic((volatile SInt32*)&lt_thread_lock_grabbed);
	lt_wait_for_lock_test_threads();
	T_ASSERT_NULL(lt_thread_lock_success, "spin trylock attempt of previously held lock should fail");
	lck_spin_unlock(&lt_lck_spin_t);

	return KERN_SUCCESS;
}

static void
lt_thread(void *arg, wait_result_t wres __unused) 
{
	void (*func)(void) = (void(*)(void)) arg;
	uint32_t i;

	for (i = 0; i < LOCK_TEST_ITERATIONS; i++) {
		func();
	}

	OSIncrementAtomic((volatile SInt32*) &lt_done_threads);
}

static void
lt_bound_thread(void *arg, wait_result_t wres __unused) 
{
	void (*func)(void) = (void(*)(void)) arg;

	int cpuid = OSIncrementAtomic((volatile SInt32 *)&lt_cpu_bind_id);

	processor_t processor = processor_list;
	while ((processor != NULL) && (processor->cpu_id != cpuid)) {
		processor = processor->processor_list;
	}

	if (processor != NULL) {
		thread_bind(processor);
	}

	thread_block(THREAD_CONTINUE_NULL);

	func();

	OSIncrementAtomic((volatile SInt32*) &lt_done_threads);
}

static void
lt_start_lock_thread(thread_continue_t func)
{
	thread_t thread;
	kern_return_t kr;

	kr = kernel_thread_start(lt_thread, func, &thread);
	assert(kr == KERN_SUCCESS);

	thread_deallocate(thread);
}


static void
lt_start_lock_thread_bound(thread_continue_t func)
{
	thread_t thread;
	kern_return_t kr;

	kr = kernel_thread_start(lt_bound_thread, func, &thread);
	assert(kr == KERN_SUCCESS);

	thread_deallocate(thread);
}

static kern_return_t
lt_test_locks()
{
	kern_return_t kr = KERN_SUCCESS;
	lck_grp_attr_t *lga = lck_grp_attr_alloc_init();
	lck_grp_t *lg = lck_grp_alloc_init("lock test", lga);

	lck_mtx_init(&lt_mtx, lg, LCK_ATTR_NULL);
	lck_rw_init(&lt_rwlock, lg, LCK_ATTR_NULL);
	lck_spin_init(&lt_lck_spin_t, lg, LCK_ATTR_NULL);
	hw_lock_init(&lt_hw_lock);

	T_LOG("Testing locks.");

	/* Try locks (custom) */
	lt_reset();

	T_LOG("Running try lock test.");
	kr = lt_test_trylocks();
	T_EXPECT_NULL(kr, "try lock test failed.");

	/* Uncontended mutex */
	T_LOG("Running uncontended mutex test.");
	lt_reset();
	lt_target_done_threads = 1;
	lt_start_lock_thread(lt_grab_mutex);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Contended mutex:try locks*/
	T_LOG("Running contended mutex test.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_mutex);
	lt_start_lock_thread(lt_grab_mutex);
	lt_start_lock_thread(lt_grab_mutex);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Contended mutex: try locks*/
	T_LOG("Running contended mutex trylock test.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_mutex_with_try);
	lt_start_lock_thread(lt_grab_mutex_with_try);
	lt_start_lock_thread(lt_grab_mutex_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Uncontended exclusive rwlock */
	T_LOG("Running uncontended exclusive rwlock test.");
	lt_reset();
	lt_target_done_threads = 1;
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Uncontended shared rwlock */

	/* Disabled until lt_grab_rw_shared() is fixed (rdar://30685840)
	T_LOG("Running uncontended shared rwlock test.");
	lt_reset();
	lt_target_done_threads = 1;
	lt_start_lock_thread(lt_grab_rw_shared);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);
	*/

	/* Contended exclusive rwlock */
	T_LOG("Running contended exclusive rwlock test.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* One shared, two exclusive */
	/* Disabled until lt_grab_rw_shared() is fixed (rdar://30685840)
	T_LOG("Running test with one shared and two exclusive rw lock threads.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_rw_shared);
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_start_lock_thread(lt_grab_rw_exclusive);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);
	*/

	/* Four shared */
	/* Disabled until lt_grab_rw_shared() is fixed (rdar://30685840)
	T_LOG("Running test with four shared holders.");
	lt_reset();
	lt_target_done_threads = 4;
	lt_start_lock_thread(lt_grab_rw_shared);
	lt_start_lock_thread(lt_grab_rw_shared);
	lt_start_lock_thread(lt_grab_rw_shared);
	lt_start_lock_thread(lt_grab_rw_shared);
	lt_wait_for_lock_test_threads();
	T_EXPECT_LE_UINT(lt_max_holders, 4, NULL);
	*/

	/* Three doing upgrades and downgrades */
	T_LOG("Running test with threads upgrading and downgrading.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_upgrade_downgrade_rw);
	lt_start_lock_thread(lt_upgrade_downgrade_rw);
	lt_start_lock_thread(lt_upgrade_downgrade_rw);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_LE_UINT(lt_max_holders, 3, NULL);
	T_EXPECT_EQ_UINT(lt_max_upgrade_holders, 1, NULL);

	/* Uncontended - exclusive trylocks */
	T_LOG("Running test with single thread doing exclusive rwlock trylocks.");
	lt_reset();
	lt_target_done_threads = 1;
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Uncontended - shared trylocks */
	/* Disabled until lt_grab_rw_shared_with_try() is fixed (rdar://30685840)
	T_LOG("Running test with single thread doing shared rwlock trylocks.");
	lt_reset();
	lt_target_done_threads = 1;
	lt_start_lock_thread(lt_grab_rw_shared_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);
	*/

	/* Three doing exclusive trylocks */
	T_LOG("Running test with threads doing exclusive rwlock trylocks.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_EQ_UINT(lt_max_holders, 1, NULL);

	/* Three doing shared trylocks */
	/* Disabled until lt_grab_rw_shared_with_try() is fixed (rdar://30685840)
	T_LOG("Running test with threads doing shared rwlock trylocks.");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_rw_shared_with_try);
	lt_start_lock_thread(lt_grab_rw_shared_with_try);
	lt_start_lock_thread(lt_grab_rw_shared_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_LE_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_LE_UINT(lt_max_holders, 3, NULL);
	*/

	/* Three doing various trylocks */
	/* Disabled until lt_grab_rw_shared_with_try() is fixed (rdar://30685840)
	T_LOG("Running test with threads doing mixed rwlock trylocks.");
	lt_reset();
	lt_target_done_threads = 4;
	lt_start_lock_thread(lt_grab_rw_shared_with_try);
	lt_start_lock_thread(lt_grab_rw_shared_with_try);
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_start_lock_thread(lt_grab_rw_exclusive_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_LE_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);
	T_EXPECT_LE_UINT(lt_max_holders, 2, NULL);
	*/

	/* HW locks */
	T_LOG("Running test with hw_lock_lock()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_hw_lock);
	lt_start_lock_thread(lt_grab_hw_lock);
	lt_start_lock_thread(lt_grab_hw_lock);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

	/* HW locks stress test */
	T_LOG("Running HW locks stress test with hw_lock_lock()");
	extern unsigned int real_ncpus;
	lt_reset();
	lt_target_done_threads = real_ncpus;
	for (processor_t processor = processor_list; processor != NULL; processor = processor->processor_list) {
		lt_start_lock_thread_bound(lt_stress_hw_lock);
	}
	lt_wait_for_lock_test_threads();
	bool starvation = false;
	uint total_local_count = 0;
	for (processor_t processor = processor_list; processor != NULL; processor = processor->processor_list) {
		starvation = starvation || (lt_stress_local_counters[processor->cpu_id] < 10);
		total_local_count += lt_stress_local_counters[processor->cpu_id];
	}
	if (total_local_count != lt_counter) {
		T_FAIL("Lock failure\n");
	} else if (starvation) {
		T_FAIL("Lock starvation found\n");
	} else {
		T_PASS("HW locks stress test with hw_lock_lock()");
	}


	/* HW locks: trylocks */
	T_LOG("Running test with hw_lock_try()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_hw_lock_with_try);
	lt_start_lock_thread(lt_grab_hw_lock_with_try);
	lt_start_lock_thread(lt_grab_hw_lock_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

	/* HW locks: with timeout */
	T_LOG("Running test with hw_lock_to()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_hw_lock_with_to);
	lt_start_lock_thread(lt_grab_hw_lock_with_to);
	lt_start_lock_thread(lt_grab_hw_lock_with_to);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

	/* Spin locks */
	T_LOG("Running test with lck_spin_lock()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_spin_lock);
	lt_start_lock_thread(lt_grab_spin_lock);
	lt_start_lock_thread(lt_grab_spin_lock);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

	/* Spin locks: trylocks */
	T_LOG("Running test with lck_spin_try_lock()");
	lt_reset();
	lt_target_done_threads = 3;
	lt_start_lock_thread(lt_grab_spin_lock_with_try);
	lt_start_lock_thread(lt_grab_spin_lock_with_try);
	lt_start_lock_thread(lt_grab_spin_lock_with_try);
	lt_wait_for_lock_test_threads();
	T_EXPECT_EQ_UINT(lt_counter, LOCK_TEST_ITERATIONS * lt_target_done_threads, NULL);

	return KERN_SUCCESS;
}

#define MT_MAX_ARGS		8
#define MT_INITIAL_VALUE	0xfeedbeef
#define MT_W_VAL		(0x00000000feedbeefULL)	/* Drop in zeros */
#define MT_S_VAL		(0xfffffffffeedbeefULL) /* High bit is 1, so sign-extends as negative */
#define MT_L_VAL		(((uint64_t)MT_INITIAL_VALUE) | (((uint64_t)MT_INITIAL_VALUE) << 32)) /* Two back-to-back */

typedef void (*sy_munge_t)(void*);

#define MT_FUNC(x) #x, x
struct munger_test {
	const char	*mt_name;
	sy_munge_t 	mt_func;
	uint32_t	mt_in_words;
	uint32_t	mt_nout;
	uint64_t 	mt_expected[MT_MAX_ARGS];
} munger_tests[] = {
	{MT_FUNC(munge_w), 		1, 1, 	{MT_W_VAL}},
	{MT_FUNC(munge_ww), 		2, 2, 	{MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_www), 		3, 3, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwww), 		4, 4, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwww), 		5, 5, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwww), 	6, 6, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwww), 	7, 7, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwwww),	8, 8, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wl), 		3, 2, 	{MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwl),		4, 3, 	{MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwlll), 		8, 5, 	{MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wlw), 		4, 3, 	{MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wlwwwll), 	10, 7, 	{MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wlwwwllw),	11, 8, 	{MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wlwwlwlw),	11, 8,	{MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wll), 		5, 3, 	{MT_W_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wlll), 		7, 4, 	{MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wllwwll),	11, 7,	{MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwlw), 		6, 5, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwlww), 	7, 6, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwl), 		5, 4, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwlw), 	7, 6, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwl), 		6, 5, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwwl), 	7, 6, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwwlww),	9, 8, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwllw),	10, 8, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwlll),	11, 8, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwwwl), 	8, 7, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwwwwwlw),	9, 8, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wwwwwwll),	10, 8, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wsw), 		3, 3, 	{MT_W_VAL, MT_S_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wws), 		3, 3, 	{MT_W_VAL, MT_W_VAL, MT_S_VAL}},
	{MT_FUNC(munge_wwwsw), 		5, 5, 	{MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_S_VAL, MT_W_VAL}},
	{MT_FUNC(munge_llllll), 	12, 6, 	{MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL, MT_L_VAL}},
	{MT_FUNC(munge_l), 		2, 1, 	{MT_L_VAL}},
	{MT_FUNC(munge_lw), 		3, 2, 	{MT_L_VAL, MT_W_VAL}},
	{MT_FUNC(munge_lwww), 		5, 4, 	{MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_lwwwwwww),	9, 8, 	{MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL}},
	{MT_FUNC(munge_wlwwwl), 	8, 6, 	{MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}},
	{MT_FUNC(munge_wwlwwwl), 	9, 7, 	{MT_W_VAL, MT_W_VAL, MT_L_VAL, MT_W_VAL, MT_W_VAL, MT_W_VAL, MT_L_VAL}}
};

#define MT_TEST_COUNT (sizeof(munger_tests) / sizeof(struct munger_test))

static void
mt_reset(uint32_t in_words, size_t total_size, uint32_t *data) 
{
	uint32_t i;

	for (i = 0; i < in_words; i++) {
		data[i] = MT_INITIAL_VALUE;
	}

	if (in_words * sizeof(uint32_t) < total_size) {
		bzero(&data[in_words], total_size - in_words * sizeof(uint32_t));
	}
}

static void
mt_test_mungers()
{
	uint64_t data[MT_MAX_ARGS];
	uint32_t i, j;

	for (i = 0; i < MT_TEST_COUNT; i++) {
		struct munger_test *test = &munger_tests[i];
		int pass = 1;

		T_LOG("Testing %s", test->mt_name);

		mt_reset(test->mt_in_words, sizeof(data), (uint32_t*)data);
		test->mt_func(data);

		for (j = 0; j < test->mt_nout; j++) {
			if (data[j] != test->mt_expected[j]) {
				T_FAIL("Index %d: expected %llx, got %llx.", j, test->mt_expected[j], data[j]);
				pass = 0;
			}
		}
		if (pass) {
			T_PASS(test->mt_name);
		}
	}
}

/* Exception Callback Test */
static ex_cb_action_t excb_test_action(
	ex_cb_class_t		cb_class,
	void				*refcon,
	const ex_cb_state_t	*state
	)
{
	ex_cb_state_t *context = (ex_cb_state_t *)refcon;

	if ((NULL == refcon) || (NULL == state))
	{
		return EXCB_ACTION_TEST_FAIL;
	}

	context->far = state->far;

	switch (cb_class)
	{
		case EXCB_CLASS_TEST1:
			return EXCB_ACTION_RERUN;
		case EXCB_CLASS_TEST2:
			return EXCB_ACTION_NONE;
		default:
			return EXCB_ACTION_TEST_FAIL;
	}
}


kern_return_t
ex_cb_test()
{
	const vm_offset_t far1 = 0xdead0001;
	const vm_offset_t far2 = 0xdead0002;
	kern_return_t kr;
	ex_cb_state_t test_context_1 = {0xdeadbeef};
	ex_cb_state_t test_context_2 = {0xdeadbeef};
	ex_cb_action_t action;

	T_LOG("Testing Exception Callback.");
	
	T_LOG("Running registration test.");

	kr = ex_cb_register(EXCB_CLASS_TEST1, &excb_test_action, &test_context_1);
	T_ASSERT(KERN_SUCCESS == kr, "First registration of TEST1 exception callback");
	kr = ex_cb_register(EXCB_CLASS_TEST2, &excb_test_action, &test_context_2);
	T_ASSERT(KERN_SUCCESS == kr, "First registration of TEST2 exception callback");

	kr = ex_cb_register(EXCB_CLASS_TEST2, &excb_test_action, &test_context_2);
	T_ASSERT(KERN_SUCCESS != kr, "Second registration of TEST2 exception callback");
	kr = ex_cb_register(EXCB_CLASS_TEST1, &excb_test_action, &test_context_1);
	T_ASSERT(KERN_SUCCESS != kr, "Second registration of TEST1 exception callback");

	T_LOG("Running invocation test.");

	action = ex_cb_invoke(EXCB_CLASS_TEST1, far1);
	T_ASSERT(EXCB_ACTION_RERUN == action, NULL);
	T_ASSERT(far1 == test_context_1.far, NULL);

	action = ex_cb_invoke(EXCB_CLASS_TEST2, far2);
	T_ASSERT(EXCB_ACTION_NONE == action, NULL);
	T_ASSERT(far2 == test_context_2.far, NULL);

	action = ex_cb_invoke(EXCB_CLASS_TEST3, 0);
	T_ASSERT(EXCB_ACTION_NONE == action, NULL);

	return KERN_SUCCESS;
}

#if __ARM_PAN_AVAILABLE__
kern_return_t
arm64_pan_test()
{
	unsigned long last_pan_config;
	vm_offset_t priv_addr = _COMM_PAGE_SIGNATURE;

	T_LOG("Testing PAN.");

	last_pan_config = __builtin_arm_rsr("pan");
	if (!last_pan_config) {
		T_ASSERT(!arm_pan_enabled, "PAN is not enabled even though it is configured to be"); 
		__builtin_arm_wsr("pan", 1);
	}
		
	T_ASSERT(__builtin_arm_rsr("pan") != 0, NULL);

	// convert priv_addr to one that is accessible from user mode
	pan_test_addr = priv_addr + _COMM_PAGE64_BASE_ADDRESS - 
		_COMM_PAGE_START_ADDRESS;

	// Below should trigger a PAN exception as pan_test_addr is accessible 
	// in user mode
	// The exception handler, upon recognizing the fault address is pan_test_addr,
	// will disable PAN and rerun this instruction successfully
	T_ASSERT(*(char *)pan_test_addr == *(char *)priv_addr, NULL);
	pan_test_addr = 0;

	T_ASSERT(__builtin_arm_rsr("pan") == 0, NULL);

	// restore previous PAN config value
	if (last_pan_config)
		__builtin_arm_wsr("pan", 1);

	return KERN_SUCCESS;
}
#endif


kern_return_t
arm64_lock_test()
{
	return lt_test_locks();
}

kern_return_t
arm64_munger_test()
{
	mt_test_mungers();
	return 0;
}

