/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#if !(DEVELOPMENT || DEBUG)
#error "Testing is not enabled on RELEASE configurations"
#endif

#include <tests/xnupost.h>
#include <kern/kalloc.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <sys/random.h>

#define VFP_STATE_TEST_N_THREADS                4
#define VFP_STATE_TEST_N_REGS                   8
#define VFP_STATE_TEST_N_ITER                   100
#define VFP_STATE_TEST_DELAY_USEC               10000
#if __arm__
#define VFP_STATE_TEST_NZCV_SHIFT               28
#define VFP_STATE_TEST_NZCV_MAX                 16
#else
#define VFP_STATE_TEST_RMODE_STRIDE_SHIFT       20
#define VFP_STATE_TEST_RMODE_STRIDE_MAX         16
#endif

#if __ARM_VFP__
extern kern_return_t vfp_state_test(void);

const uint64_t vfp_state_test_regs[VFP_STATE_TEST_N_REGS] = {
	0x6a4cac4427ab5658, 0x51200e9ebbe0c9d1,
	0xa94d20c2bbe367bc, 0xfee45035460927db,
	0x64f3f1f7e93d019f, 0x02a625f02b890a40,
	0xf5e42399d8480de8, 0xc38cdde520908d6b,
};

struct vfp_state_test_args {
	uint64_t vfp_reg_rand;
#if __arm__
	uint32_t fp_control_mask;
#else
	uint64_t fp_control_mask;
#endif
	int result;
	int *start_barrier;
	int *end_barrier;
};

static void
wait_threads(
	int* var,
	int num)
{
	if (var != NULL) {
		while (os_atomic_load(var, acquire) != num) {
			assert_wait((event_t) var, THREAD_UNINT);
			if (os_atomic_load(var, acquire) != num) {
				(void) thread_block(THREAD_CONTINUE_NULL);
			} else {
				clear_wait(current_thread(), THREAD_AWAKENED);
			}
		}
	}
}

static void
wake_threads(
	int* var)
{
	if (var) {
		os_atomic_inc(var, relaxed);
		thread_wakeup((event_t) var);
	}
}

static void
vfp_state_test_thread_routine(void *args, __unused wait_result_t wr)
{
	struct vfp_state_test_args *vfp_state_test_args = (struct vfp_state_test_args *)args;
	uint64_t *vfp_regs, *vfp_regs_expected;
	int retval;
#if __arm__
	uint32_t fp_control, fp_control_expected;
#else
	uint64_t fp_control, fp_control_expected;
#endif

	vfp_state_test_args->result = -1;

	/* Allocate memory to store expected and actual VFP register values */
	vfp_regs = kalloc(sizeof(vfp_state_test_regs));
	if (vfp_regs == NULL) {
		goto vfp_state_thread_kalloc1_failure;
	}

	vfp_regs_expected = kalloc(sizeof(vfp_state_test_regs));
	if (vfp_regs_expected == NULL) {
		goto vfp_state_thread_kalloc2_failure;
	}

	/* Preload VFP registers with unique, per-thread patterns */
	bcopy(vfp_state_test_regs, vfp_regs_expected, sizeof(vfp_state_test_regs));
	for (int i = 0; i < VFP_STATE_TEST_N_REGS; i++) {
		vfp_regs_expected[i] ^= vfp_state_test_args->vfp_reg_rand;
	}

#if __arm__
	asm volatile ("vldr d8, [%0, #0] \t\n vldr d9, [%0, #8] \t\n\
				   vldr d10, [%0, #16] \t\n vldr d11, [%0, #24] \t\n\
				   vldr d12, [%0, #32] \t\n vldr d13, [%0, #40] \t\n\
				   vldr d14, [%0, #48] \t\n vldr d15, [%0, #56]" \
                                   : : "r"(vfp_regs_expected) : \
                                   "memory", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15");

	/*
	 * Set FPSCR to a known value, so we can validate the save/restore path.
	 * Only touch NZCV flags, since 1) writing them does not have visible side-effects
	 * and 2) they're only set by the CPU as a result of executing an FP comparison,
	 * which do not exist in this function.
	 */
	asm volatile ("fmrx	%0, fpscr" : "=r"(fp_control_expected));
	fp_control_expected |= vfp_state_test_args->fp_control_mask;
	asm volatile ("fmxr	fpscr, %0" : : "r"(fp_control_expected));
#else
	asm volatile ("ldr d8, [%0, #0] \t\n ldr d9, [%0, #8] \t\n\
				   ldr d10, [%0, #16] \t\n ldr d11, [%0, #24] \t\n\
				   ldr d12, [%0, #32] \t\n ldr d13, [%0, #40] \t\n\
				   ldr d14, [%0, #48] \t\n ldr d15, [%0, #56]" \
                                   : : "r"(vfp_regs_expected) : \
                                   "memory", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15");

	asm volatile ("mrs	%0, fpcr" : "=r"(fp_control_expected));
	fp_control_expected |= vfp_state_test_args->fp_control_mask;
	asm volatile ("msr	fpcr, %0" : : "r"(fp_control_expected));
#endif

	/* Make sure all threads start at roughly the same time */
	wake_threads(vfp_state_test_args->start_barrier);
	wait_threads(vfp_state_test_args->start_barrier, VFP_STATE_TEST_N_THREADS);

	/* Check VFP registers against expected values, and go to sleep */
	for (int i = 0; i < VFP_STATE_TEST_N_ITER; i++) {
		bzero(vfp_regs, sizeof(vfp_state_test_regs));

#if __arm__
		asm volatile ("vstr d8, [%0, #0] \t\n vstr d9, [%0, #8] \t\n\
					   vstr d10, [%0, #16] \t\n vstr d11, [%0, #24] \t\n\
					   vstr d12, [%0, #32] \t\n vstr d13, [%0, #40] \t\n\
					   vstr d14, [%0, #48] \t\n vstr d15, [%0, #56]" \
                                           : : "r"(vfp_regs) : "memory");
		asm volatile ("fmrx	%0, fpscr" : "=r"(fp_control));
#else
		asm volatile ("str d8, [%0, #0] \t\n str d9, [%0, #8] \t\n\
					   str d10, [%0, #16] \t\n str d11, [%0, #24] \t\n\
					   str d12, [%0, #32] \t\n str d13, [%0, #40] \t\n\
					   str d14, [%0, #48] \t\n str d15, [%0, #56]" \
                                           : : "r"(vfp_regs) : "memory");
		asm volatile ("mrs	%0, fpcr" : "=r"(fp_control));
#endif

		retval = bcmp(vfp_regs, vfp_regs_expected, sizeof(vfp_state_test_regs));
		if ((retval != 0) || (fp_control != fp_control_expected)) {
			goto vfp_state_thread_cmp_failure;
		}

		delay(VFP_STATE_TEST_DELAY_USEC);
	}

	vfp_state_test_args->result = 0;

vfp_state_thread_cmp_failure:
	kfree(vfp_regs_expected, sizeof(vfp_state_test_regs));
vfp_state_thread_kalloc2_failure:
	kfree(vfp_regs, sizeof(vfp_state_test_regs));
vfp_state_thread_kalloc1_failure:

	/* Signal that the thread has finished, and terminate */
	wake_threads(vfp_state_test_args->end_barrier);
	thread_terminate_self();
}

/*
 * This test spawns N threads that preload unique values into
 * callee-saved VFP registers and then repeatedly check them
 * for correctness after waking up from delay()
 */
kern_return_t
vfp_state_test(void)
{
	thread_t vfp_state_thread[VFP_STATE_TEST_N_THREADS];
	struct vfp_state_test_args vfp_state_test_args[VFP_STATE_TEST_N_THREADS];
	kern_return_t retval;
	int start_barrier = 0, end_barrier = 0;

	/* Spawn threads */
	for (int i = 0; i < VFP_STATE_TEST_N_THREADS; i++) {
		vfp_state_test_args[i].start_barrier = &start_barrier;
		vfp_state_test_args[i].end_barrier = &end_barrier;
#if __arm__
		vfp_state_test_args[i].fp_control_mask = (i % VFP_STATE_TEST_NZCV_MAX) << VFP_STATE_TEST_NZCV_SHIFT;
#else
		vfp_state_test_args[i].fp_control_mask = (i % VFP_STATE_TEST_RMODE_STRIDE_MAX) << VFP_STATE_TEST_RMODE_STRIDE_SHIFT;
#endif
		read_random(&vfp_state_test_args[i].vfp_reg_rand, sizeof(uint64_t));

		retval = kernel_thread_start((thread_continue_t)vfp_state_test_thread_routine,
		    (void *)&vfp_state_test_args[i],
		    &vfp_state_thread[i]);

		T_EXPECT((retval == KERN_SUCCESS), "thread %d started", i);
	}

	/* Wait for all threads to finish */
	wait_threads(&end_barrier, VFP_STATE_TEST_N_THREADS);

	/* Check if all threads completed successfully */
	for (int i = 0; i < VFP_STATE_TEST_N_THREADS; i++) {
		T_EXPECT((vfp_state_test_args[i].result == 0), "thread %d finished", i);
	}

	return KERN_SUCCESS;
}
#endif /* __ARM_VFP__ */
