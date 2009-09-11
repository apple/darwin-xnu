/*
 * Copyright (c) 2003-2009 Apple Inc. All rights reserved.
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

#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/asm.h>
#include <assym.s>

/*
 * extern void	commpage_sched_gen_inc(void);
 */
	.text

	.globl	_commpage_sched_gen_inc
_commpage_sched_gen_inc:
#if defined (__x86_64__)
	FRAME
	
	/* Increment 32-bit commpage field if present */
	movq	_commPagePtr32(%rip),%rdx
	testq	%rdx,%rdx
	je	1f
	subq	$(ASM_COMM_PAGE32_BASE_ADDRESS),%rdx
	lock
	incl	ASM_COMM_PAGE_SCHED_GEN(%rdx)

	/* Increment 64-bit commpage field if present */
	movq	_commPagePtr64(%rip),%rdx
	testq	%rdx,%rdx
	je	1f
	subq	$(ASM_COMM_PAGE32_START_ADDRESS),%rdx
	lock
	incl	ASM_COMM_PAGE_SCHED_GEN(%rdx)
1:
	EMARF
	ret
#elif defined (__i386__)
	FRAME
	
	/* Increment 32-bit commpage field if present */
	mov	_commPagePtr32,%edx
	testl	%edx,%edx
	je	1f
	sub	$(ASM_COMM_PAGE32_BASE_ADDRESS),%edx
	lock
	incl	ASM_COMM_PAGE_SCHED_GEN(%edx)

	/* Increment 64-bit commpage field if present */
	mov	_commPagePtr64,%edx
	testl	%edx,%edx
	je	1f
	sub	$(ASM_COMM_PAGE32_START_ADDRESS),%edx
	lock
	incl	ASM_COMM_PAGE_SCHED_GEN(%edx)
1:
	EMARF
	ret
#else
#error unsupported architecture
#endif

/* pointers to the 32-bit commpage routine descriptors */
/* WARNING: these must be sorted by commpage address! */
	.const_data
	.align	3
	.globl	_commpage_32_routines
_commpage_32_routines:
	COMMPAGE_DESCRIPTOR_REFERENCE(compare_and_swap32_mp)
	COMMPAGE_DESCRIPTOR_REFERENCE(compare_and_swap32_up)
	COMMPAGE_DESCRIPTOR_REFERENCE(compare_and_swap64_mp)
	COMMPAGE_DESCRIPTOR_REFERENCE(compare_and_swap64_up)
	COMMPAGE_DESCRIPTOR_REFERENCE(AtomicEnqueue)
	COMMPAGE_DESCRIPTOR_REFERENCE(AtomicDequeue)
	COMMPAGE_DESCRIPTOR_REFERENCE(memory_barrier)
	COMMPAGE_DESCRIPTOR_REFERENCE(memory_barrier_sse2)
	COMMPAGE_DESCRIPTOR_REFERENCE(atomic_add32_mp)
	COMMPAGE_DESCRIPTOR_REFERENCE(atomic_add32_up)
	COMMPAGE_DESCRIPTOR_REFERENCE(cpu_number)
	COMMPAGE_DESCRIPTOR_REFERENCE(mach_absolute_time)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_lock_try_mp)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_lock_try_up)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_lock_mp)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_lock_up)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_unlock)
	COMMPAGE_DESCRIPTOR_REFERENCE(pthread_getspecific)
	COMMPAGE_DESCRIPTOR_REFERENCE(gettimeofday)
	COMMPAGE_DESCRIPTOR_REFERENCE(sys_flush_dcache)
	COMMPAGE_DESCRIPTOR_REFERENCE(sys_icache_invalidate)
	COMMPAGE_DESCRIPTOR_REFERENCE(pthread_self)
	COMMPAGE_DESCRIPTOR_REFERENCE(preempt)
//	COMMPAGE_DESCRIPTOR_REFERENCE(relinquish)
	COMMPAGE_DESCRIPTOR_REFERENCE(bit_test_and_set_mp)
	COMMPAGE_DESCRIPTOR_REFERENCE(bit_test_and_set_up)
	COMMPAGE_DESCRIPTOR_REFERENCE(bit_test_and_clear_mp)
	COMMPAGE_DESCRIPTOR_REFERENCE(bit_test_and_clear_up)
	COMMPAGE_DESCRIPTOR_REFERENCE(bzero_scalar)
	COMMPAGE_DESCRIPTOR_REFERENCE(bzero_sse2)
	COMMPAGE_DESCRIPTOR_REFERENCE(bzero_sse42)
	COMMPAGE_DESCRIPTOR_REFERENCE(bcopy_scalar)
	COMMPAGE_DESCRIPTOR_REFERENCE(bcopy_sse2)
	COMMPAGE_DESCRIPTOR_REFERENCE(bcopy_sse3x)
	COMMPAGE_DESCRIPTOR_REFERENCE(bcopy_sse42)
	COMMPAGE_DESCRIPTOR_REFERENCE(memset_pattern_sse2)
	COMMPAGE_DESCRIPTOR_REFERENCE(longcopy_sse3x)
	COMMPAGE_DESCRIPTOR_REFERENCE(backoff)
	COMMPAGE_DESCRIPTOR_REFERENCE(AtomicFifoEnqueue)
	COMMPAGE_DESCRIPTOR_REFERENCE(AtomicFifoDequeue)
	COMMPAGE_DESCRIPTOR_REFERENCE(nanotime)
	COMMPAGE_DESCRIPTOR_REFERENCE(nanotime_slow)
	COMMPAGE_DESCRIPTOR_REFERENCE(pthread_mutex_lock)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_enqueue)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_dequeue)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_mutex_lock)
#if defined (__i386__)
	.long	0
#elif defined (__x86_64__)
	.quad	0
#else
#error unsupported architecture
#endif


/* pointers to the 64-bit commpage routine descriptors */
/* WARNING: these must be sorted by commpage address! */
	.const_data
	.align	3
	.globl	_commpage_64_routines
_commpage_64_routines:
	COMMPAGE_DESCRIPTOR_REFERENCE(compare_and_swap32_mp_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(compare_and_swap32_up_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(compare_and_swap64_mp_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(compare_and_swap64_up_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(AtomicEnqueue_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(AtomicDequeue_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(memory_barrier_sse2)	/* same routine as 32-bit version */
	COMMPAGE_DESCRIPTOR_REFERENCE(atomic_add32_mp_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(atomic_add32_up_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(atomic_add64_mp_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(atomic_add64_up_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(cpu_number_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(mach_absolute_time)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_lock_try_mp_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_lock_try_up_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_lock_mp_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_lock_up_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(spin_unlock_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(pthread_getspecific_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(gettimeofday_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(sys_flush_dcache_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(sys_icache_invalidate)	/* same routine as 32-bit version, just a "ret" */
	COMMPAGE_DESCRIPTOR_REFERENCE(pthread_self_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(preempt_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(bit_test_and_set_mp_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(bit_test_and_set_up_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(bit_test_and_clear_mp_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(bit_test_and_clear_up_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(bzero_sse2_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(bzero_sse42_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(bcopy_sse3x_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(bcopy_sse42_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(memset_pattern_sse2_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(longcopy_sse3x_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(backoff_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(AtomicFifoEnqueue_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(AtomicFifoDequeue_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(nanotime_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(pthread_mutex_lock_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_enqueue_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_dequeue_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_mutex_lock_64)
#if defined (__i386__)
	.long	0
#elif defined (__x86_64__)
	.quad	0
#else
#error unsupported architecture
#endif

