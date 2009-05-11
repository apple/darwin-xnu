/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
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


/*
 * extern void	commpage_sched_gen_inc(void);
 */
	.text
	.align  2, 0x90
	.globl	_commpage_sched_gen_inc

_commpage_sched_gen_inc:
	push	%ebp
	mov	%esp,%ebp

	/* Increment 32-bit commpage field if present */
	mov	_commPagePtr32,%edx
	testl	%edx,%edx
	je	1f
	sub	$(_COMM_PAGE32_BASE_ADDRESS),%edx
	lock
	incl	_COMM_PAGE_SCHED_GEN(%edx)

	/* Increment 64-bit commpage field if present */
	mov	_commPagePtr64,%edx
	testl	%edx,%edx
	je	1f
	sub	$(_COMM_PAGE32_START_ADDRESS),%edx
	lock
	incl	_COMM_PAGE_SCHED_GEN(%edx)
1:
	pop	%ebp
	ret

#define	CPN(routine)	_commpage_ ## routine

/* pointers to the 32-bit commpage routine descriptors */
/* WARNING: these must be sorted by commpage address! */
	.const_data
	.align	2
	.globl	_commpage_32_routines
_commpage_32_routines:
	.long	CPN(compare_and_swap32_mp)
	.long	CPN(compare_and_swap32_up)
	.long	CPN(compare_and_swap64_mp)
	.long	CPN(compare_and_swap64_up)
	.long	CPN(AtomicEnqueue)
	.long	CPN(AtomicDequeue)
	.long	CPN(memory_barrier)
	.long	CPN(memory_barrier_sse2)
	.long	CPN(atomic_add32_mp)
	.long	CPN(atomic_add32_up)
	.long	CPN(mach_absolute_time)
	.long	CPN(spin_lock_try_mp)
	.long	CPN(spin_lock_try_up)
	.long	CPN(spin_lock_mp)
	.long	CPN(spin_lock_up)
	.long	CPN(spin_unlock)
	.long	CPN(pthread_getspecific)
	.long	CPN(gettimeofday)
	.long	CPN(sys_flush_dcache)
	.long	CPN(sys_icache_invalidate)
	.long	CPN(pthread_self)
//	.long	CPN(relinquish)
	.long	CPN(bit_test_and_set_mp)
	.long	CPN(bit_test_and_set_up)
	.long	CPN(bit_test_and_clear_mp)
	.long	CPN(bit_test_and_clear_up)
	.long	CPN(bzero_scalar)
	.long	CPN(bzero_sse2)
	.long	CPN(bzero_sse42)
	.long	CPN(bcopy_scalar)
	.long	CPN(bcopy_sse2)
	.long	CPN(bcopy_sse3x)
	.long	CPN(bcopy_sse42)
	.long	CPN(memset_pattern_sse2)
	.long	CPN(longcopy_sse3x)
	.long	CPN(nanotime)
	.long	CPN(nanotime_slow)
	.long	0


/* pointers to the 64-bit commpage routine descriptors */
/* WARNING: these must be sorted by commpage address! */
	.const_data
	.align	2
	.globl	_commpage_64_routines
_commpage_64_routines:
	.long	CPN(compare_and_swap32_mp_64)
	.long	CPN(compare_and_swap32_up_64)
	.long	CPN(compare_and_swap64_mp_64)
	.long	CPN(compare_and_swap64_up_64)
	.long	CPN(AtomicEnqueue_64)
	.long	CPN(AtomicDequeue_64)
	.long	CPN(memory_barrier_sse2)	/* same routine as 32-bit version */
	.long	CPN(atomic_add32_mp_64)
	.long	CPN(atomic_add32_up_64)
	.long	CPN(atomic_add64_mp_64)
	.long	CPN(atomic_add64_up_64)
	.long	CPN(mach_absolute_time)
	.long	CPN(spin_lock_try_mp_64)
	.long	CPN(spin_lock_try_up_64)
	.long	CPN(spin_lock_mp_64)
	.long	CPN(spin_lock_up_64)
	.long	CPN(spin_unlock_64)
	.long	CPN(pthread_getspecific_64)
	.long	CPN(gettimeofday_64)
	.long	CPN(sys_flush_dcache_64)
	.long	CPN(sys_icache_invalidate)	/* same routine as 32-bit version, just a "ret" */
	.long	CPN(pthread_self_64)
	.long	CPN(bit_test_and_set_mp_64)
	.long	CPN(bit_test_and_set_up_64)
	.long	CPN(bit_test_and_clear_mp_64)
	.long	CPN(bit_test_and_clear_up_64)
	.long	CPN(bzero_sse2_64)
	.long	CPN(bzero_sse42_64)
	.long	CPN(bcopy_sse3x_64)
	.long	CPN(bcopy_sse42_64)
	.long	CPN(memset_pattern_sse2_64)
	.long	CPN(longcopy_sse3x_64)
	.long	CPN(nanotime_64)
	.long	0

