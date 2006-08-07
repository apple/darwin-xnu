/*
 * Copyright (c) 2003-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <machine/cpu_capabilities.h>

        .text
        .align  2, 0x90
	.globl	__commpage_set_timestamp
/* extern void	_commpage_set_timestamp(uint64_t abstime, uint64_t secs); */
__commpage_set_timestamp:
	push	%ebp
	mov	%esp,%ebp

	mov	_commPagePtr32,%ecx
	sub	$ _COMM_PAGE32_BASE_ADDRESS,%ecx
	mov	_commPagePtr64,%edx			/* point to 64-bit commpage too */
	mov	%edx,%eax
	sub	$ _COMM_PAGE32_START_ADDRESS,%edx	/* because kernel is built 32-bit */
	test	%eax,%eax
	cmovz	%ecx,%edx				/* if no 64-bit commpage, point to 32 with both */

	movl	$0,_COMM_PAGE_TIMEENABLE(%ecx)
	movl	$0,_COMM_PAGE_TIMEENABLE(%edx)

	mov	8(%ebp),%eax
	or	12(%ebp),%eax
	je	1f

	mov	8(%ebp),%eax
	mov	%eax,_COMM_PAGE_TIMEBASE(%ecx)
	mov	%eax,_COMM_PAGE_TIMEBASE(%edx)
	mov	12(%ebp),%eax
	mov	%eax,_COMM_PAGE_TIMEBASE+4(%ecx)
	mov	%eax,_COMM_PAGE_TIMEBASE+4(%edx)

	mov	16(%ebp),%eax
	mov	%eax,_COMM_PAGE_TIMESTAMP(%ecx)
	mov	%eax,_COMM_PAGE_TIMESTAMP(%edx)
	mov	20(%ebp),%eax
	mov	%eax,_COMM_PAGE_TIMESTAMP+4(%ecx)
	mov	%eax,_COMM_PAGE_TIMESTAMP+4(%edx)

	movl	$1,_COMM_PAGE_TIMEENABLE(%ecx)
	movl	$1,_COMM_PAGE_TIMEENABLE(%edx)
1:
	pop	%ebp
	ret

        .text
        .align  2, 0x90
	.globl	_commpage_set_nanotime
/* extern void	commpage_set_nanotime(uint64_t tsc_base, uint64_t ns_base, uint32_t scale, uint32_t shift); */
_commpage_set_nanotime:
	push	%ebp
	mov	%esp,%ebp

	mov	_commPagePtr32,%ecx
	testl	%ecx,%ecx
	je	1f

	sub	$(_COMM_PAGE_BASE_ADDRESS),%ecx
	mov	_commPagePtr64,%edx			/* point to 64-bit commpage too */
	mov	%edx,%eax
	sub	$ _COMM_PAGE32_START_ADDRESS,%edx	/* because kernel is built 32-bit */
	test	%eax,%eax
	cmovz	%ecx,%edx				/* if no 64-bit commpage, point to 32 with both */

	mov	8(%ebp),%eax
	mov	%eax,_COMM_PAGE_NT_TSC_BASE(%ecx)
	mov	%eax,_COMM_PAGE_NT_TSC_BASE(%edx)
	mov	12(%ebp),%eax
	mov	%eax,_COMM_PAGE_NT_TSC_BASE+4(%ecx)
	mov	%eax,_COMM_PAGE_NT_TSC_BASE+4(%edx)

	mov	24(%ebp),%eax
	mov	%eax,_COMM_PAGE_NT_SCALE(%ecx)
	mov	%eax,_COMM_PAGE_NT_SCALE(%edx)

	mov	28(%ebp),%eax
	mov	%eax,_COMM_PAGE_NT_SHIFT(%ecx)
	mov	%eax,_COMM_PAGE_NT_SHIFT(%edx)

	mov	16(%ebp),%eax
	mov	%eax,_COMM_PAGE_NT_NS_BASE(%ecx)
	mov	%eax,_COMM_PAGE_NT_NS_BASE(%edx)
	mov	20(%ebp),%eax
	mov	%eax,_COMM_PAGE_NT_NS_BASE+4(%ecx)
	mov	%eax,_COMM_PAGE_NT_NS_BASE+4(%edx)
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
	.long	CPN(bzero_sse3)
	.long	CPN(bcopy_scalar)
	.long	CPN(bcopy_sse3)
	.long	CPN(bcopy_sse4)
	.long	CPN(old_nanotime)
	.long	CPN(memset_pattern_sse3)
	.long	CPN(longcopy_sse4)
	.long	CPN(nanotime)
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
	.long	CPN(bzero_sse3_64)
	.long	CPN(bcopy_sse4_64)
	.long	CPN(old_nanotime_64)
	.long	CPN(memset_pattern_sse3_64)
	.long	CPN(longcopy_sse4_64)
	.long	CPN(nanotime_64)
	.long	0

