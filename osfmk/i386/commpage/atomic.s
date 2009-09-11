/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

/* OSAtomic.h library native implementations. */

// This is a regparm(3) subroutine used by:

// bool OSAtomicCompareAndSwap32( int32_t old, int32_t new, int32_t *value);
// int32_t OSAtomicAnd32( int32_t mask, int32_t *value);
// int32_t OSAtomicOr32( int32_t mask, int32_t *value);
// int32_t OSAtomicXor32( int32_t mask, int32_t *value);

// It assumes old -> %eax, new -> %edx, value -> %ecx
// on success: returns with ZF set
// on failure: returns with *value in %eax, ZF clear

// The first word of the routine contains the address of the first instruction,
// so callers can pass parameters in registers by using the absolute:

// 	call *_COMPARE_AND_SWAP32

//	TODO: move the .long onto a separate page to reduce icache pollution (?)

COMMPAGE_FUNCTION_START(compare_and_swap32_mp, 32, 4)
.long	_COMM_PAGE_COMPARE_AND_SWAP32+4
	lock
	cmpxchgl  %edx, (%ecx)
	ret
COMMPAGE_DESCRIPTOR(compare_and_swap32_mp,_COMM_PAGE_COMPARE_AND_SWAP32,0,kUP)

COMMPAGE_FUNCTION_START(compare_and_swap32_up, 32, 4)
.long	_COMM_PAGE_COMPARE_AND_SWAP32+4
	cmpxchgl %edx, (%ecx)
	ret
COMMPAGE_DESCRIPTOR(compare_and_swap32_up,_COMM_PAGE_COMPARE_AND_SWAP32,kUP,0)

// This is a subroutine used by:
// bool OSAtomicCompareAndSwap64( int64_t old, int64_t new, int64_t *value);

// It assumes old -> %eax/%edx, new -> %ebx/%ecx, value -> %esi
// on success: returns with ZF set
// on failure: returns with *value in %eax/%edx, ZF clear

COMMPAGE_FUNCTION_START(compare_and_swap64_mp, 32, 4)
.long	_COMM_PAGE_COMPARE_AND_SWAP64+4
	lock
	cmpxchg8b (%esi)
	ret
COMMPAGE_DESCRIPTOR(compare_and_swap64_mp,_COMM_PAGE_COMPARE_AND_SWAP64,0,kUP)

COMMPAGE_FUNCTION_START(compare_and_swap64_up, 32, 4)
.long	_COMM_PAGE_COMPARE_AND_SWAP64+4
	cmpxchg8b (%esi)
	ret
COMMPAGE_DESCRIPTOR(compare_and_swap64_up,_COMM_PAGE_COMPARE_AND_SWAP64,kUP,0)

// This is a subroutine used by:
// bool OSAtomicTestAndSet( uint32_t n, void *value );
// It assumes n -> %eax, value -> %edx

// Returns: old value of bit in CF

COMMPAGE_FUNCTION_START(bit_test_and_set_mp, 32, 4)
.long	_COMM_PAGE_BTS+4
	lock
	btsl %eax, (%edx)
	ret
COMMPAGE_DESCRIPTOR(bit_test_and_set_mp,_COMM_PAGE_BTS,0,kUP)

COMMPAGE_FUNCTION_START(bit_test_and_set_up, 32, 4)
.long	_COMM_PAGE_BTS+4
	btsl %eax, (%edx)
	ret
COMMPAGE_DESCRIPTOR(bit_test_and_set_up,_COMM_PAGE_BTS,kUP,0)

// This is a subroutine used by:
// bool OSAtomicTestAndClear( uint32_t n, void *value );
// It assumes n -> %eax, value -> %edx

// Returns: old value of bit in CF

COMMPAGE_FUNCTION_START(bit_test_and_clear_mp, 32, 4)
.long	_COMM_PAGE_BTC+4
	lock
	btrl %eax, (%edx)
	ret
COMMPAGE_DESCRIPTOR(bit_test_and_clear_mp,_COMM_PAGE_BTC,0,kUP)

COMMPAGE_FUNCTION_START(bit_test_and_clear_up, 32, 4)
.long	_COMM_PAGE_BTC+4
	btrl %eax, (%edx)
	ret
COMMPAGE_DESCRIPTOR(bit_test_and_clear_up,_COMM_PAGE_BTC,kUP,0)

// This is a subroutine used by:
// int32_t OSAtomicAdd32( int32_t amt, int32_t *value );
// It assumes amt -> %eax, value -> %edx

// Returns: old value in %eax
// NB: OSAtomicAdd32 returns the new value,  so clients will add amt to %eax 

COMMPAGE_FUNCTION_START(atomic_add32_mp, 32, 4)
.long	_COMM_PAGE_ATOMIC_ADD32+4
	lock
	xaddl	%eax, (%edx)
	ret
COMMPAGE_DESCRIPTOR(atomic_add32_mp,_COMM_PAGE_ATOMIC_ADD32,0,kUP)

COMMPAGE_FUNCTION_START(atomic_add32_up, 32, 4)
.long	_COMM_PAGE_ATOMIC_ADD32+4
	xaddl	%eax, (%edx)
	ret
COMMPAGE_DESCRIPTOR(atomic_add32_up,_COMM_PAGE_ATOMIC_ADD32,kUP,0)
    
    
// OSMemoryBarrier()
// These are used both in 32 and 64-bit mode.  We use a fence even on UP
// machines, so this function can be used with nontemporal stores.

COMMPAGE_FUNCTION_START(memory_barrier, 32, 4)
	lock
	addl	$0,(%esp)
	ret
COMMPAGE_DESCRIPTOR(memory_barrier,_COMM_PAGE_MEMORY_BARRIER,0,kHasSSE2);

COMMPAGE_FUNCTION_START(memory_barrier_sse2, 32, 4)
	mfence
	ret
COMMPAGE_DESCRIPTOR(memory_barrier_sse2,_COMM_PAGE_MEMORY_BARRIER,kHasSSE2,0);
    

/*
 *	typedef	volatile struct {
 *		void	*opaque1;  <-- ptr to 1st queue element or null
 *		long	 opaque2;  <-- generation count
 *	} OSQueueHead;
 *
 * void  OSAtomicEnqueue( OSQueueHead *list, void *new, size_t offset);
 */

COMMPAGE_FUNCTION_START(AtomicEnqueue, 32, 4)
	pushl	%edi
	pushl	%esi
	pushl	%ebx
	movl	16(%esp),%edi	// %edi == ptr to list head
	movl	20(%esp),%ebx	// %ebx == new
	movl	24(%esp),%esi	// %esi == offset
	movl	(%edi),%eax	// %eax == ptr to 1st element in Q
	movl	4(%edi),%edx	// %edx == current generation count
1:
	movl	%eax,(%ebx,%esi)// link to old list head from new element
	movl	%edx,%ecx
	incl	%ecx		// increment generation count
	lock			// always lock for now...
	cmpxchg8b (%edi)	// ...push on new element
	jnz	1b
	popl	%ebx
	popl	%esi
	popl	%edi
	ret
COMMPAGE_DESCRIPTOR(AtomicEnqueue,_COMM_PAGE_ENQUEUE,0,0)
	
	
/* void* OSAtomicDequeue( OSQueueHead *list, size_t offset); */

COMMPAGE_FUNCTION_START(AtomicDequeue, 32, 4)
	pushl	%edi
	pushl	%esi
	pushl	%ebx
	movl	16(%esp),%edi	// %edi == ptr to list head
	movl	20(%esp),%esi	// %esi == offset
	movl	(%edi),%eax	// %eax == ptr to 1st element in Q
	movl	4(%edi),%edx	// %edx == current generation count
1:
	testl	%eax,%eax	// list empty?
	jz	2f		// yes
	movl	(%eax,%esi),%ebx // point to 2nd in Q
	movl	%edx,%ecx
	incl	%ecx		// increment generation count
	lock			// always lock for now...
	cmpxchg8b (%edi)	// ...pop off 1st element
	jnz	1b
2:
	popl	%ebx
	popl	%esi
	popl	%edi
	ret			// ptr to 1st element in Q still in %eax
COMMPAGE_DESCRIPTOR(AtomicDequeue,_COMM_PAGE_DEQUEUE,0,0)



/************************* x86_64 versions follow **************************/


// This is a subroutine used by:

// bool OSAtomicCompareAndSwap32( int32_t old, int32_t new, int32_t *value);
// int32_t OSAtomicAnd32( int32_t mask, int32_t *value);
// int32_t OSAtomicOr32( int32_t mask, int32_t *value);
// int32_t OSAtomicXor32( int32_t mask, int32_t *value);

// It assumes: old -> %rdi  (ie, it follows the ABI parameter conventions)
//             new -> %rsi
//             value -> %rdx
// on success: returns with ZF set
// on failure: returns with *value in %eax, ZF clear

COMMPAGE_FUNCTION_START(compare_and_swap32_mp_64, 64, 4)
	movl	%edi,%eax			// put old value where "cmpxchg" wants it
	lock
	cmpxchgl  %esi, (%rdx)
	ret
COMMPAGE_DESCRIPTOR(compare_and_swap32_mp_64,_COMM_PAGE_COMPARE_AND_SWAP32,0,kUP)

COMMPAGE_FUNCTION_START(compare_and_swap32_up_64, 64, 4)
	movl	%edi,%eax			// put old value where "cmpxchg" wants it
	cmpxchgl  %esi, (%rdx)
	ret
COMMPAGE_DESCRIPTOR(compare_and_swap32_up_64,_COMM_PAGE_COMPARE_AND_SWAP32,kUP,0)

// This is a subroutine used by:
// bool OSAtomicCompareAndSwap64( int64_t old, int64_t new, int64_t *value);

// It assumes: old -> %rdi  (ie, it follows the ABI parameter conventions)
//             new -> %rsi
//             value -> %rdx
// on success: returns with ZF set
// on failure: returns with *value in %rax, ZF clear

COMMPAGE_FUNCTION_START(compare_and_swap64_mp_64, 64, 4)
	movq	%rdi,%rax			// put old value where "cmpxchg" wants it
	lock
	cmpxchgq  %rsi, (%rdx)
	ret
COMMPAGE_DESCRIPTOR(compare_and_swap64_mp_64,_COMM_PAGE_COMPARE_AND_SWAP64,0,kUP)

COMMPAGE_FUNCTION_START(compare_and_swap64_up_64, 64, 4)
	movq	%rdi,%rax			// put old value where "cmpxchg" wants it
	cmpxchgq  %rsi, (%rdx)
	ret
COMMPAGE_DESCRIPTOR(compare_and_swap64_up_64,_COMM_PAGE_COMPARE_AND_SWAP64,kUP,0)

// This is a subroutine used by:
// bool OSAtomicTestAndSet( uint32_t n, void *value );
// It is called with standard register conventions:
//			n = %rdi
//			value = %rsi
// Returns: old value of bit in CF

COMMPAGE_FUNCTION_START(bit_test_and_set_mp_64, 64, 4)
	lock
	btsl %edi, (%rsi)
	ret
COMMPAGE_DESCRIPTOR(bit_test_and_set_mp_64,_COMM_PAGE_BTS,0,kUP)

COMMPAGE_FUNCTION_START(bit_test_and_set_up_64, 64, 4)
	btsl %edi, (%rsi)
	ret
COMMPAGE_DESCRIPTOR(bit_test_and_set_up_64,_COMM_PAGE_BTS,kUP,0)

// This is a subroutine used by:
// bool OSAtomicTestAndClear( uint32_t n, void *value );
// It is called with standard register conventions:
//			n = %rdi
//			value = %rsi
// Returns: old value of bit in CF

COMMPAGE_FUNCTION_START(bit_test_and_clear_mp_64, 64, 4)
	lock
	btrl %edi, (%rsi)
	ret
COMMPAGE_DESCRIPTOR(bit_test_and_clear_mp_64,_COMM_PAGE_BTC,0,kUP)

COMMPAGE_FUNCTION_START(bit_test_and_clear_up_64, 64, 4)
	btrl %edi, (%rsi)
	ret
COMMPAGE_DESCRIPTOR(bit_test_and_clear_up_64,_COMM_PAGE_BTC,kUP,0)

// This is a subroutine used by:
// int32_t OSAtomicAdd32( int32_t amt, int32_t *value );
// It is called with standard register conventions:
//			amt = %rdi
//			value = %rsi
// Returns: old value in %edi
// NB: OSAtomicAdd32 returns the new value,  so clients will add amt to %edi 

COMMPAGE_FUNCTION_START(atomic_add32_mp_64, 64, 4)
	lock
	xaddl	%edi, (%rsi)
	ret
COMMPAGE_DESCRIPTOR(atomic_add32_mp_64,_COMM_PAGE_ATOMIC_ADD32,0,kUP)

COMMPAGE_FUNCTION_START(atomic_add32_up_64, 64, 4)
	xaddl	%edi, (%rsi)
	ret
COMMPAGE_DESCRIPTOR(atomic_add32_up_64,_COMM_PAGE_ATOMIC_ADD32,kUP,0)

// This is a subroutine used by:
// int64_t OSAtomicAdd64( int64_t amt, int64_t *value );
// It is called with standard register conventions:
//			amt = %rdi
//			value = %rsi
// Returns: old value in %rdi
// NB: OSAtomicAdd64 returns the new value,  so clients will add amt to %rdi 

COMMPAGE_FUNCTION_START(atomic_add64_mp_64, 64, 4)
	lock
	xaddq	%rdi, (%rsi)
	ret
COMMPAGE_DESCRIPTOR(atomic_add64_mp_64,_COMM_PAGE_ATOMIC_ADD64,0,kUP)

COMMPAGE_FUNCTION_START(atomic_add64_up_64, 64, 4)
	xaddq	%rdi, (%rsi)
	ret
COMMPAGE_DESCRIPTOR(atomic_add64_up_64,_COMM_PAGE_ATOMIC_ADD64,kUP,0)


/*
 *	typedef	volatile struct {
 *		void	*opaque1;  <-- ptr to 1st queue element or null
 *		long	 opaque2;  <-- generation count
 *	} OSQueueHead;
 *
 * void  OSAtomicEnqueue( OSQueueHead *list, void *new, size_t offset);
 */

// %rdi == list head, %rsi == new, %rdx == offset

COMMPAGE_FUNCTION_START(AtomicEnqueue_64, 64, 4)
	pushq	%rbx
	movq	%rsi,%rbx	// %rbx == new
	movq	%rdx,%rsi	// %rsi == offset
	movq	(%rdi),%rax	// %rax == ptr to 1st element in Q
	movq	8(%rdi),%rdx	// %rdx == current generation count
1:
	movq	%rax,(%rbx,%rsi)// link to old list head from new element
	movq	%rdx,%rcx
	incq	%rcx		// increment generation count
	lock			// always lock for now...
	cmpxchg16b (%rdi)	// ...push on new element
	jnz	1b
	popq	%rbx
	ret
COMMPAGE_DESCRIPTOR(AtomicEnqueue_64,_COMM_PAGE_ENQUEUE,0,0)
	
	
/* void* OSAtomicDequeue( OSQueueHead *list, size_t offset); */

// %rdi == list head, %rsi == offset

COMMPAGE_FUNCTION_START(AtomicDequeue_64, 64, 4)
	pushq	%rbx
	movq	(%rdi),%rax	// %rax == ptr to 1st element in Q
	movq	8(%rdi),%rdx	// %rdx == current generation count
1:
	testq	%rax,%rax	// list empty?
	jz	2f		// yes
	movq	(%rax,%rsi),%rbx // point to 2nd in Q
	movq	%rdx,%rcx
	incq	%rcx		// increment generation count
	lock			// always lock for now...
	cmpxchg16b (%rdi)	// ...pop off 1st element
	jnz	1b
2:
	popq	%rbx
	ret			// ptr to 1st element in Q still in %rax
COMMPAGE_DESCRIPTOR(AtomicDequeue_64,_COMM_PAGE_DEQUEUE,0,0)
