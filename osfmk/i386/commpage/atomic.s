/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

/* OSAtomic.h library native implementations. */

	.text
	.align	2, 0x90

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

Lcompare_and_swap32_mp:
.long	_COMM_PAGE_COMPARE_AND_SWAP32+4
	lock
	cmpxchgl  %edx, (%ecx)
	ret

    COMMPAGE_DESCRIPTOR(compare_and_swap32_mp,_COMM_PAGE_COMPARE_AND_SWAP32,0,kUP)

Lcompare_and_swap32_up:
.long	_COMM_PAGE_COMPARE_AND_SWAP32+4
	cmpxchgl %edx, (%ecx)
	ret

    COMMPAGE_DESCRIPTOR(compare_and_swap32_up,_COMM_PAGE_COMPARE_AND_SWAP32,kUP,0)

// This is a subroutine used by:
// bool OSAtomicCompareAndSwap64( int64_t old, int64_t new, int64_t *value);

// It assumes old -> %eax/%edx, new -> %ebx/%ecx, value -> %esi
// on success: returns with ZF set
// on failure: returns with *value in %eax/%edx, ZF clear

Lcompare_and_swap64_mp:
.long	_COMM_PAGE_COMPARE_AND_SWAP64+4
	lock
	cmpxchg8b (%esi)
	ret

    COMMPAGE_DESCRIPTOR(compare_and_swap64_mp,_COMM_PAGE_COMPARE_AND_SWAP64,0,kUP)

Lcompare_and_swap64_up:
.long	_COMM_PAGE_COMPARE_AND_SWAP64+4
	cmpxchg8b (%esi)
	ret

    COMMPAGE_DESCRIPTOR(compare_and_swap64_up,_COMM_PAGE_COMPARE_AND_SWAP64,kUP,0)

// This is a subroutine used by:
// bool OSAtomicTestAndSet( uint32_t n, void *value );
// It assumes n -> %eax, value -> %edx

// Returns: old value of bit in CF

Lbit_test_and_set_mp:
.long	_COMM_PAGE_BTS+4
	lock
	btsl %eax, (%edx)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_set_mp,_COMM_PAGE_BTS,0,kUP)

Lbit_test_and_set_up:
.long	_COMM_PAGE_BTS+4
	btsl %eax, (%edx)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_set_up,_COMM_PAGE_BTS,kUP,0)

// This is a subroutine used by:
// bool OSAtomicTestAndClear( uint32_t n, void *value );
// It assumes n -> %eax, value -> %edx

// Returns: old value of bit in CF

Lbit_test_and_clear_mp:
.long	_COMM_PAGE_BTC+4
	lock
	btrl %eax, (%edx)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_clear_mp,_COMM_PAGE_BTC,0,kUP)

Lbit_test_and_clear_up:
.long	_COMM_PAGE_BTC+4
	btrl %eax, (%edx)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_clear_up,_COMM_PAGE_BTC,kUP,0)

// This is a subroutine used by:
// int32_t OSAtomicAdd32( int32_t amt, int32_t *value );
// It assumes amt -> %eax, value -> %edx

// Returns: old value in %eax
// NB: OSAtomicAdd32 returns the new value,  so clients will add amt to %eax 

Latomic_add32_mp:
.long	_COMM_PAGE_ATOMIC_ADD32+4
	lock
	xaddl	%eax, (%edx)
	ret
		
    COMMPAGE_DESCRIPTOR(atomic_add32_mp,_COMM_PAGE_ATOMIC_ADD32,0,kUP)

Latomic_add32_up:
.long	_COMM_PAGE_ATOMIC_ADD32+4
	xaddl	%eax, (%edx)
	ret

    COMMPAGE_DESCRIPTOR(atomic_add32_up,_COMM_PAGE_ATOMIC_ADD32,kUP,0)


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

	.code64
Lcompare_and_swap32_mp_64:
	movl	%edi,%eax			// put old value where "cmpxchg" wants it
	lock
	cmpxchgl  %esi, (%rdx)
	ret

    COMMPAGE_DESCRIPTOR(compare_and_swap32_mp_64,_COMM_PAGE_COMPARE_AND_SWAP32,0,kUP)

	.code64
Lcompare_and_swap32_up_64:
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

	.code64
Lcompare_and_swap64_mp_64:
	movq	%rdi,%rax			// put old value where "cmpxchg" wants it
	lock
	cmpxchgq  %rsi, (%rdx)
	ret

    COMMPAGE_DESCRIPTOR(compare_and_swap64_mp_64,_COMM_PAGE_COMPARE_AND_SWAP64,0,kUP)

	.code64
Lcompare_and_swap64_up_64:
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

	.code64
Lbit_test_and_set_mp_64:
	lock
	btsl %edi, (%rsi)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_set_mp_64,_COMM_PAGE_BTS,0,kUP)

	.code64
Lbit_test_and_set_up_64:
	btsl %edi, (%rsi)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_set_up_64,_COMM_PAGE_BTS,kUP,0)

// This is a subroutine used by:
// bool OSAtomicTestAndClear( uint32_t n, void *value );
// It is called with standard register conventions:
//			n = %rdi
//			value = %rsi
// Returns: old value of bit in CF

	.code64
Lbit_test_and_clear_mp_64:
	lock
	btrl %edi, (%rsi)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_clear_mp_64,_COMM_PAGE_BTC,0,kUP)

	.code64
Lbit_test_and_clear_up_64:
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

	.code64
Latomic_add32_mp_64:
	lock
	xaddl	%edi, (%rsi)
	ret
		
    COMMPAGE_DESCRIPTOR(atomic_add32_mp_64,_COMM_PAGE_ATOMIC_ADD32,0,kUP)

	.code64
Latomic_add32_up_64:
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

	.code64
Latomic_add64_mp_64:
	lock
	xaddq	%rdi, (%rsi)
	ret
		
    COMMPAGE_DESCRIPTOR(atomic_add64_mp_64,_COMM_PAGE_ATOMIC_ADD64,0,kUP)

	.code64
Latomic_add64_up_64:
	xaddq	%rdi, (%rsi)
	ret

    COMMPAGE_DESCRIPTOR(atomic_add64_up_64,_COMM_PAGE_ATOMIC_ADD64,kUP,0)
