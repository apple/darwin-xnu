/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
	bts %eax, (%edx)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_set_mp,_COMM_PAGE_BTS,0,kUP)

Lbit_test_and_set_up:
.long	_COMM_PAGE_BTS+4
	bts %eax, (%edx)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_set_up,_COMM_PAGE_BTS,kUP,0)

// This is a subroutine used by:
// bool OSAtomicTestAndClear( uint32_t n, void *value );
// It assumes n -> %eax, value -> %edx

// Returns: old value of bit in CF

Lbit_test_and_clear_mp:
.long	_COMM_PAGE_BTC+4
	lock
	btc %eax, (%edx)
	ret

    COMMPAGE_DESCRIPTOR(bit_test_and_clear_mp,_COMM_PAGE_BTC,0,kUP)

Lbit_test_and_clear_up:
.long	_COMM_PAGE_BTC+4
	btc %eax, (%edx)
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
