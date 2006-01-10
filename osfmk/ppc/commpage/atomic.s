/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/appleapiopts.h>
#include <ppc/asm.h>					// EXT, LEXT
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>


/* OSAtomic.h library native implementations. */

        .text
        .align	2

atomic_add32:						// int32_t OSAtomicAdd32( int32_t amt, int32_t *value );
1:
		lwarx   r5,0,r4
		add		r6,r3,r5
		stwcx.  r6,0,r4
		bne--   1b
		mr		r3,r6
		blr
		
    COMMPAGE_DESCRIPTOR(atomic_add32,_COMM_PAGE_ATOMIC_ADD32,0,0,kCommPageBoth)


atomic_add64:						// int64_t OSAtomicAdd64( int64_t amt, int64_t *value );
1:
		ldarx   r5,0,r4
		add		r6,r3,r5
		stdcx.  r6,0,r4
		bne--   1b
		mr		r3,r6
		blr
		
    COMMPAGE_DESCRIPTOR(atomic_add64,_COMM_PAGE_ATOMIC_ADD64,k64Bit,0,kCommPage64)

/* WARNING: Libc clients assume compare-and-swap preserves r4, r5, and r9-r12! */
/* This is the no-barrier version */
compare_and_swap32_on32:			// bool OSAtomicCompareAndSwap32( int32_t old, int32_t new, int32_t *value);
1:
		lwarx   r7,0,r5
		cmplw   r7,r3
		bne-	2f
		stwcx.  r4,0,r5
		bne-	1b
		li		r3,1
		blr
2:
		li		r3,0				// return failure
		blr

    COMMPAGE_DESCRIPTOR(compare_and_swap32_on32,_COMM_PAGE_COMPARE_AND_SWAP32,0,k64Bit,kCommPageBoth)


/* WARNING: Libc clients assume compare-and-swap preserves r4, r5, and r9-r12! */
/* This is the no-barrier version */
compare_and_swap32_on64:			// bool OSAtomicCompareAndSwap32( int32_t old, int32_t new, int32_t *value);
1:
		lwarx   r7,0,r5
		cmplw   r7,r3
		bne--	2f
		stwcx.  r4,0,r5
		bne--	1b
		li		r3,1
		blr
2:
		li		r8,-8				// on 970, must release reservation
		li		r3,0				// return failure
		stwcx.  r4,r8,r1			// store into red zone to release
		blr

    COMMPAGE_DESCRIPTOR(compare_and_swap32_on64,_COMM_PAGE_COMPARE_AND_SWAP32,k64Bit,0,kCommPageBoth)


/* WARNING: Libc clients assume compare-and-swap preserves r4, r5, and r9-r12! */
/* This is the no-barrier version */
compare_and_swap64:					// bool OSAtomicCompareAndSwap64( int64_t old, int64_t new, int64_t *value);
1:
		ldarx   r7,0,r5
		cmpld   r7,r3
		bne--	2f
		stdcx.  r4,0,r5
		bne--	1b
		li		r3,1
		blr
2:
		li		r8,-8				// on 970, must release reservation
		li		r3,0				// return failure
		stdcx.  r4,r8,r1			// store into red zone to release
		blr

    COMMPAGE_DESCRIPTOR(compare_and_swap64,_COMM_PAGE_COMPARE_AND_SWAP64,k64Bit,0,kCommPage64)

/* WARNING: Libc clients assume compare-and-swap preserves r4, r5, and r9-r12! */
/* This version of compare-and-swap incorporates a memory barrier. */
compare_and_swap32_on32b:			// bool OSAtomicCompareAndSwapBarrier32( int32_t old, int32_t new, int32_t *value);
        eieio                       // write barrier, NOP'd on a UP
1:
		lwarx   r7,0,r5
		cmplw   r7,r3
		bne-	2f
		stwcx.  r4,0,r5
		bne-	1b
        isync                       // read barrier, NOP'd on a UP
		li		r3,1
		blr
2:
		li		r3,0				// return failure
		blr

    COMMPAGE_DESCRIPTOR(compare_and_swap32_on32b,_COMM_PAGE_COMPARE_AND_SWAP32B,0,k64Bit,kCommPageBoth+kCommPageSYNC+kCommPageISYNC)


/* WARNING: Libc clients assume compare-and-swap preserves r4, r5, and r9-r12! */
/* This version of compare-and-swap incorporates a memory barrier. */
compare_and_swap32_on64b:			// bool OSAtomicCompareAndSwapBarrier32( int32_t old, int32_t new, int32_t *value);
        lwsync                      // write barrier, NOP'd on a UP
1:
		lwarx   r7,0,r5
		cmplw   r7,r3
		bne--	2f
		stwcx.  r4,0,r5
		bne--	1b
        isync                       // read barrier, NOP'd on a UP
		li		r3,1
		blr
2:
		li		r8,-8				// on 970, must release reservation
		li		r3,0				// return failure
		stwcx.  r4,r8,r1			// store into red zone to release
		blr

    COMMPAGE_DESCRIPTOR(compare_and_swap32_on64b,_COMM_PAGE_COMPARE_AND_SWAP32B,k64Bit,0,kCommPageBoth+kCommPageSYNC+kCommPageISYNC)


/* WARNING: Libc clients assume compare-and-swap preserves r4, r5, and r9-r12! */
/* This version of compare-and-swap incorporates a memory barrier. */
compare_and_swap64b:				// bool OSAtomicCompareAndSwapBarrier64( int64_t old, int64_t new, int64_t *value);
        lwsync                      // write barrier, NOP'd on a UP
1:
		ldarx   r7,0,r5
		cmpld   r7,r3
		bne--	2f
		stdcx.  r4,0,r5
		bne--	1b
        isync                       // read barrier, NOP'd on a UP
		li		r3,1
		blr
2:
		li		r8,-8				// on 970, must release reservation
		li		r3,0				// return failure
		stdcx.  r4,r8,r1			// store into red zone to release
		blr

    COMMPAGE_DESCRIPTOR(compare_and_swap64b,_COMM_PAGE_COMPARE_AND_SWAP64B,k64Bit,0,kCommPage64+kCommPageSYNC+kCommPageISYNC)


atomic_enqueue32:					// void OSAtomicEnqueue( void **list, void *new, size_t offset);
1:
		lwarx   r6,0,r3				// get link to 1st on list
		stwx	r6,r4,r5			// hang list off new node
		eieio						// make sure the "stwx" comes before "stwcx." (nop'd on UP)
		stwcx.  r4,0,r3				// make new 1st on list
		beqlr++
		b		1b
		
    COMMPAGE_DESCRIPTOR(atomic_enqueue32,_COMM_PAGE_ENQUEUE,0,0,kCommPageSYNC+kCommPage32)


atomic_enqueue64:					// void OSAtomicEnqueue( void **list, void *new, size_t offset);
1:
		ldarx   r6,0,r3				// get link to 1st on list
		stdx	r6,r4,r5			// hang list off new node
		lwsync						// make sure the "stdx" comes before the "stdcx." (nop'd on UP)
		stdcx.  r4,0,r3				// make new 1st on list
		beqlr++
		b		1b
		
    COMMPAGE_DESCRIPTOR(atomic_enqueue64,_COMM_PAGE_ENQUEUE,k64Bit,0,kCommPageSYNC+kCommPage64)


atomic_dequeue32_on32:              // void* OSAtomicDequeue( void **list, size_t offset);
        mr      r5,r3
1:
		lwarx   r3,0,r5				// get 1st in list
        cmpwi   r3,0                // null?
        beqlr                       // yes, list empty
		lwzx	r6,r3,r4			// get 2nd
		stwcx.  r6,0,r5				// make 2nd first
		bne--	1b
		isync						// cancel read-aheads (nop'd on UP)
		blr

    COMMPAGE_DESCRIPTOR(atomic_dequeue32_on32,_COMM_PAGE_DEQUEUE,0,k64Bit,kCommPageISYNC+kCommPage32)


atomic_dequeue32_on64:              // void* OSAtomicDequeue( void **list, size_t offset);
        mr      r5,r3
        li      r7,-8               // use red zone to release reservation if necessary
1:
		lwarx   r3,0,r5				// get 1st in list
        cmpwi   r3,0                // null?
        beq     2f
		lwzx	r6,r3,r4			// get 2nd
		stwcx.  r6,0,r5				// make 2nd first
		isync						// cancel read-aheads (nop'd on UP)
		beqlr++                     // return next element in r2
        b       1b                  // retry (lost reservation)
2:
        stwcx.  r0,r7,r1            // on 970, release reservation using red zone
		blr                         // return null

    COMMPAGE_DESCRIPTOR(atomic_dequeue32_on64,_COMM_PAGE_DEQUEUE,k64Bit,0,kCommPageISYNC+kCommPage32)


atomic_dequeue64:					// void* OSAtomicDequeue( void **list, size_t offset);
        mr      r5,r3
        li      r7,-8               // use red zone to release reservation if necessary
1:
		ldarx   r3,0,r5				// get 1st in list
        cmpdi   r3,0                // null?
        beq     2f
		ldx     r6,r3,r4			// get 2nd
		stdcx.  r6,0,r5				// make 2nd first
		isync						// cancel read-aheads (nop'd on UP)
		beqlr++                     // return next element in r2
        b       1b                  // retry (lost reservation)
2:
        stdcx.  r0,r7,r1            // on 970, release reservation using red zone
		blr                         // return null

    COMMPAGE_DESCRIPTOR(atomic_dequeue64,_COMM_PAGE_DEQUEUE,k64Bit,0,kCommPageISYNC+kCommPage64)


memory_barrier_up:					// void OSMemoryBarrier( void )
		blr							// nothing to do on UP
		
    COMMPAGE_DESCRIPTOR(memory_barrier_up,_COMM_PAGE_MEMORY_BARRIER,kUP,0,kCommPageBoth)


memory_barrier_mp32:				// void OSMemoryBarrier( void )
		isync						// we use eieio in preference to sync...
		eieio						// ...because it is faster
		blr
		
    COMMPAGE_DESCRIPTOR(memory_barrier_mp32,_COMM_PAGE_MEMORY_BARRIER,0,kUP+k64Bit,kCommPage32)


memory_barrier_mp64:				// void OSMemoryBarrier( void )
		isync
		lwsync						// on 970, lwsync is faster than eieio
		blr
		
    COMMPAGE_DESCRIPTOR(memory_barrier_mp64,_COMM_PAGE_MEMORY_BARRIER,k64Bit,kUP,kCommPageBoth)
