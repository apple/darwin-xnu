/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
#include <ppc/asm.h>					// EXT, LEXT
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
        .align	2
        .globl	EXT(spinlock_32_try_mp)
        .globl	EXT(spinlock_32_try_up)
        .globl	EXT(spinlock_32_lock_mp)
        .globl	EXT(spinlock_32_lock_up)
        .globl	EXT(spinlock_32_unlock_mp)
        .globl	EXT(spinlock_32_unlock_up)
        
        .globl	EXT(spinlock_64_try_mp)
        .globl	EXT(spinlock_64_try_up)
        .globl	EXT(spinlock_64_lock_mp)
        .globl	EXT(spinlock_64_lock_up)
        .globl	EXT(spinlock_64_unlock_mp)
        .globl	EXT(spinlock_64_unlock_up)
        
        .globl	EXT(spinlock_relinquish)

#define	MP_SPIN_TRIES   1000


// The user mode spinlock library.  There are many versions,
// in order to take advantage of a few special cases:
//	- no barrier instructions (SYNC,ISYNC) are needed if UP
//	- 64-bit processors can use LWSYNC instead of SYNC (if MP)
//	- branch hints appropriate to the processor (+ vs ++ etc)
//	- potentially custom relinquish strategies (not used at present)
//	- fixes for errata as necessary


spinlock_32_try_mp:
	mr	r5, r3
	li	r3, 1
1:
        lwarx	r4,0,r5
        cmpwi	r4,0
        bne-	2f
        stwcx.	r5,0,r5
        isync				// cancel speculative execution
        beqlr+
        b		1b
2:
        li		r3,0
        blr

    COMMPAGE_DESCRIPTOR(spinlock_32_try_mp,_COMM_PAGE_SPINLOCK_TRY,0,k64Bit+kUP,0)
        

spinlock_32_try_up:
	mr	r5, r3
	li	r3, 1
1:
        lwarx	r4,0,r5
        cmpwi	r4,0
        bne-	2f
        stwcx.	r5,0,r5
        beqlr+
        b		1b
2:
        li		r3,0
        blr

    COMMPAGE_DESCRIPTOR(spinlock_32_try_up,_COMM_PAGE_SPINLOCK_TRY,kUP,k64Bit,0)


spinlock_32_lock_mp:
        li		r5,MP_SPIN_TRIES
1:
        lwarx	r4,0,r3
        cmpwi	r4,0
        bne-	2f
        stwcx.	r3,0,r3
        isync				// cancel speculative execution
        beqlr+				// we return void
        b		1b
2:
        subic.	r5,r5,1		// try again before relinquish?
        bne		1b
        ba		_COMM_PAGE_RELINQUISH

    COMMPAGE_DESCRIPTOR(spinlock_32_lock_mp,_COMM_PAGE_SPINLOCK_LOCK,0,k64Bit+kUP,0)


spinlock_32_lock_up:
1:
        lwarx	r4,0,r3
        cmpwi	r4,0
        bnea-	_COMM_PAGE_RELINQUISH	// always depress on UP (let lock owner run)
        stwcx.	r3,0,r3
        beqlr+				// we return void
        b		1b

    COMMPAGE_DESCRIPTOR(spinlock_32_lock_up,_COMM_PAGE_SPINLOCK_LOCK,kUP,k64Bit,0)


spinlock_32_unlock_mp:
        li		r4,0
        sync				// complete prior stores before unlock
        stw		r4,0(r3)
        blr

    COMMPAGE_DESCRIPTOR(spinlock_32_unlock_mp,_COMM_PAGE_SPINLOCK_UNLOCK,0,k64Bit+kUP,0)


spinlock_32_unlock_up:
        li		r4,0
        stw		r4,0(r3)
        blr

    COMMPAGE_DESCRIPTOR(spinlock_32_unlock_up,_COMM_PAGE_SPINLOCK_UNLOCK,kUP,k64Bit,0)


spinlock_64_try_mp:
	mr	r5, r3
	li	r3, 1
1:
        lwarx	r4,0,r5
        cmpwi	r4,0
        bne--	2f
        stwcx.	r5,0,r5
        isync				// cancel speculative execution
        beqlr++
        b		1b
2:
        li		r6,-4
        stwcx.	r5,r6,r1	// clear the pending reservation (using red zone)
        li		r3,0		// Pass failure
        blr

    COMMPAGE_DESCRIPTOR(spinlock_64_try_mp,_COMM_PAGE_SPINLOCK_TRY,k64Bit,kUP,0)


spinlock_64_try_up:
	mr	r5, r3
	li	r3, 1
1:
        lwarx	r4,0,r5
        cmpwi	r4,0
        bne--	2f
        stwcx.	r5,0,r5
        beqlr++
        b		1b
2:
        li		r6,-4
        stwcx.	r5,r6,r1	// clear the pending reservation (using red zone)
        li		r3,0
        blr

    COMMPAGE_DESCRIPTOR(spinlock_64_try_up,_COMM_PAGE_SPINLOCK_TRY,k64Bit+kUP,0,0)


spinlock_64_lock_mp:
        li		r5,MP_SPIN_TRIES
1:
        lwarx	r4,0,r3
        cmpwi	r4,0
        bne--	2f
        stwcx.	r3,0,r3
        isync				// cancel speculative execution
        beqlr++				// we return void
        b		1b
2:
        li		r6,-4
        stwcx.	r3,r6,r1	// clear the pending reservation (using red zone)
        subic.	r5,r5,1		// try again before relinquish?
        bne--	1b			// mispredict this one (a cheap back-off)
        ba		_COMM_PAGE_RELINQUISH

    COMMPAGE_DESCRIPTOR(spinlock_64_lock_mp,_COMM_PAGE_SPINLOCK_LOCK,k64Bit,kUP,0)


spinlock_64_lock_up:
1:
        lwarx	r4,0,r3
        cmpwi	r4,0
        bne--	2f
        stwcx.	r3,0,r3
        beqlr++				// we return void
        b		1b
2:							// always relinquish on UP (let lock owner run)
        li		r6,-4
        stwcx.	r3,r6,r1	// clear the pending reservation (using red zone)
		ba		_COMM_PAGE_RELINQUISH

    COMMPAGE_DESCRIPTOR(spinlock_64_lock_up,_COMM_PAGE_SPINLOCK_LOCK,k64Bit+kUP,0,0)


spinlock_64_unlock_mp:
        li		r4,0
        lwsync				// complete prior stores before unlock
        stw		r4,0(r3)
        blr

    COMMPAGE_DESCRIPTOR(spinlock_64_unlock_mp,_COMM_PAGE_SPINLOCK_UNLOCK,k64Bit,kUP,0)


spinlock_64_unlock_up:
        li		r4,0
        stw		r4,0(r3)
        blr

    COMMPAGE_DESCRIPTOR(spinlock_64_unlock_up,_COMM_PAGE_SPINLOCK_UNLOCK,k64Bit+kUP,0,0)
    

spinlock_relinquish:
        mr		r12,r3		// preserve lockword ptr across relinquish
        li		r3,0		// THREAD_NULL
        li		r4,1		// SWITCH_OPTION_DEPRESS
        li		r5,1		// timeout (ms)
        li		r0,-61		// SYSCALL_THREAD_SWITCH
        sc					// relinquish
        mr		r3,r12
        ba		_COMM_PAGE_SPINLOCK_LOCK
        
    COMMPAGE_DESCRIPTOR(spinlock_relinquish,_COMM_PAGE_RELINQUISH,0,0,0)

