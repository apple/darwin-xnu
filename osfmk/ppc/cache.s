/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/*
 * @OSF_COPYRIGHT@
 */

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <assym.s>

/* These routines run in 32 or 64-bit addressing, and handle
 * 32 and 128 byte caches.  They do not use compare instructions
 * on addresses, since compares are 32/64-bit-mode-specific.
 */

#define	kDcbf			0x1
#define	kDcbfb			31
#define	kDcbi			0x2
#define	kDcbib			30
#define	kIcbi			0x4
#define	kIcbib			29


/*
 * extern void flush_dcache(vm_offset_t addr, unsigned count, boolean phys);
 * extern void flush_dcache64(addr64_t addr, unsigned count, boolean phys);
 *
 * flush_dcache takes a virtual or physical address and count to flush
 * and (can be called for multiple virtual pages).
 *
 * it flushes the data cache
 * cache for the address range in question
 *
 * if 'phys' is non-zero then physical addresses will be used
 */


 
        .text
        .align	5
        .globl	_flush_dcache
_flush_dcache:
        li		r0,kDcbf					// use DCBF instruction
        rlwinm	r3,r3,0,0,31				// truncate address in case this is a 64-bit machine
        b		cache_op_join				// join common code

        .align	5
        .globl	_flush_dcache64
_flush_dcache64:
		rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
		li		r0,kDcbf					// use DCBF instruction
		rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
		mr		r4,r5						; Move count
		mr		r5,r6						; Move physical flag
        b		cache_op_join				// join common code


/*
 * extern void invalidate_dcache(vm_offset_t va, unsigned count, boolean phys);
 * extern void invalidate_dcache64(addr64_t va, unsigned count, boolean phys);
 *
 * invalidate_dcache takes a virtual or physical address and count to
 * invalidate and (can be called for multiple virtual pages).
 *
 * it invalidates the data cache for the address range in question
 */
 
        .globl	_invalidate_dcache
_invalidate_dcache:
        li		r0,kDcbi					// use DCBI instruction
        rlwinm	r3,r3,0,0,31				// truncate address in case this is a 64-bit machine
        b		cache_op_join				// join common code


        .align	5
        .globl	_invalidate_dcache64
_invalidate_dcache64:
		rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
        li		r0,kDcbi					// use DCBI instruction
		rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
		mr		r4,r5						; Move count
		mr		r5,r6						; Move physical flag
        b		cache_op_join				// join common code

/*
 * extern void invalidate_icache(vm_offset_t addr, unsigned cnt, boolean phys);
 * extern void invalidate_icache64(addr64_t addr, unsigned cnt, boolean phys);
 *
 * invalidate_icache takes a virtual or physical address and
 * count to invalidate, (can be called for multiple virtual pages).
 *
 * it invalidates the instruction cache for the address range in question.
 */
 
        .globl	_invalidate_icache
_invalidate_icache:
        li		r0,kIcbi					// use ICBI instruction
        rlwinm	r3,r3,0,0,31				// truncate address in case this is a 64-bit machine
        b		cache_op_join				// join common code
        

        .align	5
        .globl	_invalidate_icache64
_invalidate_icache64:
		rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
        li		r0,kIcbi					// use ICBI instruction
		rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
		mr		r4,r5						; Move count
		mr		r5,r6						; Move physical flag
        b		cache_op_join				// join common code
                        
/*
 * extern void sync_ppage(ppnum_t pa);
 *
 * sync_ppage takes a physical page number
 *
 * it writes out the data cache and invalidates the instruction
 * cache for the address range in question
 */

        .globl	_sync_ppage
        .align	5
_sync_ppage:								// Should be the most commonly called routine, by far 
		mfsprg	r2,2
        li		r0,kDcbf+kIcbi				// we need to dcbf and then icbi
		mtcrf	0x02,r2						; Move pf64Bit to cr6
        li		r5,1						// set flag for physical addresses
		li		r4,4096						; Set page size
		bt++	pf64Bitb,spp64				; Skip if 64-bit (only they take the hint)
        rlwinm	r3,r3,12,0,19				; Convert to physical address - 32-bit
        b		cache_op_join				; Join up....
        
spp64:	sldi	r3,r3,12					; Convert to physical address - 64-bit        
        b		cache_op_join				; Join up....
                        


/*
 * extern void sync_cache_virtual(vm_offset_t addr, unsigned count);
 *
 * Like "sync_cache", except it takes a virtual address and byte count.
 * It flushes the data cache, invalidates the I cache, and sync's.
 */
 
        .globl	_sync_cache_virtual
        .align	5
_sync_cache_virtual:
        li		r0,kDcbf+kIcbi				// we need to dcbf and then icbi
        li		r5,0						// set flag for virtual addresses
        b		cache_op_join				// join common code
        
                        
/*
 * extern void sync_cache(vm_offset_t pa, unsigned count);
 * extern void sync_cache64(addr64_t pa, unsigned count);
 *
 * sync_cache takes a physical address and count to sync, thus
 * must not be called for multiple virtual pages.
 *
 * it writes out the data cache and invalidates the instruction
 * cache for the address range in question
 */

        .globl	_sync_cache
        .align	5
_sync_cache:
        li		r0,kDcbf+kIcbi				// we need to dcbf and then icbi
        li		r5,1						// set flag for physical addresses
        rlwinm	r3,r3,0,0,31				// truncate address in case this is a 64-bit machine
        b		cache_op_join				// join common code

        .globl	_sync_cache64
        .align	5
_sync_cache64: 
		rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
        li		r0,kDcbf+kIcbi				// we need to dcbf and then icbi
		rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
       	mr		r4,r5						; Copy over the length
        li		r5,1						// set flag for physical addresses

        
        // Common code to handle the cache operations.

cache_op_join:								// here with r3=addr, r4=count, r5=phys flag, r0=bits
        mfsprg	r10,2						// r10 <- processor feature flags
        cmpwi	cr5,r5,0					// using physical addresses?
        mtcrf	0x01,r0						// move kDcbf, kDcbi, and kIcbi bits to CR7
        andi.	r9,r10,pf32Byte+pf128Byte	// r9 <- cache line size
        mtcrf	0x02,r10					// move pf64Bit bit to CR6
        subi	r8,r9,1						// r8 <- (linesize-1)
        beq--	cr5,cache_op_2				// skip if using virtual addresses
        
        bf--	pf64Bitb,cache_op_not64		// This is not a 64-bit machine
       
        srdi	r12,r3,31					// Slide bit 32 to bit 63
        cmpldi	r12,1						// Are we in the I/O mapped area?
        beqlr--								// No cache ops allowed here...
        
cache_op_not64:
        mflr	r12							// save return address
        bl		EXT(ml_set_physical)		// turn on physical addressing
        mtlr	r12							// restore return address

        // get r3=first cache line, r4=first line not in set, r6=byte count
        
cache_op_2:        
        add		r7,r3,r4					// point to 1st byte not to operate on
        andc	r3,r3,r8					// r3 <- 1st line to operate on
        add		r4,r7,r8					// round up
        andc	r4,r4,r8					// r4 <- 1st line not to operate on
        sub.	r6,r4,r3					// r6 <- byte count to operate on
        beq--	cache_op_exit				// nothing to do
        bf--	kDcbfb,cache_op_6			// no need to dcbf
        
        
        // DCBF loop
        
cache_op_5:
        sub.	r6,r6,r9					// more to go?
        dcbf	r6,r3						// flush next line to RAM
        bne		cache_op_5					// loop if more to go
        sync								// make sure the data reaches RAM
        sub		r6,r4,r3					// reset count


        // ICBI loop
        
cache_op_6:
        bf--	kIcbib,cache_op_8			// no need to icbi
cache_op_7:
        sub.	r6,r6,r9					// more to go?
        icbi	r6,r3						// invalidate next line
        bne		cache_op_7
        sub		r6,r4,r3					// reset count
        isync
        sync
        
        
        // DCBI loop
        
cache_op_8:
        bf++	kDcbib,cache_op_exit		// no need to dcbi
cache_op_9:
        sub.	r6,r6,r9					// more to go?
        dcbi	r6,r3						// invalidate next line
        bne		cache_op_9
        sync
        
        
        // restore MSR iff necessary and done
        
cache_op_exit:
        beqlr--	cr5							// if using virtual addresses, no need to restore MSR
        b		EXT(ml_restore)				// restore MSR and return

