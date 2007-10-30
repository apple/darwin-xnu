/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
#include <ppc/asm.h>					// EXT, LEXT
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

        .text
        .align	2


// *********************************************
// * C O M M P A G E _ F L U S H _ D C A C H E *
// *********************************************
//
// Note that this routine is called both in 32 and 64-bit mode.
//
//	r3 = ptr to 1st byte to flush
//	r4 = length to flush (may be 0)

commpage_flush_dcache:
        mr.     r4,r4           // test length for 0 in mode-independent way
        lhz		r5,_COMM_PAGE_CACHE_LINESIZE(0)
        subi	r9,r5,1			// get (linesize-1)
        and		r0,r3,r9		// get offset within line of 1st byte
        add		r4,r4,r0		// adjust length so we flush them all
        add		r4,r4,r9		// round length up...
        andc	r4,r4,r9		// ...to multiple of cache lines
        beqlr--					// length was 0, so exit
1:
        sub.	r4,r4,r5		// more to go?
        dcbf	0,r3			// flush another line
        add		r3,r3,r5
        bne		1b
        sync					// make sure lines are flushed before we return
        blr
        
	COMMPAGE_DESCRIPTOR(commpage_flush_dcache,_COMM_PAGE_FLUSH_DCACHE,0,0,kCommPageBoth)
        
        
// *********************************************
// * C O M M P A G E _ F L U S H _ I C A C H E *
// *********************************************
//
// Note that this routine is called both in 32 and 64-bit mode.
//
//	r3 = ptr to 1st byte to flush
//	r4 = length to flush (may be 0)

commpage_flush_icache:
        mr.     r4,r4           // test length for 0 in mode-independent way
        lhz		r5,_COMM_PAGE_CACHE_LINESIZE(0)
        subi	r9,r5,1			// get (linesize-1)
        and		r0,r3,r9		// get offset within line of 1st byte
        add		r4,r4,r0		// adjust length so we flush them all
        mr		r7,r3			// copy ptr
        add		r4,r4,r9		// round length up...
        andc	r4,r4,r9		// ...to multiple of cache lines
        mr		r6,r4			// copy length
        beqlr--					// length was 0, so exit
1:
        sub.	r4,r4,r5		// more to go?
        dcbf	0,r3			// flush another line
        add		r3,r3,r5
        bne		1b
        sync					// make sure lines are flushed
2:
        sub.	r6,r6,r5		// more to go?
        icbi	0,r7
        add		r7,r7,r5
        bne		2b
        
        // The following sync is only needed on MP machines, probably only on
        // 7400-family MP machines.  But because we're not certain of this, and
        // this isn't a speed critical routine, we are conservative and always sync.
        
        sync					// wait until other processors see the icbi's
        isync					// make sure we haven't prefetched old instructions
        
        blr

	COMMPAGE_DESCRIPTOR(commpage_flush_icache,_COMM_PAGE_FLUSH_ICACHE,0,0,kCommPageBoth)

        
