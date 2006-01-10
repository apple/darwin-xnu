/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
#include <debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <mach/ppc/vm_param.h>
#include <assym.s>
#include <sys/errno.h>

#define INSTRUMENT 0

//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * void pmap_zero_page(vm_offset_t pa)
 *
 * Zero a page of physical memory.  This routine runs in 32 or 64-bit mode,
 * and handles 32 and 128-byte cache lines.
 */


		.align	5
		.globl	EXT(pmap_zero_page)

LEXT(pmap_zero_page)

        mflr	r12								// save return address
        bl		EXT(ml_set_physical_disabled)	// turn DR and EE off, SF on, get features in r10
        mtlr	r12								// restore return address
        andi.	r9,r10,pf32Byte+pf128Byte		// r9 <- cache line size

        subfic	r4,r9,PPC_PGBYTES				// r4 <- starting offset in page
		
		bt++	pf64Bitb,page0S4				// Go do the big guys...
		
		slwi	r3,r3,12						// get page address from page num
		b		page_zero_1						// Jump to line aligned loop...

        .align	5

		nop
		nop
		nop
		nop
		nop
		nop
		nop
		
page0S4:
		sldi	r3,r3,12						// get page address from page num

page_zero_1:									// loop zeroing cache lines
        sub.	r5,r4,r9						// more to go?
        dcbz128	r3,r4							// zero either 32 or 128 bytes
        sub		r4,r5,r9						// generate next offset
        dcbz128	r3,r5
        bne--	page_zero_1
        
        b		EXT(ml_restore)					// restore MSR and do the isync


//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/* void
 * phys_copy(src, dst, bytecount)
 *      addr64_t 	    src;
 *      addr64_t 	    dst;
 *      int             bytecount
 *
 * This routine will copy bytecount bytes from physical address src to physical
 * address dst.  It runs in 64-bit mode if necessary, but does not handle
 * overlap or make any attempt to be optimal.  Length must be a signed word.
 * Not performance critical.
 */


		.align	5
		.globl	EXT(phys_copy)

LEXT(phys_copy)

		rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
        mflr	r12								// get return address
		rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
		rlwinm	r4,r5,0,1,0					; Duplicate high half of long long paddr into top of reg
        bl		EXT(ml_set_physical_disabled)	// turn DR and EE off, SF on, get features in r10
		rlwimi	r4,r6,0,0,31				; Combine bottom of long long to full 64-bits
        mtlr	r12								// restore return address
        subic.	r5,r7,4							// a word to copy?
        b		phys_copy_2
        
		.align	5
         
phys_copy_1:									// loop copying words
        subic.	r5,r5,4							// more to go?
        lwz		r0,0(r3)
        addi	r3,r3,4
        stw		r0,0(r4)
        addi	r4,r4,4
phys_copy_2:
        bge		phys_copy_1
        addic.	r5,r5,4							// restore count
        ble		phys_copy_4						// no more
        
        										// Loop is aligned here
        
phys_copy_3:									// loop copying bytes
        subic.	r5,r5,1							// more to go?
        lbz		r0,0(r3)
        addi	r3,r3,1
        stb		r0,0(r4)
        addi	r4,r4,1
        bgt		phys_copy_3
phys_copy_4:        
        b		EXT(ml_restore)					// restore MSR and do the isync


//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/* void
 * pmap_copy_page(src, dst)
 *      ppnum_t     src;
 *      ppnum_t     dst;
 *
 * This routine will copy the physical page src to physical page dst
 * 
 * This routine assumes that the src and dst are page numbers and that the
 * destination is cached.  It runs on 32 and 64 bit processors, with and
 * without altivec, and with 32 and 128 byte cache lines.
 * We also must assume that no-one will be executing within the destination
 * page, and that this will be used for paging.  Because this
 * is a common routine, we have tuned loops for each processor class.
 *
 */
#define	kSFSize	(FM_SIZE+160)

ENTRY(pmap_copy_page, TAG_NO_FRAME_USED)

		lis		r2,hi16(MASK(MSR_VEC))			; Get the vector flag
        mflr	r0								// get return
 		ori		r2,r2,lo16(MASK(MSR_FP))		; Add the FP flag
		stw		r0,8(r1)						// save
        stwu	r1,-kSFSize(r1)					// set up a stack frame for VRs or FPRs
        mfmsr	r11								// save MSR at entry
        mfsprg	r10,2							// get feature flags
        andc	r11,r11,r2						// Clear out vec and fp
        ori		r2,r2,lo16(MASK(MSR_EE))		// Get EE on also
        andc	r2,r11,r2						// Clear out EE as well
        mtcrf	0x02,r10						// we need to test pf64Bit
        ori		r2,r2,MASK(MSR_FP)				// must enable FP for G3...
        mtcrf	0x80,r10						// we need to test pfAltivec too
        oris	r2,r2,hi16(MASK(MSR_VEC))		// enable altivec for G4 (ignored if G3)
        mtmsr	r2								// turn EE off, FP and VEC on
        isync
        bt++	pf64Bitb,pmap_copy_64			// skip if 64-bit processor (only they take hint)
 		slwi	r3,r3,12						// get page address from page num
		slwi	r4,r4,12						// get page address from page num
        rlwinm	r12,r2,0,MSR_DR_BIT+1,MSR_DR_BIT-1	// get ready to turn off DR
        bt		pfAltivecb,pmap_copy_g4			// altivec but not 64-bit means G4
        
        
        // G3 -- copy using FPRs
        
        stfd	f0,FM_SIZE+0(r1)				// save the 4 FPRs we use to copy
        stfd	f1,FM_SIZE+8(r1)
        li		r5,PPC_PGBYTES/32				// count of cache lines in a page
        stfd	f2,FM_SIZE+16(r1)
        mtctr	r5
        stfd	f3,FM_SIZE+24(r1)
        mtmsr	r12								// turn off DR after saving FPRs on stack
        isync
        
pmap_g3_copy_loop:								// loop over 32-byte cache lines
        dcbz	0,r4							// avoid read of dest line
        lfd		f0,0(r3)
        lfd		f1,8(r3)
        lfd		f2,16(r3)
        lfd		f3,24(r3)
        addi	r3,r3,32
        stfd	f0,0(r4)
        stfd	f1,8(r4)
        stfd	f2,16(r4)
        stfd	f3,24(r4)
        dcbst	0,r4							// flush dest line to RAM
        addi	r4,r4,32
        bdnz	pmap_g3_copy_loop
        
        sync									// wait for stores to take
        subi	r4,r4,PPC_PGBYTES				// restore ptr to destintation page
        li		r6,PPC_PGBYTES-32				// point to last line in page
pmap_g3_icache_flush:
        subic.	r5,r6,32						// more to go?
        icbi	r4,r6							// flush another line in icache
        subi	r6,r5,32						// get offset to next line
        icbi	r4,r5
        bne		pmap_g3_icache_flush
        
        sync
        mtmsr	r2								// turn DR back on
        isync
        lfd		f0,FM_SIZE+0(r1)				// restore the FPRs
        lfd		f1,FM_SIZE+8(r1)
        lfd		f2,FM_SIZE+16(r1)
        lfd		f3,FM_SIZE+24(r1)        
        
        b		pmap_g4_restore					// restore MSR and done

        
        // G4 -- copy using VRs

pmap_copy_g4:									// r2=(MSR-EE), r12=(r2-DR), r10=features, r11=old MSR
        la		r9,FM_SIZE+16(r1)				// place where we save VRs to r9
        li		r5,16							// load x-form offsets into r5-r9
        li		r6,32							// another offset
        stvx	v0,0,r9							// save some VRs so we can use to copy
        li		r7,48							// another offset
        stvx	v1,r5,r9
        li		r0,PPC_PGBYTES/64				// we loop over 64-byte chunks
        stvx	v2,r6,r9
        mtctr	r0
        li		r8,96							// get look-ahead for touch
        stvx	v3,r7,r9
        li		r9,128
        mtmsr	r12								// now we've saved VRs on stack, turn off DR
        isync									// wait for it to happen
        b		pmap_g4_copy_loop
        
        .align	5								// align inner loops
pmap_g4_copy_loop:								// loop over 64-byte chunks
        dcbt	r3,r8							// touch 3 lines ahead
        nop										// avoid a 17-word loop...
        dcbt	r3,r9							// touch 4 lines ahead
        nop										// more padding
        dcba	0,r4							// avoid pre-fetch of 1st dest line
        lvx		v0,0,r3							// offset 0
        lvx		v1,r5,r3						// offset 16
        lvx		v2,r6,r3						// offset 32
        lvx		v3,r7,r3						// offset 48
        addi	r3,r3,64
        dcba	r6,r4							// avoid pre-fetch of 2nd line
        stvx	v0,0,r4							// offset 0
        stvx	v1,r5,r4						// offset 16
        stvx	v2,r6,r4						// offset 32
        stvx	v3,r7,r4						// offset 48
        dcbf	0,r4							// push line 1
        dcbf	r6,r4							// and line 2
        addi	r4,r4,64
        bdnz	pmap_g4_copy_loop

        sync									// wait for stores to take
        subi	r4,r4,PPC_PGBYTES				// restore ptr to destintation page
        li		r8,PPC_PGBYTES-32				// point to last line in page
pmap_g4_icache_flush:
        subic.	r9,r8,32						// more to go?
        icbi	r4,r8							// flush from icache
        subi	r8,r9,32						// get offset to next line
        icbi	r4,r9
        bne		pmap_g4_icache_flush
        
        sync
        mtmsr	r2								// turn DR back on
        isync
        la		r9,FM_SIZE+16(r1)				// get base of VR save area
        lvx		v0,0,r9							// restore the VRs
        lvx		v1,r5,r9
        lvx		v2,r6,r9
        lvx		v3,r7,r9        
        
pmap_g4_restore:								// r11=MSR
        mtmsr	r11								// turn EE on, VEC and FR off
        isync									// wait for it to happen
        addi	r1,r1,kSFSize					// pop off our stack frame
        lwz		r0,8(r1)						// restore return address
        mtlr	r0
        blr
        
        
        // 64-bit/128-byte processor: copy using VRs
        
pmap_copy_64:									// r10=features, r11=old MSR
 		sldi	r3,r3,12						// get page address from page num
		sldi	r4,r4,12						// get page address from page num
		la		r9,FM_SIZE+16(r1)				// get base of VR save area
        li		r5,16							// load x-form offsets into r5-r9
        li		r6,32							// another offset
        bf		pfAltivecb,pmap_novmx_copy		// altivec suppressed...
        stvx	v0,0,r9							// save 8 VRs so we can copy wo bubbles
        stvx	v1,r5,r9
        li		r7,48							// another offset
        li		r0,PPC_PGBYTES/128				// we loop over 128-byte chunks
        stvx	v2,r6,r9
        stvx	v3,r7,r9
        addi	r9,r9,64						// advance base ptr so we can store another 4
        mtctr	r0
        li		r0,MASK(MSR_DR)					// get DR bit
        stvx	v4,0,r9
        stvx	v5,r5,r9
        andc	r12,r2,r0						// turn off DR bit
        li		r0,1							// get a 1 to slam into SF
        stvx	v6,r6,r9
        stvx	v7,r7,r9
        rldimi	r12,r0,63,MSR_SF_BIT			// set SF bit (bit 0)
        li		r8,-128							// offset so we can reach back one line
        mtmsrd	r12								// now we've saved VRs, turn DR off and SF on
        isync									// wait for it to happen
        dcbt128	0,r3,1							// start a forward stream
        b		pmap_64_copy_loop
        
        .align	5								// align inner loops
pmap_64_copy_loop:								// loop over 128-byte chunks
        dcbz128	0,r4							// avoid read of destination line
        lvx		v0,0,r3							// offset 0
        lvx		v1,r5,r3						// offset 16
        lvx		v2,r6,r3						// offset 32
        lvx		v3,r7,r3						// offset 48
        addi	r3,r3,64						// don't have enough GPRs so add 64 2x
        lvx		v4,0,r3							// offset 64
        lvx		v5,r5,r3						// offset 80
        lvx		v6,r6,r3						// offset 96
        lvx		v7,r7,r3						// offset 112
        addi	r3,r3,64
        stvx	v0,0,r4							// offset 0
        stvx	v1,r5,r4						// offset 16
        stvx	v2,r6,r4						// offset 32
        stvx	v3,r7,r4						// offset 48
        addi	r4,r4,64
        stvx	v4,0,r4							// offset 64
        stvx	v5,r5,r4						// offset 80
        stvx	v6,r6,r4						// offset 96
        stvx	v7,r7,r4						// offset 112
        addi	r4,r4,64
        dcbf	r8,r4							// flush the line we just wrote
        bdnz	pmap_64_copy_loop

        sync									// wait for stores to take
        subi	r4,r4,PPC_PGBYTES				// restore ptr to destintation page
        li		r8,PPC_PGBYTES-128				// point to last line in page
pmap_64_icache_flush:
        subic.	r9,r8,128						// more to go?
        icbi	r4,r8							// flush from icache
        subi	r8,r9,128						// get offset to next line
        icbi	r4,r9
        bne		pmap_64_icache_flush
        
        sync
        mtmsrd	r2								// turn DR back on, SF off
        isync
        la		r9,FM_SIZE+16(r1)				// get base address of VR save area on stack
        lvx		v0,0,r9							// restore the VRs
        lvx		v1,r5,r9
        lvx		v2,r6,r9
        lvx		v3,r7,r9
        addi	r9,r9,64        
        lvx		v4,0,r9
        lvx		v5,r5,r9
        lvx		v6,r6,r9
        lvx		v7,r7,r9

        b		pmap_g4_restore					// restore lower half of MSR and return

 //
 //		Copy on 64-bit without VMX
 //

pmap_novmx_copy:        
		li		r0,PPC_PGBYTES/128				// we loop over 128-byte chunks
		mtctr	r0
		li		r0,MASK(MSR_DR)					// get DR bit
		andc	r12,r2,r0						// turn off DR bit
		li		r0,1							// get a 1 to slam into SF
		rldimi	r12,r0,63,MSR_SF_BIT			// set SF bit (bit 0)
		mtmsrd	r12								// now we've saved VRs, turn DR off and SF on
		isync									// wait for it to happen
		dcbt128	0,r3,1							// start a forward stream 
       
pmap_novmx_copy_loop:							// loop over 128-byte cache lines
        dcbz128	0,r4							// avoid read of dest line
        
        ld		r0,0(r3)						// Load half a line
        ld		r12,8(r3)
        ld		r5,16(r3)
        ld		r6,24(r3)
        ld		r7,32(r3)
        ld		r8,40(r3)
        ld		r9,48(r3)
        ld		r10,56(r3)
        
        std		r0,0(r4)						// Store half a line
        std		r12,8(r4)
        std		r5,16(r4)
        std		r6,24(r4)
        std		r7,32(r4)
        std		r8,40(r4)
        std		r9,48(r4)
        std		r10,56(r4)
        
        ld		r0,64(r3)						// Load half a line
        ld		r12,72(r3)
        ld		r5,80(r3)
        ld		r6,88(r3)
        ld		r7,96(r3)
        ld		r8,104(r3)
        ld		r9,112(r3)
        ld		r10,120(r3)
        
        addi	r3,r3,128
 
        std		r0,64(r4)						// Store half a line
        std		r12,72(r4)
        std		r5,80(r4)
        std		r6,88(r4)
        std		r7,96(r4)
        std		r8,104(r4)
        std		r9,112(r4)
        std		r10,120(r4)
        
        dcbf	0,r4							// flush the line we just wrote
		addi	r4,r4,128
        bdnz	pmap_novmx_copy_loop

        sync									// wait for stores to take
        subi	r4,r4,PPC_PGBYTES				// restore ptr to destintation page
        li		r8,PPC_PGBYTES-128				// point to last line in page

pmap_novmx_icache_flush:
        subic.	r9,r8,128						// more to go?
        icbi	r4,r8							// flush from icache
        subi	r8,r9,128						// get offset to next line
        icbi	r4,r9
        bne		pmap_novmx_icache_flush
        
        sync
        mtmsrd	r2								// turn DR back on, SF off
        isync

        b		pmap_g4_restore					// restore lower half of MSR and return



//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>	
		
// Stack frame format used by copyin, copyout, copyinstr and copyoutstr.
// These routines all run both on 32 and 64-bit machines, though because they are called
// by the BSD kernel they are always in 32-bit mode when entered.  The mapped ptr returned
// by MapUserMemoryWindow will be 64 bits however on 64-bit machines.  Beware to avoid
// using compare instructions on this ptr.  This mapped ptr is kept globally in r31, so there
// is no need to store or load it, which are mode-dependent operations since it could be
// 32 or 64 bits.

#define	kkFrameSize	(FM_SIZE+32)

#define	kkBufSize	(FM_SIZE+0)
#define	kkCR3		(FM_SIZE+4)
#define	kkSource	(FM_SIZE+8)
#define	kkDest		(FM_SIZE+12)
#define	kkCountPtr	(FM_SIZE+16)
#define	kkR31Save	(FM_SIZE+20)
#define	kkThrErrJmp	(FM_SIZE+24)
 
 
// nonvolatile CR bits we use as flags in cr3

#define	kk64bit		12
#define	kkNull		13
#define	kkIn		14
#define	kkString	15
#define	kkZero		15


//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * int
 * copyoutstr(src, dst, maxcount, count)
 *	vm_offset_t	src;        // r3
 *	addr64_t	dst;        // r4 and r5
 *	vm_size_t	maxcount;   // r6
 *	vm_size_t*	count;      // r7
 *
 * Set *count to the number of bytes copied.
 */

ENTRY(copyoutstr, TAG_NO_FRAME_USED)
        mfcr	r2,0x10                         // save caller's cr3, which we use for flags
        mr      r10,r4                          // move high word of 64-bit user address to r10
        li		r0,0
        crset	kkString						// flag as a string op
        mr      r11,r5                          // move low word of 64-bit user address to r11
        stw		r0,0(r7)						// initialize #bytes moved
        crclr	kkIn							// flag as copyout
        b		copyJoin


//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * int
 * copyinstr(src, dst, maxcount, count)
 *	addr64_t	src;        // r3 and r4
 *	vm_offset_t	dst;        // r5
 *	vm_size_t	maxcount;   // r6
 *	vm_size_t*	count;      // r7
 *
 * Set *count to the number of bytes copied
 * If dst == NULL, don't copy, just count bytes.
 * Only currently called from klcopyinstr. 
 */

ENTRY(copyinstr, TAG_NO_FRAME_USED)
        mfcr	r2,0x10                         // save caller's cr3, which we use for flags
        cmplwi	r5,0							// dst==NULL?
        mr      r10,r3                          // move high word of 64-bit user address to r10
        li		r0,0
        crset	kkString						// flag as a string op
        mr      r11,r4                          // move low word of 64-bit user address to r11
        crmove	kkNull,cr0_eq					// remember if (dst==NULL)
        stw		r0,0(r7)						// initialize #bytes moved
        crset	kkIn							// flag as copyin (rather than copyout)
        b		copyJoin1						// skip over the "crclr kkNull"


//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * int
 * copyout(src, dst, count)
 *	vm_offset_t	src;        // r3
 *	addr64_t	dst;        // r4 and r5
 *	size_t		count;      // r6
 */

			.align	5
			.globl	EXT(copyout)
			.globl	EXT(copyoutmsg)

LEXT(copyout)
LEXT(copyoutmsg)

#if INSTRUMENT
        mfspr	r12,pmc1						; INSTRUMENT - saveinstr[12] - Take stamp at copyout
        stw		r12,0x6100+(12*16)+0x0(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc2						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(12*16)+0x4(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc3						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(12*16)+0x8(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc4						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(12*16)+0xC(0)		; INSTRUMENT - Save it
#endif			
        mfcr	r2,0x10                         // save caller's cr3, which we use for flags
        mr      r10,r4                          // move high word of 64-bit user address to r10
        crclr	kkString						// not a string version
        mr      r11,r5                          // move low word of 64-bit user address to r11
        crclr	kkIn							// flag as copyout
        b		copyJoin
        

//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * int
 * copyin(src, dst, count)
 *	addr64_t	src;        // r3 and r4
 *	vm_offset_t	dst;        // r5
 *	size_t		count;      // r6
 */


			.align	5
			.globl	EXT(copyin)
			.globl	EXT(copyinmsg)

LEXT(copyin)
LEXT(copyinmsg)

        mfcr	r2,0x10                         // save caller's cr3, which we use for flags
        mr      r10,r3                          // move high word of 64-bit user address to r10
        crclr	kkString						// not a string version
        mr      r11,r4                          // move low word of 64-bit user address to r11
        crset	kkIn							// flag as copyin
        
        
// Common code to handle setup for all the copy variants:
//		r2 = caller's cr3
//      r3 = source if copyout
//      r5 = dest if copyin
//      r6 = buffer length or count
//      r7 = count output ptr (if kkString set)
//	   r10 = high word of 64-bit user-space address (source if copyin, dest if copyout)
//	   r11 = low word of 64-bit user-space address
//     cr3 = kkIn, kkString, kkNull flags

copyJoin:
        crclr	kkNull							// (dst==NULL) convention not used with this call
copyJoin1:										// enter from copyinstr with kkNull set
		mflr	r0								// get return address
        cmplwi	r6,0							// buffer length 0?
        lis		r9,0x1000						// r9 <- 0x10000000 (256MB)
		stw		r0,FM_LR_SAVE(r1)				// save return
        cmplw	cr1,r6,r9						// buffer length > 256MB ?
        mfsprg	r8,2							// get the features
        beq--	copyinout_0						// 0 length is degenerate case
		stwu	r1,-kkFrameSize(r1)				// set up stack frame
        stw		r2,kkCR3(r1)                    // save caller's cr3, which we use for flags
        mtcrf	0x02,r8							// move pf64Bit to cr6
        stw		r3,kkSource(r1)					// save args across MapUserMemoryWindow
        stw		r5,kkDest(r1)
        stw		r6,kkBufSize(r1)
        crmove	kk64bit,pf64Bitb				// remember if this is a 64-bit processor
        stw		r7,kkCountPtr(r1)
        stw		r31,kkR31Save(r1)				// we use r31 globally for mapped user ptr
        li		r31,0							// no mapped ptr yet
        
        
// Handle buffer length > 256MB.  This is an error (ENAMETOOLONG) on copyin and copyout.
// The string ops are passed -1 lengths by some BSD callers, so for them we silently clamp
// the buffer length to 256MB.  This isn't an issue if the string is less than 256MB
// (as most are!), but if they are >256MB we eventually return ENAMETOOLONG.  This restriction
// is due to MapUserMemoryWindow; we don't want to consume more than two segments for
// the mapping. 

        ble++	cr1,copyin0						// skip if buffer length <= 256MB
        bf		kkString,copyinout_too_big		// error if not string op
        mr		r6,r9							// silently clamp buffer length to 256MB
        stw		r9,kkBufSize(r1)				// update saved copy too


// Set up thread_recover in case we hit an illegal address.

copyin0:
		mfsprg  r8,1							// Get the current thread 
		lis		r2,hi16(copyinout_error)
		ori		r2,r2,lo16(copyinout_error)
		lwz		r4,THREAD_RECOVER(r8)
		lwz		r3,ACT_VMMAP(r8)				// r3 <- vm_map virtual address
		stw		r2,THREAD_RECOVER(r8)
		stw		r4,kkThrErrJmp(r1)


// Map user segment into kernel map, turn on 64-bit mode.  At this point:
//		r3 = vm map
//		r6 = buffer length
// r10/r11 = 64-bit user-space ptr (source if copyin, dest if copyout)
//
// When we call MapUserMemoryWindow, we pass:
//      r3 = vm map ptr
//   r4/r5 = 64-bit user space address as an addr64_t
        
        mr      r4,r10                          // copy user ptr into r4/r5
        mr      r5,r11
#if INSTRUMENT
        mfspr	r12,pmc1						; INSTRUMENT - saveinstr[13] - Take stamp before mapuseraddressspace
        stw		r12,0x6100+(13*16)+0x0(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc2						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(13*16)+0x4(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc3						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(13*16)+0x8(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc4						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(13*16)+0xC(0)		; INSTRUMENT - Save it
#endif			
        bl		EXT(MapUserMemoryWindow)		// get r3/r4 <- 64-bit address in kernel map of user operand
#if INSTRUMENT
        mfspr	r12,pmc1						; INSTRUMENT - saveinstr[14] - Take stamp after mapuseraddressspace
        stw		r12,0x6100+(14*16)+0x0(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc2						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(14*16)+0x4(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc3						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(14*16)+0x8(0)		; INSTRUMENT - Save it
        mfspr	r12,pmc4						; INSTRUMENT - Get stamp
        stw		r12,0x6100+(14*16)+0xC(0)		; INSTRUMENT - Save it
#endif			
        mr		r31,r4							// r31 <- mapped ptr into user space (may be 64-bit)
        bf--	kk64bit,copyin1					// skip if a 32-bit processor
 
 		rldimi	r31,r3,32,0						// slam high-order bits into mapped ptr
        mfmsr	r4								// if 64-bit, turn on SF so we can use returned ptr
        li		r0,1
        rldimi	r4,r0,63,MSR_SF_BIT				// light bit 0
        mtmsrd	r4								// turn on 64-bit mode
        isync									// wait for mode to change
        
        
// Load r3-r5, substituting mapped ptr as appropriate.

copyin1:
        lwz		r5,kkBufSize(r1)				// restore length to copy
        bf		kkIn,copyin2					// skip if copyout
        lwz		r4,kkDest(r1)					// copyin: dest is kernel ptr
        mr		r3,r31							// source is mapped ptr
        b		copyin3
copyin2:										// handle copyout
        lwz		r3,kkSource(r1)					// source is kernel buffer (r3 at entry)
        mr		r4,r31							// dest is mapped ptr into user space
        
        
// Finally, all set up to copy:
//		r3 = source ptr (mapped if copyin)
//		r4 = dest ptr (mapped if copyout)
//		r5 = length
//	   r31 = mapped ptr returned by MapUserMemoryWindow
//	   cr3 = kkIn, kkString, kk64bit, and kkNull flags

copyin3:
        bt		kkString,copyString				// handle copyinstr and copyoutstr
        bl		EXT(bcopy)						// copyin and copyout: let bcopy do the work
        li		r3,0							// return success
        
        
// Main exit point for copyin, copyout, copyinstr, and copyoutstr.  Also reached
// from error recovery if we get a DSI accessing user space.  Clear recovery ptr, 
// and pop off frame.
//		r3 = 0, EFAULT, or ENAMETOOLONG

copyinx: 
        lwz		r2,kkCR3(r1)                    // get callers cr3
		mfsprg  r6,1							// Get the current thread 
        bf--	kk64bit,copyinx1				// skip if 32-bit processor
        mfmsr	r12
        rldicl	r12,r12,0,MSR_SF_BIT+1			// if 64-bit processor, turn 64-bit mode off
        mtmsrd	r12								// turn SF off
        isync									// wait for the mode to change
copyinx1:
		lwz		r0,FM_LR_SAVE+kkFrameSize(r1)   // get return address
        lwz		r31,kkR31Save(r1)				// restore callers r31
        lwz		r4,kkThrErrJmp(r1)				// load saved thread recover
        addi	r1,r1,kkFrameSize				// pop off our stack frame
		mtlr	r0
		stw		r4,THREAD_RECOVER(r6)			// restore thread recover
        mtcrf	0x10,r2							// restore cr3
		blr


/* We get here via the exception handler if an illegal
 * user memory reference was made.  This error handler is used by
 * copyin, copyout, copyinstr, and copyoutstr.  Registers are as
 * they were at point of fault, so for example cr3 flags are valid.
 */

copyinout_error:
        li		r3,EFAULT						// return error
        b		copyinx

copyinout_0:									// degenerate case: 0-length copy
		mtcrf	0x10,r2							// restore cr3
        li		r3,0							// return success
        blr
        
copyinout_too_big:								// degenerate case
        mtcrf	0x10,r2							// restore cr3
        lwz		r1,0(r1)						// pop off stack frame
        li		r3,ENAMETOOLONG
        blr
        

//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
// Handle copyinstr and copyoutstr.  At this point the stack frame is set up,
// the recovery ptr is set, the user's buffer is mapped, we're in 64-bit mode
// if necessary, and:
//		r3 = source ptr, mapped if copyinstr
//		r4 = dest ptr, mapped if copyoutstr
//		r5 = buffer length
//	   r31 = mapped ptr returned by MapUserMemoryWindow
//     cr3 = kkIn, kkString, kkNull, and kk64bit flags
// We do word copies unless the buffer is very short, then use a byte copy loop
// for the leftovers if necessary.  The crossover at which the word loop becomes
// faster is about seven bytes, counting the zero.
//
// We first must word-align the source ptr, in order to avoid taking a spurious
// page fault.

copyString:
        cmplwi	cr1,r5,15						// is buffer very short?
        mr      r12,r3                          // remember ptr to 1st source byte
        mtctr	r5								// assuming short, set up loop count for bytes
        blt--   cr1,copyinstr8					// too short for word loop
        rlwinm  r2,r3,0,0x3                     // get byte offset of 1st byte within word
        rlwinm  r9,r3,3,0x18                    // get bit offset of 1st byte within word
        li      r7,-1
        sub     r3,r3,r2                        // word-align source address
        add     r6,r5,r2                        // get length starting at byte 0 in word
        srw     r7,r7,r9                        // get mask for bytes in first word
        srwi	r0,r6,2							// get #words in buffer
        lwz     r5,0(r3)                        // get aligned word with first source byte
        lis		r10,hi16(0xFEFEFEFF)			// load magic constants into r10 and r11
        lis		r11,hi16(0x80808080)
        mtctr	r0								// set up word loop count
        addi    r3,r3,4                         // advance past the source word
        ori		r10,r10,lo16(0xFEFEFEFF)
        ori		r11,r11,lo16(0x80808080)
        orc     r8,r5,r7                        // map bytes preceeding first source byte into 0xFF
        bt--	kkNull,copyinstr5enter          // enter loop that just counts
        
// Special case 1st word, which has been 0xFF filled on left.  Note that we use
// "and.", even though we execute both in 32 and 64-bit mode.  This is OK.

        slw     r5,r5,r9                        // left justify payload bytes
        add		r9,r10,r8						// r9 =  data + 0xFEFEFEFF
        andc	r7,r11,r8						// r7 = ~data & 0x80808080
		subfic  r0,r2,4							// get r0 <- #payload bytes in 1st word
        and.    r7,r9,r7						// if r7==0, then all bytes in r8 are nonzero
        stw     r5,0(r4)                        // copy payload bytes to dest buffer
        add		r4,r4,r0						// then point to next byte in dest buffer
        bdnzt   cr0_eq,copyinstr6               // use loop that copies if 0 not found
        
        b		copyinstr7                      // 0 found (buffer can't be full)
        
        
// Word loop(s).  They do a word-parallel search for 0s, using the following
// inobvious but very efficient test:
//		y =  data + 0xFEFEFEFF
//		z = ~data & 0x80808080
// If (y & z)==0, then all bytes in dataword are nonzero.  There are two copies
// of this loop, one that just counts and another that copies.
//		r3 = ptr to next word of source (word aligned)
//		r4 = ptr to next byte in buffer
//      r6 = original buffer length (adjusted to be word origin)
//     r10 = 0xFEFEFEFE
//     r11 = 0x80808080
//     r12 = ptr to 1st source byte (used to determine string length)

        .align	5								// align inner loops for speed
copyinstr5:										// version that counts but does not copy
        lwz     r8,0(r3)						// get next word of source
        addi    r3,r3,4                         // advance past it
copyinstr5enter:
        add		r9,r10,r8						// r9 =  data + 0xFEFEFEFF
        andc	r7,r11,r8						// r7 = ~data & 0x80808080
        and.    r7,r9,r7                        // r7 = r9 & r7 ("." ok even in 64-bit mode)
        bdnzt   cr0_eq,copyinstr5				// if r7==0, then all bytes in r8 are nonzero

        b		copyinstr7

        .align	5								// align inner loops for speed
copyinstr6:										// version that counts and copies
        lwz     r8,0(r3)						// get next word of source
        addi    r3,r3,4                         // advance past it
        addi	r4,r4,4							// increment dest ptr while we wait for data
        add		r9,r10,r8						// r9 =  data + 0xFEFEFEFF
        andc	r7,r11,r8						// r7 = ~data & 0x80808080
        and.    r7,r9,r7                        // r7 = r9 & r7 ("." ok even in 64-bit mode)
        stw		r8,-4(r4)						// pack all 4 bytes into buffer
        bdnzt	cr0_eq,copyinstr6				// if r7==0, then all bytes are nonzero


// Either 0 found or buffer filled.  The above algorithm has mapped nonzero bytes to 0
// and 0 bytes to 0x80 with one exception: 0x01 bytes preceeding the first 0 are also
// mapped to 0x80.  We must mask out these false hits before searching for an 0x80 byte.
//		r3 = word aligned ptr to next word of source (ie, r8==mem(r3-4))
//      r6 = original buffer length (adjusted to be word origin)
//      r7 = computed vector of 0x00 and 0x80 bytes
//      r8 = original source word, coming from -4(r3), possibly padded with 0xFFs on left if 1st word
//     r12 = ptr to 1st source byte (used to determine string length)
//     cr0 = beq set iff 0 not found

copyinstr7:
        rlwinm	r2,r8,7,0,31					// move 0x01 bits to 0x80 position
		rlwinm  r6,r6,0,0x3						// mask down to partial byte count in last word
        andc	r7,r7,r2						// turn off false hits from 0x0100 worst case
        crnot	kkZero,cr0_eq					// 0 found iff cr0_eq is off
        srwi    r7,r7,8                         // we want to count the 0 as a byte xferred
		cmpwi   r6,0							// any bytes left over in last word?
        cntlzw	r7,r7							// now we can find the 0 byte (ie, the 0x80)
        subi    r3,r3,4                         // back up r3 to point to 1st byte in r8
        srwi	r7,r7,3							// convert 8,16,24,32 to 1,2,3,4
        add     r3,r3,r7                        // now r3 points one past 0 byte, or at 1st byte not xferred
        bt++	kkZero,copyinstr10				// 0 found, so done
        
        beq		copyinstr10						// r6==0, so buffer truly full
        mtctr	r6								// 0 not found, loop over r6 bytes
        b		copyinstr8						// enter byte loop for last 1-3 leftover bytes
        

// Byte loop.  This is used for very small buffers and for the odd bytes left over
// after searching and copying words at a time.
//      r3 = ptr to next byte of source
//      r4 = ptr to next dest byte
//     r12 = ptr to first byte of source
//     ctr = count of bytes to check
    
        .align	5								// align inner loops for speed
copyinstr8:										// loop over bytes of source
        lbz		r0,0(r3)						// get next byte of source
        addi	r3,r3,1
        addi	r4,r4,1							// increment dest addr whether we store or not
        cmpwi	r0,0							// the 0?
        bt--	kkNull,copyinstr9				// don't store if copyinstr with NULL ptr
        stb		r0,-1(r4)
copyinstr9:
        bdnzf	cr0_eq,copyinstr8				// loop if byte not 0 and more room in buffer
        
        crmove	kkZero,cr0_eq					// remember if 0 found or buffer filled

        
// Buffer filled or 0 found.  Unwind and return.
//      r3 = ptr to 1st source byte not transferred
//     r12 = ptr to 1st source byte
//     r31 = mapped ptr returned by MapUserMemoryWindow
//     cr3 = kkZero set iff 0 found

copyinstr10:
        lwz		r9,kkCountPtr(r1)				// get ptr to place to store count of bytes moved
        sub     r2,r3,r12                       // compute #bytes copied (including the 0)
        li		r3,0							// assume success return status
        stw		r2,0(r9)						// store #bytes moved
        bt++	kkZero,copyinx					// we did find the 0 so return 0
        li		r3,ENAMETOOLONG					// buffer filled
        b		copyinx							// join main exit routine

//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * int
 * copypv(source, sink, size, which)
 *	addr64_t	src;        // r3 and r4
 *	addr64_t	dst;        // r5 and r6
 *	size_t		size;		// r7
 *	int			which;		// r8
 *
 * Operand size bytes are copied from operand src into operand dst. The source and
 * destination operand addresses are given as addr64_t, and may designate starting
 * locations in physical or virtual memory in any combination except where both are
 * virtual. Virtual memory locations may be in either the kernel or the current thread's
 * address space. Operand size may be up to 256MB.
 *
 * Operation is controlled by operand which, which offers these options:
 *		cppvPsrc : source operand is (1) physical or (0) virtual
 *		cppvPsnk : destination operand is (1) physical or (0) virtual
 *		cppvKmap : virtual operand is in (1) kernel or (0) current thread
 *		cppvFsnk : (1) flush destination before and after transfer
 *		cppvFsrc : (1) flush source before and after transfer
 *		cppvNoModSnk : (1) don't set source operand's changed bit(s)
 *		cppvNoRefSrc : (1) don't set destination operand's referenced bit(s)
 *
 * Implementation is now split into this new 64-bit path and the old path, hw_copypv_32().
 * This section describes the operation of the new 64-bit path.
 *
 * The 64-bit path utilizes the more capacious 64-bit kernel address space to create a
 * window in the kernel address space into all of physical RAM plus the I/O hole. Since
 * the window's mappings specify the proper access policies for the underlying memory,
 * the new path does not have to flush caches to avoid a cache paradox, so cppvFsnk
 * and cppvFsrc are ignored. Physical operand adresses are relocated into the physical
 * memory window, and are accessed with data relocation on. Virtual addresses are either
 * within the kernel, or are mapped into the kernel address space through the user memory
 * window. Because accesses to a virtual operand are performed with data relocation on,
 * the new path does not have to translate the address, disable/enable interrupts, lock
 * the mapping, or update referenced and changed bits.
 *
 * The IBM 970 (a.k.a. G5) processor treats real-mode accesses as guarded, so there is
 * a substantial performance penalty for copypv operating in real mode. Utilizing the
 * new 64-bit path, transfer performance increases >100% on the G5.
 *
 * The attentive reader may notice that mtmsrd ops are not followed by isync ops as 
 * might be expected. The 970 follows PowerPC architecture version 2.01, which defines
 * mtmsrd with L=0 as a context synchronizing op, so a following isync is no longer
 * required.
 *
 * To keep things exciting, we develop 64-bit values in non-volatiles, but we also need
 * to call 32-bit functions, which would lead to the high-order 32 bits of our values
 * getting clobbered unless we do something special. So, we preserve our 64-bit non-volatiles
 * in our own stack frame across calls to 32-bit functions.
 *		
 */

// Map operand which bits into non-volatile CR2 and CR3 bits.
#define whichAlign	((3+1)*4)
#define whichMask	0x007F0000
#define pvPsnk		(cppvPsnkb - whichAlign)
#define pvPsrc		(cppvPsrcb - whichAlign)
#define pvFsnk		(cppvFsnkb - whichAlign)
#define pvFsrc		(cppvFsrcb - whichAlign)
#define pvNoModSnk	(cppvNoModSnkb - whichAlign)
#define pvNoRefSrc	(cppvNoRefSrcb - whichAlign)
#define pvKmap		(cppvKmapb - whichAlign)
#define pvNoCache	cr2_lt

		.align	5
		.globl	EXT(copypv)

LEXT(copypv)
        mfsprg	r10,2							// get feature flags
        mtcrf	0x02,r10						// we need to test pf64Bit
        bt++	pf64Bitb,copypv_64				// skip if 64-bit processor (only they take hint)
        
        b		EXT(hw_copypv_32)				// carry on with 32-bit copypv

// Push a 32-bit ABI-compliant stack frame and preserve all non-volatiles that we'll clobber.        
copypv_64:
		mfsprg	r9,1							// get current thread
		stwu	r1,-(FM_ALIGN((31-26+11)*4)+FM_SIZE)(r1)
												// allocate stack frame and link it
		mflr	r0								// get return address
		mfcr	r10								// get cr2 and cr3
		lwz		r12,THREAD_RECOVER(r9)			// get error callback
		stw		r26,FM_ARG0+0x00(r1)			// save non-volatile r26
		stw		r27,FM_ARG0+0x04(r1)			// save non-volatile r27
		stw		r28,FM_ARG0+0x08(r1)			// save non-volatile r28
		stw		r29,FM_ARG0+0x0C(r1)			// save non-volatile r29
		stw		r30,FM_ARG0+0x10(r1)			// save non-volatile r30
		stw		r31,FM_ARG0+0x14(r1)			// save non-volatile r31
		stw		r12,FM_ARG0+0x20(r1)			// save error callback
		stw		r0,(FM_ALIGN((31-26+11)*4)+FM_SIZE+FM_LR_SAVE)(r1)
												// save return address
		stw		r10,(FM_ALIGN((31-26+11)*4)+FM_SIZE+FM_CR_SAVE)(r1)
												// save non-volatile cr2 and cr3

// Non-volatile register usage in this routine is:
//	r26: saved msr image
//	r27: current pmap_t / virtual source address
//	r28: destination virtual address
//	r29: source address
//	r30: destination address
//	r31: byte count to copy
//	cr2/3: parameter 'which' bits

		rlwinm	r8,r8,whichAlign,whichMask		// align and mask which bits
		mr		r31,r7							// copy size to somewhere non-volatile
		mtcrf	0x20,r8							// insert which bits into cr2 and cr3
		mtcrf	0x10,r8							// insert which bits into cr2 and cr3
		rlwinm	r29,r3,0,1,0					// form source address high-order bits
		rlwinm	r30,r5,0,1,0					// form destination address high-order bits
		rlwimi	r29,r4,0,0,31					// form source address low-order bits
		rlwimi	r30,r6,0,0,31					// form destination address low-order bits
		crand	cr7_lt,pvPsnk,pvPsrc			// are both operand addresses physical?
		cntlzw	r0,r31							// count leading zeroes in byte count
		cror	cr7_eq,pvPsnk,pvPsrc			// cr7_eq <- source or destination is physical
		bf--	cr7_eq,copypv_einval			// both operands may not be virtual
		cmplwi	r0,4							// byte count greater than or equal 256M (2**28)?
		blt--	copypv_einval					// byte count too big, give EINVAL
		cmplwi	r31,0							// byte count zero?
		beq--	copypv_zero						// early out
		bt		cr7_lt,copypv_phys				// both operand addresses are physical
		mr		r28,r30							// assume destination is virtual
		bf		pvPsnk,copypv_dv				// is destination virtual?
		mr		r28,r29							// no, so source must be virtual
copypv_dv:
		lis		r27,ha16(EXT(kernel_pmap))		// get kernel's pmap_t *, high-order
		lwz		r27,lo16(EXT(kernel_pmap))(r27) // get kernel's pmap_t
		bt		pvKmap,copypv_kern				// virtual address in kernel map?
		lwz		r3,ACT_VMMAP(r9)				// get user's vm_map *
		rldicl	r4,r28,32,32					// r4, r5 <- addr64_t virtual address 
		rldicl	r5,r28,0,32
		std		r29,FM_ARG0+0x30(r1)			// preserve 64-bit r29 across 32-bit call
		std		r30,FM_ARG0+0x38(r1)			// preserve 64-bit r30 across 32-bit call
		bl		EXT(MapUserMemoryWindow)		// map slice of user space into kernel space
		ld		r29,FM_ARG0+0x30(r1)			// restore 64-bit r29
		ld		r30,FM_ARG0+0x38(r1)			// restore 64-bit r30
		rlwinm	r28,r3,0,1,0					// convert relocated addr64_t virtual address 
		rlwimi	r28,r4,0,0,31					//  into a single 64-bit scalar
copypv_kern:

// Since we'll be accessing the virtual operand with data-relocation on, we won't need to 
// update the referenced and changed bits manually after the copy. So, force the appropriate
// flag bit on for the virtual operand.
		crorc	pvNoModSnk,pvNoModSnk,pvPsnk	// for virtual dest, let hardware do ref/chg bits
		crorc	pvNoRefSrc,pvNoRefSrc,pvPsrc	// for virtual source, let hardware do ref bit
		
// We'll be finding a mapping and looking at, so we need to disable 'rupts.
		lis		r0,hi16(MASK(MSR_VEC))			// get vector mask
		ori		r0,r0,lo16(MASK(MSR_FP))		// insert fp mask
		mfmsr	r26								// save current msr
		andc	r26,r26,r0						// turn off VEC and FP in saved copy
		ori		r0,r0,lo16(MASK(MSR_EE))		// add EE to our mask
		andc	r0,r26,r0						// disable EE in our new msr image
		mtmsrd	r0								// introduce new msr image

// We're now holding the virtual operand's pmap_t in r27 and its virtual address in r28. We now
// try to find a mapping corresponding to this address in order to determine whether the address
// is cacheable. If we don't find a mapping, we can safely assume that the operand is cacheable
// (a non-cacheable operand must be a block mapping, which will always exist); otherwise, we
// examine the mapping's caching-inhibited bit.
		mr		r3,r27							// r3 <- pmap_t pmap
		rldicl	r4,r28,32,32					// r4, r5 <- addr64_t va
		rldicl	r5,r28,0,32
		la		r6,FM_ARG0+0x18(r1)				// r6 <- addr64_t *nextva
		li		r7,1							// r7 <- int full, search nested mappings
		std		r26,FM_ARG0+0x28(r1)			// preserve 64-bit r26 across 32-bit calls
		std		r28,FM_ARG0+0x30(r1)			// preserve 64-bit r28 across 32-bit calls
		std		r29,FM_ARG0+0x38(r1)			// preserve 64-bit r29 across 32-bit calls
		std		r30,FM_ARG0+0x40(r1)			// preserve 64-bit r30 across 32-bit calls
		bl		EXT(mapping_find)				// find mapping for virtual operand
		mr.		r3,r3							// did we find it?
		beq		copypv_nomapping				// nope, so we'll assume it's cacheable
		lwz		r4,mpVAddr+4(r3)				// get low half of virtual addr for hw flags
		rlwinm.	r4,r4,0,mpIb-32,mpIb-32			// caching-inhibited bit set?
		crnot	pvNoCache,cr0_eq				// if it is, use bcopy_nc
		bl		EXT(mapping_drop_busy)			// drop busy on the mapping
copypv_nomapping:
		ld		r26,FM_ARG0+0x28(r1)			// restore 64-bit r26
		ld		r28,FM_ARG0+0x30(r1)			// restore 64-bit r28
		ld		r29,FM_ARG0+0x38(r1)			// restore 64-bit r29
		ld		r30,FM_ARG0+0x40(r1)			// restore 64-bit r30
		mtmsrd	r26								// restore msr to it's previous state

// Set both the source and destination virtual addresses to the virtual operand's address --
// we'll overlay one of them with the physical operand's address.
		mr		r27,r28							// make virtual operand BOTH source AND destination

// Now we're ready to relocate the physical operand address(es) into the physical memory window.
// Recall that we've mapped physical memory (including the I/O hole) into the kernel's address
// space somewhere at or over the 2**32 line. If one or both of the operands are in the I/O hole,
// we'll set the pvNoCache flag, forcing use of non-caching bcopy_nc() to do the copy.
copypv_phys:
		ld		r6,lgPMWvaddr(0)				// get physical memory window virtual address
		bf		pvPsnk,copypv_dstvirt			// is destination address virtual?
		cntlzd	r4,r30							// count leading zeros in destination address
		cmplwi	r4,32							// if it's 32, then it's in the I/O hole (2**30 to 2**31-1)
		cror	pvNoCache,cr0_eq,pvNoCache		// use bcopy_nc for I/O hole locations		
		add		r28,r30,r6						// relocate physical destination into physical window
copypv_dstvirt:
		bf		pvPsrc,copypv_srcvirt			// is source address virtual?
		cntlzd	r4,r29							// count leading zeros in source address
		cmplwi	r4,32							// if it's 32, then it's in the I/O hole (2**30 to 2**31-1)
		cror	pvNoCache,cr0_eq,pvNoCache		// use bcopy_nc for I/O hole locations		
		add		r27,r29,r6						// relocate physical source into physical window
copypv_srcvirt:

// Once the copy is under way (bcopy or bcopy_nc), we will want to get control if anything
// funny happens during the copy. So, we set a pointer to our error handler in the per-thread
// control block.
		mfsprg	r8,1							// get current threads stuff
		lis		r3,hi16(copypv_error)			// get our error callback's address, high
		ori		r3,r3,lo16(copypv_error)		// get our error callback's address, low
		stw		r3,THREAD_RECOVER(r8)			// set our error callback
		
// Since our physical operand(s) are relocated at or above the 2**32 line, we must enter
// 64-bit mode.
		li		r0,1							// get a handy one bit
		mfmsr	r3								// get current msr
		rldimi	r3,r0,63,MSR_SF_BIT				// set SF bit on in our msr copy
		mtmsrd	r3								// enter 64-bit mode

// If requested, flush data cache
// Note that we don't flush, the code is being saved "just in case".
#if 0
		bf		pvFsrc,copypv_nfs				// do we flush the source?
		rldicl	r3,r27,32,32					// r3, r4 <- addr64_t source virtual address
		rldicl	r4,r27,0,32
		mr		r5,r31							// r5 <- count (in bytes)
		li		r6,0							// r6 <- boolean phys (false, not physical)
		bl		EXT(flush_dcache)				// flush the source operand
copypv_nfs:
		bf		pvFsnk,copypv_nfdx				// do we flush the destination?
		rldicl	r3,r28,32,32					// r3, r4 <- addr64_t destination virtual address
		rldicl	r4,r28,0,32
		mr		r5,r31							// r5 <- count (in bytes)
		li		r6,0							// r6 <- boolean phys (false, not physical)
		bl		EXT(flush_dcache)				// flush the destination operand
copypv_nfdx:
#endif

// Call bcopy or bcopy_nc to perform the copy.
		mr		r3,r27							// r3 <- source virtual address
		mr		r4,r28							// r4 <- destination virtual address
		mr		r5,r31							// r5 <- bytes to copy
		bt		pvNoCache,copypv_nc				// take non-caching route
		bl		EXT(bcopy)						// call bcopy to do the copying
		b		copypv_copydone
copypv_nc:
		bl		EXT(bcopy_nc)					// call bcopy_nc to do the copying
copypv_copydone:

// If requested, flush data cache
// Note that we don't flush, the code is being saved "just in case".
#if 0
		bf		pvFsrc,copypv_nfsx				// do we flush the source?
		rldicl	r3,r27,32,32					// r3, r4 <- addr64_t source virtual address
		rldicl	r4,r27,0,32
		mr		r5,r31							// r5 <- count (in bytes)
		li		r6,0							// r6 <- boolean phys (false, not physical)
		bl		EXT(flush_dcache)				// flush the source operand
copypv_nfsx:
		bf		pvFsnk,copypv_nfd				// do we flush the destination?
		rldicl	r3,r28,32,32					// r3, r4 <- addr64_t destination virtual address
		rldicl	r4,r28,0,32
		mr		r5,r31							// r5 <- count (in bytes)
		li		r6,0							// r6 <- boolean phys (false, not physical)
		bl		EXT(flush_dcache)				// flush the destination operand
copypv_nfd:
#endif

// Leave 64-bit mode.
		mfmsr	r3								// get current msr
		rldicl	r3,r3,0,MSR_SF_BIT+1			// clear SF bit in our copy
		mtmsrd	r3								// leave 64-bit mode

// If requested, set ref/chg on source/dest physical operand(s). It is possible that copy is
// from/to a RAM disk situated outside of mapped physical RAM, so we check each page by calling
// mapping_phys_lookup() before we try to set its ref/chg bits; otherwise, we might panic.
// Note that this code is page-size sensitive, so it should probably be a part of our low-level
// code in hw_vm.s.
		bt		pvNoModSnk,copypv_nomod			// skip destination update if not requested
		std		r29,FM_ARG0+0x30(r1)			// preserve 64-bit r29 across 32-bit calls
		li		r26,1							// r26 <- 4K-page count						
		mr		r27,r31							// r27 <- byte count
		rlwinm	r3,r30,0,20,31					// does destination cross a page boundary?
		subfic	r3,r3,4096						//
		cmplw	r3,r27							// 
		blt		copypv_modnox					// skip if not crossing case
		subf	r27,r3,r27						// r27 <- byte count less initial fragment
		addi	r26,r26,1						// increment page count
copypv_modnox:
		srdi	r3,r27,12						// pages to update (not including crosser)
		add		r26,r26,r3						// add in crosser
		srdi	r27,r30,12						// r27 <- destination page number
copypv_modloop:
		mr		r3,r27							// r3 <- destination page number				
		la		r4,FM_ARG0+0x18(r1)				// r4 <- unsigned int *pindex
		bl		EXT(mapping_phys_lookup)		// see if page is really there
		mr.		r3,r3							// is it?
		beq--	copypv_modend					// nope, break out of modify loop
		mr		r3,r27							// r3 <- destination page number
		bl		EXT(mapping_set_mod)			// set page changed status
		subi	r26,r26,1						// decrement page count
		cmpwi	r26,0							// done yet?
		bgt		copypv_modloop					// nope, iterate
copypv_modend:
		ld		r29,FM_ARG0+0x30(r1)			// restore 64-bit r29
copypv_nomod:
		bt		pvNoRefSrc,copypv_done			// skip source update if not requested
copypv_debugref:
		li		r26,1							// r26 <- 4K-page count						
		mr		r27,r31							// r27 <- byte count
		rlwinm	r3,r29,0,20,31					// does source cross a page boundary?
		subfic	r3,r3,4096						//
		cmplw	r3,r27							// 
		blt		copypv_refnox					// skip if not crossing case
		subf	r27,r3,r27						// r27 <- byte count less initial fragment
		addi	r26,r26,1						// increment page count
copypv_refnox:
		srdi	r3,r27,12						// pages to update (not including crosser)
		add		r26,r26,r3						// add in crosser
		srdi	r27,r29,12						// r27 <- source page number
copypv_refloop:
		mr		r3,r27							// r3 <- source page number
		la		r4,FM_ARG0+0x18(r1)				// r4 <- unsigned int *pindex
		bl		EXT(mapping_phys_lookup)		// see if page is really there
		mr.		r3,r3							// is it?
		beq--	copypv_done						// nope, break out of modify loop
		mr		r3,r27							// r3 <- source  page number
		bl		EXT(mapping_set_ref)			// set page referenced status
		subi	r26,r26,1						// decrement page count
		cmpwi	r26,0							// done yet?
		bgt		copypv_refloop					// nope, iterate
		
// Return, indicating success.
copypv_done:
copypv_zero:
		li		r3,0							// our efforts were crowned with success

// Pop frame, restore caller's non-volatiles, clear recovery routine pointer.
copypv_return:
		mfsprg	r9,1							// get current threads stuff
		lwz		r0,(FM_ALIGN((31-26+11)*4)+FM_SIZE+FM_LR_SAVE)(r1)
												// get return address
		lwz		r4,(FM_ALIGN((31-26+11)*4)+FM_SIZE+FM_CR_SAVE)(r1)
												// get non-volatile cr2 and cr3
		lwz		r26,FM_ARG0+0x00(r1)			// restore non-volatile r26
		lwz		r27,FM_ARG0+0x04(r1)			// restore non-volatile r27
		mtlr	r0								// restore return address
		lwz		r28,FM_ARG0+0x08(r1)			// restore non-volatile r28
		mtcrf	0x20,r4							// restore non-volatile cr2
		mtcrf	0x10,r4							// restore non-volatile cr3
		lwz		r11,FM_ARG0+0x20(r1)			// save error callback
		lwz		r29,FM_ARG0+0x0C(r1)			// restore non-volatile r29
		lwz		r30,FM_ARG0+0x10(r1)			// restore non-volatile r30
		lwz		r31,FM_ARG0+0x14(r1)			// restore non-volatile r31
		stw		r11,THREAD_RECOVER(r9)			// restore our error callback
		lwz		r1,0(r1)						// release stack frame
												
		blr										// y'all come back now

// Invalid argument handler.
copypv_einval:
		li		r3,EINVAL						// invalid argument
		b		copypv_return					// return

// Error encountered during bcopy or bcopy_nc.		
copypv_error:
		mfmsr	r3								// get current msr
		rldicl	r3,r3,0,MSR_SF_BIT+1			// clear SF bit in our copy
		mtmsrd	r3								// leave 64-bit mode
		li		r3,EFAULT						// it was all his fault
		b		copypv_return					// return
