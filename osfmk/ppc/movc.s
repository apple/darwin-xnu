/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
// by MapUserAddressSpace will be 64 bits however on 64-bit machines.  Beware to avoid
// using compare instructions on this ptr.  This mapped ptr is kept globally in r31, so there
// is no need to store or load it, which are mode-dependent operations since it could be
// 32 or 64 bits.

#define	kkFrameSize	(FM_SIZE+32)

#define	kkBufSize	(FM_SIZE+0)
#define	kkCR		(FM_SIZE+4)
#define	kkSource	(FM_SIZE+8)
#define	kkDest		(FM_SIZE+12)
#define	kkCountPtr	(FM_SIZE+16)
#define	kkR31Save	(FM_SIZE+20)
 
 
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
 *	vm_offset_t	src;
 *	vm_offset_t	dst;
 *	vm_size_t	maxcount; 
 *	vm_size_t*	count;
 *
 * Set *count to the number of bytes copied.
 */

ENTRY(copyoutstr, TAG_NO_FRAME_USED)
        mfcr	r2								// we use nonvolatile cr3
        li		r0,0
        crset	kkString						// flag as a string op
        mr		r10,r4							// for copyout, dest ptr (r4) is in user space
        stw		r0,0(r6)						// initialize #bytes moved
        crclr	kkIn							// flag as copyout
        b		copyJoin


//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * int
 * copyinstr(src, dst, maxcount, count)
 *	vm_offset_t	src;
 *	vm_offset_t	dst;
 *	vm_size_t	maxcount; 
 *	vm_size_t*	count;
 *
 * Set *count to the number of bytes copied
 * If dst == NULL, don't copy, just count bytes.
 * Only currently called from klcopyinstr. 
 */

ENTRY(copyinstr, TAG_NO_FRAME_USED)
        mfcr	r2								// we use nonvolatile cr3
        cmplwi	r4,0							// dst==NULL?
        li		r0,0
        crset	kkString						// flag as a string op
        mr		r10,r3							// for copyin, source ptr (r3) is in user space
        crmove	kkNull,cr0_eq					// remember if (dst==NULL)
        stw		r0,0(r6)						// initialize #bytes moved
        crset	kkIn							// flag as copyin (rather than copyout)
        b		copyJoin1						// skip over the "crclr kkNull"


//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * int
 * copyout(src, dst, count)
 *	vm_offset_t	src;
 *	vm_offset_t	dst;
 *	size_t		count;
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
        mfcr	r2								// save caller's CR
        crclr	kkString						// not a string version
        mr		r10,r4							// dest (r4) is user-space ptr
        crclr	kkIn							// flag as copyout
        b		copyJoin
        

//<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
/*
 * int
 * copyin(src, dst, count)
 *	vm_offset_t	src;
 *	vm_offset_t	dst;
 *	size_t		count;
 */


			.align	5
			.globl	EXT(copyin)
			.globl	EXT(copyinmsg)

LEXT(copyin)
LEXT(copyinmsg)

        mfcr	r2								// save caller's CR
        crclr	kkString						// not a string version
        mr		r10,r3							// source (r3) is user-space ptr in copyin
        crset	kkIn							// flag as copyin
        
        
// Common code to handle setup for all the copy variants:
//		r2 = caller's CR, since we use cr3
//   r3-r6 = parameters
//	   r10 = user-space ptr (r3 if copyin, r4 if copyout)
//     cr3 = kkIn, kkString, kkNull flags

copyJoin:
        crclr	kkNull							// (dst==NULL) convention not used with this call
copyJoin1:										// enter from copyinstr with kkNull set
		mflr	r0								// get return address
        cmplwi	r5,0							// buffer length 0?
        lis		r9,0x1000						// r9 <- 0x10000000 (256MB)
		stw		r0,FM_LR_SAVE(r1)				// save return
        cmplw	cr1,r5,r9						// buffer length > 256MB ?
        mfsprg	r8,2							// get the features
        beq--	copyinout_0						// 0 length is degenerate case
		stwu	r1,-kkFrameSize(r1)				// set up stack frame
        stw		r2,kkCR(r1)						// save caller's CR since we use cr3
        mtcrf	0x02,r8							// move pf64Bit to cr6
        stw		r3,kkSource(r1)					// save args across MapUserAddressSpace
        stw		r4,kkDest(r1)
        stw		r5,kkBufSize(r1)
        crmove	kk64bit,pf64Bitb				// remember if this is a 64-bit processor
        stw		r6,kkCountPtr(r1)
        stw		r31,kkR31Save(r1)				// we use r31 globally for mapped user ptr
        li		r31,0							// no mapped ptr yet
        
        
// Handle buffer length > 256MB.  This is an error (ENAMETOOLONG) on copyin and copyout.
// The string ops are passed -1 lengths by some BSD callers, so for them we silently clamp
// the buffer length to 256MB.  This isn't an issue if the string is less than 256MB
// (as most are!), but if they are >256MB we eventually return ENAMETOOLONG.  This restriction
// is due to MapUserAddressSpace; we don't want to consume more than two segments for
// the mapping. 

        ble++	cr1,copyin0						// skip if buffer length <= 256MB
        bf		kkString,copyinout_too_big		// error if not string op
        mr		r5,r9							// silently clamp buffer length to 256MB
        stw		r9,kkBufSize(r1)				// update saved copy too


// Set up thread_recover in case we hit an illegal address.

copyin0:
		mfsprg  r8,1							/* Get the current act */ 
		lis		r2,hi16(copyinout_error)
		lwz		r7,ACT_THREAD(r8)
		ori		r2,r2,lo16(copyinout_error)
		lwz		r3,ACT_VMMAP(r8)				// r3 <- vm_map virtual address
		stw		r2,THREAD_RECOVER(r7)


// Map user segment into kernel map, turn on 64-bit mode.
//		r3 = vm map
//		r5 = buffer length
//	   r10 = user space ptr (r3 if copyin, r4 if copyout)
        
		mr		r6,r5							// Set length to map
		li		r4,0							// Note: we only do this 32-bit for now
        mr		r5,r10							// arg2 <- user space ptr
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
        bl		EXT(MapUserAddressSpace)		// set r3 <- address in kernel map of user operand
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
		or.		r0,r3,r4						// Did we fail the mapping?
        mr		r31,r4							// r31 <- mapped ptr into user space (may be 64-bit)
        beq--	copyinout_error					// was 0, so there was an error making the mapping
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
        lwz		r4,kkDest(r1)					// copyin: source is mapped, dest is r4 at entry
        mr		r3,r31							// source is mapped ptr
        b		copyin3
copyin2:										// handle copyout
        lwz		r3,kkSource(r1)					// source is kernel buffer (r3 at entry)
        mr		r4,r31							// dest is mapped ptr into user space
        
        
// Finally, all set up to copy:
//		r3 = source ptr (mapped if copyin)
//		r4 = dest ptr (mapped if copyout)
//		r5 = length
//	   r31 = mapped ptr returned by MapUserAddressSpace
//	   cr3 = kkIn, kkString, kk64bit, and kkNull flags

copyin3:
        bt		kkString,copyString				// handle copyinstr and copyoutstr
        bl		EXT(bcopy)						// copyin and copyout: let bcopy do the work
        li		r3,0							// return success
        
        
// Main exit point for copyin, copyout, copyinstr, and copyoutstr.  Also reached
// from error recovery if we get a DSI accessing user space.  Clear recovery ptr, 
// and pop off frame.  Note that we have kept
// the mapped ptr into user space in r31, as a reg64_t type (ie, a 64-bit ptr on
// 64-bit machines.)  We must unpack r31 into an addr64_t in (r3,r4) before passing
// it to ReleaseUserAddressSpace.
//		r3 = 0, EFAULT, or ENAMETOOLONG

copyinx: 
        lwz		r2,kkCR(r1)						// get callers cr3
		mfsprg  r6,1							// Get the current act 
		lwz		r10,ACT_THREAD(r6)
		
        bf--	kk64bit,copyinx1				// skip if 32-bit processor
        mfmsr	r12
        rldicl	r12,r12,0,MSR_SF_BIT+1			// if 64-bit processor, turn 64-bit mode off
        mtmsrd	r12								// turn SF off and EE back on
        isync									// wait for the mode to change
copyinx1:
        lwz		r31,kkR31Save(r1)				// restore callers r31
        addi	r1,r1,kkFrameSize				// pop off our stack frame
		lwz		r0,FM_LR_SAVE(r1)
		li		r4,0
		stw		r4,THREAD_RECOVER(r10)			// Clear recovery
		mtlr	r0
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
//	   r31 = mapped ptr returned by MapUserAddressSpace
//     cr3 = kkIn, kkString, kkNull, and kk64bit flags
// We do word copies unless the buffer is very short, then use a byte copy loop
// for the leftovers if necessary.

copyString:
        li		r12,0							// Set header bytes count to zero
        cmplwi	cr1,r5,20						// is buffer very short?
        mtctr	r5								// assuming short, set up loop count for bytes
        blt		cr1,copyinstr8					// too short for word loop
        andi.	r12,r3,0x3						// is source ptr word aligned?
        bne		copyinstr11						//  bytes loop
copyinstr1:
        srwi	r6,r5,2							// get #words in buffer
        mtctr	r6								// set up word loop count
        lis		r10,hi16(0xFEFEFEFF)			// load magic constants into r10 and r11
        lis		r11,hi16(0x80808080)
        ori		r10,r10,lo16(0xFEFEFEFF)
        ori		r11,r11,lo16(0x80808080)
        bf		kkNull,copyinstr6				// enter loop that copies
        b		copyinstr5						// use loop that just counts
        
        
// Word loop(s).  They do a word-parallel search for 0s, using the following
// inobvious but very efficient test:
//		y =  data + 0xFEFEFEFF
//		z = ~data & 0x80808080
// If (y & z)==0, then all bytes in dataword are nonzero.  We need two copies of
// this loop, since if we test kkNull in the loop then it becomes 9 words long.

        .align	5								// align inner loops for speed
copyinstr5:										// version that counts but does not copy
        lwz		r8,0(r3)						// get next word of source
        addi	r3,r3,4							// increment source ptr
        add		r9,r10,r8						// r9 =  data + 0xFEFEFEFF
        andc	r7,r11,r8						// r7 = ~data & 0x80808080
        and.	r7,r9,r7						// r7 = r9 & r7
        bdnzt	cr0_eq,copyinstr5				// if r7==0, then all bytes are nonzero

        b		copyinstr7

        .align	5								// align inner loops for speed
copyinstr6:										// version that counts and copies
        lwz		r8,0(r3)						// get next word of source
        addi	r3,r3,4							// increment source ptr
        addi	r4,r4,4							// increment dest ptr while we wait for data
        add		r9,r10,r8						// r9 =  data + 0xFEFEFEFF
        andc	r7,r11,r8						// r7 = ~data & 0x80808080
        and.	r7,r9,r7						// r7 = r9 & r7
        stw		r8,-4(r4)						// pack all 4 bytes into buffer
        bdnzt	cr0_eq,copyinstr6				// if r7==0, then all bytes are nonzero


// Either 0 found or buffer filled.  The above algorithm has mapped nonzero bytes to 0
// and 0 bytes to 0x80 with one exception: 0x01 bytes preceeding the first 0 are also
// mapped to 0x80.  We must mask out these false hits before searching for an 0x80 byte.

copyinstr7:
        crnot	kkZero,cr0_eq					// 0 found iff cr0_eq is off
        mfctr	r6								// get #words remaining in buffer
        rlwinm	r2,r8,7,0,31					// move 0x01 bits to 0x80 position
        slwi	r6,r6,2							// convert to #bytes remaining
        andc	r7,r7,r2						// turn off false hits from 0x0100 worst case
        rlwimi	r6,r5,0,30,31					// add in odd bytes leftover in buffer
        srwi	r7,r7,8							// we want to count the 0 as a byte xferred
        addi	r6,r6,4							// don't count last word xferred (yet)
        cntlzw	r7,r7							// now we can find the 0 byte (ie, the 0x80)
        srwi	r7,r7,3							// convert 8,16,24,32 to 1,2,3,4
        sub.	r6,r6,r7						// account for nonzero bytes in last word
        bt++	kkZero,copyinstr10				// 0 found, so done
        
        beq		copyinstr10						// r6==0, so buffer truly full
        mtctr	r6								// 0 not found, loop over r6 bytes
        b		copyinstr8						// enter byte loop for last 1-3 leftover bytes
        

// Byte loop.  This is used for very small buffers and for the odd bytes left over
// after searching and copying words at a time.
    
        .align	5								// align inner loops for speed
copyinstr8:										// loop over bytes of source
        lbz		r0,0(r3)						// get next byte of source
        addi	r3,r3,1
        addi	r4,r4,1							// increment dest addr whether we store or not
        cmpwi	r0,0							// the 0?
        bt--	kkNull,copyinstr9				// don't store (was copyinstr with NULL ptr)
        stb		r0,-1(r4)
copyinstr9:
        bdnzf	cr0_eq,copyinstr8				// loop if byte not 0 and more room in buffer
        
        mfctr	r6								// get #bytes left in buffer
        crmove	kkZero,cr0_eq					// remember if 0 found or buffer filled

        
// Buffer filled or 0 found.  Unwind and return.
//	r5 = kkBufSize, ie buffer length
//  r6 = untransferred bytes remaining in buffer
// r31 = mapped ptr returned by MapUserAddressSpace
// cr3 = kkZero set iff 0 found

copyinstr10:
        lwz		r9,kkCountPtr(r1)				// get ptr to place to store count of bytes moved
        sub		r2,r5,r6						// get #bytes we moved, counting the 0 iff any
        add		r2,r2,r12						// add the header bytes count
        li		r3,0							// assume 0 return status
        stw		r2,0(r9)						// store #bytes moved
        bt++	kkZero,copyinx					// we did find the 0 so return 0
        li		r3,ENAMETOOLONG					// buffer filled
        b		copyinx							// join main exit routine

// Byte loop.  This is used on the header bytes for unaligned source 
    
        .align	5								// align inner loops for speed
copyinstr11:
        li		r10,4							// load word size
        sub		r12,r10,r12						// set the header bytes count
        mtctr	r12								// set up bytes loop count
copyinstr12:									// loop over bytes of source
        lbz		r0,0(r3)						// get next byte of source
        addi	r3,r3,1
        addi	r4,r4,1							// increment dest addr whether we store or not
        cmpwi	r0,0							// the 0?
        bt--	kkNull,copyinstr13				// don't store (was copyinstr with NULL ptr)
        stb		r0,-1(r4)
copyinstr13:
        bdnzf	cr0_eq,copyinstr12				// loop if byte not 0 and more room in buffer
        sub		r5,r5,r12						// substract the bytes copied
        bne		cr0_eq,copyinstr1				// branch to word loop

        mr		r5,r12							// Get the header bytes count
        li		r12,0							// Clear the header bytes count
        mfctr	r6								// get #bytes left in buffer
        crmove	kkZero,cr0_eq					// remember if 0 found or buffer filled
        b		copyinstr10

