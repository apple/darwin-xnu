/*
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
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
;
;			Copy bytes of data around. Handles overlapped data.
;
;
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <assym.s>

;       These routines use CR5 for certain flags:
;		Use CR5_lt to indicate non-cached (in bcopy and memcpy)
#define noncache 20


;       The bcopy_phys variants use a stack frame so they can call bcopy as a subroutine.
#define BCOPY_SF_SIZE   32      // total size
#define BCOPY_SF_MSR    16      // we save caller's MSR here (possibly minus VEC and FP)


#define kShort  32              // short operands are special cased


; void bcopy_physvir_32(from, to, nbytes)
;
; Attempt to copy physically addressed memory with translation on if conditions are met.
; Otherwise do a normal bcopy_phys.  This routine is used because some 32-bit processors 
; are very slow doing real-mode (translation off) copies, so we set up temporary BATs
; for the passed phys addrs and do the copy with translation on.  
;
; Rules are: - neither source nor destination can cross a page. 
;            - Interrupts must be disabled when this routine is called.
;            - Translation must be on when called.
;
; To do the copy, we build a 128 DBAT for both the source and sink.  If both are the same, only one
; is loaded.  We do not touch the IBATs, so there is no issue if either physical page
; address is the same as the virtual address of the instructions we are executing.
;
; At the end, we invalidate the used DBATs.
;
; Note that the address parameters are long longs.  We will transform these to 64-bit
; values.  Note that on 32-bit architectures that this will ignore the high half of the
; passed in value.  This should be ok since we can not have any bigger than 32 bit addresses
; there anyhow.
;
; Note also that this routine is used only on 32-bit machines. If you're contemplating use
; on a 64-bit processor, use the physical memory window instead; please refer to copypv()
; for an example of how this is done.

			.align	5
			.globl	EXT(bcopy_physvir_32)

LEXT(bcopy_physvir_32)
            mflr    r0                          ; get return address
            rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
            mfsprg	r8,2						; get processor feature flags
            stw     r0,8(r1)                    ; save return address
			rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
            stwu    r1,-BCOPY_SF_SIZE(r1)       ; push on a stack frame so we can call bcopy
            mtcrf	0x02,r8						; move pf64Bit to cr6 so we can test
            subi    r0,r7,1                     ; get length - 1
			rlwinm	r4,r5,0,1,0					; Duplicate high half of long long paddr into top of reg
			add		r11,r3,r0					; Point to last byte of sink
			mr		r5,r7						; Get the length into the right register
            rlwimi	r4,r6,0,0,31				; Combine bottom of long long to full 64-bits

; This test for page overflow may not work if the length is negative.  Negative lengths are invalid input
; to bcopy_physvir() on 32-bit machines, and will result in a panic.
            
			add		r12,r4,r0					; Point to last byte of source
			xor		r7,r11,r3					; See if we went to next page
			xor		r8,r12,r4					; See if we went to next page
			or		r0,r7,r8					; Combine wrap
			
//			li		r9,((PTE_WIMG_CB_CACHED_COHERENT<<3)|2)	; Set default attributes
			li		r9,((2<<3)|2)				; Set default attributes
			rlwinm.	r0,r0,0,0,19				; Did we overflow a page?
			li		r7,2						; Set validity flags
			li		r8,2						; Set validity flags
			bne-	bcopy_phys1					; Overflowed page, do normal physical copy...

			rlwimi	r11,r9,0,15,31				; Set sink lower DBAT value
			rlwimi	r12,r9,0,15,31				; Set source lower DBAT value
			rlwimi	r7,r11,0,0,14				; Set sink upper DBAT value
			rlwimi	r8,r12,0,0,14				; Set source upper DBAT value
			cmplw	cr1,r11,r12					; See if sink and source are same block
			
			sync

			mtdbatl	0,r11						; Set sink lower DBAT 
			mtdbatu	0,r7						; Set sink upper DBAT

			beq-	cr1,bcpvsame				; Source and sink are in same block

			mtdbatl	1,r12						; Set source lower DBAT 
			mtdbatu	1,r8						; Set source upper DBAT
            
bcpvsame:	
            sync                                ; wait for the BATs to stabilize
            isync
            
            bl      EXT(bcopy)                  ; BATs set up, args in r3-r5, so do the copy with DR on

            li		r0,0						; Get set to invalidate upper half of BATs
			sync								; Make sure all is well
			mtdbatu	0,r0						; Clear sink upper DBAT
			mtdbatu	1,r0						; Clear source upper DBAT
			sync
			isync			
            
            lwz     r0,BCOPY_SF_SIZE+8(r1)      ; get return address
            addi    r1,r1,BCOPY_SF_SIZE         ; pop off stack frame
            mtlr    r0
            blr


; void bcopy_phys(from, to, nbytes)
;
; Turns off data translation before the copy.  This one will not work in user state.
; This routine is used on 32 and 64-bit machines.
;
; Note that the address parameters are long longs.  We will transform these to 64-bit
; values.  Note that on 32-bit architectures that this will ignore the high half of the
; passed in value.  This should be ok since we can not have any bigger than 32 bit addresses
; there anyhow.
;
; Also note that you probably will not be happy if either the sink or source spans across the
; boundary between RAM and I/O space.  Good chance of hanging the machine and this code 
; will not check, so be careful.
;
; NOTE: when called, translation must be on, and we must be in 32-bit mode.
;       Interrupts may or may not be disabled.

			.align	5
			.globl	EXT(bcopy_phys)

LEXT(bcopy_phys)
            mflr    r0                          ; get return address
            rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
            stw     r0,8(r1)                    ; save
            mfsprg	r8,2						; get processor feature flags
            stwu    r1,-BCOPY_SF_SIZE(r1)       ; push on a stack frame so we can call bcopy
			rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
			rlwinm	r4,r5,0,1,0					; Duplicate high half of long long paddr into top of reg
			mtcrf	0x02,r8						; move pf64Bit to cr6 so we can test
			rlwimi	r4,r6,0,0,31				; Combine bottom of long long to full 64-bits
			mr		r5,r7						; Get the length into the right register

bcopy_phys1:									; enter from bcopy_physvir with pf64Bit in cr6 and parms in r3-r5
			mfmsr	r9							; Get the MSR
			lis		r6,hi16(MASK(MSR_VEC))		; Get vector enable            
            ori     r6,r6,lo16(MASK(MSR_FP)|MASK(MSR_DR))	; Add in FP and DR
            andc    r9,r9,r6                    ; unconditionally turn DR, VEC, and FP off
            bt++	pf64Bitb,bcopy_phys64		; skip if 64-bit (only they take hint)

; 32-bit CPUs

			mtmsr	r9							; turn DR, FP, and VEC off
			isync								; Wait for it
			
            bl      EXT(bcopy)                  ; do the copy with translation off and caching on
            
			mfmsr	r9							; Get the MSR
            ori     r9,r9,lo16(MASK(MSR_DR))    ; turn translation back on (but leave VEC and FP off)
            mtmsr   r9                          ; restore msr
            isync                               ; wait for it to happen
            lwz     r0,BCOPY_SF_SIZE+8(r1)      ; get return address once translation is back on
            mtlr    r0
            addi    r1,r1,BCOPY_SF_SIZE         ; pop off stack frame
            blr

            
; 64-bit: turn DR off and SF on.

bcopy_phys64:									; r9 = MSR with DP, VEC, and FP off
            ori     r8,r9,lo16(MASK(MSR_DR))    ; make a copy with DR back on... this is what we return to caller
			srdi	r2,r3,31					; Get a 1 if source is in I/O memory
            li		r0,1						; Note - we use this in a couple places below
			srdi	r10,r4,31					; Get a 1 if sink is in I/O memory
            std     r8,BCOPY_SF_MSR(r1)         ; save caller's MSR so we remember whether EE was on
            rldimi	r9,r0,63,MSR_SF_BIT			; set SF on in MSR we will copy with
			cmpldi	cr0,r2,1					; Is source in I/O memory?
			cmpldi	cr7,r10,1					; Is sink in I/O memory?
            mtmsrd	r9							; turn 64-bit addressing on, data translation off
            isync								; wait for it to happen
			cror	cr7_eq,cr0_eq,cr7_eq		; See if either source or sink is in I/O area
            beq--   cr7,io_space_real_mode_copy ; an operand is in I/O space
            
            bl      EXT(bcopy)                  ; do copy with DR off and SF on, cache enabled
                        
bcopy_phys64x:
			mfmsr	r9							; Get the MSR we used to copy
            rldicl	r9,r9,0,MSR_SF_BIT+1		; clear SF
            ori     r9,r9,lo16(MASK(MSR_DR))    ; turn translation back on
            mtmsrd  r9                          ; turn 64-bit mode off, translation back on
            isync								; wait for it to happen
            lwz     r0,BCOPY_SF_SIZE+8(r1)      ; get return address once translation is back on
            ld      r8,BCOPY_SF_MSR(r1)         ; get caller's MSR once translation is back on
            mtlr    r0
            mtmsrd  r8,1                        ; turn EE back on if necessary
            addi    r1,r1,BCOPY_SF_SIZE         ; pop off stack frame
            blr

;   We need to copy with DR off, but one of the operands is in I/O space.  To avoid wedging U3,
;   which cannot handle a cache burst in I/O space, we must turn caching off for the real memory access.
;   This can only be done by setting bits in HID4.  We cannot lose control and execute random code in
;   this state, so we have to disable interrupts as well.  This is an unpleasant hack.

io_space_real_mode_copy:                        ; r0=1, r9=MSR we want to copy with
			sldi	r11,r0,31-MSR_EE_BIT		; Get a mask for the EE bit
			sldi	r0,r0,32+8					; Get the right bit to turn off caching
			andc	r9,r9,r11					; Turn off EE bit
			mfspr	r2,hid4						; Get HID4
			mtmsrd	r9,1                        ; Force off EE
			or		r2,r2,r0					; Set bit to make real accesses cache-inhibited
			sync								; Sync up
			mtspr	hid4,r2						; Make real accesses cache-inhibited
			isync								; Toss prefetches

			lis		r12,0xE000					; Get the unlikeliest ESID possible
			srdi	r12,r12,1					; Make 0x7FFFFFFFF0000000
			slbie	r12							; Make sure the ERAT is cleared 
			
			sync
			isync
			
            bl      EXT(bcopy_nc)               ; copy with SF on and EE, DR, VEC, and FP off, cache inhibited
            
			li		r0,1						; Get a 1
			sldi	r0,r0,32+8					; Get the right bit to turn off caching
			mfspr	r2,hid4						; Get HID4
			andc	r2,r2,r0					; Clear bit to make real accesses cache-inhibited
			sync								; Sync up
			mtspr	hid4,r2						; Make real accesses not cache-inhibited
			isync								; Toss prefetches
	
			lis		r12,0xE000					; Get the unlikeliest ESID possible
			srdi	r12,r12,1					; Make 0x7FFFFFFFF0000000
			slbie	r12							; Make sure the ERAT is cleared
            b       bcopy_phys64x


;
; shortcopy
;
; Special case short operands (<32 bytes), which are very common.  Note that the check for
; reverse vs normal moves isn't quite correct in 64-bit mode; in rare cases we will move in
; reverse when it wasn't necessary to do so.  This is OK, since performance of the two cases
; is similar.  We do get the direction right when it counts (ie, when the operands overlap.)
; Also note that we use the G3/G4 "backend" code, even on G5.  This is OK too, since G5 has
; plenty of load/store dispatch bandwidth in this case, the extra ops are hidden by latency,
; and using word instead of doubleword moves reduces the possibility of unaligned accesses,
; which cost about 20 cycles if they cross a 32-byte boundary on G5.  Finally, because we
; might do unaligned accesses this code cannot be called from bcopy_nc().
;           r4 = destination
;           r5 = length (<32)
;           r6 = source
;           r12 = (dest - source)

            .align  5
shortcopy:
            cmplw   r12,r5                      ; must move reverse if (dest-source)<length
            mtcrf   2,r5                        ; move length to cr6 and cr7 one at a time...
            mtcrf   1,r5                        ; ...which is faster on G4 and G5
            bge++   backend                     ; handle forward moves (most common case)
            add     r6,r6,r5                    ; point one past end of operands in reverse moves
            add     r4,r4,r5
            b       bbackend                    ; handle reverse moves
            
;	
; void bcopy(from, to, nbytes)
;
; NOTE: bcopy is called from copyin and copyout etc with the "thread_recover" ptr set.
; This means bcopy must not set up a stack frame or touch non-volatile registers, and also means that it
; cannot rely on turning off interrupts, because we expect to get DSIs and have execution aborted by a "longjmp"
; to the thread_recover routine.  What this means is that it would be hard to use vector or floating point
; registers to accelerate the copy.
;
; NOTE: this code can be called in any of three "modes":
;       - on 32-bit processors (32-byte cache line)
;       - on 64-bit processors running in 32-bit mode (128-byte cache line)
;       - on 64-bit processors running in 64-bit mode (128-byte cache line)

			.align	5
			.globl	EXT(bcopy)
            .globl  EXT(bcopy_nop_if_32bit)

LEXT(bcopy)
			cmplwi	cr1,r5,kShort               ; less than 32 bytes?
            sub.    r12,r4,r3					; test for to==from in mode-independent way, start fwd/rev check
			mr		r6,r3						; Set source (must preserve r3 for memcopy return)
			blt     cr1,shortcopy               ; special case short operands
			crclr	noncache					; Set cached
LEXT(bcopy_nop_if_32bit)
            bne++   copyit64                    ; handle 64-bit processor (patched to NOP if 32-bit processor)
			bne+    copyit32					; handle 32-bit processor
            blr                                 ; to==from so nothing to do
	
;
; bcopy_nc(from, to, nbytes)
;
; bcopy_nc() operates on non-cached memory so we can not use any kind of cache instructions.
; Furthermore, we must avoid all unaligned accesses on 64-bit machines, since they take
; alignment exceptions.  Thus we cannot use "shortcopy", which could do unaligned lwz/stw.
; Like bcopy(), bcopy_nc() can be called both in 32- and 64-bit mode.

			.align	5
			.globl	EXT(bcopy_nc)
            .globl  EXT(bcopy_nc_nop_if_32bit)

LEXT(bcopy_nc)
			cmpwi	cr1,r5,0					; Check if we have a 0 length
            sub.	r12,r4,r3					; test for to==from in mode-independent way, start fwd/rev check
			mr		r6,r3						; Set source (must preserve r3 for memcopy return)
			crset	noncache					; Set non-cached
			cror    cr0_eq,cr1_eq,cr0_eq        ; set cr0 beq if either length zero or to==from
LEXT(bcopy_nc_nop_if_32bit)
            bne++   copyit64                    ; handle 64-bit processor (patched to NOP if 32-bit processor)
			bne+    copyit32					; handle 32-bit processor
            blr                                 ; either zero length or to==from

;
; void* memcpy(to, from, nbytes)
; void* memmove(to, from, nbytes)
;
; memcpy() and memmove() are only called in 32-bit mode, albeit on both 32- and 64-bit processors.
; However, they would work correctly if called in 64-bit mode.

			.align	5
			.globl	EXT(memcpy)
			.globl	EXT(memmove)
            .globl  EXT(memcpy_nop_if_32bit)

LEXT(memcpy)
LEXT(memmove)
			cmplwi	cr1,r5,kShort               ; less than 32 bytes?
            sub.    r12,r3,r4					; test for to==from in mode-independent way, start fwd/rev check
			mr		r6,r4						; Set source
			mr		r4,r3						; Set the "to" (must preserve r3 for return value)
			blt     cr1,shortcopy               ; special case short operands
			crclr	noncache					; Set cached
LEXT(memcpy_nop_if_32bit)
            bne++   copyit64                    ; handle 64-bit processor (patched to NOP if 32-bit processor)
			beqlr-                              ; exit if to==from


;       Here to copy on 32-bit processors.
;
;			When we move the memory, forward overlays must be handled.  We
;			also can not use the cache instructions if we are from bcopy_nc.
;			We need to preserve R3 because it needs to be returned for memcpy.
;			We can be interrupted and lose control here.
;
;           When entered:
;               r4 = destination
;               r5 = length (>0)
;               r6 = source
;               r12 = (dest - source)
;               cr5 = noncache flag

copyit32:                                       ; WARNING! can drop down to this label
            cmplw   cr1,r12,r5                  ; must move reverse if (dest-source)<length
            cntlzw  r11,r5                      ; get magnitude of length
            dcbt    0,r6                        ; start to touch in source
            lis     r10,hi16(0x80000000)        ; get 0x80000000
            neg     r9,r4                       ; start to get alignment for destination
            dcbtst  0,r4                        ; start to touch in destination
            sraw    r8,r10,r11                  ; get mask based on operand length, to limit alignment
            blt-    cr1,reverse32bit            ; reverse move required
			
; Forward moves on 32-bit machines, also word aligned uncached ops on 64-bit machines.
; NOTE: we never do an unaligned access if the source and destination are "relatively"
; word aligned.  We depend on this in the uncached case on 64-bit processors.
;               r4 = destination
;               r5 = length (>0)
;               r6 = source
;               r8 = inverse of largest mask smaller than operand length
;               r9 = neg(dest), used to compute alignment
;               cr5 = noncache flag

forward32bit:                                   ; enter from 64-bit CPUs with word aligned uncached operands
			rlwinm	r7,r9,0,0x1F				; get bytes to 32-byte-align destination
			andc.   r0,r7,r8					; limit to the maximum front end move
            mtcrf   0x01,r0                     ; move length to cr6 and cr7 one cr at a time...
			beq		alline						; Already on a line...
			
			mtcrf	0x02,r0						; ...since moving more than one is slower on G4 and G5
			sub		r5,r5,r0					; Set the length left to move

			bf		31,alhalf					; No single byte to do...
			lbz		r7,0(r6)					; Get the byte
			addi	r6,r6,1						; Point to the next
			stb		r7,0(r4)					; Save the single
			addi	r4,r4,1						; Bump sink
			
;			Sink is halfword aligned here

alhalf:		bf		30,alword					; No halfword to do...
			lhz		r7,0(r6)					; Get the halfword
			addi	r6,r6,2						; Point to the next
			sth		r7,0(r4)					; Save the halfword
			addi	r4,r4,2						; Bump sink
			
;			Sink is word aligned here

alword:		bf		29,aldouble					; No word to do...
			lwz		r7,0(r6)					; Get the word
			addi	r6,r6,4						; Point to the next
			stw		r7,0(r4)					; Save the word
			addi	r4,r4,4						; Bump sink
			
;			Sink is double aligned here

aldouble:	bf		28,alquad					; No double to do...
			lwz		r7,0(r6)					; Get the first word
			lwz		r8,4(r6)					; Get the second word
			addi	r6,r6,8						; Point to the next
			stw		r7,0(r4)					; Save the first word
			stw		r8,4(r4)					; Save the second word
			addi	r4,r4,8						; Bump sink
			
;			Sink is quadword aligned here

alquad:		bf		27,alline					; No quad to do...
			lwz		r7,0(r6)					; Get the first word
			lwz		r8,4(r6)					; Get the second word
			lwz		r9,8(r6)					; Get the third word
			stw		r7,0(r4)					; Save the first word
			lwz		r11,12(r6)					; Get the fourth word
			addi	r6,r6,16					; Point to the next
			stw		r8,4(r4)					; Save the second word
			stw		r9,8(r4)					; Save the third word
			stw		r11,12(r4)					; Save the fourth word
			addi	r4,r4,16					; Bump sink
			
;			Sink is line aligned here

alline:		rlwinm.	r0,r5,27,5,31				; Get the number of full lines to move
            mtcrf   0x02,r5                     ; move length to cr6 and cr7 one cr at a time...
			mtcrf	0x01,r5						; ...since moving more than one is slower on G4 and G5			
			beq-	backend						; No full lines to move
            
            mtctr   r0                          ; set up loop count
			li		r0,96						; Stride for touch ahead
            b       nxtline
			
            .align  4
nxtline:
            lwz		r2,0(r6)					; Get the first word
			lwz		r5,4(r6)					; Get the second word
			lwz		r7,8(r6)					; Get the third word
			lwz		r8,12(r6)					; Get the fourth word
			lwz		r9,16(r6)					; Get the fifth word
			lwz		r10,20(r6)					; Get the sixth word
			lwz		r11,24(r6)					; Get the seventh word
			lwz		r12,28(r6)					; Get the eighth word
			bt-		noncache,skipz				; Skip if we are not cached...
			dcbz	0,r4						; Blow away the whole line because we are replacing it
			dcbt	r6,r0						; Touch ahead a bit
skipz:
			addi	r6,r6,32					; Point to the next
			stw		r2,0(r4)					; Save the first word
			stw		r5,4(r4)					; Save the second word
			stw		r7,8(r4)					; Save the third word
			stw		r8,12(r4)					; Save the fourth word
			stw		r9,16(r4)					; Save the fifth word
			stw		r10,20(r4)					; Save the sixth word
			stw		r11,24(r4)					; Save the seventh word
			stw		r12,28(r4)					; Save the eighth word
			addi	r4,r4,32					; Bump sink
			bdnz+	nxtline						; Do the next line, if any...

	
;			Move backend quadword

backend:                                        ; Join here from "shortcopy" for forward moves <32 bytes
            bf		27,noquad					; No quad to do...
			lwz		r7,0(r6)					; Get the first word
			lwz		r8,4(r6)					; Get the second word
			lwz		r9,8(r6)					; Get the third word
			lwz		r11,12(r6)					; Get the fourth word
			stw		r7,0(r4)					; Save the first word
			addi	r6,r6,16					; Point to the next
			stw		r8,4(r4)					; Save the second word
			stw		r9,8(r4)					; Save the third word
			stw		r11,12(r4)					; Save the fourth word
			addi	r4,r4,16					; Bump sink
			
;			Move backend double

noquad:		bf		28,nodouble					; No double to do...
			lwz		r7,0(r6)					; Get the first word
			lwz		r8,4(r6)					; Get the second word
			addi	r6,r6,8						; Point to the next
			stw		r7,0(r4)					; Save the first word
			stw		r8,4(r4)					; Save the second word
			addi	r4,r4,8						; Bump sink
			
;			Move backend word

nodouble:	bf		29,noword					; No word to do...
			lwz		r7,0(r6)					; Get the word
			addi	r6,r6,4						; Point to the next
			stw		r7,0(r4)					; Save the word
			addi	r4,r4,4						; Bump sink
			
;			Move backend halfword

noword:		bf		30,nohalf					; No halfword to do...
			lhz		r7,0(r6)					; Get the halfword
			addi	r6,r6,2						; Point to the next
			sth		r7,0(r4)					; Save the halfword
			addi	r4,r4,2						; Bump sink

;			Move backend byte

nohalf:		bflr    31                          ; Leave cuz we are all done...	
			lbz		r7,0(r6)					; Get the byte
			stb		r7,0(r4)					; Save the single
            blr


; Reverse moves on 32-bit machines, also reverse word aligned uncached moves on 64-bit machines.
; NOTE: we never do an unaligned access if the source and destination are "relatively"
; word aligned.  We depend on this in the uncached case on 64-bit processors.
; These are slower because we don't bother with dcbz.  Fortunately, reverse moves are uncommon.
;               r4 = destination
;               r5 = length (>0)
;               r6 = source
;               r8 = inverse of largest mask smaller than operand length
;               cr5 = noncache flag (but we don't dcbz anyway)

reverse32bit:									; here from 64-bit code with word aligned uncached operands
            add		r4,r5,r4					; Point past the last sink byte
			add		r6,r5,r6					; Point past the last source byte 
			rlwinm	r7,r4,0,0x1F				; Calculate the length to align dest on cache boundary
			li		r12,-1						; Make sure we touch in the actual line
			andc.   r0,r7,r8					; Apply movement limit
			dcbt	r12,r6						; Touch in the last line of source
            mtcrf   0x01,r0                     ; move length to cr6 and cr7 one cr at a time...
			dcbtst	r12,r4						; Touch in the last line of the sink
			mtcrf	0x02,r0						; ...since moving more than one is slower on G4 and G5			
			beq-	balline						; Aready on cache line boundary (or too short to bother)
			
			sub		r5,r5,r0					; Precaculate move length left after alignment
			
			bf		31,balhalf					; No single byte to do...
			lbz		r7,-1(r6)					; Get the byte
			subi	r6,r6,1						; Point to the next
			stb		r7,-1(r4)					; Save the single
			subi	r4,r4,1						; Bump sink
			
;			Sink is halfword aligned here

balhalf:	bf		30,balword					; No halfword to do...
			lhz		r7,-2(r6)					; Get the halfword
			subi	r6,r6,2						; Point to the next
			sth		r7,-2(r4)					; Save the halfword
			subi	r4,r4,2						; Bump sink
			
;			Sink is word aligned here

balword:	bf		29,baldouble				; No word to do...
			lwz		r7,-4(r6)					; Get the word
			subi	r6,r6,4						; Point to the next
			stw		r7,-4(r4)					; Save the word
			subi	r4,r4,4						; Bump sink
			
;			Sink is double aligned here

baldouble:	bf		28,balquad					; No double to do...
			lwz		r7,-8(r6)					; Get the first word
			lwz		r8,-4(r6)					; Get the second word
			subi	r6,r6,8						; Point to the next
			stw		r7,-8(r4)					; Save the first word
			stw		r8,-4(r4)					; Save the second word
			subi	r4,r4,8						; Bump sink
			
;			Sink is quadword aligned here

balquad:	bf		27,balline					; No quad to do...
			lwz		r7,-16(r6)					; Get the first word
			lwz		r8,-12(r6)					; Get the second word
			lwz		r9,-8(r6)					; Get the third word
			lwz		r11,-4(r6)					; Get the fourth word
			stw		r7,-16(r4)					; Save the first word
			subi	r6,r6,16					; Point to the next
			stw		r8,-12(r4)					; Save the second word
			stw		r9,-8(r4)					; Save the third word
			stw		r11,-4(r4)					; Save the fourth word
			subi	r4,r4,16					; Bump sink
			
;			Sink is line aligned here

balline:	rlwinm.	r0,r5,27,5,31				; Get the number of full lines to move
            mtcrf   0x02,r5                     ; move length to cr6 and cr7 one cr at a time...
			mtcrf	0x01,r5						; ...since moving more than one is slower on G4 and G5			
			beq-	bbackend					; No full lines to move
            mtctr   r0                          ; set up loop count
            b       bnxtline
			
            .align  4
bnxtline:
			lwz		r7,-32(r6)					; Get the first word
			lwz		r5,-28(r6)					; Get the second word
			lwz		r2,-24(r6)					; Get the third word
			lwz		r12,-20(r6)					; Get the third word
			lwz		r11,-16(r6)					; Get the fifth word
			lwz		r10,-12(r6)					; Get the sixth word
			lwz		r9,-8(r6)					; Get the seventh word
			lwz		r8,-4(r6)					; Get the eighth word
			subi	r6,r6,32					; Point to the next
			
			stw		r7,-32(r4)					; Get the first word
            stw		r5,-28(r4)					; Get the second word
			stw		r2,-24(r4)					; Get the third word
			stw		r12,-20(r4)					; Get the third word
			stw		r11,-16(r4)					; Get the fifth word
			stw		r10,-12(r4)					; Get the sixth word
			stw		r9,-8(r4)					; Get the seventh word
			stw		r8,-4(r4)					; Get the eighth word
			subi	r4,r4,32					; Bump sink
			
			bdnz+	bnxtline					; Do the next line, if any...

;
;			Note: We touched these lines in at the beginning
;
	
;			Move backend quadword

bbackend:                                       ; Join here from "shortcopy" for reverse moves of <32 bytes
            bf		27,bnoquad					; No quad to do...
			lwz		r7,-16(r6)					; Get the first word
			lwz		r8,-12(r6)					; Get the second word
			lwz		r9,-8(r6)					; Get the third word
			lwz		r11,-4(r6)					; Get the fourth word
			stw		r7,-16(r4)					; Save the first word
			subi	r6,r6,16					; Point to the next
			stw		r8,-12(r4)					; Save the second word
			stw		r9,-8(r4)					; Save the third word
			stw		r11,-4(r4)					; Save the fourth word
			subi	r4,r4,16					; Bump sink
			
;			Move backend double

bnoquad:	bf		28,bnodouble				; No double to do...
			lwz		r7,-8(r6)					; Get the first word
			lwz		r8,-4(r6)					; Get the second word
			subi	r6,r6,8						; Point to the next
			stw		r7,-8(r4)					; Save the first word
			stw		r8,-4(r4)					; Save the second word
			subi	r4,r4,8						; Bump sink
			
;			Move backend word

bnodouble:	bf		29,bnoword					; No word to do...
			lwz		r7,-4(r6)					; Get the word
			subi	r6,r6,4						; Point to the next
			stw		r7,-4(r4)					; Save the word
			subi	r4,r4,4						; Bump sink
			
;			Move backend halfword

bnoword:	bf		30,bnohalf					; No halfword to do...
			lhz		r7,-2(r6)					; Get the halfword
			subi	r6,r6,2						; Point to the next
			sth		r7,-2(r4)					; Save the halfword
			subi	r4,r4,2						; Bump sink

;			Move backend byte

bnohalf:	bflr    31                          ; Leave cuz we are all done...	
			lbz		r7,-1(r6)					; Get the byte
			stb		r7,-1(r4)					; Save the single
			blr


// Here on 64-bit processors, which have a 128-byte cache line.  This can be
// called either in 32 or 64-bit mode, which makes the test for reverse moves
// a little tricky.  We've already filtered out the (sou==dest) and (len==0)
// special cases.
//
// When entered:
//		r4 = destination (32 or 64-bit ptr)
//		r5 = length (always 32 bits)
//		r6 = source (32 or 64-bit ptr)
//      r12 = (dest - source), reverse move required if (dest-source)<length
//		cr5 = noncache flag

        .align	5
copyit64:
        rlwinm  r7,r5,0,0,31        // truncate length to 32-bit, in case we're running in 64-bit mode
        cntlzw	r11,r5				// get magnitude of length
        dcbt	0,r6				// touch in 1st block of source
        dcbtst	0,r4				// touch in 1st destination cache block
        subc    r7,r12,r7           // set Carry if (dest-source)>=length, in mode-independent way
        li      r0,0                // get a 0
        lis     r10,hi16(0x80000000)// get 0x80000000
        addze.  r0,r0               // set cr0 on carry bit (beq if reverse move required)
        neg     r9,r4               // start to get alignment for destination
        sraw    r8,r10,r11          // get mask based on operand length, to limit alignment
        bt--	noncache,c64uncached// skip if uncached
        beq--	c64rdouble          // handle cached reverse moves        
                
        
// Forward, cached or doubleword aligned uncached.  This is the common case.
// NOTE: we never do an unaligned access if the source and destination are "relatively"
// doubleword aligned.  We depend on this in the uncached case.
//      r4 = destination
//      r5 = length (>0)
//      r6 = source
//      r8 = inverse of largest mask smaller than operand length
//      r9 = neg(dest), used to compute alignment
//      cr5 = noncache flag

c64double:
        rlwinm  r7,r9,0,0x7F        // get #bytes to 128-byte align destination
        andc    r7,r7,r8            // limit by operand length
        andi.	r8,r7,7				// r8 <- #bytes to doubleword align
        srwi	r9,r7,3				// r9 <- #doublewords to 128-byte align
        sub		r5,r5,r7			// adjust length remaining
        cmpwi	cr1,r9,0			// any doublewords to move to cache align?
        srwi	r10,r5,7			// r10 <- 128-byte chunks to xfer after aligning dest
        cmpwi	cr7,r10,0			// set cr7 on chunk count
        beq		c64double2			// dest already doubleword aligned
        mtctr	r8
        b		c64double1
        
        .align	5					// align inner loops
c64double1:							// copy bytes until dest is doubleword aligned
        lbz		r0,0(r6)
        addi	r6,r6,1
        stb		r0,0(r4)
        addi	r4,r4,1
        bdnz	c64double1

c64double2:							// r9/cr1=doublewords, r10/cr7=128-byte chunks
        beq		cr1,c64double4		// no doublewords to xfer in order to cache align
        mtctr	r9
        b		c64double3

        .align	5					// align inner loops
c64double3:							// copy doublewords until dest is 128-byte aligned
        ld		r7,0(r6)
        addi	r6,r6,8
        std		r7,0(r4)
        addi	r4,r4,8
        bdnz	c64double3
        
// Here to xfer 128-byte chunks, if any.  Since we only have 8 GPRs for
// data (64 bytes), we load/store each twice per 128-byte chunk.

c64double4:							// r10/cr7=128-byte chunks
        rlwinm	r0,r5,29,28,31		// r0 <- count of leftover doublewords, after moving chunks
        cmpwi	cr1,r0,0			// set cr1 on leftover doublewords
        beq		cr7,c64double7		// no 128-byte chunks
        
        ; We must check for (source-dest)<128 in a mode-independent way.  If within 128 bytes,
        ; turn on "noncache" because we cannot use dcbz128 even if operands are cacheable.
        
        sub		r8,r6,r4			// r8 <- (source - dest)
        rldicr. r0,r8,0,63-7        // zero low 7 bits and check for 0, mode independent
        cror	noncache,cr0_eq,noncache	// turn on "noncache" flag if (source-dest)<128
        mtctr	r10
        b		c64InnerLoop
                
        .align	5					// align inner loop
c64InnerLoop:						// loop copying 128-byte cache lines to 128-aligned destination
        ld		r0,0(r6)			// start pipe: load 1st half-line
        ld		r2,8(r6)
        ld		r7,16(r6)
        ld		r8,24(r6)
        ld		r9,32(r6)
        ld		r10,40(r6)
        ld		r11,48(r6)
        ld		r12,56(r6)
        bt		noncache,c64InnerLoop1	// skip if uncached or overlap
        dcbz128	0,r4				// avoid prefetch of next cache line
c64InnerLoop1:

        std		r0,0(r4)
        std		r2,8(r4)
        std		r7,16(r4)
        std		r8,24(r4)
        std		r9,32(r4)
        std		r10,40(r4)
        std		r11,48(r4)
        std		r12,56(r4)
        
        ld		r0,64(r6)			// load 2nd half of chunk
        ld		r2,72(r6)
        ld		r7,80(r6)
        ld		r8,88(r6)
        ld		r9,96(r6)
        ld		r10,104(r6)
        ld		r11,112(r6)
        ld		r12,120(r6)
        addi	r6,r6,128

        std		r0,64(r4)
        std		r2,72(r4)
        std		r7,80(r4)
        std		r8,88(r4)
        std		r9,96(r4)
        std		r10,104(r4)
        std		r11,112(r4)
        std		r12,120(r4)
        addi	r4,r4,128			// advance to next dest chunk

        bdnz	c64InnerLoop		// loop if more chunks
        

c64double7:         	            // r5 <- leftover bytes, cr1 set on doubleword count
        rlwinm	r0,r5,29,28,31		// r0 <- count of leftover doublewords (0-15)
        andi.	r5,r5,7				// r5/cr0 <- count of leftover bytes (0-7)
        beq		cr1,c64byte			// no leftover doublewords
        mtctr	r0
        b		c64double8
        
        .align	5					// align inner loop
c64double8:							// loop copying leftover doublewords
        ld		r0,0(r6)
        addi	r6,r6,8
        std		r0,0(r4)
        addi	r4,r4,8
        bdnz	c64double8


// Forward byte loop.

c64byte:							// r5/cr0 <- byte count (can be big if unaligned uncached)
		beqlr                       // done if no leftover bytes
        mtctr	r5
        b		c64byte1
        
        .align	5					// align inner loop
c64byte1:
        lbz		r0,0(r6)
        addi	r6,r6,1
        stb		r0,0(r4)
        addi	r4,r4,1
        bdnz	c64byte1

        blr


// Uncached copies.  We must avoid unaligned accesses, since they always take alignment
// exceptions on uncached memory on 64-bit processors.  This may mean we copy long operands
// a byte at a time, but that is still much faster than alignment exceptions.
//      r4 = destination
//      r5 = length (>0)
//      r6 = source
//      r8 = inverse of largest mask smaller than operand length
//      r9 = neg(dest), used to compute alignment
//      r12 = (dest-source), used to test relative alignment
//      cr0 = beq if reverse move required
//      cr5 = noncache flag

c64uncached:
        rlwinm	r10,r12,0,29,31		// relatively doubleword aligned?
        rlwinm	r11,r12,0,30,31		// relatively word aligned?
        cmpwi	cr7,r10,0			// set cr7 beq if doubleword aligned
        cmpwi	cr1,r11,0			// set cr1 beq if word aligned
        beq--   c64reverseUncached
        
        beq		cr7,c64double		// doubleword aligned
        beq		cr1,forward32bit    // word aligned, use G3/G4 code
        cmpwi	r5,0				// set cr0 on byte count
        b		c64byte				// unaligned operands

c64reverseUncached:
        beq		cr7,c64rdouble		// doubleword aligned so can use LD/STD
        beq		cr1,reverse32bit	// word aligned, use G3/G4 code
        add		r6,r6,r5			// point to (end+1) of source and dest
        add		r4,r4,r5
        cmpwi	r5,0				// set cr0 on length
        b		c64rbyte			// copy a byte at a time
        
        

// Reverse doubleword copies.  This is used for all cached copies, and doubleword
// aligned uncached copies.
//      r4 = destination
//      r5 = length (>0)
//      r6 = source
//      r8 = inverse of largest mask of low-order 1s smaller than operand length
//      cr5 = noncache flag

c64rdouble:
        add		r6,r6,r5			// point to (end+1) of source and dest
        add		r4,r4,r5
        rlwinm	r7,r4,0,29,31		// r7 <- #bytes to doubleword align dest
        andc.   r7,r7,r8            // limit by operand length
        sub		r5,r5,r7			// adjust length
        srwi	r8,r5,6				// r8 <- 64-byte chunks to xfer
        cmpwi	cr1,r8,0			// any chunks?
        beq		c64rd2				// source already doubleword aligned
        mtctr	r7

c64rd1:								// copy bytes until source doublword aligned
        lbzu	r0,-1(r6)
        stbu	r0,-1(r4)
        bdnz	c64rd1
        
c64rd2:								// r8/cr1 <- count of 64-byte chunks
        rlwinm	r0,r5,29,29,31		// r0 <- count of leftover doublewords
        andi.	r5,r5,7				// r5/cr0 <- count of leftover bytes
        cmpwi	cr7,r0,0			// leftover doublewords?
        beq		cr1,c64rd4			// no chunks to xfer
        mtctr	r8
        b		c64rd3
        
        .align	5					// align inner loop
c64rd3:								// loop copying 64-byte chunks
        ld		r7,-8(r6)
        ld		r8,-16(r6)
        ld		r9,-24(r6)
        ld		r10,-32(r6)
        ld		r11,-40(r6)
        ld		r12,-48(r6)
        std		r7,-8(r4)
        std		r8,-16(r4)
        ld		r7,-56(r6)
        ldu		r8,-64(r6)
        std		r9,-24(r4)
        std		r10,-32(r4)
        std		r11,-40(r4)
        std		r12,-48(r4)
        std		r7,-56(r4)
        stdu	r8,-64(r4)
        bdnz	c64rd3

c64rd4:								// r0/cr7 = leftover doublewords  r5/cr0 = leftover bytes
        beq		cr7,c64rbyte		// no leftover doublewords
        mtctr	r0
        
c64rd5:								// loop copying leftover doublewords
        ldu		r0,-8(r6)
        stdu	r0,-8(r4)
        bdnz	c64rd5


// Reverse byte loop.

c64rbyte:							// r5/cr0 <- byte count (can be big if unaligned uncached)
        beqlr                       // done if no leftover bytes
        mtctr	r5
        
c64rbyte1:
        lbzu	r0,-1(r6)
        stbu	r0,-1(r4)
        bdnz	c64rbyte1

        blr

