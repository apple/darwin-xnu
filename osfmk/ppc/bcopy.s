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
;
;			Copy bytes of data around. handles overlapped data.
;
;			Change this to use Altivec later on, and maybe floating point.
;
;
#include <ppc/asm.h>
#include <ppc/proc_reg.h>

;		Use CR5_lt to indicate non-cached
#define noncache 20
;		Use CR5_gt to indicate that we need to turn data translation back on
#define fixxlate 21
;		Use CR5_eq to indicate that we need to invalidate bats
#define killbats 22

;
; bcopy_nc(from, to, nbytes)
;
; bcopy_nc operates on non-cached memory so we can not use any kind
; of cache instructions.
;

			.align	5
			.globl	EXT(bcopy_nc)

LEXT(bcopy_nc)
			
			crset	noncache					; Set non-cached
			b		bcpswap

;	
; void bcopy_physvir(from, to, nbytes)
; Attempt to copy physically addressed memory with translation on if conditions are met.
; Otherwise do a normal bcopy_phys.
;
; Rules are: neither source nor destination can cross a page. 
; No accesses above the 2GB line (I/O or ROM).
;
; Interrupts must be disabled throughout the copy when this is called

; To do this, we build a
; 128 DBAT for both the source and sink.  If both are the same, only one is
; loaded.  We do not touch the IBATs, so there is no issue if either physical page
; address is the same as the virtual address of the instructions we are executing.
;
; At the end, we invalidate the used DBATs and reenable interrupts.
;
; Note, this one will not work in user state
; 

			.align	5
			.globl	EXT(bcopy_physvir)

LEXT(bcopy_physvir)

			addic.	r0,r5,-1					; Get length - 1
			add		r11,r3,r0					; Point to last byte of sink
			cmplw	cr1,r3,r4					; Does source == sink?			
			add		r12,r4,r0					; Point to last byte of source
			bltlr-								; Bail if length is 0 or way too big
			xor		r7,r11,r3					; See if we went to next page
			xor		r8,r12,r4					; See if we went to next page
			or		r0,r7,r8					; Combine wrap
			
			li		r9,((PTE_WIMG_CB_CACHED_COHERENT<<3)|2)	; Set default attributes
			rlwinm.	r0,r0,0,0,19				; Did we overflow a page?
			li		r7,2						; Set validity flags
			li		r8,2						; Set validity flags
			bne-	EXT(bcopy_phys)				; Overflowed page, do normal physical copy...

			crset	killbats					; Remember to trash BATs on the way out
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

bcpvsame:	mr		r6,r3						; Set source
			crclr	noncache					; Set cached
			
			b		copyit						; Go copy it...


;	
; void bcopy_phys(from, to, nbytes)
; Turns off data translation before the copy.  Note, this one will
; not work in user state
;

			.align	5
			.globl	EXT(bcopy_phys)

LEXT(bcopy_phys)

			mfmsr	r9							; Get the MSR

			crclr	noncache					; Set cached
			rlwinm.	r8,r9,0,MSR_DR_BIT,MSR_DR_BIT	; Is data translation on?

			cmplw	cr1,r4,r3					; Compare "to" and "from"
			cmplwi	cr7,r5,0					; Check if we have a 0 length
			mr		r6,r3						; Set source
			beqlr-	cr1							; Bail if "to" and "from" are the same	
			xor		r9,r9,r8					; Turn off translation if it is on (should be)
			beqlr-	cr7							; Bail if length is 0
			
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			crclr	killbats					; Make sure we do not trash BATs on the way out
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			mtmsr	r9							; Set DR translation off
			isync								; Wait for it
			
			crnot	fixxlate,cr0_eq				; Remember to turn on translation if it was
			b		copyit						; Go copy it...

;	
; void bcopy(from, to, nbytes)
;

			.align	5
			.globl	EXT(bcopy)

LEXT(bcopy)

			crclr	noncache					; Set cached

bcpswap:	cmplw	cr1,r4,r3					; Compare "to" and "from"
			mr.		r5,r5						; Check if we have a 0 length
			mr		r6,r3						; Set source
			crclr	killbats					; Make sure we do not trash BATs on the way out
			beqlr-	cr1							; Bail if "to" and "from" are the same	
			beqlr-								; Bail if length is 0
			crclr	fixxlate					; Set translation already ok
			b		copyit						; Go copy it...

;
;			When we move the memory, forward overlays must be handled.  We
;			also can not use the cache instructions if we are from bcopy_nc.
;			We need to preserve R3 because it needs to be returned for memcpy.
;			We can be interrupted and lose control here.
;
;			There is no stack, so in order to used floating point, we would
;			need to take the FP exception. Any potential gains by using FP 
;			would be more than eaten up by this.
;
;			Later, we should used Altivec for large moves.
;
	
			.align	5
			.globl	EXT(memcpy)

LEXT(memcpy)

			cmplw	cr1,r3,r4					; "to" and "from" the same?
			mr		r6,r4						; Set the "from"
			mr.		r5,r5						; Length zero?
			crclr	noncache					; Set cached
			mr		r4,r3						; Set the "to"
			crclr	fixxlate					; Set translation already ok
			beqlr-	cr1							; "to" and "from" are the same
			beqlr-								; Length is 0
			crclr	killbats					; Make sure we do not trash BATs on the way out
			
copyit:		sub		r12,r4,r6					; Get potential overlap (negative if backward move)
			lis		r8,0x7FFF					; Start up a mask
			srawi	r11,r12,31					; Propagate the sign bit
			dcbt	br0,r6						; Touch in the first source line
			cntlzw	r7,r5						; Get the highest power of 2 factor of the length
			ori		r8,r8,0xFFFF				; Make limit 0x7FFFFFFF
			xor		r9,r12,r11					; If sink - source was negative, invert bits
			srw		r8,r8,r7					; Get move length limitation
			sub		r9,r9,r11					; If sink - source was negative, add 1 and get absolute value
			cmplw	r12,r5						; See if we actually forward overlap
			cmplwi	cr7,r9,32					; See if at least a line between  source and sink
			dcbtst	br0,r4						; Touch in the first sink line
			cmplwi	cr1,r5,32					; Are we moving more than a line?
			cror	noncache,noncache,28		; Set to not DCBZ output line if not enough space
			blt-	fwdovrlap					; This is a forward overlapping area, handle it...

;
;			R4 = sink
;			R5 = length
;			R6 = source
;
			
;
;			Here we figure out how much we have to move to get the sink onto a
;			cache boundary.  If we can, and there are still more that 32 bytes
;			left to move, we can really speed things up by DCBZing the sink line.
;			We can not do this if noncache is set because we will take an 
;			alignment exception.

			neg		r0,r4						; Get the number of bytes to move to align to a line boundary
			rlwinm.	r0,r0,0,27,31				; Clean it up and test it
			and		r0,r0,r8					; limit to the maximum front end move
			mtcrf	3,r0						; Make branch mask for partial moves
			sub		r5,r5,r0					; Set the length left to move
			beq		alline						; Already on a line...
			
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
			mtcrf	3,r5						; Make branch mask for backend partial moves
			rlwinm	r11,r5,0,0,26				; Get number of bytes we are going to move
			beq-	backend						; No full lines to move
			
			sub		r5,r5,r11					; Calculate the residual
			li		r10,96						; Stride for touch ahead
			
nxtline:	subic.	r0,r0,1						; Account for the line now

			bt-		noncache,skipz				; Skip if we are not cached...
			dcbz	br0,r4						; Blow away the whole line because we are replacing it
			dcbt	r6,r10						; Touch ahead a bit
			
skipz:		lwz		r7,0(r6)					; Get the first word
			lwz		r8,4(r6)					; Get the second word
			lwz		r9,8(r6)					; Get the third word
			stw		r7,0(r4)					; Save the first word
			lwz		r11,12(r6)					; Get the fourth word
			stw		r8,4(r4)					; Save the second word
			lwz		r7,16(r6)					; Get the fifth word
			stw		r9,8(r4)					; Save the third word
			lwz		r8,20(r6)					; Get the sixth word
			stw		r11,12(r4)					; Save the fourth word
			lwz		r9,24(r6)					; Get the seventh word
			stw		r7,16(r4)					; Save the fifth word
			lwz		r11,28(r6)					; Get the eighth word
			addi	r6,r6,32					; Point to the next
			stw		r8,20(r4)					; Save the sixth word
			stw		r9,24(r4)					; Save the seventh word
			stw		r11,28(r4)					; Save the eighth word
			addi	r4,r4,32					; Bump sink
			bgt+	nxtline						; Do the next line, if any...

	
;			Move backend quadword

backend:	bf		27,noquad					; No quad to do...
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

nohalf:		bf		31,bcpydone					; Leave cuz we are all done...	
			lbz		r7,0(r6)					; Get the byte
			stb		r7,0(r4)					; Save the single

bcpydone:	bt-		killbats,bcclrbat			; Jump if we need to clear bats...
			bflr	fixxlate					; Leave now if we do not need to fix translation...
			mfmsr	r9							; Get the MSR
			ori		r9,r9,lo16(MASK(MSR_DR))	; Turn data translation on
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			mtmsr	r9							; Just do it
			isync								; Hang in there
			blr									; Leave cuz we are all done...			

bcclrbat:	li		r0,0						; Get set to invalidate upper half
			sync								; Make sure all is well
			mtdbatu	0,r0						; Clear sink upper DBAT
			mtdbatu	1,r0						; Clear source upper DBAT
			sync
			isync			
			blr


;
;			0123456789ABCDEF0123456789ABCDEF
;			 0123456789ABCDEF0123456789ABCDEF
;										    F
;										  DE
;									  9ABC
;							  12345678
;             123456789ABCDEF0	
;            0

;
;			Here is where we handle a forward overlapping move.  These will be slow
;			because we can not kill the cache of the destination until after we have
;			loaded/saved the source area.  Also, because reading memory backwards is
;			slower when the cache line needs to be loaded because the critical 
;			doubleword is loaded first, i.e., the last, then it goes back to the first,
;			and on in order.  That means that when we are at the second to last DW we
;			have to wait until the whole line is in cache before we can proceed.
;
	
fwdovrlap:	add		r4,r5,r4					; Point past the last sink byte
			add		r6,r5,r6					; Point past the last source byte 
			and		r0,r4,r8					; Apply movement limit
			li		r12,-1						; Make sure we touch in the actual line 			
			mtcrf	3,r0						; Figure out the best way to move backwards			
			dcbt	r12,r6						; Touch in the last line of source
			rlwinm.	r0,r0,0,27,31				; Calculate the length to adjust to cache boundary
			dcbtst	r12,r4						; Touch in the last line of the sink
			beq-	balline						; Aready on cache line boundary
			
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
			mtcrf	3,r5						; Make branch mask for backend partial moves
			beq-	bbackend					; No full lines to move


;			Registers in use: R0, R1,     R3, R4, R5, R6
;       Registers not in use:         R2,                 R7, R8, R9, R10, R11, R12 - Ok, we can make another free for 8 of them
			
bnxtline:	subic.	r0,r0,1						; Account for the line now

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
			ble-	bnotouch					; Last time, skip touch of source...
			dcbt	br0,r6						; Touch in next source line
			
bnotouch:	stw		r5,-28(r4)					; Get the second word
			stw		r2,-24(r4)					; Get the third word
			stw		r12,-20(r4)					; Get the third word
			stw		r11,-16(r4)					; Get the fifth word
			stw		r10,-12(r4)					; Get the sixth word
			stw		r9,-8(r4)					; Get the seventh word
			stw		r8,-4(r4)					; Get the eighth word
			subi	r4,r4,32					; Bump sink
			
			bgt+	bnxtline					; Do the next line, if any...

;
;			Note: We touched these lines in at the beginning
;
	
;			Move backend quadword

bbackend:	bf		27,bnoquad					; No quad to do...
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

bnohalf:	bflr	31							; Leave cuz we are all done...	
			lbz		r7,-1(r6)					; Get the byte
			stb		r7,-1(r4)					; Save the single
			
			b		bcpydone					; Go exit cuz we are all done...
