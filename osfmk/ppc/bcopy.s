/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
;			Copy bytes of data around. handles overlapped data.
;
;			Change this to use Altivec later on, and maybe floating point.
;
;			NOTE: This file compiles and executes on both MacOX 8.x (Codewarrior)
;			      and MacOX X.  The  "#if 0"s are treated as comments by CW so the
;				  stuff between them is included by CW and excluded on MacOX X.
;				  Same with the "#include"s.
;
#include <ppc/asm.h>
#include <ppc/proc_reg.h>

;		Use CR5_lt to indicate non-cached
#define noncache 20
;		Use CR5_gt to indicate that we need to turn data translation back on
#define fixxlate 21
#if 0
noncache:	equ	20
fixxlate:	equ	21
#endif
#if 0
br0:		equ	0
#endif

;
; bcopy_nc(from, to, nbytes)
;
; bcopy_nc operates on non-cached memory so we can not use any kind
; of cache instructions.
;



#if 0
			IF 0
#endif
ENTRY(bcopy_nc, TAG_NO_FRAME_USED)
#if 0
			ENDIF
			export	xbcopy_nc[DS]
			tc		xbcopy_nc[TC],xbcopy_nc[DS]
			csect	xbcopy_nc[DS]
			dc.l	.xbcopy_nc
			dc.l	TOC[tc0]
			export	.xbcopy_nc
			csect	xbcopy_nc[PR]
.xbcopy_nc:
#endif
			
			crset	noncache					; Set non-cached
			b		bcpswap

;	
; void bcopy_phys(from, to, nbytes)
; Turns off data translation before the copy.  Note, this one will
; not work in user state
;

#if 0
			IF 0
#endif
ENTRY(bcopy_phys, TAG_NO_FRAME_USED)
#if 0
			ENDIF
			export	xbcopy_phys[DS]
			tc		bcopy_physc[TC],bcopy_phys[DS]
			csect	bcopy_phys[DS]
			dc.l	.bcopy_phys
			dc.l	TOC[tc0]
			export	.bcopy_phys
			csect	bcopy_phys[PR]
.bcopy_phys:
#endif

			mfmsr	r9							; Get the MSR
			crclr	noncache					; Set cached
			rlwinm.	r8,r9,0,MSR_DR_BIT,MSR_DR_BIT	; Is data translation on?

			cmplw	cr1,r4,r3					; Compare "to" and "from"
			cmplwi	cr7,r5,0					; Check if we have a 0 length
			mr		r6,r3						; Set source
			beqlr-	cr1							; Bail if "to" and "from" are the same	
			xor		r9,r9,r8					; Turn off translation if it is on (should be)
			beqlr-	cr7							; Bail if length is 0
			
			mtmsr	r9							; Set DR translation off
			isync								; Wait for it
			
			crnot	fixxlate,cr0_eq				; Remember to turn on translation if it was
			b		copyit						; Go copy it...

;	
; void bcopy(from, to, nbytes)
;

#if 0
			IF 0
#endif
ENTRY(bcopy, TAG_NO_FRAME_USED)
#if 0
			ENDIF
			export	xbcopy[DS]
			tc		xbcopyc[TC],xbcopy[DS]
			csect	xbcopy[DS]
			dc.l	.xbcopy
			dc.l	TOC[tc0]
			export	.xbcopy
			csect	xbcopy[PR]
.xbcopy:
#endif

			crclr	noncache					; Set cached

bcpswap:	cmplw	cr1,r4,r3					; Compare "to" and "from"
			mr.		r5,r5						; Check if we have a 0 length
			mr		r6,r3						; Set source
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
	
#if 0
			IF 0
#endif
ENTRY(memcpy, TAG_NO_FRAME_USED)
#if 0
			ENDIF
			export	xmemcpy[DS]
			tc		xmemcpy[TC],xmemcpy[DS]
			csect	xmemcpy[DS]
			dc.l	.xmemcpy
			dc.l	TOC[tc0]
			export	.xmemcpy
			csect	xmemcpy[PR]
.xmemcpy:
#endif
			cmplw	cr1,r3,r4					; "to" and "from" the same?
			mr		r6,r4						; Set the "from"
			mr.		r5,r5						; Length zero?
			crclr	noncache					; Set cached
			mr		r4,r3						; Set the "to"
			crclr	fixxlate					; Set translation already ok
			beqlr-	cr1							; "to" and "from" are the same
			beqlr-								; Length is 0
			
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

bcpydone:	bflr	fixxlate					; Leave now if we do not need to fix translation...
			mfmsr	r9							; Get the MSR
			ori		r9,r9,lo16(MASK(MSR_DR))	; Turn data translation on
			mtmsr	r9							; Just do it
			isync								; Hang in there
			blr									; Leave cuz we are all done...			

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
#if 0
			stwu	r1,-8(r1)					; Dummy stack for MacOS
			stw		r2,4(r1)					; Save RTOC
#endif


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
#if 0
			lwz		r2,4(r1)					; Restore RTOC
			lwz		r1,0(r1)					; Pop dummy stack
#endif

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
			
			blr									; Leave cuz we are all done...			
