/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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
;
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <assym.s>

;		Use CR5_lt to indicate non-cached
#define noncache 20

;		Use CR5_gt to indicate that we need to turn data translation back on
#define fixxlate 21

;		Use CR5_eq to indicate that we need to invalidate bats (if 32-bit) or turn off
;		64-bit mode (if 64-bit) before returning to our caller.  We overload the
;		bit to reduce the number of conditional branches at bcopy exit.
#define restorex 22

;		Use CR5_so to indicate that we need to restore real-mode cachability
;		Only needed on 64-bit machines
#define flipcache 23

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
; Otherwise do a normal bcopy_phys.  This routine is used because some 32-bit processors 
; are very slow doing real-mode (translation off) copies, so we set up temporary BATs
; for the passed phys addrs and do the copy with translation on.  
;
; Rules are: neither source nor destination can cross a page. 
;
; Interrupts must be disabled throughout the copy when this is called.
; To do this, we build a
; 128 DBAT for both the source and sink.  If both are the same, only one is
; loaded.  We do not touch the IBATs, so there is no issue if either physical page
; address is the same as the virtual address of the instructions we are executing.
;
; At the end, we invalidate the used DBATs.
;
; Note that the address parameters are long longs.  We will transform these to 64-bit
; values.  Note that on 32-bit architectures that this will ignore the high half of the
; passed in value.  This should be ok since we can not have any bigger than 32 bit addresses
; there anyhow.
;
; Note, this one will not work in user state
; 

			.align	5
			.globl	EXT(bcopy_physvir)

LEXT(bcopy_physvir)

			crclr	flipcache					; (HACK) No cache flip needed
            mfsprg	r8,2						; get processor feature flags
            rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
			addic.	r0,r7,-1					; Get length - 1
			rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
			add		r11,r3,r0					; Point to last byte of sink
			rlwinm	r4,r5,0,1,0					; Duplicate high half of long long paddr into top of reg
            mtcrf	0x02,r8						; move pf64Bit to cr6 so we can test
            rlwimi	r4,r6,0,0,31				; Combine bottom of long long to full 64-bits
			mr		r5,r7						; Get the length into the right register
			cmplw	cr1,r3,r4					; Does source == sink?	
            bt++	pf64Bitb,bcopy_phys1		; if 64-bit processor, use standard routine (no BATs)
			add		r12,r4,r0					; Point to last byte of source
			bltlr-								; Bail if length is 0 or way too big
			xor		r7,r11,r3					; See if we went to next page
			xor		r8,r12,r4					; See if we went to next page
			or		r0,r7,r8					; Combine wrap
			
//			li		r9,((PTE_WIMG_CB_CACHED_COHERENT<<3)|2)	; Set default attributes
			li		r9,((2<<3)|2)				; Set default attributes
			rlwinm.	r0,r0,0,0,19				; Did we overflow a page?
			li		r7,2						; Set validity flags
			li		r8,2						; Set validity flags
			bne-	bcopy_phys1					; Overflowed page, do normal physical copy...

			crset	restorex					; Remember to trash BATs on the way out
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
            sync                                ; wait for BAT to stabilize
            isync
            mr		r6,r3						; Set source
			crclr	noncache					; Set cached
			crclr	fixxlate					; Set translation already ok
			
			b		copyit32					; Go copy it...

;	
; void bcopy_phys(from, to, nbytes)
; Turns off data translation before the copy.  Note, this one will
; not work in user state.  This routine is used on 32 and 64-bit
; machines.
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

			.align	5
			.globl	EXT(bcopy_phys)

LEXT(bcopy_phys)
			crclr	flipcache					; (HACK) No cache flip needed
            rlwinm	r3,r3,0,1,0					; Duplicate high half of long long paddr into top of reg
            mfsprg	r8,2						; get processor feature flags
			rlwimi	r3,r4,0,0,31				; Combine bottom of long long to full 64-bits
			rlwinm	r4,r5,0,1,0					; Duplicate high half of long long paddr into top of reg
			mtcrf	0x02,r8						; move pf64Bit to cr6 so we can test
			rlwimi	r4,r6,0,0,31				; Combine bottom of long long to full 64-bits
			mr		r5,r7						; Get the length into the right register
            
bcopy_phys1:									; enter from bcopy_physvir with pf64Bit already in cr6
			mfmsr	r9							; Get the MSR
			crclr	noncache					; Set cached
            bt++	pf64Bitb,bcopy_phys64		; skip if 64-bit (only they take hint)

; 32-bit CPUs
            
            sub.	r0,r3,r4					; to==from?
			rlwinm	r8,r9,0,MSR_DR_BIT,MSR_DR_BIT	; was translation on?
            cmpwi	cr1,r8,0					; set cr1 beq if translation was off
			oris	r8,r8,hi16(MASK(MSR_VEC))	; Get vector enable
			cmplwi	cr7,r5,0					; Check if we have a 0 length
            beqlr-								; bail if to==from
			ori		r8,r8,lo16(MASK(MSR_FP))	; Get FP
			mr		r6,r3						; Set source
			andc	r9,r9,r8					; Turn off translation if it is on (should be) and FP, VEC
			beqlr-	cr7							; Bail if length is 0
			
			crclr	restorex					; Make sure we do not trash BATs on the way out
			mtmsr	r9							; Set DR translation off
			isync								; Wait for it
			
			crnot	fixxlate,cr1_eq				; Remember to turn on translation if it was
			b		copyit32					; Go copy it...
            
; 64-bit: turn DR off and SF on, remember if we need to restore on way out.

bcopy_phys64:									; r9 = MSR

			srdi	r2,r3,31					; (HACK) Get a 1 if source is in I/O memory
            srdi.	r0,r9,63-MSR_SF_BIT			; set cr0 beq on if SF was off when we were called
            rlwinm	r8,r9,MSR_DR_BIT+1,31,31	; r8 <- DR bit right justified
            cmpld	cr1,r3,r4					; to==from?
            li		r0,1						; Note - we use this in a couple places below
			lis		r6,hi16(MASK(MSR_VEC))		; Get vector enable
            cmpwi	cr7,r5,0					; length==0 ?
            ori		r6,r6,lo16(MASK(MSR_FP)|MASK(MSR_DR))	; Add in FP and DR
            beqlr--	cr1							; bail if to==from
			srdi	r10,r4,31					; (HACK) Get a 1 if sink is in I/O memory
            rldimi	r9,r0,63,MSR_SF_BIT			; set SF on
            beqlr--	cr7							; bail if length==0
            andc	r9,r9,r6					; turn DR, VEC, FP off
            cmpwi	cr1,r8,0					; was DR on?
            crmove	restorex,cr0_eq				; if SF was off, remember to turn back off before we return
            mtmsrd	r9							; turn 64-bit addressing on, data translation off
			cmpldi	cr0,r2,1					; (HACK) Is source in I/O memory?
            isync								; wait for it to happen
			mr		r6,r3						; Set source
			cmpldi	cr7,r10,1					; (HACK) Is sink in I/O memory?
            crnot	fixxlate,cr1_eq				; if DR was on, remember to turn back on before we return

			cror	flipcache,cr0_eq,cr7_eq		; (HACK) See if either source or sink is in I/O area

			rlwinm	r10,r9,MSR_EE_BIT+1,31,31	; (HACK GLORIOUS HACK) Isolate the EE bit
			sldi	r11,r0,31-MSR_EE_BIT		; (HACK GLORIOUS HACK)) Get a mask for the EE bit
			sldi	r0,r0,32+8					; (HACK) Get the right bit to turn off caching
			bf++	flipcache,copyit64			; (HACK) No need to mess with caching...
			
;
;			HACK GLORIOUS HACK - when we force of caching, we need to also force off
;			interruptions.  We are out of CR bits, so we need to stash the entry EE
;			somewheres.  It is in the XER....  We NEED to change this!!!!
;

			mtxer	r10							; (HACK GLORIOUS HACK) Remember EE
			andc	r9,r9,r11					; (HACK GLORIOUS HACK) Turn off EE bit
			mfspr	r2,hid4						; (HACK) Get HID4
			crset	noncache					; (HACK) Set non-cached
			mtmsrd	r9							; (HACK GLORIOUS HACK) Force off EE
			or		r2,r2,r0					; (HACK) Set bit to make real accesses cache-inhibited
			sync								; (HACK) Sync up
			li		r0,1
			mtspr	hid4,r2						; (HACK) Make real accesses cache-inhibited
			isync								; (HACK) Toss prefetches

			lis		r12,0xE000					; (HACK) Get the unlikeliest ESID possible
			srdi	r12,r12,1					; (HACK) Make 0x7FFFFFFFF0000000
			slbie	r12							; (HACK) Make sure the ERAT is cleared 
			
			sync								; (HACK)
			isync								; (HACK)
			
            b		copyit64
            

;	
; void bcopy(from, to, nbytes)
;

			.align	5
			.globl	EXT(bcopy)

LEXT(bcopy)

			crclr	noncache					; Set cached

bcpswap:	
			crclr	flipcache					; (HACK) No cache flip needed
            mfsprg	r8,2						; get processor feature flags
            sub.	r0,r4,r3					; test for to==from in mode-independent way
            mtcrf	0x02,r8						; move pf64Bit to cr6 so we can test
			cmpwi	cr1,r5,0					; Check if we have a 0 length
			crclr	restorex					; Make sure we do not trash BATs on the way out
			mr		r6,r3						; Set source
			crclr	fixxlate					; Set translation already ok
			beqlr-								; Bail if "to" and "from" are the same	
			beqlr-	cr1							; Bail if length is 0
            bt++	pf64Bitb,copyit64			; handle 64-bit processor
			b		copyit32					; Go copy it...

;
;			When we move the memory, forward overlays must be handled.  We
;			also can not use the cache instructions if we are from bcopy_nc.
;			We need to preserve R3 because it needs to be returned for memcpy.
;			We can be interrupted and lose control here.
;
;			There is no stack, so in order to use vectors, we would
;			need to take the vector exception. Any potential gains by using vectors 
;			would be more than eaten up by this.
;
;			NOTE: this code is called in three "modes":
;				- on 32-bit processors (32-byte cache line)
;				- on 64-bit processors running in 32-bit mode (128-byte cache line)
;				- on 64-bit processors running in 64-bit mode (128-byte cache line)
;
;			ALSO NOTE: bcopy is called from copyin and copyout etc
;			with the "thread_recover" ptr set.  This means bcopy must not set up a
;			stack frame or touch non-volatile registers, and also means that it
;			cannot rely on turning off interrupts, because we expect to get DSIs
;			and have execution aborted by a "longjmp" to the thread_recover
;			routine.
;
	
			.align	5
			.globl	EXT(memcpy)
            ; NB: memcpy is only called in 32-bit mode, albeit on both 32- and 64-bit
            ; processors...
LEXT(memcpy)
			crclr	flipcache					; (HACK) No cache flip needed
            mfsprg	r8,2						; get processor feature flags
			cmplw	cr1,r3,r4					; "to" and "from" the same?
            mtcrf	0x02,r8						; move pf64Bit to cr6 so we can test
			mr		r6,r4						; Set the "from"
			mr.		r5,r5						; Length zero?
			crclr	noncache					; Set cached
			mr		r4,r3						; Set the "to"
			crclr	fixxlate					; Set translation already ok
			beqlr-	cr1							; "to" and "from" are the same
			beqlr-								; Length is 0
			crclr	restorex					; Make sure we do not trash BATs on the way out
            bt++	pf64Bitb,copyit64			; handle 64-bit processors
			
copyit32:	sub		r12,r4,r6					; Get potential overlap (negative if backward move)
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
			cror	noncache,noncache,cr7_lt	; Set to not DCBZ output line if not enough space
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

G4word:											; enter from 64-bit case with word aligned uncached operands
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

bcpydone:	
			mfmsr	r9							; Get the MSR
			bf++	flipcache,bcpydone0			; (HACK) No need to mess with caching...

			li		r0,1						; (HACK) Get a 1
			mfxer	r10							; (HACK GLORIOUS HACK) Get the entry EE
			sldi	r0,r0,32+8					; (HACK) Get the right bit to turn off caching
			mfspr	r2,hid4						; (HACK) Get HID4
			rlwinm	r10,r10,31-MSR_EE_BIT,MSR_EE_BIT,MSR_EE_BIT	; (HACK GLORIOUS HACK) Set the EE bit
			andc	r2,r2,r0					; (HACK) Clear bit to make real accesses cache-inhibited
			or		r9,r9,r10					; (HACK GLORIOUS HACK) Set the EE in MSR
			sync								; (HACK) Sync up
			mtspr	hid4,r2						; (HACK) Make real accesses not cache-inhibited
			isync								; (HACK) Toss prefetches
	
			lis		r12,0xE000					; (HACK) Get the unlikeliest ESID possible
			srdi	r12,r12,1					; (HACK) Make 0x7FFFFFFFF0000000
			slbie	r12							; (HACK) Make sure the ERAT is cleared 

			mtmsr	r9							; (HACK GLORIOUS HACK) Set EE properly

bcpydone0:
			lis		r0,hi16(MASK(MSR_VEC))		; Get the vector bit
			ori		r0,r0,lo16(MASK(MSR_FP))	; Get the float bit
			bf++	fixxlate,bcpydone1			; skip if we do not need to fix translation...
			ori		r9,r9,lo16(MASK(MSR_DR))	; Turn data translation on
			andc	r9,r9,r0					; Make sure that FP and VEC are off
			mtmsr	r9							; Just do it
			isync								; Hang in there
            
bcpydone1:
            bflr++	restorex					; done if we do not have to fix up addressing
            mfsprg	r8,2						; get the feature flags again
            mtcrf	0x02,r8						; put pf64Bit where we can test it
            bt++	pf64Bitb,bcpydone2			; skip if 64-bit processor
            
            ; 32-bit processor, so clear out the BATs we set up for bcopy_physvir
            
            li		r0,0						; Get set to invalidate upper half
			sync								; Make sure all is well
			mtdbatu	0,r0						; Clear sink upper DBAT
			mtdbatu	1,r0						; Clear source upper DBAT
			sync
			isync			
			blr

            ; 64-bit processor, so turn off 64-bit mode we turned on to do bcopy_phys
            
bcpydone2:
            mfmsr	r9							; get MSR again
			andc	r9,r9,r0					; Make sure that FP and VEC are off
            rldicl	r9,r9,0,MSR_SF_BIT+1		; clear SF
            mtmsrd	r9
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

G4reverseWord:									; here from 64-bit code with word aligned uncached operands
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

bnohalf:	bf		31,bcpydone					; Leave cuz we are all done...	
			lbz		r7,-1(r6)					; Get the byte
			stb		r7,-1(r4)					; Save the single
			
			b		bcpydone					; Go exit cuz we are all done...


// Here on 64-bit processors, which have a 128-byte cache line.  This can be
// called either in 32 or 64-bit mode, which makes the test for reverse moves
// a little tricky.  We've already filtered out the (sou==dest) and (len==0)
// special cases.
//
// When entered:
//		r4 = destination (32 or 64-bit ptr)
//		r5 = length (always 32 bits)
//		r6 = source (32 or 64-bit ptr)
//		cr5 = noncache, fixxlate, flipcache, and restorex flags set

        .align	5
copyit64:
        lis		r2,0x4000			// r2 = 0x00000000 40000000
        neg		r12,r4				// start to compute #bytes to align dest
		bt--	noncache,noncache1	// (HACK) Do not even try anything cached...
        dcbt	0,r6				// touch in 1st block of source
noncache1:     
        add.	r2,r2,r2			// if 0x00000000 80000000 < 0, we are in 32-bit mode
        cntlzw	r9,r5				// get highest power-of-2 in length
        rlwinm	r7,r12,0,25,31		// r7 <- bytes to 128-byte align dest
		bt--	noncache,noncache2	// (HACK) Do not even try anything cached...
        dcbtst	0,r4				// touch in 1st destination cache block
noncache2:
        sraw	r2,r2,r9			// get mask with 1s for leading 0s in length, plus 1 more 1-bit
        bge		copyit64a			// skip if we are running in 64-bit mode
        rlwinm	r4,r4,0,0,31		// running in 32-bit mode, so truncate ptrs and lengths to 32 bits
        rlwinm	r5,r5,0,0,31
        rlwinm	r6,r6,0,0,31
copyit64a:							// now we can use 64-bit compares even if running in 32-bit mode
        sub		r8,r4,r6			// get (dest-source)
        andc	r7,r7,r2			// limit bytes to align by operand length
        cmpld	cr1,r8,r5			// if (dest-source)<length, must move reverse
        bt--	noncache,c64uncached	// skip if uncached
        blt--	cr1,c64rdouble		// handle cached reverse moves        
        
        
// Forward, cached or doubleword aligned uncached.  This is the common case.
//   r4-r6 = dest, length, source (as above)
//		r7 = #bytes 128-byte align dest (limited by copy length)
//     cr5 = flags, as above

c64double:
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

c64double2:							// r9/cr1=doublewords, r10=128-byte chunks, cr7=blt if r5==0
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
        
// Here to xfer 128-byte chunks, if any.  Because the IBM 970 cannot issue two stores/cycle,
// we pipeline the inner loop so we can pair loads and stores.  Since we only have 8 GPRs for
// data (64 bytes), we load/store each twice per 128-byte chunk.

c64double4:							// r10/cr7=128-byte chunks
        rlwinm	r0,r5,29,28,31		// r0 <- count of leftover doublewords, after moving chunks
        cmpwi	cr1,r0,0			// set cr1 on leftover doublewords
        beq		cr7,c64double7		// no 128-byte chunks
        sub		r8,r6,r4			// r8 <- (source - dest)
        li		r9,128				// start at next cache line (we've already touched in 1st line)
        cmpldi	cr7,r8,128			// if (source-dest)<128, cannot use dcbz128 beacause of overlap
        cror	noncache,cr7_lt,noncache	// turn on "noncache" flag if (source-dest)<128
		bt--	noncache,noncache3	// (HACK) Skip cache touch if noncachable
        dcbt128	r9,r6,1				// start forward stream
noncache3:
        mtctr	r10
        
        ld		r0,0(r6)			// start pipe: load 1st half-line
        ld		r2,8(r6)
        ld		r7,16(r6)
        ld		r8,24(r6)
        ld		r9,32(r6)
        ld		r10,40(r6)
        ld		r11,48(r6)
        ld		r12,56(r6)
		b		c64InnerLoopEntryPt
        
        .align	5					// align inner loop
c64InnerLoop:						// loop copying 128-byte cache lines to 128-aligned destination
        std		r0,64(r4)			// store 2nd half of chunk n
        ld		r0,0(r6)			// load 1st half of chunk n+1
        std		r2,72(r4)
        ld		r2,8(r6)
        std		r7,80(r4)
        ld		r7,16(r6)
        std		r8,88(r4)
        ld		r8,24(r6)
        std		r9,96(r4)
        ld		r9,32(r6)
        std		r10,104(r4)
        ld		r10,40(r6)
        std		r11,112(r4)
        ld		r11,48(r6)
        std		r12,120(r4)
        ld		r12,56(r6)
        addi	r4,r4,128			// advance to next dest chunk
c64InnerLoopEntryPt:				// initial entry into loop, with 1st halfline loaded        
        bt		noncache,c64InnerLoop1	// skip if uncached or overlap
        dcbz128	0,r4				// avoid prefetch of next cache line
c64InnerLoop1:
        std		r0,0(r4)			// store 1st half of chunk n
        ld		r0,64(r6)			// load 2nd half of chunk n
        std		r2,8(r4)
        ld		r2,72(r6)
        std		r7,16(r4)
        ld		r7,80(r6)
        std		r8,24(r4)
        ld		r8,88(r6)
        std		r9,32(r4)
        ld		r9,96(r6)
        std		r10,40(r4)
        ld		r10,104(r6)
        std		r11,48(r4)
        ld		r11,112(r6)
        std		r12,56(r4)
        ld		r12,120(r6)
        addi	r6,r6,128			// advance to next source chunk if any
        bdnz	c64InnerLoop		// loop if more chunks
        
        std		r0,64(r4)			// store 2nd half of last chunk
        std		r2,72(r4)
        std		r7,80(r4)
        std		r8,88(r4)
        std		r9,96(r4)
        std		r10,104(r4)
        std		r11,112(r4)
        std		r12,120(r4)
        addi	r4,r4,128			// advance to next dest chunk

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
		beq		bcpydone			// done if no leftover bytes
        mtctr	r5
        b		c64byte1
        
        .align	5					// align inner loop
c64byte1:
        lbz		r0,0(r6)
        addi	r6,r6,1
        stb		r0,0(r4)
        addi	r4,r4,1
        bdnz	c64byte1

        b		bcpydone


// Uncached copies.  We must avoid unaligned accesses, since they always take alignment
// exceptions on uncached memory on 64-bit processors.  This may mean we copy long operands
// a byte at a time, but that is still much faster than alignment exceptions.
//   r4-r6 = dest, length, source (as above)
//		r2 = mask of 1s for leading 0s in length, plus 1 extra 1
//		r7 = #bytes to copy to 128-byte align dest (limited by operand length)
//	   cr1 = blt if reverse move required

c64uncached:
        xor		r0,r6,r4			// get relative alignment
        rlwinm	r10,r0,0,29,31		// relatively doubleword aligned?
        rlwinm	r11,r0,0,30,31		// relatively word aligned?
        not		r8,r2				// get mask to limit initial length of copy for G4word
        blt		cr1,c64reverseUncached
        
        cmpwi	cr0,r10,0			// set cr0 beq if doubleword aligned
        cmpwi	cr1,r11,0			// set cr1 beq if word aligned
        beq		cr0,c64double		// doubleword aligned
        beq		cr1,G4word			// word aligned, use G3/G4 code
        cmpwi	r5,0				// set cr0 on byte count
        b		c64byte				// unaligned operands

c64reverseUncached:
        cmpwi	cr0,r10,0			// set cr0 beq if doubleword aligned
        cmpwi	cr1,r11,0			// set cr1 beq if word aligned
        beq		cr0,c64rdouble		// doubleword aligned so can use LD/STD
        beq		cr1,G4reverseWord	// word aligned, use G3/G4 code
        add		r6,r6,r5			// point to (end+1) of source and dest
        add		r4,r4,r5
        cmpwi	r5,0				// set cr0 on length
        b		c64rbyte			// copy a byte at a time
        
        

// Reverse doubleword copies.  This is used for all cached copies, and doubleword
// aligned uncached copies.
//		r4 = destination (32 or 64-bit ptr)
//		r5 = length (always 32 bits)
//		r6 = source (32 or 64-bit ptr)
//		cr5 = noncache, fixxlate, and restorex flags set

c64rdouble:
        add		r6,r6,r5			// point to (end+1) of source and dest
        add		r4,r4,r5
        rlwinm.	r7,r4,0,29,31		// r7 <- #bytes to doubleword align dest
        cmplw	cr1,r7,r5			// operand long enough to doubleword align?
        blt		cr1,c64rd0			// yes
        mr		r7,r5				// no
c64rd0:
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
        li		r9,-128				// start at next cache line
        mtctr	r8
        bt		noncache,c64rd3		// (HACK) Do not start a stream if noncachable...
        dcbt128	r9,r6,3				// start reverse stream
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
        beq		bcpydone			// done if no leftover bytes
        mtctr	r5
        
c64rbyte1:
        lbzu	r0,-1(r6)
        stbu	r0,-1(r4)
        bdnz	c64rbyte1

        b		bcpydone

