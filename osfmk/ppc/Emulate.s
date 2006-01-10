/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 	Emulate.s 

	Emulate instructions and traps.

	Lovingly crafted by Bill Angell using traditional methods and only natural or recycled materials.
	No animal products are used other than rendered otter bile and deep fried pork lard.

*/

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/cpu_capabilities.h>
#include <mach/machine/vm_param.h>
#include <assym.s>

#define traceInst 30
#define dssAllDone 29

;			General stuff what happens here:
;				1)	All general context saved, interrupts off, translation off
;				2)	Vector and floating point disabled, but there may be live context.
;					This code is responsible for saving and restoring what is used. This
;					includes exception states, java mode, etc.
;				3)	No attempt is made to resolve page faults.  PTE misses are handled
;					automatically, but actual faults (ala copyin/copyout) are not. If 
;					a fault does occur, the exception that caused entry to the emulation
;					routine is remapped to either an instruction or data miss (depending
;					upon the stage detected) and redrived through the exception handler.
;					The only time that an instruction fault can happen is when a different
;					processor removes a mapping between our original fault and when we
;					fetch the assisted instruction. For an assisted instruction, data
;					faults should not occur (except in the MP case).  For a purely
;					emulated instruction, faults can occur.
;
;


			.align	5
			.globl	EXT(Emulate)

LEXT(Emulate)

			bf--	pf64Bitb,emn64					; Skip if not 64-bit
			b		EXT(Emulate64)					; Jump to the 64-bit code...
			
emn64:		mfsprg	r31,0							; Get the per_proc
			lwz		r12,savesrr1+4(r13)				; Get the exception info
			rlwinm.	r0,r12,0,SRR1_PRG_ILL_INS_BIT,SRR1_PRG_ILL_INS_BIT	; Emulation candidate?
			lwz		r30,dgFlags(0)					; Get the flags
			beq+	eExit							; Nope, do not try to emulate...

			rlwinm.	r0,r30,0,enaDiagEMb,enaDiagEMb	; Do we want to try to emulate something?
			mfsprg	r28,2							; Get the processor features
			beq+	eExit							; No emulation allowed...

			rlwinm.	r28,r28,0,pfAltivecb,pfAltivecb	; Do we have Altivec on this machine?
			beq		eNoVect							; Nope, no Altivec...
			
			dssall									; We need to kill streams because we are going to flip to problem state
			sync

eNoVect:	bl		eIFetch							; Get the instruction image
			bne-	eRedriveAsISI					; Go redrive this as an ISI...	

			rlwinm.	r0,r10,0,0,5					; See if we have the "special" op code here
			rlwinm	r20,r10,16,22,31				; Set rS/rD and rA
			bne+	eExit							; Not special op, ignore...

			rlwinm	r0,r10,31,22,31					; Extract the sub op code
			crclr	cr1_eq							; Clear
			rlwimi	r20,r10,14,15,16				; Move bits 29 and 30 of instruction to 15 and 16 of DSISR
			cmplwi	r0,790							; lhbrx?
			rlwimi	r20,r10,8,17,17					; Move bit 25 to bit 17
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			cmplwi	r0,534							; lwbrx?
			rlwimi	r20,r10,3,18,21					; Move bit 21-24 to bit 18-21
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			cmplwi	r0,918							; sthbrx?
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			cmplwi	r0,662							; stwbrx?
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			cmplwi	r0,1014							; dcbz?
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			cmplwi	r0,533							; lswx?
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			cmplwi	r0,661							; stswx?
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			bne		cr1_eq,eNotIndex				; Go check non-index forms...

			rlwinm.	r21,r10,19,24,28				; Extract index to rA to build EA
			rlwinm	r22,r10,24,24,28				; Extract index to rB
			addi	r24,r13,saver0+4				; Point to the start of registers
			li		r19,0							; Assume 0 base
			beq		eZeroBase						; Yes...
			lwzx	r19,r24,r21						; Get the base register value
			
eZeroBase:	lwzx	r22,r24,r22						; Get the index value
			add		r22,r22,r19						; Get DAR
			b		eFinishUp						; Done, go finish up...
						
eNotIndex:	cmplwi	r0,725							; stswi?
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			cmplwi	r0,597							; lswi?
			cror	cr1_eq,cr1_eq,cr0_eq			; Remember
			bne		cr1,eExit						; Not one we handle...
	
			rlwinm.	r21,r10,19,24,28				; Extract index to rA to build EA
			addi	r24,r13,saver0+4				; Point to the start of registers
			li		r22,0							; Assume 0 base
			beq		eFinishUp						; Yes, it is...
			lwzx	r22,r24,r21						; Get the base register value
			
eFinishUp:	stw		r20,savedsisr(r13)				; Set the DSISR
			li		r11,T_ALIGNMENT					; Get the exception code
			stw		r22,savedar+4(r13)				; Save the DAR
			stw		r11,saveexception(r13)			; Set the exception code
			b		EXT(AlignAssist)				; Go emulate the handler...


eExit:		b		EXT(EmulExit)					; Just return for now...


;
;			Fetch the failing instruction.
;			Image returned in R10 if CR0_EQ is false, otherwise, an ISI should be generated/
;			The cr bit kernAccess is set if this was a kernel access.
;			R1 has the DSISR if access failed.
;

			.align	5

eIFetch:	lwz		r23,savesrr1+4(r13)				; Get old MSR
			mflr	r28								; Save return

			rlwinm.	r22,r23,0,MSR_PR_BIT,MSR_PR_BIT	; Within kernel?

			mfmsr	r30								; Save the MSR for now
			lwz		r23,savesrr0+4(r13)				; Get instruction address
			
			ori		r22,r30,lo16(MASK(MSR_DR)|MASK(MSR_RI))		; Set RI and DR onto access MSR

			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync
			
			lwz		r10,0(r23)						; Fetch the instruction
			
			mtmsr	r30								; Trans and RI off
			isync
			
			mtlr	r28								; Restore the LR
			blr										; Return with instruction image in R10


;
;			Redrive as an ISI
;

eRedriveAsISI:
			lwz		r6,savesrr1+4(r13)				; Get the srr1 value
			lwz		r4,SAVflags(r13)				; Pick up the flags
			li		r11,T_INSTRUCTION_ACCESS		; Set failing instruction fetch code
			rlwimi	r6,r1,0,0,4						; Move the DSISR bits to the SRR1
			oris	r4,r4,hi16(SAVredrive)			; Set the redrive bit
			stw		r11,saveexception(r13)			; Set the replacement code
			stw		r4,SAVflags(r13)				; Set redrive request
			stw		r6,savesrr1+4(r13)				; Set the srr1 value
			b		EXT(EmulExit)					; Bail out to handle ISI...


;
;			This code emulates instructions that have failed because of operand 
;			alignment.  We decode the DSISR to figure out what we need to do.
;
;			DSISR:
;				0001FC00 - Instruction designation
#define iFloat 12
#define iOptype1 15
#define iOptype2 16
#define iOptype3 18
#define iOptype4 19
#define iUpdate 17
#define iStore 20
#define iDouble 21
#define iNotify 22
;				000003E0 - Target/Source register
;				0000001F - Register to update if update form
;

			.align	5
			.globl	EXT(AlignAssist)

LEXT(AlignAssist)
			bf--	pf64Bitb,aan64					; Skip if not 64-bit
			b		EXT(AlignAssist64)				; Jump to the 64-bit code...
			
aan64:		lwz		r20,savedsisr(r13)				; Get the DSISR
			li		r0,0							; Assume we emulate
			mfsprg	r31,0							; Get the per_proc
			mtcrf	0x10,r20						; Put instruction ID in CR for later
			lwz		r21,spcFlags(r31)				; Grab the special flags
			stw		r0,savemisc3(r13)				; Assume that we emulate ok
			mtcrf	0x08,r20						; Put instruction ID in CR for later
			rlwinm.	r0,r21,0,runningVMbit,runningVMbit	; Are we running a VM?
			mtcrf	0x04,r20						; Put instruction ID in CR for later
			lwz		r22,savesrr1+4(r13)				; Get the SRR1
			bne-	aaPassAlong						; We are in a VM, no emulation for alignment exceptions...
			lwz		r19,dgFlags(0)					; Get the diagnostics flags
			crxor	iFloat,iOptype1,iOptype2		; Set this to 0 if both bits are either 0 or 1
			mr		r26,r20							; Save the DSISR
			rlwinm.	r0,r22,0,MSR_SE_BIT,MSR_SE_BIT	; Were we single stepping?
			lwz		r23,savedar+4(r13)				; Pick up the address that we want to access
			crnot	traceInst,cr0_eq				; Remember if trace is on
			
			rlwinm.	r0,r19,0,enaNotifyEMb,enaNotifyEMb	; Should we notify that an alignment exception happened?
			mfmsr	r30								; Save the MSR for now
			crnot	iNotify,cr0_eq					; Remember to tell someone we did this				
			li		r29,emfp0						; Point to work area
			crxor	iFloat,iFloat,iOptype3			; Set true if we have a floating point instruction
			dcbz	r29,r31							; Clear and allocate a cache line for us to work in
			rlwinm	r24,r20,3,24,28					; Get displacement to register to update if update form
			rlwimi	r20,r20,24,28,28				; Move load/store indication to the bottom of index
			ori		r22,r30,lo16(MASK(MSR_DR)|MASK(MSR_RI))		; Set RI onto access MSR
			rlwimi	r20,r20,26,27,27				; Move single/double indication to just above the bottom
			lis		r29,hi16(EXT(aaFPopTable))		; High part of FP branch table
			bf-		iFloat,aaNotFloat				; This is not a floating point instruction...
			ori		r29,r29,lo16(EXT(aaFPopTable))	; Low part of FP branch table
			
			rlwimi	r29,r20,0,22,28					; Index into table based upon register||iDouble||iStore
			mtctr	r29								; Get set to call the function	
			bt		iStore,aaFPstore				; This is an FP store...
		
;
;			Here we handle floating point loads
;			

aaFPload:	crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI
			isync
			
			lwz		r10,0(r23)						; Get the first word
			bf-		cr0_eq,aaLdNotDbl				; Jump out if we DSIed...
			bf		iDouble,aaLdNotDbl				; this is not a double...
			lwz		r11,4(r23)						; Get the second half
			
aaLdNotDbl:	mr		r4,r0							; Save the DAR if we failed the access
			
			mtmsr	r30								; Turn off translation again
			isync
			
			bf-		cr0_eq,aaRedriveAsDSI			; Go redrive this as a DSI...	
			
			stw		r10,emfp0(r31)					; Save the first half
			stw		r11,emfp0+4(r31)				; Save the second half, just in case we need it
			
			bctrl									; Go set the target FP register

			b		aaComExit						; All done, go exit...			
		
;
;			Here we handle floating point stores
;			

			.align	5

aaFPstore:	bctrl									; Go save the source FP register
			
			lwz		r10,emfp0(r31)					; Get first word
			crandc	iDouble,iDouble,iOptype4		; Change to 4-byte access if stfiwx
			lwz		r11,emfp0+4(r31)				; and the second
			bf+		iOptype4,aaNotstfiwx			; This is not a stfiwx...
			mr		r10,r11							; The stfiwx wants to store the second half

aaNotstfiwx:
			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI
			isync
			
			stw		r10,0(r23)						; Save the first word
			bf-		cr0_eq,aaStNotDbl				; Jump out if we DSIed...
			bf		iDouble,aaStNotDbl				; this is not a double...
			stw		r11,4(r23)						; Save the second half
			
aaStNotDbl:	mr		r4,r0							; Save the DAR if we failed the access
			mtmsr	r30								; Turn off
			isync
			
			bf-		cr0_eq,aaRedriveAsDSI			; Go redrive this as a DSI...

;
;			Common exit routines
;

aaComExit:	lwz		r10,savesrr0+4(r13)				; Get the failing instruction address
			add		r24,r24,r13						; Offset to update register
			li		r11,T_IN_VAIN					; Assume we are all done
			addi	r10,r10,4						; Step to the next instruction
			bf		iUpdate,aaComExNU				; Skip if not an update form...
			stw		r23,saver0+4(r24)				; Update the target
			
aaComExNU:	lwz		r9,SAVflags(r13)				; Get the flags
			stw		r10,savesrr0+4(r13)				; Set new PC
			bt-		traceInst,aaComExitrd			; We are tracing, go emulate trace...
			bf+		iNotify,aaComExGo				; Nothing special here, go...
	
			li		r11,T_ALIGNMENT					; Set the we just did an alignment exception....
			
aaComExGo:	b		EXT(EmulExit)					; We are done, no tracing on...


;
;			This is not a floating point operation
;
;			The table of these emulation routines is indexed by taking the low order 4 bits of
;			the instruction code in the DSISR and subtracting 7.  If this comes up negative,
;			the instruction is not to be emulated.  Then we add bit 0 of the code * 4.  This
;			gives us a fairly compact and almost unique index.  Both lwm and stmw map to 0 so
;			that one needs to be further reduced, and we end up with holes at a few indexes.
;

			.align	5

aaNotFloat:
			lis		r19,hi16(aaEmTable)				; Point to high part of table address
			rlwinm	r3,r26,24,26,29					; Isolate last 4 bits of op type * 4
			rlwimi	r19,r26,20,27,27				; Get bit 0 of instruction code * 4 into bottom of table base
			addic.	r3,r3,-28						; Subtract 7*4 to adjust index
			ori		r19,r19,lo16(aaEmTable)			; Low part of table address
			blt-	aaPassAlong						; We do not handle any of these (lwarx, stwcx., eciwx, ecowx)...
			add		r19,r19,r3						; Point to emulation routine
			rlwinm	r18,r26,30,24,28				; Get the target/source register displacement

			mtctr	r19								; Set the routine address
			
			bctr									; Go emulate the instruction...

;
;			This is the table of non-floating point emulation routines.
;			It is indexed by the code immediately above.
		
			.align	5							

aaEmTable:
			b		aaLmwStmw						; This for lmw/stmw
			b		aaLswx							; This for lwwx
			b		aaLswi							; This for lswi
			b		aaStswx							; This for stswx
			b		aaStswi							; This for stswi
			b		aaLwbrx							; This for lwbrx
			b		aaPassAlong						; This an invalid index (6)
			b		aaStwbrx						; This for stwbrx
			b		aaPassAlong						; This an invalid index (8)
			b		aaLhbrx							; This for lhbrx
			b		aaPassAlong						; This an invalid index (A)
			b		aaSthbrx						; This for sthbrx
			b		aaDcbz							; This for dcbz
			b		aaPassAlong						; This an invalid index (D)
			b		aaPassAlong						; This an invalid index (E)
			b		aaPassAlong						; This an invalid index (F)


;
;			Here we handle the set up for the lmw and stmw.  After that, we split off to the
;			individual routines.
;
;			Note also that after some set up, all of the string instructions come through here as well.
;
			.align	5
						
aaLmwStmw:
			rlwinm	r17,r18,31,1,29					; Convert doublword based index to words
			li		r28,0							; Set no extra bytes to move (used for string instructions)
			subfic	r17,r17,32*4					; Calculate the length of the transfer

aaLSComm:	addi	r19,r13,saver0+4				; Offset to registers in savearea
			mr		r16,r23							; Make a hunk pointer
			
			bt		iUpdate,aaStmw					; This is the stmw...
			
;
;			Load multiple word
;

aaLmwNxt:	cmplwi	cr1,r17,8*4						; Is there enough to move 8?
			blt-	cr1,aaLmwNxtH					; Not enough for a full hunk...
			subi	r17,r17,8*4						; Back off for another hunk
			
			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI
			isync
		
			lwz		r2,0(r16)						; Load word 0
			bf-		cr0_eq,aaLmwB1					; Error, bail...
			lwz		r15,4(r16)						; Load word 1
			bf-		cr0_eq,aaLmwB1					; Error, bail...
			lwz		r14,8(r16)						; Load word 2
			bf-		cr0_eq,aaLmwB1					; Error, bail...
			lwz		r5,12(r16)						; Load word 3
			bf-		cr0_eq,aaLmwB1					; Error, bail...
			lwz		r6,16(r16)						; Load word 4
			bf-		cr0_eq,aaLmwB1					; Error, bail...
			lwz		r7,20(r16)						; Load word 5
			bf-		cr0_eq,aaLmwB1					; Error, bail...
			lwz		r8,24(r16)						; Load word 6
			bf-		cr0_eq,aaLmwB1					; Error, bail...
			lwz		r9,28(r16)						; Load word 7
		
aaLmwB1:	mr		r4,r0							; Remember DAR, jus in case we failed the access
			mtmsr	r30								; Turn off DR, RI
			isync

			bf-		cr0_eq,aaRedriveAsDSI			; We failed, go redrive this as a DSI...

			addi	r16,r16,8*4						; Point up to next input aread
		
			stwx	r2,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r15,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r14,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r5,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r6,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r7,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r8,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r9,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed

			b		aaLmwNxt						; Do the next hunk...

			.align	5
			
aaLmwNxtH:	cmplwi	cr1,r17,4*4						; Do we have 4 left?
			blt		cr1,aaLmwL4						; Nope...

			subi	r17,r17,4*4						; Set count properly
			
			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync
		
			lwz		r2,0(r16)						; Load word 0
			bf-		cr0_eq,aaLmwB2					; Error, bail...
			lwz		r15,4(r16)						; Load word 1
			bf-		cr0_eq,aaLmwB2					; Error, bail...
			lwz		r14,8(r16)						; Load word 2
			bf-		cr0_eq,aaLmwB2					; Error, bail...
			lwz		r5,12(r16)						; Load word 3
		
aaLmwB2:	mr		r4,r0							; Remember DAR, jus in case we failed the access
			mtmsr	r30								; Turn off DR, RI
			isync

			bf-		cr0_eq,aaRedriveAsDSI			; We failed, go redrive this as a DSI...
		
			addi	r16,r16,4*4						; Point up to next input aread
			
			stwx	r2,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r15,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r14,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			stwx	r5,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed

aaLmwL4:	or.		r5,r17,r28						; Do we have anything left?
			cmplwi	cr1,r17,(2*4)					; Do we have one, two, or three full words left?
			cmplwi	cr2,r17,0						; Do we have no full words left?
			beq		aaComExit						; Nothing left...

			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync

			beq-	cr2,aaLmwBy						; No full words, get bytes...
			
			lwz		r2,0(r16)						; Pick up first word
			bf-		cr0_eq,aaLmwDn					; Read failed, escape...
			addi	r16,r16,4						; Next input location
			blt		cr1,aaLmwBy						; We only had one, we are done...

			lwz		r15,0(r16)						; Pick up second word
			bf-		cr0_eq,aaLmwDn					; Read failed, escape...
			addi	r16,r16,4						; Next input location
			beq		cr1,aaLmwBy						; We had two, we are done...

			lwz		r14,0(r16)						; Load word 3
			addi	r16,r16,4						; Next input location

aaLmwBy:	cmplwi	cr2,r28,0						; Any trailing bytes to do?
			li		r8,0							; Clear second trailing byte
			cmplwi	cr1,r28,2						; Check for 1, 2, or 3
			li		r9,0							; Clear third trailing byte
			beq+	cr2,aaLmwDn						; No trailing bytes...
			
			lbz		r5,0(r16)						; Pick up first trailing byte
			bf-		cr0_eq,aaLmwDn					; Read failed, escape...
			blt		cr1,aaLmwDn						; We only had one, we are done...

			lbz		r8,1(r16)						; Pick up second trailing byte
			bf-		cr0_eq,aaLmwDn					; Read failed, escape...
			beq		cr1,aaLmwDn						; We had two, we are done...

			lbz		r9,2(r16)						; Get last trailing byte
			

aaLmwDn:	rlwinm	r5,r5,24,0,7					; Move first byte to top
			cmplwi	cr2,r17,0						; Any full words to do?
			mr		r4,r0							; Remember DAR, just in case we failed the access
			rlwimi	r9,r8,8,16,23					; Move second byte above third byte
			cmplwi	cr1,r17,(2*4)					; Do we have one, two, or three full words left?
			mr		r3,r30							; Set the normal MSR
			rlwimi	r5,r9,8,8,23					; Move bytes 1 and 2 after 0

			mtmsr	r30								; Turn off DR, RI
			isync

			bf-		cr0_eq,aaRedriveAsDSI			; We failed, go redrive this as a DSI...

			beq-	cr2,aaLmwCb						; No full words, copy bytes...

			stwx	r2,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			blt		cr1,aaLmwCb						; We only had one, we are done...
			
			stwx	r15,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			beq		cr1,aaLmwCb						; We had two, we are done...

			stwx	r14,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed

aaLmwCb:	mr.		r28,r28							; Any trailing bytes to do?
			beq+	aaComExit						; Nope, leave...

			stwx	r5,r19,r18						; Store register
						
			b		aaComExit						; We are done....

;
;			Store multiple word
;

			.align	5

aaStmw:
			crclr	iUpdate							; Make sure we do not think this is an update form

aaStmwNxt:	cmplwi	cr1,r17,8*4						; Is there enough to move 8?
			blt-	cr1,aaStmwNxtH					; Not enough for a full hunk...
			subi	r17,r17,8*4						; Back off for another hunk
		
			lwzx	r2,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r15,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r14,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r5,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r6,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r7,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r8,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r9,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			
			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync

			stw		r2,0(r16)						; Store word 0
			bf-		cr0_eq,aaStmwB1					; Error, bail...
			stw		r15,4(r16)						; Store word 1
			bf-		cr0_eq,aaStmwB1					; Error, bail...
			stw		r14,8(r16)						; Store word 2
			bf-		cr0_eq,aaStmwB1					; Error, bail...
			stw		r5,12(r16)						; Store word 3
			bf-		cr0_eq,aaStmwB1					; Error, bail...
			stw		r6,16(r16)						; Store word 4
			bf-		cr0_eq,aaStmwB1					; Error, bail...
			stw		r7,20(r16)						; Store word 5
			bf-		cr0_eq,aaStmwB1					; Error, bail...
			stw		r8,24(r16)						; Store word 6
			bf-		cr0_eq,aaStmwB1					; Error, bail...
			stw		r9,28(r16)						; Store word 7
		
			addi	r16,r16,8*4						; Point up to next output aread
		
		
aaStmwB1:	mr		r4,r0							; Remember DAR, jus in case we failed the access
			mtmsr	r30								; Normal MSR
			isync

			bt-		cr0_eq,aaStmwNxt				; We have more to do and no failed access...
			b		aaRedriveAsDSI					; We failed, go redrive this as a DSI...

			.align	5
			
aaStmwNxtH:	cmplwi	cr1,r17,(4*4)					; Do we have at least 4 left?
			blt		cr1,aaStmwL4					; Nope...
			subi	r17,r17,4*4						; Set count properly

			lwzx	r2,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r15,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r14,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			lwzx	r5,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			
			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI
			isync
		
			stw		r2,0(r16)						; Store word 0
			bf-		cr0_eq,aaStmwB2					; Error, bail...
			stw		r15,4(r16)						; Store word 1
			bf-		cr0_eq,aaStmwB2					; Error, bail...
			stw		r14,8(r16)						; Store word 2
			bf-		cr0_eq,aaStmwB2					; Error, bail...
			stw		r5,12(r16)						; Store word 3

			addi	r16,r16,4*4						; Point up to next input aread
		
aaStmwB2:	mr		r4,r0							; Remember DAR, jus in case we failed the access
			mtmsr	r30								; Normal MSR
			isync

			bf-		cr0_eq,aaRedriveAsDSI			; We failed, go redrive this as a DSI...

aaStmwL4:	or.		r5,r17,r28						; Do we have anything left to do?
			cmplwi	cr1,r17,(2*4)					; Do we have one, two, or three left?
			cmplwi	cr2,r17,0						; Do we have no full words left?
			beq		aaComExit						; Nothing left...

			beq-	cr2,aaStmwBy1					; No full words, check out bytes

			lwzx	r2,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			blt		cr1,aaStmwBy1					; We only had one, go save it...
			
			lwzx	r15,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			beq		cr1,aaStmwBy1					; We had two, go save it...
			
			lwzx	r14,r19,r18						; Store register
			addi	r18,r18,8						; Next register
			rlwinm	r18,r18,0,24,28					; Wrap back to 0 if needed
			
aaStmwBy1:	mr.		r28,r28							; Do we have any trailing bytes?
			beq+	aaStmwSt						; Nope...
			
			lwzx	r5,r19,r18						; Yes, pick up one extra register
			
aaStmwSt:	crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI
			isync

			beq-	cr2,aaStmwBy2					; No words, check trailing bytes...					

			stw		r2,0(r16)						; Save first word
			bf-		cr0_eq,aaStmwDn					; Store failed, escape...
			addi	r16,r16,4						; Bump sink
			blt		cr1,aaStmwBy2					; We only had one, we are done...

			stw		r15,0(r16)						; Save second word
			bf-		cr0_eq,aaStmwDn					; Store failed, escape...
			addi	r16,r16,4						; Bump sink
			beq		cr1,aaStmwBy2					; We had two, we are done...

			stw		r14,0(r16)						; Save third word
			bf-		cr0_eq,aaStmwDn					; Store failed, escape...
			addi	r16,r16,4						; Bump sink
				
aaStmwBy2:	rlwinm	r2,r5,8,24,31					; Get byte 0
			cmplwi	cr2,r28,0						; Any trailing bytes to do?
			rlwinm	r14,r5,24,24,31					; Get byte 3
			li		r8,0							; Clear second trailing byte
			cmplwi	cr1,r28,2						; Check for 1, 2, or 3
			li		r9,0							; Clear third trailing byte
			beq+	cr2,aaStmwDn					; No trailing bytes...
			rlwinm	r15,r5,16,24,31					; Get byte 1

			stb		r2,0(r16)						; Save first byte
			bf-		cr0_eq,aaStmwDn					; Read failed, escape...
			blt		cr1,aaStmwDn					; We only had one, we are done...

			stb		r15,1(r16)						; Save second byte
			bf-		cr0_eq,aaStmwDn					; Read failed, escape...
			beq		cr1,aaStmwDn					; We had two, we are done...

			stb		r14,2(r16)						; Save third byte

aaStmwDn:	mr		r4,r0							; Remember DAR, jus in case we failed the access
			mtmsr	r30								; Normal MSR
			isync

			bf-		cr0_eq,aaRedriveAsDSI			; We failed, go redrive this as a DSI...

			b		aaComExit						; We are done....

	
;
;			Load String Indexed
;

			.align	5
			
aaLswx:		lwz		r17,savexer+4(r13)				; Pick up the XER
			crclr	iUpdate							; Make sure we think this the load form
			rlwinm.	r25,r17,0,25,31					; Get the number of bytes to load
			rlwinm	r28,r17,0,30,31					; Get the number of bytes past an even word
			beq-	aaComExit						; Do nothing if 0 length...
			xor		r17,r25,r28						; Round down to an even word boundary
			b		aaLSComm						; Join up with common load/store code...

	
;
;			Load String Immediate
;

			.align	5

aaLswi:		mr		r9,r23							; Save the DAR
			bl		eIFetch							; Get the instruction image
			bne-	eRedriveAsISI					; Go redrive this as an ISI...	
			rlwinm	r25,r10,21,27,31				; Get the number of bytes to load
			crclr	iUpdate							; Make sure we think this the load form
			subi	r25,r25,1						; Back off by 1
			rlwinm	r25,r25,0,27,31					; Clear back down
			addi	r25,r25,1						; Add back the 1 to convert 0 to 32
			rlwinm	r28,r25,0,30,31					; Get the number of bytes past an even word
			xor		r17,r25,r28						; Round down to an even word boundary
			mr		r23,r9							; Move back the DAR
			b		aaLSComm						; Join up with common load/store code...
	
;
;			Store String Indexed
;

			.align	5

aaStswx:	lwz		r17,savexer+4(r13)				; Pick up the XER
			crclr	iUpdate							; Make sure this is clear in case we have 0 length
			rlwinm.	r25,r17,0,25,31					; Get the number of bytes to load
			rlwinm	r28,r17,0,30,31					; Get the number of bytes past an even word
			beq-	aaComExit						; Do nothing if 0 length...
			xor		r17,r25,r28						; Round down to an even word boundary
			crset	iUpdate							; Make sure we think this the store form
			b		aaLSComm						; Join up with common load/store code...

	
;
;			Store String Immediate
;

			.align	5

aaStswi:	mr		r9,r23							; Save the DAR
			bl		eIFetch							; Get the instruction image
			bne-	eRedriveAsISI					; Go redrive this as an ISI...	
			rlwinm	r25,r10,21,27,31				; Get the number of bytes to load
			crclr	iUpdate							; Make sure we think this the load form
			subi	r25,r25,1						; Back off by 1
			rlwinm	r25,r25,0,27,31					; Clear back down
			addi	r25,r25,1						; Add back the 1 to convert 0 to 32
			rlwinm	r28,r25,21,30,31				; Get the number of bytes past an even word
			xor		r17,r25,r28						; Round down to an even word boundary
			mr		r23,r9							; Move back the DAR
			b		aaLSComm						; Join up with common load/store code...
	

;
;			Load byte-reversed word
;

			.align	5

aaLwbrx:
			add		r18,r18,r13						; Index to source register

			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync
		
			lwz		r11,0(r23)						; Load the word
		
			mr		r4,r0							; Save the DAR if we failed the access
			mtmsr	r30								; Restore normal MSR
			isync
			
			bf-		cr0_eq,aaRedriveAsDSI			; We failed, go redrive this as a DSI...
			
			rlwinm	r10,r11,8,0,31					; Get byte 0 to 3 and byte 2 to 1
			rlwimi	r10,r11,24,16,23				; Move byte 1 to byte 2
			rlwimi	r10,r11,24,0,7					; Move byte 3 to byte 0
		
			stw		r10,saver0+4(r18)				; Set the register

			b		aaComExit						; All done, go exit...



;
;			Store byte-reversed word
;

			.align	5

aaStwbrx:
			add		r18,r18,r13						; Index to source register
			lwz		r11,saver0+4(r18)				; Get the register to store

			rlwinm	r10,r11,8,0,31					; Get byte 0 to 3 and byte 2 to 1
			rlwimi	r10,r11,24,16,23				; Move byte 1 to byte 2
			rlwimi	r10,r11,24,0,7					; Move byte 3 to byte 0
			
			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync
		
			stw		r10,0(r23)						; Store the reversed halfword
		
			mr		r4,r0							; Save the DAR if we failed the access
			mtmsr	r30								; Restore normal MSR
			isync
			
			bt+		cr0_eq,aaComExit				; All done, go exit...
			b		aaRedriveAsDSI					; We failed, go redrive this as a DSI...	



;
;			Load byte-reversed halfword
;

			.align	5

aaLhbrx:
			add		r18,r18,r13						; Index to source register

			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync
		
			lhz		r11,0(r23)						; Load the halfword
		
			mr		r4,r0							; Save the DAR if we failed the access
			mtmsr	r30								; Restore normal MSR
			isync

			bf-		cr0_eq,aaRedriveAsDSI			; We failed, go redrive this as a DSI...
			
			rlwinm	r10,r11,8,16,23					; Rotate bottom byte up one and clear everything else
			rlwimi	r10,r11,24,24,31				; Put old second from bottom into bottom
		
			stw		r10,saver0+4(r18)				; Set the register

			b		aaComExit						; All done, go exit...


;
;			Store byte-reversed halfword
;

			.align	5

aaSthbrx:
			add		r18,r18,r13						; Index to source register
			lwz		r10,saver0+4(r18)				; Get the register to store
			rlwinm	r10,r10,8,0,31					; Rotate bottom byte up one
			rlwimi	r10,r10,16,24,31				; Put old second from bottom into bottom
			
			crset	cr0_eq							; Set this to see if we failed
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync
		
			sth		r10,0(r23)						; Store the reversed halfword
		
			mr		r4,r0							; Save the DAR if we failed the access
			mtmsr	r30								; Restore normal MSR
			isync

			bt+		cr0_eq,aaComExit				; All done, go exit...
			b		aaRedriveAsDSI					; We failed, go redrive this as a DSI...	

;
;			Data cache block zero
;

			.align	5

aaDcbz:			
            lwz     r0,savesrr0+4(r13)              ; get instruction address
            li		r4,_COMM_PAGE_BASE_ADDRESS
			rlwinm	r23,r23,0,0,26					; Round EA back to a 32-byte boundary
            sub     r4,r0,r4                        ; compute instruction offset from base of commpage
            cmplwi  r4,_COMM_PAGE_AREA_USED         ; did fault occur in commpage?
            bge+    aaDcbz1                         ; skip if not in commpage
            lwz		r4,savecr(r13)                  ; if we take a dcbz in the commpage...
            rlwinm	r4,r4,0,0,27                    ; ...clear users cr7 as a flag for commpage code
            stw		r4,savecr(r13)
aaDcbz1:
			crset	cr0_eq							; Set this to see if we failed
			li		r0,0							; Clear this out
			mtmsr	r22								; Flip DR, RI, and maybe PR on
			isync
			
			stw		r0,0(r23)						; Clear word	
			bne-	aaDcbzXit						; Got DSI, we are stopping...	
			stw		r0,4(r23)						; Clear word		
			bne-	aaDcbzXit						; Got DSI, we are stopping...	
			stw		r0,8(r23)						; Clear word		
			bne-	aaDcbzXit						; Got DSI, we are stopping...	
			stw		r0,12(r23)						; Clear word		
			bne-	aaDcbzXit						; Got DSI, we are stopping...	
			stw		r0,16(r23)						; Clear word		
			bne-	aaDcbzXit						; Got DSI, we are stopping...	
			stw		r0,20(r23)						; Clear word		
			bne-	aaDcbzXit						; Got DSI, we are stopping...	
			stw		r0,24(r23)						; Clear word		
			bne-	aaDcbzXit						; Got DSI, we are stopping...	
			stw		r0,28(r23)						; Clear word		
			
aaDcbzXit:	mr		r4,r0							; Save the DAR if we failed the access
			mtmsr	r30								; Restore normal MSR
			isync

			crclr	iUpdate							; Make sure we do not think this is an update form
			
			bt+		cr0_eq,aaComExit				; All done, go exit...
			b		aaRedriveAsDSI					; We failed, go redrive this as a DSI...	


;
;			Unhandled alignment exception, pass it along
;

aaPassAlong:
			li		r0,1							; Indicate that we failed to emulate
			stw		r0,savemisc3(r13)				; Assume that we emulate ok
			b		EXT(EmulExit)					




;
;			We go here to emulate a trace exception after we have handled alignment error
;

			.align	5
			
aaComExitrd:
			oris	r9,r9,hi16(SAVredrive)			; Set the redrive bit
			li		r11,T_TRACE						; Set trace interrupt
			rlwinm	r12,r12,0,16,31					; Clear top half of SRR1
			stw		r9,SAVflags(r13)				; Set the flags
			stw		r11,saveexception(r13)			; Set the exception code
			b		EXT(EmulExit)					; Exit and do trace interrupt...
			


;
;			Redrive as a DSI

aaRedriveAsDSI:
			mr		r20,r1							; Save the DSISR
			mr		r21,r4
			lwz		r4,SAVflags(r13)				; Pick up the flags
			li		r11,T_DATA_ACCESS				; Set failing data access code
			oris	r4,r4,hi16(SAVredrive)			; Set the redrive bit
			stw		r20,savedsisr(r13)				; Set the DSISR of failed access
			stw		r21,savedar+4(r13)				; Set the address of the failed access
			stw		r11,saveexception(r13)			; Set the replacement code
			stw		r4,SAVflags(r13)				; Set redrive request
			b		EXT(EmulExit)					; Bail out to handle ISI...



;
;			Table of functions to load or store floating point registers
;			This table is indexed reg||size||dir.  That means that each
;			like load/store pair (e.g., lfd f31/stfd f31) are within the same
;			quadword, which is the current ifetch size.  We expect most of the
;			unaligned accesses to be part of copies, therefore, with this
;			organization, we will save the ifetch of the store after the load.
;

			.align	10								; Make sure we are on a 1k boundary
			.globl	EXT(aaFPopTable)
			
LEXT(aaFPopTable)
			lfs		f0,emfp0(r31)					; Load single variant
			blr

			stfs	f0,emfp0(r31)					; Store single variant
			blr
			
			lfd		f0,emfp0(r31)					; Load double variant
			blr
			
			stfd	f0,emfp0(r31)					; Store double variant
			blr

			lfs		f1,emfp0(r31)					; Load single variant
			blr

			stfs	f1,emfp0(r31)					; Store single variant
			blr
			
			lfd		f1,emfp0(r31)					; Load double variant
			blr
			
			stfd	f1,emfp0(r31)					; Store double variant
			blr

			lfs		f2,emfp0(r31)					; Load single variant
			blr

			stfs	f2,emfp0(r31)					; Store single variant
			blr
			
			lfd		f2,emfp0(r31)					; Load double variant
			blr
			
			stfd	f2,emfp0(r31)					; Store double variant
			blr

			lfs		f3,emfp0(r31)					; Load single variant
			blr

			stfs	f3,emfp0(r31)					; Store single variant
			blr
			
			lfd		f3,emfp0(r31)					; Load double variant
			blr
			
			stfd	f3,emfp0(r31)					; Store double variant
			blr

			lfs		f4,emfp0(r31)					; Load single variant
			blr

			stfs	f4,emfp0(r31)					; Store single variant
			blr
			
			lfd		f4,emfp0(r31)					; Load double variant
			blr
			
			stfd	f4,emfp0(r31)					; Store double variant
			blr

			lfs		f5,emfp0(r31)					; Load single variant
			blr

			stfs	f5,emfp0(r31)					; Store single variant
			blr
			
			lfd		f5,emfp0(r31)					; Load double variant
			blr
			
			stfd	f5,emfp0(r31)					; Store double variant
			blr

			lfs		f6,emfp0(r31)					; Load single variant
			blr

			stfs	f6,emfp0(r31)					; Store single variant
			blr
			
			lfd		f6,emfp0(r31)					; Load double variant
			blr
			
			stfd	f6,emfp0(r31)					; Store double variant
			blr

			lfs		f7,emfp0(r31)					; Load single variant
			blr

			stfs	f7,emfp0(r31)					; Store single variant
			blr
			
			lfd		f7,emfp0(r31)					; Load double variant
			blr
			
			stfd	f7,emfp0(r31)					; Store double variant
			blr

			lfs		f8,emfp0(r31)					; Load single variant
			blr

			stfs	f8,emfp0(r31)					; Store single variant
			blr
			
			lfd		f8,emfp0(r31)					; Load double variant
			blr
			
			stfd	f8,emfp0(r31)					; Store double variant
			blr

			lfs		f9,emfp0(r31)					; Load single variant
			blr

			stfs	f9,emfp0(r31)					; Store single variant
			blr
			
			lfd		f9,emfp0(r31)					; Load double variant
			blr
			
			stfd	f9,emfp0(r31)					; Store double variant
			blr

			lfs		f10,emfp0(r31)					; Load single variant
			blr

			stfs	f10,emfp0(r31)					; Store single variant
			blr
			
			lfd		f10,emfp0(r31)					; Load double variant
			blr
			
			stfd	f10,emfp0(r31)					; Store double variant
			blr

			lfs		f11,emfp0(r31)					; Load single variant
			blr

			stfs	f11,emfp0(r31)					; Store single variant
			blr
			
			lfd		f11,emfp0(r31)					; Load double variant
			blr
			
			stfd	f11,emfp0(r31)					; Store double variant
			blr

			lfs		f12,emfp0(r31)					; Load single variant
			blr

			stfs	f12,emfp0(r31)					; Store single variant
			blr
			
			lfd		f12,emfp0(r31)					; Load double variant
			blr
			
			stfd	f12,emfp0(r31)					; Store double variant
			blr

			lfs		f13,emfp0(r31)					; Load single variant
			blr

			stfs	f13,emfp0(r31)					; Store single variant
			blr
			
			lfd		f13,emfp0(r31)					; Load double variant
			blr
			
			stfd	f13,emfp0(r31)					; Store double variant
			blr

			lfs		f14,emfp0(r31)					; Load single variant
			blr

			stfs	f14,emfp0(r31)					; Store single variant
			blr
			
			lfd		f14,emfp0(r31)					; Load double variant
			blr
			
			stfd	f14,emfp0(r31)					; Store double variant
			blr

			lfs		f15,emfp0(r31)					; Load single variant
			blr

			stfs	f15,emfp0(r31)					; Store single variant
			blr
			
			lfd		f15,emfp0(r31)					; Load double variant
			blr
			
			stfd	f15,emfp0(r31)					; Store double variant
			blr

			lfs		f16,emfp0(r31)					; Load single variant
			blr

			stfs	f16,emfp0(r31)					; Store single variant
			blr
			
			lfd		f16,emfp0(r31)					; Load double variant
			blr
			
			stfd	f16,emfp0(r31)					; Store double variant
			blr

			lfs		f17,emfp0(r31)					; Load single variant
			blr

			stfs	f17,emfp0(r31)					; Store single variant
			blr
			
			lfd		f17,emfp0(r31)					; Load double variant
			blr
			
			stfd	f17,emfp0(r31)					; Store double variant
			blr

			lfs		f18,emfp0(r31)					; Load single variant
			blr

			stfs	f18,emfp0(r31)					; Store single variant
			blr
			
			lfd		f18,emfp0(r31)					; Load double variant
			blr
			
			stfd	f18,emfp0(r31)					; Store double variant
			blr

			lfs		f19,emfp0(r31)					; Load single variant
			blr

			stfs	f19,emfp0(r31)					; Store single variant
			blr
			
			lfd		f19,emfp0(r31)					; Load double variant
			blr
			
			stfd	f19,emfp0(r31)					; Store double variant
			blr

			lfs		f20,emfp0(r31)					; Load single variant
			blr

			stfs	f20,emfp0(r31)					; Store single variant
			blr
			
			lfd		f20,emfp0(r31)					; Load double variant
			blr
			
			stfd	f20,emfp0(r31)					; Store double variant
			blr

			lfs		f21,emfp0(r31)					; Load single variant
			blr

			stfs	f21,emfp0(r31)					; Store single variant
			blr
			
			lfd		f21,emfp0(r31)					; Load double variant
			blr
			
			stfd	f21,emfp0(r31)					; Store double variant
			blr

			lfs		f22,emfp0(r31)					; Load single variant
			blr

			stfs	f22,emfp0(r31)					; Store single variant
			blr
			
			lfd		f22,emfp0(r31)					; Load double variant
			blr
			
			stfd	f22,emfp0(r31)					; Store double variant
			blr

			lfs		f23,emfp0(r31)					; Load single variant
			blr

			stfs	f23,emfp0(r31)					; Store single variant
			blr
			
			lfd		f23,emfp0(r31)					; Load double variant
			blr
			
			stfd	f23,emfp0(r31)					; Store double variant
			blr

			lfs		f24,emfp0(r31)					; Load single variant
			blr

			stfs	f24,emfp0(r31)					; Store single variant
			blr
			
			lfd		f24,emfp0(r31)					; Load double variant
			blr
			
			stfd	f24,emfp0(r31)					; Store double variant
			blr

			lfs		f25,emfp0(r31)					; Load single variant
			blr

			stfs	f25,emfp0(r31)					; Store single variant
			blr
			
			lfd		f25,emfp0(r31)					; Load double variant
			blr
			
			stfd	f25,emfp0(r31)					; Store double variant
			blr

			lfs		f26,emfp0(r31)					; Load single variant
			blr

			stfs	f26,emfp0(r31)					; Store single variant
			blr
			
			lfd		f26,emfp0(r31)					; Load double variant
			blr
			
			stfd	f26,emfp0(r31)					; Store double variant
			blr

			lfs		f27,emfp0(r31)					; Load single variant
			blr

			stfs	f27,emfp0(r31)					; Store single variant
			blr
			
			lfd		f27,emfp0(r31)					; Load double variant
			blr
			
			stfd	f27,emfp0(r31)					; Store double variant
			blr

			lfs		f28,emfp0(r31)					; Load single variant
			blr

			stfs	f28,emfp0(r31)					; Store single variant
			blr
			
			lfd		f28,emfp0(r31)					; Load double variant
			blr
			
			stfd	f28,emfp0(r31)					; Store double variant
			blr

			lfs		f29,emfp0(r31)					; Load single variant
			blr

			stfs	f29,emfp0(r31)					; Store single variant
			blr
			
			lfd		f29,emfp0(r31)					; Load double variant
			blr
			
			stfd	f29,emfp0(r31)					; Store double variant
			blr

			lfs		f30,emfp0(r31)					; Load single variant
			blr

			stfs	f30,emfp0(r31)					; Store single variant
			blr
			
			lfd		f30,emfp0(r31)					; Load double variant
			blr
			
			stfd	f30,emfp0(r31)					; Store double variant
			blr

			lfs		f31,emfp0(r31)					; Load single variant
			blr

			stfs	f31,emfp0(r31)					; Store single variant
			blr
			
			lfd		f31,emfp0(r31)					; Load double variant
			blr
			
			stfd	f31,emfp0(r31)					; Store double variant
			blr

