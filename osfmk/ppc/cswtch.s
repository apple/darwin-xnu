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
/*
 * @OSF_COPYRIGHT@
 */

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <cpus.h>
#include <assym.s>
#include <debug.h>
#include <mach/ppc/vm_param.h>
#include <ppc/exception.h>
#include <ppc/savearea.h>

#define FPVECDBG 0
#define GDDBG 0

	.text
	
/*
 * void     load_context(thread_t        thread)
 *
 * Load the context for the first kernel thread, and go.
 *
 * NOTE - if DEBUG is set, the former routine is a piece
 * of C capable of printing out debug info before calling the latter,
 * otherwise both entry points are identical.
 */

			.align	5
			.globl	EXT(load_context)

LEXT(load_context)

			.globl	EXT(Load_context)

LEXT(Load_context)

/*
 * Since this is the first thread, we came in on the interrupt
 * stack. The first thread never returns, so there is no need to
 e worry about saving its frame, hence we can reset the istackptr
 * back to the saved_state structure at it's top
 */
			

/*
 * get new thread pointer and set it into the active_threads pointer
 *
 */
	
			mfsprg	r6,0
			lwz		r0,PP_INTSTACK_TOP_SS(r6)
			stw		r0,PP_ISTACKPTR(r6)
			stw		r3,PP_ACTIVE_THREAD(r6)

/* Find the new stack and store it in active_stacks */
	
			lwz		r12,PP_ACTIVE_STACKS(r6)
			lwz		r1,THREAD_KERNEL_STACK(r3)
			lwz		r9,THREAD_TOP_ACT(r3)			/* Point to the active activation */
			mtsprg		1,r9
			stw		r1,0(r12)
			li		r0,0							/* Clear a register */
			lwz		r8,ACT_MACT_PCB(r9)				/* Get the savearea used */
			rlwinm	r7,r8,0,0,19					/* Switch to savearea base */
			lwz		r11,SAVprev(r8)					/* Get the previous savearea */
			mfmsr	r5								/* Since we are passing control, get our MSR values */
			lwz		r1,saver1(r8)					/* Load new stack pointer */
			stw		r0,saver3(r8)					/* Make sure we pass in a 0 for the continuation */
			lwz		r7,SACvrswap(r7)				/* Get the translation from virtual to real */
			stw		r0,FM_BACKPTR(r1)				/* zero backptr */
			stw		r5,savesrr1(r8)					/* Pass our MSR to the new guy */
			xor		r3,r7,r8						/* Get the physical address of the new context save area */
			stw		r11,ACT_MACT_PCB(r9)			/* Unstack our savearea */
			b		EXT(exception_exit)				/* Go end it all... */
	
/* struct thread_shuttle *Switch_context(struct thread_shuttle   *old,
 * 				      	 void                    (*cont)(void),
 *				         struct thread_shuttle   *new)
 *
 * Switch from one thread to another. If a continuation is supplied, then
 * we do not need to save callee save registers.
 *
 */

/* void Call_continuation( void (*continuation)(void),  vm_offset_t stack_ptr)
 */

			.align	5
			.globl	EXT(Call_continuation)

LEXT(Call_continuation)

			mtlr	r3
			mr		r1, r4							/* Load new stack pointer */
			blr										/* Jump to the continuation */

/*
 * Get the old kernel stack, and store into the thread structure.
 * See if a continuation is supplied, and skip state save if so.
 * NB. Continuations are no longer used, so this test is omitted,
 * as should the second argument, but it is in generic code.
 * We always save state. This does not hurt even if continuations
 * are put back in.
 */

/* 			Context switches are double jumps.  We pass the following to the
 *			context switch firmware call:
 *
 *			R3  = switchee's savearea
 *			R4  = old thread
 *			R5  = new SRR0
 *			R6  = new SRR1
 *
 *			savesrr0 is set to go to switch_in
 *			savesrr1 is set to uninterruptible with translation on
 */


			.align	5
			.globl	EXT(Switch_context)

LEXT(Switch_context)

			mfsprg	r12,0							; Get the per_proc block
			lwz		r10,PP_ACTIVE_STACKS(r12)		; Get the pointer to the current stack
#if DEBUG
			lwz		r11,PP_ISTACKPTR(r12)			; (DEBUG/TRACE) make sure we are not
			mr.		r11,r11							; (DEBUG/TRACE) on the interrupt
			bne+	notonintstack					; (DEBUG/TRACE) stack
			BREAKPOINT_TRAP
notonintstack:
#endif	
 			stw		r4,THREAD_CONTINUATION(r3)		; Set continuation into the thread
			cmpwi	cr1,r4,0						; used waaaay down below 
			lwz		r7,0(r10)						; Get the current stack
/*
 * Make the new thread the current thread.
 */
	
			stw		r7,THREAD_KERNEL_STACK(r3)		; Remember the current stack in the thread (do not need???)
			stw		r5,	PP_ACTIVE_THREAD(r12)		; Make the new thread current
			
			lwz		r11,THREAD_KERNEL_STACK(r5)		; Get the new stack pointer
		
			lwz		r5,THREAD_TOP_ACT(r5)			; Get the new activation
			mtsprg		1,r5
			lwz		r7,CTHREAD_SELF(r5)				; Pick up the user assist word
			lwz		r8,ACT_MACT_PCB(r5)				; Get the PCB for the new guy
			
#if 0
			lwz		r0,SAVflags(r8)					; (TEST/DEBUG)
			rlwinm	r0,r0,24,24,31					; (TEST/DEBUG)
			cmplwi	r0,SAVempty						; (TEST/DEBUG)
			bne+	nnnn							; (TEST/DEBUG)
			b		.								; (TEST/DEBUG)
nnnn:												; (TEST/DEBUG)
#endif			
			
			stw		r11,0(r10)						; Save the new kernel stack address
			stw		r7,UAW(r12)						; Save the assist word for the "ultra fast path"
			
			lwz		r11,ACT_MACT_BTE(r5)			; Get BlueBox Task Environment
		
			lwz		r7,ACT_MACT_SPF(r5)				; Get the special flags
			
			lwz		r10,ACT_KLOADED(r5)
			stw		r11,ppbbTaskEnv(r12)			; Save the bb task env
			li		r0,0
			cmpwi	cr0,r10,0
			lwz		r10,PP_ACTIVE_KLOADED(r12)
			stw		r7,spcFlags(r12)				; Set per_proc copy of the special flags
			beq		cr0,.L_sw_ctx_not_kld
		
			stw		r5,0(r10)
			b		.L_sw_ctx_cont

.L_sw_ctx_not_kld:	
			stw		r0,0(r10)						/* act_kloaded = 0 */

.L_sw_ctx_cont:	
			lis		r10,hi16(EXT(trcWork))			; Get top of trace mask
			rlwinm	r7,r8,0,0,19					/* Switch to savearea base */
			ori		r10,r10,lo16(EXT(trcWork))		; Get bottom of mask
			lwz		r11,SAVprev(r8)					/* Get the previous of the switchee's savearea */
			lwz		r10,traceMask(r10)				; Get the enabled traces
			lis		r0,hi16(CutTrace)				; Trace FW call
			mr.		r10,r10							; Any tracing going on?
			ori		r0,r0,lo16(CutTrace)			; Trace FW call
			beq+	cswNoTrc						; No trace today, dude...
			mr		r10,r3							; Save across trace
			lwz		r2,THREAD_TOP_ACT(r3)			; Trace old activation
			mr		r3,r11							; Trace prev savearea
			sc										; Cut trace entry of context switch
			mr		r3,r10							; Restore
			
cswNoTrc:	mfmsr	r6								/* Get the MSR because the switched to thread should inherit it */
			lwz		r7,SACvrswap(r7)				/* Get the translation from virtual to real */
			stw		r11,ACT_MACT_PCB(r5)			/* Dequeue the savearea we're switching to */

			rlwinm	r6,r6,0,MSR_FP_BIT+1,MSR_FP_BIT-1	/* Turn off the FP */
			lwz		r2,curctx(r5)					; Grab our current context pointer
			rlwinm	r6,r6,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	/* Turn off the vector */
			mr		r4,r3							/* Save our old thread to pass back */
			
			lhz		r0,PP_CPU_NUMBER(r12)			; Get our CPU number
			lwz		r10,FPUowner(r12)				; Grab the owner of the FPU			
			lwz		r9,VMXowner(r12)				; Grab the owner of the vector
			cmplw	r10,r2							; Do we have the live float context?
			lwz		r10,FPUlevel(r2)				; Get the live level
			cmplw	cr5,r9,r2						; Do we have the live vector context?		
			bne+	cswnofloat						; Float is not ours...
			
			cmplw	r10,r11							; Is the level the same?
			lwz		r5,FPUcpu(r2)					; Get the owning cpu
			bne+	cswnofloat						; Level not the same, this is not live...
			
			cmplw	r5,r0							; Still owned by this cpu?
			lwz		r10,FPUsave(r2)					; Get the level
			bne+	cswnofloat						; CPU claimed by someone else...
			
			mr.		r10,r10							; Is there a savearea here?
			ori		r6,r6,lo16(MASK(MSR_FP))		; Enable floating point
			
			beq-	cswnofloat						; No savearea to check...
			
			lwz		r3,SAVlevel(r10)				; Get the level
			lwz		r5,SAVprev(r10)					; Get the previous of this savearea
			cmplw	r3,r11							; Is it for the current level?
			
			bne+	cswnofloat						; Nope...
			
			stw		r5,FPUsave(r2)					; Pop off this savearea
			rlwinm	r5,r10,0,0,19					; Move back to start of page
			lwz		r5,SACvrswap(r5)				; Get the virtual to real conversion
			la		r9,quickfret(r12)				; Point to the quickfret chain header					
			xor		r5,r10,r5						; Convert savearea address to real

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x4401						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
			lhz		r0,PP_CPU_NUMBER(r12)			; (TEST/DEBUG)
#endif	

;
;			Note: we need to do the atomic operation here because, even though
;			it is impossible with the current implementation, that we may take a
;			PTE miss between the load of the quickfret anchor and the subsequent
;			store.  The interrupt handler will dequeue everything on the list and
;			we could end up using stale data.  I do not like doing this...
;

cswfpudq:	lwarx	r3,0,r9							; Pick up the old chain head
			stw		r3,SAVprev(r10)					; Move it to the current guy
			stwcx.	r5,0,r9							; Save it
			bne-	cswfpudq						; Someone chaged the list...

cswnofloat:	bne+	cr5,cswnovect					; Vector is not ours...

			lwz		r10,VMXlevel(r2)				; Get the live level
			
			cmplw	r10,r11							; Is the level the same?
			lwz		r5,VMXcpu(r2)					; Get the owning cpu
			bne+	cswnovect						; Level not the same, this is not live...
			
			cmplw	r5,r0							; Still owned by this cpu?
			lwz		r10,VMXsave(r2)					; Get the level
			bne+	cswnovect						; CPU claimed by someone else...
			
			mr.		r10,r10							; Is there a savearea here?
			oris	r6,r6,hi16(MASK(MSR_VEC))		; Enable vector
			
			beq-	cswnovect						; No savearea to check...
			
			lwz		r3,SAVlevel(r10)				; Get the level
			lwz		r5,SAVprev(r10)					; Get the previous of this savearea
			cmplw	r3,r11							; Is it for the current level?
			
			bne+	cswnovect						; Nope...
			
			stw		r5,VMXsave(r2)					; Pop off this savearea
			rlwinm	r5,r10,0,0,19					; Move back to start of page
			lwz		r5,SACvrswap(r5)				; Get the virtual to real conversion
			la		r9,quickfret(r12)				; Point to the quickfret chain header					
			xor		r5,r10,r5						; Convert savearea address to real

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x4501						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	

;
;			Note: we need to do the atomic operation here because, even though
;			it is impossible with the current implementation, that we may take a
;			PTE miss between the load of the quickfret anchor and the subsequent
;			store.  The interrupt handler will dequeue everything on the list and
;			we could end up using stale data.  I do not like doing this...
;

cswvecdq:	lwarx	r3,0,r9							; Pick up the old chain head
			stw		r3,SAVprev(r10)					; Move it to the current guy
			stwcx.	r5,0,r9							; Save it
			bne-	cswvecdq						; Someone chaged the list...

cswnovect:	lis		r9,hi16(EXT(switch_in))			/* Get top of switch in routine */
			lwz		r5,savesrr0(r8)					/* Set up the new SRR0 */
			ori		r9,r9,lo16(EXT(switch_in))		/* Bottom half of switch in */
			lis		r0,hi16(SwitchContextCall)		/* Top part of switch context */
			stw		r9,savesrr0(r8)					/* Make us jump to the switch in routine */
			
			li		r10,MSR_SUPERVISOR_INT_OFF		/* Get the switcher's MSR */
			lwz		r9,SAVflags(r8)					/* Get the flags */
			stw		r10,savesrr1(r8)				/* Set up for switch in */
			rlwinm	r9,r9,0,15,13					/* Reset the syscall flag */
			ori		r0,r0,lo16(SwitchContextCall)	/* Bottom part of switch context */
			xor		r3,r7,r8						/* Get the physical address of the new context save area */
			stw		r9,SAVflags(r8)					/* Set the flags */

			bne		cr1,swtchtocont					; Switch to the continuation
			sc										/* Switch to the new context */
	
/*			We come back here in the new thread context	
 * 			R4 was set to hold the old thread pointer, but switch_in will put it into
 *			R3 where it belongs.
 */
			blr										/* Jump into the new thread */

;
;			This is where we go when a continuation is set.  We are actually
;			killing off the old context of the new guy so we need to pop off
;			any float or vector states for the ditched level.
;
;			Note that we do the same kind of thing a chkfac in hw_exceptions.s
;

		
swtchtocont:
			stw		r5,savesrr0(r8)					; Set the pc
			stw		r6,savesrr1(r8)					; Set the next MSR to use
			stw		r4,saver3(r8)					; Make sure we pass back the old thread
			
			b		EXT(exception_exit)				; Blocking on continuation, toss old context...



/*
 *			All switched to threads come here first to clean up the old thread.
 *			We need to do the following contortions because we need to keep
 *			the LR clean. And because we need to manipulate the savearea chain
 *			with translation on.  If we could, this should be done in lowmem_vectors
 *			before translation is turned on.  But we can't, dang it!
 *
 *			R3  = switcher's savearea
 *			saver4  = old thread in switcher's save
 *			saver5  = new SRR0 in switcher's save
 *			saver6  = new SRR1 in switcher's save


 */
 

			.align	5
			.globl	EXT(switch_in)

LEXT(switch_in)
			
			lwz		r4,saver4(r3)					/* Get the old thread */
			lwz		r9,THREAD_TOP_ACT(r4)			/* Get the switched from ACT */
			lwz		r5,saver5(r3)					/* Get the srr0 value */
			lwz		r10,ACT_MACT_PCB(r9)			/* Get the top PCB on the old thread */
			lwz		r6,saver6(r3)					/* Get the srr1 value */

			stw		r3,ACT_MACT_PCB(r9)				/* Put the new one on top */
			stw		r10,SAVprev(r3)					/* Chain on the old one */

			mr		r3,r4							/* Pass back the old thread */

			mtsrr0	r5								/* Set return point */
			mtsrr1	r6								/* Set return MSR */
			rfi										/* Jam... */
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0


			
/*
 * void fpu_save(facility_context ctx)
 *
 *			Note that there are some oddities here when we save a context we are using.
 *			It is really not too cool to do this, but what the hey...  Anyway, 
 *			we turn fpus and vecs off before we leave., The oddity is that if you use fpus after this, the
 *			savearea containing the context just saved will go away.  So, bottom line is
 *			that don't use fpus until after you are done with the saved context.
 */
			.align	5
			.globl	EXT(fpu_save)

LEXT(fpu_save)
			

			mfmsr	r0								; Get the MSR
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r2,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; But do interrupts only for now
			ori		r2,r2,MASK(MSR_FP)				; Enable the floating point feature for now also
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			mtmsr	r2								; Set the MSR
			isync

			mfsprg	r6,0							; Get the per_processor block 
			lwz		r12,FPUowner(r6)				; Get the context ID for owner

#if FPVECDBG
			mr		r7,r0							; (TEST/DEBUG)
			li		r4,0							; (TEST/DEBUG)
			mr		r10,r3							; (TEST/DEBUG)
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			mr.		r3,r12							; (TEST/DEBUG)
			li		r2,0x6F00						; (TEST/DEBUG)
			li		r5,0							; (TEST/DEBUG)
			beq-	noowneryet						; (TEST/DEBUG)
			lwz		r4,FPUlevel(r12)				; (TEST/DEBUG)
			lwz		r5,FPUsave(r12)					; (TEST/DEBUG)

noowneryet:	oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
			mr		r0,r7							; (TEST/DEBUG)
			mr		r3,r10							; (TEST/DEBUG)
#endif	
			mflr	r2								; Save the return address

fsretry:	mr.		r12,r12							; Anyone own the FPU?
			lhz		r11,PP_CPU_NUMBER(r6)			; Get our CPU number
			beq-	fsret							; Nobody owns the FPU, no save required...
			
			cmplw	cr1,r3,r12						; Is the specified context live?
			
			isync									; Force owner check first
			
			lwz		r9,FPUcpu(r12)					; Get the cpu that context was last on		
			bne-	cr1,fsret						; No, it is not...
			
			cmplw	cr1,r9,r11						; Was the context for this processor? 
			beq-	cr1,fsgoodcpu					; Facility last used on this processor...

			b		fsret							; Someone else claimed it...
			
			.align	5
			
fsgoodcpu:	lwz		r3,FPUsave(r12)					; Get the current FPU savearea for the thread
			lwz		r9,FPUlevel(r12)				; Get our current level indicator
			
			cmplwi	cr1,r3,0						; Have we ever saved this facility context?
			beq-	cr1,fsneedone					; Never saved it, so go do it...
			
			lwz		r8,SAVlevel(r3)					; Get the level this savearea is for
			cmplw	cr1,r9,r8						; Correct level?
			beq-	cr1,fsret						; The current level is already saved, bail out...

fsneedone:	bl		EXT(save_get)					; Get a savearea for the context

			mfsprg	r6,0							; Get back per_processor block
			li		r4,SAVfloat						; Get floating point tag			
			lwz		r12,FPUowner(r6)				; Get back our thread
			stb		r4,SAVflags+2(r3)				; Mark this savearea as a float
			mr.		r12,r12							; See if we were disowned while away. Very, very small chance of it...
			beq-	fsbackout						; If disowned, just toss savearea...
			lwz		r4,facAct(r12)					; Get the activation associated with live context
			mtlr	r2								; Restore return
			lwz		r8,FPUsave(r12)					; Get the current top floating point savearea
			stw		r4,SAVact(r3)					; Indicate the right activation for this context
			lwz		r9,FPUlevel(r12)				; Get our current level indicator again		
			stw		r3,FPUsave(r12)					; Set this as the most current floating point context
			stw		r8,SAVprev(r3)					; And then chain this in front

			stw		r9,SAVlevel(r3)					; Show level in savearea

;
; 			Save the current FPU state into the PCB of the thread that owns it.
; 

			la		r11,savefp0(r3)					; Point to the 1st line
			dcbz	0,r11							; Allocate the first savearea line 
			
			la		r11,savefp4(r3)					; Point to the 2nd line 
			stfd    f0,savefp0(r3)
			dcbz	0,r11							; Allocate it
			stfd    f1,savefp1(r3)
			stfd    f2,savefp2(r3)
			la		r11,savefp8(r3)					; Point to the 3rd line 
			stfd    f3,savefp3(r3)
			dcbz	0,r11							; Allocate it 
			stfd    f4,savefp4(r3)
			stfd    f5,savefp5(r3)
			stfd    f6,savefp6(r3)
			la		r11,savefp12(r3)				; Point to the 4th line 
			stfd    f7,savefp7(r3)
			dcbz	0,r11							; Allocate it 
			stfd    f8,savefp8(r3)
			stfd    f9,savefp9(r3)
			stfd    f10,savefp10(r3)
			la		r11,savefp16(r3)				; Point to the 5th line 
			stfd    f11,savefp11(r3)
			dcbz	0,r11							; Allocate it 
			stfd    f12,savefp12(r3)
			stfd    f13,savefp13(r3)
			stfd    f14,savefp14(r3)
			la		r11,savefp20(r3)				; Point to the 6th line 
			stfd    f15,savefp15(r3)
			stfd    f16,savefp16(r3)
			stfd    f17,savefp17(r3)
			stfd    f18,savefp18(r3)
			la		r11,savefp24(r3)				; Point to the 7th line 
			stfd    f19,savefp19(r3)
			dcbz	0,r11							; Allocate it 
			stfd    f20,savefp20(r3)
			stfd    f21,savefp21(r3)
			stfd    f22,savefp22(r3)
			la		r11,savefp28(r3)				; Point to the 8th line 
			stfd    f23,savefp23(r3)
			dcbz	0,r11							; Allocate it 
			stfd    f24,savefp24(r3)
			stfd    f25,savefp25(r3)
			stfd    f26,savefp26(r3)
			stfd    f27,savefp27(r3)
			stfd    f28,savefp28(r3)

			stfd    f29,savefp29(r3)
			stfd    f30,savefp30(r3)
			stfd    f31,savefp31(r3)

fsret:		mtmsr	r0								; Put interrupts on if they were and floating point off
			isync

			blr

fsbackout:	mr		r12,r0							; Save the original MSR
			b		EXT(save_ret_join)				; Toss savearea and return from there...

/*
 * fpu_switch()
 *
 * Entered to handle the floating-point unavailable exception and
 * switch fpu context
 *
 * This code is run in virtual address mode on with interrupts off.
 *
 * Upon exit, the code returns to the users context with the floating
 * point facility turned on.
 *
 * ENTRY:	VM switched ON
 *		Interrupts  OFF
 *              State is saved in savearea pointed to by R4.
 *				All other registers are free.
 * 
 */

			.align	5
			.globl	EXT(fpu_switch)

LEXT(fpu_switch)

#if DEBUG
			lis		r3,hi16(EXT(fpu_trap_count))	; Get address of FP trap counter
			ori		r3,r3,lo16(EXT(fpu_trap_count))	; Get address of FP trap counter
			lwz		r1,0(r3)
			addi	r1,r1,1
			stw		r1,0(r3)
#endif /* DEBUG */

			mfsprg	r26,0							; Get the per_processor block
			mfmsr	r19								; Get the current MSR 
			
			mr		r25,r4							; Save the entry savearea
			lwz		r22,FPUowner(r26)				; Get the thread that owns the FPU
			lwz		r10,PP_ACTIVE_THREAD(r26)		; Get the pointer to the active thread
			ori		r19,r19,lo16(MASK(MSR_FP))		; Enable the floating point feature
			lwz		r17,THREAD_TOP_ACT(r10)			; Now get the activation that is running
			
			mtmsr	r19								; Enable floating point instructions
			isync

			lwz		r27,ACT_MACT_PCB(r17)			; Get the current level
			lwz		r29,curctx(r17)					; Grab the current context anchor of the current thread

;			R22 has the "old" context anchor
;			R29 has the "new" context anchor

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x7F01						; (TEST/DEBUG)
			mr		r3,r22							; (TEST/DEBUG)
			mr		r5,r29							; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
						
			lhz		r16,PP_CPU_NUMBER(r26)			; Get the current CPU number

fswretry:	mr.		r22,r22							; See if there is any live FP status			

			beq-	fsnosave						; No live context, so nothing to save...

			isync									; Make sure we see this in the right order

			lwz		r30,FPUsave(r22)				; Get the top savearea
			cmplw	cr2,r22,r29						; Are both old and new the same context?
			lwz		r18,FPUcpu(r22)					; Get the last CPU we ran on
			cmplwi	cr1,r30,0						; Anything saved yet?
			cmplw	r18,r16							; Make sure we are on the right processor
			lwz		r31,FPUlevel(r22)				; Get the context level

			bne-	fsnosave						; No, not on the same processor...
						
;
;			Check to see if the live context has already been saved.
;			Also check to see if all we are here just to re-enable the MSR
;			and handle specially if so.
;

			cmplw	r31,r27							; See if the current and active levels are the same
			crand	cr0_eq,cr2_eq,cr0_eq			; Remember if both the levels and contexts are the same
			li		r3,0							; Clear this
			
			beq-	fsthesame						; New and old are the same, just go enable...

			beq-	cr1,fsmstsave					; Not saved yet, go do it...
			
			lwz		r11,SAVlevel(r30)				; Get the level of top saved context
			
			cmplw	r31,r11							; Are live and saved the same?

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x7F02						; (TEST/DEBUG)
			mr		r3,r30							; (TEST/DEBUG)
			mr		r5,r31							; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	

			beq+	fsnosave						; Same level, so already saved...
			
			
fsmstsave:	stw		r3,FPUowner(r26)				; Kill the context now
			eieio									; Make sure everyone sees it
			bl		EXT(save_get)					; Go get a savearea

			la		r11,savefp0(r3)					; Point to the 1st line in new savearea
			lwz		r12,facAct(r22)					; Get the activation associated with the context
			dcbz	0,r11							; Allocate cache
			stw		r3,FPUsave(r22)					; Set this as the latest context savearea for the thread

			stw		r30,SAVprev(r3)					; Point us to the old context
			stw		r31,SAVlevel(r3)				; Tag our level
			li		r7,SAVfloat						; Get the floating point ID
			stw		r12,SAVact(r3)					; Make sure we point to the right guy
			stb		r7,SAVflags+2(r3)				; Set that we have a floating point save area

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x7F03						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	

;
;			Now we will actually save the old context
;
			
			la		r11,savefp4(r3)					; Point to the 2nd line
			stfd    f0,savefp0(r3)
			dcbz	0,r11							; Allocate cache
			stfd    f1,savefp1(r3)
			stfd    f2,savefp2(r3)
			la		r11,savefp8(r3)					; Point to the 3rd line
			stfd    f3,savefp3(r3)
			dcbz	0,r11							; Allocate cache
			stfd    f4,savefp4(r3)
			stfd    f5,savefp5(r3)
			stfd    f6,savefp6(r3)
			la		r11,savefp12(r3)				; Point to the 4th line
			stfd    f7,savefp7(r3)
			dcbz	0,r11							; Allocate cache
			stfd    f8,savefp8(r3)
			stfd    f9,savefp9(r3)
			stfd    f10,savefp10(r3)
			la		r11,savefp16(r3)				; Point to the 5th line
			stfd    f11,savefp11(r3)
			dcbz	0,r11							; Allocate cache
			stfd    f12,savefp12(r3)
			stfd    f13,savefp13(r3)
			stfd    f14,savefp14(r3)
			la		r11,savefp20(r3)				; Point to the 6th line 
			stfd    f15,savefp15(r3)
			dcbz	0,r11							; Allocate cache
			stfd    f16,savefp16(r3)
			stfd    f17,savefp17(r3)
			stfd    f18,savefp18(r3)
			la		r11,savefp24(r3)				; Point to the 7th line
			stfd    f19,savefp19(r3)
			dcbz	0,r11							; Allocate cache
			stfd    f20,savefp20(r3)

			stfd    f21,savefp21(r3)
			stfd    f22,savefp22(r3)
			la		r11,savefp28(r3)				; Point to the 8th line
			stfd    f23,savefp23(r3)
			dcbz	0,r11							; allocate it
			stfd    f24,savefp24(r3)
			stfd    f25,savefp25(r3)
			stfd    f26,savefp26(r3)
			stfd    f27,savefp27(r3)
			dcbz	0,r11							; allocate it
			stfd    f28,savefp28(r3)
			stfd    f29,savefp29(r3)
			stfd    f30,savefp30(r3)
			stfd    f31,savefp31(r3)

;
;			The context is all saved now and the facility is free.
;
;			If we do not we need to fill the registers with junk, because this level has 
;			never used them before and some thieving bastard could hack the old values
;			of some thread!  Just imagine what would happen if they could!  Why, nothing
;			would be safe! My God! It is terrifying!
;


fsnosave:	lwz		r15,ACT_MACT_PCB(r17)			; Get the current level of the "new" one
			lwz		r19,FPUcpu(r29)					; Get the last CPU we ran on
			lwz		r14,FPUsave(r29)				; Point to the top of the "new" context stack

			stw		r16,FPUcpu(r29)					; Claim context for us
			eieio

#if FPVECDBG
			lwz		r13,FPUlevel(r29)				; (TEST/DEBUG)
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x7F04						; (TEST/DEBUG)
			mr		r1,r15							; (TEST/DEBUG)
			mr		r3,r14							; (TEST/DEBUG)
			mr		r5,r13							; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
			
			lis		r18,hi16(EXT(per_proc_info))	; Set base per_proc
			mulli	r19,r19,ppSize					; Find offset to the owner per_proc			
			ori		r18,r18,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r16,FPUowner					; Displacement to float owner
			add		r19,r18,r19						; Point to the owner per_proc	
			li		r0,0
			
fsinvothr:	lwarx	r18,r16,r19						; Get the owner
			cmplw	r18,r29							; Does he still have this context?
			bne		fsinvoths						; Nope...		
			stwcx.	r0,r16,r19						; Try to invalidate it
			bne-	fsinvothr						; Try again if there was a collision...
		
fsinvoths:	cmplwi	cr1,r14,0						; Do we possibly have some context to load?
			la		r11,savefp0(r14)				; Point to first line to bring in
			stw		r15,FPUlevel(r29)				; Set the "new" active level
			eieio
			stw		r29,FPUowner(r26)				; Mark us as having the live context
			
			beq+	cr1,MakeSureThatNoTerroristsCanHurtUsByGod	; No "new" context to load...
			
			dcbt	0,r11							; Touch line in

			lwz		r3,SAVprev(r14)					; Get the previous context
			lwz		r0,SAVlevel(r14)				; Get the level of first facility savearea
			cmplw	r0,r15							; Top level correct to load?
			bne-	MakeSureThatNoTerroristsCanHurtUsByGod	; No, go initialize...

			stw		r3,FPUsave(r29)					; Pop the context (we will toss the savearea later)
			
#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x7F05						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	

			la		r11,savefp4(r14)				; Point to next line
			dcbt	0,r11							; Touch line in
			lfd     f0, savefp0(r14)
			lfd     f1,savefp1(r14)
			lfd     f2,savefp2(r14)
			la		r11,savefp8(r14)				; Point to next line
			lfd     f3,savefp3(r14)
			dcbt	0,r11							; Touch line in
			lfd     f4,savefp4(r14)
			lfd     f5,savefp5(r14)
			lfd     f6,savefp6(r14)
			la		r11,savefp12(r14)				; Point to next line
			lfd     f7,savefp7(r14)
			dcbt	0,r11							; Touch line in
			lfd     f8,savefp8(r14)
			lfd     f9,savefp9(r14)
			lfd     f10,savefp10(r14)
			la		r11,savefp16(r14)				; Point to next line
			lfd     f11,savefp11(r14)
			dcbt	0,r11							; Touch line in
			lfd     f12,savefp12(r14)
			lfd     f13,savefp13(r14)
			lfd     f14,savefp14(r14)
			la		r11,savefp20(r14)				; Point to next line
			lfd     f15,savefp15(r14)
			dcbt	0,r11							; Touch line in
			lfd     f16,savefp16(r14)
			lfd     f17,savefp17(r14)
			lfd     f18,savefp18(r14)
			la		r11,savefp24(r14)				; Point to next line
			lfd     f19,savefp19(r14)
			dcbt	0,r11							; Touch line in
			lfd     f20,savefp20(r14)
			lfd     f21,savefp21(r14)
			la		r11,savefp28(r14)				; Point to next line
			lfd     f22,savefp22(r14)
			lfd     f23,savefp23(r14)
			dcbt	0,r11							; Touch line in
			lfd     f24,savefp24(r14)
			lfd     f25,savefp25(r14)
			lfd     f26,savefp26(r14)
			lfd     f27,savefp27(r14)
			lfd     f28,savefp28(r14)
			lfd     f29,savefp29(r14)
			lfd     f30,savefp30(r14)
			lfd     f31,savefp31(r14)
			
			mr		r3,r14							; Get the old savearea (we popped it before)
			bl		EXT(save_ret)					; Toss it
			
fsenable:	lwz		r8,savesrr1(r25)				; Get the msr of the interrupted guy
			rlwinm	r5,r25,0,0,19					; Get the page address of the savearea 
			ori		r8,r8,MASK(MSR_FP)				; Enable the floating point feature
			lwz		r10,ACT_MACT_SPF(r17)			; Get the act special flags
			lwz		r11,spcFlags(r26)				; Get per_proc spec flags cause not in sync with act
			lwz		r5,SACvrswap(r5)				; Get Virtual to Real translation 
			oris	r10,r10,hi16(floatUsed|floatCng)	; Set that we used floating point
			oris	r11,r11,hi16(floatUsed|floatCng)	; Set that we used floating point
			rlwinm.	r0,r8,0,MSR_PR_BIT,MSR_PR_BIT	; See if we are doing this for user state
			stw		r8,savesrr1(r25)				; Set the msr of the interrupted guy
			xor		r3,r25,r5						; Get the real address of the savearea
			beq-	fsnuser							; We are not user state...
			stw		r10,ACT_MACT_SPF(r17)			; Set the activation copy
			stw		r11,spcFlags(r26)				; Set per_proc copy

fsnuser:
#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x7F07						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
			
			b		EXT(exception_exit)				; Exit to the fray...

/*
 *			Initialize the registers to some bogus value
 */

MakeSureThatNoTerroristsCanHurtUsByGod:

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x7F06						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
			lis		r5,hi16(EXT(FloatInit))			; Get top secret floating point init value address
			ori		r5,r5,lo16(EXT(FloatInit))		; Slam bottom
			lfd		f0,0(r5)						; Initialize FP0 
			fmr		f1,f0							; Do them all						
			fmr		f2,f0								
			fmr		f3,f0								
			fmr		f4,f0								
			fmr		f5,f0						
			fmr		f6,f0						
			fmr		f7,f0						
			fmr		f8,f0						
			fmr		f9,f0						
			fmr		f10,f0						
			fmr		f11,f0						
			fmr		f12,f0						
			fmr		f13,f0						
			fmr		f14,f0						
			fmr		f15,f0						
			fmr		f16,f0						
			fmr		f17,f0
			fmr		f18,f0						
			fmr		f19,f0						
			fmr		f20,f0						
			fmr		f21,f0						
			fmr		f22,f0						
			fmr		f23,f0						
			fmr		f24,f0						
			fmr		f25,f0						
			fmr		f26,f0						
			fmr		f27,f0						
			fmr		f28,f0						
			fmr		f29,f0						
			fmr		f30,f0						
			fmr		f31,f0						
			b		fsenable						; Finish setting it all up...				


;
;			We get here when we are switching to the same context at the same level and the context
;			is still live.  Essentially, all we are doing is turning on the faility.  It may have
;			gotten turned off due to doing a context save for the current level or a context switch
;			back to the live guy.
;

			.align	5
			
fsthesame:

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x7F0A						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
			beq-	cr1,fsenable					; Not saved yet, nothing to pop, go enable and exit...
			
			lwz		r11,SAVlevel(r30)				; Get the level of top saved context
			lwz		r14,SAVprev(r30)				; Get the previous savearea
			
			cmplw	r11,r31							; Are live and saved the same?

			bne+	fsenable						; Level not the same, nothing to pop, go enable and exit...
			
			mr		r3,r30							; Get the old savearea (we popped it before)
			bl		EXT(save_ret)					; Toss it
			b		fsenable						; Go enable and exit...


;
;			This function invalidates any live floating point context for the passed in facility_context.
;			This is intended to be called just before act_machine_sv_free tosses saveareas.
;

			.align	5
			.globl	EXT(toss_live_fpu)

LEXT(toss_live_fpu)
			
			
			mfmsr	r9								; Get the MSR
			rlwinm	r0,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear interuptions
			rlwinm.	r8,r9,0,MSR_FP_BIT,MSR_FP_BIT	; Are floats on right now?
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Make sure vectors are turned off
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Make sure floats are turned off
			mtmsr	r0								; No interruptions
			isync
			beq+	tlfnotours						; Floats off, can not be live here...

			mfsprg	r8,0							; Get the per proc

;
;			Note that at this point, since floats are on, we are the owner
;			of live state on this processor
;

			lwz		r6,FPUowner(r8)					; Get the thread that owns the floats
			li		r0,0							; Clear this just in case we need it
			cmplw	r6,r3							; Are we tossing our own context?
			bne-	tlfnotours						; Nope...
			
			fsub	f1,f1,f1						; Make a 0			
			mtfsf	0xFF,f1							; Clear it

tlfnotours:	lwz		r11,FPUcpu(r3)					; Get the cpu on which we last loaded context
			lis		r12,hi16(EXT(per_proc_info))	; Set base per_proc
			mulli	r11,r11,ppSize					; Find offset to the owner per_proc			
			ori		r12,r12,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r10,FPUowner					; Displacement to float owner
			add		r11,r12,r11						; Point to the owner per_proc	
			li		r0,0							; Set a 0 to invalidate context
			
tlfinvothr:	lwarx	r12,r10,r11						; Get the owner
			cmplw	r12,r3							; Does he still have this context?
			bne+	tlfexit							; Nope, leave...		
			stwcx.	r0,r10,r11						; Try to invalidate it
			bne-	tlfinvothr						; Try again if there was a collision...

tlfexit:	mtmsr	r9								; Restore interruptions
			isync									; Could be turning off floats here
			blr										; Leave...


/*
 *			Altivec stuff is here. The techniques used are pretty identical to
 *			the floating point. Except that we will honor the VRSAVE register
 *			settings when loading and restoring registers.
 *
 *			There are two indications of saved VRs: the VRSAVE register and the vrvalid
 *			mask. VRSAVE is set by the vector user and represents the VRs that they
 *			say that they are using. The vrvalid mask indicates which vector registers
 *			are saved in the savearea. Whenever context is saved, it is saved according
 *			to the VRSAVE register.  It is loaded based on VRSAVE anded with
 *			vrvalid (all other registers are splatted with 0s). This is done because we
 *			don't want to load any registers we don't have a copy of, we want to set them
 *			to zero instead.
 *
 *			Note that there are some oddities here when we save a context we are using.
 *			It is really not too cool to do this, but what the hey...  Anyway, 
 *			we turn vectors and fpu off before we leave.
 *			The oddity is that if you use vectors after this, the
 *			savearea containing the context just saved will go away.  So, bottom line is
 *			that don't use vectors until after you are done with the saved context.
 *
 */

			.align	5
			.globl	EXT(vec_save)

LEXT(vec_save)

			mfmsr	r0								; Get the MSR
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Make sure vectors are turned off when we leave
			rlwinm	r2,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; But do interrupts only for now
			oris	r2,r2,hi16(MASK(MSR_VEC))		; Enable the vector facility for now also
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force off fp
			mtmsr	r2								; Set the MSR
			isync
		
			mfsprg	r6,0							; Get the per_processor block 
			lwz		r12,VMXowner(r6)				; Get the context ID for owner

#if FPVECDBG
			mr		r7,r0							; (TEST/DEBUG)
			li		r4,0							; (TEST/DEBUG)
			mr		r10,r3							; (TEST/DEBUG)
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			mr.		r3,r12							; (TEST/DEBUG)
			li		r2,0x5F00						; (TEST/DEBUG)
			li		r5,0							; (TEST/DEBUG)
			beq-	noowneryeu						; (TEST/DEBUG)
			lwz		r4,VMXlevel(r12)				; (TEST/DEBUG)
			lwz		r5,VMXsave(r12)					; (TEST/DEBUG)

noowneryeu:	oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
			mr		r0,r7							; (TEST/DEBUG)
			mr		r3,r10							; (TEST/DEBUG)
#endif	
			mflr	r2								; Save the return address

vsretry:	mr.		r12,r12							; Anyone own the vector?
			lhz		r11,PP_CPU_NUMBER(r6)			; Get our CPU number
			beq-	vsret							; Nobody owns the vector, no save required...
			
			cmplw	cr1,r3,r12						; Is the specified context live?
			
			isync									; Force owner check first

			lwz		r9,VMXcpu(r12)					; Get the cpu that context was last on		
			bne-	cr1,vsret						; Specified context is not live
			
			cmplw	cr1,r9,r11						; Was the context for this processor? 
			beq+	cr1,vsgoodcpu					; Facility last used on this processor...

			b		vsret							; Someone else claimed this...
			
			.align	5
			
vsgoodcpu:	lwz		r3,VMXsave(r12)					; Get the current vector savearea for the thread
			lwz		r10,liveVRS(r6)					; Get the right VRSave register
			lwz		r9,VMXlevel(r12)				; Get our current level indicator
			
			
			cmplwi	cr1,r3,0						; Have we ever saved this facility context?
			beq-	cr1,vsneedone					; Never saved it, so we need an area...
			
			lwz		r8,SAVlevel(r3)					; Get the level this savearea is for
			mr.		r10,r10							; Is VRsave set to 0?
			cmplw	cr1,r9,r8						; Correct level?
			bne-	cr1,vsneedone					; Different level, so we need to save...
			
			bne+	vsret							; VRsave is non-zero so we need to keep what is saved...
						
			lwz		r4,SAVprev(r3)					; Pick up the previous area
			lwz		r5,SAVlevel(r4)					; Get the level associated with save
			stw		r4,VMXsave(r12)					; Dequeue this savearea
			stw		r5,VMXlevel(r12)				; Save the level
	
			li		r3,0							; Clear
			stw		r3,VMXowner(r12)				; Show no live context here
			eieio

vsbackout:	mr		r12,r0							; Set the saved MSR			
			b		EXT(save_ret_join)				; Toss the savearea and return from there...

			.align	5

vsneedone:	mr.		r10,r10							; Is VRsave set to 0?
			beq-	vsret							; Yeah, they do not care about any of them...

			bl		EXT(save_get)					; Get a savearea for the context
			
			mfsprg	r6,0							; Get back per_processor block
			li		r4,SAVvector					; Get vector tag			
			lwz		r12,VMXowner(r6)				; Get back our context ID
			stb		r4,SAVflags+2(r3)				; Mark this savearea as a vector
			mr.		r12,r12							; See if we were disowned while away. Very, very small chance of it...
			beq-	vsbackout						; If disowned, just toss savearea...
			lwz		r4,facAct(r12)					; Get the activation associated with live context
			mtlr	r2								; Restore return
			lwz		r8,VMXsave(r12)					; Get the current top vector savearea
			stw		r4,SAVact(r3)					; Indicate the right activation for this context
			lwz		r9,VMXlevel(r12)				; Get our current level indicator again		
			stw		r3,VMXsave(r12)					; Set this as the most current floating point context
			stw		r8,SAVprev(r3)					; And then chain this in front

			stw		r9,SAVlevel(r3)					; Set level in savearea

			mfcr	r2						; Save non-volatile CRs
			lwz		r10,liveVRS(r6)			; Get the right VRSave register
			lis		r9,0x5555				; Mask with odd bits set		
			rlwinm	r11,r10,1,0,31			; Shift over 1
			ori		r9,r9,0x5555			; Finish mask
			or		r4,r10,r11				; After this, even bits show which lines to zap
			
			andc	r11,r4,r9				; Clear out odd bits
			
			la		r6,savevr0(r3)			; Point to line 0
			rlwinm	r4,r11,15,0,15			; Move line 8-15 flags to high order odd bits
			or		r4,r11,r4				; Set the odd bits
											; (bit 0 is line 0, bit 1 is line 8,
											; bit 2 is line 1, bit 3 is line 9, etc.
			rlwimi	r4,r10,16,16,31			; Put vrsave 0 - 15 into positions 16 - 31
			la		r7,savevr2(r3)			; Point to line 1
			mtcrf	255,r4					; Load up the CRs
			stw		r10,savevrvalid(r3)		; Save the validity information
			mr		r8,r6					; Start registers off
;	
;			Save the current vector state
;
						
			bf		0,snol0					; No line 0 to do...
			dcba	br0,r6					; Allocate cache line 0
			
snol0:		
			la		r6,savevr4(r3)			; Point to line 2
			bf		2,snol1					; No line 1 to do...
			dcba	br0,r7					; Allocate cache line 1
			
snol1:		
			la		r7,savevr6(r3)			; Point to line 3
			bf		4,snol2					; No line 2 to do...
			dcba	br0,r6					; Allocate cache line 2
			
snol2:		
			li		r11,16					; Get offset for odd registers
			bf		16,snovr0				; Do not save VR0...
			stvxl	v0,br0,r8				; Save VR0
			
snovr0:		
			la		r9,savevr2(r3)			; Point to V2/V3 pair
			bf		17,snovr1				; Do not save VR1...
			stvxl	v1,r11,r8				; Save VR1
			
snovr1:
			la		r6,savevr8(r3)			; Point to line 4
			bf		6,snol3					; No line 3 to do...
			dcba	br0,r7					; Allocate cache line 3
			
snol3:		
			la		r8,savevr4(r3)			; Point to V4/V5 pair
			bf		18,snovr2				; Do not save VR2...
			stvxl	v2,br0,r9				; Save VR2
			
snovr2:
			bf		19,snovr3				; Do not save VR3...
			stvxl	v3,r11,r9				; Save VR3
			
snovr3:
;
;			Note: CR4 is now free
;
			la		r7,savevr10(r3)			; Point to line 5
			bf		8,snol4					; No line 4 to do...
			dcba	br0,r6					; Allocate cache line 4
			
snol4:		
			la		r9,savevr6(r3)			; Point to R6/R7 pair
			bf		20,snovr4				; Do not save VR4...
			stvxl	v4,br0,r8				; Save VR4
			
snovr4:
			bf		21,snovr5				; Do not save VR5...
			stvxl	v5,r11,r8				; Save VR5
			
snovr5:
			mtcrf	0x08,r10				; Set CRs for registers 16-19
			la		r6,savevr12(r3)			; Point to line 6
			bf		10,snol5				; No line 5 to do...
			dcba	br0,r7					; Allocate cache line 5
			
snol5:		
			la		r8,savevr8(r3)			; Point to V8/V9 pair
			bf		22,snovr6				; Do not save VR6...
			stvxl	v6,br0,r9				; Save VR6
			
snovr6:
			bf		23,snovr7				; Do not save VR7...
			stvxl	v7,r11,r9				; Save VR7
			
snovr7:
;
;			Note: CR5 is now free
;
			la		r7,savevr14(r3)			; Point to line 7
			bf		12,snol6				; No line 6 to do...
			dcba	br0,r6					; Allocate cache line 6
			
snol6:		
			la		r9,savevr10(r3)			; Point to V10/V11 pair
			bf		24,snovr8				; Do not save VR8...
			stvxl	v8,br0,r8				; Save VR8
			
snovr8:
			bf		25,snovr9				; Do not save VR9...
			stvxl	v9,r11,r8				; Save VR9
			
snovr9:
			mtcrf	0x04,r10				; Set CRs for registers 20-23
			la		r6,savevr16(r3)			; Point to line 8
			bf		14,snol7				; No line 7 to do...
			dcba	br0,r7					; Allocate cache line 7
			
snol7:		
			la		r8,savevr12(r3)			; Point to V12/V13 pair
			bf		26,snovr10				; Do not save VR10...
			stvxl	v10,br0,r9				; Save VR10
			
snovr10:
			bf		27,snovr11				; Do not save VR11...
			stvxl	v11,r11,r9				; Save VR11
			
snovr11:

;
;			Note: CR6 is now free
;
			la		r7,savevr18(r3)			; Point to line 9
			bf		1,snol8					; No line 8 to do...
			dcba	br0,r6					; Allocate cache line 8
			
snol8:		
			la		r9,savevr14(r3)			; Point to V14/V15 pair
			bf		28,snovr12				; Do not save VR12...
			stvxl	v12,br0,r8				; Save VR12
			
snovr12:
			bf		29,snovr13				; Do not save VR13...
			stvxl	v13,r11,r8				; Save VR13
			
snovr13:
			mtcrf	0x02,r10				; Set CRs for registers 24-27
			la		r6,savevr20(r3)			; Point to line 10
			bf		3,snol9					; No line 9 to do...
			dcba	br0,r7					; Allocate cache line 9
			
snol9:		
			la		r8,savevr16(r3)			; Point to V16/V17 pair
			bf		30,snovr14				; Do not save VR14...
			stvxl	v14,br0,r9				; Save VR14
			
snovr14:
			bf		31,snovr15				; Do not save VR15...
			stvxl	v15,r11,r9				; Save VR15
			
snovr15:
;
;			Note: CR7 is now free
;
			la		r7,savevr22(r3)			; Point to line 11
			bf		5,snol10				; No line 10 to do...
			dcba	br0,r6					; Allocate cache line 10
			
snol10:		
			la		r9,savevr18(r3)			; Point to V18/V19 pair
			bf		16,snovr16				; Do not save VR16...
			stvxl	v16,br0,r8				; Save VR16
			
snovr16:
			bf		17,snovr17				; Do not save VR17...
			stvxl	v17,r11,r8				; Save VR17
			
snovr17:
			mtcrf	0x01,r10				; Set CRs for registers 28-31
;
;			Note: All registers have been or are accounted for in CRs
;
			la		r6,savevr24(r3)			; Point to line 12
			bf		7,snol11				; No line 11 to do...
			dcba	br0,r7					; Allocate cache line 11
			
snol11:		
			la		r8,savevr20(r3)			; Point to V20/V21 pair
			bf		18,snovr18				; Do not save VR18...
			stvxl	v18,br0,r9				; Save VR18
			
snovr18:
			bf		19,snovr19				; Do not save VR19...
			stvxl	v19,r11,r9				; Save VR19
			
snovr19:
			la		r7,savevr26(r3)			; Point to line 13
			bf		9,snol12				; No line 12 to do...
			dcba	br0,r6					; Allocate cache line 12
			
snol12:		
			la		r9,savevr22(r3)			; Point to V22/V23 pair
			bf		20,snovr20				; Do not save VR20...
			stvxl	v20,br0,r8				; Save VR20
			
snovr20:
			bf		21,snovr21				; Do not save VR21...
			stvxl	v21,r11,r8				; Save VR21
			
snovr21:
			la		r6,savevr28(r3)			; Point to line 14
			bf		11,snol13				; No line 13 to do...
			dcba	br0,r7					; Allocate cache line 13
			
snol13:		
			la		r8,savevr24(r3)			; Point to V24/V25 pair
			bf		22,snovr22				; Do not save VR22...
			stvxl	v22,br0,r9				; Save VR22
			
snovr22:
			bf		23,snovr23				; Do not save VR23...
			stvxl	v23,r11,r9				; Save VR23
			
snovr23:
			la		r7,savevr30(r3)			; Point to line 15
			bf		13,snol14				; No line 14 to do...
			dcba	br0,r6					; Allocate cache line 14
			
snol14:		
			la		r9,savevr26(r3)			; Point to V26/V27 pair
			bf		24,snovr24				; Do not save VR24...
			stvxl	v24,br0,r8				; Save VR24
			
snovr24:
			bf		25,snovr25				; Do not save VR25...
			stvxl	v25,r11,r8				; Save VR25
			
snovr25:
			bf		15,snol15				; No line 15 to do...
			dcba	br0,r7					; Allocate cache line 15
			
snol15:		
;
;			Note: All cache lines allocated now
;
			la		r8,savevr28(r3)			; Point to V28/V29 pair
			bf		26,snovr26				; Do not save VR26...
			stvxl	v26,br0,r9				; Save VR26

snovr26:
			bf		27,snovr27				; Do not save VR27...
			stvxl	v27,r11,r9				; Save VR27
			
snovr27:
			la		r7,savevr30(r3)			; Point to V30/V31 pair
			bf		28,snovr28				; Do not save VR28...
			stvxl	v28,br0,r8				; Save VR28
			
snovr28:		
			bf		29,snovr29				; Do not save VR29...
			stvxl	v29,r11,r8				; Save VR29
			
snovr29:		
			bf		30,snovr30				; Do not save VR30...
			stvxl	v30,br0,r7				; Save VR30
			
snovr30:
			bf		31,snovr31				; Do not save VR31...
			stvxl	v31,r11,r7				; Save VR31
			
snovr31:
			mtcrf	255,r2					; Restore all cr

vsret:		mtmsr	r0						; Put interrupts on if they were and vector off
			isync

			blr

/*
 * vec_switch()
 *
 * Entered to handle the vector unavailable exception and
 * switch vector context
 *
 * This code is run with virtual address mode on and interrupts off.
 *
 * Upon exit, the code returns to the users context with the vector
 * facility turned on.
 *
 * ENTRY:	VM switched ON
 *		Interrupts  OFF
 *              State is saved in savearea pointed to by R4.
 *				All other registers are free.
 * 
 */

			.align	5
			.globl	EXT(vec_switch)

LEXT(vec_switch)

#if DEBUG
			lis		r3,hi16(EXT(vec_trap_count))	; Get address of vector trap counter
			ori		r3,r3,lo16(EXT(vec_trap_count))	; Get address of vector trap counter
			lwz		r1,0(r3)
			addi	r1,r1,1
			stw		r1,0(r3)
#endif /* DEBUG */

			mfsprg	r26,0							; Get the per_processor block
			mfmsr	r19								; Get the current MSR 
			
			mr		r25,r4							; Save the entry savearea
			lwz		r22,VMXowner(r26)				; Get the thread that owns the vector
			lwz		r10,PP_ACTIVE_THREAD(r26)		; Get the pointer to the active thread
			oris	r19,r19,hi16(MASK(MSR_VEC))		; Enable the vector feature
			lwz		r17,THREAD_TOP_ACT(r10)			; Now get the activation that is running
				
			mtmsr	r19								; Enable vector instructions
			isync
			
			lwz		r27,ACT_MACT_PCB(r17)			; Get the current level
			lwz		r29,curctx(r17)					; Grab the current context anchor of the current thread

;			R22 has the "old" context anchor
;			R29 has the "new" context anchor

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x5F01						; (TEST/DEBUG)
			mr		r3,r22							; (TEST/DEBUG)
			mr		r5,r29							; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	

			lhz		r16,PP_CPU_NUMBER(r26)			; Get the current CPU number
			
vsvretry:	mr.		r22,r22							; See if there is any live vector status
			
			beq-	vsnosave						; No live context, so nothing to save...

			isync									; Make sure we see this in the right order

			lwz		r30,VMXsave(r22)				; Get the top savearea
			cmplw	cr2,r22,r29						; Are both old and new the same context?
			lwz		r18,VMXcpu(r22)					; Get the last CPU we ran on
			cmplwi	cr1,r30,0						; Anything saved yet?
			cmplw	r18,r16							; Make sure we are on the right processor
			lwz		r31,VMXlevel(r22)				; Get the context level
			
			lwz		r10,liveVRS(r26)				; Get the right VRSave register

			bne-	vsnosave						; No, not on the same processor...
		
;
;			Check to see if the live context has already been saved.
;			Also check to see if all we are here just to re-enable the MSR
;			and handle specially if so.
;

			cmplw	r31,r27							; See if the current and active levels are the same
			crand	cr0_eq,cr2_eq,cr0_eq			; Remember if both the levels and contexts are the same
			li		r8,0							; Clear this
			
			beq-	vsthesame						; New and old are the same, just go enable...

			cmplwi	cr2,r10,0						; Check VRSave to see if we really need to save anything...
			beq-	cr1,vsmstsave					; Not saved yet, go do it...
			
			lwz		r11,SAVlevel(r30)				; Get the level of top saved context
			
			cmplw	r31,r11							; Are live and saved the same?

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x5F02						; (TEST/DEBUG)
			mr		r3,r30							; (TEST/DEBUG)
			mr		r5,r31							; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	

			bne-	vsmstsave						; Live context has not been saved yet...

			bne-	cr2,vsnosave					; Live context saved and VRSave not 0, no save and keep context...
			
			lwz		r4,SAVprev(r30)					; Pick up the previous area
			li		r5,0							; Assume this is the only one (which should be the ususal case)
			mr.		r4,r4							; Was this the only one?
			stw		r4,VMXsave(r22)					; Dequeue this savearea
			beq+	vsonlyone						; This was the only one...
			lwz		r5,SAVlevel(r4)					; Get the level associated with previous save

vsonlyone:	stw		r5,VMXlevel(r22)				; Save the level
			stw		r8,VMXowner(r26)				; Clear owner
			eieio
			mr		r3,r30							; Copy the savearea we are tossing
			bl		EXT(save_ret)					; Toss the savearea
			b		vsnosave						; Go load up the context...

			.align	5

	
vsmstsave:	stw		r8,VMXowner(r26)				; Clear owner
			eieio
			beq-	cr2,vsnosave					; The VRSave was 0, so there is nothing to save...

			bl		EXT(save_get)					; Go get a savearea

			lwz		r12,facAct(r22)					; Get the activation associated with the context
			stw		r3,VMXsave(r22)					; Set this as the latest context savearea for the thread

			stw		r30,SAVprev(r3)					; Point us to the old context
			stw		r31,SAVlevel(r3)				; Tag our level
			li		r7,SAVvector					; Get the vector ID
			stw		r12,SAVact(r3)					; Make sure we point to the right guy
			stb		r7,SAVflags+2(r3)				; Set that we have a vector save area

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x5F03						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	

			lwz		r10,liveVRS(r26)				; Get the right VRSave register
			lis		r9,0x5555						; Mask with odd bits set		
			rlwinm	r11,r10,1,0,31					; Shift over 1
			ori		r9,r9,0x5555					; Finish mask
			or		r21,r10,r11						; After this, even bits show which lines to zap
			
			andc	r13,r21,r9						; Clear out odd bits
			
			la		r11,savevr0(r3)					; Point to line 0
			rlwinm	r24,r13,15,0,15					; Move line 8-15 flags to high order odd bits
			or		r24,r13,r24						; Set the odd bits
													; (bit 0 is line 0, bit 1 is line 8,
													; bit 2 is line 1, bit 3 is line 9, etc.
			rlwimi	r24,r10,16,16,31				; Put vrsave 0 - 15 into positions 16 - 31
			la		r21,savevr2(r3)					; Point to line 1
			mtcrf	255,r24							; Load up the CRs
			stw		r10,savevrvalid(r3)				; Save the validity information
			mr		r12,r11							; Start registers off
;	
;			Save the current vector state
;
						
			bf		0,nol0							; No line 0 to do...
			dcba	br0,r11							; Allocate cache line 0
			
nol0:		
			la		r11,savevr4(r3)					; Point to line 2
			bf		2,nol1							; No line 1 to do...
			dcba	br0,r21							; Allocate cache line 1
			
nol1:		
			la		r21,savevr6(r3)					; Point to line 3
			bf		4,nol2							; No line 2 to do...
			dcba	br0,r11							; Allocate cache line 2
			
nol2:		
			li		r14,16							; Get offset for odd registers
			bf		16,novr0						; Do not save VR0...
			stvxl	v0,br0,r12						; Save VR0
			
novr0:		
			la		r13,savevr2(r3)					; Point to V2/V3 pair
			bf		17,novr1						; Do not save VR1...
			stvxl	v1,r14,r12						; Save VR1
			
novr1:
			la		r11,savevr8(r3)					; Point to line 4
			bf		6,nol3							; No line 3 to do...
			dcba	br0,r21							; Allocate cache line 3
			
nol3:		
			la		r12,savevr4(r3)					; Point to V4/V5 pair
			bf		18,novr2						; Do not save VR2...
			stvxl	v2,br0,r13						; Save VR2
			
novr2:
			bf		19,novr3						; Do not save VR3...
			stvxl	v3,r14,r13						; Save VR3
			
novr3:
;
;			Note: CR4 is now free
;
			la		r21,savevr10(r3)				; Point to line 5
			bf		8,nol4							; No line 4 to do...
			dcba	br0,r11							; Allocate cache line 4
			
nol4:		
			la		r13,savevr6(r3)					; Point to R6/R7 pair
			bf		20,novr4						; Do not save VR4...
			stvxl	v4,br0,r12						; Save VR4
			
novr4:
			bf		21,novr5						; Do not save VR5...
			stvxl	v5,r14,r12						; Save VR5
			
novr5:
			mtcrf	0x08,r10						; Set CRs for registers 16-19
			la		r11,savevr12(r3)				; Point to line 6
			bf		10,nol5							; No line 5 to do...
			dcba	br0,r21							; Allocate cache line 5
			
nol5:		
			la		r12,savevr8(r3)					; Point to V8/V9 pair
			bf		22,novr6						; Do not save VR6...
			stvxl	v6,br0,r13						; Save VR6
			
novr6:
			bf		23,novr7						; Do not save VR7...
			stvxl	v7,r14,r13						; Save VR7
			
novr7:
;
;			Note: CR5 is now free
;
			la		r21,savevr14(r3)				; Point to line 7
			bf		12,nol6							; No line 6 to do...
			dcba	br0,r11							; Allocate cache line 6
			
nol6:		
			la		r13,savevr10(r3)				; Point to V10/V11 pair
			bf		24,novr8						; Do not save VR8...
			stvxl	v8,br0,r12						; Save VR8
			
novr8:
			bf		25,novr9						; Do not save VR9...
			stvxl	v9,r14,r12						; Save VR9
			
novr9:
			mtcrf	0x04,r10						; Set CRs for registers 20-23
			la		r11,savevr16(r3)				; Point to line 8
			bf		14,nol7							; No line 7 to do...
			dcba	br0,r21							; Allocate cache line 7
			
nol7:		
			la		r12,savevr12(r3)				; Point to V12/V13 pair
			bf		26,novr10						; Do not save VR10...
			stvxl	v10,br0,r13						; Save VR10
			
novr10:
			bf		27,novr11						; Do not save VR11...
			stvxl	v11,r14,r13						; Save VR11
			
novr11:

;
;			Note: CR6 is now free
;
			la		r21,savevr18(r3)				; Point to line 9
			bf		1,nol8							; No line 8 to do...
			dcba	br0,r11							; Allocate cache line 8
			
nol8:		
			la		r13,savevr14(r3)				; Point to V14/V15 pair
			bf		28,novr12						; Do not save VR12...
			stvxl	v12,br0,r12						; Save VR12
			
novr12:
			bf		29,novr13						; Do not save VR13...
			stvxl	v13,r14,r12						; Save VR13
			
novr13:
			mtcrf	0x02,r10						; Set CRs for registers 24-27
			la		r11,savevr20(r3)				; Point to line 10
			bf		3,nol9							; No line 9 to do...
			dcba	br0,r21							; Allocate cache line 9
			
nol9:		
			la		r12,savevr16(r3)				; Point to V16/V17 pair
			bf		30,novr14						; Do not save VR14...
			stvxl	v14,br0,r13						; Save VR14
			
novr14:
			bf		31,novr15						; Do not save VR15...
			stvxl	v15,r14,r13						; Save VR15
			
novr15:
;
;			Note: CR7 is now free
;
			la		r21,savevr22(r3)				; Point to line 11
			bf		5,nol10							; No line 10 to do...
			dcba	br0,r11							; Allocate cache line 10
			
nol10:		
			la		r13,savevr18(r3)				; Point to V18/V19 pair
			bf		16,novr16						; Do not save VR16...
			stvxl	v16,br0,r12						; Save VR16
			
novr16:
			bf		17,novr17						; Do not save VR17...
			stvxl	v17,r14,r12						; Save VR17
			
novr17:
			mtcrf	0x01,r10						; Set CRs for registers 28-31
;
;			Note: All registers have been or are accounted for in CRs
;
			la		r11,savevr24(r3)				; Point to line 12
			bf		7,nol11							; No line 11 to do...
			dcba	br0,r21							; Allocate cache line 11
			
nol11:		
			la		r12,savevr20(r3)				; Point to V20/V21 pair
			bf		18,novr18						; Do not save VR18...
			stvxl	v18,br0,r13						; Save VR18
			
novr18:
			bf		19,novr19						; Do not save VR19...
			stvxl	v19,r14,r13						; Save VR19
			
novr19:
			la		r21,savevr26(r3)				; Point to line 13
			bf		9,nol12							; No line 12 to do...
			dcba	br0,r11							; Allocate cache line 12
			
nol12:		
			la		r13,savevr22(r3)				; Point to V22/V23 pair
			bf		20,novr20						; Do not save VR20...
			stvxl	v20,br0,r12						; Save VR20
			
novr20:
			bf		21,novr21						; Do not save VR21...
			stvxl	v21,r14,r12						; Save VR21
			
novr21:
			la		r11,savevr28(r3)				; Point to line 14
			bf		11,nol13						; No line 13 to do...
			dcba	br0,r21							; Allocate cache line 13
			
nol13:		
			la		r12,savevr24(r3)				; Point to V24/V25 pair
			bf		22,novr22						; Do not save VR22...
			stvxl	v22,br0,r13						; Save VR22
			
novr22:
			bf		23,novr23						; Do not save VR23...
			stvxl	v23,r14,r13						; Save VR23
			
novr23:
			la		r21,savevr30(r3)				; Point to line 15
			bf		13,nol14						; No line 14 to do...
			dcba	br0,r11							; Allocate cache line 14
			
nol14:		
			la		r13,savevr26(r3)				; Point to V26/V27 pair
			bf		24,novr24						; Do not save VR24...
			stvxl	v24,br0,r12						; Save VR24
			
novr24:
			bf		25,novr25						; Do not save VR25...
			stvxl	v25,r14,r12						; Save VR25
			
novr25:
			bf		15,nol15						; No line 15 to do...
			dcba	br0,r21							; Allocate cache line 15
			
nol15:		
;
;			Note: All cache lines allocated now
;
			la		r12,savevr28(r3)				; Point to V28/V29 pair
			bf		26,novr26						; Do not save VR26...
			stvxl	v26,br0,r13						; Save VR26
			
novr26:
			bf		27,novr27						; Do not save VR27...
			stvxl	v27,r14,r13						; Save VR27
			
novr27:
			la		r13,savevr30(r3)				; Point to V30/V31 pair
			bf		28,novr28						; Do not save VR28...
			stvxl	v28,br0,r12						; Save VR28
			
novr28:		
			bf		29,novr29						; Do not save VR29...
			stvxl	v29,r14,r12						; Save VR29
			
novr29:		
			bf		30,novr30						; Do not save VR30...
			stvxl	v30,br0,r13						; Save VR30
			
novr30:
			bf		31,novr31						; Do not save VR31...
			stvxl	v31,r14,r13						; Save VR31
			
novr31:

			

;
;			The context is all saved now and the facility is free.
;
;			If we do not we need to fill the registers with junk, because this level has 
;			never used them before and some thieving bastard could hack the old values
;			of some thread!  Just imagine what would happen if they could!  Why, nothing
;			would be safe! My God! It is terrifying!
;
;			Also, along the way, thanks to Ian Ollmann, we generate the 0x7FFFDEAD (QNaNbarbarian)
;			constant that we may need to fill unused vector registers.
;




vsnosave:	vspltisb v31,-10						; Get 0xF6F6F6F6	
			lwz		r15,ACT_MACT_PCB(r17)			; Get the current level of the "new" one
			vspltisb v30,5							; Get 0x05050505	
			lwz		r19,VMXcpu(r29)					; Get the last CPU we ran on
			vspltish v29,4							; Get 0x00040004
			lwz		r14,VMXsave(r29)				; Point to the top of the "new" context stack
			vrlb	v31,v31,v30						; Get 0xDEDEDEDE

			stw		r16,VMXcpu(r29)					; Claim context for us
			eieio

#if FPVECDBG
			lwz		r13,VMXlevel(r29)				; (TEST/DEBUG)
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x5F04						; (TEST/DEBUG)
			mr		r1,r15							; (TEST/DEBUG)
			mr		r3,r14							; (TEST/DEBUG)
			mr		r5,r13							; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
			
			lis		r18,hi16(EXT(per_proc_info))	; Set base per_proc
			vspltisb v28,-2							; Get 0xFEFEFEFE		   
			mulli	r19,r19,ppSize					; Find offset to the owner per_proc			
			vsubuhm	v31,v31,v29						; Get 0xDEDADEDA
			ori		r18,r18,lo16(EXT(per_proc_info))	; Set base per_proc
			vpkpx	v30,v28,v3						; Get 0x7FFF7FFF
			li		r16,VMXowner					; Displacement to vector owner
			add		r19,r18,r19						; Point to the owner per_proc	
			vrlb	v31,v31,v29						; Get 0xDEADDEAD	
			li		r0,0
			
vsinvothr:	lwarx	r18,r16,r19						; Get the owner
			cmplw	r18,r29							; Does he still have this context?
			bne		vsinvoths						; Nope...		
			stwcx.	r0,r16,r19						; Try to invalidate it
			bne-	vsinvothr						; Try again if there was a collision...
		
	
vsinvoths:	cmplwi	cr1,r14,0						; Do we possibly have some context to load?
			vmrghh	v31,v30,v31						; Get 0x7FFFDEAD.  V31 keeps this value until the bitter end
			stw		r15,VMXlevel(r29)				; Set the "new" active level
			eieio
			stw		r29,VMXowner(r26)				; Mark us as having the live context

			beq-	cr1,ProtectTheAmericanWay		; Nothing to restore, first time use...
		
			lwz		r3,SAVprev(r14)					; Get the previous context
			lwz		r0,SAVlevel(r14)				; Get the level of first facility savearea
			cmplw	r0,r15							; Top level correct to load?
			bne-	ProtectTheAmericanWay			; No, go initialize...
			
			stw		r3,VMXsave(r29)					; Pop the context (we will toss the savearea later)

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x5F05						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	

			lwz		r22,savevrsave(r25)				; Get the most current VRSAVE
			lwz		r10,savevrvalid(r14)			; Get the valid VRs in the savearea
			lis		r9,0x5555						; Mask with odd bits set
			and		r10,r10,r22						; Figure out just what registers need to be loaded
			ori		r9,r9,0x5555					; Finish mask
			rlwinm	r11,r10,1,0,31					; Shift over 1
			or		r12,r10,r11						; After this, even bits show which lines to touch
			andc	r13,r12,r9						; Clear out odd bits
			
			la		r20,savevr0(r14)				; Point to line 0
			rlwinm	r3,r13,15,0,15					; Move line 8-15 flags to high order odd bits
			la		r21,savevr2(r3)					; Point to line 1
			or		r3,r13,r3						; Set the odd bits
													; (bit 0 is line 0, bit 1 is line 8,
													; bit 2 is line 1, bit 3 is line 9, etc.
			rlwimi	r3,r10,16,16,31					; Put vrsave 0 - 15 into positions 16 - 31
			mtcrf	255,r3							; Load up the CRs
			mr		r22,r20							; Start registers off
;	
;			Load the new vector state
;
						
			bf		0,lnol0							; No line 0 to do...
			dcbt	br0,r20							; Touch cache line 0
			
lnol0:		
			la		r20,savevr4(r14)				; Point to line 2
			bf		2,lnol1							; No line 1 to do...
			dcbt	br0,r21							; Touch cache line 1
			
lnol1:		
			la		r21,savevr6(r14)				; Point to line 3
			bf		4,lnol2							; No line 2 to do...
			dcbt	br0,r20							; Touch cache line 2
			
lnol2:		
			li		r30,16							; Get offset for odd registers
			bf		16,lnovr0						; Do not restore VR0...
			lvxl	v0,br0,r22						; Restore VR0
			
lnovr0:		
			la		r23,savevr2(r14)				; Point to V2/V3 pair
			bf		17,lnovr1						; Do not restore VR1...
			lvxl	v1,r30,r22						; Restore VR1
			
lnovr1:
			la		r20,savevr8(r14)				; Point to line 4
			bf		6,lnol3							; No line 3 to do...
			dcbt	br0,r21							; Touch cache line 3
			
lnol3:		
			la		r22,savevr4(r14)				; Point to V4/V5 pair
			bf		18,lnovr2						; Do not restore VR2...
			lvxl	v2,br0,r23						; Restore VR2
			
lnovr2:
			bf		19,lnovr3						; Do not restore VR3...
			lvxl	v3,r30,r23						; Restore VR3
			
lnovr3:
;
;			Note: CR4 is now free
;
			la		r21,savevr10(r14)				; Point to line 5
			bf		8,lnol4							; No line 4 to do...
			dcbt	br0,r20							; Touch cache line 4
			
lnol4:		
			la		r23,savevr6(r14)				; Point to R6/R7 pair
			bf		20,lnovr4						; Do not restore VR4...
			lvxl	v4,br0,r22						; Restore VR4
			
lnovr4:
			bf		21,lnovr5						; Do not restore VR5...
			lvxl	v5,r30,r22						; Restore VR5
			
lnovr5:
			mtcrf	0x08,r10						; Set CRs for registers 16-19
			la		r20,savevr12(r14)				; Point to line 6
			bf		10,lnol5						; No line 5 to do...
			dcbt	br0,r21							; Touch cache line 5
			
lnol5:		
			la		r22,savevr8(r14)				; Point to V8/V9 pair
			bf		22,lnovr6						; Do not restore VR6...
			lvxl	v6,br0,r23						; Restore VR6
			
lnovr6:
			bf		23,lnovr7						; Do not restore VR7...
			lvxl	v7,r30,r23						; Restore VR7
			
lnovr7:
;
;			Note: CR5 is now free
;
			la		r21,savevr14(r14)				; Point to line 7
			bf		12,lnol6						; No line 6 to do...
			dcbt	br0,r20							; Touch cache line 6
			
lnol6:		
			la		r23,savevr10(r14)				; Point to V10/V11 pair
			bf		24,lnovr8						; Do not restore VR8...
			lvxl	v8,br0,r22						; Restore VR8
			
lnovr8:
			bf		25,lnovr9						; Do not save VR9...
			lvxl	v9,r30,r22						; Restore VR9
			
lnovr9:
			mtcrf	0x04,r10						; Set CRs for registers 20-23
			la		r20,savevr16(r14)				; Point to line 8
			bf		14,lnol7						; No line 7 to do...
			dcbt	br0,r21							; Touch cache line 7
			
lnol7:		
			la		r22,savevr12(r14)				; Point to V12/V13 pair
			bf		26,lnovr10						; Do not restore VR10...
			lvxl	v10,br0,r23						; Restore VR10
			
lnovr10:
			bf		27,lnovr11						; Do not restore VR11...
			lvxl	v11,r30,r23						; Restore VR11
			
lnovr11:

;
;			Note: CR6 is now free
;
			la		r21,savevr18(r14)				; Point to line 9
			bf		1,lnol8							; No line 8 to do...
			dcbt	br0,r20							; Touch cache line 8
			
lnol8:		
			la		r23,savevr14(r14)				; Point to V14/V15 pair
			bf		28,lnovr12						; Do not restore VR12...
			lvxl	v12,br0,r22						; Restore VR12
			
lnovr12:
			bf		29,lnovr13						; Do not restore VR13...
			lvxl	v13,r30,r22						; Restore VR13
			
lnovr13:
			mtcrf	0x02,r10						; Set CRs for registers 24-27
			la		r20,savevr20(r14)				; Point to line 10
			bf		3,lnol9							; No line 9 to do...
			dcbt	br0,r21							; Touch cache line 9
			
lnol9:		
			la		r22,savevr16(r14)				; Point to V16/V17 pair
			bf		30,lnovr14						; Do not restore VR14...
			lvxl	v14,br0,r23						; Restore VR14
			
lnovr14:
			bf		31,lnovr15						; Do not restore VR15...
			lvxl	v15,r30,r23						; Restore VR15
			
lnovr15:
;
;			Note: CR7 is now free
;
			la		r21,savevr22(r14)				; Point to line 11
			bf		5,lnol10						; No line 10 to do...
			dcbt	br0,r20							; Touch cache line 10
			
lnol10:		
			la		r23,savevr18(r14)				; Point to V18/V19 pair
			bf		16,lnovr16						; Do not restore VR16...
			lvxl	v16,br0,r22						; Restore VR16
			
lnovr16:
			bf		17,lnovr17						; Do not restore VR17...
			lvxl	v17,r30,r22						; Restore VR17
			
lnovr17:
			mtcrf	0x01,r10						; Set CRs for registers 28-31
;
;			Note: All registers have been or are accounted for in CRs
;
			la		r20,savevr24(r14)				; Point to line 12
			bf		7,lnol11						; No line 11 to do...
			dcbt	br0,r21							; Touch cache line 11
			
lnol11:		
			la		r22,savevr20(r14)				; Point to V20/V21 pair
			bf		18,lnovr18						; Do not restore VR18...
			lvxl	v18,br0,r23						; Restore VR18
			
lnovr18:
			bf		19,lnovr19						; Do not restore VR19...
			lvxl	v19,r30,r23						; Restore VR19
			
lnovr19:
			la		r21,savevr26(r14)				; Point to line 13
			bf		9,lnol12						; No line 12 to do...
			dcbt	br0,r20							; Touch cache line 12
			
lnol12:		
			la		r23,savevr22(r14)				; Point to V22/V23 pair
			bf		20,lnovr20						; Do not restore VR20...
			lvxl	v20,br0,r22						; Restore VR20
			
lnovr20:
			bf		21,lnovr21						; Do not restore VR21...
			lvxl	v21,r30,r22						; Restore VR21
			
lnovr21:
			la		r20,savevr28(r14)				; Point to line 14
			bf		11,lnol13						; No line 13 to do...
			dcbt	br0,r21							; Touch cache line 13
			
lnol13:		
			la		r22,savevr24(r14)				; Point to V24/V25 pair
			bf		22,lnovr22						; Do not restore VR22...
			lvxl	v22,br0,r23						; Restore VR22
			
lnovr22:
			bf		23,lnovr23						; Do not restore VR23...
			lvxl	v23,r30,r23						; Restore VR23
			
lnovr23:
			la		r21,savevr30(r14)				; Point to line 15
			bf		13,lnol14						; No line 14 to do...
			dcbt	br0,r20							; Touch cache line 14
			
lnol14:		
			la		r23,savevr26(r14)				; Point to V26/V27 pair
			bf		24,lnovr24						; Do not restore VR24...
			lvxl	v24,br0,r22						; Restore VR24
			
lnovr24:
			bf		25,lnovr25						; Do not restore VR25...
			lvxl	v25,r30,r22						; Restore VR25
			
lnovr25:
			bf		15,lnol15						; No line 15 to do...
			dcbt	br0,r21							; Touch cache line 15
			
lnol15:		
;
;			Note: All needed cache lines have been touched now
;
			la		r22,savevr28(r14)				; Point to V28/V29 pair
			bf		26,lnovr26						; Do not restore VR26...
			lvxl	v26,br0,r23						; Restore VR26
			
lnovr26:
			bf		27,lnovr27						; Do not restore VR27...
			lvxl	v27,r30,r23						; Restore VR27
			
lnovr27:
			la		r23,savevr30(r14)				; Point to V30/V31 pair
			bf		28,lnovr28						; Do not restore VR28...
			lvxl	v28,br0,r22						; Restore VR28
			
lnovr28:		
			bf		29,lnovr29						; Do not restore VR29...
			lvxl	v29,r30,r22						; Restore VR29
			
lnovr29:		
			bf		30,lnovr30						; Do not restore VR30...
			lvxl	v30,br0,r23						; Restore VR30
			
lnovr30:
;
;			Everything is restored now except for VR31.  We need it to get
;			the QNaNBarbarian value to put into idle vector registers. 
;			Note: V31 was set above to QNaNbarbarian
;
			
			cmpwi	r10,-1							; Handle the quick case of all registers in use
			beq-	mstlvr31						; Not likely, but all are in use...
			mtcrf	255,r10							; Get mask of valid registers

			bt		0,ni0							; Register is ok already...
			vor		v0,v31,v31						; Copy into the next register
ni0:
			bt		1,ni1							; Register is ok already...
			vor		v1,v31,v31						; Copy into the next register
ni1:
			bt		2,ni2							; Register is ok already...
			vor		v2,v31,v31						; Copy into the next register
ni2:
			bt		3,ni3							; Register is ok already...
			vor		v3,v31,v31						; Copy into the next register
ni3:
			bt		4,ni4							; Register is ok already...
			vor		v4,v31,v31						; Copy into the next register
ni4:
			bt		5,ni5							; Register is ok already...
			vor		v5,v31,v31						; Copy into the next register
ni5:
			bt		6,ni6							; Register is ok already...
			vor		v6,v31,v31						; Copy into the next register
ni6:
			bt		7,ni7							; Register is ok already...
			vor		v7,v31,v31						; Copy into the next register
ni7:
			bt		8,ni8							; Register is ok already...
			vor		v8,v31,v31						; Copy into the next register
ni8:
			bt		9,ni9							; Register is ok already...
			vor		v9,v31,v31						; Copy into the next register
ni9:
			bt		10,ni10							; Register is ok already...
			vor		v10,v31,v31						; Copy into the next register
ni10:
			bt		11,ni11							; Register is ok already...
			vor		v11,v31,v31						; Copy into the next register
ni11:
			bt		12,ni12							; Register is ok already...
			vor		v12,v31,v31						; Copy into the next register
ni12:
			bt		13,ni13							; Register is ok already...
			vor		v13,v31,v31						; Copy into the next register
ni13:
			bt		14,ni14							; Register is ok already...
			vor		v14,v31,v31						; Copy into the next register
ni14:
			bt		15,ni15							; Register is ok already...
			vor		v15,v31,v31						; Copy into the next register
ni15:
			bt		16,ni16							; Register is ok already...
			vor		v16,v31,v31						; Copy into the next register
ni16:
			bt		17,ni17							; Register is ok already...
			vor		v17,v31,v31						; Copy into the next register
ni17:
			bt		18,ni18							; Register is ok already...
			vor		v18,v31,v31						; Copy into the next register
ni18:
			bt		19,ni19							; Register is ok already...
			vor		v19,v31,v31						; Copy into the next register
ni19:
			bt		20,ni20							; Register is ok already...
			vor		v20,v31,v31						; Copy into the next register
ni20:
			bt		21,ni21							; Register is ok already...
			vor		v21,v31,v31						; Copy into the next register
ni21:
			bt		22,ni22							; Register is ok already...
			vor		v22,v31,v31						; Copy into the next register
ni22:
			bt		23,ni23							; Register is ok already...
			vor		v23,v31,v31						; Copy into the next register
ni23:
			bt		24,ni24							; Register is ok already...
			vor		v24,v31,v31						; Copy into the next register
ni24:
			bt		25,ni25							; Register is ok already...
			vor		v25,v31,v31						; Copy into the next register
ni25:
			bt		26,ni26							; Register is ok already...
			vor		v26,v31,v31						; Copy into the next register
ni26:
			bt		27,ni27							; Register is ok already...
			vor		v27,v31,v31						; Copy into the next register
ni27:
			bt		28,ni28							; Register is ok already...
			vor		v28,v31,v31						; Copy into the next register
ni28:
			bt		29,ni29							; Register is ok already...
			vor		v29,v31,v31						; Copy into the next register
ni29:
			bt		30,ni30							; Register is ok already...
			vor		v30,v31,v31						; Copy into the next register
ni30:
			bf		31,lnovr31						; V31 is empty, no need to restore...

mstlvr31:	lvxl	v31,r30,r23						; Restore VR31
			
lnovr31:	mr		r3,r14							; Get the old savearea (we popped it before)
			bl		EXT(save_ret)					; Toss it
			
vrenable:	lwz		r8,savesrr1(r25)				; Get the msr of the interrupted guy
			rlwinm	r5,r25,0,0,19					; Get the page address of the savearea 
			oris	r8,r8,hi16(MASK(MSR_VEC))		; Enable the vector facility
			lwz		r10,ACT_MACT_SPF(r17)			; Get the act special flags
			lwz		r11,spcFlags(r26)				; Get per_proc spec flags cause not in sync with act
			lwz		r5,SACvrswap(r5)				; Get Virtual to Real translation 
			oris	r10,r10,hi16(vectorUsed|vectorCng)	; Set that we used vectors
			oris	r11,r11,hi16(vectorUsed|vectorCng)	; Set that we used vectors
			rlwinm.	r0,r8,0,MSR_PR_BIT,MSR_PR_BIT	; See if we are doing this for user state
			stw		r8,savesrr1(r25)				; Set the msr of the interrupted guy
			xor		r3,r25,r5						; Get the real address of the savearea
			beq-	vrnuser							; We are not user state...
			stw		r10,ACT_MACT_SPF(r17)			; Set the activation copy
			stw		r11,spcFlags(r26)				; Set per_proc copy

vrnuser:
#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x5F07						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
			b		EXT(exception_exit)				; Exit to the fray...

/*
 *			Initialize the registers to some bogus value
 */

ProtectTheAmericanWay:
			
#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x5F06						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
			
			vor		v0,v31,v31						; Copy into the next register
			vor		v1,v31,v31						; Copy into the next register
			vor		v2,v31,v31						; Copy into the next register
			vor		v3,v31,v31						; Copy into the next register
			vor		v4,v31,v31						; Copy into the next register
			vor		v5,v31,v31						; Copy into the next register
			vor		v6,v31,v31						; Copy into the next register
			vor		v7,v31,v31						; Copy into the next register
			vor		v8,v31,v31						; Copy into the next register
			vor		v9,v31,v31						; Copy into the next register
			vor		v10,v31,v31						; Copy into the next register
			vor		v11,v31,v31						; Copy into the next register
			vor		v12,v31,v31						; Copy into the next register
			vor		v13,v31,v31						; Copy into the next register
			vor		v14,v31,v31						; Copy into the next register
			vor		v15,v31,v31						; Copy into the next register
			vor		v16,v31,v31						; Copy into the next register
			vor		v17,v31,v31						; Copy into the next register
			vor		v18,v31,v31						; Copy into the next register
			vor		v19,v31,v31						; Copy into the next register
			vor		v20,v31,v31						; Copy into the next register
			vor		v21,v31,v31						; Copy into the next register
			vor		v22,v31,v31						; Copy into the next register
			vor		v23,v31,v31						; Copy into the next register
			vor		v24,v31,v31						; Copy into the next register
			vor		v25,v31,v31						; Copy into the next register
			vor		v26,v31,v31						; Copy into the next register
			vor		v27,v31,v31						; Copy into the next register
			vor		v28,v31,v31						; Copy into the next register
			vor		v29,v31,v31						; Copy into the next register
			vor		v30,v31,v31						; Copy into the next register
			b		vrenable						; Finish setting it all up...				



;
;			We get here when we are switching to the same context at the same level and the context
;			is still live.  Essentially, all we are doing is turning on the faility.  It may have
;			gotten turned off due to doing a context save for the current level or a context switch
;			back to the live guy.
;

			.align	5
			
vsthesame:

#if FPVECDBG
			lis		r0,hi16(CutTrace)				; (TEST/DEBUG)
			li		r2,0x5F0A						; (TEST/DEBUG)
			oris	r0,r0,lo16(CutTrace)			; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif	
			beq-	cr1,vrenable					; Not saved yet, nothing to pop, go enable and exit...
			
			lwz		r11,SAVlevel(r30)				; Get the level of top saved context
			lwz		r14,SAVprev(r30)				; Get the previous savearea
			
			cmplw	r11,r31							; Are live and saved the same?

			bne+	vrenable						; Level not the same, nothing to pop, go enable and exit...
			
			mr		r3,r30							; Get the old savearea (we popped it before)
			bl		EXT(save_ret)					; Toss it
			b		vrenable						; Go enable and exit...


;
;			This function invalidates any live vector context for the passed in facility_context.
;			This is intended to be called just before act_machine_sv_free tosses saveareas.
;

			.align	5
			.globl	EXT(toss_live_vec)

LEXT(toss_live_vec)
			
			mfmsr	r9								; Get the MSR
			rlwinm	r0,r9,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear interuptions
			rlwinm.	r8,r9,0,MSR_VEC_BIT,MSR_VEC_BIT	; Is vector on right now?
			rlwinm	r9,r9,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Make sure vector is turned off
			rlwinm	r9,r9,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Make sure fpu is turned off
			mtmsr	r0								; No interruptions
			isync
			beq+	tlvnotours						; Vector off, can not be live here...

			mfsprg	r8,0							; Get the per proc

;
;			Note that at this point, since vecs are on, we are the owner
;			of live state on this processor
;

			lwz		r6,VMXowner(r8)					; Get the thread that owns the vector
			li		r0,0							; Clear this just in case we need it
			cmplw	r6,r3							; Are we tossing our own context?
			bne-	tlvnotours						; Nope...
			
			vspltish v1,1							; Turn on the non-Java bit and saturate
			vspltisw v0,1							; Turn on the saturate bit
			vxor	v1,v1,v0						; Turn off saturate	
			mtspr	vrsave,r0						; Clear VRSAVE 
			mtvscr	v1								; Set the non-java, no saturate status

tlvnotours:	lwz		r11,VMXcpu(r3)					; Get the cpu on which we last loaded context
			lis		r12,hi16(EXT(per_proc_info))	; Set base per_proc
			mulli	r11,r11,ppSize					; Find offset to the owner per_proc			
			ori		r12,r12,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r10,VMXowner					; Displacement to vector owner
			add		r11,r12,r11						; Point to the owner per_proc	
			li		r0,0							; Set a 0 to invalidate context
			
tlvinvothr:	lwarx	r12,r10,r11						; Get the owner
			cmplw	r12,r3							; Does he still have this context?
			bne+	tlvexit							; Nope, leave...		
			stwcx.	r0,r10,r11						; Try to invalidate it
			bne-	tlvinvothr						; Try again if there was a collision...

tlvexit:	mtmsr	r9								; Restore interruptions
			isync									; Could be turning off vectors here
			blr										; Leave....

#if 0
;
;			This function invalidates any live vector context for the passed in facility_context
;			if the level is current.  It also tosses the corresponding savearea if there is one.
;			This function is primarily used whenever we detect a VRSave that is all zeros.
;

			.align	5
			.globl	EXT(vec_trash)

LEXT(vec_trash)
			
			lwz		r12,facAct(r3)					; Get the activation
			lwz		r11,VMXlevel(r3)				; Get the context level
			lwz		r10,ACT_MACT_PCB(r12)			; Grab the current level for the thread
			lwz		r9,VMXsave(r3)					; Get the savearea, if any
			cmplw	r10,r11							; Are we at the right level?
			cmplwi	cr1,r9,0						; Remember if there is a savearea
			bnelr+									; No, we do nothing...			
			
			lwz		r11,VMXcpu(r3)					; Get the cpu on which we last loaded context
			lis		r12,hi16(EXT(per_proc_info))	; Set base per_proc
			mulli	r11,r11,ppSize					; Find offset to the owner per_proc			
			ori		r12,r12,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r10,VMXowner					; Displacement to vector owner
			add		r11,r12,r11						; Point to the owner per_proc	
			li		r0,0							; Set a 0 to invalidate context
			
vtinvothr:	lwarx	r12,r10,r11						; Get the owner
			cmplw	r12,r3							; Does he still have this context?
			bne		vtnotlive						; Nope, not live anywhere...	
			stwcx.	r0,r10,r11						; Try to invalidate it
			bne-	vtinvothr						; Try again if there was a collision...

vtnotlive:	beqlr+	cr1								; Leave if there is no savearea
			lwz		r8,SAVlevel(r9)					; Get the level of the savearea
			cmplw	r8,r11							; Savearea for the current level?
			bnelr+									; No, nothing to release...
			
			lwz		r8,SAVprev(r9)					; Pick up the previous area
			mr.		r8,r8							; Is there a previous?
			beq-	vtnoprev						; Nope...
			lwz		r7,SAVlevel(r8)					; Get the level associated with save

vtnoprev:	stw		r8,VMXsave(r3)					; Dequeue this savearea
			stw		r7,VMXlevel(r3)					; Pop the level
			
			mr		r3,r9							; Get the savearea to release
			b		EXT(save_ret)					; Go and toss the save area (note, we will return from there)...
#endif	
			
;
;			Just some test code to force vector and/or floating point in the kernel
;			

			.align	5
			.globl	EXT(fctx_test)

LEXT(fctx_test)
			
			mfsprg	r3,0							; Get the per_proc block
			lwz		r3,PP_ACTIVE_THREAD(r3)			; Get the thread pointer
			mr.		r3,r3							; Are we actually up and running?
			beqlr-									; No...
			
			fmr		f0,f0							; Use floating point
			mftb	r4								; Get time base for a random number
			li		r5,1							; Get a potential vrsave to use
			andi.	r4,r4,0x3F						; Get a number from 0 - 63
			slw		r5,r5,r4						; Choose a register to save (should be 0 half the time)
			mtspr	vrsave,r5						; Set VRSave
			vor		v0,v0,v0						; Use vectors
			blr
