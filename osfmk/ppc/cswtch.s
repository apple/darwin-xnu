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

ENTRY2(load_context, Load_context, TAG_NO_FRAME_USED)

/*
 * Since this is the first thread, we came in on the interrupt
 * stack. The first thread never returns, so there is no need to
 * worry about saving its frame, hence we can reset the istackptr
 * back to the saved_state structure at it's top
 */
			

/*
 * get new thread pointer and set it into the active_threads pointer
 *
 */
	
			mfsprg	r6,0
			lwz		r0,PP_INTSTACK_TOP_SS(r6)
			lwz		r11,PP_CPU_DATA(r6)
			stw		r0,PP_ISTACKPTR(r6)
			stw		r3,CPU_ACTIVE_THREAD(r11)

/* Find the new stack and store it in active_stacks */
	
			lwz		r12,PP_ACTIVE_STACKS(r6)
			lwz		r1,THREAD_KERNEL_STACK(r3)
			lwz		r9,THREAD_TOP_ACT(r3)			/* Point to the active activation */
			stw		r1,0(r12)
			li		r0,0							/* Clear a register */
			lwz		r8,ACT_MACT_PCB(r9)				/* Get the savearea used */
			lwz		r10,SAVflags(r8)				/* Get the savearea flags */
			rlwinm	r7,r8,0,0,19					/* Switch to savearea base */
			lwz		r11,SAVprev(r8)					/* Get the previous savearea */
			mfmsr	r5								/* Since we are passing control, get our MSR values */
			lwz		r1,saver1(r8)					/* Load new stack pointer */
			rlwinm	r10,r10,0,1,31					/* Remove the attached flag */
			stw		r0,saver3(r8)					/* Make sure we pass in a 0 for the continuation */
			lwz		r7,SACvrswap(r7)				/* Get the translation from virtual to real */
			stw		r0,FM_BACKPTR(r1)				/* zero backptr */
			stw		r5,savesrr1(r8)					/* Pass our MSR to the new guy */
			stw		r10,SAVflags(r8)				/* Pass back the flags */
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

ENTRY(Call_continuation, TAG_NO_FRAME_USED)
	mtlr	r3
	mr	r1, r4		/* Load new stack pointer */
	blr			/* Jump to the continuation */

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


ENTRY(Switch_context, TAG_NO_FRAME_USED)

			mfsprg	r6,0							/* Get the per_proc block */
			lwz		r12,PP_ACTIVE_STACKS(r6)
#if DEBUG
			lwz		r11,PP_ISTACKPTR(r6)			; (DEBUG/TRACE) make sure we are not
			mr.		r11,r11							; (DEBUG/TRACE) on the interrupt
			bne+	notonintstack					; (DEBUG/TRACE) stack
			BREAKPOINT_TRAP
notonintstack:
#endif	
 			stw		r4,THREAD_CONTINUATION(r3)
			cmpwi	cr1,r4,0						/* used waaaay down below */
			lwz		r11,0(r12)
			stw		r11,THREAD_KERNEL_STACK(r3)
/*
 * Make the new thread the current thread.
 */
	
			lwz		r11,PP_CPU_DATA(r6)
			stw		r5,	CPU_ACTIVE_THREAD(r11)
			
			lwz		r11,THREAD_KERNEL_STACK(r5)
		
			lwz		r5,THREAD_TOP_ACT(r5)
			lwz		r10,PP_ACTIVE_STACKS(r6)
			lwz		r7,CTHREAD_SELF(r5)				; Pick up the user assist word
			lwz		r8,ACT_MACT_PCB(r5)				/* Get the PCB for the new guy */
		
			stw		r11,0(r10)						; Save the kernel stack address
			stw		r7,UAW(r6)						; Save the assist word for the "ultra fast path"
		
			lwz		r7,ACT_MACT_SPF(r5)				; Get the special flags
			
			lwz		r10,ACT_KLOADED(r5)
			li		r0,0
			cmpwi	cr0,r10,0
			lwz		r10,PP_ACTIVE_KLOADED(r6)
			stw		r7,spcFlags(r6)					; Set per_proc copy of the special flags
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
			lis		r0,hi16(SwitchContextCall)		/* Top part of switch context */
			lis		r9,hi16(EXT(switch_in))			/* Get top of switch in routine */
			stw		r11,ACT_MACT_PCB(r5)			/* Dequeue the savearea we're switching to */

			rlwinm	r6,r6,0,MSR_FP_BIT+1,MSR_FP_BIT-1	/* Turn off the FP */
			ori		r9,r9,lo16(EXT(switch_in))		/* Bottom half of switch in */
			lwz		r5,savesrr0(r8)					/* Set up the new SRR0 */
			rlwinm	r6,r6,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	/* Turn off the vector */
			mr		r4,r3							/* Save our old thread to pass back */
			stw		r9,savesrr0(r8)					/* Make us jump to the switch in routine */
			li		r10,MSR_SUPERVISOR_INT_OFF		/* Get the switcher's MSR */
			lwz		r9,SAVflags(r8)					/* Get the flags */
			stw		r10,savesrr1(r8)				/* Set up for switch in */
			rlwinm	r9,r9,0,15,13					/* Reset the syscall flag */
			ori		r0,r0,lo16(SwitchContextCall)	/* Bottom part of switch context */
			rlwinm	r9,r9,0,1,31					/* Clear the attached flag */
			xor		r3,r7,r8						/* Get the physical address of the new context save area */
			stw		r9,SAVflags(r8)					/* Set the flags */
/* if blocking on continuation avoid saving state */
			bne		cr1,1f
			sc										/* Switch to the new context */
	
/*			We come back here in the new thread context	
 * 			R4 was set to hold the old thread pointer, but switch_in will put it into
 *			R3 where it belongs.
 */
			blr										/* Jump into the new thread */
		
1:		stw		r5,savesrr0(r8)					/* go to real pc */
		stw		r4,saver3(r8)					/* must pass back old thread */
		b		EXT(exception_exit)				/* blocking on continuation, avoid state save */



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
 
ENTRY(switch_in, TAG_NO_FRAME_USED)
			
			lwz		r4,saver4(r3)					/* Get the old thread */
			li		r8,MSR_VM_OFF					/* Set to everything off */
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
 * void fpu_save(void)
 *
 *		To do the floating point and VMX, we keep three thread pointers:  one
 *		to the current thread, one to the thread that has the floating point context
 *		loaded into the FPU registers, and one for the VMX owner.
 *
 *		Each of these threads has three PCB pointers.  The normal PCB, the FPU pcb,
 *		and the VMX pcb.  There is also a bit for each in the savearea flags.
 *		When we take an exception, or need to use the FPU/VMX in the kernel, we call
 *		this routine.  It checks to see if there is an owner thread for the facility.
 *		If so, it saves the facility's state information in the normal PCB. Then, it
 *		turns on the appropriate flag in the savearea to indicate that the state is
 *		in that particular savearea.  Also, the thread pointer for the owner in
 *		the per_processor block is cleared.  Note that we don't have to worry about the
 *		PCB pointers in the thread because whenever the state is loaded, the associated
 *		savearea is released and the pointer cleared.  This is done so that the facility
 *		context always migrates to the normal savearea/PCB.  This always insures that
 *		no more than 2 saveareas are used for a thread.
 *
 *		When the context is loaded into the facility, the associated PCB is released if
 *		its usage flags indicate that it is empty.  (Note that return from exception and
 *		context switch honor these flags and won't release a savearea if there is unrestored
 *		facility context.) The per_processor is set to point to the facility owner's
 *		thread and the associated PCB pointer within the thread is cleared because
 *		the PCB has been released.
 *
 *		Part of loading a context is to release the savearea.  If the savearea contains
 *		other context, the savearea cannot be released.  So, what we're left with is 
 *		that there will be no normal context savearea, but one for the as-not-yet
 *		restored facility savearea.  Again, when that context is reloaded, the PCB
 *		is released, and when it is again stored, it goes into the "normal" savearea.
 *
 *		So, what do we do when there is no general context, and we have some FPU/VMX
 *		state to save?  Heck if I know, but it happens when we switch threads when
 *		we shortcut system calls.  The question is: does the target thread carry the
 *		FPU/VMX context with it or not? Actually, it don't matter, not one little bit.
 *		If we are asked to save it, we gotta.  It's a really lousy way to do it, but
 *		short of starting over with FPUs, it's what's what.  Therefore, we'll
 *		allocate an FPU context save and attach it.  
 *
 *		Actually, it's not quite that simple:  since we aren't in 
 *		in interrupt handler context (that's only in fpu_switch) we can't use 
 *		quickfret to merge FPU into general context.  So, if there is an FPU
 *		savearea, we need to use that.  So what we do is:  if there is FPU context
 *		use that.  If there is a general context, then use that.  If neither, 
 *		allocate a savearea and make that the FPU context.
 *
 *		The next thing we have to do is to allow the kernel to use both the 
 *		floating point and Altivec.  It is not recommended, but there may be a
 *		good reason to do so. So, what we need to do is to treat each of the
 *		three types of context the same, by keeping a LIFO chain of states.
 *		We do have a problem with that in that there can be multiple levels of
 *		kernel context. For example, we are using floating point and we take a
 *		page fault, and somehow start using the FPU, and take another page fault,
 *		etc. 
 *
 *		Anyway, we will hope that we only reasonably use floating point and vectors in
 *		the kernel. And try to pack the context in as few saveareas as possible.
 *
 *		The way we keep these "levels" of floating point or vector context straight is
 *		to remember the top of the normal savearea chain when we activate the 
 *		facility when it is first used.  Then, when we save that context, this value
 *		is saved in its level field.
 *
 *		What the level concept gives us is a way to distinguish between multiple
 *		independent contexts under the same thread activation. Any time we take
 *		any kind of interruption (trap, system call, I/O interruption), we are,
 *		in effect, running with a different context even though we are in the 
 *		same thread. The top savearea address is used only as a marker. It does not
 *		point to any context associated with the float or vector context. For example,
 *		the top savearea pointer will always be 0 for the user context, because there 
 *		it it always last on the list.
 *
 *		As normal context is unstacked, the first facility context is checked and
 *		if there is a match, the facility savearea is released.  This is because we
 *		are returning to a level before the facility saved there was used. In effect,
 *		this allows us to unwind the facility context saveareas at different rates.
 *
 *		In conjunction with the current activation, these markers are also used to 
 *		determine the state of the facility enablement. Whenever the facility context is
 *		"live," i.e., loaded in the hardware registers and belonging to the currently
 *		running context, the facility is enabled before dispatch.
 *
 *		There is nothing special about using floating point or vector facilities,
 *		no preliminary saving, enabling, or disabling. You just use them.  The only exception
 *		is during context switching on an SMP system.  In this case, the context must
 *		be saved as there is no guarantee that the thread will resume on the same 
 *		processor. This is not a good thing, not at all.  
 *
 *		Whenever we switch out a thread with a dirty context, we always need to save it
 *		because it can wake up on a different processor.  However, once the context has
 *		been saved, we don't need to save it again until it gets dirty, nor do we need
 *		to reload it unless someone else's context has been loaded. To handle this
 *		optimization, we need 3 things.  We need to know what processor the saved context
 *		was last loaded on, whether the loaded context could be dirty, and if we've already 
 *		saved it.
 *
 *		Whenever the facility is enabled, the processor ID is saved in the activation. This
 *		will show which processor has dirty data. When a context switch occurs, the facility 
 *		contexts are saved, but are still remembered as live. The next time we need to
 *		context switch, we first check if the state is live, and if not, do no state
 *		saving.  Then we check if the state has already been save and if not, save it.
 *		The facility is always disabled on a context switch. On a UP, this save function
 *		does not occur.
 *		
 *		Whenever a facility unavailable interruption occurs, the current state is saved
 *		if it is live and unsaved.  However, if the live state is the same as the new
 *		one to be loaded, the processor ID is checked and if it is the current processor
 *		the state does not need to be loaded or saved. The facility is simply enabled.
 *		
 *		Once allocated, facility saveareas are not released until a return is made to a
 *		previous level. Once a facility has been enabled, there is no way to tell if
 *		it will ever be used again, but it is likely.  Therefore, discarding a savearea
 *		when its context is made live is extra overhead.  So, we don't do it, but we
 *		do mark the savearea contents as invalid.
 *		
 */

/*
;		The following is the actual way it is implemented.  It doesn't quite match
;		the above text. I need to go and fix that.
;
;       Context download (operates on owner's data):
;       
;       0)	enable facility
;       1)	if no owner exit to context restore
;       2)	if context processor != current processor exit to context restore
;       3)	if current activation == owner activation:
;       	1)	if curr level == active level:
;       		1)	if top facility savearea exists:
;       			invalidate savearea by setting level to 1
;       		2)	enable facility for user
;       		3)	exit
;       	
;       	2) else go to 5
;       
;       4)	if curr level == active level:
;       	1)	if top facility savearea exists:
;       		1)	if top save level == active level exit to context restore		
;       
;       5)	allocate savearea
;       	1)	if there is a facility save and it is invalid, select it, and break
;       	2)	scan normal list for free facility area, select if found, and break
;       	3)	scan other facility for free save: select, if found, and break
;       	4)	allocate a new save area
;       
;       6)	save context
;       7)	mark facility save with curr level
;       8)	if reusing cached savearea (case #1) exit to context restore
;       9)	set facility save backchain to facility top savearea
;       10)	set facility top to savearea
;       11)	exit to context restore
;       
;       
;       Context restore/upload (operates on current activation's data):
;       
;       1)	set current to activation
;       2)	set active level to current level
;       3)	set context processor to current processor
;       4)	if no facility savearea or top save level != curr level
;       		initialize facility registers to empty value
;       5)	else 
;       	1)	load registers from savearea
;       	2)	invalidate save area by setting level to 1
;       	
;       6)	enable facility for user
;       7)	exit to interrupt return
;       
;       
;       Context save (operates on current activation's data; only used during context switch):
;       			 (context switch always disables the facility)
;       
;       1)	if no owner exit
;       2)	if owner != current activation exit
;       3)	if context processor != current processor 
;       	1)	clear owner
;       	2)	exit
;       	
;       4)	if facility top savearea level exists and == active level exit
;       5)	if curr level != active level exit
;       6)	allocate savearea
;       	1)	if there is a facility save and it is invalid, select it, and break
;       	2)	scan normal list for free facility area, select if found, and break
;       	3)	scan other facility for free save: select, if found, and break
;       	4)	allocate a new save area
;       7)	save context
;       8)	mark facility savearea with curr level
;       9)	if reusing cached savearea (case #1) exit
;       10)	set facility save backchain to facility top savearea
;       11)	set facility top to savearea
;       12)	exit
;       
;       
;       Exception exit (hw_exceptions):
;       
;       1)	disable return facility
;       2)	if returning savearea != active level 
;       	1)	if owner != current activation exit
;       	2)	if context processor != current processor:
;       		1)	clear owner
;       		2)	exit
;       	
;       	3)	if new level != active level exit
;       	4)	enable return facility
;       	5)	exit
;       
;       3)	if no facility savearea exit
;       4)	if top save level == active or top is invalid
;       	1)	dequeue top facility savearea
;       	2)	set active level to new top savearea's level
;       	3)	release savearea
;       	4)	if owner == current activation clear owner
;       5)	exit
;       
;       
;       
;       
;       if (owner == activation) && (curr level == active level)
;       	&& (activation processor == current processor) ::= context live
*/

ENTRY(fpu_save, TAG_NO_FRAME_USED)

			mfmsr	r0						; Get the MSR
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Turn off floating point forever
			rlwinm	r2,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; But do interrupts only for now
			ori		r2,r2,MASK(MSR_FP)		; Enable the floating point feature for now also
			mtmsr	r2						; Set the MSR
			isync
		
			mfsprg	r6,0					; Get the per_processor block 
			lwz		r12,PP_FPU_THREAD(r6)	; Get the thread that owns the FPU
#if FPVECDBG
			mr		r7,r0					; (TEST/DEBUG)
			li		r4,0					; (TEST/DEBUG)
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			mr.		r3,r12					; (TEST/DEBUG)
			li		r2,0x6F00				; (TEST/DEBUG)
			li		r5,0					; (TEST/DEBUG)
			beq-	noowneryet				; (TEST/DEBUG)
			lwz		r4,ACT_MACT_FPUlvl(r12)	; (TEST/DEBUG)
			lwz		r5,ACT_MACT_FPU(r12)	; (TEST/DEBUG)

noowneryet:	oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
			mr		r0,r7					; (TEST/DEBUG)
#endif	
			mflr	r2						; Save the return address
			lwz		r10,PP_CPU_DATA(r6)		; Get the CPU data pointer
			lhz		r11,PP_CPU_NUMBER(r6)	; Get our CPU number
			
			mr.		r12,r12					; Anyone own the FPU?
			
			lwz		r10,CPU_ACTIVE_THREAD(r10)	; Get the pointer to the active thread
			
			beq-	fsret					; Nobody owns the FPU, no save required...
			
			lwz		r10,THREAD_TOP_ACT(r10)	; Now get the activation that is running
			lwz		r9,ACT_MACT_FPUcpu(r12)	; Get the last CPU to use this context
			
			cmplw	r12,r10					; Do we own the FPU?
			cmplw	cr1,r9,r11				; Was the context for this processor? 
			bne+	fsret					; Facility belongs to some other activation...
			li		r3,0					; Assume we need a fix-me-up
			beq-	cr1,fsgoodcpu			; Facility last used on this processor...
			stw		r3,PP_FPU_THREAD(r6)	; Clear owner because it was really on the other processor
			b		fsret					; Bail now with no save...
			
fsgoodcpu:	lwz		r3,ACT_MACT_FPU(r12)	; Get the current FPU savearea for the thread
			lwz		r9,ACT_MACT_FPUlvl(r12)	; Get our current level indicator
			
			cmplwi	cr1,r3,0				; Have we ever saved this facility context?
			beq-	cr1,fsneedone			; Never saved it, so we need an area...
			
			lwz		r8,SAVlvlfp(r3)			; Get the level this savearea is for
			cmplwi	r8,1					; See if it is a spare
			cmplw	cr1,r9,r8				; Correct level?
			beq+	fsusespare				; We have a spare to use...
			beq-	cr1,fsret				; The current level is already saved, bail out...

fsneedone:	li		r3,0					; Tell the routine to allocate an area if none found
			bl		fpsrchsave				; Find a free savearea
			
			mfsprg	r6,0					; Get back per_processor block
			oris	r7,r7,hi16(SAVfpuvalid)	; Set the allocated bit
			lwz		r12,PP_FPU_THREAD(r6)	; Get back our thread
			mtlr	r2						; Restore return
			lwz		r8,ACT_MACT_FPU(r12)	; Get the current top floating point savearea
			lwz		r9,ACT_MACT_FPUlvl(r12)	; Get our current level indicator again		
			stw		r3,ACT_MACT_FPU(r12)	; Set this as the latest FPU savearea for the thread
			stw		r8,SAVprefp(r3)			; And then chain this in front
			stw		r7,SAVflags(r3)			; Set the validity flags
			stw		r12,SAVact(r3)			; Make sure we point to the right guy

fsusespare:	stw		r9,SAVlvlfp(r3)			; And set the level this savearea is for

;
; 			Save the current FPU state into the PCB of the thread that owns it.
; 

			la		r11,savefp0(r3)			; Point to the 1st line
			dcbz	0,r11					; Allocate the first savearea line 
			
			la		r11,savefp4(r3)			/* Point to the 2nd line */
			stfd    f0,savefp0(r3)
			dcbz	0,r11					/* allocate it */
			stfd    f1,savefp1(r3)
			stfd    f2,savefp2(r3)
			la		r11,savefp8(r3)			/* Point to the 3rd line */
			stfd    f3,savefp3(r3)
			dcbz	0,r11					/* allocate it */
			stfd    f4,savefp4(r3)
			stfd    f5,savefp5(r3)
			stfd    f6,savefp6(r3)
			la		r11,savefp12(r3)		/* Point to the 4th line */
			stfd    f7,savefp7(r3)
			dcbz	0,r11					/* allocate it */
			stfd    f8,savefp8(r3)
			stfd    f9,savefp9(r3)
			stfd    f10,savefp10(r3)
			la		r11,savefp16(r3)		/* Point to the 5th line */
			stfd    f11,savefp11(r3)
			dcbz	0,r11					/* allocate it */
			stfd    f12,savefp12(r3)
			stfd    f13,savefp13(r3)
			stfd    f14,savefp14(r3)
			la		r11,savefp20(r3)		/* Point to the 6th line */
			stfd    f15,savefp15(r3)
			stfd    f16,savefp16(r3)
			stfd    f17,savefp17(r3)
			stfd    f18,savefp18(r3)
			la		r11,savefp24(r3)		/* Point to the 7th line */
			stfd    f19,savefp19(r3)
			dcbz	0,r11					/* allocate it */
			stfd    f20,savefp20(r3)
			lwz		r10,liveFPSCR(r6)		; Get the previously saved FPSCR
			stfd    f21,savefp21(r3)
			stfd    f22,savefp22(r3)
			li		r9,0					; Just clear this out 
			la		r11,savefp28(r3)		/* Point to the 8th line */
			stfd    f23,savefp23(r3)
			dcbz	0,r11					/* allocate it */
			stfd    f24,savefp24(r3)
			stfd    f25,savefp25(r3)
			stfd    f26,savefp26(r3)
			stfd    f27,savefp27(r3)
			stfd    f28,savefp28(r3)

;			Note that we just save the FPSCR here for ease.  It is really already saved
;			in the "normal" context area of the savearea.

			stw		r9,savefpscrpad(r3)		; Save the FPSCR pad
			stw		r10,savefpscr(r3)		; Save the FPSCR
			
			stfd    f29,savefp29(r3)
			stfd    f30,savefp30(r3)
			stfd    f31,savefp31(r3)
			lfd    	f0,savefp0(r3)			; We need to restore F0 because we used it	
											; to get the FPSCR
											
#if 0
			la		r9,savefp0(r3)			; (TEST/DEBUG)
			la		r10,savefp31(r3)		; (TEST/DEBUG)
			
chkkillmedead:
			lha		r8,0(r9)				; (TEST/DEBUG)
			addi	r9,r9,8					; (TEST/DEBUG)
			cmpwi	r8,-8					; (TEST/DEBUG)
			cmplw	cr1,r9,r10				; (TEST/DEBUG)
			bne+	dontkillmedead			; (TEST/DEBUG)
			BREAKPOINT_TRAP					; (TEST/DEBUG)

dontkillmedead:								; (TEST/DEBUG)
			ble+	cr1,chkkillmedead		; (TEST/DEBUG)
#endif

fsret:		mtmsr	r0						; Put interrupts on if they were and floating point off
			isync

			blr

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

ENTRY(fpu_switch, TAG_NO_FRAME_USED)
#if DEBUG
#if GDDBG
			mr		r7,r4					; Save input parameter
			lis		r3,hi16(EXT(fpu_trap_count))	; Get address of FP trap counter
			ori		r3,r3,lo16(EXT(fpu_trap_count))	; Get address of FP trap counter
			lwz		r1,0(r3)
			lis		r5,hi16(EXT(GratefulDeb))	; Point to top of display
			ori		r5,r5,lo16(EXT(GratefulDeb))	; Put in bottom part
			addi	r1,r1,1
			mtlr	r5						; Set link register
			stw		r1,0(r3)
			mr		r4,r1
			li		r3,0
			blrl							; Display count
			mr		r4,r7					; Restore the parameter
#else
			lis		r3,hi16(EXT(fpu_trap_count))	; Get address of FP trap counter
			ori		r3,r3,lo16(EXT(fpu_trap_count))	; Get address of FP trap counter
			lwz		r1,0(r3)
			addi	r1,r1,1
			stw		r1,0(r3)
#endif
#endif /* DEBUG */

			mfsprg	r6,0					; Get the per_processor block
			mfmsr	r19						; Get the current MSR 
			
			lwz		r10,PP_CPU_DATA(r6)		; Get the CPU data pointer
			lwz		r12,PP_FPU_THREAD(r6)	; Get the thread that owns the FPU
			lwz		r10,CPU_ACTIVE_THREAD(r10)	; Get the pointer to the active thread
			ori		r19,r19,lo16(MASK(MSR_FP))	; Enable the floating point feature
			lwz		r17,THREAD_TOP_ACT(r10)	; Now get the activation that is running

;			R12 has the "old" activation
;			R17 has the "new" activation

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F01				; (TEST/DEBUG)
			mr		r3,r12					; (TEST/DEBUG)
			mr		r5,r17					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	
			mr.		r12,r12					; See if there is any live FP status
			
			lhz		r18,PP_CPU_NUMBER(r6)	; Get the current CPU, we will need it later
			
			mtmsr	r19						; Enable floating point instructions
			isync
			
			beq-	fsnosave				; No live context, so nothing to save...

			lwz		r19,ACT_MACT_FPUcpu(r12)	; Get the "old" active CPU
			lwz		r15,ACT_MACT_PCB(r12)	; Get the current level of the "old" one
			cmplw	r18,r19					; Check the CPU that the old context is live on
			lwz		r14,ACT_MACT_FPU(r12)	; Point to the top of the old context stack
			bne-	fsnosave				; Context is not live if used on a different CPU...
			lwz		r13,ACT_MACT_FPUlvl(r12)	; Get the "old" active level
			
;
;			First, check to see if all we are doing is enabling because the
;			"new" context is live.
;
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F02				; (TEST/DEBUG)
			mr		r1,r15					; (TEST/DEBUG)
			mr		r3,r13					; (TEST/DEBUG)
			mr		r5,r14					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	

			cmplw	cr1,r12,r17				; Are the "old" activation and the "new" the same?
			cmplwi	cr2,r14,0				; Is there any saved context on the "old" activation?
			bne+	cr1,fsmstsave			; The activations are different so "old" context must be saved...

;
;			Here we know that both the "old" and "new" activations are the same.  We will
;			check the current level and active levels.  If they are the same, the context is
;			already live, so all we do is turn on the facility and invalidate the top
;			savearea. 
;		
;			If the current level, the active level, and the top savearea level are the
;			same, then the context was saved as part of a thread context switch and neither
;			needs saving or restoration.
;			
;			In all other cases, the context must be saved unless we are just re-enabling
;			floating point.
;

			cmplw	r13,r15					; Are the levels the same?
			cmplwi	cr2,r14,0				; Is there any saved context?
			bne-	fsmstsave				; Levels are different, we need to save...
			
			beq-	cr2,fsenable			; No saved context at all, enable and go...
			
			lwz		r20,SAVlvlfp(r14)		; Get the level of the top savearea

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F03				; (TEST/DEBUG)
			mr		r3,r15					; (TEST/DEBUG)
			mr		r5,r20					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	
			cmplw	r15,r20					; Is the top level the same as the current?
			li		r0,1					; Get the invalid flag
			bne-	fsenable				; Not the same, just enable and go...
			
			stw		r0,SAVlvlfp(r14)		; Invalidate that top savearea

			b		fsenable				; Then enable and go...
			
;
;			We need to save the "old" context here.  The LIFO queueing scheme works
;			out for all cases because if both the "new" and "old" activations are the
;			same, there can not be any saved state to load.  the "new" level is
;			truely new.
;
;			When we save the context, we either use a new savearea, or the free
;			one that is cached at the head of the list.
			
fsmstsave:	beq-	cr2,fsgetsave			; There is no possible cached save area
			
			lwz		r5,SAVlvlfp(r14)		; Get the level of first facility savearea
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F04				; (TEST/DEBUG)
			mr		r3,r15					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	
			mr		r3,r14					; Assume we are invalid
			cmplwi	r5,1					; Is it invalid?
			cmplw	cr1,r5,r13				; Is the SA level the active one?
			beq+	fsusecache				; Invalid, just use it...
			beq-	cr1,fsnosave			; The SA level is active, it is already saved...
			
fsgetsave:	mr		r3,r4					; Use the interrupt save as the context savearea if none cached
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F05				; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	
			
			bl		fpsrchsave				; Find a free savearea

			stw		r3,ACT_MACT_FPU(r12)	; Set this as the latest context savearea for the thread
			mfsprg	r6,0					; Get back per_processor block
			stw		r14,SAVprefp(r3)		; And then chain this in front
			oris	r7,r7,hi16(SAVfpuvalid)	; Set the allocated bit
			stw		r12,SAVact(r3)			; Make sure we point to the right guy
			stw		r7,SAVflags(r3)			; Set the allocation flags

fsusecache:	la		r11,savefp0(r3)			; Point to the 1st line in area
			stw		r13,SAVlvlfp(r3)		; Set this context level
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F06				; (TEST/DEBUG)
			mr		r5,r13					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	

;
;			Now we will actually save the old context
;
			
			dcbz	0,r11					; Allocate the output area

			la		r11,savefp4(r3)			; Point to the 2nd line
			stfd    f0,savefp0(r3)
			dcbz	0,r11					; Allocate cache
			stfd    f1,savefp1(r3)
			stfd    f2,savefp2(r3)
			la		r11,savefp8(r3)			; Point to the 3rd line
			stfd    f3,savefp3(r3)
			dcbz	0,r11					; Allocate cache
			stfd    f4,savefp4(r3)
			stfd    f5,savefp5(r3)
			stfd    f6,savefp6(r3)
			la		r11,savefp12(r3)		; Point to the 4th line
			stfd    f7,savefp7(r3)
			dcbz	0,r11					; Allocate cache
			stfd    f8,savefp8(r3)
			stfd    f9,savefp9(r3)
			stfd    f10,savefp10(r3)
			la		r11,savefp16(r3)		; Point to the 5th line
			stfd    f11,savefp11(r3)
			dcbz	0,r11					; Allocate cache
			stfd    f12,savefp12(r3)
			stfd    f13,savefp13(r3)
			stfd    f14,savefp14(r3)
			la		r11,savefp20(r3)		; Point to the 6th line 
			stfd    f15,savefp15(r3)
			dcbz	0,r11					; Allocate cache
			stfd    f16,savefp16(r3)
			stfd    f17,savefp17(r3)
			stfd    f18,savefp18(r3)
			la		r11,savefp24(r3)		; Point to the 7th line
			stfd    f19,savefp19(r3)
			dcbz	0,r11					; Allocate cache
			stfd    f20,savefp20(r3)

			li		r14,0					; Clear this for now
			lwz		r15,liveFPSCR(r6)		; Get the previously saved FPSCR

			stfd    f21,savefp21(r3)
			stfd    f22,savefp22(r3)
			la		r11,savefp28(r3)		; Point to the 8th line
			stfd    f23,savefp23(r3)
			dcbz	0,r11					; allocate it
			stfd    f24,savefp24(r3)
			stfd    f25,savefp25(r3)
			stfd    f26,savefp26(r3)
			la		r11,savefpscrpad(r3)	; Point to the 9th line
			stfd    f27,savefp27(r3)
			dcbz	0,r11					; allocate it
			stfd    f28,savefp28(r3)
			stfd    f29,savefp29(r3)
			stfd    f30,savefp30(r3)
			stfd    f31,savefp31(r3)

;			Note that we just save the FPSCR here for ease.  It is really already saved
;			in the "normal" context area of the savearea.

			stw		r14,savefpscrpad(r3)	; Save the FPSCR pad
			stw		r15,savefpscr(r3)		; Save the FPSCR

;
;			The context is all saved now and the facility is free.
;
; 			Now check out the "new" and see if we need to load up his context.
;			If we do (and this should be the normal case), do it and then invalidate the
;			savearea. (This will keep it cached for quick access next time around.)
;			
;			If we do not (remember, we already took care of the case where we just enable
;			the FPU), we need to fill the registers with junk, because this level has 
;			never used them before and some thieving bastard could hack the old values
;			of some thread!  Just imagine what would happen if they could!  Why, nothing
;			would be safe! My God! It is terrifying!
;

			
fsnosave:	lwz		r15,ACT_MACT_PCB(r17)	; Get the current level of the "new" one
			lwz		r14,ACT_MACT_FPU(r17)	; Point to the top of the "new" context stack
			lwz		r13,ACT_MACT_FPUlvl(r17)	; Get the "new" active level
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F07				; (TEST/DEBUG)
			mr		r1,r15					; (TEST/DEBUG)
			mr		r3,r14					; (TEST/DEBUG)
			mr		r5,r13					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	

			cmplwi	cr1,r14,0				; Do we possibly have some context to load?
			stw		r15,ACT_MACT_FPUlvl(r17)	; Set the "new" active level
			stw		r18,ACT_MACT_FPUcpu(r17)	; Set the active CPU
			la		r11,savefp0(r14)		; Point to first line to bring in
			stw		r17,PP_FPU_THREAD(r6)	; Store current thread address in fpu_thread to claim fpu for thread
			
			beq+	cr1,MakeSureThatNoTerroristsCanHurtUsByGod	; No "new" context to load...
			lwz		r0,SAVlvlfp(r14)		; Get the level of first facility savearea
			cmplw	r0,r15					; Top level correct to load?
			bne-	MakeSureThatNoTerroristsCanHurtUsByGod	; No, go initialize...
			
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F08				; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	

			dcbt	0,r11					; Touch line in
			li		r0,1					; Get the level invalid indication
						
			la		r11,savefp4(r14)		; Point to next line
			dcbt	0,r11					; Touch line in
			lfd     f0, savefp0(r14)
			lfd     f1,savefp1(r14)
			stw		r0,SAVlvlfp(r14)		; Mark the savearea invalid because we are activating again
			lfd     f2,savefp2(r14)
			la		r11,savefp8(r14)		; Point to next line
			lfd     f3,savefp3(r14)
			dcbt	0,r11					; Touch line in
			lfd     f4,savefp4(r14)
			lfd     f5,savefp5(r14)
			lfd     f6,savefp6(r14)
			la		r11,savefp12(r14)		; Point to next line
			lfd     f7,savefp7(r14)
			dcbt	0,r11					; Touch line in
			lfd     f8,savefp8(r14)
			lfd     f9,savefp9(r14)
			lfd     f10,savefp10(r14)
			la		r11,savefp16(r14)		; Point to next line
			lfd     f11,savefp11(r14)
			dcbt	0,r11					; Touch line in
			lfd     f12,savefp12(r14)
			lfd     f13,savefp13(r14)
			lfd     f14,savefp14(r14)
			la		r11,savefp20(r14)		; Point to next line
			lfd     f15,savefp15(r14)
			dcbt	0,r11					; Touch line in
			lfd     f16,savefp16(r14)
			lfd     f17,savefp17(r14)
			lfd     f18,savefp18(r14)
			la		r11,savefp24(r14)		; Point to next line
			lfd     f19,savefp19(r14)
			dcbt	0,r11					; Touch line in
			lfd     f20,savefp20(r14)
			lfd     f21,savefp21(r14)
			la		r11,savefp28(r14)		; Point to next line
			lfd     f22,savefp22(r14)
			lfd     f23,savefp23(r14)
			dcbt	0,r11					; Touch line in
			lfd     f24,savefp24(r14)
			lfd     f25,savefp25(r14)
			lfd     f26,savefp26(r14)
			lfd     f27,savefp27(r14)
			lfd     f28,savefp28(r14)
			lfd     f29,savefp29(r14)
			lfd     f30,savefp30(r14)
			lfd     f31,savefp31(r14)
			
fsenable:	lwz		r9,SAVflags(r4)			/* Get the flags of the current savearea */
			lwz		r8,savesrr1(r4)			; Get the msr of the interrupted guy
			rlwinm	r5,r4,0,0,19			/* Get the page address of the savearea */
			ori		r8,r8,MASK(MSR_FP)		; Enable the floating point feature
			lwz		r10,ACT_MACT_SPF(r17)	; Get the special flags
			lis		r7,hi16(SAVattach)		/* Get the attached flag */
			lwz		r5,SACvrswap(r5)		/* Get Virtual to Real translation */
			oris	r10,r10,hi16(floatUsed|floatCng)	; Set that we used floating point
			mr.		r15,r15					; See if we are doing this for user state
			stw		r8,savesrr1(r4)			; Set the msr of the interrupted guy
			andc	r9,r9,r7				/* Clear the attached bit */
			xor		r3,r4,r5				/* Get the real address of the savearea */
			bne-	fsnuser					; We are not user state...
			stw		r10,ACT_MACT_SPF(r17)	; Set the activation copy
			stw		r10,spcFlags(r6)		; Set per_proc copy

fsnuser:
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F0A				; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	
			stw		r9,SAVflags(r4)			/* Set the flags of the current savearea */
			
			b		EXT(exception_exit)		/* Exit from the fray... */

/*
 *			Initialize the registers to some bogus value
 */

MakeSureThatNoTerroristsCanHurtUsByGod:
			
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x7F09				; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	
			lis		r5,hi16(EXT(FloatInit))	/* Get top secret floating point init value address */
			ori		r5,r5,lo16(EXT(FloatInit))	/* Slam bottom */
			lfd		f0,0(r5)				/* Initialize FP0 */
			fmr		f1,f0					; Do them all						
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
			fsub	f31,f31,f31				; Get set to initialize the FPSCR
			fmr		f18,f0						
			fmr		f19,f0						
			fmr		f20,f0						
			mtfsf	0xff,f31				; Clear all FPSCR exception eanbles
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
			b		fsenable				; Finish setting it all up...				

;
;			Finds an unused floating point area in the activation pointed
;			to by R12s saved contexts.  If none are found (unlikely but possible)
;			and R3 is 0, a new area is allocated.  If R3 is non-zero, it contains 
;			a pointer to an floating point savearea that is free.
;
fpsrchsave:
			lwz		r6,ACT_MACT_PCB(r12)		; Get the first "normal" savearea
			
fpsrnorm:	mr.		r5,r6						; Is there another?
			beq-	fpsrvect					; No, search the vector saveareas...
			lwz		r7,SAVflags(r5)				; Get the flags for this guy
			lwz		r6,SAVprev(r5)				; Get the previous savearea, just in case
			andis.	r8,r7,hi16(SAVfpuvalid)		; Have we found an empty FPU save in normal?
			beq+	fpsrgot						; We found one...
			b		fpsrnorm					; Search again...

fpsrvect:	lwz		r6,ACT_MACT_VMX(r12)		; Get the first "vector" savearea
			
fpsrvectx:	mr.		r5,r6						; Is there another?
			beq-	fpsrget						; No, try to allocate one...
			lwz		r7,SAVflags(r5)				; Get the flags for this guy
			lwz		r6,SAVprevec(r5)			; Get the previous savearea, just in case
			andis.	r8,r7,hi16(SAVfpuvalid)		; Have we found an empty FPU save in vector?
			bne-	fpsrvectx					; Search again...
			
fpsrgot:	mr		r3,r5						; Get the savearea into the right register
			blr									; Return...

fpsrget:	mr.		r5,r3						; Do we allocate or use existing?
			beq+	fpsrallo					; Allocate one...
			
			lwz		r7,SAVflags(r3)				; Get the passed in area flags
			blr									; Return...
;			
;			NOTE: save_get will return directly and set R7 to 0...
;
fpsrallo:	b		EXT(save_get)				; Get a fresh savearea 

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
 */

ENTRY(vec_save, TAG_NO_FRAME_USED)

			mfmsr	r0						; Get the MSR
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Turn off vector forever
			rlwinm	r2,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; But do interrupts only for now
			oris	r2,r2,hi16(MASK(MSR_VEC))	; Enable the vector facility for now also
			mtmsr	r2						; Set the MSR
			isync
		
			mfsprg	r6,0					; Get the per_processor block 
			lwz		r12,PP_VMX_THREAD(r6)	; Get the thread that owns the vector
#if FPVECDBG
			mr		r7,r0					; (TEST/DEBUG)
			li		r4,0					; (TEST/DEBUG)
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			mr.		r3,r12					; (TEST/DEBUG)
			li		r2,0x5F00				; (TEST/DEBUG)
			li		r5,0					; (TEST/DEBUG)
			beq-	noowneryeu				; (TEST/DEBUG)
			lwz		r4,ACT_MACT_VMXlvl(r12)	; (TEST/DEBUG)
			lwz		r5,ACT_MACT_VMX(r12)	; (TEST/DEBUG)

noowneryeu:	oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
			mr		r0,r7					; (TEST/DEBUG)
#endif	
			mflr	r2						; Save the return address
			lwz		r10,PP_CPU_DATA(r6)		; Get the CPU data pointer
			lhz		r11,PP_CPU_NUMBER(r6)	; Get our CPU number
			
			mr.		r12,r12					; Anyone own the vector?
			
			lwz		r10,CPU_ACTIVE_THREAD(r10)	; Get the pointer to the active thread
			
			beq-	vsret					; Nobody owns the vector, no save required...
			
			lwz		r10,THREAD_TOP_ACT(r10)	; Now get the activation that is running
			lwz		r9,ACT_MACT_VMXcpu(r12)	; Get the last CPU to use this context
			
			cmplw	r12,r10					; Do we own the thread?
			cmplw	cr1,r9,r11				; Was the context for this processor? 
			bne+	vsret					; Facility belongs to some other activation...
			li		r3,0					; Assume we need a fix-me-up
			beq-	cr1,vsgoodcpu			; Facility last used on this processor...
			stw		r3,PP_VMX_THREAD(r6)	; Clear owner because it was really on the other processor
			b		vsret					; Bail now with no save...
			
vsgoodcpu:	lwz		r3,ACT_MACT_VMX(r12)	; Get the current vector savearea for the thread
			lwz		r9,ACT_MACT_VMXlvl(r12)	; Get our current level indicator
			
			cmplwi	cr1,r3,0				; Have we ever saved this facility context?
			beq-	cr1,vsneedone			; Never saved it, so we need an area...
			
			lwz		r8,SAVlvlvec(r3)		; Get the level this savearea is for
			cmplwi	r8,1					; See if this is a spare
			cmplw	cr1,r9,r8				; Correct level?
			beq+	vsusespare				; It is still live...
			beq-	cr1,vsret				; The current level is already saved, bail out...

vsneedone:	li		r3,0					; Tell the routine to allocate an area if none found
			bl		vsrchsave				; Find a free savearea
			
			mfsprg	r6,0					; Get back per_processor block
			oris	r7,r7,hi16(SAVvmxvalid)	; Set the allocated bit
			lwz		r12,PP_VMX_THREAD(r6)	; Get back our thread
			mtlr	r2						; Restore return
			lwz		r8,ACT_MACT_VMX(r12)	; Get the current top vector savearea
			lwz		r9,ACT_MACT_VMXlvl(r12)	; Get our current level indicator again		
			stw		r3,ACT_MACT_VMX(r12)	; Set this as the latest vector savearea for the thread
			stw		r8,SAVprevec(r3)		; And then chain this in front
			stw		r7,SAVflags(r3)			; Set the allocation flags
			stw		r12,SAVact(r3)			; Make sure we point to the right guy

vsusespare:	stw		r9,SAVlvlvec(r3)		; And set the level this savearea is for
			mfcr	r2						; Save non-volatile CRs
			lwz		r10,liveVRS(r6)			; Get the right VRSave register
			lis		r9,0x5555				; Mask with odd bits set		
			rlwinm	r11,r10,1,0,31			; Shift over 1
			ori		r9,r9,0x5555			; Finish mask
			or		r12,r10,r11				; After this, even bits show which lines to zap
			
			andc	r11,r12,r9				; Clear out odd bits
			
			la		r6,savevr0(r3)			; Point to line 0
			rlwinm	r4,r11,15,0,15			; Move line 8-15 flags to high order odd bits
			la		r9,savevrvalid(r3)		; Point to the saved register mask field
			or		r4,r11,r4				; Set the odd bits
											; (bit 0 is line 0, bit 1 is line 8,
											; bit 2 is line 1, bit 3 is line 9, etc.
			dcba	br0,r9					; Allocate the cache for it
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
			mfvscr	v27						; Get the VSCR
			la		r8,savevscr(r3)			; Point to the VSCR save area
			bf		30,snovr30				; Do not save VR30...
			stvxl	v30,br0,r7				; Save VR30
			
snovr30:
			dcba	br0,r8					; Allocate VSCR savearea
			bf		31,snovr31				; Do not save VR31...
			stvxl	v31,r11,r7				; Save VR31
			
snovr31:
			add		r11,r11,r9				; Point to V27s saved value
			stvxl	v27,br0,r8				; Save the VSCR
			bt		27,v27ok				; V27 has been saved and is marked as wanted
		
			lis		r11,hi16(EXT(QNaNbarbarian))	; V27 is not wanted, so get empty value
			ori		r11,r11,lo16(EXT(QNaNbarbarian))

v27ok:		mtcrf	255,r2					; Restore all non-volatile CRs
			lvxl	v27,br0,r11				; Restore or load empty value into V27 because we used it	

;
; 			Save the current vector state into the savearea of the thread that owns it.
; 

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

ENTRY(vec_switch, TAG_NO_FRAME_USED)

#if DEBUG
#if GDDBG
			mr		r7,r4					; Save input parameter
			lis		r3,hi16(EXT(vec_trap_count))	; Get address of vector trap counter
			ori		r3,r3,lo16(EXT(vec_trap_count))	; Get address of vector trap counter
			lwz		r1,0(r3)
			lis		r5,hi16(EXT(GratefulDeb))	; Point to top of display
			ori		r5,r5,lo16(EXT(GratefulDeb))	; Put in bottom part
			addi	r1,r1,1
			mtlr	r5						; Set link register
			stw		r1,0(r3)
			mr		r4,r1
			lis		r3,1
			blrl							; Display count
			mr		r4,r7					; Restore the parameter
#else
			lis		r3,hi16(EXT(vec_trap_count))	; Get address of vector trap counter
			ori		r3,r3,lo16(EXT(vec_trap_count))	; Get address of vector trap counter
			lwz		r1,0(r3)
			addi	r1,r1,1
			stw		r1,0(r3)
#endif
#endif /* DEBUG */

			mfsprg	r6,0					/* Get the per_processor block */
			mfmsr	r19						/* Get the current MSR */
			
			lwz		r10,PP_CPU_DATA(r6)		/* Get the CPU data pointer */
			lwz		r12,PP_VMX_THREAD(r6)	/* Get the thread that owns the vector */
			lwz		r10,CPU_ACTIVE_THREAD(r10)	/* Get the pointer to the active thread */
			oris	r19,r19,hi16(MASK(MSR_VEC))	/* Enable the vector feature */
			lwz		r17,THREAD_TOP_ACT(r10)	/* Now get the activation that is running */
			
;			R12 has the "old" activation
;			R17 has the "new" activation

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F01				; (TEST/DEBUG)
			mr		r3,r12					; (TEST/DEBUG)
			mr		r5,r17					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			mr		r18,r4					; Save this
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r4,r18					; Restore it
			mfsprg	r6,0					; Get the per_processor block back
#endif
#endif	
			mr.		r12,r12					; See if there is any live vector status
			
			lhz		r18,PP_CPU_NUMBER(r6)	; Get our CPU number
		
			mtmsr	r19						/* Set vector available */
			isync
			
			
			beq-	vsnosave				; No live context, so nothing to save...
	
			lwz		r19,ACT_MACT_VMXcpu(r12)	; Get the "old" active CPU
			lwz		r15,ACT_MACT_PCB(r12)	; Get the current level of the "old" one
			cmplw	r18,r19					; Check the CPU that the old context is live on
			lwz		r14,ACT_MACT_VMX(r12)	; Point to the top of the old context stack
			bne-	vsnosave				; Context is not live if used on a different CPU...
			lwz		r13,ACT_MACT_VMXlvl(r12)	; Get the "old" active level
			
;
;			First, check to see if all we are doing is enabling because the
;			"new" context is live.
;
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F02				; (TEST/DEBUG)
			mr		r1,r15					; (TEST/DEBUG)
			mr		r3,r13					; (TEST/DEBUG)
			mr		r5,r14					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			mr		r8,r4					; Save this
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r4,r8					; Restore it
#endif
#endif	

			cmplw	cr1,r12,r17				; Is the "old" activation and the "new" the same?
			cmplwi	cr2,r14,0				; Is there any saved context on the "old" activation?
			bne+	cr1,vsmstsave			; The activations are different so "old" context must be saved...

;
;			Here we know that both the "old" and "new" activations are the same.  We will
;			check the current level and active levels.  If they are the same, the context is
;			already live, so all we do is turn on the facility and invalidate the top
;			savearea. 
;		
;			If the current level, the active level, and the top savearea level are the
;			same, then the context was saved as part of a thread context switch and neither
;			needs saving or restoration.
;			
;			In all other cases, the context must be saved unless we are just re-enabling
;			vector.
;

			cmplw	r13,r15					; Are the levels the same?
			cmplwi	cr2,r14,0				; Is there any saved context?
			bne-	vsmstsave				; Levels are different, we need to save...
			
			beq-	cr2,vrenable			; No saved context at all, enable and go...
			
			lwz		r20,SAVlvlvec(r14)		; Get the level of the top savearea

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F03				; (TEST/DEBUG)
			mr		r3,r15					; (TEST/DEBUG)
			mr		r5,r20					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			mr		r8,r4					; Save this
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r4,r8					; Restore it
#endif
#endif	
			cmplw	r15,r20					; Is the top level the same as the current?
			li		r0,1					; Get the invalid flag
			bne-	vrenable				; Not the same, just enable and go...
			
			stw		r0,SAVlvlvec(r14)		; Invalidate that top savearea

			b		vrenable				; Then enable and go...
			
;
;			We need to save the "old" context here.  The LIFO queueing scheme works
;			out for all cases because if both the "new" and "old" activations are the
;			same, there can not be any saved state to load.  the "new" level is
;			truely new.
;
;			When we save the context, we either use a new savearea, or the free
;			one that is cached at the head of the list.
			
vsmstsave:	beq-	cr2,vsgetsave			; There is no possible cached save area
			
			lwz		r5,SAVlvlvec(r14)		; Get the level of first facility savearea
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F04				; (TEST/DEBUG)
			mr		r3,r15					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			mr		r8,r4					; Save this
			mr		r7,r5					; Save this
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r4,r8					; Restore it
			mr		r5,r7					; Restore it
#endif
#endif	
			mr		r3,r14					; Assume we are invalid
			cmplwi	r5,1					; Is it invalid?
			cmplw	cr1,r5,r13				; Is the SA level the active one?
			beq+	vsusecache				; Invalid, just use it...
			beq-	cr1,vsnosave			; The SA level is active, it is already saved...
			
vsgetsave:	mr		r3,r4					; Use the interrupt save as the context savearea if none cached
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F05				; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			mr		r8,r4					; Save this
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r4,r8					; Restore it
			mr		r3,r8					; This too
#endif
#endif	
			
			bl		vsrchsave				; Find a free savearea

			stw		r3,ACT_MACT_VMX(r12)	; Set this as the latest context savearea for the thread
			mfsprg	r6,0					; Get back per_processor block
			stw		r14,SAVprevec(r3)		; And then chain this in front
			oris	r7,r7,hi16(SAVvmxvalid)	; Set the allocated bit
			stw		r12,SAVact(r3)			; Make sure we point to the right guy
			stw		r7,SAVflags(r3)			; Set the allocation flags

vsusecache:	la		r11,savevr0(r3)			; Point to the 1st line in area
			stw		r13,SAVlvlvec(r3)		; Set this context level
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F06				; (TEST/DEBUG)
			mr		r5,r13					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			mr		r10,r3
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			mr		r8,r4					; Save this
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r4,r8					; Restore it
			mr		r3,r10
			mfsprg	r6,0					; Get back per_processor block
#endif
#endif	

vsgotsave:	
			lwz		r10,liveVRS(r6)			; Get the right VRSave register
			lis		r9,0x5555				; Mask with odd bits set		
			rlwinm	r11,r10,1,0,31			; Shift over 1
			ori		r9,r9,0x5555			; Finish mask
			or		r12,r10,r11				; After this, even bits show which lines to zap
			
			stw		r13,SAVlvlvec(r3)		; Set the savearea level
			andc	r13,r12,r9				; Clear out odd bits
			
			la		r20,savevr0(r3)			; Point to line 0
			rlwinm	r24,r13,15,0,15			; Move line 8-15 flags to high order odd bits
			la		r23,savevrvalid(r3)		; Point to the saved register mask field
			or		r24,r13,r24				; Set the odd bits
											; (bit 0 is line 0, bit 1 is line 8,
											; bit 2 is line 1, bit 3 is line 9, etc.
			dcba	br0,r23					; Allocate the cache for it
			rlwimi	r24,r10,16,16,31		; Put vrsave 0 - 15 into positions 16 - 31
			la		r21,savevr2(r3)			; Point to line 1
			mtcrf	255,r24					; Load up the CRs
			stw		r10,savevrvalid(r3)		; Save the validity information
			mr		r22,r20					; Start registers off
;	
;			Save the current vector state
;
						
			bf		0,nol0					; No line 0 to do...
			dcba	br0,r20					; Allocate cache line 0
			
nol0:		
			la		r20,savevr4(r3)			; Point to line 2
			bf		2,nol1					; No line 1 to do...
			dcba	br0,r21					; Allocate cache line 1
			
nol1:		
			la		r21,savevr6(r3)			; Point to line 3
			bf		4,nol2					; No line 2 to do...
			dcba	br0,r20					; Allocate cache line 2
			
nol2:		
			li		r30,16					; Get offset for odd registers
			bf		16,novr0				; Do not save VR0...
			stvxl	v0,br0,r22				; Save VR0
			
novr0:		
			la		r23,savevr2(r3)			; Point to V2/V3 pair
			bf		17,novr1				; Do not save VR1...
			stvxl	v1,r30,r22				; Save VR1
			
novr1:
			la		r20,savevr8(r3)			; Point to line 4
			bf		6,nol3					; No line 3 to do...
			dcba	br0,r21					; Allocate cache line 3
			
nol3:		
			la		r22,savevr4(r3)			; Point to V4/V5 pair
			bf		18,novr2				; Do not save VR2...
			stvxl	v2,br0,r23				; Save VR2
			
novr2:
			bf		19,novr3				; Do not save VR3...
			stvxl	v3,r30,r23				; Save VR3
			
novr3:
;
;			Note: CR4 is now free
;
			la		r21,savevr10(r3)		; Point to line 5
			bf		8,nol4					; No line 4 to do...
			dcba	br0,r20					; Allocate cache line 4
			
nol4:		
			la		r23,savevr6(r3)			; Point to R6/R7 pair
			bf		20,novr4				; Do not save VR4...
			stvxl	v4,br0,r22				; Save VR4
			
novr4:
			bf		21,novr5				; Do not save VR5...
			stvxl	v5,r30,r22				; Save VR5
			
novr5:
			mtcrf	0x08,r10				; Set CRs for registers 16-19
			la		r20,savevr12(r3)		; Point to line 6
			bf		10,nol5					; No line 5 to do...
			dcba	br0,r21					; Allocate cache line 5
			
nol5:		
			la		r22,savevr8(r3)			; Point to V8/V9 pair
			bf		22,novr6				; Do not save VR6...
			stvxl	v6,br0,r23				; Save VR6
			
novr6:
			bf		23,novr7				; Do not save VR7...
			stvxl	v7,r30,r23				; Save VR7
			
novr7:
;
;			Note: CR5 is now free
;
			la		r21,savevr14(r3)		; Point to line 7
			bf		12,nol6					; No line 6 to do...
			dcba	br0,r20					; Allocate cache line 6
			
nol6:		
			la		r23,savevr10(r3)		; Point to V10/V11 pair
			bf		24,novr8				; Do not save VR8...
			stvxl	v8,br0,r22				; Save VR8
			
novr8:
			bf		25,novr9				; Do not save VR9...
			stvxl	v9,r30,r22				; Save VR9
			
novr9:
			mtcrf	0x04,r10				; Set CRs for registers 20-23
			la		r20,savevr16(r3)		; Point to line 8
			bf		14,nol7					; No line 7 to do...
			dcba	br0,r21					; Allocate cache line 7
			
nol7:		
			la		r22,savevr12(r3)		; Point to V12/V13 pair
			bf		26,novr10				; Do not save VR10...
			stvxl	v10,br0,r23				; Save VR10
			
novr10:
			bf		27,novr11				; Do not save VR11...
			stvxl	v11,r30,r23				; Save VR11
			
novr11:

;
;			Note: CR6 is now free
;
			la		r21,savevr18(r3)		; Point to line 9
			bf		1,nol8					; No line 8 to do...
			dcba	br0,r20					; Allocate cache line 8
			
nol8:		
			la		r23,savevr14(r3)		; Point to V14/V15 pair
			bf		28,novr12				; Do not save VR12...
			stvxl	v12,br0,r22				; Save VR12
			
novr12:
			bf		29,novr13				; Do not save VR13...
			stvxl	v13,r30,r22				; Save VR13
			
novr13:
			mtcrf	0x02,r10				; Set CRs for registers 24-27
			la		r20,savevr20(r3)		; Point to line 10
			bf		3,nol9					; No line 9 to do...
			dcba	br0,r21					; Allocate cache line 9
			
nol9:		
			la		r22,savevr16(r3)		; Point to V16/V17 pair
			bf		30,novr14				; Do not save VR14...
			stvxl	v14,br0,r23				; Save VR14
			
novr14:
			bf		31,novr15				; Do not save VR15...
			stvxl	v15,r30,r23				; Save VR15
			
novr15:
;
;			Note: CR7 is now free
;
			la		r21,savevr22(r3)		; Point to line 11
			bf		5,nol10					; No line 10 to do...
			dcba	br0,r20					; Allocate cache line 10
			
nol10:		
			la		r23,savevr18(r3)		; Point to V18/V19 pair
			bf		16,novr16				; Do not save VR16...
			stvxl	v16,br0,r22				; Save VR16
			
novr16:
			bf		17,novr17				; Do not save VR17...
			stvxl	v17,r30,r22				; Save VR17
			
novr17:
			mtcrf	0x01,r10				; Set CRs for registers 28-31
;
;			Note: All registers have been or are accounted for in CRs
;
			la		r20,savevr24(r3)		; Point to line 12
			bf		7,nol11					; No line 11 to do...
			dcba	br0,r21					; Allocate cache line 11
			
nol11:		
			la		r22,savevr20(r3)		; Point to V20/V21 pair
			bf		18,novr18				; Do not save VR18...
			stvxl	v18,br0,r23				; Save VR18
			
novr18:
			bf		19,novr19				; Do not save VR19...
			stvxl	v19,r30,r23				; Save VR19
			
novr19:
			la		r21,savevr26(r3)		; Point to line 13
			bf		9,nol12					; No line 12 to do...
			dcba	br0,r20					; Allocate cache line 12
			
nol12:		
			la		r23,savevr22(r3)		; Point to V22/V23 pair
			bf		20,novr20				; Do not save VR20...
			stvxl	v20,br0,r22				; Save VR20
			
novr20:
			bf		21,novr21				; Do not save VR21...
			stvxl	v21,r30,r22				; Save VR21
			
novr21:
			la		r20,savevr28(r3)		; Point to line 14
			bf		11,nol13				; No line 13 to do...
			dcba	br0,r21					; Allocate cache line 13
			
nol13:		
			la		r22,savevr24(r3)		; Point to V24/V25 pair
			bf		22,novr22				; Do not save VR22...
			stvxl	v22,br0,r23				; Save VR22
			
novr22:
			bf		23,novr23				; Do not save VR23...
			stvxl	v23,r30,r23				; Save VR23
			
novr23:
			la		r21,savevr30(r3)		; Point to line 15
			bf		13,nol14				; No line 14 to do...
			dcba	br0,r20					; Allocate cache line 14
			
nol14:		
			la		r23,savevr26(r3)		; Point to V26/V27 pair
			bf		24,novr24				; Do not save VR24...
			stvxl	v24,br0,r22				; Save VR24
			
novr24:
			bf		25,novr25				; Do not save VR25...
			stvxl	v25,r30,r22				; Save VR25
			
novr25:
			bf		15,nol15				; No line 15 to do...
			dcba	br0,r21					; Allocate cache line 15
			
nol15:		
;
;			Note: All cache lines allocated now
;
			la		r22,savevr28(r3)		; Point to V28/V29 pair
			bf		26,novr26				; Do not save VR26...
			stvxl	v26,br0,r23				; Save VR26
			
novr26:
			bf		27,novr27				; Do not save VR27...
			stvxl	v27,r30,r23				; Save VR27
			
novr27:
			la		r23,savevr30(r3)		; Point to V30/V31 pair
			bf		28,novr28				; Do not save VR28...
			stvxl	v28,br0,r22				; Save VR28
			
novr28:		
			mfvscr	v27						; Get the VSCR
			bf		29,novr29				; Do not save VR29...
			stvxl	v29,r30,r22				; Save VR29
			
novr29:		
			la		r22,savevscr(r3)		; Point to the VSCR save area
			bf		30,novr30				; Do not save VR30...
			stvxl	v30,br0,r23				; Save VR30
			
novr30:
			dcba	br0,r22					; Allocate VSCR savearea
			bf		31,novr31				; Do not save VR31...
			stvxl	v31,r30,r23				; Save VR31
			
novr31:
			stvxl	v27,br0,r22				; Save the VSCR

			

/*
 * 			Now check out the current thread and see if we need to load up his context.
 *			If we do (and this should be the normal case), do it and then release the
 *			savearea.
 *			
 *			If we don't (remember, we already took care of the case where we just enable
 *			the vector), we need to fill the registers with garbage, because this thread has 
 *			never used them before and some thieving bastard could hack the old values
 *			of some thread!  Just imagine what would happen if they could!  Why, nothing
 *			would be safe! My Gosh! It's terrifying!
 */

vsnosave:	lwz		r15,ACT_MACT_PCB(r17)	; Get the current level of the "new" one
			lwz		r14,ACT_MACT_VMX(r17)	; Point to the top of the "new" context stack
			lwz		r13,ACT_MACT_VMXlvl(r17)	; Get the "new" active level

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F07				; (TEST/DEBUG)
			mr		r1,r15					; (TEST/DEBUG)
			mr		r3,r14					; (TEST/DEBUG)
			mr		r5,r13					; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#endif	

			cmplwi	cr1,r14,0				; Do we possibly have some context to load?
			stw		r15,ACT_MACT_VMXlvl(r17)	; Set the "new" active level
			la		r23,savevscr(r14)		; Point to the VSCR
			stw		r18,ACT_MACT_VMXcpu(r17)	; Set the active CPU
			la		r20,savevr0(r14)		; Point to first line to bring in
			stw		r17,PP_VMX_THREAD(r6)	; Store current thread address in vmx_thread to claim vector for thread
			beq-	cr1,ProtectTheAmericanWay	; Nothing to restore, first time use...
			lwz		r0,SAVlvlvec(r14)		; Get the level of first facility savearea
			cmplw	r0,r15					; Top level correct to load?
			bne-	ProtectTheAmericanWay	; No, go initialize...
			
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F08				; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			mr		r8,r3
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			mr		r22,r4					; Save this
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r4,r22					; Restore it
			mr		r3,r8
#endif
#endif	

			li		r0,1					; Get the level invalid indication
			lwz		r22,savevrsave(r4)		; Get the most current VRSAVE
			lwz		r10,savevrvalid(r14)	; Get the valid VRs in the savearea
			lis		r9,0x5555				; Mask with odd bits set
			and		r10,r10,r22				; Figure out just what registers need to be loaded
			ori		r9,r9,0x5555			; Finish mask
			rlwinm	r11,r10,1,0,31			; Shift over 1
			stw		r0,SAVlvlvec(r14)		; Mark the savearea invalid because we are activating again
			or		r12,r10,r11				; After this, even bits show which lines to touch
			dcbt	br0,r23					; Touch in the VSCR
			andc	r13,r12,r9				; Clear out odd bits
			
			la		r20,savevr0(r14)		; Point to line 0
			rlwinm	r3,r13,15,0,15			; Move line 8-15 flags to high order odd bits
			la		r21,savevr2(r3)			; Point to line 1
			or		r3,r13,r3				; Set the odd bits
											; (bit 0 is line 0, bit 1 is line 8,
											; bit 2 is line 1, bit 3 is line 9, etc.
			lvxl	v31,br0,r23				; Get the VSCR
			rlwimi	r3,r10,16,16,31			; Put vrsave 0 - 15 into positions 16 - 31
			mtvscr	v31						; Slam the VSCR value
			mtcrf	255,r3					; Load up the CRs
			mr		r22,r20					; Start registers off
;	
;			Load the new vector state
;
						
			bf		0,lnol0					; No line 0 to do...
			dcbt	br0,r20					; Touch cache line 0
			
lnol0:		
			la		r20,savevr4(r14)		; Point to line 2
			bf		2,lnol1					; No line 1 to do...
			dcbt	br0,r21					; Touch cache line 1
			
lnol1:		
			la		r21,savevr6(r14)		; Point to line 3
			bf		4,lnol2					; No line 2 to do...
			dcbt	br0,r20					; Touch cache line 2
			
lnol2:		
			li		r30,16					; Get offset for odd registers
			bf		16,lnovr0				; Do not restore VR0...
			lvxl	v0,br0,r22				; Restore VR0
			
lnovr0:		
			la		r23,savevr2(r14)		; Point to V2/V3 pair
			bf		17,lnovr1				; Do not restore VR1...
			lvxl	v1,r30,r22				; Restore VR1
			
lnovr1:
			la		r20,savevr8(r14)		; Point to line 4
			bf		6,lnol3					; No line 3 to do...
			dcbt	br0,r21					; Touch cache line 3
			
lnol3:		
			la		r22,savevr4(r14)		; Point to V4/V5 pair
			bf		18,lnovr2				; Do not restore VR2...
			lvxl	v2,br0,r23				; Restore VR2
			
lnovr2:
			bf		19,lnovr3				; Do not restore VR3...
			lvxl	v3,r30,r23				; Restore VR3
			
lnovr3:
;
;			Note: CR4 is now free
;
			la		r21,savevr10(r14)		; Point to line 5
			bf		8,lnol4					; No line 4 to do...
			dcbt	br0,r20					; Touch cache line 4
			
lnol4:		
			la		r23,savevr6(r14)		; Point to R6/R7 pair
			bf		20,lnovr4				; Do not restore VR4...
			lvxl	v4,br0,r22				; Restore VR4
			
lnovr4:
			bf		21,lnovr5				; Do not restore VR5...
			lvxl	v5,r30,r22				; Restore VR5
			
lnovr5:
			mtcrf	0x08,r10				; Set CRs for registers 16-19
			la		r20,savevr12(r14)		; Point to line 6
			bf		10,lnol5				; No line 5 to do...
			dcbt	br0,r21					; Touch cache line 5
			
lnol5:		
			la		r22,savevr8(r14)		; Point to V8/V9 pair
			bf		22,lnovr6				; Do not restore VR6...
			lvxl	v6,br0,r23				; Restore VR6
			
lnovr6:
			bf		23,lnovr7				; Do not restore VR7...
			lvxl	v7,r30,r23				; Restore VR7
			
lnovr7:
;
;			Note: CR5 is now free
;
			la		r21,savevr14(r14)		; Point to line 7
			bf		12,lnol6				; No line 6 to do...
			dcbt	br0,r20					; Touch cache line 6
			
lnol6:		
			la		r23,savevr10(r14)		; Point to V10/V11 pair
			bf		24,lnovr8				; Do not restore VR8...
			lvxl	v8,br0,r22				; Restore VR8
			
lnovr8:
			bf		25,lnovr9				; Do not save VR9...
			lvxl	v9,r30,r22				; Restore VR9
			
lnovr9:
			mtcrf	0x04,r10				; Set CRs for registers 20-23
			la		r20,savevr16(r14)		; Point to line 8
			bf		14,lnol7				; No line 7 to do...
			dcbt	br0,r21					; Touch cache line 7
			
lnol7:		
			la		r22,savevr12(r14)		; Point to V12/V13 pair
			bf		26,lnovr10				; Do not restore VR10...
			lvxl	v10,br0,r23				; Restore VR10
			
lnovr10:
			bf		27,lnovr11				; Do not restore VR11...
			lvxl	v11,r30,r23				; Restore VR11
			
lnovr11:

;
;			Note: CR6 is now free
;
			la		r21,savevr18(r14)		; Point to line 9
			bf		1,lnol8					; No line 8 to do...
			dcbt	br0,r20					; Touch cache line 8
			
lnol8:		
			la		r23,savevr14(r14)		; Point to V14/V15 pair
			bf		28,lnovr12				; Do not restore VR12...
			lvxl	v12,br0,r22				; Restore VR12
			
lnovr12:
			bf		29,lnovr13				; Do not restore VR13...
			lvxl	v13,r30,r22				; Restore VR13
			
lnovr13:
			mtcrf	0x02,r10				; Set CRs for registers 24-27
			la		r20,savevr20(r14)		; Point to line 10
			bf		3,lnol9					; No line 9 to do...
			dcbt	br0,r21					; Touch cache line 9
			
lnol9:		
			la		r22,savevr16(r14)		; Point to V16/V17 pair
			bf		30,lnovr14				; Do not restore VR14...
			lvxl	v14,br0,r23				; Restore VR14
			
lnovr14:
			bf		31,lnovr15				; Do not restore VR15...
			lvxl	v15,r30,r23				; Restore VR15
			
lnovr15:
;
;			Note: CR7 is now free
;
			la		r21,savevr22(r14)		; Point to line 11
			bf		5,lnol10				; No line 10 to do...
			dcbt	br0,r20					; Touch cache line 10
			
lnol10:		
			la		r23,savevr18(r14)		; Point to V18/V19 pair
			bf		16,lnovr16				; Do not restore VR16...
			lvxl	v16,br0,r22				; Restore VR16
			
lnovr16:
			bf		17,lnovr17				; Do not restore VR17...
			lvxl	v17,r30,r22				; Restore VR17
			
lnovr17:
			mtcrf	0x01,r10				; Set CRs for registers 28-31
;
;			Note: All registers have been or are accounted for in CRs
;
			la		r20,savevr24(r14)		; Point to line 12
			bf		7,lnol11				; No line 11 to do...
			dcbt	br0,r21					; Touch cache line 11
			
lnol11:		
			la		r22,savevr20(r14)		; Point to V20/V21 pair
			bf		18,lnovr18				; Do not restore VR18...
			lvxl	v18,br0,r23				; Restore VR18
			
lnovr18:
			bf		19,lnovr19				; Do not restore VR19...
			lvxl	v19,r30,r23				; Restore VR19
			
lnovr19:
			la		r21,savevr26(r14)		; Point to line 13
			bf		9,lnol12				; No line 12 to do...
			dcbt	br0,r20					; Touch cache line 12
			
lnol12:		
			la		r23,savevr22(r14)		; Point to V22/V23 pair
			bf		20,lnovr20				; Do not restore VR20...
			lvxl	v20,br0,r22				; Restore VR20
			
lnovr20:
			bf		21,lnovr21				; Do not restore VR21...
			lvxl	v21,r30,r22				; Restore VR21
			
lnovr21:
			la		r20,savevr28(r14)		; Point to line 14
			bf		11,lnol13				; No line 13 to do...
			dcbt	br0,r21					; Touch cache line 13
			
lnol13:		
			la		r22,savevr24(r14)		; Point to V24/V25 pair
			bf		22,lnovr22				; Do not restore VR22...
			lvxl	v22,br0,r23				; Restore VR22
			
lnovr22:
			bf		23,lnovr23				; Do not restore VR23...
			lvxl	v23,r30,r23				; Restore VR23
			
lnovr23:
			la		r21,savevr30(r14)		; Point to line 15
			bf		13,lnol14				; No line 14 to do...
			dcbt	br0,r20					; Touch cache line 14
			
lnol14:		
			la		r23,savevr26(r14)		; Point to V26/V27 pair
			bf		24,lnovr24				; Do not restore VR24...
			lvxl	v24,br0,r22				; Restore VR24
			
lnovr24:
			bf		25,lnovr25				; Do not restore VR25...
			lvxl	v25,r30,r22				; Restore VR25
			
lnovr25:
			bf		15,lnol15				; No line 15 to do...
			dcbt	br0,r21					; Touch cache line 15
			
lnol15:		
;
;			Note: All needed cache lines have been touched now
;
			la		r22,savevr28(r14)		; Point to V28/V29 pair
			bf		26,lnovr26				; Do not restore VR26...
			lvxl	v26,br0,r23				; Restore VR26
			
lnovr26:
			bf		27,lnovr27				; Do not restore VR27...
			lvxl	v27,r30,r23				; Restore VR27
			
lnovr27:
			la		r23,savevr30(r14)		; Point to V30/V31 pair
			bf		28,lnovr28				; Do not restore VR28...
			lvxl	v28,br0,r22				; Restore VR28
			
lnovr28:		
			bf		29,lnovr29				; Do not restore VR29...
			lvxl	v29,r30,r22				; Restore VR29
			
lnovr29:		
			bf		30,lnovr30				; Do not restore VR30...
			lvxl	v30,br0,r23				; Restore VR30
			
lnovr30:
;
;			Everything is restored now except for VR31.  We need it to get
;			the QNaNBarbarian value to put into idle vector registers
;
			
			lis		r5,hi16(EXT(QNaNbarbarian))	; Get address of empty value
			cmpwi	r10,-1					; Handle the quick case of all registers in use
			ori		r5,r5,lo16(EXT(QNaNbarbarian))	; Get low address of empty value
			beq-	mstlvr31				; Not likely, but all are in use...
			mtcrf	255,r10					; Get mask of valid registers
			lvxl	v31,br0,r5				; Initialize VR31 to the empty value

			bt		0,ni0					; Register is ok already...
			vor		v0,v31,v31				; Copy into the next register
ni0:
			bt		1,ni1					; Register is ok already...
			vor		v1,v31,v31				; Copy into the next register
ni1:
			bt		2,ni2					; Register is ok already...
			vor		v2,v31,v31				; Copy into the next register
ni2:
			bt		3,ni3					; Register is ok already...
			vor		v3,v31,v31				; Copy into the next register
ni3:
			bt		4,ni4					; Register is ok already...
			vor		v4,v31,v31				; Copy into the next register
ni4:
			bt		5,ni5					; Register is ok already...
			vor		v5,v31,v31				; Copy into the next register
ni5:
			bt		6,ni6					; Register is ok already...
			vor		v6,v31,v31				; Copy into the next register
ni6:
			bt		7,ni7					; Register is ok already...
			vor		v7,v31,v31				; Copy into the next register
ni7:
			bt		8,ni8					; Register is ok already...
			vor		v8,v31,v31				; Copy into the next register
ni8:
			bt		9,ni9					; Register is ok already...
			vor		v9,v31,v31				; Copy into the next register
ni9:
			bt		10,ni10					; Register is ok already...
			vor		v10,v31,v31				; Copy into the next register
ni10:
			bt		11,ni11					; Register is ok already...
			vor		v11,v31,v31				; Copy into the next register
ni11:
			bt		12,ni12					; Register is ok already...
			vor		v12,v31,v31				; Copy into the next register
ni12:
			bt		13,ni13					; Register is ok already...
			vor		v13,v31,v31				; Copy into the next register
ni13:
			bt		14,ni14					; Register is ok already...
			vor		v14,v31,v31				; Copy into the next register
ni14:
			bt		15,ni15					; Register is ok already...
			vor		v15,v31,v31				; Copy into the next register
ni15:
			bt		16,ni16					; Register is ok already...
			vor		v16,v31,v31				; Copy into the next register
ni16:
			bt		17,ni17					; Register is ok already...
			vor		v17,v31,v31				; Copy into the next register
ni17:
			bt		18,ni18					; Register is ok already...
			vor		v18,v31,v31				; Copy into the next register
ni18:
			bt		19,ni19					; Register is ok already...
			vor		v19,v31,v31				; Copy into the next register
ni19:
			bt		20,ni20					; Register is ok already...
			vor		v20,v31,v31				; Copy into the next register
ni20:
			bt		21,ni21					; Register is ok already...
			vor		v21,v31,v31				; Copy into the next register
ni21:
			bt		22,ni22					; Register is ok already...
			vor		v22,v31,v31				; Copy into the next register
ni22:
			bt		23,ni23					; Register is ok already...
			vor		v23,v31,v31				; Copy into the next register
ni23:
			bt		24,ni24					; Register is ok already...
			vor		v24,v31,v31				; Copy into the next register
ni24:
			bt		25,ni25					; Register is ok already...
			vor		v25,v31,v31				; Copy into the next register
ni25:
			bt		26,ni26					; Register is ok already...
			vor		v26,v31,v31				; Copy into the next register
ni26:
			bt		27,ni27					; Register is ok already...
			vor		v27,v31,v31				; Copy into the next register
ni27:
			bt		28,ni28					; Register is ok already...
			vor		v28,v31,v31				; Copy into the next register
ni28:
			bt		29,ni29					; Register is ok already...
			vor		v29,v31,v31				; Copy into the next register
ni29:
			bt		30,ni30					; Register is ok already...
			vor		v30,v31,v31				; Copy into the next register
ni30:
			bf		31,lnovr31				; R31 is empty, no need to restore...

mstlvr31:	lvxl	v31,r30,r23				; Restore VR31
			
lnovr31:
			
vrenable:	
			lwz		r9,SAVflags(r4)			/* Get the flags of the current savearea */
			lwz		r8,savesrr1(r4)			; Get the msr of the interrupted guy
			rlwinm	r5,r4,0,0,19			/* Get the page address of the savearea */
			oris	r8,r8,hi16(MASK(MSR_VEC))	; Enable the vector facility
			lwz		r10,ACT_MACT_SPF(r17)	; Get the special flags
			lis		r7,hi16(SAVattach)		/* Get the attached flag */
			lwz		r5,SACvrswap(r5)		/* Get Virtual to Real translation */
			oris	r10,r10,hi16(vectorUsed|vectorCng)	; Set that we used vectors
			mr.		r15,r15					; See if we are doing this for user state
			stw		r8,savesrr1(r4)			; Set the msr of the interrupted guy
			andc	r9,r9,r7				/* Clear the attached bit */
			xor		r3,r4,r5				/* Get the real address of the savearea */
			stw		r9,SAVflags(r4)			/* Set the flags of the current savearea */
			bne-	vrnuser					; We are not user state...
			stw		r10,ACT_MACT_SPF(r17)	; Set the activation copy
			stw		r10,spcFlags(r6)		; Set per_proc copy

vrnuser:
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F0A				; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			mr		r8,r3					; Save this
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r3,r8					; Restore it
#endif
#endif	
			b		EXT(exception_exit)		/* Exit from the fray... */

/*
 *			Initialize the registers to some bogus value
 *			We make sure that non-Java mode is the default here
 */

ProtectTheAmericanWay:
			
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)	; (TEST/DEBUG)
			li		r2,0x5F09				; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)	; (TEST/DEBUG)
			sc								; (TEST/DEBUG)
#if GDDBG
			lis		r3,hi16(EXT(GratefulDeb))	; Point to top of display
			mr		r8,r4					; Save this
			ori		r3,r3,lo16(EXT(GratefulDeb))	; Put in bottom part
			mr		r4,r2					; Set value
			mtlr	r3						; Set link register
			li		r3,1					; Display address
			blrl							; Display it
			mr		r4,r8					; Restore it
#endif
#endif	
			lis		r5,hi16(EXT(QNaNbarbarian))	; Get address of empty value
			vspltish v1,1					; Turn on the non-Java bit and saturate
			ori		r5,r5,lo16(EXT(QNaNbarbarian))	; Get low address of empty value
			vspltisw v2,1					; Turn on the saturate bit
			lvxl	v0,br0,r5				; Initialize VR0
			vxor	v1,v1,v2				; Turn off saturate	
			
			vor		v2,v0,v0				; Copy into the next register
			mtvscr	v1						; Clear the vector status register
			vor		v3,v0,v0				; Copy into the next register
			vor		v1,v0,v0				; Copy into the next register
			vor		v4,v0,v0				; Copy into the next register
			vor		v5,v0,v0				; Copy into the next register
			vor		v6,v0,v0				; Copy into the next register
			vor		v7,v0,v0				; Copy into the next register
			vor		v8,v0,v0				; Copy into the next register
			vor		v9,v0,v0				; Copy into the next register
			vor		v10,v0,v0				; Copy into the next register
			vor		v11,v0,v0				; Copy into the next register
			vor		v12,v0,v0				; Copy into the next register
			vor		v13,v0,v0				; Copy into the next register
			vor		v14,v0,v0				; Copy into the next register
			vor		v15,v0,v0				; Copy into the next register
			vor		v16,v0,v0				; Copy into the next register
			vor		v17,v0,v0				; Copy into the next register
			vor		v18,v0,v0				; Copy into the next register
			vor		v19,v0,v0				; Copy into the next register
			vor		v20,v0,v0				; Copy into the next register
			vor		v21,v0,v0				; Copy into the next register
			vor		v22,v0,v0				; Copy into the next register
			vor		v23,v0,v0				; Copy into the next register
			vor		v24,v0,v0				; Copy into the next register
			vor		v25,v0,v0				; Copy into the next register
			vor		v26,v0,v0				; Copy into the next register
			vor		v27,v0,v0				; Copy into the next register
			vor		v28,v0,v0				; Copy into the next register
			vor		v29,v0,v0				; Copy into the next register
			vor		v30,v0,v0				; Copy into the next register
			vor		v31,v0,v0				; Copy into the next register
			b		vrenable				; Finish setting it all up...				

;
;			Finds a unused vector area in the activation pointed
;			to by R12s saved contexts.  If none are found (unlikely but possible)
;			and R3 is 0, a new area is allocated.  If R3 is non-zero, it contains 
;			a pointer to a vector savearea that is free.
;

vsrchsave:	lwz		r6,ACT_MACT_PCB(r12)		; Get the first "normal" savearea
			
vsrnorm:	mr.		r5,r6						; Is there another?
			beq-	vsrvect						; No, search the floating point saveareas...
			lwz		r7,SAVflags(r5)				; Get the flags for this guy
			lwz		r6,SAVprev(r5)				; Get the previous savearea, just in case
			andis.	r8,r7,hi16(SAVvmxvalid)		; Have we found an empty vector save in normal?
			beq+	vsrgot						; We found one...
			b		vsrnorm						; Search again...

vsrvect:	lwz		r6,ACT_MACT_FPU(r12)		; Get the first "floating point" savearea
			
vsrvectx:	mr.		r5,r6						; Is there another?
			beq-	vsrget						; No, try to allocate one...
			lwz		r7,SAVflags(r5)				; Get the flags for this guy
			lwz		r6,SAVprefp(r5)				; Get the previous savearea, just in case
			andis.	r8,r7,hi16(SAVvmxvalid)		; Have we found an empty vector save in float?
			bne-	vsrvectx					; Search again...
			
vsrgot:		mr		r3,r5						; Get the savearea into the right register
			blr									; Return...

vsrget:		mr.		r5,r3						; Do we allocate or use existing?
			beq+	vsrallo						; Allocate one...
			
			lwz		r7,SAVflags(r3)				; Get the passed in area flags
			blr									; Return...
;			
;			NOTE: save_get will return directly and set R7 to 0...
;
vsrallo:	b		EXT(save_get)				; Get a fresh savearea 


/*
 * void lfs(fpsp,fpdp)
 *
 * load the single precision float to the double
 *
 * This routine is used by the alignment handler.
 *
 */
ENTRY(lfs, TAG_NO_FRAME_USED)
        lfs     f1,	0(r3)
	stfd	f1,	0(r4)
	blr

/*
 * fpsp stfs(fpdp,fpsp)
 *
 * store the double precision float to the single
 *
 * This routine is used by the alignment handler.
 *
 */
ENTRY(stfs, TAG_NO_FRAME_USED)
	lfd	f1,	0(r3)
        stfs	f1,	0(r4)
	blr

