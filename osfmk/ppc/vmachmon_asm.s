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
#include <assym.s>
#include <debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>

/*
 *	This file contains implementations for the Virtual Machine Monitor
 *	facility.
 */


/*
 *	int vmm_dispatch(savearea, act);
 
 *	vmm_dispatch is a PPC only system call.  It is used with a selector (first
 *	parameter) to determine what function to enter.  This is treated as an extension
 *	of hw_exceptions.
 *
 *	Inputs: 
 *		R4  = current activation
 *		R16 = current thread
 *		R30 = current savearea
 */
 
 			.align	5								/* Line up on cache line */
			.globl	EXT(vmm_dispatch_table)

LEXT(vmm_dispatch_table)

			/* Don't change the order of these routines in the table. It's  */
			/* OK to add new routines, but they must be added at the bottom. */

			.long	EXT(vmm_get_version_sel)						; Get the version of the VMM interface
			.long	EXT(vmm_get_features_sel)						; Get the features of the VMM interface
			.long	EXT(vmm_init_context_sel)						; Initializes a new VMM context
			.long	EXT(vmm_tear_down_context)						; Tears down a previously-allocated VMM context
			.long	EXT(vmm_tear_down_all)							; Tears down all VMMs 
			.long	EXT(vmm_map_page)								; Maps a page from the main address space into the VM space 
			.long	EXT(vmm_get_page_mapping)						; Returns client va associated with VM va
			.long	EXT(vmm_unmap_page)								; Unmaps a page from the VM space
			.long	EXT(vmm_unmap_all_pages)						; Unmaps all pages from the VM space 
			.long	EXT(vmm_get_page_dirty_flag)					; Gets the change bit for a page and optionally clears it
			.long	EXT(vmm_get_float_state)						; Gets current floating point state
			.long	EXT(vmm_get_vector_state)						; Gets current vector state
			.long	EXT(vmm_set_timer)								; Sets a timer value
			.long	EXT(vmm_get_timer)								; Gets a timer value
			.long	EXT(switchIntoVM)								; Switches to the VM context
			.long	EXT(vmm_protect_page)							; Sets protection values for a page
			.long	EXT(vmm_map_execute)							; Maps a page an launches VM
			.long	EXT(vmm_protect_execute)						; Sets protection values for a page and launches VM

			.set	vmm_count,(.-EXT(vmm_dispatch_table))/4			; Get the top number


			.align	5
			.globl	EXT(vmm_dispatch)

LEXT(vmm_dispatch)

			lwz		r11,saver3(r30)				; Get the selector
			mr		r3,r4						; All of our functions want the activation as the first parm
			lis		r10,hi16(EXT(vmm_dispatch_table))	; Get top half of table
			cmplwi	r11,kVmmExecuteVM			; Should we switch to the VM now?
			cmplwi	cr1,r11,vmm_count			; See if we have a valid selector
			ori		r10,r10,lo16(EXT(vmm_dispatch_table))	; Get low half of table
			lwz		r4,saver4(r30)				; Get 1st parameter after selector
			beq+	EXT(switchIntoVM)			; Yes, go switch to it....
			rlwinm	r11,r11,2,0,29				; Index into table
			bgt-	cr1,vmmBogus				; It is a bogus entry
			lwzx	r10,r10,r11					; Get address of routine
			lwz		r5,saver5(r30)				; Get 2nd parameter after selector
			lwz		r6,saver6(r30)				; Get 3rd parameter after selector
			mtlr	r10							; Set the routine address
			lwz		r7,saver7(r30)				; Get 4th parameter after selector
;
;			NOTE: currently the most paramters for any call is 4.  We will support at most 8 because we
;			do not want to get into any stack based parms.  However, here is where we need to add
;			code for the 5th - 8th parms if we need them.
;			

			blrl								; Call function
			
			stw		r3,saver3(r30)				; Pass back the return code
			li		r3,1						; Set normal return with check for AST
			b		EXT(ppcscret)				; Go back to handler...
			
vmmBogus:	li		r3,0						; Bogus selector, treat like a bogus system call
			b		EXT(ppcscret)				; Go back to handler...


			.align	5
			.globl	EXT(vmm_get_version_sel)

LEXT(vmm_get_version_sel)						; Selector based version of get version

			lis		r3,hi16(EXT(vmm_get_version))
			ori		r3,r3,lo16(EXT(vmm_get_version))
			b		selcomm


			.align	5
			.globl	EXT(vmm_get_features_sel)

LEXT(vmm_get_features_sel)						; Selector based version of get features

			lis		r3,hi16(EXT(vmm_get_features))
			ori		r3,r3,lo16(EXT(vmm_get_features))
			b		selcomm


			.align	5
			.globl	EXT(vmm_init_context_sel)

LEXT(vmm_init_context_sel)						; Selector based version of init context

			lwz		r4,saver4(r30)				; Get the passed in version
			lwz		r5,saver5(r30)				; Get the passed in comm area
			lis		r3,hi16(EXT(vmm_init_context))
			stw		r4,saver3(r30)				; Cheat and move this parameter over
			ori		r3,r3,lo16(EXT(vmm_init_context))
			stw		r5,saver4(r30)				; Cheat and move this parameter over

selcomm:	mtlr	r3							; Set the real routine address
			mr		r3,r30						; Pass in the savearea
			blrl								; Call the function
			b		EXT(ppcscret)				; Go back to handler...

/*
 *			Here is where we transition to the virtual machine.
 *
 *			We will swap the register context in the savearea with that which is saved in our shared
 *			context area.  We will validity check a bit and clear any nasty bits in the MSR and force 
 *			the manditory ones on.
 *
 *			Then we will setup the new address space to run with, and anything else that is normally part
 *			of a context switch.
 *
 *			The vmm_execute_vm entry point is for the fused vmm_map_execute and vmm_protect_execute
 *			calls.  This is called, but never returned from.  We always go directly back to the
 *			user from here.
 *
 *			Still need to figure out final floats and vectors. For now, we will go brute
 *			force and when we go into the VM, we will force save any normal floats and 
 *			vectors. Then we will hide them and swap the VM copy (if any) into the normal
 *			chain.  When we exit VM we will do the opposite.  This is not as fast as I would
 *			like it to be.
 *
 *
 */
 
 
 			.align	5
 			.globl	EXT(vmm_execute_vm)

LEXT(vmm_execute_vm)

 			lwz		r30,ACT_MACT_PCB(r3)		; Restore the savearea pointer because it could be trash here
 			b		EXT(switchIntoVM)			; Join common...
 
 
 			.align	5
 			.globl	EXT(switchIntoVM)

LEXT(switchIntoVM)

			lwz		r5,vmmControl(r3)			; Pick up the control table address
			subi	r4,r4,1						; Switch to zero offset
			rlwinm.	r2,r5,0,0,30				; Is there a context there? (Note: we will ignore bit 31 so that we 
												;   do not try this while we are transitioning off to on
			cmplwi	cr1,r4,kVmmMaxContextsPerThread	; Is the index valid?
			beq-	vmmBogus					; Not started, treat like a bogus system call
			mulli	r2,r4,vmmCEntrySize			; Get displacement from index
			bgt-	cr1,swvmmBogus				; Index is bogus...
			add		r2,r2,r5					; Point to the entry
			
			lwz		r4,vmmFlags(r2)				; Get the flags for the selected entry
			lwz		r5,vmmContextKern(r2)		; Get the context area address
			rlwinm.	r26,r4,0,vmmInUseb,vmmInUseb	; See if the slot is in use
			bne+	swvmChkIntcpt				; We are so cool. Go do check for immediate intercepts...
			
swvmmBogus:	li		r2,kVmmBogusContext			; Set bogus index return
			li		r3,1						; Set normal return with check for AST	
			stw		r2,saver3(r30)				; Pass back the return code
			b		EXT(ppcscret)				; Go back to handler...

;
;			Here we check for any immediate intercepts.  So far, the only
;			two of these are a timer pop and and external stop.  We will not dispatch if
;			either is true.  They need to either reset the timer (i.e. set timer
;			to 0) or to set a future time, or if it is external stop, set the vmmXStopRst flag.
;

swvmChkIntcpt:
			lwz		r6,vmmCntrl(r5)				; Get the control field
			rlwinm.	r7,r6,0,vmmXStartb,vmmXStartb	; Clear all but start bit
			beq+	swvmChkStop					; Do not reset stop
			andc	r6,r6,r7					; Clear it
			li		r8,vmmFlags					; Point to the flags
			stw		r6,vmmCntrl(r5)				; Set the control field

swvmtryx:	lwarx	r4,r8,r2					; Pick up the flags
			rlwinm	r4,r4,0,vmmXStopb+1,vmmXStopb-1	; Clear the stop bit
			stwcx.	r4,r8,r2					; Save the updated field
			bne-	swvmtryx					; Try again...

swvmChkStop:			
			rlwinm.	r26,r4,0,vmmXStopb,vmmXStopb	; Is this VM stopped?
			beq+	swvmNoStop					; Nope...
				
			li		r2,kVmmStopped				; Set stopped return
			li		r3,1						; Set normal return with check for AST
			stw		r2,saver3(r30)				; Pass back the return code
			stw		r2,return_code(r5)			; Save the exit code
			b		EXT(ppcscret)				; Go back to handler...
			
swvmNoStop:			
			rlwinm.	r26,r4,0,vmmTimerPopb,vmmTimerPopb	; Did the timer pop?
			beq+	swvmDoSwitch				; No...
		
			li		r2,kVmmReturnNull			; Set null return
			li		r3,1						; Set normal return with check for AST
			stw		r2,saver3(r30)				; Pass back the return code
			stw		r2,return_code(r5)			; Save the exit code
			b		EXT(ppcscret)				; Go back to handler...

;
;			Here is where we actually swap into the VM (alternate) context.
;			We will bulk do a wholesale swap of the registers in the context area (the VMs)
;			with the ones in the savearea (our main code).  During the copy, we will fix up the
;			MSR, forcing on a few bits and turning off a few others.  Then we will deal with the 
;			PMAP and other per_proc stuff.  Finally, we will exit back through the main exception
;			handler to deal with unstacking saveareas and ASTs, etc.
;

swvmDoSwitch:

;			
;			First, we save the volatile registers we care about.  Remember, all register
;			handling here is pretty funky anyway, so we just pick the ones that are ok.
;			
			mr		r26,r3						; Save the activation pointer
			mr		r28,r5						; Save the context pointer
			mr		r27,r2						; Save the context entry
			
			bl		vmmxcng						; Exchange the vector and floating point contexts
			mr		r5,r28						; Restore this register

			lwz		r11,ACT_MACT_SPF(r26)		; Get the special flags
			lwz		r3,vmmPmap(r27)				; Get the pointer to the PMAP
			oris	r15,r11,hi16(runningVM)	; 	; Show that we are swapped to the VM right now
			bl		EXT(hw_set_user_space_dis)	; Swap the address spaces
			lwz		r17,vmmFlags(r27)			; Get the status flags
			mfsprg	r10,0						; Get the per_proc
			rlwinm.	r0,r17,0,vmmMapDoneb,vmmMapDoneb	; Did we just do a map function?
			stw		r27,vmmCEntry(r26)			; Remember what context we are running
			andc	r17,r17,r0					; Turn off map flag
			beq+	swvmNoMap					; No mapping done...

;
;			This little bit of hoopala here (triggered by vmmMapDone) is
;			a performance enhancement.  This will change the returning savearea
;			to look like we had a DSI rather than a system call. Then, setting
;			the redrive bit, the exception handler will redrive the exception as 
;			a DSI, entering the last mapped address into the hash table.  This keeps
;			double faults from happening.  Note that there is only a gain if the VM
;			takes a fault, then the emulator resolves it only, and then begins
;			the VM execution again.  It seems like this should be the normal case.
;
			
			lwz		r3,SAVflags(r30)			; Pick up the savearea flags
			lwz		r2,vmmLastMap(r27)			; Get the last mapped address
			li		r20,T_DATA_ACCESS			; Change to DSI fault
			oris	r3,r3,hi16(SAVredrive)		; Set exception redrive
			stw		r2,savedar(r30)				; Set the DAR to the last thing we mapped
			stw		r3,SAVflags(r30)			; Turn on the redrive request
			lis		r2,hi16(MASK(DSISR_HASH))	; Set PTE/DBAT miss
			stw		r20,saveexception(r30)		; Say we need to emulate a DSI
			stw		r2,savedsisr(r30)			; Pretend we have a PTE miss			
			
swvmNoMap:	lwz		r20,vmmContextKern(r27)		; Get the comm area
			rlwimi	r15,r17,32-(floatCngbit-vmmFloatCngdb),floatCngbit,vectorCngbit	; Shift and insert changed bits			
			lwz		r20,vmmCntrl(r20)			; Get the control flags
			rlwimi	r17,r11,8,24,31				; Save the old spf flags
			rlwimi	r15,r20,32+vmmKeyb-userProtKeybit,userProtKeybit,userProtKeybit	; Set the protection key
			stw		r15,spcFlags(r10)			; Set per_proc copy of the special flags
			stw		r15,ACT_MACT_SPF(r26)		; Get the special flags

			stw		r17,vmmFlags(r27)			; Set the status flags
			
			bl		swapCtxt					; First, swap the general register state

			lwz		r17,vmmContextKern(r27)		; Get the comm area back
			
			lwz		r15,vmmCntrl(r17)			; Get the control flags again
			
			rlwinm.	r0,r15,0,vmmFloatLoadb,vmmFloatLoadb	; Are there new floating point values?
			li		r14,vmmppcFPRs				; Get displacement to the new values
			andc	r15,r15,r0					; Clear the bit
			beq+	swvmNoNewFloats				; Nope, good...
			
			lwz		r3,ACT_MACT_FPU(r26)		; Get the FPU savearea
			dcbt	r14,r18						; Touch in first line of new stuff
			mr.		r3,r3						; Is there one?
			bne+	swvmGotFloat				; Yes...
			
			bl		EXT(save_get)				; Get a savearea

			li		r11,0						; Get a 0
			lis		r7,hi16(SAVfpuvalid)		; Set the allocated bit			
			stw		r3,ACT_MACT_FPU(r26)		; Set the floating point savearea
			stw		r7,SAVflags(r3)				; Set the validity flags
			stw		r11,SAVlvlfp(r3)			; Set the context level

swvmGotFloat:
			dcbt	r14,r17						; Touch in first line of new stuff
			la		r4,savefp0(r3)				; Point to the destination
			mr		r21,r3						; Save the save area
			la		r3,vmmppcFPRs(r17)			; Point to the source
			li		r5,33*8						; Get the size (32 FP + FPSCR at 8 bytes each)
			
			bl		EXT(bcopy)					; Copy the new values

			lwz		r11,ACT_MACT_SPF(r26)		; Get the special flags
			stw		r15,vmmCntrl(r17)			; Save the control flags sans vmmFloatLoad
			rlwinm	r11,r11,0,floatCngbit+1,floatCngbit-1	; Clear the changed bit here
			lwz		r14,vmmStat(r17)			; Get the status flags
			mfsprg	r10,0						; Get the per_proc
			stw		r11,ACT_MACT_SPF(r26)		; Get the special flags
			rlwinm	r14,r14,0,vmmFloatCngdb+1,vmmFloatCngdb-1	; Clear the changed flag
			stw		r11,spcFlags(r10)			; Set per_proc copy of the special flags
			stw		r14,vmmStat(r17)			; Set the status flags sans vmmFloatCngd
			lwz		r11,savefpscrpad(r21)		; Get the new fpscr pad
			lwz		r14,savefpscr(r21)			; Get the new fpscr
			stw		r11,savexfpscrpad(r30)		; Save the new fpscr pad
			stw		r14,savexfpscr(r30)			; Save the new fpscr
			
swvmNoNewFloats:
			rlwinm.	r0,r15,0,vmmVectLoadb,vmmVectLoadb	; Are there new vector values?
			li		r14,vmmppcVRs				; Get displacement to the new values
			andc	r15,r15,r0					; Clear the bit
			beq+	swvmNoNewVects				; Nope, good...
			
			lwz		r3,ACT_MACT_VMX(r26)		; Get the vector savearea
			dcbt	r14,r27						; Touch in first line of new stuff
			mr.		r3,r3						; Is there one?
			bne+	swvmGotVect					; Yes...
			
			bl		EXT(save_get)				; Get a savearea

			li		r21,0						; Get a 0
			lis		r7,hi16(SAVvmxvalid)		; Set the allocated bit			
			stw		r3,ACT_MACT_VMX(r26)		; Set the vector savearea indication
			stw		r7,SAVflags(r3)				; Set the validity flags
			stw		r21,SAVlvlvec(r3)			; Set the context level

swvmGotVect:
			dcbt	r14,r17						; Touch in first line of new stuff
			mr		r21,r3						; Save the pointer to the savearea
			la		r4,savevr0(r3)				; Point to the destination
			la		r3,vmmppcVRs(r17)			; Point to the source
			li		r5,33*16					; Get the size (32 vectors + VSCR at 16 bytes each)
			
			bl		EXT(bcopy)					; Copy the new values

			lwz		r11,ACT_MACT_SPF(r26)		; Get the special flags
			stw		r15,vmmCntrl(r17)			; Save the control flags sans vmmVectLoad
			rlwinm	r11,r11,0,vectorCngbit+1,vectorCngbit-1	; Clear the changed bit here
			lwz		r14,vmmStat(r17)			; Get the status flags
			mfsprg	r10,0						; Get the per_proc
			stw		r11,ACT_MACT_SPF(r26)		; Get the special flags
			rlwinm	r14,r14,0,vmmVectCngdb+1,vmmVectCngdb-1	; Clear the changed flag
			eqv		r15,r15,r15					; Get all foxes
			stw		r11,spcFlags(r10)			; Set per_proc copy of the special flags
			stw		r14,vmmStat(r17)			; Set the status flags sans vmmVectCngd
			stw		r15,savevrvalid(r21)		; Set the valid bits to all foxes
			
swvmNoNewVects:			
			li		r3,1						; Show normal exit with check for AST
			mr		r9,r26						; Move the activation pointer
			b		EXT(ppcscret)				; Go back to handler...


;
;			Here is where we exchange the emulator floating and vector contexts
;			for the virtual machines.  Remember, this is not so efficient and needs
;			a rewrite.  Also remember the funky register conventions (i.e.,
;			we need to know what our callers need saved and what our callees trash.
;
;			Note: we expect R26 to contain the activation and R27 to contain the context
;			entry pointer.
;

vmmxcng:	mflr	r21							; Save the return point
			mr		r3,r26						; Pass in the activation
			bl		EXT(fpu_save)				; Save any floating point context
			mr		r3,r26						; Pass in the activation
			bl		EXT(vec_save)				; Save any vector point context

			lis		r10,hi16(EXT(per_proc_info))	; Get top of first per_proc
			li		r8,PP_FPU_THREAD			; Index to FPU owner
			ori		r10,r10,lo16(EXT(per_proc_info))	; Get bottom of first per_proc
			lis		r6,hi16(EXT(real_ncpus))	; Get number of CPUs
			li		r7,0						; Get set to clear
			ori		r6,r6,lo16(EXT(real_ncpus))	; Get number of CPUs
			li		r9,PP_VMX_THREAD			; Index to vector owner
			lwz		r6,0(r6)					; Get the actual CPU count

vmmrt1:		lwarx	r3,r8,r10					; Get FPU owner
			cmplw	r3,r26						; Do we own it?
			bne		vmmrt2						; Nope...
			stwcx.	r7,r8,r10					; Clear it
			bne-	vmmrt1						; Someone else diddled, try again....

vmmrt2:		lwarx	r3,r9,r10					; Get vector owner
			cmplw	r3,r26						; Do we own it?
			bne		vmmxnvec					; Nope...
			stwcx.	r7,r9,r10					; Clear it
			bne-	vmmrt2						; Someone else diddled, try again....

vmmxnvec:	addic.	r6,r6,-1					; Done with all CPUs?
			addi	r10,r10,ppSize				; On to the next
			bgt		vmmrt1						; Do all processors...
			
;
;			At this point, the FP and Vector states for the current activation
;			are saved and not live on any processor.  Also, they should be the
;			only contexts on the activation. Note that because we are currently
;			taking the cowardly way out and insuring that no contexts are live,
;			we do not need to worry about the CPU fields.
;		
			
			lwz		r8,ACT_MACT_FPU(r26)		; Get the FPU savearea
			lwz		r9,ACT_MACT_VMX(r26)		; Get the vector savearea
			lwz		r10,vmmFPU_pcb(r27)			; Get the FPU savearea
			lwz		r11,vmmVMX_pcb(r27)			; Get the vector savearea
			li		r7,0						; Clear this
			mtlr	r21							; Restore the return
			stw		r10,ACT_MACT_FPU(r26)		; Set the FPU savearea
			stw		r11,ACT_MACT_VMX(r26)		; Set the vector savearea
			stw		r8,vmmFPU_pcb(r27)			; Set the FPU savearea
			stw		r9,vmmVMX_pcb(r27)			; Set the vector savearea
			stw		r7,ACT_MACT_FPUlvl(r26)		; Make sure the level is clear
			stw		r7,ACT_MACT_VMXlvl(r26)		; Make sure the level is clear

			mr.		r8,r8						; Do we have any old floating point context?
			lwz		r7,savexfpscrpad(r30)		; Get first part of latest fpscr
			lwz		r9,savexfpscr(r30)			; Get second part of the latest fpscr
			beq-	xcngnold					; Nope...
			stw		r7,savefpscrpad(r8)			; Set first part of fpscr
			stw		r9,savefpscr(r8)			; Set fpscr

xcngnold:	mr.		r10,r10						; Any new context?
			li		r7,0						; Assume no FP
			li		r9,0						; Assume no FP
			beq-	xcngnnew					; Nope...
			lwz		r7,savefpscrpad(r10)		; Get first part of latest fpscr
			lwz		r9,savefpscr(r10)			; Get second part of the latest fpscr
			
xcngnnew:	stw		r7,savexfpscrpad(r30)		; Set the fpsc
			stw		r9,savexfpscr(r30)			; Set the fpscr	
			blr									; Return...

;
;			Here is where we exit from vmm mode.  We do this on any kind of exception.
;			Interruptions (decrementer, external, etc.) are another story though.  
;			These we just pass through. We also switch back explicity when requested.
;			This will happen in response to a timer pop and some kinds of ASTs.
;
;			Inputs:
;				R3  = activation
;				R4  = savearea
;

			.align	5
			.globl	EXT(vmm_exit)

LEXT(vmm_exit)

			lwz		r2,vmmCEntry(r3)			; Get the context that is active
			lwz		r12,ACT_VMMAP(r3)			; Get the VM_MAP for this guy
			lwz		r11,ACT_MACT_SPF(r3)		; Get the special flags
			lwz		r19,vmmFlags(r2)			; Get the status flags
			mr		r16,r3						; R16 is safe to use for the activation address
		
			rlwimi	r19,r11,floatCngbit-vmmFloatCngdb,vmmFloatCngdb,vmmVectCngdb	; Shift and insert changed bits			
			li		r0,0						; Get a zero
			rlwimi	r11,r19,vmmSpfSaveb,floatCngbit,vectorCngbit	; Restore the saved part of the spf
			lwz		r3,VMMAP_PMAP(r12)			; Get the pmap for the activation
			rlwinm	r11,r11,0,runningVMbit+1,runningVMbit-1	; Clear the "in VM" flag
			stw		r0,vmmCEntry(r16)			; Clear pointer to active context
			stw		r19,vmmFlags(r2)			; Set the status flags
			rlwinm	r11,r11,0,userProtKeybit+1,userProtKeybit-1	; Set back to normal protection key
			mfsprg	r10,0						; Get the per_proc block
			stw		r11,ACT_MACT_SPF(r16)		; Get the special flags
			stw		r11,spcFlags(r10)			; Set per_proc copy of the special flags
			
			mr		r26,r16						; Save the activation pointer
			mr		r27,r2						; Save the context entry
			
			bl		EXT(hw_set_user_space_dis)	; Swap the address spaces back to the emulator
			
			bl		vmmxcng						; Exchange the vector and floating point contexts
			
			mr		r2,r27						; Restore
			lwz		r5,vmmContextKern(r2)		; Get the context area address
			mr		r3,r16						; Restore activation address
			stw		r19,vmmStat(r5)				; Save the changed and popped flags
			bl		swapCtxt					; Exchange the VM context for the emulator one
			stw		r8,saver3(r30)				; Set the return code as the return value also
			b		EXT(retFromVM)				; Go back to handler...


;
;			Here is where we force exit from vmm mode.  We do this when as
;			part of termination and is used to insure that we are not executing
;			in an alternate context.  Because this is called from C we need to save 
;			all non-volatile registers.
;
;			Inputs:
;				R3  = activation
;				R4  = user savearea
;				Interruptions disabled
;

			.align	5
			.globl	EXT(vmm_force_exit)

LEXT(vmm_force_exit)

			stwu	r1,-(FM_ALIGN(20*4)+FM_SIZE)(r1)	; Get enough space for the registers
			mflr	r0							; Save the return
			stmw	r13,FM_ARG0(r1)				; Save all non-volatile registers
			stw		r0,(FM_ALIGN(20*4)+FM_SIZE+FM_LR_SAVE)(r1)	; Save the return

			lwz		r2,vmmCEntry(r3)			; Get the context that is active
			lwz		r11,ACT_MACT_SPF(r3)		; Get the special flags
			lwz		r19,vmmFlags(r2)			; Get the status flags
			lwz		r12,ACT_VMMAP(r3)			; Get the VM_MAP for this guy
			
			rlwimi	r19,r11,floatCngbit-vmmFloatCngdb,vmmFloatCngdb,vmmVectCngdb	; Shift and insert changed bits			
			mr		r26,r3						; Save the activation pointer
			rlwimi	r11,r19,vmmSpfSaveb,floatCngbit,vectorCngbit	; Restore the saved part of the spf
			li		r0,0						; Get a zero
			rlwinm	r9,r11,0,runningVMbit+1,runningVMbit-1	; Clear the "in VM" flag
			cmplw	r9,r11						; Check if we were in a vm
			lwz		r3,VMMAP_PMAP(r12)			; Get the pmap for the activation
			beq-	vfeNotRun					; We were not in a vm....
			rlwinm	r9,r9,0,userProtKeybit+1,userProtKeybit-1	; Set back to normal protection key
			stw		r0,vmmCEntry(r26)			; Clear pointer to active context
			mfsprg	r10,0						; Get the per_proc block
			stw		r9,ACT_MACT_SPF(r26)		; Get the special flags
			stw		r9,spcFlags(r10)			; Set per_proc copy of the special flags
			
			mr		r27,r2						; Save the context entry
			mr		r30,r4						; Save the savearea
			
			bl		EXT(hw_set_user_space_dis)	; Swap the address spaces back to the emulator
			
			bl		vmmxcng						; Exchange the vector and floating point contexts
			
			lwz		r5,vmmContextKern(r27)		; Get the context area address
			stw		r19,vmmStat(r5)				; Save the changed and popped flags
			bl		swapCtxt					; Exchange the VM context for the emulator one
			
			lwz		r8,saveexception(r30)		; Pick up the exception code
			rlwinm	r8,r8,30,24,31				; Convert exception to return code
			stw		r8,saver3(r30)				; Set the return code as the return value also
			

vfeNotRun:	lmw		r13,FM_ARG0(r1)				; Restore all non-volatile registers
			lwz		r1,0(r1)					; Pop the stack
			lwz		r0,FM_LR_SAVE(r1)			; Get the return address
			mtlr	r0							; Set return
			blr				

;
;			Note: we will not do any DCBTs to the savearea.  It was just stored to a few cycles ago and should 
;			still be in the cache. Note also that the context area registers map identically to the savearea.
;
;			NOTE: we do not save any of the non-volatile registers through this swap code
;			NOTE NOTE:  R16 is important to save!!!!
;			NOTE: I am too dumb to figure out a faster way to swap 5 lines of memory.  So I go for
;			      the simple way

			.align	5

swapCtxt:	addi	r6,r5,vmm_proc_state		; Point to the state
			li		r25,32						; Get a cache size increment
			addi	r4,r30,savesrr0				; Point to the start of the savearea	
			dcbt	0,r6						; Touch in the first line of the context area
			
			lwz		r14,saveexception(r30)		; Get the exception code
			lwz		r7,savesrr0(r4)				; First line of savearea	
			lwz		r8,savesrr1(r4)				
			lwz		r9,saver0(r4)				
			cmplwi	cr1,r14,T_SYSTEM_CALL		; Are we switching because of a system call?
			lwz		r10,saver1(r4)				
			lwz		r11,saver2(r4)				
			lwz		r12,saver3(r4)				
			lwz		r13,saver4(r4)				
			lwz		r14,saver5(r4)				
			
			dcbt	r25,r6						; Touch second line of context area
			addi	r25,r25,32					; Bump
			
			lwz		r15,savesrr0(r6)			; First line of context	
			lis		r22,hi16(MSR_IMPORT_BITS)	; Get the MSR bits that are controllable by user
			lwz		r23,savesrr1(r6)				
			ori		r22,r25,lo16(MSR_IMPORT_BITS)	; Get the rest of the MSR bits that are controllable by user
			lwz		r17,saver0(r6)				
			lwz		r18,saver1(r6)		
			and		r23,r23,r22					; Keep only the controllable bits		
			lwz		r19,saver2(r6)		
			oris	r23,r23,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			lwz		r20,saver3(r6)				
			ori		r23,r23,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			lwz		r21,saver4(r6)				
			lwz		r22,saver5(r6)				

			dcbt	r25,r6						; Touch third line of context area
			addi	r25,r25,32					; Bump (r25 is 64 now)
		
			stw		r7,savesrr0(r6)				; Save emulator context into the context area	
			stw		r8,savesrr1(r6)				
			stw		r9,saver0(r6)				
			stw		r10,saver1(r6)				
			stw		r11,saver2(r6)				
			stw		r12,saver3(r6)				
			stw		r13,saver4(r6)				
			stw		r14,saver5(r6)			

;			
;			Save the first 3 parameters if we are an SC (we will take care of the last later)
;
			bne+	cr1,swapnotsc				; Skip next if not an SC exception...	
			stw		r12,return_params+0(r5)		; Save the first return
			stw		r13,return_params+4(r5)		; Save the second return
			stw		r14,return_params+8(r5)		; Save the third return

swapnotsc:	stw		r15,savesrr0(r4)			; Save vm context into the savearea	
			stw		r23,savesrr1(r4)				
			stw		r17,saver0(r4)				
			stw		r18,saver1(r4)		
			stw		r19,saver2(r4)		
			stw		r20,saver3(r4)				
			stw		r21,saver4(r4)				
			stw		r22,saver5(r4)				
			
;
;			The first hunk is swapped, do the rest in a loop
;
			li		r23,4						; Four more hunks to swap
					

swaploop:	addi	r4,r4,32					; Bump savearea pointer
			addi	r6,r6,32					; Bump context area pointer
			addic.	r23,r23,-1					; Count down
			dcbt	r25,r6						; Touch 4th, 5th, and 6th and 7th which are extra
			
			lwz		r7,0(r4)					; Read savearea	
			lwz		r8,4(r4)				
			lwz		r9,8(r4)				
			lwz		r10,12(r4)				
			lwz		r11,16(r4)				
			lwz		r12,20(r4)				
			lwz		r13,24(r4)				
			lwz		r14,28(r4)				

			lwz		r15,0(r6)					; Read vm context 
			lwz		r24,4(r6)				
			lwz		r17,8(r6)				
			lwz		r18,12(r6)		
			lwz		r19,16(r6)		
			lwz		r20,20(r6)				
			lwz		r21,24(r6)				
			lwz		r22,28(r6)				

			stw		r7,0(r6)					; Write context	
			stw		r8,4(r6)				
			stw		r9,8(r6)				
			stw		r10,12(r6)				
			stw		r11,16(r6)				
			stw		r12,20(r6)				
			stw		r13,24(r6)				
			stw		r14,28(r6)				

			stw		r15,0(r4)					; Write vm context 
			stw		r24,4(r4)				
			stw		r17,8(r4)				
			stw		r18,12(r4)		
			stw		r19,16(r4)		
			stw		r20,20(r4)				
			stw		r21,24(r4)				
			stw		r22,28(r4)				

			bgt+	swaploop					; Do it all...
			
;
;			Cobble up the exception return code and save any specific return values
;
			
			lwz		r7,saveexception(r30)		; Pick up the exception code
			rlwinm	r8,r7,30,24,31				; Convert exception to return code
			cmplwi	r7,T_DATA_ACCESS			; Was this a DSI?
			stw		r8,return_code(r5)			; Save the exit code
			cmplwi	cr1,r7,T_INSTRUCTION_ACCESS	; Exiting because of an ISI?
			beq+	swapDSI						; Yeah...
			cmplwi	r7,T_ALIGNMENT				; Alignment exception?
			beq+	cr1,swapISI					; We had an ISI...
			cmplwi	cr1,r7,T_SYSTEM_CALL		; Exiting because of an system call?
			beq+	swapDSI						; An alignment exception looks like a DSI...
			beq+	cr1,swapSC					; We had a system call...
			
			blr									; Return...

;
;			Set exit returns for a DSI or alignment exception
;

swapDSI:	lwz		r10,savedar(r30)			; Get the DAR
			lwz		r7,savedsisr(r30)			; and the DSISR
			stw		r10,return_params+0(r5)		; Save DAR as first return parm
			stw		r7,return_params+4(r5)		; Save DSISR as second return parm
			blr									; Return...

;
;			Set exit returns for a ISI
;

swapISI:	lwz		r7,savesrr1+vmm_proc_state(r5)	; Get the SRR1 value
			lwz		r10,savesrr0+vmm_proc_state(r5)	; Get the PC as failing address
			rlwinm	r7,r7,0,1,4					; Save the bits that match the DSISR
			stw		r10,return_params+0(r5)		; Save PC as first return parm
			stw		r7,return_params+4(r5)		; Save the pseudo-DSISR as second return parm
			blr									; Return...

;
;			Set exit returns for a system call (note: we did the first 3 earlier)
;			Do we really need to pass parameters back here????
;

swapSC:		lwz		r10,saver6+vmm_proc_state(r5)	; Get the fourth paramter
			stw		r10,return_params+12(r5)	; Save it
			blr									; Return...

