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
			.long	0												; Not valid in Fam
			.long	EXT(vmm_get_features_sel)						; Get the features of the VMM interface
			.long	0												; Not valid in Fam
			.long	EXT(vmm_init_context_sel)						; Initializes a new VMM context
			.long	0												; Not valid in Fam
			.long	EXT(vmm_tear_down_context)						; Tears down a previously-allocated VMM context
			.long	0												; Not valid in Fam
			.long	EXT(vmm_tear_down_all)							; Tears down all VMMs 
			.long	0												; Not valid in Fam
			.long	EXT(vmm_map_page)								; Maps a page from the main address space into the VM space 
			.long	1												; Valid in Fam
			.long	EXT(vmm_get_page_mapping)						; Returns client va associated with VM va
			.long	1												; Valid in Fam
			.long	EXT(vmm_unmap_page)								; Unmaps a page from the VM space
			.long	1												; Valid in Fam
			.long	EXT(vmm_unmap_all_pages)						; Unmaps all pages from the VM space 
			.long	1												; Valid in Fam
			.long	EXT(vmm_get_page_dirty_flag)					; Gets the change bit for a page and optionally clears it
			.long	1												; Valid in Fam
			.long	EXT(vmm_get_float_state)						; Gets current floating point state
			.long	0												; not valid in Fam
			.long	EXT(vmm_get_vector_state)						; Gets current vector state
			.long	0												; Not valid in Fam
			.long	EXT(vmm_set_timer)								; Sets a timer value
			.long	1												; Valid in Fam
			.long	EXT(vmm_get_timer)								; Gets a timer value
			.long	1												; Valid in Fam
			.long	EXT(switchIntoVM)								; Switches to the VM context
			.long	1												; Valid in Fam
			.long	EXT(vmm_protect_page)							; Sets protection values for a page
			.long	1												; Valid in Fam
			.long	EXT(vmm_map_execute)							; Maps a page an launches VM
			.long	1												; Not valid in Fam
			.long	EXT(vmm_protect_execute)						; Sets protection values for a page and launches VM
			.long	1												; Valid in Fam
			.long	EXT(vmm_map_list)								; Maps a list of pages
			.long	1												; Valid in Fam
			.long	EXT(vmm_unmap_list)								; Unmaps a list of pages
			.long	1												; Valid in Fam
			.long	EXT(vmm_fam_reserved)							; exit from Fam to host
			.long	1												; Valid in Fam
			.long	EXT(vmm_fam_reserved)							; resume guest from Fam
			.long	1												; Valid in Fam
			.long	EXT(vmm_fam_reserved)							; get guest register from Fam
			.long	1												; Valid in Fam
			.long	EXT(vmm_fam_reserved)							; Set guest register from Fam
			.long	1												; Valid in Fam

			.set	vmm_count,(.-EXT(vmm_dispatch_table))/8			; Get the top number


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
			rlwinm	r11,r11,3,0,28				; Index into table
			bgt-	cr1,vmmBogus				; It is a bogus entry
			add		r12,r10,r11					; Get the vmm dispatch syscall entry
			mfsprg	r10,0						; Get the per_proc
			lwz		r13,0(r12)					; Get address of routine
			lwz		r12,4(r12)					; Get validity flag
			lwz		r5,spcFlags(r10)			; Get per_proc special flags
			cmpwi	cr1,r12,0					; Check Fam valid 
			rlwinm.	r5,r5,0,FamVMmodebit,FamVMmodebit	; Test FamVMmodebit
			crand	cr0_eq,cr1_eq,cr0_gt		; In Fam and Invalid syscall	
			beq		vmmBogus					; Intercept to host
			lwz		r5,saver5(r30)				; Get 2nd parameter after selector
			lwz		r6,saver6(r30)				; Get 3rd parameter after selector
			mtlr	r13							; Set the routine address
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
			
vmmBogus:	
			mfsprg	r10,0						; Get the per_proc
			mfsprg	r3,1						; Load current activation
			lwz		r5,spcFlags(r10)			; Get per_proc special flags
			rlwinm.	r5,r5,0,FamVMmodebit,FamVMmodebit	; Test FamVMmodebit
			bne		vmmexitcall					; Do it to it		
			li		r3,0						; Bogus selector, treat like a bogus system call
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
			mfsprg	r10,0						; Get the per_proc
			lwz		r15,spcFlags(r10)			; Get per_proc special flags
			rlwinm.	r0,r15,0,FamVMmodebit,FamVMmodebit	; Test FamVMmodebit
			bne		vmmFamGuestResume		
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
			rlwinm.	r26,r4,0,vmmTimerPopb,vmmTimerPopb	; Did the timer go pop?
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
			
			la		r11,vmmFacCtx(r2)			; Point to the virtual machine facility context
			mr		r27,r2						; Save the context entry
			stw		r11,deferctx(r3)			; Start using the virtual machine facility context when we exit

			lwz		r11,ACT_MACT_SPF(r26)		; Get the special flags
			lwz		r3,vmmPmap(r27)				; Get the pointer to the PMAP
			oris	r15,r11,hi16(runningVM)	; 	; Show that we are swapped to the VM right now
			bl		EXT(hw_set_user_space_dis)	; Swap the address spaces
			lwz		r17,vmmFlags(r27)			; Get the status flags
			lwz		r20,vmmContextKern(r27)		; Get the state page kernel addr
			lwz		r21,vmmCntrl(r20)			; Get vmmCntrl
			rlwinm.	r22,r21,0,vmmFamEnab,vmmFamEnab	; Is vmmFamEnab set?
			beq		swvmNoFam					; No Fam intercept
			rlwimi	r15,r21,32+vmmFamSetb-FamVMmodebit,FamVMmodebit,FamVMmodebit	; Set FamVMmode bit
			rlwinm	r21,r21,0,vmmFamSetb+1,vmmFamSetb-1	; Clear FamSet bit
			lwz		r22,famintercepts(r20)		; Load intercept bit field
			stw		r21,vmmCntrl(r20)			; Update vmmCntrl
			lwz		r19,vmmContextPhys(r27)		; Get vmmFAMarea address
			stw		r22,vmmFAMintercept(r27)	; Get vmmFAMintercept
			stw		r22,FAMintercept(r10)		; Store vmmFAMintercept in per_proc FAMintercept
			stw		r19,vmmContextPhys(r27)		; Store vmmContextPhys
			stw		r19,VMMareaPhys(r10)		; Store VMMareaPhys
			oris	r15,r15,hi16(FamVMena)		; Set FamVMenabit
swvmNoFam:
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
			la		r25,vmmFacCtx(r27)			; Point to the facility context
			lwz		r15,vmmCntrl(r17)			; Get the control flags again
			mfsprg	r29,0						; Get the per_proc
			
;
;			Check if there is new floating point context to load
;			
						
			rlwinm.	r0,r15,0,vmmFloatLoadb,vmmFloatLoadb	; Are there new floating point values?
			lhz		r29,PP_CPU_NUMBER(r29)		; Get our cpu number
			li		r14,vmmppcFPRs				; Get displacement to the new values
			andc	r15,r15,r0					; Clear the bit
			beq+	swvmNoNewFloats				; Nope, good...
			
			lwz		r19,FPUcpu(r25)				; Get the last CPU we ran on
			
			stw		r29,FPUcpu(r25)				; Claim the context for ourselves
			
			eieio								; Make sure this stays in order
			
			lis		r18,hi16(EXT(per_proc_info))	; Set base per_proc
			mulli	r19,r19,ppSize				; Find offset to the owner per_proc			
			ori		r18,r18,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r16,FPUowner				; Displacement to float owner
			add		r19,r18,r19					; Point to the owner per_proc
			li		r0,0						; Clear this out	
			
swvminvfpu:	lwarx	r18,r16,r19					; Get the owner
			cmplw	r18,r25						; Does he still have this context?
			bne		swvminvfpv					; Nope...		
			stwcx.	r0,r16,r19					; Try to invalidate it
			bne-	swvminvfpu					; Try again if there was a collision...
			
swvminvfpv:	lwz		r3,FPUsave(r25)				; Get the FPU savearea
			dcbt	r14,r17						; Touch in first line of new stuff
			mr.		r3,r3						; Is there one?
			bne+	swvmGotFloat				; Yes...
			
			bl		EXT(save_get)				; Get a savearea

			li		r7,SAVfloat					; Get floating point flag
			stw		r26,SAVact(r3)				; Save our activation
			li		r0,0						; Get a zero
			stb		r7,SAVflags+2(r3)			; Set that this is floating point
			stw		r0,SAVprev(r3)				; Clear the back chain
			stw		r0,SAVlevel(r3)				; We are always at level 0 (user state)
			
			stw		r3,FPUsave(r25)				; Chain us to context

swvmGotFloat:
			la		r4,savefp0(r3)				; Point to the destination
			mr		r21,r3						; Save the save area
			la		r3,vmmppcFPRs(r17)			; Point to the source
			li		r5,32*8						; Get the size (32 FPRs at 8 bytes each)
			
			bl		EXT(bcopy)					; Copy the new values
			
			lwz		r14,vmmppcFPSCRshadow(r17)	; Get the fpscr pad
			lwz		r10,vmmppcFPSCRshadow+4(r17)	; Get the fpscr
			stw		r14,savefpscrpad(r30)		; Save the new fpscr pad
			stw		r10,savefpscr(r30)			; Save the new fpscr

			lwz		r11,ACT_MACT_SPF(r26)		; Get the special flags
			stw		r15,vmmCntrl(r17)			; Save the control flags sans vmmFloatLoad
			rlwinm	r11,r11,0,floatCngbit+1,floatCngbit-1	; Clear the changed bit here
			lwz		r14,vmmStat(r17)			; Get the status flags
			mfsprg	r10,0						; Get the per_proc
			stw		r11,ACT_MACT_SPF(r26)		; Get the special flags
			rlwinm	r14,r14,0,vmmFloatCngdb+1,vmmFloatCngdb-1	; Clear the changed flag
			stw		r11,spcFlags(r10)			; Set per_proc copy of the special flags
			stw		r14,vmmStat(r17)			; Set the status flags sans vmmFloatCngd
			
;
;			Check if there is new vector context to load
;			
									
swvmNoNewFloats:
			rlwinm.	r0,r15,0,vmmVectLoadb,vmmVectLoadb	; Are there new vector values?
			li		r14,vmmppcVRs				; Get displacement to the new values
			andc	r15,r15,r0					; Clear the bit
			beq+	swvmNoNewVects				; Nope, good...
			
			lwz		r19,VMXcpu(r25)				; Get the last CPU we ran on
			
			stw		r29,VMXcpu(r25)				; Claim the context for ourselves
			
			eieio								; Make sure this stays in order
			
			lis		r18,hi16(EXT(per_proc_info))	; Set base per_proc
			mulli	r19,r19,ppSize				; Find offset to the owner per_proc			
			ori		r18,r18,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r16,VMXowner				; Displacement to vector owner
			add		r19,r18,r19					; Point to the owner per_proc	
			li		r0,0						; Clear this out	
			
swvminvvec:	lwarx	r18,r16,r19					; Get the owner
			cmplw	r18,r25						; Does he still have this context?
			bne		swvminvved					; Nope...		
			stwcx.	r0,r16,r19					; Try to invalidate it
			bne-	swvminvvec					; Try again if there was a collision...
			
swvminvved:	lwz		r3,VMXsave(r25)				; Get the vector savearea
			dcbt	r14,r17						; Touch in first line of new stuff
			mr.		r3,r3						; Is there one?
			bne+	swvmGotVect					; Yes...
			
			bl		EXT(save_get)				; Get a savearea

			li		r7,SAVvector				; Get the vector type flag
			stw		r26,SAVact(r3)				; Save our activation
			li		r0,0						; Get a zero
			stb		r7,SAVflags+2(r3)			; Set that this is vector
			stw		r0,SAVprev(r3)				; Clear the back chain
			stw		r0,SAVlevel(r3)				; We are always at level 0 (user state)
			
			stw		r3,VMXsave(r25)				; Chain us to context

swvmGotVect:
			mr		r21,r3						; Save the pointer to the savearea
			la		r4,savevr0(r3)				; Point to the destination
			la		r3,vmmppcVRs(r17)			; Point to the source
			li		r5,32*16					; Get the size (32 vectors at 16 bytes each)
			
			bl		EXT(bcopy)					; Copy the new values

			lwz		r11,vmmppcVSCRshadow+0(r17)	; Get the VSCR
			lwz		r14,vmmppcVSCRshadow+4(r17)	; Get the VSCR
			lwz		r10,vmmppcVSCRshadow+8(r17)	; Get the VSCR
			lwz		r9,vmmppcVSCRshadow+12(r17)	; Get the VSCR
			lwz		r8,savevrsave(r30)			; Get the current VRSave
			
			stw		r11,savevscr+0(r30)			; Set the VSCR
			stw		r14,savevscr+4(r30)			; Set the VSCR
			stw		r10,savevscr+8(r30)			; Set the VSCR
			stw		r9,savevscr+12(r30)			; Set the VSCR
			stw		r8,savevrvalid(r21)			; Set the current VRSave as valid saved
			
			lwz		r11,ACT_MACT_SPF(r26)		; Get the special flags
			stw		r15,vmmCntrl(r17)			; Save the control flags sans vmmVectLoad
			rlwinm	r11,r11,0,vectorCngbit+1,vectorCngbit-1	; Clear the changed bit here
			lwz		r14,vmmStat(r17)			; Get the status flags
			mfsprg	r10,0						; Get the per_proc
			stw		r11,ACT_MACT_SPF(r26)		; Get the special flags
			rlwinm	r14,r14,0,vmmVectCngdb+1,vmmVectCngdb-1	; Clear the changed flag
			stw		r11,spcFlags(r10)			; Set per_proc copy of the special flags
			stw		r14,vmmStat(r17)			; Set the status flags sans vmmVectCngd
			
swvmNoNewVects:			
			li		r3,1						; Show normal exit with check for AST
			lwz		r16,ACT_THREAD(r26)			; Restore the thread pointer
			b		EXT(ppcscret)				; Go back to handler...


;
;			These syscalls are invalid, FAM syscall fast path 
;

			.align	5
			.globl	EXT(vmm_fam_reserved)

LEXT(vmm_fam_reserved)
			li		r3,0						; Force exception
			b		EXT(ppcscret)				; Go back to handler...

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

vmmexitcall:
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
			rlwinm	r11,r11,0,FamVMenabit+1,FamVMenabit-1	; Clear FamVMEnable
			lwz		r18,spcFlags(r10)			; Get per_proc copy of the special flags
			lwz		r5,vmmContextKern(r2)		; Get the state page kernel addr 
			rlwinm	r11,r11,0,FamVMmodebit+1,FamVMmodebit-1	; Clear FamVMMode
			lwz		r6,vmmCntrl(r5)				; Get the control field
			rlwimi	r19,r18,FamVMmodebit-vmmFAMmodeb,vmmFAMmodeb,vmmFAMmodeb	; Shift and insert changed bits			
			rlwimi	r6,r18,FamVMmodebit-vmmFamSetb,vmmFamSetb,vmmFamSetb		; Shift and insert changed bits			
			rlwimi	r6,r18,userProtKeybit-vmmKeyb,vmmKeyb,vmmKeyb				; Shift and insert changed bits			
			stw		r11,ACT_MACT_SPF(r16)		; Get the special flags
			stw		r6,vmmCntrl(r5)				; Store the control field
			stw		r11,spcFlags(r10)			; Set per_proc copy of the special flags
			
			mr		r26,r16						; Save the activation pointer
			mr		r27,r2						; Save the context entry
			
			bl		EXT(hw_set_user_space_dis)	; Swap the address spaces back to the emulator
			
			la		r5,facctx(r16)				; Point to the main facility context
			mr		r2,r27						; Restore
			stw		r5,deferctx(r16)			; Start using the main facility context on the way out
			lwz		r5,vmmContextKern(r27)		; Get the context area address
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
			lwz		r18,spcFlags(r10)			; Get per_proc copy of the special flags
			rlwinm	r9,r9,0,FamVMenabit+1,FamVMenabit-1	; Clear Fam Enable
			rlwinm	r9,r9,0,FamVMmodebit+1,FamVMmodebit-1	; Clear Fam Enable
			lwz		r5,vmmContextKern(r2)		; Get the context area address
			lwz		r6,vmmCntrl(r5)				; Get the control field
			rlwimi	r19,r18,FamVMmodebit-vmmFAMmodeb,vmmFAMmodeb,vmmFAMmodeb	; Shift and insert changed bits			
			rlwimi	r6,r18,FamVMmodebit-vmmFamSetb,vmmFamSetb,vmmFamSetb		; Shift and insert changed bits			
			rlwimi	r6,r18,userProtKeybit-vmmKeyb,vmmKeyb,vmmKeyb				; Shift and insert changed bits			
			stw		r6,vmmCntrl(r5)				; Store the control field
			stw		r9,ACT_MACT_SPF(r26)		; Get the special flags
			stw		r9,spcFlags(r10)			; Set per_proc copy of the special flags
			
			mr		r27,r2						; Save the context entry
			mr		r30,r4						; Save the savearea
			
			bl		EXT(hw_set_user_space_dis)	; Swap the address spaces back to the emulator
			
			la		r7,facctx(r26)				; Point to the main facility context
			
			lwz		r5,vmmContextKern(r27)		; Get the context area address
			stw		r19,vmmStat(r5)				; Save the changed and popped flags
			stw		r7,deferctx(r26)			; Tell context launcher to switch facility context
	
			bl		swapCtxt					; Exchange the VM context for the emulator one
			
			lwz		r8,saveexception(r30)		; Pick up the exception code
			lwz		r7,SAVflags(r30)			; Pick up the savearea flags
			lis		r9,hi16(SAVredrive)			; Get exception redrive bit
			rlwinm	r8,r8,30,24,31				; Convert exception to return code
			andc	r7,r7,r9					; Make sure redrive is off because we are intercepting
			stw		r8,saver3(r30)				; Set the return code as the return value also
			stw		r7,SAVflags(r30)			; Set the savearea flags
			

vfeNotRun:	lmw		r13,FM_ARG0(r1)				; Restore all non-volatile registers
			lwz		r1,0(r1)					; Pop the stack
			lwz		r0,FM_LR_SAVE(r1)			; Get the return address
			mtlr	r0							; Set return
			blr				

;
;			Note: we will not do any DCBTs to the savearea.  It was just stored to a few cycles ago and should 
;			still be in the cache.
;
;			NOTE NOTE:  R16 is important to save!!!!
;
			.align	5

swapCtxt:	la		r6,vmmppcpc(r5)				; Point to the first line
			
			lwz		r14,saveexception(r30)		; Get the exception code
			dcbt	0,r6						; Touch in the first line of the context area
			lwz		r7,savesrr0(r30)			; Start moving context	
			lwz		r8,savesrr1(r30)				
			lwz		r9,saver0(r30)				
			cmplwi	cr1,r14,T_SYSTEM_CALL		; Are we switching because of a system call?
			lwz		r10,saver1(r30)				
			lwz		r11,saver2(r30)				
			lwz		r12,saver3(r30)				
			lwz		r13,saver4(r30)	
			la		r6,vmmppcr6(r5)				; Point to second line		
			lwz		r14,saver5(r30)				
			
			dcbt	0,r6						; Touch second line of context area
			
			lwz		r15,vmmppcpc(r5)			; First line of context	
			lis		r22,hi16(MSR_IMPORT_BITS)	; Get the MSR bits that are controllable by user
			lwz		r23,vmmppcmsr(r5)				
			ori		r22,r22,lo16(MSR_IMPORT_BITS)	; Get the rest of the MSR bits that are controllable by user
			lwz		r17,vmmppcr0(r5)				
			lwz		r18,vmmppcr1(r5)		
			and		r23,r23,r22					; Keep only the controllable bits		
			lwz		r19,vmmppcr2(r5)		
			oris	r23,r23,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			lwz		r20,vmmppcr3(r5)				
			ori		r23,r23,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			lwz		r21,vmmppcr4(r5)				
			lwz		r22,vmmppcr5(r5)				

			dcbt	0,r6						; Touch third line of context area
		
			stw		r7,vmmppcpc(r5)				; Save emulator context into the context area	
			stw		r8,vmmppcmsr(r5)				
			stw		r9,vmmppcr0(r5)				
			stw		r10,vmmppcr1(r5)				
			stw		r11,vmmppcr2(r5)				
			stw		r12,vmmppcr3(r5)				
			stw		r13,vmmppcr4(r5)				
			stw		r14,vmmppcr5(r5)			

;			
;			Save the first 3 parameters if we are an SC (we will take care of the last later)
;
			bne+	cr1,swapnotsc				; Skip next if not an SC exception...	
			stw		r12,return_params+0(r5)		; Save the first return
			stw		r13,return_params+4(r5)		; Save the second return
			stw		r14,return_params+8(r5)		; Save the third return

swapnotsc:	stw		r15,savesrr0(r30)			; Save vm context into the savearea	
			stw		r23,savesrr1(r30)				
			stw		r17,saver0(r30)				
			stw		r18,saver1(r30)		
			stw		r19,saver2(r30)		
			stw		r20,saver3(r30)				
			stw		r21,saver4(r30)		
			la		r6,vmmppcr14(r5)			; Point to fourth line		
			stw		r22,saver5(r30)				
			
			dcbt	0,r6						; Touch fourth line

;			Swap 8 registers
			
			lwz		r7,saver6(r30)				; Read savearea	
			lwz		r8,saver7(r30)				
			lwz		r9,saver8(r30)				
			lwz		r10,saver9(r30)				
			lwz		r11,saver10(r30)				
			lwz		r12,saver11(r30)				
			lwz		r13,saver12(r30)				
			lwz		r14,saver13(r30)				

			lwz		r15,vmmppcr6(r5)			; Read vm context 
			lwz		r24,vmmppcr7(r5)				
			lwz		r17,vmmppcr8(r5)				
			lwz		r18,vmmppcr9(r5)		
			lwz		r19,vmmppcr10(r5)		
			lwz		r20,vmmppcr11(r5)				
			lwz		r21,vmmppcr12(r5)				
			lwz		r22,vmmppcr13(r5)				

			stw		r7,vmmppcr6(r5)				; Write context	
			stw		r8,vmmppcr7(r5)				
			stw		r9,vmmppcr8(r5)				
			stw		r10,vmmppcr9(r5)				
			stw		r11,vmmppcr10(r5)				
			stw		r12,vmmppcr11(r5)				
			stw		r13,vmmppcr12(r5)	
			la		r6,vmmppcr22(r5)			; Point to fifth line			
			stw		r14,vmmppcr13(r5)				

			dcbt	0,r6						; Touch fifth line

			stw		r15,saver6(r30)				; Write vm context 
			stw		r24,saver7(r30)				
			stw		r17,saver8(r30)				
			stw		r18,saver9(r30)		
			stw		r19,saver10(r30)		
			stw		r20,saver11(r30)				
			stw		r21,saver12(r30)				
			stw		r22,saver13(r30)				

;			Swap 8 registers
			
			lwz		r7,saver14(r30)				; Read savearea	
			lwz		r8,saver15(r30)				
			lwz		r9,saver16(r30)				
			lwz		r10,saver17(r30)				
			lwz		r11,saver18(r30)				
			lwz		r12,saver19(r30)				
			lwz		r13,saver20(r30)				
			lwz		r14,saver21(r30)				

			lwz		r15,vmmppcr14(r5)			; Read vm context 
			lwz		r24,vmmppcr15(r5)				
			lwz		r17,vmmppcr16(r5)				
			lwz		r18,vmmppcr17(r5)		
			lwz		r19,vmmppcr18(r5)		
			lwz		r20,vmmppcr19(r5)				
			lwz		r21,vmmppcr20(r5)				
			lwz		r22,vmmppcr21(r5)				

			stw		r7,vmmppcr14(r5)			; Write context	
			stw		r8,vmmppcr15(r5)				
			stw		r9,vmmppcr16(r5)				
			stw		r10,vmmppcr17(r5)				
			stw		r11,vmmppcr18(r5)				
			stw		r12,vmmppcr19(r5)				
			stw		r13,vmmppcr20(r5)
			la		r6,vmmppcr30(r5)			; Point to sixth line				
			stw		r14,vmmppcr21(r5)				
			
			dcbt	0,r6						; Touch sixth line

			stw		r15,saver14(r30)			; Write vm context 
			stw		r24,saver15(r30)				
			stw		r17,saver16(r30)				
			stw		r18,saver17(r30)		
			stw		r19,saver18(r30)		
			stw		r20,saver19(r30)				
			stw		r21,saver20(r30)				
			stw		r22,saver21(r30)				

;			Swap 8 registers
			
			lwz		r7,saver22(r30)				; Read savearea	
			lwz		r8,saver23(r30)				
			lwz		r9,saver24(r30)				
			lwz		r10,saver25(r30)				
			lwz		r11,saver26(r30)				
			lwz		r12,saver27(r30)				
			lwz		r13,saver28(r30)				
			lwz		r14,saver29(r30)				

			lwz		r15,vmmppcr22(r5)			; Read vm context 
			lwz		r24,vmmppcr23(r5)				
			lwz		r17,vmmppcr24(r5)				
			lwz		r18,vmmppcr25(r5)		
			lwz		r19,vmmppcr26(r5)		
			lwz		r20,vmmppcr27(r5)				
			lwz		r21,vmmppcr28(r5)				
			lwz		r22,vmmppcr29(r5)				

			stw		r7,vmmppcr22(r5)			; Write context	
			stw		r8,vmmppcr23(r5)				
			stw		r9,vmmppcr24(r5)				
			stw		r10,vmmppcr25(r5)				
			stw		r11,vmmppcr26(r5)				
			stw		r12,vmmppcr27(r5)				
			stw		r13,vmmppcr28(r5)	
			la		r6,vmmppcvscr(r5)			; Point to seventh line			
			stw		r14,vmmppcr29(r5)				

			dcbt	0,r6						; Touch seventh line

			stw		r15,saver22(r30)			; Write vm context 
			stw		r24,saver23(r30)				
			stw		r17,saver24(r30)				
			stw		r18,saver25(r30)		
			stw		r19,saver26(r30)		
			stw		r20,saver27(r30)				
			stw		r21,saver28(r30)				
			stw		r22,saver29(r30)				

;			Swap 8 registers
			
			lwz		r7,saver30(r30)				; Read savearea	
			lwz		r8,saver31(r30)				
			lwz		r9,savecr(r30)				
			lwz		r10,savexer(r30)				
			lwz		r11,savelr(r30)				
			lwz		r12,savectr(r30)				
			lwz		r14,savevrsave(r30)				

			lwz		r15,vmmppcr30(r5)			; Read vm context 
			lwz		r24,vmmppcr31(r5)				
			lwz		r17,vmmppccr(r5)				
			lwz		r18,vmmppcxer(r5)		
			lwz		r19,vmmppclr(r5)		
			lwz		r20,vmmppcctr(r5)				
			lwz		r22,vmmppcvrsave(r5)				

			stw		r7,vmmppcr30(r5)			; Write context	
			stw		r8,vmmppcr31(r5)				
			stw		r9,vmmppccr(r5)				
			stw		r10,vmmppcxer(r5)				
			stw		r11,vmmppclr(r5)				
			stw		r12,vmmppcctr(r5)				
			stw		r14,vmmppcvrsave(r5)				

			stw		r15,saver30(r30)			; Write vm context 
			stw		r24,saver31(r30)				
			stw		r17,savecr(r30)				
			stw		r18,savexer(r30)		
			stw		r19,savelr(r30)		
			stw		r20,savectr(r30)				
			stw		r22,savevrsave(r30)				

;			Swap 8 registers
			
			lwz		r7,savevscr+0(r30)			; Read savearea	
			lwz		r8,savevscr+4(r30)				
			lwz		r9,savevscr+8(r30)				
			lwz		r10,savevscr+12(r30)				
			lwz		r11,savefpscrpad(r30)				
			lwz		r12,savefpscr(r30)				

			lwz		r15,vmmppcvscr+0(r5)		; Read vm context 
			lwz		r24,vmmppcvscr+4(r5)				
			lwz		r17,vmmppcvscr+8(r5)				
			lwz		r18,vmmppcvscr+12(r5)		
			lwz		r19,vmmppcfpscrpad(r5)		
			lwz		r20,vmmppcfpscr(r5)				

			stw		r7,vmmppcvscr+0(r5)			; Write context	
			stw		r8,vmmppcvscr+4(r5)				
			stw		r9,vmmppcvscr+8(r5)				
			stw		r10,vmmppcvscr+12(r5)				
			stw		r11,vmmppcfpscrpad(r5)				
			stw		r12,vmmppcfpscr(r5)				

			stw		r15,savevscr+0(r30)			; Write vm context 
			stw		r24,savevscr+4(r30)				
			stw		r17,savevscr+8(r30)				
			stw		r18,savevscr+12(r30)		
			stw		r19,savefpscrpad(r30)		
			stw		r20,savefpscr(r30)				

			
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

swapISI:	lwz		r7,vmmppcmsr(r5)			; Get the SRR1 value
			lwz		r10,vmmppcpc(r5)			; Get the PC as failing address
			rlwinm	r7,r7,0,1,4					; Save the bits that match the DSISR
			stw		r10,return_params+0(r5)		; Save PC as first return parm
			stw		r7,return_params+4(r5)		; Save the pseudo-DSISR as second return parm
			blr									; Return...

;
;			Set exit returns for a system call (note: we did the first 3 earlier)
;			Do we really need to pass parameters back here????
;

swapSC:		lwz		r10,vmmppcr6(r5)			; Get the fourth paramter
			stw		r10,return_params+12(r5)	; Save it
			blr									; Return...

;
;			vmmFamGuestResume:
;				Restore Guest context from Fam mode.
;

vmmFamGuestResume:
			mfsprg	r10,0							; Get the per_proc
			lwz		r27,vmmCEntry(r3)				; Get the context that is active
			lwz		r15,spcFlags(r10)				; Get per_proc special flags
			mr		r26,r3							; Save the activation pointer
			lwz		r17,vmmFlags(r27)				; Get the status flags
			lwz		r20,vmmContextKern(r27)			; Get the comm area
			rlwinm	r15,r15,0,FamVMmodebit+1,FamVMmodebit-1	; Clear FamVMmodebit
			stw		r15,spcFlags(r10)				; Update the special flags
			rlwinm.	r0,r17,0,vmmMapDoneb,vmmMapDoneb	; Did we just do a map function?
			lwz		r7,famguestpc(r20)				; Load famguest ctx pc
			andc	r17,r17,r0						; Turn off map flag
			stw		r17,vmmFlags(r27)				; Update vmmFlags
			beq+	vmmFamRetNoMap					; No mapping done...
			lwz		r3,SAVflags(r30)				; Pick up the savearea flags
			lwz		r2,vmmLastMap(r27)				; Get the last mapped address
			li		r4,T_DATA_ACCESS				; Change to DSI fault
			oris	r3,r3,hi16(SAVredrive)			; Set exception redrive
			stw		r2,savedar(r30)					; Set the DAR to the last thing we mapped
			stw		r3,SAVflags(r30)				; Turn on the redrive request
			lis		r2,hi16(MASK(DSISR_HASH))		; Set PTE/DBAT miss
			stw		r4,saveexception(r30)			; Say we need to emulate a DSI
			stw		r2,savedsisr(r30)				; Pretend we have a PTE miss
vmmFamRetNoMap:
			mfsrr1	r4								; Get the current MSR value
			stw		r7,savesrr0(r30)				; Set savearea pc
			lwz		r5,famguestmsr(r20)				; Load famguest ctx msr
			lis		r6,hi16(MSR_IMPORT_BITS)		; Get the MSR bits that are controllable by user
			ori		r6,r6,lo16(MSR_IMPORT_BITS)		; Get the rest of the MSR bits that are controllable by user
			and		r5,r5,r6						; Keep only the controllable bits
			oris	r5,r5,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			ori		r5,r5,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			rlwimi	r5,r4,0,MSR_FP_BIT,MSR_FP_BIT	; Propagate guest FP
			rlwimi	r5,r4,0,MSR_VEC_BIT,MSR_VEC_BIT	; Propagate guest Vector	
			stw		r5,savesrr1(r30)				; Set savearea srr1
			lwz		r4,famguestr0(r20)				; Load famguest ctx r0
			lwz		r5,famguestr1(r20)				; Load famguest ctx r1
			lwz		r6,famguestr2(r20)				; Load famguest ctx r2
			lwz		r7,famguestr3(r20)				; Load famguest ctx r3
			stw		r4,saver0(r30)					; Set savearea r0
			stw		r5,saver1(r30)					; Set savearea r1
			stw		r6,saver2(r30)					; Set savearea r2
			stw		r7,saver3(r30)					; Set savearea r3
			lwz		r4,famguestr4(r20)				; Load famguest ctx r4
			lwz		r5,famguestr5(r20)				; Load famguest ctx r5
			lwz		r6,famguestr6(r20)				; Load famguest ctx r6
			lwz		r7,famguestr7(r20)				; Load famguest ctx r7
			stw		r4,saver4(r30)					; Set savearea r4
			stw		r5,saver5(r30)					; Set savearea r5
			stw		r6,saver6(r30)					; Set savearea r6
			stw		r7,saver7(r30)					; Set savearea r7

			li		r3,1							; Show normal exit with check for AST
			lwz		r16,ACT_THREAD(r26)				; Restore the thread pointer
			b		EXT(ppcscret)					; Go back to handler...

;
;			FAM Intercept handler
;

			.align	5
			.globl	EXT(vmm_fam_handler)

LEXT(vmm_fam_handler)
			lwz		r4,saver4(r13)					; Load savearea r0
			cmplwi	r11,T_ALIGNMENT					; Alignment exception?
			lwz		r3,VMMareaPhys(r2)				; Load phys state page addr
			cmplwi	cr1,r11,T_PROGRAM				; Exiting because of an PRG?
			stw		r4,famguestr4(r3)				; Save r4 in famguest ctx
			stw		r5,famguestr5(r3)				; Save r5 in famguest ctx
			stw		r6,famguestr6(r3)				; Save r6 in famguest ctx
			stw		r7,famguestr7(r3)				; Save r7 in famguest ctx
			lwz		r4,saver0(r13)					; Load savearea r0
			lwz		r5,saver1(r13)					; Load savearea r1
			lwz		r6,saver2(r13)					; Load savearea r2
			lwz		r7,saver3(r13)					; Load savearea r3
			stw		r4,famguestr0(r3)				; Save r0 in famguest ctx
			stw		r5,famguestr1(r3)				; Save r1 in famguest ctx
			stw		r6,famguestr2(r3)				; Save r2 in famguest ctx
			stw		r7,famguestr3(r3)				; Save r3 in famguest ctx
			lwz		r4,spcFlags(r2)					; Load per_proc spcFlags
			oris	r4,r4,hi16(FamVMmode)			; Set FAM mode
			stw		r4,spcFlags(r2)					; Update per_proc spcFlags
			mfsrr0  r2								; Get the interrupt srr0
			mfsrr1  r4								; Get the interrupt srr1
			stw		r2,famguestpc(r3)				; Save srr0 in famguest ctx
			stw		r4,famguestmsr(r3)				; Save srr1 in famguest ctx
			li		r6,lo16(MASK(MSR_FE0)|MASK(MSR_SE)|MASK(MSR_BE)|MASK(MSR_FE1))
			andc	r6,r4,r6						; Clear SE BE FE0 FE1
			mtsrr1	r6								; Set srr1
			mr		r6,r3							; Set r6 with  phys state page addr
			rlwinm	r7,r11,30,24,31					; Convert exception to return code
			beq+	cr1,famPRG						; We had a program exception...
			bne+	famRet	
													; We had an Alignment...
			mfdar	r3								; Load dar
			mfdsisr	r4								; Load dsisr
			stw		r3,famparam+0x4(r6)				; Set famparam 1 with dar
			stw		r4,famparam+0x8(r6)				; Set famparam 2 with dsir
			b		famRet							;
famPRG:
			stw		r4,famparam+0x4(r6)				; Set famparam 1 with srr1
			mr		r3,r4							; Set r3 with dsisr
			lwz		r4,famguestr4(r6)				; Load r4 from famguest context
famRet:
			lwz		r5,famguestr5(r6)				; Load r5 from famguest context
			lwz		r13,famhandler(r6)				; Load user address to resume
			stw		r2,famparam(r6)					; Set famparam 0 with srr0
			stw		r7,famdispcode(r6)				; Save the exit code
			lwz		r1,famrefcon(r6)				; load refcon
			mtcr	r0								; Restore cr
			mtsrr0	r13								; Load srr0
			mr		r0,r7							; Set dispatch code
			lwz		r7,famguestr7(r6)				; Load r7 from famguest context
			lwz		r6,famguestr6(r6)				; Load r6 from famguest context
			mfsprg	r13,2							; Restore r13
			mfsprg  r11,3							; Restore r11
			rfi

;
;			FAM Intercept DSI ISI fault handler
;

			.align	5
			.globl	EXT(vmm_fam_pf_handler)

LEXT(vmm_fam_pf_handler)
			lwz		r3,VMMareaPhys(r2)				; Load phys state page addr
			lwz		r4,saver0(r13)					; Load savearea r0
			lwz		r5,saver1(r13)					; Load savearea r1
			lwz		r6,saver2(r13)					; Load savearea r2
			lwz		r7,saver3(r13)					; Load savearea r3
			stw		r4,famguestr0(r3)				; Save r0 in famguest
			stw		r5,famguestr1(r3)				; Save r1 in famguest
			stw		r6,famguestr2(r3)				; Save r2 in famguest
			stw		r7,famguestr3(r3)				; Save r3 in famguest
			lwz		r4,saver4(r13)					; Load savearea r0
			lwz		r5,saver5(r13)					; Load savearea r1
			lwz		r6,saver6(r13)					; Load savearea r2
			lwz		r7,saver7(r13)					; Load savearea r3
			stw		r4,famguestr4(r3)				; Save r4 in famguest
			lwz		r4,spcFlags(r2)					; Load spcFlags
			stw		r5,famguestr5(r3)				; Save r5 in famguest
			lwz		r5,savesrr0(r13)				; Get the interrupt srr0
			stw		r6,famguestr6(r3)				; Save r6 in famguest
			lwz		r6,savesrr1(r13)				; Load srr1
			oris	r4,r4,hi16(FamVMmode)			; Set FAM mode
			stw		r7,famguestr7(r3)				; Save r7 in famguest
			stw		r4,spcFlags(r2)					; Update spcFlags
			lwz		r1,famrefcon(r3)				; Load refcon
			lwz		r2,famhandler(r3)				; Load famhandler to resume
			stw		r5,famguestpc(r3)				; Save srr0
			stw		r5,saver2(r13)					; Store srr0 in savearea r2
			stw		r5,famparam(r3)					; Store srr0 in fam param 0
			stw		r6,famguestmsr(r3)				; Save srr1 in famguestmsr
			cmplwi	cr1,r11,T_INSTRUCTION_ACCESS	; Was this a ISI?
			rlwinm	r7,r11,30,24,31					; Convert exception to return code
			beq+	cr1,FamPfISI					; We had an ISI...
; FamPfDSI
			lwz		r6,savedar(r13)					; Load dar from savearea
			lwz		r4,savedsisr(r13)				; Load dsisr from savearea
			stw		r6,famparam+0x4(r3)				; Store dar in fam param 1
			stw		r6,saver3(r13)					; Store dar in savearea r3
			stw		r4,famparam+0x8(r3)				; Store dsisr in fam param 2
			stw		r4,saver4(r13)					; Store dsisr in savearea r4
			b		FamPfRet
FamPfISI:	
			rlwinm	r6,r6,0,1,4						; Save the bits that match the DSISR
			stw		r6,famparam+0x4(r3)				; Store srr1 in fam param 1 
			stw		r6,saver3(r13)					; Store srr1 in savearea r3
FamPfRet:
			stw		r7,saver0(r13)					; Set dispatch code
			stw		r7,famdispcode(r3)				; Set dispatch code
			stw		r1,saver1(r13)					; Store refcon in savearea r1
			stw		r2,savesrr0(r13)				; Store famhandler in srr0
			blr

;
;			Ultra Fast Path FAM syscalls
;

			.align	5
			.globl	EXT(vmm_ufp)

LEXT(vmm_ufp)
			mfsprg	r3,0							; Get the per_proc area
			bt		cr5_eq,ResumeGuest				; if kvmmResumeGuest, branch to ResumeGuest
			lwz		r3,VMMareaPhys(r3)				; Load fast assist area
			cmpwi	cr7,r4,0						; Compare first arg with 0
			cmpwi	cr5,r4,7						; Compare first arg with 7
			cror	cr1_eq,cr7_lt,cr5_gt			; Is it in 0 to 7 range
			beq		cr1,ufpVMret					; Return if not in the range
			slwi	r4,r4,2							; multiply index by 4
			la		r3,famguestr0(r3)				; Load the base address
			bt		cr6_eq,SetGuestReg				; Set/get selector
; GetGuestReg
			lwzx	r3,r4,r3						; Load the guest register
			b		ufpVMret						; Return
SetGuestReg:
			stwx	r5,r4,r3						; Update the guest register
			li		r3,0							; Set return value
			b		ufpVMret						; Return
ResumeGuest:
			lwz		r7,spcFlags(r3)					; Pick up the special flags
			lwz		r13,VMMareaPhys(r3)				; Load fast assist area
			mtsrr0	r4								; Set srr0
			rlwinm.	r6,r6,0,vmmKeyb,vmmKeyb			; Check vmmKeyb in maskCntrl
			rlwinm	r7,r7,0,FamVMmodebit+1,FamVMmodebit-1	; Clear FamVMmodebit
			beq		ResumeGuest_nokey				; Branch if not key switch
			mr		r2,r7							; Save r7
			rlwimi	r7,r5,32+vmmKeyb-userProtKeybit,userProtKeybit,userProtKeybit	; Set the protection key
			cmpw	cr0,r7,r2						; Is userProtKeybit changed?						
			beq		ResumeGuest_nokey				; No, go to ResumeGuest_nokey
			lwz		r2,PP_USERPMAP(r3)				; Get user pmap phys addr
			rlwinm	r6,r7,userProtKeybit-2,2,2		; Extract and shift the key bit
			lwz		r5,PMAP_SPACE(r2)				; Load the space id
			oris	r5,r5,hi16(SEG_REG_PROT)		; Set the protection
			xor		r5,r5,r6						; Flip to proper segment register key
			addis	r4,r5,0x0000					; Get SR0 value
			mtsr	sr0,r4							; Load up the SR
			addis	r4,r5,0x0010					; Get SR1 value
			mtsr	sr1,r4							; Load up the SR
			addis	r4,r5,0x0020					; Get SR2 value
			mtsr	sr2,r4							; Load up the SR
			addis	r4,r5,0x0030					; Get SR3 value
			mtsr	sr3,r4							; Load up the SR
			addis	r4,r5,0x0040					; Get SR4 value
			mtsr	sr4,r4							; Load up the SR
			addis	r4,r5,0x0050					; Get SR5 value
			mtsr	sr5,r4							; Load up the SR
			addis	r4,r5,0x0060					; Get SR6 value
			mtsr	sr6,r4							; Load up the SR
			addis	r4,r5,0x0070					; Get SR7 value
			mtsr	sr7,r4							; Load up the SR
			addis	r4,r5,0x0080					; Get SR8 value
			mtsr	sr8,r4							; Load up the SR
			addis	r4,r5,0x0090					; Get SR9 value
			mtsr	sr9,r4							; Load up the SR
			addis	r4,r5,0x00a0					; Get SR10 value
			mtsr	sr10,r4							; Load up the SR
			addis	r4,r5,0x00b0					; Get SR11 value
			mtsr	sr11,r4							; Load up the SR
			addis	r4,r5,0x00c0					; Get SR12 value
			mtsr	sr12,r4							; Load up the SR
			addis	r4,r5,0x00d0					; Get SR13 value
			mtsr	sr13,r4							; Load up the SR
			addis	r4,r5,0x00e0					; Get SR14 value
			mtsr	sr14,r4							; Load up the SR
			addis	r4,r5,0x00f0					; Get SR15 value
			mtsr	sr15,r4							; Load up the SR
ResumeGuest_nokey:
			mfsrr1	r6								; Get the current MSR value
			lwz		r0,famguestr0(r13)				; Load r0 
			lwz		r1,famguestr1(r13)				; Load r1
			lwz		r4,famguestmsr(r13)				; Load guest srr1
			stw		r7,spcFlags(r3)					; Update the special flags
			lis		r5,hi16(MSR_IMPORT_BITS)		; Get the MSR bits that are controllable by user
			lwz		r2,famguestr2(r13)				; Load r2
			lwz		r3,famguestr3(r13)				; Load r3
			ori		r5,r5,lo16(MSR_IMPORT_BITS)		; Get the rest of the MSR bits that are controllable by user
			and		r7,r4,r5						; Keep only the controllable bits
			lwz		r4,famguestr4(r13)				; Load r4
			oris	r7,r7,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			lwz		r5,famguestr5(r13)				; Load r5
			ori		r7,r7,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			rlwimi	r7,r6,0,MSR_FP_BIT,MSR_FP_BIT	; Propagate guest FP
			rlwimi	r7,r6,0,MSR_VEC_BIT,MSR_VEC_BIT	; Propagate guest Vector	
			mtsrr1	r7								; Set srr1
			lwz		r6,famguestr6(r13)				; Load r6
			lwz		r7,famguestr7(r13)				; Load r7
ufpVMret:
			mtcrf	0xFF,r11						; Restore CR
			mfsprg	r11,3							; Restore R11
			mfsprg	r13,2							; Restore R13
			rfi										; All done, go back...
