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

#define vmmMapDone 31
#define vmmDoing64 30


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
 
 			.align	5												; Line up on cache line
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
			.long	EXT(vmm_map_page32)								; Maps a page from the main address space into the VM space - supports 32-bit
			.long	1												; Valid in Fam
			.long	EXT(vmm_get_page_mapping32)						; Returns client va associated with VM va - supports 32-bit
			.long	1												; Valid in Fam
			.long	EXT(vmm_unmap_page32)							; Unmaps a page from the VM space - supports 32-bit
			.long	1												; Valid in Fam
			.long	EXT(vmm_unmap_all_pages)						; Unmaps all pages from the VM space
			.long	1												; Valid in Fam
			.long	EXT(vmm_get_page_dirty_flag32)					; Gets the change bit for a page and optionally clears it - supports 32-bit
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
			.long	EXT(vmm_protect_page32)							; Sets protection values for a page - supports 32-bit
			.long	1												; Valid in Fam
			.long	EXT(vmm_map_execute32)							; Maps a page an launches VM - supports 32-bit
			.long	1												; Not valid in Fam
			.long	EXT(vmm_protect_execute32)						; Sets protection values for a page and launches VM - supports 32-bit
			.long	1												; Valid in Fam
			.long	EXT(vmm_map_list32)								; Maps a list of pages - supports 32-bit
			.long	1												; Valid in Fam
			.long	EXT(vmm_unmap_list32)							; Unmaps a list of pages - supports 32-bit
			.long	1												; Valid in Fam
			.long	EXT(vmm_fam_reserved)							; exit from Fam to host
			.long	1												; Valid in Fam
			.long	EXT(vmm_fam_reserved)							; resume guest from Fam
			.long	1												; Valid in Fam
			.long	EXT(vmm_fam_reserved)							; get guest register from Fam
			.long	1												; Valid in Fam
			.long	EXT(vmm_fam_reserved)							; Set guest register from Fam
			.long	1												; Valid in Fam
			.long	EXT(vmm_set_XA)									; Set extended architecture features for a VM 
			.long	0												; Not valid in Fam
			.long	EXT(vmm_get_XA)									; Get extended architecture features from a VM 
			.long	1												; Valid in Fam
			.long	EXT(vmm_map_page)								; Map a host to guest address space - supports 64-bit 
			.long	1												; Valid in Fam
			.long	EXT(vmm_get_page_mapping)						; Get host address of a guest page - supports 64-bit 
			.long	1												; Valid in Fam
			.long	EXT(vmm_unmap_page)								; Unmap a guest page - supports 64-bit 
			.long	1												; Valid in Fam
			.long	EXT(vmm_get_page_dirty_flag)					; Check if guest page modified - supports 64-bit 
			.long	1												; Valid in Fam
			.long	EXT(vmm_protect_page)							; Sets protection values for a page - supports 64-bit
			.long	1												; Valid in Fam
			.long	EXT(vmm_map_execute)							; Map guest page and launch - supports 64-bit 
			.long	1												; Valid in Fam
			.long	EXT(vmm_protect_execute)						; Set prot attributes and launch - supports 64-bit 
			.long	1												; Valid in Fam
			.long	EXT(vmm_map_list64)								; Map a list of pages into guest address spaces - supports 64-bit 
			.long	1												; Valid in Fam
			.long	EXT(vmm_unmap_list64)							; Unmap a list of pages from guest address spaces - supports 64-bit 
			.long	1												; Valid in Fam
			.long	EXT(vmm_max_addr)								; Returns the maximum virtual address 
			.long	1												; Valid in Fam


			.set	vmm_count,(.-EXT(vmm_dispatch_table))/8			; Get the top number


			.align	5
			.globl	EXT(vmm_dispatch)

LEXT(vmm_dispatch)

			lwz		r11,saver3+4(r30)			; Get the selector
			mr		r3,r4						; All of our functions want the activation as the first parm
			lis		r10,hi16(EXT(vmm_dispatch_table))	; Get top half of table
			cmplwi	r11,kVmmExecuteVM			; Should we switch to the VM now?
			cmplwi	cr1,r11,vmm_count			; See if we have a valid selector
			ori		r10,r10,lo16(EXT(vmm_dispatch_table))	; Get low half of table
			lwz		r4,saver4+4(r30)			; Get 1st parameter after selector
			beq+	EXT(switchIntoVM)			; Yes, go switch to it....
			rlwinm	r11,r11,3,0,28				; Index into table
			bge-	cr1,vmmBogus				; It is a bogus entry
			add		r12,r10,r11					; Get the vmm dispatch syscall entry
			mfsprg	r10,0						; Get the per_proc
			lwz		r13,0(r12)					; Get address of routine
			lwz		r12,4(r12)					; Get validity flag
			lwz		r5,spcFlags(r10)			; Get per_proc special flags
			cmpwi	cr1,r12,0					; Check Fam valid 
			rlwinm.	r5,r5,0,FamVMmodebit,FamVMmodebit	; Test FamVMmodebit
			crand	cr0_eq,cr1_eq,cr0_gt		; In Fam and Invalid syscall	
			beq		vmmBogus					; Intercept to host
			lwz		r5,saver5+4(r30)			; Get 2nd parameter after selector - note that some of these parameters may actually be long longs
			lwz		r6,saver6+4(r30)			; Get 3rd parameter after selector
			mtlr	r13							; Set the routine address
			lwz		r7,saver7+4(r30)			; Get 4th parameter after selector
			lwz		r8,saver8+4(r30)			; Get 5th parameter after selector
			lwz		r9,saver9+4(r30)			; Get 6th parameter after selector
;
;			NOTE: some of the above parameters are actually long longs.  We have glue code that transforms
;			all needed parameters and/or adds 32-/64-bit flavors to the needed functions.
;			

			blrl								; Call function

vmmRetPt:	li		r0,0						; Clear this out			
			stw		r0,saver3(r30)				; Make sure top of RC is clear
			stw		r3,saver3+4(r30)			; Pass back the return code
			stw		r0,saver4(r30)				; Make sure bottom of RC is clear (just in case)
			stw		r4,saver4+4(r30)			; Pass back the bottom return code (just in case)
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

			lwz		r4,saver4+4(r30)			; Get the passed in version
			lwz		r5,saver5+4(r30)			; Get the passed in comm area
			lis		r3,hi16(EXT(vmm_init_context))
			stw		r4,saver3+4(r30)			; Cheat and move this parameter over
			ori		r3,r3,lo16(EXT(vmm_init_context))
			stw		r5,saver4+4(r30)			; Cheat and move this parameter over

selcomm:	mtlr	r3							; Set the real routine address
			mr		r3,r30						; Pass in the savearea
			blrl								; Call the function
			b		EXT(ppcscret)				; Go back to handler...

			.align	5
			.globl	EXT(vmm_map_page32)

LEXT(vmm_map_page32)
			mr		r9,r7											; Move prot to correct parm
			mr		r8,r6											; Move guest address to low half of long long
			li		r7,0											; Clear high half of guest address
			mr		r6,r5											; Move host address to low half of long long
			li		r5,0											; Clear high half of host address
			b		EXT(vmm_map_page)								; Transition to real function...

			.align	5
			.globl	EXT(vmm_get_page_mapping32)

LEXT(vmm_get_page_mapping32)
			mr		r6,r5											; Move guest address to low half of long long
			li		r5,0											; Clear high half of guest address
			bl		EXT(vmm_get_page_mapping)						; Transition to real function...
			mr		r3,r4											; Convert addr64_t to vm_offset_t, dropping top half
			b		vmmRetPt										; Join normal return...

			.align	5
			.globl	EXT(vmm_unmap_page32)

LEXT(vmm_unmap_page32)
			mr		r6,r5											; Move guest address to low half of long long
			li		r5,0											; Clear high half of guest address
			b		EXT(vmm_unmap_page)								; Transition to real function...

			.align	5
			.globl	EXT(vmm_get_page_dirty_flag32)

LEXT(vmm_get_page_dirty_flag32)
			mr		r7,r6											; Move reset flag
			mr		r6,r5											; Move guest address to low half of long long
			li		r5,0											; Clear high half of guest address
			b		EXT(vmm_get_page_dirty_flag)					; Transition to real function...

			.align	5
			.globl	EXT(vmm_protect_page32)

LEXT(vmm_protect_page32)
			mr		r7,r6											; Move protection bits
			mr		r6,r5											; Move guest address to low half of long long
			li		r5,0											; Clear high half of guest address
			b		EXT(vmm_protect_page)							; Transition to real function...

			.align	5
			.globl	EXT(vmm_map_execute32)

LEXT(vmm_map_execute32)
			mr		r9,r7											; Move prot to correct parm
			mr		r8,r6											; Move guest address to low half of long long
			li		r7,0											; Clear high half of guest address
			mr		r6,r5											; Move host address to low half of long long
			li		r5,0											; Clear high half of host address
			b		EXT(vmm_map_execute)							; Transition to real function...

			.align	5
			.globl	EXT(vmm_protect_execute32)
			
LEXT(vmm_protect_execute32)
			mr		r7,r6											; Move protection bits
			mr		r6,r5											; Move guest address to low half of long long
			li		r5,0											; Clear high half of guest address
			b		EXT(vmm_protect_execute)						; Transition to real function...

			.align	5
			.globl	EXT(vmm_map_list32)
			
LEXT(vmm_map_list32)
			li		r6,0											; Set 32-bit flavor
			b		EXT(vmm_map_list)								; Go to common routine...

			.align	5
			.globl	EXT(vmm_map_list64)
			
LEXT(vmm_map_list64)
			li		r6,1											; Set 64-bit flavor
			b		EXT(vmm_map_list)								; Go to common routine...

			.align	5
			.globl	EXT(vmm_map_list32)
			
LEXT(vmm_unmap_list32)
			li		r6,0											; Set 32-bit flavor
			b		EXT(vmm_unmap_list)								; Go to common routine...

			.align	5
			.globl	EXT(vmm_map_list64)
			
LEXT(vmm_unmap_list64)
			li		r6,1											; Set 64-bit flavor
			b		EXT(vmm_unmap_list)								; Go to common routine...

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
			rlwinm	r31,r4,24,24,31				; Get the address space
			rlwinm	r4,r4,0,24,31				; Isolate the context id
			lwz		r28,vmmControl(r3)			; Pick up the control table address
			subi	r4,r4,1						; Switch to zero offset
			rlwinm.	r2,r28,0,0,30				; Is there a context there? (Note: we will ignore bit 31 so that we 
												;   do not try this while we are transitioning off to on
			cmplwi	cr1,r4,kVmmMaxContexts		; Is the index valid?
			beq-	vmmBogus					; Not started, treat like a bogus system call
			subic.	r31,r31,1					; Make address space 0 based and test if we use default
			mulli	r2,r4,vmmCEntrySize			; Get displacement from index
			bge-	cr1,swvmmBogus				; Index is bogus...
			add		r2,r2,r28					; Point to the entry
			bge--	swvmmDAdsp					; There was an explicit address space request
			mr		r31,r4						; Default the address space to the context ID

swvmmDAdsp:	la		r2,vmmc(r2)					; Get the offset to the context array
			lwz		r8,vmmGFlags(r28)			; Get the general flags
			lwz		r4,vmmFlags(r2)				; Get the flags for the selected entry
			crset	vmmMapDone					; Assume we will be mapping something
			lwz		r5,vmmContextKern(r2)		; Get the context area address
			rlwinm.	r26,r4,0,vmmInUseb,vmmInUseb	; See if the slot is in use
			cmplwi	cr1,r31,kVmmMaxContexts		; See if we have a valid address space ID
			rlwinm	r8,r8,0,24,31				; Clean up address space
			beq--	swvmmBogus					; This context is no good...

			la		r26,vmmAdsp(r28)			; Point to the pmaps
			sub		r8,r8,r31					; Get diff between launching address space - 1 and last mapped into (should be 1 if the same)
			rlwinm	r31,r31,2,0,29				; Index to the pmap
			cmplwi	r8,1						; See if we have the same address space
			bge--	cr1,swvmmBogAdsp			; Address space is no good...
			lwzx	r31,r26,r31					; Get the requested address space pmap
			li		r0,0						; Get a 0 in case we need to trash redrive
			lwz		r15,spcFlags(r10)			; Get per_proc special flags
			beq		swvmmAdspOk					; Do not invalidate address space if we are launching the same
			crclr	vmmMapDone					; Clear map done flag
			stb		r0,vmmGFlags+3(r28)			; Clear the last mapped address space ID so we will not redrive later
;
;			Here we check for any immediate intercepts.  So far, the only
;			two of these are a timer pop and and external stop.  We will not dispatch if
;			either is true.  They need to either reset the timer (i.e. set timer
;			to 0) or to set a future time, or if it is external stop, set the vmmXStopRst flag.
;

swvmmAdspOk:
			rlwinm.	r0,r15,0,FamVMmodebit,FamVMmodebit	; Test FamVMmodebit
			stw		r31,vmmPmap(r2)				; Save the last dispatched address space
			bne		vmmFamGuestResume		
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
			bne--	swvmSetStop					; Yes...
			
			rlwinm.	r26,r4,0,vmmTimerPopb,vmmTimerPopb	; Did the timer go pop?
			cmplwi	cr1,r31,0					; Is there actually an address space defined?
			bne--	svvmTimerPop				; Yes...

;
;			Special note: we need to intercept any attempt to launch a guest into a non-existent address space.
;			We will just go emulate an ISI if there is not one.
;

			beq--	cr1,swvmEmulateISI			; We are trying to launch into an undefined address space.  This is not so good...

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
			mr		r3,r31						; Get the pointer to the PMAP
			oris	r15,r11,hi16(runningVM)	; 	; Show that we are swapped to the VM right now
			bl		EXT(hw_set_user_space_dis)	; Swap the address spaces
			lwz		r17,vmmFlags(r27)			; Get the status flags
			lwz		r20,vmmContextKern(r27)		; Get the state page kernel addr
			lwz		r21,vmmCntrl(r20)			; Get vmmCntrl
			rlwinm.	r22,r21,0,vmmFamEnab,vmmFamEnab	; Is vmmFamEnab set?
			lwz		r22,vmmXAFlgs(r27)			; Get the eXtended Architecture flags
			stw		r22,VMMXAFlgs(r10)			; Store vmmXAFlgs in per_proc VMMXAFlgs
			beq		swvmNoFam					; No Fam intercept
			rlwinm.	r22,r22,0,0,0				; Are we doing a 64-bit virtual machine?
			rlwimi	r15,r21,32+vmmFamSetb-FamVMmodebit,FamVMmodebit,FamVMmodebit	; Set FamVMmode bit
			rlwinm	r21,r21,0,vmmFamSetb+1,vmmFamSetb-1	; Clear FamSet bit
			bne		swvmXfamintercpt
			lwz		r22,famintercepts(r20)		; Load intercept bit field
			b		swvmfamintercptres
swvmXfamintercpt:
			lwz		r22,faminterceptsX(r20)		; Load intercept bit field
swvmfamintercptres:
			stw		r21,vmmCntrl(r20)			; Update vmmCntrl
			lwz		r19,vmmContextPhys(r27)		; Get vmmFAMarea address
			stw		r22,vmmFAMintercept(r27)	; Get vmmFAMintercept
			stw		r22,FAMintercept(r10)		; Store vmmFAMintercept in per_proc FAMintercept
			stw		r19,VMMareaPhys(r10)		; Store VMMareaPhys
			oris	r15,r15,hi16(FamVMena)		; Set FamVMenabit
swvmNoFam:
			stw		r27,vmmCEntry(r26)			; Remember what context we are running
			bf++	vmmMapDone,swvmNoMap		; We have not mapped anything or it was not for this address space

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
;			Note that we need to revisit this when we move the virtual machines to the task because
;			then it will be possible for more than one thread to access this stuff at the same time.
;
			
			lwz		r3,SAVflags(r30)			; Pick up the savearea flags
			lwz		r2,vmmLastMap(r28)			; Get the last mapped address
			lwz		r14,vmmLastMap+4(r28)		; Get the last mapped address low half
			li		r20,T_DATA_ACCESS			; Change to DSI fault
			oris	r3,r3,hi16(SAVredrive)		; Set exception redrive
			stw		r2,savedar(r30)				; Set the DAR to the last thing we mapped
			stw		r14,savedar+4(r30)			; Set the DAR to the last thing we mapped
			stw		r3,SAVflags(r30)			; Turn on the redrive request
			lis		r2,hi16(MASK(DSISR_HASH))	; Set PTE/DBAT miss
			li		r0,0						; Clear
			stw		r20,saveexception(r30)		; Say we need to emulate a DSI
			stw		r2,savedsisr(r30)			; Pretend we have a PTE miss			
			stb		r0,vmmGFlags+3(r28)			; Show that the redrive has been taken care of
			
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
			
swvminvfpu:	lwarx	r18,r16,r19					; Get the owner

			sub		r0,r18,r25					; Subtract one from the other
			sub		r3,r25,r18					; Subtract the other from the one
			or		r3,r3,r0					; Combine them
			srawi	r3,r3,31					; Get a 0 if equal or -1 of not
			and		r18,r18,r3					; Make 0 if same, unchanged if not
			stwcx.	r18,r16,r19					; Try to invalidate it
			bne--	swvminvfpu					; Try again if there was a collision...

			lwz		r3,FPUsave(r25)				; Get the FPU savearea
			dcbt	r14,r17						; Touch in first line of new stuff
			mr.		r3,r3						; Is there one?
			bne+	swvmGotFloat				; Yes...
			
			bl		EXT(save_get)				; Get a savearea

			li		r7,SAVfloat					; Get floating point flag
			stw		r26,SAVact(r3)				; Save our activation
			li		r0,0						; Get a zero
			stb		r7,SAVflags+2(r3)			; Set that this is floating point
			stw		r0,SAVprev+4(r3)			; Clear the back chain
			stw		r0,SAVlevel(r3)				; We are always at level 0 (user state)
			
			stw		r3,FPUsave(r25)				; Chain us to context

swvmGotFloat:
			la		r4,savefp0(r3)				; Point to the destination
			mr		r21,r3						; Save the save area
			la		r3,vmmppcFPRs(r17)			; Point to the source
			li		r5,32*8						; Get the size (32 FPRs at 8 bytes each)
			
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
			
swvminvvec:	lwarx	r18,r16,r19					; Get the owner

			sub		r0,r18,r25					; Subtract one from the other
			sub		r3,r25,r18					; Subtract the other from the one
			or		r3,r3,r0					; Combine them
			srawi	r3,r3,31					; Get a 0 if equal or -1 of not
			and		r18,r18,r3					; Make 0 if same, unchanged if not
			stwcx.	r18,r16,r19					; Try to invalidate it
			bne--	swvminvfpu					; Try again if there was a collision...
			
swvminvved:	lwz		r3,VMXsave(r25)				; Get the vector savearea
			dcbt	r14,r17						; Touch in first line of new stuff
			mr.		r3,r3						; Is there one?
			bne+	swvmGotVect					; Yes...
			
			bl		EXT(save_get)				; Get a savearea

			li		r7,SAVvector				; Get the vector type flag
			stw		r26,SAVact(r3)				; Save our activation
			li		r0,0						; Get a zero
			stb		r7,SAVflags+2(r3)			; Set that this is vector
			stw		r0,SAVprev+4(r3)			; Clear the back chain
			stw		r0,SAVlevel(r3)				; We are always at level 0 (user state)
			
			stw		r3,VMXsave(r25)				; Chain us to context

swvmGotVect:
			mr		r21,r3						; Save the pointer to the savearea
			la		r4,savevr0(r3)				; Point to the destination
			la		r3,vmmppcVRs(r17)			; Point to the source
			li		r5,32*16					; Get the size (32 vectors at 16 bytes each)
			
			bl		EXT(bcopy)					; Copy the new values

			lwz		r8,savevrsave(r30)			; Get the current VRSave
			
			lwz		r11,ACT_MACT_SPF(r26)		; Get the special flags
			stw		r15,vmmCntrl(r17)			; Save the control flags sans vmmVectLoad
			rlwinm	r11,r11,0,vectorCngbit+1,vectorCngbit-1	; Clear the changed bit here
			stw		r8,savevrvalid(r21)			; Set the current VRSave as valid saved
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

			.align	5
			
swvmmBogus:	li		r2,kVmmBogusContext			; Set bogus index return
			li		r0,0						; Clear
			li		r3,1						; Set normal return with check for AST	
			stw		r0,saver3(r30)				; Clear upper half
			stw		r2,saver3+4(r30)			; Pass back the return code
			b		EXT(ppcscret)				; Go back to handler...
			
swvmmBogAdsp:
			li		r2,kVmmInvalidAdSpace		; Set bogus address space return
			li		r0,0						; Clear
			li		r3,1						; Set normal return with check for AST	
			stw		r0,saver3(r30)				; Clear upper half
			stw		r2,saver3+4(r30)			; Pass back the return code
			b		EXT(ppcscret)				; Go back to handler...
				
swvmSetStop:
			li		r2,kVmmStopped				; Set stopped return
			li		r0,0						; Clear
			li		r3,1						; Set normal return with check for AST
			stw		r0,saver3(r30)				; Clear upper half
			stw		r2,saver3+4(r30)			; Pass back the return code
			stw		r2,return_code(r5)			; Save the exit code
			b		EXT(ppcscret)				; Go back to handler...
		
svvmTimerPop:
			li		r2,kVmmReturnNull			; Set null return
			li		r0,0						; Clear
			li		r3,1						; Set normal return with check for AST
			stw		r0,saver3(r30)				; Clear upper half
			stw		r2,saver3+4(r30)			; Pass back the return code
			stw		r2,return_code(r5)			; Save the exit code
			b		EXT(ppcscret)				; Go back to handler...
		
swvmEmulateISI:
			mfsprg	r10,2						; Get feature flags
			lwz		r11,vmmXAFlgs(r28)			; Get the eXtended Architecture flags			
			mtcrf	0x02,r10					; Move pf64Bit to its normal place in CR6
			rlwinm.	r11,r11,0,0,0				; Are we doing a 64-bit virtual machine?		
			li		r2,kVmmReturnInstrPageFault	; Set ISI
			crnot	vmmDoing64,cr0_eq			; Remember if this is a 64-bit VM
			li		r0,0						; Clear
			li		r3,1						; Set normal return with check for AST
			stw		r0,saver3(r30)				; Clear upper half
			stw		r2,saver3+4(r30)			; Pass back the return code
			stw		r2,return_code(r5)			; Save the exit code
			lis		r7,hi16(MASK(DSISR_HASH))	; Pretend like we got a PTE miss
			bt		vmmDoing64,vmISI64			; Go do this for a 64-bit VM...

			lwz		r10,vmmppcpc(r5)			; Get the PC as failing address
			stw		r10,return_params+0(r5)		; Save PC as first return parm
			stw		r7,return_params+4(r5)		; Save the pseudo-DSISR as second return parm
			b		EXT(ppcscret)				; Go back to handler...

vmISI64:	ld		r10,vmmppcXpc(r5)			; Get the PC as failing address
			std		r10,return_paramsX+0(r5)	; Save PC as first return parm
			std		r7,return_paramsX+8(r5)		; Save the pseudo-DSISR as second return parm
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
			stw		r8,saver3+4(r30)			; Set the return code as the return value also
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
			stw		r8,saver3+4(r30)			; Set the return code as the return value also
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

swapCtxt:	
			mfsprg	r10,2						; Get feature flags
			la		r6,vmmppcpc(r5)				; Point to the first line
			mtcrf	0x02,r10					; Move pf64Bit to its normal place in CR6
			
			lwz		r14,saveexception(r30)		; Get the exception code
			dcbt	0,r6						; Touch in the first line of the context area
			bt++	pf64Bitb,swap64				; Go do this swap on a 64-bit machine...
			
			lwz		r7,savesrr0+4(r30)			; Start moving context	
			lwz		r8,savesrr1+4(r30)				
			lwz		r9,saver0+4(r30)				
			cmplwi	cr1,r14,T_SYSTEM_CALL		; Are we switching because of a system call?
			lwz		r10,saver1+4(r30)				
			lwz		r11,saver2+4(r30)				
			lwz		r12,saver3+4(r30)				
			lwz		r13,saver4+4(r30)	
			la		r6,vmmppcr6(r5)				; Point to second line		
			lwz		r14,saver5+4(r30)				
			
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

swapnotsc:	li		r6,0						; Clear this out
			stw		r6,savesrr0(r30)			; Insure that high order is clear
			stw		r15,savesrr0+4(r30)			; Save vm context into the savearea	
			stw		r6,savesrr1(r30)			; Insure that high order is clear
			stw		r23,savesrr1+4(r30)				
			stw		r17,saver0+4(r30)				
			stw		r18,saver1+4(r30)		
			stw		r19,saver2+4(r30)		
			stw		r20,saver3+4(r30)				
			stw		r21,saver4+4(r30)		
			la		r6,vmmppcr14(r5)			; Point to fourth line		
			stw		r22,saver5+4(r30)				
			
			dcbt	0,r6						; Touch fourth line

;			Swap 8 registers
			
			lwz		r7,saver6+4(r30)			; Read savearea	
			lwz		r8,saver7+4(r30)				
			lwz		r9,saver8+4(r30)				
			lwz		r10,saver9+4(r30)				
			lwz		r11,saver10+4(r30)				
			lwz		r12,saver11+4(r30)				
			lwz		r13,saver12+4(r30)				
			lwz		r14,saver13+4(r30)				

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

			stw		r15,saver6+4(r30)			; Write vm context 
			stw		r24,saver7+4(r30)				
			stw		r17,saver8+4(r30)				
			stw		r18,saver9+4(r30)		
			stw		r19,saver10+4(r30)		
			stw		r20,saver11+4(r30)				
			stw		r21,saver12+4(r30)				
			stw		r22,saver13+4(r30)				

;			Swap 8 registers
			
			lwz		r7,saver14+4(r30)			; Read savearea	
			lwz		r8,saver15+4(r30)				
			lwz		r9,saver16+4(r30)				
			lwz		r10,saver17+4(r30)				
			lwz		r11,saver18+4(r30)				
			lwz		r12,saver19+4(r30)				
			lwz		r13,saver20+4(r30)				
			lwz		r14,saver21+4(r30)				

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

			stw		r15,saver14+4(r30)			; Write vm context 
			stw		r24,saver15+4(r30)				
			stw		r17,saver16+4(r30)				
			stw		r18,saver17+4(r30)		
			stw		r19,saver18+4(r30)		
			stw		r20,saver19+4(r30)				
			stw		r21,saver20+4(r30)				
			stw		r22,saver21+4(r30)				

;			Swap 8 registers
			
			lwz		r7,saver22+4(r30)			; Read savearea	
			lwz		r8,saver23+4(r30)				
			lwz		r9,saver24+4(r30)				
			lwz		r10,saver25+4(r30)				
			lwz		r11,saver26+4(r30)				
			lwz		r12,saver27+4(r30)				
			lwz		r13,saver28+4(r30)				
			lwz		r14,saver29+4(r30)				

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

			stw		r15,saver22+4(r30)			; Write vm context 
			stw		r24,saver23+4(r30)				
			stw		r17,saver24+4(r30)				
			stw		r18,saver25+4(r30)		
			stw		r19,saver26+4(r30)		
			stw		r20,saver27+4(r30)				
			stw		r21,saver28+4(r30)				
			stw		r22,saver29+4(r30)				

;			Swap 8 registers
			
			lwz		r7,saver30+4(r30)			; Read savearea	
			lwz		r8,saver31+4(r30)				
			lwz		r9,savecr(r30)				
			lwz		r10,savexer+4(r30)				
			lwz		r11,savelr+4(r30)				
			lwz		r12,savectr+4(r30)				
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

			stw		r15,saver30+4(r30)			; Write vm context 
			stw		r24,saver31+4(r30)				
			stw		r17,savecr(r30)				
			stw		r18,savexer+4(r30)		
			stw		r19,savelr+4(r30)		
			stw		r20,savectr+4(r30)				
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

swapDSI:	lwz		r10,savedar+4(r30)			; Get the DAR
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
;			Here is the swap for 64-bit machines
;

swap64:		lwz		r22,vmmXAFlgs(r27)			; Get the eXtended Architecture flags			
			ld		r7,savesrr0(r30)			; Start moving context	
			ld		r8,savesrr1(r30)				
			ld		r9,saver0(r30)				
			cmplwi	cr1,r14,T_SYSTEM_CALL		; Are we switching because of a system call?
			ld		r10,saver1(r30)				
			ld		r11,saver2(r30)		
			rlwinm.	r22,r22,0,0,0				; Are we doing a 64-bit virtual machine?		
			ld		r12,saver3(r30)				
			crnot	vmmDoing64,cr0_eq			; Remember if this is a 64-bit VM
			ld		r13,saver4(r30)	
			la		r6,vmmppcr6(r5)				; Point to second line		
			ld		r14,saver5(r30)				
			
			dcbt	0,r6						; Touch second line of context area
			
			bt		vmmDoing64,sw64x1			; Skip to 64-bit stuff
			
			lwz		r15,vmmppcpc(r5)			; First line of context	
			lis		r22,hi16(MSR_IMPORT_BITS)	; Get the MSR bits that are controllable by user
			lwz		r23,vmmppcmsr(r5)				
			ori		r22,r25,lo16(MSR_IMPORT_BITS)	; Get the rest of the MSR bits that are controllable by user
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
			bne+	cr1,sw64x1done				; Skip next if not an SC exception...	
			stw		r12,return_params+0(r5)		; Save the first return
			stw		r13,return_params+4(r5)		; Save the second return
			stw		r14,return_params+8(r5)		; Save the third return
			b		sw64x1done					; We are done with this section...

sw64x1:		ld		r15,vmmppcXpc(r5)			; First line of context	
			li		r0,1						; Get a 1 to turn on 64-bit
			lis		r22,hi16(MSR_IMPORT_BITS)	; Get the MSR bits that are controllable by user (we will also allow 64-bit here)
			sldi	r0,r0,63					; Get 64-bit bit
			ld		r23,vmmppcXmsr(r5)				
			ori		r22,r25,lo16(MSR_IMPORT_BITS)	; Get the rest of the MSR bits that are controllable by user
			ld		r17,vmmppcXr0(r5)		
			or		r22,r22,r0					; Add the 64-bit bit		
			ld		r18,vmmppcXr1(r5)		
			and		r23,r23,r22					; Keep only the controllable bits		
			ld		r19,vmmppcXr2(r5)		
			oris	r23,r23,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			ld		r20,vmmppcXr3(r5)				
			ori		r23,r23,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			ld		r21,vmmppcXr4(r5)				
			ld		r22,vmmppcXr5(r5)				

			dcbt	0,r6						; Touch third line of context area
		
			std		r7,vmmppcXpc(r5)			; Save emulator context into the context area	
			std		r8,vmmppcXmsr(r5)				
			std		r9,vmmppcXr0(r5)				
			std		r10,vmmppcXr1(r5)				
			std		r11,vmmppcXr2(r5)				
			std		r12,vmmppcXr3(r5)				
			std		r13,vmmppcXr4(r5)				
			std		r14,vmmppcXr5(r5)			

;			
;			Save the first 3 parameters if we are an SC (we will take care of the last later)
;
			bne+	cr1,sw64x1done				; Skip next if not an SC exception...	
			std		r12,return_paramsX+0(r5)	; Save the first return
			std		r13,return_paramsX+8(r5)	; Save the second return
			std		r14,return_paramsX+16(r5)	; Save the third return

sw64x1done:	
			std		r15,savesrr0(r30)			; Save vm context into the savearea	
			std		r23,savesrr1(r30)				
			std		r17,saver0(r30)				
			std		r18,saver1(r30)		
			std		r19,saver2(r30)		
			std		r20,saver3(r30)				
			std		r21,saver4(r30)		
			la		r6,vmmppcr14(r5)			; Point to fourth line		
			std		r22,saver5(r30)				
			
			dcbt	0,r6						; Touch fourth line

;			Swap 8 registers
			
			ld		r7,saver6(r30)			; Read savearea	
			ld		r8,saver7(r30)				
			ld		r9,saver8(r30)				
			ld		r10,saver9(r30)				
			ld		r11,saver10(r30)				
			ld		r12,saver11(r30)				
			ld		r13,saver12(r30)				
			ld		r14,saver13(r30)				
			
			bt		vmmDoing64,sw64x2			; Skip to 64-bit stuff

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
			b		sw64x2done					; We are done with this section...

sw64x2:		ld		r15,vmmppcXr6(r5)			; Read vm context 
			ld		r24,vmmppcXr7(r5)				
			ld		r17,vmmppcXr8(r5)				
			ld		r18,vmmppcXr9(r5)		
			ld		r19,vmmppcXr10(r5)		
			ld		r20,vmmppcXr11(r5)				
			ld		r21,vmmppcXr12(r5)				
			ld		r22,vmmppcXr13(r5)				

			std		r7,vmmppcXr6(r5)				; Write context	
			std		r8,vmmppcXr7(r5)				
			std		r9,vmmppcXr8(r5)				
			std		r10,vmmppcXr9(r5)				
			std		r11,vmmppcXr10(r5)				
			std		r12,vmmppcXr11(r5)				
			std		r13,vmmppcXr12(r5)	
			la		r6,vmmppcXr22(r5)			; Point to fifth line			
			std		r14,vmmppcXr13(r5)				

			dcbt	0,r6						; Touch fifth line

sw64x2done:	std		r15,saver6(r30)			; Write vm context 
			std		r24,saver7(r30)				
			std		r17,saver8(r30)				
			std		r18,saver9(r30)		
			std		r19,saver10(r30)		
			std		r20,saver11(r30)				
			std		r21,saver12(r30)				
			std		r22,saver13(r30)				

;			Swap 8 registers
			
			ld		r7,saver14(r30)			; Read savearea	
			ld		r8,saver15(r30)				
			ld		r9,saver16(r30)				
			ld		r10,saver17(r30)				
			ld		r11,saver18(r30)				
			ld		r12,saver19(r30)				
			ld		r13,saver20(r30)				
			ld		r14,saver21(r30)				

			bt		vmmDoing64,sw64x3			; Skip to 64-bit stuff

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
			b		sw64x3done					; Done with this section...

sw64x3:		ld		r15,vmmppcXr14(r5)			; Read vm context 
			ld		r24,vmmppcXr15(r5)				
			ld		r17,vmmppcXr16(r5)				
			ld		r18,vmmppcXr17(r5)		
			ld		r19,vmmppcXr18(r5)		
			ld		r20,vmmppcXr19(r5)				
			ld		r21,vmmppcXr20(r5)				
			ld		r22,vmmppcXr21(r5)				

			std		r7,vmmppcXr14(r5)			; Write context	
			std		r8,vmmppcXr15(r5)				
			std		r9,vmmppcXr16(r5)				
			std		r10,vmmppcXr17(r5)				
			std		r11,vmmppcXr18(r5)				
			std		r12,vmmppcXr19(r5)				
			std		r13,vmmppcXr20(r5)
			la		r6,vmmppcXr30(r5)			; Point to sixth line				
			std		r14,vmmppcXr21(r5)				
			
			dcbt	0,r6						; Touch sixth line

sw64x3done:	std		r15,saver14(r30)			; Write vm context 
			std		r24,saver15(r30)				
			std		r17,saver16(r30)				
			std		r18,saver17(r30)		
			std		r19,saver18(r30)		
			std		r20,saver19(r30)				
			std		r21,saver20(r30)				
			std		r22,saver21(r30)				

;			Swap 8 registers
			
			ld		r7,saver22(r30)			; Read savearea	
			ld		r8,saver23(r30)				
			ld		r9,saver24(r30)				
			ld		r10,saver25(r30)				
			ld		r11,saver26(r30)				
			ld		r12,saver27(r30)				
			ld		r13,saver28(r30)				
			ld		r14,saver29(r30)				

			bt		vmmDoing64,sw64x4			; Skip to 64-bit stuff

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
			b		sw64x4done					; Done with this section...
			
sw64x4:		ld		r15,vmmppcXr22(r5)			; Read vm context 
			ld		r24,vmmppcXr23(r5)				
			ld		r17,vmmppcXr24(r5)				
			ld		r18,vmmppcXr25(r5)		
			ld		r19,vmmppcXr26(r5)		
			ld		r20,vmmppcXr27(r5)				
			ld		r21,vmmppcXr28(r5)				
			ld		r22,vmmppcXr29(r5)				

			std		r7,vmmppcXr22(r5)			; Write context	
			std		r8,vmmppcXr23(r5)				
			std		r9,vmmppcXr24(r5)				
			std		r10,vmmppcXr25(r5)				
			std		r11,vmmppcXr26(r5)				
			std		r12,vmmppcXr27(r5)				
			std		r13,vmmppcXr28(r5)	
			la		r6,vmmppcvscr(r5)			; Point to seventh line			
			std		r14,vmmppcXr29(r5)				

			dcbt	0,r6						; Touch seventh line

sw64x4done:	std		r15,saver22(r30)			; Write vm context 
			std		r24,saver23(r30)				
			std		r17,saver24(r30)				
			std		r18,saver25(r30)		
			std		r19,saver26(r30)		
			std		r20,saver27(r30)				
			std		r21,saver28(r30)				
			std		r22,saver29(r30)				

;			Swap 8 registers
			
			ld		r7,saver30(r30)			; Read savearea	
			ld		r8,saver31(r30)				
			lwz		r9,savecr(r30)				
			ld		r10,savexer(r30)				
			ld		r11,savelr(r30)				
			ld		r12,savectr(r30)				
			lwz		r14,savevrsave(r30)				

			bt		vmmDoing64,sw64x5			; Skip to 64-bit stuff

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
			b		sw64x5done					; Done here...		

sw64x5:		ld		r15,vmmppcXr30(r5)			; Read vm context 
			ld		r24,vmmppcXr31(r5)				
			lwz		r17,vmmppcXcr(r5)				
			ld		r18,vmmppcXxer(r5)		
			ld		r19,vmmppcXlr(r5)		
			ld		r20,vmmppcXctr(r5)				
			lwz		r22,vmmppcXvrsave(r5)				

			std		r7,vmmppcXr30(r5)			; Write context	
			std		r8,vmmppcXr31(r5)				
			stw		r9,vmmppcXcr(r5)				
			std		r10,vmmppcXxer(r5)				
			std		r11,vmmppcXlr(r5)				
			std		r12,vmmppcXctr(r5)				
			stw		r14,vmmppcXvrsave(r5)				

sw64x5done:	std		r15,saver30(r30)			; Write vm context 
			std		r24,saver31(r30)				
			stw		r17,savecr(r30)				
			std		r18,savexer(r30)		
			std		r19,savelr(r30)		
			std		r20,savectr(r30)				
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
			beq+	swapDSI64					; Yeah...
			cmplwi	r7,T_ALIGNMENT				; Alignment exception?
			beq+	cr1,swapISI64				; We had an ISI...
			cmplwi	cr1,r7,T_SYSTEM_CALL		; Exiting because of an system call?
			beq+	swapDSI64					; An alignment exception looks like a DSI...
			beq+	cr1,swapSC64				; We had a system call...
			
			blr									; Return...

;
;			Set exit returns for a DSI or alignment exception
;

swapDSI64:	ld		r10,savedar(r30)			; Get the DAR
			lwz		r7,savedsisr(r30)			; and the DSISR
			bt		vmmDoing64,sw64DSI			; Skip to 64-bit stuff...


			stw		r10,return_params+0(r5)		; Save DAR as first return parm
			stw		r7,return_params+4(r5)		; Save DSISR as second return parm
			blr									; Return...

sw64DSI:	std		r10,return_paramsX+0(r5)	; Save DAR as first return parm
			std		r7,return_paramsX+8(r5)		; Save DSISR as second return parm (note that this is expanded to 64 bits)
			blr									; Return...

;
;			Set exit returns for a ISI
;

swapISI64:	bt		vmmDoing64,sw64ISI			; Skip to 64-bit stuff...
			lwz		r7,vmmppcmsr(r5)			; Get the SRR1 value
			lwz		r10,vmmppcpc(r5)			; Get the PC as failing address
			rlwinm	r7,r7,0,1,4					; Save the bits that match the DSISR
			stw		r10,return_params+0(r5)		; Save PC as first return parm
			stw		r7,return_params+4(r5)		; Save the pseudo-DSISR as second return parm
			blr									; Return...

sw64ISI:	ld		r7,vmmppcXmsr(r5)			; Get the SRR1 value
			ld		r10,vmmppcXpc(r5)			; Get the PC as failing address
			rlwinm	r7,r7,0,1,4					; Save the bits that match the DSISR
			std		r10,return_paramsX+0(r5)		; Save PC as first return parm
			std		r7,return_paramsX+8(r5)		; Save the pseudo-DSISR as second return parm
			blr									; Return...

;
;			Set exit returns for a system call (note: we did the first 3 earlier)
;			Do we really need to pass parameters back here????
;

swapSC64:	bt		vmmDoing64,sw64SC			; Skip to 64-bit stuff...
			lwz		r10,vmmppcr6(r5)			; Get the fourth paramter
			stw		r10,return_params+12(r5)	; Save it
			blr									; Return...

sw64SC:		ld		r10,vmmppcXr6(r5)			; Get the fourth paramter
			std		r10,return_paramsX+24(r5)	; Save it
			blr									; Return...

;
;			vmmFamGuestResume:
;				Restore Guest context from Fam mode.
;

vmmFamGuestResume:
			mfsprg	r10,0							; Get the per_proc
			lwz		r27,vmmCEntry(r3)				; Get the context that is active
			lwz		r4,VMMXAFlgs(r10)				; Get the eXtended Architecture flags			
			rlwinm.	r4,r4,0,0,0						; Are we doing a 64-bit virtual machine?		
			lwz		r15,spcFlags(r10)				; Get per_proc special flags
			mr		r26,r3							; Save the activation pointer
			lwz		r20,vmmContextKern(r27)			; Get the comm area
			rlwinm	r15,r15,0,FamVMmodebit+1,FamVMmodebit-1	; Clear FamVMmodebit
			stw		r15,spcFlags(r10)				; Update the special flags
			bne		fgrX
			lwz		r7,famguestpc(r20)				; Load famguest ctx pc
			bf++	vmmMapDone,fgrNoMap				; No mapping done for this space.
			lwz		r3,SAVflags(r30)				; Pick up the savearea flags
			lwz		r2,vmmLastMap(r28)				; Get the last mapped address
			lwz		r6,vmmLastMap+4(r28)			; Get the last mapped address
			li		r4,T_DATA_ACCESS				; Change to DSI fault
			oris	r3,r3,hi16(SAVredrive)			; Set exception redrive
			stw		r2,savedar(r30)					; Set the DAR to the last thing we mapped
			stw		r6,savedar+4(r30)				; Set the DAR to the last thing we mapped
			stw		r3,SAVflags(r30)				; Turn on the redrive request
			lis		r2,hi16(MASK(DSISR_HASH))		; Set PTE/DBAT miss
			stw		r4,saveexception(r30)			; Say we need to emulate a DSI
			li		r0,0							; Clear
			stw		r2,savedsisr(r30)				; Pretend we have a PTE miss
			stb		r0,vmmGFlags+3(r28)				; Show that the redrive has been taken care of
fgrNoMap:
			lwz		r4,savesrr1+4(r30)				; Get the saved MSR value
			stw		r7,savesrr0+4(r30)				; Set savearea pc
			lwz		r5,famguestmsr(r20)				; Load famguest ctx msr
			lis		r6,hi16(MSR_IMPORT_BITS)		; Get the MSR bits that are controllable by user
			ori		r6,r6,lo16(MSR_IMPORT_BITS)		; Get the rest of the MSR bits that are controllable by user
			and		r5,r5,r6						; Keep only the controllable bits
			oris	r5,r5,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			ori		r5,r5,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			rlwimi	r5,r4,0,MSR_FP_BIT,MSR_FP_BIT	; Propagate guest FP
			rlwimi	r5,r4,0,MSR_VEC_BIT,MSR_VEC_BIT	; Propagate guest Vector	
			stw		r5,savesrr1+4(r30)				; Set savearea srr1
			lwz		r4,famguestr0(r20)				; Load famguest ctx r0
			lwz		r5,famguestr1(r20)				; Load famguest ctx r1
			lwz		r6,famguestr2(r20)				; Load famguest ctx r2
			lwz		r7,famguestr3(r20)				; Load famguest ctx r3
			stw		r4,saver0+4(r30)				; Set savearea r0
			stw		r5,saver1+4(r30)				; Set savearea r1
			stw		r6,saver2+4(r30)				; Set savearea r2
			stw		r7,saver3+4(r30)				; Set savearea r3
			lwz		r4,famguestr4(r20)				; Load famguest ctx r4
			lwz		r5,famguestr5(r20)				; Load famguest ctx r5
			lwz		r6,famguestr6(r20)				; Load famguest ctx r6
			lwz		r7,famguestr7(r20)				; Load famguest ctx r7
			stw		r4,saver4+4(r30)				; Set savearea r4
			stw		r5,saver5+4(r30)				; Set savearea r5
			stw		r6,saver6+4(r30)				; Set savearea r6
			stw		r7,saver7+4(r30)				; Set savearea r7
			b		fgrret
fgrX:
			ld		r7,famguestXpc(r20)				; Load famguest ctx pc
			bf++	vmmMapDone,fgrXNoMap			; No mapping done for this space.
			lwz		r3,SAVflags(r30)				; Pick up the savearea flags
			ld		r2,vmmLastMap(r28)				; Get the last mapped address
			li		r4,T_DATA_ACCESS				; Change to DSI fault
			oris	r3,r3,hi16(SAVredrive)			; Set exception redrive
			std		r2,savedar(r30)					; Set the DAR to the last thing we mapped
			stw		r3,SAVflags(r30)				; Turn on the redrive request
			lis		r2,hi16(MASK(DSISR_HASH))		; Set PTE/DBAT miss
			stw		r4,saveexception(r30)			; Say we need to emulate a DSI
			li		r0,0							; Clear
			stw		r2,savedsisr(r30)				; Pretend we have a PTE miss
			stb		r0,vmmGFlags+3(r28)				; Show that the redrive has been taken care of
fgrXNoMap:
			ld		r4,savesrr1(r30)				; Get the saved MSR value
			std		r7,savesrr0(r30)				; Set savearea pc
			ld		r5,famguestXmsr(r20)			; Load famguest ctx msr
			lis		r6,hi16(MSR_IMPORT_BITS)		; Get the MSR bits that are controllable by user
			ori		r6,r6,lo16(MSR_IMPORT_BITS)		; Get the rest of the MSR bits that are controllable by user
			and		r5,r5,r6						; Keep only the controllable bits
			oris	r5,r5,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			ori		r5,r5,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			rlwimi	r5,r4,0,MSR_FP_BIT,MSR_FP_BIT	; Propagate guest FP
			rlwimi	r5,r4,0,MSR_VEC_BIT,MSR_VEC_BIT	; Propagate guest Vector	
			std		r5,savesrr1(r30)				; Set savearea srr1
			ld		r4,famguestXr0(r20)				; Load famguest ctx r0
			ld		r5,famguestXr1(r20)				; Load famguest ctx r1
			ld		r6,famguestXr2(r20)				; Load famguest ctx r2
			ld		r7,famguestXr3(r20)				; Load famguest ctx r3
			std		r4,saver0(r30)					; Set savearea r0
			std		r5,saver1(r30)					; Set savearea r1
			std		r6,saver2(r30)					; Set savearea r2
			std		r7,saver3(r30)					; Set savearea r3
			ld		r4,famguestXr4(r20)				; Load famguest ctx r4
			ld		r5,famguestXr5(r20)				; Load famguest ctx r5
			ld		r6,famguestXr6(r20)				; Load famguest ctx r6
			ld		r7,famguestXr7(r20)				; Load famguest ctx r7
			std		r4,saver4(r30)					; Set savearea r4
			std		r5,saver5(r30)					; Set savearea r5
			std		r6,saver6(r30)					; Set savearea r6
			std		r7,saver7(r30)					; Set savearea r7
fgrret:
			li		r3,1							; Show normal exit with check for AST
			lwz		r16,ACT_THREAD(r26)				; Restore the thread pointer
			b		EXT(ppcscret)					; Go back to handler...

;
;			FAM Intercept exception handler
;

			.align	5
			.globl	EXT(vmm_fam_exc)

LEXT(vmm_fam_exc)
			lwz		r4,VMMXAFlgs(r2)				; Get the eXtended Architecture flags			
			lwz		r1,pfAvailable(r2)				; Get the CPU features flags
			rlwinm.	r4,r4,0,0,0						; Are we doing a 64-bit virtual machine?		
			bne		fexcX
			lwz		r4,saver4+4(r13)				; Load savearea r4
			cmplwi	r11,T_ALIGNMENT					; Alignment exception?
			lwz		r3,VMMareaPhys(r2)				; Load phys state page addr
			mtcrf   0x02,r1							; Move pf64Bit to its normal place in CR6
			cmplwi	cr1,r11,T_PROGRAM				; Exiting because of an PRG?
            bt++    pf64Bitb,fexcVMareaPhys64		; Go do this on a 64-bit machine...
			slwi	r3,r3,12						; Change ppnum to physical address
			b		fexcVMareaPhysres
fexcVMareaPhys64:
			mtxer	r5								; Restore xer
			lwz		r5,saver5+4(r13)				; Load savearea r5
			lwz		r6,saver6+4(r13)				; Load savearea r6
			sldi	r3,r3,12						; Change ppnum to physical address
fexcVMareaPhysres:
			stw		r4,famguestr4(r3)				; Save r4 in famguest ctx
			stw		r5,famguestr5(r3)				; Save r5 in famguest ctx
			stw		r6,famguestr6(r3)				; Save r6 in famguest ctx
			stw		r7,famguestr7(r3)				; Save r7 in famguest ctx
			lwz		r4,saver0+4(r13)				; Load savearea r0
			lwz		r5,saver1+4(r13)				; Load savearea r1
			lwz		r6,saver2+4(r13)				; Load savearea r2
			lwz		r7,saver3+4(r13)				; Load savearea r3
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
			beq+	cr1,fexcPRG						; We had a program exception...
			bne+	fexcret	
													; We had an Alignment...
			mfdar	r3								; Load dar
			mfdsisr	r4								; Load dsisr
			stw		r3,famparam+0x4(r6)				; Set famparam 1 with dar
			stw		r4,famparam+0x8(r6)				; Set famparam 2 with dsir
			b		fexcret							;
fexcPRG:
			stw		r4,famparam+0x4(r6)				; Set famparam 1 with srr1
			mr		r3,r4							; Set r3 with dsisr
			lwz		r4,famguestr4(r6)				; Load r4 from famguest context
fexcret:
			lwz		r5,famguestr5(r6)				; Load r5 from famguest context
			lwz		r13,famhandler(r6)				; Load user address to resume
			stw		r2,famparam(r6)					; Set famparam 0 with srr0
			stw		r7,famdispcode(r6)				; Save the exit code
			lwz		r1,famrefcon(r6)				; load refcon
            bt++    pf64Bitb,fexcrfi64				; Go do this on a 64-bit machine...
			mtcr	r0								; Restore cr
			mtsrr0	r13								; Load srr0
			mr		r0,r7							; Set dispatch code
			lwz		r7,famguestr7(r6)				; Load r7 from famguest context
			lwz		r6,famguestr6(r6)				; Load r6 from famguest context
			mfsprg	r13,2							; Restore r13
			mfsprg  r11,3							; Restore r11
			rfi
fexcrfi64:
			mtcr	r0								; Restore cr
			mtsrr0	r13								; Load srr0
			mr		r0,r7							; Set dispatch code
			lwz		r7,famguestr7(r6)				; Load r7 from famguest context
			lwz		r6,famguestr6(r6)				; Load r6 from famguest context
			mfsprg	r13,2							; Restore r13
			mfsprg  r11,3							; Restore r11
			rfid
fexcX:
			mtxer	r5								; Restore xer
			ld		r4,saver4(r13)					; Load savearea r4
			ld		r5,saver5(r13)					; Load savearea r5
			ld		r6,saver6(r13)					; Load savearea r6
			cmplwi	r11,T_ALIGNMENT					; Alignment exception?
			lwz		r3,VMMareaPhys(r2)				; Load phys state page addr
			mtcrf   0x02,r1							; Move pf64Bit to its normal place in CR6
			cmplwi	cr1,r11,T_PROGRAM				; Exiting because of an PRG?
			sldi	r3,r3,12						; Change ppnum to physical address
			std		r4,famguestXr4(r3)				; Save r4 in famguest ctx
			std		r5,famguestXr5(r3)				; Save r5 in famguest ctx
			std		r6,famguestXr6(r3)				; Save r6 in famguest ctx
			std		r7,famguestXr7(r3)				; Save r7 in famguest ctx
			ld		r4,saver0(r13)					; Load savearea r0
			ld		r5,saver1(r13)					; Load savearea r1
			ld		r6,saver2(r13)					; Load savearea r2
			ld		r7,saver3(r13)					; Load savearea r3
			std		r4,famguestXr0(r3)				; Save r0 in famguest ctx
			std		r5,famguestXr1(r3)				; Save r1 in famguest ctx
			std		r6,famguestXr2(r3)				; Save r2 in famguest ctx
			std		r7,famguestXr3(r3)				; Save r3 in famguest ctx
			lwz		r4,spcFlags(r2)					; Load per_proc spcFlags
			oris	r4,r4,hi16(FamVMmode)			; Set FAM mode
			stw		r4,spcFlags(r2)					; Update per_proc spcFlags
			mfsrr0  r2								; Get the interrupt srr0
			mfsrr1  r4								; Get the interrupt srr1
			std		r2,famguestXpc(r3)				; Save srr0 in famguest ctx
			std		r4,famguestXmsr(r3)				; Save srr1 in famguest ctx
			li		r6,lo16(MASK(MSR_FE0)|MASK(MSR_SE)|MASK(MSR_BE)|MASK(MSR_FE1))
			andc	r6,r4,r6						; Clear SE BE FE0 FE1
			mtsrr1	r6								; Set srr1
			mr		r6,r3							; Set r6 with  phys state page addr
			rlwinm	r7,r11,30,24,31					; Convert exception to return code
			beq+	cr1,fexcXPRG					; We had a program exception...
			bne+	fexcXret	
													; We had an Alignment...
			mfdar	r3								; Load dar
			mfdsisr	r4								; Load dsisr
			std		r3,famparamX+0x8(r6)			; Set famparam 1 with dar
			std		r4,famparamX+0x10(r6)			; Set famparam 2 with dsir
			b		fexcXret
fexcXPRG:
			std		r4,famparamX+0x8(r6)			; Set famparam 1 with srr1
			mr		r3,r4							; Set r3 with dsisr
			ld		r4,famguestXr4(r6)				; Load r4 from famguest context
fexcXret:
			ld		r5,famguestXr5(r6)				; Load r5 from famguest context
			ld		r13,famhandlerX(r6)				; Load user address to resume
			std		r2,famparamX(r6)				; Set famparam 0 with srr0
			std		r7,famdispcodeX(r6)				; Save the exit code
			ld		r1,famrefconX(r6)				; load refcon
			mtcr	r0								; Restore cr
			mtsrr0	r13								; Load srr0
			mr		r0,r7							; Set dispatch code
			ld		r7,famguestXr7(r6)				; Load r7 from famguest context
			ld		r6,famguestXr6(r6)				; Load r6 from famguest context
			mfsprg	r13,2							; Restore r13
			mfsprg  r11,3							; Restore r11
			rfid

;
;			FAM Intercept DSI ISI fault handler
;

			.align	5
			.globl	EXT(vmm_fam_pf)

LEXT(vmm_fam_pf)
			lwz		r4,VMMXAFlgs(r2)				; Get the eXtended Architecture flags			
			lwz		r3,VMMareaPhys(r2)				; Load phys state page addr
			rlwinm.	r4,r4,0,0,0						; Are we doing a 64-bit virtual machine?		
			bne		fpfX
			lwz		r4,saver0+4(r13)				; Load savearea r0
			lwz		r5,saver1+4(r13)				; Load savearea r1
			lwz		r6,saver2+4(r13)				; Load savearea r2
			lwz		r7,saver3+4(r13)				; Load savearea r3
            bt++    pf64Bitb,fpfVMareaPhys64		; Go do this on a 64-bit machine...
			slwi	r3,r3,12						; Change ppnum to physical address
			b		fpfVMareaPhysret
fpfVMareaPhys64:
			sldi	r3,r3,12						; Change ppnum to physical address
fpfVMareaPhysret:
			stw		r4,famguestr0(r3)				; Save r0 in famguest
			stw		r5,famguestr1(r3)				; Save r1 in famguest
			stw		r6,famguestr2(r3)				; Save r2 in famguest
			stw		r7,famguestr3(r3)				; Save r3 in famguest
			lwz		r4,saver4+4(r13)				; Load savearea r0
			lwz		r5,saver5+4(r13)				; Load savearea r1
			lwz		r6,saver6+4(r13)				; Load savearea r2
			lwz		r7,saver7+4(r13)				; Load savearea r3
			stw		r4,famguestr4(r3)				; Save r4 in famguest
			lwz		r4,spcFlags(r2)					; Load spcFlags
			stw		r5,famguestr5(r3)				; Save r5 in famguest
			lwz		r5,savesrr0+4(r13)				; Get the interrupt srr0
			stw		r6,famguestr6(r3)				; Save r6 in famguest
			lwz		r6,savesrr1+4(r13)				; Load srr1
			oris	r4,r4,hi16(FamVMmode)			; Set FAM mode
			stw		r7,famguestr7(r3)				; Save r7 in famguest
			stw		r4,spcFlags(r2)					; Update spcFlags
			lwz		r1,famrefcon(r3)				; Load refcon
			lwz		r2,famhandler(r3)				; Load famhandler to resume
			stw		r5,famguestpc(r3)				; Save srr0
			stw		r5,saver2+4(r13)				; Store srr0 in savearea r2
			stw		r5,famparam(r3)					; Store srr0 in fam param 0
			stw		r6,famguestmsr(r3)				; Save srr1 in famguestmsr
			cmplwi	cr1,r11,T_INSTRUCTION_ACCESS	; Was this a ISI?
			rlwinm	r7,r11,30,24,31					; Convert exception to return code
			beq+	cr1,fpfISI						; We had an ISI...
; fpfDSI
			lwz		r6,savedar+4(r13)				; Load dar from savearea
			lwz		r4,savedsisr(r13)				; Load dsisr from savearea
			stw		r6,famparam+0x4(r3)				; Store dar in fam param 1
			stw		r6,saver3+4(r13)				; Store dar in savearea r3
			stw		r4,famparam+0x8(r3)				; Store dsisr in fam param 2
			stw		r4,saver4+4(r13)				; Store dsisr in savearea r4
			b		fpfret
fpfISI:	
			rlwinm	r6,r6,0,1,4						; Save the bits that match the DSISR
			stw		r6,famparam+0x4(r3)				; Store srr1 in fam param 1 
			stw		r6,saver3+4(r13)				; Store srr1 in savearea r3
fpfret:
			stw		r7,saver0+4(r13)				; Set dispatch code
			stw		r7,famdispcode(r3)				; Set dispatch code
			stw		r1,saver1+4(r13)				; Store refcon in savearea r1
			stw		r2,savesrr0+4(r13)				; Store famhandler in srr0
			blr
fpfX:
			ld		r4,saver0(r13)					; Load savearea r0
			ld		r5,saver1(r13)					; Load savearea r1
			ld		r6,saver2(r13)					; Load savearea r2
			ld		r7,saver3(r13)					; Load savearea r3
			sldi	r3,r3,12						; Change ppnum to physical address
			std		r4,famguestXr0(r3)				; Save r0 in famguest
			std		r5,famguestXr1(r3)				; Save r1 in famguest
			std		r6,famguestXr2(r3)				; Save r2 in famguest
			std		r7,famguestXr3(r3)				; Save r3 in famguest
			ld		r4,saver4(r13)					; Load savearea r0
			ld		r5,saver5(r13)					; Load savearea r1
			ld		r6,saver6(r13)					; Load savearea r2
			ld		r7,saver7(r13)					; Load savearea r3
			std		r4,famguestXr4(r3)				; Save r4 in famguest
			lwz		r4,spcFlags(r2)					; Load spcFlags
			std		r5,famguestXr5(r3)				; Save r5 in famguest
			ld		r5,savesrr0(r13)				; Get the interrupt srr0
			std		r6,famguestXr6(r3)				; Save r6 in famguest
			ld		r6,savesrr1(r13)				; Load srr1
			oris	r4,r4,hi16(FamVMmode)			; Set FAM mode
			std		r7,famguestXr7(r3)				; Save r7 in famguest
			stw		r4,spcFlags(r2)					; Update spcFlags
			ld		r1,famrefconX(r3)				; Load refcon
			ld		r2,famhandlerX(r3)				; Load famhandler to resume
			std		r5,famguestXpc(r3)				; Save srr0
			std		r5,saver2(r13)					; Store srr0 in savearea r2
			std		r5,famparamX(r3)				; Store srr0 in fam param 0
			std		r6,famguestXmsr(r3)				; Save srr1 in famguestmsr
			cmplwi	cr1,r11,T_INSTRUCTION_ACCESS	; Was this a ISI?
			rlwinm	r7,r11,30,24,31					; Convert exception to return code
			beq+	cr1,fpfXISI						; We had an ISI...
; fpfXDSI
			ld		r6,savedar(r13)					; Load dar from savearea
			lwz		r4,savedsisr(r13)				; Load dsisr from savearea
			std		r6,famparamX+0x8(r3)			; Store dar in fam param 1
			std		r6,saver3(r13)					; Store dar in savearea r3
			std		r4,famparamX+0x10(r3)				; Store dsisr in fam param 2
			std		r4,saver4(r13)					; Store dsisr in savearea r4
			b		fpfXret
fpfXISI:	
			rlwinm	r6,r6,0,1,4						; Save the bits that match the DSISR
			std		r6,famparamX+0x8(r3)			; Store srr1 in fam param 1 
			std		r6,saver3(r13)					; Store srr1 in savearea r3
fpfXret:
			std		r7,saver0(r13)					; Set dispatch code
			std		r7,famdispcodeX(r3)				; Set dispatch code
			std		r1,saver1(r13)					; Store refcon in savearea r1
			std		r2,savesrr0(r13)				; Store famhandler in srr0
			blr

;
;			Ultra Fast Path FAM syscalls
;

			.align	5
			.globl	EXT(vmm_ufp)

LEXT(vmm_ufp)
			mfsprg	r3,0							; Get the per_proc area
			mr		r11,r13							; Saved cr in r11
			lwz		r13,VMMXAFlgs(r3)				; Get the eXtended Architecture flags			
			rlwinm.	r13,r13,0,0,0						; Are we doing a 64-bit virtual machine?		
			lwz		r13,pfAvailable(r3)				; Get feature flags
			mtcrf	0x02,r13						; Put pf64Bitb etc in cr6
			lwz		r13,VMMareaPhys(r3)				; Load fast assist area
            bt++    pf64Bitb,ufpVMareaPhys64		; Go do this on a 64-bit machine...
			slwi	r13,r13,12						; Change ppnum to physical address
			b		ufpVMareaPhysret
ufpVMareaPhys64:
			sldi	r13,r13,12						; Change ppnum to physical address
ufpVMareaPhysret:
			bne		ufpX
			bt		cr5_eq,ufpResumeGuest			; if kvmmResumeGuest, branch to ResumeGuest
			cmpwi	cr7,r4,0						; Compare first arg with 0
			cmpwi	cr5,r4,7						; Compare first arg with 7
			cror	cr1_eq,cr7_lt,cr5_gt			; Is it in 0 to 7 range
			beq		cr1,ufpVMret					; Return if not in the range
			slwi	r4,r4,2							; multiply index by 4
			la		r3,famguestr0(r13)				; Load the base address
			bt		cr2_eq,ufpSetGuestReg			; Set/get selector
; ufpGetGuestReg
			lwzx	r3,r4,r3						; Load the guest register
			b		ufpVMret						; Return
ufpSetGuestReg:
			stwx	r5,r4,r3						; Update the guest register
			li		r3,0							; Set return value
			b		ufpVMret						; Return
ufpResumeGuest:
			lwz		r7,spcFlags(r3)					; Pick up the special flags
			mtsrr0	r4								; Set srr0
			rlwinm.	r6,r6,0,vmmKeyb,vmmKeyb			; Check vmmKeyb in maskCntrl
			rlwinm	r7,r7,0,FamVMmodebit+1,FamVMmodebit-1	; Clear FamVMmodebit
			stw		r7,spcFlags(r3)					; Update the special flags
			mfsrr1	r6								; Get the current MSR value

			lwz		r4,famguestmsr(r13)				; Load guest srr1
			lis		r1,hi16(MSR_IMPORT_BITS)		; Get the MSR bits that are controllable by user
			ori		r1,r1,lo16(MSR_IMPORT_BITS)		; Get the rest of the MSR bits that are controllable by user
			and		r4,r4,r1						; Keep only the controllable bits
			oris	r4,r4,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			ori		r4,r4,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			rlwimi	r4,r6,0,MSR_FP_BIT,MSR_FP_BIT	; Propagate guest FP
			rlwimi	r4,r6,0,MSR_VEC_BIT,MSR_VEC_BIT	; Propagate guest Vector	
			beq		ufpnokey						; Branch if not key switch
			mr		r2,r7							; Save r7
			rlwimi	r7,r5,32+vmmKeyb-userProtKeybit,userProtKeybit,userProtKeybit	; Set the protection key
			cmpw	cr0,r7,r2						; Is userProtKeybit changed?						
			beq		ufpnokey						; No, go to ResumeGuest_nokey
			mr		r5,r3							; Get the per_proc area
			stw		r7,spcFlags(r3)					; Update the special flags

            bt++    pf64Bitb,ufpsave64			; Go do this on a 64-bit machine...

			lwz		r3,next_savearea+4(r5)			; Get the exception save area
			stw		r8,saver8+4(r3)					; Save r8
			stw		r9,saver9+4(r3)					; Save r9
			stw		r10,saver10+4(r3)				; Save r10
			stw		r11,saver11+4(r3)				; Save r11
			stw		r12,saver12+4(r3)				; Save r12
			stw		r13,saver13+4(r3)				; Save r12
			stw		r14,saver14+4(r3)				; Save r14
			stw		r15,saver15+4(r3)				; Save r15
			stw		r16,saver16+4(r3)				; Save r16
			stw		r17,saver17+4(r3)				; Save r17
			stw		r18,saver18+4(r3)				; Save r18
			stw		r19,saver19+4(r3)				; Save r19
			stw		r20,saver20+4(r3)				; Save r20
			stw		r21,saver21+4(r3)				; Save r21
			stw		r22,saver22+4(r3)				; Save r22
			stw		r23,saver23+4(r3)				; Save r23
			stw		r24,saver24+4(r3)				; Save r24
			stw		r25,saver25+4(r3)				; Save r25
			stw		r26,saver26+4(r3)				; Save r26
			stw		r27,saver27+4(r3)				; Save r27
			stw		r28,saver28+4(r3)				; Save r28
			stw		r29,saver29+4(r3)				; Save r29
			stw		r30,saver30+4(r3)				; Save r30
			stw		r31,saver31+4(r3)				; Save r31
			b		ufpsaveres						; Continue

ufpsave64:
			ld		r3,next_savearea(r5)			; Get the exception save area
			std		r8,saver8(r3)					; Save r8
			std		r9,saver9(r3)					; Save r9
			std		r10,saver10(r3)					; Save r10
			std		r11,saver11(r3)					; Save r11
			std		r12,saver12(r3)					; Save r12
			std		r13,saver13(r3)					; Save r12
			std		r14,saver14(r3)					; Save r14
			std		r15,saver15(r3)					; Save r15
			std		r16,saver16(r3)					; Save r16
			std		r17,saver17(r3)					; Save r17
			std		r18,saver18(r3)					; Save r18
			std		r19,saver19(r3)					; Save r19
			std		r20,saver20(r3)					; Save r20
			std		r21,saver21(r3)					; Save r21
			std		r22,saver22(r3)					; Save r22
			std		r23,saver23(r3)					; Save r23
			std		r24,saver24(r3)					; Save r24
			std		r25,saver25(r3)					; Save r25
			std		r26,saver26(r3)					; Save r26
			std		r27,saver27(r3)					; Save r27
			std		r28,saver28(r3)					; Save r28
			std		r29,saver29(r3)					; Save r29
			mfxer	r2								; Get xer
			std		r30,saver30(r3)					; Save r30
			std		r31,saver31(r3)					; Save r31
			std		r2,savexer(r3)					; Save xer

ufpsaveres:
			mflr	r20								; Get lr
			li		r2,1							; Set to  1
			stw		r7,spcFlags(r5)					; Update the special flags
			mr		r13,r3							; Set current savearea
			mr		r21,r4							; Save r4
			sth		r2,ppInvSeg(r5)					; Force a reload of the SRs
			mr		r29,r5							; Get the per_proc area
			mr		r3,r4							; Set MSR value we going to
			bl		EXT(switchSegs)					; Go handle the segment registers/STB
			mr		r3,r13							; Set current savearea
			mr		r4,r21							; Restore r4
			mtlr	r20								; Set lr

            bt++    pf64Bitb,ufprestore64			; Go do this on a 64-bit machine...
			lwz		r8,saver8+4(r3)					; Load r8
			lwz		r9,saver9+4(r3)					; Load r9
			lwz		r10,saver10+4(r3)				; Load r10
			lwz		r11,saver11+4(r3)				; Load r11
			lwz		r12,saver12+4(r3)				; Load r12
			lwz		r13,saver13+4(r3)				; Load r12
			lwz		r14,saver14+4(r3)				; Load r14
			lwz		r15,saver15+4(r3)				; Load r15
			lwz		r16,saver16+4(r3)				; Load r16
			lwz		r17,saver17+4(r3)				; Load r17
			lwz		r18,saver18+4(r3)				; Load r18
			lwz		r19,saver19+4(r3)				; Load r19
			lwz		r20,saver20+4(r3)				; Load r20
			lwz		r21,saver21+4(r3)				; Load r21
			lwz		r22,saver22+4(r3)				; Load r22
			lwz		r23,saver23+4(r3)				; Load r23
			lwz		r24,saver24+4(r3)				; Load r24
			lwz		r25,saver25+4(r3)				; Load r25
			lwz		r26,saver26+4(r3)				; Load r26
			lwz		r27,saver27+4(r3)				; Load r27
			lwz		r28,saver28+4(r3)				; Load r28
			lwz		r29,saver29+4(r3)				; Load r29
			lwz		r30,saver30+4(r3)				; Load r30
			lwz		r31,saver31+4(r3)				; Load r31
			b		ufpnokey						; Continue
ufprestore64:
			ld		r2,savexer(r3)					; Load xer
			ld		r8,saver8(r3)					; Load r8
			ld		r9,saver9(r3)					; Load r9
			ld		r10,saver10(r3)					; Load r10
			mtxer	r2								; Restore xer
			ld		r11,saver11(r3)					; Load r11
			ld		r12,saver12(r3)					; Load r12
			ld		r13,saver13(r3)					; Load r12
			ld		r14,saver14(r3)					; Load r14
			ld		r15,saver15(r3)					; Load r15
			ld		r16,saver16(r3)					; Load r16
			ld		r17,saver17(r3)					; Load r17
			ld		r18,saver18(r3)					; Load r18
			ld		r19,saver19(r3)					; Load r19
			ld		r20,saver20(r3)					; Load r20
			ld		r21,saver21(r3)					; Load r21
			ld		r22,saver22(r3)					; Load r22
			ld		r23,saver23(r3)					; Load r23
			ld		r24,saver24(r3)					; Load r24
			ld		r25,saver25(r3)					; Load r25
			ld		r26,saver26(r3)					; Load r26
			ld		r27,saver27(r3)					; Load r27
			ld		r28,saver28(r3)					; Load r28
			ld		r29,saver29(r3)					; Load r29
			ld		r30,saver30(r3)					; Load r30
			ld		r31,saver31(r3)					; Load r31
ufpnokey:
			mfsprg	r3,0							; Get the per_proc area
			mtsrr1	r4								; Set srr1
			lwz		r0,famguestr0(r13)				; Load r0 
			lwz		r1,famguestr1(r13)				; Load r1
			lwz		r2,famguestr2(r13)				; Load r2
			lwz		r3,famguestr3(r13)				; Load r3
			lwz		r4,famguestr4(r13)				; Load r4
			lwz		r5,famguestr5(r13)				; Load r5
			lwz		r6,famguestr6(r13)				; Load r6
			lwz		r7,famguestr7(r13)				; Load r7
ufpVMret:
			mfsprg	r13,2							; Restore R13
            bt++    pf64Bitb,ufpVMrfi64				; Go do this on a 64-bit machine...
			mtcrf	0xFF,r11						; Restore CR
			mfsprg	r11,3							; Restore R11
			rfi										; All done, go back...
ufpVMrfi64:
			mtcrf	0xFF,r11						; Restore CR
			mfsprg	r11,3							; Restore R11
			rfid

ufpX:
			bt		cr5_eq,ufpXResumeGuest			; if kvmmResumeGuest, branch to ResumeGuest
			cmpwi	cr7,r4,0						; Compare first arg with 0
			cmpwi	cr5,r4,7						; Compare first arg with 7
			cror	cr1_eq,cr7_lt,cr5_gt			; Is it in 0 to 7 range
			beq		cr1,ufpXVMret					; Return if not in the range
			slwi	r4,r4,3							; multiply index by 8
			la		r3,famguestXr0(r13)				; Load the base address
			bt		cr2_eq,ufpXSetGuestReg			; Set/get selector
; ufpXGetGuestReg
			ldx	r3,r4,r3							; Load the guest register
			b			ufpXVMret					; Return
ufpXSetGuestReg:
			stdx	r5,r4,r3						; Update the guest register
			li		r3,0							; Set return value
			b		ufpXVMret						; Return
ufpXResumeGuest:
			lwz		r7,spcFlags(r3)					; Pick up the special flags
			mtsrr0	r4								; Set srr0
			rlwinm.	r6,r6,0,vmmKeyb,vmmKeyb			; Check vmmKeyb in maskCntrl
			rlwinm	r7,r7,0,FamVMmodebit+1,FamVMmodebit-1	; Clear FamVMmodebit
			stw		r7,spcFlags(r3)					; Update the special flags
			mfsrr1	r6								; Get the current MSR value

			ld		r4,famguestXmsr(r13)			; Load guest srr1
			lis		r1,hi16(MSR_IMPORT_BITS)		; Get the MSR bits that are controllable by user
			ori		r1,r1,lo16(MSR_IMPORT_BITS)		; Get the rest of the MSR bits that are controllable by user
			and		r4,r4,r1						; Keep only the controllable bits
			oris	r4,r4,hi16(MSR_EXPORT_MASK_SET)	; Force on the required bits
			ori		r4,r4,lo16(MSR_EXPORT_MASK_SET)	; Force on the other required bits
			rlwimi	r4,r6,0,MSR_FP_BIT,MSR_FP_BIT	; Propagate guest FP
			rlwimi	r4,r6,0,MSR_VEC_BIT,MSR_VEC_BIT	; Propagate guest Vector	
			beq		ufpXnokey						; Branch if not key switch
			mr		r2,r7							; Save r7
			rlwimi	r7,r5,32+vmmKeyb-userProtKeybit,userProtKeybit,userProtKeybit	; Set the protection key
			cmpw	cr0,r7,r2						; Is userProtKeybit changed?						
			beq		ufpXnokey						; No, go to ResumeGuest_nokey
			mr		r5,r3							; Get the per_proc area
			stw		r7,spcFlags(r3)					; Update the special flags

			ld		r3,next_savearea(r5)			; Get the exception save area
			std		r8,saver8(r3)					; Save r8
			std		r9,saver9(r3)					; Save r9
			std		r10,saver10(r3)					; Save r10
			std		r11,saver11(r3)					; Save r11
			std		r12,saver12(r3)					; Save r12
			std		r13,saver13(r3)					; Save r12
			std		r14,saver14(r3)					; Save r14
			std		r15,saver15(r3)					; Save r15
			std		r16,saver16(r3)					; Save r16
			std		r17,saver17(r3)					; Save r17
			std		r18,saver18(r3)					; Save r18
			std		r19,saver19(r3)					; Save r19
			std		r20,saver20(r3)					; Save r20
			std		r21,saver21(r3)					; Save r21
			std		r22,saver22(r3)					; Save r22
			std		r23,saver23(r3)					; Save r23
			std		r24,saver24(r3)					; Save r24
			std		r25,saver25(r3)					; Save r25
			std		r26,saver26(r3)					; Save r26
			std		r27,saver27(r3)					; Save r27
			std		r28,saver28(r3)					; Save r28
			std		r29,saver29(r3)					; Save r29
			mfxer	r2								; Get xer
			std		r30,saver30(r3)					; Save r30
			std		r31,saver31(r3)					; Save r31
			std		r2,savexer(r3)					; Save xer

			mflr	r20								; Get lr
			li		r2,1							; Set to  1
			stw		r7,spcFlags(r5)					; Update the special flags
			mr		r13,r3							; Set current savearea
			mr		r21,r4							; Save r4
			sth		r2,ppInvSeg(r5)					; Force a reload of the SRs
			mr		r29,r5							; Get the per_proc area
			mr		r3,r4							; Set MSR value we going to
			bl		EXT(switchSegs)					; Go handle the segment registers/STB
			mr		r3,r13							; Set current savearea
			mr		r4,r21							; Restore r4
			mtlr	r20								; Set lr

			ld		r2,savexer(r3)					; Load xer
			ld		r8,saver8(r3)					; Load r8
			ld		r9,saver9(r3)					; Load r9
			ld		r10,saver10(r3)					; Load r10
			mtxer	r2								; Restore xer
			ld		r11,saver11(r3)					; Load r11
			ld		r12,saver12(r3)					; Load r12
			ld		r13,saver13(r3)					; Load r12
			ld		r14,saver14(r3)					; Load r14
			ld		r15,saver15(r3)					; Load r15
			ld		r16,saver16(r3)					; Load r16
			ld		r17,saver17(r3)					; Load r17
			ld		r18,saver18(r3)					; Load r18
			ld		r19,saver19(r3)					; Load r19
			ld		r20,saver20(r3)					; Load r20
			ld		r21,saver21(r3)					; Load r21
			ld		r22,saver22(r3)					; Load r22
			ld		r23,saver23(r3)					; Load r23
			ld		r24,saver24(r3)					; Load r24
			ld		r25,saver25(r3)					; Load r25
			ld		r26,saver26(r3)					; Load r26
			ld		r27,saver27(r3)					; Load r27
			ld		r28,saver28(r3)					; Load r28
			ld		r29,saver29(r3)					; Load r29
			ld		r30,saver30(r3)					; Load r30
			ld		r31,saver31(r3)					; Load r31
ufpXnokey:
			mtsrr1	r4								; Set srr1
			ld		r0,famguestXr0(r13)				; Load r0 
			ld		r1,famguestXr1(r13)				; Load r1
			ld		r2,famguestXr2(r13)				; Load r2
			ld		r3,famguestXr3(r13)				; Load r3
			ld		r4,famguestXr4(r13)				; Load r4
			ld		r5,famguestXr5(r13)				; Load r5
			ld		r6,famguestXr6(r13)				; Load r6
			ld		r7,famguestXr7(r13)				; Load r7
ufpXVMret:
			mfsprg	r13,2							; Restore R13
			mtcrf	0xFF,r11						; Restore CR
			mfsprg	r11,3							; Restore R11
			rfid

