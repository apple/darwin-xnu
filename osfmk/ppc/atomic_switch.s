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
#include	<ppc/asm.h>
#include	<ppc/proc_reg.h>
#include	<ppc/exception.h>
#include	<mach/ppc/vm_param.h>
#include	<assym.s>

/*
 *	Classic atomic switch and fast trap code
 *	Written by: Mark Gorlinsky
 */

/*
**
** Blue Box Fast Trap entry
**
**
** The registers at entry are as hw_exceptions left them. Which means
** that the Blue Box data area is pointed to be R26.
**
** We exit here through the fast path exit point in hw_exceptions.  That means that
** upon exit, R4 must not change.  It is the savearea with the current user context
** to restore.
**
** Input registers are:
** r0  = Syscall number
** r4  = Current context savearea (do not modify)
** r13 = THREAD_TOP_ACT pointer
** r26 = base of ACT_MACH_BDA in kernel address space
** -- for Traps --
** r24 = Index into TWI table (x4)
**
**
*/


ENTRY(atomic_switch_syscall, TAG_NO_FRAME_USED)
	
/*
 *			Note: the BlueBox fast path system calls (-1 and -2) we handled as
 *			an ultra-fast trap in lowmem_vectors.
 */
			li		r5, BTTD_SYSCALL_VECTOR
			b		.L_CallPseudoKernel

ENTRY(atomic_switch_trap, TAG_NO_FRAME_USED)

/*
** functions 0-15 -> Call PseudoKernel
**             16 -> Exit PseudoKernel
*/

			cmplwi	cr7,r24,BB_RFI_TRAP					; Is this an RFI?
			beq		cr7,.L_ExitPseudoKernel				; Yes...

			li		r5, BTTD_TRAP_VECTOR

/******************************************************************************
 * void CallPseudoKernel ( int vector, thread_act_t * act, BEDA_t * beda, savearea *sv )
 *
 * This op provides a means of invoking the BlueBox PseudoKernel from a
 * system (68k) or native (PPC) context while changing BlueBox interruption
 * state atomically.  As an added bonus, this op leaves all but R1/PC of the user 
 * state registers intact.  R1/PC are saved in a per thread save area, the base of
 * which is located in the bbDescAddr member of the thread_act structure.
 *
 * This op is invoked from the Emulator Trap dispatch table or from a System
 * Call when Mach SCs have been disabled. A vectorindex is passed in to indicate
 * which vector should be taken.
 *
 * If this op is invoked from the Emulator Trap dispatch table, the kernel is
 * aware of starting address of this table.  It used the users PC (SRR0) 
 * and the start of the Trap dispatch table address to verify the trap exception 
 * as a atomic_switch trap.  If a trap exception is verified as a atomic_switch
 * trap we enter here with the following registers loaded.
 *
 * Input registers are:
 * r5	= Vector to take
 * r13 	= Current thread context data
 * r26	= Base address of BlueBox exception data area in kernel address space
 * r4	= Current context savearea (do not modify)
 *
 ******************************************************************************/

.L_CallPseudoKernel:

			mfsprg	r2,0								; Get the per_proc
			rlwinm	r6,r26,0,0,19						; Start of page is bttd
			lwz		r7,ACT_MACT_SPF(r13)				; Get special flags 
			lwz		r1,BTTD_INTERRUPT_VECTOR(r6)		; Get interrupt vector
			rlwinm	r7,r7,0,bbNoMachSCbit+1,bbNoMachSCbit-1	
														; Reactivate Mach SCs
			lwz		r8,BTTD_INTCONTROLWORD(r6)			; Get Interrupt Control Word
			cmpwi	r1,0								; Is this a preemptive thread ?
			stw		r7,ACT_MACT_SPF(r13)				; Update special flags
			stw		r7,spcFlags(r2)						; Update per_proc version
			beq		.L_CallFromPreemptiveThread			; No int vector means preemptive thread

			rlwinm	r1,r8,0,INTSTATEMASK_B,INTSTATEMASK_E
														; Extract current Interrupt state
			rlwinm	r8,r8,0,INTSTATEMASK_E+1,INTSTATEMASK_B-1
														; Clear current interrupt state
			xoris	r2,r1,SYSCONTEXTSTATE				; Setup for System Context check 
			lwz		r1,savecr(r4)						; Load current CR bits
			cmpwi	r2,0								; Check if state is System Context?
			oris	r8,r8,PSEUDOKERNELSTATE				; Update state for entering the PK
			bne		.L_CallFromAlternateContext			; No, then do not save CR2 bits

			rlwimi	r8,r1,32-INTCR2TOBACKUPSHIFT,INTBACKUPCR2MASK_B,INTBACKUPCR2MASK_E
														; Insert live CR2 in ICW BackupCR2
.L_CallFromAlternateContext:

			stw		r8,BTTD_INTCONTROLWORD(r6)			; Update ICW

.L_CallFromPreemptiveThread:

			lwz		r1,savesrr0(r4)						; Get current PC
			lwz		r2,saver1(r4)						; Get current R1
			lwz		r3,savesrr1(r4)						; Get current MSR
			stw		r1,BEDA_SRR0(r26)					; Save current PC
			rlwinm	r3,r3,0,MSR_BE_BIT+1,MSR_SE_BIT-1				
														; Clear SE|BE bits in MSR
			stw		r2,BEDA_SPRG1(r26)					; Save current R1 
			stw		r3,savesrr1(r4)						; Load new MSR

			lwz		r1,BEDA_SPRG0(r26)					; Get replacement R1
			lwzx	r2,r5,r6							; Load vector address
			stw		r3,BEDA_SRR1(r26)					; Update saved MSR
			stw		r1,saver1(r4)						; Load up new R1
			stw		r2,savesrr0(r4)						; Save vector as PC

			b		EXT(fastexit)						; Go back and take the fast path exit...

/******************************************************************************
 * void ExitPseudoKernel ( thread_act_t * act, BEDA_t * beda, savearea * sv  )
 *
 * This op provides a means of exiting from the BlueBox PseudoKernel to a
 * user context.  This op attempts to simulate an RFI for the returning
 * Traps (atomic_switch_trap) and SysCalls (atomic_switch_syscall).  Only the
 * Blue Thread handling interrupts is allowed to atomically change
 * interruption state and handle pending interrupts.
 *
 * If an interrupt is pending and we are returning to the alternate context,
 * the exit is aborted and we return to an pending interrupt handler in the
 * Blue Box pseudokernel.  
 *
 * It also allows the MSR's FE0, FE1, BE and SE bits to updated for the user
 * and completes the PPC register loading.
 *
 * Input registers are:
 * r4  = Current context savearea (do not modify)
 * r13 = Pointer to the current active thread's data
 * r26 = Base address of BlueBox Data in kernel address space 
 *
 ******************************************************************************/

.L_ExitPseudoKernel:

			rlwinm	r6,r26,0,0,19						; Start of page is bttd
			lwz		r7,ACT_MACT_SPF(r13)				; Get special flags
			lwz		r2,BTTD_INTERRUPT_VECTOR(r6)		; Get the interrupt vector
			lwz		r1,BEDA_SPRG1(r26)					; Get saved CTR
			ori		r7,r7,(0x8000 >> (bbNoMachSCbit - 16))	; Disable Mach SCs for Blue Box

			cmpwi	r2,0								; Is this a preemptive thread
			stw		r1,savectr(r4)						; Update CTR
			beq		.L_ExitFromPreemptiveThread

			lwz		r8,BTTD_INTCONTROLWORD(r6)			; Get ICW
			lwz		r1,BTTD_NEWEXITSTATE(r6)			; New interrupt state
			lwz		r2,BTTD_TESTINTMASK(r6)				; Get pending interrupt mask
			lis		r3,SYSCONTEXTSTATE					; Setup for check in system context
			rlwimi	r8,r1,0,INTSTATEMASK_B,INTSTATEMASK_E
														; Insert new state
			cmplw	cr1,r1,r3							; System context ?
			and.	r2,r8,r2							; Any pending interrupt?
			lwz		r1,savecr(r4)						; Get current CR
			
			beq		cr1,.L_ExitToSystemContext			; We are in system context
			beq		.L_ExitUpdateRuptControlWord		; We do not have a pending interrupt

			lwz		r2,saver1(r4)						; Get current R1
			lwz		r1,BEDA_SPRG0(r26)					; Get replacement R1
			stw		r2,BEDA_SPRG1(r26)					; Save current R1
			stw		r1,saver1(r4)						; Load up new R1
			lwz		r3,BTTD_PENDINGINT_VECTOR(r6)		; Get pending interrupt PC
			b		.L_ExitAbortExit					; Abort and Exit

.L_ExitToSystemContext:
			rlwimi	r1,r8,INTCR2TOBACKUPSHIFT,INTCR2MASK_B,INTCR2MASK_E
														; Insert live CR2 into backup CR2
.L_ExitUpdateRuptControlWord:
			stw		r8,BTTD_INTCONTROLWORD(r6)			; Update ICW
			stw		r1,savecr(r4)						; Update CR

.L_ExitFromPreemptiveThread:
			mfsprg	r3,0								; Get the per_proc
			lwz		r2,savesrr1(r4)						; Get current MSR	
			lwz		r1,BEDA_SRR1(r26)					; Get new MSR
			stw		r7,ACT_MACT_SPF(r13)				; Update special flags
			stw		r7,spcFlags(r3)						; Update per_proc version
			rlwimi	r2,r1,0,MSR_FE0_BIT,MSR_FE1_BIT
														; Insert FE0,FE1,SE,BE bits
			lwz		r3,BEDA_SRR0(r26)					; Get new PC
			stw		r2,savesrr1(r4)						; Update MSR

.L_ExitAbortExit:
			stw		r3,savesrr0(r4)						; Update PC

			b		EXT(fastexit)						; Go back and take the fast path exit...

