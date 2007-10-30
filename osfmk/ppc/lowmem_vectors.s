/*
 * Copyright (c) 2000-2007 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#include <assym.s>
#include <debug.h>
#include <db_machine_commands.h>
	
#include <mach_debug.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/Performance.h>
#include <ppc/savearea.h>
#include <mach/ppc/vm_param.h>

#define ESPDEBUG 0
#define INSTRUMENT 0

#define featAltivec 29
#define wasNapping 30

#define	VECTOR_SEGMENT	.section __VECTORS, __interrupts

			VECTOR_SEGMENT

			.globl	EXT(lowGlo)
EXT(lowGlo):

			.globl	EXT(ExceptionVectorsStart)

EXT(ExceptionVectorsStart):							/* Used if relocating the exception vectors */
baseR:												/* Used so we have more readable code */

;
;			Handle system reset.
;			We do not ever expect a hard reset so we do not actually check.
;			When we come here, we check for a RESET_HANDLER_START (which means we are
;			waking up from sleep), a RESET_HANDLER_BUPOR (which is using for bring up
;			when starting directly from a POR), and RESET_HANDLER_IGNORE (which means
;			ignore the interrupt).
;
;			Some machines (so far, 32-bit guys) will always ignore a non-START interrupt.
;			The ones who do take it, check if the interrupt is too be ignored.  This is 
;			always the case until the previous reset is handled (i.e., we have exited
;			from the debugger).
;
			. = 0xf0
			.globl	EXT(ResetHandler)
EXT(ResetHandler):
			.long	0x0
			.long	0x0
			.long	0x0

			. = 0x100
.L_handler100:
			mtsprg	2,r13			/* Save R13 */
			mtsprg	3,r11			/* Save R11 */
			lwz		r13,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_TYPE)(br0)	; Get reset type
			mfcr	r11
			cmpi	cr0,r13,RESET_HANDLER_START
			bne		resetexc

			li		r11,RESET_HANDLER_NULL
			stw		r11,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_TYPE)(br0)	; Clear reset type

			lwz		r4,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_CALL)(br0)
			lwz		r3,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_ARG)(br0)
			mtlr	r4
			blr

resetexc:	cmplwi	r13,RESET_HANDLER_BUPOR			; Special bring up POR sequence?
			bne		resetexc2						; No...
			lis		r4,hi16(EXT(resetPOR))			; Get POR code
			ori		r4,r4,lo16(EXT(resetPOR))		; The rest
			mtlr	r4								; Set it
			blr										; Jump to it....

resetexc2:	cmplwi	cr1,r13,RESET_HANDLER_IGNORE	; Are we ignoring these? (Software debounce)

			mfsprg	r13,0							; Get per_proc
			lwz		r13,pfAvailable(r13)			; Get the features
			rlwinm.	r13,r13,0,pf64Bitb,pf64Bitb		; Is this a 64-bit machine?
			cror	cr1_eq,cr0_eq,cr1_eq			; See if we want to take this
			bne--	cr1,rxCont						; Yes, continue...
			bne--	rxIg64							; 64-bit path...

			mtcr	r11								; Restore the CR
			mfsprg	r13,2							; Restore R13
			mfsprg	r11,0							; Get per_proc
			lwz		r11,pfAvailable(r11)			; Get the features
			mtsprg	2,r11							; Restore sprg2
			mfsprg	r11,3							; Restore R11
			rfi										; Return and ignore the reset

rxIg64:		mtcr	r11								; Restore the CR
			mfsprg	r11,0							; Get per_proc
			mtspr	hsprg0,r14						; Save a register
			ld		r14,UAW(r11)					; Get the User Assist DoubleWord
			mfsprg	r13,2							; Restore R13
			lwz		r11,pfAvailable(r11)			; Get the features
			mtsprg	2,r11							; Restore sprg2
			mfsprg	r11,3							; Restore R11
			mtsprg	3,r14							; Set the UAW in sprg3
			mfspr	r14,hsprg0						; Restore R14
			rfid									; Return and ignore the reset

rxCont:		mtcr	r11
			li		r11,RESET_HANDLER_IGNORE		; Get set to ignore
			stw		r11,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_TYPE)(br0)	; Start ignoring these
			mfsprg	r13,1							/* Get the exception save area */
			li		r11,T_RESET						/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Machine check 
 */

			. = 0x200
.L_handler200:
			mtsprg	2,r13							; Save R13 
			mtsprg	3,r11							; Save R11

			.globl	EXT(extPatchMCK)
LEXT(extPatchMCK)									; This is patched to a nop for 64-bit 
			b		h200aaa							; Skip 64-bit code... 

;
;			Fall through here for 970 MCKs.
;

			li		r11,1							; ?
			sldi	r11,r11,32+3					; ?
			mfspr	r13,hid4						; ?
			or		r11,r11,r13						; ?
			sync
			mtspr	hid4,r11						; ?
			isync
			li		r11,1							; ?
			sldi	r11,r11,32+8					; ?
			andc	r13,r13,r11						; ?
			lis		r11,0xE000						; Get the unlikeliest ESID possible
			sync
			mtspr	hid4,r13						; ?
			isync									; ?
			
			srdi	r11,r11,1						; ?
			slbie	r11								; ?
			sync
			isync
		
			li		r11,T_MACHINE_CHECK				; Set rupt code
			b		.L_exception_entry				; Join common...

;
;			Preliminary checking of other MCKs
;

h200aaa:	mfsrr1	r11								; Get the SRR1
			mfcr	r13								; Save the CR
			
			rlwinm.	r11,r11,0,dcmck,dcmck			; ?
			beq+	notDCache						; ?
			
			sync
			mfspr	r11,msscr0						; ?
			dssall									; ?
			sync
			isync

			oris	r11,r11,hi16(dl1hwfm)			; ?
			mtspr	msscr0,r11						; ?
			
rstbsy:		mfspr	r11,msscr0						; ?
			
			rlwinm.	r11,r11,0,dl1hwf,dl1hwf			; ?
			bne		rstbsy							; ?
			
			sync									; ?

			mfsprg	r11,0							; Get the per_proc
			mtcrf	255,r13							; Restore CRs
			lwz		r13,hwMachineChecks(r11)		; Get old count
			addi	r13,r13,1						; Count this one
			stw		r13,hwMachineChecks(r11)		; Set new count
			lwz		r11,pfAvailable(r11)			; Get the feature flags
			mfsprg	r13,2							; Restore R13
			mtsprg	2,r11							; Set the feature flags
			mfsprg	r11,3							; Restore R11
			rfi										; Return

notDCache:	mtcrf	255,r13							; Restore CRs
			li		r11,T_MACHINE_CHECK				; Set rupt code
			b		.L_exception_entry				; Join common...


/*
 * 			Data access - page fault, invalid memory rights for operation
 */

			. = 0x300
.L_handler300:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_DATA_ACCESS				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 * 			Data segment
 */

			. = 0x380
.L_handler380:
			mtsprg	2,r13							; Save R13
			mtsprg	3,r11							; Save R11
			li		r11,T_DATA_SEGMENT				; Set rupt code
			b		.L_exception_entry				; Join common...

/*
 * 			Instruction access - as for data access
 */

			. = 0x400
.L_handler400:
			mtsprg	2,r13							; Save R13
			mtsprg	3,r11							; Save R11
			li		r11,T_INSTRUCTION_ACCESS		; Set rupt code
			b		.L_exception_entry				; Join common...

/*
 * 			Instruction segment
 */

			. = 0x480
.L_handler480:
			mtsprg	2,r13							; Save R13 
			mtsprg	3,r11							; Save R11 
			li		r11,T_INSTRUCTION_SEGMENT		; Set rupt code
			b		.L_exception_entry				; Join common... 

/*
 * 			External interrupt
 */

			. = 0x500
.L_handler500:
			mtsprg	2,r13							; Save R13 
			mtsprg	3,r11							; Save R11
			li		r11,T_INTERRUPT					; Set rupt code
			b		.L_exception_entry				; Join common...

/*
 * 			Alignment - many reasons
 */

			. = 0x600
.L_handler600:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_ALIGNMENT|T_FAM			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Program - floating point exception, illegal inst, priv inst, user trap
 */

			. = 0x700
.L_handler700:
			mtsprg	2,r13							; Save R13
			mtsprg	3,r11							; Save R11			
			li		r11,T_PROGRAM|T_FAM				; Set program interruption code
			b		.L_exception_entry				; Join common...

/*
 * 			Floating point disabled
 */

			. = 0x800
.L_handler800:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_FP_UNAVAILABLE			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 * 			Decrementer - DEC register has passed zero.
 */

			. = 0x900
.L_handler900:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_DECREMENTER				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			I/O controller interface error - MACH does not use this
 */

			. = 0xA00
.L_handlerA00:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_IO_ERROR					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			Reserved
 */

			. = 0xB00
.L_handlerB00:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_RESERVED					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


;           System Calls (sc instruction)
;
;           The syscall number is in r0.  All we do here is munge the number into an
;           8-bit index into the "scTable", and dispatch on it to handle the Ultra
;           Fast Traps (UFTs.)  The index is:
;
;               0x80 - set if syscall number is 0x80000000 (CutTrace)
;               0x40 - set if syscall number is 0x00006004
;               0x20 - set if upper 29 bits of syscall number are 0xFFFFFFF8
;               0x10 - set if upper 29 bits of syscall number are 0x00007FF0
;               0x0E - low three bits of syscall number
;               0x01 - zero, as scTable is an array of shorts

			. = 0xC00
.L_handlerC00:
			mtsprg	3,r11							; Save R11
			mtsprg	2,r13							; Save R13
			rlwinm	r11,r0,0,0xFFFFFFF8				; mask off low 3 bits of syscall number
			xori	r13,r11,0x7FF0					; start to check for the 0x7FFx traps
			addi	r11,r11,8						; make a 0 iff this is a 0xFFFFFFF8 trap
			cntlzw	r13,r13							; set bit 0x20 iff a 0x7FFx trap
			cntlzw	r11,r11							; set bit 0x20 iff a 0xFFFFFFF8 trap
			xoris	r0,r0,0x8000					; Flip bit to make 0 iff 0x80000000
			rlwimi	r11,r13,31,0x10					; move 0x7FFx bit into position
			cntlzw	r13,r0							; Set bit 0x20 iff 0x80000000
			xoris	r0,r0,0x8000					; Flip bit to restore R0
			rlwimi	r11,r13,2,0x80					; Set bit 0x80 iff CutTrace
			xori	r13,r0,0x6004					; start to check for 0x6004
			rlwimi	r11,r0,1,0xE					; move in low 3 bits of syscall number
			cntlzw	r13,r13							; set bit 0x20 iff 0x6004
			rlwinm	r11,r11,0,0,30					; clear out bit 31
			rlwimi	r11,r13,1,0x40					; move 0x6004 bit into position
			lhz		r11,lo16(scTable)(r11)			; get branch address from sc table
			mfctr	r13								; save callers ctr in r13
			mtctr	r11								; set up branch to syscall handler
			mfsprg	r11,0							; get per_proc, which most UFTs use
			bctr									; dispatch (r11 in sprg3, r13 in sprg2, ctr in r13, per_proc in r11)

/*
 * 			Trace - generated by single stepping
 *				performance monitor BE branch enable tracing/logging
 *				is also done here now.  while this is permanently in the
 *				system the impact is completely unnoticable as this code is
 *				only executed when (a) a single step or branch exception is
 *				hit, (b) in the single step debugger case there is so much
 *				overhead already the few extra instructions for testing for BE
 *				are not even noticable
 *
 *			Note that this trace is available only to user state so we do not 
 *			need to set sprg2 before returning.
 */

			. = 0xD00
.L_handlerD00:
			mtsprg	3,r11							; Save R11
			mfsprg	r11,2							; Get the feature flags
			mtsprg	2,r13							; Save R13

			li		r11,T_TRACE|T_FAM				; Set interrupt code
			b		.L_exception_entry				; Join common...

/*
 * 			Floating point assist
 */

			. = 0xE00
.L_handlerE00:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_FP_ASSIST					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 *			Performance monitor interruption
 */

 			. = 0xF00
PMIhandler:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_PERF_MON					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */
	

/*
 *			VMX exception
 */

 			. = 0xF20
VMXhandler:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_VMX						/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

	

;
;			Instruction translation miss exception - not supported
;

 			. = 0x1000
.L_handler1000:
			mtsprg	2,r13							; Save R13
			mtsprg	3,r11							; Save R11
			li		r11,T_INVALID_EXCP0				; Set rupt code
			b		.L_exception_entry				; Join common...

	

;
;			Data load translation miss exception - not supported
;

 			. = 0x1100
.L_handler1100:
			mtsprg	2,r13							; Save R13
			mtsprg	3,r11							; Save R11
			li		r11,T_INVALID_EXCP1				; Set rupt code
			b		.L_exception_entry				; Join common...

	

;
;			Data store translation miss exception - not supported
;

 			. = 0x1200
.L_handler1200:
			mtsprg	2,r13							; Save R13
			mtsprg	3,r11							; Save R11
			li		r11,T_INVALID_EXCP2				; Set rupt code
			b		.L_exception_entry				; Join common...

	
/*
 * 			Instruction address breakpoint
 */

			. = 0x1300
.L_handler1300:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_INSTRUCTION_BKPT			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * 			System management interrupt
 */

			. = 0x1400
.L_handler1400:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_SYSTEM_MANAGEMENT			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


/*
 * 			Soft Patch
 */

			. = 0x1500
.L_handler1500:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_SOFT_PATCH				/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

;
; 			Altivec Java Mode Assist interrupt or Maintenace interrupt
;

			. = 0x1600
.L_handler1600:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_ALTIVEC_ASSIST			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

;
; 			Altivec Java Mode Assist interrupt or Thermal interruption 
;

			. = 0x1700
.L_handler1700:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_THERMAL					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

;
; 			Thermal interruption - 64-bit
;

			. = 0x1800
.L_handler1800:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_ARCHDEP0					/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */

/*
 * There is now a large gap of reserved traps
 */

/*
 * 			Instrumentation interruption
 */

			. = 0x2000
.L_handler2000:
			mtsprg	2,r13							/* Save R13 */
			mtsprg	3,r11							/* Save R11 */
			li		r11,T_INSTRUMENTATION			/* Set 'rupt code */
			b		.L_exception_entry				/* Join common... */


	
			.data
			.align	ALIGN
			.globl	EXT(exception_entry)
EXT(exception_entry):
			.long	.L_exception_entry-EXT(ExceptionVectorsStart) /* phys addr of fn */
				
			VECTOR_SEGMENT

/*<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
 *
 * First-level syscall dispatch.  The syscall vector maps r0 (the syscall number) into an
 * index into the "scTable" (below), and then branches to one of these routines.  The PPC
 * syscalls come in several varieties, as follows:
 *
 * 1. If (syscall & 0xFFFFF000) == 0x00007000, then it is a PPC Fast Trap or UFT.
 *    The UFTs are dispatched here, the Fast Traps are dispatched in hw_exceptions.s.
 *
 * 2. If (syscall & 0xFFFFF000) == 0x00006000, then it is a PPC-only trap.
 *    One of these (0x6004) is a UFT, but most are dispatched in hw_exceptions.s.  These
 *    are mostly Blue Box or VMM (Virtual Machine) calls.
 *
 * 3. If (syscall & 0xFFFFFFF0) == 0xFFFFFFF0, then it is also a UFT and is dispatched here.
 *
 * 4. If (syscall & 0xFFFFF000) == 0x80000000, then it is a "firmware" call and is dispatched in
 *    Firmware.s, though the special "Cut Trace" trap (0x80000000) is handled here as an ultra
 *    fast trap.
 *
 * 5. If (syscall & 0xFFFFF000) == 0xFFFFF000, and it is not one of the above, then it is a Mach
 *    syscall, which are dispatched in hw_exceptions.s via "mach_trap_table".
 *
 * 6. If (syscall & 0xFFFFF000) == 0x00000000, then it is a BSD syscall, which are dispatched
 *    by "unix_syscall" using the "sysent" table.
 *
 * What distinguishes the UFTs, aside from being ultra fast, is that they cannot rely on translation
 * being on, and so cannot look at the activation or task control block, etc.  We handle them right
 * here, and return to the caller without turning interrupts or translation on.  The UFTs are:
 *
 *      0xFFFFFFFF - BlueBox only - MKIsPreemptiveTask
 *      0xFFFFFFFE - BlueBox only - MKIsPreemptiveTaskEnv
 *      0x00007FF2 - User state only - thread info (32-bit mode)
 *      0x00007FF3 - User state only - floating point / vector facility status
 *      0x00007FF4 - Kernel only - loadMSR - not used on 64-bit machines
 *      0x00006004 - vmm_dispatch (only some of which are UFTs)
 *
 * "scTable" is an array of 2-byte addresses, accessed using a 7-bit index derived from the syscall
 * number as follows:
 *
 *      0x80 (A) - set if syscall number is 0x80000000
 *      0x40 (B) - set if syscall number is 0x00006004
 *      0x20 (C) - set if upper 29 bits of syscall number are 0xFFFFFFF8
 *      0x10 (D) - set if upper 29 bits of syscall number are 0x00007FF0
 *      0x0E (E) - low three bits of syscall number
 *
 * If you define another UFT, try to use a number in one of the currently decoded ranges, ie one marked
 * "unassigned" below.  The dispatch table and the UFT handlers must reside in the first 32KB of
 * physical memory.
 */
 
            .align  8                               ; start this table on a 256-byte boundry
scTable:                                            ; ABCD E
			.short	uftNormalSyscall-baseR			; 0000 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0000 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0000 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0000 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0000 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0000 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0000 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0000 7  these syscalls are not in a reserved range

			.short	uftNormalSyscall-baseR			; 0001 0  0x7FF0 is unassigned
			.short	uftNormalSyscall-baseR			; 0001 1  0x7FF1 is Set Thread Info Fast Trap (pass up)
			.short	uftThreadInfo-baseR				; 0001 2  0x7FF2 is Thread Info
			.short	uftFacilityStatus-baseR			; 0001 3  0x7FF3 is Facility Status
			.short	uftLoadMSR-baseR				; 0001 4  0x7FF4 is Load MSR
			.short	uftNormalSyscall-baseR			; 0001 5  0x7FF5 is the Null FastPath Trap (pass up)
			.short	uftNormalSyscall-baseR			; 0001 6  0x7FF6 is unassigned
			.short	uftNormalSyscall-baseR			; 0001 7  0x7FF7 is unassigned

			.short	uftNormalSyscall-baseR			; 0010 0  0xFFFFFFF0 is unassigned
			.short	uftNormalSyscall-baseR			; 0010 1  0xFFFFFFF1 is unassigned
			.short	uftNormalSyscall-baseR			; 0010 2  0xFFFFFFF2 is unassigned
			.short	uftNormalSyscall-baseR			; 0010 3  0xFFFFFFF3 is unassigned
			.short	uftNormalSyscall-baseR			; 0010 4  0xFFFFFFF4 is unassigned
			.short	uftNormalSyscall-baseR			; 0010 5  0xFFFFFFF5 is unassigned
			.short	uftIsPreemptiveTaskEnv-baseR	; 0010 6  0xFFFFFFFE is Blue Box uftIsPreemptiveTaskEnv
			.short	uftIsPreemptiveTask-baseR		; 0010 7  0xFFFFFFFF is Blue Box IsPreemptiveTask

			.short	WhoaBaby-baseR					; 0011 0  impossible combination
			.short	WhoaBaby-baseR					; 0011 1  impossible combination
			.short	WhoaBaby-baseR					; 0011 2  impossible combination
			.short	WhoaBaby-baseR					; 0011 3  impossible combination
			.short	WhoaBaby-baseR					; 0011 4  impossible combination
			.short	WhoaBaby-baseR					; 0011 5  impossible combination
			.short	WhoaBaby-baseR					; 0011 6  impossible combination
			.short	WhoaBaby-baseR					; 0011 7  impossible combination

			.short	WhoaBaby-baseR					; 0100 0  0x6000 is an impossible index (diagCall)
			.short	WhoaBaby-baseR					; 0100 1  0x6001 is an impossible index (vmm_get_version)
			.short	WhoaBaby-baseR					; 0100 2  0x6002 is an impossible index (vmm_get_features)
			.short	WhoaBaby-baseR					; 0100 3  0x6003 is an impossible index (vmm_init_context)
			.short	uftVMM-baseR					; 0100 4  0x6004 is vmm_dispatch (only some of which are UFTs)
			.short	WhoaBaby-baseR					; 0100 5  0x6005 is an impossible index (bb_enable_bluebox)
			.short	WhoaBaby-baseR					; 0100 6  0x6006 is an impossible index (bb_disable_bluebox)
			.short	WhoaBaby-baseR					; 0100 7  0x6007 is an impossible index (bb_settaskenv)

			.short	uftNormalSyscall-baseR			; 0101 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0101 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0101 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0101 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0101 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0101 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0101 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0101 7  these syscalls are not in a reserved range
			
			.short	uftNormalSyscall-baseR			; 0110 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0110 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0110 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0110 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0110 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0110 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0110 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0110 7  these syscalls are not in a reserved range
			
			.short	uftNormalSyscall-baseR			; 0111 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0111 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0111 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0111 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0111 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0111 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0111 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 0111 7  these syscalls are not in a reserved range

			.short	uftCutTrace-baseR				; 1000 0  CutTrace
			.short	uftNormalSyscall-baseR			; 1000 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1000 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1000 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1000 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1000 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1000 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1000 7  these syscalls are not in a reserved range

			.short	uftNormalSyscall-baseR			; 1001 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1001 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1001 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1001 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1001 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1001 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1001 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1001 7  these syscalls are not in a reserved range

			.short	uftNormalSyscall-baseR			; 1010 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1010 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1010 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1010 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1010 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1010 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1010 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1010 7  these syscalls are not in a reserved range

			.short	uftNormalSyscall-baseR			; 1011 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1011 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1011 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1011 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1011 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1011 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1011 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1011 7  these syscalls are not in a reserved range

			.short	uftNormalSyscall-baseR			; 1100 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1100 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1100 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1100 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1100 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1100 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1100 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1100 7  these syscalls are not in a reserved range
			
			.short	uftNormalSyscall-baseR			; 1101 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1101 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1101 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1101 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1101 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1101 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1101 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1101 7  these syscalls are not in a reserved range
			
			.short	uftNormalSyscall-baseR			; 1110 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1110 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1110 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1110 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1110 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1110 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1110 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1110 7  these syscalls are not in a reserved range
			
			.short	uftNormalSyscall-baseR			; 1111 0  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1111 1  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1111 2  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1111 3  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1111 4  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1111 5  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1111 6  these syscalls are not in a reserved range
			.short	uftNormalSyscall-baseR			; 1111 7  these syscalls are not in a reserved range

            .align  2                               ; prepare for code


/* Ultra Fast Trap (UFT) Handlers:
 *
 * We get here directly from the hw syscall vector via the "scTable" vector (above), 
 * with interrupts and VM off, in 64-bit mode if supported, and with all registers live
 * except the following:
 *
 *        r11 = per_proc ptr (ie, sprg0)
 *        r13 = holds caller's ctr register
 *      sprg2 = holds caller's r13
 *      sprg3 = holds caller's r11
 */

;			Handle "vmm_dispatch" (0x6004), of which only some selectors are UFTs.

uftVMM:
			mtctr	r13								; restore callers ctr
			lwz		r11,spcFlags(r11)				; get the special flags word from per_proc
			mfcr	r13								; save callers entire cr (we use all fields below)
			rlwinm	r11,r11,16,16,31				; Extract spcFlags upper bits
			andi.	r11,r11,hi16(runningVM|FamVMena|FamVMmode)
			cmpwi	cr0,r11,hi16(runningVM|FamVMena|FamVMmode)	; Test in VM FAM
			bne--	uftNormal80						; not eligible for FAM UFTs
			cmpwi	cr5,r3,kvmmResumeGuest			; Compare r3 with kvmmResumeGuest
			cmpwi	cr2,r3,kvmmSetGuestRegister		; Compare r3 with kvmmSetGuestRegister
			cror	cr1_eq,cr5_lt,cr2_gt			; Set true if out of VMM Fast syscall range
			bt--	cr1_eq,uftNormalFF				; Exit if out of range (the others are not UFTs)
			b		EXT(vmm_ufp)					; handle UFT range of vmm_dispatch syscall

			
;			Handle blue box UFTs (syscalls -1 and -2).

uftIsPreemptiveTask:
uftIsPreemptiveTaskEnv:
			mtctr	r13								; restore callers ctr
			lwz		r11,spcFlags(r11)				; get the special flags word from per_proc
			mfcr	r13,0x80						; save callers cr0 so we can use it
			andi.	r11,r11,bbNoMachSC|bbPreemptive ; Clear what we do not need
			cmplwi	r11,bbNoMachSC					; See if we are trapping syscalls
			blt--	uftNormal80						; No...
			cmpwi	r0,-2							; is this call IsPreemptiveTaskEnv?
			rlwimi	r13,r11,bbPreemptivebit-cr0_eq,cr0_eq,cr0_eq	; Copy preemptive task flag into user cr0_eq
			mfsprg	r11,0							; Get the per proc once more
			bne++	uftRestoreThenRFI				; do not load r0 if IsPreemptiveTask
			lwz		r0,ppbbTaskEnv(r11)				; Get the shadowed taskEnv (only difference)
			b		uftRestoreThenRFI				; restore modified cr0 and return


;			Handle "Thread Info" UFT (0x7FF2)

			.globl	EXT(uft_uaw_nop_if_32bit)
uftThreadInfo:
			lwz		r3,UAW+4(r11)					; get user assist word, assuming a 32-bit processor
LEXT(uft_uaw_nop_if_32bit)
			ld		r3,UAW(r11)						; get the whole doubleword if 64-bit (patched to nop if 32-bit)
			mtctr	r13								; restore callers ctr
			b		uftRFI							; done


;			Handle "Facility Status" UFT (0x7FF3)

uftFacilityStatus:
			lwz		r3,spcFlags(r11)				; get "special flags" word from per_proc
			mtctr	r13								; restore callers ctr
			b		uftRFI							; done


;			Handle "Load MSR" UFT (0x7FF4).	 This is not used on 64-bit processors, though it would work.

uftLoadMSR:
			mfsrr1	r11								; get callers MSR
			mtctr	r13								; restore callers ctr
			mfcr	r13,0x80						; save callers cr0 so we can test PR
			rlwinm. r11,r11,0,MSR_PR_BIT,MSR_PR_BIT ; really in the kernel?
			bne-	uftNormal80						; do not permit from user mode
			mfsprg	r11,0							; restore per_proc
			mtsrr1	r3								; Set new MSR


;			Return to caller after UFT.	 When called:
;				r11 = per_proc ptr
;				r13 = callers cr0 in upper nibble (if uftRestoreThenRFI called)
;				sprg2 = callers r13
;				sprg3 = callers r11

uftRestoreThenRFI:									; WARNING: can drop down to here
			mtcrf	0x80,r13						; restore callers cr0
uftRFI:
			.globl	EXT(uft_nop_if_32bit)
LEXT(uft_nop_if_32bit)
			b		uftX64							; patched to NOP if 32-bit processor
			
uftX32:		lwz		r11,pfAvailable(r11)			; Get the feature flags
			mfsprg	r13,2							; Restore R13
			mtsprg	2,r11							; Set the feature flags
			mfsprg	r11,3							; Restore R11
			rfi										; Back to our guy...
			
uftX64:		mtspr	hsprg0,r14						; Save a register in a Hypervisor SPRG
			ld		r14,UAW(r11)					; Get the User Assist DoubleWord
			lwz		r11,pfAvailable(r11)			; Get the feature flags
			mfsprg	r13,2							; Restore R13
			mtsprg	2,r11							; Set the feature flags
			mfsprg	r11,3							; Restore R11
			mtsprg	3,r14							; Set the UAW in sprg3
			mfspr	r14,hsprg0						; Restore R14
			rfid									; Back to our guy...

;
;			Quickly cut a trace table entry for the CutTrace firmware call.
;
;			All registers except R11 and R13 are unchanged.
;
;			Note that this code cuts a trace table entry for the CutTrace call only.
;			An identical entry is made during normal interrupt processing.  Any entry
;			format entry changes made must be done in both places.
;

			.align	5
			
			.globl	EXT(uft_cuttrace)
LEXT(uft_cuttrace)
uftCutTrace:
			b		uftct64							; patched to NOP if 32-bit processor

			stw		r20,tempr0(r11)					; Save some work registers
			lwz		r20,dgFlags(0)					; Get the flags
			stw		r21,tempr1(r11)					; Save some work registers
			mfsrr1	r21								; Get the SRR1
			rlwinm	r20,r20,MSR_PR_BIT-enaUsrFCallb,MASK(MSR_PR)	; Shift the validity bit over to pr bit spot
			stw		r25,tempr2(r11)					; Save some work registers
			orc		r20,r20,r21						; Get ~PR | FC
			mfcr	r25								; Save the CR
			stw		r22,tempr3(r11)					; Save some work registers
			lhz		r22,PP_CPU_NUMBER(r11)			; Get the logical processor number
			andi.	r20,r20,MASK(MSR_PR)			; Set cr0_eq is we are in problem state and the validity bit is not set
			stw		r23,tempr4(r11)					; Save some work registers
			lwz		r23,traceMask(0)				; Get the trace mask
			stw		r24,tempr5(r11)					; Save some work registers
			beq-	ctbail32						; Can not issue from user...
			

			addi	r24,r22,16						; Get shift to move cpu mask to syscall mask
			rlwnm	r24,r23,r24,12,12				; Shift cpu mask bit to rupt type mask
			and.	r24,r24,r23						; See if both are on

;
;			We select a trace entry using a compare and swap on the next entry field.
;			Since we do not lock the actual trace buffer, there is a potential that
;			another processor could wrap an trash our entry.  Who cares?
;

			li		r23,trcWork						; Get the trace work area address
			lwz		r21,traceStart(0)				; Get the start of trace table
			lwz		r22,traceEnd(0)					; Get end of trace table
			
			beq--	ctdisa32						; Leave because tracing is disabled...					

ctgte32:	lwarx	r20,0,r23						; Get and reserve the next slot to allocate
			addi	r24,r20,LTR_size				; Point to the next trace entry
			cmplw	r24,r22							; Do we need to wrap the trace table?
			bne+	ctgte32s						; No wrap, we got us a trace entry...
			
			mr		r24,r21							; Wrap back to start

ctgte32s:	stwcx.	r24,0,r23						; Try to update the current pointer
			bne-	ctgte32							; Collision, try again...
			
#if ESPDEBUG
			dcbf	0,r23							; Force to memory
			sync
#endif
			
			dcbz	0,r20							; Clear and allocate first trace line
			li		r24,32							; Offset to next line
			
ctgte32tb:	mftbu	r21								; Get the upper time now
			mftb	r22								; Get the lower time now
			mftbu	r23								; Get upper again
			cmplw	r21,r23							; Has it ticked?
			bne-	ctgte32tb						; Yes, start again...

			dcbz	r24,r20							; Clean second line

;
;			Let us cut that trace entry now.
;
;			Note that this code cuts a trace table entry for the CutTrace call only.
;			An identical entry is made during normal interrupt processing.  Any entry
;			format entry changes made must be done in both places.
;

			lhz		r24,PP_CPU_NUMBER(r11)			; Get the logical processor number
			li		r23,T_SYSTEM_CALL				; Get the system call id
			mtctr	r13								; Restore the callers CTR
			sth		r24,LTR_cpu(r20)				; Save processor number
			li		r24,64							; Offset to third line
			sth		r23,LTR_excpt(r20)				; Set the exception code
			dcbz	r24,r20							; Clean 3rd line
			mfspr	r23,dsisr						; Get the DSISR
			stw		r21,LTR_timeHi(r20)				; Save top of time stamp
			li		r24,96							; Offset to fourth line
			mflr	r21								; Get the LR
			dcbz	r24,r20							; Clean 4th line
			stw		r22,LTR_timeLo(r20)				; Save bottom of time stamp
			mfsrr0	r22								; Get SRR0
			stw		r25,LTR_cr(r20)					; Save CR
			mfsrr1	r24								; Get the SRR1
			stw		r23,LTR_dsisr(r20)				; Save DSISR
			stw		r22,LTR_srr0+4(r20)				; Save SRR0
			mfdar	r23								; Get DAR
			stw		r24,LTR_srr1+4(r20)				; Save SRR1
			stw		r23,LTR_dar+4(r20)				; Save DAR
			stw		r21,LTR_lr+4(r20)				; Save LR

			stw		r13,LTR_ctr+4(r20)				; Save CTR
			stw		r0,LTR_r0+4(r20)				; Save register
			stw		r1,LTR_r1+4(r20)				; Save register
			stw		r2,LTR_r2+4(r20)				; Save register
			stw		r3,LTR_r3+4(r20)				; Save register
			stw		r4,LTR_r4+4(r20)				; Save register
			stw		r5,LTR_r5+4(r20)				; Save register
			stw		r6,LTR_r6+4(r20)				; Save register

#if 0
			lwz		r21,FPUowner(r11)				; (TEST/DEBUG) Get the current floating point owner
			stw		r21,LTR_rsvd0(r20)				; (TEST/DEBUG) Record the owner
#endif
			
#if ESPDEBUG
			addi	r21,r20,32						; Second line
			addi	r22,r20,64						; Third line
			dcbst	0,r20							; Force to memory
			dcbst	0,r21							; Force to memory
			addi	r21,r22,32						; Fourth line
			dcbst	0,r22							; Force to memory
			dcbst	0,r21							; Force to memory
			sync									; Make sure it all goes
#endif

ctdisa32:	mtcrf	0x80,r25						; Restore the used condition register field
			lwz		r20,tempr0(r11)					; Restore work register
			lwz		r21,tempr1(r11)					; Restore work register
			lwz		r25,tempr2(r11)					; Restore work register
			mtctr	r13								; Restore the callers CTR
			lwz		r22,tempr3(r11)					; Restore work register
			lwz		r23,tempr4(r11)					; Restore work register
			lwz		r24,tempr5(r11)					; Restore work register
			b		uftX32							; Go restore the rest and go...

ctbail32:	mtcrf	0x80,r25						; Restore the used condition register field
			lwz		r20,tempr0(r11)					; Restore work register
			lwz		r21,tempr1(r11)					; Restore work register
			lwz		r25,tempr2(r11)					; Restore work register
			mtctr	r13								; Restore the callers CTR
			lwz		r22,tempr3(r11)					; Restore work register
			lwz		r23,tempr4(r11)					; Restore work register
			b		uftNormalSyscall				; Go pass it on along...

;
;			This is the 64-bit version.
;

uftct64:	std		r20,tempr0(r11)					; Save some work registers
			lwz		r20,dgFlags(0)					; Get the flags
			std		r21,tempr1(r11)					; Save some work registers
			mfsrr1	r21								; Get the SRR1
			rlwinm	r20,r20,MSR_PR_BIT-enaUsrFCallb,MASK(MSR_PR)	; Shift the validity bit over to pr bit spot
			std		r25,tempr2(r11)					; Save some work registers
			orc		r20,r20,r21						; Get ~PR | FC
			mfcr	r25								; Save the CR
			std		r22,tempr3(r11)					; Save some work registers
			lhz		r22,PP_CPU_NUMBER(r11)			; Get the logical processor number
			andi.	r20,r20,MASK(MSR_PR)			; Set cr0_eq when we are in problem state and the validity bit is not set
			std		r23,tempr4(r11)					; Save some work registers
			lwz		r23,traceMask(0)				; Get the trace mask
			std		r24,tempr5(r11)					; Save some work registers
			beq--	ctbail64						; Can not issue from user...

			addi	r24,r22,16						; Get shift to move cpu mask to syscall mask
			rlwnm	r24,r23,r24,12,12				; Shift cpu mask bit to rupt type mask
			and.	r24,r24,r23						; See if both are on
			
;
;			We select a trace entry using a compare and swap on the next entry field.
;			Since we do not lock the actual trace buffer, there is a potential that
;			another processor could wrap an trash our entry.  Who cares?
;

			li		r23,trcWork						; Get the trace work area address
			lwz		r21,traceStart(0)				; Get the start of trace table
			lwz		r22,traceEnd(0)					; Get end of trace table
			
			beq--	ctdisa64						; Leave because tracing is disabled...					

ctgte64:	lwarx	r20,0,r23						; Get and reserve the next slot to allocate
			addi	r24,r20,LTR_size				; Point to the next trace entry
			cmplw	r24,r22							; Do we need to wrap the trace table?
			bne++	ctgte64s						; No wrap, we got us a trace entry...
			
			mr		r24,r21							; Wrap back to start

ctgte64s:	stwcx.	r24,0,r23						; Try to update the current pointer
			bne--	ctgte64							; Collision, try again...
			
#if ESPDEBUG
			dcbf	0,r23							; Force to memory
			sync
#endif
			
			dcbz128	0,r20							; Zap the trace entry
			
			mftb	r21								; Get the time

;
;			Let us cut that trace entry now.
;
;			Note that this code cuts a trace table entry for the CutTrace call only.
;			An identical entry is made during normal interrupt processing.  Any entry
;			format entry changes made must be done in both places.
;

			lhz		r24,PP_CPU_NUMBER(r11)			; Get the logical processor number
			li		r23,T_SYSTEM_CALL				; Get the system call id
			sth		r24,LTR_cpu(r20)				; Save processor number
			sth		r23,LTR_excpt(r20)				; Set the exception code
			mfspr	r23,dsisr						; Get the DSISR
			std		r21,LTR_timeHi(r20)				; Save top of time stamp
			mflr	r21								; Get the LR
			mfsrr0	r22								; Get SRR0
			stw		r25,LTR_cr(r20)					; Save CR
			mfsrr1	r24								; Get the SRR1
			stw		r23,LTR_dsisr(r20)				; Save DSISR
			std		r22,LTR_srr0(r20)				; Save SRR0
			mfdar	r23								; Get DAR
			std		r24,LTR_srr1(r20)				; Save SRR1
			std		r23,LTR_dar(r20)				; Save DAR
			std		r21,LTR_lr(r20)					; Save LR

			std		r13,LTR_ctr(r20)				; Save CTR
			std		r0,LTR_r0(r20)					; Save register
			std		r1,LTR_r1(r20)					; Save register
			std		r2,LTR_r2(r20)					; Save register
			std		r3,LTR_r3(r20)					; Save register
			std		r4,LTR_r4(r20)					; Save register
			std		r5,LTR_r5(r20)					; Save register
			std		r6,LTR_r6(r20)					; Save register
			
#if 0
			lwz		r21,FPUowner(r11)				; (TEST/DEBUG) Get the current floating point owner
			stw		r21,LTR_rsvd0(r20)				; (TEST/DEBUG) Record the owner
#endif

#if ESPDEBUG
			dcbf	0,r20							; Force to memory			
			sync									; Make sure it all goes
#endif

ctdisa64:	mtcrf	0x80,r25						; Restore the used condition register field
			ld		r20,tempr0(r11)					; Restore work register
			ld		r21,tempr1(r11)					; Restore work register
			ld		r25,tempr2(r11)					; Restore work register
			mtctr	r13								; Restore the callers CTR
			ld		r22,tempr3(r11)					; Restore work register
			ld		r23,tempr4(r11)					; Restore work register
			ld		r24,tempr5(r11)					; Restore work register
			b		uftX64							; Go restore the rest and go...

ctbail64:	mtcrf	0x80,r25						; Restore the used condition register field
			ld		r20,tempr0(r11)					; Restore work register
			ld		r21,tempr1(r11)					; Restore work register
			ld		r25,tempr2(r11)					; Restore work register
			mtctr	r13								; Restore the callers CTR
			ld		r22,tempr3(r11)					; Restore work register
			ld		r23,tempr4(r11)					; Restore work register
			li		r11,T_SYSTEM_CALL|T_FAM			; Set system code call
			b		extEntry64						; Go straight to the 64-bit code...



;			Handle a system call that is not a UFT and which thus goes upstairs.

uftNormalFF:										; here with entire cr in r13
			mtcr	r13								; restore all 8 fields
			b		uftNormalSyscall1				; Join common...
			
uftNormal80:										; here with callers cr0 in r13
			mtcrf	0x80,r13						; restore cr0
			b		uftNormalSyscall1				; Join common...
			
uftNormalSyscall:									; r13 = callers ctr
			mtctr	r13								; restore ctr
uftNormalSyscall1:
			li		r11,T_SYSTEM_CALL|T_FAM			; this is a system call (and fall through)


/*<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>*/
/*
 * .L_exception_entry(type)
 *
 * Come here via branch directly from the vector, or falling down from above, with the following
 * set up:
 *
 * ENTRY:	interrupts off, VM off, in 64-bit mode if supported
 *          Caller's r13 saved in sprg2.
 *          Caller's r11 saved in sprg3.
 *          Exception code (ie, T_SYSTEM_CALL etc) in r11.
 *          All other registers are live.
 *
 */

.L_exception_entry:                                 ; WARNING: can fall through from UFT handler
			
/*
 *
 *	Here we will save off a mess of registers, the special ones and R0-R12.  We use the DCBZ
 *	instruction to clear and allcoate a line in the cache.  This way we won't take any cache
 *	misses, so these stores won't take all that long. Except the first line that is because
 *	we can't do a DCBZ if the L1 D-cache is off.  The rest we will skip if they are
 *	off also.
 * 
 *	Note that if we are attempting to sleep (as opposed to nap or doze) all interruptions
 *	are ignored.
 */


			.globl	EXT(extPatch32)						
			

LEXT(extPatch32)
			b		extEntry64						; Go do 64-bit (patched to a nop if 32-bit)
			mfsprg  r13,0							; Load per_proc
			lwz		r13,next_savearea+4(r13)		; Get the exception save area
			stw		r0,saver0+4(r13)				; Save register 0
			stw		r1,saver1+4(r13)				; Save register 1

			mfspr	r1,hid0							; Get HID0
			mfcr	r0								; Save the whole CR
			
			mtcrf	0x20,r1							; Get set to test for sleep
			cror	doze,doze,nap					; Remember if we are napping
			bf		sleep,notsleep					; Skip if we are not trying to sleep
			
			mtcrf	0x20,r0							; Restore the CR
			lwz		r0,saver0+4(r13)				; Restore R0
			lwz		r1,saver1+4(r13)				; Restore R1
			mfsprg	r13,0							; Get the per_proc 
			lwz		r11,pfAvailable(r13)			; Get back the feature flags
			mfsprg	r13,2							; Restore R13
			mtsprg	2,r11							; Set sprg2 to the features
			mfsprg	r11,3							; Restore R11
			rfi										; Jump back into sleep code...
			.long	0								; Leave these here please...
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			

;
;			This is the 32-bit context saving stuff
;

			.align	5
						
notsleep:	stw		r2,saver2+4(r13)				; Save this one
			bf		doze,notspdo					; Skip the next if we are not napping/dozing...
			rlwinm	r2,r1,0,nap+1,doze-1			; Clear any possible nap and doze bits
			mtspr	hid0,r2							; Clear the nap/doze bits

notspdo:
			la		r1,saver4(r13)					; Point to the next line in case we need it
			crmove	wasNapping,doze					; Remember if we were napping
			mfsprg	r2,0							; Get the per_proc area
			dcbz	0,r1							; allocate r4-r7 32-byte line in cache
			
;
;			Remember, we are setting up CR6 with feature flags
;
			andi.	r1,r11,T_FAM					; Check FAM bit
	
			stw		r3,saver3+4(r13)				; Save this one
			stw		r4,saver4+4(r13)				; Save this one
			andc	r11,r11,r1						; Clear FAM bit
			beq+	noFAM							; Is it FAM intercept
			mfsrr1	r3								; Load srr1
			rlwinm.	r3,r3,0,MSR_PR_BIT,MSR_PR_BIT	; Are we trapping from supervisor state?
			beq+	noFAM							; From supervisor state
			lwz		r1,spcFlags(r2)					; Load spcFlags 
			rlwinm	r1,r1,1+FamVMmodebit,30,31		; Extract FamVMenabit and FamVMmodebit
			cmpwi	cr0,r1,2						; Check FamVMena set without FamVMmode
			bne+	noFAM							; Can this context be FAM intercept
			lwz		r4,FAMintercept(r2)				; Load exceptions mask to intercept
			srwi	r1,r11,2						; Divide r11 by 4
			lis		r3,0x8000						; Set r3 to 0x80000000
			srw		r1,r3,r1						; Set bit for current exception
			and.	r1,r1,r4						; And current exception with the intercept mask
			beq+	noFAM							; Is it FAM intercept
			b		EXT(vmm_fam_exc)
noFAM:
			lwz		r1,pfAvailable(r2)				; Get the CPU features flags			
			la		r3,saver8(r13)					; Point to line with r8-r11
			mtcrf	0xE2,r1							; Put the features flags (that we care about) in the CR
			dcbz	0,r3							; allocate r8-r11 32-byte line in cache
            la		r3,saver12(r13)					; point to r12-r15 line
			lis		r4,hi16(MASK(MSR_VEC)|MASK(MSR_FP)|MASK(MSR_ME))	; Set up the MSR we will use throughout. Note that ME come on here if MCK
			stw		r6,saver6+4(r13)				; Save this one
			ori		r4,r4,lo16(MASK(MSR_VEC)|MASK(MSR_FP)|MASK(MSR_ME))	; Rest of MSR
			stw		r8,saver8+4(r13)				; Save this one
			crmove	featAltivec,pfAltivecb			; Set the Altivec flag
			mtmsr	r4								; Set MSR
			isync
			mfsrr0	r6								; Get the interruption SRR0 
            la		r8,savesrr0(r13)				; point to line with SRR0, SRR1, CR, XER, and LR
			dcbz	0,r3							; allocate r12-r15 32-byte line in cache
            la		r3,saver16(r13)					; point to next line
			dcbz	0,r8							; allocate 32-byte line with SRR0, SRR1, CR, XER, and LR
			stw		r7,saver7+4(r13)				; Save this one
			mfsrr1	r7								; Get the interrupt SRR1
			stw		r6,savesrr0+4(r13)				; Save the SRR0 
			stw		r5,saver5+4(r13)				; Save this one 
			mfsprg	r6,2							; Get interrupt time R13
			mtsprg	2,r1							; Set the feature flags
			mfsprg	r8,3							; Get rupt time R11
			stw		r7,savesrr1+4(r13)				; Save SRR1 
			stw		r8,saver11+4(r13)				; Save rupt time R11
			stw		r6,saver13+4(r13)				; Save rupt R13
			dcbz	0,r3							; allocate 32-byte line with r16-r19
            la		r3,saver20(r13)					; point to next line

getTB:		mftbu	r6								; Get the upper timebase
			mftb	r7								; Get the lower timebase
			mftbu	r8								; Get the upper one again
			cmplw	r6,r8							; Did the top tick?
			bne-	getTB							; Yeah, need to get it again...

			stw		r8,ruptStamp(r2)				; Save the top of time stamp
			stw		r8,SAVtime(r13)					; Save the top of time stamp
			stw		r7,ruptStamp+4(r2)				; Save the bottom of time stamp
			stw		r7,SAVtime+4(r13)				; Save the bottom of time stamp

			dcbz	0,r3							; allocate 32-byte line with r20-r23
			stw		r9,saver9+4(r13)				; Save this one

			stw		r10,saver10+4(r13)				; Save this one
			mflr	r4								; Get the LR
			mfxer	r10								; Get the XER
			
			bf+		wasNapping,notNapping			; Skip if not waking up from nap...

			lwz		r6,napStamp+4(r2)				; Pick up low order nap stamp
			lis		r3,hi16(EXT(machine_idle_ret))	; Get high part of nap/doze return
			lwz		r5,napStamp(r2)					; and high order
			subfc	r7,r6,r7						; Subtract low stamp from now
			lwz		r6,napTotal+4(r2)				; Pick up low total
			subfe	r5,r5,r8						; Subtract high stamp and borrow from now
			lwz		r8,napTotal(r2)					; Pick up the high total
			addc	r6,r6,r7						; Add low to total
			ori		r3,r3,lo16(EXT(machine_idle_ret))	; Get low part of nap/doze return
			adde	r8,r8,r5						; Add high and carry to total
			stw		r6,napTotal+4(r2)				; Save the low total
			stw		r8,napTotal(r2)					; Save the high total
			stw		r3,savesrr0+4(r13)				; Modify to return to nap/doze exit
			
			rlwinm.	r3,r1,0,pfSlowNapb,pfSlowNapb	; Should HID1 be restored?
			beq		notInSlowNap

			lwz		r3,pfHID1(r2)					; Get saved HID1 value
			mtspr	hid1,r3							; Restore HID1

notInSlowNap:
			rlwinm.	r3,r1,0,pfNoL2PFNapb,pfNoL2PFNapb	; Should MSSCR0 be restored?
			beq		notNapping

			lwz		r3,pfMSSCR0(r2)					; Get saved MSSCR0 value
			mtspr	msscr0,r3						; Restore MSSCR0
			sync
			isync

notNapping:	stw		r12,saver12+4(r13)				; Save this one
						
			stw		r14,saver14+4(r13)				; Save this one
			stw		r15,saver15+4(r13)				; Save this one 
			la		r14,saver24(r13)				; Point to the next block to save into
			mfctr	r6								; Get the CTR 
			stw		r16,saver16+4(r13)				; Save this one
            la		r15,savectr(r13)				; point to line with CTR, DAR, DSISR, Exception code, and VRSAVE
			stw		r4,savelr+4(r13)				; Save rupt LR
		
			dcbz	0,r14							; allocate 32-byte line with r24-r27
            la		r16,saver28(r13)				; point to line with r28-r31
			dcbz	0,r15							; allocate line with CTR, DAR, DSISR, Exception code, and VRSAVE
			stw		r17,saver17+4(r13)				; Save this one
			stw		r18,saver18+4(r13)				; Save this one 
			stw		r6,savectr+4(r13)				; Save rupt CTR
			stw		r0,savecr(r13)					; Save rupt CR
			stw		r19,saver19+4(r13)				; Save this one
			mfdar	r6								; Get the rupt DAR
			stw		r20,saver20+4(r13)				; Save this one 
			dcbz	0,r16							; allocate 32-byte line with r28-r31

			stw		r21,saver21+4(r13)				; Save this one
			lwz		r21,spcFlags(r2)				; Get the special flags from per_proc
			stw		r10,savexer+4(r13)				; Save the rupt XER
			stw		r30,saver30+4(r13)				; Save this one 
			lhz		r30,pfrptdProc(r2)				; Get the reported processor type
			stw		r31,saver31+4(r13)				; Save this one 
			stw		r22,saver22+4(r13)				; Save this one 
			stw		r23,saver23+4(r13)				; Save this one 
			stw		r24,saver24+4(r13)				; Save this one 
			stw		r25,saver25+4(r13)				; Save this one 
			mfdsisr	r7								; Get the rupt DSISR 
			stw		r26,saver26+4(r13)				; Save this one		
			stw		r27,saver27+4(r13)				; Save this one 
			andis.	r21,r21,hi16(perfMonitor)		; Is the performance monitor enabled?
			stw		r28,saver28+4(r13)				; Save this one
			cmpwi	cr1, r30,CPU_SUBTYPE_POWERPC_750	; G3?
            la		r27,savevscr(r13)				; point to 32-byte line with VSCR and FPSCR
			cmpwi	cr2,r30,CPU_SUBTYPE_POWERPC_7400	; This guy?
			stw		r29,saver29+4(r13)				; Save R29
			stw		r6,savedar+4(r13)				; Save the rupt DAR 
			li		r10,savepmc						; Point to pmc savearea

			beq+	noPerfMonSave32					; No perfmon on here...

			dcbz	r10,r13							; Clear first part of pmc area
			li		r10,savepmc+0x20				; Point to pmc savearea second part
			li		r22,0							; r22:	zero
			dcbz	r10,r13							; Clear second part of pmc area
		
			beq		cr1,perfMonSave32_750			; This is a G3...

			beq		cr2,perfMonSave32_7400			; Regular olde G4...

			mfspr	r24,pmc5						; Here for a 7450
			mfspr	r25,pmc6
			stw		r24,savepmc+16(r13)				; Save PMC5
			stw		r25,savepmc+20(r13)				; Save PMC6
			mtspr	pmc5,r22						; Leave PMC5 clear
			mtspr	pmc6,r22						; Leave PMC6 clear

perfMonSave32_7400:		
			mfspr	r25,mmcr2
			stw		r25,savemmcr2+4(r13)			; Save MMCR2
			mtspr	mmcr2,r22						; Leave MMCR2 clear

perfMonSave32_750:		
			mfspr	r23,mmcr0
			mfspr	r24,mmcr1
			stw		r23,savemmcr0+4(r13)			; Save MMCR0
			stw		r24,savemmcr1+4(r13)			; Save MMCR1 
			mtspr	mmcr0,r22						; Leave MMCR0 clear
			mtspr	mmcr1,r22						; Leave MMCR1 clear
			mfspr	r23,pmc1
			mfspr	r24,pmc2
			mfspr	r25,pmc3
			mfspr	r26,pmc4
			stw		r23,savepmc+0(r13)				; Save PMC1
			stw		r24,savepmc+4(r13)				; Save PMC2
			stw		r25,savepmc+8(r13)				; Save PMC3
			stw		r26,savepmc+12(r13)				; Save PMC4
			mtspr	pmc1,r22						; Leave PMC1 clear 
			mtspr	pmc2,r22						; Leave PMC2 clear
			mtspr	pmc3,r22						; Leave PMC3 clear 		
			mtspr	pmc4,r22						; Leave PMC4 clear

noPerfMonSave32:		
			dcbz	0,r27							; allocate line with VSCR and FPSCR 
			
			stw		r7,savedsisr(r13)				; Save the rupt code DSISR
			stw		r11,saveexception(r13)			; Save the exception code 


;
;			Everything is saved at this point, except for FPRs, and VMX registers.
;			Time for us to get a new savearea and then trace interrupt if it is enabled.
;

			lwz		r25,traceMask(0)				; Get the trace mask
			li		r0,SAVgeneral					; Get the savearea type value
			lhz		r19,PP_CPU_NUMBER(r2)			; Get the logical processor number											
			rlwinm	r22,r11,30,0,31					; Divide interrupt code by 4
			stb		r0,SAVflags+2(r13)				; Mark valid context
			addi	r22,r22,10						; Adjust code so we shift into CR5
			li		r23,trcWork						; Get the trace work area address
			rlwnm	r7,r25,r22,22,22				; Set CR5_EQ bit position to 0 if tracing allowed 
			li		r26,0x8							; Get start of cpu mask
			srw		r26,r26,r19						; Get bit position of cpu number
			mtcrf	0x04,r7							; Set CR5 to show trace or not
			and.	r26,r26,r25						; See if we trace this cpu
			crandc	cr5_eq,cr5_eq,cr0_eq			; Turn off tracing if cpu is disabled
;
;			At this point, we can take another exception and lose nothing.
;

			bne+	cr5,xcp32xit					; Skip all of this if no tracing here...

;
;			We select a trace entry using a compare and swap on the next entry field.
;			Since we do not lock the actual trace buffer, there is a potential that
;			another processor could wrap an trash our entry.  Who cares?
;

			lwz		r25,traceStart(0)				; Get the start of trace table
			lwz		r26,traceEnd(0)					; Get end of trace table
	
trcsel:		lwarx	r20,0,r23						; Get and reserve the next slot to allocate
			
			addi	r22,r20,LTR_size				; Point to the next trace entry
			cmplw	r22,r26							; Do we need to wrap the trace table?
			bne+	gotTrcEnt						; No wrap, we got us a trace entry...
			
			mr		r22,r25							; Wrap back to start

gotTrcEnt:	stwcx.	r22,0,r23						; Try to update the current pointer
			bne-	trcsel							; Collision, try again...
			
#if ESPDEBUG
			dcbf	0,r23							; Force to memory
			sync
#endif
			
			dcbz	0,r20							; Clear and allocate first trace line

;
;			Let us cut that trace entry now.
;
;			Note that this code cuts a trace table entry for everything but the CutTrace call.
;			An identical entry is made during normal CutTrace processing.  Any entry
;			format changes made must be done in both places.
;

			lwz		r16,ruptStamp(r2)				; Get top of time base
			lwz		r17,ruptStamp+4(r2)				; Get the bottom of time stamp

			li		r14,32							; Offset to second line

			lwz		r0,saver0+4(r13)				; Get back interrupt time R0
			lwz		r1,saver1+4(r13)				; Get back interrupt time R1
			lwz		r8,savecr(r13)					; Get the CR value
			
			dcbz	r14,r20							; Zap the second line
			
			sth		r19,LTR_cpu(r20)				; Stash the cpu number
			li		r14,64							; Offset to third line
			sth		r11,LTR_excpt(r20)				; Save the exception type 
			lwz		r7,saver2+4(r13)				; Get back interrupt time R2
			lwz		r3,saver3+4(r13)				; Restore this one
		
			dcbz	r14,r20							; Zap the third half
			
			mfdsisr	r9								; Get the DSISR
			li		r14,96							; Offset to forth line
			stw		r16,LTR_timeHi(r20)				; Set the upper part of TB 
			stw		r17,LTR_timeLo(r20)				; Set the lower part of TB
			lwz		r10,savelr+4(r13)				; Get the LR
			mfsrr0	r17								; Get SRR0 back, it is still good
			
			dcbz	r14,r20							; Zap the forth half
			lwz		r4,saver4+4(r13)				; Restore this one
			lwz		r5,saver5+4(r13)				; Restore this one
			mfsrr1	r18								; SRR1 is still good in here

			stw		r8,LTR_cr(r20)					; Save the CR
			lwz		r6,saver6+4(r13)				; Get R6
			mfdar	r16								; Get this back
			stw		r9,LTR_dsisr(r20)				; Save the DSISR
			stw		r17,LTR_srr0+4(r20)				; Save the SSR0 
			
			stw		r18,LTR_srr1+4(r20)				; Save the SRR1 
			stw		r16,LTR_dar+4(r20)				; Save the DAR
			mfctr	r17								; Get the CTR (still good in register)
			stw		r13,LTR_save+4(r20)				; Save the savearea 
			stw		r10,LTR_lr+4(r20)				; Save the LR
			
			stw		r17,LTR_ctr+4(r20)				; Save off the CTR
			stw		r0,LTR_r0+4(r20)				; Save off register 0 			
			stw		r1,LTR_r1+4(r20)				; Save off register 1			
			stw		r7,LTR_r2+4(r20)				; Save off register 2 	
					
		
			stw		r3,LTR_r3+4(r20)				; Save off register 3
			stw		r4,LTR_r4+4(r20)				; Save off register 4 
			stw		r5,LTR_r5+4(r20)				; Save off register 5	
			stw		r6,LTR_r6+4(r20)				; Save off register 6	

#if ESPDEBUG
			addi	r17,r20,32						; Second line
			addi	r16,r20,64						; Third line
			dcbst	br0,r20							; Force to memory
			dcbst	br0,r17							; Force to memory
			addi	r17,r17,32						; Fourth line
			dcbst	br0,r16							; Force to memory
			dcbst	br0,r17							; Force to memory
			
			sync									; Make sure it all goes
#endif
xcp32xit:	mr		r14,r11							; Save the interrupt code across the call
			bl		EXT(save_get_phys_32)			; Grab a savearea
			mfsprg	r2,0							; Get the per_proc info
			li		r10,emfp0						; Point to floating point save
			mr		r11,r14							; Get the exception code back
			dcbz	r10,r2							; Clear for speed
			stw		r3,next_savearea+4(r2)			; Store the savearea for the next rupt

			b		xcpCommon						; Go join the common interrupt processing...

;
;
;			This is the 64-bit context saving stuff
;

			.align	5
						
extEntry64:	mfsprg  r13,0							; Load per_proc
			ld		r13,next_savearea(r13)			; Get the exception save area
			std		r0,saver0(r13)					; Save register 0
			lis		r0,hi16(MASK(MSR_VEC)|MASK(MSR_FP)|MASK(MSR_ME))	; Set up the MSR we will use throughout. Note that ME come on here if MCK
			std		r1,saver1(r13)					; Save register 1
			ori		r1,r0,lo16(MASK(MSR_VEC)|MASK(MSR_FP)|MASK(MSR_ME))	; Rest of MSR
			lis		r0,0x0010						; Get rupt code transform validity mask
			mtmsr	r1								; Set MSR
			isync
		
			ori		r0,r0,0x0200					; Get rupt code transform validity mask
			std		r2,saver2(r13)					; Save this one
			lis		r1,0x00F0						; Top half of xform XOR
			rlwinm	r2,r11,29,27,31					; Get high 5 bits of rupt code
			std		r3,saver3(r13)					; Save this one
			slw		r0,r0,r2						; Move transform validity bit to bit 0
			std		r4,saver4(r13)					; Save this one
			std		r5,saver5(r13)					; Save this one 
			ori		r1,r1,0x04EC					; Bottom half of xform XOR
			mfxer	r5								; Save the XER because we are about to muck with it
			rlwinm	r4,r11,1,27,28					; Get bottom of interrupt code * 8
			lis		r3,hi16(dozem|napm)				; Get the nap and doze bits
			srawi	r0,r0,31						; Get 0xFFFFFFFF of xform valid, 0 otherwise
			rlwnm	r4,r1,r4,24,31					; Extract the xform XOR
			li		r1,saver16						; Point to the next line
			and		r4,r4,r0						; Only keep transform if we are to use it
			li		r2,lgKillResv					; Point to the killing field
			mfcr	r0								; Save the CR
			stwcx.	r2,0,r2							; Kill any pending reservation
			dcbz128	r1,r13							; Blow away the line
			sldi	r3,r3,32						; Position it
			mfspr	r1,hid0							; Get HID0
			andc	r3,r1,r3						; Clear nap and doze
			xor		r11,r11,r4						; Transform 970 rupt code to standard keeping FAM bit
			cmpld	r3,r1							; See if nap and/or doze was on
			std		r6,saver6(r13)					; Save this one
			mfsprg	r2,0							; Get the per_proc area
			la		r6,savesrr0(r13)				; point to line with SRR0, SRR1, CR, XER, and LR
			beq++	eE64NoNap						; No nap here,  skip all this...
		
			sync									; Make sure we are clean
			mtspr	hid0,r3							; Set the updated hid0
			mfspr	r1,hid0							; Yes, this is silly, keep it here
			mfspr	r1,hid0							; Yes, this is a duplicate, keep it here
			mfspr	r1,hid0							; Yes, this is a duplicate, keep it here
			mfspr	r1,hid0							; Yes, this is a duplicate, keep it here
			mfspr	r1,hid0							; Yes, this is a duplicate, keep it here
			mfspr	r1,hid0							; Yes, this is a duplicate, keep it here
			
eE64NoNap:	crnot	wasNapping,cr0_eq				; Remember if we were napping
			andi.	r1,r11,T_FAM					; Check FAM bit
			beq++	eEnoFAM							; Is it FAM intercept
			mfsrr1	r3								; Load srr1
			andc	r11,r11,r1						; Clear FAM bit
			rlwinm.	r3,r3,0,MSR_PR_BIT,MSR_PR_BIT	; Are we trapping from supervisor state?
			beq++	eEnoFAM							; From supervisor state
			lwz		r1,spcFlags(r2)					; Load spcFlags 
			rlwinm	r1,r1,1+FamVMmodebit,30,31		; Extract FamVMenabit and FamVMmodebit
			cmpwi	cr0,r1,2						; Check FamVMena set without FamVMmode
			bne++	eEnoFAM							; Can this context be FAM intercept
			lwz		r4,FAMintercept(r2)				; Load exceptions mask to intercept
			li		r3,0							; Clear
			srwi	r1,r11,2						; divide r11 by 4
			oris	r3,r3,0x8000					; Set r3 to 0x80000000
			srw		r1,r3,r1						; Set bit for current exception
			and.	r1,r1,r4						; And current exception with the intercept mask
			beq++	eEnoFAM							; Is it FAM intercept
			b		EXT(vmm_fam_exc)

			.align	5

eEnoFAM:	lwz		r1,pfAvailable(r2)				; Get the CPU features flags	
			dcbz128	0,r6							; allocate 128-byte line with SRR0, SRR1, CR, XER, and LR
			
;
;			Remember, we are setting up CR6 with feature flags
;
			std		r7,saver7(r13)					; Save this one
			mtcrf	0x80,r1							; Put the features flags (that we care about) in the CR
			std		r8,saver8(r13)					; Save this one
			mtcrf	0x40,r1							; Put the features flags (that we care about) in the CR
			mfsrr0	r6								; Get the interruption SRR0 
			mtcrf	0x20,r1							; Put the features flags (that we care about) in the CR
			mfsrr1	r7								; Get the interrupt SRR1
			std		r6,savesrr0(r13)				; Save the SRR0 
			mtcrf	0x02,r1							; Put the features flags (that we care about) in the CR
			std		r9,saver9(r13)					; Save this one
			crmove	featAltivec,pfAltivecb			; Set the Altivec flag
			std		r7,savesrr1(r13)				; Save SRR1 
			mfsprg	r9,3							; Get rupt time R11
			std		r10,saver10(r13)				; Save this one
			mfsprg	r6,2							; Get interrupt time R13
			std		r9,saver11(r13)					; Save rupt time R11
			mtsprg	2,r1							; Set the feature flags
			std		r12,saver12(r13)				; Save this one
			mflr	r4								; Get the LR
 			mftb	r7								; Get the timebase
			std		r6,saver13(r13)					; Save rupt R13
			std		r7,ruptStamp(r2)				; Save the time stamp
			std		r7,SAVtime(r13)					; Save the time stamp
			
			bf++	wasNapping,notNappingSF			; Skip if not waking up from nap...

			ld		r6,napStamp(r2)					; Pick up nap stamp
			lis		r3,hi16(EXT(machine_idle_ret))	; Get high part of nap/doze return
			sub		r7,r7,r6						; Subtract stamp from now
			ld		r6,napTotal(r2)					; Pick up total
			add		r6,r6,r7						; Add low to total
			ori		r3,r3,lo16(EXT(machine_idle_ret))	; Get low part of nap/doze return
			std		r6,napTotal(r2)					; Save the high total
			std		r3,savesrr0(r13)				; Modify to return to nap/doze exit
			
notNappingSF:	
			std		r14,saver14(r13)				; Save this one
			std		r15,saver15(r13)				; Save this one 
			stw		r0,savecr(r13)					; Save rupt CR
			mfctr	r6								; Get the CTR 
			std		r16,saver16(r13)				; Save this one
			std		r4,savelr(r13)					; Save rupt LR
		
			std		r17,saver17(r13)				; Save this one
			li		r7,savepmc						; Point to pmc area
			std		r18,saver18(r13)				; Save this one 
			lwz		r17,spcFlags(r2)				; Get the special flags from per_proc
			std		r6,savectr(r13)					; Save rupt CTR
			std		r19,saver19(r13)				; Save this one
			mfdar	r6								; Get the rupt DAR
			std		r20,saver20(r13)				; Save this one 

			dcbz128	r7,r13							; Clear out the pmc spot
					
			std		r21,saver21(r13)				; Save this one
			std		r5,savexer(r13)					; Save the rupt XER
			std		r22,saver22(r13)				; Save this one 
			std		r23,saver23(r13)				; Save this one 
			std		r24,saver24(r13)				; Save this one 
			std		r25,saver25(r13)				; Save this one 
			mfdsisr	r7								; Get the rupt DSISR 
			std		r26,saver26(r13)				; Save this one		
			andis.	r17,r17,hi16(perfMonitor)		; Is the performance monitor enabled?
			std		r27,saver27(r13)				; Save this one 
			li		r10,emfp0						; Point to floating point save
			std		r28,saver28(r13)				; Save this one
            la		r27,savevscr(r13)				; point to 32-byte line with VSCR and FPSCR
			std		r29,saver29(r13)				; Save R29
			std		r30,saver30(r13)				; Save this one 
			std		r31,saver31(r13)				; Save this one 
			std		r6,savedar(r13)					; Save the rupt DAR 
			stw		r7,savedsisr(r13)				; Save the rupt code DSISR
			stw		r11,saveexception(r13)			; Save the exception code 

			beq++	noPerfMonSave64					; Performance monitor not on...

			li		r22,0							; r22:	zero
		
			mfspr	r23,mmcr0_gp
			mfspr	r24,mmcr1_gp
			mfspr	r25,mmcra_gp
			std		r23,savemmcr0(r13)				; Save MMCR0
			std		r24,savemmcr1(r13)				; Save MMCR1 
			std		r25,savemmcr2(r13)				; Save MMCRA
			mtspr	mmcr0_gp,r22					; Leave MMCR0 clear
			mtspr	mmcr1_gp,r22					; Leave MMCR1 clear
			mtspr	mmcra_gp,r22					; Leave MMCRA clear 
			mfspr	r23,pmc1_gp
			mfspr	r24,pmc2_gp
			mfspr	r25,pmc3_gp
			mfspr	r26,pmc4_gp
			stw		r23,savepmc+0(r13)				; Save PMC1
			stw		r24,savepmc+4(r13)				; Save PMC2
			stw		r25,savepmc+8(r13)				; Save PMC3
			stw		r26,savepmc+12(r13)				; Save PMC4
			mfspr	r23,pmc5_gp
			mfspr	r24,pmc6_gp
			mfspr	r25,pmc7_gp
			mfspr	r26,pmc8_gp
			stw		r23,savepmc+16(r13)				; Save PMC5
			stw		r24,savepmc+20(r13)				; Save PMC6
			stw		r25,savepmc+24(r13)				; Save PMC7
			stw		r26,savepmc+28(r13)				; Save PMC8
			mtspr	pmc1_gp,r22						; Leave PMC1 clear 
			mtspr	pmc2_gp,r22						; Leave PMC2 clear
			mtspr	pmc3_gp,r22						; Leave PMC3 clear 		
			mtspr	pmc4_gp,r22						; Leave PMC4 clear 
			mtspr	pmc5_gp,r22						; Leave PMC5 clear 
			mtspr	pmc6_gp,r22						; Leave PMC6 clear
			mtspr	pmc7_gp,r22						; Leave PMC7 clear 		
			mtspr	pmc8_gp,r22						; Leave PMC8 clear 

noPerfMonSave64:		

;
;			Everything is saved at this point, except for FPRs, and VMX registers.
;			Time for us to get a new savearea and then trace interrupt if it is enabled.
;

			lwz		r25,traceMask(0)				; Get the trace mask
			li		r0,SAVgeneral					; Get the savearea type value
			lhz		r19,PP_CPU_NUMBER(r2)			; Get the logical processor number											
			stb		r0,SAVflags+2(r13)				; Mark valid context
			rlwinm	r22,r11,30,0,31					; Divide interrupt code by 2
			li		r23,trcWork						; Get the trace work area address
			addi	r22,r22,10						; Adjust code so we shift into CR5
			li		r26,0x8							; Get start of cpu mask
			rlwnm	r7,r25,r22,22,22				; Set CR5_EQ bit position to 0 if tracing allowed 
			srw		r26,r26,r19						; Get bit position of cpu number
			mtcrf	0x04,r7							; Set CR5 to show trace or not
			and.	r26,r26,r25						; See if we trace this cpu
			crandc	cr5_eq,cr5_eq,cr0_eq			; Turn off tracing if cpu is disabled

			bne++	cr5,xcp64xit					; Skip all of this if no tracing here...

;
;			We select a trace entry using a compare and swap on the next entry field.
;			Since we do not lock the actual trace buffer, there is a potential that
;			another processor could wrap an trash our entry.  Who cares?
;

			lwz		r25,traceStart(0)				; Get the start of trace table
			lwz		r26,traceEnd(0)					; Get end of trace table

trcselSF:	lwarx	r20,0,r23						; Get and reserve the next slot to allocate
			
			addi	r22,r20,LTR_size				; Point to the next trace entry
			cmplw	r22,r26							; Do we need to wrap the trace table?
			bne++	gotTrcEntSF						; No wrap, we got us a trace entry...
			
			mr		r22,r25							; Wrap back to start

gotTrcEntSF:	
			stwcx.	r22,0,r23						; Try to update the current pointer
			bne-	trcselSF						; Collision, try again...
			
#if ESPDEBUG
			dcbf	0,r23							; Force to memory
			sync
#endif

;
;			Let us cut that trace entry now.
;
;			Note that this code cuts a trace table entry for everything but the CutTrace call.
;			An identical entry is made during normal CutTrace processing.  Any entry
;			format changes made must be done in both places.
;

			dcbz128	0,r20							; Zap the trace entry

			lwz		r9,SAVflags(r13)				; Get savearea flags

			ld		r16,ruptStamp(r2)				; Get top of time base
			ld		r0,saver0(r13)					; Get back interrupt time R0 (we need this whether we trace or not)
			std		r16,LTR_timeHi(r20)				; Set the upper part of TB 
			ld		r1,saver1(r13)					; Get back interrupt time R1
			rlwinm	r9,r9,20,16,23					; Isolate the special flags
			ld		r18,saver2(r13)					; Get back interrupt time R2
			std		r0,LTR_r0(r20)					; Save off register 0 			
			rlwimi	r9,r19,0,24,31					; Slide in the cpu number
			ld		r3,saver3(r13)					; Restore this one
			sth		r9,LTR_cpu(r20)					; Stash the cpu number and special flags
			std		r1,LTR_r1(r20)					; Save off register 1			
			ld		r4,saver4(r13)					; Restore this one
			std		r18,LTR_r2(r20)					; Save off register 2 			
			ld		r5,saver5(r13)					; Restore this one
			ld		r6,saver6(r13)					; Get R6
			std		r3,LTR_r3(r20)					; Save off register 3
			lwz		r16,savecr(r13)					; Get the CR value
			std		r4,LTR_r4(r20)					; Save off register 4 
			mfsrr0	r17								; Get SRR0 back, it is still good
			std		r5,LTR_r5(r20)					; Save off register 5	
			std		r6,LTR_r6(r20)					; Save off register 6	
			mfsrr1	r18								; SRR1 is still good in here
			stw		r16,LTR_cr(r20)					; Save the CR
			std		r17,LTR_srr0(r20)				; Save the SSR0 
			std		r18,LTR_srr1(r20)				; Save the SRR1 
						
			mfdar	r17								; Get this back
			ld		r16,savelr(r13)					; Get the LR
			std		r17,LTR_dar(r20)				; Save the DAR
			mfctr	r17								; Get the CTR (still good in register)
			std		r16,LTR_lr(r20)					; Save the LR
			std		r17,LTR_ctr(r20)				; Save off the CTR
			mfdsisr	r17								; Get the DSISR
			std		r13,LTR_save(r20)				; Save the savearea 
			stw		r17,LTR_dsisr(r20)				; Save the DSISR
			sth		r11,LTR_excpt(r20)				; Save the exception type 
#if 0
			lwz		r17,FPUowner(r2)				; (TEST/DEBUG) Get the current floating point owner
			stw		r17,LTR_rsvd0(r20)				; (TEST/DEBUG) Record the owner
#endif

#if ESPDEBUG
			dcbf	0,r20							; Force to memory			
			sync									; Make sure it all goes
#endif
xcp64xit:	mr		r14,r11							; Save the interrupt code across the call
			bl		EXT(save_get_phys_64)			; Grab a savearea
			mfsprg	r2,0							; Get the per_proc info
			li		r10,emfp0						; Point to floating point save
			mr		r11,r14							; Get the exception code back
			dcbz128	r10,r2							; Clear for speed
			std		r3,next_savearea(r2)			; Store the savearea for the next rupt
			b		xcpCommon						; Go join the common interrupt processing...

;
;			All of the context is saved. Now we will get a
;			fresh savearea.  After this we can take an interrupt.
;

			.align	5

xcpCommon:

;
;			Here we will save some floating point and vector status
;			and we also set a clean default status for a new interrupt level.
;			Note that we assume that emfp0 is on an altivec boundary
;			and that R10 points to it (as a displacemnt from R2).
;
;			We need to save the FPSCR as if it is normal context.
;			This is because pending exceptions will cause an exception even if
;			FP is disabled. We need to clear the FPSCR when we first start running in the
;			kernel.
;

			stfd	f0,emfp0(r2)					; Save FPR0	
			stfd	f1,emfp1(r2)					; Save FPR1	
			li		r19,0							; Assume no Altivec
			mffs	f0								; Get the FPSCR
			lfd		f1,Zero(0)						; Make a 0			
			stfd	f0,savefpscrpad(r13)			; Save the FPSCR
			li		r9,0							; Get set to clear VRSAVE
			mtfsf	0xFF,f1							; Clear it
			addi	r14,r10,16						; Displacement to second vector register
			lfd		f0,emfp0(r2)					; Restore FPR0	
			la		r28,savevscr(r13)				; Point to the status area
			lfd		f1,emfp1(r2)					; Restore FPR1	

			bf		featAltivec,noavec				; No Altivec on this CPU...
			
			stvxl	v0,r10,r2						; Save a register
			stvxl	v1,r14,r2						; Save a second register
			mfspr	r19,vrsave						; Get the VRSAVE register
			mfvscr	v0								; Get the vector status register
			vspltish v1,1							; Turn on the non-Java bit and saturate
			stvxl	v0,0,r28						; Save the vector status
			vspltisw v0,1							; Turn on the saturate bit
			vxor	v1,v1,v0						; Turn off saturate	
			mtvscr	v1								; Set the non-java, no saturate status for new level
			mtspr	vrsave,r9						; Clear VRSAVE for each interrupt level

			lvxl	v0,r10,r2						; Restore first work register
			lvxl	v1,r14,r2						; Restore second work register

noavec:		stw		r19,savevrsave(r13)				; Save the vector register usage flags
			
;
;			We are now done saving all of the context.  Start filtering the interrupts.
;			Note that a Redrive will count as an actual interrupt.
;			Note also that we take a lot of system calls so we will start decode here.
;

Redrive:	
			lwz		r22,SAVflags(r13)				; Pick up the flags
			lwz		r0,saver0+4(r13)				; Get back interrupt time syscall number
			mfsprg	r2,0							; Restore per_proc
		
			lwz		r20,lo16(xcpTable)(r11)         ; Get the interrupt handler (note: xcpTable must be in 1st 32k of physical memory)
			la		r12,hwCounts(r2)				; Point to the exception count area
			andis.	r24,r22,hi16(SAVeat)			; Should we eat this one?		
			rlwinm	r22,r22,SAVredriveb+1,31,31		; Get a 1 if we are redriving
			add		r12,r12,r11						; Point to the count
			lwz		r25,0(r12)						; Get the old value
			lwz		r23,hwRedrives(r2)				; Get the redrive count
			crmove	cr3_eq,cr0_eq					; Remember if we are ignoring
			xori	r24,r22,1						; Get the NOT of the redrive
			mtctr	r20								; Point to the interrupt handler
			mtcrf	0x80,r0							; Set our CR0 to the high nybble of possible syscall code
			add		r25,r25,r24						; Count this one if not a redrive
			add		r23,r23,r22						; Count this one if if is a redrive
			crandc	cr0_lt,cr0_lt,cr0_gt			; See if we have R0 equal to 0b10xx...x 
			stw		r25,0(r12)						; Store it back
			stw		r23,hwRedrives(r2)				; Save the redrive count
			bne--	cr3,IgnoreRupt					; Interruption is being ignored...
			bctr									; Go process the exception...
	

;
;			Exception vector filter table (like everything in this file, must be in 1st 32KB of physical memory)
;

			.align	7
			
xcpTable:
			.long	EatRupt							; T_IN_VAIN			
			.long	PassUpTrap						; T_RESET				
			.long	MachineCheck					; T_MACHINE_CHECK		
			.long	EXT(handlePF)					; T_DATA_ACCESS		
			.long	EXT(handlePF)					; T_INSTRUCTION_ACCESS
			.long	PassUpRupt						; T_INTERRUPT		
			.long	EXT(AlignAssist)				; T_ALIGNMENT			
			.long	ProgramChk						; T_PROGRAM
			.long	PassUpFPU						; T_FP_UNAVAILABLE		
			.long	PassUpRupt						; T_DECREMENTER		
			.long	PassUpTrap						; T_IO_ERROR			
			.long	PassUpTrap						; T_RESERVED			
			.long	xcpSyscall						; T_SYSTEM_CALL			
			.long	PassUpTrap						; T_TRACE				
			.long	PassUpTrap						; T_FP_ASSIST			
			.long	PassUpTrap						; T_PERF_MON				
			.long	PassUpVMX						; T_VMX					
			.long	PassUpTrap						; T_INVALID_EXCP0		
			.long	PassUpTrap						; T_INVALID_EXCP1			
			.long	PassUpTrap						; T_INVALID_EXCP2		
			.long	PassUpTrap						; T_INSTRUCTION_BKPT		
			.long	PassUpRupt						; T_SYSTEM_MANAGEMENT		
			.long	EXT(AltivecAssist)				; T_ALTIVEC_ASSIST		
			.long	PassUpRupt						; T_THERMAL				
			.long	PassUpTrap						; T_INVALID_EXCP5		
			.long	PassUpTrap						; T_INVALID_EXCP6			
			.long	PassUpTrap						; T_INVALID_EXCP7			
			.long	PassUpTrap						; T_INVALID_EXCP8			
			.long	PassUpTrap						; T_INVALID_EXCP9			
			.long	PassUpTrap						; T_INVALID_EXCP10		
			.long	PassUpTrap						; T_INVALID_EXCP11		
			.long	PassUpTrap						; T_INVALID_EXCP12	
			.long	PassUpTrap						; T_INVALID_EXCP13		

			.long	PassUpTrap						; T_RUNMODE_TRACE			

			.long	PassUpRupt						; T_SIGP					
			.long	PassUpTrap						; T_PREEMPT				
			.long	conswtch						; T_CSWITCH				
			.long	PassUpRupt						; T_SHUTDOWN				
			.long	PassUpAbend						; T_CHOKE					

			.long	EXT(handleDSeg)					; T_DATA_SEGMENT			
			.long	EXT(handleISeg)					; T_INSTRUCTION_SEGMENT	

			.long	WhoaBaby						; T_SOFT_PATCH			
			.long	WhoaBaby						; T_MAINTENANCE			
			.long	WhoaBaby						; T_INSTRUMENTATION		
			.long	WhoaBaby						; T_ARCHDEP0
			.long	EatRupt							; T_HDEC
;
;			Just what the heck happened here???? 
;           NB: also get here from UFT dispatch table, on bogus index
;
			
WhoaBaby:	b		.								; Open the hood and wait for help

			.align	5
			
IgnoreRupt:
			lwz		r20,hwIgnored(r2)				; Grab the ignored interruption count
			addi	r20,r20,1						; Count this one
			stw		r20,hwIgnored(r2)				; Save the ignored count
			b		EatRupt							; Ignore it...


													
;
;			System call
;
		
			.align	5

xcpSyscall:	lis		r20,hi16(EXT(shandler))			; Assume this is a normal one, get handler address
			rlwinm	r6,r0,1,0,31					; Move sign bit to the end 
			ori		r20,r20,lo16(EXT(shandler))		; Assume this is a normal one, get handler address
			bnl++	cr0,PassUp						; R0 not 0b10xxx...x, can not be any kind of magical system call, just pass it up...
			lwz		r7,savesrr1+4(r13)				; Get the entering MSR (low half)
			lwz		r1,dgFlags(0)					; Get the flags
			cmplwi	cr2,r6,1						; See if original R0 had the CutTrace request code in it 
			
			rlwinm.	r7,r7,0,MSR_PR_BIT,MSR_PR_BIT	; Did we come from user state?
			beq++	FCisok							; From supervisor state...

			rlwinm.	r1,r1,0,enaUsrFCallb,enaUsrFCallb	; Are they valid?
			beq++	PassUp							; No, treat as a normal one...

FCisok:		beq++	cr2,EatRupt						; This is a CutTrace system call, we are done with it...
			
;
;			Here is where we call the firmware.  If it returns T_IN_VAIN, that means
;			that it has handled the interruption.  Remember: thou shalt not trash R13
;			while you are away.  Anything else is ok.
;			

			lwz		r3,saver3+4(r13)				; Restore the first parameter
			b		EXT(FirmwareCall)				; Go handle the firmware call....

;
;			Here is where we return from the firmware call
;

			.align	5
			.globl	EXT(FCReturn)

LEXT(FCReturn)
			cmplwi	r3,T_IN_VAIN					; Was it handled? 
			beq++	EatRupt							; Interrupt was handled...
			mr		r11,r3							; Put the rupt code into the right register
			b		Redrive							; Go through the filter again...
		

;
;			Here is where we return from the PTE miss and segment exception handler
;

			.align	5
			.globl	EXT(PFSExit)

LEXT(PFSExit)

#if 0
			mfsprg	r2,0							; (BRINGUP)
			lwz		r0,savedsisr(r13)				; (BRINGUP)
			andis.	r0,r0,hi16(dsiAC)				; (BRINGUP)
			beq++	didnthit						; (BRINGUP)
			lwz		r0,20(0)						; (BRINGUP)
			mr.		r0,r0							; (BRINGUP)
			bne--	didnthit						; (BRINGUP)
#if 0
			li		r0,1							; (BRINGUP)
			stw		r0,20(0)						; (BRINGUP)
			lis		r0,hi16(Choke)					; (BRINGUP)
			ori		r0,r0,lo16(Choke)				; (BRINGUP)
			sc										; (BRINGUP)
#endif
			
			lwz		r4,savesrr0+4(r13)				; (BRINGUP)
			lwz		r8,savesrr1+4(r13)				; (BRINGUP)
			lwz		r6,savedar+4(r13)				; (BRINGUP)
			rlwinm.	r0,r8,0,MSR_IR_BIT,MSR_IR_BIT	; (BRINGUP)
			mfmsr	r9								; (BRINGUP)
			ori		r0,r9,lo16(MASK(MSR_DR))		; (BRINGUP)
			beq--	hghg							; (BRINGUP)
			mtmsr	r0								; (BRINGUP)
			isync									; (BRINGUP)

hghg:		lwz		r5,0(r4)						; (BRINGUP)
			beq--	hghg1							; (BRINGUP)
			mtmsr	r9								; (BRINGUP)
			isync									; (BRINGUP)

hghg1:		rlwinm	r7,r5,6,26,31					; (BRINGUP)
			rlwinm	r27,r5,14,24,28					; (BRINGUP)
			addi	r3,r13,saver0+4					; (BRINGUP)
			lwzx	r3,r3,r27						; (BRINGUP)
			
#if 0
			lwz		r27,patcharea+4(r2)				; (BRINGUP)
			mr.		r3,r3							; (BRINGUP)
			bne++	nbnbnb							; (BRINGUP)
			addi	r27,r27,1						; (BRINGUP)
			stw		r27,patcharea+4(r2)				; (BRINGUP)
nbnbnb:					
#endif			
			
			rlwinm.	r28,r8,0,MSR_DR_BIT,MSR_DR_BIT	; (BRINGUP)
			rlwinm	r27,r6,0,0,29					; (BRINGUP)
			ori		r28,r9,lo16(MASK(MSR_DR))		; (BRINGUP)
			mfspr	r10,dabr						; (BRINGUP)
			li		r0,0							; (BRINGUP)
			mtspr	dabr,r0							; (BRINGUP)
			cmplwi	cr1,r7,31						; (BRINGUP) 
			beq--	qqq0							; (BRINGUP)
			mtmsr	r28								; (BRINGUP)
qqq0:
			isync									; (BRINGUP)
			
			lwz		r27,0(r27)						; (BRINGUP) - Get original value
			
			bne		cr1,qqq1						; (BRINGUP)
			
			rlwinm	r5,r5,31,22,31					; (BRINGUP)
			cmplwi	cr1,r5,151						; (BRINGUP)			
			beq		cr1,qqq3						; (BRINGUP)
			cmplwi	cr1,r5,407						; (BRINGUP)			
			beq		cr1,qqq2						; (BRINGUP)
			cmplwi	cr1,r5,215						; (BRINGUP)			
			beq		cr1,qqq0q						; (BRINGUP)
			cmplwi	cr1,r5,1014						; (BRINGUP)
			beq		cr1,qqqm1						; (BRINGUP)

			lis		r0,hi16(Choke)					; (BRINGUP)
			ori		r0,r0,lo16(Choke)				; (BRINGUP)
			sc										; (BRINGUP)
			
qqqm1:		rlwinm	r7,r6,0,0,26					; (BRINGUP)
			stw		r0,0(r7)						; (BRINGUP)
			stw		r0,4(r7)						; (BRINGUP)
			stw		r0,8(r7)						; (BRINGUP)
			stw		r0,12(r7)						; (BRINGUP)
			stw		r0,16(r7)						; (BRINGUP)
			stw		r0,20(r7)						; (BRINGUP)
			stw		r0,24(r7)						; (BRINGUP)
			stw		r0,28(r7)						; (BRINGUP)
			b		qqq9
		
qqq1:		cmplwi	r7,38							; (BRINGUP)
			bgt		qqq2							; (BRINGUP)
			blt		qqq3							; (BRINGUP)

qqq0q:		stb		r3,0(r6)						; (BRINGUP)
			b		qqq9							; (BRINGUP)
			
qqq2:		sth		r3,0(r6)						; (BRINGUP)
			b		qqq9							; (BRINGUP)
			
qqq3:		stw		r3,0(r6)						; (BRINGUP)
			
qqq9:		
#if 0
			rlwinm	r7,r6,0,0,29					; (BRINGUP)
			lwz		r0,0(r7)						; (BRINGUP) - Get newest value
#else
			lis		r7,hi16(0x000792B8)				; (BRINGUP)
			ori		r7,r7,lo16(0x000792B8)			; (BRINGUP)
			lwz		r0,0(r7)						; (BRINGUP) - Get newest value
#endif
			mtmsr	r9								; (BRINGUP)
			mtspr	dabr,r10						; (BRINGUP)
			isync									; (BRINGUP)

#if 0
			lwz		r28,patcharea+12(r2)			; (BRINGUP)
			mr.		r28,r28							; (BRINGUP)
			bne++	qqq12							; (BRINGUP)
			lis		r28,0x4000						; (BRINGUP)

qqq12:		stw		r27,0(r28)						; (BRINGUP)
			lwz		r6,savedar+4(r13)				; (BRINGUP)
			stw		r0,4(r28)						; (BRINGUP)
			stw		r4,8(r28)						; (BRINGUP)
			stw		r6,12(r28)						; (BRINGUP)
			addi	r28,r28,16						; (BRINGUP)
			mr.		r3,r3							; (BRINGUP)
			stw		r28,patcharea+12(r2)			; (BRINGUP)
			lwz		r10,patcharea+8(r2)				; (BRINGUP)
			lwz		r0,patcharea+4(r2)				; (BRINGUP)
#endif

#if 1
			stw		r0,patcharea(r2)				; (BRINGUP)
#endif

#if 0
			xor		r28,r0,r27						; (BRINGUP) - See how much it changed
			rlwinm	r28,r28,24,24,31				; (BRINGUP)
			cmplwi	r28,1							; (BRINGUP)

			ble++	qqq10							; (BRINGUP)

			mr		r7,r0							; (BRINGUP)
			li		r0,1							; (BRINGUP)
			stw		r0,20(0)						; (BRINGUP)
			lis		r0,hi16(Choke)					; (BRINGUP)
			ori		r0,r0,lo16(Choke)				; (BRINGUP)
			sc										; (BRINGUP)
#endif


qqq10:		addi	r4,r4,4							; (BRINGUP)
			stw		r4,savesrr0+4(r13)				; (BRINGUP)
				
			li		r11,T_IN_VAIN					; (BRINGUP)
			b		EatRupt							; (BRINGUP)
			
didnthit:											; (BRINGUP)
#endif
#if 0
			lwz		r0,20(0)						; (BRINGUP)
			mr.		r0,r0							; (BRINGUP)
			beq++	opopop							; (BRINGUP)
			li		r0,0							; (BRINGUP)
			stw		r0,20(0)						; (BRINGUP)
			lis		r0,hi16(Choke)					; (BRINGUP)
			ori		r0,r0,lo16(Choke)				; (BRINGUP)
			sc										; (BRINGUP)
opopop:
#endif
			lwz		r0,savesrr1+4(r13)				; Get the MSR in use at exception time
			cmplwi	cr1,r11,T_IN_VAIN				; Was it handled?
			rlwinm.	r4,r0,0,MSR_PR_BIT,MSR_PR_BIT	; Are we trapping from supervisor state?
			beq++	cr1,EatRupt						; Yeah, just blast back to the user... 
			beq--	NoFamPf
			mfsprg	r2,0							; Get back per_proc
			lwz		r1,spcFlags(r2)					; Load spcFlags
            rlwinm	r1,r1,1+FamVMmodebit,30,31		; Extract FamVMenabit and FamVMmodebit
            cmpi	cr0,r1,2						; Check FamVMena set without FamVMmode
			bne--	cr0,NoFamPf
            lwz		r6,FAMintercept(r2)				; Load exceptions mask to intercept
			li		r5,0							; Clear
			srwi	r1,r11,2						; divide r11 by 4
            oris	r5,r5,0x8000					; Set r5 to 0x80000000
            srw		r1,r5,r1						; Set bit for current exception
            and.	r1,r1,r6						; And current exception with the intercept mask
            beq++	NoFamPf							; Is it FAM intercept
			bl		EXT(vmm_fam_pf)
			b		EatRupt

NoFamPf:	andi.	r4,r0,lo16(MASK(MSR_RI))		; See if the recover bit is on
			lis		r0,0x8000						; Get 0xFFFFFFFF80000000
			add		r0,r0,r0						; Get 0xFFFFFFFF00000000
			beq++	PassUpTrap						; Not on, normal case...
;
;			Here is where we handle the "recovery mode" stuff.
;			This is set by an emulation routine to trap any faults when it is fetching data or
;			instructions.  
;
;			If we get a fault, we turn off RI, set CR0_EQ to false, bump the PC, and set R0
;			and R1 to the DAR and DSISR, respectively.
;
			lwz		r3,savesrr0(r13)				; Get the failing instruction address
			lwz		r4,savesrr0+4(r13)				; Get the failing instruction address
			lwz		r5,savecr(r13)					; Get the condition register
			or		r4,r4,r0						; Fill the high part with foxes
			lwz		r0,savedar(r13)					; Get the DAR
			addic	r4,r4,4							; Skip failing instruction
			lwz		r6,savedar+4(r13)				; Get the DAR
			addze	r3,r3							; Propagate carry
			rlwinm	r5,r5,0,3,1						; Clear CR0_EQ to let emulation code know we failed
			lwz		r7,savedsisr(r13)				; Grab the DSISR
			stw		r3,savesrr0(r13)				; Save resume address
			stw		r4,savesrr0+4(r13)				; Save resume address
			stw		r5,savecr(r13)					; And the resume CR
			stw		r0,saver0(r13)					; Pass back the DAR
			stw		r6,saver0+4(r13)				; Pass back the DAR
			stw		r7,saver1+4(r13)				; Pass back the DSISR
			b		EatRupt							; Resume emulated code

;
;			Here is where we handle the context switch firmware call.  The old 
;			context has been saved. The new savearea is in kind of hokey, the high order
;			half is stored in saver7 and the low half is in saver3. We will just
;			muck around with the savearea pointers, and then join the exit routine 
;

			.align	5

conswtch:	
			li		r0,0xFFF						; Get page boundary
			mr		r29,r13							; Save the save
			andc	r30,r13,r0						; Round down to page boundary (64-bit safe)
			lwz		r5,saver3+4(r13)				; Switch to the new savearea
			bf--	pf64Bitb,xcswNo64				; Not 64-bit...
			lwz		r6,saver7+4(r13)				; Get the high order half
			sldi	r6,r6,32						; Position high half
			or		r5,r5,r6						; Merge them

xcswNo64:	lwz		r30,SACvrswap+4(r30)			; get real to virtual translation
			mr		r13,r5							; Switch saveareas
			li		r0,0							; Clear this
			xor		r27,r29,r30						; Flip to virtual
			stw		r0,saver3(r5)					; Push the new virtual savearea to the switch to routine
			stw		r27,saver3+4(r5)				; Push the new virtual savearea to the switch to routine
			b		EatRupt							; Start it up... 

;
;			Handle machine check here.
;
; ?
;

			.align	5

MachineCheck:

			bt++	pf64Bitb,mck64					; ?
			
			lwz		r27,savesrr1+4(r13)				; Pick up srr1

;
;			Check if the failure was in 
;			ml_probe_read.  If so, this is expected, so modify the PC to
;			ml_proble_read_mck and then eat the exception.
;
			lwz		r30,savesrr0+4(r13)				; Get the failing PC
			lis		r28,hi16(EXT(ml_probe_read_mck))	; High order part
			lis		r27,hi16(EXT(ml_probe_read))	; High order part
			ori		r28,r28,lo16(EXT(ml_probe_read_mck))	; Get the low part
			ori		r27,r27,lo16(EXT(ml_probe_read))	; Get the low part
			cmplw	r30,r28							; Check highest possible
			cmplw	cr1,r30,r27						; Check lowest
			bge-	PassUpTrap						; Outside of range
			blt-	cr1,PassUpTrap					; Outside of range
;
;			We need to fix up the BATs here because the probe
;			routine messed them all up... As long as we are at it,
;			fix up to return directly to caller of probe.
;
		
			lis		r11,hi16(EXT(shadow_BAT)+shdDBAT)	; Get shadow address
			ori		r11,r11,lo16(EXT(shadow_BAT)+shdDBAT)	; Get shadow address
			
			lwz		r30,0(r11)						; Pick up DBAT 0 high
			lwz		r28,4(r11)						; Pick up DBAT 0 low
			lwz		r27,8(r11)						; Pick up DBAT 1 high
			lwz		r18,16(r11)						; Pick up DBAT 2 high
			lwz		r11,24(r11)						; Pick up DBAT 3 high
			
			sync
			mtdbatu	0,r30							; Restore DBAT 0 high
			mtdbatl	0,r28							; Restore DBAT 0 low
			mtdbatu	1,r27							; Restore DBAT 1 high
			mtdbatu	2,r18							; Restore DBAT 2 high
			mtdbatu	3,r11							; Restore DBAT 3 high 
			sync

			lwz		r28,savelr+4(r13)				; Get return point
			lwz		r27,saver0+4(r13)				; Get the saved MSR
			li		r30,0							; Get a failure RC
			stw		r28,savesrr0+4(r13)				; Set the return point
			stw		r27,savesrr1+4(r13)				; Set the continued MSR
			stw		r30,saver3+4(r13)				; Set return code
			b		EatRupt							; Yum, yum, eat it all up...

;
;			64-bit machine checks
;

mck64:		

;
;			NOTE: WE NEED TO RETHINK RECOVERABILITY A BIT - radar 3167190
;

			ld		r23,savesrr0(r13)				; Grab the SRR0 in case we need bad instruction
			ld		r20,savesrr1(r13)				; Grab the SRR1 so we can decode the thing
			lwz		r21,savedsisr(r13)				; We might need this in a bit
			ld		r22,savedar(r13)				; We might need this in a bit

			lis		r8,AsyMCKSrc					; Get the Async MCK Source register address
			mfsprg	r19,2							; Get the feature flags
			ori		r8,r8,0x8000					; Set to read data
			rlwinm.	r0,r19,0,pfSCOMFixUpb,pfSCOMFixUpb	; Do we need to fix the SCOM data?
			
			sync

			mtspr	scomc,r8						; Request the MCK source
			mfspr	r24,scomd						; Get the source
			mfspr	r8,scomc						; Get back the status (we just ignore it)
			sync
			isync							

			lis		r8,AsyMCKRSrc					; Get the Async MCK Source AND mask address
			li		r9,0							; Get and AND mask of 0
			
			sync

			mtspr	scomd,r9						; Set the AND mask to 0
			mtspr	scomc,r8						; Write the AND mask and clear conditions
			mfspr	r8,scomc						; Get back the status (we just ignore it)
			sync
			isync							

			lis		r8,cFIR							; Get the Core FIR register address
			ori		r8,r8,0x8000					; Set to read data
			
			sync

			mtspr	scomc,r8						; Request the Core FIR
			mfspr	r25,scomd						; Get the source
			mfspr	r8,scomc						; Get back the status (we just ignore it)
			sync
			isync							
			
			lis		r8,cFIRrst						; Get the Core FIR AND mask address
			
			sync

			mtspr	scomd,r9						; Set the AND mask to 0
			mtspr	scomc,r8						; Write the AND mask and clear conditions
			mfspr	r8,scomc						; Get back the status (we just ignore it)
			sync
			isync							

			lis		r8,l2FIR						; Get the L2 FIR register address
			ori		r8,r8,0x8000					; Set to read data
			
			sync

			mtspr	scomc,r8						; Request the L2 FIR
			mfspr	r26,scomd						; Get the source
			mfspr	r8,scomc						; Get back the status (we just ignore it)
			sync
			isync							
			
			lis		r8,l2FIRrst						; Get the L2 FIR AND mask address
			
			sync

			mtspr	scomd,r9						; Set the AND mask to 0
			mtspr	scomc,r8						; Write the AND mask and clear conditions
			mfspr	r8,scomc						; Get back the status (we just ignore it)
			sync
			isync							

			lis		r8,busFIR						; Get the Bus FIR register address
			ori		r8,r8,0x8000					; Set to read data
			
			sync

			mtspr	scomc,r8						; Request the Bus FIR
			mfspr	r27,scomd						; Get the source
			mfspr	r8,scomc						; Get back the status (we just ignore it)
			sync
			isync							
			
			lis		r8,busFIRrst					; Get the Bus FIR AND mask address
			
			sync

			mtspr	scomd,r9						; Set the AND mask to 0
			mtspr	scomc,r8						; Write the AND mask and clear conditions
			mfspr	r8,scomc						; Get back the status (we just ignore it)
			sync
			isync							
			
;			Note: bug in early chips where scom reads are shifted right by 1. We fix that here.
;			Also note that we will lose bit 63

			beq++	mckNoFix						; No fix up is needed
			sldi	r24,r24,1						; Shift left 1
			sldi	r25,r25,1						; Shift left 1
			sldi	r26,r26,1						; Shift left 1
			sldi	r27,r27,1						; Shift left 1
			
mckNoFix:	std		r24,savexdat0(r13)				; Save the MCK source in case we pass the error
			std		r25,savexdat1(r13)				; Save the Core FIR in case we pass the error
			std		r26,savexdat2(r13)				; Save the L2 FIR in case we pass the error
			std		r27,savexdat3(r13)				; Save the BUS FIR in case we pass the error

			rlwinm.	r0,r20,0,mckIFUE-32,mckIFUE-32	; Is this some kind of uncorrectable?
			bne		mckUE							; Yeah...
			
			rlwinm.	r0,r20,0,mckLDST-32,mckLDST-32	; Some kind of load/store error?
			bne		mckHandleLDST					; Yes...
			
			rldicl.	r0,r20,46,62					; Get the error cause code
			beq		mckNotSure						; We need some more checks for this one...
			
			cmplwi	r0,2							; Check for TLB parity error
			blt		mckSLBparity					; This is an SLB parity error...
			bgt		mckhIFUE						; This is an IFetch tablewalk reload UE...
			
;			IFetch TLB parity error

			isync
			tlbiel	r23								; Locally invalidate TLB entry for iaddr
			sync									; Wait for it
			b		ceMck							; All recovered...
			
;			SLB parity error.  This could be software caused.  We get one if there is
;			more than 1 valid SLBE with a matching ESID. That one we do not want to
;			try to recover from.  Search for it and if we get it, panic. 

mckSLBparity:
			crclr	cr0_eq							; Make sure we are not equal so we take correct exit

			la		r3,emvr0(r2)					; Use this to keep track of valid ESIDs we find
			li		r5,0							; Start with index 0

mckSLBck:	la		r4,emvr0(r2)					; Use this to keep track of valid ESIDs we find
			slbmfee	r6,r5							; Get the next SLBE
			andis.	r0,r6,0x0800					; See if valid bit is on
			beq		mckSLBnx						; Skip invalid and go to next
			
mckSLBck2:	cmpld	r4,r3							; Have we reached the end of the table?
			beq		mckSLBne						; Yes, go enter this one...
			ld		r7,0(r4)						; Pick up the saved ESID
			cmpld	r6,r7							; Is this a match?
			beq		mckSLBrec						; Whoops, I did bad, recover and pass up...
			addi	r4,r4,8							; Next table entry
			b		mckSLBck2						; Check the next...

mckSLBnx:	addi	r5,r5,1							; Point to next SLBE
			cmplwi	r5,64							; Have we checked all of them?
			bne++	mckSLBck						; Not yet, check again...
			b		mckSLBrec						; We looked at them all, go recover...
			
mckSLBne:	std		r6,0(r3)						; Save this ESID
			addi	r3,r3,8							; Point to the new slot
			b		mckSLBnx						; Go do the next SLBE...
			
;			Recover an SLB error
			
mckSLBrec:	li		r0,0							; Set an SLB slot index of 0
			slbia									; Trash all SLB entries (except for entry 0 that is)
			slbmfee	r7,r0							; Get the entry that is in SLB index 0
			rldicr	r7,r7,0,35						; Clear the valid bit and the rest
			slbie	r7								; Invalidate it
			
			li		r3,0							; Set the first SLBE
			
mckSLBclr:	slbmte	r0,r3							; Clear the whole entry to 0s
			addi	r3,r3,1							; Bump index
			cmplwi	cr1,r3,64						; Have we done them all?
			bne++	cr1,mckSLBclr					; Yup....
			
			sth		r3,ppInvSeg(r2)					; Store non-zero to trigger SLB reload 
			bne++	ceMck							; This was not a programming error, all recovered...
			b		ueMck							; Pass the software error up...

;
;			Handle a load/store unit error.  We need to decode the DSISR
;

mckHandleLDST:
			rlwinm.	r0,r21,0,mckL1DCPE,mckL1DCPE	; An L1 data cache parity error?
			bne++	mckL1D							; Yeah, we dealt with this back in the vector...
		
			rlwinm.	r0,r21,0,mckL1DTPE,mckL1DTPE	; An L1 tag error?
			bne++	mckL1T							; Yeah, we dealt with this back in the vector...
		
			rlwinm.	r0,r21,0,mckUEdfr,mckUEdfr		; Is the a "deferred" UE?
			bne		mckDUE							; Yeah, go see if expected...
		
			rlwinm.	r0,r21,0,mckUETwDfr,mckUETwDfr	; Is the a "deferred" tablewalk UE?
			bne		mckDTW							; Yeah, no recovery...
			
			rlwinm.	r0,r21,0,mckSLBPE,mckSLBPE		; SLB parity error?
			bne		mckSLBparity					; Yeah, go attempt recovery....
			
;			This is a recoverable D-ERAT or TLB error

			la		r9,hwMckERCPE(r2)				; Get DERAT parity error count

mckInvDAR:	isync
			tlbiel	r22								; Locally invalidate the TLB entry
			sync
			
			lwz		r21,0(r9)						; Get count
			addi	r21,r21,1						; Count this one
			stw		r21,0(r9)						; Stick it back
			
			b		ceMck							; All recovered...
		
;
;			When we come here, we are not quite sure what the error is.  We need to
;			dig a bit further.
;
;			R24 is interrupt source
;			R25 is Core FIR
;
;			Note that both have been cleared already.
;

mckNotSure:
			rldicl.	r0,r24,AsyMCKfir+1,63			; Something in the FIR?
			bne--	mckFIR							; Yup, go check some more...
			
			rldicl.	r0,r24,AsyMCKhri+1,63			; Hang recovery?
			bne--	mckHangRcvr						; Yup...
			
			rldicl.	r0,r24,AsyMCKext+1,63			; External signal?
			bne--	mckExtMck						; Yup...

;
;			We really do not know what this one is or what to do with it...
;
			
mckUnk:		lwz		r21,hwMckUnk(r2)				; Get unknown error count
			addi	r21,r21,1						; Count it
			stw		r21,hwMckUnk(r2)				; Stuff it
			b		ueMck							; Go south, young man...

;
;			Hang recovery.  This is just a notification so we only count.
;
			
mckHangRcrvr:
			lwz		r21,hwMckHang(r2)				; Get hang recovery count
			addi	r21,r21,1						; Count this one
			stw		r21,hwMckHang(r2)				; Stick it back
			b		ceMck							; All recovered...

;
;			Externally signaled MCK.  No recovery for the moment, but we this may be
;			where we handle ml_probe_read problems eventually.
;			
mckExtMck:
			lwz		r21,hwMckHang(r2)				; Get hang recovery count
			addi	r21,r21,1						; Count this one
			stw		r21,hwMckHang(r2)				; Stick it back
			b		ceMck							; All recovered...

;
;			Machine check cause is in a FIR.  Suss it out here.
;			Core FIR is in R25 and has been cleared in HW.
;			

mckFIR:		rldicl.	r0,r25,cFIRICachePE+1,63		; I-Cache parity error?
			la		r19,hwMckICachePE(r2)			; Point to counter
			bne		mckInvICache					; Go invalidate I-Cache...

			rldicl.	r0,r25,cFIRITagPE0+1,63			; I-Cache tag parity error?
			la		r19,hwMckITagPE(r2)				; Point to counter
			bne		mckInvICache					; Go invalidate I-Cache...

			rldicl.	r0,r25,cFIRITagPE1+1,63			; I-Cache tag parity error?
			la		r19,hwMckITagPE(r2)				; Point to counter
			bne		mckInvICache					; Go invalidate I-Cache...

			rldicl.	r0,r25,cFIRIEratPE+1,63			; IERAT parity error?
			la		r19,hwMckIEratPE(r2)			; Point to counter
			bne		mckInvERAT						; Go invalidate ERATs...

			rldicl.	r0,r25,cFIRIFUL2UE+1,63			; IFetch got L2 UE?
			bne		mckhIFUE						; Go count and pass up...

			rldicl.	r0,r25,cFIRDCachePE+1,63		; D-Cache PE?
			bne		mckL1D							; Handled, just go count...

			rldicl.	r0,r25,cFIRDTagPE+1,63			; D-Cache tag PE?
			bne		mckL1T							; Handled, just go count...

			rldicl.	r0,r25,cFIRDEratPE+1,63			; DERAT PE?
			la		r19,hwMckDEratPE(r2)			; Point to counter
			bne		mckInvERAT						; Go invalidate ERATs...

			rldicl.	r0,r25,cFIRTLBPE+1,63			; TLB PE?
			la		r9,hwMckTLBPE(r2)				; Get TLB parity error count
			bne		mckInvDAR						; Go recover...

			rldicl.	r0,r25,cFIRSLBPE+1,63			; SLB PE?
			bne		mckSLBparity					; Cope with it...
			
			b		mckUnk							; Have not a clue...

;
;			General recovery for I-Cache errors.  Just flush it completely.
;

			.align	7								; Force into cache line

mckInvICache:
			lis		r0,0x0080						; Get a 0x0080 (bit 9 >> 32)
			mfspr	r21,hid1						; Get the current HID1
			sldi	r0,r0,32						; Get the "forced ICBI match" bit
			or		r0,r0,r21						; Set forced match
			
			isync
			mtspr	hid1,r0							; Stick it
			mtspr	hid1,r0							; Stick it again
			isync
		
			li		r6,0							; Start at 0
			
mckIcbi:	icbi	0,r6							; Kill I$
			addi	r6,r6,128						; Next line
			andis.	r5,r6,1							; Have we done them all?
			beq++	mckIcbi							; Not yet...

			isync
			mtspr	hid1,r21						; Restore original HID1
			mtspr	hid1,r21						; Stick it again
			isync
			
			lwz		r5,0(r19)						; Get the counter
			addi	r5,r5,1							; Count it
			stw		r5,0(r19)						; Stuff it back
			b		ceMck							; All recovered...
			
		
;			General recovery for ERAT problems - handled in exception vector already

mckInvERAT:	lwz		r21,0(r19)						; Get the exception count spot
			addi	r21,r21,1						; Count this one
			stw		r21,0(r19)						; Save count
			b		ceMck							; All recovered...
			
;			General hang recovery - this is a notification only, just count.	
			
mckHangRcvr:			
			lwz		r21,hwMckHang(r2)				; Get hang recovery count
			addi	r21,r21,1						; Count this one
			stw		r21,hwMckHang(r2)				; Stick it back
			b		ceMck							; All recovered...


;
;			These are the uncorrectable errors, just count them then pass it along.
;
	
mckUE:		lwz		r21,hwMckUE(r2)					; Get general uncorrectable error count
			addi	r21,r21,1						; Count it
			stw		r21,hwMckUE(r2)					; Stuff it
			b		ueMck							; Go south, young man...
	
mckhIFUE:	lwz		r21,hwMckIUEr(r2)				; Get I-Fetch TLB reload uncorrectable error count
			addi	r21,r21,1						; Count it
			stw		r21,hwMckIUEr(r2)				; Stuff it
			b		ueMck							; Go south, young man...

mckDUE:		lwz		r21,hwMckDUE(r2)				; Get deferred uncorrectable error count
			addi	r21,r21,1						; Count it
			stw		r21,hwMckDUE(r2)				; Stuff it
			
;
;			Right here is where we end up after a failure on a ml_probe_read_64.
;			We will check if that is the case, and if so, fix everything up and
;			return from it.
			
			lis		r8,hi16(EXT(ml_probe_read_64))	; High of start
			lis		r9,hi16(EXT(ml_probe_read_mck_64))	; High of end
			ori		r8,r8,lo16(EXT(ml_probe_read_64))	; Low of start
			ori		r9,r9,lo16(EXT(ml_probe_read_mck_64))	; Low of end
			cmpld	r23,r8							; Too soon?
			cmpld	cr1,r23,r9						; Too late?
			
			cror	cr0_lt,cr0_lt,cr1_gt			; Too soon or too late?
			ld		r3,saver12(r13)					; Get the original MSR
			ld		r5,savelr(r13)					; Get the return address
			li		r4,0							; Get fail code
			blt--	ueMck							; This is a normal machine check, just pass up...
			std		r5,savesrr0(r13)				; Set the return MSR
			
			std		r3,savesrr1(r13)				; Set the return address
			std		r4,saver3(r13)					; Set failure return code
			b		ceMck							; All recovered...

mckDTW:		lwz		r21,hwMckDTW(r2)				; Get deferred tablewalk uncorrectable error count
			addi	r21,r21,1						; Count it
			stw		r21,hwMckDTW(r2)				; Stuff it
			b		ueMck							; Go south, young man...

mckL1D:		lwz		r21,hwMckL1DPE(r2)				; Get data cache parity error count
			addi	r21,r21,1						; Count it
			stw		r21,hwMckL1DPE(r2)				; Stuff it
			b		ceMck							; All recovered...

mckL1T:		lwz		r21,hwMckL1TPE(r2)				; Get TLB parity error count
			addi	r21,r21,1						; Count it
			stw		r21,hwMckL1TPE(r2)				; Stuff it

ceMck:		lwz		r21,mckFlags(0)					; Get the flags
			li		r0,1							; Set the recovered flag before passing up
			rlwinm.	r21,r21,0,31,31					; Check if we want to log recoverables
			stw		r0,savemisc3(r13)				; Set it
			beq++	EatRupt							; No log of recoverables wanted...
			b		PassUpTrap						; Go up and log error...

ueMck:		li		r0,0							; Set the unrecovered flag before passing up
			stw		r0,savemisc3(r13)				; Set it
			b		PassUpTrap						; Go up and log error and probably panic
			
;
;			We come here to handle program exceptions
;
;			When the program check is a trap instruction and it happens when
;			we are executing injected code, we need to check if it is an exit trap.
;			If it is, we need to populate the current savearea with some of the context from 
;			the saved pre-inject savearea.  This is needed because the current savearea will be
;			tossed as part of the pass up code.  Additionally, because we will not be nullifying
;			the emulated instruction as we do with any other exception.
;
			
			.align	5

ProgramChk:	lwz		r5,savesrr1+4(r13)				; Get the interrupt SRR1
			lwz		r3,ijsave(r2)					; Get the inject savearea top
			lwz		r4,ijsave+4(r2)					; And get the bottom of the inject savearea pointer
			rlwimi	r5,r5,15,31,31					; Scoot trap flag down to a spare bit
			rlwinm	r3,r3,0,1,0						; Copy low 32 bits of to top 32
			li		r0,0x0023						; Get bits that match scooted trap flag, IR, and RI
			and		r0,r5,r0						; Clear any extra SRR1 bits
			rlwimi.	r3,r4,0,0,31					; Insert low part of 64-bit address in bottom 32 bits and see if ijsave is 0		
			cmplwi	cr1,r0,1						; Make sure we were IR off, RI off, and got a trap exception
			crandc	cr0_eq,cr1_eq,cr0_eq			; If we are injecting, ijsave will be non-zero and we had the trap bit set
			mfsrr0	r4								; Get the PC
			bne++	cr0,mustem						; This is not an injection exit...

			lwz		r4,0(r4)						; Get the trap instruction
			lis		r5,hi16(ijtrap)					; Get high half of inject exit trap
			ori		r5,r5,lo16(ijtrap)				; And the low half
			cmplw	r4,r5							; Correct trap instruction?
			bne		mustem							; No, not inject exit...

			lwz		r4,savesrr0(r3)					; Get the original SRR0
			lwz		r5,savesrr0+4(r3)				; And the rest of it
			lwz		r6,savesrr1(r3)					; Get the original SRR1
			stw		r4,savesrr0(r13)				; Set the new SRR0 to the original
			lwz		r4,savesrr1+4(r13)				; Get the bottom of the new SRR1
			lwz		r7,savesrr1+4(r3)				; Get the bottom of the original SRR1
			li		r11,T_INJECT_EXIT				; Set an inject exit exception
			stw		r5,savesrr0+4(r13)				; Set the new bottom of SRR0 to the original
			rlwimi	r7,r4,0,MSR_FP_BIT,MSR_FP_BIT	; Make sure we retain the current floating point enable bit
			stw		r6,savesrr1(r13)				; Save the top half of the original SRR1
			sth		r7,savesrr1+6(r13)				; And the last bottom
			stw		r11,saveexception(r13)			; Set the new the exception code
			b		PassUpTrap						; Go pass it on up...

mustem:		b		EXT(Emulate)					; Go try to emulate this one...


/*
 *			Here's where we come back from some instruction emulator.  If we come back with
 *			T_IN_VAIN, the emulation is done and we should just reload state and directly
 *			go back to the interrupted code. Otherwise, we'll check to see if
 *			we need to redrive with a different interrupt, i.e., DSI.
 *			Note that this we are actually not redriving the rupt, rather changing it
 *			into a different one.  Thus we clear the redrive bit.
 */
 
			.align	5
			.globl	EXT(EmulExit)

LEXT(EmulExit)

			cmplwi	cr1,r11,T_IN_VAIN				; Was it emulated?
			lis		r1,hi16(SAVredrive)				; Get redrive request
			beq++	cr1,EatRupt						; Yeah, just blast back to the user...
			lwz		r4,SAVflags(r13)				; Pick up the flags

			and.	r0,r4,r1						; Check if redrive requested

			beq++	PassUpTrap						; No redrive, just keep on going...

			b		Redrive							; Redrive the exception...
		
;
; 			Jump into main handler code switching on VM at the same time.
;
; 			We assume kernel data is mapped contiguously in physical
; 			memory, otherwise we would need to switch on (at least) virtual data.
;			SRs are already set up.
;
	
			.align	5
	
PassUpTrap:	lis		r20,hi16(EXT(thandler))			; Get thandler address
			ori		r20,r20,lo16(EXT(thandler))		; Get thandler address
			b		PassUp							; Go pass it up...
	
PassUpRupt:	lis		r20,hi16(EXT(ihandler))			; Get ihandler address
			ori		r20,r20,lo16(EXT(ihandler))		; Get ihandler address
			b		PassUp							; Go pass it up...
	
			.align	5
	
PassUpFPU:	lis		r20,hi16(EXT(fpu_switch))		; Get FPU switcher address
			ori		r20,r20,lo16(EXT(fpu_switch))	; Get FPU switcher address
			b		PassUp							; Go pass it up...

			.align	5

PassUpVMX:	lis		r20,hi16(EXT(vec_switch))		; Get VMX switcher address
			ori		r20,r20,lo16(EXT(vec_switch))	; Get VMX switcher address
			bt++	featAltivec,PassUp				; We have VMX on this CPU...
			li		r11,T_PROGRAM					; Say that it is a program exception
			li		r20,8							; Set invalid instruction
			stw		r11,saveexception(r13)			; Set the new the exception code
			sth		r20,savesrr1+4(r13)				; Set the invalid instruction SRR code
			
			b		PassUpTrap						; Go pass it up...
	
			.align	5
	
PassUpAbend:	
			lis		r20,hi16(EXT(chandler))			; Get choke handler address
			ori		r20,r20,lo16(EXT(chandler))		; Get choke handler address
			b		PassUp							; Go pass it up...

			.align	5

PassUp:		
			mfsprg	r29,0							; Get the per_proc block back
			
			cmplwi	cr1,r11,T_INJECT_EXIT			; Are we exiting from an injection?
			lwz		r3,ijsave(r29)					; Get the inject savearea top
			lwz		r4,ijsave+4(r29)				; And get the bottom of the inject savearea pointer
			rlwinm	r3,r3,0,1,0						; Copy low 32 bits to top 32
			rlwimi.	r3,r4,0,0,31					; Insert low part of 64-bit address in bottom 32 bits and see if ijsave is 0		
			beq++	notaninjct						; Skip tossing savearea if no injection...

			beq--	cr1,nonullify					; Have not finished the instruction, go nullify it...
			
			lwz		r4,savesrr1+4(r3)				; Get the interrupt modifiers from the original SRR1
			lwz		r5,savesrr1+4(r13)				; Get the interrupt modifiers from the new SRR1
			lwz		r6,savedar(r13)					; Get the top of the DAR
			rlwimi	r4,r5,0,0,15					; copy the new top to the original SRR1
			lwz		r7,savedar+4(r13)				; Get the bottom of the DAR
			rlwimi	r4,r5,0,MSR_FP_BIT,MSR_FP_BIT	; Copy the new FP enable bit into the old SRR1
			stw		r4,savesrr1+4(r3)				; Save the updated SRR1
			lwz		r5,savedsisr(r13)				; Grab the new DSISR
			
			mr		r4,r13							; Save the new savearea pointer
			mr		r13,r3							; Point to the old savearea we are keeping
			stw		r6,savedar(r13)					; Save top of new DAR
			stw		r7,savedar+4(r13)				; Save bottom of new DAR
			stw		r5,savedsisr(r13)				; Set the new DSISR
			stw		r11,saveexception(r13)			; Set the new exception code
			mr		r3,r4							; Point to the new savearea in order to toss it
			
nonullify:	li		r0,0							; Get a zero
			stw		r0,ijsave(r29)					; Clear the pointer to the saved savearea
			stw		r0,ijsave+4(r29)				; Clear the pointer to the saved savearea
			
			bl		EXT(save_ret_phys)				; Dump that pesky extra savearea			
			
notaninjct:	lwz		r10,SAVflags(r13)				; Pick up the flags

			li		r0,0xFFF						; Get a page mask
			li		r2,MASK(MSR_BE)|MASK(MSR_SE)	; Get the mask to save trace bits
			andc	r5,r13,r0						; Back off to the start of savearea block
			mfmsr	r3								; Get our MSR
			rlwinm	r10,r10,0,SAVredriveb+1,SAVredriveb-1	; Clear the redrive before we pass it up
			li		r21,MSR_SUPERVISOR_INT_OFF		; Get our normal MSR value
			and		r3,r3,r2						; Clear all but trace
			lwz		r5,SACvrswap+4(r5)				; Get real to virtual conversion			
			or		r21,r21,r3						; Keep the trace bits if they are on
			stw		r10,SAVflags(r13)				; Set the flags with the cleared redrive flag

			xor		r4,r13,r5						; Pass up the virtual address of context savearea
			rlwinm	r4,r4,0,0,31					; Clean top half of virtual savearea if 64-bit

			mr		r3,r21							; Pass in the MSR we will go to
			bl		EXT(switchSegs)					; Go handle the segment registers/STB

			lwz		r3,saveexception(r13)			; Recall the exception code
			
			mtsrr0	r20								; Set up the handler address
			mtsrr1	r21								; Set up our normal MSR value

			bt++	pf64Bitb,puLaunch				; Handle 64-bit machine...

			rfi										; Launch the exception handler
			
puLaunch:	rfid									; Launch the exception handler

/*
 *			This routine is the main place where we return from an interruption.
 *
 *			This is also where we release the quickfret list.  These are saveareas
 *			that were released as part of the exception exit path in hw_exceptions.
 *			In order to save an atomic operation (which actually will not work
 *			properly on a 64-bit machine) we use holdQFret to indicate that the list
 *			is in flux and should not be looked at here.  This comes into play only
 *			when we take a PTE miss when we are queuing a savearea onto qfret.
 *			Quite rare but could happen.  If the flag is set, this code does not
 *			release the list and waits until next time.
 *
 *			All we need to remember here is that R13 must point to the savearea
 *			that has the context we need to load up. Translation and interruptions
 *			must be disabled.
 *
 *			This code always loads the context in the savearea pointed to
 *			by R13.  In the process, it throws away the savearea.  If there 
 *			is any tomfoolery with savearea stacks, it must be taken care of 
 *			before we get here.
 *
 */
 
 			.align	5
 
EatRupt:	mfsprg	r29,0							; Get the per_proc block back
			mr		r31,r13							; Move the savearea pointer to the far end of the register set
			mfsprg	r27,2							; Get the processor features
			
			lwz		r3,holdQFret(r29)				; Get the release hold off flag

			bt++	pf64Bitb,eat64a					; Skip down to the 64-bit version of this

;
;			This starts the 32-bit version
;

			mr.		r3,r3							; Should we hold off the quick release?
			lwz		r30,quickfret+4(r29)			; Pick up the quick fret list, if any
			la		r21,saver0(r31)					; Point to the first thing we restore
			bne-	ernoqfret						; Hold off set, do not release just now...
			
erchkfret:	mr.		r3,r30							; Any savearea to quickly release?
			beq+	ernoqfret						; No quickfrets...
			lwz		r30,SAVprev+4(r30)				; Chain back now
			
			bl		EXT(save_ret_phys)				; Put it on the free list			
			stw		r30,quickfret+4(r29)			; Dequeue previous guy (really, it is ok to wait until after the release)
			b		erchkfret						; Try the next one...

			.align	5
			
ernoqfret:	
			lwz		r30,SAVflags(r31)				; Pick up the flags
			lis		r0,hi16(SAVinject)				; Get inject flag
			dcbt	0,r21							; Touch in the first thing we need
			
;
;			Here we release the savearea.
;
;			Important!!!!  The savearea is released before we are done with it. When the
;			local free savearea list (anchored at lclfree) gets too long, save_ret_phys
;			will trim the list, making the extra saveareas allocatable by another processor
;			The code in there must ALWAYS leave our savearea on the local list, otherwise
;			we could be very, very unhappy.  The code there always queues the "just released"
;			savearea to the head of the local list.  Then, if it needs to trim, it will
;			start with the SECOND savearea, leaving ours intact.
;
;			If we are going to inject code here, we must not toss the savearea because
;			we will continue to use it.  The code stream to inject is in it and we 
;			use it to hold the pre-inject context so that we can merge that with the
;			post-inject context.  The field ijsave in the per-proc is used to point to the savearea.
;
;			Note that we will NEVER pass an interrupt up without first dealing with this savearea.
;			
;			All permanent interruptions (i.e., not denorm, alignment, or handled page and segment faults)
;			will nullify any injected code and pass the interrupt up in the original savearea.  A normal
;			inject completion will merge the original context into the new savearea and pass that up.
;			
;			Note that the following code which sets up the injection will only be executed when
;			SAVinject is set.  That means that if will not run if we are returning from an alignment
;			or denorm exception, or from a handled page or segment fault.
;

			andc	r0,r30,r0						; Clear the inject flag
			cmplw	cr4,r0,r30						; Remember if we need to inject
			mr		r3,r31							; Get the exiting savearea in parm register
			beq+	cr4,noinject					; No, we are not going to inject instructions...	
			
			stw		r0,SAVflags(r31)				; Yes we are, clear the request...
			
			lhz		r26,PP_CPU_NUMBER(r29)			; Get the cpu number
			lwz		r25,saveinstr(r31)				; Get the instruction count
			la		r3,saveinstr+4(r31)				; Point to the instruction stream
			slwi	r26,r26,6						; Get offset to the inject code stream for this processor
			li		r5,0							; Get the current instruction offset
			ori		r26,r26,lo16(EXT(ijcode))		; Get the base of the inject buffer for this processor (always < 64K)
			slwi	r25,r25,2						; Multiply by 4
			
injctit:	lwzx	r6,r5,r3						; Pick up the instruction
			stwx	r6,r5,r26						; Inject into code buffer
			addi	r5,r5,4							; Bump offset
			cmplw	r5,r25							; Have we hit the end?
			blt-	injctit							; Continue until we have copied all...
			
			lis		r3,0x0FFF						; Build our magic trap
			ori		r3,r3,0xC9C9					; Build our magic trap
			stw		r31,ijsave+4(r29)				; Save the original savearea for injection
			stwx	r3,r5,r26						; Save the magic trap

			li		r3,32							; Get cache line size
			dcbf	0,r26							; Flush first line
			dcbf	r3,r26							; And the second
			sync									; Hang on until it's done
			
			icbi	0,r26							; Flush instructions in the first line
			icbi	r3,r26							; And the second
			isync									; Throw anything stale away
			sync									; Hang on until it's done
			b		injected						; Skip the savearea release...
			
noinject:	bl		EXT(save_ret_phys)				; Put old savearea on the free list			

injected:	lwz		r3,savesrr1+4(r31)				; Pass in the MSR we are going to
			bl		EXT(switchSegs)					; Go handle the segment registers/STB

			li		r3,savesrr1+4					; Get offset to the srr1 value
			lwarx	r8,r3,r31						; Get destination MSR and take reservation along the way (just so we can blow it away)
			cmplw	cr3,r14,r14						; Set that we do not need to stop streams

			li		r21,emfp0						; Point to the fp savearea
			stwcx.	r8,r3,r31						; Blow away any reservations we hold

			lwz		r25,savesrr0+4(r31)				; Get the SRR0 to use
			
			la		r28,saver4(r31)					; Point to the 32-byte line with r4-r7
			dcbz	r21,r29							; Clear a work area
			lwz		r0,saver0+4(r31)				; Restore R0			
			dcbt	0,r28							; Touch in r4-r7 
			lwz		r1,saver1+4(r31)				; Restore R1	
			
			beq+	cr4,noinject2					; No code injection here...
			
;
;			If we are injecting, we need to stay in supervisor state with instruction
;			address translation off.  We also need to have as few potential interruptions as
;			possible.  Therefore, we turn off external interruptions and tracing (which doesn't
;			make much sense anyway).
;
			ori		r8,r8,lo16(ijemoff)				; Force the need-to-be-off bits on
			mr		r25,r26							; Get the injected code address
			xori	r8,r8,lo16(ijemoff)				; Turn off all of the need-to-be-off bits
			
noinject2:	lwz		r2,saver2+4(r31)				; Restore R2	
			la		r28,saver8(r31)					; Point to the 32-byte line with r8-r11
			lwz		r3,saver3+4(r31)				; Restore R3
            andis.	r6,r27,hi16(pfAltivec)			; Do we have altivec on the machine?
            dcbt	0,r28							; touch in r8-r11
			lwz		r4,saver4+4(r31)				; Restore R4
            la		r28,saver12(r31)				; Point to the 32-byte line with r12-r15
			mtsrr0	r25								; Restore the SRR0 now
			lwz		r5,saver5+4(r31)				; Restore R5
			mtsrr1	r8								; Restore the SRR1 now 
			lwz		r6,saver6+4(r31)				; Restore R6			
			
			dcbt	0,r28							; touch in r12-r15
			la		r28,saver16(r31)
			
			lwz		r7,saver7+4(r31)				; Restore R7
			lwz		r8,saver8+4(r31)				; Restore R8	
			lwz		r9,saver9+4(r31)				; Restore R9
            
            dcbt	0,r28							; touch in r16-r19
            la		r28,saver20(r31)			
            		
			lwz		r10,saver10+4(r31)				; Restore R10
			lwz		r11,saver11+4(r31)				; Restore R11			
			
			dcbt	0,r28							; touch in r20-r23
			la		r28,savevscr(r31)				; Point to the status area
			
			lwz		r12,saver12+4(r31)				; Restore R12
			lwz		r13,saver13+4(r31)				; Restore R13			

            la		r14,savectr+4(r31)
			dcbt	0,r28							; Touch in VSCR and FPSCR
            dcbt	0,r14							; touch in CTR, DAR, DSISR, VRSAVE, and Exception code

			lwz		r26,next_savearea+4(r29)		; Get the exception save area
			la		r28,saver24(r31)

			lwz		r14,saver14+4(r31)				; Restore R14	
			lwz		r15,saver15+4(r31)				; Restore R15			


			stfd	f0,emfp0(r29)					; Save FP0
			lwz		r27,savevrsave(r31)				; Get the vrsave
            dcbt	0,r28							; touch in r24-r27
			la		r28,savevscr(r31)				; Point to the status area
			lfd		f0,savefpscrpad(r31)			; Get the fpscr
            la		r22,saver28(r31)
			mtfsf	0xFF,f0							; Restore fpscr		
			lfd		f0,emfp0(r29)					; Restore the used register

			beq		noavec3							; No Altivec on this CPU...
			
			stvxl	v0,r21,r29						; Save a vector register
			lvxl	v0,0,r28						; Get the vector status
			mtspr	vrsave,r27						; Set the vrsave
			mtvscr	v0								; Set the vector status
			lvxl	v0,r21,r29						; Restore work vector register

noavec3:	dcbt	0,r22							; touch in r28-r31
           	
 			lwz		r23,spcFlags(r29)				; Get the special flags from per_proc
            la		r17,savesrr0(r31)
			la		r26,saver0(r26)					; Point to the first part of the next savearea
            dcbt	0,r17							; touch in SRR0, SRR1, CR, XER, LR 
			lhz		r28,pfrptdProc(r29)				; Get the reported processor type

			lwz		r16,saver16+4(r31)				; Restore R16
			lwz		r17,saver17+4(r31)				; Restore R17
			lwz		r18,saver18+4(r31)				; Restore R18	
			lwz		r19,saver19+4(r31)				; Restore R19	
			lwz		r20,saver20+4(r31)				; Restore R20
			lwz		r21,saver21+4(r31)				; Restore R21
			lwz		r22,saver22+4(r31)				; Restore R22

			cmpwi	cr1,r28,CPU_SUBTYPE_POWERPC_750	; G3?

			dcbz	0,r26							; Clear and allocate next savearea we use in the off chance it is still in when we next interrupt

			andis.	r23,r23,hi16(perfMonitor)		; Is the performance monitor enabled?
			lwz		r23,saver23+4(r31)				; Restore R23
			cmpwi	cr2,r28,CPU_SUBTYPE_POWERPC_7400	; Yer standard G4?
			lwz		r24,saver24+4(r31)				; Restore R24			
			lwz		r25,saver25+4(r31)				; Restore R25			
			lwz		r26,saver26+4(r31)				; Restore R26		
			lwz		r27,saver27+4(r31)				; Restore R27			

			beq+	noPerfMonRestore32				; No perf monitor... 

			beq-	cr1,perfMonRestore32_750		; This is a G3...
			beq-	cr2,perfMonRestore32_7400		; Standard G4...
		
			lwz		r28,savepmc+16(r31)
			lwz		r29,savepmc+20(r31)
			mtspr	pmc5,r28						; Restore PMC5
			mtspr	pmc6,r29						; Restore PMC6

perfMonRestore32_7400:
			lwz		r28,savemmcr2+4(r31)
			mtspr	mmcr2,r28						; Restore MMCR2

perfMonRestore32_750:
			lwz		r28,savepmc+0(r31)
			lwz		r29,savepmc+4(r31)
			mtspr	pmc1,r28						; Restore PMC1 
			mtspr	pmc2,r29						; Restore PMC2 
			lwz		r28,savepmc+8(r31)
			lwz		r29,savepmc+12(r31)
			mtspr	pmc3,r28						; Restore PMC3
			mtspr	pmc4,r29						; Restore PMC4
			lwz		r28,savemmcr1+4(r31)
			lwz		r29,savemmcr0+4(r31)
			mtspr	mmcr1,r28						; Restore MMCR1
			mtspr	mmcr0,r29						; Restore MMCR0

noPerfMonRestore32:		
			lwz		r28,savecr(r31)					; Get CR to restore
			lwz		r29,savexer+4(r31)				; Get XER to restore
			mtcr	r28								; Restore the CR
			lwz		r28,savelr+4(r31)				; Get LR to restore
			mtxer	r29								; Restore the XER
			lwz		r29,savectr+4(r31)				; Get the CTR to restore
			mtlr	r28								; Restore the LR 
			lwz		r28,saver30+4(r31)				; Get R30
			mtctr	r29								; Restore the CTR
			lwz		r29,saver31+4(r31)				; Get R31
			mtsprg	2,r28							; Save R30 for later
			lwz		r28,saver28+4(r31)				; Restore R28			
			mtsprg	3,r29							; Save R31 for later
			lwz		r29,saver29+4(r31)				; Restore R29

			mfsprg	r31,0							; Get per_proc
			mfsprg	r30,2							; Restore R30 
			lwz		r31,pfAvailable(r31)			; Get the feature flags
			mtsprg	2,r31							; Set the feature flags
			mfsprg	r31,3							; Restore R31

			rfi										; Click heels three times and think very hard that there is no place like home...

			.long	0								; Leave this here
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0
			.long	0


;
;			This starts the 64-bit version
;

			.align	7

eat64a:		ld		r30,quickfret(r29)				; Pick up the quick fret list, if any

			mr.		r3,r3							; Should we hold off the quick release?
			la		r21,saver0(r31)					; Point to the first thing we restore
			bne--	ernoqfre64						; Hold off set, do not release just now...
			
erchkfre64:	mr.		r3,r30							; Any savearea to quickly release?
			beq+	ernoqfre64						; No quickfrets...
			ld		r30,SAVprev(r30)				; Chain back now
			
			bl		EXT(save_ret_phys)				; Put it on the free list			

			std		r30,quickfret(r29)				; Dequeue previous guy (really, it is ok to wait until after the release)
			b		erchkfre64						; Try the next one...

			.align	7
			
ernoqfre64:	lwz		r30,SAVflags(r31)				; Pick up the flags
			lis		r0,hi16(SAVinject)				; Get inject flag
			dcbt	0,r21							; Touch in the first thing we need
			
;
;			Here we release the savearea.
;
;			Important!!!!  The savearea is released before we are done with it. When the
;			local free savearea list (anchored at lclfree) gets too long, save_ret_phys
;			will trim the list, making the extra saveareas allocatable by another processor
;			The code in there must ALWAYS leave our savearea on the local list, otherwise
;			we could be very, very unhappy.  The code there always queues the "just released"
;			savearea to the head of the local list.  Then, if it needs to trim, it will
;			start with the SECOND savearea, leaving ours intact.
;
;			If we are going to inject code here, we must not toss the savearea because
;			we will continue to use it.  The code stream to inject is in it and we 
;			use it to hold the pre-inject context so that we can merge that with the
;			post-inject context.  The field ijsave in the per-proc is used to point to the savearea.
;
;			Note that we will NEVER pass an interrupt up without first dealing with this savearea.
;			
;			All permanent interruptions (i.e., not denorm, alignment, or handled page and segment faults)
;			will nullify any injected code and pass the interrupt up in the original savearea.  A normal
;			inject completion will merge the original context into the new savearea and pass that up.
;			
;			Note that the following code which sets up the injection will only be executed when
;			SAVinject is set.  That means that if will not run if we are returning from an alignment
;			or denorm exception, or from a handled page or segment fault.
;


			li		r3,lgKillResv					; Get spot to kill reservation
			andc	r0,r30,r0						; Clear the inject flag
			stdcx.	r3,0,r3							; Blow away any reservations we hold
			cmplw	cr4,r0,r30						; Remember if we need to inject
			mr		r3,r31							; Get the exiting savearea in parm register
			beq++	cr4,noinject3					; No, we are not going to inject instructions...	
			
			stw		r0,SAVflags(r31)				; Yes we are, clear the request...

			lhz		r26,PP_CPU_NUMBER(r29)			; Get the cpu number
			lwz		r25,saveinstr(r31)				; Get the instruction count
			la		r3,saveinstr+4(r31)				; Point to the instruction stream
			slwi	r26,r26,6						; Get offset to the inject code stream for this processor
			li		r5,0							; Get the current instruction offset
			ori		r26,r26,lo16(EXT(ijcode))		; Get the base of the inject buffer for this processor (always < 64K)
			slwi	r25,r25,2						; Multiply by 4
			
injctit2:	lwzx	r6,r5,r3						; Pick up the instruction
			stwx	r6,r5,r26						; Inject into code buffer
			addi	r5,r5,4							; Bump offset
			cmplw	r5,r25							; Have we hit the end?
			blt--	injctit2						; Continue until we have copied all...
			
			lis		r3,0x0FFF						; Build our magic trap
			ori		r3,r3,0xC9C9					; Build our magic trap
			std		r31,ijsave(r29)					; Save the original savearea for injection
			stwx	r3,r5,r26						; Save the magic trap

			dcbf	0,r26							; Flush the line
			sync									; Hang on until it's done
			
			icbi	0,r26							; Flush instructions in the line
			isync									; Throw anything stale away
			sync									; Hang on until it's done
			b		injected2						; Skip the savearea release...
			
noinject3:	bl		EXT(save_ret_phys)				; Put it on the free list			

injected2:	lwz		r3,savesrr1+4(r31)				; Pass in the MSR we will be going to
			bl		EXT(switchSegs)					; Go handle the segment registers/STB

			ld		r8,savesrr1(r31)				; Get destination MSR
			cmplw	cr3,r14,r14						; Set that we do not need to stop streams
			li		r21,emfp0						; Point to a workarea

			ld		r25,savesrr0(r31)				; Get the SRR0 to use
			la		r28,saver16(r31)				; Point to the 128-byte line with r16-r31
			dcbz128	r21,r29							; Clear a work area
			ld		r0,saver0(r31)					; Restore R0			
			dcbt	0,r28							; Touch in r16-r31 
			ld		r1,saver1(r31)					; Restore R1	
			
			beq++	cr4,noinject4					; No code injection here...
			
;
;			If we are injecting, we need to stay in supervisor state with instruction
;			address translation off.  We also need to have as few potential interruptions as
;			possible.  Therefore, we turn off external interruptions and tracing (which doesn't
;			make much sense anyway).
;
			ori		r8,r8,lo16(ijemoff)				; Force the need-to-be-off bits on
			mr		r25,r26							; Point pc to injection code buffer
			xori	r8,r8,lo16(ijemoff)				; Turn off all of the need-to-be-off bits
			
noinject4:	ld		r2,saver2(r31)					; Restore R2	
			ld		r3,saver3(r31)					; Restore R3
			mtcrf	0x80,r27						; Get facility availability flags (do not touch CR1-7)
			ld		r4,saver4(r31)					; Restore R4
			mtsrr0	r25								; Restore the SRR0 now
			ld		r5,saver5(r31)					; Restore R5
			mtsrr1	r8								; Restore the SRR1 now 
			ld		r6,saver6(r31)					; Restore R6			
						
			ld		r7,saver7(r31)					; Restore R7
			ld		r8,saver8(r31)					; Restore R8	
			ld		r9,saver9(r31)					; Restore R9
            
			la		r28,savevscr(r31)				; Point to the status area
            		
			ld		r10,saver10(r31)				; Restore R10
			ld		r11,saver11(r31)				; Restore R11			
			ld		r12,saver12(r31)				; Restore R12
			ld		r13,saver13(r31)				; Restore R13			

			ld		r26,next_savearea(r29)			; Get the exception save area

			ld		r14,saver14(r31)				; Restore R14	
			ld		r15,saver15(r31)				; Restore R15			
			lwz		r27,savevrsave(r31)				; Get the vrsave
			
			bf--	pfAltivecb,noavec2s				; Skip if no VMX...
			
			stvxl	v0,r21,r29						; Save a vector register
			lvxl	v0,0,r28						; Get the vector status
			mtvscr	v0								; Set the vector status

			lvxl	v0,r21,r29						; Restore work vector register
		
noavec2s:	mtspr	vrsave,r27						; Set the vrsave

			lwz		r28,saveexception(r31)			; Get exception type
			stfd	f0,emfp0(r29)					; Save FP0
			lfd		f0,savefpscrpad(r31)			; Get the fpscr
			mtfsf	0xFF,f0							; Restore fpscr		
			lfd		f0,emfp0(r29)					; Restore the used register
			ld		r16,saver16(r31)				; Restore R16
			lwz		r30,spcFlags(r29)				; Get the special flags from per_proc
			ld		r17,saver17(r31)				; Restore R17
			ld		r18,saver18(r31)				; Restore R18	
			cmplwi	cr1,r28,T_RESET					; Are we returning from a reset?
			ld		r19,saver19(r31)				; Restore R19	
			ld		r20,saver20(r31)				; Restore R20
			li		r27,0							; Get a zero
			ld		r21,saver21(r31)				; Restore R21
			la		r26,saver0(r26)					; Point to the first part of the next savearea
			andis.	r30,r30,hi16(perfMonitor)		; Is the performance monitor enabled?
			ld		r22,saver22(r31)				; Restore R22
			ld		r23,saver23(r31)				; Restore R23
			bne++	cr1,er64rrst					; We are not returning from a reset...
			stw		r27,lo16(EXT(ResetHandler)-EXT(ExceptionVectorsStart)+RESETHANDLER_TYPE)(br0)	; Allow resets again

er64rrst:	ld		r24,saver24(r31)				; Restore R24			

			dcbz128	0,r26							; Clear and allocate next savearea we use in the off chance it is still in when we next interrupt

			ld		r25,saver25(r31)				; Restore R25			
			ld		r26,saver26(r31)				; Restore R26		
			ld		r27,saver27(r31)				; Restore R27			

			beq++	noPerfMonRestore64				; Nope... 

			lwz		r28,savepmc+0(r31)
			lwz		r29,savepmc+4(r31)
			mtspr	pmc1_gp,r28						; Restore PMC1 
			mtspr	pmc2_gp,r29						; Restore PMC2 
			lwz		r28,savepmc+8(r31)
			lwz		r29,savepmc+12(r31)
			mtspr	pmc3_gp,r28						; Restore PMC3
			mtspr	pmc4_gp,r29						; Restore PMC4
			lwz		r28,savepmc+16(r31)
			lwz		r29,savepmc+20(r31)
			mtspr	pmc5_gp,r28						; Restore PMC5 
			mtspr	pmc6_gp,r29						; Restore PMC6 
			lwz		r28,savepmc+24(r31)
			lwz		r29,savepmc+28(r31)
			mtspr	pmc7_gp,r28						; Restore PMC7
			mtspr	pmc8_gp,r29						; Restore PMC8
			ld		r28,savemmcr1(r31)
			ld		r29,savemmcr2(r31)
			mtspr	mmcr1_gp,r28					; Restore MMCR1
			mtspr	mmcra_gp,r29					; Restore MMCRA
			ld		r28,savemmcr0(r31)
			
			mtspr	mmcr0_gp,r28					; Restore MMCR0

noPerfMonRestore64:		
			mfsprg	r30,0							; Get per_proc
			lwz		r28,savecr(r31)					; Get CR to restore
			ld		r29,savexer(r31)				; Get XER to restore
			mtcr	r28								; Restore the CR
			ld		r28,savelr(r31)					; Get LR to restore
			mtxer	r29								; Restore the XER
			ld		r29,savectr(r31)				; Get the CTR to restore
			mtlr	r28								; Restore the LR 
			ld		r28,saver30(r31)				; Get R30
			mtctr	r29								; Restore the CTR
			ld		r29,saver31(r31)				; Get R31
			mtspr	hsprg0,r28						; Save R30 for later
			ld		r28,saver28(r31)				; Restore R28			
			mtsprg	3,r29							; Save R31 for later
			ld		r29,saver29(r31)				; Restore R29

			lwz		r31,pfAvailable(r30)			; Get the feature flags
			ld		r30,UAW(r30)					; Get the User Assist DoubleWord
			mtsprg	2,r31							; Set the feature flags
			mfsprg	r31,3							; Restore R31
			mtsprg	3,r30							; Set the UAW
			mfspr	r30,hsprg0						; Restore R30

			rfid									; Click heels three times and think very hard that there is no place like home...


	
/*
 * exception_exit(savearea *)
 *
 *
 * ENTRY :	IR and/or DR and/or interruptions can be on
 *			R3 points to the virtual address of a savearea
 */
	
			.align	5
			.globl	EXT(exception_exit)

LEXT(exception_exit)

			mfsprg	r29,2							; Get feature flags
			mr		r31,r3							; Get the savearea in the right register 
			mtcrf	0x04,r29						; Set the features			
			li		r0,1							; Get this just in case		
			mtcrf	0x02,r29						; Set the features			
			lis		r30,hi16(MASK(MSR_VEC)|MASK(MSR_FP)|MASK(MSR_ME))	; Set up the MSR we will use throughout. Note that ME come on here if MCK
			rlwinm	r4,r3,0,0,19					; Round down to savearea block base
			lis		r1,hi16(SAVredrive)				; Get redrive request
			mfsprg	r2,0							; Get the per_proc block
			ori		r30,r30,lo16(MASK(MSR_VEC)|MASK(MSR_FP)|MASK(MSR_ME))	; Rest of MSR
			bt++	pf64Bitb,eeSixtyFour			; We are 64-bit...
			
			lwz		r4,SACvrswap+4(r4)				; Get the virtual to real translation
			
			bt		pfNoMSRirb,eeNoMSR				; No MSR...

			mtmsr	r30								; Translation and all off
			isync									; Toss prefetch
			b		eeNoMSRx
			
			.align	5
			
eeSixtyFour:
			ld		r4,SACvrswap(r4)				; Get the virtual to real translation
			rldimi	r30,r0,63,MSR_SF_BIT			; Set SF bit (bit 0)
			mtmsrd	r30								; Set 64-bit mode, turn off EE, DR, and IR
			isync									; Toss prefetch
			b		eeNoMSRx
			
			.align	5
			
eeNoMSR:	li		r0,loadMSR						; Get the MSR setter SC
			mr		r3,r30							; Get new MSR
			sc										; Set it

eeNoMSRx:	xor		r31,r31,r4						; Convert the savearea to physical addressing
			lwz		r4,SAVflags(r31)				; Pick up the flags
			mr		r13,r31							; Put savearea here also

			and.	r0,r4,r1						; Check if redrive requested
			
			dcbt	br0,r2							; We will need this in just a sec

			beq+	EatRupt							; No redrive, just exit...

0:			mftbu	r2								; Avoid using an obsolete timestamp for the redrive
			mftb	r4
			mftbu	r0
			cmplw	r0,r2
			bne--	0b

			stw		r2,SAVtime(r13)
			stw		r4,SAVtime+4(r13)

			lwz		r11,saveexception(r13)			; Restore exception code
			b		Redrive							; Redrive the exception...


		
			.align	12								; Force page alignment

			.globl EXT(ExceptionVectorsEnd)
EXT(ExceptionVectorsEnd):							/* Used if relocating the exception vectors */




;
;			Here is where we keep the low memory globals
;

			. = 0x5000
			
			.ascii	"Hagfish "						; 5000 Unique eyecatcher
			.long	0								; 5008 Zero
			.long	0								; 500C Zero cont...
			.long	EXT(PerProcTable)				; 5010 pointer to per_proc_entry table
			.long	0								; 5014 Zero

			.globl	EXT(mckFlags)
EXT(mckFlags):
			.long	0								; 5018 Machine check flags
			
			.long	EXT(version)					; 501C Pointer to kernel version string
			.long	0								; 5020 physical memory window virtual address
			.long	0								; 5024 physical memory window virtual address
			.long	0								; 5028 user memory window virtual address
			.long	0								; 502C user memory window virtual address
			.long	0								; 5030 VMM boot-args forced feature flags

			.globl	EXT(maxDec)
EXT(maxDec):
			.long	0x7FFFFFFF						; 5034 maximum decrementer value
			

			.globl	EXT(pmsCtlp)
EXT(pmsCtlp):
			.long	0								; 5038 Pointer to power management stepper control
			
			.long	0								; 503C reserved
			.long	0								; 5040 reserved
			.long	0								; 5044 reserved
			.long	0								; 5048 reserved
			.long	0								; 504C reserved
			.long	0								; 5050 reserved
			.long	0								; 5054 reserved
			.long	0								; 5058 reserved
			.long	0								; 505C reserved
			.long	0								; 5060 reserved
			.long	0								; 5064 reserved
			.long	0								; 5068 reserved
			.long	0								; 506C reserved
			.long	0								; 5070 reserved
			.long	0								; 5074 reserved
			.long	0								; 5078 reserved
			.long	0								; 507C reserved

			.globl	EXT(trcWork)
EXT(trcWork):
			.long	0								; 5080 The next trace entry to use
#if DEBUG
			.long	0xFFFFFFFF 						; 5084 All enabled 
#else
			.long	0x00000000						; 5084 All disabled on non-debug systems
#endif
			.long	0								; 5088 Start of the trace table
			.long	0								; 508C End (wrap point) of the trace
			.long	0								; 5090 Saved mask while in debugger
			.long	0								; 5094 Size of trace table (1 - 256 pages)
			.long	0								; 5098 traceGas[0]
			.long	0								; 509C traceGas[1]

			.long	0								; 50A0 reserved			
			.long	0								; 50A4 reserved			
			.long	0								; 50A8 reserved			
			.long	0								; 50AC reserved			
			.long	0								; 50B0 reserved			
			.long	0								; 50B4 reserved			
			.long	0								; 50B8 reserved			
			.long	0								; 50BC reserved			
			.long	0								; 50C0 reserved			
			.long	0								; 50C4 reserved			
			.long	0								; 50C8 reserved			
			.long	0								; 50CC reserved			
			.long	0								; 50D0 reserved			
			.long	0								; 50D4 reserved			
			.long	0								; 50D8 reserved			
			.long	0								; 50DC reserved			
			.long	0								; 50E0 reserved			
			.long	0								; 50E4 reserved			
			.long	0								; 50E8 reserved			
			.long	0								; 50EC reserved			
			.long	0								; 50F0 reserved			
			.long	0								; 50F4 reserved			
			.long	0								; 50F8 reserved			
			.long	0								; 50FC reserved			

			.globl	EXT(saveanchor)

EXT(saveanchor):									; 5100 saveanchor
			.set	.,.+SVsize
			
			.long	0								; 5140 reserved
			.long	0								; 5144 reserved
			.long	0								; 5148 reserved
			.long	0								; 514C reserved
			.long	0								; 5150 reserved
			.long	0								; 5154 reserved
			.long	0								; 5158 reserved
			.long	0								; 515C reserved
			.long	0								; 5160 reserved
			.long	0								; 5164 reserved
			.long	0								; 5168 reserved
			.long	0								; 516C reserved
			.long	0								; 5170 reserved
			.long	0								; 5174 reserved
			.long	0								; 5178 reserved
			.long	0								; 517C reserved
			
			.long	0								; 5180 tlbieLock

			.long	0								; 5184 reserved
			.long	0								; 5188 reserved
			.long	0								; 518C reserved
			.long	0								; 5190 reserved
			.long	0								; 5194 reserved
			.long	0								; 5198 reserved
			.long	0								; 519C reserved
			.long	0								; 51A0 reserved			
			.long	0								; 51A4 reserved			
			.long	0								; 51A8 reserved			
			.long	0								; 51AC reserved			
			.long	0								; 51B0 reserved			
			.long	0								; 51B4 reserved			
			.long	0								; 51B8 reserved			
			.long	0								; 51BC reserved			
			.long	0								; 51C0 reserved			
			.long	0								; 51C4 reserved			
			.long	0								; 51C8 reserved			
			.long	0								; 51CC reserved			
			.long	0								; 51D0 reserved			
			.long	0								; 51D4 reserved			
			.long	0								; 51D8 reserved			
			.long	0								; 51DC reserved			
			.long	0								; 51E0 reserved			
			.long	0								; 51E4 reserved			
			.long	0								; 51E8 reserved			
			.long	0								; 51EC reserved			
			.long	0								; 51F0 reserved			
			.long	0								; 51F4 reserved			
			.long	0								; 51F8 reserved			
			.long	0								; 51FC reserved	
			
			.globl	EXT(dgWork)
			
EXT(dgWork):
			.long	0								; 5200 dgLock
			.long	0								; 5204 dgFlags		
			.long	0								; 5208 dgMisc0		
			.long	0								; 520C dgMisc1		
			.long	0								; 5210 dgMisc2		
			.long	0								; 5214 dgMisc3		
			.long	0								; 5218 dgMisc4		
			.long	0								; 521C dgMisc5	

			.globl	EXT(LcksOpts)
EXT(LcksOpts):
			.long	0								; 5220 lcksWork
			.long	0								; 5224 reserved
			.long	0								; 5228 reserved
			.long	0								; 522C reserved
			.long	0								; 5230 reserved
			.long	0								; 5234 reserved
			.long	0								; 5238 reserved
			.long	0								; 523C reserved
			.long	0								; 5240 reserved
			.long	0								; 5244 reserved
			.long	0								; 5248 reserved
			.long	0								; 524C reserved
			.long	0								; 5250 reserved
			.long	0								; 5254 reserved
			.long	0								; 5258 reserved
			.long	0								; 525C reserved
			.long	0								; 5260 reserved
			.long	0								; 5264 reserved
			.long	0								; 5268 reserved
			.long	0								; 526C reserved
			.long	0								; 5270 reserved
			.long	0								; 5274 reserved
			.long	0								; 5278 reserved
			.long	0								; 527C reserved
			
			.globl	EXT(pPcfg)
EXT(pPcfg):
			.long	0x80000000 | (12 << 8) | 12		; 5280 pcfDefPcfg - 4k
			.long	0								; 5284 pcfLargePcfg
			.long	0								; 5288 Non-primary page configurations
			.long	0								; 528C Non-primary page configurations
			.long	0								; 5290 Non-primary page configurations
			.long	0								; 5294 Non-primary page configurations
			.long	0								; 5298 Non-primary page configurations
			.long	0								; 529C Non-primary page configurations
			
			.long	0								; 52A0 reserved			
			.long	0								; 52A4 reserved			
			.long	0								; 52A8 reserved			
			.long	0								; 52AC reserved			
			.long	0								; 52B0 reserved			
			.long	0								; 52B4 reserved			
			.long	0								; 52B8 reserved			
			.long	0								; 52BC reserved			
			.long	0								; 52C0 reserved			
			.long	0								; 52C4 reserved			
			.long	0								; 52C8 reserved			
			.long	0								; 52CC reserved			
			.long	0								; 52D0 reserved			
			.long	0								; 52D4 reserved			
			.long	0								; 52D8 reserved			
			.long	0								; 52DC reserved			
			.long	0								; 52E0 reserved			
			.long	0								; 52E4 reserved			
			.long	0								; 52E8 reserved			
			.long	0								; 52EC reserved			
			.long	0								; 52F0 reserved			
			.long	0								; 52F4 reserved			
			.long	0								; 52F8 reserved			
			.long	0								; 52FC reserved	

			.globl	EXT(killresv)
EXT(killresv):

			.long	0								; 5300 Used to kill reservations
			.long	0								; 5304 Used to kill reservations
			.long	0								; 5308 Used to kill reservations
			.long	0								; 530C Used to kill reservations
			.long	0								; 5310 Used to kill reservations
			.long	0								; 5314 Used to kill reservations
			.long	0								; 5318 Used to kill reservations
			.long	0								; 531C Used to kill reservations
			.long	0								; 5320 Used to kill reservations
			.long	0								; 5324 Used to kill reservations
			.long	0								; 5328 Used to kill reservations
			.long	0								; 532C Used to kill reservations
			.long	0								; 5330 Used to kill reservations
			.long	0								; 5334 Used to kill reservations
			.long	0								; 5338 Used to kill reservations
			.long	0								; 533C Used to kill reservations
			.long	0								; 5340 Used to kill reservations
			.long	0								; 5344 Used to kill reservations
			.long	0								; 5348 Used to kill reservations
			.long	0								; 534C Used to kill reservations
			.long	0								; 5350 Used to kill reservations
			.long	0								; 5354 Used to kill reservations
			.long	0								; 5358 Used to kill reservations
			.long	0								; 535C Used to kill reservations
			.long	0								; 5360 Used to kill reservations
			.long	0								; 5364 Used to kill reservations
			.long	0								; 5368 Used to kill reservations
			.long	0								; 536C Used to kill reservations
			.long	0								; 5370 Used to kill reservations
			.long	0								; 5374 Used to kill reservations
			.long	0								; 5378 Used to kill reservations
			.long	0								; 537C Used to kill reservations
			
			.long	0								; 5380 reserved
			.long	0								; 5384 reserved
			.long	0								; 5388 reserved
			.long	0								; 538C reserved
			.long	0								; 5390 reserved
			.long	0								; 5394 reserved
			.long	0								; 5398 reserved
			.long	0								; 539C reserved
			.long	0								; 53A0 reserved			
			.long	0								; 53A4 reserved			
			.long	0								; 53A8 reserved			
			.long	0								; 53AC reserved			
			.long	0								; 53B0 reserved			
			.long	0								; 53B4 reserved			
			.long	0								; 53B8 reserved			
			.long	0								; 53BC reserved			
			.long	0								; 53C0 reserved			
			.long	0								; 53C4 reserved			
			.long	0								; 53C8 reserved			
			.long	0								; 53CC reserved			
			.long	0								; 53D0 reserved			
			.long	0								; 53D4 reserved			
			.long	0								; 53D8 reserved			
			.long	0								; 53DC reserved			
			.long	0								; 53E0 reserved			
			.long	0								; 53E4 reserved			
			.long	0								; 53E8 reserved			
			.long	0								; 53EC reserved			
			.long	0								; 53F0 reserved			
			.long	0								; 53F4 reserved			
			.long	0								; 53F8 reserved			
			.long	0								; 53FC reserved	
			.long	0								; 5400 reserved
			.long	0								; 5404 reserved
			.long	0								; 5408 reserved
			.long	0								; 540C reserved
			.long	0								; 5410 reserved
			.long	0								; 5414 reserved
			.long	0								; 5418 reserved
			.long	0								; 541C reserved
			.long	0								; 5420 reserved			
			.long	0								; 5424 reserved			
			.long	0								; 5428 reserved			
			.long	0								; 542C reserved			
			.long	0								; 5430 reserved			
			.long	0								; 5434 reserved			
			.long	0								; 5438 reserved			
			.long	0								; 543C reserved			
			.long	0								; 5440 reserved			
			.long	0								; 5444 reserved			
			.long	0								; 5448 reserved			
			.long	0								; 544C reserved			
			.long	0								; 5450 reserved			
			.long	0								; 5454 reserved			
			.long	0								; 5458 reserved			
			.long	0								; 545C reserved			
			.long	0								; 5460 reserved			
			.long	0								; 5464 reserved			
			.long	0								; 5468 reserved			
			.long	0								; 546C reserved			
			.long	0								; 5470 reserved			
			.long	0								; 5474 reserved			
			.long	0								; 5478 reserved			
			.long	0								; 547C reserved
			.long	EXT(kmod)						; 5480 Pointer to kmod, debugging aid
			.long	EXT(kdp_trans_off)				; 5484 Pointer to kdp_trans_off, debugging aid
			.long	EXT(kdp_read_io)				; 5488 Pointer to kdp_read_io, debugging aid
			.long	0								; 548C Reserved for developer use
			.long	0								; 5490 Reserved for developer use
			.long	EXT(osversion)					; 5494	Pointer to osversion string, debugging aid
			.long	EXT(flag_kdp_trigger_reboot)					; 5498	Pointer to KDP reboot trigger, debugging aid

;
;	The "shared page" is used for low-level debugging and is actually 1/2 page long
;

			. = 0x6000
			.globl	EXT(sharedPage)

EXT(sharedPage):									; This is a debugging page shared by all processors
			.long	0xC24BC195						; Comm Area validity value 
			.long	0x87859393						; Comm Area validity value 
			.long	0xE681A2C8						; Comm Area validity value 
			.long	0x8599855A						; Comm Area validity value 
			.long	0xD74BD296						; Comm Area validity value 
			.long	0x8388E681						; Comm Area validity value 
			.long	0xA2C88599						; Comm Area validity value 
			.short	0x855A							; Comm Area validity value 
			.short	1								; Comm Area version number
			.fill	504*4,1,0						; (filled with 0s)

;
;	The ijcode area is used for code injection.  It is 1/2 page long and will allow 32 processors to inject
;	16 instructions each concurrently.
;

			.globl	EXT(ijcode)

EXT(ijcode):										; Code injection area
			.fill	512*4,1,0						; 6800 32x64 slots for code injection streams

	.data
	.align	ALIGN
	.globl	EXT(exception_end)
EXT(exception_end):
	.long	EXT(ExceptionVectorsEnd) -EXT(ExceptionVectorsStart) /* phys fn */



