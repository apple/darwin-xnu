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

/* Low level routines dealing with exception entry and exit.
 * There are various types of exception:
 *
 *    Interrupt, trap, system call and debugger entry. Each has it's own
 *    handler since the state save routine is different for each. The
 *    code is very similar (a lot of cut and paste).
 *
 *    The code for the FPU disabled handler (lazy fpu) is in cswtch.s
 */

#include <debug.h>
#include <mach_assert.h>
#include <mach/exception_types.h>
#include <mach/kern_return.h>
#include <mach/ppc/vm_param.h>

#include <assym.s>

#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/trap.h>
#include <ppc/exception.h>
#include <ppc/savearea.h>
#include <ppc/spl.h>


#define VERIFYSAVE 0
#define FPVECDBG 0
#define INSTRUMENT 0

/*
 * thandler(type)
 *
 * ENTRY:	VM switched ON
 *			Interrupts  OFF
 *			R3 contains exception code
 *			R4 points to the saved context (virtual address)
 *			Everything is saved in savearea
 */

/*
 * If pcb.ksp == 0 then the kernel stack is already busy,
 *         we make a stack frame
 *		   leaving enough space for the 'red zone' in case the
 *		   trapped thread was in the middle of saving state below
 *		   its stack pointer.
 *
 * otherwise       we make a stack frame and
 * 		   the kernel stack (setting pcb.ksp to 0)
 *
 * on return, we do the reverse, the last state is popped from the pcb
 * and pcb.ksp is set to the top of stack                  
 */

/* TRAP_SPACE_NEEDED is the space assumed free on the kernel stack when
 * another trap is taken. We need at least enough space for a saved state
 * structure plus two small backpointer frames, and we add a few
 * hundred bytes for the space needed by the C (which may be less but
 * may be much more). We're trying to catch kernel stack overflows :-)
 */

#define TRAP_SPACE_NEEDED	FM_REDZONE+(2*FM_SIZE)+256

			.text

			.align	5
			.globl EXT(thandler)
LEXT(thandler)										; Trap handler

			mfsprg	r25,0							; Get the per_proc 
		
			lwz		r1,PP_ISTACKPTR(r25)			; Get interrupt stack pointer
	
			mfsprg	r13,1							; Get the current thread
			cmpwi	cr0,r1,0						; Are we on interrupt stack?					
			lwz		r6,ACT_THREAD(r13)				; Get the shuttle
			beq-	cr0,EXT(ihandler)				; If on interrupt stack, treat this as interrupt...
			lwz		r26,ACT_MACT_SPF(r13)			; Get special flags
			lwz		r8,ACT_MACT_PCB(r13)			; Get the last savearea used
			rlwinm.	r26,r26,0,bbThreadbit,bbThreadbit	; Do we have Blue Box Assist active? 
			lwz		r1,ACT_MACT_KSP(r13)			; Get the top of kernel stack
			bnel-	checkassist						; See if we should assist this
			stw		r4,ACT_MACT_PCB(r13)			; Point to our savearea
			stw		r8,SAVprev+4(r4)				; Queue the new save area in the front 
			
#if VERIFYSAVE
			bl		versave							; (TEST/DEBUG)
#endif
			
			lwz		r9,THREAD_KERNEL_STACK(r6)		; Get our kernel stack start
			cmpwi	cr1,r1,0						; Are we already on kernel stack?
			stw		r13,SAVact(r4)					; Mark the savearea as belonging to this activation
			lwz		r26,saver1+4(r4)				; Get the stack at interrupt time

			bne+	cr1,.L_kstackfree				; We are not on kernel stack yet...		

			subi	r1,r26,FM_REDZONE				; Make a red zone on interrupt time kernel stack

.L_kstackfree:
			lwz		r7,savesrr1+4(r4)				; Pick up the entry MSR 
			sub		r9,r1,r9						; Get displacment into the kernel stack
			li		r0,0							; Make this 0
			rlwinm.	r0,r9,0,28,31					; Verify that we have a 16-byte aligned stack (and get a 0)
			cmplwi	cr2,r9,KERNEL_STACK_SIZE		; Do we still have room on the stack?
			beq		cr1,.L_state_on_kstack			; using above test for pcb/stack

			stw		r0,ACT_MACT_KSP(r13)			; Show that we have taken the stack

.L_state_on_kstack:	
			lwz		r9,savevrsave(r4)				; Get the VRSAVE register
			bne--	kernelStackUnaligned			; Stack is unaligned...
			rlwinm.	r6,r7,0,MSR_VEC_BIT,MSR_VEC_BIT	; Was vector on?
			subi	r1,r1,FM_SIZE					; Push a header onto the current stack 
			bgt--	cr2,kernelStackBad				; Kernel stack is bogus...

kernelStackNotBad:									; Vector was off
			beq++	tvecoff							; Vector off, do not save vrsave...
			stw		r9,liveVRS(r25)					; Set the live value

tvecoff:	stw		r26,FM_BACKPTR(r1)				; Link back to the previous frame

#if	DEBUG
/* If debugging, we need two frames, the first being a dummy
 * which links back to the trapped routine. The second is
 * that which the C routine below will need
 */
			lwz		r3,savesrr0+4(r4)				; Get the point of interruption
			stw		r3,FM_LR_SAVE(r1)				; save old instr ptr as LR value 
			stwu	r1,	-FM_SIZE(r1)				; and make new frame 
#endif /* DEBUG */


/* call trap handler proper, with
 *   ARG0 = type		(not yet, holds pcb ptr)
 *   ARG1 = saved_state ptr	(already there)
 *   ARG2 = dsisr		(already there)
 *   ARG3 = dar			(already there)
 */


			lwz		r3,saveexception(r4)			; Get the exception code 
			lwz		r0,ACT_MACT_SPF(r13)			; Get the special flags
			
			addi	r5,r3,-T_DATA_ACCESS			; Adjust to start of range
			rlwinm.	r0,r0,0,runningVMbit,runningVMbit	; Are we in VM state? (cr0_eq == 0 if yes)
			cmplwi	cr2,r5,T_TRACE-T_DATA_ACCESS	; Are we still in range? (cr_gt if not)
			
			lwz		r5,savedsisr(r4)				; Get the saved DSISR
			
			crnor	cr7_eq,cr0_eq,cr2_gt			; We should intercept if in VM and is a true trap (cr7_eq == 1 if yes)
			rlwinm.	r0,r7,0,MSR_PR_BIT,MSR_PR_BIT	; Are we trapping from supervisor state? (cr0_eq == 1 if yes)

			cmpi	cr2,r3,T_PREEMPT				; Is this a preemption?

			beq--	.L_check_VM
			stw		r4,ACT_MACT_UPCB(r13)			; Store user savearea
.L_check_VM:
			
			crandc	cr0_eq,cr7_eq,cr0_eq			; Do not intercept if we are in the kernel (cr0_eq == 1 if yes)
			
			lwz		r6,savedar(r4)					; Get the DAR (top)
			lwz		r7,savedar+4(r4)				; Get the DAR (bottom)
	
			beq-	cr2,.L_call_trap				; Do not turn on interrupts for T_PREEMPT
			beq-	exitFromVM						; Any true trap but T_MACHINE_CHECK exits us from the VM...

/* syscall exception might warp here if there's nothing left
 * to do except generate a trap
 */

.L_call_trap:	

			bl	EXT(trap)

			lis		r10,hi16(MASK(MSR_VEC))			; Get the vector enable
			mfmsr	r7								; Get the MSR
			ori		r10,r10,lo16(MASK(MSR_FP)|MASK(MSR_EE))	; Add in FP and EE
			andc	r7,r7,r10						; Turn off VEC, FP, and EE
			mtmsr	r7								; Disable for interrupts
			mfsprg	r10,0							; Restore the per_proc info
/*
 * This is also the point where new threads come when they are created.
 * The new thread is setup to look like a thread that took an 
 * interrupt and went immediatly into trap.
 */

thread_return:
			lwz		r11,SAVflags(r3)				; Get the flags of the current savearea
			lwz		r0,savesrr1+4(r3)				; Get the MSR we are going to
			lwz		r4,SAVprev+4(r3)				; Pick up the previous savearea 
			mfsprg	r8,1							; Get the current thread
			rlwinm	r11,r11,0,15,13					; Clear the syscall flag
			rlwinm.	r0,r0,0,MSR_PR_BIT,MSR_PR_BIT	; Are we going to the user?
			lwz		r1,ACT_THREAD(r8)				; Get the shuttle
			stw		r11,SAVflags(r3)				; Save back the flags (with reset stack cleared) 
			
			lwz		r5,THREAD_KERNEL_STACK(r1)		; Get the base pointer to the stack 
			stw		r4,ACT_MACT_PCB(r8)				; Point to the previous savearea (or 0 if none)
			addi	r5,r5,KERNEL_STACK_SIZE-FM_SIZE	; Reset to empty 

			beq--	chkfac							; We are not leaving the kernel yet...

			stw		r5,ACT_MACT_KSP(r8)				; Save the empty stack pointer 
			b		chkfac							; Go end it all...


;
;			Here is where we go when we detect that the kernel stack is all messed up.
;			We just try to dump some info and get into the debugger.
;

kernelStackBad:

			lwz		r3,PP_DEBSTACK_TOP_SS(r25)		; Pick up debug stack top
			subi	r3,r3,KERNEL_STACK_SIZE-FM_SIZE	; Adjust to start of stack
			sub		r3,r1,r3						; Get displacement into debug stack
			cmplwi	cr2,r3,KERNEL_STACK_SIZE-FM_SIZE	; Check if we are on debug stack
			blt+	cr2,kernelStackNotBad			; Yeah, that is ok too...

			lis		r0,hi16(Choke)					; Choke code
			ori		r0,r0,lo16(Choke)				; and the rest
			li		r3,failStack					; Bad stack code
			sc										; System ABEND

kernelStackUnaligned:
			lis		r0,hi16(Choke)					; Choke code
			ori		r0,r0,lo16(Choke)				; and the rest
			li		r3,failUnalignedStk				; Unaligned stack code
			sc										; System ABEND


/*
 * shandler(type)
 *
 * ENTRY:	VM switched ON
 *			Interrupts  OFF
 *			R3 contains exception code
 *			R4 points to the saved context (virtual address)
 *			Everything is saved in savearea
 */

/*
 * If pcb.ksp == 0 then the kernel stack is already busy,
 *                 this is an error - jump to the debugger entry
 * 
 * otherwise       depending upon the type of
 *                 syscall, look it up in the kernel table
 *		   		   or pass it to the server.
 *
 * on return, we do the reverse, the state is popped from the pcb
 * and pcb.ksp is set to the top of stack.
 */
 
/*
 *	NOTE:
 *		mach system calls are negative
 *		BSD system calls are low positive
 *		PPC-only system calls are in the range 0x6xxx
 *		PPC-only "fast" traps are in the range 0x7xxx
 */
 
			.align	5
			.globl EXT(shandler)
LEXT(shandler)										; System call handler

			lwz		r7,savesrr1+4(r4)				; Get the SRR1 value
			mfsprg	r25,0							; Get the per proc area 
			lwz		r0,saver0+4(r4)					; Get the original syscall number
			lwz		r17,PP_ISTACKPTR(r25)			; Get interrupt stack pointer
			mfsprg	r13,1							; Get the current thread 
			rlwinm	r15,r0,0,0,19					; Clear the bottom of call number for fast check
			mr.		r17,r17							; Are we on interrupt stack?
			lwz		r9,savevrsave(r4)				; Get the VRsave register
			beq--	EXT(ihandler)					; On interrupt stack, not allowed...
			rlwinm.	r6,r7,0,MSR_VEC_BIT,MSR_VEC_BIT	; Was vector on?
			lwz		r16,ACT_THREAD(r13)				; Get the shuttle

			beq++	svecoff							; Vector off, do not save vrsave...
			stw		r9,liveVRS(r25)					; Set the live value
;
; 			Check if SCs are being redirected for the BlueBox or to VMM
;

svecoff:	lwz		r6,ACT_MACT_SPF(r13)			; Pick up activation special flags
			mtcrf	0x40,r6							; Check special flags
			mtcrf	0x01,r6							; Check special flags
			crmove	cr6_eq,runningVMbit				; Remember if we are in VMM
			bne++	cr6,sVMchecked					; Not running VM
			lwz		r18,spcFlags(r25)				; Load per_proc special flags
			rlwinm. r18,r18,0,FamVMmodebit,FamVMmodebit	; Is FamVMmodebit set?
			beq		sVMchecked						; Not in FAM
			cmpwi	r0,0x6004						; Is it vmm_dispatch syscall:
			bne		sVMchecked
			lwz		r26,saver3+4(r4)				; Get the original syscall number
			cmpwi	cr6,r26,kvmmExitToHost			; vmm_exit_to_host request
sVMchecked:
			bf++	bbNoMachSCbit,noassist			; Take branch if SCs are not redirected
			lwz		r26,ACT_MACT_BEDA(r13)			; Pick up the pointer to the blue box exception area
			b		EXT(atomic_switch_syscall)		; Go to the assist...

noassist:	cmplwi	r15,0x7000						; Do we have a fast path trap? 
			lwz		r14,ACT_MACT_PCB(r13)			; Now point to the PCB 
			beql	fastpath						; We think it is a fastpath... 

			lwz		r1,ACT_MACT_KSP(r13)			; Get the kernel stack pointer 
#if DEBUG
			mr.		r1,r1							; Are we already on the kernel stack? 
			li		r3,T_SYSTEM_CALL				; Yup, pretend we had an interrupt... 
			beq-	EXT(ihandler)					; Bad boy, bad boy... What cha gonna do when they come for you?
#endif /* DEBUG */

			stw		r4,ACT_MACT_PCB(r13)			; Point to our savearea
			stw		r4,ACT_MACT_UPCB(r13)			; Store user savearea
			li		r0,0							; Clear this out 
			stw		r14,SAVprev+4(r4)				; Queue the new save area in the front 
			stw		r13,SAVact(r4)					; Point the savearea at its activation
			
#if VERIFYSAVE
			bl		versave							; (TEST/DEBUG)
#endif			
			
			lwz		r15,saver1+4(r4)				; Grab interrupt time stack 
			mr		r30,r4							; Save pointer to the new context savearea
			stw		r0,ACT_MACT_KSP(r13)			; Mark stack as busy with 0 val 
			stw		r15,FM_BACKPTR(r1)				; Link stack frame backwards
		
#if	DEBUG
/* If debugging, we need two frames, the first being a dummy
 * which links back to the trapped routine. The second is
 * that which the C routine below will need
 */
			lwz		r8,savesrr0+4(r30)				; Get the point of interruption
			stw		r8,FM_LR_SAVE(r1)				; Save old instr ptr as LR value
			stwu	r1,	-FM_SIZE(r1)				; and make new frame
#endif /* DEBUG */

			lwz		r15,SAVflags(r30)				; Get the savearea flags
			lwz		r0,saver0+4(r30)				; Get R0 back
			mfmsr	r11								; Get the MSR
			stwu	r1,-(FM_SIZE+ARG_SIZE)(r1)		; Make a stack frame
			ori		r11,r11,lo16(MASK(MSR_EE))		; Turn on interruption enabled bit
			rlwinm	r10,r0,0,0,19					; Keep only the top part 
			oris	r15,r15,SAVsyscall >> 16 		; Mark that it this is a syscall
			cmplwi	r10,0x6000						; Is it the special ppc-only guy?
			stw		r15,SAVflags(r30)				; Save syscall marker
			beq--	cr6,exitFromVM					; It is time to exit from alternate context...
			
			beq--	ppcscall						; Call the ppc-only system call handler...

			mr.		r0,r0							; What kind is it?
			mtmsr	r11								; Enable interruptions

			blt--	.L_kernel_syscall				; System call number if negative, this is a mach call...
											
			lwz     r8,ACT_TASK(r13)				; Get our task
			cmpwi	cr0,r0,0x7FFA					; Special blue box call?
			beq--	.L_notify_interrupt_syscall		; Yeah, call it...
			
			lwz     r7,TASK_SYSCALLS_UNIX(r8)		; Get the current count
			mr      r3,r30							; Get PCB/savearea
			mr      r4,r13							; current activation
			addi    r7,r7,1							; Bump it
			stw     r7,TASK_SYSCALLS_UNIX(r8)		; Save it
			bl      EXT(unix_syscall)				; Check out unix...

.L_call_server_syscall_exception:		
			li		r3,EXC_SYSCALL					; doexception(EXC_SYSCALL, num, 1)

.L_call_server_exception:
			mr		r4,r0							; Set syscall selector
			li		r5,1
			b		EXT(doexception)				; Go away, never to return...

.L_notify_interrupt_syscall:
			lwz		r3,saver3+4(r30)				; Get the new PC address to pass in
			bl		EXT(syscall_notify_interrupt)
/*
 * Ok, return from C function, R3 = return value
 *
 * saved state is still in R30 and the active thread is in R16	.	
 */
			mr		r31,r16							; Move the current thread pointer
			stw		r3,saver3+4(r30)				; Stash the return code
			b		.L_thread_syscall_ret_check_ast
	
;
;			Handle PPC-only system call interface
;			These are called with interruptions disabled
;			and the savearea/pcb as the first parameter.
;			It is up to the callee to enable interruptions if
;			they should be.  We are in a state here where
;			both interrupts and preemption is ok, but because we could
;			be calling diagnostic code we will not enable.
;			
;			Also, the callee is responsible for finding any parameters
;			in the savearea/pcb. It also must set saver3 with any return
;			code before returning.
;
;			There are 3 possible return codes:
;				0  the call is disabled or something, we treat this like it was bogus
;				+  the call finished ok, check for AST
;				-  the call finished ok, do not check for AST
;
;			Note: the last option is intended for special diagnostics calls that 
;			want the thread to return and execute before checking for preemption.
;
;			NOTE: Both R16 (thread) and R30 (savearea) need to be preserved over this call!!!!
;

			.align	5

ppcscall:	rlwinm	r11,r0,2,18,29					; Make an index into the table
			lis		r10,hi16(EXT(PPCcalls))			; Get PPC-only system call table
			cmplwi	r11,PPCcallmax					; See if we are too big
			ori		r10,r10,lo16(EXT(PPCcalls))		; Merge in low half
			bgt-	.L_call_server_syscall_exception	; Bogus call...
			lwzx	r11,r10,r11						; Get function address
			
;
;			Note: make sure we do not change the savearea in R30 to
;			a different register without checking.  Some of the PPCcalls
;			depend upon it being there.
;
	
			mr		r3,r30							; Pass the savearea
			mr		r4,r13							; Pass the activation
			mr.		r11,r11							; See if there is a function here
			mtctr	r11								; Set the function address
			beq-	.L_call_server_syscall_exception	; Disabled call...
#if INSTRUMENT
			mfspr	r4,pmc1							; Get stamp
			stw		r4,0x6100+(9*16)+0x0(0)			; Save it
			mfspr	r4,pmc2							; Get stamp
			stw		r4,0x6100+(9*16)+0x4(0)			; Save it
			mfspr	r4,pmc3							; Get stamp
			stw		r4,0x6100+(9*16)+0x8(0)			; Save it
			mfspr	r4,pmc4							; Get stamp
			stw		r4,0x6100+(9*16)+0xC(0)			; Save it
#endif
			bctrl									; Call it
	
			.globl	EXT(ppcscret)

LEXT(ppcscret)
			mr.		r3,r3							; See what we should do
			mr		r31,r16							; Restore the current thread pointer
			bgt+	.L_thread_syscall_ret_check_ast	; Take normal AST checking return....
			mfsprg	r10,0							; Get the per_proc
			blt+	.L_thread_syscall_return		; Return, but no ASTs....
			lwz		r0,saver0+4(r30)				; Restore the system call number
			b		.L_call_server_syscall_exception	; Go to common exit...



/*
 * we get here for mach system calls
 * when kdebug tracing is enabled
 */
	
ksystrace:	
			mr		r4,r30						; Pass in saved state
			bl      EXT(syscall_trace)
			
			cmplw	r31,r29						; Is this syscall in the table?	
			add		r31,r27,r28					; Point right to the syscall table entry

			bge-	.L_call_server_syscall_exception	; The syscall number is invalid
	
			lwz		r0,MACH_TRAP_FUNCTION(r31)	; Pick up the function address
;
;	NOTE: We do not support more than 8 parameters for PPC.  The only 
;	system call to use more than 8 is mach_msg_overwrite_trap and it
;	uses 9.  We pass a 0 in as number 9.
;
			lwz		r3,saver3+4(r30)  			; Restore r3 
			lwz		r4,saver4+4(r30)  			; Restore r4 
			mtctr	r0							; Set the function call address
			lwz		r5,saver5+4(r30)  			; Restore r5 
			lwz		r6,saver6+4(r30)  			; Restore r6
			lwz		r7,saver7+4(r30)  			; Restore r7
			li		r0,0						; Clear this out
			lwz		r8,saver8+4(r30)  			; Restore r8 
			lwz		r9,saver9+4(r30)  			; Restore r9 
			lwz		r10,saver10+4(r30)  		; Restore r10
			stw		r0,FM_ARG0(r1)				; Clear that 9th parameter just in case some fool uses it
			bctrl								; perform the actual syscall
	
			mr		r4,r30						; Pass in the savearea
			bl		EXT(syscall_trace_end)		; Trace the exit of the system call	
			b		.L_mach_return

	
			
/* Once here, we know that the syscall was -ve
 * we should still have r1=ksp,
 * r16		= pointer to current thread,
 * r13		= pointer to top activation,
 * r0		= syscall number
 * r30		= pointer to saved state (in pcb)
 */

				.align	5

.L_kernel_syscall:	
;
; Call a function that can print out our syscall info 
; Note that we don t care about any volatiles yet
;
			lwz		r10,ACT_TASK(r13)			; Get our task 
			lwz		r0,saver0+4(r30)
			lis		r8,hi16(EXT(kdebug_enable))	; Get top of kdebug_enable 
			lis		r28,hi16(EXT(mach_trap_table))	; Get address of table
			ori		r8,r8,lo16(EXT(kdebug_enable))	; Get bottom of kdebug_enable 
			lwz		r8,0(r8)					; Get kdebug_enable 

			lwz		r7,TASK_SYSCALLS_MACH(r10)	; Get the current count
			neg		r31,r0						; Make this positive
			slwi	r27,r31,MACH_TRAP_OFFSET_POW2	; Convert index to offset
			ori		r28,r28,lo16(EXT(mach_trap_table))	; Get address of table
			addi	r7,r7,1						; Bump TASK_SYSCALLS_MACH count
			cmplwi	r8,0						; Is kdebug_enable non-zero
			stw		r7,TASK_SYSCALLS_MACH(r10)	; Save count
			bne--	ksystrace					; yes, tracing enabled
			
			cmplwi	r31,MACH_TRAP_TABLE_COUNT	; Is this syscall in the table?	
			add		r31,r27,r28					; Point right to the syscall table entry

			bge--	.L_call_server_syscall_exception	; The syscall number is invalid
	
			lwz		r0,MACH_TRAP_FUNCTION(r31)	; Pick up the function address

;
;	NOTE: We do not support more than 8 parameters for PPC.  The only 
;	system call to use more than 8 is mach_msg_overwrite_trap and it
;	uses 9.  We pass a 0 in as number 9.
;
			lwz		r3,saver3+4(r30)  			; Restore r3 
			lwz		r4,saver4+4(r30)  			; Restore r4 
			lwz		r5,saver5+4(r30)  			; Restore r5 
			mtctr	r0							; Set the function call address
			lwz		r6,saver6+4(r30)  			; Restore r6
			lwz		r7,saver7+4(r30)  			; Restore r7
			lwz		r8,saver8+4(r30)  			; Restore r8 
			li		r0,0						; Clear this out
			lwz		r9,saver9+4(r30)  			; Restore r9 
			lwz		r10,saver10+4(r30)  		; Restore r10
			stw		r0,FM_ARG0(r1)				; Clear that 9th parameter just in case some fool uses it
			bctrl								; perform the actual syscall

/*
 * Ok, return from C function, R3 = return value
 *
 * get the active thread's PCB pointer and thus pointer to user state
 * saved state is still in R30 and the active thread is in R16
 */

.L_mach_return:	
			mr		r31,r16						; Move the current thread pointer
			stw		r3,saver3+4(r30)				; Stash the return code
			cmpi		cr0,r3,KERN_INVALID_ARGUMENT			; deal with invalid system calls
			beq-		cr0,.L_mach_invalid_ret				; otherwise fall through into the normal return path
.L_mach_invalid_arg:		


/* 'standard' syscall returns here - INTERRUPTS ARE STILL ON
 * the syscall may perform a thread_set_syscall_return
 * followed by a thread_exception_return, ending up
 * at thread_syscall_return below, with SS_R3 having
 * been set up already
 *
 * When we are here, r31 should point to the current thread,
 *                   r30 should point to the current pcb
 *    r3 contains value that we're going to return to the user
 *    which has already been stored back into the save area
 */
		
.L_thread_syscall_ret_check_ast:	
			lis		r10,hi16(MASK(MSR_VEC))			; Get the vector enable
			mfmsr	r12								; Get the current MSR 
			ori		r10,r10,lo16(MASK(MSR_FP)|MASK(MSR_EE))	; Add in FP and EE
			andc	r12,r12,r10						; Turn off VEC, FP, and EE
			mtmsr	r12								; Turn interruptions off
			
			mfsprg	r10,0							; Get the per_processor block

/* Check to see if there's an outstanding AST */
		
			lwz		r4,PP_NEED_AST(r10)				; Get the pointer to the ast requests
			lwz		r4,0(r4)						; Get the flags
			cmpi	cr0,r4,	0						; Any pending asts?
			beq++	cr0,.L_syscall_no_ast			; Nope...

/* Yes there is, call ast_taken 
 * pretending that the user thread took an AST exception here,
 * ast_taken will save all state and bring us back here
 */

#if	DEBUG
/* debug assert - make sure that we're not returning to kernel */
			lwz		r3,savesrr1+4(r30)
			andi.	r3,r3,MASK(MSR_PR)
			bne++	scrnotkern						; returning to user level, check 
			
			lis		r0,hi16(Choke)					; Choke code
			ori		r0,r0,lo16(Choke)				; and the rest
			li		r3,failContext					; Bad state code
			sc										; System ABEND

scrnotkern:		
#endif	/* DEBUG */
	
			li		r3,AST_ALL						; Set ast flags
			li		r4,1							; Set interrupt allowed
			bl		EXT(ast_taken)					; Process the pending ast
			b		.L_thread_syscall_ret_check_ast	; Go see if there was another...

.L_mach_invalid_ret:	
/*
 * need to figure out why we got an KERN_INVALID_ARG
 * if it was due to a non-existent system call
 * then we want to throw an exception... otherwise
 * we want to pass the error code back to the caller
 */
			lwz     r0,saver0+4(r30)				; reload the original syscall number
			neg		r28,r0							; Make this positive
			slwi	r27,r28,MACH_TRAP_OFFSET_POW2	; Convert index to offset
			lis		r28,hi16(EXT(mach_trap_table))	; Get address of table
			ori		r28,r28,lo16(EXT(mach_trap_table))	; Get address of table
			add		r28,r27,r28						; Point right to the syscall table entry
			lwz		r27,MACH_TRAP_FUNCTION(r28)		; Pick up the function address
			lis		r28,hi16(EXT(kern_invalid))		; Get high half of invalid syscall function
			ori		r28,r28,lo16(EXT(kern_invalid))	; Get low half of invalid syscall function
			cmpw	cr0,r27,r28						; Check if this is an invalid system call
			beq--	.L_call_server_syscall_exception	; We have a bad system call
			b		.L_mach_invalid_arg             ; a system call returned KERN_INVALID_ARG
		
	
/* thread_exception_return returns to here, almost all
 * registers intact. It expects a full context restore
 * of what it hasn't restored itself (ie. what we use).
 *
 * In particular for us,
 * we still have     r31 points to the current thread,
 *                   r30 points to the current pcb
 */
 
 			.align	5
 
.L_syscall_no_ast:
.L_thread_syscall_return:

			mr		r3,r30							; Get savearea to the correct register for common exit

			lwz		r11,SAVflags(r30)				; Get the flags 
			lwz		r5,THREAD_KERNEL_STACK(r31)		; Get the base pointer to the stack 
			lwz		r4,SAVprev+4(r30)				; Get the previous save area
			rlwinm	r11,r11,0,15,13					; Clear the syscall flag
			mfsprg	r8,1				 			; Now find the current activation 
			addi	r5,r5,KERNEL_STACK_SIZE-FM_SIZE	; Reset to empty
			stw		r11,SAVflags(r30)				; Stick back the flags
			stw		r5,ACT_MACT_KSP(r8)				; Save the empty stack pointer
			stw		r4,ACT_MACT_PCB(r8)				; Save previous save area
			b		chkfac							; Go end it all...

/*
 * thread_exception_return()
 *
 * Return to user mode directly from within a system call.
 */

			.align	5
			.globl EXT(thread_bootstrap_return)
LEXT(thread_bootstrap_return)						; NOTE: THIS IS GOING AWAY IN A FEW DAYS....

			.globl EXT(thread_exception_return)
LEXT(thread_exception_return)						; Directly return to user mode

.L_thread_exc_ret_check_ast:	
			lis		r10,hi16(MASK(MSR_VEC))			; Get the vector enable
			mfmsr	r3								; Get the MSR 
			ori		r10,r10,lo16(MASK(MSR_FP)|MASK(MSR_EE))	; Add in FP and EE
			andc	r3,r3,r10						; Turn off VEC, FP, and EE
			mtmsr	r3								; Disable interrupts

/* Check to see if there's an outstanding AST */
/* We don't bother establishing a call frame even though CHECK_AST
   can invoke ast_taken(), because it can just borrow our caller's
   frame, given that we're not going to return.  
*/
		
			mfsprg	r10,0							; Get the per_processor block 
			lwz		r4,PP_NEED_AST(r10)
			lwz		r4,0(r4)
			cmpi	cr0,r4,	0
			beq+		cr0,.L_exc_ret_no_ast
		
/* Yes there is, call ast_taken 
 * pretending that the user thread took an AST exception here,
 * ast_taken will save all state and bring us back here
 */
	
			li		r3,AST_ALL
			li		r4,1
			
			bl		EXT(ast_taken)
			b		.L_thread_exc_ret_check_ast		; check for a second AST (rare)
	
/* arriving here, interrupts should be disabled */
/* Get the active thread's PCB pointer to restore regs
 */
.L_exc_ret_no_ast:
			
			mfsprg  r30,1							; Get the currrent activation
			lwz		r31,ACT_THREAD(r30)				; Get the current thread

			lwz		r30,ACT_MACT_PCB(r30)
			mr.		r30,r30							; Is there any context yet?
			beq-	makeDummyCtx					; No, hack one up...
#if	DEBUG
/* 
 * debug assert - make sure that we're not returning to kernel
 * get the active thread's PCB pointer and thus pointer to user state
 */
		
			lwz		r3,savesrr1+4(r30)
			andi.	r3,r3,MASK(MSR_PR)
			bne+	ret_user2						; We are ok...

			lis		r0,hi16(Choke)					; Choke code
			ori		r0,r0,lo16(Choke)				; and the rest
			li		r3,failContext					; Bad state code
			sc										; System ABEND
			
ret_user2:		
#endif	/* DEBUG */
		
/* If the system call flag isn't set, then we came from a trap,
 * so warp into the return_from_trap (thread_return) routine,
 * which takes PCB pointer in R3, not in r30!
 */
			lwz		r0,SAVflags(r30)				; Grab the savearea flags
			andis.	r0,r0,SAVsyscall>>16			; Are we returning from a syscall?
			mr		r3,r30							; Copy pcb pointer into r3 in case we need it
			beq--	cr0,thread_return				; Nope, must be a thread return...
			b		.L_thread_syscall_return		; Join up with the system call return...

;
;			This is where we handle someone trying who did a thread_create followed
;			by a thread_resume with no intervening thread_set_state.  Just make an
;			empty context, initialize it to trash and let em execute at 0...
;

			.align	5

makeDummyCtx:
			bl		EXT(save_get)					; Get a save_area
			li		r4,SAVgeneral					; Get the general context type
			li		r0,0							; Get a 0
			stb		r4,SAVflags+2(r3)				; Set type
			addi	r2,r3,savefpscr+4				; Point past what we are clearing
			mr		r4,r3							; Save the start
			
cleardummy:	stw		r0,0(r4)						; Clear stuff
			addi	r4,r4,4							; Next word
			cmplw	r4,r2							; Still some more?
			blt+	cleardummy						; Yeah...
			
			lis		r2,hi16(MSR_EXPORT_MASK_SET)	; Set the high part of the user MSR
			ori		r2,r2,lo16(MSR_EXPORT_MASK_SET)	; And the low part
			stw		r2,savesrr1+4(r3)				; Set the default user MSR
	
			b		thread_return					; Go let em try to execute, hah!
	
/*
 * ihandler(type)
 *
 * ENTRY:	VM switched ON
 *			Interrupts  OFF
 *			R3 contains exception code
 *			R4 points to the saved context (virtual address)
 *			Everything is saved in savearea
 *
 */

			.align	5
			.globl EXT(ihandler)
LEXT(ihandler)										; Interrupt handler */

/*
 * get the value of istackptr, if it's zero then we're already on the
 * interrupt stack.
 */

			lwz		r10,savesrr1+4(r4)				; Get SRR1 
			lwz		r7,savevrsave(r4)				; Get the VRSAVE register
			mfsprg	r25,0							; Get the per_proc block
			li		r14,0							; Zero this for now
			rlwinm.	r13,r10,0,MSR_VEC_BIT,MSR_VEC_BIT	; Was vector on?
			lwz		r1,PP_ISTACKPTR(r25)			; Get the interrupt stack
			mfsprg	r13,1							; Get the current thread
			li		r16,0							; Zero this for now

			beq+	ivecoff							; Vector off, do not save vrsave...
			stw		r7,liveVRS(r25)					; Set the live value

ivecoff:	li		r0,0							; Get a constant 0
			rlwinm	r5,r10,0,MSR_PR_BIT,MSR_PR_BIT	; Are we trapping from supervisor state?
			mr.		r1,r1							; Is it active?
			cmplwi	cr2,r5,0						; cr2_eq == 1 if yes
			lwz		r16,ACT_THREAD(r13)				; Get the shuttle
			lwz		r14,ACT_MACT_PCB(r13)			; Now point to the PCB 
			lwz		r9,saver1+4(r4)					; Pick up the rupt time stack
			stw		r14,SAVprev+4(r4)				; Queue the new save area in the front
			stw		r13,SAVact(r4)					; Point the savearea at its activation
			stw		r4,ACT_MACT_PCB(r13)			; Point to our savearea 
			beq		cr2,ifromk
			stw		r4,ACT_MACT_UPCB(r13)			; Store user savearea

ifromk:		bne		.L_istackfree					; Nope... 

/* We're already on the interrupt stack, get back the old
 * stack pointer and make room for a frame
 */

			lwz		r10,PP_INTSTACK_TOP_SS(r25)		; Get the top of the interrupt stack
			addi	r5,r9,INTSTACK_SIZE-FM_SIZE		; Shift stack for bounds check
			subi	r1,r9,FM_REDZONE				; Back up beyond the red zone
			sub		r5,r5,r10						; Get displacement into stack
			cmplwi	r5,INTSTACK_SIZE-FM_SIZE		; Is the stack actually invalid?
			blt+	ihsetback						; The stack is ok...

			lwz		r5,PP_DEBSTACK_TOP_SS(r25)		; Pick up debug stack top
			subi	r5,r5,KERNEL_STACK_SIZE-FM_SIZE	; Adjust to start of stack
			sub		r5,r1,r5						; Get displacement into debug stack
			cmplwi	cr2,r5,KERNEL_STACK_SIZE-FM_SIZE	; Check if we are on debug stack
			blt+	cr2,ihsetback					; Yeah, that is ok too...

			lis		r0,hi16(Choke)					; Choke code
			ori		r0,r0,lo16(Choke)				; and the rest
			li		r3,failStack					; Bad stack code
			sc										; System ABEND

intUnalignedStk:
			lis		r0,hi16(Choke)					; Choke code
			ori		r0,r0,lo16(Choke)				; and the rest
			li		r3,failUnalignedStk				; Unaligned stack code
			sc										; System ABEND

			.align	5
			
.L_istackfree:
			rlwinm.	r0,r1,0,28,31					; Check if stack is aligned (and get 0)
			lwz		r10,SAVflags(r4)				; Get savearea flags
			bne--	intUnalignedStk					; Stack is unaligned...
			stw		r0,PP_ISTACKPTR(r25)			; Mark the stack in use 
			oris	r10,r10,hi16(SAVrststk)			; Indicate we reset stack when we return from this one 
			stw		r10,SAVflags(r4)				; Stick it back		
	
/*
 * To summarize, when we reach here, the state has been saved and
 * the stack is marked as busy. We now generate a small
 * stack frame with backpointers to follow the calling
 * conventions. We set up the backpointers to the trapped
 * routine allowing us to backtrace.
 */
	
ihsetback:	subi	r1,r1,FM_SIZE					; Make a new frame 
			stw		r9,FM_BACKPTR(r1)				; Point back to previous stackptr
		
#if VERIFYSAVE
			beq-	cr1,ihbootnover					; (TEST/DEBUG)
			bl		versave							; (TEST/DEBUG)
ihbootnover:										; (TEST/DEBUG)
#endif

#if	DEBUG
/* If debugging, we need two frames, the first being a dummy
 * which links back to the trapped routine. The second is
 * that which the C routine below will need
 */
			lwz		r5,savesrr0+4(r4)				; Get interrupt address 
			stw		r5,FM_LR_SAVE(r1)				; save old instr ptr as LR value 
			stwu	r1,-FM_SIZE(r1)					; Make another new frame for C routine
#endif /* DEBUG */

			lwz		r5,savedsisr(r4)				; Get the DSISR
			lwz		r6,savedar+4(r4)				; Get the DAR 
			
			bl	EXT(interrupt)


/* interrupt() returns a pointer to the saved state in r3
 *
 * Ok, back from C. Disable interrupts while we restore things
 */
			.globl EXT(ihandler_ret)

LEXT(ihandler_ret)									; Marks our return point from debugger entry

			lis		r10,hi16(MASK(MSR_VEC))			; Get the vector enable
			mfmsr	r0								; Get our MSR
			ori		r10,r10,lo16(MASK(MSR_FP)|MASK(MSR_EE))	; Add in FP and EE
			andc	r0,r0,r10						; Turn off VEC, FP, and EE
			mtmsr	r0								; Make sure interrupts are disabled
			mfsprg	r10,0							; Get the per_proc block
		
			lwz		r7,SAVflags(r3)					; Pick up the flags
			mfsprg	r8,1							; Get the current thread
			lwz		r9,SAVprev+4(r3)					; Get previous save area
			cmplwi	cr1,r8,0						; Are we still initializing?
			lwz		r12,savesrr1+4(r3)				; Get the MSR we will load on return 
			lwz		r8,THREAD_TOP_ACT(r8)			; Pick up the active thread 
			andis.	r11,r7,hi16(SAVrststk)			; Is this the first on the stack?
			stw		r9,ACT_MACT_PCB(r8)				; Point to previous context savearea 
			mr		r4,r3							; Move the savearea pointer
			beq		.L_no_int_ast2					; Get going if not the top-o-stack...


/* We're the last frame on the stack. Restore istackptr to empty state.
 *
 * Check for ASTs if one of the below is true:	
 *    returning to user mode
 *    returning to a kloaded server
 */
			lwz		r9,PP_INTSTACK_TOP_SS(r10)		; Get the empty stack value 
			andc	r7,r7,r11						; Remove the stack reset bit in case we pass this one
			stw		r9,PP_ISTACKPTR(r10)			; Save that saved state ptr 
			lwz		r3,ACT_PREEMPT_CNT(r8)			; Get preemption level 
			stw		r7,SAVflags(r4)					; Save the flags
			cmplwi	r3, 0							; Check for preemption
			bne		.L_no_int_ast					; Do not preempt if level is not zero
			andi.	r6,r12,MASK(MSR_PR)				; privilege mode
			lwz		r11,PP_NEED_AST(r10)			; Get the AST request address
			lwz		r11,0(r11)						; Get the request
			beq-	.L_kernel_int_ast				; In kernel space, AST_URGENT check
			li		r3,T_AST						; Assume the worst
			mr.		r11,r11							; Are there any pending? 
			beq		.L_no_int_ast					; Nope... 
			b		.L_call_thandler

.L_kernel_int_ast:
			andi.	r11,r11,AST_URGENT				; Do we have AST_URGENT?
			li		r3,T_PREEMPT					; Assume the worst
			beq		.L_no_int_ast					; Nope... 

/*
 * There is a pending AST. Massage things to make it look like
 * we took a trap and jump into the trap handler.  To do this
 * we essentially pretend to return from the interrupt but
 * at the last minute jump into the trap handler with an AST
 * trap instead of performing an rfi.
 */

.L_call_thandler:
			stw		r3,saveexception(r4)			; Set the exception code to T_AST/T_PREEMPT
			b		EXT(thandler)					; We need to preempt so treat like a trap...

.L_no_int_ast:	
			mr		r3,r4							; Get into the right register for common code
			
.L_no_int_ast2:	
			rlwinm	r7,r7,0,15,13					; Clear the syscall flag
			li		r4,0							; Assume for a moment that we are in init
			stw		r7,SAVflags(r3)					; Set the flags with cleared syscall flag
			beq--	cr1,chkfac						; Jump away if we are in init...

			lwz		r4,ACT_MACT_PCB(r8)				; Get the new level marker


;
;			This section is common to all exception exits.  It throws away vector
;			and floating point saveareas as the exception level of a thread is
;			exited.  
;
;			It also enables the facility if its context is live
;			Requires:
;				R3  = Savearea to be released (virtual)
;				R4  = New top of savearea stack (could be 0)
;				R8  = pointer to activation
;				R10 = per_proc block
;
;			Note that barring unforseen crashes, there is no escape from this point
;			on. We WILL call exception_exit and launch this context. No worries
;			about preemption or interruptions here.
;
;			Note that we will set up R26 with whatever context we will be launching,
;			so it will indicate the current, or the deferred it it is set and we
;			are going to user state.  CR2_eq will be set to indicate deferred.
;

chkfac:		lwz		r29,savesrr1+4(r3)				; Get the current MSR
			mr.		r28,r8							; Are we still in boot?
			mr		r31,r10							; Move per_proc address
			mr		r30,r4							; Preserve new level
			mr		r27,r3							; Save the old level
			beq--	chkenax							; Yeah, skip it all...
			
			rlwinm.	r0,r29,0,MSR_PR_BIT,MSR_PR_BIT	; Are we going into user state?

			lwz		r20,curctx(r28)					; Get our current context
			lwz		r26,deferctx(r28)				; Get any deferred context switch
			li		r0,1							; Get set to hold off quickfret
			rlwinm	r29,r29,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Turn off floating point for now
			lwz		r21,FPUlevel(r20)				; Get the facility level
			cmplwi	cr2,r26,0						; Are we going into a deferred context later?
			rlwinm	r29,r29,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Turn off vector for now
			crnor	cr2_eq,cr0_eq,cr2_eq			; Set cr2_eq if going to user state and there is deferred
			lhz		r19,PP_CPU_NUMBER(r31)			; Get our CPU number
			cmplw	r27,r21							; Are we returning from the active level?
			stw		r0,holdQFret(r31)				; Make sure we hold off releasing quickfret
			bne++	fpuchkena						; Nope...

;
;			First clean up any live context we are returning from
;

			lwz		r22,FPUcpu(r20)					; Get CPU this context was last dispatched on
			
			stw		r19,FPUcpu(r20)					; Claim context for us
			
			eieio									; Make sure this gets out before owner clear
			
#if ppSize != 4096
#error per_proc_info is not 4k in size
#endif
			
			lis		r23,hi16(EXT(per_proc_info))	; Set base per_proc
			slwi	r22,r22,12						; FInd offset to the owner per_proc
			ori		r23,r23,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r24,FPUowner					; Displacement to FPU owner
			add		r22,r23,r22						; Point to the owner per_proc	
			
fpuinvothr:	lwarx	r23,r24,r22						; Get the owner

			sub		r0,r23,r20						; Subtract one from the other
			sub		r21,r20,r23						; Subtract the other from the one
			or		r21,r21,r0						; Combine them
			srawi	r21,r21,31						; Get a 0 if equal or -1 of not
			and		r23,r23,r21						; Make 0 if same, unchanged if not
			stwcx.	r23,r24,r22						; Try to invalidate it
			bne--	fpuinvothr						; Try again if there was a collision...

			isync

;
;			Now if there is a savearea associated with the popped context, release it.
;			Either way, pop the level to the top stacked context.
;

			lwz		r22,FPUsave(r20)				; Get pointer to the first savearea
			li		r21,0							; Assume we popped all the way out
			mr.		r22,r22							; Is there anything there?
			beq++	fpusetlvl						; No, see if we need to enable...
			
			lwz		r21,SAVlevel(r22)				; Get the level of that savearea
			cmplw	r21,r27							; Is this the saved copy of the live stuff?
			bne		fpusetlvl						; No, leave as is...
			
			lwz		r24,SAVprev+4(r22)				; Pick up the previous area
			li		r21,0							; Assume we popped all the way out
			mr.		r24,r24							; Any more context stacked?
			beq--	fpuonlyone						; Nope...
			lwz		r21,SAVlevel(r24)				; Get the level associated with save

fpuonlyone:	stw		r24,FPUsave(r20)				; Dequeue this savearea

			rlwinm	r3,r22,0,0,19					; Find main savearea header

			lwz		r8,quickfret(r31)				; Get the first in quickfret list (top)					
			lwz		r9,quickfret+4(r31)				; Get the first in quickfret list (bottom)					
			lwz		r2,SACvrswap(r3)				; Get the virtual to real conversion (top)
			lwz		r3,SACvrswap+4(r3)				; Get the virtual to real conversion (bottom)
			stw		r8,SAVprev(r22)					; Link the old in (top)					
			stw		r9,SAVprev+4(r22)				; Link the old in (bottom)					
			xor		r3,r22,r3						; Convert to physical
			stw		r2,quickfret(r31)				; Set the first in quickfret list (top)					
			stw		r3,quickfret+4(r31)				; Set the first in quickfret list (bottom)					
			
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x3301						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif				

fpusetlvl:	stw		r21,FPUlevel(r20)				; Save the level
		
;
;			Here we check if we are at the right level
;			We need to check the level we are entering, not the one we are exiting.
;			Therefore, we will use the defer level if it is non-zero and we are
;			going into user state.
;
			
fpuchkena:	bt--	cr2_eq,fpuhasdfrd				; Skip if deferred, R26 already set up...
			mr		r26,r20							; Use the non-deferred value
			
fpuhasdfrd:	
#if 0
			rlwinm.	r0,r29,0,MSR_PR_BIT,MSR_PR_BIT	; (TEST/DEBUG) Going into user state?
			beq		fpunusrstt						; (TEST/DEBUG) Nope...	
			lwz		r23,FPUlevel(r26)				; (TEST/DEBUG) Get the level ID
			lwz		r24,FPUsave(r26)				; (TEST/DEBUG) Get the first savearea
			mr.		r23,r23							; (TEST/DEBUG) Should be level 0
			beq++	fpulvl0							; (TEST/DEBUG) Yes...
			BREAKPOINT_TRAP							; (TEST/DEBUG)
			
fpulvl0:	mr.		r24,r24							; (TEST/DEBUG) Any context?
			beq		fpunusrstt						; (TEST/DEBUG) No...
			lwz		r23,SAVlevel(r24)				; (TEST/DEBUG) Get level of context
			lwz		r21,SAVprev+4(r24)				; (TEST/DEBUG) Get previous pointer
			mr.		r23,r23							; (TEST/DEBUG) Is this our user context?
			beq++	fpulvl0b						; (TEST/DEBUG) Yes...
			BREAKPOINT_TRAP							; (TEST/DEBUG)
			
fpulvl0b:	mr.		r21,r21							; (TEST/DEBUG) Is there a forward chain?
			beq++	fpunusrstt						; (TEST/DEBUG) Nope...
			BREAKPOINT_TRAP							; (TEST/DEBUG)
						
fpunusrstt:											; (TEST/DEBUG)
#endif				
			
			lwz		r21,FPUowner(r31)				; Get the ID of the live context
			lwz		r23,FPUlevel(r26)				; Get the level ID
			lwz		r24,FPUcpu(r26)					; Get the CPU that the context was last dispatched on
			cmplw	cr3,r26,r21						; Do we have the live context?
			cmplw	r30,r23							; Are we about to launch the live level?
			bne--	cr3,chkvec						; No, can not possibly enable...
			cmplw	cr1,r19,r24						; Was facility used on this processor last?
			bne--	chkvec							; No, not live...
			bne--	cr1,chkvec						; No, wrong cpu, have to enable later....
			
			lwz		r24,FPUsave(r26)				; Get the first savearea
			mr.		r24,r24							; Any savearea?
			beq++	fpuena							; Nope...
			lwz		r25,SAVlevel(r24)				; Get the level of savearea
			lwz		r0,SAVprev+4(r24)				; Get the previous
			cmplw	r30,r25							; Is savearea for the level we are launching?
			bne++	fpuena							; No, just go enable...
			
			stw		r0,FPUsave(r26)					; Pop the chain

			rlwinm	r3,r24,0,0,19					; Find main savearea header

			lwz		r8,quickfret(r31)				; Get the first in quickfret list (top)					
			lwz		r9,quickfret+4(r31)				; Get the first in quickfret list (bottom)					
			lwz		r2,SACvrswap(r3)				; Get the virtual to real conversion (top)
			lwz		r3,SACvrswap+4(r3)				; Get the virtual to real conversion (bottom)
			stw		r8,SAVprev(r24)					; Link the old in (top)					
			stw		r9,SAVprev+4(r24)				; Link the old in (bottom)					
			xor		r3,r24,r3						; Convert to physical
			stw		r2,quickfret(r31)				; Set the first in quickfret list (top)					
			stw		r3,quickfret+4(r31)				; Set the first in quickfret list (bottom)					

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x3302						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif				

fpuena:		ori		r29,r29,lo16(MASK(MSR_FP))		; Enable facility			
			
chkvec:		

			lwz		r21,VMXlevel(r20)				; Get the facility level
		
			cmplw	r27,r21							; Are we returning from the active level?
			bne+	vmxchkena						; Nope...
			

;
;			First clean up any live context we are returning from
;

			lwz		r22,VMXcpu(r20)					; Get CPU this context was last dispatched on
			
			stw		r19,VMXcpu(r20)					; Claim context for us
			
			eieio									; Make sure this gets out before owner clear
			
			lis		r23,hi16(EXT(per_proc_info))	; Set base per_proc
			slwi	r22,r22,12						; Find offset to the owner per_proc			
			ori		r23,r23,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r24,VMXowner					; Displacement to VMX owner
			add		r22,r23,r22						; Point to the owner per_proc	
			
vmxinvothr:	lwarx	r23,r24,r22						; Get the owner

			sub		r0,r23,r20						; Subtract one from the other
			sub		r21,r20,r23						; Subtract the other from the one
			or		r21,r21,r0						; Combine them
			srawi	r21,r21,31						; Get a 0 if equal or -1 of not
			and		r23,r23,r21						; Make 0 if same, unchanged if not
			stwcx.	r23,r24,r22						; Try to invalidate it
			bne--	vmxinvothr						; Try again if there was a collision...

			isync

;
;			Now if there is a savearea associated with the popped context, release it.
;			Either way, pop the level to the top stacked context.
;

			lwz		r22,VMXsave(r20)				; Get pointer to the first savearea
			li		r21,0							; Assume we popped all the way out
			mr.		r22,r22							; Is there anything there?
			beq++	vmxsetlvl						; No, see if we need to enable...
			
			lwz		r21,SAVlevel(r22)				; Get the level of that savearea
			cmplw	r21,r27							; Is this the saved copy of the live stuff?
			bne		vmxsetlvl						; No, leave as is...
			
			lwz		r24,SAVprev+4(r22)				; Pick up the previous area
			li		r21,0							; Assume we popped all the way out
			mr.		r24,r24							; Any more context?
			beq--	vmxonlyone						; Nope...
			lwz		r21,SAVlevel(r24)				; Get the level associated with save

vmxonlyone:	stw		r24,VMXsave(r20)				; Dequeue this savearea
			
			rlwinm	r3,r22,0,0,19					; Find main savearea header

			lwz		r8,quickfret(r31)				; Get the first in quickfret list (top)					
			lwz		r9,quickfret+4(r31)				; Get the first in quickfret list (bottom)					
			lwz		r2,SACvrswap(r3)				; Get the virtual to real conversion (top)
			lwz		r3,SACvrswap+4(r3)				; Get the virtual to real conversion (bottom)
			stw		r8,SAVprev(r22)					; Link the old in (top)					
			stw		r9,SAVprev+4(r22)				; Link the old in (bottom)					
			xor		r3,r22,r3						; Convert to physical
			stw		r2,quickfret(r31)				; Set the first in quickfret list (top)					
			stw		r3,quickfret+4(r31)				; Set the first in quickfret list (bottom)					

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x3401						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif				

vmxsetlvl:	stw		r21,VMXlevel(r20)				; Save the level
		
;
;			Here we check if we are at the right level
;
			
vmxchkena:	lwz		r21,VMXowner(r31)				; Get the ID of the live context
			lwz		r23,VMXlevel(r26)				; Get the level ID
			cmplw	r26,r21							; Do we have the live context?
			lwz		r24,VMXcpu(r26)					; Get the CPU that the context was last dispatched on
			bne--	setena							; No, can not possibly enable...
			cmplw	r30,r23							; Are we about to launch the live level?
			cmplw	cr1,r19,r24						; Was facility used on this processor last?
			bne--	setena							; No, not live...
			bne--	cr1,setena						; No, wrong cpu, have to enable later....
			
			lwz		r24,VMXsave(r26)				; Get the first savearea
			mr.		r24,r24							; Any savearea?
			beq++	vmxena							; Nope...
			lwz		r25,SAVlevel(r24)				; Get the level of savearea
			lwz		r0,SAVprev+4(r24)				; Get the previous
			cmplw	r30,r25							; Is savearea for the level we are launching?
			bne++	vmxena							; No, just go enable...

			stw		r0,VMXsave(r26)					; Pop the chain
			
			rlwinm	r3,r24,0,0,19					; Find main savearea header

			lwz		r8,quickfret(r31)				; Get the first in quickfret list (top)					
			lwz		r9,quickfret+4(r31)				; Get the first in quickfret list (bottom)					
			lwz		r2,SACvrswap(r3)				; Get the virtual to real conversion (top)
			lwz		r3,SACvrswap+4(r3)				; Get the virtual to real conversion (bottom)
			stw		r8,SAVprev(r24)					; Link the old in (top)					
			stw		r9,SAVprev+4(r24)				; Link the old in (bottom)					
			xor		r3,r24,r3						; Convert to physical
			stw		r2,quickfret(r31)				; Set the first in quickfret list (top)					
			stw		r3,quickfret+4(r31)				; Set the first in quickfret list (bottom)					

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x3402						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif				
			
vmxena:		oris	r29,r29,hi16(MASK(MSR_VEC))		; Enable facility

setena:		lwz		r18,cioSpace(r28)				; Get the space ID in case we are launching user
			rlwinm.	r0,r29,0,MSR_PR_BIT,MSR_PR_BIT	; Are we about to launch user state?
			li		r0,0							; Get set to release quickfret holdoff
			crmove	cr7_eq,cr0_eq					; Remember if we are going to user state
			rlwimi.	r20,r29,(((31-floatCngbit)+(MSR_FP_BIT+1))&31),floatCngbit,floatCngbit	; Set flag if we enabled floats
			lwz		r19,deferctx(r28)				; Get any deferred facility context switch
			rlwinm	r20,r29,(((31-vectorCngbit)+(MSR_VEC_BIT+1))&31),vectorCngbit,vectorCngbit	; Set flag if we enabled vector
			stw		r29,savesrr1+4(r27)				; Turn facility on or off
			stw		r0,holdQFret(r31)				; Release quickfret
			oris	r18,r18,hi16(cioSwitchAway)		; Set the switch-away bit in case we go to user

			beq		setenaa							; Neither float nor vector turned on....
			
			lwz		r5,ACT_MACT_SPF(r28)			; Get activation copy
			lwz		r6,spcFlags(r31)				; Get per_proc copy
			or		r5,r5,r20						; Set vector/float changed bits in activation
			or		r6,r6,r20						; Set vector/float changed bits in per_proc
			stw		r5,ACT_MACT_SPF(r28)			; Set activation copy
			stw		r6,spcFlags(r31)				; Set per_proc copy

setenaa:	mfdec	r24								; Get decrementer
			bf+		cr2_eq,nodefer					; No deferred to switch to...
						
			li		r20,0							; Clear this
			stw		r26,curctx(r28)					; Make the facility context current
			stw		r20,deferctx(r28)				; Clear deferred context

nodefer:	lwz		r22,qactTimer(r28)				; Get high order quick activation timer
			mr.		r24,r24							; See if it has popped already...
			lwz		r23,qactTimer+4(r28)			; Get low order qact timer
			ble-	chkifuser						; We have popped or are just about to...
			
segtb:		mftbu	r20								; Get the upper time base
			mftb	r21								; Get the low
			mftbu	r19								; Get upper again
			or.		r0,r22,r23						; Any time set?
			cmplw	cr1,r20,r19						; Did they change?
			beq++	chkifuser						; No time set....
			bne--	cr1,segtb						; Timebase ticked, get them again...
			
			subfc	r6,r21,r23						; Subtract current from qact time
			li		r0,0							; Make a 0
			subfe	r5,r20,r22						; Finish subtract
			subfze	r0,r0							; Get a 0 if qact was bigger than current, -1 otherwise
			andc.	r12,r5,r0						; Set 0 if qact has passed
			andc	r13,r6,r0						; Set 0 if qact has passed
			bne		chkifuser						; If high order is non-zero, this is too big for a decrementer
			cmplw	r13,r24							; Is this earlier than the decrementer? (logical compare takes care of high bit on)
			bge++	chkifuser						; No, do not reset decrementer...
			
			mtdec	r13								; Set our value

chkifuser:	beq--	cr7,chkenax						; Skip this if we are going to kernel...
			stw		r18,cioSpace(r28)				; Half-invalidate to force MapUserAddressSpace to reload SRs

chkenax:	

	
#if DEBUG
			lwz		r20,SAVact(r27)					; (TEST/DEBUG) Make sure our restore
			mfsprg	r21, 1							; (TEST/DEBUG) with the current act.
			cmpwi	r21,0							; (TEST/DEBUG)
			beq--	yeswereok						; (TEST/DEBUG)
			cmplw	r21,r20							; (TEST/DEBUG)
			beq++	yeswereok						; (TEST/DEBUG)

			lis		r0,hi16(Choke)					; (TEST/DEBUG) Choke code
			ori		r0,r0,lo16(Choke)				; (TEST/DEBUG) and the rest
			mr		r21,r27							; (TEST/DEBUG) Save the savearea address
			li		r3,failContext					; (TEST/DEBUG) Bad state code
			sc										; (TEST/DEBUG) System ABEND

yeswereok:
#endif
	
			mr		r3,r27							; Pass savearea back
			b		EXT(exception_exit)				; We are all done now...



;
;			Null PPC call - performance testing, does absolutely nothing
;

			.align	5
			
			.globl	EXT(ppcNull)
			
LEXT(ppcNull)

			li		r3,-1							; Make sure we test no asts
			blr


;
;			Instrumented null PPC call - performance testing, does absolutely nothing
;			Forces various timestamps to be returned.
;

			.align	5
			
			.globl	EXT(ppcNullinst)
			
LEXT(ppcNullinst)

			li		r3,-1							; Make sure we test no asts
			blr


/*
 *			Here's where we handle the fastpath stuff
 *			We'll do what we can here because registers are already
 *			loaded and it will be less confusing that moving them around.
 *			If we need to though, we'll branch off somewhere's else.
 *
 *			Registers when we get here:
 *
 *				r0  = syscall number
 *				r4  = savearea/pcb
 *				r13 = activation
 *				r14 = previous savearea (if any)
 *				r16 = thread
 *				r25 = per_proc
 */

			.align	5

fastpath:	cmplwi	cr3,r0,0x7FF5				; Is this a null fastpath?
			beq--	cr3,fastexutl				; Yes, bail fast...
			cmplwi	cr3,r0,0x7FF1				; Is it CthreadSetSelfNumber? 	
			bnelr--	cr3							; Not a fast path...

/*
 * void cthread_set_self(cproc_t p)
 *
 * set's thread state "user_value"
 *
 * This op is invoked as follows:
 *	li r0, CthreadSetSelfNumber	// load the fast-trap number
 *	sc				// invoke fast-trap
 *	blr
 *
 */

CthreadSetSelfNumber:

			lwz		r5,saver3+4(r4)				/* Retrieve the self number */
			stw		r5,CTHREAD_SELF(r13)		/* Remember it */
			stw		r5,UAW(r25)					/* Prime the per_proc_info with it */


			.globl	EXT(fastexit)
EXT(fastexit):
fastexutl:	mr		r3,r4						; Pass back savearea
			b		EXT(exception_exit)			; Go back to the caller...


/*
 *			Here's where we check for a hit on the Blue Box Assist
 *			Most registers are non-volatile, so be careful here. If we don't 
 *			recognize the trap instruction we go back for regular processing.
 *			Otherwise we transfer to the assist code.
 */
 
			.align	5
			
checkassist:
			lwz		r0,saveexception(r4)		; Get the exception code
			lwz		r23,savesrr1+4(r4)			; Get the interrupted MSR 
			lwz		r26,ACT_MACT_BEDA(r13)		; Get Blue Box Descriptor Area
			mtcrf	0x18,r23					; Check what SRR1 says
			lwz		r24,ACT_MACT_BTS(r13)		; Get the table start 
			cmplwi	r0,T_AST					; Check for T_AST trap 
			lwz		r27,savesrr0+4(r4)			; Get trapped address 
			crnand	cr1_eq,SRR1_PRG_TRAP_BIT,MSR_PR_BIT	; We need both trap and user state
			sub		r24,r27,r24					; See how far into it we are 
			cror	cr0_eq,cr0_eq,cr1_eq		; Need to bail if AST or not trap or not user state
			cmplwi	cr1,r24,BB_MAX_TRAP			; Do we fit in the list? 
			cror	cr0_eq,cr0_eq,cr1_gt		; Also leave it trap not in range
			btlr-	cr0_eq						; No assist if AST or not trap or not user state or trap not in range
			b		EXT(atomic_switch_trap)		; Go to the assist...
			
;
;			Virtual Machine Monitor 
;			Here is where we exit from the emulated context
;			Note that most registers get trashed here
;			R3 and R30 are preserved across the call and hold the activation
;			and savearea respectivily.
;			

			.align	5

exitFromVM:	mr		r30,r4						; Get the savearea
			mr		r3,r13						; Get the activation
			
			b		EXT(vmm_exit)				; Do it to it
			
			.align	5
			.globl	EXT(retFromVM)

LEXT(retFromVM)
			mfsprg	r10,0						; Restore the per_proc info
			mr		r8,r3						; Get the activation
			lwz		r4,SAVprev+4(r30)			; Pick up the previous savearea
			mr		r3,r30						; Put savearea in proper register for common code
			lwz		r11,SAVflags(r30)			; Get the flags of the current savearea
			rlwinm	r11,r11,0,15,13				; Clear the syscall flag 
			lwz		r1,ACT_THREAD(r8)			; and the active thread
			stw		r11,SAVflags(r3)			; Save back the flags (with reset stack cleared)

			stw		r4,ACT_MACT_PCB(r8)			; Point to the previous savearea (or 0 if none)

			lwz		r5,THREAD_KERNEL_STACK(r1)	; Get the base pointer to the stack
			addi	r5,r5,KERNEL_STACK_SIZE-FM_SIZE	; Reset to empty 
			stw		r5,ACT_MACT_KSP(r8)			; Save the empty stack pointer
			b		chkfac						; Go end it all...


;
;			chandler (note: not a candle maker or tallow merchant)
;
;			Here is the system choke handler.  This is where the system goes
;			to die.
;			
;			We get here as a result of a T_CHOKE exception which is generated
;			by the Choke firmware call or by lowmem_vectors when it detects a
;			fatal error. Examples of where this may be used is when we detect
;			problems in low-level mapping chains, trashed savearea free chains,
;			or stack guardpage violations.
;
;			Note that we can not set a back chain in the stack when we come
;			here because we are probably here because the chain was corrupt.
;


			.align	5
			.globl EXT(chandler)
LEXT(chandler)									; Choke handler

			li		r31,0						; Get a 0
			mfsprg	r25,0						; Get the per_proc 
			stw		r31,traceMask(0)			; Force tracing off right now
		
		
		
			lwz		r1,PP_DEBSTACKPTR(r25)		; Get debug stack pointer
			cmpwi	r1,-1						; Are we already choking?
			bne		chokefirst					; Nope...
			
chokespin:	addi	r31,r31,1					; Spin and hope for an analyzer connection...				
			addi	r31,r31,1					; Spin and hope for an analyzer connection...				
			addi	r31,r31,1					; Spin and hope for an analyzer connection...				
			addi	r31,r31,1					; Spin and hope for an analyzer connection...				
			addi	r31,r31,1					; Spin and hope for an analyzer connection...				
			addi	r31,r31,1					; Spin and hope for an analyzer connection...				
			b		chokespin					; Spin and hope for an analyzer connection...
			
chokefirst:	li		r0,-1						; Set choke value
			mr.		r1,r1						; See if we are on debug stack yet
			lwz		r10,saver1+4(r4)			; 
			stw		r0,PP_DEBSTACKPTR(r25)		; Show we are choking
			bne		chokestart					; We are not on the debug stack yet...
			
			lwz		r2,PP_DEBSTACK_TOP_SS(r25)	; Get debug stack top
			sub		r11,r2,r10					; Get stack depth

			cmplwi	r11,KERNEL_STACK_SIZE-FM_SIZE-TRAP_SPACE_NEEDED	; Check if stack pointer is ok			
			bgt		chokespin					; Bad stack pointer or too little left, just die...

			subi	r1,r10,FM_REDZONE			; Make a red zone

chokestart:	li		r0,0						; Get a zero
			stw		r0,FM_BACKPTR(r1)			; We now have terminated the back chain

			bl		EXT(SysChoked)				; Call the "C" phase of this
			b		chokespin					; Should not be here so just go spin...
			

#if VERIFYSAVE			
;
;			Savearea chain verification
;
		
versave:	
#if 0
			lis		r22,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r22,r22,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			lwz		r23,0(r22)						; (TEST/DEBUG)
			mr.		r23,r23							; (TEST/DEBUG)
			beqlr-									; (TEST/DEBUG)
			mfsprg	r20,0							; (TEST/DEBUG)
			lwz		r21,pfAvailable(r20)			; (TEST/DEBUG)
			mr.		r21,r21							; (TEST/DEBUG)
			bnelr+									; (TEST/DEBUG)
			
			stw		r22,0(r22)						; (TEST/DEBUG) Lock out more checks
			BREAKPOINT_TRAP							; (TEST/DEBUG) Get into debugger
#endif

#if 0
		;; This code is broken and migration will make the matter even worse
;
;			Make sure that all savearea chains have the right type on them
;

			lis		r28,hi16(EXT(default_pset))		; (TEST/DEBUG)
			lis		r27,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r28,r28,lo16(EXT(default_pset))	; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			li		r20,0							; (TEST/DEBUG)
			lwz		r26,0(r27)						; (TEST/DEBUG)
			lwz		r27,psthreadcnt(r28)			; (TEST/DEBUG)
			mr.		r26,r26							; (TEST/DEBUG) Have we locked the test out?
			lwz		r28,psthreads(r28)				; (TEST/DEBUG)
			mflr	r31								; (TEST/DEBUG) Save return
			bnelr-									; (TEST/DEBUG) Test already triggered, skip...
			b		fckgo							; (TEST/DEBUG) Join up...
			
fcknext:	mr.		r27,r27							; (TEST/DEBUG) Any more threads?
			bne+	fckxxx							; (TEST/DEBUG) Yes...

			mtlr	r31								; (TEST/DEBUG) Restore return
			blr										; (TEST/DEBUG) Leave...
			
fckxxx:		lwz		r28,THREAD_PSTHRN(r28)			; (TEST/DEBUG) Get next thread

fckgo:		subi	r27,r27,1						; (TEST/DEBUG) Decrement thread count
			lwz		r24,THREAD_TOP_ACT(r28)			; (TEST/DEBUG) Get activation for the thread
			lwz		r20,ACT_MACT_PCB(r24)			; (TEST/DEBUG) Get the normal context
			li		r21,SAVgeneral					; (TEST/DEBUG) Make sure this is all general context
			bl		versavetype						; (TEST/DEBUG) Check the chain
			
			lwz		r20,facctx+FPUsave(r24)			; (TEST/DEBUG) Get regular floating point
			li		r21,SAVfloat					; (TEST/DEBUG) Make sure this is all floating point
			bl		versavetype						; (TEST/DEBUG) Check the chain			
			
			lwz		r20,facctx+VMXsave(r24)			; (TEST/DEBUG) Get regular vector point
			li		r21,SAVvector					; (TEST/DEBUG) Make sure this is all vector
			bl		versavetype						; (TEST/DEBUG) Check the chain			
			
			lwz		r29,vmmControl(r24)				; (TEST/DEBUG) Get the virtual machine control blocks
			mr.		r29,r29							; (TEST/DEBUG) Are there any?
			beq+	fcknext							; (TEST/DEBUG) Nope, next thread...
			
			li		r22,kVmmMaxContextsPerThread	; (TEST/DEBUG) Get the number of control blocks	
			subi	r29,r29,vmmCEntrySize			; (TEST/DEBUG) Get running start	
			
fcknvmm:	subi	r22,r22,1						; (TEST/DEBUG) Do all of them
			mr.		r22,r22							; (TEST/DEBUG) Are we all done?
			addi	r29,r29,vmmCEntrySize			; (TEST/DEBUG) Get the next entry
			blt-	fcknext							; (TEST/DEBUG) Yes, check next thread...
			
			lwz		r23,vmmFlags(r29)				; (TEST/DEBUG) Get entry flags
			rlwinm.	r23,r23,0,0,0					; (TEST/DEBUG) Is this in use?
			beq+	fcknvmm							; (TEST/DEBUG) Not in use...
			
			lwz		r20,vmmFacCtx+FPUsave(r29)		; (TEST/DEBUG) Get regular floating point
			li		r21,SAVfloat					; (TEST/DEBUG) Make sure this is all floating point
			bl		versavetype						; (TEST/DEBUG) Check the chain			
			
			lwz		r20,vmmFacCtx+VMXsave(r29)		; (TEST/DEBUG) Get regular vector point
			li		r21,SAVvector					; (TEST/DEBUG) Make sure this is all vector
			bl		versavetype						; (TEST/DEBUG) Check the chain			
			b		fcknvmm							; (TEST/DEBUG) Get then vmm block...
			
versavetype:
			mr.		r20,r20							; (TEST/DEBUG) Chain done?
			beqlr-									; (TEST/DEBUG) Yes...
			
			lwz		r23,SAVflags(r20)				; (TEST/DEBUG) Get the flags
			rlwinm	r23,r23,24,24,31				; (TEST/DEBUG) Position it
			cmplw	r23,r21							; (TEST/DEBUG) Are we the correct type?
			beq+	versvok							; (TEST/DEBUG) This one is ok...
			
			lis		r22,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r22,r22,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			stw		r22,0(r22)						; (TEST/DEBUG) Lock out more checks
			BREAKPOINT_TRAP							; (TEST/DEBUG) Get into debugger
			
versvok:	lwz		r20,SAVprev+4(r20)				; (TEST/DEBUG) Get the previous one
			b		versavetype						; (TEST/DEBUG) Go check its type...
#endif


#endif	
