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
	
			cmpwi	cr0,r1,0						; Are we on interrupt stack?					
			lwz		r6,PP_ACTIVE_THREAD(r25)		; Get the pointer to the currently active thread
			beq-	cr0,EXT(ihandler)				; If on interrupt stack, treat this as interrupt...
			lwz		r13,THREAD_TOP_ACT(r6)			; Point to the active activation
			lwz		r26,ACT_MACT_SPF(r13)			; Get special flags
			lwz		r8,ACT_MACT_PCB(r13)			; Get the last savearea used
			rlwinm.	r26,r26,0,bbThreadbit,bbThreadbit	; Do we have Blue Box Assist active? 
			lwz		r1,ACT_MACT_KSP(r13)			; Get the top of kernel stack
			bnel-	checkassist						; See if we should assist this
			stw		r4,ACT_MACT_PCB(r13)			; Point to our savearea
			stw		r8,SAVprev(r4)					; Queue the new save area in the front 
			
#if VERIFYSAVE
			bl		versave							; (TEST/DEBUG)
#endif
			
			lwz		r9,THREAD_KERNEL_STACK(r6)		; Get our kernel stack start
			cmpwi	cr1,r1,0						; Are we already on kernel stack?
			stw		r13,SAVact(r4)					; Mark the savearea as belonging to this activation
			lwz		r26,saver1(r4)					; Get the stack at interrupt time

			bne+	cr1,.L_kstackfree				; We are not on kernel stack yet...		

			subi	r1,r26,FM_REDZONE				; Make a red zone on interrupt time kernel stack

.L_kstackfree:
			lwz		r7,savesrr1(r4)					; Pick up the entry MSR 
			sub		r9,r1,r9						; Get displacment into the kernel stack
			li		r0,0							; Make this 0
			cmplwi	cr2,r9,KERNEL_STACK_SIZE		; Do we still have room on the stack?
			beq		cr1,.L_state_on_kstack			; using above test for pcb/stack

			stw		r0,ACT_MACT_KSP(r13)			; Show that we have taken the stack

.L_state_on_kstack:	
			lwz		r9,savevrsave(r4)				; Get the VRSAVE register
			rlwinm.	r6,r7,0,MSR_VEC_BIT,MSR_VEC_BIT	; Was vector on?
			subi	r1,r1,FM_SIZE					; Push a header onto the current stack 
			bgt-	cr2,kernelStackBad				; Kernel stack is bogus...

kernelStackNotBad:									; Vector was off
			beq+	tvecoff							; Vector off, do not save vrsave...
			stw		r9,liveVRS(r25)					; Set the live value

tvecoff:	stw		r26,FM_BACKPTR(r1)				; Link back to the previous frame

#if	DEBUG
/* If debugging, we need two frames, the first being a dummy
 * which links back to the trapped routine. The second is
 * that which the C routine below will need
 */
			lwz		r3,savesrr0(r4)					; Get the point of interruption
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
			
			crandc	cr0_eq,cr7_eq,cr0_eq			; Do not intercept if we are in the kernel (cr0_eq == 1 if yes)
			
			lwz		r6,savedar(r4)					; Get the DAR 
	
			beq-	cr2, .L_call_trap				; Do not turn on interrupts for T_PREEMPT
			beq-	exitFromVM						; Any true trap but T_MACHINE_CHECK exits us from the VM...

/* syscall exception might warp here if there's nothing left
 * to do except generate a trap
 */

.L_call_trap:	

			bl	EXT(trap)

			mfmsr	r7								; Get the MSR
			rlwinm	r7,r7,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r7,r7,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r7,r7,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear the interrupt enable mask
			mtmsr	r7								; Disable for interrupts
			mfsprg	r10,0							; Restore the per_proc info
/*
 * This is also the point where new threads come when they are created.
 * The new thread is setup to look like a thread that took an 
 * interrupt and went immediatly into trap.
 */

thread_return:
			lwz		r4,SAVprev(r3)					; Pick up the previous savearea 
			lwz		r11,SAVflags(r3)				; Get the flags of the current savearea
			lwz		r8,savesrr1(r3)					; Get the MSR we are going to
			rlwinm	r11,r11,0,15,13					; Clear the syscall flag
			lwz		r1,PP_ACTIVE_THREAD(r10)		; Get the active thread 
			rlwinm.	r8,r8,0,MSR_PR_BIT,MSR_PR_BIT	; Are we going to the user?
			mfsprg	r8,1							; Get the current activation
			stw		r11,SAVflags(r3)				; Save back the flags (with reset stack cleared) 

			stw		r4,ACT_MACT_PCB(r8)				; Point to the previous savearea (or 0 if none)

			beq-	chkfac							; We are not leaving the kernel yet...

			lwz		r5,THREAD_KERNEL_STACK(r1)		; Get the base pointer to the stack 
			addi	r5,r5,KERNEL_STACK_SIZE-FM_SIZE	; Reset to empty 
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

			mfsprg	r25,0							; Get the per proc area 
			lwz		r0,saver0(r4)					; Get the original syscall number
			lwz		r17,PP_ISTACKPTR(r25)			; Get interrupt stack pointer
			rlwinm	r15,r0,0,0,19					; Clear the bottom of call number for fast check
			mr.		r17,r17							; Are we on interrupt stack?
			lwz		r7,savesrr1(r4)					; Get the SRR1 value
			beq-	EXT(ihandler)					; On interrupt stack, not allowed...
			lwz		r9,savevrsave(r4)				; Get the VRsave register
			rlwinm.	r6,r7,0,MSR_VEC_BIT,MSR_VEC_BIT	; Was vector on?
			lwz		r16,PP_ACTIVE_THREAD(r25)		; Get the thread pointer 
			mfsprg	r13,1							; Pick up the active thread 

			beq+	svecoff							; Vector off, do not save vrsave...
			stw		r9,liveVRS(r25)					; Set the live value
;
; 			Check if SCs are being redirected for the BlueBox or to VMM
;

svecoff:	lwz		r6,ACT_MACT_SPF(r13)			; Pick up activation special flags
			mtcrf	0x41,r6							; Check special flags
			crmove	cr6_eq,runningVMbit				; Remember if we are in VMM
			bne		cr6,sVMchecked					; Not running VM
			lwz		r18,spcFlags(r25)				; Load per_proc special flags
			rlwinm. r18,r18,0,FamVMmodebit,FamVMmodebit	; Is FamVMmodebit set?
			beq		sVMchecked						; Not in FAM
			cmpwi	r0,0x6004						; Is it vmm_dispatch syscall:
			bne		sVMchecked
			lwz		r26,saver3(r4)					; Get the original syscall number
			cmpwi	cr6,r26,kvmmExitToHost			; vmm_exit_to_host request
sVMchecked:
			bf+		bbNoMachSCbit,noassist			; Take branch if SCs are not redirected
			lwz		r26,ACT_MACT_BEDA(r13)			; Pick up the pointer to the blue box exception area
			b		EXT(atomic_switch_syscall)		; Go to the assist...

noassist:	cmplwi	r15,0x7000						; Do we have a fast path trap? 
			lwz		r14,ACT_MACT_PCB(r13)			; Now point to the PCB 
			beql+	fastpath						; We think it is a fastpath... 

			lwz		r1,ACT_MACT_KSP(r13)			; Get the kernel stack pointer 
#if DEBUG
			mr.		r1,r1							; Are we already on the kernel stack? 
			li		r3,T_SYSTEM_CALL				; Yup, pretend we had an interrupt... 
			beq-	EXT(ihandler)					; Bad boy, bad boy... What cha gonna do when they come for you?
#endif /* DEBUG */

			stw		r4,ACT_MACT_PCB(r13)			; Point to our savearea
			li		r0,0							; Clear this out 
			stw		r14,SAVprev(r4)					; Queue the new save area in the front 
			stw		r13,SAVact(r4)					; Point the savearea at its activation
			
#if VERIFYSAVE
			bl		versave							; (TEST/DEBUG)
#endif			
			
			mr		r30,r4							; Save pointer to the new context savearea
			lwz		r15,saver1(r4)					; Grab interrupt time stack 
			stw		r0,ACT_MACT_KSP(r13)			; Mark stack as busy with 0 val 
			stw		r15,FM_BACKPTR(r1)				; Link stack frame backwards
		
#if	DEBUG
/* If debugging, we need two frames, the first being a dummy
 * which links back to the trapped routine. The second is
 * that which the C routine below will need
 */
			lwz		r8,savesrr0(r30)				; Get the point of interruption
			stw		r8,FM_LR_SAVE(r1)				; Save old instr ptr as LR value
			stwu	r1,	-FM_SIZE(r1)				; and make new frame
#endif /* DEBUG */

			mfmsr	r11								; Get the MSR
			lwz		r15,SAVflags(r30)				; Get the savearea flags
			ori		r11,r11,lo16(MASK(MSR_EE))		; Turn on interruption enabled bit
			lwz		r0,saver0(r30)					; Get R0 back
			oris	r15,r15,SAVsyscall >> 16 		; Mark that it this is a syscall
			rlwinm	r10,r0,0,0,19					; Keep only the top part 
			stwu	r1,-(FM_SIZE+ARG_SIZE)(r1)		; Make a stack frame
			cmplwi	r10,0x6000						; Is it the special ppc-only guy?
			stw		r15,SAVflags(r30)				; Save syscall marker
			beq-	cr6,exitFromVM					; It is time to exit from alternate context...
			
			beq-	ppcscall						; Call the ppc-only system call handler...

			mtmsr	r11								; Enable interruptions

			lwz		r0,saver0(r30)					; Get the system call selector
			mr.		r0,r0							; What kind is it?
			blt-	.L_kernel_syscall				; System call number if negative, this is a mach call...
											
			cmpwi	cr0,r0,0x7FFA					; Special blue box call?
			beq-	.L_notify_interrupt_syscall		; Yeah, call it...
			
			lwz     r8,ACT_TASK(r13)				; Get our task
			lis     r10,hi16(EXT(c_syscalls_unix))	; Get top half of counter address 
			lwz     r7,TASK_SYSCALLS_UNIX(r8)		; Get the current count
			ori     r10,r10,lo16(EXT(c_syscalls_unix))	; Get low half of counter address
			addi    r7,r7,1							; Bump it
			lwz     r9,0(r10)						; Get counter
			stw     r7,TASK_SYSCALLS_UNIX(r8)		; Save it
			mr      r3,r30							; Get PCB/savearea
			mr      r4,r13							; current activation
			addi    r9,r9,1							; Add 1 
			stw     r9,0(r10)						; Save it back 
			bl      EXT(unix_syscall)				; Check out unix...

.L_call_server_syscall_exception:		
			li		r3,EXC_SYSCALL					; doexception(EXC_SYSCALL, num, 1)

.L_call_server_exception:
			mr		r4,r0							; Set syscall selector
			li		r5,1
			b		EXT(doexception)				; Go away, never to return...

.L_notify_interrupt_syscall:
			lwz		r3,saver3(r30)					; Get the new PC address to pass in
			bl		EXT(syscall_notify_interrupt)
			b		.L_syscall_return
	
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
			mtlr	r11								; Set the function address
			beq-	.L_call_server_syscall_exception	; Disabled call...
			blrl									; Call it
	
			.globl	EXT(ppcscret)

LEXT(ppcscret)
			mr.		r3,r3							; See what we should do
			mr		r31,r16							; Restore the current thread pointer
			bgt+	.L_thread_syscall_ret_check_ast	; Take normal AST checking return....
			mfsprg	r10,0							; Get the per_proc
			blt+	.L_thread_syscall_return		; Return, but no ASTs....
			lwz		r0,saver0(r30)					; Restore the system call number
			b		.L_call_server_syscall_exception	; Go to common exit...


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
			mr		r4,r30 
			bl      EXT(syscall_trace)
			lwz		r0,saver0(r30)					; Get the system call selector */
			neg		r31,r0							; Make system call number positive and put in r31
			lis		r29,hi16(EXT(mach_trap_count))	; High part of valid trap number
			ori		r29,r29,lo16(EXT(mach_trap_count))	; Low part of valid trap number
			lis		r28,hi16(EXT(mach_trap_table))	; High part of trap table
			lwz		r29,0(r29)						; Get the first invalid system call number
			ori		r28,r28,lo16(EXT(mach_trap_table))	; Low part of trap table

			cmplw	r31,r29							; See if we have a valid system call number
			slwi	r31,r31,MACH_TRAP_OFFSET_POW2	; Get offset into table
		
			bge-	.L_call_server_syscall_exception	; System call number of bogus

			add		r31,r31,r28						; Point to the system call entry
			lis		r28,hi16(EXT(kern_invalid))		; Get the high invalid routine address
			lwz		r0,MACH_TRAP_FUNCTION(r31)		; Grab the system call routine address
			ori		r28,r28,lo16(EXT(kern_invalid))	; Get the low part of the invalid routine address
			lwz		r29,MACH_TRAP_ARGC(r31)			; Get the number of arguments in the call
			cmplw	r0,r28							; Is this an invalid entry?
			beq-	.L_call_server_syscall_exception	; Yes, it is invalid...
		
/* get arg count. If argc > 8 then not all args were in regs,
 * so we must perform copyin.
 */
			cmpwi	cr0,r29,8						; Do we have more than 8 arguments?
			ble+	.L_syscall_got_args				; Nope, no copy in needed...

/* argc > 8  - perform a copyin */
/* if the syscall came from kernel space, we can just copy */

			lwz		r0,savesrr1(r30)				; Pick up exception time MSR
			andi.	r0,r0,MASK(MSR_PR)				; Check the priv bit
			bne+	.L_syscall_arg_copyin			; We are not priviliged...

/* we came from a privilaged task, just do a copy */
/* get user's stack pointer */

			lwz		r28,saver1(r30)					; Get the stack pointer

			subi	r29,r29,8						; Get the number of arguments to copy 

			addi	r28,r28,COPYIN_ARG0_OFFSET-4	; Point to source - 4 
			addi	r27,r1,FM_ARG0-4			; Point to sink - 4

.L_syscall_copy_word_loop:
			addic.	r29,r29,-1						; Count down the number of arguments left
			lwz		r0,4(r28)						; Pick up the argument from the stack 
			addi	r28,r28,4						; Point to the next source 
			stw		r0,4(r27)						; Store the argument 
			addi	r27,r27,4						; Point to the next sink 
			bne+	.L_syscall_copy_word_loop		; Move all arguments... 
			b		.L_syscall_got_args				; Go call it now... 


/* we came from a user task, pay the price of a real copyin */	
/* set recovery point */

			.align	5

.L_syscall_arg_copyin:
			lwz		r8,ACT_VMMAP(r13)				; Get the vm_map for this activation
			lis		r28,hi16(.L_syscall_copyin_recover)
			lwz		r8,VMMAP_PMAP(r8)				; Get the pmap
			ori		r28,r28,lo16(.L_syscall_copyin_recover)
			addi	r8,r8,PMAP_SEGS					; Point to the pmap SR slots
			stw		r28,THREAD_RECOVER(r16) 		; R16 still holds thread ptr 

/* We can manipulate the COPYIN segment register quite easily
 * here, but we've also got to make sure we don't go over a
 * segment boundary - hence some mess.
 * Registers from 12-29 are free for our use.
 */
	

			lwz		r28,saver1(r30)					; Get the stack pointer 
			subi	r29,r29,8						; Get the number of arguments to copy
			addi	r28,r28,COPYIN_ARG0_OFFSET		; Set source in user land 

/* set up SR_COPYIN to allow us to copy, we may need to loop
 * around if we change segments. We know that this previously
 * pointed to user space, so the sid doesn't need setting.
 */

			rlwinm	r7,r28,6,26,29					; Get index to the segment slot

.L_syscall_copyin_seg_loop:			
			lwzx	r10,r8,r7						; Get the source SR value
			rlwinm	r26,r28,0,4,31					; Clear the segment number from source address
			mtsr	SR_COPYIN,r10					; Set the copyin SR
			isync

			oris	r26,r26,(SR_COPYIN_NUM << (28-16))	; Insert the copyin segment number into source address
	
			addi	r27,r1,FM_ARG0-4				; Point to area - 4 where we will store the arguments
	
.L_syscall_copyin_word_loop:			
			lwz		r0,0(r26)						; MAY CAUSE PAGE FAULT!
			subi	r29,r29,1						; Decrement count
			addi	r26,r26,4						; Bump input
			stw		r0,4(r27)						; Save the copied in word
			mr.		r29,r29							; Are they all moved?
			addi	r27,r27,4						; Bump output
			beq+	.L_syscall_copyin_done			; Escape if we are done...
	
			rlwinm.	r0,r26,0,4,29					; Did we just step into a new segment?		
			addi	r28,r28,4						; Bump up user state address also
			bne+	.L_syscall_copyin_word_loop		; We are still on the same segment...

			addi	r7,r7,4							; Bump to next slot
			b		.L_syscall_copyin_seg_loop		; On new segment! remap 

/* Don't bother restoring SR_COPYIN, we can leave it trashed */
/* clear thread recovery as we're done touching user data */

			.align	5

.L_syscall_copyin_done:	
			li		r0,0
			stw		r0,THREAD_RECOVER(r16) 			; R16 still holds thread ptr 

.L_syscall_got_args:
			lwz		r0,MACH_TRAP_FUNCTION(r31)		; Get function address
			lwz		r8,ACT_TASK(r13)				; Get our task 
			lis		r10,hi16(EXT(c_syscalls_mach))	; Get top half of counter address
			lwz		r7,TASK_SYSCALLS_MACH(r8)		; Get the current count
			lwz		r3,saver3(r30)  				; Restore r3
			addi	r7,r7,1							; Bump it
			ori		r10,r10,lo16(EXT(c_syscalls_mach)) ; Get low half of counter address 
			stw		r7,TASK_SYSCALLS_MACH(r8)		; Save it
			lwz		r4,saver4(r30)  				; Restore r4 
			lwz		r9,0(r10)						; Get counter	
			mtctr	r0								; Set function address
			lwz		r5,saver5(r30)  				; Restore r5 
			lwz		r6,saver6(r30)  				; Restore r6
			addi	r9,r9,1							; Add 1 
			lwz		r7,saver7(r30)  				; Restore r7 
			lwz		r8,saver8(r30)  				; Restore r8 
			stw		r9,0(r10)						; Save it back	
			lwz		r9,saver9(r30)  				; Restore r9 
			lwz		r10,saver10(r30)  				; Restore r10


;
;			Note that all arguments from the system call are passed into the function
;

			bctrl									; Perform the actual syscall

/* 'standard' syscall returns here - INTERRUPTS ARE STILL ON */

/* r3 contains value that we're going to return to the user
 */

/*
 * Ok, return from C function, R3 = return value
 *
 * get the active thread's PCB pointer and thus pointer to user state
 * saved state is still in R30 and the active thread is in R16	.	
 */

/* Store return value into saved state structure, since
 * we need to pick up the value from here later - the
 * syscall may perform a thread_set_syscall_return
 * followed by a thread_exception_return, ending up
 * at thread_syscall_return below, with SS_R3 having
 * been set up already
 */

/* When we are here, r16 should point to the current thread,
 *                   r30 should point to the current pcb
 */

/* save off return value, we must load it
 * back anyway for thread_exception_return
 */

.L_syscall_return:	
			mr		r31,r16							; Move the current thread pointer
			stw		r3,saver3(r30)					; Stash the return code
	
			mr		r4,r30							; Pass in the savearea
			bl		EXT(syscall_trace_end)			; Trace the exit of the system call	
	
.L_thread_syscall_ret_check_ast:	
			mfmsr	r12								; Get the current MSR 
			rlwinm	r12,r12,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r12,r12,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r12,r12,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Turn off interruptions enable bit
			mtmsr	r12								; Turn interruptions off
			
			mfsprg	r10,0							; Get the per_processor block

/* Check to see if there's an outstanding AST */
		
			lwz		r4,PP_NEED_AST(r10)				; Get the pointer to the ast requests
			lwz		r4,0(r4)						; Get the flags
			cmpi	cr0,r4,	0						; Any pending asts?
			beq+	cr0,.L_syscall_no_ast			; Nope...

/* Yes there is, call ast_taken 
 * pretending that the user thread took an AST exception here,
 * ast_taken will save all state and bring us back here
 */

#if	DEBUG
/* debug assert - make sure that we're not returning to kernel */
			lwz		r3,savesrr1(r30)
			andi.	r3,r3,MASK(MSR_PR)
			bne+	scrnotkern						; returning to user level, check 
			
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
			mfsprg	r8,1				 			; Now find the current activation 

			lwz		r11,SAVflags(r30)				; Get the flags 
			lwz		r5,THREAD_KERNEL_STACK(r31)		; Get the base pointer to the stack 
			rlwinm	r11,r11,0,15,13					; Clear the syscall flag
			lwz		r4,SAVprev(r30)					; Get the previous save area
			stw		r11,SAVflags(r30)				; Stick back the flags
			addi	r5,r5,KERNEL_STACK_SIZE-FM_SIZE	; Reset to empty
			stw		r4,ACT_MACT_PCB(r8)				; Save previous save area
			stw		r5,ACT_MACT_KSP(r8)				; Save the empty stack pointer
			b		chkfac							; Go end it all...

			.align	5

.L_syscall_copyin_recover:

/* This is the catcher for any data faults in the copyin
 * of arguments from the user's stack.
 * r30 still holds a pointer to the PCB
 *
 * call syscall_error(EXC_BAD_ACCESS, EXC_PPC_VM_PROT_READ, sp, ssp),
 *
 * we already had a frame so we can do this
 */	
	
			li		r3,EXC_BAD_ACCESS				; Set bad access code
			li		r4,EXC_PPC_VM_PROT_READ			; Set protection exception
			lwz		r5,saver1(r30)					; Point to the stack
			mr		r6,r30							; Pass savearea
		
			bl		EXT(syscall_error)				; Generate error...
			b		.L_syscall_return				; Continue out...

		
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
			mfmsr	r3								; Get the MSR 
			rlwinm	r3,r3,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r3,r3,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r3,r3,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Clear EE 
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
			beq		cr0,.L_exc_ret_no_ast
		
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
		
			lwz		r3,savesrr1(r30)
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
			mr		r3,r30							; Copy pcb pointer into r3 in case we need it
			andis.	r0,r0,SAVsyscall>>16			; Are we returning from a syscall?
			beq-	cr0,thread_return				; Nope, must be a thread return...
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
			addi	r2,r3,savevscr					; Point past what we are clearing
			mr		r4,r3							; Save the start
			
cleardummy:	stw		r0,0(r4)						; Clear stuff
			addi	r4,r4,4							; Next word
			cmplw	r4,r2							; Still some more?
			blt+	cleardummy						; Yeah...
			
			lis		r2,hi16(MSR_EXPORT_MASK_SET)	; Set the high part of the user MSR
			ori		r2,r2,lo16(MSR_EXPORT_MASK_SET)	; And the low part
			stw		r2,savesrr1(r3)					; Set the default user MSR
	
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

			lwz		r10,savesrr1(r4)				; Get SRR1 
			lwz		r7,savevrsave(r4)				; Get the VRSAVE register
			mfsprg	r25,0							; Get the per_proc block
			li		r14,0							; Zero this for now
			rlwinm.	r13,r10,0,MSR_VEC_BIT,MSR_VEC_BIT	; Was vector on?
			lwz		r1,PP_ISTACKPTR(r25)			; Get the interrupt stack
			li		r13,0							; Zero this for now
			lwz		r16,PP_ACTIVE_THREAD(r25)		; Get the thread pointer

			beq+	ivecoff							; Vector off, do not save vrsave...
			stw		r7,liveVRS(r25)					; Set the live value

ivecoff:	li		r0,0							; Get a constant 0
			cmplwi	cr1,r16,0						; Are we still booting? 

ifpoff:		mr.		r1,r1							; Is it active?
			beq-	cr1,ihboot1						; We are still coming up...
			lwz		r13,THREAD_TOP_ACT(r16)			; Pick up the active thread
			lwz		r14,ACT_MACT_PCB(r13)			; Now point to the PCB 

ihboot1:	lwz		r9,saver1(r4)					; Pick up the rupt time stack
			stw		r14,SAVprev(r4)					; Queue the new save area in the front
			stw		r13,SAVact(r4)					; Point the savearea at its activation
			beq-	cr1,ihboot4						; We are still coming up...
			stw		r4,ACT_MACT_PCB(r13)			; Point to our savearea 

ihboot4:	bne		.L_istackfree					; Nope... 

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
			blt+	ihsetback						; Yeah, that is ok too...

			lis		r0,hi16(Choke)					; Choke code
			ori		r0,r0,lo16(Choke)				; and the rest
			li		r3,failStack					; Bad stack code
			sc										; System ABEND

			.align	5
			
.L_istackfree:
			lwz		r10,SAVflags(r4)			
			stw		r0,PP_ISTACKPTR(r25)			; Mark the stack in use 
			oris	r10,r10,HIGH_ADDR(SAVrststk)	; Indicate we reset stack when we return from this one 
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
			lwz		r5,savesrr0(r4)					; Get interrupt address 
			stw		r5,FM_LR_SAVE(r1)				; save old instr ptr as LR value 
			stwu	r1,-FM_SIZE(r1)					; Make another new frame for C routine
#endif /* DEBUG */

			lwz		r5,savedsisr(r4)				; Get the DSISR
			lwz		r6,savedar(r4)					; Get the DAR 
			
			bl	EXT(interrupt)


/* interrupt() returns a pointer to the saved state in r3
 *
 * Ok, back from C. Disable interrupts while we restore things
 */
			.globl EXT(ihandler_ret)

LEXT(ihandler_ret)									; Marks our return point from debugger entry

			mfmsr	r0								; Get our MSR
			rlwinm	r0,r0,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Force floating point off
			rlwinm	r0,r0,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Force vectors off
			rlwinm	r0,r0,0,MSR_EE_BIT+1,MSR_EE_BIT-1	; Flip off the interrupt enabled bit
			mtmsr	r0								; Make sure interrupts are disabled
			mfsprg	r10,0							; Get the per_proc block
		
			lwz		r7,SAVflags(r3)					; Pick up the flags
			lwz		r8,PP_ACTIVE_THREAD(r10)		; and the active thread 
			lwz		r9,SAVprev(r3)					; Get previous save area
			cmplwi	cr1,r8,0						; Are we still initializing?
			lwz		r12,savesrr1(r3)				; Get the MSR we will load on return 
			beq-	cr1,ihboot2						; Skip if we are still in init... 
			lwz		r8,THREAD_TOP_ACT(r8)			; Pick up the active thread 

ihboot2:	andis.	r11,r7,hi16(SAVrststk)			; Is this the first on the stack?
			beq-	cr1,ihboot3						; Skip if we are still in init... 
			stw		r9,ACT_MACT_PCB(r8)				; Point to previous context savearea 

ihboot3:	mr		r4,r3							; Move the savearea pointer
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
			lwz		r3,PP_PREEMPT_CNT(r10)		; Get preemption level 
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
			beq-	cr1,chkfac						; Jump away if we are in init...

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

chkfac:		mr		r31,r10							; Move per_proc address
			mr		r30,r4							; Preserve new level
			lwz		r29,savesrr1(r3)				; Get the current MSR
			mr.		r28,r8							; Are we still in boot?
			mr		r27,r3							; Save the old level
			beq-	chkenax							; Yeah, skip it all...
			
			rlwinm.	r0,r29,0,MSR_PR_BIT,MSR_PR_BIT	; Are we going into user state?

#if 0
			beq+	lllll							; (TEST/DEBUG)
			BREAKPOINT_TRAP							; (TEST/DEBUG)
lllll:
#endif
			
			lwz		r20,curctx(r28)					; Get our current context
			lwz		r26,deferctx(r28)				; Get any deferred context switch
			rlwinm	r29,r29,0,MSR_FP_BIT+1,MSR_FP_BIT-1	; Turn off floating point for now
			lwz		r21,FPUlevel(r20)				; Get the facility level
			cmplwi	cr2,r26,0						; Are we going into a deferred context later?
			rlwinm	r29,r29,0,MSR_VEC_BIT+1,MSR_VEC_BIT-1	; Turn off vector for now
			crnor	cr2_eq,cr0_eq,cr2_eq			; Set cr2_eq if going to user state and there is deferred
			cmplw	r27,r21							; Are we returning from the active level?
			lhz		r19,PP_CPU_NUMBER(r31)			; Get our CPU number
			bne+	fpuchkena						; Nope...

;
;			First clean up any live context we are returning from
;

			lwz		r22,FPUcpu(r20)					; Get CPU this context was last dispatched on
			
			stw		r19,FPUcpu(r20)					; Claim context for us
			
			eieio									; Make sure this gets out before owner clear
			
			lis		r23,hi16(EXT(per_proc_info))	; Set base per_proc
			mulli	r22,r22,ppSize					; Find offset to the owner per_proc			
			ori		r23,r23,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r24,FPUowner					; Displacement to FPU owner
			add		r22,r23,r22						; Point to the owner per_proc	
			li		r0,0							; We need this in a bit
			
fpuinvothr:	lwarx	r23,r24,r22						; Get the owner
			cmplw	r23,r20							; Does he still have this context?
			bne		fpuinvoths						; Nope...		
			stwcx.	r0,r24,r22						; Try to invalidate it
			bne-	fpuinvothr						; Try again if there was a collision...
			
fpuinvoths:	isync

;
;			Now if there is a savearea associated with the popped context, release it.
;			Either way, pop the level to the top stacked context.
;

			lwz		r22,FPUsave(r20)				; Get pointer to the first savearea
			li		r21,0							; Assume we popped all the way out
			mr.		r22,r22							; Is there anything there?
			beq+	fpusetlvl						; No, see if we need to enable...
			
			lwz		r21,SAVlevel(r22)				; Get the level of that savearea
			cmplw	r21,r27							; Is this the saved copy of the live stuff?
			bne		fpusetlvl						; No, leave as is...
			
			lwz		r24,SAVprev(r22)				; Pick up the previous area
			li		r21,0							; Assume we popped all the way out
			mr.		r24,r24							; Any more context stacked?
			beq-	fpuonlyone						; Nope...
			lwz		r21,SAVlevel(r24)				; Get the level associated with save

fpuonlyone:	stw		r24,FPUsave(r20)				; Dequeue this savearea

			rlwinm	r3,r22,0,0,19					; Find main savearea header
			lwz		r3,SACvrswap(r3)				; Get the virtual to real conversion
			la		r9,quickfret(r31)				; Point to the quickfret chain header					
			xor		r3,r22,r3						; Convert to physical
			
#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x3301						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif				

fpufpucdq:	lwarx	r0,0,r9							; Pick up the old chain head
			stw		r0,SAVprev(r22)					; Move it to the current guy
			stwcx.	r3,0,r9							; Save it
			bne-	fpufpucdq						; Someone chaged the list...

fpusetlvl:	stw		r21,FPUlevel(r20)				; Save the level
		
;
;			Here we check if we are at the right level
;			We need to check the level we are entering, not the one we are exiting.
;			Therefore, we will use the defer level if it is non-zero and we are
;			going into user state.
;
			
fpuchkena:	bt-		cr2_eq,fpuhasdfrd				; Skip if deferred, R26 already set up...
			mr		r26,r20							; Use the non-deferred value
			
fpuhasdfrd:	lwz		r21,FPUowner(r31)				; Get the ID of the live context
			lwz		r23,FPUlevel(r26)				; Get the level ID
			cmplw	cr3,r26,r21						; Do we have the live context?
			lwz		r24,FPUcpu(r26)					; Get the CPU that the context was last dispatched on
			bne-	cr3,chkvec						; No, can not possibly enable...
			cmplw	r30,r23							; Are we about to launch the live level?
			cmplw	cr1,r19,r24						; Was facility used on this processor last?
			bne-	chkvec							; No, not live...
			bne-	cr1,chkvec						; No, wrong cpu, have to enable later....
			
			lwz		r24,FPUsave(r26)				; Get the first savearea
			mr.		r24,r24							; Any savearea?
			beq+	fpuena							; Nope...
			lwz		r25,SAVlevel(r24)				; Get the level of savearea
			lwz		r0,SAVprev(r24)					; Get the previous
			cmplw	r30,r25							; Is savearea for the level we are launching?
			bne+	fpuena							; No, just go enable...
			
			stw		r0,FPUsave(r26)					; Pop the chain

			rlwinm	r3,r24,0,0,19					; Find main savearea header
			lwz		r3,SACvrswap(r3)				; Get the virtual to real conversion
			la		r9,quickfret(r31)				; Point to the quickfret chain header					
			xor		r3,r24,r3						; Convert to physical

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x3302						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif				
			
fpuhascdq:	lwarx	r0,0,r9							; Pick up the old chain head
			stw		r0,SAVprev(r24)					; Move it to the current guy
			stwcx.	r3,0,r9							; Save it
			bne-	fpuhascdq						; Someone chaged the list...

fpuena:		ori		r29,r29,lo16(MASK(MSR_FP))		; Enable facility			
			
chkvec:		

#if 0
			rlwinm.	r21,r29,0,MSR_PR_BIT,MSR_PR_BIT	; (TEST/DEBUG)
			beq+	ppppp							; (TEST/DEBUG)
			lwz		r21,FPUlevel(r26)				; (TEST/DEBUG)
			mr.		r21,r21							; (TEST/DEBUG)
			bne-	qqqqq							; (TEST/DEBUG)
			lwz		r21,FPUsave(r26)				; (TEST/DEBUG)
			mr.		r21,r21							; (TEST/DEBUG)
			beq+	ppppp							; (TEST/DEBUG)
			lwz		r22,SAVlevel(r21)				; (TEST/DEBUG)
			mr.		r22,r22							; (TEST/DEBUG)
			beq+	ppppp							; (TEST/DEBUG)
qqqqq:
			BREAKPOINT_TRAP							; (TEST/DEBUG)

ppppp:												; (TEST/DEBUG)
#endif
			
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
			mulli	r22,r22,ppSize					; Find offset to the owner per_proc			
			ori		r23,r23,lo16(EXT(per_proc_info))	; Set base per_proc
			li		r24,VMXowner					; Displacement to VMX owner
			add		r22,r23,r22						; Point to the owner per_proc	
			li		r0,0							; We need this in a bit
			
vmxinvothr:	lwarx	r23,r24,r22						; Get the owner
			cmplw	r23,r20							; Does he still have this context?
			bne		vmxinvoths						; Nope...		
			stwcx.	r0,r24,r22						; Try to invalidate it
			bne-	vmxinvothr						; Try again if there was a collision...
			
vmxinvoths:	isync

;
;			Now if there is a savearea associated with the popped context, release it.
;			Either way, pop the level to the top stacked context.
;

			lwz		r22,VMXsave(r20)				; Get pointer to the first savearea
			li		r21,0							; Assume we popped all the way out
			mr.		r22,r22							; Is there anything there?
			beq+	vmxsetlvl						; No, see if we need to enable...
			
			lwz		r21,SAVlevel(r22)				; Get the level of that savearea
			cmplw	r21,r27							; Is this the saved copy of the live stuff?
			bne		vmxsetlvl						; No, leave as is...
			
			lwz		r24,SAVprev(r22)				; Pick up the previous area
			li		r21,0							; Assume we popped all the way out
			mr.		r24,r24							; Any more context?
			beq-	vmxonlyone						; Nope...
			lwz		r21,SAVlevel(r24)				; Get the level associated with save

vmxonlyone:	stw		r24,VMXsave(r20)				; Dequeue this savearea
			
			rlwinm	r3,r22,0,0,19					; Find main savearea header
			lwz		r3,SACvrswap(r3)				; Get the virtual to real conversion
			la		r9,quickfret(r31)				; Point to the quickfret chain header					
			xor		r3,r22,r3						; Convert to physical

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x3401						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif				
			
vmxhscdq:	lwarx	r0,0,r9							; Pick up the old chain head
			stw		r0,SAVprev(r22)					; Move it to the current guy
			stwcx.	r3,0,r9							; Save it
			bne-	vmxhscdq						; Someone chaged the list...

vmxsetlvl:	stw		r21,VMXlevel(r20)				; Save the level
		
;
;			Here we check if we are at the right level
;
			
vmxchkena:	lwz		r21,VMXowner(r31)				; Get the ID of the live context
			lwz		r23,VMXlevel(r26)				; Get the level ID
			cmplw	r26,r21							; Do we have the live context?
			lwz		r24,VMXcpu(r26)					; Get the CPU that the context was last dispatched on
			bne-	setena							; No, can not possibly enable...
			cmplw	r30,r23							; Are we about to launch the live level?
			cmplw	cr1,r19,r24						; Was facility used on this processor last?
			bne-	setena							; No, not live...
			bne-	cr1,setena						; No, wrong cpu, have to enable later....
			
			lwz		r24,VMXsave(r26)				; Get the first savearea
			mr.		r24,r24							; Any savearea?
			beq+	vmxena							; Nope...
			lwz		r25,SAVlevel(r24)				; Get the level of savearea
			lwz		r0,SAVprev(r24)					; Get the previous
			cmplw	r30,r25							; Is savearea for the level we are launching?
			bne+	vmxena							; No, just go enable...

			stw		r0,VMXsave(r26)					; Pop the chain
			
			rlwinm	r3,r24,0,0,19					; Find main savearea header
			lwz		r3,SACvrswap(r3)				; Get the virtual to real conversion
			la		r9,quickfret(r31)				; Point to the quickfret chain header					
			xor		r3,r24,r3						; Convert to physical

#if FPVECDBG
			lis		r0,HIGH_ADDR(CutTrace)			; (TEST/DEBUG)
			li		r2,0x3402						; (TEST/DEBUG)
			oris	r0,r0,LOW_ADDR(CutTrace)		; (TEST/DEBUG)
			sc										; (TEST/DEBUG)
#endif				
			
vmxckcdq:	lwarx	r0,0,r9							; Pick up the old chain head
			stw		r0,SAVprev(r24)					; Move it to the current guy
			stwcx.	r3,0,r9							; Save it
			bne-	vmxckcdq						; Someone chaged the list...
			
vmxena:		oris	r29,r29,hi16(MASK(MSR_VEC))		; Enable facility


setena:		rlwinm.	r0,r29,0,MSR_PR_BIT,MSR_PR_BIT	; Are we about to launch user state?
			rlwinm	r20,r29,(((31-vectorCngbit)+(MSR_VEC_BIT+1))&31),vectorCngbit,vectorCngbit	; Set flag if we enabled vector
			stw		r29,savesrr1(r27)				; Turn facility on or off
			crmove	cr7_eq,cr0_eq					; Remember if we are going to user state
			lwz		r19,deferctx(r28)				; Get any deferred facility context switch
			rlwimi.	r20,r29,(((31-floatCngbit)+(MSR_FP_BIT+1))&31),floatCngbit,floatCngbit	; Set flag if we enabled floats
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
			ble-	chkenax							; We have popped or are just about to...
			
segtb:		mftbu	r20								; Get the upper time base
			mftb	r21								; Get the low
			mftbu	r19								; Get upper again
			or.		r0,r22,r23						; Any time set?
			cmplw	cr1,r20,r19						; Did they change?
			beq+	chkenax							; No time set....
			bne-	cr1,segtb						; Timebase ticked, get them again...
			
			subfc	r6,r21,r23						; Subtract current from qact time
			li		r0,0							; Make a 0
			subfe	r5,r20,r22						; Finish subtract
			subfze	r0,r0							; Get a 0 if qact was bigger than current, -1 otherwise
			andc.	r12,r5,r0						; Set 0 if qact has passed
			andc	r13,r6,r0						; Set 0 if qact has passed
			bne		chkenax							; If high order is non-zero, this is too big for a decrementer
			cmplw	r13,r24							; Is this earlier than the decrementer? (logical compare takes care of high bit on)
			bge+	chkenax							; No, do not reset decrementer...
			
			mtdec	r13								; Set our value

chkenax:	

	
#if DEBUG
			lwz		r20,SAVact(r27)					; (TEST/DEBUG) Make sure our restore
			lwz		r21,PP_ACTIVE_THREAD(r31)		; (TEST/DEBUG) with the current act.
			cmpwi	r21,0							; (TEST/DEBUG)
			beq-	yeswereok						; (TEST/DEBUG)
			lwz		r21,THREAD_TOP_ACT(r21)			; (TEST/DEBUG)
			cmplw	r21,r20							; (TEST/DEBUG)
			beq+	yeswereok						; (TEST/DEBUG)

			lis		r0,hi16(Choke)					; (TEST/DEBUG) Choke code
			ori		r0,r0,lo16(Choke)				; (TEST/DEBUG) and the rest
			mr		r21,r27							; (TEST/DEBUG) Save the savearea address
			li		r3,failContext					; (TEST/DEBUG) Bad state code
			sc										; (TEST/DEBUG) System ABEND

yeswereok:
#endif
	
			rlwinm	r5,r27,0,0,19					; Round savearea down to page bndry
			lwz		r5,SACvrswap(r5)				; Get the conversion from virtual to real
			xor		r3,r27,r5						; Flip to physical address
			b		EXT(exception_exit)				; We are all done now...



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

fastpath:	cmplwi	cr3,r0,0x7FF1				; Is it CthreadSetSelfNumber? 	
			bnelr-	cr3							; Not a fast path...

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

			lwz		r5,saver3(r4)				/* Retrieve the self number */
			stw		r5,CTHREAD_SELF(r13)		/* Remember it */
			stw		r5,UAW(r25)					/* Prime the per_proc_info with it */


			.globl	EXT(fastexit)
EXT(fastexit):
			rlwinm	r9,r4,0,0,19				/* Round down to the base savearea block */
			lwz		r9,SACvrswap(r9)			/* Get the conversion from virtual to real */
			xor		r3,r4,r9					/* Switch savearea to physical addressing */
			b		EXT(exception_exit)			/* Go back to the caller... */


/*
 *			Here's where we check for a hit on the Blue Box Assist
 *			Most registers are non-volatile, so be careful here. If we don't 
 *			recognize the trap instruction we go back for regular processing.
 *			Otherwise we transfer to the assist code.
 */
 
			.align	5
			
checkassist:
			lwz		r0,saveexception(r4)		; Get the exception code
			lwz		r23,savesrr1(r4)			; Get the interrupted MSR 
			lwz		r26,ACT_MACT_BEDA(r13)		; Get Blue Box Descriptor Area
			mtcrf	0x18,r23					; Check what SRR1 says
			lwz		r24,ACT_MACT_BTS(r13)		; Get the table start 
			cmplwi	r0,T_AST					; Check for T_AST trap 
			lwz		r27,savesrr0(r4)			; Get trapped address 
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
			lwz		r4,SAVprev(r30)				; Pick up the previous savearea
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
LEXT(chandler)									/* Choke handler */

			lis		r25,hi16(EXT(trcWork))		; (TEST/DEBUG)
			li		r31,0						; (TEST/DEBUG)
			ori		r25,r25,lo16(EXT(trcWork))	; (TEST/DEBUG)
			stw		r31,traceMask(r25)			; (TEST/DEBUG)
		
		
			mfsprg	r25,0						; Get the per_proc 
		
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
			lwz		r10,saver1(r4)				; 
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
#if 1
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
			
versvok:	lwz		r20,SAVprev(r20)				; (TEST/DEBUG) Get the previous one
			b		versavetype						; (TEST/DEBUG) Go check its type...
#endif

#if 0
;
;			Make sure there are no circular links in the float chain
;			And that FP is marked busy in it.
;			And the only the top is marked invalid.
;			And that the owning PCB is correct.
;

			lis		r28,hi16(EXT(default_pset))		; (TEST/DEBUG)
			lis		r27,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r28,r28,lo16(EXT(default_pset))	; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			li		r20,0							; (TEST/DEBUG)
			lwz		r26,0(r27)						; (TEST/DEBUG)
			lwz		r27,psthreadcnt(r28)			; (TEST/DEBUG)
			mr.		r26,r26							; (TEST/DEBUG)
			lwz		r28,psthreads(r28)				; (TEST/DEBUG)
			bnelr-									; (TEST/DEBUG)
			
fcknxtth:	mr.		r27,r27							; (TEST/DEBUG)
			beqlr-									; (TEST/DEBUG)
			
			lwz		r26,THREAD_TOP_ACT(r28)			; (TEST/DEBUG)

fckact:		mr.		r26,r26							; (TEST/DEBUG)
			bne+	fckact2							; (TEST/DEBUG)
			
			lwz		r28,THREAD_PSTHRN(r28)			; (TEST/DEBUG) Next in line
			subi	r27,r27,1						; (TEST/DEBUG)
			b		fcknxtth						; (TEST/DEBUG) 
	
fckact2:	lwz		r20,ACT_MACT_FPU(r26)			; (TEST/DEBUG) Get FPU chain
			li		r29,1							; (TEST/DEBUG)
			li		r22,0							; (TEST/DEBUG)

fckact3:	mr.		r20,r20							; (TEST/DEBUG) Are there any?
			beq+	fckact5							; (TEST/DEBUG) No...
			
			addi	r22,r22,1						; (TEST/DEBUG) Count chain depth
			
			lwz		r21,SAVflags(r20)				; (TEST/DEBUG) Get the flags
			rlwinm.	r21,r21,0,1,1					; (TEST/DEBUG) FP busy?
			bne+	fckact3a						; (TEST/DEBUG) Yeah...
			lis		r27,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			stw		r27,0(r27)						; (TEST/DEBUG)
			BREAKPOINT_TRAP							; (TEST/DEBUG) Die
			
fckact3a:	cmplwi	r22,1							; (TEST/DEBUG) At first SA?
			beq+	fckact3b						; (TEST/DEBUG) Yeah, invalid is ok...
			lwz		r21,SAVlvlfp(r20)				; (TEST/DEBUG) Get level
			cmplwi	r21,1							; (TEST/DEBUG) Is it invalid?
			bne+	fckact3b						; (TEST/DEBUG) Nope, it is ok...
			lis		r27,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			stw		r27,0(r27)						; (TEST/DEBUG)
			BREAKPOINT_TRAP							; (TEST/DEBUG) Die
			
fckact3b:	lwz		r21,SAVact(r20)					; (TEST/DEBUG) Get the owner
			cmplw	r21,r26							; (TEST/DEBUG) Correct activation?
			beq+	fckact3c						; (TEST/DEBUG) Yup...
			lis		r27,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			stw		r27,0(r27)						; (TEST/DEBUG)
			BREAKPOINT_TRAP							; (TEST/DEBUG) Die

fckact3c:											; (TEST/DEBUG)
			lbz		r21,SAVflags+3(r20)				; (TEST/DEBUG) Pick up the test byte
			mr.		r21,r21							; (TEST/DEBUG) marked?
			beq+	fckact4							; (TEST/DEBUG) No, good...
			
			lis		r27,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			stw		r27,0(r27)						; (TEST/DEBUG)
			BREAKPOINT_TRAP							; (TEST/DEBUG)
			
fckact4:	stb		r29,SAVflags+3(r20)				; (TEST/DEBUG) Set the test byte
			lwz		r20,SAVprefp(r20)				; (TEST/DEBUG) Next in list
			b		fckact3							; (TEST/DEBUG) Try it...

fckact5:	lwz		r20,ACT_MACT_FPU(r26)			; (TEST/DEBUG) Get FPU chain
			li		r29,0							; (TEST/DEBUG)

fckact6:	mr.		r20,r20							; (TEST/DEBUG) Are there any?
			beq+	fcknact							; (TEST/DEBUG) No...
			
			stb		r29,SAVflags+3(r20)				; (TEST/DEBUG) Clear the test byte
			lwz		r20,SAVprefp(r20)				; (TEST/DEBUG) Next in list
			b		fckact6							; (TEST/DEBUG) Try it...
			
fcknact:	lwz		r26,ACT_LOWER(r26)				; (TEST/DEBUG) Next activation
			b		fckact							; (TEST/DEBUG)
#endif


#if 0
;
;			Make sure in use count matches found savearea.  This is
;			not always accurate.  There is a variable "fuzz" factor in count.

			lis		r28,hi16(EXT(default_pset))		; (TEST/DEBUG)
			lis		r27,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r28,r28,lo16(EXT(default_pset))	; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			li		r20,0							; (TEST/DEBUG)
			lwz		r26,0(r27)						; (TEST/DEBUG)
			lwz		r27,psthreadcnt(r28)			; (TEST/DEBUG)
			mr.		r26,r26							; (TEST/DEBUG)
			lwz		r28,psthreads(r28)				; (TEST/DEBUG)
			bnelr-									; (TEST/DEBUG)
			
cknxtth:	mr.		r27,r27							; (TEST/DEBUG)
			beq-	cktotal							; (TEST/DEBUG)
			
			lwz		r26,THREAD_TOP_ACT(r28)			; (TEST/DEBUG)

ckact:		mr.		r26,r26							; (TEST/DEBUG)
			bne+	ckact2							; (TEST/DEBUG)
			
			lwz		r28,THREAD_PSTHRN(r28)			; (TEST/DEBUG) Next in line
			subi	r27,r27,1						; (TEST/DEBUG)
			b		cknxtth							; (TEST/DEBUG) 
			
ckact2:		lwz		r29,ACT_MACT_PCB(r26)			; (TEST/DEBUG)
			
cknorm:		mr.		r29,r29							; (TEST/DEBUG)
			beq-	cknormd							; (TEST/DEBUG)
			
			addi	r20,r20,1						; (TEST/DEBUG) Count normal savearea
			
			lwz		r29,SAVprev(r29)				; (TEST/DEBUG)
			b		cknorm							; (TEST/DEBUG)
			
cknormd:	lwz		r29,ACT_MACT_FPU(r26)			; (TEST/DEBUG)

ckfpu:		mr.		r29,r29							; (TEST/DEBUG)
			beq-	ckfpud							; (TEST/DEBUG)
			
			lwz		r21,SAVflags(r29)				; (TEST/DEBUG)
			rlwinm.	r21,r21,0,0,0					; (TEST/DEBUG) See if already counted
			bne-	cknfpu							; (TEST/DEBUG)
			
			addi	r20,r20,1						; (TEST/DEBUG) Count fpu savearea
			
cknfpu:		lwz		r29,SAVprefp(r29)				; (TEST/DEBUG)
			b		ckfpu							; (TEST/DEBUG)
			
ckfpud:		lwz		r29,ACT_MACT_VMX(r26)			; (TEST/DEBUG)

ckvmx:		mr.		r29,r29							; (TEST/DEBUG)
			beq-	ckvmxd							; (TEST/DEBUG)
			
			lwz		r21,SAVflags(r29)				; (TEST/DEBUG)
			rlwinm.	r21,r21,0,0,1					; (TEST/DEBUG) See if already counted
			bne-	cknvmx							; (TEST/DEBUG)
			
			addi	r20,r20,1						; (TEST/DEBUG) Count vector savearea
			
cknvmx:		lwz		r29,SAVprevec(r29)				; (TEST/DEBUG)
			b		ckvmx							; (TEST/DEBUG)
			
ckvmxd:		lwz		r26,ACT_LOWER(r26)				; (TEST/DEBUG) Next activation
			b		ckact							; (TEST/DEBUG)

cktotal:	lis		r28,hi16(EXT(saveanchor))		; (TEST/DEBUG)
			lis		r27,hi16(EXT(real_ncpus))		; (TEST/DEBUG)
			ori		r28,r28,lo16(EXT(saveanchor))	; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(real_ncpus))	; (TEST/DEBUG)

			lwz		r21,SVinuse(r28)				; (TEST/DEBUG)
			lwz		r27,0(r27)						; (TEST/DEBUG) Get the number of CPUs
			sub.	r29,r21,r20						; (TEST/DEBUG) Get number accounted for
			blt-	badsave							; (TEST/DEBUG) Have too many in use...
			sub		r26,r29,r27						; (TEST/DEBUG) Should be 1 unaccounted for for each processor
			cmpwi	r26,10							; (TEST/DEBUG) Allow a 10 area slop factor
			bltlr+									; (TEST/DEBUG)
			
badsave:	lis		r27,hi16(EXT(DebugWork))		; (TEST/DEBUG)
			ori		r27,r27,lo16(EXT(DebugWork))	; (TEST/DEBUG)
			stw		r27,0(r27)						; (TEST/DEBUG)
			BREAKPOINT_TRAP							; (TEST/DEBUG)
#endif
#endif	
