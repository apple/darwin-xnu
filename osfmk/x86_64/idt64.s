/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
#include <i386/asm.h>
#include <assym.s>
#include <mach_kdb.h>
#include <i386/eflags.h>
#include <i386/rtclock.h>
#include <i386/trap.h>
#define _ARCH_I386_ASM_HELP_H_	/* Prevent inclusion of user header */
#include <mach/i386/syscall_sw.h>
#include <i386/postcode.h>
#include <i386/proc_reg.h>
#include <mach/exception_types.h>

#if DEBUG
#define	DEBUG_IDT64 		1	
#endif

/*
 * This is the low-level trap and interrupt handling code associated with
 * the IDT. It also includes system call handlers for sysenter/syscall.
 * The IDT itself is defined in mp_desc.c.
 *
 * Code here is structured as follows:
 *
 * stubs 	Code called directly from an IDT vector.
 *		All entry points have the "idt64_" prefix and they are built
 *		using macros expanded by the inclusion of idt_table.h.
 *		This code performs vector-dependent identification and jumps
 * 		into the dispatch code.
 *
 * dispatch	The dispatch code is responsible for saving the thread state
 *		(which is either 64-bit or 32-bit) and then jumping to the
 *		class handler identified by the stub.
 *
 * returns	Code to restore state and return to the previous context.
 *
 * handlers	There are several classes of handlers:
 *   interrupt	- asynchronous events typically from external devices
 *   trap	- synchronous events due to thread execution
 *   syscall	- synchronous system call request
 *   fatal	- fatal traps
 */

/*
 * Handlers:
 */
#define	HNDL_ALLINTRS		EXT(hndl_allintrs)
#define	HNDL_ALLTRAPS		EXT(hndl_alltraps)
#define	HNDL_SYSENTER		EXT(hndl_sysenter)
#define	HNDL_SYSCALL		EXT(hndl_syscall)
#define	HNDL_UNIX_SCALL		EXT(hndl_unix_scall)
#define	HNDL_MACH_SCALL		EXT(hndl_mach_scall)
#define	HNDL_MDEP_SCALL		EXT(hndl_mdep_scall)
#define	HNDL_DIAG_SCALL		EXT(hndl_diag_scall)
#define	HNDL_DOUBLE_FAULT	EXT(hndl_double_fault)
#define	HNDL_MACHINE_CHECK	EXT(hndl_machine_check)

/*
 * Nanosecond timing.
 */

/*
 * Nanotime returned in %rax.
 * Computed from tsc based on the scale factor and an implicit 32 bit shift.
 * This code must match what _rtc_nanotime_read does in
 * machine_routines_asm.s.  Failure to do so can
 * result in "weird" timing results.
 *
 * Uses: %rsi, %rdi, %rdx, %rcx
 */
#define NANOTIME							  \
	movq	%gs:CPU_NANOTIME,%rdi					; \
	RTC_NANOTIME_READ_FAST()

/*
 * Add 64-bit delta in register reg to timer pointed to by register treg.
 */
#define TIMER_UPDATE(treg,reg,offset)						  \
	addq	reg,(offset)+TIMER_ALL(treg)		/* add timer */

/*
 * Add time delta to old timer and start new.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 */
#define TIMER_EVENT(old,new)						  \
	NANOTIME				/* %rax := nanosecs */	; \
	movq	%rax,%rsi			/* save timestamp */	; \
	movq	%gs:CPU_ACTIVE_THREAD,%rcx		/* get thread */	; \
	subq	(old##_TIMER)+TIMER_TSTAMP(%rcx),%rax	/* compute elapsed */	; \
	TIMER_UPDATE(%rcx,%rax,old##_TIMER)	/* update timer */	; \
	leaq	(new##_TIMER)(%rcx),%rcx	/* point to new timer */; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */	; \
	movq	%gs:CPU_PROCESSOR,%rdx		/* get processor */	; \
	movq	%rcx,THREAD_TIMER(%rdx)		/* set current timer */	; \
	movq	%rsi,%rax			/* restore timestamp */	; \
	subq	(old##_STATE)+TIMER_TSTAMP(%rdx),%rax	/* compute elapsed */	; \
	TIMER_UPDATE(%rdx,%rax,old##_STATE)	/* update timer */	; \
	leaq	(new##_STATE)(%rdx),%rcx 	/* point to new state */; \
	movq	%rcx,CURRENT_STATE(%rdx)	/* set current state */	; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */

/*
 * Update time on user trap entry.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 */
#define	TIME_TRAP_UENTRY	TIMER_EVENT(USER,SYSTEM)

/*
 * update time on user trap exit.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 */
#define	TIME_TRAP_UEXIT		TIMER_EVENT(SYSTEM,USER)

/*
 * update time on interrupt entry.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 * Saves processor state info on stack.
 */
#define	TIME_INT_ENTRY							  \
	NANOTIME				/* %rax := nanosecs */	; \
	movq	%rax,%gs:CPU_INT_EVENT_TIME	/* save in cpu data */	; \
	movq	%rax,%rsi			/* save timestamp */	; \
	movq	%gs:CPU_PROCESSOR,%rdx		/* get processor */	; \
	movq 	THREAD_TIMER(%rdx),%rcx		/* get current timer */	; \
	subq	TIMER_TSTAMP(%rcx),%rax		/* compute elapsed */	; \
	TIMER_UPDATE(%rcx,%rax,0)			/* update timer */	; \
	movq	KERNEL_TIMER(%rdx),%rcx		/* get kernel timer */	; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */	; \
	movq	%rsi,%rax			/* restore timestamp */	; \
	movq	CURRENT_STATE(%rdx),%rcx	/* get current state */	; \
	pushq	%rcx				/* save state */	; \
	subq	TIMER_TSTAMP(%rcx),%rax		/* compute elapsed */	; \
	TIMER_UPDATE(%rcx,%rax,0)			/* update timer */	; \
	leaq	IDLE_STATE(%rdx),%rax		/* get idle state */	; \
	cmpq	%rax,%rcx			/* compare current */	; \
	je	0f				/* skip if equal */	; \
	leaq	SYSTEM_STATE(%rdx),%rcx		/* get system state */	; \
	movq	%rcx,CURRENT_STATE(%rdx)	/* set current state */	; \
0:	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */

/*
 * update time on interrupt exit.
 * Uses: %rsi, %rdi, %rdx, %rcx, %rax
 * Restores processor state info from stack.
 */
#define	TIME_INT_EXIT							  \
	NANOTIME				/* %rax := nanosecs */	; \
	movq	%rax,%gs:CPU_INT_EVENT_TIME	/* save in cpu data */	; \
	movq	%rax,%rsi			/* save timestamp */	; \
	movq	%gs:CPU_PROCESSOR,%rdx		/* get processor */	; \
	movq	KERNEL_TIMER(%rdx),%rcx		/* get kernel timer */	; \
	subq	TIMER_TSTAMP(%rcx),%rax		/* compute elapsed */	; \
	TIMER_UPDATE(%rcx,%rax,0)			/* update timer */	; \
	movq	THREAD_TIMER(%rdx),%rcx		/* interrupted timer */	; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */	; \
	movq	%rsi,%rax			/* restore timestamp */	; \
	movq	CURRENT_STATE(%rdx),%rcx	/* get current state */	; \
	subq	TIMER_TSTAMP(%rcx),%rax		/* compute elapsed */	; \
	TIMER_UPDATE(%rcx,%rax,0)			/* update timer */	; \
	popq	%rcx				/* restore state */	; \
	movq	%rcx,CURRENT_STATE(%rdx)	/* set current state */	; \
	movq	%rsi,TIMER_TSTAMP(%rcx)		/* set timestamp */

/*
 * Check for vtimers for task.
 *   task_reg   is register pointing to current task
 *   thread_reg is register pointing to current thread
 */
#define TASK_VTIMER_CHECK(task_reg,thread_reg)				  \
	cmpl	$0,TASK_VTIMERS(task_reg)				; \
	jz	1f							; \
	orl	$(AST_BSD),%gs:CPU_PENDING_AST	/* Set pending AST */	; \
	lock								; \
	orl	$(AST_BSD),ACT_AST(thread_reg)	/* Set thread AST  */	; \
1:									; \


/*
 * Macros for calling into C functions.
 * The stack is 16-byte aligned by masking.
 */
#define CCALL(fn)				 \
	mov	%rsp, %r12			;\
	and	$0xFFFFFFFFFFFFFFF0, %rsp	;\
	call	EXT(fn)				;\
	mov	%r12, %rsp

#define CCALL1(fn, arg1) 			 \
	mov	arg1, %rdi 			;\
	CCALL(fn)

#define CCALL2(fn, arg1, arg2)		 	 \
	mov	arg1, %rdi 			;\
	CCALL(fn)

#define CCALL3(fn, arg1, arg2, arg3) 		 \
	mov	arg1, %rdi 			;\
	mov	arg2, %rsi 			;\
	mov	arg3, %rdx 			;\
	CCALL(fn)

#if 1
#define PUSH_FUNCTION(func) 			 \
	sub	$8, %rsp			;\
	push	%rax				;\
	leaq	func(%rip), %rax		;\
	movq	%rax, 8(%rsp)			;\
	pop	%rax
#else
#define PUSH_FUNCTION(func) pushq func
#endif

/* The wrapper for all non-special traps/interrupts */
/* Everything up to PUSH_FUNCTION is just to output 
 * the interrupt number out to the postcode display
 */
#if DEBUG_IDT64
#define IDT_ENTRY_WRAPPER(n, f)			 \
	push	%rax				;\
	POSTCODE2(0x6400+n)			;\
	pop	%rax				;\
	PUSH_FUNCTION(f)  			;\
	pushq	$(n)				;\
	jmp L_dispatch
#else
#define IDT_ENTRY_WRAPPER(n, f)			 \
	PUSH_FUNCTION(f)  			;\
	pushq	$(n)				;\
	jmp L_dispatch
#endif

/* A trap that comes with an error code already on the stack */
#define TRAP_ERR(n, f)				 \
	Entry(f)				;\
	IDT_ENTRY_WRAPPER(n, HNDL_ALLTRAPS)

/* A normal trap */
#define TRAP(n, f)				 \
	Entry(f)				;\
	pushq	$0          			;\
	IDT_ENTRY_WRAPPER(n, HNDL_ALLTRAPS)

#define USER_TRAP TRAP

/* An interrupt */
#define INTERRUPT(n)			 	\
	Entry(_intr_ ## n)			;\
	pushq	$0          			;\
	IDT_ENTRY_WRAPPER(n, HNDL_ALLINTRS)

/* A trap with a special-case handler, hence we don't need to define anything */
#define TRAP_SPC(n, f)
#define TRAP_IST(n, f)
#define USER_TRAP_SPC(n, f)

/* Generate all the stubs */
#include "idt_table.h"

/*
 * Common dispatch point.
 * Determine what mode has been interrupted and save state accordingly.
 */
L_dispatch:
	cmpq	$(KERNEL64_CS), ISF64_CS(%rsp)
	je	L_64bit_dispatch

	swapgs

	cmpl	$(USER_CS), ISF64_CS(%rsp)
	je	L_32bit_dispatch /* 32-bit user task */
	/* fall through to 64bit user dispatch */

/*
 * Here for 64-bit user task or kernel
 */
L_64bit_dispatch:
	subq	$(ISS64_OFFSET), %rsp
	movl	$(SS_64), SS_FLAVOR(%rsp)

	/*
	 * Save segment regs - for completeness since theyre not used.
	 */
	mov	%fs, R64_FS(%rsp)
	mov	%gs, R64_GS(%rsp)

	/* Save general-purpose registers */
	mov	%rax, R64_RAX(%rsp)
	mov	%rcx, R64_RCX(%rsp)
	mov	%rbx, R64_RBX(%rsp)
	mov	%rbp, R64_RBP(%rsp)
	mov	%r11, R64_R11(%rsp)
	mov	%r12, R64_R12(%rsp)
	mov	%r13, R64_R13(%rsp)
	mov	%r14, R64_R14(%rsp)
	mov	%r15, R64_R15(%rsp)

	/* cr2 is significant only for page-faults */
	mov	%cr2, %rax
	mov	%rax, R64_CR2(%rsp)

	/* Other registers (which may contain syscall args) */
	mov	%rdi, R64_RDI(%rsp)	/* arg0 .. */
	mov	%rsi, R64_RSI(%rsp)
	mov	%rdx, R64_RDX(%rsp)
	mov	%r10, R64_R10(%rsp)
	mov	%r8, R64_R8(%rsp)
	mov	%r9, R64_R9(%rsp)	/* .. arg5 */

	mov	R64_TRAPNO(%rsp), %ebx	/* %ebx := trapno for later */
	mov	R64_TRAPFN(%rsp), %rdx	/* %rdx := trapfn for later */
	mov	R64_CS(%rsp), %esi	/* %esi := cs for later */

	jmp L_common_dispatch

L_64bit_entry_reject:
	/*
	 * Here for a 64-bit user attempting an invalid kernel entry.
	 */
	pushq	%rax
	leaq	HNDL_ALLTRAPS(%rip), %rax
	movq	%rax, ISF64_TRAPFN+8(%rsp)
	popq	%rax
	movq	$(T_INVALID_OPCODE), ISF64_TRAPNO(%rsp)
	jmp 	L_64bit_dispatch
	
L_32bit_entry_check:
	/*
	 * Check we're not a confused 64-bit user.
	 */
	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP
	jne	L_64bit_entry_reject
	/* fall through to 32-bit handler: */

L_32bit_dispatch: /* 32-bit user task */
	subq	$(ISC32_OFFSET), %rsp
	movl	$(SS_32), SS_FLAVOR(%rsp)

	/*
	 * Save segment regs
	 */
	mov	%ds, R32_DS(%rsp)
	mov	%es, R32_ES(%rsp)
	mov	%fs, R32_FS(%rsp)
	mov	%gs, R32_GS(%rsp)

	/*
	 * Save general 32-bit registers
	 */
	mov	%eax, R32_EAX(%rsp)
	mov	%ebx, R32_EBX(%rsp)
	mov	%ecx, R32_ECX(%rsp)
	mov	%edx, R32_EDX(%rsp)
	mov	%ebp, R32_EBP(%rsp)
	mov	%esi, R32_ESI(%rsp)
	mov	%edi, R32_EDI(%rsp)

	/* Unconditionally save cr2; only meaningful on page faults */
	mov	%cr2, %rax
	mov	%eax, R32_CR2(%rsp)

	/*
	 * Copy registers already saved in the machine state 
	 * (in the interrupt stack frame) into the compat save area.
	 */
	mov	ISC32_RIP(%rsp), %eax
	mov	%eax, R32_EIP(%rsp)
	mov	ISC32_RFLAGS(%rsp), %eax
	mov	%eax, R32_EFLAGS(%rsp)
	mov	ISC32_CS(%rsp), %esi		/* %esi := %cs for later */

	mov	%esi, R32_CS(%rsp)
	mov	ISC32_RSP(%rsp), %eax
	mov	%eax, R32_UESP(%rsp)
	mov	ISC32_SS(%rsp), %eax
	mov	%eax, R32_SS(%rsp)
L_32bit_dispatch_after_fault:
	mov	ISC32_TRAPNO(%rsp), %ebx	/* %ebx := trapno for later */
	mov	%ebx, R32_TRAPNO(%rsp)
	mov	ISC32_ERR(%rsp), %eax
	mov	%eax, R32_ERR(%rsp)
	mov	ISC32_TRAPFN(%rsp), %rdx	/* %rdx := trapfn for later */

L_common_dispatch:
	/*
	 * On entering the kernel, we don't need to switch cr3
	 * because the kernel shares the user's address space.
	 * But we mark the kernel's cr3 as "active".
	 * If, however, the invalid cr3 flag is set, we have to flush tlbs
	 * since the kernel's mapping was changed while we were in userspace.
	 *
	 * But: if global no_shared_cr3 is TRUE we do switch to the kernel's cr3
	 * so that illicit accesses to userspace can be trapped.
	 */
	mov	%gs:CPU_KERNEL_CR3, %rcx
	mov	%rcx, %gs:CPU_ACTIVE_CR3
	test	$3, %esi			/* user/kernel? */
	jz	1f				/* skip cr3 reload from kernel */
	xor	%rbp, %rbp
	cmpl	$0, EXT(no_shared_cr3)(%rip)
	je	1f
	mov	%rcx, %cr3			/* load kernel cr3 */
	jmp	2f				/* and skip tlb flush test */
1:	
	cmpl	$0, %gs:CPU_TLB_INVALID		/* flush needed? */
	je	2f				/* - no */
	movl	$0, %gs:CPU_TLB_INVALID 
	mov	%cr3, %rcx
	mov	%rcx, %cr3
2:
	mov	%gs:CPU_ACTIVE_THREAD, %rcx	/* Get the active thread */
	cmpq	$0, ACT_PCB_IDS(%rcx)	/* Is there a debug register state? */
	je	3f
	mov	$0, %rcx		/* If so, reset DR7 (the control) */
	mov	%rcx, %dr7
3:
	addl	$1,%gs:hwIntCnt(,%ebx,4)	// Bump the trap/intr count
	/* Dispatch the designated handler */
	mov	%rsp, %rdi		/* rsp points to saved state */
	jmp	*%rdx

/*
 * Control is passed here to return to user.
 */ 
Entry(return_to_user)
	TIME_TRAP_UEXIT

Entry(ret_to_user)
// XXX 'Be nice to tidy up this debug register restore sequence...
	mov	%gs:CPU_ACTIVE_THREAD, %rdx
	movq	ACT_PCB_IDS(%rdx),%rax	/* Obtain this thread's debug state */
	
	cmpq	$0,%rax			/* Is there a debug register context? */
	je	2f 			/* branch if not */
	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP /* Are we a 32-bit task? */
	jne	1f
	movl	DS_DR0(%rax), %ecx	/* If so, load the 32 bit DRs */
	movq	%rcx, %dr0
	movl	DS_DR1(%rax), %ecx
	movq	%rcx, %dr1
	movl	DS_DR2(%rax), %ecx
	movq	%rcx, %dr2
	movl	DS_DR3(%rax), %ecx
	movq	%rcx, %dr3
	movl	DS_DR7(%rax), %ecx
	movq 	%rcx, %gs:CPU_DR7
	jmp 	2f
1:
	mov	DS64_DR0(%rax), %rcx	/* Load the full width DRs*/
	mov	%rcx, %dr0
	mov	DS64_DR1(%rax), %rcx
	mov	%rcx, %dr1
	mov	DS64_DR2(%rax), %rcx
	mov	%rcx, %dr2
	mov	DS64_DR3(%rax), %rcx
	mov	%rcx, %dr3
	mov	DS64_DR7(%rax), %rcx
	mov 	%rcx, %gs:CPU_DR7
2:
	/*
	 * On exiting the kernel there's no need to switch cr3 since we're
	 * already running in the user's address space which includes the
	 * kernel. Nevertheless, we now mark the task's cr3 as active.
	 * However, there may be a defered tlb flush to deal with.
	 * This is a case where another cpu modified this task's address 
	 * space while this thread was in the kernel.
	 * But, if no_shared_cr3 is set, we do need to switch cr3 at this point.
	 */
	mov	%gs:CPU_TASK_CR3, %rcx
	mov	%rcx, %gs:CPU_ACTIVE_CR3
	movl	%gs:CPU_TLB_INVALID, %eax
	orl	EXT(no_shared_cr3)(%rip), %eax
	test	%eax, %eax		/* -no_shered_cr3 or flush required? */
	jz	3f
	movl	$0, %gs:CPU_TLB_INVALID
	mov	%rcx, %cr3
3:

	mov	%gs:CPU_DR7, %rax	/* Is there a debug control register?*/
	cmp	$0, %rax
	je	4f
	mov	%rax, %dr7		/* Set DR7 */
	movq	$0, %gs:CPU_DR7
4:
	cmpl	$(SS_64), SS_FLAVOR(%rsp)	/* 64-bit state? */
	je	L_64bit_return

L_32bit_return:
#if DEBUG_IDT64
	cmpl	$(SS_32), SS_FLAVOR(%rsp)	/* 32-bit state? */
	je	1f
	cli
	POSTCODE2(0x6432)
	CCALL1(panic_idt64, %rsp)
1:
#endif /* DEBUG_IDT64 */

	/*
	 * Restore registers into the machine state for iret.
	 */
	movl	R32_EIP(%rsp), %eax
	movl	%eax, ISC32_RIP(%rsp)
	movl	R32_EFLAGS(%rsp), %eax
	movl	%eax, ISC32_RFLAGS(%rsp)
	movl	R32_CS(%rsp), %eax
	movl	%eax, ISC32_CS(%rsp)
	movl	R32_UESP(%rsp), %eax
	movl	%eax, ISC32_RSP(%rsp)
	movl	R32_SS(%rsp), %eax
	movl	%eax, ISC32_SS(%rsp)

	/*
	 * Restore general 32-bit registers
	 */
	movl	R32_EAX(%rsp), %eax
	movl	R32_EBX(%rsp), %ebx
	movl	R32_ECX(%rsp), %ecx
	movl	R32_EDX(%rsp), %edx
	movl	R32_EBP(%rsp), %ebp
	movl	R32_ESI(%rsp), %esi
	movl	R32_EDI(%rsp), %edi

	/*
	 * Restore segment registers. We make take an exception here but
	 * we've got enough space left in the save frame area to absorb
         * a hardware frame plus the trapfn and trapno
	 */
	swapgs
EXT(ret32_set_ds):	
	movw	R32_DS(%rsp), %ds
EXT(ret32_set_es):
	movw	R32_ES(%rsp), %es
EXT(ret32_set_fs):
	movw	R32_FS(%rsp), %fs
EXT(ret32_set_gs):
	movw	R32_GS(%rsp), %gs

	/* pop compat frame + trapno, trapfn and error */	
	add	$(ISC32_OFFSET)+8+8+8, %rsp
        cmp	$(SYSENTER_CS),ISF64_CS-8-8-8(%rsp)
					/* test for fast entry/exit */
        je      L_fast_exit
EXT(ret32_iret):
        iretq				/* return from interrupt */

L_fast_exit:
	pop	%rdx			/* user return eip */
	pop	%rcx			/* pop and toss cs */
	andl	$(~EFL_IF), (%rsp)	/* clear interrupts enable, sti below */
	popf				/* flags - carry denotes failure */
	pop	%rcx			/* user return esp */
	sti				/* interrupts enabled after sysexit */
	sysexit				/* 32-bit sysexit */

ret_to_kernel:
#if DEBUG_IDT64
	cmpl	$(SS_64), SS_FLAVOR(%rsp)	/* 64-bit state? */
	je	1f
	cli
	POSTCODE2(0x6464)
	CCALL1(panic_idt64, %rsp)
	hlt
1:
	cmpq	$(KERNEL64_CS), R64_CS(%rsp)
	je	2f
	CCALL1(panic_idt64, %rsp)
	hlt
2:
#endif

L_64bit_return:
	testb	$3, R64_CS(%rsp)		/* returning to user-space? */
	jz	1f
	swapgs
1:

	/*
	 * Restore general 64-bit registers
	 */
	mov	R64_R15(%rsp), %r15
	mov	R64_R14(%rsp), %r14
	mov	R64_R13(%rsp), %r13
	mov	R64_R12(%rsp), %r12
	mov	R64_R11(%rsp), %r11
	mov	R64_R10(%rsp), %r10
	mov	R64_R9(%rsp),  %r9
	mov	R64_R8(%rsp),  %r8
	mov	R64_RSI(%rsp), %rsi
	mov	R64_RDI(%rsp), %rdi
	mov	R64_RBP(%rsp), %rbp
	mov	R64_RDX(%rsp), %rdx
	mov	R64_RBX(%rsp), %rbx
	mov	R64_RCX(%rsp), %rcx
	mov	R64_RAX(%rsp), %rax

	add	$(ISS64_OFFSET)+24, %rsp	/* pop saved state frame +
						   trapno + trapfn and error */	
	cmpl	$(SYSCALL_CS),ISF64_CS-24(%rsp)
				/* test for fast entry/exit */
	je      L_sysret
.globl _dump_iretq
EXT(ret64_iret):
        iretq				/* return from interrupt */

L_sysret:
	/*
	 * Here to load rcx/r11/rsp and perform the sysret back to user-space.
	 * 	rcx	user rip
	 *	r1	user rflags
	 *	rsp	user stack pointer
	 */
	mov	ISF64_RIP-24(%rsp), %rcx
	mov	ISF64_RFLAGS-24(%rsp), %r11
	mov	ISF64_RSP-24(%rsp), %rsp
        sysretq				/* return from systen call */



/*
 * System call handlers.
 * These are entered via a syscall interrupt. The system call number in %rax
 * is saved to the error code slot in the stack frame. We then branch to the
 * common state saving code.
 */
		
#ifndef UNIX_INT
#error NO UNIX INT!!!
#endif
Entry(idt64_unix_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_unix_scall_continue:
	pushq	%rax			/* save system call number */
	PUSH_FUNCTION(HNDL_UNIX_SCALL)
	pushq	$(UNIX_INT)
	jmp	L_32bit_entry_check

	
Entry(idt64_mach_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_mach_scall_continue:
	pushq	%rax			/* save system call number */
	PUSH_FUNCTION(HNDL_MACH_SCALL)
	pushq	$(MACH_INT)
	jmp	L_32bit_entry_check

	
Entry(idt64_mdep_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_mdep_scall_continue:
	pushq	%rax			/* save system call number */
	PUSH_FUNCTION(HNDL_MDEP_SCALL)
	pushq	$(MACHDEP_INT)
	jmp	L_32bit_entry_check

	
Entry(idt64_diag_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_diag_scall_continue:
	push	%rax			/* save system call number */
	PUSH_FUNCTION(HNDL_DIAG_SCALL)
	pushq	$(DIAG_INT)
	jmp	L_32bit_entry_check

Entry(hi64_syscall)
Entry(idt64_syscall)
	swapgs				/* Kapow! get per-cpu data area */
L_syscall_continue:
	mov	%rsp, %gs:CPU_UBER_TMP	/* save user stack */
	mov	%gs:CPU_UBER_ISF, %rsp	/* switch stack to pcb */

	/*
	 * Save values in the ISF frame in the PCB
	 * to cons up the saved machine state.
	 */
	movl	$(USER_DS), ISF64_SS(%rsp)	
	movl	$(SYSCALL_CS), ISF64_CS(%rsp)	/* cs - a pseudo-segment */
	mov	%r11, ISF64_RFLAGS(%rsp)	/* rflags */
	mov	%rcx, ISF64_RIP(%rsp)		/* rip */
	mov	%gs:CPU_UBER_TMP, %rcx
	mov	%rcx, ISF64_RSP(%rsp)		/* user stack */
	mov	%rax, ISF64_ERR(%rsp)		/* err/rax - syscall code */
	movq	$(T_SYSCALL), ISF64_TRAPNO(%rsp)	/* trapno */
	leaq	HNDL_SYSCALL(%rip), %r11;
	movq	%r11, ISF64_TRAPFN(%rsp)
	jmp	L_64bit_dispatch		/* this can only be a 64-bit task */
	
/*
 * sysenter entry point
 * Requires user code to set up:
 *	edx: user instruction pointer (return address)
 *	ecx: user stack pointer
 *		on which is pushed stub ret addr and saved ebx
 * Return to user-space is made using sysexit.
 * Note: sysenter/sysexit cannot be used for calls returning a value in edx,
 *       or requiring ecx to be preserved.
 */
Entry(hi64_sysenter)
Entry(idt64_sysenter)
	movq	(%rsp), %rsp
	/*
	 * Push values on to the PCB stack
	 * to cons up the saved machine state.
	 */
	push	$(USER_DS)		/* ss */
	push	%rcx			/* uesp */
	pushf				/* flags */
	push	$(SYSENTER_CS)		/* cs */ 
	swapgs				/* switch to kernel gs (cpu_data) */
L_sysenter_continue:
	push	%rdx			/* eip */
	push	%rax			/* err/eax - syscall code */
	PUSH_FUNCTION(HNDL_SYSENTER)
	pushq	$(T_SYSENTER)
	orl	$(EFL_IF), ISF64_RFLAGS(%rsp)
	jmp	L_32bit_entry_check


Entry(idt64_page_fault)
	PUSH_FUNCTION(HNDL_ALLTRAPS)
	push	%rax			/* save %rax temporarily in trap slot */
	leaq	EXT(idt64_unix_scall_copy_args)(%rip), %rax
	cmp	%rax, ISF64_RIP(%rsp)
	jne	1f
	add	$(ISF64_SIZE), %rsp	/* remove entire intr stack frame */
	jmp	L_copy_args_continue	/* continue system call entry */
1:
	mov	(%rsp), %rax		/* restore %rax from trap slot */
	movq	$(T_PAGE_FAULT), (%rsp)	/* set trap code */
	jne	L_dispatch


/*
 * Debug trap.  Check for single-stepping across system call into
 * kernel.  If this is the case, taking the debug trap has turned
 * off single-stepping - save the flags register with the trace
 * bit set.
 */
Entry(idt64_debug)
	push	$0			/* error code */
	PUSH_FUNCTION(HNDL_ALLTRAPS)
	pushq	$(T_DEBUG)

	testb	$3, ISF64_CS(%rsp)
	jnz	L_dispatch

	/*
	 * trap came from kernel mode
	 */

	push	%rax			/* save %rax temporarily */

	leaq	EXT(idt64_mach_scall)(%rip), %rax
	cmp	%rax, ISF64_RIP(%rsp)
	jne	1f
	pop	%rax
	add	$(ISF64_SIZE),%rsp	/* remove entire intr stack frame */
	jmp	L_mach_scall_continue	/* continue system call entry */
1:
	leaq	EXT(idt64_mdep_scall)(%rip), %rax
	cmp	%rax, ISF64_RIP(%rsp)
	jne	2f
	pop	%rax
	add	$(ISF64_SIZE),%rsp	/* remove entire intr stack frame */
	jmp	L_mdep_scall_continue	/* continue system call entry */
2:
	leaq	EXT(idt64_unix_scall)(%rip), %rax
	cmp	%rax, ISF64_RIP(%rsp)
	jne	3f
	pop	%rax
	add	$(ISF64_SIZE),%rsp	/* remove entire intr stack frame */
	jmp	L_unix_scall_continue	/* continue system call entry */
3:
	lea	EXT(idt64_sysenter)(%rip), %rax
	cmp	%rax, ISF64_RIP(%rsp)
	je	4f
	pop	%rax
	jmp	L_dispatch
4:
	pop	%rax
	/*
	 * Interrupt stack frame has been pushed on the temporary stack.
	 * We have to switch to pcb stack and copy eflags.
	 */ 
	add	$40,%rsp		/* remove trapno/trapfn/err/rip/cs */
	push	%rcx			/* save %rcx - user stack pointer */
	mov	40(%rsp),%rcx		/* top of intr stack -> pcb stack */
	xchg	%rcx,%rsp		/* switch to pcb stack */
	push	$(USER_DS)		/* ss */
	push	(%rcx)			/* saved %rcx into rsp slot */
	push	8(%rcx)			/* rflags */
	mov	(%rcx),%rcx		/* restore %rcx */
	push	$(SYSENTER_TF_CS)	/* cs - not SYSENTER_CS for iret path */
	jmp	L_sysenter_continue	/* continue sysenter entry */

	

Entry(idt64_double_fault)
	PUSH_FUNCTION(HNDL_DOUBLE_FAULT)
	pushq	$(T_DOUBLE_FAULT)

	push	%rax
	leaq	EXT(idt64_syscall)(%rip), %rax
	cmp	%rax, ISF64_RIP(%rsp)
	pop	%rax
	jne	L_dispatch

	mov	ISF64_RSP(%rsp), %rsp
	jmp	L_syscall_continue
	

/*
 * General protection or segment-not-present fault.
 * Check for a GP/NP fault in the kernel_return
 * sequence; if there, report it as a GP/NP fault on the user's instruction.
 *
 * rsp->     0:	trap function
 *	     8: trap code (NP or GP)
 *	    16:	segment number in error (error code)
 *	    24:	rip
 *	    32:	cs
 *	    40:	rflags 
 *	    48:	rsp
 *	    56:	ss
 *	    64:	old registers (trap is from kernel)
 */
Entry(idt64_gen_prot)
	PUSH_FUNCTION(HNDL_ALLTRAPS)
	pushq	$(T_GENERAL_PROTECTION)
	jmp	trap_check_kernel_exit	/* check for kernel exit sequence */

Entry(idt64_stack_fault)
	PUSH_FUNCTION(HNDL_ALLTRAPS)
	pushq	$(T_STACK_FAULT)
	jmp	trap_check_kernel_exit	/* check for kernel exit sequence */

Entry(idt64_segnp)
	PUSH_FUNCTION(HNDL_ALLTRAPS)
	pushq	$(T_SEGMENT_NOT_PRESENT)
					/* indicate fault type */
trap_check_kernel_exit:
	testb	$3,32(%rsp)
	jnz	L_dispatch
	/*
	 * trap was from kernel mode,
	 * so check for the kernel exit sequence
	 */
	push	%rax

	leaq	EXT(ret32_iret)(%rip), %rax
	cmp	%rax, 24+8(%rsp)
	je	L_fault_iret
	leaq	EXT(ret64_iret)(%rip), %rax
	cmp	%rax, 24+8(%rsp)
	je	L_fault_iret
	leaq	EXT(ret32_set_ds)(%rip), %rax
	cmp	%rax, 24+8(%rsp)
	je	L_32bit_fault_set_seg
	leaq	EXT(ret32_set_es)(%rip), %rax
	cmp	%rax, 24+8(%rsp)
	je	L_32bit_fault_set_seg
	leaq	EXT(ret32_set_fs)(%rip), %rax
	cmp	%rax, 24+8(%rsp)
	je	L_32bit_fault_set_seg
	leaq	EXT(ret32_set_gs)(%rip), %rax
	cmp	%rax, 24+8(%rsp)
	je	L_32bit_fault_set_seg

	leaq	EXT(idt64_unix_scall_copy_args)(%rip), %rax
	cmp	%rax, 24+8(%rsp)
	add	$(ISF64_SIZE)+8, (%rsp)
	je	L_copy_args_continue

	pop %rax
	jmp	L_dispatch

		
/*
 * GP/NP fault on IRET: CS or SS is in error.
 * Note that the user ss is originally 16-byte aligned, we'd popped the
 * stack back to contain just the rip/cs/rflags/rsp/ss before issuing the iret.
 * On taking the GP/NP fault on the iret instruction, the stack is 16-byte
 * aligned before pushed the interrupt frame. Hence, an 8-byte padding exists.
 *
 * on SP is
 *  (-  rax saved above, which is immediately popped)
 *   0	function
 *   8	trap number
 *  16	errcode
 *  24	rip
 *  32	cs
 *  40	rflags
 *  48	rsp		--> new trapfn
 *  56	ss		--> new trapno
 *  64	pad		--> new errcode
 *  72	user rip
 *  80	user cs
 *  88	user rflags
 *  96	user rsp
 * 104  user ss	(16-byte aligned)
 */
L_fault_iret:
	pop	%rax			/* recover saved %rax */
	mov	%rax, 24(%rsp)		/* save rax (we don`t need saved rip) */
	mov	0(%rsp), %rax		/* get trap func */
	mov	%rax, 48(%rsp)		/* put in user trap func */
	mov	8(%rsp), %rax		/* get trap number */
	mov	%rax, 56(%rsp)		/* put in user trap number */
	mov	16(%rsp), %rax		/* get error code */
	mov	%rax, 64(%rsp)		/* put in user errcode */
	mov	24(%rsp), %rax		/* restore rax */
	add	$48,%rsp		/* reset to new trapfn */
					/* now treat as fault from user */
	jmp	L_dispatch

/*
 * Fault restoring a segment register.  All of the saved state is still
 * on the stack untouched since we haven't yet moved the stack pointer.
 */
L_32bit_fault_set_seg:
	pop	%rax			/* recover %rax from stack */
	mov	0(%rsp), %rax		/* get trap function */
	mov	8(%rsp), %rcx		/* get trap number */
	mov	16(%rsp), %rdx		/* get error code */
	mov	48(%rsp), %rsp		/* reset stack to saved state */
	mov	%rax,ISC32_TRAPFN(%rsp)
	mov	%rcx,ISC32_TRAPNO(%rsp)
	mov	%rdx,ISC32_ERR(%rsp)
					/* now treat as fault from user */
					/* except that all the state is */
					/* already saved - we just have to */
					/* move the trapno and error into */
					/* the compatibility frame */
	jmp	L_32bit_dispatch_after_fault


/*
 * Fatal exception handlers:
 */
Entry(idt64_db_task_dbl_fault)
	PUSH_FUNCTION(HNDL_DOUBLE_FAULT)
	pushq	$(T_DOUBLE_FAULT)
	jmp	L_dispatch	

Entry(idt64_db_task_stk_fault)
	PUSH_FUNCTION(HNDL_DOUBLE_FAULT)
	pushq	$(T_STACK_FAULT)
	jmp	L_dispatch	

Entry(idt64_mc)
	push	$(0)			/* Error */
	PUSH_FUNCTION(HNDL_MACHINE_CHECK)
	pushq	$(T_MACHINE_CHECK)
	jmp	L_dispatch	


/* All 'exceptions' enter hndl_alltraps:
 *	rsp	-> x86_saved_state_t
 *	esi	   cs at trap
 * 
 * The rest of the state is set up as:	
 *	interrupts disabled
 *	direction flag cleared
 */
Entry(hndl_alltraps)
	mov	%esi, %eax
	testb	$3, %al
	jz	trap_from_kernel

	TIME_TRAP_UENTRY

	movq	%gs:CPU_ACTIVE_THREAD,%rdi
	movq	%rsp, ACT_PCB_ISS(%rdi)		/* stash the PCB stack */
	movq	%rsp, %rdi			/* also pass it as arg0 */
	movq	%gs:CPU_KERNEL_STACK,%rsp	/* switch to kernel stack */
	sti

	CCALL(user_trap)			/* call user trap routine */
	cli					/* hold off intrs - critical section */
	movq	%gs:CPU_ACTIVE_THREAD,%rsp
	movq	ACT_PCB_ISS(%rsp), %rsp 	/* switch back to PCB stack */
	xorl	%ecx, %ecx			/* don't check if we're in the PFZ */

#define CLI cli
#define STI sti

Entry(return_from_trap)
	movl	%gs:CPU_PENDING_AST,%eax
	testl	%eax,%eax
	je	EXT(return_to_user)	/* branch if no AST */

L_return_from_trap_with_ast:
	movq	%rsp, %r13
	movq	%gs:CPU_KERNEL_STACK, %rsp

	testl	%ecx, %ecx		/* see if we need to check for an EIP in the PFZ */
	je	2f			/* no, go handle the AST */
	cmpl	$(SS_64), SS_FLAVOR(%r13)	/* are we a 64-bit task? */
	je	1f
					/* no... 32-bit user mode */
	movl	R32_EIP(%r13), %edi
	CCALL(commpage_is_in_pfz32)
	testl	%eax, %eax
	je	2f			/* not in the PFZ... go service AST */
	movl	%eax, R32_EBX(%r13)	/* let the PFZ know we've pended an AST */
	movq	%r13, %rsp		/* switch back to PCB stack */
	jmp	EXT(return_to_user)
1:
	movq	R64_RIP(%r13), %rdi
	CCALL(commpage_is_in_pfz64)
	testl	%eax, %eax
	je	2f			/* not in the PFZ... go service AST */
	movl	%eax, R64_RBX(%r13)	/* let the PFZ know we've pended an AST */
	movq	%r13, %rsp		/* switch back to PCB stack */
	jmp	EXT(return_to_user)
2:	
	STI				/* interrupts always enabled on return to user mode */

	xor	%edi, %edi			/* zero %rdi */
	CCALL(i386_astintr)	/* take the AST */

	CLI
	movq	%r13, %rsp			/* switch back to PCB stack */

	xorl	%ecx, %ecx		/* don't check if we're in the PFZ */
	jmp	EXT(return_from_trap)	/* and check again (rare) */

/*
 * Trap from kernel mode.  No need to switch stacks.
 * Interrupts must be off here - we will set them to state at time of trap
 * as soon as it's safe for us to do so and not recurse doing preemption
 */
hndl_kerntrap:
trap_from_kernel:
	
	movq	%rsp, %rdi		/* saved state addr */
	pushq   R64_RIP(%rsp)           /* Simulate a CALL from fault point */
	pushq   %rbp                    /* Extend framepointer chain */
	movq    %rsp, %rbp
	CCALL(kernel_trap)		/* to kernel trap routine */
	popq    %rbp
	addq    $8, %rsp
	cli

	movl	%gs:CPU_PENDING_AST,%eax	/* get pending asts */
	testl	$(AST_URGENT),%eax		/* any urgent preemption? */
	je	ret_to_kernel			/* no, nothing to do */
	cmpl	$(T_PREEMPT),R64_TRAPNO(%rsp)
	je	ret_to_kernel			/* T_PREEMPT handled in kernel_trap() */
	testl	$(EFL_IF),R64_RFLAGS(%rsp)	/* interrupts disabled? */
	je	ret_to_kernel
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL	/* preemption disabled? */
	jne	ret_to_kernel
	movq	%gs:CPU_KERNEL_STACK,%rax
	movq	%rsp,%rcx
	xorq	%rax,%rcx
	andq	EXT(kernel_stack_mask)(%rip),%rcx
	testq	%rcx,%rcx		/* are we on the kernel stack? */
	jne	ret_to_kernel		/* no, skip it */

	CCALL1(i386_astintr, $1)	/* take the AST */
	jmp	ret_to_kernel


/*
 * All interrupts on all tasks enter here with:
 *	rsp->	 x86_saved_state_t
 *	esi	 cs at trap
 *
 *	interrupts disabled
 *	direction flag cleared
 */
Entry(hndl_allintrs)
	/*
	 * test whether already on interrupt stack
	 */
	movq	%gs:CPU_INT_STACK_TOP,%rcx
	cmpq	%rsp,%rcx
	jb	1f
	leaq	-INTSTACK_SIZE(%rcx),%rdx
	cmpq	%rsp,%rdx
	jb	int_from_intstack
1:	
	xchgq	%rcx,%rsp		/* switch to interrupt stack */

	mov	%cr0,%rax		/* get cr0 */
	orl	$(CR0_TS),%eax		/* or in TS bit */
	mov	%rax,%cr0		/* set cr0 */

	subq	$8, %rsp		/* for 16-byte stack alignment */
	pushq	%rcx			/* save pointer to old stack */
	movq	%rcx,%gs:CPU_INT_STATE	/* save intr state */
	
	TIME_INT_ENTRY			/* do timing */

	incl	%gs:CPU_PREEMPTION_LEVEL
	incl	%gs:CPU_INTERRUPT_LEVEL

	movq	%gs:CPU_INT_STATE, %rdi
	
	CCALL(interrupt)		/* call generic interrupt routine */

	cli				/* just in case we returned with intrs enabled */
	xor	%rax,%rax
	movq	%rax,%gs:CPU_INT_STATE	/* clear intr state pointer */

	.globl	EXT(return_to_iret)
LEXT(return_to_iret)			/* (label for kdb_kintr and hardclock) */

	decl	%gs:CPU_INTERRUPT_LEVEL
	decl	%gs:CPU_PREEMPTION_LEVEL

	TIME_INT_EXIT			/* do timing */

	movq	%gs:CPU_ACTIVE_THREAD,%rax
	movq	ACT_PCB(%rax),%rax	/* get act`s PCB */
	movq	PCB_FPS(%rax),%rax	/* get pcb's ims.ifps */
	cmpq	$0,%rax			/* Is there a context */
	je	1f			/* Branch if not */
	movl	FP_VALID(%rax),%eax	/* Load fp_valid */
	cmpl	$0,%eax			/* Check if valid */
	jne	1f			/* Branch if valid */
	clts				/* Clear TS */
	jmp	2f
1:
	mov	%cr0,%rax		/* get cr0 */
	orl	$(CR0_TS),%eax		/* or in TS bit */
	mov	%rax,%cr0		/* set cr0 */
2:
	popq	%rsp			/* switch back to old stack */

	/* Load interrupted code segment into %eax */
	movl	R32_CS(%rsp),%eax		/* assume 32-bit state */
	cmpl	$(SS_64),SS_FLAVOR(%rsp)/* 64-bit? */	
#if DEBUG_IDT64
	jne	4f
	movl	R64_CS(%rsp),%eax	/* 64-bit user mode */
	jmp	3f
4:
	cmpl    $(SS_32),SS_FLAVOR(%rsp)
	je	3f
	POSTCODE2(0x6431)
	CCALL1(panic_idt64, %rsp)
	hlt
#else
	jne	3f
	movl	R64_CS(%rsp),%eax	/* 64-bit user mode */
#endif
3:
	testb	$3,%al			/* user mode, */
	jnz	ast_from_interrupt_user	/* go handle potential ASTs */
	/*
	 * we only want to handle preemption requests if
	 * the interrupt fell in the kernel context
	 * and preemption isn't disabled
	 */
	movl	%gs:CPU_PENDING_AST,%eax	
	testl	$(AST_URGENT),%eax		/* any urgent requests? */
	je	ret_to_kernel			/* no, nothing to do */

	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL	/* preemption disabled? */
	jne	ret_to_kernel			/* yes, skip it */

	movq	%gs:CPU_KERNEL_STACK,%rax
	movq	%rsp,%rcx
	xorq	%rax,%rcx
	andq	EXT(kernel_stack_mask)(%rip),%rcx
	testq	%rcx,%rcx			/* are we on the kernel stack? */
	jne	ret_to_kernel			/* no, skip it */

	/*
	 * Take an AST from kernel space.  We don't need (and don't want)
	 * to do as much as the case where the interrupt came from user
	 * space.
	 */
	CCALL1(i386_astintr, $1)

	jmp	ret_to_kernel


/*
 * nested int - simple path, can't preempt etc on way out
 */
int_from_intstack:
	incl	%gs:CPU_PREEMPTION_LEVEL
	incl	%gs:CPU_INTERRUPT_LEVEL

	mov	%rsp, %rdi		/* x86_saved_state */
	CCALL(interrupt)

	decl	%gs:CPU_INTERRUPT_LEVEL
	decl	%gs:CPU_PREEMPTION_LEVEL

#if DEBUG_IDT64
	CCALL1(panic_idt64, %rsp)
	POSTCODE2(0x6411)
	hlt
#endif
	jmp	ret_to_kernel

/*
 *	Take an AST from an interrupted user
 */
ast_from_interrupt_user:
	movl	%gs:CPU_PENDING_AST,%eax
	testl	%eax,%eax		/* pending ASTs? */
	je	EXT(ret_to_user)	/* no, nothing to do */

	TIME_TRAP_UENTRY

	movl	$1, %ecx		/* check if we're in the PFZ */
	jmp	L_return_from_trap_with_ast	/* return */


/* Syscall dispatch routines! */

/*
 *
 * 32bit Tasks
 * System call entries via INTR_GATE or sysenter:
 *
 *	rsp	 -> x86_saved_state32_t
 *	interrupts disabled
 *	direction flag cleared
 */

Entry(hndl_sysenter)
	/*
	 * We can be here either for a mach syscall or a unix syscall,
	 * as indicated by the sign of the code:
	 */
	movl	R32_EAX(%rsp),%eax
	testl	%eax,%eax
	js	EXT(hndl_mach_scall)		/* < 0 => mach */
						/* > 0 => unix */
	
Entry(hndl_unix_scall)
/* If the caller (typically LibSystem) has recorded the cumulative size of
 * the arguments in EAX, copy them over from the user stack directly.
 * We recover from exceptions inline--if the copy loop doesn't complete
 * due to an exception, we fall back to copyin from compatibility mode.
 * We can potentially extend this mechanism to mach traps as well (DRK).
 */
	testl	$(I386_SYSCALL_ARG_BYTES_MASK), %eax
	jz	L_copy_args_continue
	movl	%eax, %ecx
	mov	%gs:CPU_UBER_ARG_STORE_VALID, %rbx
	shrl	$(I386_SYSCALL_ARG_DWORDS_SHIFT), %ecx
	andl	$(I386_SYSCALL_ARG_DWORDS_MASK), %ecx
	mov	%gs:CPU_UBER_ARG_STORE, %rdi
	mov	ISC32_RSP(%rsp), %rsi
	add	$4, %rsi
	movl	$0, (%rbx)

EXT(idt64_unix_scall_copy_args):
	rep movsl
	movl	$1, (%rbx)
L_copy_args_continue:

        TIME_TRAP_UENTRY

	movq	%gs:CPU_KERNEL_STACK,%rdi
	xchgq	%rdi,%rsp			/* switch to kernel stack */
	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movq	%rdi,ACT_PCB_ISS(%rcx)
	movq	ACT_TASK(%rcx),%rbx		/* point to current task  */
	addl	$1,TASK_SYSCALLS_UNIX(%rbx)	/* increment call count   */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	sti

	CCALL(unix_syscall)
	/*
	 * always returns through thread_exception_return
	 */


Entry(hndl_mach_scall)
	TIME_TRAP_UENTRY

	movq	%gs:CPU_KERNEL_STACK,%rdi
	xchgq	%rdi,%rsp			/* switch to kernel stack */
	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movq	%rdi,ACT_PCB_ISS(%rcx)
	movq	ACT_TASK(%rcx),%rbx		/* point to current task  */
	addl	$1,TASK_SYSCALLS_MACH(%rbx)	/* increment call count   */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	sti

	CCALL(mach_call_munger)
	/*
	 * always returns through thread_exception_return
	 */


Entry(hndl_mdep_scall)
	TIME_TRAP_UENTRY

	movq	%gs:CPU_KERNEL_STACK,%rdi
	xchgq	%rdi,%rsp			/* switch to kernel stack */

	/* Check for active vtimers in the current task */
	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movq	ACT_TASK(%rcx),%rbx		/* point to current task  */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	sti

	CCALL(machdep_syscall)
	/*
	 * always returns through thread_exception_return
	 */


Entry(hndl_diag_scall)
	TIME_TRAP_UENTRY

	movq	%gs:CPU_KERNEL_STACK,%rdi
	xchgq	%rdi,%rsp			/* switch to kernel stack */
	
	/* Check for active vtimers in the current task */
	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movq	ACT_TASK(%rcx),%rbx		/* point to current task  */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	pushq	%rdi			/* push pcb stack so we can pop it later */

	CCALL(diagCall)		// Call diagnostics
	cli				// Disable interruptions just in case they were enabled
	popq	%rsp			// Get back the original stack
	
	cmpl	$0,%eax			// What kind of return is this?
	jne	EXT(return_to_user)	// Normal return, do not check asts...
				
	CCALL3(i386_exception, $EXC_SYSCALL, $0x6000, $1)
		// pass what would be the diag syscall
		// error return - cause an exception
	/* no return */
	


/*
 * 64bit Tasks
 * System call entries via syscall only:
 *
 *	rsp	 -> x86_saved_state64_t
 *	interrupts disabled
 *	direction flag cleared
 */

Entry(hndl_syscall)
	TIME_TRAP_UENTRY

	movq	%gs:CPU_KERNEL_STACK,%rdi
	xchgq	%rdi,%rsp			/* switch to kernel stack */
	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movq	%rdi, ACT_PCB_ISS(%rcx)
	movq	ACT_TASK(%rcx),%rbx		/* point to current task  */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	/*
	 * We can be here either for a mach, unix machdep or diag syscall,
	 * as indicated by the syscall class:
	 */
	movl	R64_RAX(%rdi), %eax		/* syscall number/class */
	movl	%eax, %edx
	andl	$(SYSCALL_CLASS_MASK), %edx	/* syscall class */
	cmpl	$(SYSCALL_CLASS_MACH<<SYSCALL_CLASS_SHIFT), %edx
	je	EXT(hndl_mach_scall64)
	cmpl	$(SYSCALL_CLASS_UNIX<<SYSCALL_CLASS_SHIFT), %edx
	je	EXT(hndl_unix_scall64)
	cmpl	$(SYSCALL_CLASS_MDEP<<SYSCALL_CLASS_SHIFT), %edx
	je	EXT(hndl_mdep_scall64)
	cmpl	$(SYSCALL_CLASS_DIAG<<SYSCALL_CLASS_SHIFT), %edx
	je	EXT(hndl_diag_scall64)

	/* Syscall class unknown */
	CCALL3(i386_exception, $(EXC_SYSCALL), %rax, $1)
	/* no return */


Entry(hndl_unix_scall64)
	addl	$1,TASK_SYSCALLS_UNIX(%rbx)	/* increment call count   */
	sti

	CCALL(unix_syscall64)
	/*
	 * always returns through thread_exception_return
	 */


Entry(hndl_mach_scall64)
	addl	$1,TASK_SYSCALLS_MACH(%rbx)	/* increment call count   */
	sti

	CCALL(mach_call_munger64)
	/*
	 * always returns through thread_exception_return
	 */



Entry(hndl_mdep_scall64)
	sti

	CCALL(machdep_syscall64)
	/*
	 * always returns through thread_exception_return
	 */


Entry(hndl_diag_scall64)
	pushq	%rdi				// Push the previous stack
	CCALL(diagCall64)			// Call diagnostics
	cli					// Disable interruptions just in case
	popq	%rsp				// Get back the original stack

	cmpl	$0,%eax				// What kind of return is this?
	jne	EXT(return_to_user)		// Normal return, do not check asts...
				
	CCALL3(i386_exception, $EXC_SYSCALL, $0x6000, $1)
	/* no return */

Entry(hndl_machine_check)
	CCALL1(panic_machine_check64, %rsp)
	hlt

Entry(hndl_double_fault)
	CCALL1(panic_double_fault64, %rsp)
	hlt
