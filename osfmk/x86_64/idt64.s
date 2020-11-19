/*
 * Copyright (c) 2010-2020 Apple Inc. All rights reserved.
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
#include <debug.h>
#include "dwarf_unwind.h"
#include <i386/eflags.h>
#include <i386/rtclock_asm.h>
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
 * Indices of handlers for each exception type.
 */
#define	HNDL_ALLINTRS		0
#define	HNDL_ALLTRAPS		1
#define	HNDL_SYSENTER		2
#define	HNDL_SYSCALL		3
#define	HNDL_UNIX_SCALL		4
#define	HNDL_MACH_SCALL		5
#define	HNDL_MDEP_SCALL		6
#define	HNDL_DOUBLE_FAULT	7
#define	HNDL_MACHINE_CHECK	8

	
/* Begin double-mapped descriptor section */
	
.section	__HIB, __desc
.globl EXT(idt64_hndl_table0)
EXT(idt64_hndl_table0):
/* 0x00 */	.quad EXT(ks_dispatch)
/* 0x08 */	.quad EXT(ks_64bit_return)
/* 0x10 */	.quad 0 /* Populated with CPU shadow displacement*/
/* 0x18 */	.quad EXT(ks_32bit_return)
#define	TBL0_OFF_DISP_USER_WITH_POPRAX	0x20
/* 0x20 */	.quad EXT(ks_dispatch_user_with_pop_rax)
#define	TBL0_OFF_DISP_KERN_WITH_POPRAX	0x28
/* 0x28 */	.quad EXT(ks_dispatch_kernel_with_pop_rax)
#define	TBL0_OFF_PTR_KERNEL_STACK_MASK	0x30
/* 0x30 */	.quad 0 /* &kernel_stack_mask */

EXT(idt64_hndl_table1):
	.quad	EXT(hndl_allintrs)
	.quad	EXT(hndl_alltraps)
	.quad	EXT(hndl_sysenter)
	.quad	EXT(hndl_syscall)
	.quad	EXT(hndl_unix_scall)
	.quad	EXT(hndl_mach_scall)
	.quad	EXT(hndl_mdep_scall)
	.quad	EXT(hndl_double_fault)
	.quad	EXT(hndl_machine_check)
.text


/* The wrapper for all non-special traps/interrupts */
/* Everything up to PUSH_FUNCTION is just to output 
 * the interrupt number out to the postcode display
 */
#if DEBUG_IDT64
#define IDT_ENTRY_WRAPPER(n, f)			 \
	push	%rax				;\
	POSTCODE2(0x6400+n)			;\
	pop	%rax				;\
	pushq	$(f)				;\
	pushq	$(n)				;\
	jmp L_dispatch
#else
#define IDT_ENTRY_WRAPPER(n, f)			 \
	pushq	$(f)				;\
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
#define TRAP_IST1(n, f)
#define TRAP_IST2(n, f)
#define USER_TRAP_SPC(n, f)

/* Begin double-mapped text section */
.section __HIB, __text
/* Generate all the stubs */
#include "idt_table.h"

Entry(idt64_page_fault)
	pushq	$(HNDL_ALLTRAPS)
#if !(DEVELOPMENT || DEBUG)
	pushq	$(T_PAGE_FAULT)
	jmp	L_dispatch
#else
	pushq	$(T_PAGE_FAULT)

	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	testb	$3, 8+8+8+ISF64_CS(%rsp)	/* Coming from userspace? */
	jz	L_pfkern		/* No? (relatively uncommon), goto L_pfkern */

	/*
	 * We faulted from the user; if the fault address is at the user's %rip,
	 * abort trying to save the cacheline since that adds another page fault's
	 * overhead when we recover, below.
	 */
	movq	8+8+8+ISF64_RIP(%rsp), %rbx
	movq	%cr2, %rcx
	cmpq	%rbx, %rcx

	/* note that the next 3 instructions do not affect RFLAGS */
	swapgs
	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	mov	16(%rax), %rax	/* Offset of per-CPU shadow */

	jne	L_dispatch_from_user_with_rbx_rcx_pushes
	jmp	abort_rip_cacheline_read

L_pfkern:
	/*
	 * Kernel page fault
	 * If the fault occurred on while reading from the user's code cache line, abort the cache line read;
	 * otherwise, treat this as a regular kernel fault
	 */
	movq	8+8+8+ISF64_RIP(%rsp), %rbx
	leaq	rip_cacheline_read(%rip), %rcx
	cmpq	%rcx, %rbx
	jb	regular_kernel_page_fault
	leaq	rip_cacheline_read_end(%rip), %rcx
	cmpq	%rcx, %rbx
	jbe	L_pf_on_clread	/* Did we hit a #PF within the cacheline read? */

regular_kernel_page_fault:
	/* No, regular kernel #PF */
	popq	%rcx
	popq	%rbx
	jmp	L_dispatch_from_kernel_no_push_rax

L_pf_on_clread:
	/*
	 * We faulted while trying to read user instruction memory at the parent fault's %rip; abort that action by
	 * changing the return address on the stack, restoring cr2 to its previous value, peeling off the pushes we
	 * added on entry to the page fault handler, then performing an iretq
	 */
	popq	%rcx
	movq	%rcx, %cr2
	popq	%rbx
	leaq	abort_rip_cacheline_read(%rip), %rax
	movq	%rax, 8+ISF64_RIP(%rsp)
	popq	%rax
	addq	$24, %rsp	/* pop the 2 pushes + the error code */
	iretq			/* Resume previous trap/fault processing */
#endif /* !(DEVELOPMENT || DEBUG) */

/*
 * #DB handler, which runs on IST1, will treat as spurious any #DB received while executing in the
 * kernel while not on the kernel's gsbase.
 */
Entry(idt64_debug)
	/* Synthesize common interrupt stack frame */
	push	$0			/* error code */
	pushq	$(HNDL_ALLTRAPS)
	pushq	$(T_DEBUG)
	/* Spill prior to RDMSR */
	push	%rax
	push	%rcx
	push	%rdx
	mov	$(MSR_IA32_GS_BASE), %ecx
	rdmsr					/* Check contents of GSBASE MSR */
	test	$0x80000000, %edx		/* MSB set? Already swapped to kernel's */
	jnz	1f

	/*
	 * If we're not already swapped to the kernel's gsbase AND this #DB originated from kernel space,
	 * it must have happened within the very small window on entry or exit before or after (respectively)
	 * swapgs occurred.  In those cases, consider the #DB spurious and immediately return.
	 */
	testb	$3, 8+8+8+ISF64_CS(%rsp)
	jnz	2f
	pop	%rdx
	pop	%rcx
	pop	%rax
	addq	$0x18, %rsp	/* Remove synthesized interrupt stack frame */
	jmp	EXT(ret64_iret)
2:
	swapgs					/* direct from user */
1:
	pop	%rdx

	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	mov	16(%rax), %rax /* Offset of per-CPU shadow */

	mov	%gs:CPU_SHADOWTASK_CR3(%rax), %rax
	mov	%rax, %cr3

	pop	%rcx

	/* Note that %rax will be popped from the stack in ks_dispatch, below */

	leaq    EXT(idt64_hndl_table0)(%rip), %rax
	jmp	*(%rax)

/*
 * Legacy interrupt gate System call handlers.
 * These are entered via a syscall interrupt. The system call number in %rax
 * is saved to the error code slot in the stack frame. We then branch to the
 * common state saving code.
 */

#ifndef UNIX_INT
#error NO UNIX INT!!!
#endif
Entry(idt64_unix_scall)
	pushq	%rax			/* save system call number */
	pushq	$(HNDL_UNIX_SCALL)
	pushq	$(UNIX_INT)
	jmp	L_u64bit_entry_check
	
Entry(idt64_mach_scall)
	pushq	%rax			/* save system call number */
	pushq	$(HNDL_MACH_SCALL)
	pushq	$(MACH_INT)
	jmp	L_u64bit_entry_check
	
Entry(idt64_mdep_scall)
	pushq	%rax			/* save system call number */
	pushq	$(HNDL_MDEP_SCALL)
	pushq	$(MACHDEP_INT)
	jmp	L_u64bit_entry_check

/*
 * For GP/NP/SS faults, we use the IST1 stack.
 * For faults from user-space, we have to copy the machine state to the
 * PCB stack and then dispatch as normal.
 * For faults in kernel-space, we need to scrub for kernel exit faults and
 * treat these as user-space faults. But for all other kernel-space faults
 * we continue to run on the IST1 stack as we dispatch to handle the fault
 * as fatal.
 */
Entry(idt64_segnp)
	pushq	$(HNDL_ALLTRAPS)
	pushq	$(T_SEGMENT_NOT_PRESENT)
	jmp	L_check_for_kern_flt

Entry(idt64_gen_prot)
	pushq	$(HNDL_ALLTRAPS)
	pushq	$(T_GENERAL_PROTECTION)
	jmp	L_check_for_kern_flt

Entry(idt64_stack_fault)
	pushq	$(HNDL_ALLTRAPS)
	pushq	$(T_STACK_FAULT)
	jmp	L_check_for_kern_flt

L_check_for_kern_flt:
	/*
	 * If we took a #GP or #SS from the kernel, check if we took them
	 * from either ret32_iret or ret64_iret.  If we did, we need to
	 * jump into L_dispatch at the swapgs so that the code in L_dispatch
	 * can proceed with the correct GSbase.
	 */
	pushq	%rax
	testb	$3, 8+ISF64_CS(%rsp)
	jnz	L_dispatch_from_user_no_push_rax		/* Fault from user, go straight to dispatch */

	/* Check if the fault occurred in the 32-bit segment restoration window (which executes with user gsb) */
	leaq	L_32bit_seg_restore_begin(%rip), %rax
	cmpq	%rax, 8+ISF64_RIP(%rsp)
	jb	L_not_32bit_segrestores
	leaq	L_32bit_seg_restore_done(%rip), %rax
	cmpq	%rax, 8+ISF64_RIP(%rsp)
	jae	L_not_32bit_segrestores
	jmp	1f
L_not_32bit_segrestores:
	leaq	EXT(ret32_iret)(%rip), %rax
	cmpq	%rax, 8+ISF64_RIP(%rsp)
	je	1f
	leaq	EXT(ret64_iret)(%rip), %rax
	cmpq	%rax, 8+ISF64_RIP(%rsp)
	je	1f
	jmp	L_dispatch_from_kernel_no_push_rax
	/*
	 * We hit the fault on iretq, so check the original return %cs.  If
	 * it's a user %cs, fixup the stack and then jump to dispatch..
	 *
	 * With this type of fault, the stack is layed-out as follows:
	 *
	 * 
	 * orig %ss      saved_rsp+32
	 * orig %rsp     saved_rsp+24
	 * orig %rflags  saved_rsp+16
	 * orig %cs      saved_rsp+8
	 * orig %rip     saved_rsp
         * ^^^^^^^^^ (maybe on another stack, since we switched to IST1)
	 * %ss           +64            -8
	 * saved_rsp     +56           -16
	 * %rflags       +48           -24
	 * %cs           +40           -32
	 * %rip          +32           -40
	 * error code    +24           -48
	 * hander        +16           -56
	 * trap number   +8            -64
	 * <saved %rax>  <== %rsp      -72
	 */
1:
	pushq	%rbx
	movq	16+ISF64_RSP(%rsp), %rbx
	movq	ISF64_CS-24(%rbx), %rax
	testb	$3, %al					/* If the original return destination was to user */
	jnz	2f
	popq	%rbx
	jmp	L_dispatch_from_kernel_no_push_rax	/* Fault occurred when trying to return to kernel */
2:
	/*
	 * Fix the stack so the original trap frame is current, then jump to dispatch
	 */

	movq	%rax, 16+ISF64_CS(%rsp)

	movq	ISF64_RSP-24(%rbx), %rax
	movq	%rax, 16+ISF64_RSP(%rsp)

	movq	ISF64_RIP-24(%rbx), %rax
	movq	%rax, 16+ISF64_RIP(%rsp)

	movq	ISF64_SS-24(%rbx), %rax
	movq	%rax, 16+ISF64_SS(%rsp)

	movq	ISF64_RFLAGS-24(%rbx), %rax
	movq	%rax, 16+ISF64_RFLAGS(%rsp)

	popq	%rbx
	jmp	L_dispatch_from_user_no_push_rax


/*
 * Fatal exception handlers:
 */
Entry(idt64_db_task_dbl_fault)
	pushq	$(HNDL_DOUBLE_FAULT)
	pushq	$(T_DOUBLE_FAULT)
	jmp	L_dispatch

Entry(idt64_db_task_stk_fault)
	pushq	$(HNDL_DOUBLE_FAULT)
	pushq	$(T_STACK_FAULT)
	jmp	L_dispatch

Entry(idt64_mc)
	push	$(0)			/* Error */
	pushq	$(HNDL_MACHINE_CHECK)
	pushq	$(T_MACHINE_CHECK)
	jmp	L_dispatch

/*
 * NMI
 * This may or may not be fatal but extreme care is required
 * because it may fall when control was already in another trampoline.
 *
 * We get here on IST2 stack which is used exclusively for NMIs.
 * Machine checks, doublefaults and similar use IST1
 */
Entry(idt64_nmi)
	push	%rax
	push	%rcx
	push	%rdx
	testb	$3, ISF64_CS(%rsp)
	jz	1f

	/* From user-space: copy interrupt state to user PCB */
	swapgs

	leaq    EXT(idt64_hndl_table0)(%rip), %rax
	mov     16(%rax), %rax /* Offset of per-CPU shadow */
	mov     %gs:CPU_SHADOWTASK_CR3(%rax), %rax
	mov     %rax, %cr3			/* note that SMAP is enabled in L_common_dispatch (on Broadwell+) */

	mov	%gs:CPU_UBER_ISF, %rcx		/* PCB stack addr */
	add	$(ISF64_SIZE), %rcx		/* adjust to base of ISF */

	leaq    TBL0_OFF_DISP_USER_WITH_POPRAX+EXT(idt64_hndl_table0)(%rip), %rax		/* ks_dispatch_user_with_pop_rax */
	jmp	4f						/* Copy state to PCB */

1:
	/*
	 * From kernel-space:
	 * Determine whether the kernel or user GS is set.
	 * Sets the high 32 bits of the return CS to 1 to ensure that we'll swapgs back correctly at IRET.
	 */
	mov	$(MSR_IA32_GS_BASE), %ecx
	rdmsr					/* read kernel gsbase */
	test	$0x80000000, %edx		/* test MSB of address */
	jnz	2f
	swapgs					/* so swap */
	movl	$1, ISF64_CS+4(%rsp)		/* and set flag in CS slot */
2:

	leaq    EXT(idt64_hndl_table0)(%rip), %rax
	mov     16(%rax), %rax /* Offset of per-CPU shadow */
	mov	%cr3, %rdx
	mov     %gs:CPU_SHADOWTASK_CR3(%rax), %rax
	mov     %rax, %cr3 /* Unconditionally switch to primary kernel pagetables */

	/*
	 * Determine whether we're on the kernel or interrupt stack
	 * when the NMI hit.
	 */
	mov	ISF64_RSP(%rsp), %rcx
	mov	%gs:CPU_KERNEL_STACK, %rax
	xor	%rcx, %rax
	movq	TBL0_OFF_PTR_KERNEL_STACK_MASK+EXT(idt64_hndl_table0)(%rip), %rdx
	mov	(%rdx), %rdx		/* Load kernel_stack_mask */
	and	%rdx, %rax
	test	%rax, %rax		/* are we on the kernel stack? */
	jz	3f			/* yes */

	mov	%gs:CPU_INT_STACK_TOP, %rax
	cmp	%rcx, %rax		/* are we on the interrupt stack? */
	jb	5f			/* no */
	leaq	-INTSTACK_SIZE(%rax), %rax
	cmp	%rcx, %rax
	jb	3f			/* yes */
5:
	mov    %gs:CPU_KERNEL_STACK, %rcx
3:
	/* 16-byte-align kernel/interrupt stack for state push */
	and	$0xFFFFFFFFFFFFFFF0, %rcx

	leaq    TBL0_OFF_DISP_KERN_WITH_POPRAX+EXT(idt64_hndl_table0)(%rip), %rax		/* ks_dispatch_kernel_with_pop_rax */
4:
	/*
	 * Copy state from NMI stack (RSP) to the save area (RCX) which is
	 * the PCB for user or kernel/interrupt stack from kernel.
	 * ISF64_ERR(RSP)    saved RAX
	 * ISF64_TRAPFN(RSP) saved RCX
	 * ISF64_TRAPNO(RSP) saved RDX
	 */
	xchg	%rsp, %rcx			/* set for pushes */
	push	ISF64_SS(%rcx)
	push	ISF64_RSP(%rcx)
	push	ISF64_RFLAGS(%rcx)
	push	ISF64_CS(%rcx)
	push	ISF64_RIP(%rcx)
	/* Synthesize common interrupt stack frame */
	push	$(0)				/* error code 0 */
	push	$(HNDL_ALLINTRS)		/* trapfn allintrs */
	push	$(T_NMI)			/* trapno T_NMI */
	push	ISF64_ERR(%rcx)			/* saved %rax is popped in ks_dispatch_{kernel|user}_with_pop_rax */
	mov	ISF64_TRAPNO(%rcx), %rdx
	mov	ISF64_TRAPFN(%rcx), %rcx

	jmp	*(%rax)		/* ks_dispatch_{kernel|user}_with_pop_rax */

Entry(idt64_double_fault)
	pushq	$(HNDL_DOUBLE_FAULT)
	pushq	$(T_DOUBLE_FAULT)
	jmp	L_dispatch

Entry(hi64_syscall)
Entry(idt64_syscall)
	swapgs
     /* Use RAX as a temporary by shifting its contents into R11[32:63]
      * The systemcall number is defined to be a 32-bit quantity, as is
      * RFLAGS.
      */
	shlq	$32, %rax
	or 	%rax, %r11
.globl EXT(dblsyscall_patch_point)
EXT(dblsyscall_patch_point):
//	movabsq	$0x12345678ABCDEFFFULL, %rax
     /* Generate offset to the double-mapped per-CPU data shadow
      * into RAX
      */
	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	mov	16(%rax), %rax
	mov     %rsp, %gs:CPU_UBER_TMP(%rax)  /* save user stack */
	mov     %gs:CPU_ESTACK(%rax), %rsp  /* switch stack to per-cpu estack */
	sub	$(ISF64_SIZE), %rsp

	/*
	 * Synthesize an ISF frame on the exception stack
	 */
	movl	$(USER_DS), ISF64_SS(%rsp)
	mov	%rcx, ISF64_RIP(%rsp)		/* rip */

	mov	%gs:CPU_UBER_TMP(%rax), %rcx
	mov	%rcx, ISF64_RSP(%rsp)		/* user stack --changed */

	mov	%r11, %rax
	shrq	$32, %rax		/* Restore RAX */
	mov	%r11d, %r11d		/* Clear r11[32:63] */

	mov	%r11, ISF64_RFLAGS(%rsp)	/* rflags */
	movl	$(SYSCALL_CS), ISF64_CS(%rsp)	/* cs - a pseudo-segment */
	mov	%rax, ISF64_ERR(%rsp)		/* err/rax - syscall code */
	movq	$(HNDL_SYSCALL), ISF64_TRAPFN(%rsp)
	movq	$(T_SYSCALL), ISF64_TRAPNO(%rsp)	/* trapno */
	swapgs
	jmp	L_dispatch			/* this can only be 64-bit */

Entry(hi64_sysenter)
Entry(idt64_sysenter)
	/* Synthesize an interrupt stack frame onto the
	 * exception stack.
	 */
	push	$(USER_DS)		/* ss */
	push	%rcx			/* uesp */
	pushf				/* flags */
	/*
	 * Clear, among others, the Nested Task (NT) flags bit;
	 * this is zeroed by INT, but not by SYSENTER.
	 */
	push	$0
	popf
	push	$(SYSENTER_CS)		/* cs */ 
L_sysenter_continue:
	push	%rdx			/* eip */
	push	%rax			/* err/eax - syscall code */
	pushq	$(HNDL_SYSENTER)
	pushq	$(T_SYSENTER)
	orl	$(EFL_IF), ISF64_RFLAGS(%rsp)
	jmp	L_u64bit_entry_check

#if DEVELOPMENT || DEBUG
do_cacheline_stash:
	/*
	 * Copy the cache line that includes the user's EIP/RIP into the shadow cpu structure
	 * for later extraction/sanity-checking in user_trap().
	 */

	pushq	%rbx
	pushq	%rcx
L_dispatch_from_user_with_rbx_rcx_pushes:
	movq	8+8+8+ISF64_RIP(%rsp), %rbx
	andq	$-64, %rbx	/* Round address to cacheline boundary */
	pushf
	/*
	 * disable SMAP, if it's enabled (note that CLAC is present in BDW and later only, so we're
	 * using generic instructions here without checking whether the CPU supports SMAP first)
	 */
	orq	$(1 << 18), (%rsp)
	popf
	/*
	 * Note that we only check for a faulting read on the first read, since if the first read
	 * succeeds, the rest of the cache line should also be readible since we are running with
	 * interrupts disabled here and a TLB invalidation cannot sneak in and pull the rug out.
	 */
	movq	%cr2, %rcx	/* stash the original %cr2 in case the first cacheline read triggers a #PF */
				/* This value of %cr2 is restored in the page fault handler if it detects */
				/* that the fault occurrent on the next instruction, so the original #PF can */
				/* continue to be handled without issue. */
rip_cacheline_read:
	mov	(%rbx), %rcx
	/* Note that CPU_RTIMES in the shadow cpu struct was just a convenient place to stash the cacheline */
	mov	%rcx, %gs:CPU_RTIMES(%rax)
	movq    %cr2, %rcx
	mov	8(%rbx), %rcx
	mov	%rcx, %gs:8+CPU_RTIMES(%rax)
	movq    %cr2, %rcx
	mov	16(%rbx), %rcx
	mov	%rcx, %gs:16+CPU_RTIMES(%rax)
	movq    %cr2, %rcx
	mov	24(%rbx), %rcx
	mov	%rcx, %gs:24+CPU_RTIMES(%rax)
	movq    %cr2, %rcx
	mov	32(%rbx), %rcx
	mov	%rcx, %gs:32+CPU_RTIMES(%rax)
	movq    %cr2, %rcx
	mov	40(%rbx), %rcx
	mov	%rcx, %gs:40+CPU_RTIMES(%rax)
	movq    %cr2, %rcx
	mov	48(%rbx), %rcx
	mov	%rcx, %gs:48+CPU_RTIMES(%rax)
	movq    %cr2, %rcx
rip_cacheline_read_end:
	mov	56(%rbx), %rcx
	mov	%rcx, %gs:56+CPU_RTIMES(%rax)

	pushf
	andq	$~(1 << 18), (%rsp) 	/* reenable SMAP */
	popf

	jmp	cacheline_read_cleanup_stack

abort_rip_cacheline_read:
	pushf
	andq	$~(1 << 18), (%rsp) 	/* reenable SMAP */
	popf
abort_rip_cacheline_read_no_smap_reenable:
	movl	$0xdeadc0de, %ecx			/* Write a sentinel so higher-level code knows this was aborted */
	shlq	$32, %rcx
	movl	$0xbeefcafe, %ebx
	orq	%rbx, %rcx
	movq	%rcx, %gs:CPU_RTIMES(%rax)
	movq	%rcx, %gs:8+CPU_RTIMES(%rax)

cacheline_read_cleanup_stack:
	popq	%rcx
	popq	%rbx
	jmp	L_dispatch_kgsb
#endif /* if DEVELOPMENT || DEBUG */

/*
 * Common dispatch point.
 * Determine what mode has been interrupted and save state accordingly.
 * Here with:
 *	rsp	from user-space:   interrupt state in PCB, or
 *		from kernel-space: interrupt state in kernel or interrupt stack
 *	GSBASE	from user-space:   pthread area, or
 *		from kernel-space: cpu_data
 */

L_dispatch:
	pushq	%rax
	testb	$3, 8+ISF64_CS(%rsp)
	jz	1f
L_dispatch_from_user_no_push_rax:
	swapgs
	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	mov	16(%rax), %rax	/* Offset of per-CPU shadow */

#if DEVELOPMENT || DEBUG
	/* Stash the cacheline for #UD, #PF, and #GP */
	cmpl	$(T_INVALID_OPCODE), 8+ISF64_TRAPNO(%rsp)
	je	do_cacheline_stash
	cmpl	$(T_PAGE_FAULT), 8+ISF64_TRAPNO(%rsp)
	je	do_cacheline_stash
	cmpl	$(T_GENERAL_PROTECTION), 8+ISF64_TRAPNO(%rsp)
	je	do_cacheline_stash
#endif

L_dispatch_kgsb:
	mov	%gs:CPU_SHADOWTASK_CR3(%rax), %rax
	mov	%rax, %cr3
#if	DEBUG
	mov	%rax, %gs:CPU_ENTRY_CR3
#endif
L_dispatch_from_kernel_no_push_rax:
1:
	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	/* The text/data relationship here must be preserved in the doublemap, and the contents must be remapped */
	/* Indirect branch to non-doublemapped trampolines */
	jmp *(%rax)
/* User return: register restoration and address space switch sequence */
Entry(ks_64bit_return)

	mov	R64_R14(%r15), %r14
	mov	R64_R13(%r15), %r13
	mov	R64_R12(%r15), %r12
	mov	R64_R11(%r15), %r11
	mov	R64_R10(%r15), %r10
	mov	R64_R9(%r15),  %r9
	mov	R64_R8(%r15),  %r8
	mov	R64_RSI(%r15), %rsi
	mov	R64_RDI(%r15), %rdi
	mov	R64_RBP(%r15), %rbp
	mov	R64_RDX(%r15), %rdx
	mov	R64_RCX(%r15), %rcx
	mov	R64_RBX(%r15), %rbx
	mov	R64_RAX(%r15), %rax
	/* Switch to per-CPU exception stack */
	mov	%gs:CPU_ESTACK, %rsp

	/* Synthesize interrupt stack frame from PCB savearea to exception stack */
	push	R64_SS(%r15)
	push	R64_RSP(%r15)
	push	R64_RFLAGS(%r15)
	push	R64_CS(%r15)
	push	R64_RIP(%r15)

	cmpq	$(KERNEL64_CS), 8(%rsp)
	jne	1f			/* Returning to user (%r15 will be restored after the segment checks) */
	mov	R64_R15(%r15), %r15
	jmp	L_64b_kernel_return	/* Returning to kernel */

1:
	push	%rax				/* [A] */
	movl	%gs:CPU_NEED_SEGCHK, %eax
	push	%rax				/* [B] */

	/* Returning to user */
	cmpl	$0, %gs:CPU_CURTASK_HAS_LDT	/* If the current task has an LDT, check and restore segment regs */
	jne	L_64b_segops_island

	/*
	 * Restore %r15, since we're now done accessing saved state
	 * and (%r15) won't be accessible after the %cr3 load anyway.
	 * Note that %r15 is restored below for the segment-restore
	 * case, just after we no longer need to access register state
	 * relative to %r15.
	 */
	mov	R64_R15(%r15), %r15

	/*
	 * Note that this %cr3 sequence is duplicated here to save
	 * [at least] a load and comparison that would be required if
	 * this block were shared.
	 */
	/* Discover user cr3/ASID */
	mov	%gs:CPU_UCR3, %rax
#if	DEBUG
	mov	%rax, %gs:CPU_EXIT_CR3
#endif
	mov	%rax, %cr3
	/* Continue execution on the shared/doublemapped trampoline */
	swapgs

L_chk_sysret:
	pop	%rax	/* Matched to [B], above (segchk required) */

	/*
	 * At this point, the stack contains:
	 *
	 * +--------------+
	 * |  Return SS   | +40
	 * |  Return RSP  | +32
	 * |  Return RFL  | +24
	 * |  Return CS   | +16
	 * |  Return RIP  | +8
	 * |  Saved RAX   |  <-- rsp
	 * +--------------+
	 */
	cmpl	$(SYSCALL_CS), 16(%rsp) /* test for exit via SYSRET */
	je      L_sysret

	cmpl	$1, %eax
	je	L_verw_island_2

	pop	%rax		/* Matched to [A], above */

L_64b_kernel_return:
.globl EXT(ret64_iret)
EXT(ret64_iret):
        iretq			/* return from interrupt */


L_sysret:
	cmpl	$1, %eax
	je	L_verw_island_3

	pop	%rax		/* Matched to [A], above */
	/*
	 * Here to restore rcx/r11/rsp and perform the sysret back to user-space.
	 * 	rcx	user rip
	 *	r11	user rflags
	 *	rsp	user stack pointer
	 */
	pop	%rcx
	add	$8, %rsp
	pop	%r11
	pop	%rsp
	sysretq			/* return from system call */


L_verw_island_2:

	pop	%rax		/* Matched to [A], above */
	verw	40(%rsp)	/* verw operates on the %ss value already on the stack */
	jmp	EXT(ret64_iret)


L_verw_island_3:

	pop	%rax		/* Matched to [A], above */

	/*
	 * Here to restore rcx/r11/rsp and perform the sysret back to user-space.
	 * 	rcx	user rip
	 *	r11	user rflags
	 *	rsp	user stack pointer
	 */
	pop	%rcx
	add	$8, %rsp
	pop	%r11
	verw	8(%rsp)		/* verw operates on the %ss value already on the stack */
	pop	%rsp
	sysretq			/* return from system call */


L_64b_segops_island:

	/* Validate CS/DS/ES/FS/GS segment selectors with the Load Access Rights instruction prior to restoration */
	/* Exempt "known good" statically configured selectors, e.g. USER64_CS and 0 */
	cmpl	$(USER64_CS), R64_CS(%r15)
	jz 	11f
	larw	R64_CS(%r15), %ax
	jnz	L_64_reset_cs
	/* Ensure that the segment referenced by CS in the saved state is a code segment (bit 11 == 1) */
	testw	$0x800, %ax
	jz	L_64_reset_cs		/* Update stored %cs with known-good selector if ZF == 1 */
	jmp	11f
L_64_reset_cs:
	movl	$(USER64_CS), R64_CS(%r15)
11:
	cmpl	$0, R64_DS(%r15)
	jz 	22f
	larw	R64_DS(%r15), %ax
	jz	22f
	movl	$0, R64_DS(%r15)
22:
	cmpl	$0, R64_ES(%r15)
	jz 	33f
	larw	R64_ES(%r15), %ax
	jz	33f
	movl	$0, R64_ES(%r15)
33:
	cmpl	$0, R64_FS(%r15)
	jz 	44f
	larw	R64_FS(%r15), %ax
	jz	44f
	movl	$0, R64_FS(%r15)
44:
	cmpl	$0, R64_GS(%r15)
	jz	55f
	larw	R64_GS(%r15), %ax
	jz	55f
	movl	$0, R64_GS(%r15)
55:
	/*
	 * Pack the segment registers in %rax since (%r15) will not
	 * be accessible after the %cr3 switch.
	 * Only restore %gs if cthread_self is zero, (indicate
	 * this to the code below with a value of 0xffff)
	 */
	mov	%gs:CPU_ACTIVE_THREAD, %rax	/* Get the active thread */
	cmpq	$0, TH_CTH_SELF(%rax)
	je	L_restore_gs
	movw	$0xFFFF, %ax
	jmp	1f
L_restore_gs:
	movw	R64_GS(%r15), %ax
1:
	shlq	$16, %rax
	movw	R64_FS(%r15), %ax
	shlq	$16, %rax
	movw	R64_ES(%r15), %ax
	shlq	$16, %rax
	movw	R64_DS(%r15), %ax

	/*
	 * Restore %r15, since we're done accessing saved state
	 * and (%r15) won't be accessible after the %cr3 switch.
	 */
	mov	R64_R15(%r15), %r15

	/* Discover user cr3/ASID */
	push	%rax
	mov	%gs:CPU_UCR3, %rax
#if	DEBUG
	mov	%rax, %gs:CPU_EXIT_CR3
#endif
	mov	%rax, %cr3
	/* Continue execution on the shared/doublemapped trampoline */
	pop	%rax
	swapgs

	/*
	 * Returning to user; restore segment registers that might be used
	 * by compatibility-mode code in a 64-bit user process.
	 *
	 * Note that if we take a fault here, it's OK that we haven't yet
	 * popped %rax from the stack, because %rsp will be reset to
	 * the value pushed onto the exception stack (above).
	 */
	movw	%ax, %ds
	shrq	$16, %rax

	movw	%ax, %es
	shrq	$16, %rax

	movw	%ax, %fs
	shrq	$16, %rax

	/*
	 * 0xFFFF is the sentinel set above that indicates we should
	 * not restore %gs (because GS.base was already set elsewhere
	 * (e.g.: in act_machine_set_pcb or machine_thread_set_tsd_base))
	 */
	cmpw	$0xFFFF, %ax
	je	L_chk_sysret
	movw	%ax, %gs		/* Restore %gs to user-set value */
	jmp	L_chk_sysret


L_u64bit_entry_check:
	/*
	 * Check we're not a confused 64-bit user.
	 */
	pushq	%rax
	swapgs
	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	mov	16(%rax), %rax

	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP(%rax)
	jne	L_64bit_entry_reject
	jmp	L_dispatch_kgsb

L_64bit_entry_reject:
	/*
	 * Here for a 64-bit user attempting an invalid kernel entry.
	 */
	movq	$(HNDL_ALLTRAPS), 8+ISF64_TRAPFN(%rsp)
	movq	$(T_INVALID_OPCODE), 8+ISF64_TRAPNO(%rsp)
	jmp 	L_dispatch_kgsb

Entry(ks_32bit_return)

	/* Validate CS/DS/ES/FS/GS segment selectors with the Load Access Rights instruction prior to restoration */
	/* Exempt "known good" statically configured selectors, e.g. USER_CS, USER_DS and 0 */
	cmpl	$(USER_CS), R32_CS(%r15)
	jz 	11f
	larw	R32_CS(%r15), %ax
	jnz	L_32_reset_cs
	/* Ensure that the segment referenced by CS in the saved state is a code segment (bit 11 == 1) */
	testw	$0x800, %ax
	jz	L_32_reset_cs		/* Update stored %cs with known-good selector if ZF == 1 */
	jmp	11f
L_32_reset_cs:
	movl	$(USER_CS), R32_CS(%r15)
11:
	cmpl	$(USER_DS), R32_DS(%r15)
	jz	22f
	cmpl	$0, R32_DS(%r15)
	jz 	22f
	larw	R32_DS(%r15), %ax
	jz	22f
	movl	$(USER_DS), R32_DS(%r15)
22:
	cmpl	$(USER_DS), R32_ES(%r15)
	jz	33f
	cmpl	$0, R32_ES(%r15)
	jz 	33f
	larw	R32_ES(%r15), %ax
	jz	33f
	movl	$(USER_DS), R32_ES(%r15)
33:
	cmpl	$(USER_DS), R32_FS(%r15)
	jz	44f
	cmpl	$0, R32_FS(%r15)
	jz 	44f
	larw	R32_FS(%r15), %ax
	jz	44f
	movl	$(USER_DS), R32_FS(%r15)
44:
	cmpl	$(USER_CTHREAD), R32_GS(%r15)
	jz	55f
	cmpl	$0, R32_GS(%r15)
	jz 	55f
	larw	R32_GS(%r15), %ax
	jz	55f
	movl	$(USER_CTHREAD), R32_GS(%r15)
55:

	/*
	 * Restore general 32-bit registers
	 */
	movl	R32_EAX(%r15), %eax
	movl	R32_EBX(%r15), %ebx
	movl	R32_ECX(%r15), %ecx
	movl	R32_EDX(%r15), %edx
	movl	R32_EBP(%r15), %ebp
	movl	R32_ESI(%r15), %esi
	movl	R32_EDI(%r15), %edi
	movl	R32_DS(%r15), %r8d
	movl	R32_ES(%r15), %r9d
	movl	R32_FS(%r15), %r10d
	movl	R32_GS(%r15), %r11d

	/* Switch to the per-cpu (doublemapped) exception stack */
	mov	%gs:CPU_ESTACK, %rsp

	/* Now transfer the ISF to the exception stack in preparation for iret, below */
	movl	R32_SS(%r15), %r12d
	push	%r12
	movl	R32_UESP(%r15), %r12d
	push	%r12
	movl	R32_EFLAGS(%r15), %r12d
	push	%r12
	movl	R32_CS(%r15), %r12d
	push	%r12
	movl	R32_EIP(%r15), %r12d
	push	%r12

	movl	%gs:CPU_NEED_SEGCHK, %r14d	/* %r14 will be zeroed just before we return */

	/*
	 * Finally, switch to the user pagetables.  After this, all %gs-relative
	 * accesses MUST be to cpu shadow data ONLY.  Note that after we restore %gs
	 * (after the swapgs), no %gs-relative accesses should be performed.
	 */
	/* Discover user cr3/ASID */
	mov	%gs:CPU_UCR3, %r13
#if	DEBUG
	mov	%r13, %gs:CPU_EXIT_CR3
#endif
	mov	%r13, %cr3

	swapgs

	/*
	 * Restore segment registers. A #GP taken here will push state onto IST1,
	 * not the exception stack.  Note that the placement of the labels here
	 * corresponds to the fault address-detection logic (so do not change them
	 * without also changing that code).
	 */
L_32bit_seg_restore_begin:
	mov	%r8, %ds
	mov	%r9, %es
	mov	%r10, %fs
	mov	%r11, %gs
L_32bit_seg_restore_done:

	/* Zero 64-bit-exclusive GPRs to prevent data leaks */
	xor	%r8, %r8
	xor	%r9, %r9
	xor	%r10, %r10
	xor	%r11, %r11
	xor	%r12, %r12
	xor	%r13, %r13
	xor	%r15, %r15

	/*
	 * At this point, the stack contains:
	 *
	 * +--------------+
	 * |  Return SS   | +32
	 * |  Return RSP  | +24
	 * |  Return RFL  | +16
	 * |  Return CS   | +8
	 * |  Return RIP  | <-- rsp
	 * +--------------+
	 */

	cmpl	$(SYSENTER_CS), 8(%rsp)
					/* test for sysexit */
	je      L_rtu_via_sysexit

	cmpl	$1, %r14d
	je	L_verw_island

L_after_verw:
	xor	%r14, %r14

.globl EXT(ret32_iret)
EXT(ret32_iret):
	iretq				/* return from interrupt */

L_verw_island:
	verw	32(%rsp)
	jmp	L_after_verw

L_verw_island_1:
	verw	16(%rsp)
	jmp	L_after_verw_1

L_rtu_via_sysexit:
	pop	%rdx			/* user return eip */
	pop	%rcx			/* pop and toss cs */
	andl	$(~EFL_IF), (%rsp)	/* clear interrupts enable, sti below */

	/*
	 * %ss is now at 16(%rsp)
	 */
	cmpl	$1, %r14d
	je	L_verw_island_1
L_after_verw_1:
	xor	%r14, %r14

	popf				/* flags - carry denotes failure */
	pop	%rcx			/* user return esp */


	sti				/* interrupts enabled after sysexit */
	sysexitl			/* 32-bit sysexit */

/* End of double-mapped TEXT */
.text

Entry(ks_dispatch)
	popq	%rax
	cmpl	$(KERNEL64_CS), ISF64_CS(%rsp)
	je	EXT(ks_dispatch_kernel)

	mov 	%rax, %gs:CPU_UBER_TMP
	mov 	%gs:CPU_UBER_ISF, %rax
	add 	$(ISF64_SIZE), %rax

	xchg	%rsp, %rax
/* Memory to memory moves (aint x86 wonderful):
 * Transfer the exception frame from the per-CPU exception stack to the
 * 'PCB' stack programmed at cswitch.
 */
	push	ISF64_SS(%rax)
	push	ISF64_RSP(%rax)
	push	ISF64_RFLAGS(%rax)
	push	ISF64_CS(%rax)
	push	ISF64_RIP(%rax)
	push	ISF64_ERR(%rax)
	push	ISF64_TRAPFN(%rax)
	push 	ISF64_TRAPNO(%rax)
	mov	%gs:CPU_UBER_TMP, %rax
	jmp	EXT(ks_dispatch_user)

Entry(ks_dispatch_user_with_pop_rax)
	pop	%rax
	jmp	EXT(ks_dispatch_user)

Entry(ks_dispatch_user)
	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP
	je	L_dispatch_U32		/* 32-bit user task */

L_dispatch_U64:
	subq	$(ISS64_OFFSET), %rsp
	mov	%r15, R64_R15(%rsp)
	mov	%rsp, %r15
	mov	%gs:CPU_KERNEL_STACK, %rsp
	jmp	L_dispatch_64bit

Entry(ks_dispatch_kernel_with_pop_rax)
	pop	%rax
	jmp	EXT(ks_dispatch_kernel)

Entry(ks_dispatch_kernel)
	subq	$(ISS64_OFFSET), %rsp
	mov	%r15, R64_R15(%rsp)
	mov	%rsp, %r15

/*
 * Here for 64-bit user task or kernel
 */
L_dispatch_64bit:
	movl	$(SS_64), SS_FLAVOR(%r15)

	/*
	 * Save segment regs if a 64-bit task has
	 * installed customized segments in the LDT
	 */
	cmpl	$0, %gs:CPU_CURTASK_HAS_LDT
	je	L_skip_save_extra_segregs

	mov	%ds, R64_DS(%r15)
	mov	%es, R64_ES(%r15)

L_skip_save_extra_segregs:
	mov	%fs, R64_FS(%r15)
	mov	%gs, R64_GS(%r15)


	/* Save general-purpose registers */
	mov	%rax, R64_RAX(%r15)
	mov	%rbx, R64_RBX(%r15)
	mov	%rcx, R64_RCX(%r15)
	mov	%rdx, R64_RDX(%r15)
	mov	%rbp, R64_RBP(%r15)
	mov	%rdi, R64_RDI(%r15)
	mov	%rsi, R64_RSI(%r15)
	mov	%r8,  R64_R8(%r15)
	mov	%r9,  R64_R9(%r15)
	mov	%r10, R64_R10(%r15)
	mov	%r11, R64_R11(%r15)
	mov	%r12, R64_R12(%r15)
	mov	%r13, R64_R13(%r15)
	mov	%r14, R64_R14(%r15)

	/* Zero unused GPRs. BX/DX/SI are clobbered elsewhere across the exception handler, and are skipped. */
	xor	%ecx, %ecx
	xor	%edi, %edi
	xor	%r8, %r8
	xor	%r9, %r9
	xor	%r10, %r10
	xor	%r11, %r11
	xor	%r12, %r12
	xor	%r13, %r13
	xor	%r14, %r14

	/* cr2 is significant only for page-faults */
	mov	%cr2, %rax
	mov	%rax, R64_CR2(%r15)

L_dispatch_U64_after_fault:
	mov	R64_TRAPNO(%r15), %ebx	/* %ebx := trapno for later */
	mov	R64_TRAPFN(%r15), %rdx	/* %rdx := trapfn for later */
	mov	R64_CS(%r15), %esi	/* %esi := cs for later */

	jmp	L_common_dispatch

L_dispatch_U32: /* 32-bit user task */
	subq	$(ISS64_OFFSET), %rsp
	mov	%rsp, %r15
	mov	%gs:CPU_KERNEL_STACK, %rsp
	movl	$(SS_32), SS_FLAVOR(%r15)

	/*
	 * Save segment regs
	 */
	mov	%ds, R32_DS(%r15)
	mov	%es, R32_ES(%r15)
	mov	%fs, R32_FS(%r15)
	mov	%gs, R32_GS(%r15)

	/*
	 * Save general 32-bit registers
	 */
	mov	%eax, R32_EAX(%r15)
	mov	%ebx, R32_EBX(%r15)
	mov	%ecx, R32_ECX(%r15)
	mov	%edx, R32_EDX(%r15)
	mov	%ebp, R32_EBP(%r15)
	mov	%esi, R32_ESI(%r15)
	mov	%edi, R32_EDI(%r15)

	/* Unconditionally save cr2; only meaningful on page faults */
	mov	%cr2, %rax
	mov	%eax, R32_CR2(%r15)
	/* Zero unused GPRs. BX/DX/SI/R15 are clobbered elsewhere across the exception handler, and are skipped. */
	xor	%ecx, %ecx
	xor	%edi, %edi
	xor	%r8, %r8
	xor	%r9, %r9
	xor	%r10, %r10
	xor	%r11, %r11
	xor	%r12, %r12
	xor	%r13, %r13
	xor	%r14, %r14

	/*
	 * Copy registers already saved in the machine state 
	 * (in the interrupt stack frame) into the compat save area.
	 */
	mov	R64_RIP(%r15), %eax
	mov	%eax, R32_EIP(%r15)
	mov	R64_RFLAGS(%r15), %eax
	mov	%eax, R32_EFLAGS(%r15)
	mov	R64_RSP(%r15), %eax
	mov	%eax, R32_UESP(%r15)
	mov	R64_SS(%r15), %eax
	mov	%eax, R32_SS(%r15)
L_dispatch_U32_after_fault:
	mov	R64_CS(%r15), %esi		/* %esi := %cs for later */
	mov	%esi, R32_CS(%r15)
	mov	R64_TRAPNO(%r15), %ebx		/* %ebx := trapno for later */
	mov	%ebx, R32_TRAPNO(%r15)
	mov	R64_ERR(%r15), %eax
	mov	%eax, R32_ERR(%r15)
	mov	R64_TRAPFN(%r15), %rdx		/* %rdx := trapfn for later */

L_common_dispatch:
	cld		/* Ensure the direction flag is clear in the kernel */
	cmpl    $0, EXT(pmap_smap_enabled)(%rip)
	je	1f
	clac		/* Clear EFLAGS.AC if SMAP is present/enabled */
1:
	/*
	 * We mark the kernel's cr3 as "active" for TLB coherency evaluation
	 * For threads with a mapped pagezero (some WINE games) on non-SMAP platforms,
	 * we switch to the kernel's address space on entry. Also, 
	 * if the global no_shared_cr3 is TRUE we do switch to the kernel's cr3
	 * so that illicit accesses to userspace can be trapped.
	 */
	mov	%gs:CPU_KERNEL_CR3, %rcx
	mov	%rcx, %gs:CPU_ACTIVE_CR3
	test	$3, %esi			/* CS: user/kernel? */
	jz	2f				/* skip CR3 reload if from kernel */
	xor	%ebp, %ebp
	cmpl	$0, %gs:CPU_PAGEZERO_MAPPED
	jnz	11f
	cmpl	$0, EXT(no_shared_cr3)(%rip)
	je	2f
11:
	xor	%eax, %eax
	movw	%gs:CPU_KERNEL_PCID, %ax
	or	%rax, %rcx
	mov	%rcx, %cr3			/* load kernel cr3 */
	jmp	4f
2:
	/* Deferred processing of pending kernel address space TLB invalidations */
	mov     %gs:CPU_ACTIVE_CR3+4, %rcx
	shr     $32, %rcx
	testl   %ecx, %ecx
	jz      4f
	movl    $0, %gs:CPU_TLB_INVALID
	cmpb	$0, EXT(invpcid_enabled)(%rip)
	jz	L_cr4_island
	movl	$2, %ecx
	invpcid %gs:CPU_IP_DESC, %rcx
4:
L_set_act:
	mov	%gs:CPU_ACTIVE_THREAD, %rcx	/* Get the active thread */
	testq	%rcx, %rcx
	je	L_intcnt
	movl	$-1, TH_IOTIER_OVERRIDE(%rcx)	/* Reset IO tier override to -1 before handling trap */
	cmpq	$0, TH_PCB_IDS(%rcx)	/* Is there a debug register state? */
	jnz	L_dr7_island
L_intcnt:
	incl	%gs:hwIntCnt(,%ebx,4)		// Bump the trap/intr count
	/* Dispatch the designated handler */
	cmp	EXT(dblmap_base)(%rip), %rsp
	jb	66f
	cmp	EXT(dblmap_max)(%rip), %rsp
	jge	66f
	subq	EXT(dblmap_dist)(%rip), %rsp
	subq	EXT(dblmap_dist)(%rip), %r15
66:
	leaq	EXT(idt64_hndl_table1)(%rip), %rax
	jmp	*(%rax, %rdx, 8)

L_cr4_island:
	mov	%cr4, %rcx      /* RMWW CR4, for lack of an alternative*/
	and	$(~CR4_PGE), %rcx
	mov	%rcx, %cr4
	or	$(CR4_PGE), %rcx
	mov	%rcx, %cr4
	jmp	L_set_act
L_dr7_island:
	xor	%ecx, %ecx		/* If so, reset DR7 (the control) */
	mov	%rcx, %dr7
	jmp	L_intcnt
/*
 * Control is passed here to return to user.
 */ 
Entry(return_to_user)
	TIME_TRAP_UEXIT

Entry(ret_to_user)
	mov	%gs:CPU_ACTIVE_THREAD, %rdx
	cmpq	$0, TH_PCB_IDS(%rdx)	/* Is there a debug register context? */
	jnz	L_dr_restore_island
L_post_dr_restore:
	/*
	 * We now mark the task's address space as active for TLB coherency.
	 * Handle special cases such as pagezero-less tasks here.
	 */
	mov	%gs:CPU_TASK_CR3, %rcx
	mov	%rcx, %gs:CPU_ACTIVE_CR3
	cmpl	$0, %gs:CPU_PAGEZERO_MAPPED
	jnz	L_cr3_switch_island
	movl	EXT(no_shared_cr3)(%rip), %eax
	test	%eax, %eax		/* -no_shared_cr3 */
	jnz	L_cr3_switch_island

L_cr3_switch_return:
	mov	%gs:CPU_DR7, %rax	/* Is there a debug control register?*/
	cmp	$0, %rax
	je	4f
	mov	%rax, %dr7		/* Set DR7 */
	movq	$0, %gs:CPU_DR7
4:
	cmpl	$(SS_64), SS_FLAVOR(%r15)	/* 64-bit state? */
	jne	L_32bit_return

	/*
	 * Restore general 64-bit registers.
	 * Here on fault stack and PCB address in R15.
	 */
	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	jmp	*8(%rax)


L_32bit_return:
#if DEBUG_IDT64
	cmpl	$(SS_32), SS_FLAVOR(%r15)	/* 32-bit state? */
	je	1f
	cli
	POSTCODE2(0x6432)
	CCALL1(panic_idt64, %r15)
1:
#endif /* DEBUG_IDT64 */

	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	jmp	*0x18(%rax)


L_dr_restore_island:
	movq    TH_PCB_IDS(%rdx),%rax   /* Obtain this thread's debug state */
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
	jmp	L_post_dr_restore
L_cr3_switch_island:
	xor	%eax, %eax
	movw	%gs:CPU_ACTIVE_PCID, %ax
	or	%rax, %rcx
	mov	%rcx, %cr3
	jmp	L_cr3_switch_return

ret_to_kernel:
#if DEBUG_IDT64
	cmpl	$(SS_64), SS_FLAVOR(%r15)	/* 64-bit state? */
	je	1f
	cli
	POSTCODE2(0x6464)
	CCALL1(panic_idt64, %r15)
	hlt
1:
	cmpl	$(KERNEL64_CS), R64_CS(%r15)
	je	2f
	CCALL1(panic_idt64, %r15)
	hlt
2:
#endif
	/*
	 * Restore general 64-bit registers.
	 * Here on fault stack and PCB address in R15.
	 */
	leaq	EXT(idt64_hndl_table0)(%rip), %rax
	jmp *8(%rax)

/* All 'exceptions' enter hndl_alltraps, with:
 *	r15	x86_saved_state_t address
 *	rsp	kernel stack if user-space, otherwise interrupt or kernel stack
 *	esi	cs at trap
 * 
 * The rest of the state is set up as:	
 *	both rsp and r15 are 16-byte aligned
 *	interrupts disabled
 *	direction flag cleared
 */
Entry(hndl_alltraps)
	mov	%esi, %eax
	testb	$3, %al
	jz	trap_from_kernel

	TIME_TRAP_UENTRY

	/* Check for active vtimers in the current task */
	mov	%gs:CPU_ACTIVE_THREAD, %rcx
	movl	$-1, TH_IOTIER_OVERRIDE(%rcx)	/* Reset IO tier override to -1 before handling trap/exception */
	mov	TH_TASK(%rcx), %rbx
	TASK_VTIMER_CHECK(%rbx, %rcx)

	CCALL1(user_trap, %r15)			/* call user trap routine */
	/* user_trap() unmasks interrupts */
	cli					/* hold off intrs - critical section */
	xorl	%ecx, %ecx			/* don't check if we're in the PFZ */


Entry(return_from_trap)
	movq	%gs:CPU_ACTIVE_THREAD,%r15	/* Get current thread */
	movl	$-1, TH_IOTIER_OVERRIDE(%r15)	/* Reset IO tier override to -1 before returning to userspace */

	cmpl	$0, TH_RWLOCK_COUNT(%r15)	/* Check if current thread has pending RW locks held */
	jz	1f
	xorq	%rbp, %rbp			/* clear framepointer */
	mov	%r15, %rdi			/* Set RDI to current thread */
	CCALL(lck_rw_clear_promotions_x86)	/* Clear promotions if needed */
1:	

	cmpl	$0, TH_TMP_ALLOC_CNT(%r15)	/* Check if current thread has KHEAP_TEMP leaks */
	jz	1f
	xorq	%rbp, %rbp			/* clear framepointer */
	mov	%r15, %rdi			/* Set RDI to current thread */
	CCALL(kheap_temp_leak_panic)
1:

	movq	TH_PCB_ISS(%r15), %r15		/* PCB stack */
	movl	%gs:CPU_PENDING_AST,%eax
	testl	%eax,%eax
	je	EXT(return_to_user)		/* branch if no AST */

L_return_from_trap_with_ast:
	testl	%ecx, %ecx		/* see if we need to check for an EIP in the PFZ */
	je	2f			/* no, go handle the AST */
	cmpl	$(SS_64), SS_FLAVOR(%r15)	/* are we a 64-bit task? */
	je	1f
					/* no... 32-bit user mode */
	movl	R32_EIP(%r15), %edi
	xorq	%rbp, %rbp		/* clear framepointer */
	CCALL(commpage_is_in_pfz32)
	testl	%eax, %eax
	je	2f			/* not in the PFZ... go service AST */
	movl	%eax, R32_EBX(%r15)	/* let the PFZ know we've pended an AST */
	jmp	EXT(return_to_user)
1:
	movq	R64_RIP(%r15), %rdi
	xorq	%rbp, %rbp		/* clear framepointer */
	CCALL(commpage_is_in_pfz64)
	testl	%eax, %eax
	je	2f			/* not in the PFZ... go service AST */
	movl	%eax, R64_RBX(%r15)	/* let the PFZ know we've pended an AST */
	jmp	EXT(return_to_user)
2:

	xorq	%rbp, %rbp		/* clear framepointer */
	CCALL(ast_taken_user)		/* handle all ASTs (enables interrupts, may return via continuation) */

	cli
	mov	%rsp, %r15		/* AST changes stack, saved state */
	xorl	%ecx, %ecx		/* don't check if we're in the PFZ */
	jmp	EXT(return_from_trap)	/* and check again (rare) */

/*
 * Trap from kernel mode.  No need to switch stacks.
 * Interrupts must be off here - we will set them to state at time of trap
 * as soon as it's safe for us to do so and not recurse doing preemption
 * 
 */
trap_from_kernel:

UNWIND_PROLOGUE	
	
	movq	%r15, %rdi		/* saved state addr */

UNWIND_DIRECTIVES	

	pushq   R64_RIP(%r15)           /* Simulate a CALL from fault point */
	pushq   %rbp                    /* Extend framepointer chain */
	movq    %rsp, %rbp
	CCALLWITHSP(kernel_trap)	/* to kernel trap routine */
	popq    %rbp
	addq    $8, %rsp
	mov	%rsp, %r15		/* DTrace slides stack/saved-state */
	cli

	movl	%gs:CPU_PENDING_AST,%eax	/* get pending asts */
	testl	$(AST_URGENT),%eax		/* any urgent preemption? */
	je	ret_to_kernel			/* no, nothing to do */
	cmpl	$(T_PREEMPT),R64_TRAPNO(%r15)
	je	ret_to_kernel			/* T_PREEMPT handled in kernel_trap() */
	testl	$(EFL_IF),R64_RFLAGS(%r15)	/* interrupts disabled? */
	je	ret_to_kernel
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL	/* preemption disabled? */
	jne	ret_to_kernel
	movq	%gs:CPU_KERNEL_STACK,%rax
	movq	%rsp,%rcx
	xorq	%rax,%rcx
	andq	EXT(kernel_stack_mask)(%rip),%rcx
	testq	%rcx,%rcx		/* are we on the kernel stack? */
	jne	ret_to_kernel		/* no, skip it */

	CCALL(ast_taken_kernel)         /* take the AST */

	mov	%rsp, %r15		/* AST changes stack, saved state */
	jmp	ret_to_kernel

UNWIND_EPILOGUE
	
/*
 * All interrupts on all tasks enter here with:
 *	r15	 x86_saved_state_t
 *	rsp	 kernel or interrupt stack
 *	esi	 cs at trap
 *
 *	both rsp and r15 are 16-byte aligned
 *	interrupts disabled
 *	direction flag cleared
 */
Entry(hndl_allintrs)

UNWIND_PROLOGUE	
	
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

	pushq	%rcx			/* save pointer to old stack */
	pushq	%gs:CPU_INT_STATE	/* save previous intr state */
	movq	%r15,%gs:CPU_INT_STATE	/* set intr state */

UNWIND_DIRECTIVES	
	
	TIME_INT_ENTRY			/* do timing */

	/* Check for active vtimers in the current task */
	mov	%gs:CPU_ACTIVE_THREAD, %rcx
	mov	TH_TASK(%rcx), %rbx
	TASK_VTIMER_CHECK(%rbx, %rcx)

	incl	%gs:CPU_PREEMPTION_LEVEL
	incl	%gs:CPU_INTERRUPT_LEVEL

	CCALL1(interrupt, %r15)		/* call generic interrupt routine */
	
UNWIND_EPILOGUE

.globl	EXT(return_to_iret)
LEXT(return_to_iret)			/* (label for kdb_kintr and hardclock) */

	decl	%gs:CPU_INTERRUPT_LEVEL
	decl	%gs:CPU_PREEMPTION_LEVEL

	TIME_INT_EXIT			/* do timing */

	popq	%gs:CPU_INT_STATE 	/* reset/clear intr state pointer */
	popq	%rsp			/* switch back to old stack */

	movq	%gs:CPU_ACTIVE_THREAD,%rax
	movq	TH_PCB_FPS(%rax),%rax	/* get pcb's ifps */
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
	/* Load interrupted code segment into %eax */
	movl	R64_CS(%r15),%eax	/* assume 64-bit state */
	cmpl	$(SS_32),SS_FLAVOR(%r15)/* 32-bit? */
#if DEBUG_IDT64
	jne	5f
	movl	R32_CS(%r15),%eax	/* 32-bit user mode */
	jmp	3f
5:
	cmpl    $(SS_64),SS_FLAVOR(%r15)
	je	3f
	POSTCODE2(0x6431)
	CCALL1(panic_idt64, %r15)
	hlt
#else
	je	4f
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

	/*
	 * Take an AST from kernel space.  We don't need (and don't want)
	 * to do as much as the case where the interrupt came from user
	 * space.
	 */
	CCALL(ast_taken_kernel)

	mov	%rsp, %r15		/* AST changes stack, saved state */
	jmp	ret_to_kernel
4:
	movl	R32_CS(%r15),%eax	/* 32-bit user mode */
	jmp	3b


/*
 * nested int - simple path, can't preempt etc on way out
 */
int_from_intstack:
	incl	%gs:CPU_PREEMPTION_LEVEL
	incl	%gs:CPU_INTERRUPT_LEVEL
	incl	%gs:CPU_NESTED_ISTACK

	push	%gs:CPU_INT_STATE
	mov	%r15, %gs:CPU_INT_STATE

	CCALL1(interrupt, %r15)

	pop	%gs:CPU_INT_STATE

	decl	%gs:CPU_INTERRUPT_LEVEL
	decl	%gs:CPU_PREEMPTION_LEVEL
	decl	%gs:CPU_NESTED_ISTACK

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
 *	r15	 x86_saved_state32_t
 *	rsp	 kernel stack
 *
 *	both rsp and r15 are 16-byte aligned
 *	interrupts disabled
 *	direction flag cleared
 */

Entry(hndl_sysenter)
	/*
	 * We can be here either for a mach syscall or a unix syscall,
	 * as indicated by the sign of the code:
	 */
	movl	R32_EAX(%r15),%eax
	testl	%eax,%eax
	js	EXT(hndl_mach_scall)		/* < 0 => mach */
						/* > 0 => unix */
	
Entry(hndl_unix_scall)

        TIME_TRAP_UENTRY

	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movq	TH_TASK(%rcx),%rbx		/* point to current task  */
	incl	TH_SYSCALLS_UNIX(%rcx)		/* increment call count   */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	sti

	CCALL1(unix_syscall, %r15)
	/*
	 * always returns through thread_exception_return
	 */


Entry(hndl_mach_scall)
	TIME_TRAP_UENTRY

	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movq	TH_TASK(%rcx),%rbx		/* point to current task  */
	incl	TH_SYSCALLS_MACH(%rcx)		/* increment call count   */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	sti

	CCALL1(mach_call_munger, %r15)
	/*
	 * always returns through thread_exception_return
	 */


Entry(hndl_mdep_scall)
	TIME_TRAP_UENTRY

	/* Check for active vtimers in the current task */
	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movq	TH_TASK(%rcx),%rbx		/* point to current task  */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	sti

	CCALL1(machdep_syscall, %r15)
	/*
	 * always returns through thread_exception_return
	 */

/*
 * 64bit Tasks
 * System call entries via syscall only:
 *
 *	r15	 x86_saved_state64_t
 *	rsp	 kernel stack
 *
 *	both rsp and r15 are 16-byte aligned
 *	interrupts disabled
 *	direction flag cleared
 */

Entry(hndl_syscall)
	TIME_TRAP_UENTRY

	movq	%gs:CPU_ACTIVE_THREAD,%rcx	/* get current thread     */
	movl	$-1, TH_IOTIER_OVERRIDE(%rcx)	/* Reset IO tier override to -1 before handling syscall */
	movq	TH_TASK(%rcx),%rbx		/* point to current task  */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%rbx,%rcx)

	/*
	 * We can be here either for a mach, unix machdep or diag syscall,
	 * as indicated by the syscall class:
	 */
	movl	R64_RAX(%r15), %eax		/* syscall number/class */
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
	sti
	CCALL3(i386_exception, $(EXC_SYSCALL), %rax, $1)
	/* no return */


Entry(hndl_unix_scall64)
	incl	TH_SYSCALLS_UNIX(%rcx)		/* increment call count   */
	sti

	CCALL1(unix_syscall64, %r15)
	/*
	 * always returns through thread_exception_return
	 */


Entry(hndl_mach_scall64)
	incl	TH_SYSCALLS_MACH(%rcx)		/* increment call count   */
	sti

	CCALL1(mach_call_munger64, %r15)
	/*
	 * always returns through thread_exception_return
	 */



Entry(hndl_mdep_scall64)
	sti

	CCALL1(machdep_syscall64, %r15)
	/*
	 * always returns through thread_exception_return
	 */

Entry(hndl_diag_scall64)
	CCALL1(diagCall64, %r15)	// Call diagnostics
	test	%eax, %eax		// What kind of return is this?
	je	1f			// - branch if bad (zero)
	jmp	EXT(return_to_user)	// Normal return, do not check asts...
1:
	sti
	CCALL3(i386_exception, $EXC_SYSCALL, $0x6000, $1)
	/* no return */
/* TODO assert at all 'C' entry points that we're never operating on the fault stack's alias mapping */
Entry(hndl_machine_check)
	/* Adjust SP and savearea to their canonical, non-aliased addresses */
	CCALL1(panic_machine_check64, %r15)
	hlt

Entry(hndl_double_fault)
	CCALL1(panic_double_fault64, %r15)
	hlt
