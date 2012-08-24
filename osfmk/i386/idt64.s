/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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
#include <i386/asm64.h>
#include <assym.s>
#include <i386/eflags.h>
#include <i386/trap.h>
#include <i386/rtclock_asm.h>
#define _ARCH_I386_ASM_HELP_H_		/* Prevent inclusion of user header */
#include <mach/i386/syscall_sw.h>
#include <i386/postcode.h>
#include <i386/proc_reg.h>
#include <mach/exception_types.h>


/*
 * Low-memory compability-mode handlers.
 */
#define	LO_ALLINTRS		EXT(lo_allintrs)
#define	LO_ALLTRAPS		EXT(lo_alltraps)
#define	LO_SYSCALL		EXT(lo_syscall)
#define	LO_UNIX_SCALL		EXT(lo_unix_scall)
#define	LO_MACH_SCALL		EXT(lo_mach_scall)
#define	LO_MDEP_SCALL		EXT(lo_mdep_scall)
#define	LO_DOUBLE_FAULT		EXT(lo_df64)
#define	LO_MACHINE_CHECK	EXT(lo_mc64)

/*
 * Interrupt descriptor table and code vectors for it.
 *
 * The IDT64_BASE_ENTRY macro lays down a fake descriptor that must be
 * reformatted ("fixed") before use. 
 * All vector are rebased in uber-space.
 * Special vectors (e.g. double-fault) use a non-0 IST.
 */
#define	IDT64_BASE_ENTRY(vec,seg,ist,type)		 \
	.data						;\
	.long	vec					;\
	.long	KERNEL_UBER_BASE_HI32			;\
	.word	seg					;\
	.byte	ist*16					;\
	.byte	type					;\
	.long	0					;\
	.text

#define	IDT64_ENTRY(vec,ist,type)			\
	IDT64_BASE_ENTRY(EXT(vec),KERNEL64_CS,ist,type)
#define	IDT64_ENTRY_LOCAL(vec,ist,type)			\
	IDT64_BASE_ENTRY(vec,KERNEL64_CS,ist,type)

/*
 * Push trap number and address of compatibility mode handler,
 * then branch to common trampoline. Error already pushed.
 */
#define	EXCEP64_ERR(n,name)				 \
	IDT64_ENTRY(name,0,K_INTR_GATE)			;\
Entry(name)						;\
	push	$(LO_ALLTRAPS)				;\
	push	$(n)					;\
	jmp	L_enter_lohandler


/*
 * Push error(0), trap number and address of compatibility mode handler,
 * then branch to common trampoline.
 */
#define	EXCEPTION64(n,name)				 \
	IDT64_ENTRY(name,0,K_INTR_GATE)			;\
Entry(name)						;\
	push	$0					;\
	push	$(LO_ALLTRAPS)				;\
	push	$(n)					;\
	jmp	L_enter_lohandler

	
/*
 * Interrupt from user.
 * Push error (0), trap number and address of compatibility mode handler,
 * then branch to common trampoline.
 */
#define	EXCEP64_USR(n,name)				 \
	IDT64_ENTRY(name,0,U_INTR_GATE)			;\
Entry(name)						;\
	push	$0					;\
	push	$(LO_ALLTRAPS)				;\
	push	$(n)					;\
	jmp	L_enter_lohandler


/*
 * Special interrupt code from user.
 */
#define EXCEP64_SPC_USR(n,name) 			\
	IDT64_ENTRY(name,0,U_INTR_GATE) 


/*
 * Special interrupt code. 
 * In 64-bit mode we may use an IST slot instead of task gates.
 */
#define	EXCEP64_IST(n,name,ist) 			\
	IDT64_ENTRY(name,ist,K_INTR_GATE)
#define	EXCEP64_SPC(n,name)	 			\
	IDT64_ENTRY(name,0,K_INTR_GATE)

	
/*
 * Interrupt.
 * Push zero err, interrupt vector and address of compatibility mode handler,
 * then branch to common trampoline.
 */
#define	INTERRUPT64(n)					 \
	IDT64_ENTRY_LOCAL(L_ ## n,0,K_INTR_GATE)	;\
	.align FALIGN					;\
L_ ## n:						;\
	push	$0					;\
	push	$(LO_ALLINTRS)				;\
	push	$(n)					;\
	jmp	L_enter_lohandler


	.data
	.align 12
Entry(master_idt64)
Entry(hi64_data_base)
	.text
	.code64
Entry(hi64_text_base)

EXCEPTION64(0x00,t64_zero_div)
EXCEP64_SPC(0x01,hi64_debug)
INTERRUPT64(0x02)			/* NMI */
EXCEP64_USR(0x03,t64_int3)
EXCEP64_USR(0x04,t64_into)
EXCEP64_USR(0x05,t64_bounds)
EXCEPTION64(0x06,t64_invop)
EXCEPTION64(0x07,t64_nofpu)
EXCEP64_IST(0x08,hi64_double_fault,1)
EXCEPTION64(0x09,a64_fpu_over)
EXCEPTION64(0x0a,a64_inv_tss)
EXCEP64_SPC(0x0b,hi64_segnp)
EXCEP64_SPC(0x0c,hi64_stack_fault)
EXCEP64_SPC(0x0d,hi64_gen_prot)
EXCEP64_SPC(0x0e, hi64_page_fault)
EXCEPTION64(0x0f,t64_trap_0f)
EXCEPTION64(0x10,t64_fpu_err)
EXCEPTION64(0x11,t64_trap_11)
EXCEP64_IST(0x12,mc64,1)
EXCEPTION64(0x13,t64_sse_err)
EXCEPTION64(0x14,t64_trap_14)
EXCEPTION64(0x15,t64_trap_15)
EXCEPTION64(0x16,t64_trap_16)
EXCEPTION64(0x17,t64_trap_17)
EXCEPTION64(0x18,t64_trap_18)
EXCEPTION64(0x19,t64_trap_19)
EXCEPTION64(0x1a,t64_trap_1a)
EXCEPTION64(0x1b,t64_trap_1b)
EXCEPTION64(0x1c,t64_trap_1c)
EXCEPTION64(0x1d,t64_trap_1d)
EXCEPTION64(0x1e,t64_trap_1e)
EXCEPTION64(0x1f,t64_trap_1f)

INTERRUPT64(0x20)
INTERRUPT64(0x21)
INTERRUPT64(0x22)
INTERRUPT64(0x23)
INTERRUPT64(0x24)
INTERRUPT64(0x25)
INTERRUPT64(0x26)
INTERRUPT64(0x27)
INTERRUPT64(0x28)
INTERRUPT64(0x29)
INTERRUPT64(0x2a)
INTERRUPT64(0x2b)
INTERRUPT64(0x2c)
INTERRUPT64(0x2d)
INTERRUPT64(0x2e)
INTERRUPT64(0x2f)

INTERRUPT64(0x30)
INTERRUPT64(0x31)
INTERRUPT64(0x32)
INTERRUPT64(0x33)
INTERRUPT64(0x34)
INTERRUPT64(0x35)
INTERRUPT64(0x36)
INTERRUPT64(0x37)
INTERRUPT64(0x38)
INTERRUPT64(0x39)
INTERRUPT64(0x3a)
INTERRUPT64(0x3b)
INTERRUPT64(0x3c)
INTERRUPT64(0x3d)
INTERRUPT64(0x3e)
INTERRUPT64(0x3f)

INTERRUPT64(0x40)
INTERRUPT64(0x41)
INTERRUPT64(0x42)
INTERRUPT64(0x43)
INTERRUPT64(0x44)
INTERRUPT64(0x45)
INTERRUPT64(0x46)
INTERRUPT64(0x47)
INTERRUPT64(0x48)
INTERRUPT64(0x49)
INTERRUPT64(0x4a)
INTERRUPT64(0x4b)
INTERRUPT64(0x4c)
INTERRUPT64(0x4d)
INTERRUPT64(0x4e)
INTERRUPT64(0x4f)

INTERRUPT64(0x50)
INTERRUPT64(0x51)
INTERRUPT64(0x52)
INTERRUPT64(0x53)
INTERRUPT64(0x54)
INTERRUPT64(0x55)
INTERRUPT64(0x56)
INTERRUPT64(0x57)
INTERRUPT64(0x58)
INTERRUPT64(0x59)
INTERRUPT64(0x5a)
INTERRUPT64(0x5b)
INTERRUPT64(0x5c)
INTERRUPT64(0x5d)
INTERRUPT64(0x5e)
INTERRUPT64(0x5f)

INTERRUPT64(0x60)
INTERRUPT64(0x61)
INTERRUPT64(0x62)
INTERRUPT64(0x63)
INTERRUPT64(0x64)
INTERRUPT64(0x65)
INTERRUPT64(0x66)
INTERRUPT64(0x67)
INTERRUPT64(0x68)
INTERRUPT64(0x69)
INTERRUPT64(0x6a)
INTERRUPT64(0x6b)
INTERRUPT64(0x6c)
INTERRUPT64(0x6d)
INTERRUPT64(0x6e)
INTERRUPT64(0x6f)

INTERRUPT64(0x70)
INTERRUPT64(0x71)
INTERRUPT64(0x72)
INTERRUPT64(0x73)
INTERRUPT64(0x74)
INTERRUPT64(0x75)
INTERRUPT64(0x76)
INTERRUPT64(0x77)
INTERRUPT64(0x78)
INTERRUPT64(0x79)
INTERRUPT64(0x7a)
INTERRUPT64(0x7b)
INTERRUPT64(0x7c)
INTERRUPT64(0x7d)
INTERRUPT64(0x7e)
EXCEP64_USR(0x7f, t64_dtrace_ret)

EXCEP64_SPC_USR(0x80,hi64_unix_scall)
EXCEP64_SPC_USR(0x81,hi64_mach_scall)
EXCEP64_SPC_USR(0x82,hi64_mdep_scall)
INTERRUPT64(0x83)
INTERRUPT64(0x84)
INTERRUPT64(0x85)
INTERRUPT64(0x86)
INTERRUPT64(0x87)
INTERRUPT64(0x88)
INTERRUPT64(0x89)
INTERRUPT64(0x8a)
INTERRUPT64(0x8b)
INTERRUPT64(0x8c)
INTERRUPT64(0x8d)
INTERRUPT64(0x8e)
INTERRUPT64(0x8f)

INTERRUPT64(0x90)
INTERRUPT64(0x91)
INTERRUPT64(0x92)
INTERRUPT64(0x93)
INTERRUPT64(0x94)
INTERRUPT64(0x95)
INTERRUPT64(0x96)
INTERRUPT64(0x97)
INTERRUPT64(0x98)
INTERRUPT64(0x99)
INTERRUPT64(0x9a)
INTERRUPT64(0x9b)
INTERRUPT64(0x9c)
INTERRUPT64(0x9d)
INTERRUPT64(0x9e)
INTERRUPT64(0x9f)

INTERRUPT64(0xa0)
INTERRUPT64(0xa1)
INTERRUPT64(0xa2)
INTERRUPT64(0xa3)
INTERRUPT64(0xa4)
INTERRUPT64(0xa5)
INTERRUPT64(0xa6)
INTERRUPT64(0xa7)
INTERRUPT64(0xa8)
INTERRUPT64(0xa9)
INTERRUPT64(0xaa)
INTERRUPT64(0xab)
INTERRUPT64(0xac)
INTERRUPT64(0xad)
INTERRUPT64(0xae)
INTERRUPT64(0xaf)

INTERRUPT64(0xb0)
INTERRUPT64(0xb1)
INTERRUPT64(0xb2)
INTERRUPT64(0xb3)
INTERRUPT64(0xb4)
INTERRUPT64(0xb5)
INTERRUPT64(0xb6)
INTERRUPT64(0xb7)
INTERRUPT64(0xb8)
INTERRUPT64(0xb9)
INTERRUPT64(0xba)
INTERRUPT64(0xbb)
INTERRUPT64(0xbc)
INTERRUPT64(0xbd)
INTERRUPT64(0xbe)
INTERRUPT64(0xbf)

INTERRUPT64(0xc0)
INTERRUPT64(0xc1)
INTERRUPT64(0xc2)
INTERRUPT64(0xc3)
INTERRUPT64(0xc4)
INTERRUPT64(0xc5)
INTERRUPT64(0xc6)
INTERRUPT64(0xc7)
INTERRUPT64(0xc8)
INTERRUPT64(0xc9)
INTERRUPT64(0xca)
INTERRUPT64(0xcb)
INTERRUPT64(0xcc)
INTERRUPT64(0xcd)
INTERRUPT64(0xce)
INTERRUPT64(0xcf)

INTERRUPT64(0xd0)
INTERRUPT64(0xd1)
INTERRUPT64(0xd2)
INTERRUPT64(0xd3)
INTERRUPT64(0xd4)
INTERRUPT64(0xd5)
INTERRUPT64(0xd6)
INTERRUPT64(0xd7)
INTERRUPT64(0xd8)
INTERRUPT64(0xd9)
INTERRUPT64(0xda)
INTERRUPT64(0xdb)
INTERRUPT64(0xdc)
INTERRUPT64(0xdd)
INTERRUPT64(0xde)
INTERRUPT64(0xdf)

INTERRUPT64(0xe0)
INTERRUPT64(0xe1)
INTERRUPT64(0xe2)
INTERRUPT64(0xe3)
INTERRUPT64(0xe4)
INTERRUPT64(0xe5)
INTERRUPT64(0xe6)
INTERRUPT64(0xe7)
INTERRUPT64(0xe8)
INTERRUPT64(0xe9)
INTERRUPT64(0xea)
INTERRUPT64(0xeb)
INTERRUPT64(0xec)
INTERRUPT64(0xed)
INTERRUPT64(0xee)
INTERRUPT64(0xef)

INTERRUPT64(0xf0)
INTERRUPT64(0xf1)
INTERRUPT64(0xf2)
INTERRUPT64(0xf3)
INTERRUPT64(0xf4)
INTERRUPT64(0xf5)
INTERRUPT64(0xf6)
INTERRUPT64(0xf7)
INTERRUPT64(0xf8)
INTERRUPT64(0xf9)
INTERRUPT64(0xfa)
INTERRUPT64(0xfb)
INTERRUPT64(0xfc)
INTERRUPT64(0xfd)
INTERRUPT64(0xfe)
EXCEPTION64(0xff,t64_preempt)


        .text
/*
 *
 * Trap/interrupt entry points.
 *
 * All traps must create the following 32-bit save area on the PCB "stack"
 * - this is identical to the legacy mode 32-bit case:
 *
 *	gs
 *	fs
 *	es
 *	ds
 *	edi
 *	esi
 *	ebp
 *	cr2 (defined only for page fault)
 *	ebx
 *	edx
 *	ecx
 *	eax
 *	trap number
 *	error code
 *	eip
 *	cs
 *	eflags
 *	user esp - if from user
 *	user ss  - if from user
 *
 * Above this is the trap number and compatibility mode handler address
 * (packed into an 8-byte stack entry) and the 64-bit interrupt stack frame:
 *
 *	(trapno, trapfn)
 *	err
 *	rip
 *	cs
 *	rflags
 *	rsp
 *	ss
 *	
 */

	.code32

/*
 * Control is passed here to return to the compatibility mode user.
 * At this stage we're in kernel space in compatibility mode
 * but we need to switch into 64-bit mode in the 4G-based trampoline
 * space before performing the iret.
 */ 
ret_to_user:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	movl	TH_PCB_IDS(%ecx),%eax	/* Obtain this thread's debug state */
	cmpl	$0,%eax			/* Is there a debug register context? */
	je	2f 			/* branch if not */
	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP /* Are we a 32-bit task? */
	jne	1f
	movl	DS_DR0(%eax), %ecx	/* If so, load the 32 bit DRs */
	movl	%ecx, %db0
	movl	DS_DR1(%eax), %ecx
	movl	%ecx, %db1
	movl	DS_DR2(%eax), %ecx
	movl	%ecx, %db2
	movl	DS_DR3(%eax), %ecx
	movl	%ecx, %db3
	movl	DS_DR7(%eax), %ecx
	movl 	%ecx, %gs:CPU_DR7
	movl	$0, %gs:CPU_DR7 + 4
	jmp 	2f
1:
	ENTER_64BIT_MODE()		/* Enter long mode */
	mov	DS64_DR0(%eax), %rcx	/* Load the full width DRs*/
	mov	%rcx, %dr0
	mov	DS64_DR1(%eax), %rcx
	mov	%rcx, %dr1
	mov	DS64_DR2(%eax), %rcx
	mov	%rcx, %dr2
	mov	DS64_DR3(%eax), %rcx
	mov	%rcx, %dr3
	mov	DS64_DR7(%eax), %rcx
	mov 	%rcx, %gs:CPU_DR7
	jmp	3f			/* Enter uberspace */
2:
	ENTER_64BIT_MODE()
3:
	ENTER_UBERSPACE()	

	/*
	 * Now switch %cr3, if necessary.
	 */
	swapgs				/* switch back to uber-kernel gs base */
	mov	%gs:CPU_TASK_CR3,%rcx
	mov	%rcx,%gs:CPU_ACTIVE_CR3
	mov	%cr3, %rax
	cmp	%rcx, %rax
	je	1f
	/* flag the copyio engine state as WINDOWS_CLEAN */
	mov	%gs:CPU_ACTIVE_THREAD,%eax
	movl	$(WINDOWS_CLEAN),TH_COPYIO_STATE(%eax)
	mov	%rcx,%cr3               /* switch to user's address space */
1:

	mov	%gs:CPU_DR7, %rax	/* Is there a debug control register?*/
	cmp	$0, %rax
	je	1f
	mov	%rax, %dr7		/* Set DR7 */
	movq	$0, %gs:CPU_DR7
1:

	/*
	 * Adjust stack to use uber-space.
	 */
	mov	$(KERNEL_UBER_BASE_HI32), %rax
	shl	$32, %rsp
	shrd	$32, %rax, %rsp			/* relocate into uber-space */

	cmpl	$(SS_32), SS_FLAVOR(%rsp)	/* 32-bit state? */
	jne	L_64bit_return
	jmp	L_32bit_return

ret_to_kernel:
	ENTER_64BIT_MODE()
	ENTER_UBERSPACE()	

	swapgs				/* switch back to uber-kernel gs base */

	/*
	 * Adjust stack to use uber-space.
	 */
	mov	$(KERNEL_UBER_BASE_HI32), %rax
	shl	$32, %rsp
	shrd	$32, %rax, %rsp			/* relocate into uber-space */

	/* Check for return to 64-bit kernel space (EFI today) */
	cmpl	$(SS_32), SS_FLAVOR(%rsp)	/* 32-bit state? */
	jne	L_64bit_return
	/* fall through for 32-bit return */

L_32bit_return:
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

	add	$(ISC32_OFFSET)+8+8+8, %rsp	/* pop compat frame +
						   trapno, trapfn and error */	
        cmpl	$(SYSENTER_CS),ISF64_CS-8-8-8(%rsp)
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
	.code32
	sti				/* interrupts enabled after sysexit */
	.byte 0x0f,0x35			/* 32-bit sysexit */
	.code64

L_64bit_return:
	/*
	 * Set the GS Base MSR with the user's gs base.
	 */
	movl	%gs:CPU_UBER_USER_GS_BASE, %eax
	movl	%gs:CPU_UBER_USER_GS_BASE+4, %edx
	movl	$(MSR_IA32_GS_BASE), %ecx
	swapgs
	testb	$3, R64_CS(%rsp)		/* returning to user-space? */
	jz	1f
	wrmsr					/* set 64-bit base */
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

	add	$(ISS64_OFFSET)+8+8+8, %rsp	/* pop saved state frame +
						   trapno, trapfn and error */	
        cmpl	$(SYSCALL_CS),ISF64_CS-8-8-8(%rsp)
					/* test for fast entry/exit */
        je      L_sysret
EXT(ret64_iret):
        iretq				/* return from interrupt */

L_sysret:
	/*
	 * Here to load rcx/r11/rsp and perform the sysret back to user-space.
	 * 	rcx	user rip
	 *	r1	user rflags
	 *	rsp	user stack pointer
	 */
	mov	ISF64_RIP-8-8-8(%rsp), %rcx
	mov	ISF64_RFLAGS-8-8-8(%rsp), %r11
	mov	ISF64_RSP-8-8-8(%rsp), %rsp
	sysretq				/* return from system call */

/*
 * Common path to enter locore handlers.
 */
L_enter_lohandler:
	swapgs				/* switch to kernel gs (cpu_data) */
L_enter_lohandler_continue:
	cmpl	$(USER64_CS), ISF64_CS(%rsp)
	je	L_64bit_enter		/* this is a 64-bit user task */
	cmpl	$(KERNEL64_CS), ISF64_CS(%rsp)
	je	L_64bit_enter		/* we're in 64-bit (EFI) code */
	jmp	L_32bit_enter

/*
 * System call handlers.
 * These are entered via a syscall interrupt. The system call number in %rax
 * is saved to the error code slot in the stack frame. We then branch to the
 * common state saving code.
 */
		
Entry(hi64_unix_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_unix_scall_continue:
	push	%rax			/* save system call number */
	push	$(LO_UNIX_SCALL)
	push	$(UNIX_INT)
	jmp	L_32bit_enter_check

	
Entry(hi64_mach_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_mach_scall_continue:
	push	%rax			/* save system call number */
	push	$(LO_MACH_SCALL)
	push	$(MACH_INT)
	jmp	L_32bit_enter_check

	
Entry(hi64_mdep_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_mdep_scall_continue:
	push	%rax			/* save system call number */
	push	$(LO_MDEP_SCALL)
	push	$(MACHDEP_INT)
	jmp	L_32bit_enter_check

	
Entry(hi64_syscall)
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
	movl	$(T_SYSCALL), ISF64_TRAPNO(%rsp)	/* trapno */
	movl	$(LO_SYSCALL), ISF64_TRAPFN(%rsp)
	jmp	L_64bit_enter		/* this can only be a 64-bit task */


L_32bit_enter_check:
	/*
	 * Check we're not a confused 64-bit user.
	 */
	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP
	jne	L_64bit_entry_reject
	jmp	L_32bit_enter
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
	mov	(%rsp), %rsp		/* switch from temporary stack to pcb */
	/*
	 * Push values on to the PCB stack
	 * to cons up the saved machine state.
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
	swapgs				/* switch to kernel gs (cpu_data) */
L_sysenter_continue:
	push	%rdx			/* eip */
	push	%rax			/* err/eax - syscall code */
	push	$0
	push	$(T_SYSENTER)
	orl	$(EFL_IF), ISF64_RFLAGS(%rsp)
	movl	$(LO_MACH_SCALL), ISF64_TRAPFN(%rsp)
	testl	%eax, %eax
	js	L_32bit_enter_check
	movl	$(LO_UNIX_SCALL), ISF64_TRAPFN(%rsp)
 	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP
 	jne	L_64bit_entry_reject
/* If the caller (typically LibSystem) has recorded the cumulative size of
 * the arguments in EAX, copy them over from the user stack directly.
 * We recover from exceptions inline--if the copy loop doesn't complete
 * due to an exception, we fall back to copyin from compatibility mode.
 * We can potentially extend this mechanism to mach traps as well (DRK).
 */
L_sysenter_copy_args:
	testl	$(I386_SYSCALL_ARG_BYTES_MASK), %eax
	jz	L_32bit_enter
	xor	%r9, %r9
	mov	%gs:CPU_UBER_ARG_STORE, %r8
	movl	%eax, %r9d
	mov	%gs:CPU_UBER_ARG_STORE_VALID, %r12
	xor	%r10, %r10
	shrl	$(I386_SYSCALL_ARG_DWORDS_SHIFT), %r9d
	andl	$(I386_SYSCALL_ARG_DWORDS_MASK), %r9d
	movl	$0, (%r12)
EXT(hi64_sysenter_user_arg_copy):
0:
	movl	4(%rcx, %r10, 4), %r11d
	movl	%r11d, (%r8, %r10, 4)
	incl	%r10d
	decl	%r9d
	jnz	0b
	movl	$1, (%r12)
	/* Fall through to 32-bit handler */

L_32bit_enter:
	cld
	/*
	 * Make space for the compatibility save area.
	 */
	sub	$(ISC32_OFFSET), %rsp
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
	mov	ISC32_CS(%rsp), %eax
	mov	%eax, R32_CS(%rsp)
	testb	$3, %al
	jz	1f
	xor	%ebp, %ebp
1:	
	mov	ISC32_RSP(%rsp), %eax
	mov	%eax, R32_UESP(%rsp)
	mov	ISC32_SS(%rsp), %eax
	mov	%eax, R32_SS(%rsp)
L_32bit_enter_after_fault:
	mov	ISC32_TRAPNO(%rsp), %ebx	/* %ebx := trapno for later */
	mov	%ebx, R32_TRAPNO(%rsp)
	mov	ISC32_ERR(%rsp), %eax
	mov	%eax, R32_ERR(%rsp)
	mov	ISC32_TRAPFN(%rsp), %edx

/*
 * Common point to enter lo_handler in compatibilty mode:
 *	%ebx	trapno
 *	%edx	locore handler address 
 */
L_enter_lohandler2:
	/*
	 * Switch address space to kernel
	 * if not shared space and not already mapped.
	 * Note: cpu_task_map is valid only if cpu_task_cr3 is loaded in cr3.
	 */
	mov	%cr3, %rax
	mov	%gs:CPU_TASK_CR3, %rcx
	cmp	%rax, %rcx			/* is the task's cr3 loaded? */
	jne	1f
	cmpl	$(TASK_MAP_64BIT_SHARED), %gs:CPU_TASK_MAP
	je	2f
1:
	mov	%gs:CPU_KERNEL_CR3, %rcx
	cmp	%rax, %rcx
	je	2f
	mov	%rcx, %cr3
	mov	%rcx, %gs:CPU_ACTIVE_CR3
2:
	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* Get the active thread */
	cmpl	$0, TH_PCB_IDS(%ecx)	/* Is there a debug register state? */
	jz	21f
	xor	%ecx, %ecx		/* If so, reset DR7 (the control) */
	mov	%rcx, %dr7
21:	
	/*
	 * Switch to compatibility mode.
	 * Then establish kernel segments.
	 */
	swapgs					/* Done with uber-kernel gs */
	ENTER_COMPAT_MODE()

	/*
	 * Now in compatibility mode and running in compatibility space
	 * prepare to enter the locore handler.
	 * 	%ebx		trapno
	 *	%edx		lo_handler pointer
	 * Note: the stack pointer (now 32-bit) is now directly addressing the
	 * the kernel below 4G and therefore is automagically re-based.
	 */
	mov	$(KERNEL_DS), %eax
	mov	%eax, %ss
	mov	%eax, %ds
	mov	%eax, %es
	mov	%eax, %fs
	mov	$(CPU_DATA_GS), %eax
	mov	%eax, %gs

	incl	%gs:hwIntCnt(,%ebx,4)	/* Bump the trap/intr count */

	/* Dispatch the designated lo handler */
	jmp	*%edx

	.code64
L_64bit_entry_reject:
	/*
	 * Here for a 64-bit user attempting an invalid kernel entry.
	 */
	movl	$(LO_ALLTRAPS), ISF64_TRAPFN(%rsp)
	movl	$(T_INVALID_OPCODE), ISF64_TRAPNO(%rsp)
	/* Fall through... */
	
L_64bit_enter:
	/*
	 * Here for a 64-bit user task, or special 64-bit kernel code.
	 * Make space for the save area.
	 */
	sub	$(ISS64_OFFSET), %rsp
	movl	$(SS_64), SS_FLAVOR(%rsp)

	cld
	/*
	 * Save segment regs
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

L_64bit_enter_after_fault:
	/*
	 * At this point we're almost ready to join the common lo-entry code.
	 */ 
	mov	R64_TRAPNO(%rsp), %ebx
	mov	R64_TRAPFN(%rsp), %edx

	testb	$3, ISF64_CS+ISS64_OFFSET(%rsp)
	jz	1f
	xor	%rbp, %rbp
1:
	jmp	L_enter_lohandler2

Entry(hi64_page_fault)
	push	$(LO_ALLTRAPS)
	push	$(T_PAGE_FAULT)
	cmpl	$(KERNEL_UBER_BASE_HI32), ISF64_RIP+4(%rsp)
	jne	L_enter_lohandler
	cmpl	$(EXT(hi64_sysenter_user_arg_copy)), ISF64_RIP(%rsp)
	jne	hi64_kernel_trap
	mov	ISF64_RSP(%rsp), %rsp
	jmp	L_32bit_enter

/*
 * Debug trap.  Check for single-stepping across system call into
 * kernel.  If this is the case, taking the debug trap has turned
 * off single-stepping - save the flags register with the trace
 * bit set.
 */
Entry(hi64_debug)
	swapgs				/* set %gs for cpu data */
	push	$0			/* error code */
	push	$(LO_ALLTRAPS)
	push	$(T_DEBUG)

	testb	$3, ISF64_CS(%rsp)
	jnz	L_enter_lohandler_continue

	/*
	 * trap came from kernel mode
	 */
	cmpl	$(KERNEL_UBER_BASE_HI32), ISF64_RIP+4(%rsp)
	jne	L_enter_lohandler_continue	/* trap not in uber-space */

	cmpl	$(EXT(hi64_mach_scall)), ISF64_RIP(%rsp)
	jne	6f
	add	$(ISF64_SIZE),%rsp	/* remove entire intr stack frame */
	jmp	L_mach_scall_continue	/* continue system call entry */
6:
	cmpl	$(EXT(hi64_mdep_scall)), ISF64_RIP(%rsp)
	jne	5f
	add	$(ISF64_SIZE),%rsp	/* remove entire intr stack frame */
	jmp	L_mdep_scall_continue	/* continue system call entry */
5:
	cmpl	$(EXT(hi64_unix_scall)), ISF64_RIP(%rsp)
	jne	4f
	add	$(ISF64_SIZE),%rsp	/* remove entire intr stack frame */
	jmp	L_unix_scall_continue	/* continue system call entry */
4:
	cmpl	$(EXT(hi64_sysenter)), ISF64_RIP(%rsp)
	jne	L_enter_lohandler_continue	
	/*
	 * Interrupt stack frame has been pushed on the temporary stack.
	 * We have to switch to pcb stack and copy eflags.
	 */ 
	add	$40,%rsp		/* remove trapno/trapfn/err/rip/cs */
	push	%rcx			/* save %rcx - user stack pointer */
	mov	32(%rsp),%rcx		/* top of intr stack -> pcb stack */
	xchg	%rcx,%rsp		/* switch to pcb stack */
	push	$(USER_DS)		/* ss */
	push	(%rcx)			/* saved %rcx into rsp slot */
	push	8(%rcx)			/* rflags */
	mov	(%rcx),%rcx		/* restore %rcx */
	push	$(SYSENTER_TF_CS)	/* cs - not SYSENTER_CS for iret path */
	jmp	L_sysenter_continue	/* continue sysenter entry */


Entry(hi64_double_fault)
	swapgs				/* set %gs for cpu data */
	push	$(LO_DOUBLE_FAULT)
	push	$(T_DOUBLE_FAULT)

	cmpl	$(KERNEL_UBER_BASE_HI32), ISF64_RIP+4(%rsp)
	jne	L_enter_lohandler_continue	/* trap not in uber-space */

	cmpl	$(EXT(hi64_syscall)), ISF64_RIP(%rsp)
	jne	L_enter_lohandler_continue

	mov	ISF64_RSP(%rsp), %rsp
	jmp	L_syscall_continue
	

/*
 * General protection or segment-not-present fault.
 * Check for a GP/NP fault in the kernel_return
 * sequence; if there, report it as a GP/NP fault on the user's instruction.
 *
 * rsp->     0 ISF64_TRAPNO:	trap code (NP or GP)
 *	     8 ISF64_TRAPFN:	trap function
 *	    16 ISF64_ERR:	segment number in error (error code)
 *	    24 ISF64_RIP:	rip
 *	    32 ISF64_CS:	cs
 *	    40 ISF64_RFLAGS:	rflags 
 *	    48 ISF64_RSP:	rsp
 *	    56 ISF64_SS:	ss
 *	    64 			old registers (trap is from kernel)
 */
Entry(hi64_gen_prot)
	push	$(LO_ALLTRAPS)
	push	$(T_GENERAL_PROTECTION)
	jmp	trap_check_kernel_exit	/* check for kernel exit sequence */

Entry(hi64_stack_fault)
	push	$(LO_ALLTRAPS)
	push	$(T_STACK_FAULT)
	jmp	trap_check_kernel_exit	/* check for kernel exit sequence */

Entry(hi64_segnp)
	push	$(LO_ALLTRAPS)
	push	$(T_SEGMENT_NOT_PRESENT)
					/* indicate fault type */
trap_check_kernel_exit:
	testb	$3,ISF64_CS(%rsp)
	jnz	L_enter_lohandler
					/* trap was from kernel mode, so */
					/* check for the kernel exit sequence */
	cmpl	$(KERNEL_UBER_BASE_HI32), ISF64_RIP+4(%rsp)
	jne	L_enter_lohandler_continue	/* trap not in uber-space */

	cmpl	$(EXT(ret32_iret)), ISF64_RIP(%rsp)
	je	L_fault_iret32
	cmpl	$(EXT(ret32_set_ds)), ISF64_RIP(%rsp)
	je	L_32bit_fault_set_seg
	cmpl	$(EXT(ret32_set_es)), ISF64_RIP(%rsp)
	je	L_32bit_fault_set_seg
	cmpl	$(EXT(ret32_set_fs)), ISF64_RIP(%rsp)
	je	L_32bit_fault_set_seg
	cmpl	$(EXT(ret32_set_gs)), ISF64_RIP(%rsp)
	je	L_32bit_fault_set_seg

	cmpl	$(EXT(ret64_iret)), ISF64_RIP(%rsp)
	je	L_fault_iret64

	cmpl	$(EXT(hi64_sysenter_user_arg_copy)), ISF64_RIP(%rsp)
	cmove	ISF64_RSP(%rsp), %rsp
	je	L_32bit_enter

hi64_kernel_trap:
	/*
	 * Here after taking an unexpected trap from kernel mode - perhaps
	 * while running in the trampolines hereabouts.
	 * Make sure we're not on the PCB stack, if so move to the kernel stack.
	 * This is likely a fatal condition.
	 * But first, try to be sure we have the kernel gs base active...
	 */
	cmpq	$0, %gs:CPU_THIS		/* test gs_base */
	js	1f				/* -ve kernel addr, no swap */
	swapgs					/* +ve user addr, swap */
1:
	movq	%rax, %gs:CPU_UBER_TMP		/* save %rax */
	movq	%gs:CPU_UBER_ISF, %rax		/* PCB stack addr */
	subq	%rsp, %rax
	cmpq	$(PAGE_SIZE), %rax		/* current stack in PCB? */
	movq	%gs:CPU_UBER_TMP, %rax		/* restore %rax */
	ja	L_enter_lohandler_continue	/* stack not in PCB */

	/*
	 *  Here if %rsp is in the PCB
	 *  Copy the interrupt stack frame from PCB stack to kernel stack
	 */
	movq	%gs:CPU_KERNEL_STACK, %rax	/* note: %rax restored below */
	xchgq	%rax, %rsp
	pushq	ISF64_SS(%rax)
	pushq	ISF64_RSP(%rax)
	pushq	ISF64_RFLAGS(%rax)
	pushq	ISF64_CS(%rax)
	pushq	ISF64_RIP(%rax)
	pushq	ISF64_ERR(%rax)
	pushq	ISF64_TRAPFN(%rax)
	pushq	ISF64_TRAPNO(%rax)
	movq	%gs:CPU_UBER_TMP, %rax		/* restore %rax */
	jmp	L_enter_lohandler_continue


/*
 * GP/NP fault on IRET: CS or SS is in error.
 * All registers contain the user's values.
 *
 * on SP is
 *   0 ISF64_TRAPNO:	trap code (NP or GP)
 *   8 ISF64_TRAPFN:	trap function
 *  16 ISF64_ERR:	segment number in error (error code)
 *  24 ISF64_RIP:	rip
 *  32 ISF64_CS:	cs
 *  40 ISF64_RFLAGS:	rflags 
 *  48 ISF64_RSP:	rsp
 *  56 ISF64_SS:	ss  --> new new trapno/trapfn
 *  64			pad --> new errcode
 *  72			user rip
 *  80			user cs
 *  88			user rflags
 *  96			user rsp
 * 104 			user ss	(16-byte aligned)
 */
L_fault_iret32:
	mov	%rax, ISF64_RIP(%rsp)	/* save rax (we don`t need saved rip) */
	mov	ISF64_TRAPNO(%rsp), %rax
	mov	%rax, ISF64_SS(%rsp)	/* put in user trap number */
	mov	ISF64_ERR(%rsp), %rax
	mov	%rax, 8+ISF64_SS(%rsp)	/* put in user errcode */
	mov	ISF64_RIP(%rsp), %rax	/* restore rax */
	add	$(ISF64_SS), %rsp	/* reset to original frame */
					/* now treat as fault from user */
	swapgs
	jmp	L_32bit_enter

L_fault_iret64:
	mov	%rax, ISF64_RIP(%rsp)	/* save rax (we don`t need saved rip) */
	mov	ISF64_TRAPNO(%rsp), %rax
	mov	%rax, ISF64_SS(%rsp)	/* put in user trap number */
	mov	ISF64_ERR(%rsp), %rax
	mov	%rax, 8+ISF64_SS(%rsp)	/* put in user errcode */
	mov	ISF64_RIP(%rsp), %rax	/* restore rax */
	add	$(ISF64_SS), %rsp	/* reset to original frame */
					/* now treat as fault from user */
	swapgs
	jmp	L_64bit_enter

/*
 * Fault restoring a segment register.  All of the saved state is still
 * on the stack untouched since we didn't move the stack pointer.
 */
L_32bit_fault_set_seg:
	mov	ISF64_TRAPNO(%rsp), %rax
	mov	ISF64_ERR(%rsp), %rdx
	mov	ISF64_RSP(%rsp), %rsp	/* reload stack prior to fault */
	mov	%rax,ISC32_TRAPNO(%rsp)
	mov	%rdx,ISC32_ERR(%rsp)
					/* now treat as fault from user */
					/* except that all the state is */
					/* already saved - we just have to */
					/* move the trapno and error into */
					/* the compatibility frame */
	swapgs
	jmp	L_32bit_enter_after_fault


/*
 * Fatal exception handlers:
 */
Entry(db_task_dbl_fault64)
	push	$(LO_DOUBLE_FAULT)
	push	$(T_DOUBLE_FAULT)
	jmp	L_enter_lohandler	

Entry(db_task_stk_fault64)
	push	$(LO_DOUBLE_FAULT)
	push	$(T_STACK_FAULT)
	jmp	L_enter_lohandler	

Entry(mc64)
	push	$(0)			/* Error */
	push	$(LO_MACHINE_CHECK)
	push	$(T_MACHINE_CHECK)
	jmp	L_enter_lohandler	


	.code32

/*
 * All task 'exceptions' enter lo_alltraps:
 *	esp	-> x86_saved_state_t
 * 
 * The rest of the state is set up as:	
 *	cr3	 -> kernel directory
 *	esp	 -> low based stack
 *	gs	 -> CPU_DATA_GS
 *	cs	 -> KERNEL32_CS
 *	ss/ds/es -> KERNEL_DS
 *
 *	interrupts disabled
 *	direction flag cleared
 */
Entry(lo_alltraps)
	movl	R32_CS(%esp),%eax	/* assume 32-bit state */
	cmpl	$(SS_64),SS_FLAVOR(%esp)/* 64-bit? */	
	jne	1f
	movl	R64_CS(%esp),%eax	/* 64-bit user mode */
1:
	testb	$3,%al
	jz	trap_from_kernel
						/* user mode trap */
	TIME_TRAP_UENTRY

	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	TH_TASK(%ecx),%ebx

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%ebx, %ecx)

	movl	%gs:CPU_KERNEL_STACK,%ebx
	xchgl	%ebx,%esp		/* switch to kernel stack */

	CCALL1(user_trap, %ebx)		/* call user trap routine */
	/* user_trap() unmasks interrupts */
	cli				/* hold off intrs - critical section */
	xorl	%ecx,%ecx		/* don't check if we're in the PFZ */
	
/*
 * Return from trap or system call, checking for ASTs.
 * On lowbase PCB stack with intrs disabled
 */	
Entry(return_from_trap)
	movl	%gs:CPU_ACTIVE_THREAD, %esp
	movl	TH_PCB_ISS(%esp),%esp	/* switch back to PCB stack */
	movl	%gs:CPU_PENDING_AST, %eax
	testl	%eax, %eax
	je	return_to_user		/* branch if no AST */
LEXT(return_from_trap_with_ast)
	movl	%gs:CPU_KERNEL_STACK, %ebx
	xchgl	%ebx, %esp		/* switch to kernel stack */

	testl	%ecx, %ecx		/* see if we need to check for an EIP in the PFZ */
	je	2f			/* no, go handle the AST */
	cmpl	$(SS_64), SS_FLAVOR(%ebx)	/* are we a 64-bit task? */
	je	1f
					/* no... 32-bit user mode */
	movl	R32_EIP(%ebx), %eax
	pushl	%ebx			/* save PCB stack */
	xorl	%ebp, %ebp		/* clear frame pointer */
	CCALL1(commpage_is_in_pfz32, %eax)
	popl	%ebx			/* retrieve pointer to PCB stack */
	testl	%eax, %eax
	je	2f			/* not in the PFZ... go service AST */
	movl	%eax, R32_EBX(%ebx)	/* let the PFZ know we've pended an AST */
	xchgl	%ebx, %esp		/* switch back to PCB stack */
	jmp	return_to_user
1:					/* 64-bit user mode */
	movl	R64_RIP(%ebx), %ecx
	movl	R64_RIP+4(%ebx), %eax
	pushl	%ebx			/* save PCB stack */
	xorl	%ebp, %ebp		/* clear frame pointer */
	CCALL2(commpage_is_in_pfz64, %ecx, %eax)
	popl	%ebx			/* retrieve pointer to PCB stack */
	testl	%eax, %eax		
	je	2f			/* not in the PFZ... go service AST */
	movl	%eax, R64_RBX(%ebx)	/* let the PFZ know we've pended an AST */
	xchgl	%ebx, %esp		/* switch back to PCB stack */
	jmp	return_to_user
2:	
	sti				/* interrupts always enabled on return to user mode */
	pushl	%ebx			/* save PCB stack */
	xorl	%ebp, %ebp		/* Clear framepointer */
	CCALL1(i386_astintr, $0)	/* take the AST */
	cli
	
	popl	%esp			/* switch back to PCB stack (w/exc link) */

	xorl	%ecx, %ecx		/* don't check if we're in the PFZ */
	jmp	EXT(return_from_trap)	/* and check again (rare) */



/*
 * Trap from kernel mode.  No need to switch stacks.
 * Interrupts must be off here - we will set them to state at time of trap
 * as soon as it's safe for us to do so and not recurse doing preemption
 */
trap_from_kernel:
	movl	%esp, %eax		/* saved state addr */
	pushl	R32_EIP(%esp)		/* Simulate a CALL from fault point */
	pushl   %ebp			/* Extend framepointer chain */
	movl	%esp, %ebp
	CCALL1WITHSP(kernel_trap, %eax)	/* Call kernel trap handler */
	popl	%ebp
	addl	$4, %esp
	cli

	movl	%gs:CPU_PENDING_AST,%eax		/* get pending asts */
	testl	$ AST_URGENT,%eax	/* any urgent preemption? */
	je	ret_to_kernel			/* no, nothing to do */
	cmpl	$ T_PREEMPT,R32_TRAPNO(%esp)
	je	ret_to_kernel			  /* T_PREEMPT handled in kernel_trap() */
	testl	$ EFL_IF,R32_EFLAGS(%esp)		/* interrupts disabled? */
	je	ret_to_kernel
	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL		/* preemption disabled? */
	jne	ret_to_kernel
	movl	%gs:CPU_KERNEL_STACK,%eax
	movl	%esp,%ecx
	xorl	%eax,%ecx
	and	EXT(kernel_stack_mask),%ecx
	testl	%ecx,%ecx		/* are we on the kernel stack? */
	jne	ret_to_kernel		/* no, skip it */

	CCALL1(i386_astintr, $1)	/* take the AST */


/*
 * All interrupts on all tasks enter here with:
 *	esp->	 -> x86_saved_state_t
 *
 *	cr3	 -> kernel directory
 *	esp	 -> low based stack
 *	gs	 -> CPU_DATA_GS
 *	cs	 -> KERNEL32_CS
 *	ss/ds/es -> KERNEL_DS
 *
 *	interrupts disabled
 *	direction flag cleared
 */
Entry(lo_allintrs)
	/*
	 * test whether already on interrupt stack
	 */
	movl	%gs:CPU_INT_STACK_TOP,%ecx
	cmpl	%esp,%ecx
	jb	1f
	leal	-INTSTACK_SIZE(%ecx),%edx
	cmpl	%esp,%edx
	jb	int_from_intstack
1:	
	xchgl	%ecx,%esp		/* switch to interrupt stack */

	movl	%cr0,%eax		/* get cr0 */
	orl	$(CR0_TS),%eax		/* or in TS bit */
	movl	%eax,%cr0		/* set cr0 */

	subl	$8, %esp		/* for 16-byte stack alignment */
	pushl	%ecx			/* save pointer to old stack */
	movl	%ecx,%gs:CPU_INT_STATE	/* save intr state */
	
	TIME_INT_ENTRY			/* do timing */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx
	movl	TH_TASK(%ecx),%ebx

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%ebx, %ecx)

	incl	%gs:CPU_PREEMPTION_LEVEL
	incl	%gs:CPU_INTERRUPT_LEVEL

	movl	%gs:CPU_INT_STATE, %eax
	CCALL1(interrupt, %eax)		/* call generic interrupt routine */

	cli				/* just in case we returned with intrs enabled */
	xorl	%eax,%eax
	movl	%eax,%gs:CPU_INT_STATE	/* clear intr state pointer */

	decl	%gs:CPU_INTERRUPT_LEVEL
	decl	%gs:CPU_PREEMPTION_LEVEL

	TIME_INT_EXIT			/* do timing */

	movl	%gs:CPU_ACTIVE_THREAD,%eax
	movl	TH_PCB_FPS(%eax),%eax	/* get pcb's ifps */
	testl	%eax, %eax		/* Is there a context */
	je	1f			/* Branch if not */
	cmpl	$0, FP_VALID(%eax)	/* Check fp_valid */
	jne	1f			/* Branch if valid */
	clts				/* Clear TS */
	jmp	2f
1:
	movl	%cr0,%eax		/* get cr0 */
	orl	$(CR0_TS),%eax		/* or in TS bit */
	movl	%eax,%cr0		/* set cr0 */
2:
	popl	%esp			/* switch back to old stack */

	/* Load interrupted code segment into %eax */
	movl	R32_CS(%esp),%eax	/* assume 32-bit state */
	cmpl	$(SS_64),SS_FLAVOR(%esp)/* 64-bit? */	
	jne	3f
	movl	R64_CS(%esp),%eax	/* 64-bit user mode */
3:
	testb	$3,%al			/* user mode, */
	jnz	ast_from_interrupt_user	/* go handle potential ASTs */
	/*
	 * we only want to handle preemption requests if
	 * the interrupt fell in the kernel context
	 * and preemption isn't disabled
	 */
	movl	%gs:CPU_PENDING_AST,%eax	
	testl	$ AST_URGENT,%eax		/* any urgent requests? */
	je	ret_to_kernel			/* no, nothing to do */

	cmpl	$0,%gs:CPU_PREEMPTION_LEVEL	/* preemption disabled? */
	jne	ret_to_kernel			/* yes, skip it */

	movl	%gs:CPU_KERNEL_STACK,%eax
	movl	%esp,%ecx
	xorl	%eax,%ecx
	and	EXT(kernel_stack_mask),%ecx
	testl	%ecx,%ecx			/* are we on the kernel stack? */
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
	incl	%gs:CPU_NESTED_ISTACK

	movl	%esp, %edx		/* x86_saved_state */
	CCALL1(interrupt, %edx)

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
	je	ret_to_user		/* no, nothing to do */

	TIME_TRAP_UENTRY

	movl	$1, %ecx		/* check if we're in the PFZ */
	jmp	EXT(return_from_trap_with_ast)	/* return */


/*
 * 32bit Tasks
 * System call entries via INTR_GATE or sysenter:
 *
 *	esp	 -> x86_saved_state32_t
 *	cr3	 -> kernel directory
 *	esp	 -> low based stack
 *	gs	 -> CPU_DATA_GS
 *	cs	 -> KERNEL32_CS
 *	ss/ds/es -> KERNEL_DS
 *
 *	interrupts disabled
 *	direction flag cleared
 */

Entry(lo_unix_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_KERNEL_STACK,%edi
	xchgl	%edi,%esp			/* switch to kernel stack */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	TH_TASK(%ecx),%ebx		/* point to current task  */
	incl	TH_SYSCALLS_UNIX(%ecx)		/* increment call count   */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%ebx, %ecx)

	sti

	CCALL1(unix_syscall, %edi)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo_mach_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_KERNEL_STACK,%edi
	xchgl	%edi,%esp			/* switch to kernel stack */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	TH_TASK(%ecx),%ebx		/* point to current task  */
	incl	TH_SYSCALLS_MACH(%ecx)		/* increment call count   */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%ebx, %ecx)

	sti

	CCALL1(mach_call_munger, %edi)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo_mdep_scall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_KERNEL_STACK,%edi
	xchgl	%edi,%esp			/* switch to kernel stack */
	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	TH_TASK(%ecx),%ebx		/* point to current task  */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%ebx, %ecx)
	
	sti

	CCALL1(machdep_syscall, %edi)
	/*
	 * always returns through thread_exception_return
	 */

return_to_user:
	TIME_TRAP_UEXIT
	jmp	ret_to_user
	

/*
 * 64bit Tasks
 * System call entries via syscall only:
 *
 *	esp	 -> x86_saved_state64_t
 *	cr3	 -> kernel directory
 *	esp	 -> low based stack
 *	gs	 -> CPU_DATA_GS
 *	cs	 -> KERNEL32_CS
 *	ss/ds/es -> KERNEL_DS
 *
 *	interrupts disabled
 *	direction flag cleared
 */

Entry(lo_syscall)
	TIME_TRAP_UENTRY

	movl	%gs:CPU_KERNEL_STACK,%edi
	xchgl	%edi,%esp			/* switch to kernel stack */

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* get current thread     */
	movl	TH_TASK(%ecx),%ebx		/* point to current task  */

	/* Check for active vtimers in the current task */
	TASK_VTIMER_CHECK(%ebx, %ecx)

	/*
	 * We can be here either for a mach, unix machdep or diag syscall,
	 * as indicated by the syscall class:
	 */
	movl	R64_RAX(%edi), %eax		/* syscall number/class */
	movl	%eax, %edx
	andl	$(SYSCALL_CLASS_MASK), %edx	/* syscall class */
	cmpl	$(SYSCALL_CLASS_MACH<<SYSCALL_CLASS_SHIFT), %edx
	je	EXT(lo64_mach_scall)
	cmpl	$(SYSCALL_CLASS_UNIX<<SYSCALL_CLASS_SHIFT), %edx
	je	EXT(lo64_unix_scall)
	cmpl	$(SYSCALL_CLASS_MDEP<<SYSCALL_CLASS_SHIFT), %edx
	je	EXT(lo64_mdep_scall)
	cmpl	$(SYSCALL_CLASS_DIAG<<SYSCALL_CLASS_SHIFT), %edx
	je	EXT(lo64_diag_scall)

	sti

	/* Syscall class unknown */
	CCALL5(i386_exception, $(EXC_SYSCALL), %eax, $0, $1, $0)
	/* no return */


Entry(lo64_unix_scall)
	incl	TH_SYSCALLS_UNIX(%ecx)		/* increment call count   */
	sti

	CCALL1(unix_syscall64, %edi)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo64_mach_scall)
	incl	TH_SYSCALLS_MACH(%ecx)		/* increment call count   */
	sti

	CCALL1(mach_call_munger64, %edi)
	/*
	 * always returns through thread_exception_return
	 */



Entry(lo64_mdep_scall)
	sti

	CCALL1(machdep_syscall64, %edi)
	/*
	 * always returns through thread_exception_return
	 */


Entry(lo64_diag_scall)
	CCALL1(diagCall64, %edi)	// Call diagnostics
		
	cli				// Disable interruptions just in case
	cmpl	$0,%eax			// What kind of return is this?
	je	1f
	movl	%edi, %esp		// Get back the original stack
	jmp	return_to_user		// Normal return, do not check asts...
1:	
	CCALL5(i386_exception, $EXC_SYSCALL, $0x6000, $0, $1, $0)
		// pass what would be the diag syscall
		// error return - cause an exception
	/* no return */


	
/*
 * Compatibility mode's last gasp...
 */
Entry(lo_df64)
	movl	%esp, %eax
	CCALL1(panic_double_fault64, %eax)
	hlt

Entry(lo_mc64)
	movl	%esp, %eax
	CCALL1(panic_machine_check64, %eax)
	hlt
