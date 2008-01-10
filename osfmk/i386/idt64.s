/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
#include <i386/asm.h>
#include <i386/asm64.h>
#include <assym.s>
#include <mach_kdb.h>
#include <i386/eflags.h>
#include <i386/trap.h>
#define _ARCH_I386_ASM_HELP_H_		/* Prevent inclusion of user header */
#include <mach/i386/syscall_sw.h>
#include <i386/postcode.h>
#include <i386/proc_reg.h>

/*
 * Locore handlers.
 */
#define	LO_ALLINTRS		EXT(lo_allintrs)
#define	LO_ALLTRAPS		EXT(lo_alltraps)
#define	LO_SYSENTER		EXT(lo_sysenter)
#define	LO_SYSCALL		EXT(lo_syscall)
#define	LO_UNIX_SCALL		EXT(lo_unix_scall)
#define	LO_MACH_SCALL		EXT(lo_mach_scall)
#define	LO_MDEP_SCALL		EXT(lo_mdep_scall)
#define	LO_DIAG_SCALL		EXT(lo_diag_scall)
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
	push	$(n)					;\
	movl	$(LO_ALLTRAPS), 4(%rsp)			;\
	jmp	L_enter_lohandler


/*
 * Push error(0), trap number and address of compatibility mode handler,
 * then branch to common trampoline.
 */
#define	EXCEPTION64(n,name)				 \
	IDT64_ENTRY(name,0,K_INTR_GATE)			;\
Entry(name)						;\
	push	$0					;\
	push	$(n)					;\
	movl	$(LO_ALLTRAPS), 4(%rsp)			;\
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
	push	$(n)					;\
	movl	$(LO_ALLTRAPS), 4(%rsp)			;\
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
	push	$(n)					;\
	movl	$(LO_ALLINTRS), 4(%rsp)			;\
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
#if	MACH_KDB
EXCEP64_IST(0x08,db_task_dbl_fault64,1)
#else
EXCEP64_IST(0x08,hi64_double_fault,1)
#endif
EXCEPTION64(0x09,a64_fpu_over)
EXCEPTION64(0x0a,a64_inv_tss)
EXCEP64_SPC(0x0b,hi64_segnp)
#if	MACH_KDB
EXCEP64_IST(0x0c,db_task_stk_fault64,1)
#else
EXCEP64_SPC(0x0c,hi64_stack_fault)
#endif
EXCEP64_SPC(0x0d,hi64_gen_prot)
EXCEP64_ERR(0x0e,t64_page_fault)
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
INTERRUPT64(0x7f)

EXCEP64_SPC_USR(0x80,hi64_unix_scall)
EXCEP64_SPC_USR(0x81,hi64_mach_scall)
EXCEP64_SPC_USR(0x82,hi64_mdep_scall)
EXCEP64_SPC_USR(0x83,hi64_diag_scall)

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
Entry(lo64_ret_to_user)
	movl	%gs:CPU_ACTIVE_THREAD,%ecx

	movl	ACT_PCB_IDS(%ecx),%eax	/* Obtain this thread's debug state */
	cmpl	$0,%eax			/* Is there a debug register context? */
	je	2f 			/* branch if not */
	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP	/* Are we a 64-bit task? */
	jne	1f
	movl	DS_DR0(%eax), %ecx	/* If not, load the 32 bit DRs */
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
	movl	$(WINDOWS_CLEAN),ACT_COPYIO_STATE(%eax)
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

Entry(lo64_ret_to_kernel)
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
	movl	R_EIP(%rsp), %eax
	movl	%eax, ISC32_RIP(%rsp)
	movl	R_EFLAGS(%rsp), %eax
	movl	%eax, ISC32_RFLAGS(%rsp)
	movl	R_CS(%rsp), %eax
	movl	%eax, ISC32_CS(%rsp)
	movl	R_UESP(%rsp), %eax
	movl	%eax, ISC32_RSP(%rsp)
	movl	R_SS(%rsp), %eax
	movl	%eax, ISC32_SS(%rsp)

	/*
	 * Restore general 32-bit registers
	 */
	movl	R_EAX(%rsp), %eax
	movl	R_EBX(%rsp), %ebx
	movl	R_ECX(%rsp), %ecx
	movl	R_EDX(%rsp), %edx
	movl	R_EBP(%rsp), %ebp
	movl	R_ESI(%rsp), %esi
	movl	R_EDI(%rsp), %edi

	/*
	 * Restore segment registers. We make take an exception here but
	 * we've got enough space left in the save frame area to absorb
         * a hardware frame plus the trapfn and trapno
	 */
	swapgs
EXT(ret32_set_ds):	
	movw	R_DS(%rsp), %ds
EXT(ret32_set_es):
	movw	R_ES(%rsp), %es
EXT(ret32_set_fs):
	movw	R_FS(%rsp), %fs
EXT(ret32_set_gs):
	movw	R_GS(%rsp), %gs

	add	$(ISC32_OFFSET)+8+8, %rsp	/* pop compat frame +
						   trapno/trapfn and error */	
        cmp	$(SYSENTER_CS),ISF64_CS-8-8(%rsp)
					/* test for fast entry/exit */
        je      L_fast_exit
EXT(ret32_iret):
        iretq				/* return from interrupt */

L_fast_exit:
	pop	%rdx                    /* user return eip */
        pop	%rcx                    /* pop and toss cs */
	andl	$(~EFL_IF), (%rsp)	/* clear interrupts enable, sti below */
        popf                            /* flags - carry denotes failure */
        pop	%rcx                    /* user return esp */
	.code32
	sti				/* interrupts enabled after sysexit */
        sysexit				/* 32-bit sysexit */
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

	add	$(ISS64_OFFSET)+8+8, %rsp	/* pop saved state frame +
						   trapno/trapfn and error */	
        cmpl	$(SYSCALL_CS),ISF64_CS-8-8(%rsp)
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
	mov	ISF64_RIP-16(%rsp), %rcx
	mov	ISF64_RFLAGS-16(%rsp), %r11
	mov	ISF64_RSP-16(%rsp), %rsp
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
	push	$(UNIX_INT)
	movl	$(LO_UNIX_SCALL), 4(%rsp)
	jmp	L_32bit_enter_check

	
Entry(hi64_mach_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_mach_scall_continue:
	push	%rax			/* save system call number */
	push	$(MACH_INT)
	movl	$(LO_MACH_SCALL), 4(%rsp)
	jmp	L_32bit_enter_check

	
Entry(hi64_mdep_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_mdep_scall_continue:
	push	%rax			/* save system call number */
	push	$(MACHDEP_INT)
	movl	$(LO_MDEP_SCALL), 4(%rsp)
	jmp	L_32bit_enter_check

	
Entry(hi64_diag_scall)
	swapgs				/* switch to kernel gs (cpu_data) */
L_diag_scall_continue:
	push	%rax			/* save system call number */
	push	$(DIAG_INT)
	movl	$(LO_DIAG_SCALL), 4(%rsp)
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
	movl	$(0), ISF64_TRAPNO(%rsp)	/* trapno */
	movl	$(LO_SYSCALL), ISF64_TRAPFN(%rsp)
	jmp	L_64bit_enter		/* this can only be a 64-bit task */
	
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
	* This is cleared by INT, but not by sysenter, which only
	* clears RF, VM and IF.
	*/
	push	$0
	popf
	push	$(SYSENTER_CS)		/* cs */
	swapgs				/* switch to kernel gs (cpu_data) */
L_sysenter_continue:
	push	%rdx			/* eip */
	push	%rax			/* err/eax - syscall code */
	push	$(0)
	movl	$(LO_SYSENTER), ISF64_TRAPFN(%rsp)
	orl	$(EFL_IF), ISF64_RFLAGS(%rsp)

L_32bit_enter_check:
	/*
	 * Check we're not a confused 64-bit user.
	 */
	cmpl	$(TASK_MAP_32BIT), %gs:CPU_TASK_MAP
	jne	L_64bit_entry_reject
	/* fall through to 32-bit handler: */

L_32bit_enter:
	/*
	 * Make space for the compatibility save area.
	 */
	sub	$(ISC32_OFFSET), %rsp
	movl	$(SS_32), SS_FLAVOR(%rsp)

	/*
	 * Save segment regs
	 */
	mov	%ds, R_DS(%rsp)
	mov	%es, R_ES(%rsp)
	mov	%fs, R_FS(%rsp)
	mov	%gs, R_GS(%rsp)

	/*
	 * Save general 32-bit registers
	 */
	mov	%eax, R_EAX(%rsp)
	mov	%ebx, R_EBX(%rsp)
	mov	%ecx, R_ECX(%rsp)
	mov	%edx, R_EDX(%rsp)
	mov	%ebp, R_EBP(%rsp)
	mov	%esi, R_ESI(%rsp)
	mov	%edi, R_EDI(%rsp)

	/* Unconditionally save cr2; only meaningful on page faults */
	mov	%cr2, %rax
	mov	%eax, R_CR2(%rsp)

	/*
	 * Copy registers already saved in the machine state 
	 * (in the interrupt stack frame) into the compat save area.
	 */
	mov	ISC32_RIP(%rsp), %eax
	mov	%eax, R_EIP(%rsp)
	mov	ISC32_RFLAGS(%rsp), %eax
	mov	%eax, R_EFLAGS(%rsp)
	mov	ISC32_CS(%rsp), %eax
	mov	%eax, R_CS(%rsp)
	mov	ISC32_RSP(%rsp), %eax
	mov	%eax, R_UESP(%rsp)
	mov	ISC32_SS(%rsp), %eax
	mov	%eax, R_SS(%rsp)
L_32bit_enter_after_fault:
	mov	ISC32_TRAPNO(%rsp), %ebx	/* %ebx := trapno for later */
	mov	%ebx, R_TRAPNO(%rsp)
	mov	ISC32_ERR(%rsp), %eax
	mov	%eax, R_ERR(%rsp)
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

	movl	%gs:CPU_ACTIVE_THREAD,%ecx	/* Get the active thread */
	cmpl	$0, ACT_PCB_IDS(%ecx)	/* Is there a debug register state? */
	je	1f
	movl	$0, %ecx		/* If so, reset DR7 (the control) */
	movl	%ecx, %dr7
1:
	addl	$1,%gs:hwIntCnt(,%ebx,4)	// Bump the trap/intr count
	
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

	jmp	L_enter_lohandler2

/*
 * Debug trap.  Check for single-stepping across system call into
 * kernel.  If this is the case, taking the debug trap has turned
 * off single-stepping - save the flags register with the trace
 * bit set.
 */
Entry(hi64_debug)
	swapgs				/* set %gs for cpu data */
	push	$0			/* error code */
	push	$(T_DEBUG)
	movl	$(LO_ALLTRAPS), ISF64_TRAPFN(%rsp)

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
	add	$32,%rsp		/* remove trapno/trapfn/err/rip/cs */
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
	push	$(T_DOUBLE_FAULT)
	movl	$(LO_DOUBLE_FAULT), ISF64_TRAPFN(%rsp)

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
 * rsp->     0:	trap code (NP or GP) and trap function
 *	     8:	segment number in error (error code)
 *	    16	rip
 *	    24	cs
 *	    32	rflags 
 *	    40	rsp
 *	    48	ss
 *	    56	old registers (trap is from kernel)
 */
Entry(hi64_gen_prot)
	push	$(T_GENERAL_PROTECTION)
	jmp	trap_check_kernel_exit	/* check for kernel exit sequence */

Entry(hi64_stack_fault)
	push	$(T_STACK_FAULT)
	jmp	trap_check_kernel_exit	/* check for kernel exit sequence */

Entry(hi64_segnp)
	push	$(T_SEGMENT_NOT_PRESENT)
					/* indicate fault type */
trap_check_kernel_exit:
	movl	$(LO_ALLTRAPS), 4(%rsp)
	testb	$3,24(%rsp)
	jnz	hi64_take_trap
					/* trap was from kernel mode, so */
					/* check for the kernel exit sequence */
	cmpl	$(KERNEL_UBER_BASE_HI32), 16+4(%rsp)
	jne	hi64_take_trap		/* trap not in uber-space */

	cmpl	$(EXT(ret32_iret)), 16(%rsp)
	je	L_fault_iret32
	cmpl	$(EXT(ret32_set_ds)), 16(%rsp)
	je	L_32bit_fault_set_seg
	cmpl	$(EXT(ret32_set_es)), 16(%rsp)
	je	L_32bit_fault_set_seg
	cmpl	$(EXT(ret32_set_fs)), 16(%rsp)
	je	L_32bit_fault_set_seg
	cmpl	$(EXT(ret32_set_gs)), 16(%rsp)
	je	L_32bit_fault_set_seg

	cmpl	$(EXT(ret64_iret)), 16(%rsp)
	je	L_fault_iret64

hi64_take_trap:
	jmp	L_enter_lohandler

		
/*
 * GP/NP fault on IRET: CS or SS is in error.
 * All registers contain the user's values.
 *
 * on SP is
 *   0	trap number/function
 *   8	errcode
 *  16	rip
 *  24	cs
 *  32	rflags
 *  40	rsp
 *  48	ss			--> new trapno/trapfn
 *  56  (16-byte padding)	--> new errcode
 *  64	user rip
 *  72	user cs
 *  80	user rflags
 *  88	user rsp
 *  96  user ss
 */
L_fault_iret32:
	mov	%rax, 16(%rsp)		/* save rax (we don`t need saved rip) */
	mov	0(%rsp), %rax		/* get trap number */
	mov	%rax, 48(%rsp)		/* put in user trap number */
	mov	8(%rsp), %rax		/* get error code */
	mov	%rax, 56(%rsp)		/* put in user errcode */
	mov	16(%rsp), %rax		/* restore rax */
	add	$48, %rsp		/* reset to original frame */
					/* now treat as fault from user */
	swapgs
	jmp	L_32bit_enter

L_fault_iret64:
	mov	%rax, 16(%rsp)		/* save rax (we don`t need saved rip) */
	mov	0(%rsp), %rax		/* get trap number */
	mov	%rax, 48(%rsp)		/* put in user trap number */
	mov	8(%rsp), %rax		/* get error code */
	mov	%rax, 56(%rsp)		/* put in user errcode */
	mov	16(%rsp), %rax		/* restore rax */
	add	$48, %rsp		/* reset to original frame */
					/* now treat as fault from user */
	swapgs
	jmp	L_64bit_enter

/*
 * Fault restoring a segment register.  All of the saved state is still
 * on the stack untouched since we didn't move the stack pointer.
 */
L_32bit_fault_set_seg:
	mov	0(%rsp), %rax		/* get trap number/function */
	mov	8(%rsp), %rdx		/* get error code */
	mov	40(%rsp), %rsp		/* reload stack prior to fault */
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
	push	$(T_DOUBLE_FAULT)
	movl	$(LO_DOUBLE_FAULT), ISF64_TRAPFN(%rsp)
	jmp	L_enter_lohandler	

Entry(db_task_stk_fault64)
	push	$(T_STACK_FAULT)
	movl	$(LO_DOUBLE_FAULT), ISF64_TRAPFN(%rsp)
	jmp	L_enter_lohandler	

Entry(mc64)
	push	$(0)			/* Error */
	push	$(T_MACHINE_CHECK)
	movl	$(LO_MACHINE_CHECK), ISF64_TRAPFN(%rsp)
	jmp	L_enter_lohandler	
