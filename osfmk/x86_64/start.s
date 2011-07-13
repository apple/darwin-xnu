/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#include <platforms.h>
#include <mach_kdb.h>

#include <i386/asm.h>
#include <i386/proc_reg.h>
#include <i386/postcode.h>
#include <assym.s>

#include <i386/mp.h>
#include <i386/cpuid.h>
#include <i386/acpi.h>

.code32


/*
 * Interrupt and bootup stack for initial processor.
 */

	/* in the __HIB section since the hibernate restore code uses this stack. */
	.section __HIB, __data
	.align	12

	.globl	EXT(low_intstack)
EXT(low_intstack):
	.globl  EXT(gIOHibernateRestoreStack)
EXT(gIOHibernateRestoreStack):

	.space	INTSTACK_SIZE

	.globl	EXT(low_eintstack)
EXT(low_eintstack:)
	.globl  EXT(gIOHibernateRestoreStackEnd)
EXT(gIOHibernateRestoreStackEnd):

	/* back to the regular __DATA section. */

	.section __DATA, __data

/*
 * Stack for last-gasp double-fault handler.
 */
	.align	12
	.globl	EXT(df_task_stack)
EXT(df_task_stack):
	.space	INTSTACK_SIZE
	.globl	EXT(df_task_stack_end)
EXT(df_task_stack_end):


/*
 * Stack for machine-check handler.
 */
	.align	12
	.globl	EXT(mc_task_stack)
EXT(mc_task_stack):
	.space	INTSTACK_SIZE
	.globl	EXT(mc_task_stack_end)
EXT(mc_task_stack_end):

/*
 * BSP CPU start here.
 *	eax points to kernbootstruct
 *
 * Environment:
 *	protected mode, no paging, flat 32-bit address space.
 *	(Code/data/stack segments have base == 0, limit == 4G)
 */

#define SWITCH_TO_64BIT_MODE \
	movl	$(CR4_PAE),%eax		/* enable PAE */		;\
	movl	%eax,%cr4									;\
	movl    $MSR_IA32_EFER,%ecx							;\
	rdmsr												;\
	orl	$MSR_IA32_EFER_LME,%eax	/* enable long mode */	;\
	wrmsr												;\
	movl	$INITPT_SEG_BASE,%eax						;\
	movl	%eax,%cr3									;\
	movl	%cr0,%eax									;\
	orl	$(CR0_PG|CR0_WP),%eax	/* enable paging */		;\
	movl	%eax,%cr0									;\
	/* "The Aussie Maneuver" ("Myria" variant) */ 		;\
	pushl $(0xcb<<24)|KERNEL64_CS /* reload CS with 0x08 */ ;\
	call .-1											;\
	.code64

/*
 * [ We used to have a reason for the following statement; ]
 * [ but the issue has been fixed. The line is true        ]
 * [ nevertheless, therefore it should remain there.       ]
 * This proves that Little Endian is superior to Big Endian.
 */
	
	.text
	.align	ALIGN
	.globl	EXT(_start)
	.globl	EXT(_pstart)
LEXT(_start)
LEXT(_pstart)

	.code32

#if 0
	mov $0x3f8, %dx
	mov $0x4D, %al; out %al, %dx
	mov $0x49, %al; out %al, %dx
	mov $0x53, %al; out %al, %dx
	mov $0x54, %al; out %al, %dx
	mov $0x0D, %al; out %al, %dx
	mov $0x0A, %al; out %al, %dx
#endif
	
/*
 * Here we do the minimal setup to switch from 32 bit mode to 64 bit long mode.
 *
 * Initial memory layout:
 *
 *	-------------------------
 *	|			|
 *	| Kernel text/data	|
 *	|			|
 *	------------------------- Kernel start addr
 *	|			|
 *	|			|
 *	------------------------- 0
 *
 */	
	mov	%eax, %edi	/* save kernbootstruct */

	/* Use low 32-bits of address as 32-bit stack */
	movl $EXT(low_eintstack), %esp
	
	/*
	 * Set up segmentation
	 */
	movl	$EXT(protected_mode_gdtr), %eax
	lgdtl	(%eax)

/* the following code is shared by the master CPU and all slave CPUs */
L_pstart_common:
	/*
	 * switch to 64 bit mode
	 */
	SWITCH_TO_64BIT_MODE

	/* Flush data segment selectors */
	xor	%eax, %eax
	mov	%ax, %ss
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %fs
	mov	%ax, %gs

	/* %edi = boot_args_start */
	
	leaq _vstart(%rip), %rcx
	movq $0xffffff8000000000, %rax	/* adjust the pointer to be up high */
	or %rax, %rsp			/* and stack pointer up there too */
	or %rcx, %rax
	andq $0xfffffffffffffff0, %rsp	/* align stack */
	xorq %rbp, %rbp			/* zero frame pointer */
	callq *%rax

/*
 * AP (slave) CPUs enter here.
 *
 * Environment:
 *	protected mode, no paging, flat 32-bit address space.
 *	(Code/data/stack segments have base == 0, limit == 4G)
 */
	.align	ALIGN
	.globl	EXT(slave_pstart)
LEXT(slave_pstart)
	.code32
	cli				/* disable interrupts, so we don`t */
					/* need IDT for a while */
	POSTCODE(SLAVE_PSTART_ENTRY)

	movl	$EXT(mp_slave_stack) + PAGE_SIZE, %esp

	/* set up identity mapping of page tables */
	movl	$INITPT_SEG_BASE,%eax
	movl	(KERNEL_PML4_INDEX*8)(%eax), %esi
	movl	%esi, (0)(%eax)
	movl	(KERNEL_PML4_INDEX*8+4)(%eax), %esi
	movl	%esi, (0+4)(%eax)

	movl	$0, %edi		/* "no kernbootstruct" */

	jmp	L_pstart_common		/* hop a ride to vstart() */


/* BEGIN HIBERNATE CODE */

.section __HIB, __text
/*
This code is linked into the kernel but part of the "__HIB" section, which means
its used by code running in the special context of restoring the kernel text and data
from the hibernation image read by the booter. hibernate_kernel_entrypoint() and everything
it calls or references (ie. hibernate_restore_phys_page())
needs to be careful to only touch memory also in the "__HIB" section.
*/


	.align	ALIGN
	.globl	EXT(hibernate_machine_entrypoint)
.code32
LEXT(hibernate_machine_entrypoint)
	movl    %eax, %edi /* regparm(1) calling convention */

	/* restore gdt */
	mov 	$(SLEEP_SEG_BASE)+20, %eax // load saved_gdt, this may break
	lgdtl	(%eax)

	/* setup the protected mode segment registers */
	mov		$KERNEL_DS, %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	xor		%eax,%eax
	movw	%ax, %fs
	movw	%ax, %gs

	/* set up the page tables to use BootstrapPTD 
	 * as done in idle_pt.c, but this must be done programatically */
	mov $(INITPT_SEG_BASE + PAGE_SIZE), %eax
	mov $(INITPT_SEG_BASE + 2*PAGE_SIZE | INTEL_PTE_WRITE | INTEL_PTE_VALID), %ecx
	mov $0x0, %edx
	mov	%ecx, (0*8+0)(%eax)
	mov %edx, (0*8+4)(%eax)
	add	$(PAGE_SIZE), %ecx
	mov %ecx, (1*8+0)(%eax)
	mov %edx, (1*8+4)(%eax)
	add	$(PAGE_SIZE), %ecx
	mov %ecx, (2*8+0)(%eax)
	mov %edx, (2*8+4)(%eax)
	add	$(PAGE_SIZE), %ecx
	mov %ecx, (3*8+0)(%eax)
	mov %edx, (3*8+4)(%eax)

	/* Temporary stack */
	mov	$(REAL_MODE_BOOTSTRAP_OFFSET + PROT_MODE_START), %esp

	SWITCH_TO_64BIT_MODE

	leaq EXT(hibernate_kernel_entrypoint)(%rip),%rcx
	leaq EXT(gIOHibernateRestoreStackEnd)(%rip),%rsp	/* switch to the bootup stack */
	movq $0xffffff8000000000, %rax	/* adjust the pointer to be up high */
	orq %rax, %rsp			/* and stack pointer up there too :D */
	orq %rcx, %rax			/* put entrypoint in %rax */
	/* %edi is already filled with header pointer */
	xorl %esi, %esi /* zero 2nd arg */
	xorl %edx, %edx /* zero 3rd arg */
	xorl %ecx, %ecx /* zero 4th arg */
	andq $0xfffffffffffffff0, %rsp	/* align stack */
					/* (future-proofing, stack should already be aligned) */
	xorq %rbp, %rbp			/* zero frame pointer */
	call *%rax /* call instead of jmp to keep the required stack alignment */
	/* NOTREACHED */
	hlt

/* END HIBERNATE CODE */

#if CONFIG_SLEEP
/* BEGIN ACPI WAKEUP CODE */

#include <i386/acpi.h>




#define	PA(addr)	(addr)

/*
 * acpi_wake_start
 *
 * The code from acpi_wake_start to acpi_wake_end is copied to
 * memory below 1MB.  The firmware waking vector is updated to
 * point at acpi_wake_start in low memory before sleeping.
 */

.section __TEXT,__text
.text
.align	12	/* Page align for single bcopy_phys() */
.code32
.globl EXT(acpi_wake_prot)
EXT(acpi_wake_prot):
	/* protected mode, paging disabled */

	/* jump to acpi_temp_alloc (stored in saved_tmp) */
	mov $(SLEEP_SEG_BASE)+16, %eax 
	mov (%eax), %ecx // Load acpi_temp_reloc from saved_eip
	jmp	*%ecx
acpi_temp_reloc:
	mov $(SLEEP_SEG_BASE)+16, %esp  /* setup stack for 64bit */

	SWITCH_TO_64BIT_MODE

	lea Lwake_64(%rip), %rax
	movq $0xffffff8000000000, %rdx
	orq	%rdx, %rax
	jmp *%rax
.code32

.code64

/*
 * acpi_sleep_cpu(acpi_sleep_callback func, void * refcon)
 *
 * Save CPU state before platform sleep. Restore CPU state
 * following wake up.
 */

ENTRY(acpi_sleep_cpu)
	push	%rbp
	mov	%rsp, %rbp

	/* save flags */
	pushf

	/* save general purpose registers */
	push %rax
	push %rbx
	push %rcx
	push %rdx
	push %rbp
	push %rsi
	push %rdi
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15

	mov	%rsp, saved_rsp(%rip)

	/* make sure tlb is flushed */
	mov	%cr3,%rax
	mov	%rax,%cr3
	
	/* save control registers */
	mov	%cr0, %rax
	mov	%rax, saved_cr0(%rip)
	mov	%cr2, %rax
	mov	%rax, saved_cr2(%rip)
	mov	%cr4, %rax
	mov	%rax, saved_cr4(%rip)

	/* save segment registers */
	movw	%es, saved_es(%rip)
	movw	%fs, saved_fs(%rip)
	movw	%gs, saved_gs(%rip)
	movw	%ss, saved_ss(%rip)	

	/* save the 64bit user and kernel gs base */
	/* note: user's curently swapped into kernel base MSR */
	mov	$MSR_IA32_KERNEL_GS_BASE, %rcx
	rdmsr
	movl	%eax, saved_ugs_base(%rip)
	movl	%edx, saved_ugs_base+4(%rip)
	swapgs
	rdmsr
	movl	%eax, saved_kgs_base(%rip)
	movl	%edx, saved_kgs_base+4(%rip)
	swapgs

	/* save descriptor table registers */
	sgdt	saved_gdt(%rip)
	sldt	saved_ldt(%rip)
	sidt	saved_idt(%rip)
	str	saved_tr(%rip)

	/*
	 * When system wakes up, the real mode wake handler will revert to
	 * protected mode, then jump to the address stored at saved_eip.
	 */
	leaq	acpi_temp_reloc(%rip), %rax
	mov		%eax, saved_eip(%rip)

	/*
	 * Call ACPI function provided by the caller to sleep the platform.
	 * This call will not return on success.
	 */

	xchgq %rdi, %rsi
	call	*%rsi

	/* sleep failed, no cpu context lost */
	jmp	wake_restore

.globl EXT(acpi_wake_prot_entry)
EXT(acpi_wake_prot_entry):
	POSTCODE(ACPI_WAKE_PROT_ENTRY)
	/* Entry from the hibernate code in iokit/Kernel/IOHibernateRestoreKernel.c
	 *
	 * Reset the first 4 PDE's to point to entries in IdlePTD, as done in
	 * Idle_PTs_init() during startup */
	leaq	_IdlePDPT(%rip), %rax
	movq	_IdlePTD(%rip), %rcx
	mov		%ecx, %ecx /* zero top 32bits of %rcx */
	orq		$(INTEL_PTE_WRITE|INTEL_PTE_VALID), %rcx
	movq	%rcx, 0x0(%rax)
	add		$0x1000, %rcx
	movq	%rcx, 0x8(%rax)
	add		$0x1000, %rcx
	movq	%rcx, 0x10(%rax)
	add		$0x1000, %rcx
	movq	%rcx, 0x18(%rax)
	mov 	%cr3, %rax
	mov 	%rax, %cr3
	
Lwake_64:
	/*
	 * restore cr4, PAE and NXE states in an orderly fashion
	 */
	mov		saved_cr4(%rip), %rcx
	mov		%rcx, %cr4

	mov		$(MSR_IA32_EFER), %ecx			/* MSR number in ecx */
	rdmsr						/* MSR value return in edx: eax */
	or		$(MSR_IA32_EFER_NXE), %eax		/* Set NXE bit in low 32-bits */
	wrmsr						/* Update Extended Feature Enable reg */

	/* restore kernel GDT */
	lgdt	EXT(protected_mode_gdtr)(%rip)

	movq	saved_cr2(%rip), %rax
	mov		%rax, %cr2

	/* restore CR0, paging enabled */
	mov		saved_cr0(%rip), %rax
	mov		%rax, %cr0

	/* protected mode, paging enabled */
	POSTCODE(ACPI_WAKE_PAGED_ENTRY)

	/* load null segment selectors */
	xor	%eax, %eax
	movw	%ax, %ss
	movw	%ax, %ds

	/* restore local and interrupt descriptor tables */
	lldt	saved_ldt(%rip)
	lidt	saved_idt(%rip)

	/* restore segment registers */
	movw	saved_es(%rip), %es
	movw	saved_fs(%rip), %fs
	movw	saved_gs(%rip), %gs
	movw	saved_ss(%rip), %ss

	/* restore the 64bit kernel and user gs base */
	mov	$MSR_IA32_KERNEL_GS_BASE, %rcx
	movl	saved_kgs_base(%rip),   %eax 
	movl	saved_kgs_base+4(%rip), %edx 
	wrmsr
	swapgs
	movl	saved_ugs_base(%rip),   %eax 
	movl	saved_ugs_base+4(%rip), %edx 
	wrmsr

	/*
	 * Restore task register. Before doing this, clear the busy flag
	 * in the TSS descriptor set by the CPU.
	 */
	lea	saved_gdt(%rip), %rax
	movq	2(%rax), %rdx			/* GDT base, skip limit word */
	movl	$(KERNEL_TSS), %eax		/* TSS segment selector */
	movb	$(K_TSS), 5(%rdx, %rax)		/* clear busy flag */

	ltr	saved_tr(%rip)			/* restore TR */

wake_restore:
	mov	saved_rsp(%rip), %rsp 

	/* restore general purpose registers */
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rdi
	pop %rsi
	pop %rbp
	pop %rdx
	pop %rcx
	pop %rbx
	pop %rax

	/* restore flags */
	popf

	leave
	ret

/* END ACPI WAKEUP CODE */
#endif /* CONFIG_SLEEP */

/* Code to get from real mode to protected mode */

#define	operand_size_prefix	.byte 0x66
#define	address_size_prefix	.byte 0x67
#define	cs_base_prefix		.byte 0x2e

#define	LJMP(segment,address)			\
	operand_size_prefix			;\
	.byte	0xea				;\
	.long	address-EXT(real_mode_bootstrap_base)	;\
	.word	segment

#define	LGDT(address)				\
	cs_base_prefix				;\
	address_size_prefix			;\
	operand_size_prefix			;\
	.word	0x010f				;\
	.byte	0x15				;\
	.long	address-EXT(real_mode_bootstrap_base)

.section __TEXT,__text
.align	12	/* Page align for single bcopy_phys() */
.code32
Entry(real_mode_bootstrap_base)
	cli

	LGDT(EXT(protected_mode_gdtr))

	/* set the PE bit of CR0 */
	mov	%cr0, %eax
	inc %eax
	mov	%eax, %cr0 

	/* reload CS register */
	LJMP(KERNEL32_CS, 1f + REAL_MODE_BOOTSTRAP_OFFSET)
1:
	
	/* we are in protected mode now */
	/* set up the segment registers */
	mov	$KERNEL_DS, %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	xor		%eax,%eax
	movw	%ax, %fs
	movw	%ax, %gs

	POSTCODE(SLAVE_STARTPROG_ENTRY);

	mov	PROT_MODE_START+REAL_MODE_BOOTSTRAP_OFFSET, %ecx
	jmp 	*%ecx

Entry(protected_mode_gdtr)
	.short	160		/* limit (8*6 segs) */
	.quad	EXT(master_gdt)

Entry(real_mode_bootstrap_end)

/* Save area used across sleep/wake */
.section __SLEEP, __data
.align	2

temp_stack: .quad 0
			.quad 0
saved_eip:	.long 0
saved_gdt:	.word 0
			.quad 0
saved_rsp:	.quad 0
saved_es:	.word 0
saved_fs:	.word 0
saved_gs:	.word 0
saved_ss:	.word 0
saved_cr0:	.quad 0
saved_cr2:	.quad 0
saved_cr4:	.quad 0
saved_idt:	.word 0
		.quad 0
saved_ldt:	.word 0
saved_tr:	.word 0
saved_kgs_base:	.quad 0
saved_ugs_base:	.quad 0

