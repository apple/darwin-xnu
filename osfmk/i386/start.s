/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <i386/asm.h>
#include <i386/proc_reg.h>
#include <i386/postcode.h>
#include <assym.s>

#define	CX(addr,reg)	addr(,reg,4)

#include <i386/acpi.h>
#include <i386/cpuid.h>

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

/*
 * Pointers to GDT and IDT.  These contain linear addresses.
 */
	.align	ALIGN
	.globl	EXT(gdtptr)
	/* align below properly */
	.word	0 
LEXT(gdtptr)
	.word	Times(8,GDTSZ)-1
	.long	EXT(master_gdt)

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

#if	MACH_KDB
/*
 * Stack for last-ditch debugger task for each processor.
 */
	.align	12
	.globl	EXT(db_task_stack_store)
EXT(db_task_stack_store):
	.space	(INTSTACK_SIZE*MAX_CPUS)

#endif	/* MACH_KDB */


/*
 * BSP CPU start here.
 *	eax points to kernbootstruct
 *
 * Environment:
 *	protected mode, no paging, flat 32-bit address space.
 *	(Code/data/stack segments have base == 0, limit == 4G)
 */
	.text
	.align	ALIGN
	.globl	EXT(_start)
LEXT(_start)
	mov		%ds, %bx
	mov		%bx, %es
	mov		%eax, %ebp		/* Move kernbootstruct to ebp */
	mov		%eax, %ebx		/* get pointer to kernbootstruct */

	mov	$EXT(low_eintstack),%esp			/* switch to the bootup stack */

	POSTCODE(PSTART_ENTRY)

	lgdt	EXT(gdtptr)					/* load GDT */

	mov	$(KERNEL_DS),%ax				/* set kernel data segment */
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %ss
	xor	%ax, %ax						/* fs must be zeroed; */
	mov	%ax, %fs						/* some bootstrappers don`t do this */
	mov	%ax, %gs
	cld

	/* "The Aussie Maneuver" ("Myria" variant) */
	pushl $(0xcb<<24)|KERNEL32_CS		/* reload CS  */
	call .-1

paging:
	andl	$0xfffffff0, %esp				/* align stack */
	subl	$0xc, %esp
	pushl	%ebp						/* push boot args addr */
	xorl	%ebp, %ebp					/* zero frame pointer */
	
	POSTCODE(PSTART_BEFORE_PAGING)

/*
 * Turn on paging.
 */
	movl	$EXT(IdlePDPT), %eax		/* CR3 */
	movl	%eax, %cr3
	movl	%cr4, %eax					/* PAE */
	orl	$(CR4_PAE), %eax
	movl	%eax, %cr4
	movl	%cr0,%eax					/* paging */
	orl	$(CR0_PG|CR0_WP),%eax
	movl	%eax,%cr0
	
	call	EXT(vstart)					/* run C code */
	/*NOTREACHED*/
	hlt

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
	cli				/* disable interrupts, so we don`t */
					/* need IDT for a while */
	xor %ebp, %ebp	// zero boot cpu
	mov $EXT(mp_slave_stack)+PAGE_SIZE, %esp;
	jmp paging


/* Code to get from real mode to protected mode */

#define	operand_size_prefix	.byte 0x66
#define	address_size_prefix	.byte 0x67
#define	cs_base_prefix		.byte 0x2e

#undef LJMP
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

.section __HIB,__text
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
	mov		$0, %ax
	movw	%ax, %fs
	movw	%ax, %gs

	POSTCODE(SLAVE_STARTPROG_ENTRY);

	mov	PROT_MODE_START+REAL_MODE_BOOTSTRAP_OFFSET, %ecx
	jmp 	*%ecx

Entry(protected_mode_gdtr)
	.short	160		/* limit (8*6 segs) */
	.long	EXT(master_gdt)

Entry(real_mode_bootstrap_end)

.section __HIB,__text
	.align	ALIGN
	.globl	EXT(hibernate_machine_entrypoint)
LEXT(hibernate_machine_entrypoint)
	mov 	%eax, %edi // save header pointer
	/* restore gdt */
	lgdt	EXT(protected_mode_gdtr)

	/* setup the protected mode segment registers */
	mov		$KERNEL_DS, %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	mov		$0,%ax			/* fs must be zeroed; */
	mov		%ax,%fs
	mov		%ax,%gs

	/* set up the page tables to use BootstrapPTD 
	 * as done in idle_pt.c, but this must be done programatically */
	mov $EXT(IdlePDPT), %eax
	mov $EXT(BootstrapPTD) + (INTEL_PTE_VALID), %ecx
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
	mov %eax, %cr3


	movl	%cr4,%eax
	orl		$(CR4_PAE),%eax
	movl	%eax,%cr4               /* enable page size extensions */

	movl	$(MSR_IA32_EFER), %ecx			/* MSR number in ecx */
	rdmsr						/* MSR value return in edx: eax */
	orl	$(MSR_IA32_EFER_NXE), %eax		/* Set NXE bit in low 32-bits */
	wrmsr						/* Update Extended Feature Enable reg */

	movl	%cr0, %eax
	orl	$(CR0_PG|CR0_WP), %eax
	movl	%eax, %cr0	/* ready paging */

	mov $EXT(gIOHibernateRestoreStackEnd), %esp	/* setup stack */
	xorl	%ebp, %ebp				/* zero frame pointer */

	ljmpl	$(KERNEL32_CS), $Ltemp
Ltemp:
	xorl	%eax, %eax              /* Video memory - N/A */
	pushl	%eax
	pushl	%eax
	pushl	%eax
	mov		%edi, %eax              /* Pointer to hibernate header */
	pushl	%eax
	call	EXT(hibernate_kernel_entrypoint)
	/* NOTREACHED */
	hlt
