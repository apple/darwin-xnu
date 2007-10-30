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

#include <i386/asm.h>
#include <i386/proc_reg.h>
#include <i386/postcode.h>
#include <i386/acpi.h>
#include <assym.s>

	.file "acpi_wakeup.s"

	.text
	.align	12	/* Page align for single bcopy_phys() */

#define LJMP(segment, address)			 \
	.byte	0xea				;\
	.long	address - EXT(acpi_wake_start)	;\
	.word	segment

#define	PA(addr)	((addr)-KERNELBASE)

/*
 * acpi_wake_start
 *
 * The code from acpi_wake_start to acpi_wake_end is copied to
 * memory below 1MB.  The firmware waking vector is updated to
 * point at acpi_wake_start in low memory before sleeping.
 */

ENTRY(acpi_wake_start)
	/*
	 * CPU woke up from sleep, and is back in real mode.
	 * Initialize it just enough to get back to protected mode.
	 */
	cli

	POSTCODE(ACPI_WAKE_START_ENTRY)

	/* set up DS to match CS */
	movw	%cs, %ax
	movw	%ax, %ds

	/*
	 * Must initialize GDTR before entering protected mode.
	 * Use a temporary GDT that is 0 based, 4GB limit, code and data.
	 * Restoring the actual GDT will come later.
	 */
	addr16
	data16
	lgdt	EXT(acpi_gdtr) - EXT(acpi_wake_start)

	/* set CR0.PE to enter protected mode */
	mov	%cr0, %eax
	data16
	or	$(CR0_PE), %eax
	mov	%eax, %cr0

	/*
	 * Make intra-segment jump to flush pipeline and reload CS register.
	 * If GDT is bogus, it will blow up here.
	 */
	data16
	LJMP(0x8, acpi_wake_prot + ACPI_WAKE_ADDR)

acpi_wake_prot:

	/* protected mode, paging disabled */

	/* setup the protected mode segment registers */
	mov	$0x10, %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	movw	%ax, %fs
	movw	%ax, %gs

	/* jump back to the sleep function in the kernel */
	movl	PA(saved_eip), %eax
	jmp	*%eax

/*  Segment Descriptor
 *
 * 31          24         19   16                 7           0
 * ------------------------------------------------------------
 * |             | |B| |A|       | |   |1|0|E|W|A|            |
 * | BASE 31..24 |G|/|0|V| LIMIT |P|DPL|  TYPE   | BASE 23:16 |
 * |             | |D| |L| 19..16| |   |1|1|C|R|A|            |
 * ------------------------------------------------------------
 * |                             |                            |
 * |        BASE 15..0           |       LIMIT 15..0          |
 * |                             |                            |
 * ------------------------------------------------------------
 */
ENTRY(acpi_gdt)
	.word	0, 0		/* 0x0  : null */
	.byte	0, 0, 0, 0

	.word	0xffff, 0x0000	/* 0x8  : code */
	.byte	0, 0x9e, 0xcf, 0

	.word	0xffff, 0x0000	/* 0x10 : data */
	.byte	0, 0x92, 0xcf, 0

ENTRY(acpi_gdtr)
	.word	24		/* limit (8*3 segs) */
	.long	EXT(acpi_gdt) - EXT(acpi_wake_start) + ACPI_WAKE_ADDR

ENTRY(acpi_wake_end)


/*
 * acpi_sleep_cpu(acpi_sleep_callback func, void * refcon)
 *
 * Save CPU state before platform sleep. Restore CPU state
 * following wake up.
 */

ENTRY(acpi_sleep_cpu)
	pushl	%ebp
	movl	%esp, %ebp

	/* save flags */
	pushfl

	/* save general purpose registers */
	pushal
	movl	%esp, saved_esp

	/* save control registers */
	movl	%cr0, %eax
	movl	%eax, saved_cr0
	movl	%cr2, %eax
	movl	%eax, saved_cr2
	movl	%cr3, %eax
	movl	%eax, saved_cr3
	movl	%cr4, %eax
	movl	%eax, saved_cr4

	/* save segment registers */
	movw	%es, saved_es
	movw	%fs, saved_fs
	movw	%gs, saved_gs
	movw	%ss, saved_ss

	/* save descriptor table registers */
	sgdt	saved_gdt
	sldt	saved_ldt
	sidt	saved_idt
	str	saved_tr

	/*
	 * When system wakes up, the real mode wake handler will revert to
	 * protected mode, then jump to the address stored at saved_eip.
	 */
	movl	$(PA(wake_prot)), saved_eip

	/*
	 * Call ACPI function provided by the caller to sleep the platform.
	 * This call will not return on success.
	 */
	pushl	B_ARG1
	movl	B_ARG0, %edi
	call	*%edi
	popl	%edi

	/* sleep failed, no cpu context lost */
	jmp	wake_restore

wake_prot:

	/* protected mode, paging disabled */
	POSTCODE(ACPI_WAKE_PROT_ENTRY)

	/* restore kernel GDT */
	lgdt	PA(saved_gdt)

	/* restore control registers */
	movl	PA(saved_cr2), %eax
	movl	%eax, %cr2
	
#ifdef PAE
	movl	PA(EXT(IdlePDPT)), %eax
	movl	(%eax), %esi		/* save orig */
	movl	24(%eax), %ebx
	movl	%ebx, (%eax)	/* identity map low mem */
	movl	%eax, %cr3

	movl	PA(saved_cr4), %eax
	movl	%eax, %cr4
#else
	movl	PA(saved_cr4), %eax
	movl	%eax, %cr4

	/*
	 * Temporarily use the page tables at IdlePTD
	 * to enable paging.  Copy the KPTDI entry to
	 * entry 0 in the PTD to identity map the kernel.
	 */
	movl	PA(EXT(IdlePTD)), %eax
	movl	%eax, %ebx
	addl	$(KPTDI << PTEINDX), %ebx  /* bytes per PDE */
	movl	(%ebx), %ebx		/* IdlePTD[KPTDI]  */
	movl	(%eax), %esi		/* save original IdlePTD[0] */
	movl	%ebx, (%eax)		/* update IdlePTD[0] */   
	movl	%eax, %cr3		/* CR3 = IdlePTD */
#endif

	/* restore CR0, paging enabled */
	movl	PA(saved_cr0), %eax
	movl	%eax, %cr0

	/* switch to kernel code segment */
	ljmpl	$(KERNEL_CS), $wake_paged

wake_paged:

	/* protected mode, paging enabled */
	POSTCODE(ACPI_WAKE_PAGED_ENTRY)

	/* switch to kernel data segment */
	movw	$(KERNEL_DS), %ax
	movw	%ax, %ds

	/* undo changes to IdlePTD */
#ifdef PAE
	movl	EXT(IdlePDPT), %eax
#else	
	movl	EXT(IdlePTD), %eax
#endif
	addl	$(KERNELBASE), %eax	/* make virtual */
	movl	%esi, (%eax)

	/* restore real PDE base */
	movl	saved_cr3, %eax
	movl	%eax, %cr3


	/* restore local and interrupt descriptor tables */
	lldt	saved_ldt
	lidt	saved_idt

	/* restore segment registers */
	movw	saved_es, %es
	movw	saved_fs, %fs
	movw	saved_gs, %gs
	movw	saved_ss, %ss

	/*
	 * Restore task register. Before doing this, clear the busy flag
	 * in the TSS descriptor set by the CPU.
	 */
	movl	$saved_gdt, %eax
	movl	2(%eax), %edx			/* GDT base, skip limit word */
	movl	$(KERNEL_TSS), %eax		/* TSS segment selector */
	movb	$(K_TSS), 5(%edx, %eax)		/* clear busy flag */
	ltr	saved_tr			/* restore TR */

wake_restore:

	/* restore general purpose registers */
	movl	saved_esp, %esp
	popal

	/* restore flags */
	popfl

	leave
	ret


        .section __HIB, __text
	.align 2
        
        .globl EXT(acpi_wake_prot_entry)
ENTRY(acpi_wake_prot_entry)
	/* protected mode, paging enabled */
	POSTCODE(ACPI_WAKE_PAGED_ENTRY)

	/* restore kernel GDT */
	lgdt	PA(saved_gdt)
	
	POSTCODE(0x40)
	/* restore control registers */
	movl	saved_cr2, %eax
	movl	%eax, %cr2

        POSTCODE(0x3E)
	/* switch to kernel data segment */
	movw	$(KERNEL_DS), %ax
	movw	%ax, %ds

        POSTCODE(0x3D)
	/* restore real PDE base */
	movl	saved_cr3, %eax
	movl	saved_cr4, %edx
	movl	%eax, %cr3
	movl	%edx, %cr4

        POSTCODE(0x3C)
	/* restore local and interrupt descriptor tables */
	lldt	saved_ldt
	lidt	saved_idt

        POSTCODE(0x3B)
	/* restore segment registers */
	movw	saved_es, %es
	movw	saved_fs, %fs
	movw	saved_gs, %gs
	movw	saved_ss, %ss

        POSTCODE(0x3A)
	/*
	 * Restore task register. Before doing this, clear the busy flag
	 * in the TSS descriptor set by the CPU.
	 */
	movl	$saved_gdt, %eax
	movl	2(%eax), %edx			/* GDT base, skip limit word */
	movl	$(KERNEL_TSS), %eax		/* TSS segment selector */
	movb	$(K_TSS), 5(%edx, %eax)		/* clear busy flag */
	ltr	saved_tr			/* restore TR */

	/* restore general purpose registers */
	movl	saved_esp, %esp
	popal

	/* restore flags */
	popfl

        /* make sure interrupts are disabled */
        cli
        
        movl   $2, %eax

        leave
	ret

        
	.data
        .section __HIB, __data
	.align	2


/*
 * CPU registers saved across sleep/wake.
 */
saved_esp:	.long 0
saved_es:	.word 0
saved_fs:	.word 0
saved_gs:	.word 0
saved_ss:	.word 0
saved_cr0:	.long 0
saved_cr2:	.long 0
saved_cr3:	.long 0
saved_cr4:	.long 0
saved_gdt:	.word 0
		.long 0
saved_idt:	.word 0
		.long 0
saved_ldt:	.word 0
saved_tr:	.word 0
saved_eip:	.long 0

