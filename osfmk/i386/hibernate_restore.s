/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
#include <i386/proc_reg.h>
	
#include <i386/postcode.h>
#include <assym.s>

/*
This code is linked into the kernel but part of the "__HIB" section, which means
its used by code running in the special context of restoring the kernel text and data
from the hibernation image read by the booter. hibernate_kernel_entrypoint() and everything
it calls or references (ie. hibernate_restore_phys_page())
needs to be careful to only touch memory also in the "__HIB" section.
*/

/*
 * GAS won't handle an intersegment jump with a relocatable offset.
 */
#define	LJMP(segment,address)	\
	.byte	0xea		;\
	.long	address		;\
	.word	segment
	
/* Location of temporary page tables */
#define HPTD        (0x13000)
#define HPDPT       (0x17000)

#define LAST_PAGE	(0xFFE00000)
#define LAST_PAGE_PDE   (0x7ff)

/*
 * fillpse
 *	eax = physical page address
 *	ebx = index into page table
 *	ecx = how many pages to map
 * 	base = base address of page dir/table
 *	prot = protection bits
 */
#define	fillpse(base, prot)		  \
	shll	$3,%ebx			; \
	addl	base,%ebx		; \
	orl	$(PTE_V|PTE_PS|0x60), %eax   ; \
	orl	prot,%eax		; \
        xorl    %edx, %edx		; \
1:	movl	%eax,(%ebx)		; /* low 32b */ \
	addl	$4,%ebx			; \
	movl	%edx,(%ebx)		; /* high 32b */ \
	addl	$(1 << PDESHIFT),%eax	; /* increment physical address 2Mb */ \
	addl	$4,%ebx			; /* next entry */ \
	loop	1b
	


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

	.align	ALIGN
ENTRY(hib_gdt)
	.word	0, 0		/* 0x0  : null */
	.byte	0, 0, 0, 0

	.word	0xffff, 0x0000	/* 0x8  : code */
	.byte	0, 0x9e, 0xcf, 0

	.word	0xffff, 0x0000	/* 0x10 : data */
	.byte	0, 0x92, 0xcf, 0

ENTRY(hib_gdtr)
	.word	24		/* limit (8*3 segs) */
	.long	EXT(hib_gdt) 

/*
 * Hibernation code restarts here.  Steal some pages from 0x10000
 * to 0x90000 for pages tables and directories etc to temporarily
 * map the hibernation code (put at 0x100000 (phys) by the booter
 * and linked to 0xC0100000 by the linker) to 0xC0100000 so it can
 * execute.  It's self-contained and won't make any references outside
 * of itself.
 *
 * On the way down it has to save IdlePTD (and if PAE also IdlePDPT)
 * and after it runs it has to restore those and load IdlePTD (or
 * IdlePDPT if PAE) into %cr3 to re-establish the original mappings
 */

	.align	ALIGN
	.globl	EXT(hibernate_machine_entrypoint)
LEXT(hibernate_machine_entrypoint)
	cli

        mov     %eax, %edi

	POSTCODE(0x1)

	/* Map physical memory from zero to LAST_PAGE */
        xorl    %eax, %eax
        xorl    %ebx, %ebx
        movl    $(LAST_PAGE_PDE), %ecx
        fillpse( $(HPTD), $(PTE_W) )

	movl	$(HPDPT), %ebx
        movl    $(HPTD), %eax
	orl	$(PTE_V), %eax

        xorl    %edx, %edx		; \

	movl	%eax,(%ebx)		; /* low 32b */ \
	addl	$4,%ebx			; \
	movl	%edx,(%ebx)		; /* high 32b */ \
	addl	$4,%ebx			; \
	addl	$(1 << 12),%eax		; /* increment physical address 1Gb */ \

	movl	%eax,(%ebx)		; /* low 32b */ \
	addl	$4,%ebx			; \
	movl	%edx,(%ebx)		; /* high 32b */ \
	addl	$4,%ebx			; \
	addl	$(1 << 12),%eax		; /* increment physical address 1Gb */ \

	movl	%eax,(%ebx)		; /* low 32b */ \
	addl	$4,%ebx			; \
	movl	%edx,(%ebx)		; /* high 32b */ \
	addl	$4,%ebx			; \
	addl	$(1 << 12),%eax		; /* increment physical address 1Gb */ \

	movl	%eax,(%ebx)		; /* low 32b */
	addl	$4,%ebx			; 
	movl	%edx,(%ebx)		; /* high 32b */ \
	addl	$4,%ebx			; \
	addl	$(1 << 12),%eax		; /* increment physical address 1Gb */ \

	/* set page dir ptr table addr */
	movl	$(HPDPT), %eax
	movl	%eax, %cr3

        POSTCODE(0x3)
        
	movl    %cr4,%eax
        orl     $(CR4_PAE|CR4_PGE|CR4_MCE),%eax
        movl    %eax,%cr4               /* enable page size extensions */

	movl	$(MSR_IA32_EFER), %ecx			/* MSR number in ecx */
	rdmsr						/* MSR value return in edx: eax */
	orl	$(MSR_IA32_EFER_NXE), %eax		/* Set NXE bit in low 32-bits */
	wrmsr						/* Update Extended Feature Enable reg */

	movl	%cr0, %eax
	orl	$(CR0_PG|CR0_WP|CR0_PE), %eax
	movl	%eax, %cr0	/* ready paging */
	
        POSTCODE(0x4)

	lgdt	EXT(gdtptr)		/* load GDT */
	lidt	EXT(idtptr)		/* load IDT */

        POSTCODE(0x5)

        LJMP	(KERNEL_CS,EXT(hstart))  /* paging on and go to correct vaddr */

/* Hib restart code now running with correct addresses */
LEXT(hstart)
	POSTCODE(0x6)

	mov	$(KERNEL_DS),%ax	/* set kernel data segment */
	mov	%ax,%ds
	mov	%ax,%es
	mov	%ax,%ss
	
	mov	$0,%ax			/* fs must be zeroed; */
	mov	%ax,%fs			/* some bootstrappers don`t do this */
	mov	%ax,%gs
	
	lea	EXT(gIOHibernateRestoreStackEnd),%esp	/* switch to the bootup stack */

        POSTCODE(0x7)	
	
        xorl    %eax, %eax              /* Video memory - N/A */
        pushl   %eax
        pushl   %eax
        pushl   %eax
        mov     %edi, %eax              /* Pointer to hibernate header */
        pushl   %eax
        call    EXT(hibernate_kernel_entrypoint)
        /* NOTREACHED */
        hlt
        
/*
void 
hibernate_restore_phys_page(uint64_t src, uint64_t dst, uint32_t len, uint32_t procFlags);
*/

	.align	5
	.globl	EXT(hibernate_restore_phys_page)

	/* XXX can only deal with exactly one page */
LEXT(hibernate_restore_phys_page)
	pushl	%edi
	pushl	%esi

	movl	8+ 4(%esp),%esi		/* source virtual address */
        addl    $0, %esi
        jz      3f                      /* If source == 0, nothing to do */
        
	movl    8+ 16(%esp),%eax        /* destination physical address, high 32 bits  */
	movl    8+ 12(%esp),%edi        /* destination physical address, low 32 bits */
        addl    $0, %eax
        jne     1f                      /* need to map, above LAST_PAGE */

        cmpl    $(LAST_PAGE), %edi
        jb      2f                      /* no need to map, below LAST_PAGE */
1:
        /* Map physical address %eax:%edi to virt. address LAST_PAGE (4GB - 2MB) */
        movl    %eax, (HPTD + (LAST_PAGE_PDE * 8) + 4)
        movl    %edi, %eax              /* destination physical address */
        andl    $(LAST_PAGE), %eax
        orl     $(PTE_V | PTE_PS | PTE_W), %eax
        movl    %eax, (HPTD + (LAST_PAGE_PDE * 8))
        orl     $(LAST_PAGE), %edi
        invlpg  (%edi)

2:      
	movl	8+ 20(%esp),%edx	/* number of bytes */
	cld
	/* move longs*/
	movl	%edx,%ecx
	sarl	$2,%ecx
	rep
	movsl
	/* move bytes*/
	movl	%edx,%ecx
	andl	$3,%ecx
	rep
	movsb
3:
	popl	%esi
	popl	%edi
	ret
