/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
	
#define KVTOPHYS	(-KERNELBASE)
#define	KVTOLINEAR	LINEAR_KERNELBASE

#define	PA(addr)	((addr)+KVTOPHYS)
#define	VA(addr)	((addr)-KVTOPHYS)

/* Location of temporary page tables */
#define HPTD        0x80000
	
#define KERNEL_MAP_SIZE (  4 * 1024 * 1024)

/*
 * fillkpt
 *	eax = page frame address
 *	ebx = index into page table
 *	ecx = how many pages to map
 * 	base = base address of page dir/table
 *	prot = protection bits
 */
#define	fillkpt(base, prot)		  \
	shll	$2,%ebx			; \
	addl	base,%ebx		; \
	orl	$(PTE_V), %eax          ; \
	orl	prot,%eax		; \
1:	movl	%eax,(%ebx)		; \
	addl	$(PAGE_SIZE),%eax	; /* increment physical address */ \
	addl	$4,%ebx			; /* next pte */ \
	loop	1b

/*
 * fillpse
 *	eax = physical page address
 *	ebx = index into page table
 *	ecx = how many pages to map
 * 	base = base address of page dir/table
 *	prot = protection bits
 */
#define	fillpse(base, prot)		  \
	shll	$2,%ebx			; \
	addl	base,%ebx		; \
	orl	$(PTE_V|PTE_PS), %eax   ; \
	orl	prot,%eax		; \
1:	movl	%eax,(%ebx)		; \
	addl	$(1 << PDESHIFT),%eax	; /* increment physical address 4Mb */ \
	addl	$4,%ebx			; /* next entry */ \
	loop	1b
	
/*
 * fillkptphys(base, prot)
 *	eax = physical address
 *	ecx = how many pages to map
 *      base = base of page table
 *	prot = protection bits
 */
#define	fillkptphys(base, prot)		  \
	movl	%eax, %ebx		; \
	shrl	$(PAGE_SHIFT), %ebx	; \
	fillkpt(base, prot)

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

	/* Map physical memory from zero to 0xC0000000 */
        xorl    %eax, %eax
        xorl    %ebx, %ebx
        movl    $(KPTDI), %ecx
        fillpse( $(HPTD), $(PTE_W) )

        /* Map 0 again at 0xC0000000 */
        xorl    %eax, %eax
        movl    $(KPTDI), %ebx
        movl    $(KERNEL_MAP_SIZE >> PDESHIFT), %ecx
        fillpse( $(HPTD), $(PTE_W) )
        	
	movl	$(HPTD), %eax
	movl	%eax, %cr3

        POSTCODE(0x3)
        
	movl    %cr4,%eax
        orl     $(CR4_PSE),%eax
        movl    %eax,%cr4               /* enable page size extensions */
	movl	%cr0, %eax
	orl	$(CR0_PG|CR0_WP|CR0_PE), %eax
	movl	%eax, %cr0	/* ready paging */
	
        POSTCODE(0x4)

	lgdt	PA(EXT(gdtptr))		/* load GDT */
	lidt	PA(EXT(idtptr))		/* load IDT */
	
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

        /* XXX doesn't handle 64-bit addresses yet */
	/* XXX can only deal with exactly one page */
LEXT(hibernate_restore_phys_page)
	pushl	%edi
	pushl	%esi

	movl	8+ 4(%esp),%esi		/* source virtual address */
        addl    $0, %esi
        jz      2f                      /* If source == 0, nothing to do */
        

	movl    8+ 12(%esp),%edi        /* destination physical address */
        cmpl    $(LINEAR_KERNELBASE), %edi
        jl      1f                      /* no need to map, below 0xC0000000 */

        movl    %edi, %eax              /* destination physical address */
        /* Map physical address to virt. address 0xffc00000 (4GB - 4MB) */
        andl    $0xFFC00000, %eax
        orl     $(PTE_V | PTE_PS | PTE_W), %eax
        movl    %eax, (HPTD + (0x3FF * 4))
        orl     $0xFFC00000, %edi
        invlpg  (%edi)

1:      
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
2:
	popl	%esi
	popl	%edi
	ret
