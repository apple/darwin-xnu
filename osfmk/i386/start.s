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
#include <cpus.h>
#include <mach_kdb.h>

#include <i386/asm.h>
#include <i386/proc_reg.h>
#include <assym.s>

#if	NCPUS > 1

#define	CX(addr,reg)	addr(,reg,4)

#else

#define	CPU_NUMBER(reg)
#define	CX(addr,reg)	addr

#endif	/* NCPUS > 1 */

#include <i386/mp.h>

/*
 * GAS won't handle an intersegment jump with a relocatable offset.
 */
#define	LJMP(segment,address)	\
	.byte	0xea		;\
	.long	address		;\
	.word	segment



#define KVTOPHYS	(-KERNELBASE)
#define	KVTOLINEAR	LINEAR_KERNELBASE


#define	PA(addr)	(addr)+KVTOPHYS
#define	VA(addr)	(addr)-KVTOPHYS

	.data
	.align 	2
	.globl	EXT(_kick_buffer_)
EXT(_kick_buffer_):
	.long	1
	.long	3
	.set	.,.+16836
/*
 * Interrupt and bootup stack for initial processor.
 */
	.align	ALIGN
	.globl	EXT(intstack)
EXT(intstack):
	.set	., .+INTSTACK_SIZE
	.globl	EXT(eintstack)
EXT(eintstack:)

#if	NCPUS == 1
	.globl	EXT(int_stack_high)	/* all interrupt stacks */
EXT(int_stack_high):			/* must lie below this */
	.long	EXT(eintstack)		/* address */

	.globl	EXT(int_stack_top)	/* top of interrupt stack */
EXT(int_stack_top):
	.long	EXT(eintstack)
#endif

#if	MACH_KDB
/*
 * Kernel debugger stack for each processor.
 */
	.align	ALIGN
	.globl	EXT(db_stack_store)
EXT(db_stack_store):
	.set	., .+(INTSTACK_SIZE*NCPUS)

/*
 * Stack for last-ditch debugger task for each processor.
 */
	.align	ALIGN
	.globl	EXT(db_task_stack_store)
EXT(db_task_stack_store):
	.set	., .+(INTSTACK_SIZE*NCPUS)
#endif	/* MACH_KDB */

/*
 * per-processor kernel debugger stacks
 */
        .align  ALIGN
        .globl  EXT(kgdb_stack_store)
EXT(kgdb_stack_store):
        .set    ., .+(INTSTACK_SIZE*NCPUS)


/*
 * Pointers to GDT and IDT.  These contain linear addresses.
 */
	.align	ALIGN
	.globl	EXT(gdtptr)
LEXT(gdtptr)
	.word	Times(8,GDTSZ)-1
	.long	EXT(gdt)+KVTOLINEAR

	.align	ALIGN
	.globl	EXT(idtptr)
LEXT(idtptr)
	.word	Times(8,IDTSZ)-1
	.long	EXT(idt)+KVTOLINEAR

#if	NCPUS > 1
	.data
	/*
	 *	start_lock is very special.  We initialize the
	 *	lock at allocation time rather than at run-time.
	 *	Although start_lock should be an instance of a
	 *	hw_lock, we hand-code all manipulation of the lock
	 *	because the hw_lock code may require function calls;
	 *	and we'd rather not introduce another dependency on
	 *	a working stack at this point.
	 */
	.globl	EXT(start_lock)
EXT(start_lock):
	.long	0			/* synchronizes processor startup */

	.globl	EXT(master_is_up)
EXT(master_is_up):
	.long	0			/* 1 when OK for other processors */
					/* to start */
	.globl	EXT(mp_boot_pde)
EXT(mp_boot_pde):
	.long	0
#endif	/* NCPUS > 1 */

/*
 * All CPUs start here.
 *
 * Environment:
 *	protected mode, no paging, flat 32-bit address space.
 *	(Code/data/stack segments have base == 0, limit == 4G)
 */
	.text
	.align	ALIGN
	.globl	EXT(pstart)
	.globl	EXT(_start)
LEXT(_start)
LEXT(pstart)
	mov     %eax, %ebx		/* save pointer to kernbootstruct */
	mov	$0,%ax			/* fs must be zeroed; */
	mov	%ax,%fs			/* some bootstrappers don`t do this */
	mov	%ax,%gs

#if	NCPUS > 1
	jmp	1f
0:	cmpl	$0,PA(EXT(start_lock))
	jne	0b
1:	movb	$1,%eax
	xchgl	%eax,PA(EXT(start_lock)) /* locked */
	testl	%eax,%eax
	jnz	0b

	cmpl	$0,PA(EXT(master_is_up))	/* are we first? */
	jne	EXT(slave_start)		/* no -- system already up. */
	movl	$1,PA(EXT(master_is_up))	/* others become slaves */
#endif	/* NCPUS > 1 */

/*
 * Get startup parameters.
 */

#include <i386/AT386/asm_startup.h>

/*
 * Build initial page table directory and page tables.
 * %ebx holds first available physical address.
 */

	addl	$(NBPG-1),%ebx		/* round first avail physical addr */
	andl	$(-NBPG),%ebx		/* to machine page size */
	leal	-KVTOPHYS(%ebx),%eax	/* convert to virtual address */
	movl	%eax,PA(EXT(kpde))	/* save as kernel page table directory */
	movl	%ebx,%cr3		/* set physical address in CR3 now */

	movl	%ebx,%edi		/* clear page table directory */
	movl	$(PTES_PER_PAGE),%ecx	/* one page of ptes */
	xorl	%eax,%eax
	cld
	rep
	stosl				/* edi now points to next page */

/*
 * Use next few pages for page tables.
 */
	addl	$(KERNELBASEPDE),%ebx	/* point to pde for kernel base */
	movl	%edi,%esi		/* point to end of current pte page */

/*
 * Enter 1-1 mappings for kernel and for kernel page tables.
 */
	movl	$(INTEL_PTE_KERNEL),%eax /* set up pte prototype */
0:
	cmpl	%esi,%edi		/* at end of pte page? */
	jb	1f			/* if so: */
	movl	%edi,%edx		/*    get pte address (physical) */
	andl	$(-NBPG),%edx		/*    mask out offset in page */
	orl	$(INTEL_PTE_KERNEL),%edx /*   add pte bits */
	movl	%edx,(%ebx)		/*    set pde */
	addl	$4,%ebx			/*    point to next pde */
	movl	%edi,%esi		/*    point to */
	addl	$(NBPG),%esi		/*    end of new pte page */
1:
	movl	%eax,(%edi)		/* set pte */
	addl	$4,%edi			/* advance to next pte */
	addl	$(NBPG),%eax		/* advance to next phys page */
	cmpl	%edi,%eax		/* have we mapped this pte page yet? */
	jb	0b			/* loop if not */

/*
 * Zero rest of last pte page.
 */
	xor	%eax,%eax		/* don`t map yet */
2:	cmpl	%esi,%edi		/* at end of pte page? */
	jae	3f
	movl	%eax,(%edi)		/* zero mapping */
	addl	$4,%edi
	jmp	2b
3:

#if	NCPUS > 1
/*
 * Grab (waste?) another page for a bootstrap page directory
 * for the other CPUs.  We don't want the running CPUs to see
 * addresses 0..3fffff mapped 1-1.
 */
	movl	%edi,PA(EXT(mp_boot_pde)) /* save its physical address */
	movl	$(PTES_PER_PAGE),%ecx	/* and clear it */
	rep
	stosl
#endif	/* NCPUS > 1 */
	movl	%edi,PA(EXT(first_avail)) /* save first available phys addr */

/*
 * pmap_bootstrap will enter rest of mappings.
 */

/*
 * Fix initial descriptor tables.
 */
	lea	PA(EXT(idt)),%esi	/* fix IDT */
	movl	$(IDTSZ),%ecx
	movl	$(PA(fix_idt_ret)),%ebx
	jmp	fix_desc_common		/* (cannot use stack) */
fix_idt_ret:

	lea	PA(EXT(gdt)),%esi	/* fix GDT */
	movl	$(GDTSZ),%ecx
	movl	$(PA(fix_gdt_ret)),%ebx
	jmp	fix_desc_common		/* (cannot use stack) */
fix_gdt_ret:

	lea	PA(EXT(ldt)),%esi	/* fix LDT */
	movl	$(LDTSZ),%ecx
	movl	$(PA(fix_ldt_ret)),%ebx
	jmp	fix_desc_common		/* (cannot use stack) */
fix_ldt_ret:

/*
 * Turn on paging.
 */
	movl	%cr3,%eax		/* retrieve kernel PDE phys address */
	movl	KERNELBASEPDE(%eax),%ecx
	movl	%ecx,(%eax)		/* set it also as pte for location */
					/* 0..3fffff, so that the code */
					/* that enters paged mode is mapped */
					/* to identical addresses after */
					/* paged mode is enabled */

	addl	$4,%eax			/* 400000..7fffff */
	movl	KERNELBASEPDE(%eax),%ecx
	movl	%ecx,(%eax)

	movl	$ EXT(pag_start),%ebx	/* first paged code address */

	movl	%cr0,%eax
	orl	$(CR0_PG),%eax		/* set PG bit in CR0 */
	orl	$(CR0_WP),%eax
	movl	%eax,%cr0		/* to enable paging */

	jmp	*%ebx			/* flush prefetch queue */

/*
 * We are now paging, and can run with correct addresses.
 */
LEXT(pag_start)
	lgdt	EXT(gdtptr)		/* load GDT */
	lidt	EXT(idtptr)		/* load IDT */
	LJMP(KERNEL_CS,EXT(vstart))	/* switch to kernel code segment */

/*
 * Master is now running with correct addresses.
 */
LEXT(vstart)
	mov	$(KERNEL_DS),%ax	/* set kernel data segment */
	mov	%ax,%ds
	mov	%ax,%es
	mov	%ax,%ss
	mov	%ax,EXT(ktss)+TSS_SS0	/* set kernel stack segment */
					/* for traps to kernel */
#if	MACH_KDB
	mov	%ax,EXT(dbtss)+TSS_SS0	/* likewise for debug task switch */
	mov	%cr3,%eax		/* get PDBR into debug TSS */
	mov	%eax,EXT(dbtss)+TSS_PDBR
	mov	$0,%eax
#endif

	movw	$(KERNEL_LDT),%ax	/* get LDT segment */
	lldt	%ax			/* load LDT */
#if	MACH_KDB
	mov	%ax,EXT(ktss)+TSS_LDT	/* store LDT in two TSS, as well... */
	mov	%ax,EXT(dbtss)+TSS_LDT	/*   ...matters if we switch tasks */
#endif
	movw	$(KERNEL_TSS),%ax
	ltr	%ax			/* set up KTSS */

	mov	$ CPU_DATA,%ax
	mov	%ax,%gs

	lea	EXT(eintstack),%esp	/* switch to the bootup stack */
	call	EXT(i386_init)		/* run C code */
	/*NOTREACHED*/
	hlt

#if	NCPUS > 1
/*
 * master_up is used by the master cpu to signify that it is done
 * with the interrupt stack, etc. See the code in pstart and svstart
 * that this interlocks with.
 */
	.align	ALIGN
	.globl	EXT(master_up)
LEXT(master_up)
	pushl	%ebp			/* set up */
	movl	%esp,%ebp		/* stack frame */
	movl	$0,%ecx			/* unlock start_lock */
	xchgl	%ecx,EXT(start_lock)	/* since we are no longer using */
					/* bootstrap stack */
	leave				/* pop stack frame */
	ret

/*
 * We aren't the first.  Call slave_main to initialize the processor
 * and get Mach going on it.
 */
	.align	ALIGN
	.globl	EXT(slave_start)
LEXT(slave_start)
	cli				/* disable interrupts, so we don`t */
					/* need IDT for a while */
	movl	EXT(kpde)+KVTOPHYS,%ebx	/* get PDE virtual address */
	addl	$(KVTOPHYS),%ebx	/* convert to physical address */

	movl	PA(EXT(mp_boot_pde)),%edx /* point to the bootstrap PDE */
	movl	KERNELBASEPDE(%ebx),%eax
					/* point to pte for KERNELBASE */
	movl	%eax,KERNELBASEPDE(%edx)
					/* set in bootstrap PDE */
	movl	%eax,(%edx)		/* set it also as pte for location */
					/* 0..3fffff, so that the code */
					/* that enters paged mode is mapped */
					/* to identical addresses after */
					/* paged mode is enabled */
	movl	%edx,%cr3		/* use bootstrap PDE to enable paging */

	movl	$ EXT(spag_start),%edx	/* first paged code address */

	movl	%cr0,%eax
	orl	$(CR0_PG),%eax		/* set PG bit in CR0 */
	orl	$(CR0_WP),%eax
	movl	%eax,%cr0		/* to enable paging */

	jmp	*%edx			/* flush prefetch queue. */

/*
 * We are now paging, and can run with correct addresses.
 */
LEXT(spag_start)

	lgdt	EXT(gdtptr)		/* load GDT */
	lidt	EXT(idtptr)		/* load IDT */
	LJMP(KERNEL_CS,EXT(svstart))	/* switch to kernel code segment */

/*
 * Slave is now running with correct addresses.
 */
LEXT(svstart)
	mov	$(KERNEL_DS),%ax	/* set kernel data segment */
	mov	%ax,%ds
	mov	%ax,%es
	mov	%ax,%ss

	movl	%ebx,%cr3		/* switch to the real kernel PDE  */

	CPU_NUMBER(%eax)
	movl	CX(EXT(interrupt_stack),%eax),%esp /* get stack */
	addl	$(INTSTACK_SIZE),%esp	/* point to top */
	xorl	%ebp,%ebp		/* for completeness */

	movl	$0,%ecx			/* unlock start_lock */
	xchgl	%ecx,EXT(start_lock)	/* since we are no longer using */
					/* bootstrap stack */

/*
 * switch to the per-cpu descriptor tables
 */

	pushl	%eax			/* pass CPU number */
	call	EXT(mp_desc_init)	/* set up local table */
					/* pointer returned in %eax */
	subl	$4,%esp			/* get space to build pseudo-descriptors */
	
	CPU_NUMBER(%eax)
	movw	$(GDTSZ*8-1),0(%esp)	/* set GDT size in GDT descriptor */
	movl	CX(EXT(mp_gdt),%eax),%edx
	addl	$ KVTOLINEAR,%edx
	movl	%edx,2(%esp)		/* point to local GDT (linear address) */
	lgdt	0(%esp)			/* load new GDT */
	
	movw	$(IDTSZ*8-1),0(%esp)	/* set IDT size in IDT descriptor */
	movl	CX(EXT(mp_idt),%eax),%edx
	addl	$ KVTOLINEAR,%edx
	movl	%edx,2(%esp)		/* point to local IDT (linear address) */
	lidt	0(%esp)			/* load new IDT */
	
	movw	$(KERNEL_LDT),%ax	/* get LDT segment */
	lldt	%ax			/* load LDT */

	movw	$(KERNEL_TSS),%ax
	ltr	%ax			/* load new KTSS */

	mov	$ CPU_DATA,%ax
	mov	%ax,%gs

	call	EXT(slave_main)		/* start MACH */
	/*NOTREACHED*/
	hlt
#endif	/* NCPUS > 1 */

/*
 * Convert a descriptor from fake to real format.
 *
 * Calls from assembly code:
 * %ebx = return address (physical) CANNOT USE STACK
 * %esi	= descriptor table address (physical)
 * %ecx = number of descriptors
 *
 * Calls from C:
 * 0(%esp) = return address
 * 4(%esp) = descriptor table address (physical)
 * 8(%esp) = number of descriptors
 *
 * Fake descriptor format:
 *	bytes 0..3		base 31..0
 *	bytes 4..5		limit 15..0
 *	byte  6			access byte 2 | limit 19..16
 *	byte  7			access byte 1
 *
 * Real descriptor format:
 *	bytes 0..1		limit 15..0
 *	bytes 2..3		base 15..0
 *	byte  4			base 23..16
 *	byte  5			access byte 1
 *	byte  6			access byte 2 | limit 19..16
 *	byte  7			base 31..24
 *
 * Fake gate format:
 *	bytes 0..3		offset
 *	bytes 4..5		selector
 *	byte  6			word count << 4 (to match fake descriptor)
 *	byte  7			access byte 1
 *
 * Real gate format:
 *	bytes 0..1		offset 15..0
 *	bytes 2..3		selector
 *	byte  4			word count
 *	byte  5			access byte 1
 *	bytes 6..7		offset 31..16
 */
	.globl	EXT(fix_desc)
LEXT(fix_desc)
	pushl	%ebp			/* set up */
	movl	%esp,%ebp		/* stack frame */
	pushl	%esi			/* save registers */
	pushl	%ebx
	movl	B_ARG0,%esi		/* point to first descriptor */
	movl	B_ARG1,%ecx		/* get number of descriptors */
	lea	0f,%ebx			/* get return address */
	jmp	fix_desc_common		/* call internal routine */
0:	popl	%ebx			/* restore registers */
	popl	%esi
	leave				/* pop stack frame */
	ret				/* return */

fix_desc_common:
0:
	movw	6(%esi),%dx		/* get access byte */
	movb	%dh,%al
	andb	$0x14,%al
	cmpb	$0x04,%al		/* gate or descriptor? */
	je	1f

/* descriptor */
	movl	0(%esi),%eax		/* get base in eax */
	rol	$16,%eax		/* swap 15..0 with 31..16 */
					/* (15..0 in correct place) */
	movb	%al,%dl			/* combine bits 23..16 with ACC1 */
					/* in dh/dl */
	movb	%ah,7(%esi)		/* store bits 31..24 in correct place */
	movw	4(%esi),%ax		/* move limit bits 0..15 to word 0 */
	movl	%eax,0(%esi)		/* store (bytes 0..3 correct) */
	movw	%dx,4(%esi)		/* store bytes 4..5 */
	jmp	2f

/* gate */
1:
	movw	4(%esi),%ax		/* get selector */
	shrb	$4,%dl			/* shift word count to proper place */
	movw	%dx,4(%esi)		/* store word count / ACC1 */
	movw	2(%esi),%dx		/* get offset 16..31 */
	movw	%dx,6(%esi)		/* store in correct place */
	movw	%ax,2(%esi)		/* store selector in correct place */
2:
	addl	$8,%esi			/* bump to next descriptor */
	loop	0b			/* repeat */
	jmp	*%ebx			/* all done */

/*
 * put arg in kbd leds and spin a while
 * eats eax, ecx, edx
 */
#define	K_RDWR		0x60
#define	K_CMD_LEDS	0xed
#define	K_STATUS	0x64
#define	K_IBUF_FULL	0x02		/* input (to kbd) buffer full */
#define	K_OBUF_FULL	0x01		/* output (from kbd) buffer full */

ENTRY(set_kbd_leds)
	mov	S_ARG0,%cl		/* save led value */
	
0:	inb	$(K_STATUS),%al		/* get kbd status */
	testb	$(K_IBUF_FULL),%al	/* input busy? */
	jne	0b			/* loop until not */
	
	mov	$(K_CMD_LEDS),%al	/* K_CMD_LEDS */
	outb	%al,$(K_RDWR)		/* to kbd */

0:	inb	$(K_STATUS),%al		/* get kbd status */
	testb	$(K_OBUF_FULL),%al	/* output present? */
	je	0b			/* loop if not */

	inb	$(K_RDWR),%al		/* read status (and discard) */

0:	inb	$(K_STATUS),%al		/* get kbd status */
	testb	$(K_IBUF_FULL),%al	/* input busy? */
	jne	0b			/* loop until not */
	
	mov	%cl,%al			/* move led value */
	outb	%al,$(K_RDWR)		/* to kbd */

	movl	$10000000,%ecx		/* spin */
0:	nop
	nop
	loop	0b			/* a while */

	ret
