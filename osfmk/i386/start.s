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
#include <mach_kdb.h>

#include <i386/asm.h>
#include <i386/proc_reg.h>
#include <i386/postcode.h>
#include <assym.s>

#define	CX(addr,reg)	addr(,reg,4)

#include <i386/mp.h>
#include <i386/mp_slave_boot.h>
#include <i386/cpuid.h>

/*
 * GAS won't handle an intersegment jump with a relocatable offset.
 */
#define	LJMP(segment,address)	\
	.byte	0xea		;\
	.long	address		;\
	.word	segment



#define	PA(addr)	(addr)
#define	VA(addr)	(addr)

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

	.set	., .+INTSTACK_SIZE

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
	.word   0 
LEXT(gdtptr)
	.word	Times(8,GDTSZ)-1
	.long	EXT(master_gdt)

	.align	ALIGN
	.globl	EXT(idtptr)
	/* align below properly */
	.word   0 
LEXT(idtptr)
	.word	Times(8,IDTSZ)-1
	.long	EXT(master_idt)

          /* back to the regular __DATA section. */

          .section __DATA, __data

/*
 * Stack for last-gasp double-fault handler.
 */
	.align	12
	.globl	EXT(df_task_stack)
EXT(df_task_stack):
	.set	., .+INTSTACK_SIZE
	.globl	EXT(df_task_stack_end)
EXT(df_task_stack_end):


/*
 * Stack for machine-check handler.
 */
	.align	12
	.globl	EXT(mc_task_stack)
EXT(mc_task_stack):
	.set	., .+INTSTACK_SIZE
	.globl	EXT(mc_task_stack_end)
EXT(mc_task_stack_end):


#if	MACH_KDB
/*
 * Kernel debugger stack for each processor.
 */
	.align	12
	.globl	EXT(db_stack_store)
EXT(db_stack_store):
	.set	., .+(INTSTACK_SIZE*MAX_CPUS)

/*
 * Stack for last-ditch debugger task for each processor.
 */
	.align	12
	.globl	EXT(db_task_stack_store)
EXT(db_task_stack_store):
	.set	., .+(INTSTACK_SIZE*MAX_CPUS)

/*
 * per-processor kernel debugger stacks
 */
        .align  ALIGN
        .globl  EXT(kgdb_stack_store)
EXT(kgdb_stack_store):
        .set    ., .+(INTSTACK_SIZE*MAX_CPUS)
#endif	/* MACH_KDB */

	.data
physfree:
	.long	0			/* phys addr of next free page */

	.globl	EXT(IdlePTD)
EXT(IdlePTD):
	.long	0			/* phys addr of kernel PTD */
#ifdef PAE
	.globl	EXT(IdlePDPT)
EXT(IdlePDPT):
	.long 0				/* phys addr of kernel PDPT */
#endif
#ifdef X86_64
	.globl EXT(IdlePML4)
EXT(IdlePML4):
	.long 0
	.globl EXT(IdlePDPT64)
EXT(IdlePDPT64):
	.long 0
#endif

KPTphys:
	.long	0			/* phys addr of kernel page tables */

	.globl	EXT(KernelRelocOffset)
EXT(KernelRelocOffset):
	.long	0					/* Kernel relocation offset  */
	

/*   Some handy macros */

#define ALLOCPAGES(npages)			   \
	movl	PA(physfree), %esi		 ; \
	movl	$((npages) * PAGE_SIZE), %eax	 ; \
	addl	%esi, %eax			 ; \
	movl	%eax, PA(physfree)		 ; \
	movl	%esi, %edi			 ; \
	movl	$((npages) * PAGE_SIZE / 4),%ecx ; \
	xorl	%eax,%eax			 ; \
	cld					 ; \
	rep					 ; \
	stosl

/*
 * fillkpt
 *	eax = page frame address
 *	ebx = index into page table
 *	ecx = how many pages to map
 * 	base = base address of page dir/table
 *	prot = protection bits
 */
#define	fillkpt(base, prot)		  \
	shll	$(PTEINDX),%ebx		; \
	addl	base,%ebx		; \
	orl	$(PTE_V) ,%eax		; \
	orl	prot,%eax		; \
1:	movl	%eax,(%ebx)		; \
	addl	$(PAGE_SIZE),%eax	; /* increment physical address */ \
	addl	$(PTESIZE),%ebx			; /* next pte */ \
	loop	1b

/*
 * fillkptphys(prot)
 *	eax = physical address
 *	ecx = how many pages to map
 *	prot = protection bits
 */
#define	fillkptphys(prot)		  \
	movl	%eax, %ebx		; \
	shrl	$(PAGE_SHIFT), %ebx	; \
	fillkpt(PA(KPTphys), prot)

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
	.globl	EXT(_pstart)
LEXT(_start)
LEXT(_pstart)
	mov	%ds, %bx
	mov	%bx, %es
	mov	%eax, %ebp		// Move kernbootstruct to ebp
	POSTCODE(_PSTART_ENTRY)
	movl	KADDR(%ebp), %ebx	// Load boot image phys addr
	movl	%ebx, %edx		// Set edx with boot load phys addr
	addl	KSIZE(%ebp), %edx	// Add boot image size
	addl	$(NBPG-1), %edx		// Round to a page size
	andl	$(-NBPG), %edx		// Set edx to first free page
	movl	%edx, %esp		// Set temporay stack
	addl	$(NBPG), %esp		// add page size
	call	Ls1
Ls1:	popl	%esi			// Get return address
	cmpl	$(PA(Ls1)), %esi 	// Compare with static physicall addr 
	je	EXT(pstart)		// Branch if equal
	subl	$(PA(Ls1)), %esi	// Extract relocation offset
	movl	%esi, %esp		// Store relocation offset in esp
	leal	(PA(Lreloc_start))(%esp),%esi
					// Set esi to reloc_start boot phys addr
	movl	%edx, %edi		// Set edi to first free page
	movl	$(Lreloc_end-Lreloc_start), %ecx
					// Set ecx to copy code size
	cld				// count up
	rep
	movsb				// copy reloc copy code
	wbinvd				// Write back and Invalidate cache
	movl	%ebx, %esi		// Set esi to kernbootstruct kaddr
	movl	KADDR(%ebp), %edi	// Load boot image phys addr
	subl	%esp,  %edi		// Adjust to static phys addr
	movl	KSIZE(%ebp), %ecx	// Set ecx to kernbootstruct ksize
	addl	$(NBPG-1), %ecx		// Add NBPG-1 to ecx
	andl	$(-NBPG), %ecx		// Truncate  ecx to a page aligned addr
	shrl	$2, %ecx		// Divide ecx by 4
	movl	%esp, (PA(EXT(KernelRelocOffset)))(%esp)
					// Store relocation offset
	movl	%edi, KADDR(%ebp)	// Relocate kaddr in kernbootstruct
	subl	%esp, MEMORYMAP(%ebp)	// And relocate MemoryMap 
	subl	%esp, DEVICETREEP(%ebp)	// And relocate deviceTreeP
	subl	%esp, %ebp		// Set ebp with relocated phys addr
	jmp	*%edx			// Branch to relocated copy code
Lreloc_start:
	POSTCODE(_PSTART_RELOC)
	rep
	movsl				// Copy boot image at BASE_KERNEL_PADDR
	wbinvd				// Write back and Invalidate cache
	movl	$(PA(EXT(pstart))), %edx	// Set branch target
	jmp	*%edx			// Far jmp to pstart phys addr
Lreloc_end:
	/* NOTREACHED */
	hlt

	.text
	.globl __start
	.set __start, PA(EXT(_pstart))

/*
 * BSP CPU continues here after possible relocation.
 *	ebp points to kernbootstruct
 */
	.align	ALIGN
	.globl	EXT(pstart)
LEXT(pstart)
	mov     %ebp, %ebx		/* get pointer to kernbootstruct */

	POSTCODE(PSTART_ENTRY)

	mov	$0,%ax			/* fs must be zeroed; */
	mov	%ax,%fs			/* some bootstrappers don`t do this */
	mov	%ax,%gs

/*
 * Get startup parameters.
 */
	movl	KADDR(%ebx), %eax
	addl	KSIZE(%ebx), %eax
	addl	$(NBPG-1),%eax
	andl	$(-NBPG), %eax
	movl	%eax, PA(physfree)
	cld

/* allocate kernel page table pages */
	ALLOCPAGES(NKPT)
	movl	%esi,PA(KPTphys)

#ifdef X86_64
/* allocate PML4 page */
	ALLOCPAGES(1)
	movl	%esi,EXT(IdlePML4)
/* allocate new 3rd level directory page */
	ALLOCPAGES(1)
	movl	%esi,EXT(IdlePDPT64)
#endif
	
#ifdef PAE
/* allocate Page Table Directory Page */
	ALLOCPAGES(1)
	movl	%esi,PA(EXT(IdlePDPT))
#endif

/* allocate kernel page directory page */
	ALLOCPAGES(NPGPTD)
	movl	%esi,PA(EXT(IdlePTD))

/* map from zero to end of kernel */
	xorl	%eax,%eax
	movl	PA(physfree),%ecx
	shrl	$(PAGE_SHIFT),%ecx
	fillkptphys( $(PTE_W) )

/* map page directory */
#ifdef PAE
	movl	PA(EXT(IdlePDPT)), %eax
	movl	$1, %ecx
	fillkptphys( $(PTE_W) )
	
	movl	PA(EXT(IdlePDPT64)), %eax
	movl	$1, %ecx
	fillkptphys( $(PTE_W) )
#endif
	movl	PA(EXT(IdlePTD)),%eax
	movl	$(NPGPTD), %ecx
	fillkptphys( $(PTE_W) )

/* install a pde for temp double map of bottom of VA */
	movl	PA(KPTphys),%eax
	xorl	%ebx,%ebx
	movl	$(NKPT), %ecx
	fillkpt(PA(EXT(IdlePTD)), $(PTE_W))

/* install pde's for page tables */
	movl	PA(KPTphys),%eax
	movl	$(KPTDI),%ebx
	movl	$(NKPT),%ecx
	fillkpt(PA(EXT(IdlePTD)), $(PTE_W))

/* install a pde recursively mapping page directory as a page table */
	movl	PA(EXT(IdlePTD)),%eax
	movl	$(PTDPTDI),%ebx
	movl	$(NPGPTD),%ecx
	fillkpt(PA(EXT(IdlePTD)), $(PTE_W))

#ifdef PAE
	movl	PA(EXT(IdlePTD)), %eax
	xorl	%ebx, %ebx
	movl	$(NPGPTD), %ecx
	fillkpt(PA(EXT(IdlePDPT)), $0)
#endif

/* install a pde page for commpage use up in high memory */

	movl	PA(physfree),%eax	/* grab next phys page */
	movl	%eax,%ebx
	addl	$(PAGE_SIZE),%ebx
	movl	%ebx,PA(physfree)	/* show next free phys pg */
	movl	$(COMM_PAGE_BASE_ADDR),%ebx
	shrl	$(PDESHIFT),%ebx	/* index into pde page */
	movl	$(1), %ecx		/* # pdes to store */
	fillkpt(PA(EXT(IdlePTD)), $(PTE_W|PTE_U)) /* user has access! */

	movl	PA(physfree),%edi
	movl	%edi,PA(EXT(first_avail)) /* save first available phys addr */

#ifdef PAE
/*
 * We steal 0x4000 for a temp pdpt and 0x5000-0x8000
 *   for temp pde pages in the PAE case.  Once we are
 *   running at the proper virtual address we switch to
 *   the PDPT/PDE's the master is using */

	/* clear pdpt page to be safe */
	xorl	%eax, %eax
	movl	$(PAGE_SIZE),%ecx
	movl	$(0x4000),%edi
	cld
	rep
	stosb
	
	/* build temp pdpt */
	movl	$(0x5000), %eax
	xorl	%ebx, %ebx
	movl	$(NPGPTD), %ecx
	fillkpt($(0x4000), $0)

	/* copy the NPGPTD pages of pdes */
	movl	PA(EXT(IdlePTD)),%eax
	movl	$0x5000,%ebx
	movl	$((PTEMASK+1)*NPGPTD),%ecx
1:	movl	0(%eax),%edx
	movl	%edx,0(%ebx)
	movl	4(%eax),%edx
	movl	%edx,4(%ebx)
	addl	$(PTESIZE),%eax
	addl	$(PTESIZE),%ebx
	loop	1b
#else
/* create temp pde for slaves to use
   use unused lomem page and copy in IdlePTD */
	movl	PA(EXT(IdlePTD)),%eax
	movl	$0x4000,%ebx
	movl	$(PTEMASK+1),%ecx
1:	movl	0(%eax),%edx
	movl	%edx,0(%ebx)
	addl	$(PTESIZE),%eax
	addl	$(PTESIZE),%ebx
	loop	1b
#endif
	
	POSTCODE(PSTART_PAGE_TABLES)

/*
 * Fix initial descriptor tables.
 */
	lea	PA(EXT(master_idt)),%esi	/* fix IDT */
	movl	$(IDTSZ),%ecx
	movl	$(PA(fix_idt_ret)),%ebx
	jmp	fix_desc_common		/* (cannot use stack) */
fix_idt_ret:

	lea	PA(EXT(master_gdt)),%esi	/* fix GDT */
	movl	$(GDTSZ),%ecx
	movl	$(PA(fix_gdt_ret)),%ebx
	jmp	fix_desc_common		/* (cannot use stack) */
fix_gdt_ret:

	lea	PA(EXT(master_ldt)),%esi	/* fix LDT */
	movl	$(LDTSZ),%ecx
	movl	$(PA(fix_ldt_ret)),%ebx
	jmp	fix_desc_common		/* (cannot use stack) */
fix_ldt_ret:

/*
 *
 */

	lgdt	PA(EXT(gdtptr))		/* load GDT */
	lidt	PA(EXT(idtptr))		/* load IDT */

	POSTCODE(PSTART_BEFORE_PAGING)

/*
 * Turn on paging.
 */
#ifdef PAE
	movl	PA(EXT(IdlePDPT)), %eax
	movl	%eax, %cr3

	movl	%cr4, %eax
	orl	$(CR4_PAE), %eax
	movl	%eax, %cr4

	movl	$0x80000001, %eax
	cpuid
	and	$(CPUID_EXTFEATURE_XD), %edx	/* clear all but bit 20 */
	cmp	$0, %edx		/* skip setting NXE if 20 is not set */
	je	1f
	
	movl	$(MSR_IA32_EFER), %ecx			/* MSR number in ecx */
	rdmsr						/* MSR value return in edx: eax */
	orl	$(MSR_IA32_EFER_NXE), %eax		/* Set NXE bit in low 32-bits */
	wrmsr						/* Update Extended Feature Enable reg */
1:

#else	
	movl	PA(EXT(IdlePTD)), %eax
	movl	%eax,%cr3
#endif

	movl	%cr0,%eax
	orl	$(CR0_PG|CR0_WP|CR0_PE),%eax
	movl	%eax,%cr0		/* to enable paging */
	
	LJMP(KERNEL_CS,EXT(vstart))	/* switch to kernel code segment */

/*
 * BSP is now running with correct addresses.
 */
LEXT(vstart)
	POSTCODE(VSTART_ENTRY)	; 

	mov	$(KERNEL_DS),%ax	/* set kernel data segment */
	mov	%ax,%ds
	mov	%ax,%es
	mov	%ax,%ss
	mov	%ax,EXT(master_ktss)+TSS_SS0	/* set kernel stack segment */
					/* for traps to kernel */

#if	MACH_KDB
	mov	%ax,EXT(master_dbtss)+TSS_SS0	/* likewise for debug task switch */
	mov	%cr3,%eax		/* get PDBR into debug TSS */
	mov	%eax,EXT(master_dbtss)+TSS_PDBR
	mov	$0,%eax
#endif
	mov	%cr3,%eax		/* get PDBR into DF TSS */
	mov	%eax,EXT(master_dftss)+TSS_PDBR
	mov	%eax,EXT(master_mctss)+TSS_PDBR

	movw	$(KERNEL_LDT),%ax	/* get LDT segment */
	lldt	%ax			/* load LDT */
#if	MACH_KDB
	mov	%ax,EXT(master_ktss)+TSS_LDT	/* store LDT in two TSS, as well... */
	mov	%ax,EXT(master_dbtss)+TSS_LDT	/*   ...matters if we switch tasks */
#endif
	movw	$(KERNEL_TSS),%ax
	ltr	%ax			/* set up KTSS */

	mov	$(CPU_DATA_GS),%ax
	mov	%ax,%gs

	POSTCODE(VSTART_STACK_SWITCH)

	lea	EXT(low_eintstack),%esp	/* switch to the bootup stack */
	pushl	%ebp			/* push boot args addr */
	xorl	%ebp,%ebp		/* clear stack frame ptr */

	POSTCODE(VSTART_EXIT)

	call	EXT(i386_init)		/* run C code */
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

	POSTCODE(SLAVE_PSTART_ENTRY)
/*
 * Turn on paging.
 */
#ifdef PAE
	movl	%cr4, %eax
	orl	$(CR4_PAE), %eax
	movl	%eax, %cr4

	movl	$(MSR_IA32_EFER), %ecx			/* MSR number in ecx */
	rdmsr						/* MSR value return in edx: eax */
	orl	$(MSR_IA32_EFER_NXE), %eax		/* Set NXE bit in low 32-bits */
	wrmsr						/* Update Extended Feature Enable reg */
#endif
	movl	$(0x4000),%eax  /* tmp until we get mapped */
	movl	%eax,%cr3

	movl	%cr0,%eax
	orl	$(CR0_PG|CR0_WP|CR0_PE),%eax
	movl	%eax,%cr0		/* to enable paging */

	POSTCODE(SLAVE_PSTART_EXIT)

	movl	$(EXT(spag_start)),%edx /* first paged code address */
	jmp	*%edx			/* flush prefetch queue */

/*
 * We are now paging, and can run with correct addresses.
 */
LEXT(spag_start)

	lgdt	PA(EXT(gdtptr))		/* load GDT */
	lidt	PA(EXT(idtptr))		/* load IDT */

	LJMP(KERNEL_CS,EXT(slave_vstart))	/* switch to kernel code segment */


/*
 * Slave is now running with correct addresses.
 */
LEXT(slave_vstart)

	POSTCODE(SLAVE_VSTART_ENTRY)

#ifdef PAE
	movl	PA(EXT(IdlePDPT)), %eax
	movl	%eax, %cr3
#else	
	movl	PA(EXT(IdlePTD)), %eax
	movl	%eax, %cr3
#endif

	mov	$(KERNEL_DS),%ax	/* set kernel data segment */
	mov	%ax,%ds
	mov	%ax,%es
	mov	%ax,%ss

	/*
	 * We're not quite through with the boot stack
	 * but we need to reset the stack pointer to the correct virtual
	 * address.
	 * And we need to offset above the address of pstart.
	 */
	movl	$(VA(MP_BOOTSTACK+MP_BOOT+4)), %esp

/*
 * Switch to the per-cpu descriptor tables
 */
	POSTCODE(SLAVE_VSTART_DESC_INIT)

	CPU_NUMBER_FROM_LAPIC(%eax)
	movl	CX(EXT(cpu_data_ptr),%eax),%ecx

	movw	$(GDTSZ*8-1),0(%esp)	/* set GDT size in GDT descriptor */
	movl	CPU_DESC_INDEX+CDI_GDT(%ecx),%edx
	movl	%edx,2(%esp)		/* point to local GDT (linear addr) */
	lgdt	0(%esp)			/* load new GDT */
	
	movw	$(IDTSZ*8-1),0(%esp)	/* set IDT size in IDT descriptor */
	movl	CPU_DESC_INDEX+CDI_IDT(%ecx),%edx
	movl	%edx,2(%esp)		/* point to local IDT (linear addr) */
	lidt	0(%esp)			/* load new IDT */
	
	movw	$(KERNEL_LDT),%ax	/* get LDT segment */
	lldt	%ax			/* load LDT */

	movw	$(KERNEL_TSS),%ax
	ltr	%ax			/* load new KTSS */

	mov	$(CPU_DATA_GS),%ax
	mov	%ax,%gs

/*
 * Get stack top from pre-cpu data and switch
 */
	POSTCODE(SLAVE_VSTART_STACK_SWITCH)

	movl	%gs:CPU_INT_STACK_TOP,%esp
	xorl    %ebp,%ebp               /* for completeness */

	POSTCODE(SLAVE_VSTART_EXIT)

	call	EXT(i386_init_slave)	/* start MACH */
	/*NOTREACHED*/
	hlt

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
