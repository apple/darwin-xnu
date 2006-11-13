/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <i386/asm.h>
#include <i386/mp_slave_boot.h>
#include <i386/postcode.h>

#define CR0_PE_ON	0x1
#define CR0_PE_OFF	0xfffffffe

	.file	"slave_boot.s"

	.text	
	.align	12		// Page align for single bcopy_phys()

#define	operand_size_prefix	.byte 0x66
#define	address_size_prefix	.byte 0x67

#define	LJMP(segment,address)			\
	operand_size_prefix			;\
	.byte	0xea				;\
	.long	address-EXT(slave_boot_base)	;\
	.word	segment

#define	LGDT(address)				\
	address_size_prefix			;\
	operand_size_prefix			;\
	.word	0x010f				;\
	.byte	0x15				;\
	.long	address-EXT(slave_boot_base)

Entry(slave_boot_base)
	/* code is loaded at 0x0:0x1000 */
	/* ljmp to the next instruction to set up %cs */
	LJMP(MP_BOOTSEG, EXT(slave_rstart))

Entry(slave_rstart)
	/* set up %ds */
	mov	%cs, %ax
	mov	%ax, %ds

	POSTCODE(SLAVE_RSTART_ENTRY);

	/* set up %ss and %esp */
	mov	%cs, %ax
	mov	%ax, %ss
	mov	$(MP_BOOTSTACK), %esp

	/*set up %es */
	mov	%ax, %es

	/* change to protected mode */
	operand_size_prefix
	call	EXT(slave_real_to_prot)

	push	MP_MACH_START
	call	EXT(slave_startprog)

/*
 slave_real_to_prot()
 	transfer from real mode to protected mode.
*/

Entry(slave_real_to_prot)
	/* guarantee that interrupt is disabled when in prot mode */
	cli

	POSTCODE(SLAVE_REAL_TO_PROT_ENTRY);

	/* load the gdtr */
	LGDT(EXT(gdtr))

	/* load the gdtr */
	/* set the PE bit of CR0 */
	mov	%cr0, %eax
	or	$(CR0_PE_ON), %eax
	mov	%eax, %cr0 

	/* make intrasegment jump to flush the processor pipeline and */
	/* reload CS register */
	LJMP(0x08, xprot)
xprot:
	
	/* we are in USE32 mode now */
	/* set up the protective mode segment registers : DS, SS, ES */
	mov	$0x10, %eax
	movw	%ax, %ds
	movw	%ax, %ss
	movw	%ax, %es

	POSTCODE(SLAVE_REAL_TO_PROT_EXIT);

	ret

/*
 slave_startprog(phyaddr)
	start the program on protected mode where phyaddr is the entry point
*/

Entry(slave_startprog)
	push	%ebp
	movl	%esp, %ebp
	
	POSTCODE(SLAVE_STARTPROG_ENTRY);

	movl	0x8(%ebp), %ecx		/* entry offset  */
	movl	$0x28, %ebx		/* segment */
	push	%ebx
	push	%ecx

	/* set up %ds and %es */
	movl	$0x20, %ebx
	movw	%bx, %ds
	movw	%bx, %es

	POSTCODE(SLAVE_STARTPROG_EXIT);

	lret


	. = MP_BOOTGDT-MP_BOOT	/* GDT location */
Entry(Gdt)

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
	.word	0,0		/* 0x0 : null */
	.byte	0,0,0,0

	.word	0xffff,MP_BOOT	/* 0x8 : boot code */
	.byte	0,0x9e,0xcf,0

	.word	0xffff,MP_BOOT	/* 0x10 : boot data */
	.byte	0,0x92,0xcf,0

	.word	0xffff,MP_BOOT	/* 0x18 : boot code, 16 bits */
	.byte	0,0x9e,0x0,0

	.word	0xffff,0	/* 0x20 : init data */
	.byte	0,0x9f,0xcf,0

	.word	0xffff,0	/* 0x28 : init code */
	.byte	0,0x9f,0xcf,0

Entry(gdtr)
	.short	48		/* limit (8*6 segs) */
	.short	MP_BOOTGDT	/* base low */
	.short	0		/* base high */

Entry(slave_boot_end)














