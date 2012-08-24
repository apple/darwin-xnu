/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

#include <platforms.h>
#include <i386/asm.h>
#include <i386/asm64.h>
#include <i386/proc_reg.h>
#include <i386/postcode.h>
#include <i386/vmx/vmx_asm.h>
#include <assym.s>

	.data
	.align 3
	.globl EXT(gdtptr64)
	/* align below right */
	.word	0
LEXT(gdtptr64)
	.word	Times(8,GDTSZ)-1
	/* XXX really want .quad here */
	.long	EXT(master_gdt)
	.long	KERNEL_UBER_BASE_HI32  /* must be in uber-space */

	.align 3
	.globl EXT(idtptr64)
	/* align below right */
	.word	0
LEXT(idtptr64)
	.word	Times(16,IDTSZ)-1
	/* XXX really want .quad here */
	.long	EXT(master_idt64)
	.long	KERNEL_UBER_BASE_HI32  /* must be in uber-space */

	.text

Entry(ml_load_desc64)

	ENTER_64BIT_MODE()

	POSTCODE(ML_LOAD_DESC64_ENTRY)
	
	lgdt	EXT(gdtptr64)		/* load GDT */

	POSTCODE(ML_LOAD_DESC64_GDT)

	lidt	EXT(idtptr64)		/* load IDT */

	POSTCODE(ML_LOAD_DESC64_IDT)

	movw	$(KERNEL_LDT),%ax	/* get LDT segment */
	lldt	%ax			/* load LDT */

	POSTCODE(ML_LOAD_DESC64_LDT)

	movw	$(KERNEL_TSS),%ax
	ltr	%ax			/* set up KTSS */

	POSTCODE(ML_LOAD_DESC64_EXIT)

	ENTER_COMPAT_MODE()

	ret


Entry(ml_64bit_lldt)
	/* (int32_t selector) */

	FRAME

	ENTER_64BIT_MODE()

	movl	B_ARG0, %eax
	lldt	%ax

	ENTER_COMPAT_MODE()

	EMARF
	ret

Entry(set_64bit_debug_regs)
	/* x86_debug_state64_t *ds */

	FRAME

	ENTER_64BIT_MODE()

	mov	B_ARG0, %edx
	mov	DS64_DR0(%edx), %rax
	mov	%rax, %dr0
	mov	DS64_DR1(%edx), %rax
	mov	%rax, %dr1
	mov	DS64_DR2(%edx), %rax
	mov	%rax, %dr2
	mov	DS64_DR3(%edx), %rax
	mov	%rax, %dr3

	ENTER_COMPAT_MODE()

	EMARF
	ret

Entry(flush_tlb64)

	FRAME

	ENTER_64BIT_MODE()

	mov	%cr3, %rax
	mov	%rax, %cr3

	ENTER_COMPAT_MODE()

	EMARF
	ret

Entry(set64_cr3)

	FRAME

	movl	B_ARG0, %eax
	movl	B_ARG1, %edx

	ENTER_64BIT_MODE()

	/* %rax = %edx:%eax */
	shl	$32, %rax
	shrd	$32, %rdx, %rax

	mov	%rax, %cr3

	ENTER_COMPAT_MODE()

	EMARF
	ret

Entry(get64_cr3)

	FRAME

	ENTER_64BIT_MODE()

	mov	%cr3, %rax
	mov	%rax, %rdx
	shr	$32, %rdx		// %edx:%eax = %cr3

	ENTER_COMPAT_MODE()

	EMARF
	ret

Entry(cpuid64)
	ENTER_64BIT_MODE()
	cpuid
	ENTER_COMPAT_MODE()
	ret


/* FXSAVE and FXRSTOR operate in a mode dependent fashion, hence these variants.
 * Must be called with interrupts disabled.
 */

Entry(fxsave64)
	movl		S_ARG0,%eax
	ENTER_64BIT_MODE()
	fxsave		(%eax)
	ENTER_COMPAT_MODE()
	ret

Entry(fxrstor64)
	movl		S_ARG0,%eax
	ENTER_64BIT_MODE()
	fxrstor		(%rax)
	ENTER_COMPAT_MODE()
	ret

Entry(xsave64o)
	ENTER_64BIT_MODE()
	.short	0xAE0F
	/* MOD 0x4, ECX, 0x1 */
	.byte	0x21
	ENTER_COMPAT_MODE()
	ret

Entry(xrstor64o)
	ENTER_64BIT_MODE()
	.short	0xAE0F
	/* MOD 0x5, ECX 0x1 */
	.byte	0x29
	ENTER_COMPAT_MODE()
	ret

#if CONFIG_VMX

/*
 *	__vmxon -- Enter VMX Operation
 *	int __vmxon(addr64_t v);
 */
Entry(__vmxon)
	FRAME
	
	ENTER_64BIT_MODE()
	mov	$(VMX_FAIL_INVALID), %ecx
	mov	$(VMX_FAIL_VALID), %edx
	mov	$(VMX_SUCCEED), %eax
	vmxon	8(%rbp)		/* physical addr passed on stack */
	cmovcl 	%ecx, %eax	/* CF = 1, ZF = 0 */
	cmovzl	%edx, %eax	/* CF = 0, ZF = 1 */
	ENTER_COMPAT_MODE()

	EMARF
	ret

/*
 *	__vmxoff -- Leave VMX Operation
 *	int __vmxoff(void);
 */
Entry(__vmxoff)
	FRAME
	
	ENTER_64BIT_MODE()
	mov	$(VMX_FAIL_INVALID), %ecx
	mov	$(VMX_FAIL_VALID), %edx
	mov	$(VMX_SUCCEED), %eax
	vmxoff
	cmovcl 	%ecx, %eax	/* CF = 1, ZF = 0 */
	cmovzl	%edx, %eax	/* CF = 0, ZF = 1 */
	ENTER_COMPAT_MODE()

	EMARF
	ret

#endif /* CONFIG_VMX */
