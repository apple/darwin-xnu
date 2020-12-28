/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

.code64
.globl _compat_mode_trampoline
_compat_mode_trampoline:
	/*
	 * %rdi => address of far_call_t (64-bit offset, then 16-bit selector)
	 * %rsi => lowmem stack
	 * %rdx => argument to 32-bit function
	 * %rcx => address of long mode callback
	 * %r8  => 64-bit address of _thunk64
	 */
	movq	%rsp, %rax
	movq	%rsi, %rsp
	pushq	%rax		/* Save 64-bit stack pointer */
	leaq	1f(%rip), %rax
	movq	%rdx, %r9
	xorq	%rdx, %rdx
	movw	%cs, %dx
	shlq	$32, %rdx
	orq	%rdx, %rax
	movq	%r9, %rdx
	/*
	 * Save all callee-saved regs before calling down to compat mode,
	 * as there's no guarantee that the top 32 bits are preserved
	 * across compat mode/long mode switches.
	 */
	pushq	%rbp
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	pushq	%r8		/* Push the absolute address of _thunk64 below */
	pushq	%rcx		/* Push the 64-bit fn ptr that compat mode will call */
	pushq	%rdx		/* Push arg to 32-bit code */
	pushq	%rax		/* Push the return offset + segment onto the stack */

	ljmpq	*(%rdi)
1:
	/*
	 * lretl from compat mode pops off the first 8 bytes,
	 * so manually reclaim the remaining 24 bytes
	 */
	addq	$0x18, %rsp

	/* Restore callee-saved registers */
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
	popq	%rbp

	popq	%rsp
	retq


.code32
.globl _code_32
.align 12
_code_32:
	/*
	 * After the standard stack frame is established, the stack layout is as follows:
	 *
	 *     (%esp) -> old %ebp
	 *    4(%ebp) -> return %eip
	 *    8(%ebp) -> return %cs
	 *  0xc(%ebp) -> function arg (value to increment and return)
	 * 0x14(%ebp) -> 8-byte long mode function pointer to call via trampoline (with 0 args)
	 * 0x1c(%ebp) -> absolute (32-bit) base address of the 64-bit thunk
	 *               (Note that the caller pushed a 64-bit value here, so the 4 bytes
	 *               at 0x20(%ebp) are zeroes.)
	 */
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	call	1f
1:
	popl	%ebx		/* save EIP for use in PIC calculation below */
	subl	$8, %esp

	movl	0x1c(%ebp), %eax

	/* Populate the far call descriptor: */
	movl	%eax, -8(%ebp)
	movl	8(%ebp), %eax	/* The long-mode %cs from whence we came */
	movl	%eax, -4(%ebp)

	pushl	$0	/* number of arguments */
	pushl	0x18(%ebp)	/* high 32-bits of long mode funcptr */
	pushl	0x14(%ebp)	/* low 32-bits of long mode funcptr */

	/*
	 * The next 2 instructions are necessary because clang cannot deal with
	 * a "leal offset(index_reg), dest_reg" construct despite the fact that
	 * this code is marked .code32 (because the target is 64-bit and cannot
	 * process this uniquely-32-bit construct.)
	 */
	leal	2f - 1b, %eax
	addl	%ebx, %eax

	pushl	$0
	pushl	%cs
	pushl	$0
	pushl	%eax

	/*
	 * Note that the long-mode-based function that is called will need
	 * to restore GSbase before calling into any frameworks that might
	 * access %gs-relative data.
	 */
	ljmpl	*-8(%ebp)	/* far call to the long mode trampoline */
2:
	/*
	 * lretq from long mode pops 16 bytes, so reclaim the remaining 12
	 */
	addl	$12, %esp

	/*
	 * Do a division-by-zero so the exception handler can catch it and
	 * restore execution right after.  If a signal handler is used,
	 * it must restore GSbase first if it intends to call into any
	 * frameworks / APIs that access %gs-relative data.
	 */
	xorl	%eax, %eax
	div	%eax

.globl _first_invalid_opcode
_first_invalid_opcode:
	/*
	 * Next, try to perform a sysenter syscall -- which should result in
	 * a #UD.
	 */
	leal	3f - 1b, %edx
	addl	%ebx, %edx		/* return address is expected in %edx */
	pushl	%ecx
	movl	%esp, %ecx		/* stack ptr is expected in %ecx */
	sysenter
3:
	popl	%ecx

	/*
	 * Do the same with each of the old-style INT syscalls.
	 */
	int $0x80
	int $0x81
.globl _last_invalid_opcode
_last_invalid_opcode:
	int $0x82

	/*
	 * discard the return value from the trampolined function and
	 * increment the value passed in as this function's first argument
	 * then return that value + 1 so caller can verify a successful
	 * thunk.
	 */
	movl	0xc(%ebp), %eax
	incl	%eax
	addl	$8, %esp
	popl	%ebx
	popl	%ebp
	lret

.code64

.globl _thunk64
_thunk64:
	/*
	 * The thunk is a very simple code fragment that uses an
	 * absolute address modified at setup time to call into
	 * the long mode trampoline.far call data passed on the stack to jump to long mode
	 * code (where %rip-relative addressing will work properly.)
	 *
	 */
.globl _thunk64_movabs
_thunk64_movabs:
	movabs	$0xdeadbeeffeedface, %rax
	jmpq	*%rax


.globl _compat_mode_trampoline_len
_compat_mode_trampoline_len:
	.long   (. - _compat_mode_trampoline)


.globl _long_mode_trampoline
_long_mode_trampoline:
	/*
	 * After creating a standard stack frame, the stack layout is:
	 *
	 *    8(%rbp) => %eip of far return to compat mode
	 * 0x10(%rbp) => %cs of far return to compat mode
	 * 0x18(%rbp) => low 32-bits of function pointer
	 * 0x1C(%rbp) => high 32-bits of function pointer
	 * 0x20(%rbp) => number of parameters (0..4)
	 * 0x24(%rbp) => first argument [low 32-bits] (if needed)
	 * 0x28(%rbp) => first argument [high 32-bits] (if needed)
	 * 0x2c(%rbp) => second argument [low 32-bits] (if needed)
	 * 0x30(%rbp) => second argument [high 32-bits] (if needed)
	 * 0x34(%rbp) => third argument [low 32-bits] (if needed)
	 * 0x38(%rbp) => third argument [high 32-bits] (if needed)
	 * 0x3c(%rbp) => fourth argument [low 32-bits] (if needed)
	 * 0x40(%rbp) => fourth argument [high 32-bits] (if needed)
	 *
	 * Note that we continue to use the existing (<4G) stack
	 * after the call into long mode.
	 */
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%rdi
	pushq	%rsi
	pushq	%rcx
	movl	0x20(%rbp), %eax

	testl	%eax, %eax
	jz	5f

	movq	0x24(%rbp), %rdi
	decl	%eax

2:
	testl	%eax, %eax
	jz	5f

	movq	0x2c(%rbp), %rsi
	decl	%eax

3:
	testl	%eax, %eax
	jz	5f

	movq	0x34(%rbp), %rdx
	decl	%eax

4:
	testl	%eax, %eax
	jnz	1f			/* too many arguments specified -- bail out and return */

	movq	0x3c(%rbp), %rcx

5:	/* Call passed-in function */
	/* Note that the stack MUST be 16-byte aligned before we call into frameworks in long mode */	

	pushq	%rbx
	movq	%rsp, %rbx
	subq	$0x10, %rsp
	andq	$0xffffffffffffffe0, %rsp

	callq	*0x18(%rbp)
	movq	%rbx, %rsp
	popq	%rbx
1:
	popq	%rcx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	lretq
