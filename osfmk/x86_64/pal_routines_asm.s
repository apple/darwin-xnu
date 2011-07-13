/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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
#include <i386/asm64.h>
       
#include <assym.s>

/*
 * Copy "count" bytes from "src" to %rsp, using
 * "tmpindex" for a scratch counter and %rax
 */
#define COPY_STACK(src, count, tmpindex) \
	mov	$0, tmpindex	/* initial scratch counter */ ; \
1: \
	mov	0(src,tmpindex,1), %rax	 /* copy one 64-bit word from source... */ ; \
	mov	%rax, 0(%rsp,tmpindex,1) /* ... to stack */ ; \
	add	$8, tmpindex		 /* increment counter */ ; \
	cmp	count, tmpindex		 /* exit it stack has been copied */ ; \
	jne 1b
	
/*
	void
	pal_efi_call_in_64bit_mode_asm(uint64_t func,
	                           struct pal_efi_registers *efi_reg,
	                           void *stack_contents,
	                           size_t stack_contents_size)

	* Switch from compatibility mode to long mode, and
	* then execute the function pointer with the specified
	* register and stack contents (based at %rsp). Afterwards,
	* collect the return value, restore the original state,
	* and return.
*/
ENTRY(_pal_efi_call_in_64bit_mode_asm)
	FRAME

	/* save non-volatile registers */
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	/* save parameters that we will need later */
	push	%rsi
	push	%rcx

	sub	$8, %rsp	/* align to 16-byte boundary */
				/* efi_reg in %rsi */
				/* stack_contents into %rdx */
				/* s_c_s into %rcx */
	sub	%rcx, %rsp	/* make room for stack contents */

	COPY_STACK(%rdx, %rcx, %r8)

	/* load efi_reg into real registers */
	mov	0(%rsi),  %rcx
	mov	8(%rsi),  %rdx
	mov	16(%rsi), %r8
	mov	24(%rsi), %r9
	mov	32(%rsi), %rax

					/* func pointer in %rdi */
	call	*%rdi			/* call EFI runtime */

	mov	-48(%rbp), %rsi		/* load efi_reg into %esi */
	mov	%rax, 32(%rsi)		/* save RAX back */

	mov	-56(%rbp), %rcx	/* load s_c_s into %rcx */
	add	%rcx, %rsp	/* discard stack contents */
	add	$8, %rsp	/* restore stack pointer */

	pop	%rcx
	pop	%rsi
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx

	EMARF
	ret

/*
	void
	pal_efi_call_in_32bit_mode_asm(uint32_t func,
	                           struct pal_efi_registers *efi_reg,
	                           void *stack_contents,
	                           size_t stack_contents_size)

*/
ENTRY(_pal_efi_call_in_32bit_mode_asm)
	FRAME

	/* save non-volatile registers */
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	/* save parameters that we will need later */
	push	%rsi
	push	%rcx

	push	%rbp	/* save %rbp and align to 16-byte boundary */
				/* efi_reg in %rsi */
				/* stack_contents into %rdx */
				/* s_c_s into %rcx */
	sub	%rcx, %rsp	/* make room for stack contents */

	COPY_STACK(%rdx, %rcx, %r8)

	/*
	 * Here in long-mode, with high kernel addresses,
	 * but with the kernel double-mapped in the bottom 4GB.
	 * We now switch to compat mode and call into EFI.
	 */
	ENTER_COMPAT_MODE()

	call	*%edi			/* call EFI runtime */

	ENTER_64BIT_MODE()

	mov	-48(%rbp), %rsi		/* load efi_reg into %esi */
	mov	%rax, 32(%rsi)		/* save RAX back */

	mov	-56(%rbp), %rcx	/* load s_c_s into %rcx */
	add	%rcx, %rsp	/* discard stack contents */
	pop	%rbp		/* restore full 64-bit frame pointer */
				/* which the 32-bit EFI will have truncated */
				/* our full %rsp will be restored by EMARF */
	pop	%rcx
	pop	%rsi
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx

	EMARF
	ret



/*
 * void _pal_rtc_nanotime_store(
 *		uint64_t        tsc,		// %rdi
 *		uint64_t        nsec,		// %rsi
 *		uint32_t        scale,		// %rdx
 *		uint32_t        shift,		// %rcx
 *		rtc_nanotime_t  *dst);		// %r8
 */
ENTRY(_pal_rtc_nanotime_store)
	movl	RNT_GENERATION(%r8),%eax	/* get current generation */
	movl	$0,RNT_GENERATION(%r8)		/* flag data as being updated */
	movq	%rdi,RNT_TSC_BASE(%r8)
	movq	%rsi,RNT_NS_BASE(%r8)
	movl	%edx,RNT_SCALE(%r8)
	movl	%ecx,RNT_SHIFT(%r8)

	incl	%eax				/* next generation */
	jnz	1f
	incl	%eax				/* skip 0, which is a flag */
1:	movl	%eax,RNT_GENERATION(%r8)	/* update generation */

	ret

