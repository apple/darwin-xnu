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
 * Copy "count" bytes from "src" to %esp, using
 * "tmpindex" for a scratch counter and %eax
 */
#define COPY_STACK(src, count, tmpindex) \
	mov	$0, tmpindex	/* initial scratch counter */ ; \
1: \
	mov	0(src,tmpindex,1), %eax	 /* copy one 32-bit word from source... */ ; \
	mov	%eax, 0(%esp,tmpindex,1) /* ... to stack */ ; \
	add	$4, tmpindex		 /* increment counter */ ; \
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
	push	%ebx
	push	%esi
	push	%edi

	sub	$12, %esp	/* align to 16-byte boundary */
	mov	16(%ebp), %esi	/* load efi_reg into %esi */
	mov	20(%ebp), %edx	/* load stack_contents into %edx */
	mov	24(%ebp), %ecx	/* load s_c_s into %ecx */
	sub	%ecx, %esp	/* make room for stack contents */

	COPY_STACK(%edx, %ecx, %edi)
	
	ENTER_64BIT_MODE()

	/* load efi_reg into real registers */
	mov	0(%rsi),  %rcx
	mov	8(%rsi),  %rdx
	mov	16(%rsi), %r8
	mov	24(%rsi), %r9
	mov	32(%rsi), %rax

	mov	8(%rbp), %rdi		/* load func pointer */
	call	*%rdi			/* call EFI runtime */

	mov	16(%rbp), %esi		/* load efi_reg into %esi */
	mov	%rax, 32(%rsi)		/* save RAX back */

	ENTER_COMPAT_MODE()

	add	24(%ebp), %esp	/* discard stack contents */
	add	$12, %esp	/* restore stack pointer */

	pop	%edi
	pop	%esi
	pop	%ebx

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
	push	%ebx
	push	%esi
	push	%edi

	sub	$12, %esp	/* align to 16-byte boundary */
	mov	12(%ebp), %esi	/* load efi_reg into %esi */
	mov	16(%ebp), %edx	/* load stack_contents into %edx */
	mov	20(%ebp), %ecx	/* load s_c_s into %ecx */
	sub	%ecx, %esp	/* make room for stack contents */

	COPY_STACK(%edx, %ecx, %edi)
	
	/* load efi_reg into real registers */
	mov	0(%esi),  %ecx
	mov	8(%esi),  %edx
	mov	32(%esi), %eax

	mov	8(%ebp), %edi		/* load func pointer */
	call	*%edi			/* call EFI runtime */

	mov	12(%ebp), %esi		/* load efi_reg into %esi */
	mov	%eax, 32(%esi)		/* save RAX back */
	movl	$0, 36(%esi)		/* zero out high bits of RAX */

	add	20(%ebp), %esp	/* discard stack contents */
	add	$12, %esp	/* restore stack pointer */

	pop	%edi
	pop	%esi
	pop	%ebx

	EMARF
	ret


/* void             _rtc_nanotime_store(uint64_t                tsc,
	                                uint64_t                nsec,
	                                uint32_t                scale,
	                                uint32_t                shift,
	                                rtc_nanotime_t  *dst) ;
*/

ENTRY(_pal_rtc_nanotime_store)
	push		%ebp
	movl		%esp,%ebp
	push		%esi

	mov		32(%ebp),%edx				/* get ptr to rtc_nanotime_info */
		
	movl		RNT_GENERATION(%edx),%esi		/* get current generation */
	movl		$0,RNT_GENERATION(%edx)			/* flag data as being updated */

	mov		8(%ebp),%eax
	mov		%eax,RNT_TSC_BASE(%edx)
	mov		12(%ebp),%eax
	mov		%eax,RNT_TSC_BASE+4(%edx)

	mov		24(%ebp),%eax
	mov		%eax,RNT_SCALE(%edx)

	mov		28(%ebp),%eax
	mov		%eax,RNT_SHIFT(%edx)

	mov		16(%ebp),%eax
	mov		%eax,RNT_NS_BASE(%edx)
	mov		20(%ebp),%eax
	mov		%eax,RNT_NS_BASE+4(%edx)
		
	incl		%esi					/* next generation */
	jnz		1f
	incl		%esi					/* skip 0, which is a flag */
1:	movl		%esi,RNT_GENERATION(%edx)		/* update generation and make usable */

	pop		%esi
	pop		%ebp

	ret


