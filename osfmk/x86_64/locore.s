/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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

#include <mach_rt.h>
#include <mach_kdp.h>
#include <mach_assert.h>

#include <sys/errno.h>
#include <i386/asm.h>
#include <i386/cpuid.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/trap.h>
#include <assym.s>
#include <mach/exception_types.h>
#include <config_dtrace.h>

#define _ARCH_I386_ASM_HELP_H_          /* Prevent inclusion of user header */
#include <mach/i386/syscall_sw.h>

/*
 * Fault recovery.
 */

#ifdef	__MACHO__
#define	RECOVERY_SECTION	.section	__VECTORS, __recover 
#else
#define	RECOVERY_SECTION	.text
#define	RECOVERY_SECTION	.text
#endif

#define	RECOVER_TABLE_START	\
	.align 3		; \
	.globl	EXT(recover_table) ;\
LEXT(recover_table)		;\
	.text

#define	RECOVER(addr)		\
	.align	3;		\
	.quad	9f		;\
	.quad	addr		;\
	.text			;\
9:

#define	RECOVER_TABLE_END		\
	.align	3			;\
	.globl	EXT(recover_table_end)	;\
LEXT(recover_table_end)			;\
	.text

/*
 * Allocate recovery and table.
 */
	RECOVERY_SECTION
	RECOVER_TABLE_START

/*
 * int rdmsr_carefully(uint32_t msr, uint32_t *lo, uint32_t *hi)
 */
ENTRY(rdmsr_carefully)
	movl	%edi, %ecx
	movq	%rdx, %rdi
	RECOVERY_SECTION
	RECOVER(rdmsr_fail)
	rdmsr
	movl	%eax, (%rsi)
	movl	%edx, (%rdi)
	xorl	%eax, %eax
	ret

rdmsr_fail:
	movq	$1, %rax
	ret
/*
 * int rdmsr64_carefully(uint32_t msr, uint64_t *val);
 */

ENTRY(rdmsr64_carefully)
	movl	%edi, %ecx
	RECOVERY_SECTION
	RECOVER(rdmsr64_carefully_fail)
	rdmsr
	movl	%eax, (%rsi)
	movl	%edx, 4(%rsi)
	xorl	%eax, %eax
	ret
rdmsr64_carefully_fail:
	movl	$1, %eax
	ret
/*
 * int wrmsr64_carefully(uint32_t msr, uint64_t val);
 */

ENTRY(wrmsr_carefully)
	movl	%edi, %ecx
	movl	%esi, %eax
	shr	$32, %rsi
	movl	%esi, %edx
	RECOVERY_SECTION
	RECOVER(wrmsr_fail)
	wrmsr
	xorl	%eax, %eax
	ret
wrmsr_fail:
	movl	$1, %eax
	ret

.globl	EXT(thread_exception_return)
.globl	EXT(thread_bootstrap_return)
LEXT(thread_bootstrap_return)
#if CONFIG_DTRACE
	call EXT(dtrace_thread_bootstrap)
#endif

LEXT(thread_exception_return)
	cli
	xorl	%ecx, %ecx		/* don't check if we're in the PFZ */
	jmp	EXT(return_from_trap)

/*
 * Copyin/out from user/kernel address space.
 * rdi:	source address
 * rsi:	destination address
 * rdx:	byte count (in fact, always < 64MB -- see copyio)
 */
Entry(_bcopy)
	xchg	%rdi, %rsi		/* source %rsi, dest %rdi */

	cld				/* count up */
	mov	%rdx, %rcx		/* move by longwords first */
	shr	$3, %rcx
	RECOVERY_SECTION
	RECOVER(_bcopy_fail)
	rep
	movsq				/* move longwords */

	movl	%edx, %ecx		/* now move remaining bytes */
	andl	$7, %ecx
	RECOVERY_SECTION
	RECOVER(_bcopy_fail)
	rep
	movsb

	xorl	%eax,%eax		/* return 0 for success */
	ret				/* and return */

_bcopy_fail:
	movl	$(EFAULT),%eax		/* return error for failure */
	ret

Entry(pmap_safe_read)
	RECOVERY_SECTION
	RECOVER(_pmap_safe_read_fail)
	movq	(%rdi), %rcx
	mov	%rcx, (%rsi)
	mov	$1, %eax
	ret
_pmap_safe_read_fail:
	xor	%eax, %eax
	ret

/*
 * 2-byte copy used by ml_copy_phys().
 * rdi:	source address
 * rsi:	destination address
 */
Entry(_bcopy2)
	RECOVERY_SECTION
	RECOVER(_bcopy_fail)
	movw	(%rdi), %cx
	RECOVERY_SECTION
	RECOVER(_bcopy_fail)
	movw	%cx, (%rsi)

	xorl	%eax,%eax		/* return 0 for success */
	ret				/* and return */

/*
 * 4-byte copy used by ml_copy_phys().
 * rdi:	source address
 * rsi:	destination address
 */
Entry(_bcopy4)
	RECOVERY_SECTION
	RECOVER(_bcopy_fail)
	movl	(%rdi), %ecx
	RECOVERY_SECTION
	RECOVER(_bcopy_fail)
	mov	%ecx, (%rsi)

	xorl	%eax,%eax		/* return 0 for success */
	ret				/* and return */

/*
 * 8-byte copy used by ml_copy_phys().
 * rdi:	source address
 * rsi:	destination address
 */
Entry(_bcopy8)
	RECOVERY_SECTION
	RECOVER(_bcopy_fail)
	movq	(%rdi), %rcx
	RECOVERY_SECTION
	RECOVER(_bcopy_fail)
	mov	%rcx, (%rsi)

	xorl	%eax,%eax		/* return 0 for success */
	ret				/* and return */


	
/*
 * Copyin string from user/kern address space.
 * rdi:	source address
 * rsi:	destination address
 * rdx:	max byte count
 * rcx:	actual byte count (OUT)
 */
Entry(_bcopystr)
	pushq	%rdi
	xchgq	%rdi, %rsi		/* source %rsi, dest %rdi */

	xorl	%eax,%eax		/* set to 0 here so that high 24 bits */
					/* are 0 for the cmpl against 0 */
2:
	RECOVERY_SECTION
	RECOVER(_bcopystr_fail)		/* copy bytes... */
	movb	(%rsi),%al
	incq	%rsi
	testq	%rdi,%rdi		/* if kernel address is ... */
	jz	3f			/* not NULL */
	movb	%al,(%rdi)		/* copy the byte */
	incq	%rdi
3:
	testl	%eax,%eax		/* did we just stuff the 0-byte? */
	jz	4f			/* yes, return 0 already in %eax */
	decq	%rdx			/* decrement #bytes left in buffer */
	jnz	2b			/* buffer not full, copy another byte */
	movl	$(ENAMETOOLONG),%eax	/* buffer full, no \0: ENAMETOOLONG */
4:
	cmpq	$0,%rcx			/* get OUT len ptr */
	jz	_bcopystr_ret		/* if null, just return */
	subq	(%rsp),%rsi
	movq	%rsi,(%rcx)		/* else set OUT arg to xfer len */
	popq	%rdi			/* restore registers */
_bcopystr_ret:
	ret				/* and return */

_bcopystr_fail:
	popq	%rdi			/* restore registers */
	movl	$(EFAULT),%eax		/* return error for failure */
	ret

/*
 * Done with recovery table.
 */
	RECOVERY_SECTION
	RECOVER_TABLE_END

