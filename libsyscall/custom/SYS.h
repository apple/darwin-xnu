/*
 * Copyright (c) 1999-2007 Apple Inc. All rights reserved.
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
/* Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved.
 *
 *	File:	SYS.h
 *
 *	Definition of the user side of the UNIX system call interface
 *	for M98K.
 *
 *	Errors are flagged by the location of the trap return (ie., which
 *	instruction is executed upon rfi):
 *
 *		SC PC + 4:	Error (typically branch to cerror())
 *		SC PC + 8:	Success
 *
 * HISTORY
 * 18-Nov-92	Ben Fathi (benf@next.com)
 *	Ported to m98k.
 *
 *  9-Jan-92	Peter King (king@next.com)
 *	Created.
 */

#include <sys/syscall.h>

#ifndef SYS_setquota
#define SYS_setquota	148
#endif
#ifndef SYS_quota
#define SYS_quota	149
#endif

#if defined(__ppc__) || defined(__ppc64__)

#include <architecture/ppc/mode_independent_asm.h>

/* From rhapsody kernel mach/ppc/syscall_sw.h */
#define	kernel_trap_args_0
#define	kernel_trap_args_1
#define	kernel_trap_args_2
#define	kernel_trap_args_3
#define	kernel_trap_args_4
#define	kernel_trap_args_5
#define	kernel_trap_args_6
#define	kernel_trap_args_7
#define	kernel_trap_args_8
/* End of rhapsody kernel mach/ppc/syscall_sw.h */

/*
 * Macros.
 */

#define	SYSCALL(name, nargs)			\
	.globl	cerror				@\
    MI_ENTRY_POINT(_##name)     @\
	kernel_trap_args_##nargs    @\
	li	r0,SYS_##name			@\
	sc                          @\
	b	1f                      @\
	blr                         @\
1:	MI_BRANCH_EXTERNAL(cerror)


#define	SYSCALL_NONAME(name, nargs)		\
	.globl	cerror				@\
	kernel_trap_args_##nargs    @\
	li	r0,SYS_##name			@\
	sc                          @\
	b	1f                      @\
	b	2f                      @\
1:	MI_BRANCH_EXTERNAL(cerror)  @\
2:


#define	PSEUDO(pseudo, name, nargs)		\
    .private_extern  _##pseudo           @\
    .text                       @\
    .align  2                   @\
_##pseudo:                      @\
	SYSCALL_NONAME(name, nargs)

#define __SYSCALL(pseudo, name, nargs)	\
    PSEUDO(pseudo, name, nargs)	@\
    blr

#elif defined(__i386__)

#include <architecture/i386/asm_help.h>
#include <mach/i386/syscall_sw.h>

/*
 * We have two entry points. int's is used for syscalls which need to preserve
 * %ecx across the call, or return a 64-bit value in %eax:%edx. sysenter is used
 * for the majority of syscalls which just return a value in %eax.
 */

#define UNIX_SYSCALL_SYSENTER		call __sysenter_trap
#define UNIX_SYSCALL(name, nargs)			\
	.globl	cerror					;\
LEAF(_##name, 0)					;\
	movl	$ SYS_##name, %eax			;\
	UNIX_SYSCALL_SYSENTER				;\
	jnb	2f					;\
	BRANCH_EXTERN(cerror)  				;\
2:

#define UNIX_SYSCALL_INT(name, nargs)			\
	.globl	cerror					;\
LEAF(_##name, 0)					;\
	movl	$ SYS_##name, %eax			;\
	UNIX_SYSCALL_TRAP				;\
	jnb	2f					;\
	BRANCH_EXTERN(cerror)  				;\
2:

#if defined(__SYSCALL_I386_ARG_BYTES) && ((__SYSCALL_I386_ARG_BYTES >= 4) && (__SYSCALL_I386_ARG_BYTES <= 20))
#define UNIX_SYSCALL_NONAME(name, nargs)			\
	movl	$(SYS_##name | (__SYSCALL_I386_ARG_BYTES << I386_SYSCALL_ARG_BYTES_SHIFT)), %eax		;\
	UNIX_SYSCALL_SYSENTER					;\
	jnb	2f						;\
	BRANCH_EXTERN(cerror)					;\
2:
#else /* __SYSCALL_I386_ARG_BYTES < 4 || > 20 */
#define UNIX_SYSCALL_NONAME(name, nargs)		\
	.globl	cerror					;\
	movl	$ SYS_##name, %eax			;\
	UNIX_SYSCALL_SYSENTER				;\
	jnb	2f					;\
	BRANCH_EXTERN(cerror)				;\
2:
#endif

#define UNIX_SYSCALL_INT_NONAME(name, nargs)		\
	.globl	cerror					;\
	movl	$ SYS_##name, %eax			;\
	UNIX_SYSCALL_TRAP				;\
	jnb	2f					;\
	BRANCH_EXTERN(cerror)  				;\
2:

#define PSEUDO(pseudo, name, nargs)			\
LEAF(_##pseudo, 0)					;\
	UNIX_SYSCALL_NONAME(name, nargs)

#define PSEUDO_INT(pseudo, name, nargs)			\
LEAF(_##pseudo, 0)					;\
	UNIX_SYSCALL_INT_NONAME(name, nargs)

#define __SYSCALL(pseudo, name, nargs)			\
	PSEUDO(pseudo, name, nargs)			;\
	ret

#define __SYSCALL_INT(pseudo, name, nargs)		\
	PSEUDO_INT(pseudo, name, nargs)			;\
	ret

#elif defined(__x86_64__)

#include <architecture/i386/asm_help.h>
#include <mach/i386/syscall_sw.h>

#define UNIX_SYSCALL_SYSCALL	\
	movq	%rcx, %r10		;\
	syscall

#define UNIX_SYSCALL(name, nargs)			\
	.globl	cerror					;\
LEAF(_##name, 0)					;\
	movl	$ SYSCALL_CONSTRUCT_UNIX(SYS_##name), %eax	;\
	UNIX_SYSCALL_SYSCALL				;\
	jnb	2f					;\
	BRANCH_EXTERN(cerror)  				;\
2:

#define UNIX_SYSCALL_NONAME(name, nargs)		\
	.globl	cerror					;\
	movl	$ SYSCALL_CONSTRUCT_UNIX(SYS_##name), %eax	;\
	UNIX_SYSCALL_SYSCALL				;\
	jnb	2f					;\
	BRANCH_EXTERN(cerror)  				;\
2:

#define PSEUDO(pseudo, name, nargs)			\
LEAF(_##pseudo, 0)					;\
	UNIX_SYSCALL_NONAME(name, nargs)

#define __SYSCALL(pseudo, name, nargs)			\
	PSEUDO(pseudo, name, nargs)			;\
	ret

#else
#error Unsupported architecture
#endif
