/*
 * Copyright (c) 2003-2009 Apple, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <mach/i386/syscall_sw.h>
	

COMMPAGE_FUNCTION_START(spin_lock_try_up, 32, 4)
	movl		4(%esp), %ecx 
	xorl		%eax, %eax
	orl		$-1, %edx
	cmpxchgl	%edx, (%ecx)
	setz		%dl
	movzbl		%dl, %eax
	ret
COMMPAGE_DESCRIPTOR(spin_lock_try_up,_COMM_PAGE_SPINLOCK_TRY,kUP,0)
 

COMMPAGE_FUNCTION_START(spin_lock_try_mp, 32, 4)
	movl		4(%esp), %ecx 
	xorl		%eax, %eax
	orl		$-1, %edx
	lock
	cmpxchgl	%edx, (%ecx)
	setz		%dl
	movzbl		%dl, %eax
	ret
COMMPAGE_DESCRIPTOR(spin_lock_try_mp,_COMM_PAGE_SPINLOCK_TRY,0,kUP)


COMMPAGE_FUNCTION_START(spin_lock_up, 32, 4)
	movl		4(%esp), %ecx
	xorl		%eax, %eax
	orl		$-1, %edx
	cmpxchgl	%edx, (%ecx)
	jnz		1f
	ret
1:
	/* failed to get lock so relinquish the processor immediately on UP */
	pushl		$1		/* 1 ms				*/
	pushl		$1		/* SWITCH_OPTION_DEPRESS	*/
	pushl		$0		/* THREAD_NULL			*/
	pushl		$0		/* push dummy stack ret addr    */
	movl		$-61,%eax	/* SYSCALL_THREAD_SWITCH */
	int		$(MACH_INT)
	addl		$16, %esp	/* adjust stack*/
	jmp		Lspin_lock_up
COMMPAGE_DESCRIPTOR(spin_lock_up,_COMM_PAGE_SPINLOCK_LOCK,kUP,0)


COMMPAGE_FUNCTION_START(spin_lock_mp, 32, 4)
	movl		4(%esp), %ecx
	xorl		%eax, %eax
0:
	orl		$-1, %edx
	lock
	cmpxchgl	%edx, (%ecx)
	jnz		1f
	ret
1:
	xorl		%eax, %eax
	movl		$(MP_SPIN_TRIES), %edx
2:
	pause	
	cmpl		%eax, (%ecx)
	jz		0b		/* favor success and slow down spin loop */
	decl		%edx
	jnz		2b
	/* failed to get lock after spinning so relinquish  */
	pushl		$1		/* 1 ms				*/
	pushl		$1		/* SWITCH_OPTION_DEPRESS	*/
	pushl		$0		/* THREAD_NULL			*/
	pushl		$0		/* push dummy stack ret addr    */
	movl		$-61,%eax	/* SYSCALL_THREAD_SWITCH */
	int		$(MACH_INT)
	addl		$16, %esp	/* adjust stack*/
	jmp		Lspin_lock_mp
COMMPAGE_DESCRIPTOR(spin_lock_mp,_COMM_PAGE_SPINLOCK_LOCK,0,kUP)


COMMPAGE_FUNCTION_START(spin_unlock, 32, 4)
	movl		4(%esp), %ecx
	movl		$0, (%ecx)
	ret
COMMPAGE_DESCRIPTOR(spin_unlock,_COMM_PAGE_SPINLOCK_UNLOCK,0,0)


/* ============================ 64-bit versions follow ===================== */


COMMPAGE_FUNCTION_START(spin_lock_try_up_64, 64, 4)
	xorl		%eax, %eax
	orl		$-1, %edx
	cmpxchgl	%edx, (%rdi)
	setz		%dl
	movzbl		%dl, %eax
	ret
COMMPAGE_DESCRIPTOR(spin_lock_try_up_64,_COMM_PAGE_SPINLOCK_TRY,kUP,0)


COMMPAGE_FUNCTION_START(spin_lock_try_mp_64, 64, 4)
	xorl		%eax, %eax
	orl		$-1, %edx
	lock
	cmpxchgl	%edx, (%rdi)
	setz		%dl
	movzbl		%dl, %eax
	ret
COMMPAGE_DESCRIPTOR(spin_lock_try_mp_64,_COMM_PAGE_SPINLOCK_TRY,0,kUP)


COMMPAGE_FUNCTION_START(spin_lock_up_64, 64, 4)
	movq		%rdi,%r8
0:
	xorl		%eax, %eax
	orl		$-1, %edx
	cmpxchgl	%edx, (%r8)
	jnz		1f
	ret
1:
	/* failed to get lock so relinquish the processor immediately on UP */
	xorl		%edi,%edi	/* THREAD_NULL			*/
	movl		$1,%esi		/* SWITCH_OPTION_DEPRESS	*/
	movl		$1,%edx		/* 1 ms				*/
	movl		$(SYSCALL_CONSTRUCT_MACH(61)),%eax	/* 61 = thread_switch */
	syscall
	jmp		0b
COMMPAGE_DESCRIPTOR(spin_lock_up_64,_COMM_PAGE_SPINLOCK_LOCK,kUP,0)
	
	
COMMPAGE_FUNCTION_START(spin_lock_mp_64, 64, 4)
	movq		%rdi,%r8
0:
	xorl		%eax, %eax
	orl		$-1, %edx
	lock
	cmpxchgl	%edx, (%r8)
	jnz		1f
	ret
1:
	xorl		%eax, %eax
	movl		$(MP_SPIN_TRIES), %edx
2:					/* spin for awhile before relinquish */
	pause	
	cmpl		%eax, (%r8)
	jz		0b
	decl		%edx
	jnz		2b
	/* failed to get lock after spinning so relinquish  */
	xorl		%edi,%edi	/* THREAD_NULL			*/
	movl		$1,%esi		/* SWITCH_OPTION_DEPRESS	*/
	movl		$1,%edx		/* 1 ms				*/
	movl		$(SYSCALL_CONSTRUCT_MACH(61)),%eax	/* 61 = thread_switch */
	syscall
	jmp		0b
COMMPAGE_DESCRIPTOR(spin_lock_mp_64,_COMM_PAGE_SPINLOCK_LOCK,0,kUP)


COMMPAGE_FUNCTION_START(spin_unlock_64, 64, 4)
	movl		$0, (%rdi)
	ret
COMMPAGE_DESCRIPTOR(spin_unlock_64,_COMM_PAGE_SPINLOCK_UNLOCK,0,0)
