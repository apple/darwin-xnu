/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include <sys/appleapiopts.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>

/*
 * We need a relative branch within the comm page, and don't want the linker
 * to relocate it, so we have to hand-code the instructions. LEN is to account
 * for the length of a .long, since the jmp is relative to the next instruction.
 */

#define JNZ .byte 0x0f, 0x85; .long
#define JMP .byte 0xe9; .long
#define LEN 4 

/*
 * Branch prediction prefixes
 */

#define LIKELY		.byte 0x3e
#define UNLIKELY	.byte 0x2e

#define MP_SPIN_TRIES	1024

	.text
	.align 4, 0x90

Lspin_lock_try_up:
	movl		4(%esp), %ecx 
	xorl		%eax, %eax
	orl		$-1, %edx
	cmpxchgl	%edx, (%ecx)
	setz		%dl
	movzbl		%dl, %eax
	ret

	COMMPAGE_DESCRIPTOR(spin_lock_try_up,_COMM_PAGE_SPINLOCK_TRY,kUP,0)
 
	.align 4, 0x90
Lspin_lock_try_mp:
	movl		4(%esp), %ecx 
	xorl		%eax, %eax
	orl		$-1, %edx
	lock
	cmpxchgl	%edx, (%ecx)
	setz		%dl
	movzbl		%dl, %eax
	ret

	COMMPAGE_DESCRIPTOR(spin_lock_try_mp,_COMM_PAGE_SPINLOCK_TRY,0,kUP)

.set Lrelinquish_off,	_COMM_PAGE_RELINQUISH - _COMM_PAGE_SPINLOCK_LOCK

	.align 4, 0x90
Lspin_lock_up:
	movl		4(%esp), %ecx
	xorl		%eax, %eax
.set Lretry,		. - Lspin_lock_up
	orl		$-1, %edx
	cmpxchgl	%edx, (%ecx)
	UNLIKELY
	JNZ		Lrelinquish_off - . + Lspin_lock_up - LEN
	ret

	COMMPAGE_DESCRIPTOR(spin_lock_up,_COMM_PAGE_SPINLOCK_LOCK,kUP,0)

	.align 4, 0x90
Lspin_lock_mp:
	movl		4(%esp), %ecx
	xorl		%eax, %eax
0:
	orl		$-1, %edx
	lock
	cmpxchgl	%edx, (%ecx)
	UNLIKELY
	jnz		1f
	ret
1:
	xorl		%eax, %eax
	movl		$(MP_SPIN_TRIES), %edx
2:
	pause	
	cmpl		%eax, (%ecx)
	LIKELY
	jz		0b
	decl		%edx
	LIKELY
	jnz		2b
	JMP		Lrelinquish_off - . + Lspin_lock_mp - LEN
 
	COMMPAGE_DESCRIPTOR(spin_lock_mp,_COMM_PAGE_SPINLOCK_LOCK,0,kUP)

	.align 4, 0x90
Lspin_unlock:
	movl		4(%esp), %ecx
	movl		$0, (%ecx)
	ret

	COMMPAGE_DESCRIPTOR(spin_unlock,_COMM_PAGE_SPINLOCK_UNLOCK,0,0)

	.align 4, 0x90
Lrelinquish:				/* relinquish the processor	*/
	pushl		$1		/* 1 ms				*/
	pushl		$1		/* SWITCH_OPTION_DEPRESS	*/
	pushl		$0		/* THREAD_NULL			*/
	pushl		$0		/* push dummy stack ret addr    */
	movl		$-61, %eax	/* syscall_thread_switch	*/
	lcall		$7, $0
	addl		$16, %esp	/* adjust stack*/
	xorl		%eax, %eax	/* set %eax to 0 again		*/
	JMP		Lretry - Lrelinquish_off - . + Lrelinquish - LEN

	COMMPAGE_DESCRIPTOR(relinquish,_COMM_PAGE_RELINQUISH,0,0)
