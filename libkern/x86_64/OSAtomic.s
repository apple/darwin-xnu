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

#;***************************************************************************
#;* Boolean OSCompareAndSwap(SInt32 oldValue, SInt32 newValue, SInt32 *ptr) *
#;***************************************************************************

	.globl _OSCompareAndSwap
_OSCompareAndSwap: #;oldValue, newValue, ptr
#if	DEBUG
	test	$3, %rdx
	jz	1f
	ud2
1:
#endif	
	movl		 %edi, %eax
	lock
	cmpxchgl	%esi, (%rdx)	#; CAS (eax is an implicit operand)
	sete		%al			#; did CAS succeed? (TZ=1)
	movzbq		%al, %rax		#; clear out the high bytes
	ret

#;*****************************************************************************
#;* Boolean OSCompareAndSwap64(SInt64 oldValue, SInt64 newValue, SInt64 *ptr) *
#;*****************************************************************************

	.globl _OSCompareAndSwap64
	.globl _OSCompareAndSwapPtr

_OSCompareAndSwap64:
_OSCompareAndSwapPtr: #;oldValue, newValue, ptr
#if	DEBUG
	test	$7, %rdx
	jz	1f
	ud2
1:
#endif
	movq		%rdi, %rax
	lock
	cmpxchgq	%rsi, (%rdx)	#; CAS (rax is an implicit operand)
	sete		%al			#; did CAS succeed? (TZ=1)
	movzbq		%al, %rax		#; clear out the high bytes
	ret

#;*******************************************************
#;* SInt64 OSAddAtomic64(SInt64 theAmount, SInt64 *ptr) *
#;*******************************************************

	.globl	_OSAddAtomicLong
	.globl	_OSAddAtomic64
_OSAddAtomic64:
_OSAddAtomicLong:
#if	DEBUG
	test	$7, %rsi
	jz	1f
	ud2
1:
#endif
	lock
	xaddq	%rdi, (%rsi)		#; Atomic exchange and add
	movq	%rdi, %rax;
	ret


#;*******************************************************
#; SInt32 OSAddAtomic(SInt32 delta, SInt32 *address) 
#;*******************************************************

	.globl	_OSAddAtomic
_OSAddAtomic:
#if	DEBUG
	test	$3, %rsi
	jz	1f
	ud2
1:
#endif
	lock
	xaddl	%edi, (%rsi)		#; Atomic exchange and add
	movl	%edi, %eax;
	ret
