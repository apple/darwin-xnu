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
	.globl _OSCompareAndSwapPtr

_OSCompareAndSwap:
_OSCompareAndSwapPtr:
	movl		 4(%esp), %eax	#; oldValue
	movl		 8(%esp), %edx	#; newValue
	movl		12(%esp), %ecx	#; ptr
	lock
	cmpxchgl	%edx, 0(%ecx)	#; CAS (eax is an implicit operand)
	sete		%al			#; did CAS succeed? (TZ=1)
	movzbl		%al, %eax		#; clear out the high bytes
	ret

#;*****************************************************************************
#;* Boolean OSCompareAndSwap64(SInt64 oldValue, SInt64 newValue, SInt64 *ptr) *
#;*****************************************************************************

	.globl _OSCompareAndSwap64

_OSCompareAndSwap64:
	pushl		%edi
	pushl		%ebx

	movl		 4+8(%esp), %eax	#; low 32-bits of oldValue
	movl		 8+8(%esp), %edx	#; high 32-bits of oldValue
	movl		12+8(%esp), %ebx	#; low 32-bits of newValue
	movl		16+8(%esp), %ecx	#; high 32-bits of newValue
	movl		20+8(%esp), %edi	#; ptr
	lock
	cmpxchg8b	0(%edi)		#; CAS (eax:edx, ebx:ecx implicit)
	sete		%al			#; did CAS succeed? (TZ=1)
	movzbl		%al, %eax		#; clear out the high bytes

	popl		%ebx
	popl		%edi
	ret

#;*******************************************************
#;* SInt64 OSAddAtomic64(SInt64 theAmount, SInt64 *ptr) *
#;*******************************************************

	.globl	_OSAddAtomic64
_OSAddAtomic64:
	pushl		%edi
	pushl		%ebx

	movl		12+8(%esp), %edi	#; ptr
	movl		0(%edi), %eax		#; load low 32-bits of *ptr
	movl		4(%edi), %edx		#; load high 32-bits of *ptr
1:
	movl		%eax, %ebx		
	movl		%edx, %ecx		#; ebx:ecx := *ptr
	addl		4+8(%esp), %ebx
	adcl		8+8(%esp), %ecx		#; ebx:ecx := *ptr + theAmount
	lock
	cmpxchg8b	0(%edi)		#; CAS (eax:edx, ebx:ecx implicit)
	jnz		1b		#; - failure: eax:edx re-loaded, retry
					#; - success: old value in eax:edx
	popl		%ebx
	popl		%edi
	ret

#;*******************************************************
#; SInt32 OSAddAtomic(SInt32 delta, SInt32 *address) 
#;*******************************************************

	.globl	_OSAddAtomic
	.globl	_OSAddAtomicLong
_OSAddAtomic:
_OSAddAtomicLong:
	movl	4(%esp), %eax		#; Load addend
	movl	8(%esp), %ecx		#; Load address of operand
	lock
	xaddl	%eax, 0(%ecx)		#; Atomic exchange and add
	ret
