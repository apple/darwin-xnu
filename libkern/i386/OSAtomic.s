/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#;**************************************************************************
#;* Boolean OSCompareAndSwap(SInt32 oldValue, SInt32 newValue, SInt32 * ptr) *
#;**************************************************************************

	.globl _OSCompareAndSwap

_OSCompareAndSwap:
	#; this is _lame_, the project will not currently accept asm code that
	#; requires anything beyond a 386, but that chip:
	#; - does not support MP
	#; - does not support the cmpxchgl instruction
	#; - does not support the lock meta-instruction
	#; so what is a poor guy to do?  comment it out...
	pushl		%edi
	pushl		%esi
	movl		0+8+4(%esp),%eax	#; oldValue
	movl		4+8+4(%esp),%edi	#; newValue
	movl		8+8+4(%esp),%esi	#; ptr
	lock
	cmpxchgl	%edi,0(%esi)		#; CAS (eax is an implicit operand)
	sete		%al					#; did CAS succeed? (TZ=1)
	andl		$0x000000ff,%eax	#; clear out the high bytes (has to be an easier way...)
	popl		%esi
	popl		%edi
	ret

