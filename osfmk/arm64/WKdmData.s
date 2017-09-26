/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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


.globl _hashLookupTable
	.const
	.align 5
_hashLookupTable:
	.byte	0
	.byte	52
	.byte	8
	.byte	56
	.byte	16
	.byte	12
	.byte	28
	.byte	20
	.byte	4
	.byte	36
	.byte	48
	.byte	24
	.byte	44
	.byte	40
	.byte	32
	.byte	60
	.byte	8
	.byte	12
	.byte	28
	.byte	20
	.byte	4
	.byte	60
	.byte	16
	.byte	36
	.byte	24
	.byte	48
	.byte	44
	.byte	32
	.byte	52
	.byte	56
	.byte	40
	.byte	12
	.byte	8
	.byte	48
	.byte	16
	.byte	52
	.byte	60
	.byte	28
	.byte	56
	.byte	32
	.byte	20
	.byte	24
	.byte	36
	.byte	40
	.byte	44
	.byte	4
	.byte	8
	.byte	40
	.byte	60
	.byte	32
	.byte	20
	.byte	44
	.byte	4
	.byte	36
	.byte	52
	.byte	24
	.byte	16
	.byte	56
	.byte	48
	.byte	12
	.byte	28
	.byte	16
	.byte	8
	.byte	40
	.byte	36
	.byte	28
	.byte	32
	.byte	12
	.byte	4
	.byte	44
	.byte	52
	.byte	20
	.byte	24
	.byte	48
	.byte	60
	.byte	56
	.byte	40
	.byte	48
	.byte	8
	.byte	32
	.byte	28
	.byte	36
	.byte	4
	.byte	44
	.byte	20
	.byte	56
	.byte	60
	.byte	24
	.byte	52
	.byte	16
	.byte	12
	.byte	12
	.byte	4
	.byte	48
	.byte	20
	.byte	8
	.byte	52
	.byte	16
	.byte	60
	.byte	24
	.byte	36
	.byte	44
	.byte	28
	.byte	56
	.byte	40
	.byte	32
	.byte	36
	.byte	20
	.byte	24
	.byte	60
	.byte	40
	.byte	44
	.byte	52
	.byte	16
	.byte	32
	.byte	4
	.byte	48
	.byte	8
	.byte	28
	.byte	56
	.byte	12
	.byte	28
	.byte	32
	.byte	40
	.byte	52
	.byte	36
	.byte	16
	.byte	20
	.byte	48
	.byte	8
	.byte	4
	.byte	60
	.byte	24
	.byte	56
	.byte	44
	.byte	12
	.byte	8
	.byte	36
	.byte	24
	.byte	28
	.byte	16
	.byte	60
	.byte	20
	.byte	56
	.byte	32
	.byte	40
	.byte	48
	.byte	12
	.byte	4
	.byte	44
	.byte	52
	.byte	44
	.byte	40
	.byte	12
	.byte	56
	.byte	8
	.byte	36
	.byte	24
	.byte	60
	.byte	28
	.byte	48
	.byte	4
	.byte	32
	.byte	20
	.byte	16
	.byte	52
	.byte	60
	.byte	12
	.byte	24
	.byte	36
	.byte	8
	.byte	4
	.byte	16
	.byte	56
	.byte	48
	.byte	44
	.byte	40
	.byte	52
	.byte	32
	.byte	20
	.byte	28
	.byte	32
	.byte	12
	.byte	36
	.byte	28
	.byte	24
	.byte	56
	.byte	40
	.byte	16
	.byte	52
	.byte	44
	.byte	4
	.byte	20
	.byte	60
	.byte	8
	.byte	48
	.byte	48
	.byte	52
	.byte	12
	.byte	20
	.byte	32
	.byte	44
	.byte	36
	.byte	28
	.byte	4
	.byte	40
	.byte	24
	.byte	8
	.byte	56
	.byte	60
	.byte	16
	.byte	36
	.byte	32
	.byte	8
	.byte	40
	.byte	4
	.byte	52
	.byte	24
	.byte	44
	.byte	20
	.byte	12
	.byte	28
	.byte	48
	.byte	56
	.byte	16
	.byte	60
	.byte	4
	.byte	52
	.byte	60
	.byte	48
	.byte	20
	.byte	16
	.byte	56
	.byte	44
	.byte	24
	.byte	8
	.byte	40
	.byte	12
	.byte	32
	.byte	28
	.byte	36
	.byte	24
	.byte	32
	.byte	12
	.byte	4
	.byte	20
	.byte	16
	.byte	60
	.byte	36
	.byte	28
	.byte	8
	.byte	52
	.byte	40
	.byte	48
	.byte	44
	.byte	56

	.globl	_table_2bits
_table_2bits:
	.word	0
	.word	-2
	.word	-4
	.word	-6
	.word	0x03030303
	.word	0x03030303
	.word	0x03030303
	.word	0x03030303

	.globl	_table_4bits
_table_4bits:
	.word	0
	.word	-4
	.word	0
	.word	-4
	.word	0x0f0f0f0f
	.word	0x0f0f0f0f
	.word	0x0f0f0f0f
	.word	0x0f0f0f0f

	.globl	_table_10bits
_table_10bits:
	.word	6
	.word	0
	.word	6
	.word	0
	.word	0
	.word	-20
	.word	0
	.word	-20
	.word	(1023<<16)
	.word	0
	.word	(1023<<16)
	.word	0
	.word	1023
	.word	1023
	.word	1023
	.word	1023
