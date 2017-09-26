/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#include <arm64/asm.h>

#if ALTERNATE_DEBUGGER
	.text
/* void alternate_debugger_just_return(__unused mach_vm_size_t size, __unused mach_vm_address_t pages, __unused mach_vm_size_t pages_size, t_putc_fn putc_address) */
	.align 2
	.globl EXT(alternate_debugger_just_return)
LEXT(alternate_debugger_just_return)
	sub		sp, sp, #0x20 
	stp		x29, x30, [sp, #0x10]
	add		x29, sp, #0x10 
	str		x3, [sp, #0x8]
	mov		w0, #0xa
	mov		x1, x3
	blr		x1				// (*putc_address)('\n');
	orr		w0, wzr, #0x3e
	ldr		x1, [sp, #0x8]
	blr		x1				// (*putc_address)('>');
	mov		w0, #0x4d
	ldr		x1, [sp, #0x8]
	blr		x1				// (*putc_address)('M');
	mov		w0, #0x54
	ldr		x1, [sp, #0x8]
	blr		x1				// (*putc_address)('T');
	orr		w0, wzr, #0x3c
	ldr		x1, [sp, #0x8]
	blr		x1				// (*putc_address)('<');
	mov		w0, #0xa
	ldr		x1, [sp, #0x8]
	ldp		x29, x30, [sp, #0x10]
	add		sp, sp, #0x20 
	br		x1				// (*putc_address)('\n');
	.align 2
	.globl EXT(alternate_debugger_just_return_end)
LEXT(alternate_debugger_just_return_end)

#endif /* ALTERNATE_DEBUGGER */
