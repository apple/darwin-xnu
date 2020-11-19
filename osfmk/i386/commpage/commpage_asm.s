/*
 * Copyright (c) 2003-2012 Apple Inc. All rights reserved.
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

#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/asm.h>
#include <assym.s>

/* pointers to the 32-bit commpage routine descriptors */
/* WARNING: these must be sorted by commpage address! */
	.const_data
	.align	3
	.globl	_commpage_32_routines
_commpage_32_routines:
	COMMPAGE_DESCRIPTOR_REFERENCE(preempt)
	COMMPAGE_DESCRIPTOR_REFERENCE(backoff)
	COMMPAGE_DESCRIPTOR_REFERENCE(ret)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_enqueue)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_dequeue)
	.quad	0


/* pointers to the 64-bit commpage routine descriptors */
/* WARNING: these must be sorted by commpage address! */
	.const_data
	.align	3
	.globl	_commpage_64_routines
_commpage_64_routines:
	COMMPAGE_DESCRIPTOR_REFERENCE(preempt_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(backoff_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(ret_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_enqueue_64)
	COMMPAGE_DESCRIPTOR_REFERENCE(pfz_dequeue_64)
	.quad	0

