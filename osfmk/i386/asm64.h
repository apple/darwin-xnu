/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

/* Helper macros for 64-bit mode switching */

/*
 * Long jump to 64-bit space from 32-bit compatibility mode.
 */
#define	ENTER_64BIT_MODE()			\
	.code32					;\
	.byte   0xea	/* far jump longmode */	;\
	.long   1f				;\
	.word   KERNEL64_CS			;\
        .code64					;\
1:

/*
 * Here in long mode but still running below 4G.
 * "Near" jump into uber-space.
 */
#define	ENTER_UBERSPACE()			\
        mov     2f,%rax				;\
        jmp     *%rax				;\
2:      .long   3f				;\
        .long   KERNEL_UBER_BASE_HI32		;\
3:     

/*
 * Long jump to 32-bit compatibility mode from 64-bit space.
 */
#define ENTER_COMPAT_MODE()			\
	ljmp	*(%rip)				;\
	.long	4f				;\
	.word	KERNEL_CS			;\
	.code32					;\
4:

