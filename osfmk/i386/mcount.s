/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#define __NO_UNDERSCORES__
#include <i386/asm.h>
#include <assym.s>

Entry(mcount)
        pushl   %ebp            	// setup mcount's frame
        movl    %esp,%ebp
        pushl	%eax			// save %eax
        pushf				// save interrupt state
        cli				// disable interrupts

	//
	// Check that this cpu is ready.
	// This delays the start of mcounting until a cpu is really prepared.
	//
        movl	%gs:CPU_RUNNING,%eax
        testl	%eax,%eax
	jz	1f

	//
	// Test for recursion as indicated by a per-cpu flag.
	// Skip if nested, otherwise set the flag and call the C mount().
	//
        movl	%gs:CPU_MCOUNT_OFF,%eax
        testl	%eax,%eax		// test for recursion
        jnz	1f

        incl	%gs:CPU_MCOUNT_OFF	// set recursion flag

        movl    (%ebp),%eax     	// frame pointer of mcount's caller
        movl    4(%eax),%eax    	// mcount's caller's return address
        pushl   4(%ebp)         	// push selfpc parameter for mcount()
        pushl   %eax            	// push frompc parameter for mcount()
        call	_mcount			// call the C mcount
	addl	$8,%esp			// pop args

        decl	%gs:CPU_MCOUNT_OFF	// turn off recursion flag
1:
        popf				// restore interrupt state
        popl	%eax
        movl    %ebp,%esp       	// tear down mcount's frame
        popl    %ebp
        ret
