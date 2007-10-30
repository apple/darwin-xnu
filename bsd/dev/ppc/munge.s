/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

/*
 *  Syscall argument mungers.
 *
 *  Passed a pointer to the users register array in the savearea, we copy args into
 *  the uu_arg[] array, padding etc as appropriate.  The issue is that parameters
 *  passed in registers from a 32-bit address space do not map directly into the uu_args.
 *  For example, a 32-bit long-long comes in two registers, but we need to combine
 *  them into one 64-bit long-long in the uu_args.
 *
 *  There are several functions in this file.  Each takes two parameters:
 *
 *      void    munge_XXXX( const void *regs, void *uu_args);
 *
 *  The name of the function encodes the number and type of the parameters, as follows:
 *
 *      w = a 32-bit value such as an int or a 32-bit ptr, that does not require
 *          sign extension.  These are handled by skipping a word in the input,
 *          zeroing a word of output, and copying a word from input to output.
 *
 *      s = a 32-bit value such as a long, which must be sign-extended to a 64-bit
 *          long-long in the uu_args.  These are handled by skipping a word of
 *          input, loading a word of input and sign extending it to a double,
 *          and storing two words of output.
 *
 *      l = a 64-bit long-long, passed in two registers.  These are handled by skipping
 *          a word of input, copying a word, skipping another word of input, and
 *          copying another word.
 *
 *      d = a 32-bit int or a 64-bit ptr or long, passed in via a 64-bit GPR 
 *          from a 64-bit process.  We copy two words from input to output.
 *
 *  For example, "munge_wls" takes a word, a long-long, and a word.  This takes
 *  four registers: the first word is in one, the long-long takes two, and the
 *  final word is in the fourth.  We store six words: a 0, the low words of the
 *  first three registers, and the two words resulting from sign-extending the
 *  low word of the fourth register.
 *
 *  As you can see, we save a lot of code by collapsing mungers that are prefixes
 *  of each other, into the more general routine.  This ends up copying a few extra
 *  bytes of parameters, but big deal.  The old kernel copied all eight words for
 *  every system call.
 *
 *  These routines assume explicit pad words in the uu_arg structures, that fill out
 *  int parameters to 64 bits.  Having pad words makes munging args for 64-bit
 *  processes the equivalent of a simple bcopy(), though it does introduce an
 *  endian dependency.
 */

        .align  5
        .globl  _munge_dddddddd        // that is 8 'd's
_munge_dddddddd:
        .globl  _munge_ddddddd
_munge_ddddddd:
        .globl  _munge_dddddd
_munge_dddddd:
        .globl  _munge_ddddd
_munge_ddddd:
        ld     r5,0*8+0(r3)
        ld     r6,1*8+0(r3)
        ld     r7,2*8+0(r3)
        ld     r8,3*8+0(r3)
        ld     r9,4*8+0(r3)
        ld     r10,5*8+0(r3)
        ld     r11,6*8+0(r3)
        ld     r12,7*8+0(r3)
        
        std     r5,0*8+0(r4)
        std     r6,1*8+0(r4)
        std     r7,2*8+0(r4)
        std     r8,3*8+0(r4)
        std     r9,4*8+0(r4)
        std     r10,5*8+0(r4)
        std     r11,6*8+0(r4)
        std     r12,7*8+0(r4)
        
        blr


        .align  5
        .globl  _munge_dddd
_munge_dddd:
        .globl  _munge_ddd
_munge_ddd:
        .globl  _munge_dd
_munge_dd:
        .globl  _munge_d
_munge_d:
        ld     r5,0*8+0(r3)
        ld     r6,1*8+0(r3)
        ld     r7,2*8+0(r3)
        ld     r8,3*8+0(r3)
        
        std     r5,0*8+0(r4)
        std     r6,1*8+0(r4)
        std     r7,2*8+0(r4)
        std     r8,3*8+0(r4)
        
        blr


        .align  5
        .globl  _munge_wwwwwwww        // that is 8 'w's
_munge_wwwwwwww:
        .globl  _munge_wwwwwww
_munge_wwwwwww:
        .globl  _munge_wwwwww
_munge_wwwwww:
        .globl  _munge_wwwww
_munge_wwwww:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        lwz     r8,3*8+4(r3)
        lwz     r9,4*8+4(r3)
        lwz     r10,5*8+4(r3)
        lwz     r11,6*8+4(r3)
        lwz     r12,7*8+4(r3)
        
        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r0,1*8+0(r4)
        stw     r6,1*8+4(r4)
        stw     r0,2*8+0(r4)
        stw     r7,2*8+4(r4)
        stw     r0,3*8+0(r4)
        stw     r8,3*8+4(r4)
        stw     r0,4*8+0(r4)
        stw     r9,4*8+4(r4)
        stw     r0,5*8+0(r4)
        stw     r10,5*8+4(r4)
        stw     r0,6*8+0(r4)
        stw     r11,6*8+4(r4)
        stw     r0,7*8+0(r4)
        stw     r12,7*8+4(r4)
        
        blr


        .align  5
        .globl  _munge_wwww
_munge_wwww:
        .globl  _munge_www
_munge_www:
        .globl  _munge_ww
_munge_ww:
        .globl  _munge_w
_munge_w:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        lwz     r8,3*8+4(r3)
        
        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r0,1*8+0(r4)
        stw     r6,1*8+4(r4)
        stw     r0,2*8+0(r4)
        stw     r7,2*8+4(r4)
        stw     r0,3*8+0(r4)
        stw     r8,3*8+4(r4)
        
        blr

        .align	5
	.globl	_munge_l
_munge_l:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)

        stw     r5,0*8+0(r4)
        stw     r6,0*8+4(r4)
        
        blr
        
        .align  5
        .globl  _munge_wlw
_munge_wlw:
        .globl  _munge_wl
_munge_wl:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        lwz     r8,3*8+4(r3)

        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r6,1*8+0(r4)
        stw     r7,1*8+4(r4)
        stw     r0,2*8+0(r4)
        stw     r8,2*8+4(r4)
        
        blr


        .align  5
        .globl  _munge_wwwl
_munge_wwwl:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        lwz     r8,3*8+4(r3)
        lwz     r9,4*8+4(r3)
        
        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r0,1*8+0(r4)
        stw     r6,1*8+4(r4)
        stw     r0,2*8+0(r4)
        stw     r7,2*8+4(r4)
        stw     r8,3*8+0(r4)
        stw     r9,3*8+4(r4)
        
        blr


        .align  5
        .globl  _munge_wwwlww
_munge_wwwlww:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        lwz     r8,3*8+4(r3)
        lwz     r9,4*8+4(r3)
        lwz     r10,5*8+4(r3)
        lwz     r11,6*8+4(r3)
        
        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r0,1*8+0(r4)
        stw     r6,1*8+4(r4)
        stw     r0,2*8+0(r4)
        stw     r7,2*8+4(r4)
        stw     r8,3*8+0(r4)
        stw     r9,3*8+4(r4)
        stw     r0,4*8+0(r4)
        stw     r10,4*8+4(r4)
        stw     r0,5*8+0(r4)
        stw     r11,5*8+4(r4)
        
        blr


        .align  5
        .globl  _munge_wwlwww
_munge_wwlwww:
        li      r0,0
        lwz     r5,0*8+4(r3)	// Wwlwww
        lwz     r6,1*8+4(r3)	// wWlwww
        lwz     r7,2*8+4(r3)	// wwLwww (hi)
        lwz     r8,3*8+4(r3)	// wwLwww (lo)
        lwz     r9,4*8+4(r3)	// wwlWww
        lwz     r10,5*8+4(r3)	// wwlwWw
        lwz     r11,6*8+4(r3)	// wwlwwW
        
        stw     r0,0*8+0(r4)	// 0wlwww
        stw     r5,0*8+4(r4)	// Wwlwww
        stw     r0,1*8+0(r4)	// w0lwww
        stw     r6,1*8+4(r4)	// wWlwww
        stw     r7,2*8+0(r4)	// wwLwww (hi)
        stw     r8,2*8+4(r4)	// wwLwww (lo)
        stw     r0,3*8+0(r4)	// wwl0ww 
        stw     r9,3*8+4(r4)	// wwlwww
        stw     r0, 4*8+0(r4)	// wwlw0w
        stw     r10,4*8+4(r4)	// wwlwWw
        stw     r0, 5*8+0(r4)	// wwlww0
        stw     r11,5*8+4(r4)	// wwlwwW
        
        blr


        .align  5
        .globl  _munge_wwwwl	// 4 'w's and an l
_munge_wwwwl:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        lwz     r8,3*8+4(r3)
        lwz     r9,4*8+4(r3)
        lwz     r10,5*8+4(r3)
        
        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r0,1*8+0(r4)
        stw     r6,1*8+4(r4)
        stw     r0,2*8+0(r4)
        stw     r7,2*8+4(r4)
        stw     r0,3*8+0(r4)
        stw     r8,3*8+4(r4)
        stw     r9,4*8+0(r4)
        stw     r10,4*8+4(r4)
        
        blr


        .align  5
        .globl  _munge_wwwwwl      // 5 'w's and an l
_munge_wwwwwl:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        lwz     r8,3*8+4(r3)
        lwz     r9,4*8+4(r3)
        lwz     r10,5*8+4(r3)
        lwz     r11,6*8+4(r3)
        
        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r0,1*8+0(r4)
        stw     r6,1*8+4(r4)
        stw     r0,2*8+0(r4)
        stw     r7,2*8+4(r4)
        stw     r0,3*8+0(r4)
        stw     r8,3*8+4(r4)
        stw     r0,4*8+0(r4)
        stw     r9,4*8+4(r4)
        stw     r10,5*8+0(r4)
        stw     r11,5*8+4(r4)
        
        blr
        
        
        .align  5
        .globl  _munge_wsw
_munge_wsw:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)

        stw     r0,0*8+0(r4)
        srawi   r2,r6,31
        stw     r5,0*8+4(r4)
        stw     r2,1*8+0(r4)
        stw     r6,1*8+4(r4)
        stw     r0,2*8+0(r4)
        stw     r7,2*8+4(r4)

        blr
        
        
        .align  5
        .globl  _munge_wws
_munge_wws:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        
        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r0,1*8+0(r4)
        srawi   r2,r7,31
        stw     r6,1*8+4(r4)
        stw     r2,2*8+0(r4)
        stw     r7,2*8+4(r4)

        blr


        .align  5
        .globl  _munge_wwwsw
_munge_wwwsw:
        li      r0,0
        lwz     r5,0*8+4(r3)
        lwz     r6,1*8+4(r3)
        lwz     r7,2*8+4(r3)
        lwz     r8,3*8+4(r3)
        lwz     r9,4*8+4(r3)
                
        stw     r0,0*8+0(r4)
        stw     r5,0*8+4(r4)
        stw     r0,1*8+0(r4)
        stw     r6,1*8+4(r4)
        srawi   r2,r8,31
        stw     r0,2*8+0(r4)
        stw     r7,2*8+4(r4)
        stw     r2,3*8+0(r4)
        stw     r8,3*8+4(r4)
        stw     r0,4*8+0(r4)
        stw     r9,4*8+4(r4)

        blr
