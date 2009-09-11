/*
 * Coyright (c) 2005-2008 Apple Computer, Inc. All rights reserved.
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
 * Syscall argument mungers.
 *
 * The data to be munged has been explicitly copied in to the argument area,
 * and will be munged in place in the uu_arg[] array.  Because of this, the
 * functions all take the same arguments as their PPC equivalents, but the
 * first argument is ignored.  These mungers are for 32-bit app's syscalls,
 * since 64-bit args are stored into the save area (which overlays the
 * uu_args) in the order the syscall ABI calls for.
 *
 * The issue is that the incoming args are 32-bit, but we must expand
 * them in place into 64-bit args, as if they were from a 64-bit process.
 *
 * There are several functions in this file.  Each takes two parameters:
 *
 *	void	munge_XXXX(const void *regs,		// %rdi
 *			   void       *uu_args);	// %rsi
 *
 * The name of the function encodes the number and type of the parameters,
 * as follows:
 *
 *	w = a 32-bit value such as an int or a 32-bit ptr, that does not
 *	    require sign extension.  These are handled by zeroing a word
 *          of output, and copying a word from input to output.
 *
 *	s = a 32-bit value such as a long, which must be sign-extended to
 *	    a 64-bit long-long in the uu_args.  These are handled by
 *	    loading a word of input and sign extending it to a double,
 *          and storing two words of output.
 *
 *	l = a 64-bit long-long.  These are handled by copying two words
 *          of input to the output.
 *
 * For example, "munge_wls" takes a word, a long-long, and a word.  This
 * takes four words in the uu_arg[] area: the first word is in one, the
 * long-long takes two, and the final word is in the fourth.  We store six
 * words: the low word is left in place, followed by a 0, followed by the
 * two words of the long-long, followed by the low word and the sign extended
 * high word of the preceeding low word.
 *
 * Because this is an in-place modification, we actually start at the end
 * of uu_arg[] and work our way back to the beginning of the array.
 *
 * As you can see, we save a lot of code by collapsing mungers that are
 * prefixes or suffixes of each other.
 */
#include <i386/asm.h>

ENTRY(munge_w)
	movl	$0,4(%rsi)
	ret
	
ENTRY(munge_ww)
	xorl	%edx,%edx
	jmp	Lw2
ENTRY(munge_www)
	xorl	%edx,%edx
	jmp	Lw3
ENTRY(munge_wwww)
	xorl	%edx,%edx
	jmp	Lw4
ENTRY(munge_wwwww)
	xorl	%edx,%edx
	jmp	Lw5
ENTRY(munge_wwwwww)
	xorl	%edx,%edx
	jmp	Lw6
ENTRY(munge_wwwwwww)
	xorl	%edx,%edx
	jmp	Lw7
ENTRY(munge_wwwwwwww)
	xorl	%edx,%edx
	movl	28(%rsi),%eax
	movl	%eax,56(%rsi)
	movl	%edx,60(%rsi)
Lw7:
	movl	24(%rsi),%eax
	movl	%eax,48(%rsi)
	movl	%edx,52(%rsi)
Lw6:
	movl	20(%rsi),%eax
	movl	%eax,40(%rsi)
	movl	%edx,44(%rsi)
Lw5:
	movl	16(%rsi),%eax
	movl	%eax,32(%rsi)
	movl	%edx,36(%rsi)
Lw4:
	movl	12(%rsi),%eax
	movl	%eax,24(%rsi)
	movl	%edx,28(%rsi)
Lw3:
	movl	8(%rsi),%eax
	movl	%eax,16(%rsi)
	movl	%edx,20(%rsi)
Lw2:
	movl	4(%rsi),%eax
	movl	%eax,8(%rsi)
	movl	%edx,12(%rsi)
	movl	%edx,4(%rsi)
	ret


Entry(munge_wl)			/* Costs an extra w move to do this */
ENTRY(munge_wlw)
	xorl	%edx,%edx
	movl	12(%rsi),%eax
	movl	%eax,16(%rsi)
	movl	%edx,20(%rsi)
	movl	8(%rsi),%eax
	movl	%eax,12(%rsi)
	movl	4(%rsi),%eax
	movl	%eax,8(%rsi)
	movl	%edx,4(%rsi)
	ret

Entry(munge_wwwlw)
	xorl	%edx,%edx
	movl	20(%rsi),%eax
	movl	%eax,32(%rsi)
	movl	%edx,36(%rsi)
	jmp Lwwwl


ENTRY(munge_wwwl)
	xorl	%edx,%edx
Lwwwl:
	movl	12(%rsi),%eax
	movl	%eax,24(%rsi)
	movl	16(%rsi),%eax
	movl	%eax,28(%rsi)
	jmp	Lw3

ENTRY(munge_wwwwlw)
	xorl	%edx,%edx
	movl	24(%rsi),%eax
	movl	%eax,40(%rsi)
	movl	%edx,44(%rsi)
	jmp	Lwwwwl

ENTRY(munge_wwwwl)
	xorl	%edx,%edx
Lwwwwl:
	movl	16(%rsi),%eax
	movl	%eax,32(%rsi)
	movl	20(%rsi),%eax
	movl	%eax,36(%rsi)
	jmp	Lw4

ENTRY(munge_wwwwwl)
	xorl	%edx,%edx
	movl	20(%rsi),%eax
	movl	%eax,40(%rsi)
	movl	24(%rsi),%eax
	movl	%eax,44(%rsi)
	jmp	Lw5

ENTRY(munge_wwwwwwlw)
	xorl	%edx,%edx
	movl	32(%rsi),%eax
	movl	%eax,56(%rsi)
	movl	%edx,60(%rsi)
	movl	24(%rsi),%eax
	movl	%eax,48(%rsi)
	movl	28(%rsi),%eax
	movl	%eax,52(%rsi)
	jmp	Lw6

ENTRY(munge_wwwwwwll)
	xorl	%edx,%edx
	movl	32(%rsi),%eax
	movl	%eax,56(%rsi)
	movl	36(%rsi),%eax
	movl	%eax,60(%rsi)
	movl	24(%rsi),%eax
	movl	%eax,48(%rsi)
	movl	28(%rsi),%eax
	movl	%eax,52(%rsi)
	jmp	Lw6

ENTRY(munge_wsw)
	movl	8(%rsi),%eax
	movl	%eax,16(%rsi)
	movl	$0,20(%rsi)
	movl	4(%rsi),%eax
	cltd
	movl	%eax,8(%rsi)
	movl	%edx,12(%rsi)
	movl	$0,4(%rsi)
	ret

ENTRY(munge_wws)
	movl	8(%rsi),%eax
	cltd
	movl	%eax,16(%rsi)
	movl	%edx,20(%rsi)
	xorl	%edx,%edx
	jmp	Lw2

ENTRY(munge_wwwsw)
	movl	16(%rsi),%eax
	movl	%eax,32(%rsi)
	movl	$0,36(%rsi)
	movl	12(%rsi),%eax
	cltd
	movl	%eax,24(%rsi)
	movl	%edx,28(%rsi)
	xorl	%edx,%edx
	jmp	Lw3

ENTRY(munge_llllll)
	ret						// nothing to do here, either - all args are already
							// 64-bit and do not require sign/zero extension
							// also, there is no mixing in of shorter args that
							// do need extension
