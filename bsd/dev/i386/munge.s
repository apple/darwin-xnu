/*
 * Coyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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
 *	void	munge_XXXX( const void *regs, void *uu_args);
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
	movl	8(%esp),%ecx	// get &uu_args
	movl	$0,4(%ecx)
	ret
	
ENTRY(munge_ww)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	jmp	Lw2
ENTRY(munge_www)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	jmp	Lw3
ENTRY(munge_wwww)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	jmp	Lw4
ENTRY(munge_wwwww)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	jmp	Lw5
ENTRY(munge_wwwwww)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	jmp	Lw6
ENTRY(munge_wwwwwww)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	jmp	Lw7
ENTRY(munge_wwwwwwww)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	movl	28(%ecx),%eax
	movl	%eax,56(%ecx)
	movl	%edx,60(%ecx)
Lw7:
	movl	24(%ecx),%eax
	movl	%eax,48(%ecx)
	movl	%edx,52(%ecx)
Lw6:
	movl	20(%ecx),%eax
	movl	%eax,40(%ecx)
	movl	%edx,44(%ecx)
Lw5:
	movl	16(%ecx),%eax
	movl	%eax,32(%ecx)
	movl	%edx,36(%ecx)
Lw4:
	movl	12(%ecx),%eax
	movl	%eax,24(%ecx)
	movl	%edx,28(%ecx)
Lw3:
	movl	8(%ecx),%eax
	movl	%eax,16(%ecx)
	movl	%edx,20(%ecx)
Lw2:
	movl	4(%ecx),%eax
	movl	%eax,8(%ecx)
	movl	%edx,12(%ecx)
	movl	%edx,4(%ecx)
	ret


Entry(munge_wl)			/* Costs an extra w move to do this */
ENTRY(munge_wlw)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	movl	12(%ecx),%eax
	movl	%eax,16(%ecx)
	movl	%edx,20(%ecx)
	movl	8(%ecx),%eax
	movl	%eax,12(%ecx)
	movl	4(%ecx),%eax
	movl	%eax,8(%ecx)
	movl	%edx,4(%ecx)
	ret

ENTRY(munge_wwwl)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	movl	12(%ecx),%eax
	movl	%eax,24(%ecx)
	movl	16(%ecx),%eax
	movl	%eax,28(%ecx)
	jmp	Lw3

ENTRY(munge_wwwwl)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	movl	16(%ecx),%eax
	movl	%eax,32(%ecx)
	movl	20(%ecx),%eax
	movl	%eax,36(%ecx)
	jmp	Lw4

ENTRY(munge_wwwwwl)
	movl	8(%esp),%ecx	// get &uu_args
	xorl	%edx,%edx
	movl	20(%ecx),%eax
	movl	%eax,40(%ecx)
	movl	24(%ecx),%eax
	movl	%eax,44(%ecx)
	jmp	Lw5

ENTRY(munge_wsw)
	movl	8(%esp),%ecx	// get &uu_args
	movl	8(%ecx),%eax
	movl	%eax,16(%ecx)
	movl	$0,20(%ecx)
	movl	4(%ecx),%eax
	cltd
	movl	%eax,8(%ecx)
	movl	%edx,12(%ecx)
	movl	$0,4(%ecx)
	ret

ENTRY(munge_wws)
	movl	8(%esp),%ecx	// get &uu_args
	movl	8(%ecx),%eax
	cltd
	movl	%eax,16(%ecx)
	movl	%edx,20(%ecx)
	xorl	%edx,%edx
	jmp	Lw2

ENTRY(munge_wwwsw)
	movl	8(%esp),%ecx	// get &uu_args
	movl	16(%ecx),%eax
	movl	%eax,32(%ecx)
	movl	$0,36(%ecx)
	movl	12(%ecx),%eax
	cltd
	movl	%eax,24(%ecx)
	movl	%edx,28(%ecx)
	xorl	%edx,%edx
	jmp	Lw3
