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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#include <i386/asm.h>

/* void *memcpy((void *) to, (const void *) from, (size_t) bcount) */

ENTRY(memcpy)
	pushl	%edi
	pushl	%esi
	movl	8+ 4(%esp),%edi		/* to */
	movl	%edi,%eax		/* returns its first argument */
	movl	8+ 8(%esp),%esi		/* from */
memcpy_common:
	movl	8+ 12(%esp),%edx	/* number of bytes */
	cld
/* move longs*/
	movl	%edx,%ecx
	sarl	$2,%ecx
	rep
	movsl
/* move bytes*/
	movl	%edx,%ecx
	andl	$3,%ecx
	rep
	movsb
	popl	%esi
	popl	%edi
	ret

/* void bcopy((const char *) from, (char *) to, (unsigned int) count) */

ENTRY(bcopy_no_overwrite)
	pushl	%edi
	pushl	%esi
	movl	8+ 8(%esp),%edi		/* to */
	movl	8+ 4(%esp),%esi		/* from */
	jmp	memcpy_common

/* bcopy16(from, to, bcount) using word moves */

ENTRY(bcopy16)
	pushl	%edi
	pushl	%esi
 	movl	8+12(%esp),%edx		/*  8 for the two pushes above */
 	movl	8+ 8(%esp),%edi
 	movl	8+ 4(%esp),%esi
/* move words */
0:	cld
	movl	%edx,%ecx
	sarl	$1,%ecx
	rep
	movsw
/* move bytes */
	movl	%edx,%ecx
	andl	$1,%ecx
	rep
	movsb
	popl	%esi
	popl	%edi
	ret	

