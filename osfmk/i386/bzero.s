/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

/*
 * void *memset(void * addr, int pattern, size_t length)
 */

ENTRY(memset)
	pushl	%edi
	movl	4+ 4(%esp),%edi		/* addr */
	movb	4+ 8(%esp),%al		/* pattern */
	movl	4+ 12(%esp),%edx	/* length */
	movb	%al,%ah
	movw	%ax,%cx
	shll	$16,%eax
	movw	%cx,%ax	
	cld
/* zero longs */
	movl	%edx,%ecx
	shrl	$2,%ecx
	rep
	stosl
/* zero bytes */
	movl	%edx,%ecx
	andl	$3,%ecx
	rep
	stosb
	movl	4+ 4(%esp),%eax		/* returns its first argument */
	popl	%edi
	ret

/*
 * void bzero(char * addr, unsigned int length)
 */
Entry(blkclr)
ENTRY(bzero)
	pushl	%edi
	movl	4+ 4(%esp),%edi		/* addr */
	movl	4+ 8(%esp),%edx		/* length */
	xorl	%eax,%eax
	cld
/* zero longs */
	movl	%edx,%ecx
	shrl	$2,%ecx
	rep
	stosl
/* zero bytes */
	movl	%edx,%ecx
	andl	$3,%ecx
	rep
	stosb
	popl	%edi
	ret
