/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 * Copyright (c) 1994 The University of Utah and
 * the Computer Systems Laboratory at the University of Utah (CSL).
 * All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software is hereby
 * granted provided that (1) source code retains these copyright, permission,
 * and disclaimer notices, and (2) redistributions including binaries
 * reproduce the notices in supporting documentation, and (3) all advertising
 * materials mentioning features or use of this software display the following
 * acknowledgement: ``This product includes software developed by the
 * Computer Systems Laboratory at the University of Utah.''
 *
 * THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSL DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 */

/*
 *	File:	vm_param.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1985
 *
 *	I386 machine dependent virtual memory parameters.
 *	Most of the declarations are preceeded by I386_ (or i386_)
 *	which is OK because only I386 specific code will be using
 *	them.
 */

#ifndef	_MACH_I386_VM_PARAM_H_
#define _MACH_I386_VM_PARAM_H_

#define BYTE_SIZE	8	/* byte size in bits */

#define I386_PGBYTES	4096	/* bytes per 80386 page */
#define I386_PGSHIFT	12	/* number of bits to shift for pages */

/*
 *	Convert bytes to pages and convert pages to bytes.
 *	No rounding is used.
 */

#define i386_btop(x)		(((unsigned)(x)) >> I386_PGSHIFT)
#define machine_btop(x)		i386_btop(x)
#define i386_ptob(x)		(((unsigned)(x)) << I386_PGSHIFT)

/*
 *	Round off or truncate to the nearest page.  These will work
 *	for either addresses or counts.  (i.e. 1 byte rounds to 1 page
 *	bytes.
 */

#define i386_round_page(x)	((((unsigned)(x)) + I386_PGBYTES - 1) & \
					~(I386_PGBYTES-1))
#define i386_trunc_page(x)	(((unsigned)(x)) & ~(I386_PGBYTES-1))

#define VM_MAX_PAGE_ADDRESS     0x00000000C0000000ULL

#define VM_MIN_ADDRESS		((vm_offset_t) 0)
#define VM_MAX_ADDRESS		((vm_offset_t) (VM_MAX_PAGE_ADDRESS & 0xFFFFFFFF))

#define LINEAR_KERNEL_ADDRESS	((vm_offset_t) 0xc0000000)

#define VM_MIN_KERNEL_ADDRESS	((vm_offset_t) 0x00000000U)
#define VM_MAX_KERNEL_ADDRESS	((vm_offset_t) 0x3fffffffU)

#define VM_MIN_KERNEL_LOADED_ADDRESS	((vm_offset_t) 0x0c000000U)
#define VM_MAX_KERNEL_LOADED_ADDRESS	((vm_offset_t) 0x1fffffffU)

/* FIXME  - always leave like this? */
#define	INTSTACK_SIZE	(I386_PGBYTES*4)
#define	KERNEL_STACK_SIZE	(I386_PGBYTES*4)

/*
 *	Conversion between 80386 pages and VM pages
 */

#define trunc_i386_to_vm(p)	(atop(trunc_page(i386_ptob(p))))
#define round_i386_to_vm(p)	(atop(round_page(i386_ptob(p))))
#define vm_to_i386(p)		(i386_btop(ptoa(p)))

/*
 *	Physical memory is mapped 1-1 with virtual memory starting
 *	at VM_MIN_KERNEL_ADDRESS.
 */
#define phystokv(a)	((vm_offset_t)(a) + VM_MIN_KERNEL_ADDRESS)

/*
 *	For 386 only, ensure that pages are installed in the
 *	kernel_pmap with VM_PROT_WRITE enabled.  This avoids
 *	code in pmap_enter that disallows a read-only mapping
 *	in the kernel's pmap.  (See ri-osc CR1387.)
 *
 *	An entry in kernel_pmap is made only by the kernel or
 *	a collocated server -- by definition (;-)), the requester
 *	is trusted code.  If it asked for read-only access,
 *	it won't attempt a write.  We don't have to enforce the
 *	restriction.  (Naturally, this assumes that any collocated
 *	server will _not_ depend on trapping write accesses to pages
 *	mapped read-only; this cannot be made to work in the current
 *	i386-inspired pmap model.)
 */

/*#if defined(AT386)

#define PMAP_ENTER_386_CHECK \
	if (cpuid_family == CPUID_FAMILY_386)

#else -- FIXME? We're only running on Pentiums or better */

#define PMAP_ENTER_386_CHECK

/*#endif*/

#define PMAP_ENTER(pmap, virtual_address, page, protection, flags, wired) \
	MACRO_BEGIN					\
	vm_prot_t __prot__ =				\
		(protection) & ~(page)->page_lock;	\
							\
    	PMAP_ENTER_386_CHECK				\
	if ((pmap) == kernel_pmap)			\
		__prot__ |= VM_PROT_WRITE;		\
	pmap_enter(					\
		(pmap),					\
		(virtual_address),			\
		(page)->phys_page,			\
		__prot__,				\
		flags,					\
		(wired)					\
	 );						\
	MACRO_END

#endif	/* _MACH_I386_VM_PARAM_H_ */
