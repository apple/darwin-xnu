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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
#include <string.h>

#include <mach/vm_param.h>
#include <mach/boolean.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <kern/misc_protos.h>

/*
 *	pmap_zero_page zeros the specified (machine independent) page.
 */
void
pmap_zero_page(
	       ppnum_t pn)
{
        vm_offset_t p;
	assert(pn != vm_page_fictitious_addr);
	p = (vm_offset_t)i386_ptob(pn);
	bzero((char *)phystokv(p), PAGE_SIZE);
}

/*
 *	pmap_zero_part_page
 *	zeros the specified (machine independent) part of a page.
 */
void
pmap_zero_part_page(
        ppnum_t         pn,
	vm_offset_t     offset,
	vm_size_t       len)
{
	assert(pn != vm_page_fictitious_addr);
	assert(offset + len <= PAGE_SIZE);
	bzero((char *)phystokv(i386_ptob(pn)) + offset, len);
}

/*
 *	pmap_copy_page copies the specified (machine independent) pages.
 */
void
pmap_copy_page(
       ppnum_t  psrc,
       ppnum_t  pdst)

{
        vm_offset_t src,dst;

	assert(psrc != vm_page_fictitious_addr);
	assert(pdst != vm_page_fictitious_addr);
	src = (vm_offset_t)i386_ptob(psrc);
	dst = (vm_offset_t)i386_ptob(pdst);

	memcpy((void *)phystokv(dst), (void *)phystokv(src), PAGE_SIZE);
}

/*
 *	pmap_copy_page copies the specified (machine independent) pages.
 */
void
pmap_copy_part_page(
	ppnum_t 	psrc,
	vm_offset_t	src_offset,
	ppnum_t	        pdst,
	vm_offset_t	dst_offset,
	vm_size_t	len)
{
        vm_offset_t  src, dst;

	assert(psrc != vm_page_fictitious_addr);
	assert(pdst != vm_page_fictitious_addr);
	src = (vm_offset_t)i386_ptob(psrc);
	dst = (vm_offset_t)i386_ptob(pdst);
	assert(((dst & PAGE_MASK) + dst_offset + len) <= PAGE_SIZE);
	assert(((src & PAGE_MASK) + src_offset + len) <= PAGE_SIZE);

        memcpy((void *)(phystokv(dst) + dst_offset),
	       (void *)(phystokv(src) + src_offset), len);
}

/*
 *      pmap_copy_part_lpage copies part of a virtually addressed page 
 *      to a physically addressed page.
 */
void
pmap_copy_part_lpage(
	vm_offset_t 	src,
	ppnum_t 	pdst,
	vm_offset_t	dst_offset,
	vm_size_t	len)
{
        vm_offset_t dst;

	assert(src != vm_page_fictitious_addr);
	assert(pdst != vm_page_fictitious_addr);
	dst = (vm_offset_t)i386_ptob(pdst);
	assert(((dst & PAGE_MASK) + dst_offset + len) <= PAGE_SIZE);

        memcpy((void *)(phystokv(dst) + dst_offset), (void *)src, len);
}

/*
 *      pmap_copy_part_rpage copies part of a physically addressed page 
 *      to a virtually addressed page.
 */
void
pmap_copy_part_rpage(
	ppnum_t	        psrc,
	vm_offset_t	src_offset,
	vm_offset_t	dst,
	vm_size_t	len)
{
        vm_offset_t src;

	assert(psrc != vm_page_fictitious_addr);
	assert(dst != vm_page_fictitious_addr);
	src = (vm_offset_t)i386_ptob(psrc);
	assert(((src & PAGE_MASK) + src_offset + len) <= PAGE_SIZE);

        memcpy((void *)dst, (void *)(phystokv(src) + src_offset), len);
}

/*
 *	kvtophys(addr)
 *
 *	Convert a kernel virtual address to a physical address
 */
vm_offset_t
kvtophys(
	vm_offset_t addr)
{
	pt_entry_t *pte;

	if ((pte = pmap_pte(kernel_pmap, addr)) == PT_ENTRY_NULL)
		return 0;
	return i386_trunc_page(*pte) | (addr & INTEL_OFFMASK);
}
