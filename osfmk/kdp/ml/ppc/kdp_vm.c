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
#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>

#include <vm/pmap.h>
 
#include <ppc/proc_reg.h>
#include <ppc/machparam.h>
#include <ppc/mem.h>
#include <ppc/pmap.h>
#include <ppc/mappings.h> 

pmap_t kdp_pmap=0;
boolean_t kdp_trans_off=0;
boolean_t kdp_read_io  =0;

unsigned kdp_vm_read( caddr_t, caddr_t, unsigned);
unsigned kdp_vm_write( caddr_t, caddr_t, unsigned);


/*
 *
 */
addr64_t kdp_vtophys(
	pmap_t pmap,
	addr64_t va)
{
	addr64_t    pa;
	ppnum_t pp;

	pp = pmap_find_phys(pmap, va);				/* Get the page number */
	if(!pp) return 0;							/* Just return if no translation */
	
	pa = ((addr64_t)pp << 12) | (va & 0x0000000000000FFFULL);	/* Shove in the page offset */
	return(pa);
}

/*
 *
 */
unsigned kdp_vm_read(
	caddr_t src, 
	caddr_t dst, 
	unsigned len)
{
	addr64_t cur_virt_src, cur_virt_dst;
	addr64_t cur_phys_src;
	unsigned resid, cnt;
	unsigned int dummy;
	pmap_t pmap;

#ifdef KDP_VM_READ_DEBUG
    kprintf("kdp_vm_read1: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *)src)[0], ((unsigned long *)src)[1]);
#endif

	cur_virt_src = (addr64_t)((unsigned int)src);
	cur_virt_dst = (addr64_t)((unsigned int)dst);
	
	if (kdp_trans_off) {
		
		
		resid = len;								/* Get the length to copy */

		while (resid != 0) {

			if(kdp_read_io == 0)
				if(!mapping_phys_lookup((ppnum_t)(cur_virt_src >> 12), &dummy)) return 0;	/* Can't read where there's not any memory */
		
			cnt = 4096 - (cur_virt_src & 0xFFF);	/* Get length left on page */
		
			if (cnt > resid)  cnt = resid;

			bcopy_phys(cur_virt_src, cur_virt_dst, cnt);		/* Copy stuff over */

			cur_virt_src += cnt;
			cur_virt_dst += cnt;
			resid -= cnt;
		}
		
	} else {

		resid = len;

		if(kdp_pmap) pmap = kdp_pmap;				/* If special pmap, use it */
		else pmap = kernel_pmap;					/* otherwise, use kernel's */

		while (resid != 0) {   

			if((cur_phys_src = kdp_vtophys(pmap, cur_virt_src)) == 0) goto exit;
			if(kdp_read_io == 0)
				if(!mapping_phys_lookup((ppnum_t)(cur_phys_src >> 12), &dummy)) goto exit;	/* Can't read where there's not any memory */

			cnt = 4096 - (cur_virt_src & 0xFFF);	/* Get length left on page */
			if (cnt > resid) cnt = resid;

#ifdef KDP_VM_READ_DEBUG
				kprintf("kdp_vm_read2: pmap %08X, virt %016LLX, phys %016LLX\n", 
					pmap, cur_virt_src, cur_phys_src);
#endif

			bcopy_phys(cur_phys_src, cur_virt_dst, cnt);		/* Copy stuff over */
			
			cur_virt_src +=cnt;
			cur_virt_dst +=cnt;
			resid -= cnt;
		}
	}
exit:
#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_vm_read: ret %08X\n", len-resid);
#endif
        return (len - resid);
}

/*
 * 
 */
unsigned kdp_vm_write(
        caddr_t src,
        caddr_t dst,
        unsigned len)
{       
	addr64_t cur_virt_src, cur_virt_dst;
	addr64_t cur_phys_src, cur_phys_dst;
    unsigned resid, cnt, cnt_src, cnt_dst;

#ifdef KDP_VM_WRITE_DEBUG
	printf("kdp_vm_write: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *)src)[0], ((unsigned long *)src)[1]);
#endif

	cur_virt_src = (addr64_t)((unsigned int)src);
	cur_virt_dst = (addr64_t)((unsigned int)dst);

	resid = len;

	while (resid != 0) {
		if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0) 
			goto exit;
		if ((cur_phys_src = kdp_vtophys(kernel_pmap, cur_virt_src)) == 0) 
			goto exit;

		cnt_src = ((cur_phys_src + NBPG) & (-NBPG)) - cur_phys_src;
		cnt_dst = ((cur_phys_dst + NBPG) & (-NBPG)) - cur_phys_dst;

		if (cnt_src > cnt_dst)
			cnt = cnt_dst;
		else
			cnt = cnt_src;
		if (cnt > resid) 
			cnt = resid;

		bcopy_phys(cur_phys_src, cur_phys_dst, cnt);		/* Copy stuff over */
		sync_cache64(cur_phys_dst, cnt);					/* Sync caches */

		cur_virt_src +=cnt;
		cur_virt_dst +=cnt;
		resid -= cnt;
	}
exit:
	return (len - resid);
}

