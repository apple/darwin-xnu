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
#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>

#include <vm/pmap.h>
 
#include <ppc/proc_reg.h>
#include <ppc/machparam.h>
#include <ppc/mem.h>
#include <ppc/pmap.h>
#include <ppc/pmap_internals.h> 
#include <ppc/mappings.h> 

pmap_t kdp_pmap=0;
boolean_t kdp_trans_off=0;

unsigned kdp_xlate_off(void);
void kdp_xlate_restore(unsigned);
void kdp_flush_cache(vm_offset_t, unsigned);
vm_offset_t kdp_vtophys(pmap_t pmap, vm_offset_t vaddr);
void kdp_bcopy( unsigned char *, unsigned char *, unsigned);
void kdp_pmemcpy( vm_offset_t , vm_offset_t, unsigned);
unsigned kdp_vm_read( caddr_t, caddr_t, unsigned);
unsigned kdp_vm_write( caddr_t, caddr_t, unsigned);

extern vm_offset_t kvtophys(vm_offset_t);
extern vm_offset_t mem_actual;

/*
 *
 */
vm_offset_t kdp_vtophys(
	pmap_t pmap,
	vm_offset_t va)
{
	register mapping                *mp;
	register vm_offset_t    pa;

	pa = (vm_offset_t)LRA(pmap->space,(void *)va);

	if (pa != 0)            
		return(pa);     

	mp = hw_lock_phys_vir(pmap->space, va);
	if((unsigned int)mp&1) {
		return 0;
	}

	if(!mp) {								/* If it was not a normal page */
		pa = hw_cvp_blk(pmap, va);			/* Try to convert odd-sized page (returns 0 if not found) */
		return pa;							/* Return physical address */
	}

	mp = hw_cpv(mp);

	if(!mp->physent) {
		pa = (vm_offset_t)((mp->PTEr & -PAGE_SIZE) | ((unsigned int)va & (PAGE_SIZE-1)));
	} else {
		pa = (vm_offset_t)((mp->physent->pte1 & -PAGE_SIZE) | ((unsigned int)va & (PAGE_SIZE-1)));
		hw_unlock_bit((unsigned int *)&mp->physent->phys_link, PHYS_LOCK);
	}

	return(pa);
}

/*
 *
 */
void kdp_bcopy(
	unsigned char *src, 
	unsigned char *dst,
	unsigned cnt)
{
        while (cnt--)
                *dst++ = *src++;
}

/*
 *
 */
unsigned kdp_vm_read(
	caddr_t src, 
	caddr_t dst, 
	unsigned len)
{
	vm_offset_t cur_virt_src, cur_virt_dst;
	vm_offset_t cur_phys_src;
	unsigned resid, cnt;
	unsigned msr;

#ifdef KDP_VM_READ_DEBUG
    kprintf("kdp_vm_read1: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *)src)[0], ((unsigned long *)src)[1]);
#endif
	if (kdp_trans_off) {
		cur_virt_src = (vm_offset_t)src;
		if((vm_offset_t)src >= mem_actual) return 0;	/* Can't read where there's not any memory */
		cur_virt_dst = (vm_offset_t)dst;
		resid = (mem_actual - (vm_offset_t)src) > len ? len : (mem_actual - (vm_offset_t)src);

		while (resid != 0) {
			cur_phys_src = cur_virt_src;
			cnt = ((cur_virt_src + NBPG) & (-NBPG)) - cur_virt_src;	
			if (cnt > resid)  cnt = resid;
			msr = kdp_xlate_off();
			kdp_bcopy((unsigned char *)cur_phys_src, 
				(unsigned char *)cur_virt_dst, cnt);
			kdp_xlate_restore(msr);
			cur_virt_src +=cnt;
			cur_virt_dst +=cnt;
			resid -= cnt;
		}
	} else {
		cur_virt_src = (vm_offset_t)src;
		cur_virt_dst = (vm_offset_t)dst;
		resid = len;

		while (resid != 0) {   
			if (kdp_pmap) {
				if ((cur_phys_src = 
					kdp_vtophys(kdp_pmap,trunc_page(cur_virt_src))) == 0)
					goto exit;
				cur_phys_src += (cur_virt_src & PAGE_MASK);
			} else {
				if ((cur_phys_src = kdp_vtophys(kernel_pmap,cur_virt_src)) == 0)
					goto exit;
			}

			cnt = ((cur_virt_src + NBPG) & (-NBPG)) - cur_virt_src;
			if (cnt > resid) cnt = resid;
				if (kdp_pmap) {
#ifdef KDP_VM_READ_DEBUG
					kprintf("kdp_vm_read2: pmap %x, virt %x, phys %x\n", 
							kdp_pmap, cur_virt_src, cur_phys_src);
#endif
				msr = kdp_xlate_off();
				kdp_bcopy((unsigned char *)cur_phys_src, 
						(unsigned char *)cur_virt_dst, cnt);
				kdp_xlate_restore(msr);
			} else {
				kdp_bcopy((unsigned char *)cur_virt_src, 
						(unsigned char *)cur_virt_dst, cnt);
			}
			cur_virt_src +=cnt;
			cur_virt_dst +=cnt;
			resid -= cnt;
		}
	}
exit:
#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_vm_read: ret %08X\n", len-resid);
#endif
        return (len-resid);
}

/*
 * 
 */
unsigned kdp_vm_write(
        caddr_t src,
        caddr_t dst,
        unsigned len)
{       
	vm_offset_t cur_virt_src, cur_virt_dst;
	vm_offset_t cur_phys_src, cur_phys_dst;
        unsigned resid, cnt, cnt_src, cnt_dst;
	unsigned msr;

#ifdef KDP_VM_WRITE_DEBUG
	printf("kdp_vm_write: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *)src)[0], ((unsigned long *)src)[1]);
#endif

	cur_virt_src = (vm_offset_t)src;
	cur_virt_dst = (vm_offset_t)dst;
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

		msr = kdp_xlate_off();
		kdp_bcopy((unsigned char *)cur_virt_src,  (unsigned char *)cur_phys_dst, cnt);
		kdp_flush_cache(cur_phys_dst, cnt);
		kdp_xlate_restore(msr);

		cur_virt_src +=cnt;
		cur_virt_dst +=cnt;
		resid -= cnt;
	}
exit:
	return (len-resid);
}

