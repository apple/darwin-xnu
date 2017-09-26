/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>

#include <vm/pmap.h>

#include <mach/thread_status.h>
#include <mach-o/loader.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>

#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_protos.h>
#include <kdp/kdp_core.h>
#include <kdp/kdp_udp.h>
#include <kdp/kdp_internal.h>
#include <arm/misc_protos.h>
#include <arm/caches_internal.h>
#include <arm/cpu_data_internal.h>

pmap_t          kdp_pmap = 0;
boolean_t       kdp_trans_off;
boolean_t	kdp_read_io = 0;

pmap_paddr_t    kdp_vtophys(pmap_t pmap, vm_offset_t va);

/*
 * kdp_vtophys
 */
pmap_paddr_t
kdp_vtophys(
	    pmap_t pmap,
	    vm_offset_t va)
{
	pmap_paddr_t    pa;
	ppnum_t         pp;

	/* Ensure that the provided va resides within the provided pmap range. */
	if(!pmap || ((pmap != kernel_pmap) && ((va < pmap->min) || (va >= pmap->max))))
	{
#ifdef KDP_VTOPHYS_DEBUG
		printf("kdp_vtophys(%08x, %016lx) not in range %08x .. %08x\n", (unsigned int) pmap,
		                                                                (unsigned long) va,
		                                                                (unsigned int) (pmap ? pmap->min : 0),
		                                                                (unsigned int) (pmap ? pmap->max : 0));
#endif
		return 0;   /* Just return if no translation */	
	}

	pp = pmap_find_phys(pmap, va);	/* Get the page number */
	if (!pp)
		return 0;	/* Just return if no translation */

	pa = ((pmap_paddr_t) pp << PAGE_SHIFT) | (va & PAGE_MASK);	/* Insert page offset */
	return (pa);
}


/*
 * kdp_machine_vm_read
 *
 * Verify that src is valid, and physically copy len bytes from src to
 * dst, translating if necessary. If translation is enabled
 * (kdp_trans_off is 0), a non-zero kdp_pmap specifies the pmap to use
 * when translating src.
 */

mach_vm_size_t
kdp_machine_vm_read( mach_vm_address_t src, caddr_t dst, mach_vm_size_t len)
{
	addr64_t        cur_virt_src, cur_virt_dst;
	addr64_t        cur_phys_src, cur_phys_dst;
	mach_vm_size_t	resid, cnt;
	pmap_t          pmap;

#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_machine_vm_read1: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *) src)[0], ((unsigned long *) src)[1]);
#endif

	cur_virt_src = (addr64_t) src;
	cur_virt_dst = (addr64_t) dst;

	if (kdp_trans_off) {
		kdp_readphysmem64_req_t rq;
		mach_vm_size_t ret;

		rq.address = src;
		rq.nbytes = (uint32_t)len;
		ret = kdp_machine_phys_read(&rq, dst, 0 /* unused */);
		return ret;
	} else {

		resid = len;

		if (kdp_pmap)
			pmap = kdp_pmap;	/* If special pmap, use it */
		else
			pmap = kernel_pmap;	/* otherwise, use kernel's */

		while (resid != 0) {
			/*
			 * Always translate the destination using the
			 * kernel_pmap.
			 */
			if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0)
				goto exit;

			if ((cur_phys_src = kdp_vtophys(pmap, cur_virt_src)) == 0)
				goto exit;

			/* Attempt to ensure that there are valid translations for src and dst. */
			if  (!kdp_read_io && ((!pmap_valid_address(cur_phys_dst)) || (!pmap_valid_address(cur_phys_src))))
				goto exit;

			cnt = ARM_PGBYTES - (cur_virt_src & PAGE_MASK);	/* Get length left on
									 * page */
			if (cnt > (ARM_PGBYTES - (cur_virt_dst & PAGE_MASK)))
				cnt = ARM_PGBYTES - (cur_virt_dst & PAGE_MASK);

			if (cnt > resid)
				cnt = resid;

#ifdef KDP_VM_READ_DEBUG
			kprintf("kdp_machine_vm_read2: pmap %08X, virt %016LLX, phys %016LLX\n",
				pmap, cur_virt_src, cur_phys_src);
#endif
			bcopy_phys(cur_phys_src, cur_phys_dst, cnt);

			cur_virt_src += cnt;
			cur_virt_dst += cnt;
			resid -= cnt;
		}
	}
exit:
#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_machine_vm_read: ret %08X\n", len - resid);
#endif
	return (len - resid);
}

mach_vm_size_t
kdp_machine_phys_read(kdp_readphysmem64_req_t *rq, caddr_t dst, uint16_t lcpu __unused)
{
	mach_vm_address_t src = rq->address;
	mach_vm_size_t    len = rq->nbytes;
	
	addr64_t        cur_virt_dst;
	addr64_t        cur_phys_src, cur_phys_dst;
	mach_vm_size_t  resid = len;
	mach_vm_size_t  cnt = 0, cnt_src, cnt_dst;

#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_phys_read src %x dst %p len %x\n", src, dst, len);
#endif

	cur_virt_dst = (addr64_t) dst;
	cur_phys_src = (addr64_t) src;

	while (resid != 0) {
		
		if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0)
			goto exit;

		/* Get length left on page */
		
		cnt_src = ARM_PGBYTES - (cur_phys_src & PAGE_MASK);
		cnt_dst = ARM_PGBYTES - (cur_phys_dst & PAGE_MASK);
		if (cnt_src > cnt_dst)
			cnt = cnt_dst;
		else
			cnt = cnt_src;
		if (cnt > resid)
			cnt = resid;
		
		bcopy_phys(cur_phys_src, cur_phys_dst, cnt);	/* Copy stuff over */
		cur_phys_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}

exit:
    return (len - resid);
}

/*
 * kdp_vm_write
 */
mach_vm_size_t
kdp_machine_vm_write( caddr_t src, mach_vm_address_t dst, mach_vm_size_t len)
{
	addr64_t        cur_virt_src, cur_virt_dst;
	addr64_t        cur_phys_src, cur_phys_dst;
	mach_vm_size_t  resid, cnt, cnt_src, cnt_dst;

#ifdef KDP_VM_WRITE_DEBUG
	printf("kdp_vm_write: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *) src)[0], ((unsigned long *) src)[1]);
#endif

	cur_virt_src = (addr64_t) src;
	cur_virt_dst = (addr64_t) dst;

	resid = len;

	while (resid != 0) {
		if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0)
			goto exit;

		if ((cur_phys_src = kdp_vtophys(kernel_pmap, cur_virt_src)) == 0)
			goto exit;

		/* Attempt to ensure that there are valid translations for src and dst. */
		/* No support for enabling writes for an invalid translation at the moment. */
		if ((!pmap_valid_address(cur_phys_dst)) || (!pmap_valid_address(cur_phys_src)))
			goto exit;

		cnt_src = ((cur_phys_src + ARM_PGBYTES) & (-ARM_PGBYTES)) - cur_phys_src;
		cnt_dst = ((cur_phys_dst + ARM_PGBYTES) & (-ARM_PGBYTES)) - cur_phys_dst;

		if (cnt_src > cnt_dst)
			cnt = cnt_dst;
		else
			cnt = cnt_src;
		if (cnt > resid)
			cnt = resid;

#ifdef KDP_VM_WRITE_DEBUG
		printf("kdp_vm_write: cur_phys_src %x cur_phys_src %x len %x - %08X %08X\n", src, dst, cnt);
#endif
		bcopy_phys(cur_phys_src, cur_phys_dst, cnt);	/* Copy stuff over */
		flush_dcache64(cur_phys_dst, (unsigned int)cnt, TRUE);
		invalidate_icache64(cur_phys_dst, (unsigned int)cnt, TRUE);

		cur_virt_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}
exit:
	return (len - resid);
}

mach_vm_size_t
kdp_machine_phys_write(kdp_writephysmem64_req_t *rq __unused, caddr_t src __unused,
		       uint16_t lcpu __unused)
{
    return 0; /* unimplemented */
}

void
kern_collectth_state_size(uint64_t * tstate_count, uint64_t * tstate_size)
{
    uint64_t    count = ml_get_max_cpu_number() + 1;

    *tstate_count = count;
    *tstate_size  = sizeof(struct thread_command)
	          + (sizeof(arm_state_hdr_t) 
#if defined(__arm64__)
	          + ARM_THREAD_STATE64_COUNT * sizeof(uint32_t));
#else
	          + ARM_THREAD_STATE32_COUNT * sizeof(uint32_t));
#endif
}

void
kern_collectth_state(thread_t thread __unused, void *buffer, uint64_t size, void ** iter)
{
    cpu_data_entry_t *cpuentryp = *iter;
    if (cpuentryp == NULL)
        cpuentryp = &CpuDataEntries[0];

    if (cpuentryp == &CpuDataEntries[ml_get_max_cpu_number()])
        *iter = NULL;
    else
        *iter = cpuentryp + 1;

    struct cpu_data *cpudatap = cpuentryp->cpu_data_vaddr;

    struct thread_command *tc = (struct thread_command *)buffer;
    arm_state_hdr_t *hdr = (arm_state_hdr_t *)(void *)(tc + 1);
#if defined(__arm64__)
    hdr->flavor = ARM_THREAD_STATE64;
    hdr->count = ARM_THREAD_STATE64_COUNT;
    arm_thread_state64_t *state = (arm_thread_state64_t *)(void *)(hdr + 1);
#else
    hdr->flavor = ARM_THREAD_STATE;
    hdr->count = ARM_THREAD_STATE_COUNT;
    arm_thread_state_t *state = (arm_thread_state_t *)(void *)(hdr + 1);
#endif

    tc->cmd = LC_THREAD;
    tc->cmdsize = (uint32_t) size;

    if ((cpudatap != NULL) && (cpudatap->halt_status == CPU_HALTED_WITH_STATE)) {
        *state = cpudatap->halt_state;
        return;
    }

    if ((cpudatap == NULL) || (cpudatap->cpu_processor == NULL) || (cpudatap->cpu_processor->active_thread == NULL)) {
        bzero(state, hdr->count * sizeof(uint32_t));
        return;
    }

    vm_offset_t kstackptr = (vm_offset_t) cpudatap->cpu_processor->active_thread->machine.kstackptr;
    arm_saved_state_t *saved_state = (arm_saved_state_t *) kstackptr;

#if defined(__arm64__)

    state->fp   = saved_state->ss_64.fp;
    state->lr   = saved_state->ss_64.lr;
    state->sp   = saved_state->ss_64.sp;
    state->pc   = saved_state->ss_64.pc;
    state->cpsr = saved_state->ss_64.cpsr;
    bcopy(&saved_state->ss_64.x[0], &state->x[0], sizeof(state->x));

#else /* __arm64__ */

    state->lr   = saved_state->lr;
    state->sp   = saved_state->sp;
    state->pc   = saved_state->pc;
    state->cpsr = saved_state->cpsr;
    bcopy(&saved_state->r[0], &state->r[0], sizeof(state->r));

#endif /* !__arm64__ */


}


