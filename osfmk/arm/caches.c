/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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
#include <mach_assert.h>
#include <mach/vm_types.h>
#include <mach/mach_time.h>
#include <kern/timer.h>
#include <kern/clock.h>
#include <kern/machine.h>
#include <mach/machine.h>
#include <mach/machine/vm_param.h>
#include <mach_kdp.h>
#include <kdp/kdp_udp.h>
#include <arm/caches_internal.h>
#include <arm/cpuid.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>

#include <arm/misc_protos.h>

/*
 * dcache_incoherent_io_flush64() dcache_incoherent_io_store64() result info
 */
#define	LWOpDone 1
#define	BWOpDone 3

#ifndef	__ARM_COHERENT_IO__

extern boolean_t up_style_idle_exit;

void
flush_dcache(
	vm_offset_t addr,
	unsigned length,
	boolean_t phys)
{
	cpu_data_t	*cpu_data_ptr = getCpuDatap();

	if (phys) {
		unsigned int	paddr;
		unsigned int	vaddr;

		paddr = CAST_DOWN(unsigned int, addr);
		if (!isphysmem(paddr))
			return;
		vaddr = (unsigned int)phystokv(paddr);
		FlushPoC_DcacheRegion( (vm_offset_t) vaddr, length);

		if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
			((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
					    cpu_data_ptr->cpu_id, CacheCleanFlushRegion, (unsigned int) paddr, length);
		return;
	}
	if (cpu_data_ptr->cpu_cache_dispatch == (cache_dispatch_t) NULL) {
		FlushPoC_DcacheRegion( (vm_offset_t) addr, length);
	} else {
		addr64_t	paddr;
		uint32_t	count;

		while (length > 0) {
			count = PAGE_SIZE - (addr & PAGE_MASK);
			if (count > length)
				count = length;
			FlushPoC_DcacheRegion( (vm_offset_t) addr, count);
			paddr = kvtophys(addr);
			if (paddr) 
				((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
				                    cpu_data_ptr->cpu_id, CacheCleanFlushRegion, (unsigned int) paddr, count);
			addr += count;
			length -= count;
		}
	}
	return;
}

void
clean_dcache(
	vm_offset_t addr,
	unsigned length,
	boolean_t phys)
{
	cpu_data_t	*cpu_data_ptr = getCpuDatap();

	if (phys) {
		unsigned int	paddr;
		unsigned int	vaddr;

		paddr = CAST_DOWN(unsigned int, addr);
		if (!isphysmem(paddr))
			return;

		vaddr = (unsigned int)phystokv(paddr);
		CleanPoC_DcacheRegion( (vm_offset_t) vaddr, length);

		if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
			((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
					    cpu_data_ptr->cpu_id, CacheCleanRegion, paddr, length);
		return;
	}
	
	if (cpu_data_ptr->cpu_cache_dispatch == (cache_dispatch_t) NULL) {
		CleanPoC_DcacheRegion( (vm_offset_t) addr, length);
	} else {
		addr64_t	paddr;
		uint32_t	count;

		while (length > 0) {
			count = PAGE_SIZE - (addr & PAGE_MASK);
			if (count > length)
				count = length;
			CleanPoC_DcacheRegion( (vm_offset_t) addr, count);
			paddr = kvtophys(addr);
			if (paddr) 
				((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
				                    cpu_data_ptr->cpu_id, CacheCleanRegion, (unsigned int) paddr, count);
			addr += count;
			length -= count;
		}
	}
	return;
}

void
flush_dcache_syscall(
	vm_offset_t va,
	unsigned length)
{
	if ((cache_info()->c_bulksize_op !=0) && (length >= (cache_info()->c_bulksize_op))) {
#if	__ARM_SMP__ && defined(ARMA7)
		cache_xcall(LWFlush);
#else
		FlushPoC_Dcache();
		if (getCpuDatap()->cpu_cache_dispatch != (cache_dispatch_t) NULL)
			((cache_dispatch_t) getCpuDatap()->cpu_cache_dispatch) ( getCpuDatap()->cpu_id, CacheCleanFlush, 0x0UL , 0x0UL);
#endif
	} else {
		FlushPoC_DcacheRegion( (vm_offset_t) va, length);
	}
	return;
}

void
dcache_incoherent_io_flush64(
	addr64_t pa,
	unsigned int size,
	unsigned int remaining,
	unsigned int *res)
{
	unsigned int vaddr;
	unsigned int paddr = CAST_DOWN(unsigned int, pa);
	cpu_data_t *cpu_data_ptr = getCpuDatap();

	if ((cache_info()->c_bulksize_op !=0) && (remaining >= (cache_info()->c_bulksize_op))) {
#if	__ARM_SMP__ && defined (ARMA7)
		cache_xcall(LWFlush);
#else
		FlushPoC_Dcache();
		if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
			((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) ( cpu_data_ptr->cpu_id, CacheCleanFlush, 0x0UL , 0x0UL);
#endif
		*res = BWOpDone;
	} else {
		if (isphysmem(paddr)) {
			vaddr = (unsigned int)phystokv(pa);
			{
				FlushPoC_DcacheRegion( (vm_offset_t) vaddr, size);

				if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
					((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (cpu_data_ptr->cpu_id, CacheCleanFlushRegion, (unsigned int) pa, size);
			}
		} else {
			/* slow path - pa isn't in the vtop region. Flush one page at a time via cpu_copywindows */
			unsigned int wimg_bits, index;
			uint32_t count;

			mp_disable_preemption();

			while (size > 0) {
				count = PAGE_SIZE - (paddr & PAGE_MASK);
				if (count > size)
					count = size;

				wimg_bits = pmap_cache_attributes((paddr >> PAGE_SHIFT));
				index = pmap_map_cpu_windows_copy((paddr >> PAGE_SHIFT), VM_PROT_READ|VM_PROT_WRITE, wimg_bits);
				vaddr = pmap_cpu_windows_copy_addr(cpu_number(), index) | (paddr & PAGE_MASK);

				CleanPoC_DcacheRegion( (vm_offset_t) vaddr, count);

				pmap_unmap_cpu_windows_copy(index);

				paddr += count;
				size -= count;
			}

			mp_enable_preemption();
		}
	}

	return;
}

void
dcache_incoherent_io_store64(
	addr64_t pa,
	unsigned int size,
	unsigned int remaining,
	unsigned int *res)
{
	unsigned int vaddr;
	unsigned int paddr = CAST_DOWN(unsigned int, pa);
	cpu_data_t *cpu_data_ptr = getCpuDatap();

	if (isphysmem(paddr)) {
		unsigned int wimg_bits = pmap_cache_attributes(paddr >> PAGE_SHIFT);
		if ((wimg_bits == VM_WIMG_IO) || (wimg_bits == VM_WIMG_WCOMB)) {
			return;
		}
	}

	if ((cache_info()->c_bulksize_op !=0) && (remaining >= (cache_info()->c_bulksize_op))) {
#if	__ARM_SMP__ && defined (ARMA7)
		cache_xcall(LWClean);
		if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
			((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) ( cpu_data_ptr->cpu_id, CacheClean, 0x0UL , 0x0UL);
#else
		CleanPoC_Dcache();
		if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
			((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) ( cpu_data_ptr->cpu_id, CacheClean, 0x0UL , 0x0UL);
#endif
		*res = BWOpDone;
	} else {
		if (isphysmem(paddr)) {
			vaddr = (unsigned int)phystokv(pa);
			{
				CleanPoC_DcacheRegion( (vm_offset_t) vaddr, size);

				if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
					((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (cpu_data_ptr->cpu_id, CacheCleanRegion, (unsigned int) pa, size);
			}
		} else {
			/* slow path - pa isn't in the vtop region. Flush one page at a time via cpu_copywindows */
			unsigned int wimg_bits, index;
			uint32_t count;

			mp_disable_preemption();

			while (size > 0) {
				count = PAGE_SIZE - (paddr & PAGE_MASK);
				if (count > size)
					count = size;

				wimg_bits = pmap_cache_attributes((paddr >> PAGE_SHIFT));
				index = pmap_map_cpu_windows_copy((paddr >> PAGE_SHIFT), VM_PROT_READ|VM_PROT_WRITE, wimg_bits);
				vaddr = pmap_cpu_windows_copy_addr(cpu_number(), index) | (paddr & PAGE_MASK);

				CleanPoC_DcacheRegion( (vm_offset_t) vaddr, count);

				pmap_unmap_cpu_windows_copy(index);

				paddr += count;
				size -= count;
			}

			mp_enable_preemption();
		}
	}

	return;
}

void
cache_sync_page(
	ppnum_t pp
)
{
        pmap_paddr_t    paddr = ptoa(pp);

	if (isphysmem(paddr)) {
		vm_offset_t     vaddr = phystokv(paddr);

		CleanPoU_DcacheRegion(vaddr, PAGE_SIZE);
#ifdef  __ARM_IC_NOALIAS_ICACHE__
		InvalidatePoU_IcacheRegion(vaddr, PAGE_SIZE);
#else
		InvalidatePoU_Icache();
#endif
	} else {
		FlushPoC_Dcache();
		InvalidatePoU_Icache();
	};
}

void
platform_cache_init(
	void)
{
	cache_info_t   *cpuid_cache_info;
	unsigned int cache_size = 0x0UL;
	cpu_data_t	*cpu_data_ptr = getCpuDatap();

	cpuid_cache_info = cache_info();

	if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL) {
		((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
		                    cpu_data_ptr->cpu_id, CacheControl, CacheControlEnable, 0x0UL);

		if ( cpuid_cache_info->c_l2size == 0x0 ) {
			((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
			                    cpu_data_ptr->cpu_id, CacheConfig, CacheConfigSize , (unsigned int)&cache_size); 
			cpuid_cache_info->c_l2size = cache_size;
		}
	}

}

void
platform_cache_flush(
	void)
{
	cpu_data_t	*cpu_data_ptr = getCpuDatap();

	FlushPoC_Dcache();

	if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
		((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
	                    cpu_data_ptr->cpu_id, CacheCleanFlush, 0x0UL , 0x0UL);
}

void
platform_cache_clean(
	void)
{
	cpu_data_t	*cpu_data_ptr = getCpuDatap();

	CleanPoC_Dcache();

	if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
		((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
	                    cpu_data_ptr->cpu_id, CacheClean, 0x0UL , 0x0UL);
}

void
platform_cache_shutdown(
	void)
{
	cpu_data_t	*cpu_data_ptr = getCpuDatap();

	CleanPoC_Dcache();

	if (cpu_data_ptr->cpu_cache_dispatch != (cache_dispatch_t) NULL)
		((cache_dispatch_t) cpu_data_ptr->cpu_cache_dispatch) (
	                    cpu_data_ptr->cpu_id, CacheShutdown, 0x0UL , 0x0UL);
}

void
platform_cache_disable(void)
{
	uint32_t sctlr_value = 0;

	/* Disable dcache allocation. */
	__asm__ volatile("mrc p15, 0, %0, c1, c0, 0"
	                 : "=r"(sctlr_value));

	sctlr_value &= ~SCTLR_DCACHE;

	__asm__ volatile("mcr p15, 0, %0, c1, c0, 0\n"
	                 "isb"
	                 :: "r"(sctlr_value));

}

void
platform_cache_idle_enter(
	void)
{
#if	__ARM_SMP__
	platform_cache_disable();

	/*
	 * If we're only using a single CPU, just write back any
	 * dirty cachelines.  We can avoid doing housekeeping
	 * on CPU data that would normally be modified by other
	 * CPUs.
	 */
	if (up_style_idle_exit && (real_ncpus == 1))
		CleanPoU_Dcache();
	else {
		cpu_data_t	*cpu_data_ptr = getCpuDatap();

		FlushPoU_Dcache();

		cpu_data_ptr->cpu_CLW_active = 0;
		__asm__ volatile("dmb ish");
		cpu_data_ptr->cpu_CLWFlush_req = 0;
		cpu_data_ptr->cpu_CLWClean_req = 0;
		CleanPoC_DcacheRegion((vm_offset_t) cpu_data_ptr, sizeof(cpu_data_t));
	}
#else
	CleanPoU_Dcache();
#endif

#if	 defined (__ARM_SMP__) && defined (ARMA7)
	uint32_t actlr_value = 0;

	/* Leave the coherency domain */
	__asm__ volatile("clrex\n"
	                 "mrc p15, 0, %0, c1, c0, 1\n"
	                 : "=r"(actlr_value));

	actlr_value &= ~0x40;

	__asm__ volatile("mcr p15, 0, %0, c1, c0, 1\n"
	                 /* Ensures any pending fwd request gets serviced and ends up */
	                 "dsb\n"
	                 /* Forces the processor to re-fetch, so any pending fwd request gets into the core */
	                 "isb\n"
	                 /* Ensures the second possible pending fwd request ends up. */
	                 "dsb\n"
	                 :: "r"(actlr_value));
#endif
}

void
platform_cache_idle_exit(
	void)
{
#if defined (ARMA7)
	uint32_t actlr_value = 0;

	/* Flush L1 caches and TLB before rejoining the coherency domain */
	FlushPoU_Dcache();
	/*
	 * If we're only using a single CPU, we can avoid flushing the
	 * I-cache or the TLB, as neither program text nor pagetables
	 * should have been changed during the idle period.  We still
	 * want to flush the D-cache to PoU (above), as memory contents
	 * may have been changed by DMA.
	 */
	if (!up_style_idle_exit || (real_ncpus > 1)) {
		InvalidatePoU_Icache();
		flush_core_tlb();
	}

	/* Rejoin the coherency domain */
	__asm__ volatile("mrc p15, 0, %0, c1, c0, 1\n"
	                 : "=r"(actlr_value));

	actlr_value |= 0x40;

	__asm__ volatile("mcr p15, 0, %0, c1, c0, 1\n"
	                 "isb\n"
	                 :: "r"(actlr_value));

#if __ARM_SMP__
	uint32_t sctlr_value = 0;

	/* Enable dcache allocation. */
	__asm__ volatile("mrc p15, 0, %0, c1, c0, 0\n"
	                 : "=r"(sctlr_value));

	sctlr_value |= SCTLR_DCACHE;

	__asm__ volatile("mcr p15, 0, %0, c1, c0, 0\n"
	                 "isb"
	                 :: "r"(sctlr_value));
	getCpuDatap()->cpu_CLW_active = 1;
#endif
#endif
}

boolean_t
platform_cache_batch_wimg(
	__unused unsigned int new_wimg, 
	__unused unsigned int size
	)
{
	boolean_t	do_cache_op = FALSE;

	if ((cache_info()->c_bulksize_op != 0) && (size >= (cache_info()->c_bulksize_op))) do_cache_op = TRUE;

	return do_cache_op;
}

void
platform_cache_flush_wimg(
	__unused unsigned int new_wimg
)
{
#if	__ARM_SMP__ && defined (ARMA7)
	cache_xcall(LWFlush);
#else
	FlushPoC_Dcache();
	if (getCpuDatap()->cpu_cache_dispatch != (cache_dispatch_t) NULL)
		((cache_dispatch_t) getCpuDatap()->cpu_cache_dispatch) ( getCpuDatap()->cpu_id, CacheCleanFlush, 0x0UL , 0x0UL);
#endif
}

#if	__ARM_SMP__ && defined(ARMA7)
void
cache_xcall_handler(unsigned int op)
{
	cpu_data_t	*cdp;
	uint64_t	abstime;

	cdp = getCpuDatap();

	if ((op == LWFlush) && (cdp->cpu_CLWFlush_req > cdp->cpu_CLWFlush_last)) {
		FlushPoU_Dcache();
		abstime = ml_get_timebase();
		cdp->cpu_CLWFlush_last = abstime;
		cdp->cpu_CLWClean_last = abstime;
	} else if  ((op == LWClean) && (cdp->cpu_CLWClean_req > cdp->cpu_CLWClean_last)) {
		CleanPoU_Dcache();
		abstime = ml_get_timebase();
		cdp->cpu_CLWClean_last = abstime;
	}
}


void
cache_xcall(unsigned int op)
{
	boolean_t	intr;
	cpu_data_t	*cdp;
	cpu_data_t	*target_cdp;
	unsigned int	cpu;
	unsigned int	signal;
	uint64_t	abstime;

	intr = ml_set_interrupts_enabled(FALSE);
	cdp = getCpuDatap();
	abstime = ml_get_timebase();
	if (op == LWClean)
		signal = SIGPLWClean;
	else
		signal = SIGPLWFlush;

	for (cpu=0; cpu < MAX_CPUS; cpu++) {

		target_cdp = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;
		if(target_cdp == (cpu_data_t *)NULL)
			break;

		if (target_cdp->cpu_CLW_active == 0)
			continue;

		if (op == LWFlush)
			target_cdp->cpu_CLWFlush_req = abstime;
		else if (op == LWClean)
			target_cdp->cpu_CLWClean_req = abstime;
		__asm__ volatile("dmb ish");
		if (target_cdp->cpu_CLW_active == 0) {
			if (op == LWFlush)
				target_cdp->cpu_CLWFlush_req = 0x0ULL;
			else if (op == LWClean)
				target_cdp->cpu_CLWClean_req = 0x0ULL;
			continue;
		}

		if (target_cdp == cdp)
			continue;

		if(KERN_SUCCESS != cpu_signal(target_cdp, signal, (void *)NULL, NULL)) {
			if (op == LWFlush)
				target_cdp->cpu_CLWFlush_req = 0x0ULL;
			else if (op == LWClean)
				target_cdp->cpu_CLWClean_req = 0x0ULL;
		}
		if (cpu == real_ncpus)
			break;
	}

	cache_xcall_handler (op);

	(void) ml_set_interrupts_enabled(intr);

	for (cpu=0; cpu < MAX_CPUS; cpu++) {

		target_cdp = (cpu_data_t *)CpuDataEntries[cpu].cpu_data_vaddr;
		if(target_cdp == (cpu_data_t *)NULL)
			break;

		if (target_cdp == cdp)
			continue;

		if (op == LWFlush)
			while ((target_cdp->cpu_CLWFlush_req != 0x0ULL) && (target_cdp->cpu_CLWFlush_last < abstime));
		else if (op == LWClean)
			while ((target_cdp->cpu_CLWClean_req != 0x0ULL ) && (target_cdp->cpu_CLWClean_last < abstime));

		if (cpu == real_ncpus)
			break;
	}

	if (op ==  LWFlush)
		FlushPoC_Dcache();
	else if (op ==  LWClean)
		CleanPoC_Dcache();
}
#endif


#else	/* __ARM_COHERENT_IO__ */

void
flush_dcache(
	__unused vm_offset_t addr,
	__unused unsigned length,
	__unused boolean_t phys)
{
	__asm__ volatile ("dsb sy"); 
}

void
clean_dcache(
	__unused vm_offset_t addr,
	__unused unsigned length,
	__unused boolean_t phys)
{
	__asm__ volatile ("dsb sy"); 
}

void
flush_dcache_syscall(
	__unused vm_offset_t va,
	__unused unsigned length)
{
	__asm__ volatile ("dsb sy"); 
}

void
dcache_incoherent_io_flush64(
	__unused addr64_t pa,
	__unused unsigned int size,
	__unused unsigned int remaining,
	__unused unsigned int *res)
{
	__asm__ volatile ("dsb sy"); 
	*res = LWOpDone;
	return;
}

void
dcache_incoherent_io_store64(
	__unused addr64_t pa,
	__unused unsigned int size,
	__unused unsigned int remaining,
	__unused unsigned int *res)
{
	__asm__ volatile ("dsb sy"); 
	*res = LWOpDone;
	return;
}

void
cache_sync_page(
	ppnum_t pp
)
{
        pmap_paddr_t    paddr = ptoa(pp);

	if (isphysmem(paddr)) {
		vm_offset_t     vaddr = phystokv(paddr);

#ifdef  __ARM_IC_NOALIAS_ICACHE__
		InvalidatePoU_IcacheRegion(vaddr, PAGE_SIZE);
#else
		InvalidatePoU_Icache();
#endif
	} 
}

void
platform_cache_init(
	void)
{
}

void
platform_cache_flush(
	void)
{
}

void
platform_cache_clean(
	void)
{
}

void
platform_cache_shutdown(
	void)
{
}

void
platform_cache_idle_enter(
	void)
{
}

void
platform_cache_idle_exit(
	void)
{
}

boolean_t
platform_cache_batch_wimg(
	__unused unsigned int new_wimg, 
	__unused unsigned int size
	)
{
	return TRUE;
}

void
platform_cache_flush_wimg(
	__unused unsigned int new_wimg)
{
}

#endif	/* __ARM_COHERENT_IO__ */
