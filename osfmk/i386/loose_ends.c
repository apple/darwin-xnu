/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 */
#include <mach_assert.h>

#include <string.h>
#include <mach/boolean.h>
#include <mach/i386/vm_types.h>
#include <mach/i386/vm_param.h>
#include <kern/kern_types.h>
#include <kern/misc_protos.h>
#include <sys/errno.h>
#include <i386/param.h>
#include <i386/misc_protos.h>
#include <i386/cpu_data.h>
#include <i386/machine_routines.h>
#include <i386/cpuid.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>

#include <libkern/OSAtomic.h>
#include <sys/kdebug.h>

#if 0

#undef KERNEL_DEBUG
#define KERNEL_DEBUG KERNEL_DEBUG_CONSTANT
#define KDEBUG 1

#endif

/* XXX - should be gone from here */
extern void		invalidate_icache64(addr64_t addr, unsigned cnt, int phys);
extern void		flush_dcache64(addr64_t addr, unsigned count, int phys);
extern boolean_t	phys_page_exists(ppnum_t);
extern void		bcopy_no_overwrite(const char *from, char *to,vm_size_t bytes);
extern void		pmap_set_reference(ppnum_t pn);
extern void		mapping_set_mod(ppnum_t pa); 
extern void		mapping_set_ref(ppnum_t pn);

extern void		fillPage(ppnum_t pa, unsigned int fill);
extern void		ovbcopy(const char	*from,
				char		*to,
				vm_size_t	nbytes);
void machine_callstack(natural_t *buf, vm_size_t callstack_max);


#define value_64bit(value)  ((value) & 0xFFFFFFFF00000000LL)
#define low32(x)  ((unsigned int)((x) & 0x00000000FFFFFFFFLL))


void
bzero_phys(
	   addr64_t src64,
	   vm_size_t bytes)
{
        mapwindow_t *map;
	pt_entry_t save;

        mp_disable_preemption();
	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | ((pmap_paddr_t)src64 & PG_FRAME) | INTEL_PTE_REF | INTEL_PTE_MOD));
	if (map == 0) {
	        panic("bzero_phys: CMAP busy");
	}
	save = *map->prv_CMAP;

	invlpg((uintptr_t)map->prv_CADDR);

	bzero((void *)((uintptr_t)map->prv_CADDR | ((uint32_t)src64 & INTEL_OFFMASK)), bytes);

	if (save != *map->prv_CMAP)
	        panic("bzero_phys: CMAP changed");
	*map->prv_CMAP = 0;

	mp_enable_preemption();
}


/*
 * bcopy_phys - like bcopy but copies from/to physical addresses.
 */

void
bcopy_phys(
	   addr64_t src64,
	   addr64_t dst64,
	   vm_size_t bytes)
{
        mapwindow_t *src_map, *dst_map;
	pt_entry_t save1, save2;

	/* ensure we stay within a page */
	if ( ((((uint32_t)src64 & (NBPG-1)) + bytes) > NBPG) || ((((uint32_t)dst64 & (NBPG-1)) + bytes) > NBPG) ) {
	        panic("bcopy_phys alignment");
	}
	mp_disable_preemption();

	src_map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | ((pmap_paddr_t)src64 & PG_FRAME) | INTEL_PTE_REF));
	dst_map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | ((pmap_paddr_t)dst64 & PG_FRAME) |
						  INTEL_PTE_REF | INTEL_PTE_MOD));

	if (src_map == 0 || dst_map == 0) {
	        panic("bcopy_phys: CMAP busy");
	}
	save1 = *src_map->prv_CMAP;
	save2 = *dst_map->prv_CMAP;

	invlpg((uintptr_t)src_map->prv_CADDR);
	invlpg((uintptr_t)dst_map->prv_CADDR);

	bcopy((void *) ((uintptr_t)src_map->prv_CADDR | ((uint32_t)src64 & INTEL_OFFMASK)),
	      (void *) ((uintptr_t)dst_map->prv_CADDR | ((uint32_t)dst64 & INTEL_OFFMASK)), bytes);

	if ( (save1 != *src_map->prv_CMAP) || (save2 != *dst_map->prv_CMAP))
	        panic("bcopy_phys CMAP changed");

	*src_map->prv_CMAP = 0;
	*dst_map->prv_CMAP = 0;

	mp_enable_preemption();
}

/* 
 * ovbcopy - like bcopy, but recognizes overlapping ranges and handles 
 *           them correctly.
 */

void
ovbcopy(
	const char	*from,
	char		*to,
	vm_size_t	bytes)		/* num bytes to copy */
{
	/* Assume that bcopy copies left-to-right (low addr first). */
	if (from + bytes <= to || to + bytes <= from || to == from)
		bcopy_no_overwrite(from, to, bytes);	/* non-overlapping or no-op*/
	else if (from > to)
		bcopy_no_overwrite(from, to, bytes);	/* overlapping but OK */
	else {
		/* to > from: overlapping, and must copy right-to-left. */
		from += bytes - 1;
		to += bytes - 1;
		while (bytes-- > 0)
			*to-- = *from--;
	}
}


/*
 *  Read data from a physical address. Memory should not be cache inhibited.
 */


static unsigned int
ml_phys_read_data(pmap_paddr_t paddr, int size )
{
        mapwindow_t *map;
	unsigned int result;
	pt_entry_t save;

	mp_disable_preemption();
	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | (paddr & PG_FRAME) | INTEL_PTE_REF));
	if (map == 0) {
		panic("ml_phys_read_data: CMAP busy");
	}

	save = *map->prv_CMAP;
	invlpg((uintptr_t)map->prv_CADDR);

        switch (size) {
            unsigned char s1;
            unsigned short s2;
        case 1:
            s1 = *(unsigned char *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK));
            result = s1;
            break;
        case 2:
            s2 = *(unsigned short *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK));
            result = s2;
            break;
        case 4:
        default:
            result = *(unsigned int *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK));
            break;
        }

	if (save != *map->prv_CMAP)
	        panic("ml_phys_read_data CMAP changed");
        *map->prv_CMAP = 0;
	mp_enable_preemption();

        return result;
}

static unsigned long long
ml_phys_read_long_long(pmap_paddr_t paddr )
{
        mapwindow_t *map;
	unsigned long long result;
	pt_entry_t save;

	mp_disable_preemption();
	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | (paddr & PG_FRAME) | INTEL_PTE_REF));

	if (map == 0) {
		panic("ml_phys_read_long_long: CMAP busy");
	}

	save = *map->prv_CMAP;
	invlpg((uintptr_t)map->prv_CADDR);

	result = *(unsigned long long *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK));

	if (save != *map->prv_CMAP)
	        panic("ml_phys_read_long_long CMAP changed");
	*map->prv_CMAP = 0;
	mp_enable_preemption();

	return result;
}



unsigned int ml_phys_read(vm_offset_t paddr)
{
        return ml_phys_read_data((pmap_paddr_t)paddr, 4);
}

unsigned int ml_phys_read_word(vm_offset_t paddr) {

        return ml_phys_read_data((pmap_paddr_t)paddr, 4);
}

unsigned int ml_phys_read_64(addr64_t paddr64)
{
        return ml_phys_read_data((pmap_paddr_t)paddr64, 4);
}

unsigned int ml_phys_read_word_64(addr64_t paddr64)
{
        return ml_phys_read_data((pmap_paddr_t)paddr64, 4);
}

unsigned int ml_phys_read_half(vm_offset_t paddr)
{
        return ml_phys_read_data((pmap_paddr_t)paddr, 2);
}

unsigned int ml_phys_read_half_64(addr64_t paddr64)
{
        return ml_phys_read_data((pmap_paddr_t)paddr64, 2);
}

unsigned int ml_phys_read_byte(vm_offset_t paddr)
{
        return ml_phys_read_data((pmap_paddr_t)paddr, 1);
}

unsigned int ml_phys_read_byte_64(addr64_t paddr64)
{
        return ml_phys_read_data((pmap_paddr_t)paddr64, 1);
}

unsigned long long ml_phys_read_double(vm_offset_t paddr)
{
        return ml_phys_read_long_long((pmap_paddr_t)paddr);
}

unsigned long long ml_phys_read_double_64(addr64_t paddr64)
{
        return ml_phys_read_long_long((pmap_paddr_t)paddr64);
}



/*
 *  Write data to a physical address. Memory should not be cache inhibited.
 */

static void
ml_phys_write_data(pmap_paddr_t paddr, unsigned long data, int size)
{
        mapwindow_t *map;
	pt_entry_t save;

	mp_disable_preemption();
	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | (paddr & PG_FRAME) | 
					  INTEL_PTE_REF | INTEL_PTE_MOD));

	if (map == 0) {
		panic("ml_phys_write_data: CMAP busy");
	}

	save = *map->prv_CMAP;
	invlpg((uintptr_t)map->prv_CADDR);

        switch (size) {
        case 1:
	    *(unsigned char *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK)) = (unsigned char)data;
            break;
        case 2:
	    *(unsigned short *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK)) = (unsigned short)data;
            break;
        case 4:
        default:
	    *(unsigned int *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK)) = data;
            break;
        }

	if (save != *map->prv_CMAP)
	        panic("ml_phys_write_data CMAP changed");
	*map->prv_CMAP = 0;

	mp_enable_preemption();
}

static void
ml_phys_write_long_long(pmap_paddr_t paddr, unsigned long long data)
{
        mapwindow_t *map;
	pt_entry_t save;

	mp_disable_preemption();
	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | (paddr & PG_FRAME) | 
					      INTEL_PTE_REF | INTEL_PTE_MOD));
	if (map == 0) {
		panic("ml_phys_write_data: CMAP busy");
	}

	save = *map->prv_CMAP;
	invlpg((uintptr_t)map->prv_CADDR);

	*(unsigned long long *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK)) = data;

	if (save != *map->prv_CMAP)
	        panic("ml_phys_write_data CMAP changed");
	*map->prv_CMAP = 0;
	mp_enable_preemption();
}



void ml_phys_write_byte(vm_offset_t paddr, unsigned int data)
{
        ml_phys_write_data((pmap_paddr_t)paddr, data, 1);
}

void ml_phys_write_byte_64(addr64_t paddr64, unsigned int data)
{
        ml_phys_write_data((pmap_paddr_t)paddr64, data, 1);
}

void ml_phys_write_half(vm_offset_t paddr, unsigned int data)
{
        ml_phys_write_data((pmap_paddr_t)paddr, data, 2);
}

void ml_phys_write_half_64(addr64_t paddr64, unsigned int data)
{
        ml_phys_write_data((pmap_paddr_t)paddr64, data, 2);
}

void ml_phys_write(vm_offset_t paddr, unsigned int data)
{
        ml_phys_write_data((pmap_paddr_t)paddr, data, 4);
}

void ml_phys_write_64(addr64_t paddr64, unsigned int data)
{
        ml_phys_write_data((pmap_paddr_t)paddr64, data, 4);
}

void ml_phys_write_word(vm_offset_t paddr, unsigned int data)
{
        ml_phys_write_data((pmap_paddr_t)paddr, data, 4);
}

void ml_phys_write_word_64(addr64_t paddr64, unsigned int data)
{
        ml_phys_write_data((pmap_paddr_t)paddr64, data, 4);
}

void ml_phys_write_double(vm_offset_t paddr, unsigned long long data)
{
        ml_phys_write_long_long((pmap_paddr_t)paddr, data);
}

void ml_phys_write_double_64(addr64_t paddr64, unsigned long long data)
{
        ml_phys_write_long_long((pmap_paddr_t)paddr64, data);
}


/* PCI config cycle probing
 *
 *
 *      Read the memory location at physical address paddr.
 *  This is a part of a device probe, so there is a good chance we will
 *  have a machine check here. So we have to be able to handle that.
 *  We assume that machine checks are enabled both in MSR and HIDs
 */

boolean_t
ml_probe_read(vm_offset_t paddr, unsigned int *val)
{
        *val = ml_phys_read((pmap_paddr_t)paddr);

	return TRUE;
}

/*
 *  Read the memory location at physical address paddr.
 *  This is a part of a device probe, so there is a good chance we will
 *  have a machine check here. So we have to be able to handle that.
 *  We assume that machine checks are enabled both in MSR and HIDs
 */
boolean_t 
ml_probe_read_64(addr64_t paddr64, unsigned int *val)
{
        *val = ml_phys_read_64((pmap_paddr_t)paddr64);

	return TRUE;
}


int bcmp(
	const void	*pa,
	const void	*pb,
	size_t	len)
{
	const char *a = (const char *)pa;
	const char *b = (const char *)pb;

	if (len == 0)
		return 0;

	do
		if (*a++ != *b++)
			break;
	while (--len);

	return len;
}

int
memcmp(s1, s2, n)
	const void *s1, *s2;
	size_t n;
{
	if (n != 0) {
		const unsigned char *p1 = s1, *p2 = s2;

		do {
			if (*p1++ != *p2++)
				return (*--p1 - *--p2);
		} while (--n != 0);
	}
	return (0);
}

/*
 * Abstract:
 * strlen returns the number of characters in "string" preceeding
 * the terminating null character.
 */

size_t
strlen(
	register const char *string)
{
	register const char *ret = string;

	while (*string++ != '\0')
		continue;
	return string - 1 - ret;
}

uint32_t
hw_atomic_add(
	uint32_t	*dest,
	uint32_t	delt)
{
	uint32_t	oldValue;
	uint32_t	newValue;
	
	do {
		oldValue = *dest;
		newValue = (oldValue + delt);
	} while (!OSCompareAndSwap((UInt32)oldValue,
									(UInt32)newValue, (UInt32 *)dest));
	
	return newValue;
}

uint32_t
hw_atomic_sub(
	uint32_t	*dest,
	uint32_t	delt)
{
	uint32_t	oldValue;
	uint32_t	newValue;
	
	do {
		oldValue = *dest;
		newValue = (oldValue - delt);
	} while (!OSCompareAndSwap((UInt32)oldValue,
									(UInt32)newValue, (UInt32 *)dest));
	
	return newValue;
}

uint32_t
hw_atomic_or(
	uint32_t	*dest,
	uint32_t	mask)
{
	uint32_t	oldValue;
	uint32_t	newValue;
	
	do {
		oldValue = *dest;
		newValue = (oldValue | mask);
	} while (!OSCompareAndSwap((UInt32)oldValue,
									(UInt32)newValue, (UInt32 *)dest));
	
	return newValue;
}

uint32_t
hw_atomic_and(
	uint32_t	*dest,
	uint32_t	mask)
{
	uint32_t	oldValue;
	uint32_t	newValue;
	
	do {
		oldValue = *dest;
		newValue = (oldValue & mask);
	} while (!OSCompareAndSwap((UInt32)oldValue,
									(UInt32)newValue, (UInt32 *)dest));
	
	return newValue;
}

uint32_t
hw_compare_and_store(
	uint32_t	oldval,
	uint32_t	newval,
	uint32_t	*dest)
{
	return OSCompareAndSwap((UInt32)oldval, (UInt32)newval, (UInt32 *)dest);
}

#if	MACH_ASSERT

/*
 * Machine-dependent routine to fill in an array with up to callstack_max
 * levels of return pc information.
 */
void machine_callstack(
	__unused natural_t	*buf,
	__unused vm_size_t	callstack_max)
{
}

#endif	/* MACH_ASSERT */




void fillPage(ppnum_t pa, unsigned int fill)
{
    mapwindow_t *map;
    pmap_paddr_t src;
    int i;
    int cnt = PAGE_SIZE/sizeof(unsigned int);
    unsigned int *addr;

    mp_disable_preemption();
    src = i386_ptob(pa);
    map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | (src & PG_FRAME) | 
					  INTEL_PTE_REF | INTEL_PTE_MOD));
    if (map == 0) {
        panic("fillPage: CMAP busy");
    }
    invlpg((uintptr_t)map->prv_CADDR);

    for (i = 0, addr = (unsigned int *)map->prv_CADDR; i < cnt ; i++ )
        *addr++ = fill;

    *map->prv_CMAP = 0;
    mp_enable_preemption();
}

static inline void __sfence(void)
{
    __asm__ volatile("sfence");
}
static inline void __mfence(void)
{
    __asm__ volatile("mfence");
}
static inline void __wbinvd(void)
{
    __asm__ volatile("wbinvd");
}
static inline void __clflush(void *ptr)
{
	__asm__ volatile("clflush (%0)" : : "r" (ptr));
}

void dcache_incoherent_io_store64(addr64_t pa, unsigned int count)
{
        mapwindow_t *map;
        uint32_t  linesize = cpuid_info()->cache_linesize;
        addr64_t  addr;
        uint32_t  offset, chunk;
        boolean_t istate;

	__mfence();

        istate = ml_set_interrupts_enabled(FALSE);

        offset = pa & (linesize - 1);
        addr   = pa - offset;

        map = pmap_get_mapwindow((pt_entry_t)(i386_ptob(atop_64(addr)) | INTEL_PTE_VALID));
        if (map == 0) {
                panic("cache_flush_page_phys: CMAP busy");
        }

        count += offset;
        offset = addr & ((addr64_t) (page_size - 1));
        chunk  = page_size - offset;

        do
        {
            if (chunk > count)
                chunk = count;

            *map->prv_CMAP = (pt_entry_t)(i386_ptob(atop_64(addr)) | INTEL_PTE_VALID);
            invlpg((uintptr_t)map->prv_CADDR);
    
            for (; offset < chunk; offset += linesize)
                __clflush((void *)(((uintptr_t)map->prv_CADDR) + offset));

            count -= chunk;
            addr  += chunk;
            chunk  = page_size;
            offset = 0;
        }
        while (count);

        *map->prv_CMAP = 0;

        (void) ml_set_interrupts_enabled(istate);

	__mfence();
}

void dcache_incoherent_io_flush64(addr64_t pa, unsigned int count)
{
    return(dcache_incoherent_io_store64(pa,count));
}

void
flush_dcache64(__unused addr64_t addr,
	       __unused unsigned count,
	       __unused int phys)
{
}

void
invalidate_icache64(__unused addr64_t addr,
		    __unused unsigned count,
		    __unused int phys)
{
}


addr64_t         vm_last_addr;

void
mapping_set_mod(ppnum_t pn)
{
  pmap_set_modify(pn);
}

void
mapping_set_ref(ppnum_t pn)
{
  pmap_set_reference(pn);
}

void
cache_flush_page_phys(ppnum_t pa)
{
        mapwindow_t     *map;
	boolean_t	istate;
	int		i;
	unsigned char	*cacheline_addr;
	int		cacheline_size = cpuid_info()->cache_linesize;
	int		cachelines_in_page = PAGE_SIZE/cacheline_size;

	__mfence();

	istate = ml_set_interrupts_enabled(FALSE);

        map = pmap_get_mapwindow((pt_entry_t)(i386_ptob(pa) | INTEL_PTE_VALID));
	if (map == 0) {
		panic("cache_flush_page_phys: CMAP busy");
        }

	invlpg((uintptr_t)map->prv_CADDR);

	for (i = 0, cacheline_addr = (unsigned char *)map->prv_CADDR;
	     i < cachelines_in_page;
	     i++, cacheline_addr += cacheline_size) {
		__clflush((void *) cacheline_addr);
	}

        *map->prv_CMAP = 0;

	(void) ml_set_interrupts_enabled(istate);

	__mfence();
}


void exit_funnel_section(void)
{
        thread_t thread;

	thread = current_thread();

        if (thread->funnel_lock)
	        (void) thread_funnel_set(thread->funnel_lock, FALSE);
}



/*
 * the copy engine has the following characteristics
 *   - copyio handles copies to/from user or kernel space
 *   - copypv deals with physical or virtual addresses
 *
 * implementation details as follows
 *   - a cache of up to NCOPY_WINDOWS is maintained per thread for
 *     access of user virutal space
 *   - the window size is determined by the amount of virtual space
 *     that can be mapped by a single page table
 *   - the mapping is done by copying the page table pointer from
 *     the user's directory entry corresponding to the window's
 *     address in user space to the directory entry corresponding
 *     to the window slot in the kernel's address space
 *   - the set of mappings is preserved across context switches,
 *     so the copy can run with pre-emption enabled
 *   - there is a gdt entry set up to anchor the kernel window on
 *     each processor
 *   - the copies are done using the selector corresponding to the
 *     gdt entry
 *   - the addresses corresponding to the user virtual address are
 *     relative to the beginning of the window being used to map
 *     that region... thus the thread can be pre-empted and switched
 *     to a different processor while in the midst of a copy
 *   - the window caches must be invalidated if the pmap changes out
 *     from under the thread... this can happen during vfork/exec...
 *     inval_copy_windows is the invalidation routine to be used
 *   - the copyio engine has 4 different states associated with it
 *     that allows for lazy tlb flushes and the ability to avoid
 *     a flush all together if we've just come from user space
 *     the 4 states are as follows...
 *
 *	WINDOWS_OPENED - set by copyio to indicate to the context
 *	  switch code that it is necessary to do a tlbflush after
 * 	  switching the windows since we're in the middle of a copy
 *
 *	WINDOWS_CLOSED - set by copyio to indicate that it's done
 *	  using the windows, so that the context switch code need
 *	  not do the tlbflush... instead it will set the state to...
 *
 *	WINDOWS_DIRTY - set by the context switch code to indicate
 *	  to the copy engine that it is responsible for doing a 
 *	  tlbflush before using the windows again... it's also
 *	  set by the inval_copy_windows routine to indicate the
 *	  same responsibility.
 *
 *	WINDOWS_CLEAN - set by the return to user path to indicate
 * 	  that a tlbflush has happened and that there is no need
 *	  for copyio to do another when it is entered next...
 *
 *   - a window for mapping single physical pages is provided for copypv
 *   - this window is maintained across context switches and has the
 *     same characteristics as the user space windows w/r to pre-emption
 */

extern int copyout_user(const char *, vm_offset_t, vm_size_t);
extern int copyout_kern(const char *, vm_offset_t, vm_size_t);
extern int copyin_user(const vm_offset_t, char *, vm_size_t);
extern int copyin_kern(const vm_offset_t, char *, vm_size_t);
extern int copyoutphys_user(const char *, vm_offset_t, vm_size_t);
extern int copyoutphys_kern(const char *, vm_offset_t, vm_size_t);
extern int copyinphys_user(const vm_offset_t, char *, vm_size_t);
extern int copyinphys_kern(const vm_offset_t, char *, vm_size_t);
extern int copyinstr_user(const vm_offset_t, char *, vm_size_t, vm_size_t *);
extern int copyinstr_kern(const vm_offset_t, char *, vm_size_t, vm_size_t *);

static int copyio(int, user_addr_t, char *, vm_size_t, vm_size_t *, int);
static int copyio_phys(addr64_t, addr64_t, vm_size_t, int);


#define COPYIN		0
#define COPYOUT		1
#define COPYINSTR	2
#define COPYINPHYS	3
#define COPYOUTPHYS	4



void inval_copy_windows(thread_t thread)
{
        int	i;
	
	for (i = 0; i < NCOPY_WINDOWS; i++) {
                thread->machine.copy_window[i].user_base = -1;
	}
	thread->machine.nxt_window = 0;
	thread->machine.copyio_state = WINDOWS_DIRTY;

	KERNEL_DEBUG(0xeff70058 | DBG_FUNC_NONE, (int)thread, (int)thread->map, 0, 0, 0);
}


static int
copyio(int copy_type, user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied, int use_kernel_map)
{
        thread_t	thread;
	pmap_t		pmap;
	pt_entry_t	*updp;
	pt_entry_t	*kpdp;
	user_addr_t 	user_base;
	vm_offset_t 	user_offset;
	vm_offset_t 	kern_vaddr;
	vm_size_t	cnt;
	vm_size_t	bytes_copied;
	int		error = 0;
	int		window_index;
	int		copyio_state;
        boolean_t	istate;
#if KDEBUG
	int		debug_type = 0xeff70010;
	debug_type += (copy_type << 2);
#endif

	thread = current_thread();

	KERNEL_DEBUG(debug_type | DBG_FUNC_START, (int)(user_addr >> 32), (int)user_addr, (int)nbytes, thread->machine.copyio_state, 0);

	if (nbytes == 0) {
	        KERNEL_DEBUG(debug_type | DBG_FUNC_END, (int)user_addr, (int)kernel_addr, (int)nbytes, 0, 0);
	        return (0);
	}
        pmap = thread->map->pmap;

        if (pmap == kernel_pmap || use_kernel_map) {

	        kern_vaddr = (vm_offset_t)user_addr;
	  
	        switch (copy_type) {

		case COPYIN:
		        error = copyin_kern(kern_vaddr, kernel_addr, nbytes);
			break;

		case COPYOUT:
		        error = copyout_kern(kernel_addr, kern_vaddr, nbytes);
			break;

		case COPYINSTR:
		        error = copyinstr_kern(kern_vaddr, kernel_addr, nbytes, lencopied);
			break;

		case COPYINPHYS:
		        error = copyinphys_kern(kern_vaddr, kernel_addr, nbytes);
			break;

		case COPYOUTPHYS:
		        error = copyoutphys_kern(kernel_addr, kern_vaddr, nbytes);
			break;
		}
		KERNEL_DEBUG(debug_type | DBG_FUNC_END, (int)kern_vaddr, (int)kernel_addr, (int)nbytes, error | 0x80000000, 0);

		return (error);
	}
	user_base = user_addr & ~((user_addr_t)(NBPDE - 1));
	user_offset = user_addr & (NBPDE - 1);

	KERNEL_DEBUG(debug_type | DBG_FUNC_NONE, (int)(user_base >> 32), (int)user_base, (int)user_offset, 0, 0);

	cnt = NBPDE - user_offset;

	if (cnt > nbytes)
	        cnt = nbytes;

	istate = ml_set_interrupts_enabled(FALSE);

	copyio_state = thread->machine.copyio_state;
	thread->machine.copyio_state = WINDOWS_OPENED;

	(void) ml_set_interrupts_enabled(istate);


	for (;;) {

	        for (window_index = 0; window_index < NCOPY_WINDOWS; window_index++) {
		        if (thread->machine.copy_window[window_index].user_base == user_base)
			        break;
		}
	        if (window_index >= NCOPY_WINDOWS) {

		        window_index = thread->machine.nxt_window;
			thread->machine.nxt_window++;

			if (thread->machine.nxt_window >= NCOPY_WINDOWS)
			        thread->machine.nxt_window = 0;
			thread->machine.copy_window[window_index].user_base = user_base;

			/*
			 * it's necessary to disable pre-emption
			 * since I have to compute the kernel descriptor pointer
			 * for the new window
			 */
			istate = ml_set_interrupts_enabled(FALSE);

		        updp = pmap_pde(pmap, user_base);

			kpdp = current_cpu_datap()->cpu_copywindow_pdp;
			kpdp += window_index;

			pmap_store_pte(kpdp, updp ? *updp : 0);

			(void) ml_set_interrupts_enabled(istate);

		        copyio_state = WINDOWS_DIRTY;

			KERNEL_DEBUG(0xeff70040 | DBG_FUNC_NONE, window_index, (int)user_base, (int)updp, (int)kpdp, 0);

		}
#if JOE_DEBUG
		else {
			istate = ml_set_interrupts_enabled(FALSE);

		        updp = pmap_pde(pmap, user_base);

			kpdp = current_cpu_datap()->cpu_copywindow_pdp;

			kpdp += window_index;

			if ((*kpdp & PG_FRAME) != (*updp & PG_FRAME)) {
				panic("copyio: user pdp mismatch - kpdp = 0x%x,  updp = 0x%x\n", kpdp, updp);
			}
			(void) ml_set_interrupts_enabled(istate);
		}
#endif
		if (copyio_state == WINDOWS_DIRTY) {
		        flush_tlb();

		        copyio_state = WINDOWS_CLEAN;

			KERNEL_DEBUG(0xeff70054 | DBG_FUNC_NONE, window_index, 0, 0, 0, 0);
		}
		user_offset += (window_index * NBPDE);

		KERNEL_DEBUG(0xeff70044 | DBG_FUNC_NONE, (int)user_offset, (int)kernel_addr, cnt, 0, 0);

	        switch (copy_type) {

		case COPYIN:
		        error = copyin_user(user_offset, kernel_addr, cnt);
			break;
			
		case COPYOUT:
		        error = copyout_user(kernel_addr, user_offset, cnt);
			break;

		case COPYINPHYS:
		        error = copyinphys_user(user_offset, kernel_addr, cnt);
			break;
			
		case COPYOUTPHYS:
		        error = copyoutphys_user(kernel_addr, user_offset, cnt);
			break;

		case COPYINSTR:
		        error = copyinstr_user(user_offset, kernel_addr, cnt, &bytes_copied);

			/*
			 * lencopied should be updated on success
			 * or ENAMETOOLONG...  but not EFAULT
			 */
			if (error != EFAULT)
			        *lencopied += bytes_copied;

			/*
			 * if we still have room, then the ENAMETOOLONG
			 * is just an artifact of the buffer straddling
			 * a window boundary and we should continue
			 */
			if (error == ENAMETOOLONG && nbytes > cnt)
			        error = 0;

			if (error) {
#if KDEBUG
			        nbytes = *lencopied;
#endif
			        break;
			}
			if (*(kernel_addr + bytes_copied - 1) == 0) {
			        /*
				 * we found a NULL terminator... we're done
				 */
#if KDEBUG
			        nbytes = *lencopied;
#endif
				goto done;
			}
			if (cnt == nbytes) {
			        /*
				 * no more room in the buffer and we haven't
				 * yet come across a NULL terminator
				 */
#if KDEBUG
			        nbytes = *lencopied;
#endif
			        error = ENAMETOOLONG;
				break;
			}
			assert(cnt == bytes_copied);

			break;
		}
		if (error)
		        break;
		if ((nbytes -= cnt) == 0)
		        break;

		kernel_addr += cnt;
		user_base += NBPDE;
		user_offset = 0;

		if (nbytes > NBPDE)
		        cnt = NBPDE;
		else
		        cnt = nbytes;
	}
done:
	thread->machine.copyio_state = WINDOWS_CLOSED;

	KERNEL_DEBUG(debug_type | DBG_FUNC_END, (int)user_addr, (int)kernel_addr, (int)nbytes, error, 0);

	return (error);
}


static int
copyio_phys(addr64_t source, addr64_t sink, vm_size_t csize, int which)
{
        pmap_paddr_t paddr;
	user_addr_t  vaddr;
	char        *window_offset;
	pt_entry_t  pentry;
	int         ctype;
	int	    retval;
	boolean_t   istate;

	if (which & cppvPsnk) {
		paddr  = (pmap_paddr_t)sink;
	        vaddr  = (user_addr_t)source;
		ctype  = COPYINPHYS;
		pentry = (pt_entry_t)(INTEL_PTE_VALID | (paddr & PG_FRAME) | INTEL_PTE_RW);
	} else {
	        paddr  = (pmap_paddr_t)source;
		vaddr  = (user_addr_t)sink;
		ctype  = COPYOUTPHYS;
		pentry = (pt_entry_t)(INTEL_PTE_VALID | (paddr & PG_FRAME));
	}
	window_offset = (char *)((uint32_t)paddr & (PAGE_SIZE - 1));

	if (current_thread()->machine.physwindow_busy) {
	        pt_entry_t	old_pentry;

	        KERNEL_DEBUG(0xeff70048 | DBG_FUNC_NONE, paddr, csize, 0, -1, 0);
		/*
		 * we had better be targeting wired memory at this point
		 * we will not be able to handle a fault with interrupts
		 * disabled... we disable them because we can't tolerate
		 * being preempted during this nested use of the window
		 */
		istate = ml_set_interrupts_enabled(FALSE);

		old_pentry = *(current_cpu_datap()->cpu_physwindow_ptep);
		pmap_store_pte((current_cpu_datap()->cpu_physwindow_ptep), pentry);

		invlpg((uintptr_t)current_cpu_datap()->cpu_physwindow_base);

		retval = copyio(ctype, vaddr, window_offset, csize, NULL, which & cppvKmap);

		pmap_store_pte((current_cpu_datap()->cpu_physwindow_ptep), old_pentry);

		invlpg((uintptr_t)current_cpu_datap()->cpu_physwindow_base);

		(void) ml_set_interrupts_enabled(istate);
	} else {
	        /*
		 * mark the window as in use... if an interrupt hits while we're
		 * busy, or we trigger another coyppv from the fault path into
		 * the driver on a user address space page fault due to a copyin/out
		 * then we need to save and restore the current window state instead
		 * of caching the window preserving it across context switches
		 */
	        current_thread()->machine.physwindow_busy = 1;

	        if (current_thread()->machine.physwindow_pte != pentry) {
		        KERNEL_DEBUG(0xeff70048 | DBG_FUNC_NONE, paddr, csize, 0, 0, 0);

			current_thread()->machine.physwindow_pte = pentry;
			
			/*
			 * preemption at this point would be bad since we
			 * could end up on the other processor after we grabbed the
			 * pointer to the current cpu data area, but before we finished
			 * using it to stuff the page table entry since we would
			 * be modifying a window that no longer belonged to us
			 * the invlpg can be done unprotected since it only flushes
			 * this page address from the tlb... if it flushes the wrong
			 * one, no harm is done, and the context switch that moved us
			 * to the other processor will have already take care of 
			 * flushing the tlb after it reloaded the page table from machine.physwindow_pte
			 */
			istate = ml_set_interrupts_enabled(FALSE);
			*(current_cpu_datap()->cpu_physwindow_ptep) = pentry;
			(void) ml_set_interrupts_enabled(istate);

			invlpg((uintptr_t)current_cpu_datap()->cpu_physwindow_base);
		}
#if JOE_DEBUG
		else {
		        if (pentry !=
			    (*(current_cpu_datap()->cpu_physwindow_ptep) & (INTEL_PTE_VALID | PG_FRAME | INTEL_PTE_RW)))
			        panic("copyio_phys: pentry != *physwindow_ptep");
		}
#endif
		retval = copyio(ctype, vaddr, window_offset, csize, NULL, which & cppvKmap);

	        current_thread()->machine.physwindow_busy = 0;
	}
	return (retval);
}



int
copyinmsg(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
{
        return (copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0));
}    

int
copyin(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
{
        return (copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0));
}

int
copyinstr(const user_addr_t user_addr,  char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied)
{
	*lencopied = 0;

        return (copyio(COPYINSTR, user_addr, kernel_addr, nbytes, lencopied, 0));
}

int
copyoutmsg(const char *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
        return (copyio(COPYOUT, user_addr, (char *)kernel_addr, nbytes, NULL, 0));
}

int
copyout(const char *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
        return (copyio(COPYOUT, user_addr, (char *)kernel_addr, nbytes, NULL, 0));
}


kern_return_t copypv(addr64_t src64, addr64_t snk64, unsigned int size, int which)
{
	unsigned int lop, csize;
	int bothphys = 0;
	

	KERNEL_DEBUG(0xeff7004c | DBG_FUNC_START, (int)src64, (int)snk64, size, which, 0);

	if ((which & (cppvPsrc | cppvPsnk)) == 0 )				/* Make sure that only one is virtual */
		panic("copypv: no more than 1 parameter may be virtual\n");	/* Not allowed */

	if ((which & (cppvPsrc | cppvPsnk)) == (cppvPsrc | cppvPsnk))
	        bothphys = 1;							/* both are physical */

	while (size) {
	  
	        if (bothphys) {
		        lop = (unsigned int)(PAGE_SIZE - (snk64 & (PAGE_SIZE - 1)));		/* Assume sink smallest */

			if (lop > (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1))))
			        lop = (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1)));	/* No, source is smaller */
		} else {
		        /*
			 * only need to compute the resid for the physical page
			 * address... we don't care about where we start/finish in
			 * the virtual since we just call the normal copyin/copyout
			 */
		        if (which & cppvPsrc)
			        lop = (unsigned int)(PAGE_SIZE - (src64 & (PAGE_SIZE - 1)));
			else
			        lop = (unsigned int)(PAGE_SIZE - (snk64 & (PAGE_SIZE - 1)));
		}
		csize = size;						/* Assume we can copy it all */
		if (lop < size)
		        csize = lop;					/* Nope, we can't do it all */
#if 0		
		/*
		 * flush_dcache64 is currently a nop on the i386... 
		 * it's used when copying to non-system memory such
		 * as video capture cards... on PPC there was a need
		 * to flush due to how we mapped this memory... not
		 * sure if it's needed on i386.
		 */
		if (which & cppvFsrc)
		        flush_dcache64(src64, csize, 1);		/* If requested, flush source before move */
		if (which & cppvFsnk)
		        flush_dcache64(snk64, csize, 1);		/* If requested, flush sink before move */
#endif
		if (bothphys)
		        bcopy_phys(src64, snk64, csize);		/* Do a physical copy, virtually */
		else {
		        if (copyio_phys(src64, snk64, csize, which))
			        return (KERN_FAILURE);
		}
#if 0
		if (which & cppvFsrc)
		        flush_dcache64(src64, csize, 1);	/* If requested, flush source after move */
		if (which & cppvFsnk)
		        flush_dcache64(snk64, csize, 1);	/* If requested, flush sink after move */
#endif
		size  -= csize;					/* Calculate what is left */
		snk64 += csize;					/* Bump sink to next physical address */
		src64 += csize;					/* Bump source to next physical address */
	}
	KERNEL_DEBUG(0xeff7004c | DBG_FUNC_END, (int)src64, (int)snk64, size, which, 0);

	return KERN_SUCCESS;
}
