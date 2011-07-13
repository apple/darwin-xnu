/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#include <i386/vmx.h>
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

extern void		ovbcopy(const char	*from,
				char		*to,
				vm_size_t	nbytes);
void machine_callstack(natural_t *buf, vm_size_t callstack_max);


#define value_64bit(value)  ((value) & 0xFFFFFFFF00000000LL)
#define low32(x)  ((unsigned int)((x) & 0x00000000FFFFFFFFLL))

#define JOE_DEBUG 0

void
bzero_phys_nc(
	      addr64_t src64,
	      uint32_t bytes)
{
  bzero_phys(src64,bytes);
}

void
bzero_phys(
	   addr64_t src64,
	   uint32_t bytes)
{
        mapwindow_t *map;

        mp_disable_preemption();

	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | ((pmap_paddr_t)src64 & PG_FRAME) | INTEL_PTE_REF | INTEL_PTE_MOD));

	bzero((void *)((uintptr_t)map->prv_CADDR | ((uint32_t)src64 & INTEL_OFFMASK)), bytes);

	pmap_put_mapwindow(map);

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

	/* ensure we stay within a page */
	if ( ((((uint32_t)src64 & (NBPG-1)) + bytes) > NBPG) || ((((uint32_t)dst64 & (NBPG-1)) + bytes) > NBPG) ) {
	        panic("bcopy_phys alignment");
	}
	mp_disable_preemption();

	src_map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | ((pmap_paddr_t)src64 & PG_FRAME) | INTEL_PTE_REF));
	dst_map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | ((pmap_paddr_t)dst64 & PG_FRAME) |
						  INTEL_PTE_REF | INTEL_PTE_MOD));

	bcopy((void *) ((uintptr_t)src_map->prv_CADDR | ((uint32_t)src64 & INTEL_OFFMASK)),
	      (void *) ((uintptr_t)dst_map->prv_CADDR | ((uint32_t)dst64 & INTEL_OFFMASK)), bytes);

	pmap_put_mapwindow(src_map);
	pmap_put_mapwindow(dst_map);

	mp_enable_preemption();
}

/*
 * allow a function to get a quick virtual mapping of a physical page 
 */

int
apply_func_phys(
		addr64_t dst64,
		vm_size_t bytes,
		int (*func)(void * buffer, vm_size_t bytes, void * arg),
		void * arg)
{
        mapwindow_t *dst_map;
	int rc = -1;

	/* ensure we stay within a page */
	if ( ((((uint32_t)dst64 & (NBPG-1)) + bytes) > NBPG) ) {
	        panic("apply_func_phys alignment");
	}
	mp_disable_preemption();

	dst_map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | ((pmap_paddr_t)dst64 & PG_FRAME) |
						  INTEL_PTE_REF | INTEL_PTE_MOD));

	rc = func((void *)((uintptr_t)dst_map->prv_CADDR | ((uint32_t)dst64 & INTEL_OFFMASK)), bytes, arg);

	pmap_put_mapwindow(dst_map);

	mp_enable_preemption();

	return rc;
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
 *  Read data from a physical address.
 */


static unsigned int
ml_phys_read_data(pmap_paddr_t paddr, int size )
{
        mapwindow_t *map;
	unsigned int result;

	mp_disable_preemption();

	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | (paddr & PG_FRAME) | INTEL_PTE_REF));

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
        pmap_put_mapwindow(map);

	mp_enable_preemption();

        return result;
}

static unsigned long long
ml_phys_read_long_long(pmap_paddr_t paddr )
{
        mapwindow_t *map;
	unsigned long long result;

	mp_disable_preemption();

	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | (paddr & PG_FRAME) | INTEL_PTE_REF));

	result = *(unsigned long long *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK));

        pmap_put_mapwindow(map);

	mp_enable_preemption();

        return result;
}

unsigned int ml_phys_read( vm_offset_t paddr)
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
 *  Write data to a physical address.
 */

static void
ml_phys_write_data(pmap_paddr_t paddr, unsigned long data, int size)
{
        mapwindow_t *map;

	mp_disable_preemption();

	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | (paddr & PG_FRAME) | 
					  INTEL_PTE_REF | INTEL_PTE_MOD));

        switch (size) {
        case 1:
	    *(unsigned char *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK)) = (unsigned char)data;
            break;
        case 2:
	    *(unsigned short *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK)) = (unsigned short)data;
            break;
        case 4:
        default:
	    *(unsigned int *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK)) = (uint32_t)data;
            break;
        }
        pmap_put_mapwindow(map);

	mp_enable_preemption();
}

static void
ml_phys_write_long_long(pmap_paddr_t paddr, unsigned long long data)
{
        mapwindow_t *map;

	mp_disable_preemption();

	map = pmap_get_mapwindow((pt_entry_t)(INTEL_PTE_VALID | INTEL_PTE_RW | (paddr & PG_FRAME) | 
					      INTEL_PTE_REF | INTEL_PTE_MOD));

	*(unsigned long long *)((uintptr_t)map->prv_CADDR | ((uint32_t)paddr & INTEL_OFFMASK)) = data;

        pmap_put_mapwindow(map);

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
    if ((PAGE_SIZE - (paddr & PAGE_MASK)) < 4)
        return FALSE;

    *val = ml_phys_read(paddr);

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
    if ((PAGE_SIZE - (paddr64 & PAGE_MASK)) < 4)
        return FALSE;

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

	return (int)len;
}

int
memcmp(const void *s1, const void *s2, size_t n)
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
hw_compare_and_store(uint32_t oldval, uint32_t newval, volatile uint32_t *dest)
{
	return OSCompareAndSwap((UInt32)oldval,
				(UInt32)newval,
				(volatile UInt32 *)dest);
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

	for (i = 0, addr = (unsigned int *)map->prv_CADDR; i < cnt ; i++ )
	        *addr++ = fill;

	pmap_put_mapwindow(map);

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

        offset = (uint32_t)(pa & (linesize - 1));
        addr   = pa - offset;

        map = pmap_get_mapwindow((pt_entry_t)(i386_ptob(atop_64(addr)) | INTEL_PTE_VALID));

        count += offset;
        offset = (uint32_t)(addr & ((addr64_t) (page_size - 1)));
        chunk  = (uint32_t)page_size - offset;

        do
        {
            if (chunk > count)
                chunk = count;
    
            for (; offset < chunk; offset += linesize)
                __clflush((void *)(((uintptr_t)map->prv_CADDR) + offset));

            count -= chunk;
            addr  += chunk;
            chunk  = (uint32_t) page_size;
            offset = 0;

	    if (count) {
	        pmap_store_pte(map->prv_CMAP, (pt_entry_t)(i386_ptob(atop_64(addr)) | INTEL_PTE_VALID));
		invlpg((uintptr_t)map->prv_CADDR);
	    }
        }
        while (count);

        pmap_put_mapwindow(map);

        (void) ml_set_interrupts_enabled(istate);

	__mfence();
}

void dcache_incoherent_io_flush64(addr64_t pa, unsigned int count)
{
    return(dcache_incoherent_io_store64(pa,count));
}


void
flush_dcache64(addr64_t addr, unsigned count, int phys)
{
	if (phys) {
		dcache_incoherent_io_flush64(addr, count);
	}
	else {
		uint32_t  linesize = cpuid_info()->cache_linesize;
		addr64_t  bound = (addr + count + linesize - 1) & ~(linesize - 1);
		__mfence();
		while (addr < bound) {
			__clflush((void *) (uintptr_t) addr);
			addr += linesize;
		}
		__mfence();
	}
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

	for (i = 0, cacheline_addr = (unsigned char *)map->prv_CADDR;
	     i < cachelines_in_page;
	     i++, cacheline_addr += cacheline_size) {
		__clflush((void *) cacheline_addr);
	}
        pmap_put_mapwindow(map);

	(void) ml_set_interrupts_enabled(istate);

	__mfence();
}


#if !MACH_KDP
void
kdp_register_callout(void)
{
}
#endif

#if !CONFIG_VMX
int host_vmxon(boolean_t exclusive __unused)
{
	return VMX_UNSUPPORTED;
}

void host_vmxoff(void)
{
	return;
}
#endif

#ifdef __LP64__

#define INT_SIZE	(BYTE_SIZE * sizeof (int))

/*
 * Set indicated bit in bit string.
 */
void
setbit(int bitno, int *s)
{
	s[bitno / INT_SIZE] |= 1 << (bitno % INT_SIZE);
}

/*
 * Clear indicated bit in bit string.
 */
void
clrbit(int bitno, int *s)
{
	s[bitno / INT_SIZE] &= ~(1 << (bitno % INT_SIZE));
}

/*
 * Test if indicated bit is set in bit string.
 */
int
testbit(int bitno, int *s)
{
	return s[bitno / INT_SIZE] & (1 << (bitno % INT_SIZE));
}

/*
 * Find first bit set in bit string.
 */
int
ffsbit(int *s)
{
	int             offset;

	for (offset = 0; !*s; offset += (int)INT_SIZE, ++s);
	return offset + __builtin_ctz(*s);
}

int
ffs(unsigned int mask)
{
	if (mask == 0)
		return 0;

	/*
	 * NOTE: cannot use __builtin_ffs because it generates a call to
	 * 'ffs'
	 */
	return 1 + __builtin_ctz(mask);
}
#endif
