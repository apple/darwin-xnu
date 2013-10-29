/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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

#if !MACH_KDP
#include <kdp/kdp_callout.h>
#endif /* !MACH_KDP */

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
void machine_callstack(uintptr_t *buf, vm_size_t callstack_max);


#define value_64bit(value)  ((value) & 0xFFFFFFFF00000000ULL)
#define low32(x)  ((unsigned int)((x) & 0x00000000FFFFFFFFULL))

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
	bzero(PHYSMAP_PTOV(src64), bytes);
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
	/* Not necessary for K64 - but ensure we stay within a page */
	if (((((uint32_t)src64 & (NBPG-1)) + bytes) > NBPG) ||
            ((((uint32_t)dst64 & (NBPG-1)) + bytes) > NBPG) ) {
	        panic("bcopy_phys alignment");
	}
	bcopy(PHYSMAP_PTOV(src64), PHYSMAP_PTOV(dst64), bytes);
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
	/* Not necessary for K64 - but ensure we stay within a page */
	if (((((uint32_t)dst64 & (NBPG-1)) + bytes) > NBPG) ) {
	        panic("apply_func_phys alignment");
	}

	return func(PHYSMAP_PTOV(dst64), bytes, arg);
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


static inline unsigned int
ml_phys_read_data(pmap_paddr_t paddr, int size)
{
	unsigned int result = 0;

	if (!physmap_enclosed(paddr))
		panic("%s: 0x%llx out of bounds\n", __FUNCTION__, paddr);

        switch (size) {
		unsigned char s1;
		unsigned short s2;
        case 1:
		s1 = *(volatile unsigned char *)PHYSMAP_PTOV(paddr);
		result = s1;
		break;
        case 2:
		s2 = *(volatile unsigned short *)PHYSMAP_PTOV(paddr);
		result = s2;
		break;
        case 4:
		result = *(volatile unsigned int *)PHYSMAP_PTOV(paddr);
		break;
	default:
		panic("Invalid size %d for ml_phys_read_data\n", size);
		break;
        }
        return result;
}

static unsigned long long
ml_phys_read_long_long(pmap_paddr_t paddr )
{
	if (!physmap_enclosed(paddr))
		panic("%s: 0x%llx out of bounds\n", __FUNCTION__, paddr);
	return *(volatile unsigned long long *)PHYSMAP_PTOV(paddr);
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
 *  Write data to a physical address. Memory should not be cache inhibited.
 */

static inline void
ml_phys_write_data(pmap_paddr_t paddr, unsigned long data, int size)
{
	if (!physmap_enclosed(paddr))
		panic("%s: 0x%llx out of bounds\n", __FUNCTION__, paddr);

        switch (size) {
        case 1:
	    *(volatile unsigned char *)PHYSMAP_PTOV(paddr) = (unsigned char)data;
            break;
        case 2:
	    *(volatile unsigned short *)PHYSMAP_PTOV(paddr) = (unsigned short)data;
            break;
        case 4:
	    *(volatile unsigned int *)PHYSMAP_PTOV(paddr) = (unsigned int)data;
            break;
	default:
		panic("Invalid size %d for ml_phys_write_data\n", size);
		break;
        }
}

static void
ml_phys_write_long_long(pmap_paddr_t paddr, unsigned long long data)
{
	if (!physmap_enclosed(paddr))
		panic("%s: 0x%llx out of bounds\n", __FUNCTION__, paddr);

	*(volatile unsigned long long *)PHYSMAP_PTOV(paddr) = data;
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
 * *Does not* recover from machine checks, unlike the PowerPC implementation.
 * Should probably be deprecated.
 */

boolean_t
ml_probe_read(vm_offset_t paddr, unsigned int *val)
{
    if ((PAGE_SIZE - (paddr & PAGE_MASK)) < 4)
        return FALSE;

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
	__unused uintptr_t	*buf,
	__unused vm_size_t	callstack_max)
{
}

#endif	/* MACH_ASSERT */

void fillPage(ppnum_t pa, unsigned int fill)
{
	pmap_paddr_t    src;
	int             i;
	int             cnt = PAGE_SIZE / sizeof(unsigned int);
	unsigned int   *addr;

	src = i386_ptob(pa);
	for (i = 0, addr = (unsigned int *)PHYSMAP_PTOV(src); i < cnt; i++)
		*addr++ = fill;
}

static inline void __clflush(void *ptr)
{
	__asm__ volatile("clflush (%0)" : : "r" (ptr));
}

void dcache_incoherent_io_store64(addr64_t pa, unsigned int count)
{
	addr64_t  linesize = cpuid_info()->cache_linesize;
	addr64_t  bound = (pa + count + linesize - 1) & ~(linesize - 1);

	mfence();

	while (pa < bound) {
		__clflush(PHYSMAP_PTOV(pa));
		pa += linesize;
	}

	mfence();
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
		uint64_t  linesize = cpuid_info()->cache_linesize;
		addr64_t  bound = (addr + count + linesize -1) & ~(linesize - 1);
		mfence();
		while (addr < bound) {
			__clflush((void *) (uintptr_t) addr);
			addr += linesize;
		}
		mfence();
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

extern i386_cpu_info_t	cpuid_cpu_info;
void
cache_flush_page_phys(ppnum_t pa)
{
	boolean_t	istate;
	unsigned char	*cacheline_addr;
	i386_cpu_info_t	*cpuid_infop = cpuid_info();
	int		cacheline_size;
	int		cachelines_to_flush;

	cacheline_size = cpuid_infop->cache_linesize;
	if (cacheline_size == 0)
		panic("cacheline_size=0 cpuid_infop=%p\n", cpuid_infop);
	cachelines_to_flush = PAGE_SIZE/cacheline_size;

	mfence();

	istate = ml_set_interrupts_enabled(FALSE);

	for (cacheline_addr = (unsigned char *)PHYSMAP_PTOV(i386_ptob(pa));
	     cachelines_to_flush > 0;
	     cachelines_to_flush--, cacheline_addr += cacheline_size) {
		__clflush((void *) cacheline_addr);
	}

	(void) ml_set_interrupts_enabled(istate);

	mfence();
}


#if !MACH_KDP
void
kdp_register_callout(kdp_callout_fn_t fn, void *arg)
{
#pragma unused(fn,arg)
}
#endif

/*
 * Return a uniformly distributed 64-bit random number.
 *
 * This interface should have minimal dependencies on kernel
 * services, and thus be available very early in the life
 * of the kernel.  But as a result, it may not be very random
 * on all platforms.
 */
uint64_t
early_random(void)
{
	return (ml_early_random());
}

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
