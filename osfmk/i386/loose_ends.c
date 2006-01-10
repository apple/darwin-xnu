/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
/*
 */
#include <mach_assert.h>

#include <string.h>
#include <mach/boolean.h>
#include <mach/i386/vm_types.h>
#include <mach/i386/vm_param.h>
#include <kern/kern_types.h>
#include <kern/misc_protos.h>
#include <i386/param.h>
#include <i386/misc_protos.h>
#include <i386/cpu_data.h>
#include <i386/machine_routines.h>
#include <i386/cpuid.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_fault.h>

/* XXX - should be gone from here */
extern void		invalidate_icache64(addr64_t addr, unsigned cnt, int phys);
extern void		flush_dcache64(addr64_t addr, unsigned count, int phys);
extern boolean_t	phys_page_exists(ppnum_t);
extern pt_entry_t	*pmap_mapgetpte(vm_map_t, vm_offset_t);
extern void		bcopy_no_overwrite(const char *from, char *to,vm_size_t bytes);
extern void		pmap_set_reference(ppnum_t pn);
extern void		mapping_set_mod(ppnum_t pa); 
extern void		mapping_set_ref(ppnum_t pn);
extern void		switch_to_serial_console(void);
extern kern_return_t	copyp2p(vm_offset_t	source,
				vm_offset_t	dest,
				unsigned int	size,
				unsigned int	flush_action);
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
  vm_offset_t src = low32(src64);
  pt_entry_t save2;
        mp_disable_preemption();
	if (*(pt_entry_t *) CM2)
		panic("bzero_phys: CMAP busy");

	*(pt_entry_t *) CM2 = INTEL_PTE_VALID | INTEL_PTE_RW | (src & PG_FRAME) | 
	  INTEL_PTE_REF | INTEL_PTE_MOD;
	save2=*(pt_entry_t *)CM2;
	invlpg((u_int)CA2);

        bzero((void *)((unsigned int)CA2 | (src & INTEL_OFFMASK)), bytes);
	if (save2 != *(pt_entry_t *)CM2)  panic("bzero_phys CMAP changed");
	*(pt_entry_t *) CM2 = 0;
	mp_enable_preemption();
}

/*
 * copy 'size' bytes from physical to physical address
 * the caller must validate the physical ranges 
 *
 * if flush_action == 0, no cache flush necessary
 * if flush_action == 1, flush the source
 * if flush_action == 2, flush the dest
 * if flush_action == 3, flush both source and dest
 */

kern_return_t
copyp2p(vm_offset_t	source,
	vm_offset_t	dest,
	unsigned int	size,
	unsigned int	flush_action)
{

        switch(flush_action) {
	case 1:
	        flush_dcache(source, size, 1);
		break;
	case 2:
	        flush_dcache(dest, size, 1);
		break;
	case 3:
	        flush_dcache(source, size, 1);
	        flush_dcache(dest, size, 1);
		break;

	}
        bcopy_phys((addr64_t)source, (addr64_t)dest, (vm_size_t)size);	/* Do a physical copy */

        switch(flush_action) {
	case 1:
	        flush_dcache(source, size, 1);
		break;
	case 2:
	        flush_dcache(dest, size, 1);
		break;
	case 3:
	        flush_dcache(source, size, 1);
	        flush_dcache(dest, size, 1);
		break;

	}
	return KERN_SUCCESS;
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
  vm_offset_t src = low32(src64);
  vm_offset_t dst = low32(dst64);
  pt_entry_t save1,save2;
  /* ensure we stay within a page */
  if ( (((src & (NBPG-1)) + bytes) > NBPG) ||
       (((dst & (NBPG-1)) + bytes) > NBPG) ) panic("bcopy_phys");
  mp_disable_preemption();
	if (*(pt_entry_t *) CM1 || *(pt_entry_t *) CM2)
		panic("bcopy_phys: CMAP busy");

	*(pt_entry_t *) CM1 = INTEL_PTE_VALID | (src & PG_FRAME) | INTEL_PTE_REF;
	*(pt_entry_t *) CM2 = INTEL_PTE_VALID | INTEL_PTE_RW | (dst & PG_FRAME) | 
	  INTEL_PTE_REF | INTEL_PTE_MOD;
	save1 = *(pt_entry_t *)CM1;save2 = *(pt_entry_t *)CM2;
	invlpg((u_int)CA1);
	invlpg((u_int)CA2);

        bcopy((void *) ((uintptr_t)CA1 | (src & INTEL_OFFMASK)),
	      (void *) ((uintptr_t)CA2 | (dst & INTEL_OFFMASK)), bytes);
	if ( (save1 != *(pt_entry_t *)CM1) || (save2 != *(pt_entry_t *)CM2)) panic("bcopy_phys CMAP changed");
	*(pt_entry_t *) CM1 = 0;
	*(pt_entry_t *) CM2 = 0;
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
ml_phys_read_data( vm_offset_t paddr, int size )
{
    unsigned int result;
    pt_entry_t save;
    mp_disable_preemption();
	if (*(pt_entry_t *) CM3)
		panic("ml_phys_read_data: CMAP busy");

	*(pt_entry_t *) CM3 = INTEL_PTE_VALID | (paddr & PG_FRAME) | INTEL_PTE_REF;
        save = *(pt_entry_t *)CM3;
	invlpg((u_int)CA3);


        switch (size) {
            unsigned char s1;
            unsigned short s2;
        case 1:
            s1 = *(unsigned char *)((unsigned int)CA3 | (paddr & INTEL_OFFMASK));
            result = s1;
            break;
        case 2:
            s2 = *(unsigned short *)((unsigned int)CA3 | (paddr & INTEL_OFFMASK));
            result = s2;
            break;
        case 4:
        default:
            result = *(unsigned int *)((unsigned int)CA3 | (paddr & INTEL_OFFMASK));
            break;
        }

	if (save != *(pt_entry_t *)CM3) panic("ml_phys_read_data CMAP changed");
	*(pt_entry_t *) CM3 = 0;
	mp_enable_preemption();
        return result;
}

static unsigned long long
ml_phys_read_long_long( vm_offset_t paddr )
{
    unsigned long long result;
    pt_entry_t save;
    mp_disable_preemption();
	if (*(pt_entry_t *) CM3)
		panic("ml_phys_read_data: CMAP busy");

	*(pt_entry_t *) CM3 = INTEL_PTE_VALID | (paddr & PG_FRAME) | INTEL_PTE_REF;
        save = *(pt_entry_t *)CM3;
	invlpg((u_int)CA3);

        result = *(unsigned long long *)((unsigned int)CA3 | (paddr & INTEL_OFFMASK));

	if (save != *(pt_entry_t *)CM3) panic("ml_phys_read_data CMAP changed");
	*(pt_entry_t *) CM3 = 0;
	mp_enable_preemption();
        return result;
}

unsigned int ml_phys_read( vm_offset_t paddr)
{
    return ml_phys_read_data(paddr, 4);
}

unsigned int ml_phys_read_word(vm_offset_t paddr) {
    return ml_phys_read_data(paddr, 4);
}

unsigned int ml_phys_read_64(addr64_t paddr64)
{
    return ml_phys_read_data(low32(paddr64), 4);
}

unsigned int ml_phys_read_word_64(addr64_t paddr64)
{
    return ml_phys_read_data(low32(paddr64), 4);
}

unsigned int ml_phys_read_half(vm_offset_t paddr)
{
    return ml_phys_read_data(paddr, 2);
}

unsigned int ml_phys_read_half_64(addr64_t paddr64)
{
    return ml_phys_read_data(low32(paddr64), 2);
}

unsigned int ml_phys_read_byte(vm_offset_t paddr)
{
    return ml_phys_read_data(paddr, 1);
}

unsigned int ml_phys_read_byte_64(addr64_t paddr64)
{
    return ml_phys_read_data(low32(paddr64), 1);
}

unsigned long long ml_phys_read_double(vm_offset_t paddr)
{
    return ml_phys_read_long_long(paddr);
}

unsigned long long ml_phys_read_double_64(addr64_t paddr)
{
    return ml_phys_read_long_long(low32(paddr));
}


/*
 *  Write data to a physical address. Memory should not be cache inhibited.
 */

static void
ml_phys_write_data( vm_offset_t paddr, unsigned long data, int size )
{
    pt_entry_t save;
    mp_disable_preemption();
	if (*(pt_entry_t *) CM3)
		panic("ml_phys_write_data: CMAP busy");

	*(pt_entry_t *) CM3 = INTEL_PTE_VALID | INTEL_PTE_RW | (paddr & PG_FRAME) | 
	  INTEL_PTE_REF | INTEL_PTE_MOD;
        save = *(pt_entry_t *)CM3;
	invlpg((u_int)CA3);

        switch (size) {
        case 1:
            *(unsigned char *)((unsigned int)CA3 | (paddr & INTEL_OFFMASK)) = (unsigned char)data;
            break;
        case 2:
            *(unsigned short *)((unsigned int)CA3 | (paddr & INTEL_OFFMASK)) = (unsigned short)data;
            break;
        case 4:
        default:
            *(unsigned int *)((unsigned int)CA3 | (paddr & INTEL_OFFMASK)) = data;
            break;
        }

	if (save != *(pt_entry_t *)CM3) panic("ml_phys_write_data CMAP changed");
	*(pt_entry_t *) CM3 = 0;
	mp_enable_preemption();
}

static void
ml_phys_write_long_long( vm_offset_t paddr, unsigned long long data )
{
    pt_entry_t save;
    mp_disable_preemption();
	if (*(pt_entry_t *) CM3)
		panic("ml_phys_write_data: CMAP busy");

	*(pt_entry_t *) CM3 = INTEL_PTE_VALID | INTEL_PTE_RW | (paddr & PG_FRAME) | 
	  INTEL_PTE_REF | INTEL_PTE_MOD;
        save = *(pt_entry_t *)CM3;
	invlpg((u_int)CA3);

        *(unsigned long long *)((unsigned int)CA3 | (paddr & INTEL_OFFMASK)) = data;

	if (save != *(pt_entry_t *)CM3) panic("ml_phys_write_data CMAP changed");
	*(pt_entry_t *) CM3 = 0;
	mp_enable_preemption();
}

void ml_phys_write_byte(vm_offset_t paddr, unsigned int data)
{
    ml_phys_write_data(paddr, data, 1);
}

void ml_phys_write_byte_64(addr64_t paddr, unsigned int data)
{
    ml_phys_write_data(low32(paddr), data, 1);
}

void ml_phys_write_half(vm_offset_t paddr, unsigned int data)
{
    ml_phys_write_data(paddr, data, 2);
}

void ml_phys_write_half_64(addr64_t paddr, unsigned int data)
{
    ml_phys_write_data(low32(paddr), data, 2);
}

void ml_phys_write(vm_offset_t paddr, unsigned int data)
{
    ml_phys_write_data(paddr, data, 4);
}

void ml_phys_write_64(addr64_t paddr, unsigned int data)
{
    ml_phys_write_data(low32(paddr), data, 4);
}

void ml_phys_write_word(vm_offset_t paddr, unsigned int data)
{
    ml_phys_write_data(paddr, data, 4);
}

void ml_phys_write_word_64(addr64_t paddr, unsigned int data)
{
    ml_phys_write_data(low32(paddr), data, 4);
}


void ml_phys_write_double(vm_offset_t paddr, unsigned long long data)
{
    ml_phys_write_long_long(paddr, data);
}

void ml_phys_write_double_64(addr64_t paddr, unsigned long long data)
{
    ml_phys_write_long_long(low32(paddr), data);
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
ml_probe_read_64(addr64_t paddr, unsigned int *val)
{
    *val = ml_phys_read_64(paddr);
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

#include <libkern/OSAtomic.h>

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
  pmap_paddr_t src;
  int i;
  int cnt = PAGE_SIZE/sizeof(unsigned int);
  unsigned int *addr;
  mp_disable_preemption();
  if (*(pt_entry_t *) CM2)
        panic("fillPage: CMAP busy");
  src = (pmap_paddr_t)i386_ptob(pa);
  *(pt_entry_t *) CM2 = INTEL_PTE_VALID | INTEL_PTE_RW | (src & PG_FRAME) | 
      INTEL_PTE_REF | INTEL_PTE_MOD;
      invlpg((u_int)CA2);

  for (i = 0, addr = (unsigned int *)CA2; i < cnt ; i++ )
    *addr++ = fill;

  *(pt_entry_t *) CM2 = 0;
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
    __asm__ volatile(".byte 0x0F; .byte 0xae; .byte 0x38" : : "a" (ptr));
}

void dcache_incoherent_io_store64(addr64_t pa, unsigned int count)
{
    if (cpuid_features() & CPUID_FEATURE_CLFSH)
    {
        uint32_t  linesize = cpuid_info()->cache_linesize;
        addr64_t  addr;
        uint32_t  offset, chunk;
        boolean_t istate;

        istate = ml_set_interrupts_enabled(FALSE);

        if (*(pt_entry_t *) CM2)
                panic("cache_flush_page_phys: CMAP busy");

        offset = pa & (linesize - 1);
        count += offset;
        addr   = pa - offset;
        offset = addr & ((addr64_t) (page_size - 1));
        chunk  = page_size - offset;

        do
        {
            if (chunk > count)
                chunk = count;

            *(pt_entry_t *) CM2 = i386_ptob(atop_64(addr)) | INTEL_PTE_VALID;
            invlpg((u_int)CA2);
    
            for (; offset < chunk; offset += linesize)
                __clflush((void *)(((u_int)CA2) + offset));

            count -= chunk;
            addr  += chunk;
            chunk  = page_size;
            offset = 0;
        }
        while (count);

        *(pt_entry_t *) CM2 = 0;

        (void) ml_set_interrupts_enabled(istate);
    }
    else
        __wbinvd();
    __sfence();
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

kern_return_t copypv(addr64_t		src64,
		     addr64_t		snk64,
		     unsigned int	size,
		     int		which)
{
 
	vm_map_t map;
	kern_return_t ret;
	vm_offset_t source, sink;
	vm_offset_t vaddr;
	vm_offset_t paddr;
	spl_t s;
	unsigned int lop, csize;
	int needtran, bothphys;
	vm_prot_t prot;
	pt_entry_t *ptep;
	
	map = (which & cppvKmap) ? kernel_map : current_map_fast();

	source = low32(src64);
	sink = low32(snk64);

	if((which & (cppvPsrc | cppvPsnk)) == 0 ) {		/* Make sure that only one is virtual */
		panic("copypv: no more than 1 parameter may be virtual\n");	/* Not allowed */
	}
	
	bothphys = 1;									/* Assume both are physical */
	
	if(!(which & cppvPsnk)) {						/* Is there a virtual page here? */
		vaddr = sink;								/* Sink side is virtual */
		bothphys = 0;								/* Show both aren't physical */
		prot = VM_PROT_READ | VM_PROT_WRITE;		/* Sink always must be read/write */
	} else /* if(!(which & cppvPsrc)) */ {				/* Source side is virtual */
		vaddr = source;								/* Source side is virtual */
		bothphys = 0;								/* Show both aren't physical */
		prot = VM_PROT_READ; 						/* Virtual source is always read only */
	}

	needtran = 1;									/* Show we need to map the virtual the first time */
	s = splhigh();									/* Don't bother me */

	while(size) {

		if(!bothphys && (needtran || !(vaddr & 4095LL))) {	/* If first time or we stepped onto a new page, we need to translate */
		        needtran = 0;
			while(1) {
			  ptep = pmap_mapgetpte(map, vaddr);
			  if((0 == ptep) || ((*ptep & INTEL_PTE_VALID) == 0)) {
					splx(s);						/* Restore the interrupt level */
					ret = vm_fault(map, vm_map_trunc_page(vaddr), prot, FALSE, THREAD_UNINT, NULL, 0);	/* Didn't find it, try to fault it in... */
				
					if(ret != KERN_SUCCESS)return KERN_FAILURE;	/* Didn't find any, return no good... */
					
					s = splhigh();					/* Don't bother me */
					continue;						/* Go try for the map again... */
	
				}
		
				/* Note that we have to have the destination writable.  So, if we already have it, or we are mapping the source,
					we can just leave.
				*/		
				if((which & cppvPsnk) || (*ptep & INTEL_PTE_WRITE)) break;		/* We got it mapped R/W or the source is not virtual, leave... */
				splx(s);							/* Restore the interrupt level */
				
				ret = vm_fault(map, vm_map_trunc_page(vaddr), VM_PROT_READ | VM_PROT_WRITE, FALSE, THREAD_UNINT, NULL, 0);	/* check for a COW area */
				if (ret != KERN_SUCCESS) return KERN_FAILURE;	/* We couldn't get it R/W, leave in disgrace... */
				s = splhigh();						/* Don't bother me */
			}

		        paddr = pte_to_pa(*ptep) | (vaddr & 4095);
	
			if(which & cppvPsrc) sink = paddr;		/* If source is physical, then the sink is virtual */
			else source = paddr;					/* Otherwise the source is */
		}
			
		lop = (unsigned int)(4096LL - (sink & 4095LL));		/* Assume sink smallest */
		if(lop > (unsigned int)(4096LL - (source & 4095LL))) lop = (unsigned int)(4096LL - (source & 4095LL));	/* No, source is smaller */
		
		csize = size;								/* Assume we can copy it all */
		if(lop < size) csize = lop;					/* Nope, we can't do it all */
		
		if(which & cppvFsrc) flush_dcache64((addr64_t)source, csize, 1);	/* If requested, flush source before move */
		if(which & cppvFsnk) flush_dcache64((addr64_t)sink, csize, 1);	/* If requested, flush sink before move */

		bcopy_phys((addr64_t)source, (addr64_t)sink, csize);			/* Do a physical copy, virtually */
		
		if(which & cppvFsrc) flush_dcache64((addr64_t)source, csize, 1);	/* If requested, flush source after move */
		if(which & cppvFsnk) flush_dcache64((addr64_t)sink, csize, 1);	/* If requested, flush sink after move */


/*
 *		Note that for certain ram disk flavors, we may be copying outside of known memory.
 *		Therefore, before we try to mark it modifed, we check if it exists.
 */

		if( !(which & cppvNoModSnk)) {
		  if (phys_page_exists((ppnum_t)sink >> 12))
			mapping_set_mod((ppnum_t)(sink >> 12));		/* Make sure we know that it is modified */
		}
		if( !(which & cppvNoRefSrc)) {
		  if (phys_page_exists((ppnum_t)source >> 12))
			mapping_set_ref((ppnum_t)(source >> 12));		/* Make sure we know that it is modified */
		}


		size = size - csize;						/* Calculate what is left */
		vaddr = vaddr + csize;						/* Move to next sink address */
		source = source + csize;					/* Bump source to next physical address */
		sink = sink + csize;						/* Bump sink to next physical address */
	}
	
	splx(s);										/* Open up for interrupts */

	return KERN_SUCCESS;
}

void switch_to_serial_console(void)
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
	boolean_t	istate;
	int		i;
	unsigned int	*cacheline_addr;
	int		cacheline_size = cpuid_info()->cache_linesize;
	int		cachelines_in_page = PAGE_SIZE/cacheline_size;

	/*
	 * If there's no clflush instruction, we're sadly forced to use wbinvd.
	 */
	if (!(cpuid_features() & CPUID_FEATURE_CLFSH)) {
		asm volatile("wbinvd" : : : "memory");
		return;
	} 

	istate = ml_set_interrupts_enabled(FALSE);

	if (*(pt_entry_t *) CM2)
		panic("cache_flush_page_phys: CMAP busy");

	*(pt_entry_t *) CM2 = i386_ptob(pa) | INTEL_PTE_VALID;
	invlpg((u_int)CA2);

	for (i = 0, cacheline_addr = (unsigned int *)CA2;
	     i < cachelines_in_page;
	     i++, cacheline_addr += cacheline_size) {
		asm volatile("clflush %0" : : "m" (cacheline_addr));
	}

	*(pt_entry_t *) CM2 = 0;

	(void) ml_set_interrupts_enabled(istate);

}

