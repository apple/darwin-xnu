/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
ml_phys_read_data(pmap_paddr_t paddr, int size)
{
	unsigned int result;

        switch (size) {
            unsigned char s1;
            unsigned short s2;
        case 1:
            s1 = *(unsigned char *)PHYSMAP_PTOV(paddr);
            result = s1;
            break;
        case 2:
            s2 = *(unsigned short *)PHYSMAP_PTOV(paddr);
            result = s2;
            break;
        case 4:
        default:
            result = *(unsigned int *)PHYSMAP_PTOV(paddr);
            break;
        }

        return result;
}

static unsigned long long
ml_phys_read_long_long(pmap_paddr_t paddr )
{
	return *(unsigned long long *)PHYSMAP_PTOV(paddr);
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

static void
ml_phys_write_data(pmap_paddr_t paddr, unsigned long data, int size)
{
        switch (size) {
        case 1:
	    *(unsigned char *)PHYSMAP_PTOV(paddr) = (unsigned char)data;
            break;
        case 2:
	    *(unsigned short *)PHYSMAP_PTOV(paddr) = (unsigned short)data;
            break;
        case 4:
        default:
	    *(unsigned int *)PHYSMAP_PTOV(paddr) = (unsigned int)data;
            break;
        }
}

static void
ml_phys_write_long_long(pmap_paddr_t paddr, unsigned long long data)
{
	*(unsigned long long *)PHYSMAP_PTOV(paddr) = data;
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
	__unused natural_t	*buf,
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
        uint32_t  linesize = cpuid_info()->cache_linesize;
        addr64_t  addr;
        boolean_t istate;

	__mfence();

        istate = ml_set_interrupts_enabled(FALSE);

	for (addr = pa; addr < pa + count; addr += linesize)
		__clflush(PHYSMAP_PTOV(addr));

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
	boolean_t	istate;
	unsigned char	*cacheline_addr;
	int		cacheline_size = cpuid_info()->cache_linesize;
	int		cachelines_to_flush = PAGE_SIZE/cacheline_size;

	__mfence();

	istate = ml_set_interrupts_enabled(FALSE);

	for (cacheline_addr = (unsigned char *)PHYSMAP_PTOV(i386_ptob(pa));
	     cachelines_to_flush > 0;
	     cachelines_to_flush--, cacheline_addr += cacheline_size) {
		__clflush((void *) cacheline_addr);
	}

	(void) ml_set_interrupts_enabled(istate);

	__mfence();
}


static int copyio(int, user_addr_t, char *, vm_size_t, vm_size_t *, int);
static int copyio_phys(addr64_t, addr64_t, vm_size_t, int);

/*
 * The copy engine has the following characteristics
 *   - copyio() handles copies to/from user or kernel space
 *   - copypv() deals with physical or virtual addresses
 *
 * Readers familiar with the 32-bit kernel will expect Joe's thesis at this
 * point describing the full glory of the copy window implementation. In K64,
 * however, there is no need for windowing. Thanks to the vast shared address
 * space, the kernel has direct access to userspace and to physical memory.
 *
 * User virtual addresses are accessible provided the user's cr3 is loaded.
 * Physical addresses are accessible via the direct map and the PHYSMAP_PTOV()
 * translation.
 *
 * Copyin/out variants all boil done to just these 2 routines in locore.s which
 * provide fault-recoverable copying:
 */
extern int _bcopy(const void *, void *, vm_size_t);
extern int _bcopystr(const void *, void *, vm_size_t, vm_size_t *);


/*
 * Types of copies:
 */
#define COPYIN		0	/* from user virtual to kernel virtual */
#define COPYOUT		1	/* from kernel virtual to user virtual */
#define COPYINSTR	2	/* string variant of copyout */
#define COPYINPHYS	3	/* from user virtual to kernel physical */
#define COPYOUTPHYS	4	/* from kernel physical to user virtual */


static int
copyio(int copy_type, user_addr_t user_addr, char *kernel_addr,
       vm_size_t nbytes, vm_size_t *lencopied, int use_kernel_map)
{
        thread_t	thread;
	pmap_t		pmap;
	vm_size_t	bytes_copied;
	int		error = 0;
	boolean_t	istate = FALSE;
	boolean_t	recursive_CopyIOActive;
#if KDEBUG
	int		debug_type = 0xeff70010;
	debug_type += (copy_type << 2);
#endif

	thread = current_thread();

	KERNEL_DEBUG(debug_type | DBG_FUNC_START,
		     (unsigned)(user_addr >> 32), (unsigned)user_addr,
		     nbytes, thread->machine.copyio_state, 0);

	if (nbytes == 0)
		goto out;

        pmap = thread->map->pmap;

	/* Sanity and security check for addresses to/from a user */
	if ((copy_type == COPYIN ||
	     copy_type == COPYINSTR ||
	     copy_type == COPYOUT) &&
	    (pmap != kernel_pmap) &&
	    ((vm_offset_t)kernel_addr < VM_MIN_KERNEL_AND_KEXT_ADDRESS ||
	     !IS_USERADDR64_CANONICAL(user_addr))) {
		error = EACCES;
		goto out;
	}

	/*
	 * If the no_shared_cr3 boot-arg is set (true), the kernel runs on 
	 * its own pmap and cr3 rather than the user's -- so that wild accesses
	 * from kernel or kexts can be trapped. So, during copyin and copyout,
	 * we need to switch back to the user's map/cr3. The thread is flagged
	 * "CopyIOActive" at this time so that if the thread is pre-empted,
	 * we will later restore the correct cr3.
	 */
	recursive_CopyIOActive = thread->machine.specFlags & CopyIOActive;
	thread->machine.specFlags |= CopyIOActive;
	if (no_shared_cr3) {
		istate = ml_set_interrupts_enabled(FALSE);
 		if (get_cr3() != pmap->pm_cr3)
			set_cr3(pmap->pm_cr3);
	}

	/*
	 * Ensure that we're running on the target thread's cr3.
	 */
	if ((pmap != kernel_pmap) && !use_kernel_map &&
	    (get_cr3() != pmap->pm_cr3)) {
		panic("copyio(%d,%p,%p,%ld,%p,%d) cr3 is %p expects %p",
			copy_type, (void *)user_addr, kernel_addr, nbytes, lencopied, use_kernel_map,
			(void *) get_cr3(), (void *) pmap->pm_cr3);
	}
	if (no_shared_cr3)
		(void) ml_set_interrupts_enabled(istate);

	KERNEL_DEBUG(0xeff70044 | DBG_FUNC_NONE, (unsigned)user_addr,
		     (unsigned)kernel_addr, nbytes, 0, 0);

        switch (copy_type) {

	case COPYIN:
	        error = _bcopy((const void *) user_addr,
				kernel_addr,
				nbytes);
		break;
			
	case COPYOUT:
	        error = _bcopy(kernel_addr,
				(void *) user_addr,
				nbytes);
		break;

	case COPYINPHYS:
	        error = _bcopy((const void *) user_addr,
				PHYSMAP_PTOV(kernel_addr),
				nbytes);
		break;

	case COPYOUTPHYS:
	        error = _bcopy((const void *) PHYSMAP_PTOV(kernel_addr),
				(void *) user_addr,
				nbytes);
		break;

	case COPYINSTR:
	        error = _bcopystr((const void *) user_addr,
				kernel_addr,
				(int) nbytes,
				&bytes_copied);

		/*
		 * lencopied should be updated on success
		 * or ENAMETOOLONG...  but not EFAULT
		 */
		if (error != EFAULT)
		        *lencopied = bytes_copied;

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
			break;
		} else {
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
		break;
	}

	if (!recursive_CopyIOActive)
		thread->machine.specFlags &= ~CopyIOActive;
	if (no_shared_cr3) {
		istate = ml_set_interrupts_enabled(FALSE);
		if  (get_cr3() != kernel_pmap->pm_cr3)
			set_cr3(kernel_pmap->pm_cr3);
		(void) ml_set_interrupts_enabled(istate);
	}

out:
	KERNEL_DEBUG(debug_type | DBG_FUNC_END, (unsigned)user_addr,
		     (unsigned)kernel_addr, (unsigned)nbytes, error, 0);

	return (error);
}


static int
copyio_phys(addr64_t source, addr64_t sink, vm_size_t csize, int which)
{
        char	    *paddr;
	user_addr_t vaddr;
	int         ctype;

	if (which & cppvPsnk) {
		paddr  = (char *)sink;
	        vaddr  = (user_addr_t)source;
		ctype  = COPYINPHYS;
	} else {
	        paddr  = (char *)source;
		vaddr  = (user_addr_t)sink;
		ctype  = COPYOUTPHYS;
	}
	return copyio(ctype, vaddr, paddr, csize, NULL, which & cppvKmap);
}

int
copyinmsg(const user_addr_t user_addr, char *kernel_addr, mach_msg_size_t nbytes)
{
    return copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0);
}    

int
copyin(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
{
    return copyio(COPYIN, user_addr, kernel_addr, nbytes, NULL, 0);
}

int
copyinstr(const user_addr_t user_addr,  char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied)
{
    *lencopied = 0;

    return copyio(COPYINSTR, user_addr, kernel_addr, nbytes, lencopied, 0);
}

int
copyoutmsg(const char *kernel_addr, user_addr_t user_addr, mach_msg_size_t nbytes)
{
    return copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0);
}

int
copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
    return copyio(COPYOUT, user_addr, (char *)(uintptr_t)kernel_addr, nbytes, NULL, 0);
}


kern_return_t
copypv(addr64_t src64, addr64_t snk64, unsigned int size, int which)
{
	unsigned int lop, csize;
	int bothphys = 0;
	
	KERNEL_DEBUG(0xeff7004c | DBG_FUNC_START, (unsigned)src64,
		     (unsigned)snk64, size, which, 0);

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
		size   -= csize;					/* Calculate what is left */
		snk64 += csize;					/* Bump sink to next physical address */
		src64 += csize;					/* Bump source to next physical address */
	}
	KERNEL_DEBUG(0xeff7004c | DBG_FUNC_END, (unsigned)src64,
		     (unsigned)snk64, size, which, 0);

	return KERN_SUCCESS;
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
