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
#include <vm/pmap.h>
#include <i386/param.h>
#include <i386/misc_protos.h>

#define value_64bit(value)  ((value) & 0xFFFFFFFF00000000LL)
#define low32(x)  ((unsigned int)((x) & 0x00000000FFFFFFFFLL))

	/*
	 * Should be rewritten in asm anyway.
	 */


void
bzero_phys(addr64_t p, uint32_t len)
{
	bzero((char *)phystokv(low32(p)), len);
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

extern void flush_dcache(vm_offset_t addr, unsigned count, int phys);

kern_return_t copyp2p(vm_offset_t source, vm_offset_t dest, unsigned int size, unsigned int flush_action) {

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
 *              Copies data from a physical page to a virtual page.  This is used to
 *              move data from the kernel to user state.
 *
 */
#if 0
kern_return_t
copyp2v(char *from, char *to, unsigned int size) {

  return(copyout(phystokv(from), to, size));
}
#endif

/*
 *              Copies data from a virtual page to a physical page.  This is used to
 *              move data from the user address space into the kernel.
 *
 */
#if 0
kern_return_t
copyv2p(char *from, char *to, unsigned int size) {

  return(copyin(from, phystokv(to), size));
}
#endif

/*
 * bcopy_phys - like bcopy but copies from/to physical addresses.
 *              this is trivial since all phys mem is mapped into 
 *              kernel virtual space
 */

void
bcopy_phys(addr64_t from, addr64_t to, vm_size_t bytes)
{
  /* this will die horribly if we ever run off the end of a page */
  if ( value_64bit(from) || value_64bit(to)) panic("bcopy_phys: 64 bit value");
  bcopy((char *)phystokv(low32(from)),
	(char *)phystokv(low32(to)), bytes);
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

void
bcopy(
	const char	*from,
	char		*to,
	vm_size_t	bytes)		/* num bytes to copy */
{
	ovbcopy(from, to, bytes);
}

int bcmp(
	const char	*a,
	const char	*b,
	vm_size_t	len)
{
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
	register char *s1, *s2;
	register n;
{
	while (--n >= 0)
		if (*s1++ != *s2++)
			return (*--s1 - *--s2);
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
	natural_t	*buf,
	vm_size_t	callstack_max)
{
}

#endif	/* MACH_ASSERT */




void fillPage(ppnum_t pa, unsigned int fill)
{
  unsigned int *addr = (unsigned int *)phystokv(i386_ptob(pa));
  int i;
  int cnt = NBPG/sizeof(unsigned int);

  for (i = 0; i < cnt ; i++ )
    *addr++ = fill;
}

#define cppvPHYS      (cppvPsnk|cppvPsrc)

kern_return_t copypv(addr64_t source, addr64_t sink, unsigned int size, int which)
{
    char *src32, *dst32;

    if (value_64bit(source) | value_64bit(sink)) panic("copypv: 64 bit value");

    src32 = (char *)low32(source);
    dst32 = (char *)low32(sink);

    if (which & cppvFsrc) flush_dcache(source, size, 1);	/* If requested, flush source before move */
    if (which & cppvFsnk) flush_dcache(sink, size, 1);	/* If requested, flush sink before move */

    switch (which & cppvPHYS) {

    case cppvPHYS:
        /*
	 * both destination and source are physical
	 */
        bcopy_phys(source, sink, (vm_size_t)size);
	break;

    case cppvPsnk:
        /*
	 * destination is physical, source is virtual
	 */
        if (which & cppvKmap)
   	    /*
	     * source is kernel virtual
	     */
	    bcopy(src32, (char *)phystokv(dst32), size);
	else
   	    /*
	     * source is user virtual
	     */
	    copyin(src32, (char *)phystokv(dst32), size);
	break;

    case cppvPsrc:
        /*
	 * source is physical, destination is virtual
	 */
        if (which & cppvKmap)
   	    /*
	     * destination is kernel virtual
	     */
	    bcopy((char *)phystokv(src32), dst32, size);
	else
   	    /*
	     * destination is user virtual
	     */
	    copyout((char *)phystokv(src32), dst32, size);
	break;

    default:
        panic("copypv: both virtual");
    }

    if (which & cppvFsrc) flush_dcache(source, size, 1);	/* If requested, flush source before move */
    if (which & cppvFsnk) flush_dcache(sink, size, 1);	/* If requested, flush sink before move */

    return KERN_SUCCESS;
}


void flush_dcache64(addr64_t addr, unsigned count, int phys)
{
}

void invalidate_icache64(addr64_t addr, unsigned cnt, int phys)
{
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

boolean_t
mutex_preblock(
	mutex_t		*mutex,
	thread_t	thread)
{
	return (FALSE);
}
