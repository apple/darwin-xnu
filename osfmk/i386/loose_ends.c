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
#include <i386/misc_protos.h>

	/*
	 * Should be rewritten in asm anyway.
	 */



/*
 *              Copies data from a physical page to a virtual page.  This is used to
 *              move data from the kernel to user state.
 *
 */

kern_return_t
copyp2v(char *from, char *to, unsigned int size) {

  return(copyout(phystokv(from), to, size));
}

/*
 * bcopy_phys - like bcopy but copies from/to physical addresses.
 *              this is trivial since all phys mem is mapped into 
 *              kernel virtual space
 */

void
bcopy_phys(const char *from, char *to, vm_size_t bytes)
{
  bcopy((char *)phystokv(from), (char *)phystokv(to), bytes);
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
