/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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

#include <vm/pmap.h>
#include <sys/kdebug.h>

#ifdef MACH_KERNEL_PRIVATE

/*
 * pmap locking
 */

#define PMAP_LOCK(pmap) {		\
	simple_lock(&(pmap)->lock);	\
}

#define PMAP_UNLOCK(pmap) {			\
	simple_unlock(&(pmap)->lock);		\
}

extern void pmap_flush_tlbs(pmap_t pmap);

#define PMAP_UPDATE_TLBS(pmap, s, e)					\
	pmap_flush_tlbs(pmap)

#define	iswired(pte)	((pte) & INTEL_PTE_WIRED)

#ifdef	PMAP_TRACES
extern	boolean_t	pmap_trace;
#define PMAP_TRACE(x,a,b,c,d,e)						\
	if (pmap_trace) {						\
		KERNEL_DEBUG_CONSTANT(x,a,b,c,d,e);			\
	}
#else
#define PMAP_TRACE(x,a,b,c,d,e)	KERNEL_DEBUG(x,a,b,c,d,e)
#endif /* PMAP_TRACES */

void		pmap_expand_pml4(
			pmap_t		map,
			vm_map_offset_t	v);

void		pmap_expand_pdpt(
			pmap_t		map,
			vm_map_offset_t	v);
#if	defined(__x86_64__)
extern const boolean_t cpu_64bit;
#else
extern boolean_t cpu_64bit;
#endif

#endif /* MACH_KERNEL_PRIVATE */
