/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 * Copyright (c) 1990 The University of Utah and
 * the Center for Software Science at the University of Utah (CSS).
 * All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software is hereby
 * granted provided that (1) source code retains these copyright, permission,
 * and disclaimer notices, and (2) redistributions including binaries
 * reproduce the notices in supporting documentation, and (3) all advertising
 * materials mentioning features or use of this software display the following
 * acknowledgement: ``This product includes software developed by the Center
 * for Software Science at the University of Utah.''
 *
 * THE UNIVERSITY OF UTAH AND CSS ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSS DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSS requests users of this software to return to css-dist@cs.utah.edu any
 * improvements that they make and grant CSS redistribution rights.
 *
 * 	Utah $Hdr: pmap.h 1.13 91/09/25$
 *	Author: Mike Hibler, Bob Wheeler, University of Utah CSS, 9/90
 */

#ifndef	_PPC_PMAP_H_
#define	_PPC_PMAP_H_

#include <mach/vm_types.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <kern/queue.h>
#include <vm/pmap.h>

struct pmap {
	queue_head_t	pmap_link;		/* MUST BE FIRST */
	unsigned int	pmapvr;			/* Virtual to real conversion mask */
	space_t			space;			/* space for this pmap */
#define BMAPLOCK 0x00000001
	struct blokmap	*bmaps;			/* Physical pointer to odd-size page maps */
	int				ref_count;		/* reference count */
	unsigned int	vflags;			/* Alternate map validity flags */
#define pmapBatVal  0xFF000000
#define pmapBatDVal 0xF0000000
#define pmapBatIVal 0x0F000000
#define pmapFlags   0x00FF0000
#define pmapSubord  0x00800000
#define pmapVMhost  0x00400000
#define pmapAltSeg	0x0000FFFF
	unsigned int	spaceNum;		/* Space number */
/*	PPC line boundary here - 020 */
	unsigned int	pmapSegs[16];	/* Contents of segment register if different than base space */
/*	PPC line boundary here - 060 */
	struct pmap		*pmapPmaps[16];	/* Pointer to next lower level of pmaps */
/*	PPC line boundary here - 0A0 */
/*	Note: this must start on a word boundary */
	unsigned short	pmapUsage[128];	/* Count of pages mapped into 32mb (8192 page) slots */
#define pmapUsageShft 25
#define pmapUsageMask 0x0000007F
#define pmapUsageSize (32*1024*1024)
	
/*	PPC line boundary here - 1A0 */
	struct pmap_statistics	stats;	/* statistics */
	decl_simple_lock_data(,lock)	/* lock on map */
	
/* Need to pad out to a power of 2 - right now it is 512 bytes */
#define pmapSize 512
};

#define PMAP_NULL  ((pmap_t) 0)

extern pmap_t	kernel_pmap;			/* The kernel's map */
extern pmap_t	cursor_pmap;			/* The pmap to start allocations with */

#define	PMAP_SWITCH_USER(th, map, my_cpu) th->map = map;	

#define PMAP_ACTIVATE(pmap, th, cpu)
#define PMAP_DEACTIVATE(pmap, th, cpu)
#define PMAP_CONTEXT(pmap,th)

#define pmap_kernel_va(VA)	\
	(((VA) >= VM_MIN_KERNEL_ADDRESS) && ((VA) <= VM_MAX_KERNEL_ADDRESS))

#define	PPC_SID_KERNEL  0       /* Must change KERNEL_SEG_REG0_VALUE if !0 */
#define SID_MAX	((1<<20) - 1)	/* Space ID=20 bits, segment_id=SID + 4 bits */

#define pmap_kernel()			(kernel_pmap)
#define	pmap_resident_count(pmap)	((pmap)->stats.resident_count)
#define pmap_remove_attributes(pmap,start,end)
#define pmap_copy(dpmap,spmap,da,len,sa)
#define	pmap_update()

#define pmap_phys_address(x)	((x) << PPC_PGSHIFT)
#define pmap_phys_to_frame(x)	((x) >> PPC_PGSHIFT)

#define PMAP_DEFAULT_CACHE	0
#define PMAP_INHIBIT_CACHE	1
#define PMAP_GUARDED_CACHE	2
#define PMAP_ACTIVATE_CACHE	4
#define PMAP_NO_GUARD_CACHE	8

/* corresponds to cached, coherent, not writethru, not guarded */
#define VM_WIMG_DEFAULT		VM_MEM_COHERENT
#define VM_WIMG_IO		VM_MEM_COHERENT | 	\
				VM_MEM_NOT_CACHEABLE | VM_MEM_GUARDED

/* 
 * prototypes.
 */
extern void 		ppc_protection_init(void);
extern vm_offset_t phystokv(vm_offset_t pa);					/* Get kernel virtual address from physical */
extern vm_offset_t kvtophys(vm_offset_t va);					/* Get physical address from kernel virtual */
extern vm_offset_t	pmap_map(vm_offset_t va,
				 vm_offset_t spa,
				 vm_offset_t epa,
				 vm_prot_t prot);
extern kern_return_t    pmap_add_physical_memory(vm_offset_t spa,
						 vm_offset_t epa,
						 boolean_t available,
						 unsigned int attr);
extern vm_offset_t	pmap_map_bd(vm_offset_t va,
				    vm_offset_t spa,
				    vm_offset_t epa,
				    vm_prot_t prot);
extern void		pmap_bootstrap(unsigned int mem_size,
				       vm_offset_t *first_avail,
				       vm_offset_t *first_phys_avail, unsigned int kmapsize);
extern void		pmap_block_map(vm_offset_t pa,
				       vm_size_t size,
				       vm_prot_t prot,
				       int entry, 
				       int dtlb);
extern void		pmap_switch(pmap_t);

extern vm_offset_t pmap_extract(pmap_t pmap,
				vm_offset_t va);

extern void pmap_remove_all(vm_offset_t pa);

extern boolean_t pmap_verify_free(vm_offset_t pa);
extern void sync_cache(vm_offset_t pa, unsigned length);
extern void flush_dcache(vm_offset_t va, unsigned length, boolean_t phys);
extern void invalidate_dcache(vm_offset_t va, unsigned length, boolean_t phys);
extern void invalidate_icache(vm_offset_t va, unsigned length, boolean_t phys);
extern void pmap_sync_caches_phys(vm_offset_t pa);
extern void invalidate_cache_for_io(vm_offset_t va, unsigned length, boolean_t phys);
extern void pmap_map_block(pmap_t pmap, vm_offset_t va, vm_offset_t pa, vm_size_t size,
	 vm_prot_t prot, int attr, unsigned int flags);	/* Map a block */
extern kern_return_t pmap_map_block_opt(vm_map_t map, vm_offset_t *va, 
     vm_offset_t pa, vm_size_t size, vm_prot_t prot, int attr);	/* Map a block allocating an optimal virtual address */
extern kern_return_t vm_map_block(vm_map_t map, vm_offset_t *va, vm_offset_t *bnd, vm_offset_t pa, 
	vm_size_t size, vm_prot_t prot);

extern kern_return_t pmap_nest(pmap_t grand, pmap_t subord, vm_offset_t vaddr, vm_size_t size);

extern void pmap_ver(pmap_t pmap, vm_offset_t sva, vm_offset_t eva);

#endif /* _PPC_PMAP_H_ */

