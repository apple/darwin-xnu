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

#define maxPPage32 0x000FFFFF			/* Maximum page number in 32-bit machines */

typedef uint32_t shexlock;

#pragma pack(4)							/* Make sure the structure stays as we defined it */

struct sgc {
	uint64_t	sgcESID;				/* ESID portion of segment cache */
#define sgcESmsk	0xFFFFFFFFF0000000ULL	/* ESID portion of segment register cache */
	uint64_t	sgcVSID;				/* VSID portion of segment cache */
#define sgcVSmsk	0xFFFFFFFFFFFFF000ULL	/* VSID mask */
#define sgcVSKeys	0x0000000000000C00ULL	/* Protection keys */
#define sgcVSKeyUsr	53					/* User protection key */
#define sgcVSNoEx	0x0000000000000200ULL	/* No execute */
};
#pragma pack()

typedef struct sgc sgc;

#pragma pack(4)							/* Make sure the structure stays as we defined it */
struct pmap {
	queue_head_t	pmap_link;			/* MUST BE FIRST */
	addr64_t		pmapvr;				/* Virtual to real conversion mask */
	shexlock		pmapSXlk;			/* Shared/Exclusive lock for mapping changes */
	unsigned int	space;				/* space for this pmap */
#define invalSpace 0x00000001			/* Predefined always invalid space */
	int				ref_count;			/* reference count */
	unsigned int	pmapFlags;			/* Flags */
#define pmapKeys	0x00000007			/* Keys and no execute bit to use with this pmap */
#define pmapKeyDef	0x00000006			/* Default keys - Sup = 1, user = 1, no ex = 0 */
#define pmapVMhost	0x00000010			/* pmap with Virtual Machines attached to it */
	unsigned int	spaceNum;			/* Space number */
	unsigned int	pmapCCtl;			/* Cache control */
#define pmapCCtlVal	0xFFFF0000			/* Valid entries */
#define pmapCCtlLck	0x00008000			/* Lock bit */
#define pmapCCtlLckb	16				/* Lock bit */
#define pmapCCtlGen	0x00007FFF			/* Generation number */

#define pmapSegCacheCnt 16				/* Maximum number of cache entries */
#define pmapSegCacheUse	16				/* Number of cache entries to use */

	struct pmap		*freepmap;			/* Free pmaps */

	unsigned int	pmapRsv1[3];
/*											0x038 */
	uint64_t		pmapSCSubTag;		/* Segment cache sub-tags. This is a 16 entry 4 bit array */
/*											0x040 */
	sgc			pmapSegCache[pmapSegCacheCnt];	/* SLD values cached for quick load */

/*											0x140 */	
/* if fanout is 4, then shift is 1, if fanout is 8 shift is 2, etc */
#define	kSkipListFanoutShift	1
/* with n lists, we can handle (fanout**n) pages optimally */
#define	kSkipListMaxLists		12    
    unsigned char	pmapCurLists;		/*  0x140 - max #lists any mapping in this pmap currently has */
    unsigned char	pmapRsv2[3];
    uint32_t		pmapRandNum;		/* 0x144 - used by mapSetLists() as a random number generator */
    addr64_t		pmapSkipLists[kSkipListMaxLists];	/* 0x148 - the list headers */
/* following statistics conditionally gathered */
    uint64_t		pmapSearchVisits;	/* 0x1A8 - nodes visited searching pmaps */
    uint32_t		pmapSearchCnt;		/* 0x1B0 - number of calls to mapSearch or mapSearchFull */

	unsigned int	pmapRsv3[3];

/*											0x1C0 */	

	struct pmap_statistics	stats;		/* statistics */
	decl_simple_lock_data(,lock)		/* lock on map */
	
/* Need to pad out to a power of 2 - right now it is 512 bytes */
#define pmapSize 512
};
#pragma pack()

#pragma pack(4)
struct pmapTransTab {
	addr64_t		pmapPAddr;			/* Physcial address of pmap */
	unsigned int	pmapVAddr;			/* Virtual address of pmap */
};
#pragma pack()							/* Make sure the structure stays as we defined it */

typedef struct pmapTransTab pmapTransTab;

#define PMAP_NULL  ((pmap_t) 0)

extern pmap_t	kernel_pmap;			/* The kernel's map */
extern pmap_t	cursor_pmap;			/* The pmap to start allocations with */
extern pmap_t	sharedPmap;
extern unsigned int sharedPage;
extern int ppc_max_adrsp;				/* Maximum number of concurrent address spaces allowed. */	
extern addr64_t vm_max_address;			/* Maximum effective address supported */
extern addr64_t vm_max_physical;		/* Maximum physical address supported */
extern pmapTransTab *pmapTrans;			/* Space to pmap translate table */
#define	PMAP_SWITCH_USER(th, map, my_cpu) th->map = map;	

#define PMAP_ACTIVATE(pmap, th, cpu)
#define PMAP_DEACTIVATE(pmap, th, cpu)
#define PMAP_CONTEXT(pmap,th)

#define pmap_kernel_va(VA)	\
	(((VA) >= VM_MIN_KERNEL_ADDRESS) && ((VA) <= vm_last_addr))

#define	PPC_SID_KERNEL  0       /* Must change KERNEL_SEG_REG0_VALUE if !0 */

#define maxAdrSp 16384
#define maxAdrSpb 14
#define copyIOaddr 0x00000000E0000000ULL

#define pmap_kernel()			(kernel_pmap)
#define	pmap_resident_count(pmap)	((pmap)->stats.resident_count)
#define pmap_remove_attributes(pmap,start,end)
#define pmap_copy(dpmap,spmap,da,len,sa)
#define	pmap_update()

#define PMAP_DEFAULT_CACHE	0
#define PMAP_INHIBIT_CACHE	1
#define PMAP_GUARDED_CACHE	2
#define PMAP_ACTIVATE_CACHE	4
#define PMAP_NO_GUARD_CACHE	8

/* corresponds to cached, coherent, not writethru, not guarded */
#define VM_WIMG_DEFAULT		(VM_MEM_COHERENT)
#define	VM_WIMG_COPYBACK	(VM_MEM_COHERENT)
#define VM_WIMG_IO		(VM_MEM_COHERENT | 	\
				VM_MEM_NOT_CACHEABLE | VM_MEM_GUARDED)
#define VM_WIMG_WTHRU		(VM_MEM_WRITE_THROUGH | VM_MEM_COHERENT | VM_MEM_GUARDED)
/* write combining mode, aka store gather */
#define VM_WIMG_WCOMB		(VM_MEM_NOT_CACHEABLE | VM_MEM_COHERENT) 

/* 
 * prototypes.
 */
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
extern void		pmap_bootstrap(uint64_t msize,
				       vm_offset_t *first_avail,
				       unsigned int kmapsize);
extern void		pmap_switch(pmap_t);

extern vm_offset_t pmap_extract(pmap_t pmap,
				vm_offset_t va);

extern void pmap_remove_all(vm_offset_t pa);

extern boolean_t pmap_verify_free(ppnum_t pa);
extern void sync_cache(vm_offset_t pa, unsigned length);
extern void sync_cache64(addr64_t pa, unsigned length);
extern void sync_ppage(ppnum_t pa);
extern void	sync_cache_virtual(vm_offset_t va, unsigned length);
extern void flush_dcache(vm_offset_t va, unsigned length, boolean_t phys);
extern void flush_dcache64(addr64_t va, unsigned length, boolean_t phys);
extern void invalidate_dcache(vm_offset_t va, unsigned length, boolean_t phys);
extern void invalidate_dcache64(addr64_t va, unsigned length, boolean_t phys);
extern void invalidate_icache(vm_offset_t va, unsigned length, boolean_t phys);
extern void invalidate_icache64(addr64_t va, unsigned length, boolean_t phys);
extern void pmap_sync_caches_phys(ppnum_t pa);
extern void pmap_map_block(pmap_t pmap, addr64_t va, ppnum_t pa, vm_size_t size, vm_prot_t prot, int attr, unsigned int flags);
extern int pmap_map_block_rc(pmap_t pmap, addr64_t va, ppnum_t pa, vm_size_t size, vm_prot_t prot, int attr, unsigned int flags);

extern kern_return_t pmap_nest(pmap_t grand, pmap_t subord, addr64_t vstart, addr64_t nstart, uint64_t size);
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
extern addr64_t MapUserAddressSpace(vm_map_t map, addr64_t va, unsigned int size);
extern void ReleaseUserAddressSpace(addr64_t kva);
extern kern_return_t pmap_attribute_cache_sync(ppnum_t pp, vm_size_t size,
				vm_machine_attribute_t  attribute,
				vm_machine_attribute_val_t* value);
extern int pmap_canExecute(ppnum_t pa);

#endif /* _PPC_PMAP_H_ */

