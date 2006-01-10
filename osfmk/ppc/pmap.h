/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <ppc/mappings.h>

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
struct pmap_vmm_stats {
	unsigned int	vxsGpf;				/* Guest faults */
	unsigned int	vxsGpfMiss;			/* Faults that miss in hash table */
	
	unsigned int	vxsGrm;				/* Guest mapping remove requests */
	unsigned int	vxsGrmMiss;			/* Remove misses in hash table */
	unsigned int	vxsGrmActive;		/* Remove hits that are active */
	
	unsigned int	vxsGra;				/* Guest remove all mappings requests */
	unsigned int	vxsGraHits;			/* Remove hits in hash table */
	unsigned int	vxsGraActive;		/* Remove hits that are active */
	
	unsigned int	vxsGrl;				/* Guest remove local mappings requests */
	unsigned int	vxsGrlActive;		/* Active mappings removed */

	unsigned int	vxsGrs;				/* Guest mapping resumes */
	unsigned int	vxsGrsHitAct;		/* Resume hits active entry */
	unsigned int	vxsGrsHitSusp;		/* Resume hits suspended entry */
	unsigned int	vxsGrsMissGV;		/* Resume misses on guest virtual */
	unsigned int	vxsGrsHitPE;		/* Resume hits on host virtual */
	unsigned int	vxsGrsMissPE;		/* Resume misses on host virtual */

	unsigned int	vxsGad;				/* Guest mapping adds */
	unsigned int	vxsGadHit;			/* Add hits entry (active or dormant) */
	unsigned int	vxsGadFree;			/* Add takes free entry in group */
	unsigned int	vxsGadDormant;		/* Add steals dormant entry in group */
	unsigned int	vxsGadSteal;		/* Add steals active entry in group */
	
	unsigned int	vxsGsu;				/* Guest mapping suspends */
	unsigned int	vxsGsuHit;			/* Suspend hits entry (active only) */
	unsigned int	vxsGsuMiss;			/* Suspend misses entry */
	
	unsigned int	vxsGtd;				/* Guest test ref&chg */
	unsigned int	vxsGtdHit;			/* Test r&c hits entry (active only) */
	unsigned int	vxsGtdMiss;			/* Test r&c misses entry */
};
#pragma pack()
typedef struct pmap_vmm_stats pmap_vmm_stats;

/* Not wanting to tax all of our customers for the sins of those that use virtual operating
   systems, we've built the hash table from its own primitive virtual memory. We first
   allocate a pmap_vmm_ext with sufficient space following to accomodate the hash table 
   index (one 64-bit physical address per 4k-byte page of hash table). The allocation 
   must not cross a 4k-byte page boundary (we'll be accessing the block with relocation
   off), so we'll try a couple of times, then just burn a whole page. We stuff the effective
   address of the cache-aligned index into hIdxBase; the physical-mode code locates the index
   by adding the size of a pmap_vmm_extension to its translated physical address, then rounding
   up to the next 32-byte boundary. Now we grab enough virtual pages to contain the hash table,
   and fill in the index with the page's physical addresses. For the final touch that's sure
   to please, we initialize the hash table. Mmmmm, golden brown perfection.
 */

#pragma pack(4)
struct pmap_vmm_ext {
	addr64_t		vmxSalt;			/* This block's virt<->real conversion salt */
	addr64_t		vmxHostPmapPhys;	/* Host pmap physical address */
	struct pmap		*vmxHostPmap;		/* Host pmap effective address */
	addr64_t		*vmxHashPgIdx;		/* Hash table physical index base address */
	vm_offset_t		*vmxHashPgList;		/* List of virtual pages comprising the hash table */
	unsigned int	*vmxActiveBitmap;	/* Bitmap of active mappings in hash table */
	pmap_vmm_stats	vmxStats;			/* Stats for VMM assists */
#define VMX_HPIDX_OFFSET ((sizeof(pmap_vmm_ext) + 127) & ~127)
										/* The hash table physical index begins at the first
										   128-byte boundary after the pmap_vmm_ext struct */
#define VMX_HPLIST_OFFSET (VMX_HPIDX_OFFSET + (GV_HPAGES * sizeof(addr64_t)))
#define VMX_ACTMAP_OFFSET (VMX_HPLIST_OFFSET + (GV_HPAGES * sizeof(vm_offset_t)))
};
#pragma pack()
typedef struct pmap_vmm_ext pmap_vmm_ext;

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
#define pmapVMgsaa	0x00000020			/* Guest shadow assist active */
	unsigned int	spaceNum;			/* Space number */
	unsigned int	pmapCCtl;			/* Cache control */
#define pmapCCtlVal	0xFFFF0000			/* Valid entries */
#define pmapCCtlLck	0x00008000			/* Lock bit */
#define pmapCCtlLckb	16				/* Lock bit */
#define pmapCCtlGen	0x00007FFF			/* Generation number */

#define pmapSegCacheCnt 16				/* Maximum number of cache entries */
#define pmapSegCacheUse	16				/* Number of cache entries to use */

	struct pmap		*freepmap;			/* Free pmaps */
	pmap_vmm_ext   *pmapVmmExt;			/* VMM extension block, for VMM host and guest pmaps */
	addr64_t		pmapVmmExtPhys;		/* VMM extension block physical address */
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

/*
 *	Address Chunk IDentified Table
 */
 
struct acidTabEnt {
	unsigned int	acidVAddr;			/* Virtual address of pmap or pointer to next free entry */
	unsigned int	acidGas;			/* reserved */
	addr64_t		acidPAddr;			/* Physcial address of pmap */
};

typedef struct acidTabEnt acidTabEnt;

extern acidTabEnt *acidTab;				/* Pointer to acid table */
extern acidTabEnt *acidFree;			/* List of free acid entries */

#define PMAP_NULL  ((pmap_t) 0)

extern pmap_t	cursor_pmap;			/* The pmap to start allocations with */
extern pmap_t	sharedPmap;
extern unsigned int sharedPage;
extern int ppc_max_adrsp;				/* Maximum number of concurrent address spaces allowed. */	
extern addr64_t vm_max_address;			/* Maximum effective address supported */
extern addr64_t vm_max_physical;		/* Maximum physical address supported */
extern pmapTransTab *pmapTrans;			/* Space to pmap translate table */
#define	PMAP_SWITCH_USER(th, map, my_cpu) th->map = map;	

#define PMAP_CONTEXT(pmap,th)

#define pmap_kernel_va(VA)	\
	(((VA) >= VM_MIN_KERNEL_ADDRESS) && ((VA) <= vm_last_addr))

#define	PPC_SID_KERNEL  0       /* Must change KERNEL_SEG_REG0_VALUE if !0 */

#define maxAdrSp 16384
#define maxAdrSpb 14
#define USER_MEM_WINDOW_VADDR	0x00000000E0000000ULL
#define PHYS_MEM_WINDOW_VADDR	0x0000000100000000ULL
#define IO_MEM_WINDOW_VADDR		0x0000000080000000ULL
#define IO_MEM_WINDOW_SIZE		0x0000000080000000ULL
#define pmapSmallBlock 65536

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

extern vm_offset_t pmap_boot_map(vm_size_t size);

extern void sync_cache64(addr64_t pa, unsigned length);
extern void sync_ppage(ppnum_t pa);
extern void	sync_cache_virtual(vm_offset_t va, unsigned length);
extern void flush_dcache(vm_offset_t va, unsigned length, boolean_t phys);
extern void flush_dcache64(addr64_t va, unsigned length, boolean_t phys);
extern void invalidate_dcache(vm_offset_t va, unsigned length, boolean_t phys);
extern void invalidate_dcache64(addr64_t va, unsigned length, boolean_t phys);
extern void invalidate_icache(vm_offset_t va, unsigned length, boolean_t phys);
extern void invalidate_icache64(addr64_t va, unsigned length, boolean_t phys);
extern void pmap_sync_page_data_phys(ppnum_t pa);
extern void pmap_sync_page_attributes_phys(ppnum_t pa);
extern void pmap_map_block(pmap_t pmap, addr64_t va, ppnum_t pa, uint32_t size, vm_prot_t prot, int attr, unsigned int flags);
extern int pmap_map_block_rc(pmap_t pmap, addr64_t va, ppnum_t pa, uint32_t size, vm_prot_t prot, int attr, unsigned int flags);

extern kern_return_t pmap_nest(pmap_t grand, pmap_t subord, addr64_t vstart, addr64_t nstart, uint64_t size);
extern kern_return_t pmap_unnest(pmap_t grand, addr64_t vaddr);
extern ppnum_t pmap_find_phys(pmap_t pmap, addr64_t va);
extern void MapUserMemoryWindowInit(void);
extern addr64_t MapUserMemoryWindow(vm_map_t map, addr64_t va);
extern boolean_t pmap_eligible_for_execute(ppnum_t pa);
extern int pmap_list_resident_pages(
	struct pmap	*pmap,
	vm_offset_t	*listp,
	int		space);
extern void pmap_init_sharedpage(vm_offset_t cpg);
extern void pmap_map_sharedpage(task_t task, pmap_t pmap);
extern void pmap_unmap_sharedpage(pmap_t pmap);



#endif /* _PPC_PMAP_H_ */

