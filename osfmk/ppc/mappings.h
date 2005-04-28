/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 *		Header files for the hardware virtual memory mapping stuff 
 */
#ifdef	XNU_KERNEL_PRIVATE

#ifndef	_PPC_MAPPINGS_H_
#define	_PPC_MAPPINGS_H_

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <kern/assert.h>
#include <kern/cpu_number.h>
#include <kern/lock.h>
#include <kern/queue.h>
#include <ppc/proc_reg.h>

/*
 * Don't change these structures unless you change the assembly code
 */

/*
 *	This control block serves as anchor for all virtual mappings of the same physical
 *	page, i.e., aliases.  There is a table for each bank (mem_region).  All tables
 *	must reside in V=R storage and within the first 2GB of memory. Also, the
 *	mappings to which it points must be on at least a 64-byte boundary. These 
 *	requirements allow a total of 2 bits for status and flags, and allow all address
 *	calculations to be 32-bit.
 */

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct phys_entry {
	addr64_t	ppLink;				/* Physical pointer to aliased mappings and flags */
#define		ppLock		0x8000000000000000LL	/* Lock for alias chain */
#define		ppFlags		0x700000000000000FLL	/* Status and flags */
#define		ppI			0x2000000000000000LL	/* Cache inhibited */
#define		ppIb		2						/* Cache inhibited */
#define		ppG			0x1000000000000000LL	/* Guarded */
#define		ppGb		3						/* Guarded */
#define		ppR			0x0000000000000008LL	/* Referenced */
#define		ppRb		60						/* Referenced */
#define		ppC			0x0000000000000004LL	/* Changed */
#define		ppCb		61						/* Changed */

/* The lock, attribute, and flag bits are arranged so that their positions may be
 * described by a contiguous mask of one bits wrapping from bit postion 63 to 0.
 * In assembly language, we can then rapidly produce this mask with:
 *		li		r0,ppLFAmask		; r0 <- 0x00000000000000FF
 *		rotrdi	r0,r0,ppLFArrot		; r0 <- 0xF00000000000000F
 */
#define		ppLFAmask	0x00FF					/* One bit for each lock, attr, or flag bit */
#define		ppLFArrot	4						/* Right-rotate count to obtain 64-bit mask */
} phys_entry_t;
#pragma pack()
#define physEntrySize sizeof(phys_entry_t)

/* Memory may be non-contiguous. This data structure contains info
 * for mapping this non-contiguous space into the contiguous
 * physical->virtual mapping tables. An array of this type is
 * provided to the pmap system at bootstrap by ppc_vm_init.
 *
 */

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct mem_region {
	phys_entry_t	   *mrPhysTab;	/* Base of region table */
	ppnum_t				mrStart;	/* Start of region */
	ppnum_t				mrEnd;		/* Last page in region */
	ppnum_t				mrAStart;	/* Next page in region to allocate */
	ppnum_t				mrAEnd;		/* Last page in region to allocate */
} mem_region_t;
#pragma pack()

#define mrSize sizeof(mem_region_t)
#define PMAP_MEM_REGION_MAX 11

extern mem_region_t pmap_mem_regions[PMAP_MEM_REGION_MAX + 1];
extern int          pmap_mem_regions_count;

/* Prototypes */


#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct PCA {					/* PTEG Control Area */
	union flgs {
		unsigned int	PCAallo;		/* Allocation controls */
		struct PCAalflgs {				/* Keep these in order!!! */
			unsigned char	PCAfree;	/* Indicates the slot is free */
			unsigned char	PCAsteal;	/* Steal scan start position */
			unsigned char	PCAauto;	/* Indicates that the PTE was autogenned */
			unsigned char	PCAmisc;	/* Misc. flags */
#define PCAlock 1						/* This locks up the associated PTEG */
#define PCAlockb 31
		} PCAalflgs;
	} flgs;
} PCA_t;
#pragma pack()

/* The hash table is composed of mappings organized into G groups of S slots
 * each. In the macros below, by GV_GROUPS_LG2, GV_SLOT_SZ_LG2, and GV_SLOTS_LG2, the number 
 * of groups, the size (in bytes) of a slot, and the number of slots in a group are given.
 * Since these values are given as log2, they're restricted to powers of two. Fast operation
 * and all that.
 * 
 * This patch of macros define all of the hash table's metrics and handy masks. It's a
 * build-time thing because it's faster that way. Only the first group of values may
 * be adjusted.
 */
#define GV_GROUPS_LG2	10	/* 1024 groups per hash table (log2(max) is 14, viz. 16K groups) */
#define GV_SLOTS_LG2	3	/* 8 slots per group (log2(max) is 8, viz. 256 slots) */

#define GV_SLOT_SZ_LG2	5	/* 32 bytes per slot (mapping size) */
#define GV_PGIDX_SZ_LG2	3	/* 64-bit Hash-table-page physical-addrress index entry size */
#define GV_PAGE_SZ_LG2	12	/* 4k-byte hash-table-page size */

#define GV_GROUPS		(1 << GV_GROUPS_LG2)
#define GV_SLOT_SZ		(1 << GV_SLOT_SZ_LG2)
#define GV_SLOTS		(1 << GV_SLOTS_LG2)
#define GV_PAGE_SZ		(1 << GV_PAGE_SZ_LG2)
#define GV_GRP_MASK		(GV_GROUPS - 1)
#define GV_SLOT_MASK	(GV_SLOTS - 1)
#define GV_PAGE_MASK	(GV_PAGE_SZ - 1)
#define GV_HPAGES		(1 << (GV_GROUPS_LG2 + GV_SLOT_SZ_LG2 + GV_SLOTS_LG2 - GV_PAGE_SZ_LG2))
#define GV_GRPS_PPG_LG2	(GV_PAGE_SZ_LG2 - (GV_SLOT_SZ_LG2 + GV_SLOTS_LG2))
#define GV_GRPS_PPG		(1 << GV_GRPS_PPG_LG2)
#define GV_SLTS_PPG_LG2 (GV_PAGE_SZ_LG2 - GV_SLOT_SZ_LG2)
#define GV_SLTS_PPG		(1 << GV_SLTS_PPG_LG2)

#define GV_HPAGE_SHIFT	(GV_PGIDX_SZ_LG2 - GV_GRPS_PPG_LG2)
#define GV_HPAGE_MASK	((GV_HPAGES - 1) << GV_PGIDX_SZ_LG2)
#define GV_HGRP_SHIFT	(GV_SLOT_SZ_LG2 + GV_SLOTS_LG2)
#define GV_HGRP_MASK	((GV_GRPS_PPG - 1) << GV_HGRP_SHIFT)

#define GV_MAPWD_BITS_LG2	5	/* 32-bit active map word size */
#define GV_MAPWD_SZ_LG2	(GV_MAPWD_BITS_LG2 - 3)
#define GV_BAND_SHIFT	(GV_MAPWD_BITS_LG2 + GV_SLOT_SZ_LG2)
#define GV_BAND_SZ_LG2	(GV_PAGE_SZ_LG2 - GV_SLOT_SZ_LG2 - GV_MAPWD_BITS_LG2)
#define GV_BAND_MASK	(((1 << GV_BAND_SZ_LG2) - 1) << GV_BAND_SHIFT)
#define GV_MAP_WORDS	(1 << (GV_GROUPS_LG2 + GV_SLOTS_LG2 - GV_MAPWD_BITS_LG2))
#define GV_MAP_MASK		((GV_MAP_WORDS - 1) << GV_MAPWD_SZ_LG2)
#define GV_MAP_SHIFT	(GV_PGIDX_SZ_LG2 - GV_BAND_SZ_LG2)


/* Mappings currently come in two sizes: 64 and 128 bytes.  The only difference is the
 * number of skiplists (ie, mpLists): 64-byte mappings have 1-4 lists and 128-byte mappings
 * have from 5-12.  Only 1 in 256 mappings is large, so an average mapping is 64.25 bytes.
 * All mappings are 64-byte aligned.
 *
 * Special note on mpFIP and mpRIP:
 *	These flags are manipulated under various locks.  RIP is always set under an
 *	exclusive lock while FIP is shared.  The only worry is that there is a possibility that
 *	FIP could be attempted by more than 1 processor at a time.  Obviously, one will win.
 *	The other(s) bail all the way to user state and may refault (or not).  There are only
 *	a few things in mpFlags that are not static, mpFIP, mpRIP, and mpBusy.
 *	
 *	We organize these so that mpFIP is in a byte with static data and mpRIP is in another. 
 *	That means that we can use a store byte to update the guys without worrying about load
 *  and reserve. Note that mpFIP must be set atomically because it is under a share lock;
 *  but, it may be cleared with a simple store byte. Because mpRip is set once and then never
 *  cleared, we can get away with setting it by means of a simple store byte.
 *	
 */   
#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct mapping {
	unsigned int		mpFlags;		/* 0x000 - Various flags, lock bit. These are static except for lock */
#define	mpBusy				0xFF000000	/*         Busy count */
#define mpPrevious			0x00800000	/*		   A previous mapping exists in a composite */
#define mpNext				0x00400000	/*		   A next mapping exist in a composite */
#define	mpPIndex			0x003F0000	/*         Index into physical table (in words) */
#define mpType				0x0000F000	/*		   Mapping type: */
#define mpNormal			0x00000000	/*			Normal logical page - backed by RAM, RC maintained, logical page size == physical page size */
										/*			DO NOT CHANGE THIS CODE */
#define mpBlock				0x00001000	/*			Block mapping - used for I/O memory or non-RC maintained RAM, logical page size is independent from physical */
#define mpMinSpecial		0x00002000	/*			Any mapping with this type or above has extra special handling */
#define mpNest				0x00002000	/*			Forces transtion to an alternate address space after applying relocation */
#define mpLinkage			0x00003000	/*			Transition to current user address space with relocation - used for copyin/out/pv */
#define mpACID				0x00004000	/*			Address Chunk ID - provides the address space ID for VSID calculation.  Normally mapped at chunk size - 2KB */
#define mpGuest				0x00005000	/*			Guest->physical shadow mapping */
/*							0x00006000 - 0x0000F000	Reserved */
#define	mpFIP				0x00000800	/*         Fault in progress */
#define	mpFIPb				20			/*         Fault in progress */
#define mpPcfg				0x00000700	/*		   Physical Page configuration */
#define mpPcfgb				23			/*		   Physical Page configuration index bit */
#define mpRIP				0x00000080	/*         Remove in progress - DO NOT MOVE */
#define mpRIPb				24			/*         Remove in progress */
#define mpPerm				0x00000040	/*         Mapping is permanent - DO NOT MOVE */
#define mpPermb				25			/*         Mapping is permanent */
#define mpBSu				0x00000020	/*         Basic Size unit - 0 = 4KB, 1 = 32MB */
#define mpBSub				26			/*         Basic Size unit - 0 = 4KB, 1 = 32MB */
#define mpLists				0x0000001F	/*         Number of skip lists mapping is on, max of 27 */
#define mpListsb			27			/*         Number of skip lists mapping is on, max of 27 */
#define mpgFlags			0x0000001F	/*	Shadow cache mappings re-use mpLists for flags: */
#define mpgGlobal			0x00000004	/*         Mapping is global (1) or local (0) */
#define mpgFree				0x00000002	/*		   Mapping is free */
#define mpgDormant			0x00000001	/*		   Mapping is dormant */

	unsigned short		mpSpace;		/* 0x004 - Address space hash */
	union {	
		unsigned short	mpBSize;		/* 0x006 - Block size - 1 in pages - max block size 256MB */
		unsigned char	mpgCursor;		/* 0x006 - Shadow-cache group allocation cursor (first mapping in the group) */
	} u;
	
	unsigned int		mpPte;			/* 0x008 - Offset to PTEG in hash table. Offset to exact PTE if mpHValid set - NOTE: this MUST be 0 for block mappings */
#define mpHValid			0x00000001	/* PTE is entered in hash table */
#define mpHValidb			31			/* PTE is entered in hash table */
	ppnum_t				mpPAddr;		/* 0x00C - Physical page number */
	addr64_t			mpVAddr;		/* 0x010 - Starting virtual address */
#define mpHWFlags			0x0000000000000FFFULL	/* Reference/Change, WIMG, AC, N, protection flags from PTE */
#define mpHWFlagsb			52
#define mpN					0x0000000000000004ULL	/* Page-level no-execute (PowerAS machines) */
#define mpNb				61
#define mpPP				0x0000000000000003ULL	/* Protection flags */
#define mpPPb				62
#define mpPPe				63
#define mpKKN				0x0000000000000007ULL	/* Segment key and no execute flag (nested pmap) */
#define mpKKNb				61
#define mpWIMG				0x0000000000000078ULL	/* Attribute bits */
#define mpWIMGb				57
#define mpW					0x0000000000000040ULL
#define mpWb				57
#define mpI					0x0000000000000020ULL
#define mpIb				58
#define mpM					0x0000000000000010ULL
#define mpMb				59
#define mpG					0x0000000000000008ULL
#define mpGb				60
#define mpWIMGe				60
#define mpC					0x0000000000000080ULL	/* Change bit */
#define mpCb				56
#define mpR					0x0000000000000100ULL	/* Reference bit */
#define mpRb				55
	addr64_t			mpAlias;		/* 0x018 - Pointer to alias mappings of physical page */
#define mpNestReloc			mpAlias		/* 0x018 - Redefines mpAlias relocation value of vaddr to nested pmap value */
#define mpBlkRemCur			mpAlias		/* 0x018 - Next offset in block map to remove (this is 4 bytes) */
	addr64_t			mpList0;		/* 0x020 - Forward chain of mappings. This one is always used */
	addr64_t			mpList[3];		/* 0x028 - Forward chain of mappings. Next higher order */
/*										   0x040 - End of basic mapping */
#define	mpBasicSize			64
#define	mpBasicLists		4
/* note the dependence on kSkipListMaxLists, which must be <= #lists in a 256-byte mapping (ie, <=28) */
/*	addr64_t			mpList4[8];		   0x040 - First extended list entries */
/*										   0x080 - End of first extended mapping */
/*	addr64_t			mpList12[8];	   0x080 - Second extended list entries */
/*										   0x0C0 - End of second extended mapping */
/*	addr64_t			mpList20[8];	   0x0C0 - Third extended list entries */
/*										   0x100 - End of third extended mapping */

} mapping_t;
#pragma pack()

#define MAPPING_NULL	((struct mapping *) 0)

#define mapDirect 0x08
#define mapRWNA   0x00000000
#define mapRWRO   0x00000001
#define mapRWRW   0x00000002
#define mapRORO   0x00000003

/* All counts are in units of basic 64-byte mappings.  A 128-byte mapping is
 * just two adjacent 64-byte entries.
 */
#pragma pack(4)							/* Make sure the structure stays as we defined it */

typedef struct mappingflush {
	addr64_t			addr;			/* Start address to search mapping */
	unsigned int		spacenum;		/* Last space num to search pmap */
	unsigned int		mapfgas[1];		/* Pad to 64 bytes */
} mappingflush_t;

typedef struct mappingctl {
	unsigned int		mapclock;		/* Mapping allocation lock */
	unsigned int		mapcrecurse;	/* Mapping allocation recursion control */
	struct mappingblok	*mapcnext;		/* First mapping block with free entries */
	struct mappingblok	*mapclast;		/* Last mapping block with free entries */
	struct mappingblok	*mapcrel;		/* List of deferred block releases */
	unsigned int		mapcfree;		/* Total free entries on list */
	unsigned int		mapcinuse;		/* Total entries in use */
	unsigned int		mapcreln;		/* Total blocks on pending release list */
	int					mapcholdoff;	/* Hold off clearing release list */
	unsigned int		mapcfreec;		/* Total calls to mapping free */
	unsigned int		mapcallocc;		/* Total calls to mapping alloc */
    unsigned int		mapcbig;		/* Count times a big mapping was requested of mapping_alloc */
    unsigned int		mapcbigfails;	/* Times caller asked for a big one but we gave 'em a small one */
	unsigned int		mapcmin;		/* Minimum free mappings to keep */
	unsigned int		mapcmaxalloc;	/* Maximum number of mappings allocated at one time */
	unsigned int		mapcgas[1];		/* Pad to 64 bytes */
	struct mappingflush	mapcflush;
} mappingctl_t;
#pragma pack()

/* MAPPERBLOK is the number of basic 64-byte mappings per block (ie, per page.) */
#define MAPPERBLOK 63
#define MAPALTHRSH (4*MAPPERBLOK)
#define MAPFRTHRSH (2 * ((MAPALTHRSH + MAPPERBLOK - 1) / MAPPERBLOK))
typedef struct mappingblok {
	unsigned int		mapblokfree[2];	/* Bit map of free mapping entrys */
	addr64_t			mapblokvrswap;	/* Virtual address XORed with physical address */
	unsigned int		mapblokflags;	/* Various flags */
#define mbPerm 0x80000000				/* Block is permanent */
	struct mappingblok	*nextblok;		/* Pointer to the next mapping block */
} mappingblok_t;

#define mapRemChunk 128

#define mapRetCode	0xF
#define mapRtOK		0
#define mapRtBadLk	1
#define mapRtPerm	2
#define mapRtNotFnd	3
#define mapRtBlock	4
#define mapRtNest	5
#define mapRtRemove	6
#define mapRtMapDup	7
#define mapRtGuest	8
#define mapRtEmpty	9
#define mapRtSmash	0xA					/* Mapping already exists and doesn't match new mapping */

/*
 *	This struct describes available physical page configurations
 *	Note:
 *		Index 0 is required and is the primary page configuration (4K, non-large)
 *		Index 1 is the primary large page config if supported by hw (16M, large page)
 */
 
typedef struct pcfg {
	uint8_t				pcfFlags;		/* Flags */
#define pcfValid		0x80			/* Configuration is valid */
#define pcfLarge		0x40			/* Large page */
#define pcfDedSeg		0x20			/* Requires dedicated segment */
	uint8_t				pcfEncode;		/* Implementation specific PTE encoding */
	uint8_t				pcfPSize;		/* Page size in powers of 2 */
	uint8_t				pcfShift;		/* Shift for PTE construction */
} pcfg;

#define pcfDefPcfg		0				/* Primary page configuration */
#define pcfLargePcfg	1				/* Primary large page configuration */

extern pcfg pPcfg[8];					/* Supported page configurations */

extern mappingctl_t	mapCtl;				/* Mapping allocation control */

extern unsigned char ppc_prot[];		/* Mach -> PPC protection translation table */

#define getProtPPC(__key) (ppc_prot[(__key) & 0xF])
										/* Safe Mach -> PPC protection key conversion */

extern addr64_t 	mapping_remove(pmap_t pmap, addr64_t va);	/* Remove a single mapping for this VADDR */
extern mapping_t 	*mapping_find(pmap_t pmap, addr64_t va, addr64_t *nextva, int full);	/* Finds a mapping */
extern void 		mapping_free_init(vm_offset_t mbl, int perm, boolean_t locked);	/* Sets start and end of a block of mappings */
extern void 		mapping_prealloc(unsigned int);				/* Preallocate mappings for large use */
extern void 		mapping_relpre(void);						/* Releases preallocate request */
extern void 		mapping_init(void);							/* Do initial stuff */
extern mapping_t    *mapping_alloc(int lists);					/* Obtain a mapping */
extern void 		mapping_free(struct mapping *mp);			/* Release a mapping */
extern boolean_t 	mapping_tst_ref(ppnum_t pa);				/* Tests the reference bit of a physical page */
extern boolean_t 	mapping_tst_mod(ppnum_t pa);				/* Tests the change bit of a physical page */
extern void 		mapping_set_ref(ppnum_t pa);				/* Sets the reference bit of a physical page */
extern void 		mapping_clr_ref(ppnum_t pa);				/* Clears the reference bit of a physical page */
extern void 		mapping_set_mod(ppnum_t pa);				/* Sets the change bit of a physical page */
extern void 		mapping_clr_mod(ppnum_t pa);				/* Clears the change bit of a physical page */
extern unsigned int mapping_tst_refmod(ppnum_t pa);				/* Tests the reference and change bits of a physical page */
extern void			mapping_clr_refmod(ppnum_t pa, unsigned int mask);	/* Clears the reference and change bits of a physical page */
extern void 		mapping_protect_phys(ppnum_t pa, vm_prot_t prot);	/* Change protection of all mappings to page */
extern void	 	mapping_protect(pmap_t pmap, addr64_t va, vm_prot_t prot, addr64_t *nextva);	/* Change protection of a single mapping to page */
extern addr64_t		mapping_make(pmap_t pmap, addr64_t va, ppnum_t pa, unsigned int flags, unsigned int size, vm_prot_t prot); /* Make a mapping */
/* Flags for mapping_make */
#define mmFlgBlock		0x80000000	/* This is a block map, use size for number of pages covered */
#define mmFlgUseAttr	0x40000000	/* Use specified attributes */
#define mmFlgPerm		0x20000000	/* Mapping is permanant */
#define mmFlgPcfg		0x07000000	/* Physical page configuration index */
#define mmFlgCInhib		0x00000002	/* Cahching inhibited - use if mapFlgUseAttr set or block */
#define mmFlgGuarded	0x00000001	/* Access guarded - use if mapFlgUseAttr set or block */
extern void 		mapping_purge(ppnum_t pa);		/* Remove all mappings for this physent */
extern addr64_t		mapping_p2v(pmap_t pmap, ppnum_t pa);	/* Finds first virtual mapping of a physical page in a space */
extern void			mapping_drop_busy(struct mapping *mapping);	/* Drops busy count on mapping */
extern phys_entry_t  *mapping_phys_lookup(ppnum_t pp, unsigned int *pindex);	/* Finds the physical entry for the page */
extern int			mapalc1(struct mappingblok *mb);			/* Finds and allcates a 1-bit mapping entry */
extern int			mapalc2(struct mappingblok *mb);			/* Finds and allcates a 2-bit mapping entry */
extern void			ignore_zero_fault(boolean_t type);			/* Sets up to ignore or honor any fault on page 0 access for the current thread */

extern void			mapping_fake_zone_info(		/* return mapping usage stats as a fake zone info */
						int *count,
						vm_size_t *cur_size,
						vm_size_t *max_size,
						vm_size_t *elem_size,
						vm_size_t *alloc_size,
						int *collectable,
						int *exhaustable);

extern mapping_t 	*hw_rem_map(pmap_t pmap, addr64_t va, addr64_t *next);	/* Remove a mapping from the system */
extern mapping_t	*hw_purge_map(pmap_t pmap, addr64_t va, addr64_t *next);	/* Remove a regular mapping from the system */
extern mapping_t	*hw_purge_space(struct phys_entry *pp, pmap_t pmap);	/* Remove the first mapping for a specific pmap from physentry */
extern mapping_t	*hw_purge_phys(struct phys_entry *pp);		/* Remove the first mapping for a physentry */
extern mapping_t	*hw_scrub_guest(struct phys_entry *pp, pmap_t pmap);	/* Scrub first guest mapping belonging to this host */ 
extern mapping_t	*hw_find_map(pmap_t pmap, addr64_t va, addr64_t *nextva);	/* Finds a mapping */
extern mapping_t	*hw_find_space(struct phys_entry *pp, unsigned int space);	/* Given a phys_entry, find its first mapping in the specified space */
extern addr64_t		hw_add_map(pmap_t pmap, struct mapping *mp);	/* Add a mapping to a pmap */
extern unsigned int	hw_protect(pmap_t pmap, addr64_t va, vm_prot_t prot, addr64_t *nextva);	/* Change the protection of a virtual page */
extern unsigned int	hw_test_rc(pmap_t pmap, addr64_t va, boolean_t reset);	/* Test and optionally reset the RC bit of specific mapping */

extern unsigned int	hw_clear_maps(void);

extern unsigned int	hw_walk_phys(struct phys_entry *pp, unsigned int preop, unsigned int op, /* Perform function on all mappings on a physical page */
	unsigned int postop, unsigned int parm, unsigned int opmod);	
/* Opcodes for hw_walk_phys */
#define hwpNoop			0	/* No operation */
#define hwpSPrtPhy		1	/* Sets protection in physent (obsolete)  */
#define hwpSPrtMap		2	/* Sets protection in mapping  */
#define hwpSAtrPhy		3	/* Sets attributes in physent  */
#define hwpSAtrMap		4	/* Sets attributes in mapping  */
#define hwpCRefPhy		5	/* Clears reference in physent  */
#define hwpCRefMap		6	/* Clears reference in mapping  */
#define hwpCCngPhy		7	/* Clears change in physent  */
#define hwpCCngMap		8	/* Clears change in mapping  */
#define hwpSRefPhy		9	/* Sets reference in physent  */
#define hwpSRefMap		10	/* Sets reference in mapping  */
#define hwpSCngPhy		11	/* Sets change in physent  */
#define hwpSCngMap		12	/* Sets change in mapping  */
#define hwpTRefPhy		13	/* Tests reference in physent  */
#define hwpTRefMap		14	/* Tests reference in mapping  */
#define hwpTCngPhy		15	/* Tests change in physent  */
#define hwpTCngMap		16	/* Tests change in mapping  */
#define hwpTRefCngPhy	17  /* Tests reference and change in physent */
#define hwpTRefCngMap	18	/* Tests reference and change in mapping */
#define hwpCRefCngPhy	19  /* Clears reference and change in physent */
#define hwpCRefCngMap	20	/* Clears reference and change in mapping */
/* Operation modifiers for connected PTE visits for hw_walk_phys */
#define hwpPurgePTE		0	/* Invalidate/purge PTE and merge RC bits for each connected mapping */
#define hwpMergePTE		1	/* Merge RC bits for each connected mapping */
#define hwpNoopPTE		2	/* Take no additional action for each connected mapping */

extern void 		hw_set_user_space(pmap_t pmap);				/* Indicate we need a space switch */
extern void 		hw_set_user_space_dis(pmap_t pmap);			/* Indicate we need a space switch (already disabled) */
extern void 		hw_setup_trans(void);						/* Setup hardware for translation */
extern void 		hw_start_trans(void);						/* Start translation for the first time */
extern void 		hw_map_seg(pmap_t pmap, addr64_t seg, addr64_t va);		/* Validate a segment */
extern void 		hw_blow_seg(addr64_t seg);					/* Invalidate a segment */
extern void 		invalidateSegs(pmap_t pmap);				/* Invalidate the segment cache */
extern struct phys_entry *pmap_find_physentry(ppnum_t pa);
extern void			mapLog(unsigned int laddr, unsigned int type, addr64_t va);
extern unsigned int	mapSkipListVerifyC(pmap_t pmap, unsigned long long *dumpa);
extern void			fillPage(ppnum_t pa, unsigned int fill);
extern kern_return_t hw_copypv_32(addr64_t source, addr64_t sink, unsigned int size, int which);

extern void			hw_rem_all_gv(pmap_t pmap);					/* Remove all of a guest's mappings */
extern void			hw_rem_local_gv(pmap_t gpmap);				/* Remove guest local mappings */
extern unsigned int hw_res_map_gv(pmap_t hpmap, pmap_t gpmap, addr64_t hva, addr64_t gva, vm_prot_t prot);
																/* Resume a guest mapping */
extern void			hw_add_map_gv(pmap_t hpmap, pmap_t gpmap, addr64_t gva, unsigned int mflags, ppnum_t pa);
																/* Add a guest mapping */
extern void			hw_susp_map_gv(pmap_t hpmap, pmap_t gpmap, addr64_t gva);
																/* Suspend a guest mapping */
extern unsigned int hw_test_rc_gv(pmap_t hpmap, pmap_t gpmap, addr64_t gva, unsigned int reset);
																/* Test/reset mapping ref and chg */
extern unsigned int	hw_protect_gv(pmap_t gpmap, addr64_t va, vm_prot_t prot);
																/* Change the protection of a guest page */
extern addr64_t		hw_gva_to_hva(pmap_t gpmap, addr64_t gva);	/* Convert guest to host virtual address */
extern unsigned int hw_find_map_gv(pmap_t gpmap, addr64_t gva, void *mpbuf);
																/* Find and copy guest mapping into buffer */

extern unsigned int	mappingdeb0;								/* (TEST/DEBUG) */
extern unsigned int	incrVSID;									/* VSID increment value */

extern int mapSetLists(pmap_t);
extern void consider_mapping_adjust(void);

#endif /* _PPC_MAPPINGS_H_ */

#endif /* XNU_KERNEL_PRIVATE */
