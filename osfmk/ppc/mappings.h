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
 *		Header files for the hardware virtual memory mapping stuff 
 */
#ifndef	_PPC_MAPPINGS_H_
#define	_PPC_MAPPINGS_H_

typedef struct PCA {					/* PTEG Control Area */
	unsigned int		PCAlock;		/* PCA lock */
	union flgs {
		unsigned int	PCAallo;		/* Allocation controls */
		struct PCAalflgs {				/* Keep these in order!!! */
			unsigned char	PCAfree;	/* Indicates the slot is free */
			unsigned char	PCAauto;	/* Indicates that the PTE was autogenned */
			unsigned char	PCAslck;	/* Indicates that the slot is locked */
			unsigned char	PCAsteal;	/* Steal scan start position */
		} PCAalflgs;
	} flgs;
	unsigned int		PCAgas[6];		/* Filler to 32 byte boundary */
	unsigned int		PCAhash[8];		/* PTEG hash chains */
} PCA;

#define MAPFLAGS 0x0000001F
#define BMAP 0x00000001

typedef struct mapping {
	struct mapping		*next;			/* MUST BE FIRST - chain off physent */
	struct mapping		*hashnext;		/* Next mapping in same hash group */
	unsigned int		*PTEhash;		/* Pointer to the head of the mapping hash list */
	unsigned int		*PTEent;		/* Pointer to PTE if exists */
	struct phys_entry	*physent;		/* Quick pointer back to the physical entry */
	unsigned int		PTEv;			/* Virtual half of HW PTE */
	unsigned int		PTEr;			/* Real half of HW PTE. This is used ONLY if
										   there is no physical entry associated
										   with this mapping, ie.e, physent==0 */
	struct pmap 		*pmap;			/* Quick pointer back to the containing pmap */
} mapping;

/* 
 *	This control block maps odd size blocks of memory.  The mapping must
 *	be V=F (Virtual = Fixed), i.e., virtually and physically contiguous
 *	multiples of hardware size pages.
 *
 *	This control block overlays the mapping CB and is allocated from the
 *	same pool.
 *
 *	It is expected that only a small number of these exist for each address
 *	space and will typically be for I/O areas. It is further assumed that 
 *	there is a minimum size (ODDBLKMIN) for these blocks.  If smaller, the
 *	block will be split into N normal page mappings.
 *
 *	Binary tree for fast lookups. 
 */


typedef struct blokmap {
	struct blokmap		*next;			/* Next block in list */
	unsigned int		start;			/* Start of block */
	unsigned int		end;			/* End of block */
	unsigned int		PTEr;			/* Real half of HW PTE at base address */
	unsigned int		space;			/* Cached VSID */
	unsigned int		blkFlags;		/* Flags for this block */
#define blkPerm 0x80000000
#define blkPermbit 0
	unsigned int		gas3;			/* Reserved */
	unsigned int		gas4;			/* Reserved */
} blokmap;

#define ODDBLKMIN (8 * PAGE_SIZE)

#define MAPPING_NULL	((struct mapping *) 0)

#define mapDirect 0x08
#define mapRWNA   0x00000000
#define mapRWRO   0x00000001
#define mapRWRW   0x00000002
#define mapRORO   0x00000003


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
	unsigned int		mapcmin;		/* Minimum free mappings to keep */
	unsigned int		mapcmaxalloc;	/* Maximum number of mappings allocated at one time */
	unsigned int		mapcgas[3];		/* Pad to 64 bytes */
} mappingctl;

#define MAPPERBLOK 127
#define MAPALTHRSH (4*MAPPERBLOK)
#define MAPFRTHRSH (2 * ((MAPALTHRSH + MAPPERBLOK - 1) / MAPPERBLOK))
typedef struct mappingblok {
	unsigned int		mapblokfree[4];	/* Bit map of free mapping entrys */
	unsigned int		mapblokvrswap;	/* Virtual address XORed with physical address */
	unsigned int		mapblokflags;	/* Various flags */
#define mbPerm 0x80000000				/* Block is permanent */
	struct mappingblok	*nextblok;		/* Pointer to the next mapping block */
} mappingblok;

extern mappingctl	mapCtl;				/* Mapping allocation control */

extern void 		mapping_phys_init(struct phys_entry *pp, unsigned int pa, unsigned int wimg);	/* Initializes hw specific storage attributes */
extern boolean_t 	mapping_remove(pmap_t pmap, vm_offset_t va);	/* Remove a single mapping for this VADDR */
extern void 		mapping_free_init(vm_offset_t mbl, int perm, boolean_t locked);	/* Sets start and end of a block of mappings */
extern void 		mapping_adjust(void);						/* Adjust free mapping count */
extern void 		mapping_free_prime(void);					/* Primes the mapping block release list */
extern void 		mapping_prealloc(unsigned int);				/* Preallocate mappings for large use */
extern void 		mapping_relpre(void);						/* Releases preallocate request */
extern void 		mapping_init(void);							/* Do initial stuff */
extern mapping 		*mapping_alloc(void);						/* Obtain a mapping */
extern void 		mapping_free(struct mapping *mp);			/* Release a mapping */
extern boolean_t 	mapping_tst_ref(struct phys_entry *pp);		/* Tests the reference bit of a physical page */
extern boolean_t 	mapping_tst_mod(struct phys_entry *pp);		/* Tests the change bit of a physical page */
extern void 		mapping_set_ref(struct phys_entry *pp);		/* Sets the reference bit of a physical page */
extern void 		mapping_clr_ref(struct phys_entry *pp);		/* Clears the reference bit of a physical page */
extern void 		mapping_set_mod(struct phys_entry *pp);		/* Sets the change bit of a physical page */
extern void 		mapping_clr_mod(struct phys_entry *pp);		/* Clears the change bit of a physical page */
extern void 		mapping_invall(struct phys_entry *pp);		/* Clear all PTEs pointing to a physical page */
extern void 		mapping_protect_phys(struct phys_entry *pp, vm_prot_t prot, boolean_t locked);	/* Change protection of all mappings to page */
extern void 		mapping_protect(pmap_t pmap, vm_offset_t vaddr, vm_prot_t prot);	/* Change protection of a single mapping to page */
extern mapping 		*mapping_make(pmap_t pmap, struct phys_entry *pp, vm_offset_t va, vm_offset_t pa, vm_prot_t prot, int attr, boolean_t locked);	/* Make an address mapping */
extern void 		mapping_purge(struct phys_entry *pp);		/* Remove all mappings for this physent */
extern void		mapping_purge_pmap(struct phys_entry *pp, pmap_t pmap); /* Remove physent mappings for this pmap */
extern vm_offset_t	mapping_p2v(pmap_t pmap, struct phys_entry *pp);	/* Finds first virtual mapping of a physical page in a space */
extern void 		mapping_phys_attr(struct phys_entry *pp, vm_prot_t prot, unsigned int wimg);	/* Sets the default physical page attributes */
extern void 		mapping_block_map_opt(pmap_t pmap, vm_offset_t va, vm_offset_t pa, vm_offset_t bnd, vm_size_t size, vm_prot_t prot, int attr);	/* Map a block optimally */
extern int			mapalc(struct mappingblok *mb);				/* Finds and allcates a mapping entry */
extern void			ignore_zero_fault(boolean_t type);			/* Sets up to ignore or honor any fault on page 0 access for the current thread */


extern mapping 		*hw_lock_phys_vir(space_t space, vm_offset_t va);	/* Finds and locks a physical entry by vaddr */
extern mapping 		*hw_cpv(struct mapping *mapping);			/* Converts a physical mapping control block address to virtual */
extern mapping 		*hw_cvp(struct mapping *mapping);			/* Converts a virtual mapping control block address to physical */
extern void 		hw_rem_map(struct mapping *mapping);		/* Remove a mapping from the system */
extern void			hw_add_map(struct mapping *mp, space_t space, vm_offset_t va);	/* Add a mapping to the PTEG hash list */
extern blokmap 		*hw_rem_blk(pmap_t pmap, vm_offset_t sva, vm_offset_t eva);	/* Remove a block that falls within a range */
extern vm_offset_t	hw_cvp_blk(pmap_t pmap, vm_offset_t va);	/* Convert mapped block virtual to physical */
extern blokmap 		*hw_add_blk(pmap_t pmap, struct blokmap *bmr);	/* Add a block to the pmap */
extern void 		hw_prot(struct phys_entry *pp, vm_prot_t prot);	/* Change the protection of a physical page */
extern void 		hw_prot_virt(struct mapping *mp, vm_prot_t prot);	/* Change the protection of a virtual page */
extern void 		hw_attr_virt(struct mapping *mp, unsigned int wimg);	/* Change the attributes of a virtual page */
extern void 		hw_phys_attr(struct phys_entry *pp, vm_prot_t prot, unsigned int wimg);	/* Sets the default physical page attributes */
extern unsigned int	hw_test_rc(struct mapping *mp, boolean_t reset);	/* Test and optionally reset the RC bit of specific mapping */

extern boolean_t 	hw_tst_mod(struct phys_entry *pp);			/* Tests change bit */
extern void 		hw_set_mod(struct phys_entry *pp);			/* Set change bit */
extern void 		hw_clr_mod(struct phys_entry *pp);			/* Clear change bit */

extern boolean_t 	hw_tst_ref(struct phys_entry *pp);			/* Tests reference bit */
extern void 		hw_set_ref(struct phys_entry *pp);			/* Set reference bit */
extern void 		hw_clr_ref(struct phys_entry *pp);			/* Clear reference bit */

extern void 		hw_inv_all(struct phys_entry *pp);			/* Invalidate all PTEs associated with page */
extern void 		hw_set_user_space(pmap_t pmap);				/* Indicate we need a space switch */
extern void 		hw_set_user_space_dis(pmap_t pmap);			/* Indicate we need a space switch (already disabled) */
kern_return_t		copyp2v(vm_offset_t source, vm_offset_t sink, unsigned int size);	/* Copy a physical page to a virtual address */
extern void			*LRA(space_t space, void *vaddr);			/* Translate virtual to real using only HW tables */
extern void 		dumpaddr(space_t space, vm_offset_t va);
extern void			dumpmapping(struct mapping *mp);			/* Print contents of a mapping */
extern void			dumppca(struct mapping *mp);				/* Print contents of a PCA */
extern void			dumpphys(struct phys_entry *pp);			/* Prints stuff starting at phys */

extern unsigned int	mappingdeb0;								/* (TEST/DEBUG) */
extern unsigned int	incrVSID;									/* VSID increment value */

#endif /* _PPC_MAPPINGS_H_ */

