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

/* Things that don't need to be exported from pmap. Putting
 * them here and not in pmap.h avoids major recompiles when
 * modifying something either here or in proc_reg.h
 */

#ifndef _PMAP_INTERNALS_H_
#define _PMAP_INTERNALS_H_

/*
 *	Definition of the flags in the low 5 bits of the phys_link field of the phys_entry
 */
 
#define PHYS_LOCK	0x00000001
#define PHYS_FLAGS	0x0000001F

#ifndef ASSEMBLER

#include <cpus.h>
#include <mach_ldebug.h>
#include <debug.h>

#include <mach/vm_types.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <kern/assert.h>
#include <kern/cpu_number.h>
#include <kern/lock.h>
#include <kern/queue.h>
#include <ppc/proc_reg.h>


/* Page table entries are stored in groups (PTEGS) in a hash table */

#if __PPC__
#if _BIG_ENDIAN == 0
error - bitfield structures are not checked for bit ordering in words
#endif /* _BIG_ENDIAN */
#endif /* __PPC__ */

/*
 * Don't change these structures unless you change the assembly code
 */

struct phys_entry {
	struct mapping	*phys_link;		/* MUST BE FIRST - chain of mappings and flags in the low 5 bits, see above */
	unsigned int	pte1;			/* referenced/changed/wimg - info update atomically */
};

 
#define PHYS_NULL	((struct phys_entry *)0)

/* Memory may be non-contiguous. This data structure contains info
 * for mapping this non-contiguous space into the contiguous
 * physical->virtual mapping tables. An array of this type is
 * provided to the pmap system at bootstrap by ppc_vm_init.
 *
 * NB : regions must be in order in this structure.
 */

typedef struct mem_region {
	vm_offset_t start;	/* Address of base of region */
	struct phys_entry *phys_table; /* base of region's table */
	unsigned int end;       /* End address+1 */
} mem_region_t;

/* PMAP_MEM_REGION_MAX has a PowerMac dependancy - at least the value of
 * kMaxRAMBanks in ppc/POWERMAC/nkinfo.h
 */
#define PMAP_MEM_REGION_MAX 26

extern mem_region_t pmap_mem_regions[PMAP_MEM_REGION_MAX];
extern int          pmap_mem_regions_count;

/* keep track of free regions of physical memory so that we can offer
 * them up via pmap_next_page later on
 */

#define FREE_REGION_MAX 8
extern mem_region_t free_regions[FREE_REGION_MAX];
extern int          free_regions_count;

/* Prototypes */

struct phys_entry *pmap_find_physentry(vm_offset_t pa);


#if	DEBUG
extern int pmdebug;
#define PDB_LOCK	0x100
#define LOCKPRINTF(args)	if (pmdebug & PDB_LOCK) printf args; else
#else	/* DEBUG */
#define LOCKPRINTF(args)
#endif	/* DEBUG */

extern vm_offset_t	hash_table_base;
extern unsigned int	hash_table_size;

#endif
#endif /* _PMAP_INTERNALS_H_ */
