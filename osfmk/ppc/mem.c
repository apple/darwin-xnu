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

/* A marvelous selection of support routines for virtual memory */

#include <cpus.h>
#include <debug.h>
#include <mach_kdb.h>
#include <mach_vm_debug.h>

#include <kern/cpu_number.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <ppc/misc_protos.h>
#include <ppc/mem.h>
#include <ppc/pmap_internals.h>		/* For pmap_pteg_overflow */

/* These refer to physical addresses and are set and referenced elsewhere */

unsigned int hash_table_base;
unsigned int hash_table_size;

unsigned int hash_function_mask;

struct shadowBAT shadow_BAT;

/* gather statistics about hash table usage */

#if	DEBUG
#define MEM_STATS 1
#else
#define MEM_STATS 0
#endif /* DEBUG */

#if MEM_STATS
/* hash table usage information */
struct hash_table_stats {
	int find_pte_in_pteg_calls;
	int find_pte_in_pteg_not_found;
	int find_pte_in_pteg_location[8];
	struct find_or_alloc_calls {
		int found_primary;
		int found_secondary;
		int alloc_primary;
		int alloc_secondary;
		int overflow;
		int not_found;
	} find_or_alloc_calls[2];
	
} hash_table_stats[NCPUS];

#define INC_STAT(LOC) \
	hash_table_stats[cpu_number()].find_pte_in_pteg_location[LOC]++

#else	/* MEM_STATS */
#define INC_STAT(LOC)
#endif	/* MEM_STATS */

/* Set up the machine registers for the given hash table.
 * The table has already been zeroed.
 */
void hash_table_init(unsigned int base, unsigned int size)
{
	sync();					/* SYNC: it's not just the law, it's a good idea... */
	mtsdr1(hash_table_base | ((size-1)>>16));	/* Slam the SDR1 with the has table address */
	sync();					/* SYNC: it's not just the law, it's a good idea... */
	isync();
}

