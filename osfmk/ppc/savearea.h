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
#ifndef _PPC_SAVEAREA_H_
#define _PPC_SAVEAREA_H_

#include <ppc/exception.h>
#include <mach/ppc/vm_types.h>

void 			save_release(struct savearea *save);	/* Release a save area  */
struct savectl	*save_dequeue(void);			/* Find and dequeue one that is all empty */
unsigned int	save_queue(vm_offset_t);		/* Add a new savearea block to the free list */
struct savearea	*save_get(void);				/* Obtains a savearea from the free list (returns virtual address) */
struct savearea	*save_get_phys(void);			/* Obtains a savearea from the free list (returns physical address) */
struct savearea	*save_alloc(void);				/* Obtains a savearea and allocates blocks if needed */
struct savearea	*save_cpv(struct savearea *);	/* Converts a physical savearea address to virtual */
unsigned int	*save_deb(unsigned int *msr);	/* Finds virtual of first free block and disableds interrupts */
void			save_ret(struct savearea *);	/* Returns a savearea to the free list */
#if DEBUG
void 			save_free_dump(void);			/* Dump the free chain */
void			DumpTheSave(struct savearea *);	/* Prints out a savearea */
void 			DumpBackChain(struct savearea *save); /* Dumps a backchain */
#endif

#endif /* _PPC_SAVEAREA_H_ */


