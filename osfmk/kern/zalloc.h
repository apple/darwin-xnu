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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
/*
 *	File:	zalloc.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	 1985
 *
 */

#ifdef	KERNEL_PRIVATE

#ifndef	_KERN_ZALLOC_H_
#define _KERN_ZALLOC_H_

#include <mach/machine/vm_types.h>
#include <kern/kern_types.h>
#include <sys/cdefs.h>

#ifdef	MACH_KERNEL_PRIVATE

#include <zone_debug.h>
#include <mach_kdb.h>
#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/call_entry.h>

/*
 *	A zone is a collection of fixed size blocks for which there
 *	is fast allocation/deallocation access.  Kernel routines can
 *	use zones to manage data structures dynamically, creating a zone
 *	for each type of data structure to be managed.
 *
 */

struct zone {
	int		count;		/* Number of elements used now */
	vm_offset_t	free_elements;
	decl_mutex_data(,lock)		/* generic lock */
	vm_size_t	cur_size;	/* current memory utilization */
	vm_size_t	max_size;	/* how large can this zone grow */
	vm_size_t	elem_size;	/* size of an element */
	vm_size_t	alloc_size;	/* size used for more memory */
	unsigned int
	/* boolean_t */ exhaustible :1,	/* (F) merely return if empty? */
	/* boolean_t */	collectable :1,	/* (F) garbage collect empty pages */
	/* boolean_t */	expandable :1,	/* (T) expand zone (with message)? */
	/* boolean_t */ allows_foreign :1,/* (F) allow non-zalloc space */
	/* boolean_t */	doing_alloc :1,	/* is zone expanding now? */
	/* boolean_t */	waiting :1,	/* is thread waiting for expansion? */
	/* boolean_t */	async_pending :1,	/* asynchronous allocation pending? */
	/* boolean_t */	doing_gc :1;	/* garbage collect in progress? */
	struct zone *	next_zone;	/* Link for all-zones list */
	call_entry_data_t	call_async_alloc;	/* callout for asynchronous alloc */
	const char	*zone_name;	/* a name for the zone */
#if	ZONE_DEBUG
	queue_head_t	active_zones;	/* active elements */
#endif	/* ZONE_DEBUG */
};

extern void		zone_gc(void);
extern void		consider_zone_gc(void);

/* Steal memory for zone module */
extern void		zone_steal_memory(void);

/* Bootstrap zone module (create zone zone) */
extern void		zone_bootstrap(void);

/* Init zone module */
extern void		zone_init(
					vm_size_t	map_size);

/* Stack use statistics */
extern void		stack_fake_zone_info(
					int			*count, 
					vm_size_t	*cur_size, 
					vm_size_t	*max_size,
					vm_size_t	*elem_size,
					vm_size_t	*alloc_size, 
					int			*collectable, 
					int			*exhaustable);

#if		ZONE_DEBUG

#if		MACH_KDB

extern void *	next_element(
				zone_t		z,
				void 		*elt);

extern void *	first_element(
				zone_t		z);

#endif	/* MACH_KDB */

extern void		zone_debug_enable(
				zone_t		z);

extern void		zone_debug_disable(
				zone_t		z);

#endif	/* ZONE_DEBUG */

#endif	/* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS

#ifdef	XNU_KERNEL_PRIVATE

/* Allocate from zone */
extern void *	zalloc(
					zone_t		zone);

/* Free zone element */
extern void		zfree(
					zone_t		zone,
					void 		*elem);

/* Create zone */
extern zone_t	zinit(
					vm_size_t	size,		/* the size of an element */
					vm_size_t	maxmem,		/* maximum memory to use */
					vm_size_t	alloc,		/* allocation size */
					const char	*name);		/* a name for the zone */


/* Non-blocking version of zalloc */
extern void *	zalloc_noblock(
					zone_t		zone);

/* direct (non-wrappered) interface */
extern void *	zalloc_canblock(
					zone_t		zone,
					boolean_t	canblock);

/* Get from zone free list */
extern void *	zget(
					zone_t		zone);

/* Fill zone with memory */
extern void		zcram(
					zone_t		zone,
					void		*newmem,
					vm_size_t	size);

/* Initially fill zone with specified number of elements */
extern int		zfill(
					zone_t		zone,
					int			nelem);

/* Change zone parameters */
extern void		zone_change(
					zone_t			zone,
					unsigned int	item,
					boolean_t		value);

/* Item definitions */
#define Z_EXHAUST	1	/* Make zone exhaustible	*/
#define Z_COLLECT	2	/* Make zone collectable	*/
#define Z_EXPAND	3	/* Make zone expandable		*/
#define	Z_FOREIGN	4	/* Allow collectable zone to contain foreign elements */

/* Preallocate space for zone from zone map */
extern void		zprealloc(
					zone_t		zone,
					vm_size_t	size);

extern integer_t	zone_free_count(
						zone_t		zone);

#endif	/* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif	/* _KERN_ZALLOC_H_ */

#endif	/* KERNEL_PRIVATE */
