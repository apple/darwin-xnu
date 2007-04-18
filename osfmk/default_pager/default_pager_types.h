/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */


#ifndef	_MACH_DEFAULT_PAGER_TYPES_H_
#define _MACH_DEFAULT_PAGER_TYPES_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE

#include <mach/mach_types.h>
#include <mach/machine/vm_types.h>
#include <mach/memory_object_types.h>

typedef	memory_object_default_t	default_pager_t;

/*
 *	Remember to update the mig type definitions
 *	in default_pager_types.defs when adding/removing fields.
 */

typedef struct default_pager_info {
	vm_size_t 	dpi_total_space; /* size of backing store */
	vm_size_t	dpi_free_space;	 /* how much of it is unused */
	vm_size_t	dpi_page_size;	 /* the pager's vm page size */
} default_pager_info_t;

typedef struct default_pager_info_64 {
	memory_object_size_t 	dpi_total_space; /* size of backing store */
	memory_object_size_t	dpi_free_space;	 /* how much of it is unused */
	vm_size_t		dpi_page_size;	 /* the pager's vm page size */
	int			dpi_flags;
#define DPI_ENCRYPTED	0x1	/* swap files are encrypted */
} default_pager_info_64_t;

typedef integer_t *backing_store_info_t;
typedef int	backing_store_flavor_t;
typedef int	*vnode_ptr_t;

#define BACKING_STORE_BASIC_INFO	1
#define BACKING_STORE_BASIC_INFO_COUNT \
		(sizeof(struct backing_store_basic_info)/sizeof(integer_t))
struct backing_store_basic_info {
	natural_t	pageout_calls;		/* # pageout calls */
	natural_t	pagein_calls;		/* # pagein calls */
	natural_t	pages_in;		/* # pages paged in (total) */
	natural_t	pages_out;		/* # pages paged out (total) */
	natural_t	pages_unavail;		/* # zero-fill pages */
	natural_t	pages_init;		/* # page init requests */
	natural_t	pages_init_writes;	/* # page init writes */

	natural_t	bs_pages_total;		/* # pages (total) */
	natural_t	bs_pages_free;		/* # unallocated pages */
	natural_t	bs_pages_in;		/* # page read requests */
	natural_t	bs_pages_in_fail;	/* # page read errors */
	natural_t	bs_pages_out;		/* # page write requests */
	natural_t	bs_pages_out_fail;	/* # page write errors */

	integer_t	bs_priority;
	integer_t	bs_clsize;
};
typedef struct backing_store_basic_info	*backing_store_basic_info_t;


typedef struct default_pager_object {
	vm_offset_t dpo_object;		/* object managed by the pager */
	vm_size_t dpo_size;		/* backing store used for the object */
} default_pager_object_t;

typedef default_pager_object_t *default_pager_object_array_t;

typedef struct default_pager_page {
	vm_offset_t dpp_offset;		/* offset of the page in its object */
} default_pager_page_t;

typedef default_pager_page_t *default_pager_page_array_t;

#define DEFAULT_PAGER_BACKING_STORE_MAXPRI	4

#define HI_WAT_ALERT		0x01
#define LO_WAT_ALERT		0x02
#define SWAP_ENCRYPT_ON		0x04
#define SWAP_ENCRYPT_OFF	0x08

#endif /* __APPLE_API_UNSTABLE */

#endif	/* _MACH_DEFAULT_PAGER_TYPES_H_ */
