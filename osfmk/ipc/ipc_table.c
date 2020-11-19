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
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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
 *	File:	ipc/ipc_table.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate tables of IPC capabilities.
 */

#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <ipc/ipc_table.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_entry.h>
#include <kern/kalloc.h>
#include <vm/vm_kern.h>

#define IPC_TABLE_ENTRIES_SIZE CONFIG_IPC_TABLE_ENTRIES_STEPS
SECURITY_READ_ONLY_LATE(struct ipc_table_size) ipc_table_entries[IPC_TABLE_ENTRIES_SIZE];

#define IPC_TABLE_REQUESTS_SIZE 64
SECURITY_READ_ONLY_LATE(struct ipc_table_size) ipc_table_requests[IPC_TABLE_REQUESTS_SIZE];

static void
ipc_table_fill(
	ipc_table_size_t        its,         /* array to fill */
	unsigned int            num,         /* size of array */
	unsigned int            min,         /* at least this many elements */
	vm_size_t               elemsize)    /* size of elements */
{
	unsigned int index;
	vm_size_t minsize = min * elemsize;
	vm_size_t size;
	vm_size_t incrsize;

	/* first use powers of two, up to the page size */

	for (index = 0, size = 1;
	    (index < num) && (size < PAGE_MAX_SIZE);
	    size <<= 1) {
		if (size >= minsize) {
			its[index].its_size = (ipc_table_elems_t)(size / elemsize);
			index++;
		}
	}

	/* then increments of a page, then two pages, etc. */

	for (incrsize = PAGE_MAX_SIZE; index < num;) {
		unsigned int period;

		for (period = 0;
		    (period < 15) && (index < num);
		    period++, size += incrsize) {
			if (size >= minsize) {
				its[index].its_size = (ipc_table_elems_t)(size / elemsize);
				index++;
			}
		}
		if (incrsize < (vm_size_t)(PAGE_MAX_SIZE << 3)) {
			incrsize <<= 1;
		}
	}
}

__startup_func
static void
ipc_table_init(void)
{
	ipc_table_fill(ipc_table_entries, IPC_TABLE_ENTRIES_SIZE - 1,
	    16, sizeof(struct ipc_entry));

	/* the last two elements should have the same size */

	ipc_table_entries[IPC_TABLE_ENTRIES_SIZE - 1].its_size =
	    ipc_table_entries[IPC_TABLE_ENTRIES_SIZE - 2].its_size;

	/* make sure the robin hood hashing in ipc hash will work */
	assert(ipc_table_entries[IPC_TABLE_ENTRIES_SIZE - 1].its_size <=
	    IPC_ENTRY_INDEX_MAX);

	ipc_table_fill(ipc_table_requests, IPC_TABLE_REQUESTS_SIZE - 1,
	    2, sizeof(struct ipc_port_request));

	/* the last element should have zero size */

	ipc_table_requests[IPC_TABLE_REQUESTS_SIZE - 1].its_size = 0;
}
STARTUP(MACH_IPC, STARTUP_RANK_FIRST, ipc_table_init);


/*
 *	Routine: ipc_table_max_entries
 *	Purpose:
 *		returns the maximum number of entries an IPC space
 *		is allowed to contain (the maximum size to which it will grow)
 *	Conditions:
 *		none
 */
unsigned int
ipc_table_max_entries(void)
{
	static_assert(IPC_TABLE_ENTRIES_SIZE >= 1);
	return (unsigned int)ipc_table_entries[IPC_TABLE_ENTRIES_SIZE - 1].its_size;
}


/*
 *	Routine: ipc_table_max_requests
 *	Purpose:
 *		returns the maximum number of requests an IPC request table
 *		is allowed to contain (the maximum size to which it will grow)
 *	Conditions:
 *		none
 */
unsigned int
ipc_table_max_requests(void)
{
	static_assert(IPC_TABLE_REQUESTS_SIZE >= 2);
	return (unsigned int)ipc_table_requests[IPC_TABLE_REQUESTS_SIZE - 2].its_size;
}


/*
 *	Routine:	ipc_table_alloc
 *	Purpose:
 *		Allocate a table.
 *	Conditions:
 *		May block.
 */

void *
ipc_table_alloc(
	vm_size_t       size)
{
	return kalloc(size);
}


/*
 *	Routine:	ipc_table_free
 *	Purpose:
 *		Free a table allocated with ipc_table_alloc.
 *	Conditions:
 *		May block.
 */

void
ipc_table_free(
	vm_size_t       size,
	void *          table)
{
	kfree(table, size);
}
