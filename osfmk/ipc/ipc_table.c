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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:28  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.2  1998/06/01 17:29:25  youngwor
 * Added infrastructure for shared port space support
 *
 * Revision 1.1.1.1  1998/03/07 02:26:16  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.10.1  1994/09/23  02:12:16  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:30:49  ezf]
 *
 * Revision 1.2.2.3  1993/07/22  16:17:30  rod
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/22  13:33:29  rod]
 * 
 * Revision 1.2.2.2  1993/06/02  23:33:55  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:11:14  jeffc]
 * 
 * Revision 1.2  1992/11/25  01:09:56  robert
 * 	integrate changes below for norma_14
 * 
 * 	Philippe Bernadat (bernadat) at gr.osf.org
 * 	Limit ipc table allocation chunks to 8 pages, otherwise
 * 	the kernel might dead lock because of VM_PAGE_FREE_RESERVED
 * 	limited to 15. [dlb@osf.org & barbou@gr.osf.org]
 * 	[1992/11/13  19:31:46  robert]
 * 
 * Revision 1.1  1992/09/30  02:08:13  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.6  91/10/09  16:11:08  af
 * 	 Revision 2.5.2.1  91/09/16  10:16:06  rpd
 * 	 	Removed unused variables.
 * 	 	[91/09/02            rpd]
 * 
 * Revision 2.5.2.1  91/09/16  10:16:06  rpd
 * 	Removed unused variables.
 * 	[91/09/02            rpd]
 * 
 * Revision 2.5  91/05/14  16:37:35  mrt
 * 	Correcting copyright
 * 
 * Revision 2.4  91/03/16  14:48:52  rpd
 * 	Added ipc_table_realloc and ipc_table_reallocable.
 * 	[91/03/04            rpd]
 * 
 * Revision 2.3  91/02/05  17:24:15  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  15:52:05  mrt]
 * 
 * Revision 2.2  90/06/02  14:51:58  rpd
 * 	Created for new IPC.
 * 	[90/03/26  21:04:20  rpd]
 * 
 */
/* CMU_ENDHIST */
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

/*
 * Forward declarations
 */
void ipc_table_fill(
	ipc_table_size_t	its,
	unsigned int		num,
	unsigned int		min,
	vm_size_t		elemsize);

/*
 *	We borrow the kalloc map, rather than creating
 *	yet another submap of the kernel map.
 */

extern vm_map_t kalloc_map;

ipc_table_size_t ipc_table_entries;
unsigned int ipc_table_entries_size = 512;

ipc_table_size_t ipc_table_dnrequests;
unsigned int ipc_table_dnrequests_size = 64;

void
ipc_table_fill(
	ipc_table_size_t	its,	     /* array to fill */
	unsigned int		num,	     /* size of array */
	unsigned int		min,	     /* at least this many elements */
	vm_size_t		elemsize)    /* size of elements */
{
	unsigned int index;
	vm_size_t minsize = min * elemsize;
	vm_size_t size;
	vm_size_t incrsize;

	/* first use powers of two, up to the page size */

	for (index = 0, size = 1;
	     (index < num) && (size < PAGE_SIZE);
	     size <<= 1) {
		if (size >= minsize) {
			its[index].its_size = size / elemsize;
			index++;
		}
	}

	/* then increments of a page, then two pages, etc. */

	for (incrsize = PAGE_SIZE; index < num;) {
		unsigned int period;

		for (period = 0;
		     (period < 15) && (index < num);
		     period++, size += incrsize) {
			if (size >= minsize) {
				its[index].its_size = size / elemsize;
				index++;
			}
		}
		if (incrsize < (PAGE_SIZE << 3))
			incrsize <<= 1;
	}
}

void
ipc_table_init(void)
{
	ipc_table_entries = (ipc_table_size_t)
		kalloc(sizeof(struct ipc_table_size) *
		       ipc_table_entries_size);
	assert(ipc_table_entries != ITS_NULL);

	ipc_table_fill(ipc_table_entries, ipc_table_entries_size - 1,
		       16, sizeof(struct ipc_entry));

	/* the last two elements should have the same size */

	ipc_table_entries[ipc_table_entries_size - 1].its_size =
		ipc_table_entries[ipc_table_entries_size - 2].its_size;


	ipc_table_dnrequests = (ipc_table_size_t)
		kalloc(sizeof(struct ipc_table_size) *
		       ipc_table_dnrequests_size);
	assert(ipc_table_dnrequests != ITS_NULL);

	ipc_table_fill(ipc_table_dnrequests, ipc_table_dnrequests_size - 1,
		       2, sizeof(struct ipc_port_request));

	/* the last element should have zero size */

	ipc_table_dnrequests[ipc_table_dnrequests_size - 1].its_size = 0;
}

/*
 *	Routine:	ipc_table_alloc
 *	Purpose:
 *		Allocate a table.
 *	Conditions:
 *		May block.
 */

vm_offset_t
ipc_table_alloc(
	vm_size_t	size)
{
	vm_offset_t table;

	if (size < PAGE_SIZE)
		table = kalloc(size);
	else
		if (kmem_alloc(kalloc_map, &table, size) != KERN_SUCCESS)
			table = 0;

	return table;
}

/*
 *	Routine:	ipc_table_realloc
 *	Purpose:
 *		Reallocate a big table.
 *
 *		The new table remaps the old table,
 *		so copying is not necessary.
 *	Conditions:
 *		Only works for page-size or bigger tables.
 *		May block.
 */

vm_offset_t
ipc_table_realloc(
	vm_size_t	old_size,
	vm_offset_t	old_table,
	vm_size_t	new_size)
{
	vm_offset_t new_table;

	if (kmem_realloc(kalloc_map, old_table, old_size,
			 &new_table, new_size) != KERN_SUCCESS)
		new_table = 0;

	return new_table;
}

/*
 *	Routine:	ipc_table_free
 *	Purpose:
 *		Free a table allocated with ipc_table_alloc or
 *		ipc_table_realloc.
 *	Conditions:
 *		May block.
 */

void
ipc_table_free(
	vm_size_t	size,
	vm_offset_t	table)
{
	if (size < PAGE_SIZE)
		kfree(table, size);
	else
		kmem_free(kalloc_map, table, size);
}
