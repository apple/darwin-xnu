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
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:28  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.2  1998/05/29 23:50:33  youngwor
 * Added infrastructure for shared port space support
 *
 * Revision 1.1.1.1  1998/03/07 02:26:16  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.8.3  1995/01/06  19:46:05  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	64bit cleanup
 * 	[1994/10/14  03:41:41  dwm]
 *
 * Revision 1.1.8.2  1994/09/23  02:12:26  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:30:53  ezf]
 * 
 * Revision 1.1.8.1  1994/08/18  23:11:45  widyono
 * 	RT IPC from RT2_SHARED
 * 	[1994/08/18  15:49:24  widyono]
 * 
 * Revision 1.1.6.1  1994/07/29  07:33:22  widyono
 * 	Define default target size, ITS_SIZE_NONE
 * 	[1994/07/28  22:27:01  widyono]
 * 
 * Revision 1.1.2.4  1993/07/22  16:17:33  rod
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/22  13:33:33  rod]
 * 
 * Revision 1.1.2.3  1993/06/07  22:11:46  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  19:02:58  jeffc]
 * 
 * Revision 1.1.2.2  1993/06/02  23:34:02  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:11:17  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:29:14  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/05/14  16:37:52  mrt
 * 	Correcting copyright
 * 
 * Revision 2.4  91/03/16  14:49:01  rpd
 * 	Added ipc_table_realloc.
 * 	[91/03/04            rpd]
 * 
 * Revision 2.3  91/02/05  17:24:19  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  15:52:19  mrt]
 * 
 * Revision 2.2  90/06/02  14:52:02  rpd
 * 	Created for new IPC.
 * 	[90/03/26  21:04:35  rpd]
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
 *	File:	ipc/ipc_table.h
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Definitions for tables, used for IPC capabilities (ipc_entry_t)
 *	and dead-name requests (ipc_port_request_t).
 */

#ifndef	_IPC_IPC_TABLE_H_
#define	_IPC_IPC_TABLE_H_

#include <mach/boolean.h>
#include <mach/vm_param.h>

/*
 *	The is_table_next field of an ipc_space_t points to
 *	an ipc_table_size structure.  These structures must
 *	be elements of an array, ipc_table_entries.
 *
 *	The array must end with two elements with the same its_size value.
 *	Except for the terminating element, the its_size values must
 *	be strictly increasing.  The largest (last) its_size value
 *	must be less than or equal to MACH_PORT_INDEX(MACH_PORT_DEAD).
 *	This ensures that
 *		1) MACH_PORT_INDEX(MACH_PORT_DEAD) isn't a valid index
 *		in the table, so ipc_entry_get won't allocate it.
 *		2) MACH_PORT_MAKE(index+1, 0) and MAKE_PORT_MAKE(size, 0)
 *		won't ever overflow.
 *
 *
 *	The ipr_size field of the first element in a table of
 *	dead-name requests (ipc_port_request_t) points to the
 *	ipc_table_size structure.  The structures must be elements
 *	of ipc_table_dnrequests.  ipc_table_dnrequests must end
 *	with an element with zero its_size, and except for this last
 *	element, the its_size values must be strictly increasing.
 *
 *	The is_table_next field points to the ipc_table_size structure
 *	for the next larger size of table, not the one currently in use.
 *	The ipr_size field points to the currently used ipc_table_size.
 */

typedef natural_t ipc_table_index_t;	/* index into tables */
typedef natural_t ipc_table_elems_t;	/* size of tables */

typedef struct ipc_table_size {
	ipc_table_elems_t its_size;	/* number of elements in table */
} *ipc_table_size_t;

#define	ITS_NULL	((ipc_table_size_t) 0)
#define ITS_SIZE_NONE	-1

extern ipc_table_size_t ipc_table_entries;
extern ipc_table_size_t ipc_table_dnrequests;

/* Initialize IPC capabilities table storage */
extern void ipc_table_init(void);

/*
 *	Note that ipc_table_alloc, ipc_table_realloc, and ipc_table_free
 *	all potentially use the VM system.  Hence simple locks can't
 *	be held across them.
 *
 *	We can't use a copying realloc, because the realloc happens
 *	with the data unlocked.  ipc_table_realloc remaps the data,
 *	so it is OK.
 */

/* Allocate a table */
extern vm_offset_t ipc_table_alloc(
	vm_size_t	size);

/* Reallocate a big table */
extern vm_offset_t ipc_table_realloc(
	vm_size_t	old_size,
	vm_offset_t	old_table,
	vm_size_t	new_size);

/* Free a table */
extern void ipc_table_free(
	vm_size_t	size,
	vm_offset_t	table);

#define	it_entries_alloc(its)						\
	((ipc_entry_t)							\
	 ipc_table_alloc(round_page( 					\
	(its)->its_size * sizeof(struct ipc_entry))))

#define it_entries_reallocable(its)					\
	((its)->its_size * sizeof(struct ipc_entry) 			\
	>= PAGE_SIZE)

#define	it_entries_realloc(its, table, nits)				\
	((ipc_entry_t)							\
	ipc_table_realloc(						\
	    round_page((its)->its_size * sizeof(struct ipc_entry)),	\
	    (vm_offset_t)(table),					\
	    round_page((nits)->its_size * sizeof(struct ipc_entry))	\
	))

#define	it_entries_free(its, table)					\
	ipc_table_free(							\
	    round_page((its)->its_size * sizeof(struct ipc_entry)),	\
	    (vm_offset_t)(table)					\
	)

#define	it_dnrequests_alloc(its)					\
	((ipc_port_request_t)						\
	 ipc_table_alloc((its)->its_size *				\
			 sizeof(struct ipc_port_request)))

#define	it_dnrequests_free(its, table)					\
	ipc_table_free((its)->its_size *				\
		       sizeof(struct ipc_port_request),			\
		       (vm_offset_t)(table))

#endif	/* _IPC_IPC_TABLE_H_ */
