/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.6.1  1994/09/23  01:23:04  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:11:39  ezf]
 *
 * Revision 1.1.2.4  1993/07/27  18:28:34  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:13:34  elliston]
 * 
 * Revision 1.1.2.3  1993/06/07  22:07:00  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  18:57:38  jeffc]
 * 
 * Revision 1.1.2.2  1993/06/02  23:13:21  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  20:57:59  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:24:28  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5  91/10/09  16:04:47  af
 * 	 Revision 2.4.3.1  91/10/05  13:09:14  jeffreyh
 * 	 	Changed "map" field of db_watchpoint structure to "task",
 * 	 	and also changed paramters of function declarations.
 * 	 	[91/08/29            tak]
 * 
 * Revision 2.4.3.1  91/10/05  13:09:14  jeffreyh
 * 	Changed "map" field of db_watchpoint structure to "task",
 * 	and also changed paramters of function declarations.
 * 	[91/08/29            tak]
 * 
 * Revision 2.4  91/05/14  15:37:46  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:07:31  mrt
 * 	Changed to new Mach copyright
 * 	[91/01/31  16:20:09  mrt]
 * 
 * Revision 2.2  90/10/25  14:44:21  rwd
 * 	Generalized the watchpoint support.
 * 	[90/10/16            rwd]
 * 	Created.
 * 	[90/10/16            rpd]
 * 
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
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
 * 	Author: David B. Golub, Carnegie Mellon University
 *	Date:	10/90
 */

#ifndef	_DDB_DB_WATCH_H_
#define	_DDB_DB_WATCH_H_

#include <mach/machine/vm_types.h>
#include <kern/task.h>
#include <machine/db_machdep.h>

/*
 * Watchpoint.
 */

typedef struct db_watchpoint {
	task_t    task;			/* in this map */
	db_addr_t loaddr;		/* from this address */
	db_addr_t hiaddr;		/* to this address */
	struct db_watchpoint *link;	/* link in in-use or free chain */
} *db_watchpoint_t;



/* Prototypes for functions exported by this module.
 */

void db_deletewatch_cmd(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif);

void db_watchpoint_cmd(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif);

void db_listwatch_cmd(void);

void db_clear_watchpoints(void);

void db_set_watchpoints(void);

boolean_t db_find_watchpoint(
	vm_map_t	map,
	db_addr_t	addr,
	db_regs_t	*regs);

#endif	/* !_DDB_DB_WATCH_H_ */
