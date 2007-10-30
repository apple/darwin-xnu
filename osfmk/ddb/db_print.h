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
 * Revision 1.1.31.1  1997/03/27  18:46:44  barbou
 * 	ri-osc CR1566: Add db_show_one_thread() prototype. [dwm]
 * 	[1995/08/28  15:47:07  bolinger]
 * 	[97/02/25            barbou]
 *
 * Revision 1.1.16.6  1995/02/23  21:43:39  alanl
 * 	Merge with DIPC2_SHARED.
 * 	[1995/01/05  13:30:16  alanl]
 * 
 * Revision 1.1.21.2  1994/12/09  22:11:02  dwm
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	* Rev 1.1.16.4  1994/10/11  16:36:02  emcmanus
 * 	  Added db_show_shuttle() and db_show_runq() prototypes.
 * 	[1994/12/09  20:36:53  dwm]
 * 
 * Revision 1.1.21.1  1994/11/10  06:06:47  dwm
 * 	mk6 CR764 - s/spinlock/simple_lock/ (name change only)
 * 	[1994/11/10  05:24:14  dwm]
 * 
 * Revision 1.1.16.3  1994/09/23  01:21:01  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:10:46  ezf]
 * 
 * Revision 1.1.16.2  1994/09/16  15:30:07  emcmanus
 * 	Add prototype for db_show_subsystem.
 * 	[1994/09/16  15:29:05  emcmanus]
 * 
 * Revision 1.1.16.1  1994/06/11  21:12:10  bolinger
 * 	Merge up to NMK17.2.
 * 	[1994/06/11  20:04:06  bolinger]
 * 
 * Revision 1.1.18.2  1994/12/06  19:43:09  alanl
 * 	Intel merge, Oct 94 code drop.
 * 	Added prototypes for db_show_{one,all}_task_vm
 * 	[94/11/28            mmp]
 * 
 * Revision 1.1.18.1  1994/08/05  19:35:57  mmp
 * 	Remove duplicate prototype for db_show_port_id.
 * 	[1994/08/05  19:31:44  mmp]
 * 
 * Revision 1.1.10.3  1994/04/15  18:41:54  paire
 * 	Changed db_task_from_space prototype.
 * 	[94/03/31            paire]
 * 
 * Revision 1.1.10.2  1994/03/07  16:37:54  paire
 * 	Added ANSI prototype for db_port_kmsg_count routine.
 * 	[94/02/15            paire]
 * 
 * Revision 1.1.10.1  1994/02/08  10:58:27  bernadat
 * 	Added	db_show_one_space
 * 		db_show_all_spaces
 * 		db_sys
 * 	prototypes
 * 	[94/02/07            bernadat]
 * 
 * Revision 1.1.2.3  1993/09/17  21:34:40  robert
 * 	change marker to OSF_FREE_COPYRIGHT
 * 	[1993/09/17  21:27:24  robert]
 * 
 * Revision 1.1.2.2  1993/07/27  18:28:01  elliston
 * 	Add ANSI prototypes.  CR #9523.
 * 	[1993/07/27  18:12:43  elliston]
 * 
 * $EndLog$
 */

#ifndef	_DDB_DB_PRINT_H_
#define	_DDB_DB_PRINT_H_

#include <mach/boolean.h>
#include <machine/db_machdep.h>

/* Prototypes for functions exported by this module.
 */
void db_show_regs(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif);

void db_show_all_acts(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_one_act(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_one_thread(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_one_task(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_shuttle(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_port_id(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_one_task_vm(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif);

void db_show_all_task_vm(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif);

void db_show_one_space(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_all_spaces(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_sys(void);

int db_port_kmsg_count(
	ipc_port_t	port);

db_addr_t db_task_from_space(
	ipc_space_t	space,
	int		*task_id);

void db_show_one_simple_lock(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_one_mutex(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_runq(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char *		modif);

void db_show_one_lock(lock_t *);

#endif	/* !_DDB_DB_PRINT_H_ */
