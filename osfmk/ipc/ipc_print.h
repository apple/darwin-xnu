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
 * Revision 1.1.1.1  1998/09/22 21:05:29  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:16  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.8.3  1995/02/23  17:31:31  alanl
 * 	DIPC:  Merge from nmk17b2 to nmk18b8.
 * 	[95/01/03            mmp]
 *
 * Revision 1.1.7.3  1994/11/29  01:21:22  robert
 * 	re-submit for failed CF backup
 * 	[1994/11/29  01:17:55  robert]
 * 
 * Revision 1.1.7.2  1994/11/28  23:58:36  travos
 * 	Add MACH_KDB ifdef.
 * 	[1994/11/28  23:53:46  travos]
 * 
 * Revision 1.1.7.1  1994/08/04  02:22:55  mmp
 * 	NOTE: file was moved back to b11 version for dipc2_shared.
 * 	Update prototype for ipc_port_print.
 * 	[1994/08/03  19:26:56  mmp]
 * 
 * Revision 1.1.8.2  1994/09/23  02:10:26  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:30:09  ezf]
 * 
 * Revision 1.1.8.1  1994/08/07  20:46:08  bolinger
 * 	Merge up to colo_b7.
 * 	[1994/08/01  20:59:21  bolinger]
 * 
 * Revision 1.1.2.2  1993/08/02  16:12:25  jeffc
 * 	CR9523 -- New file to hold prototypes for ddb print
 * 	functions in the ipc system.
 * 	[1993/07/29  20:13:45  jeffc]
 * 
 * $EndLog$
 */

#ifndef IPC_PRINT_H
#define	IPC_PRINT_H

#include <mach_kdb.h>
#include <ipc/ipc_pset.h>

extern void ipc_pset_print(
			ipc_pset_t	pset);

#include <ipc/ipc_port.h>

#if     MACH_KDB
#include <ddb/db_expr.h>

extern void ipc_port_print(
			ipc_port_t	port,
			boolean_t	have_addr,
			db_expr_t	count,
			char		*modif);

#include <ipc/ipc_kmsg.h>

extern void	ipc_kmsg_print(
			ipc_kmsg_t      kmsg);

#include <mach/message.h>

extern void	ipc_msg_print(
		mach_msg_header_t       *msgh);

extern ipc_port_t ipc_name_to_data(
			task_t			task,
			mach_port_name_t	name);

#endif  /* MACH_KDB */
#endif	/* IPC_PRINT_H */
