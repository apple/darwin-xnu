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
 * Revision 1.1.1.1  1998/09/22 21:05:30  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:46  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.7.2  1995/01/06  19:51:58  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	[1994/10/14  03:43:15  dwm]
 *
 * Revision 1.2.7.1  1994/09/23  02:43:04  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:43:04  ezf]
 * 
 * Revision 1.2.2.5  1993/09/03  15:53:54  jeffc
 * 	CR9255 - Remove MACH_EXC_COMPAT
 * 	[1993/08/26  15:10:56  jeffc]
 * 
 * Revision 1.2.2.4  1993/08/05  19:09:45  jeffc
 * 	CR9508 - Delete dead code. Remove MACH_IPC_COMPAT
 * 	[1993/08/03  17:09:30  jeffc]
 * 
 * Revision 1.2.2.3  1993/08/03  19:05:13  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	CR9600: Add task_special_port_t typedef.
 * 	[1993/08/02  18:34:37  gm]
 * 
 * Revision 1.2.2.2  1993/06/09  02:43:37  gm
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:18:21  jeffc]
 * 
 * Revision 1.2  1993/04/19  16:39:36  devrcs
 * 	ansi C conformance changes
 * 	[1993/02/02  18:55:14  david]
 * 
 * Revision 1.1  1992/09/30  02:32:11  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4.2.1  92/03/03  16:22:36  jeffreyh
 * 	Changes from TRUNK
 * 	[92/02/26  12:20:27  jeffreyh]
 * 
 * Revision 2.5  92/01/15  13:44:54  rpd
 * 	Changed MACH_IPC_COMPAT conditionals to default to not present.
 * 
 * Revision 2.4  91/05/14  17:00:57  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:36:29  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:21:29  mrt]
 * 
 * Revision 2.2  90/06/02  15:00:03  rpd
 * 	Converted to new IPC.
 * 	[90/03/26  22:40:08  rpd]
 * 
 * Revision 2.1  89/08/03  16:06:01  rwd
 * Created.
 * 
 * Revision 2.3  89/02/25  18:41:12  gm0w
 * 	Changes for cleanup.
 * 
 * 17-Jan-88  David Golub (dbg) at Carnegie-Mellon University
 *	Created.
 *
 */
/* CMU_ENDHIST */
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
 *	File:	mach/task_special_ports.h
 *
 *	Defines codes for special_purpose task ports.  These are NOT
 *	port identifiers - they are only used for the task_get_special_port
 *	and task_set_special_port routines.
 *	
 */

#ifndef	_MACH_TASK_SPECIAL_PORTS_H_
#define _MACH_TASK_SPECIAL_PORTS_H_

typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
					   world.*/

#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */

#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */

#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */

#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */

/*
 *	Definitions for ease of use
 */

#define task_get_kernel_port(task, port)	\
		(task_get_special_port((task), TASK_KERNEL_PORT, (port)))

#define task_set_kernel_port(task, port)	\
		(task_set_special_port((task), TASK_KERNEL_PORT, (port)))

#define task_get_host_port(task, port)		\
		(task_get_special_port((task), TASK_HOST_PORT, (port)))

#define task_set_host_port(task, port)	\
		(task_set_special_port((task), TASK_HOST_PORT, (port)))

#define task_get_bootstrap_port(task, port)	\
		(task_get_special_port((task), TASK_BOOTSTRAP_PORT, (port)))

#define task_set_bootstrap_port(task, port)	\
		(task_set_special_port((task), TASK_BOOTSTRAP_PORT, (port)))

#define task_get_wired_ledger_port(task, port)	\
		(task_get_special_port((task), TASK_WIRED_LEDGER_PORT, (port)))

#define task_set_wired_ledger_port(task, port)	\
		(task_set_special_port((task), TASK_WIRED_LEDGER_PORT, (port)))

#define task_get_paged_ledger_port(task, port)	\
		(task_get_special_port((task), TASK_PAGED_LEDGER_PORT, (port)))

#define task_set_paged_ledger_port(task, port)	\
		(task_set_special_port((task), TASK_PAGED_LEDGER_PORT, (port)))

#endif	/* _MACH_TASK_SPECIAL_PORTS_H_ */
