/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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

#define TASK_NAME_PORT		3	/* the name (unpriv) port for task */

#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */

/*
 * Evolving and likely to change.
 */

#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */

#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */

#define task_get_wired_ledger_port(task, port)	\
		(task_get_special_port((task), TASK_WIRED_LEDGER_PORT, (port)))

#define task_set_wired_ledger_port(task, port)	\
		(task_set_special_port((task), TASK_WIRED_LEDGER_PORT, (port)))

#define task_get_paged_ledger_port(task, port)	\
		(task_get_special_port((task), TASK_PAGED_LEDGER_PORT, (port)))

#define task_set_paged_ledger_port(task, port)	\
		(task_set_special_port((task), TASK_PAGED_LEDGER_PORT, (port)))

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

#endif	/* _MACH_TASK_SPECIAL_PORTS_H_ */
