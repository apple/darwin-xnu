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
 * Revision 1.1.1.1  1998/09/22 21:05:34  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:55  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.9.1  1994/09/23  02:22:28  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:34:35  ezf]
 *
 * Revision 1.1.7.1  1994/01/12  17:54:33  dwm
 * 	Coloc: initial restructuring to follow Utah model.
 * 	added various maxima for act/thread_pool zones
 * 	[1994/01/12  17:29:08  dwm]
 * 
 * Revision 1.1.3.3  1993/06/07  22:13:58  jeffc
 * 	CR9176 - ANSI C violations: trailing tokens on CPP
 * 	directives, extra semicolons after decl_ ..., asm keywords
 * 	[1993/06/07  19:06:04  jeffc]
 * 
 * Revision 1.1.3.2  1993/06/02  23:38:46  jeffc
 * 	Added to OSF/1 R1.3 from NMK15.0.
 * 	[1993/06/02  21:13:30  jeffc]
 * 
 * Revision 1.1  1992/09/30  02:29:52  robert
 * 	Initial revision
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.5.2.1  92/03/03  16:20:11  jeffreyh
 * 	19-Feb-92 David L. Black (dlb) at Open Software Foundation
 * 		Double object slop in PORT_MAX, allow for extra (non-task)
 * 	ipc spaces (e.g. ipc_space_remote) in SPACE_MAX
 * 	[92/02/26  11:54:50  jeffreyh]
 * 
 * Revision 2.5  91/05/14  16:44:25  mrt
 * 	Correcting copyright
 * 
 * Revision 2.4  91/02/05  17:27:56  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  16:15:07  mrt]
 * 
 * Revision 2.3  90/06/02  14:55:13  rpd
 * 	Added new IPC parameters.
 * 	[90/03/26  22:11:55  rpd]
 * 
 *
 * Condensed history:
 *	Moved TASK_MAX, PORT_MAX, etc. here from mach/mach_param.h (rpd).
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
 *	File:	kern/mach_param.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1986
 *
 *	Mach system sizing parameters
 *
 */

#ifndef	_KERN_MACH_PARAM_H_
#define _KERN_MACH_PARAM_H_

#define THREAD_MAX	1024		/* Max number of threads */
#define THREAD_CHUNK	64		/* Allocation chunk */

#define TASK_MAX	1024		/* Max number of tasks */
#define TASK_CHUNK	64		/* Allocation chunk */

#define	ACT_MAX		1024		/* Max number of acts */
#define ACT_CHUNK	64		/* Allocation chunk */

#define	THREAD_POOL_MAX	1024		/* Max number of thread_pools */
#define THREAD_POOL_CHUNK 64		/* Allocation chunk */

#define PORT_MAX	((TASK_MAX * 3 + THREAD_MAX)	/* kernel */ \
				+ (THREAD_MAX * 2)	/* user */ \
				+ 40000)		/* slop for objects */
					/* Number of ports, system-wide */

#define SET_MAX		(TASK_MAX + THREAD_MAX + 200)
					/* Max number of port sets */

#define	ITE_MAX		(1 << 16)	/* Max number of splay tree entries */

#define	SPACE_MAX	(TASK_MAX + 5)	/* Max number of IPC spaces */

#define SEMAPHORE_MAX   (PORT_MAX >> 1)	/* Maximum number of semaphores */

#endif	/* _KERN_MACH_PARAM_H_ */
