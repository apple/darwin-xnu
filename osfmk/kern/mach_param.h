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

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE
#ifdef	__APPLE_API_EVOLVING

#define THREAD_MAX		2560	/* Max number of threads */
#define THREAD_CHUNK	64		/* Allocation chunk */

#define TASK_MAX	1024		/* Max number of tasks */
#define TASK_CHUNK	64			/* Allocation chunk */

#define PORT_MAX	((TASK_MAX * 3 + THREAD_MAX)	/* kernel */ \
				+ (THREAD_MAX * 2)	/* user */ \
				+ 40000)		/* slop for objects */
					/* Number of ports, system-wide */

#define SET_MAX		(TASK_MAX + THREAD_MAX + 200)
					/* Max number of port sets */

#define	ITE_MAX		(1 << 16)	/* Max number of splay tree entries */

#define	SPACE_MAX	(TASK_MAX + 5)	/* Max number of IPC spaces */

#define SEMAPHORE_MAX   (PORT_MAX >> 1)	/* Maximum number of semaphores */

#endif	/* __APPLE_API_EVOLVING */
#endif	/* __APPLE_API_PRIVATE */

#endif	/* _KERN_MACH_PARAM_H_ */
