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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	kern/host.h
 *
 *	Definitions for host data structures.
 *
 */

#ifndef	_KERN_HOST_H_
#define _KERN_HOST_H_

#include <mach/mach_types.h>

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef MACH_KERNEL_PRIVATE
#include <kern/lock.h>
#include <kern/exception.h>
#include <mach/exception_types.h>
#include <kern/kern_types.h>


struct	host {
	decl_mutex_data(,lock)		/* lock to protect exceptions */
    	ipc_port_t host_self;
	ipc_port_t host_priv_self;
	ipc_port_t host_security_self;
	ipc_port_t io_master;
	struct exception_action exc_actions[EXC_TYPES_COUNT];
};

typedef struct host	host_data_t;

extern host_data_t	realhost;

#define host_lock(host)		mutex_lock(&(host)->lock)
#define host_unlock(host)	mutex_unlock(&(host)->lock)

#endif /* MACH_KERNEL_PRIVATE */

#endif	/* __APPLE_API_PRIVATE */

/*
 * Access routines for inside the kernel.
 */
extern host_t host_self(void);
extern host_priv_t host_priv_self(void);
extern host_security_t host_security_self(void);

#endif	/* _KERN_HOST_H_ */
