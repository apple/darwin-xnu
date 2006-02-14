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
 * Machine-dependent simple locks for the i386.
 */

#ifndef	_I386_HW_LOCK_TYPES_H_
#define	_I386_HW_LOCK_TYPES_H_

/*
 *	The "hardware lock".  Low-level locking primitives that
 *	MUST be exported by machine-dependent code; this abstraction
 *	must provide atomic, non-blocking mutual exclusion that
 *	is invulnerable to uniprocessor or SMP races, interrupts,
 *	traps or any other events.
 *
 *		hw_lock_data_t		machine-specific lock data structure
 *		hw_lock_t		pointer to hw_lock_data_t
 *
 *	An implementation must export these data types and must
 *	also provide routines to manipulate them (see prototypes,
 *	below).  These routines may be external, inlined, optimized,
 *	or whatever, based on the kernel configuration.  In the event
 *	that the implementation wishes to define its own prototypes,
 *	macros, or inline functions, it may define LOCK_HW_PROTOS
 *	to disable the definitions below.
 *
 *	Mach does not expect these locks to support statistics,
 *	debugging, tracing or any other complexity.  In certain
 *	configurations, Mach will build other locking constructs
 *	on top of this one.  A correctly functioning Mach port need
 *	only implement these locks to be successful.  However,
 *	greater efficiency may be gained with additional machine-
 *	dependent optimizations for the locking constructs defined
 *	later in kern/lock.h..
 */
struct hslock {
	int		lock_data;
};
typedef struct hslock hw_lock_data_t, *hw_lock_t;
#define hw_lock_addr(hwl)	(&((hwl).lock_data))

#endif	/* _I386_HW_LOCK_TYPES_H_ */

