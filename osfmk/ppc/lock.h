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
 * Copyright (C) 1998 Apple Computer
 * All Rights Reserved
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

#ifndef	_PPC_LOCK_H_
#define	_PPC_LOCK_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE

#include <kern/macro_help.h>
#include <kern/assert.h>
#include <mach/etap_events.h>
#include <mach/etap.h>

extern unsigned int LockTimeOut;			/* Number of hardware ticks of a lock timeout */

#if defined(MACH_KERNEL_PRIVATE)

#include <cpus.h>

#if !(NCPUS == 1 || ETAP_LOCK_TRACE || USLOCK_DEBUG)

#include <ppc/hw_lock_types.h>

#define __slock_held_func__(l)  hw_lock_held(l)

extern void                     ppc_usimple_lock_init(simple_lock_t,etap_event_t);
extern void                     ppc_usimple_lock(simple_lock_t);
extern void                     ppc_usimple_unlock_rwmb(simple_lock_t);
extern void                     ppc_usimple_unlock_rwcmb(simple_lock_t);
extern unsigned int             ppc_usimple_lock_try(simple_lock_t);

#define	MACHINE_SIMPLE_LOCK

#define simple_lock_init(l,t)	ppc_usimple_lock_init(l,t)
#define simple_lock(l)			ppc_usimple_lock(l)
#define simple_unlock(l)		ppc_usimple_unlock_rwcmb(l)
#define simple_unlock_rwmb(l)		ppc_usimple_unlock_rwmb(l)
#define simple_lock_try(l)		ppc_usimple_lock_try(l)  
#define simple_lock_addr(l)		(&(l))
#define thread_sleep_simple_lock(l, e, i) \
				thread_sleep_fast_usimple_lock((l), (e), (i))

#define mutex_unlock(l)		mutex_unlock_rwcmb(l)

#endif /* !(NCPUS == 1 || ETAP_LOCK_TRACE || USLOCK_DEBUG) */

#endif /* MACH_KERNEL_PRIVATE */

#endif /* __APPLE_API_PRIVATE */

#endif	/* _PPC_LOCK_H_ */
