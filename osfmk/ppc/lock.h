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

extern unsigned int LockTimeOut;			/* Number of hardware ticks of a lock timeout */

#if defined(MACH_KERNEL_PRIVATE)

#include <cpus.h>

#if !(NCPUS == 1 || ETAP_LOCK_TRACE || USLOCK_DEBUG)

#include <ppc/hw_lock_types.h>

#define simple_lock_init(l,t)   hw_lock_init(l)
#define __slock_held_func__(l)  hw_lock_held(l)

extern void                     fast_usimple_lock(simple_lock_t);
extern void                     fast_usimple_unlock(simple_lock_t);
extern unsigned int             fast_usimple_lock_try(simple_lock_t);

#define simple_lock(l)          fast_usimple_lock(l)
#define simple_unlock(l)        fast_usimple_unlock(l)
#define simple_lock_try(l)      fast_usimple_lock_try(l)  
#define simple_lock_addr(l)     (&(l))
#define thread_sleep_simple_lock(l, e, i) \
				thread_sleep_fast_usimple_lock((l), (e), (i))

#endif /* !(NCPUS == 1 || ETAP_LOCK_TRACE || USLOCK_DEBUG) */

#endif /* MACH_KERNEL_PRIVATE */

#endif /* __APPLE_API_PRIVATE */

#endif	/* _PPC_LOCK_H_ */
