/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

/*
 * Multiprocessor locks used within the shared memory area between the
 * kernel and event system.  These must work in both user and kernel mode.
 * 
 * These routines are public, for the purpose of writing frame buffer device
 * drivers which handle their own cursors.  Certain architectures define a
 * generic display class which handles cursor drawing and is subclassed by
 * driver writers.  These drivers need not be concerned with the following
 * types and definitions.
 *
 * The ev_lock(), ev_unlock(), and ev_try_lock() functions are available only
 * to drivers built in or dynamically loaded into the kernel, and to DPS
 * drivers built in or dynamically loaded into the Window Server.  They do not
 * exist in any shared library.
 *
 * --> They're now in IOKit user lib.
 */

#ifndef _IOKIT_IOSHAREDLOCK_H
#define _IOKIT_IOSHAREDLOCK_H

#ifdef __cplusplus
extern "C" {
#endif

// should be 32 bytes on PPC
typedef volatile int		IOSharedLockData;
typedef IOSharedLockData    *   IOSharedLock;

#define IOSpinLockInit(l)	(*(l) = (IOSharedLockData)0)

#ifndef KERNEL
extern void IOSpinLock(IOSharedLock l);
#endif

extern void IOSpinUnlock(IOSharedLock l);
extern boolean_t IOTrySpinLock(IOSharedLock l);

/* exact same stuff & implementation */

typedef IOSharedLockData 	ev_lock_data_t;
typedef ev_lock_data_t	    *	ev_lock_t;

#define ev_init_lock(l)		(*(l) = (ev_lock_data_t)0)
// needs isync?
//#define ev_is_locked(l)	(*(l) != (ev_lock_data_t)0)

#ifndef KERNEL
extern void ev_lock(ev_lock_t l);		// Spin lock!
#endif

extern void ev_unlock(ev_lock_t l);
extern boolean_t ev_try_lock(ev_lock_t l);

#ifdef __cplusplus
}
#endif
#endif /* ! _IOKIT_IOSHAREDLOCK_H */
