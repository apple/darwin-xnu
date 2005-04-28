/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

/* 	Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. 
 *
 * EventShmemLock.h -	Shared memory area locks for use between the
 *			WindowServer and the Event Driver.
 *
 *
 * HISTORY
 * 29 April 1992    Mike Paquette at NeXT
 *      Created. 
 *
 * Multiprocessor locks used within the shared memory area between the
 * kernel and event system.  These must work in both user and kernel mode.
 * The locks are defined in an include file so they get exported to the local
 * include file area.
 *
 * This is basically a ripoff of the spin locks under the cthreads packages.
 */

#ifndef _IOKIT_IOSHAREDLOCKIMP_H
#define _IOKIT_IOSHAREDLOCKIMP_H

#include <architecture/i386/asm_help.h>

/* 
 * void
 * ev_lock(p)
 *	int *p;
 *
 * Lock the lock pointed to by p.  Spin (possibly forever) until the next
 * lock is available.
 */
	TEXT

#ifndef KERNEL
LEAF(_ev_lock, 0)
LEAF(_IOSpinLock, 0)
	movl		4(%esp), %ecx
0:
	xorl		%eax, %eax
	rep
	nop		/* pause for hyperthreaded CPU's */
	lock
	cmpxchgl	%ecx, (%ecx)
	jne		0b
	ret
END(_ev_lock)
#endif

/*
 * void
 * ev_unlock(p)
 *	int *p;
 *
 * Unlock the lock pointed to by p.
 */
LEAF(_ev_unlock, 0)
LEAF(_IOSpinUnlock, 0)
	movl		4(%esp), %ecx
	movl		$0, (%ecx)
	ret
END(_ev_unlock)



/*
 * int
 * ev_try_lock(p)
 *	int *p;
 *
 * Try to lock p.  Return zero if not successful.
 */

LEAF(_ev_try_lock, 0)
LEAF(_IOTrySpinLock, 0)
        movl            4(%esp), %ecx 
	xorl		%eax, %eax
        lock
        cmpxchgl        %ecx, (%ecx)
	jne	1f
	movl	$1, %eax		/* yes */
	ret
1:
	xorl	%eax, %eax		/* no */
END(_ev_try_lock)


#endif /* ! _IOKIT_IOSHAREDLOCKIMP_H */
