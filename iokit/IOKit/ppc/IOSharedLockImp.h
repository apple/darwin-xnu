/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 * HISTORY
 * 30 Nov   1992    Ben Fathi (benf@next.com)
 *      Ported to m98k.
 *
 * 29 April 1992    Mike Paquette at NeXT
 *      Created. 
 *
 * Multiprocessor locks used within the shared memory area between the
 * kernel and event system.  These must work in both user and kernel mode.
 * The locks are defined in an include file so they get exported to the local
 * include file area.
 */


#ifndef _IOKIT_IOSHAREDLOCKIMP_H
#define _IOKIT_IOSHAREDLOCKIMP_H

#include <architecture/ppc/asm_help.h>
#ifdef KERNEL
#undef END
#include <mach/ppc/asm.h>
#endif

.macro DISABLE_PREEMPTION
#ifdef KERNEL
	stwu	r1,-(FM_SIZE)(r1)
	mflr	r0
	stw		r3,FM_ARG0(r1)
	stw		r0,(FM_SIZE+FM_LR_SAVE)(r1)
	bl		EXT(_disable_preemption)
	lwz		r3,FM_ARG0(r1)
	lwz		r1,0(r1)
	lwz		r0,FM_LR_SAVE(r1)
	mtlr	r0
#endif
.endmacro
.macro ENABLE_PREEMPTION
#ifdef KERNEL
	stwu	r1,-(FM_SIZE)(r1)
	mflr	r0
	stw		r3,FM_ARG0(r1)
	stw		r0,(FM_SIZE+FM_LR_SAVE)(r1)
	bl		EXT(_enable_preemption)
	lwz		r3,FM_ARG0(r1)
	lwz		r1,0(r1)
	lwz		r0,FM_LR_SAVE(r1)
	mtlr	r0
#endif
.endmacro

/*
 *	void
 *	ev_lock(p)
 *		register int *p;
 *
 *	Lock the lock pointed to by p.  Spin (possibly forever) until
 *		the lock is available.  Test and test and set logic used.
 */
	TEXT

#ifndef KERNEL
LEAF(_ev_lock)

		li		a6,1			// lock value
		
8:		lwz		a7,0(a0)		// Get lock word
		mr.		a7,a7			// Is it held?
		bne--	8b				// Yup...

9:		lwarx	a7,0,a0			// read the lock
		mr.		a7,a7			// Is it held?
		bne--	7f				// yes, kill reservation
		stwcx.	a6,0,a0			// try to get the lock
		bne--	9b 				// failed, try again
		isync
		blr						// got it, return
		
7:		li		a7,-4			// Point to a spot in the red zone
		stwcx.	a7,a7,r1		// Kill reservation
		b		8b				// Go wait some more...
		
		
END(_ev_lock)

LEAF(_IOSpinLock)

		li		a6,1			// lock value
		
8:		lwz		a7,0(a0)		// Get lock word
		mr.		a7,a7			// Is it held?
		bne--	8b				// Yup...

9:		lwarx	a7,0,a0			// read the lock
		mr.		a7,a7			// Is it held?
		bne--	7f				// yes, kill reservation
		stwcx.	a6,0,a0			// try to get the lock
		bne--	9b 				// failed, try again
		isync
		blr						// got it, return
		
7:		li		a7,-4			// Point to a spot in the red zone
		stwcx.	a7,a7,r1		// Kill reservation
		b		8b				// Go wait some more...
END(_IOSpinLock)
#endif

/*
 *	void
 *	spin_unlock(p)
 *		int *p;
 *
 *	Unlock the lock pointed to by p.
 */

LEAF(_ev_unlock)
	sync
	li	a7,0
	stw	a7,0(a0)
	ENABLE_PREEMPTION()
	blr
END(_ev_unlock)

LEAF(_IOSpinUnlock)
	sync
	li	a7,0
	stw	a7,0(a0)
	ENABLE_PREEMPTION()
	blr
END(_IOSpinUnlock)


/*
 *	ev_try_lock(p)
 *		int *p;
 *
 *	Try to lock p.  Return TRUE if successful in obtaining lock.
 */

LEAF(_ev_try_lock)
	
		DISABLE_PREEMPTION()

		li		a6,1			// lock value
		
		lwz		a7,0(a0)		// Get lock word
		mr.		a7,a7			// Is it held?
		bne--	6f				// Yup...

9:		lwarx	a7,0,a0			// read the lock
		mr.		a7,a7			// Is it held?
		bne--	7f				// yes, kill reservation
		stwcx.	a6,0,a0			// try to get the lock
		bne--	9b 				// failed, try again
		li		a0,1			// return TRUE
		isync
		blr						// got it, return
		
7:		li		a7,-4			// Point to a spot in the red zone
		stwcx.	a7,a7,r1		// Kill reservation

6:
		ENABLE_PREEMPTION()
		li	a0,0				// return FALSE
		blr
		
END(_ev_try_lock)

LEAF(_IOTrySpinLock)
	
		DISABLE_PREEMPTION()

		li		a6,1			// lock value
		
		lwz		a7,0(a0)		// Get lock word
		mr.		a7,a7			// Is it held?
		bne--	6f				// Yup...

9:		lwarx	a7,0,a0			// read the lock
		mr.		a7,a7			// Is it held?
		bne--	7f				// yes, kill reservation
		stwcx.	a6,0,a0			// try to get the lock
		bne--	9b 				// failed, try again
		li		a0,1			// return TRUE
		isync
		blr						// got it, return
		
7:		li		a7,-4			// Point to a spot in the red zone
		stwcx.	a7,a7,r1		// Kill reservation

6:
		ENABLE_PREEMPTION()
		li	a0,0				// return FALSE
		blr
		
END(_IOTrySpinLock)

#endif /* ! _IOKIT_IOSHAREDLOCKIMP_H */
