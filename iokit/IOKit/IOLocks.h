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
 *
 */

#ifndef __IOKIT_IOLOCKS_H
#define __IOKIT_IOLOCKS_H

#ifndef KERNEL
#error IOLocks.h is for kernel use only
#endif

#ifndef IOKIT_DEPRECATED
#define IOKIT_DEPRECATED	1
#endif

#include <IOKit/system.h>

#include <IOKit/IOReturn.h>
#include <IOKit/IOTypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <kern/lock.h>
#include <kern/simple_lock.h>
#include <machine/machine_routines.h>

/*
 * Mutex lock operations
 */

typedef mutex_t	IOLock;

/*! @function IOLockAlloc
    @abstract Allocates and initializes an osfmk mutex.
    @discussion Allocates an osfmk mutex in general purpose memory, and initilizes it. Mutexes are general purpose blocking mutual exclusion locks, supplied by osfmk/kern/lock.h. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @result Pointer to the allocated lock, or zero on failure. */

IOLock * IOLockAlloc( void );

/*! @function IOLockFree
    @abstract Frees an osfmk mutex.
    @discussion Frees a lock allocated with IOLockAlloc. Any blocked waiters will not be woken.
    @param lock Pointer to the allocated lock. */

void	IOLockFree( IOLock * lock);

/*! @function IOLockLock
    @abstract Lock an osfmk mutex.
    @discussion Lock the mutex. If the lock is held by any thread, block waiting for its unlock. This function may block and so should not be called from interrupt level or while a simple lock is held. Locking the mutex recursively from one thread will result in deadlock. 
    @param lock Pointer to the allocated lock. */

static __inline__
void	IOLockLock( IOLock * lock)
{
    _mutex_lock(lock);
}

/*! @function IOLockTryLock
    @abstract Attempt to lock an osfmk mutex.
    @discussion Lock the mutex if it is currently unlocked, and return true. If the lock is held by any thread, return false.
    @param lock Pointer to the allocated lock.
    @result True if the mutex was unlocked and is now locked by the caller, otherwise false. */

static __inline__
boolean_t IOLockTryLock( IOLock * lock)
{
    return(_mutex_try(lock));
}

/*! @function IOLockUnlock
    @abstract Unlock an osfmk mutex.
@discussion Unlock the mutex and wake any blocked waiters. Results are undefined if the caller has not locked the mutex. This function may block and so should not be called from interrupt level or while a simple lock is held. 
    @param lock Pointer to the allocated lock. */

static __inline__
void	IOLockUnlock( IOLock * lock)
{
    mutex_unlock(lock);
}

#if IOKIT_DEPRECATED

/* The following API is deprecated */

typedef enum {
    kIOLockStateUnlocked	= 0,
    kIOLockStateLocked		= 1,
} IOLockState;

void	IOLockInitWithState( IOLock * lock, IOLockState state);
#define	IOLockInit( l )	IOLockInitWithState( l, kIOLockStateUnlocked);

static __inline__ void IOTakeLock( IOLock * lock) { IOLockLock(lock); 	     }
static __inline__ boolean_t IOTryLock(  IOLock * lock) { return(IOLockTryLock(lock)); }
static __inline__ void IOUnlock(   IOLock * lock) { IOLockUnlock(lock);	     }

#endif /* IOKIT_DEPRECATED */

/*
 * Recursive lock operations
 */

typedef struct _IORecursiveLock IORecursiveLock;

/*! @function IORecursiveLockAlloc
    @abstract Allocates and initializes an recursive lock.
    @discussion Allocates a recursive lock in general purpose memory, and initilizes it. Recursive locks function identically to osfmk mutexes but allow one thread to lock more than once, with balanced unlocks.
    @result Pointer to the allocated lock, or zero on failure. */

IORecursiveLock * IORecursiveLockAlloc( void );

/*! @function IORecursiveLockFree
    @abstract Frees a recursive lock.
    @discussion Frees a lock allocated with IORecursiveLockAlloc. Any blocked waiters will not be woken.
    @param lock Pointer to the allocated lock. */

void		IORecursiveLockFree( IORecursiveLock * lock);

/*! @function IORecursiveLockLock
    @abstract Lock a recursive lock.
    @discussion Lock the recursive lock. If the lock is held by another thread, block waiting for its unlock. This function may block and so should not be called from interrupt level or while a simple lock is held. The lock may be taken recursively by the same thread, with a balanced number of calls to IORecursiveLockUnlock.
    @param lock Pointer to the allocated lock. */

void		IORecursiveLockLock( IORecursiveLock * lock);

/*! @function IORecursiveLockTryLock
    @abstract Attempt to lock a recursive lock.
    @discussion Lock the lock if it is currently unlocked, or held by the calling thread, and return true. If the lock is held by another thread, return false. Successful calls to IORecursiveLockTryLock should be balanced with calls to IORecursiveLockUnlock.
    @param lock Pointer to the allocated lock.
    @result True if the lock is now locked by the caller, otherwise false. */

boolean_t	IORecursiveLockTryLock( IORecursiveLock * lock);

/*! @function IORecursiveLockUnlock
    @abstract Unlock a recursive lock.
@discussion Undo one call to IORecursiveLockLock, if the lock is now unlocked wake any blocked waiters. Results are undefined if the caller does not balance calls to IORecursiveLockLock with IORecursiveLockUnlock. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @param lock Pointer to the allocated lock. */

void		IORecursiveLockUnlock( IORecursiveLock * lock);

/*! @function IORecursiveLockHaveLock
    @abstract Check if a recursive lock is held by the calling thread.
    @discussion If the lock is held by the calling thread, return true, otherwise the lock is unlocked, or held by another thread and false is returned.
    @param lock Pointer to the allocated lock.
    @result True if the calling thread holds the lock otherwise false. */

boolean_t	IORecursiveLockHaveLock( const IORecursiveLock * lock);

extern int	IORecursiveLockSleep( IORecursiveLock *_lock,
                                      void *event, UInt32 interType);
extern void	IORecursiveLockWakeup( IORecursiveLock *_lock,
                                       void *event, bool oneThread);

/*
 * Complex (read/write) lock operations
 */

typedef lock_t	IORWLock;

/*! @function IORWLockAlloc
    @abstract Allocates and initializes an osfmk general (read/write) lock.
@discussion Allocates an initializes an osfmk lock_t in general purpose memory, and initilizes it. Read/write locks provide for multiple readers, one exclusive writer, and are supplied by osfmk/kern/lock.h. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @result Pointer to the allocated lock, or zero on failure. */

IORWLock * IORWLockAlloc( void );

/*! @function IORWLockFree
   @abstract Frees an osfmk general (read/write) lock.
   @discussion Frees a lock allocated with IORWLockAlloc. Any blocked waiters will not be woken.
    @param lock Pointer to the allocated lock. */

void	IORWLockFree( IORWLock * lock);

/*! @function IORWLockRead
    @abstract Lock an osfmk lock for read.
@discussion Lock the lock for read, allowing multiple readers when there are no writers. If the lock is held for write, block waiting for its unlock. This function may block and so should not be called from interrupt level or while a simple lock is held. Locking the lock recursively from one thread, for read or write, can result in deadlock.
    @param lock Pointer to the allocated lock. */

static __inline__
void	IORWLockRead( IORWLock * lock)
{
    lock_read( lock);
}

/*! @function IORWLockWrite
    @abstract Lock an osfmk lock for write.
    @discussion Lock the lock for write, allowing one writer exlusive access. If the lock is held for read or write, block waiting for its unlock. This function may block and so should not be called from interrupt level or while a simple lock is held. Locking the lock recursively from one thread, for read or write, can result in deadlock.
    @param lock Pointer to the allocated lock. */

static __inline__
void	IORWLockWrite( IORWLock * lock)
{
    lock_write( lock);
}

/*! @function IORWLockUnlock
    @abstract Unlock an osfmk lock.
    @discussion Undo one call to IORWLockRead or IORWLockWrite. Results are undefined if the caller has not locked the lock. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @param lock Pointer to the allocated lock. */

static __inline__
void	IORWLockUnlock( IORWLock * lock)
{
    lock_done( lock);
}

#if IOKIT_DEPRECATED

/* The following API is deprecated */

static __inline__ void IOReadLock( IORWLock * lock)   { IORWLockRead(lock);   }
static __inline__ void IOWriteLock(  IORWLock * lock) { IORWLockWrite(lock);  }
static __inline__ void IORWUnlock(   IORWLock * lock) { IORWLockUnlock(lock); }

#endif /* IOKIT_DEPRECATED */


/*
 * Simple locks. Cannot block while holding a simple lock.
 */

typedef simple_lock_data_t IOSimpleLock;

/*! @function IOSimpleLockAlloc
    @abstract Allocates and initializes an osfmk simple (spin) lock.
    @discussion Allocates an initializes an osfmk simple lock in general purpose memory, and initilizes it. Simple locks provide non-blocking mutual exclusion for synchronization between thread context and interrupt context, or for multiprocessor synchronization, and are supplied by osfmk/kern/simple_lock.h. This function may block and so should not be called from interrupt level or while a simple lock is held.
    @result Pointer to the allocated lock, or zero on failure. */

IOSimpleLock * IOSimpleLockAlloc( void );

/*! @function IOSimpleLockFree
    @abstract Frees an osfmk simple (spin) lock.
    @discussion Frees a lock allocated with IOSimpleLockAlloc.
    @param lock Pointer to the lock. */

void IOSimpleLockFree( IOSimpleLock * lock );

/*! @function IOSimpleLockInit
    @abstract Initialize an osfmk simple (spin) lock.
    @discussion Initialize an embedded osfmk simple lock, to the unlocked state.
    @param lock Pointer to the lock. */

void IOSimpleLockInit( IOSimpleLock * lock );

/*! @function IOSimpleLockLock
    @abstract Lock an osfmk simple lock.
@discussion Lock the simple lock. If the lock is held, spin waiting for its unlock. Simple locks disable preemption, cannot be held across any blocking operation, and should be held for very short periods. When used to synchronize between interrupt context and thread context they should be locked with interrupts disabled - IOSimpleLockLockDisableInterrupt() will do both. Locking the lock recursively from one thread will result in deadlock.
    @param lock Pointer to the lock. */

static __inline__
void IOSimpleLockLock( IOSimpleLock * lock )
{
    simple_lock( lock );
}

/*! @function IOSimpleLockTryLock
    @abstract Attempt to lock an osfmk simple lock.
@discussion Lock the simple lock if it is currently unlocked, and return true. If the lock is held, return false. Successful calls to IOSimpleLockTryLock should be balanced with calls to IOSimpleLockUnlock. 
    @param lock Pointer to the lock.
    @result True if the lock was unlocked and is now locked by the caller, otherwise false. */

static __inline__
boolean_t IOSimpleLockTryLock( IOSimpleLock * lock )
{
    return( simple_lock_try( lock ) );
}

/*! @function IOSimpleLockUnlock
    @abstract Unlock an osfmk simple lock.
    @discussion Unlock the lock, and restore preemption. Results are undefined if the caller has not locked the lock.
    @param lock Pointer to the lock. */

static __inline__
void IOSimpleLockUnlock( IOSimpleLock * lock )
{
    simple_unlock( lock );
}

typedef long int IOInterruptState;

/*! @function IOSimpleLockLockDisableInterrupt
    @abstract Lock an osfmk simple lock.
    @discussion Lock the simple lock. If the lock is held, spin waiting for its unlock. Simple locks disable preemption, cannot be held across any blocking operation, and should be held for very short periods. When used to synchronize between interrupt context and thread context they should be locked with interrupts disabled - IOSimpleLockLockDisableInterrupt() will do both. Locking the lock recursively from one thread will result in deadlock.
    @param lock Pointer to the lock. */

static __inline__
IOInterruptState IOSimpleLockLockDisableInterrupt( IOSimpleLock * lock )
{
    IOInterruptState	state = ml_set_interrupts_enabled( false );
    simple_lock( lock );
    return( state );
}

/*! @function IOSimpleLockUnlockEnableInterrupt
    @abstract Unlock an osfmk simple lock, and restore interrupt state.
    @discussion Unlock the lock, and restore preemption and interrupts to the state as they were when the lock was taken. Results are undefined if the caller has not locked the lock.
    @param lock Pointer to the lock.
    @param state The interrupt state returned by IOSimpleLockLockDisableInterrupt() */

static __inline__
void IOSimpleLockUnlockEnableInterrupt( IOSimpleLock * lock,
					IOInterruptState state )
{
    simple_unlock( lock );
    ml_set_interrupts_enabled( state );
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__IOKIT_IOLOCKS_H */

