/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */


#define	IOLOCKS_CPP	1

#include <IOKit/system.h>

#include <IOKit/IOReturn.h>
#include <IOKit/IOLib.h> 
#include <IOKit/assert.h>

extern "C" {
#include <kern/locks.h>

void	IOLockInitWithState( IOLock * lock, IOLockState state)
{
    if( state == kIOLockStateLocked)
        lck_mtx_lock( lock);
}

IOLock * IOLockAlloc( void )
{
    return( lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL) );
}

void	IOLockFree( IOLock * lock)
{
    lck_mtx_free( lock, IOLockGroup);
}

lck_mtx_t * IOLockGetMachLock( IOLock * lock)
{
    return( (lck_mtx_t *)lock);
}

int	IOLockSleep( IOLock * lock, void *event, UInt32 interType)
{
    return (int) lck_mtx_sleep(lock, LCK_SLEEP_DEFAULT, (event_t) event, (wait_interrupt_t) interType);
}

int	IOLockSleepDeadline( IOLock * lock, void *event,
                                AbsoluteTime deadline, UInt32 interType)
{
    return (int) lck_mtx_sleep_deadline(lock, LCK_SLEEP_DEFAULT, (event_t) event,
    					(wait_interrupt_t) interType, __OSAbsoluteTime(deadline));
}

void	IOLockWakeup(IOLock * lock, void *event, bool oneThread)
{   
	thread_wakeup_prim((event_t) event, oneThread, THREAD_AWAKENED);
}   


struct _IORecursiveLock {
    lck_mtx_t   *mutex;
    thread_t	thread;
    UInt32	count;
};

IORecursiveLock * IORecursiveLockAlloc( void )
{
    _IORecursiveLock * lock;

    lock = IONew( _IORecursiveLock, 1);
    if( !lock)
        return( 0 );

    lock->mutex = lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL);
    if( lock->mutex) {
        lock->thread = 0;
        lock->count  = 0;
    } else {
        IODelete( lock, _IORecursiveLock, 1);
        lock = 0;
    }

    return( (IORecursiveLock *) lock );
}

void IORecursiveLockFree( IORecursiveLock * _lock )
{
    _IORecursiveLock * lock = (_IORecursiveLock *)_lock;

    lck_mtx_free( lock->mutex , IOLockGroup);
    IODelete( lock, _IORecursiveLock, 1);
}

lck_mtx_t * IORecursiveLockGetMachLock( IORecursiveLock * lock)
{
    return( lock->mutex);
}

void IORecursiveLockLock( IORecursiveLock * _lock)
{
    _IORecursiveLock * lock = (_IORecursiveLock *)_lock;

    if( lock->thread == IOThreadSelf())
        lock->count++;
    else {
        lck_mtx_lock( lock->mutex );
        assert( lock->thread == 0 );
        assert( lock->count == 0 );
        lock->thread = IOThreadSelf();
        lock->count = 1;
    }
}

boolean_t IORecursiveLockTryLock( IORecursiveLock * _lock)
{
    _IORecursiveLock * lock = (_IORecursiveLock *)_lock;

    if( lock->thread == IOThreadSelf()) {
        lock->count++;
	return( true );
    } else {
        if( lck_mtx_try_lock( lock->mutex )) {
            assert( lock->thread == 0 );
            assert( lock->count == 0 );
            lock->thread = IOThreadSelf();
            lock->count = 1;
            return( true );
	}
    }
    return( false );
}

void IORecursiveLockUnlock( IORecursiveLock * _lock)
{
    _IORecursiveLock * lock = (_IORecursiveLock *)_lock;

    assert( lock->thread == IOThreadSelf() );

    if( 0 == (--lock->count)) {
        lock->thread = 0;
        lck_mtx_unlock( lock->mutex );
    }
}

boolean_t IORecursiveLockHaveLock( const IORecursiveLock * _lock)
{
    _IORecursiveLock * lock = (_IORecursiveLock *)_lock;

    return( lock->thread == IOThreadSelf());
}

int IORecursiveLockSleep(IORecursiveLock *_lock, void *event, UInt32 interType)
{
    _IORecursiveLock * lock = (_IORecursiveLock *)_lock;
    UInt32 count = lock->count;
    int res;

    assert(lock->thread == IOThreadSelf());
    assert(lock->count == 1 || interType == THREAD_UNINT);
    
    lock->count = 0;
    lock->thread = 0;
    res = lck_mtx_sleep(lock->mutex, LCK_SLEEP_DEFAULT, (event_t) event, (wait_interrupt_t) interType);

    // Must re-establish the recursive lock no matter why we woke up
    // otherwise we would potentially leave the return path corrupted.
    assert(lock->thread == 0);
    assert(lock->count == 0);
    lock->thread = IOThreadSelf();
    lock->count = count;
    return res;
}

void IORecursiveLockWakeup(IORecursiveLock *, void *event, bool oneThread)
{
    thread_wakeup_prim((event_t) event, oneThread, THREAD_AWAKENED);
}

/*
 * Complex (read/write) lock operations
 */

IORWLock * IORWLockAlloc( void )
{
    return(  lck_rw_alloc_init(IOLockGroup, LCK_ATTR_NULL)  );
}

void	IORWLockFree( IORWLock * lock)
{
    lck_rw_free( lock, IOLockGroup);
}

lck_rw_t * IORWLockGetMachLock( IORWLock * lock)
{
    return( (lck_rw_t *)lock);
}


/*
 * Spin locks
 */

IOSimpleLock * IOSimpleLockAlloc( void )
{
    return( lck_spin_alloc_init( IOLockGroup, LCK_ATTR_NULL) );
}

void IOSimpleLockInit( IOSimpleLock * lock)
{
    lck_spin_init( lock, IOLockGroup, LCK_ATTR_NULL);
}

void IOSimpleLockFree( IOSimpleLock * lock )
{
    lck_spin_free( lock, IOLockGroup);
}

lck_spin_t * IOSimpleLockGetMachLock( IOSimpleLock * lock)
{
    return( (lck_spin_t *)lock);
}

} /* extern "C" */


