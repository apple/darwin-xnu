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


#include <IOKit/system.h>

#include <IOKit/IOReturn.h>
#include <IOKit/IOLib.h> 
#include <IOKit/assert.h>

extern "C" {
#include <kern/simple_lock.h>
#include <machine/machine_routines.h>

IOLock * IOLockAlloc( void )
{
    return( mutex_alloc(ETAP_IO_AHA) );
}

void	IOLockFree( IOLock * lock)
{
    mutex_free( lock );
}

void	IOLockInitWithState( IOLock * lock, IOLockState state)
{
    if( state == kIOLockStateLocked)
        IOLockLock( lock);
}

struct _IORecursiveLock {
    mutex_t  *	mutex;
    thread_t	thread;
    UInt32	count;
};

IORecursiveLock * IORecursiveLockAlloc( void )
{
    _IORecursiveLock * lock;

    lock = IONew( _IORecursiveLock, 1);
    if( !lock)
        return( 0 );

    lock->mutex = mutex_alloc(ETAP_IO_AHA);
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

    mutex_free( lock->mutex );
    IODelete( lock, _IORecursiveLock, 1);
}

void IORecursiveLockLock( IORecursiveLock * _lock)
{
    _IORecursiveLock * lock = (_IORecursiveLock *)_lock;

    if( lock->thread == IOThreadSelf())
        lock->count++;
    else {
        mutex_lock( lock->mutex );
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
        if( mutex_try( lock->mutex )) {
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
        mutex_unlock( lock->mutex );
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
    res = thread_sleep_mutex((event_t) event, lock->mutex, (int) interType);

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
    IORWLock * lock;

    lock = lock_alloc( true, ETAP_IO_AHA, ETAP_IO_AHA);

    return( lock);
}

void	IORWLockFree( IORWLock * lock)
{
    lock_free( lock );
}


/*
 * Spin locks
 */

IOSimpleLock * IOSimpleLockAlloc( void )
{
    IOSimpleLock *	lock;

    lock = (IOSimpleLock *) IOMalloc( sizeof(IOSimpleLock));
    if( lock)
	IOSimpleLockInit( lock );

    return( lock );
}

void IOSimpleLockInit( IOSimpleLock * lock)
{
    simple_lock_init( (simple_lock_t) lock, ETAP_IO_AHA );
}

void IOSimpleLockFree( IOSimpleLock * lock )
{
    IOFree( lock, sizeof(IOSimpleLock));
}

} /* extern "C" */


