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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * IOTimerEventSource.cpp
 *
 * HISTORY
 * 2-Feb-1999		Joe Liu (jliu) created.
 * 1999-10-14		Godfrey van der Linden(gvdl)
 *		Revamped to use thread_call APIs
 *
 */

#include <sys/cdefs.h>

__BEGIN_DECLS
#include <kern/thread_call.h>
__END_DECLS

#include <IOKit/assert.h>
#include <IOKit/system.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>

#include <IOKit/IOTimeStamp.h>

#define super IOEventSource
OSDefineMetaClassAndStructors(IOTimerEventSource, IOEventSource)
OSMetaClassDefineReservedUnused(IOTimerEventSource, 0);
OSMetaClassDefineReservedUnused(IOTimerEventSource, 1);
OSMetaClassDefineReservedUnused(IOTimerEventSource, 2);
OSMetaClassDefineReservedUnused(IOTimerEventSource, 3);
OSMetaClassDefineReservedUnused(IOTimerEventSource, 4);
OSMetaClassDefineReservedUnused(IOTimerEventSource, 5);
OSMetaClassDefineReservedUnused(IOTimerEventSource, 6);
OSMetaClassDefineReservedUnused(IOTimerEventSource, 7);

bool IOTimerEventSource::checkForWork() { return false; }

// Timeout handler function. This function is called by the kernel when
// the timeout interval expires.
//
void IOTimerEventSource::timeout(void *self)
{
    IOTimerEventSource *me = (IOTimerEventSource *) self;

    if (me->enabled) {
        Action doit = (Action) me->action;

        if (doit) {
            IOTimeStampConstant(IODBG_TIMES(IOTIMES_ACTION),
                                (unsigned int) doit, (unsigned int) me->owner);
            me->closeGate();
            (*doit)(me->owner, me);
            me->openGate();
        }
    }
}

void IOTimerEventSource::setTimeoutFunc()
{
    calloutEntry = (void *) thread_call_allocate((thread_call_func_t) timeout,
                                                 (thread_call_param_t) this);
}

bool IOTimerEventSource::init(OSObject *inOwner, Action inAction)
{
    if (!super::init(inOwner, (IOEventSource::Action) inAction) )
        return false;

    setTimeoutFunc();
    if (!calloutEntry)
        return false;

    return true;
}

IOTimerEventSource *
IOTimerEventSource::timerEventSource(OSObject *inOwner, Action inAction)
{
    IOTimerEventSource *me = new IOTimerEventSource;

    if (me && !me->init(inOwner, inAction)) {
        me->free();
        return 0;
    }

    return me;
}

void IOTimerEventSource::free()
{
    if (calloutEntry) {
        cancelTimeout();
        thread_call_free((thread_call_t) calloutEntry);    
    }

    super::free();
}

void IOTimerEventSource::cancelTimeout()
{
    thread_call_cancel((thread_call_t) calloutEntry);
    AbsoluteTime_to_scalar(&abstime) = 0;
}

void IOTimerEventSource::enable()
{
    super::enable();
    if (kIOReturnSuccess != wakeAtTime(abstime))
        super::disable(); // Problem re-scheduling timeout ignore enable
}

void IOTimerEventSource::disable()
{
    thread_call_cancel((thread_call_t) calloutEntry);
    super::disable();
}

IOReturn IOTimerEventSource::setTimeoutTicks(UInt32 ticks)
{
    return setTimeout(ticks, NSEC_PER_SEC/hz);
}

IOReturn IOTimerEventSource::setTimeoutMS(UInt32 ms)
{
    return setTimeout(ms, kMillisecondScale);
}

IOReturn IOTimerEventSource::setTimeoutUS(UInt32 us)
{
    return setTimeout(us, kMicrosecondScale);
}

IOReturn IOTimerEventSource::setTimeout(UInt32 interval, UInt32 scale_factor)
{
    AbsoluteTime end;
    
    clock_interval_to_deadline(interval, scale_factor, &end);
    return wakeAtTime(end);
}

IOReturn IOTimerEventSource::setTimeout(mach_timespec_t interval)
{
    AbsoluteTime end, nsecs;

    clock_interval_to_absolutetime_interval
        (interval.tv_nsec, kNanosecondScale, &nsecs);
    clock_interval_to_deadline
        (interval.tv_sec, NSEC_PER_SEC, &end);
    ADD_ABSOLUTETIME(&end, &nsecs);

    return wakeAtTime(end);
}

IOReturn IOTimerEventSource::setTimeout(AbsoluteTime interval)
{
    AbsoluteTime end;

    clock_get_uptime(&end);
    ADD_ABSOLUTETIME(&end, &interval);

    return wakeAtTime(end);
}

IOReturn IOTimerEventSource::wakeAtTimeTicks(UInt32 ticks)
{
    return wakeAtTime(ticks, NSEC_PER_SEC/hz);
}

IOReturn IOTimerEventSource::wakeAtTimeMS(UInt32 ms)
{
    return wakeAtTime(ms, kMillisecondScale);
}

IOReturn IOTimerEventSource::wakeAtTimeUS(UInt32 us)
{
    return wakeAtTime(us, kMicrosecondScale);
}

IOReturn IOTimerEventSource::wakeAtTime(UInt32 abstime, UInt32 scale_factor)
{
    AbsoluteTime end;
    clock_interval_to_absolutetime_interval(abstime, scale_factor, &end);

    return wakeAtTime(end);
}

IOReturn IOTimerEventSource::wakeAtTime(mach_timespec_t abstime)
{
    AbsoluteTime end, nsecs;

    clock_interval_to_absolutetime_interval
        (abstime.tv_nsec, kNanosecondScale, &nsecs);
    clock_interval_to_absolutetime_interval
        (abstime.tv_sec, kSecondScale, &end);
    ADD_ABSOLUTETIME(&end, &nsecs);

    return wakeAtTime(end);
}

IOReturn IOTimerEventSource::wakeAtTime(AbsoluteTime inAbstime)
{
    if (!action)
        return kIOReturnNoResources;

    abstime = inAbstime;
    if ( enabled && AbsoluteTime_to_scalar(&abstime) )
        thread_call_enter_delayed((thread_call_t) calloutEntry, abstime);

    return kIOReturnSuccess;
}
